//! Write-Ahead Log (WAL) implementation, generic over its backing storage.
//!
//! # Warning
//! Not for regular use, use [`crate::Log`] instead.

use std::io::{self, SeekFrom, Write};
use std::path::{Path, PathBuf};

use cfg_if::cfg_if;

use crate::ext::{read_u32, read_u64, read_u8, write_u32, write_u64, write_u8};
use crate::{Storage, Version};

/// The maximum size of a single log entry in bytes. (1 GiB)
const MAX_ENTRY_SIZE: usize = 1024 * 1024 * 1024;

/// Assigns a stable, sequential small integer to each WAL file path, so oracle
/// observations carry a real instance identity instead of a placeholder.
/// Numbering restarts per test (the harness names each test's thread after the
/// test), which is also the boundary the oracle records a trace for.
/// Dead code unless the oracle client is compiled in.
#[allow(dead_code)]
fn oracle_path_id(path: &Path) -> usize {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    static IDS: OnceLock<Mutex<HashMap<String, HashMap<PathBuf, usize>>>> = OnceLock::new();

    let owner = std::thread::current().name().unwrap_or("").to_owned();

    let mut ids = IDS.get_or_init(Default::default).lock().unwrap();
    let per_test = ids.entry(owner).or_default();
    let next = per_test.len();
    *per_test.entry(path.to_owned()).or_insert(next)
}

/// Represents a single entry in the Write-Ahead Log (WAL).
///
/// Each entry has the following format on disk:
///
/// ```text
/// +-----------------|-----------------+----------------+-----------------+
/// |  Is compressed  |     Length      |      CRC       |      Data       |
/// |     (1 byte)    |  (8 bytes, BE)  |   (4 bytes)    | ($length bytes) |
/// +-----------------|-----------------+----------------+-----------------+
/// ```
pub struct LogEntry<'a, S> {
    /// Reference to the parent WAL
    log: &'a mut Log<S>,
}

/// The outcome of reading one entry.
///
/// A damaged entry does not have to end the scan: the entries are
/// length-framed, so a payload that fails its CRC (or fails to decompress)
/// says nothing about the framing of the entries behind it. Whenever the
/// stream is still positioned on an entry boundary, `next` carries the
/// continuation so the reader can report the damage and carry on.
pub struct EntryRead<'a, S> {
    /// `Ok(())` when the entry read back cleanly, `Err` when it did not.
    pub result: io::Result<()>,

    /// The entry that follows, when the stream is still positioned at an entry
    /// boundary and the log has more entries. `None` ends the scan.
    pub next: Option<LogEntry<'a, S>>,
}

impl<'a, S> EntryRead<'a, S> {
    /// The stream is no longer positioned on a known entry boundary, so the
    /// scan cannot continue.
    fn fatal(error: io::Error) -> Self {
        Self {
            result: Err(error),
            next: None,
        }
    }
}

impl<'a, S> LogEntry<'a, S>
where
    S: Storage,
{
    /// Reads the compression flag of the current entry
    fn read_compression_flag(&mut self) -> io::Result<bool> {
        read_u8(&mut self.log.storage).map(|byte| byte != 0)
    }

    /// Reads the length field of the current entry
    fn read_length(&mut self) -> io::Result<u64> {
        read_u64(&mut self.log.storage)
    }

    /// Reads the CRC field of the current entry
    fn read_crc(&mut self) -> io::Result<u32> {
        read_u32(&mut self.log.storage)
    }

    /// The continuation of the scan, given that the stream is positioned at
    /// the start of the next entry: `Some(self)` while entries remain, `None`
    /// at the end of the file or if the position cannot be determined.
    fn continuation(self) -> Option<Self> {
        let pos = self.log.storage.stream_position().ok()?;
        let len = self.log.storage.size_bytes().ok()?;

        (pos < len).then_some(self)
    }

    /// A damaged entry whose payload was already consumed, so the stream sits
    /// on the next entry's header and the scan can continue past it.
    fn damaged(self, error: io::Error) -> EntryRead<'a, S> {
        EntryRead {
            result: Err(error),
            next: self.continuation(),
        }
    }

    /// A damaged entry whose payload has *not* been consumed: skip `length`
    /// bytes to reach the next entry's header, and continue from there.
    fn skip_over(self, error: io::Error, length: u64) -> EntryRead<'a, S> {
        let Ok(offset) = i64::try_from(length) else {
            return EntryRead::fatal(error);
        };

        if self.log.storage.seek(SeekFrom::Current(offset)).is_err() {
            return EntryRead::fatal(error);
        }

        self.damaged(error)
    }

    /// Reads the current entry's data and advances to the next entry.
    /// The entry data is written to the provided writer.
    ///
    /// # Arguments
    /// * `writer` - The writer to output the entry data to
    ///
    /// # Returns
    /// An [`EntryRead`]: whether this entry read back cleanly, plus the next
    /// entry when the scan can continue. A CRC mismatch, a failed
    /// decompression or an oversized length field damages only the entry it
    /// is reported for — the frame is still intact, so the following entries
    /// are still readable. Only a failure that leaves the stream off an entry
    /// boundary (a short read, an I/O error in the fixed header) ends the
    /// scan.
    pub fn read_to_next<W: Write>(mut self, writer: &mut W) -> EntryRead<'a, S> {
        let is_compressed = match self.read_compression_flag() {
            Ok(flag) => flag,
            Err(e) => return EntryRead::fatal(e),
        };

        let length = match self.read_length() {
            Ok(length) => length,
            Err(e) => return EntryRead::fatal(e),
        };

        let expected_crc = match self.read_crc() {
            Ok(crc) => crc,
            Err(e) => return EntryRead::fatal(e),
        };

        if length > MAX_ENTRY_SIZE as u64 {
            // The open-time scan framed this entry with the very same length
            // field, so skipping that many bytes still lands on the next
            // entry's header.
            let error = io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Entry size {length} exceeds maximum of {MAX_ENTRY_SIZE}"),
            );

            return self.skip_over(error, length);
        }

        let mut data = vec![0; length as usize];
        if let Err(e) = self.log.storage.read_exact(&mut data) {
            return EntryRead::fatal(e);
        }

        #[cfg(not(feature = "compression"))]
        if is_compressed {
            let error = io::Error::new(
                io::ErrorKind::InvalidData,
                "Entry is compressed but compression is disabled",
            );

            return self.damaged(error);
        }

        #[cfg(feature = "compression")]
        if is_compressed {
            match lz4_flex::decompress_size_prepended(&data) {
                Ok(decompressed) => data = decompressed,
                Err(e) => {
                    let error = io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Failed to decompress entry: {e}"),
                    );

                    return self.damaged(error);
                }
            }
        }

        let actual_crc = compute_crc(&data);

        if expected_crc != actual_crc {
            let error = io::Error::new(io::ErrorKind::InvalidData, "CRC mismatch");

            return self.damaged(error);
        }

        if let Err(e) = writer.write_all(&data) {
            return EntryRead::fatal(e);
        }

        EntryRead {
            result: Ok(()),
            next: self.continuation(),
        }
    }
}

/// Write-Ahead Log (WAL)
///
/// A Write-Ahead Log is a sequential log of records that provides durability and atomicity
/// guarantees by writing changes to disk before they are applied to the main database.
///
/// # Format on disk
///
/// ```text
/// +-----------------+-----------------+-----------------+-----------------+-----------------+
/// |     Version     |     Sequence    |    Entry #1     |       ...       |     Entry #n    |
/// |    (4 bytes)    |    (8 bytes)    |    (variable)   |                 |    (variable)   |
/// +-----------------+-----------------+-----------------+-----------------+-----------------+
/// ```
#[derive(Debug)]
pub struct Log<S> {
    storage: S,
    path: PathBuf,
    /// Oracle-only: this log's stable identity in the `PATHS` domain, assigned
    /// when the log is opened so every thread that later drives it reports the
    /// same path.
    oracle_path: usize,
    version: Version,
    sequence: u64,
    len: usize,
}

pub mod constants {
    use super::Version;

    pub const VERSION_SIZE: u64 = size_of::<Version>() as u64;
    pub const SEQUENCE_SIZE: u64 = size_of::<u64>() as u64;
    pub const HEADER_SIZE: u64 = VERSION_SIZE + SEQUENCE_SIZE;

    pub const VERSION_OFFSET: u64 = 0;
    pub const SEQUENCE_OFFSET: u64 = VERSION_OFFSET + VERSION_SIZE;
    pub const FIRST_ENTRY_OFFSET: u64 = HEADER_SIZE;

    pub const ENTRY_CRC_SIZE: u64 = size_of::<u32>() as u64;
    pub const ENTRY_LENGTH_SIZE: u64 = size_of::<u64>() as u64;
    pub const ENTRY_COMPRESSION_FLAG_SIZE: u64 = size_of::<u8>() as u64;
    pub const ENTRY_HEADER_SIZE: u64 =
        ENTRY_COMPRESSION_FLAG_SIZE + ENTRY_LENGTH_SIZE + ENTRY_CRC_SIZE;
}

use constants::*;

enum WriteEntry<'a> {
    Raw(&'a [u8]),

    #[cfg(feature = "compression")]
    Compressed {
        compressed: &'a [u8],
        uncompressed: &'a [u8],
    },
}

impl WriteEntry<'_> {
    fn data(&self) -> &[u8] {
        match self {
            WriteEntry::Raw(data) => data,

            #[cfg(feature = "compression")]
            WriteEntry::Compressed { compressed, .. } => compressed,
        }
    }

    fn len(&self) -> usize {
        match self {
            WriteEntry::Raw(data) => data.len(),

            #[cfg(feature = "compression")]
            WriteEntry::Compressed { compressed, .. } => compressed.len(),
        }
    }

    fn uncompressed_crc(&self) -> u32 {
        match self {
            WriteEntry::Raw(data) => compute_crc(data),

            #[cfg(feature = "compression")]
            WriteEntry::Compressed { uncompressed, .. } => compute_crc(uncompressed),
        }
    }

    fn is_compressed(&self) -> bool {
        cfg_if! {
            if #[cfg(feature = "compression")] {
                matches!(self, WriteEntry::Compressed { .. })
            } else {
                false
            }
        }
    }
}

impl<S> Log<S>
where
    S: Storage<OpenOptions = ()>,
{
    /// Opens a Write-Ahead Log file at the specified path.
    ///
    /// If the file already exists, it will be opened and validated.
    /// If the file does not exist, a new one will be created.
    ///
    /// # Arguments
    /// * `path` - Path where the WAL file should be created/opened
    ///
    /// # Returns
    /// * `Ok(Wal)` - Successfully opened/created WAL
    /// * `Err` - If file operations fail or existing WAL is invalid
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::open_with(path, ())
    }
}

impl<S> Log<S>
where
    S: Storage,
{
    /// Opens a Write-Ahead Log file at the specified path.
    ///
    /// If the file already exists, it will be opened and validated.
    /// If the file does not exist, a new one will be created.
    ///
    /// # Arguments
    /// * `path` - Path where the WAL file should be created/opened
    ///
    /// # Returns
    /// * `Ok(Wal)` - Successfully opened/created WAL
    /// * `Err` - If file operations fail or existing WAL is invalid
    pub fn open_with(path: impl AsRef<Path>, options: S::OpenOptions) -> io::Result<Self> {
        let path = path.as_ref().to_owned();
        let oracle_path = oracle_path_id(&path);

        let mut storage = S::open_with(&path, options)?;

        let size = storage.size_bytes()?;

        // If file exists and has content
        if size > 0 {
            // Read and validate version number
            let version = Version::try_from(read_u32(&mut storage)?).map_err(|_| {
                quint_oracle::log!(
                    Logopen,
                    path: (oracle_path) @ PATHS,
                    ok: false,
                    len: 0 @ LENS,
                    [wal],
                );
                io::Error::new(io::ErrorKind::InvalidData, "Invalid WAL version")
            })?;

            // Read sequence number
            let sequence = read_u64(&mut storage).map_err(|_| {
                quint_oracle::log!(
                    Logopen,
                    path: (oracle_path) @ PATHS,
                    ok: false,
                    len: 0 @ LENS,
                    [wal],
                );
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Failed to read sequence number",
                )
            })?;

            // Track current position and entry count
            let mut pos = FIRST_ENTRY_OFFSET; // Start after header
            let mut len = 0;

            // Scan through entries to validate and count them

            // Check if there's enough space for the fixed part of the header.
            while size.saturating_sub(pos) >= ENTRY_COMPRESSION_FLAG_SIZE + ENTRY_LENGTH_SIZE {
                // Skip over compression flag
                read_u8(&mut storage)?;

                // Read entry length
                let data_length = read_u64(&mut storage)?;

                // Calculate the full size required for this entry (header + data).
                let Some(full_entry_size) = data_length.checked_add(ENTRY_HEADER_SIZE) else {
                    break; // Corrupt, entry length overflows u64
                };

                // Check if enough bytes remain for full entry
                if size.saturating_sub(pos) < full_entry_size {
                    break; // Partial/corrupt entry
                }

                // Calculate just the payload size for seeking past it.
                let Some(payload_size) = data_length.checked_add(ENTRY_CRC_SIZE) else {
                    break; // Integer overflow, file is corrupt
                };

                // Skip to next entry
                let seek_offset = i64::try_from(payload_size).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Entry length too large for seeking",
                    )
                })?;

                pos = storage.seek(SeekFrom::Current(seek_offset))?;
                len += 1;
            }

            // Truncate any partial entries at the end
            storage.truncate_to(pos)?;
            storage.sync_all()?;

            quint_oracle::log!(
                Logopen,
                path: (oracle_path) @ PATHS,
                ok: true,
                %len @ LENS,
                [wal],
            );

            return Ok(Self {
                version,
                storage,
                path,
                oracle_path,
                sequence,
                len,
            });
        }

        // Creating new WAL file
        let version = Version::V1;

        // Write header: version (4 bytes)
        write_u32(&mut storage, version as u32)?;

        // Write header: sequence (8 bytes)
        write_u64(&mut storage, 0)?;

        // Ensure file is exactly header size
        storage.truncate_to(HEADER_SIZE)?;

        // Ensure header is persisted to disk
        storage.sync_all()?;

        quint_oracle::log!(
            Logopen,
            path: (oracle_path) @ PATHS,
            ok: true,
            len: 0 @ LENS,
            [wal],
        );

        Ok(Self {
            version,
            storage,
            path,
            oracle_path,
            sequence: 0,
            len: 0,
        })
    }

    /// Writes a new entry to the WAL.
    ///
    /// The entry is appended to the end of the log with length, CRC and data.
    /// If writing fails, the WAL is truncated to remove the partial write.
    ///
    /// If the `force-compression` feature is enabled, all entries will be compressed.
    ///
    /// # Arguments
    /// * `data` - The data to write as a new WAL entry
    ///
    /// # Returns
    /// * `Ok(())` - Entry was successfully written
    /// * `Err` - If writing fails
    pub fn append(&mut self, data: impl AsRef<[u8]>) -> io::Result<()> {
        cfg_if! {
            if #[cfg(feature = "force-compression")] {
                self.write_compressed(data)
            } else {
                self.write_raw(data)
            }
        }
    }

    /// Writes a new entry to the WAL, without compressing it.
    ///
    /// The entry is appended to the end of the log with length, CRC and data.
    /// If writing fails, the WAL is truncated to remove the partial write.
    ///
    /// # Arguments
    /// * `data` - The data to write as a new WAL entry
    ///
    /// # Returns
    /// * `Ok(())` - Entry was successfully written
    /// * `Err` - If writing fails
    pub fn write_raw(&mut self, data: impl AsRef<[u8]>) -> io::Result<()> {
        self.write_entry(WriteEntry::Raw(data.as_ref()))
    }

    /// Writes a new entry to the WAL, compressing it with the LZ4 algorithm.
    ///
    /// The entry is appended to the end of the log with length, CRC and data.
    /// If writing fails, the WAL is truncated to remove the partial write.
    ///
    /// # Arguments
    /// * `data` - The data to write as a new WAL entry
    ///
    /// # Returns
    /// * `Ok(())` - Entry was successfully written
    /// * `Err` - If writing fails
    #[cfg(feature = "compression")]
    #[cfg_attr(docsrs, doc(cfg(feature = "compression")))]
    pub fn write_compressed(&mut self, data: impl AsRef<[u8]>) -> io::Result<()> {
        let data = data.as_ref();
        let compressed = lz4_flex::compress_prepend_size(data);

        // Only use compression if it actually helps
        let entry = if compressed.len() < data.len() {
            WriteEntry::Compressed {
                compressed: &compressed,
                uncompressed: data,
            }
        } else {
            WriteEntry::Raw(data)
        };

        // Rest of write logic...
        self.write_entry(entry)
    }

    fn write_entry(&mut self, entry: WriteEntry<'_>) -> io::Result<()> {
        // The read path refuses any entry longer than `MAX_ENTRY_SIZE`, so the
        // write path must refuse it too instead of making it durable.
        if entry.len() > MAX_ENTRY_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Entry size {} exceeds maximum of {MAX_ENTRY_SIZE}",
                    entry.len()
                ),
            ));
        }

        let pos = self.storage.seek(SeekFrom::End(0))?;

        let result = || -> io::Result<()> {
            // Write compression flag
            write_u8(&mut self.storage, entry.is_compressed() as u8)?;

            // Write length of (compressed) data
            write_u64(&mut self.storage, entry.len() as u64)?;

            // Write CRC of (uncompressed) data
            write_u32(&mut self.storage, entry.uncompressed_crc())?;

            // Write (compressed) entry data
            self.storage.write_all(entry.data())?;

            Ok(())
        }();

        match result {
            Ok(()) => {
                self.len += 1;

                quint_oracle::log!(
                    Logappend__write_raw__write_compressed,
                    path: (self.oracle_path) @ PATHS,
                    dataLength: (entry.len()) @ SIZES,
                    ok: true,
                    len: (self.len) @ LENS,
                    [wal],
                );

                Ok(())
            }
            Err(e) => {
                self.storage.truncate_to(pos)?;

                quint_oracle::log!(
                    Logappend__write_raw__write_compressed,
                    path: (self.oracle_path) @ PATHS,
                    dataLength: (entry.len()) @ SIZES,
                    ok: false,
                    len: (self.len) @ LENS,
                    [wal],
                );

                Err(e)
            }
        }
    }

    /// Returns an the first entry in the WAL if it exists.
    ///
    /// # Returns
    /// * `Ok(Some(WalEntry))` - First entry exists and was retrieved
    /// * `Ok(None)` - WAL is empty
    /// * `Err` - If reading fails or WAL is invalid
    pub fn first_entry(&mut self) -> io::Result<Option<LogEntry<'_, S>>> {
        // IF the file is empty, return an error
        if self.storage.size_bytes()? == 0 {
            quint_oracle::log!(
                Logfirst_entry__iter,
                path: (self.oracle_path) @ PATHS,
                ok: false,
                len: (self.len) @ LENS,
                [wal],
            );

            return Err(io::Error::new(io::ErrorKind::NotFound, "Empty WAL"));
        }

        quint_oracle::log!(
            Logfirst_entry__iter,
            path: (self.oracle_path) @ PATHS,
            ok: true,
            len: (self.len) @ LENS,
            [wal],
        );

        // If there are no entries, return None
        if self.len == 0 {
            return Ok(None);
        }

        // Seek to the first entry after the header
        self.storage.seek(SeekFrom::Start(FIRST_ENTRY_OFFSET))?;

        Ok(Some(LogEntry { log: self }))
    }

    /// Returns an iterator over all entries in the WAL.
    ///
    /// # Returns
    /// * `Ok(LogIter)` - Iterator over WAL entries
    /// * `Err` - If reading fails
    pub fn iter(&mut self) -> io::Result<LogIter<'_, S>> {
        Ok(LogIter {
            next: self.first_entry()?,
            idx: 0,
        })
    }

    /// Reset the WAL with a new sequence number.
    ///
    /// This truncates all existing entries and resets the WAL to an empty state
    /// with the specified sequence number.
    ///
    /// # Arguments
    /// * `sequence` - New sequence number to start from
    ///
    /// # Returns
    /// * `Ok(())` - WAL was successfully restarted
    /// * `Err` - If file operations fail
    pub fn reset(&mut self, sequence: u64) -> io::Result<()> {
        // Reset sequence number and entry count
        self.sequence = sequence;
        self.len = 0;

        // Seek to start of sequence number
        self.storage.seek(SeekFrom::Start(SEQUENCE_OFFSET))?;

        // Write new sequence number
        write_u64(&mut self.storage, sequence)?;

        // Truncate all entries
        self.storage.truncate_to(HEADER_SIZE)?;

        // Sync changes to disk
        self.storage.sync_all()?;

        quint_oracle::log!(
            Logreset,
            path: (self.oracle_path) @ PATHS,
            %sequence @ HEIGHTS,
            len: 0 @ LENS,
            [wal],
        );

        Ok(())
    }

    /// Truncates the WAL to the specified entry index.
    ///
    /// All entries from `from_entry` onwards will be removed.
    /// If `from_entry` is greater than or equal to the current length,
    /// no action is taken.
    ///
    /// # Arguments
    /// * `from_entry` - The entry index to truncate from
    ///
    /// # Returns
    /// * `Ok(())` - WAL was successfully truncated
    /// * `Err` - If file operations fail
    pub fn truncate(&mut self, from_entry: u64) -> io::Result<()> {
        if from_entry >= self.len as u64 {
            quint_oracle::log!(
                Logtruncate,
                path: (self.oracle_path) @ PATHS,
                %from_entry @ INDICES,
                len: (self.len) @ LENS,
                [wal],
            );

            return Ok(());
        }

        let mut pos = FIRST_ENTRY_OFFSET;

        self.storage.seek(SeekFrom::Start(pos))?;

        for _ in 0..from_entry {
            // Skip compression flag
            let _ = read_u8(&mut self.storage)?;
            pos += ENTRY_COMPRESSION_FLAG_SIZE;

            // Read entry length
            let data_length = read_u64(&mut self.storage)?;
            pos += ENTRY_LENGTH_SIZE;

            // Skip CRC
            let _ = read_u32(&mut self.storage)?;
            pos += ENTRY_CRC_SIZE;

            // Compute seek offset to skip over data
            let seek_offset = i64::try_from(data_length).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Entry length too large for seeking",
                )
            })?;

            // Skip to next entry
            let new_pos = self.storage.seek(SeekFrom::Current(seek_offset))?;

            // Check consistency
            assert_eq!(new_pos, pos + data_length);

            // Update position
            pos = new_pos;
        }

        // Truncate the storage to the computed position
        self.storage.truncate_to(pos)?;

        // Sync changes to disk
        self.storage.sync_all()?;

        // Update entry count
        self.len = from_entry as usize;

        quint_oracle::log!(
            Logtruncate,
            path: (self.oracle_path) @ PATHS,
            %from_entry @ INDICES,
            len: (self.len) @ LENS,
            [wal],
        );

        Ok(())
    }

    /// Syncs all written data to disk.
    ///
    /// On UNIX systems, this will call `fsync` to ensure all data is written to disk.
    ///
    /// # Returns
    /// * `Ok(())` - Successfully synced to disk
    /// * `Err` - If sync fails
    pub fn flush(&mut self) -> io::Result<()> {
        let result = self.storage.sync_all();

        quint_oracle::log!(
            Logflush,
            path: (self.oracle_path) @ PATHS,
            ok: (result.is_ok()),
            len: (self.len) @ LENS,
            [wal],
        );

        result
    }

    /// Build a Write-Ahead Log (WAL) from its raw components.
    ///
    /// # Safety
    /// This is a dangerous function that should not be used directly.
    /// It bypasses important initialization and validation checks.
    /// Instead, use `malachitebft_wal::file::Log::open` which properly initializes the WAL.
    ///
    /// This function exists primarily for internal use and testing purposes.
    pub fn from_raw_parts(
        file: S,
        path: PathBuf,
        version: Version,
        sequence: u64,
        len: usize,
    ) -> Self {
        let oracle_path = oracle_path_id(&path);

        quint_oracle::log!(
            Logfrom_raw_parts,
            path: (oracle_path) @ PATHS,
            %sequence @ HEIGHTS,
            %len @ LENS,
            [wal],
        );

        Self {
            storage: file,
            path,
            oracle_path,
            version,
            sequence,
            len,
        }
    }

    /// Returns the size in bytes of the underlying storage
    pub fn size_bytes(&self) -> io::Result<u64> {
        self.storage.size_bytes()
    }
}

impl<S> Log<S> {
    /// Returns the version of the WAL format.
    pub fn version(&self) -> Version {
        self.version
    }

    /// Returns the current sequence number.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the path to the WAL file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the number of entries in the WAL.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the WAL is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Iterator over entries in a Write-Ahead Log (WAL)
pub struct LogIter<'a, F> {
    /// The next entry to be read from the WAL
    next: Option<LogEntry<'a, F>>,

    /// Index of the entry `next()` will read, for oracle observations
    idx: usize,
}

/// Iterator over entries in a Write-Ahead Log (WAL)
///
/// Provides sequential access to entries stored in the WAL.
/// Each iteration returns the data contained in the next entry.
impl<F> Iterator for LogIter<'_, F>
where
    F: Storage,
{
    /// Each iteration returns a Result containing either the entry data as a `Vec<u8>`
    /// or an IO error if reading fails
    type Item = io::Result<Vec<u8>>;

    /// Advances the iterator and returns the next entry's data
    ///
    /// # Returns
    /// * `Some(Ok(Vec<u8>))` - Successfully read entry data
    /// * `Some(Err(e))` - Error occurred while reading entry
    /// * `None` - No more entries to read
    fn next(&mut self) -> Option<Self::Item> {
        let mut buf = Vec::new();
        let next = self.next.take()?;

        let idx = self.idx;
        let path_id = next.log.oracle_path;
        self.idx += 1;

        let EntryRead { result, next } = next.read_to_next(&mut buf);

        // A damaged entry does not end the scan when the frame behind it is
        // still intact: `next` carries the continuation in that case.
        self.next = next;

        match result {
            Ok(()) => {
                quint_oracle::log!(
                    Logread_entry,
                    path: (path_id) @ PATHS,
                    %idx @ INDICES,
                    ok: true,
                    [wal],
                );

                Some(Ok(buf))
            }
            Err(e) => {
                quint_oracle::log!(
                    Logread_entry,
                    path: (path_id) @ PATHS,
                    %idx @ INDICES,
                    ok: false,
                    [wal],
                );

                Some(Err(e))
            }
        }
    }
}

/// Computes the CRC32 checksum of the provided data
///
/// # Arguments
/// * `data` - The bytes to compute the checksum for
///
/// # Returns
/// The CRC32 checksum as a u32 in big-endian byte order
fn compute_crc(data: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(data);
    hasher.finalize()
}
