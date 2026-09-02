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

impl<S> LogEntry<'_, S>
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

    /// Reads the current entry's data and advances to the next entry.
    /// The entry data is written to the provided writer.
    ///
    /// # Arguments
    /// * `writer` - The writer to output the entry data to
    ///
    /// # Returns
    /// * `Ok(Some(self))` - If there are more entries to read
    /// * `Ok(None)` - If this was the last entry
    /// * `Err` - If an I/O error occurs or the CRC check fails
    pub fn read_to_next<W: Write>(mut self, writer: &mut W) -> io::Result<Option<Self>> {
        let is_compressed = self.read_compression_flag()?;
        let length = self.read_length()? as usize;
        let expected_crc = self.read_crc()?;

        if length > MAX_ENTRY_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Entry size {length} exceeds maximum of {MAX_ENTRY_SIZE}"),
            ));
        }

        let mut data = vec![0; length];
        self.log.storage.read_exact(&mut data)?;

        #[cfg(not(feature = "compression"))]
        if is_compressed {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Entry is compressed but compression is disabled",
            ));
        }

        #[cfg(feature = "compression")]
        if is_compressed {
            data = lz4_flex::decompress_size_prepended(&data).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Failed to decompress entry: {e}"),
                )
            })?;
        }

        let actual_crc = compute_crc(&data);

        if expected_crc != actual_crc {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "CRC mismatch"));
        }

        writer.write_all(&data)?;

        let pos = self.log.storage.stream_position()?;
        let len = self.log.storage.size_bytes()?;

        if pos < len {
            Ok(Some(self))
        } else {
            Ok(None)
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

        let mut storage = S::open_with(&path, options)?;

        let size = storage.size_bytes()?;

        // If file exists and has content
        if size > 0 {
            // Read and validate version number
            let version = Version::try_from(read_u32(&mut storage)?).map_err(|_| {
                quint_oracle::log!(
                    Logopen,
                    path: (oracle_path_id(&path)) @ PATHS,
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
                    path: (oracle_path_id(&path)) @ PATHS,
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
                path: (oracle_path_id(&path)) @ PATHS,
                ok: true,
                %len @ LENS,
                [wal],
            );

            return Ok(Self {
                version,
                storage,
                path,
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
            path: (oracle_path_id(&path)) @ PATHS,
            ok: true,
            len: 0 @ LENS,
            [wal],
        );

        Ok(Self {
            version,
            storage,
            path,
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
                    path: (oracle_path_id(&self.path)) @ PATHS,
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
                    path: (oracle_path_id(&self.path)) @ PATHS,
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
                path: (oracle_path_id(&self.path)) @ PATHS,
                ok: false,
                len: (self.len) @ LENS,
                [wal],
            );

            return Err(io::Error::new(io::ErrorKind::NotFound, "Empty WAL"));
        }

        quint_oracle::log!(
            Logfirst_entry__iter,
            path: (oracle_path_id(&self.path)) @ PATHS,
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
            path: (oracle_path_id(&self.path)) @ PATHS,
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
                path: (oracle_path_id(&self.path)) @ PATHS,
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
            path: (oracle_path_id(&self.path)) @ PATHS,
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
            path: (oracle_path_id(&self.path)) @ PATHS,
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
        quint_oracle::log!(
            Logfrom_raw_parts,
            path: (oracle_path_id(&path)) @ PATHS,
            %sequence @ HEIGHTS,
            %len @ LENS,
            [wal],
        );

        Self {
            storage: file,
            path,
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
        let path_id = oracle_path_id(&next.log.path);
        self.idx += 1;

        match next.read_to_next(&mut buf) {
            Ok(Some(entry)) => {
                quint_oracle::log!(
                    Logread_entry,
                    path: (path_id) @ PATHS,
                    %idx @ INDICES,
                    ok: true,
                    [wal],
                );

                self.next = Some(entry);
                Some(Ok(buf))
            }
            Ok(None) => {
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
