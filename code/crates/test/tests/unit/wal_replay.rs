//! Contract tests for what a replay does when one entry in the middle of the
//! log cannot be read back (bit rot, a torn sector — the damage CRCs exist to
//! catch).
//!
//! Wired the same way as `node_supervisor`: a real `Node`, the real `Wal` actor
//! and the real protobuf codec, so the log is written and replayed through the
//! production path.

use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use tempfile::TempDir;

use arc_malachitebft_test::codec::proto::ProtobufCodec;
use arc_malachitebft_test::{Address, Height, Signature, TestContext, Value, Vote};

use malachitebft_core_consensus::Input;
use malachitebft_core_types::{NilOrVal, Round, SignedVote};
use malachitebft_engine::node::{Node, NodeRef};
use malachitebft_engine::wal::{encode_entry, Msg as WalMsg, Wal, WalRef};
use malachitebft_metrics::{Metrics, SharedRegistry};

const ENTRIES: usize = 4;
/// compression flag + length + CRC, ahead of every entry's data.
const ENTRY_HEADER: usize = 1 + 8 + 4;

async fn spawn_node() -> NodeRef {
    let registry = SharedRegistry::new(Default::default(), None);
    let metrics = Metrics::register(&registry);
    let node = Node::new(metrics, tracing::Span::current());
    let (node_ref, _) = node.spawn().await.expect("spawn Node");
    node_ref
}

async fn spawn_wal(node: NodeRef, path: PathBuf) -> WalRef<TestContext> {
    Wal::<TestContext, ProtobufCodec>::spawn(
        &TestContext::default(),
        ProtobufCodec,
        path,
        SharedRegistry::new(Default::default(), None),
        tracing::Span::current(),
        node,
    )
    .await
    .expect("spawn Wal")
}

fn vote(height: Height, round: u32) -> Input<TestContext> {
    Input::Vote(SignedVote::new(
        Vote::new_prevote(
            height,
            Round::new(round),
            NilOrVal::Val(Value::new(100).id()),
            Address::new([0; 20]),
        ),
        Signature::test(),
    ))
}

/// Length of one encoded entry's data, so the on-disk position of entry `idx`
/// can be derived without reaching into the WAL crate's private layout.
fn encoded_len(entry: &Input<TestContext>) -> usize {
    let mut buf = Vec::new();
    encode_entry(entry.clone(), &ProtobufCodec, &mut buf).expect("encode_entry");
    buf.len()
}

/// Writes `ENTRIES` prevotes for `height` through the actor, then shuts it down
/// so the file is closed. All entries encode to the same length.
async fn write_log(path: &Path, height: Height) -> usize {
    let node = spawn_node().await;
    let wal = spawn_wal(node.clone(), path.to_path_buf()).await;
    wal.link(node.get_cell());

    let _started: Vec<_> = ractor::call!(wal, WalMsg::StartedHeight, height)
        .expect("StartedHeight call")
        .expect("StartedHeight reply");

    for round in 0..ENTRIES {
        ractor::call!(wal, WalMsg::Append, height, vote(height, round as u32))
            .expect("Append call")
            .expect("Append reply");
    }

    ractor::call!(wal, WalMsg::Flush)
        .expect("Flush call")
        .expect("Flush reply");

    let len = encoded_len(&vote(height, 0));

    wal.stop(None);
    node.stop(None);
    tokio::time::sleep(Duration::from_millis(100)).await;

    len
}

/// Flips one bit inside entry `idx`'s data, the way a bit flip on disk would:
/// the entry's CRC no longer matches, every other entry is untouched.
fn corrupt_entry(path: &Path, idx: usize, data_len: usize) {
    let size = fs::metadata(path).expect("metadata").len() as usize;
    let entry_size = ENTRY_HEADER + data_len;
    let header_size = size - ENTRIES * entry_size;
    let offset = header_size + idx * entry_size + ENTRY_HEADER;

    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("open wal");

    file.seek(SeekFrom::Start(offset as u64)).expect("seek");
    let mut byte = [0u8; 1];
    file.read_exact(&mut byte).expect("read byte");
    byte[0] ^= 0b0000_0001;
    file.seek(SeekFrom::Start(offset as u64)).expect("seek");
    file.write_all(&byte).expect("write byte");
    file.sync_all().expect("sync");
}

/// reproduces obs:replay_stopped_at_unreadable_entry — fails on current code.
///
/// A replay that hits a damaged entry stops there and truncates the log at that
/// index, so the bytes of every later entry — intact ones included — are deleted
/// from disk. Reading past a damaged record is impossible; destroying what
/// follows it is a choice, and it is unrecoverable.
///
/// The contract: stopping at an unreadable entry must not delete the rest of the
/// log.
///
/// Ignored because it fails on current code.
#[tokio::test]
#[ignore]
async fn replay_stopping_at_a_damaged_entry_does_not_delete_the_rest_of_the_log() {
    let tmp = TempDir::new().expect("tempdir");
    let path = tmp.path().join("wal");
    let height = Height::new(1);

    let data_len = write_log(&path, height).await;
    corrupt_entry(&path, 1, data_len);

    let size_before = fs::metadata(&path).expect("metadata").len();

    // The node restarts and consensus asks the WAL for the height it was at.
    let node = spawn_node().await;
    let wal = spawn_wal(node.clone(), path.clone()).await;
    wal.link(node.get_cell());

    let _entries: Vec<_> = ractor::call!(wal, WalMsg::StartedHeight, height)
        .expect("StartedHeight call")
        .expect("StartedHeight reply");

    wal.stop(None);
    node.stop(None);
    tokio::time::sleep(Duration::from_millis(100)).await;

    let size_after = fs::metadata(&path).expect("metadata").len();

    assert_eq!(
        size_after, size_before,
        "the replay truncated the log at the damaged entry, deleting the entries after it"
    );
}

/// reproduces obs:replay_discarded_later_intact_entries — fails on current code.
///
/// The same replay hands consensus only the entries ahead of the damaged one:
/// it breaks out of the loop at the first read error, so entries 2 and 3 — whose
/// CRCs are perfectly valid — are never returned. Those are the node's own
/// later votes for the height it is resuming.
///
/// The contract: a replay must still hand back the entries after a damaged one
/// that read back cleanly.
///
/// Ignored because it fails on current code.
#[tokio::test]
#[ignore]
async fn replay_keeps_the_intact_entries_after_a_damaged_one() {
    let tmp = TempDir::new().expect("tempdir");
    let path = tmp.path().join("wal");
    let height = Height::new(1);

    let data_len = write_log(&path, height).await;
    corrupt_entry(&path, 1, data_len);

    let node = spawn_node().await;
    let wal = spawn_wal(node.clone(), path.clone()).await;
    wal.link(node.get_cell());

    let entries: Vec<_> = ractor::call!(wal, WalMsg::StartedHeight, height)
        .expect("StartedHeight call")
        .expect("StartedHeight reply");

    let recovered = entries.iter().filter(|e| e.is_ok()).count();

    wal.stop(None);
    node.stop(None);

    assert_eq!(
        recovered, ENTRIES - 1,
        "the replay dropped the intact entries that follow the damaged one"
    );
}
