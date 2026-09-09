//! Actor-level tests for the engine WAL actor's per-height append guard.
//!
//! `engine::wal::Wal` remembers the height it was last told about in its own
//! state, and `Msg::Append` compares each entry's height against it. The
//! mismatch branch is unreachable from the whole-node runs in `tests/it`,
//! where the orchestrator only ever appends at the height it just started, and
//! unreachable from the `arc-malachitebft-wal` suite, which exercises the raw
//! log layer beneath the actor. These tests drive the actor directly so that
//! branch executes.

use std::path::PathBuf;

use ractor::call;
use tempfile::TempDir;

use arc_malachitebft_test::codec::proto::ProtobufCodec;
use arc_malachitebft_test::{Address, Height, Signature, TestContext, Value, Vote};

use malachitebft_core_consensus::Input;
use malachitebft_core_types::{NilOrVal, Round, SignedVote};
use malachitebft_engine::node::{Node, NodeRef};
use malachitebft_engine::wal::{Msg, Wal, WalRef};
use malachitebft_metrics::{Metrics, SharedRegistry};

/// A prevote input, shaped the way `node_supervisor.rs` builds one.
fn prevote_input(height: u64) -> Input<TestContext> {
    Input::Vote(SignedVote::new(
        Vote::new_prevote(
            Height::new(height),
            Round::new(0),
            NilOrVal::Val(Value::new(0xABCD).id()),
            Address::new([1; 20]),
        ),
        Signature::test(),
    ))
}

/// The WAL actor reports a safety failure to the Node, so it needs one to
/// hold. An isolated registry keeps this test's metrics off the global one.
async fn spawn_node() -> NodeRef {
    let registry = SharedRegistry::new(Default::default(), None);
    let metrics = Metrics::register(&registry);
    let node = Node::new(metrics, tracing::Span::current());
    let (node_ref, _) = node.spawn().await.expect("spawn Node");
    node_ref
}

async fn spawn_wal(node: NodeRef, path: PathBuf) -> WalRef<TestContext> {
    Wal::spawn(
        &TestContext::default(),
        ProtobufCodec,
        path,
        SharedRegistry::new(Default::default(), None),
        tracing::Span::current(),
        node,
    )
    .await
    .expect("WAL actor should spawn")
}

/// Puts a WAL actor at `actor_height`, appends an entry stamped
/// `append_height`, then reopens the log with a fresh actor to see what
/// actually survived.
///
/// Reopening matters: `Msg::StartedHeight` short-circuits when the actor is
/// already at the requested height, so asking the *same* actor what it holds
/// would report an empty replay whether or not the entry was written. A fresh
/// actor starts at height zero, so its `StartedHeight` consults the log.
///
/// Returns whether the append was acked, and how many entries were durable.
async fn append_then_reopen(path: PathBuf, actor_height: u64, append_height: u64) -> (bool, usize) {
    let node = spawn_node().await;
    let wal = spawn_wal(node.clone(), path.clone()).await;

    call!(wal, Msg::StartedHeight, Height::new(actor_height))
        .expect("StartedHeight reply")
        .expect("StartedHeight should succeed");

    let acked = call!(
        wal,
        Msg::Append,
        Height::new(append_height),
        prevote_input(append_height)
    )
    .expect("Append reply")
    .is_ok();

    call!(wal, Msg::Flush)
        .expect("Flush reply")
        .expect("Flush should succeed");

    wal.stop_and_wait(None, None)
        .await
        .expect("WAL actor should stop");

    let wal = spawn_wal(node, path).await;

    let durable = call!(wal, Msg::StartedHeight, Height::new(actor_height))
        .expect("StartedHeight reply")
        .expect("StartedHeight should succeed")
        .len();

    wal.stop_and_wait(None, None)
        .await
        .expect("WAL actor should stop");

    (acked, durable)
}

/// Records the mismatch branch as it behaves today: an append whose height has
/// been overtaken is answered with `Ok(())` and never written.
///
/// This is the reachability test for that branch — see
/// `append_ack_implies_the_entry_is_durable` below for the contract the reply
/// ought to satisfy.
#[quint_oracle::test]
#[tokio::test]
async fn append_at_mismatched_height_is_acked_but_not_written() {
    let dir = TempDir::new().expect("temp dir");

    let (acked, durable) = append_then_reopen(dir.path().join("wal"), 2, 1).await;

    assert!(acked, "the actor reports success for a mismatched append");
    assert_eq!(durable, 0, "yet the entry it acked never reached the log");
}

/// Control for the test above: the identical sequence with a matching height
/// does make the entry durable, so the zero there is the height guard and not
/// a broken fixture.
#[quint_oracle::test]
#[tokio::test]
async fn append_at_matching_height_is_durable() {
    let dir = TempDir::new().expect("temp dir");

    let (acked, durable) = append_then_reopen(dir.path().join("wal"), 2, 2).await;

    assert!(acked, "a matching-height append should be acked");
    assert_eq!(durable, 1, "a matching-height append should be replayable");
}

/// reproduces obs:append_dropped_on_height_mismatch — fails on current code.
///
/// The contract behind `append_ack_is_honest`: an `Ok(())` from `Msg::Append`
/// has to mean the entry is durable, because that reply is what consensus
/// treats as permission to publish the vote. A `StartHeight` racing an
/// in-flight `Append` therefore loses a vote the node goes on to broadcast,
/// which is the no-amnesia guarantee the WAL exists to provide.
///
/// v0.8.0 routes a *reported* WAL failure through `hang_on_safety_failure`, but
/// this branch reports success, so that guard never fires for it.
///
/// The honest outcomes are to write the entry or to answer with an error. The
/// current code does neither.
///
/// Ignored because it fails on current code.
#[tokio::test]
#[ignore]
async fn append_ack_implies_the_entry_is_durable() {
    let dir = TempDir::new().expect("temp dir");

    let (acked, durable) = append_then_reopen(dir.path().join("wal"), 2, 1).await;

    if acked {
        assert_eq!(durable, 1, "the actor acked an append it silently dropped");
    }
}

/// A prevote input at `height` from validator `v`, so several entries in one
/// log are distinguishable after a replay.
fn prevote_input_from(height: u64, v: u8) -> Input<TestContext> {
    Input::Vote(SignedVote::new(
        Vote::new_prevote(
            Height::new(height),
            Round::new(0),
            NilOrVal::Val(Value::new(0xABCD).id()),
            Address::new([v; 20]),
        ),
        Signature::test(),
    ))
}

/// Flips one byte inside entry `idx`'s payload, the way bit rot on disk would.
///
/// The on-disk layout is a 12-byte header (version + sequence) followed by
/// entries of `flag(1) | length(8, BE) | crc(4) | data`. Only the payload is
/// touched, so every entry stays correctly framed and the open-time scan —
/// which validates framing, not CRCs — still counts all of them. The damage
/// surfaces later, when the entry is actually read back.
fn corrupt_entry_payload(path: &std::path::Path, idx: usize) {
    let mut bytes = std::fs::read(path).expect("read WAL file");

    let mut pos = 12usize;
    for i in 0..=idx {
        let len = u64::from_be_bytes(bytes[pos + 1..pos + 9].try_into().unwrap()) as usize;
        let data = pos + 13;
        if i == idx {
            assert!(len > 0, "entry {idx} has no payload to corrupt");
            bytes[data] ^= 0xFF;
            std::fs::write(path, &bytes).expect("write WAL file");
            return;
        }
        pos = data + len;
    }

    panic!("entry {idx} not found in the log");
}

/// reproduces obs:replay_stopped_at_unreadable_entry.
///
/// The contract behind `replay_keeps_later_intact_entries`: a replay that hits
/// one unreadable entry must still hand back — and keep — the later entries
/// whose CRC is fine. The WAL is length-framed, so a CRC failure on one
/// payload says nothing about the framing of the entries after it: the reader
/// is still correctly positioned and those entries read back cleanly.
///
/// `fetch_entries` (engine/src/wal/thread.rs) used to call `log.truncate(idx)`
/// at the first read error and break, destroying every later entry on disk. If
/// the damaged entry is an early prevote and a precommit the node already
/// broadcast sits behind it, the node would restart with no record of that
/// precommit and could vote again for a different value at the same height —
/// exactly the amnesia the WAL exists to prevent, caused by damage to an
/// unrelated entry. This test is the regression guard for that fix.
///
/// The realistic path: three entries appended at one height through the WAL
/// actor's public `Msg::Append`, flushed, the process gone; one payload byte
/// rots on disk; the node comes back up and `Msg::StartedHeight` replays.
#[quint_oracle::test]
#[tokio::test]
async fn replay_keeps_entries_after_an_unreadable_one() {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("wal");

    let entries: Vec<_> = (1..=3).map(|v| prevote_input_from(2, v)).collect();

    let node = spawn_node().await;
    let wal = spawn_wal(node.clone(), path.clone()).await;

    call!(wal, Msg::StartedHeight, Height::new(2))
        .expect("StartedHeight reply")
        .expect("StartedHeight should succeed");

    for entry in &entries {
        call!(wal, Msg::Append, Height::new(2), entry.clone())
            .expect("Append reply")
            .expect("Append should succeed");
    }

    call!(wal, Msg::Flush)
        .expect("Flush reply")
        .expect("Flush should succeed");

    wal.stop_and_wait(None, None)
        .await
        .expect("WAL actor should stop");

    // Bit rot on the middle entry only; the first and last are untouched.
    corrupt_entry_payload(&path, 1);

    let wal = spawn_wal(node, path.clone()).await;

    let replayed = call!(wal, Msg::StartedHeight, Height::new(2))
        .expect("StartedHeight reply")
        .expect("StartedHeight should succeed");

    wal.stop_and_wait(None, None)
        .await
        .expect("WAL actor should stop");

    assert!(
        replayed.iter().any(|e| e.is_err()),
        "the damaged entry should be reported as unreadable"
    );

    assert!(
        replayed
            .iter()
            .any(|e| matches!(e, Ok(input) if input == &entries[2])),
        "the last entry still reads back cleanly, yet the replay dropped it"
    );
}

/// reproduces obs:replay_stopped_at_unreadable_entry — the contract assertion
/// for `replay_keeps_later_intact_entries` and `unreadable_entry_is_reported`.
///
/// The contract: a replay that hits one unreadable entry must report that
/// entry AND still hand back every later entry that reads back cleanly,
/// leaving them on disk for the next replay too.
///
/// `fetch_entries` (engine/src/wal/thread.rs) used to push the read error,
/// call `log.truncate(idx)` and break — so a single rotted byte in an early
/// entry deleted every entry behind it from the file. If a precommit the node
/// already broadcast sat behind a damaged prevote, the node would come back up
/// with no record of it and could vote again at the same height: the amnesia
/// the WAL exists to prevent, triggered by damage to an unrelated entry.
///
/// Where `replay_keeps_entries_after_an_unreadable_one` above checks the
/// single replay, this one adds the durability half: it stops and reopens the
/// log a second time and asserts the tail is *still* there, which is what the
/// on-disk truncation destroyed permanently.
///
/// The realistic path: three prevotes appended at one height through the WAL
/// actor's public `Msg::Append`, flushed, the process gone; one payload byte
/// rots on disk; the node restarts and `Msg::StartedHeight` replays — twice.
///
/// Ignored so it stays a dormant contract guard; run with `-- --ignored`.
#[tokio::test]
#[ignore]
async fn replay_reports_the_damaged_entry_and_keeps_the_tail_durable() {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("wal");

    let entries: Vec<_> = (1..=3).map(|v| prevote_input_from(2, v)).collect();

    let node = spawn_node().await;
    let wal = spawn_wal(node.clone(), path.clone()).await;

    call!(wal, Msg::StartedHeight, Height::new(2))
        .expect("StartedHeight reply")
        .expect("StartedHeight should succeed");

    for entry in &entries {
        call!(wal, Msg::Append, Height::new(2), entry.clone())
            .expect("Append reply")
            .expect("Append should succeed");
    }

    call!(wal, Msg::Flush)
        .expect("Flush reply")
        .expect("Flush should succeed");

    wal.stop_and_wait(None, None)
        .await
        .expect("WAL actor should stop");

    // Bit rot on the middle entry only; the first and last stay intact and
    // correctly framed, so the reader remains positioned on entry boundaries.
    corrupt_entry_payload(&path, 1);

    // First restart: the replay must report entry 1 and return 0 and 2.
    for round in 0..2 {
        let wal = spawn_wal(node.clone(), path.clone()).await;

        let replayed = call!(wal, Msg::StartedHeight, Height::new(2))
            .expect("StartedHeight reply")
            .expect("StartedHeight should succeed");

        wal.stop_and_wait(None, None)
            .await
            .expect("WAL actor should stop");

        assert_eq!(
            replayed.len(),
            3,
            "replay {round} dropped entries the log still holds"
        );

        assert!(
            replayed[1].is_err(),
            "replay {round} did not report the damaged entry"
        );

        for i in [0, 2] {
            assert!(
                matches!(&replayed[i], Ok(input) if input == &entries[i]),
                "replay {round} lost intact entry {i}, which sits behind a damaged one"
            );
        }
    }
}

/// reproduces the `entries_belong_to_the_logs_height` violation — fails on
/// current code.
///
/// The contract: every entry the WAL holds was appended at the height its
/// sequence number names, so a replay for height H can only hand back entries
/// written at H. The counterexample's violating step is an append that lands
/// in a log whose sequence names a different height.
///
/// How the real code gets there: `pre_start` (engine/src/wal.rs:295-303) starts
/// a fresh actor at `Height::ZERO` whatever the log's sequence is, and
/// `Msg::StartedHeight` short-circuits when `state.height == height`
/// (wal.rs:88-99) — it returns early *without* asking the thread to reset the
/// log. So a restarted node that begins at height zero over a WAL file left at
/// sequence 3 never syncs the two: the following `Msg::Append` at height zero
/// matches the actor's in-memory height and is written into a log still
/// labelled height 3. The next restart replays that file for height 3 and
/// hands consensus a height-zero vote as height-3 state.
///
/// Everything here goes through the actor's public message API under default
/// settings: two ordinary restarts around a crash, no internal access.
///
/// Ignored because it fails on current code; run with `-- --ignored`.
#[tokio::test]
#[ignore]
async fn entries_belong_to_the_logs_height() {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("wal");

    let node = spawn_node().await;

    // Run 1: the node reaches height 3 and persists a prevote there, so the
    // file on disk carries sequence 3.
    let wal = spawn_wal(node.clone(), path.clone()).await;

    call!(wal, Msg::StartedHeight, Height::new(3))
        .expect("StartedHeight reply")
        .expect("StartedHeight should succeed");

    call!(wal, Msg::Append, Height::new(3), prevote_input(3))
        .expect("Append reply")
        .expect("Append should succeed");

    call!(wal, Msg::Flush)
        .expect("Flush reply")
        .expect("Flush should succeed");

    wal.stop_and_wait(None, None)
        .await
        .expect("WAL actor should stop");

    // Run 2: the node comes back up starting at height zero — which is where
    // a fresh actor's in-memory height already sits, so StartedHeight returns
    // early and the log keeps sequence 3.
    let wal = spawn_wal(node.clone(), path.clone()).await;

    call!(wal, Msg::StartedHeight, Height::new(0))
        .expect("StartedHeight reply")
        .expect("StartedHeight should succeed");

    call!(wal, Msg::Append, Height::new(0), prevote_input(0))
        .expect("Append reply")
        .expect("Append should succeed");

    call!(wal, Msg::Flush)
        .expect("Flush reply")
        .expect("Flush should succeed");

    wal.stop_and_wait(None, None)
        .await
        .expect("WAL actor should stop");

    // Run 3: the log is replayed for the height its sequence names. Only
    // entries written at that height may come back.
    let wal = spawn_wal(node, path).await;

    let replayed = call!(wal, Msg::StartedHeight, Height::new(3))
        .expect("StartedHeight reply")
        .expect("StartedHeight should succeed");

    wal.stop_and_wait(None, None)
        .await
        .expect("WAL actor should stop");

    let stray = prevote_input(0);

    assert!(
        !replayed
            .iter()
            .any(|e| matches!(e, Ok(input) if input == &stray)),
        "the height-3 replay handed back an entry appended at height 0"
    );
}
