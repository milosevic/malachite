//! Contract test for what the `Wal` actor hands back when it is told about a
//! height it already believes it is at.
//!
//! Wired the same way as `node_supervisor`: a real `Node`, the real `Wal` actor
//! and the real protobuf codec, so the messages travel the production path.

use tempfile::TempDir;

use arc_malachitebft_test::codec::proto::ProtobufCodec;
use arc_malachitebft_test::{Address, Height, Signature, TestContext, Value, Vote};

use malachitebft_core_consensus::Input;
use malachitebft_core_types::{NilOrVal, Round, SignedVote};
use malachitebft_engine::node::{Node, NodeRef};
use malachitebft_engine::wal::{Msg as WalMsg, Wal, WalRef};
use malachitebft_metrics::{Metrics, SharedRegistry};

async fn spawn_node() -> NodeRef {
    let registry = SharedRegistry::new(Default::default(), None);
    let metrics = Metrics::register(&registry);
    let node = Node::new(metrics, tracing::Span::current());
    let (node_ref, _) = node.spawn().await.expect("spawn Node");
    node_ref
}

async fn spawn_wal(node: NodeRef, path: std::path::PathBuf) -> WalRef<TestContext> {
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

fn vote_at(height: Height) -> Input<TestContext> {
    Input::Vote(SignedVote::new(
        Vote::new_prevote(
            height,
            Round::new(0),
            NilOrVal::Val(Value::new(100).id()),
            Address::new([0; 20]),
        ),
        Signature::test(),
    ))
}

/// reproduces obs:started_height_returned_early — fails on current code.
///
/// Consensus recovers the votes it already cast for a height by asking the WAL
/// to start that height: `wal_fetch` replays whatever comes back. But when the
/// actor finds it is already at that height it returns an empty list without
/// consulting the log at all, so a second StartedHeight for the height in
/// progress reports "nothing persisted" while the node's own prevote is sitting
/// in the log — exactly the record that stops it from signing twice.
///
/// Driven through the actor's own message API with the production codec: start
/// height 1, persist a prevote for it, flush, then start height 1 again.
///
/// The contract: StartedHeight must report the entries the log holds for that
/// height, whatever the actor believed its height already was.
///
/// Ignored because it fails on current code.
#[tokio::test]
#[ignore]
async fn started_height_at_the_current_height_still_reports_persisted_entries() {
    let node = spawn_node().await;

    let tmp = TempDir::new().expect("tempdir");
    let wal = spawn_wal(node.clone(), tmp.path().join("wal")).await;
    wal.link(node.get_cell());

    let height = Height::new(1);

    let _started: Vec<_> = ractor::call!(wal, WalMsg::StartedHeight, height)
        .expect("StartedHeight call")
        .expect("StartedHeight reply");

    ractor::call!(wal, WalMsg::Append, height, vote_at(height))
        .expect("Append call")
        .expect("Append reply");

    ractor::call!(wal, WalMsg::Flush)
        .expect("Flush call")
        .expect("Flush reply");

    let entries: Vec<_> = ractor::call!(wal, WalMsg::StartedHeight, height)
        .expect("StartedHeight call")
        .expect("StartedHeight reply");

    assert_eq!(
        entries.len(),
        1,
        "the WAL reported no entries for a height whose prevote it had persisted"
    );

    node.stop(None);
}
