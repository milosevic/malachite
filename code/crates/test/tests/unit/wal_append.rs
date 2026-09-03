//! Contract test for the `Wal` actor's answer to an append it does not write.
//!
//! Wired the same way as `node_supervisor`: a real `Node`, the real `Wal` actor
//! and the real protobuf codec, so the append travels the production path.

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

/// reproduces obs:append_dropped_on_height_mismatch — fails on current code.
///
/// The WAL is started at height 2 and then asked to persist a vote for height 1
/// — a late message for the previous height, which is exactly what the actor's
/// "Ignoring append, mismatched height" branch is there to handle. That branch
/// drops the entry and answers the caller `Ok(())` anyway, so consensus is told
/// its vote is durable when nothing was written and goes on to broadcast it.
///
/// The contract: an append the WAL does not write must not be acknowledged as
/// written.
///
/// Ignored because it fails on current code.
#[tokio::test]
#[ignore]
async fn append_at_mismatched_height_is_not_acknowledged_as_written() {
    let node = spawn_node().await;

    let tmp = TempDir::new().expect("tempdir");
    let wal = spawn_wal(node.clone(), tmp.path().join("wal")).await;
    wal.link(node.get_cell());

    // Consensus has moved on to height 2; the WAL follows it there.
    let _started: Vec<_> = ractor::call!(wal, WalMsg::StartedHeight, Height::new(2))
        .expect("StartedHeight call")
        .expect("StartedHeight reply");

    // A late vote for height 1 arrives and is handed to the WAL.
    let reply = ractor::call!(wal, WalMsg::Append, Height::new(1), vote_at(Height::new(1)))
        .expect("Append call");

    assert!(
        reply.is_err(),
        "the WAL acknowledged an append it dropped for a mismatched height"
    );

    node.stop(None);
}
