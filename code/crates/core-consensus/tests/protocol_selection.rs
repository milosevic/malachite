//! Selecting a consensus protocol, and why the classic path cannot hold one it does not
//! implement.

use arc_malachitebft_core_consensus::{Params, ThresholdParams};
use malachitebft_core_types::{ConsensusProtocol, ValuePayload};
use malachitebft_test::{Address, PrivateKey, TestContext};

fn classic() -> Params<TestContext> {
    Params::<TestContext>::classic(
        Address::from_public_key(&PrivateKey::from([1u8; 32]).public_key()),
        ValuePayload::ProposalAndParts,
        true,
    )
}

/// Classic is what this path runs, so an existing deployment keeps its protocol and its
/// thresholds.
#[test]
fn the_classic_constructor_yields_classic_thresholds() {
    let p = classic();
    assert_eq!(p.protocol(), ConsensusProtocol::Classic);
    assert_eq!(p.threshold_params(), ThresholdParams::default());
}

/// The thresholds are DERIVED from the protocol, never stored beside it. That is what
/// makes it impossible to configure a fast node running on classic quorums.
#[test]
fn thresholds_are_derived_from_the_protocol() {
    let p = classic();
    assert_eq!(p.threshold_params().quorum, ConsensusProtocol::Classic.quorum());
    assert_eq!(
        p.threshold_params().honest,
        ConsensusProtocol::Classic.honest().expect("classic has one")
    );
}

/// The protocol field is PRIVATE and `classic` is the only constructor, so no caller can
/// put a protocol into this type that the classic consensus path does not implement — not
/// at construction and not afterwards.
///
/// This replaced an `expect` that was safe only by convention: while the field was public,
/// `state.params.protocol = Fast` after construction was legal, and the next
/// `threshold_params()` would abort inside a handler — or inside the `info!` block that
/// logs the required voting power.
///
/// The compile-fail case is the point of this test and cannot be asserted at runtime:
///
/// ```compile_fail
/// # use arc_malachitebft_core_consensus::Params;
/// # use malachitebft_core_types::ConsensusProtocol;
/// # use malachitebft_test::TestContext;
/// # fn f(p: &mut Params<TestContext>) {
/// p.protocol = ConsensusProtocol::Fast; // private field
/// # }
/// ```
#[test]
fn the_protocol_cannot_be_changed_after_construction() {
    let p = classic();
    assert_eq!(p.protocol(), ConsensusProtocol::Classic);
    // `threshold_params` is total rather than fallible precisely because of that.
    let _: ThresholdParams = p.threshold_params();
}
