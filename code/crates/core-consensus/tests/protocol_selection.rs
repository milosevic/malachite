//! Selecting a consensus protocol, and what the classic path does with a fast one.

use arc_malachitebft_core_consensus::{Params, ThresholdParams};
use malachitebft_core_types::{ConsensusProtocol, ValuePayload};
use malachitebft_test::{Address, PrivateKey, TestContext};

fn params(protocol: ConsensusProtocol) -> Params<TestContext> {
    Params {
        address: Address::from_public_key(&PrivateKey::from([1u8; 32]).public_key()),
        protocol,
        value_payload: ValuePayload::ProposalAndParts,
        enabled: true,
    }
}

/// Classic is the default, so an existing deployment that says nothing keeps its protocol
/// and its thresholds.
#[test]
fn the_default_protocol_is_classic_with_classic_thresholds() {
    let p = params(ConsensusProtocol::default());
    assert_eq!(p.protocol, ConsensusProtocol::Classic);
    assert_eq!(p.threshold_params(), ThresholdParams::default());
}

/// The thresholds are DERIVED from the protocol, never stored beside it. This is what
/// makes it impossible to configure a fast node that runs on classic quorums.
#[test]
fn thresholds_are_derived_from_the_protocol() {
    let p = params(ConsensusProtocol::Classic);
    assert_eq!(p.threshold_params().quorum, ConsensusProtocol::Classic.quorum());
    assert_eq!(
        p.threshold_params().honest,
        ConsensusProtocol::Classic.honest().expect("classic has one")
    );
}

/// Selecting the fast protocol and running it through the CLASSIC consensus path fails
/// loudly rather than silently using classic thresholds. The fast driver does not exist
/// yet; when it does, the selection happens above this call rather than here.
#[test]
#[should_panic(expected = "the fast protocol has no classic thresholds")]
fn a_fast_protocol_cannot_borrow_classic_thresholds() {
    let _ = params(ConsensusProtocol::Fast).threshold_params();
}
