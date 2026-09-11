//! Tests for protocol selection and the validator-set fault-budget check.

use arc_malachitebft_core_types::{ConsensusProtocol, InadequateValidatorSet, ThresholdParam};
use malachitebft_test::{PrivateKey, TestContext, Validator, ValidatorSet};

fn set(powers: &[u64]) -> ValidatorSet {
    ValidatorSet::new(
        powers
            .iter()
            .enumerate()
            .map(|(i, p)| Validator::new(PrivateKey::from([i as u8; 32]).public_key(), *p))
            .collect::<Vec<_>>(),
    )
}

#[test]
fn classic_and_fast_carry_different_thresholds() {
    assert_eq!(ConsensusProtocol::Classic.quorum(), ThresholdParam::new(2, 3));
    assert_eq!(ConsensusProtocol::Classic.decision(), ThresholdParam::new(2, 3));
    assert_eq!(ConsensusProtocol::Fast.quorum(), ThresholdParam::new(2, 5));
    assert_eq!(ConsensusProtocol::Fast.decision(), ThresholdParam::new(4, 5));
}

/// Classic decides on the same quorum that makes a value valid; Fast needs a strictly
/// stronger one. This is why a commit certificate from one does not prove a decision under
/// the other.
#[test]
fn only_fast_separates_the_quorum_from_the_decision() {
    assert_eq!(
        ConsensusProtocol::Classic.quorum(),
        ConsensusProtocol::Classic.decision()
    );
    assert_ne!(
        ConsensusProtocol::Fast.quorum(),
        ConsensusProtocol::Fast.decision()
    );
}

/// Fast removes the round-skip rule the `f+1` threshold exists for, so it reports no
/// honest threshold at all rather than a fraction a skip could be rebuilt from.
#[test]
fn fast_has_no_honest_threshold() {
    assert_eq!(ConsensusProtocol::Classic.honest(), Some(ThresholdParam::new(1, 3)));
    assert_eq!(ConsensusProtocol::Fast.honest(), None);
    assert!(ConsensusProtocol::Classic.classic_threshold_params().is_some());
    assert!(ConsensusProtocol::Fast.classic_threshold_params().is_none());
}

/// Classic is the default, so an existing deployment that says nothing keeps its protocol.
#[test]
fn classic_is_the_default() {
    assert_eq!(ConsensusProtocol::default(), ConsensusProtocol::Classic);
}

#[test]
fn an_even_set_supports_both_protocols_at_the_right_size() {
    // Four equal validators: one fault is 1/4 of the power — fine for classic (< 1/3),
    // too much for fast (not < 1/5).
    assert!(ConsensusProtocol::Classic.check_validator_set::<TestContext>(&set(&[1, 1, 1, 1])).is_ok());
    assert!(ConsensusProtocol::Fast.check_validator_set::<TestContext>(&set(&[1, 1, 1, 1])).is_err());

    // Six equal validators: one fault is 1/6 — fine for both.
    assert!(ConsensusProtocol::Fast.check_validator_set::<TestContext>(&set(&[1; 6])).is_ok());
}

/// The set the vote keeper's own tests use, and the one Studio chose for its model. It is
/// a perfectly good tally fixture and a hopeless production set for this protocol: one
/// validator holds half the power, so a single fault blows the `f < n/5` budget.
#[test]
fn a_lopsided_set_is_rejected_for_fast() {
    let lopsided = set(&[5, 3, 1, 1]);
    match ConsensusProtocol::Fast.check_validator_set::<TestContext>(&lopsided) {
        Err(InadequateValidatorSet::SingleValidatorExceedsFaultBudget {
            largest,
            total,
            tolerated_denominator,
        }) => {
            assert_eq!(largest, 5);
            assert_eq!(total, 10);
            assert_eq!(tolerated_denominator, 5);
        }
        other => panic!("expected a fault-budget rejection, got {other:?}"),
    }
}

/// The same check catches a classic set where one validator holds a third or more.
#[test]
fn a_validator_holding_a_third_is_rejected_for_classic() {
    // 2 of 4 is half.
    assert!(ConsensusProtocol::Classic.check_validator_set::<TestContext>(&set(&[2, 1, 1])).is_err());
    // 2 of 5 is 40%, still over a third.
    assert!(ConsensusProtocol::Classic.check_validator_set::<TestContext>(&set(&[1, 1, 1, 2])).is_err());
    // 1 of 4 is 25%.
    assert!(ConsensusProtocol::Classic.check_validator_set::<TestContext>(&set(&[1, 1, 1, 1])).is_ok());
}

/// Exactly at the budget is NOT within it — the same strictness the thresholds use.
#[test]
fn exactly_at_the_fault_budget_is_rejected() {
    // total 5, largest 1: 1*5 == 5, so not strictly below a fifth.
    assert!(ConsensusProtocol::Fast.check_validator_set::<TestContext>(&set(&[1, 1, 1, 1, 1])).is_err());
    // total 6, largest 1: 1*5 = 5 < 6.
    assert!(ConsensusProtocol::Fast.check_validator_set::<TestContext>(&set(&[1; 6])).is_ok());
}

/// The `Empty` variant is defensive only: `ValidatorSet::new` panics on an empty set
/// (documented at validator_set.rs), so a caller cannot reach it through the test context.
/// The check still handles zero total power, since a `ValidatorSet` built by other means —
/// its `validators` field is public — can have it. See ledger F-18.
#[test]
fn a_set_with_no_voting_power_is_rejected() {
    assert_eq!(
        ConsensusProtocol::Fast.check_validator_set::<TestContext>(&set(&[0, 0, 0])),
        Err(InadequateValidatorSet::Empty)
    );
}
