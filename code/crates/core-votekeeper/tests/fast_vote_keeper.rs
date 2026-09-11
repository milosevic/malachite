//! Behavior tests for the Fast Tendermint vote keeper.
//!
//! The point of this keeper is that TWO thresholds act on ONE tally and must be reported
//! independently: `2f+1` makes a value valid (Algorithm 1, L36) and `n - f` decides it
//! (L42). Most of what follows exists to pin that, plus the absence of any `f+1` rule.

use malachitebft_core_types::{NilOrVal, Round, SignedVote};

use arc_malachitebft_core_votekeeper::fast::keeper::{FastVoteKeeper, Output};
use arc_malachitebft_core_votekeeper::fast::params::FastThresholdParams;

use malachitebft_test::{
    Address, Height, PrivateKey, Signature, TestContext, Validator, ValidatorSet, ValueId, Vote,
};

fn setup<const N: usize>(powers: [u64; N]) -> ([Address; N], FastVoteKeeper<TestContext>) {
    let mut addrs = [Address::new([0; 20]); N];
    let mut vals = Vec::with_capacity(N);
    for i in 0..N {
        let pk = PrivateKey::from([i as u8; 32]);
        addrs[i] = Address::from_public_key(&pk.public_key());
        vals.push(Validator::new(pk.public_key(), powers[i]));
    }
    let keeper = FastVoteKeeper::new(ValidatorSet::new(vals), FastThresholdParams::default());
    (addrs, keeper)
}

fn vote_for(round: u32, value: NilOrVal<ValueId>, addr: Address) -> SignedVote<TestContext> {
    SignedVote::new(
        Vote::new_precommit(Height::new(1), Round::new(round), value, addr),
        Signature::test(),
    )
}

fn val(v: u64) -> NilOrVal<ValueId> {
    NilOrVal::Val(ValueId::new(v))
}

// ------------------------------------------------------ the two thresholds, one tally

/// The core claim. With 6 unit validators: `2f+1` is met at 3 votes (3 > 2/5 of 6 = 2.4)
/// and `n - f` at 5 (5 > 4/5 of 6 = 4.8). Both must be reported for the same round, in
/// order, with the first NOT suppressing the second.
#[test]
fn both_thresholds_fire_for_one_round_in_order() {
    let (a, mut k) = setup([1, 1, 1, 1, 1, 1]);

    assert!(k.apply_vote(vote_for(0, val(7), a[0])).is_empty());
    assert!(k.apply_vote(vote_for(0, val(7), a[1])).is_empty());

    // Third vote: 2f+1 for the value.
    let third = k.apply_vote(vote_for(0, val(7), a[2]));
    assert_eq!(third, vec![Output::VoteQuorumValue(Round::new(0), ValueId::new(7))]);

    assert!(k.apply_vote(vote_for(0, val(7), a[3])).is_empty());

    // Fifth vote: n - f for the value, and n - f for any. The earlier 2f+1 must not have
    // swallowed these.
    let fifth = k.apply_vote(vote_for(0, val(7), a[4]));
    assert_eq!(
        fifth,
        vec![Output::DecisionQuorumValue(Round::new(0), ValueId::new(7)), Output::QuorumAny(Round::new(0))]
    );
}

/// One vote can cross BOTH thresholds at once when weights are uneven, which is why
/// `apply_vote` returns a list where the classic keeper returns at most one output.
/// Powers [4, 5, 1], total 10: `2f+1` needs > 4, `n - f` needs > 8.
#[test]
fn a_single_vote_can_cross_both_thresholds_at_once() {
    let (a, mut k) = setup([4, 5, 1]);

    assert!(k.apply_vote(vote_for(0, val(1), a[0])).is_empty(), "4 is below 2f+1");

    let out = k.apply_vote(vote_for(0, val(1), a[1]));
    assert_eq!(
        out,
        vec![
            Output::VoteQuorumValue(Round::new(0), ValueId::new(1)),
            Output::DecisionQuorumValue(Round::new(0), ValueId::new(1)),
            Output::QuorumAny(Round::new(0))
        ],
        "one vote takes the tally from 4 to 9, crossing 2f+1 and n-f together"
    );
}

/// Each threshold reports at most once per round.
#[test]
fn each_threshold_reports_at_most_once_per_round() {
    let (a, mut k) = setup([1, 1, 1, 1, 1, 1]);
    for i in 0..5 {
        k.apply_vote(vote_for(0, val(7), a[i]));
    }
    assert!(k.apply_vote(vote_for(0, val(7), a[5])).is_empty(), "nothing new to report");
}

/// Exactly at a threshold is NOT met — the strict inequality both protocols depend on.
/// 5 unit validators: `2f+1` needs > 2 (2 is exactly 2/5), `n - f` needs > 4.
#[test]
fn exactly_at_a_threshold_is_not_met() {
    let (a, mut k) = setup([1, 1, 1, 1, 1]);

    k.apply_vote(vote_for(0, val(3), a[0]));
    let at_two_fifths = k.apply_vote(vote_for(0, val(3), a[1]));
    assert!(at_two_fifths.is_empty(), "2 of 5 is exactly 2/5, so not met");
    assert!(!k.has_vote_quorum(Round::new(0), &ValueId::new(3)));

    let over = k.apply_vote(vote_for(0, val(3), a[2]));
    assert_eq!(over, vec![Output::VoteQuorumValue(Round::new(0), ValueId::new(3))]);

    k.apply_vote(vote_for(0, val(3), a[3]));
    assert!(!k.has_decision_quorum(Round::new(0), &ValueId::new(3)), "4 of 5 is exactly 4/5");
    k.apply_vote(vote_for(0, val(3), a[4]));
    assert!(k.has_decision_quorum(Round::new(0), &ValueId::new(3)));
}

// ------------------------------------------------------ nil, and what it does not count for

/// Nil votes count toward the quorum-any that advances a round, but never toward a value
/// threshold.
#[test]
fn nil_votes_count_for_quorum_any_but_never_for_a_value() {
    let (a, mut k) = setup([1, 1, 1, 1, 1, 1]);

    for i in 0..4 {
        assert!(k.apply_vote(vote_for(0, NilOrVal::Nil, a[i])).is_empty());
    }
    let fifth = k.apply_vote(vote_for(0, NilOrVal::Nil, a[4]));
    assert_eq!(fifth, vec![Output::QuorumAny(Round::new(0))], "nil reaches n-f for any, and nothing else");
}

/// A quorum split across different values reaches quorum-any and no value threshold.
#[test]
fn a_split_quorum_reaches_only_quorum_any() {
    let (a, mut k) = setup([1, 1, 1, 1, 1, 1]);

    k.apply_vote(vote_for(0, val(1), a[0]));
    k.apply_vote(vote_for(0, val(2), a[1]));
    k.apply_vote(vote_for(0, val(3), a[2]));
    k.apply_vote(vote_for(0, val(1), a[3]));
    let fifth = k.apply_vote(vote_for(0, val(2), a[4]));

    assert_eq!(fifth, vec![Output::QuorumAny(Round::new(0))]);
    assert!(!k.has_vote_quorum(Round::new(0), &ValueId::new(1)));
}

// ------------------------------------------------------ there is no f+1 rule

/// Votes in a higher round report that round's own thresholds and nothing else. There is
/// no `SkipRound`: the paper removes the f+1 one-correct-process rule, so a couple of
/// future-round votes must produce no output at all.
#[test]
fn future_round_votes_never_produce_a_skip() {
    let (a, mut k) = setup([1, 1, 1, 1, 1, 1]);

    // f+1 = 2 votes in a far future round would trigger SkipRound in classic Tendermint.
    assert!(k.apply_vote(vote_for(9, val(1), a[0])).is_empty());
    assert!(k.apply_vote(vote_for(9, val(1), a[1])).is_empty());

    // Only the round's own 2f+1 reports anything.
    assert_eq!(
        k.apply_vote(vote_for(9, val(1), a[2])),
        vec![Output::VoteQuorumValue(Round::new(9), ValueId::new(1))],
        "the output carries the round it is for, which the consumer must check"
    );
}

// ------------------------------------------------------ equivocation

/// A conflicting second vote becomes evidence and is NOT tallied, so equivocation cannot
/// manufacture a quorum.
#[test]
fn equivocation_is_recorded_as_evidence_and_never_tallied() {
    let (a, mut k) = setup([1, 1, 1, 1, 1, 1]);

    k.apply_vote(vote_for(0, val(1), a[0]));
    k.apply_vote(vote_for(0, val(1), a[1]));

    // a[0] equivocates toward the value that would otherwise reach 2f+1.
    let out = k.apply_vote(vote_for(0, val(1), a[0]));
    assert!(out.is_empty(), "a duplicate from a counted validator reports nothing");

    let conflicting = k.apply_vote(vote_for(0, val(2), a[0]));
    assert!(conflicting.is_empty(), "the conflicting vote is not tallied");
    assert_eq!(k.evidence().len(), 1, "it is recorded as evidence instead");

    // The tally is still only two voters, so no threshold is met.
    assert!(!k.has_vote_quorum(Round::new(0), &ValueId::new(1)));
    assert!(!k.has_vote_quorum(Round::new(0), &ValueId::new(2)));
}

// ------------------------------------------------------ housekeeping

/// A vote from outside the validator set is discarded and creates no round state.
#[test]
fn unknown_validator_is_discarded() {
    let (_, mut k) = setup([1, 1, 1]);
    let stranger = Address::from_public_key(&PrivateKey::from([99u8; 32]).public_key());

    assert!(k.apply_vote(vote_for(0, val(1), stranger)).is_empty());
    assert!(!k.has_vote_quorum(Round::new(0), &ValueId::new(1)));
}

/// Pruning drops old rounds but never the evidence.
#[test]
fn pruning_drops_rounds_and_keeps_evidence() {
    let (a, mut k) = setup([1, 1, 1, 1, 1, 1]);

    k.apply_vote(vote_for(0, val(1), a[0]));
    k.apply_vote(vote_for(0, val(2), a[0])); // equivocation -> evidence
    for i in 0..3 {
        k.apply_vote(vote_for(5, val(9), a[i]));
    }
    assert!(k.has_vote_quorum(Round::new(5), &ValueId::new(9)));

    k.prune_votes(Round::new(5));

    assert!(k.has_vote_quorum(Round::new(5), &ValueId::new(9)), "round 5 survives");
    assert_eq!(k.evidence().len(), 1, "evidence is never pruned");
}

// ---------------------------------------------- regression found by independent review

/// Fast Tendermint has ONE voting step, named precommit. A prevote is not part of this
/// protocol and must not be tallied: counting it would let a value reach a threshold on
/// votes the protocol never defined, and would misread a prevote/precommit pair from one
/// validator as equivocation.
#[test]
fn a_prevote_is_never_tallied() {
    let (a, mut k) = setup([1, 1, 1, 1, 1, 1]);

    let prevote = |addr| {
        SignedVote::new(
            Vote::new_prevote(Height::new(1), Round::new(0), val(7), addr),
            Signature::test(),
        )
    };

    for i in 0..5 {
        assert!(k.apply_vote(prevote(a[i])).is_empty(), "prevotes report nothing");
    }
    assert!(
        !k.has_vote_quorum(Round::new(0), &ValueId::new(7)),
        "five prevotes must not make a value valid"
    );
    assert!(!k.has_decision_quorum(Round::new(0), &ValueId::new(7)));

    // And a precommit from a validator that already prevoted is NOT equivocation.
    assert!(k.apply_vote(vote_for(0, val(9), a[0])).is_empty());
    assert_eq!(k.evidence().len(), 0, "a prevote/precommit pair is not a double vote");
}

/// L27 verifies a re-proposal against `2f+1` votes from an EARLIER round, and L42's
/// decision quorum may come from a different round than the proposal. Pruning the tallies
/// must not destroy the answer to either question.
#[test]
fn pruning_keeps_the_cross_round_justification() {
    let (a, mut k) = setup([1, 1, 1, 1, 1, 1]);

    for i in 0..5 {
        k.apply_vote(vote_for(2, val(9), a[i]));
    }
    assert!(k.has_vote_quorum(Round::new(2), &ValueId::new(9)));
    assert!(k.has_decision_quorum(Round::new(2), &ValueId::new(9)));

    k.prune_votes(Round::new(7));

    assert!(
        k.has_vote_quorum(Round::new(2), &ValueId::new(9)),
        "the 2f+1 justification L27 needs must survive pruning"
    );
    assert!(
        k.has_decision_quorum(Round::new(2), &ValueId::new(9)),
        "and so must the cross-round n-f quorum L42 may decide on"
    );
}

/// A pruned round must not re-report its thresholds if its votes arrive again through
/// sync or WAL replay.
#[test]
fn a_pruned_round_does_not_report_its_thresholds_twice() {
    let (a, mut k) = setup([1, 1, 1, 1, 1, 1]);

    for i in 0..3 {
        k.apply_vote(vote_for(1, val(4), a[i]));
    }
    k.prune_votes(Round::new(6));

    for i in 0..3 {
        assert!(
            k.apply_vote(vote_for(1, val(4), a[i])).is_empty(),
            "a replayed vote for a pruned round reports nothing"
        );
    }
}

/// Algorithm 1 defines no vote at an undefined round.
#[test]
fn a_vote_at_an_undefined_round_is_discarded() {
    let (a, mut k) = setup([1, 1, 1]);
    let nil_round = SignedVote::new(
        Vote::new_precommit(Height::new(1), Round::Nil, val(1), a[0]),
        Signature::test(),
    );
    assert!(k.apply_vote(nil_round).is_empty());
    assert!(!k.has_vote_quorum(Round::Nil, &ValueId::new(1)));
}
