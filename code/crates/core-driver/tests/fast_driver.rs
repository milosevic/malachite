//! Behavior tests for the Fast Tendermint driver.
//!
//! The driver exists for the three rules neither the state machine nor the vote keeper can
//! satisfy alone: L27's justified re-proposal, L42's cross-round decision, and L15-L16's
//! identifier-to-value resolution. These pin those.

use malachitebft_core_types::{
    Context, NilOrVal, Proposal as _, Round, SignedVote, Timeout, TimeoutKind, Validity,
    Value as _, Vote as _,
};

use arc_malachitebft_core_driver::fast::driver::{Driver, Input, Output};
use malachitebft_core_votekeeper::fast::params::FastThresholdParams;

use malachitebft_test::{
    Address, Height, PrivateKey, Signature, TestContext, Validator, ValidatorSet, Value, ValueId,
    Vote,
};

/// Six equal validators: `2f+1` is 3 votes, `n-f` is 5.
fn driver_with(me_is_proposer: bool) -> ([Address; 6], Driver<TestContext>) {
    let mut addrs = [Address::new([0; 20]); 6];
    let mut vals = Vec::new();
    for i in 0..6 {
        let pk = PrivateKey::from([i as u8; 32]);
        addrs[i] = Address::from_public_key(&pk.public_key());
        vals.push(Validator::new(pk.public_key(), 1));
    }
    let me = addrs[0];
    let proposer = if me_is_proposer { addrs[0] } else { addrs[1] };
    let driver = Driver::new(
        TestContext::new(),
        Height::new(1),
        ValidatorSet::new(vals),
        me,
        proposer,
        FastThresholdParams::default(),
    );
    (addrs, driver)
}

fn fresh(round: u32, v: u64, proposer: Address) -> <TestContext as Context>::Proposal {
    TestContext::new().new_proposal(Height::new(1), Round::new(round), Value::new(v), Round::Nil, proposer)
}

fn reproposal(round: u32, v: u64, vr: u32, proposer: Address) -> <TestContext as Context>::Proposal {
    TestContext::new().new_proposal(Height::new(1), Round::new(round), Value::new(v), Round::new(vr), proposer)
}

fn vote(round: u32, v: u64, addr: Address) -> SignedVote<TestContext> {
    SignedVote::new(
        Vote::new_precommit(Height::new(1), Round::new(round), NilOrVal::Val(ValueId::new(v)), addr),
        Signature::test(),
    )
}

// ------------------------------------------------------------------ L27

/// A re-proposal is only handed to the state machine once `2f+1` votes from the round it
/// names actually exist. Without the keeper check the state machine would be asked to
/// trust a justification nobody verified.
#[test]
fn an_unjustified_reproposal_is_not_accepted() {
    let (a, mut d) = driver_with(false);
    d.process(Input::NewRound(Round::new(0)));
    d.set_proposer(a[1]);
    d.process(Input::NewRound(Round::new(1)));

    // Nobody has voted, so nothing justifies a re-proposal claiming round 0.
    let out = d.process(Input::Proposal(reproposal(1, 7, 0, a[1]), Validity::Valid));

    // It is routed as an invalid re-proposal, so the node votes nil rather than for it.
    match out.as_slice() {
        [Output::Vote(v)] => assert_eq!(*v.value(), NilOrVal::Nil, "must vote nil"),
        other => panic!("expected a nil vote, got {other:?}"),
    }
}

/// With the justification present, the same re-proposal is accepted and drawn a vote.
#[test]
fn a_justified_reproposal_is_accepted() {
    let (a, mut d) = driver_with(false);
    d.process(Input::NewRound(Round::new(0)));

    // Three of six validators vote for the value in round 0: that is 2f+1.
    for i in 0..3 {
        d.process(Input::Vote(vote(0, 7, a[i])));
    }

    d.set_proposer(a[1]);
    d.process(Input::NewRound(Round::new(1)));
    let out = d.process(Input::Proposal(reproposal(1, 7, 0, a[1]), Validity::Valid));

    match out.as_slice() {
        [Output::Vote(v)] => assert_eq!(
            *v.value(),
            NilOrVal::Val(ValueId::new(7)),
            "the justification exists, so vote for it"
        ),
        other => panic!("expected a vote for the value, got {other:?}"),
    }
}

// ------------------------------------------------------------------ L42

/// The decision pairs a fresh proposal from ONE round with `n-f` votes from ANOTHER. The
/// proposal that supplies the value may be several rounds behind the quorum that decides.
#[test]
fn a_decision_pairs_a_quorum_with_a_proposal_from_an_earlier_round() {
    let (a, mut d) = driver_with(false);
    d.process(Input::NewRound(Round::new(0)));

    // A fresh proposal in round 0, which we retain.
    d.process(Input::Proposal(fresh(0, 7, a[1]), Validity::Valid));

    // Move on, then reach n-f votes for that value in a LATER round.
    d.set_proposer(a[2]);
    d.process(Input::NewRound(Round::new(1)));

    let mut decided = None;
    for i in 0..5 {
        for out in d.process(Input::Vote(vote(1, 7, a[i]))) {
            if let Output::Decision(round, value) = out {
                decided = Some((round, value));
            }
        }
    }

    let (round, value) = decided.expect("five of six votes is n-f, so it must decide");
    assert_eq!(round, Round::new(0), "the decision carries the PROPOSAL's round");
    assert_eq!(value, Value::new(7));
    assert_eq!(d.decision().map(|(_, v)| v.clone()), Some(Value::new(7)));
}

/// L42 is a symmetric `upon`: both conjuncts persist and whichever arrives SECOND fires
/// it. A quorum arriving before its proposal must not be lost.
///
/// An earlier version of this test asserted only the first half — that the quorum decides
/// nothing — and so pinned a liveness bug as intended behaviour. The keeper latches each
/// threshold once and never re-reports it, so the decision was gone for good. Votes before
/// value is the NORMAL ordering for a lagging node: votes are small, values are large, and
/// sync delivers certificates ahead of payloads.
#[test]
fn a_quorum_that_arrives_before_its_proposal_still_decides() {
    let (a, mut d) = driver_with(false);
    d.process(Input::NewRound(Round::new(0)));

    // The quorum lands first. Nothing supplies the value yet, so nothing decides.
    for i in 0..5 {
        for out in d.process(Input::Vote(vote(0, 7, a[i]))) {
            assert!(
                !matches!(out, Output::Decision(..)),
                "no value is available yet, so nothing may be decided"
            );
        }
    }
    assert!(d.decision().is_none(), "not yet");

    // The proposal arrives afterwards and completes the rule.
    let out = d.process(Input::Proposal(fresh(0, 7, a[1]), Validity::Valid));
    assert!(
        out.iter().any(|o| matches!(o, Output::Decision(..))),
        "the second conjunct fires the rule, got {out:?}"
    );
    assert_eq!(d.decision().map(|(_, v)| v.clone()), Some(Value::new(7)));
}

/// Only a proposal the application ACCEPTED may supply a value for a decision. Retaining
/// one it rejected would let an invalid value be decided at L42.
#[test]
fn an_invalid_proposal_never_supplies_a_decision() {
    let (a, mut d) = driver_with(false);
    d.process(Input::NewRound(Round::new(0)));

    d.process(Input::Proposal(fresh(0, 7, a[1]), Validity::Invalid));

    for i in 0..5 {
        for out in d.process(Input::Vote(vote(0, 7, a[i]))) {
            assert!(
                !matches!(out, Output::Decision(..)),
                "the only proposal for this value was rejected by the application"
            );
        }
    }
    assert!(d.decision().is_none());
}

/// A proposer that holds an identifier valid but never saw the fresh proposal carrying its
/// value cannot build the re-proposal. That is ORDINARY — `valid` is set from vote
/// quorums, and votes carry only `id(v)`.
///
/// It must not stall: emitting nothing left the node in Propose as proposer with no
/// proposal, no timeout and no wait, until some other node's quorum happened to arm one.
#[test]
fn a_proposer_that_cannot_build_its_reproposal_still_schedules_a_timeout() {
    let (a, mut d) = driver_with(false);
    d.process(Input::NewRound(Round::new(0)));

    // 2f+1 votes make the value valid. No proposal for it was ever seen.
    for i in 0..3 {
        d.process(Input::Vote(vote(0, 7, a[i])));
    }

    // We propose round 1, holding (0, id(7)) valid with no value behind it.
    d.set_proposer(a[0]);
    let out = d.process(Input::NewRound(Round::new(1)));

    assert!(
        out.iter().any(|o| matches!(
            o,
            Output::ScheduleTimeout(t) if t.kind == TimeoutKind::Propose
        )),
        "the round must still be able to end, got {out:?}"
    );
    assert!(
        !out.iter().any(|o| matches!(o, Output::Proposal(_))),
        "and no proposal may be invented"
    );
}

// ------------------------------------------------------------------ L15-L16

/// The state machine re-proposes an IDENTIFIER. The driver resolves it back to the value
/// the original fresh proposal carried, and emits a real proposal.
#[test]
fn a_repropose_is_resolved_into_a_full_proposal() {
    let (a, mut d) = driver_with(false);
    d.process(Input::NewRound(Round::new(0)));
    d.process(Input::Proposal(fresh(0, 7, a[1]), Validity::Valid));

    // 2f+1 votes make it valid, so a later round re-proposes it.
    for i in 0..3 {
        d.process(Input::Vote(vote(0, 7, a[i])));
    }

    // We are the proposer of round 1, and we already hold a valid value.
    d.set_proposer(a[0]);
    let out = d.process(Input::NewRound(Round::new(1)));

    match out.as_slice() {
        [Output::Proposal(p)] => {
            assert_eq!(*p.value(), Value::new(7), "resolved from the retained proposal");
            assert_eq!(p.pol_round(), Round::new(0), "carrying the justifying round");
            assert_eq!(p.round(), Round::new(1), "proposed in the round we are at");
        }
        other => panic!("expected a resolved proposal, got {other:?}"),
    }
}

// ------------------------------------------------------------------ plumbing

/// The propose timeout draws a nil vote; a timeout kind this protocol has no step for is
/// ignored rather than misrouted.
#[test]
fn timeouts_route_by_kind() {
    let (_, mut d) = driver_with(false);
    d.process(Input::NewRound(Round::new(0)));

    let out = d.process(Input::TimeoutElapsed(Timeout {
        round: Round::new(0),
        kind: TimeoutKind::Propose,
    }));
    assert!(matches!(out.as_slice(), [Output::Vote(_)]), "propose timeout votes nil");

    let ignored = d.process(Input::TimeoutElapsed(Timeout {
        round: Round::new(0),
        kind: TimeoutKind::Prevote,
    }));
    assert!(ignored.is_empty(), "this protocol has no prevote step");
}

// ------------------------------------------------------ equivocation, at the driver

/// A validator that votes twice for different values in one round must have the second
/// vote recorded as evidence, never tallied. The driver is the layer where a tallied
/// equivocation would become a quorum input and, through L42, a decision — so the claim
/// worth pinning here is that no round input escapes.
///
/// Four honest validators vote for 7 and a fifth votes for 9; the fifth then equivocates
/// toward 7. Counting that second vote would make five of six — `n-f` — and decide.
///
/// reproduces obs:equivocating_vote_not_tallied — asserts the keeper's equivocation guard
/// holds at the driver boundary.
#[test]
fn an_equivocating_vote_cannot_manufacture_a_decision() {
    let (a, mut d) = driver_with(false);
    d.process(Input::NewRound(Round::new(0)));

    // The value is proposed and retained, so only the votes stand between us and L42.
    d.process(Input::Proposal(fresh(0, 7, a[1]), Validity::Valid));

    // Four of six for 7: below n-f (5).
    for i in 0..4 {
        d.process(Input::Vote(vote(0, 7, a[i])));
    }
    assert!(d.decision().is_none(), "four votes are not n-f");

    // The fifth validator votes for a different value, then equivocates toward 7.
    d.process(Input::Vote(vote(0, 9, a[4])));
    let out = d.process(Input::Vote(vote(0, 7, a[4])));

    assert!(
        !out.iter().any(|o| matches!(o, Output::Decision(..))),
        "the equivocating vote must not produce a decision, got {out:?}"
    );
    assert!(
        d.decision().is_none(),
        "an equivocating vote must not manufacture the n-f quorum that decides"
    );

    // Control. Every assertion above is negative, so all of them would hold just as well
    // on a driver that can never decide at all — verified by mutation: replacing the
    // Decision arm of `resolve` with a discard leaves them green. A genuine fifth voter
    // must still decide, and that is what makes the test falsifiable.
    let out = d.process(Input::Vote(vote(0, 7, a[5])));
    assert!(
        out.iter().any(|o| matches!(o, Output::Decision(..))),
        "a legitimate fifth vote must still decide, got {out:?}"
    );
    assert_eq!(d.decision().map(|(_, v)| v.clone()), Some(Value::new(7)));
}

/// A vote attributed to an address outside the validator set must be discarded before it
/// is counted — gossip delivers whatever peers send, and signature verification happens
/// elsewhere, so such a vote can arrive at any time. The driver is the layer where a
/// wrongly counted vote would turn into a round input and, through L42, a decision.
///
/// Four honest validators vote for 7; a stranger then votes for 7 too. Counting it would
/// make five — `n-f` — and decide.
///
/// reproduces obs:vote_from_a_non_validator_discarded — asserts the keeper's membership
/// guard holds at the driver boundary.
#[test]
fn a_vote_from_outside_the_validator_set_cannot_manufacture_a_decision() {
    let (a, mut d) = driver_with(false);
    d.process(Input::NewRound(Round::new(0)));

    // The value is proposed and retained, so only the votes stand between us and L42.
    d.process(Input::Proposal(fresh(0, 7, a[1]), Validity::Valid));

    // Four of six for 7: below n-f (5).
    for i in 0..4 {
        d.process(Input::Vote(vote(0, 7, a[i])));
    }
    assert!(d.decision().is_none(), "four votes are not n-f");

    // A fifth vote for the same value, from an address that is not in the set.
    let stranger = Address::from_public_key(&PrivateKey::from([99u8; 32]).public_key());
    let out = d.process(Input::Vote(vote(0, 7, stranger)));

    assert!(
        !out.iter().any(|o| matches!(o, Output::Decision(..))),
        "a non-validator's vote must not produce a decision, got {out:?}"
    );
    assert!(
        d.decision().is_none(),
        "a vote from outside the validator set must not manufacture the n-f quorum"
    );

    // Control, for the same reason and verified the same way as above.
    let out = d.process(Input::Vote(vote(0, 7, a[4])));
    assert!(
        out.iter().any(|o| matches!(o, Output::Decision(..))),
        "a legitimate fifth vote must still decide, got {out:?}"
    );
    assert_eq!(d.decision().map(|(_, v)| v.clone()), Some(Value::new(7)));
}
