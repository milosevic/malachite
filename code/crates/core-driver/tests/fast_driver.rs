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

/// A quorum with no retained proposal decides nothing: the votes carry an identifier, and
/// only the fresh proposal carries the value. The quorum waits rather than inventing one.
#[test]
fn a_quorum_without_its_proposal_decides_nothing() {
    let (a, mut d) = driver_with(false);
    d.process(Input::NewRound(Round::new(0)));

    for i in 0..5 {
        for out in d.process(Input::Vote(vote(0, 7, a[i]))) {
            assert!(
                !matches!(out, Output::Decision(..)),
                "nothing supplies the value, so nothing may be decided"
            );
        }
    }
    assert!(d.decision().is_none());
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
