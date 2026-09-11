//! Behavior tests for the Fast Tendermint round state machine.
//!
//! Each test names the line of Algorithm 1 (arXiv:2608.13434) it pins. The set is chosen
//! for the mistakes a hand transcription of that algorithm is most likely to make: the
//! binding rule that decides vote-vs-nil, the re-proposal acceptance condition, the two
//! distinct thresholds, and the absence of any `f+1` round-skip.

use malachitebft_core_types::{Context, NilOrVal, Round, TimeoutKind};

use arc_malachitebft_core_state_machine::fast::input::Input;
use arc_malachitebft_core_state_machine::fast::output::Output;
use arc_malachitebft_core_state_machine::fast::state::{State, Step};
use arc_malachitebft_core_state_machine::fast::state_machine::{apply, Info};

use malachitebft_test::{Address, Height, PrivateKey, TestContext, Value, ValueId};

fn addr(seed: u8) -> Address {
    Address::from_public_key(&PrivateKey::from([seed; 32]).public_key())
}

fn ctx() -> TestContext {
    TestContext::new()
}

fn at(round: u32) -> Round {
    Round::new(round)
}

/// A state already in `Propose` for `round`, as if `NewRound` had been applied.
fn proposing(round: u32) -> State<TestContext> {
    State::new(Height::new(1), at(round)).with_step(Step::Propose)
}

fn fresh_proposal(round: u32, v: u64, proposer: Address) -> <TestContext as Context>::Proposal {
    ctx().new_proposal(Height::new(1), at(round), Value::new(v), Round::Nil, proposer)
}

fn re_proposal(
    round: u32,
    v: u64,
    valid_round: u32,
    proposer: Address,
) -> <TestContext as Context>::Proposal {
    ctx().new_proposal(Height::new(1), at(round), Value::new(v), at(valid_round), proposer)
}

// ---------------------------------------------------------------- starting a round

/// L12-L13: the round-0 proposer holds nothing valid, so it asks the application.
#[test]
fn round_zero_proposer_asks_for_a_value() {
    let me = addr(1);
    let info = Info::<TestContext>::new_proposer(at(0), &me);
    let t = apply(&ctx(), State::new(Height::new(1), Round::Nil), &info, Input::NewRound(at(0)));

    assert!(t.valid);
    assert_eq!(t.next_state.step, Step::Propose);
    assert!(!t.next_state.awaiting_valid, "round 0 never waits");
    assert!(matches!(t.output, Some(Output::GetValueAndScheduleTimeout(..))));
}

/// L10-L11: a proposer of a round above 0 must first learn `valid` from the round below,
/// so it enters Propose waiting rather than proposing. This mechanism has no analogue in
/// classic Tendermint.
#[test]
fn later_round_proposer_waits_for_valid() {
    let me = addr(1);
    let info = Info::<TestContext>::new_proposer(at(3), &me);
    let t = apply(&ctx(), State::new(Height::new(1), Round::Nil), &info, Input::NewRound(at(3)));

    assert!(t.valid);
    assert!(t.next_state.awaiting_valid, "must wait: valid is nil, round is 3");
    assert!(matches!(t.output, Some(Output::WaitForValid(_))));
}

/// L18: a non-proposer schedules the propose timeout and waits.
#[test]
fn non_proposer_schedules_the_propose_timeout() {
    let (me, them) = (addr(1), addr(2));
    let info = Info::<TestContext>::new(at(0), &me, &them);
    let t = apply(&ctx(), State::new(Height::new(1), Round::Nil), &info, Input::NewRound(at(0)));

    match t.output {
        Some(Output::ScheduleTimeout(to)) => assert_eq!(to.kind, TimeoutKind::Propose),
        other => panic!("expected a propose timeout, got {other:?}"),
    }
}

// ---------------------------------------------------------------- voting on a proposal

/// L20-L22: nothing binds us, so we vote for the proposed identifier.
#[test]
fn unbound_node_votes_for_a_fresh_proposal() {
    let me = addr(1);
    let info = Info::<TestContext>::new_proposer(at(0), &me);
    let p = fresh_proposal(0, 42, me);
    let t = apply(&ctx(), proposing(0), &info, Input::Proposal(p));

    assert!(t.valid);
    assert_eq!(t.next_state.step, Step::Precommit, "one voting step, named precommit");
    match t.output {
        Some(Output::Vote(_)) => {}
        other => panic!("expected a vote, got {other:?}"),
    }
}

/// L21, the safety-critical negative: we hold a different identifier valid, and the
/// proposal is fresh (no justification), so we must vote nil rather than switch.
#[test]
fn bound_node_votes_nil_for_a_conflicting_fresh_proposal() {
    let me = addr(1);
    let info = Info::<TestContext>::new_proposer(at(2), &me);
    let state = proposing(2).set_valid(at(1), ValueId::new(7));

    let t = apply(&ctx(), state, &info, Input::Proposal(fresh_proposal(2, 42, me)));

    assert!(t.valid);
    assert_eq!(t.next_state.step, Step::Precommit);
    assert_eq!(
        t.next_state.valid.as_ref().map(|v| v.value_id.clone()),
        Some(ValueId::new(7)),
        "a conflicting fresh proposal must not move what we hold valid"
    );
}

/// L21, the positive case: the fresh proposal re-offers exactly what we hold valid.
#[test]
fn bound_node_votes_for_a_fresh_proposal_matching_its_valid() {
    let me = addr(1);
    let info = Info::<TestContext>::new_proposer(at(2), &me);
    let value = Value::new(42);
    let state = proposing(2).set_valid(at(1), value.id());

    let t = apply(&ctx(), state, &info, Input::Proposal(fresh_proposal(2, 42, me)));
    assert!(t.valid);
    assert!(matches!(t.output, Some(Output::Vote(_))));
}

/// L23-L24: a value the application rejected draws a nil vote.
#[test]
fn invalid_proposal_draws_a_nil_vote() {
    let me = addr(1);
    let info = Info::<TestContext>::new_proposer(at(0), &me);
    let t = apply(&ctx(), proposing(0), &info, Input::InvalidProposal);

    assert!(t.valid);
    assert_eq!(t.next_state.step, Step::Precommit);
}

// ---------------------------------------------------------------- re-proposals

/// L28-L31: the justification is at least as recent as what binds us, so we accept the
/// re-proposal and raise `valid` to the justifying round.
#[test]
fn re_proposal_with_recent_enough_justification_is_accepted() {
    let me = addr(1);
    let info = Info::<TestContext>::new_proposer(at(4), &me);
    let value = Value::new(9);
    let state = proposing(4).set_valid(at(1), ValueId::new(77));

    let t = apply(&ctx(), state, &info, Input::ProposalAndVoteQuorumPrevious(re_proposal(4, 9, 2, me)));

    assert!(t.valid);
    let got = t.next_state.valid.expect("valid must be set");
    assert_eq!(got.round, at(2), "valid rises to the justifying round vr");
    assert_eq!(got.value_id, value.id());
}

/// L28, the safety-critical negative: the justification is older than what binds us and
/// names a different value, so we refuse it and keep our own.
#[test]
fn re_proposal_with_stale_justification_is_refused() {
    let me = addr(1);
    let info = Info::<TestContext>::new_proposer(at(5), &me);
    let state = proposing(5).set_valid(at(4), ValueId::new(77));

    let t = apply(&ctx(), state, &info, Input::ProposalAndVoteQuorumPrevious(re_proposal(5, 9, 1, me)));

    assert!(t.valid, "the input applies; the vote is nil");
    let got = t.next_state.valid.expect("valid must survive");
    assert_eq!(got.round, at(4), "a stale justification must not lower valid");
    assert_eq!(got.value_id, ValueId::new(77));
}

/// A re-proposal whose `vr` is not below its own round is malformed and must not apply.
#[test]
fn re_proposal_with_a_future_justification_is_rejected() {
    let me = addr(1);
    let info = Info::<TestContext>::new_proposer(at(2), &me);
    let t = apply(&ctx(), proposing(2), &info, Input::ProposalAndVoteQuorumPrevious(re_proposal(2, 9, 3, me)));
    assert!(!t.valid, "vr must be strictly below the current round");
}

// ---------------------------------------------------------------- the two thresholds

/// L36-L37: 2f+1 votes for a value in this round make it valid.
#[test]
fn vote_quorum_raises_valid() {
    let me = addr(1);
    let info = Info::<TestContext>::new_proposer(at(2), &me);
    let t = apply(&ctx(), proposing(2), &info, Input::VoteQuorumForValue(ValueId::new(5)));

    assert!(t.valid);
    let got = t.next_state.valid.expect("valid must be set");
    assert_eq!(got.round, at(2));
    assert_eq!(got.value_id, ValueId::new(5));
}

/// The paper only ever raises `valid_p`; a quorum in a round we have already passed for
/// must not lower it.
#[test]
fn vote_quorum_never_lowers_valid() {
    let me = addr(1);
    let info = Info::<TestContext>::new_proposer(at(2), &me);
    let state = proposing(2).set_valid(at(2), ValueId::new(1));

    let t = apply(&ctx(), state, &info, Input::VoteQuorumForValue(ValueId::new(2)));
    assert!(!t.valid, "nothing to raise, so the input does not apply");
    assert_eq!(t.next_state.valid.expect("kept").value_id, ValueId::new(1));
}

/// L39-L40: n-f votes for any value arm the precommit timeout, and only once per round.
/// This is the ONLY path that advances a round — there is no f+1 skip rule.
#[test]
fn quorum_any_arms_the_precommit_timeout_once() {
    let me = addr(1);
    let info = Info::<TestContext>::new_proposer(at(1), &me);

    let first = apply(&ctx(), proposing(1), &info, Input::QuorumAny(at(1)));
    assert!(first.valid);
    match first.output {
        Some(Output::ScheduleTimeout(to)) => assert_eq!(to.kind, TimeoutKind::Precommit),
        other => panic!("expected a precommit timeout, got {other:?}"),
    }

    let second = apply(&ctx(), first.next_state, &info, Input::QuorumAny(at(1)));
    assert!(!second.valid, "the timeout is armed at most once per round");
}

// ---------------------------------------------------------------- deciding

/// L42-L43: a fresh proposal supplies the value, and the n-f votes may come from a
/// DIFFERENT round. The decision records the proposal's round, not ours.
#[test]
fn decides_on_a_fresh_proposal_from_another_round() {
    let me = addr(1);
    let info = Info::<TestContext>::new_proposer(at(5), &me);
    let state = proposing(5);

    let t = apply(&ctx(), state, &info, Input::ProposalAndDecisionQuorum(fresh_proposal(2, 42, me)));

    assert!(t.valid);
    assert_eq!(t.next_state.step, Step::Commit);
    let (round, value) = t.next_state.decision.expect("must decide");
    assert_eq!(round, at(2), "the decision carries the proposal's round");
    assert_eq!(value, Value::new(42));
    assert!(matches!(t.output, Some(Output::Decision(..))));
}

/// Only a fresh proposal establishes validity. A re-proposal carries an identifier, so it
/// cannot be decided on by itself even with n-f votes.
#[test]
fn a_re_proposal_alone_cannot_be_decided_on() {
    let me = addr(1);
    let info = Info::<TestContext>::new_proposer(at(5), &me);
    let t = apply(&ctx(), proposing(5), &info, Input::ProposalAndDecisionQuorum(re_proposal(5, 42, 1, me)));

    assert!(!t.valid);
    assert!(t.next_state.decision.is_none());
}

/// Commit is terminal: once decided, further inputs do not apply.
#[test]
fn commit_is_terminal() {
    let me = addr(1);
    let info = Info::<TestContext>::new_proposer(at(5), &me);
    let decided = proposing(5).set_decision(at(2), Value::new(42)).with_step(Step::Commit);

    let t = apply(&ctx(), decided, &info, Input::ProposalAndDecisionQuorum(fresh_proposal(3, 99, me)));
    assert!(!t.valid, "a second decision must not be accepted");
    assert_eq!(t.next_state.decision.expect("kept").1, Value::new(42));
}

// ---------------------------------------------------------------- timeouts

/// L50-L52: no proposal arrived, so we vote nil and move to the voting step.
#[test]
fn propose_timeout_votes_nil() {
    let me = addr(1);
    let info = Info::<TestContext>::new_proposer(at(0), &me);
    let t = apply(&ctx(), proposing(0), &info, Input::TimeoutPropose);

    assert!(t.valid);
    assert_eq!(t.next_state.step, Step::Precommit);
    assert!(matches!(t.output, Some(Output::Vote(_))));
}

/// L55-L57: the precommit timeout gives up on this round and starts the next.
#[test]
fn precommit_timeout_starts_the_next_round() {
    let me = addr(1);
    let info = Info::<TestContext>::new_proposer(at(2), &me);
    let t = apply(&ctx(), proposing(2), &info, Input::TimeoutPrecommit);

    assert!(t.valid);
    assert_eq!(t.output, Some(Output::NewRound(at(3))));
}

/// L56: once decided, the precommit timeout must not start another round.
#[test]
fn precommit_timeout_after_a_decision_does_nothing() {
    let me = addr(1);
    let info = Info::<TestContext>::new_proposer(at(2), &me);
    let decided = proposing(2).set_decision(at(2), Value::new(1));

    let t = apply(&ctx(), decided, &info, Input::TimeoutPrecommit);
    assert!(!t.valid);
}

/// L46: when the proposer's bounded wait expires it proposes anyway. With nothing valid,
/// that means asking the application for a value.
#[test]
fn wait_for_valid_expiry_lets_the_proposer_propose() {
    let me = addr(1);
    let info = Info::<TestContext>::new_proposer(at(3), &me);
    let mut waiting = proposing(3);
    waiting.awaiting_valid = true;

    let t = apply(&ctx(), waiting, &info, Input::WaitForValidExpired);

    assert!(t.valid);
    assert!(!t.next_state.awaiting_valid, "the wait is over");
    assert!(matches!(t.output, Some(Output::GetValueAndScheduleTimeout(..))));
}

/// L47-L48 into L15-L16: a vote quorum that arrives while the proposer is waiting ends the
/// wait, and the proposer re-proposes the identifier it just learned.
#[test]
fn vote_quorum_while_waiting_makes_the_proposer_repropose() {
    let me = addr(1);
    let info = Info::<TestContext>::new_proposer(at(3), &me);
    let mut waiting = proposing(3);
    waiting.awaiting_valid = true;

    let t = apply(&ctx(), waiting, &info, Input::VoteQuorumForValue(ValueId::new(8)));

    assert!(t.valid);
    assert!(!t.next_state.awaiting_valid);
    match t.output {
        Some(Output::Repropose { value_id, valid_round }) => {
            assert_eq!(value_id, ValueId::new(8));
            assert_eq!(valid_round, at(3));
        }
        other => panic!("expected a Repropose, got {other:?}"),
    }
}

/// A nil vote must never be emitted as a vote for a value. Guards the NilOrVal plumbing.
#[test]
fn nil_and_value_votes_are_distinguishable() {
    let nil: NilOrVal<ValueId> = NilOrVal::Nil;
    let val: NilOrVal<ValueId> = NilOrVal::Val(ValueId::new(1));
    assert_ne!(nil, val);
}

/// L43/L56: a decision is final — once the machine has decided, no later input may
/// replace that decision with another value.
///
/// Realistic path, all through `apply` under default settings: decide at round 4, then
/// take the `NewRound(5)` the driver issues for the next round — the decide arm guards
/// only on `step != Commit`, and `NewRound` leaves `decision` set while moving the step
/// back to `Propose`, so the next `ProposalAndDecisionQuorum` overwrites the decision.
///
/// reproduces decision_is_final_and_commit_is_terminal — fails on current code
#[test]
#[ignore]
fn a_decision_is_never_replaced_after_a_new_round() {
    let me = addr(1);
    let ctx = ctx();

    // Decide value 7 (proposed in round 4) while at round 4.
    let info4 = Info::<TestContext>::new_proposer(at(4), &me);
    let decided = apply(
        &ctx,
        proposing(4),
        &info4,
        Input::ProposalAndDecisionQuorum(fresh_proposal(4, 7, me)),
    )
    .next_state;
    assert_eq!(decided.step, Step::Commit);
    assert_eq!(decided.decision.clone().expect("decided").1, Value::new(7));

    // The driver moves on to round 5; the decision is carried along.
    let info5 = Info::<TestContext>::new_proposer(at(5), &me);
    let at_five = apply(&ctx, decided, &info5, Input::NewRound(at(5))).next_state;
    assert_eq!(
        at_five.decision.clone().expect("the decision survives the round change").1,
        Value::new(7)
    );

    // A second decision quorum, for a different value, must not be accepted.
    let t = apply(
        &ctx,
        at_five,
        &info5,
        Input::ProposalAndDecisionQuorum(fresh_proposal(4, 5, me)),
    );

    assert!(!t.valid, "a second decision must not be accepted");
    assert_eq!(
        t.next_state.decision.expect("kept").1,
        Value::new(7),
        "the first decision is final"
    );
}
