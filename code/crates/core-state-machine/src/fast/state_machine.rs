//! The Fast Tendermint round transition function.
//!
//! Line numbers in comments refer to Algorithm 1 of Vander Vos & Cason, *"Fast Tendermint"*
//! (arXiv:2608.13434).

use malachitebft_core_types::{Context, NilOrVal, Proposal, Round, TimeoutKind, Value};

use crate::fast::input::Input;
use crate::fast::output::Output;
use crate::fast::state::{State, Step};

/// A transition of the Fast Tendermint state machine.
pub type Transition<Ctx> = FastTransition<Ctx>;

/// The result of applying one input: the next state, an optional output, and whether the
/// input was meaningful in the state it arrived in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FastTransition<Ctx: Context> {
    /// The state to continue from.
    pub next_state: State<Ctx>,
    /// The output for the caller to act on, if any.
    pub output: Option<Output<Ctx>>,
    /// Whether this was a valid transition. `false` means the input was ignored.
    pub valid: bool,
}

impl<Ctx: Context> FastTransition<Ctx> {
    /// A valid transition to `next_state` with no output.
    pub fn to(next_state: State<Ctx>) -> Self {
        Self { next_state, output: None, valid: true }
    }

    /// An invalid transition: the input did not apply, and nothing changed.
    pub fn invalid(next_state: State<Ctx>) -> Self {
        Self { next_state, output: None, valid: false }
    }

    /// Attach an output.
    pub fn with_output(mut self, output: Output<Ctx>) -> Self {
        self.output = Some(output);
        self
    }
}

/// Immutable context for one input: which round it is for, who we are, and who proposes.
pub struct Info<'a, Ctx: Context> {
    /// The round the input is for, which may differ from the round we are at.
    pub input_round: Round,
    /// Our own address.
    pub address: &'a Ctx::Address,
    /// The proposer of the round we are at.
    pub proposer: &'a Ctx::Address,
}

impl<'a, Ctx: Context> Info<'a, Ctx> {
    /// Create a new `Info`.
    pub fn new(input_round: Round, address: &'a Ctx::Address, proposer: &'a Ctx::Address) -> Self {
        Self { input_round, address, proposer }
    }

    /// Create an `Info` in which we are the proposer.
    pub fn new_proposer(input_round: Round, address: &'a Ctx::Address) -> Self {
        Self { input_round, address, proposer: address }
    }

    /// Whether we propose the round we are at.
    pub fn is_proposer(&self) -> bool {
        self.address == self.proposer
    }
}

/// Apply `input` to `state`.
///
/// The classic state machine's [`ClassicTransition`] is deliberately *not* reused: the two
/// protocols carry different state, so sharing the type would let one be fed to the other.
#[allow(clippy::needless_pass_by_value)]
pub fn apply<Ctx>(
    ctx: &Ctx,
    mut state: State<Ctx>,
    info: &Info<Ctx>,
    input: Input<Ctx>,
) -> Transition<Ctx>
where
    Ctx: Context,
{
    let this_round = state.round == info.input_round;

    match (state.step, input) {
        // L6-L18: start a round.
        (_, Input::NewRound(round)) if state.round <= round => start_round(state, info, round),

        // L13/L16: the application produced a value and we are the proposer, no longer
        // waiting. `valid` is nil here, so the proposal is fresh and carries validRound -1.
        (Step::Propose, Input::ProposeValue(value))
            if this_round && info.is_proposer() && !state.awaiting_valid =>
        {
            let proposal =
                ctx.new_proposal(state.height, state.round, value, Round::Nil, info.address.clone());
            Transition::to(state).with_output(Output::Proposal(proposal))
        }

        // L20-L25: a fresh proposal. Vote for it when nothing binds us, or when it
        // re-offers the identifier we already hold valid.
        (Step::Propose, Input::Proposal(proposal))
            if this_round && proposal.pol_round().is_nil() =>
        {
            let value_id = proposal.value().id();
            let unbound = state.valid.is_none() || state.valid_is(&value_id);
            if unbound {
                vote(ctx, state, info, NilOrVal::Val(value_id))
            } else {
                vote(ctx, state, info, NilOrVal::Nil)
            }
        }

        // L23-L24: the value failed validation.
        (Step::Propose, Input::InvalidProposal) if this_round => {
            vote(ctx, state, info, NilOrVal::Nil)
        }

        // L27-L34: a re-proposal justified by 2f+1 votes from round `vr`.
        (Step::Propose, Input::ProposalAndVoteQuorumPrevious(proposal)) if this_round => {
            let vr = proposal.pol_round();
            let value_id = proposal.value().id();

            // The justification must name a real earlier round of this height.
            if !vr.is_defined() || vr >= state.round {
                return Transition::invalid(state);
            }

            // L28: accept when the justification is at least as recent as what binds us,
            // or when it re-offers the same identifier.
            if state.valid_round() <= vr || state.valid_is(&value_id) {
                // L29-L30.
                state = state.set_valid(vr, value_id.clone());
                vote(ctx, state, info, NilOrVal::Val(value_id))
            } else {
                vote(ctx, state, info, NilOrVal::Nil)
            }
        }

        // L33: the justification or the value was rejected.
        (Step::Propose, Input::InvalidProposalAndVoteQuorumPrevious(_)) if this_round => {
            vote(ctx, state, info, NilOrVal::Nil)
        }

        // L36-L37: the observation rule. 2f+1 votes for a value in this round make it
        // valid. A proposer still waiting may now have what it needs to propose.
        (_, Input::VoteQuorumForValue(value_id)) if this_round => {
            let round = state.round;
            let raised = state.valid_round() < round;
            state = state.set_valid(round, value_id);

            if !raised {
                return Transition::invalid(state);
            }
            if state.awaiting_valid && info.is_proposer() {
                propose_now(state)
            } else {
                Transition::to(state)
            }
        }

        // L39-L40: n - f votes for any value at a round at or above ours arms the
        // precommit timeout. This is the only path that advances a round.
        (_, Input::QuorumAny(round)) if round >= state.round => {
            if state.check_timeout(TimeoutKind::Precommit) {
                Transition::to(state)
                    .with_output(Output::schedule_timeout(round, TimeoutKind::Precommit))
            } else {
                Transition::invalid(state)
            }
        }

        // L42-L43: decide. The fresh proposal supplies the value and its validity; the
        // n - f votes may come from a different round.
        (step, Input::ProposalAndDecisionQuorum(proposal)) if step != Step::Commit => {
            if !proposal.pol_round().is_nil() {
                // Only a fresh proposal establishes validity; a re-proposal carries an
                // identifier and cannot be decided on alone.
                return Transition::invalid(state);
            }
            let round = proposal.round();
            let value = proposal.value().clone();
            let state = state.set_decision(round, value.clone()).with_step(Step::Commit);
            Transition::to(state).with_output(Output::Decision(round, value))
        }

        // L50-L53: no proposal arrived in time.
        (Step::Propose, Input::TimeoutPropose) if this_round => {
            vote(ctx, state, info, NilOrVal::Nil)
        }

        // L46: the proposer's bounded wait ran out; propose with whatever we have.
        (Step::Propose, Input::WaitForValidExpired)
            if this_round && state.awaiting_valid && info.is_proposer() =>
        {
            propose_now(state)
        }

        // L55-L57: give up on this round.
        (_, Input::TimeoutPrecommit) if info.input_round >= state.round && state.decision.is_none() => {
            Transition::to(state).with_output(Output::NewRound(info.input_round.increment()))
        }

        _ => Transition::invalid(state),
    }
}

/// L6-L18. Enter `round`. A proposer of a round above 0 must first learn `valid` from the
/// previous round (L11), so it enters `Propose` waiting rather than proposing.
fn start_round<Ctx>(mut state: State<Ctx>, info: &Info<Ctx>, round: Round) -> Transition<Ctx>
where
    Ctx: Context,
{
    state.update_round(round);
    state = state.with_step(Step::Propose);

    if !info.is_proposer() {
        // L18.
        return if state.check_timeout(TimeoutKind::Propose) {
            Transition::to(state).with_output(Output::schedule_timeout(round, TimeoutKind::Propose))
        } else {
            Transition::to(state)
        };
    }

    // L10-L11: rounds above the first wait to learn a valid value first.
    // L46: `valid_p.round < round_p - 1`. Round has no decrement, and Round::Nil is -1,
    // so the comparison is done on the i64 projection.
    if round > Round::new(0) && state.valid_round().as_i64() < round.as_i64() - 1 {
        state.awaiting_valid = true;
        return Transition::to(state)
            .with_output(Output::WaitForValid(malachitebft_core_types::Timeout {
                round,
                kind: TimeoutKind::Precommit,
            }));
    }

    propose_now(state)
}

/// L12-L16. Re-propose the value we hold valid, or ask the application for a fresh one.
fn propose_now<Ctx>(mut state: State<Ctx>) -> Transition<Ctx>
where
    Ctx: Context,
{
    state.awaiting_valid = false;

    match state.valid.clone() {
        // L15-L16: re-propose the identifier, together with the round that justifies it.
        Some(valid) => Transition::to(state).with_output(Output::Repropose {
            value_id: valid.value_id,
            valid_round: valid.round,
        }),
        // L13: nothing is valid yet, so ask the application to build a value.
        None => {
            let (height, round) = (state.height, state.round);
            Transition::to(state).with_output(Output::GetValueAndScheduleTimeout(
                height,
                round,
                malachitebft_core_types::Timeout { round, kind: TimeoutKind::Propose },
            ))
        }
    }
}

/// L22/L24/L31/L33/L52. Cast this round's single vote and move to the voting step.
fn vote<Ctx>(
    ctx: &Ctx,
    state: State<Ctx>,
    info: &Info<Ctx>,
    value_id: NilOrVal<malachitebft_core_types::ValueId<Ctx>>,
) -> Transition<Ctx>
where
    Ctx: Context,
{
    let (height, round) = (state.height, state.round);
    let state = state.with_step(Step::Precommit);
    Transition::to(state).with_output(Output::vote(
        ctx,
        height,
        round,
        value_id,
        info.address.clone(),
    ))
}
