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
    state: State<Ctx>,
    info: &Info<Ctx>,
    input: Input<Ctx>,
) -> Transition<Ctx>
where
    Ctx: Context,
{
    let this_round = state.round == info.input_round;

    // Quint oracle: describe the input the way the spec models it — the
    // constructor by name, plus the proposal / round fields it carries — before
    // `input` is moved into the match below.
    let oracle_on = quint_oracle::enabled();
    let oracle_input_round = info.input_round.as_i64();
    let oracle_state_round = state.round.as_i64();
    let oracle_proposer = if info.is_proposer() { "a" } else { "b" };
    // `apply` is a pure function of (state, info, input), and callers hand it
    // states they built themselves, so the pre-state is part of the transition's
    // payload, not something the model could track on its own. Log it whole.
    let oracle_sstep = match state.step {
        Step::Unstarted => "Unstarted",
        Step::Propose => "Propose",
        Step::Precommit => "Precommit",
        Step::Commit => "Commit",
    };
    let (oracle_svround, oracle_svalue) = match &state.valid {
        Some(rv) => (rv.round.as_i64(), alloc::format!("{}", rv.value_id)),
        None => (-1, alloc::string::String::from("v")),
    };
    let (oracle_sdround, oracle_sdvalue) = match &state.decision {
        Some((round, value)) => (round.as_i64(), alloc::format!("{}", value.id())),
        None => (-1, alloc::string::String::from("v")),
    };
    let oracle_sawaiting = state.awaiting_valid;
    let oracle_sscheduled = i64::from(state.scheduled_timeouts.bits());
    // `armed_precommit_rounds` travels as a bitmask over the model's round band:
    // bit 0 is round -1, bit i+1 is round i, for i in 0..=9. A round armed
    // outside the band is not represented, which fails replay loudly rather than
    // passing wrongly.
    let oracle_sarmed = state
        .armed_precommit_rounds
        .iter()
        .filter_map(|r| {
            let i = r.as_i64();
            (-1..=9).contains(&i).then(|| 1_i64 << (i + 1))
        })
        .sum::<i64>();
    let (oracle_tag, oracle_value, oracle_pround, oracle_ppol, oracle_nround) = if oracle_on {
        match &input {
            Input::NewRound(round) => ("NewRound", None, None, None, Some(round.as_i64())),
            Input::ProposeValue(value) => (
                "ProposeValue",
                Some(alloc::format!("{}", value.id())),
                None,
                None,
                None,
            ),
            Input::Proposal(proposal) => (
                "Proposal",
                Some(alloc::format!("{}", proposal.value().id())),
                Some(proposal.round().as_i64()),
                Some(proposal.pol_round().as_i64()),
                None,
            ),
            Input::InvalidProposal => ("InvalidProposal", None, None, None, None),
            Input::ProposalAndVoteQuorumPrevious(proposal) => (
                "ProposalAndVoteQuorumPrevious",
                Some(alloc::format!("{}", proposal.value().id())),
                Some(proposal.round().as_i64()),
                Some(proposal.pol_round().as_i64()),
                None,
            ),
            Input::InvalidProposalAndVoteQuorumPrevious(proposal) => (
                "InvalidProposalAndVoteQuorumPrevious",
                Some(alloc::format!("{}", proposal.value().id())),
                Some(proposal.round().as_i64()),
                Some(proposal.pol_round().as_i64()),
                None,
            ),
            Input::VoteQuorumForValue(quorum_round, value_id) => (
                "VoteQuorumForValue",
                Some(alloc::format!("{value_id}")),
                Some(quorum_round.as_i64()),
                None,
                None,
            ),
            Input::QuorumAny(round) => ("QuorumAny", None, None, None, Some(round.as_i64())),
            Input::ProposalAndDecisionQuorum(proposal) => (
                "ProposalAndDecisionQuorum",
                Some(alloc::format!("{}", proposal.value().id())),
                Some(proposal.round().as_i64()),
                Some(proposal.pol_round().as_i64()),
                None,
            ),
            Input::TimeoutPropose => ("TimeoutPropose", None, None, None, None),
            Input::TimeoutPrecommit => ("TimeoutPrecommit", None, None, None, None),
            Input::WaitForValidExpired => ("WaitForValidExpired", None, None, None, None),
        }
    } else {
        ("", None, None, None, None)
    };

    let transition = apply_inner(ctx, state, info, input, this_round);

    if oracle_on {
        // Inputs that carry no proposal / no round leave those picks as
        // don't-cares in the spec; pin them to values the spec always holds so
        // replay never has to search them blind.
        quint_oracle::Event::builder(quint_oracle::current_test(), "faststate_machineapply")
            .argument("inputTag", oracle_tag, Some("ALL_TAGS"))
            .argument("input_round", oracle_input_round, None)
            .argument("proposer", oracle_proposer, Some("ADDRS"))
            .argument(
                "pvalue",
                oracle_value.as_deref().unwrap_or("v"),
                Some("VALUES"),
            )
            .argument("pround", oracle_pround.unwrap_or(oracle_state_round), None)
            .argument("ppol", oracle_ppol.unwrap_or(-1), None)
            .argument("nround", oracle_nround.unwrap_or(oracle_state_round), None)
            // The pre-state `apply` was handed.
            .argument("sround", oracle_state_round, None)
            .argument("sstep", oracle_sstep, Some("STEP_NAMES"))
            .argument("svround", oracle_svround, None)
            .argument("svalue", oracle_svalue.as_str(), Some("VALUES"))
            .argument("sdround", oracle_sdround, None)
            .argument("sdvalue", oracle_sdvalue.as_str(), Some("VALUES"))
            .argument("sawaiting", oracle_sawaiting, None)
            .argument("sscheduled", oracle_sscheduled, None)
            .argument("sarmed", oracle_sarmed, None)
            // Conformance fact: whether the transition table accepted the input.
            // The absolute round is deliberately NOT asserted — `apply` is also
            // called on caller-built states, whose round the model has no logged
            // event to follow.
            .assert(
                alloc::vec::Vec::from([quint_oracle::PathSeg::ident("lastValid")]),
                transition.valid,
            )
            .scope("fast-round-state-machine")
            .send();
    }

    transition
}

/// The transition table itself, split out so `apply` can report the transition to
/// the Quint oracle without the match arms having to know about it.
fn apply_inner<Ctx>(
    ctx: &Ctx,
    mut state: State<Ctx>,
    info: &Info<Ctx>,
    input: Input<Ctx>,
    this_round: bool,
) -> Transition<Ctx>
where
    Ctx: Context,
{
    match (state.step, input) {
        // L6-L18: start a round. The step guard matters: Algorithm 1 only ever calls
        // StartRound(round+1), so re-entering the round we are already in never happens.
        // Without it, a NewRound for the current round resets Precommit back to Propose
        // and the node can cast a SECOND vote in that round — equivocating against itself.
        (Step::Unstarted, Input::NewRound(round))
            if state.round <= round && state.decision.is_none() =>
        {
            start_round(state, info, round)
        }
        // L56 calls StartRound only while `decision_p = nil`. Without the decision guard a
        // decided node keeps entering rounds: `with_step` correctly refuses to leave
        // Commit, but `update_round` still advances and `start_round` runs to completion,
        // so the node schedules timeouts and emits proposals after deciding.
        (_, Input::NewRound(round)) if state.round < round && state.decision.is_none() => {
            start_round(state, info, round)
        }

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
                // L29-L30. Note `<=`: at equality the paper REPLACES the value it holds.
                // With n > 5f two 2f+1 quorums need not intersect
                // (2(2f+1) - (5f+1) = 1-f <= 0), so two different values can each hold a
                // quorum in the same round vr. `set_valid` is monotone and no-ops at
                // equality, so it cannot express this — write it directly.
                if state.valid_round() <= vr {
                    state.valid = Some(crate::fast::state::RoundValueId::new(vr, value_id.clone()));
                }
                vote(ctx, state, info, NilOrVal::Val(value_id))
            } else {
                vote(ctx, state, info, NilOrVal::Nil)
            }
        }

        // L33: the justification or the value was rejected.
        (Step::Propose, Input::InvalidProposalAndVoteQuorumPrevious(_)) if this_round => {
            vote(ctx, state, info, NilOrVal::Nil)
        }

        // L36-L37 and L47-L48: the observation rule. 2f+1 votes for a value in any round
        // above the one we hold valid raise `valid`. The round is carried explicitly
        // because a proposer inside WaitForValid is at round_p while the quorum that ends
        // its wait is for round_p - 1 (L46) — gating on the current round would make L47
        // unreachable and force every wait to burn its full timeout.
        (_, Input::VoteQuorumForValue(quorum_round, value_id))
            if quorum_round <= state.round =>
        {
            // The upper bound is the paper's core restriction: the observation rule must
            // capture valid values BEFORE a process moves to a higher round. L36 sets
            // valid_p from round_p, and L47 runs inside WaitForValid whose loop condition
            // (valid_p.round < round_p - 1) bounds r below round_p. Neither lets valid_p
            // exceed round_p. Without this, a quorum for a far-future round sets valid
            // there and the node votes nil in every round up to it — a self-inflicted lock.
            let raised = state.valid_round() < quorum_round;
            state = state.set_valid(quorum_round, value_id);

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
            // L39 latches per r ("for the first time with r >= round_p"), and the timeout
            // scheduled is for r, which may be ABOVE the round we are at. Using the
            // per-round bit would let a quorum for round 0 consume the only slot and leave
            // round 1's timeout unarmed forever.
            if state.arm_precommit_timeout(round) {
                Transition::to(state)
                    .with_output(Output::schedule_timeout(round, TimeoutKind::Precommit))
            } else {
                Transition::invalid(state)
            }
        }

        // L42-L43: decide. The fresh proposal supplies the value and its validity; the
        // n - f votes may come from a different round.
        // L42-L43. The guard is on `decision`, NOT on the step: `NewRound` resets the step
        // to Propose while carrying the decision forward, so a step-only guard would let a
        // second quorum overwrite a finalized value — two different values decided at one
        // height. The paper treats `decision_p` as write-once; L56 reads it as a latch.
        (_, Input::ProposalAndDecisionQuorum(proposal)) if state.decision.is_none() => {
            if !proposal.pol_round().is_nil() {
                // Only a fresh proposal establishes validity; a re-proposal carries an
                // identifier and cannot be decided on alone.
                return Transition::invalid(state);
            }
            let round = proposal.round();
            let value = proposal.value().clone();
            // Clearing the wait matters: a proposer that decided while still waiting would
            // otherwise have `awaiting_valid` set, and a later vote quorum would drive
            // propose_now — emitting a proposal from a committed state.
            state.awaiting_valid = false;
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

    // `awaiting_valid` is scoped to the round that set it: it means "we propose THIS round
    // and are waiting to learn a valid value first" (L10-L11). Entering any round clears
    // it, and only the proposer branch below sets it again. Without this it survives into
    // a round we do not propose, and the L36 guard at `VoteQuorumForValue` — which is
    // `awaiting_valid && is_proposer()` — would rest entirely on the proposer field.
    state.awaiting_valid = false;

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
