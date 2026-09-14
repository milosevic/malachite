//! The Fast Tendermint driver.

use alloc::vec::Vec;

use derive_where::derive_where;

use malachitebft_core_state_machine::fast::input::Input as RoundInput;
use malachitebft_core_state_machine::fast::output::Output as RoundOutput;
use malachitebft_core_state_machine::fast::state::State as RoundState;
use malachitebft_core_state_machine::fast::state_machine::{apply, Info};
use malachitebft_core_types::{
    Context, NilOrVal, Proposal, Round, SignedVote, Timeout, TimeoutKind, Validator,
    ValidatorSet, Validity, Value, Vote, VoteType,
};
use malachitebft_core_votekeeper::fast::keeper::{FastVoteKeeper, Output as KeeperOutput};
use malachitebft_core_votekeeper::fast::params::FastThresholdParams;

use crate::fast::proposals::FreshProposals;

/// What the driver is asked to do.
#[derive_where(Clone, Debug, PartialEq, Eq)]
pub enum Input<Ctx: Context> {
    /// Start a round, naming its proposer.
    ///
    /// The proposer is carried here rather than set by a separate call because
    /// `start_round` is the only place the fast state machine consults it (L6-L18), and a
    /// round entered with the previous round's proposer takes the wrong branch there: a
    /// node that proposed `r-1` and does not propose `r` would follow the proposer path in
    /// `r`, and the mirror case would silently miss its own proposal slot. Folding it into
    /// the input means the question cannot be asked. The classic driver does the same
    /// (`Input::NewRound(height, round, proposer)`).
    NewRound(Round, Ctx::Address),
    /// The application built a value for us to propose.
    ProposeValue(Round, Ctx::Value),
    /// A proposal arrived, with the application's verdict on its validity.
    Proposal(Ctx::Proposal, Validity),
    /// A vote arrived.
    Vote(SignedVote<Ctx>),
    /// A scheduled timeout fired.
    TimeoutElapsed(Timeout),
    /// The proposer's bounded `WaitForValid` ran out (L46).
    WaitForValidExpired,
}

/// What the driver asks its caller to do.
///
/// The same as the round state machine's outputs, except that `Repropose` is resolved: the
/// state machine names an identifier, and the driver turns it back into a proposal.
#[derive_where(Clone, Debug, PartialEq, Eq)]
pub enum Output<Ctx: Context> {
    /// Move to this round.
    NewRound(Round),
    /// Broadcast this proposal.
    Proposal(Ctx::Proposal),
    /// Broadcast this vote. Always a precommit.
    Vote(Ctx::Vote),
    /// Schedule this timeout.
    ScheduleTimeout(Timeout),
    /// Ask the application for a value, and schedule the propose timeout.
    GetValueAndScheduleTimeout(Ctx::Height, Round, Timeout),
    /// Wait to learn `valid` before proposing, but no longer than this timeout.
    WaitForValid(Timeout),
    /// Decide this value, proposed in this round.
    Decision(Round, Ctx::Value),
}

/// Drives one height of Fast Tendermint.
pub struct Driver<Ctx: Context> {
    ctx: Ctx,
    address: Ctx::Address,
    validator_set: Ctx::ValidatorSet,
    /// The proposer of the round we are at. Only `Input::NewRound` writes it, and only
    /// when the state machine actually enters the round — a refused `NewRound` restores
    /// the previous value — so it always describes the round `round_state` is in.
    proposer: Ctx::Address,
    vote_keeper: FastVoteKeeper<Ctx>,
    proposals: FreshProposals<Ctx>,
    round_state: RoundState<Ctx>,
}

impl<Ctx: Context> Driver<Ctx> {
    /// Create a driver for `height`.
    pub fn new(
        ctx: Ctx,
        height: Ctx::Height,
        validator_set: Ctx::ValidatorSet,
        address: Ctx::Address,
        proposer: Ctx::Address,
        threshold_params: FastThresholdParams,
    ) -> Self {
        let driver = Self {
            ctx,
            address,
            proposer,
            vote_keeper: FastVoteKeeper::new(validator_set.clone(), threshold_params),
            validator_set,
            proposals: FreshProposals::new(),
            round_state: RoundState::new(height, Round::Nil),
        };

        if quint_oracle::enabled() {
            driver.oracle_log_new();
        }

        driver
    }

    /// Quint oracle: the model names validators by letter, with our own address
    /// always `a` and the rest lettered by their position in the validator set.
    /// An address outside the set is `z`, which the model's VOTERS domain holds
    /// so the discard branch stays expressible.
    fn oracle_addr(&self, address: &Ctx::Address) -> &'static str {
        const LETTERS: [&str; 6] = ["a", "b", "c", "d", "e", "f"];
        if address == &self.address {
            return LETTERS[0];
        }
        let me = (0..self.validator_set.count())
            .find(|i| self.validator_set.get_by_index(*i).map(|v| v.address()) == Some(&self.address));
        let idx = (0..self.validator_set.count())
            .find(|i| self.validator_set.get_by_index(*i).map(|v| v.address()) == Some(address));
        match (idx, me) {
            // Rank among the validators that are not us, shifted past `a`.
            (Some(i), Some(m)) => {
                let rank = if i < m { i } else { i - 1 };
                LETTERS.get(rank + 1).copied().unwrap_or("z")
            }
            (Some(i), None) => LETTERS.get(i).copied().unwrap_or("z"),
            (None, _) => "z",
        }
    }

    /// Quint oracle: report the constructed baseline. The whole payload the
    /// model needs is one argument, so replay never searches at step 0.
    fn oracle_log_new(&self) {
        let proposer = self.oracle_addr(&self.proposer);
        quint_oracle::Event::builder(quint_oracle::current_test(), "Drivernew")
            .argument("proposer", proposer, Some("VALIDATORS"))
            .assert(
                alloc::vec::Vec::from([
                    quint_oracle::PathSeg::ident("d"),
                    quint_oracle::PathSeg::ident("rs"),
                    quint_oracle::PathSeg::ident("round"),
                ]),
                self.round_state.round().as_i64(),
            )
            .scope("fast-driver")
            .send();
    }

    /// The round we are at.
    pub fn round(&self) -> Round {
        self.round_state.round()
    }

    /// The decided value and the round of the proposal it came from.
    pub fn decision(&self) -> Option<&(Round, Ctx::Value)> {
        self.round_state.decision()
    }

    /// The validator set for this height.
    pub fn validator_set(&self) -> &Ctx::ValidatorSet {
        &self.validator_set
    }

    /// Apply one input and return everything the caller should act on.
    pub fn process(&mut self, input: Input<Ctx>) -> Vec<Output<Ctx>> {
        // Quint oracle: describe the input the way the spec models it — the
        // constructor by name plus the scalar fields it carries — before
        // `input` is moved into the match below. Fields an input does not carry
        // are pinned to values the model always holds, so replay never searches
        // them blind.
        let oracle_on = quint_oracle::enabled();
        let (
            oracle_tag,
            oracle_round,
            oracle_value,
            oracle_pol,
            oracle_validity,
            oracle_voter,
            oracle_vtype,
            oracle_kind,
        ) = if oracle_on {
            match &input {
                Input::NewRound(round, _) => (
                    "NewRound",
                    round.as_i64(),
                    alloc::string::String::from("v"),
                    -1,
                    true,
                    "a",
                    "Precommit",
                    "Propose",
                ),
                Input::ProposeValue(round, value) => (
                    "ProposeValue",
                    round.as_i64(),
                    alloc::format!("{}", value.id()),
                    -1,
                    true,
                    "a",
                    "Precommit",
                    "Propose",
                ),
                Input::Proposal(proposal, validity) => (
                    "Proposal",
                    proposal.round().as_i64(),
                    alloc::format!("{}", proposal.value().id()),
                    proposal.pol_round().as_i64(),
                    validity.is_valid(),
                    "a",
                    "Precommit",
                    "Propose",
                ),
                Input::Vote(vote) => (
                    "Vote",
                    vote.round().as_i64(),
                    match vote.value() {
                        NilOrVal::Nil => alloc::string::String::from("Nil"),
                        NilOrVal::Val(id) => alloc::format!("{id}"),
                    },
                    -1,
                    true,
                    self.oracle_addr(vote.validator_address()),
                    if vote.vote_type() == VoteType::Precommit {
                        "Precommit"
                    } else {
                        "Prevote"
                    },
                    "Propose",
                ),
                Input::TimeoutElapsed(timeout) => (
                    "TimeoutElapsed",
                    timeout.round.as_i64(),
                    alloc::string::String::from("v"),
                    -1,
                    true,
                    "a",
                    "Precommit",
                    match timeout.kind {
                        TimeoutKind::Propose => "Propose",
                        TimeoutKind::Precommit => "Precommit",
                        TimeoutKind::Prevote => "Prevote",
                        TimeoutKind::Rebroadcast => "Rebroadcast",
                        _ => "FinalizeHeight",
                    },
                ),
                Input::WaitForValidExpired => (
                    "WaitForValidExpired",
                    self.round_state.round().as_i64(),
                    alloc::string::String::from("v"),
                    -1,
                    true,
                    "a",
                    "Precommit",
                    "Propose",
                ),
            }
        } else {
            (
                "",
                -1,
                alloc::string::String::new(),
                -1,
                true,
                "a",
                "Precommit",
                "Propose",
            )
        };

        let outputs = self.process_inner(input);

        if oracle_on {
            quint_oracle::Event::builder(quint_oracle::current_test(), "Driverprocess")
                .argument("inputTag", oracle_tag, Some("ALL_TAGS"))
                .argument("iround", oracle_round, None)
                .argument("ivalue", oracle_value.as_str(), Some("VOTE_VALUES"))
                .argument("ipol", oracle_pol, None)
                .argument("ivalidity", oracle_validity, None)
                .argument("ivoter", oracle_voter, Some("VOTERS"))
                .argument("ivtype", oracle_vtype, Some("VOTE_TYPES"))
                .argument("ikind", oracle_kind, Some("KIND_NAMES"))
                // Conformance facts: the round the driver is at, and how many
                // outputs the call actually returned.
                .assert(
                    alloc::vec::Vec::from([
                        quint_oracle::PathSeg::ident("d"),
                        quint_oracle::PathSeg::ident("rs"),
                        quint_oracle::PathSeg::ident("round"),
                    ]),
                    self.round_state.round().as_i64(),
                )
                .assert(
                    alloc::vec::Vec::from([quint_oracle::PathSeg::ident("lastOutputCount")]),
                    outputs.len() as i64,
                )
                .scope("fast-driver")
                .send();
        }

        outputs
    }

    /// The routing itself, split out so `process` can report the call to the
    /// Quint oracle without the match arms having to know about it.
    fn process_inner(&mut self, input: Input<Ctx>) -> Vec<Output<Ctx>> {
        match input {
            Input::NewRound(round, proposer) => {
                // The proposer has to be in place before `apply_round`, because
                // `start_round` reads it through `Info::is_proposer` on this very call.
                //
                // But the state machine REFUSES a `NewRound` for a round at or below the
                // one we are in, and for any round at all once we have decided. A refused
                // input must not leave us holding the proposer of a round we never
                // entered: every later input reads this field through `Info`, so a
                // duplicated, replayed or stale `NewRound` would otherwise desynchronize
                // it from `round_state.round` permanently. So it is restored on refusal.
                let previous = core::mem::replace(&mut self.proposer, proposer);
                let (outputs, entered) = self.apply_round_checked(RoundInput::NewRound(round), round);
                if !entered {
                    self.proposer = previous;
                }
                outputs
            }

            Input::ProposeValue(round, value) => {
                self.apply_round(RoundInput::ProposeValue(value), round)
            }

            Input::Proposal(proposal, validity) => self.apply_proposal(proposal, validity),

            Input::Vote(vote) => self.apply_vote(vote),

            Input::TimeoutElapsed(timeout) => match timeout.kind {
                TimeoutKind::Propose => {
                    self.apply_round(RoundInput::TimeoutPropose, timeout.round)
                }
                TimeoutKind::Precommit => {
                    self.apply_round(RoundInput::TimeoutPrecommit, timeout.round)
                }
                // The protocol has no prevote step, and the other kinds are not per-round.
                _ => Vec::new(),
            },

            Input::WaitForValidExpired => {
                let round = self.round_state.round();
                self.apply_round(RoundInput::WaitForValidExpired, round)
            }
        }
    }

    /// L20-L34. Route a proposal by whether it is fresh or a re-proposal, and in the
    /// latter case only once the keeper confirms the justification it names.
    fn apply_proposal(&mut self, proposal: Ctx::Proposal, validity: Validity) -> Vec<Output<Ctx>> {
        let round = proposal.round();
        let value_id = proposal.value().id();
        let pol_round = proposal.pol_round();

        // Only a proposal the application accepted may be retained. An earlier version
        // kept every proposal, reasoning that one we vote nil on might still supply the
        // value for a later decision — which conflates two different nil votes. Voting nil
        // because L21's binding clause forbids the value is a reason to KEEP it; voting
        // nil because `validate(v)` failed is not, and retaining it would let an invalid
        // value be decided at L42. Malachite lets applications define validity and does
        // not guarantee it is deterministic, so this is the safety-relevant direction.
        if validity.is_valid() {
            self.proposals.keep(proposal.clone());
        }

        let input = if pol_round.is_nil() {
            // L20: a fresh proposal.
            if validity.is_valid() {
                RoundInput::Proposal(proposal)
            } else {
                RoundInput::InvalidProposal
            }
        } else {
            // L27: a re-proposal is only offered once `2f+1` votes from the round it names
            // actually exist. Without that check the state machine would be asked to trust
            // a justification nobody verified.
            let justified = self.vote_keeper.has_vote_quorum(pol_round, &value_id);
            if justified && validity.is_valid() {
                RoundInput::ProposalAndVoteQuorumPrevious(proposal)
            } else {
                RoundInput::InvalidProposalAndVoteQuorumPrevious(proposal)
            }
        };

        let mut outputs = self.apply_round(input, round);

        // L42 is a symmetric `upon`: both conjuncts persist and whichever arrives SECOND
        // fires it. Evaluating it only on the vote edge lost the decision whenever the
        // quorum arrived first — the keeper latches each threshold once and never
        // re-reports it, so nothing would have fired again. Votes-before-value is the
        // normal ordering for a lagging node, since votes are small and sync delivers
        // certificates ahead of payloads.
        if validity.is_valid() && self.round_state.decision().is_none() {
            if let Some(quorum_round) = self.vote_keeper.decision_quorum_round(&value_id) {
                if let Some(retained) = self.proposals.get(&value_id).cloned() {
                    outputs.extend(self.apply_round(
                        RoundInput::ProposalAndDecisionQuorum(retained),
                        quorum_round,
                    ));
                }
            }
        }

        outputs
    }

    /// Feed a vote to the keeper and turn each threshold it reports into a round input.
    fn apply_vote(&mut self, vote: SignedVote<Ctx>) -> Vec<Output<Ctx>> {
        let mut outputs = Vec::new();

        for reported in self.vote_keeper.apply_vote(vote) {
            let (input, round) = match reported {
                // L36/L47. The round is carried through rather than assumed to be ours:
                // the state machine refuses a quorum for a round above its own, and it can
                // only do that if the round survives the trip.
                KeeperOutput::VoteQuorumValue(round, value_id) => {
                    (RoundInput::VoteQuorumForValue(round, value_id), round)
                }

                // L39. Arms the precommit timeout for the quorum's round.
                KeeperOutput::QuorumAny(round) => (RoundInput::QuorumAny(round), round),

                // L42. The votes decide, but the VALUE comes from the fresh proposal that
                // established it, which may be from an earlier round. Without that
                // proposal there is nothing to decide on, so the quorum waits.
                KeeperOutput::DecisionQuorumValue(round, value_id) => {
                    match self.proposals.get(&value_id) {
                        Some(proposal) => (
                            RoundInput::ProposalAndDecisionQuorum(proposal.clone()),
                            round,
                        ),
                        None => continue,
                    }
                }
            };

            outputs.extend(self.apply_round(input, round));
        }

        outputs
    }

    /// Apply one round input and resolve the state machine's outputs.
    fn apply_round(&mut self, input: RoundInput<Ctx>, input_round: Round) -> Vec<Output<Ctx>> {
        self.apply_round_checked(input, input_round).0
    }

    /// As [`Driver::apply_round`], but also reports whether the state machine accepted the
    /// input. Only the `NewRound` path needs that: it is the one input that writes driver
    /// state of its own before applying, and so the one that must undo it on refusal.
    fn apply_round_checked(
        &mut self,
        input: RoundInput<Ctx>,
        input_round: Round,
    ) -> (Vec<Output<Ctx>>, bool) {
        let info = Info::new(input_round, &self.address, &self.proposer);
        // The height is read before the state is taken: reading through `self` inside the
        // replace would borrow what is already mutably borrowed.
        let height = self.round_state.height();
        let state = core::mem::replace(&mut self.round_state, RoundState::new(height, Round::Nil));

        let transition = apply(&self.ctx, state, &info, input);
        self.round_state = transition.next_state;
        let valid = transition.valid;

        let outputs = match transition.output {
            None => Vec::new(),
            Some(output) => self.resolve(output).into_iter().collect(),
        };
        (outputs, valid)
    }

    /// Turn a round-state-machine output into a driver output.
    ///
    /// The only one that needs work is `Repropose`: the state machine holds an identifier,
    /// so the driver looks up the fresh proposal that carried the value and builds the
    /// re-proposal from it. If that proposal is missing the re-proposal is dropped rather
    /// than faked — a re-proposal naming a value nobody can produce is unusable to every
    /// receiver.
    fn resolve(&self, output: RoundOutput<Ctx>) -> Option<Output<Ctx>> {
        Some(match output {
            RoundOutput::NewRound(round) => Output::NewRound(round),
            RoundOutput::Proposal(proposal) => Output::Proposal(proposal),
            RoundOutput::Vote(vote) => Output::Vote(vote),
            RoundOutput::ScheduleTimeout(timeout) => Output::ScheduleTimeout(timeout),
            RoundOutput::GetValueAndScheduleTimeout(height, round, timeout) => {
                Output::GetValueAndScheduleTimeout(height, round, timeout)
            }
            RoundOutput::WaitForValid(timeout) => Output::WaitForValid(timeout),
            RoundOutput::Decision(round, value) => Output::Decision(round, value),

            RoundOutput::Repropose {
                value_id,
                valid_round,
            } => match self.proposals.get(&value_id) {
                Some(original) => Output::Proposal(self.ctx.new_proposal(
                    self.round_state.height(),
                    self.round_state.round(),
                    original.value().clone(),
                    valid_round,
                    self.address.clone(),
                )),

                // We hold an identifier valid but never saw the fresh proposal that
                // carried its value. This is ORDINARY, not exotic: `valid` is set from
                // vote quorums, and votes carry only `id(v)`.
                //
                // The paper has no such problem — L15-L16 broadcasts the identifier, and a
                // proposer never needs the value. Reconstructing a full-value proposal is
                // this driver's divergence, and closing it properly needs the
                // value-or-id proposal type the plan already calls for.
                //
                // Until then: schedule the propose timeout rather than emitting nothing.
                // Emitting nothing left the node in `Propose` as proposer with no
                // proposal, no timeout and no wait — stalled until some other node's
                // quorum happened to arm one. With the timeout, the round ends, everyone
                // votes nil, and the height makes progress.
                None => Output::ScheduleTimeout(Timeout {
                    round: self.round_state.round(),
                    kind: TimeoutKind::Propose,
                }),
            },
        })
    }
}

/// Re-exported so callers need not reach into the state machine crate.
pub use malachitebft_core_state_machine::fast::state::Step;
