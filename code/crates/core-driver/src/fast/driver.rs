//! The Fast Tendermint driver.

use alloc::vec::Vec;

use derive_where::derive_where;

use malachitebft_core_state_machine::fast::input::Input as RoundInput;
use malachitebft_core_state_machine::fast::output::Output as RoundOutput;
use malachitebft_core_state_machine::fast::state::State as RoundState;
use malachitebft_core_state_machine::fast::state_machine::{apply, Info};
use malachitebft_core_types::{
    Context, Proposal, Round, SignedVote, Timeout, TimeoutKind, Validity, Value,
};
use malachitebft_core_votekeeper::fast::keeper::{FastVoteKeeper, Output as KeeperOutput};
use malachitebft_core_votekeeper::fast::params::FastThresholdParams;

use crate::fast::proposals::FreshProposals;

/// What the driver is asked to do.
#[derive_where(Clone, Debug, PartialEq, Eq)]
pub enum Input<Ctx: Context> {
    /// Start a round.
    NewRound(Round),
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
        Self {
            ctx,
            address,
            proposer,
            vote_keeper: FastVoteKeeper::new(validator_set.clone(), threshold_params),
            validator_set,
            proposals: FreshProposals::new(),
            round_state: RoundState::new(height, Round::Nil),
        }
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

    /// Set the proposer for the round being entered.
    pub fn set_proposer(&mut self, proposer: Ctx::Address) {
        self.proposer = proposer;
    }

    /// Apply one input and return everything the caller should act on.
    pub fn process(&mut self, input: Input<Ctx>) -> Vec<Output<Ctx>> {
        match input {
            Input::NewRound(round) => self.apply_round(RoundInput::NewRound(round), round),

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

        // Keep it before routing: even a proposal we vote nil on may be the one that
        // supplies the value for a decision several rounds later (L42).
        self.proposals.keep(proposal.clone());

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

        self.apply_round(input, round)
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
        let info = Info::new(input_round, &self.address, &self.proposer);
        // The height is read before the state is taken: reading through `self` inside the
        // replace would borrow what is already mutably borrowed.
        let height = self.round_state.height();
        let state = core::mem::replace(&mut self.round_state, RoundState::new(height, Round::Nil));

        let transition = apply(&self.ctx, state, &info, input);
        self.round_state = transition.next_state;

        match transition.output {
            None => Vec::new(),
            Some(output) => self.resolve(output).into_iter().collect(),
        }
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
            } => {
                let original = self.proposals.get(&value_id)?;
                Output::Proposal(self.ctx.new_proposal(
                    self.round_state.height(),
                    self.round_state.round(),
                    original.value().clone(),
                    valid_round,
                    self.address.clone(),
                ))
            }
        })
    }
}

/// Re-exported so callers need not reach into the state machine crate.
pub use malachitebft_core_state_machine::fast::state::Step;
