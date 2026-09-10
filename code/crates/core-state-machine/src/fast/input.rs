//! Inputs to the Fast Tendermint round state machine.

use derive_where::derive_where;

use malachitebft_core_types::{Context, Round, ValueId};

/// Input to the Fast Tendermint round state machine.
///
/// Compared with classic Tendermint, the whole polka family is gone (there is one voting
/// step, not two) and so is `SkipRound`: the paper removes the `f+1`
/// one-correct-process-in-a-higher-round rule, leaving the `n - f` quorum-any rule of
/// [`Input::QuorumAny`] as the only way to move up a round.
///
/// Two distinct thresholds over the *same* vote tally reach this state machine, and the
/// caller is responsible for telling them apart:
///
/// - `2f+1` for a value, via [`Input::VoteQuorumForValue`] and
///   [`Input::ProposalAndVoteQuorumPrevious`] — enough to make a value *valid*, and to
///   justify a re-proposal.
/// - `n - f`, via [`Input::QuorumAny`] and [`Input::ProposalAndDecisionQuorum`] — enough to
///   advance a round, and enough to decide.
#[derive_where(Clone, Debug, PartialEq, Eq)]
pub enum Input<Ctx>
where
    Ctx: Context,
{
    /// Start `round` (L6).
    NewRound(Round),

    /// The value the application built for us to propose (L13).
    ///
    /// Only meaningful for the proposer, and only once it is no longer waiting on
    /// `WaitForValid`.
    ProposeValue(Ctx::Value),

    /// A **fresh** proposal from the round's proposer, carrying a full value and
    /// `validRound = -1` (L20).
    Proposal(Ctx::Proposal),

    /// A fresh proposal the application rejected, or one we will not vote for (L23-L24).
    InvalidProposal,

    /// A **re-proposal** together with the `2f+1` votes from round `validRound` that
    /// justify it (L27).
    ///
    /// The proposal's own `pol_round` is the paper's `vr`.
    ProposalAndVoteQuorumPrevious(Ctx::Proposal),

    /// A re-proposal whose justification we reject, or whose value we will not vote for
    /// (L33).
    InvalidProposalAndVoteQuorumPrevious(Ctx::Proposal),

    /// `2f+1` votes for `id(v)` in the round we are at (L36) — the observation rule.
    VoteQuorumForValue(ValueId<Ctx>),

    /// `n - f` votes for *any* value at a round at or above ours, seen for the first time
    /// (L39).
    ///
    /// This arms the precommit timeout, and is the only path that advances a round.
    QuorumAny(Round),

    /// A fresh proposal for `v` together with `n - f` votes for `id(v)` (L42).
    ///
    /// The proposal's round and the votes' round may differ; the fresh proposal is what
    /// establishes validity, so it is the proposal — not the votes — that carries the value.
    ProposalAndDecisionQuorum(Ctx::Proposal),

    /// The propose timeout elapsed (L50).
    TimeoutPropose,

    /// The precommit timeout elapsed (L55).
    TimeoutPrecommit,

    /// The bounded wait a proposer performs before proposing has expired (L46).
    ///
    /// The paper bounds `WaitForValid` with `timeoutPrecommit(round_p)`, but that is a
    /// *duration* passed into `StartRound`, not the scheduled `OnTimeoutPrecommit` that
    /// advances the round. Modelling them as one input would conflate "stop waiting and
    /// propose" with "give up on this round", so the wait gets its own input.
    WaitForValidExpired,
}
