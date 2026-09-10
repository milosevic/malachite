//! Outputs of the Fast Tendermint round state machine.

use derive_where::derive_where;

use malachitebft_core_types::{Context, NilOrVal, Round, Timeout, TimeoutKind, ValueId};

/// Output of the Fast Tendermint round state machine.
///
/// This mirrors the classic output set, minus anything prevote-shaped, plus
/// [`Output::WaitForValid`] which has no classic counterpart.
#[derive_where(Clone, Debug, PartialEq, Eq)]
pub enum Output<Ctx>
where
    Ctx: Context,
{
    /// Move to the given round.
    NewRound(Round),

    /// Broadcast this proposal.
    Proposal(Ctx::Proposal),

    /// Broadcast this vote. Always a precommit — the protocol has one voting step.
    Vote(Ctx::Vote),

    /// Schedule this timeout.
    ScheduleTimeout(Timeout),

    /// Ask the application for a value, and schedule the propose timeout that bounds how
    /// long it has to build one.
    GetValueAndScheduleTimeout(Ctx::Height, Round, Timeout),

    /// As proposer of a round above 0, wait until `valid` is learned from the previous
    /// round before proposing, but no longer than this timeout (L45-L48).
    ///
    /// The paper writes `WaitForValid` as a bounded busy-wait inside `StartRound`. A pure
    /// transition function cannot block, so it is surfaced as an output: the caller arms
    /// the timeout and feeds back either the vote quorum that resolves the wait or
    /// [`crate::fast::input::Input::TimeoutPrecommit`].
    WaitForValid(Timeout),

    /// Re-propose the value we hold valid (L15-L16).
    ///
    /// The state machine holds only the *identifier*, so it cannot build a proposal
    /// itself: the caller resolves `value_id` against the retained fresh proposal and
    /// broadcasts `<PROPOSAL, round, value, valid_round>`. This is the direct consequence
    /// of re-proposals carrying `id(v)` rather than a full value.
    Repropose {
        /// The identifier to re-propose.
        value_id: ValueId<Ctx>,
        /// The round whose `2f+1` votes justify it — the paper's `valid_p.round`.
        valid_round: Round,
    },

    /// Decide `value`, which was proposed in `round`.
    Decision(Round, Ctx::Value),
}

impl<Ctx: Context> Output<Ctx> {
    /// Build a vote output for the protocol's single voting step.
    pub fn vote(
        ctx: &Ctx,
        height: Ctx::Height,
        round: Round,
        value_id: NilOrVal<ValueId<Ctx>>,
        address: Ctx::Address,
    ) -> Self {
        Output::Vote(ctx.new_precommit(height, round, value_id, address))
    }

    /// Build a `ScheduleTimeout` output.
    pub fn schedule_timeout(round: Round, kind: TimeoutKind) -> Self {
        Output::ScheduleTimeout(Timeout { round, kind })
    }
}
