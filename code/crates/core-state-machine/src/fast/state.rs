//! State of the Fast Tendermint round state machine.

use derive_where::derive_where;

use malachitebft_core_types::{Context, Round, TimeoutKind, ValueId};

/// A value identifier and the round it became valid in.
///
/// The paper's `valid_p` is a `(round, id(value))` pair (L4). We keep the **identifier**,
/// not the value: a re-proposal carries only `id(v)` (L15), and the full value is recovered
/// from the retained fresh proposal when a decision is reached (L42).
#[derive_where(Clone, Debug, PartialEq, Eq)]
pub struct RoundValueId<Ctx: Context> {
    /// The round in which this identifier became valid.
    pub round: Round,
    /// The value identifier.
    pub value_id: ValueId<Ctx>,
}

impl<Ctx: Context> RoundValueId<Ctx> {
    /// Create a new `RoundValueId`.
    pub fn new(round: Round, value_id: ValueId<Ctx>) -> Self {
        Self { round, value_id }
    }
}

/// Tracks which of this round's timeouts have already been scheduled.
///
/// Fast Tendermint has only two per-round timeouts — there is no prevote step — so this is
/// two bits rather than the classic three.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ScheduledTimeouts {
    bits: u8,
}

impl ScheduledTimeouts {
    const PROPOSE_BIT: u8 = 1 << 0;
    const PRECOMMIT_BIT: u8 = 1 << 1;

    /// Clear every recorded timeout, for use when the round changes.
    pub fn clear(&mut self) {
        self.bits = 0;
    }

    /// Record `timeout` as scheduled and report whether it was newly recorded.
    ///
    /// Returns `false` for a timeout already scheduled in this round, and for any timeout
    /// kind this state machine does not track per round.
    pub fn check(&mut self, timeout: TimeoutKind) -> bool {
        match Self::mask(timeout) {
            Some(mask) => {
                let was_scheduled = (self.bits & mask) != 0;
                self.bits |= mask;
                !was_scheduled
            }
            None => false,
        }
    }

    const fn mask(timeout: TimeoutKind) -> Option<u8> {
        match timeout {
            TimeoutKind::Propose => Some(Self::PROPOSE_BIT),
            TimeoutKind::Precommit => Some(Self::PRECOMMIT_BIT),
            // Prevote does not exist in this protocol; Rebroadcast and FinalizeHeight are
            // not per-round.
            _ => None,
        }
    }
}

/// The step of a Fast Tendermint round.
///
/// The paper's `step_p` ranges over `{propose, precommit}` (L2); `Unstarted` and `Commit`
/// bracket those the way they do in the classic state machine.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Step {
    /// The round has not started yet.
    Unstarted,
    /// Waiting for a proposal, or building one as proposer.
    Propose,
    /// Our vote for this round has been cast.
    Precommit,
    /// A value has been decided.
    Commit,
}

/// The state of the Fast Tendermint round state machine.
#[derive_where(Clone, Debug, PartialEq, Eq)]
pub struct State<Ctx>
where
    Ctx: Context,
{
    /// The height being decided.
    pub height: Ctx::Height,

    /// The round we are at within the height.
    pub round: Round,

    /// The step we are at within the round.
    pub step: Step,

    /// The paper's `valid_p` (L4): the highest round in which we saw `2f+1` votes for a
    /// value, and that value's identifier. `None` is the paper's `(-1, nil)`.
    ///
    /// This single field replaces classic Tendermint's `locked` **and** `valid`. There is
    /// consequently no "unlock" transition: a re-proposal is accepted when its justifying
    /// round is at least ours, or when it re-proposes the same identifier (L28).
    pub valid: Option<RoundValueId<Ctx>>,

    /// The decided value and the round of the proposal it was decided from.
    ///
    /// The decision round may differ from `round`: L42 pairs a fresh proposal from one
    /// round with `n - f` votes from another.
    pub decision: Option<(Round, Ctx::Value)>,

    /// Whether the proposer of this round is still waiting to learn `valid` before
    /// proposing — the paper's `WaitForValid` (L45-L48).
    ///
    /// A pure transition function cannot block, so the wait is represented as state: the
    /// proposer enters `Propose` with this set, and leaves it when either `valid` advances
    /// far enough or the precommit timeout fires.
    pub awaiting_valid: bool,

    /// Timeouts already scheduled in the current round.
    #[derive_where(skip(EqHashOrd))]
    pub scheduled_timeouts: ScheduledTimeouts,
}

impl<Ctx> State<Ctx>
where
    Ctx: Context,
{
    /// Create a new state at the given height and round, with nothing valid or decided.
    pub fn new(height: Ctx::Height, round: Round) -> Self {
        Self {
            height,
            round,
            step: Step::Unstarted,
            valid: None,
            decision: None,
            awaiting_valid: false,
            scheduled_timeouts: ScheduledTimeouts::default(),
        }
    }

    /// The round recorded in `valid`, or `Round::Nil` when nothing is valid yet.
    ///
    /// This is the paper's `valid_p.round`, whose initial value is `-1`.
    pub fn valid_round(&self) -> Round {
        self.valid.as_ref().map_or(Round::Nil, |v| v.round)
    }

    /// Whether `value_id` is the identifier currently recorded in `valid`.
    pub fn valid_is(&self, value_id: &ValueId<Ctx>) -> bool {
        self.valid.as_ref().is_some_and(|v| &v.value_id == value_id)
    }

    /// Set the step.
    pub fn with_step(self, step: Step) -> Self {
        Self { step, ..self }
    }

    /// Move to `round`, clearing the per-round timeout bookkeeping.
    ///
    /// `valid` and `decision` are per-height and deliberately survive.
    pub fn update_round(&mut self, round: Round) {
        self.round = round;
        self.scheduled_timeouts.clear();
    }

    /// Record `2f+1` votes for `value_id` seen in `round` (L30, L37, L48).
    ///
    /// The paper only ever raises `valid_p`, so this is a no-op when `round` is not above
    /// the round already recorded.
    pub fn set_valid(mut self, round: Round, value_id: ValueId<Ctx>) -> Self {
        if self.valid_round() < round {
            self.valid = Some(RoundValueId::new(round, value_id));
        }
        self
    }

    /// Record the decided value and the round of the proposal it came from (L43).
    pub fn set_decision(self, proposal_round: Round, value: Ctx::Value) -> Self {
        Self {
            decision: Some((proposal_round, value)),
            ..self
        }
    }

    /// Check whether `timeout` can still be scheduled in this round.
    pub fn check_timeout(&mut self, timeout: TimeoutKind) -> bool {
        self.scheduled_timeouts.check(timeout)
    }
}
