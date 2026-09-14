use derive_where::derive_where;

use malachitebft_core_types::{ConsensusProtocol, Context, Round, ValuePayload};

/// The round from which we enable the hidden lock mitigation mechanism
pub const HIDDEN_LOCK_ROUND: Round = Round::new(10);

/// Maximum number of rounds ahead of the current consensus round from which
/// votes are accepted at the current height.
///
/// Votes whose round exceeds `current_round + MAX_FUTURE_ROUND_LOOKAHEAD` are
/// dropped before signature verification and WAL append, bounding per-height
/// vote-keeper state, signature verification work, and WAL I/O regardless of
/// the round numbers carried by incoming votes.
///
/// The bound still allows the `SkipRound` mechanism (`f+1` honest votes at a
/// higher round trigger a round skip) to catch up progressively: as the
/// current round advances, the ceiling slides with it, so votes that were
/// previously out of range become acceptable.
pub const MAX_FUTURE_ROUND_LOOKAHEAD: u32 = 10;

#[doc(inline)]
pub use malachitebft_core_driver::ThresholdParams;

/// Consensus parameters.
#[derive_where(Clone, Debug)]
pub struct Params<Ctx: Context> {
    /// The address of this validator
    pub address: Ctx::Address,

    /// Which consensus protocol this node runs.
    ///
    /// The **single** source for the thresholds — they are derived from it by
    /// [`Params::threshold_params`] rather than stored alongside it. Storing both would
    /// let them disagree, and a `Fast` protocol paired with classic 2/3 thresholds would
    /// compile and run a fast node on classic quorums.
    pub protocol: ConsensusProtocol,

    /// The messages required to deliver proposals
    pub value_payload: ValuePayload,

    /// Whether consensus is enabled for this node
    pub enabled: bool,
}

impl<Ctx: Context> Params<Ctx> {
    /// The classic quorum and honest thresholds, derived from [`Params::protocol`].
    ///
    /// # Panics
    ///
    /// If the protocol is [`ConsensusProtocol::Fast`], which has no honest threshold and
    /// therefore no `ThresholdParams` at all. That is a construction error rather than a
    /// runtime condition: this whole module is the CLASSIC consensus path, and a fast node
    /// needs a fast driver that does not exist yet. [`crate::State::new`] checks for it up
    /// front so the failure lands at startup with a clear message, not inside a handler.
    pub fn threshold_params(&self) -> ThresholdParams {
        self.protocol.classic_threshold_params().expect(
            "the fast protocol has no classic thresholds; \
             a fast node cannot run through the classic consensus path",
        )
    }
}
