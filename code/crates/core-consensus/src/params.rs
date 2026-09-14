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
    ///
    /// Private, and this is load-bearing rather than tidiness. While it was public a
    /// caller could write `state.params.protocol = Fast` after construction, and the next
    /// `threshold_params()` would abort — not at startup, but inside a handler, or inside
    /// the `info!` block that logs the required voting power. Constructing a `Params` is
    /// now the only way to choose, and [`Params::classic`] is the only constructor, so the
    /// classic consensus path cannot hold a protocol it does not implement.
    protocol: ConsensusProtocol,

    /// The messages required to deliver proposals
    pub value_payload: ValuePayload,

    /// Whether consensus is enabled for this node
    pub enabled: bool,
}

impl<Ctx: Context> Params<Ctx> {
    /// Parameters for a node running classic Tendermint.
    ///
    /// The only constructor, deliberately. This module is the classic consensus path, and
    /// the fast protocol needs a driver that does not exist yet — so there is no way to
    /// build a `Params` the rest of this crate cannot honour. A `fast` constructor belongs
    /// here when that driver does, and `threshold_params` becomes fallible at that point.
    pub fn classic(address: Ctx::Address, value_payload: ValuePayload, enabled: bool) -> Self {
        Self {
            address,
            protocol: ConsensusProtocol::Classic,
            value_payload,
            enabled,
        }
    }

    /// Which protocol this node runs.
    pub fn protocol(&self) -> ConsensusProtocol {
        self.protocol
    }

    /// The classic quorum and honest thresholds, derived from the protocol.
    ///
    /// Total, not fallible: [`Params::classic`] is the only constructor and the field is
    /// private, so the protocol is always `Classic` here. An earlier version derived the
    /// same value through an `expect`, which was safe only by convention — the field was
    /// public, so a caller could change it after construction and turn a logging statement
    /// into an abort.
    pub fn threshold_params(&self) -> ThresholdParams {
        debug_assert_eq!(
            self.protocol,
            ConsensusProtocol::Classic,
            "only Params::classic can build this type"
        );
        ThresholdParams::default()
    }
}
