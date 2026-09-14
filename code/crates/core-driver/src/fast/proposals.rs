//! Retained proposals for the fast protocol.

use alloc::collections::BTreeMap;

use derive_where::derive_where;
use malachitebft_core_types::{Context, Proposal, Round, Value, ValueId};

/// The fresh proposals seen this height, keyed by the identifier they carry.
///
/// Only a **fresh** proposal — one with `validRound = -1` — establishes that a value is
/// valid (Algorithm 1, L20-L21). A re-proposal carries only `id(v)` (L15), so the full
/// value can never be recovered from it. Two rules therefore need the original kept:
///
/// - **L42, deciding.** The decision pairs a fresh proposal from round `r` with `n - f`
///   votes from round `r'`, and the two rounds may differ. The proposal that supplies the
///   value may be several rounds behind the quorum that decides it.
/// - **L15-L16, re-proposing.** The round state machine holds only an identifier, so when
///   it asks to re-propose, the full value has to come from here.
///
/// Keyed by identifier rather than by round because both lookups are by identifier, and
/// because the same value may be proposed fresh in more than one round.
#[derive_where(Clone, Debug, Default)]
pub struct FreshProposals<Ctx: Context> {
    by_id: BTreeMap<ValueId<Ctx>, Ctx::Proposal>,
}

impl<Ctx: Context> FreshProposals<Ctx> {
    /// An empty store.
    pub fn new() -> Self {
        Self {
            by_id: BTreeMap::new(),
        }
    }

    /// Retain `proposal` if it is fresh.
    ///
    /// Re-proposals are ignored: they carry an identifier rather than a value, so they
    /// cannot establish validity and there is nothing in them worth keeping. The first
    /// fresh proposal for an identifier wins — a later one carries the same value by
    /// definition, since the identifier is derived from it.
    pub fn keep(&mut self, proposal: Ctx::Proposal) -> bool {
        if proposal.pol_round().is_defined() {
            return false;
        }

        let id = proposal.value().id();
        if self.by_id.contains_key(&id) {
            return false;
        }

        self.by_id.insert(id, proposal);
        true
    }

    /// The fresh proposal that established `value_id`, if one has been seen.
    pub fn get(&self, value_id: &ValueId<Ctx>) -> Option<&Ctx::Proposal> {
        self.by_id.get(value_id)
    }

    /// How many fresh proposals are retained.
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// Whether nothing is retained.
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Forget everything, for use when the height changes.
    ///
    /// Deliberately not pruned by round: a proposal from an early round stays relevant for
    /// the whole height, because L42 lets the deciding quorum arrive in any later round.
    /// The bound is the number of distinct values proposed in one height, not the number
    /// of rounds.
    pub fn clear(&mut self) {
        self.by_id.clear();
    }

    /// The round of the retained fresh proposal for `value_id`.
    pub fn round_of(&self, value_id: &ValueId<Ctx>) -> Option<Round> {
        self.by_id.get(value_id).map(|p| p.round())
    }
}
