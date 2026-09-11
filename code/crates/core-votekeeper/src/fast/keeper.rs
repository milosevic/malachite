//! The Fast Tendermint vote keeper.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use derive_where::derive_where;

use malachitebft_core_types::{
    Context, NilOrVal, Round, SignedVote, Validator, ValidatorSet, ValueId, Vote,
};

use crate::evidence::EvidenceMap;
use crate::fast::params::FastThresholdParams;
use crate::round_weights::RoundWeights;
use crate::value_weights::ValuesWeights;
use crate::Weight;

/// What the keeper reports when a threshold is crossed.
///
/// The two value-thresholds are **separate variants on purpose**. Crossing `2f+1` must not
/// suppress a later `n - f` in the same round: the first makes a value valid (L36), the
/// second decides it (L42), and a consumer needs both events. There is no `SkipRound`.
#[derive_where(Clone, Debug, PartialEq, Eq)]
pub enum Output<Ctx: Context> {
    /// `2f+1` votes for this value in this round — the observation rule (L36), and the
    /// justification a re-proposal needs (L27).
    VoteQuorumValue(ValueId<Ctx>),

    /// `n - f` votes for this value — enough to decide (L42).
    DecisionQuorumValue(ValueId<Ctx>),

    /// `n - f` votes spread across any values, including nil (L39).
    ///
    /// Arms the precommit timeout, and is the only path that advances a round.
    QuorumAny,
}

/// Which outputs a round has already reported, so each fires at most once per round.
///
/// Keyed per output *kind and value*, not per vote type — that is what lets `2f+1` and
/// `n - f` for the same value both fire.
#[derive_where(Clone, Debug, PartialEq, Eq, Default)]
struct Emitted<Ctx: Context> {
    vote_quorum: BTreeSet<ValueId<Ctx>>,
    decision_quorum: BTreeSet<ValueId<Ctx>>,
    quorum_any: bool,
}

/// The votes of one round.
#[derive_where(Clone, Debug, PartialEq, Eq, Default)]
struct PerRound<Ctx: Context> {
    /// Weight per voted value, with nil as its own key.
    values_weights: ValuesWeights<NilOrVal<ValueId<Ctx>>>,
    /// Weight per voter, counted once each.
    addresses_weights: RoundWeights<Ctx::Address>,
    /// The first vote each validator cast, retained whole.
    ///
    /// The value alone would be enough to *detect* equivocation, but `EvidenceMap::add`
    /// needs the conflicting **pair**, so the original signed vote has to survive. This is
    /// the standing bridge check that the keeper's normal path keeps the first vote.
    votes_by_address: BTreeMap<Ctx::Address, SignedVote<Ctx>>,
    /// Outputs already reported for this round.
    emitted: Emitted<Ctx>,
}

/// Tallies the single vote step of Fast Tendermint and reports both thresholds.
#[derive_where(Clone, Debug)]
pub struct FastVoteKeeper<Ctx: Context> {
    validator_set: Ctx::ValidatorSet,
    threshold_params: FastThresholdParams,
    per_round: BTreeMap<Round, PerRound<Ctx>>,
    evidence: EvidenceMap<Ctx>,
}

impl<Ctx: Context> FastVoteKeeper<Ctx> {
    /// Create a keeper for `validator_set` using `threshold_params`.
    pub fn new(validator_set: Ctx::ValidatorSet, threshold_params: FastThresholdParams) -> Self {
        Self {
            validator_set,
            threshold_params,
            per_round: BTreeMap::new(),
            evidence: EvidenceMap::new(),
        }
    }

    /// The total voting power of the validator set.
    pub fn total_weight(&self) -> Weight {
        self.validator_set.total_voting_power()
    }

    /// Recorded equivocation evidence.
    pub fn evidence(&self) -> &EvidenceMap<Ctx> {
        &self.evidence
    }

    /// Apply one vote and report every threshold it newly crosses.
    ///
    /// Returns a **list**, not a single output: one vote can cross `2f+1` and `n - f` at
    /// once when weights are uneven, and a consumer must see both. This is the difference
    /// the classic keeper's `Option<Output>` cannot express.
    ///
    /// A vote from an unknown validator is discarded. A second, conflicting vote from a
    /// validator already counted becomes evidence and is **not** tallied, so equivocation
    /// cannot manufacture a quorum.
    pub fn apply_vote(&mut self, signed_vote: SignedVote<Ctx>) -> Vec<Output<Ctx>> {
        let Some(validator) = self.validator_set.get_by_address(signed_vote.validator_address())
        else {
            // Not in the set: no state is created for it.
            return Vec::new();
        };

        let weight = validator.voting_power();
        let round = signed_vote.round();
        let address = signed_vote.validator_address().clone();
        let value = signed_vote.value().clone();

        let total_weight = self.total_weight();
        let params = self.threshold_params;
        let per_round = self.per_round.entry(round).or_default();

        // Equivocation: a different value from a validator already counted is recorded as
        // evidence instead of being tallied.
        if let Some(existing) = per_round.votes_by_address.get(&address) {
            if existing.value() != &value {
                let existing = existing.clone();
                self.evidence.add(existing, signed_vote);
            }
            return Vec::new();
        }

        per_round
            .votes_by_address
            .insert(address.clone(), signed_vote.clone());
        per_round.addresses_weights.set_once(&address, weight);
        per_round.values_weights.add(value.clone(), weight);

        let mut outputs = Vec::new();

        // L36 then L42, in that order, so a consumer that acts on both sees `valid` set
        // before the decision that depends on it.
        if let NilOrVal::Val(id) = &value {
            let for_value = per_round.values_weights.get(&value);

            if params.quorum.is_met(for_value, total_weight)
                && per_round.emitted.vote_quorum.insert(id.clone())
            {
                outputs.push(Output::VoteQuorumValue(id.clone()));
            }

            if params.decision.is_met(for_value, total_weight)
                && per_round.emitted.decision_quorum.insert(id.clone())
            {
                outputs.push(Output::DecisionQuorumValue(id.clone()));
            }
        }

        // L39: n - f votes for anything, nil included.
        if params
            .decision
            .is_met(per_round.addresses_weights.sum(), total_weight)
            && !per_round.emitted.quorum_any
        {
            per_round.emitted.quorum_any = true;
            outputs.push(Output::QuorumAny);
        }

        outputs
    }

    /// Whether `2f+1` votes for `value_id` have been seen in `round` (L27's justification).
    pub fn has_vote_quorum(&self, round: Round, value_id: &ValueId<Ctx>) -> bool {
        self.weight_for(round, value_id).is_some_and(|w| {
            self.threshold_params.quorum.is_met(w, self.total_weight())
        })
    }

    /// Whether `n - f` votes for `value_id` have been seen in `round` (L42's condition).
    pub fn has_decision_quorum(&self, round: Round, value_id: &ValueId<Ctx>) -> bool {
        self.weight_for(round, value_id).is_some_and(|w| {
            self.threshold_params.decision.is_met(w, self.total_weight())
        })
    }

    fn weight_for(&self, round: Round, value_id: &ValueId<Ctx>) -> Option<Weight> {
        self.per_round
            .get(&round)
            .map(|pr| pr.values_weights.get(&NilOrVal::Val(value_id.clone())))
    }

    /// Drop the votes of every round below `min_round`. Evidence is never pruned.
    pub fn prune_votes(&mut self, min_round: Round) {
        self.per_round.retain(|round, _| *round >= min_round);
    }
}
