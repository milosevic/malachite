//! The Fast Tendermint vote keeper.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use derive_where::derive_where;

use malachitebft_core_types::{
    Context, NilOrVal, Round, SignedVote, Validator, ValidatorSet, ValueId, Vote, VoteType,
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
    VoteQuorumValue(Round, ValueId<Ctx>),

    /// `n - f` votes for this value — enough to decide (L42).
    DecisionQuorumValue(Round, ValueId<Ctx>),

    /// `n - f` votes spread across any values, including nil (L39).
    ///
    /// Arms the precommit timeout, and is the only path that advances a round.
    QuorumAny(Round),
}

// Every variant carries its round deliberately. The consumer must not re-derive it from
// the vote it happened to pass in: the round decides whether the round state machine
// records a value as valid, and a quorum for a round above the consumer's own must be
// refused. Making the caller reconstruct safety-relevant data is how that check gets
// skipped.

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
}

/// Tallies the single vote step of Fast Tendermint and reports both thresholds.
#[derive_where(Clone, Debug)]
pub struct FastVoteKeeper<Ctx: Context> {
    validator_set: Ctx::ValidatorSet,
    threshold_params: FastThresholdParams,
    per_round: BTreeMap<Round, PerRound<Ctx>>,
    /// Which thresholds each round has reached, and which have been reported.
    ///
    /// Deliberately NOT part of `PerRound`, because `prune_votes` drops the tallies while
    /// this must survive: L27 verifies a re-proposal against `2f+1` votes from an EARLIER
    /// round, and L42's decision quorum may come from a different round than the proposal.
    /// Pruning the record that answers those questions would discard the justification the
    /// protocol still needs. Keeping it also stops a pruned round re-reporting its
    /// thresholds if its votes arrive again through sync or WAL replay.
    reached: BTreeMap<Round, Emitted<Ctx>>,
    evidence: EvidenceMap<Ctx>,
}

impl<Ctx: Context> FastVoteKeeper<Ctx> {
    /// Create a keeper for `validator_set` using `threshold_params`.
    pub fn new(validator_set: Ctx::ValidatorSet, threshold_params: FastThresholdParams) -> Self {
        // `decision` (n-f) must be the stricter of the two. Swapped params would silently
        // invert L36 and L42 — a value would "decide" on the weaker threshold.
        debug_assert!(
            threshold_params.decision.numerator * threshold_params.quorum.denominator
                >= threshold_params.quorum.numerator * threshold_params.decision.denominator,
            "the decision threshold (n-f) must be at least as strict as the quorum (2f+1)"
        );
        Self {
            validator_set,
            threshold_params,
            per_round: BTreeMap::new(),
            reached: BTreeMap::new(),
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
        // Fast Tendermint has ONE voting step, which the paper names precommit. A prevote
        // is not part of this protocol, so it is discarded rather than tallied — counting
        // it would let a value reach a threshold on votes the protocol never defined, and
        // would misread a prevote/precommit pair from one validator as equivocation.
        if signed_vote.vote_type() != VoteType::Precommit {
            return Vec::new();
        }

        let Some(validator) = self.validator_set.get_by_address(signed_vote.validator_address())
        else {
            // Not in the set: no state is created for it.
            return Vec::new();
        };

        let weight = validator.voting_power();
        let round = signed_vote.round();
        let address = signed_vote.validator_address().clone();
        let value = signed_vote.value().clone();

        // Algorithm 1 defines no vote at an undefined round.
        if !round.is_defined() {
            return Vec::new();
        }

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

        let for_value = per_round.values_weights.get(&value);
        let any_weight = per_round.addresses_weights.sum();
        let reached = self.reached.entry(round).or_default();
        let mut outputs = Vec::new();

        // L36 then L42, in that order, so a consumer that acts on both sees `valid` set
        // before the decision that depends on it.
        if let NilOrVal::Val(id) = &value {
            if params.quorum.is_met(for_value, total_weight)
                && reached.vote_quorum.insert(id.clone())
            {
                outputs.push(Output::VoteQuorumValue(round, id.clone()));
            }

            if params.decision.is_met(for_value, total_weight)
                && reached.decision_quorum.insert(id.clone())
            {
                outputs.push(Output::DecisionQuorumValue(round, id.clone()));
            }
        }

        // L39: n - f votes for anything, nil included.
        if params.decision.is_met(any_weight, total_weight) && !reached.quorum_any {
            reached.quorum_any = true;
            outputs.push(Output::QuorumAny(round));
        }

        outputs
    }

    /// Whether `2f+1` votes for `value_id` have been seen in `round` (L27's justification).
    ///
    /// Answers from the reached-threshold record, so it still answers after `prune_votes`.
    pub fn has_vote_quorum(&self, round: Round, value_id: &ValueId<Ctx>) -> bool {
        self.reached
            .get(&round)
            .is_some_and(|r| r.vote_quorum.contains(value_id))
    }

    /// Whether `n - f` votes for `value_id` have been seen in `round` (L42's condition).
    ///
    /// L42 permits the decision quorum to come from a different round than the proposal,
    /// so this must keep answering for rounds whose tallies have been pruned.
    pub fn has_decision_quorum(&self, round: Round, value_id: &ValueId<Ctx>) -> bool {
        self.reached
            .get(&round)
            .is_some_and(|r| r.decision_quorum.contains(value_id))
    }

    /// Drop the per-round vote tallies below `min_round`.
    ///
    /// The reached-threshold record and the evidence are NOT pruned. Dropping them would
    /// discard the `2f+1` justification L27 needs for a re-proposal from an earlier round,
    /// and the cross-round `n - f` quorum L42 may decide on — neither of which is safe to
    /// forget merely because the round is behind us.
    pub fn prune_votes(&mut self, min_round: Round) {
        self.per_round.retain(|round, _| *round >= min_round);
    }
}
