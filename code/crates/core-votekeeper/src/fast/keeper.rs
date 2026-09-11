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

}

/// Tallies the single vote step of Fast Tendermint and reports both thresholds.
#[derive_where(Clone, Debug)]
pub struct FastVoteKeeper<Ctx: Context> {
    validator_set: Ctx::ValidatorSet,
    threshold_params: FastThresholdParams,
    per_round: BTreeMap<Round, PerRound<Ctx>>,
    /// The first vote each validator cast, per round, retained whole.
    ///
    /// The value alone would be enough to *detect* equivocation, but `EvidenceMap::add`
    /// needs the conflicting **pair**, so the original signed vote has to survive.
    ///
    /// Deliberately NOT part of `PerRound`, for the same reason as `reached`: pruning must
    /// not destroy it. This record is what equivocation is detected against, and
    /// accountability evidence is per HEIGHT — a double vote in round 3 is equally
    /// provable whether the node is now in round 3 or round 9. Pruning is a memory
    /// optimisation for the tally, not a decision to stop detecting misbehaviour. An
    /// equivocator would otherwise only have to delay its second vote until the victim
    /// moved on, which ordinary gossip and sync delivery make easy.
    first_votes: BTreeMap<Round, BTreeMap<Ctx::Address, SignedVote<Ctx>>>,

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
        if quint_oracle::enabled() {
            let powers: Vec<i64> = (0..validator_set.count())
                .filter_map(|i| validator_set.get_by_index(i))
                .map(|v| v.voting_power() as i64)
                .collect();
            let total: i64 = powers.iter().sum();
            quint_oracle::Event::builder(quint_oracle::current_test(), "FastVoteKeepernew")
                .argument("validator_set", powers, None)
                .argument("total_weight", total, Some("TOTALS"))
                .scope("fast-vote-keeper")
                .send();
        }

        Self {
            validator_set,
            threshold_params,
            per_round: BTreeMap::new(),
            first_votes: BTreeMap::new(),
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
        // Oracle-only views of this call's arguments, normalised the way the model names
        // them: the voter by its index in the validator set (-1 when it is not a member),
        // the value by its rendering with "Nil" for a nil vote.
        let oracle_on = quint_oracle::enabled();
        let oracle_voter: i64 = if oracle_on {
            (0..self.validator_set.count())
                .find(|i| {
                    self.validator_set.get_by_index(*i).map(|v| v.address())
                        == Some(signed_vote.validator_address())
                })
                .map(|i| i as i64)
                .unwrap_or(-1)
        } else {
            -1
        };
        let oracle_round: i64 = signed_vote.round().as_i64();
        let oracle_value = if oracle_on {
            match signed_vote.value() {
                NilOrVal::Nil => alloc::string::String::from("Nil"),
                NilOrVal::Val(id) => alloc::format!("{id}"),
            }
        } else {
            alloc::string::String::new()
        };
        let oracle_vote_type = if signed_vote.vote_type() == VoteType::Precommit {
            "Precommit"
        } else {
            "Prevote"
        };

        // Fast Tendermint has ONE voting step, which the paper names precommit. A prevote
        // is not part of this protocol, so it is discarded rather than tallied — counting
        // it would let a value reach a threshold on votes the protocol never defined, and
        // would misread a prevote/precommit pair from one validator as equivocation.
        if signed_vote.vote_type() != VoteType::Precommit {
            if oracle_on {
                quint_oracle::Event::builder(
                    quint_oracle::current_test(),
                    "FastVoteKeeperapply_vote",
                )
                .argument("voter", oracle_voter, None)
                .argument("round", oracle_round, Some("ROUNDS"))
                .argument("value", oracle_value.as_str(), Some("VALUES"))
                .argument("vote_type", oracle_vote_type, Some("VOTE_TYPES"))
                .argument("outputs", 0i64, Some("MASKS"))
                .scope("fast-vote-keeper")
                .send();
            }

            return Vec::new();
        }

        let Some(validator) = self.validator_set.get_by_address(signed_vote.validator_address())
        else {
            // Not in the set: no state is created for it.
            if oracle_on {
                quint_oracle::Event::builder(
                    quint_oracle::current_test(),
                    "FastVoteKeeperapply_vote",
                )
                .argument("voter", oracle_voter, None)
                .argument("round", oracle_round, Some("ROUNDS"))
                .argument("value", oracle_value.as_str(), Some("VALUES"))
                .argument("vote_type", oracle_vote_type, Some("VOTE_TYPES"))
                .argument("outputs", 0i64, Some("MASKS"))
                .scope("fast-vote-keeper")
                .send();
            }

            return Vec::new();
        };

        let weight = validator.voting_power();
        let round = signed_vote.round();
        let address = signed_vote.validator_address().clone();
        let value = signed_vote.value().clone();

        // Algorithm 1 defines no vote at an undefined round.
        if !round.is_defined() {
            if oracle_on {
                quint_oracle::Event::builder(
                    quint_oracle::current_test(),
                    "FastVoteKeeperapply_vote",
                )
                .argument("voter", oracle_voter, None)
                .argument("round", oracle_round, Some("ROUNDS"))
                .argument("value", oracle_value.as_str(), Some("VALUES"))
                .argument("vote_type", oracle_vote_type, Some("VOTE_TYPES"))
                .argument("outputs", 0i64, Some("MASKS"))
                .scope("fast-vote-keeper")
                .send();
            }

            return Vec::new();
        }

        let total_weight = self.total_weight();
        let params = self.threshold_params;

        // Equivocation: a different value from a validator already counted is recorded as
        // evidence instead of being tallied. Checked against `first_votes`, which survives
        // pruning, so a conflicting vote arriving after its round was pruned is still
        // caught.
        if let Some(existing) = self
            .first_votes
            .get(&round)
            .and_then(|by_addr| by_addr.get(&address))
        {
            if existing.value() != &value {
                let existing = existing.clone();
                self.evidence.add(existing, signed_vote);
            }
            if oracle_on {
                quint_oracle::Event::builder(
                    quint_oracle::current_test(),
                    "FastVoteKeeperapply_vote",
                )
                .argument("voter", oracle_voter, None)
                .argument("round", oracle_round, Some("ROUNDS"))
                .argument("value", oracle_value.as_str(), Some("VALUES"))
                .argument("vote_type", oracle_vote_type, Some("VOTE_TYPES"))
                .argument("outputs", 0i64, Some("MASKS"))
                .scope("fast-vote-keeper")
                .send();
            }

            return Vec::new();
        }

        self.first_votes
            .entry(round)
            .or_default()
            .insert(address.clone(), signed_vote.clone());

        let per_round = self.per_round.entry(round).or_default();
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

        if oracle_on {
            let mask: i64 = outputs.iter().fold(0, |acc, o| {
                acc + match o {
                    Output::VoteQuorumValue(..) => 1,
                    Output::DecisionQuorumValue(..) => 2,
                    Output::QuorumAny(..) => 4,
                }
            });
            quint_oracle::Event::builder(
                quint_oracle::current_test(),
                    "FastVoteKeeperapply_vote",
                )
                .argument("voter", oracle_voter, None)
                .argument("round", oracle_round, Some("ROUNDS"))
                .argument("value", oracle_value.as_str(), Some("VALUES"))
                .argument("vote_type", oracle_vote_type, Some("VOTE_TYPES"))
                .argument("outputs", mask, Some("MASKS"))
                .scope("fast-vote-keeper")
                .send();
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
    /// Three things are deliberately NOT pruned:
    ///
    /// - the **reached-threshold** record, because L27 verifies a re-proposal against
    ///   `2f+1` votes from an earlier round and L42's decision quorum may come from a
    ///   different round than the proposal;
    /// - the **first-vote** record, because it is what equivocation is detected against and
    ///   accountability evidence is per height, not per round;
    /// - the **evidence** itself.
    ///
    /// Only the weight tallies go, which is what actually grows with traffic.
    pub fn prune_votes(&mut self, min_round: Round) {
        self.per_round.retain(|round, _| *round >= min_round);

        if quint_oracle::enabled() {
            quint_oracle::Event::builder(
                quint_oracle::current_test(),
                "FastVoteKeeperprune_votes",
            )
            .argument("min_round", min_round.as_i64(), Some("PRUNE_ROUNDS"))
            .argument("rounds_left", self.per_round.len() as i64, Some("ROUND_COUNTS"))
            .scope("fast-vote-keeper")
            .send();
        }
    }
}
