//! For tallying votes and emitting messages when certain thresholds are reached.

use derive_where::derive_where;
use thiserror::Error;
use tracing::warn;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use malachitebft_core_types::{
    Context, NilOrVal, Round, SignedVote, Validator, ValidatorSet, ValueId, Vote, VoteType,
};

use crate::evidence::EvidenceMap;
use crate::round_votes::RoundVotes;
use crate::round_weights::RoundWeights;
use crate::{Threshold, ThresholdParams, Weight};

/// Messages emitted by the vote keeper
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Output<Value> {
    /// We have a quorum of prevotes for some value or nil
    PolkaAny,

    /// We have a quorum of prevotes for nil
    PolkaNil,

    /// We have a quorum of prevotes for specific value
    PolkaValue(Value),

    /// We have a quorum of precommits for some value or nil
    PrecommitAny,

    /// We have a quorum of precommits for a specific value
    PrecommitValue(Value),

    /// We have f+1 honest votes for a value at a higher round
    SkipRound(Round),
}

/// Keeps track of votes and emitted outputs for a given round.
#[derive_where(Clone, Debug, PartialEq, Eq, Default)]
pub struct PerRound<Ctx>
where
    Ctx: Context,
{
    /// The votes for this round.
    votes: RoundVotes<Ctx>,

    /// The addresses and their weights for this round.
    addresses_weights: RoundWeights<Ctx::Address>,

    /// All the votes received for this round.
    received_votes: Vec<SignedVote<Ctx>>,

    /// The emitted outputs for this round.
    emitted_outputs: BTreeSet<Output<ValueId<Ctx>>>,
}

/// Errors can that be yielded when recording a vote.
#[derive(Error)]
pub enum RecordVoteError<Ctx>
where
    Ctx: Context,
{
    /// Attempted to record a conflicting vote.
    #[error("Conflicting vote: {existing} vs {conflicting}")]
    ConflictingVote {
        /// The vote already recorded.
        existing: SignedVote<Ctx>,
        /// The conflicting vote.
        conflicting: SignedVote<Ctx>,
    },
}

impl<Ctx> PerRound<Ctx>
where
    Ctx: Context,
{
    /// Create a new `PerRound` instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new `PerRound` instance with pre-allocated capacity for the expected number of votes.
    pub fn with_expected_number_of_votes(num_votes: usize) -> Self {
        Self {
            // pre-allocate capacity to avoid re-allocations during the addition of votes
            received_votes: Vec::with_capacity(num_votes),
            ..Self::default()
        }
    }

    /// Add a vote to the round, checking for conflicts.
    pub fn add(
        &mut self,
        vote: SignedVote<Ctx>,
        weight: Weight,
    ) -> Result<(), RecordVoteError<Ctx>> {
        let existing_idx = self.received_votes.iter().position(|v| {
            v.vote_type() == vote.vote_type() && v.validator_address() == vote.validator_address()
        });

        if let Some(idx) = existing_idx {
            let existing = &self.received_votes[idx];
            if existing.value() != vote.value() {
                // This is an equivocating vote
                return Err(RecordVoteError::ConflictingVote {
                    existing: existing.clone(),
                    conflicting: vote,
                });
            }
            // Upgrade the stored vote if the incoming one carries an extension
            // while the stored vote lacks one. This can happen if the stored
            // vote came from a precommit round certificate whose votes do not
            // carry extensions, while individual votes are received after and
            // include extensions.
            if existing.extension().is_none() && vote.extension().is_some() {
                self.received_votes[idx] = vote;
            }
            return Ok(());
        }

        // Tally this vote
        self.votes.add_vote(&vote, weight);

        // Update the weight of the validator
        self.addresses_weights
            .set_once(vote.validator_address(), weight);

        // Add the vote to the received votes
        self.received_votes.push(vote);

        Ok(())
    }

    /// Return the vote of the given type received from the given validator.
    pub fn get_vote<'a>(
        &'a self,
        vote_type: VoteType,
        address: &'a Ctx::Address,
    ) -> Option<&'a SignedVote<Ctx>> {
        self.received_votes
            .iter()
            .find(move |vote| vote.vote_type() == vote_type && vote.validator_address() == address)
    }

    /// Return the votes for this round.
    pub fn votes(&self) -> &RoundVotes<Ctx> {
        &self.votes
    }

    /// Return the votes for this round.
    pub fn received_votes(&self) -> &Vec<SignedVote<Ctx>> {
        &self.received_votes
    }

    /// Return precommits for the given value in this round.
    pub fn precommits_for_value(&self, value_id: &ValueId<Ctx>) -> Vec<SignedVote<Ctx>> {
        self.received_votes
            .iter()
            .filter(|v| {
                v.vote_type() == VoteType::Precommit
                    && v.value() == &NilOrVal::Val(value_id.clone())
            })
            .cloned()
            .collect()
    }

    /// Return the addresses and their weights for this round.
    pub fn addresses_weights(&self) -> &RoundWeights<Ctx::Address> {
        &self.addresses_weights
    }

    /// Return the emitted outputs for this round.
    pub fn emitted_outputs(&self) -> &BTreeSet<Output<ValueId<Ctx>>> {
        &self.emitted_outputs
    }
}

/// Keeps track of votes and emits messages when thresholds are reached.
#[derive_where(Clone, Debug)]
pub struct VoteKeeper<Ctx>
where
    Ctx: Context,
{
    /// The validator set for this height.
    validator_set: Ctx::ValidatorSet,

    /// The threshold parameters.
    threshold_params: ThresholdParams,

    /// The votes and emitted outputs for each round.
    per_round: BTreeMap<Round, PerRound<Ctx>>,

    /// Evidence of equivocation.
    evidence: EvidenceMap<Ctx>,
}

impl<Ctx> VoteKeeper<Ctx>
where
    Ctx: Context,
{
    /// Create a new `VoteKeeper` instance, for the given
    /// total network weight (ie. voting power) and threshold parameters.
    pub fn new(validator_set: Ctx::ValidatorSet, threshold_params: ThresholdParams) -> Self {
        let keeper = Self {
            validator_set,
            threshold_params,
            per_round: BTreeMap::new(),
            evidence: EvidenceMap::new(),
        };

        if quint_oracle::enabled() {
            let voting_powers: Vec<u64> = keeper
                .validator_set
                .iter()
                .map(|v| v.voting_power())
                .collect();

            quint_oracle::Event::builder(quint_oracle::current_test(), "VoteKeeperNew")
                .argument("voting_powers", voting_powers, Some("VOTING_POWER_SETS"))
                .assert(
                    Vec::from([
                        quint_oracle::PathSeg::ident("ghost"),
                        quint_oracle::PathSeg::ident("roundsCount"),
                    ]),
                    0i64,
                )
                .scope("vote-keeper")
                .send();
        }

        keeper
    }

    /// Return the current validator set
    pub fn validator_set(&self) -> &Ctx::ValidatorSet {
        &self.validator_set
    }

    /// Return the total weight (ie. voting power) of the network.
    pub fn total_weight(&self) -> Weight {
        self.validator_set.total_voting_power()
    }

    /// Return the votes for the given round.
    pub fn per_round(&self, round: Round) -> Option<&PerRound<Ctx>> {
        self.per_round.get(&round)
    }

    /// Return votes for all rounds we have seen so far.
    pub fn all_rounds(&self) -> &BTreeMap<Round, PerRound<Ctx>> {
        &self.per_round
    }

    /// Return how many rounds we have seen votes for so far.
    pub fn rounds(&self) -> usize {
        self.per_round.len()
    }

    /// Return the highest round we have seen votes for so far.
    pub fn max_round(&self) -> Round {
        self.per_round.keys().max().copied().unwrap_or(Round::Nil)
    }

    /// Return the evidence of equivocation.
    pub fn evidence(&self) -> &EvidenceMap<Ctx> {
        if quint_oracle::enabled() && !self.evidence.is_empty() {
            quint_oracle::Event::builder(quint_oracle::current_test(), "read_vote_evidence")
                .assert(
                    Vec::from([quint_oracle::PathSeg::ident("ghost"), quint_oracle::PathSeg::ident("votePairs")]),
                    self.evidence.pair_count() as i64,
                )
                .assert(
                    Vec::from([quint_oracle::PathSeg::ident("ghost"), quint_oracle::PathSeg::ident("voteAddrs")]),
                    self.evidence.len() as i64,
                )
                .scope("equivocation-detection")
                .send();
        }

        &self.evidence
    }

    /// Remove and return all recorded evidence.
    pub fn take_evidence(&mut self) -> EvidenceMap<Ctx> {
        let evidence = core::mem::take(&mut self.evidence);

        if quint_oracle::enabled() {
            quint_oracle::Event::builder(quint_oracle::current_test(), "take_evidence")
                .assert(
                    Vec::from([
                        quint_oracle::PathSeg::ident("ghost"),
                        quint_oracle::PathSeg::ident("evidenceCount"),
                    ]),
                    0i64,
                )
                .assert(
                    Vec::from([
                        quint_oracle::PathSeg::ident("ghost"),
                        quint_oracle::PathSeg::ident("roundsCount"),
                    ]),
                    self.per_round.len() as i64,
                )
                .scope("vote-keeper")
                .send();
        }

        evidence
    }

    /// Check if we have already seen a vote.
    ///
    /// Matches `PerRound::add`'s duplicate semantic: a stored vote from the
    /// same validator with the same type and value counts as "seen", unless
    /// the incoming vote carries an extension the stored one lacks — in
    /// which case the stored vote can still be upgraded.
    pub fn has_vote(&self, vote: &SignedVote<Ctx>) -> bool {
        self.per_round
            .get(&vote.round())
            .and_then(|per_round| per_round.get_vote(vote.vote_type(), vote.validator_address()))
            .is_some_and(|existing| {
                existing.value() == vote.value()
                    && !(existing.extension().is_none() && vote.extension().is_some())
            })
    }

    /// Apply a vote with a given weight, potentially triggering an output.
    pub fn apply_vote(
        &mut self,
        vote: SignedVote<Ctx>,
        round: Round,
    ) -> Option<Output<ValueId<Ctx>>> {
        // Quint oracle: the vote as the spec models it — the sender by its index
        // in the validator set (-1 when it is not in the set at all), the value
        // rendered through its Display id, and both rounds as i64.
        let oracle_on = quint_oracle::enabled();
        let oracle_src: i64 = if oracle_on {
            (0..self.validator_set.count())
                .find(|i| {
                    self.validator_set
                        .get_by_index(*i)
                        .is_some_and(|v| v.address() == vote.validator_address())
                })
                .map_or(-1, |i| i as i64)
        } else {
            -1
        };
        let oracle_vote_type = match vote.vote_type() {
            VoteType::Prevote => "Prevote",
            VoteType::Precommit => "Precommit",
        };
        let oracle_value = if oracle_on {
            match vote.value() {
                NilOrVal::Nil => alloc::string::String::from("Nil"),
                NilOrVal::Val(id) => alloc::format!("{id}"),
            }
        } else {
            alloc::string::String::new()
        };
        let oracle_round = vote.round().as_i64();
        let oracle_current_round = round.as_i64();

        let total_weight = self.total_weight();
        let per_round =
            self.per_round
                .entry(vote.round())
                .or_insert(PerRound::with_expected_number_of_votes(
                    self.validator_set.count(),
                ));

        let Some(validator) = self.validator_set.get_by_address(vote.validator_address()) else {
            // Vote from unknown validator, let's discard it.
            if oracle_on {
                quint_oracle::Event::builder(quint_oracle::current_test(), "apply_vote")
                    .argument("vote_type", oracle_vote_type, Some("VOTE_TYPES"))
                    .argument("src", oracle_src, Some("SENDERS"))
                    .argument("vote_round", oracle_round, Some("VOTE_ROUNDS"))
                    .argument("value", oracle_value.as_str(), Some("VOTE_VALUES"))
                    .argument("current_round", oracle_current_round, Some("CURRENT_ROUNDS"))
                    .assert(
                        Vec::from([
                            quint_oracle::PathSeg::ident("ghost"),
                            quint_oracle::PathSeg::ident("lastOutputName"),
                        ]),
                        "None",
                    )
                    .assert(
                        Vec::from([
                            quint_oracle::PathSeg::ident("ghost"),
                            quint_oracle::PathSeg::ident("roundsCount"),
                        ]),
                        self.per_round.len() as i64,
                    )
                    .assert(
                        Vec::from([
                            quint_oracle::PathSeg::ident("ghost"),
                            quint_oracle::PathSeg::ident("evidenceCount"),
                        ]),
                        self.evidence.len() as i64,
                    )
                    .scope("vote-keeper")
                    .send();

                quint_oracle::Event::builder(quint_oracle::current_test(), "apply_vote")
                    .argument("vote_type", oracle_vote_type, Some("VOTE_TYPES"))
                    .argument("src", oracle_src, Some("SENDERS"))
                    .argument("vote_round", oracle_round, Some("VOTE_ROUNDS"))
                    .argument("value", oracle_value.as_str(), Some("VOTE_VALUES"))
                    .argument("current_round", oracle_current_round, Some("CURRENT_ROUNDS"))
                    .assert(
                        Vec::from([quint_oracle::PathSeg::ident("ghost"), quint_oracle::PathSeg::ident("votePairs")]),
                        self.evidence.pair_count() as i64,
                    )
                    .assert(
                        Vec::from([quint_oracle::PathSeg::ident("ghost"), quint_oracle::PathSeg::ident("voteAddrs")]),
                        self.evidence.len() as i64,
                    )
                    .scope("equivocation-detection")
                    .send();
            }

            return None;
        };

        match per_round.add(vote.clone(), validator.voting_power()) {
            Ok(()) => (),
            Err(RecordVoteError::ConflictingVote {
                existing,
                conflicting,
            }) => {
                // This is an equivocating vote
                warn!(
                    "Received equivocating vote {:?}, existing {:?}",
                    conflicting, existing
                );
                self.evidence.add(existing, conflicting);

                if oracle_on {
                    quint_oracle::Event::builder(quint_oracle::current_test(), "apply_vote")
                        .argument("vote_type", oracle_vote_type, Some("VOTE_TYPES"))
                        .argument("src", oracle_src, Some("SENDERS"))
                        .argument("vote_round", oracle_round, Some("VOTE_ROUNDS"))
                        .argument("value", oracle_value.as_str(), Some("VOTE_VALUES"))
                        .argument("current_round", oracle_current_round, Some("CURRENT_ROUNDS"))
                        .assert(
                            Vec::from([
                                quint_oracle::PathSeg::ident("ghost"),
                                quint_oracle::PathSeg::ident("lastOutputName"),
                            ]),
                            "None",
                        )
                        .assert(
                            Vec::from([
                                quint_oracle::PathSeg::ident("ghost"),
                                quint_oracle::PathSeg::ident("roundsCount"),
                            ]),
                            self.per_round.len() as i64,
                        )
                        .assert(
                            Vec::from([
                                quint_oracle::PathSeg::ident("ghost"),
                                quint_oracle::PathSeg::ident("evidenceCount"),
                            ]),
                            self.evidence.len() as i64,
                        )
                        .scope("vote-keeper")
                        .send();

                    quint_oracle::Event::builder(quint_oracle::current_test(), "apply_vote")
                        .argument("vote_type", oracle_vote_type, Some("VOTE_TYPES"))
                        .argument("src", oracle_src, Some("SENDERS"))
                        .argument("vote_round", oracle_round, Some("VOTE_ROUNDS"))
                        .argument("value", oracle_value.as_str(), Some("VOTE_VALUES"))
                        .argument("current_round", oracle_current_round, Some("CURRENT_ROUNDS"))
                        .assert(
                            Vec::from([quint_oracle::PathSeg::ident("ghost"), quint_oracle::PathSeg::ident("votePairs")]),
                            self.evidence.pair_count() as i64,
                        )
                        .assert(
                            Vec::from([quint_oracle::PathSeg::ident("ghost"), quint_oracle::PathSeg::ident("voteAddrs")]),
                            self.evidence.len() as i64,
                        )
                        .scope("equivocation-detection")
                        .send();
                }

                return None;
            }
        }

        let threshold = compute_threshold(
            vote.vote_type(),
            per_round,
            vote.value(),
            self.threshold_params,
            total_weight,
        );

        let skip_round = if vote.round() > round
            && self
                .threshold_params
                .honest
                .is_met(per_round.addresses_weights.sum(), total_weight)
        {
            Some(vote.round())
        } else {
            None
        };

        let output = threshold_to_output(vote.vote_type(), threshold, skip_round);

        let result = match output {
            // Ensure we do not output the same message twice
            Some(output) if !per_round.emitted_outputs.contains(&output) => {
                per_round.emitted_outputs.insert(output.clone());
                Some(output)
            }
            _ => None,
        };

        if oracle_on {
            let (name, value, skipped) = match &result {
                None => ("None", alloc::string::String::new(), -1i64),
                Some(Output::PolkaAny) => ("PolkaAny", alloc::string::String::new(), -1),
                Some(Output::PolkaNil) => ("PolkaNil", alloc::string::String::new(), -1),
                Some(Output::PolkaValue(v)) => ("PolkaValue", alloc::format!("{v}"), -1),
                Some(Output::PrecommitAny) => ("PrecommitAny", alloc::string::String::new(), -1),
                Some(Output::PrecommitValue(v)) => ("PrecommitValue", alloc::format!("{v}"), -1),
                Some(Output::SkipRound(r)) => {
                    ("SkipRound", alloc::string::String::new(), r.as_i64())
                }
            };

            quint_oracle::Event::builder(quint_oracle::current_test(), "apply_vote")
                .argument("vote_type", oracle_vote_type, Some("VOTE_TYPES"))
                .argument("src", oracle_src, Some("SENDERS"))
                .argument("vote_round", oracle_round, Some("VOTE_ROUNDS"))
                .argument("value", oracle_value.as_str(), Some("VOTE_VALUES"))
                .argument("current_round", oracle_current_round, Some("CURRENT_ROUNDS"))
                .assert(
                    Vec::from([
                        quint_oracle::PathSeg::ident("ghost"),
                        quint_oracle::PathSeg::ident("lastOutputName"),
                    ]),
                    name,
                )
                .assert(
                    Vec::from([
                        quint_oracle::PathSeg::ident("ghost"),
                        quint_oracle::PathSeg::ident("lastOutputValue"),
                    ]),
                    value,
                )
                .assert(
                    Vec::from([
                        quint_oracle::PathSeg::ident("ghost"),
                        quint_oracle::PathSeg::ident("lastOutputRound"),
                    ]),
                    skipped,
                )
                .assert(
                    Vec::from([
                        quint_oracle::PathSeg::ident("ghost"),
                        quint_oracle::PathSeg::ident("roundsCount"),
                    ]),
                    self.per_round.len() as i64,
                )
                .assert(
                    Vec::from([
                        quint_oracle::PathSeg::ident("ghost"),
                        quint_oracle::PathSeg::ident("evidenceCount"),
                    ]),
                    self.evidence.len() as i64,
                )
                .scope("vote-keeper")
                .send();

            quint_oracle::Event::builder(quint_oracle::current_test(), "apply_vote")
                .argument("vote_type", oracle_vote_type, Some("VOTE_TYPES"))
                .argument("src", oracle_src, Some("SENDERS"))
                .argument("vote_round", oracle_round, Some("VOTE_ROUNDS"))
                .argument("value", oracle_value.as_str(), Some("VOTE_VALUES"))
                .argument("current_round", oracle_current_round, Some("CURRENT_ROUNDS"))
                .assert(
                    Vec::from([quint_oracle::PathSeg::ident("ghost"), quint_oracle::PathSeg::ident("votePairs")]),
                    self.evidence.pair_count() as i64,
                )
                .assert(
                    Vec::from([quint_oracle::PathSeg::ident("ghost"), quint_oracle::PathSeg::ident("voteAddrs")]),
                    self.evidence.len() as i64,
                )
                .scope("equivocation-detection")
                .send();
        }

        result
    }

    /// Check if a threshold is met, ie. if we have a quorum for that threshold.
    pub fn is_threshold_met(
        &self,
        round: &Round,
        vote_type: VoteType,
        threshold: Threshold<ValueId<Ctx>>,
    ) -> bool {
        self.per_round.get(round).is_some_and(|per_round| {
            per_round.votes.is_threshold_met(
                vote_type,
                threshold,
                self.threshold_params.quorum,
                self.total_weight(),
            )
        })
    }

    /// Prunes all stored votes from rounds less than `min_round`.
    pub fn prune_votes(&mut self, min_round: Round) {
        self.per_round.retain(|round, _| *round >= min_round);

        if quint_oracle::enabled() {
            quint_oracle::Event::builder(quint_oracle::current_test(), "prune_votes")
                .argument("min_round", min_round.as_i64(), Some("PRUNE_ROUNDS"))
                .assert(
                    Vec::from([
                        quint_oracle::PathSeg::ident("ghost"),
                        quint_oracle::PathSeg::ident("roundsCount"),
                    ]),
                    self.per_round.len() as i64,
                )
                .assert(
                    Vec::from([
                        quint_oracle::PathSeg::ident("ghost"),
                        quint_oracle::PathSeg::ident("evidenceCount"),
                    ]),
                    self.evidence.len() as i64,
                )
                .scope("vote-keeper")
                .send();
        }
    }
}

/// Compute whether or not we have reached a threshold for the given value,
/// and return that threshold.
fn compute_threshold<Ctx>(
    vote_type: VoteType,
    round: &PerRound<Ctx>,
    value: &NilOrVal<ValueId<Ctx>>,
    thresholds: ThresholdParams,
    total_weight: Weight,
) -> Threshold<ValueId<Ctx>>
where
    Ctx: Context,
{
    let weight = round.votes.get_weight(vote_type, value);

    match value {
        NilOrVal::Val(value) if thresholds.quorum.is_met(weight, total_weight) => {
            Threshold::Value(value.clone())
        }

        NilOrVal::Nil if thresholds.quorum.is_met(weight, total_weight) => Threshold::Nil,

        _ => {
            let weight_sum = round.votes.weight_sum(vote_type);

            if thresholds.quorum.is_met(weight_sum, total_weight) {
                Threshold::Any
            } else {
                Threshold::Unreached
            }
        }
    }
}

/// Map a vote type and a threshold to a state machine output.
/// Also considers an optional honest threshold for a future round.
fn threshold_to_output<Value>(
    typ: VoteType,
    threshold: Threshold<Value>,
    future_round: Option<Round>,
) -> Option<Output<Value>> {
    if let Some(future_round) = future_round {
        // Only PrecommitValue(v) has larger priority than SkipRound(r)
        match (typ, threshold) {
            (VoteType::Precommit, Threshold::Value(v)) => Some(Output::PrecommitValue(v)),

            (_, _) => Some(Output::SkipRound(future_round)),
        }
    } else {
        // Thresholds for the current round
        match (typ, threshold) {
            (_, Threshold::Unreached) => None,

            (VoteType::Prevote, Threshold::Any) => Some(Output::PolkaAny),
            (VoteType::Prevote, Threshold::Nil) => Some(Output::PolkaNil),
            (VoteType::Prevote, Threshold::Value(v)) => Some(Output::PolkaValue(v)),

            (VoteType::Precommit, Threshold::Any) => Some(Output::PrecommitAny),
            (VoteType::Precommit, Threshold::Nil) => Some(Output::PrecommitAny),
            (VoteType::Precommit, Threshold::Value(v)) => Some(Output::PrecommitValue(v)),
        }
    }
}
