//! Evidence of equivocation.

use alloc::collections::btree_map::BTreeMap;
use alloc::{vec, vec::Vec};

use derive_where::derive_where;

use malachitebft_core_types::{Context, DoubleVote, NilOrVal, SignedVote, Vote, VoteType};

/// Maximum number of distinct equivocation pairs retained per validator.
///
/// A few pairs suffice to prove equivocation; further pairs from the same
/// validator are dropped so per-validator storage remains bounded.
pub const MAX_EVIDENCE_PER_VALIDATOR: usize = 3;

/// Keeps track of evidence of equivocation.
#[derive_where(Clone, Debug, Default)]
pub struct EvidenceMap<Ctx>
where
    Ctx: Context,
{
    map: BTreeMap<Ctx::Address, Vec<DoubleVote<Ctx>>>,
}

impl<Ctx> EvidenceMap<Ctx>
where
    Ctx: Context,
{
    /// Create a new `EvidenceMap` instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return whether or not there is any evidence of equivocation.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Return the evidence of equivocation for a given address, if any.
    pub fn get(&self, address: &Ctx::Address) -> Option<&Vec<DoubleVote<Ctx>>> {
        self.map.get(address)
    }

    /// Add evidence of equivocating votes, ie. two votes submitted by the same validator,
    /// but with different values but for the same height and round.
    /// If evidence for the same pair of votes already exists, it will not be added again.
    /// Once a validator has [`MAX_EVIDENCE_PER_VALIDATOR`] recorded pairs, further pairs
    /// from that validator are dropped.
    ///
    /// # Precondition
    /// - Both votes must be from the same validator (debug-asserted).
    pub fn add(&mut self, existing: SignedVote<Ctx>, conflicting: SignedVote<Ctx>) {
        debug_assert_eq!(
            existing.validator_address(),
            conflicting.validator_address()
        );

        let oracle_on = quint_oracle::enabled();
        let oracle_vote_type = conflicting.vote_type();
        let oracle_round = conflicting.round().as_i64();
        let oracle_existing_value = if oracle_on {
            match existing.value() {
                NilOrVal::Nil => alloc::string::String::from("Nil"),
                NilOrVal::Val(id) => alloc::format!("{id}"),
            }
        } else {
            alloc::string::String::new()
        };
        let oracle_address = conflicting.validator_address().clone();
        let oracle_conflicting_value = if oracle_on {
            match conflicting.value() {
                NilOrVal::Nil => alloc::string::String::from("Nil"),
                NilOrVal::Val(id) => alloc::format!("{id}"),
            }
        } else {
            alloc::string::String::new()
        };

        if let Some(evidence) = self.map.get_mut(conflicting.validator_address()) {
            // Check if this evidence already exists (in either order)
            let already_exists = evidence.iter().any(|(e, c)| {
                (e == &existing && c == &conflicting) || (e == &conflicting && c == &existing)
            });
            if !already_exists && evidence.len() < MAX_EVIDENCE_PER_VALIDATOR {
                evidence.push((existing, conflicting));
            }
        } else {
            self.map.insert(
                conflicting.validator_address().clone(),
                vec![(existing, conflicting)],
            );
        }

        if quint_oracle::enabled() {
            // Quint oracle: this type holds no validator set, so `src` cannot be
            // the validator-set index. It is the address's rank in this map's key
            // order — a stable identity for a fixed set of equivocators, which is
            // what the spec's per-validator evidence list needs.
            let oracle_src: i64 = self
                .map
                .keys()
                .position(|address| address == &oracle_address)
                .map_or(-1, |i| i as i64);
            let vote_type = match oracle_vote_type {
                VoteType::Prevote => "Prevote",
                VoteType::Precommit => "Precommit",
            };
            quint_oracle::Event::builder(quint_oracle::current_test(), "vote_evidence_add")
                .argument("src", oracle_src, Some("SENDERS"))
                .argument("vote_type", vote_type, Some("VOTE_TYPES"))
                .argument("vote_round", oracle_round, Some("VOTE_ROUNDS"))
                .argument("existing_value", oracle_existing_value.as_str(), Some("VOTE_VALUES"))
                .argument("conflicting_value", oracle_conflicting_value.as_str(), Some("VOTE_VALUES"))
                .assert(
                    Vec::from([quint_oracle::PathSeg::ident("ghost"), quint_oracle::PathSeg::ident("votePairs")]),
                    self.pair_count() as i64,
                )
                .assert(
                    Vec::from([quint_oracle::PathSeg::ident("ghost"), quint_oracle::PathSeg::ident("voteAddrs")]),
                    self.map.len() as i64,
                )
                .scope("equivocation-detection")
                .send();
        }
    }

    /// Total number of recorded equivocation pairs across all validators.
    pub(crate) fn pair_count(&self) -> usize {
        self.map.values().map(|pairs| pairs.len()).sum()
    }

    /// Return the number of addresses with recorded vote equivocations.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Iterate over all addresses with recorded vote equivocations.
    pub fn iter(
        &self,
    ) -> alloc::collections::btree_map::Iter<'_, Ctx::Address, Vec<DoubleVote<Ctx>>> {
        self.map.iter()
    }
}

impl<'a, Ctx> IntoIterator for &'a EvidenceMap<Ctx>
where
    Ctx: Context,
{
    type Item = (&'a Ctx::Address, &'a Vec<DoubleVote<Ctx>>);
    type IntoIter = alloc::collections::btree_map::Iter<'a, Ctx::Address, Vec<DoubleVote<Ctx>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.map.iter()
    }
}

impl<Ctx> IntoIterator for EvidenceMap<Ctx>
where
    Ctx: Context,
{
    type Item = (Ctx::Address, Vec<DoubleVote<Ctx>>);
    type IntoIter = alloc::collections::btree_map::IntoIter<Ctx::Address, Vec<DoubleVote<Ctx>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.map.into_iter()
    }
}
