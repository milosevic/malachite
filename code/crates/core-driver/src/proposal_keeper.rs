//! For storing proposals.

use alloc::collections::BTreeMap;
use alloc::{vec, vec::Vec};

use derive_where::derive_where;

use malachitebft_core_types::{
    Context, DoubleProposal, Proposal, Round, SignedProposal, Validity, Value, ValueId,
};
use tracing::{error, warn};

/// Outcome of storing a proposal in a [`PerRound`] / [`ProposalKeeper`].
///
/// Equivocation is surfaced to the caller rather than recorded by the keeper, matching the
/// convention of the full-proposal keeper in the consensus layer. The caller records the pair
/// via [`ProposalKeeper::record_evidence`].
#[must_use]
#[derive_where(Clone, Debug)]
pub enum StoreProposalResult<Ctx: Context> {
    /// The proposal was stored, or an exact duplicate was ignored.
    Stored,
    /// A different proposal from the same validator is already stored for this round, so the
    /// proposer has equivocated. Both proposals are returned so the caller can record evidence.
    Equivocation {
        /// The proposal already stored for this round.
        existing: SignedProposal<Ctx>,
        /// The conflicting proposal, from the same validator.
        conflicting: SignedProposal<Ctx>,
    },
}

/// The proposals received in a given round, if any.
#[derive_where(Clone, Debug, PartialEq, Eq, Default)]
pub struct PerRound<Ctx>
where
    Ctx: Context,
{
    /// The proposals received in a given round (proposal.round) if any.
    proposals: Vec<(SignedProposal<Ctx>, Validity)>,
}

impl<Ctx> PerRound<Ctx>
where
    Ctx: Context,
{
    /// Return the first proposal and its validity that matches the given value_id, if any.
    fn get_first_proposal_and_validity(
        &self,
        value_id: ValueId<Ctx>,
    ) -> Option<&(SignedProposal<Ctx>, Validity)> {
        self.proposals
            .iter()
            .find(|(proposal, _)| proposal.value().id() == value_id)
    }

    // /// Return the first proposal, if any, without validity.
    fn get_first_proposal(&self) -> Option<&SignedProposal<Ctx>> {
        self.proposals.first().map(|(p, _)| p)
    }

    /// Returns all proposals and their validities.
    pub fn get_proposals_and_validities(&self) -> &[(SignedProposal<Ctx>, Validity)] {
        &self.proposals
    }

    /// Add a proposal to this round, checking for conflicts.
    ///
    /// All proposals must come from the same validator (proposer).
    /// If a proposal comes from a different validator than the first,
    /// this is considered a calling code bug and the function will panic.
    ///
    /// - Stores each unique proposal once.
    /// - Returns [`StoreProposalResult::Equivocation`] if equivocation is detected from the
    ///   **same** validator.
    /// - Panics if proposals come from **different validators**.
    pub fn add(
        &mut self,
        proposal: SignedProposal<Ctx>,
        validity: Validity,
    ) -> StoreProposalResult<Ctx> {
        // Early return for exact duplicates
        if self.contains_exact(&proposal, validity) {
            return StoreProposalResult::Stored;
        }

        // Ensure all proposals come from the same validator
        self.verify_same_validator(&proposal);

        // Update existing proposal or add new one
        match self.proposal_validity_mut(&proposal) {
            Some(existing_validity) => {
                Self::update_validity(&proposal, existing_validity, validity);
            }
            None => {
                self.proposals.push((proposal.clone(), validity));
            }
        }

        // Check for equivocation (multiple distinct proposals)
        self.check_equivocation(proposal)
    }

    fn contains_exact(&self, proposal: &SignedProposal<Ctx>, validity: Validity) -> bool {
        self.proposals
            .iter()
            .any(|(p, v)| p == proposal && *v == validity)
    }

    fn verify_same_validator(&self, proposal: &SignedProposal<Ctx>) {
        if let Some(first) = self.get_first_proposal() {
            assert_eq!(
                first.validator_address(),
                proposal.validator_address(),
                "BUG: Received proposals from different validators in the same round.\n\
                Existing: {:?}, New: {:?}",
                first.validator_address(),
                proposal.validator_address()
            );
        }
    }

    fn proposal_validity_mut(&mut self, proposal: &SignedProposal<Ctx>) -> Option<&mut Validity> {
        self.proposals
            .iter_mut()
            .find(|(p, _)| p == proposal)
            .map(|(_, v)| v)
    }

    fn update_validity(proposal: &SignedProposal<Ctx>, current: &mut Validity, new: Validity) {
        use Validity::{Invalid, Valid};

        match (&current, &new) {
            (Invalid, Valid) => {
                warn!(
                    height = %proposal.message.height(),
                    round = %proposal.message.round(),
                    value_id = %proposal.message.value().id(),
                    "Application changed its mind on proposal's validity: Invalid --> Valid"
                );
                *current = new;
            }
            (Valid, Invalid) => {
                error!(
                    height = %proposal.message.height(),
                    round = %proposal.message.round(),
                    value_id = %proposal.message.value().id(),
                    "Application changed its mind on proposal's validity: Valid --> Invalid; \
                    this should not happen"
                );
            }
            _ => {
                // Same validity, no action needed
            }
        }
    }

    fn check_equivocation(&self, proposal: SignedProposal<Ctx>) -> StoreProposalResult<Ctx> {
        if self.proposals.len() > 1 {
            let existing = self
                .get_first_proposal()
                .expect("at least one proposal should exist")
                .clone();

            StoreProposalResult::Equivocation {
                existing,
                conflicting: proposal,
            }
        } else {
            StoreProposalResult::Stored
        }
    }
}

/// Keeps track of proposals.
#[derive_where(Clone, Debug, Default)]
pub struct ProposalKeeper<Ctx>
where
    Ctx: Context,
{
    /// Addresses in first-seen order, giving each validator a stable index for
    /// oracle events. Only populated while the Quint oracle is enabled, and read
    /// by nothing else — it takes no part in equality, ordering or the public API.
    oracle_addresses: Vec<Ctx::Address>,

    /// The proposal for each round.
    per_round: BTreeMap<Round, PerRound<Ctx>>,

    /// Evidence of equivocation.
    evidence: EvidenceMap<Ctx>,
}

impl<Ctx> ProposalKeeper<Ctx>
where
    Ctx: Context,
{
    /// Create a new `ProposalKeeper` instance
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the proposal and its validity for the round, matching the value_id, if any.
    pub fn get_proposal_and_validity_for_round_and_value(
        &self,
        round: Round,
        value_id: ValueId<Ctx>,
    ) -> Option<&(SignedProposal<Ctx>, Validity)> {
        self.per_round
            .get(&round)
            .and_then(|round_info| round_info.get_first_proposal_and_validity(value_id))
    }

    /// Returns all proposals and their validities for the round, if any.
    pub fn get_proposals_and_validities_for_round(
        &self,
        round: Round,
    ) -> &[(SignedProposal<Ctx>, Validity)] {
        self.per_round
            .get(&round)
            .map(PerRound::get_proposals_and_validities)
            .unwrap_or(&[])
    }

    /// Returns all proposals and their validities for all rounds.
    pub fn all_rounds(&self) -> &BTreeMap<Round, PerRound<Ctx>> {
        &self.per_round
    }

    /// This address's stable index for oracle events, assigned on first sight.
    fn oracle_validator_index(&mut self, address: &Ctx::Address) -> i64 {
        match self.oracle_addresses.iter().position(|a| a == address) {
            Some(i) => i as i64,
            None => {
                self.oracle_addresses.push(address.clone());
                (self.oracle_addresses.len() - 1) as i64
            }
        }
    }

    /// Recorded evidence sizes as (pairs, addresses), without logging a read.
    pub(crate) fn evidence_counts(&self) -> (usize, usize) {
        (self.evidence.pair_count(), self.evidence.len())
    }

    /// Return the evidence of equivocation.
    pub fn evidence(&self) -> &EvidenceMap<Ctx> {
        if quint_oracle::enabled() && !self.evidence.is_empty() {
            quint_oracle::Event::builder(quint_oracle::current_test(), "read_proposal_evidence")
                .assert(
                    Vec::from([quint_oracle::PathSeg::ident("ghost"), quint_oracle::PathSeg::ident("proposalPairs")]),
                    self.evidence.pair_count() as i64,
                )
                .assert(
                    Vec::from([quint_oracle::PathSeg::ident("ghost"), quint_oracle::PathSeg::ident("proposalAddrs")]),
                    self.evidence.len() as i64,
                )
                .scope("equivocation-detection")
                .send();
        }

        &self.evidence
    }

    /// Remove and return all recorded evidence.
    pub fn take_evidence(&mut self) -> EvidenceMap<Ctx> {
        core::mem::take(&mut self.evidence)
    }

    /// Store a proposal, returning whether it revealed an equivocation.
    ///
    /// On [`StoreProposalResult::Equivocation`] the caller records the surfaced pair via
    /// [`record_evidence`](Self::record_evidence).
    pub fn store_proposal(
        &mut self,
        proposal: SignedProposal<Ctx>,
        validity: Validity,
    ) -> StoreProposalResult<Ctx> {
        let oracle_on = quint_oracle::enabled();
        let oracle_validator = if oracle_on {
            self.oracle_validator_index(&proposal.validator_address().clone())
        } else {
            -1
        };
        let oracle_round = proposal.round().as_i64();
        let oracle_value = if oracle_on {
            alloc::format!("{}", proposal.message.value().id())
        } else {
            alloc::string::String::new()
        };
        let oracle_pol_round = proposal.message.pol_round().as_i64();
        let oracle_validity = match validity {
            Validity::Valid => "Valid",
            Validity::Invalid => "Invalid",
        };

        let result = self
            .per_round
            .entry(proposal.round())
            .or_default()
            .add(proposal, validity);

        if oracle_on {
            let oracle_counts = self.evidence_counts();

            quint_oracle::Event::builder(quint_oracle::current_test(), "store_proposal")
                .argument("validator", oracle_validator, Some("PROPOSERS"))
                .argument("proposal_round", oracle_round, Some("PROPOSAL_ROUNDS"))
                .argument("value", oracle_value.as_str(), Some("PROPOSAL_VALUES"))
                .argument("pol_round", oracle_pol_round, Some("POL_ROUNDS"))
                .argument("validity", oracle_validity, Some("VALIDITIES"))
                .assert(
                    Vec::from([
                        quint_oracle::PathSeg::ident("ghost"),
                        quint_oracle::PathSeg::ident("proposalPairs"),
                    ]),
                    oracle_counts.0 as i64,
                )
                .assert(
                    Vec::from([
                        quint_oracle::PathSeg::ident("ghost"),
                        quint_oracle::PathSeg::ident("abortedFlag"),
                    ]),
                    0i64,
                )
                .scope("equivocation-detection")
                .send();
        }

        result
    }

    /// Record a pair of equivocating proposals directly in the evidence map.
    ///
    /// Callers record evidence here after [`store_proposal`](Self::store_proposal) returns a
    /// [`StoreProposalResult::Equivocation`], or when an upstream layer detects equivocation for
    /// two proposals that share a value id but differ in another field (such as `pol_round`) and
    /// filters the conflicting one before it reaches the per-round store.
    /// [`EvidenceMap::add`] deduplicates, so calling this for a pair already recorded is a no-op.
    pub fn record_evidence(
        &mut self,
        existing: SignedProposal<Ctx>,
        conflicting: SignedProposal<Ctx>,
    ) {
        warn!(
            height = %conflicting.message.height(),
            round = %conflicting.message.round(),
            proposer = %conflicting.message.validator_address(),
            value_id = %conflicting.message.value().id(),
            "Received equivocating proposal"
        );
        let oracle_on = quint_oracle::enabled();
        let oracle_validator = if oracle_on {
            self.oracle_validator_index(&conflicting.validator_address().clone())
        } else {
            -1
        };
        let oracle_round = conflicting.round().as_i64();
        let oracle_existing_value = if oracle_on {
            alloc::format!("{}", existing.message.value().id())
        } else {
            alloc::string::String::new()
        };
        let oracle_conflicting_value = if oracle_on {
            alloc::format!("{}", conflicting.message.value().id())
        } else {
            alloc::string::String::new()
        };
        let oracle_existing_pol = existing.message.pol_round().as_i64();
        let oracle_conflicting_pol = conflicting.message.pol_round().as_i64();

        if oracle_on {
            // The surfaced pair is reported here; EvidenceMap::add performs and
            // logs the write itself, so this event records no evidence change.
            quint_oracle::Event::builder(quint_oracle::current_test(), "record_proposal_evidence")
                .argument("validator", oracle_validator, Some("PROPOSERS"))
                .argument("proposal_round", oracle_round, Some("PROPOSAL_ROUNDS"))
                .argument(
                    "existing_value",
                    oracle_existing_value.as_str(),
                    Some("PROPOSAL_VALUES"),
                )
                .argument("existing_pol_round", oracle_existing_pol, Some("POL_ROUNDS"))
                .argument(
                    "conflicting_value",
                    oracle_conflicting_value.as_str(),
                    Some("PROPOSAL_VALUES"),
                )
                .argument(
                    "conflicting_pol_round",
                    oracle_conflicting_pol,
                    Some("POL_ROUNDS"),
                )
                .assert(
                    Vec::from([
                        quint_oracle::PathSeg::ident("ghost"),
                        quint_oracle::PathSeg::ident("proposalPairs"),
                    ]),
                    self.evidence.pair_count() as i64,
                )
                .scope("equivocation-detection")
                .send();
        }

        self.evidence.add(existing, conflicting);
    }
}

/// Keeps track of evidence of equivocation.
#[derive_where(Clone, Debug, Default)]
pub struct EvidenceMap<Ctx>
where
    Ctx: Context,
{
    map: BTreeMap<Ctx::Address, Vec<DoubleProposal<Ctx>>>,
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
    pub fn get(&self, address: &Ctx::Address) -> Option<&Vec<DoubleProposal<Ctx>>> {
        self.map.get(address)
    }

    /// Add evidence of equivocating proposals, ie. two proposals submitted by the same validator
    /// for the same height and round that differ in any field — a different value, or the same
    /// value with a different `pol_round`, for example.
    /// If evidence for the same pair of proposals already exists, it will not be added again.
    ///
    /// # Precondition
    /// - Both proposals must be from the same validator (debug-asserted).
    pub fn add(&mut self, existing: SignedProposal<Ctx>, conflicting: SignedProposal<Ctx>) {
        debug_assert_eq!(
            existing.validator_address(),
            conflicting.validator_address()
        );

        let oracle_on = quint_oracle::enabled();
        let oracle_address = conflicting.validator_address().clone();
        let oracle_round = conflicting.round().as_i64();
        let oracle_existing_value = if oracle_on {
            alloc::format!("{}", existing.message.value().id())
        } else {
            alloc::string::String::new()
        };
        let oracle_conflicting_value = if oracle_on {
            alloc::format!("{}", conflicting.message.value().id())
        } else {
            alloc::string::String::new()
        };
        let oracle_existing_pol = existing.message.pol_round().as_i64();
        let oracle_conflicting_pol = conflicting.message.pol_round().as_i64();

        if let Some(evidence) = self.map.get_mut(conflicting.validator_address()) {
            // Check if this evidence already exists (in either order)
            let already_exists = evidence.iter().any(|(e, c)| {
                (e == &existing && c == &conflicting) || (e == &conflicting && c == &existing)
            });
            if !already_exists {
                evidence.push((existing, conflicting));
            }
        } else {
            self.map.insert(
                conflicting.validator_address().clone(),
                vec![(existing, conflicting)],
            );
        }

        if oracle_on {
            // This type holds no validator set, so `validator` is the address's
            // rank in this map's key order — a stable identity for a fixed set
            // of equivocators, which is what the per-validator list needs.
            let oracle_validator: i64 = self
                .map
                .keys()
                .position(|address| address == &oracle_address)
                .map_or(-1, |i| i as i64);

            quint_oracle::Event::builder(quint_oracle::current_test(), "proposal_evidence_add")
                .argument("validator", oracle_validator, Some("PROPOSERS"))
                .argument("proposal_round", oracle_round, Some("PROPOSAL_ROUNDS"))
                .argument(
                    "existing_value",
                    oracle_existing_value.as_str(),
                    Some("PROPOSAL_VALUES"),
                )
                .argument("existing_pol_round", oracle_existing_pol, Some("POL_ROUNDS"))
                .argument(
                    "conflicting_value",
                    oracle_conflicting_value.as_str(),
                    Some("PROPOSAL_VALUES"),
                )
                .argument(
                    "conflicting_pol_round",
                    oracle_conflicting_pol,
                    Some("POL_ROUNDS"),
                )
                .assert(
                    Vec::from([
                        quint_oracle::PathSeg::ident("ghost"),
                        quint_oracle::PathSeg::ident("proposalPairs"),
                    ]),
                    self.pair_count() as i64,
                )
                .assert(
                    Vec::from([
                        quint_oracle::PathSeg::ident("ghost"),
                        quint_oracle::PathSeg::ident("proposalAddrs"),
                    ]),
                    self.map.len() as i64,
                )
                .scope("equivocation-detection")
                .send();
        }
    }

    /// Return the number of addresses with recorded proposal equivocations.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Total number of recorded equivocation pairs across all validators.
    pub(crate) fn pair_count(&self) -> usize {
        self.map.values().map(|pairs| pairs.len()).sum()
    }

    /// Iterate over all addresses with recorded proposal equivocations.
    pub fn iter(
        &self,
    ) -> alloc::collections::btree_map::Iter<'_, Ctx::Address, Vec<DoubleProposal<Ctx>>> {
        self.map.iter()
    }
}

impl<'a, Ctx> IntoIterator for &'a EvidenceMap<Ctx>
where
    Ctx: Context,
{
    type Item = (&'a Ctx::Address, &'a Vec<DoubleProposal<Ctx>>);
    type IntoIter = alloc::collections::btree_map::Iter<'a, Ctx::Address, Vec<DoubleProposal<Ctx>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.map.iter()
    }
}

impl<Ctx> IntoIterator for EvidenceMap<Ctx>
where
    Ctx: Context,
{
    type Item = (Ctx::Address, Vec<DoubleProposal<Ctx>>);
    type IntoIter = alloc::collections::btree_map::IntoIter<Ctx::Address, Vec<DoubleProposal<Ctx>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.map.into_iter()
    }
}
