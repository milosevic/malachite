use core::slice;
use std::sync::Arc;

use malachitebft_core_types::VotingPower;
use serde::{Deserialize, Serialize};

use crate::signing::PublicKey;
use crate::{Address, TestContext};

/// A validator is a public key and voting power
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Validator {
    pub address: Address,
    pub public_key: PublicKey,
    pub voting_power: VotingPower,
}

impl Validator {
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn new(public_key: PublicKey, voting_power: VotingPower) -> Self {
        Self {
            address: Address::from_public_key(&public_key),
            public_key,
            voting_power,
        }
    }
}

impl PartialOrd for Validator {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Validator {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.address.cmp(&other.address)
    }
}

impl malachitebft_core_types::Validator<TestContext> for Validator {
    fn address(&self) -> &Address {
        &self.address
    }

    fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    fn voting_power(&self) -> VotingPower {
        self.voting_power
    }
}

/// Quint oracle: each validator's address's LEXICOGRAPHIC RANK inside its own set.
/// The real addresses are seed-derived hex, which no enumerable spec domain can
/// hold; the rank is a plain int and preserves exactly the comparison the documented
/// validator ordering is defined by (rank ascending iff address ascending).
fn oracle_addr_ranks(validators: &[Validator]) -> Vec<i64> {
    let mut sorted: Vec<String> = validators.iter().map(|v| v.address.to_string()).collect();
    sorted.sort();
    sorted.dedup();

    validators
        .iter()
        .map(|v| {
            let address = v.address.to_string();
            sorted.iter().position(|a| a == &address).unwrap_or(0) as i64
        })
        .collect()
}

/// A validator set contains a list of validators sorted by address.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSet {
    pub validators: Arc<Vec<Validator>>,
}

impl ValidatorSet {
    /// Create a new validator set from an iterator of validators.
    ///
    /// # Important
    /// The validators must be unique and sorted in a deterministic order.
    ///
    /// Such an ordering can be defined as in CometBFT:
    /// - first by validator power (descending)
    /// - then lexicographically by address (ascending)
    ///
    /// # Panics
    /// If the validator set is empty.
    pub fn new(validators: impl IntoIterator<Item = Validator>) -> Self {
        let validators: Vec<_> = validators.into_iter().collect();

        let total = validators
            .iter()
            .try_fold(0u64, |acc, v| acc.checked_add(v.voting_power));

        if quint_oracle::enabled() {
            // The vector cannot travel as one logged argument (replay only accepts a
            // value the spec's own nondet set contains), so the collection this
            // constructor performs is reported item by item: begin, one add per
            // validator, then the arm that ran.
            quint_oracle::Event::builder(quint_oracle::current_test(), "ValidatorSetnew_begin")
                .scope("core-types-domain")
                .send();

            for (validator, addr_rank) in validators.iter().zip(oracle_addr_ranks(&validators)) {
                quint_oracle::Event::builder(quint_oracle::current_test(), "ValidatorSetnew_add")
                    .argument("power", validator.voting_power, Some("POWERS"))
                    .argument("addr_rank", addr_rank, Some("ADDRESSES"))
                    .scope("core-types-domain")
                    .send();
            }

            if validators.is_empty() {
                quint_oracle::Event::builder(
                    quint_oracle::current_test(),
                    "ValidatorSetnew_empty_panics",
                )
                .assert(
                    vec![
                        quint_oracle::PathSeg::ident("state"),
                        quint_oracle::PathSeg::ident("panic_vset_empty"),
                    ],
                    true,
                )
                .scope("core-types-domain")
                .send();
            } else if total.is_none() {
                quint_oracle::Event::builder(
                    quint_oracle::current_test(),
                    "ValidatorSetnew_power_overflow_panics",
                )
                .assert(
                    vec![
                        quint_oracle::PathSeg::ident("state"),
                        quint_oracle::PathSeg::ident("panic_vset_power_overflow"),
                    ],
                    true,
                )
                .scope("core-types-domain")
                .send();
            }
        }

        assert!(!validators.is_empty());

        // Verify that total voting power does not overflow u64
        total.expect("total voting power overflow");

        if quint_oracle::enabled() {
            quint_oracle::Event::builder(quint_oracle::current_test(), "ValidatorSetnew")
                .assert(
                    vec![
                        quint_oracle::PathSeg::ident("state"),
                        quint_oracle::PathSeg::ident("vset_installed"),
                    ],
                    true,
                )
                .scope("core-types-domain")
                .send();
        }

        Self {
            validators: Arc::new(validators),
        }
    }

    /// Get the number of validators in the set
    pub fn len(&self) -> usize {
        self.validators.len()
    }

    /// Check if the set is empty
    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    /// Iterate over the validators in the set
    pub fn iter(&self) -> slice::Iter<'_, Validator> {
        self.validators.iter()
    }

    /// The total voting power of the validator set
    pub fn total_voting_power(&self) -> VotingPower {
        let total = self
            .validators
            .iter()
            .try_fold(0u64, |acc, v| acc.checked_add(v.voting_power))
            .expect("total voting power overflow");

        if quint_oracle::enabled() {
            quint_oracle::Event::builder(
                quint_oracle::current_test(),
                "ValidatorSettotal_voting_power",
            )
            .assert(
                vec![
                    quint_oracle::PathSeg::ident("state"),
                    quint_oracle::PathSeg::ident("vset_installed"),
                ],
                true,
            )
            .scope("core-types-domain")
            .send();
        }

        total
    }

    /// Get a validator by its index
    pub fn get_by_index(&self, index: usize) -> Option<&Validator> {
        let found = self.validators.get(index);

        if quint_oracle::enabled() {
            quint_oracle::Event::builder(quint_oracle::current_test(), "ValidatorSetget_by_index")
                .argument("index", index as i64, Some("INDICES"))
                .assert(
                    vec![
                        quint_oracle::PathSeg::ident("state"),
                        quint_oracle::PathSeg::ident("last_index_code"),
                    ],
                    if found.is_some() { 1i64 } else { 0i64 },
                )
                .scope("core-types-domain")
                .send();
        }

        found
    }

    /// Get a validator by its address
    pub fn get_by_address(&self, address: &Address) -> Option<&Validator> {
        let found = self.validators.iter().find(|v| &v.address == address);

        if quint_oracle::enabled() {
            quint_oracle::Event::builder(
                quint_oracle::current_test(),
                "ValidatorSetget_by_address",
            )
            .argument(
                "address",
                self.validators
                    .iter()
                    .zip(oracle_addr_ranks(&self.validators))
                    .find(|(v, _)| &v.address == address)
                    .map_or(-1, |(_, rank)| rank),
                // SIGNER_RANKS: this argument is -1 for an address the set does
                // not contain, which ADDRESSES (ranks only) cannot hold.
                Some("SIGNER_RANKS"),
            )
            .assert(
                vec![
                    quint_oracle::PathSeg::ident("state"),
                    quint_oracle::PathSeg::ident("last_lookup_code"),
                ],
                if found.is_some() { 1i64 } else { 0i64 },
            )
            .scope("core-types-domain")
            .send();
        }

        found
    }

    pub fn get_by_public_key(&self, public_key: &PublicKey) -> Option<&Validator> {
        self.validators.iter().find(|v| &v.public_key == public_key)
    }

    pub fn get_keys(&self) -> Vec<PublicKey> {
        self.validators.iter().map(|v| v.public_key).collect()
    }
}

impl malachitebft_core_types::ValidatorSet<TestContext> for ValidatorSet {
    fn count(&self) -> usize {
        if quint_oracle::enabled() {
            quint_oracle::Event::builder(quint_oracle::current_test(), "ValidatorSetcount")
                .scope("core-types-domain")
                .send();
        }

        self.validators.len()
    }

    fn total_voting_power(&self) -> VotingPower {
        self.total_voting_power()
    }

    fn get_by_address(&self, address: &Address) -> Option<&Validator> {
        self.get_by_address(address)
    }

    fn get_by_index(&self, index: usize) -> Option<&Validator> {
        self.validators.get(index)
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    use super::*;

    use crate::PrivateKey;

    #[test]
    fn new_validator_set_vp() {
        let mut rng = StdRng::seed_from_u64(0x42);

        let sk1 = PrivateKey::generate(&mut rng);
        let sk2 = PrivateKey::generate(&mut rng);
        let sk3 = PrivateKey::generate(&mut rng);

        let v1 = Validator::new(sk1.public_key(), 1);
        let v2 = Validator::new(sk2.public_key(), 2);
        let v3 = Validator::new(sk3.public_key(), 3);

        let vs = ValidatorSet::new(vec![v1, v2, v3]);
        assert_eq!(vs.total_voting_power(), 6);
    }
}
