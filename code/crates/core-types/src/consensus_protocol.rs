//! Which consensus protocol a node runs.

use crate::{Context, ThresholdParam, ThresholdParams, ValidatorSet, VotingPower};

/// The consensus protocol a node runs for a height.
///
/// Malachite ships two, and both remain available: classic Tendermint, and the two-step
/// Fast Tendermint of Vander Vos & Cason (arXiv:2608.13434). They are **not**
/// interoperable — they differ in resilience, in how many communication steps a decision
/// takes, and in the quorum a commit certificate must carry — so every validator in a set
/// must run the same one. This is selected at genesis and fixed for the network, never
/// toggled at runtime.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum ConsensusProtocol {
    /// Classic Tendermint: tolerates `f < n/3`, decides in three communication steps.
    ///
    /// The default, and what every existing deployment runs.
    #[default]
    Classic,

    /// Fast Tendermint: tolerates `f < n/5`, decides in two communication steps.
    ///
    /// Buys a communication step at the cost of a much larger validator set for the same
    /// fault tolerance — six validators to tolerate one, eleven to tolerate two.
    Fast,
}

/// Why a validator set cannot run a protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InadequateValidatorSet {
    /// The set is empty.
    Empty,

    /// One validator holds enough voting power that a single fault would exceed the
    /// protocol's budget, so its safety argument does not apply to this set.
    SingleValidatorExceedsFaultBudget {
        /// The largest single voting power in the set.
        largest: VotingPower,
        /// The set's total voting power.
        total: VotingPower,
        /// The denominator of the tolerated fraction: 3 for classic, 5 for fast.
        tolerated_denominator: u64,
    },
}

impl ConsensusProtocol {
    /// The denominator of the tolerated faulty fraction: `f < n/3` or `f < n/5`.
    pub const fn tolerated_fault_denominator(self) -> u64 {
        match self {
            ConsensusProtocol::Classic => 3,
            ConsensusProtocol::Fast => 5,
        }
    }

    /// The threshold that makes a value *valid* and justifies a re-proposal.
    ///
    /// `2f+1` in both protocols, but that is a different fraction of the total in each:
    /// more than 2/3 when `n = 3f+1`, more than 2/5 when `n = 5f+1`.
    pub const fn quorum(self) -> ThresholdParam {
        match self {
            ConsensusProtocol::Classic => ThresholdParam::new(2, 3),
            ConsensusProtocol::Fast => ThresholdParam::new(2, 5),
        }
    }

    /// The threshold required to decide.
    ///
    /// Classic decides on the same `2f+1` quorum; Fast requires `n - f`, more than 4/5.
    /// This is why a commit certificate from one protocol does not prove a decision under
    /// the other.
    pub const fn decision(self) -> ThresholdParam {
        match self {
            ConsensusProtocol::Classic => ThresholdParam::new(2, 3),
            ConsensusProtocol::Fast => ThresholdParam::new(4, 5),
        }
    }

    /// The `f+1` "at least one correct process" threshold, if the protocol has one.
    ///
    /// `None` for Fast: it removes the round-skip rule that this threshold exists for,
    /// because its observation rule must capture valid values *before* a process moves to
    /// a higher round. Returning `None` rather than a fraction keeps a skip mechanism from
    /// being reintroduced by accident.
    pub const fn honest(self) -> Option<ThresholdParam> {
        match self {
            ConsensusProtocol::Classic => Some(ThresholdParam::new(1, 3)),
            ConsensusProtocol::Fast => None,
        }
    }

    /// The classic `ThresholdParams`, for the code paths that still take them.
    ///
    /// Only meaningful for [`ConsensusProtocol::Classic`], since the fast protocol has no
    /// honest threshold.
    pub const fn classic_threshold_params(self) -> Option<ThresholdParams> {
        match self {
            ConsensusProtocol::Classic => Some(ThresholdParams {
                quorum: ThresholdParam::new(2, 3),
                honest: ThresholdParam::new(1, 3),
            }),
            ConsensusProtocol::Fast => None,
        }
    }

    /// Whether `validator_set` can support this protocol's fault assumption.
    ///
    /// The protocols assume faulty voting power below `total/3` or `total/5`. Nobody knows
    /// which validators are faulty, but a set where a **single** validator already holds
    /// that share cannot satisfy the assumption under any single fault, and running on it
    /// means the safety argument does not apply. That is easy to create by accident: a set
    /// of four with weights 5/3/1/1 is fine for classic and hopeless for fast.
    pub fn check_validator_set<Ctx>(
        self,
        validator_set: &Ctx::ValidatorSet,
    ) -> Result<(), InadequateValidatorSet>
    where
        Ctx: Context,
    {
        let total = validator_set.total_voting_power();
        if validator_set.count() == 0 || total == 0 {
            return Err(InadequateValidatorSet::Empty);
        }

        let denominator = self.tolerated_fault_denominator();
        let largest = (0..validator_set.count())
            .filter_map(|i| validator_set.get_by_index(i))
            .map(crate::Validator::voting_power)
            .max()
            .unwrap_or(0);

        // A single fault must stay inside the budget: largest < total / denominator.
        if largest.saturating_mul(denominator) >= total {
            return Err(InadequateValidatorSet::SingleValidatorExceedsFaultBudget {
                largest,
                total,
                tolerated_denominator: denominator,
            });
        }

        Ok(())
    }
}
