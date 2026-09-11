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
///
/// # This type does not yet enforce network-wide agreement
///
/// Nothing here carries the protocol into genesis, the handshake, or certificate
/// verification, so a `Fast` node and a `Classic` node on one network would disagree
/// silently at the first quorum. This enum is a prerequisite for that check, not the check
/// itself.
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

/// Why a validator set cannot tolerate even one fault under a protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NoFaultTolerance {
    /// The set has no voting power at all.
    NoVotingPower,

    /// The voting powers are large enough that the comparison overflows, which means the
    /// set is malformed rather than merely intolerant.
    PowerOverflow {
        /// The largest single voting power in the set.
        largest: VotingPower,
    },

    /// One validator holds at least the whole tolerated share, so a single fault from it
    /// would already exceed the budget.
    SingleValidatorHoldsTheWholeBudget {
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
    /// `None` for [`ConsensusProtocol::Fast`], which has no honest threshold at all. Call
    /// this only where the classic protocol is already established — do **not** thread the
    /// `Option` outward and unwrap it at a call site that might be running fast, which
    /// would turn a protocol mismatch into a panic. Prefer [`Self::quorum`],
    /// [`Self::decision`] and [`Self::honest`], which are total.
    pub const fn classic_threshold_params(self) -> Option<ThresholdParams> {
        match self {
            ConsensusProtocol::Classic => Some(ThresholdParams {
                quorum: ThresholdParam::new(2, 3),
                honest: ThresholdParam::new(1, 3),
            }),
            ConsensusProtocol::Fast => None,
        }
    }

    /// Whether `validator_set` can tolerate **at least one** fault under this protocol.
    ///
    /// # This is ADVISORY. Do not use it as a startup gate for [`ConsensusProtocol::Classic`]
    ///
    /// A set that fails this is not invalid — it is a set that tolerates `f = 0`, which is
    /// a legitimate and widely used configuration. Malachite's own test suite runs
    /// `[2, 3, 2]` in dozens of places, and a three-node network with a 2/3 quorum is safe
    /// and shipped. Rejecting those at startup would remove working classic deployments,
    /// which the coexistence constraint forbids.
    ///
    /// Use it to warn an operator who believes they are getting fault tolerance and is
    /// not, and to catch the easy mistake when opting in to
    /// [`ConsensusProtocol::Fast`] — whose whole justification is a much larger set for
    /// the same tolerance, so a set that tolerates nothing defeats the point entirely.
    /// `[3, 3, 3, 1]` tolerates one fault under classic and none under fast.
    ///
    /// # What it does and does not prove
    ///
    /// It is a **necessary, not sufficient** condition. Bounding the largest single
    /// validator cannot express "tolerates `k` faults": `[1; 6]` passes for fast and
    /// tolerates exactly one, while `[1; 11]` tolerates two. The check asks only whether
    /// one validator already holds the entire budget.
    pub fn tolerates_at_least_one_fault<Ctx>(
        self,
        validator_set: &Ctx::ValidatorSet,
    ) -> Result<(), NoFaultTolerance>
    where
        Ctx: Context,
    {
        let total = validator_set.total_voting_power();
        if validator_set.count() == 0 || total == 0 {
            return Err(NoFaultTolerance::NoVotingPower);
        }

        let denominator = self.tolerated_fault_denominator();
        let largest = (0..validator_set.count())
            .filter_map(|i| validator_set.get_by_index(i))
            .map(crate::Validator::voting_power)
            .max()
            .unwrap_or(0);

        // Reported separately rather than folded into the intolerance case: an overflowing
        // product means the set is malformed, not merely intolerant.
        let Some(share) = largest.checked_mul(denominator) else {
            return Err(NoFaultTolerance::PowerOverflow { largest });
        };

        // `f < n/d` is strict, so a validator holding exactly the share already breaks it.
        if share >= total {
            return Err(NoFaultTolerance::SingleValidatorHoldsTheWholeBudget {
                largest,
                total,
                tolerated_denominator: denominator,
            });
        }

        Ok(())
    }
}
