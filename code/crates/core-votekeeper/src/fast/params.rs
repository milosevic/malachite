//! Threshold parameters for Fast Tendermint.

use malachitebft_core_types::ThresholdParam;

/// The two thresholds Fast Tendermint tests, as fractions of total voting power.
///
/// Deliberately **no** honest (`f+1`) parameter: the protocol has no `f+1` rule, and
/// leaving the field out means a `SkipRound` mechanism cannot be reintroduced by accident.
///
/// With `n = 5f+1` and unit weights the fractions work out as:
///
/// | Threshold | Count | Fraction | Check |
/// | --- | --- | --- | --- |
/// | `n - f` | `4f+1` | > 4/5 | `4f+1 > (4/5)(5f+1) = 4f+0.8` |
/// | `2f+1`  | `2f+1` | > 2/5 | `2f+1 > (2/5)(5f+1) = 2f+0.4` |
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FastThresholdParams {
    /// `n - f` — enough to decide (L42), and to advance a round on any value (L39).
    pub decision: ThresholdParam,

    /// `2f+1` — enough to make a value valid (L36) and to justify a re-proposal (L27).
    pub quorum: ThresholdParam,
}

impl FastThresholdParams {
    /// `n - f`, i.e. more than four fifths of the total voting power.
    pub const N_MINUS_F: ThresholdParam = ThresholdParam::new(4, 5);

    /// `2f+1`, i.e. more than two fifths of the total voting power.
    pub const TWO_F_PLUS_ONE: ThresholdParam = ThresholdParam::new(2, 5);
}

impl Default for FastThresholdParams {
    fn default() -> Self {
        Self {
            decision: Self::N_MINUS_F,
            quorum: Self::TWO_F_PLUS_ONE,
        }
    }
}
