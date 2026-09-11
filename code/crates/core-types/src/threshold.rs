use alloc::vec::Vec;

use crate::VotingPower;

/// Represents the different quorum thresholds.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Threshold<ValueId> {
    /// No quorum has been reached yet
    Unreached,

    /// Quorum of votes but not for the same value
    Any,

    /// Quorum of votes for nil
    Nil,

    /// Quorum (+2/3) of votes for a value
    Value(ValueId),
}

/// Represents the different quorum thresholds.
///
/// There are two thresholds:
/// - The quorum threshold, which is the minimum number of votes required for a quorum.
/// - The honest threshold, which is the minimum number of votes required for a quorum of honest nodes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ThresholdParams {
    /// Threshold for a quorum (default: 2f+1)
    pub quorum: ThresholdParam,

    /// Threshold for the minimum number of honest nodes (default: f+1)
    pub honest: ThresholdParam,
}

impl Default for ThresholdParams {
    /// The classic protocol's thresholds.
    ///
    /// Derived from [`crate::ConsensusProtocol::Classic`] rather than written out again,
    /// so the fractions live in exactly one place. Three copies of them existed at one
    /// point and nothing kept them in sync.
    fn default() -> Self {
        Self {
            quorum: crate::ConsensusProtocol::Classic.quorum(),
            honest: crate::ConsensusProtocol::Classic
                .honest()
                .expect("the classic protocol always has an honest threshold"),
        }
    }
}

/// Represents the different quorum thresholds.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ThresholdParam {
    /// Numerator of the threshold
    pub numerator: u64,

    /// Denominator of the threshold
    pub denominator: u64,
}

impl ThresholdParam {
    /// 2f+1, ie. more than two thirds of the total weight
    pub const TWO_F_PLUS_ONE: Self = Self::new(2, 3);

    /// f+1, ie. more than one third of the total weight
    pub const F_PLUS_ONE: Self = Self::new(1, 3);

    /// Create a new threshold parameter with the given numerator and denominator.
    pub const fn new(numerator: u64, denominator: u64) -> Self {
        Self {
            numerator,
            denominator,
        }
    }

    /// Quint oracle: the param this call runs against. `ThresholdParam::new` is a
    /// `const fn` and the two shipped values are `const`s, so there is no
    /// constructor to instrument — `self` here IS the installed param, and the
    /// spec's `ThresholdParamnew` records it as the state the call sees.
    fn log_param_install(&self) {
        quint_oracle::Event::builder(quint_oracle::current_test(), "ThresholdParamnew")
            .argument("numerator", self.numerator, Some("PARAM_NUMERATORS"))
            .argument("denominator", self.denominator, Some("PARAM_DENOMINATORS"))
            .assert(
                Vec::from([
                    quint_oracle::PathSeg::ident("state"),
                    quint_oracle::PathSeg::ident("threshold"),
                    quint_oracle::PathSeg::ident("denominator"),
                ]),
                self.denominator,
            )
            .scope("core-types-domain")
            .send();
    }

    /// Check whether the threshold is met.
    pub fn is_met(&self, weight: VotingPower, total: VotingPower) -> bool {
        // Both products are computed up front so the oracle can report the
        // overflow arm before the `expect` below aborts the call. `checked_mul`
        // has no side effects, so evaluating it early changes nothing; the
        // panic order and message are unchanged.
        let lhs_checked = weight.checked_mul(self.denominator);
        let rhs_checked = total.checked_mul(self.numerator);

        if quint_oracle::enabled() {
            self.log_param_install();

            if lhs_checked.is_none() || rhs_checked.is_none() {
                quint_oracle::Event::builder(
                    quint_oracle::current_test(),
                    "ThresholdParamis_met_overflow_panics",
                )
                .argument("weight", weight, Some("ARITH_NUMBERS"))
                .argument("total", total, Some("ARITH_NUMBERS"))
                .assert(
                    Vec::from([
                        quint_oracle::PathSeg::ident("state"),
                        quint_oracle::PathSeg::ident("panic_threshold_overflow"),
                    ]),
                    true,
                )
                .scope("core-types-domain")
                .send();
            }
        }

        let lhs = lhs_checked.expect("attempt to multiply with overflow");
        let rhs = rhs_checked.expect("attempt to multiply with overflow");

        let is_met = lhs > rhs;

        if quint_oracle::enabled() {
            quint_oracle::Event::builder(quint_oracle::current_test(), "ThresholdParamis_met")
                .argument("weight", weight, Some("ARITH_NUMBERS"))
                .argument("total", total, Some("ARITH_NUMBERS"))
                .assert(
                    Vec::from([
                        quint_oracle::PathSeg::ident("state"),
                        quint_oracle::PathSeg::ident("last_is_met_code"),
                    ]),
                    if is_met { 1i64 } else { 0i64 },
                )
                .scope("core-types-domain")
                .send();
        }

        is_met
    }

    /// Return the minimum expected weight to meet the threshold when applied to the given total.
    pub fn min_expected(&self, total: VotingPower) -> VotingPower {
        // Same shape as `is_met`: compute the checked steps first so the panic
        // arm can be reported before the `expect` aborts.
        let product = total.checked_mul(self.numerator);
        let quotient = product.and_then(|p| p.checked_div(self.denominator));

        if quint_oracle::enabled() {
            self.log_param_install();

            if quotient.is_none() {
                let event = quint_oracle::Event::builder(
                    quint_oracle::current_test(),
                    "ThresholdParammin_expected_panics",
                )
                .argument("total", total, Some("ARITH_NUMBERS"));

                // The spec latches whichever of the two `expect`s this call hits.
                let event = if self.denominator == 0 {
                    event.assert(
                        Vec::from([
                            quint_oracle::PathSeg::ident("state"),
                            quint_oracle::PathSeg::ident("panic_min_expected_div0"),
                        ]),
                        true,
                    )
                } else {
                    event.assert(
                        Vec::from([
                            quint_oracle::PathSeg::ident("state"),
                            quint_oracle::PathSeg::ident("panic_threshold_overflow"),
                        ]),
                        true,
                    )
                };

                event.scope("core-types-domain").send();
            }
        }

        let min_expected = 1 + product
            .expect("attempt to multiply with overflow")
            .checked_div(self.denominator)
            .expect("attempt to divide with overflow");

        if quint_oracle::enabled() {
            quint_oracle::Event::builder(
                quint_oracle::current_test(),
                "ThresholdParammin_expected",
            )
            .argument("total", total, Some("ARITH_NUMBERS"))
            .assert(
                Vec::from([
                    quint_oracle::PathSeg::ident("state"),
                    quint_oracle::PathSeg::ident("last_min_expected_value"),
                ]),
                min_expected,
            )
            .scope("core-types-domain")
            .send();
        }

        min_expected
    }
}

#[cfg(test)]
mod tests {
    use core::iter;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    use super::*;

    #[test]
    fn threshold_param_is_met() {
        assert!(!ThresholdParam::TWO_F_PLUS_ONE.is_met(1, 3));
        assert!(!ThresholdParam::TWO_F_PLUS_ONE.is_met(2, 3));
        assert!(ThresholdParam::TWO_F_PLUS_ONE.is_met(3, 3));

        assert!(!ThresholdParam::F_PLUS_ONE.is_met(3, 10));
        assert!(ThresholdParam::F_PLUS_ONE.is_met(4, 10));
        assert!(!ThresholdParam::TWO_F_PLUS_ONE.is_met(6, 10));
        assert!(ThresholdParam::TWO_F_PLUS_ONE.is_met(7, 10));
    }

    #[test]
    #[should_panic(expected = "attempt to multiply with overflow")]
    fn threshold_param_is_met_overflow() {
        assert!(!ThresholdParam::TWO_F_PLUS_ONE.is_met(1, u64::MAX));
    }

    #[test]
    fn threshold_params_corner_cases() {
        let mut rng = StdRng::seed_from_u64(123456789);
        let max_total_power: u64 = 1u64 << 20; // ~10^6
        let mut total_power: u64 = 0;

        let steps = iter::from_fn(|| {
            let step = rng.gen_range(1..=20);
            total_power += step;
            Some(total_power)
        });

        for total in steps.take_while(|&v| v <= max_total_power) {
            let one_third_expected = ThresholdParam::F_PLUS_ONE.min_expected(total);
            let two_thirds_expected = ThresholdParam::TWO_F_PLUS_ONE.min_expected(total);
            // Assumption: f < n/3, take a margin before and after
            let power_margin = 3;
            let min_power = core::cmp::max(total / 3, power_margin + 1) - power_margin;
            let max_power = core::cmp::min(total / 3 + power_margin, total);
            for power in min_power..max_power {
                // Assumption: a quorum Q has more than 1/3 of the voting power
                let one_third = ThresholdParam::F_PLUS_ONE.is_met(power, total);
                assert!(
                    one_third == (3 * power > total),
                    "power = {power}, 3*power = {}, total = {total}, {one_third}",
                    3 * power,
                );
                assert!(
                    one_third == (power >= one_third_expected),
                    "power = {power}, total = {total}, one_third_expected = {one_third_expected}"
                );

                // Assumption: a quorum Q has twice more voting power than the remaining
                // Q = total - power; if Q is even, Q/2 > power; else (Q+1)/2 > power
                let two_thirds = ThresholdParam::TWO_F_PLUS_ONE.is_met(total - power, total);
                assert!(
                    two_thirds == ((total - power).div_ceil(2) > power),
                    "power = {power}, total - power = {}, total = {total}, {two_thirds}",
                    total - power,
                );
                assert!(
                    two_thirds == (total - power >= two_thirds_expected),
                    "power = {}, total = {total}, two_thirds_expected = {two_thirds_expected}",
                    total - power,
                );
            }
        }
    }
}
