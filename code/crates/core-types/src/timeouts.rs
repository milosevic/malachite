use alloc::vec::Vec;
use core::fmt::Debug;
use core::time::Duration;

use crate::{Context, Timeout, TimeoutKind};

/// Timeouts control how long the consensus engine waits for various steps
/// in the consensus protocol.
///
/// The standard implementation is [`LinearTimeouts`], which should be used
/// unless you have specific requirements for custom timeout behavior. See
/// [`LinearTimeouts::default`] for the default values.
pub trait Timeouts<Ctx>
where
    Self: Clone + Debug + Eq + Send + Sync + Copy + Default,
    Ctx: Context,
{
    /// Get the duration for a given timeout.
    ///
    /// # Arguments
    ///
    /// * `timeout` - The timeout to get the duration for.
    ///
    /// # Returns
    ///
    /// The duration for the given timeout
    ///
    /// # Panics
    ///
    /// If the timeout round is nil, this function must panic.
    fn duration_for(&self, timeout: Timeout) -> Duration;
}

/// Timeouts that increase linearly with the round number.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LinearTimeouts {
    /// How long we wait for a proposal block before prevoting nil
    pub propose: Duration,

    /// How much timeout_propose increases with each round
    pub propose_delta: Duration,

    /// How long we wait after receiving +2/3 prevotes for “anything” (ie. not a single block or nil)
    pub prevote: Duration,

    /// How much the timeout_prevote increases with each round
    pub prevote_delta: Duration,

    /// How long we wait after receiving +2/3 precommits for “anything” (ie. not a single block or nil)
    pub precommit: Duration,

    /// How much the timeout_precommit increases with each round
    pub precommit_delta: Duration,

    /// How long we wait after entering a round before starting
    /// the rebroadcast liveness protocol
    pub rebroadcast: Duration,

    /// Upper bound on the duration returned by [`LinearTimeouts::duration_for`]
    /// for any of the per-round timeout kinds (`Propose`, `Prevote`,
    /// `Precommit`, `Rebroadcast`).
    ///
    /// The computed `base + delta * round` value is clamped to this cap, so
    /// timeouts cannot grow without bound at high round numbers.
    /// [`TimeoutKind::FinalizeHeight`] carries its own duration and is not
    /// affected.
    pub max_timeout: Duration,
}

impl<Ctx: Context> Timeouts<Ctx> for LinearTimeouts {
    fn duration_for(&self, timeout: Timeout) -> Duration {
        self.duration_for(timeout)
    }
}

impl Default for LinearTimeouts {
    fn default() -> Self {
        let propose = Duration::from_secs(3);
        let prevote = Duration::from_secs(1);
        let precommit = Duration::from_secs(1);
        let rebroadcast = propose + prevote + precommit;
        Self {
            propose,
            propose_delta: Duration::from_millis(500),
            prevote,
            prevote_delta: Duration::from_millis(500),
            precommit,
            precommit_delta: Duration::from_millis(500),
            rebroadcast,
            max_timeout: Duration::from_secs(60),
        }
    }
}

/// Quint oracle: a duration in whole milliseconds, the unit the spec models
/// timeouts in. Clamped into i64 so a `Duration::MAX` field cannot wrap the
/// logged value.
fn oracle_ms(duration: Duration) -> i64 {
    let millis = duration.as_millis();
    if millis > i64::MAX as u128 {
        i64::MAX
    } else {
        millis as i64
    }
}

impl LinearTimeouts {
    /// Quint oracle: the configuration this call runs against. `LinearTimeouts` is
    /// built as a struct literal (here and in the applications' middleware), so
    /// there is no constructor to instrument — `self` IS the installed
    /// configuration, and the spec's `LinearTimeoutsset` records it as the state
    /// the call sees.
    fn log_config_install(&self) {
        // Eight scalar arguments, named exactly as the spec action's parameters, so
        // each one PINS its own nondet pick. A single record argument named `cfg`
        // matched no parameter at all: replay left all eight unguided and picked
        // max_timeout: 0, which is what the oracle's assertion mismatch caught.
        quint_oracle::Event::builder(quint_oracle::current_test(), "LinearTimeoutsset")
            .argument("propose", oracle_ms(self.propose), Some("TIMEOUT_MS"))
            .argument(
                "propose_delta",
                oracle_ms(self.propose_delta),
                Some("TIMEOUT_MS"),
            )
            .argument("prevote", oracle_ms(self.prevote), Some("TIMEOUT_MS"))
            .argument(
                "prevote_delta",
                oracle_ms(self.prevote_delta),
                Some("TIMEOUT_MS"),
            )
            .argument("precommit", oracle_ms(self.precommit), Some("TIMEOUT_MS"))
            .argument(
                "precommit_delta",
                oracle_ms(self.precommit_delta),
                Some("TIMEOUT_MS"),
            )
            .argument("rebroadcast", oracle_ms(self.rebroadcast), Some("TIMEOUT_MS"))
            .argument("max_timeout", oracle_ms(self.max_timeout), Some("TIMEOUT_MS"))
            .assert(
                Vec::from([
                    quint_oracle::PathSeg::ident("state"),
                    quint_oracle::PathSeg::ident("timeouts"),
                    quint_oracle::PathSeg::ident("max_timeout"),
                ]),
                oracle_ms(self.max_timeout),
            )
            .scope("core-types-domain")
            .send();
    }

    /// See [`Timeouts::duration_for`].
    pub fn duration_for(&self, timeout: Timeout) -> Duration {
        // The kind travels as its name plus, for FinalizeHeight, its own duration:
        // the oracle's value dialect has no constructor for a payload-carrying
        // variant, and the spec models the kind the same way.
        let (oracle_kind, oracle_finalize_ms) = match timeout.kind {
            TimeoutKind::Propose => ("Propose", 0i64),
            TimeoutKind::Prevote => ("Prevote", 0i64),
            TimeoutKind::Precommit => ("Precommit", 0i64),
            TimeoutKind::Rebroadcast => ("Rebroadcast", 0i64),
            TimeoutKind::FinalizeHeight(duration) => ("FinalizeHeight", oracle_ms(duration)),
        };

        if quint_oracle::enabled() {
            self.log_config_install();

            if timeout.round.is_nil() {
                quint_oracle::Event::builder(
                    quint_oracle::current_test(),
                    "Timeoutsduration_for_nil_round_panics",
                )
                .argument("kind", oracle_kind, Some("TIMEOUT_KINDS"))
                .argument(
                    "finalize_ms",
                    oracle_finalize_ms,
                    Some("FINALIZE_DURATIONS"),
                )
                .argument("round", timeout.round.as_i64(), Some("ROUNDS"))
                .assert(
                    Vec::from([
                        quint_oracle::PathSeg::ident("state"),
                        quint_oracle::PathSeg::ident("panic_timeout_nil_round"),
                    ]),
                    true,
                )
                .scope("core-types-domain")
                .send();
            }
        }

        let round = timeout.round.as_u32().expect("Round must be defined");

        // Saturating arithmetic: `delta * round` with Duration's `Mul<u32>`
        // panics on overflow. The extrapolated per-round value is clamped
        // to `max_timeout` immediately after, so any saturation beyond the
        // cap is indistinguishable from a normal clamp.
        let duration = match timeout.kind {
            TimeoutKind::Propose => self
                .propose
                .saturating_add(self.propose_delta.saturating_mul(round))
                .min(self.max_timeout),
            TimeoutKind::Prevote => self
                .prevote
                .saturating_add(self.prevote_delta.saturating_mul(round))
                .min(self.max_timeout),
            TimeoutKind::Precommit => self
                .precommit
                .saturating_add(self.precommit_delta.saturating_mul(round))
                .min(self.max_timeout),
            TimeoutKind::Rebroadcast => {
                let deltas = self
                    .propose_delta
                    .saturating_add(self.prevote_delta)
                    .saturating_add(self.precommit_delta);
                self.rebroadcast
                    .saturating_add(deltas.saturating_mul(round))
                    .min(self.max_timeout)
            }
            TimeoutKind::FinalizeHeight(duration) => duration,
        };

        if quint_oracle::enabled() {
            let per_round = !matches!(timeout.kind, TimeoutKind::FinalizeHeight(_));
            let unclamped = match timeout.kind {
                TimeoutKind::Propose => self
                    .propose
                    .saturating_add(self.propose_delta.saturating_mul(round)),
                TimeoutKind::Prevote => self
                    .prevote
                    .saturating_add(self.prevote_delta.saturating_mul(round)),
                TimeoutKind::Precommit => self
                    .precommit
                    .saturating_add(self.precommit_delta.saturating_mul(round)),
                TimeoutKind::Rebroadcast => {
                    let deltas = self
                        .propose_delta
                        .saturating_add(self.prevote_delta)
                        .saturating_add(self.precommit_delta);
                    self.rebroadcast.saturating_add(deltas.saturating_mul(round))
                }
                TimeoutKind::FinalizeHeight(duration) => duration,
            };

            let event =
                quint_oracle::Event::builder(quint_oracle::current_test(), "Timeoutsduration_for")
                    .argument("kind", oracle_kind, Some("TIMEOUT_KINDS"))
                    .argument("finalize_ms", oracle_finalize_ms, Some("FINALIZE_DURATIONS"))
                    .argument("round", timeout.round.as_i64(), Some("ROUNDS"));

            // Both flags are monotone in the spec, so each is pinned only on a call
            // that actually sets it.
            let event = if per_round && unclamped > duration {
                event.assert(
                    Vec::from([
                        quint_oracle::PathSeg::ident("state"),
                        quint_oracle::PathSeg::ident("timeout_clamped"),
                    ]),
                    true,
                )
            } else {
                event
            };
            let event = if !per_round && duration > self.max_timeout {
                event.assert(
                    Vec::from([
                        quint_oracle::PathSeg::ident("state"),
                        quint_oracle::PathSeg::ident("finalize_above_cap"),
                    ]),
                    true,
                )
            } else {
                event
            };

            event.scope("core-types-domain").send();
        }

        duration
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Round;

    #[test]
    fn test_default_timeouts() {
        let timeouts = LinearTimeouts::default();

        assert_eq!(timeouts.propose, Duration::from_secs(3));
        assert_eq!(timeouts.propose_delta, Duration::from_millis(500));
        assert_eq!(timeouts.prevote, Duration::from_secs(1));
        assert_eq!(timeouts.prevote_delta, Duration::from_millis(500));
        assert_eq!(timeouts.precommit, Duration::from_secs(1));
        assert_eq!(timeouts.precommit_delta, Duration::from_millis(500));
        assert_eq!(timeouts.rebroadcast, Duration::from_secs(5)); // 3 + 1 + 1
        assert_eq!(timeouts.max_timeout, Duration::from_secs(60));
    }

    /// reproduces obs:zero_timeout_computed — fails on current code.
    ///
    /// An application supplies its timeouts through the middleware's
    /// `get_timeouts` hook, which returns a `LinearTimeouts` built as a struct
    /// literal over the defaults (see the test app's timeout middleware). All
    /// the fields are public and nothing validates them, so an operator who
    /// zeroes `propose` — "don't wait for a proposal" — gets a propose timeout
    /// of zero at round 0, which expires immediately and prevotes nil before
    /// any proposal can arrive. The model's
    /// `computed_timeouts_are_positive_and_capped` requires every duration
    /// `duration_for` produces to be strictly positive. A zero `max_timeout`
    /// collapses every timeout kind the same way.
    #[test]
    #[ignore]
    fn duration_for_never_returns_a_zero_timeout() {
        let timeouts = LinearTimeouts {
            propose: Duration::ZERO,
            ..LinearTimeouts::default()
        };

        let propose_r0 = timeouts.duration_for(Timeout::propose(Round::new(0)));

        assert!(
            !propose_r0.is_zero(),
            "propose timeout at round 0 expired immediately"
        );
    }

    #[test]
    fn test_propose_timeout_increases_linearly() {
        let timeouts = LinearTimeouts::default();

        // Round 0: 3s
        let r0 = timeouts.duration_for(Timeout::propose(Round::new(0)));
        assert_eq!(r0, Duration::from_secs(3));

        // Round 1: 3s + 0.5s = 3.5s
        let r1 = timeouts.duration_for(Timeout::propose(Round::new(1)));
        assert_eq!(r1, Duration::from_millis(3500));

        // Round 2: 3s + 1s = 4s
        let r2 = timeouts.duration_for(Timeout::propose(Round::new(2)));
        assert_eq!(r2, Duration::from_secs(4));

        // Round 10: 3s + 5s = 8s
        let r10 = timeouts.duration_for(Timeout::propose(Round::new(10)));
        assert_eq!(r10, Duration::from_secs(8));
    }

    #[test]
    fn test_prevote_timeout_increases_linearly() {
        let timeouts = LinearTimeouts::default();

        // Round 0: 1s
        let r0 = timeouts.duration_for(Timeout::prevote(Round::new(0)));
        assert_eq!(r0, Duration::from_secs(1));

        // Round 1: 1s + 0.5s = 1.5s
        let r1 = timeouts.duration_for(Timeout::prevote(Round::new(1)));
        assert_eq!(r1, Duration::from_millis(1500));

        // Round 2: 1s + 1s = 2s
        let r2 = timeouts.duration_for(Timeout::prevote(Round::new(2)));
        assert_eq!(r2, Duration::from_secs(2));

        // Round 10: 1s + 5s = 6s
        let r10 = timeouts.duration_for(Timeout::prevote(Round::new(10)));
        assert_eq!(r10, Duration::from_secs(6));
    }

    #[test]
    fn test_precommit_timeout_increases_linearly() {
        let timeouts = LinearTimeouts::default();

        // Round 0: 1s
        let r0 = timeouts.duration_for(Timeout::precommit(Round::new(0)));
        assert_eq!(r0, Duration::from_secs(1));

        // Round 1: 1s + 0.5s = 1.5s
        let r1 = timeouts.duration_for(Timeout::precommit(Round::new(1)));
        assert_eq!(r1, Duration::from_millis(1500));

        // Round 2: 1s + 1s = 2s
        let r2 = timeouts.duration_for(Timeout::precommit(Round::new(2)));
        assert_eq!(r2, Duration::from_secs(2));

        // Round 10: 1s + 5s = 6s
        let r10 = timeouts.duration_for(Timeout::precommit(Round::new(10)));
        assert_eq!(r10, Duration::from_secs(6));
    }

    #[test]
    fn test_rebroadcast_timeout_increases_linearly() {
        let timeouts = LinearTimeouts::default();

        // Round 0: 5s
        let r0 = timeouts.duration_for(Timeout::rebroadcast(Round::new(0)));
        assert_eq!(r0, Duration::from_secs(5));

        // Round 1: 5s + (0.5s + 0.5s + 0.5s) = 5s + 1.5s = 6.5s
        let r1 = timeouts.duration_for(Timeout::rebroadcast(Round::new(1)));
        assert_eq!(r1, Duration::from_millis(6500));

        // Round 2: 5s + 3s = 8s
        let r2 = timeouts.duration_for(Timeout::rebroadcast(Round::new(2)));
        assert_eq!(r2, Duration::from_secs(8));

        // Round 10: 5s + 15s = 20s
        let r10 = timeouts.duration_for(Timeout::rebroadcast(Round::new(10)));
        assert_eq!(r10, Duration::from_secs(20));
    }

    #[test]
    fn test_custom_timeouts() {
        let timeouts = LinearTimeouts {
            propose: Duration::from_secs(5),
            propose_delta: Duration::from_secs(1),
            prevote: Duration::from_secs(2),
            prevote_delta: Duration::from_millis(100),
            precommit: Duration::from_secs(3),
            precommit_delta: Duration::from_millis(200),
            rebroadcast: Duration::from_secs(10),
            ..LinearTimeouts::default()
        };

        // Test propose at round 3: 5s + 3*1s = 8s
        let propose_r3 = timeouts.duration_for(Timeout::propose(Round::new(3)));
        assert_eq!(propose_r3, Duration::from_secs(8));

        // Test prevote at round 5: 2s + 5*0.1s = 2.5s
        let prevote_r5 = timeouts.duration_for(Timeout::prevote(Round::new(5)));
        assert_eq!(prevote_r5, Duration::from_millis(2500));

        // Test precommit at round 4: 3s + 4*0.2s = 3.8s
        let precommit_r4 = timeouts.duration_for(Timeout::precommit(Round::new(4)));
        assert_eq!(precommit_r4, Duration::from_millis(3800));

        // Test rebroadcast at round 2: 10s + 2*(1s + 0.1s + 0.2s) = 10s + 2.6s = 12.6s
        let rebroadcast_r2 = timeouts.duration_for(Timeout::rebroadcast(Round::new(2)));
        assert_eq!(rebroadcast_r2, Duration::from_millis(12600));
    }

    #[test]
    fn test_per_round_timeouts_clamped_at_max_timeout() {
        let timeouts = LinearTimeouts {
            max_timeout: Duration::from_secs(10),
            ..LinearTimeouts::default()
        };

        // Propose: 3s + 0.5s * 100 = 53s, clamped to 10s
        let propose = timeouts.duration_for(Timeout::propose(Round::new(100)));
        assert_eq!(propose, Duration::from_secs(10));

        // Prevote: 1s + 0.5s * 100 = 51s, clamped to 10s
        let prevote = timeouts.duration_for(Timeout::prevote(Round::new(100)));
        assert_eq!(prevote, Duration::from_secs(10));

        // Precommit: 1s + 0.5s * 100 = 51s, clamped to 10s
        let precommit = timeouts.duration_for(Timeout::precommit(Round::new(100)));
        assert_eq!(precommit, Duration::from_secs(10));

        // Rebroadcast: 5s + 1.5s * 100 = 155s, clamped to 10s
        let rebroadcast = timeouts.duration_for(Timeout::rebroadcast(Round::new(100)));
        assert_eq!(rebroadcast, Duration::from_secs(10));
    }

    #[test]
    fn test_per_round_timeouts_not_clamped_below_max_timeout() {
        let timeouts = LinearTimeouts::default();
        // With default max_timeout of 60s, round 2 values all fall well below the cap.
        assert_eq!(
            timeouts.duration_for(Timeout::propose(Round::new(2))),
            Duration::from_secs(4)
        );
        assert_eq!(
            timeouts.duration_for(Timeout::prevote(Round::new(2))),
            Duration::from_secs(2)
        );
        assert_eq!(
            timeouts.duration_for(Timeout::precommit(Round::new(2))),
            Duration::from_secs(2)
        );
        assert_eq!(
            timeouts.duration_for(Timeout::rebroadcast(Round::new(2))),
            Duration::from_secs(8)
        );
    }

    #[test]
    fn test_duration_for_does_not_overflow_at_max_round() {
        let timeouts = LinearTimeouts {
            propose_delta: Duration::MAX,
            prevote_delta: Duration::MAX,
            precommit_delta: Duration::MAX,
            ..LinearTimeouts::default()
        };
        let round = Round::new(u32::MAX);

        // Without saturating arithmetic, `delta * round` on Duration panics.
        // All per-round kinds should saturate and then clamp to max_timeout.
        assert_eq!(
            timeouts.duration_for(Timeout::propose(round)),
            timeouts.max_timeout
        );
        assert_eq!(
            timeouts.duration_for(Timeout::prevote(round)),
            timeouts.max_timeout
        );
        assert_eq!(
            timeouts.duration_for(Timeout::precommit(round)),
            timeouts.max_timeout
        );
        assert_eq!(
            timeouts.duration_for(Timeout::rebroadcast(round)),
            timeouts.max_timeout
        );
    }

    #[test]
    fn test_finalize_height_timeout_not_clamped() {
        let timeouts = LinearTimeouts {
            max_timeout: Duration::from_secs(10),
            ..LinearTimeouts::default()
        };
        // A FinalizeHeight duration larger than max_timeout passes through unchanged.
        let duration = Duration::from_secs(120);
        let timeout = Timeout::finalize_height(Round::new(0), duration);
        assert_eq!(timeouts.duration_for(timeout), duration);
    }
}
