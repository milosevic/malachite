//! Vote tallying for Fast Tendermint (`n > 5f`).
//!
//! A **separate** keeper, not a mode of the classic one. Three things make it structurally
//! different rather than differently parameterised:
//!
//! 1. **One vote type.** Fast Tendermint has a single voting step, which the paper names
//!    `precommit`, so there is no prevote tally and no polka family at all.
//! 2. **Two thresholds over the same tally, latched independently.** `2f+1` for a value
//!    makes it valid; `n - f` decides. Both can fire for one round, and the first must not
//!    suppress the second. The classic keeper emits at most one output per round per vote
//!    type, so it cannot express this — see [`keeper::Output`].
//! 3. **No `SkipRound` and no `f+1` threshold.** The paper removes round-skipping on
//!    one-correct-process-in-a-higher-round, because the observation rule must capture
//!    valid values before a process moves up. The `n - f` quorum-any rule
//!    ([`keeper::Output::QuorumAny`]) is the only path that advances a round.
//!
//! Reference: Vander Vos & Cason, *"Fast Tendermint"* (arXiv:2608.13434). Line numbers in
//! comments refer to its Algorithm 1.

pub mod keeper;
pub mod params;
