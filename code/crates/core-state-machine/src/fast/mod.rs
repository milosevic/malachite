//! The Fast Tendermint per-round state machine (`n > 5f`).
//!
//! This is a **separate** implementation of the round state machine, not a mode of the
//! classic one. Fast Tendermint tolerates `f < n/5` rather than `f < n/3` and decides in
//! two communication steps instead of three, so the two protocols are not interoperable at
//! the resilience, wire or certificate level. Keeping them apart means the classic path
//! cannot regress while this one is built.
//!
//! Reference: Preston Vander Vos, Daniel Cason, *"Fast Tendermint: Speeding Up a
//! Foundational Consensus Protocol"*, arXiv:2608.13434. Line numbers in comments below
//! refer to Algorithm 1 of that paper.
//!
//! Two differences from classic Tendermint drive everything else:
//!
//! 1. **The prevote and precommit steps collapse into one voting step**, which the paper
//!    calls `precommit`. A round is therefore `Unstarted -> Propose -> Precommit -> Commit`.
//! 2. **`locked` and `valid` merge into a single `valid: (round, id(value))`**, holding the
//!    value *identifier* rather than the value — fresh proposals carry a full value,
//!    re-proposals carry only an id (L13/L15).
//!
//! Two thresholds act on the single vote tally, and there is no `f+1` rule at all: the
//! paper removes round-skipping on one-correct-process-in-a-higher-round, because the
//! observation rule must capture valid values *before* a process moves up. See
//! [`crate::fast::input::Input`] for how the two thresholds enter.

pub mod input;
pub mod output;
pub mod state;
pub mod state_machine;
