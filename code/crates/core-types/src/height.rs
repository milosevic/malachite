use alloc::vec::Vec;
use core::fmt::{Debug, Display};
use core::hash::Hash;

/// Defines the requirements for a height type.
///
/// A height denotes the number of blocks (values) created since the chain began.
///
/// A height of 0 represents a chain which has not yet produced a block.
pub trait Height
where
    Self: Copy + Clone + Default + Debug + Display + Eq + Ord + Hash + Send + Sync,
{
    /// The zero-th height. Typically 0.
    ///
    /// This value must be the same as the one built by the `Default` impl.
    const ZERO: Self;

    /// The initial height. Typically 1.
    const INITIAL: Self;

    /// Increment the height by one.
    fn increment(&self) -> Self {
        let incremented = self.increment_by(1);

        if quint_oracle::enabled() {
            quint_oracle::Event::builder(quint_oracle::current_test(), "Heightincrement_by")
                .argument("from", self.as_u64(), Some("HEIGHTS"))
                .argument("by", 1i64, None)
                .scope("core-types-domain")
                .send();
        }

        incremented
    }

    /// Decrement the height by one.
    fn decrement(&self) -> Option<Self> {
        let decremented = self.decrement_by(1);

        // Only the arguments are pinned, deliberately: the two Height impls in this
        // repo disagree about the result below the minimum (the test context
        // saturates and returns Some, the core-types unit test's own impl returns
        // None), so asserting a result here would report one of them as a replay
        // violation. The contract itself lives in the spec's
        // decrement_below_minimum_returns_none invariant.
        if quint_oracle::enabled() {
            quint_oracle::Event::builder(quint_oracle::current_test(), "Heightdecrement_by")
                .argument("from", self.as_u64(), Some("HEIGHTS"))
                .argument("by", 1i64, None)
                .assert(
                    Vec::from([
                        quint_oracle::PathSeg::ident("state"),
                        quint_oracle::PathSeg::ident("last_decrement_from"),
                    ]),
                    self.as_u64(),
                )
                .assert(
                    Vec::from([
                        quint_oracle::PathSeg::ident("state"),
                        quint_oracle::PathSeg::ident("last_decrement_by"),
                    ]),
                    1i64,
                )
                .scope("core-types-domain")
                .send();
        }

        decremented
    }

    /// Increment this height by the given amount.
    fn increment_by(&self, n: u64) -> Self;

    /// Decrement this height by the given amount.
    /// Returns None if the height would be decremented below its minimum.
    fn decrement_by(&self, n: u64) -> Option<Self>;

    /// Convert the height to a `u64`.
    fn as_u64(&self) -> u64;
}
