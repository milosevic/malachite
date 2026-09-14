//! The Fast Tendermint driver (`n > 5f`).
//!
//! A **separate** driver from the classic one, for the same reason the state machine and
//! vote keeper are separate: the two protocols are not interoperable, and keeping them
//! apart means the classic path cannot regress.
//!
//! Its job is the multiplexing that neither the state machine nor the keeper can do alone.
//! The keeper reports threshold crossings over votes; the state machine consumes protocol
//! inputs about proposals and quorums. Three of the paper's rules need something in
//! between:
//!
//! - **L27** accepts a re-proposal only when `2f+1` votes justify it *from the round the
//!   proposal names*, so the driver asks the keeper before handing it over.
//! - **L42** decides on a fresh proposal from one round plus `n - f` votes from another, so
//!   the driver has to pair a quorum with a proposal it may have seen rounds earlier.
//! - **L15-L16** re-proposes an identifier, which only means something once resolved back
//!   to the value the original fresh proposal carried.
//!
//! See [`proposals::FreshProposals`] for why the originals are retained.

pub mod driver;
pub mod proposals;
