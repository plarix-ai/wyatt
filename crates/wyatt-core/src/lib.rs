//! Policy model and decision engine for Wyatt.
//!
//! The crate does no I/O and reads no clock. The daemon hands it a compiled
//! policy, the session state, the request and the current time, and gets back
//! a [`Decision`]. The same inputs always give the same decision, which is
//! what makes `wyatt test` and `wyatt eval` trustworthy.

pub mod cond;
pub mod error;
pub mod net;
pub mod path;
pub mod units;
