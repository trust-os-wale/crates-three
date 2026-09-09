//! Database crate for Trust OS.
//!
//! Provides PostgreSQL connection pooling and query helpers.

pub mod models;
pub mod pool;

pub use models::*;
pub use pool::*;
