//! gRPC Contracts for Trust OS
//!
//! This crate contains the generated protobuf service definitions.
//! Run `cargo build` to generate code from proto files.

#[cfg(feature = "generated")]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/trustos.identity.v1.rs"));
    include!(concat!(env!("OUT_DIR"), "/trustos.governance.v1.rs"));
    include!(concat!(env!("OUT_DIR"), "/trustos.compliance.v1.rs"));
    include!(concat!(env!("OUT_DIR"), "/trustos.risk.v1.rs"));
    include!(concat!(env!("OUT_DIR"), "/trustos.audit.v1.rs"));
    include!(concat!(env!("OUT_DIR"), "/trustos.trust.v1.rs"));
    include!(concat!(env!("OUT_DIR"), "/trustos.events.v1.rs"));
}

#[cfg(feature = "generated")]
pub use generated::*;
