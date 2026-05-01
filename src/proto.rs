//! xLedgRS purpose: Expose generated XRPL protobuf bindings to Rust code.
//! Protobuf definitions for the XRPL peer protocol.
//!
//! Generated from rippled's `xrpl.proto` (proto2) via `prost`.
//! These types encode and decode peer-to-peer messages compatible with
//! rippled nodes.

include!(concat!(env!("OUT_DIR"), "/protocol.rs"));
