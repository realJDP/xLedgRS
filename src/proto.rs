//! Protobuf definitions for the XRPL peer protocol.
//!
//! Generated from rippled's `xrpl.proto` (proto2) via prost.
//! These types are used for encoding/decoding peer-to-peer messages
//! that are compatible with rippled nodes.

include!(concat!(env!("OUT_DIR"), "/protocol.rs"));
