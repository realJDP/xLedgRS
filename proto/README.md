# Protocol Definitions

This folder contains protobuf schemas used by the peer protocol and optional
gRPC service layer.

- `xrpl.proto` - XRPL peer protocol messages used for RTXP networking, ledger sync, transactions, proposals, and validations.
- `grpc.proto` - gRPC service definitions exposed by xLedgRSv2Beta for local clients and tooling.

`build.rs` compiles these files during Cargo builds.
