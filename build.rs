// Compile XRPL peer and gRPC protobuf schemas for the daemon and service layer.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=proto/xrpl.proto");
    println!("cargo:rerun-if-changed=proto/grpc.proto");

    tonic_build::configure()
        .build_client(false)
        .build_server(true)
        .compile_protos(&["proto/xrpl.proto", "proto/grpc.proto"], &["proto/"])
        .expect("failed to compile protobuf definitions");
}
