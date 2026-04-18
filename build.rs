fn main() {
    tonic_build::configure()
        .build_client(false)
        .build_server(true)
        .compile_protos(&["proto/xrpl.proto", "proto/grpc.proto"], &["proto/"])
        .expect("failed to compile protobuf definitions");
}
