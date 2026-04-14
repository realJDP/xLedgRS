fn main() {
    prost_build::Config::new()
        .compile_protos(&["proto/xrpl.proto"], &["proto/"])
        .expect("failed to compile xrpl.proto");
}
