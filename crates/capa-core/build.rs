fn main() {
    prost_build::Config::new()
        .compile_protos(&["proto/capa.proto"], &["proto/"])
        .expect("compile capa.proto");
}
