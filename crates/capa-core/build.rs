fn main() {
    if std::env::var_os("PROTOC").is_none() {
        if let Ok(protoc) = protoc_bin_vendored::protoc_bin_path() {
            std::env::set_var("PROTOC", protoc);
        }
    }

    prost_build::Config::new()
        .compile_protos(&["proto/capa.proto"], &["proto/"])
        .expect("compile capa.proto");
}
