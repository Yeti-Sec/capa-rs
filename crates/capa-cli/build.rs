fn main() {
    // When the ida-backend feature is enabled on Windows, pass /FORCE:UNRESOLVED
    // because some autocxx-wrapped C++ inline methods from the IDA SDK headers are
    // only available at runtime in ida.dll/idalib.dll, not in the SDK import stubs.
    #[cfg(all(feature = "ida-backend", target_os = "windows"))]
    {
        println!("cargo::rustc-link-arg=/FORCE:UNRESOLVED");
    }

    // On Linux, link directly against libida.so + libidalib.so from IDADIR.
    #[cfg(all(feature = "ida-backend", target_os = "linux"))]
    {
        let idadir = std::env::var("IDADIR").unwrap_or_else(|_| "/opt/ida".to_string());
        println!("cargo::rustc-link-search=native={idadir}");
        println!("cargo::rustc-link-lib=dylib=ida");
        println!("cargo::rustc-link-lib=dylib=idalib");
    }
}
