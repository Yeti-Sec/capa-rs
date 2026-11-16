fn main() {
    #[cfg(all(feature = "ida-backend", target_os = "windows"))]
    {
        println!("cargo::rustc-link-arg=/FORCE:UNRESOLVED");
    }

    #[cfg(all(feature = "ida-backend", target_os = "linux"))]
    {
        let idadir = std::env::var("IDADIR").unwrap_or_else(|_| "/opt/ida".to_string());
        println!("cargo::rustc-link-search=native={idadir}");
        println!("cargo::rustc-link-lib=dylib=ida");
        println!("cargo::rustc-link-lib=dylib=idalib");
    }
}
