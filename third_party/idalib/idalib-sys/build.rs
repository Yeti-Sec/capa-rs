use std::env;
use std::path::{Path, PathBuf};

use autocxx_bindgen::Builder as BindgenBuilder;
use autocxx_bindgen::callbacks::{IntKind, ParseCallbacks};

/// Returns the OS of the target being built (e.g., `linux`).
fn target_os() -> String {
    env::var("CARGO_CFG_TARGET_OS").expect("CARGO_CFG_TARGET_OS should be set")
}

/// Returns the architecture of the target being built (e.g., `aarch64`).
fn target_arch() -> String {
    env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH should be set")
}

/// Returns the IDA SDK platform macros (each defined as `1`) for target `os` and `arch`.
fn sdk_defines(os: &str, arch: &str) -> Vec<&'static str> {
    let mut defines = vec![match os {
        "linux" => "__LINUX__",
        "macos" => "__MACOS__",
        "windows" => "__NT__",
        _ => panic!("unsupported platform"),
    }];

    if arch == "aarch64" {
        defines.push("__ARM__");
    }

    defines.push("__EA64__");
    defines
}

/// Returns the clang arguments for parsing the IDA SDK headers for target `os` and `arch`.
fn sdk_clang_args(os: &str, arch: &str) -> Vec<String> {
    let mut args = vec!["-std=c++17".to_owned()];

    args.extend(
        sdk_defines(os, arch)
            .into_iter()
            .map(|name| format!("-D{name}=1")),
    );

    if os == "windows" {
        args.push("-D_CRT_USE_BUILTIN_OFFSETOF".to_owned());
    }

    args
}

#[derive(Debug)]
struct InstructionEnumCallbacks;

impl ParseCallbacks for InstructionEnumCallbacks {
    fn enum_type_override(&self, _: &str) -> Option<IntKind> {
        Some(IntKind::U16)
    }
}

fn configure_and_generate(
    builder: BindgenBuilder,
    ida: &Path,
    clang_args: &[String],
    output: impl AsRef<Path>,
) {
    let rs = PathBuf::from(env::var("OUT_DIR").unwrap()).join(output.as_ref());
    let bindings = builder
        .clang_arg("-xc++")
        .clang_arg(format!("-I{}", ida.display()))
        .clang_args(clang_args)
        .respect_cxx_access_specs(true)
        .generate()
        .expect("generate bindings");

    bindings.write_to_file(rs).expect("write bindings");
}

/// This vendored copy targets IDA 9.5 (floss-rs local patch). The resolved SDK's
/// `IDA_SDK_VERSION` must match, so an incompatible SDK is rejected at build time
/// rather than miscompiled.
const EXPECTED_IDA_SDK_VERSION: u32 = 950;

/// Resolve the IDA SDK path (floss-rs local patch; no network access).
///
/// Order: `IDASDK_ROOT` (either the SDK `src` dir or its parent), then the
/// `sdk/src` submodule. The SDK itself is never vendored in this repo.
fn resolve_sdk_path() -> PathBuf {
    println!("cargo::rerun-if-env-changed=IDASDK_ROOT");
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR should be set"));

    if let Ok(sdk_root) = env::var("IDASDK_ROOT") {
        let sdk_path = PathBuf::from(&sdk_root);
        if sdk_path.join("include").join("pro.h").exists() {
            return sdk_path;
        }
        let src_path = sdk_path.join("src");
        if src_path.join("include").join("pro.h").exists() {
            return src_path;
        }
        panic!("IDASDK_ROOT={sdk_root} does not contain include/pro.h.");
    }

    let submodule_path = manifest_dir.join("sdk").join("src");
    if submodule_path.join("include").join("pro.h").exists() {
        return submodule_path;
    }
    panic!(
        "IDA SDK not found. Set IDASDK_ROOT to a local IDA 9.5 SDK `src` directory \
         (looked for {}/include/pro.h).",
        submodule_path.display()
    );
}

/// Reject an SDK whose `IDA_SDK_VERSION` is not `EXPECTED_IDA_SDK_VERSION`.
fn verify_sdk_version(ida_include: &Path) {
    let pro_h = ida_include.join("pro.h");
    let contents = std::fs::read_to_string(&pro_h)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", pro_h.display()));
    let version = contents.lines().find_map(|line| {
        let rest = line.trim().strip_prefix("#define")?.trim_start();
        let rest = rest.strip_prefix("IDA_SDK_VERSION")?.trim_start();
        rest.split_whitespace().next()?.parse::<u32>().ok()
    });
    match version {
        Some(v) if v == EXPECTED_IDA_SDK_VERSION => {}
        Some(v) => panic!(
            "IDA SDK version mismatch: found IDA_SDK_VERSION={v}, but this vendored idalib \
             targets {EXPECTED_IDA_SDK_VERSION} (IDA 9.5). Point IDASDK_ROOT at a 9.5 SDK."
        ),
        None => panic!("could not determine IDA_SDK_VERSION from {}", pro_h.display()),
    }
}

fn main() {
    let sdk_path = resolve_sdk_path();
    verify_sdk_version(&sdk_path.join("include"));
    let ida = sdk_path.join("include");

    let ffi_path = Path::new("src");

    cxx_build::CFG.exported_header_dirs.push(&ida);

    let os = target_os();
    let arch = target_arch();
    let clang_args = sdk_clang_args(&os, &arch);

    let mut builder = autocxx_build::Builder::new(ffi_path.join("lib.rs"), [ffi_path, &*ida])
        .extra_clang_args(&clang_args.iter().map(String::as_str).collect::<Vec<_>>())
        .build()
        .expect("parsed correctly");

    let stubs = builder.cargo_warnings(false);

    if os == "windows" {
        stubs.cpp(true).std("c++17");
    } else {
        stubs.flag_if_supported("-std=c++17");
    }

    for name in sdk_defines(&os, &arch) {
        stubs.define(name, "1");
    }

    stubs.compile("libida-stubs");

    let pod = autocxx_bindgen::builder()
        .header(ida.join("pro.h").to_str().expect("path is valid string"))
        .header(ida.join("ua.hpp").to_str().expect("path is valid string"))
        .allowlist_type("insn_t")
        .allowlist_type("op_t")
        .allowlist_type("optype_t")
        .allowlist_item("OF_.*");

    configure_and_generate(pod, &ida, &clang_args, "pod.rs");

    let idp = autocxx_bindgen::builder()
        .header(ida.join("pro.h").to_str().expect("path is valid string"))
        .header(ida.join("idp.hpp").to_str().expect("path is valid string"))
        .allowlist_item("PLFM_.*");

    configure_and_generate(idp, &ida, &clang_args, "idp.rs");

    let inf = autocxx_bindgen::builder()
        .header(ida.join("pro.h").to_str().expect("path is valid string"))
        .header(ida.join("ida.hpp").to_str().expect("path is valid string"))
        .header(
            ida.join("typeinf.hpp")
                .to_str()
                .expect("path is valid string"),
        )
        .allowlist_item("AF_.*")
        .allowlist_item("AF2_.*")
        .allowlist_item("CM_.*")
        .allowlist_item("COMP_.*")
        .allowlist_item("INFFL_.*")
        .allowlist_item("LFLG_.*")
        .allowlist_item("STT_.*")
        .allowlist_item("SW_.*")
        .allowlist_item("compiler_info_t");

    configure_and_generate(inf, &ida, &clang_args, "inf.rs");

    let insn_consts = [
        ("ARM_.*", "insn_arm.rs"),
        ("NN_.*", "insn_x86.rs"),
        ("MIPS_.*", "insn_mips.rs"),
    ];

    for (prefix, output) in insn_consts {
        let insn = autocxx_bindgen::builder()
            .header(ida.join("pro.h").to_str().expect("path is valid string"))
            .header(
                ida.join("allins.hpp")
                    .to_str()
                    .expect("path is a valid string"),
            )
            .clang_arg("-fshort-enums")
            .parse_callbacks(Box::new(InstructionEnumCallbacks))
            .allowlist_item(prefix);

        configure_and_generate(insn, &ida, &clang_args, output);
    }

    let hexrays = autocxx_bindgen::builder()
        .header(ida.join("pro.h").to_str().expect("path is valid string"))
        .header(
            ida.join("hexrays.hpp")
                .to_str()
                .expect("path is valid string"),
        )
        .allowlist_item("CV_.*")
        .allowlist_item("DECOMP_.*");

    configure_and_generate(hexrays, &ida, &clang_args, "hexrays.rs");

    let plugin = autocxx_bindgen::builder()
        .header(ida.join("pro.h").to_str().expect("path is valid string"))
        .header(
            ida.join("loader.hpp")
                .to_str()
                .expect("path is valid string"),
        )
        .allowlist_item("plugmod_t")
        .allowlist_item("plugin_t");

    configure_and_generate(plugin, &ida, &clang_args, "plugin.rs");

    println!("cargo::metadata=sdk={}", sdk_path.display());

    println!(
        "cargo::rerun-if-changed={}",
        ffi_path.join("lib.rs").display()
    );
}
