//! FLIRT library-function identification for the IDA backend (opt-in, off by default).
//!
//! Python capa applies its three bundled FLIRT signature files (`sigs/*.sig`)
//! to PE inputs (vivisect backend only, `capa.main.get_signatures_from_cli`)
//! and skips every function the signatures match. This module reproduces that
//! with IDA: the signature files are planned via `plan_to_apply_idasgn`, and
//! after `auto_wait()` IDA marks matched functions `FUNC_LIB`, which the
//! lifter already treats as library code.
//!
//! IDA's API takes a *short* file name (no directory part, see
//! `funcs.hpp: plan_to_apply_idasgn`) and resolves it against its signature
//! directories (`$IDADIR/sig/pc`, `$IDAUSR/sig/pc`). When a file is not found
//! there it is copied into the IDA user signature directory and planned again.
//!
//! Ordering mirrors capa (`capa.loader.get_signatures`): files with suffix
//! `.sig` found under the signatures path, sorted alphabetically by name.

use std::path::{Path, PathBuf};

use idalib::idb::IDB;
use log::{debug, warn};

/// Environment variable naming the directory that holds capa's `.sig` files.
pub const SIGS_DIR_ENV: &str = "CAPA_SIGS_DIR";

/// Resolve the signature path. FLIRT application is OPT-IN: returns `Some` only
/// when an explicit path was given (`--signatures`) or `CAPA_SIGS_DIR` is set and
/// non-empty. There is no implicit default search path, so without either, no
/// signatures are applied and IDA behaves as before.
pub fn resolve_sigs_dir(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return Some(p.to_path_buf());
    }
    match std::env::var_os(SIGS_DIR_ENV) {
        Some(v) if !v.is_empty() => Some(PathBuf::from(v)),
        _ => None,
    }
}

/// List `.sig` files under `path` (file or directory), sorted by file name like capa.
pub fn list_sig_files(path: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if path.is_file() {
        out.push(path.to_path_buf());
    } else if path.is_dir() {
        collect(path, &mut out);
    }
    out.retain(|p| {
        p.extension()
            .map(|e| e.eq_ignore_ascii_case("sig"))
            .unwrap_or(false)
    });
    out.sort_by(|a, b| a.file_name().cmp(&b.file_name()));
    out
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                collect(&p, out);
            } else if p.is_file() {
                out.push(p);
            }
        }
    }
}

/// IDA user signature directory (`<first IDAUSR entry or default>/sig/pc`).
fn user_sig_dir() -> Option<PathBuf> {
    let base = match std::env::var_os("IDAUSR") {
        Some(v) if !v.is_empty() => std::env::split_paths(&v).next()?,
        _ => {
            if cfg!(windows) {
                PathBuf::from(std::env::var_os("APPDATA")?)
                    .join("Hex-Rays")
                    .join("IDA Pro")
            } else {
                PathBuf::from(std::env::var_os("HOME")?).join(".idapro")
            }
        }
    };
    Some(base.join("sig").join("pc"))
}

fn stage_into_user_dir(sig: &Path) -> Option<PathBuf> {
    let dir = user_sig_dir()?;
    std::fs::create_dir_all(&dir).ok()?;
    let dest = dir.join(sig.file_name()?);
    std::fs::copy(sig, &dest).ok()?;
    Some(dest)
}

/// Plan capa's signature files and let IDA apply them. Never fails: problems
/// are logged and analysis continues without library identification.
/// Returns the number of signature files IDA accepted.
pub fn apply_flirt_signatures(idb: &mut IDB, sigs: &Path) -> usize {
    let files = list_sig_files(sigs);
    if files.is_empty() {
        warn!(
            "FLIRT: no .sig files found under {}; library functions will not be identified",
            sigs.display()
        );
        return 0;
    }
    let mut planned = 0usize;
    for sig in &files {
        let Some(short) = sig.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let mut rc = idb.plan_to_apply_idasgn(short).unwrap_or(0);
        if rc == 0 {
            if let Some(dest) = stage_into_user_dir(sig) {
                debug!("FLIRT: {short} not in IDA sig dirs; staged {}", dest.display());
                rc = idb.plan_to_apply_idasgn(short).unwrap_or(0);
            }
        }
        if rc == 0 {
            warn!("FLIRT: IDA could not load signature {short} (not in $IDADIR/sig/pc or $IDAUSR/sig/pc); skipping");
        } else {
            planned += 1;
        }
    }
    if planned > 0 {
        idb.auto_wait();
        for n in 0..idb.idasgn_qty() {
            debug!(
                "FLIRT: signature #{n} state={} matched_modules={}",
                idb.idasgn_state(n),
                idb.idasgn_matches(n)
            );
        }
    }
    planned
}
