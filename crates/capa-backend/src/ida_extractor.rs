//! IDA Pro feature extractor — top-level entry point.
//!
//! Opens a binary via idalib, loads metadata, lifts to LiftedProgram,
//! and reuses BinaryExtractor::extract_from_lifted() for feature detection.
//! For .NET assemblies, delegates entirely to the goblin+dotscope path
//! since IDA's native disassembly misses managed metadata.

use std::fs;
use std::path::Path;

use log::debug;
use idalib::idb::IDB;

use crate::extractor::BinaryExtractor;
use crate::ida_lifter::lift_from_idb;
use crate::ida_loader::load_from_idb;
use capa_core::feature::{ExtractedFeatures, FeatureExtractor};

/// IDA-backed feature extractor.
///
/// Uses IDA Pro (via idalib-rs) for disassembly and analysis,
/// then feeds the result through the same feature detection pipeline.
/// .NET binaries are routed to the goblin+dotscope path automatically
/// since IDA adds no value for managed code analysis.
pub struct IdaExtractor {
    extractor: BinaryExtractor,
    save_idb: bool,
}

impl IdaExtractor {
    pub fn new() -> Self {
        Self {
            extractor: BinaryExtractor::new(),
            save_idb: false,
        }
    }

    pub fn with_save_idb(mut self, save: bool) -> Self {
        self.save_idb = save;
        self
    }

    /// Extract features from a binary file.
    ///
    /// For .NET assemblies (detected via PE CLR header), bypasses IDA
    /// entirely and uses the goblin+dotscope path which properly handles
    /// managed metadata, user strings, and API resolution.
    ///
    /// For native binaries, uses IDA for disassembly and analysis.
    pub fn extract_file(&self, path: &Path) -> Result<ExtractedFeatures, Box<dyn std::error::Error + Send + Sync>> {
        let bytes = fs::read(path)
            .map_err(|e| format!("Failed to read binary {}: {}", path.display(), e))?;

        // .NET binaries: skip IDA, use goblin+dotscope directly.
        // IDA adds no value for managed code — it disassembles the CLR stub
        // and misses all managed strings, imports, types, and API calls.
        if has_clr_header(&bytes) {
            debug!("Detected .NET assembly, using goblin+dotscope instead of IDA");
            return self.extractor.extract(&bytes)
                .map_err(|e| e.to_string().into());
        }

        // Native binary: use IDA (disable PDB symbol server network lookups via `-Opdb:off`
        // and empty `_NT_SYMBOL_PATH` so PEs with CodeView `RSDS` debug entries do not stall
        // ~135s on `tcp_syn_retries` inside sandboxed containers).
        idalib::force_batch_mode();
        if std::env::var_os("_NT_SYMBOL_PATH").is_none() {
            std::env::set_var("_NT_SYMBOL_PATH", "");
        }

        let idb = IDB::open_with_args(path, true, self.save_idb, &["-Opdb:off"])
            .map_err(|e| format!("Failed to open IDB for {}: {}", path.display(), e))?;

        let mut info = load_from_idb(&idb);

        // Augment `info.imports` with exact on-disk PE `.rdata`/`.idata` IAT slot VAs
        // (`image_base + imp.offset` from goblin `pe.imports`, since IDA relocates imports
        // into a synthetic `extern` segment) PLUS PE Delay-Import Directory (`DataDirectory[13]`)
        // entries. This guarantees `E8 -> FF 25 [IAT_VA]` thunks always match `imports_by_addr`.
        if let Ok(goblin::Object::PE(pe)) = goblin::Object::parse(&bytes) {
            let mut existing: std::collections::HashSet<(String, u64)> = info
                .imports
                .iter()
                .map(|i| (i.name.clone(), i.address))
                .collect();
            let image_base = pe.image_base as u64;
            for imp in &pe.imports {
                let iat_va = image_base.wrapping_add(imp.offset as u64);
                let name = imp.name.to_string();
                if existing.insert((name.clone(), iat_va)) {
                    info.imports.push(crate::loader::ImportInfo {
                        name,
                        module: Some(imp.dll.to_lowercase()),
                        address: iat_va,
                    });
                }
            }
            for di in crate::loader::extract_pe_delay_imports(&pe, &bytes) {
                if existing.insert((di.name.clone(), di.address)) {
                    info.imports.push(di);
                }
            }
        }

        let program = lift_from_idb(&idb, info, &bytes);
        let mut features = self.extractor.extract_from_lifted(&program, &bytes);

        // Augment file-scope strings with raw whole-image ASCII/UTF-16 strings AFTER
        // function/BB lifting so accidental 4-byte ASCII sequences inside `.text` code
        // never pollute `strings_at` pointer lookups (avoiding false function-scope
        // hits such as `.boto`), while keeping file-scope string coverage complete.
        for s in crate::strings::extract_ascii_strings(&bytes, 4) {
            features.file.strings.insert(s.value);
        }
        for s in crate::strings::extract_unicode_strings(&bytes, 4) {
            features.file.strings.insert(s.value);
        }

        Ok(features)
    }
}

/// Check if raw PE bytes contain a CLR runtime header (data directory index 14).
fn has_clr_header(bytes: &[u8]) -> bool {
    use goblin::pe::PE;
    if let Ok(pe) = PE::parse(bytes) {
        if let Some(opt) = pe.header.optional_header {
            if let Some(clr) = opt.data_directories.get_clr_runtime_header() {
                return clr.virtual_address != 0 && clr.size != 0;
            }
        }
    }
    false
}
