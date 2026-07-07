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

        // Native binary: use IDA
        idalib::force_batch_mode();

        let idb = IDB::open_with(path, true, self.save_idb)
            .map_err(|e| format!("Failed to open IDB for {}: {}", path.display(), e))?;

        let info = load_from_idb(&idb);
        let program = lift_from_idb(&idb, info);
        let features = self.extractor.extract_from_lifted(&program, &bytes);

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
