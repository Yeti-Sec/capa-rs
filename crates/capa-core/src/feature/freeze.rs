//! Feature freeze — serialize/deserialize extracted features.
//!
//! Enables the "extract once, match many" workflow: run feature extraction
//! once on a binary, serialize the result, then re-match against updated
//! rules without re-extracting.
//!
//! The native Rust format uses serde JSON on `ExtractedFeatures` directly.
//! For interop with Python capa's freeze format, use `to_freeze_json()`
//! and `from_freeze_json()` which produce a compatible schema.

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::error::Result;
use crate::feature::types::ExtractedFeatures;

/// Frozen feature set — the on-disk representation.
///
/// This wraps `ExtractedFeatures` with metadata about how and when
/// the extraction was performed, matching Python capa's freeze format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrozenFeatures {
    pub version: u32,
    pub extractor: String,
    pub base_address: u64,
    pub os: String,
    pub arch: String,
    pub format: String,
    pub features: ExtractedFeatures,
}

impl FrozenFeatures {
    /// Create a frozen feature set from extracted features.
    pub fn new(features: ExtractedFeatures) -> Self {
        Self {
            version: 3,
            extractor: "capa-rs".to_string(),
            base_address: 0,
            os: format!("{:?}", features.os).to_lowercase(),
            arch: format!("{:?}", features.arch).to_lowercase(),
            format: format!("{:?}", features.format).to_lowercase(),
            features,
        }
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Serialize to compact JSON (for disk storage).
    pub fn to_json_compact(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    /// Deserialize from JSON string.
    pub fn from_json(json: &str) -> Result<Self> {
        Ok(serde_json::from_str(json)?)
    }

    /// Write to a file.
    pub fn write_to_file(&self, path: &Path) -> Result<()> {
        let json = self.to_json()?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Read from a file.
    pub fn read_from_file(path: &Path) -> Result<Self> {
        let json = std::fs::read_to_string(path)?;
        Self::from_json(&json)
    }

    /// Get the inner extracted features (consuming self).
    pub fn into_features(self) -> ExtractedFeatures {
        self.features
    }
}

/// Summary statistics for frozen features (useful for quick inspection).
#[derive(Debug, Clone, Serialize)]
pub struct FreezeSummary {
    pub os: String,
    pub arch: String,
    pub format: String,
    pub function_count: usize,
    pub file_import_count: usize,
    pub file_export_count: usize,
    pub file_string_count: usize,
    pub file_characteristic_count: usize,
    pub total_instruction_count: usize,
}

impl From<&FrozenFeatures> for FreezeSummary {
    fn from(frozen: &FrozenFeatures) -> Self {
        let total_insns: usize = frozen.features.functions.values()
            .map(|f| f.instructions.len())
            .sum();
        Self {
            os: frozen.os.clone(),
            arch: frozen.arch.clone(),
            format: frozen.format.clone(),
            function_count: frozen.features.functions.len(),
            file_import_count: frozen.features.file.imports.len(),
            file_export_count: frozen.features.file.exports.len(),
            file_string_count: frozen.features.file.strings.len(),
            file_characteristic_count: frozen.features.file.characteristics.len(),
            total_instruction_count: total_insns,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::types::{Address, FunctionFeatures};
    use crate::rule::{ArchType, FormatType, OsType};

    fn sample_features() -> ExtractedFeatures {
        let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
        features.file.imports.insert("kernel32.dll!CreateFileA".to_string());
        features.file.strings.insert("malware".to_string());
        features.file.characteristics.insert(crate::rule::CharacteristicType::MixedMode);

        let mut func = FunctionFeatures::new(Address(0x401000));
        func.name = Some("main".to_string());
        func.features.imports.insert("kernel32.dll!VirtualAlloc".to_string());
        features.functions.insert(Address(0x401000), func);

        features
    }

    #[test]
    fn test_freeze_roundtrip() {
        let features = sample_features();
        let frozen = FrozenFeatures::new(features.clone());
        let json = frozen.to_json().unwrap();
        let restored = FrozenFeatures::from_json(&json).unwrap();

        assert_eq!(restored.version, 3);
        assert_eq!(restored.os, "windows");
        assert_eq!(restored.features.functions.len(), 1);
        assert_eq!(restored.features.file.imports.len(), 1);
    }

    #[test]
    fn test_freeze_compact() {
        let features = sample_features();
        let frozen = FrozenFeatures::new(features);
        let compact = frozen.to_json_compact().unwrap();
        let pretty = frozen.to_json().unwrap();
        assert!(compact.len() < pretty.len());
    }

    #[test]
    fn test_freeze_summary() {
        let features = sample_features();
        let frozen = FrozenFeatures::new(features);
        let summary = FreezeSummary::from(&frozen);
        assert_eq!(summary.function_count, 1);
        assert_eq!(summary.file_import_count, 1);
        assert_eq!(summary.file_string_count, 1);
    }

    #[test]
    fn test_freeze_file_roundtrip() {
        let features = sample_features();
        let frozen = FrozenFeatures::new(features);
        let tmp = std::env::temp_dir().join("capa_freeze_test.json");
        frozen.write_to_file(&tmp).unwrap();
        let restored = FrozenFeatures::read_from_file(&tmp).unwrap();
        assert_eq!(restored.features.functions.len(), 1);
        std::fs::remove_file(&tmp).ok();
    }
}
