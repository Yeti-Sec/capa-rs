//! Feature type definitions
//!
//! Types representing extracted features from binaries.

use crate::rule::{ArchType, CharacteristicType, FormatType, OsType, PropertyAccess};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Address in the binary
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Address(pub u64);

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:x}", self.0)
    }
}

/// Collection of features at a specific scope
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FeatureSet {
    /// API calls
    pub apis: HashSet<String>,
    /// Imported functions
    pub imports: HashSet<String>,
    /// Exported functions
    pub exports: HashSet<String>,
    /// Function names (from FLIRT/.NET)
    pub function_names: HashSet<String>,
    /// String literals
    pub strings: HashSet<String>,
    /// Numeric constants
    pub numbers: HashSet<i64>,
    /// Offset values
    pub offsets: HashSet<i64>,
    /// Byte sequences found
    pub bytes_sequences: Vec<Vec<u8>>,
    /// Mnemonic counts
    pub mnemonics: HashMap<String, usize>,
    /// Operand values: (index, number, offset)
    pub operands: Vec<(usize, Option<i64>, Option<i64>)>,
    /// Characteristics
    pub characteristics: HashSet<CharacteristicType>,
    /// Characteristic occurrence counts (backs `count(characteristic(...))` rules)
    #[serde(default)]
    pub characteristic_counts: HashMap<CharacteristicType, usize>,
    /// Section names
    pub sections: HashSet<String>,
    /// .NET namespaces
    pub namespaces: HashSet<String>,
    /// .NET classes
    pub classes: HashSet<String>,
    /// .NET properties: (name, access)
    pub properties: Vec<(String, PropertyAccess)>,
    /// Basic block count (for function scope)
    pub basic_block_count: usize,
}

impl FeatureSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one occurrence of a characteristic in this scope.
    pub fn add_characteristic(&mut self, c: CharacteristicType) {
        self.characteristics.insert(c);
        *self.characteristic_counts.entry(c).or_insert(0) += 1;
    }

    /// Return the occurrence count of a characteristic in this scope.
    /// Falls back to `1` if `characteristics` contains `c` without an explicit
    /// count entry (e.g. legacy deserialized JSON or tests that inserted into `characteristics` directly).
    pub fn characteristic_count(&self, c: &CharacteristicType) -> usize {
        match self.characteristic_counts.get(c) {
            Some(&n) if n > 0 => n,
            Some(_) => 1,
            None if self.characteristics.contains(c) => 1,
            None => 0,
        }
    }

    /// Merge another feature set into this one (summing additive counts across disjoint child scopes).
    pub fn merge(&mut self, other: &FeatureSet) {
        self.apis.extend(other.apis.iter().cloned());
        self.imports.extend(other.imports.iter().cloned());
        self.exports.extend(other.exports.iter().cloned());
        self.function_names.extend(other.function_names.iter().cloned());
        self.strings.extend(other.strings.iter().cloned());
        self.numbers.extend(other.numbers.iter().cloned());
        self.offsets.extend(other.offsets.iter().cloned());
        self.bytes_sequences.extend(other.bytes_sequences.iter().cloned());
        for (k, v) in &other.mnemonics {
            *self.mnemonics.entry(k.clone()).or_insert(0) += v;
        }
        self.operands.extend(other.operands.iter().cloned());
        for (&c, &n) in &other.characteristic_counts {
            if n > 0 {
                self.characteristics.insert(c);
                *self.characteristic_counts.entry(c).or_insert(0) += n;
            }
        }
        for &c in &other.characteristics {
            self.characteristics.insert(c);
            if !other.characteristic_counts.contains_key(&c) {
                *self.characteristic_counts.entry(c).or_insert(0) += 1;
            }
        }
        self.sections.extend(other.sections.iter().cloned());
        self.namespaces.extend(other.namespaces.iter().cloned());
        self.classes.extend(other.classes.iter().cloned());
        self.properties.extend(other.properties.iter().cloned());
        self.basic_block_count += other.basic_block_count;
    }

    /// Roll up set-valued presence fields into a parent summary `FeatureSet` without
    /// duplicating additive child counts (`mnemonics`, `characteristic_counts`, `basic_block_count`)
    /// that `all_features()` already sums across child scopes.
    pub fn merge_sets_only(&mut self, other: &FeatureSet) {
        self.apis.extend(other.apis.iter().cloned());
        self.imports.extend(other.imports.iter().cloned());
        self.exports.extend(other.exports.iter().cloned());
        self.function_names.extend(other.function_names.iter().cloned());
        self.strings.extend(other.strings.iter().cloned());
        self.numbers.extend(other.numbers.iter().cloned());
        self.offsets.extend(other.offsets.iter().cloned());
        self.characteristics.extend(other.characteristics.iter().cloned());
        for &c in &other.characteristics {
            self.characteristic_counts.entry(c).or_insert(0);
        }
        self.sections.extend(other.sections.iter().cloned());
        self.namespaces.extend(other.namespaces.iter().cloned());
        self.classes.extend(other.classes.iter().cloned());
    }
}

/// Features for a single function
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionFeatures {
    /// Function address
    pub address: Address,
    /// Function name (if known)
    pub name: Option<String>,
    /// Function-level features
    pub features: FeatureSet,
    /// Basic block features by index
    pub basic_blocks: HashMap<usize, FeatureSet>,
    /// Instruction features by address
    pub instructions: HashMap<Address, FeatureSet>,
}

impl FunctionFeatures {
    pub fn new(address: Address) -> Self {
        Self {
            address,
            name: None,
            features: FeatureSet::new(),
            basic_blocks: HashMap::new(),
            instructions: HashMap::new(),
        }
    }

    /// Get all features merged (function + basic blocks + instructions)
    pub fn all_features(&self) -> FeatureSet {
        let mut merged = self.features.clone();
        for bb in self.basic_blocks.values() {
            merged.merge(bb);
        }
        for inst in self.instructions.values() {
            merged.merge(inst);
        }
        merged
    }
}

/// Complete extracted features from a binary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedFeatures {
    /// File-level features
    pub file: FeatureSet,
    /// Function features by address
    pub functions: HashMap<Address, FunctionFeatures>,
    /// Detected operating system
    pub os: OsType,
    /// Detected architecture
    pub arch: ArchType,
    /// Detected file format
    pub format: FormatType,
}

impl ExtractedFeatures {
    pub fn new(os: OsType, arch: ArchType, format: FormatType) -> Self {
        Self {
            file: FeatureSet::new(),
            functions: HashMap::new(),
            os,
            arch,
            format,
        }
    }

    /// Get all features merged across all scopes
    pub fn all_features(&self) -> FeatureSet {
        let mut merged = self.file.clone();
        for func in self.functions.values() {
            merged.merge(&func.all_features());
        }
        merged
    }
}
