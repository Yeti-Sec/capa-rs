//! Result Document — structured output format compatible with Python capa.
//!
//! This module defines the `ResultDocument` schema, which is the canonical
//! intermediate format consumed by all renderers (JSON, verbose, vverbose).
//! It mirrors Python's `capa/render/result_document.py` so that downstream
//! tools parsing capa JSON output get the same schema from both implementations.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::feature::Address;
use crate::matcher::RuleMatch;
use crate::rule::{ArchType, FormatType, OsType};

/// Top-level result document, matching Python's `ResultDocument`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultDocument {
    pub meta: Metadata,
    pub rules: HashMap<String, RuleMatches>,
}

/// Analysis metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    pub timestamp: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub argv: Option<Vec<String>>,
    pub sample: Sample,
    pub flavor: Flavor,
    pub analysis: Analysis,
}

/// Sample hash information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sample {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub path: String,
}

/// Analysis flavor (static or dynamic).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Flavor {
    Static,
    Dynamic,
}

/// Analysis details, unified for static analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Analysis {
    pub format: String,
    pub arch: String,
    pub os: String,
    pub extractor: String,
    pub rules: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_address: Option<AddressValue>,
    pub layout: StaticLayout,
    pub feature_counts: StaticFeatureCounts,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub library_functions: Vec<LibraryFunction>,
}

/// Address representation matching Python's `capa.features.freeze.Address`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressValue {
    #[serde(rename = "type")]
    pub addr_type: String,
    pub value: u64,
}

impl From<Address> for AddressValue {
    fn from(addr: Address) -> Self {
        if addr.0 == 0 {
            Self { addr_type: "no address".to_string(), value: 0 }
        } else {
            Self { addr_type: "absolute".to_string(), value: addr.0 }
        }
    }
}

/// Static layout — which functions/basic blocks matched.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticLayout {
    pub functions: Vec<FunctionLayout>,
}

/// Layout of a single matched function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionLayout {
    pub address: AddressValue,
    pub matched_basic_blocks: Vec<BasicBlockLayout>,
}

/// Layout of a single matched basic block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlockLayout {
    pub address: AddressValue,
}

/// Feature count summaries for static analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticFeatureCounts {
    pub file: usize,
    pub functions: Vec<FunctionFeatureCount>,
}

/// Feature count for a single function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionFeatureCount {
    pub address: AddressValue,
    pub count: usize,
}

/// A recognized library function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibraryFunction {
    pub address: AddressValue,
    pub name: String,
}

/// Per-rule match results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatches {
    pub meta: RuleMetadata,
    pub source: String,
    pub matches: Vec<(AddressValue, MatchNode)>,
}

/// Rule metadata for output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMetadata {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    pub authors: Vec<String>,
    pub scopes: ScopesOutput,
    #[serde(rename = "att&ck")]
    pub attack: Vec<AttackSpec>,
    pub mbc: Vec<MBCSpec>,
    pub references: Vec<String>,
    pub examples: Vec<String>,
    pub description: String,
    #[serde(rename = "lib")]
    pub lib: bool,
    #[serde(rename = "capa/subscope")]
    pub is_subscope_rule: bool,
}

/// Scopes output format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopesOutput {
    #[serde(rename = "static")]
    pub static_scope: String,
    pub dynamic: String,
}

/// MITRE ATT&CK spec, parsed from "Tactic::Technique::Subtechnique [ID]".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSpec {
    pub parts: Vec<String>,
    pub tactic: String,
    pub technique: String,
    pub subtechnique: String,
    pub id: String,
}

impl AttackSpec {
    pub fn from_str(s: &str) -> Self {
        let (parts, id) = parse_parts_id(s);
        Self {
            tactic: parts.first().cloned().unwrap_or_default(),
            technique: parts.get(1).cloned().unwrap_or_default(),
            subtechnique: parts.get(2).cloned().unwrap_or_default(),
            parts,
            id,
        }
    }
}

/// MBC spec, parsed from "Objective::Behavior::Method [ID]".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MBCSpec {
    pub parts: Vec<String>,
    pub objective: String,
    pub behavior: String,
    pub method: String,
    pub id: String,
}

impl MBCSpec {
    pub fn from_str(s: &str) -> Self {
        let (parts, id) = parse_parts_id(s);
        Self {
            objective: parts.first().cloned().unwrap_or_default(),
            behavior: parts.get(1).cloned().unwrap_or_default(),
            method: parts.get(2).cloned().unwrap_or_default(),
            parts,
            id,
        }
    }
}

/// Match tree node — represents how a rule matched.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchNode {
    pub success: bool,
    pub node: MatchNodeType,
    pub children: Vec<MatchNode>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub locations: Vec<AddressValue>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub captures: HashMap<String, Vec<AddressValue>>,
}

/// Discriminated node type in the match tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum MatchNodeType {
    #[serde(rename = "statement")]
    Statement { statement: StatementType },
    #[serde(rename = "feature")]
    Feature { feature: FeatureDescription },
}

/// Statement types in the match tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum StatementType {
    #[serde(rename = "and")]
    And { description: Option<String> },
    #[serde(rename = "or")]
    Or { description: Option<String> },
    #[serde(rename = "not")]
    Not { description: Option<String> },
    #[serde(rename = "optional")]
    Optional { description: Option<String> },
    #[serde(rename = "some")]
    Some { description: Option<String>, count: usize },
    #[serde(rename = "range")]
    Range { description: Option<String>, min: u64, max: u64 },
    #[serde(rename = "subscope")]
    Subscope { description: Option<String>, scope: String },
}

/// Feature description in the match tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureDescription {
    #[serde(rename = "type")]
    pub feature_type: String,
    #[serde(flatten)]
    pub details: HashMap<String, serde_json::Value>,
}

/// Parse "Tactic::Technique [ID]" into (parts, id).
fn parse_parts_id(s: &str) -> (Vec<String>, String) {
    let mut id = String::new();
    let mut parts: Vec<String> = s.split("::").map(|p| p.trim().to_string()).collect();
    if let Some(last) = parts.last_mut() {
        if let Some(bracket_start) = last.rfind('[') {
            if let Some(bracket_end) = last.rfind(']') {
                if bracket_end > bracket_start {
                    id = last[bracket_start + 1..bracket_end].to_string();
                    *last = last[..bracket_start].trim().to_string();
                }
            }
        }
    }
    (parts, id)
}

impl ResultDocument {
    /// Build a ResultDocument from match results and extracted features metadata.
    pub fn from_matches(
        matches: &[RuleMatch],
        _total_rules: usize,
        sample: Sample,
        os: OsType,
        arch: ArchType,
        format: FormatType,
        file_feature_count: usize,
        function_feature_counts: &[(Address, usize)],
        rule_paths: &[String],
    ) -> Self {
        let mut rule_matches = HashMap::new();

        for m in matches {
            if m.is_lib {
                continue;
            }

            let meta = RuleMetadata {
                name: m.name.clone(),
                namespace: m.namespace.clone(),
                authors: Vec::new(),
                scopes: ScopesOutput {
                    static_scope: "function".to_string(),
                    dynamic: "unsupported".to_string(),
                },
                attack: m.attack.iter().map(|s| AttackSpec::from_str(s)).collect(),
                mbc: m.mbc.iter().map(|s| MBCSpec::from_str(s)).collect(),
                references: Vec::new(),
                examples: Vec::new(),
                description: String::new(),
                lib: m.is_lib,
                is_subscope_rule: false,
            };

            let match_entries: Vec<(AddressValue, MatchNode)> = m.locations.iter().map(|addr| {
                (
                    AddressValue::from(*addr),
                    MatchNode {
                        success: true,
                        node: MatchNodeType::Statement {
                            statement: StatementType::And { description: None },
                        },
                        children: Vec::new(),
                        locations: vec![AddressValue::from(*addr)],
                        captures: HashMap::new(),
                    },
                )
            }).collect();

            rule_matches.insert(m.name.clone(), RuleMatches {
                meta,
                source: String::new(),
                matches: match_entries,
            });
        }

        let now = chrono::Utc::now().to_rfc3339();

        let layout = StaticLayout {
            functions: function_feature_counts.iter().map(|(addr, _)| {
                FunctionLayout {
                    address: AddressValue::from(*addr),
                    matched_basic_blocks: Vec::new(),
                }
            }).collect(),
        };

        let feature_counts = StaticFeatureCounts {
            file: file_feature_count,
            functions: function_feature_counts.iter().map(|(addr, count)| {
                FunctionFeatureCount {
                    address: AddressValue::from(*addr),
                    count: *count,
                }
            }).collect(),
        };

        ResultDocument {
            meta: Metadata {
                timestamp: now,
                version: env!("CARGO_PKG_VERSION").to_string(),
                argv: None,
                sample,
                flavor: Flavor::Static,
                analysis: Analysis {
                    format: format!("{:?}", format).to_lowercase(),
                    arch: format!("{:?}", arch).to_lowercase(),
                    os: format!("{:?}", os).to_lowercase(),
                    extractor: "capa-rs/goblin".to_string(),
                    rules: rule_paths.to_vec(),
                    base_address: None,
                    layout,
                    feature_counts,
                    library_functions: Vec::new(),
                },
            },
            rules: rule_matches,
        }
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn to_json_compact(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attack_spec_from_str() {
        let spec = AttackSpec::from_str("Execution::Command and Scripting Interpreter::Python [T1059.006]");
        assert_eq!(spec.tactic, "Execution");
        assert_eq!(spec.technique, "Command and Scripting Interpreter");
        assert_eq!(spec.subtechnique, "Python");
        assert_eq!(spec.id, "T1059.006");
    }

    #[test]
    fn test_mbc_spec_from_str() {
        let spec = MBCSpec::from_str("Collection::Input Capture::Mouse Events [E1056.m01]");
        assert_eq!(spec.objective, "Collection");
        assert_eq!(spec.behavior, "Input Capture");
        assert_eq!(spec.method, "Mouse Events");
        assert_eq!(spec.id, "E1056.m01");
    }

    #[test]
    fn test_parse_parts_id_no_id() {
        let (parts, id) = parse_parts_id("Execution::Command");
        assert_eq!(parts, vec!["Execution", "Command"]);
        assert_eq!(id, "");
    }

    #[test]
    fn test_result_document_serialization() {
        let doc = ResultDocument {
            meta: Metadata {
                timestamp: "2026-07-06T00:00:00Z".to_string(),
                version: "0.1.0".to_string(),
                argv: None,
                sample: Sample {
                    md5: "d41d8cd98f00b204e9800998ecf8427e".to_string(),
                    sha1: "da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string(),
                    sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
                    path: "test.exe".to_string(),
                },
                flavor: Flavor::Static,
                analysis: Analysis {
                    format: "pe".to_string(),
                    arch: "i386".to_string(),
                    os: "windows".to_string(),
                    extractor: "capa-rs/goblin".to_string(),
                    rules: vec!["rules/".to_string()],
                    base_address: Some(AddressValue { addr_type: "absolute".to_string(), value: 0x400000 }),
                    layout: StaticLayout { functions: vec![] },
                    feature_counts: StaticFeatureCounts { file: 0, functions: vec![] },
                    library_functions: vec![],
                },
            },
            rules: HashMap::new(),
        };
        let json = doc.to_json().unwrap();
        assert!(json.contains("\"version\": \"0.1.0\""));
        assert!(json.contains("\"flavor\": \"static\""));
    }
}
