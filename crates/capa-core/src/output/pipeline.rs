//! Pipeline output format
//!
//! Serializes analysis results as Protocol Buffers for integration
//! with downstream analysis pipelines and automation frameworks.
//!
//! Supports two modes:
//! - **Built-in schema**: Uses the bundled `capa.proto` (default)
//! - **User-defined schema**: Reads a `.proto` file at runtime via protoc
//!   and maps capa output onto the user's message structure by field name

use prost::Message;
use std::path::Path;

use super::json::CapaOutput;

/// Generated protobuf types from the bundled `proto/capa.proto`.
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/shared.models.capa.rs"));
}

fn parse_attack(s: &str) -> proto::Attack {
    let (body, id) = extract_bracketed_id(s);
    let parts: Vec<&str> = body.split("::").map(str::trim).collect();
    proto::Attack {
        parts: parts.iter().map(|p| p.to_string()).collect(),
        tactic: parts.first().unwrap_or(&"").to_string(),
        technique: parts.get(1).unwrap_or(&"").to_string(),
        subtechnique: parts.get(2).unwrap_or(&"").to_string(),
        id,
    }
}

fn parse_mbc(s: &str) -> proto::Mbc {
    let (body, id) = extract_bracketed_id(s);
    let parts: Vec<&str> = body.split("::").map(str::trim).collect();
    proto::Mbc {
        parts: parts.iter().map(|p| p.to_string()).collect(),
        objective: parts.first().unwrap_or(&"").to_string(),
        behavior: parts.get(1).unwrap_or(&"").to_string(),
        method: parts.get(2).unwrap_or(&"").to_string(),
        id,
    }
}

fn extract_bracketed_id(s: &str) -> (String, String) {
    if let (Some(start), Some(end)) = (s.rfind('['), s.rfind(']')) {
        if end > start {
            return (s[..start].trim().to_string(), s[start + 1..end].to_string());
        }
    }
    (s.to_string(), String::new())
}

impl CapaOutput {
    /// Serialize using the built-in proto schema.
    pub fn to_pipeline(&self) -> Vec<u8> {
        let rules = self.capabilities.iter().map(|cap| {
            proto::Rule {
                name: cap.name.clone(),
                namespace: cap.namespace.clone().unwrap_or_default(),
                attacks: cap.attack_raw.iter().map(|s| parse_attack(s)).collect(),
                mbcs: cap.mbc_raw.iter().map(|s| parse_mbc(s)).collect(),
                rule_content: String::new(),
                num_of_matches: cap.matches as u64,
            }
        }).collect();
        proto::CapaResult { rules }.encode_to_vec()
    }

    /// Serialize using a user-provided `.proto` schema file.
    ///
    /// Compiles the proto via protoc, then uses prost-reflect to dynamically
    /// construct messages by mapping capa output fields onto proto fields
    /// by name convention.
    pub fn to_pipeline_with_schema(
        &self,
        proto_path: &Path,
        message_name: Option<&str>,
    ) -> Result<Vec<u8>, PipelineError> {
        use prost_reflect::{DescriptorPool, DynamicMessage, Value};

        let desc_bytes = compile_proto(proto_path)?;
        let pool = DescriptorPool::decode(desc_bytes.as_slice())
            .map_err(|e| PipelineError::Schema(format!("descriptor decode: {e}")))?;

        let result_desc = match message_name {
            Some(name) => pool.get_message_by_name(name)
                .ok_or_else(|| PipelineError::Schema(
                    format!("message '{}' not found in schema", name)
                ))?,
            None => auto_detect_result(&pool)?,
        };

        let rules_field = result_desc.get_field_by_name("rules")
            .ok_or_else(|| PipelineError::Schema(
                "result message has no 'rules' field".to_string()
            ))?;

        let rule_desc = match rules_field.kind() {
            prost_reflect::Kind::Message(desc) => desc,
            _ => return Err(PipelineError::Schema(
                "'rules' field is not a message type".to_string()
            )),
        };

        let attack_desc = rule_desc.get_field_by_name("attacks")
            .and_then(|f| match f.kind() {
                prost_reflect::Kind::Message(d) => Some(d),
                _ => None,
            });

        let mbc_desc = rule_desc.get_field_by_name("mbcs")
            .and_then(|f| match f.kind() {
                prost_reflect::Kind::Message(d) => Some(d),
                _ => None,
            });

        let mut rule_values = Vec::new();
        for cap in &self.capabilities {
            let mut rule = DynamicMessage::new(rule_desc.clone());

            try_set_str(&rule_desc, &mut rule, "name", &cap.name);
            try_set_str(&rule_desc, &mut rule, "namespace",
                cap.namespace.as_deref().unwrap_or(""));

            if rule_desc.get_field_by_name("num_of_matches").is_some() {
                rule.set_field_by_name("num_of_matches", Value::U64(cap.matches as u64));
            } else if rule_desc.get_field_by_name("match_count").is_some() {
                rule.set_field_by_name("match_count", Value::U64(cap.matches as u64));
            }

            if let Some(ref ad) = attack_desc {
                let attacks: Vec<Value> = cap.attack_raw.iter().map(|s| {
                    let (body, id) = extract_bracketed_id(s);
                    let parts: Vec<&str> = body.split("::").map(str::trim).collect();
                    let mut a = DynamicMessage::new(ad.clone());
                    try_set_str(ad, &mut a, "tactic", parts.first().unwrap_or(&""));
                    try_set_str(ad, &mut a, "technique", parts.get(1).unwrap_or(&""));
                    try_set_str(ad, &mut a, "subtechnique", parts.get(2).unwrap_or(&""));
                    try_set_str(ad, &mut a, "id", &id);
                    try_set_parts(ad, &mut a, &parts);
                    Value::Message(a)
                }).collect();
                rule.set_field_by_name("attacks", Value::List(attacks));
            }

            if let Some(ref md) = mbc_desc {
                let mbcs: Vec<Value> = cap.mbc_raw.iter().map(|s| {
                    let (body, id) = extract_bracketed_id(s);
                    let parts: Vec<&str> = body.split("::").map(str::trim).collect();
                    let mut m = DynamicMessage::new(md.clone());
                    try_set_str(md, &mut m, "objective", parts.first().unwrap_or(&""));
                    try_set_str(md, &mut m, "behavior", parts.get(1).unwrap_or(&""));
                    try_set_str(md, &mut m, "method", parts.get(2).unwrap_or(&""));
                    try_set_str(md, &mut m, "id", &id);
                    try_set_parts(md, &mut m, &parts);
                    Value::Message(m)
                }).collect();
                rule.set_field_by_name("mbcs", Value::List(mbcs));
            }

            rule_values.push(Value::Message(rule));
        }

        let mut result = DynamicMessage::new(result_desc);
        result.set_field_by_name("rules", Value::List(rule_values));
        Ok(result.encode_to_vec())
    }
}

fn try_set_str(
    desc: &prost_reflect::MessageDescriptor,
    msg: &mut prost_reflect::DynamicMessage,
    field: &str,
    value: &str,
) {
    if desc.get_field_by_name(field).is_some() {
        msg.set_field_by_name(field, prost_reflect::Value::String(value.to_string()));
    }
}

fn try_set_parts(
    desc: &prost_reflect::MessageDescriptor,
    msg: &mut prost_reflect::DynamicMessage,
    parts: &[&str],
) {
    if desc.get_field_by_name("parts").is_some() {
        msg.set_field_by_name("parts",
            prost_reflect::Value::List(
                parts.iter().map(|p| prost_reflect::Value::String(p.to_string())).collect()
            ));
    }
}

fn auto_detect_result(
    pool: &prost_reflect::DescriptorPool,
) -> Result<prost_reflect::MessageDescriptor, PipelineError> {
    for msg in pool.all_messages() {
        let name = msg.name().to_lowercase();
        if msg.get_field_by_name("rules").is_some()
            && (name.contains("result") || name.contains("output") || name.contains("response"))
        {
            return Ok(msg);
        }
    }
    for msg in pool.all_messages() {
        if msg.get_field_by_name("rules").is_some() {
            return Ok(msg);
        }
    }
    Err(PipelineError::Schema(
        "no message with 'rules' field found — use --pipeline-message".to_string()
    ))
}

fn compile_proto(proto_path: &Path) -> Result<Vec<u8>, PipelineError> {
    let proto_dir = proto_path.parent().unwrap_or(Path::new("."));
    let tmp_desc = std::env::temp_dir().join("capa_pipeline_desc.bin");

    let protoc = std::env::var("PROTOC").unwrap_or_else(|_| "protoc".to_string());
    let status = std::process::Command::new(&protoc)
        .arg("--descriptor_set_out")
        .arg(&tmp_desc)
        .arg("--include_imports")
        .arg(format!("--proto_path={}", proto_dir.display()))
        .arg(proto_path)
        .status()
        .map_err(|e| PipelineError::Io(
            format!("protoc not found (set PROTOC env var): {e}")
        ))?;

    if !status.success() {
        return Err(PipelineError::Schema(
            format!("protoc failed on {}", proto_path.display())
        ));
    }

    let bytes = std::fs::read(&tmp_desc)
        .map_err(|e| PipelineError::Io(format!("read descriptor: {e}")))?;
    let _ = std::fs::remove_file(&tmp_desc);
    Ok(bytes)
}

#[derive(Debug)]
pub enum PipelineError {
    Io(String),
    Schema(String),
}

impl std::fmt::Display for PipelineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PipelineError::Io(s) => write!(f, "pipeline I/O error: {s}"),
            PipelineError::Schema(s) => write!(f, "pipeline schema error: {s}"),
        }
    }
}

impl std::error::Error for PipelineError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::json::Capability;
    use std::collections::HashMap;

    fn sample_output() -> CapaOutput {
        CapaOutput {
            matched_rules: 1,
            total_rules: 100,
            sample: None,
            capabilities: vec![Capability {
                name: "check for debugger via API".to_string(),
                namespace: Some("anti-analysis/anti-debugging".to_string()),
                matches: 3,
                locations: vec!["0x401000".to_string()],
                function_names: vec![],
                attack: Some(vec!["T1622".to_string()]),
                attack_raw: vec!["Discovery::Debugger Evasion [T1622]".to_string()],
                mbc_raw: vec!["Anti-Behavioral Analysis::Debugger Detection [B0001]".to_string()],
            }],
            mitre_attack: vec!["T1622".to_string()],
            namespaces: HashMap::new(),
            timing: None,
        }
    }

    #[test]
    fn test_builtin_roundtrip() {
        let output = sample_output();
        let bytes = output.to_pipeline();
        let decoded = proto::CapaResult::decode(bytes.as_slice()).expect("decode");
        assert_eq!(decoded.rules.len(), 1);
        assert_eq!(decoded.rules[0].name, "check for debugger via API");
        assert_eq!(decoded.rules[0].attacks[0].id, "T1622");
        assert_eq!(decoded.rules[0].mbcs[0].id, "B0001");
    }

    #[test]
    fn test_parse_attack_subtechnique() {
        let a = parse_attack("Defense Evasion::Impair Defenses::Disable or Modify Tools [T1562.001]");
        assert_eq!(a.id, "T1562.001");
        assert_eq!(a.parts.len(), 3);
    }

    #[test]
    fn test_parse_mbc() {
        let m = parse_mbc("Collection::Input Capture::Mouse Events [E1056.m01]");
        assert_eq!(m.objective, "Collection");
        assert_eq!(m.id, "E1056.m01");
    }
}
