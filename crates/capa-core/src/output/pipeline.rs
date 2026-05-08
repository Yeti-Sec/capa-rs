//! Pipeline output format
//!
//! Serializes analysis results as Protocol Buffers matching the
//! `shared.models.capa` schema for downstream pipeline consumption.

use prost::Message;

use super::json::CapaOutput;

/// Generated protobuf types from `proto/capa.proto`.
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/shared.models.capa.rs"));
}

/// Parse an ATT&CK string like `"Defense Evasion::Impair Defenses::Disable or Modify Tools [T1562.001]"`
/// into a structured `proto::Attack`.
fn parse_attack(s: &str) -> proto::Attack {
    let (body, id) = extract_bracketed_id(s);
    let parts: Vec<&str> = body.split("::").map(str::trim).collect();

    // ATT&CK hierarchy: Tactic::Technique[::Subtechnique]
    let tactic = parts.first().unwrap_or(&"").to_string();
    let technique = parts.get(1).unwrap_or(&"").to_string();
    let subtechnique = parts.get(2).unwrap_or(&"").to_string();

    proto::Attack {
        parts: parts.iter().map(|p| p.to_string()).collect(),
        tactic,
        technique,
        subtechnique,
        id,
    }
}

/// Parse an MBC string like `"Defense Evasion::Disable or Evade Security Tools::Modify Policy [F0004.005]"`
/// into a structured `proto::Mbc`.
fn parse_mbc(s: &str) -> proto::Mbc {
    let (body, id) = extract_bracketed_id(s);
    let parts: Vec<&str> = body.split("::").map(str::trim).collect();

    // MBC hierarchy: Objective::Behavior[::Method]
    let objective = parts.first().unwrap_or(&"").to_string();
    let behavior = parts.get(1).unwrap_or(&"").to_string();
    let method = parts.get(2).unwrap_or(&"").to_string();

    proto::Mbc {
        parts: parts.iter().map(|p| p.to_string()).collect(),
        objective,
        behavior,
        method,
        id,
    }
}

/// Extract the bracketed ID suffix and the body before it.
/// `"Tactic::Technique [T1059]"` -> `("Tactic::Technique", "T1059")`
fn extract_bracketed_id(s: &str) -> (String, String) {
    if let (Some(start), Some(end)) = (s.rfind('['), s.rfind(']')) {
        if end > start {
            let id = s[start + 1..end].to_string();
            let body = s[..start].trim().to_string();
            return (body, id);
        }
    }
    (s.to_string(), String::new())
}

impl CapaOutput {
    /// Serialize to protobuf wire format matching `shared.models.capa.CapaResult`.
    pub fn to_pipeline(&self) -> Vec<u8> {
        let result = self.to_capa_result();
        result.encode_to_vec()
    }

    fn to_capa_result(&self) -> proto::CapaResult {
        let rules = self
            .capabilities
            .iter()
            .map(|cap| {
                let attacks = cap.attack_raw.iter().map(|s| parse_attack(s)).collect();
                let mbcs = cap.mbc_raw.iter().map(|s| parse_mbc(s)).collect();

                proto::Rule {
                    name: cap.name.clone(),
                    namespace: cap.namespace.clone().unwrap_or_default(),
                    attacks,
                    mbcs,
                    rule_content: String::new(),
                    num_of_matches: cap.matches as u64,
                }
            })
            .collect();

        proto::CapaResult { rules }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::json::Capability;
    use std::collections::HashMap;

    #[test]
    fn test_parse_attack_with_subtechnique() {
        let a = parse_attack("Defense Evasion::Impair Defenses::Disable or Modify Tools [T1562.001]");
        assert_eq!(a.tactic, "Defense Evasion");
        assert_eq!(a.technique, "Impair Defenses");
        assert_eq!(a.subtechnique, "Disable or Modify Tools");
        assert_eq!(a.id, "T1562.001");
        assert_eq!(a.parts.len(), 3);
    }

    #[test]
    fn test_parse_attack_without_subtechnique() {
        let a = parse_attack("Execution::Command and Scripting Interpreter [T1059]");
        assert_eq!(a.tactic, "Execution");
        assert_eq!(a.technique, "Command and Scripting Interpreter");
        assert_eq!(a.subtechnique, "");
        assert_eq!(a.id, "T1059");
    }

    #[test]
    fn test_parse_mbc() {
        let m = parse_mbc("Defense Evasion::Disable or Evade Security Tools::Modify Policy [F0004.005]");
        assert_eq!(m.objective, "Defense Evasion");
        assert_eq!(m.behavior, "Disable or Evade Security Tools");
        assert_eq!(m.method, "Modify Policy");
        assert_eq!(m.id, "F0004.005");
    }

    #[test]
    fn test_parse_mbc_no_method() {
        let m = parse_mbc("Defense Evasion::Disable or Evade Security Tools [F0004]");
        assert_eq!(m.objective, "Defense Evasion");
        assert_eq!(m.behavior, "Disable or Evade Security Tools");
        assert_eq!(m.method, "");
        assert_eq!(m.id, "F0004");
    }

    #[test]
    fn test_roundtrip_pipeline_output() {
        let output = CapaOutput {
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
        };

        let bytes = output.to_pipeline();
        let decoded = proto::CapaResult::decode(bytes.as_slice()).expect("decode");

        assert_eq!(decoded.rules.len(), 1);
        let rule = &decoded.rules[0];
        assert_eq!(rule.name, "check for debugger via API");
        assert_eq!(rule.namespace, "anti-analysis/anti-debugging");
        assert_eq!(rule.num_of_matches, 3);

        assert_eq!(rule.attacks.len(), 1);
        assert_eq!(rule.attacks[0].tactic, "Discovery");
        assert_eq!(rule.attacks[0].technique, "Debugger Evasion");
        assert_eq!(rule.attacks[0].id, "T1622");

        assert_eq!(rule.mbcs.len(), 1);
        assert_eq!(rule.mbcs[0].objective, "Anti-Behavioral Analysis");
        assert_eq!(rule.mbcs[0].behavior, "Debugger Detection");
        assert_eq!(rule.mbcs[0].id, "B0001");
    }
}
