//! Rule AST optimizer.
//!
//! Sorts children of boolean operators (And/Or/NOrMore/Optional) by
//! estimated evaluation cost so that cheap features are checked first.
//! This enables short-circuit evaluation in the matcher.
//!
//! Cost model (from Python capa optimizer.py):
//! - OS/Arch/Format features: cost 0 (most restrictive, checked first)
//! - Hash-lookup features (mnemonic, import, etc.): cost 1
//! - Scan features (substring, regex, bytes): cost 2
//! - Compound nodes: 1 + sum of children costs

use super::types::{Feature, FeatureNode};

/// Estimate the evaluation cost of a feature node.
pub fn node_cost(node: &FeatureNode) -> usize {
    match node {
        FeatureNode::Feature(f) => feature_cost(f),

        FeatureNode::Not(child) => 1 + node_cost(child),
        FeatureNode::Count(child, _) => 1 + node_cost(child),
        FeatureNode::Description(_, child) => node_cost(child),

        FeatureNode::And(children)
        | FeatureNode::Or(children)
        | FeatureNode::NOrMore(_, children)
        | FeatureNode::Optional(children)
        | FeatureNode::Instruction(children)
        | FeatureNode::BasicBlock(children)
        | FeatureNode::Function(children) => {
            1 + children.iter().map(node_cost).sum::<usize>()
        }

        FeatureNode::Match(_) => 1,
    }
}

fn feature_cost(feature: &Feature) -> usize {
    match feature {
        Feature::Characteristic(c) => {
            use super::types::CharacteristicType;
            match c {
                CharacteristicType::MixedMode
                | CharacteristicType::EmbeddedPe
                | CharacteristicType::ForwardedExport => 0,
                _ => 1,
            }
        }

        // Substring/regex/bytes require scanning — most expensive
        Feature::Substring(_) | Feature::Bytes(_) => 2,

        // Everything else is a hash lookup — moderate cost
        _ => 1,
    }
}

/// Optimize a single feature node tree in-place.
///
/// Sorts children of boolean nodes by cost (cheapest first).
pub fn optimize_node(node: &mut FeatureNode) {
    match node {
        FeatureNode::And(children)
        | FeatureNode::Or(children)
        | FeatureNode::NOrMore(_, children)
        | FeatureNode::Optional(children) => {
            for child in children.iter_mut() {
                optimize_node(child);
            }
            children.sort_by_key(|c| node_cost(c));
        }

        FeatureNode::Not(child)
        | FeatureNode::Count(child, _)
        | FeatureNode::Description(_, child) => {
            optimize_node(child);
        }

        FeatureNode::Instruction(children)
        | FeatureNode::BasicBlock(children)
        | FeatureNode::Function(children) => {
            for child in children.iter_mut() {
                optimize_node(child);
            }
            children.sort_by_key(|c| node_cost(c));
        }

        FeatureNode::Feature(_) | FeatureNode::Match(_) => {}
    }
}

/// Optimize all rules in a set.
///
/// Call this after parsing and before matching for best performance.
pub fn optimize_rules(rules: &mut [super::types::Rule]) {
    for rule in rules.iter_mut() {
        optimize_node(&mut rule.features);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::types::*;

    #[test]
    fn test_feature_cost_ordering() {
        assert!(feature_cost(&Feature::Characteristic(CharacteristicType::EmbeddedPe)) <
                feature_cost(&Feature::Mnemonic("mov".to_string())));
        assert!(feature_cost(&Feature::Mnemonic("mov".to_string())) <
                feature_cost(&Feature::Substring(StringMatcher::Exact("hello".to_string()))));
    }

    #[test]
    fn test_optimize_sorts_by_cost() {
        let mut node = FeatureNode::And(vec![
            FeatureNode::Feature(Feature::Substring(StringMatcher::Exact("expensive".to_string()))),
            FeatureNode::Feature(Feature::Mnemonic("mov".to_string())),
            FeatureNode::Feature(Feature::Characteristic(CharacteristicType::EmbeddedPe)),
        ]);

        optimize_node(&mut node);

        if let FeatureNode::And(children) = &node {
            // Characteristic (cost 0) should be first, then mnemonic (1), then substring (2)
            assert!(matches!(&children[0], FeatureNode::Feature(Feature::Characteristic(_))));
            assert!(matches!(&children[1], FeatureNode::Feature(Feature::Mnemonic(_))));
            assert!(matches!(&children[2], FeatureNode::Feature(Feature::Substring(_))));
        } else {
            panic!("expected And node");
        }
    }

    #[test]
    fn test_optimize_nested() {
        let mut node = FeatureNode::And(vec![
            FeatureNode::Or(vec![
                FeatureNode::Feature(Feature::Bytes(vec![Some(0x90)])),
                FeatureNode::Feature(Feature::Characteristic(CharacteristicType::MixedMode)),
            ]),
            FeatureNode::Feature(Feature::Characteristic(CharacteristicType::EmbeddedPe)),
        ]);

        optimize_node(&mut node);

        // The And should put Characteristic(Exe) first (cost 0)
        // and the Or second (cost 1+2+0=3)
        if let FeatureNode::And(children) = &node {
            assert!(matches!(&children[0], FeatureNode::Feature(Feature::Characteristic(_))));
            // The inner Or should also be sorted: MixedMode (0) before Bytes (2)
            if let FeatureNode::Or(inner) = &children[1] {
                assert!(matches!(&inner[0], FeatureNode::Feature(Feature::Characteristic(_))));
                assert!(matches!(&inner[1], FeatureNode::Feature(Feature::Bytes(_))));
            }
        }
    }

    #[test]
    fn test_node_cost() {
        let leaf = FeatureNode::Feature(Feature::Mnemonic("nop".to_string()));
        assert_eq!(node_cost(&leaf), 1);

        let and = FeatureNode::And(vec![leaf.clone(), leaf.clone()]);
        assert_eq!(node_cost(&and), 3); // 1 + 1 + 1
    }
}
