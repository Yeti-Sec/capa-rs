//! Core matching engine
//!
//! Evaluates rules against extracted features with parallel processing
//! and optimized string matching.

use dashmap::DashMap;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::feature::{Address, ExtractedFeatures, FeatureSet, FunctionFeatures};
use crate::rule::{
    ArchType, CountConstraint, Feature, FeatureNode, FormatType, OsType,
    Rule, StaticScope, StringMatcher,
};

/// Match result for a single rule
#[derive(Debug, Clone)]
pub struct RuleMatch {
    /// Rule name
    pub name: String,
    /// Rule namespace
    pub namespace: Option<String>,
    /// Number of locations where rule matched
    pub match_count: usize,
    /// Locations where rule matched (addresses)
    pub locations: Vec<Address>,
    /// Function names where rule matched (for .NET and other symbolic binaries)
    pub function_names: Vec<String>,
    /// ATT&CK technique IDs
    pub attack: Vec<String>,
    /// MBC IDs
    pub mbc: Vec<String>,
    /// Is this a library rule?
    pub is_lib: bool,
}


/// Rule matching engine with parallel processing
pub struct MatchEngine {
    rules: Vec<Rule>,
    rule_index: HashMap<String, usize>,
}

type MatchCache = Arc<DashMap<String, Option<RuleMatch>>>;

struct PreparedFeatures<'a> {
    raw: &'a ExtractedFeatures,
    file_all: FeatureSet,
    func_all: HashMap<Address, FeatureSet>,
    bb_all: HashMap<(Address, usize), FeatureSet>,
}

impl<'a> PreparedFeatures<'a> {
    fn new(raw: &'a ExtractedFeatures) -> Self {
        let mut func_all = HashMap::with_capacity(raw.functions.len());
        let mut bb_all = HashMap::new();
        let mut file_all = raw.file.clone();

        for (&addr, func) in &raw.functions {
            let ff = func.all_features();
            file_all.merge(&ff);
            func_all.insert(addr, ff);
            for &bb_idx in func.basic_blocks.keys() {
                bb_all.insert((addr, bb_idx), func.basic_block_all_features(bb_idx));
            }
        }

        Self {
            raw,
            file_all,
            func_all,
            bb_all,
        }
    }

    #[inline]
    fn func_features<'b>(&'b self, func: &'b FunctionFeatures) -> &'b FeatureSet {
        self.func_all.get(&func.address).unwrap_or(&func.features)
    }

    #[inline]
    fn bb_features<'b>(&'b self, func: &'b FunctionFeatures, bb_idx: usize) -> &'b FeatureSet {
        self.bb_all
            .get(&(func.address, bb_idx))
            .or_else(|| func.basic_blocks.get(&bb_idx))
            .unwrap_or(&func.features)
    }
}

#[derive(Clone, Copy)]
enum ScopeContext<'a> {
    File,
    Function(&'a FunctionFeatures),
    BasicBlock(&'a FunctionFeatures, usize),
    Instruction(&'a FunctionFeatures, Option<Address>),
}

impl MatchEngine {
    /// Create a new match engine with the given rules
    pub fn new(rules: Vec<Rule>) -> Self {
        let mut rule_index = HashMap::new();
        for (i, rule) in rules.iter().enumerate() {
            rule_index.insert(rule.meta.name.clone(), i);
        }

        Self {
            rules,
            rule_index,
        }
    }

    /// Get total number of rules
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Match all rules against extracted features (parallel)
    pub fn match_all(&self, features: &ExtractedFeatures) -> Vec<RuleMatch> {
        let prep = PreparedFeatures::new(features);
        let cache: MatchCache = Arc::new(DashMap::new());

        // Process rules in parallel
        self.rules
            .par_iter()
            .filter_map(|rule| {
                self.match_rule(rule, &prep, &cache, 0)
            })
            .collect()
    }

    /// Match all rules sequentially (for debugging/testing)
    pub fn match_all_sequential(&self, features: &ExtractedFeatures) -> Vec<RuleMatch> {
        let prep = PreparedFeatures::new(features);
        let cache: MatchCache = Arc::new(DashMap::new());

        self.rules
            .iter()
            .filter_map(|rule| {
                self.match_rule(rule, &prep, &cache, 0)
            })
            .collect()
    }

    /// Match a single rule by name
    pub fn match_rule_by_name(
        &self,
        name: &str,
        features: &ExtractedFeatures,
    ) -> Option<RuleMatch> {
        let prep = PreparedFeatures::new(features);
        let cache: MatchCache = Arc::new(DashMap::new());
        let idx = self.rule_index.get(name)?;
        let rule = &self.rules[*idx];
        self.match_rule(rule, &prep, &cache, 0)
    }

    fn match_rule(
        &self,
        rule: &Rule,
        prep: &PreparedFeatures<'_>,
        cache: &MatchCache,
        depth: usize,
    ) -> Option<RuleMatch> {
        if depth > 64 {
            return None;
        }

        // Check cache first (drop DashMap guard immediately before any recursive work)
        let cached = cache.get(&rule.meta.name).map(|r| r.value().clone());
        if let Some(res) = cached {
            return res;
        }

        let features = prep.raw;
        let scope = rule.meta.scopes.static_scope;
        let mut locations = Vec::new();
        let mut function_names = Vec::new();

        let matched = match scope {
            StaticScope::File => {
                if self.evaluate_node(&rule.features, &prep.file_all, prep, ScopeContext::File, cache, depth) {
                    // File-scope matched - now find which functions contributed
                    // by checking which functions have features that match the rule
                    for (addr, func) in &features.functions {
                        let func_features = prep.func_features(func);
                        if self.evaluate_node(&rule.features, func_features, prep, ScopeContext::Function(func), cache, depth) {
                            locations.push(*addr);
                            for name in &func_features.function_names {
                                if !function_names.contains(name) {
                                    function_names.push(name.clone());
                                }
                            }
                        }
                    }
                    if locations.is_empty() {
                        locations.push(Address(0));
                    }
                    true
                } else {
                    false
                }
            }
            StaticScope::Function => {
                for (addr, func) in &features.functions {
                    let func_features = prep.func_features(func);
                    if self.evaluate_node(&rule.features, func_features, prep, ScopeContext::Function(func), cache, depth) {
                        locations.push(*addr);
                        for name in &func_features.function_names {
                            if !function_names.contains(name) {
                                function_names.push(name.clone());
                            }
                        }
                    }
                }
                !locations.is_empty()
            }
            StaticScope::BasicBlock => {
                for (func_addr, func) in &features.functions {
                    for &bb_idx in func.basic_blocks.keys() {
                        let bb_features = prep.bb_features(func, bb_idx);
                        if self.evaluate_node(&rule.features, bb_features, prep, ScopeContext::BasicBlock(func, bb_idx), cache, depth) {
                            let bb_addr = func
                                .basic_block_addresses
                                .get(&bb_idx)
                                .copied()
                                .unwrap_or_else(|| Address(func_addr.0 + bb_idx as u64));
                            locations.push(bb_addr);
                        }
                    }
                }
                !locations.is_empty()
            }
            StaticScope::Instruction => {
                for func in features.functions.values() {
                    for (addr, inst) in &func.instructions {
                        if self.evaluate_node(&rule.features, inst, prep, ScopeContext::Instruction(func, Some(*addr)), cache, depth) {
                            locations.push(*addr);
                        }
                    }
                }
                !locations.is_empty()
            }
            StaticScope::Unsupported => false,
        };

        let result = if matched {
            Some(RuleMatch {
                name: rule.meta.name.clone(),
                namespace: rule.meta.namespace.clone(),
                match_count: locations.len(),
                locations,
                function_names,
                attack: rule.meta.attack.clone(),
                mbc: rule.meta.mbc.clone(),
                is_lib: rule.meta.is_lib,
            })
        } else {
            None
        };

        cache.insert(rule.meta.name.clone(), result.clone());
        result
    }

    fn evaluate_node(
        &self,
        node: &FeatureNode,
        scope_features: &FeatureSet,
        prep: &PreparedFeatures<'_>,
        ctx: ScopeContext<'_>,
        cache: &MatchCache,
        depth: usize,
    ) -> bool {
        let all_features = prep.raw;
        match node {
            FeatureNode::And(children) => {
                children.iter().all(|c| self.evaluate_node(c, scope_features, prep, ctx, cache, depth))
            }

            FeatureNode::Or(children) => children
                .iter()
                .any(|c| self.evaluate_node(c, scope_features, prep, ctx, cache, depth)),

            FeatureNode::Not(child) => {
                !self.evaluate_node(child, scope_features, prep, ctx, cache, depth)
            }

            FeatureNode::NOrMore(n, children) => {
                let count = children
                    .iter()
                    .filter(|c| self.evaluate_node(c, scope_features, prep, ctx, cache, depth))
                    .count();
                count >= *n
            }

            FeatureNode::Optional(_) => true,

            FeatureNode::Count(child, constraint) => {
                let count = match Self::unwrap_match(child) {
                    Some(rule_name) => self.count_rule_matches_in_context(rule_name, ctx, prep, cache, depth),
                    None => self.count_feature(child, scope_features),
                };
                match constraint {
                    CountConstraint::Exact(n) => count == *n,
                    CountConstraint::OrMore(n) => count >= *n,
                    CountConstraint::OrFewer(n) => count <= *n,
                    CountConstraint::Range(min, max) => count >= *min && count <= *max,
                }
            }

            FeatureNode::Feature(feature) => self.match_feature(feature, scope_features, all_features),

            FeatureNode::Description(_, child) => {
                self.evaluate_node(child, scope_features, prep, ctx, cache, depth)
            }

            FeatureNode::Match(rule_name) => {
                self.count_rule_matches_in_context(rule_name, ctx, prep, cache, depth) > 0
            }

            FeatureNode::Instruction(children) => {
                match ctx {
                    ScopeContext::File => {
                        all_features.functions.values().any(|func| {
                            if func.is_synthetic_func_only() {
                                let ff = prep.func_features(func);
                                children.iter().all(|c| self.evaluate_node(c, ff, prep, ScopeContext::Instruction(func, None), cache, depth))
                            } else {
                                func.instructions.iter().any(|(&addr, inst)| {
                                    children.iter().all(|c| self.evaluate_node(c, inst, prep, ScopeContext::Instruction(func, Some(addr)), cache, depth))
                                })
                            }
                        })
                    }
                    ScopeContext::Function(func) => {
                        if func.is_synthetic_func_only() {
                            children.iter().all(|c| self.evaluate_node(c, scope_features, prep, ScopeContext::Instruction(func, None), cache, depth))
                        } else {
                            func.instructions.iter().any(|(&addr, inst)| {
                                children.iter().all(|c| self.evaluate_node(c, inst, prep, ScopeContext::Instruction(func, Some(addr)), cache, depth))
                            })
                        }
                    }
                    ScopeContext::BasicBlock(func, bb_idx) => {
                        if let Some(addrs) = func.basic_block_instructions.get(&bb_idx) {
                            addrs.iter().any(|addr| {
                                func.instructions.get(addr).is_some_and(|inst| {
                                    children.iter().all(|c| self.evaluate_node(c, inst, prep, ScopeContext::Instruction(func, Some(*addr)), cache, depth))
                                })
                            })
                        } else if !func.instructions.is_empty() {
                            func.instructions.iter().any(|(&addr, inst)| {
                                children.iter().all(|c| self.evaluate_node(c, inst, prep, ScopeContext::Instruction(func, Some(addr)), cache, depth))
                            })
                        } else {
                            children.iter().all(|c| self.evaluate_node(c, scope_features, prep, ScopeContext::Instruction(func, None), cache, depth))
                        }
                    }
                    ScopeContext::Instruction(_, _) => {
                        children.iter().all(|c| self.evaluate_node(c, scope_features, prep, ctx, cache, depth))
                    }
                }
            }

            FeatureNode::BasicBlock(children) => {
                match ctx {
                    ScopeContext::File => {
                        all_features.functions.values().any(|func| {
                            if func.basic_blocks.is_empty() {
                                if func.is_synthetic_func_only() {
                                    let ff = prep.func_features(func);
                                    children.iter().all(|c| self.evaluate_node(c, ff, prep, ScopeContext::Function(func), cache, depth))
                                } else {
                                    false
                                }
                            } else {
                                func.basic_blocks.keys().any(|&bb_idx| {
                                    let bbf = prep.bb_features(func, bb_idx);
                                    children.iter().all(|c| self.evaluate_node(c, bbf, prep, ScopeContext::BasicBlock(func, bb_idx), cache, depth))
                                })
                            }
                        })
                    }
                    ScopeContext::Function(func) => {
                        if func.basic_blocks.is_empty() {
                            if func.is_synthetic_func_only() {
                                children.iter().all(|c| self.evaluate_node(c, scope_features, prep, ctx, cache, depth))
                            } else {
                                false
                            }
                        } else {
                            func.basic_blocks.keys().any(|&bb_idx| {
                                let bbf = prep.bb_features(func, bb_idx);
                                children.iter().all(|c| self.evaluate_node(c, bbf, prep, ScopeContext::BasicBlock(func, bb_idx), cache, depth))
                            })
                        }
                    }
                    ScopeContext::BasicBlock(_, _) | ScopeContext::Instruction(_, _) => {
                        children.iter().all(|c| self.evaluate_node(c, scope_features, prep, ctx, cache, depth))
                    }
                }
            }

            FeatureNode::Function(children) => {
                match ctx {
                    ScopeContext::File => {
                        all_features.functions.values().any(|func| {
                            let ff = prep.func_features(func);
                            children.iter().all(|c| self.evaluate_node(c, ff, prep, ScopeContext::Function(func), cache, depth))
                        })
                    }
                    ScopeContext::Function(_) | ScopeContext::BasicBlock(_, _) | ScopeContext::Instruction(_, _) => {
                        children.iter().all(|c| self.evaluate_node(c, scope_features, prep, ctx, cache, depth))
                    }
                }
            }
        }
    }

    fn count_feature(&self, node: &FeatureNode, scope_features: &FeatureSet) -> usize {
        match node {
            FeatureNode::Feature(Feature::Api(matcher)) => {
                count_api_matches(matcher, &scope_features.apis)
            }
            FeatureNode::Feature(Feature::String(matcher)) => {
                count_string_matches(matcher, &scope_features.strings)
            }
            FeatureNode::Feature(Feature::Import(matcher)) => {
                count_string_matches(matcher, &scope_features.imports)
            }
            FeatureNode::Feature(Feature::Mnemonic(mnem)) => {
                *scope_features.mnemonics.get(mnem).unwrap_or(&0)
            }
            FeatureNode::Feature(Feature::Number(num)) => {
                scope_features.number_count(num.value)
            }
            FeatureNode::Feature(Feature::Characteristic(char_type)) => {
                scope_features.characteristic_count(char_type)
            }
            FeatureNode::Feature(Feature::Offset(offset_matcher)) => {
                scope_features.offset_count(offset_matcher.value)
            }
            FeatureNode::Feature(Feature::Export(matcher)) => {
                count_string_matches(matcher, &scope_features.exports)
            }
            FeatureNode::Feature(Feature::Section(matcher)) => {
                count_string_matches(matcher, &scope_features.sections)
            }
            FeatureNode::Feature(Feature::Substring(matcher)) => {
                // Count substring matches across all strings
                match matcher {
                    StringMatcher::Exact(pattern) => {
                        let p = pattern.to_lowercase();
                        scope_features.strings.iter().filter(|s| s.to_lowercase().contains(&p)).count()
                    }
                    StringMatcher::Regex(compiled) => {
                        scope_features.strings.iter().filter(|s| compiled.is_match(s)).count()
                    }
                }
            }
            FeatureNode::Feature(Feature::BasicBlockFeature) => {
                scope_features.basic_block_count
            }
            FeatureNode::Feature(Feature::Property(prop)) => {
                scope_features
                    .properties
                    .iter()
                    .filter(|(name, access)| {
                        name == &prop.name
                            && (prop.access == crate::rule::PropertyAccess::Any || *access == prop.access)
                    })
                    .count()
            }
            FeatureNode::Feature(Feature::Class(matcher)) => {
                count_string_matches(matcher, &scope_features.classes)
            }
            FeatureNode::Feature(Feature::Namespace(matcher)) => {
                count_string_matches(matcher, &scope_features.namespaces)
            }
            FeatureNode::Feature(Feature::FunctionName(matcher)) => {
                count_string_matches(matcher, &scope_features.function_names)
            }
            _ => 0,
        }
    }

    /// Unwrap a `match:` node (possibly Description-wrapped) to its target name.
    fn unwrap_match(node: &FeatureNode) -> Option<&str> {
        match node {
            FeatureNode::Match(name) => Some(name.as_str()),
            FeatureNode::Description(_, inner) => Self::unwrap_match(inner),
            _ => None,
        }
    }

    /// Count matches of a single rule within the active `ScopeContext`.
    /// First consults the memoized program-global `match_rule` cache (O(1) fast-reject
    /// when a rule does not match anywhere in the binary), then filters matches to
    /// the current function, basic block, or instruction scope.
    fn count_single_rule_in_context(
        &self,
        target: &Rule,
        ctx: ScopeContext<'_>,
        prep: &PreparedFeatures<'_>,
        cache: &MatchCache,
        depth: usize,
    ) -> usize {
        let Some(m) = self.match_rule(target, prep, cache, depth + 1) else {
            return 0;
        };

        let target_scope = target.meta.scopes.static_scope;
        match (target_scope, ctx) {
            // File-scope target matched -> holds in every enclosing/nested scope.
            (StaticScope::File, _) => m.locations.len().max(1),

            // Evaluating at file scope -> count all match locations across the binary.
            (_, ScopeContext::File) => m.locations.len(),

            // Function-scope target inside a Function / BasicBlock / Instruction context:
            // must have matched on THIS function (`func.address`).
            (
                StaticScope::Function,
                ScopeContext::Function(func)
                | ScopeContext::BasicBlock(func, _)
                | ScopeContext::Instruction(func, _),
            ) => usize::from(m.locations.contains(&func.address)),

            // BasicBlock-scope target inside a Function context: count matching blocks in `func`.
            (StaticScope::BasicBlock, ScopeContext::Function(func)) => {
                if func.basic_blocks.is_empty() {
                    if func.is_synthetic_func_only() {
                        let ff = prep.func_features(func);
                        usize::from(self.evaluate_node(&target.features, ff, prep, ctx, cache, depth + 1))
                    } else {
                        0
                    }
                } else if !func.basic_block_addresses.is_empty() {
                    func.basic_block_addresses
                        .values()
                        .filter(|bb_addr| m.locations.contains(bb_addr))
                        .count()
                } else {
                    func.basic_blocks
                        .keys()
                        .filter(|&&bb_idx| {
                            let bbf = prep.bb_features(func, bb_idx);
                            self.evaluate_node(
                                &target.features,
                                bbf,
                                prep,
                                ScopeContext::BasicBlock(func, bb_idx),
                                cache,
                                depth + 1,
                            )
                        })
                        .count()
                }
            }

            // BasicBlock-scope target inside a BasicBlock context (e.g. `check for PEB BeingDebugged flag`
            // requiring `match: PEB access` in the SAME basic block): O(1) lookup via `basic_block_addresses`
            // when available, otherwise zero-copy check on precomputed `prep.bb_features`.
            (StaticScope::BasicBlock, ScopeContext::BasicBlock(func, bb_idx)) => {
                if let Some(bb_addr) = func.basic_block_addresses.get(&bb_idx) {
                    usize::from(m.locations.contains(bb_addr))
                } else {
                    let bbf = prep.bb_features(func, bb_idx);
                    usize::from(self.evaluate_node(
                        &target.features,
                        bbf,
                        prep,
                        ScopeContext::BasicBlock(func, bb_idx),
                        cache,
                        depth + 1,
                    ))
                }
            }

            // BasicBlock-scope target inside an Instruction context: check enclosing block if known.
            (StaticScope::BasicBlock, ScopeContext::Instruction(func, inst_addr)) => {
                if let Some(addr) = inst_addr {
                    if let Some((&bb_idx, _)) = func
                        .basic_block_instructions
                        .iter()
                        .find(|(_, addrs)| addrs.contains(&addr))
                    {
                        if let Some(bb_addr) = func.basic_block_addresses.get(&bb_idx) {
                            return usize::from(m.locations.contains(bb_addr));
                        }
                        let bbf = prep.bb_features(func, bb_idx);
                        return usize::from(self.evaluate_node(
                            &target.features,
                            bbf,
                            prep,
                            ScopeContext::BasicBlock(func, bb_idx),
                            cache,
                            depth + 1,
                        ));
                    }
                }
                0
            }

            // Instruction-scope target inside a Function context: count matching instructions in `func`.
            (StaticScope::Instruction, ScopeContext::Function(func)) => {
                if func.is_synthetic_func_only() {
                    let ff = prep.func_features(func);
                    usize::from(self.evaluate_node(&target.features, ff, prep, ctx, cache, depth + 1))
                } else {
                    m.locations
                        .iter()
                        .filter(|a| func.instructions.contains_key(a))
                        .count()
                }
            }

            // Instruction-scope target inside a BasicBlock context: count matching instructions in `bb_idx`.
            (StaticScope::Instruction, ScopeContext::BasicBlock(func, bb_idx)) => {
                if let Some(addrs) = func.basic_block_instructions.get(&bb_idx) {
                    addrs.iter().filter(|a| m.locations.contains(a)).count()
                } else {
                    m.locations
                        .iter()
                        .filter(|a| func.instructions.contains_key(a))
                        .count()
                }
            }

            // Instruction-scope target inside an Instruction context: must match THIS instruction.
            (StaticScope::Instruction, ScopeContext::Instruction(func, inst_addr)) => {
                match inst_addr {
                    Some(addr) => usize::from(m.locations.contains(&addr)),
                    None if func.is_synthetic_func_only() => {
                        let ff = prep.func_features(func);
                        usize::from(self.evaluate_node(&target.features, ff, prep, ctx, cache, depth + 1))
                    }
                    None => 0,
                }
            }

            (StaticScope::Unsupported, _) => 0,
        }
    }

    /// Count scoped matches of a referenced rule (by exact name, or any rule in a namespace).
    fn count_rule_matches_in_context(
        &self,
        rule_name: &str,
        ctx: ScopeContext<'_>,
        prep: &PreparedFeatures<'_>,
        cache: &MatchCache,
        depth: usize,
    ) -> usize {
        if let Some(&idx) = self.rule_index.get(rule_name) {
            return self.count_single_rule_in_context(&self.rules[idx], ctx, prep, cache, depth);
        }
        let prefix = format!("{}/", rule_name);
        self.rules
            .iter()
            .filter(|r| {
                r.meta
                    .namespace
                    .as_ref()
                    .map_or(false, |ns| ns == rule_name || ns.starts_with(&prefix))
            })
            .map(|r| self.count_single_rule_in_context(r, ctx, prep, cache, depth))
            .sum()
    }

    fn match_feature(
        &self,
        feature: &Feature,
        scope_features: &FeatureSet,
        all_features: &ExtractedFeatures,
    ) -> bool {
        match feature {
            Feature::Api(matcher) => match_api(matcher, &scope_features.apis),
            Feature::Import(matcher) => match_string(matcher, &scope_features.imports),
            Feature::Export(matcher) => match_string(matcher, &scope_features.exports),
            Feature::FunctionName(matcher) => match_string(matcher, &scope_features.function_names),
            Feature::String(matcher) => match_string(matcher, &scope_features.strings),
            Feature::Substring(matcher) => match_substring(matcher, &scope_features.strings),
            Feature::Section(matcher) => match_string(matcher, &scope_features.sections),
            Feature::Namespace(matcher) => match_string(matcher, &scope_features.namespaces),
            Feature::Class(matcher) => match_string(matcher, &scope_features.classes),

            Feature::Number(num_matcher) => scope_features.numbers.contains(&num_matcher.value),

            Feature::Offset(offset_matcher) => scope_features.offsets.contains(&offset_matcher.value),

            Feature::Bytes(pattern) => {
                scope_features.bytes_sequences.iter().any(|seq| {
                    if seq.len() < pattern.len() {
                        return false;
                    }
                    seq[..pattern.len()].iter().zip(pattern.iter()).all(|(actual, expected)| {
                        expected.map_or(true, |b| *actual == b)
                    })
                })
            }

            Feature::Mnemonic(mnem) => scope_features.mnemonics.contains_key(mnem),

            Feature::Operand(op_matcher) => {
                scope_features.operands.iter().any(|(idx, num, offset)| {
                    if *idx != op_matcher.index {
                        return false;
                    }
                    match &op_matcher.value {
                        crate::rule::OperandValue::Number(n) => {
                            num.map(|v| v == n.value).unwrap_or(false)
                        }
                        crate::rule::OperandValue::Offset(o) => {
                            offset.map(|v| v == o.value).unwrap_or(false)
                        }
                    }
                })
            }

            Feature::Characteristic(char_type) => {
                scope_features.characteristics.contains(char_type)
            }

            Feature::Property(prop) => {
                scope_features.properties.iter().any(|(name, access)| {
                    name == &prop.name && (prop.access == crate::rule::PropertyAccess::Any || *access == prop.access)
                })
            }

            Feature::ComClass(name) => {
                // Match COM class GUID against extracted classes
                scope_features.classes.iter().any(|c| c.eq_ignore_ascii_case(name))
            }
            Feature::ComInterface(name) => {
                // Match COM interface GUID against extracted classes
                scope_features.classes.iter().any(|c| c.eq_ignore_ascii_case(name))
            }

            Feature::Os(os) => *os == OsType::Any || *os == all_features.os,
            Feature::Arch(arch) => *arch == ArchType::Any || *arch == all_features.arch,
            Feature::Format(fmt) => *fmt == FormatType::Any || *fmt == all_features.format,

            Feature::BasicBlockFeature => {
                // BasicBlockFeature matches if there's at least one basic block
                scope_features.basic_block_count > 0
            }
        }
    }
}

/// Mirror Python capa's `trim_dll_part`: for Win32 `dll.FuncName` specs (single `.`,
/// not ordinal `.#` and not .NET `Namespace.Class::Method`), ignore the human-oriented
/// DLL prefix so API-set / thunked calls (e.g. `api-ms-win-crt-*.getenv` -> `msvcrt.getenv`) match.
fn trim_dll_part(api: &str) -> &str {
    if api.contains(".#") || api.contains("::") {
        return api;
    }
    let mut parts = api.split('.');
    let _first = parts.next();
    match (parts.next(), parts.next()) {
        (Some(func), None) if !func.is_empty() => func,
        _ => api,
    }
}

fn match_api(matcher: &StringMatcher, apis: &HashSet<String>) -> bool {
    match matcher {
        StringMatcher::Exact(pattern) => {
            let bare = trim_dll_part(pattern);
            apis.iter().any(|s| {
                s.eq_ignore_ascii_case(pattern) || (bare != pattern && s.eq_ignore_ascii_case(bare))
            })
        }
        StringMatcher::Regex(compiled) => apis.iter().any(|s| compiled.is_match(s)),
    }
}

fn count_api_matches(matcher: &StringMatcher, apis: &HashSet<String>) -> usize {
    match matcher {
        StringMatcher::Exact(pattern) => {
            let bare = trim_dll_part(pattern);
            if apis.iter().any(|s| s.eq_ignore_ascii_case(pattern)) {
                apis.iter().filter(|s| s.eq_ignore_ascii_case(pattern)).count()
            } else if bare != pattern {
                apis.iter().filter(|s| s.eq_ignore_ascii_case(bare)).count()
            } else {
                0
            }
        }
        StringMatcher::Regex(compiled) => apis.iter().filter(|s| compiled.is_match(s)).count(),
    }
}

fn match_string(matcher: &StringMatcher, strings: &HashSet<String>) -> bool {
    match matcher {
        StringMatcher::Exact(pattern) => {
            // Case-insensitive comparison for API names
            strings.iter().any(|s| s.eq_ignore_ascii_case(pattern))
        }
        StringMatcher::Regex(compiled) => strings.iter().any(|s| compiled.is_match(s)),
    }
}

fn match_substring(matcher: &StringMatcher, strings: &HashSet<String>) -> bool {
    match matcher {
        StringMatcher::Exact(pattern) => {
            let pattern_lower = pattern.to_lowercase();
            strings.iter().any(|s| s.to_lowercase().contains(&pattern_lower))
        }
        StringMatcher::Regex(compiled) => strings.iter().any(|s| compiled.is_match(s)),
    }
}

fn count_string_matches(
    matcher: &StringMatcher,
    strings: &HashSet<String>,
) -> usize {
    match matcher {
        StringMatcher::Exact(pattern) => {
            strings.iter().filter(|s| s.eq_ignore_ascii_case(pattern)).count()
        }
        StringMatcher::Regex(compiled) => strings.iter().filter(|s| compiled.is_match(s)).count(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::parse_rule;

    #[test]
    fn test_simple_api_match() {
        let yaml = r#"
rule:
  meta:
    name: test api
    scopes:
      static: function
  features:
    - api: CreateFileA
"#;
        let rule = parse_rule(yaml).unwrap();
        let engine = MatchEngine::new(vec![rule]);

        let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
        let mut func = crate::feature::FunctionFeatures::new(crate::feature::Address(0x1000));
        func.features.apis.insert("CreateFileA".to_string());
        features.functions.insert(crate::feature::Address(0x1000), func);

        let matches = engine.match_all(&features);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name, "test api");
        assert_eq!(matches[0].match_count, 1);
        assert_eq!(matches[0].locations.len(), 1);
    }

    #[test]
    fn test_case_insensitive_api_match() {
        let yaml = r#"
rule:
  meta:
    name: test api case
    scopes:
      static: function
  features:
    - api: createfilea
"#;
        let rule = parse_rule(yaml).unwrap();
        let engine = MatchEngine::new(vec![rule]);

        let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
        let mut func = crate::feature::FunctionFeatures::new(crate::feature::Address(0x1000));
        func.features.apis.insert("CreateFileA".to_string());
        features.functions.insert(crate::feature::Address(0x1000), func);

        let matches = engine.match_all(&features);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_and_operator() {
        let yaml = r#"
rule:
  meta:
    name: test and
    scopes:
      static: function
  features:
    - and:
      - api: CreateFileA
      - api: WriteFile
"#;
        let rule = parse_rule(yaml).unwrap();
        let engine = MatchEngine::new(vec![rule]);

        // Test with both APIs present
        let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
        let mut func = crate::feature::FunctionFeatures::new(crate::feature::Address(0x1000));
        func.features.apis.insert("CreateFileA".to_string());
        func.features.apis.insert("WriteFile".to_string());
        features.functions.insert(crate::feature::Address(0x1000), func);

        let matches = engine.match_all(&features);
        assert_eq!(matches.len(), 1);

        // Test with only one API present
        let mut features2 = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
        let mut func2 = crate::feature::FunctionFeatures::new(crate::feature::Address(0x1000));
        func2.features.apis.insert("CreateFileA".to_string());
        features2.functions.insert(crate::feature::Address(0x1000), func2);

        let matches2 = engine.match_all(&features2);
        assert_eq!(matches2.len(), 0);
    }

    #[test]
    fn test_or_operator() {
        let yaml = r#"
rule:
  meta:
    name: test or
    scopes:
      static: function
  features:
    - or:
      - api: CreateFileA
      - api: CreateFileW
"#;
        let rule = parse_rule(yaml).unwrap();
        let engine = MatchEngine::new(vec![rule]);

        // Test with one API present
        let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
        let mut func = crate::feature::FunctionFeatures::new(crate::feature::Address(0x1000));
        func.features.apis.insert("CreateFileW".to_string());
        features.functions.insert(crate::feature::Address(0x1000), func);

        let matches = engine.match_all(&features);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_count_constraint() {
        let yaml = r#"
rule:
  meta:
    name: test count
    scopes:
      static: function
  features:
    - count(mnemonic(push)): (3, 10)
"#;
        let rule = parse_rule(yaml).unwrap();
        let engine = MatchEngine::new(vec![rule]);

        // Test with 5 push instructions
        let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
        let mut func = crate::feature::FunctionFeatures::new(crate::feature::Address(0x1000));
        func.features.mnemonics.insert("push".to_string(), 5);
        features.functions.insert(crate::feature::Address(0x1000), func);

        let matches = engine.match_all(&features);
        assert_eq!(matches.len(), 1);

        // Test with 2 push instructions (below range)
        let mut features2 = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
        let mut func2 = crate::feature::FunctionFeatures::new(crate::feature::Address(0x1000));
        func2.features.mnemonics.insert("push".to_string(), 2);
        features2.functions.insert(crate::feature::Address(0x1000), func2);

        let matches2 = engine.match_all(&features2);
        assert_eq!(matches2.len(), 0);
    }

    #[test]
    fn test_parallel_vs_sequential() {
        let yaml = r#"
rule:
  meta:
    name: test parallel
    scopes:
      static: function
  features:
    - api: TestAPI
"#;
        let rule = parse_rule(yaml).unwrap();
        let engine = MatchEngine::new(vec![rule]);

        let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
        let mut func = crate::feature::FunctionFeatures::new(crate::feature::Address(0x1000));
        func.features.apis.insert("TestAPI".to_string());
        features.functions.insert(crate::feature::Address(0x1000), func);

        let parallel_matches = engine.match_all(&features);
        let sequential_matches = engine.match_all_sequential(&features);

        assert_eq!(parallel_matches.len(), sequential_matches.len());
    }
}
