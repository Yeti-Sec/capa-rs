// Virtual functions: additive second matching pass, function-scope rules only.

use capa_core::feature::{Address, ExtractedFeatures, FeatureSet, FunctionFeatures};
use capa_core::matcher::MatchEngine;
use capa_core::rule::parse_rule;
use capa_core::rule::{ArchType, CharacteristicType, FormatType, OsType};

const RULE_FN: &str = r#"
rule:
  meta:
    name: recursive function
    scopes:
      static: function
  features:
    - characteristic: recursive call
"#;

const RULE_FILE: &str = r#"
rule:
  meta:
    name: file level recursion
    scopes:
      static: file
  features:
    - characteristic: recursive call
"#;

fn base() -> ExtractedFeatures {
    let mut f = ExtractedFeatures::new(OsType::Windows, ArchType::Amd64, FormatType::Pe);
    // the stub's own (unchanged) evaluation: nothing recursive
    f.functions.insert(Address(0x1000), FunctionFeatures::new(Address(0x1000)));
    f
}

fn virtual_fn(addr: u64) -> FunctionFeatures {
    let mut v = FunctionFeatures::new(Address(addr));
    v.features.add_characteristic(CharacteristicType::RecursiveCall);
    v
}

#[test]
fn virtual_function_match_is_reported_at_head_address() {
    let engine = MatchEngine::new(vec![parse_rule(RULE_FN).unwrap()]);
    let mut f = base();
    assert!(engine.match_all(&f).is_empty());
    f.virtual_functions.push(virtual_fn(0x1000));
    let m = engine.match_all(&f);
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].locations, vec![Address(0x1000)]);
    // sequential path behaves the same
    assert_eq!(engine.match_all_sequential(&f)[0].locations, vec![Address(0x1000)]);
}

#[test]
fn virtual_pass_is_additive_and_does_not_duplicate_locations() {
    let engine = MatchEngine::new(vec![parse_rule(RULE_FN).unwrap()]);
    let mut f = base();
    // a normal function that already matches
    f.functions.get_mut(&Address(0x1000)).unwrap().features.add_characteristic(CharacteristicType::RecursiveCall);
    f.functions.insert(Address(0x2000), FunctionFeatures::new(Address(0x2000)));
    f.virtual_functions.push(virtual_fn(0x1000)); // same head: no duplicate
    f.virtual_functions.push(virtual_fn(0x2000)); // new location
    let m = engine.match_all(&f);
    assert_eq!(m.len(), 1);
    let mut locs: Vec<u64> = m[0].locations.iter().map(|a| a.0).collect();
    locs.sort();
    assert_eq!(locs, vec![0x1000, 0x2000]);
    assert_eq!(m[0].match_count, 2);
}

#[test]
fn virtual_functions_do_not_affect_file_scope_rules() {
    let engine = MatchEngine::new(vec![parse_rule(RULE_FILE).unwrap()]);
    let mut f = base();
    f.virtual_functions.push(virtual_fn(0x1000));
    assert!(engine.match_all(&f).is_empty(), "file-scope evaluation must ignore virtual functions");
    let _ = FeatureSet::new();
}

// ---- M1: file-scope dependents see function-scope matches that exist only virtually ----

const RULE_FILE_DEP: &str = r#"
rule:
  meta:
    name: file depends on recursive function
    scopes:
      static: file
  features:
    - match: recursive function
"#;

const RULE_FILE_NOT: &str = r#"
rule:
  meta:
    name: file not recursive
    scopes:
      static: file
  features:
    - and:
      - string: x
      - not:
        - match: recursive function
"#;

fn names(m: &[capa_core::matcher::RuleMatch]) -> Vec<String> {
    m.iter().map(|x| x.name.clone()).collect()
}

#[test]
fn file_rule_with_match_dependency_sees_virtual_only_function_match() {
    let engine = MatchEngine::new(vec![
        parse_rule(RULE_FN).unwrap(),
        parse_rule(RULE_FILE_DEP).unwrap(),
    ]);
    let mut f = base();
    assert!(engine.match_all(&f).is_empty());
    f.virtual_functions.push(virtual_fn(0x1000));
    for m in [engine.match_all(&f), engine.match_all_sequential(&f)] {
        let n = names(&m);
        assert!(n.contains(&"recursive function".to_string()), "{n:?}");
        assert!(n.contains(&"file depends on recursive function".to_string()), "{n:?}");
    }
    // match_rule_by_name is consistent with match_all
    let one = engine.match_rule_by_name("file depends on recursive function", &f);
    assert!(one.is_some());
}

#[test]
fn primary_only_scenario_is_unchanged_by_the_virtual_machinery() {
    let engine = MatchEngine::new(vec![
        parse_rule(RULE_FN).unwrap(),
        parse_rule(RULE_FILE_DEP).unwrap(),
    ]);
    let mut f = base();
    f.functions.get_mut(&Address(0x1000)).unwrap().features.add_characteristic(CharacteristicType::RecursiveCall);
    let before = engine.match_all_sequential(&f);
    // a virtual function that adds nothing new (same head, same result)
    f.virtual_functions.push(virtual_fn(0x1000));
    let after = engine.match_all_sequential(&f);
    assert_eq!(names(&before), names(&after));
    for (b, a) in before.iter().zip(after.iter()) {
        assert_eq!(b.locations, a.locations);
        assert_eq!(b.match_count, a.match_count);
    }
}

#[test]
fn not_rule_cannot_lose_a_primary_match() {
    let engine = MatchEngine::new(vec![
        parse_rule(RULE_FN).unwrap(),
        parse_rule(RULE_FILE_NOT).unwrap(),
    ]);
    let mut f = base();
    f.file.strings.insert("x".to_string());
    let before = engine.match_all_sequential(&f);
    assert!(names(&before).contains(&"file not recursive".to_string()));
    // after the virtual pass `recursive function` matches, so the `not:` rule would no longer
    // match if re-evaluated from scratch; the primary match must still be reported unchanged.
    f.virtual_functions.push(virtual_fn(0x1000));
    let after = engine.match_all_sequential(&f);
    let n = names(&after);
    assert!(n.contains(&"file not recursive".to_string()), "primary match lost: {n:?}");
    assert!(n.contains(&"recursive function".to_string()));
    let b = before.iter().find(|m| m.name == "file not recursive").unwrap();
    let a = after.iter().find(|m| m.name == "file not recursive").unwrap();
    assert_eq!(b.locations, a.locations);
}
