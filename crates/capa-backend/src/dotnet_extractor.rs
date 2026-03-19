//! .NET feature extraction using dotscope
//!
//! Extracts CAPA features from .NET assemblies using dotscope for
//! proper metadata parsing, user string extraction, and API resolution.
//!
//! This path targets parity with Python capa's `dnfile` extractor:
//!   - managed API names in canonical `Namespace.Type::Method` form (G1)
//!   - unmanaged P/Invoke imports from the ImplMap table, not just the PE
//!     import directory (G2)
//!   - instruction-scope API/class/namespace + `unmanaged call` characteristic
//!     from call-site token resolution (G3)
//!   - `class:` / `namespace:` routed to dedicated feature channels (G4)
//!   - `property:` features from get_/set_ accessors and field load/store (G5)
//!   - width/sign-correct numeric constants (G6)
//!   - `calls to` / `calls from` / `recursive call` characteristics (G8)
//!   - managed resource names + embedded strings (G9)
//!   - generic (MethodSpec) call unwrapping (G10)

use capa_core::feature::{Address, FeatureSet, FunctionFeatures};
use capa_core::rule::{CharacteristicType, PropertyAccess};
use crate::loader::StringInfo;
use log::debug;
use std::collections::{HashMap, HashSet};

/// Features produced by a single IL instruction (instruction scope). Only
/// instructions that yield a matchable feature are retained.
#[derive(Debug, Clone, Default)]
pub struct DotNetInsnFeatures {
    /// Instruction RVA (unique address within the method)
    pub rva: u64,
    /// APIs referenced at this instruction (managed Ns.Type::Method and, for
    /// P/Invoke call sites, unmanaged dll.func / func variants)
    pub apis: Vec<String>,
    /// Numeric constants at this instruction
    pub numbers: Vec<i64>,
    /// Strings loaded at this instruction (ldstr)
    pub strings: Vec<String>,
    /// Property accesses at this instruction
    pub properties: Vec<(String, PropertyAccess)>,
    /// Declaring-type class referenced at this instruction
    pub classes: Vec<String>,
    /// Namespace referenced at this instruction
    pub namespaces: Vec<String>,
    /// Whether this instruction is an unmanaged (P/Invoke) call
    pub unmanaged_call: bool,
}

/// Aggregated features for one IL basic block (basic-block scope). Lets capa
/// rules that require co-located features (e.g. `create TCP socket` =
/// Socket::ctor + SOCK_STREAM number) match within a block.
#[derive(Debug, Clone, Default)]
pub struct DotNetBlockFeatures {
    /// dotscope basic-block id (unique within the method)
    pub id: usize,
    pub apis: Vec<String>,
    pub numbers: Vec<i64>,
    pub strings: Vec<String>,
    pub properties: Vec<(String, PropertyAccess)>,
    pub classes: Vec<String>,
    pub namespaces: Vec<String>,
    pub mnemonics: HashMap<String, u32>,
    pub unmanaged_call: bool,
}

/// Features for a single .NET method (function scope).
#[derive(Debug, Clone, Default)]
pub struct DotNetMethodFeatures {
    /// Method RVA (address for matching)
    pub rva: u64,
    /// This method's own metadata token value (for recursion detection)
    pub token_value: u32,
    /// Method name
    pub name: String,
    /// IL mnemonics in this method
    pub mnemonics: HashMap<String, u32>,
    /// Numeric constants in this method
    pub numbers: HashSet<i64>,
    /// Strings loaded by this method (ldstr targets)
    pub strings: Vec<String>,
    /// API calls resolved at call sites in this method (Namespace.Type::Method)
    pub apis: HashSet<String>,
    /// Property accesses in this method (name, Read/Write)
    pub properties: Vec<(String, PropertyAccess)>,
    /// Declaring-type class names referenced at call sites (insn scope)
    pub classes: HashSet<String>,
    /// Namespaces referenced at call sites (insn scope)
    pub namespaces: HashSet<String>,
    /// Whether this method calls at least one P/Invoke target (`unmanaged call`)
    pub unmanaged_call: bool,
    /// Whether this method makes any call (`calls from`)
    pub calls_out: bool,
    /// Whether this method calls itself (`recursive call`)
    pub is_recursive: bool,
    /// Whether this method's CFG has a back edge (`characteristic: loop`)
    pub has_loop: bool,
    /// Whether this method has a self-looping block (`characteristic: tight loop`)
    pub has_tight_loop: bool,
    /// Per-instruction features (instruction-scope matching)
    pub instructions: Vec<DotNetInsnFeatures>,
    /// Per-basic-block features (basic-block-scope matching)
    pub blocks: Vec<DotNetBlockFeatures>,
}

/// Map short-form `ldc.i4.*` opcodes (which carry no operand) to their implicit
/// constant. dnfile/dncil's get_ldc() resolves these; without it, values like
/// SW_HIDE (0), SC_MONITORPOWER arg (2), SPIF flags (3) are lost and number-based
/// rules never fire.
#[cfg(feature = "dotnet")]
fn short_form_ldc(mnemonic: &str) -> Option<i64> {
    match mnemonic {
        "ldc.i4.m1" | "ldc.i4.M1" => Some(-1),
        "ldc.i4.0" => Some(0),
        "ldc.i4.1" => Some(1),
        "ldc.i4.2" => Some(2),
        "ldc.i4.3" => Some(3),
        "ldc.i4.4" => Some(4),
        "ldc.i4.5" => Some(5),
        "ldc.i4.6" => Some(6),
        "ldc.i4.7" => Some(7),
        "ldc.i4.8" => Some(8),
        _ => None,
    }
}

/// .NET-specific features extracted from an assembly.
#[derive(Debug, Clone, Default)]
pub struct DotNetExtractedFeatures {
    /// User strings from the #US heap (actual string literals in code)
    pub user_strings: Vec<StringInfo>,
    /// Fully-qualified class names (nested joined with `/`) -> `class:` channel
    pub classes: Vec<String>,
    /// Namespaces -> `namespace:` channel
    pub namespaces: Vec<String>,
    /// Method names (file scope) -> `function_names`
    pub methods: Vec<String>,
    /// Managed API calls (member references) -> `apis` (Namespace.Type::Method)
    pub api_calls: Vec<String>,
    /// Unmanaged P/Invoke imports (module.function variants) -> `apis` + `imports`
    pub imports: Vec<String>,
    /// File-scope property accesses (name, Read/Write)
    pub properties: Vec<(String, PropertyAccess)>,
    /// Strings recovered from managed resources (names + embedded blobs)
    pub resource_strings: Vec<String>,
    /// Module name
    pub module_name: String,
    /// IL opcodes/mnemonics used in methods (ldstr, call, newobj, etc.)
    pub il_mnemonics: HashMap<String, u32>,
    /// Numeric constants from IL operands
    pub il_numbers: HashSet<i64>,
    /// Per-method features with RVAs for function-scope matching
    pub method_features: Vec<DotNetMethodFeatures>,
    /// Set of all method tokens that are called by some method (for `calls to`)
    pub called_tokens: HashSet<u32>,
}

/// Build capa's canonical API string `Namespace.Type::Method`, normalizing
/// constructor names (`.ctor` -> `ctor`, `.cctor` -> `cctor`) to match capa's
/// `DnType.format_name`.
#[cfg(feature = "dotnet")]
fn canonical_api(type_fullname: &str, method: &str) -> String {
    let m = match method {
        ".ctor" => "ctor",
        ".cctor" => "cctor",
        other => other,
    };
    if type_fullname.is_empty() {
        m.to_string()
    } else {
        format!("{}::{}", type_fullname, m)
    }
}

/// If `method` is a property accessor (`get_X` / `set_X`), return the property
/// name and access kind. Mirrors capa's accessor-to-property diversion so
/// accessor calls become `property:` features instead of `api:`.
#[cfg(feature = "dotnet")]
fn accessor_kind(method: &str) -> Option<(String, PropertyAccess)> {
    if let Some(rest) = method.strip_prefix("get_") {
        Some((rest.to_string(), PropertyAccess::Read))
    } else if let Some(rest) = method.strip_prefix("set_") {
        Some((rest.to_string(), PropertyAccess::Write))
    } else {
        None
    }
}

/// A resolved call-site target.
#[cfg(feature = "dotnet")]
struct ResolvedCall {
    /// Canonical `Namespace.Type::Method`
    api: String,
    /// Bare method name (for accessor detection)
    method_name: String,
    /// Declaring type fullname, if known
    class: Option<String>,
    /// Namespace of the declaring type, if known
    namespace: Option<String>,
    /// Whether the resolved target is a P/Invoke (unmanaged) method
    is_pinvoke: bool,
    /// Token value of the resolved target method (for call-graph / recursion)
    target_token: u32,
}

/// Resolve a call/callvirt/newobj/jmp token to a method target. Handles
/// MethodDef (0x06), MemberRef (0x0A), and unwraps MethodSpec (0x2B) to its
/// underlying method (G10).
#[cfg(feature = "dotnet")]
fn resolve_call_target(
    assembly: &dotscope::CilObject,
    token: &dotscope::metadata::token::Token,
) -> Option<ResolvedCall> {
    match token.table() {
        0x06 => {
            // MethodDef — internal method
            let m = assembly.method(token)?;
            let dt = m.declaring_type_rc();
            let class = dt.as_ref().map(|t| t.fullname());
            let namespace = dt
                .as_ref()
                .map(|t| t.namespace.clone())
                .filter(|s| !s.is_empty());
            Some(ResolvedCall {
                api: canonical_api(class.as_deref().unwrap_or(""), &m.name),
                method_name: m.name.clone(),
                class,
                namespace,
                is_pinvoke: m.is_pinvoke(),
                target_token: token.value(),
            })
        }
        0x0A => {
            // MemberRef — external (managed) method or field
            let mr = assembly.member_ref(token)?;
            let class = mr.declaredby.fullname();
            let namespace = class
                .as_deref()
                .and_then(|c| c.rsplit_once('.').map(|(ns, _)| ns.to_string()));
            Some(ResolvedCall {
                api: canonical_api(class.as_deref().unwrap_or(""), &mr.name),
                method_name: mr.name.clone(),
                class,
                namespace,
                is_pinvoke: false,
                target_token: token.value(),
            })
        }
        0x2B => {
            // MethodSpec — generic instantiation; unwrap to the underlying method
            let ms = assembly.method_spec(token)?;
            let inner = ms.method.token()?;
            resolve_call_target(assembly, &inner)
        }
        _ => None,
    }
}

/// Best-effort extraction of printable ASCII and UTF-16LE strings from a blob.
#[cfg(feature = "dotnet")]
fn extract_blob_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut out = Vec::new();

    // ASCII runs
    let mut cur = String::new();
    for &b in data {
        if (0x20..0x7f).contains(&b) {
            cur.push(b as char);
        } else {
            if cur.len() >= min_len {
                out.push(std::mem::take(&mut cur));
            } else {
                cur.clear();
            }
        }
    }
    if cur.len() >= min_len {
        out.push(cur);
    }

    // UTF-16LE runs (ascii char followed by 0x00)
    let mut u16cur = String::new();
    let mut i = 0;
    while i + 1 < data.len() {
        let (lo, hi) = (data[i], data[i + 1]);
        if hi == 0x00 && (0x20..0x7f).contains(&lo) {
            u16cur.push(lo as char);
            i += 2;
        } else {
            if u16cur.len() >= min_len {
                out.push(std::mem::take(&mut u16cur));
            } else {
                u16cur.clear();
            }
            i += 1;
        }
    }
    if u16cur.len() >= min_len {
        out.push(u16cur);
    }

    out
}

/// Extract .NET-specific features using dotscope
#[cfg(feature = "dotnet")]
pub fn extract_dotnet_features(bytes: &[u8]) -> Option<DotNetExtractedFeatures> {
    use dotscope::CilObject;
    use dotscope::ValidationConfig;
    use dotscope::assembly::{Immediate, Operand};
    use dotscope::metadata::imports::{ImportSourceId, ImportType};
    use std::collections::{HashMap, HashSet};

    // Minimum string length, shared by file-scope #US and instruction-scope
    // ldstr, matching capa (>= 4).
    const MIN_STR: usize = 4;

    // Try to parse as .NET assembly with disabled validation (most lenient for malware)
    let assembly = match CilObject::from_mem_with_validation(bytes.to_vec(), ValidationConfig::disabled()) {
        Ok(asm) => asm,
        Err(e) => {
            debug!("Failed to parse .NET assembly with dotscope: {:?}", e);
            return None;
        }
    };

    let mut features = DotNetExtractedFeatures::default();

    // Get module name
    if let Some(module) = assembly.module() {
        features.module_name = module.name.clone();
    }

    // Get user strings heap for resolving ldstr tokens
    let user_strings_heap = assembly.userstrings();

    // Extract user strings from #US heap (file scope)
    if let Some(ref user_strings) = user_strings_heap {
        let mut addr = 0u64;
        for (_, s) in user_strings.iter() {
            let s_string = s.to_string_lossy();
            if s_string.len() >= MIN_STR {
                features.user_strings.push(StringInfo {
                    value: s_string,
                    address: addr,
                });
                addr += 1;
            }
        }
    }

    // Extract type names into the class channel (G4), using dotscope's
    // fullname() which joins nested types with '/' like the CLR. Also build a
    // field-token -> "Type::field" index for property field-access (G5).
    let types = assembly.types();
    let mut namespaces_set: HashSet<String> = HashSet::new();
    let mut field_index: HashMap<u32, String> = HashMap::new();

    for entry in types.iter() {
        let type_info = entry.value();
        let type_fullname = type_info.fullname();
        features.classes.push(type_fullname.clone());

        if !type_info.namespace.is_empty() {
            namespaces_set.insert(type_info.namespace.clone());
        }

        for (_, field) in type_info.fields.iter() {
            field_index.insert(
                field.token.value(),
                canonical_api(&type_fullname, &field.name),
            );
        }
    }

    // Managed imports from the MemberRef table (G1) — capa's
    // get_dotnet_managed_imports path. Accessor calls (get_/set_) become
    // property features rather than api.
    for entry in assembly.refs_members().iter() {
        let mr = entry.value();
        let class = mr.declaredby.fullname();
        if let Some((prop, access)) = accessor_kind(&mr.name) {
            let name = canonical_api(class.as_deref().unwrap_or(""), &prop);
            features.properties.push((name, access));
        } else {
            features
                .api_calls
                .push(canonical_api(class.as_deref().unwrap_or(""), &mr.name));
        }
    }

    // Build a P/Invoke map: wrapper MethodDef token -> (dll, entrypoint). Lets
    // call sites to P/Invoke wrappers emit the UNMANAGED api name
    // (kernel32.CreateMutex) at instruction scope, matching capa's
    // instruction-scoped unmanaged api: rules. Mirrors dotscope's own
    // extract_dll_from_pinvoke_import.
    let mut pinvoke_map: HashMap<u32, (String, String)> = HashMap::new();
    {
        let cil = assembly.imports().cil();
        for entry in cil.iter() {
            let import = entry.value();
            if let ImportType::Method(m) = &import.import {
                if let ImportSourceId::ModuleRef(tok) = &import.source_id {
                    if let Some(mr) = cil.get_module_ref(*tok) {
                        pinvoke_map
                            .insert(m.token.value(), (mr.name.clone(), import.name.clone()));
                    }
                }
            }
        }
    }

    // Extract method names and IL mnemonics/numbers/call sites
    let methods = assembly.methods();
    let file = assembly.file();
    let file_data = file.data();
    let mut il_mnemonics: HashMap<String, u32> = HashMap::new();
    let mut il_numbers: HashSet<i64> = HashSet::new();
    let mut called_tokens: HashSet<u32> = HashSet::new();
    let mut methods_with_rva = 0u32;
    let mut methods_decoded = 0u32;
    let mut decode_failures = 0u32;
    let mut userstring_failures = 0u32;
    let mut total_instructions = 0u32;
    let mut strings_resolved = 0u32;

    for entry in methods.iter() {
        let method = entry.value();
        let method_token = entry.key().value();
        features.methods.push(method.name.clone());

        let Some(rva) = method.rva else { continue };
        if rva == 0 {
            continue;
        }
        methods_with_rva += 1;

        let mut mf = DotNetMethodFeatures {
            rva: rva as u64,
            token_value: method_token,
            name: method.name.clone(),
            ..Default::default()
        };

        // Convert RVA to file offset and decode the method body
        if let Ok(offset) = file.rva_to_offset(rva as usize) {
            if offset > 0 && offset < file_data.len() {
                let method_bytes = &file_data[offset..];
                if let Some((header_size, code_size)) = parse_method_header(method_bytes) {
                    let code_start = offset + header_size;
                    let code_end = code_start + code_size;

                    if code_end <= file_data.len() && code_size > 0 {
                        let il_bytes = &file_data[code_start..code_end];
                        match dotscope::assembly::decode_blocks(
                            il_bytes,
                            0,
                            rva as usize + header_size,
                            None,
                        ) {
                            Ok(blocks) => {
                                methods_decoded += 1;
                                let mut raw_blocks: Vec<DotNetBlockFeatures> =
                                    Vec::with_capacity(blocks.len());
                                for block in &blocks {
                                    let mut blk = DotNetBlockFeatures {
                                        id: block.id,
                                        ..Default::default()
                                    };
                                    for instruction in &block.instructions {
                                        total_instructions += 1;
                                        let mnemonic = instruction.mnemonic;
                                        *il_mnemonics.entry(mnemonic.to_string()).or_insert(0) += 1;
                                        *mf.mnemonics.entry(mnemonic.to_string()).or_insert(0) += 1;

                                        let mut insn = DotNetInsnFeatures {
                                            rva: instruction.rva,
                                            ..Default::default()
                                        };

                                        // Short-form ldc.i4.* carry no operand (RC1)
                                        if let Some(n) = short_form_ldc(mnemonic) {
                                            il_numbers.insert(n);
                                            mf.numbers.insert(n);
                                            insn.numbers.push(n);
                                        }

                                        match &instruction.operand {
                                            Operand::Immediate(imm) => {
                                                // Width/sign-correct numeric extraction (G6)
                                                let n: i64 = match imm {
                                                    Immediate::Int8(v) => *v as i64,
                                                    Immediate::UInt8(v) => *v as i64,
                                                    Immediate::Int16(v) => *v as i64,
                                                    Immediate::UInt16(v) => *v as i64,
                                                    Immediate::Int32(v) => *v as i64,
                                                    Immediate::UInt32(v) => *v as i64,
                                                    Immediate::Int64(v) => *v,
                                                    Immediate::UInt64(v) => *v as i64,
                                                    Immediate::Float32(v) => v.to_bits() as i64,
                                                    Immediate::Float64(v) => v.to_bits() as i64,
                                                };
                                                il_numbers.insert(n);
                                                mf.numbers.insert(n);
                                                insn.numbers.push(n);
                                            }
                                            Operand::Token(token) => {
                                                match mnemonic {
                                                    "ldstr" if token.table() == 0x70 => {
                                                        if let Some(ref us) = user_strings_heap {
                                                            match us.get(token.row() as usize) {
                                                                Ok(s) => {
                                                                    let s = s.to_string_lossy();
                                                                    if s.len() >= MIN_STR {
                                                                        mf.strings.push(s.clone());
                                                                        insn.strings.push(s);
                                                                        strings_resolved += 1;
                                                                    }
                                                                }
                                                                Err(_) => userstring_failures += 1,
                                                            }
                                                        }
                                                    }
                                                    "call" | "callvirt" | "newobj" | "jmp" => {
                                                        // Call-site resolution (G3/G10)
                                                        if let Some(rc) =
                                                            resolve_call_target(&assembly, token)
                                                        {
                                                            if let Some((prop, access)) =
                                                                accessor_kind(&rc.method_name)
                                                            {
                                                                let name = canonical_api(
                                                                    rc.class.as_deref().unwrap_or(""),
                                                                    &prop,
                                                                );
                                                                mf.properties
                                                                    .push((name.clone(), access));
                                                                features
                                                                    .properties
                                                                    .push((name.clone(), access));
                                                                insn.properties.push((name, access));
                                                            } else {
                                                                mf.apis.insert(rc.api.clone());
                                                                features.api_calls.push(rc.api.clone());
                                                                insn.apis.push(rc.api.clone());
                                                            }
                                                            // For P/Invoke wrappers, also emit the
                                                            // UNMANAGED name (kernel32.CreateMutex /
                                                            // CreateMutex) at this instruction so
                                                            // capa's unmanaged api: rules match.
                                                            if let Some((dll, func)) =
                                                                pinvoke_map.get(&rc.target_token)
                                                            {
                                                                for sym in crate::helpers::generate_symbols(dll, func, true) {
                                                                    mf.apis.insert(sym.clone());
                                                                    features.api_calls.push(sym.clone());
                                                                    insn.apis.push(sym);
                                                                }
                                                            }
                                                            if let Some(c) = rc.class.clone() {
                                                                mf.classes.insert(c.clone());
                                                                features.classes.push(c.clone());
                                                                insn.classes.push(c);
                                                            }
                                                            if let Some(ns) = rc.namespace.clone() {
                                                                mf.namespaces.insert(ns.clone());
                                                                namespaces_set.insert(ns.clone());
                                                                insn.namespaces.push(ns);
                                                            }
                                                            if rc.is_pinvoke {
                                                                mf.unmanaged_call = true;
                                                                insn.unmanaged_call = true;
                                                            }
                                                            mf.calls_out = true;
                                                            called_tokens.insert(rc.target_token);
                                                            if rc.target_token == method_token {
                                                                mf.is_recursive = true;
                                                            }
                                                        }
                                                    }
                                                    "ldfld" | "ldflda" | "ldsfld" | "ldsflda"
                                                    | "stfld" | "stsfld" => {
                                                        // Field access -> property (G5)
                                                        let access = if mnemonic.starts_with("st") {
                                                            PropertyAccess::Write
                                                        } else {
                                                            PropertyAccess::Read
                                                        };
                                                        if let Some(fname) =
                                                            field_index.get(&token.value())
                                                        {
                                                            mf.properties
                                                                .push((fname.clone(), access));
                                                            features
                                                                .properties
                                                                .push((fname.clone(), access));
                                                            insn.properties
                                                                .push((fname.clone(), access));
                                                        }
                                                    }
                                                    _ => {}
                                                }
                                            }
                                            _ => {}
                                        }

                                        // Fold this instruction into the basic-block
                                        // aggregate (bb-scope matching).
                                        *blk.mnemonics
                                            .entry(mnemonic.to_string())
                                            .or_insert(0) += 1;
                                        blk.apis.extend(insn.apis.iter().cloned());
                                        blk.numbers.extend(insn.numbers.iter().cloned());
                                        blk.strings.extend(insn.strings.iter().cloned());
                                        blk.properties.extend(insn.properties.iter().cloned());
                                        blk.classes.extend(insn.classes.iter().cloned());
                                        blk.namespaces.extend(insn.namespaces.iter().cloned());
                                        if insn.unmanaged_call {
                                            blk.unmanaged_call = true;
                                        }

                                        // Retain only instructions that produced a
                                        // matchable feature (keeps the map small).
                                        if !insn.apis.is_empty()
                                            || !insn.numbers.is_empty()
                                            || !insn.strings.is_empty()
                                            || !insn.properties.is_empty()
                                            || !insn.classes.is_empty()
                                            || !insn.namespaces.is_empty()
                                            || insn.unmanaged_call
                                        {
                                            mf.instructions.push(insn);
                                        }
                                    }

                                    raw_blocks.push(blk);
                                }

                                // Predecessor merge: pull each block's immediate
                                // predecessors' NUMBERS and STRINGS (the arg-setup
                                // operands) into it, so an api and the constant it is
                                // called with co-locate even when dotscope splits the
                                // CFG finer than capa/dncil (e.g. ShowWindow + SW_HIDE).
                                // APIs stay anchored to their own block to bound false
                                // positives. Superset by design (parity goal).
                                for (i, block) in blocks.iter().enumerate() {
                                    let mut merged = raw_blocks[i].clone();
                                    for &p in &block.predecessors {
                                        if let Some(pb) = raw_blocks.get(p) {
                                            merged.numbers.extend(pb.numbers.iter().cloned());
                                            merged.strings.extend(pb.strings.iter().cloned());
                                        }
                                    }
                                    if !merged.apis.is_empty()
                                        || !merged.numbers.is_empty()
                                        || !merged.strings.is_empty()
                                        || !merged.properties.is_empty()
                                        || !merged.classes.is_empty()
                                        || !merged.namespaces.is_empty()
                                        || merged.unmanaged_call
                                    {
                                        mf.blocks.push(merged);
                                    }
                                }

                                // CFG back-edge detection (RC4) -> characteristic
                                // loop / tight loop. successors are indices into
                                // `blocks`; a back edge targets a block at an
                                // earlier-or-equal RVA.
                                for (i, b) in blocks.iter().enumerate() {
                                    for &s in &b.successors {
                                        if s == i {
                                            mf.has_tight_loop = true;
                                            mf.has_loop = true;
                                        } else if let Some(tb) = blocks.get(s) {
                                            if tb.rva <= b.rva {
                                                mf.has_loop = true;
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                decode_failures += 1;
                                debug!(
                                    ".NET IL decode failed for method {} (rva {:#x}): {:?}",
                                    method.name, rva, e
                                );
                            }
                        }
                    }
                }
            }
        }

        features.method_features.push(mf);
    }

    features.namespaces = namespaces_set.into_iter().collect();
    features.il_mnemonics = il_mnemonics;
    features.il_numbers = il_numbers;
    features.called_tokens = called_tokens;

    // Unmanaged imports: P/Invoke (ImplMap) + native PE import directory,
    // unified by dotscope (G2). generate_symbols yields module.func / func /
    // A-W-stripped variants matching capa's generate_symbols(include_dll=True).
    for dep in assembly.imports().get_all_dll_dependencies() {
        for func in &dep.functions {
            for sym in crate::helpers::generate_symbols(&dep.name, func, true) {
                features.imports.push(sym);
            }
        }
    }

    // Managed resources: names + embedded strings (G9). Resource parse errors
    // are tolerated (non-fatal).
    let resources = assembly.resources();
    for entry in resources.iter() {
        let name = entry.key().clone();
        if !name.is_empty() {
            features.resource_strings.push(name);
        }
        let resource = entry.value();
        if let Some(data) = resources.get_data(resource) {
            for s in extract_blob_strings(data, MIN_STR) {
                features.resource_strings.push(s);
            }
        }
    }

    debug!(
        ".NET IL decode: {} methods w/rva, {} decoded ({} decode fails, {} userstring fails), {} insns, {} mnemonics, {} strings",
        methods_with_rva, methods_decoded, decode_failures, userstring_failures,
        total_instructions, features.il_mnemonics.len(), strings_resolved
    );
    debug!(
        ".NET features: {} user strings, {} classes, {} namespaces, {} methods, {} managed apis, {} unmanaged imports, {} properties, {} resource strings, {} IL numbers",
        features.user_strings.len(),
        features.classes.len(),
        features.namespaces.len(),
        features.methods.len(),
        features.api_calls.len(),
        features.imports.len(),
        features.properties.len(),
        features.resource_strings.len(),
        features.il_numbers.len(),
    );

    Some(features)
}

/// Parse .NET method header to get header size and code size
/// Returns (header_size, code_size) or None if invalid
#[cfg(feature = "dotnet")]
fn parse_method_header(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }

    let first_byte = data[0];

    // Check for tiny header (bit 0-1 = 0b10)
    if (first_byte & 0x03) == 0x02 {
        // Tiny header: 1 byte, code size in upper 6 bits
        let code_size = (first_byte >> 2) as usize;
        return Some((1, code_size));
    }

    // Check for fat header (bit 0-1 = 0b11)
    if (first_byte & 0x03) == 0x03 {
        if data.len() < 12 {
            return None;
        }

        // Fat header is 12 bytes
        // Bytes 0-1: flags and header size (in 4-byte units)
        // Bytes 2-3: max stack
        // Bytes 4-7: code size (little-endian u32)
        // Bytes 8-11: local var sig token

        let header_size = ((data[1] >> 4) as usize) * 4;
        let code_size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;

        return Some((header_size, code_size));
    }

    None
}

/// Stub when dotnet feature is not enabled
#[cfg(not(feature = "dotnet"))]
pub fn extract_dotnet_features(_bytes: &[u8]) -> Option<DotNetExtractedFeatures> {
    None
}

/// Merge .NET features into a FeatureSet (file-level).
pub fn merge_dotnet_features(features: &DotNetExtractedFeatures, feature_set: &mut FeatureSet) {
    // User strings + resource strings + module name -> strings
    for string_info in &features.user_strings {
        feature_set.strings.insert(string_info.value.clone());
    }
    for s in &features.resource_strings {
        feature_set.strings.insert(s.clone());
    }
    if !features.module_name.is_empty() {
        feature_set.strings.insert(features.module_name.clone());
    }

    // Classes / namespaces -> dedicated channels (G4)
    for class in &features.classes {
        feature_set.classes.insert(class.clone());
    }
    for ns in &features.namespaces {
        feature_set.namespaces.insert(ns.clone());
    }

    // Managed member APIs -> apis (G1). No longer dumped into strings.
    for api in &features.api_calls {
        feature_set.apis.insert(api.clone());
    }

    // Unmanaged P/Invoke imports -> apis + imports (G2)
    for imp in &features.imports {
        feature_set.apis.insert(imp.clone());
        feature_set.imports.insert(imp.clone());
    }

    // Property accesses (G5)
    for (name, access) in &features.properties {
        feature_set.properties.push((name.clone(), *access));
    }

    // Method names -> function_names
    for method in &features.methods {
        feature_set.function_names.insert(method.clone());
    }

    // IL mnemonics + numbers
    for (mnemonic, count) in &features.il_mnemonics {
        *feature_set.mnemonics.entry(mnemonic.clone()).or_insert(0) += *count as usize;
    }
    for num in &features.il_numbers {
        feature_set.numbers.insert(*num);
    }
}

/// Merge .NET method features into the functions map (for function-scope
/// matching). Merges into any existing entry at the same RVA rather than
/// overwriting native-lifted analysis.
pub fn merge_dotnet_method_features(
    dotnet_features: &DotNetExtractedFeatures,
    functions: &mut HashMap<Address, FunctionFeatures>,
) {
    for method in &dotnet_features.method_features {
        let addr = Address(method.rva);
        let func_features = functions
            .entry(addr)
            .or_insert_with(|| FunctionFeatures::new(addr));

        func_features
            .features
            .function_names
            .insert(method.name.clone());

        for (mnemonic, count) in &method.mnemonics {
            *func_features
                .features
                .mnemonics
                .entry(mnemonic.clone())
                .or_insert(0) += *count as usize;
        }
        for num in &method.numbers {
            func_features.features.numbers.insert(*num);
        }
        for s in &method.strings {
            func_features.features.strings.insert(s.clone());
        }
        for api in &method.apis {
            func_features.features.apis.insert(api.clone());
        }
        for (name, access) in &method.properties {
            func_features.features.properties.push((name.clone(), *access));
        }
        for c in &method.classes {
            func_features.features.classes.insert(c.clone());
        }
        for ns in &method.namespaces {
            func_features.features.namespaces.insert(ns.clone());
        }

        // Call-graph characteristics (G8)
        if method.calls_out {
            func_features
                .features
                .characteristics
                .insert(CharacteristicType::CallsFrom);
        }
        if method.is_recursive {
            func_features
                .features
                .characteristics
                .insert(CharacteristicType::RecursiveCall);
        }
        if dotnet_features.called_tokens.contains(&method.token_value) {
            func_features
                .features
                .characteristics
                .insert(CharacteristicType::CallsTo);
        }
        if method.unmanaged_call {
            func_features
                .features
                .characteristics
                .insert(CharacteristicType::UnmanagedCall);
        }
        if method.has_loop {
            func_features
                .features
                .characteristics
                .insert(CharacteristicType::Loop);
        }
        if method.has_tight_loop {
            func_features
                .features
                .characteristics
                .insert(CharacteristicType::TightLoop);
        }

        // Instruction-scope features: each call/ldstr/ldc/field instruction gets
        // its own FeatureSet so capa's instruction-scoped rules (create mutex,
        // create socket/thread, WinCrypt hashing, etc.) can match.
        for insn in &method.instructions {
            let mut fs = FeatureSet::new();
            for api in &insn.apis {
                fs.apis.insert(api.clone());
            }
            for num in &insn.numbers {
                fs.numbers.insert(*num);
            }
            for s in &insn.strings {
                fs.strings.insert(s.clone());
            }
            for (name, access) in &insn.properties {
                fs.properties.push((name.clone(), *access));
            }
            for c in &insn.classes {
                fs.classes.insert(c.clone());
            }
            for ns in &insn.namespaces {
                fs.namespaces.insert(ns.clone());
            }
            if insn.unmanaged_call {
                fs.characteristics.insert(CharacteristicType::UnmanagedCall);
            }
            func_features.instructions.insert(Address(insn.rva), fs);
        }

        // Basic-block-scope features: co-located api+number etc. per block.
        for blk in &method.blocks {
            let mut fs = FeatureSet::new();
            for api in &blk.apis {
                fs.apis.insert(api.clone());
            }
            for num in &blk.numbers {
                fs.numbers.insert(*num);
            }
            for s in &blk.strings {
                fs.strings.insert(s.clone());
            }
            for (name, access) in &blk.properties {
                fs.properties.push((name.clone(), *access));
            }
            for c in &blk.classes {
                fs.classes.insert(c.clone());
            }
            for ns in &blk.namespaces {
                fs.namespaces.insert(ns.clone());
            }
            for (mnemonic, count) in &blk.mnemonics {
                *fs.mnemonics.entry(mnemonic.clone()).or_insert(0) += *count as usize;
            }
            if blk.unmanaged_call {
                fs.characteristics.insert(CharacteristicType::UnmanagedCall);
            }
            func_features.basic_blocks.insert(blk.id, fs);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dotnet_features_default() {
        let features = DotNetExtractedFeatures::default();
        assert!(features.user_strings.is_empty());
        assert!(features.classes.is_empty());
        assert!(features.api_calls.is_empty());
    }

    #[cfg(feature = "dotnet")]
    #[test]
    fn test_canonical_api_normalizes_ctor() {
        assert_eq!(
            canonical_api("System.Threading.Mutex", ".ctor"),
            "System.Threading.Mutex::ctor"
        );
        assert_eq!(
            canonical_api("System.Foo", ".cctor"),
            "System.Foo::cctor"
        );
        assert_eq!(canonical_api("System.IO.File", "Delete"), "System.IO.File::Delete");
        assert_eq!(canonical_api("", "Bare"), "Bare");
    }

    #[cfg(feature = "dotnet")]
    #[test]
    fn test_accessor_kind() {
        assert_eq!(
            accessor_kind("get_Length"),
            Some(("Length".to_string(), PropertyAccess::Read))
        );
        assert_eq!(
            accessor_kind("set_Name"),
            Some(("Name".to_string(), PropertyAccess::Write))
        );
        assert_eq!(accessor_kind("Invoke"), None);
    }

    #[cfg(feature = "dotnet")]
    #[test]
    fn test_extract_blob_strings_ascii_and_utf16() {
        // Non-printable bytes separate the two runs.
        let mut data = b"hello\x00\x01world".to_vec();
        let found = extract_blob_strings(&data, 4);
        assert!(found.iter().any(|s| s == "hello"));
        assert!(found.iter().any(|s| s == "world"));

        // UTF-16LE "test"
        data = vec![b't', 0, b'e', 0, b's', 0, b't', 0];
        let found = extract_blob_strings(&data, 4);
        assert!(found.iter().any(|s| s == "test"));
    }
}
