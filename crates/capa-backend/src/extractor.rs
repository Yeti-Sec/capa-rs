//! Feature extraction from binaries
//!
//! Extracts CAPA features from lifted binary code using iced-x86/capstone.

use aho_corasick::AhoCorasick;
use capa_core::error::Result;
use capa_core::feature::{Address, ExtractedFeatures, FeatureExtractor, FeatureSet, FunctionFeatures};
use capa_core::rule::{ArchType, CharacteristicType, OsType};
use log::debug;
use memchr::memmem;
use std::collections::HashMap;
use std::sync::OnceLock;

/// Normalize module name by stripping the `.dll`/`.DLL` extension.
/// CAPA rules use `kernel32.VirtualAlloc` not `KERNEL32.dll.VirtualAlloc`.
fn normalize_module(module: &str) -> String {
    let m = module.strip_suffix(".dll")
        .or_else(|| module.strip_suffix(".DLL"))
        .or_else(|| module.strip_suffix(".Dll"))
        .unwrap_or(module);
    m.to_string()
}

/// Format a qualified API name as `module.function` with normalized module name.
fn format_api(module: &Option<String>, name: &str) -> String {
    if let Some(ref m) = module {
        format!("{}.{}", normalize_module(m), name)
    } else {
        name.to_string()
    }
}

/// Insert an API name into a set using `helpers::generate_symbols` for variant generation.
/// This matches Python's `pefile.py` which calls `generate_symbols(module, name, include_dll=True)`
/// for import features. Also handles Ex suffix variants for broader matching.
fn insert_api(apis: &mut std::collections::HashSet<String>, module: &Option<String>, name: &str) {
    let module_str = module.as_ref().map(|m| normalize_module(m)).unwrap_or_default();

    // Use generate_symbols for standard variant generation (A/W stripping, dll.api forms)
    // include_dll=true for imports (matching Python's pefile.py:94)
    for symbol in crate::helpers::generate_symbols(&module_str, name, module.is_some()) {
        apis.insert(symbol);
    }

    // Also handle Ex suffix variants: CreateFileExW -> CreateFileEx, CreateFile
    // This extends beyond generate_symbols to match capa's broader API normalization
    if name.len() > 2 && name.ends_with("Ex") {
        let base = &name[..name.len() - 2];
        if !base.is_empty() {
            apis.insert(base.to_string());
            apis.insert(format_api(module, base));
        }
    }
    if name.len() > 3 && (name.ends_with("ExA") || name.ends_with("ExW")) {
        let base = &name[..name.len() - 3];
        if !base.is_empty() {
            apis.insert(format!("{}Ex", base));
            apis.insert(format_api(module, &format!("{}Ex", base)));
            apis.insert(base.to_string());
            apis.insert(format_api(module, base));
        }
    }
}
use crate::lifter::{lift_binary, ILOperation, LiftedBasicBlock, LiftedProgram};
use crate::loader::{load_binary, BinaryInfo};
use crate::dotnet_extractor::{extract_dotnet_features, merge_dotnet_features, merge_dotnet_method_features};

/// Multi-pattern byte matcher for efficient batch searching
#[derive(Debug)]
pub struct BytePatternMatcher {
    patterns: Vec<Vec<u8>>,
    automaton: Option<AhoCorasick>,
}

impl BytePatternMatcher {
    /// Create a new matcher with the given patterns
    pub fn new(patterns: Vec<Vec<u8>>) -> Self {
        let automaton = if !patterns.is_empty() {
            AhoCorasick::new(&patterns).ok()
        } else {
            None
        };
        Self { patterns, automaton }
    }

    /// Find all matches in the binary
    /// Returns a map of pattern index -> list of match offsets
    pub fn find_all(&self, bytes: &[u8]) -> HashMap<usize, Vec<u64>> {
        let mut results: HashMap<usize, Vec<u64>> = HashMap::new();

        if let Some(ref automaton) = self.automaton {
            for mat in automaton.find_iter(bytes) {
                results
                    .entry(mat.pattern().as_usize())
                    .or_default()
                    .push(mat.start() as u64);
            }
        }

        results
    }

    /// Check if any pattern matches in the binary
    pub fn has_any_match(&self, bytes: &[u8]) -> bool {
        if let Some(ref automaton) = self.automaton {
            automaton.find(bytes).is_some()
        } else {
            false
        }
    }

    /// Get pattern by index
    pub fn get_pattern(&self, index: usize) -> Option<&[u8]> {
        self.patterns.get(index).map(|v| v.as_slice())
    }
}

/// Feature extractor using goblin for PE/ELF parsing (basic)
#[derive(Debug, Default)]
pub struct GoblinExtractor;

impl GoblinExtractor {
    pub fn new() -> Self {
        Self
    }

    fn binary_info_to_features(&self, info: &BinaryInfo) -> ExtractedFeatures {
        let mut features = ExtractedFeatures::new(info.os, info.arch, info.format);

        // Add imports (with A/W suffix normalization)
        for import in &info.imports {
            insert_api(&mut features.file.imports, &import.module, &import.name);
        }

        // Add exports
        for export in &info.exports {
            features.file.exports.insert(export.name.clone());
        }

        // Add sections
        for section in &info.sections {
            features.file.sections.insert(section.name.clone());
        }

        // Add strings
        for string_info in &info.strings {
            features.file.strings.insert(string_info.value.clone());
        }

        features
    }
}

impl FeatureExtractor for GoblinExtractor {
    fn extract(&self, binary: &[u8]) -> Result<ExtractedFeatures> {
        let info = load_binary(binary).map_err(|e| {
            capa_core::error::CapaError::ExtractionError(e.to_string())
        })?;

        let mut features = self.binary_info_to_features(&info);

        // Extract .NET-specific features if this is a .NET assembly
        if info.is_dotnet {
            debug!("Detected .NET assembly, extracting .NET-specific features");
            if let Some(dotnet_features) = extract_dotnet_features(binary) {
                merge_dotnet_features(&dotnet_features, &mut features.file);
                debug!(
                    ".NET extraction complete: {} user strings, {} classes, {} API calls",
                    dotnet_features.user_strings.len(),
                    dotnet_features.classes.len(),
                    dotnet_features.api_calls.len()
                );
            }
        }

        Ok(features)
    }

    fn extract_file_features(&self, binary: &[u8]) -> Result<FeatureSet> {
        let features = self.extract(binary)?;
        Ok(features.file)
    }

    fn extract_function_features(&self, _binary: &[u8], addr: Address) -> Result<FunctionFeatures> {
        Ok(FunctionFeatures::new(addr))
    }
}

#[derive(Debug, Clone)]
struct VaSegment {
    va_start: u64,
    file_start: u64,
    raw_size: u64,
}

/// Maps between raw file offsets and virtual addresses for PE/ELF images.
#[derive(Debug, Default, Clone)]
pub(crate) struct BinaryVaMap {
    segments: Vec<VaSegment>,
}

impl BinaryVaMap {
    pub(crate) fn from_bytes(bytes: &[u8]) -> Self {
        use goblin::Object;
        let mut segments = Vec::new();
        if let Ok(obj) = Object::parse(bytes) {
            match obj {
                Object::PE(pe) => {
                    let image_base = pe.image_base as u64;
                    for sec in &pe.sections {
                        let raw_size = sec.size_of_raw_data as u64;
                        if raw_size > 0 {
                            segments.push(VaSegment {
                                va_start: image_base.wrapping_add(sec.virtual_address as u64),
                                file_start: sec.pointer_to_raw_data as u64,
                                raw_size,
                            });
                        }
                    }
                }
                Object::Elf(elf) => {
                    for ph in &elf.program_headers {
                        if ph.p_type == goblin::elf::program_header::PT_LOAD && ph.p_filesz > 0 {
                            segments.push(VaSegment {
                                va_start: ph.p_vaddr,
                                file_start: ph.p_offset,
                                raw_size: ph.p_filesz,
                            });
                        }
                    }
                }
                _ => {}
            }
        }
        Self { segments }
    }

    #[allow(dead_code)]
    pub(crate) fn file_offset_to_va(&self, file_off: u64) -> Option<u64> {
        for seg in &self.segments {
            if file_off >= seg.file_start && file_off < seg.file_start + seg.raw_size {
                return Some(seg.va_start + (file_off - seg.file_start));
            }
        }
        None
    }

    pub(crate) fn slice_at_va<'a>(&self, bytes: &'a [u8], va: u64, max_len: usize) -> Option<&'a [u8]> {
        for seg in &self.segments {
            if va >= seg.va_start && va < seg.va_start + seg.raw_size {
                let off = (seg.file_start + (va - seg.va_start)) as usize;
                let end_bound = ((seg.file_start + seg.raw_size) as usize).min(bytes.len());
                if off < end_bound {
                    let take = (end_bound - off).min(max_len);
                    if take > 0 {
                        return Some(&bytes[off..off + take]);
                    }
                }
            }
        }
        None
    }
}

/// Insert a FLIRT-recognized `is_library` callee's C/WinAPI name into `apis` (e.g. `_getenv` -> `getenv`),
/// ignoring auto-generated IDA labels and C++ mangled (`?` / `$`) internal helpers.
fn insert_flirt_library_callee_api(
    target: u64,
    program: &LiftedProgram,
    apis: &mut std::collections::HashSet<String>,
) {
    let Some(callee) = program.functions.get(&target) else {
        return;
    };
    if !callee.is_library {
        return;
    }
    let Some(raw_name) = callee.name.as_deref() else {
        return;
    };
    let name = raw_name.trim();
    if name.is_empty()
        || name.starts_with('?')
        || name.starts_with('$')
        || name.starts_with('@')
        || name.starts_with("sub_")
        || name.starts_with("nullsub_")
        || name.starts_with("loc_")
        || name.starts_with("__security_")
        || name.starts_with("_RTC_")
        || name.starts_with("__scrt_")
        || name.starts_with("__crt")
    {
        return;
    }
    insert_api(apis, &None, name);
    if let Some(stripped) = name.strip_prefix('_') {
        if !stripped.is_empty() && !stripped.starts_with('_') {
            insert_api(apis, &None, stripped);
        }
    }
}

/// Check if a function's basic-block directed graph contains a multi-block cycle
/// (Tarjan strongly connected component with `len >= 2`, matching Python capa's
/// `loops.has_loop(edges, threshold=2)`). Falls back to `bb.is_loop_header` only
/// for synthetic unit-test blocks constructed without CFG edges.
fn has_cfg_loop(blocks: &[LiftedBasicBlock]) -> bool {
    let any_edges = blocks
        .iter()
        .any(|bb| !bb.successors.is_empty() || !bb.predecessors.is_empty());
    if !any_edges {
        return blocks.iter().any(|bb| bb.is_loop_header);
    }

    let n = blocks.len();
    let mut idx_to_pos = std::collections::HashMap::with_capacity(n);
    for (pos, bb) in blocks.iter().enumerate() {
        idx_to_pos.insert(bb.index, pos);
    }

    struct TarjanState {
        index: usize,
        indices: Vec<Option<usize>>,
        lowlink: Vec<usize>,
        on_stack: Vec<bool>,
        stack: Vec<usize>,
        found_multi_cycle: bool,
    }

    fn strongconnect(
        v: usize,
        blocks: &[LiftedBasicBlock],
        idx_to_pos: &std::collections::HashMap<usize, usize>,
        st: &mut TarjanState,
    ) {
        st.indices[v] = Some(st.index);
        st.lowlink[v] = st.index;
        st.index += 1;
        st.stack.push(v);
        st.on_stack[v] = true;

        for &succ_id in &blocks[v].successors {
            let Some(&w) = idx_to_pos.get(&succ_id) else {
                continue;
            };
            if st.indices[w].is_none() {
                strongconnect(w, blocks, idx_to_pos, st);
                st.lowlink[v] = st.lowlink[v].min(st.lowlink[w]);
            } else if st.on_stack[w] {
                st.lowlink[v] = st.lowlink[v].min(st.indices[w].unwrap());
            }
            if st.found_multi_cycle {
                return;
            }
        }

        if Some(st.lowlink[v]) == st.indices[v] {
            let mut scc_len = 0usize;
            loop {
                let w = st.stack.pop().unwrap();
                st.on_stack[w] = false;
                scc_len += 1;
                if w == v {
                    break;
                }
            }
            if scc_len >= 2 {
                st.found_multi_cycle = true;
            }
        }
    }

    let mut st = TarjanState {
        index: 0,
        indices: vec![None; n],
        lowlink: vec![0; n],
        on_stack: vec![false; n],
        stack: Vec::with_capacity(n),
        found_multi_cycle: false,
    };

    for v in 0..n {
        if st.indices[v].is_none() {
            strongconnect(v, blocks, &idx_to_pos, &mut st);
            if st.found_multi_cycle {
                return true;
            }
        }
    }
    false
}

/// True for `add sp/esp/rsp, imm` stack-cleanup instructions (matching Python capa
/// `viv/insn.py` line 487: `insn.mnem == "add" and oper0 in (ESP, RSP)`), while keeping
/// `retn 4` / `sub esp, 4` immediates intact (`allocate or change RW memory`).
fn is_add_sp_insn(insn: &crate::lifter::LiftedInstruction) -> bool {
    if insn.mnemonic == "add" {
        if let Some(dst) = insn.operands.first() {
            let d = dst.trim().to_lowercase();
            if matches!(d.as_str(), "sp" | "esp" | "rsp") {
                return true;
            }
        }
    }
    false
}

/// True when a memory operand uses the hardware stack pointer (`sp`/`esp`/`rsp`)
/// without an `fs:`/`gs:` segment prefix (safe now that `ida_lifter` decodes REX.B + SIB
/// so `[r12+...]` and `[rax+rcx+...]` are never misformatted as `[rsp+...]`).
fn is_stack_frame_mem_operand(op: &str) -> bool {
    let op_lower = op.to_lowercase();
    if op_lower.contains("fs:") || op_lower.contains("gs:") {
        return false;
    }
    let Some(b_start) = op_lower.find('[') else {
        return false;
    };
    let Some(b_end) = op_lower.find(']') else {
        return false;
    };
    let inside = op_lower[b_start + 1..b_end].trim();
    matches!(inside, "sp" | "esp" | "rsp")
}

/// Map x86/x64 GPR sub-registers to a canonical 64-bit register family key for
/// intra-procedural `mov reg, [IAT] -> call reg` tracking.
fn canonical_gpr(op: &str) -> Option<&'static str> {
    match op.trim().to_lowercase().as_str() {
        "rax" | "eax" | "ax" | "al" => Some("rax"),
        "rbx" | "ebx" | "bx" | "bl" => Some("rbx"),
        "rcx" | "ecx" | "cx" | "cl" => Some("rcx"),
        "rdx" | "edx" | "dx" | "dl" => Some("rdx"),
        "rsi" | "esi" | "si" | "sil" => Some("rsi"),
        "rdi" | "edi" | "di" | "dil" => Some("rdi"),
        "rbp" | "ebp" | "bp" | "bpl" => Some("rbp"),
        "r8" | "r8d" | "r8w" | "r8b" => Some("r8"),
        "r9" | "r9d" | "r9w" | "r9b" => Some("r9"),
        "r10" | "r10d" | "r10w" | "r10b" => Some("r10"),
        "r11" | "r11d" | "r11w" | "r11b" => Some("r11"),
        "r12" | "r12d" | "r12w" | "r12b" => Some("r12"),
        "r13" | "r13d" | "r13w" | "r13b" => Some("r13"),
        "r14" | "r14d" | "r14w" | "r14b" => Some("r14"),
        "r15" | "r15d" | "r15w" | "r15b" => Some("r15"),
        _ => None,
    }
}

/// Propagate `mov reg, [IAT]` across a function's CFG so register-indirect `call reg` /
/// `jmp reg` instructions (e.g. `mov rbx, [__imp_getenv]; ...; call rbx`) emit the
/// resolved API at the `call`/`jmp` site without emitting false APIs on data loads.
fn resolve_reg_indirect_iat_calls(
    extractor: &BinaryExtractor,
    func: &crate::lifter::LiftedFunction,
    info: &BinaryInfo,
    program: &LiftedProgram,
) -> std::collections::HashMap<u64, Vec<(Option<String>, String)>> {
    use std::collections::HashMap;
    let mut resolved_at: HashMap<u64, Vec<(Option<String>, String)>> = HashMap::new();
    if func.basic_blocks.is_empty() {
        return resolved_at;
    }

    let mut in_envs: HashMap<usize, HashMap<&'static str, (Option<String>, String)>> = HashMap::new();

    for pass in 0..2 {
        for bb in &func.basic_blocks {
            let mut env = in_envs.get(&bb.index).cloned().unwrap_or_default();
            for insn in &bb.instructions {
                if insn.mnemonic == "mov" && insn.operands.len() >= 2 {
                    if let Some(dst_reg) = canonical_gpr(&insn.operands[0]) {
                        let src = &insn.operands[1];
                        let mut loaded: Option<(Option<String>, String)> = None;
                        if src.contains('[') && src.contains("0x") {
                            if let Some(addr) = extractor.parse_memory_address(src, insn.address, insn.bytes.len()) {
                                if let Some(entry) = program.iat_entries.get(&addr) {
                                    loaded = Some(entry.clone());
                                } else if let Some(imp) = info.imports.iter().find(|i| i.address == addr) {
                                    loaded = Some((imp.module.clone(), imp.name.clone()));
                                }
                            }
                        } else if let Some(src_reg) = canonical_gpr(src) {
                            loaded = env.get(src_reg).cloned();
                        }
                        if let Some(val) = loaded {
                            env.insert(dst_reg, val);
                        } else {
                            env.remove(dst_reg);
                        }
                    }
                } else if insn.mnemonic == "call" || insn.mnemonic == "jmp" {
                    if let Some(op0) = insn.operands.first() {
                        if let Some(reg) = canonical_gpr(op0) {
                            if pass == 1 {
                                if let Some(entry) = env.get(reg) {
                                    resolved_at.entry(insn.address).or_default().push(entry.clone());
                                }
                            }
                        }
                    }
                    if insn.mnemonic == "call" {
                        for scratch in ["rax", "rcx", "rdx", "r8", "r9", "r10", "r11"] {
                            env.remove(scratch);
                        }
                    }
                } else if !matches!(insn.mnemonic.as_str(), "cmp" | "test" | "push" | "nop") {
                    if let Some(op0) = insn.operands.first() {
                        if let Some(dst_reg) = canonical_gpr(op0) {
                            env.remove(dst_reg);
                        }
                    }
                }
            }

            for &succ_idx in &bb.successors {
                let succ_in = in_envs.entry(succ_idx).or_default();
                for (&k, v) in &env {
                    succ_in.entry(k).or_insert_with(|| v.clone());
                }
            }
        }
    }

    resolved_at
}

/// True when `op` is a single-base register + displacement (`[r8+0x10]` or `[rcx-0x30]`)
/// without SIB index/scale (`*` or multiple `+`/`-`), matching Python capa's `lea` -> `Number` rule.
fn is_lea_single_base_displ(op: &str) -> bool {
    let op_lower = op.to_lowercase();
    let Some(b_start) = op_lower.find('[') else {
        return false;
    };
    let Some(b_end) = op_lower.find(']') else {
        return false;
    };
    let inside = op_lower[b_start + 1..b_end].trim();
    if inside.is_empty() || inside.contains('*') {
        return false;
    }
    if !inside.chars().next().map_or(false, |c| c.is_ascii_alphabetic()) {
        return false;
    }
    let sign_count = inside.chars().filter(|&c| c == '+' || c == '-').count();
    sign_count == 1
}

/// Full-featured extractor using iced/vivisect disassembly
#[derive(Debug, Default)]
pub struct BinaryExtractor;

impl BinaryExtractor {
    pub fn new() -> Self {
        Self
    }

    /// Extract features from a lifted program
    pub(crate) fn extract_from_lifted(&self, program: &LiftedProgram, bytes: &[u8]) -> ExtractedFeatures {
        let info = &program.info;
        let va_map = BinaryVaMap::from_bytes(bytes);
        let mut features = ExtractedFeatures::new(info.os, info.arch, info.format);

        // File-level features from binary info (with A/W suffix normalization)
        for import in &info.imports {
            insert_api(&mut features.file.imports, &import.module, &import.name);
        }

        for export in &info.exports {
            features.file.exports.insert(export.name.clone());
            // Issue 10: Also add forwarded export target names as function names
            if export.is_forwarded {
                if let Some(ref target) = export.forward_target {
                    features.file.function_names.insert(target.clone());
                }
            }
        }

        for section in &info.sections {
            features.file.sections.insert(section.name.clone());
        }

        for string_info in &info.strings {
            features.file.strings.insert(string_info.value.clone());
        }

        // Issue 8: Improved PE carving - scan raw bytes for embedded PE files
        if self.has_embedded_pe_bytes(bytes) {
            features.file.add_characteristic(CharacteristicType::EmbeddedPe);
        }

        // Check for forwarded exports
        if info.has_forwarded_exports {
            features.file.add_characteristic(CharacteristicType::ForwardedExport);
        }

        // Check for mixed-mode assembly (.NET + native)
        if info.is_mixed_mode {
            features.file.add_characteristic(CharacteristicType::MixedMode);
        }

        // Issue 9: COM detection - check for COM-related imports
        self.detect_com_features(info, &mut features.file);

        // Extract function-level features
        for (addr, func) in &program.functions {
            // Issue 1: Skip library/thunk functions from feature extraction
            if func.is_library || func.is_thunk {
                continue;
            }

            let mut func_features = FunctionFeatures::new(Address(*addr));
            func_features.name = func.name.clone();

            // Check for multi-block CFG cycles (Tarjan SCC >= 2, matching Python capa)
            if has_cfg_loop(&func.basic_blocks) {
                func_features.features.add_characteristic(CharacteristicType::Loop);
            }

            // Check for recursive calls
            if func.callees.contains(addr) {
                func_features.features.add_characteristic(CharacteristicType::RecursiveCall);
            }

            // Incoming callers count (`calls to`)
            let unique_callers: std::collections::HashSet<u64> = func.callers.iter().copied().collect();
            for _ in 0..unique_callers.len() {
                func_features.features.add_characteristic(CharacteristicType::CallsTo);
            }

            // Outgoing unique call targets count (`calls from`), deduplicated by target
            // address to match Python capa's `FeatureSet[Characteristic("calls from")]` set.
            let unique_callees: std::collections::HashSet<u64> = func.callees.iter().copied().collect();
            for _ in 0..unique_callees.len() {
                func_features.features.add_characteristic(CharacteristicType::CallsFrom);
            }

            // Propagate `mov reg, [IAT] -> call reg / jmp reg` across CFG blocks
            let reg_indirect_apis_at = resolve_reg_indirect_iat_calls(self, func, info, program);

            // Extract basic block features
            for bb in &func.basic_blocks {
                let mut bb_features = self.extract_basic_block_features(bb, info, program);
                for insn in &bb.instructions {
                    if let Some(reg_apis) = reg_indirect_apis_at.get(&insn.address) {
                        for (module, name) in reg_apis {
                            insert_api(&mut bb_features.apis, module, name);
                        }
                    }
                }

                // Detect stack string construction at BB scope
                if self.detect_stack_strings_in_bb(bb) {
                    bb_features.add_characteristic(CharacteristicType::StackString);
                }

                // Debug: Check for blocks with both TightLoop and Nzxor
                if bb_features.characteristics.contains(&CharacteristicType::TightLoop)
                    && bb_features.characteristics.contains(&CharacteristicType::Nzxor) {
                    // This block has tight loop with nzxor - good for XOR encryption detection
                }

                func_features.basic_block_addresses.insert(bb.index, Address(bb.address));
                func_features.basic_block_instructions.insert(
                    bb.index,
                    bb.instructions.iter().map(|i| Address(i.address)).collect(),
                );
                func_features.basic_blocks.insert(bb.index, bb_features.clone());

                // Roll up set-valued summary fields to function level without
                // duplicating additive counts (`mnemonics`, `characteristic_counts`)
                // that `func.all_features()` already sums across basic blocks.
                func_features.features.merge_sets_only(&bb_features);
            }

            // Set basic block count for count(basic block) feature
            func_features.features.basic_block_count = func.basic_blocks.len();

            // Extract instruction features
            for bb in &func.basic_blocks {
                for insn in &bb.instructions {
                    let mut insn_features = self.extract_instruction_features(insn, info, program, bytes, &va_map);
                    if let Some(reg_apis) = reg_indirect_apis_at.get(&insn.address) {
                        for (module, name) in reg_apis {
                            insert_api(&mut insn_features.apis, module, name);
                        }
                    }
                    func_features.instructions.insert(Address(insn.address), insn_features.clone());
                }
            }

            features.functions.insert(Address(*addr), func_features);
        }

        // Roll up set-valued summary fields to file level (for CLI summary stats)
        // without duplicating additive counts summed by `features.all_features()`.
        for func in features.functions.values() {
            features.file.merge_sets_only(&func.features);
        }

        // Log extraction summary
        log::debug!("Extraction: {} functions, {} APIs, {} thunks, {} IAT entries, {} strings_at",
            features.functions.len(), features.file.apis.len(),
            program.thunk_targets.len(), program.iat_entries.len(), program.strings_at.len());

        features
    }

    /// Extract features from a basic block
    fn extract_basic_block_features(&self, bb: &LiftedBasicBlock, info: &BinaryInfo, program: &LiftedProgram) -> FeatureSet {
        let mut features = FeatureSet::new();

        // Check for tight loop: basic block branches directly back to itself
        // (`bb.successors.contains(&bb.index)`, matching Python capa's
        // `is_basic_block_tight_loop`). Preserve fallback for synthetic unit-test blocks
        // built without CFG edges.
        let has_cfg_edges = !bb.successors.is_empty() || !bb.predecessors.is_empty();
        let is_tight_loop = if has_cfg_edges {
            bb.successors.contains(&bb.index)
        } else {
            bb.is_loop_header && bb.instructions.len() <= 10
        };
        if is_tight_loop {
            features.add_characteristic(CharacteristicType::TightLoop);
        }

        // Check for nzxor in block (counted per instruction for count(characteristic(nzxor)))
        for insn in &bb.instructions {
            if self.is_nzxor(insn) {
                features.add_characteristic(CharacteristicType::Nzxor);
            }
        }

        // Collect mnemonics
        for insn in &bb.instructions {
            *features.mnemonics.entry(insn.mnemonic.clone()).or_insert(0) += 1;
        }

        // Collect numeric constants (excluding `add sp/esp/rsp, imm`)
        for insn in &bb.instructions {
            if is_add_sp_insn(insn) {
                continue;
            }
            for val in insn.operand_values.iter().flatten() {
                features.numbers.insert(*val);
            }
        }

        // Check for API calls (`call` and tailcall `jmp`, matching Python capa)
        for insn in &bb.instructions {
            if insn.mnemonic == "call" || insn.mnemonic == "jmp" {
                // Try to resolve call/jmp target to import (direct call/jmp)
                for op in &insn.operations {
                    if let ILOperation::Branch { target: Some(target), .. } = op {
                        // First check if target is a direct import
                        if let Some(import) = info.imports.iter().find(|i| i.address == *target) {
                            insert_api(&mut features.apis, &import.module, &import.name);
                        }
                        // Issue 5/6: Check if target is a thunk function
                        else if let Some(api_name) = program.thunk_targets.get(target) {
                            // Thunk targets are already formatted as "module.name"
                            if let Some(dot_pos) = api_name.rfind('.') {
                                let module = Some(api_name[..dot_pos].to_string());
                                let name = &api_name[dot_pos + 1..];
                                insert_api(&mut features.apis, &module, name);
                            } else {
                                insert_api(&mut features.apis, &None, api_name);
                            }
                        } else {
                            insert_flirt_library_callee_api(*target, program, &mut features.apis);
                        }
                    }
                }

                // Check for indirect call/jmp through IAT (`call [rip+X]` or `call [address]`)
                for operand in &insn.operands {
                    if operand.contains('[') && operand.contains("0x") {
                        if let Some(addr) = self.parse_memory_address(operand, insn.address, insn.bytes.len()) {
                            // Issue 5: Check IAT map for indirect calls
                            if let Some((module, name)) = program.iat_entries.get(&addr) {
                                insert_api(&mut features.apis, module, name);
                            }
                            // Legacy: also check imports directly
                            else if let Some(import) = info.imports.iter().find(|i| i.address == addr) {
                                insert_api(&mut features.apis, &import.module, &import.name);
                            }
                        }
                    }
                }

                if let Some(apis_here) = program.import_apis_at.get(&insn.address) {
                    for (module, name) in apis_here {
                        insert_api(&mut features.apis, module, name);
                    }
                }
            }

            if let Some(strs_here) = program.insn_strings_at.get(&insn.address) {
                for s in strs_here {
                    features.strings.insert(s.clone());
                }
            }

            // Issue 4: Detect strings referenced by memory operands (any instruction, not just call)
            for operand in &insn.operands {
                if operand.contains('[') && operand.contains("0x") {
                    if let Some(addr) = self.parse_memory_address(operand, insn.address, insn.bytes.len()) {
                        // Check if the referenced address contains a string
                        if let Some(s) = program.strings_at.get(&addr) {
                            features.strings.insert(s.clone());
                        }
                    }
                }
                // Also check immediate values that might be string pointers
                if operand.starts_with("0x") && !operand.contains('[') {
                    if let Ok(addr) = u64::from_str_radix(&operand[2..], 16) {
                        if let Some(s) = program.strings_at.get(&addr) {
                            features.strings.insert(s.clone());
                        }
                    }
                }
            }
            // Check operand_values for string pointers too (skipping branch/call targets)
            if insn.mnemonic != "call" && !insn.mnemonic.starts_with('j') {
                for val in insn.operand_values.iter().flatten() {
                    let addr = *val as u64;
                    if let Some(s) = program.strings_at.get(&addr) {
                        features.strings.insert(s.clone());
                    }
                }
            }
        }

        // Check for indirect calls (counted per indirect call instruction)
        for insn in &bb.instructions {
            if insn.mnemonic == "call" {
                for op in &insn.operations {
                    if let ILOperation::Branch { target: None, is_call: true } = op {
                        features.add_characteristic(CharacteristicType::IndirectCall);
                    }
                }
            }
        }

        // Check for FS/GS segment access (anti-debug, PEB access on Windows)
        // On Windows x86: FS points to TEB, FS:[0x30] is PEB pointer
        // On Windows x64: GS points to TEB, GS:[0x60] is PEB pointer
        // On Linux: FS/GS are used for TLS, not PEB (no PEB exists)
        for insn in &bb.instructions {
            for op in &insn.operands {
                let op_lower = op.to_lowercase();
                if op_lower.contains("fs:") {
                    features.add_characteristic(CharacteristicType::FsAccess);
                    // PEB access requires specific TEB offset on Windows
                    if info.os == OsType::Windows && self.operand_has_offset(&op_lower, 0x30) {
                        features.add_characteristic(CharacteristicType::Peb);
                    }
                }
                if op_lower.contains("gs:") {
                    features.add_characteristic(CharacteristicType::GsAccess);
                    if info.os == OsType::Windows && info.arch == ArchType::Amd64
                        && self.operand_has_offset(&op_lower, 0x60)
                    {
                        features.add_characteristic(CharacteristicType::Peb);
                    }
                }
            }
        }

        // Extract offset values from memory references
        for insn in &bb.instructions {
            for offset in self.extract_offsets(insn) {
                features.offsets.insert(offset);
            }
        }

        // Check for call-next pattern (shellcode/position-independent code)
        if self.detect_call_next(bb) {
            features.add_characteristic(CharacteristicType::CallsFromShellcode);
        }

        // Check for call $+5 pattern (get EIP/RIP)
        if self.detect_call_plus_5(bb) {
            features.add_characteristic(CharacteristicType::CallPlus5);
        }

        // Check for unmangled API calls
        if self.detect_unmangled_call(bb, info) {
            features.add_characteristic(CharacteristicType::UnmangledCall);
        }

        // Check for cross-section flow
        if self.detect_cross_section_flow(bb, info) {
            features.add_characteristic(CharacteristicType::CrossSectionFlow);
        }

        features
    }

    /// Resolve an instruction's call/jmp target to an API name (direct import,
    /// thunk, IAT-indirect, or IDA xref chain) and insert it into `apis`.
    /// Restricted to `call` and `jmp` instructions to match Python capa (`insn.py`),
    /// avoiding false API hits on global data reads (`mov rax, [__imp__wpgmptr]`).
    fn resolve_instruction_apis(
        &self,
        insn: &crate::lifter::LiftedInstruction,
        info: &BinaryInfo,
        program: &LiftedProgram,
        apis: &mut std::collections::HashSet<String>,
    ) {
        if insn.mnemonic != "call" && insn.mnemonic != "jmp" {
            return;
        }
        for op in &insn.operations {
            if let ILOperation::Branch { target: Some(target), .. } = op {
                if let Some(import) = info.imports.iter().find(|i| i.address == *target) {
                    insert_api(apis, &import.module, &import.name);
                } else if let Some(api_name) = program.thunk_targets.get(target) {
                    if let Some(dot_pos) = api_name.rfind('.') {
                        let module = Some(api_name[..dot_pos].to_string());
                        insert_api(apis, &module, &api_name[dot_pos + 1..]);
                    } else {
                        insert_api(apis, &None, api_name);
                    }
                } else {
                    insert_flirt_library_callee_api(*target, program, apis);
                }
            }
        }
        for operand in &insn.operands {
            if operand.contains('[') && operand.contains("0x") {
                if let Some(addr) = self.parse_memory_address(operand, insn.address, insn.bytes.len()) {
                    if let Some((module, name)) = program.iat_entries.get(&addr) {
                        insert_api(apis, module, name);
                    } else if let Some(import) = info.imports.iter().find(|i| i.address == addr) {
                        insert_api(apis, &import.module, &import.name);
                    }
                }
            }
        }
        if let Some(apis_here) = program.import_apis_at.get(&insn.address) {
            for (module, name) in apis_here {
                insert_api(apis, module, name);
            }
        }
    }

    /// Extract features from a single instruction
    fn extract_instruction_features(
        &self,
        insn: &crate::lifter::LiftedInstruction,
        info: &BinaryInfo,
        program: &LiftedProgram,
        image_bytes: &[u8],
        va_map: &BinaryVaMap,
    ) -> FeatureSet {
        const MAX_STRUCTURE_SIZE: i64 = 0x10000;
        let mut features = FeatureSet::new();

        // Mnemonic
        *features.mnemonics.entry(insn.mnemonic.clone()).or_insert(0) += 1;

        // API resolution (`call`/`jmp` only)
        self.resolve_instruction_apis(insn, info, program, &mut features.apis);

        // IDA `DataRefsFrom` string references
        if let Some(strs_here) = program.insn_strings_at.get(&insn.address) {
            for s in strs_here {
                features.strings.insert(s.clone());
            }
        }

        let skip_numbers = is_add_sp_insn(insn);
        let max_ops = insn.operand_values.len().max(insn.operands.len());

        // Operand values and offsets
        for idx in 0..max_ops {
            let mut num = if skip_numbers {
                None
            } else {
                insn.operand_values.get(idx).and_then(|v| *v)
            };
            if let Some(v) = num {
                features.numbers.insert(v);
            }

            // Extract offset from this operand's memory reference
            let mut offset = insn
                .operands
                .get(idx)
                .and_then(|op_str| self.extract_operand_offset(op_str));
            if let Some(off) = offset {
                features.offsets.insert(off);
            }

            // Python capa `insn.py` rule 1: `add reg, imm` (`0 < imm < 0x10000`, non-SP)
            // also yields `Offset(imm)` + `OperandOffset(idx, imm)` (e.g. `add rcx, 0x18`
            // in `enumerate PE sections` and `add rax, 0x88` in `resolve function by parsing PE exports`).
            if insn.mnemonic == "add" && !skip_numbers && offset.is_none() {
                if let Some(v) = num {
                    if v > 0 && v < MAX_STRUCTURE_SIZE {
                        features.offsets.insert(v);
                        offset = Some(v);
                    }
                }
            }

            // Python capa `insn.py` rule 2: `lea reg, [base + disp]` (operand 1 without SIB scale/index)
            // also yields `Number(disp)` + `OperandNumber(1, disp)` (e.g. `lea edx, [r8 + 0x10]`
            // and `lea eax, [rbx + 1]`).
            if insn.mnemonic == "lea" && idx == 1 && num.is_none() {
                if let (Some(off), Some(op_str)) = (offset, insn.operands.get(1)) {
                    if is_lea_single_base_displ(op_str) {
                        features.numbers.insert(off);
                        num = Some(off);
                    }
                }
            }

            if num.is_some() || offset.is_some() {
                features.operands.push((idx, num, offset));
            }
        }

        // Record per-instruction occurrence counts (1 per distinct constant/offset on this insn,
        // matching Python capa's `set[Address]` feature cardinality).
        for &n in &features.numbers {
            features.number_counts.insert(n, 1);
        }
        for &o in &features.offsets {
            features.offset_counts.insert(o, 1);
        }

        // Bytes: raw instruction bytes + up to 0x100 bytes at referenced data pointers
        // (matching Python capa's `extract_insn_bytes` for COM GUIDs, S-boxes, etc.)
        if !insn.bytes.is_empty() {
            features.bytes_sequences.push(insn.bytes.clone());
        }
        if let Some(bytes_here) = program.insn_bytes_at.get(&insn.address) {
            for b in bytes_here {
                features.bytes_sequences.push(b.clone());
            }
        }
        let is_branch_or_call = insn.mnemonic == "call"
            || insn.mnemonic.starts_with('j')
            || insn.mnemonic.starts_with("loop");
        if !is_branch_or_call && program.insn_bytes_at.is_empty() && !image_bytes.is_empty() {
            for operand in &insn.operands {
                if operand.contains('[') && operand.contains("0x") {
                    if let Some(addr) = self.parse_memory_address(operand, insn.address, insn.bytes.len()) {
                        if !program.strings_at.contains_key(&addr) {
                            if let Some(slice) = va_map.slice_at_va(image_bytes, addr, 0x100) {
                                if slice.iter().any(|&b| b != 0) {
                                    features.bytes_sequences.push(slice.to_vec());
                                }
                            }
                        }
                    }
                }
            }
            for &val in insn.operand_values.iter().flatten() {
                if val > 0x1000 {
                    let addr = val as u64;
                    if !program.strings_at.contains_key(&addr) {
                        if let Some(slice) = va_map.slice_at_va(image_bytes, addr, 0x100) {
                            if slice.iter().any(|&b| b != 0) {
                                features.bytes_sequences.push(slice.to_vec());
                            }
                        }
                    }
                }
            }
        }

        features
    }

    /// Check if instruction is a non-zero XOR (excluding zeroing XORs and stack/frame
    /// security-cookie XORs such as `xor rax, rsp` / `xor rcx, rsp` / `xor eax, ebp`).
    fn is_nzxor(&self, insn: &crate::lifter::LiftedInstruction) -> bool {
        if !matches!(insn.mnemonic.as_str(), "xor" | "pxor" | "eor") {
            return false;
        }

        if insn.operands.len() >= 2 {
            let op1 = insn.operands[0].trim().to_lowercase();
            let op2 = insn.operands[1].trim().to_lowercase();

            // Same register XOR (zeroing) is NOT nzxor
            if op1 == op2 {
                return false;
            }

            // XOR with 0 is NOT nzxor
            if op2 == "0" || op2 == "0x0" {
                return false;
            }

            // Stack/frame pointer XORs (`xor rax, rsp`, `xor rcx, rsp`, `xor eax, ebp`)
            // are MSVC `/GS` stack security cookie checks, excluded by Python capa.
            const STACK_REGS: &[&str] = &["esp", "ebp", "rsp", "rbp"];
            if STACK_REGS.contains(&op1.as_str())
                || STACK_REGS.contains(&op2.as_str())
                || op1.contains("security_cookie")
                || op2.contains("security_cookie")
            {
                return false;
            }

            return true;
        }

        false
    }

    /// Issue 9: Detect COM class/interface features from imports and strings
    fn detect_com_features(&self, info: &BinaryInfo, features: &mut FeatureSet) {
        // COM-related API imports that indicate COM usage
        let com_apis = [
            "CoCreateInstance", "CoCreateInstanceEx", "CoGetClassObject",
            "CLSIDFromProgID", "CLSIDFromString", "CoInitialize",
            "CoInitializeEx", "OleInitialize", "CoRegisterClassObject",
            "CoGetInterfaceAndReleaseStream",
        ];

        for import in &info.imports {
            for com_api in &com_apis {
                if import.name.eq_ignore_ascii_case(com_api) {
                    features.characteristics.insert(CharacteristicType::CallsFrom);
                    // Add the COM API as an API feature too
                    insert_api(&mut features.apis, &import.module, &import.name);
                }
            }
        }

        // Look for CLSID patterns in strings (GUID format: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX})
        static GUID_RE: OnceLock<regex::Regex> = OnceLock::new();
        let guid_re = GUID_RE.get_or_init(|| {
            regex::Regex::new(
                r"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}"
            ).expect("GUID regex is valid")
        });

        for si in &info.strings {
            if guid_re.is_match(&si.value) {
                features.classes.insert(si.value.clone());
            }
        }
    }

    /// Issue 8: Check for embedded PE by looking for MZ header in raw bytes.
    /// Validates the PE signature to avoid false positives.
    fn has_embedded_pe_bytes(&self, bytes: &[u8]) -> bool {
        // Skip the first MZ header (the file itself), look for embedded ones
        if bytes.len() < 1024 {
            return false;
        }

        let finder = memmem::Finder::new(b"MZ");
        let mut iter = finder.find_iter(&bytes[512..]); // Skip first 512 bytes

        // Check if any MZ found is followed by PE signature
        while let Some(pos) = iter.next() {
            let abs_pos = pos + 512;
            // Check for "This program" or PE header offset
            if abs_pos + 64 < bytes.len() {
                // Get PE header offset from e_lfanew (offset 0x3C)
                let pe_offset_pos = abs_pos + 0x3C;
                if pe_offset_pos + 4 < bytes.len() {
                    let pe_offset = u32::from_le_bytes([
                        bytes[pe_offset_pos],
                        bytes[pe_offset_pos + 1],
                        bytes[pe_offset_pos + 2],
                        bytes[pe_offset_pos + 3],
                    ]) as usize;

                    // Check for "PE\0\0" at that offset
                    if abs_pos + pe_offset + 4 < bytes.len() {
                        let pe_sig = &bytes[abs_pos + pe_offset..abs_pos + pe_offset + 4];
                        if pe_sig == b"PE\0\0" {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    /// Detect stack string construction patterns within a single basic block.
    fn detect_stack_strings_in_bb(&self, bb: &LiftedBasicBlock) -> bool {
        let mut stack_moves = 0;

        for insn in &bb.instructions {
            if insn.mnemonic == "mov" && insn.operands.len() >= 2 {
                let dst = insn.operands[0].to_lowercase();

                let is_stack_dst = dst.contains("esp")
                    || dst.contains("ebp")
                    || dst.contains("rsp")
                    || dst.contains("rbp");

                let is_char_imm = insn.operand_values.get(1).and_then(|v| *v).map_or(false, |v| {
                    is_printable_immediate(v)
                });

                if is_stack_dst && is_char_imm {
                    stack_moves += 1;
                }
            }
        }

        stack_moves >= 4
    }

    /// Check if an operand string contains a specific offset value.
    /// e.g., "fs:[0x30]" has offset 0x30, "[ebp+0x30]" has offset 0x30.
    fn operand_has_offset(&self, op: &str, target: i64) -> bool {
        if let Some(offset) = self.extract_operand_offset(op) {
            offset == target
        } else {
            false
        }
    }

    /// Extract the offset/displacement value from a single operand string.
    fn extract_operand_offset(&self, op: &str) -> Option<i64> {
        if is_stack_frame_mem_operand(op) {
            return None;
        }
        let op_lower = op.to_lowercase();
        let bracket_start = op_lower.find('[')?;
        let bracket_end = op_lower.find(']')?;
        let inside = &op_lower[bracket_start + 1..bracket_end];

        let last_plus = inside.rfind('+');
        let last_minus = inside.rfind('-');
        match (last_plus, last_minus) {
            (Some(p), m) if m.map_or(true, |mp| p > mp) => {
                parse_number(inside[p + 1..].trim())
            }
            (_, Some(m)) => {
                parse_number(inside[m + 1..].trim()).map(|v| -v)
            }
            (None, None) => {
                // Bare address like [0x30]
                let trimmed = inside.trim();
                if trimmed.starts_with("0x") || trimmed.chars().next().map_or(false, |c| c.is_ascii_digit()) {
                    parse_number(trimmed)
                } else if !trimmed.is_empty()
                    && !trimmed.contains('*')
                    && trimmed.chars().next().map_or(false, |c| c.is_ascii_alphabetic())
                {
                    // Register-indirect memory operand like [eax] / [rdi] (and
                    // zero-displacement forms IDA renders as [reg]) — displacement 0.
                    // Matches capa's operand-offset semantics and makes
                    // `operand[N].offset: 0` satisfiable (Fix C, e.g. PlugX module rule).
                    Some(0)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Detect call to next instruction (shellcode pattern)
    fn detect_call_next(&self, bb: &LiftedBasicBlock) -> bool {
        for (i, insn) in bb.instructions.iter().enumerate() {
            if insn.mnemonic == "call" {
                for op in &insn.operations {
                    if let ILOperation::Branch { target: Some(target), is_call: true } = op {
                        // Check if call target is the next instruction
                        if let Some(next_insn) = bb.instructions.get(i + 1) {
                            if *target == next_insn.address {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Detect unmangled API calls (direct calls to API functions)
    fn detect_unmangled_call(&self, bb: &LiftedBasicBlock, info: &BinaryInfo) -> bool {
        for insn in &bb.instructions {
            if insn.mnemonic == "call" {
                for op in &insn.operations {
                    if let ILOperation::Branch { target: Some(target), is_call: true } = op {
                        // Check if target is in import table
                        if info.imports.iter().any(|imp| imp.address == *target) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Search for byte pattern in binary
    pub fn find_bytes(&self, bytes: &[u8], pattern: &[u8]) -> Vec<u64> {
        let finder = memmem::Finder::new(pattern);
        finder.find_iter(bytes).map(|pos| pos as u64).collect()
    }

    /// Extract offset values from operands (memory references).
    ///
    /// Handles patterns:
    /// - `[reg+0x10]` → offset 0x10
    /// - `[reg-0x8]`  → offset -0x8
    /// - `[0x401000]` → offset 0x401000  (bare address)
    /// - `fs:[0x30]`  → offset 0x30      (segment-prefixed)
    fn extract_offsets(&self, insn: &crate::lifter::LiftedInstruction) -> Vec<i64> {
        let mut offsets = Vec::new();

        for op in &insn.operands {
            if is_stack_frame_mem_operand(op) {
                continue;
            }
            let op_lower = op.to_lowercase();

            // Find the bracketed portion, stripping any segment prefix (fs:, gs:)
            let bracket_start = match op_lower.find('[') {
                Some(pos) => pos,
                None => continue,
            };
            let bracket_end = match op_lower.find(']') {
                Some(pos) => pos,
                None => continue,
            };
            let inside = &op_lower[bracket_start + 1..bracket_end];

            let last_plus = inside.rfind('+');
            let last_minus = inside.rfind('-');
            match (last_plus, last_minus) {
                (Some(p), m) if m.map_or(true, |mp| p > mp) => {
                    let offset_str = inside[p + 1..].trim();
                    if let Some(offset) = parse_number(offset_str) {
                        offsets.push(offset);
                    }
                }
                (_, Some(m)) => {
                    let offset_str = inside[m + 1..].trim();
                    if let Some(offset) = parse_number(offset_str) {
                        offsets.push(-offset);
                    }
                }
                _ => {
                    // [0x401000] or bare address — extract number directly
                    let trimmed = inside.trim();
                    if let Some(offset) = parse_number(trimmed) {
                        offsets.push(offset);
                    }
                }
            }
        }

        offsets
    }

    /// Detect call $+5 pattern (common in shellcode to get EIP/RIP)
    /// Pattern: call instruction where target is exactly 5 bytes after the call itself
    fn detect_call_plus_5(&self, bb: &LiftedBasicBlock) -> bool {
        for insn in &bb.instructions {
            if insn.mnemonic == "call" {
                for op in &insn.operations {
                    if let ILOperation::Branch { target: Some(target), is_call: true } = op {
                        // Call instruction is typically 5 bytes on x86
                        // call $+5 means target = address + 5
                        if *target == insn.address + 5 {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Parse memory address from operand string for IAT resolution
    /// Handles formats like "[0x1234]" or "[rip+0x1234]"
    fn parse_memory_address(&self, operand: &str, _insn_addr: u64, _insn_len: usize) -> Option<u64> {
        let op_lower = operand.to_lowercase();

        // Extract hex value from memory operand
        // Note: iced-x86's memory_displacement64() returns the resolved absolute address
        // for RIP-relative addressing, so [rip+0xABCD] means the target IS 0xABCD,
        // not rip + 0xABCD.
        if let Some(start) = op_lower.find("0x") {
            let hex_part = &op_lower[start + 2..];
            let end = hex_part.find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(hex_part.len());
            let hex_str = &hex_part[..end];

            if let Ok(addr) = u64::from_str_radix(hex_str, 16) {
                return Some(addr);
            }
        }

        None
    }

    /// Detect cross-section control flow (jump/call to different section)
    fn detect_cross_section_flow(&self, bb: &LiftedBasicBlock, info: &BinaryInfo) -> bool {
        // Find which section the basic block is in
        let bb_section = info.sections.iter().find(|s| {
            bb.address >= s.address && bb.address < s.address + s.size
        });

        let bb_section = match bb_section {
            Some(s) => s,
            None => return false,
        };

        // Check if any direct code branch target is in a different section (excluding
        // memory-indirect IAT/pointer slots `[0x...]` and import entries, matching Python capa)
        for insn in &bb.instructions {
            if insn.operands.first().is_some_and(|o| o.contains('[')) {
                continue;
            }
            for op in &insn.operations {
                if let ILOperation::Branch { target: Some(target), .. } = op {
                    if info.imports.iter().any(|i| i.address == *target) {
                        continue;
                    }
                    // Find section of target
                    let target_section = info.sections.iter().find(|s| {
                        *target >= s.address && *target < s.address + s.size
                    });

                    if let Some(ts) = target_section {
                        if ts.name != bb_section.name {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }
}

/// Check if an immediate value represents printable ASCII character(s).
///
/// Handles both single-byte values (0x20..0x7E) and packed multi-byte values
/// where each non-zero byte is printable ASCII (e.g., 0x726f4d20 = "Mor ").
fn is_printable_immediate(v: i64) -> bool {
    // Single ASCII char
    if v >= 0x20 && v <= 0x7E {
        return true;
    }
    // Packed multi-byte: positive values above 0x7E may encode multiple printable chars
    // (e.g., stack strings built with `mov dword [esp], 0x726f4d20`).
    // Each non-zero byte must be a printable ASCII character (0x20..0x7E).
    if v > 0x7E {
        let bytes = (v as u64).to_le_bytes();
        let mut has_printable = false;
        for &b in &bytes {
            if b == 0 {
                continue; // null padding is OK
            }
            if b < 0x20 || b > 0x7E {
                return false; // non-printable byte
            }
            has_printable = true;
        }
        return has_printable;
    }
    false
}

/// Parse a number from string (hex or decimal)
fn parse_number(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        i64::from_str_radix(&s[2..], 16).ok()
    } else if s.ends_with('h') || s.ends_with('H') {
        i64::from_str_radix(&s[..s.len() - 1], 16).ok()
    } else if s.chars().all(|c| c.is_ascii_hexdigit()) && s.len() > 1 {
        i64::from_str_radix(s, 16).ok()
    } else {
        s.parse::<i64>().ok()
    }
}

impl BinaryExtractor {
    /// Extract features with explicit format specification
    /// Used for shellcode or when auto-detection should be bypassed
    pub fn extract_with_format(&self, binary: &[u8], format: capa_core::rule::FormatType) -> Result<ExtractedFeatures> {
        // Load binary info with explicit format
        let info = crate::loader::load_binary_with_format(binary, format).map_err(|e| {
            capa_core::error::CapaError::ExtractionError(e.to_string())
        })?;

        // Then lift to IL
        let program = lift_binary(binary, &info).map_err(|e| {
            capa_core::error::CapaError::ExtractionError(e.to_string())
        })?;

        let mut features = self.extract_from_lifted(&program, binary);

        // Extract .NET-specific features if this is a .NET assembly
        if info.is_dotnet {
            debug!("Detected .NET assembly, extracting .NET-specific features via dotscope");
            if let Some(dotnet_features) = extract_dotnet_features(binary) {
                merge_dotnet_features(&dotnet_features, &mut features.file);
                merge_dotnet_method_features(&dotnet_features, &mut features.functions);
            }
        }

        Ok(features)
    }
}

impl FeatureExtractor for BinaryExtractor {
    fn extract(&self, binary: &[u8]) -> Result<ExtractedFeatures> {
        // First load basic binary info
        let info = load_binary(binary).map_err(|e| {
            capa_core::error::CapaError::ExtractionError(e.to_string())
        })?;

        // Then lift to IL
        let program = lift_binary(binary, &info).map_err(|e| {
            capa_core::error::CapaError::ExtractionError(e.to_string())
        })?;

        let mut features = self.extract_from_lifted(&program, binary);

        // Extract .NET-specific features if this is a .NET assembly
        if info.is_dotnet {
            debug!("Detected .NET assembly, extracting .NET-specific features via dotscope");
            if let Some(dotnet_features) = extract_dotnet_features(binary) {
                // Merge file-level features
                merge_dotnet_features(&dotnet_features, &mut features.file);

                // Merge method-level features for function-scope matching
                merge_dotnet_method_features(&dotnet_features, &mut features.functions);

                debug!(
                    ".NET extraction complete: {} user strings, {} classes, {} API calls, {} methods",
                    dotnet_features.user_strings.len(),
                    dotnet_features.classes.len(),
                    dotnet_features.api_calls.len(),
                    dotnet_features.method_features.len()
                );
            }
        }

        Ok(features)
    }

    fn extract_file_features(&self, binary: &[u8]) -> Result<FeatureSet> {
        let features = self.extract(binary)?;
        Ok(features.file)
    }

    fn extract_function_features(&self, binary: &[u8], addr: Address) -> Result<FunctionFeatures> {
        let features = self.extract(binary)?;
        features
            .functions
            .get(&addr)
            .cloned()
            .ok_or_else(|| capa_core::error::CapaError::ExtractionError(
                format!("Function at {} not found", addr)
            ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::SectionInfo;

    #[test]
    fn test_goblin_extractor() {
        let extractor = GoblinExtractor::new();
        assert!(extractor.extract(&[]).is_err());
    }

    #[test]
    fn test_binary_extractor() {
        let extractor = BinaryExtractor::new();
        assert!(extractor.extract(&[]).is_err());
    }

    #[test]
    fn test_byte_pattern_matcher() {
        let patterns = vec![
            b"MZ".to_vec(),
            b"PE\x00\x00".to_vec(),
            b"kernel32.dll".to_vec(),
        ];
        let matcher = BytePatternMatcher::new(patterns);

        let data = b"This is a test MZ header followed by PE\x00\x00 signature";
        let matches = matcher.find_all(data);

        assert!(matches.contains_key(&0)); // MZ found
        assert!(matches.contains_key(&1)); // PE\0\0 found
        assert!(!matches.contains_key(&2)); // kernel32.dll not found
    }

    #[test]
    fn test_byte_pattern_matcher_empty() {
        let matcher = BytePatternMatcher::new(vec![]);
        let data = b"test data";
        assert!(!matcher.has_any_match(data));
    }

    #[test]
    fn test_parse_number() {
        assert_eq!(parse_number("0x40"), Some(0x40));
        assert_eq!(parse_number("40h"), Some(0x40));
        assert_eq!(parse_number("64"), Some(100)); // "64" is all hex digits, parsed as hex
        assert_eq!(parse_number("abc"), Some(0xabc)); // All hex digits, parsed as hex
        assert_eq!(parse_number("xyz"), None); // Not valid hex or decimal
    }

    #[test]
    fn test_nzxor_detection() {
        let extractor = BinaryExtractor::new();

        // XOR with same register (zeroing) - NOT nzxor
        let insn_zero = crate::lifter::LiftedInstruction {
            address: 0x1000,
            mnemonic: "xor".to_string(),
            operands: vec!["eax".to_string(), "eax".to_string()],
            operand_values: vec![None, None],
            bytes: vec![0x33, 0xc0],
            operations: vec![],
        };
        assert!(!extractor.is_nzxor(&insn_zero));

        // XOR with different registers - IS nzxor
        let insn_nzxor = crate::lifter::LiftedInstruction {
            address: 0x1000,
            mnemonic: "xor".to_string(),
            operands: vec!["eax".to_string(), "ebx".to_string()],
            operand_values: vec![None, None],
            bytes: vec![0x33, 0xc3],
            operations: vec![],
        };
        assert!(extractor.is_nzxor(&insn_nzxor));

        // XOR with immediate 0 - NOT nzxor
        let insn_zero_imm = crate::lifter::LiftedInstruction {
            address: 0x1000,
            mnemonic: "xor".to_string(),
            operands: vec!["eax".to_string(), "0".to_string()],
            operand_values: vec![None, Some(0)],
            bytes: vec![0x83, 0xf0, 0x00],
            operations: vec![],
        };
        assert!(!extractor.is_nzxor(&insn_zero_imm));
    }

    #[test]
    fn test_call_plus_5_detection() {
        let extractor = BinaryExtractor::new();

        // Create a call instruction that targets address + 5
        let call_plus_5 = crate::lifter::LiftedInstruction {
            address: 0x1000,
            mnemonic: "call".to_string(),
            operands: vec!["0x1005".to_string()],
            operand_values: vec![Some(0x1005)],
            bytes: vec![0xE8, 0x00, 0x00, 0x00, 0x00],
            operations: vec![ILOperation::Branch { target: Some(0x1005), is_call: true }],
        };

        let bb = crate::lifter::LiftedBasicBlock {
            index: 0,
            address: 0x1000,
            end_address: 0x1004,
            instructions: vec![call_plus_5],
            successors: vec![],
            predecessors: vec![],
            is_loop_header: false,
        };

        assert!(extractor.detect_call_plus_5(&bb));
    }

    #[test]
    fn test_call_plus_5_not_detected() {
        let extractor = BinaryExtractor::new();

        // Call to a different address (not $+5)
        let call_other = crate::lifter::LiftedInstruction {
            address: 0x1000,
            mnemonic: "call".to_string(),
            operands: vec!["0x2000".to_string()],
            operand_values: vec![Some(0x2000)],
            bytes: vec![0xE8, 0x00, 0x10, 0x00, 0x00],
            operations: vec![ILOperation::Branch { target: Some(0x2000), is_call: true }],
        };

        let bb = crate::lifter::LiftedBasicBlock {
            index: 0,
            address: 0x1000,
            end_address: 0x1004,
            instructions: vec![call_other],
            successors: vec![],
            predecessors: vec![],
            is_loop_header: false,
        };

        assert!(!extractor.detect_call_plus_5(&bb));
    }

    #[test]
    fn test_cross_section_flow() {
        let extractor = BinaryExtractor::new();

        // Create sections
        let info = BinaryInfo {
            os: capa_core::rule::OsType::Windows,
            arch: capa_core::rule::ArchType::I386,
            format: capa_core::rule::FormatType::Pe,
            imports: vec![],
            exports: vec![],
            sections: vec![
                SectionInfo {
                    name: ".text".to_string(),
                    address: 0x1000,
                    size: 0x1000,
                    is_executable: true,
                },
                SectionInfo {
                    name: ".data".to_string(),
                    address: 0x2000,
                    size: 0x1000,
                    is_executable: false,
                },
            ],
            strings: vec![],
            is_dotnet: false,
            has_forwarded_exports: false,
            is_mixed_mode: false,
            entry_point: 0x1000,
        };

        // Jump from .text to .data
        let jmp_cross = crate::lifter::LiftedInstruction {
            address: 0x1100,
            mnemonic: "jmp".to_string(),
            operands: vec!["0x2100".to_string()],
            operand_values: vec![Some(0x2100)],
            bytes: vec![0xE9, 0x00, 0x10, 0x00, 0x00],
            operations: vec![ILOperation::Branch { target: Some(0x2100), is_call: false }],
        };

        let bb = crate::lifter::LiftedBasicBlock {
            index: 0,
            address: 0x1100,
            end_address: 0x1104,
            instructions: vec![jmp_cross],
            successors: vec![],
            predecessors: vec![],
            is_loop_header: false,
        };

        assert!(extractor.detect_cross_section_flow(&bb, &info));
    }

    #[test]
    fn test_characteristic_occurrence_counts_without_double_counting() {
        use std::collections::HashMap;
        use capa_core::matcher::MatchEngine;
        use capa_core::rule::{parse_rule, FormatType};

        let extractor = BinaryExtractor::new();
        let make_xor = |addr: u64, dst: &str, src: &str, imm: Option<i64>| crate::lifter::LiftedInstruction {
            address: addr,
            mnemonic: "xor".to_string(),
            operands: vec![dst.to_string(), src.to_string()],
            operand_values: vec![None, imm],
            bytes: vec![0x34, imm.unwrap_or(0) as u8],
            operations: vec![ILOperation::Xor {
                operands: vec![dst.to_string(), src.to_string()],
                constants: vec![],
            }],
        };

        let info = crate::loader::BinaryInfo {
            os: OsType::Windows,
            arch: ArchType::Amd64,
            format: FormatType::Pe,
            imports: vec![],
            exports: vec![],
            sections: vec![],
            strings: vec![],
            is_dotnet: false,
            has_forwarded_exports: false,
            is_mixed_mode: false,
            entry_point: 0x1000,
        };

        // Function 0 (0x1000): 0 nzxor (only zeroing `xor eax, eax`)
        let f0 = crate::lifter::LiftedFunction {
            address: 0x1000,
            name: Some("f_zero".to_string()),
            basic_blocks: vec![crate::lifter::LiftedBasicBlock {
                index: 0,
                address: 0x1000,
                end_address: 0x1002,
                instructions: vec![make_xor(0x1000, "eax", "eax", None)],
                successors: vec![],
                predecessors: vec![],
                is_loop_header: true,
            }],
            callees: vec![],
            callers: vec![],
            is_thunk: false,
            thunk_target: None,
            is_library: false,
        };

        // Function 1 (0x2000): 1 nzxor (`xor al, 0x36`) + 1 zeroing `xor eax, eax`
        let f1 = crate::lifter::LiftedFunction {
            address: 0x2000,
            name: Some("f_one".to_string()),
            basic_blocks: vec![crate::lifter::LiftedBasicBlock {
                index: 0,
                address: 0x2000,
                end_address: 0x2004,
                instructions: vec![
                    make_xor(0x2000, "eax", "eax", None),
                    make_xor(0x2002, "al", "0x36", Some(0x36)),
                ],
                successors: vec![],
                predecessors: vec![],
                is_loop_header: true,
            }],
            callees: vec![],
            callers: vec![],
            is_thunk: false,
            thunk_target: None,
            is_library: false,
        };

        // Function 2 (0x3000): 2 nzxor (`xor al, 0x36` and `xor al, 0x5c`, HMAC ipad/opad)
        let f2 = crate::lifter::LiftedFunction {
            address: 0x3000,
            name: Some("f_hmac".to_string()),
            basic_blocks: vec![crate::lifter::LiftedBasicBlock {
                index: 0,
                address: 0x3000,
                end_address: 0x3004,
                instructions: vec![
                    make_xor(0x3000, "al", "0x36", Some(0x36)),
                    make_xor(0x3002, "al", "0x5c", Some(0x5c)),
                ],
                successors: vec![],
                predecessors: vec![],
                is_loop_header: true,
            }],
            callees: vec![],
            callers: vec![],
            is_thunk: false,
            thunk_target: None,
            is_library: false,
        };

        let mut functions = HashMap::new();
        functions.insert(0x1000, f0);
        functions.insert(0x2000, f1);
        functions.insert(0x3000, f2);
        let program = crate::lifter::LiftedProgram {
            functions,
            entry_point: 0x1000,
            info,
            strings_at: HashMap::new(),
            iat_entries: HashMap::new(),
            thunk_targets: HashMap::new(),
            import_apis_at: HashMap::new(),
            insn_strings_at: HashMap::new(),
            insn_bytes_at: HashMap::new(),
        };

        let extracted = extractor.extract_from_lifted(&program, &[]);
        assert_eq!(
            extracted.functions[&Address(0x1000)].all_features().characteristic_count(&CharacteristicType::Nzxor),
            0,
            "zeroing xor must have nzxor count 0"
        );
        assert_eq!(
            extracted.functions[&Address(0x2000)].all_features().characteristic_count(&CharacteristicType::Nzxor),
            1,
            "single nzxor must count as 1 (no double-counting from BB+Function merge)"
        );
        assert_eq!(
            extracted.functions[&Address(0x3000)].all_features().characteristic_count(&CharacteristicType::Nzxor),
            2,
            "two nzxors must count as 2"
        );
        assert_eq!(
            extracted.all_features().characteristic_count(&CharacteristicType::Nzxor),
            3,
            "file all_features() must sum 0 + 1 + 2 = 3 without double-counting"
        );

        let rule_exact_one = parse_rule(
            r#"
rule:
  meta:
    name: exact one nzxor
    scopes:
      static: function
      dynamic: unsupported
  features:
    - count(characteristic(nzxor)): 1
"#,
        ).unwrap();
        let rule_two_or_more = parse_rule(
            r#"
rule:
  meta:
    name: two or more nzxor
    scopes:
      static: function
      dynamic: unsupported
  features:
    - count(characteristic(nzxor)): 2 or more
"#,
        ).unwrap();

        let engine = MatchEngine::new(vec![rule_exact_one, rule_two_or_more]);
        let m_one = engine.match_rule_by_name("exact one nzxor", &extracted).expect("f_one must match exact 1");
        assert_eq!(m_one.locations, vec![Address(0x2000)], "only f_one has exact 1 nzxor");

        let m_two = engine.match_rule_by_name("two or more nzxor", &extracted).expect("f_hmac must match >=2");
        assert_eq!(m_two.locations, vec![Address(0x3000)], "only f_hmac has >=2 nzxors");
    }

    #[test]
    fn test_calls_from_deduplicates_unique_callees_and_sib_offsets_parse() {
        use std::collections::HashMap;
        use capa_core::rule::FormatType;

        let extractor = BinaryExtractor::new();
        assert_eq!(extractor.extract_operand_offset("[rcx+rax*4+0x20]"), Some(0x20));
        assert_eq!(extractor.extract_operand_offset("[rcx+rax*4-0x8]"), Some(-0x8));

        let info = crate::loader::BinaryInfo {
            os: OsType::Windows,
            arch: ArchType::Amd64,
            format: FormatType::Pe,
            imports: vec![],
            exports: vec![],
            sections: vec![],
            strings: vec![],
            is_dotnet: false,
            has_forwarded_exports: false,
            is_mixed_mode: false,
            entry_point: 0x1000,
        };

        // Function at 0x1000 calls 0x2000 five times and 0x3000 twice (7 call insns, 2 unique targets)
        let f_dedup = crate::lifter::LiftedFunction {
            address: 0x1000,
            name: Some("f_rc4".to_string()),
            basic_blocks: vec![crate::lifter::LiftedBasicBlock {
                index: 0,
                address: 0x1000,
                end_address: 0x1020,
                instructions: vec![],
                successors: vec![],
                predecessors: vec![],
                is_loop_header: false,
            }],
            callees: vec![0x2000, 0x2000, 0x2000, 0x2000, 0x2000, 0x3000, 0x3000],
            callers: vec![],
            is_thunk: false,
            thunk_target: None,
            is_library: false,
        };

        // Function at 0x4000 calls 5 distinct targets (exceeding RC4 PRGA `(0, 4)`)
        let f_many = crate::lifter::LiftedFunction {
            address: 0x4000,
            name: Some("f_many".to_string()),
            basic_blocks: vec![crate::lifter::LiftedBasicBlock {
                index: 0,
                address: 0x4000,
                end_address: 0x4020,
                instructions: vec![],
                successors: vec![],
                predecessors: vec![],
                is_loop_header: false,
            }],
            callees: vec![0x5000, 0x5010, 0x5020, 0x5030, 0x5040],
            callers: vec![],
            is_thunk: false,
            thunk_target: None,
            is_library: false,
        };

        let mut functions = HashMap::new();
        functions.insert(0x1000, f_dedup);
        functions.insert(0x4000, f_many);
        let program = crate::lifter::LiftedProgram {
            functions,
            entry_point: 0x1000,
            info,
            strings_at: HashMap::new(),
            iat_entries: HashMap::new(),
            thunk_targets: HashMap::new(),
            import_apis_at: HashMap::new(),
            insn_strings_at: HashMap::new(),
            insn_bytes_at: HashMap::new(),
        };

        let extracted = extractor.extract_from_lifted(&program, &[]);
        assert_eq!(
            extracted.functions[&Address(0x1000)].all_features().characteristic_count(&CharacteristicType::CallsFrom),
            2,
            "7 call instructions to 2 unique targets must count as 2 CallsFrom"
        );
        assert_eq!(
            extracted.functions[&Address(0x4000)].all_features().characteristic_count(&CharacteristicType::CallsFrom),
            5,
            "5 distinct callee targets must count as 5 CallsFrom"
        );
    }

    #[test]
    fn test_parity_add_offset_lea_number_scc_loops_stack_cookie_and_offset_counts() {
        use std::collections::HashMap;
        use capa_core::matcher::MatchEngine;
        use capa_core::rule::{parse_rule, FormatType};

        let extractor = BinaryExtractor::new();
        let info = crate::loader::BinaryInfo {
            os: OsType::Windows,
            arch: ArchType::Amd64,
            format: FormatType::Pe,
            imports: vec![crate::loader::ImportInfo {
                name: "_wpgmptr".to_string(),
                module: Some("msvcrt.dll".to_string()),
                address: 0x200000,
            }],
            exports: vec![],
            sections: vec![
                crate::loader::SectionInfo {
                    name: ".text".to_string(),
                    address: 0x1000,
                    size: 0x8000,
                    is_executable: true,
                },
                crate::loader::SectionInfo {
                    name: ".rdata".to_string(),
                    address: 0x200000,
                    size: 0x4000,
                    is_executable: false,
                },
            ],
            strings: vec![],
            is_dotnet: false,
            has_forwarded_exports: false,
            is_mixed_mode: false,
            entry_point: 0x1000,
        };

        // 1. Acyclic out-of-line block at higher EA jumping to lower EA (0 -> 2 -> 1):
        //    must NOT emit Loop or TightLoop; also tests `add rcx, 0x18` -> offset,
        //    `add rsp, 0x30` -> ignored, `lea edx, [r8+0x10]` -> number,
        //    `xor rcx, rsp` -> NOT nzxor, `mov rax, [0x200000]` -> NOT api,
        //    `call [0x200000]` -> NOT CrossSectionFlow, and 2 `movzx` -> count == 2 (not 4).
        let bb0 = crate::lifter::LiftedBasicBlock {
            index: 0,
            address: 0x1000,
            end_address: 0x1030,
            instructions: vec![
                crate::lifter::LiftedInstruction {
                    address: 0x1000,
                    mnemonic: "xor".to_string(),
                    operands: vec!["rcx".to_string(), "rsp".to_string()],
                    operand_values: vec![None, None],
                    bytes: vec![0x48, 0x33, 0xCC],
                    operations: vec![],
                },
                crate::lifter::LiftedInstruction {
                    address: 0x1003,
                    mnemonic: "add".to_string(),
                    operands: vec!["rcx".to_string(), "0x18".to_string()],
                    operand_values: vec![None, Some(0x18)],
                    bytes: vec![0x48, 0x83, 0xC1, 0x18],
                    operations: vec![],
                },
                crate::lifter::LiftedInstruction {
                    address: 0x1007,
                    mnemonic: "add".to_string(),
                    operands: vec!["rsp".to_string(), "0x30".to_string()],
                    operand_values: vec![None, Some(0x30)],
                    bytes: vec![0x48, 0x83, 0xC4, 0x30],
                    operations: vec![],
                },
                crate::lifter::LiftedInstruction {
                    address: 0x100b,
                    mnemonic: "lea".to_string(),
                    operands: vec!["edx".to_string(), "[r8+0x10]".to_string()],
                    operand_values: vec![None, None],
                    bytes: vec![0x41, 0x8D, 0x50, 0x10],
                    operations: vec![],
                },
                crate::lifter::LiftedInstruction {
                    address: 0x100f,
                    mnemonic: "lea".to_string(),
                    operands: vec!["edx".to_string(), "[r8+rax*4+0x20]".to_string()],
                    operand_values: vec![None, None],
                    bytes: vec![0x41, 0x8D, 0x54, 0x80, 0x20],
                    operations: vec![],
                },
                crate::lifter::LiftedInstruction {
                    address: 0x1014,
                    mnemonic: "mov".to_string(),
                    operands: vec!["rax".to_string(), "[0x200000]".to_string()],
                    operand_values: vec![None, None],
                    bytes: vec![0x48, 0x8B, 0x05],
                    operations: vec![],
                },
                crate::lifter::LiftedInstruction {
                    address: 0x101b,
                    mnemonic: "call".to_string(),
                    operands: vec!["[0x200000]".to_string()],
                    operand_values: vec![None],
                    bytes: vec![0xFF, 0x15],
                    operations: vec![ILOperation::Branch {
                        target: Some(0x200000),
                        is_call: true,
                    }],
                },
            ],
            successors: vec![2],
            predecessors: vec![],
            is_loop_header: false,
        };
        let bb1 = crate::lifter::LiftedBasicBlock {
            index: 1,
            address: 0x1040,
            end_address: 0x1050,
            instructions: vec![
                crate::lifter::LiftedInstruction {
                    address: 0x1040,
                    mnemonic: "movzx".to_string(),
                    operands: vec!["eax".to_string(), "[rax]".to_string()],
                    operand_values: vec![None, None],
                    bytes: vec![0x0F, 0xB6, 0x00],
                    operations: vec![],
                },
                crate::lifter::LiftedInstruction {
                    address: 0x1043,
                    mnemonic: "movzx".to_string(),
                    operands: vec!["ecx".to_string(), "[rcx]".to_string()],
                    operand_values: vec![None, None],
                    bytes: vec![0x0F, 0xB6, 0x09],
                    operations: vec![],
                },
            ],
            successors: vec![],
            predecessors: vec![2],
            is_loop_header: true, // naive EA check marked true, but DAG has no cycle!
        };
        let bb2 = crate::lifter::LiftedBasicBlock {
            index: 2,
            address: 0x1080,
            end_address: 0x1090,
            instructions: vec![crate::lifter::LiftedInstruction {
                address: 0x1080,
                mnemonic: "mov".to_string(),
                operands: vec!["rax".to_string(), "[rax]".to_string()],
                operand_values: vec![None, None],
                bytes: vec![0x48, 0x8B, 0x00],
                operations: vec![],
            }],
            successors: vec![1],
            predecessors: vec![0],
            is_loop_header: false,
        };

        // 2. Self-looping block with 12 instructions -> must emit TightLoop!
        let self_loop_insns: Vec<_> = (0..12)
            .map(|k| crate::lifter::LiftedInstruction {
                address: 0x2000 + k * 2,
                mnemonic: "nop".to_string(),
                operands: vec![],
                operand_values: vec![],
                bytes: vec![0x90],
                operations: vec![],
            })
            .collect();
        let bb_self_loop = crate::lifter::LiftedBasicBlock {
            index: 0,
            address: 0x2000,
            end_address: 0x2020,
            instructions: self_loop_insns,
            successors: vec![0],
            predecessors: vec![0],
            is_loop_header: true,
        };

        let mut functions = HashMap::new();
        functions.insert(
            0x1000,
            crate::lifter::LiftedFunction {
                address: 0x1000,
                name: Some("f_dag".to_string()),
                basic_blocks: vec![bb0, bb1, bb2],
                callees: vec![0x200000],
                callers: vec![],
                is_thunk: false,
                thunk_target: None,
                is_library: false,
            },
        );
        functions.insert(
            0x2000,
            crate::lifter::LiftedFunction {
                address: 0x2000,
                name: Some("f_tight".to_string()),
                basic_blocks: vec![bb_self_loop],
                callees: vec![],
                callers: vec![],
                is_thunk: false,
                thunk_target: None,
                is_library: false,
            },
        );

        let mut iat_entries = HashMap::new();
        iat_entries.insert(0x200000, (Some("msvcrt".to_string()), "_wpgmptr".to_string()));
        let mut insn_bytes_at = HashMap::new();
        // 32-byte data buffer starting with 16-byte GUID
        let mut guid_buf = vec![0x9F, 0x36, 0x87, 0x0F, 0xE5, 0xA4, 0xFC, 0x4C, 0xBD, 0x3E, 0x73, 0xE6, 0x15, 0x45, 0x72, 0xDD];
        guid_buf.extend_from_slice(&[0xAA; 16]);
        insn_bytes_at.insert(0x100b, vec![guid_buf]);

        let program = crate::lifter::LiftedProgram {
            functions,
            entry_point: 0x1000,
            info,
            strings_at: HashMap::new(),
            iat_entries,
            thunk_targets: HashMap::new(),
            import_apis_at: HashMap::new(),
            insn_strings_at: HashMap::new(),
            insn_bytes_at,
        };

        let extracted = extractor.extract_from_lifted(&program, &[]);
        let f_dag = &extracted.functions[&Address(0x1000)];
        let f_dag_all = f_dag.all_features();

        // Negative: DAG must NOT have Loop; stack cookie XOR must NOT be Nzxor;
        // `add rsp, 0x30` must NOT emit number/offset 0x30; SIB `lea` must NOT emit number 0x20;
        // `call [IAT]` must NOT emit CrossSectionFlow; `mov rax, [IAT]` at 0x1014 must NOT emit api.
        assert!(!f_dag_all.characteristics.contains(&CharacteristicType::Loop));
        assert!(!f_dag_all.characteristics.contains(&CharacteristicType::Nzxor));
        assert!(!f_dag_all.characteristics.contains(&CharacteristicType::CrossSectionFlow));
        assert!(!f_dag_all.numbers.contains(&0x30));
        assert!(!f_dag_all.offsets.contains(&0x30));
        assert!(!f_dag_all.numbers.contains(&0x20));
        assert!(f_dag.instructions[&Address(0x1014)].apis.is_empty());

        // Positive: `add rcx, 0x18` emits offset 0x18 + operand[1].offset 0x18;
        // `lea edx, [r8+0x10]` emits number 0x10 + operand[1].number 0x10;
        // 2 `movzx` instructions have mnemonic count == 2 (not doubled to 4);
        // 12-insn self-loop has TightLoop.
        assert!(f_dag_all.offsets.contains(&0x18));
        assert!(f_dag.instructions[&Address(0x1003)].operands.contains(&(1, Some(0x18), Some(0x18))));
        assert!(f_dag_all.numbers.contains(&0x10));
        assert!(f_dag.instructions[&Address(0x100b)].operands.contains(&(1, Some(0x10), Some(0x10))));
        assert_eq!(f_dag_all.mnemonics.get("movzx").copied(), Some(2));
        assert!(extracted.functions[&Address(0x2000)].all_features().characteristics.contains(&CharacteristicType::TightLoop));

        // Verify `count(offset(0)): 1` matches bb2 (1 `[rax]`) and rejects bb1 (2 `[rax]`/`[rcx]`),
        // and `bytes:` prefix matching matches the 16-byte GUID inside the 32-byte data buffer.
        let r_offset_one = parse_rule(
            r#"
rule:
  meta:
    name: single zero offset
    scopes:
      static: basic block
  features:
    - count(offset(0)): 1
"#,
        ).unwrap();
        let r_guid_bytes = parse_rule(
            r#"
rule:
  meta:
    name: guid prefix bytes
    scopes:
      static: basic block
  features:
    - bytes: 9F 36 87 0F E5 A4 FC 4C BD 3E 73 E6 15 45 72 DD = CLSID_TaskScheduler
"#,
        ).unwrap();

        let engine = MatchEngine::new(vec![r_offset_one, r_guid_bytes]);
        let m_off = engine.match_rule_by_name("single zero offset", &extracted).unwrap();
        assert_eq!(m_off.locations, vec![Address(0x1080)], "only bb2 (0x1080) has exactly 1 offset(0); bb1 (0x1040) has 2");

        let m_guid = engine.match_rule_by_name("guid prefix bytes", &extracted).unwrap();
        assert_eq!(m_guid.locations, vec![Address(0x1000)], "bb0 must match 16-byte GUID prefix inside 32-byte referenced data");
    }

    #[test]
    fn test_all_bundled_capa_rules_v10_parse_cleanly() {
        let rules_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("capa-rules");
        let rules = capa_core::rule::parse_rules_directory(&rules_dir)
            .expect("capa-rules directory should load");
        assert!(
            rules.len() >= 1054,
            "expected all 1054 Mandiant v10.0.0 rules to parse with zero errors, got {}",
            rules.len()
        );
        // Verify rules that previously failed or corrupted inline comments are present and parsed properly
        let names: std::collections::HashSet<_> = rules.iter().map(|r| r.meta.name.as_str()).collect();
        assert!(names.contains("check for time delay in .NET"));
        assert!(names.contains("reference absolute stream path on Windows"));
        assert!(names.contains("validate payment card number using luhn algorithm with no lookup table"));
        assert!(names.contains("schedule task via ITaskService"));
        assert!(names.contains("get process heap flags"));
        assert!(names.contains("encrypt data using speck"));
    }

    #[test]
    fn test_stack_frame_offsets_excluded_and_reg_indirect_iat_calls_resolved() {
        use std::collections::HashMap;
        use capa_core::rule::FormatType;

        let extractor = BinaryExtractor::new();
        // Hardware stack pointer (`sp`/`esp`/`rsp`) must NOT emit struct offsets, while
        // `rbp`/`ebp` (`-fomit-frame-pointer` general-purpose struct base) and `gs:` MUST.
        assert_eq!(extractor.extract_operand_offset("[rsp]"), None);
        assert_eq!(extractor.extract_operand_offset("[esp]"), None);
        assert_eq!(extractor.extract_operand_offset("[rsp+0x30]"), Some(0x30));
        assert_eq!(extractor.extract_operand_offset("[r12+0x30]"), Some(0x30));
        assert_eq!(extractor.extract_operand_offset("[rbp+0x18]"), Some(0x18));
        assert_eq!(extractor.extract_operand_offset("gs:[0x60]"), Some(0x60));
        assert_eq!(extractor.extract_operand_offset("[rax]"), Some(0));
        assert_eq!(extractor.extract_operand_offset("[rcx+0x30]"), Some(0x30));

        // Verify Unix path strings like `"/etc/passwd-s3fs"` do NOT falsely match `"refresh: fetch fail"`
        let aws_rule = capa_core::rule::parse_rule(
            r#"
rule:
  meta:
    name: unix path not regex
    scopes:
      static: function
  features:
    - or:
      - string: "/etc/passwd-s3fs"
      - substring: "/etc/profile.d/"
"#,
        ).unwrap();
        let mut neg_features = ExtractedFeatures::new(OsType::Windows, ArchType::Amd64, FormatType::Pe);
        let mut f_fetch = FunctionFeatures::new(Address(0x5000));
        f_fetch.features.strings.insert("refresh: fetch fail".to_string());
        neg_features.functions.insert(Address(0x5000), f_fetch);
        let eng = capa_core::matcher::MatchEngine::new(vec![aws_rule]);
        assert!(
            eng.match_rule_by_name("unix path not regex", &neg_features).is_none(),
            "/etc/passwd-s3fs must be parsed as Exact, not /etc/ regex matching 'fetch'"
        );

        let info = crate::loader::BinaryInfo {
            os: OsType::Windows,
            arch: ArchType::Amd64,
            format: FormatType::Pe,
            imports: vec![
                crate::loader::ImportInfo {
                    name: "getenv".to_string(),
                    module: Some("msvcrt.dll".to_string()),
                    address: 0x200100,
                },
                crate::loader::ImportInfo {
                    name: "_wpgmptr".to_string(),
                    module: Some("msvcrt.dll".to_string()),
                    address: 0x200200,
                },
            ],
            exports: vec![],
            sections: vec![],
            strings: vec![],
            is_dotnet: false,
            has_forwarded_exports: false,
            is_mixed_mode: false,
            entry_point: 0x1000,
        };

        let bb0 = crate::lifter::LiftedBasicBlock {
            index: 0,
            address: 0x1000,
            end_address: 0x1010,
            instructions: vec![
                crate::lifter::LiftedInstruction {
                    address: 0x1000,
                    mnemonic: "mov".to_string(),
                    operands: vec!["rbx".to_string(), "[0x200100]".to_string()],
                    operand_values: vec![None, None],
                    bytes: vec![0x48, 0x8B, 0x1D],
                    operations: vec![],
                },
                crate::lifter::LiftedInstruction {
                    address: 0x1007,
                    mnemonic: "mov".to_string(),
                    operands: vec!["rax".to_string(), "[0x200200]".to_string()],
                    operand_values: vec![None, None],
                    bytes: vec![0x48, 0x8B, 0x05],
                    operations: vec![],
                },
            ],
            successors: vec![1],
            predecessors: vec![],
            is_loop_header: false,
        };
        let bb1 = crate::lifter::LiftedBasicBlock {
            index: 1,
            address: 0x1020,
            end_address: 0x1030,
            instructions: vec![
                crate::lifter::LiftedInstruction {
                    address: 0x1020,
                    mnemonic: "call".to_string(),
                    operands: vec!["rbx".to_string()],
                    operand_values: vec![None],
                    bytes: vec![0xFF, 0xD3],
                    operations: vec![ILOperation::Branch {
                        target: None,
                        is_call: true,
                    }],
                },
                crate::lifter::LiftedInstruction {
                    address: 0x1022,
                    mnemonic: "ret".to_string(),
                    operands: vec!["0x4".to_string()],
                    operand_values: vec![Some(4)],
                    bytes: vec![0xC2, 0x04, 0x00],
                    operations: vec![],
                },
            ],
            successors: vec![],
            predecessors: vec![0],
            is_loop_header: false,
        };

        let mut functions = HashMap::new();
        functions.insert(
            0x1000,
            crate::lifter::LiftedFunction {
                address: 0x1000,
                name: Some("f_env".to_string()),
                basic_blocks: vec![bb0, bb1],
                callees: vec![],
                callers: vec![],
                is_thunk: false,
                thunk_target: None,
                is_library: false,
            },
        );
        let mut iat_entries = HashMap::new();
        iat_entries.insert(0x200100, (Some("msvcrt".to_string()), "getenv".to_string()));
        iat_entries.insert(0x200200, (Some("msvcrt".to_string()), "_wpgmptr".to_string()));

        let program = crate::lifter::LiftedProgram {
            functions,
            entry_point: 0x1000,
            info,
            strings_at: HashMap::new(),
            iat_entries,
            thunk_targets: HashMap::new(),
            import_apis_at: HashMap::new(),
            insn_strings_at: HashMap::new(),
            insn_bytes_at: HashMap::new(),
        };

        let extracted = extractor.extract_from_lifted(&program, &[]);
        let f = &extracted.functions[&Address(0x1000)];
        // Positive: `call rbx` at 0x1020 resolves `getenv`, and `ret 4` preserves `number: 4`
        assert!(f.instructions[&Address(0x1020)].apis.contains("getenv"));
        assert!(f.basic_block_all_features(1).apis.contains("getenv"));
        assert!(f.basic_block_all_features(1).numbers.contains(&4));
        // Negative: `_wpgmptr` loaded into `rax` without `call rax` must NOT appear in apis
        assert!(!f.all_features().apis.contains("_wpgmptr"));
    }
}
