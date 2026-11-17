//! IDA Pro lifter — produces LiftedProgram from an IDB.
//!
//! This module walks IDA's function/CFG/instruction model
//! and produces the same LiftedProgram IR that lifter.rs creates
//! from goblin+iced-x86, so that extract_from_lifted() can be reused.

use std::collections::HashMap;

use idalib::idb::IDB;
use idalib::func::FunctionFlags;
use idalib::insn::{Operand, OperandType, OperandDataType};

use capa_core::rule::ArchType;

use crate::lifter::{
    ILOperation, LiftedBasicBlock, LiftedFunction, LiftedInstruction, LiftedProgram,
};
use crate::loader::BinaryInfo;

// ---------------------------------------------------------------------------
// x86 register name lookup — maps IDA register ID + operand data type to name.
//
// IDA register IDs from intel.hpp (SDK):
//   0-7:   ax,cx,dx,bx,sp,bp,si,di  (GPR base)
//   8-15:  r8-r15
//   16-23: al,cl,dl,bl,ah,ch,dh,bh  (explicit byte regs)
//   24-27: spl,bpl,sil,dil
//   28-33: es,cs,ss,ds,fs,gs         (segment regs)
// ---------------------------------------------------------------------------

/// 64/32/16/8-bit names for GPR IDs 0-15.
/// Index by [reg_id][size_idx] where size_idx: 0=64, 1=32, 2=16, 3=8.
const GPR_NAMES: [[&str; 4]; 16] = [
    ["rax", "eax", "ax",  "al"],
    ["rcx", "ecx", "cx",  "cl"],
    ["rdx", "edx", "dx",  "dl"],
    ["rbx", "ebx", "bx",  "bl"],
    ["rsp", "esp", "sp",  "spl"],
    ["rbp", "ebp", "bp",  "bpl"],
    ["rsi", "esi", "si",  "sil"],
    ["rdi", "edi", "di",  "dil"],
    ["r8",  "r8d", "r8w", "r8b"],
    ["r9",  "r9d", "r9w", "r9b"],
    ["r10", "r10d","r10w","r10b"],
    ["r11", "r11d","r11w","r11b"],
    ["r12", "r12d","r12w","r12b"],
    ["r13", "r13d","r13w","r13b"],
    ["r14", "r14d","r14w","r14b"],
    ["r15", "r15d","r15w","r15b"],
];

/// Explicit byte register names for IDA IDs 16-27.
const BYTE_REG_NAMES: [&str; 12] = [
    "al", "cl", "dl", "bl",   // 16-19
    "ah", "ch", "dh", "bh",   // 20-23
    "spl", "bpl", "sil", "dil", // 24-27
];

/// Segment register names for IDA IDs 29-34.
/// From intel.hpp enum: R_es=29, R_cs=30, R_ss=31, R_ds=32, R_fs=33, R_gs=34.
/// (R_ip=28 sits between byte regs and segment regs.)
const SEG_REG_NAMES: [&str; 6] = ["es", "cs", "ss", "ds", "fs", "gs"];

/// IDA segment register IDs for FS and GS (from intel.hpp: R_fs=33, R_gs=34).
/// insn_t.segpref stores the register ID directly.
const SEGPREF_FS: i32 = 33;
const SEGPREF_GS: i32 = 34;

/// Map operand data type to size index for GPR lookup.
fn dtype_to_size_idx(dtype: OperandDataType) -> usize {
    match dtype {
        OperandDataType::QWord => 0,  // 64-bit
        OperandDataType::DWord => 1,  // 32-bit
        OperandDataType::Word => 2,   // 16-bit
        OperandDataType::Byte => 3,   // 8-bit
        _ => 0,                        // default to 64-bit
    }
}

/// Get x86 register name from IDA register ID and operand data type.
fn x86_reg_name(reg_id: u16, dtype: OperandDataType) -> &'static str {
    let id = reg_id as usize;
    if id < 16 {
        GPR_NAMES[id][dtype_to_size_idx(dtype)]
    } else if id >= 16 && id < 28 {
        BYTE_REG_NAMES[id - 16]
    } else if id >= 29 && id < 35 {
        SEG_REG_NAMES[id - 29]
    } else {
        // XMM/YMM/ST/CR/DR etc — return empty, caller will use fallback
        ""
    }
}

/// Mask an immediate value to the width of its IDA operand dtype so sign-extended
/// 8/16/32-bit immediates (e.g. `cmp eax, -1` where IDA stores `0xffffffff_ffffffff`
/// with `OperandDataType::DWord`) yield `0xFFFFFFFF` (`4294967295`), matching Python
/// capa's `mask_op_val` semantics.
fn mask_imm_by_dtype(val: u64, dtype: OperandDataType) -> i64 {
    match dtype {
        OperandDataType::Byte => (val & 0xFF) as i64,
        OperandDataType::Word => (val & 0xFFFF) as i64,
        OperandDataType::DWord => (val & 0xFFFF_FFFF) as i64,
        _ => val as i64,
    }
}

/// Extract numeric operand value for `number:` / `operand[n].number` matching.
/// Memory/displacement addresses are intentionally excluded (they belong in `offset:`).
fn operand_numeric_value(
    op_type: OperandType,
    dtype: OperandDataType,
    imm_val: Option<u64>,
    addr_val: Option<u64>,
) -> Option<i64> {
    match op_type {
        OperandType::Imm => imm_val.map(|v| mask_imm_by_dtype(v, dtype)),
        OperandType::Near | OperandType::Far => addr_val.map(|v| v as i64),
        _ => None,
    }
}

/// Format an operand string from op_t POD fields — no FFI, pure Rust.
///
/// Produces strings compatible with what the extractor expects:
/// - Register: "rax", "esp", etc.
/// - Immediate: "0x1234"
/// - Memory: "[0x401000]" or "fs:[0x30]"
/// - Displacement: "[rbp+0x10]" or "[rsp-0x8]"
/// - Phrase: "[rax]"
/// - Near/Far: "0x401000"
fn format_operand(op: &Operand, segpref: Option<i32>, addr_dtype: OperandDataType) -> String {
    let seg_prefix = match segpref {
        Some(SEGPREF_FS) => "fs:",
        Some(SEGPREF_GS) => "gs:",
        _ => "",
    };

    match op.type_() {
        OperandType::Reg => {
            let name = x86_reg_name(op.reg().unwrap_or(0), op.dtype());
            if name.is_empty() {
                format!("reg{}", op.reg().unwrap_or(0))
            } else {
                name.to_string()
            }
        }
        OperandType::Imm => {
            let val = mask_imm_by_dtype(op.value().unwrap_or(0), op.dtype()) as u64;
            format!("0x{:x}", val)
        }
        OperandType::Mem => {
            let addr = op.addr().unwrap_or(0);
            format!("{}[0x{:x}]", seg_prefix, addr)
        }
        OperandType::Displ => {
            let base = op.phrase().unwrap_or(0);
            let base_name = x86_reg_name(base, addr_dtype);
            let disp = op.addr().unwrap_or(0);
            let base_str = if base_name.is_empty() {
                format!("reg{}", base)
            } else {
                base_name.to_string()
            };
            if disp == 0 {
                format!("{}[{}]", seg_prefix, base_str)
            } else {
                // x86/x86-64 ModRM/SIB displacements are 32-bit two's complement
                // (IDA may store negative displacements either 32-bit masked `0xffff_ffd0`
                // or 64-bit sign-extended `0xffffffff_ffffffd0`). Preserve genuine >4GB 64-bit
                // base addresses (`0x18005b148`) intact.
                let signed = if disp <= u32::MAX as u64 || (disp >> 32) == 0xFFFF_FFFF {
                    (disp as u32 as i32) as i64
                } else {
                    disp as i64
                };
                if signed < 0 && signed > -0x8000_0000 {
                    format!("{}[{}-0x{:x}]", seg_prefix, base_str, -signed)
                } else {
                    format!("{}[{}+0x{:x}]", seg_prefix, base_str, signed)
                }
            }
        }
        OperandType::Phrase => {
            let base = op.phrase().unwrap_or(0);
            let base_name = x86_reg_name(base, addr_dtype);
            if base_name.is_empty() {
                format!("{}[reg{}]", seg_prefix, base)
            } else {
                format!("{}[{}]", seg_prefix, base_name)
            }
        }
        OperandType::Near | OperandType::Far => {
            let addr = op.addr().unwrap_or(0);
            format!("0x{:x}", addr)
        }
        _ => {
            // IdpSpec0-5 and other processor-specific operands
            String::new()
        }
    }
}

/// Lift all functions in the IDB into a LiftedProgram.
///
/// Iterates over IDA's functions, builds CFGs via flow charts,
/// decodes instructions, and maps them to ILOperations.
pub(crate) fn lift_from_idb(idb: &IDB, info: BinaryInfo) -> LiftedProgram {
    let mut functions = HashMap::new();
    let entry_point = info.entry_point;

    // Determine addressing register size from binary architecture.
    // 32-bit binaries use esp/ebp (DWord), 64-bit use rsp/rbp (QWord).
    let addr_dtype = match info.arch {
        ArchType::I386 => OperandDataType::DWord,
        _ => OperandDataType::QWord,
    };

    let known_import_names: std::collections::HashSet<String> =
        info.imports.iter().map(|i| i.name.clone()).collect();

    for (_id, func) in idb.functions() {
        let func_addr = func.start_address();
        let func_name = func.name();
        let flags = func.flags();
        let mut is_thunk = flags.contains(FunctionFlags::THUNK);
        let is_msvc_lib_sym = func_name.as_deref().is_some_and(|n| {
            n.starts_with('?')
                && (n.contains("@ATL@@")
                    || n.contains("@std@@")
                    || n.starts_with("?_com_issue_error@@")
                    || n.contains("@_com_error@@"))
        });
        let is_library = flags.contains(FunctionFlags::LIB) || is_msvc_lib_sym;

        // Build CFG and lift basic blocks
        let (basic_blocks, callees) = match func.cfg() {
            Ok(cfg) => lift_cfg(idb, &cfg, func_addr, addr_dtype),
            Err(_) => {
                // Fallback: create a single basic block for the function
                let (bb, callees) = lift_linear(idb, func_addr, func.end_address(), addr_dtype);
                (vec![bb], callees)
            }
        };

        // Detect thunk target (standard JMP thunks + MSVC `/DELAYLOAD` 2-insn `__tailMerge` stubs
        // whose function name matches a known import/delay-import symbol).
        let mut thunk_target = if is_thunk {
            func.calc_thunk_target()
                .and_then(|target_addr| {
                    idb.function_at(target_addr)
                        .and_then(|f| f.name())
                        .or_else(|| idb.address_to_string(target_addr))
                })
                .and_then(|n| crate::ida_loader::clean_ida_import_symbol(&n))
                .or_else(|| {
                    func_name
                        .as_deref()
                        .and_then(crate::ida_loader::clean_ida_import_symbol)
                })
        } else {
            None
        };

        if thunk_target.is_none() && basic_blocks.len() == 1 && basic_blocks[0].instructions.len() <= 4 {
            if let Some(cleaned) = func_name
                .as_deref()
                .and_then(crate::ida_loader::clean_ida_import_symbol)
            {
                if known_import_names.contains(&cleaned) {
                    is_thunk = true;
                    thunk_target = Some(cleaned);
                }
            }
        }

        functions.insert(
            func_addr,
            LiftedFunction {
                address: func_addr,
                name: func_name,
                basic_blocks,
                callees,
                callers: Vec::new(), // Populated below
                is_thunk,
                thunk_target,
                is_library,
            },
        );
    }

    // Build caller lists from callee lists
    let callee_map: Vec<(u64, Vec<u64>)> = functions
        .iter()
        .map(|(&addr, f)| (addr, f.callees.clone()))
        .collect();

    for (caller_addr, callees) in &callee_map {
        for callee in callees {
            if let Some(callee_func) = functions.get_mut(callee) {
                callee_func.callers.push(*caller_addr);
            }
        }
    }

    // Build IAT entries, string maps, import call xrefs, and data-xref string/bytes maps
    let mut iat_entries = build_iat_map(&info);
    let strings_at = build_string_map(idb, &info);
    let thunk_targets = build_thunk_map(&functions);
    let import_apis_at = build_import_xref_map(idb, &info, &functions, &mut iat_entries);
    let (insn_strings_at, insn_bytes_at) = build_insn_data_xref_maps(idb, &functions, &strings_at);

    LiftedProgram {
        functions,
        entry_point,
        info,
        strings_at,
        iat_entries,
        thunk_targets,
        import_apis_at,
        insn_strings_at,
        insn_bytes_at,
    }
}

/// Non-flow code xrefs from `ea` (equivalent to `idautils.CodeRefsFrom(ea, False)`).
fn code_refs_from(idb: &IDB, ea: u64) -> Vec<u64> {
    let mut out = Vec::new();
    let mut cur = idb.first_xref_from(ea, idalib::xref::XRefQuery::FAR);
    while let Some(x) = cur {
        if x.is_code() {
            out.push(x.to());
        }
        cur = x.next_from();
    }
    out
}

/// Data xrefs from `ea` (equivalent to `idautils.DataRefsFrom(ea)`).
fn data_refs_from(idb: &IDB, ea: u64) -> Vec<u64> {
    let mut out = Vec::new();
    let mut cur = idb.first_xref_from(ea, idalib::xref::XRefQuery::DATA);
    while let Some(x) = cur {
        if x.is_data() {
            out.push(x.to());
        }
        cur = x.next_from();
    }
    out
}

/// Follow a chain of single `DataRefsFrom` links up to `max_depth` (matching Python
/// capa's `find_data_reference_from_insn`).
fn follow_data_ref_chain(idb: &IDB, start_ea: u64, max_depth: usize) -> Option<u64> {
    let mut ea = start_ea;
    let mut depth = 0;
    loop {
        let drefs = data_refs_from(idb, ea);
        if drefs.len() != 1 {
            break;
        }
        let next = drefs[0];
        if next == ea || idb.segment_at(next).is_none() {
            break;
        }
        ea = next;
        depth += 1;
        if depth >= max_depth {
            break;
        }
    }
    if ea != start_ea {
        Some(ea)
    } else {
        None
    }
}

fn read_bytes_at_seg_bounded(idb: &IDB, ea: u64, max_len: usize) -> Vec<u8> {
    let Some(seg) = idb.segment_at(ea) else {
        return Vec::new();
    };
    let avail = seg.end_address().saturating_sub(ea) as usize;
    let take = avail.min(max_len);
    if take == 0 {
        return Vec::new();
    }
    idb.get_bytes(ea, take)
}

/// Resolve per-instruction `DataRefsFrom` strings (including unlabeled UTF-16LE wide
/// strings such as Windows stream paths) and byte slices (matching Python capa's
/// `extract_insn_string_features` and `extract_insn_bytes_features`).
fn build_insn_data_xref_maps(
    idb: &IDB,
    functions: &HashMap<u64, LiftedFunction>,
    strings_at: &HashMap<u64, String>,
) -> (HashMap<u64, Vec<String>>, HashMap<u64, Vec<Vec<u8>>>) {
    let mut insn_strings: HashMap<u64, Vec<String>> = HashMap::new();
    let mut insn_bytes: HashMap<u64, Vec<Vec<u8>>> = HashMap::new();

    for f in functions.values() {
        if f.is_library || f.is_thunk {
            continue;
        }
        for bb in &f.basic_blocks {
            for insn in &bb.instructions {
                if insn.mnemonic == "call" {
                    continue;
                }
                let initial_drefs = data_refs_from(idb, insn.address);
                if initial_drefs.is_empty() {
                    continue;
                }
                for first_ref in initial_drefs {
                    if first_ref == insn.address || idb.segment_at(first_ref).is_none() {
                        continue;
                    }
                    // Follow single-pointer deref chains (up to 9 additional hops)
                    let ref_ea = follow_data_ref_chain(idb, first_ref, 9).unwrap_or(first_ref);
                    if let Some(s) = strings_at.get(&ref_ea) {
                        insn_strings.entry(insn.address).or_default().push(s.clone());
                        continue;
                    }
                    let is_non_exec = idb
                        .segment_at(ref_ea)
                        .is_some_and(|seg| !seg.permissions().is_executable());
                    let raw = read_bytes_at_seg_bounded(idb, ref_ea, 0x200);
                    if raw.is_empty() {
                        continue;
                    }
                    if is_non_exec {
                        if let Some(probed_str) = crate::ida_loader::decode_ida_string_bytes(&raw, true) {
                            insn_strings.entry(insn.address).or_default().push(probed_str);
                            continue;
                        }
                    }
                    let slice_len = raw.len().min(0x100);
                    let slice = &raw[..slice_len];
                    if slice.iter().any(|&b| b != 0) {
                        insn_bytes.entry(insn.address).or_default().push(slice.to_vec());
                    }
                }
            }
        }
    }

    (insn_strings, insn_bytes)
}

/// Match an IDA symbol name (as returned by `address_to_string`) against a known
/// import name, tolerating `__imp_` / `__imp_load_` prefixes and `module_`/`module.`/`module!`
/// qualifiers. Returns the bare import name if matched.
fn match_import_symbol(sym: &str, import_names: &std::collections::HashSet<String>) -> Option<String> {
    if let Some(cleaned) = crate::ida_loader::clean_ida_import_symbol(sym) {
        if import_names.contains(&cleaned) {
            return Some(cleaned);
        }
    }
    let base = sym
        .strip_prefix("__imp_load_")
        .or_else(|| sym.strip_prefix("__imp_"))
        .unwrap_or(sym);
    if import_names.contains(base) {
        return Some(base.to_string());
    }
    // module-qualified: kernel32_CreateFileW / kernel32.CreateFileW / kernel32!CreateFileW
    if let Some(seg) = base.rsplit(['_', '.', '!']).next() {
        if seg != base && import_names.contains(seg) {
            return Some(seg.to_string());
        }
    }
    None
}

/// Parse the first `[0x<hex>]` address out of an operand string
/// (e.g. `[0x1400a10]`, `fs:[0x30]`, `[0x1400a10+8]`).
fn parse_bracket_hex(operand: &str) -> Option<u64> {
    let start = operand.find("[0x")? + 3;
    let rest = &operand[start..];
    let end = rest.find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(rest.len());
    u64::from_str_radix(&rest[..end], 16).ok()
}

/// Resolve API targets for `call` and `jmp` instructions using IDA's `CodeRefsFrom` /
/// `DataRefsFrom` chains (up to `THUNK_CHAIN_DEPTH_DELTA = 5`) plus FLIRT `FUNC_LIB`
/// callees, while also populating `iat_entries` for `[0x<addr>]` import slots referenced
/// by `mov reg, [IAT]` (so intra-procedural `call reg` resolution in `extractor.rs` works).
fn build_import_xref_map(
    idb: &IDB,
    info: &BinaryInfo,
    functions: &HashMap<u64, LiftedFunction>,
    iat_entries: &mut HashMap<u64, (Option<String>, String)>,
) -> HashMap<u64, Vec<(Option<String>, String)>> {
    const THUNK_CHAIN_DEPTH_DELTA: usize = 5;

    let import_names: std::collections::HashSet<String> =
        info.imports.iter().map(|i| i.name.clone()).collect();
    let mut imports_by_addr: HashMap<u64, (Option<String>, String)> = HashMap::new();
    let mut name_to_module: HashMap<String, Option<String>> = HashMap::new();
    for imp in &info.imports {
        let norm_mod = imp.module.as_ref().map(|m| normalize_module(m));
        if imp.address > 0 {
            imports_by_addr.insert(imp.address, (norm_mod.clone(), imp.name.clone()));
        }
        name_to_module
            .entry(imp.name.clone())
            .or_insert(norm_mod);
    }

    let mut addr_sym_cache: HashMap<u64, Option<String>> = HashMap::new();
    let mut map: HashMap<u64, Vec<(Option<String>, String)>> = HashMap::new();

    for f in functions.values() {
        if f.is_library || f.is_thunk {
            continue;
        }
        for bb in &f.basic_blocks {
            for insn in &bb.instructions {
                // Enrich `iat_entries` for `[0x<addr>]` IAT slots on `mov`/`lea` so
                // `mov rbx, [__imp_getenv]; ...; call rbx` resolves at the `call` site
                // without emitting false APIs on non-call instructions.
                if insn.mnemonic == "mov" || insn.mnemonic == "lea" {
                    for operand in &insn.operands {
                        if let Some(addr) = parse_bracket_hex(operand) {
                            if !iat_entries.contains_key(&addr) {
                                let sym_hit = addr_sym_cache
                                    .entry(addr)
                                    .or_insert_with(|| {
                                        idb.address_to_string(addr)
                                            .and_then(|sym| match_import_symbol(&sym, &import_names))
                                    })
                                    .clone();
                                if let Some(name) = sym_hit {
                                    let module = name_to_module.get(&name).cloned().flatten();
                                    iat_entries.insert(addr, (module, name));
                                }
                            }
                        }
                    }
                    continue;
                }

                if insn.mnemonic != "call" && insn.mnemonic != "jmp" {
                    continue;
                }

                let mut matched_import: Option<(Option<String>, String)> = None;

                // 1. Follow CodeRefsFrom / DataRefsFrom chain up to THUNK_CHAIN_DEPTH_DELTA
                // (resolves direct IAT calls, register-tracked `call rsi`, and chained thunks)
                let mut ref_ea = insn.address;
                for _ in 0..THUNK_CHAIN_DEPTH_DELTA {
                    let next_opt = code_refs_from(idb, ref_ea)
                        .into_iter()
                        .next()
                        .or_else(|| data_refs_from(idb, ref_ea).into_iter().next());
                    let Some(next_ea) = next_opt else {
                        break;
                    };
                    if let Some(imp) = imports_by_addr.get(&next_ea) {
                        matched_import = Some(imp.clone());
                        break;
                    }
                    let sym_hit = addr_sym_cache
                        .entry(next_ea)
                        .or_insert_with(|| {
                            idb.address_to_string(next_ea)
                                .and_then(|sym| match_import_symbol(&sym, &import_names))
                        })
                        .clone();
                    if let Some(name) = sym_hit {
                        let module = name_to_module.get(&name).cloned().flatten();
                        matched_import = Some((module, name));
                        break;
                    }
                    let is_chainable = functions
                        .get(&next_ea)
                        .is_some_and(|tf| tf.is_thunk || (tf.basic_blocks.len() == 1 && tf.basic_blocks[0].instructions.len() <= 3));
                    if !is_chainable {
                        break;
                    }
                    ref_ea = next_ea;
                }

                // 2. Fallback: `[0x<addr>]` operand symbol lookup (for `call [IAT]` / `jmp [IAT]`)
                if matched_import.is_none() {
                    for operand in &insn.operands {
                        if let Some(addr) = parse_bracket_hex(operand) {
                            let sym_hit = addr_sym_cache
                                .entry(addr)
                                .or_insert_with(|| {
                                    idb.address_to_string(addr)
                                        .and_then(|sym| match_import_symbol(&sym, &import_names))
                                })
                                .clone();
                            if let Some(name) = sym_hit {
                                let module = name_to_module.get(&name).cloned().flatten();
                                matched_import = Some((module, name));
                                break;
                            }
                        }
                    }
                }

                if let Some(entry) = matched_import {
                    map.entry(insn.address).or_default().push(entry);
                    continue;
                }

                // 3. FLIRT-recognized `is_library` function target (matching Vivisect
                // `if is_library_function(target): yield API(name)` without emitting false
                // APIs on internal non-library COFF-named functions).
                if let Some(target_ea) = code_refs_from(idb, insn.address).into_iter().next() {
                    if let Some(target_func) = functions.get(&target_ea) {
                        if target_func.is_library {
                            if let Some(raw_name) = target_func.name.as_deref() {
                                let name = raw_name.trim();
                                if !name.is_empty()
                                    && !name.starts_with('?')
                                    && !name.starts_with('$')
                                    && !name.starts_with("nullsub_")
                                    && !name.starts_with("loc_")
                                    && !name.starts_with("__security_")
                                {
                                    let entry_list = map.entry(insn.address).or_default();
                                    entry_list.push((None, name.to_string()));
                                    if let Some(cleaned) = crate::ida_loader::clean_ida_import_symbol(name) {
                                        if cleaned != name {
                                            let module = name_to_module.get(&cleaned).cloned().flatten();
                                            entry_list.push((module, cleaned));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    map
}

/// Lift a function's CFG into basic blocks.
fn lift_cfg(
    idb: &IDB,
    cfg: &idalib::func::FunctionCFG<'_>,
    _func_addr: u64,
    addr_dtype: OperandDataType,
) -> (Vec<LiftedBasicBlock>, Vec<u64>) {
    let mut blocks = Vec::new();
    let mut all_callees = Vec::new();

    for (block_idx, block) in cfg.blocks().enumerate() {
        let start = block.start_address();
        let end = block.end_address();

        let (instructions, callees) = lift_instructions(idb, start, end, addr_dtype);
        all_callees.extend(callees);

        let successors: Vec<usize> = block.succs().collect();
        let predecessors: Vec<usize> = block.preds().collect();

        // Detect loop headers: block is a loop header if any predecessor has a higher address
        let is_loop_header = predecessors.iter().any(|&pred_idx| {
            cfg.block_by_id(pred_idx)
                .map_or(false, |pred| pred.start_address() >= start)
        });

        blocks.push(LiftedBasicBlock {
            index: block_idx,
            address: start,
            end_address: if end > start { end - 1 } else { start },
            instructions,
            successors,
            predecessors,
            is_loop_header,
        });
    }

    (blocks, all_callees)
}

/// Fallback: lift a linear range of instructions as a single basic block.
fn lift_linear(idb: &IDB, start: u64, end: u64, addr_dtype: OperandDataType) -> (LiftedBasicBlock, Vec<u64>) {
    let (instructions, callees) = lift_instructions(idb, start, end, addr_dtype);

    let bb = LiftedBasicBlock {
        index: 0,
        address: start,
        end_address: if end > start { end - 1 } else { start },
        instructions,
        successors: Vec::new(),
        predecessors: Vec::new(),
        is_loop_header: false,
    };

    (bb, callees)
}

/// Lift instructions in an address range [start, end).
fn lift_instructions(idb: &IDB, start: u64, end: u64, addr_dtype: OperandDataType) -> (Vec<LiftedInstruction>, Vec<u64>) {
    let mut instructions = Vec::new();
    let mut callees = Vec::new();
    let mut ea = start;

    while ea < end {
        let insn = match idb.insn_at(ea) {
            Some(insn) => insn,
            None => {
                // Skip to next head if we can't decode here
                ea = match idb.next_head(ea) {
                    Some(next) => next,
                    None => break,
                };
                continue;
            }
        };

        let insn_len = insn.len();
        if insn_len == 0 {
            ea = match idb.next_head(ea) {
                Some(next) => next,
                None => break,
            };
            continue;
        }

        // Get mnemonic from IDA (1 FFI call — the only one per instruction)
        let mnemonic = insn
            .mnemonic()
            .unwrap_or_default()
            .to_lowercase();

        // Build operands from op_t POD fields — zero FFI, pure Rust formatting.
        // Previously called insn.print_operand(n) per operand (~6 FFI round-trips
        // + heap allocs), now formats directly from the decoded insn_t struct.
        let mut operands = Vec::new();
        let mut operand_values = Vec::new();
        let segpref = insn.segpref();

        for n in 0..insn.operand_count() {
            let (op_str, op_val) = if let Some(op) = insn.operand(n) {
                let s = format_operand(&op, segpref, addr_dtype);
                let v = operand_numeric_value(op.type_(), op.dtype(), op.value(), op.addr());
                (s, v)
            } else {
                (String::new(), None)
            };

            operands.push(op_str);
            operand_values.push(op_val);
        }

        // Build IL operations
        let mut operations = Vec::new();

        // Branch/call detection
        if insn.is_call() {
            let target = insn.operand(0).and_then(|op| {
                use idalib::insn::OperandType;
                match op.type_() {
                    OperandType::Near | OperandType::Far => op.addr(),
                    OperandType::Mem => op.addr(),
                    _ => None,
                }
            });
            operations.push(ILOperation::Branch {
                target,
                is_call: true,
            });
            let crefs = code_refs_from(idb, ea);
            if !crefs.is_empty() {
                callees.extend(crefs);
            } else if let Some(t) = target {
                callees.push(t);
            }
        } else if mnemonic.starts_with('j') || insn.is_ret() {
            let target = insn.operand(0).and_then(|op| {
                use idalib::insn::OperandType;
                match op.type_() {
                    OperandType::Near | OperandType::Far => op.addr(),
                    _ => None,
                }
            });
            operations.push(ILOperation::Branch {
                target,
                is_call: false,
            });
        }

        // XOR detection for nzxor
        if mnemonic == "xor" || mnemonic == "eor" || mnemonic == "pxor" {
            operations.push(ILOperation::Xor {
                operands: operands.clone(),
                constants: Vec::new(),
            });
        }

        // Get raw bytes
        let raw_bytes = idb.get_bytes(ea, insn_len);

        instructions.push(LiftedInstruction {
            address: ea,
            mnemonic,
            operands,
            operand_values,
            bytes: raw_bytes,
            operations,
        });

        ea += insn_len as u64;
    }

    (instructions, callees)
}

/// Build IAT entry map from imports.
fn build_iat_map(info: &BinaryInfo) -> HashMap<u64, (Option<String>, String)> {
    let mut iat = HashMap::new();
    for import in &info.imports {
        if import.address > 0 {
            let module = import.module.as_ref().map(|m| normalize_module(m));
            iat.insert(import.address, (module, import.name.clone()));
        }
    }
    iat
}

/// Build string address map from IDA's string list.
fn build_string_map(_idb: &IDB, info: &BinaryInfo) -> HashMap<u64, String> {
    let mut strings_at = HashMap::new();

    // Add strings from loader (which uses IDA's string list)
    for si in &info.strings {
        if si.address > 0 && !si.value.is_empty() {
            strings_at.insert(si.address, si.value.clone());
        }
    }

    strings_at
}

/// Build thunk target map from lifted functions.
fn build_thunk_map(functions: &HashMap<u64, LiftedFunction>) -> HashMap<u64, String> {
    functions
        .iter()
        .filter_map(|(&addr, f)| {
            if f.is_thunk {
                f.thunk_target.as_ref().map(|t| (addr, t.clone()))
            } else {
                None
            }
        })
        .collect()
}

/// Normalize module names (strip .dll suffix, lowercase).
fn normalize_module(module: &str) -> String {
    module
        .trim_end_matches(".dll")
        .trim_end_matches(".DLL")
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x86_reg_name_64bit() {
        assert_eq!(x86_reg_name(0, OperandDataType::QWord), "rax");
        assert_eq!(x86_reg_name(4, OperandDataType::QWord), "rsp");
        assert_eq!(x86_reg_name(5, OperandDataType::QWord), "rbp");
        assert_eq!(x86_reg_name(8, OperandDataType::QWord), "r8");
        assert_eq!(x86_reg_name(15, OperandDataType::QWord), "r15");
    }

    #[test]
    fn test_x86_reg_name_32bit() {
        assert_eq!(x86_reg_name(0, OperandDataType::DWord), "eax");
        assert_eq!(x86_reg_name(4, OperandDataType::DWord), "esp");
        assert_eq!(x86_reg_name(5, OperandDataType::DWord), "ebp");
        assert_eq!(x86_reg_name(8, OperandDataType::DWord), "r8d");
    }

    #[test]
    fn test_x86_reg_name_16bit() {
        assert_eq!(x86_reg_name(0, OperandDataType::Word), "ax");
        assert_eq!(x86_reg_name(4, OperandDataType::Word), "sp");
    }

    #[test]
    fn test_x86_reg_name_8bit() {
        assert_eq!(x86_reg_name(0, OperandDataType::Byte), "al");
        assert_eq!(x86_reg_name(3, OperandDataType::Byte), "bl");
    }

    #[test]
    fn test_x86_reg_name_explicit_byte_regs() {
        assert_eq!(x86_reg_name(16, OperandDataType::Byte), "al");
        assert_eq!(x86_reg_name(20, OperandDataType::Byte), "ah");
        assert_eq!(x86_reg_name(24, OperandDataType::Byte), "spl");
    }

    #[test]
    fn test_x86_reg_name_segment_regs() {
        assert_eq!(x86_reg_name(29, OperandDataType::Word), "es");
        assert_eq!(x86_reg_name(33, OperandDataType::Word), "fs");
        assert_eq!(x86_reg_name(34, OperandDataType::Word), "gs");
    }

    #[test]
    fn test_x86_reg_name_unknown() {
        assert_eq!(x86_reg_name(100, OperandDataType::QWord), "");
    }

    #[test]
    fn test_dtype_to_size_idx() {
        assert_eq!(dtype_to_size_idx(OperandDataType::QWord), 0);
        assert_eq!(dtype_to_size_idx(OperandDataType::DWord), 1);
        assert_eq!(dtype_to_size_idx(OperandDataType::Word), 2);
        assert_eq!(dtype_to_size_idx(OperandDataType::Byte), 3);
    }

    #[test]
    fn test_normalize_module() {
        assert_eq!(normalize_module("kernel32.dll"), "kernel32");
        assert_eq!(normalize_module("NTDLL.DLL"), "ntdll");
        assert_eq!(normalize_module("user32"), "user32");
    }

    #[test]
    fn test_operand_numeric_value_excludes_mem_and_displ_and_masks_imm_width() {
        // Positive: immediates masked to dtype width (`cmp eax, -1` -> 0xFFFFFFFF = 4294967295)
        assert_eq!(
            operand_numeric_value(OperandType::Imm, OperandDataType::Byte, Some(0x36), None),
            Some(0x36)
        );
        assert_eq!(
            operand_numeric_value(
                OperandType::Imm,
                OperandDataType::DWord,
                Some(0xFFFF_FFFF_FFFF_FFFF),
                None
            ),
            Some(0xFFFF_FFFF)
        );
        assert_eq!(
            operand_numeric_value(
                OperandType::Imm,
                OperandDataType::QWord,
                Some(0xFFFF_FFFF_FFFF_FFFF),
                None
            ),
            Some(-1)
        );
        assert_eq!(
            operand_numeric_value(OperandType::Near, OperandDataType::QWord, None, Some(0x140001000)),
            Some(0x140001000)
        );
        // Negative: Mem and Displ operands must NOT leak into `number:` features
        assert_eq!(
            operand_numeric_value(OperandType::Mem, OperandDataType::QWord, None, Some(0x140002000)),
            None
        );
        assert_eq!(
            operand_numeric_value(OperandType::Displ, OperandDataType::QWord, None, Some(0x20)),
            None
        );
        assert_eq!(
            operand_numeric_value(OperandType::Reg, OperandDataType::QWord, None, None),
            None
        );
    }
}
