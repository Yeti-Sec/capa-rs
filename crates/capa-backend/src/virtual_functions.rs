//! Virtual functions: jmp-stub / fall-through chains merged with their target functions.
//!
//! Vivisect (and therefore Python capa) assigns a basic block to the function whose code flow
//! reaches it, even when that block is also the start of another function that is reached by
//! a tail `jmp` (or by falling through). IDA keeps such code in the target function only. For
//! every function `H` that ends in an unconditional direct `jmp` (or falls through) into the
//! start of another function `G`, this module builds an additional function `V(H)` whose
//! blocks are `H`'s blocks plus `G`'s (transitively, depth-capped, cycle-guarded). The
//! feature extractor evaluates `V(H)` in addition to the unchanged per-function evaluation and
//! the matcher reports function-scope matches of `V(H)` at `H`'s address.
//!
//! Structure-dependent features (loops, recursion, calls from/to, basic block count) are
//! computed afterwards on the merged CFG, not by unioning the per-function features.

use std::collections::{HashMap, HashSet};

use crate::lifter::{ILOperation, LiftedBasicBlock, LiftedFunction, LiftedProgram};

/// Maximum number of chained functions merged behind a head (mirrors capa's
/// `THUNK_CHAIN_DEPTH_DELTA`).
pub const MAX_CHAIN_DEPTH: usize = 5;

/// Mnemonics after which control flow does not continue to the next address.
fn is_terminator(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "jmp" | "jmpf" | "ret" | "retn" | "retf" | "retfq" | "iret" | "iretd" | "iretq" | "int3" | "ud2" | "hlt" | "call"
    )
}

/// If control flow leaves `bb` into the start of another (non-library) function, return that
/// function's address: an unconditional direct `jmp` target, or the next address when the
/// block ends without a terminator (fall-through).
fn chain_target(program: &LiftedProgram, owner: &LiftedFunction, bb: &LiftedBasicBlock) -> Option<u64> {
    let last = bb.instructions.last()?;
    let target = if last.mnemonic == "jmp" {
        last.operations.iter().find_map(|op| match op {
            ILOperation::Branch { target: Some(t), is_call: false } => Some(*t),
            _ => None,
        })?
    } else if !is_terminator(&last.mnemonic) {
        last.address + last.bytes.len() as u64
    } else {
        return None;
    };
    if target == owner.address {
        return None;
    }
    // Library (IDA FUNC_LIB) functions are merged too: capa only skips what its own FLIRT
    // signatures match, so e.g. IDA-library `__security_check_cookie -> __report_gsfailure`
    // is an ordinary Vivisect function chain there.
    program.functions.get(&target)?;
    Some(target)
}

/// Build the merged function for `head`, or `None` if it chains into no other function.
pub fn build_virtual_function(program: &LiftedProgram, head: &LiftedFunction) -> Option<LiftedFunction> {
    let mut members: Vec<&LiftedFunction> = vec![head];
    let mut index_of: HashMap<u64, usize> = HashMap::new();
    index_of.insert(head.address, 0);
    // (member index, block index within member, target member index)
    let mut links: Vec<(usize, usize, usize)> = Vec::new();

    let mut frontier = vec![0usize];
    for _ in 0..MAX_CHAIN_DEPTH {
        let mut next = Vec::new();
        for &mi in &frontier {
            let owner = members[mi];
            for (bi, bb) in owner.basic_blocks.iter().enumerate() {
                let Some(t) = chain_target(program, owner, bb) else { continue };
                let tm = match index_of.get(&t) {
                    Some(&i) => i,
                    None => {
                        let tf = program.functions.get(&t)?;
                        members.push(tf);
                        let i = members.len() - 1;
                        index_of.insert(t, i);
                        next.push(i);
                        i
                    }
                };
                links.push((mi, bi, tm));
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    if members.len() < 2 {
        return None;
    }

    // Offsets of each member's blocks in the merged block list.
    let mut offsets = Vec::with_capacity(members.len());
    let mut total = 0usize;
    for m in &members {
        offsets.push(total);
        total += m.basic_blocks.len();
    }
    let entry_index = |m: &LiftedFunction| -> usize {
        m.basic_blocks.iter().position(|b| b.address == m.address).unwrap_or(0)
    };

    let mut blocks: Vec<LiftedBasicBlock> = Vec::with_capacity(total);
    for (mi, m) in members.iter().enumerate() {
        for b in &m.basic_blocks {
            let mut nb = b.clone();
            nb.index = offsets[mi] + b.index;
            nb.successors = b.successors.iter().map(|s| offsets[mi] + s).collect();
            nb.predecessors = b.predecessors.iter().map(|p| offsets[mi] + p).collect();
            blocks.push(nb);
        }
    }
    for &(mi, bi, tm) in &links {
        if members[mi].basic_blocks.is_empty() || members[tm].basic_blocks.is_empty() {
            continue;
        }
        let from = offsets[mi] + bi;
        let to = offsets[tm] + entry_index(members[tm]);
        if !blocks[from].successors.contains(&to) {
            blocks[from].successors.push(to);
        }
        if !blocks[to].predecessors.contains(&from) {
            blocks[to].predecessors.push(from);
        }
    }

    let mut callees: Vec<u64> = Vec::new();
    let mut seen: HashSet<u64> = HashSet::new();
    let mut direct: HashSet<u64> = HashSet::new();
    let mut indirect: HashSet<u64> = HashSet::new();
    for m in &members {
        for &c in &m.callees {
            if seen.insert(c) {
                callees.push(c);
            }
            if !m.indirect_callees.contains(&c) {
                direct.insert(c);
            }
        }
        indirect.extend(m.indirect_callees.iter().copied());
    }
    let mut indirect_callees: Vec<u64> = indirect.difference(&direct).copied().collect();
    indirect_callees.sort_unstable();

    Some(LiftedFunction {
        address: head.address,
        name: head.name.clone(),
        basic_blocks: blocks,
        callees,
        callers: head.callers.clone(),
        is_thunk: false,
        thunk_target: None,
        is_library: false,
        indirect_callees,
    })
}

/// Build all virtual functions of `program` (deterministic order by head address).
pub fn build_virtual_functions(program: &LiftedProgram) -> Vec<LiftedFunction> {
    let mut addrs: Vec<u64> = program.functions.keys().copied().collect();
    addrs.sort_unstable();
    addrs
        .into_iter()
        .filter_map(|a| build_virtual_function(program, &program.functions[&a]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifter::LiftedInstruction;

    fn insn(addr: u64, mnem: &str, len: usize, ops: Vec<ILOperation>) -> LiftedInstruction {
        LiftedInstruction {
            address: addr,
            mnemonic: mnem.to_string(),
            operands: vec![],
            operand_values: vec![],
            bytes: vec![0x90; len],
            operations: ops,
        }
    }

    fn jmp(addr: u64, target: u64) -> LiftedInstruction {
        insn(addr, "jmp", 5, vec![ILOperation::Branch { target: Some(target), is_call: false }])
    }

    fn call(addr: u64, target: u64) -> LiftedInstruction {
        insn(addr, "call", 5, vec![ILOperation::Branch { target: Some(target), is_call: true }])
    }

    fn bb(index: usize, insns: Vec<LiftedInstruction>, succ: Vec<usize>, pred: Vec<usize>) -> LiftedBasicBlock {
        LiftedBasicBlock {
            index,
            address: insns[0].address,
            end_address: insns[insns.len() - 1].address,
            instructions: insns,
            successors: succ,
            predecessors: pred,
            is_loop_header: false,
        }
    }

    fn func(addr: u64, blocks: Vec<LiftedBasicBlock>, callees: Vec<u64>) -> LiftedFunction {
        LiftedFunction {
            address: addr,
            name: None,
            basic_blocks: blocks,
            callees,
            callers: vec![],
            is_thunk: false,
            thunk_target: None,
            is_library: false,
            indirect_callees: vec![],
        }
    }

    fn program(fs: Vec<LiftedFunction>) -> LiftedProgram {
        use capa_core::rule::{ArchType, FormatType, OsType};
        LiftedProgram {
            functions: fs.into_iter().map(|f| (f.address, f)).collect(),
            entry_point: 0,
            info: crate::loader::BinaryInfo {
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
                entry_point: 0,
            },
            strings_at: HashMap::new(),
            iat_entries: HashMap::new(),
            thunk_targets: HashMap::new(),
            import_apis_at: HashMap::new(),
            insn_strings_at: HashMap::new(),
            insn_bytes_at: HashMap::new(),
        }
    }

    #[test]
    fn merges_stub_with_jmp_target_and_detects_recursion() {
        // H=0x1000: `jmp 0x2000`. G=0x2000 calls H and returns. (92804faa 0x14001bbe4 shape)
        let h = func(0x1000, vec![bb(0, vec![jmp(0x1000, 0x2000)], vec![], vec![])], vec![]);
        let g = func(
            0x2000,
            vec![bb(0, vec![call(0x2000, 0x1000), insn(0x2005, "retn", 1, vec![])], vec![], vec![])],
            vec![0x1000],
        );
        let p = program(vec![h, g]);
        let v = build_virtual_functions(&p);
        // only H chains; G has no chain target
        assert_eq!(v.len(), 1);
        let v = &v[0];
        assert_eq!(v.address, 0x1000);
        assert_eq!(v.basic_blocks.len(), 2);
        assert!(v.callees.contains(&0x1000), "recursive in the union");
        assert_eq!(v.basic_blocks[0].successors, vec![1], "stub block flows into target entry");
        assert_eq!(v.basic_blocks[1].predecessors, vec![0]);
    }

    #[test]
    fn follows_fallthrough_and_chains_transitively_with_cycle_guard() {
        // A: mov; (falls through into B at 0x1005). B: jmp C. C: jmp A (cycle).
        let a = func(0x1000, vec![bb(0, vec![insn(0x1000, "mov", 5, vec![])], vec![], vec![])], vec![]);
        let b = func(0x1005, vec![bb(0, vec![jmp(0x1005, 0x3000)], vec![], vec![])], vec![]);
        let c = func(0x3000, vec![bb(0, vec![jmp(0x3000, 0x1000)], vec![], vec![])], vec![]);
        let p = program(vec![a, b, c]);
        let v = build_virtual_functions(&p);
        assert_eq!(v.len(), 3, "each member heads its own merged function");
        let va = v.iter().find(|f| f.address == 0x1000).unwrap();
        assert_eq!(va.basic_blocks.len(), 3, "A + B + C, A not duplicated");
        // cycle edge C -> A exists
        assert!(va.basic_blocks[2].successors.contains(&0));
    }

    #[test]
    fn depth_is_capped_and_library_functions_are_merged() {
        // chain of 8 functions: f0 -> f1 -> ... -> f7 via jmp
        let mut fs = Vec::new();
        for i in 0..8u64 {
            let a = 0x1000 + i * 0x100;
            let blk = if i < 7 { vec![jmp(a, a + 0x100)] } else { vec![insn(a, "retn", 1, vec![])] };
            fs.push(func(a, vec![bb(0, blk, vec![], vec![])], vec![]));
        }
        let p = program(fs);
        let v = build_virtual_function(&p, &p.functions[&0x1000]).unwrap();
        assert_eq!(v.basic_blocks.len(), 1 + MAX_CHAIN_DEPTH);

        // library (IDA FUNC_LIB) heads and targets are merged as well (capa's own FLIRT set differs)
        let mut lib = func(0x2000, vec![bb(0, vec![insn(0x2000, "retn", 1, vec![])], vec![], vec![])], vec![]);
        lib.is_library = true;
        let mut h = func(0x1000, vec![bb(0, vec![jmp(0x1000, 0x2000)], vec![], vec![])], vec![]);
        h.is_library = true;
        let p = program(vec![h, lib]);
        let v = build_virtual_functions(&p);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].basic_blocks.len(), 2);
        assert!(!v[0].is_library, "virtual function is never itself flagged library");
    }

    #[test]
    fn plain_functions_and_conditional_or_indirect_jumps_do_not_chain() {
        // ret-terminated function; function ending in indirect jmp (no Branch target)
        let r = func(0x1000, vec![bb(0, vec![insn(0x1000, "retn", 1, vec![])], vec![], vec![])], vec![]);
        let ind = func(0x2000, vec![bb(0, vec![insn(0x2000, "jmp", 2, vec![ILOperation::Branch { target: None, is_call: false }])], vec![], vec![])], vec![]);
        let tail_call_noreturn = func(0x3000, vec![bb(0, vec![call(0x3000, 0x1000)], vec![], vec![])], vec![0x1000]);
        let p = program(vec![r, ind, tail_call_noreturn]);
        assert!(build_virtual_functions(&p).is_empty());
    }
}
