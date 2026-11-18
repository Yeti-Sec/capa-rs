//! Helper utilities
//!
//! Porting Python capa's `capa.features.extractors.helpers` module.

/// Returns true if all bytes in the buffer are zero. Empty buffer returns false.
pub fn all_zeros(buf: &[u8]) -> bool {
    !buf.is_empty() && buf.iter().all(|&b| b == 0)
}

/// Generate symbol name variants for an import.
///
/// If `include_dll` is true, generates qualified names like `module.api`.
/// Strips `.dll` extension from module name.
/// For names ending in A or W (where preceding char is lowercase), also generates base name.
/// For ordinal imports (starting with `#`), always uses qualified `module.#N` form.
pub fn generate_symbols(module: &str, api: &str, include_dll: bool) -> Vec<String> {
    let mut symbols = Vec::new();

    // Normalize module name: strip .dll extension
    let module = if module.to_lowercase().ends_with(".dll") {
        &module[..module.len() - 4]
    } else {
        module
    };

    // Ordinal imports
    if api.starts_with('#') {
        symbols.push(format!("{}.{}", module, api));
        return symbols;
    }

    if include_dll {
        // Qualified name: module.api
        symbols.push(format!("{}.{}", module, api));
    }

    // Unqualified name
    symbols.push(api.to_string());

    // A/W suffix stripping
    if api.len() > 1 && (api.ends_with('A') || api.ends_with('W')) {
        let base = &api[..api.len() - 1];
        if base.chars().last().map_or(false, |c| c.is_ascii_lowercase()) {
            if include_dll {
                symbols.push(format!("{}.{}", module, base));
            }
            symbols.push(base.to_string());
        }
    }

    symbols
}

/// Decode an `FF 15 disp32` (`call [mem]`) at `ea` and return the memory slot address
/// (RIP-relative on x64, absolute on x86). Used only to resolve a `jmp` whose target
/// instruction itself is an IAT call (capa `viv/insn.py:98-141` follows `get_coderef_from`
/// from any jump target, not only function starts).
#[allow(dead_code)]
pub(crate) fn decode_raw_iat_call_slot(raw: &[u8], ea: u64, is_64: bool) -> Option<u64> {
    if raw.len() >= 6 && raw[0] == 0xFF && raw[1] == 0x15 {
        let raw32 = [raw[2], raw[3], raw[4], raw[5]];
        return Some(if is_64 {
            ((ea as i64) + 6 + i32::from_le_bytes(raw32) as i64) as u64
        } else {
            u32::from_le_bytes(raw32) as u64
        });
    }
    None
}

#[cfg(test)]
mod iat_call_slot_tests {
    use super::decode_raw_iat_call_slot;

    #[test]
    fn decodes_ff15_slot() {
        // 0x1a0005284: ff 15 3e d9 02 00 -> slot 0x1a0005284 + 6 + 0x2d93e
        assert_eq!(
            decode_raw_iat_call_slot(&[0xff, 0x15, 0x3e, 0xd9, 0x02, 0x00], 0x1a0005284, true),
            Some(0x1a0005284 + 6 + 0x2d93e)
        );
        assert_eq!(
            decode_raw_iat_call_slot(&[0xff, 0x15, 0x38, 0x30, 0x47, 0x00], 0x401000, false),
            Some(0x473038)
        );
    }

    #[test]
    fn rejects_other_encodings() {
        assert_eq!(decode_raw_iat_call_slot(&[0xff, 0x25, 0, 0, 0, 0], 0x1000, true), None);
        assert_eq!(decode_raw_iat_call_slot(&[0xe8, 0, 0, 0, 0, 0], 0x1000, true), None);
        assert_eq!(decode_raw_iat_call_slot(&[0xff, 0x15, 0], 0x1000, true), None);
    }
}
