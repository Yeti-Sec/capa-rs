//! IDA Pro binary loader — produces BinaryInfo from an IDB.
//!
//! This module uses idalib-rs to extract the same metadata
//! (imports, exports, sections, strings) that goblin+loader.rs provides,
//! but leverages IDA's analysis for richer results.

use idalib::idb::IDB;
use idalib::func::FunctionFlags;
use capa_core::rule::{ArchType, FormatType, OsType};

use crate::loader::{BinaryInfo, ExportInfo, ImportInfo, SectionInfo, StringInfo};

/// Load binary metadata from an IDA database.
pub(crate) fn load_from_idb(idb: &IDB) -> BinaryInfo {
    let meta = idb.meta();
    let processor = idb.processor();

    // Detect architecture from IDA's processor module
    let arch = detect_arch(&processor, &meta);
    let os = detect_os(&meta);
    let format = detect_format(&meta);

    // Extract imports from IDA's name list and function analysis
    let imports = extract_imports(idb);
    let exports = extract_exports(idb);
    let sections = extract_sections(idb);
    let strings = extract_strings(idb);

    // Detect .NET
    let is_dotnet = matches!(format, FormatType::DotNet)
        || processor.family().is_net();

    let entry_point = meta.start_address().unwrap_or(0);

    BinaryInfo {
        os,
        arch,
        format,
        imports,
        exports,
        sections,
        strings,
        is_dotnet,
        has_forwarded_exports: false, // IDA resolves forwarded exports transparently
        is_mixed_mode: false,
        entry_point,
    }
}

fn detect_arch(
    processor: &idalib::processor::Processor<'_>,
    meta: &idalib::meta::Metadata<'_>,
) -> ArchType {
    let family = processor.family();

    if family.is_386() {
        if meta.is_64bit() {
            ArchType::Amd64
        } else {
            ArchType::I386
        }
    } else if family.is_arm() {
        if meta.is_64bit() {
            ArchType::Arm64
        } else {
            ArchType::Arm
        }
    } else if family.is_mips() {
        ArchType::Mips
    } else if family.is_ppc() {
        if meta.is_64bit() {
            ArchType::Ppc64
        } else {
            ArchType::Ppc
        }
    } else if meta.is_64bit() {
        ArchType::Amd64
    } else {
        ArchType::I386
    }
}

fn detect_os(meta: &idalib::meta::Metadata<'_>) -> OsType {
    use idalib::meta::FileType;

    match meta.filetype() {
        FileType::PE | FileType::WIN | FileType::EXE | FileType::COM | FileType::DRV => {
            OsType::Windows
        }
        FileType::ELF | FileType::AOUT => OsType::Linux,
        FileType::MACHO => OsType::MacOS,
        _ => OsType::Windows, // default fallback
    }
}

fn detect_format(meta: &idalib::meta::Metadata<'_>) -> FormatType {
    use idalib::meta::FileType;

    match meta.filetype() {
        FileType::PE | FileType::WIN | FileType::EXE | FileType::COM | FileType::DRV => {
            FormatType::Pe
        }
        FileType::ELF | FileType::AOUT => FormatType::Elf,
        FileType::MACHO => FormatType::MachO,
        _ => FormatType::Pe, // default fallback
    }
}

/// Normalize an IDA import module name so bare names receive a `.dll` suffix.
fn normalize_import_module(raw: &str) -> Option<String> {
    if raw.is_empty() {
        None
    } else {
        let m = raw.to_lowercase();
        if m.ends_with(".dll")
            || m.ends_with(".drv")
            || m.ends_with(".sys")
            || m.ends_with(".ocx")
            || m.ends_with(".exe")
        {
            Some(m)
        } else {
            Some(format!("{}.dll", m))
        }
    }
}

/// Clean an IDA import or thunk symbol name into a bare API identifier.
/// Strips `j_`, `__imp_load_`, `__imp_`, leading `.` / `_` (for 32-bit stdcall
/// `_CreateFileA@28`), and `@<stack_bytes>` suffixes, while rejecting auto-generated
/// IDA labels (`sub_*`, `loc_*`, `nullsub_*`, `__tailMerge_*`, C++ `?` mangled names).
pub(crate) fn clean_ida_import_symbol(raw: &str) -> Option<String> {
    let mut s = raw.trim();
    if s.is_empty() || s.starts_with('?') || s.starts_with('$') {
        return None;
    }
    loop {
        if let Some(rest) = s.strip_prefix("j_") {
            s = rest;
        } else if let Some(rest) = s.strip_prefix("__imp_load_") {
            s = rest;
        } else if let Some(rest) = s.strip_prefix("__imp_") {
            s = rest;
        } else {
            break;
        }
    }
    // Reject delay-load helper internals and IDA auto-names before stripping leading '_'
    if s.starts_with("__tailMerge_")
        || s.starts_with("__delayLoadHelper")
        || s.starts_with("sub_")
        || s.starts_with("loc_")
        || s.starts_with("nullsub_")
        || s.starts_with("unk_")
        || s.starts_with("off_")
        || s.starts_with("def_")
    {
        return None;
    }
    s = s.trim_start_matches('.');
    // Strip 32-bit stdcall decoration (`_CreateFileA@28` -> `CreateFileA`),
    // while preserving genuine leading underscores on CRT imports (`_exit` != `exit`).
    if let Some(at_pos) = s.rfind('@') {
        if at_pos > 0 && s[at_pos + 1..].chars().all(|c| c.is_ascii_digit()) {
            s = &s[..at_pos];
            s = s.strip_prefix('_').unwrap_or(s);
        }
    }
    let cleaned = s;
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned.to_string())
    }
}

/// Extract imports using IDA's native import enumeration API, augmented with
/// delay-load (`__imp_load_*` / `__imp_*`) symbols from IDA's name list and thunk stubs.
fn extract_imports(idb: &IDB) -> Vec<ImportInfo> {
    let mut imports = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Primary: use IDA's native import enumeration
    // This gives us proper module names (kernel32.dll, ntdll.dll, etc.)
    let ida_imports = idalib::imports::enum_all_imports();
    for entry in &ida_imports {
        let module = normalize_import_module(&entry.module);

        let key = format!("{}@{:#x}", entry.name, entry.address);
        if seen.insert(key) {
            imports.push(ImportInfo {
                name: entry.name.clone(),
                module,
                address: entry.address,
            });
        }
    }

    // Secondary: scan IDA's name list for delay-load IAT slots (`__imp_load_*`) and
    // any `__imp_*` data symbols omitted by `get_import_module_qty()` (MSVC `/DELAYLOAD`).
    for sym in idb.names().iter() {
        let raw_name = sym.name();
        if raw_name.starts_with("__imp_load_") || raw_name.starts_with("__imp_") {
            if let Some(cleaned) = clean_ida_import_symbol(raw_name) {
                let addr = sym.address();
                let key = format!("{}@{:#x}", cleaned, addr);
                if seen.insert(key) {
                    imports.push(ImportInfo {
                        name: cleaned,
                        module: None,
                        address: addr,
                    });
                }
            }
        }
    }

    // Tertiary: check for .plt / delay-load thunk functions
    for (_id, func) in idb.functions() {
        if func.flags().contains(FunctionFlags::THUNK) {
            if let Some(name) = func.name() {
                if let Some(normalized) = clean_ida_import_symbol(&name) {
                    let key = format!("{}@{:#x}", normalized, func.start_address());
                    if seen.insert(key) {
                        imports.push(ImportInfo {
                            name: normalized,
                            module: None,
                            address: func.start_address(),
                        });
                    }
                }
            }
        }
    }

    imports
}

/// Extract exports from functions that are publicly named.
fn extract_exports(idb: &IDB) -> Vec<ExportInfo> {
    let mut exports = Vec::new();
    let names = idb.names();

    for name in names.iter() {
        if name.is_public() {
            exports.push(ExportInfo {
                name: name.name().to_string(),
                address: name.address(),
                is_forwarded: false,
                forward_target: None,
            });
        }
    }

    exports
}

/// Extract sections from IDA's segment list.
fn extract_sections(idb: &IDB) -> Vec<SectionInfo> {
    let mut sections = Vec::new();

    for (_id, seg) in idb.segments() {
        let name = seg.name().unwrap_or_default();
        let perms = seg.permissions();

        sections.push(SectionInfo {
            name,
            address: seg.start_address(),
            size: seg.len() as u64,
            is_executable: perms.is_executable(),
        });
    }

    sections
}

/// Decode raw bytes from IDA into a clean UTF-8 `String`, handling both UTF-16LE wide
/// strings (`[lo, 0x00, ...]` terminated by `0x0000`) and null-terminated ASCII/UTF-8 strings.
/// When `strict_printable_null_term` is true (used when probing unlabeled `DataRefsFrom` targets),
/// requires >= 4 strictly printable characters terminated by a null terminator within `buf`.
pub(crate) fn decode_ida_string_bytes(buf: &[u8], strict_printable_null_term: bool) -> Option<String> {
    if buf.len() < 4 {
        return None;
    }

    let is_printable_byte = |b: u8| (0x20..=0x7E).contains(&b) || matches!(b, b'\t' | b'\r' | b'\n');

    // 1. Check for UTF-16LE wide string (e.g. Windows wide paths `L"\\\\?\\C:\\foo:bar"`)
    if buf.len() >= 8 && buf[1] == 0 && buf[3] == 0 && is_printable_byte(buf[0]) && is_printable_byte(buf[2]) {
        let mut units = Vec::new();
        let mut found_nul = false;
        let mut all_ascii_printable = true;
        for chunk in buf.chunks_exact(2) {
            let u = u16::from_le_bytes([chunk[0], chunk[1]]);
            if u == 0 {
                found_nul = true;
                break;
            }
            if u > 0x7E || !is_printable_byte(u as u8) {
                all_ascii_printable = false;
                if strict_printable_null_term {
                    break;
                }
            }
            units.push(u);
        }
        if units.len() >= 4 && (!strict_printable_null_term || (found_nul && all_ascii_printable)) {
            if let Ok(s) = String::from_utf16(&units) {
                let trimmed = s.trim_end_matches('\0');
                if trimmed.chars().count() >= 4 {
                    return Some(trimmed.to_string());
                }
            }
        }
    }

    // 2. Check for null-terminated ASCII / UTF-8 string
    let nul_pos = buf.iter().position(|&b| b == 0);
    if strict_printable_null_term {
        let end = nul_pos?;
        if end < 4 || !buf[..end].iter().all(|&b| is_printable_byte(b)) {
            return None;
        }
        return std::str::from_utf8(&buf[..end]).ok().map(|s| s.to_string());
    }

    let slice = match nul_pos {
        Some(end) => &buf[..end],
        None => buf,
    };
    let s = String::from_utf8_lossy(slice);
    let trimmed = s.trim_end_matches('\0');
    if trimmed.len() >= 4 {
        Some(trimmed.to_string())
    } else {
        None
    }
}

/// Extract strings from IDA's string list, properly decoding UTF-16LE and stripping `\0`.
fn extract_strings(idb: &IDB) -> Vec<StringInfo> {
    let mut strings = Vec::new();
    let strlist = idb.strings();
    strlist.rebuild();

    for (addr, raw_lossy) in strlist.iter() {
        let read_len = raw_lossy.len().max(16).min(4096);
        let raw = idb.get_bytes(addr, read_len);
        if let Some(decoded) = decode_ida_string_bytes(&raw, false) {
            strings.push(StringInfo {
                value: decoded,
                address: addr,
            });
        } else {
            let cleaned = raw_lossy.trim_end_matches('\0');
            if cleaned.len() >= 4 && !cleaned.contains('\0') {
                strings.push(StringInfo {
                    value: cleaned.to_string(),
                    address: addr,
                });
            }
        }
    }

    strings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_import_module_bare() {
        assert_eq!(normalize_import_module("kernel32"), Some("kernel32.dll".to_string()));
        assert_eq!(normalize_import_module("KERNEL32"), Some("kernel32.dll".to_string()));
    }

    #[test]
    fn test_normalize_import_module_with_extension() {
        assert_eq!(normalize_import_module("KERNEL32.DLL"), Some("kernel32.dll".to_string()));
        assert_eq!(normalize_import_module("ntoskrnl.exe"), Some("ntoskrnl.exe".to_string()));
        assert_eq!(normalize_import_module("winspool.drv"), Some("winspool.drv".to_string()));
    }

    #[test]
    fn test_normalize_import_module_empty() {
        assert_eq!(normalize_import_module(""), None);
    }

    #[test]
    fn test_clean_ida_import_symbol() {
        assert_eq!(clean_ida_import_symbol("__imp_load_NetShareEnum"), Some("NetShareEnum".to_string()));
        assert_eq!(clean_ida_import_symbol("j___imp_CryptBinaryToStringW"), Some("CryptBinaryToStringW".to_string()));
        assert_eq!(clean_ida_import_symbol("_CreateFileA@28"), Some("CreateFileA".to_string()));
        assert_eq!(clean_ida_import_symbol("j__exit"), Some("_exit".to_string()));
        assert_eq!(clean_ida_import_symbol("__tailMerge_netapi32_dll"), None);
        assert_eq!(clean_ida_import_symbol("sub_140001000"), None);
        assert_eq!(clean_ida_import_symbol("?mangled@@YAXZ"), None);
    }

    #[test]
    fn test_decode_ida_string_bytes_utf16le_and_ascii_and_rejects_binary_guid() {
        let wide_stream: Vec<u8> = "\\\\?\\C:\\temp\\payload.bin:ads"
            .encode_utf16()
            .chain(std::iter::once(0u16))
            .flat_map(|u| u.to_le_bytes())
            .collect();
        assert_eq!(
            decode_ida_string_bytes(&wide_stream, true),
            Some("\\\\?\\C:\\temp\\payload.bin:ads".to_string())
        );

        let ascii = b"NetShareEnum\0garbage";
        assert_eq!(
            decode_ida_string_bytes(ascii, true),
            Some("NetShareEnum".to_string())
        );

        // Binary COM GUID bytes must NOT be misclassified as a strict printable string
        let guid = [
            0x9F, 0x36, 0x87, 0x0F, 0xE5, 0xA4, 0xFC, 0x4C,
            0xBD, 0x3E, 0x73, 0xE6, 0x15, 0x45, 0x72, 0xDD,
        ];
        assert_eq!(decode_ida_string_bytes(&guid, true), None);
    }
}
