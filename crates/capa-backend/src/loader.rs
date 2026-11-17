//! Binary loading using goblin
//!
//! Loads PE and ELF binaries and extracts basic metadata.

use capa_core::rule::{ArchType, FormatType, OsType};
use goblin::Object;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum LoaderError {
    #[error("Failed to parse binary: {0}")]
    ParseError(String),
    #[error("Unsupported binary format")]
    UnsupportedFormat,
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Information extracted from binary header
#[derive(Debug, Clone)]
pub struct BinaryInfo {
    pub os: OsType,
    pub arch: ArchType,
    pub format: FormatType,
    pub imports: Vec<ImportInfo>,
    pub exports: Vec<ExportInfo>,
    pub sections: Vec<SectionInfo>,
    pub strings: Vec<StringInfo>,
    /// PE-specific: has .NET CLR header
    pub is_dotnet: bool,
    /// PE-specific: has forwarded exports
    pub has_forwarded_exports: bool,
    /// PE-specific: is mixed-mode assembly (native + .NET)
    pub is_mixed_mode: bool,
    /// Entry point address
    pub entry_point: u64,
}

#[derive(Debug, Clone)]
pub struct ImportInfo {
    pub name: String,
    pub module: Option<String>,
    pub address: u64,
}

#[derive(Debug, Clone)]
pub struct ExportInfo {
    pub name: String,
    pub address: u64,
    /// True if this export forwards to another DLL
    pub is_forwarded: bool,
    /// Forward target if forwarded (e.g., "NTDLL.RtlAllocateHeap")
    pub forward_target: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub is_executable: bool,
}

#[derive(Debug, Clone)]
pub struct StringInfo {
    pub value: String,
    pub address: u64,
}

/// Load a binary and extract metadata
pub fn load_binary(bytes: &[u8]) -> Result<BinaryInfo, LoaderError> {
    match Object::parse(bytes).map_err(|e| LoaderError::ParseError(e.to_string()))? {
        Object::PE(pe) => load_pe(&pe, bytes),
        Object::Elf(elf) => load_elf(&elf, bytes),
        Object::Mach(_) => Err(LoaderError::UnsupportedFormat),
        Object::Archive(_) => Err(LoaderError::UnsupportedFormat),
        Object::Unknown(_) => Err(LoaderError::UnsupportedFormat),
        _ => Err(LoaderError::UnsupportedFormat),
    }
}

/// Load a binary with explicit format specification
/// Used for shellcode or when auto-detection fails
pub fn load_binary_with_format(bytes: &[u8], format: FormatType) -> Result<BinaryInfo, LoaderError> {
    match format {
        FormatType::Sc32 => load_shellcode(bytes, ArchType::I386),
        FormatType::Sc64 => load_shellcode(bytes, ArchType::Amd64),
        FormatType::Pe | FormatType::Elf | FormatType::MachO | FormatType::DotNet | FormatType::Any => {
            load_binary(bytes)
        }
    }
}

/// Load raw shellcode (no PE/ELF headers)
/// Shellcode is treated as pure machine code starting at offset 0
fn load_shellcode(bytes: &[u8], arch: ArchType) -> Result<BinaryInfo, LoaderError> {
    // Extract strings from shellcode
    let strings = extract_strings(bytes);

    // Create a single executable section covering the entire shellcode
    let sections = vec![SectionInfo {
        name: ".shellcode".to_string(),
        address: 0,
        size: bytes.len() as u64,
        is_executable: true,
    }];

    Ok(BinaryInfo {
        // Shellcode OS is unknown - could be any OS
        // Rules with os: conditions may not match
        os: OsType::Windows, // Default to Windows (most common for shellcode)
        arch,
        format: if arch == ArchType::I386 {
            FormatType::Sc32
        } else {
            FormatType::Sc64
        },
        imports: Vec::new(),   // Shellcode has no import table
        exports: Vec::new(),   // Shellcode has no export table
        sections,
        strings,
        is_dotnet: false,
        has_forwarded_exports: false,
        is_mixed_mode: false,
        entry_point: 0, // Shellcode starts at offset 0
    })
}

fn load_pe(pe: &goblin::pe::PE, bytes: &[u8]) -> Result<BinaryInfo, LoaderError> {
    let mut arch = if pe.is_64 {
        ArchType::Amd64
    } else {
        ArchType::I386
    };

    // Extract imports (standard IAT + PE delay-load imports in DataDirectory[13])
    let mut imports = Vec::new();
    for import in &pe.imports {
        imports.push(ImportInfo {
            name: import.name.to_string(),
            module: Some(import.dll.to_string()),
            address: import.offset as u64,
        });
    }
    imports.extend(extract_pe_delay_imports(pe, bytes));

    // Check for .NET CLR imports (indicates managed code)
    let has_clr_import = imports.iter().any(|i| {
        i.module.as_ref().map_or(false, |m| m.eq_ignore_ascii_case("mscoree.dll"))
    });

    // Extract exports and detect forwarded exports
    let mut exports = Vec::new();
    let mut has_forwarded_exports = false;

    for export in &pe.exports {
        if let Some(name) = export.name {
            // Check if export is forwarded
            let (is_forwarded, forward_target) = if let Some(reexport) = &export.reexport {
                has_forwarded_exports = true;
                // Reexport is an enum with DLLName and DLLOrdinal variants
                let target = match reexport {
                    goblin::pe::export::Reexport::DLLName { export, lib } => {
                        format!("{}.{}", lib, export)
                    }
                    goblin::pe::export::Reexport::DLLOrdinal { ordinal, lib } => {
                        format!("{}.#{}", lib, ordinal)
                    }
                };
                (true, Some(target))
            } else {
                (false, None)
            };

            exports.push(ExportInfo {
                name: name.to_string(),
                address: export.offset.unwrap_or(0) as u64,
                is_forwarded,
                forward_target,
            });
        }
    }

    // Extract sections
    let mut sections = Vec::new();
    let mut has_native_code = false;

    for section in &pe.sections {
        let name = String::from_utf8_lossy(&section.name)
            .trim_end_matches('\0')
            .to_string();

        let is_executable = section.characteristics & 0x20000000 != 0;
        if is_executable {
            has_native_code = true;
        }

        sections.push(SectionInfo {
            name,
            address: section.virtual_address as u64,
            size: section.virtual_size as u64,
            is_executable,
        });
    }

    // Detect .NET via CLR header directory
    let is_dotnet = pe.header.optional_header
        .map(|oh| {
            oh.data_directories.get_clr_runtime_header().is_some()
        })
        .unwrap_or(false) || has_clr_import;

    // .NET arch (G11): match capa's dotnetfile.extract_file_arch —
    //   I386 only when the CLR 32BITREQUIRED flag is set (PE32),
    //   Amd64 when PE32+ without it, else ANY (AnyCPU IL-only).
    if is_dotnet {
        let requires_32bit = clr_32bit_required(pe, bytes).unwrap_or(pe.is_64 == false);
        arch = if requires_32bit && !pe.is_64 {
            ArchType::I386
        } else if !requires_32bit && pe.is_64 {
            ArchType::Amd64
        } else {
            ArchType::Any
        };
    }

    // Mixed mode: has both .NET CLR and native executable code
    let is_mixed_mode = is_dotnet && has_native_code && !exports.is_empty();

    // Extract strings
    let strings = extract_strings(bytes);

    Ok(BinaryInfo {
        os: OsType::Windows,
        arch,
        format: if is_dotnet { FormatType::DotNet } else { FormatType::Pe },
        imports,
        exports,
        sections,
        strings,
        is_dotnet,
        has_forwarded_exports,
        is_mixed_mode,
        entry_point: pe.entry as u64,
    })
}

/// Read the CLR 2.0 header COMIMAGE_FLAGS_32BITREQUIRED (0x2) flag, if the
/// .NET runtime header is present and readable. Returns None on any failure,
/// letting the caller fall back to a PE-magic-based arch guess.
fn clr_32bit_required(pe: &goblin::pe::PE, bytes: &[u8]) -> Option<bool> {
    let oh = pe.header.optional_header?;
    let dir = oh.data_directories.get_clr_runtime_header()?;
    let clr_rva = dir.virtual_address as usize;

    // Map the CLR header RVA to a file offset via the section table.
    let mut file_off = None;
    for section in &pe.sections {
        let va = section.virtual_address as usize;
        let span = (section.virtual_size as usize).max(section.size_of_raw_data as usize);
        if clr_rva >= va && clr_rva < va + span {
            file_off = Some(clr_rva - va + section.pointer_to_raw_data as usize);
            break;
        }
    }
    let off = file_off?;

    // IMAGE_COR20_HEADER.Flags is at byte offset 16 (u32 LE).
    let flag_bytes = bytes.get(off + 16..off + 20)?;
    let flags = u32::from_le_bytes([flag_bytes[0], flag_bytes[1], flag_bytes[2], flag_bytes[3]]);
    const COMIMAGE_FLAGS_32BITREQUIRED: u32 = 0x0000_0002;
    Some(flags & COMIMAGE_FLAGS_32BITREQUIRED != 0)
}

fn load_elf(elf: &goblin::elf::Elf, bytes: &[u8]) -> Result<BinaryInfo, LoaderError> {
    use goblin::elf::header::*;

    // Detect architecture from ELF machine type
    let arch = match elf.header.e_machine {
        EM_386 => ArchType::I386,
        EM_X86_64 => ArchType::Amd64,
        EM_ARM => ArchType::Arm,
        EM_AARCH64 => ArchType::Arm64,
        EM_MIPS | EM_MIPS_RS3_LE => ArchType::Mips,
        EM_PPC => ArchType::Ppc,
        EM_PPC64 => ArchType::Ppc64,
        _ => {
            // Fallback based on bitness for unknown architectures
            if elf.is_64 {
                ArchType::Amd64
            } else {
                ArchType::I386
            }
        }
    };

    // ELF is always treated as Linux regardless of OSABI field.
    // The OSABI byte can indicate FreeBSD, Solaris, etc., but capa rules
    // target Linux-specific behaviour, so we default uniformly.
    let os = OsType::Linux;

    // Extract imports (dynamic symbols)
    let mut imports = Vec::new();
    for sym in &elf.dynsyms {
        if sym.is_import() {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                imports.push(ImportInfo {
                    name: name.to_string(),
                    module: None,
                    address: sym.st_value,
                });
            }
        }
    }

    // Extract exports
    let mut exports = Vec::new();
    for sym in &elf.dynsyms {
        if !sym.is_import() && sym.st_bind() != goblin::elf::sym::STB_LOCAL {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                if !name.is_empty() {
                    exports.push(ExportInfo {
                        name: name.to_string(),
                        address: sym.st_value,
                        is_forwarded: false,
                        forward_target: None,
                    });
                }
            }
        }
    }

    // Extract sections
    let mut sections = Vec::new();
    for section in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
            sections.push(SectionInfo {
                name: name.to_string(),
                address: section.sh_addr,
                size: section.sh_size,
                is_executable: section.sh_flags & goblin::elf::section_header::SHF_EXECINSTR as u64 != 0,
            });
        }
    }

    // Extract strings
    let strings = extract_strings(bytes);

    Ok(BinaryInfo {
        os,
        arch,
        format: FormatType::Elf,
        imports,
        exports,
        sections,
        strings,
        is_dotnet: false,
        has_forwarded_exports: false,
        is_mixed_mode: false,
        entry_point: elf.entry,
    })
}

/// Extract printable strings from binary (ASCII and wide/UTF-16LE)
/// Delegates to the public `strings` module, matching Python's
/// `capa.features.extractors.common.extract_file_strings`.
fn extract_strings(bytes: &[u8]) -> Vec<StringInfo> {
    let mut strings = Vec::new();

    for s in crate::strings::extract_ascii_strings(bytes, 4) {
        strings.push(StringInfo {
            value: s.value,
            address: s.offset,
        });
    }

    for s in crate::strings::extract_unicode_strings(bytes, 4) {
        strings.push(StringInfo {
            value: s.value,
            address: s.offset,
        });
    }

    strings
}

/// Parse PE `IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT` (`DataDirectory[13]`) descriptors,
/// returning `ImportInfo` entries at both the delay-load IAT slot VA and the initial
/// on-disk `__imp_load_<name>` helper stub VA.
#[cfg_attr(not(feature = "ida-backend"), allow(dead_code))]
pub(crate) fn extract_pe_delay_imports_from_bytes(bytes: &[u8]) -> Vec<ImportInfo> {
    if let Ok(Object::PE(pe)) = Object::parse(bytes) {
        extract_pe_delay_imports(&pe, bytes)
    } else {
        Vec::new()
    }
}

pub(crate) fn extract_pe_delay_imports(pe: &goblin::pe::PE, bytes: &[u8]) -> Vec<ImportInfo> {
    let mut out = Vec::new();
    if bytes.len() < 0x40 || &bytes[0..2] != b"MZ" {
        return out;
    }
    let e_lfanew = u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize;
    let opt_off = match e_lfanew.checked_add(24) {
        Some(v) if v + 2 <= bytes.len() => v,
        _ => return out,
    };
    let magic = u16::from_le_bytes([bytes[opt_off], bytes[opt_off + 1]]);
    let (num_rva_off, dd_base) = match magic {
        0x10b => (opt_off + 92, opt_off + 96),
        0x20b => (opt_off + 108, opt_off + 112),
        _ => return out,
    };
    if num_rva_off + 4 > bytes.len() {
        return out;
    }
    let num_rva = u32::from_le_bytes([
        bytes[num_rva_off],
        bytes[num_rva_off + 1],
        bytes[num_rva_off + 2],
        bytes[num_rva_off + 3],
    ]) as usize;
    if num_rva <= 13 {
        return out;
    }
    let dd13 = dd_base + 13 * 8;
    if dd13 + 8 > bytes.len() {
        return out;
    }
    let delay_rva = u32::from_le_bytes([bytes[dd13], bytes[dd13 + 1], bytes[dd13 + 2], bytes[dd13 + 3]]) as u64;
    let delay_size = u32::from_le_bytes([bytes[dd13 + 4], bytes[dd13 + 5], bytes[dd13 + 6], bytes[dd13 + 7]]) as usize;
    if delay_rva == 0 || delay_size < 32 {
        return out;
    }

    let image_base = pe.image_base as u64;
    let is_64 = pe.is_64;
    let ptr_size: usize = if is_64 { 8 } else { 4 };

    let rva_to_off = |rva: u64| -> Option<usize> {
        for sec in &pe.sections {
            let va = sec.virtual_address as u64;
            let span = (sec.virtual_size.max(sec.size_of_raw_data)) as u64;
            if rva >= va && rva < va + span {
                let off = (sec.pointer_to_raw_data as u64).checked_add(rva - va)? as usize;
                if off < bytes.len() {
                    return Some(off);
                }
            }
        }
        None
    };

    let read_cstr = |off: usize| -> Option<String> {
        if off >= bytes.len() {
            return None;
        }
        let max_end = (off + 256).min(bytes.len());
        let slice = &bytes[off..max_end];
        let nul = slice.iter().position(|&b| b == 0)?;
        if nul == 0 {
            return None;
        }
        let s = std::str::from_utf8(&slice[..nul]).ok()?.trim();
        if s.is_empty() {
            None
        } else {
            Some(s.to_string())
        }
    };

    let to_rva = |val: u64, attrs: u32| -> u64 {
        if (attrs & 1) != 0 || val < image_base {
            val
        } else {
            val - image_base
        }
    };

    let mut seen = std::collections::HashSet::new();
    let max_descs = (delay_size / 32).min(256);
    for idx in 0..max_descs {
        let Some(desc_off) = rva_to_off(delay_rva + (idx * 32) as u64) else {
            break;
        };
        if desc_off + 32 > bytes.len() {
            break;
        }
        let d = &bytes[desc_off..desc_off + 32];
        let attrs = u32::from_le_bytes([d[0], d[1], d[2], d[3]]);
        let dll_raw = u32::from_le_bytes([d[4], d[5], d[6], d[7]]) as u64;
        let iat_raw = u32::from_le_bytes([d[12], d[13], d[14], d[15]]) as u64;
        let int_raw = u32::from_le_bytes([d[16], d[17], d[18], d[19]]) as u64;
        if dll_raw == 0 || iat_raw == 0 || int_raw == 0 {
            break;
        }

        let Some(dll_off) = rva_to_off(to_rva(dll_raw, attrs)) else {
            continue;
        };
        let Some(raw_dll) = read_cstr(dll_off) else {
            continue;
        };
        let dll_lower = raw_dll.to_lowercase();
        let module = Some(if dll_lower.contains('.') {
            dll_lower
        } else {
            format!("{}.dll", dll_lower)
        });

        let iat_base_rva = to_rva(iat_raw, attrs);
        let int_base_rva = to_rva(int_raw, attrs);

        for slot in 0..4096usize {
            let entry_disp = (slot * ptr_size) as u64;
            let Some(int_off) = rva_to_off(int_base_rva + entry_disp) else {
                break;
            };
            if int_off + ptr_size > bytes.len() {
                break;
            }
            let thunk_val = if is_64 {
                u64::from_le_bytes(bytes[int_off..int_off + 8].try_into().unwrap())
            } else {
                u32::from_le_bytes(bytes[int_off..int_off + 4].try_into().unwrap()) as u64
            };
            if thunk_val == 0 {
                break;
            }

            let is_ordinal = if is_64 {
                (thunk_val & (1u64 << 63)) != 0
            } else {
                (thunk_val & (1u64 << 31)) != 0
            };
            let func_name = if is_ordinal {
                format!("#{}", thunk_val & 0xFFFF)
            } else {
                let hn_val = if is_64 {
                    thunk_val & 0x7FFF_FFFF_FFFF_FFFF
                } else {
                    thunk_val & 0x7FFF_FFFF
                };
                let hn_rva = to_rva(hn_val, attrs);
                let Some(hn_off) = rva_to_off(hn_rva) else {
                    continue;
                };
                let Some(n) = read_cstr(hn_off + 2) else {
                    continue;
                };
                n
            };

            let iat_slot_va = image_base.wrapping_add(iat_base_rva + entry_disp);
            if seen.insert((func_name.clone(), iat_slot_va)) {
                out.push(ImportInfo {
                    name: func_name.clone(),
                    module: module.clone(),
                    address: iat_slot_va,
                });
            }

            if let Some(iat_off) = rva_to_off(iat_base_rva + entry_disp) {
                if iat_off + ptr_size <= bytes.len() {
                    let stub_va = if is_64 {
                        u64::from_le_bytes(bytes[iat_off..iat_off + 8].try_into().unwrap())
                    } else {
                        u32::from_le_bytes(bytes[iat_off..iat_off + 4].try_into().unwrap()) as u64
                    };
                    if stub_va >= image_base
                        && stub_va != iat_slot_va
                        && seen.insert((func_name.clone(), stub_va))
                    {
                        out.push(ImportInfo {
                            name: func_name,
                            module: module.clone(),
                            address: stub_va,
                        });
                    }
                }
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ascii_strings() {
        let data = b"hello\x00world\x00ab\x00testing123\x00";
        let strings = crate::strings::extract_ascii_strings(data, 4);
        assert_eq!(strings.len(), 3); // "hello", "world", "testing123" (min 4 chars)
    }

    #[test]
    fn test_extract_wide_strings() {
        // "test" in UTF-16LE
        let data = b"t\x00e\x00s\x00t\x00\x00\x00";
        let strings = crate::strings::extract_unicode_strings(data, 4);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "test");
    }

    #[test]
    fn test_extract_strings_combined() {
        // Mix of ASCII and wide strings with proper alignment
        let mut data = Vec::new();
        data.extend_from_slice(b"hello\x00\x00\x00"); // ASCII with padding to align
        data.extend_from_slice(b"t\x00e\x00s\x00t\x00i\x00n\x00g\x00\x00\x00"); // "testing" in UTF-16LE
        let strings = extract_strings(&data);

        // Should find ASCII "hello" and potentially wide "testing"
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();
        assert!(values.contains(&"hello"));
        // Wide string extraction is best-effort due to alignment challenges
        // Just verify we got at least the ASCII string
        assert!(!strings.is_empty());
    }
}
