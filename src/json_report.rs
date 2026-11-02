use crate::elf::{ElfClass, Endianness};
use crate::inspection::Inspection;
use serde_json::{Value, json};
use std::path::Path;
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}
fn byte_value(bytes: &[u8]) -> Value {
    json!({"text": String::from_utf8_lossy(bytes), "bytes_hex": hex(bytes)})
}
fn optional_bytes(bytes: Option<&[u8]>) -> Value {
    bytes.map(byte_value).unwrap_or(Value::Null)
}
#[cfg(unix)]
fn path_hex(path: &Path) -> Option<String> {
    use std::os::unix::ffi::OsStrExt;
    Some(hex(path.as_os_str().as_bytes()))
}
#[cfg(not(unix))]
fn path_hex(_path: &Path) -> Option<String> {
    None
}
pub(crate) fn record(path: &Path, inspection: &Inspection) -> Value {
    let header = &inspection.elf.header;
    let class = match header.ident.class {
        ElfClass::Elf32 => "ELF32",
        ElfClass::Elf64 => "ELF64",
    };
    let endianness = match header.ident.endianness {
        Endianness::Little => "little",
        Endianness::Big => "big",
    };
    let names_index = match header.section_names_index {
        0 => None,
        0xffff => inspection
            .sections
            .headers
            .first()
            .map(|zero| u64::from(zero.link)),
        index => Some(u64::from(index)),
    };
    let dynamic = inspection.dynamic.as_ref().map(|info| json!({
        "needed": info.needed.iter().map(|name| byte_value(name)).collect::<Vec<_>>(),
        "soname": optional_bytes(info.soname.as_deref()), "rpath": optional_bytes(info.rpath.as_deref()), "runpath": optional_bytes(info.runpath.as_deref()),
        "flags_hex": info.flags.map(|flags| format!("{:#x}", flags)), "flags_1_hex": info.flags_1.map(|flags| format!("{:#x}", flags)),
        "bind_now_tag": info.bind_now_tag, "textrel_tag": info.textrel_tag,
        "bind_now_requested": info.bind_now_requested(), "pie_flag_set": info.pie_requested(), "textrel_requested": info.textrel_requested()
    }));
    json!({
        "schema_version": 1, "kind": "elf", "path": path.to_string_lossy(), "path_bytes_hex": path_hex(path),
        "header": {"class": class, "endianness": endianness, "file_type": header.file_type, "machine": header.machine,
            "os_abi": header.ident.os_abi, "abi_version": header.ident.abi_version, "ident_version": header.ident.version, "elf_version": header.version,
            "entry_hex": format!("{:#x}", header.entry), "flags_hex": format!("{:#x}", header.flags),
            "program_header_count": inspection.elf.program_headers.len(), "section_header_count": inspection.sections.headers.len(), "section_names_index": names_index,
            "raw_e_phnum": header.program_header_count, "raw_e_shnum": header.section_header_count, "raw_e_shstrndx": header.section_names_index},
        "interpreter": optional_bytes(inspection.interpreter.as_deref()), "dynamic": dynamic,
        "build_ids": inspection.build_ids.iter().map(|id| json!({"hex": id.to_string(), "note_offset_hex": format!("{:#x}", id.note_offset), "sources": id.sources.iter().map(ToString::to_string).collect::<Vec<_>>() })).collect::<Vec<_>>(),
        "symbol_tables": inspection.symbols.iter().map(|table| json!({"section_index": table.section_index, "total": table.total, "functions": table.functions, "objects": table.objects, "locals": table.locals, "globals": table.globals, "weaks": table.weaks, "undefined": table.undefined, "extended_indices": table.extended_indices})).collect::<Vec<_>>(),
        "relocation_tables": inspection.relocations.iter().map(|table| json!({"section_index": table.section_index, "format": if table.with_addend { "RELA" } else { "REL" }, "total": table.total, "symbol_table_index": table.symbol_table_index, "target_section_index": table.target_section_index})).collect::<Vec<_>>()
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hex_preserves_zero_bytes() {
        assert_eq!(hex(&[0, 1, 0xff]), "0001ff");
    }
    #[test]
    fn preserves_invalid_utf8_as_hex() {
        let value = byte_value(&[0xff]);
        assert_eq!(value["bytes_hex"], "ff");
        assert_eq!(value["text"], "\u{fffd}");
    }
    #[test]
    fn absent_bytes_are_null() {
        assert_eq!(optional_bytes(None), Value::Null);
    }
    #[test]
    fn serialization_escapes_control_characters() {
        let value = byte_value(b"quote\" newline\n slash\\ zero\0");
        let encoded = serde_json::to_string(&value).unwrap();
        assert!(!encoded.contains('\n'));
        assert_eq!(serde_json::from_str::<Value>(&encoded).unwrap(), value);
    }
}
