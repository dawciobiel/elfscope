use crate::build_id::{self, BuildId};
use crate::dynamic::{self, DynamicInfo};
use crate::elf::{self, ElfFile};
use crate::interpreter;
use crate::relocations::{self, RelocationTableSummary};
use crate::sections::{self, SectionTable};
use crate::symbols::{self, SymbolTableSummary};
use std::fs::File;
use std::io;
use std::path::Path;

pub(crate) struct Inspection {
    pub(crate) elf: ElfFile,
    pub(crate) sections: SectionTable,
    pub(crate) interpreter: Option<Vec<u8>>,
    pub(crate) dynamic: Option<DynamicInfo>,
    pub(crate) symbols: Vec<SymbolTableSummary>,
    pub(crate) relocations: Vec<RelocationTableSummary>,
    pub(crate) build_ids: Vec<BuildId>,
}

pub(crate) fn inspect_file(path: &Path) -> io::Result<Option<Inspection>> {
    let mut file = File::open(path)?;
    let parsed = match elf::read_elf(&mut file)? {
        Some(parsed) => parsed,
        None => return Ok(None),
    };
    let interpreter = interpreter::read_interpreter(&mut file, &parsed.program_headers)?;
    let dynamic = dynamic::read_dynamic(&mut file, &parsed)?;
    let sections = sections::read_sections(&mut file, &parsed.header)?;
    let symbols = symbols::read_symbol_summaries(&mut file, &parsed.header, &sections.headers)?;
    let relocations =
        relocations::read_relocation_summaries(&mut file, &parsed.header, &sections.headers)?;
    let build_ids = build_id::read_build_ids(
        &mut file,
        &parsed.header,
        &sections,
        &parsed.program_headers,
    )?;
    Ok(Some(Inspection {
        elf: parsed,
        sections,
        interpreter,
        dynamic,
        symbols,
        relocations,
        build_ids,
    }))
}
