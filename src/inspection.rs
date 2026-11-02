use crate::build_id::{self, BuildId};
use crate::dynamic::{self, DynamicInfo};
use crate::elf::{self, ElfFile};
use crate::interpreter;
use crate::relocations::{self, RelocationLimits, RelocationTableSummary};
use crate::sections::{self, SectionTable};
use crate::selection::ElfSelection;
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
pub(crate) enum InspectionOutcome {
    NotElf,
    Filtered,
    Parsed(Box<Inspection>),
}
pub(crate) fn inspect_file(
    path: &Path,
    limits: &RelocationLimits,
    selection: &ElfSelection,
) -> io::Result<InspectionOutcome> {
    let mut file = File::open(path)?;
    let header = match elf::read_header(&mut file)? {
        Some(header) => header,
        None => return Ok(InspectionOutcome::NotElf),
    };
    if !selection.matches(header.ident.class, header.file_type, header.machine) {
        return Ok(InspectionOutcome::Filtered);
    }
    // Ten sam otwarty plik; pełny parser ponownie odczytuje nagłówek.
    // Nie zapewnia to snapshotu zawartości przy równoległym zapisie.
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(0))?;
    let parsed = elf::read_elf(&mut file)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Plik zmienił się podczas analizy nagłówka",
        )
    })?;
    let interpreter = interpreter::read_interpreter(&mut file, &parsed.program_headers)?;
    let dynamic = dynamic::read_dynamic(&mut file, &parsed)?;
    let sections = sections::read_sections(&mut file, &parsed.header)?;
    let symbols = symbols::read_symbol_summaries(&mut file, &parsed.header, &sections.headers)?;
    let relocations = relocations::read_relocation_summaries_with_limits(
        &mut file,
        &parsed.header,
        &sections.headers,
        limits,
    )?;
    let build_ids = build_id::read_build_ids(
        &mut file,
        &parsed.header,
        &sections,
        &parsed.program_headers,
    )?;
    Ok(InspectionOutcome::Parsed(Box::new(Inspection {
        elf: parsed,
        sections,
        interpreter,
        dynamic,
        symbols,
        relocations,
        build_ids,
    })))
}
