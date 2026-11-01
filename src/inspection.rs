use std::fs::File;
use std::io;
use std::path::Path;

use crate::dynamic::{self, DynamicInfo};
use crate::elf::{self, ElfFile};
use crate::interpreter;
use crate::sections::{self, SectionTable};

pub(crate) struct Inspection {
    pub(crate) elf: ElfFile,
    pub(crate) sections: SectionTable,
    pub(crate) interpreter: Option<Vec<u8>>,
    pub(crate) dynamic: Option<DynamicInfo>,
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

    Ok(Some(Inspection {
        elf: parsed,
        sections,
        interpreter,
        dynamic,
    }))
}
