use crate::elf::ElfClass;

const EM_386: u16 = 3;
const EM_X86_64: u16 = 62;

fn type_name(class: ElfClass, machine: u16, kind: u32) -> Option<&'static str> {
    match (class, machine) {
        (ElfClass::Elf32, EM_386) => match kind {
            0 => Some("R_386_NONE"),
            1 => Some("R_386_32"),
            2 => Some("R_386_PC32"),
            3 => Some("R_386_GOT32"),
            4 => Some("R_386_PLT32"),
            5 => Some("R_386_COPY"),
            6 => Some("R_386_GLOB_DAT"),
            7 => Some("R_386_JMP_SLOT"),
            8 => Some("R_386_RELATIVE"),
            9 => Some("R_386_GOTOFF"),
            10 => Some("R_386_GOTPC"),
            _ => None,
        },
        (ElfClass::Elf64, EM_X86_64) => match kind {
            0 => Some("R_X86_64_NONE"),
            1 => Some("R_X86_64_64"),
            2 => Some("R_X86_64_PC32"),
            3 => Some("R_X86_64_GOT32"),
            4 => Some("R_X86_64_PLT32"),
            5 => Some("R_X86_64_COPY"),
            6 => Some("R_X86_64_GLOB_DAT"),
            7 => Some("R_X86_64_JUMP_SLOT"),
            8 => Some("R_X86_64_RELATIVE"),
            9 => Some("R_X86_64_GOTPCREL"),
            10 => Some("R_X86_64_32"),
            11 => Some("R_X86_64_32S"),
            16 => Some("R_X86_64_DTPMOD64"),
            17 => Some("R_X86_64_DTPOFF64"),
            18 => Some("R_X86_64_TPOFF64"),
            19 => Some("R_X86_64_TLSGD"),
            20 => Some("R_X86_64_TLSLD"),
            21 => Some("R_X86_64_DTPOFF32"),
            22 => Some("R_X86_64_GOTTPOFF"),
            23 => Some("R_X86_64_TPOFF32"),
            36 => Some("R_X86_64_TLSDESC"),
            37 => Some("R_X86_64_IRELATIVE"),
            41 => Some("R_X86_64_GOTPCRELX"),
            42 => Some("R_X86_64_REX_GOTPCRELX"),
            _ => None,
        },
        _ => None,
    }
}

pub(super) fn label(class: ElfClass, machine: u16, kind: u32) -> String {
    match type_name(class, machine, kind) {
        Some(name) => format!("{} ({})", name, kind),
        None => format!("NIEZNANY ({})", kind),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_common_x86_64_types() {
        assert_eq!(
            label(ElfClass::Elf64, EM_X86_64, 8),
            "R_X86_64_RELATIVE (8)"
        );

        assert_eq!(
            label(ElfClass::Elf64, EM_X86_64, 7),
            "R_X86_64_JUMP_SLOT (7)"
        );

        assert_eq!(
            label(ElfClass::Elf64, EM_X86_64, 6),
            "R_X86_64_GLOB_DAT (6)"
        );
    }

    #[test]
    fn names_common_i386_types() {
        assert_eq!(label(ElfClass::Elf32, EM_386, 7), "R_386_JMP_SLOT (7)");

        assert_eq!(label(ElfClass::Elf32, EM_386, 8), "R_386_RELATIVE (8)");
    }

    #[test]
    fn distinguishes_architecture_specific_numbers() {
        assert_eq!(label(ElfClass::Elf32, EM_386, 9), "R_386_GOTOFF (9)");

        assert_eq!(
            label(ElfClass::Elf64, EM_X86_64, 9),
            "R_X86_64_GOTPCREL (9)"
        );
    }

    #[test]
    fn preserves_unknown_type_number() {
        assert_eq!(
            label(ElfClass::Elf64, EM_X86_64, u32::MAX),
            "NIEZNANY (4294967295)"
        );
    }

    #[test]
    fn does_not_guess_for_other_architectures() {
        assert_eq!(label(ElfClass::Elf64, 183, 8), "NIEZNANY (8)");
    }

    #[test]
    fn requires_matching_class_and_machine() {
        assert_eq!(label(ElfClass::Elf32, EM_X86_64, 8), "NIEZNANY (8)");

        assert_eq!(label(ElfClass::Elf64, EM_386, 8), "NIEZNANY (8)");
    }

    #[test]
    fn names_relaxation_types() {
        assert_eq!(
            label(ElfClass::Elf64, EM_X86_64, 41),
            "R_X86_64_GOTPCRELX (41)"
        );

        assert_eq!(
            label(ElfClass::Elf64, EM_X86_64, 42),
            "R_X86_64_REX_GOTPCRELX (42)"
        );
    }
}
