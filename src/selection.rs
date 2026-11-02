use crate::elf::ElfClass;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ElfSelection {
    pub class: Option<ElfClass>,
    pub file_types: Vec<u16>,
    pub machines: Vec<u16>,
}
impl ElfSelection {
    pub fn is_active(&self) -> bool {
        self.class.is_some() || !self.file_types.is_empty() || !self.machines.is_empty()
    }
    pub fn matches(&self, class: ElfClass, file_type: u16, machine: u16) -> bool {
        self.class.map_or(true, |selected| selected == class)
            && (self.file_types.is_empty() || self.file_types.contains(&file_type))
            && (self.machines.is_empty() || self.machines.contains(&machine))
    }
}
pub fn parse_file_type(value: &str) -> Result<u16, String> {
    match value {
        "none" => Ok(0),
        "rel" => Ok(1),
        "exec" => Ok(2),
        "dyn" => Ok(3),
        "core" => Ok(4),
        _ => Err("--elf-type: dozwolone none, rel, exec, dyn, core".into()),
    }
}
pub fn parse_machine(value: &str) -> Result<u16, String> {
    match value {
        "i386" => Ok(3),
        "x86_64" => Ok(62),
        "arm" => Ok(40),
        "aarch64" => Ok(183),
        "riscv" => Ok(243),
        _ => value.parse::<u16>().map_err(|_| {
            "--machine: użyj i386, x86_64, arm, aarch64, riscv lub dziesiętnego numeru u16".into()
        }),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_selection_accepts_all_headers() {
        let s = ElfSelection::default();
        assert!(!s.is_active());
        assert!(s.matches(ElfClass::Elf64, 3, 62));
    }
    #[test]
    fn types_are_combined_with_or() {
        let s = ElfSelection {
            file_types: vec![2, 3],
            ..ElfSelection::default()
        };
        assert!(s.matches(ElfClass::Elf64, 2, 62));
        assert!(s.matches(ElfClass::Elf64, 3, 62));
        assert!(!s.matches(ElfClass::Elf64, 1, 62));
    }
    #[test]
    fn machines_are_combined_with_or() {
        let s = ElfSelection {
            machines: vec![3, 62],
            ..ElfSelection::default()
        };
        assert!(s.matches(ElfClass::Elf32, 1, 3));
        assert!(s.matches(ElfClass::Elf64, 1, 62));
        assert!(!s.matches(ElfClass::Elf64, 1, 183));
    }
    #[test]
    fn dimensions_are_combined_with_and() {
        let s = ElfSelection {
            file_types: vec![3],
            machines: vec![62],
            ..ElfSelection::default()
        };
        assert!(s.matches(ElfClass::Elf64, 3, 62));
        assert!(!s.matches(ElfClass::Elf64, 2, 62));
        assert!(!s.matches(ElfClass::Elf64, 3, 183));
    }
    #[test]
    fn class_filter_is_respected() {
        let s = ElfSelection {
            class: Some(ElfClass::Elf32),
            ..ElfSelection::default()
        };
        assert!(s.matches(ElfClass::Elf32, 1, 3));
        assert!(!s.matches(ElfClass::Elf64, 1, 62));
    }
    #[test]
    fn parses_named_machines() {
        assert_eq!(parse_machine("x86_64").unwrap(), 62);
        assert_eq!(parse_machine("aarch64").unwrap(), 183);
    }
    #[test]
    fn parses_numeric_machines() {
        assert_eq!(parse_machine("243").unwrap(), 243);
    }
    #[test]
    fn rejects_unknown_machine_values() {
        assert!(parse_machine("unknown").is_err());
        assert!(parse_machine("65536").is_err());
    }
    #[test]
    fn parses_file_types() {
        assert_eq!(parse_file_type("rel").unwrap(), 1);
        assert_eq!(parse_file_type("dyn").unwrap(), 3);
        assert!(parse_file_type("executable").is_err());
    }
}
