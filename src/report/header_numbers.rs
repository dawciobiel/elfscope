const PN_XNUM: u16 = 0xffff;
const SHN_XINDEX: u16 = 0xffff;

pub(super) fn program_count(raw: u16, actual: usize) -> String {
    if raw == PN_XNUM {
        format!("{} (e_phnum={}, PN_XNUM)", actual, raw)
    } else {
        actual.to_string()
    }
}

pub(super) fn section_count(raw: u16, actual: usize) -> String {
    if raw == 0 && actual != 0 {
        format!("{} (e_shnum=0, rozszerzona numeracja)", actual)
    } else {
        actual.to_string()
    }
}

pub(super) fn section_names_index(raw: u16, section_zero_link: Option<u32>) -> String {
    if raw != SHN_XINDEX {
        return raw.to_string();
    }
    match section_zero_link {
        Some(actual) => format!("{} (e_shstrndx={}, SHN_XINDEX)", actual, raw),
        None => format!("nieustalony (e_shstrndx={}, SHN_XINDEX)", raw),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn displays_normal_program_count() {
        assert_eq!(program_count(14, 14), "14");
    }
    #[test]
    fn displays_extended_program_count_with_raw_marker() {
        assert_eq!(
            program_count(0xffff, 70_000),
            "70000 (e_phnum=65535, PN_XNUM)"
        );
    }
    #[test]
    fn preserves_marker_when_actual_count_equals_marker() {
        assert_eq!(
            program_count(0xffff, 65_535),
            "65535 (e_phnum=65535, PN_XNUM)"
        );
    }
    #[test]
    fn displays_normal_and_absent_section_counts() {
        assert_eq!(section_count(43, 43), "43");
        assert_eq!(section_count(0, 0), "0");
    }
    #[test]
    fn displays_extended_section_count() {
        assert_eq!(
            section_count(0, 65_281),
            "65281 (e_shnum=0, rozszerzona numeracja)"
        );
    }
    #[test]
    fn displays_normal_section_names_index() {
        assert_eq!(section_names_index(42, Some(0)), "42");
        assert_eq!(section_names_index(0, None), "0");
    }
    #[test]
    fn displays_extended_section_names_index() {
        assert_eq!(
            section_names_index(0xffff, Some(65_280)),
            "65280 (e_shstrndx=65535, SHN_XINDEX)"
        );
    }
    #[test]
    fn does_not_guess_when_section_zero_is_absent() {
        assert_eq!(
            section_names_index(0xffff, None),
            "nieustalony (e_shstrndx=65535, SHN_XINDEX)"
        );
    }
}
