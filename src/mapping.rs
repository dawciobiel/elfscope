use crate::elf::ProgramHeader;
use crate::sections::SectionHeader;

const PT_LOAD: u32 = 1;
const PT_TLS: u32 = 7;

const SHT_NULL: u32 = 0;
const SHT_NOBITS: u32 = 8;

const SHF_ALLOC: u64 = 0x2;
const SHF_TLS: u64 = 0x400;

pub fn is_supported_segment(segment: &ProgramHeader) -> bool {
    matches!(segment.segment_type, PT_LOAD | PT_TLS)
}

fn contains_range(outer_start: u64, outer_size: u64, inner_start: u64, inner_size: u64) -> bool {
    let Some(outer_end) = outer_start.checked_add(outer_size) else {
        return false;
    };

    let Some(inner_end) = inner_start.checked_add(inner_size) else {
        return false;
    };

    inner_start >= outer_start && inner_end <= outer_end
}

pub fn section_belongs_to_segment(section: &SectionHeader, segment: &ProgramHeader) -> bool {
    if !is_supported_segment(segment) {
        return false;
    }

    if section.section_type == SHT_NULL || section.size == 0 {
        return false;
    }

    if section.flags & SHF_ALLOC == 0 {
        return false;
    }

    let is_tls = section.flags & SHF_TLS != 0;
    let is_nobits = section.section_type == SHT_NOBITS;

    match segment.segment_type {
        PT_TLS if !is_tls => return false,
        PT_LOAD if is_tls && is_nobits => return false,
        _ => {}
    }

    if !contains_range(
        segment.virtual_address,
        segment.memory_size,
        section.address,
        section.size,
    ) {
        return false;
    }

    if is_nobits {
        return true;
    }

    if !contains_range(
        segment.offset,
        segment.file_size,
        section.offset,
        section.size,
    ) {
        return false;
    }

    let memory_delta = section.address.checked_sub(segment.virtual_address);

    let file_delta = section.offset.checked_sub(segment.offset);

    matches!(
        (memory_delta, file_delta),
        (Some(memory), Some(file)) if memory == file
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segment() -> ProgramHeader {
        ProgramHeader {
            segment_type: PT_LOAD,
            flags: 6,
            offset: 0x1000,
            virtual_address: 0x4000,
            physical_address: 0,
            file_size: 0x200,
            memory_size: 0x300,
            alignment: 0x1000,
        }
    }

    fn section() -> SectionHeader {
        SectionHeader {
            name_offset: 0,
            section_type: 1,
            flags: SHF_ALLOC,
            address: 0x4040,
            offset: 0x1040,
            size: 0x20,
            link: 0,
            info: 0,
            alignment: 1,
            entry_size: 0,
        }
    }

    #[test]
    fn maps_file_backed_section() {
        assert!(section_belongs_to_segment(&section(), &segment(),));
    }

    #[test]
    fn rejects_section_without_alloc_flag() {
        let mut section = section();
        section.flags = 0;

        assert!(!section_belongs_to_segment(&section, &segment(),));
    }

    #[test]
    fn rejects_section_outside_memory_range() {
        let mut section = section();
        section.address = 0x5000;

        assert!(!section_belongs_to_segment(&section, &segment(),));
    }

    #[test]
    fn rejects_mismatched_file_and_memory_offsets() {
        let mut section = section();
        section.offset += 1;

        assert!(!section_belongs_to_segment(&section, &segment(),));
    }

    #[test]
    fn maps_regular_bss_without_file_contents() {
        let mut section = section();
        section.section_type = SHT_NOBITS;
        section.address = 0x4200;
        section.size = 0x100;
        section.offset = u64::MAX;

        assert!(section_belongs_to_segment(&section, &segment(),));
    }

    #[test]
    fn maps_tbss_to_tls_but_not_load() {
        let mut section = section();
        section.flags |= SHF_TLS;
        section.section_type = SHT_NOBITS;
        section.offset = u64::MAX;

        let load = segment();
        let mut tls = segment();
        tls.segment_type = PT_TLS;

        assert!(!section_belongs_to_segment(&section, &load));
        assert!(section_belongs_to_segment(&section, &tls));
    }

    #[test]
    fn maps_tdata_to_both_load_and_tls() {
        let mut section = section();
        section.flags |= SHF_TLS;

        let load = segment();
        let mut tls = segment();
        tls.segment_type = PT_TLS;

        assert!(section_belongs_to_segment(&section, &load));
        assert!(section_belongs_to_segment(&section, &tls));
    }

    #[test]
    fn rejects_non_tls_section_in_tls_template() {
        let mut segment = segment();
        segment.segment_type = PT_TLS;

        assert!(!section_belongs_to_segment(&section(), &segment,));
    }

    #[test]
    fn rejects_overflowing_ranges() {
        assert!(!contains_range(u64::MAX, 1, u64::MAX, 1));
        assert!(!contains_range(0, u64::MAX, u64::MAX, 1));
    }

    #[test]
    fn skips_empty_sections() {
        let mut section = section();
        section.size = 0;

        assert!(!section_belongs_to_segment(&section, &segment(),));
    }
}
