use crate::elf::ProgramHeader;
use crate::sections::SectionHeader;

const PT_LOAD: u32 = 1;
const PT_TLS: u32 = 7;

const SHT_NULL: u32 = 0;
const SHT_NOBITS: u32 = 8;

const SHF_ALLOC: u64 = 0x2;
const SHF_TLS: u64 = 0x400;

const PF_X: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryLocation {
    pub segment_index: usize,
    pub file_offset: Option<u64>,
    pub executable: bool,
}

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

pub fn entry_locations(entry: u64, segments: &[ProgramHeader]) -> Vec<EntryLocation> {
    segments
        .iter()
        .enumerate()
        .filter_map(|(segment_index, segment)| {
            if segment.segment_type != PT_LOAD {
                return None;
            }

            let memory_end = segment.virtual_address.checked_add(segment.memory_size)?;

            if entry < segment.virtual_address || entry >= memory_end {
                return None;
            }

            let delta = entry.checked_sub(segment.virtual_address)?;

            let file_offset = if delta < segment.file_size {
                Some(segment.offset.checked_add(delta)?)
            } else {
                None
            };

            Some(EntryLocation {
                segment_index,
                file_offset,
                executable: segment.flags & PF_X != 0,
            })
        })
        .collect()
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

    #[test]
    fn maps_entry_to_file_offset() {
        let mut segment = segment();
        segment.flags = 5;

        let locations = entry_locations(0x4040, &[segment]);

        assert_eq!(
            locations,
            vec![EntryLocation {
                segment_index: 0,
                file_offset: Some(0x1040),
                executable: true,
            }]
        );
    }

    #[test]
    fn identifies_entry_in_zero_filled_memory() {
        let locations = entry_locations(0x4250, &[segment()]);

        assert_eq!(
            locations,
            vec![EntryLocation {
                segment_index: 0,
                file_offset: None,
                executable: false,
            }]
        );
    }

    #[test]
    fn reports_non_executable_entry_segment() {
        let locations = entry_locations(0x4040, &[segment()]);

        assert_eq!(locations.len(), 1);
        assert!(!locations[0].executable);
    }

    #[test]
    fn excludes_entry_at_memory_end() {
        assert!(entry_locations(0x4300, &[segment()]).is_empty());
        assert!(entry_locations(0x3fff, &[segment()]).is_empty());
    }

    #[test]
    fn ignores_overflowing_entry_mapping() {
        let mut segment = segment();
        segment.virtual_address = u64::MAX - 1;
        segment.memory_size = 4;

        assert!(entry_locations(u64::MAX, &[segment]).is_empty());
    }
}
