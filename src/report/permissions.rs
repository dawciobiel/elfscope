use crate::dynamic::DynamicInfo;
use crate::elf::{self, ProgramHeader};
const PT_LOAD: u32 = 1;
const PT_GNU_STACK: u32 = 0x6474e551;
const PT_GNU_RELRO: u32 = 0x6474e552;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
#[derive(Debug, Default, PartialEq, Eq)]
struct PermissionDeclarations {
    stacks: Vec<(usize, u32)>,
    writable_executable_loads: Vec<usize>,
    relro: Vec<usize>,
}
fn analyze(headers: &[ProgramHeader]) -> PermissionDeclarations {
    let mut result = PermissionDeclarations::default();
    for (index, header) in headers.iter().enumerate() {
        match header.segment_type {
            PT_GNU_STACK => result.stacks.push((index, header.flags)),
            PT_GNU_RELRO => result.relro.push(index),
            PT_LOAD if header.memory_size != 0 && header.flags & (PF_W | PF_X) == (PF_W | PF_X) => {
                result.writable_executable_loads.push(index)
            }
            _ => {}
        }
    }
    result
}
fn indices(values: &[usize]) -> String {
    values
        .iter()
        .map(|index| format!("#{}", index))
        .collect::<Vec<_>>()
        .join(", ")
}
fn relro_and_now(relro: &[usize], dynamic: Option<&DynamicInfo>) -> bool {
    !relro.is_empty() && dynamic.is_some_and(DynamicInfo::bind_now_requested)
}
fn optional_flags(name: &str, flags: Option<u64>) {
    match flags {
        Some(value) => println!("    {}: {:#x}", name, value),
        None => println!("    {}: brak wpisu", name),
    }
}
pub(super) fn print(headers: &[ProgramHeader], dynamic: Option<&DynamicInfo>) {
    let declarations = analyze(headers);
    println!("  Deklaracje uprawnień ELF:");
    if declarations.stacks.is_empty() {
        println!("    Stos: brak PT_GNU_STACK — nieustalone");
    } else {
        if declarations.stacks.len() > 1 {
            println!("    Stos: wiele wpisów PT_GNU_STACK — niejednoznaczne");
        }
        for (index, flags) in &declarations.stacks {
            println!(
                "    Stos: PT_GNU_STACK #{} {} — {}",
                index,
                elf::segment_permissions(*flags),
                if flags & PF_X != 0 {
                    "zadeklarowano PF_X"
                } else {
                    "brak PF_X"
                }
            );
        }
    }
    if declarations.writable_executable_loads.is_empty() {
        println!("    Niepuste LOAD z W+X: brak");
    } else {
        println!(
            "    Niepuste LOAD z W+X: {}",
            indices(&declarations.writable_executable_loads)
        );
    }
    if declarations.relro.is_empty() {
        println!("    PT_GNU_RELRO: brak wpisu");
    } else {
        println!("    PT_GNU_RELRO: {}", indices(&declarations.relro));
    }
    match dynamic {
        Some(info) => {
            optional_flags("DT_FLAGS", info.flags);
            optional_flags("DT_FLAGS_1", info.flags_1);
            println!(
                "    Wiązanie NOW: {}",
                if info.bind_now_requested() {
                    "zadeklarowane"
                } else {
                    "brak deklaracji"
                }
            );
            println!(
                "    Marker DF_1_PIE: {}",
                if info.pie_requested() {
                    "ustawiony"
                } else {
                    "nieustawiony"
                }
            );
            println!(
                "    TEXTREL: {}",
                if info.textrel_requested() {
                    "zadeklarowano relokacje do segmentów niezapisywalnych"
                } else {
                    "brak deklaracji"
                }
            );
            crate::search_paths::print(info);
        }
        None => println!("    Flagi dynamiczne: brak PT_DYNAMIC"),
    }
    println!(
        "    PT_GNU_RELRO + NOW: {}",
        if relro_and_now(&declarations.relro, dynamic) {
            "obie deklaracje obecne"
        } else {
            "nie stwierdzono obu deklaracji"
        }
    );
    println!("    To deklaracje pliku, nie pomiar uprawnień działającego procesu");
    println!("    Nie potwierdzono pełnego RELRO ani rzeczywistych uprawnień procesu");
}
#[cfg(test)]
mod tests {
    use super::*;
    fn header(kind: u32, flags: u32, memory_size: u64) -> ProgramHeader {
        ProgramHeader {
            segment_type: kind,
            flags,
            offset: 0,
            virtual_address: 0,
            physical_address: 0,
            file_size: 0,
            memory_size,
            alignment: 1,
        }
    }
    #[test]
    fn preserves_non_executable_stack_declaration() {
        let result = analyze(&[header(PT_GNU_STACK, 6, 0)]);
        assert_eq!(result.stacks, vec![(0, 6)]);
        assert_eq!(result.stacks[0].1 & PF_X, 0);
    }
    #[test]
    fn preserves_executable_stack_declaration() {
        assert_ne!(analyze(&[header(PT_GNU_STACK, 7, 0)]).stacks[0].1 & PF_X, 0);
    }
    #[test]
    fn missing_stack_header_remains_unspecified() {
        assert!(analyze(&[]).stacks.is_empty());
    }
    #[test]
    fn keeps_multiple_stack_headers() {
        assert_eq!(
            analyze(&[header(PT_GNU_STACK, 6, 0), header(PT_GNU_STACK, 7, 0)]).stacks,
            vec![(0, 6), (1, 7)]
        );
    }
    #[test]
    fn finds_only_nonempty_writable_executable_loads() {
        assert_eq!(
            analyze(&[
                header(PT_LOAD, 7, 4096),
                header(PT_LOAD, 5, 4096),
                header(PT_LOAD, 6, 4096),
                header(PT_LOAD, 7, 0)
            ])
            .writable_executable_loads,
            vec![0]
        );
    }
    #[test]
    fn does_not_treat_other_headers_as_loads() {
        assert!(
            analyze(&[header(4, 7, 4096)])
                .writable_executable_loads
                .is_empty()
        );
    }
    #[test]
    fn records_relro_presence_without_classifying_full_relro() {
        assert_eq!(
            analyze(&[header(PT_GNU_RELRO, 4, 0), header(PT_GNU_RELRO, 4, 32)]).relro,
            vec![0, 1]
        );
    }
    #[test]
    fn combines_relro_and_now_declarations() {
        let info = DynamicInfo {
            flags: Some(8),
            ..DynamicInfo::default()
        };
        assert!(relro_and_now(&[0], Some(&info)));
    }
    #[test]
    fn requires_both_relro_and_now() {
        let info = DynamicInfo {
            flags: Some(8),
            ..DynamicInfo::default()
        };
        assert!(!relro_and_now(&[], Some(&info)));
        assert!(!relro_and_now(&[0], None));
        assert!(!relro_and_now(&[0], Some(&DynamicInfo::default())));
    }
}
