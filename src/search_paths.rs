use crate::dynamic::DynamicInfo;
use serde_json::{Value, json};
const MAX_PREVIEW_ENTRIES: usize = 32;
const MAX_PREVIEW_BYTES: usize = 256;
const ORIGIN: u8 = 1;
const LIB: u8 = 2;
const PLATFORM: u8 = 4;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Form {
    Empty,
    Absolute,
    Relative,
    Tokenized,
}
impl Form {
    fn name(self) -> &'static str {
        match self {
            Self::Empty => "empty_component",
            Self::Absolute => "absolute_literal",
            Self::Relative => "relative_literal",
            Self::Tokenized => "tokenized",
        }
    }
}
#[derive(Debug)]
struct Entry<'a> {
    index: usize,
    raw: &'a [u8],
    form: Form,
    tokens: u8,
    unrecognized_dollar: bool,
    parent: bool,
}
#[derive(Debug, Default)]
struct Counts {
    total: usize,
    empty: usize,
    absolute: usize,
    relative: usize,
    tokenized: usize,
    parent: usize,
    unrecognized_dollar: usize,
}
#[derive(Debug)]
struct PathList<'a> {
    explicitly_empty: bool,
    counts: Counts,
    preview: Vec<Entry<'a>>,
}
fn identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}
fn token_features(raw: &[u8]) -> (u8, bool) {
    let mut tokens = 0;
    let mut unrecognized = false;
    let mut index = 0;
    while index < raw.len() {
        if raw[index] != b'$' {
            index += 1;
            continue;
        }
        let tail = &raw[index + 1..];
        let mut matched = None;
        for (name, flag) in [
            (b"ORIGIN".as_slice(), ORIGIN),
            (b"LIB".as_slice(), LIB),
            (b"PLATFORM".as_slice(), PLATFORM),
        ] {
            if tail.first() == Some(&b'{') {
                if tail[1..].starts_with(name) && tail.get(name.len() + 1) == Some(&b'}') {
                    matched = Some((name.len() + 2, flag));
                    break;
                }
            } else if tail.starts_with(name)
                && !tail
                    .get(name.len())
                    .is_some_and(|byte| identifier_byte(*byte))
            {
                matched = Some((name.len(), flag));
                break;
            }
        }
        match matched {
            Some((length, flag)) => {
                tokens |= flag;
                index += length + 1;
            }
            None => {
                unrecognized = true;
                index += 1;
            }
        }
    }
    (tokens, unrecognized)
}
fn entry(index: usize, raw: &[u8]) -> Entry<'_> {
    let (tokens, unrecognized_dollar) = token_features(raw);
    let form = if raw.is_empty() {
        Form::Empty
    } else if tokens != 0 {
        Form::Tokenized
    } else if raw.starts_with(b"/") {
        Form::Absolute
    } else {
        Form::Relative
    };
    Entry {
        index,
        raw,
        form,
        tokens,
        unrecognized_dollar,
        parent: raw.split(|byte| *byte == b'/').any(|part| part == b".."),
    }
}
fn analyze_list(raw: Option<&[u8]>) -> Option<PathList<'_>> {
    let raw = raw?;
    let mut result = PathList {
        explicitly_empty: raw.is_empty(),
        counts: Counts::default(),
        preview: Vec::new(),
    };
    // glibc ignores a wholly empty RPATH/RUNPATH before splitting it.
    if raw.is_empty() {
        return Some(result);
    }
    for (index, part) in raw.split(|byte| *byte == b':').enumerate() {
        let item = entry(index, part);
        result.counts.total += 1;
        match item.form {
            Form::Empty => result.counts.empty += 1,
            Form::Absolute => result.counts.absolute += 1,
            Form::Relative => result.counts.relative += 1,
            Form::Tokenized => result.counts.tokenized += 1,
        }
        result.counts.parent += usize::from(item.parent);
        result.counts.unrecognized_dollar += usize::from(item.unrecognized_dollar);
        if result.preview.len() < MAX_PREVIEW_ENTRIES {
            result.preview.push(item);
        }
    }
    Some(result)
}
fn selected_tag(info: &DynamicInfo) -> Option<&'static str> {
    if info.runpath.is_some() {
        Some("RUNPATH")
    } else if info.rpath.is_some() {
        Some("RPATH")
    } else {
        None
    }
}
fn token_names(mask: u8) -> Vec<&'static str> {
    [(ORIGIN, "ORIGIN"), (LIB, "LIB"), (PLATFORM, "PLATFORM")]
        .into_iter()
        .filter_map(|(flag, name)| (mask & flag != 0).then_some(name))
        .collect()
}
fn byte_preview(raw: &[u8]) -> Value {
    let preview = &raw[..raw.len().min(MAX_PREVIEW_BYTES)];
    json!({"text": String::from_utf8_lossy(preview), "bytes_hex": preview.iter().map(|byte| format!("{:02x}", byte)).collect::<String>(), "byte_length": raw.len(), "truncated": preview.len() != raw.len()})
}
fn entry_json(item: &Entry<'_>) -> Value {
    json!({"index": item.index, "value_preview": byte_preview(item.raw), "form": item.form.name(), "dynamic_tokens": token_names(item.tokens), "unrecognized_dollar_syntax": item.unrecognized_dollar, "has_parent_component": item.parent})
}
fn list_json(list: Option<&PathList<'_>>, selected: bool) -> Value {
    let Some(list) = list else {
        return Value::Null;
    };
    json!({"selected_tag": selected, "explicitly_empty": list.explicitly_empty,
        "counts": {"entries": list.counts.total, "empty_components": list.counts.empty, "absolute_literal": list.counts.absolute, "relative_literal": list.counts.relative,
            "tokenized": list.counts.tokenized, "with_parent_component": list.counts.parent, "with_unrecognized_dollar_syntax": list.counts.unrecognized_dollar},
        "entries_preview": list.preview.iter().map(entry_json).collect::<Vec<_>>(), "preview_truncated": list.counts.total > list.preview.len()})
}
fn needed_form(item: &Entry<'_>) -> &'static str {
    if item.tokens != 0 {
        "tokenized"
    } else if item.raw.starts_with(b"/") {
        "absolute_path"
    } else if item.raw.contains(&b'/') {
        "relative_path"
    } else {
        "search_name"
    }
}
fn needed_json(info: &DynamicInfo) -> Value {
    let mut search_names = 0;
    let mut absolute = 0;
    let mut relative = 0;
    let mut tokenized = 0;
    let mut preview = Vec::new();
    for (index, raw) in info.needed.iter().enumerate() {
        let item = entry(index, raw);
        let form = needed_form(&item);
        match form {
            "search_name" => search_names += 1,
            "absolute_path" => absolute += 1,
            "relative_path" => relative += 1,
            _ => tokenized += 1,
        }
        if preview.len() < MAX_PREVIEW_ENTRIES {
            preview.push(json!({"index": index, "value_preview": byte_preview(raw), "form": form, "dynamic_tokens": token_names(item.tokens), "unrecognized_dollar_syntax": item.unrecognized_dollar}));
        }
    }
    json!({"counts": {"entries": info.needed.len(), "search_names": search_names, "absolute_paths": absolute, "relative_paths": relative, "tokenized": tokenized}, "entries_preview": preview, "preview_truncated": info.needed.len() > MAX_PREVIEW_ENTRIES})
}
pub(crate) fn json(info: &DynamicInfo) -> Value {
    let rpath = analyze_list(info.rpath.as_deref());
    let runpath = analyze_list(info.runpath.as_deref());
    let selected = selected_tag(info);
    json!({"model": "linux_glibc_static", "selected_tag": selected, "rpath_ignored_due_to_runpath": info.rpath.is_some() && info.runpath.is_some(),
        "rpath": list_json(rpath.as_ref(), selected == Some("RPATH")), "runpath": list_json(runpath.as_ref(), selected == Some("RUNPATH")), "needed": needed_json(info),
        "preview_entry_limit": MAX_PREVIEW_ENTRIES, "preview_byte_limit": MAX_PREVIEW_BYTES})
}
pub(crate) fn print(info: &DynamicInfo) {
    println!("    Analiza ścieżek: Linux/glibc, bez rozwiązywania bibliotek");
    match selected_tag(info) {
        Some(tag) => println!("      Wybrany tag własnych ścieżek: {}", tag),
        None => println!("      Brak własnych tagów RPATH/RUNPATH"),
    }
    if info.rpath.is_some() && info.runpath.is_some() {
        println!("      RPATH pomijany przez obecność RUNPATH, także pustego");
    }
    for (tag, raw) in [
        ("RPATH", info.rpath.as_deref()),
        ("RUNPATH", info.runpath.as_deref()),
    ] {
        let Some(list) = analyze_list(raw) else {
            continue;
        };
        if list.explicitly_empty {
            println!("      {}: jawnie pusty — bez elementów listy", tag);
            continue;
        }
        println!(
            "      {}: elementy={}, puste={}, względne literalne={}, z tokenami={}",
            tag, list.counts.total, list.counts.empty, list.counts.relative, list.counts.tokenized
        );
        for item in &list.preview {
            let shown = &item.raw[..item.raw.len().min(MAX_PREVIEW_BYTES)];
            println!(
                "        #{} {:?}{} | {} | tokeny={:?} | ..={} | nierozpoznane $={}",
                item.index,
                String::from_utf8_lossy(shown),
                if shown.len() != item.raw.len() {
                    " [podgląd skrócony]"
                } else {
                    ""
                },
                item.form.name(),
                token_names(item.tokens),
                item.parent,
                item.unrecognized_dollar
            );
        }
        if list.counts.total > list.preview.len() {
            println!(
                "        Podgląd ograniczony do {} elementów",
                MAX_PREVIEW_ENTRIES
            );
        }
    }
    let mut slash = 0;
    let mut tokens = 0;
    for raw in &info.needed {
        slash += usize::from(raw.contains(&b'/'));
        tokens += usize::from(token_features(raw).0 != 0);
    }
    println!(
        "      DT_NEEDED: nazwy={}, ze znakiem '/'={}, z tokenami={}",
        info.needed.len(),
        slash,
        tokens
    );
    println!("      Nie sprawdzono istnienia katalogów, praw zapisu, cache ani środowiska loadera");
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn classifies_absolute_literal() {
        assert_eq!(entry(0, b"/usr/lib").form, Form::Absolute);
    }
    #[test]
    fn classifies_relative_literal() {
        assert_eq!(entry(0, b"libs").form, Form::Relative);
    }
    #[test]
    fn preserves_empty_components_in_nonempty_list() {
        let list = analyze_list(Some(b":/lib:")).unwrap();
        assert_eq!(list.counts.total, 3);
        assert_eq!(list.counts.empty, 2);
    }
    #[test]
    fn wholly_empty_list_has_no_components() {
        let list = analyze_list(Some(b"")).unwrap();
        assert!(list.explicitly_empty);
        assert_eq!(list.counts.total, 0);
    }
    #[test]
    fn absent_list_stays_absent() {
        assert!(analyze_list(None).is_none());
    }
    #[test]
    fn recognizes_all_known_tokens() {
        assert_eq!(token_features(b"$ORIGIN/$LIB/$PLATFORM"), (7, false));
    }
    #[test]
    fn recognizes_braced_tokens() {
        assert_eq!(token_features(b"${ORIGIN}/${LIB}/${PLATFORM}"), (7, false));
    }
    #[test]
    fn does_not_accept_token_prefixes() {
        assert_eq!(token_features(b"$ORIGINAL/$LIBRARY/$PLATFORM2"), (0, true));
    }
    #[test]
    fn marks_unknown_and_malformed_dollar_syntax() {
        assert_eq!(token_features(b"$UNKNOWN/${ORIGIN/$"), (0, true));
    }
    #[test]
    fn parent_component_is_not_a_substring_test() {
        assert!(entry(0, b"$ORIGIN/../lib").parent);
        assert!(!entry(0, b"/lib..old").parent);
    }
    #[test]
    fn entry_preview_is_bounded_but_counts_are_complete() {
        let raw = vec![b':'; 1000];
        let list = analyze_list(Some(&raw)).unwrap();
        assert_eq!(list.counts.total, 1001);
        assert_eq!(list.preview.len(), MAX_PREVIEW_ENTRIES);
    }
    #[test]
    fn byte_preview_is_bounded_and_preserves_raw_prefix() {
        let raw = vec![0xff; 1000];
        let value = byte_preview(&raw);
        assert_eq!(value["byte_length"], 1000);
        assert_eq!(value["truncated"], true);
        assert_eq!(
            value["bytes_hex"].as_str().unwrap().len(),
            MAX_PREVIEW_BYTES * 2
        );
    }
    #[test]
    fn empty_runpath_still_selects_runpath_over_rpath() {
        let info = DynamicInfo {
            rpath: Some(b"/old".to_vec()),
            runpath: Some(Vec::new()),
            ..DynamicInfo::default()
        };
        assert_eq!(selected_tag(&info), Some("RUNPATH"));
    }
    #[test]
    fn classifies_needed_without_expanding_tokens() {
        assert_eq!(needed_form(&entry(0, b"libx.so")), "search_name");
        assert_eq!(needed_form(&entry(0, b"../libx.so")), "relative_path");
        assert_eq!(needed_form(&entry(0, b"/opt/libx.so")), "absolute_path");
        assert_eq!(needed_form(&entry(0, b"$ORIGIN/libx.so")), "tokenized");
    }
}
