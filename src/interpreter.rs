use std::io::{self, Read, Seek, SeekFrom};

use crate::elf::ProgramHeader;

const PT_INTERP: u32 = 3;

// Limit naszego parsera.
const MAX_INTERPRETER_SIZE: u64 = 4096;

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub fn read_interpreter(
    reader: &mut (impl Read + Seek),
    headers: &[ProgramHeader],
) -> io::Result<Option<Vec<u8>>> {
    let mut matches = headers
        .iter()
        .filter(|header| header.segment_type == PT_INTERP);

    let segment = match matches.next() {
        Some(segment) => segment,
        None => return Ok(None),
    };

    if matches.next().is_some() {
        return Err(invalid_data("Plik zawiera więcej niż jeden wpis PT_INTERP"));
    }

    if segment.file_size < 2 {
        return Err(invalid_data(
            "PT_INTERP: brak niepustej ścieżki zakończonej bajtem zerowym",
        ));
    }

    if segment.file_size > MAX_INTERPRETER_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "PT_INTERP przekracza limit narzędzia: 4096 bajtów",
        ));
    }

    let end = segment
        .offset
        .checked_add(segment.file_size)
        .ok_or_else(|| invalid_data("PT_INTERP: przepełnienie zakresu"))?;

    let file_size = reader.seek(SeekFrom::End(0))?;

    if end > file_size {
        return Err(invalid_data("PT_INTERP: zakres wykracza poza plik"));
    }

    let size = usize::try_from(segment.file_size)
        .map_err(|_| invalid_data("PT_INTERP: rozmiar nie mieści się w usize"))?;

    reader.seek(SeekFrom::Start(segment.offset))?;

    let mut bytes = vec![0_u8; size];
    reader.read_exact(&mut bytes)?;

    if bytes.last() != Some(&0) {
        return Err(invalid_data("PT_INTERP: brak końcowego bajtu zerowego"));
    }

    bytes.pop();

    if bytes.contains(&0) {
        return Err(invalid_data(
            "PT_INTERP: dodatkowy bajt zerowy wewnątrz ścieżki",
        ));
    }

    Ok(Some(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn segment(offset: u64, size: u64) -> ProgramHeader {
        ProgramHeader {
            segment_type: PT_INTERP,
            flags: 4,
            offset,
            virtual_address: 0,
            physical_address: 0,
            file_size: size,
            memory_size: size,
            alignment: 1,
        }
    }

    #[test]
    fn reads_interpreter_path() {
        let path = b"/lib/example-loader.so\0";
        let mut bytes = vec![0_u8; 16];
        bytes.extend_from_slice(path);

        let result =
            read_interpreter(&mut Cursor::new(bytes), &[segment(16, path.len() as u64)]).unwrap();

        assert_eq!(result, Some(b"/lib/example-loader.so".to_vec()));
    }

    #[test]
    fn accepts_absent_interpreter() {
        let result = read_interpreter(&mut Cursor::new(Vec::<u8>::new()), &[]).unwrap();

        assert_eq!(result, None);
    }

    #[test]
    fn rejects_duplicate_interpreters() {
        let headers = [segment(0, 3), segment(0, 3)];

        let error = read_interpreter(&mut Cursor::new(b"/a\0"), &headers).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_unterminated_path() {
        let bytes = b"/loader";

        assert!(
            read_interpreter(&mut Cursor::new(bytes), &[segment(0, bytes.len() as u64)],).is_err()
        );
    }

    #[test]
    fn rejects_embedded_zero() {
        let bytes = b"/a\0b\0";

        assert!(
            read_interpreter(&mut Cursor::new(bytes), &[segment(0, bytes.len() as u64)],).is_err()
        );
    }

    #[test]
    fn rejects_out_of_file_range() {
        assert!(read_interpreter(&mut Cursor::new(b"/a\0"), &[segment(100, 3)],).is_err());
    }

    #[test]
    fn rejects_empty_path() {
        assert!(read_interpreter(&mut Cursor::new(b"\0"), &[segment(0, 1)],).is_err());
    }

    #[test]
    fn rejects_oversized_interpreter() {
        let error = read_interpreter(
            &mut Cursor::new(Vec::<u8>::new()),
            &[segment(0, MAX_INTERPRETER_SIZE + 1)],
        )
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }
}
