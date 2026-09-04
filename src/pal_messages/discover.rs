use super::{MAX_CSTRING_BYTES, MessagePlan, PalMessageError, SEED};
use crate::runtime_image::{ByteBackedRange, MAX_EXACT_READ, RuntimeImage};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SeedHit {
    pub address: u32,
    pub string_start: u32,
    pub string_len: u32,
}

#[derive(Clone, Copy)]
struct Occurrence {
    address: u32,
    range: ByteBackedRange,
}

pub(crate) fn discover(
    runtime: &RuntimeImage<'_>,
    _label: &str,
) -> Result<Option<MessagePlan>, PalMessageError> {
    let _ = find_unique_seed(runtime, SEED)?;
    Ok(None)
}

pub(crate) fn find_unique_seed(
    runtime: &RuntimeImage<'_>,
    needle: &[u8],
) -> Result<Option<SeedHit>, PalMessageError> {
    if needle.is_empty() {
        return Err(malformed("seed needle is empty"));
    }
    let mut hits = Vec::new();
    for range in runtime.byte_backed_ranges() {
        collect_hits(runtime, needle, range, &mut hits)?;
    }
    match hits.as_slice() {
        [] => Ok(None),
        [hit] => parse_cstring(runtime, *hit, needle.len()).map(Some),
        _ => Err(PalMessageError::Ambiguous {
            values: hits.iter().map(|hit| hit.address).collect(),
        }),
    }
}

fn malformed(context: impl Into<String>) -> PalMessageError {
    PalMessageError::Malformed {
        context: context.into(),
    }
}

fn runtime_error(address: u32, size: u32, error: crate::error::Error) -> PalMessageError {
    PalMessageError::Runtime {
        address,
        size,
        reason: error.to_string(),
    }
}

fn collect_hits(
    runtime: &RuntimeImage<'_>,
    needle: &[u8],
    range: ByteBackedRange,
    hits: &mut Vec<Occurrence>,
) -> Result<(), PalMessageError> {
    let needle_len = u32::try_from(needle.len())
        .map_err(|_| malformed("seed needle length does not fit u32"))?;
    let tail = needle_len - 1;
    let max_body = (MAX_EXACT_READ as u32)
        .checked_sub(tail)
        .ok_or_else(|| malformed("seed needle exceeds the exact-read ceiling"))?;
    if max_body == 0 {
        return Err(malformed("seed needle exceeds the exact-read ceiling"));
    }
    let mut cursor = range.start;
    while cursor < range.end {
        let remaining = range.end - cursor;
        let body = remaining.min(max_body);
        let window = (body + tail).min(remaining);
        let bytes = runtime
            .read_exact(cursor, window as usize)
            .map_err(|error| runtime_error(cursor, window, error))?;
        if let Some(last_start) = window.checked_sub(needle_len) {
            for offset in 0..=last_start {
                let start = offset as usize;
                if bytes[start..start + needle.len()] == needle[..] {
                    hits.push(Occurrence {
                        address: cursor + offset,
                        range,
                    });
                }
            }
        }
        cursor += body;
    }
    Ok(())
}

fn cstring_content_byte(byte: u8) -> bool {
    byte == b'\t' || byte == b'\n' || byte == b'\r' || (0x20..=0x7e).contains(&byte)
}

fn parse_cstring(
    runtime: &RuntimeImage<'_>,
    hit: Occurrence,
    needle_len: usize,
) -> Result<SeedHit, PalMessageError> {
    let mut string_start = hit.address;
    while string_start > hit.range.start {
        let prev = string_start - 1;
        let byte = runtime
            .read_u8(prev)
            .map_err(|error| runtime_error(prev, 1, error))?;
        if byte == 0 || !cstring_content_byte(byte) {
            break;
        }
        string_start = prev;
        if (hit.address - string_start) as usize >= MAX_CSTRING_BYTES {
            return Err(malformed("containing C-string exceeds the 128-byte bound"));
        }
    }
    let mut string_len = 0u32;
    loop {
        if string_len as usize >= MAX_CSTRING_BYTES {
            return Err(malformed("containing C-string exceeds the 128-byte bound"));
        }
        let cursor = string_start
            .checked_add(string_len)
            .ok_or_else(|| malformed("containing C-string wraps the address space"))?;
        if cursor >= hit.range.end {
            return Err(malformed("containing C-string is unterminated"));
        }
        let byte = runtime
            .read_u8(cursor)
            .map_err(|error| runtime_error(cursor, 1, error))?;
        string_len += 1;
        if byte == 0 {
            let needle_end = hit
                .address
                .checked_add(
                    u32::try_from(needle_len)
                        .map_err(|_| malformed("seed needle length does not fit u32"))?,
                )
                .ok_or_else(|| malformed("seed needle wraps the address space"))?;
            let string_end = string_start
                .checked_add(string_len)
                .ok_or_else(|| malformed("containing C-string wraps the address space"))?;
            if hit.address < string_start || needle_end >= string_end {
                return Err(malformed(
                    "seed needle is not inside the containing C-string",
                ));
            }
            return Ok(SeedHit {
                address: hit.address,
                string_start,
                string_len,
            });
        }
        if !cstring_content_byte(byte) {
            return Err(malformed("containing C-string has a non-printable byte"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{discover, find_unique_seed};
    use crate::pal_messages::{PalMessageError, SEED};
    use crate::runtime_image::RuntimeImage;

    const BASE: u32 = 0x4001_0000;

    fn runtime(raw: &[u8]) -> RuntimeImage<'_> {
        RuntimeImage::from_plan(raw, BASE, None).expect("raw fixture")
    }

    #[test]
    fn missing_seed_is_clean_absence() {
        let image = vec![0u8; 64];
        assert!(
            discover(&runtime(&image), "02_MAIN")
                .expect("no seed")
                .is_none()
        );
    }

    #[test]
    fn unique_seed_is_present_and_duplicate_is_ambiguous() {
        let mut unique = SEED.to_vec();
        unique.push(0);
        let hit = find_unique_seed(&runtime(&unique), SEED)
            .expect("unique seed")
            .expect("present");
        assert_eq!(hit.address, BASE);
        assert_eq!(hit.string_start, BASE);
        assert_eq!(hit.string_len, unique.len() as u32);

        let mut duplicate = unique.clone();
        duplicate.extend_from_slice(&unique);
        match find_unique_seed(&runtime(&duplicate), SEED) {
            Err(PalMessageError::Ambiguous { values }) => {
                assert_eq!(values, vec![BASE, BASE + unique.len() as u32]);
            }
            other => panic!("expected Ambiguous, got {other:?}"),
        }
    }

    #[test]
    fn unique_seed_after_thumb_padding_starts_at_the_needle() {
        let mut image = vec![0u8, 0xbf];
        image.extend_from_slice(SEED);
        image.push(0);
        let hit = find_unique_seed(&runtime(&image), SEED)
            .expect("unique seed")
            .expect("present");
        assert_eq!(hit.address, BASE + 2);
        assert_eq!(hit.string_start, BASE + 2);
    }

    #[test]
    fn unterminated_or_nonprintable_unique_hit_is_malformed() {
        match find_unique_seed(&runtime(SEED), SEED) {
            Err(PalMessageError::Malformed { context }) => {
                assert!(context.contains("unterminated"));
            }
            other => panic!("expected unterminated, got {other:?}"),
        }
        let mut image = SEED.to_vec();
        image.push(0x01);
        image.push(0);
        match find_unique_seed(&runtime(&image), SEED) {
            Err(PalMessageError::Malformed { context }) => {
                assert!(context.contains("non-printable"));
            }
            other => panic!("expected non-printable, got {other:?}"),
        }
    }
}
