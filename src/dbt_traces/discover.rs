use crate::runtime_image::{MAX_EXACT_READ, RuntimeImage};

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct DbtOccurrence {
    pub address: u32,
    pub aligned: bool,
}

#[allow(dead_code)]
pub(crate) fn sweep_occurrences(
    runtime: &RuntimeImage<'_>,
) -> Result<Vec<DbtOccurrence>, super::DbtTraceError> {
    sweep_occurrences_capped(runtime, super::MAX_OCCURRENCES)
}

/// Sweeps byte-backed ranges in bounded reads; the 27-byte overlap completes every 28-byte window in one read.
pub(crate) fn sweep_occurrences_capped(
    runtime: &RuntimeImage<'_>,
    cap: usize,
) -> Result<Vec<DbtOccurrence>, super::DbtTraceError> {
    let tail = (super::RECORD_BYTES - 1) as u32;
    let mut occurrences = Vec::new();
    for range in runtime.byte_backed_ranges() {
        let mut cursor = range.start;
        while cursor < range.end {
            let remaining = range.end - cursor;
            let body = remaining.min(MAX_EXACT_READ as u32 - tail);
            let window = (body + tail).min(remaining);
            let bytes = runtime.read_exact(cursor, window as usize)?;
            if let Some(last_start) = window.checked_sub(super::RECORD_BYTES as u32) {
                for offset in 0..=last_start {
                    let start = offset as usize;
                    if bytes[start..start + super::HEADER.len()] == super::HEADER[..] {
                        if occurrences.len() >= cap {
                            return Err(super::DbtTraceError::OccurrenceCap(cap + 1));
                        }
                        let address = cursor + offset;
                        occurrences.push(DbtOccurrence {
                            address,
                            aligned: address % 4 == 0,
                        });
                    }
                }
            }
            cursor += body;
        }
    }
    Ok(occurrences)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dbt_traces::{HEADER, RECORD_BYTES};

    fn runtime(bytes: &[u8]) -> RuntimeImage<'_> {
        RuntimeImage::from_plan(bytes, 0x4000_0000, None).expect("raw runtime")
    }

    fn brute(image: &[u8]) -> Vec<usize> {
        let mut positions = Vec::new();
        if let Some(last) = image.len().checked_sub(RECORD_BYTES) {
            for at in 0..=last {
                if image[at..at + HEADER.len()] == HEADER[..] {
                    positions.push(at);
                }
            }
        }
        positions
    }

    #[test]
    fn sweep_finds_aligned_and_unaligned_headers() {
        let mut image = vec![0u8; 0x100];
        image[0x10..0x14].copy_from_slice(HEADER);
        image[0x33..0x37].copy_from_slice(HEADER);
        let hits = sweep_occurrences(&runtime(&image)).expect("sweep");
        let addresses: Vec<u32> = hits.iter().map(|h| h.address).collect();
        assert_eq!(addresses, vec![0x4000_0010, 0x4000_0033]);
        assert!(hits[0].aligned);
        assert!(!hits[1].aligned);
    }

    #[test]
    fn sweep_needs_readable_following_bytes_but_any_bytes_suffice() {
        let mut image = vec![0u8; 0x40];
        image[0x4..0x8].copy_from_slice(HEADER);
        assert_eq!(sweep_occurrences(&runtime(&image)).unwrap().len(), 1);
    }

    #[test]
    fn sweep_at_exact_range_end_is_found() {
        let mut image = vec![0u8; 0x20];
        let start = image.len() - super::super::RECORD_BYTES;
        image[start..start + 4].copy_from_slice(HEADER);
        assert_eq!(sweep_occurrences(&runtime(&image)).unwrap().len(), 1);
    }

    #[test]
    fn sweep_enforces_the_occurrence_cap() {
        let mut image = vec![0u8; 0x40];
        image[0x0..0x4].copy_from_slice(HEADER);
        image[0x10..0x14].copy_from_slice(HEADER);
        image[0x20..0x24].copy_from_slice(HEADER);
        let runtime = runtime(&image);
        let error = sweep_occurrences_capped(&runtime, 2).unwrap_err();
        assert!(matches!(
            error,
            super::super::DbtTraceError::OccurrenceCap(3)
        ));
    }

    #[test]
    fn sweep_matches_a_brute_force_reference_scan() {
        let mut image = vec![0u8; crate::runtime_image::MAX_EXACT_READ + 0x100];
        let mut at = 7;
        while at + HEADER.len() <= image.len() {
            image[at..at + HEADER.len()].copy_from_slice(HEADER);
            at += 7;
        }
        let exact_end = image.len() - RECORD_BYTES;
        image[exact_end..exact_end + HEADER.len()].copy_from_slice(HEADER);
        let expected: Vec<u32> = brute(&image)
            .iter()
            .map(|&p| 0x4000_0000 + p as u32)
            .collect();
        assert!(expected.contains(&(0x4000_0000 + exact_end as u32)));
        let hits = sweep_occurrences(&runtime(&image)).expect("sweep");
        let addresses: Vec<u32> = hits.iter().map(|h| h.address).collect();
        assert_eq!(addresses, expected);
    }
}
