use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use crate::runtime_image::{MAX_EXACT_READ, RuntimeImage, StorageKind};

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

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) enum MessageRef {
    Text(u32),
    Unresolved {
        pointer: u32,
        storage: UnmappedStorage,
    },
}

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) enum UnmappedStorage {
    Unmapped,
    ScatterZero,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuarantineReason {
    MessageUnterminated,
    MessageOverCap,
    MessageInvalidBytes,
    PointerWrap,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QuarantinedRecord {
    pub address: u32,
    pub reason: QuarantineReason,
    pub raw_words: [u32; 7],
}

#[allow(dead_code)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FourthCounts {
    pub parameter_count: u64,
    pub sentinel: u64,
    pub unknown: u64,
}

#[allow(dead_code)]
#[derive(Debug, Default)]
pub(crate) struct Discovery {
    pub spill_path: PathBuf,
    pub record_count: usize,
    pub quarantined: Vec<QuarantinedRecord>,
    pub files: Vec<String>,
    pub messages: Vec<String>,
    pub occurrences: usize,
    pub aligned_records: usize,
    pub unaligned_records: usize,
    pub unresolved_messages: usize,
    pub fourth: FourthCounts,
    pub scatter_entries_used: BTreeSet<usize>,
}

enum MessageResolution {
    Resolved(String),
    Unresolved(UnmappedStorage),
    Bad(QuarantineReason),
}

fn readable_slab<'a>(
    runtime: &'a RuntimeImage<'_>,
    cursor: u32,
    want: usize,
) -> Option<Cow<'a, [u8]>> {
    let mut n = want.max(1);
    loop {
        if let Ok(slab) = runtime.read_exact(cursor, n) {
            return Some(slab);
        }
        if n == 1 {
            return None;
        }
        n /= 2;
    }
}

fn resolve_message(runtime: &RuntimeImage<'_>, pointer: u32) -> MessageResolution {
    let Some(end) = pointer.checked_add(super::MAX_MESSAGE_BYTES as u32) else {
        return MessageResolution::Bad(QuarantineReason::PointerWrap);
    };
    let mut bytes: Vec<u8> = Vec::with_capacity(64);
    let mut cursor = pointer;
    while cursor < end {
        let want = ((end - cursor) as usize).min(256);
        let Some(slab) = readable_slab(runtime, cursor, want) else {
            return MessageResolution::Unresolved(UnmappedStorage::Unmapped);
        };
        for (i, &byte) in slab.iter().enumerate() {
            if byte == 0 {
                // A NUL served by scatter zero-fill is not a terminator.
                if let Ok(spans) = runtime.storage_spans(cursor + i as u32, 1)
                    && matches!(
                        spans.first().map(|span| span.kind),
                        Some(StorageKind::ScatterZero)
                    )
                {
                    return MessageResolution::Unresolved(UnmappedStorage::ScatterZero);
                }
                return match String::from_utf8(bytes) {
                    Ok(text) => MessageResolution::Resolved(text),
                    Err(_) => MessageResolution::Bad(QuarantineReason::MessageInvalidBytes),
                };
            }
            if byte != b'\t' && !(0x20..=0x7e).contains(&byte) {
                return MessageResolution::Bad(QuarantineReason::MessageInvalidBytes);
            }
            bytes.push(byte);
        }
        cursor += slab.len() as u32;
    }
    MessageResolution::Bad(QuarantineReason::MessageOverCap)
}

fn read_bounded_string(runtime: &RuntimeImage<'_>, pointer: u32, max: usize) -> Option<String> {
    let mut bytes: Vec<u8> = Vec::with_capacity(64);
    let mut cursor = pointer;
    let mut remaining = max;
    while remaining > 0 {
        let want = remaining.min(256);
        let slab = readable_slab(runtime, cursor, want)?;
        for &byte in slab.iter() {
            if byte == 0 {
                return String::from_utf8(bytes).ok();
            }
            if !(0x20..=0x7e).contains(&byte) {
                return None;
            }
            bytes.push(byte);
        }
        cursor += slab.len() as u32;
        remaining -= slab.len();
    }
    None
}

#[allow(dead_code)]
pub(crate) fn discover(
    runtime: &RuntimeImage<'_>,
    spill_dir: &Path,
) -> Result<Discovery, super::DbtTraceError> {
    let occurrences = sweep_occurrences(runtime)?;
    std::fs::create_dir_all(spill_dir)?;
    let spill_path = spill_dir.join("records.spill");
    let mut spill = BufWriter::new(std::fs::File::create(&spill_path)?);
    let mut discovery = Discovery {
        spill_path,
        ..Discovery::default()
    };
    discovery.occurrences = occurrences.len();
    let mut file_index: BTreeMap<String, u32> = BTreeMap::new();
    let mut message_index: BTreeMap<String, u32> = BTreeMap::new();
    for occurrence in occurrences {
        let bytes = runtime.read_exact(occurrence.address, super::RECORD_BYTES)?;
        let mut words = [0u32; 7];
        for (word, chunk) in words.iter_mut().zip(bytes.as_chunks::<4>().0) {
            *word = u32::from_le_bytes(*chunk);
        }
        // Plausibility threshold: source path + line. Below -> noise.
        let Some(path) = read_bounded_string(runtime, words[6], 200) else {
            continue;
        };
        if !crate::source_tree::is_src_path(&path) {
            continue;
        }
        if words[5] == 0 || words[5] > super::MAX_LINE {
            continue;
        }
        // Invariants: message pointer.
        let message = match resolve_message(runtime, words[4]) {
            MessageResolution::Resolved(text) => {
                let id = intern(
                    &mut discovery.messages,
                    &mut message_index,
                    &text,
                    super::MAX_UNIQUE_MESSAGES,
                    super::DbtTraceError::MessageCap,
                )?;
                MessageRef::Text(id)
            }
            MessageResolution::Unresolved(storage) => {
                discovery.unresolved_messages += 1;
                MessageRef::Unresolved {
                    pointer: words[4],
                    storage,
                }
            }
            MessageResolution::Bad(reason) => {
                quarantine(&mut discovery, occurrence.address, reason, words)?;
                continue;
            }
        };
        let file_id = intern(
            &mut discovery.files,
            &mut file_index,
            &path,
            super::MAX_UNIQUE_FILES,
            super::DbtTraceError::FileCap,
        )?;
        if discovery.record_count >= super::MAX_RECORDS {
            return Err(super::DbtTraceError::RecordCap(discovery.record_count + 1));
        }
        if occurrence.aligned {
            discovery.aligned_records += 1;
        } else {
            discovery.unaligned_records += 1;
        }
        classify_fourth(&mut discovery, words[3]);
        for span in runtime.storage_spans(occurrence.address, super::RECORD_BYTES as u32)? {
            if let Some(entry) = span.scatter_entry {
                discovery.scatter_entries_used.insert(entry);
            }
        }
        let (msg_kind, msg_idx_or_ptr) = match message {
            MessageRef::Text(id) => (0u8, id),
            MessageRef::Unresolved { pointer, storage } => (
                if matches!(storage, UnmappedStorage::Unmapped) {
                    1
                } else {
                    2
                },
                pointer,
            ),
        };
        spill.write_all(&occurrence.address.to_le_bytes())?;
        spill.write_all(&[u8::from(occurrence.aligned)])?;
        spill.write_all(&words[1].to_le_bytes())?;
        spill.write_all(&words[2].to_le_bytes())?;
        spill.write_all(&words[3].to_le_bytes())?;
        spill.write_all(&words[5].to_le_bytes())?;
        spill.write_all(&file_id.to_le_bytes())?;
        spill.write_all(&[msg_kind])?;
        spill.write_all(&msg_idx_or_ptr.to_le_bytes())?;
        discovery.record_count += 1;
    }
    spill.flush()?;
    Ok(discovery)
}

fn intern(
    table: &mut Vec<String>,
    index: &mut BTreeMap<String, u32>,
    value: &str,
    cap: usize,
    mk_err: fn(usize) -> super::DbtTraceError,
) -> Result<u32, super::DbtTraceError> {
    if let Some(id) = index.get(value) {
        return Ok(*id);
    }
    if table.len() >= cap {
        return Err(mk_err(table.len() + 1));
    }
    let id = table.len() as u32;
    table.push(value.to_string());
    index.insert(value.to_string(), id);
    Ok(id)
}

fn quarantine(
    discovery: &mut Discovery,
    address: u32,
    reason: QuarantineReason,
    raw_words: [u32; 7],
) -> Result<(), super::DbtTraceError> {
    if discovery.quarantined.len() >= super::MAX_QUARANTINED {
        return Err(super::DbtTraceError::QuarantineCap(
            discovery.quarantined.len() + 1,
        ));
    }
    discovery.quarantined.push(QuarantinedRecord {
        address,
        reason,
        raw_words,
    });
    Ok(())
}

fn classify_fourth(discovery: &mut Discovery, raw: u32) {
    if raw <= 32 {
        discovery.fourth.parameter_count += 1;
    } else if raw == 0xfecdba98 {
        discovery.fourth.sentinel += 1;
    } else {
        discovery.fourth.unknown += 1;
    }
}

#[cfg(test)]
pub(crate) mod testkit {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    pub(crate) const BASE: u32 = 0x4000_0000;

    static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);

    pub(crate) fn unique_dir(prefix: &str) -> std::path::PathBuf {
        let n = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("{prefix}-{n}-{}", std::process::id()))
    }

    pub(crate) fn ptr(offset: usize) -> u32 {
        BASE + offset as u32
    }

    pub(crate) fn record(words: [u32; 7]) -> [u8; 28] {
        let mut bytes = [0u8; 28];
        for (i, word) in words.iter().enumerate() {
            bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    #[allow(dead_code)]
    pub(crate) fn image_with(records: &[([u8; 28], usize)], filler: usize) -> Vec<u8> {
        let mut image = vec![0xaau8; filler];
        for (rec, at) in records {
            let end = at + 28;
            if image.len() < end {
                image.resize(end, 0xaa);
            }
            image[*at..end].copy_from_slice(rec);
        }
        image
    }

    pub(crate) fn good_record(file_off: usize, msg_off: usize) -> [u32; 7] {
        [
            u32::from_le_bytes(*b"DBT:"),
            4,
            2,
            0xfecdba98,
            ptr(msg_off),
            214,
            ptr(file_off),
        ]
    }

    pub(crate) fn layout() -> (Vec<u8>, usize, usize) {
        // file string at 0x100, message at 0x140, record at 0x200
        let mut image = vec![0u8; 0x220];
        image[0x100..0x109].copy_from_slice(b"main.c\0\0\0");
        image[0x140..0x149].copy_from_slice(b"hello %d\0");
        (image, 0x100, 0x140)
    }

    pub(crate) fn discover_tmp(image: &[u8]) -> Discovery {
        let runtime = RuntimeImage::from_plan(image, BASE, None).unwrap();
        let dir = unique_dir("dbt-discover");
        std::fs::create_dir_all(&dir).unwrap();
        discover(&runtime, &dir).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::{BASE, discover_tmp, good_record, layout, ptr, record};
    use super::*;
    use crate::dbt_traces::{
        DbtTraceError, HEADER, MAX_MESSAGE_BYTES, MAX_QUARANTINED, RECORD_BYTES,
    };
    use crate::scatter::{
        Descriptor, HandlerMap, LoadPlan, Operation, PlannedEntry, PlannedOutput,
    };

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
        let start = image.len() - RECORD_BYTES;
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
        assert!(matches!(error, DbtTraceError::OccurrenceCap(3)));
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

    #[test]
    fn valid_record_is_discovered_with_interned_strings() {
        let (mut image, file_off, msg_off) = layout();
        image[0x200..0x21c].copy_from_slice(&record(good_record(file_off, msg_off)));
        let discovery = discover_tmp(&image);
        assert_eq!(discovery.record_count, 1);
        assert_eq!(discovery.files, vec!["main.c".to_string()]);
        assert_eq!(discovery.messages, vec!["hello %d".to_string()]);
        assert_eq!(discovery.aligned_records, 1);
        assert_eq!(discovery.fourth.sentinel, 1);
        assert!(discovery.quarantined.is_empty());
    }

    #[test]
    fn below_threshold_is_noise_not_error() {
        let (mut image, file_off, msg_off) = layout();
        image.resize(0x25c, 0);
        let mut words = good_record(file_off, msg_off);
        words[5] = 0;
        image[0x200..0x21c].copy_from_slice(&record(words));
        let mut words = good_record(file_off, msg_off);
        words[6] = ptr(msg_off);
        image[0x240..0x25c].copy_from_slice(&record(words));
        let discovery = discover_tmp(&image);
        assert_eq!(discovery.record_count, 0);
        assert!(discovery.quarantined.is_empty());
    }

    #[test]
    fn unmapped_message_pointer_is_unresolved_not_quarantined() {
        let (mut image, file_off, _msg_off) = layout();
        let mut words = good_record(file_off, 0);
        words[4] = 0x7000_0000;
        image[0x200..0x21c].copy_from_slice(&record(words));
        let discovery = discover_tmp(&image);
        assert_eq!(discovery.record_count, 1);
        assert_eq!(discovery.unresolved_messages, 1);
        assert!(discovery.quarantined.is_empty());
    }

    #[test]
    fn unterminated_and_invalid_messages_are_quarantined_with_reasons() {
        let record_at = 0x140 + MAX_MESSAGE_BYTES + 0x40;
        let mut image = vec![0u8; record_at + RECORD_BYTES];
        image[0x100..0x107].copy_from_slice(b"main.c\0");
        image[0x140..0x140 + MAX_MESSAGE_BYTES].fill(b'x');
        image[record_at..record_at + RECORD_BYTES]
            .copy_from_slice(&record(good_record(0x100, 0x140)));
        let discovery = discover_tmp(&image);
        assert_eq!(discovery.quarantined.len(), 1);
        assert!(matches!(
            discovery.quarantined[0].reason,
            QuarantineReason::MessageOverCap
        ));

        let (mut image2, file_off, msg_off) = layout();
        image2[0x140..0x143].copy_from_slice(b"a\x01b");
        image2[0x200..0x21c].copy_from_slice(&record(good_record(file_off, msg_off)));
        let discovery = discover_tmp(&image2);
        assert_eq!(discovery.quarantined.len(), 1);
        assert!(matches!(
            discovery.quarantined[0].reason,
            QuarantineReason::MessageInvalidBytes
        ));
    }

    #[test]
    fn message_pointer_wrap_is_quarantined() {
        let (mut image, file_off, _msg_off) = layout();
        let mut words = good_record(file_off, 0);
        words[4] = u32::MAX - 2;
        image[0x200..0x21c].copy_from_slice(&record(words));
        let discovery = discover_tmp(&image);
        assert_eq!(discovery.quarantined.len(), 1);
        assert!(matches!(
            discovery.quarantined[0].reason,
            QuarantineReason::PointerWrap
        ));
        assert_eq!(discovery.quarantined[0].raw_words, words);
    }

    #[test]
    fn quarantine_cap_fails_the_discovery() {
        let (mut image, file_off, _msg_off) = layout();
        for i in 0..(MAX_QUARANTINED + 1) {
            let at = 0x200 + i * RECORD_BYTES;
            image.resize(at + RECORD_BYTES, 0);
            let mut words = good_record(file_off, 0);
            words[4] = u32::MAX - 2;
            image[at..at + RECORD_BYTES].copy_from_slice(&record(words));
        }
        let runtime = RuntimeImage::from_plan(&image, BASE, None).unwrap();
        let dir = super::testkit::unique_dir("dbt-cap");
        std::fs::create_dir_all(&dir).unwrap();
        let error = discover(&runtime, &dir).unwrap_err();
        assert!(matches!(error, DbtTraceError::QuarantineCap(_)));
    }

    #[test]
    fn fourth_word_variants_classify() {
        let (mut image, file_off, msg_off) = layout();
        image.resize(0x200 + 3 * RECORD_BYTES, 0);
        for (i, raw) in [7u32, 0xfecdba98, 999].iter().enumerate() {
            let at = 0x200 + i * RECORD_BYTES;
            let mut words = good_record(file_off, msg_off);
            words[3] = *raw;
            image[at..at + RECORD_BYTES].copy_from_slice(&record(words));
        }
        let discovery = discover_tmp(&image);
        assert_eq!(discovery.fourth.parameter_count, 1);
        assert_eq!(discovery.fourth.sentinel, 1);
        assert_eq!(discovery.fourth.unknown, 1);
        assert_eq!(discovery.record_count, 3);
    }

    #[test]
    fn spill_is_framed_ascending_and_matches_discovery() {
        let (mut image, file_off, msg_off) = layout();
        image.resize(0x200 + 3 * RECORD_BYTES, 0);
        for i in 0..3 {
            let at = 0x200 + i * RECORD_BYTES;
            let mut words = good_record(file_off, msg_off);
            words[1] = i as u32 + 1;
            image[at..at + RECORD_BYTES].copy_from_slice(&record(words));
        }
        let discovery = discover_tmp(&image);
        let bytes = std::fs::read(&discovery.spill_path).unwrap();
        assert_eq!(bytes.len(), discovery.record_count * 30);
        for (i, chunk) in bytes.as_chunks::<30>().0.iter().enumerate() {
            let address = u32::from_le_bytes(chunk[0..4].try_into().unwrap());
            let aligned = chunk[4];
            let group = u32::from_le_bytes(chunk[5..9].try_into().unwrap());
            let channel = u32::from_le_bytes(chunk[9..13].try_into().unwrap());
            let fourth_raw = u32::from_le_bytes(chunk[13..17].try_into().unwrap());
            let line = u32::from_le_bytes(chunk[17..21].try_into().unwrap());
            let file_idx = u32::from_le_bytes(chunk[21..25].try_into().unwrap());
            let msg_kind = chunk[25];
            let msg_idx = u32::from_le_bytes(chunk[26..30].try_into().unwrap());
            assert_eq!(address, ptr(0x200 + i * RECORD_BYTES));
            assert_eq!(aligned, 1);
            assert_eq!(group, i as u32 + 1);
            assert_eq!(channel, 2);
            assert_eq!(fourth_raw, 0xfecdba98);
            assert_eq!(line, 214);
            assert_eq!(file_idx, 0);
            assert_eq!(msg_kind, 0);
            assert_eq!(msg_idx, 0);
        }
    }

    #[test]
    fn scatter_backed_records_collect_provenance_and_zero_fill_messages_stay_unresolved() {
        let scatter_base = BASE + 0x1000;
        let zero_base = BASE + 0x2000;
        let mut payload = vec![0u8; 0x9c];
        payload[0x00..0x07].copy_from_slice(b"main.c\0");
        let mut words = good_record(0x1000, 0);
        words[4] = zero_base;
        payload[0x80..0x80 + RECORD_BYTES].copy_from_slice(&record(words));
        let raw = vec![0x55u8; 16];
        let plan = LoadPlan {
            image_base: BASE,
            image_size: raw.len() as u32,
            loader_address: BASE,
            literal_pair_address: BASE + 4,
            table_start: BASE,
            table_end: BASE + 16,
            handlers: HandlerMap {
                null: BASE,
                copy: BASE + 1,
                decompress1: BASE + 4,
                zero: BASE + 9,
            },
            entries: vec![
                PlannedEntry {
                    index: 3,
                    descriptor: Descriptor {
                        source: BASE,
                        destination: scatter_base,
                        size: payload.len() as u32,
                        handler: BASE + 4,
                    },
                    operation: Operation::Decompress1,
                    compressed_size: Some(2),
                    output: PlannedOutput::Bytes(payload),
                },
                PlannedEntry {
                    index: 4,
                    descriptor: Descriptor {
                        source: BASE,
                        destination: zero_base,
                        size: 0x1000,
                        handler: BASE + 9,
                    },
                    operation: Operation::Zero,
                    compressed_size: None,
                    output: PlannedOutput::ZeroFill,
                },
            ],
            logical_output_size: (0x9c + 0x1000) as u64,
        };
        let runtime = RuntimeImage::from_plan(&raw, BASE, Some(&plan)).unwrap();
        let dir = super::testkit::unique_dir("dbt-scatter");
        std::fs::create_dir_all(&dir).unwrap();
        let discovery = discover(&runtime, &dir).unwrap();
        assert_eq!(discovery.record_count, 1);
        assert_eq!(discovery.unresolved_messages, 1);
        assert!(discovery.messages.is_empty());
        assert_eq!(
            discovery
                .scatter_entries_used
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            vec![3]
        );
        let bytes = std::fs::read(&discovery.spill_path).unwrap();
        assert_eq!(u32::from_le_bytes(bytes[21..25].try_into().unwrap()), 0);
        assert_eq!(bytes[25], 2);
        assert_eq!(
            u32::from_le_bytes(bytes[26..30].try_into().unwrap()),
            zero_base
        );
    }
}
