use super::discover::fourth_word_variant;
use super::discover::{Discovery, FourthCounts, QuarantineReason};
use super::wire::JsonWriter;
use super::{DbtTraceError, FORMAT, HEADER, RECORD_BYTES, SCHEMA_VERSION};
use crate::manifest::blake3_fixed;
use crate::runtime_image::{RuntimeImage, StorageSpan};
use atomic_write_file::AtomicWriteFile;
use std::io::{BufReader, Read as _, Write};
use std::path::Path;

const SPILL_FRAME_BYTES: usize = 30;
pub(crate) const THRESHOLD: &str = "byte-backed 28-byte record; source-file pointer resolves to a NUL-terminated string satisfying the shared source-path classifier; source line in 1..=1048575";

/// The identity a reader must pin: the image label, the raw image
/// digest, and the complete scatter dependency.
pub(crate) struct DbtContext<'a> {
    pub label: &'a str,
    pub image_blake3: [u8; 32],
    pub scatter_load_map_blake3: Option<[u8; 32]>,
}

#[derive(Debug, Clone)]
pub(crate) struct CatalogCounts {
    pub(crate) records: usize,
    pub(crate) files: usize,
    pub(crate) messages: usize,
    pub(crate) quarantined: usize,
    pub(crate) unresolved_messages: usize,
    pub(crate) occurrences: usize,
}

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct MaterializedCatalog {
    pub(crate) manifest_blake3: [u8; 32],
    pub(crate) identity: String,
    pub(crate) counts: CatalogCounts,
}

#[derive(Clone)]
pub(crate) struct TableHashes {
    pub(crate) files: String,
    pub(crate) messages: String,
    pub(crate) records: String,
    pub(crate) quarantine: String,
}

/// The typed manifest: the reader re-serializes a parsed manifest through
/// `serialize_manifest` to enforce canonical bytes, so the writer and the
/// reader share one wire definition.
#[derive(Clone)]
pub(crate) struct ManifestWire {
    pub(crate) format: String,
    pub(crate) schema_version: u32,
    pub(crate) tool_version: String,
    pub(crate) label: String,
    pub(crate) image_blake3: [u8; 32],
    pub(crate) scatter_load_map_blake3: Option<[u8; 32]>,
    pub(crate) scatter_entries_used: Vec<usize>,
    pub(crate) base_addr: u32,
    pub(crate) image_size: u32,
    pub(crate) record_bytes: usize,
    pub(crate) header: String,
    pub(crate) occurrences: usize,
    pub(crate) aligned_records: usize,
    pub(crate) unaligned_records: usize,
    pub(crate) threshold: String,
    pub(crate) counts: CatalogCounts,
    pub(crate) fourth: FourthCounts,
    pub(crate) tables: TableHashes,
    pub(crate) identity: Option<String>,
}

#[allow(dead_code)]
pub(crate) fn publish(
    discovery: &Discovery,
    runtime: &RuntimeImage<'_>,
    ctx: &DbtContext<'_>,
    parent: &Path,
    clean_absence: bool,
) -> Result<Option<MaterializedCatalog>, DbtTraceError> {
    if clean_absence && discovery.record_count == 0 && discovery.quarantined.is_empty() {
        clear(parent)?;
        return Ok(None);
    }
    let pid = std::process::id();
    let staging = parent.join(format!("debug_traces.staging+{pid}"));
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(parent)?;
    std::fs::create_dir(&staging)?;
    let outcome = (|| -> Result<MaterializedCatalog, DbtTraceError> {
        let catalog = write_catalog(discovery, runtime, ctx, &staging)?;
        swap_into_place(parent, &staging, pid)?;
        Ok(catalog)
    })();
    if outcome.is_err() {
        let _ = std::fs::remove_dir_all(&staging);
    }
    outcome.map(Some)
}

pub(crate) fn clear(parent: &Path) -> std::io::Result<()> {
    let dir = parent.join("debug_traces");
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }
    Ok(())
}

fn swap_into_place(parent: &Path, staging: &Path, pid: u32) -> Result<(), DbtTraceError> {
    let target = parent.join("debug_traces");
    let old = parent.join(format!("debug_traces.old+{pid}"));
    if target.exists() {
        std::fs::rename(&target, &old)?;
    }
    std::fs::rename(staging, &target)?;
    let _ = std::fs::remove_dir_all(&old);
    Ok(())
}

fn write_catalog(
    discovery: &Discovery,
    runtime: &RuntimeImage<'_>,
    ctx: &DbtContext<'_>,
    staging: &Path,
) -> Result<MaterializedCatalog, DbtTraceError> {
    let file_id = sorted_remap(&discovery.files);
    let message_id = sorted_remap(&discovery.messages);
    write_string_table(
        &staging.join("files.json"),
        "files",
        "path",
        &discovery.files,
    )?;
    write_string_table(
        &staging.join("messages.json"),
        "messages",
        "text",
        &discovery.messages,
    )?;
    write_records(
        &staging.join("records.json"),
        discovery,
        runtime,
        &file_id,
        &message_id,
    )?;
    write_quarantine(&staging.join("quarantine.json"), discovery)?;
    let tables = TableHashes {
        files: crate::manifest::blake3_file(&staging.join("files.json"))?,
        messages: crate::manifest::blake3_file(&staging.join("messages.json"))?,
        records: crate::manifest::blake3_file(&staging.join("records.json"))?,
        quarantine: crate::manifest::blake3_file(&staging.join("quarantine.json"))?,
    };
    let counts = CatalogCounts {
        records: discovery.record_count,
        files: discovery.files.len(),
        messages: discovery.messages.len(),
        quarantined: discovery.quarantined.len(),
        unresolved_messages: discovery.unresolved_messages,
        occurrences: discovery.occurrences,
    };
    let mut wire = manifest_wire(discovery, runtime, ctx, counts, tables);
    let body = serialize_manifest(&wire)?;
    let manifest_blake3 = *blake3::hash(&body).as_bytes();
    let identity = format!(
        "v1:{}:{}:{}:{}",
        blake3_fixed(manifest_blake3),
        wire.counts.records,
        wire.counts.files,
        wire.counts.messages
    );
    wire.identity = Some(identity.clone());
    let manifest = serialize_manifest(&wire)?;
    write_atomic(&staging.join("manifest.json"), &manifest)?;
    Ok(MaterializedCatalog {
        manifest_blake3,
        identity,
        counts: wire.counts,
    })
}

fn manifest_wire(
    discovery: &Discovery,
    runtime: &RuntimeImage<'_>,
    ctx: &DbtContext<'_>,
    counts: CatalogCounts,
    tables: TableHashes,
) -> ManifestWire {
    let (base_addr, image_size) = runtime.image_bounds();
    ManifestWire {
        format: FORMAT.to_string(),
        schema_version: SCHEMA_VERSION,
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        label: ctx.label.to_string(),
        image_blake3: ctx.image_blake3,
        scatter_load_map_blake3: ctx.scatter_load_map_blake3,
        scatter_entries_used: discovery.scatter_entries_used.iter().copied().collect(),
        base_addr,
        image_size,
        record_bytes: RECORD_BYTES,
        header: std::str::from_utf8(HEADER)
            .expect("DBT header is ASCII")
            .to_string(),
        occurrences: counts.occurrences,
        aligned_records: discovery.aligned_records,
        unaligned_records: discovery.unaligned_records,
        threshold: THRESHOLD.to_string(),
        counts,
        fourth: discovery.fourth,
        tables,
        identity: None,
    }
}

fn sorted_remap(table: &[String]) -> Vec<u32> {
    let mut order: Vec<u32> = (0..table.len() as u32).collect();
    order.sort_by_key(|&index| &table[index as usize]);
    let mut remap = vec![0u32; table.len()];
    for (sorted, &inserted) in order.iter().enumerate() {
        remap[inserted as usize] = sorted as u32;
    }
    remap
}

fn write_atomic(path: &Path, contents: &[u8]) -> Result<(), DbtTraceError> {
    let mut file = AtomicWriteFile::open(path)?;
    file.write_all(contents)?;
    file.flush()?;
    file.commit()?;
    Ok(())
}

fn begin_table(
    json: &mut JsonWriter<impl Write>,
    count: usize,
    table_key: &str,
) -> Result<(), DbtTraceError> {
    json.open_object()?;
    json.key(true, "format")?;
    json.string_value(FORMAT)?;
    json.key(false, "schema_version")?;
    json.u64_value(u64::from(SCHEMA_VERSION))?;
    json.key(false, "tool_version")?;
    json.string_value(env!("CARGO_PKG_VERSION"))?;
    json.key(false, "count")?;
    json.u64_value(count as u64)?;
    json.key(false, table_key)?;
    json.open_array()?;
    Ok(())
}

fn write_string_table(
    path: &Path,
    table_key: &str,
    value_key: &str,
    table: &[String],
) -> Result<(), DbtTraceError> {
    let mut order: Vec<&String> = table.iter().collect();
    order.sort();
    let mut json = JsonWriter::new(Vec::new());
    begin_table(&mut json, table.len(), table_key)?;
    for (index, value) in order.iter().enumerate() {
        json.element(index == 0)?;
        json.open_object()?;
        json.key(true, "id")?;
        json.u64_value(index as u64)?;
        json.key(false, value_key)?;
        json.string_value(value)?;
        json.close_object()?;
    }
    end_table(&mut json)?;
    write_atomic(path, &terminated(json))
}

fn write_records(
    path: &Path,
    discovery: &Discovery,
    runtime: &RuntimeImage<'_>,
    file_id: &[u32],
    message_id: &[u32],
) -> Result<(), DbtTraceError> {
    let spill = std::fs::File::open(&discovery.spill_path)?;
    let mut reader = BufReader::new(spill);
    let mut file = AtomicWriteFile::open(path)?;
    {
        let mut json = JsonWriter::new(&mut file);
        begin_table(&mut json, discovery.record_count, "records")?;
        let mut frame = [0u8; SPILL_FRAME_BYTES];
        let mut first = true;
        loop {
            match reader.read_exact(&mut frame) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(error) => return Err(error.into()),
            }
            json.element(first)?;
            first = false;
            write_record(&mut json, &frame, runtime, file_id, message_id)?;
        }
        json.close_array()?;
        json.close_object()?;
    }
    file.write_all(b"\n")?;
    file.flush()?;
    file.commit()?;
    Ok(())
}

fn frame_u32(frame: &[u8; SPILL_FRAME_BYTES], at: usize) -> u32 {
    u32::from_le_bytes(frame[at..at + 4].try_into().expect("four-byte frame slice"))
}

fn write_record(
    json: &mut JsonWriter<impl Write>,
    frame: &[u8; SPILL_FRAME_BYTES],
    runtime: &RuntimeImage<'_>,
    file_id: &[u32],
    message_id: &[u32],
) -> Result<(), DbtTraceError> {
    let address = frame_u32(frame, 0);
    let group = frame_u32(frame, 5);
    let channel = frame_u32(frame, 9);
    let fourth_raw = frame_u32(frame, 13);
    let line = frame_u32(frame, 17);
    let file_idx = frame_u32(frame, 21);
    let message_kind = frame[25];
    let message_ref = frame_u32(frame, 26);
    let file_id = *file_id.get(file_idx as usize).ok_or_else(|| {
        DbtTraceError::Artifact(format!("spill file index {file_idx} out of range"))
    })?;

    json.open_object()?;
    json.key(true, "address")?;
    json.u32_hex_value(address)?;
    json.key(false, "aligned")?;
    json.bool_value(frame[4] == 1)?;
    json.key(false, "group")?;
    json.u64_value(u64::from(group))?;
    json.key(false, "channel")?;
    json.u64_value(u64::from(channel))?;
    json.key(false, "fourth_word")?;
    json.open_object()?;
    json.key(true, "raw")?;
    json.u64_value(u64::from(fourth_raw))?;
    json.key(false, "variant")?;
    json.string_value(fourth_word_variant(fourth_raw).as_str())?;
    json.close_object()?;
    json.key(false, "message")?;
    json.open_object()?;
    match message_kind {
        0 => {
            let text_id = *message_id.get(message_ref as usize).ok_or_else(|| {
                DbtTraceError::Artifact(format!("spill message ref {message_ref} out of range"))
            })?;
            json.key(true, "text_id")?;
            json.u64_value(u64::from(text_id))?;
        }
        storage => {
            json.key(true, "unresolved")?;
            json.open_object()?;
            json.key(true, "pointer")?;
            json.u32_hex_value(message_ref)?;
            json.key(false, "storage")?;
            json.string_value(if storage == 1 {
                "unmapped"
            } else {
                "scatter_zero"
            })?;
            json.close_object()?;
        }
    }
    json.close_object()?;
    json.key(false, "source")?;
    json.open_object()?;
    json.key(true, "file_id")?;
    json.u64_value(u64::from(file_id))?;
    json.key(false, "line")?;
    json.u64_value(u64::from(line))?;
    json.close_object()?;
    json.key(false, "provenance")?;
    let spans = canonical_spans(runtime.storage_spans(address, RECORD_BYTES as u32)?)?;
    json.open_array()?;
    for (index, span) in spans.iter().enumerate() {
        json.element(index == 0)?;
        json.open_object()?;
        json.key(true, "kind")?;
        json.string_value(crate::pal_tasks::artifact::storage_kind_name(span.kind))?;
        json.key(false, "address")?;
        json.u32_hex_value(span.address)?;
        json.key(false, "size")?;
        json.u64_value(u64::from(span.size))?;
        if let Some(entry) = span.scatter_entry {
            json.key(false, "scatter_entry")?;
            json.u64_value(entry as u64)?;
        }
        json.close_object()?;
    }
    json.close_array()?;
    json.close_object()?;
    Ok(())
}

fn canonical_spans(spans: Vec<StorageSpan>) -> Result<Vec<StorageSpan>, DbtTraceError> {
    let mut canonical = spans;
    canonical.sort_by_key(|span| (span.address, span.size));
    canonical.dedup();
    let mut coalesced: Vec<StorageSpan> = Vec::with_capacity(canonical.len());
    for span in canonical {
        match coalesced.last_mut() {
            Some(last)
                if last.kind == span.kind
                    && last.scatter_entry == span.scatter_entry
                    && last.address.checked_add(last.size) == Some(span.address) =>
            {
                last.size = last.size.checked_add(span.size).ok_or_else(|| {
                    DbtTraceError::Artifact("canonical storage span coalescing overflows".into())
                })?;
            }
            _ => coalesced.push(span),
        }
    }
    Ok(coalesced)
}

fn write_quarantine(path: &Path, discovery: &Discovery) -> Result<(), DbtTraceError> {
    let mut json = JsonWriter::new(Vec::new());
    begin_table(&mut json, discovery.quarantined.len(), "quarantine")?;
    for (index, record) in discovery.quarantined.iter().enumerate() {
        json.element(index == 0)?;
        json.open_object()?;
        json.key(true, "address")?;
        json.u32_hex_value(record.address)?;
        json.key(false, "reason")?;
        json.string_value(quarantine_reason_name(record.reason))?;
        json.key(false, "raw_words")?;
        json.open_array()?;
        for (word_index, word) in record.raw_words.iter().enumerate() {
            json.element(word_index == 0)?;
            json.u64_value(u64::from(*word))?;
        }
        json.close_array()?;
        json.close_object()?;
    }
    end_table(&mut json)?;
    write_atomic(path, &terminated(json))
}

fn quarantine_reason_name(reason: QuarantineReason) -> &'static str {
    match reason {
        QuarantineReason::MessageUnterminated => "message_unterminated",
        QuarantineReason::MessageOverCap => "message_over_cap",
        QuarantineReason::MessageInvalidBytes => "message_invalid_bytes",
        QuarantineReason::PointerWrap => "pointer_wrap",
    }
}

fn end_table(json: &mut JsonWriter<impl Write>) -> Result<(), DbtTraceError> {
    json.close_array()?;
    json.close_object()?;
    Ok(())
}

fn terminated(json: JsonWriter<Vec<u8>>) -> Vec<u8> {
    let mut bytes = json.into_inner();
    bytes.push(b'\n');
    bytes
}

pub(crate) fn serialize_manifest(wire: &ManifestWire) -> Result<Vec<u8>, DbtTraceError> {
    let mut json = JsonWriter::new(Vec::new());
    json.open_object()?;
    json.key(true, "format")?;
    json.string_value(&wire.format)?;
    json.key(false, "schema_version")?;
    json.u64_value(u64::from(wire.schema_version))?;
    json.key(false, "tool_version")?;
    json.string_value(&wire.tool_version)?;

    json.key(false, "image")?;
    json.open_object()?;
    json.key(true, "label")?;
    json.string_value(&wire.label)?;
    json.key(false, "base_addr")?;
    json.u32_hex_value(wire.base_addr)?;
    json.key(false, "size")?;
    json.u64_value(u64::from(wire.image_size))?;
    json.key(false, "blake3")?;
    json.hex_value(&wire.image_blake3)?;
    json.close_object()?;

    json.key(false, "runtime_view")?;
    json.open_object()?;
    json.key(true, "scatter_load_map_blake3")?;
    match wire.scatter_load_map_blake3 {
        Some(digest) => json.hex_value(&digest)?,
        None => json.null_value()?,
    }
    json.key(false, "scatter_entries_used")?;
    json.open_array()?;
    for (index, entry) in wire.scatter_entries_used.iter().enumerate() {
        json.element(index == 0)?;
        json.u64_value(*entry as u64)?;
    }
    json.close_array()?;
    json.close_object()?;

    json.key(false, "scan")?;
    json.open_object()?;
    json.key(true, "record_bytes")?;
    json.u64_value(wire.record_bytes as u64)?;
    json.key(false, "header")?;
    json.string_value(&wire.header)?;
    json.key(false, "occurrences")?;
    json.u64_value(wire.occurrences as u64)?;
    json.key(false, "aligned_records")?;
    json.u64_value(wire.aligned_records as u64)?;
    json.key(false, "unaligned_records")?;
    json.u64_value(wire.unaligned_records as u64)?;
    json.key(false, "threshold")?;
    json.string_value(&wire.threshold)?;
    json.close_object()?;

    json.key(false, "counts")?;
    json.open_object()?;
    json.key(true, "records")?;
    json.u64_value(wire.counts.records as u64)?;
    json.key(false, "files")?;
    json.u64_value(wire.counts.files as u64)?;
    json.key(false, "messages")?;
    json.u64_value(wire.counts.messages as u64)?;
    json.key(false, "quarantined")?;
    json.u64_value(wire.counts.quarantined as u64)?;
    json.key(false, "unresolved_messages")?;
    json.u64_value(wire.counts.unresolved_messages as u64)?;
    json.key(false, "fourth_word_variants")?;
    json.open_object()?;
    json.key(true, "parameter_count")?;
    json.u64_value(wire.fourth.parameter_count)?;
    json.key(false, "sentinel_fecdba98")?;
    json.u64_value(wire.fourth.sentinel)?;
    json.key(false, "unknown")?;
    json.u64_value(wire.fourth.unknown)?;
    json.close_object()?;
    json.close_object()?;

    json.key(false, "tables")?;
    json.open_object()?;
    json.key(true, "files_blake3")?;
    json.string_value(&wire.tables.files)?;
    json.key(false, "messages_blake3")?;
    json.string_value(&wire.tables.messages)?;
    json.key(false, "records_blake3")?;
    json.string_value(&wire.tables.records)?;
    json.key(false, "quarantine_blake3")?;
    json.string_value(&wire.tables.quarantine)?;
    json.close_object()?;

    if let Some(identity) = &wire.identity {
        json.key(false, "identity")?;
        json.string_value(identity)?;
    }
    json.close_object()?;
    Ok(terminated(json))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dbt_traces::discover::discover;
    use crate::dbt_traces::discover::testkit::{BASE, good_record, layout, record, unique_dir};
    use crate::runtime_image::RuntimeImage;

    fn published(tmp: &std::path::Path) -> MaterializedCatalog {
        let (mut image, file_off, msg_off) = layout();
        image[0x200..0x21c].copy_from_slice(&record(good_record(file_off, msg_off)));
        let runtime = RuntimeImage::from_plan(&image, BASE, None).unwrap();
        let spill = tmp.join("spill");
        std::fs::create_dir_all(&spill).unwrap();
        let discovery = discover(&runtime, &spill).unwrap();
        let ctx = DbtContext {
            label: "02_MAIN",
            image_blake3: [7u8; 32],
            scatter_load_map_blake3: None,
        };
        publish(&discovery, &runtime, &ctx, tmp, false)
            .unwrap()
            .unwrap()
    }

    #[test]
    fn publish_writes_five_tables_and_manifest_binds_them() {
        let tmp = unique_dir("pub");
        let materialized = published(tmp.path());
        let dir = tmp.path().join("debug_traces");
        for name in [
            "manifest.json",
            "files.json",
            "messages.json",
            "records.json",
            "quarantine.json",
        ] {
            assert!(dir.join(name).is_file(), "missing {name}");
        }
        let manifest = std::fs::read_to_string(dir.join("manifest.json")).unwrap();
        assert!(manifest.starts_with("{\n  \"format\": \"pixel-modem-extractor-debug-traces-v1\""));
        assert!(manifest.contains("\"identity\": \"v1:"));
        assert_eq!(materialized.counts.records, 1);
        let records = std::fs::read_to_string(dir.join("records.json")).unwrap();
        assert!(records.contains("\"address\": \"0x40000200\""));
        for (key, file) in [
            ("files_blake3", "files.json"),
            ("messages_blake3", "messages.json"),
            ("records_blake3", "records.json"),
            ("quarantine_blake3", "quarantine.json"),
        ] {
            let hash = crate::manifest::blake3_file(&dir.join(file)).unwrap();
            assert!(
                manifest.contains(&format!("\"{key}\": \"{hash}\"")),
                "{key} bound"
            );
        }
    }

    #[test]
    fn publish_is_deterministic_and_replaces_stale_output() {
        let tmp = unique_dir("det");
        let first = published(tmp.path());
        let dir = tmp.path().join("debug_traces");
        std::fs::write(dir.join("stray.txt"), b"stale").unwrap();
        let second = published(tmp.path());
        assert_eq!(first.identity, second.identity);
        assert!(
            !dir.join("stray.txt").exists(),
            "stale owned output removed"
        );
        for entry in std::fs::read_dir(tmp.path()).unwrap() {
            let name = entry.unwrap().file_name().into_string().unwrap();
            assert!(
                !name.starts_with("debug_traces.staging"),
                "staging leftover {name}"
            );
        }
    }

    #[test]
    fn clean_absence_removes_owned_directory() {
        let tmp = unique_dir("absent");
        let dir = tmp.path().join("debug_traces");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("manifest.json"), b"stale").unwrap();
        let image = vec![0u8; 0x100];
        let runtime = RuntimeImage::from_plan(&image, BASE, None).unwrap();
        let spill = tmp.path().join("spill2");
        std::fs::create_dir_all(&spill).unwrap();
        let discovery = discover(&runtime, &spill).unwrap();
        let ctx = DbtContext {
            label: "02_MAIN",
            image_blake3: [7u8; 32],
            scatter_load_map_blake3: None,
        };
        assert!(
            publish(&discovery, &runtime, &ctx, tmp.path(), true)
                .unwrap()
                .is_none()
        );
        assert!(!dir.exists());
    }

    fn corrupt_spill_discovery(tmp: &std::path::Path, frame: [u8; 30]) -> Discovery {
        let spill_path = tmp.join("records.spill");
        std::fs::write(&spill_path, frame).unwrap();
        Discovery {
            spill_path,
            record_count: 1,
            files: vec!["main.c".to_string()],
            messages: vec!["hello %d".to_string()],
            ..Discovery::default()
        }
    }

    fn frame_with(file_idx: u32, message_kind: u8, message_ref: u32) -> [u8; 30] {
        let mut frame = [0u8; 30];
        frame[0..4].copy_from_slice(&0x4000_0200u32.to_le_bytes());
        frame[4] = 1;
        frame[21..25].copy_from_slice(&file_idx.to_le_bytes());
        frame[25] = message_kind;
        frame[26..30].copy_from_slice(&message_ref.to_le_bytes());
        frame
    }

    #[test]
    fn write_records_rejects_out_of_range_spill_remaps() {
        let tmp = unique_dir("spill-oob");
        let ctx = DbtContext {
            label: "02_MAIN",
            image_blake3: [7u8; 32],
            scatter_load_map_blake3: None,
        };
        for (frame, needle) in [
            (frame_with(5, 0, 0), "spill file index 5 out of range"),
            (frame_with(0, 0, 9), "spill message ref 9 out of range"),
        ] {
            let discovery = corrupt_spill_discovery(tmp.path(), frame);
            let (image, _, _) = layout();
            let runtime = RuntimeImage::from_plan(&image, BASE, None).unwrap();
            let error = publish(&discovery, &runtime, &ctx, tmp.path(), false).unwrap_err();
            let DbtTraceError::Artifact(message) = &error else {
                panic!("expected Artifact error, got {error:?}");
            };
            assert!(message.contains(needle), "message was {message}");
        }
    }
}
