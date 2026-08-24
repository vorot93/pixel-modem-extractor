use crate::dbt_traces::artifact::{
    CatalogCounts, DbtContext, ManifestWire, THRESHOLD, TableHashes, serialize_manifest,
};
use crate::dbt_traces::discover::{FourthCounts, fourth_word_variant};
use crate::dbt_traces::{
    DbtTraceError, FORMAT, HEADER, MAX_LINE, MAX_QUARANTINED, RECORD_BYTES, SCHEMA_VERSION,
};
use crate::manifest::blake3_fixed;
use crate::runtime_image::RuntimeImage;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
const QUARANTINE_REASONS: [&str; 4] = [
    "message_unterminated",
    "message_over_cap",
    "message_invalid_bytes",
    "pointer_wrap",
];

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct ValidatedCatalog {
    pub(crate) counts: CatalogCounts,
    pub(crate) identity: String,
    pub(crate) manifest_blake3: [u8; 32],
    pub(crate) scatter_entries_used: Vec<usize>,
}

#[allow(dead_code)]
pub(crate) struct RecordWire {
    pub(crate) address: u32,
    pub(crate) file_id: u32,
    pub(crate) line: u32,
}

fn artifact(message: impl Into<String>) -> DbtTraceError {
    DbtTraceError::Artifact(message.into())
}

fn hex_nibble(field: &str, byte: u8) -> Result<u8, DbtTraceError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(artifact(format!(
            "field {field} contains a non-lowercase-hex digit"
        ))),
    }
}

fn hex_word(field: &str, value: &str) -> Result<u32, DbtTraceError> {
    let digits = value
        .strip_prefix("0x")
        .ok_or_else(|| artifact(format!("field {field} lacks the 0x prefix")))?;
    if digits.len() != 8 {
        return Err(artifact(format!(
            "field {field} is not an 8-digit hex word"
        )));
    }
    let mut word = 0u32;
    for byte in digits.bytes() {
        word = (word << 4) | u32::from(hex_nibble(field, byte)?);
    }
    Ok(word)
}

fn hex_digest(field: &str, value: &str) -> Result<[u8; 32], DbtTraceError> {
    if value.len() != 64 {
        return Err(artifact(format!(
            "field {field} is not a 64-digit hex digest"
        )));
    }
    let bytes = value.as_bytes();
    let mut digest = [0u8; 32];
    for (index, slot) in digest.iter_mut().enumerate() {
        let hi = hex_nibble(field, bytes[2 * index])?;
        let lo = hex_nibble(field, bytes[2 * index + 1])?;
        *slot = (hi << 4) | lo;
    }
    Ok(digest)
}

fn counted(field: &str, value: u64) -> Result<usize, DbtTraceError> {
    usize::try_from(value)
        .map_err(|_| artifact(format!("field {field} overflows the host word size")))
}

fn bounded_u32(field: &str, value: u64) -> Result<u32, DbtTraceError> {
    u32::try_from(value).map_err(|_| artifact(format!("field {field} overflows u32")))
}

#[allow(dead_code)]
pub(crate) fn read(
    dir: &Path,
    runtime: &RuntimeImage<'_>,
    expected: &DbtContext<'_>,
) -> Result<ValidatedCatalog, DbtTraceError> {
    let bytes = read_manifest_bounded(&dir.join("manifest.json"))?;
    let wire = parse_manifest(&bytes)?;

    let canonical = serialize_manifest(&wire)?;
    if canonical != bytes {
        return Err(artifact("manifest bytes are not canonical"));
    }

    if wire.format != FORMAT {
        return Err(artifact(format!(
            "manifest format {:?} does not match {:?}",
            wire.format, FORMAT
        )));
    }
    if wire.schema_version != SCHEMA_VERSION {
        return Err(artifact(format!(
            "manifest schema_version {} does not match {SCHEMA_VERSION}",
            wire.schema_version
        )));
    }
    if wire.tool_version != env!("CARGO_PKG_VERSION") {
        return Err(artifact(format!(
            "manifest tool_version {:?} does not match the compiled crate version {:?}",
            wire.tool_version,
            env!("CARGO_PKG_VERSION")
        )));
    }
    if wire.record_bytes != RECORD_BYTES {
        return Err(artifact(format!(
            "manifest scan.record_bytes {} does not match {RECORD_BYTES}",
            wire.record_bytes
        )));
    }
    if wire.header != std::str::from_utf8(HEADER).expect("DBT header is ASCII") {
        return Err(artifact(
            "manifest scan.header does not match the DBT header",
        ));
    }
    if wire.threshold != THRESHOLD {
        return Err(artifact(
            "manifest scan.threshold does not match the compiled threshold",
        ));
    }

    let (base, size) = runtime.image_bounds();
    if wire.base_addr != base || wire.image_size != size {
        return Err(artifact(format!(
            "manifest image block {:#010x}+{:#x} does not match the runtime bounds {base:#010x}+{size:#x}",
            wire.base_addr, wire.image_size
        )));
    }
    let fresh = runtime
        .hash_range(wire.base_addr, wire.image_size)
        .map_err(|error| artifact(format!("runtime image digest unavailable: {error}")))?;
    if fresh != wire.image_blake3 {
        return Err(artifact(
            "manifest image blake3 does not match the runtime image",
        ));
    }
    if wire.image_blake3 != expected.image_blake3 {
        return Err(artifact(
            "manifest image blake3 does not match the expected context",
        ));
    }
    if wire.scatter_load_map_blake3 != expected.scatter_load_map_blake3 {
        return Err(artifact(
            "manifest scatter_load_map_blake3 binding does not match the expected runtime view",
        ));
    }
    if wire.label != expected.label {
        return Err(artifact(format!(
            "manifest image label {:?} does not match the expected context",
            wire.label
        )));
    }

    let identity = wire.identity.clone().unwrap_or_default();
    let mut body_wire = wire.clone();
    body_wire.identity = None;
    let body = serialize_manifest(&body_wire)?;
    let manifest_blake3 = *blake3::hash(&body).as_bytes();
    let recomputed = format!(
        "v1:{}:{}:{}:{}",
        blake3_fixed(manifest_blake3),
        wire.counts.records,
        wire.counts.files,
        wire.counts.messages
    );
    if recomputed != identity {
        return Err(artifact(
            "manifest identity does not match the identity-less manifest body",
        ));
    }

    for (name, file, bound) in [
        ("files_blake3", "files.json", &wire.tables.files),
        ("messages_blake3", "messages.json", &wire.tables.messages),
        ("records_blake3", "records.json", &wire.tables.records),
        (
            "quarantine_blake3",
            "quarantine.json",
            &wire.tables.quarantine,
        ),
    ] {
        let actual = crate::manifest::blake3_file(&dir.join(file))
            .map_err(|error| artifact(format!("table {file} cannot be hashed: {error}")))?;
        if &actual != bound {
            return Err(artifact(format!(
                "table {name} does not match the manifest hash"
            )));
        }
    }

    validate_string_table(&dir.join("files.json"), "files", "path", wire.counts.files)?;
    validate_string_table(
        &dir.join("messages.json"),
        "messages",
        "text",
        wire.counts.messages,
    )?;
    validate_records_table(&dir.join("records.json"), &wire.counts)?;
    validate_quarantine_table(&dir.join("quarantine.json"), wire.counts.quarantined)?;

    Ok(ValidatedCatalog {
        counts: wire.counts,
        identity,
        manifest_blake3,
        scatter_entries_used: wire.scatter_entries_used,
    })
}

fn read_manifest_bounded(path: &Path) -> Result<Vec<u8>, DbtTraceError> {
    let mut file = std::fs::File::open(path)
        .map_err(|error| artifact(format!("manifest open failed: {error}")))?;
    let length = file
        .metadata()
        .map_err(|error| artifact(format!("manifest metadata is unavailable: {error}")))?
        .len();
    if length > MAX_MANIFEST_BYTES as u64 {
        return Err(artifact(
            "manifest exceeds the 4 MiB ceiling and is rejected before parsing",
        ));
    }
    let length =
        usize::try_from(length).map_err(|_| artifact("manifest size does not fit the host"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| artifact("manifest allocation failed"))?;
    bytes.resize(length, 0);
    file.read_exact(&mut bytes)
        .map_err(|error| artifact(format!("manifest read failed: {error}")))?;
    let mut trailing = [0u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|error| artifact(format!("manifest trailing read failed: {error}")))?
        != 0
    {
        return Err(artifact("manifest grew while it was being authenticated"));
    }
    Ok(bytes)
}

#[derive(Deserialize)]
struct ManifestJson {
    format: String,
    schema_version: u64,
    tool_version: String,
    image: ImageJson,
    runtime_view: RuntimeViewJson,
    scan: ScanJson,
    counts: CountsJson,
    tables: TablesJson,
    identity: String,
}

#[derive(Deserialize)]
struct ImageJson {
    label: String,
    base_addr: String,
    size: u64,
    blake3: String,
}

#[derive(Deserialize)]
struct RuntimeViewJson {
    scatter_load_map_blake3: Option<String>,
    scatter_entries_used: Vec<u64>,
}

#[derive(Deserialize)]
struct ScanJson {
    record_bytes: u64,
    header: String,
    occurrences: u64,
    aligned_records: u64,
    unaligned_records: u64,
    threshold: String,
}

#[derive(Deserialize)]
struct CountsJson {
    records: u64,
    files: u64,
    messages: u64,
    quarantined: u64,
    unresolved_messages: u64,
    fourth_word_variants: FourthJson,
}

#[derive(Deserialize)]
struct FourthJson {
    parameter_count: u64,
    sentinel_fecdba98: u64,
    unknown: u64,
}

#[derive(Deserialize)]
struct TablesJson {
    files_blake3: String,
    messages_blake3: String,
    records_blake3: String,
    quarantine_blake3: String,
}

fn parse_manifest(bytes: &[u8]) -> Result<ManifestWire, DbtTraceError> {
    let json: ManifestJson = serde_json::from_slice(bytes)
        .map_err(|error| artifact(format!("manifest field parsing failed: {error}")))?;
    Ok(ManifestWire {
        format: json.format,
        schema_version: bounded_u32("manifest schema_version", json.schema_version)?,
        tool_version: json.tool_version,
        label: json.image.label,
        base_addr: hex_word("manifest image.base_addr", &json.image.base_addr)?,
        image_size: bounded_u32("manifest image.size", json.image.size)?,
        image_blake3: hex_digest("manifest image.blake3", &json.image.blake3)?,
        scatter_load_map_blake3: json
            .runtime_view
            .scatter_load_map_blake3
            .as_deref()
            .map(|value| hex_digest("manifest runtime_view.scatter_load_map_blake3", value))
            .transpose()?,
        scatter_entries_used: json
            .runtime_view
            .scatter_entries_used
            .iter()
            .map(|&entry| counted("manifest runtime_view.scatter_entries_used", entry))
            .collect::<Result<Vec<_>, _>>()?,
        record_bytes: counted("manifest scan.record_bytes", json.scan.record_bytes)?,
        header: json.scan.header,
        occurrences: counted("manifest scan.occurrences", json.scan.occurrences)?,
        aligned_records: counted("manifest scan.aligned_records", json.scan.aligned_records)?,
        unaligned_records: counted(
            "manifest scan.unaligned_records",
            json.scan.unaligned_records,
        )?,
        threshold: json.scan.threshold,
        counts: CatalogCounts {
            records: counted("manifest counts.records", json.counts.records)?,
            files: counted("manifest counts.files", json.counts.files)?,
            messages: counted("manifest counts.messages", json.counts.messages)?,
            quarantined: counted("manifest counts.quarantined", json.counts.quarantined)?,
            unresolved_messages: counted(
                "manifest counts.unresolved_messages",
                json.counts.unresolved_messages,
            )?,
            occurrences: counted("manifest scan.occurrences", json.scan.occurrences)?,
        },
        fourth: FourthCounts {
            parameter_count: json.counts.fourth_word_variants.parameter_count,
            sentinel: json.counts.fourth_word_variants.sentinel_fecdba98,
            unknown: json.counts.fourth_word_variants.unknown,
        },
        tables: TableHashes {
            files: json.tables.files_blake3,
            messages: json.tables.messages_blake3,
            records: json.tables.records_blake3,
            quarantine: json.tables.quarantine_blake3,
        },
        identity: Some(json.identity),
    })
}

#[derive(Deserialize)]
struct RecordJson {
    address: String,
    aligned: bool,
    group: u64,
    channel: u64,
    fourth_word: FourthWordJson,
    message: MessageJson,
    source: SourceJson,
}

#[derive(Deserialize)]
struct FourthWordJson {
    raw: u64,
    variant: String,
}

#[derive(Deserialize)]
struct MessageJson {
    text_id: Option<u64>,
    unresolved: Option<UnresolvedJson>,
}

#[derive(Deserialize)]
struct UnresolvedJson {
    pointer: String,
    storage: String,
}

#[derive(Deserialize)]
struct SourceJson {
    file_id: u64,
    line: u64,
}

struct RecordsScan {
    files: usize,
    messages: usize,
    seen: usize,
    last_address: Option<u32>,
}

fn check_record(scan: &mut RecordsScan, record: RecordJson) -> Result<(), String> {
    let address = hex_word("record address", &record.address).map_err(|error| error.to_string())?;
    if scan.last_address.is_some_and(|last| address <= last) {
        return Err(format!(
            "record address {address:#010x} breaks strictly ascending order"
        ));
    }
    scan.last_address = Some(address);
    if record.aligned != (address % 4 == 0) {
        return Err(format!(
            "record aligned flag does not match the alignment of address {address:#010x}"
        ));
    }
    let raw = u32::try_from(record.fourth_word.raw).map_err(|_| {
        format!(
            "record fourth_word.raw {} overflows u32",
            record.fourth_word.raw
        )
    })?;
    if record.fourth_word.variant != fourth_word_variant(raw).as_str() {
        return Err(format!(
            "record fourth_word.variant {:?} does not classify raw {raw}",
            record.fourth_word.variant
        ));
    }
    match (record.message.text_id, record.message.unresolved) {
        (Some(text_id), None) => {
            if text_id >= scan.messages as u64 {
                return Err(format!(
                    "record message text_id {text_id} exceeds the messages table"
                ));
            }
        }
        (None, Some(unresolved)) => {
            hex_word("record message.unresolved.pointer", &unresolved.pointer)
                .map_err(|error| error.to_string())?;
            if unresolved.storage != "unmapped" && unresolved.storage != "scatter_zero" {
                return Err(format!(
                    "record message.unresolved.storage {:?} is not a known storage kind",
                    unresolved.storage
                ));
            }
        }
        _ => return Err("record message must be exactly one of text_id or unresolved".into()),
    }
    if record.source.file_id >= scan.files as u64 {
        return Err(format!(
            "record source.file_id {} exceeds the files table",
            record.source.file_id
        ));
    }
    let line = u32::try_from(record.source.line)
        .map_err(|_| format!("record source.line {} overflows u32", record.source.line))?;
    if line == 0 || line > MAX_LINE {
        return Err(format!(
            "record source.line {line} is outside 1..={MAX_LINE}"
        ));
    }
    u32::try_from(record.group)
        .map_err(|_| format!("record group {} overflows u32", record.group))?;
    u32::try_from(record.channel)
        .map_err(|_| format!("record channel {} overflows u32", record.channel))?;
    scan.seen += 1;
    Ok(())
}

struct RecordsSeq<'scan> {
    scan: &'scan mut RecordsScan,
}

impl<'de> DeserializeSeed<'de> for RecordsSeq<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<(), D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for RecordsSeq<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a debug-trace records array")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<(), A::Error>
    where
        A: SeqAccess<'de>,
    {
        while let Some(record) = seq.next_element::<RecordJson>()? {
            check_record(self.scan, record).map_err(de::Error::custom)?;
        }
        Ok(())
    }
}

struct RecordsTableVisitor<'scan> {
    scan: &'scan mut RecordsScan,
    expected_records: usize,
}

impl<'de> Visitor<'de> for RecordsTableVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a debug-trace records table")
    }

    fn visit_map<A>(self, mut map: A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut format: Option<String> = None;
        let mut schema_version: Option<u64> = None;
        let mut tool_version: Option<String> = None;
        let mut count: Option<u64> = None;
        let mut saw_records = false;
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "format" => {
                    if format.is_some() {
                        return Err(de::Error::custom(
                            "duplicate records-table field \"format\"",
                        ));
                    }
                    format = Some(map.next_value()?);
                }
                "schema_version" => {
                    if schema_version.is_some() {
                        return Err(de::Error::duplicate_field("schema_version"));
                    }
                    schema_version = Some(map.next_value()?);
                }
                "tool_version" => {
                    if tool_version.is_some() {
                        return Err(de::Error::duplicate_field("tool_version"));
                    }
                    tool_version = Some(map.next_value()?);
                }
                "count" => {
                    if count.is_some() {
                        return Err(de::Error::duplicate_field("count"));
                    }
                    count = Some(map.next_value()?);
                }
                "records" => {
                    saw_records = true;
                    map.next_value_seed(RecordsSeq { scan: self.scan })?;
                }
                other => {
                    return Err(de::Error::custom(format!(
                        "unexpected records-table field {other:?}"
                    )));
                }
            }
        }
        if format.as_deref() != Some(FORMAT) {
            return Err(de::Error::custom("records-table format mismatch"));
        }
        if schema_version != Some(u64::from(SCHEMA_VERSION)) {
            return Err(de::Error::custom("records-table schema_version mismatch"));
        }
        if tool_version.as_deref() != Some(env!("CARGO_PKG_VERSION")) {
            return Err(de::Error::custom("records-table tool_version mismatch"));
        }
        let count = count.ok_or_else(|| de::Error::missing_field("count"))?;
        if count != self.expected_records as u64 {
            return Err(de::Error::custom(format!(
                "records-table envelope count {count} does not match the manifest counts.records {}",
                self.expected_records
            )));
        }
        if self.scan.seen as u64 != count {
            return Err(de::Error::custom(format!(
                "records table streamed {} records but its envelope count is {count}",
                self.scan.seen
            )));
        }
        if !saw_records {
            return Err(de::Error::missing_field("records"));
        }
        Ok(())
    }
}

fn validate_records_table(path: &Path, counts: &CatalogCounts) -> Result<(), DbtTraceError> {
    let file = std::fs::File::open(path)
        .map_err(|error| artifact(format!("records table open failed: {error}")))?;
    let mut deserializer = serde_json::Deserializer::from_reader(BufReader::new(file));
    let mut scan = RecordsScan {
        files: counts.files,
        messages: counts.messages,
        seen: 0,
        last_address: None,
    };
    let parsed = deserializer.deserialize_any(RecordsTableVisitor {
        scan: &mut scan,
        expected_records: counts.records,
    });
    match parsed.and_then(|()| deserializer.end()) {
        Ok(()) => Ok(()),
        Err(error) => Err(artifact(format!("records table rejected: {error}"))),
    }
}

struct StringEntryVisitor<'scan> {
    value_key: &'static str,
    expected_id: u64,
    seen: &'scan mut usize,
}

impl<'de> DeserializeSeed<'de> for StringEntryVisitor<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<(), D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for StringEntryVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a string-table entry")
    }

    fn visit_map<A>(self, mut map: A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut id: Option<u64> = None;
        let mut value: Option<String> = None;
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "id" => {
                    if id.is_some() {
                        return Err(de::Error::duplicate_field("id"));
                    }
                    id = Some(map.next_value()?);
                }
                key if key == self.value_key => {
                    if value.is_some() {
                        return Err(de::Error::custom(format!(
                            "duplicate string-table field {key:?}"
                        )));
                    }
                    value = Some(map.next_value()?);
                }
                other => {
                    return Err(de::Error::custom(format!(
                        "unexpected string-table field {other:?}"
                    )));
                }
            }
        }
        if value.is_none() {
            return Err(de::Error::missing_field(self.value_key));
        }
        let id = id.ok_or_else(|| de::Error::missing_field("id"))?;
        if id != self.expected_id {
            return Err(de::Error::custom(format!(
                "string-table entry id {id} is out of sequence, expected {}",
                self.expected_id
            )));
        }
        *self.seen += 1;
        Ok(())
    }
}

struct StringEntries<'scan> {
    value_key: &'static str,
    seen: &'scan mut usize,
}

impl<'de> DeserializeSeed<'de> for StringEntries<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<(), D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for StringEntries<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a string-table array")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<(), A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut expected_id = 0u64;
        while let Some(()) = seq.next_element_seed(StringEntryVisitor {
            value_key: self.value_key,
            expected_id,
            seen: self.seen,
        })? {
            expected_id += 1;
        }
        Ok(())
    }
}

struct StringTableVisitor<'scan> {
    table_key: &'static str,
    value_key: &'static str,
    expected_count: usize,
    seen: &'scan mut usize,
}

impl<'de> Visitor<'de> for StringTableVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a string table")
    }

    fn visit_map<A>(self, mut map: A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut format: Option<String> = None;
        let mut schema_version: Option<u64> = None;
        let mut tool_version: Option<String> = None;
        let mut count: Option<u64> = None;
        let mut saw_table = false;
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "format" => {
                    if format.is_some() {
                        return Err(de::Error::duplicate_field("format"));
                    }
                    format = Some(map.next_value()?);
                }
                "schema_version" => {
                    if schema_version.is_some() {
                        return Err(de::Error::duplicate_field("schema_version"));
                    }
                    schema_version = Some(map.next_value()?);
                }
                "tool_version" => {
                    if tool_version.is_some() {
                        return Err(de::Error::duplicate_field("tool_version"));
                    }
                    tool_version = Some(map.next_value()?);
                }
                "count" => {
                    if count.is_some() {
                        return Err(de::Error::duplicate_field("count"));
                    }
                    count = Some(map.next_value()?);
                }
                key if key == self.table_key => {
                    saw_table = true;
                    map.next_value_seed(StringEntries {
                        value_key: self.value_key,
                        seen: self.seen,
                    })?;
                }
                other => {
                    return Err(de::Error::custom(format!(
                        "unexpected string-table field {other:?}"
                    )));
                }
            }
        }
        if format.as_deref() != Some(FORMAT) {
            return Err(de::Error::custom("string-table format mismatch"));
        }
        if schema_version != Some(u64::from(SCHEMA_VERSION)) {
            return Err(de::Error::custom("string-table schema_version mismatch"));
        }
        if tool_version.as_deref() != Some(env!("CARGO_PKG_VERSION")) {
            return Err(de::Error::custom("string-table tool_version mismatch"));
        }
        let count = count.ok_or_else(|| de::Error::missing_field("count"))?;
        if count != self.expected_count as u64 {
            return Err(de::Error::custom(format!(
                "string-table envelope count {count} does not match the manifest {}",
                self.expected_count
            )));
        }
        if *self.seen as u64 != count {
            return Err(de::Error::custom(format!(
                "string table streamed {} entries but its envelope count is {count}",
                self.seen
            )));
        }
        if !saw_table {
            return Err(de::Error::missing_field(self.table_key));
        }
        Ok(())
    }
}

fn validate_string_table(
    path: &Path,
    table_key: &'static str,
    value_key: &'static str,
    expected_count: usize,
) -> Result<(), DbtTraceError> {
    let file = std::fs::File::open(path)
        .map_err(|error| artifact(format!("{table_key} table open failed: {error}")))?;
    let mut deserializer = serde_json::Deserializer::from_reader(BufReader::new(file));
    let mut seen = 0usize;
    let parsed = deserializer.deserialize_any(StringTableVisitor {
        table_key,
        value_key,
        expected_count,
        seen: &mut seen,
    });
    match parsed.and_then(|()| deserializer.end()) {
        Ok(()) => Ok(()),
        Err(error) => Err(artifact(format!("{table_key} table rejected: {error}"))),
    }
}

#[derive(Deserialize)]
struct QuarantineJson {
    format: String,
    schema_version: u64,
    tool_version: String,
    count: u64,
    quarantine: Vec<QuarantineEntryJson>,
}

#[derive(Deserialize)]
struct QuarantineEntryJson {
    address: String,
    reason: String,
    raw_words: Vec<u64>,
}

fn validate_quarantine_table(path: &Path, expected_count: usize) -> Result<(), DbtTraceError> {
    let bytes = std::fs::read(path)
        .map_err(|error| artifact(format!("quarantine table read failed: {error}")))?;
    let table: QuarantineJson = serde_json::from_slice(&bytes)
        .map_err(|error| artifact(format!("quarantine table rejected: {error}")))?;
    if table.format != FORMAT {
        return Err(artifact("quarantine-table format mismatch"));
    }
    if table.schema_version != u64::from(SCHEMA_VERSION) {
        return Err(artifact("quarantine-table schema_version mismatch"));
    }
    if table.tool_version != env!("CARGO_PKG_VERSION") {
        return Err(artifact("quarantine-table tool_version mismatch"));
    }
    if table.count != expected_count as u64 {
        return Err(artifact(format!(
            "quarantine-table envelope count {} does not match the manifest counts.quarantined {expected_count}",
            table.count
        )));
    }
    if table.quarantine.len() != expected_count {
        return Err(artifact(format!(
            "quarantine table holds {} entries but the manifest count is {expected_count}",
            table.quarantine.len()
        )));
    }
    if table.quarantine.len() > MAX_QUARANTINED {
        return Err(artifact(format!(
            "quarantine table exceeds the {MAX_QUARANTINED}-entry ceiling"
        )));
    }
    let mut last_address: Option<u32> = None;
    for entry in &table.quarantine {
        let address = hex_word("quarantine address", &entry.address)?;
        if last_address.is_some_and(|last| address <= last) {
            return Err(artifact(format!(
                "quarantine address {address:#010x} does not strictly ascend"
            )));
        }
        last_address = Some(address);
        if !QUARANTINE_REASONS.contains(&entry.reason.as_str()) {
            return Err(artifact(format!(
                "quarantine reason {:?} is not a known reason",
                entry.reason
            )));
        }
        if entry.raw_words.len() != 7 {
            return Err(artifact(format!(
                "quarantine entry at {address:#010x} carries {} raw words, expected 7",
                entry.raw_words.len()
            )));
        }
        for &word in &entry.raw_words {
            u32::try_from(word)
                .map_err(|_| artifact(format!("quarantine raw word {word} overflows u32")))?;
        }
    }
    Ok(())
}

struct RecordStream {
    reader: BufReader<std::fs::File>,
}

impl RecordStream {
    fn peek(&mut self) -> Result<Option<u8>, DbtTraceError> {
        self.reader
            .fill_buf()
            .map(|buffer| buffer.first().copied())
            .map_err(|error| artifact(format!("records stream read failed: {error}")))
    }

    fn bump(&mut self) {
        self.reader.consume(1);
    }

    fn skip_ws(&mut self) -> Result<Option<u8>, DbtTraceError> {
        while let Some(byte) = self.peek()? {
            if !byte.is_ascii_whitespace() {
                return Ok(Some(byte));
            }
            self.bump();
        }
        Ok(None)
    }

    fn expect(&mut self, want: u8, what: &str) -> Result<(), DbtTraceError> {
        match self.skip_ws()? {
            Some(byte) if byte == want => {
                self.bump();
                Ok(())
            }
            Some(byte) => Err(artifact(format!(
                "{what}: expected {want:#04x}, found {byte:#04x}"
            ))),
            None => Err(artifact(format!(
                "{what}: records stream ended unexpectedly"
            ))),
        }
    }

    fn read_string_body(&mut self) -> Result<Vec<u8>, DbtTraceError> {
        self.expect(b'"', "string opening quote")?;
        let mut body = Vec::new();
        loop {
            let Some(byte) = self.peek()? else {
                return Err(artifact("string ended unexpectedly"));
            };
            self.bump();
            match byte {
                b'"' => return Ok(body),
                b'\\' => {
                    if self.peek()?.is_none() {
                        return Err(artifact("string escape ended unexpectedly"));
                    }
                    self.bump();
                    body.push(byte);
                }
                _ => body.push(byte),
            }
        }
    }

    fn skip_scalar(&mut self) -> Result<(), DbtTraceError> {
        while let Some(byte) = self.peek()? {
            if byte.is_ascii_whitespace() || byte == b',' || byte == b'}' || byte == b']' {
                return Ok(());
            }
            self.bump();
        }
        Ok(())
    }

    fn scan_object(&mut self) -> Result<Vec<u8>, DbtTraceError> {
        let mut bytes = Vec::new();
        self.expect(b'{', "record object")?;
        bytes.push(b'{');
        let mut depth = 1usize;
        while depth > 0 {
            let Some(byte) = self.peek()? else {
                return Err(artifact("record object ended unexpectedly"));
            };
            self.bump();
            bytes.push(byte);
            match byte {
                b'"' => {
                    while let Some(inner) = self.peek()? {
                        self.bump();
                        bytes.push(inner);
                        if inner == b'"' {
                            break;
                        }
                        if inner == b'\\' {
                            let Some(escaped) = self.peek()? else {
                                return Err(artifact("record string escape ended unexpectedly"));
                            };
                            self.bump();
                            bytes.push(escaped);
                        }
                    }
                }
                b'{' => depth += 1,
                b'}' => depth -= 1,
                _ => {}
            }
        }
        Ok(bytes)
    }

    fn seek_records_array(&mut self) -> Result<(), DbtTraceError> {
        self.expect(b'{', "records table is not a JSON object")?;
        loop {
            let Some(byte) = self.skip_ws()? else {
                return Err(artifact("records table ended before the records array"));
            };
            if byte == b'}' {
                return Err(artifact("records table has no records array"));
            }
            let key = self.read_string_body()?;
            self.expect(b':', "records table key separator")?;
            let Some(byte) = self.skip_ws()? else {
                return Err(artifact("records table value ended unexpectedly"));
            };
            if key == b"records" {
                if byte != b'[' {
                    return Err(artifact("records value is not an array"));
                }
                self.bump();
                return Ok(());
            }
            match byte {
                b'"' => {
                    self.read_string_body()?;
                }
                b'{' | b'[' => {
                    return Err(artifact(
                        "records table carries a nested container before the records array",
                    ));
                }
                _ => self.skip_scalar()?,
            }
            self.expect(b',', "records table field separator")?;
        }
    }

    fn next_record(&mut self) -> Result<Option<RecordWire>, DbtTraceError> {
        let mut byte = self.skip_ws()?;
        while byte == Some(b',') {
            self.bump();
            byte = self.skip_ws()?;
        }
        match byte {
            None => Err(artifact("records array ended unexpectedly")),
            Some(b']') => {
                self.bump();
                Ok(None)
            }
            Some(b'{') => {
                let bytes = self.scan_object()?;
                let record: RecordJson = serde_json::from_slice(&bytes)
                    .map_err(|error| artifact(format!("record parse failed: {error}")))?;
                Ok(Some(RecordWire {
                    address: hex_word("record address", &record.address)?,
                    file_id: bounded_u32("record source.file_id", record.source.file_id)?,
                    line: bounded_u32("record source.line", record.source.line)?,
                }))
            }
            Some(other) => Err(artifact(format!(
                "records array element does not start an object: byte {other:#04x}"
            ))),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RecordPhase {
    SeekArray,
    InArray,
}

struct RecordIter {
    stream: Option<RecordStream>,
    open_error: Option<DbtTraceError>,
    phase: RecordPhase,
}

impl RecordIter {
    fn advance(&mut self) -> Result<Option<RecordWire>, DbtTraceError> {
        if let Some(error) = self.open_error.take() {
            return Err(error);
        }
        let Some(stream) = self.stream.as_mut() else {
            return Ok(None);
        };
        match self.phase {
            RecordPhase::SeekArray => {
                stream.seek_records_array()?;
                self.phase = RecordPhase::InArray;
                stream.next_record()
            }
            RecordPhase::InArray => stream.next_record(),
        }
    }
}

impl Iterator for RecordIter {
    type Item = Result<RecordWire, DbtTraceError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.advance() {
            Ok(Some(record)) => Some(Ok(record)),
            Ok(None) => {
                self.stream = None;
                None
            }
            Err(error) => {
                self.stream = None;
                Some(Err(error))
            }
        }
    }
}

#[allow(dead_code)]
pub(crate) fn iter_records(dir: &Path) -> impl Iterator<Item = Result<RecordWire, DbtTraceError>> {
    let (stream, open_error) = match std::fs::File::open(dir.join("records.json")) {
        Ok(file) => (
            Some(RecordStream {
                reader: BufReader::new(file),
            }),
            None,
        ),
        Err(error) => (
            None,
            Some(artifact(format!("records table open failed: {error}"))),
        ),
    };
    RecordIter {
        stream,
        open_error,
        phase: RecordPhase::SeekArray,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dbt_traces::artifact::publish;
    use crate::dbt_traces::discover::discover;
    use crate::dbt_traces::discover::testkit::{
        BASE, good_record, layout, record, scatter_fixture, unique_dir,
    };

    fn with_catalog(
        tag: &str,
        records: usize,
        scatter_ctx: Option<[u8; 32]>,
        body: impl FnOnce(
            &Path,
            &RuntimeImage<'_>,
            &DbtContext<'_>,
            &crate::dbt_traces::artifact::MaterializedCatalog,
        ),
    ) {
        let tmp = unique_dir(tag);
        let (mut image, file_off, msg_off) = layout();
        image.resize(0x200 + records * RECORD_BYTES, 0);
        for i in 0..records {
            let at = 0x200 + i * RECORD_BYTES;
            let mut words = good_record(file_off, msg_off);
            words[1] = i as u32 + 1;
            image[at..at + RECORD_BYTES].copy_from_slice(&record(words));
        }
        let runtime = RuntimeImage::from_plan(&image, BASE, None).unwrap();
        let (base, size) = runtime.image_bounds();
        let ctx = DbtContext {
            label: "02_MAIN",
            image_blake3: runtime.hash_range(base, size).unwrap(),
            scatter_load_map_blake3: scatter_ctx,
        };
        let spill = tmp.path().join("spill");
        std::fs::create_dir_all(&spill).unwrap();
        let discovery = discover(&runtime, &spill).unwrap();
        let materialized = publish(&discovery, &runtime, &ctx, tmp.path(), false)
            .unwrap()
            .unwrap();
        body(tmp.path(), &runtime, &ctx, &materialized);
    }

    #[test]
    fn read_validates_a_fresh_catalog() {
        with_catalog("rd-ok", 3, None, |parent, runtime, ctx, materialized| {
            let validated = read(&parent.join("debug_traces"), runtime, ctx).unwrap();
            assert_eq!(validated.identity, materialized.identity);
            assert_eq!(validated.manifest_blake3, materialized.manifest_blake3);
            assert_eq!(validated.counts.records, 3);
            assert_eq!(validated.counts.files, 1);
            assert_eq!(validated.counts.messages, 1);
            assert_eq!(validated.counts.quarantined, 0);
            assert!(validated.scatter_entries_used.is_empty());
        });
        let fixture = scatter_fixture();
        let runtime = RuntimeImage::from_plan(&fixture.raw, BASE, Some(&fixture.plan)).unwrap();
        let tmp = unique_dir("rd-scatter");
        let (base, size) = runtime.image_bounds();
        let ctx = DbtContext {
            label: "02_MAIN",
            image_blake3: runtime.hash_range(base, size).unwrap(),
            scatter_load_map_blake3: None,
        };
        let spill = tmp.path().join("spill");
        std::fs::create_dir_all(&spill).unwrap();
        let discovery = discover(&runtime, &spill).unwrap();
        publish(&discovery, &runtime, &ctx, tmp.path(), false)
            .unwrap()
            .unwrap();
        let validated = read(&tmp.path().join("debug_traces"), &runtime, &ctx).unwrap();
        assert_eq!(validated.scatter_entries_used, vec![3usize]);
    }

    #[test]
    fn read_rejects_table_hash_tampering() {
        with_catalog("rd-tamper", 1, None, |parent, runtime, ctx, _m| {
            let dir = parent.join("debug_traces");
            let mut messages = std::fs::read(dir.join("messages.json")).unwrap();
            messages.push(b'x');
            std::fs::write(dir.join("messages.json"), &messages).unwrap();
            let error = read(&dir, runtime, ctx).unwrap_err();
            let DbtTraceError::Artifact(message) = &error else {
                panic!("expected Artifact error, got {error:?}");
            };
            assert!(message.contains("messages_blake3"), "message was {message}");
        });
    }

    #[test]
    fn read_rejects_wrong_image_binding() {
        with_catalog("rd-image", 1, None, |parent, runtime, _ctx, _m| {
            let ctx = DbtContext {
                label: "02_MAIN",
                image_blake3: [9u8; 32],
                scatter_load_map_blake3: None,
            };
            let error = read(&parent.join("debug_traces"), runtime, &ctx).unwrap_err();
            let DbtTraceError::Artifact(message) = &error else {
                panic!("expected Artifact error, got {error:?}");
            };
            assert!(message.contains("image"), "message was {message}");
        });
    }

    #[test]
    fn read_rejects_stale_scatter_binding() {
        with_catalog("rd-scatter-stale", 1, None, |parent, runtime, _ctx, _m| {
            let (base, size) = runtime.image_bounds();
            let ctx = DbtContext {
                label: "02_MAIN",
                image_blake3: runtime.hash_range(base, size).unwrap(),
                scatter_load_map_blake3: Some([1u8; 32]),
            };
            let error = read(&parent.join("debug_traces"), runtime, &ctx).unwrap_err();
            let DbtTraceError::Artifact(message) = &error else {
                panic!("expected Artifact error, got {error:?}");
            };
            assert!(message.contains("scatter"), "message was {message}");
        });
    }

    fn rewritten_records(
        original: &serde_json::Value,
        transform: impl FnOnce(serde_json::Value) -> serde_json::Value,
    ) -> String {
        let mut text = serde_json::to_string_pretty(&transform(original.clone())).unwrap();
        text.push('\n');
        text
    }

    fn rebind_records_hash(dir: &Path, text: &str, records: usize, files: usize, messages: usize) {
        std::fs::write(dir.join("records.json"), text).unwrap();
        let hash = crate::manifest::blake3_file(&dir.join("records.json")).unwrap();
        let mut manifest = std::fs::read_to_string(dir.join("manifest.json")).unwrap();
        let hash_at =
            manifest.find("\"records_blake3\": \"").unwrap() + "\"records_blake3\": \"".len();
        let hash_end = hash_at + manifest[hash_at..].find('"').unwrap();
        manifest.replace_range(hash_at..hash_end, &hash);
        let identity_at = manifest.find(",\n  \"identity\": \"").unwrap();
        let body = format!("{}\n}}\n", &manifest[..identity_at]);
        let digest = blake3_fixed(*blake3::hash(body.as_bytes()).as_bytes());
        let identity = format!("v1:{digest}:{records}:{files}:{messages}");
        manifest = format!(
            "{},\n  \"identity\": \"{}\"\n}}\n",
            &manifest[..identity_at],
            identity
        );
        std::fs::write(dir.join("manifest.json"), manifest).unwrap();
    }

    #[test]
    fn read_rejects_count_mismatch_and_bad_ordering() {
        with_catalog("rd-order", 3, None, |parent, runtime, ctx, materialized| {
            let dir = parent.join("debug_traces");
            let counts = &materialized.counts;
            let original: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(dir.join("records.json")).unwrap())
                    .unwrap();

            let reversed = rewritten_records(&original, |mut value| {
                value["records"].as_array_mut().unwrap().reverse();
                value
            });
            rebind_records_hash(
                &dir,
                &reversed,
                counts.records,
                counts.files,
                counts.messages,
            );
            let error = read(&dir, runtime, ctx).unwrap_err();
            let DbtTraceError::Artifact(message) = &error else {
                panic!("expected Artifact error, got {error:?}");
            };
            assert!(
                message.contains("ascending") || message.contains("order"),
                "message was {message}"
            );

            let inflated = rewritten_records(&original, |mut value| {
                value["count"] = serde_json::Value::from(4);
                value
            });
            rebind_records_hash(
                &dir,
                &inflated,
                counts.records,
                counts.files,
                counts.messages,
            );
            let error = read(&dir, runtime, ctx).unwrap_err();
            let DbtTraceError::Artifact(message) = &error else {
                panic!("expected Artifact error, got {error:?}");
            };
            assert!(message.contains("count"), "message was {message}");
        });
    }

    #[test]
    fn read_rejects_manifest_growth_and_ceiling() {
        with_catalog("rd-manifest", 1, None, |parent, runtime, ctx, _m| {
            let dir = parent.join("debug_traces");
            let mut grown = std::fs::read(dir.join("manifest.json")).unwrap();
            grown.push(b'\n');
            std::fs::write(dir.join("manifest.json"), &grown).unwrap();
            let error = read(&dir, runtime, ctx).unwrap_err();
            assert!(matches!(error, DbtTraceError::Artifact(_)));

            let text = std::fs::read_to_string(dir.join("manifest.json")).unwrap();
            let padded = format!("{{{}\n{}", " ".repeat(4 * 1024 * 1024), &text[1..]);
            std::fs::write(dir.join("manifest.json"), padded).unwrap();
            let error = read(&dir, runtime, ctx).unwrap_err();
            let DbtTraceError::Artifact(message) = &error else {
                panic!("expected Artifact error, got {error:?}");
            };
            assert!(message.contains("ceiling"), "message was {message}");
        });
    }

    #[test]
    fn iter_records_streams_the_full_set() {
        with_catalog("rd-iter", 3, None, |parent, _runtime, _ctx, _m| {
            let dir = parent.join("debug_traces");
            let records: Vec<RecordWire> = iter_records(&dir).collect::<Result<_, _>>().unwrap();
            assert_eq!(records.len(), 3);
            assert!(
                records
                    .windows(2)
                    .all(|pair| pair[0].address < pair[1].address)
            );
            assert_eq!(records[0].address, BASE + 0x200);
            assert_eq!(records[2].address, BASE + 0x200 + 2 * RECORD_BYTES as u32);
            assert!(records.iter().all(|record| record.file_id == 0));
            assert!(records.iter().all(|record| record.line == 214));
        });
    }
}
