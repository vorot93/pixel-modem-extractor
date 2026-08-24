// DBT-exact source attribution index: a strict reader over the published
// `debug_traces/references.json` that resolves each reference row to its
// record's source path (through records.json and files.json) and keys the
// claims by function identity, for recover_source's dbt_exact pre-pass.
use crate::analysis_tool::AnalysisTool;
use crate::dbt_traces::reader;
use crate::dbt_traces::refs::producer_from_name;
use crate::dbt_traces::{DbtTraceError, MAX_REFERENCES, REFS_FORMAT, SCHEMA_VERSION};
use crate::execution_ranges::{FunctionEvidenceKey, FunctionOwner};
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::collections::{BTreeMap, BTreeSet};
use std::io::BufReader;
use std::path::Path;

/// Function identity -> DBT-exact source path.
///
/// Keys are derived from each reference row's `(producer, function_entry)`.
/// `references.json` deliberately carries no execution digest, so every key
/// uses `execution_blake3: None` and consumers must look functions up by
/// owner + entry alone. Owners are reconstructed exactly as the recovered
/// index reader does from producer alone: Ghidra rows map to
/// `FunctionOwner::Ghidra`, radare2/rizin rows to `FunctionOwner::Legacy`.
/// Run-owned thumb functions (whose owner needs region and run coordinates
/// the artifact does not carry) are therefore never claimable through this
/// index. An identity claiming more than one distinct path is dropped from
/// `by_function` and recorded in `ambiguous`.
#[derive(Debug, Default)]
pub(crate) struct ExactIndex {
    pub(crate) by_function: BTreeMap<FunctionEvidenceKey, String>,
    pub(crate) ambiguous: Vec<(FunctionEvidenceKey, Vec<String>)>,
}

/// Load the exact index for an image dir holding `debug_traces/`. An absent
/// `references.json` (no catalog, or the refs stage did not run) is
/// `Ok(None)`; anything present but invalid is a typed error - the caller
/// fails closed rather than silently dropping dbt evidence.
pub(crate) fn load_exact_index(image_dir: &Path) -> Result<Option<ExactIndex>, DbtTraceError> {
    let catalog_dir = image_dir.join("debug_traces");
    let refs_path = catalog_dir.join("references.json");
    if !refs_path.exists() {
        return Ok(None);
    }
    let binding = reader::manifest_binding(&catalog_dir)?;
    let envelope = read_references(&refs_path, &binding)?;
    let paths = reader::file_paths(&catalog_dir)?;
    let file_of: BTreeMap<u32, u32> = reader::iter_records(&catalog_dir)
        .map(|record| record.map(|record| (record.address, record.file_id)))
        .collect::<Result<_, _>>()?;

    let mut claims: BTreeMap<FunctionEvidenceKey, BTreeSet<String>> = BTreeMap::new();
    for row in envelope.rows {
        let file_id = *file_of.get(&row.record_address).ok_or_else(|| {
            artifact(format!(
                "reference row record address {:#010x} is absent from the catalog records",
                row.record_address
            ))
        })?;
        let Some(path) = paths.get(usize::try_from(file_id).expect("file id fits the host")) else {
            return Err(artifact(format!(
                "record file id {file_id} exceeds the files table"
            )));
        };
        let owner = match row.producer {
            AnalysisTool::Ghidra => FunctionOwner::Ghidra,
            producer => FunctionOwner::Legacy { producer },
        };
        claims
            .entry(FunctionEvidenceKey {
                owner,
                entry: u64::from(row.function_entry),
                execution_blake3: None,
            })
            .or_default()
            .insert(path.clone());
    }

    let mut index = ExactIndex::default();
    for (key, paths) in claims {
        if paths.len() == 1 {
            index
                .by_function
                .insert(key, paths.into_iter().next().expect("one path"));
        } else {
            index.ambiguous.push((key, paths.into_iter().collect()));
        }
    }
    Ok(Some(index))
}

fn artifact(message: impl Into<String>) -> DbtTraceError {
    DbtTraceError::Artifact(message.into())
}

/// The fields the exact index retains from one reference row.
struct ExactRow {
    record_address: u32,
    producer: AnalysisTool,
    function_entry: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RefsImageJson {
    blake3: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RefsCatalogJson {
    manifest_blake3: String,
    identity: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RefsInputsJson {
    /// Parsed for shape only; the exact index does not re-derive them.
    #[allow(dead_code)]
    functions_blake3: String,
    #[allow(dead_code)]
    thumb_functions_blake3: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RefRowJson {
    record_address: String,
    pc: String,
    isa: String,
    function_entry: String,
    /// Parsed for shape only; the exact index keys on entry + producer.
    #[allow(dead_code)]
    function_name: String,
    producer: String,
    evidence_kind: String,
}

const REFERENCE_ISAS: [&str; 2] = ["arm", "thumb"];
const REFERENCE_EVIDENCE_KINDS: [&str; 3] = ["movw_movt", "literal_load", "pc_relative"];

/// The declared count is checked against the ceiling the moment it is seen
/// (before any row streams), and streaming itself is bounded so a lying
/// count cannot materialize unbounded rows.
fn references_over_ceiling() -> String {
    format!("references artifact exceeds the {MAX_REFERENCES}-row ceiling")
}

fn exact_row(row: RefRowJson) -> Result<ExactRow, DbtTraceError> {
    let record_address = reader::hex_word("reference record_address", &row.record_address)?;
    let function_entry = reader::hex_word("reference function_entry", &row.function_entry)?;
    reader::hex_word("reference pc", &row.pc)?;
    if !REFERENCE_ISAS.contains(&row.isa.as_str()) {
        return Err(artifact(format!(
            "reference isa {:?} is not a known decode isa",
            row.isa
        )));
    }
    if !REFERENCE_EVIDENCE_KINDS.contains(&row.evidence_kind.as_str()) {
        return Err(artifact(format!(
            "reference evidence_kind {:?} is not a known evidence kind",
            row.evidence_kind
        )));
    }
    let producer = producer_from_name(&row.producer).ok_or_else(|| {
        artifact(format!(
            "reference producer {:?} is not a known producer",
            row.producer
        ))
    })?;
    Ok(ExactRow {
        record_address,
        producer,
        function_entry,
    })
}

#[derive(Default)]
struct RefsEnvelope {
    format: Option<String>,
    schema_version: Option<u64>,
    tool_version: Option<String>,
    image_blake3: Option<String>,
    manifest_blake3: Option<String>,
    identity: Option<String>,
    count: Option<u64>,
    saw_references: bool,
    rows: Vec<ExactRow>,
}

struct RefsRows<'envelope> {
    envelope: &'envelope mut RefsEnvelope,
}

impl<'de> DeserializeSeed<'de> for RefsRows<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for RefsRows<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a references array")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<(), A::Error>
    where
        A: SeqAccess<'de>,
    {
        while let Some(row) = seq.next_element::<RefRowJson>()? {
            let row = exact_row(row).map_err(serde::de::Error::custom)?;
            self.envelope.rows.push(row);
            if self.envelope.rows.len() > MAX_REFERENCES {
                return Err(serde::de::Error::custom(references_over_ceiling()));
            }
        }
        Ok(())
    }
}

struct RefsVisitor {
    envelope: RefsEnvelope,
}

impl<'de> Visitor<'de> for RefsVisitor {
    type Value = RefsEnvelope;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a debug-trace references artifact")
    }

    fn visit_map<A>(self, mut map: A) -> Result<RefsEnvelope, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut envelope = self.envelope;
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "format" => {
                    set_once(&mut envelope.format, "format", map.next_value()?)?;
                }
                "schema_version" => {
                    set_once(
                        &mut envelope.schema_version,
                        "schema_version",
                        map.next_value()?,
                    )?;
                }
                "tool_version" => {
                    set_once(
                        &mut envelope.tool_version,
                        "tool_version",
                        map.next_value()?,
                    )?;
                }
                "count" => {
                    let count: u64 = map.next_value()?;
                    if count > MAX_REFERENCES as u64 {
                        return Err(serde::de::Error::custom(references_over_ceiling()));
                    }
                    set_once(&mut envelope.count, "count", count)?;
                }
                "image" => {
                    set_once(
                        &mut envelope.image_blake3,
                        "image",
                        map.next_value::<RefsImageJson>()?.blake3,
                    )?;
                }
                "catalog" => {
                    let catalog: RefsCatalogJson = map.next_value()?;
                    set_once(
                        &mut envelope.manifest_blake3,
                        "catalog",
                        catalog.manifest_blake3,
                    )?;
                    set_once(&mut envelope.identity, "identity", catalog.identity)?;
                }
                "inputs" => {
                    let _inputs: RefsInputsJson = map.next_value()?;
                }
                "references" => {
                    if envelope.saw_references {
                        return Err(serde::de::Error::duplicate_field("references"));
                    }
                    envelope.saw_references = true;
                    map.next_value_seed(RefsRows {
                        envelope: &mut envelope,
                    })?;
                }
                other => {
                    return Err(serde::de::Error::custom(format!(
                        "unexpected references-artifact field {other:?}"
                    )));
                }
            }
        }
        Ok(envelope)
    }
}

fn set_once<T, E>(slot: &mut Option<T>, field: &'static str, value: T) -> Result<(), E>
where
    E: serde::de::Error,
{
    if slot.replace(value).is_some() {
        return Err(serde::de::Error::custom(format!(
            "duplicate references-artifact field {field:?}"
        )));
    }
    Ok(())
}

fn read_references(
    path: &Path,
    binding: &reader::ManifestBinding,
) -> Result<RefsEnvelope, DbtTraceError> {
    let file = std::fs::File::open(path)
        .map_err(|error| artifact(format!("references artifact open failed: {error}")))?;
    let mut deserializer = serde_json::Deserializer::from_reader(BufReader::new(file));
    let parsed = deserializer.deserialize_any(RefsVisitor {
        envelope: RefsEnvelope::default(),
    });
    let envelope = parsed
        .and_then(|envelope| deserializer.end().map(|()| envelope))
        .map_err(|error| artifact(format!("references artifact rejected: {error}")))?;

    if envelope.format.as_deref() != Some(REFS_FORMAT) {
        return Err(artifact(format!(
            "references artifact format {:?} does not match {REFS_FORMAT:?}",
            envelope.format
        )));
    }
    if envelope.schema_version != Some(u64::from(SCHEMA_VERSION)) {
        return Err(artifact(
            "references artifact schema_version does not match {SCHEMA_VERSION}",
        ));
    }
    if envelope.tool_version.as_deref() != Some(env!("CARGO_PKG_VERSION")) {
        return Err(artifact(
            "references artifact tool_version does not match the compiled crate version",
        ));
    }
    let count = envelope
        .count
        .ok_or_else(|| artifact("references artifact lacks the count field"))?;
    if count != envelope.rows.len() as u64 {
        return Err(artifact(format!(
            "references artifact streamed {} rows but its envelope count is {count}",
            envelope.rows.len()
        )));
    }
    if !envelope.saw_references {
        return Err(artifact("references artifact lacks the references array"));
    }
    let image_blake3 = envelope
        .image_blake3
        .as_deref()
        .map(|value| reader::hex_digest("references image.blake3", value))
        .transpose()?
        .ok_or_else(|| artifact("references artifact lacks the image block"))?;
    if image_blake3 != binding.image_blake3 {
        return Err(artifact(
            "references image blake3 does not match the catalog manifest",
        ));
    }
    let manifest_blake3 = envelope
        .manifest_blake3
        .as_deref()
        .map(|value| reader::hex_digest("references catalog.manifest_blake3", value))
        .transpose()?
        .ok_or_else(|| artifact("references artifact lacks the catalog block"))?;
    if manifest_blake3 != binding.manifest_blake3 {
        return Err(artifact(
            "references catalog manifest blake3 does not match the catalog manifest",
        ));
    }
    if envelope.identity.as_deref() != Some(binding.identity.as_str()) {
        return Err(artifact(
            "references catalog identity does not match the catalog manifest",
        ));
    }
    Ok(envelope)
}
#[cfg(test)]
mod tests {
    use super::load_exact_index;
    use crate::dbt_traces::artifact::{self, DbtContext};
    use crate::dbt_traces::discover::{self, testkit};
    use crate::dbt_traces::reader;
    use crate::dbt_traces::refs::{self, RefFunction, RefsInputs};
    use crate::execution_ranges::{
        AuthenticatedDecodeRange, DecodeIsa, ExecutionIdentity, FunctionEvidenceKey, FunctionOwner,
    };
    use crate::runtime_image::RuntimeImage;

    // T32 `adr r0, pc+8` from the refs fixtures: at pc BASE+0x1f4 and
    // BASE+0x2f4 it materializes BASE+0x200 and BASE+0x300 respectively.
    const ADR_PLUS_8: [u8; 2] = [0x02, 0xa0];

    /// Two files, two records: record at +0x200 cites "main.c", record at
    /// +0x300 cites "other.c". `single_fn` walks the +0x1f4 ADR; `amb_fn`
    /// walks the +0x1f6 and +0x2f4 ADRs (rows dedup on
    /// pc+record+producer+evidence, so each claim needs its own pc).
    fn two_file_image() -> Vec<u8> {
        let mut image = vec![0u8; 0x400];
        image[0x100..0x107].copy_from_slice(b"main.c\0");
        image[0x140..0x149].copy_from_slice(b"hello %d\0");
        image[0x180..0x188].copy_from_slice(b"other.c\0");
        image[0x1f4..0x1f6].copy_from_slice(&ADR_PLUS_8);
        image[0x1f6..0x1f8].copy_from_slice(&ADR_PLUS_8);
        image[0x2f4..0x2f6].copy_from_slice(&ADR_PLUS_8);
        image[0x200..0x21c].copy_from_slice(&testkit::record(testkit::good_record(0x100, 0x140)));
        image[0x300..0x31c].copy_from_slice(&testkit::record(testkit::good_record(0x180, 0x140)));
        image
    }

    fn thumb_range(runtime: &RuntimeImage<'_>, start: u32, end: u32) -> AuthenticatedDecodeRange {
        AuthenticatedDecodeRange {
            isa: DecodeIsa::Thumb,
            start,
            end,
            blake3: runtime.hash_range(start, end - start).unwrap(),
        }
    }

    fn ref_function(name: &str, entry: u32, ranges: Vec<AuthenticatedDecodeRange>) -> RefFunction {
        RefFunction {
            owner: FunctionOwner::Ghidra,
            identity: ExecutionIdentity {
                entry,
                decode_ranges: ranges,
                execution_blake3: [0u8; 32],
            },
            name: name.to_string(),
        }
    }

    /// Publish a real catalog, optionally write a references artifact bound
    /// to it, and return the image dir holding `debug_traces/`.
    fn fixture(tag: &str, write_refs: bool) -> testkit::TestDir {
        let image = two_file_image();
        let runtime = RuntimeImage::from_plan(&image, testkit::BASE, None).unwrap();
        let tmp = testkit::unique_dir(tag);
        let (base, size) = runtime.image_bounds();
        let ctx = DbtContext {
            label: "02_MAIN",
            image_blake3: runtime.hash_range(base, size).unwrap(),
            scatter_load_map_blake3: None,
        };
        let spill = tmp.path().join("spill");
        std::fs::create_dir_all(&spill).unwrap();
        let discovery = discover::discover(&runtime, &spill).unwrap();
        artifact::publish(&discovery, &runtime, &ctx, tmp.path(), false)
            .unwrap()
            .unwrap();
        if write_refs {
            let catalog_dir = tmp.path().join("debug_traces");
            let catalog = reader::read(&catalog_dir, &runtime, &ctx).unwrap();
            let functions = vec![
                ref_function(
                    "single_fn",
                    testkit::BASE + 0x1f4,
                    vec![thumb_range(
                        &runtime,
                        testkit::BASE + 0x1f4,
                        testkit::BASE + 0x1f6,
                    )],
                ),
                ref_function(
                    "amb_fn",
                    testkit::BASE + 0x1f6,
                    vec![
                        thumb_range(&runtime, testkit::BASE + 0x1f6, testkit::BASE + 0x1f8),
                        thumb_range(&runtime, testkit::BASE + 0x2f4, testkit::BASE + 0x2f6),
                    ],
                ),
            ];
            refs::attribute(
                &runtime,
                &[testkit::BASE + 0x200, testkit::BASE + 0x300],
                &functions,
                &catalog,
                RefsInputs {
                    functions_blake3: "0f".repeat(32),
                    thumb_functions_blake3: None,
                },
                &catalog_dir.join("references.json"),
            )
            .unwrap();
        }
        tmp
    }

    fn key(entry: u32) -> FunctionEvidenceKey {
        FunctionEvidenceKey {
            owner: FunctionOwner::Ghidra,
            entry: u64::from(entry),
            execution_blake3: None,
        }
    }

    #[test]
    fn load_exact_index_is_none_when_references_are_absent() {
        let empty = testkit::unique_dir("exact-empty");
        assert!(load_exact_index(empty.path()).unwrap().is_none());

        let tmp = fixture("exact-no-refs", false);
        assert!(load_exact_index(tmp.path()).unwrap().is_none());
    }

    #[test]
    fn load_exact_index_maps_records_and_records_ambiguity() {
        let tmp = fixture("exact-map", true);
        let index = load_exact_index(tmp.path()).unwrap().unwrap();

        let single = key(testkit::BASE + 0x1f4);
        let amb = key(testkit::BASE + 0x1f6);
        assert_eq!(
            index.by_function.get(&single).map(String::as_str),
            Some("main.c")
        );
        assert!(!index.by_function.contains_key(&amb));
        assert_eq!(
            index.ambiguous,
            vec![(amb, vec!["main.c".to_string(), "other.c".to_string()])]
        );
        assert_eq!(index.by_function.len(), 1);
    }

    #[test]
    fn load_exact_index_rejects_a_tampered_envelope() {
        let tmp = fixture("exact-tamper", true);
        let refs_path = tmp.path().join("debug_traces/references.json");
        let original: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&refs_path).unwrap()).unwrap();

        let mut tampered = original.clone();
        tampered["image"]["blake3"] = serde_json::json!("0".repeat(64));
        std::fs::write(&refs_path, serde_json::to_string_pretty(&tampered).unwrap()).unwrap();
        let error = load_exact_index(tmp.path()).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("image"), "message was {message}");

        let mut tampered = original.clone();
        tampered["count"] = serde_json::json!(99);
        std::fs::write(&refs_path, serde_json::to_string_pretty(&tampered).unwrap()).unwrap();
        let error = load_exact_index(tmp.path()).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("count"), "message was {message}");
    }

    #[test]
    fn load_exact_index_rejects_an_over_ceiling_count_before_streaming() {
        let tmp = fixture("exact-ceiling", true);
        let refs_path = tmp.path().join("debug_traces/references.json");
        let original: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&refs_path).unwrap()).unwrap();

        // An envelope count above the ceiling must fail on the ceiling itself
        // (checked against the declared count before any row streams), not on
        // the streamed-rows mismatch that would only fire after materializing.
        let mut tampered = original.clone();
        tampered["count"] = serde_json::json!(crate::dbt_traces::MAX_REFERENCES + 1);
        std::fs::write(&refs_path, serde_json::to_string_pretty(&tampered).unwrap()).unwrap();
        let error = load_exact_index(tmp.path()).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("ceiling"), "message was {message}");
    }
}
