// Input validation, source hashes, v4 schema, and atomic sidecar commit.

use super::{
    FunctionContext, FunctionExecution, RecoveredGlobal, RunRequest, SourceProjectionCounts,
};
use crate::error::{Error, Result};
use crate::execution_ranges::{
    ExecutionIdentity, ExecutionProjection, execution_identity, parse_projection,
    validate_inventory_projection,
};
use crate::manifest::{blake3_bytes, load_addr_for_image};
use atomic_write_file::AtomicWriteFile;
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::Path;

const GLOBALS_FORMAT: &str = "pixel-modem-extractor-globals-v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InputHashes {
    pub image_blake3: String,
    pub globals_blake3: String,
    pub functions_blake3: String,
    pub thumb_functions_blake3: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LoadedInputs {
    pub image: Vec<u8>,
    pub load_address: u32,
    pub hashes: InputHashes,
    pub globals: Vec<RecoveredGlobal>,
    pub functions: Vec<FunctionExecution>,
    pub source_counts: SourceProjectionCounts,
}

struct ParsedInventory {
    accepted: usize,
    quarantined: usize,
    quarantine_errors: usize,
    substantial: usize,
    identities: BTreeMap<ExecutionIdentity, BTreeSet<FunctionContext>>,
}

impl ParsedInventory {
    fn empty() -> Self {
        Self {
            accepted: 0,
            quarantined: 0,
            quarantine_errors: 0,
            substantial: 0,
            identities: BTreeMap::new(),
        }
    }
}

pub(crate) fn load_inputs(request: &RunRequest<'_>) -> Result<LoadedInputs> {
    let thumb_expected = thumb_expectations(request)?;
    let load_address = resolve_load_address(request)?;

    let image_path = request
        .image_dir
        .join(format!("{}.bin", request.image_label));
    let decompiled = request.image_dir.join("decompiled");
    let globals_path = decompiled.join("globals.json");
    let functions_path = decompiled.join("functions.json");
    let thumb_path = decompiled.join("thumb_functions.json");

    let image = std::fs::read(&image_path)?;
    let image_blake3 = blake3_bytes(&image);
    let image_len = mapped_image_len(load_address, image.len())?;

    let (globals_blake3, globals_json) = read_json(&globals_path)?;
    let globals = parse_globals(&globals_json, request)?;
    drop(globals_json);

    let (functions_blake3, functions_json) = read_json(&functions_path)?;
    let ghidra = parse_ghidra_inventory(&functions_json, request, load_address, image_len)?;
    drop(functions_json);

    let (thumb_functions_blake3, thumb) = match thumb_expected {
        None => {
            if thumb_path.exists() {
                return Err(invalid("unexpected thumb_functions.json"));
            }
            (None, ParsedInventory::empty())
        }
        Some((substantial, accepted, quarantined)) => {
            let artifact = crate::thumb_analysis::read_thumb_artifact(
                &thumb_path,
                Some(crate::thumb_analysis::MappedImage::new(
                    load_address,
                    image_len,
                )?),
            )?;
            let hash = artifact.source_blake3().to_owned();
            let parsed =
                parse_thumb_inventory(artifact.function_values(), load_address, image_len)?;
            if artifact
                .validated_v3_run_totals()
                .is_some_and(|run_totals| {
                    (parsed.substantial, parsed.accepted, parsed.quarantined) != run_totals
                })
            {
                return Err(invalid(
                    "thumb projection counts do not match validated v3 run totals",
                ));
            }
            if parsed.substantial != substantial
                || parsed.accepted != accepted
                || parsed.quarantined != quarantined
            {
                return Err(invalid(
                    "thumb producer counts do not match the current-run request",
                ));
            }
            (Some(hash), parsed)
        }
    };

    let mut identities = ghidra.identities;
    for (identity, contexts) in thumb.identities {
        identities.entry(identity).or_default().extend(contexts);
    }

    Ok(LoadedInputs {
        image,
        load_address,
        hashes: InputHashes {
            image_blake3,
            globals_blake3,
            functions_blake3,
            thumb_functions_blake3,
        },
        globals,
        functions: identities
            .into_iter()
            .map(|(identity, contexts)| FunctionExecution { identity, contexts })
            .collect(),
        source_counts: SourceProjectionCounts {
            ghidra_accepted: ghidra.accepted,
            ghidra_quarantined: ghidra.quarantined,
            thumb_accepted: thumb.accepted,
            thumb_quarantined: thumb.quarantined,
            quarantine_errors: ghidra
                .quarantine_errors
                .checked_add(thumb.quarantine_errors)
                .ok_or_else(|| invalid("quarantine error count overflow"))?,
        },
    })
}

fn thumb_expectations(request: &RunRequest<'_>) -> Result<Option<(usize, usize, usize)>> {
    match (
        request.expected_thumb_substantial,
        request.expected_thumb_accepted,
        request.expected_thumb_quarantined,
    ) {
        (None, None, None) => Ok(None),
        (Some(substantial), Some(accepted), Some(quarantined)) => {
            Ok(Some((substantial, accepted, quarantined)))
        }
        _ => Err(invalid(
            "thumb expectations must be all present or all absent",
        )),
    }
}

fn resolve_load_address(request: &RunRequest<'_>) -> Result<u32> {
    let load_addr = load_addr_for_image(request.manifest_path, request.image_label)?
        .ok_or_else(|| invalid(&format!("load_addr missing for {}", request.image_label)))?;
    u32::try_from(load_addr).map_err(|_| invalid("manifest load address does not fit u32"))
}

fn mapped_image_len(load_address: u32, image_len: usize) -> Result<u32> {
    let len = u32::try_from(image_len).map_err(|_| invalid("image length does not fit u32"))?;
    load_address
        .checked_add(len)
        .ok_or_else(|| invalid("mapped image end does not fit u32"))?;
    Ok(len)
}

fn read_json(path: &Path) -> Result<(String, Value)> {
    let bytes = std::fs::read(path)?;
    let hash = blake3_bytes(&bytes);
    let value = serde_json::from_slice(&bytes).map_err(|e| Error::Serialize(e.to_string()))?;
    Ok((hash, value))
}

fn parse_globals(value: &Value, request: &RunRequest<'_>) -> Result<Vec<RecoveredGlobal>> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("globals.json must be an object"))?;
    if object.get("format").and_then(Value::as_str) != Some(GLOBALS_FORMAT) {
        return Err(invalid("unsupported globals format"));
    }
    if object.get("image").and_then(Value::as_str) != Some(request.image_label) {
        return Err(invalid("globals image label mismatch"));
    }
    let raw = object
        .get("globals")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("globals must be an array"))?;

    let mut recovered = Vec::new();
    let mut recovered_count = 0usize;
    let mut seen = BTreeSet::new();
    for (source_index, global) in raw.iter().enumerate() {
        let record = global
            .as_object()
            .ok_or_else(|| invalid("global record must be an object"))?;
        require_fields(
            record,
            &[
                "address",
                "arch",
                "name",
                "tier",
                "size",
                "evidence",
                "annotations",
            ],
        )?;
        let address = parse_global_address(required_string(record, "address")?)?;
        let name = required_string(record, "name")?.to_owned();
        let arch = required_string(record, "arch")?;
        if !matches!(arch, "arm" | "thumb" | "mixed") {
            return Err(invalid("global arch must be arm, thumb, or mixed"));
        }
        let tier = required_string(record, "tier")?;
        if !matches!(tier, "recovered" | "provisional") {
            return Err(invalid("global tier must be recovered or provisional"));
        }
        if !record.get("size").is_some_and(Value::is_null) {
            return Err(invalid("global size must be null"));
        }
        if !record.get("evidence").is_some_and(Value::is_array) {
            return Err(invalid("global evidence must be an array"));
        }
        if !record.get("annotations").is_some_and(Value::is_array) {
            return Err(invalid("global annotations must be an array"));
        }
        if tier == "recovered" {
            recovered_count = recovered_count
                .checked_add(1)
                .ok_or_else(|| invalid("recovered global count overflow"))?;
            if !seen.insert(address) {
                return Err(invalid(
                    "duplicate recovered global address after normalization",
                ));
            }
            recovered.push(RecoveredGlobal {
                source_index,
                address,
                name,
                arch: arch.to_owned(),
            });
        }
    }
    if recovered_count != request.expected_recovered_globals {
        return Err(invalid(
            "recovered global count does not match the current-run request",
        ));
    }
    Ok(recovered)
}

fn parse_ghidra_inventory(
    value: &Value,
    request: &RunRequest<'_>,
    image_start: u32,
    image_len: u32,
) -> Result<ParsedInventory> {
    let records = value
        .as_array()
        .ok_or_else(|| invalid("functions.json must be an array"))?;
    if records.len() != request.expected_ghidra_records {
        return Err(invalid(
            "raw ghidra count does not match the current-run request",
        ));
    }
    let parsed = parse_inventory_records(records, true, image_start, image_len)?;
    if parsed.accepted != request.expected_ghidra_accepted
        || parsed.quarantined != request.expected_ghidra_quarantined
    {
        return Err(invalid(
            "ghidra producer counts do not match the current-run request",
        ));
    }
    Ok(parsed)
}

fn parse_thumb_inventory(
    records: &[Value],
    image_start: u32,
    image_len: u32,
) -> Result<ParsedInventory> {
    parse_inventory_records(records, false, image_start, image_len)
}

fn parse_inventory_records(
    records: &[Value],
    require_end: bool,
    image_start: u32,
    image_len: u32,
) -> Result<ParsedInventory> {
    let mut parsed = ParsedInventory::empty();
    for record in records {
        let object = record
            .as_object()
            .ok_or_else(|| invalid("inventory record must be an object"))?;
        let name = required_string(object, "name")?.to_owned();
        let entry = parse_canonical_hex(required_string(object, "entry")?)?;
        if require_end {
            let _end = parse_canonical_hex(required_string(object, "end")?)?;
        }
        let size = parse_positive_size(object.get("size").ok_or_else(|| invalid("missing size"))?)?;
        if size >= 32 {
            parsed.substantial = parsed
                .substantial
                .checked_add(1)
                .ok_or_else(|| invalid("thumb substantial count overflow"))?;
        }
        let projection = parse_projection(record)?;
        validate_inventory_projection(entry, &projection, image_start, image_len)?;
        match execution_identity(entry, &projection)? {
            Some(identity) => {
                parsed.accepted = parsed
                    .accepted
                    .checked_add(1)
                    .ok_or_else(|| invalid("accepted inventory count overflow"))?;
                parsed
                    .identities
                    .entry(identity)
                    .or_default()
                    .insert(FunctionContext { entry, name });
            }
            None => {
                parsed.quarantined = parsed
                    .quarantined
                    .checked_add(1)
                    .ok_or_else(|| invalid("quarantined inventory count overflow"))?;
                let ExecutionProjection::Quarantined(errors) = &projection else {
                    return Err(invalid("quarantined record missing error list"));
                };
                parsed.quarantine_errors = parsed
                    .quarantine_errors
                    .checked_add(errors.len())
                    .ok_or_else(|| invalid("quarantine error count overflow"))?;
            }
        }
    }
    let raw_count = records.len();
    if parsed
        .accepted
        .checked_add(parsed.quarantined)
        .is_none_or(|total| total != raw_count)
    {
        return Err(invalid(
            "raw inventory count does not equal accepted plus quarantined",
        ));
    }
    Ok(parsed)
}

fn require_fields(object: &Map<String, Value>, keys: &[&str]) -> Result<()> {
    for key in keys {
        if !object.contains_key(*key) {
            return Err(invalid(&format!("missing {key}")));
        }
    }
    Ok(())
}

fn required_string<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(&format!("{key} must be a string")))
}

fn parse_canonical_hex(value: &str) -> Result<u32> {
    if !value.starts_with("0x")
        || value.len() == 2
        || !value[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid("address must be lowercase canonical hexadecimal"));
    }
    let parsed =
        u32::from_str_radix(&value[2..], 16).map_err(|_| invalid("address is outside u32"))?;
    if format!("0x{parsed:x}") != value {
        return Err(invalid("address is not canonical hexadecimal"));
    }
    Ok(parsed)
}

fn parse_global_address(value: &str) -> Result<u32> {
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid("global address must be hexadecimal"));
    }
    u32::from_str_radix(digits, 16).map_err(|_| invalid("global address is outside u32"))
}

fn parse_positive_size(value: &Value) -> Result<u64> {
    let size = value
        .as_u64()
        .ok_or_else(|| invalid("size must be a positive integer"))?;
    if size == 0 {
        return Err(invalid("size must be a positive integer"));
    }
    Ok(size)
}

fn invalid(message: &str) -> Error {
    Error::Serialize(message.to_owned())
}

#[derive(Debug, Serialize)]
pub(crate) struct GlobalShapesFile {
    pub format: &'static str,
    pub image: String,
    pub load_address: String,
    pub inputs: InputHashesWire,
    pub decoder: DecoderWire,
    pub analysis: AnalysisWire,
    pub globals: Vec<GlobalWire>,
}

#[derive(Debug, Serialize)]
pub(crate) struct InputHashesWire {
    pub image_blake3: String,
    pub globals_blake3: String,
    pub functions_blake3: String,
    pub thumb_functions_blake3: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct DecoderWire {
    #[serde(rename = "crate")]
    pub crate_name: String,
    pub version: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct AnalysisWire {
    pub arm_functions: usize,
    pub thumb_functions: usize,
    pub ghidra_records_quarantined: usize,
    pub thumb_records_quarantined: usize,
    pub quarantine_errors: usize,
    pub instructions_decoded: usize,
    pub decode_failures: usize,
    pub state_barriers: usize,
    pub observations: usize,
    pub conflicts: usize,
    pub direct_calls_resolved: usize,
    pub call_facts_unresolved: usize,
    pub seeded_callees: usize,
    pub seed_vectors: usize,
    pub interprocedural_observations: usize,
    pub interprocedural_dropped: usize,
    pub cross_block_join_kills: usize,
    pub cross_block_join_facts: usize,
    pub cross_block_entry_facts: usize,
    pub cross_block_propagated_facts: usize,
    pub cross_block_functions: usize,
    pub cross_block_seeded_functions: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct GlobalWire {
    pub address: String,
    pub name: String,
    pub arch: String,
    pub status: Status,
    pub observations: Vec<ObservationWire>,
    pub conflicts: Vec<ConflictWire>,
    pub summary: Option<SummaryWire>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Status {
    Inferred,
    NoEvidence,
    Conflicting,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ObservationWire {
    pub arch: IsaWire,
    pub pc: String,
    pub conditional: bool,
    pub kind: AccessKindWire,
    pub width: u8,
    pub offset: u32,
    pub functions: Vec<FunctionContextWire>,
    pub provenance_paths: Vec<Vec<String>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub via: Vec<CallHopWire>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct FunctionContextWire {
    pub entry: String,
    pub name: String,
}

/// One depth-1 `bl` hop from a caller's entry block into the tracked
/// callee, recorded on observations whose evidence crossed a direct call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct CallHopWire {
    pub caller_entry: String,
    pub caller_name: String,
    pub call_pc: String,
    pub arg_register: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ConflictWire {
    pub arch: IsaWire,
    pub pc: String,
    pub alternatives: Vec<AlternativeWire>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct AlternativeWire {
    pub target_address: String,
    pub conditional: bool,
    pub kind: AccessKindWire,
    pub width: u8,
    pub offset: u32,
    pub functions: Vec<FunctionContextWire>,
    pub provenance_paths: Vec<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct SummaryWire {
    pub minimum_size: u32,
    pub observed_widths: Vec<u8>,
    pub accessed_offsets: Vec<u32>,
    pub reads: usize,
    pub writes: usize,
    pub provisional_shape: ProvisionalShape,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum ProvisionalShape {
    ScalarCandidate {
        width: u8,
    },
    ArrayCandidate {
        element_width: u8,
        minimum_elements: u32,
    },
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum IsaWire {
    Arm,
    Thumb,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AccessKindWire {
    Read,
    Write,
    ReadWrite,
}

pub(crate) fn serialize(file: &GlobalShapesFile) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec_pretty(file).map_err(|e| Error::Serialize(e.to_string()))?;
    if bytes.ends_with(b"\n") {
        return Err(invalid(
            "serialized global shapes must not have a trailing newline",
        ));
    }
    Ok(bytes)
}

pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    write_atomic_with_before_commit(path, bytes, || Ok(()))
}

pub(crate) fn write_atomic_with_before_commit(
    path: &Path,
    bytes: &[u8],
    before_commit: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let mut file = AtomicWriteFile::open(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    before_commit()?;
    file.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        AnalysisWire, DecoderWire, FunctionContextWire, GlobalShapesFile, InputHashesWire,
        load_inputs, serialize, write_atomic, write_atomic_with_before_commit,
    };
    use crate::error::Error;
    use crate::execution_ranges::{DecodeIsa, DecodeRange};
    use crate::global_shapes::aggregate::aggregate;
    use crate::global_shapes::decoder::AccessKind;
    use crate::global_shapes::tracker::CandidateObservation;
    use crate::global_shapes::{
        FORMAT_V4, FunctionContext, RecoveredGlobal, RunRequest, SourceProjectionCounts,
    };
    use crate::manifest::blake3_bytes;
    use serde_json::{Value, json};
    use std::collections::{BTreeSet, HashMap};
    use std::fs;
    use std::path::PathBuf;

    const LABEL: &str = "02_MAIN";
    const LOAD_ADDR: u32 = 0x4000;

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir()
                .join(format!("pme_global_shapes_{name}_{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(root.join(LABEL).join("decompiled")).unwrap();
            Self { root }
        }

        fn image_dir(&self) -> PathBuf {
            self.root.join(LABEL)
        }

        fn decompiled(&self) -> PathBuf {
            self.image_dir().join("decompiled")
        }

        fn manifest_path(&self) -> PathBuf {
            self.root.join("manifest.json")
        }

        fn write_manifest(&self, load_addr: u64) {
            fs::write(
                self.manifest_path(),
                format!(r#"{{"toc":[{{"name":"MAIN","load_addr":{load_addr}}}]}}"#),
            )
            .unwrap();
        }

        fn write_image(&self, bytes: &[u8]) {
            fs::write(self.image_dir().join(format!("{LABEL}.bin")), bytes).unwrap();
        }

        fn write_globals(&self, value: &Value) {
            fs::write(self.decompiled().join("globals.json"), value.to_string()).unwrap();
        }

        fn write_globals_bytes(&self, bytes: &[u8]) {
            fs::write(self.decompiled().join("globals.json"), bytes).unwrap();
        }

        fn write_functions(&self, value: &Value) {
            fs::write(self.decompiled().join("functions.json"), value.to_string()).unwrap();
        }

        fn write_functions_bytes(&self, bytes: &[u8]) {
            fs::write(self.decompiled().join("functions.json"), bytes).unwrap();
        }

        fn write_thumb(&self, value: &Value) {
            fs::write(
                self.decompiled().join("thumb_functions.json"),
                value.to_string(),
            )
            .unwrap();
        }

        fn write_thumb_bytes(&self, bytes: &[u8]) {
            fs::write(self.decompiled().join("thumb_functions.json"), bytes).unwrap();
        }
    }

    // RunRequest holds references; keep owned paths alive for the call.
    struct BoundRequest {
        image_dir: PathBuf,
        manifest: PathBuf,
        ghidra_records: usize,
        ghidra_accepted: usize,
        ghidra_quarantined: usize,
        thumb_substantial: Option<usize>,
        thumb_accepted: Option<usize>,
        thumb_quarantined: Option<usize>,
        recovered: usize,
    }

    impl BoundRequest {
        #[allow(clippy::too_many_arguments)]
        fn from_fixture(
            fixture: &Fixture,
            ghidra_records: usize,
            ghidra_accepted: usize,
            ghidra_quarantined: usize,
            thumb_substantial: Option<usize>,
            thumb_accepted: Option<usize>,
            thumb_quarantined: Option<usize>,
            recovered: usize,
        ) -> Self {
            Self {
                image_dir: fixture.image_dir(),
                manifest: fixture.manifest_path(),
                ghidra_records,
                ghidra_accepted,
                ghidra_quarantined,
                thumb_substantial,
                thumb_accepted,
                thumb_quarantined,
                recovered,
            }
        }

        fn get(&self) -> RunRequest<'_> {
            RunRequest {
                image_dir: &self.image_dir,
                image_label: LABEL,
                manifest_path: &self.manifest,
                expected_ghidra_records: self.ghidra_records,
                expected_ghidra_accepted: self.ghidra_accepted,
                expected_ghidra_quarantined: self.ghidra_quarantined,
                expected_thumb_substantial: self.thumb_substantial,
                expected_thumb_accepted: self.thumb_accepted,
                expected_thumb_quarantined: self.thumb_quarantined,
                expected_recovered_globals: self.recovered,
            }
        }
    }

    fn recovered_global(address: &str, name: &str, arch: &str) -> Value {
        json!({
            "address": address,
            "arch": arch,
            "name": name,
            "tier": "recovered",
            "size": null,
            "evidence": [],
            "annotations": [],
            "producer_note": "known-extension",
        })
    }

    fn provisional_global(address: &str, name: &str) -> Value {
        json!({
            "address": address,
            "arch": "arm",
            "name": name,
            "tier": "provisional",
            "size": null,
            "evidence": [],
            "annotations": [],
        })
    }

    fn globals_file(globals: &[Value]) -> Value {
        json!({
            "format": "pixel-modem-extractor-globals-v1",
            "image": LABEL,
            "globals": globals,
            "phase3_0_1_error": null,
            "provisional_suppressed": 0,
        })
    }

    fn arm_range(start: &str, end: &str) -> Value {
        json!({"isa": "arm", "start": start, "end": end})
    }

    fn thumb_range(start: &str, end: &str) -> Value {
        json!({"isa": "thumb", "start": start, "end": end})
    }

    fn ghidra_accepted(name: &str, entry: &str, end: &str, size: u64, ranges: Vec<Value>) -> Value {
        json!({
            "name": name,
            "entry": entry,
            "end": end,
            "size": size,
            "decode_ranges": ranges,
            "decode_range_errors": [],
            "data_refs": [],
        })
    }

    fn ghidra_quarantined(
        name: &str,
        entry: &str,
        end: &str,
        size: u64,
        errors: Vec<Value>,
    ) -> Value {
        json!({
            "name": name,
            "entry": entry,
            "end": end,
            "size": size,
            "decode_ranges": [],
            "decode_range_errors": errors,
            "data_refs": [],
        })
    }

    fn thumb_accepted(name: &str, entry: &str, size: u64, ranges: Vec<Value>) -> Value {
        json!({
            "name": name,
            "entry": entry,
            "size": size,
            "decode_ranges": ranges,
            "decode_range_errors": [],
        })
    }

    fn thumb_quarantined(name: &str, entry: &str, size: u64, errors: Vec<Value>) -> Value {
        json!({
            "name": name,
            "entry": entry,
            "size": size,
            "decode_ranges": [],
            "decode_range_errors": errors,
        })
    }

    fn thumb_file(format: &str, functions: &[Value]) -> Value {
        json!({"format": format, "functions": functions})
    }

    fn quarantine_error(kind: &str, address: &str, end: Option<&str>) -> Value {
        match end {
            Some(end) => json!({"kind": kind, "address": address, "end": end}),
            None => json!({"kind": kind, "address": address, "end": null}),
        }
    }

    fn seed_valid_arm(fixture: &Fixture) {
        fixture.write_manifest(u64::from(LOAD_ADDR));
        fixture.write_image(&[0u8; 0x20]);
        fixture.write_globals(&globals_file(&[recovered_global("0x4100", "g_arm", "arm")]));
        fixture.write_functions(&json!([ghidra_accepted(
            "FUN_4000",
            "0x4000",
            "0x4010",
            4,
            vec![arm_range("0x4000", "0x4004")],
        )]));
    }

    fn load_ok(request: &RunRequest<'_>) -> super::LoadedInputs {
        load_inputs(request).expect("valid fixture must load")
    }

    #[test]
    fn loads_v3_thumb_inventory() {
        let fixture = Fixture::new("v3_thumb_inventory");
        fixture.write_manifest(u64::from(LOAD_ADDR));
        fixture.write_image(&[0u8; 0x80]);
        fixture.write_globals(&globals_file(&[]));
        fixture.write_functions(&json!([]));
        let thumb = crate::thumb_analysis::ParsedThumbArtifact::consumer_v3_fixture();
        fixture.write_thumb_bytes(thumb);
        let bound = BoundRequest::from_fixture(&fixture, 0, 0, 0, Some(1), Some(1), Some(1), 0);

        let loaded = load_ok(&bound.get());
        assert_eq!(
            loaded.hashes.thumb_functions_blake3,
            Some(blake3_bytes(thumb))
        );
        assert_eq!(loaded.functions.len(), 1);
        assert_eq!(loaded.functions[0].identity.entry, 0x4000);
        assert_eq!(
            loaded.functions[0].identity.decode_ranges,
            vec![DecodeRange {
                start: 0x4000,
                end: 0x4008,
                isa: DecodeIsa::Thumb,
            }]
        );
        assert_eq!(
            loaded.source_counts,
            SourceProjectionCounts {
                ghidra_accepted: 0,
                ghidra_quarantined: 0,
                thumb_accepted: 1,
                thumb_quarantined: 1,
                quarantine_errors: 1,
            }
        );

        fixture.write_thumb_bytes(
            &crate::thumb_analysis::ParsedThumbArtifact::malformed_consumer_v3_fixture(),
        );
        assert_eq!(
            load_inputs(&bound.get()).unwrap_err().to_string(),
            "serialize: invalid Thumb artifact: v3 run 0 stored counts do not match its functions"
        );
    }

    #[test]
    fn loads_valid_arm_only_identity() {
        let fixture = Fixture::new("arm_only");
        seed_valid_arm(&fixture);
        let bound = BoundRequest::from_fixture(&fixture, 1, 1, 0, None, None, None, 1);
        let loaded = load_ok(&bound.get());
        assert_eq!(loaded.load_address, LOAD_ADDR);
        assert_eq!(loaded.image.len(), 0x20);
        assert_eq!(
            loaded.globals,
            vec![RecoveredGlobal {
                source_index: 0,
                address: 0x4100,
                name: "g_arm".into(),
                arch: "arm".into(),
            }]
        );
        assert_eq!(loaded.functions.len(), 1);
        assert_eq!(loaded.functions[0].identity.entry, 0x4000);
        assert_eq!(
            loaded.functions[0].identity.decode_ranges,
            vec![DecodeRange {
                start: 0x4000,
                end: 0x4004,
                isa: DecodeIsa::Arm,
            }]
        );
        assert_eq!(
            loaded.functions[0]
                .contexts
                .iter()
                .cloned()
                .collect::<Vec<_>>(),
            vec![FunctionContext {
                entry: 0x4000,
                name: "FUN_4000".into(),
            }]
        );
        assert_eq!(
            loaded.source_counts,
            SourceProjectionCounts {
                ghidra_accepted: 1,
                ghidra_quarantined: 0,
                thumb_accepted: 0,
                thumb_quarantined: 0,
                quarantine_errors: 0,
            }
        );
        assert_eq!(loaded.hashes.thumb_functions_blake3, None);
    }

    #[test]
    fn loads_valid_thumb_only_identity() {
        let fixture = Fixture::new("thumb_only");
        fixture.write_manifest(u64::from(LOAD_ADDR));
        fixture.write_image(&[0u8; 0x40]);
        fixture.write_globals(&globals_file(&[recovered_global(
            "0x4120", "g_thumb", "thumb",
        )]));
        fixture.write_functions(&json!([]));
        fixture.write_thumb(&thumb_file(
            "pixel-modem-extractor-thumb-functions-v2",
            &[thumb_accepted(
                "thumb_4000",
                "0x4000",
                32,
                vec![thumb_range("0x4000", "0x4020")],
            )],
        ));
        let bound = BoundRequest::from_fixture(&fixture, 0, 0, 0, Some(1), Some(1), Some(0), 1);
        let loaded = load_ok(&bound.get());
        assert_eq!(loaded.functions.len(), 1);
        assert_eq!(
            loaded.functions[0].identity.decode_ranges[0].isa,
            DecodeIsa::Thumb
        );
        assert_eq!(loaded.source_counts.thumb_accepted, 1);
        assert!(loaded.hashes.thumb_functions_blake3.is_some());
    }

    #[test]
    fn loads_valid_mixed_range_identity() {
        let fixture = Fixture::new("mixed_range");
        fixture.write_manifest(u64::from(LOAD_ADDR));
        fixture.write_image(&[0u8; 0x20]);
        fixture.write_globals(&globals_file(&[recovered_global(
            "0x4100", "g_mixed", "mixed",
        )]));
        fixture.write_functions(&json!([ghidra_accepted(
            "FUN_mixed",
            "0x4000",
            "0x4010",
            8,
            vec![
                arm_range("0x4000", "0x4004"),
                thumb_range("0x4004", "0x4008"),
            ],
        )]));
        let bound = BoundRequest::from_fixture(&fixture, 1, 1, 0, None, None, None, 1);
        let loaded = load_ok(&bound.get());
        assert_eq!(loaded.functions.len(), 1);
        assert_eq!(loaded.functions[0].identity.decode_ranges.len(), 2);
        assert_eq!(
            loaded.functions[0].identity.decode_ranges[0].isa,
            DecodeIsa::Arm
        );
        assert_eq!(
            loaded.functions[0].identity.decode_ranges[1].isa,
            DecodeIsa::Thumb
        );
    }

    #[test]
    fn accepts_thumb_v1_and_v2_wrappers_when_every_record_has_current_ranges() {
        for (name, format) in [
            ("thumb_v1", "pixel-modem-extractor-thumb-functions-v1"),
            ("thumb_v2", "pixel-modem-extractor-thumb-functions-v2"),
        ] {
            let fixture = Fixture::new(name);
            fixture.write_manifest(u64::from(LOAD_ADDR));
            fixture.write_image(&[0u8; 0x40]);
            fixture.write_globals(&globals_file(&[]));
            fixture.write_functions(&json!([]));
            let mut record = thumb_accepted(
                "thumb_4000",
                "0x4000",
                16,
                vec![thumb_range("0x4000", "0x4010")],
            );
            record["end"] = json!("0x4080");
            fixture.write_thumb(&thumb_file(format, &[record]));
            let bound = BoundRequest::from_fixture(&fixture, 0, 0, 0, Some(0), Some(1), Some(0), 0);
            let loaded = load_ok(&bound.get());
            assert_eq!(loaded.functions.len(), 1);
            assert_eq!(loaded.functions[0].identity.decode_ranges[0].end, 0x4010);
        }
    }

    #[test]
    fn filters_provisional_globals_in_source_order() {
        let fixture = Fixture::new("filter_provisional");
        seed_valid_arm(&fixture);
        fixture.write_globals(&globals_file(&[
            recovered_global("0x4100", "first", "arm"),
            provisional_global("0x4104", "skip_me"),
            recovered_global("0x4108", "second", "thumb"),
            provisional_global("0x410c", "also_skip"),
            recovered_global("0x4110", "third", "mixed"),
        ]));
        let bound = BoundRequest::from_fixture(&fixture, 1, 1, 0, None, None, None, 3);
        let loaded = load_ok(&bound.get());
        assert_eq!(
            loaded
                .globals
                .iter()
                .map(|global| (global.source_index, global.address, global.name.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (0, 0x4100, "first"),
                (2, 0x4108, "second"),
                (4, 0x4110, "third")
            ]
        );
    }

    #[test]
    fn accepts_zero_recovered_projection_and_still_validates_every_file() {
        let fixture = Fixture::new("zero_recovered");
        fixture.write_manifest(u64::from(LOAD_ADDR));
        let image = vec![0u8; 0x10];
        fixture.write_image(&image);
        let globals = globals_file(&[provisional_global("0x4100", "only_prov")]);
        let functions = json!([ghidra_accepted(
            "FUN_4000",
            "0x4000",
            "0x4008",
            4,
            vec![arm_range("0x4000", "0x4004")],
        )]);
        fixture.write_globals(&globals);
        fixture.write_functions(&functions);
        let bound = BoundRequest::from_fixture(&fixture, 1, 1, 0, None, None, None, 0);
        let loaded = load_ok(&bound.get());
        assert!(loaded.globals.is_empty());
        assert_eq!(loaded.hashes.image_blake3, blake3_bytes(&image));
        assert_eq!(
            loaded.hashes.globals_blake3,
            blake3_bytes(globals.to_string().as_bytes())
        );
        assert_eq!(
            loaded.hashes.functions_blake3,
            blake3_bytes(functions.to_string().as_bytes())
        );
        assert_eq!(loaded.hashes.thumb_functions_blake3, None);
    }

    #[test]
    fn rejects_raw_ghidra_and_producer_count_disagreements() {
        let fixture = Fixture::new("count_disagree");
        fixture.write_manifest(u64::from(LOAD_ADDR));
        fixture.write_image(&[0u8; 0x40]);
        fixture.write_globals(&globals_file(&[recovered_global("0x4100", "g", "arm")]));
        fixture.write_functions(&json!([
            ghidra_accepted(
                "FUN_4000",
                "0x4000",
                "0x4008",
                4,
                vec![arm_range("0x4000", "0x4004")],
            ),
            ghidra_quarantined(
                "FUN_4008",
                "0x4008",
                "0x4010",
                4,
                vec![quarantine_error("empty_projection", "0x4008", None)],
            ),
        ]));
        fixture.write_thumb(&thumb_file(
            "pixel-modem-extractor-thumb-functions-v2",
            &[
                thumb_accepted(
                    "thumb_4020",
                    "0x4020",
                    32,
                    vec![thumb_range("0x4020", "0x4040")],
                ),
                thumb_accepted(
                    "thumb_4010",
                    "0x4010",
                    8,
                    vec![thumb_range("0x4010", "0x4018")],
                ),
            ],
        ));

        let cases = [
            BoundRequest::from_fixture(&fixture, 1, 1, 1, Some(1), Some(2), Some(0), 1),
            BoundRequest::from_fixture(&fixture, 2, 0, 1, Some(1), Some(2), Some(0), 1),
            BoundRequest::from_fixture(&fixture, 2, 1, 0, Some(1), Some(2), Some(0), 1),
            BoundRequest::from_fixture(&fixture, 2, 1, 1, Some(2), Some(2), Some(0), 1),
            BoundRequest::from_fixture(&fixture, 2, 1, 1, Some(1), Some(1), Some(0), 1),
            BoundRequest::from_fixture(&fixture, 2, 1, 1, Some(1), Some(2), Some(1), 1),
            BoundRequest::from_fixture(&fixture, 2, 1, 1, Some(1), Some(2), Some(0), 0),
        ];
        for bound in cases {
            assert!(
                load_inputs(&bound.get()).is_err(),
                "accepted count disagreement {:?}",
                bound.ghidra_records
            );
        }
    }

    #[test]
    fn rejects_missing_functions_globals_or_raw_image() {
        let fixture = Fixture::new("missing_files");
        seed_valid_arm(&fixture);
        fs::remove_file(fixture.decompiled().join("functions.json")).unwrap();
        let bound = BoundRequest::from_fixture(&fixture, 1, 1, 0, None, None, None, 1);
        assert!(load_inputs(&bound.get()).is_err());

        let fixture = Fixture::new("missing_globals");
        seed_valid_arm(&fixture);
        fs::remove_file(fixture.decompiled().join("globals.json")).unwrap();
        let bound = BoundRequest::from_fixture(&fixture, 1, 1, 0, None, None, None, 1);
        assert!(load_inputs(&bound.get()).is_err());

        let fixture = Fixture::new("missing_image");
        seed_valid_arm(&fixture);
        fs::remove_file(fixture.image_dir().join(format!("{LABEL}.bin"))).unwrap();
        let bound = BoundRequest::from_fixture(&fixture, 1, 1, 0, None, None, None, 1);
        assert!(load_inputs(&bound.get()).is_err());
    }

    #[test]
    fn required_thumb_file_is_missing_while_absent_thumb_is_valid() {
        let missing = Fixture::new("thumb_required_missing");
        seed_valid_arm(&missing);
        let bound = BoundRequest::from_fixture(&missing, 1, 1, 0, Some(0), Some(0), Some(0), 1);
        assert!(load_inputs(&bound.get()).is_err());

        let absent = Fixture::new("thumb_legitimately_absent");
        seed_valid_arm(&absent);
        let bound = BoundRequest::from_fixture(&absent, 1, 1, 0, None, None, None, 1);
        assert!(load_inputs(&bound.get()).is_ok());
    }

    #[test]
    fn rejects_stale_unexpected_thumb_when_all_metrics_are_none() {
        let fixture = Fixture::new("stale_thumb");
        seed_valid_arm(&fixture);
        fixture.write_thumb(&thumb_file("pixel-modem-extractor-thumb-functions-v2", &[]));
        let bound = BoundRequest::from_fixture(&fixture, 1, 1, 0, None, None, None, 1);
        assert!(load_inputs(&bound.get()).is_err());
    }

    #[test]
    fn rejects_mixed_thumb_expectation_options() {
        let fixture = Fixture::new("mixed_thumb_opts");
        seed_valid_arm(&fixture);
        let bound = BoundRequest::from_fixture(&fixture, 1, 1, 0, Some(0), None, Some(0), 1);
        assert!(load_inputs(&bound.get()).is_err());
    }

    #[test]
    fn rejects_wrong_format_image_malformed_json_missing_fields_bad_hex_invalid_arch_tier_and_nonzero_size()
     {
        let fixture = Fixture::new("globals_schema");
        seed_valid_arm(&fixture);
        let bound = BoundRequest::from_fixture(&fixture, 1, 1, 0, None, None, None, 1);
        let valid = recovered_global("0x4100", "g", "arm");
        let cases = [
            json!({"format":"pixel-modem-extractor-globals-v0","image":LABEL,"globals":[valid.clone()]}),
            json!({"format":"pixel-modem-extractor-globals-v1","image":"03_APM","globals":[valid.clone()]}),
            json!({"format":"pixel-modem-extractor-globals-v1","image":LABEL,"globals":"nope"}),
            {
                let mut g = valid.clone();
                g.as_object_mut().unwrap().remove("evidence");
                globals_file(&[g])
            },
            {
                let mut g = valid.clone();
                g["address"] = json!("0xzz");
                globals_file(&[g])
            },
            {
                let mut g = valid.clone();
                g["arch"] = json!("a32");
                globals_file(&[g])
            },
            {
                let mut g = valid.clone();
                g["tier"] = json!("guessed");
                globals_file(&[g])
            },
            {
                let mut g = valid.clone();
                g["size"] = json!(4);
                globals_file(&[g])
            },
        ];
        for value in cases {
            fixture.write_globals(&value);
            assert!(
                load_inputs(&bound.get()).is_err(),
                "accepted invalid globals {value}"
            );
        }
        fixture.write_globals_bytes(b"{not json");
        assert!(load_inputs(&bound.get()).is_err());
    }

    #[test]
    fn rejects_duplicate_recovered_addresses_after_normalization() {
        let fixture = Fixture::new("dup_addr");
        seed_valid_arm(&fixture);
        fixture.write_globals(&globals_file(&[
            recovered_global("0x40", "left", "arm"),
            recovered_global("40", "right", "thumb"),
        ]));
        let bound = BoundRequest::from_fixture(&fixture, 1, 1, 0, None, None, None, 2);
        assert!(load_inputs(&bound.get()).is_err());
    }

    fn write_minimal_with_functions(fixture: &Fixture, functions: Value) {
        fixture.write_manifest(u64::from(LOAD_ADDR));
        fixture.write_image(&[0u8; 0x40]);
        fixture.write_globals(&globals_file(&[]));
        fixture.write_functions(&functions);
        let _ = fs::remove_file(fixture.decompiled().join("thumb_functions.json"));
    }

    #[test]
    fn rejects_missing_both_neither_unknown_extra_unsorted_errors_and_accepts_valid_quarantine() {
        let fixture = Fixture::new("tags");
        let valid_error = quarantine_error("empty_projection", "0x4008", None);
        let cases: &[Value] = &[
            json!([{
                "name": "missing_ranges",
                "entry": "0x4000",
                "end": "0x4004",
                "size": 4,
                "decode_range_errors": [],
            }]),
            json!([{
                "name": "missing_errors",
                "entry": "0x4000",
                "end": "0x4004",
                "size": 4,
                "decode_ranges": [arm_range("0x4000", "0x4004")],
            }]),
            json!([{
                "name": "both",
                "entry": "0x4000",
                "end": "0x4004",
                "size": 4,
                "decode_ranges": [arm_range("0x4000", "0x4004")],
                "decode_range_errors": [valid_error.clone()],
            }]),
            json!([{
                "name": "neither",
                "entry": "0x4000",
                "end": "0x4004",
                "size": 4,
                "decode_ranges": [],
                "decode_range_errors": [],
            }]),
            json!([ghidra_quarantined(
                "unknown_kind",
                "0x4008",
                "0x400c",
                4,
                vec![json!({"kind":"not_a_kind","address":"0x4008","end":null})],
            )]),
            json!([ghidra_quarantined(
                "extra_field",
                "0x4008",
                "0x400c",
                4,
                vec![json!({"kind":"empty_projection","address":"0x4008","end":null,"extra":true})],
            )]),
            json!([ghidra_quarantined(
                "unsorted",
                "0x4008",
                "0x400c",
                4,
                vec![
                    quarantine_error("empty_projection", "0x400c", None),
                    quarantine_error("empty_projection", "0x4008", None),
                ],
            )]),
            json!([ghidra_quarantined(
                "duplicated",
                "0x4008",
                "0x400c",
                4,
                vec![
                    quarantine_error("empty_projection", "0x4008", None),
                    quarantine_error("empty_projection", "0x4008", None),
                ],
            )]),
        ];
        for (index, functions) in cases.iter().enumerate() {
            write_minimal_with_functions(&fixture, functions.clone());
            let bound = BoundRequest::from_fixture(&fixture, 1, 0, 1, None, None, None, 0);
            assert!(
                load_inputs(&bound.get()).is_err(),
                "accepted invalid tag case {index}: {functions}"
            );
        }

        fixture.write_functions(&json!([]));
        fixture.write_thumb(&thumb_file(
            "pixel-modem-extractor-thumb-functions-v2",
            &[json!({
                "name": "missing_thumb_ranges",
                "entry": "0x4000",
                "size": 8,
                "decode_range_errors": [],
            })],
        ));
        let bound = BoundRequest::from_fixture(&fixture, 0, 0, 0, Some(0), Some(0), Some(1), 0);
        assert!(load_inputs(&bound.get()).is_err());

        write_minimal_with_functions(
            &fixture,
            json!([ghidra_quarantined(
                "FUN_4008",
                "0x4008",
                "0x400c",
                4,
                vec![valid_error],
            )]),
        );
        let bound = BoundRequest::from_fixture(&fixture, 1, 0, 1, None, None, None, 0);
        let loaded = load_ok(&bound.get());
        assert!(loaded.functions.is_empty());
        assert_eq!(loaded.source_counts.ghidra_quarantined, 1);
        assert_eq!(loaded.source_counts.quarantine_errors, 1);

        fixture.write_functions(&json!([]));
        fixture.write_thumb(&thumb_file(
            "pixel-modem-extractor-thumb-functions-v2",
            &[thumb_quarantined(
                "thumb_4008",
                "0x4008",
                8,
                vec![quarantine_error("empty_projection", "0x4008", None)],
            )],
        ));
        let bound = BoundRequest::from_fixture(&fixture, 0, 0, 0, Some(0), Some(0), Some(1), 0);
        let loaded = load_ok(&bound.get());
        assert!(loaded.functions.is_empty());
        assert_eq!(loaded.source_counts.thumb_quarantined, 1);
        assert_eq!(loaded.source_counts.quarantine_errors, 1);
    }

    #[test]
    fn rejects_invalid_accepted_ranges_on_both_inventories() {
        let fixture = Fixture::new("bad_ranges");
        let ghidra_cases = [
            ghidra_accepted("empty", "0x4000", "0x4004", 4, vec![]),
            ghidra_accepted(
                "reversed",
                "0x4000",
                "0x4004",
                4,
                vec![arm_range("0x4008", "0x4000")],
            ),
            json!({
                "name": "bad_hex",
                "entry": "0X4000",
                "end": "0x4004",
                "size": 4,
                "decode_ranges": [arm_range("0x4000", "0x4004")],
                "decode_range_errors": [],
            }),
            json!({
                "name": "bad_isa",
                "entry": "0x4000",
                "end": "0x4004",
                "size": 4,
                "decode_ranges": [{"isa":"ARM","start":"0x4000","end":"0x4004"}],
                "decode_range_errors": [],
            }),
            ghidra_accepted(
                "unsorted",
                "0x4000",
                "0x4010",
                8,
                vec![arm_range("0x4004", "0x4008"), arm_range("0x4000", "0x4004")],
            ),
            ghidra_accepted(
                "overlap",
                "0x4000",
                "0x4010",
                8,
                vec![arm_range("0x4000", "0x4008"), arm_range("0x4004", "0x400c")],
            ),
            ghidra_accepted(
                "unmerged",
                "0x4000",
                "0x4010",
                8,
                vec![arm_range("0x4000", "0x4004"), arm_range("0x4004", "0x4008")],
            ),
            ghidra_accepted(
                "arm_misaligned",
                "0x4000",
                "0x4004",
                2,
                vec![arm_range("0x4002", "0x4006")],
            ),
            ghidra_accepted(
                "thumb_misaligned",
                "0x4000",
                "0x4004",
                1,
                vec![thumb_range("0x4001", "0x4003")],
            ),
            ghidra_accepted(
                "unmappable",
                "0x1000",
                "0x1004",
                4,
                vec![arm_range("0x1000", "0x1004")],
            ),
            ghidra_accepted(
                "beyond",
                "0x4000",
                "0x4100",
                4,
                vec![arm_range("0x4000", "0x4080")],
            ),
            ghidra_accepted(
                "entry_interior",
                "0x4004",
                "0x400c",
                8,
                vec![arm_range("0x4000", "0x4008")],
            ),
        ];
        for (index, record) in ghidra_cases.into_iter().enumerate() {
            write_minimal_with_functions(&fixture, json!([record]));
            let bound = BoundRequest::from_fixture(&fixture, 1, 1, 0, None, None, None, 0);
            assert!(
                load_inputs(&bound.get()).is_err(),
                "accepted invalid ghidra range case {index}"
            );
        }

        fixture.write_functions(&json!([]));
        let thumb_bad = thumb_accepted(
            "thumb_bad",
            "0x4000",
            8,
            vec![thumb_range("0x4000", "0x4003")],
        );
        fixture.write_thumb(&thumb_file(
            "pixel-modem-extractor-thumb-functions-v2",
            &[thumb_bad],
        ));
        let bound = BoundRequest::from_fixture(&fixture, 0, 0, 0, Some(0), Some(1), Some(0), 0);
        assert!(load_inputs(&bound.get()).is_err());
    }

    #[test]
    fn rejects_overflowed_mapped_image_end() {
        let fixture = Fixture::new("overflow_map");
        fixture.write_manifest(u64::from(u32::MAX - 4));
        fixture.write_image(&[0u8; 16]);
        fixture.write_globals(&globals_file(&[]));
        fixture.write_functions(&json!([]));
        let bound = BoundRequest::from_fixture(&fixture, 0, 0, 0, None, None, None, 0);
        assert!(load_inputs(&bound.get()).is_err());
    }

    #[test]
    fn collapses_duplicate_identities_and_unions_sorted_contexts() {
        let fixture = Fixture::new("dedup_union");
        fixture.write_manifest(u64::from(LOAD_ADDR));
        fixture.write_image(&[0u8; 0x20]);
        fixture.write_globals(&globals_file(&[]));
        fixture.write_functions(&json!([
            ghidra_accepted(
                "z_name",
                "0x4000",
                "0x4008",
                4,
                vec![arm_range("0x4000", "0x4004")],
            ),
            ghidra_accepted(
                "a_name",
                "0x4000",
                "0x4010",
                16,
                vec![arm_range("0x4000", "0x4004")],
            ),
            ghidra_accepted(
                "a_name",
                "0x4000",
                "0x400c",
                8,
                vec![arm_range("0x4000", "0x4004")],
            ),
        ]));
        let bound = BoundRequest::from_fixture(&fixture, 3, 3, 0, None, None, None, 0);
        let loaded = load_ok(&bound.get());
        assert_eq!(loaded.source_counts.ghidra_accepted, 3);
        assert_eq!(loaded.functions.len(), 1);
        assert_eq!(
            loaded.functions[0]
                .contexts
                .iter()
                .map(|context| (context.entry, context.name.as_str()))
                .collect::<Vec<_>>(),
            vec![(0x4000, "a_name"), (0x4000, "z_name")]
        );
    }

    #[test]
    fn keeps_overlapping_and_adjacent_identities_separate_and_drops_quarantine() {
        let fixture = Fixture::new("distinct_ids");
        fixture.write_manifest(u64::from(LOAD_ADDR));
        fixture.write_image(&[0u8; 0x20]);
        fixture.write_globals(&globals_file(&[]));
        fixture.write_functions(&json!([
            ghidra_accepted(
                "arm_overlap",
                "0x4000",
                "0x4008",
                8,
                vec![arm_range("0x4000", "0x4008")],
            ),
            ghidra_accepted(
                "thumb_overlap",
                "0x4000",
                "0x4008",
                8,
                vec![thumb_range("0x4000", "0x4008")],
            ),
            ghidra_accepted(
                "thumb_shift",
                "0x4002",
                "0x400a",
                8,
                vec![thumb_range("0x4002", "0x400a")],
            ),
            ghidra_accepted(
                "mixed_adj",
                "0x4008",
                "0x4010",
                8,
                vec![
                    arm_range("0x4008", "0x400c"),
                    thumb_range("0x400c", "0x4010"),
                ],
            ),
            ghidra_quarantined(
                "quarantined",
                "0x4010",
                "0x4014",
                4,
                vec![quarantine_error("empty_projection", "0x4010", None)],
            ),
        ]));
        let bound = BoundRequest::from_fixture(&fixture, 5, 4, 1, None, None, None, 0);
        let loaded = load_ok(&bound.get());
        assert_eq!(loaded.functions.len(), 4);
        assert_eq!(loaded.source_counts.ghidra_accepted, 4);
        assert_eq!(loaded.source_counts.ghidra_quarantined, 1);
        assert!(
            loaded
                .functions
                .iter()
                .all(|function| function.identity.entry != 0x4010)
        );
        let same_entry_isas: BTreeSet<_> = loaded
            .functions
            .iter()
            .filter(|function| function.identity.entry == 0x4000)
            .map(|function| function.identity.decode_ranges[0].isa)
            .collect();
        assert_eq!(
            same_entry_isas,
            [DecodeIsa::Arm, DecodeIsa::Thumb].into_iter().collect()
        );
    }

    #[test]
    fn binds_lowercase_blake3_to_exact_bytes_with_explicit_null_thumb_hash() {
        let fixture = Fixture::new("hashes");
        fixture.write_manifest(u64::from(LOAD_ADDR));
        let image = b"raw-image-bytes\n".to_vec();
        let globals =
            br#"{"format":"pixel-modem-extractor-globals-v1","image":"02_MAIN","globals":[]}"#;
        let functions = br#"[]"#;
        fixture.write_image(&image);
        fixture.write_globals_bytes(globals);
        fixture.write_functions_bytes(functions);
        let bound = BoundRequest::from_fixture(&fixture, 0, 0, 0, None, None, None, 0);
        let loaded = load_ok(&bound.get());
        assert_eq!(loaded.hashes.image_blake3, blake3_bytes(&image));
        assert_eq!(loaded.hashes.globals_blake3, blake3_bytes(globals));
        assert_eq!(loaded.hashes.functions_blake3, blake3_bytes(functions));
        assert_eq!(loaded.hashes.thumb_functions_blake3, None);
        assert!(
            loaded
                .hashes
                .image_blake3
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
        assert_eq!(loaded.hashes.image_blake3.len(), 64);

        let thumb = br#"{"format":"pixel-modem-extractor-thumb-functions-v2","functions":[]}"#;
        fixture.write_thumb_bytes(thumb);
        let bound = BoundRequest::from_fixture(&fixture, 0, 0, 0, Some(0), Some(0), Some(0), 0);
        let loaded = load_ok(&bound.get());
        assert_eq!(
            loaded.hashes.thumb_functions_blake3.as_deref(),
            Some(blake3_bytes(thumb).as_str())
        );
    }

    fn golden_obs(
        target: u32,
        isa: DecodeIsa,
        pc: u32,
        kind: AccessKind,
        width: u8,
        offset: u32,
    ) -> CandidateObservation {
        CandidateObservation {
            target_address: target,
            isa,
            pc,
            conditional: false,
            kind,
            width,
            offset,
            functions: BTreeSet::new(),
            provenance_path: Vec::new(),
            via: Vec::new(),
        }
    }

    fn golden_file() -> GlobalShapesFile {
        let recovered = vec![
            RecoveredGlobal {
                source_index: 0,
                address: 0x4100,
                name: "g_scalar".into(),
                arch: "arm".into(),
            },
            RecoveredGlobal {
                source_index: 1,
                address: 0x4200,
                name: "g_array".into(),
                arch: "thumb".into(),
            },
            RecoveredGlobal {
                source_index: 2,
                address: 0x4300,
                name: "g_unknown".into(),
                arch: "mixed".into(),
            },
            RecoveredGlobal {
                source_index: 3,
                address: 0x4400,
                name: "g_none".into(),
                arch: "arm".into(),
            },
            RecoveredGlobal {
                source_index: 4,
                address: 0x4500,
                name: "g_conflict".into(),
                arch: "thumb".into(),
            },
        ];
        let mut scalar = golden_obs(0x4100, DecodeIsa::Arm, 0x4000, AccessKind::Read, 4, 0);
        scalar.functions = BTreeSet::from([FunctionContext {
            entry: 0x4000,
            name: "FUN_4000".into(),
        }]);
        scalar.provenance_path = vec![0x4000];
        let mut array_tail = golden_obs(0x4200, DecodeIsa::Thumb, 0x4010, AccessKind::Write, 2, 4);
        array_tail.conditional = true;
        let mut conflict_read =
            golden_obs(0x4500, DecodeIsa::Thumb, 0x4030, AccessKind::Read, 4, 0);
        conflict_read.functions = BTreeSet::from([FunctionContext {
            entry: 0x4030,
            name: "thumb_4030".into(),
        }]);
        conflict_read.provenance_path = vec![0x4030, 0x4032];
        let candidates = vec![
            scalar,
            golden_obs(0x4200, DecodeIsa::Thumb, 0x4008, AccessKind::Write, 2, 0),
            array_tail,
            golden_obs(0x4300, DecodeIsa::Arm, 0x4020, AccessKind::ReadWrite, 1, 1),
            conflict_read,
            golden_obs(0x4500, DecodeIsa::Thumb, 0x4030, AccessKind::Write, 4, 0),
        ];
        let aggregation =
            aggregate(&recovered, candidates, Vec::new()).expect("golden aggregation");
        GlobalShapesFile {
            format: FORMAT_V4,
            image: LABEL.into(),
            load_address: "0x40000000".into(),
            inputs: InputHashesWire {
                image_blake3: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    .into(),
                globals_blake3: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .into(),
                functions_blake3:
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
                thumb_functions_blake3: None,
            },
            decoder: DecoderWire {
                crate_name: "scaleservers-arm32-assembly".into(),
                version: "1.0.0".into(),
            },
            analysis: AnalysisWire {
                arm_functions: 2,
                thumb_functions: 3,
                ghidra_records_quarantined: 2,
                thumb_records_quarantined: 4,
                quarantine_errors: 6,
                instructions_decoded: 9,
                decode_failures: 1,
                state_barriers: 3,
                observations: aggregation.observations,
                conflicts: aggregation.conflicts,
                direct_calls_resolved: 0,
                call_facts_unresolved: 0,
                seeded_callees: 0,
                seed_vectors: 0,
                interprocedural_observations: 0,
                interprocedural_dropped: 0,
                cross_block_join_kills: 7,
                cross_block_join_facts: 11,
                cross_block_entry_facts: 13,
                cross_block_propagated_facts: 5,
                cross_block_functions: 2,
                cross_block_seeded_functions: 1,
            },
            globals: aggregation.globals,
        }
    }

    const V4_WIRE_GOLDEN: &str = r#"{
  "format": "pixel-modem-extractor-global-shapes-v4",
  "image": "02_MAIN",
  "load_address": "0x40000000",
  "inputs": {
    "image_blake3": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "globals_blake3": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "functions_blake3": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "thumb_functions_blake3": null
  },
  "decoder": {
    "crate": "scaleservers-arm32-assembly",
    "version": "1.0.0"
  },
  "analysis": {
    "arm_functions": 2,
    "thumb_functions": 3,
    "ghidra_records_quarantined": 2,
    "thumb_records_quarantined": 4,
    "quarantine_errors": 6,
    "instructions_decoded": 9,
    "decode_failures": 1,
    "state_barriers": 3,
    "observations": 4,
    "conflicts": 1,
    "direct_calls_resolved": 0,
    "call_facts_unresolved": 0,
    "seeded_callees": 0,
    "seed_vectors": 0,
    "interprocedural_observations": 0,
    "interprocedural_dropped": 0,
    "cross_block_join_kills": 7,
    "cross_block_join_facts": 11,
    "cross_block_entry_facts": 13,
    "cross_block_propagated_facts": 5,
    "cross_block_functions": 2,
    "cross_block_seeded_functions": 1
  },
  "globals": [
    {
      "address": "0x4100",
      "name": "g_scalar",
      "arch": "arm",
      "status": "inferred",
      "observations": [
        {
          "arch": "arm",
          "pc": "0x4000",
          "conditional": false,
          "kind": "read",
          "width": 4,
          "offset": 0,
          "functions": [
            {
              "entry": "0x4000",
              "name": "FUN_4000"
            }
          ],
          "provenance_paths": [
            [
              "0x4000"
            ]
          ]
        }
      ],
      "conflicts": [],
      "summary": {
        "minimum_size": 4,
        "observed_widths": [
          4
        ],
        "accessed_offsets": [
          0
        ],
        "reads": 1,
        "writes": 0,
        "provisional_shape": {
          "kind": "scalar_candidate",
          "width": 4
        }
      }
    },
    {
      "address": "0x4200",
      "name": "g_array",
      "arch": "thumb",
      "status": "inferred",
      "observations": [
        {
          "arch": "thumb",
          "pc": "0x4008",
          "conditional": false,
          "kind": "write",
          "width": 2,
          "offset": 0,
          "functions": [],
          "provenance_paths": [
            []
          ]
        },
        {
          "arch": "thumb",
          "pc": "0x4010",
          "conditional": true,
          "kind": "write",
          "width": 2,
          "offset": 4,
          "functions": [],
          "provenance_paths": [
            []
          ]
        }
      ],
      "conflicts": [],
      "summary": {
        "minimum_size": 6,
        "observed_widths": [
          2
        ],
        "accessed_offsets": [
          0,
          4
        ],
        "reads": 0,
        "writes": 2,
        "provisional_shape": {
          "kind": "array_candidate",
          "element_width": 2,
          "minimum_elements": 3
        }
      }
    },
    {
      "address": "0x4300",
      "name": "g_unknown",
      "arch": "mixed",
      "status": "inferred",
      "observations": [
        {
          "arch": "arm",
          "pc": "0x4020",
          "conditional": false,
          "kind": "read_write",
          "width": 1,
          "offset": 1,
          "functions": [],
          "provenance_paths": [
            []
          ]
        }
      ],
      "conflicts": [],
      "summary": {
        "minimum_size": 2,
        "observed_widths": [
          1
        ],
        "accessed_offsets": [
          1
        ],
        "reads": 1,
        "writes": 1,
        "provisional_shape": {
          "kind": "unknown"
        }
      }
    },
    {
      "address": "0x4400",
      "name": "g_none",
      "arch": "arm",
      "status": "no_evidence",
      "observations": [],
      "conflicts": [],
      "summary": null
    },
    {
      "address": "0x4500",
      "name": "g_conflict",
      "arch": "thumb",
      "status": "conflicting",
      "observations": [],
      "conflicts": [
        {
          "arch": "thumb",
          "pc": "0x4030",
          "alternatives": [
            {
              "target_address": "0x4500",
              "conditional": false,
              "kind": "read",
              "width": 4,
              "offset": 0,
              "functions": [
                {
                  "entry": "0x4030",
                  "name": "thumb_4030"
                }
              ],
              "provenance_paths": [
                [
                  "0x4030",
                  "0x4032"
                ]
              ]
            },
            {
              "target_address": "0x4500",
              "conditional": false,
              "kind": "write",
              "width": 4,
              "offset": 0,
              "functions": [],
              "provenance_paths": [
                []
              ]
            }
          ]
        }
      ],
      "summary": null
    }
  ]
}"#;

    #[test]
    fn v4_wire_bytes_are_exact() {
        let bytes = serialize(&golden_file()).unwrap();
        assert_eq!(bytes, V4_WIRE_GOLDEN.as_bytes());
        assert!(!bytes.ends_with(b"\n"));
    }

    #[test]
    fn normalized_hashmap_insertion_order_is_byte_identical() {
        fn contexts(order: [(&str, &str); 2]) -> Vec<FunctionContextWire> {
            let mut map = HashMap::new();
            for (entry, name) in order {
                map.insert(entry.to_owned(), name.to_owned());
            }
            let mut keys: Vec<_> = map.into_iter().collect();
            keys.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
            keys.into_iter()
                .map(|(entry, name)| FunctionContextWire { entry, name })
                .collect()
        }

        let mut first = golden_file();
        first.globals[0].observations[0].functions =
            contexts([("0x4004", "later"), ("0x4000", "earlier")]);
        let mut second = golden_file();
        second.globals[0].observations[0].functions =
            contexts([("0x4000", "earlier"), ("0x4004", "later")]);
        assert_eq!(serialize(&first).unwrap(), serialize(&second).unwrap());
    }

    #[test]
    fn write_atomic_preserves_previous_file_when_commit_fails() {
        let root =
            std::env::temp_dir().join(format!("pme_global_shapes_atomic_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let path = root.join("global_shapes.json");
        let previous = b"previous sidecar bytes";
        fs::write(&path, previous).unwrap();
        let error = write_atomic_with_before_commit(&path, b"replacement", || {
            Err(Error::Serialize(
                "injected failure immediately before commit".into(),
            ))
        })
        .unwrap_err();
        assert!(matches!(
            error,
            Error::Serialize(ref reason)
                if reason == "injected failure immediately before commit"
        ));
        assert_eq!(fs::read(&path).unwrap(), previous);
        write_atomic(&path, b"replacement").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"replacement");
    }
}
