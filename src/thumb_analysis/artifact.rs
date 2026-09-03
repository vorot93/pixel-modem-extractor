//! Shared Thumb sidecar parsing, provenance validation, bounded fragment
//! assembly, terminal scanning, and atomic function-local mutation.

use super::identity::{IdentityMode, producer_identity_error};
use super::{ProducerIdentity, ThumbAnalysisSummary, ThumbProducer};
use crate::analysis_tool::AnalysisTool;
use crate::error::{Error, Result};
use crate::execution_ranges::{
    DecodeExtent, ExecutionBudget, ExecutionIdentity, ExecutionProjection, FunctionOwner,
    OwnedExecutionIdentity, TaggedExecutionRecord, ValidatedInventory, invalid,
    legacy_non_execution_projection, validate_inventory_record, validate_legacy_execution,
    validate_projection_shape,
};
use crate::runtime_image::RuntimeImage;
use crate::trusted_fs::{TrustedAtomicFile, TrustedDirectory};
use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fmt;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub(crate) const THUMB_V1_FORMAT: &str = "pixel-modem-extractor-thumb-functions-v1";
pub(crate) const THUMB_V2_FORMAT: &str = "pixel-modem-extractor-thumb-functions-v2";
pub(crate) const THUMB_V3_FORMAT: &str = "pixel-modem-extractor-thumb-functions-v3";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ThumbFormat {
    V1,
    V2,
    V3,
}

impl ThumbFormat {
    fn parse(value: &str) -> Option<Self> {
        match value {
            THUMB_V1_FORMAT => Some(Self::V1),
            THUMB_V2_FORMAT => Some(Self::V2),
            THUMB_V3_FORMAT => Some(Self::V3),
            _ => None,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::V1 => THUMB_V1_FORMAT,
            Self::V2 => THUMB_V2_FORMAT,
            Self::V3 => THUMB_V3_FORMAT,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ThumbTerminalMetadata {
    pub format: ThumbFormat,
    pub producers: Vec<ProducerIdentity>,
    pub regions: Vec<(u32, u32)>,
    pub summary: ThumbAnalysisSummary,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValidatedThumbInventory {
    pub inventory: ValidatedInventory,
    pub metadata: ThumbTerminalMetadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum AttemptStatus {
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CaptureRecord {
    pub path: String,
    pub bytes: u64,
    pub blake3: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct AttemptRecord {
    pub producer: ThumbProducer,
    pub status: AttemptStatus,
    pub stdout: Option<CaptureRecord>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FunctionRunRecord {
    pub producer: ThumbProducer,
    pub first_function: usize,
    pub function_count: usize,
    pub substantial: usize,
    pub accepted: usize,
    pub quarantined: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct RegionRecord {
    #[serde(serialize_with = "serialize_hex_u32")]
    pub start: u32,
    #[serde(serialize_with = "serialize_hex_u32")]
    pub end: u32,
    pub attempts: Vec<AttemptRecord>,
    pub function_runs: Vec<FunctionRunRecord>,
}

#[derive(Debug)]
struct ThumbDocument {
    producers: Vec<ProducerIdentity>,
    regions: Vec<RegionRecord>,
    functions: Vec<Value>,
}

#[derive(Debug)]
pub(crate) struct ParsedThumbArtifact {
    format: ThumbFormat,
    document: ThumbDocument,
    owners: Vec<FunctionOwner>,
    executions: Vec<Option<ExecutionIdentity>>,
    original_functions: Vec<Value>,
    source_blake3: String,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct OwnedFunctionRef<'a> {
    pub owner: FunctionOwner,
    pub execution: Option<&'a ExecutionIdentity>,
    pub value: &'a Value,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ThumbDecodeRange {
    pub isa: String,
    pub start: String,
    pub end: String,
    #[serde(default)]
    pub blake3: Option<String>,
}

/// Typed function payload used by streaming consumers. Unlike the strict v3
/// wire type, this accepts legacy enrichment fields and ignores unknown legacy
/// fields while avoiding a document-sized `serde_json::Value` tree.
///
/// Only `name` and `entry` are required, because retained v1/v2 artifacts do
/// not carry the v3 semantic contract and legacy symbolication defaulted the
/// rest. V3 strictness is unaffected: v3 records are deserialized through
/// `FunctionWire`, which requires the complete producer field set, and only
/// then converted into this type.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ThumbFunctionRecord {
    pub name: String,
    #[serde(default)]
    pub original_name: Option<String>,
    pub entry: String,
    #[serde(default)]
    pub end: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub body_kind: String,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub data_refs: Vec<String>,
    #[serde(default)]
    pub decode_ranges: Vec<ThumbDecodeRange>,
}

#[derive(Debug)]
pub(crate) struct OwnedThumbFunction {
    pub owner: FunctionOwner,
    pub execution: Option<ExecutionIdentity>,
    pub function: ThumbFunctionRecord,
}

impl ParsedThumbArtifact {
    pub fn functions(&self) -> impl ExactSizeIterator<Item = OwnedFunctionRef<'_>> {
        self.document
            .functions
            .iter()
            .zip(self.owners.iter().copied())
            .zip(self.executions.iter())
            .map(move |((value, owner), execution)| OwnedFunctionRef {
                owner,
                execution: execution.as_ref(),
                value,
            })
    }

    pub fn function_values(&self) -> &[Value] {
        &self.document.functions
    }

    pub fn function_values_mut(&mut self) -> &mut [Value] {
        &mut self.document.functions
    }

    pub fn source_blake3(&self) -> &str {
        &self.source_blake3
    }

    pub fn validated_v3_run_totals(&self) -> Option<(usize, usize, usize)> {
        (self.format == ThumbFormat::V3).then(|| {
            self.document
                .regions
                .iter()
                .flat_map(|region| &region.function_runs)
                .fold((0, 0, 0), |totals, run| {
                    (
                        totals.0 + run.substantial,
                        totals.1 + run.accepted,
                        totals.2 + run.quarantined,
                    )
                })
        })
    }

    pub fn write_atomic(&self, path: &Path) -> Result<()> {
        if self.document.functions == self.original_functions {
            return Ok(());
        }
        if self.format != ThumbFormat::V3 {
            return Err(invalid_artifact(
                "legacy Thumb artifacts are read-only replay inputs",
            ));
        }
        self.validate_v3_mutation()?;

        let mut file = atomic_write_file::AtomicWriteFile::open(path)?;
        write_v3_values_into(
            &mut file,
            &self.document.producers,
            &self.document.regions,
            &self.document.functions,
        )?;
        file.commit()?;
        Ok(())
    }

    fn validate_v3_mutation(&self) -> Result<()> {
        if self.original_functions.len() != self.document.functions.len() {
            return Err(invalid_artifact(
                "v3 function count changed during mutation",
            ));
        }
        const IMMUTABLE_FIELDS: [&str; 8] = [
            "entry",
            "end",
            "size",
            "body_kind",
            "body",
            "data_refs",
            "decode_ranges",
            "decode_range_errors",
        ];
        for (index, (original, current)) in self
            .original_functions
            .iter()
            .zip(&self.document.functions)
            .enumerate()
        {
            validate_v3_function_mutation(original, current, index, &IMMUTABLE_FIELDS)?;
        }
        let owners = validate_v3_shape(
            &self.document.producers,
            &self.document.regions,
            &self.document.functions,
        )?;
        if owners != self.owners {
            return Err(invalid_artifact(
                "v3 function ownership changed during mutation",
            ));
        }
        Ok(())
    }
}

fn validate_v3_function_mutation(
    original: &Value,
    current: &Value,
    index: usize,
    immutable_fields: &[&str],
) -> Result<()> {
    let original = original.as_object().ok_or_else(|| {
        invalid_artifact(format!("original v3 function {index} is not an object"))
    })?;
    let current_object = current
        .as_object()
        .ok_or_else(|| invalid_artifact(format!("mutated v3 function {index} is not an object")))?;
    for field in immutable_fields {
        if current_object.get(*field) != original.get(*field) {
            return Err(invalid_artifact(format!(
                "v3 function {index} producer field {field:?} changed during mutation"
            )));
        }
    }
    for field in ["original_name", "annotations", "body_c"] {
        if original.contains_key(field) && !current_object.contains_key(field) {
            return Err(invalid_artifact(format!(
                "v3 function {index} enrichment field {field:?} was removed"
            )));
        }
    }
    validate_function_value(current, index)?;
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProducerWire {
    id: ThumbProducer,
    executable: String,
    version: String,
    command: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttemptWire {
    producer: ThumbProducer,
    status: AttemptStatus,
    stdout: RequiredNullable<CaptureRecord>,
    error: RequiredNullable<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegionWire {
    start: String,
    end: String,
    attempts: Vec<AttemptWire>,
    function_runs: Vec<FunctionRunRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecodeRangeWire {
    isa: String,
    start: String,
    end: String,
    blake3: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecodeRangeErrorWire {
    address: String,
    end: RequiredNullable<String>,
    kind: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(transparent)]
struct RequiredNullable<T>(Option<T>);

#[derive(Debug)]
struct OptionalField<T>(Option<T>);

impl<T> OptionalField<T> {
    fn is_missing(&self) -> bool {
        self.0.is_none()
    }
}

impl<T> Default for OptionalField<T> {
    fn default() -> Self {
        Self(None)
    }
}

impl<'de, T> Deserialize<'de> for OptionalField<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        T::deserialize(deserializer).map(|value| Self(Some(value)))
    }
}

impl<T> Serialize for OptionalField<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match &self.0 {
            Some(value) => value.serialize(serializer),
            None => serializer.serialize_unit(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FunctionWire {
    name: String,
    entry: String,
    end: String,
    size: u64,
    body_kind: String,
    body: String,
    data_refs: Vec<String>,
    decode_ranges: Vec<DecodeRangeWire>,
    decode_range_errors: Vec<DecodeRangeErrorWire>,
    #[serde(default, skip_serializing_if = "OptionalField::is_missing")]
    original_name: OptionalField<String>,
    #[serde(default, skip_serializing_if = "OptionalField::is_missing")]
    annotations: OptionalField<Vec<String>>,
    #[serde(default, skip_serializing_if = "OptionalField::is_missing")]
    body_c: OptionalField<String>,
}

impl From<FunctionWire> for ThumbFunctionRecord {
    fn from(function: FunctionWire) -> Self {
        Self {
            name: function.name,
            original_name: function.original_name.0,
            entry: function.entry,
            end: function.end,
            size: function.size,
            body_kind: function.body_kind,
            body: function.body,
            data_refs: function.data_refs,
            decode_ranges: function
                .decode_ranges
                .into_iter()
                .map(|range| ThumbDecodeRange {
                    isa: range.isa,
                    start: range.start,
                    end: range.end,
                    blake3: Some(range.blake3),
                })
                .collect(),
        }
    }
}

enum WireDocument {
    Legacy {
        format: ThumbFormat,
        functions: Vec<Value>,
    },
    V3 {
        producers: Vec<ProducerWire>,
        regions: Vec<RegionWire>,
        functions: Vec<Value>,
    },
}

struct WireDocumentVisitor;

impl<'de> Visitor<'de> for WireDocumentVisitor {
    type Value = WireDocument;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a Thumb artifact object")
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        expect_key(&mut map, "format")?;
        let raw_format = map.next_value::<String>()?;
        let format = ThumbFormat::parse(&raw_format)
            .ok_or_else(|| de::Error::custom("unsupported Thumb artifact format"))?;
        match format {
            ThumbFormat::V1 | ThumbFormat::V2 => {
                expect_key(&mut map, "functions")?;
                let functions = map.next_value::<Vec<Value>>()?;
                expect_end(&mut map)?;
                Ok(WireDocument::Legacy { format, functions })
            }
            ThumbFormat::V3 => {
                expect_key(&mut map, "producers")?;
                let producers = map.next_value::<Vec<ProducerWire>>()?;
                expect_key(&mut map, "regions")?;
                let regions = map.next_value::<Vec<RegionWire>>()?;
                expect_key(&mut map, "functions")?;
                let functions = map.next_value::<Vec<FunctionWire>>()?;
                expect_end(&mut map)?;
                let functions = functions
                    .into_iter()
                    .map(serde_json::to_value)
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(de::Error::custom)?;
                Ok(WireDocument::V3 {
                    producers,
                    regions,
                    functions,
                })
            }
        }
    }
}

impl<'de> Deserialize<'de> for WireDocument {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(WireDocumentVisitor)
    }
}

fn expect_key<'de, A>(map: &mut A, expected: &str) -> std::result::Result<(), A::Error>
where
    A: MapAccess<'de>,
{
    match map.next_key::<String>()? {
        Some(key) if key == expected => Ok(()),
        Some(key) => Err(de::Error::custom(format!(
            "expected top-level field {expected:?}, found {key:?}"
        ))),
        None => Err(de::Error::missing_field("required top-level field")),
    }
}

fn expect_end<'de, A>(map: &mut A) -> std::result::Result<(), A::Error>
where
    A: MapAccess<'de>,
{
    if let Some(key) = map.next_key::<String>()? {
        return Err(de::Error::custom(format!(
            "unexpected top-level field {key:?}"
        )));
    }
    Ok(())
}

fn serialize_hex_u32<S>(value: &u32, serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&format!("0x{value:x}"))
}

fn canonical_hex_u32(value: &str, label: &str) -> Result<u32> {
    let parsed = value
        .strip_prefix("0x")
        .filter(|digits| !digits.is_empty())
        .and_then(|digits| u32::from_str_radix(digits, 16).ok())
        .filter(|parsed| format!("0x{parsed:x}") == value)
        .ok_or_else(|| invalid_artifact(format!("{label} must be canonical lowercase u32 hex")))?;
    Ok(parsed)
}

fn canonical_hex_u64(value: &str, label: &str) -> Result<u64> {
    let parsed = value
        .strip_prefix("0x")
        .filter(|digits| !digits.is_empty())
        .and_then(|digits| u64::from_str_radix(digits, 16).ok())
        .filter(|parsed| format!("0x{parsed:x}") == value)
        .ok_or_else(|| invalid_artifact(format!("{label} must be canonical lowercase hex")))?;
    Ok(parsed)
}

fn canonical_blake3(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid_artifact(format!(
            "{label} must be lowercase BLAKE3 hex"
        )));
    }
    Ok(())
}

fn invalid_artifact(message: impl Into<String>) -> Error {
    Error::Serialize(format!("invalid Thumb artifact: {}", message.into()))
}

fn convert_producers(wires: Vec<ProducerWire>) -> Result<Vec<ProducerIdentity>> {
    if wires.is_empty() {
        return Err(invalid_artifact("v3 producers array must not be empty"));
    }
    if wires.len() > 2 {
        return Err(invalid_artifact("v3 producers contain an invalid producer"));
    }
    let expected = [ThumbProducer::Radare2, ThumbProducer::Rizin];
    let mut producers = Vec::with_capacity(wires.len());
    for (index, wire) in wires.into_iter().enumerate() {
        if wire.id != expected[index] {
            return Err(invalid_artifact(
                "v3 producers must be unique and ordered radare2 then rizin",
            ));
        }
        if wire.command != wire.id.command() {
            return Err(invalid_artifact(format!(
                "{} producer command does not match the v3 schema",
                wire.id.as_str()
            )));
        }
        // Field-level rules live in the shared producer-identity validator,
        // which `validate_v3_metadata` applies to every parsed document.
        producers.push(ProducerIdentity {
            producer: wire.id,
            executable: PathBuf::from(&wire.executable),
            version: wire.version,
            command: wire.id.command(),
        });
    }
    Ok(producers)
}

fn convert_attempt(wire: AttemptWire) -> Result<AttemptRecord> {
    let stdout = wire.stdout.0;
    let error = wire.error.0;
    match wire.status {
        AttemptStatus::Succeeded if stdout.is_none() => {
            return Err(invalid_artifact(
                "successful attempt must retain stdout metadata",
            ));
        }
        AttemptStatus::Succeeded if error.is_some() => {
            return Err(invalid_artifact("successful attempt error must be null"));
        }
        AttemptStatus::Failed if error.as_deref().is_none_or(str::is_empty) => {
            return Err(invalid_artifact(
                "failed attempt must contain a non-empty error",
            ));
        }
        _ => {}
    }
    Ok(AttemptRecord {
        producer: wire.producer,
        status: wire.status,
        stdout,
        error,
    })
}

fn convert_regions(wires: Vec<RegionWire>) -> Result<Vec<RegionRecord>> {
    if wires.is_empty() {
        return Err(invalid_artifact("v3 regions array must not be empty"));
    }
    wires
        .into_iter()
        .enumerate()
        .map(|(index, wire)| {
            let start = canonical_hex_u32(&wire.start, &format!("region {index} start"))?;
            let end = canonical_hex_u32(&wire.end, &format!("region {index} end"))?;
            let attempts = wire
                .attempts
                .into_iter()
                .map(convert_attempt)
                .collect::<Result<Vec<_>>>()?;
            Ok(RegionRecord {
                start,
                end,
                attempts,
                function_runs: wire.function_runs,
            })
        })
        .collect()
}

/// V3 regions are the analyzer's request ledger, so they must lie inside the
/// authenticated byte-backed runtime view used for the records.
fn validate_v3_regions_in_runtime(
    regions: &[RegionRecord],
    runtime: &RuntimeImage<'_>,
) -> Result<()> {
    for (index, region) in regions.iter().enumerate() {
        let size = region
            .end
            .checked_sub(region.start)
            .ok_or_else(|| invalid_artifact(format!("region {index} range wraps")))?;
        if !runtime
            .is_byte_backed(region.start, size)
            .map_err(|error| {
                invalid_artifact(format!("region {index} is outside runtime image: {error}"))
            })?
        {
            return Err(invalid_artifact(format!(
                "region {index} crosses virtual zero-fill storage"
            )));
        }
    }
    Ok(())
}

fn validate_function_value(function: &Value, index: usize) -> Result<(bool, bool, bool)> {
    let wire: FunctionWire = serde_json::from_value(function.clone())
        .map_err(|error| invalid_artifact(format!("invalid v3 function {index}: {error}")))?;
    let entry = canonical_hex_u32(&wire.entry, &format!("function {index} entry"))?;
    let end = canonical_hex_u32(&wire.end, &format!("function {index} end"))?;
    if entry >= end {
        return Err(invalid_artifact(format!(
            "function {index} entry must precede end"
        )));
    }
    if wire.size == 0 {
        return Err(invalid_artifact(format!(
            "function {index} size must be positive"
        )));
    }
    if wire.body_kind != "thumb_disassembly" {
        return Err(invalid_artifact(format!(
            "function {index} body_kind must be thumb_disassembly"
        )));
    }
    let mut previous_reference = None;
    for (reference_index, reference) in wire.data_refs.iter().enumerate() {
        let reference = canonical_hex_u64(
            reference,
            &format!("function {index} data_refs[{reference_index}]"),
        )?;
        if previous_reference.is_some_and(|previous| reference <= previous) {
            return Err(invalid_artifact(format!(
                "function {index} data_refs are not sorted and deduplicated"
            )));
        }
        previous_reference = Some(reference);
    }
    for (range_index, range) in wire.decode_ranges.iter().enumerate() {
        canonical_hex_u32(
            &range.start,
            &format!("function {index} decode_ranges[{range_index}].start"),
        )?;
        canonical_hex_u32(
            &range.end,
            &format!("function {index} decode_ranges[{range_index}].end"),
        )?;
        if range.isa != "thumb" {
            return Err(invalid_artifact(format!(
                "function {index} decode range ISA must be thumb"
            )));
        }
        canonical_blake3(
            &range.blake3,
            &format!("function {index} decode_ranges[{range_index}].blake3"),
        )?;
    }
    for (error_index, error) in wire.decode_range_errors.iter().enumerate() {
        canonical_hex_u32(
            &error.address,
            &format!("function {index} decode_range_errors[{error_index}].address"),
        )?;
        if let Some(end) = error.end.0.as_deref() {
            canonical_hex_u32(
                end,
                &format!("function {index} decode_range_errors[{error_index}].end"),
            )?;
        }
    }
    let accepted = validate_projection_shape(function, entry).map_err(|error| {
        invalid_artifact(format!("invalid v3 function {index} projection: {error}"))
    })?;
    if accepted {
        for (range_index, range) in wire.decode_ranges.iter().enumerate() {
            let range_start = canonical_hex_u32(
                &range.start,
                &format!("function {index} decode_ranges[{range_index}].start"),
            )?;
            let range_end = canonical_hex_u32(
                &range.end,
                &format!("function {index} decode_ranges[{range_index}].end"),
            )?;
            if range_end > end {
                return Err(invalid_artifact(format!(
                    "function {index} decode range {range_index} exceeds function end"
                )));
            }
            let length = range_end.checked_sub(range_start);
            if !range_start.is_multiple_of(2)
                || length.is_none_or(|length| length == 0 || !length.is_multiple_of(2))
            {
                return Err(invalid_artifact(format!(
                    "function {index} decode range {range_index} is not canonical Thumb coverage"
                )));
            }
        }
    }
    Ok((wire.size >= 32, accepted, !accepted))
}

fn authenticate_function_value(
    function: &Value,
    index: usize,
    owner: FunctionOwner,
    runtime: &RuntimeImage<'_>,
    budget: &mut ExecutionBudget,
) -> Result<(TaggedExecutionRecord, Option<ExecutionIdentity>)> {
    let (tagged, _, identity) = validate_inventory_record(function, owner, runtime, budget)
        .map_err(|error| {
            invalid_artifact(format!("invalid v3 function {index} execution: {error}"))
        })?;
    Ok((tagged, identity))
}

#[derive(Debug, Clone)]
struct V3Layout {
    runs: Vec<V3RunDescriptor>,
    function_count: usize,
}

#[derive(Debug, Clone)]
struct V3RunDescriptor {
    record: FunctionRunRecord,
    owner: FunctionOwner,
}

impl std::ops::Deref for V3RunDescriptor {
    type Target = FunctionRunRecord;

    fn deref(&self) -> &Self::Target {
        &self.record
    }
}

#[derive(Default)]
struct V3RunCursor {
    run_index: usize,
    #[cfg(test)]
    inspected_runs: usize,
}

impl V3RunCursor {
    fn owner_index(&mut self, runs: &[V3RunDescriptor], function_index: usize) -> Option<usize> {
        while let Some(run) = runs.get(self.run_index) {
            #[cfg(test)]
            {
                self.inspected_runs += 1;
            }
            let end = run.first_function.checked_add(run.function_count)?;
            if function_index < run.first_function {
                return None;
            }
            if function_index < end {
                return Some(self.run_index);
            }
            self.run_index += 1;
        }
        None
    }

    #[cfg(test)]
    fn inspected_runs(&self) -> usize {
        self.inspected_runs
    }
}

fn validate_v3_metadata(
    producers: &[ProducerIdentity],
    regions: &[RegionRecord],
) -> Result<V3Layout> {
    if producers.is_empty() || producers.len() > 2 {
        return Err(invalid_artifact("v3 producers array must not be empty"));
    }
    let expected_producers = [ThumbProducer::Radare2, ThumbProducer::Rizin];
    for (index, producer) in producers.iter().enumerate() {
        if producer.producer != expected_producers[index] {
            return Err(invalid_artifact(
                "v3 producers must be unique and ordered radare2 then rizin",
            ));
        }
        // A retained artifact records the host that produced it, so only the
        // lexical spelling of its executable can be checked here.
        if let Some(reason) =
            producer_identity_error(producer, expected_producers[index], IdentityMode::Artifact)
        {
            return Err(invalid_artifact(reason));
        }
    }
    if regions.is_empty() {
        return Err(invalid_artifact("v3 regions array must not be empty"));
    }
    let declared: BTreeSet<_> = producers.iter().map(|producer| producer.producer).collect();
    let mut attempted = BTreeSet::new();
    let mut runs = Vec::new();
    let mut next_function = 0usize;
    let mut previous_end = None;

    for (region_index, region) in regions.iter().enumerate() {
        if region.start >= region.end {
            return Err(invalid_artifact(format!(
                "region {region_index} start must precede end"
            )));
        }
        if previous_end.is_some_and(|end| region.start < end) {
            return Err(invalid_artifact(
                "v3 regions must be sorted and non-overlapping",
            ));
        }
        previous_end = Some(region.end);
        if region.attempts.is_empty() || region.attempts.len() > 2 {
            return Err(invalid_artifact(format!(
                "region {region_index} has an invalid attempt sequence"
            )));
        }
        for (attempt_index, attempt) in region.attempts.iter().enumerate() {
            let expected = if attempt_index == 0 {
                ThumbProducer::Radare2
            } else {
                ThumbProducer::Rizin
            };
            if attempt.producer != expected || !declared.contains(&attempt.producer) {
                return Err(invalid_artifact(format!(
                    "region {region_index} has an invalid attempt sequence"
                )));
            }
            attempted.insert(attempt.producer);
            match attempt.status {
                AttemptStatus::Succeeded if attempt.stdout.is_none() || attempt.error.is_some() => {
                    return Err(invalid_artifact(format!(
                        "region {region_index} successful attempt has invalid stdout or error"
                    )));
                }
                AttemptStatus::Failed if attempt.error.as_deref().is_none_or(str::is_empty) => {
                    return Err(invalid_artifact(format!(
                        "region {region_index} failed attempt lacks a non-empty error"
                    )));
                }
                _ => {}
            }
            if let Some(capture) = &attempt.stdout {
                let expected_path = format!(
                    "thumb/{:08x}.{}.stdout",
                    region.start,
                    attempt.producer.as_str()
                );
                if capture.path != expected_path {
                    return Err(invalid_artifact(format!(
                        "region {region_index} capture path does not match its attempt"
                    )));
                }
                if capture.blake3.len() != 64
                    || !capture
                        .blake3
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err(invalid_artifact(format!(
                        "region {region_index} capture digest is not lowercase BLAKE3 hex"
                    )));
                }
            }
        }

        let successes: Vec<_> = region
            .attempts
            .iter()
            .filter(|attempt| attempt.status == AttemptStatus::Succeeded)
            .map(|attempt| attempt.producer)
            .collect();
        if successes.len() != region.function_runs.len() {
            return Err(invalid_artifact(format!(
                "region {region_index} successful attempts and function runs differ"
            )));
        }
        for (run_index, (run, successful_producer)) in
            region.function_runs.iter().zip(successes).enumerate()
        {
            if run.producer != successful_producer {
                return Err(invalid_artifact(format!(
                    "region {region_index} run {run_index} does not own its successful attempt"
                )));
            }
            if run.first_function != next_function || run.function_count == 0 {
                return Err(invalid_artifact(format!(
                    "region {region_index} run {run_index} is not contiguous and non-empty"
                )));
            }
            if run.accepted.checked_add(run.quarantined) != Some(run.function_count) {
                return Err(invalid_artifact(format!(
                    "region {region_index} run {run_index} counts are not conserving"
                )));
            }
            next_function = next_function
                .checked_add(run.function_count)
                .ok_or_else(|| invalid_artifact("function run index overflow"))?;
            runs.push(V3RunDescriptor {
                record: run.clone(),
                owner: FunctionOwner::Run {
                    producer: AnalysisTool::from(run.producer),
                    region_index,
                    run_index,
                },
            });
        }
    }
    if attempted != declared {
        return Err(invalid_artifact(
            "v3 producers must contain exactly the attempted producers",
        ));
    }
    if runs.is_empty() {
        return Err(invalid_artifact(
            "v3 artifact must contain at least one successful run",
        ));
    }
    Ok(V3Layout {
        runs,
        function_count: next_function,
    })
}

fn validate_v3(
    producers: &[ProducerIdentity],
    regions: &[RegionRecord],
    functions: &[Value],
    runtime: &RuntimeImage<'_>,
) -> Result<(Vec<FunctionOwner>, Vec<Option<ExecutionIdentity>>)> {
    let owners = validate_v3_shape(producers, regions, functions)?;
    validate_v3_regions_in_runtime(regions, runtime)?;
    let mut budget = ExecutionBudget::default();
    let mut executions = Vec::new();
    executions
        .try_reserve_exact(functions.len())
        .map_err(|_| invalid_artifact("v3 execution allocation failed"))?;
    for (index, (function, owner)) in functions.iter().zip(&owners).enumerate() {
        let (_, identity) =
            authenticate_function_value(function, index, *owner, runtime, &mut budget)?;
        executions.push(identity);
    }
    Ok((owners, executions))
}

fn validate_v3_shape(
    producers: &[ProducerIdentity],
    regions: &[RegionRecord],
    functions: &[Value],
) -> Result<Vec<FunctionOwner>> {
    if functions.is_empty() {
        return Err(invalid_artifact("v3 functions array must not be empty"));
    }
    let layout = validate_v3_metadata(producers, regions)?;
    if layout.function_count != functions.len() {
        return Err(invalid_artifact(
            "every v3 function must have exactly one run owner",
        ));
    }
    let mut owners = Vec::with_capacity(functions.len());
    for (run_index, run) in layout.runs.iter().enumerate() {
        let end = run
            .first_function
            .checked_add(run.function_count)
            .ok_or_else(|| invalid_artifact("function run index overflow"))?;
        let slice = &functions[run.first_function..end];
        let mut substantial = 0usize;
        let mut accepted = 0usize;
        let mut quarantined = 0usize;
        for (offset, function) in slice.iter().enumerate() {
            let (is_substantial, is_accepted, is_quarantined) =
                validate_function_value(function, run.first_function + offset)?;
            substantial += usize::from(is_substantial);
            accepted += usize::from(is_accepted);
            quarantined += usize::from(is_quarantined);
            owners.push(run.owner);
        }
        if (run.substantial, run.accepted, run.quarantined) != (substantial, accepted, quarantined)
        {
            return Err(invalid_artifact(format!(
                "v3 run {run_index} stored counts do not match its functions"
            )));
        }
    }
    Ok(owners)
}

fn legacy_execution(
    function: &Value,
    index: usize,
    runtime: &RuntimeImage<'_>,
    budget: &mut ExecutionBudget,
) -> Result<Option<ExecutionIdentity>> {
    let object = function
        .as_object()
        .ok_or_else(|| invalid_artifact(format!("legacy function {index} must be an object")))?;
    let entry = object.get("entry").and_then(Value::as_str).ok_or_else(|| {
        invalid_artifact(format!("legacy function {index} entry must be a string"))
    })?;
    let entry = canonical_hex_u32(entry, &format!("legacy function {index} entry"))?;
    let decode_ranges = match object.get("decode_ranges") {
        Some(Value::Array(ranges)) => ranges.as_slice(),
        Some(_) => {
            return Err(invalid_artifact(format!(
                "legacy function {index} decode_ranges must be an array"
            )));
        }
        None => &[],
    };
    let mut extents = Vec::new();
    extents
        .try_reserve_exact(decode_ranges.len())
        .map_err(|_| invalid_artifact("legacy decode-range allocation failed"))?;
    for (range_index, range) in decode_ranges.iter().enumerate() {
        let range: ThumbDecodeRange = serde_json::from_value(range.clone()).map_err(|error| {
            invalid_artifact(format!(
                "invalid legacy function {index} decode range {range_index}: {error}"
            ))
        })?;
        if range.blake3.is_some() {
            return Err(invalid_artifact(format!(
                "legacy function {index} decode range {range_index} contains a fresh hash"
            )));
        }
        let isa = match range.isa.as_str() {
            "arm" => crate::execution_ranges::DecodeIsa::Arm,
            "thumb" => crate::execution_ranges::DecodeIsa::Thumb,
            _ => return Err(invalid_artifact("legacy decode range has unknown ISA")),
        };
        extents.push(DecodeExtent {
            isa,
            start: canonical_hex_u32(
                &range.start,
                &format!("legacy function {index} decode range {range_index} start"),
            )?,
            end: canonical_hex_u32(
                &range.end,
                &format!("legacy function {index} decode range {range_index} end"),
            )?,
        });
    }
    validate_legacy_execution(entry, extents, runtime, budget)
        .map_err(|error| invalid_artifact(format!("legacy function {index} execution: {error}")))
}

/// Parse a Thumb sidecar and authenticate every explicit execution range
/// against the supplied raw-plus-scatter runtime view.
pub(crate) fn parse_thumb_artifact(
    bytes: &[u8],
    runtime: &RuntimeImage<'_>,
) -> Result<ParsedThumbArtifact> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let wire = WireDocument::deserialize(&mut deserializer)
        .and_then(|wire| deserializer.end().map(|()| wire))
        .map_err(|error| Error::Serialize(format!("parse Thumb artifact: {error}")))?;
    let (format, document, owners, executions) = match wire {
        WireDocument::Legacy { format, functions } => {
            let owner = FunctionOwner::Legacy {
                producer: AnalysisTool::Radare2,
            };
            let owners = vec![owner; functions.len()];
            let mut budget = ExecutionBudget::default();
            let executions = functions
                .iter()
                .enumerate()
                .map(|(index, function)| legacy_execution(function, index, runtime, &mut budget))
                .collect::<Result<Vec<_>>>()?;
            (
                format,
                ThumbDocument {
                    producers: Vec::new(),
                    regions: Vec::new(),
                    functions,
                },
                owners,
                executions,
            )
        }
        WireDocument::V3 {
            producers,
            regions,
            functions,
        } => {
            let producers = convert_producers(producers)?;
            let regions = convert_regions(regions)?;
            let (owners, executions) = validate_v3(&producers, &regions, &functions, runtime)?;
            (
                ThumbFormat::V3,
                ThumbDocument {
                    producers,
                    regions,
                    functions,
                },
                owners,
                executions,
            )
        }
    };
    let original_functions = document.functions.clone();
    Ok(ParsedThumbArtifact {
        format,
        document,
        owners,
        executions,
        original_functions,
        source_blake3: crate::manifest::blake3_bytes(bytes),
    })
}

pub(crate) fn read_thumb_artifact(
    path: &Path,
    runtime: &RuntimeImage<'_>,
) -> Result<ParsedThumbArtifact> {
    parse_thumb_artifact(&std::fs::read(path)?, runtime)
}

/// Load consumer-facing Thumb records directly from a buffered JSON reader.
/// Metadata and run ownership are validated before records are exposed, and
/// only typed records (not a document-wide `Value` tree) are retained.
pub(crate) fn read_thumb_functions_streaming(
    path: &Path,
    runtime: &RuntimeImage<'_>,
) -> Result<Vec<OwnedThumbFunction>> {
    let file = std::fs::File::open(path)?;
    read_thumb_functions_file(file, runtime, &path.display().to_string())
}

pub(crate) fn read_thumb_functions_file(
    file: std::fs::File,
    runtime: &RuntimeImage<'_>,
    context: &str,
) -> Result<Vec<OwnedThumbFunction>> {
    read_thumb_functions_reader(file, runtime, context)
}

pub(crate) fn read_thumb_functions_bytes(
    bytes: &[u8],
    runtime: &RuntimeImage<'_>,
    context: &str,
) -> Result<Vec<OwnedThumbFunction>> {
    read_thumb_functions_reader(std::io::Cursor::new(bytes), runtime, context)
}

fn read_thumb_functions_reader<R: std::io::Read>(
    reader: R,
    runtime: &RuntimeImage<'_>,
    context: &str,
) -> Result<Vec<OwnedThumbFunction>> {
    let mut deserializer = serde_json::Deserializer::from_reader(std::io::BufReader::new(reader));
    let mut scan = TypedFunctionScan::new(runtime);
    let parsed = deserializer.deserialize_map(TypedFunctionVisitor { scan: &mut scan });
    parsed
        .and_then(|()| deserializer.end())
        .map_err(|error| Error::Serialize(format!("parse {context}: {error}")))?;
    scan.finish()
}

struct TypedFunctionScan<'runtime, 'data> {
    runtime: &'runtime RuntimeImage<'data>,
    budget: ExecutionBudget,
    format: Option<ThumbFormat>,
    saw_producers: bool,
    saw_regions: bool,
    saw_functions: bool,
    layout: Option<V3Layout>,
    run_cursor: V3RunCursor,
    observed: Vec<RunCounts>,
    functions: Vec<OwnedThumbFunction>,
}

impl<'runtime, 'data> TypedFunctionScan<'runtime, 'data> {
    fn new(runtime: &'runtime RuntimeImage<'data>) -> Self {
        Self {
            runtime,
            budget: ExecutionBudget::default(),
            format: None,
            saw_producers: false,
            saw_regions: false,
            saw_functions: false,
            layout: None,
            run_cursor: V3RunCursor::default(),
            observed: Vec::new(),
            functions: Vec::new(),
        }
    }

    fn set_v3_metadata(
        &mut self,
        producers: Vec<ProducerWire>,
        regions: Vec<RegionWire>,
    ) -> Result<()> {
        let producers = convert_producers(producers)?;
        let regions = convert_regions(regions)?;
        let layout = validate_v3_metadata(&producers, &regions)?;
        validate_v3_regions_in_runtime(&regions, self.runtime)?;
        self.observed = vec![RunCounts::default(); layout.runs.len()];
        self.run_cursor = V3RunCursor::default();
        self.layout = Some(layout);
        Ok(())
    }

    fn push_legacy(&mut self, function: ThumbFunctionRecord) -> Result<()> {
        let function_index = self.functions.len();
        let value = serde_json::to_value(&function).map_err(|error| {
            invalid_artifact(format!(
                "legacy function {function_index} cannot be rendered: {error}"
            ))
        })?;
        let execution = legacy_execution(&value, function_index, self.runtime, &mut self.budget)?;
        self.functions.push(OwnedThumbFunction {
            owner: FunctionOwner::Legacy {
                producer: AnalysisTool::Radare2,
            },
            execution,
            function,
        });
        Ok(())
    }

    fn push_v3(&mut self, function: FunctionWire) -> Result<()> {
        let function_index = self.functions.len();
        let value = serde_json::to_value(&function).map_err(|error| {
            invalid_artifact(format!(
                "v3 function {function_index} cannot be rendered: {error}"
            ))
        })?;
        let (substantial, accepted, quarantined) = validate_function_value(&value, function_index)?;
        let layout = self.layout.as_ref().ok_or_else(|| {
            invalid_artifact("v3 artifact lacks validated producer and region metadata")
        })?;
        let run_index = self.run_cursor.owner_index(&layout.runs, function_index);
        let Some(run_index) = run_index else {
            return Err(invalid_artifact(
                "every v3 function must have exactly one run owner",
            ));
        };
        let run = &layout.runs[run_index];
        let (_, execution) = authenticate_function_value(
            &value,
            function_index,
            run.owner,
            self.runtime,
            &mut self.budget,
        )?;
        let observed = &mut self.observed[run_index];
        observed.substantial += usize::from(substantial);
        observed.accepted += usize::from(accepted);
        observed.quarantined += usize::from(quarantined);
        self.functions.push(OwnedThumbFunction {
            owner: run.owner,
            execution,
            function: function.into(),
        });
        Ok(())
    }

    fn finish(self) -> Result<Vec<OwnedThumbFunction>> {
        let format = self
            .format
            .ok_or_else(|| invalid_artifact("missing Thumb artifact format"))?;
        if !self.saw_functions {
            return Err(invalid_artifact("Thumb artifact lacks functions array"));
        }
        if format == ThumbFormat::V3 {
            let layout = self.layout.as_ref().ok_or_else(|| {
                invalid_artifact("v3 artifact lacks validated producer and region metadata")
            })?;
            if self.functions.len() != layout.function_count {
                return Err(invalid_artifact(
                    "every v3 function must have exactly one run owner",
                ));
            }
            for (run_index, (run, observed)) in layout.runs.iter().zip(&self.observed).enumerate() {
                if (run.substantial, run.accepted, run.quarantined)
                    != (
                        observed.substantial,
                        observed.accepted,
                        observed.quarantined,
                    )
                {
                    return Err(invalid_artifact(format!(
                        "v3 run {run_index} stored counts do not match its functions"
                    )));
                }
            }
        }
        Ok(self.functions)
    }
}

struct TypedFunctionVisitor<'scan, 'runtime, 'data> {
    scan: &'scan mut TypedFunctionScan<'runtime, 'data>,
}

impl<'de> Visitor<'de> for TypedFunctionVisitor<'_, '_, '_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a canonical Thumb artifact object")
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        let key = map
            .next_key::<String>()?
            .ok_or_else(|| de::Error::missing_field("format"))?;
        if key != "format" {
            return Err(de::Error::custom(format!(
                "expected top-level field \"format\", found {key:?}"
            )));
        }
        let raw_format = map.next_value::<String>()?;
        let format = ThumbFormat::parse(&raw_format)
            .ok_or_else(|| de::Error::custom("unsupported Thumb artifact format"))?;
        self.scan.format = Some(format);

        match format {
            ThumbFormat::V1 | ThumbFormat::V2 => {
                let key = map
                    .next_key::<String>()?
                    .ok_or_else(|| de::Error::missing_field("functions"))?;
                if key != "functions" {
                    return Err(de::Error::custom(format!(
                        "expected top-level field \"functions\", found {key:?}"
                    )));
                }
                self.scan.saw_functions = true;
                map.next_value_seed(TypedLegacyFunctions {
                    scan: &mut *self.scan,
                })?;
            }
            ThumbFormat::V3 => {
                let key = map
                    .next_key::<String>()?
                    .ok_or_else(|| de::Error::missing_field("producers"))?;
                if key != "producers" {
                    return Err(de::Error::custom(format!(
                        "expected top-level field \"producers\", found {key:?}"
                    )));
                }
                self.scan.saw_producers = true;
                let producers = map.next_value::<Vec<ProducerWire>>()?;

                let key = map
                    .next_key::<String>()?
                    .ok_or_else(|| de::Error::missing_field("regions"))?;
                if key != "regions" {
                    return Err(de::Error::custom(format!(
                        "expected top-level field \"regions\", found {key:?}"
                    )));
                }
                self.scan.saw_regions = true;
                let regions = map.next_value::<Vec<RegionWire>>()?;
                self.scan
                    .set_v3_metadata(producers, regions)
                    .map_err(de::Error::custom)?;

                let key = map
                    .next_key::<String>()?
                    .ok_or_else(|| de::Error::missing_field("functions"))?;
                if key != "functions" {
                    return Err(de::Error::custom(format!(
                        "expected top-level field \"functions\", found {key:?}"
                    )));
                }
                self.scan.saw_functions = true;
                map.next_value_seed(TypedV3Functions {
                    scan: &mut *self.scan,
                })?;
            }
        }

        if let Some(key) = map.next_key::<String>()? {
            return Err(de::Error::custom(format!(
                "unexpected top-level field {key:?}"
            )));
        }
        Ok(())
    }
}

struct TypedLegacyFunctions<'scan, 'runtime, 'data> {
    scan: &'scan mut TypedFunctionScan<'runtime, 'data>,
}

impl<'de> DeserializeSeed<'de> for TypedLegacyFunctions<'_, '_, '_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<(), D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for TypedLegacyFunctions<'_, '_, '_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a Thumb functions array")
    }

    fn visit_seq<A>(self, mut seq: A) -> std::result::Result<(), A::Error>
    where
        A: SeqAccess<'de>,
    {
        while let Some(function) = seq.next_element::<ThumbFunctionRecord>()? {
            self.scan.push_legacy(function).map_err(de::Error::custom)?;
        }
        Ok(())
    }
}

struct TypedV3Functions<'scan, 'runtime, 'data> {
    scan: &'scan mut TypedFunctionScan<'runtime, 'data>,
}

impl<'de> DeserializeSeed<'de> for TypedV3Functions<'_, '_, '_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<(), D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for TypedV3Functions<'_, '_, '_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a strict v3 Thumb functions array")
    }

    fn visit_seq<A>(self, mut seq: A) -> std::result::Result<(), A::Error>
    where
        A: SeqAccess<'de>,
    {
        while let Some(function) = seq.next_element::<FunctionWire>()? {
            self.scan.push_v3(function).map_err(de::Error::custom)?;
        }
        Ok(())
    }
}

/// Validate a terminal Thumb artifact while retaining at most one function
/// value at a time. V3 metadata is fully validated before the function stream.
pub(crate) fn validate_thumb_inventory_streaming(
    path: &Path,
    runtime: &RuntimeImage<'_>,
    expected_substantial: usize,
) -> Result<ValidatedThumbInventory> {
    validate_thumb_inventory_bytes(&std::fs::read(path)?, runtime, expected_substantial)
}

pub(crate) fn validate_thumb_inventory_bytes(
    bytes: &[u8],
    runtime: &RuntimeImage<'_>,
    expected_substantial: usize,
) -> Result<ValidatedThumbInventory> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let mut scan = ThumbScan::new(runtime);
    let parsed = deserializer.deserialize_any(ThumbInventoryVisitor { scan: &mut scan });
    match parsed.and_then(|()| deserializer.end()) {
        Ok(()) => scan.finish(expected_substantial),
        Err(error) => Err(Error::Serialize(format!(
            "parse Thumb functions inventory: {error}"
        ))),
    }
}

#[cfg(test)]
impl ParsedThumbArtifact {
    pub(crate) fn consumer_v3_fixture() -> &'static [u8] {
        br#"{
  "format": "pixel-modem-extractor-thumb-functions-v3",
  "producers": [
    {
      "id": "radare2",
      "executable": "/usr/bin/r2",
      "version": "radare2 6.1.4",
      "command": "aaa;aflj;pdfj @@f"
    },
    {
      "id": "rizin",
      "executable": "/usr/bin/rizin",
      "version": "rizin 0.8.2",
      "command": "aaa;aflj;pdfj @@F;axlj"
    }
  ],
  "regions": [
    {
      "start": "0x4000",
      "end": "0x4080",
      "attempts": [
        {
          "producer": "radare2",
          "status": "failed",
          "stdout": null,
          "error": "radare2 fixture failure"
        },
        {
          "producer": "rizin",
          "status": "succeeded",
          "stdout": {
            "path": "thumb/00004000.rizin.stdout",
            "bytes": 128,
            "blake3": "0000000000000000000000000000000000000000000000000000000000000000"
          },
          "error": null
        }
      ],
      "function_runs": [
        {
          "producer": "rizin",
          "first_function": 0,
          "function_count": 2,
          "substantial": 1,
          "accepted": 1,
          "quarantined": 1
        }
      ]
    }
  ],
  "functions": [
    {
      "body": "0x4000: movw r0, 0x4020\n0x4004: movw r1, 0x4060\n",
      "body_kind": "thumb_disassembly",
      "data_refs": [
        "0x4020",
        "0x4060",
        "0x4070"
      ],
      "decode_range_errors": [],
      "decode_ranges": [
        {
          "end": "0x4008",
          "isa": "thumb",
          "start": "0x4000",
          "blake3": "71e0a99173564931c0b8acc52d2685a8e39c64dc52e3d02390fdac2a12b155cb"
        }
      ],
      "end": "0x4020",
      "entry": "0x4000",
      "name": "thumb_4000",
      "size": 32
    },
    {
      "body": "0x4040: invalid\n",
      "body_kind": "thumb_disassembly",
      "data_refs": [],
      "decode_range_errors": [
        {
          "address": "0x4040",
          "end": null,
          "kind": "missing_operation_body"
        }
      ],
      "decode_ranges": [],
      "end": "0x4042",
      "entry": "0x4040",
      "name": "thumb_4040",
      "size": 2
    }
  ]
}"#
    }

    pub(crate) fn malformed_consumer_v3_fixture() -> Vec<u8> {
        let fixture = std::str::from_utf8(Self::consumer_v3_fixture()).unwrap();
        let malformed = fixture.replacen("\"substantial\": 1", "\"substantial\": 0", 1);
        assert_ne!(malformed, fixture);
        malformed.into_bytes()
    }

    pub(crate) fn future_multi_run_v3_fixture() -> &'static [u8] {
        br#"{
          "format": "pixel-modem-extractor-thumb-functions-v3",
          "producers": [
            {"id":"radare2","executable":"/usr/bin/r2","version":"radare2 6.1.4","command":"aaa;aflj;pdfj @@f"},
            {"id":"rizin","executable":"/usr/bin/rizin","version":"rizin 0.8.2","command":"aaa;aflj;pdfj @@F;axlj"}
          ],
          "regions": [{
            "start": "0x1000",
            "end": "0x1100",
            "attempts": [
              {"producer":"radare2","status":"succeeded","stdout":{"path":"thumb/00001000.radare2.stdout","bytes":2,"blake3":"0000000000000000000000000000000000000000000000000000000000000000"},"error":null},
              {"producer":"rizin","status":"succeeded","stdout":{"path":"thumb/00001000.rizin.stdout","bytes":256,"blake3":"1111111111111111111111111111111111111111111111111111111111111111"},"error":null}
            ],
            "function_runs": [
              {"producer":"radare2","first_function":0,"function_count":1,"substantial":0,"accepted":1,"quarantined":0},
              {"producer":"rizin","first_function":1,"function_count":1,"substantial":1,"accepted":1,"quarantined":0}
            ]
          }],
          "functions": [
            {
              "name":"r2_same_entry","entry":"0x1000","end":"0x1002","size":2,
              "body_kind":"thumb_disassembly","body":"0x1000 bx lr\n","data_refs":[],
              "decode_ranges":[{"end":"0x1002","isa":"thumb","start":"0x1000","blake3":"1ad48f49627079d806b802c74f40c39d55fe1d78b3faf0f8017aec62cec42122"}],
              "decode_range_errors":[]
            },
            {
              "name":"rizin_same_entry","entry":"0x1000","end":"0x1100","size":256,
              "body_kind":"thumb_disassembly","body":"0x1000 push {lr}\n0x1080 bx lr\n","data_refs":[],
              "decode_ranges":[
                {"end":"0x1010","isa":"thumb","start":"0x1000","blake3":"e572dff82304700b856a555ac3a4558d0df3646a3727816500270a93c66aac1e"},
                {"end":"0x1090","isa":"thumb","start":"0x1080","blake3":"e572dff82304700b856a555ac3a4558d0df3646a3727816500270a93c66aac1e"}
              ],
              "decode_range_errors":[]
            }
          ]
        }"#
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct RunCounts {
    substantial: usize,
    accepted: usize,
    quarantined: usize,
}

struct ThumbScan<'runtime, 'data> {
    runtime: &'runtime RuntimeImage<'data>,
    budget: ExecutionBudget,
    raw_count: usize,
    substantial: usize,
    accepted: usize,
    quarantined: usize,
    accepted_executions: BTreeSet<OwnedExecutionIdentity>,
    records: Vec<TaggedExecutionRecord>,
    format: Option<ThumbFormat>,
    saw_producers: bool,
    saw_regions: bool,
    saw_functions: bool,
    v3_producers: Option<Vec<ProducerIdentity>>,
    v3_regions: Option<Vec<RegionRecord>>,
    v3_layout: Option<V3Layout>,
    v3_run_cursor: V3RunCursor,
    v3_observed: Vec<RunCounts>,
    shape_error: Option<Error>,
    size_error: Option<Error>,
    validation_error: Option<Error>,
}

impl<'runtime, 'data> ThumbScan<'runtime, 'data> {
    fn new(runtime: &'runtime RuntimeImage<'data>) -> Self {
        Self {
            runtime,
            budget: ExecutionBudget::default(),
            raw_count: 0,
            substantial: 0,
            accepted: 0,
            quarantined: 0,
            accepted_executions: BTreeSet::new(),
            records: Vec::new(),
            format: None,
            saw_producers: false,
            saw_regions: false,
            saw_functions: false,
            v3_producers: None,
            v3_regions: None,
            v3_layout: None,
            v3_run_cursor: V3RunCursor::default(),
            v3_observed: Vec::new(),
            shape_error: None,
            size_error: None,
            validation_error: None,
        }
    }

    fn shape_invalid(&mut self, message: impl Into<String>) {
        self.shape_error
            .get_or_insert_with(|| Error::Serialize(message.into()));
    }

    fn artifact_invalid(&mut self, error: Error) {
        if self.shape_error.is_none() {
            self.shape_error = Some(error);
        }
    }

    fn set_v3_regions(&mut self, regions: Vec<RegionRecord>) {
        let Some(producers) = self.v3_producers.as_deref() else {
            self.shape_invalid("unsupported Thumb functions inventory format");
            return;
        };
        if let Err(error) = validate_v3_regions_in_runtime(&regions, self.runtime) {
            self.artifact_invalid(error);
            return;
        }
        match validate_v3_metadata(producers, &regions) {
            Ok(layout) => {
                self.v3_observed = vec![RunCounts::default(); layout.runs.len()];
                self.v3_run_cursor = V3RunCursor::default();
                self.v3_regions = Some(regions);
                self.v3_layout = Some(layout);
            }
            Err(error) => self.artifact_invalid(error),
        }
    }

    fn record(&mut self, record: Value) {
        let function_index = self.raw_count;
        let Some(raw_count) = self.raw_count.checked_add(1) else {
            self.validation_error = Some(invalid("Thumb function count overflow"));
            return;
        };
        self.raw_count = raw_count;
        if self.shape_error.is_some() {
            return;
        }
        let owner = if self.format == Some(ThumbFormat::V3) {
            match validate_function_value(&record, function_index) {
                Ok((substantial, accepted, quarantined)) => {
                    let run_index = self.v3_layout.as_ref().and_then(|layout| {
                        self.v3_run_cursor.owner_index(&layout.runs, function_index)
                    });
                    let Some(run_index) = run_index else {
                        self.shape_invalid("every v3 function must have exactly one run owner");
                        return;
                    };
                    let observed = &mut self.v3_observed[run_index];
                    observed.substantial += usize::from(substantial);
                    observed.accepted += usize::from(accepted);
                    observed.quarantined += usize::from(quarantined);
                    self.v3_layout.as_ref().unwrap().runs[run_index].owner
                }
                Err(error) => {
                    self.artifact_invalid(error);
                    return;
                }
            }
        } else {
            FunctionOwner::Legacy {
                producer: AnalysisTool::Radare2,
            }
        };
        if self.size_error.is_none() {
            let Some(size) = record.get("size").and_then(Value::as_u64) else {
                self.size_error = Some(Error::Serialize(
                    "Thumb function size must be an unsigned integer".into(),
                ));
                return;
            };
            if size >= 32 {
                let Some(substantial) = self.substantial.checked_add(1) else {
                    self.size_error =
                        Some(Error::Serialize("Thumb substantial count overflow".into()));
                    return;
                };
                self.substantial = substantial;
            }
        }
        if self.validation_error.is_some() {
            return;
        }
        let validated = if self.format == Some(ThumbFormat::V3) {
            validate_inventory_record(&record, owner, self.runtime, &mut self.budget)
        } else {
            let identity =
                legacy_execution(&record, function_index, self.runtime, &mut self.budget);
            identity.and_then(|identity| {
                let entry = record
                    .get("entry")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid_artifact("legacy function entry must be a string"))
                    .and_then(|entry| canonical_hex_u32(entry, "legacy function entry"))?;
                let projection = match &identity {
                    Some(identity) => ExecutionProjection::Accepted(identity.decode_ranges.clone()),
                    None => legacy_non_execution_projection(&record, entry)?,
                };
                Ok((
                    TaggedExecutionRecord {
                        owner,
                        entry,
                        projection: projection.clone(),
                    },
                    projection,
                    identity,
                ))
            })
        };
        match validated {
            Ok((tagged, _, identity)) => match identity {
                Some(identity) => match self.accepted.checked_add(1) {
                    Some(accepted) => {
                        self.accepted = accepted;
                        self.accepted_executions
                            .insert(OwnedExecutionIdentity { owner, identity });
                        self.records.push(tagged);
                    }
                    None => {
                        self.validation_error = Some(invalid("accepted inventory count overflow"));
                    }
                },
                None => match self.quarantined.checked_add(1) {
                    Some(quarantined) => {
                        self.quarantined = quarantined;
                        self.records.push(tagged);
                    }
                    None => {
                        self.validation_error =
                            Some(invalid("quarantined inventory count overflow"));
                    }
                },
            },
            Err(error) => self.validation_error = Some(error),
        }
    }

    fn finish(mut self, expected_substantial: usize) -> Result<ValidatedThumbInventory> {
        if let Some(error) = self.shape_error {
            return Err(error);
        }
        if let Some(error) = self.size_error {
            return Err(error);
        }
        if self.format == Some(ThumbFormat::V3) {
            if let Some(error) = self.validation_error {
                return Err(error);
            }
            let layout = self.v3_layout.as_ref().ok_or_else(|| {
                invalid_artifact("v3 artifact lacks validated producer and region metadata")
            })?;
            if self.raw_count != layout.function_count {
                return Err(invalid_artifact(
                    "every v3 function must have exactly one run owner",
                ));
            }
            for (run_index, (run, observed)) in
                layout.runs.iter().zip(&self.v3_observed).enumerate()
            {
                if (run.substantial, run.accepted, run.quarantined)
                    != (
                        observed.substantial,
                        observed.accepted,
                        observed.quarantined,
                    )
                {
                    return Err(invalid_artifact(format!(
                        "v3 run {run_index} stored counts do not match its functions"
                    )));
                }
            }
        }
        if self.substantial != expected_substantial {
            return Err(Error::Serialize(format!(
                "Thumb substantial count mismatch: expected {expected_substantial}, found {}",
                self.substantial
            )));
        }
        if let Some(error) = self.validation_error {
            return Err(error);
        }
        if self.accepted.checked_add(self.quarantined) != Some(self.raw_count) {
            return Err(invalid(
                "raw inventory count does not equal accepted plus quarantined",
            ));
        }
        let format = self.format.ok_or_else(|| {
            Error::Serialize("unsupported Thumb functions inventory format".into())
        })?;
        let mut summary = ThumbAnalysisSummary {
            raw: self.raw_count,
            substantial: self.substantial,
            accepted: self.accepted,
            quarantined: self.quarantined,
            ..ThumbAnalysisSummary::default()
        };
        let (producers, regions) =
            if format == ThumbFormat::V3 {
                let producers = self.v3_producers.take().ok_or_else(|| {
                    invalid_artifact("v3 artifact lacks validated producer metadata")
                })?;
                let region_records = self.v3_regions.take().ok_or_else(|| {
                    invalid_artifact("v3 artifact lacks validated region metadata")
                })?;
                summary.regions_requested = region_records.len();
                for region in &region_records {
                    if region.function_runs.is_empty() {
                        summary.regions_failed += 1;
                    } else {
                        summary.regions_succeeded += 1;
                    }
                    for run in &region.function_runs {
                        match run.producer {
                            ThumbProducer::Radare2 => summary.radare2_runs += 1,
                            ThumbProducer::Rizin => summary.rizin_runs += 1,
                        }
                    }
                }
                let regions = region_records
                    .into_iter()
                    .map(|region| (region.start, region.end))
                    .collect();
                (producers, regions)
            } else {
                (Vec::new(), Vec::new())
            };
        Ok(ValidatedThumbInventory {
            inventory: ValidatedInventory {
                raw_count: self.raw_count,
                accepted: self.accepted,
                quarantined: self.quarantined,
                accepted_executions: self.accepted_executions.into_iter().collect(),
                records: self.records,
            },
            metadata: ThumbTerminalMetadata {
                format,
                producers,
                regions,
                summary,
            },
        })
    }
}

struct ThumbInventoryVisitor<'scan, 'runtime, 'data> {
    scan: &'scan mut ThumbScan<'runtime, 'data>,
}

impl<'de> Visitor<'de> for ThumbInventoryVisitor<'_, '_, '_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a Thumb functions inventory object")
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "format" if self.scan.format.is_none() => {
                    let value = map.next_value::<Value>()?;
                    self.scan.format = value.as_str().and_then(ThumbFormat::parse);
                    if self.scan.format.is_none() {
                        self.scan
                            .shape_invalid("unsupported Thumb functions inventory format");
                    }
                }
                "producers"
                    if self.scan.format == Some(ThumbFormat::V3) && !self.scan.saw_producers =>
                {
                    self.scan.saw_producers = true;
                    let producers = map.next_value::<Vec<ProducerWire>>()?;
                    match convert_producers(producers) {
                        Ok(producers) => self.scan.v3_producers = Some(producers),
                        Err(error) => self.scan.artifact_invalid(error),
                    }
                }
                "regions"
                    if self.scan.format == Some(ThumbFormat::V3)
                        && self.scan.saw_producers
                        && !self.scan.saw_regions =>
                {
                    self.scan.saw_regions = true;
                    let regions = map.next_value::<Vec<RegionWire>>()?;
                    match convert_regions(regions) {
                        Ok(regions) => self.scan.set_v3_regions(regions),
                        Err(error) => self.scan.artifact_invalid(error),
                    }
                }
                "functions"
                    if matches!(self.scan.format, Some(ThumbFormat::V1 | ThumbFormat::V2))
                        && !self.scan.saw_functions =>
                {
                    self.scan.saw_functions = true;
                    map.next_value_seed(FunctionsSeq {
                        scan: &mut *self.scan,
                        strict_v3: false,
                    })?;
                }
                "functions"
                    if self.scan.format == Some(ThumbFormat::V3)
                        && self.scan.saw_producers
                        && self.scan.saw_regions
                        && !self.scan.saw_functions =>
                {
                    self.scan.saw_functions = true;
                    map.next_value_seed(FunctionsSeq {
                        scan: &mut *self.scan,
                        strict_v3: true,
                    })?;
                }
                _ => {
                    self.scan
                        .shape_invalid("unsupported Thumb functions inventory format");
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        if !self.scan.saw_functions {
            self.scan
                .shape_invalid("Thumb functions inventory lacks functions array");
        }
        Ok(())
    }

    fn visit_seq<A>(self, mut seq: A) -> std::result::Result<(), A::Error>
    where
        A: SeqAccess<'de>,
    {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        self.scan
            .shape_invalid("Thumb functions inventory must be an object");
        Ok(())
    }

    fn visit_bool<E>(self, _: bool) -> std::result::Result<(), E> {
        self.scan
            .shape_invalid("Thumb functions inventory must be an object");
        Ok(())
    }

    fn visit_i64<E>(self, _: i64) -> std::result::Result<(), E> {
        self.scan
            .shape_invalid("Thumb functions inventory must be an object");
        Ok(())
    }

    fn visit_u64<E>(self, _: u64) -> std::result::Result<(), E> {
        self.scan
            .shape_invalid("Thumb functions inventory must be an object");
        Ok(())
    }

    fn visit_f64<E>(self, _: f64) -> std::result::Result<(), E> {
        self.scan
            .shape_invalid("Thumb functions inventory must be an object");
        Ok(())
    }

    fn visit_str<E>(self, _: &str) -> std::result::Result<(), E> {
        self.scan
            .shape_invalid("Thumb functions inventory must be an object");
        Ok(())
    }

    fn visit_unit<E>(self) -> std::result::Result<(), E> {
        self.scan
            .shape_invalid("Thumb functions inventory must be an object");
        Ok(())
    }
}

struct FunctionsSeq<'scan, 'runtime, 'data> {
    scan: &'scan mut ThumbScan<'runtime, 'data>,
    strict_v3: bool,
}

impl<'de> DeserializeSeed<'de> for FunctionsSeq<'_, '_, '_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<(), D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for FunctionsSeq<'_, '_, '_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a Thumb functions array")
    }

    fn visit_seq<A>(self, mut seq: A) -> std::result::Result<(), A::Error>
    where
        A: SeqAccess<'de>,
    {
        if self.strict_v3 {
            while let Some(function) = seq.next_element::<FunctionWire>()? {
                self.scan
                    .record(serde_json::to_value(function).map_err(de::Error::custom)?);
            }
        } else {
            while let Some(record) = seq.next_element::<Value>()? {
                self.scan.record(record);
            }
        }
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        while map.next_key::<IgnoredAny>()?.is_some() {
            map.next_value::<IgnoredAny>()?;
        }
        self.scan
            .shape_invalid("Thumb functions inventory lacks functions array");
        Ok(())
    }

    fn visit_bool<E>(self, _: bool) -> std::result::Result<(), E> {
        self.scan
            .shape_invalid("Thumb functions inventory lacks functions array");
        Ok(())
    }

    fn visit_i64<E>(self, _: i64) -> std::result::Result<(), E> {
        self.scan
            .shape_invalid("Thumb functions inventory lacks functions array");
        Ok(())
    }

    fn visit_u64<E>(self, _: u64) -> std::result::Result<(), E> {
        self.scan
            .shape_invalid("Thumb functions inventory lacks functions array");
        Ok(())
    }

    fn visit_f64<E>(self, _: f64) -> std::result::Result<(), E> {
        self.scan
            .shape_invalid("Thumb functions inventory lacks functions array");
        Ok(())
    }

    fn visit_str<E>(self, _: &str) -> std::result::Result<(), E> {
        self.scan
            .shape_invalid("Thumb functions inventory lacks functions array");
        Ok(())
    }

    fn visit_unit<E>(self) -> std::result::Result<(), E> {
        self.scan
            .shape_invalid("Thumb functions inventory lacks functions array");
        Ok(())
    }
}

/// Render one function as a depth-two pretty JSON fragment suitable for the
/// top-level `functions` array.
pub(super) fn render_fragment(value: &Value) -> Result<String> {
    let pretty =
        serde_json::to_string_pretty(value).map_err(|error| Error::Serialize(error.to_string()))?;
    Ok(pretty
        .split('\n')
        .map(|line| format!("    {line}"))
        .collect::<Vec<_>>()
        .join("\n"))
}

/// Validate one normalized v3 function after backend-specific evidence has
/// been injected, then render it for a fragment spill.
pub(super) fn render_v3_fragment(value: &Value, function_index: usize) -> Result<String> {
    validate_function_value(value, function_index)?;
    render_v3_function(value)
}

fn render_v3_function(value: &Value) -> Result<String> {
    let function: FunctionWire = serde_json::from_value(value.clone())
        .map_err(|error| invalid_artifact(format!("invalid v3 function: {error}")))?;
    let pretty = serde_json::to_string_pretty(&function)
        .map_err(|error| Error::Serialize(error.to_string()))?;
    Ok(pretty
        .split('\n')
        .map(|line| format!("    {line}"))
        .collect::<Vec<_>>()
        .join("\n"))
}

/// One spill slot is stored as `[u32 LE index][u32 LE length][fragment]`.
struct FragmentSlot {
    function_index: u32,
    offset: u64,
    length: u32,
}

/// Append-only function-fragment spill. Only the compact slot index remains in
/// memory while normalized function JSON stays on disk.
pub(super) struct SpillWriter {
    path: PathBuf,
    file: std::fs::File,
    offset: u64,
    slots: Vec<FragmentSlot>,
}

impl SpillWriter {
    pub(super) fn create(path: PathBuf) -> std::io::Result<Self> {
        let file = std::fs::File::create(&path)?;
        Ok(Self {
            path,
            file,
            offset: 0,
            slots: Vec::new(),
        })
    }

    pub(super) fn push(&mut self, function_index: u32, fragment: &str) -> std::io::Result<()> {
        let bytes = fragment.as_bytes();
        assert!(
            bytes.len() <= u32::MAX as usize,
            "fragment length overflows u32"
        );
        self.file.write_all(&function_index.to_le_bytes())?;
        self.file.write_all(&(bytes.len() as u32).to_le_bytes())?;
        self.file.write_all(bytes)?;
        self.slots.push(FragmentSlot {
            function_index,
            offset: self.offset + 8,
            length: bytes.len() as u32,
        });
        self.offset += 8 + bytes.len() as u64;
        Ok(())
    }

    pub(super) fn finish(mut self) -> std::io::Result<Spill> {
        self.file.flush()?;
        self.slots.sort_unstable_by_key(|slot| slot.function_index);
        Ok(Spill {
            path: self.path,
            slots: self.slots,
        })
    }
}

/// A completed spill whose fragments can be replayed in function order.
pub(crate) struct Spill {
    pub(super) path: PathBuf,
    slots: Vec<FragmentSlot>,
}

impl Spill {
    fn read_slot(&self, slot: &FragmentSlot) -> std::io::Result<Vec<u8>> {
        use std::io::{Seek, SeekFrom};

        let mut file = std::fs::File::open(&self.path)?;
        file.seek(SeekFrom::Start(slot.offset))?;
        let mut bytes = vec![0u8; slot.length as usize];
        file.read_exact(&mut bytes)?;
        Ok(bytes)
    }

    fn emit_slot<W: Write>(&self, writer: &mut W, slot: &FragmentSlot) -> std::io::Result<()> {
        use std::io::{Seek, SeekFrom};

        let mut file = std::fs::File::open(&self.path)?;
        file.seek(SeekFrom::Start(slot.offset))?;
        let mut remaining = slot.length as usize;
        let mut buffer = vec![0u8; 64 * 1024];
        while remaining > 0 {
            let read_length = buffer.len().min(remaining);
            file.read_exact(&mut buffer[..read_length])?;
            writer.write_all(&buffer[..read_length])?;
            remaining -= read_length;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn emit<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        for slot in &self.slots {
            self.emit_slot(writer, slot)?;
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct ProducerOutput<'a> {
    id: ThumbProducer,
    executable: &'a str,
    version: &'a str,
    command: &'a str,
}

fn producer_output(producers: &[ProducerIdentity]) -> Result<Vec<ProducerOutput<'_>>> {
    producers
        .iter()
        .map(|producer| {
            let executable = producer.executable.to_str().ok_or_else(|| {
                invalid_artifact(format!(
                    "{} producer executable is not UTF-8",
                    producer.producer.as_str()
                ))
            })?;
            Ok(ProducerOutput {
                id: producer.producer,
                executable,
                version: &producer.version,
                command: producer.command,
            })
        })
        .collect()
}

fn write_pretty_value<W: Write, T: Serialize>(
    writer: &mut W,
    value: &T,
    continuation_indent: &str,
) -> Result<()> {
    let rendered =
        serde_json::to_string_pretty(value).map_err(|error| Error::Serialize(error.to_string()))?;
    let mut lines = rendered.split('\n');
    writer.write_all(lines.next().unwrap_or_default().as_bytes())?;
    for line in lines {
        writer.write_all(b"\n")?;
        writer.write_all(continuation_indent.as_bytes())?;
        writer.write_all(line.as_bytes())?;
    }
    Ok(())
}

fn write_v3_values_into<W: Write>(
    writer: &mut W,
    producers: &[ProducerIdentity],
    regions: &[RegionRecord],
    functions: &[Value],
) -> Result<()> {
    let producer_output = producer_output(producers)?;
    writer.write_all(b"{\n  \"format\": \"")?;
    writer.write_all(THUMB_V3_FORMAT.as_bytes())?;
    writer.write_all(b"\",\n  \"producers\": ")?;
    write_pretty_value(writer, &producer_output, "  ")?;
    writer.write_all(b",\n  \"regions\": ")?;
    write_pretty_value(writer, &regions, "  ")?;
    writer.write_all(b",\n  \"functions\": [\n")?;
    for (index, function) in functions.iter().enumerate() {
        if index != 0 {
            writer.write_all(b",\n")?;
        }
        writer.write_all(render_v3_function(function)?.as_bytes())?;
    }
    writer.write_all(b"\n  ]\n}")?;
    Ok(())
}

struct FormatProbe;

impl<'de> Visitor<'de> for FormatProbe {
    type Value = ThumbFormat;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a Thumb artifact object beginning with format")
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        expect_key(&mut map, "format")?;
        let raw_format = map.next_value::<String>()?;
        let format = ThumbFormat::parse(&raw_format)
            .ok_or_else(|| de::Error::custom("unsupported Thumb artifact format"))?;
        while map.next_key::<IgnoredAny>()?.is_some() {
            map.next_value::<IgnoredAny>()?;
        }
        Ok(format)
    }
}

fn probe_thumb_format_reader(input: impl Read, context: &str) -> Result<ThumbFormat> {
    let mut deserializer = serde_json::Deserializer::from_reader(std::io::BufReader::new(input));
    deserializer
        .deserialize_map(FormatProbe)
        .and_then(|format| deserializer.end().map(|()| format))
        .map_err(|error| Error::Serialize(format!("parse {context}: {error}")))
}

fn probe_thumb_format(path: &Path) -> Result<ThumbFormat> {
    probe_thumb_format_reader(std::fs::File::open(path)?, &path.display().to_string())
}

trait CommitWrite: Write {
    fn commit(self) -> std::io::Result<()>;
}

impl CommitWrite for atomic_write_file::AtomicWriteFile {
    fn commit(self) -> std::io::Result<()> {
        self.commit()
    }
}

impl CommitWrite for TrustedAtomicFile {
    fn commit(self) -> std::io::Result<()> {
        self.commit()
    }
}

/// Atomically rewrite a current v3 artifact one function at a time. The format
/// preflight rejects retained v1/v2 before an `AtomicWriteFile` is opened.
pub(crate) fn stream_rewrite_thumb_functions<F>(
    path: &Path,
    runtime: &RuntimeImage<'_>,
    on_function: F,
) -> Result<()>
where
    F: FnMut(FunctionOwner, Option<&ExecutionIdentity>, &mut Value) -> Result<()>,
{
    if probe_thumb_format(path)? != ThumbFormat::V3 {
        return Err(invalid_artifact(
            "legacy Thumb artifacts are read-only replay inputs",
        ));
    }
    let input = std::fs::File::open(path)?;
    stream_rewrite_thumb_functions_with(
        input,
        atomic_write_file::AtomicWriteFile::open(path)?,
        &path.display().to_string(),
        runtime,
        on_function,
    )
}

pub(crate) fn stream_rewrite_thumb_functions_trusted<F>(
    directory: &TrustedDirectory,
    file_name: &str,
    runtime: &RuntimeImage<'_>,
    mut make_on_function: impl FnMut() -> F,
) -> Result<()>
where
    F: FnMut(FunctionOwner, Option<&ExecutionIdentity>, &mut Value) -> Result<()>,
{
    let relative = Path::new(file_name);
    let context = format!("trusted {file_name}");
    let probe = directory.open_regular_file(relative, &context)?;
    if probe_thumb_format_reader(probe, &context)? != ThumbFormat::V3 {
        return Err(invalid_artifact(
            "legacy Thumb artifacts are read-only replay inputs",
        ));
    }
    let input = directory.open_regular_file(relative, &context)?;
    let (_, changed) = rewrite_thumb_functions_into(
        input,
        std::io::sink(),
        &context,
        runtime,
        make_on_function(),
    )?;
    if !changed {
        return Ok(());
    }
    let input = directory.open_regular_file(relative, &context)?;
    let output = directory.atomic_write_file(file_name, &context)?;
    let (output, changed) =
        rewrite_thumb_functions_into(input, output, &context, runtime, make_on_function())?;
    if !changed {
        return Err(invalid_artifact(
            "trusted Thumb rewrite changed between validation and commit",
        ));
    }
    output.commit()?;
    Ok(())
}

fn stream_rewrite_thumb_functions_with<R, W, F>(
    input: R,
    output: W,
    context: &str,
    runtime: &RuntimeImage<'_>,
    on_function: F,
) -> Result<()>
where
    R: Read,
    W: CommitWrite,
    F: FnMut(FunctionOwner, Option<&ExecutionIdentity>, &mut Value) -> Result<()>,
{
    let (output, changed) =
        rewrite_thumb_functions_into(input, output, context, runtime, on_function)?;
    if changed {
        output.commit()?;
    }
    Ok(())
}

fn rewrite_thumb_functions_into<R, W, F>(
    input: R,
    output: W,
    context: &str,
    runtime: &RuntimeImage<'_>,
    on_function: F,
) -> Result<(W, bool)>
where
    R: Read,
    W: Write,
    F: FnMut(FunctionOwner, Option<&ExecutionIdentity>, &mut Value) -> Result<()>,
{
    let mut deserializer = serde_json::Deserializer::from_reader(std::io::BufReader::new(input));
    let mut scan = ThumbRewriteScan::new(output, runtime, on_function);
    let parsed = deserializer.deserialize_map(ThumbRewriteVisitor { scan: &mut scan });
    parsed
        .and_then(|()| deserializer.end())
        .map_err(|error| Error::Serialize(format!("parse {context}: {error}")))?;
    scan.finish()?;
    Ok((scan.output, scan.changed))
}

const V3_IMMUTABLE_FUNCTION_FIELDS: [&str; 8] = [
    "entry",
    "end",
    "size",
    "body_kind",
    "body",
    "data_refs",
    "decode_ranges",
    "decode_range_errors",
];

struct ThumbRewriteScan<'runtime, 'data, W, F> {
    output: W,
    runtime: &'runtime RuntimeImage<'data>,
    budget: ExecutionBudget,
    on_function: F,
    format: Option<ThumbFormat>,
    producers: Vec<ProducerIdentity>,
    regions: Vec<RegionRecord>,
    layout: Option<V3Layout>,
    run_cursor: V3RunCursor,
    observed: Vec<RunCounts>,
    function_count: usize,
    changed: bool,
    wrote_function: bool,
}

impl<'runtime, 'data, W, F> ThumbRewriteScan<'runtime, 'data, W, F>
where
    W: Write,
    F: FnMut(FunctionOwner, Option<&ExecutionIdentity>, &mut Value) -> Result<()>,
{
    fn new(output: W, runtime: &'runtime RuntimeImage<'data>, on_function: F) -> Self {
        Self {
            output,
            runtime,
            budget: ExecutionBudget::default(),
            on_function,
            format: None,
            producers: Vec::new(),
            regions: Vec::new(),
            layout: None,
            run_cursor: V3RunCursor::default(),
            observed: Vec::new(),
            function_count: 0,
            changed: false,
            wrote_function: false,
        }
    }

    fn set_v3_metadata(
        &mut self,
        producers: Vec<ProducerWire>,
        regions: Vec<RegionWire>,
    ) -> Result<()> {
        self.producers = convert_producers(producers)?;
        self.regions = convert_regions(regions)?;
        let layout = validate_v3_metadata(&self.producers, &self.regions)?;
        validate_v3_regions_in_runtime(&self.regions, self.runtime)?;
        self.observed = vec![RunCounts::default(); layout.runs.len()];
        self.run_cursor = V3RunCursor::default();
        self.layout = Some(layout);
        Ok(())
    }

    fn rewrite_v3(&mut self, function: FunctionWire) -> Result<()> {
        let mut function = serde_json::to_value(function).map_err(|error| {
            invalid_artifact(format!(
                "v3 function {} cannot be rendered: {error}",
                self.function_count
            ))
        })?;
        let original = function.clone();
        // Ownership is resolved before the mutation so the callback can key by
        // the concrete run; the cursor stays monotonic because `write_function`
        // advances `function_count` exactly once per record.
        let layout = self.layout.as_ref().ok_or_else(|| {
            invalid_artifact("v3 artifact lacks validated producer and region metadata")
        })?;
        let run_index = self
            .run_cursor
            .owner_index(&layout.runs, self.function_count);
        let Some(run_index) = run_index else {
            return Err(invalid_artifact(
                "every v3 function must have exactly one run owner",
            ));
        };
        let owner = layout.runs[run_index].owner;
        let (_, identity) = authenticate_function_value(
            &function,
            self.function_count,
            owner,
            self.runtime,
            &mut self.budget,
        )?;
        (self.on_function)(owner, identity.as_ref(), &mut function)?;
        validate_v3_function_mutation(
            &original,
            &function,
            self.function_count,
            &V3_IMMUTABLE_FUNCTION_FIELDS,
        )?;
        let (substantial, accepted, quarantined) =
            validate_function_value(&function, self.function_count)?;
        let observed = &mut self.observed[run_index];
        observed.substantial += usize::from(substantial);
        observed.accepted += usize::from(accepted);
        observed.quarantined += usize::from(quarantined);
        self.changed |= function != original;
        self.write_function(&function)
    }

    fn write_function(&mut self, function: &Value) -> Result<()> {
        if self.wrote_function {
            self.output.write_all(b",\n")?;
        } else {
            if self.format != Some(ThumbFormat::V3) {
                return Err(invalid_artifact(
                    "legacy Thumb artifacts are read-only replay inputs",
                ));
            }
            let producer_output = producer_output(&self.producers)?;
            self.output.write_all(b"{\n  \"format\": \"")?;
            self.output.write_all(THUMB_V3_FORMAT.as_bytes())?;
            self.output.write_all(b"\",\n  \"producers\": ")?;
            write_pretty_value(&mut self.output, &producer_output, "  ")?;
            self.output.write_all(b",\n  \"regions\": ")?;
            write_pretty_value(&mut self.output, &self.regions, "  ")?;
            self.output.write_all(b",\n  \"functions\": [\n")?;
            self.wrote_function = true;
        }
        self.output
            .write_all(render_v3_function(function)?.as_bytes())?;
        self.function_count = self
            .function_count
            .checked_add(1)
            .ok_or_else(|| invalid_artifact("Thumb function count overflow"))?;
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        let format = self
            .format
            .ok_or_else(|| invalid_artifact("missing Thumb artifact format"))?;
        if format == ThumbFormat::V3 {
            let layout = self.layout.as_ref().ok_or_else(|| {
                invalid_artifact("v3 artifact lacks validated producer and region metadata")
            })?;
            if self.function_count != layout.function_count {
                return Err(invalid_artifact(
                    "every v3 function must have exactly one run owner",
                ));
            }
            for (run_index, (run, observed)) in layout.runs.iter().zip(&self.observed).enumerate() {
                if (run.substantial, run.accepted, run.quarantined)
                    != (
                        observed.substantial,
                        observed.accepted,
                        observed.quarantined,
                    )
                {
                    return Err(invalid_artifact(format!(
                        "v3 run {run_index} stored counts do not match its functions"
                    )));
                }
            }
        }
        if self.wrote_function {
            self.output.write_all(b"\n  ]\n}")?;
        }
        Ok(())
    }
}

struct ThumbRewriteVisitor<'a, 'runtime, 'data, W, F> {
    scan: &'a mut ThumbRewriteScan<'runtime, 'data, W, F>,
}

impl<'de, W, F> Visitor<'de> for ThumbRewriteVisitor<'_, '_, '_, W, F>
where
    W: Write,
    F: FnMut(FunctionOwner, Option<&ExecutionIdentity>, &mut Value) -> Result<()>,
{
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a canonical Thumb artifact object")
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        let key = map
            .next_key::<String>()?
            .ok_or_else(|| de::Error::missing_field("format"))?;
        if key != "format" {
            return Err(de::Error::custom(format!(
                "expected top-level field \"format\", found {key:?}"
            )));
        }
        let raw_format = map.next_value::<String>()?;
        let format = ThumbFormat::parse(&raw_format)
            .ok_or_else(|| de::Error::custom("unsupported Thumb artifact format"))?;
        self.scan.format = Some(format);

        match format {
            ThumbFormat::V1 | ThumbFormat::V2 => {
                return Err(de::Error::custom(
                    "legacy Thumb artifacts are read-only replay inputs",
                ));
            }
            ThumbFormat::V3 => {
                let key = map
                    .next_key::<String>()?
                    .ok_or_else(|| de::Error::missing_field("producers"))?;
                if key != "producers" {
                    return Err(de::Error::custom(format!(
                        "expected top-level field \"producers\", found {key:?}"
                    )));
                }
                let producers = map.next_value::<Vec<ProducerWire>>()?;
                let key = map
                    .next_key::<String>()?
                    .ok_or_else(|| de::Error::missing_field("regions"))?;
                if key != "regions" {
                    return Err(de::Error::custom(format!(
                        "expected top-level field \"regions\", found {key:?}"
                    )));
                }
                let regions = map.next_value::<Vec<RegionWire>>()?;
                self.scan
                    .set_v3_metadata(producers, regions)
                    .map_err(de::Error::custom)?;
                let key = map
                    .next_key::<String>()?
                    .ok_or_else(|| de::Error::missing_field("functions"))?;
                if key != "functions" {
                    return Err(de::Error::custom(format!(
                        "expected top-level field \"functions\", found {key:?}"
                    )));
                }
                map.next_value_seed(RewriteV3Functions {
                    scan: &mut *self.scan,
                })?;
            }
        }
        if let Some(key) = map.next_key::<String>()? {
            return Err(de::Error::custom(format!(
                "unexpected top-level field {key:?}"
            )));
        }
        Ok(())
    }
}

struct RewriteV3Functions<'a, 'runtime, 'data, W, F> {
    scan: &'a mut ThumbRewriteScan<'runtime, 'data, W, F>,
}

impl<'de, W, F> DeserializeSeed<'de> for RewriteV3Functions<'_, '_, '_, W, F>
where
    W: Write,
    F: FnMut(FunctionOwner, Option<&ExecutionIdentity>, &mut Value) -> Result<()>,
{
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<(), D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(self)
    }
}

impl<'de, W, F> Visitor<'de> for RewriteV3Functions<'_, '_, '_, W, F>
where
    W: Write,
    F: FnMut(FunctionOwner, Option<&ExecutionIdentity>, &mut Value) -> Result<()>,
{
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a strict v3 Thumb functions array")
    }

    fn visit_seq<A>(self, mut seq: A) -> std::result::Result<(), A::Error>
    where
        A: SeqAccess<'de>,
    {
        while let Some(function) = seq.next_element::<FunctionWire>()? {
            self.scan.rewrite_v3(function).map_err(de::Error::custom)?;
        }
        Ok(())
    }
}

/// Atomically rewrite a supplied top-level JSON array snapshot while retaining
/// at most one element at a time. The caller can validate that exact snapshot
/// before mutation; a no-op leaves the destination bytes untouched.
pub(crate) fn stream_rewrite_json_array<F>(path: &Path, source: &[u8], on_element: F) -> Result<()>
where
    F: FnMut(&mut Value) -> Result<()>,
{
    stream_rewrite_json_array_with(
        atomic_write_file::AtomicWriteFile::open(path)?,
        source,
        &path.display().to_string(),
        on_element,
    )
}

pub(crate) fn stream_rewrite_json_array_trusted<F>(
    directory: &TrustedDirectory,
    file_name: &str,
    source: &[u8],
    mut make_on_element: impl FnMut() -> F,
) -> Result<()>
where
    F: FnMut(&mut Value) -> Result<()>,
{
    let context = format!("trusted {file_name}");
    let (_, changed) =
        rewrite_json_array_into(std::io::sink(), source, &context, make_on_element())?;
    if !changed {
        return Ok(());
    }
    let (output, changed) = rewrite_json_array_into(
        directory.atomic_write_file(file_name, &context)?,
        source,
        &context,
        make_on_element(),
    )?;
    if !changed {
        return Err(invalid_artifact(
            "trusted JSON rewrite changed between validation and commit",
        ));
    }
    output.commit()?;
    Ok(())
}

fn stream_rewrite_json_array_with<W, F>(
    output: W,
    source: &[u8],
    context: &str,
    on_element: F,
) -> Result<()>
where
    W: CommitWrite,
    F: FnMut(&mut Value) -> Result<()>,
{
    let (output, changed) = rewrite_json_array_into(output, source, context, on_element)?;
    if changed {
        output.commit()?;
    }
    Ok(())
}

fn rewrite_json_array_into<W, F>(
    output: W,
    source: &[u8],
    context: &str,
    on_element: F,
) -> Result<(W, bool)>
where
    W: Write,
    F: FnMut(&mut Value) -> Result<()>,
{
    let mut deserializer = serde_json::Deserializer::from_slice(source);
    let mut scan = ArrayRewriteScan {
        output,
        on_element,
        changed: false,
        wrote_element: false,
    };
    let parsed = deserializer.deserialize_seq(ArrayRewriteVisitor { scan: &mut scan });
    parsed
        .and_then(|()| deserializer.end())
        .map_err(|error| Error::Serialize(format!("parse {context}: {error}")))?;
    if scan.wrote_element {
        scan.output.write_all(b"\n]")?;
    }
    Ok((scan.output, scan.changed))
}

struct ArrayRewriteScan<W, F> {
    output: W,
    on_element: F,
    changed: bool,
    wrote_element: bool,
}

impl<W, F> ArrayRewriteScan<W, F>
where
    W: Write,
    F: FnMut(&mut Value) -> Result<()>,
{
    fn rewrite(&mut self, mut element: Value) -> Result<()> {
        let original = element.clone();
        (self.on_element)(&mut element)?;
        self.changed |= element != original;
        if self.wrote_element {
            self.output.write_all(b",\n")?;
        } else {
            self.output.write_all(b"[\n")?;
            self.wrote_element = true;
        }
        let pretty = serde_json::to_string_pretty(&element)
            .map_err(|error| Error::Serialize(error.to_string()))?;
        for (index, line) in pretty.split('\n').enumerate() {
            if index != 0 {
                self.output.write_all(b"\n")?;
            }
            self.output.write_all(b"  ")?;
            self.output.write_all(line.as_bytes())?;
        }
        Ok(())
    }
}

struct ArrayRewriteVisitor<'a, W, F> {
    scan: &'a mut ArrayRewriteScan<W, F>,
}

impl<'de, W, F> Visitor<'de> for ArrayRewriteVisitor<'_, W, F>
where
    W: Write,
    F: FnMut(&mut Value) -> Result<()>,
{
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON array")
    }

    fn visit_seq<A>(self, mut seq: A) -> std::result::Result<(), A::Error>
    where
        A: SeqAccess<'de>,
    {
        while let Some(element) = seq.next_element::<Value>()? {
            self.scan.rewrite(element).map_err(de::Error::custom)?;
        }
        Ok(())
    }
}

fn parse_v3_fragment(bytes: &[u8], run_index: usize, slot_index: usize) -> Result<Value> {
    let function: FunctionWire = serde_json::from_slice(bytes).map_err(|error| {
        invalid_artifact(format!(
            "v3 assembly run {run_index} function {slot_index} is invalid: {error}"
        ))
    })?;
    serde_json::to_value(function).map_err(|error| {
        invalid_artifact(format!(
            "v3 assembly run {run_index} function {slot_index} cannot be rendered: {error}"
        ))
    })
}

fn validate_v3_assembly_layout(
    producers: &[ProducerIdentity],
    regions: &[RegionRecord],
    spills: &[&Spill],
) -> Result<()> {
    let layout = validate_v3_metadata(producers, regions)?;
    if layout.runs.len() != spills.len() {
        return Err(invalid_artifact(
            "v3 assembly requires one spill per successful function run",
        ));
    }
    for (run_index, (run, spill)) in layout.runs.iter().zip(spills).enumerate() {
        if spill.slots.len() != run.function_count
            || spill
                .slots
                .iter()
                .enumerate()
                .any(|(index, slot)| slot.function_index as usize != index)
        {
            return Err(invalid_artifact(format!(
                "v3 assembly run {run_index} is not contiguous and conserving"
            )));
        }
        let mut observed = RunCounts::default();
        for (slot_index, slot) in spill.slots.iter().enumerate() {
            let bytes = spill.read_slot(slot)?;
            let function = parse_v3_fragment(&bytes, run_index, slot_index)?;
            let (substantial, accepted, quarantined) =
                validate_function_value(&function, run.first_function + slot_index)?;
            observed.substantial += usize::from(substantial);
            observed.accepted += usize::from(accepted);
            observed.quarantined += usize::from(quarantined);
        }
        if (run.substantial, run.accepted, run.quarantined)
            != (
                observed.substantial,
                observed.accepted,
                observed.quarantined,
            )
        {
            return Err(invalid_artifact(format!(
                "v3 assembly run {run_index} stored counts do not match its functions"
            )));
        }
    }
    Ok(())
}

/// Stream a canonical v3 document in metadata-first top-level order.
pub(crate) fn assemble_v3_into<W: Write>(
    writer: &mut W,
    producers: &[ProducerIdentity],
    regions: &[RegionRecord],
    spills: &[&Spill],
) -> Result<()> {
    validate_v3_assembly_layout(producers, regions, spills)?;
    let producer_output = producer_output(producers)?;
    writer.write_all(b"{\n  \"format\": \"")?;
    writer.write_all(THUMB_V3_FORMAT.as_bytes())?;
    writer.write_all(b"\",\n  \"producers\": ")?;
    write_pretty_value(writer, &producer_output, "  ")?;
    writer.write_all(b",\n  \"regions\": ")?;
    write_pretty_value(writer, &regions, "  ")?;
    writer.write_all(b",\n  \"functions\": [\n")?;
    let mut first = true;
    for (run_index, spill) in spills.iter().enumerate() {
        for (slot_index, slot) in spill.slots.iter().enumerate() {
            if !first {
                writer.write_all(b",\n")?;
            }
            first = false;
            let bytes = spill.read_slot(slot)?;
            let function = parse_v3_fragment(&bytes, run_index, slot_index)?;
            writer.write_all(render_v3_function(&function)?.as_bytes())?;
        }
    }
    writer.write_all(b"\n  ]\n}")?;
    Ok(())
}

pub(crate) fn assemble_v3_atomic(
    out_path: &Path,
    producers: &[ProducerIdentity],
    regions: &[RegionRecord],
    spills: &[Spill],
) -> Result<()> {
    let references: Vec<_> = spills.iter().collect();
    let mut file = atomic_write_file::AtomicWriteFile::open(out_path)?;
    assemble_v3_into(&mut file, producers, regions, &references)?;
    file.commit()?;
    for spill in spills {
        let _ = std::fs::remove_file(&spill.path);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    static TEST_IMAGE: [u8; 0x10_000] = [0; 0x10_000];

    fn test_runtime() -> RuntimeImage<'static> {
        RuntimeImage::from_plan(&TEST_IMAGE, 0x1000, None).unwrap()
    }

    fn parse_thumb_artifact(bytes: &[u8]) -> Result<ParsedThumbArtifact> {
        super::parse_thumb_artifact(bytes, &test_runtime())
    }

    fn read_thumb_functions_streaming(path: &Path) -> Result<Vec<OwnedThumbFunction>> {
        super::read_thumb_functions_streaming(path, &test_runtime())
    }

    fn read_thumb_artifact(path: &Path) -> Result<ParsedThumbArtifact> {
        super::read_thumb_artifact(path, &test_runtime())
    }

    fn validate_test_inventory(
        path: &Path,
        expected_substantial: usize,
    ) -> Result<ValidatedThumbInventory> {
        super::validate_thumb_inventory_streaming(path, &test_runtime(), expected_substantial)
    }

    use super::*;
    use crate::analysis_tool::AnalysisTool;
    use crate::execution_ranges::FunctionOwner;
    use crate::runtime_image::RuntimeImage;
    use crate::thumb_analysis::ThumbProducer;
    use serde_json::{Value, json};

    fn function(entry: &str, end: &str, size: u64) -> Value {
        let start = canonical_hex_u32(entry, "test function entry").unwrap();
        let end_address = canonical_hex_u32(end, "test function end").unwrap();
        let digest = blake3::hash(&vec![0; usize::try_from(end_address - start).unwrap()]);
        json!({
            "body": "bx lr\n",
            "body_kind": "thumb_disassembly",
            "data_refs": [],
            "decode_range_errors": [],
            "decode_ranges": [{"end": end, "isa": "thumb", "start": entry, "blake3": digest.to_hex().to_string()}],
            "end": end,
            "entry": entry,
            "name": format!("fcn.{}", entry.trim_start_matches("0x")),
            "size": size
        })
    }

    fn valid_v3() -> Value {
        json!({
            "format": "pixel-modem-extractor-thumb-functions-v3",
            "producers": [
                {
                    "id": "radare2",
                    "executable": "/usr/bin/r2",
                    "version": "radare2 6.1.4",
                    "command": "aaa;aflj;pdfj @@f"
                },
                {
                    "id": "rizin",
                    "executable": "/usr/bin/rizin",
                    "version": "rizin 0.8.2",
                    "command": "aaa;aflj;pdfj @@F;axlj"
                }
            ],
            "regions": [
                {
                    "start": "0x1000",
                    "end": "0x1100",
                    "attempts": [{
                        "producer": "radare2",
                        "status": "succeeded",
                        "stdout": {
                            "path": "thumb/00001000.radare2.stdout",
                            "bytes": 256,
                            "blake3": "0000000000000000000000000000000000000000000000000000000000000000"
                        },
                        "error": null
                    }],
                    "function_runs": [{
                        "producer": "radare2",
                        "first_function": 0,
                        "function_count": 1,
                        "substantial": 0,
                        "accepted": 1,
                        "quarantined": 0
                    }]
                },
                {
                    "start": "0x2000",
                    "end": "0x2100",
                    "attempts": [
                        {
                            "producer": "radare2",
                            "status": "failed",
                            "stdout": null,
                            "error": "radare2 exited with status 1 for Thumb region 0x2000"
                        },
                        {
                            "producer": "rizin",
                            "status": "succeeded",
                            "stdout": {
                                "path": "thumb/00002000.rizin.stdout",
                                "bytes": 512,
                                "blake3": "1111111111111111111111111111111111111111111111111111111111111111"
                            },
                            "error": null
                        }
                    ],
                    "function_runs": [{
                        "producer": "rizin",
                        "first_function": 1,
                        "function_count": 1,
                        "substantial": 1,
                        "accepted": 1,
                        "quarantined": 0
                    }]
                }
            ],
            "functions": [
                function("0x1000", "0x1002", 2),
                function("0x2000", "0x2020", 32)
            ]
        })
    }

    fn canonical_v3(document: &Value) -> Vec<u8> {
        format!(
            "{{\"format\":{},\"producers\":{},\"regions\":{},\"functions\":{}}}",
            serde_json::to_string(&document["format"]).unwrap(),
            serde_json::to_string(&document["producers"]).unwrap(),
            serde_json::to_string(&document["regions"]).unwrap(),
            serde_json::to_string(&document["functions"]).unwrap(),
        )
        .into_bytes()
    }

    fn authenticated_v3(runtime_bytes: &[u8]) -> Value {
        let mut document = valid_v3();
        for function in document["functions"].as_array_mut().unwrap() {
            for range in function["decode_ranges"].as_array_mut().unwrap() {
                let start =
                    canonical_hex_u32(range["start"].as_str().unwrap(), "test start").unwrap();
                let end = canonical_hex_u32(range["end"].as_str().unwrap(), "test end").unwrap();
                let start = usize::try_from(start - 0x1000).unwrap();
                let end = usize::try_from(end - 0x1000).unwrap();
                range["blake3"] = json!(
                    blake3::hash(&runtime_bytes[start..end])
                        .to_hex()
                        .to_string()
                );
            }
        }
        document
    }

    #[test]
    fn v3_function_exposes_region_and_run_owner() {
        let runtime_bytes = vec![0u8; 0x1100];
        let runtime = RuntimeImage::from_plan(&runtime_bytes, 0x1000, None).unwrap();
        let bytes = canonical_v3(&authenticated_v3(&runtime_bytes));

        let artifact = super::parse_thumb_artifact(&bytes, &runtime).unwrap();
        let owners = artifact
            .functions()
            .map(|function| function.owner)
            .collect::<Vec<_>>();

        assert_eq!(
            owners,
            [
                FunctionOwner::Run {
                    producer: AnalysisTool::Radare2,
                    region_index: 0,
                    run_index: 0,
                },
                FunctionOwner::Run {
                    producer: AnalysisTool::Rizin,
                    region_index: 1,
                    run_index: 0,
                },
            ]
        );
    }

    #[test]
    fn v3_missing_or_wrong_range_hash_is_rejected() {
        let runtime_bytes = vec![0u8; 0x1100];
        let runtime = RuntimeImage::from_plan(&runtime_bytes, 0x1000, None).unwrap();
        let mut missing = valid_v3();
        missing["functions"][0]["decode_ranges"][0]
            .as_object_mut()
            .unwrap()
            .remove("blake3");
        let missing = canonical_v3(&missing);
        assert!(super::parse_thumb_artifact(&missing, &runtime).is_err());

        let mut wrong = authenticated_v3(&runtime_bytes);
        wrong["functions"][0]["decode_ranges"][0]["blake3"] = json!("00".repeat(32));
        assert!(super::parse_thumb_artifact(&canonical_v3(&wrong), &runtime).is_err());
    }

    #[test]
    fn legacy_explicit_ranges_are_hashed_in_memory_through_runtime_image() {
        let runtime_bytes = [1u8, 2, 3, 4];
        let runtime = RuntimeImage::from_plan(&runtime_bytes, 0x1000, None).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("thumb_functions.json");
        std::fs::write(
            &path,
            br#"{"format":"pixel-modem-extractor-thumb-functions-v2","functions":[{"name":"thumb_1000","entry":"0x1000","end":"0x1004","size":4,"body_kind":"thumb_disassembly","body":"","data_refs":[],"decode_ranges":[{"isa":"thumb","start":"0x1000","end":"0x1004"}]}]}"#,
        )
        .unwrap();

        let functions = super::read_thumb_functions_streaming(&path, &runtime).unwrap();
        let function = &functions[0];
        let execution = function.execution.as_ref().unwrap();
        assert_eq!(
            function.owner,
            FunctionOwner::Legacy {
                producer: AnalysisTool::Radare2
            }
        );
        assert_eq!(
            execution.decode_ranges[0].blake3,
            *blake3::hash(&runtime_bytes).as_bytes()
        );
        assert_ne!(execution.execution_blake3, [0; 32]);
    }

    #[test]
    fn legacy_enrichment_is_rejected_without_rewriting_source_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("thumb_functions.json");
        let source = br#"{"format":"pixel-modem-extractor-thumb-functions-v1","functions":[{"name":"thumb_1000","entry":"0x1000"}]}"#;
        std::fs::write(&path, source).unwrap();

        let error = stream_rewrite_thumb_functions(&path, &test_runtime(), |_, _, function| {
            function["body_c"] = json!("void thumb_1000(void) {}");
            Ok(())
        })
        .unwrap_err();

        assert!(error.to_string().contains("read-only"), "{error}");
        assert_eq!(std::fs::read(path).unwrap(), source);
    }

    #[test]
    fn v3_mutation_preserves_owner_and_authenticated_ranges() {
        let runtime_bytes = vec![0u8; 0x1100];
        let runtime = RuntimeImage::from_plan(&runtime_bytes, 0x1000, None).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("thumb_functions.json");
        std::fs::write(&path, canonical_v3(&authenticated_v3(&runtime_bytes))).unwrap();
        let before = super::read_thumb_functions_streaming(&path, &runtime).unwrap();
        let expected = before
            .iter()
            .map(|function| (function.owner, function.execution.clone()))
            .collect::<Vec<_>>();
        let mut seen = Vec::new();

        stream_rewrite_thumb_functions(&path, &runtime, |owner, _, function| {
            seen.push(owner);
            function["annotations"] = json!(["generated fixture"]);
            Ok(())
        })
        .unwrap();

        let after = super::read_thumb_functions_streaming(&path, &runtime).unwrap();
        assert_eq!(
            seen,
            expected.iter().map(|(owner, _)| *owner).collect::<Vec<_>>()
        );
        assert_eq!(
            after
                .iter()
                .map(|function| (function.owner, function.execution.clone()))
                .collect::<Vec<_>>(),
            expected
        );
    }

    #[test]
    fn v3_run_totals_are_derived_from_validated_metadata() {
        let artifact = parse_thumb_artifact(ParsedThumbArtifact::consumer_v3_fixture()).unwrap();
        assert_eq!(artifact.validated_v3_run_totals(), Some((1, 1, 1)));
    }

    #[test]
    fn parsed_artifact_hashes_the_exact_source_bytes() {
        let bytes = ParsedThumbArtifact::consumer_v3_fixture();
        let artifact = parse_thumb_artifact(bytes).unwrap();
        assert_eq!(
            artifact.source_blake3(),
            crate::manifest::blake3_bytes(bytes)
        );
    }

    #[test]
    fn v3_parser_resolves_function_owners_from_runs() {
        let bytes = canonical_v3(&valid_v3());
        let artifact = parse_thumb_artifact(&bytes).unwrap();
        let owned: Vec<_> = artifact
            .functions()
            .map(|function| (function.owner, function.value["entry"].as_str().unwrap()))
            .collect();
        assert_eq!(
            owned,
            vec![
                (
                    FunctionOwner::Run {
                        producer: AnalysisTool::Radare2,
                        region_index: 0,
                        run_index: 0,
                    },
                    "0x1000",
                ),
                (
                    FunctionOwner::Run {
                        producer: AnalysisTool::Rizin,
                        region_index: 1,
                        run_index: 0,
                    },
                    "0x2000",
                )
            ]
        );
        assert!(
            artifact
                .functions()
                .all(|function| function.execution.is_some())
        );
    }

    #[test]
    fn v3_run_cursor_never_rescans_earlier_runs() {
        const RUNS: usize = 4_096;
        let layout = V3Layout {
            runs: (0..RUNS)
                .map(|index| {
                    let producer = if index.is_multiple_of(2) {
                        ThumbProducer::Radare2
                    } else {
                        ThumbProducer::Rizin
                    };
                    V3RunDescriptor {
                        record: FunctionRunRecord {
                            producer,
                            first_function: index,
                            function_count: 1,
                            substantial: 0,
                            accepted: 1,
                            quarantined: 0,
                        },
                        owner: FunctionOwner::Run {
                            producer: AnalysisTool::from(producer),
                            region_index: index,
                            run_index: 0,
                        },
                    }
                })
                .collect(),
            function_count: RUNS,
        };
        let mut cursor = V3RunCursor::default();

        for function_index in 0..RUNS {
            let run_index = cursor.owner_index(&layout.runs, function_index).unwrap();
            assert_eq!(run_index, function_index);
        }
        assert_eq!(cursor.owner_index(&layout.runs, RUNS), None);
        assert!(
            cursor.inspected_runs() <= RUNS * 2,
            "cursor inspected {} runs for {RUNS} functions",
            cursor.inspected_runs()
        );

        let mut empty = V3RunCursor::default();
        assert_eq!(empty.owner_index(&[], 0), None);
        assert_eq!(empty.inspected_runs(), 0);
    }

    #[test]
    fn v3_parser_rejects_empty_or_successless_documents() {
        let cases = ["producers", "regions", "functions", "successful_run"];
        for case in cases {
            let mut document = valid_v3();
            match case {
                "producers" | "regions" | "functions" => {
                    document[case] = json!([]);
                }
                "successful_run" => {
                    for region in document["regions"].as_array_mut().unwrap() {
                        region["function_runs"] = json!([]);
                        for attempt in region["attempts"].as_array_mut().unwrap() {
                            attempt["status"] = json!("failed");
                            attempt["stdout"] = Value::Null;
                            attempt["error"] = json!("backend failed");
                        }
                    }
                }
                _ => unreachable!(),
            }
            assert!(
                parse_thumb_artifact(&canonical_v3(&document)).is_err(),
                "accepted empty/successless case {case}"
            );
        }
        assert!(parse_thumb_artifact(b"").is_err());
    }

    #[test]
    fn v3_parser_rejects_unknown_duplicate_and_out_of_order_top_level_fields() {
        let valid = String::from_utf8(canonical_v3(&valid_v3())).unwrap();
        let unknown = valid.replacen("{\"format\":", "{\"unknown\":0,\"format\":", 1);
        let duplicate = valid.replacen(
            "{\"format\":",
            "{\"format\":\"pixel-modem-extractor-thumb-functions-v3\",\"format\":",
            1,
        );
        let out_of_order = format!(
            "{{\"producers\":{},\"format\":{},\"regions\":{},\"functions\":{}}}",
            serde_json::to_string(&valid_v3()["producers"]).unwrap(),
            serde_json::to_string(&valid_v3()["format"]).unwrap(),
            serde_json::to_string(&valid_v3()["regions"]).unwrap(),
            serde_json::to_string(&valid_v3()["functions"]).unwrap(),
        );
        let missing_producers = format!(
            "{{\"format\":{},\"regions\":{},\"functions\":{}}}",
            serde_json::to_string(&valid_v3()["format"]).unwrap(),
            serde_json::to_string(&valid_v3()["regions"]).unwrap(),
            serde_json::to_string(&valid_v3()["functions"]).unwrap(),
        );
        let missing_regions = format!(
            "{{\"format\":{},\"producers\":{},\"functions\":{}}}",
            serde_json::to_string(&valid_v3()["format"]).unwrap(),
            serde_json::to_string(&valid_v3()["producers"]).unwrap(),
            serde_json::to_string(&valid_v3()["functions"]).unwrap(),
        );
        let missing_functions = format!(
            "{{\"format\":{},\"producers\":{},\"regions\":{}}}",
            serde_json::to_string(&valid_v3()["format"]).unwrap(),
            serde_json::to_string(&valid_v3()["producers"]).unwrap(),
            serde_json::to_string(&valid_v3()["regions"]).unwrap(),
        );
        for (case, bytes) in [
            ("unknown", unknown.as_bytes()),
            ("duplicate", duplicate.as_bytes()),
            ("out_of_order", out_of_order.as_bytes()),
            ("missing_producers", missing_producers.as_bytes()),
            ("missing_regions", missing_regions.as_bytes()),
            ("missing_functions", missing_functions.as_bytes()),
        ] {
            assert!(
                parse_thumb_artifact(bytes).is_err(),
                "accepted {case} top-level fields"
            );
        }
    }

    #[test]
    fn v3_parser_rejects_duplicate_nested_fields_before_value_materialization() {
        let valid = String::from_utf8(canonical_v3(&valid_v3())).unwrap();
        let duplicate = valid.replacen("\"bytes\":256", "\"bytes\":255,\"bytes\":256", 1);
        assert!(
            parse_thumb_artifact(duplicate.as_bytes()).is_err(),
            "an intermediate Value erased a duplicate stdout field"
        );
    }

    #[test]
    fn v3_parser_rejects_duplicate_producers_and_invalid_attempt_order() {
        let mut duplicate = valid_v3();
        let producer = duplicate["producers"][0].clone();
        duplicate["producers"]
            .as_array_mut()
            .unwrap()
            .push(producer);

        let mut invalid_order = valid_v3();
        invalid_order["regions"][1]["attempts"]
            .as_array_mut()
            .unwrap()
            .swap(0, 1);

        for (case, document) in [
            ("duplicate producer", duplicate),
            ("attempt order", invalid_order),
        ] {
            assert!(
                parse_thumb_artifact(&canonical_v3(&document)).is_err(),
                "accepted invalid {case}"
            );
        }
    }

    #[test]
    fn v3_parser_rejects_noncanonical_executable_path_spelling() {
        for executable in [
            "/usr//bin/r2",
            "/usr/bin/r2/",
            r"\\?\C:\tools\\r2.exe",
            r"\\?\C:\tools\r2.exe\",
            r"\\?\C:\tools\.\r2.exe",
            r"\\?\C:tools\r2.exe",
            r"C:\tools\r2.exe",
        ] {
            let mut document = valid_v3();
            document["producers"][0]["executable"] = json!(executable);

            let error = parse_thumb_artifact(&canonical_v3(&document)).unwrap_err();

            assert!(
                error.to_string().contains("canonical absolute path"),
                "accepted {executable:?}: {error}"
            );
        }
    }

    #[test]
    fn v3_parser_accepts_canonical_executable_paths_from_both_host_families() {
        let mut document = valid_v3();
        document["producers"][0]["executable"] = json!("/usr/bin/r2");
        document["producers"][1]["executable"] = json!(r"\\?\C:\tools\rizin.exe");
        assert!(parse_thumb_artifact(&canonical_v3(&document)).is_ok());

        document["producers"][1]["executable"] = json!(r"\\?\UNC\server\share\tools\rizin.exe");
        assert!(parse_thumb_artifact(&canonical_v3(&document)).is_ok());
    }

    /// Region ledgers describe analyzer input and must be byte-backed. Function
    /// envelopes are metadata only; execution authority comes from exact ranges.
    #[test]
    fn image_aware_consumers_reject_unmapped_regions_not_metadata_envelopes() {
        let dir = tempfile::tempdir().unwrap();
        let runtime_bytes = vec![0u8; 0x1100];
        let runtime = RuntimeImage::from_plan(&runtime_bytes, 0x1000, None).unwrap();

        let mut out_of_image_region = valid_v3();
        out_of_image_region["regions"][1]["start"] = json!("0x9000");
        out_of_image_region["regions"][1]["end"] = json!("0x9100");
        out_of_image_region["regions"][1]["attempts"][1]["stdout"]["path"] =
            json!("thumb/00009000.rizin.stdout");

        let mut out_of_image_envelope = valid_v3();
        out_of_image_envelope["functions"][1]["end"] = json!("0x9000");

        let bytes = canonical_v3(&out_of_image_region);
        let path = dir.path().join("region-ledger.json");
        std::fs::write(&path, &bytes).unwrap();
        for error in [
            super::parse_thumb_artifact(&bytes, &runtime).unwrap_err(),
            super::read_thumb_functions_streaming(&path, &runtime).unwrap_err(),
        ] {
            assert!(
                error
                    .to_string()
                    .contains("region 1 is outside runtime image")
            );
        }

        let bytes = canonical_v3(&out_of_image_envelope);
        let path = dir.path().join("function-envelope.json");
        std::fs::write(&path, &bytes).unwrap();
        super::parse_thumb_artifact(&bytes, &runtime).unwrap();
        super::read_thumb_functions_streaming(&path, &runtime).unwrap();
    }

    /// Discovery caps a version at the first 1,024 stdout bytes, so a longer
    /// one cannot be a truthful producer identity.
    #[test]
    fn v3_parser_rejects_versions_beyond_the_discovery_bound() {
        let mut accepted = valid_v3();
        accepted["producers"][0]["version"] = json!("v".repeat(1_024));
        assert!(parse_thumb_artifact(&canonical_v3(&accepted)).is_ok());

        let mut oversized = valid_v3();
        oversized["producers"][0]["version"] = json!("v".repeat(1_025));

        let error = parse_thumb_artifact(&canonical_v3(&oversized)).unwrap_err();

        assert!(
            error.to_string().contains("1024-byte discovery bound"),
            "{error}"
        );
    }

    /// Producer executables are identities discovery could have produced, so
    /// spellings a version probe can never yield are rejected on both hosts.
    #[test]
    fn v3_parser_rejects_windows_reserved_and_malformed_prefix_executables() {
        for executable in [
            r"\\?\C:\tools\CON",
            r"\\?\C:\tools\nul.exe",
            r"\\?\C:\tools\rizin.exe ",
            r"\\?\C:\tools\ri*zin.exe",
            r"\\?\CON\rizin.exe",
            r"\\?\UNC\PRN\share\rizin.exe",
        ] {
            let mut document = valid_v3();
            document["producers"][0]["executable"] = json!(executable);

            let error = parse_thumb_artifact(&canonical_v3(&document)).unwrap_err();

            assert!(
                error.to_string().contains("canonical absolute path"),
                "accepted {executable:?}: {error}"
            );
        }
    }

    #[test]
    fn v3_parser_enforces_attempt_status_payloads() {
        let mut null_stdout = valid_v3();
        null_stdout["regions"][0]["attempts"][0]["stdout"] = Value::Null;

        let mut success_error = valid_v3();
        success_error["regions"][0]["attempts"][0]["error"] = json!("unexpected");

        let mut empty_failure = valid_v3();
        empty_failure["regions"][1]["attempts"][0]["error"] = json!("");

        for (case, document) in [
            ("null success stdout", null_stdout),
            ("non-null success error", success_error),
            ("empty failure error", empty_failure),
        ] {
            assert!(
                parse_thumb_artifact(&canonical_v3(&document)).is_err(),
                "accepted {case}"
            );
        }
    }

    #[test]
    fn v3_parser_rejects_failed_attempt_run_ownership() {
        let mut document = valid_v3();
        document["regions"][0]["attempts"][0]["status"] = json!("failed");
        document["regions"][0]["attempts"][0]["stdout"] = Value::Null;
        document["regions"][0]["attempts"][0]["error"] = json!("failed");
        assert!(parse_thumb_artifact(&canonical_v3(&document)).is_err());
    }

    #[test]
    fn v3_parser_rejects_run_gaps_overlaps_and_count_mismatches() {
        let mut gap = valid_v3();
        gap["regions"][1]["function_runs"][0]["first_function"] = json!(2);

        let mut overlap = valid_v3();
        overlap["regions"][1]["function_runs"][0]["first_function"] = json!(0);

        let mut stored_count = valid_v3();
        stored_count["regions"][1]["function_runs"][0]["substantial"] = json!(0);

        let mut conserving_count = valid_v3();
        conserving_count["regions"][1]["function_runs"][0]["accepted"] = json!(0);

        for (case, document) in [
            ("gap", gap),
            ("overlap", overlap),
            ("stored count", stored_count),
            ("non-conserving count", conserving_count),
        ] {
            assert!(
                parse_thumb_artifact(&canonical_v3(&document)).is_err(),
                "accepted run {case}"
            );
        }
    }

    #[test]
    fn v3_parser_rejects_noncanonical_function_execution_fields() {
        for case in [
            "reversed_range",
            "missing_entry_range",
            "duplicate_data_ref",
            "unsorted_errors",
        ] {
            let mut document = valid_v3();
            match case {
                "reversed_range" => {
                    document["functions"][0]["decode_ranges"] =
                        json!([{"end":"0x1000","isa":"thumb","start":"0x1002"}]);
                }
                "missing_entry_range" => {
                    document["functions"][0]["decode_ranges"] =
                        json!([{"end":"0x1004","isa":"thumb","start":"0x1002"}]);
                }
                "duplicate_data_ref" => {
                    document["functions"][0]["data_refs"] = json!(["0x3000", "0x3000"]);
                }
                "unsorted_errors" => {
                    document["functions"][0]["decode_ranges"] = json!([]);
                    document["functions"][0]["decode_range_errors"] = json!([
                        {"kind":"missing_operation_body","address":"0x1002","end":null},
                        {"kind":"missing_operation_body","address":"0x1000","end":null}
                    ]);
                    document["regions"][0]["function_runs"][0]["accepted"] = json!(0);
                    document["regions"][0]["function_runs"][0]["quarantined"] = json!(1);
                }
                _ => unreachable!(),
            }
            assert!(
                parse_thumb_artifact(&canonical_v3(&document)).is_err(),
                "accepted noncanonical {case}"
            );
        }
    }

    #[test]
    fn v3_parser_rejects_decode_range_above_function_end() {
        let mut document = valid_v3();
        document["functions"][0]["decode_ranges"][0]["end"] = json!("0x1004");

        let error = parse_thumb_artifact(&canonical_v3(&document)).unwrap_err();
        assert_eq!(
            error.to_string(),
            "serialize: invalid Thumb artifact: function 0 decode range 0 exceeds function end"
        );
    }

    #[test]
    fn v3_parser_rejects_null_optional_function_fields() {
        for field in ["original_name", "annotations", "body_c"] {
            let mut document = valid_v3();
            document["functions"][0][field] = Value::Null;
            assert!(
                parse_thumb_artifact(&canonical_v3(&document)).is_err(),
                "accepted null optional field {field}"
            );
        }
    }

    #[test]
    fn v3_parser_accepts_discontiguous_ranges_below_the_entry() {
        let mut document = valid_v3();
        document["functions"][0]["entry"] = json!("0x1010");
        document["functions"][0]["end"] = json!("0x1012");
        document["functions"][0]["decode_ranges"] = json!([
            {"end":"0x1002","isa":"thumb","start":"0x1000","blake3":"1ad48f49627079d806b802c74f40c39d55fe1d78b3faf0f8017aec62cec42122"},
            {"end":"0x1012","isa":"thumb","start":"0x1010","blake3":"1ad48f49627079d806b802c74f40c39d55fe1d78b3faf0f8017aec62cec42122"}
        ]);
        let artifact = parse_thumb_artifact(&canonical_v3(&document)).unwrap();
        assert_eq!(
            artifact.function_values()[0]["decode_ranges"],
            document["functions"][0]["decode_ranges"]
        );
    }

    #[test]
    fn v3_parser_rejects_function_without_exactly_one_owner() {
        let mut document = valid_v3();
        document["functions"]
            .as_array_mut()
            .unwrap()
            .push(function("0x2040", "0x2042", 2));
        assert!(parse_thumb_artifact(&canonical_v3(&document)).is_err());
    }

    #[test]
    fn v3_parser_accepts_future_radare2_success_followed_by_rizin_runs() {
        let mut document = valid_v3();
        document["regions"] = json!([{
            "start": "0x1000",
            "end": "0x1100",
            "attempts": [
                {
                    "producer": "radare2",
                    "status": "succeeded",
                    "stdout": {
                        "path": "thumb/00001000.radare2.stdout",
                        "bytes": 256,
                        "blake3": "0000000000000000000000000000000000000000000000000000000000000000"
                    },
                    "error": null
                },
                {
                    "producer": "rizin",
                    "status": "succeeded",
                    "stdout": {
                        "path": "thumb/00001000.rizin.stdout",
                        "bytes": 512,
                        "blake3": "1111111111111111111111111111111111111111111111111111111111111111"
                    },
                    "error": null
                }
            ],
            "function_runs": [
                {
                    "producer": "radare2",
                    "first_function": 0,
                    "function_count": 1,
                    "substantial": 0,
                    "accepted": 1,
                    "quarantined": 0
                },
                {
                    "producer": "rizin",
                    "first_function": 1,
                    "function_count": 1,
                    "substantial": 1,
                    "accepted": 1,
                    "quarantined": 0
                }
            ]
        }]);

        let artifact = parse_thumb_artifact(&canonical_v3(&document)).unwrap();
        assert_eq!(
            artifact
                .functions()
                .map(|function| function.owner.analysis_tool())
                .collect::<Vec<_>>(),
            vec![AnalysisTool::Radare2, AnalysisTool::Rizin]
        );

        document["regions"][0]["attempts"][1]["status"] = json!("failed");
        document["regions"][0]["attempts"][1]["stdout"] = Value::Null;
        document["regions"][0]["attempts"][1]["error"] = json!("future union attempt failed");
        document["regions"][0]["function_runs"]
            .as_array_mut()
            .unwrap()
            .truncate(1);
        document["functions"].as_array_mut().unwrap().truncate(1);
        let artifact = parse_thumb_artifact(&canonical_v3(&document)).unwrap();
        assert_eq!(
            artifact
                .functions()
                .map(|function| function.owner.analysis_tool())
                .collect::<Vec<_>>(),
            vec![AnalysisTool::Radare2]
        );
    }

    fn spill_for(dir: &Path, name: &str, functions: &[Value]) -> Spill {
        let mut writer = SpillWriter::create(dir.join(name)).unwrap();
        for (index, function) in functions.iter().enumerate() {
            writer
                .push(index as u32, &render_fragment(function).unwrap())
                .unwrap();
        }
        writer.finish().unwrap()
    }

    #[test]
    fn v3_assembly_writes_exact_minimal_document_bytes() {
        let mut document = valid_v3();
        document["producers"].as_array_mut().unwrap().truncate(1);
        document["regions"].as_array_mut().unwrap().truncate(1);
        document["functions"].as_array_mut().unwrap().truncate(1);
        let artifact = parse_thumb_artifact(&canonical_v3(&document)).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let spill = spill_for(dir.path(), "radare2.frags", artifact.function_values());
        let mut output = Vec::new();
        assemble_v3_into(
            &mut output,
            &artifact.document.producers,
            &artifact.document.regions,
            &[&spill],
        )
        .unwrap();

        let expected = r#"{
  "format": "pixel-modem-extractor-thumb-functions-v3",
  "producers": [
    {
      "id": "radare2",
      "executable": "/usr/bin/r2",
      "version": "radare2 6.1.4",
      "command": "aaa;aflj;pdfj @@f"
    }
  ],
  "regions": [
    {
      "start": "0x1000",
      "end": "0x1100",
      "attempts": [
        {
          "producer": "radare2",
          "status": "succeeded",
          "stdout": {
            "path": "thumb/00001000.radare2.stdout",
            "bytes": 256,
            "blake3": "0000000000000000000000000000000000000000000000000000000000000000"
          },
          "error": null
        }
      ],
      "function_runs": [
        {
          "producer": "radare2",
          "first_function": 0,
          "function_count": 1,
          "substantial": 0,
          "accepted": 1,
          "quarantined": 0
        }
      ]
    }
  ],
  "functions": [
    {
      "name": "fcn.1000",
      "entry": "0x1000",
      "end": "0x1002",
      "size": 2,
      "body_kind": "thumb_disassembly",
      "body": "bx lr\n",
      "data_refs": [],
      "decode_ranges": [
        {
          "isa": "thumb",
          "start": "0x1000",
          "end": "0x1002",
          "blake3": "1ad48f49627079d806b802c74f40c39d55fe1d78b3faf0f8017aec62cec42122"
        }
      ],
      "decode_range_errors": []
    }
  ]
}"#;
        assert_eq!(output, expected.as_bytes());
    }

    #[test]
    fn v3_assembly_writes_exact_multi_region_document_bytes() {
        let artifact = parse_thumb_artifact(&canonical_v3(&valid_v3())).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let first = spill_for(
            dir.path(),
            "radare2.frags",
            &artifact.function_values()[..1],
        );
        let second = spill_for(dir.path(), "rizin.frags", &artifact.function_values()[1..]);
        let mut output = Vec::new();
        assemble_v3_into(
            &mut output,
            &artifact.document.producers,
            &artifact.document.regions,
            &[&first, &second],
        )
        .unwrap();

        let expected = r#"{
  "format": "pixel-modem-extractor-thumb-functions-v3",
  "producers": [
    {
      "id": "radare2",
      "executable": "/usr/bin/r2",
      "version": "radare2 6.1.4",
      "command": "aaa;aflj;pdfj @@f"
    },
    {
      "id": "rizin",
      "executable": "/usr/bin/rizin",
      "version": "rizin 0.8.2",
      "command": "aaa;aflj;pdfj @@F;axlj"
    }
  ],
  "regions": [
    {
      "start": "0x1000",
      "end": "0x1100",
      "attempts": [
        {
          "producer": "radare2",
          "status": "succeeded",
          "stdout": {
            "path": "thumb/00001000.radare2.stdout",
            "bytes": 256,
            "blake3": "0000000000000000000000000000000000000000000000000000000000000000"
          },
          "error": null
        }
      ],
      "function_runs": [
        {
          "producer": "radare2",
          "first_function": 0,
          "function_count": 1,
          "substantial": 0,
          "accepted": 1,
          "quarantined": 0
        }
      ]
    },
    {
      "start": "0x2000",
      "end": "0x2100",
      "attempts": [
        {
          "producer": "radare2",
          "status": "failed",
          "stdout": null,
          "error": "radare2 exited with status 1 for Thumb region 0x2000"
        },
        {
          "producer": "rizin",
          "status": "succeeded",
          "stdout": {
            "path": "thumb/00002000.rizin.stdout",
            "bytes": 512,
            "blake3": "1111111111111111111111111111111111111111111111111111111111111111"
          },
          "error": null
        }
      ],
      "function_runs": [
        {
          "producer": "rizin",
          "first_function": 1,
          "function_count": 1,
          "substantial": 1,
          "accepted": 1,
          "quarantined": 0
        }
      ]
    }
  ],
  "functions": [
    {
      "name": "fcn.1000",
      "entry": "0x1000",
      "end": "0x1002",
      "size": 2,
      "body_kind": "thumb_disassembly",
      "body": "bx lr\n",
      "data_refs": [],
      "decode_ranges": [
        {
          "isa": "thumb",
          "start": "0x1000",
          "end": "0x1002",
          "blake3": "1ad48f49627079d806b802c74f40c39d55fe1d78b3faf0f8017aec62cec42122"
        }
      ],
      "decode_range_errors": []
    },
    {
      "name": "fcn.2000",
      "entry": "0x2000",
      "end": "0x2020",
      "size": 32,
      "body_kind": "thumb_disassembly",
      "body": "bx lr\n",
      "data_refs": [],
      "decode_ranges": [
        {
          "isa": "thumb",
          "start": "0x2000",
          "end": "0x2020",
          "blake3": "2ada83c1819a5372dae1238fc1ded123c8104fdaa15862aaee69428a1820fcda"
        }
      ],
      "decode_range_errors": []
    }
  ]
}"#;
        assert_eq!(output, expected.as_bytes());
    }

    #[test]
    fn v3_assembly_rejects_empty_documents() {
        let mut output = Vec::new();
        assert!(assemble_v3_into(&mut output, &[], &[], &[]).is_err());
        assert!(output.is_empty());
    }

    #[test]
    fn v3_assembly_derives_run_counters_before_writing() {
        let artifact = parse_thumb_artifact(&canonical_v3(&valid_v3())).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let first = spill_for(
            dir.path(),
            "radare2.frags",
            &artifact.function_values()[..1],
        );
        let second = spill_for(dir.path(), "rizin.frags", &artifact.function_values()[1..]);
        let mut regions = artifact.document.regions.clone();
        regions[1].function_runs[0].substantial = 0;
        let mut output = Vec::new();
        assert!(
            assemble_v3_into(
                &mut output,
                &artifact.document.producers,
                &regions,
                &[&first, &second],
            )
            .is_err()
        );
        assert!(output.is_empty());
    }

    #[test]
    fn v3_assembly_rejects_duplicate_function_keys_before_output() {
        let mut document = valid_v3();
        document["producers"].as_array_mut().unwrap().truncate(1);
        document["regions"].as_array_mut().unwrap().truncate(1);
        document["functions"].as_array_mut().unwrap().truncate(1);
        let artifact = parse_thumb_artifact(&canonical_v3(&document)).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut writer = SpillWriter::create(dir.path().join("duplicate.frags")).unwrap();
        writer
            .push(
                0,
                r#"{"name":"wrong","name":"fcn.1000","entry":"0x1000","end":"0x1002","size":2,"body_kind":"thumb_disassembly","body":"bx lr\n","data_refs":[],"decode_ranges":[{"end":"0x1002","isa":"thumb","start":"0x1000"}],"decode_range_errors":[]}"#,
            )
            .unwrap();
        let spill = writer.finish().unwrap();
        let mut output = Vec::new();

        let error = assemble_v3_into(
            &mut output,
            &artifact.document.producers,
            &artifact.document.regions,
            &[&spill],
        )
        .unwrap_err();

        assert!(
            error.to_string().contains("duplicate field `name`"),
            "{error}"
        );
        assert!(output.is_empty());
    }

    #[test]
    fn v3_assembly_canonically_renders_valid_function_fragments() {
        let mut document = valid_v3();
        document["producers"].as_array_mut().unwrap().truncate(1);
        document["regions"].as_array_mut().unwrap().truncate(1);
        document["functions"].as_array_mut().unwrap().truncate(1);
        let artifact = parse_thumb_artifact(&canonical_v3(&document)).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut writer = SpillWriter::create(dir.path().join("noncanonical.frags")).unwrap();
        writer
            .push(
                0,
                r#"{"size":2,"name":"fcn.1000","entry":"0x1000","end":"0x1002","decode_ranges":[{"start":"0x1000","isa":"thumb","end":"0x1002","blake3":"1ad48f49627079d806b802c74f40c39d55fe1d78b3faf0f8017aec62cec42122"}],"decode_range_errors":[],"data_refs":[],"body_kind":"thumb_disassembly","body":"bx lr\n"}"#,
            )
            .unwrap();
        let spill = writer.finish().unwrap();
        let mut output = Vec::new();

        assemble_v3_into(
            &mut output,
            &artifact.document.producers,
            &artifact.document.regions,
            &[&spill],
        )
        .unwrap();

        let output = String::from_utf8(output).unwrap();
        let (_, function_suffix) = output.split_once("  \"functions\": [\n").unwrap();
        assert_eq!(
            function_suffix,
            r#"    {
      "name": "fcn.1000",
      "entry": "0x1000",
      "end": "0x1002",
      "size": 2,
      "body_kind": "thumb_disassembly",
      "body": "bx lr\n",
      "data_refs": [],
      "decode_ranges": [
        {
          "isa": "thumb",
          "start": "0x1000",
          "end": "0x1002",
          "blake3": "1ad48f49627079d806b802c74f40c39d55fe1d78b3faf0f8017aec62cec42122"
        }
      ],
      "decode_range_errors": []
    }
  ]
}"#
        );
    }

    #[test]
    fn v3_atomic_assembly_commits_before_removing_spills() {
        let artifact = parse_thumb_artifact(&canonical_v3(&valid_v3())).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let first = spill_for(
            dir.path(),
            "radare2.frags",
            &artifact.function_values()[..1],
        );
        let second = spill_for(dir.path(), "rizin.frags", &artifact.function_values()[1..]);
        let spill_paths = [first.path.clone(), second.path.clone()];
        let output = dir.path().join("thumb_functions.json");
        assemble_v3_atomic(
            &output,
            &artifact.document.producers,
            &artifact.document.regions,
            &[first, second],
        )
        .unwrap();
        parse_thumb_artifact(&std::fs::read(&output).unwrap()).unwrap();
        assert!(spill_paths.iter().all(|path| !path.exists()));

        let first = spill_for(
            dir.path(),
            "invalid-radare2.frags",
            &artifact.function_values()[..1],
        );
        let second = spill_for(
            dir.path(),
            "invalid-rizin.frags",
            &artifact.function_values()[1..],
        );
        let spill_paths = [first.path.clone(), second.path.clone()];
        let mut regions = artifact.document.regions.clone();
        regions[1].function_runs[0].accepted = 0;
        std::fs::write(&output, b"prior artifact").unwrap();
        assert!(
            assemble_v3_atomic(
                &output,
                &artifact.document.producers,
                &regions,
                &[first, second],
            )
            .is_err()
        );
        assert_eq!(std::fs::read(output).unwrap(), b"prior artifact");
        assert!(spill_paths.iter().all(|path| path.exists()));
    }

    #[test]
    fn v1_and_v2_readers_assign_legacy_radare2_ownership() {
        for format in [THUMB_V1_FORMAT, THUMB_V2_FORMAT] {
            let bytes = format!(
                "{{\"format\":\"{format}\",\"functions\":[{{\"entry\":\"0x1000\",\"legacy\":true}}]}}"
            );
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("thumb_functions.json");
            std::fs::write(&path, bytes).unwrap();
            let artifact = read_thumb_artifact(&path).unwrap();
            let function = artifact.functions().next().unwrap();
            assert_eq!(
                function.owner,
                FunctionOwner::Legacy {
                    producer: AnalysisTool::Radare2,
                }
            );
            assert!(function.execution.is_none());
            assert_eq!(function.value["legacy"], true);
        }
    }

    /// Retained v1/v2 artifacts predate the v3 semantic contract, and legacy
    /// symbolication defaulted `end`, `body`, and ignored `size`/`body_kind`.
    /// Typed loading must keep reading them; v3 stays strict through
    /// `FunctionWire`.
    #[test]
    fn typed_loading_defaults_legacy_fields_v3_still_requires() {
        for format in [THUMB_V1_FORMAT, THUMB_V2_FORMAT] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("thumb_functions.json");
            std::fs::write(
                &path,
                format!(
                    "{{\"format\":\"{format}\",\"functions\":[{{\"name\":\"thumb_1000\",\"entry\":\"0x1000\"}}]}}"
                ),
            )
            .unwrap();

            let functions = read_thumb_functions_streaming(&path).unwrap();

            assert_eq!(functions.len(), 1, "{format}");
            let owned = &functions[0];
            assert_eq!(
                owned.owner,
                FunctionOwner::Legacy {
                    producer: AnalysisTool::Radare2,
                }
            );
            assert!(owned.execution.is_none());
            assert_eq!(owned.function.name, "thumb_1000");
            assert_eq!(owned.function.end, "");
            assert_eq!(owned.function.size, 0);
            assert_eq!(owned.function.body_kind, "");
            assert_eq!(owned.function.body, "");
        }

        let mut incomplete = valid_v3();
        incomplete["functions"][0]
            .as_object_mut()
            .unwrap()
            .remove("end");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("thumb_functions.json");
        std::fs::write(&path, canonical_v3(&incomplete)).unwrap();

        assert!(
            read_thumb_functions_streaming(&path).is_err(),
            "v3 must still require the complete producer field set"
        );
    }

    #[test]
    fn atomic_mutation_skips_an_unmodified_artifact_byte_for_byte() {
        let original = canonical_v3(&valid_v3());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("thumb_functions.json");
        std::fs::write(&path, &original).unwrap();
        let artifact = read_thumb_artifact(&path).unwrap();
        artifact.write_atomic(&path).unwrap();
        assert_eq!(std::fs::read(path).unwrap(), original);

        let legacy_path = dir.path().join("legacy_thumb_functions.json");
        let legacy = br#"{"format":"pixel-modem-extractor-thumb-functions-v1","functions":[]}"#;
        std::fs::write(&legacy_path, legacy).unwrap();
        let artifact = read_thumb_artifact(&legacy_path).unwrap();
        artifact.write_atomic(&legacy_path).unwrap();
        assert_eq!(std::fs::read(legacy_path).unwrap(), legacy);
    }

    #[test]
    fn atomic_v3_mutation_writes_only_allowed_fields_and_preserves_provenance() {
        let original = canonical_v3(&valid_v3());
        let original_value: Value = serde_json::from_slice(&original).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("thumb_functions.json");
        std::fs::write(&path, original).unwrap();
        let mut artifact = read_thumb_artifact(&path).unwrap();
        let function = artifact.function_values_mut()[0].as_object_mut().unwrap();
        function.insert("name".into(), json!("recovered_name"));
        function.insert("original_name".into(), json!("fcn.1000"));
        function.insert("annotations".into(), json!(["source: foo.c"]));
        function.insert("body_c".into(), json!("void recovered_name(void) {}"));
        artifact.write_atomic(&path).unwrap();

        let bytes = std::fs::read(&path).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(
            text.find("\"format\"").unwrap() < text.find("\"producers\"").unwrap()
                && text.find("\"producers\"").unwrap() < text.find("\"regions\"").unwrap()
                && text.find("\"regions\"").unwrap() < text.find("\"functions\"").unwrap()
        );
        let rewritten: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(rewritten["format"], original_value["format"]);
        assert_eq!(rewritten["producers"], original_value["producers"]);
        assert_eq!(rewritten["regions"], original_value["regions"]);
        assert_eq!(rewritten["functions"].as_array().unwrap().len(), 2);
        assert_eq!(rewritten["functions"][0]["name"], "recovered_name");
        assert_eq!(rewritten["functions"][0]["original_name"], "fcn.1000");
        assert_eq!(
            rewritten["functions"][0]["annotations"],
            json!(["source: foo.c"])
        );
        assert_eq!(
            rewritten["functions"][0]["body_c"],
            "void recovered_name(void) {}"
        );
        parse_thumb_artifact(&bytes).unwrap();
    }

    #[test]
    fn atomic_v3_mutation_rejects_execution_and_unknown_field_changes() {
        for case in ["body", "unknown", "missing"] {
            let original = canonical_v3(&valid_v3());
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("thumb_functions.json");
            std::fs::write(&path, &original).unwrap();
            let mut artifact = read_thumb_artifact(&path).unwrap();
            let function = artifact.function_values_mut()[0].as_object_mut().unwrap();
            match case {
                "body" => {
                    function.insert("body".into(), json!("changed producer evidence"));
                }
                "unknown" => {
                    function.insert("extra".into(), json!(true));
                }
                "missing" => {
                    function.remove("decode_ranges");
                }
                _ => unreachable!(),
            }
            assert!(
                artifact.write_atomic(&path).is_err(),
                "accepted {case} mutation"
            );
            assert_eq!(
                std::fs::read(&path).unwrap(),
                original,
                "failed {case} mutation replaced the destination"
            );
        }
    }

    #[test]
    fn atomic_v3_mutation_rejects_removing_existing_enrichment() {
        let mut document = valid_v3();
        document["functions"][0]["body_c"] = json!("void fcn_1000(void) {}");
        let original = canonical_v3(&document);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("thumb_functions.json");
        std::fs::write(&path, &original).unwrap();
        let mut artifact = read_thumb_artifact(&path).unwrap();
        artifact.function_values_mut()[0]
            .as_object_mut()
            .unwrap()
            .remove("body_c");
        assert!(artifact.write_atomic(&path).is_err());
        assert_eq!(std::fs::read(path).unwrap(), original);
    }

    #[test]
    fn atomic_legacy_mutation_is_rejected_without_replacing_source() {
        for format in [THUMB_V1_FORMAT, THUMB_V2_FORMAT] {
            let original =
                format!("{{\"format\":\"{format}\",\"functions\":[{{\"entry\":\"0x1000\"}}]}}");
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("thumb_functions.json");
            std::fs::write(&path, &original).unwrap();
            let mut artifact = read_thumb_artifact(&path).unwrap();
            artifact.function_values_mut()[0]["body_c"] = json!("void f(void) {}");
            assert!(artifact.write_atomic(&path).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), original.as_bytes());
        }
    }

    #[test]
    fn array_rewrite_uses_the_validated_source_snapshot() {
        let source = br#"[{"entry":"0x1000","name":"validated"}]"#;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("functions.json");
        std::fs::write(&path, br#"[{"entry":"0x2000","name":"replacement"}]"#).unwrap();

        stream_rewrite_json_array(&path, source, |function| {
            function["annotations"] = json!(["authenticated"]);
            Ok(())
        })
        .unwrap();

        let rewritten: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(rewritten[0]["entry"], "0x1000");
        assert_eq!(rewritten[0]["name"], "validated");
        assert_eq!(rewritten[0]["annotations"], json!(["authenticated"]));
    }

    #[test]
    fn v3_streaming_validation_checks_metadata_owned_runs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("thumb_functions.json");
        std::fs::write(&path, canonical_v3(&valid_v3())).unwrap();
        let validated = validate_test_inventory(&path, 1).unwrap();
        assert_eq!(validated.metadata.format, ThumbFormat::V3);
        assert_eq!(
            validated
                .metadata
                .producers
                .iter()
                .map(|producer| producer.producer)
                .collect::<Vec<_>>(),
            [ThumbProducer::Radare2, ThumbProducer::Rizin]
        );
        assert_eq!(
            validated.metadata.regions,
            [(0x1000, 0x1100), (0x2000, 0x2100)]
        );
        assert_eq!(
            validated.metadata.summary,
            ThumbAnalysisSummary {
                regions_requested: 2,
                regions_succeeded: 2,
                regions_failed: 0,
                radare2_runs: 1,
                rizin_runs: 1,
                raw: 2,
                substantial: 1,
                accepted: 2,
                quarantined: 0,
            }
        );
        assert_eq!(validated.inventory.raw_count, 2);
        assert_eq!(validated.inventory.accepted, 2);
        assert_eq!(validated.inventory.quarantined, 0);
        assert_eq!(validated.inventory.records.len(), 2);
    }

    #[test]
    fn v3_streaming_validation_accepts_future_multiple_successful_runs() {
        let mut document = valid_v3();
        let rizin_attempt = document["regions"][1]["attempts"][1].clone();
        document["regions"][0]["attempts"]
            .as_array_mut()
            .unwrap()
            .push(rizin_attempt);
        document["regions"][0]["attempts"][1]["stdout"]["path"] =
            json!("thumb/00001000.rizin.stdout");
        let mut rizin_run = document["regions"][1]["function_runs"][0].clone();
        rizin_run["first_function"] = json!(1);
        document["regions"][0]["function_runs"]
            .as_array_mut()
            .unwrap()
            .push(rizin_run);
        document["regions"].as_array_mut().unwrap().truncate(1);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("thumb_functions.json");
        std::fs::write(&path, canonical_v3(&document)).unwrap();
        let validated = validate_test_inventory(&path, 1).unwrap();
        assert_eq!(validated.inventory.raw_count, 2);
        assert_eq!(validated.metadata.summary.substantial, 1);
        assert_eq!(validated.metadata.summary.regions_requested, 1);
        assert_eq!(validated.metadata.summary.regions_succeeded, 1);
        assert_eq!(validated.metadata.summary.radare2_runs, 1);
        assert_eq!(validated.metadata.summary.rizin_runs, 1);
    }

    #[test]
    fn v3_streaming_validation_rejects_stored_run_totals_at_eof() {
        let mut document = valid_v3();
        document["regions"][1]["function_runs"][0]["substantial"] = json!(0);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("thumb_functions.json");
        std::fs::write(&path, canonical_v3(&document)).unwrap();
        assert!(validate_test_inventory(&path, 1).is_err());
    }

    #[test]
    fn v3_streaming_validation_rejects_region_outside_the_mapped_image_first() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("thumb_functions.json");
        std::fs::write(&path, canonical_v3(&valid_v3())).unwrap();
        let image = [0u8; 0x100];
        let runtime = RuntimeImage::from_plan(&image, 0x1000, None).unwrap();
        let error = validate_thumb_inventory_streaming(&path, &runtime, 1).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("region 1 is outside runtime image"),
            "{error}"
        );
    }

    #[test]
    fn v3_streaming_validation_rejects_function_boundary_violations() {
        let cases = [
            (
                "accepted entry outside image",
                "bad scatter load map: runtime range crosses unmapped memory",
            ),
            ("end outside image", "accepted"),
            ("size exceeds image length", "accepted"),
            (
                "accepted range exceeds function end",
                "function 0 decode range 0 exceeds function end",
            ),
            ("quarantined entry outside image", "accepted"),
        ];
        let mut mismatches = Vec::new();

        for (case, expected) in cases {
            let mut document = valid_v3();
            let expected_substantial = match case {
                "accepted entry outside image" => {
                    document["functions"][0]["entry"] = json!("0x3000");
                    document["functions"][0]["end"] = json!("0x3002");
                    document["functions"][0]["decode_ranges"] = json!([{"end":"0x3002","isa":"thumb","start":"0x3000","blake3":"00".repeat(32)}]);
                    1
                }
                "end outside image" => {
                    document["functions"][0]["end"] = json!("0x3002");
                    1
                }
                "size exceeds image length" => {
                    document["functions"][0]["size"] = json!(0x2001u64);
                    document["regions"][0]["function_runs"][0]["substantial"] = json!(1);
                    2
                }
                "accepted range exceeds function end" => {
                    document["functions"][0]["decode_ranges"][0]["end"] = json!("0x1004");
                    document["functions"][0]["decode_ranges"][0]["blake3"] =
                        json!("ec2bd03bf86b935fa34d71ad7ebb049f1f10f87d343e521511d8f9e6625620cd");
                    1
                }
                "quarantined entry outside image" => {
                    document["functions"][0]["entry"] = json!("0x3000");
                    document["functions"][0]["end"] = json!("0x3002");
                    document["functions"][0]["decode_ranges"] = json!([]);
                    document["functions"][0]["decode_range_errors"] = json!([{
                        "kind":"missing_operation_body",
                        "address":"0x3000",
                        "end":null
                    }]);
                    document["regions"][0]["function_runs"][0]["accepted"] = json!(0);
                    document["regions"][0]["function_runs"][0]["quarantined"] = json!(1);
                    1
                }
                _ => unreachable!(),
            };
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("thumb_functions.json");
            std::fs::write(&path, canonical_v3(&document)).unwrap();
            let image = vec![0u8; 0x2000];
            let runtime = RuntimeImage::from_plan(&image, 0x1000, None).unwrap();
            let actual =
                match validate_thumb_inventory_streaming(&path, &runtime, expected_substantial) {
                    Ok(_) => "accepted".to_owned(),
                    Err(error) => error.to_string(),
                };
            let expected =
                if expected == "accepted" || expected.starts_with("bad scatter load map:") {
                    expected.to_owned()
                } else {
                    format!("serialize: invalid Thumb artifact: {expected}")
                };
            if actual != expected {
                mismatches.push(format!("{case}: expected {expected:?}, found {actual:?}"));
            }
        }

        assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    }

    #[test]
    fn v3_streaming_validation_accepts_mapped_ranges_below_entry() {
        let mut document = valid_v3();
        document["functions"][0]["entry"] = json!("0x1100");
        document["functions"][0]["end"] = json!("0x1102");
        document["functions"][0]["decode_ranges"] = json!([
            {"end":"0x1002","isa":"thumb","start":"0x1000","blake3":"1ad48f49627079d806b802c74f40c39d55fe1d78b3faf0f8017aec62cec42122"},
            {"end":"0x1102","isa":"thumb","start":"0x1100","blake3":"1ad48f49627079d806b802c74f40c39d55fe1d78b3faf0f8017aec62cec42122"}
        ]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("thumb_functions.json");
        std::fs::write(&path, canonical_v3(&document)).unwrap();

        let validated = validate_test_inventory(&path, 1).unwrap();
        assert_eq!(
            (
                validated.inventory.accepted,
                validated.metadata.summary.substantial
            ),
            (2, 1)
        );
    }

    #[test]
    fn v1_and_v2_streaming_validation_remain_supported() {
        let mut function = function("0x1000", "0x1002", 2);
        function["decode_ranges"][0]
            .as_object_mut()
            .unwrap()
            .remove("blake3");
        for format in [THUMB_V1_FORMAT, THUMB_V2_FORMAT] {
            let document = format!(
                "{{\"format\":\"{format}\",\"functions\":[{}]}}",
                serde_json::to_string(&function).unwrap()
            );
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("thumb_functions.json");
            std::fs::write(&path, document).unwrap();
            let validated = validate_test_inventory(&path, 0).unwrap();
            assert_eq!(validated.metadata.format.as_str(), format);
            assert!(validated.metadata.producers.is_empty());
            assert!(validated.metadata.regions.is_empty());
            assert_eq!(validated.metadata.summary.substantial, 0);
            assert_eq!(validated.inventory.raw_count, 1);
            assert_eq!(validated.inventory.accepted, 1);
        }
    }

    fn write_thumb_doc(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("thumb_functions.json");
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn legacy_streaming_validation_counts_match() {
        let dir = tempfile::tempdir().unwrap();
        let document = r#"{
  "format": "pixel-modem-extractor-thumb-functions-v2",
  "functions": [
    {"name":"thumb_a","entry":"0x4000","end":"0x4020","size":32,"body_kind":"thumb_disassembly","body":"","data_refs":[],"decode_ranges":[{"isa":"thumb","start":"0x4000","end":"0x4020"}],"decode_range_errors":[]},
    {"name":"thumb_b","entry":"0x5000","end":"0x5008","size":8,"body_kind":"thumb_disassembly","body":"","data_refs":[],"decode_ranges":[],"decode_range_errors":[{"kind":"missing_operation_body","address":"0x5000","end":null}]}
  ]
}"#;
        let path = write_thumb_doc(dir.path(), document);
        let validated = validate_test_inventory(&path, 1).unwrap();
        assert_eq!(validated.metadata.summary.substantial, 1);
        assert_eq!(validated.inventory.raw_count, 2);
        assert_eq!(validated.inventory.accepted, 1);
        assert_eq!(validated.inventory.quarantined, 1);
    }

    #[test]
    fn legacy_streaming_validation_preserves_error_strings() {
        let dir = tempfile::tempdir().unwrap();
        let format = THUMB_V2_FORMAT;
        let size_string = format!(r#"{{"format":"{format}","functions":[{{"size":"32"}}]}}"#);
        let size_small = format!(r#"{{"format":"{format}","functions":[{{"size":8}}]}}"#);
        let empty = format!(r#"{{"format":"{format}","functions":[]}}"#);
        let cases = [
            (
                r#"{"format":"pixel-modem-extractor-thumb-functions-v2"}"#,
                "Thumb functions inventory lacks functions array",
                0,
            ),
            (
                r#"{"functions":[]}"#,
                "unsupported Thumb functions inventory format",
                0,
            ),
            (
                r#"{"format":"wrong","functions":[]}"#,
                "unsupported Thumb functions inventory format",
                0,
            ),
            (
                size_string.as_str(),
                "Thumb function size must be an unsigned integer",
                0,
            ),
            (
                size_small.as_str(),
                "Thumb substantial count mismatch: expected 1, found 0",
                1,
            ),
            (
                empty.as_str(),
                "Thumb substantial count mismatch: expected 1, found 0",
                1,
            ),
        ];
        for (index, (document, message, expected)) in cases.iter().enumerate() {
            let path = write_thumb_doc(dir.path(), document);
            let error = validate_test_inventory(&path, *expected).unwrap_err();
            assert_eq!(
                error.to_string(),
                format!("serialize: {message}"),
                "case {index}"
            );
        }
        let path = write_thumb_doc(dir.path(), "[1,2]");
        let error = validate_test_inventory(&path, 0).unwrap_err();
        assert_eq!(
            error.to_string(),
            "serialize: Thumb functions inventory must be an object"
        );
    }

    fn legacy_whole_file_validation(
        path: &Path,
        expected_substantial: usize,
    ) -> Result<(ValidatedInventory, usize)> {
        let bytes = std::fs::read(path)?;
        let document: Value = serde_json::from_slice(&bytes).map_err(|error| {
            Error::Serialize(format!("parse Thumb functions inventory: {error}"))
        })?;
        let object = document.as_object().ok_or_else(|| {
            Error::Serialize("Thumb functions inventory must be an object".into())
        })?;
        if object.get("format").and_then(Value::as_str) != Some(THUMB_V2_FORMAT) {
            return Err(Error::Serialize(
                "unsupported Thumb functions inventory format".into(),
            ));
        }
        let records = object
            .get("functions")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                Error::Serialize("Thumb functions inventory lacks functions array".into())
            })?;
        let substantial = records.iter().try_fold(0usize, |count, record| {
            let size = record.get("size").and_then(Value::as_u64).ok_or_else(|| {
                Error::Serialize("Thumb function size must be an unsigned integer".into())
            })?;
            if size >= 32 {
                count
                    .checked_add(1)
                    .ok_or_else(|| Error::Serialize("Thumb substantial count overflow".into()))
            } else {
                Ok(count)
            }
        })?;
        if substantial != expected_substantial {
            return Err(Error::Serialize(format!(
                "Thumb substantial count mismatch: expected {expected_substantial}, found {substantial}"
            )));
        }
        let artifact = super::parse_thumb_artifact(&bytes, &test_runtime())?;
        let mut accepted_executions = BTreeSet::new();
        let mut tagged = Vec::with_capacity(records.len());
        let mut accepted = 0usize;
        let mut quarantined = 0usize;
        for function in artifact.functions() {
            let entry = canonical_hex_u32(
                function.value["entry"]
                    .as_str()
                    .ok_or_else(|| invalid_artifact("legacy function entry must be a string"))?,
                "legacy function entry",
            )?;
            let projection = match function.execution {
                Some(identity) => {
                    accepted += 1;
                    accepted_executions.insert(OwnedExecutionIdentity {
                        owner: function.owner,
                        identity: identity.clone(),
                    });
                    ExecutionProjection::Accepted(identity.decode_ranges.clone())
                }
                None => {
                    quarantined += 1;
                    legacy_non_execution_projection(function.value, entry)?
                }
            };
            tagged.push(TaggedExecutionRecord {
                owner: function.owner,
                entry,
                projection,
            });
        }
        let inventory = ValidatedInventory {
            raw_count: records.len(),
            accepted,
            quarantined,
            accepted_executions: accepted_executions.into_iter().collect(),
            records: tagged,
        };
        Ok((inventory, substantial))
    }

    #[test]
    fn legacy_streaming_validation_matches_the_whole_file_oracle() {
        let dir = tempfile::tempdir().unwrap();
        let valid = r#"{
  "format": "pixel-modem-extractor-thumb-functions-v2",
  "functions": [
    {"name":"thumb_a","entry":"0x4000","end":"0x4020","size":32,"body_kind":"thumb_disassembly","body":"","data_refs":[],"decode_ranges":[{"isa":"thumb","start":"0x4000","end":"0x4020"}],"decode_range_errors":[]},
    {"name":"thumb_b","entry":"0x5000","end":"0x5008","size":8,"body_kind":"thumb_disassembly","body":"","data_refs":[],"decode_ranges":[],"decode_range_errors":[{"kind":"missing_operation_body","address":"0x5000","end":null}]}
  ]
}"#;
        let path = write_thumb_doc(dir.path(), valid);
        let whole = legacy_whole_file_validation(&path, 1).unwrap();
        let streaming = validate_test_inventory(&path, 1)
            .map(|validated| (validated.inventory, validated.metadata.summary.substantial))
            .unwrap();
        assert_eq!(whole, streaming);

        let format = THUMB_V2_FORMAT;
        let size_string = format!(r#"{{"format":"{format}","functions":[{{"size":"32"}}]}}"#);
        let size_small = format!(r#"{{"format":"{format}","functions":[{{"size":8}}]}}"#);
        let size_only = format!(r#"{{"format":"{format}","functions":[{{"size":32}}]}}"#);
        let trailing = format!(r#"{{"format":"{format}","functions":[]}} trailing"#);
        let cases = [
            (
                r#"{"format":"pixel-modem-extractor-thumb-functions-v2"}"#,
                0,
            ),
            (r#"{"functions":[]}"#, 0),
            (r#"{"format":"wrong","functions":[]}"#, 0),
            (size_string.as_str(), 0),
            (size_small.as_str(), 1),
            (size_only.as_str(), 1),
            ("[1,2]", 0),
            ("", 0),
            (trailing.as_str(), 0),
        ];
        for (index, (document, expected)) in cases.iter().enumerate() {
            let path = write_thumb_doc(dir.path(), document);
            let whole =
                legacy_whole_file_validation(&path, *expected).map_err(|error| error.to_string());
            let streaming = validate_test_inventory(&path, *expected)
                .map(|validated| (validated.inventory, validated.metadata.summary.substantial))
                .map_err(|error| error.to_string());
            assert_eq!(whole, streaming, "case {index}");
        }
    }

    #[test]
    fn legacy_streaming_validation_rejects_out_of_order_wrapper_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_thumb_doc(
            dir.path(),
            r#"{"functions":[],"format":"pixel-modem-extractor-thumb-functions-v2"}"#,
        );
        let error = validate_test_inventory(&path, 0).unwrap_err();
        assert_eq!(
            error.to_string(),
            "serialize: unsupported Thumb functions inventory format"
        );
    }
}
