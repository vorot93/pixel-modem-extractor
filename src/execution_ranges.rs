use crate::analysis_tool::AnalysisTool;
use crate::error::{Error, Result};
use crate::runtime_image::RuntimeImage;
use serde::de::{self, Deserializer, SeqAccess, Visitor};
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;

pub(crate) const MAX_EXECUTION_FUNCTIONS: usize = 262_144;
pub(crate) const MAX_EXECUTION_RANGES: usize = 1_048_576;
pub(crate) const MAX_EXECUTION_RANGES_PER_FUNCTION: usize = 65_536;
pub(crate) const MAX_EXECUTION_CHARGED_BYTES: u64 = 512 * 1024 * 1024;
const EXECUTION_DIGEST_DOMAIN: &[u8] = b"pixel-modem-extractor-execution-v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum DecodeIsa {
    Arm,
    Thumb,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct DecodeExtent {
    pub start: u32,
    pub end: u32,
    pub isa: DecodeIsa,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct AuthenticatedDecodeRange {
    pub isa: DecodeIsa,
    pub start: u32,
    pub end: u32,
    pub blake3: [u8; 32],
}

#[derive(Debug, Default)]
pub(crate) struct ExecutionBudget {
    functions: usize,
    ranges: usize,
    charged_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum FunctionOwner {
    Ghidra,
    Legacy {
        producer: AnalysisTool,
    },
    Run {
        producer: AnalysisTool,
        region_index: usize,
        run_index: usize,
    },
}

impl FunctionOwner {
    pub(crate) const fn analysis_tool(self) -> AnalysisTool {
        match self {
            Self::Ghidra => AnalysisTool::Ghidra,
            Self::Legacy { producer } | Self::Run { producer, .. } => producer,
        }
    }
}

/// Identity of one recovered-function evidence claim: the concrete owner,
/// the entry address, and the authenticated execution digest when the
/// inventory carried one. Shared by source attribution (recovered index
/// writer and reader) and the DBT exact index; `execution_blake3` is `None`
/// whenever the binding artifact does not carry an execution digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct FunctionEvidenceKey {
    pub(crate) owner: FunctionOwner,
    pub(crate) entry: u64,
    pub(crate) execution_blake3: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct OwnedExecutionIdentity {
    pub owner: FunctionOwner,
    pub identity: ExecutionIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum DecodeRangeErrorKind {
    MissingInstructionAtEntry,
    MissingIsaContext,
    InvalidIsaContext,
    OverriddenInstructionLength,
    InvalidInstructionLength,
    MisalignedInstruction,
    ExtentOutsideFunction,
    ExtentOutsideImage,
    MissingOperationBody,
    InvalidOperationAddress,
    InvalidOperationBytes,
    RawByteMismatch,
    DuplicateExtent,
    OverlappingExtent,
    EntryNotRangeStart,
    EmptyProjection,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct DecodeRangeError {
    pub kind: DecodeRangeErrorKind,
    pub address: u32,
    pub end: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ExecutionProjection {
    Accepted(Vec<AuthenticatedDecodeRange>),
    Quarantined(Vec<DecodeRangeError>),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ExecutionIdentity {
    pub entry: u32,
    pub decode_ranges: Vec<AuthenticatedDecodeRange>,
    pub execution_blake3: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct TaggedExecutionRecord {
    pub owner: FunctionOwner,
    pub entry: u32,
    pub projection: ExecutionProjection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValidatedInventory {
    pub raw_count: usize,
    pub accepted: usize,
    pub quarantined: usize,
    pub accepted_executions: Vec<OwnedExecutionIdentity>,
    pub records: Vec<TaggedExecutionRecord>,
}

pub(crate) fn error(
    kind: DecodeRangeErrorKind,
    address: u32,
    end: Option<u32>,
) -> DecodeRangeError {
    DecodeRangeError { kind, address, end }
}

pub(crate) fn canonicalize_errors(mut errors: Vec<DecodeRangeError>) -> Vec<DecodeRangeError> {
    errors.sort_unstable_by(|left, right| {
        (left.address, error_kind_name(left.kind), left.end).cmp(&(
            right.address,
            error_kind_name(right.kind),
            right.end,
        ))
    });
    errors.dedup();
    errors
}

/// Canonicalize producer instruction extents without treating an address
/// envelope as mapped execution. Runtime authentication happens only after this
/// geometry is exact.
pub(crate) fn canonicalize_instruction_extents(
    entry: u32,
    mut extents: Vec<DecodeExtent>,
) -> std::result::Result<Vec<DecodeExtent>, Vec<DecodeRangeError>> {
    let mut errors = Vec::new();
    for extent in &extents {
        let length = extent.end.checked_sub(extent.start);
        if length.is_none_or(|length| length == 0) {
            errors.push(error(
                DecodeRangeErrorKind::InvalidInstructionLength,
                extent.start,
                Some(extent.end),
            ));
        }
        let aligned = match extent.isa {
            DecodeIsa::Arm => {
                extent.start.is_multiple_of(4)
                    && length.is_some_and(|length| length.is_multiple_of(4))
            }
            DecodeIsa::Thumb => {
                extent.start.is_multiple_of(2)
                    && length.is_some_and(|length| length.is_multiple_of(2))
            }
        };
        if !aligned {
            errors.push(error(
                DecodeRangeErrorKind::MisalignedInstruction,
                extent.start,
                Some(extent.end),
            ));
        }
    }
    extents.sort_unstable_by_key(|extent| (extent.start, extent.end, extent.isa));
    let mut maximal_prior = extents.first().copied();
    for index in 1..extents.len() {
        let current = extents[index];
        let previous = extents[index - 1];
        if (current.start, current.end) == (previous.start, previous.end) {
            errors.push(error(
                DecodeRangeErrorKind::DuplicateExtent,
                current.start,
                Some(current.end),
            ));
        }
        let prior = maximal_prior.unwrap_or(previous);
        if current.start < prior.end {
            errors.push(error(
                DecodeRangeErrorKind::OverlappingExtent,
                prior.start,
                Some(prior.end),
            ));
            errors.push(error(
                DecodeRangeErrorKind::OverlappingExtent,
                current.start,
                Some(current.end),
            ));
        }
        if maximal_prior.is_none_or(|extent| current.end > extent.end) {
            maximal_prior = Some(current);
        }
    }
    let mut ranges: Vec<DecodeExtent> = Vec::new();
    for extent in extents {
        if let Some(last) = ranges.last_mut()
            && last.isa == extent.isa
            && last.end == extent.start
        {
            last.end = extent.end;
        } else {
            ranges.push(extent);
        }
    }
    if ranges.is_empty() {
        errors.push(error(DecodeRangeErrorKind::EmptyProjection, entry, None));
    } else if !ranges.iter().any(|range| range.start == entry) {
        let kind = if ranges
            .iter()
            .any(|range| range.start < entry && entry < range.end)
        {
            DecodeRangeErrorKind::EntryNotRangeStart
        } else {
            DecodeRangeErrorKind::MissingInstructionAtEntry
        };
        errors.push(error(kind, entry, None));
    }
    if !errors.is_empty() {
        return Err(canonicalize_errors(errors));
    }
    Ok(ranges)
}

impl ExecutionBudget {
    pub(crate) fn charge_function(&mut self) -> Result<()> {
        self.charge(0, 0)
    }

    fn charge(&mut self, ranges: usize, bytes: u64) -> Result<()> {
        if ranges > MAX_EXECUTION_RANGES_PER_FUNCTION {
            return Err(invalid(
                "execution range count exceeds the per-function limit",
            ));
        }
        let functions = self
            .functions
            .checked_add(1)
            .ok_or_else(|| invalid("execution function count overflow"))?;
        let total_ranges = self
            .ranges
            .checked_add(ranges)
            .ok_or_else(|| invalid("execution range count overflow"))?;
        let charged_bytes = self
            .charged_bytes
            .checked_add(bytes)
            .ok_or_else(|| invalid("execution charged-byte count overflow"))?;
        if functions > MAX_EXECUTION_FUNCTIONS {
            return Err(invalid(
                "execution function count exceeds the supported limit",
            ));
        }
        if total_ranges > MAX_EXECUTION_RANGES {
            return Err(invalid("execution range count exceeds the supported limit"));
        }
        if charged_bytes > MAX_EXECUTION_CHARGED_BYTES {
            return Err(invalid(
                "execution charged bytes exceed the supported limit",
            ));
        }
        self.functions = functions;
        self.ranges = total_ranges;
        self.charged_bytes = charged_bytes;
        Ok(())
    }
}

pub(crate) fn validate_execution(
    entry: u32,
    extents: Vec<DecodeExtent>,
    runtime: &RuntimeImage<'_>,
    budget: &mut ExecutionBudget,
) -> Result<ExecutionIdentity> {
    let extents = canonicalize_instruction_extents(entry, extents)
        .map_err(|_| invalid("execution extents are not canonical"))?;
    authenticate_extents(entry, &extents, None, runtime, budget)
}

fn authenticate_extents(
    entry: u32,
    extents: &[DecodeExtent],
    expected: Option<&[[u8; 32]]>,
    runtime: &RuntimeImage<'_>,
    budget: &mut ExecutionBudget,
) -> Result<ExecutionIdentity> {
    let range_count = u32::try_from(extents.len())
        .map_err(|_| invalid("execution range count does not fit u32"))?;
    let charged_bytes = extents.iter().try_fold(0u64, |total, extent| {
        let length = extent
            .end
            .checked_sub(extent.start)
            .filter(|length| *length > 0)
            .ok_or_else(|| invalid("execution range is empty or wraps"))?;
        total
            .checked_add(u64::from(length))
            .ok_or_else(|| invalid("execution charged-byte count overflow"))
    })?;
    if expected.is_some_and(|hashes| hashes.len() != extents.len()) {
        return Err(invalid("execution range hash count mismatch"));
    }

    // Counters and every limit are settled before allocation, mapping checks,
    // or hashing. A failed runtime lookup remains charged work.
    budget.charge(extents.len(), charged_bytes)?;
    let mut ranges = Vec::new();
    ranges
        .try_reserve_exact(extents.len())
        .map_err(|_| invalid("authenticated execution-range allocation failed"))?;
    for (index, extent) in extents.iter().enumerate() {
        let size = extent.end - extent.start;
        if !runtime.is_byte_backed(extent.start, size)? {
            return Err(invalid("execution range crosses virtual zero-fill storage"));
        }
        let digest = runtime.hash_range(extent.start, size)?;
        if expected.is_some_and(|hashes| hashes[index] != digest) {
            return Err(invalid(
                "execution range BLAKE3 does not match runtime bytes",
            ));
        }
        ranges.push(AuthenticatedDecodeRange {
            isa: extent.isa,
            start: extent.start,
            end: extent.end,
            blake3: digest,
        });
    }
    Ok(ExecutionIdentity {
        entry,
        execution_blake3: execution_digest(entry, range_count, &ranges),
        decode_ranges: ranges,
    })
}

fn execution_digest(entry: u32, range_count: u32, ranges: &[AuthenticatedDecodeRange]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(EXECUTION_DIGEST_DOMAIN);
    hasher.update(&entry.to_le_bytes());
    hasher.update(&range_count.to_le_bytes());
    for range in ranges {
        hasher.update(&[match range.isa {
            DecodeIsa::Arm => 0,
            DecodeIsa::Thumb => 1,
        }]);
        hasher.update(&range.start.to_le_bytes());
        hasher.update(&range.end.to_le_bytes());
        hasher.update(&range.blake3);
    }
    *hasher.finalize().as_bytes()
}

pub(crate) fn execution_identity(
    entry: u32,
    projection: &ExecutionProjection,
) -> Result<Option<ExecutionIdentity>> {
    match projection {
        ExecutionProjection::Accepted(decode_ranges) if !decode_ranges.is_empty() => {
            let range_count = u32::try_from(decode_ranges.len())
                .map_err(|_| invalid("execution range count does not fit u32"))?;
            Ok(Some(ExecutionIdentity {
                entry,
                decode_ranges: decode_ranges.clone(),
                execution_blake3: execution_digest(entry, range_count, decode_ranges),
            }))
        }
        ExecutionProjection::Accepted(_) => {
            Err(invalid("accepted decode projection must not be empty"))
        }
        ExecutionProjection::Quarantined(errors) if !errors.is_empty() => Ok(None),
        ExecutionProjection::Quarantined(_) => {
            Err(invalid("quarantined decode projection must not be empty"))
        }
    }
}

pub(crate) fn projection_to_json(projection: &ExecutionProjection) -> Result<Value> {
    match projection {
        ExecutionProjection::Accepted(ranges) if !ranges.is_empty() => Ok(json!({
            "decode_ranges": ranges.iter().map(range_to_json).collect::<Vec<_>>(),
            "decode_range_errors": [],
        })),
        ExecutionProjection::Quarantined(errors) if !errors.is_empty() => Ok(json!({
            "decode_ranges": [],
            "decode_range_errors": errors.iter().map(error_to_json).collect::<Vec<_>>(),
        })),
        ExecutionProjection::Accepted(_) => {
            Err(invalid("accepted decode projection must not be empty"))
        }
        ExecutionProjection::Quarantined(_) => {
            Err(invalid("quarantined decode projection must not be empty"))
        }
    }
}

fn parse_projection(
    value: &Value,
    entry: u32,
    runtime: &RuntimeImage<'_>,
    budget: &mut ExecutionBudget,
) -> Result<(ExecutionProjection, Option<ExecutionIdentity>)> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("projection must be an object"))?;
    let ranges = object
        .get("decode_ranges")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("decode_ranges must be an array"))?;
    let errors = object
        .get("decode_range_errors")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("decode_range_errors must be an array"))?;
    match (ranges.is_empty(), errors.is_empty()) {
        (false, true) => {
            if ranges.len() > MAX_EXECUTION_RANGES_PER_FUNCTION {
                return Err(invalid(
                    "execution range count exceeds the per-function limit",
                ));
            }
            let claimed = ranges
                .iter()
                .map(parse_claimed_range)
                .collect::<Result<Vec<_>>>()?;
            let extents = claimed.iter().map(|range| range.extent).collect::<Vec<_>>();
            let canonical = canonicalize_instruction_extents(entry, extents.clone())
                .map_err(|_| invalid("accepted decode_ranges are not canonical"))?;
            if canonical != extents {
                return Err(invalid("accepted decode_ranges are not canonical"));
            }
            let expected = claimed.iter().map(|range| range.blake3).collect::<Vec<_>>();
            let identity = authenticate_extents(entry, &extents, Some(&expected), runtime, budget)?;
            let projection = ExecutionProjection::Accepted(identity.decode_ranges.clone());
            Ok((projection, Some(identity)))
        }
        (true, false) => {
            budget.charge_function()?;
            let errors = errors.iter().map(parse_error).collect::<Result<Vec<_>>>()?;
            if errors != canonicalize_errors(errors.clone()) {
                return Err(invalid(
                    "decode_range_errors are not sorted and deduplicated",
                ));
            }
            Ok((ExecutionProjection::Quarantined(errors), None))
        }
        _ => Err(invalid(
            "decode projection must contain exactly one non-empty tag array",
        )),
    }
}

/// Validate the exact tagged wire shape without accepting its claimed hashes
/// as execution. Artifact assembly and mutation use this before a later
/// runtime-aware reader authenticates the record.
pub(crate) fn validate_projection_shape(value: &Value, entry: u32) -> Result<bool> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("projection must be an object"))?;
    let ranges = object
        .get("decode_ranges")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("decode_ranges must be an array"))?;
    let errors = object
        .get("decode_range_errors")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("decode_range_errors must be an array"))?;
    match (ranges.is_empty(), errors.is_empty()) {
        (false, true) => {
            if ranges.len() > MAX_EXECUTION_RANGES_PER_FUNCTION {
                return Err(invalid(
                    "execution range count exceeds the per-function limit",
                ));
            }
            let extents = ranges
                .iter()
                .map(parse_claimed_range)
                .map(|range| range.map(|range| range.extent))
                .collect::<Result<Vec<_>>>()?;
            let canonical = canonicalize_instruction_extents(entry, extents.clone())
                .map_err(|_| invalid("accepted decode_ranges are not canonical"))?;
            if canonical != extents {
                return Err(invalid("accepted decode_ranges are not canonical"));
            }
            Ok(true)
        }
        (true, false) => {
            let errors = errors.iter().map(parse_error).collect::<Result<Vec<_>>>()?;
            if errors != canonicalize_errors(errors.clone()) {
                return Err(invalid(
                    "decode_range_errors are not sorted and deduplicated",
                ));
            }
            Ok(false)
        }
        _ => Err(invalid(
            "decode projection must contain exactly one non-empty tag array",
        )),
    }
}

pub(crate) fn legacy_non_execution_projection(
    value: &Value,
    entry: u32,
) -> Result<ExecutionProjection> {
    let errors = value
        .get("decode_range_errors")
        .and_then(Value::as_array)
        .map(|errors| errors.iter().map(parse_error).collect::<Result<Vec<_>>>())
        .transpose()?
        .unwrap_or_default();
    if errors.is_empty() {
        return Ok(ExecutionProjection::Quarantined(vec![error(
            DecodeRangeErrorKind::EmptyProjection,
            entry,
            None,
        )]));
    }
    if errors != canonicalize_errors(errors.clone()) {
        return Err(invalid(
            "decode_range_errors are not sorted and deduplicated",
        ));
    }
    Ok(ExecutionProjection::Quarantined(errors))
}

#[cfg(test)]
pub(crate) fn validate_inventory_projection(
    entry: u32,
    projection: &ExecutionProjection,
    runtime: &RuntimeImage<'_>,
    budget: &mut ExecutionBudget,
) -> Result<Option<ExecutionIdentity>> {
    match projection {
        ExecutionProjection::Accepted(ranges) => {
            let extents = ranges
                .iter()
                .map(|range| DecodeExtent {
                    isa: range.isa,
                    start: range.start,
                    end: range.end,
                })
                .collect::<Vec<_>>();
            let canonical = canonicalize_instruction_extents(entry, extents.clone())
                .map_err(|_| invalid("accepted decode_ranges are not canonical"))?;
            if canonical != extents {
                return Err(invalid("accepted decode_ranges are not canonical"));
            }
            let expected = ranges.iter().map(|range| range.blake3).collect::<Vec<_>>();
            authenticate_extents(entry, &extents, Some(&expected), runtime, budget).map(Some)
        }
        ExecutionProjection::Quarantined(errors) => {
            if errors.is_empty() {
                return Err(invalid("quarantined decode projection must not be empty"));
            }
            if errors != &canonicalize_errors(errors.clone()) {
                return Err(invalid(
                    "decode_range_errors are not sorted and deduplicated",
                ));
            }
            budget.charge_function()?;
            Ok(None)
        }
    }
}

pub(crate) fn inventory_count_conserved(
    raw_count: usize,
    projections: &[ExecutionProjection],
) -> bool {
    projections
        .iter()
        .try_fold(
            (0usize, 0usize),
            |(accepted, quarantined), projection| match projection {
                ExecutionProjection::Accepted(ranges) if !ranges.is_empty() => accepted
                    .checked_add(1)
                    .map(|accepted| (accepted, quarantined)),
                ExecutionProjection::Quarantined(errors) if !errors.is_empty() => quarantined
                    .checked_add(1)
                    .map(|quarantined| (accepted, quarantined)),
                _ => None,
            },
        )
        .and_then(|(accepted, quarantined)| accepted.checked_add(quarantined))
        == Some(raw_count)
}

/// Validate one inventory record: object shape, canonical `entry`, the exact
/// projection representation, and the derived identity. Shared by the
/// whole-record and streaming Thumb validators so verdicts cannot drift.
pub(crate) fn validate_inventory_record(
    record: &Value,
    owner: FunctionOwner,
    runtime: &RuntimeImage<'_>,
    budget: &mut ExecutionBudget,
) -> Result<(
    TaggedExecutionRecord,
    ExecutionProjection,
    Option<ExecutionIdentity>,
)> {
    let object = record
        .as_object()
        .ok_or_else(|| invalid("inventory record must be an object"))?;
    let entry = parse_hex(required_string(object, "entry")?)?;
    let (projection, identity) = parse_projection(record, entry, runtime, budget)?;
    Ok((
        TaggedExecutionRecord {
            owner,
            entry,
            projection: projection.clone(),
        },
        projection,
        identity,
    ))
}

#[cfg(test)]
pub(crate) fn validate_inventory_records(
    records: &[Value],
    expected_raw_count: usize,
    owner: FunctionOwner,
    runtime: &RuntimeImage<'_>,
) -> Result<ValidatedInventory> {
    if records.len() > MAX_EXECUTION_FUNCTIONS {
        return Err(invalid(
            "execution function count exceeds the supported limit",
        ));
    }
    let mut projections = Vec::with_capacity(records.len());
    let mut accepted_executions = BTreeSet::new();
    let mut accepted = 0usize;
    let mut quarantined = 0usize;
    let mut tagged_records = Vec::with_capacity(records.len());
    let mut budget = ExecutionBudget::default();
    for record in records {
        let (tagged, projection, identity) =
            validate_inventory_record(record, owner, runtime, &mut budget)?;
        if let Some(identity) = identity {
            accepted = accepted
                .checked_add(1)
                .ok_or_else(|| invalid("accepted inventory count overflow"))?;
            accepted_executions.insert(OwnedExecutionIdentity { owner, identity });
        } else {
            quarantined = quarantined
                .checked_add(1)
                .ok_or_else(|| invalid("quarantined inventory count overflow"))?;
        }
        tagged_records.push(tagged);
        projections.push(projection);
    }
    if !inventory_count_conserved(expected_raw_count, &projections)
        || accepted.checked_add(quarantined) != Some(expected_raw_count)
    {
        return Err(invalid(
            "raw inventory count does not equal accepted plus quarantined",
        ));
    }
    Ok(ValidatedInventory {
        raw_count: expected_raw_count,
        accepted,
        quarantined,
        accepted_executions: accepted_executions.into_iter().collect(),
        records: tagged_records,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GhidraFunctionFields {
    pub name: String,
    pub original_name: Option<String>,
    pub primary_source: String,
    pub entry: u32,
    pub end: u32,
    pub size: u64,
    pub data_refs: Vec<u32>,
    pub quarantine_errors: usize,
    pub tagged: TaggedExecutionRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StreamedGhidraInventory {
    pub inventory: ValidatedInventory,
    pub functions: Vec<GhidraFunctionFields>,
}

const GHIDRA_REQUIRED_KEYS: [&str; 8] = [
    "name",
    "primary_source",
    "entry",
    "end",
    "size",
    "decode_ranges",
    "decode_range_errors",
    "data_refs",
];
const GHIDRA_ENRICHMENT_KEYS: [&str; 2] = ["original_name", "annotations"];

fn validate_ghidra_record_shape(record: &Value) -> Result<&Map<String, Value>> {
    let object = record
        .as_object()
        .ok_or_else(|| invalid("Ghidra function record must be an object"))?;
    if GHIDRA_REQUIRED_KEYS
        .iter()
        .any(|key| !object.contains_key(*key))
        || object.keys().any(|key| {
            !GHIDRA_REQUIRED_KEYS.contains(&key.as_str())
                && !GHIDRA_ENRICHMENT_KEYS.contains(&key.as_str())
        })
    {
        return Err(invalid(
            "Ghidra function record has unknown or missing fields",
        ));
    }
    required_string(object, "name")?;
    match required_string(object, "primary_source")? {
        "default" | "analysis" | "imported" | "user_defined" => {}
        _ => return Err(invalid("unknown Ghidra primary source")),
    }
    if object.contains_key("original_name") {
        required_string(object, "original_name")?;
    }
    if object.get("annotations").is_some_and(|annotations| {
        annotations
            .as_array()
            .is_none_or(|annotations| annotations.iter().any(|value| !value.is_string()))
    }) {
        return Err(invalid("Ghidra annotations must be an array of strings"));
    }
    Ok(object)
}

#[cfg(test)]
pub(crate) fn validate_ghidra_inventory_records(
    records: &[Value],
    expected_raw_count: usize,
    runtime: &RuntimeImage<'_>,
) -> Result<ValidatedInventory> {
    for record in records {
        validate_ghidra_record_shape(record)?;
    }
    validate_inventory_records(records, expected_raw_count, FunctionOwner::Ghidra, runtime)
}

pub(crate) fn read_ghidra_inventory_streaming(
    path: &Path,
    runtime: &RuntimeImage<'_>,
) -> Result<StreamedGhidraInventory> {
    read_ghidra_inventory_streaming_capped(path, runtime, MAX_EXECUTION_FUNCTIONS)
}

pub(crate) fn read_ghidra_inventory_streaming_capped(
    path: &Path,
    runtime: &RuntimeImage<'_>,
    cap: usize,
) -> Result<StreamedGhidraInventory> {
    let file = std::fs::File::open(path)?;
    let mut deserializer = serde_json::Deserializer::from_reader(std::io::BufReader::new(file));
    let mut scan = GhidraInventoryScan {
        runtime,
        cap,
        functions: Vec::new(),
        projections: Vec::new(),
        accepted_executions: BTreeSet::new(),
        accepted: 0,
        quarantined: 0,
        budget: ExecutionBudget::default(),
    };
    let parsed = deserializer.deserialize_any(GhidraInventoryVisitor { scan: &mut scan });
    match parsed.and_then(|()| deserializer.end()) {
        Ok(()) => scan.finish(),
        Err(error) => Err(invalid(&format!(
            "parse Ghidra functions inventory: {error}"
        ))),
    }
}

struct GhidraInventoryScan<'runtime, 'data> {
    runtime: &'runtime RuntimeImage<'data>,
    cap: usize,
    functions: Vec<GhidraFunctionFields>,
    projections: Vec<ExecutionProjection>,
    accepted_executions: BTreeSet<OwnedExecutionIdentity>,
    accepted: usize,
    quarantined: usize,
    budget: ExecutionBudget,
}

impl GhidraInventoryScan<'_, '_> {
    fn push(&mut self, record: Value) -> Result<()> {
        if self.functions.len() >= self.cap {
            return Err(invalid(
                "execution function count exceeds the supported limit",
            ));
        }
        let object = validate_ghidra_record_shape(&record)?;
        let name = required_string(object, "name")?.to_owned();
        let original_name = object
            .get("original_name")
            .map(|_| required_string(object, "original_name").map(str::to_owned))
            .transpose()?;
        let primary_source = required_string(object, "primary_source")?.to_owned();
        let end = parse_hex(required_string(object, "end")?)?;
        let size = object
            .get("size")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("size must be a u64"))?;
        let data_refs = object
            .get("data_refs")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("data_refs must be an array"))?
            .iter()
            .map(|value| {
                parse_hex(
                    value
                        .as_str()
                        .ok_or_else(|| invalid("data_ref must be a string"))?,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let quarantine_errors = object
            .get("decode_range_errors")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0);
        let (tagged, projection, identity) = validate_inventory_record(
            &record,
            FunctionOwner::Ghidra,
            self.runtime,
            &mut self.budget,
        )?;
        if let Some(identity) = identity {
            self.accepted = self
                .accepted
                .checked_add(1)
                .ok_or_else(|| invalid("accepted inventory count overflow"))?;
            self.accepted_executions.insert(OwnedExecutionIdentity {
                owner: FunctionOwner::Ghidra,
                identity,
            });
        } else {
            self.quarantined = self
                .quarantined
                .checked_add(1)
                .ok_or_else(|| invalid("quarantined inventory count overflow"))?;
        }
        self.functions.push(GhidraFunctionFields {
            name,
            original_name,
            primary_source,
            entry: tagged.entry,
            end,
            size,
            data_refs,
            quarantine_errors,
            tagged,
        });
        self.projections.push(projection);
        Ok(())
    }

    fn finish(self) -> Result<StreamedGhidraInventory> {
        let raw_count = self.functions.len();
        if !inventory_count_conserved(raw_count, &self.projections)
            || self.accepted.checked_add(self.quarantined) != Some(raw_count)
        {
            return Err(invalid(
                "raw inventory count does not equal accepted plus quarantined",
            ));
        }
        Ok(StreamedGhidraInventory {
            inventory: ValidatedInventory {
                raw_count,
                accepted: self.accepted,
                quarantined: self.quarantined,
                accepted_executions: self.accepted_executions.into_iter().collect(),
                records: self.functions.iter().map(|f| f.tagged.clone()).collect(),
            },
            functions: self.functions,
        })
    }
}

struct GhidraInventoryVisitor<'scan, 'runtime, 'data> {
    scan: &'scan mut GhidraInventoryScan<'runtime, 'data>,
}

impl<'de> Visitor<'de> for GhidraInventoryVisitor<'_, '_, '_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a Ghidra functions array")
    }

    fn visit_seq<A>(self, mut seq: A) -> std::result::Result<(), A::Error>
    where
        A: SeqAccess<'de>,
    {
        while let Some(record) = seq.next_element::<Value>()? {
            self.scan.push(record).map_err(de::Error::custom)?;
        }
        Ok(())
    }
}

pub(crate) fn validate_legacy_execution(
    entry: u32,
    ranges: Vec<DecodeExtent>,
    runtime: &RuntimeImage<'_>,
    budget: &mut ExecutionBudget,
) -> Result<Option<ExecutionIdentity>> {
    if ranges.is_empty() {
        budget.charge_function()?;
        return Ok(None);
    }
    validate_execution(entry, ranges, runtime, budget).map(Some)
}

#[cfg(test)]
fn union_function_contexts<I>(contexts: I) -> Vec<(u32, String)>
where
    I: IntoIterator<Item = (u32, String)>,
{
    contexts
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn range_to_json(range: &AuthenticatedDecodeRange) -> Value {
    json!({
        "isa": isa_name(range.isa),
        "start": hex(range.start),
        "end": hex(range.end),
        "blake3": digest_hex(range.blake3),
    })
}

fn error_to_json(error: &DecodeRangeError) -> Value {
    json!({"kind": error_kind_name(error.kind), "address": hex(error.address), "end": error.end.map(hex)})
}

#[derive(Clone, Copy)]
struct ClaimedDecodeRange {
    extent: DecodeExtent,
    blake3: [u8; 32],
}

fn parse_claimed_range(value: &Value) -> Result<ClaimedDecodeRange> {
    let object = strict_object(value, &["isa", "start", "end", "blake3"])?;
    let isa = match required_string(object, "isa")? {
        "arm" => DecodeIsa::Arm,
        "thumb" => DecodeIsa::Thumb,
        _ => return Err(invalid("unknown decode ISA")),
    };
    Ok(ClaimedDecodeRange {
        extent: DecodeExtent {
            isa,
            start: parse_hex(required_string(object, "start")?)?,
            end: parse_hex(required_string(object, "end")?)?,
        },
        blake3: parse_blake3(required_string(object, "blake3")?)?,
    })
}

/// The single digest grammar for execution evidence: exactly 64 lowercase
/// hexadecimal characters decoded into 32 bytes. Every consumer that parses a
/// BLAKE3 digest from function records must go through this parser so the
/// acceptance grammar cannot drift between stages.
pub(crate) fn parse_blake3(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(
            "BLAKE3 must be 64 lowercase hexadecimal characters",
        ));
    }
    let mut digest = [0u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        let start = index * 2;
        *byte = u8::from_str_radix(&value[start..start + 2], 16)
            .map_err(|_| invalid("BLAKE3 contains invalid hexadecimal"))?;
    }
    Ok(digest)
}

fn digest_hex(digest: [u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_error(value: &Value) -> Result<DecodeRangeError> {
    let object = strict_object(value, &["kind", "address", "end"])?;
    let kind = parse_error_kind(required_string(object, "kind")?)
        .ok_or_else(|| invalid("unknown decode range error kind"))?;
    let end = match object.get("end") {
        Some(Value::Null) => None,
        Some(value) => Some(parse_hex(value.as_str().ok_or_else(|| {
            invalid("error end must be a canonical hexadecimal string or null")
        })?)?),
        None => return Err(invalid("missing error end")),
    };
    Ok(DecodeRangeError {
        kind,
        address: parse_hex(required_string(object, "address")?)?,
        end,
    })
}

fn strict_object<'a>(value: &'a Value, keys: &[&str]) -> Result<&'a Map<String, Value>> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("decode projection element must be an object"))?;
    if object.len() != keys.len() || keys.iter().any(|key| !object.contains_key(*key)) {
        return Err(invalid(
            "decode projection element has unknown or missing fields",
        ));
    }
    Ok(object)
}

fn required_string<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(&format!("{key} must be a string")))
}

fn parse_hex(value: &str) -> Result<u32> {
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
    if hex(parsed) != value {
        return Err(invalid("address is not canonical hexadecimal"));
    }
    Ok(parsed)
}

fn hex(value: u32) -> String {
    format!("0x{value:x}")
}

fn isa_name(isa: DecodeIsa) -> &'static str {
    match isa {
        DecodeIsa::Arm => "arm",
        DecodeIsa::Thumb => "thumb",
    }
}

fn error_kind_name(kind: DecodeRangeErrorKind) -> &'static str {
    match kind {
        DecodeRangeErrorKind::MissingInstructionAtEntry => "missing_instruction_at_entry",
        DecodeRangeErrorKind::MissingIsaContext => "missing_isa_context",
        DecodeRangeErrorKind::InvalidIsaContext => "invalid_isa_context",
        DecodeRangeErrorKind::OverriddenInstructionLength => "overridden_instruction_length",
        DecodeRangeErrorKind::InvalidInstructionLength => "invalid_instruction_length",
        DecodeRangeErrorKind::MisalignedInstruction => "misaligned_instruction",
        DecodeRangeErrorKind::ExtentOutsideFunction => "extent_outside_function",
        DecodeRangeErrorKind::ExtentOutsideImage => "extent_outside_image",
        DecodeRangeErrorKind::MissingOperationBody => "missing_operation_body",
        DecodeRangeErrorKind::InvalidOperationAddress => "invalid_operation_address",
        DecodeRangeErrorKind::InvalidOperationBytes => "invalid_operation_bytes",
        DecodeRangeErrorKind::RawByteMismatch => "raw_byte_mismatch",
        DecodeRangeErrorKind::DuplicateExtent => "duplicate_extent",
        DecodeRangeErrorKind::OverlappingExtent => "overlapping_extent",
        DecodeRangeErrorKind::EntryNotRangeStart => "entry_not_range_start",
        DecodeRangeErrorKind::EmptyProjection => "empty_projection",
    }
}

fn parse_error_kind(value: &str) -> Option<DecodeRangeErrorKind> {
    Some(match value {
        "missing_instruction_at_entry" => DecodeRangeErrorKind::MissingInstructionAtEntry,
        "missing_isa_context" => DecodeRangeErrorKind::MissingIsaContext,
        "invalid_isa_context" => DecodeRangeErrorKind::InvalidIsaContext,
        "overridden_instruction_length" => DecodeRangeErrorKind::OverriddenInstructionLength,
        "invalid_instruction_length" => DecodeRangeErrorKind::InvalidInstructionLength,
        "misaligned_instruction" => DecodeRangeErrorKind::MisalignedInstruction,
        "extent_outside_function" => DecodeRangeErrorKind::ExtentOutsideFunction,
        "extent_outside_image" => DecodeRangeErrorKind::ExtentOutsideImage,
        "missing_operation_body" => DecodeRangeErrorKind::MissingOperationBody,
        "invalid_operation_address" => DecodeRangeErrorKind::InvalidOperationAddress,
        "invalid_operation_bytes" => DecodeRangeErrorKind::InvalidOperationBytes,
        "raw_byte_mismatch" => DecodeRangeErrorKind::RawByteMismatch,
        "duplicate_extent" => DecodeRangeErrorKind::DuplicateExtent,
        "overlapping_extent" => DecodeRangeErrorKind::OverlappingExtent,
        "entry_not_range_start" => DecodeRangeErrorKind::EntryNotRangeStart,
        "empty_projection" => DecodeRangeErrorKind::EmptyProjection,
        _ => return None,
    })
}

pub(crate) fn invalid(message: &str) -> Error {
    Error::Serialize(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_image::RuntimeImage;
    use crate::scatter::{
        Descriptor, HandlerMap, LoadPlan, Operation, PlannedEntry, PlannedOutput,
    };
    use serde_json::json;

    fn digest_hex(digest: [u8; 32]) -> String {
        digest.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn extent(isa: DecodeIsa, start: u32, end: u32) -> DecodeExtent {
        DecodeExtent { isa, start, end }
    }

    fn zero_fill_plan(base: u32, raw_size: u32) -> LoadPlan {
        LoadPlan {
            image_base: base,
            image_size: raw_size,
            loader_address: base,
            literal_pair_address: base,
            table_start: base,
            table_end: base + raw_size,
            handlers: HandlerMap {
                null: base,
                copy: base + 1,
                decompress1: base + 2,
                zero: base + 3,
            },
            entries: vec![PlannedEntry {
                index: 0,
                descriptor: Descriptor {
                    source: 0,
                    destination: base + raw_size,
                    size: 4,
                    handler: base + 3,
                },
                operation: Operation::Zero,
                compressed_size: None,
                output: PlannedOutput::ZeroFill,
            }],
            logical_output_size: 4,
        }
    }

    #[test]
    fn authenticated_execution_digest_matches_the_pinned_framing() {
        let bytes = [1u8, 2, 3, 4];
        let runtime = RuntimeImage::from_plan(&bytes, 0x1000, None).unwrap();
        let mut budget = ExecutionBudget::default();
        let identity = validate_execution(
            0x1000,
            vec![extent(DecodeIsa::Thumb, 0x1000, 0x1004)],
            &runtime,
            &mut budget,
        )
        .unwrap();

        assert_eq!(
            digest_hex(identity.decode_ranges[0].blake3),
            "63781d171425a36312fa058d8712d5d05135a991ec20351ce9d65cdb19a05432"
        );
        assert_eq!(
            digest_hex(identity.execution_blake3),
            "435e60b18c4a67713f0d787a4d39253650bc551764f617728591356995d500c6"
        );
    }

    #[test]
    fn execution_identity_changes_with_bytes_boundaries_and_isa() {
        let original = [1u8, 2, 3, 4, 5, 6];
        let changed = [1u8, 2, 3, 9, 5, 6];
        let original_runtime = RuntimeImage::from_plan(&original, 0x1000, None).unwrap();
        let changed_runtime = RuntimeImage::from_plan(&changed, 0x1000, None).unwrap();
        let validate = |runtime: &RuntimeImage<'_>, isa, end| {
            validate_execution(
                0x1000,
                vec![extent(isa, 0x1000, end)],
                runtime,
                &mut ExecutionBudget::default(),
            )
            .unwrap()
        };

        let baseline = validate(&original_runtime, DecodeIsa::Thumb, 0x1004);
        let changed_bytes = validate(&changed_runtime, DecodeIsa::Thumb, 0x1004);
        let changed_boundary = validate(&original_runtime, DecodeIsa::Thumb, 0x1006);
        let changed_isa = validate(&original_runtime, DecodeIsa::Arm, 0x1004);

        assert_ne!(
            baseline.decode_ranges[0].blake3,
            changed_bytes.decode_ranges[0].blake3
        );
        assert_ne!(baseline.execution_blake3, changed_bytes.execution_blake3);
        assert_ne!(baseline.execution_blake3, changed_boundary.execution_blake3);
        assert_eq!(
            baseline.decode_ranges[0].blake3,
            changed_isa.decode_ranges[0].blake3
        );
        assert_ne!(baseline.execution_blake3, changed_isa.execution_blake3);
    }

    #[test]
    fn execution_authentication_rejects_gaps_and_virtual_zero_fill() {
        let raw = [0u8; 16];
        let gap_runtime = RuntimeImage::from_plan(&raw, 0x1000, None).unwrap();
        assert!(
            validate_execution(
                0x1000,
                vec![extent(DecodeIsa::Thumb, 0x1000, 0x1012)],
                &gap_runtime,
                &mut ExecutionBudget::default(),
            )
            .is_err()
        );

        let plan = zero_fill_plan(0x1000, raw.len() as u32);
        let zero_runtime = RuntimeImage::from_plan(&raw, 0x1000, Some(&plan)).unwrap();
        assert!(
            validate_execution(
                0x1010,
                vec![extent(DecodeIsa::Thumb, 0x1010, 0x1014)],
                &zero_runtime,
                &mut ExecutionBudget::default(),
            )
            .is_err()
        );
    }

    #[test]
    fn execution_budget_enforces_inventory_aggregate_and_byte_limits() {
        let bytes = [0u8; 8];
        let runtime = RuntimeImage::from_plan(&bytes, 0x1000, None).unwrap();
        let one = || vec![extent(DecodeIsa::Arm, 0x1000, 0x1004)];

        let mut functions = ExecutionBudget {
            functions: MAX_EXECUTION_FUNCTIONS - 1,
            ..ExecutionBudget::default()
        };
        validate_execution(0x1000, one(), &runtime, &mut functions).unwrap();
        assert_eq!(functions.functions, MAX_EXECUTION_FUNCTIONS);
        assert!(validate_execution(0x1000, one(), &runtime, &mut functions).is_err());

        let mut ranges = ExecutionBudget {
            ranges: MAX_EXECUTION_RANGES - 1,
            ..ExecutionBudget::default()
        };
        validate_execution(0x1000, one(), &runtime, &mut ranges).unwrap();
        assert_eq!(ranges.ranges, MAX_EXECUTION_RANGES);
        assert!(validate_execution(0x1000, one(), &runtime, &mut ranges).is_err());

        let mut bytes = ExecutionBudget {
            charged_bytes: MAX_EXECUTION_CHARGED_BYTES - 4,
            ..ExecutionBudget::default()
        };
        validate_execution(0x1000, one(), &runtime, &mut bytes).unwrap();
        assert_eq!(bytes.charged_bytes, MAX_EXECUTION_CHARGED_BYTES);
        assert!(validate_execution(0x1000, one(), &runtime, &mut bytes).is_err());
    }

    #[test]
    fn execution_budget_enforces_per_function_range_limit_before_runtime_work() {
        let count = MAX_EXECUTION_RANGES_PER_FUNCTION + 1;
        let extents = (0..count)
            .map(|index| {
                let start = 0x1000 + u32::try_from(index * 4).unwrap();
                extent(DecodeIsa::Thumb, start, start + 2)
            })
            .collect();
        let runtime = RuntimeImage::from_plan(&[0u8; 2], 0x1000, None).unwrap();
        let mut budget = ExecutionBudget::default();

        assert!(validate_execution(0x1000, extents, &runtime, &mut budget).is_err());
        assert_eq!(budget.ranges, 0);
        assert_eq!(budget.charged_bytes, 0);
    }

    #[test]
    fn execution_budget_rejects_counter_overflow() {
        let runtime = RuntimeImage::from_plan(&[0u8; 4], 0x1000, None).unwrap();
        let mut function_overflow = ExecutionBudget {
            functions: usize::MAX,
            ..ExecutionBudget::default()
        };
        assert!(
            validate_execution(
                0x1000,
                vec![extent(DecodeIsa::Arm, 0x1000, 0x1004)],
                &runtime,
                &mut function_overflow,
            )
            .is_err()
        );

        let mut byte_overflow = ExecutionBudget {
            charged_bytes: u64::MAX,
            ..ExecutionBudget::default()
        };
        assert!(
            validate_execution(
                0x1000,
                vec![extent(DecodeIsa::Arm, 0x1000, 0x1004)],
                &runtime,
                &mut byte_overflow,
            )
            .is_err()
        );
    }

    #[test]
    fn tagged_projection_serializes_canonical_wire_shape() {
        let projection = ExecutionProjection::Accepted(vec![AuthenticatedDecodeRange {
            isa: DecodeIsa::Thumb,
            start: 0x4001_0000,
            end: 0x4001_0004,
            blake3: [0; 32],
        }]);

        assert_eq!(
            projection_to_json(&projection).unwrap(),
            json!({
                "decode_ranges": [{"isa":"thumb","start":"0x40010000","end":"0x40010004","blake3":"00".repeat(32)}],
                "decode_range_errors": [],
            })
        );
    }

    #[test]
    fn projection_parser_rejects_noncanonical_or_nonexclusive_tags() {
        let bytes = [0u8; 16];
        let runtime = RuntimeImage::from_plan(&bytes, 0x4000, None).unwrap();
        for bad in [
            json!({"decode_ranges": [], "decode_range_errors": []}),
            json!({"decode_ranges": [{"isa":"arm","start":"0x4000","end":"0x4004","blake3":"00".repeat(32)}], "decode_range_errors": [{"kind":"empty_projection","address":"0x4000","end":null}]}),
            json!({"decode_ranges": [{"isa":"ARM","start":"0x4000","end":"0x4004","blake3":"00".repeat(32)}], "decode_range_errors": []}),
            json!({"decode_ranges": [{"isa":"arm","start":"0X4000","end":"0x4004","blake3":"00".repeat(32)}], "decode_range_errors": []}),
            json!({"decode_ranges": [{"isa":"arm","start":"0x4000","end":"0x4004","blake3":"00".repeat(32),"extra":true}], "decode_range_errors": []}),
        ] {
            assert!(
                parse_projection(&bad, 0x4000, &runtime, &mut ExecutionBudget::default(),).is_err(),
                "accepted invalid projection: {bad}"
            );
        }
    }

    #[test]
    fn canonicalization_merges_only_adjacent_same_isa_and_requires_entry_start() {
        let ranges = canonicalize_instruction_extents(
            0x4000,
            vec![
                extent(DecodeIsa::Thumb, 0x4006, 0x4008),
                extent(DecodeIsa::Thumb, 0x4000, 0x4002),
                extent(DecodeIsa::Thumb, 0x4002, 0x4004),
                extent(DecodeIsa::Thumb, 0x4004, 0x4006),
                extent(DecodeIsa::Arm, 0x4008, 0x400c),
            ],
        )
        .unwrap();
        assert_eq!(
            ranges,
            vec![
                extent(DecodeIsa::Thumb, 0x4000, 0x4008),
                extent(DecodeIsa::Arm, 0x4008, 0x400c),
            ]
        );
    }

    #[test]
    fn canonicalization_quarantines_when_merging_makes_entry_interior() {
        let errors = canonicalize_instruction_extents(
            0x4004,
            vec![
                extent(DecodeIsa::Arm, 0x4000, 0x4004),
                extent(DecodeIsa::Arm, 0x4004, 0x4008),
            ],
        )
        .unwrap_err();
        let expected = vec![DecodeRangeError {
            kind: DecodeRangeErrorKind::EntryNotRangeStart,
            address: 0x4004,
            end: None,
        }];
        assert_eq!(errors, expected);

        let record = json!({
            "entry":"0x4004",
            "decode_ranges":[],
            "decode_range_errors":[{
                "kind":"entry_not_range_start",
                "address":"0x4004",
                "end":null
            }]
        });
        let bytes = [0u8; 16];
        let runtime = RuntimeImage::from_plan(&bytes, 0x4000, None).unwrap();
        let inventory =
            validate_inventory_records(&[record], 1, FunctionOwner::Ghidra, &runtime).unwrap();
        assert_eq!(inventory.accepted, 0);
        assert_eq!(inventory.quarantined, 1);
    }

    #[test]
    fn canonicalization_quarantines_whole_record_with_sorted_deduplicated_errors() {
        let errors = canonicalize_instruction_extents(
            0x4001,
            vec![
                extent(DecodeIsa::Thumb, 0x4001, 0x4003),
                extent(DecodeIsa::Thumb, 0x4002, 0x4004),
                extent(DecodeIsa::Thumb, 0x4001, 0x4003),
            ],
        )
        .unwrap_err();
        assert_eq!(
            errors,
            vec![
                DecodeRangeError {
                    kind: DecodeRangeErrorKind::DuplicateExtent,
                    address: 0x4001,
                    end: Some(0x4003)
                },
                DecodeRangeError {
                    kind: DecodeRangeErrorKind::MisalignedInstruction,
                    address: 0x4001,
                    end: Some(0x4003)
                },
                DecodeRangeError {
                    kind: DecodeRangeErrorKind::OverlappingExtent,
                    address: 0x4001,
                    end: Some(0x4003)
                },
                DecodeRangeError {
                    kind: DecodeRangeErrorKind::OverlappingExtent,
                    address: 0x4002,
                    end: Some(0x4004)
                },
            ]
        );
    }

    #[test]
    fn accepted_identity_dedup_uses_the_complete_tagged_range_list() {
        let bytes = [0u8; 4];
        let runtime = RuntimeImage::from_plan(&bytes, 0x4000, None).unwrap();
        let arm = validate_execution(
            0x4000,
            vec![extent(DecodeIsa::Arm, 0x4000, 0x4004)],
            &runtime,
            &mut ExecutionBudget::default(),
        )
        .unwrap();
        let thumb = validate_execution(
            0x4000,
            vec![extent(DecodeIsa::Thumb, 0x4000, 0x4004)],
            &runtime,
            &mut ExecutionBudget::default(),
        )
        .unwrap();
        assert_ne!(arm, thumb, "cross-ISA overlaps remain distinct identities");
        assert_eq!(
            execution_identity(
                0x4000,
                &ExecutionProjection::Accepted(arm.decode_ranges.clone())
            )
            .unwrap(),
            Some(arm)
        );
        assert_eq!(
            execution_identity(
                0x4000,
                &ExecutionProjection::Quarantined(vec![DecodeRangeError {
                    kind: DecodeRangeErrorKind::EmptyProjection,
                    address: 0x4000,
                    end: None
                }])
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn empty_tag_payloads_are_rejected_at_every_model_boundary() {
        let bytes = [0u8; 4];
        let runtime = RuntimeImage::from_plan(&bytes, 0x4000, None).unwrap();
        let empty_accepted = ExecutionProjection::Accepted(vec![]);
        let empty_quarantined = ExecutionProjection::Quarantined(vec![]);
        for projection in [&empty_accepted, &empty_quarantined] {
            assert!(projection_to_json(projection).is_err());
            assert!(execution_identity(0x4000, projection).is_err());
            assert!(
                validate_inventory_projection(
                    0x4000,
                    projection,
                    &runtime,
                    &mut ExecutionBudget::default(),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn inventory_conservation_detects_an_omitted_raw_record() {
        let projections = vec![ExecutionProjection::Accepted(vec![
            AuthenticatedDecodeRange {
                isa: DecodeIsa::Thumb,
                start: 0x4000,
                end: 0x4002,
                blake3: [0; 32],
            },
        ])];
        assert!(inventory_count_conserved(1, &projections));
        assert!(!inventory_count_conserved(2, &projections));
    }

    #[test]
    fn projection_parser_rejects_missing_and_malformed_error_fields() {
        let bytes = [0u8; 16];
        let runtime = RuntimeImage::from_plan(&bytes, 0x4000, None).unwrap();
        for bad in [
            json!({"decode_range_errors": []}),
            json!({"decode_ranges": []}),
            json!({"decode_ranges": [], "decode_range_errors": [{"kind":"unknown", "address":"0x4000", "end":null}]}),
            json!({"decode_ranges": [], "decode_range_errors": [{"kind":"empty_projection", "address":16384, "end":null}]}),
            json!({"decode_ranges": [], "decode_range_errors": [{"kind":"empty_projection", "address":"0x04000", "end":false}]}),
        ] {
            assert!(
                parse_projection(&bad, 0x4000, &runtime, &mut ExecutionBudget::default(),).is_err(),
                "accepted malformed projection: {bad}"
            );
        }
        assert_eq!(
            parse_projection(
                &json!({"decode_ranges": [], "decode_range_errors": [{"kind":"raw_byte_mismatch", "address":"0x4000", "end":"0x4004"}]}),
                0x4000,
                &runtime,
                &mut ExecutionBudget::default(),
            )
            .unwrap(),
            (
                ExecutionProjection::Quarantined(vec![DecodeRangeError { kind: DecodeRangeErrorKind::RawByteMismatch, address: 0x4000, end: Some(0x4004) }]),
                None,
            )
        );
    }

    #[test]
    fn identity_context_union_is_sorted_and_distinct_overlaps_remain_distinct() {
        assert_eq!(
            union_function_contexts(vec![
                (0x4002, "z".into()),
                (0x4000, "b".into()),
                (0x4000, "a".into()),
                (0x4000, "a".into())
            ]),
            vec![
                (0x4000, "a".into()),
                (0x4000, "b".into()),
                (0x4002, "z".into())
            ]
        );
        let bytes = [0u8; 8];
        let runtime = RuntimeImage::from_plan(&bytes, 0x4000, None).unwrap();
        let left = validate_execution(
            0x4000,
            vec![extent(DecodeIsa::Thumb, 0x4000, 0x4006)],
            &runtime,
            &mut ExecutionBudget::default(),
        )
        .unwrap();
        let right = validate_execution(
            0x4002,
            vec![extent(DecodeIsa::Thumb, 0x4002, 0x4008)],
            &runtime,
            &mut ExecutionBudget::default(),
        )
        .unwrap();
        assert_ne!(
            left, right,
            "same-ISA overlaps remain distinct complete identities"
        );
    }

    #[test]
    fn terminal_inventory_deduplicates_only_complete_accepted_identities() {
        let bytes = [0u8; 16];
        let runtime = RuntimeImage::from_plan(&bytes, 0x4000, None).unwrap();
        let range = |isa: &str, start: u32, end: u32| {
            let digest = runtime.hash_range(start, end - start).unwrap();
            json!({
                "isa": isa,
                "start": hex(start),
                "end": hex(end),
                "blake3": digest_hex(digest),
            })
        };
        let records = vec![
            json!({
                "entry": "0x4000",
                "decode_ranges": [range("arm", 0x4000, 0x4004)],
                "decode_range_errors": [],
            }),
            json!({
                "entry": "0x4000",
                "decode_ranges": [range("arm", 0x4000, 0x4004)],
                "decode_range_errors": [],
            }),
            json!({
                "entry": "0x4000",
                "decode_ranges": [range("thumb", 0x4000, 0x4004)],
                "decode_range_errors": [],
            }),
            json!({
                "entry": "0x4002",
                "decode_ranges": [range("thumb", 0x4002, 0x4006)],
                "decode_range_errors": [],
            }),
            json!({
                "entry": "0x4008",
                "decode_ranges": [],
                "decode_range_errors": [{"kind":"empty_projection","address":"0x4008","end":null}],
            }),
        ];

        let inventory =
            validate_inventory_records(&records, 5, FunctionOwner::Ghidra, &runtime).unwrap();

        assert_eq!(inventory.raw_count, 5);
        assert_eq!(inventory.accepted, 4);
        assert_eq!(inventory.quarantined, 1);
        assert_eq!(inventory.accepted_executions.len(), 3);
        assert!(inventory.accepted_executions.iter().any(|execution| {
            execution.identity.entry == 0x4000
                && execution.identity.decode_ranges[0].isa == DecodeIsa::Arm
        }));
        assert!(inventory.accepted_executions.iter().any(|execution| {
            execution.identity.entry == 0x4000
                && execution.identity.decode_ranges[0].isa == DecodeIsa::Thumb
        }));
        assert!(
            inventory
                .accepted_executions
                .iter()
                .any(|execution| execution.identity.entry == 0x4002)
        );
    }

    #[test]
    fn terminal_inventory_rejects_orphans_malformed_tags_and_count_mismatch() {
        let bytes = [0u8; 16];
        let runtime = RuntimeImage::from_plan(&bytes, 0x4000, None).unwrap();
        let digest = digest_hex(runtime.hash_range(0x4000, 4).unwrap());
        let valid = json!({
            "entry": "0x4000",
            "decode_ranges": [{"isa":"arm","start":"0x4000","end":"0x4004","blake3":digest}],
            "decode_range_errors": [],
        });
        let invalid_cases = [
            vec![json!({
                "decode_ranges": [{"isa":"arm","start":"0x4000","end":"0x4004","blake3":"00".repeat(32)}],
                "decode_range_errors": [],
            })],
            vec![json!({
                "entry": "0x4000",
                "decode_ranges": [],
                "decode_range_errors": [],
            })],
            vec![json!({
                "entry": "0x4000",
                "decode_ranges": [{"isa":"arm","start":"0x4000","end":"0x4002","blake3":"00".repeat(32)}],
                "decode_range_errors": [],
            })],
            vec![json!({
                "entry": "0x4000",
                "decode_ranges": [],
                "decode_range_errors": [
                    {"kind":"empty_projection","address":"0x4004","end":null},
                    {"kind":"empty_projection","address":"0x4000","end":null}
                ],
            })],
        ];
        for records in invalid_cases {
            assert!(
                validate_inventory_records(&records, 1, FunctionOwner::Ghidra, &runtime,).is_err(),
                "accepted invalid terminal inventory: {records:?}"
            );
        }
        assert!(validate_inventory_records(&[valid], 2, FunctionOwner::Ghidra, &runtime,).is_err());
    }

    fn ghidra_record(name: &str, entry: u32, end: u32, image: &[u8]) -> Value {
        json!({
            "name": name,
            "primary_source": "default",
            "entry": hex(entry),
            "end": hex(end),
            "size": u64::from(end - entry),
            "decode_ranges": [{
                "isa": "arm",
                "start": hex(entry),
                "end": hex(end),
                "blake3": digest_hex(blake3::hash(&image[entry as usize..end as usize]).into()),
            }],
            "decode_range_errors": [],
            "data_refs": [],
        })
    }

    #[test]
    fn streaming_ghidra_inventory_matches_the_slice_validator() {
        let image = [0u8; 16];
        let runtime = RuntimeImage::from_plan(&image, 0, None).unwrap();
        let records = vec![
            ghidra_record("FUN_0000", 0, 4, &image),
            ghidra_record("FUN_0008", 8, 12, &image),
        ];
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("functions.json");
        std::fs::write(&path, serde_json::to_vec(&records).unwrap()).unwrap();

        let sliced = validate_ghidra_inventory_records(&records, records.len(), &runtime).unwrap();
        let streamed = read_ghidra_inventory_streaming(&path, &runtime).unwrap();

        assert_eq!(streamed.inventory.raw_count, sliced.raw_count);
        assert_eq!(streamed.inventory.accepted, sliced.accepted);
        assert_eq!(streamed.inventory.records, sliced.records);
        assert_eq!(streamed.functions[0].name, "FUN_0000");
        assert_eq!(streamed.functions[1].name, "FUN_0008");
        assert_eq!(streamed.functions[0].entry, 0);
        assert_eq!(streamed.functions[1].entry, 8);
    }

    #[test]
    fn streaming_ghidra_inventory_rejects_a_non_array() {
        let image = [0u8; 4];
        let runtime = RuntimeImage::from_plan(&image, 0, None).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("functions.json");
        std::fs::write(&path, br#"{"functions":[]}"#).unwrap();
        let error = read_ghidra_inventory_streaming(&path, &runtime).unwrap_err();
        assert!(
            error.to_string().contains("Ghidra functions array"),
            "{error}"
        );
    }

    #[test]
    fn streaming_ghidra_inventory_enforces_the_function_cap() {
        let image = [0u8; 16];
        let runtime = RuntimeImage::from_plan(&image, 0, None).unwrap();
        let records = vec![
            ghidra_record("FUN_0000", 0, 4, &image),
            ghidra_record("FUN_0008", 8, 12, &image),
        ];
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("functions.json");
        std::fs::write(&path, serde_json::to_vec(&records).unwrap()).unwrap();
        let error = read_ghidra_inventory_streaming_capped(&path, &runtime, 1).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("execution function count exceeds the supported limit"),
            "{error}"
        );
    }
}
