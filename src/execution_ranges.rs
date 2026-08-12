use crate::error::{Error, Result};
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum DecodeIsa {
    Arm,
    Thumb,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct DecodeRange {
    pub start: u32,
    pub end: u32,
    pub isa: DecodeIsa,
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
    Accepted(Vec<DecodeRange>),
    Quarantined(Vec<DecodeRangeError>),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ExecutionIdentity {
    pub entry: u32,
    pub decode_ranges: Vec<DecodeRange>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct TaggedExecutionRecord {
    pub entry: u32,
    pub projection: ExecutionProjection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValidatedInventory {
    pub raw_count: usize,
    pub accepted: usize,
    pub quarantined: usize,
    pub accepted_identities: Vec<ExecutionIdentity>,
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

/// Convert instruction extents into the one permitted tagged state. A single
/// defect discards all apparent coverage; callers keep collecting errors before
/// invoking this helper so later records remain independently usable.
pub(crate) fn canonicalize_instruction_extents(
    entry: u32,
    mut extents: Vec<DecodeRange>,
    image_start: u32,
    image_len: u32,
) -> ExecutionProjection {
    let image_end = image_start.checked_add(image_len);
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
        if extent.start < image_start || image_end.is_none_or(|end| extent.end > end) {
            errors.push(error(
                DecodeRangeErrorKind::ExtentOutsideImage,
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
    let mut ranges: Vec<DecodeRange> = Vec::new();
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
        return ExecutionProjection::Quarantined(canonicalize_errors(errors));
    }
    ExecutionProjection::Accepted(ranges)
}

pub(crate) fn execution_identity(
    entry: u32,
    projection: &ExecutionProjection,
) -> Result<Option<ExecutionIdentity>> {
    match projection {
        ExecutionProjection::Accepted(decode_ranges) if !decode_ranges.is_empty() => {
            Ok(Some(ExecutionIdentity {
                entry,
                decode_ranges: decode_ranges.clone(),
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

pub(crate) fn parse_projection(value: &Value) -> Result<ExecutionProjection> {
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
    let ranges = ranges.iter().map(parse_range).collect::<Result<Vec<_>>>()?;
    let errors = errors.iter().map(parse_error).collect::<Result<Vec<_>>>()?;
    match (ranges.is_empty(), errors.is_empty()) {
        (false, true) => Ok(ExecutionProjection::Accepted(ranges)),
        (true, false) => Ok(ExecutionProjection::Quarantined(errors)),
        _ => Err(invalid(
            "decode projection must contain exactly one non-empty tag array",
        )),
    }
}

/// Validates exact producer representation rather than repairing it. This is
/// deliberately separate from canonicalization: consumers reject malformed or
/// old inventories rather than silently rewriting producer evidence.
pub(crate) fn validate_inventory_projection(
    entry: u32,
    projection: &ExecutionProjection,
    image_start: u32,
    image_len: u32,
) -> Result<()> {
    match projection {
        ExecutionProjection::Accepted(ranges) => {
            let canonical =
                canonicalize_instruction_extents(entry, ranges.clone(), image_start, image_len);
            if canonical != *projection {
                return Err(invalid("accepted decode_ranges are not canonical"));
            }
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
        }
    }
    Ok(())
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

pub(crate) fn validate_inventory_records(
    records: &[Value],
    expected_raw_count: usize,
    image_start: u32,
    image_len: u32,
) -> Result<ValidatedInventory> {
    let mut projections = Vec::with_capacity(records.len());
    let mut accepted_identities = BTreeSet::new();
    let mut accepted = 0usize;
    let mut quarantined = 0usize;
    let mut tagged_records = Vec::with_capacity(records.len());
    for record in records {
        let object = record
            .as_object()
            .ok_or_else(|| invalid("inventory record must be an object"))?;
        let entry = parse_hex(required_string(object, "entry")?)?;
        let projection = parse_projection(record)?;
        validate_inventory_projection(entry, &projection, image_start, image_len)?;
        if let Some(identity) = execution_identity(entry, &projection)? {
            accepted = accepted
                .checked_add(1)
                .ok_or_else(|| invalid("accepted inventory count overflow"))?;
            accepted_identities.insert(identity);
        } else {
            quarantined = quarantined
                .checked_add(1)
                .ok_or_else(|| invalid("quarantined inventory count overflow"))?;
        }
        tagged_records.push(TaggedExecutionRecord {
            entry,
            projection: projection.clone(),
        });
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
        accepted_identities: accepted_identities.into_iter().collect(),
        records: tagged_records,
    })
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

fn range_to_json(range: &DecodeRange) -> Value {
    json!({"isa": isa_name(range.isa), "start": hex(range.start), "end": hex(range.end)})
}

fn error_to_json(error: &DecodeRangeError) -> Value {
    json!({"kind": error_kind_name(error.kind), "address": hex(error.address), "end": error.end.map(hex)})
}

fn parse_range(value: &Value) -> Result<DecodeRange> {
    let object = strict_object(value, &["isa", "start", "end"])?;
    let isa = match required_string(object, "isa")? {
        "arm" => DecodeIsa::Arm,
        "thumb" => DecodeIsa::Thumb,
        _ => return Err(invalid("unknown decode ISA")),
    };
    Ok(DecodeRange {
        isa,
        start: parse_hex(required_string(object, "start")?)?,
        end: parse_hex(required_string(object, "end")?)?,
    })
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

fn invalid(message: &str) -> Error {
    Error::Serialize(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn tagged_projection_serializes_canonical_wire_shape() {
        let projection = ExecutionProjection::Accepted(vec![DecodeRange {
            isa: DecodeIsa::Thumb,
            start: 0x4001_0000,
            end: 0x4001_0004,
        }]);

        assert_eq!(
            projection_to_json(&projection).unwrap(),
            json!({
                "decode_ranges": [{"isa":"thumb","start":"0x40010000","end":"0x40010004"}],
                "decode_range_errors": [],
            })
        );
    }

    #[test]
    fn projection_parser_rejects_noncanonical_or_nonexclusive_tags() {
        for bad in [
            json!({"decode_ranges": [], "decode_range_errors": []}),
            json!({"decode_ranges": [{"isa":"arm","start":"0x4000","end":"0x4004"}], "decode_range_errors": [{"kind":"empty_projection","address":"0x4000","end":null}]}),
            json!({"decode_ranges": [{"isa":"ARM","start":"0x4000","end":"0x4004"}], "decode_range_errors": []}),
            json!({"decode_ranges": [{"isa":"arm","start":"0X4000","end":"0x4004"}], "decode_range_errors": []}),
            json!({"decode_ranges": [{"isa":"arm","start":"0x4000","end":"0x4004","extra":true}], "decode_range_errors": []}),
        ] {
            assert!(
                parse_projection(&bad).is_err(),
                "accepted invalid projection: {bad}"
            );
        }
    }

    #[test]
    fn canonicalization_merges_only_adjacent_same_isa_and_requires_entry_start() {
        let projection = canonicalize_instruction_extents(
            0x4000,
            vec![
                DecodeRange {
                    isa: DecodeIsa::Thumb,
                    start: 0x4006,
                    end: 0x4008,
                },
                DecodeRange {
                    isa: DecodeIsa::Thumb,
                    start: 0x4000,
                    end: 0x4002,
                },
                DecodeRange {
                    isa: DecodeIsa::Thumb,
                    start: 0x4002,
                    end: 0x4004,
                },
                DecodeRange {
                    isa: DecodeIsa::Thumb,
                    start: 0x4004,
                    end: 0x4006,
                },
                DecodeRange {
                    isa: DecodeIsa::Arm,
                    start: 0x4008,
                    end: 0x400c,
                },
            ],
            0x4000,
            0x10,
        );
        assert_eq!(
            projection,
            ExecutionProjection::Accepted(vec![
                DecodeRange {
                    isa: DecodeIsa::Thumb,
                    start: 0x4000,
                    end: 0x4008
                },
                DecodeRange {
                    isa: DecodeIsa::Arm,
                    start: 0x4008,
                    end: 0x400c
                },
            ])
        );
    }

    #[test]
    fn canonicalization_quarantines_when_merging_makes_entry_interior() {
        let projection = canonicalize_instruction_extents(
            0x4004,
            vec![
                DecodeRange {
                    isa: DecodeIsa::Arm,
                    start: 0x4000,
                    end: 0x4004,
                },
                DecodeRange {
                    isa: DecodeIsa::Arm,
                    start: 0x4004,
                    end: 0x4008,
                },
            ],
            0x4000,
            0x10,
        );
        let expected = ExecutionProjection::Quarantined(vec![DecodeRangeError {
            kind: DecodeRangeErrorKind::EntryNotRangeStart,
            address: 0x4004,
            end: None,
        }]);
        assert_eq!(projection, expected);

        let record = json!({
            "entry":"0x4004",
            "decode_ranges":[],
            "decode_range_errors":[{
                "kind":"entry_not_range_start",
                "address":"0x4004",
                "end":null
            }]
        });
        let inventory = validate_inventory_records(&[record], 1, 0x4000, 0x10).unwrap();
        assert_eq!(inventory.accepted, 0);
        assert_eq!(inventory.quarantined, 1);
    }

    #[test]
    fn canonicalization_quarantines_whole_record_with_sorted_deduplicated_errors() {
        let projection = canonicalize_instruction_extents(
            0x4001,
            vec![
                DecodeRange {
                    isa: DecodeIsa::Thumb,
                    start: 0x4001,
                    end: 0x4003,
                },
                DecodeRange {
                    isa: DecodeIsa::Thumb,
                    start: 0x4002,
                    end: 0x4004,
                },
                DecodeRange {
                    isa: DecodeIsa::Thumb,
                    start: 0x4001,
                    end: 0x4003,
                },
            ],
            0x4000,
            0x10,
        );
        assert_eq!(
            projection,
            ExecutionProjection::Quarantined(vec![
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
            ])
        );
    }

    #[test]
    fn accepted_identity_dedup_uses_the_complete_tagged_range_list() {
        let arm = ExecutionIdentity {
            entry: 0x4000,
            decode_ranges: vec![DecodeRange {
                isa: DecodeIsa::Arm,
                start: 0x4000,
                end: 0x4004,
            }],
        };
        let thumb = ExecutionIdentity {
            entry: 0x4000,
            decode_ranges: vec![DecodeRange {
                isa: DecodeIsa::Thumb,
                start: 0x4000,
                end: 0x4004,
            }],
        };
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
        let empty_accepted = ExecutionProjection::Accepted(vec![]);
        let empty_quarantined = ExecutionProjection::Quarantined(vec![]);
        for projection in [&empty_accepted, &empty_quarantined] {
            assert!(projection_to_json(projection).is_err());
            assert!(execution_identity(0x4000, projection).is_err());
            assert!(validate_inventory_projection(0x4000, projection, 0x4000, 4).is_err());
        }
    }

    #[test]
    fn inventory_conservation_detects_an_omitted_raw_record() {
        let projections = vec![ExecutionProjection::Accepted(vec![DecodeRange {
            isa: DecodeIsa::Thumb,
            start: 0x4000,
            end: 0x4002,
        }])];
        assert!(inventory_count_conserved(1, &projections));
        assert!(!inventory_count_conserved(2, &projections));
    }

    #[test]
    fn projection_parser_rejects_missing_and_malformed_error_fields() {
        for bad in [
            json!({"decode_range_errors": []}),
            json!({"decode_ranges": []}),
            json!({"decode_ranges": [], "decode_range_errors": [{"kind":"unknown", "address":"0x4000", "end":null}]}),
            json!({"decode_ranges": [], "decode_range_errors": [{"kind":"empty_projection", "address":16384, "end":null}]}),
            json!({"decode_ranges": [], "decode_range_errors": [{"kind":"empty_projection", "address":"0x04000", "end":false}]}),
        ] {
            assert!(
                parse_projection(&bad).is_err(),
                "accepted malformed projection: {bad}"
            );
        }
        assert_eq!(
            parse_projection(&json!({"decode_ranges": [], "decode_range_errors": [{"kind":"raw_byte_mismatch", "address":"0x4000", "end":"0x4004"}]})).unwrap(),
            ExecutionProjection::Quarantined(vec![DecodeRangeError { kind: DecodeRangeErrorKind::RawByteMismatch, address: 0x4000, end: Some(0x4004) }])
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
        let left = ExecutionIdentity {
            entry: 0x4000,
            decode_ranges: vec![DecodeRange {
                isa: DecodeIsa::Thumb,
                start: 0x4000,
                end: 0x4006,
            }],
        };
        let right = ExecutionIdentity {
            entry: 0x4002,
            decode_ranges: vec![DecodeRange {
                isa: DecodeIsa::Thumb,
                start: 0x4002,
                end: 0x4008,
            }],
        };
        assert_ne!(
            left, right,
            "same-ISA overlaps remain distinct complete identities"
        );
    }

    #[test]
    fn terminal_inventory_deduplicates_only_complete_accepted_identities() {
        let records = vec![
            json!({
                "entry": "0x4000",
                "decode_ranges": [{"isa":"arm","start":"0x4000","end":"0x4004"}],
                "decode_range_errors": [],
            }),
            json!({
                "entry": "0x4000",
                "decode_ranges": [{"isa":"arm","start":"0x4000","end":"0x4004"}],
                "decode_range_errors": [],
            }),
            json!({
                "entry": "0x4000",
                "decode_ranges": [{"isa":"thumb","start":"0x4000","end":"0x4004"}],
                "decode_range_errors": [],
            }),
            json!({
                "entry": "0x4002",
                "decode_ranges": [{"isa":"thumb","start":"0x4002","end":"0x4006"}],
                "decode_range_errors": [],
            }),
            json!({
                "entry": "0x4008",
                "decode_ranges": [],
                "decode_range_errors": [{"kind":"empty_projection","address":"0x4008","end":null}],
            }),
        ];

        let inventory = validate_inventory_records(&records, 5, 0x4000, 0x10).unwrap();

        assert_eq!(inventory.raw_count, 5);
        assert_eq!(inventory.accepted, 4);
        assert_eq!(inventory.quarantined, 1);
        assert_eq!(inventory.accepted_identities.len(), 3);
        assert!(inventory.accepted_identities.iter().any(|identity| {
            identity.entry == 0x4000 && identity.decode_ranges[0].isa == DecodeIsa::Arm
        }));
        assert!(inventory.accepted_identities.iter().any(|identity| {
            identity.entry == 0x4000 && identity.decode_ranges[0].isa == DecodeIsa::Thumb
        }));
        assert!(
            inventory
                .accepted_identities
                .iter()
                .any(|identity| identity.entry == 0x4002)
        );
    }

    #[test]
    fn terminal_inventory_rejects_orphans_malformed_tags_and_count_mismatch() {
        let valid = json!({
            "entry": "0x4000",
            "decode_ranges": [{"isa":"arm","start":"0x4000","end":"0x4004"}],
            "decode_range_errors": [],
        });
        let invalid_cases = [
            vec![json!({
                "decode_ranges": [{"isa":"arm","start":"0x4000","end":"0x4004"}],
                "decode_range_errors": [],
            })],
            vec![json!({
                "entry": "0x4000",
                "decode_ranges": [],
                "decode_range_errors": [],
            })],
            vec![json!({
                "entry": "0x4000",
                "decode_ranges": [{"isa":"arm","start":"0x4000","end":"0x4002"}],
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
                validate_inventory_records(&records, 1, 0x4000, 0x10).is_err(),
                "accepted invalid terminal inventory: {records:?}"
            );
        }
        assert!(validate_inventory_records(&[valid], 2, 0x4000, 0x10).is_err());
    }
}
