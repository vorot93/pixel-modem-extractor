#[cfg_attr(not(test), allow(dead_code))]
mod artifact;
mod decompress;

pub(crate) use self::artifact::{
    ArtifactSegment, MaterializedScatter, read_materialized, restage_materialized,
};
pub use self::artifact::{LOAD_MAP_FORMAT, MaterializedLoadMap, clear_materialized, materialize};
use self::decompress::{DecodeBudget, Decoded, decompress1};
use scaleservers_arm32_assembly::{
    Arm32BlockAddressMode, Arm32Condition, Arm32GeneralPurposeRegister, ArmA32Instruction,
};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

pub const MAX_ENTRIES: usize = 256;
pub const MAX_LOGICAL_OUTPUT: u64 = 512 * 1024 * 1024;
pub const MAX_DECODED_WORK: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Null,
    Copy,
    Decompress1,
    Zero,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Descriptor {
    pub source: u32,
    pub destination: u32,
    pub size: u32,
    pub handler: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandlerMap {
    pub null: u32,
    pub copy: u32,
    pub decompress1: u32,
    pub zero: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlannedOutput {
    None,
    SelfCopy,
    Bytes(Vec<u8>),
    ZeroFill,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedEntry {
    pub index: usize,
    pub descriptor: Descriptor,
    pub operation: Operation,
    pub compressed_size: Option<u32>,
    pub output: PlannedOutput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlannedStorage<'a> {
    None,
    SelfCopy,
    Bytes(&'a [u8]),
    ZeroFill,
}

impl PlannedEntry {
    pub(crate) fn storage(&self) -> PlannedStorage<'_> {
        match &self.output {
            PlannedOutput::None => PlannedStorage::None,
            PlannedOutput::SelfCopy => PlannedStorage::SelfCopy,
            PlannedOutput::Bytes(bytes)
                if self.operation == Operation::Decompress1
                    && bytes.iter().all(|&byte| byte == 0) =>
            {
                PlannedStorage::ZeroFill
            }
            PlannedOutput::Bytes(bytes) => PlannedStorage::Bytes(bytes),
            PlannedOutput::ZeroFill => PlannedStorage::ZeroFill,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadPlan {
    pub image_base: u32,
    pub image_size: u32,
    pub loader_address: u32,
    pub literal_pair_address: u32,
    pub table_start: u32,
    pub table_end: u32,
    pub handlers: HandlerMap,
    pub entries: Vec<PlannedEntry>,
    pub logical_output_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScatterError {
    #[error("scatter candidate at {loader:#010x}, entry {entry:?}: {reason}")]
    Malformed {
        loader: u32,
        entry: Option<usize>,
        reason: String,
    },
    #[error("ambiguous scatter candidates: {loaders:?}")]
    Ambiguous { loaders: Vec<u32> },
    #[error("scatter resource limit exceeded: {what} > {limit:#x}")]
    ResourceLimit { what: &'static str, limit: u64 },
}

const DESCRIPTOR_SIZE: u32 = 16;
const SENTINEL_COUNT: usize = 2;

#[derive(Clone, Copy)]
struct RawImage<'a> {
    bytes: &'a [u8],
    base: u32,
    size: u32,
    end: u32,
}

impl<'a> RawImage<'a> {
    fn new(bytes: &'a [u8], base: u32) -> Result<Self, ScatterError> {
        let size = u32::try_from(bytes.len()).map_err(|_| ScatterError::ResourceLimit {
            what: "raw image size",
            limit: u64::from(u32::MAX),
        })?;
        let end = base.checked_add(size).ok_or_else(|| {
            malformed(base, None, "raw image range wraps the 32-bit address space")
        })?;
        Ok(Self {
            bytes,
            base,
            size,
            end,
        })
    }

    fn slice(self, address: u32, length: u32) -> Option<&'a [u8]> {
        self.bytes.get(self.range(address, length)?)
    }

    fn range(self, address: u32, length: u32) -> Option<Range<usize>> {
        let start = address.checked_sub(self.base)?;
        let end = start.checked_add(length)?;
        if end > self.size {
            return None;
        }
        let start = usize::try_from(start).ok()?;
        let end = usize::try_from(end).ok()?;
        Some(start..end)
    }
}

#[derive(Clone, Copy)]
struct Anchor {
    loader: u32,
    literal_pair: u32,
    table_start: u32,
    table_end: u32,
}

struct Assignment {
    handlers: HandlerMap,
    decoded: BTreeMap<usize, Decoded>,
}

enum ValidatedOutput {
    None,
    SelfCopy,
    CopySource(Range<usize>),
    Bytes(Vec<u8>),
    ZeroFill,
}

struct ValidatedEntry {
    index: usize,
    descriptor: Descriptor,
    operation: Operation,
    compressed_size: Option<u32>,
    output: ValidatedOutput,
}

struct ValidatedCandidate {
    image_base: u32,
    image_size: u32,
    anchor: Anchor,
    handlers: HandlerMap,
    entries: Vec<ValidatedEntry>,
    logical_output_size: u64,
}

impl ValidatedCandidate {
    fn into_load_plan(self, raw: RawImage<'_>) -> LoadPlan {
        let entries = self
            .entries
            .into_iter()
            .map(|entry| PlannedEntry {
                index: entry.index,
                descriptor: entry.descriptor,
                operation: entry.operation,
                compressed_size: entry.compressed_size,
                output: match entry.output {
                    ValidatedOutput::None => PlannedOutput::None,
                    ValidatedOutput::SelfCopy => PlannedOutput::SelfCopy,
                    ValidatedOutput::CopySource(range) => {
                        PlannedOutput::Bytes(raw.bytes[range].to_vec())
                    }
                    ValidatedOutput::Bytes(bytes) => PlannedOutput::Bytes(bytes),
                    ValidatedOutput::ZeroFill => PlannedOutput::ZeroFill,
                },
            })
            .collect();
        LoadPlan {
            image_base: self.image_base,
            image_size: self.image_size,
            loader_address: self.anchor.loader,
            literal_pair_address: self.anchor.literal_pair,
            table_start: self.anchor.table_start,
            table_end: self.anchor.table_end,
            handlers: self.handlers,
            entries,
            logical_output_size: self.logical_output_size,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct DestinationRange {
    start: u32,
    end: u32,
    entry: usize,
}

#[derive(Default)]
struct ValidCandidates {
    sole: Option<ValidatedCandidate>,
    loaders: Vec<u32>,
}

impl ValidCandidates {
    fn record(&mut self, candidate: ValidatedCandidate) {
        let loader = candidate.anchor.loader;
        if self.loaders.is_empty() {
            self.sole = Some(candidate);
        } else {
            self.sole = None;
        }
        self.loaders.push(loader);
    }

    fn finish(mut self) -> Result<Option<ValidatedCandidate>, ScatterError> {
        if self.loaders.len() < 2 {
            return Ok(self.sole);
        }
        self.loaders.sort_unstable();
        Err(ScatterError::Ambiguous {
            loaders: self.loaders,
        })
    }
}

pub fn discover(image: &[u8], base: u32) -> Result<Option<LoadPlan>, ScatterError> {
    let raw = RawImage::new(image, base)?;
    let mut valid = ValidCandidates::default();
    let mut first_failure = None;
    let mut decode_budget = DecodeBudget::new(MAX_DECODED_WORK);

    let Some(last_loader_offset) = image.len().checked_sub(16) else {
        return Ok(None);
    };
    for loader_offset in (0..=last_loader_offset).step_by(4) {
        let Some(window_end) = loader_offset.checked_add(16) else {
            continue;
        };
        let Some(window) = image.get(loader_offset..window_end) else {
            continue;
        };
        let Some(immediate) = match_anchor(window) else {
            continue;
        };

        let loader_offset =
            u32::try_from(loader_offset).map_err(|_| ScatterError::ResourceLimit {
                what: "raw image size",
                limit: u64::from(u32::MAX),
            })?;
        let loader = base.checked_add(loader_offset).ok_or_else(|| {
            malformed(base, None, "loader address wraps the 32-bit address space")
        })?;
        let Some((anchor, table)) = plausible_table(raw, loader, immediate) else {
            continue;
        };

        match validate_candidate(raw, anchor, table, &mut decode_budget) {
            Ok(plan) => valid.record(plan),
            Err(error) if first_failure.is_none() => first_failure = Some(error),
            Err(_) => {}
        }
    }

    if let Some(error) = first_failure {
        return Err(error);
    }
    Ok(valid
        .finish()?
        .map(|candidate| candidate.into_load_plan(raw)))
}

fn match_anchor(bytes: &[u8]) -> Option<u32> {
    use Arm32Condition::AlwaysUnconditional;
    use Arm32GeneralPurposeRegister::{R10, R11, R15};

    let ArmA32Instruction::Add_Immediate_A1(
        AlwaysUnconditional,
        false,
        base_register,
        R15,
        immediate,
    ) = decode_a32(bytes.get(0..4)?)?
    else {
        return None;
    };
    // LDM overwrites R10/R11, while writing the initial ADD to PC redirects control.
    if matches!(base_register, R10 | R11 | R15) {
        return None;
    }
    let ArmA32Instruction::Ldm_A1(
        AlwaysUnconditional,
        Arm32BlockAddressMode::IncrementAfter,
        ldm_base,
        false,
        false,
        registers,
    ) = decode_a32(bytes.get(4..8)?)?
    else {
        return None;
    };
    if ldm_base != base_register || registers.as_slice() != [R10, R11] {
        return None;
    }

    let third = decode_a32(bytes.get(8..12)?)?;
    let third_matches = matches!(
        third,
        ArmA32Instruction::Add_Register_A1(
            AlwaysUnconditional,
            false,
            R10,
            R10,
            register,
            shift,
        ) if register == base_register && shift.is_none()
    );
    if !third_matches {
        return None;
    }
    let fourth = decode_a32(bytes.get(12..16)?)?;
    let fourth_matches = matches!(
        fourth,
        ArmA32Instruction::Add_Register_A1(
            AlwaysUnconditional,
            false,
            R11,
            R11,
            register,
            shift,
        ) if register == base_register && shift.is_none()
    );
    fourth_matches.then_some(immediate)
}

fn decode_a32(bytes: &[u8]) -> Option<ArmA32Instruction> {
    if bytes.len() != 4 {
        return None;
    }
    let mut offset = 0;
    let instruction = ArmA32Instruction::decode(&mut bytes.iter(), &mut offset)
        .ok()
        .flatten()?;
    (offset == 4).then_some(instruction)
}

fn plausible_table(raw: RawImage<'_>, loader: u32, immediate: u32) -> Option<(Anchor, &[u8])> {
    let literal_pair = loader.wrapping_add(8).wrapping_add(immediate);
    let literals = raw.slice(literal_pair, 8)?;
    let table_start = literal_pair.wrapping_add(read_u32(literals, 0)?);
    let table_end = literal_pair.wrapping_add(read_u32(literals, 4)?);
    let table_length = table_end.checked_sub(table_start)?;
    if table_length == 0 || table_length % DESCRIPTOR_SIZE != 0 {
        return None;
    }
    let entry_count = usize::try_from(table_length / DESCRIPTOR_SIZE).ok()?;
    if !(1..=MAX_ENTRIES).contains(&entry_count) {
        return None;
    }

    let table = raw.slice(table_start, table_length)?;
    let first = parse_descriptor(table.get(0..16)?)?;
    let second = parse_descriptor(table.get(16..32)?)?;
    let sentinels_match = first.source != 0
        && first.destination == 0
        && first.size == 0
        && first.handler != 0
        && second.source == 0
        && second.destination == first.source
        && second.size == 0
        && second.handler == first.handler;
    if !sentinels_match {
        return None;
    }

    Some((
        Anchor {
            loader,
            literal_pair,
            table_start,
            table_end,
        },
        table,
    ))
}

fn validate_candidate(
    raw: RawImage<'_>,
    anchor: Anchor,
    table: &[u8],
    decode_budget: &mut DecodeBudget,
) -> Result<ValidatedCandidate, ScatterError> {
    let descriptors = parse_table(table, anchor.loader)?;
    let assignment = classify(raw, anchor.loader, &descriptors, decode_budget)?;
    validate_plan(raw, anchor, descriptors, assignment)
}

fn parse_table(table: &[u8], loader: u32) -> Result<Vec<Descriptor>, ScatterError> {
    let entry_count = table.len() / DESCRIPTOR_SIZE as usize;
    let mut descriptors = Vec::with_capacity(entry_count);
    for index in 0..entry_count {
        let start = index
            .checked_mul(DESCRIPTOR_SIZE as usize)
            .ok_or_else(|| malformed(loader, Some(index), "descriptor offset overflows"))?;
        let end = start
            .checked_add(DESCRIPTOR_SIZE as usize)
            .ok_or_else(|| malformed(loader, Some(index), "descriptor end overflows"))?;
        let bytes = table.get(start..end).ok_or_else(|| {
            malformed(
                loader,
                Some(index),
                "descriptor extends past exact table end",
            )
        })?;
        let descriptor = parse_descriptor(bytes)
            .ok_or_else(|| malformed(loader, Some(index), "descriptor is truncated"))?;
        descriptors.push(descriptor);
    }
    Ok(descriptors)
}

fn parse_descriptor(bytes: &[u8]) -> Option<Descriptor> {
    Some(Descriptor {
        source: read_u32(bytes, 0)?,
        destination: read_u32(bytes, 4)?,
        size: read_u32(bytes, 8)?,
        handler: read_u32(bytes, 12)?,
    })
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    Some(u32::from_le_bytes(bytes.get(offset..end)?.try_into().ok()?))
}

fn classify(
    raw: RawImage<'_>,
    loader: u32,
    descriptors: &[Descriptor],
    decode_budget: &mut DecodeBudget,
) -> Result<Assignment, ScatterError> {
    let null = descriptors
        .first()
        .ok_or_else(|| malformed(loader, None, "bounded table is empty"))?
        .handler;
    let mut distinct_handlers = BTreeSet::new();
    for (index, descriptor) in descriptors.iter().enumerate() {
        if raw.slice(descriptor.handler & !1, 1).is_none() {
            return Err(malformed(
                loader,
                Some(index),
                "handler does not point inside the raw image",
            ));
        }
        if index >= SENTINEL_COUNT {
            if descriptor.size == 0 {
                return Err(malformed(loader, Some(index), "useful entry has zero size"));
            }
            if descriptor.destination == 0 {
                return Err(malformed(
                    loader,
                    Some(index),
                    "useful entry has a zero destination",
                ));
            }
            if descriptor.handler == null {
                return Err(malformed(
                    loader,
                    Some(index),
                    "null handler recurs after the sentinel pair",
                ));
            }
        }
        if distinct_handlers.insert(descriptor.handler) && distinct_handlers.len() > 4 {
            return Err(malformed(
                loader,
                Some(index),
                "bounded table contains more than four handler identities",
            ));
        }
    }
    if distinct_handlers.len() != 4 {
        return Err(malformed(
            loader,
            None,
            "bounded table does not contain exactly four handler identities",
        ));
    }

    let zero = descriptors
        .last()
        .ok_or_else(|| malformed(loader, None, "bounded table is empty"))?
        .handler;
    let useful = descriptors
        .get(SENTINEL_COUNT..)
        .ok_or_else(|| malformed(loader, None, "bounded table has no useful entries"))?;
    let zero_start = useful
        .iter()
        .position(|descriptor| descriptor.handler == zero)
        .and_then(|index| index.checked_add(SENTINEL_COUNT))
        .ok_or_else(|| malformed(loader, None, "zero suffix is absent"))?;
    if descriptors[zero_start..]
        .iter()
        .any(|descriptor| descriptor.handler != zero)
    {
        return Err(malformed(
            loader,
            Some(zero_start),
            "zero handler occurrences do not form the final table suffix",
        ));
    }

    distinct_handlers.remove(&null);
    distinct_handlers.remove(&zero);
    let mut remaining = distinct_handlers.into_iter();
    let first = remaining
        .next()
        .ok_or_else(|| malformed(loader, None, "copy/decompress handlers are absent"))?;
    let second = remaining
        .next()
        .ok_or_else(|| malformed(loader, None, "copy/decompress handler is absent"))?;
    if remaining.next().is_some() {
        return Err(malformed(
            loader,
            None,
            "too many copy/decompress handler candidates",
        ));
    }

    let mut assignments = Vec::new();
    let mut failures = Vec::new();
    for (copy, decompress1_handler) in [(first, second), (second, first)] {
        if let Err(error) = validate_copy_handler(raw, loader, descriptors, copy) {
            failures.push(error);
            continue;
        }
        match decode_handler(raw, loader, descriptors, decompress1_handler, decode_budget) {
            Ok(decoded) => assignments.push(Assignment {
                handlers: HandlerMap {
                    null,
                    copy,
                    decompress1: decompress1_handler,
                    zero,
                },
                decoded,
            }),
            Err(error @ ScatterError::ResourceLimit { .. }) => return Err(error),
            Err(error) => failures.push(error),
        }
    }

    match assignments.len() {
        1 => assignments
            .pop()
            .ok_or_else(|| malformed(loader, None, "handler assignment disappeared")),
        0 => Err(preferred_classification_failure(failures, loader)),
        _ => Err(malformed(
            loader,
            None,
            "bounded table has ambiguous handler assignments",
        )),
    }
}

fn validate_copy_handler(
    raw: RawImage<'_>,
    loader: u32,
    descriptors: &[Descriptor],
    handler: u32,
) -> Result<(), ScatterError> {
    let mut has_self_copy = false;
    for (index, descriptor) in descriptors.iter().enumerate() {
        if descriptor.handler != handler {
            continue;
        }
        if raw.slice(descriptor.source, descriptor.size).is_none() {
            return Err(malformed(
                loader,
                Some(index),
                "copy source range escapes the immutable raw image",
            ));
        }
        has_self_copy |= descriptor.source == descriptor.destination;
    }
    if !has_self_copy {
        return Err(malformed(
            loader,
            None,
            "copy handler has no exact self-copy entry",
        ));
    }
    Ok(())
}

fn decode_handler(
    raw: RawImage<'_>,
    loader: u32,
    descriptors: &[Descriptor],
    handler: u32,
    budget: &mut DecodeBudget,
) -> Result<BTreeMap<usize, Decoded>, ScatterError> {
    let mut decoded = BTreeMap::new();
    for (index, descriptor) in descriptors.iter().enumerate() {
        if descriptor.handler != handler {
            continue;
        }
        let remaining = raw
            .end
            .checked_sub(descriptor.source)
            .filter(|&size| size > 0);
        let input = remaining
            .and_then(|size| raw.slice(descriptor.source, size))
            .ok_or_else(|| {
                malformed(
                    loader,
                    Some(index),
                    "decompress1 source does not begin inside the raw image",
                )
            })?;
        let expected = usize::try_from(descriptor.size).map_err(|_| {
            malformed(
                loader,
                Some(index),
                "decompress1 output size does not fit the host",
            )
        })?;
        let output = decompress1(input, expected, budget)
            .map_err(|error| with_candidate_context(error, loader, index))?;
        decoded.insert(index, output);
    }
    Ok(decoded)
}

fn preferred_classification_failure(mut failures: Vec<ScatterError>, loader: u32) -> ScatterError {
    let indexed = failures
        .iter()
        .position(|error| matches!(error, ScatterError::Malformed { entry: Some(_), .. }));
    if let Some(index) = indexed {
        return failures.swap_remove(index);
    }
    failures
        .into_iter()
        .next()
        .unwrap_or_else(|| malformed(loader, None, "no handler assignment is valid"))
}

fn validate_plan(
    raw: RawImage<'_>,
    anchor: Anchor,
    descriptors: Vec<Descriptor>,
    mut assignment: Assignment,
) -> Result<ValidatedCandidate, ScatterError> {
    let mut entries = Vec::with_capacity(descriptors.len());
    let mut logical_output_size = 0u64;
    let mut materialized = Vec::new();
    let mut destinations = Vec::new();

    for (index, descriptor) in descriptors.into_iter().enumerate() {
        let operation =
            operation_for(descriptor.handler, assignment.handlers).ok_or_else(|| {
                malformed(
                    anchor.loader,
                    Some(index),
                    "entry has no classified operation",
                )
            })?;
        if operation == Operation::Null {
            entries.push(ValidatedEntry {
                index,
                descriptor,
                operation,
                compressed_size: None,
                output: ValidatedOutput::None,
            });
            continue;
        }

        logical_output_size = logical_output_size
            .checked_add(u64::from(descriptor.size))
            .ok_or(ScatterError::ResourceLimit {
                what: "logical output",
                limit: MAX_LOGICAL_OUTPUT,
            })?;
        if logical_output_size > MAX_LOGICAL_OUTPUT {
            return Err(ScatterError::ResourceLimit {
                what: "logical output",
                limit: MAX_LOGICAL_OUTPUT,
            });
        }
        let destination_end = descriptor
            .destination
            .checked_add(descriptor.size)
            .ok_or_else(|| {
                malformed(
                    anchor.loader,
                    Some(index),
                    "destination range wraps the 32-bit address space",
                )
            })?;

        let (compressed_size, output, creates_destination) = match operation {
            Operation::Null => unreachable!("null entries are handled above"),
            Operation::Copy => {
                let source = raw
                    .range(descriptor.source, descriptor.size)
                    .ok_or_else(|| {
                        malformed(
                            anchor.loader,
                            Some(index),
                            "copy source range escapes the immutable raw image",
                        )
                    })?;
                let source_end =
                    descriptor
                        .source
                        .checked_add(descriptor.size)
                        .ok_or_else(|| {
                            malformed(
                                anchor.loader,
                                Some(index),
                                "copy source range wraps the 32-bit address space",
                            )
                        })?;
                reject_source_dependency(
                    anchor.loader,
                    index,
                    descriptor.source,
                    source_end,
                    &materialized,
                )?;
                if descriptor.source == descriptor.destination {
                    (None, ValidatedOutput::SelfCopy, false)
                } else {
                    reject_raw_collision(raw, anchor.loader, index, descriptor, destination_end)?;
                    (None, ValidatedOutput::CopySource(source), true)
                }
            }
            Operation::Decompress1 => {
                let decoded = assignment.decoded.remove(&index).ok_or_else(|| {
                    malformed(
                        anchor.loader,
                        Some(index),
                        "decompress1 output was not retained during classification",
                    )
                })?;
                let compressed_size = u32::try_from(decoded.consumed).map_err(|_| {
                    malformed(
                        anchor.loader,
                        Some(index),
                        "compressed stream size does not fit u32",
                    )
                })?;
                let source_end =
                    descriptor
                        .source
                        .checked_add(compressed_size)
                        .ok_or_else(|| {
                            malformed(
                                anchor.loader,
                                Some(index),
                                "compressed source range wraps the 32-bit address space",
                            )
                        })?;
                if raw.slice(descriptor.source, compressed_size).is_none() {
                    return Err(malformed(
                        anchor.loader,
                        Some(index),
                        "compressed source range escapes the immutable raw image",
                    ));
                }
                reject_source_dependency(
                    anchor.loader,
                    index,
                    descriptor.source,
                    source_end,
                    &materialized,
                )?;
                reject_raw_collision(raw, anchor.loader, index, descriptor, destination_end)?;
                (
                    Some(compressed_size),
                    ValidatedOutput::Bytes(decoded.bytes),
                    true,
                )
            }
            Operation::Zero => {
                reject_raw_collision(raw, anchor.loader, index, descriptor, destination_end)?;
                (None, ValidatedOutput::ZeroFill, true)
            }
        };

        let destination = DestinationRange {
            start: descriptor.destination,
            end: destination_end,
            entry: index,
        };
        destinations.push(destination);
        if creates_destination {
            materialized.push(destination);
        }
        entries.push(ValidatedEntry {
            index,
            descriptor,
            operation,
            compressed_size,
            output,
        });
    }

    destinations.sort_unstable_by_key(|range| (range.start, range.end, range.entry));
    for adjacent in destinations.windows(2) {
        let [first, second] = adjacent else {
            continue;
        };
        if ranges_overlap(first.start, first.end, second.start, second.end) {
            return Err(malformed(
                anchor.loader,
                Some(second.entry),
                format!("destination overlaps entry {}", first.entry),
            ));
        }
    }

    Ok(ValidatedCandidate {
        image_base: raw.base,
        image_size: raw.size,
        anchor,
        handlers: assignment.handlers,
        entries,
        logical_output_size,
    })
}

fn operation_for(handler: u32, handlers: HandlerMap) -> Option<Operation> {
    if handler == handlers.null {
        Some(Operation::Null)
    } else if handler == handlers.copy {
        Some(Operation::Copy)
    } else if handler == handlers.decompress1 {
        Some(Operation::Decompress1)
    } else if handler == handlers.zero {
        Some(Operation::Zero)
    } else {
        None
    }
}

fn reject_source_dependency(
    loader: u32,
    index: usize,
    source_start: u32,
    source_end: u32,
    earlier_destinations: &[DestinationRange],
) -> Result<(), ScatterError> {
    if let Some(previous) = earlier_destinations.iter().find(|destination| {
        ranges_overlap(source_start, source_end, destination.start, destination.end)
    }) {
        return Err(malformed(
            loader,
            Some(index),
            format!(
                "source depends on materialized destination from entry {}",
                previous.entry
            ),
        ));
    }
    Ok(())
}

fn reject_raw_collision(
    raw: RawImage<'_>,
    loader: u32,
    index: usize,
    descriptor: Descriptor,
    destination_end: u32,
) -> Result<(), ScatterError> {
    if ranges_overlap(descriptor.destination, destination_end, raw.base, raw.end) {
        return Err(malformed(
            loader,
            Some(index),
            "non-self destination intersects the immutable raw image",
        ));
    }
    Ok(())
}

fn ranges_overlap(first_start: u32, first_end: u32, second_start: u32, second_end: u32) -> bool {
    first_start < second_end && second_start < first_end
}

fn with_candidate_context(error: ScatterError, loader: u32, index: usize) -> ScatterError {
    match error {
        ScatterError::Malformed { reason, .. } => malformed(
            loader,
            Some(index),
            format!("decompress1 stream is malformed: {reason}"),
        ),
        other => other,
    }
}

fn malformed(loader: u32, entry: Option<usize>, reason: impl Into<String>) -> ScatterError {
    ScatterError::Malformed {
        loader,
        entry,
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u32 = 0x1000_0000;
    const IMAGE_LEN: usize = 0x1000;
    const TABLE_LEN: usize = 6 * 16;
    const NULL_HANDLER: u32 = BASE + 0x600;
    const COPY_HANDLER: u32 = BASE + 0x601;
    const DECOMPRESS1_HANDLER: u32 = BASE + 0x604;
    const ZERO_HANDLER: u32 = BASE + 0x609;
    const SENTINEL_SOURCE: u32 = BASE + 0x680;
    const SELF_COPY_SOURCE: u32 = BASE + 0x700;
    const COPY_SOURCE: u32 = BASE + 0x710;
    const DECOMPRESS1_SOURCE: u32 = BASE + 0x720;
    const ZERO_SOURCE: u32 = BASE + 0x730;
    const COPY_DESTINATION: u32 = 0x2000_0100;
    const DECOMPRESS1_DESTINATION: u32 = 0x2000_0200;
    const ZERO_DESTINATION: u32 = 0x2000_0300;

    struct Fixture {
        image: Vec<u8>,
        loader_offset: usize,
        immediate: u32,
        table_offset: usize,
    }

    impl Fixture {
        fn loader_address(&self) -> u32 {
            BASE + self.loader_offset as u32
        }

        fn literal_offset(&self) -> usize {
            self.loader_offset + 8 + self.immediate as usize
        }

        fn literal_address(&self) -> u32 {
            BASE + self.literal_offset() as u32
        }

        fn table_address(&self) -> u32 {
            BASE + self.table_offset as u32
        }

        fn set_entry(
            &mut self,
            index: usize,
            source: u32,
            destination: u32,
            size: u32,
            handler: u32,
        ) {
            write_descriptor(
                &mut self.image,
                self.table_offset,
                index,
                source,
                destination,
                size,
                handler,
            );
        }
    }

    fn fixture(
        base_reg: u32,
        immediate: u32,
        loader_offset: usize,
        table_offset: usize,
    ) -> Fixture {
        let mut image = vec![0; IMAGE_LEN];
        write_anchor(&mut image, base_reg, immediate, loader_offset, table_offset);

        image[0x700..0x704].copy_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        image[0x710..0x714].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        image[0x720..0x722].copy_from_slice(&[0x22, 0xaa]);

        write_descriptor(
            &mut image,
            table_offset,
            0,
            SENTINEL_SOURCE,
            0,
            0,
            NULL_HANDLER,
        );
        write_descriptor(
            &mut image,
            table_offset,
            1,
            0,
            SENTINEL_SOURCE,
            0,
            NULL_HANDLER,
        );
        write_descriptor(
            &mut image,
            table_offset,
            2,
            SELF_COPY_SOURCE,
            SELF_COPY_SOURCE,
            4,
            COPY_HANDLER,
        );
        write_descriptor(
            &mut image,
            table_offset,
            3,
            COPY_SOURCE,
            COPY_DESTINATION,
            4,
            COPY_HANDLER,
        );
        write_descriptor(
            &mut image,
            table_offset,
            4,
            DECOMPRESS1_SOURCE,
            DECOMPRESS1_DESTINATION,
            3,
            DECOMPRESS1_HANDLER,
        );
        write_descriptor(
            &mut image,
            table_offset,
            5,
            ZERO_SOURCE,
            ZERO_DESTINATION,
            5,
            ZERO_HANDLER,
        );

        Fixture {
            image,
            loader_offset,
            immediate,
            table_offset,
        }
    }

    fn add_imm(rd: u32, rn: u32, imm12: u32) -> u32 {
        0xe280_0000 | (rn << 16) | (rd << 12) | imm12
    }

    fn ldmia(rn: u32, regs: u16) -> u32 {
        0xe890_0000 | (rn << 16) | u32::from(regs)
    }

    fn add_reg(rd: u32, rn: u32, rm: u32) -> u32 {
        0xe080_0000 | (rn << 16) | (rd << 12) | rm
    }

    fn write_anchor(
        image: &mut [u8],
        base_reg: u32,
        immediate: u32,
        loader_offset: usize,
        table_offset: usize,
    ) {
        write_anchor_with_table_len(
            image,
            base_reg,
            immediate,
            loader_offset,
            table_offset,
            TABLE_LEN as u32,
        );
    }

    fn write_anchor_with_table_len(
        image: &mut [u8],
        base_reg: u32,
        immediate: u32,
        loader_offset: usize,
        table_offset: usize,
        table_len: u32,
    ) {
        write_u32(image, loader_offset, add_imm(base_reg, 15, immediate));
        write_u32(
            image,
            loader_offset + 4,
            ldmia(base_reg, (1 << 10) | (1 << 11)),
        );
        write_u32(image, loader_offset + 8, add_reg(10, 10, base_reg));
        write_u32(image, loader_offset + 12, add_reg(11, 11, base_reg));

        let literal_offset = loader_offset + 8 + immediate as usize;
        let literal_address = BASE + literal_offset as u32;
        let table_address = BASE + table_offset as u32;
        write_u32(
            image,
            literal_offset,
            table_address.wrapping_sub(literal_address),
        );
        write_u32(
            image,
            literal_offset + 4,
            table_address
                .wrapping_add(table_len)
                .wrapping_sub(literal_address),
        );
    }

    fn write_descriptor(
        image: &mut [u8],
        table_offset: usize,
        index: usize,
        source: u32,
        destination: u32,
        size: u32,
        handler: u32,
    ) {
        let offset = table_offset + index * 16;
        write_u32(image, offset, source);
        write_u32(image, offset + 4, destination);
        write_u32(image, offset + 8, size);
        write_u32(image, offset + 12, handler);
    }

    fn write_u32(image: &mut [u8], offset: usize, value: u32) {
        image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn assert_malformed(fixture: &Fixture, expected_entry: Option<usize>) {
        match discover(&fixture.image, BASE).unwrap_err() {
            ScatterError::Malformed { loader, entry, .. } => {
                assert_eq!(loader, fixture.loader_address());
                assert_eq!(entry, expected_entry);
            }
            other => panic!("expected malformed candidate, got {other:?}"),
        }
    }

    #[test]
    fn semantic_anchor_accepts_r0_and_r6_variants() {
        for (base_reg, immediate, loader_offset, table_offset, expected_literal) in [
            (0, 0x38, 0x40, 0x200, 0x1000_0080),
            (6, 0x5c, 0x80, 0x240, 0x1000_00e4),
        ] {
            let fixture = fixture(base_reg, immediate, loader_offset, table_offset);
            let plan = discover(&fixture.image, BASE).unwrap().unwrap();
            assert_eq!(plan.loader_address, BASE + loader_offset as u32);
            assert_eq!(plan.literal_pair_address, expected_literal);
        }
    }

    #[test]
    fn semantic_anchor_accepts_a_third_register_and_immediate() {
        let fixture = fixture(3, 0x84, 0xc0, 0x2c8);
        let plan = discover(&fixture.image, BASE).unwrap().unwrap();
        assert_eq!(plan.loader_address, 0x1000_00c0);
        assert_eq!(plan.literal_pair_address, 0x1000_014c);
        assert_eq!(plan.table_start, 0x1000_02c8);
        assert_eq!(plan.table_end, 0x1000_0328);
    }

    #[test]
    fn relative_words_wrap_to_an_earlier_table() {
        let fixture = fixture(4, 0x38, 0x300, 0x100);
        let relative_start = read_u32(&fixture.image, fixture.literal_offset()).unwrap();
        assert!(relative_start > 0xffff_0000);

        let plan = discover(&fixture.image, BASE).unwrap().unwrap();

        assert_eq!(plan.loader_address, BASE + 0x300);
        assert_eq!(plan.literal_pair_address, BASE + 0x340);
        assert_eq!(plan.table_start, BASE + 0x100);
        assert_eq!(plan.table_end, BASE + 0x160);
    }

    #[test]
    fn exact_entry_limit_is_accepted_and_one_more_is_rejected() {
        let mut accepted = fixture(0, 0x38, 0x40, 0x800);
        accepted.image.resize(0x2000, 0);
        write_anchor_with_table_len(
            &mut accepted.image,
            0,
            0x38,
            0x40,
            0x800,
            (MAX_ENTRIES * DESCRIPTOR_SIZE as usize) as u32,
        );
        for index in 6..MAX_ENTRIES {
            accepted.set_entry(
                index,
                ZERO_SOURCE,
                0x3000_0000 + index as u32 * 0x10,
                1,
                ZERO_HANDLER,
            );
        }

        let plan = discover(&accepted.image, BASE).unwrap().unwrap();
        assert_eq!(plan.entries.len(), MAX_ENTRIES);
        assert_eq!(plan.table_end - plan.table_start, 256 * DESCRIPTOR_SIZE);

        let mut rejected = accepted;
        rejected.image.resize(0x3000, 0);
        write_anchor_with_table_len(
            &mut rejected.image,
            0,
            0x38,
            0x40,
            0x800,
            ((MAX_ENTRIES + 1) * DESCRIPTOR_SIZE as usize) as u32,
        );
        assert_eq!(discover(&rejected.image, BASE).unwrap(), None);
    }

    #[test]
    fn semantic_anchor_rejects_r10_r11_and_pc_base_aliases() {
        for base_reg in [10, 11, 15] {
            let fixture = fixture(base_reg, 0x38, 0x40, 0x200);
            assert_eq!(
                discover(&fixture.image, BASE).unwrap(),
                None,
                "base register r{base_reg} aliases an anchor operand"
            );
        }
    }

    #[test]
    fn loader_lookalike_without_valid_bounds_is_no_candidate() {
        let mut fixture = fixture(0, 0x38, 0x40, 0x200);
        let relative_start = fixture
            .table_address()
            .wrapping_sub(fixture.literal_address());
        let literal_end_offset = fixture.literal_offset() + 4;
        write_u32(&mut fixture.image, literal_end_offset, relative_start);
        assert_eq!(discover(&fixture.image, BASE).unwrap(), None);
    }

    #[test]
    fn bounded_final_entry_corruption_is_malformed() {
        let mut fixture = fixture(0, 0x38, 0x40, 0x200);
        fixture.set_entry(5, ZERO_SOURCE, ZERO_DESTINATION, 0, ZERO_HANDLER);
        assert_malformed(&fixture, Some(5));
    }

    #[test]
    fn two_valid_anchors_are_ambiguous() {
        let mut fixture = fixture(0, 0x38, 0x40, 0x200);
        write_anchor(&mut fixture.image, 7, 0x38, 0x100, 0x200);
        assert_eq!(
            discover(&fixture.image, BASE).unwrap_err(),
            ScatterError::Ambiguous {
                loaders: vec![0x1000_0040, 0x1000_0100],
            }
        );
    }

    #[test]
    fn valid_candidates_drop_the_sole_candidate_after_ambiguity() {
        let fixture = fixture(0, 0x38, 0x40, 0x200);
        let raw = RawImage::new(&fixture.image, BASE).unwrap();
        let table = &fixture.image[fixture.table_offset..fixture.table_offset + TABLE_LEN];
        let mut budget = DecodeBudget::new(MAX_DECODED_WORK);
        let mut candidate = |loader| {
            validate_candidate(
                raw,
                Anchor {
                    loader,
                    literal_pair: fixture.literal_address(),
                    table_start: fixture.table_address(),
                    table_end: fixture.table_address() + TABLE_LEN as u32,
                },
                table,
                &mut budget,
            )
            .unwrap()
        };

        let mut valid = ValidCandidates::default();
        valid.record(candidate(BASE + 0x40));
        assert!(valid.sole.is_some());
        valid.record(candidate(BASE + 0x180));
        assert!(valid.sole.is_none());
        valid.record(candidate(BASE + 0x100));
        assert!(valid.sole.is_none());
        let error = match valid.finish() {
            Err(error) => error,
            Ok(_) => panic!("three valid candidates must be ambiguous"),
        };
        assert_eq!(
            error,
            ScatterError::Ambiguous {
                loaders: vec![BASE + 0x40, BASE + 0x100, BASE + 0x180],
            }
        );
    }

    #[test]
    fn repeated_valid_candidates_retain_copy_ranges_until_selection() {
        let fixture = fixture(0, 0x38, 0x40, 0x200);
        let raw = RawImage::new(&fixture.image, BASE).unwrap();
        let table = &fixture.image[fixture.table_offset..fixture.table_offset + TABLE_LEN];
        let mut budget = DecodeBudget::new(MAX_DECODED_WORK);
        let mut candidates = Vec::new();

        for loader_offset in (0x40..0x140).step_by(4) {
            let candidate = validate_candidate(
                raw,
                Anchor {
                    loader: BASE + loader_offset,
                    literal_pair: fixture.literal_address(),
                    table_start: fixture.table_address(),
                    table_end: fixture.table_address() + TABLE_LEN as u32,
                },
                table,
                &mut budget,
            )
            .unwrap();
            assert!(matches!(
                candidate.entries[3].output,
                ValidatedOutput::CopySource(_)
            ));
            candidates.push(candidate);
        }

        let selected = candidates.pop().unwrap().into_load_plan(raw);
        assert_eq!(
            selected.entries[3].output,
            PlannedOutput::Bytes(vec![0x11, 0x22, 0x33, 0x44])
        );
        assert!(candidates.iter().all(|candidate| matches!(
            candidate.entries[3].output,
            ValidatedOutput::CopySource(_)
        )));
    }

    #[test]
    fn plausible_malformed_anchor_overrides_earlier_ambiguity() {
        let mut fixture = fixture(0, 0x38, 0x40, 0x200);
        let second_table_offset = 0x300;
        let table = fixture.image[0x200..0x200 + TABLE_LEN].to_vec();
        fixture.image[second_table_offset..second_table_offset + TABLE_LEN].copy_from_slice(&table);
        write_descriptor(
            &mut fixture.image,
            second_table_offset,
            5,
            ZERO_SOURCE,
            ZERO_DESTINATION,
            0,
            ZERO_HANDLER,
        );
        write_anchor(&mut fixture.image, 7, 0x38, 0x100, 0x200);
        write_anchor(&mut fixture.image, 8, 0x38, 0x180, second_table_offset);

        match discover(&fixture.image, BASE).unwrap_err() {
            ScatterError::Malformed { loader, entry, .. } => {
                assert_eq!(loader, 0x1000_0180);
                assert_eq!(entry, Some(5));
            }
            other => panic!("expected malformed candidate, got {other:?}"),
        }
    }

    #[test]
    fn classification_rejects_missing_or_reused_handlers() {
        let mut missing = fixture(0, 0x38, 0x40, 0x200);
        missing.set_entry(
            4,
            DECOMPRESS1_SOURCE,
            DECOMPRESS1_DESTINATION,
            3,
            COPY_HANDLER,
        );
        assert_malformed(&missing, None);

        let mut reused = fixture(0, 0x38, 0x40, 0x200);
        reused.set_entry(2, SELF_COPY_SOURCE, SELF_COPY_SOURCE, 4, NULL_HANDLER);
        assert_malformed(&reused, Some(2));

        let mut unknown = fixture(0, 0x38, 0x40, 0x200);
        unknown.set_entry(3, COPY_SOURCE, COPY_DESTINATION, 4, BASE + 0x60c);
        assert_malformed(&unknown, Some(5));
    }

    #[test]
    fn classification_rejects_ambiguous_assignment() {
        let mut fixture = fixture(0, 0x38, 0x40, 0x200);
        fixture.image[0x700..0x704].copy_from_slice(&[0x32, 0xaa, 0, 0]);
        fixture.image[0x710..0x714].copy_from_slice(&[0x32, 0xbb, 0, 0]);
        fixture.set_entry(
            4,
            DECOMPRESS1_SOURCE,
            DECOMPRESS1_SOURCE,
            3,
            DECOMPRESS1_HANDLER,
        );
        assert_malformed(&fixture, None);
    }

    #[test]
    fn classification_rejects_zero_before_copy_or_decompress() {
        let mut fixture = fixture(0, 0x38, 0x40, 0x200);
        fixture.set_entry(3, ZERO_SOURCE, ZERO_DESTINATION, 5, ZERO_HANDLER);
        fixture.set_entry(5, COPY_SOURCE, COPY_DESTINATION, 4, COPY_HANDLER);
        assert_malformed(&fixture, Some(2));
    }

    #[test]
    fn planning_builds_none_self_copy_bytes_and_zero_fill_outputs() {
        let fixture = fixture(0, 0x38, 0x40, 0x200);
        let plan = discover(&fixture.image, BASE).unwrap().unwrap();

        assert_eq!(plan.image_base, BASE);
        assert_eq!(plan.image_size, 0x1000);
        assert_eq!(plan.loader_address, 0x1000_0040);
        assert_eq!(plan.literal_pair_address, 0x1000_0080);
        assert_eq!(plan.table_start, 0x1000_0200);
        assert_eq!(plan.table_end, 0x1000_0260);
        assert_eq!(
            plan.handlers,
            HandlerMap {
                null: NULL_HANDLER,
                copy: COPY_HANDLER,
                decompress1: DECOMPRESS1_HANDLER,
                zero: ZERO_HANDLER,
            }
        );
        assert_eq!(
            plan.entries
                .iter()
                .map(|entry| entry.operation)
                .collect::<Vec<_>>(),
            [
                Operation::Null,
                Operation::Null,
                Operation::Copy,
                Operation::Copy,
                Operation::Decompress1,
                Operation::Zero,
            ]
        );
        assert_eq!(
            plan.entries
                .iter()
                .map(|entry| entry.index)
                .collect::<Vec<_>>(),
            [0, 1, 2, 3, 4, 5]
        );
        assert_eq!(plan.entries[0].output, PlannedOutput::None);
        assert_eq!(plan.entries[1].output, PlannedOutput::None);
        assert_eq!(plan.entries[2].output, PlannedOutput::SelfCopy);
        assert_eq!(
            plan.entries[3].output,
            PlannedOutput::Bytes(vec![0x11, 0x22, 0x33, 0x44])
        );
        assert_eq!(
            plan.entries[4].output,
            PlannedOutput::Bytes(vec![0xaa, 0, 0])
        );
        assert_eq!(plan.entries[4].compressed_size, Some(2));
        assert_eq!(plan.entries[5].output, PlannedOutput::ZeroFill);
        assert_eq!(plan.logical_output_size, 16);
    }

    #[test]
    fn planning_rejects_raw_collision_destination_overlap_source_escape_and_u32_wrap() {
        let mut raw_collision = fixture(0, 0x38, 0x40, 0x200);
        raw_collision.set_entry(3, COPY_SOURCE, BASE + 0x740, 4, COPY_HANDLER);
        assert_malformed(&raw_collision, Some(3));

        let mut self_copy_overlap = fixture(0, 0x38, 0x40, 0x200);
        self_copy_overlap.set_entry(
            3,
            SELF_COPY_SOURCE + 2,
            SELF_COPY_SOURCE + 2,
            4,
            COPY_HANDLER,
        );
        assert_malformed(&self_copy_overlap, Some(3));

        let mut overlap = fixture(0, 0x38, 0x40, 0x200);
        overlap.set_entry(5, ZERO_SOURCE, DECOMPRESS1_DESTINATION + 1, 5, ZERO_HANDLER);
        assert_malformed(&overlap, Some(5));

        let mut source_escape = fixture(0, 0x38, 0x40, 0x200);
        source_escape.set_entry(
            3,
            BASE + IMAGE_LEN as u32 - 2,
            COPY_DESTINATION,
            4,
            COPY_HANDLER,
        );
        assert_malformed(&source_escape, Some(3));

        let mut destination_wrap = fixture(0, 0x38, 0x40, 0x200);
        destination_wrap.set_entry(5, ZERO_SOURCE, u32::MAX - 2, 5, ZERO_HANDLER);
        assert_malformed(&destination_wrap, Some(5));
    }

    #[test]
    fn discovery_rejects_raw_image_range_that_wraps_u32() {
        match discover(&[0; 32], u32::MAX - 16).unwrap_err() {
            ScatterError::Malformed {
                loader,
                entry: None,
                reason,
            } => {
                assert_eq!(loader, u32::MAX - 16);
                assert!(reason.contains("raw image range"));
            }
            other => panic!("expected malformed image range, got {other:?}"),
        }
    }

    #[test]
    fn logical_output_limit_is_enforced() {
        let mut fixture = fixture(0, 0x38, 0x40, 0x200);
        fixture.set_entry(
            5,
            ZERO_SOURCE,
            0x6000_0000,
            MAX_LOGICAL_OUTPUT as u32,
            ZERO_HANDLER,
        );
        assert_eq!(
            discover(&fixture.image, BASE).unwrap_err(),
            ScatterError::ResourceLimit {
                what: "logical output",
                limit: MAX_LOGICAL_OUTPUT,
            }
        );
    }
}
