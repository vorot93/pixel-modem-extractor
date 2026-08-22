use crate::error::{Error, Result};
use crate::scatter::{
    self, ArtifactSegment, LoadPlan, MAX_ENTRIES, MAX_LOGICAL_OUTPUT, Operation, PlannedOutput,
    PlannedStorage,
};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::BTreeSet;
use std::path::Path;

pub(crate) const MAX_EXACT_READ: usize = 64 * 1024;
const MAX_ASCII_NUL: usize = 128;
static ZERO_CHUNK: [u8; MAX_EXACT_READ] = [0; MAX_EXACT_READ];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StorageKind {
    Raw,
    ScatterBytes,
    ScatterZero,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StorageSpan {
    pub kind: StorageKind,
    pub address: u32,
    pub size: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scatter_entry: Option<usize>,
}

pub(crate) struct RuntimeImage<'a> {
    segments: Vec<Segment<'a>>,
}

struct Segment<'a> {
    start: u32,
    end: u32,
    backing: Backing<'a>,
}

enum Backing<'a> {
    Raw(&'a [u8]),
    PlanBytes {
        bytes: &'a [u8],
        scatter_entry: usize,
    },
    Artifact(ArtifactSegment),
    Zero {
        scatter_entry: usize,
    },
}

#[derive(Clone, Copy)]
struct ResolvedSpan<'image, 'data> {
    segment: &'image Segment<'data>,
    address: u32,
    offset: u32,
    size: u32,
}

#[derive(Clone, Copy)]
struct DestinationRange {
    start: u32,
    end: u32,
    entry: usize,
}

impl Segment<'_> {
    fn storage_kind(&self) -> StorageKind {
        match &self.backing {
            Backing::Raw(_) => StorageKind::Raw,
            Backing::PlanBytes { .. } => StorageKind::ScatterBytes,
            Backing::Artifact(segment) if segment.is_zero_fill() => StorageKind::ScatterZero,
            Backing::Artifact(_) => StorageKind::ScatterBytes,
            Backing::Zero { .. } => StorageKind::ScatterZero,
        }
    }

    fn scatter_entry(&self) -> Option<usize> {
        match &self.backing {
            Backing::Raw(_) => None,
            Backing::PlanBytes { scatter_entry, .. } | Backing::Zero { scatter_entry } => {
                Some(*scatter_entry)
            }
            Backing::Artifact(segment) => Some(segment.scatter_entry()),
        }
    }

    fn borrowed(&self, offset: u32, size: u32) -> Result<Option<&[u8]>> {
        let start = usize::try_from(offset)
            .map_err(|_| bad("runtime segment offset does not fit the host"))?;
        let size =
            usize::try_from(size).map_err(|_| bad("runtime segment size does not fit the host"))?;
        let end = start
            .checked_add(size)
            .ok_or_else(|| bad("runtime segment slice overflows the host"))?;
        match &self.backing {
            Backing::Raw(bytes) | Backing::PlanBytes { bytes, .. } => bytes
                .get(start..end)
                .map(Some)
                .ok_or_else(|| bad("runtime segment slice escapes its backing")),
            Backing::Artifact(segment) if segment.is_zero_fill() => ZERO_CHUNK
                .get(..size)
                .map(Some)
                .ok_or_else(|| bad("zero-fill read exceeds the exact-read ceiling")),
            Backing::Artifact(_) => Ok(None),
            Backing::Zero { .. } => ZERO_CHUNK
                .get(..size)
                .map(Some)
                .ok_or_else(|| bad("zero-fill read exceeds the exact-read ceiling")),
        }
    }

    fn read(&self, offset: u32, output: &mut [u8]) -> Result<()> {
        let length =
            u32::try_from(output.len()).map_err(|_| bad("runtime read length does not fit u32"))?;
        if let Some(bytes) = self.borrowed(offset, length)? {
            output.copy_from_slice(bytes);
            return Ok(());
        }
        match &self.backing {
            Backing::Artifact(segment) => segment.read_exact(offset, output),
            _ => Err(bad("runtime backing unexpectedly requires an owned read")),
        }
    }
}

impl<'a> RuntimeImage<'a> {
    pub(crate) fn from_plan(raw: &'a [u8], base: u32, plan: Option<&'a LoadPlan>) -> Result<Self> {
        let (raw_size, raw_end) = raw_bounds(raw, base)?;
        let mut segments = Vec::new();
        segments.push(Segment {
            start: base,
            end: raw_end,
            backing: Backing::Raw(raw),
        });

        let Some(plan) = plan else {
            return Self::from_segments(segments);
        };
        if plan.image_base != base || plan.image_size != raw_size {
            return Err(bad(
                "scatter plan image identity does not match the raw image",
            ));
        }
        if plan.entries.is_empty() || plan.entries.len() > MAX_ENTRIES {
            return Err(bad("scatter plan has an invalid entry count"));
        }
        segments
            .try_reserve(plan.entries.len())
            .map_err(|_| bad("runtime segment-index allocation failed"))?;

        let mut entry_indices = BTreeSet::new();
        let mut destinations = Vec::with_capacity(plan.entries.len());
        let mut logical_output_size = 0u64;
        for entry in &plan.entries {
            let context = format!("scatter entry {}", entry.index);
            if !entry_indices.insert(entry.index) {
                return Err(bad(format!("duplicate {context} index")));
            }
            if entry.descriptor.handler != handler_for(entry.operation, plan) {
                return Err(bad(format!(
                    "{context} handler does not match its operation"
                )));
            }
            if (entry.operation == Operation::Decompress1) != entry.compressed_size.is_some() {
                return Err(bad(format!(
                    "{context} compressed-size presence does not match its operation"
                )));
            }

            if entry.operation != Operation::Null {
                if entry.descriptor.size == 0 || entry.descriptor.destination == 0 {
                    return Err(bad(format!("{context} has a zero size or destination")));
                }
                let destination_end = checked_end(
                    entry.descriptor.destination,
                    entry.descriptor.size,
                    &format!("{context} destination"),
                )?;
                logical_output_size = logical_output_size
                    .checked_add(u64::from(entry.descriptor.size))
                    .ok_or_else(|| bad("scatter plan logical output overflows u64"))?;
                if logical_output_size > MAX_LOGICAL_OUTPUT {
                    return Err(bad(
                        "scatter plan logical output exceeds the supported limit",
                    ));
                }
                destinations.push(DestinationRange {
                    start: entry.descriptor.destination,
                    end: destination_end,
                    entry: entry.index,
                });
            }

            match &entry.output {
                PlannedOutput::None => {
                    if entry.operation != Operation::Null || entry.descriptor.size != 0 {
                        return Err(bad(format!("{context} none output is not a null entry")));
                    }
                }
                PlannedOutput::SelfCopy => {
                    if entry.operation != Operation::Copy
                        || entry.descriptor.source != entry.descriptor.destination
                    {
                        return Err(bad(format!(
                            "{context} self-copy output is not an exact copy"
                        )));
                    }
                    raw_range(
                        raw,
                        base,
                        entry.descriptor.source,
                        entry.descriptor.size,
                        &context,
                    )?;
                }
                PlannedOutput::Bytes(bytes) => {
                    if !matches!(entry.operation, Operation::Copy | Operation::Decompress1) {
                        return Err(bad(format!(
                            "{context} byte output has an invalid operation"
                        )));
                    }
                    let expected = usize::try_from(entry.descriptor.size)
                        .map_err(|_| bad(format!("{context} size does not fit the host")))?;
                    if bytes.len() != expected {
                        return Err(bad(format!(
                            "{context} byte output length does not match its descriptor"
                        )));
                    }
                    if ranges_overlap(
                        entry.descriptor.destination,
                        checked_end(
                            entry.descriptor.destination,
                            entry.descriptor.size,
                            &context,
                        )?,
                        base,
                        raw_end,
                    ) {
                        return Err(bad(format!(
                            "{context} byte destination overlaps the raw image"
                        )));
                    }
                    let backing = match entry.storage() {
                        PlannedStorage::Bytes(bytes) => Backing::PlanBytes {
                            bytes,
                            scatter_entry: entry.index,
                        },
                        PlannedStorage::ZeroFill => Backing::Zero {
                            scatter_entry: entry.index,
                        },
                        _ => {
                            return Err(bad(format!(
                                "{context} byte output has an invalid storage classification"
                            )));
                        }
                    };
                    segments.push(Segment {
                        start: entry.descriptor.destination,
                        end: checked_end(
                            entry.descriptor.destination,
                            entry.descriptor.size,
                            &context,
                        )?,
                        backing,
                    });
                }
                PlannedOutput::ZeroFill => {
                    if entry.operation != Operation::Zero {
                        return Err(bad(format!(
                            "{context} zero-fill output is not a zero operation"
                        )));
                    }
                    let end = checked_end(
                        entry.descriptor.destination,
                        entry.descriptor.size,
                        &context,
                    )?;
                    if ranges_overlap(entry.descriptor.destination, end, base, raw_end) {
                        return Err(bad(format!(
                            "{context} zero-fill destination overlaps the raw image"
                        )));
                    }
                    segments.push(Segment {
                        start: entry.descriptor.destination,
                        end,
                        backing: Backing::Zero {
                            scatter_entry: entry.index,
                        },
                    });
                }
            }
        }
        if logical_output_size != plan.logical_output_size {
            return Err(bad(
                "scatter plan logical output does not match its entries",
            ));
        }
        reject_destination_overlap(&mut destinations)?;
        Self::from_segments(segments)
    }

    pub(crate) fn from_artifact(
        raw: &'a [u8],
        base: u32,
        kit_root: &Path,
        map: Option<&Path>,
    ) -> Result<Self> {
        let (_, raw_end) = raw_bounds(raw, base)?;
        let Some(map) = map else {
            return Self::from_segments(vec![Segment {
                start: base,
                end: raw_end,
                backing: Backing::Raw(raw),
            }]);
        };
        let artifact: scatter::MaterializedScatter =
            scatter::read_materialized(kit_root, map, raw, base)?;
        let capacity = artifact
            .segments
            .len()
            .checked_add(1)
            .ok_or_else(|| bad("runtime artifact segment count overflows"))?;
        let mut segments = Vec::new();
        segments
            .try_reserve_exact(capacity)
            .map_err(|_| bad("runtime artifact segment-index allocation failed"))?;
        segments.push(Segment {
            start: base,
            end: raw_end,
            backing: Backing::Raw(raw),
        });
        for segment in artifact.segments {
            let start = segment.address();
            let end = checked_end(start, segment.size(), "artifact segment")?;
            segments.push(Segment {
                start,
                end,
                backing: Backing::Artifact(segment),
            });
        }
        Self::from_segments(segments)
    }

    /// Build the runtime view for an image directory using the decompose-tree
    /// scatter convention: the map, when present, is
    /// `<image_dir>/scatter/load_map.json` and its blocks live beside it.
    /// This is the only constructor for that convention; consumers must not
    /// re-derive the map path or existence probe themselves.
    pub(crate) fn for_image_dir(raw: &'a [u8], base: u32, image_dir: &Path) -> Result<Self> {
        let root = std::fs::canonicalize(image_dir)?;
        let map = root.join("scatter/load_map.json");
        Self::from_artifact(raw, base, &root, map.try_exists()?.then_some(map.as_path()))
    }

    pub(crate) fn read_u8(&self, address: u32) -> Result<u8> {
        Ok(self.read_exact(address, 1)?[0])
    }

    pub(crate) fn read_u16(&self, address: u32) -> Result<u16> {
        let bytes = self.read_exact(address, 2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    pub(crate) fn read_u32(&self, address: u32) -> Result<u32> {
        let bytes = self.read_exact(address, 4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub(crate) fn read_exact(&self, address: u32, size: usize) -> Result<Cow<'_, [u8]>> {
        if size > MAX_EXACT_READ {
            return Err(bad("exact runtime read exceeds 64 KiB"));
        }
        let size =
            u32::try_from(size).map_err(|_| bad("exact runtime read size does not fit u32"))?;
        if size == 0 {
            return Ok(Cow::Borrowed(&[]));
        }
        let mut single = None;
        let span_count = self.visit_range(address, size, |span| {
            if single.is_none() {
                single = Some(span);
            }
            Ok(())
        })?;
        if let (1, Some(span)) = (span_count, single)
            && let Some(bytes) = span.segment.borrowed(span.offset, span.size)?
        {
            return Ok(Cow::Borrowed(bytes));
        }

        let length = usize::try_from(size)
            .map_err(|_| bad("exact runtime read size does not fit the host"))?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(length)
            .map_err(|_| bad("exact runtime read allocation failed"))?;
        output.resize(length, 0);
        let mut written = 0usize;
        self.visit_range(address, size, |span| {
            let length = usize::try_from(span.size)
                .map_err(|_| bad("resolved runtime span does not fit the host"))?;
            let end = written
                .checked_add(length)
                .ok_or_else(|| bad("exact runtime read offset overflows the host"))?;
            span.segment.read(
                span.offset,
                output.get_mut(written..end).ok_or_else(|| {
                    bad("resolved runtime spans exceed the exact-read allocation")
                })?,
            )?;
            written = end;
            Ok(())
        })?;
        if written != output.len() {
            return Err(bad("resolved runtime spans do not fill the exact read"));
        }
        Ok(Cow::Owned(output))
    }

    pub(crate) fn read_ascii_nul(
        &self,
        address: u32,
        max: usize,
    ) -> Result<(String, Vec<StorageSpan>)> {
        if max > MAX_ASCII_NUL {
            return Err(bad("ASCII string bound exceeds 128 bytes"));
        }
        max.checked_add(1)
            .ok_or_else(|| bad("ASCII string bound overflows the host"))?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(max)
            .map_err(|_| bad("ASCII string allocation failed"))?;
        for offset in 0..=max {
            let offset =
                u32::try_from(offset).map_err(|_| bad("ASCII string offset does not fit u32"))?;
            let cursor = address
                .checked_add(offset)
                .ok_or_else(|| bad("ASCII string address wraps the 32-bit address space"))?;
            if !self.is_byte_backed(cursor, 1)? {
                return Err(bad("ASCII string crosses virtual zero-fill storage"));
            }
            let byte = self.read_u8(cursor)?;
            if byte == 0 {
                let storage_size = offset
                    .checked_add(1)
                    .ok_or_else(|| bad("ASCII string storage size overflows u32"))?;
                let storage = self.storage_spans(address, storage_size)?;
                let string =
                    String::from_utf8(bytes).map_err(|_| bad("ASCII string is not valid UTF-8"))?;
                return Ok((string, storage));
            }
            if !(0x20..=0x7e).contains(&byte) {
                return Err(bad("ASCII string contains a non-printable byte"));
            }
            if offset as usize == max {
                return Err(bad("ASCII string is not NUL-terminated within its bound"));
            }
            bytes.push(byte);
        }
        unreachable!("the bounded ASCII loop returns at its terminal offset")
    }

    pub(crate) fn hash_range(&self, address: u32, size: u32) -> Result<[u8; 32]> {
        self.visit_range(address, size, |_| Ok(()))?;
        let mut hasher = blake3::Hasher::new();
        let mut buffer = [0; MAX_EXACT_READ];
        self.visit_range(address, size, |span| {
            let mut consumed = 0u32;
            while consumed < span.size {
                let length = (span.size - consumed).min(MAX_EXACT_READ as u32);
                let offset = span
                    .offset
                    .checked_add(consumed)
                    .ok_or_else(|| bad("runtime hash offset overflows u32"))?;
                let length = usize::try_from(length)
                    .map_err(|_| bad("runtime hash chunk does not fit the host"))?;
                span.segment.read(offset, &mut buffer[..length])?;
                hasher.update(&buffer[..length]);
                consumed = consumed
                    .checked_add(length as u32)
                    .ok_or_else(|| bad("runtime hash byte count overflows u32"))?;
            }
            Ok(())
        })?;
        Ok(*hasher.finalize().as_bytes())
    }

    pub(crate) fn storage_spans(&self, address: u32, size: u32) -> Result<Vec<StorageSpan>> {
        let span_count = self.visit_range(address, size, |_| Ok(()))?;
        let mut spans = Vec::new();
        spans
            .try_reserve_exact(span_count)
            .map_err(|_| bad("storage-span allocation failed"))?;
        self.visit_range(address, size, |span| {
            spans.push(StorageSpan {
                kind: span.segment.storage_kind(),
                address: span.address,
                size: span.size,
                scatter_entry: span.segment.scatter_entry(),
            });
            Ok(())
        })?;
        Ok(spans)
    }

    pub(crate) fn is_byte_backed(&self, address: u32, size: u32) -> Result<bool> {
        let mut byte_backed = true;
        self.visit_range(address, size, |span| {
            byte_backed &= span.segment.storage_kind() != StorageKind::ScatterZero;
            Ok(())
        })?;
        Ok(byte_backed)
    }

    fn from_segments(mut segments: Vec<Segment<'a>>) -> Result<Self> {
        segments.sort_unstable_by_key(|segment| (segment.start, segment.end));
        for segment in &segments {
            if segment.start >= segment.end {
                return Err(bad("runtime segment is empty or wraps"));
            }
        }
        for adjacent in segments.windows(2) {
            let [first, second] = adjacent else {
                continue;
            };
            if ranges_overlap(first.start, first.end, second.start, second.end) {
                return Err(bad("runtime segments overlap ambiguously"));
            }
        }
        Ok(Self { segments })
    }

    fn visit_range<'image>(
        &'image self,
        address: u32,
        size: u32,
        mut visit: impl FnMut(ResolvedSpan<'image, 'a>) -> Result<()>,
    ) -> Result<usize> {
        let end = checked_end(address, size, "runtime read")?;
        if size == 0 {
            return Ok(0);
        }
        let mut index = self
            .segments
            .partition_point(|segment| segment.end <= address);
        let mut cursor = address;
        let mut span_count = 0usize;
        while cursor < end {
            let segment = self
                .segments
                .get(index)
                .ok_or_else(|| bad("runtime range crosses unmapped memory"))?;
            if cursor < segment.start || cursor >= segment.end {
                return Err(bad("runtime range crosses unmapped memory"));
            }
            let span_end = segment.end.min(end);
            let span_size = span_end
                .checked_sub(cursor)
                .filter(|&size| size > 0)
                .ok_or_else(|| bad("runtime span resolution made no progress"))?;
            visit(ResolvedSpan {
                segment,
                address: cursor,
                offset: cursor - segment.start,
                size: span_size,
            })?;
            span_count = span_count
                .checked_add(1)
                .ok_or_else(|| bad("runtime span count overflows the host"))?;
            cursor = span_end;
            index = index
                .checked_add(1)
                .ok_or_else(|| bad("runtime segment index overflows"))?;
        }
        Ok(span_count)
    }
}

fn raw_bounds(raw: &[u8], base: u32) -> Result<(u32, u32)> {
    let size = u32::try_from(raw.len()).map_err(|_| bad("raw image size does not fit u32"))?;
    if size == 0 {
        return Err(bad("raw image is empty"));
    }
    let end = checked_end(base, size, "raw image")?;
    Ok((size, end))
}

fn raw_range<'a>(
    raw: &'a [u8],
    base: u32,
    address: u32,
    size: u32,
    context: &str,
) -> Result<&'a [u8]> {
    let start = address
        .checked_sub(base)
        .ok_or_else(|| bad(format!("{context} raw range begins below the image")))?;
    let end = start
        .checked_add(size)
        .ok_or_else(|| bad(format!("{context} raw range wraps")))?;
    let start = usize::try_from(start)
        .map_err(|_| bad(format!("{context} raw offset does not fit the host")))?;
    let end = usize::try_from(end)
        .map_err(|_| bad(format!("{context} raw end does not fit the host")))?;
    raw.get(start..end)
        .ok_or_else(|| bad(format!("{context} raw range escapes the image")))
}

fn handler_for(operation: Operation, plan: &LoadPlan) -> u32 {
    match operation {
        Operation::Null => plan.handlers.null,
        Operation::Copy => plan.handlers.copy,
        Operation::Decompress1 => plan.handlers.decompress1,
        Operation::Zero => plan.handlers.zero,
    }
}

fn reject_destination_overlap(destinations: &mut [DestinationRange]) -> Result<()> {
    destinations.sort_unstable_by_key(|range| (range.start, range.end, range.entry));
    for adjacent in destinations.windows(2) {
        let [first, second] = adjacent else {
            continue;
        };
        if ranges_overlap(first.start, first.end, second.start, second.end) {
            return Err(bad(format!(
                "scatter entry {} destination overlaps scatter entry {}",
                second.entry, first.entry
            )));
        }
    }
    Ok(())
}

fn checked_end(start: u32, size: u32, context: &str) -> Result<u32> {
    start
        .checked_add(size)
        .ok_or_else(|| bad(format!("{context} wraps the 32-bit address space")))
}

fn ranges_overlap(first_start: u32, first_end: u32, second_start: u32, second_end: u32) -> bool {
    first_start < second_end && second_start < first_end
}

fn bad(reason: impl Into<String>) -> Error {
    Error::BadScatter(reason.into())
}

#[cfg(test)]
mod tests {
    use super::{MAX_EXACT_READ, RuntimeImage, StorageKind, StorageSpan};
    use crate::error::{Error, Result};
    use crate::scatter::{
        Descriptor, HandlerMap, LoadPlan, Operation, PlannedEntry, PlannedOutput,
    };
    use std::borrow::Cow;

    const BASE: u32 = 0x1000;
    const BYTES_DESTINATION: u32 = BASE + 16;
    const ZERO_DESTINATION: u32 = BASE + 20;

    fn raw() -> Vec<u8> {
        vec![
            0x11, 0x22, 0x33, 0x44, b'R', b'A', b'W', 0, 0x1f, 0, 0x55, 0x66, 0x77, 0x88, b'A',
            b'B',
        ]
    }

    fn plan() -> LoadPlan {
        LoadPlan {
            image_base: BASE,
            image_size: 16,
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
                entry(
                    2,
                    BASE,
                    BASE,
                    4,
                    BASE + 1,
                    Operation::Copy,
                    None,
                    PlannedOutput::SelfCopy,
                ),
                entry(
                    3,
                    BASE + 10,
                    BYTES_DESTINATION,
                    4,
                    BASE + 4,
                    Operation::Decompress1,
                    Some(2),
                    PlannedOutput::Bytes(vec![b'C', 0, 0xcc, 0xdd]),
                ),
                entry(
                    4,
                    BASE + 12,
                    ZERO_DESTINATION,
                    4,
                    BASE + 9,
                    Operation::Zero,
                    None,
                    PlannedOutput::ZeroFill,
                ),
            ],
            logical_output_size: 12,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn entry(
        index: usize,
        source: u32,
        destination: u32,
        size: u32,
        handler: u32,
        operation: Operation,
        compressed_size: Option<u32>,
        output: PlannedOutput,
    ) -> PlannedEntry {
        PlannedEntry {
            index,
            descriptor: Descriptor {
                source,
                destination,
                size,
                handler,
            },
            operation,
            compressed_size,
            output,
        }
    }

    fn assert_bad<T>(result: Result<T>) {
        assert!(matches!(result, Err(Error::BadScatter(_))));
    }

    #[test]
    fn raw_reads_and_little_endian_words_are_borrowed() {
        let raw = raw();
        let plan = plan();
        let image = RuntimeImage::from_plan(&raw, BASE, Some(&plan)).unwrap();

        assert_eq!(image.read_u8(BASE).unwrap(), 0x11);
        assert_eq!(image.read_u16(BASE).unwrap(), 0x2211);
        assert_eq!(image.read_u32(BASE).unwrap(), 0x4433_2211);
        assert!(matches!(
            image.read_exact(BASE, 4).unwrap(),
            Cow::Borrowed(bytes) if bytes == [0x11, 0x22, 0x33, 0x44]
        ));
    }

    #[test]
    fn scatter_bytes_and_zero_fill_resolve_with_exact_provenance() {
        let raw = raw();
        let plan = plan();
        let image = RuntimeImage::from_plan(&raw, BASE, Some(&plan)).unwrap();

        assert!(matches!(
            image.read_exact(BYTES_DESTINATION, 4).unwrap(),
            Cow::Borrowed(bytes) if bytes == [b'C', 0, 0xcc, 0xdd]
        ));
        assert_eq!(
            image.read_exact(ZERO_DESTINATION, 4).unwrap().as_ref(),
            [0, 0, 0, 0]
        );
        assert_eq!(
            image.storage_spans(BYTES_DESTINATION, 8).unwrap(),
            [
                StorageSpan {
                    kind: StorageKind::ScatterBytes,
                    address: BYTES_DESTINATION,
                    size: 4,
                    scatter_entry: Some(3),
                },
                StorageSpan {
                    kind: StorageKind::ScatterZero,
                    address: ZERO_DESTINATION,
                    size: 4,
                    scatter_entry: Some(4),
                },
            ]
        );
        assert!(image.is_byte_backed(BYTES_DESTINATION, 4).unwrap());
        assert!(!image.is_byte_backed(ZERO_DESTINATION, 4).unwrap());
    }

    #[test]
    fn adjacent_cross_span_read_allocates_once_and_preserves_order() {
        let raw = raw();
        let plan = plan();
        let image = RuntimeImage::from_plan(&raw, BASE, Some(&plan)).unwrap();

        assert!(matches!(
            image.read_exact(BASE + 14, 4).unwrap(),
            Cow::Owned(bytes) if bytes == [b'A', b'B', b'C', 0]
        ));
        assert_eq!(
            image.storage_spans(BASE + 14, 4).unwrap(),
            [
                StorageSpan {
                    kind: StorageKind::Raw,
                    address: BASE + 14,
                    size: 2,
                    scatter_entry: None,
                },
                StorageSpan {
                    kind: StorageKind::ScatterBytes,
                    address: BYTES_DESTINATION,
                    size: 2,
                    scatter_entry: Some(3),
                },
            ]
        );
    }

    #[test]
    fn gaps_overlap_defense_wrap_and_zero_fill_execution_fail_closed() {
        let raw = raw();
        let plan = plan();
        let image = RuntimeImage::from_plan(&raw, BASE, Some(&plan)).unwrap();

        assert_bad(image.read_exact(ZERO_DESTINATION + 3, 2));
        assert_bad(image.storage_spans(ZERO_DESTINATION + 4, 1));
        assert_bad(image.is_byte_backed(ZERO_DESTINATION + 4, 1));
        assert!(!image.is_byte_backed(ZERO_DESTINATION, 1).unwrap());
        assert_bad(image.hash_range(u32::MAX, 2));

        let mut raw_overlap = plan.clone();
        raw_overlap.entries[1].descriptor.destination = BASE + 15;
        assert_bad(RuntimeImage::from_plan(&raw, BASE, Some(&raw_overlap)));

        let mut scatter_overlap = plan.clone();
        scatter_overlap.entries[2].descriptor.destination = BYTES_DESTINATION + 2;
        assert_bad(RuntimeImage::from_plan(&raw, BASE, Some(&scatter_overlap)));

        let mut wrapped = plan;
        wrapped.entries[2].descriptor.destination = u32::MAX - 1;
        assert_bad(RuntimeImage::from_plan(&raw, BASE, Some(&wrapped)));
        assert_bad(RuntimeImage::from_plan(&[0; 4], u32::MAX - 2, None));
    }

    #[test]
    fn ascii_nul_enforces_mapping_printability_and_128_byte_bound() {
        let raw = raw();
        let plan = plan();
        let image = RuntimeImage::from_plan(&raw, BASE, Some(&plan)).unwrap();

        let (name, storage) = image.read_ascii_nul(BASE + 14, 128).unwrap();
        assert_eq!(name, "ABC");
        assert_eq!(
            storage,
            [
                StorageSpan {
                    kind: StorageKind::Raw,
                    address: BASE + 14,
                    size: 2,
                    scatter_entry: None,
                },
                StorageSpan {
                    kind: StorageKind::ScatterBytes,
                    address: BYTES_DESTINATION,
                    size: 2,
                    scatter_entry: Some(3),
                },
            ]
        );
        assert_bad(image.read_ascii_nul(BASE + 8, 128));
        assert_bad(image.read_ascii_nul(ZERO_DESTINATION, 128));
        assert_bad(image.read_ascii_nul(ZERO_DESTINATION + 4, 128));
        assert_bad(image.read_ascii_nul(BASE, 129));

        let mut exact = vec![b'Z'; 129];
        exact[128] = 0;
        let exact_image = RuntimeImage::from_plan(&exact, BASE, None).unwrap();
        let (name, storage) = exact_image.read_ascii_nul(BASE, 128).unwrap();
        assert_eq!(name.len(), 128);
        assert_eq!(storage[0].size, 129);

        let unterminated = vec![b'Z'; 129];
        let unterminated_image = RuntimeImage::from_plan(&unterminated, BASE, None).unwrap();
        assert_bad(unterminated_image.read_ascii_nul(BASE, 128));
    }

    #[test]
    fn streaming_hash_matches_flat_reference_without_flattening_image() {
        let raw = raw();
        let plan = plan();
        let image = RuntimeImage::from_plan(&raw, BASE, Some(&plan)).unwrap();
        let flattened = [b'A', b'B', b'C', 0, 0xcc, 0xdd, 0, 0, 0, 0];

        assert_eq!(
            image.hash_range(BASE + 14, 10).unwrap(),
            *blake3::hash(&flattened).as_bytes()
        );

        let large = vec![0x5a; MAX_EXACT_READ + 17];
        let large_image = RuntimeImage::from_plan(&large, BASE, None).unwrap();
        assert_eq!(
            large_image.hash_range(BASE, large.len() as u32).unwrap(),
            *blake3::hash(&large).as_bytes()
        );
    }

    #[test]
    fn exact_reads_over_64_kib_are_rejected_before_allocation() {
        let raw = vec![0x5a; MAX_EXACT_READ + 1];
        let image = RuntimeImage::from_plan(&raw, BASE, None).unwrap();

        assert_eq!(
            image.read_exact(BASE, MAX_EXACT_READ).unwrap().len(),
            MAX_EXACT_READ
        );
        assert_bad(image.read_exact(BASE, MAX_EXACT_READ + 1));
    }

    #[test]
    fn for_image_dir_loads_the_image_dir_scatter_convention() {
        const BYTES_DEST: u32 = 0x2000_0100;
        const ZERO_DEST: u32 = 0x2000_0300;
        let mut image = vec![0u8; 0x1000];
        image[..16].copy_from_slice(&raw());
        // A materializable variant of the shared plan: the table range must
        // live inside the image (3 entries x 16 bytes), destinations must sit
        // outside the raw image, and a Copy entry's byte output must match its
        // source bytes.
        let mut scatter_plan = plan();
        scatter_plan.image_size = 0x1000;
        scatter_plan.loader_address = BASE + 0x40;
        scatter_plan.literal_pair_address = BASE + 0x80;
        scatter_plan.table_start = BASE + 0x200;
        scatter_plan.table_end = BASE + 0x230;
        let copy = &mut scatter_plan.entries[1];
        copy.descriptor.destination = BYTES_DEST;
        copy.operation = Operation::Copy;
        copy.compressed_size = None;
        copy.descriptor.handler = scatter_plan.handlers.copy;
        copy.output = PlannedOutput::Bytes(vec![0x55, 0x66, 0x77, 0x88]);
        scatter_plan.entries[2].descriptor.destination = ZERO_DEST;
        for (position, entry) in scatter_plan.entries.iter_mut().enumerate() {
            entry.index = position;
        }

        let kit = tempfile::tempdir().unwrap();
        crate::scatter::materialize(&scatter_plan, &image, "02_MAIN", kit.path()).unwrap();
        let image_dir = tempfile::tempdir().unwrap();
        // The decompose-tree convention keeps the materialized layout directly
        // under the image directory: scatter/{load_map.json, blocks/}.
        std::fs::rename(
            kit.path().join("scatter").join("02_MAIN"),
            image_dir.path().join("scatter"),
        )
        .unwrap();

        let runtime = RuntimeImage::for_image_dir(&image, BASE, image_dir.path()).unwrap();
        assert_eq!(
            runtime.read_exact(BYTES_DEST, 4).unwrap().as_ref(),
            [0x55, 0x66, 0x77, 0x88]
        );
        assert_eq!(
            runtime.storage_spans(BASE, 4).unwrap(),
            [StorageSpan {
                kind: StorageKind::Raw,
                address: BASE,
                size: 4,
                scatter_entry: None,
            }]
        );
        assert_eq!(
            runtime.storage_spans(BYTES_DEST, 4).unwrap(),
            [StorageSpan {
                kind: StorageKind::ScatterBytes,
                address: BYTES_DEST,
                size: 4,
                scatter_entry: Some(1),
            }]
        );
        assert_eq!(
            runtime.storage_spans(ZERO_DEST, 4).unwrap(),
            [StorageSpan {
                kind: StorageKind::ScatterZero,
                address: ZERO_DEST,
                size: 4,
                scatter_entry: Some(2),
            }]
        );

        // Without a scatter map the same constructor yields the raw mapping.
        let raw_only = tempfile::tempdir().unwrap();
        let runtime = RuntimeImage::for_image_dir(&image, BASE, raw_only.path()).unwrap();
        assert_eq!(
            runtime.storage_spans(BASE, 4).unwrap(),
            [StorageSpan {
                kind: StorageKind::Raw,
                address: BASE,
                size: 4,
                scatter_entry: None,
            }]
        );

        // A map at the conventional path is always consulted and fail-closed.
        std::fs::create_dir_all(image_dir.path().join("scatter")).unwrap();
        std::fs::write(image_dir.path().join("scatter/load_map.json"), b"not json").unwrap();
        assert_bad(RuntimeImage::for_image_dir(&image, BASE, image_dir.path()));
    }
}
