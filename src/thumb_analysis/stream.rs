//! Streaming Thumb backend adaptation and coordination: capture identity,
//! strict normalization, bounded fragment spills, and atomic v3 assembly.

#[cfg(test)]
use super::artifact::render_fragment;
use super::artifact::{
    AttemptRecord, AttemptStatus, CaptureRecord, FunctionRunRecord, RegionRecord, Spill,
    SpillWriter, assemble_v3_atomic, render_v3_fragment,
};
use super::radare2::{FunctionRecord, function_record};
use super::rizin::{
    RIZIN_SELECTED_XREF_CAP, RizinXrefIndex, function_record as rizin_function_record,
    read_rizin_xrefs_with_value_limit,
};
use super::{ProducerIdentity, ThumbAnalysisSummary, ThumbProducer, ThumbTools};
use crate::error::{Error, Result};
use crate::execution_ranges::{
    DecodeExtent, DecodeIsa, DecodeRangeErrorKind, ExecutionBudget, ExecutionProjection,
    canonicalize_errors, canonicalize_instruction_extents, error, projection_to_json,
    validate_execution,
};
use crate::runtime_image::RuntimeImage;
#[cfg(test)]
use serde_json::json;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

fn json_hex(v: u64) -> String {
    format!("0x{v:x}")
}

fn json_u64(v: &serde_json::Value) -> Option<u64> {
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    if let Some(n) = v.as_i64() {
        return (n >= 0).then_some(n as u64);
    }
    let s = v.as_str()?;
    s.strip_prefix("0x")
        .and_then(|hex| u64::from_str_radix(hex, 16).ok())
        .or_else(|| s.parse::<u64>().ok())
}

fn data_refs_from_pdfj(pdfj: &serde_json::Value) -> Vec<String> {
    fn is_data_ref(ref_obj: &serde_json::Map<String, serde_json::Value>) -> bool {
        let mut saw_data_hint = false;
        for field in ["type", "kind", "perm", "name"] {
            let Some(value) = ref_obj.get(field).and_then(serde_json::Value::as_str) else {
                continue;
            };
            let value = value.to_ascii_lowercase();
            if ["code", "call", "jump", "cjmp", "ujmp", "exec"]
                .iter()
                .any(|needle| value.contains(needle))
            {
                return false;
            }
            saw_data_hint |= ["data", "str", "string", "mem", "ptr", "read"]
                .iter()
                .any(|needle| value.contains(needle));
        }
        saw_data_hint
    }

    let mut refs = std::collections::BTreeSet::new();
    if let Some(ops) = pdfj.get("ops").and_then(serde_json::Value::as_array) {
        for op in ops {
            let Some(op_obj) = op.as_object() else {
                continue;
            };
            let Some(op_refs) = op_obj.get("refs").and_then(serde_json::Value::as_array) else {
                continue;
            };
            for op_ref in op_refs {
                let Some(ref_obj) = op_ref.as_object() else {
                    continue;
                };
                if !is_data_ref(ref_obj) {
                    continue;
                }
                if let Some(addr) = ref_obj
                    .get("addr")
                    .or_else(|| ref_obj.get("to"))
                    .and_then(json_u64)
                {
                    refs.insert(addr);
                }
            }
        }
    }
    refs.into_iter().map(json_hex).collect()
}

fn operation_body(pdfj: &serde_json::Value) -> String {
    let mut body = String::new();
    if let Some(ops) = pdfj.get("ops").and_then(serde_json::Value::as_array) {
        for op in ops {
            let Some(offset) = op
                .get("offset")
                .or_else(|| op.get("addr"))
                .and_then(json_u64)
            else {
                continue;
            };
            let bytes = op
                .get("bytes")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            let disasm = op
                .get("disasm")
                .or_else(|| op.get("opcode"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            if bytes.is_empty() {
                body.push_str(&format!("0x{offset:08x}      {disasm}\n"));
            } else {
                body.push_str(&format!("0x{offset:08x}      {bytes:<8}  {disasm}\n"));
            }
        }
    }
    body
}

#[cfg(test)]
fn radare2_function_entry(raw: &serde_json::Value) -> Option<u64> {
    function_record(raw).entry
}

fn pdfj_entry(pdfj: &serde_json::Value) -> Option<u64> {
    pdfj.get("addr")
        .or_else(|| pdfj.get("offset"))
        .and_then(json_u64)
        .or_else(|| {
            pdfj.get("ops")
                .and_then(serde_json::Value::as_array)
                .and_then(|ops| ops.first())
                .and_then(|op| op.get("offset").or_else(|| op.get("addr")))
                .and_then(json_u64)
        })
}

/// Legacy in-memory oracle for `balanced_json_end`; test-only.
#[cfg(test)]
fn balanced_json_end(text: &str, start: usize) -> Option<usize> {
    let mut stack = Vec::new();
    let mut in_string = false;
    let mut escaped = false;

    for (rel_idx, ch) in text[start..].char_indices() {
        let idx = start + rel_idx;
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }

        match ch {
            '"' => in_string = true,
            '{' => stack.push('}'),
            '[' => stack.push(']'),
            '}' | ']' => {
                if stack.pop() != Some(ch) {
                    return None;
                }
                if stack.is_empty() {
                    return Some(idx + ch.len_utf8());
                }
            }
            _ => {}
        }
    }
    None
}

/// Legacy in-memory oracle for `ValueScanner`; test-only.
#[cfg(test)]
fn radare2_json_values(stdout: &[u8]) -> Vec<serde_json::Value> {
    let text = String::from_utf8_lossy(stdout);
    let mut values = Vec::new();
    let mut pos = 0;

    while pos < text.len() {
        let Some((start, opener)) = text[pos..]
            .char_indices()
            .find(|(_, ch)| matches!(ch, '{' | '['))
            .map(|(rel_idx, ch)| (pos + rel_idx, ch))
        else {
            break;
        };

        if let Some(end) = balanced_json_end(&text, start)
            && let Ok(value) = serde_json::from_str::<serde_json::Value>(&text[start..end])
        {
            values.push(value);
            pos = end;
            continue;
        }

        pos = start + opener.len_utf8();
    }

    values
}

/// Streaming, noise-tolerant analyzer-output scanner: yields one top-level JSON
/// value's bytes at a time, byte-for-byte equivalent to the
/// legacy in-memory `radare2_json_values`/`balanced_json_end` pair (kept as
/// the `#[cfg(test)]` oracle). Memory is bounded by the largest single
/// top-level value plus one read chunk.
pub(super) struct ValueScanner<R> {
    reader: R,
    buf: Vec<u8>,
    eof: bool,
    out: Vec<u8>,
    consumed: u64,
    value_limit: usize,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct StreamedJsonValue {
    pub(super) start: u64,
    pub(super) end: u64,
    pub(super) opener: u8,
}

const SCANNER_CHUNK_BYTES: usize = 64 * 1024;

impl<R: Read> ValueScanner<R> {
    pub(super) fn new(reader: R) -> Self {
        Self {
            reader,
            buf: Vec::new(),
            eof: false,
            out: Vec::new(),
            consumed: 0,
            value_limit: usize::MAX,
        }
    }

    pub(super) fn with_value_limit(reader: R, value_limit: usize) -> Self {
        Self {
            value_limit,
            ..Self::new(reader)
        }
    }

    fn discard(&mut self, bytes: usize) {
        self.buf.drain(..bytes);
        self.consumed += u64::try_from(bytes).expect("scanner byte count fits u64");
    }

    fn fill(&mut self) -> std::io::Result<bool> {
        if self.eof {
            return Ok(false);
        }
        let start = self.buf.len();
        self.buf.resize(start + SCANNER_CHUNK_BYTES, 0);
        loop {
            match self.reader.read(&mut self.buf[start..]) {
                Ok(0) => {
                    self.buf.truncate(start);
                    self.eof = true;
                    return Ok(false);
                }
                Ok(n) => {
                    self.buf.truncate(start + n);
                    return Ok(true);
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    self.buf.truncate(start);
                    return Err(e);
                }
            }
        }
    }

    /// Next parseable top-level value's bytes, or `None` at EOF. The borrow
    /// is valid until the next call.
    pub(super) fn next_value(&mut self) -> std::io::Result<Option<&[u8]>> {
        loop {
            if self.buf.is_empty() && !self.fill()? {
                return Ok(None);
            }
            let noise = self
                .buf
                .iter()
                .position(|&b| b == b'{' || b == b'[')
                .unwrap_or(self.buf.len());
            if noise == self.buf.len() {
                self.discard(noise);
                if !self.fill()? {
                    return Ok(None);
                }
                continue;
            }
            if noise > 0 {
                self.discard(noise);
            }
            let mut stack: Vec<u8> = Vec::new();
            let mut in_string = false;
            let mut escaped = false;
            let mut end = None;
            for (i, &byte) in self.buf.iter().enumerate() {
                if in_string {
                    if escaped {
                        escaped = false;
                    } else if byte == b'\\' {
                        escaped = true;
                    } else if byte == b'"' {
                        in_string = false;
                    }
                    continue;
                }
                match byte {
                    b'"' => in_string = true,
                    b'{' => stack.push(b'}'),
                    b'[' => stack.push(b']'),
                    b'}' | b']' => {
                        stack.pop();
                        if stack.is_empty() {
                            end = Some(i);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let Some(end) = end else {
                if self.buf.len() > self.value_limit {
                    return Err(std::io::Error::other(format!(
                        "generic JSON value limit of {} bytes exceeded",
                        self.value_limit
                    )));
                }
                if !self.fill()? {
                    self.discard(1);
                }
                continue;
            };
            if end + 1 > self.value_limit {
                return Err(std::io::Error::other(format!(
                    "generic JSON value limit of {} bytes exceeded",
                    self.value_limit
                )));
            }
            let text = String::from_utf8_lossy(&self.buf[..=end]);
            if serde_json::from_str::<serde::de::IgnoredAny>(&text).is_ok() {
                self.out.clear();
                self.out.extend_from_slice(&self.buf[..=end]);
                self.discard(end + 1);
                return Ok(Some(&self.out));
            }
            self.discard(1);
        }
    }
}

impl<R: Read + Seek> ValueScanner<R> {
    /// Locate the next parseable object or array without retaining its bytes.
    /// Seeking lets Rizin distinguish diagnostic brackets from the final axlj
    /// array without feeding that array to the whole-value accumulator.
    pub(super) fn next_streamed_value(&mut self) -> Result<Option<StreamedJsonValue>> {
        self.next_streamed_value_inner(false)
    }

    /// Include standalone scalar records when checking that axlj is the final
    /// JSON value. Scalar-looking fragments on diagnostic records stay noise.
    pub(super) fn next_streamed_any_value(&mut self) -> Result<Option<StreamedJsonValue>> {
        self.next_streamed_value_inner(true)
    }

    fn next_streamed_value_inner(
        &mut self,
        include_scalars: bool,
    ) -> Result<Option<StreamedJsonValue>> {
        self.reader.seek(SeekFrom::Start(self.consumed))?;
        self.buf.clear();
        self.out.clear();
        self.eof = false;

        let mut position = self.consumed;
        let mut scalar_record_start = include_scalars;
        let mut byte = [0u8; 1];
        loop {
            if self.reader.read(&mut byte)? == 0 {
                self.consumed = position;
                self.eof = true;
                return Ok(None);
            }
            let start = position;
            position = position
                .checked_add(1)
                .ok_or_else(|| Error::Serialize("Rizin capture offset overflow".to_string()))?;
            self.consumed = position;
            if matches!(byte[0], b'\n' | b'\r') {
                scalar_record_start = include_scalars;
                continue;
            }
            if byte[0].is_ascii_whitespace() {
                continue;
            }

            let container = matches!(byte[0], b'{' | b'[');
            let scalar = include_scalars
                && scalar_record_start
                && matches!(byte[0], b'"' | b'-' | b'0'..=b'9' | b't' | b'f' | b'n');
            if !container && !scalar {
                scalar_record_start = false;
                continue;
            }

            let end = if scalar {
                self.standalone_scalar_end(start)?
            } else {
                self.streamed_value_end(start)?
            };
            if let Some(end) = end {
                self.reader.seek(SeekFrom::Start(end))?;
                self.consumed = end;
                return Ok(Some(StreamedJsonValue {
                    start,
                    end,
                    opener: byte[0],
                }));
            }

            scalar_record_start = false;
            position = start
                .checked_add(1)
                .ok_or_else(|| Error::Serialize("Rizin capture offset overflow".to_string()))?;
            self.reader.seek(SeekFrom::Start(position))?;
            self.consumed = position;
        }
    }

    fn streamed_value_end(&mut self, start: u64) -> Result<Option<u64>> {
        self.reader.seek(SeekFrom::Start(start))?;
        let mut stream = serde_json::Deserializer::from_reader(&mut self.reader)
            .into_iter::<serde::de::IgnoredAny>();
        let parsed = stream.next();
        let consumed = stream.byte_offset();
        drop(stream);
        match parsed {
            Some(Ok(_)) => {
                let consumed = u64::try_from(consumed).map_err(|_| {
                    Error::Serialize("Rizin capture offset exceeds u64".to_string())
                })?;
                start
                    .checked_add(consumed)
                    .map(Some)
                    .ok_or_else(|| Error::Serialize("Rizin capture offset overflow".to_string()))
            }
            Some(Err(error)) if error.is_io() => Err(Error::Serialize(format!(
                "scan Rizin capture JSON: {error}"
            ))),
            _ => Ok(None),
        }
    }

    fn standalone_scalar_end(&mut self, start: u64) -> Result<Option<u64>> {
        // A diagnostic may begin with a scalar prefix. It is standalone JSON
        // only when the complete physical record is a valid JSON value stream.
        self.reader.seek(SeekFrom::Start(start))?;
        let mut record_end = start;
        let mut byte = [0u8; 1];
        while self.reader.read(&mut byte)? != 0 {
            if matches!(byte[0], b'\n' | b'\r') {
                break;
            }
            record_end = record_end
                .checked_add(1)
                .ok_or_else(|| Error::Serialize("Rizin capture offset overflow".to_string()))?;
        }

        self.reader.seek(SeekFrom::Start(start))?;
        let record_len = record_end.checked_sub(start).ok_or_else(|| {
            Error::Serialize("Rizin capture value has invalid offsets".to_string())
        })?;
        let mut stream = serde_json::Deserializer::from_reader((&mut self.reader).take(record_len))
            .into_iter::<serde::de::IgnoredAny>();
        let mut first_end = None;
        while let Some(parsed) = stream.next() {
            match parsed {
                Ok(_) => {
                    if first_end.is_none() {
                        first_end = Some(stream.byte_offset());
                    }
                }
                Err(error) if error.is_io() => {
                    return Err(Error::Serialize(format!(
                        "scan Rizin capture JSON: {error}"
                    )));
                }
                Err(_) => return Ok(None),
            }
        }
        let Some(first_end) = first_end else {
            return Ok(None);
        };
        let first_end = u64::try_from(first_end)
            .map_err(|_| Error::Serialize("Rizin capture offset exceeds u64".to_string()))?;
        start
            .checked_add(first_end)
            .map(Some)
            .ok_or_else(|| Error::Serialize("Rizin capture offset overflow".to_string()))
    }

    pub(super) fn read_streamed_value(&mut self, value: StreamedJsonValue) -> Result<&[u8]> {
        let len = value.end.checked_sub(value.start).ok_or_else(|| {
            Error::Serialize("Rizin capture value has invalid offsets".to_string())
        })?;
        let len = usize::try_from(len).map_err(|_| {
            Error::Serialize("Rizin capture value exceeds addressable memory".to_string())
        })?;
        if len > self.value_limit {
            return Err(Error::Serialize(format!(
                "generic JSON value limit of {} bytes exceeded",
                self.value_limit
            )));
        }

        self.reader.seek(SeekFrom::Start(value.start))?;
        self.out.resize(len, 0);
        self.reader.read_exact(&mut self.out)?;
        self.reader.seek(SeekFrom::Start(value.end))?;
        self.buf.clear();
        self.eof = false;
        self.consumed = value.end;
        Ok(&self.out)
    }
}

/// Sentinel aborting a seq probe when an element disqualifies the array as
/// the aflj inventory (non-object element, or an object carrying `ops`).
const NOT_INVENTORY: &str = "\u{0}pme-not-inventory";
const INVENTORY_FUNCTION_LIMIT: &str = "pme-inventory-function-limit";

fn parse_inventory_value_with(
    bytes: &[u8],
    adapt: fn(&serde_json::Value) -> FunctionRecord,
) -> Result<Option<Vec<FunctionRecord>>> {
    use serde::Deserializer;

    let text = String::from_utf8_lossy(bytes);
    let mut de = serde_json::Deserializer::from_str(&text);
    match de.deserialize_seq(InventoryProbe { adapt }) {
        Ok(records) if !records.is_empty() => Ok(Some(records)),
        Ok(_) => Ok(None),
        Err(error) if error.to_string().contains(INVENTORY_FUNCTION_LIMIT) => Err(
            Error::Serialize("execution function count exceeds the supported limit".into()),
        ),
        Err(_) => Ok(None),
    }
}

pub(super) fn scan_rizin_inventory<R: Read>(
    scanner: &mut ValueScanner<R>,
    adapt: fn(&serde_json::Value) -> FunctionRecord,
) -> Result<Vec<FunctionRecord>> {
    let bytes = scanner
        .next_value()?
        .ok_or_else(|| Error::Serialize("Rizin capture lacks a function inventory".to_string()))?;
    parse_inventory_value_with(bytes, adapt)?.ok_or_else(|| {
        Error::Serialize(
            "Rizin capture inventory must be a non-empty object array without ops".to_string(),
        )
    })
}

pub(super) fn read_rizin_pdfj_value<R: Read + Seek>(
    scanner: &mut ValueScanner<R>,
    position: usize,
) -> Result<serde_json::Value> {
    let candidate = scanner
        .next_streamed_value()
        .map_err(|error| Error::Serialize(format!("Rizin capture pdfj body {position}: {error}")))?
        .ok_or_else(|| Error::Serialize(format!("Rizin capture lacks pdfj body {position}")))?;
    if candidate.opener != b'{' {
        return Err(Error::Serialize(format!(
            "Rizin capture pdfj body {position}: expected a JSON object before the trailing array"
        )));
    }
    let bytes = scanner.read_streamed_value(candidate).map_err(|error| {
        Error::Serialize(format!("read Rizin capture pdfj body {position}: {error}"))
    })?;
    let value = serde_json::from_slice::<serde_json::Value>(bytes)
        .map_err(|error| Error::Serialize(format!("parse Rizin pdfj body {position}: {error}")))?;
    // `pdfj @@F` emits one object per analyzed function and `ops` is the
    // operation array every projection is built from. Accepting any object
    // would let schema drift pair empty bodies positionally, quarantine every
    // function as `empty_projection`, and publish an all-quarantined
    // "successful" Rizin run instead of failing the attempt closed.
    if !value.get("ops").is_some_and(serde_json::Value::is_array) {
        return Err(Error::Serialize(format!(
            "Rizin pdfj body {position} lacks an array-valued ops field"
        )));
    }
    Ok(value)
}

struct InventoryProbe {
    adapt: fn(&serde_json::Value) -> FunctionRecord,
}

impl<'de> serde::de::Visitor<'de> for InventoryProbe {
    type Value = Vec<FunctionRecord>;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("aflj function inventory array")
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(
        self,
        mut seq: A,
    ) -> std::result::Result<Self::Value, A::Error> {
        let mut records = Vec::new();
        while let Some(element) = seq.next_element::<serde_json::Value>()? {
            if records.len() == crate::execution_ranges::MAX_EXECUTION_FUNCTIONS {
                return Err(serde::de::Error::custom(INVENTORY_FUNCTION_LIMIT));
            }
            let disqualified = match element.as_object() {
                None => true,
                Some(object) => object.contains_key("ops"),
            };
            if disqualified {
                return Err(serde::de::Error::custom(NOT_INVENTORY));
            }
            records.push((self.adapt)(&element));
        }
        Ok(records)
    }
}

/// Stream values until the first aflj inventory; returns the count of values
/// seen and the compact records. Leaves the scanner positioned after the
/// inventory value. The count matches legacy `values.len()` for the zero
/// check because a found inventory implies >= 1 and an unfound one exhausts
/// the stream.
#[cfg(test)]
fn scan_for_inventory<R: Read>(
    scanner: &mut ValueScanner<R>,
) -> std::io::Result<(usize, Option<Vec<FunctionRecord>>)> {
    scan_for_inventory_with(scanner, function_record)
}

fn scan_for_inventory_with<R: Read>(
    scanner: &mut ValueScanner<R>,
    adapt: fn(&serde_json::Value) -> FunctionRecord,
) -> std::io::Result<(usize, Option<Vec<FunctionRecord>>)> {
    let mut values = 0usize;
    while let Some(bytes) = scanner.next_value()? {
        values += 1;
        match parse_inventory_value_with(bytes, adapt) {
            Ok(Some(records)) => return Ok((values, Some(records))),
            Ok(None) => {}
            Err(error) => return Err(std::io::Error::other(error.to_string())),
        }
    }
    Ok((values, None))
}

/// Per-region counters maintained incrementally during streaming.
struct RegionStats {
    raw: usize,
    substantial: usize,
    accepted: usize,
}

/// One region's finished spill plus its stats.
struct RegionOutcome {
    spill: Spill,
    stats: RegionStats,
}

struct SuccessfulRegion {
    outcome: RegionOutcome,
    capture: CaptureRecord,
}

struct FailedRegion {
    capture: Option<CaptureRecord>,
    error: Error,
    /// Set when the attempt left unverified process or on-disk state: a child
    /// that could not be reaped, a drain that would not stop, or output that
    /// could not be removed. The coordinator then records no attempt, runs no
    /// fallback, processes no later region, and publishes no artifact.
    terminal: bool,
}

impl FailedRegion {
    /// An ordinary backend failure. The attempt is recorded and, when enabled,
    /// the region may still fall back to the other producer.
    fn recoverable(capture: Option<CaptureRecord>, error: Error) -> Self {
        Self {
            capture,
            error,
            terminal: false,
        }
    }

    /// Pre-attempt housekeeping failed, so no backend process was spawned.
    /// Recording an attempt here would claim a process that never ran and
    /// would hand a region to the fallback without running the primary.
    fn setup(error: Error) -> Self {
        Self {
            capture: None,
            error,
            terminal: true,
        }
    }

    fn mark_terminal(&mut self, context: &str, cause: std::io::Error) {
        self.error = Error::Serialize(format!("{}; {context}: {cause}", self.error));
        self.terminal = true;
    }

    fn after_cleanup(
        capture: Option<CaptureRecord>,
        error: Error,
        cleanup_context: &str,
        cleanup: std::io::Result<()>,
    ) -> Self {
        let mut failure = Self::recoverable(capture, error);
        if let Err(error) = cleanup {
            failure.mark_terminal(cleanup_context, error);
        }
        failure
    }
}

/// Carries io and callback errors out of `for_each_pdfj_position`'s read loop.
enum RegionIterError {
    Io(std::io::Error),
    Region(Error),
}

impl From<std::io::Error> for RegionIterError {
    fn from(e: std::io::Error) -> Self {
        RegionIterError::Io(e)
    }
}

fn region_iter_err(e: RegionIterError) -> Error {
    match e {
        RegionIterError::Io(e) => e.into(),
        RegionIterError::Region(e) => e,
    }
}

/// Iterate pdfj positions from a scanner positioned after the inventory: a
/// top-level object with an `ops` array is a pdfj; a top-level array
/// contributes its ops-object elements in order (the legacy nested shape);
/// everything else is skipped. Positions count accepted pdfjs in arrival
/// order — the order `pdfj_values_from_radare2_output` produced.
fn for_each_pdfj_position<R, F>(
    scanner: &mut ValueScanner<R>,
    mut on_pdfj: F,
) -> std::result::Result<(), RegionIterError>
where
    R: Read,
    F: FnMut(usize, serde_json::Value) -> Result<()>,
{
    let mut position = 0usize;
    while let Some(bytes) = scanner.next_value()? {
        let text = String::from_utf8_lossy(bytes);
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        if value
            .get("ops")
            .and_then(serde_json::Value::as_array)
            .is_some()
        {
            on_pdfj(position, value).map_err(RegionIterError::Region)?;
            position += 1;
        } else if let Some(elements) = value.as_array() {
            for element in elements {
                if element
                    .get("ops")
                    .and_then(serde_json::Value::as_array)
                    .is_some()
                {
                    on_pdfj(position, element.clone()).map_err(RegionIterError::Region)?;
                    position += 1;
                }
            }
        }
    }
    Ok(())
}

fn for_each_rizin_pdfj_position<R, F>(
    scanner: &mut ValueScanner<R>,
    expected: usize,
    mut on_pdfj: F,
) -> std::result::Result<(), RegionIterError>
where
    R: Read + Seek,
    F: FnMut(usize, serde_json::Value) -> Result<()>,
{
    for position in 0..expected {
        let value = read_rizin_pdfj_value(scanner, position).map_err(RegionIterError::Region)?;
        on_pdfj(position, value).map_err(RegionIterError::Region)?;
    }
    Ok(())
}

fn for_each_backend_pdfj_position<R, F>(
    scanner: &mut ValueScanner<R>,
    producer: ThumbProducer,
    expected: usize,
    on_pdfj: F,
) -> std::result::Result<(), RegionIterError>
where
    R: Read + Seek,
    F: FnMut(usize, serde_json::Value) -> Result<()>,
{
    match producer {
        ThumbProducer::Radare2 => for_each_pdfj_position(scanner, on_pdfj),
        ThumbProducer::Rizin => for_each_rizin_pdfj_position(scanner, expected, on_pdfj),
    }
}

/// Process one captured `.stdout` with bounded memory: stream the inventory
/// into compact records (A), entry-match arriving pdfjs normalizing and spilling
/// immediately (B1), positional-fallback re-stream (B2), and normalize the
/// never-paired remainder with `pdfj = None` (C). Validation around these
/// passes preserves no-JSON, unassignable, orphan, zero-pair producer failure,
/// then u32-domain precedence. Any `Err` removes the partial spill.
fn process_region_streaming(
    stdout_path: &Path,
    image: &[u8],
    load_addr: u32,
    addr: u32,
    thumb_dir: &Path,
) -> Result<RegionOutcome> {
    let spill_path = thumb_dir.join(format!("{addr:08x}.radare2.frags"));
    process_region_with_adapter(
        stdout_path,
        image,
        load_addr,
        addr,
        &spill_path,
        ThumbProducer::Radare2,
        function_record,
        // radare2 emits per-operation references directly; only Rizin needs
        // the adapted `axlj` index.
        &mut RizinXrefIndex::new(Vec::new()),
        usize::MAX,
    )
}

fn process_rizin_region_streaming(
    stdout_path: &Path,
    image: &[u8],
    load_addr: u32,
    addr: u32,
    thumb_dir: &Path,
) -> Result<RegionOutcome> {
    process_rizin_region_streaming_with_value_limit(
        stdout_path,
        image,
        load_addr,
        addr,
        thumb_dir,
        usize::MAX,
    )
}

fn process_rizin_region_streaming_with_value_limit(
    stdout_path: &Path,
    image: &[u8],
    load_addr: u32,
    addr: u32,
    thumb_dir: &Path,
    generic_value_limit: usize,
) -> Result<RegionOutcome> {
    // Index xrefs before normalization so only validated decode ranges can
    // attribute them and a malformed trailing axlj cannot leave a spill.
    let mut xrefs = RizinXrefIndex::new(read_rizin_xrefs_with_value_limit(
        stdout_path,
        RIZIN_SELECTED_XREF_CAP,
        generic_value_limit,
    )?);
    let spill_path = thumb_dir.join(format!("{addr:08x}.rizin.frags"));
    let outcome = process_region_with_adapter(
        stdout_path,
        image,
        load_addr,
        addr,
        &spill_path,
        ThumbProducer::Rizin,
        rizin_function_record,
        &mut xrefs,
        generic_value_limit,
    )?;
    // Unmapped selected xrefs are permitted; only their count is reported.
    tracing::debug!(
        "Rizin region 0x{addr:x} adapted {} of {} selected xrefs; {} unmapped",
        xrefs.selected() - xrefs.unmapped(),
        xrefs.selected(),
        xrefs.unmapped(),
    );
    Ok(outcome)
}

#[allow(clippy::too_many_arguments)]
fn process_region_with_adapter(
    stdout_path: &Path,
    image: &[u8],
    load_addr: u32,
    addr: u32,
    spill_path: &Path,
    producer: ThumbProducer,
    adapt: fn(&serde_json::Value) -> FunctionRecord,
    xrefs: &mut RizinXrefIndex,
    generic_value_limit: usize,
) -> Result<RegionOutcome> {
    match process_region_inner(
        stdout_path,
        image,
        load_addr,
        addr,
        spill_path,
        producer,
        adapt,
        xrefs,
        generic_value_limit,
    ) {
        Ok(outcome) => Ok(outcome),
        // A partial spill must not survive a failed parse. An unverified
        // removal is preserved in the message; `run_backend_region` sweeps the
        // same path afterwards and turns the repeat failure into a terminal
        // one, so the coordinator never publishes over unowned fragments.
        Err(error) => Err(match remove_stale_output(spill_path) {
            Ok(()) => error,
            Err(cleanup) => {
                Error::Serialize(format!("{error}; fragment spill cleanup failed: {cleanup}"))
            }
        }),
    }
}

#[allow(clippy::too_many_arguments)]
fn process_region_inner(
    stdout_path: &Path,
    image: &[u8],
    load_addr: u32,
    addr: u32,
    spill_path: &Path,
    producer: ThumbProducer,
    adapt: fn(&serde_json::Value) -> FunctionRecord,
    xrefs: &mut RizinXrefIndex,
    generic_value_limit: usize,
) -> Result<RegionOutcome> {
    let file = std::fs::File::open(stdout_path)?;
    let mut scanner =
        ValueScanner::with_value_limit(std::io::BufReader::new(file), generic_value_limit);
    let producer_name = producer.as_str();

    // Pass A — compact inventory, then the legacy verdicts known up front.
    let (value_count, inventory) = if producer == ThumbProducer::Rizin {
        (1, Some(scan_rizin_inventory(&mut scanner, adapt)?))
    } else {
        scan_for_inventory_with(&mut scanner, adapt)?
    };
    if value_count == 0 {
        return Err(Error::Serialize(format!(
            "{producer_name} produced no parseable JSON for Thumb region 0x{addr:x}"
        )));
    }
    let Some(fns) = inventory else {
        return Err(Error::Serialize(format!(
            "{producer_name} produced parseable JSON but no aflj function inventory for Thumb region 0x{addr:x}"
        )));
    };
    let unassignable = fns.iter().filter(|f| f.entry.is_none()).count();
    if unassignable > 0 {
        return Err(Error::Serialize(format!(
            "{producer_name} reported {unassignable} unassignable aflj function {} for Thumb region 0x{addr:x}",
            if unassignable == 1 {
                "record"
            } else {
                "records"
            }
        )));
    }
    // Deferred u32-domain verdict: overflow fns still pair (legacy pairing
    // runs before its normalize loop) but never normalize here; the error
    // fires after the orphan check, exactly where the legacy loop hit it.
    let overflow: Vec<bool> = fns
        .iter()
        .map(|f| u32::try_from(f.entry.expect("unassignable rejected")).is_err())
        .collect();
    let mut paired = vec![false; fns.len()];
    let mut pdfj_used: Vec<bool> = Vec::new();
    let mut spill = SpillWriter::create(spill_path.to_path_buf())?;
    let mut stats = RegionStats {
        raw: fns.len(),
        substantial: 0,
        accepted: 0,
    };
    let mut execution_budget = ExecutionBudget::default();

    // B1 — entry-matching on the same scanner. Greedy first-unpaired-fn
    // assignment is equivalent to the legacy fn-outer scan: per entry key
    // both orderings pair the i-th fn of the key with the i-th pdfj of the
    // key; different keys never compete.
    for_each_backend_pdfj_position(&mut scanner, producer, fns.len(), |position, pdfj| {
        pdfj_used.push(false);
        let Some(entry) = pdfj_entry(&pdfj) else {
            return Ok(());
        };
        let Some(fn_idx) = (0..fns.len()).find(|&i| !paired[i] && fns[i].entry == Some(entry))
        else {
            return Ok(());
        };
        paired[fn_idx] = true;
        pdfj_used[position] = true;
        if !overflow[fn_idx] {
            normalize_and_spill(
                &mut spill,
                &mut stats,
                fn_idx,
                &fns[fn_idx],
                Some(&pdfj),
                image,
                load_addr,
                addr,
                producer,
                xrefs,
                &mut execution_budget,
            )?;
        }
        Ok(())
    })
    .map_err(region_iter_err)?;

    // B2 — positional fallback over a fresh stream of the same capture.
    let file = std::fs::File::open(stdout_path)?;
    let mut scanner =
        ValueScanner::with_value_limit(std::io::BufReader::new(file), generic_value_limit);
    if producer == ThumbProducer::Rizin {
        scan_rizin_inventory(&mut scanner, adapt)?;
    } else {
        scan_for_inventory_with(&mut scanner, adapt)?;
    }
    for_each_backend_pdfj_position(&mut scanner, producer, fns.len(), |position, pdfj| {
        if pdfj_used.get(position).copied().unwrap_or(false) {
            return Ok(());
        }
        let Some(rec) = fns.get(position) else {
            return Ok(());
        };
        if paired[position] {
            return Ok(());
        }
        let candidate = pdfj_entry(&pdfj);
        if candidate.is_some_and(|entry| rec.entry != Some(entry)) {
            return Ok(());
        }
        pdfj_used[position] = true;
        paired[position] = true;
        if !overflow[position] {
            normalize_and_spill(
                &mut spill,
                &mut stats,
                position,
                rec,
                Some(&pdfj),
                image,
                load_addr,
                addr,
                producer,
                xrefs,
                &mut execution_budget,
            )?;
        }
        Ok(())
    })
    .map_err(region_iter_err)?;

    // Verdicts preserve orphan precedence; producer integrity precedes the
    // deferred u32-domain check so the streaming and in-memory paths agree.
    let orphan = pdfj_used.iter().filter(|used| !**used).count();
    if orphan > 0 {
        return Err(Error::Serialize(format!(
            "{producer_name} produced {orphan} orphan pdfj {} for Thumb region 0x{addr:x}",
            if orphan == 1 { "body" } else { "bodies" }
        )));
    }
    let paired_count = paired.iter().filter(|paired| **paired).count();
    if !fns.is_empty() && paired_count == 0 {
        return Err(Error::Serialize(format!(
            "{producer_name} produced a non-empty aflj inventory but zero paired pdfj bodies for Thumb region 0x{addr:x}"
        )));
    }
    if overflow.contains(&true) {
        return Err(Error::Serialize(format!(
            "{producer_name} function entry is outside the canonical u32 address domain for Thumb region 0x{addr:x}"
        )));
    }

    // Pass C — never-paired functions normalize with pdfj = None.
    for (fn_idx, rec) in fns.iter().enumerate() {
        if !paired[fn_idx] {
            normalize_and_spill(
                &mut spill,
                &mut stats,
                fn_idx,
                rec,
                None,
                image,
                load_addr,
                addr,
                producer,
                xrefs,
                &mut execution_budget,
            )?;
        }
    }

    if stats.accepted > stats.raw || stats.substantial > stats.raw {
        return Err(Error::Serialize(format!(
            "{producer_name} Thumb function counts are not conserving for region 0x{addr:x}"
        )));
    }
    let spill = spill.finish()?;
    Ok(RegionOutcome { spill, stats })
}

/// Normalize one adapted inventory record, classify its emitted projection,
/// and spill the fragment. `rec.entry` must be `Some` because unassignable
/// records are rejected upstream.
#[allow(clippy::too_many_arguments)]
fn normalize_and_spill(
    spill: &mut SpillWriter,
    stats: &mut RegionStats,
    fn_idx: usize,
    rec: &FunctionRecord,
    pdfj: Option<&serde_json::Value>,
    image: &[u8],
    load_addr: u32,
    addr: u32,
    producer: ThumbProducer,
    xrefs: &mut RizinXrefIndex,
    execution_budget: &mut ExecutionBudget,
) -> Result<()> {
    let normalized = match producer {
        ThumbProducer::Radare2 => normalize_radare2_record_with_budget(
            rec,
            pdfj,
            image,
            load_addr,
            addr,
            execution_budget,
        )?,
        ThumbProducer::Rizin => normalize_rizin_record_with_budget(
            rec,
            pdfj,
            xrefs,
            image,
            load_addr,
            addr,
            execution_budget,
        )?,
    };
    stats.substantial += usize::from(
        normalized
            .get("size")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|size| size >= 32),
    );
    if normalized
        .get("decode_ranges")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|ranges| !ranges.is_empty())
    {
        stats.accepted += 1;
    }
    let fragment = render_v3_fragment(&normalized, fn_idx)?;
    let function_index = u32::try_from(fn_idx).map_err(|_| {
        Error::Serialize(format!("{} function index exceeds u32", producer.as_str()))
    })?;
    spill.push(function_index, &fragment)?;
    Ok(())
}

/// Legacy in-memory oracle for `for_each_pdfj_position`'s flattening; test-only.
#[cfg(test)]
fn pdfj_values_from_radare2_output(values: &[serde_json::Value]) -> Vec<serde_json::Value> {
    let mut pdfjs = Vec::new();
    let start = values
        .iter()
        .position(is_aflj_function_inventory)
        .map(|idx| idx + 1)
        .unwrap_or(0);
    for value in values.iter().skip(start) {
        if value
            .get("ops")
            .and_then(serde_json::Value::as_array)
            .is_some()
        {
            pdfjs.push(value.clone());
        } else if let Some(values) = value.as_array() {
            pdfjs.extend(
                values
                    .iter()
                    .filter(|value| {
                        value
                            .get("ops")
                            .and_then(serde_json::Value::as_array)
                            .is_some()
                    })
                    .cloned(),
            );
        }
    }
    pdfjs
}

/// Legacy in-memory oracle for `scan_for_inventory`'s detection; test-only.
#[cfg(test)]
fn is_aflj_function_inventory(value: &serde_json::Value) -> bool {
    let Some(values) = value.as_array() else {
        return false;
    };
    !values.is_empty()
        && values.iter().all(|value| {
            value
                .as_object()
                .map(|obj| !obj.contains_key("ops"))
                .unwrap_or(false)
        })
}

/// Legacy whole-buffer parse result; oracle for the streaming pipeline, test-only.
#[cfg(test)]
#[derive(Debug)]
struct Radare2ThumbOutput {
    json_value_count: usize,
    has_function_inventory: bool,
    records: Vec<(serde_json::Value, Option<serde_json::Value>)>,
    unassignable_function_count: usize,
    orphan_pdfj_count: usize,
}

/// Legacy whole-buffer pairing oracle; test-only.
#[cfg(test)]
fn parse_radare2_thumb_output(stdout: &[u8]) -> Radare2ThumbOutput {
    let values = radare2_json_values(stdout);
    let Some(fns) = values
        .iter()
        .find(|value| is_aflj_function_inventory(value))
        .and_then(serde_json::Value::as_array)
    else {
        return Radare2ThumbOutput {
            json_value_count: values.len(),
            has_function_inventory: false,
            records: Vec::new(),
            unassignable_function_count: 0,
            orphan_pdfj_count: 0,
        };
    };
    let pdfjs = pdfj_values_from_radare2_output(&values);
    let mut used_pdfjs = vec![false; pdfjs.len()];
    let mut paired_pdfjs: Vec<Option<serde_json::Value>> = vec![None; fns.len()];
    let mut unassignable_function_count = 0;

    for (idx, f) in fns.iter().enumerate() {
        let Some(entry) = radare2_function_entry(f) else {
            unassignable_function_count += 1;
            continue;
        };
        let Some(pdfj_idx) = pdfjs.iter().enumerate().find_map(|(pdfj_idx, pdfj)| {
            (!used_pdfjs[pdfj_idx] && pdfj_entry(pdfj) == Some(entry)).then_some(pdfj_idx)
        }) else {
            continue;
        };
        used_pdfjs[pdfj_idx] = true;
        paired_pdfjs[idx] = Some(pdfjs[pdfj_idx].clone());
    }

    for (idx, paired_pdfj) in paired_pdfjs.iter_mut().enumerate() {
        if paired_pdfj.is_some() {
            continue;
        }
        let Some(pdfj) = pdfjs.get(idx) else {
            continue;
        };
        if used_pdfjs[idx] {
            continue;
        }
        let fn_entry = fns.get(idx).and_then(radare2_function_entry);
        let candidate_entry = pdfj_entry(pdfj);
        if candidate_entry.is_none() || candidate_entry == fn_entry {
            used_pdfjs[idx] = true;
            *paired_pdfj = Some(pdfj.clone());
        }
    }

    let records: Vec<_> = fns.iter().cloned().zip(paired_pdfjs).collect();

    Radare2ThumbOutput {
        json_value_count: values.len(),
        has_function_inventory: true,
        records,
        unassignable_function_count,
        orphan_pdfj_count: used_pdfjs.iter().filter(|used| !**used).count(),
    }
}

#[cfg(test)]
fn radare2_thumb_function_pdfjs(stdout: &[u8]) -> Vec<(serde_json::Value, serde_json::Value)> {
    parse_radare2_thumb_output(stdout)
        .records
        .into_iter()
        .filter_map(|(function, body)| body.map(|body| (function, body)))
        .collect()
}

/// Legacy whole-buffer verdict oracle (error strings are the pinned invariant); test-only.
#[cfg(test)]
fn parse_checked_radare2_thumb_output(stdout: &[u8], addr: u32) -> Result<Radare2ThumbOutput> {
    let parsed = parse_radare2_thumb_output(stdout);
    if parsed.json_value_count == 0 {
        return Err(Error::Serialize(format!(
            "radare2 produced no parseable JSON for Thumb region 0x{addr:x}"
        )));
    }
    if !parsed.has_function_inventory {
        return Err(Error::Serialize(format!(
            "radare2 produced parseable JSON but no aflj function inventory for Thumb region 0x{addr:x}"
        )));
    }
    if parsed.unassignable_function_count > 0 {
        return Err(Error::Serialize(format!(
            "radare2 reported {} unassignable aflj function {} for Thumb region 0x{addr:x}",
            parsed.unassignable_function_count,
            if parsed.unassignable_function_count == 1 {
                "record"
            } else {
                "records"
            },
        )));
    }
    if parsed.orphan_pdfj_count > 0 {
        return Err(Error::Serialize(format!(
            "radare2 produced {} orphan pdfj {} for Thumb region 0x{addr:x}",
            parsed.orphan_pdfj_count,
            if parsed.orphan_pdfj_count == 1 {
                "body"
            } else {
                "bodies"
            },
        )));
    }
    let paired_count = parsed
        .records
        .iter()
        .filter(|(_, pdfj)| pdfj.is_some())
        .count();
    if !parsed.records.is_empty() && paired_count == 0 {
        return Err(Error::Serialize(format!(
            "radare2 produced a non-empty aflj inventory but zero paired pdfj bodies for Thumb region 0x{addr:x}"
        )));
    }
    Ok(parsed)
}

fn check_thumb_backend_status(
    producer: ThumbProducer,
    success: bool,
    code: Option<i32>,
    addr: u32,
) -> Result<()> {
    if success {
        return Ok(());
    }
    let status = code
        .map(|code| format!("status {code}"))
        .unwrap_or_else(|| "unknown status".to_string());
    Err(Error::Serialize(format!(
        "{} exited with {status} for Thumb region 0x{addr:x}",
        producer.as_str()
    )))
}

#[cfg(test)]
fn normalize_radare2_function(
    raw: &serde_json::Value,
    pdfj: &serde_json::Value,
) -> Result<serde_json::Value> {
    let mut image = vec![0; 0x1_0000];
    populate_test_image_from_pdfj(&mut image, pdfj);
    normalize_radare2_function_checked(raw, Some(pdfj), &image, 0, 0)
}

#[cfg(test)]
fn normalize_radare2_function_checked(
    raw: &serde_json::Value,
    pdfj: Option<&serde_json::Value>,
    image: &[u8],
    load_addr: u32,
    region_addr: u32,
) -> Result<serde_json::Value> {
    normalize_radare2_record_checked(&function_record(raw), pdfj, image, load_addr, region_addr)
}

#[cfg(test)]
fn normalize_radare2_record_checked(
    record: &FunctionRecord,
    pdfj: Option<&serde_json::Value>,
    image: &[u8],
    load_addr: u32,
    region_addr: u32,
) -> Result<serde_json::Value> {
    normalize_radare2_record_with_budget(
        record,
        pdfj,
        image,
        load_addr,
        region_addr,
        &mut ExecutionBudget::default(),
    )
}

fn normalize_radare2_record_with_budget(
    record: &FunctionRecord,
    pdfj: Option<&serde_json::Value>,
    image: &[u8],
    load_addr: u32,
    region_addr: u32,
    execution_budget: &mut ExecutionBudget,
) -> Result<serde_json::Value> {
    let (mut output, _) = normalize_function_record_checked(
        ThumbProducer::Radare2,
        record,
        pdfj,
        image,
        load_addr,
        region_addr,
        execution_budget,
    )?;
    output["data_refs"] = serde_json::json!(pdfj.map(data_refs_from_pdfj).unwrap_or_default());
    Ok(output)
}

/// Test-only single-record helper: owns the xref index so cases can pass a
/// plain slice of selected pairs.
#[cfg(test)]
fn normalize_rizin_function_checked(
    raw: &serde_json::Value,
    pdfj: Option<&serde_json::Value>,
    xrefs: &[super::rizin::RizinXref],
    image: &[u8],
    load_addr: u32,
    region_addr: u32,
) -> Result<serde_json::Value> {
    normalize_rizin_record_checked(
        &rizin_function_record(raw),
        pdfj,
        &mut RizinXrefIndex::new(xrefs.to_vec()),
        image,
        load_addr,
        region_addr,
    )
}

#[cfg(test)]
fn normalize_rizin_record_checked(
    record: &FunctionRecord,
    pdfj: Option<&serde_json::Value>,
    xrefs: &mut RizinXrefIndex,
    image: &[u8],
    load_addr: u32,
    region_addr: u32,
) -> Result<serde_json::Value> {
    normalize_rizin_record_with_budget(
        record,
        pdfj,
        xrefs,
        image,
        load_addr,
        region_addr,
        &mut ExecutionBudget::default(),
    )
}

#[allow(clippy::too_many_arguments)]
fn normalize_rizin_record_with_budget(
    record: &FunctionRecord,
    pdfj: Option<&serde_json::Value>,
    xrefs: &mut RizinXrefIndex,
    image: &[u8],
    load_addr: u32,
    region_addr: u32,
    execution_budget: &mut ExecutionBudget,
) -> Result<serde_json::Value> {
    let (mut output, projection) = normalize_function_record_checked(
        ThumbProducer::Rizin,
        record,
        pdfj,
        image,
        load_addr,
        region_addr,
        execution_budget,
    )?;
    let data_refs = match &projection {
        ExecutionProjection::Accepted(ranges) => xrefs.refs_for_ranges(ranges),
        ExecutionProjection::Quarantined(_) => Vec::new(),
    };
    output["data_refs"] = serde_json::json!(data_refs);
    Ok(output)
}

fn normalize_function_record_checked(
    producer: ThumbProducer,
    record: &FunctionRecord,
    pdfj: Option<&serde_json::Value>,
    image: &[u8],
    load_addr: u32,
    region_addr: u32,
    execution_budget: &mut ExecutionBudget,
) -> Result<(serde_json::Value, ExecutionProjection)> {
    let producer_name = producer.as_str();
    let bound_name = match producer {
        ThumbProducer::Radare2 => "maxaddr",
        ThumbProducer::Rizin => "maxbound",
    };
    let entry_u64 = record.entry.ok_or_else(|| {
        Error::Serialize(format!(
            "{producer_name} function lacks entry/addr for Thumb region 0x{region_addr:x}"
        ))
    })?;
    let entry = u32::try_from(entry_u64).map_err(|_| {
        Error::Serialize(format!(
            "{producer_name} function entry is outside the canonical u32 address domain for Thumb region 0x{region_addr:x}"
        ))
    })?;
    let image_end = u64::from(load_addr)
        .checked_add(image.len() as u64)
        .filter(|end| *end <= u64::from(u32::MAX))
        .ok_or_else(|| {
            Error::Serialize(format!(
                "mapped image range is outside the canonical u32 address domain for Thumb region 0x{region_addr:x}"
            ))
        })?;
    if entry_u64 < u64::from(load_addr) || entry_u64 >= image_end {
        return Err(Error::Serialize(format!(
            "{producer_name} function entry is outside mapped image for Thumb region 0x{region_addr:x}"
        )));
    }
    let end_u64 = record.end.ok_or_else(|| {
        Error::Serialize(format!(
            "{producer_name} function lacks valid {bound_name} for Thumb region 0x{region_addr:x}"
        ))
    })?;
    let end = u32::try_from(end_u64).map_err(|_| {
        Error::Serialize(format!(
            "{producer_name} function {bound_name} is outside the canonical u32 address domain for Thumb region 0x{region_addr:x}"
        ))
    })?;
    if end <= entry {
        return Err(Error::Serialize(format!(
            "{producer_name} function {bound_name} must follow entry for Thumb region 0x{region_addr:x}"
        )));
    }
    if end_u64 > image_end {
        return Err(Error::Serialize(format!(
            "{producer_name} function {bound_name} is outside mapped image for Thumb region 0x{region_addr:x}"
        )));
    }
    let size = record.real_size.filter(|size| *size > 0).ok_or_else(|| {
        let diagnostic = record
            .bounding_size
            .map(|size| format!("; diagnostic aflj size is {size}"))
            .unwrap_or_default();
        Error::Serialize(format!(
            "{producer_name} function lacks positive realsz for Thumb region 0x{region_addr:x}{diagnostic}"
        ))
    })?;
    if size > image.len() as u64 {
        return Err(Error::Serialize(format!(
            "{producer_name} function realsz exceeds mapped image length for Thumb region 0x{region_addr:x}"
        )));
    }
    let name = record
        .name
        .clone()
        .unwrap_or_else(|| format!("thumb_{entry_u64:x}"));
    let projection =
        execution_projection_with_budget(entry, pdfj, image, load_addr, execution_budget)?;
    if let ExecutionProjection::Accepted(ranges) = &projection
        && ranges.iter().any(|range| range.end > end)
    {
        return Err(Error::Serialize(format!(
            "{producer_name} function decode range exceeds {bound_name} for Thumb region 0x{region_addr:x}"
        )));
    }
    let body = pdfj.map(operation_body).unwrap_or_default();
    let mut output = serde_json::json!({
        "name": name,
        "entry": json_hex(entry_u64),
        "end": json_hex(end_u64),
        "size": size,
        "body_kind": "thumb_disassembly",
        "body": body,
        "data_refs": [],
    });
    let tags = projection_to_json(&projection)?;
    output
        .as_object_mut()
        .expect("JSON object")
        .extend(tags.as_object().expect("JSON object").clone());
    Ok((output, projection))
}

fn strict_hex_bytes(value: &str) -> Option<Vec<u8>> {
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).ok())
        .collect()
}

#[cfg(test)]
fn execution_projection(
    entry: u32,
    pdfj: Option<&serde_json::Value>,
    image: &[u8],
    load_addr: u32,
) -> Result<ExecutionProjection> {
    execution_projection_with_budget(
        entry,
        pdfj,
        image,
        load_addr,
        &mut ExecutionBudget::default(),
    )
}

fn execution_projection_with_budget(
    entry: u32,
    pdfj: Option<&serde_json::Value>,
    image: &[u8],
    load_addr: u32,
    execution_budget: &mut ExecutionBudget,
) -> Result<ExecutionProjection> {
    let Some(pdfj) = pdfj else {
        execution_budget.charge_function()?;
        return Ok(ExecutionProjection::Quarantined(vec![error(
            DecodeRangeErrorKind::MissingOperationBody,
            entry,
            None,
        )]));
    };
    let Some(ops) = pdfj.get("ops").and_then(serde_json::Value::as_array) else {
        execution_budget.charge_function()?;
        return Ok(ExecutionProjection::Quarantined(vec![error(
            DecodeRangeErrorKind::EmptyProjection,
            entry,
            None,
        )]));
    };
    let mut extents = Vec::new();
    let mut errors = Vec::new();
    for op in ops {
        let address = op
            .get("offset")
            .or_else(|| op.get("addr"))
            .and_then(json_u64)
            .and_then(|address| u32::try_from(address).ok());
        let Some(address) = address else {
            errors.push(error(
                DecodeRangeErrorKind::InvalidOperationAddress,
                entry,
                None,
            ));
            continue;
        };
        let bytes = op
            .get("bytes")
            .and_then(serde_json::Value::as_str)
            .and_then(strict_hex_bytes);
        let Some(bytes) = bytes else {
            errors.push(error(
                DecodeRangeErrorKind::InvalidOperationBytes,
                address,
                None,
            ));
            continue;
        };
        if !matches!(bytes.len(), 2 | 4) {
            errors.push(error(
                DecodeRangeErrorKind::InvalidInstructionLength,
                address,
                None,
            ));
            continue;
        }
        let Some(end) = address.checked_add(bytes.len() as u32) else {
            errors.push(error(
                DecodeRangeErrorKind::InvalidOperationAddress,
                address,
                None,
            ));
            continue;
        };
        extents.push(DecodeExtent {
            isa: DecodeIsa::Thumb,
            start: address,
            end,
        });
        let image_end = load_addr.checked_add(image.len() as u32);
        if address < load_addr || image_end.is_none_or(|image_end| end > image_end) {
            errors.push(error(
                DecodeRangeErrorKind::ExtentOutsideImage,
                address,
                Some(end),
            ));
        } else {
            let start = (address - load_addr) as usize;
            if image.get(start..start + bytes.len()) != Some(bytes.as_slice()) {
                errors.push(error(
                    DecodeRangeErrorKind::RawByteMismatch,
                    address,
                    Some(end),
                ));
            }
        }
    }
    match canonicalize_instruction_extents(entry, extents) {
        Ok(extents) if errors.is_empty() => {
            let runtime = RuntimeImage::from_plan(image, load_addr, None)?;
            let identity = validate_execution(entry, extents, &runtime, execution_budget)?;
            Ok(ExecutionProjection::Accepted(identity.decode_ranges))
        }
        Ok(_) => {
            execution_budget.charge_function()?;
            Ok(ExecutionProjection::Quarantined(canonicalize_errors(
                errors,
            )))
        }
        Err(mut canonical_errors) => {
            canonical_errors.extend(errors);
            execution_budget.charge_function()?;
            Ok(ExecutionProjection::Quarantined(canonicalize_errors(
                canonical_errors,
            )))
        }
    }
}

#[cfg(test)]
fn populate_test_image_from_pdfj(image: &mut [u8], pdfj: &serde_json::Value) {
    for op in pdfj
        .get("ops")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(address) = op
            .get("offset")
            .or_else(|| op.get("addr"))
            .and_then(json_u64)
            .and_then(|address| usize::try_from(address).ok())
        else {
            continue;
        };
        let Some(bytes) = op
            .get("bytes")
            .and_then(serde_json::Value::as_str)
            .and_then(strict_hex_bytes)
        else {
            continue;
        };
        if let Some(destination) = image.get_mut(address..address.saturating_add(bytes.len())) {
            destination.copy_from_slice(&bytes);
        }
    }
}

/// Defensive upper bound on a single Thumb analyzer's region stdout. Grounded in
/// production: 02_MAIN's largest dense-Thumb region (`410b0000`, ~20 MiB
/// carved .bin, ~71 k functions) emits ~1.82 GiB of `aflj;pdfj @@f` JSON
/// (~25 KiB/function). 4 GiB is ~2× that peak, with headroom for analyzer-version
/// differences and slightly larger images. Exceeding it indicates genuine
/// analyzer pathology (infinite loop, corrupt input triggering verbose output) —
/// fail-closed rather than OOM the host.
const ANALYZER_STDOUT_CAP_BYTES: usize = 4 * 1024 * 1024 * 1024;
/// Rizin alone gets the measured per-region cutoff; radare2 retains no wall deadline.
const RIZIN_REGION_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Maximum idle time while finalizing an analyzer's stdout pipe after the
/// immediate process exits. This bounds pipe finalization only; it is not an
/// analyzer runtime deadline. New bytes reset this idle window.
const ANALYZER_PIPE_FINALIZATION_IDLE_LIMIT: Duration = Duration::from_secs(1);
/// Absolute stdout-pipe finalization bound after the immediate analyzer exits.
/// Progress cannot extend it. This is deliberately separate from the Rizin
/// analysis deadline and does not impose a runtime deadline on radare2.
const ANALYZER_PIPE_FINALIZATION_ABSOLUTE_LIMIT: Duration = Duration::from_secs(30);

/// Chunk size for `capture_to_cap`. Smaller than the typical Linux pipe
/// buffer (64 KiB since 2.6.11), so size checks fire promptly when r2 emits
/// fast; large enough that per-chunk write overhead is negligible.
const STREAM_CHUNK_BYTES: usize = 8 * 1024;

/// Stream up to `cap` bytes from `reader` to `writer`, hashing each chunk as
/// it is written. Returns the capture identity on EOF. If input would exceed `cap`, returns
/// `Err(io::Error)` with `ErrorKind::Other` and a cap-exceeded message;
/// the caller is responsible for process cleanup (kill, reap, remove
/// partial file).
///
/// Pure I/O — no child-process coupling, no filesystem assumptions. Testable
/// with `Cursor<Vec<u8>>` readers and `Vec<u8>` writers.
#[cfg(test)]
fn capture_to_cap<R: std::io::Read, W: std::io::Write>(
    reader: &mut R,
    writer: &mut W,
    cap: usize,
    sidecar_path: &str,
) -> std::io::Result<CaptureRecord> {
    capture_to_cap_cancellable(reader, writer, cap, sidecar_path, &DrainControl::default())
}

#[derive(Default)]
struct DrainControl {
    cancelled: AtomicBool,
    bytes: AtomicU64,
}

impl DrainControl {
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    fn bytes(&self) -> u64 {
        self.bytes.load(Ordering::Acquire)
    }
}

fn capture_to_cap_cancellable<R: std::io::Read, W: std::io::Write>(
    reader: &mut R,
    writer: &mut W,
    cap: usize,
    sidecar_path: &str,
    control: &DrainControl,
) -> std::io::Result<CaptureRecord> {
    let mut chunk = vec![0u8; STREAM_CHUNK_BYTES];
    let mut written: usize = 0;
    let mut hasher = blake3::Hasher::new();
    loop {
        if control.is_cancelled() {
            return Ok(CaptureRecord {
                path: sidecar_path.to_owned(),
                bytes: written as u64,
                blake3: hasher.finalize().to_hex().to_string(),
            });
        }
        let n = match reader.read(&mut chunk) {
            Ok(n) => n,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(ANALYZER_POLL_INTERVAL);
                continue;
            }
            Err(_) if control.is_cancelled() => {
                return Ok(CaptureRecord {
                    path: sidecar_path.to_owned(),
                    bytes: written as u64,
                    blake3: hasher.finalize().to_hex().to_string(),
                });
            }
            Err(error) => return Err(error),
        };
        if n == 0 {
            return Ok(CaptureRecord {
                path: sidecar_path.to_owned(),
                bytes: written as u64,
                blake3: hasher.finalize().to_hex().to_string(),
            });
        }
        if n > cap - written {
            let allowed = cap - written;
            writer.write_all(&chunk[..allowed])?;
            hasher.update(&chunk[..allowed]);
            return Err(std::io::Error::other(format!(
                "capture_to_cap: input exceeded {cap} bytes"
            )));
        }
        writer.write_all(&chunk[..n])?;
        hasher.update(&chunk[..n]);
        written += n;
        control.bytes.store(written as u64, Ordering::Release);
    }
}

/// Cap on an analyzer's own virtual address space (`RLIMIT_AS`) while it analyzes
/// one Thumb region. Grounded in measurement: healthy radare2 `aaa` on the densest real
/// regions peaks ~1.5 GiB RSS (mustang `02_MAIN`'s 19 MiB region) and completes,
/// while a pathological region — cheetah `01_MAIN`'s `0x42310000`, only 4 MiB —
/// runs away to 90+ GiB and OOM-kills the host. 16 GiB is ~10x the measured
/// healthy peak (ample headroom for larger images) yet far below the host RAM
/// needed for the rest of a full decompose anyway (Ghidra's JVM et al.; a
/// decompose peaked ~56 GiB back when r2 output was buffered whole — that
/// producer is streaming now), so a
/// runaway region hits the limit and fails closed (r2 gets `ENOMEM` and exits)
/// rather than exhausting host memory. Same "fail-closed rather than OOM the host"
/// intent as [`ANALYZER_STDOUT_CAP_BYTES`], but for the analyzer's own memory rather than the
/// stdout we read back from it.
#[cfg(unix)]
const ANALYZER_ADDRESS_SPACE_CAP_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// Put the analyzer in its own process group and apply
/// [`ANALYZER_ADDRESS_SPACE_CAP_BYTES`] as a soft+hard `RLIMIT_AS`. Unix-only;
/// other platforms have no shared portable equivalents.
#[cfg(unix)]
fn configure_analyzer_process(cmd: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: the closure runs in the forked child between `fork(2)` and
    // `execvp(2)`. It calls only async-signal-safe libc functions, reads a
    // `const`, touches no shared state, and allocates nothing.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let limit = libc::rlimit {
                rlim_cur: ANALYZER_ADDRESS_SPACE_CAP_BYTES as libc::rlim_t,
                rlim_max: ANALYZER_ADDRESS_SPACE_CAP_BYTES as libc::rlim_t,
            };
            if libc::setrlimit(libc::RLIMIT_AS, &limit) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
}

#[cfg(not(unix))]
fn configure_analyzer_process(_cmd: &mut std::process::Command) {}

#[cfg(unix)]
fn make_analyzer_pipe_cancellable(pipe: &std::process::ChildStdout) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;

    let descriptor = pipe.as_raw_fd();
    // SAFETY: the descriptor is borrowed from a live child pipe. These calls
    // retain no pointers and only add O_NONBLOCK to its file-status flags.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags == -1 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(unix))]
fn make_analyzer_pipe_cancellable(_pipe: &std::process::ChildStdout) -> std::io::Result<()> {
    Ok(())
}

const ANALYZER_POLL_INTERVAL: Duration = Duration::from_millis(5);
/// Bound proof that the immediate analyzer child has completed after termination.
const ANALYZER_CHILD_COMPLETION_LIMIT: Duration = Duration::from_secs(1);
/// Give a waiting shell time to reap its terminated descendants before SIGKILL.
#[cfg(unix)]
const ANALYZER_TERMINATION_GRACE: Duration = Duration::from_millis(100);
/// Bound the post-SIGKILL proof that no process remains in the analyzer group.
#[cfg(unix)]
const ANALYZER_GROUP_ABSENCE_VERIFICATION_LIMIT: Duration = Duration::from_secs(1);
/// Bound forced stdout-drain cancellation. Without it the declared pipe
/// finalization limits would only bound when cancellation starts.
const ANALYZER_DRAIN_CANCELLATION_LIMIT: Duration = Duration::from_secs(5);

#[cfg(all(test, unix))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UnixCleanupEvent {
    ExitObserved,
    Signal(libc::c_int),
    Reap,
}

#[derive(Clone, Copy)]
struct CleanupPolicy {
    child_completion_limit: Duration,
    #[cfg(unix)]
    group_absence_verification_limit: Duration,
    #[cfg(test)]
    inject_verification_failure: bool,
    #[cfg(all(test, unix))]
    events: Option<&'static std::sync::Mutex<Vec<UnixCleanupEvent>>>,
}

impl CleanupPolicy {
    const PRODUCTION: Self = Self {
        child_completion_limit: ANALYZER_CHILD_COMPLETION_LIMIT,
        #[cfg(unix)]
        group_absence_verification_limit: ANALYZER_GROUP_ABSENCE_VERIFICATION_LIMIT,
        #[cfg(test)]
        inject_verification_failure: false,
        #[cfg(all(test, unix))]
        events: None,
    };

    #[cfg(all(test, unix))]
    fn record(self, event: UnixCleanupEvent) {
        if let Some(events) = self.events {
            events.lock().unwrap().push(event);
        }
    }
}

struct AnalyzerProcess {
    child: std::process::Child,
    #[cfg(unix)]
    pid: u32,
    #[cfg(unix)]
    exit_observed: bool,
    #[cfg(unix)]
    reap_attempted: bool,
    status: Option<std::process::ExitStatus>,
    drain: Option<std::thread::JoinHandle<std::io::Result<CaptureRecord>>>,
    drain_control: Arc<DrainControl>,
}

impl AnalyzerProcess {
    fn new(child: std::process::Child, drain_control: Arc<DrainControl>) -> Self {
        #[cfg(unix)]
        let pid = child.id();
        Self {
            child,
            #[cfg(unix)]
            pid,
            #[cfg(unix)]
            exit_observed: false,
            #[cfg(unix)]
            reap_attempted: false,
            status: None,
            drain: None,
            drain_control,
        }
    }

    fn exit_observed(&self) -> bool {
        #[cfg(unix)]
        return self.exit_observed;
        #[cfg(not(unix))]
        return self.status.is_some();
    }

    #[cfg(unix)]
    fn observe_exit(&mut self, policy: CleanupPolicy) -> std::io::Result<bool> {
        #[cfg(not(test))]
        let _ = policy;
        if self.exit_observed {
            return Ok(true);
        }
        loop {
            // SAFETY: siginfo_t is a C output buffer; zeroing also satisfies
            // POSIX's WNOHANG requirement that si_pid start at zero.
            let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
            // WNOWAIT is the identity invariant: the exited leader remains a
            // waitable zombie, so its numeric PID/PGID cannot be reused before
            // every process-group cleanup signal has been sent.
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.pid as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if result == 0 {
                // SAFETY: successful waitid(WEXITED) initialized the SIGCHLD
                // payload, including si_pid (or left the zero sentinel).
                let observed_pid = unsafe { info.si_pid() };
                if observed_pid == 0 {
                    return Ok(false);
                }
                if observed_pid != self.pid as libc::pid_t {
                    return Err(std::io::Error::other(format!(
                        "waitid observed pid {observed_pid} instead of analyzer pid {}",
                        self.pid
                    )));
                }
                self.exit_observed = true;
                #[cfg(test)]
                policy.record(UnixCleanupEvent::ExitObserved);
                return Ok(true);
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    #[cfg(not(unix))]
    fn observe_exit(&mut self, policy: CleanupPolicy) -> std::io::Result<bool> {
        let _ = policy;
        if self.status.is_some() {
            return Ok(true);
        }
        if let Some(status) = self.child.try_wait()? {
            self.status = Some(status);
            return Ok(true);
        }
        Ok(false)
    }

    fn drain_finished(&self) -> bool {
        self.drain
            .as_ref()
            .is_some_and(std::thread::JoinHandle::is_finished)
    }

    fn join_drain(&mut self) -> std::io::Result<CaptureRecord> {
        self.drain
            .take()
            .ok_or_else(|| {
                std::io::Error::other("analyzer stdout drain was detached before joining")
            })?
            .join()
            .map_err(|_| std::io::Error::other("analyzer stdout drain thread panicked"))?
    }

    fn drain_bytes(&self) -> u64 {
        self.drain_control.bytes()
    }

    #[cfg(unix)]
    fn observe_exit_within(&mut self, policy: CleanupPolicy) -> std::io::Result<()> {
        let started = std::time::Instant::now();
        loop {
            if self.observe_exit(policy)? {
                return Ok(());
            }
            if started.elapsed() >= policy.child_completion_limit {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "analyzer child exit was not observed before the cleanup deadline",
                ));
            }
            std::thread::sleep(ANALYZER_POLL_INTERVAL);
        }
    }

    #[cfg(unix)]
    fn reap_observed_child(&mut self, policy: CleanupPolicy) -> std::io::Result<()> {
        #[cfg(not(test))]
        let _ = policy;
        if self.status.is_some() {
            return Ok(());
        }
        if self.reap_attempted {
            return Err(std::io::Error::other(
                "analyzer child reap was already attempted",
            ));
        }
        if !self.exit_observed {
            return Err(std::io::Error::other(
                "analyzer child cannot be reaped before exit is observed",
            ));
        }
        self.reap_attempted = true;
        #[cfg(test)]
        policy.record(UnixCleanupEvent::Reap);
        self.status = Some(self.child.wait()?);
        Ok(())
    }

    #[cfg(unix)]
    fn signal_process_group(
        &self,
        signal: libc::c_int,
        policy: CleanupPolicy,
    ) -> std::io::Result<()> {
        if self.reap_attempted {
            return Err(std::io::Error::other(
                "refusing to signal an analyzer process group after reap",
            ));
        }
        signal_analyzer_process_group(self.pid, signal, policy)
    }

    #[cfg(unix)]
    fn kill_child(&mut self, policy: CleanupPolicy) -> std::io::Result<()> {
        if self.reap_attempted {
            return Err(std::io::Error::other(
                "refusing to signal an analyzer child after reap",
            ));
        }
        #[cfg(test)]
        policy.record(UnixCleanupEvent::Signal(libc::SIGKILL));
        #[cfg(not(test))]
        let _ = policy;
        self.child.kill()
    }

    #[cfg(unix)]
    fn process_group_exists_after_reap(&self, policy: CleanupPolicy) -> std::io::Result<bool> {
        if self.status.is_none() {
            return Err(std::io::Error::other(
                "refusing to verify analyzer process-group absence before reap",
            ));
        }
        analyzer_process_group_exists(self.pid, policy)
    }

    #[cfg(not(unix))]
    fn reap_child_within(&mut self, policy: CleanupPolicy) -> std::io::Result<()> {
        let started = std::time::Instant::now();
        loop {
            if self.observe_exit(policy)? {
                return Ok(());
            }
            if started.elapsed() >= policy.child_completion_limit {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "analyzer child did not exit and reap before the cleanup deadline",
                ));
            }
            std::thread::sleep(ANALYZER_POLL_INTERVAL);
        }
    }

    #[cfg(windows)]
    fn interrupt_drain(&self) -> std::io::Result<()> {
        use std::os::windows::io::AsRawHandle;

        let Some(drain) = &self.drain else {
            return Ok(());
        };
        // SAFETY: `drain` owns a live Windows thread handle. Repeated
        // cancellation covers the race where no synchronous read is
        // pending during one call.
        let cancelled = unsafe {
            windows_sys::Win32::System::IO::CancelSynchronousIo(
                drain.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE
            )
        };
        if cancelled != 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        // No synchronous read was pending, so the shared flag alone stops the
        // reader on its next poll. Every other failure is real and reportable.
        if error.raw_os_error() == Some(windows_sys::Win32::Foundation::ERROR_NOT_FOUND as i32) {
            Ok(())
        } else {
            Err(error)
        }
    }

    #[cfg(not(windows))]
    fn interrupt_drain(&self) -> std::io::Result<()> {
        Ok(())
    }

    #[cfg(unix)]
    fn terminate_and_reap(&mut self, policy: CleanupPolicy) -> std::io::Result<()> {
        let mut first_error = None;
        if self.status.is_none() && self.reap_attempted {
            return Err(std::io::Error::other(
                "analyzer child reap was attempted but no exit status is available",
            ));
        }

        if self.status.is_none() {
            let already_observed = self.observe_exit(policy).map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!("could not observe analyzer child before cleanup: {error}"),
                )
            })?;
            let mut identity_stable = true;
            if already_observed {
                if let Err(error) = self.signal_process_group(libc::SIGKILL, policy) {
                    preserve_cleanup_error(
                        &mut first_error,
                        "could not send SIGKILL to exited analyzer process group",
                        error,
                    );
                }
            } else {
                if let Err(error) = self.signal_process_group(libc::SIGTERM, policy) {
                    preserve_cleanup_error(
                        &mut first_error,
                        "could not send SIGTERM to analyzer process group",
                        error,
                    );
                }
                let grace_started = std::time::Instant::now();
                while grace_started.elapsed() < ANALYZER_TERMINATION_GRACE {
                    match self.observe_exit(policy) {
                        Ok(true) => break,
                        Ok(false) => std::thread::sleep(ANALYZER_POLL_INTERVAL),
                        Err(error) => {
                            preserve_cleanup_error(
                                &mut first_error,
                                "could not observe analyzer child during termination grace",
                                error,
                            );
                            identity_stable = false;
                            break;
                        }
                    }
                }
                if identity_stable
                    && let Err(error) = self.signal_process_group(libc::SIGKILL, policy)
                {
                    preserve_cleanup_error(
                        &mut first_error,
                        "could not send SIGKILL to analyzer process group",
                        error,
                    );
                }
                if identity_stable
                    && !self.exit_observed
                    && let Err(error) = self.kill_child(policy)
                    && error.kind() != std::io::ErrorKind::InvalidInput
                {
                    preserve_cleanup_error(
                        &mut first_error,
                        "could not kill analyzer child during cleanup",
                        error,
                    );
                }
            }

            if identity_stable
                && !self.exit_observed
                && let Err(error) = self.observe_exit_within(policy)
            {
                preserve_cleanup_error(
                    &mut first_error,
                    "could not observe analyzer child exit during cleanup",
                    error,
                );
                identity_stable = false;
            }
            if identity_stable && let Err(error) = self.reap_observed_child(policy) {
                preserve_cleanup_error(
                    &mut first_error,
                    "could not reap analyzer child during cleanup",
                    error,
                );
            }
        }

        let mut group_absent = false;
        if self.status.is_some() {
            let verification_started = std::time::Instant::now();
            let mut last_verification_error;
            loop {
                last_verification_error = match self.process_group_exists_after_reap(policy) {
                    Ok(false) => {
                        group_absent = true;
                        break;
                    }
                    Ok(true) => None,
                    Err(error) => Some(error),
                };
                if verification_started.elapsed() >= policy.group_absence_verification_limit {
                    let detail = last_verification_error.map_or_else(
                        || "analyzer process group still exists".to_owned(),
                        |error| format!("analyzer process-group state is unknown: {error}"),
                    );
                    preserve_cleanup_error(
                        &mut first_error,
                        "could not verify analyzer process-group absence",
                        std::io::Error::new(std::io::ErrorKind::TimedOut, detail),
                    );
                    break;
                }
                std::thread::sleep(ANALYZER_POLL_INTERVAL);
            }
        }

        if self.status.is_none() {
            preserve_cleanup_error(
                &mut first_error,
                "analyzer child was not reaped",
                std::io::Error::other("child status remains unknown after cleanup"),
            );
        }
        if !group_absent && first_error.is_none() {
            first_error = Some(std::io::Error::other(
                "analyzer process-group absence was not verified",
            ));
        }
        #[cfg(test)]
        if policy.inject_verification_failure {
            preserve_cleanup_error(
                &mut first_error,
                "could not verify analyzer process-group absence",
                std::io::Error::other("injected cleanup verification failure"),
            );
        }

        first_error.map_or(Ok(()), Err)
    }

    #[cfg(not(unix))]
    fn terminate_and_reap(&mut self, policy: CleanupPolicy) -> std::io::Result<()> {
        let mut first_error = None;
        if self.status.is_none() {
            if let Err(error) = self.child.kill()
                && error.kind() != std::io::ErrorKind::InvalidInput
            {
                preserve_cleanup_error(
                    &mut first_error,
                    "could not kill analyzer child during cleanup",
                    error,
                );
            }
            if let Err(error) = self.reap_child_within(policy) {
                preserve_cleanup_error(
                    &mut first_error,
                    "could not reap analyzer child during cleanup",
                    error,
                );
            }
        }
        if self.status.is_none() {
            preserve_cleanup_error(
                &mut first_error,
                "analyzer child was not reaped",
                std::io::Error::other("child status remains unknown after cleanup"),
            );
        }
        #[cfg(test)]
        if policy.inject_verification_failure {
            preserve_cleanup_error(
                &mut first_error,
                "could not verify analyzer child cleanup",
                std::io::Error::other("injected cleanup verification failure"),
            );
        }
        first_error.map_or(Ok(()), Err)
    }

    /// Cancel the stdout drain and wait for its reader within `limit`. A reader
    /// that never observes cancellation is detached and reported: joining it
    /// would block the request forever, and its capture file must then never be
    /// treated as finalized.
    fn cancel_drain_and_wait(&mut self, limit: Duration) -> std::io::Result<()> {
        self.drain_control.cancel();
        let started = std::time::Instant::now();
        let mut first_error = None;
        while self
            .drain
            .as_ref()
            .is_some_and(|drain| !drain.is_finished())
        {
            if let Err(error) = self.interrupt_drain() {
                preserve_cleanup_error(
                    &mut first_error,
                    "could not interrupt the analyzer stdout drain",
                    error,
                );
            }
            if started.elapsed() >= limit {
                self.drain = None;
                preserve_cleanup_error(
                    &mut first_error,
                    "could not stop the analyzer stdout drain",
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "the reader did not observe cancellation before the deadline",
                    ),
                );
                break;
            }
            std::thread::sleep(ANALYZER_POLL_INTERVAL);
        }
        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for AnalyzerProcess {
    fn drop(&mut self) {
        #[cfg(unix)]
        let needs_process_cleanup = self.status.is_none() && !self.reap_attempted;
        #[cfg(not(unix))]
        let needs_process_cleanup = self.status.is_none();
        if needs_process_cleanup {
            let _ = self.terminate_and_reap(CleanupPolicy::PRODUCTION);
        }
        if self.drain.is_some() {
            // Drop cannot propagate; the supervisor's own call is what makes an
            // unstoppable drain terminal for the request.
            if let Err(error) = self.cancel_drain_and_wait(ANALYZER_DRAIN_CANCELLATION_LIMIT) {
                tracing::error!("analyzer stdout drain could not be stopped: {error}");
            }
            let _ = self.join_drain();
        }
    }
}

fn preserve_cleanup_error(
    first_error: &mut Option<std::io::Error>,
    context: &str,
    error: std::io::Error,
) {
    if first_error.is_none() {
        *first_error = Some(std::io::Error::new(
            error.kind(),
            format!("{context}: {error}"),
        ));
    }
}

#[cfg(unix)]
fn signal_analyzer_process_group(
    pid: u32,
    signal: libc::c_int,
    policy: CleanupPolicy,
) -> std::io::Result<()> {
    #[cfg(test)]
    policy.record(UnixCleanupEvent::Signal(signal));
    #[cfg(not(test))]
    let _ = policy;
    signal_process_group(pid, signal)
}

#[cfg(unix)]
fn analyzer_process_group_exists(pid: u32, policy: CleanupPolicy) -> std::io::Result<bool> {
    #[cfg(test)]
    policy.record(UnixCleanupEvent::Signal(0));
    #[cfg(not(test))]
    let _ = policy;
    process_group_exists(pid)
}

#[cfg(unix)]
fn signal_process_group(pid: u32, signal: libc::c_int) -> std::io::Result<()> {
    let pid = libc::pid_t::try_from(pid)
        .map_err(|_| std::io::Error::other("analyzer pid exceeds the Unix pid_t domain"))?;
    // SAFETY: a negative pid addresses the child-owned process group and no
    // Rust-managed memory is accessed.
    if unsafe { libc::kill(-pid, signal) } == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(error)
    }
}

#[cfg(unix)]
fn process_group_exists(pid: u32) -> std::io::Result<bool> {
    let pid = libc::pid_t::try_from(pid)
        .map_err(|_| std::io::Error::other("analyzer pid exceeds the Unix pid_t domain"))?;
    // SAFETY: signal 0 only checks the child-owned process group's existence.
    if unsafe { libc::kill(-pid, 0) } == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(false)
    } else {
        Err(error)
    }
}

fn validate_thumb_region_requests(
    image: &[u8],
    load_addr: u32,
    regions: &[(u32, u32)],
) -> Result<Vec<(u32, u32)>> {
    let image_len = u32::try_from(image.len()).map_err(|_| {
        Error::Serialize("Thumb mapped image length exceeds the canonical u32 domain".into())
    })?;
    let image_end = load_addr.checked_add(image_len).ok_or_else(|| {
        Error::Serialize("Thumb mapped image range overflows the canonical u32 domain".into())
    })?;
    let mut validated = Vec::<(u32, u32)>::with_capacity(regions.len());

    for &(start, len) in regions {
        if len == 0 {
            return Err(Error::Serialize(format!(
                "Thumb region 0x{start:x} has zero length"
            )));
        }
        let end = start.checked_add(len).ok_or_else(|| {
            Error::Serialize(format!(
                "Thumb region 0x{start:x} length 0x{len:x} overflows the u32 address space"
            ))
        })?;
        if start < load_addr || end > image_end {
            return Err(Error::Serialize(format!(
                "Thumb region 0x{start:x}..0x{end:x} is outside image 0x{load_addr:x}..0x{image_end:x}"
            )));
        }
        if let Some(&(previous_start, previous_end)) = validated.last() {
            if start < previous_start {
                return Err(Error::Serialize(format!(
                    "Thumb region requests are not sorted: 0x{start:x} follows 0x{previous_start:x}"
                )));
            }
            if start < previous_end {
                return Err(Error::Serialize(format!(
                    "Thumb region requests overlap: 0x{start:x} starts before 0x{previous_end:x}"
                )));
            }
        }
        validated.push((start, end));
    }

    Ok(validated)
}

fn validate_thumb_tools(tools: &ThumbTools) -> Result<()> {
    validate_producer_identity(&tools.radare2, ThumbProducer::Radare2)?;
    if let Some(rizin) = &tools.rizin {
        validate_producer_identity(rizin, ThumbProducer::Rizin)?;
    }
    Ok(())
}

/// The coordinator will spawn these identities and v3 will record them as the
/// executables actually used, so they are checked in runtime-native mode.
fn validate_producer_identity(identity: &ProducerIdentity, expected: ThumbProducer) -> Result<()> {
    match super::identity::producer_identity_error(
        identity,
        expected,
        super::identity::IdentityMode::Runtime,
    ) {
        Some(reason) => Err(Error::Serialize(reason)),
        None => Ok(()),
    }
}

fn add_count(total: &mut usize, value: usize, label: &str) -> Result<()> {
    *total = total
        .checked_add(value)
        .ok_or_else(|| Error::Serialize(format!("Thumb {label} count overflow")))?;
    Ok(())
}

#[derive(Clone, Copy)]
struct RunnerLimits {
    stdout_cap: usize,
    rizin_timeout: Duration,
    pipe_finalization_idle: Duration,
    pipe_finalization_absolute: Duration,
    drain_cancellation: Duration,
    cleanup: CleanupPolicy,
}

impl RunnerLimits {
    const PRODUCTION: Self = Self {
        stdout_cap: ANALYZER_STDOUT_CAP_BYTES,
        rizin_timeout: RIZIN_REGION_TIMEOUT,
        pipe_finalization_idle: ANALYZER_PIPE_FINALIZATION_IDLE_LIMIT,
        pipe_finalization_absolute: ANALYZER_PIPE_FINALIZATION_ABSOLUTE_LIMIT,
        drain_cancellation: ANALYZER_DRAIN_CANCELLATION_LIMIT,
        cleanup: CleanupPolicy::PRODUCTION,
    };
}

#[derive(Default)]
struct PendingSpills(Vec<Spill>);

impl PendingSpills {
    fn push(&mut self, spill: Spill) {
        self.0.push(spill);
    }

    fn as_slice(&self) -> &[Spill] {
        &self.0
    }
}

impl Drop for PendingSpills {
    fn drop(&mut self) {
        for spill in &self.0 {
            let _ = std::fs::remove_file(&spill.path);
        }
    }
}

/// Analyze validated dense-Thumb regions with radare2 primary and an optional
/// per-region Rizin fallback. Per-region failures remain durable when another
/// region succeeds; an all-region failure leaves any prior sidecar untouched.
pub fn run_thumb_analysis(
    tools: &ThumbTools,
    image: &[u8],
    load_addr: u32,
    regions: &[(u32, u32)],
    out_dir: &Path,
) -> Result<ThumbAnalysisSummary> {
    run_thumb_analysis_with_limits(
        tools,
        image,
        load_addr,
        regions,
        out_dir,
        RunnerLimits::PRODUCTION,
    )
}

fn run_thumb_analysis_with_limits(
    tools: &ThumbTools,
    image: &[u8],
    load_addr: u32,
    regions: &[(u32, u32)],
    out_dir: &Path,
    limits: RunnerLimits,
) -> Result<ThumbAnalysisSummary> {
    let mut carver = carve_thumb_region;
    run_thumb_analysis_with_limits_and_carver(
        tools,
        image,
        load_addr,
        regions,
        out_dir,
        limits,
        &mut carver,
    )
}

type RegionCarver<'a> = dyn FnMut(&[u8], u32, u32, u32, &Path) -> Result<std::path::PathBuf> + 'a;

fn run_thumb_analysis_with_limits_and_carver(
    tools: &ThumbTools,
    image: &[u8],
    load_addr: u32,
    regions: &[(u32, u32)],
    out_dir: &Path,
    limits: RunnerLimits,
    carve_region: &mut RegionCarver<'_>,
) -> Result<ThumbAnalysisSummary> {
    if regions.is_empty() {
        return Ok(ThumbAnalysisSummary::default());
    }
    validate_thumb_tools(tools)?;
    let regions = validate_thumb_region_requests(image, load_addr, regions)?;
    let mut summary = ThumbAnalysisSummary {
        regions_requested: regions.len(),
        ..ThumbAnalysisSummary::default()
    };
    let thumb_dir = out_dir.join("thumb");
    std::fs::create_dir_all(&thumb_dir)?;
    let mut spills = PendingSpills::default();
    let mut region_records = Vec::with_capacity(regions.len());
    let mut failures: Vec<(u32, Vec<String>)> = Vec::new();
    let mut rizin_attempted = false;

    for &(addr, end) in &regions {
        let len = end - addr;
        let bin = carve_region(image, load_addr, addr, len, &thumb_dir)?;
        let mut attempts = Vec::with_capacity(usize::from(tools.rizin.is_some()) + 1);
        let mut region_failures = Vec::with_capacity(attempts.capacity());
        let mut selected = None;

        for identity in std::iter::once(&tools.radare2).chain(tools.rizin.iter()) {
            if identity.producer == ThumbProducer::Rizin {
                rizin_attempted = true;
            }
            match run_backend_region(identity, &bin, image, load_addr, addr, &thumb_dir, limits) {
                Ok(success) => {
                    attempts.push(AttemptRecord {
                        producer: identity.producer,
                        status: AttemptStatus::Succeeded,
                        stdout: Some(success.capture),
                        error: None,
                    });
                    selected = Some((identity.producer, success.outcome));
                    break;
                }
                Err(failure) => {
                    let reason = failure.error.to_string();
                    if failure.terminal {
                        tracing::error!(
                            "Thumb region 0x{addr:x} {} left unverified state; aborting analysis: {reason}",
                            identity.producer.as_str()
                        );
                        return Err(failure.error);
                    }
                    tracing::warn!(
                        "Thumb region 0x{addr:x} {} attempt failed (fail-closed): {reason}",
                        identity.producer.as_str()
                    );
                    attempts.push(AttemptRecord {
                        producer: identity.producer,
                        status: AttemptStatus::Failed,
                        stdout: failure.capture,
                        error: Some(reason.clone()),
                    });
                    region_failures.push(reason);
                }
            }
        }

        if let Some((producer, outcome)) = selected {
            let RegionOutcome { spill, stats } = outcome;
            spills.push(spill);
            let quarantined = stats.raw.checked_sub(stats.accepted).ok_or_else(|| {
                Error::Serialize(format!(
                    "{} Thumb projection count is not conserving for region 0x{addr:x}",
                    producer.as_str()
                ))
            })?;
            let run = FunctionRunRecord {
                producer,
                first_function: summary.raw,
                function_count: stats.raw,
                substantial: stats.substantial,
                accepted: stats.accepted,
                quarantined,
            };
            add_count(&mut summary.regions_succeeded, 1, "succeeded region")?;
            match producer {
                ThumbProducer::Radare2 => add_count(&mut summary.radare2_runs, 1, "radare2 run")?,
                ThumbProducer::Rizin => add_count(&mut summary.rizin_runs, 1, "rizin run")?,
            }
            add_count(&mut summary.raw, stats.raw, "raw function")?;
            add_count(
                &mut summary.substantial,
                stats.substantial,
                "substantial function",
            )?;
            add_count(&mut summary.accepted, stats.accepted, "accepted function")?;
            add_count(
                &mut summary.quarantined,
                quarantined,
                "quarantined function",
            )?;
            region_records.push(RegionRecord {
                start: addr,
                end,
                attempts,
                function_runs: vec![run],
            });
        } else {
            add_count(&mut summary.regions_failed, 1, "failed region")?;
            failures.push((addr, region_failures));
            region_records.push(RegionRecord {
                start: addr,
                end,
                attempts,
                function_runs: Vec::new(),
            });
        }
    }

    if summary
        .regions_succeeded
        .checked_add(summary.regions_failed)
        != Some(summary.regions_requested)
        || summary.accepted.checked_add(summary.quarantined) != Some(summary.raw)
        || summary.radare2_runs.checked_add(summary.rizin_runs) != Some(summary.regions_succeeded)
        || summary.raw.checked_sub(summary.substantial).is_none()
    {
        return Err(Error::Serialize(
            "Thumb analysis summary is not conserving".into(),
        ));
    }
    if summary.regions_succeeded == 0 {
        let reasons = failures
            .iter()
            .map(|(addr, reasons)| format!("0x{addr:x}: {}", reasons.join("; ")))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(Error::Serialize(format!(
            "Thumb analysis failed for every requested region: {reasons}"
        )));
    }

    let mut attempted_producers = vec![tools.radare2.clone()];
    if rizin_attempted {
        attempted_producers.push(
            tools
                .rizin
                .clone()
                .expect("Rizin can be attempted only when configured"),
        );
    }
    assemble_v3_atomic(
        &out_dir.join("thumb_functions.json"),
        &attempted_producers,
        &region_records,
        spills.as_slice(),
    )?;
    Ok(summary)
}

fn carve_thumb_region(
    image: &[u8],
    load_addr: u32,
    addr: u32,
    len: u32,
    thumb_dir: &Path,
) -> Result<std::path::PathBuf> {
    let off = (addr - load_addr) as usize;
    let end = off + len as usize;
    let bin = thumb_dir.join(format!("{addr:08x}.bin"));
    std::fs::write(&bin, &image[off..end]).map_err(|error| {
        Error::Serialize(format!(
            "carve Thumb region 0x{addr:x} to {}: {error}",
            bin.display()
        ))
    })?;
    Ok(bin)
}

type RegionParser = fn(&Path, &[u8], u32, u32, &Path) -> Result<RegionOutcome>;

fn backend_fragment_path(
    thumb_dir: &Path,
    addr: u32,
    producer: ThumbProducer,
) -> std::path::PathBuf {
    thumb_dir.join(format!("{addr:08x}.{}.frags", producer.as_str()))
}

/// Remove output a failed or superseded attempt must not leave behind. An
/// absent path is the success case; every other error means unverified bytes
/// remain beside the sidecar, which is terminal for the whole request.
fn remove_stale_output(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn run_backend_region(
    identity: &ProducerIdentity,
    bin: &Path,
    image: &[u8],
    load_addr: u32,
    addr: u32,
    thumb_dir: &Path,
    limits: RunnerLimits,
) -> std::result::Result<SuccessfulRegion, FailedRegion> {
    let producer = identity.producer;
    let producer_name = producer.as_str();
    let stdout_path = thumb_dir.join(format!("{addr:08x}.{producer_name}.stdout"));
    let parser: RegionParser = match producer {
        ThumbProducer::Radare2 => process_region_streaming,
        ThumbProducer::Rizin => process_rizin_region_streaming,
    };
    let fragment_path = backend_fragment_path(thumb_dir, addr, producer);
    if let Err(error) = remove_stale_output(&fragment_path) {
        return Err(FailedRegion::setup(Error::Serialize(format!(
            "{producer_name} could not remove stale fragments for Thumb region 0x{addr:x}: {error}"
        ))));
    }
    let result = match run_backend_capture(identity, bin, addr, &stdout_path, limits) {
        Ok(capture) => match parser(&stdout_path, image, load_addr, addr, thumb_dir) {
            Ok(outcome) => Ok(SuccessfulRegion { outcome, capture }),
            Err(error) => Err(FailedRegion::recoverable(
                Some(capture),
                Error::Serialize(format!(
                    "{producer_name} output validation failed for Thumb region 0x{addr:x}: {error}"
                )),
            )),
        },
        Err(failure) => Err(failure),
    };
    match result {
        Ok(success) => Ok(success),
        Err(mut failure) => {
            if let Err(error) = remove_stale_output(&fragment_path) {
                failure.mark_terminal(&format!("{producer_name} fragment cleanup failed"), error);
            }
            Err(failure)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RunningObservation {
    Complete,
    BeginStdoutFinalization,
    DeadlineExpired,
    Pending,
}

enum SupervisionState {
    Running,
    FinalizingStdout {
        started: std::time::Instant,
        last_progress: std::time::Instant,
        observed_bytes: u64,
    },
}

fn supervision_sleep(
    state: &SupervisionState,
    runtime_elapsed: Duration,
    deadline: Option<Duration>,
    limits: RunnerLimits,
) -> Duration {
    match state {
        SupervisionState::Running => deadline
            .map(|deadline| ANALYZER_POLL_INTERVAL.min(deadline.saturating_sub(runtime_elapsed)))
            .unwrap_or(ANALYZER_POLL_INTERVAL),
        SupervisionState::FinalizingStdout {
            started,
            last_progress,
            ..
        } => ANALYZER_POLL_INTERVAL
            .min(
                limits
                    .pipe_finalization_idle
                    .saturating_sub(last_progress.elapsed()),
            )
            .min(
                limits
                    .pipe_finalization_absolute
                    .saturating_sub(started.elapsed()),
            ),
    }
}

fn classify_running_observation(
    exit_observed: bool,
    capture_complete: bool,
    deadline_expired: bool,
) -> RunningObservation {
    if deadline_expired {
        RunningObservation::DeadlineExpired
    } else if exit_observed && capture_complete {
        RunningObservation::Complete
    } else if exit_observed {
        RunningObservation::BeginStdoutFinalization
    } else {
        RunningObservation::Pending
    }
}

fn analyzer_status_failure_detail(
    process: &AnalyzerProcess,
    producer: ThumbProducer,
    addr: u32,
) -> Option<String> {
    let status = process.status.as_ref()?;
    if status.success() {
        return None;
    }
    match check_thumb_backend_status(producer, false, status.code(), addr)
        .expect_err("non-successful analyzer status must fail")
    {
        Error::Serialize(detail) => Some(detail),
        _ => unreachable!("backend status failures are serialization errors"),
    }
}

fn finalize_natural_analyzer_capture(
    process: &mut AnalyzerProcess,
    capture: CaptureRecord,
    producer: ThumbProducer,
    addr: u32,
    policy: CleanupPolicy,
) -> std::result::Result<CaptureRecord, FailedRegion> {
    let cleanup = process.terminate_and_reap(policy);
    if let Some(detail) = analyzer_status_failure_detail(process, producer, addr) {
        return Err(FailedRegion::after_cleanup(
            Some(capture),
            Error::Serialize(detail),
            "process cleanup failed",
            cleanup,
        ));
    }
    match cleanup {
        Ok(()) if process.status.is_some() => Ok(capture),
        Ok(()) => {
            let mut failure = FailedRegion::recoverable(
                Some(capture),
                Error::Serialize(format!(
                    "{} cleanup did not yield an exit status for Thumb region 0x{addr:x}",
                    producer.as_str()
                )),
            );
            failure.mark_terminal(
                "process cleanup failed",
                std::io::Error::other("analyzer child status is unavailable after cleanup"),
            );
            Err(failure)
        }
        Err(error) => {
            let mut failure = FailedRegion::recoverable(
                Some(capture),
                Error::Serialize(format!(
                    "{} process cleanup failed after stdout completion for Thumb region 0x{addr:x}",
                    producer.as_str()
                )),
            );
            failure.mark_terminal("process cleanup failed", error);
            Err(failure)
        }
    }
}

fn run_backend_capture(
    identity: &ProducerIdentity,
    bin: &Path,
    addr: u32,
    stdout_path: &Path,
    limits: RunnerLimits,
) -> std::result::Result<CaptureRecord, FailedRegion> {
    let producer = identity.producer;
    let producer_name = producer.as_str();
    let started = std::time::Instant::now();
    let mut cmd = std::process::Command::new(&identity.executable);
    cmd.args(["-a", "arm", "-b", "16", "-m"])
        .arg(format!("0x{addr:x}"))
        .args(["-q", "-c", identity.command])
        .arg(bin)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped());
    configure_analyzer_process(&mut cmd);
    let mut child = cmd.spawn().map_err(|error| {
        FailedRegion::recoverable(
            None,
            Error::Serialize(format!(
                "{producer_name} failed to spawn for Thumb region 0x{addr:x}: {error}"
            )),
        )
    })?;
    let stdout = child.stdout.take().expect("piped stdout");
    supervise_spawned_analyzer(child, stdout, producer, addr, stdout_path, started, limits)
}

fn supervise_spawned_analyzer(
    child: std::process::Child,
    stdout: std::process::ChildStdout,
    producer: ThumbProducer,
    addr: u32,
    stdout_path: &Path,
    started: std::time::Instant,
    limits: RunnerLimits,
) -> std::result::Result<CaptureRecord, FailedRegion> {
    let producer_name = producer.as_str();
    let stdout_cap = limits.stdout_cap;
    let deadline = (producer == ThumbProducer::Rizin).then_some(limits.rizin_timeout);
    let drain_control = Arc::new(DrainControl::default());
    let mut process = AnalyzerProcess::new(child, Arc::clone(&drain_control));
    if let Err(error) = make_analyzer_pipe_cancellable(&stdout) {
        let cleanup = process.terminate_and_reap(limits.cleanup);
        return Err(FailedRegion::after_cleanup(
            None,
            Error::Serialize(format!(
                "{producer_name} could not configure cancellable stdout for Thumb region 0x{addr:x}: {error}"
            )),
            "process cleanup failed",
            cleanup,
        ));
    }
    let file = match std::fs::File::create(stdout_path) {
        Ok(file) => file,
        Err(error) => {
            let cleanup = process.terminate_and_reap(limits.cleanup);
            return Err(FailedRegion::after_cleanup(
                None,
                Error::Serialize(format!(
                    "{producer_name} could not create stdout capture for Thumb region 0x{addr:x}: {error}"
                )),
                "process cleanup failed",
                cleanup,
            ));
        }
    };
    let sidecar_path = format!("thumb/{addr:08x}.{producer_name}.stdout");
    let drain = std::thread::Builder::new()
        .name(format!("thumb-{producer_name}-{addr:08x}-stdout"))
        .spawn(move || {
            let mut stdout = stdout;
            let mut file = file;
            let capture = capture_to_cap_cancellable(
                &mut stdout,
                &mut file,
                stdout_cap,
                &sidecar_path,
                &drain_control,
            )?;
            file.flush()?;
            Ok(capture)
        });
    process.drain = match drain {
        Ok(drain) => Some(drain),
        Err(error) => {
            let removed = remove_stale_output(stdout_path);
            let cleanup = process.terminate_and_reap(limits.cleanup);
            let mut failure = FailedRegion::after_cleanup(
                None,
                Error::Serialize(format!(
                    "{producer_name} could not start stdout capture for Thumb region 0x{addr:x}: {error}"
                )),
                "process cleanup failed",
                cleanup,
            );
            if let Err(error) = removed {
                failure.mark_terminal("unstarted stdout capture cleanup failed", error);
            }
            return Err(failure);
        }
    };

    let mut capture = None;
    let mut state = SupervisionState::Running;
    loop {
        let now = std::time::Instant::now();
        if let SupervisionState::FinalizingStdout {
            started,
            last_progress,
            observed_bytes,
        } = &mut state
        {
            let bytes = process.drain_bytes();
            if bytes != *observed_bytes {
                *observed_bytes = bytes;
                *last_progress = now;
            }
            let finalization_limit =
                if now.duration_since(*started) >= limits.pipe_finalization_absolute {
                    Some(("absolute", limits.pipe_finalization_absolute))
                } else if now.duration_since(*last_progress) >= limits.pipe_finalization_idle {
                    Some(("idle", limits.pipe_finalization_idle))
                } else {
                    None
                };
            if let Some((limit_name, limit)) = finalization_limit {
                let cleanup = process.terminate_and_reap(limits.cleanup);
                let stopped = stop_and_finalize_capture(
                    &mut process,
                    capture.take(),
                    stdout_path,
                    limits.drain_cancellation,
                );
                let forced = format!(
                    "stdout remained open after analyzer exit for Thumb region 0x{addr:x}; forced pipe finalization after the {} ms {limit_name} limit",
                    limit.as_millis()
                );
                let detail = analyzer_status_failure_detail(&process, producer, addr)
                    .map(|mut detail| {
                        detail.push_str(&format!("; {forced}"));
                        detail
                    })
                    .unwrap_or_else(|| format!("{producer_name} {forced}"));
                return Err(stopped.into_failure(detail, cleanup));
            }
        }

        if capture.is_none() && process.drain_finished() {
            match process.join_drain() {
                Ok(finalized) => capture = Some(finalized),
                Err(error) => {
                    let cleanup = process.terminate_and_reap(limits.cleanup);
                    let removed = remove_stale_output(stdout_path);
                    let mut failure = FailedRegion::after_cleanup(
                        None,
                        capture_failure_error(producer, addr, stdout_cap, error),
                        "process cleanup failed",
                        cleanup,
                    );
                    if let Err(error) = removed {
                        failure.mark_terminal("unfinalized stdout capture cleanup failed", error);
                    }
                    return Err(failure);
                }
            }
        }

        match &mut state {
            SupervisionState::Running => {
                if let Err(error) = process.observe_exit(limits.cleanup) {
                    let cleanup = process.terminate_and_reap(limits.cleanup);
                    let stopped = stop_and_finalize_capture(
                        &mut process,
                        capture.take(),
                        stdout_path,
                        limits.drain_cancellation,
                    );
                    let detail = format!(
                        "{producer_name} process supervision failed for Thumb region 0x{addr:x}: {error}"
                    );
                    return Err(stopped.into_failure(detail, cleanup));
                }

                match classify_running_observation(
                    process.exit_observed(),
                    capture.is_some(),
                    deadline.is_some_and(|deadline| started.elapsed() >= deadline),
                ) {
                    RunningObservation::Complete | RunningObservation::BeginStdoutFinalization => {
                        if let Some(finalized) = capture.take() {
                            capture = Some(finalize_natural_analyzer_capture(
                                &mut process,
                                finalized,
                                producer,
                                addr,
                                limits.cleanup,
                            )?);
                            break;
                        }
                        let now = std::time::Instant::now();
                        state = SupervisionState::FinalizingStdout {
                            started: now,
                            last_progress: now,
                            observed_bytes: process.drain_bytes(),
                        };
                        continue;
                    }
                    RunningObservation::DeadlineExpired => {
                        let cleanup = process.terminate_and_reap(limits.cleanup);
                        let stopped = stop_and_finalize_capture(
                            &mut process,
                            capture.take(),
                            stdout_path,
                            limits.drain_cancellation,
                        );
                        let detail = format!(
                            "{producer_name} timed out after {} ms for Thumb region 0x{addr:x}",
                            deadline.expect("elapsed deadline is present").as_millis()
                        );
                        return Err(stopped.into_failure(detail, cleanup));
                    }
                    RunningObservation::Pending => {}
                }
            }
            SupervisionState::FinalizingStdout { .. } => {
                if let Some(finalized) = capture.take() {
                    capture = Some(finalize_natural_analyzer_capture(
                        &mut process,
                        finalized,
                        producer,
                        addr,
                        limits.cleanup,
                    )?);
                    break;
                }
            }
        }

        let sleep = supervision_sleep(&state, started.elapsed(), deadline, limits);
        if !sleep.is_zero() {
            std::thread::sleep(sleep);
        }
    }

    let capture = capture.expect("completed analyzer capture is finalized");
    let success = process
        .status
        .as_ref()
        .map(std::process::ExitStatus::success)
        .expect("completed analyzer process is reaped");
    debug_assert!(success, "failed analyzer status escaped supervision");

    Ok(capture)
}

/// What became of a capture whose analyzer was stopped rather than finishing
/// naturally. The design permits recording `stdout: null` for a partial file
/// that could not be finalized, but only once that file is provably gone.
struct StoppedCapture {
    retained: Option<CaptureRecord>,
    /// The drain could not be joined, so the partial file was removed and the
    /// attempt truthfully records `stdout: null`. An ordinary failure.
    finalize_error: Option<std::io::Error>,
    /// The capture's final state is unverified: the reader that owns it would
    /// not stop, or the partial file could not be removed. Terminal for the
    /// whole request.
    terminal_error: Option<std::io::Error>,
}

impl StoppedCapture {
    /// Fold the drain and removal outcomes into the attempt failure `detail`
    /// describes, plus the process cleanup result.
    fn into_failure(self, mut detail: String, cleanup: std::io::Result<()>) -> FailedRegion {
        if let Some(error) = &self.finalize_error {
            detail.push_str(&format!("; partial stdout finalization failed: {error}"));
        }
        let mut failure = FailedRegion::after_cleanup(
            self.retained,
            Error::Serialize(detail),
            "cleanup failed",
            cleanup,
        );
        if let Some(error) = self.terminal_error {
            failure.mark_terminal("partial stdout capture state is unverified", error);
        }
        failure
    }
}

/// Stop the stdout drain, then finalize or remove whatever partial capture it
/// produced.
fn stop_and_finalize_capture(
    process: &mut AnalyzerProcess,
    capture: Option<CaptureRecord>,
    stdout_path: &Path,
    drain_cancellation: Duration,
) -> StoppedCapture {
    // The reader owns the capture file, so a reader that will not stop leaves
    // the file's final state unverified exactly like a failed removal.
    let mut terminal_error = process.cancel_drain_and_wait(drain_cancellation).err();
    let (retained, finalize_error) = if let Some(capture) = capture {
        (Some(capture), None)
    } else {
        match process.join_drain() {
            Ok(capture) => (Some(capture), None),
            Err(error) => {
                if let Err(cleanup) = remove_stale_output(stdout_path) {
                    terminal_error.get_or_insert(cleanup);
                }
                (None, Some(error))
            }
        }
    };
    StoppedCapture {
        retained,
        finalize_error,
        terminal_error,
    }
}

fn capture_failure_error(
    producer: ThumbProducer,
    addr: u32,
    cap: usize,
    error: std::io::Error,
) -> Error {
    let producer = producer.as_str();
    if error.kind() == std::io::ErrorKind::Other
        && error
            .to_string()
            .starts_with("capture_to_cap: input exceeded")
    {
        Error::Serialize(format!(
            "{producer} emitted more than {cap} stdout bytes for Thumb region 0x{addr:x}; capped to prevent OOM"
        ))
    } else {
        Error::Serialize(format!(
            "{producer} stdout capture failed for Thumb region 0x{addr:x}: {error}"
        ))
    }
}

#[cfg(test)]
fn test_radare2_identity(path: &Path) -> Result<ProducerIdentity> {
    Ok(ProducerIdentity {
        producer: ThumbProducer::Radare2,
        executable: std::fs::canonicalize(path)?,
        version: "radare2 test".into(),
        command: ThumbProducer::Radare2.command(),
    })
}

#[cfg(test)]
fn run_radare2_region(
    radare2: &Path,
    image: &[u8],
    load_addr: u32,
    addr: u32,
    len: u32,
    thumb_dir: &Path,
) -> Result<Option<RegionOutcome>> {
    let bin = carve_thumb_region(image, load_addr, addr, len, thumb_dir)?;
    match run_backend_region(
        &test_radare2_identity(radare2)?,
        &bin,
        image,
        load_addr,
        addr,
        thumb_dir,
        RunnerLimits::PRODUCTION,
    ) {
        Ok(success) => Ok(Some(success.outcome)),
        Err(failure) => Err(failure.error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn thumb_tools(radare2: &Path) -> crate::thumb_analysis::ThumbTools {
        crate::thumb_analysis::ThumbTools {
            radare2: test_identity(crate::thumb_analysis::ThumbProducer::Radare2, radare2),
            rizin: None,
        }
    }

    #[cfg(unix)]
    fn test_identity(
        producer: crate::thumb_analysis::ThumbProducer,
        executable: &Path,
    ) -> crate::thumb_analysis::ProducerIdentity {
        crate::thumb_analysis::ProducerIdentity {
            producer,
            executable: std::fs::canonicalize(executable).unwrap(),
            version: format!("{} test 1.0", producer.as_str()),
            command: producer.command(),
        }
    }

    #[cfg(unix)]
    fn make_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions).unwrap();
    }

    #[cfg(unix)]
    fn write_executable_stub(path: &Path, body: &str) {
        std::fs::write(path, body).unwrap();
        make_executable(path);
    }

    #[cfg(unix)]
    #[test]
    fn run_thumb_analysis_emits_partial_v3_with_contiguous_runs_and_conserved_summary() {
        let dir = tempfile::tempdir().unwrap();
        let radare2 = dir.path().join("r2");
        std::fs::write(
            &radare2,
            r#"#!/bin/sh
case " $* " in
  *" -m 0x4000 "*)
    printf '%s\n' '[{"name":"sym.first","addr":16384,"size":4096,"realsz":32,"maxaddr":16386},{"name":"sym.quarantined","addr":16416,"size":64,"realsz":2,"maxaddr":16418}]' '{"addr":16384,"ops":[{"addr":16384,"bytes":"7047","disasm":"bx lr"}]}'
    ;;
  *" -m 0x4040 "*)
    printf 'failed capture\n'
    exit 7
    ;;
  *" -m 0x4080 "*)
    printf '%s\n' '[{"name":"sym.last","addr":16512,"size":128,"realsz":2,"maxaddr":16514}]' '{"addr":16512,"ops":[{"addr":16512,"bytes":"7047","disasm":"bx lr"}]}'
    ;;
  *) exit 98 ;;
esac
"#,
        )
        .unwrap();
        make_executable(&radare2);
        let mut image = vec![0u8; 0xc0];
        image[0..2].copy_from_slice(&[0x70, 0x47]);
        image[0x80..0x82].copy_from_slice(&[0x70, 0x47]);
        let out = dir.path().join("out");

        let summary = crate::thumb_analysis::run_thumb_analysis(
            &thumb_tools(&radare2),
            &image,
            0x4000,
            &[(0x4000, 0x40), (0x4040, 0x40), (0x4080, 0x40)],
            &out,
        )
        .unwrap();

        assert_eq!(
            summary,
            crate::thumb_analysis::ThumbAnalysisSummary {
                regions_requested: 3,
                regions_succeeded: 2,
                regions_failed: 1,
                radare2_runs: 2,
                rizin_runs: 0,
                raw: 3,
                substantial: 1,
                accepted: 2,
                quarantined: 1,
            }
        );
        let bytes = std::fs::read(out.join("thumb_functions.json")).unwrap();
        let runtime = RuntimeImage::from_plan(&image, 0x4000, None).unwrap();
        crate::thumb_analysis::parse_thumb_artifact(&bytes, &runtime).unwrap();
        let artifact: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(artifact["format"], crate::thumb_analysis::THUMB_V3_FORMAT);
        assert_eq!(artifact["producers"].as_array().unwrap().len(), 1);
        assert_eq!(artifact["regions"].as_array().unwrap().len(), 3);
        assert_eq!(
            artifact["regions"][0]["function_runs"][0]["first_function"],
            0
        );
        assert_eq!(
            artifact["regions"][0]["function_runs"][0]["function_count"],
            2
        );
        assert!(
            artifact["regions"][1]["function_runs"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            artifact["regions"][2]["function_runs"][0]["first_function"],
            2
        );
        assert_eq!(artifact["regions"][1]["attempts"][0]["status"], "failed");
        let capture = &artifact["regions"][1]["attempts"][0]["stdout"];
        assert_eq!(capture["path"], "thumb/00004040.radare2.stdout");
        let retained = std::fs::read(out.join(capture["path"].as_str().unwrap())).unwrap();
        assert_eq!(capture["bytes"], retained.len() as u64);
        assert_eq!(capture["blake3"], blake3::hash(&retained).to_hex().as_str());
        assert!(!out.join("thumb/00004000.stdout").exists());
    }

    #[cfg(unix)]
    #[test]
    fn successful_radare2_region_never_spawns_rizin() {
        let dir = tempfile::tempdir().unwrap();
        let radare2 = dir.path().join("r2");
        let rizin = dir.path().join("rizin");
        let sentinel = dir.path().join("rizin-ran");
        write_executable_stub(
            &radare2,
            "#!/bin/sh\nprintf '%s\\n' '[{\"addr\":16384,\"name\":\"fcn.4000\",\"size\":2,\"realsz\":2,\"minaddr\":16384,\"maxaddr\":16386}]' '{\"addr\":16384,\"ops\":[{\"addr\":16384,\"bytes\":\"7047\",\"disasm\":\"bx lr\"}]}'\n",
        );
        write_executable_stub(
            &rizin,
            &format!("#!/bin/sh\ntouch '{}'\nexit 99\n", sentinel.display()),
        );
        let mut tools = thumb_tools(&radare2);
        tools.rizin = Some(test_identity(
            crate::thumb_analysis::ThumbProducer::Rizin,
            &rizin,
        ));
        let out = dir.path().join("out");

        let summary =
            run_thumb_analysis(&tools, &[0x70, 0x47], 0x4000, &[(0x4000, 2)], &out).unwrap();

        assert_eq!(summary.radare2_runs, 1);
        assert_eq!(summary.rizin_runs, 0);
        assert!(!sentinel.exists());
    }

    #[cfg(unix)]
    #[test]
    fn failed_radare2_region_falls_back_to_rizin_when_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let radare2 = dir.path().join("r2");
        let rizin = dir.path().join("rizin");
        write_executable_stub(&radare2, "#!/bin/sh\nexit 1\n");
        write_executable_stub(
            &rizin,
            "#!/bin/sh\nprintf '%s\\n' '[{\"offset\":16384,\"name\":\"fcn.4000\",\"size\":2,\"realsz\":2,\"minbound\":16384,\"maxbound\":16386}]' '{\"addr\":16384,\"ops\":[{\"offset\":16384,\"bytes\":\"7047\",\"disasm\":\"bx lr\"}]}' '[{\"from\":16384,\"to\":20480,\"type\":\"DATA\"}]'\n",
        );
        let mut tools = thumb_tools(&radare2);
        tools.rizin = Some(test_identity(
            crate::thumb_analysis::ThumbProducer::Rizin,
            &rizin,
        ));

        let summary =
            run_thumb_analysis(&tools, &[0x70, 0x47], 0x4000, &[(0x4000, 2)], dir.path()).unwrap();

        assert_eq!(summary.radare2_runs, 0);
        assert_eq!(summary.rizin_runs, 1);
        let image = [0x70, 0x47];
        let runtime = RuntimeImage::from_plan(&image, 0x4000, None).unwrap();
        let artifact = crate::thumb_analysis::read_thumb_artifact(
            &dir.path().join("thumb_functions.json"),
            &runtime,
        )
        .unwrap();
        let function = artifact.functions().next().unwrap();
        assert_eq!(
            function.owner.analysis_tool(),
            crate::analysis_tool::AnalysisTool::Rizin
        );
        assert_eq!(function.value["data_refs"], json!(["0x5000"]));
    }

    #[cfg(unix)]
    #[test]
    fn radare2_pairing_failure_triggers_exactly_one_rizin_attempt() {
        let dir = tempfile::tempdir().unwrap();
        let radare2 = dir.path().join("r2");
        let rizin = dir.path().join("rizin");
        let rizin_invocations = dir.path().join("rizin-invocations");
        write_executable_stub(
            &radare2,
            "#!/bin/sh\nprintf '%s\\n' '[{\"addr\":16384,\"name\":\"fcn.4000\",\"size\":2,\"realsz\":2,\"maxaddr\":16386}]'\n",
        );
        write_executable_stub(
            &rizin,
            &format!(
                "#!/bin/sh\nprintf 'invoked\\n' >> '{}'\nprintf '%s\\n' '[{{\"offset\":16384,\"name\":\"fcn.4000\",\"size\":2,\"realsz\":2,\"maxbound\":16386}}]' '{{\"addr\":16384,\"ops\":[{{\"offset\":16384,\"bytes\":\"7047\",\"disasm\":\"bx lr\"}}]}}' '[]'\n",
                rizin_invocations.display()
            ),
        );
        let mut tools = thumb_tools(&radare2);
        tools.rizin = Some(test_identity(
            crate::thumb_analysis::ThumbProducer::Rizin,
            &rizin,
        ));

        let summary =
            run_thumb_analysis(&tools, &[0x70, 0x47], 0x4000, &[(0x4000, 2)], dir.path()).unwrap();

        assert_eq!(summary.radare2_runs, 0);
        assert_eq!(summary.rizin_runs, 1);
        assert_eq!(
            std::fs::read_to_string(rizin_invocations)
                .unwrap()
                .lines()
                .count(),
            1
        );
        let document: serde_json::Value = serde_json::from_slice(
            &std::fs::read(dir.path().join("thumb_functions.json")).unwrap(),
        )
        .unwrap();
        assert!(
            document["regions"][0]["attempts"][0]["error"]
                .as_str()
                .unwrap()
                .contains("zero paired pdfj bodies")
        );
        assert_eq!(document["regions"][0]["attempts"][1]["status"], "succeeded");
    }

    /// Schema drift that emits objects without an `ops` array must fail the
    /// Rizin attempt instead of pairing empty bodies, quarantining every
    /// function, and publishing an all-quarantined "successful" run.
    #[cfg(unix)]
    #[test]
    fn rizin_pdfj_bodies_without_an_ops_array_fail_the_attempt() {
        for (case, body) in [
            ("empty object", "{}"),
            ("missing ops", "{\"addr\":16384}"),
            ("non-array ops", "{\"addr\":16384,\"ops\":7}"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let radare2 = dir.path().join("r2");
            let rizin = dir.path().join("rizin");
            write_executable_stub(&radare2, "#!/bin/sh\nexit 1\n");
            write_executable_stub(
                &rizin,
                &[
                    "#!/bin/sh\nprintf '%s\\n' ",
                    "'[{\"offset\":16384,\"name\":\"fcn.4000\",\"size\":2,\"realsz\":2,\"maxbound\":16386}]' ",
                    "'", body, "' '[]'\n",
                ]
                .concat(),
            );
            let mut tools = thumb_tools(&radare2);
            tools.rizin = Some(test_identity(
                crate::thumb_analysis::ThumbProducer::Rizin,
                &rizin,
            ));

            let error =
                run_thumb_analysis(&tools, &[0x70, 0x47], 0x4000, &[(0x4000, 2)], dir.path())
                    .unwrap_err();

            assert!(error.to_string().contains("ops"), "{case}: {error}");
            assert!(
                !dir.path().join("thumb_functions.json").exists(),
                "{case} published a sidecar"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn mixed_regions_have_contiguous_backend_runs() {
        let dir = tempfile::tempdir().unwrap();
        let radare2 = dir.path().join("r2");
        let rizin = dir.path().join("rizin");
        write_executable_stub(
            &radare2,
            r#"#!/bin/sh
case " $* " in
  *" -m 0x4000 "*)
    printf '%s\n' '[{"addr":16384,"name":"r2.accepted","size":2,"realsz":32,"maxaddr":16386},{"addr":16416,"name":"r2.quarantined","size":2,"realsz":2,"maxaddr":16418}]' '{"addr":16384,"ops":[{"addr":16384,"bytes":"7047","disasm":"bx lr"}]}'
    ;;
  *" -m 0x4040 "*) exit 5 ;;
  *) exit 98 ;;
esac
"#,
        );
        write_executable_stub(
            &rizin,
            "#!/bin/sh\nprintf '%s\\n' '[{\"offset\":16448,\"name\":\"rizin.accepted\",\"size\":2,\"realsz\":2,\"maxbound\":16450}]' '{\"addr\":16448,\"ops\":[{\"offset\":16448,\"bytes\":\"00bf\",\"disasm\":\"nop\"}]}' '[{\"from\":16448,\"to\":20480,\"type\":\"DATA\"}]'\n",
        );
        let mut tools = thumb_tools(&radare2);
        tools.rizin = Some(test_identity(
            crate::thumb_analysis::ThumbProducer::Rizin,
            &rizin,
        ));
        let mut image = vec![0u8; 0x80];
        image[..2].copy_from_slice(&[0x70, 0x47]);
        image[0x40..0x42].copy_from_slice(&[0x00, 0xbf]);

        let summary = run_thumb_analysis(
            &tools,
            &image,
            0x4000,
            &[(0x4000, 0x40), (0x4040, 0x40)],
            dir.path(),
        )
        .unwrap();

        assert_eq!(
            summary,
            crate::thumb_analysis::ThumbAnalysisSummary {
                regions_requested: 2,
                regions_succeeded: 2,
                regions_failed: 0,
                radare2_runs: 1,
                rizin_runs: 1,
                raw: 3,
                substantial: 1,
                accepted: 2,
                quarantined: 1,
            }
        );
        let bytes = std::fs::read(dir.path().join("thumb_functions.json")).unwrap();
        let runtime = RuntimeImage::from_plan(&image, 0x4000, None).unwrap();
        let artifact = crate::thumb_analysis::parse_thumb_artifact(&bytes, &runtime).unwrap();
        let owned = artifact
            .functions()
            .map(|function| {
                (
                    function.owner.analysis_tool(),
                    function.value["name"].as_str().unwrap().to_owned(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            owned,
            vec![
                (
                    crate::analysis_tool::AnalysisTool::Radare2,
                    "r2.accepted".to_string()
                ),
                (
                    crate::analysis_tool::AnalysisTool::Radare2,
                    "r2.quarantined".to_string()
                ),
                (
                    crate::analysis_tool::AnalysisTool::Rizin,
                    "rizin.accepted".to_string()
                ),
            ]
        );
        let document: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            document["regions"][0]["function_runs"][0]["first_function"],
            0
        );
        assert_eq!(
            document["regions"][0]["function_runs"][0]["function_count"],
            2
        );
        assert_eq!(
            document["regions"][1]["function_runs"][0]["first_function"],
            2
        );
        assert_eq!(
            document["regions"][1]["function_runs"][0]["function_count"],
            1
        );
        assert_eq!(document["regions"][1]["attempts"][0]["status"], "failed");
        assert_eq!(document["regions"][1]["attempts"][1]["status"], "succeeded");
        assert_eq!(document["functions"][2]["data_refs"], json!(["0x5000"]));
        assert!(dir.path().join("thumb/00004000.radare2.stdout").exists());
        assert!(dir.path().join("thumb/00004040.radare2.stdout").exists());
        assert!(dir.path().join("thumb/00004040.rizin.stdout").exists());
        assert!(!dir.path().join("thumb/00004000.rizin.stdout").exists());
        assert!(
            std::fs::read_dir(dir.path().join("thumb"))
                .unwrap()
                .all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".frags"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn all_quarantined_radare2_run_does_not_trigger_quality_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let radare2 = dir.path().join("r2");
        let rizin = dir.path().join("rizin");
        let sentinel = dir.path().join("rizin-ran");
        write_executable_stub(
            &radare2,
            "#!/bin/sh\nprintf '%s\\n' '[{\"addr\":16384,\"name\":\"r2.quarantined\",\"size\":2,\"realsz\":2,\"maxaddr\":16386}]' '{\"addr\":16384,\"ops\":[{\"addr\":16384,\"bytes\":\"zz\",\"disasm\":\"invalid\"}]}'\n",
        );
        write_executable_stub(
            &rizin,
            &format!("#!/bin/sh\ntouch '{}'\nexit 99\n", sentinel.display()),
        );
        let mut tools = thumb_tools(&radare2);
        tools.rizin = Some(test_identity(
            crate::thumb_analysis::ThumbProducer::Rizin,
            &rizin,
        ));

        let summary =
            run_thumb_analysis(&tools, &[0x70, 0x47], 0x4000, &[(0x4000, 2)], dir.path()).unwrap();

        assert_eq!(summary.radare2_runs, 1);
        assert_eq!(summary.rizin_runs, 0);
        assert_eq!(summary.raw, 1);
        assert_eq!(summary.accepted, 0);
        assert_eq!(summary.quarantined, 1);
        assert!(!sentinel.exists());
    }

    #[cfg(unix)]
    #[test]
    fn failed_radare2_region_does_not_spawn_rizin_when_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let radare2 = dir.path().join("r2");
        let rizin = dir.path().join("rizin");
        let sentinel = dir.path().join("rizin-ran");
        write_executable_stub(&radare2, "#!/bin/sh\nexit 1\n");
        write_executable_stub(
            &rizin,
            &format!("#!/bin/sh\ntouch '{}'\nexit 99\n", sentinel.display()),
        );

        let error = run_thumb_analysis(
            &thumb_tools(&radare2),
            &[0x70, 0x47],
            0x4000,
            &[(0x4000, 2)],
            dir.path(),
        )
        .unwrap_err();

        let message = error.to_string();
        assert!(message.contains("Thumb analysis failed for every requested region"));
        assert!(message.contains("radare2 exited with status 1"));
        assert!(!message.contains("rizin"));
        assert!(!sentinel.exists());
    }

    #[cfg(unix)]
    #[test]
    fn configured_fallback_both_fail_preserves_sidecar_and_orders_attempt_errors() {
        let dir = tempfile::tempdir().unwrap();
        let radare2 = dir.path().join("r2");
        let rizin = dir.path().join("rizin");
        write_executable_stub(
            &radare2,
            "#!/bin/sh\nprintf 'radare2 failed: %s\\n' \"$*\"\nexit 3\n",
        );
        write_executable_stub(
            &rizin,
            "#!/bin/sh\nprintf 'rizin failed: %s\\n' \"$*\"\nexit 4\n",
        );
        let mut tools = thumb_tools(&radare2);
        tools.rizin = Some(test_identity(
            crate::thumb_analysis::ThumbProducer::Rizin,
            &rizin,
        ));
        let sidecar = dir.path().join("thumb_functions.json");
        let original = b"pre-existing sidecar bytes\n";
        std::fs::write(&sidecar, original).unwrap();

        let error = run_thumb_analysis(
            &tools,
            &[0u8; 0x80],
            0x4000,
            &[(0x4000, 0x20), (0x4040, 0x20)],
            dir.path(),
        )
        .unwrap_err();

        let message = error.to_string();
        let first_region = message.find("0x4000:").unwrap();
        let first_radare2 = message[first_region..]
            .find("radare2 exited with status 3")
            .map(|index| first_region + index)
            .unwrap();
        let first_rizin = message[first_region..]
            .find("rizin exited with status 4")
            .map(|index| first_region + index)
            .unwrap();
        let second_region = message.find("0x4040:").unwrap();
        let second_radare2 = message[second_region..]
            .find("radare2 exited with status 3")
            .map(|index| second_region + index)
            .unwrap();
        let second_rizin = message[second_region..]
            .find("rizin exited with status 4")
            .map(|index| second_region + index)
            .unwrap();
        assert!(
            first_region < first_radare2
                && first_radare2 < first_rizin
                && first_rizin < second_region
                && second_region < second_radare2
                && second_radare2 < second_rizin
        );
        assert_eq!(std::fs::read(sidecar).unwrap(), original);
        for addr in [0x4000u32, 0x4040] {
            let radare2_capture = dir.path().join(format!("thumb/{addr:08x}.radare2.stdout"));
            let rizin_capture = dir.path().join(format!("thumb/{addr:08x}.rizin.stdout"));
            assert!(radare2_capture.exists());
            assert!(rizin_capture.exists());
            assert!(
                std::fs::read_to_string(radare2_capture)
                    .unwrap()
                    .starts_with("radare2 failed:")
            );
            assert!(
                std::fs::read_to_string(rizin_capture)
                    .unwrap()
                    .starts_with("rizin failed:")
            );
        }
        assert!(
            std::fs::read_dir(dir.path().join("thumb"))
                .unwrap()
                .all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".frags"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn fallback_uses_exact_argv_canonical_identities_and_one_shared_carve() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let real_radare2 = dir.path().join("real-r2");
        let real_rizin = dir.path().join("real-rizin");
        let radare2_alias = dir.path().join("r2");
        let rizin_alias = dir.path().join("rizin");
        let radare2_argv = dir.path().join("radare2.argv");
        let rizin_argv = dir.path().join("rizin.argv");
        let radare2_executable = dir.path().join("radare2.executable");
        let rizin_executable = dir.path().join("rizin.executable");
        let radare2_bin_path = dir.path().join("radare2.bin-path");
        let rizin_bin_path = dir.path().join("rizin.bin-path");
        let radare2_bytes = dir.path().join("radare2.bin-bytes");
        let rizin_bytes = dir.path().join("rizin.bin-bytes");
        let radare2_limit = dir.path().join("radare2.limit");
        let rizin_limit = dir.path().join("rizin.limit");
        write_executable_stub(
            &real_radare2,
            &format!(
                "#!/bin/sh\n\
                 printf '%s\\n' \"$0\" > '{}'\n\
                 printf '%s\\n' \"$@\" > '{}'\n\
                 ulimit -v > '{}'\n\
                 for arg in \"$@\"; do last=$arg; done\n\
                 printf '%s\\n' \"$last\" > '{}'\n\
                 cp \"$last\" '{}'\n\
                 exit 6\n",
                radare2_executable.display(),
                radare2_argv.display(),
                radare2_limit.display(),
                radare2_bin_path.display(),
                radare2_bytes.display(),
            ),
        );
        write_executable_stub(
            &real_rizin,
            &format!(
                "#!/bin/sh\n\
                 printf '%s\\n' \"$0\" > '{}'\n\
                 printf '%s\\n' \"$@\" > '{}'\n\
                 ulimit -v > '{}'\n\
                 for arg in \"$@\"; do last=$arg; done\n\
                 printf '%s\\n' \"$last\" > '{}'\n\
                 cp \"$last\" '{}'\n\
                 printf '%s\\n' '[{{\"offset\":16672,\"name\":\"rizin.shared\",\"size\":2,\"realsz\":2,\"maxbound\":16674}}]' '{{\"addr\":16672,\"ops\":[{{\"offset\":16672,\"bytes\":\"7047\",\"disasm\":\"bx lr\"}}]}}' '[]'\n",
                rizin_executable.display(),
                rizin_argv.display(),
                rizin_limit.display(),
                rizin_bin_path.display(),
                rizin_bytes.display(),
            ),
        );
        symlink(&real_radare2, &radare2_alias).unwrap();
        symlink(&real_rizin, &rizin_alias).unwrap();
        let tools = crate::thumb_analysis::ThumbTools {
            radare2: test_identity(
                crate::thumb_analysis::ThumbProducer::Radare2,
                &radare2_alias,
            ),
            rizin: Some(test_identity(
                crate::thumb_analysis::ThumbProducer::Rizin,
                &rizin_alias,
            )),
        };
        let mut image = vec![0u8; 0x200];
        image[0x120..0x124].copy_from_slice(&[0x70, 0x47, 0xaa, 0x55]);

        let mut carve_calls = 0usize;
        let mut carver = |image: &[u8], load_addr, addr, len, thumb_dir: &Path| {
            carve_calls += 1;
            carve_thumb_region(image, load_addr, addr, len, thumb_dir)
        };
        let summary = run_thumb_analysis_with_limits_and_carver(
            &tools,
            &image,
            0x4000,
            &[(0x4120, 4)],
            dir.path(),
            RunnerLimits::PRODUCTION,
            &mut carver,
        )
        .unwrap();

        assert_eq!(carve_calls, 1, "fallback must not rewrite the shared carve");
        assert_eq!(summary.radare2_runs, 0);
        assert_eq!(summary.rizin_runs, 1);
        let carved = dir.path().join("thumb/00004120.bin");
        let expected_radare2 = vec![
            "-a".to_string(),
            "arm".to_string(),
            "-b".to_string(),
            "16".to_string(),
            "-m".to_string(),
            "0x4120".to_string(),
            "-q".to_string(),
            "-c".to_string(),
            crate::thumb_analysis::ThumbProducer::Radare2
                .command()
                .to_string(),
            carved.display().to_string(),
        ];
        let expected_rizin = vec![
            "-a".to_string(),
            "arm".to_string(),
            "-b".to_string(),
            "16".to_string(),
            "-m".to_string(),
            "0x4120".to_string(),
            "-q".to_string(),
            "-c".to_string(),
            crate::thumb_analysis::ThumbProducer::Rizin
                .command()
                .to_string(),
            carved.display().to_string(),
        ];
        assert_eq!(
            std::fs::read_to_string(radare2_argv)
                .unwrap()
                .lines()
                .map(str::to_owned)
                .collect::<Vec<_>>(),
            expected_radare2
        );
        assert_eq!(
            std::fs::read_to_string(rizin_argv)
                .unwrap()
                .lines()
                .map(str::to_owned)
                .collect::<Vec<_>>(),
            expected_rizin
        );
        assert_eq!(
            std::fs::read_to_string(radare2_executable).unwrap().trim(),
            std::fs::canonicalize(&real_radare2)
                .unwrap()
                .to_str()
                .unwrap()
        );
        assert_eq!(
            std::fs::read_to_string(rizin_executable).unwrap().trim(),
            std::fs::canonicalize(&real_rizin)
                .unwrap()
                .to_str()
                .unwrap()
        );
        assert_eq!(
            std::fs::read_to_string(radare2_bin_path).unwrap().trim(),
            carved.to_str().unwrap()
        );
        assert_eq!(
            std::fs::read_to_string(rizin_bin_path).unwrap().trim(),
            carved.to_str().unwrap()
        );
        assert_eq!(
            std::fs::read(radare2_bytes).unwrap(),
            [0x70, 0x47, 0xaa, 0x55]
        );
        assert_eq!(
            std::fs::read(rizin_bytes).unwrap(),
            [0x70, 0x47, 0xaa, 0x55]
        );
        let expected_limit = (ANALYZER_ADDRESS_SPACE_CAP_BYTES / 1024).to_string();
        assert_eq!(
            std::fs::read_to_string(radare2_limit).unwrap().trim(),
            expected_limit
        );
        assert_eq!(
            std::fs::read_to_string(rizin_limit).unwrap().trim(),
            expected_limit
        );

        let document: serde_json::Value = serde_json::from_slice(
            &std::fs::read(dir.path().join("thumb_functions.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(document["producers"][0]["id"], "radare2");
        assert_eq!(
            document["producers"][0]["executable"],
            tools.radare2.executable.to_str().unwrap()
        );
        assert_eq!(document["producers"][0]["version"], tools.radare2.version);
        assert_eq!(document["producers"][0]["command"], tools.radare2.command);
        let rizin_identity = tools.rizin.as_ref().unwrap();
        assert_eq!(document["producers"][1]["id"], "rizin");
        assert_eq!(
            document["producers"][1]["executable"],
            rizin_identity.executable.to_str().unwrap()
        );
        assert_eq!(document["producers"][1]["version"], rizin_identity.version);
        assert_eq!(document["producers"][1]["command"], rizin_identity.command);
        assert!(dir.path().join("thumb/00004120.radare2.stdout").exists());
        assert!(dir.path().join("thumb/00004120.rizin.stdout").exists());
        assert!(!dir.path().join("thumb/00004120.stdout").exists());
    }

    #[cfg(unix)]
    #[test]
    fn shared_runner_enforces_stdout_cap_for_both_backends() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("00004000.bin");
        std::fs::write(&bin, [0u8; 2]).unwrap();

        for producer in [
            crate::thumb_analysis::ThumbProducer::Radare2,
            crate::thumb_analysis::ThumbProducer::Rizin,
        ] {
            let executable = dir.path().join(producer.as_str());
            let sentinel = dir.path().join(format!("{}-continued", producer.as_str()));
            write_executable_stub(
                &executable,
                &format!(
                    "#!/bin/sh\nprintf '123456789'\nsleep 1\ntouch '{}'\n",
                    sentinel.display()
                ),
            );
            let identity = test_identity(producer, &executable);
            let stdout = dir
                .path()
                .join(format!("00004000.{}.stdout", producer.as_str()));
            let failure = run_backend_capture(
                &identity,
                &bin,
                0x4000,
                &stdout,
                RunnerLimits {
                    stdout_cap: 8,
                    rizin_timeout: Duration::from_secs(1),
                    ..RunnerLimits::PRODUCTION
                },
            )
            .unwrap_err();

            assert!(failure.capture.is_none());
            let reason = failure.error.to_string();
            assert!(reason.contains(producer.as_str()), "{reason}");
            assert!(reason.contains("more than 8 stdout bytes"), "{reason}");
            assert!(!stdout.exists());
            assert!(!sentinel.exists());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn shared_runner_never_reports_an_unfinalized_capture() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("r2");
        let bin = dir.path().join("00004000.bin");
        let stdout = dir.path().join("00004000.radare2.stdout");
        write_executable_stub(&executable, "#!/bin/sh\nprintf 'captured bytes'\n");
        std::fs::write(&bin, [0u8; 2]).unwrap();
        symlink("/dev/full", &stdout).unwrap();

        let failure = run_backend_capture(
            &test_identity(crate::thumb_analysis::ThumbProducer::Radare2, &executable),
            &bin,
            0x4000,
            &stdout,
            RunnerLimits {
                stdout_cap: 1024,
                ..RunnerLimits::PRODUCTION
            },
        )
        .unwrap_err();

        assert!(failure.capture.is_none());
        let reason = failure.error.to_string();
        assert!(reason.contains("radare2 stdout capture failed"), "{reason}");
        assert!(!stdout.exists());
    }

    #[test]
    fn expired_rizin_deadline_precedes_completed_observation() {
        assert_eq!(
            classify_running_observation(true, true, true),
            RunningObservation::DeadlineExpired
        );
    }

    #[test]
    fn stdout_finalization_sleep_ignores_expired_runtime_deadline() {
        let now = std::time::Instant::now();
        let state = SupervisionState::FinalizingStdout {
            started: now,
            last_progress: now,
            observed_bytes: 0,
        };

        assert_eq!(
            supervision_sleep(
                &state,
                Duration::from_secs(1),
                Some(Duration::ZERO),
                RunnerLimits {
                    pipe_finalization_idle: Duration::from_secs(1),
                    pipe_finalization_absolute: Duration::from_secs(1),
                    ..RunnerLimits::PRODUCTION
                },
            ),
            ANALYZER_POLL_INTERVAL
        );
    }

    #[cfg(unix)]
    #[test]
    fn expired_rizin_deadline_precedes_immediate_nonzero_exit() {
        let dir = tempfile::tempdir().unwrap();
        let stdout_path = dir.path().join("00004000.rizin.stdout");
        let mut command = std::process::Command::new("/bin/sh");
        command
            .args(["-c", "exit 7"])
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped());
        configure_analyzer_process(&mut command);
        let started = std::time::Instant::now();
        let mut child = command.spawn().unwrap();
        let stdout = child.stdout.take().unwrap();
        // SAFETY: `waitid` only observes this live child and WNOWAIT leaves it
        // available for `AnalyzerProcess` to reap after anchored cleanup.
        let mut status = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
        let wait_result = unsafe {
            libc::waitid(
                libc::P_PID,
                child.id() as libc::id_t,
                &mut status,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        assert_eq!(
            wait_result,
            0,
            "waitid failed: {}",
            std::io::Error::last_os_error()
        );

        let failure = supervise_spawned_analyzer(
            child,
            stdout,
            crate::thumb_analysis::ThumbProducer::Rizin,
            0x4000,
            &stdout_path,
            started,
            RunnerLimits {
                rizin_timeout: Duration::ZERO,
                ..RunnerLimits::PRODUCTION
            },
        )
        .unwrap_err();
        let detail = failure.error.to_string();

        assert!(detail.contains("timed out after 0 ms"), "{detail}");
        assert!(!detail.contains("exited with status 7"), "{detail}");
    }

    #[cfg(unix)]
    #[test]
    fn expired_rizin_deadline_rejects_immediately_valid_output() {
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("rizin");
        let bin = dir.path().join("00004000.bin");
        let stdout = dir.path().join("00004000.rizin.stdout");
        write_executable_stub(
            &executable,
            "#!/bin/sh\nprintf '%s\\n' '[{\"offset\":16384,\"name\":\"rizin.too-late\",\"size\":2,\"realsz\":2,\"maxbound\":16386}]' '{\"addr\":16384,\"ops\":[{\"offset\":16384,\"bytes\":\"7047\",\"disasm\":\"bx lr\"}]}' '[]'\n",
        );
        std::fs::write(&bin, [0x70, 0x47]).unwrap();

        let failure = run_backend_capture(
            &test_identity(crate::thumb_analysis::ThumbProducer::Rizin, &executable),
            &bin,
            0x4000,
            &stdout,
            RunnerLimits {
                rizin_timeout: Duration::ZERO,
                ..RunnerLimits::PRODUCTION
            },
        )
        .unwrap_err();

        assert!(
            failure.error.to_string().contains("timed out after 0 ms"),
            "{}",
            failure.error
        );
        if let Some(capture) = failure.capture {
            let retained = std::fs::read(&stdout).unwrap();
            assert_eq!(capture.bytes, retained.len() as u64);
            assert_eq!(capture.blake3, blake3::hash(&retained).to_hex().as_str());
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_pipe_finalization_cancels_reader_and_reaps_leader() {
        let dir = tempfile::tempdir().unwrap();
        let thumb_dir = dir.path().join("thumb");
        std::fs::create_dir(&thumb_dir).unwrap();
        let stdout_path = thumb_dir.join("00004000.rizin.stdout");
        let command_interpreter = std::env::var_os("COMSPEC").unwrap_or_else(|| "cmd.exe".into());
        let mut command = std::process::Command::new(command_interpreter);
        command
            .args([
                "/D",
                "/S",
                "/C",
                "echo partial capture&start \"\" /B ping.exe -n 6 127.0.0.1",
            ])
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped());
        let started = std::time::Instant::now();
        let mut child = command.spawn().unwrap();
        let stdout = child.stdout.take().unwrap();

        let failure = supervise_spawned_analyzer(
            child,
            stdout,
            crate::thumb_analysis::ThumbProducer::Rizin,
            0x4000,
            &stdout_path,
            started,
            RunnerLimits {
                rizin_timeout: Duration::from_secs(3),
                pipe_finalization_idle: Duration::from_millis(200),
                pipe_finalization_absolute: Duration::from_secs(1),
                ..RunnerLimits::PRODUCTION
            },
        )
        .unwrap_err();

        assert!(
            started.elapsed() < Duration::from_secs(3),
            "Windows drain cancellation waited for the background writer: {:?}",
            started.elapsed()
        );
        assert!(
            failure
                .error
                .to_string()
                .contains("stdout remained open after analyzer exit"),
            "{}",
            failure.error
        );
        let capture = failure.capture.expect("forced drain was finalized");
        let retained = std::fs::read(&stdout_path).unwrap();
        assert!(retained.starts_with(b"partial capture"));
        assert_eq!(capture.bytes, retained.len() as u64);
        assert_eq!(capture.blake3, blake3::hash(&retained).to_hex().as_str());
    }

    #[cfg(unix)]
    #[test]
    fn failed_rizin_normalization_removes_partial_fragments_before_partial_commit() {
        let dir = tempfile::tempdir().unwrap();
        let radare2 = dir.path().join("r2");
        let rizin = dir.path().join("rizin");
        write_executable_stub(
            &radare2,
            r#"#!/bin/sh
case " $* " in
  *" -m 0x4000 "*)
    printf '%s\n' '[{"addr":16384,"name":"r2.kept","size":2,"realsz":2,"maxaddr":16386}]' '{"addr":16384,"ops":[{"addr":16384,"bytes":"7047","disasm":"bx lr"}]}'
    ;;
  *" -m 0x4040 "*) exit 7 ;;
  *) exit 98 ;;
esac
"#,
        );
        write_executable_stub(
            &rizin,
            "#!/bin/sh\nprintf '%s\\n' '[{\"offset\":16448,\"name\":\"rizin.partial\",\"size\":2,\"realsz\":2,\"maxbound\":16450},{\"offset\":16450,\"name\":\"rizin.invalid\",\"size\":2,\"realsz\":2}]' '{\"addr\":16448,\"ops\":[{\"offset\":16448,\"bytes\":\"00bf\",\"disasm\":\"nop\"}]}' '{\"addr\":16450,\"ops\":[{\"offset\":16450,\"bytes\":\"7047\",\"disasm\":\"bx lr\"}]}' '[]'\n",
        );
        let mut tools = thumb_tools(&radare2);
        tools.rizin = Some(test_identity(
            crate::thumb_analysis::ThumbProducer::Rizin,
            &rizin,
        ));
        let mut image = vec![0u8; 0x80];
        image[..2].copy_from_slice(&[0x70, 0x47]);
        image[0x40..0x44].copy_from_slice(&[0x00, 0xbf, 0x70, 0x47]);

        let summary = run_thumb_analysis(
            &tools,
            &image,
            0x4000,
            &[(0x4000, 0x40), (0x4040, 0x40)],
            dir.path(),
        )
        .unwrap();

        assert_eq!(summary.regions_succeeded, 1);
        assert_eq!(summary.regions_failed, 1);
        assert_eq!(summary.radare2_runs, 1);
        assert_eq!(summary.rizin_runs, 0);
        assert_eq!(summary.raw, 1);
        let document: serde_json::Value = serde_json::from_slice(
            &std::fs::read(dir.path().join("thumb_functions.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(document["functions"].as_array().unwrap().len(), 1);
        assert_eq!(document["functions"][0]["name"], "r2.kept");
        assert_eq!(document["regions"][1]["attempts"][1]["status"], "failed");
        assert!(
            document["regions"][1]["attempts"][1]["error"]
                .as_str()
                .unwrap()
                .contains("maxbound")
        );
        assert!(
            document["regions"][1]["function_runs"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(dir.path().join("thumb/00004040.rizin.stdout").exists());
        assert!(!dir.path().join("thumb/00004040.rizin.frags").exists());
        assert!(!dir.path().join("thumb/00004000.radare2.frags").exists());
    }

    #[cfg(unix)]
    #[test]
    fn process_failure_removes_stale_backend_fragments_and_retains_stdout() {
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("r2");
        let thumb_dir = dir.path().join("thumb");
        let bin = thumb_dir.join("00004000.bin");
        let fragments = thumb_dir.join("00004000.radare2.frags");
        std::fs::create_dir(&thumb_dir).unwrap();
        std::fs::write(&bin, [0x70, 0x47]).unwrap();
        std::fs::write(&fragments, b"stale fragments").unwrap();
        write_executable_stub(
            &executable,
            "#!/bin/sh\nprintf 'failed capture\\n'\nexit 7\n",
        );

        let failure = match run_backend_region(
            &test_identity(crate::thumb_analysis::ThumbProducer::Radare2, &executable),
            &bin,
            &[0x70, 0x47],
            0x4000,
            0x4000,
            &thumb_dir,
            RunnerLimits::PRODUCTION,
        ) {
            Err(failure) => failure,
            Ok(_) => panic!("non-zero radare2 unexpectedly succeeded"),
        };

        assert!(!fragments.exists());
        let capture = failure.capture.unwrap();
        let stdout = dir.path().join(&capture.path);
        let retained = std::fs::read(stdout).unwrap();
        assert_eq!(retained, b"failed capture\n");
        assert_eq!(capture.bytes, retained.len() as u64);
        assert_eq!(capture.blake3, blake3::hash(&retained).to_hex().as_str());
    }

    #[cfg(unix)]
    #[test]
    fn rizin_xref_failure_removes_stale_fragments_and_retains_stdout() {
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("rizin");
        let thumb_dir = dir.path().join("thumb");
        let bin = thumb_dir.join("00004000.bin");
        let fragments = thumb_dir.join("00004000.rizin.frags");
        std::fs::create_dir(&thumb_dir).unwrap();
        std::fs::write(&bin, [0x70, 0x47]).unwrap();
        std::fs::write(&fragments, b"stale fragments").unwrap();
        write_executable_stub(
            &executable,
            "#!/bin/sh\nprintf '%s\\n' '[{\"offset\":16384,\"name\":\"rizin.invalid-xref\",\"size\":2,\"realsz\":2,\"maxbound\":16386}]' '{\"addr\":16384,\"ops\":[{\"offset\":16384,\"bytes\":\"7047\",\"disasm\":\"bx lr\"}]}' '[{\"from\":\"invalid\",\"to\":20480,\"type\":\"DATA\"}]'\n",
        );

        let failure = match run_backend_region(
            &test_identity(crate::thumb_analysis::ThumbProducer::Rizin, &executable),
            &bin,
            &[0x70, 0x47],
            0x4000,
            0x4000,
            &thumb_dir,
            RunnerLimits::PRODUCTION,
        ) {
            Err(failure) => failure,
            Ok(_) => panic!("invalid Rizin xref unexpectedly succeeded"),
        };

        assert!(failure.error.to_string().contains("canonical u32 source"));
        assert!(!fragments.exists());
        let capture = failure.capture.unwrap();
        let stdout = dir.path().join(&capture.path);
        let retained = std::fs::read(stdout).unwrap();
        assert!(!retained.is_empty());
        assert_eq!(capture.bytes, retained.len() as u64);
        assert_eq!(capture.blake3, blake3::hash(&retained).to_hex().as_str());
    }

    #[cfg(unix)]
    #[test]
    fn assembly_failure_removes_successful_fragments_but_retains_stdout() {
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("r2");
        let artifact_path = dir.path().join("thumb_functions.json");
        std::fs::create_dir(&artifact_path).unwrap();
        write_executable_stub(
            &executable,
            "#!/bin/sh\nprintf '%s\\n' '[{\"addr\":16384,\"name\":\"r2.assembly-failure\",\"size\":2,\"realsz\":2,\"maxaddr\":16386}]' '{\"addr\":16384,\"ops\":[{\"addr\":16384,\"bytes\":\"7047\",\"disasm\":\"bx lr\"}]}'\n",
        );

        let error = run_thumb_analysis(
            &thumb_tools(&executable),
            &[0x70, 0x47],
            0x4000,
            &[(0x4000, 2)],
            dir.path(),
        )
        .unwrap_err();

        assert!(!error.to_string().is_empty());
        assert!(!dir.path().join("thumb/00004000.radare2.frags").exists());
        let retained =
            std::fs::read_to_string(dir.path().join("thumb/00004000.radare2.stdout")).unwrap();
        assert!(retained.contains("r2.assembly-failure"));
        assert!(artifact_path.is_dir());
    }

    #[cfg(unix)]
    fn assert_process_or_group_gone(id: libc::pid_t) {
        for _ in 0..100 {
            // SAFETY: signal 0 performs existence/permission checking only.
            let result = unsafe { libc::kill(id, 0) };
            if result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("process or process group {id} survived analyzer cleanup");
    }

    #[cfg(unix)]
    fn cleanup_policy_with_events(
        events: &'static std::sync::Mutex<Vec<UnixCleanupEvent>>,
    ) -> CleanupPolicy {
        CleanupPolicy {
            events: Some(events),
            ..CleanupPolicy::PRODUCTION
        }
    }

    #[cfg(unix)]
    fn assert_anchored_cleanup_order(events: &[UnixCleanupEvent]) {
        let reaps = events
            .iter()
            .enumerate()
            .filter_map(|(index, event)| (*event == UnixCleanupEvent::Reap).then_some(index))
            .collect::<Vec<_>>();
        assert_eq!(reaps.len(), 1, "expected one reap event: {events:?}");
        let reap = reaps[0];
        let observations = events
            .iter()
            .enumerate()
            .filter_map(|(index, event)| {
                (*event == UnixCleanupEvent::ExitObserved).then_some(index)
            })
            .collect::<Vec<_>>();
        assert_eq!(
            observations.len(),
            1,
            "expected one exit observation: {events:?}"
        );
        let observation = observations[0];
        assert!(
            observation < reap,
            "exit was observed after reap: {events:?}"
        );
        assert!(
            events[..reap]
                .iter()
                .any(|event| matches!(event, UnixCleanupEvent::Signal(signal) if *signal != 0)),
            "cleanup emitted no anchored TERM/KILL before reap: {events:?}"
        );
        assert!(
            events[..observation]
                .iter()
                .all(|event| !matches!(event, UnixCleanupEvent::Signal(signal) if *signal != 0)),
            "post-exit cleanup signaled before observing exit: {events:?}"
        );
        assert!(
            events[..reap]
                .iter()
                .all(|event| !matches!(event, UnixCleanupEvent::Signal(0))),
            "cleanup queried the group before reap: {events:?}"
        );
        assert!(
            events[reap + 1..]
                .iter()
                .all(|event| matches!(event, UnixCleanupEvent::Signal(0))),
            "cleanup emitted a non-verification event after reap: {events:?}"
        );
        assert!(
            events[reap + 1..]
                .iter()
                .any(|event| matches!(event, UnixCleanupEvent::Signal(0))),
            "cleanup never verified group absence after reap: {events:?}"
        );
    }

    #[cfg(unix)]
    fn wait_for_file(path: &Path, timeout: Duration) {
        let started = std::time::Instant::now();
        while !path.exists() {
            assert!(
                started.elapsed() < timeout,
                "timed out waiting for {}",
                path.display()
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[cfg(unix)]
    #[test]
    fn timely_natural_eof_signals_anchored_group_before_single_reap() {
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("r2");
        let bin = dir.path().join("00004000.bin");
        let stdout = dir.path().join("00004000.radare2.stdout");
        let events: &'static std::sync::Mutex<Vec<UnixCleanupEvent>> =
            Box::leak(Box::new(std::sync::Mutex::new(Vec::new())));
        write_executable_stub(&executable, "#!/bin/sh\nprintf 'natural eof\\n'\n");
        std::fs::write(&bin, [0x70, 0x47]).unwrap();

        let capture = match run_backend_capture(
            &test_identity(crate::thumb_analysis::ThumbProducer::Radare2, &executable),
            &bin,
            0x4000,
            &stdout,
            RunnerLimits {
                cleanup: cleanup_policy_with_events(events),
                ..RunnerLimits::PRODUCTION
            },
        ) {
            Ok(capture) => capture,
            Err(failure) => panic!("natural EOF failed: {}", failure.error),
        };

        assert_eq!(capture.bytes, b"natural eof\n".len() as u64);
        assert_anchored_cleanup_order(&events.lock().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn forced_stdout_finalization_signals_anchored_group_before_single_reap() {
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("r2");
        let bin = dir.path().join("00004000.bin");
        let stdout = dir.path().join("00004000.radare2.stdout");
        let events: &'static std::sync::Mutex<Vec<UnixCleanupEvent>> =
            Box::leak(Box::new(std::sync::Mutex::new(Vec::new())));
        write_executable_stub(
            &executable,
            "#!/bin/sh\nprintf 'forced prefix\\n'\nsleep 60 &\nexit 0\n",
        );
        std::fs::write(&bin, [0x70, 0x47]).unwrap();

        let failure = run_backend_capture(
            &test_identity(crate::thumb_analysis::ThumbProducer::Radare2, &executable),
            &bin,
            0x4000,
            &stdout,
            RunnerLimits {
                pipe_finalization_idle: Duration::from_millis(50),
                pipe_finalization_absolute: Duration::from_millis(250),
                cleanup: cleanup_policy_with_events(events),
                ..RunnerLimits::PRODUCTION
            },
        )
        .unwrap_err();

        assert!(
            failure.error.to_string().contains("stdout remained open"),
            "{}",
            failure.error
        );
        assert_anchored_cleanup_order(&events.lock().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn unix_exit_observation_leaves_child_waitable_until_explicit_cleanup() {
        let events: &'static std::sync::Mutex<Vec<UnixCleanupEvent>> =
            Box::leak(Box::new(std::sync::Mutex::new(Vec::new())));
        let policy = cleanup_policy_with_events(events);
        let mut command = std::process::Command::new("/bin/sh");
        command
            .args(["-c", "exit 7"])
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .stdout(std::process::Stdio::null());
        configure_analyzer_process(&mut command);
        let child = command.spawn().unwrap();
        let pid = child.id();
        let mut process = AnalyzerProcess::new(child, Arc::new(DrainControl::default()));
        let started = std::time::Instant::now();
        while !process.observe_exit(policy).unwrap() {
            assert!(started.elapsed() < Duration::from_secs(5));
            std::thread::sleep(ANALYZER_POLL_INTERVAL);
        }

        // A WNOWAIT observation must leave the zombie available to the one
        // explicit Child::wait that closes process-group cleanup.
        let mut observed = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
        let observed_result = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut observed,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if observed_result != 0 {
            // A WNOWAIT mutation may already have reaped the child. Suppress
            // Drop's best-effort cleanup so the deliberately failing test can
            // never signal a now-reusable numeric PGID.
            process.reap_attempted = true;
            panic!(
                "exit observation reaped the child early: {}",
                std::io::Error::last_os_error()
            );
        }
        assert_eq!(unsafe { observed.si_pid() }, pid as libc::pid_t);

        process.terminate_and_reap(policy).unwrap();
        assert_eq!(
            process.status.as_ref().and_then(|status| status.code()),
            Some(7)
        );
        let mut wait_status = 0;
        let wait_result =
            unsafe { libc::waitpid(pid as libc::pid_t, &mut wait_status, libc::WNOHANG) };
        let wait_error = std::io::Error::last_os_error();
        assert_eq!(wait_result, -1);
        assert_eq!(wait_error.raw_os_error(), Some(libc::ECHILD));
        assert_anchored_cleanup_order(&events.lock().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn successful_radare2_with_inherited_stdout_falls_back_and_reaps_group() {
        let dir = tempfile::tempdir().unwrap();
        let radare2 = dir.path().join("r2");
        let rizin = dir.path().join("rizin");
        let parent_pid_path = dir.path().join("radare2-parent.pid");
        let child_pid_path = dir.path().join("radare2-child.pid");
        let ready_path = dir.path().join("radare2.ready");
        write_executable_stub(
            &radare2,
            &format!(
                "#!/bin/sh\n\
                 printf '%s\\n' \"$$\" > '{}'\n\
                 printf '%s\\n' '[{{\"addr\":16384,\"name\":\"r2.must-not-survive\",\"size\":2,\"realsz\":2,\"maxaddr\":16386}}]' '{{\"addr\":16384,\"ops\":[{{\"addr\":16384,\"bytes\":\"7047\",\"disasm\":\"bx lr\"}}]}}'\n\
                 sleep 60 &\n\
                 child=$!\n\
                 printf '%s\\n' \"$child\" > '{}'\n\
                 : > '{}'\n\
                 exit 0\n",
                parent_pid_path.display(),
                child_pid_path.display(),
                ready_path.display(),
            ),
        );
        write_executable_stub(
            &rizin,
            "#!/bin/sh\nprintf '%s\\n' '[{\"offset\":16384,\"name\":\"rizin.fallback\",\"size\":2,\"realsz\":2,\"maxbound\":16386}]' '{\"addr\":16384,\"ops\":[{\"offset\":16384,\"bytes\":\"7047\",\"disasm\":\"bx lr\"}]}' '[]'\n",
        );
        let mut tools = thumb_tools(&radare2);
        tools.rizin = Some(test_identity(
            crate::thumb_analysis::ThumbProducer::Rizin,
            &rizin,
        ));
        let started = std::time::Instant::now();

        let summary = run_thumb_analysis_with_limits(
            &tools,
            &[0x70, 0x47],
            0x4000,
            &[(0x4000, 2)],
            dir.path(),
            RunnerLimits {
                pipe_finalization_idle: Duration::from_millis(100),
                pipe_finalization_absolute: Duration::from_secs(1),
                ..RunnerLimits::PRODUCTION
            },
        )
        .unwrap();

        assert!(
            started.elapsed() < Duration::from_secs(5),
            "inherited stdout cleanup was not prompt: {:?}",
            started.elapsed()
        );
        assert!(ready_path.exists());
        assert_eq!(summary.radare2_runs, 0);
        assert_eq!(summary.rizin_runs, 1);
        let document: serde_json::Value = serde_json::from_slice(
            &std::fs::read(dir.path().join("thumb_functions.json")).unwrap(),
        )
        .unwrap();
        let radare2_attempt = &document["regions"][0]["attempts"][0];
        assert_eq!(radare2_attempt["status"], "failed");
        assert!(
            radare2_attempt["error"]
                .as_str()
                .unwrap()
                .contains("stdout remained open after analyzer exit")
        );
        let capture = &radare2_attempt["stdout"];
        let retained = std::fs::read(dir.path().join(capture["path"].as_str().unwrap())).unwrap();
        assert_eq!(capture["bytes"], retained.len() as u64);
        assert_eq!(capture["blake3"], blake3::hash(&retained).to_hex().as_str());
        assert_eq!(document["functions"][0]["name"], "rizin.fallback");
        assert!(
            document["functions"]
                .as_array()
                .unwrap()
                .iter()
                .all(|function| function["name"] != "r2.must-not-survive")
        );

        let parent_pid: libc::pid_t = std::fs::read_to_string(parent_pid_path)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let child_pid: libc::pid_t = std::fs::read_to_string(child_pid_path)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let mut status = 0;
        // SAFETY: this only queries whether the analyzer child remains waitable.
        let wait_result = unsafe { libc::waitpid(parent_pid, &mut status, libc::WNOHANG) };
        assert_eq!(wait_result, -1, "immediate analyzer child was not reaped");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
        assert_process_or_group_gone(child_pid);
        assert_process_or_group_gone(-parent_pid);
    }

    #[cfg(unix)]
    #[test]
    fn continuing_post_exit_output_cannot_extend_absolute_finalization_bound() {
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("r2");
        let bin = dir.path().join("00004000.bin");
        let stdout = dir.path().join("00004000.radare2.stdout");
        let parent_pid_path = dir.path().join("radare2-parent.pid");
        let child_pid_path = dir.path().join("radare2-child.pid");
        write_executable_stub(
            &executable,
            &format!(
                "#!/bin/sh\n\
                 printf '%s\\n' \"$$\" > '{}'\n\
                 (while :; do printf x; sleep 0.01; done) &\n\
                 child=$!\n\
                 printf '%s\\n' \"$child\" > '{}'\n\
                 exit 0\n",
                parent_pid_path.display(),
                child_pid_path.display(),
            ),
        );
        std::fs::write(&bin, [0x70, 0x47]).unwrap();
        let started = std::time::Instant::now();

        let failure = run_backend_capture(
            &test_identity(crate::thumb_analysis::ThumbProducer::Radare2, &executable),
            &bin,
            0x4000,
            &stdout,
            RunnerLimits {
                stdout_cap: 1024 * 1024,
                pipe_finalization_idle: Duration::from_millis(100),
                pipe_finalization_absolute: Duration::from_millis(300),
                ..RunnerLimits::PRODUCTION
            },
        )
        .unwrap_err();

        assert!(
            started.elapsed() < Duration::from_secs(2),
            "absolute pipe-finalization bound was extended: {:?}",
            started.elapsed()
        );
        let reason = failure.error.to_string();
        assert!(reason.contains("absolute limit"), "{reason}");
        let capture = failure.capture.expect("forced drain was finalized");
        let retained = std::fs::read(&stdout).unwrap();
        assert!(!retained.is_empty());
        assert!(retained.len() < 1024 * 1024);
        assert_eq!(capture.bytes, retained.len() as u64);
        assert_eq!(capture.blake3, blake3::hash(&retained).to_hex().as_str());
        let parent_pid: libc::pid_t = std::fs::read_to_string(parent_pid_path)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let child_pid: libc::pid_t = std::fs::read_to_string(child_pid_path)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_process_or_group_gone(child_pid);
        assert_process_or_group_gone(-parent_pid);
    }

    #[cfg(unix)]
    #[test]
    fn nonzero_radare2_exit_cleans_redirected_descendant_before_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let radare2 = dir.path().join("r2");
        let rizin = dir.path().join("rizin");
        let parent_pid_path = dir.path().join("radare2-parent.pid");
        let child_pid_path = dir.path().join("radare2-child.pid");
        let descendant_survived = dir.path().join("descendant-survived");
        write_executable_stub(
            &radare2,
            &format!(
                "#!/bin/sh\n\
                 printf '%s\\n' \"$$\" > '{}'\n\
                 sleep 60 >/dev/null 2>&1 &\n\
                 child=$!\n\
                 printf '%s\\n' \"$child\" > '{}'\n\
                 exit 9\n",
                parent_pid_path.display(),
                child_pid_path.display(),
            ),
        );
        write_executable_stub(
            &rizin,
            &format!(
                "#!/bin/sh\n\
                 child=$(cat '{}')\n\
                 attempts=0\n\
                 while kill -0 \"$child\" 2>/dev/null && [ \"$attempts\" -lt 100 ]; do\n\
                   attempts=$((attempts + 1))\n\
                   sleep 0.01\n\
                 done\n\
                 if kill -0 \"$child\" 2>/dev/null; then\n\
                   : > '{}'\n\
                   exit 90\n\
                 fi\n\
                 printf '%s\\n' '[{{\"offset\":16384,\"name\":\"rizin.after-cleanup\",\"size\":2,\"realsz\":2,\"maxbound\":16386}}]' '{{\"addr\":16384,\"ops\":[{{\"offset\":16384,\"bytes\":\"7047\",\"disasm\":\"bx lr\"}}]}}' '[]'\n",
                child_pid_path.display(),
                descendant_survived.display(),
            ),
        );
        let mut tools = thumb_tools(&radare2);
        tools.rizin = Some(test_identity(
            crate::thumb_analysis::ThumbProducer::Rizin,
            &rizin,
        ));
        let started = std::time::Instant::now();

        let result = run_thumb_analysis(&tools, &[0x70, 0x47], 0x4000, &[(0x4000, 2)], dir.path());

        let parent_pid: libc::pid_t = std::fs::read_to_string(parent_pid_path)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let child_pid: libc::pid_t = std::fs::read_to_string(child_pid_path)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        if result.is_err() {
            // Keep the RED run from leaking the deliberately long-lived child.
            let _ = signal_process_group(parent_pid as u32, libc::SIGKILL);
            assert_process_or_group_gone(child_pid);
        }
        let summary = result.unwrap();

        assert!(
            started.elapsed() < Duration::from_secs(5),
            "failed-exit cleanup was not prompt: {:?}",
            started.elapsed()
        );
        assert_eq!(summary.radare2_runs, 0);
        assert_eq!(summary.rizin_runs, 1);
        assert!(!descendant_survived.exists());
        let document: serde_json::Value = serde_json::from_slice(
            &std::fs::read(dir.path().join("thumb_functions.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(document["functions"][0]["name"], "rizin.after-cleanup");
        assert_process_or_group_gone(child_pid);
        assert_process_or_group_gone(-parent_pid);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn nonzero_radare2_with_inherited_stdout_does_not_reset_finalization_bounds() {
        let dir = tempfile::tempdir().unwrap();
        let radare2 = dir.path().join("r2");
        let rizin = dir.path().join("rizin");
        let parent_pid_path = dir.path().join("radare2-parent.pid");
        let child_pid_path = dir.path().join("radare2-child.pid");
        write_executable_stub(
            &radare2,
            &format!(
                "#!/bin/sh\n\
                 printf '%s\\n' \"$$\" > '{}'\n\
                 setsid sh -c 'printf \"%s\\n\" \"$$\" > \"{}\"; sleep 60' &\n\
                 while [ ! -s '{}' ]; do sleep 0.01; done\n\
                 exit 9\n",
                parent_pid_path.display(),
                child_pid_path.display(),
                child_pid_path.display(),
            ),
        );
        write_executable_stub(
            &rizin,
            &format!(
                "#!/bin/sh\n\
                 child=$(cat '{}')\n\
                 /bin/kill -KILL -- \"-$child\" 2>/dev/null || true\n\
                 printf '%s\\n' '[{{\"offset\":16384,\"name\":\"rizin.after-inherited-pipe\",\"size\":2,\"realsz\":2,\"maxbound\":16386}}]' '{{\"addr\":16384,\"ops\":[{{\"offset\":16384,\"bytes\":\"7047\",\"disasm\":\"bx lr\"}}]}}' '[]'\n",
                child_pid_path.display(),
            ),
        );
        let mut tools = thumb_tools(&radare2);
        tools.rizin = Some(test_identity(
            crate::thumb_analysis::ThumbProducer::Rizin,
            &rizin,
        ));
        let watchdog_done = Arc::new(AtomicBool::new(false));
        let watchdog_flag = Arc::clone(&watchdog_done);
        let watchdog_pid_path = child_pid_path.clone();
        let watchdog = std::thread::spawn(move || {
            wait_for_file(&watchdog_pid_path, Duration::from_secs(5));
            for _ in 0..200 {
                if watchdog_flag.load(Ordering::Acquire) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let child: libc::pid_t = std::fs::read_to_string(watchdog_pid_path)
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            // SAFETY: the test-created session leader owns this process group.
            unsafe {
                libc::kill(-child, libc::SIGKILL);
            }
        });
        let started = std::time::Instant::now();

        let summary = run_thumb_analysis_with_limits(
            &tools,
            &[0x70, 0x47],
            0x4000,
            &[(0x4000, 2)],
            dir.path(),
            RunnerLimits {
                pipe_finalization_idle: Duration::from_millis(100),
                pipe_finalization_absolute: Duration::from_millis(500),
                ..RunnerLimits::PRODUCTION
            },
        )
        .unwrap();
        watchdog_done.store(true, Ordering::Release);
        watchdog.join().unwrap();

        assert!(
            started.elapsed() < Duration::from_secs(1),
            "failed status reset finalization bounds: {:?}",
            started.elapsed()
        );
        assert_eq!(summary.radare2_runs, 0);
        assert_eq!(summary.rizin_runs, 1);
        let document: serde_json::Value = serde_json::from_slice(
            &std::fs::read(dir.path().join("thumb_functions.json")).unwrap(),
        )
        .unwrap();
        let radare2_attempt = &document["regions"][0]["attempts"][0];
        let error = radare2_attempt["error"].as_str().unwrap();
        assert!(error.contains("exited with status 9"), "{error}");
        assert!(error.contains("stdout remained open"), "{error}");
        assert_eq!(
            document["functions"][0]["name"],
            "rizin.after-inherited-pipe"
        );
        let parent_pid: libc::pid_t = std::fs::read_to_string(parent_pid_path)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let child_pid: libc::pid_t = std::fs::read_to_string(child_pid_path)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_process_or_group_gone(-parent_pid);
        assert_process_or_group_gone(-child_pid);
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_verification_failure_aborts_fallback_and_later_regions() {
        let dir = tempfile::tempdir().unwrap();
        let radare2 = dir.path().join("r2");
        let rizin = dir.path().join("rizin");
        let rizin_sentinel = dir.path().join("rizin-ran");
        let later_region_sentinel = dir.path().join("later-region-ran");
        let artifact = dir.path().join("thumb_functions.json");
        let stable_artifact = b"stable artifact";
        std::fs::write(&artifact, stable_artifact).unwrap();
        write_executable_stub(
            &radare2,
            &format!(
                "#!/bin/sh\n\
                 case \" $* \" in\n\
                   *\" -m 0x4000 \"*) printf 'failed capture\\n'; exit 9 ;;\n\
                   *\" -m 0x4040 \"*) : > '{}'; printf '%s\\n' '[{{\"addr\":16448,\"name\":\"r2.later\",\"size\":2,\"realsz\":2,\"maxaddr\":16450}}]' '{{\"addr\":16448,\"ops\":[{{\"addr\":16448,\"bytes\":\"7047\",\"disasm\":\"bx lr\"}}]}}' ;;\n\
                   *) exit 98 ;;\n\
                 esac\n",
                later_region_sentinel.display(),
            ),
        );
        write_executable_stub(
            &rizin,
            &format!(
                "#!/bin/sh\n\
                 : > '{}'\n\
                 printf '%s\\n' '[{{\"offset\":16384,\"name\":\"rizin.must-not-run\",\"size\":2,\"realsz\":2,\"maxbound\":16386}}]' '{{\"addr\":16384,\"ops\":[{{\"offset\":16384,\"bytes\":\"7047\",\"disasm\":\"bx lr\"}}]}}' '[]'\n",
                rizin_sentinel.display(),
            ),
        );
        let mut tools = thumb_tools(&radare2);
        tools.rizin = Some(test_identity(
            crate::thumb_analysis::ThumbProducer::Rizin,
            &rizin,
        ));
        let mut image = vec![0u8; 0x80];
        image[..2].copy_from_slice(&[0x70, 0x47]);
        image[0x40..0x42].copy_from_slice(&[0x70, 0x47]);

        let error = run_thumb_analysis_with_limits(
            &tools,
            &image,
            0x4000,
            &[(0x4000, 0x40), (0x4040, 0x40)],
            dir.path(),
            RunnerLimits {
                cleanup: CleanupPolicy {
                    inject_verification_failure: true,
                    ..CleanupPolicy::PRODUCTION
                },
                ..RunnerLimits::PRODUCTION
            },
        )
        .unwrap_err();
        let detail = error.to_string();

        assert!(detail.contains("exited with status 9"), "{detail}");
        assert!(
            detail.contains("injected cleanup verification failure"),
            "{detail}"
        );
        assert!(!rizin_sentinel.exists());
        assert!(!later_region_sentinel.exists());
        assert_eq!(std::fs::read(artifact).unwrap(), stable_artifact);
    }

    /// Fake backends whose only job is to prove they were never spawned, plus
    /// a second region's radare2 branch that must never be reached.
    #[cfg(unix)]
    fn sentinel_backends(
        dir: &Path,
    ) -> (
        crate::thumb_analysis::ThumbTools,
        std::path::PathBuf,
        std::path::PathBuf,
    ) {
        let radare2 = dir.join("r2");
        let rizin = dir.join("rizin");
        let radare2_sentinel = dir.join("radare2-ran");
        let rizin_sentinel = dir.join("rizin-ran");
        write_executable_stub(
            &radare2,
            &format!(
                "#!/bin/sh\n\
                 printf '%s\\n' \"$*\" >> '{}'\n\
                 printf '%s\\n' '[{{\"addr\":16384,\"name\":\"r2.fn\",\"size\":2,\"realsz\":2,\"maxaddr\":16386}}]' '{{\"addr\":16384,\"ops\":[{{\"addr\":16384,\"bytes\":\"7047\",\"disasm\":\"bx lr\"}}]}}'\n",
                radare2_sentinel.display(),
            ),
        );
        write_executable_stub(
            &rizin,
            &format!(
                "#!/bin/sh\n\
                 : > '{}'\n\
                 printf '%s\\n' '[{{\"offset\":16384,\"name\":\"rizin.must-not-run\",\"size\":2,\"realsz\":2,\"maxbound\":16386}}]' '{{\"addr\":16384,\"ops\":[{{\"offset\":16384,\"bytes\":\"7047\",\"disasm\":\"bx lr\"}}]}}' '[]'\n",
                rizin_sentinel.display(),
            ),
        );
        let mut tools = thumb_tools(&radare2);
        tools.rizin = Some(test_identity(
            crate::thumb_analysis::ThumbProducer::Rizin,
            &rizin,
        ));
        (tools, radare2_sentinel, rizin_sentinel)
    }

    /// A pre-attempt housekeeping failure means no backend process was ever
    /// attempted, so it must abort the request rather than fabricate a failed
    /// radare2 attempt and hand the region to Rizin.
    #[cfg(unix)]
    #[test]
    fn undeletable_stale_fragment_aborts_before_any_backend_runs() {
        let dir = tempfile::tempdir().unwrap();
        let (tools, radare2_sentinel, rizin_sentinel) = sentinel_backends(dir.path());
        let artifact = dir.path().join("thumb_functions.json");
        let stable_artifact = b"stable stale-fragment artifact";
        std::fs::write(&artifact, stable_artifact).unwrap();
        // An undeletable stale fragment: `remove_file` on a populated directory
        // fails without needing permission tricks or a privileged test host.
        let stale = dir.path().join("thumb").join("00004000.radare2.frags");
        std::fs::create_dir_all(stale.join("occupied")).unwrap();
        let mut image = vec![0u8; 0x80];
        image[..2].copy_from_slice(&[0x70, 0x47]);
        image[0x40..0x42].copy_from_slice(&[0x70, 0x47]);

        let error = run_thumb_analysis(
            &tools,
            &image,
            0x4000,
            &[(0x4000, 0x40), (0x4040, 0x40)],
            dir.path(),
        )
        .unwrap_err();
        let detail = error.to_string();

        assert!(detail.contains("stale fragments"), "{detail}");
        assert!(!radare2_sentinel.exists(), "the primary was spawned");
        assert!(!rizin_sentinel.exists(), "the fallback was spawned");
        assert_eq!(std::fs::read(artifact).unwrap(), stable_artifact);
    }

    /// Fragment cleanup that cannot be verified leaves unowned bytes beside the
    /// sidecar, so it is terminal rather than an ordinary fallback-eligible
    /// backend failure.
    #[cfg(unix)]
    #[test]
    fn unverified_fragment_cleanup_aborts_fallback_and_later_regions() {
        let dir = tempfile::tempdir().unwrap();
        let (tools, _radare2_sentinel, rizin_sentinel) = sentinel_backends(dir.path());
        let later_region_sentinel = dir.path().join("later-region-ran");
        let artifact = dir.path().join("thumb_functions.json");
        let stable_artifact = b"stable cleanup artifact";
        std::fs::write(&artifact, stable_artifact).unwrap();
        // The carved region input is the last argument, so the stub can occupy
        // the fragment path this attempt is about to spill into. The spill then
        // fails and its cleanup cannot verify the path is gone.
        write_executable_stub(
            &dir.path().join("r2"),
            &format!(
                "#!/bin/sh\n\
                 for arg in \"$@\"; do last=\"$arg\"; done\n\
                 case \" $* \" in\n\
                   *\" -m 0x4000 \"*) mkdir -p \"$(dirname \"$last\")/00004000.radare2.frags/occupied\" ;;\n\
                   *\" -m 0x4040 \"*) : > '{}' ;;\n\
                 esac\n\
                 printf '%s\\n' '[{{\"addr\":16384,\"name\":\"r2.fn\",\"size\":2,\"realsz\":2,\"maxaddr\":16386}}]' '{{\"addr\":16384,\"ops\":[{{\"addr\":16384,\"bytes\":\"7047\",\"disasm\":\"bx lr\"}}]}}'\n",
                later_region_sentinel.display(),
            ),
        );
        let mut image = vec![0u8; 0x80];
        image[..2].copy_from_slice(&[0x70, 0x47]);
        image[0x40..0x42].copy_from_slice(&[0x70, 0x47]);

        let error = run_thumb_analysis(
            &tools,
            &image,
            0x4000,
            &[(0x4000, 0x40), (0x4040, 0x40)],
            dir.path(),
        )
        .unwrap_err();
        let detail = error.to_string();

        assert!(detail.contains("fragment cleanup failed"), "{detail}");
        assert!(!rizin_sentinel.exists(), "the fallback was spawned");
        assert!(!later_region_sentinel.exists(), "a later region ran");
        assert_eq!(std::fs::read(artifact).unwrap(), stable_artifact);
    }

    /// The declared pipe-finalization limits must bound when supervision
    /// returns, not only when cancellation starts. A drain that never observes
    /// cancellation is detached and reported instead of waited on forever.
    #[cfg(unix)]
    #[test]
    fn stuck_stdout_drain_is_detached_within_the_cancellation_bound() {
        let child = std::process::Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let mut process = AnalyzerProcess::new(child, Arc::new(DrainControl::default()));
        process.drain = Some(std::thread::spawn(|| {
            std::thread::sleep(Duration::from_secs(5));
            Ok(CaptureRecord {
                path: String::new(),
                bytes: 0,
                blake3: String::new(),
            })
        }));
        let started = std::time::Instant::now();

        let error = process
            .cancel_drain_and_wait(Duration::from_millis(50))
            .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(
            process.drain.is_none(),
            "a drain that ignores cancellation must be detached, not joined"
        );
        assert!(
            process.join_drain().is_err(),
            "a detached drain must never yield a capture identity"
        );
    }

    #[test]
    fn remove_stale_output_reports_everything_but_an_absent_path() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");
        let file = dir.path().join("capture.stdout");
        std::fs::write(&file, b"partial").unwrap();
        let occupied = dir.path().join("occupied");
        std::fs::create_dir_all(occupied.join("child")).unwrap();

        assert!(remove_stale_output(&missing).is_ok());
        assert!(remove_stale_output(&file).is_ok());
        assert!(!file.exists());
        assert!(remove_stale_output(&occupied).is_err());
        assert!(occupied.exists());
    }

    #[cfg(unix)]
    #[test]
    fn post_spawn_setup_cleanup_failure_is_terminal() {
        let dir = tempfile::tempdir().unwrap();
        let radare2 = dir.path().join("r2");
        let rizin = dir.path().join("rizin");
        let rizin_sentinel = dir.path().join("rizin-ran");
        let later_region_sentinel = dir.path().join("later-region-ran");
        let artifact = dir.path().join("thumb_functions.json");
        let stable_artifact = b"stable setup artifact";
        std::fs::write(&artifact, stable_artifact).unwrap();
        let thumb_dir = dir.path().join("thumb");
        std::fs::create_dir(&thumb_dir).unwrap();
        std::fs::create_dir(thumb_dir.join("00004000.radare2.stdout")).unwrap();
        write_executable_stub(
            &radare2,
            &format!(
                "#!/bin/sh\n\
                 case \" $* \" in\n\
                   *\" -m 0x4000 \"*) sleep 60 ;;\n\
                   *\" -m 0x4040 \"*) : > '{}'; printf '%s\\n' '[{{\"addr\":16448,\"name\":\"r2.later\",\"size\":2,\"realsz\":2,\"maxaddr\":16450}}]' '{{\"addr\":16448,\"ops\":[{{\"addr\":16448,\"bytes\":\"7047\",\"disasm\":\"bx lr\"}}]}}' ;;\n\
                   *) exit 98 ;;\n\
                 esac\n",
                later_region_sentinel.display(),
            ),
        );
        write_executable_stub(
            &rizin,
            &format!(
                "#!/bin/sh\n\
                 : > '{}'\n\
                 printf '%s\\n' '[{{\"offset\":16384,\"name\":\"rizin.must-not-run\",\"size\":2,\"realsz\":2,\"maxbound\":16386}}]' '{{\"addr\":16384,\"ops\":[{{\"offset\":16384,\"bytes\":\"7047\",\"disasm\":\"bx lr\"}}]}}' '[]'\n",
                rizin_sentinel.display(),
            ),
        );
        let mut tools = thumb_tools(&radare2);
        tools.rizin = Some(test_identity(
            crate::thumb_analysis::ThumbProducer::Rizin,
            &rizin,
        ));

        let error = run_thumb_analysis_with_limits(
            &tools,
            &[0u8; 0x80],
            0x4000,
            &[(0x4000, 0x40), (0x4040, 0x40)],
            dir.path(),
            RunnerLimits {
                cleanup: CleanupPolicy {
                    inject_verification_failure: true,
                    ..CleanupPolicy::PRODUCTION
                },
                ..RunnerLimits::PRODUCTION
            },
        )
        .unwrap_err();
        let detail = error.to_string();

        assert!(
            detail.contains("could not create stdout capture"),
            "{detail}"
        );
        assert!(
            detail.contains("injected cleanup verification failure"),
            "{detail}"
        );
        assert!(!rizin_sentinel.exists());
        assert!(!later_region_sentinel.exists());
        assert_eq!(std::fs::read(artifact).unwrap(), stable_artifact);
    }

    #[cfg(unix)]
    #[test]
    fn rizin_timeout_reaps_process_group_and_retains_finalized_partial_capture() {
        let dir = tempfile::tempdir().unwrap();
        let radare2 = dir.path().join("r2");
        let rizin = dir.path().join("rizin");
        let parent_pid_path = dir.path().join("rizin-parent.pid");
        let child_pid_path = dir.path().join("rizin-child.pid");
        let ready_path = dir.path().join("rizin.ready");
        write_executable_stub(
            &radare2,
            r#"#!/bin/sh
case " $* " in
  *" -m 0x4000 "*)
    printf '%s\n' '[{"addr":16384,"name":"fcn.4000","size":2,"realsz":2,"maxaddr":16386}]' '{"addr":16384,"ops":[{"addr":16384,"bytes":"7047","disasm":"bx lr"}]}'
    ;;
  *" -m 0x4040 "*)
    exit 7
    ;;
  *) exit 98 ;;
esac
"#,
        );
        write_executable_stub(
            &rizin,
            &format!(
                "#!/bin/sh\n\
                 printf '%s\\n' \"$$\" > '{}'\n\
                 sleep 60 &\n\
                 child=$!\n\
                 printf '%s\\n' \"$child\" > '{}'\n\
                 printf 'partial rizin capture\\n'\n\
                 : > '{}'\n\
                 wait \"$child\"\n",
                parent_pid_path.display(),
                child_pid_path.display(),
                ready_path.display(),
            ),
        );
        let mut tools = thumb_tools(&radare2);
        tools.rizin = Some(test_identity(
            crate::thumb_analysis::ThumbProducer::Rizin,
            &rizin,
        ));
        let mut image = vec![0u8; 0x80];
        image[..2].copy_from_slice(&[0x70, 0x47]);
        let started = std::time::Instant::now();
        let summary = std::thread::scope(|scope| {
            let analysis = scope.spawn(|| {
                run_thumb_analysis_with_limits(
                    &tools,
                    &image,
                    0x4000,
                    &[(0x4000, 0x40), (0x4040, 0x40)],
                    dir.path(),
                    RunnerLimits {
                        stdout_cap: ANALYZER_STDOUT_CAP_BYTES,
                        rizin_timeout: Duration::from_secs(1),
                        ..RunnerLimits::PRODUCTION
                    },
                )
            });
            wait_for_file(&ready_path, Duration::from_secs(5));
            analysis.join().unwrap().unwrap()
        });

        assert!(
            started.elapsed() < Duration::from_secs(5),
            "timeout cleanup followed the 60-second natural exit: {:?}",
            started.elapsed()
        );

        assert_eq!(summary.regions_succeeded, 1);
        assert_eq!(summary.regions_failed, 1);
        assert_eq!(summary.radare2_runs, 1);
        assert_eq!(summary.rizin_runs, 0);
        let document: serde_json::Value = serde_json::from_slice(
            &std::fs::read(dir.path().join("thumb_functions.json")).unwrap(),
        )
        .unwrap();
        let timed_out = &document["regions"][1]["attempts"][1];
        assert_eq!(timed_out["producer"], "rizin");
        assert_eq!(timed_out["status"], "failed");
        let reason = timed_out["error"].as_str().unwrap();
        assert!(reason.contains("rizin") && reason.contains("timed out after 1000 ms"));
        assert!(
            document["regions"][1]["function_runs"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        let capture = &timed_out["stdout"];
        assert_eq!(capture["path"], "thumb/00004040.rizin.stdout");
        let retained = std::fs::read(dir.path().join(capture["path"].as_str().unwrap())).unwrap();
        assert_eq!(retained, b"partial rizin capture\n");
        assert_eq!(capture["bytes"], retained.len() as u64);
        assert_eq!(capture["blake3"], blake3::hash(&retained).to_hex().as_str());
        assert!(!dir.path().join("thumb/00004040.rizin.frags").exists());

        let parent_pid: libc::pid_t = std::fs::read_to_string(parent_pid_path)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let child_pid: libc::pid_t = std::fs::read_to_string(child_pid_path)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let mut status = 0;
        // SAFETY: this only queries whether the analyzer child remains waitable.
        let wait_result = unsafe { libc::waitpid(parent_pid, &mut status, libc::WNOHANG) };
        assert_eq!(wait_result, -1, "immediate analyzer child was not reaped");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD),
            "immediate analyzer child is still owned by the test process"
        );
        assert_process_or_group_gone(parent_pid);
        assert_process_or_group_gone(child_pid);
        assert_process_or_group_gone(-parent_pid);
    }

    #[cfg(unix)]
    #[test]
    fn injected_rizin_deadline_does_not_apply_to_radare2() {
        let dir = tempfile::tempdir().unwrap();
        let radare2 = dir.path().join("r2");
        let rizin = dir.path().join("rizin");
        let sentinel = dir.path().join("rizin-ran");
        write_executable_stub(
            &radare2,
            "#!/bin/sh\nsleep 0.1\nprintf '%s\\n' '[{\"addr\":16384,\"name\":\"r2.slow\",\"size\":2,\"realsz\":2,\"maxaddr\":16386}]' '{\"addr\":16384,\"ops\":[{\"addr\":16384,\"bytes\":\"7047\",\"disasm\":\"bx lr\"}]}'\n",
        );
        write_executable_stub(
            &rizin,
            &format!("#!/bin/sh\ntouch '{}'\nexit 99\n", sentinel.display()),
        );
        let mut tools = thumb_tools(&radare2);
        tools.rizin = Some(test_identity(
            crate::thumb_analysis::ThumbProducer::Rizin,
            &rizin,
        ));

        let summary = run_thumb_analysis_with_limits(
            &tools,
            &[0x70, 0x47],
            0x4000,
            &[(0x4000, 2)],
            dir.path(),
            RunnerLimits {
                stdout_cap: ANALYZER_STDOUT_CAP_BYTES,
                rizin_timeout: Duration::from_millis(50),
                ..RunnerLimits::PRODUCTION
            },
        )
        .unwrap();

        assert_eq!(summary.radare2_runs, 1);
        assert_eq!(summary.rizin_runs, 0);
        assert!(!sentinel.exists());
    }

    #[cfg(unix)]
    #[test]
    fn run_thumb_analysis_empty_request_is_a_noop() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        std::fs::write(&out, b"not a directory").unwrap();
        let invalid_tools = crate::thumb_analysis::ThumbTools {
            radare2: crate::thumb_analysis::ProducerIdentity {
                producer: crate::thumb_analysis::ThumbProducer::Rizin,
                executable: "relative/r2".into(),
                version: "".into(),
                command: "wrong",
            },
            rizin: None,
        };

        let summary = run_thumb_analysis(&invalid_tools, &[0], u32::MAX, &[], &out).unwrap();

        assert_eq!(
            summary,
            crate::thumb_analysis::ThumbAnalysisSummary::default()
        );
        assert_eq!(std::fs::read(out).unwrap(), b"not a directory");
    }

    #[test]
    fn normalize_radare2_function_records_body_and_refs() {
        let raw = serde_json::json!({
            "name": "sym.thumb_func",
            "offset": 0x4120u64,
            "size": 4096u64,
            "realsz": 48u64,
            "maxaddr": 0x4150u64
        });
        let pdfj = serde_json::json!({
            "ops": [
                {
                    "offset": 0x4120u64,
                    "bytes": "b5f0",
                    "disasm": "push {r4, lr}",
                    "refs": [{"addr": 0x9000u64, "type": "DATA"}]
                },
                {
                    "offset": 0x4122u64,
                    "bytes": "4770",
                    "disasm": "bx lr",
                    "refs": [{"to": 0x9004u64, "kind": "string"}]
                }
            ]
        });

        let body = "0x00004120      b5f0      push {r4, lr}\n0x00004122      4770      bx lr\n";
        let entry = normalize_radare2_function(&raw, &pdfj).unwrap();

        assert_eq!(entry["name"], "sym.thumb_func");
        assert_eq!(entry["entry"], "0x4120");
        assert_eq!(entry["end"], "0x4150");
        assert_eq!(entry["size"], 48);
        assert_eq!(entry["body_kind"], "thumb_disassembly");
        assert_eq!(entry["body"], body);
        assert_eq!(entry["data_refs"][0], "0x9000");
        assert_eq!(entry["data_refs"][1], "0x9004");
        assert_eq!(
            entry["decode_ranges"],
            serde_json::json!([{
                "isa":"thumb",
                "start":"0x4120",
                "end":"0x4124",
                "blake3":"ac6a95eb5686e10323a7626706d954217ba183b8e7f8301cd524c19d067d9ce6"
            }]),
            "out-of-order pdfj operations must normalize into an exact tagged Thumb range"
        );
        assert_eq!(entry["decode_range_errors"], serde_json::json!([]));
    }

    #[test]
    fn v3_uses_maxaddr_and_realsz_not_entry_plus_bounding_size() {
        let raw = json!({
            "addr": 0x43b2847cu64,
            "size": 1_112_420u64,
            "realsz": 32u64,
            "minaddr": 0x43a18edcu64,
            "maxaddr": 0x43b28840u64,
            "name": "fcn.43b2847c"
        });
        let pdfj = json!({
            "addr": 0x43b2847cu64,
            "ops": [{
                "addr": 0x43b2847cu64,
                "bytes": "7047",
                "disasm": "bx lr"
            }]
        });
        let mut image = vec![0u8; 0x14_0000];
        let op_offset = (0x43b2847cu64 - 0x43a00000u64) as usize;
        image[op_offset..op_offset + 2].copy_from_slice(&[0x70, 0x47]);

        let normalized =
            normalize_radare2_function_checked(&raw, Some(&pdfj), &image, 0x43a00000, 0x43a00000)
                .unwrap();

        assert_eq!(normalized["end"], "0x43b28840");
        assert_eq!(normalized["size"], 32);
    }

    #[test]
    fn v3_rejects_missing_or_invalid_radare2_boundaries() {
        let valid = json!({
            "addr": 0x4000u64,
            "size": 0x1000u64,
            "realsz": 2u64,
            "maxaddr": 0x4002u64,
            "name": "fcn.4000"
        });
        let cases = [
            ("missing realsz", None, "realsz"),
            ("zero realsz", Some(("realsz", json!(0))), "positive realsz"),
            (
                "malformed realsz",
                Some(("realsz", json!("not-a-size"))),
                "realsz",
            ),
            (
                "oversized realsz",
                Some(("realsz", json!(0x21))),
                "mapped image length",
            ),
            ("missing maxaddr", None, "maxaddr"),
            (
                "malformed maxaddr",
                Some(("maxaddr", json!("not-an-address"))),
                "maxaddr",
            ),
            (
                "reversed maxaddr",
                Some(("maxaddr", json!(0x4000))),
                "must follow entry",
            ),
            (
                "out-of-image maxaddr",
                Some(("maxaddr", json!(0x4021))),
                "outside mapped image",
            ),
            (
                "overflowed maxaddr",
                Some(("maxaddr", json!(u64::from(u32::MAX) + 1))),
                "canonical u32",
            ),
        ];

        for (case, replacement, expected) in cases {
            let mut raw = valid.clone();
            match (case, replacement) {
                ("missing realsz", _) => {
                    raw.as_object_mut().unwrap().remove("realsz");
                }
                ("missing maxaddr", _) => {
                    raw.as_object_mut().unwrap().remove("maxaddr");
                }
                (_, Some((field, value))) => raw[field] = value,
                _ => unreachable!(),
            }

            let error =
                normalize_radare2_function_checked(&raw, None, &[0u8; 0x20], 0x4000, 0x4000)
                    .unwrap_err();

            assert!(
                error.to_string().contains(expected),
                "{case}: expected {expected:?}, got {error}"
            );
        }
    }

    #[test]
    fn rizin_normalization_uses_maxbound_realsz_aliases_and_axlj_refs() {
        let raw = json!({
            "offset": "0x4000",
            "addr": 0x5000u64,
            "maxbound": "0x4008",
            "maxaddr": 0x4002u64,
            "realsz": 6u64,
            "size": 0x1000u64,
            "name": "fcn.rizin",
            "xrefs_to": [{"from": 1, "to": 2, "type": "DATA"}],
            "codexrefs": [{"from": 3, "to": 4, "type": "DATA"}]
        });
        let pdfj = json!({
            "addr": 0x4000u64,
            "ops": [
                {
                    "offset": 0x4000u64,
                    "bytes": "00bf",
                    "disasm": "nop",
                    "refs": [{"to": 0xaaaa, "type": "DATA"}]
                },
                {"addr": 0x4002u64, "bytes": "7047", "disasm": "bx lr"},
                {"offset": 0x4006u64, "bytes": "00bf", "disasm": "nop"}
            ],
            "xrefs_to": [{"from": 5, "to": 6, "type": "DATA"}],
            "incoming": [{"from": 7, "to": 8, "type": "DATA"}]
        });
        let xrefs = vec![
            crate::thumb_analysis::rizin::RizinXref {
                from: 0x4000,
                to: 0x9002,
            },
            crate::thumb_analysis::rizin::RizinXref {
                from: 0x4002,
                to: 0x9000,
            },
            crate::thumb_analysis::rizin::RizinXref {
                from: 0x4004,
                to: 0x9001,
            },
            crate::thumb_analysis::rizin::RizinXref {
                from: 0x4006,
                to: 0x9000,
            },
            crate::thumb_analysis::rizin::RizinXref {
                from: 0x4008,
                to: 0x9003,
            },
        ];
        let image = [0x00, 0xbf, 0x70, 0x47, 0x00, 0x00, 0x00, 0xbf];

        let normalized =
            normalize_rizin_function_checked(&raw, Some(&pdfj), &xrefs, &image, 0x4000, 0x4000)
                .unwrap();

        assert_eq!(normalized["name"], "fcn.rizin");
        assert_eq!(normalized["entry"], "0x4000");
        assert_eq!(normalized["end"], "0x4008");
        assert_eq!(normalized["size"], 6);
        assert_eq!(
            normalized["body"],
            "0x00004000      00bf      nop\n\
             0x00004002      7047      bx lr\n\
             0x00004006      00bf      nop\n"
        );
        assert_eq!(normalized["data_refs"], json!(["0x9000", "0x9002"]));
        assert_eq!(
            normalized["decode_ranges"],
            json!([
                {"isa":"thumb", "start":"0x4000", "end":"0x4004", "blake3":"a3d517dd4692556677d7e2688ebbabed22ed8472e9ff0918e9afa1bb39aa8472"},
                {"isa":"thumb", "start":"0x4006", "end":"0x4008", "blake3":"1ebc25810942bc5c0f5ed3ddade44a9546a9be6d3df45142bf7bd45a32511d72"}
            ])
        );
        assert_eq!(normalized["decode_range_errors"], json!([]));
    }

    #[test]
    fn rizin_inventory_addresses_accept_offset_or_addr_and_enforce_u32_domain() {
        let pdfj = json!({"ops":[{"offset":0x4000u64,"bytes":"00bf"}]});
        let xrefs = Vec::new();
        for raw in [
            json!({"offset":0x4000u64,"maxbound":0x4002u64,"realsz":2}),
            json!({"addr":0x4000u64,"maxbound":0x4002u64,"realsz":2}),
        ] {
            let normalized = normalize_rizin_function_checked(
                &raw,
                Some(&pdfj),
                &xrefs,
                &[0x00, 0xbf],
                0x4000,
                0x4000,
            )
            .unwrap();
            assert_eq!(normalized["entry"], "0x4000");
        }

        let invalid = [
            (
                "missing entry",
                json!({"maxbound":0x4002u64,"realsz":2}),
                "entry/addr",
            ),
            (
                "malformed preferred offset",
                json!({"offset":"bad","addr":0x4000u64,"maxbound":0x4002u64,"realsz":2}),
                "entry/addr",
            ),
            (
                "overflowed entry",
                json!({"offset":u64::from(u32::MAX) + 1,"maxbound":u64::from(u32::MAX) + 2,"realsz":2}),
                "canonical u32",
            ),
            (
                "out-of-image entry",
                json!({"offset":0x3ffeu64,"maxbound":0x4000u64,"realsz":2}),
                "outside mapped image",
            ),
        ];
        for (case, raw, expected) in invalid {
            let error = normalize_rizin_function_checked(
                &raw,
                Some(&pdfj),
                &xrefs,
                &[0x00, 0xbf],
                0x4000,
                0x4000,
            )
            .unwrap_err();
            assert!(
                error.to_string().contains(expected),
                "{case}: expected {expected:?}, got {error}"
            );
        }
    }

    #[test]
    fn rizin_boundaries_require_strict_maxbound_and_positive_realsz() {
        let valid = json!({
            "offset": 0x4000u64,
            "maxbound": 0x4002u64,
            "maxaddr": 0x4002u64,
            "realsz": 2u64,
            "size": 0x1000u64
        });
        let pdfj = json!({"ops":[{"offset":0x4000u64,"bytes":"00bf"}]});
        let cases = [
            ("missing maxbound", "maxbound", None),
            (
                "malformed maxbound",
                "maxbound",
                Some(("maxbound", json!("bad"))),
            ),
            (
                "reversed maxbound",
                "must follow entry",
                Some(("maxbound", json!(0x4000))),
            ),
            (
                "out-of-image maxbound",
                "outside mapped image",
                Some(("maxbound", json!(0x4021))),
            ),
            (
                "overflowed maxbound",
                "canonical u32",
                Some(("maxbound", json!(u64::from(u32::MAX) + 1))),
            ),
            ("missing realsz", "realsz", None),
            ("zero realsz", "positive realsz", Some(("realsz", json!(0)))),
            ("malformed realsz", "realsz", Some(("realsz", json!("bad")))),
            (
                "oversized realsz",
                "mapped image length",
                Some(("realsz", json!(0x21))),
            ),
        ];

        for (case, expected, replacement) in cases {
            let mut raw = valid.clone();
            match (case, replacement) {
                ("missing maxbound", _) => {
                    raw.as_object_mut().unwrap().remove("maxbound");
                }
                ("missing realsz", _) => {
                    raw.as_object_mut().unwrap().remove("realsz");
                }
                (_, Some((field, value))) => raw[field] = value,
                _ => unreachable!(),
            }
            let error = normalize_rizin_function_checked(
                &raw,
                Some(&pdfj),
                &[],
                &[0u8; 0x20],
                0x4000,
                0x4000,
            )
            .unwrap_err();
            assert!(
                error.to_string().contains(expected),
                "{case}: expected {expected:?}, got {error}"
            );
        }
    }

    #[test]
    fn rizin_operation_addresses_accept_aliases_and_domain_faults_remove_refs() {
        let raw = json!({"offset":0x4000u64,"maxbound":0x4004u64,"realsz":4});
        let valid = json!({"ops":[
            {"offset":0x4000u64,"bytes":"00bf"},
            {"addr":0x4002u64,"bytes":"7047"}
        ]});
        let xrefs = [crate::thumb_analysis::rizin::RizinXref {
            from: 0x4000,
            to: 0x9000,
        }];
        let normalized = normalize_rizin_function_checked(
            &raw,
            Some(&valid),
            &xrefs,
            &[0x00, 0xbf, 0x70, 0x47],
            0x4000,
            0x4000,
        )
        .unwrap();
        assert_eq!(
            normalized["decode_ranges"],
            json!([{
                "isa":"thumb",
                "start":"0x4000",
                "end":"0x4004",
                "blake3":"a3d517dd4692556677d7e2688ebbabed22ed8472e9ff0918e9afa1bb39aa8472"
            }])
        );
        assert_eq!(normalized["data_refs"], json!(["0x9000"]));

        let invalid = json!({"ops":[{
            "offset": u64::from(u32::MAX) + 1,
            "addr": 0x4000u64,
            "bytes": "00bf"
        }]});
        let normalized = normalize_rizin_function_checked(
            &raw,
            Some(&invalid),
            &xrefs,
            &[0x00, 0xbf, 0x70, 0x47],
            0x4000,
            0x4000,
        )
        .unwrap();
        assert!(normalized["decode_ranges"].as_array().unwrap().is_empty());
        assert!(
            normalized["decode_range_errors"]
                .as_array()
                .unwrap()
                .iter()
                .any(|error| error["kind"] == "invalid_operation_address")
        );
        assert!(normalized["data_refs"].as_array().unwrap().is_empty());
    }

    #[test]
    fn rizin_capture_normalizes_validates_and_spills_adapted_data_refs() {
        let dir = tempfile::tempdir().unwrap();
        let capture = dir.path().join("capture.stdout");
        std::fs::write(
            &capture,
            r#"[
  {"offset":16384,"maxbound":16386,"realsz":2,"size":4096,"name":"accepted","xrefs_to":[{"from":1,"to":2,"type":"DATA"}]},
  {"addr":16386,"maxbound":16388,"realsz":2,"size":4096,"name":"quarantined","codexrefs":[{"from":3,"to":4,"type":"DATA"}]}
]
{"addr":16384,"ops":[{"offset":16384,"bytes":"00bf","disasm":"nop"}],"incoming":[{"from":5,"to":6,"type":"DATA"}]}
{"offset":16386,"ops":[{"addr":16386,"bytes":"zz","disasm":"invalid"}]}
[
  {"from":16384,"to":20480,"type":"DATA"},
  {"from":16386,"addr":24576,"type":"read"}
]"#,
        )
        .unwrap();

        let outcome = process_rizin_region_streaming(
            &capture,
            &[0x00, 0xbf, 0x00, 0xbf],
            0x4000,
            0x4000,
            dir.path(),
        )
        .unwrap();

        assert_eq!(outcome.stats.raw, 2);
        assert_eq!(outcome.stats.substantial, 0);
        assert_eq!(outcome.stats.accepted, 1);
        let mut fragments = Vec::new();
        outcome.spill.emit(&mut fragments).unwrap();
        let functions = serde_json::Deserializer::from_slice(&fragments)
            .into_iter::<serde_json::Value>()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(functions.len(), 2);
        assert_eq!(functions[0]["name"], "accepted");
        assert_eq!(functions[0]["data_refs"], json!(["0x5000"]));
        assert_eq!(functions[1]["name"], "quarantined");
        assert!(functions[1]["decode_ranges"].as_array().unwrap().is_empty());
        assert!(functions[1]["data_refs"].as_array().unwrap().is_empty());
    }

    #[test]
    fn rizin_capture_never_reinterprets_axlj_records_as_pdfj_bodies() {
        let dir = tempfile::tempdir().unwrap();
        let capture = dir.path().join("capture.stdout");
        std::fs::write(
            &capture,
            r#"[{"offset":16384,"maxbound":16386,"realsz":2}]
{"addr":16384,"ops":[{"offset":16384,"bytes":"00bf"}]}
[{"type":"CODE","ops":[]}]"#,
        )
        .unwrap();

        let outcome =
            process_rizin_region_streaming(&capture, &[0x00, 0xbf], 0x4000, 0x4000, dir.path())
                .unwrap();

        assert_eq!(outcome.stats.raw, 1);
        assert_eq!(outcome.stats.accepted, 1);
    }

    #[test]
    fn rizin_invalid_inventory_fails_before_generic_large_array_scan() {
        let large = format!(
            "[{}]",
            (0..32)
                .map(|index| format!("{{\"from\":{index},\"type\":\"CODE\"}}"))
                .collect::<Vec<_>>()
                .join(",")
        );
        let captures = [
            ("empty inventory", format!("[]\n{large}")),
            (
                "ops-disqualified inventory",
                format!("[{{\"ops\":[]}}]\n{{\"ops\":[]}}\n{large}"),
            ),
        ];

        for (case, contents) in captures {
            let dir = tempfile::tempdir().unwrap();
            let capture = dir.path().join("capture.stdout");
            std::fs::write(&capture, contents).unwrap();

            let spill = dir.path().join("capture.frags");
            let error = match process_region_with_adapter(
                &capture,
                &[0x00, 0xbf],
                0x4000,
                0x4000,
                &spill,
                ThumbProducer::Rizin,
                rizin_function_record,
                &mut RizinXrefIndex::new(Vec::new()),
                64,
            ) {
                Ok(_) => panic!("{case} must fail"),
                Err(error) => error,
            };
            let message = error.to_string();
            assert!(message.contains("inventory"), "{case}: {message}");
            assert!(
                !message.contains("generic JSON value limit"),
                "{case} crossed into the large array: {message}"
            );
        }
    }

    #[test]
    fn streaming_substantial_count_uses_realsz() {
        let stdout = b"[{\"name\":\"sym.a\",\"offset\":16384,\"size\":1,\"realsz\":32,\"maxaddr\":16386}]\n{\"addr\":16384,\"ops\":[{\"offset\":16384,\"bytes\":\"00bf\",\"disasm\":\"nop\"}]}\n";
        let dir = tempfile::tempdir().unwrap();
        let stdout_path = dir.path().join("capture.stdout");
        std::fs::write(&stdout_path, stdout).unwrap();

        let outcome = process_region_streaming(
            &stdout_path,
            &[
                0, 0xbf, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
            ],
            0x4000,
            0x4000,
            dir.path(),
        )
        .unwrap();

        assert_eq!(outcome.stats.substantial, 1);
    }

    #[test]
    fn radare2_pdfj_quarantines_all_faults_without_salvaging_a_prefix() {
        let pdfj = serde_json::json!({"ops": [
            {"offset": 0x4000u64, "bytes": "00bf"},
            {"offset": 0x4002u64, "bytes": "0"},
            {"offset": 0x4003u64, "bytes": "00bf"},
            {"offset": 0x4010u64, "bytes": "00bf"}
        ]});
        let projection = execution_projection(0x4000, Some(&pdfj), &[0; 8], 0x4000).unwrap();
        let ExecutionProjection::Quarantined(errors) = projection else {
            panic!("invalid operation must quarantine the entire record")
        };
        assert!(errors.iter().any(|error| error.kind
            == DecodeRangeErrorKind::InvalidOperationBytes
            && error.address == 0x4002));
        assert!(errors.iter().any(|error| error.kind
            == DecodeRangeErrorKind::MisalignedInstruction
            && error.address == 0x4003));
        assert!(errors.iter().any(
            |error| error.kind == DecodeRangeErrorKind::ExtentOutsideImage
                && error.address == 0x4010
        ));
        assert!(
            errors
                .iter()
                .any(|error| error.kind == DecodeRangeErrorKind::RawByteMismatch
                    && error.address == 0x4003)
        );
    }

    #[test]
    fn radare2_pdfj_merges_adjacent_two_and_four_byte_t32_operations() {
        let pdfj = serde_json::json!({"ops": [
            {"offset": 0x4002u64, "bytes": "f0b50000"},
            {"offset": 0x4000u64, "bytes": "00bf"}
        ]});
        let image = [0x00, 0xbf, 0xf0, 0xb5, 0x00, 0x00];
        let projection = execution_projection(0x4000, Some(&pdfj), &image, 0x4000).unwrap();
        assert_eq!(
            projection_to_json(&projection).unwrap(),
            serde_json::json!({
                "decode_ranges": [{"isa":"thumb", "start":"0x4000", "end":"0x4006", "blake3":blake3::hash(&image).to_hex().to_string()}],
                "decode_range_errors": [],
            })
        );
    }

    #[test]
    fn radare2_pdfj_preserves_gaps_and_ignores_legacy_size_as_an_extent() {
        let raw = serde_json::json!({
            "offset": 0x4000u64,
            "size": 0x1000u64,
            "realsz": 6u64,
            "maxaddr": 0x4006u64
        });
        let pdfj = serde_json::json!({"ops": [
            {"offset": 0x4000u64, "bytes": "00bf"},
            {"offset": 0x4004u64, "bytes": "00bf"}
        ]});
        let entry = normalize_radare2_function_checked(
            &raw,
            Some(&pdfj),
            &[0, 0xbf, 0, 0, 0, 0xbf],
            0x4000,
            0,
        )
        .unwrap();
        assert_eq!(entry["size"], 6);
        assert_eq!(entry["end"], "0x4006");
        assert_eq!(
            entry["decode_ranges"],
            serde_json::json!([
                {"isa":"thumb", "start":"0x4000", "end":"0x4002", "blake3":"1ebc25810942bc5c0f5ed3ddade44a9546a9be6d3df45142bf7bd45a32511d72"},
                {"isa":"thumb", "start":"0x4004", "end":"0x4006", "blake3":"1ebc25810942bc5c0f5ed3ddade44a9546a9be6d3df45142bf7bd45a32511d72"}
            ])
        );
    }

    #[test]
    fn radare2_pdfj_quarantines_missing_nonhex_duplicate_overlap_overflow_and_entry_faults() {
        let cases = [
            (
                serde_json::json!({"ops":[{"offset":0x4000u64}]}),
                0x4000,
                &[0u8; 8][..],
                DecodeRangeErrorKind::InvalidOperationBytes,
            ),
            (
                serde_json::json!({"ops":[{"offset":0x4000u64,"bytes":"zz"}]}),
                0x4000,
                &[0u8; 8][..],
                DecodeRangeErrorKind::InvalidOperationBytes,
            ),
            (
                serde_json::json!({"ops":[{"offset":0x4000u64,"bytes":"00bf"},{"offset":0x4000u64,"bytes":"00bf"}]}),
                0x4000,
                &[0, 0xbf][..],
                DecodeRangeErrorKind::DuplicateExtent,
            ),
            (
                serde_json::json!({"ops":[{"offset":0x4000u64,"bytes":"00bf0000"},{"offset":0x4002u64,"bytes":"00bf"}]}),
                0x4000,
                &[0, 0xbf, 0, 0][..],
                DecodeRangeErrorKind::OverlappingExtent,
            ),
            (
                serde_json::json!({"ops":[{"offset":u32::MAX as u64,"bytes":"00bf"}]}),
                u32::MAX,
                &[0u8; 8][..],
                DecodeRangeErrorKind::InvalidOperationAddress,
            ),
            (
                serde_json::json!({"ops":[{"offset":0x4002u64,"bytes":"00bf"}]}),
                0x4000,
                &[0, 0, 0, 0xbf][..],
                DecodeRangeErrorKind::MissingInstructionAtEntry,
            ),
        ];
        for (pdfj, entry, image, kind) in cases {
            let ExecutionProjection::Quarantined(errors) =
                execution_projection(entry, Some(&pdfj), image, 0x4000).unwrap()
            else {
                panic!("fault must quarantine")
            };
            assert!(
                errors.iter().any(|error| error.kind == kind),
                "missing {kind:?}: {errors:?}"
            );
        }
    }

    #[test]
    fn radare2_missing_pdfj_body_is_a_tagged_quarantine() {
        let projection = execution_projection(0x4000, None, &[0, 0], 0x4000).unwrap();
        assert_eq!(
            projection_to_json(&projection).unwrap(),
            serde_json::json!({
                "decode_ranges": [],
                "decode_range_errors": [{"kind":"missing_operation_body", "address":"0x4000", "end":null}],
            })
        );
    }

    #[test]
    fn capture_to_cap_streams_chunks_until_eof() {
        let input = vec![0xABu8; 100 * 1024]; // 100 KiB
        let mut reader = std::io::Cursor::new(&input[..]);
        let mut writer: Vec<u8> = Vec::new();
        let capture = capture_to_cap(&mut reader, &mut writer, 1024 * 1024, "capture").unwrap();
        assert_eq!(capture.bytes, 100 * 1024);
        assert_eq!(writer, input);
    }

    #[test]
    fn capture_to_cap_returns_capture_identity_without_rereading() {
        let input = b"captured radare2 stdout";
        let mut reader = std::io::Cursor::new(input);
        let mut writer = Vec::new();

        let capture = capture_to_cap(
            &mut reader,
            &mut writer,
            1024,
            "thumb/00004000.radare2.stdout",
        )
        .unwrap();

        assert_eq!(writer, input);
        assert_eq!(capture.path, "thumb/00004000.radare2.stdout");
        assert_eq!(capture.bytes, input.len() as u64);
        assert_eq!(capture.blake3, blake3::hash(input).to_hex().as_str());
    }

    #[test]
    fn capture_to_cap_returns_err_on_cap_exceed() {
        let cap = 1024;
        let input = vec![0xCDu8; cap + 1];
        let mut reader = std::io::Cursor::new(&input[..]);
        let mut writer: Vec<u8> = Vec::new();
        let err = capture_to_cap(&mut reader, &mut writer, cap, "capture").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        assert!(
            err.to_string().contains(&format!("{cap}")),
            "error message should mention the cap value: {err}"
        );
        // Writer must contain exactly `cap` bytes — no over-write past the cap.
        assert_eq!(writer.len(), cap);
        assert!(writer.iter().all(|b| *b == 0xCD));
    }

    #[test]
    fn capture_to_cap_handles_empty_input() {
        let mut reader = std::io::Cursor::new(b"" as &[u8]);
        let mut writer: Vec<u8> = Vec::new();
        let capture = capture_to_cap(&mut reader, &mut writer, 1024, "capture").unwrap();
        assert_eq!(capture.bytes, 0);
        assert!(writer.is_empty());
    }

    #[test]
    fn capture_to_cap_handles_exact_cap_input() {
        // Equal-to-cap is OK; exceeds is not. Boundary sentinel.
        let cap = 4096;
        let input = vec![0xEFu8; cap];
        let mut reader = std::io::Cursor::new(&input[..]);
        let mut writer: Vec<u8> = Vec::new();
        let capture = capture_to_cap(&mut reader, &mut writer, cap, "capture").unwrap();
        assert_eq!(capture.bytes, cap as u64);
        assert_eq!(writer, input);
    }

    #[test]
    fn analyzer_stdout_cap_bytes_is_4_gib() {
        // Regression sentinel against accidental value drift.
        assert_eq!(ANALYZER_STDOUT_CAP_BYTES, 4 * 1024 * 1024 * 1024);
    }

    #[cfg(unix)]
    #[test]
    fn analyzer_address_space_cap_is_applied_to_child_process() {
        // `configure_analyzer_process` must set RLIMIT_AS on the spawned child so a
        // runaway r2 gets ENOMEM (and fails closed) instead of OOM-killing the
        // host. Observe it through a child `ulimit -v`, which reports the soft
        // address-space limit in KiB.
        let mut cmd = std::process::Command::new("bash");
        cmd.args(["-c", "ulimit -v"]);
        configure_analyzer_process(&mut cmd);
        let out = cmd.output().expect("spawn bash for ulimit probe");
        let printed = String::from_utf8_lossy(&out.stdout);
        let expected_kib = (ANALYZER_ADDRESS_SPACE_CAP_BYTES / 1024).to_string();
        assert_eq!(printed.trim(), expected_kib);
    }

    #[cfg(unix)]
    #[test]
    fn one_failed_thumb_region_does_not_drop_the_others() {
        // A region whose r2 run fails (spawn/kill/address-space-cap/malformed
        // output) is recorded and skipped, never aborting the stage: the sibling
        // regions' functions still reach thumb_functions.json. Regression guard
        // for the address-space-cap fail-closed path — one runaway region (e.g.
        // cheetah 01_MAIN 0x42310000) must degrade Thumb coverage locally, not
        // zero it out. Exercises the production fold in `run_thumb_analysis`
        // through a stub r2 that fails exactly one region by its -m address.
        let dir = std::env::temp_dir().join(format!("pme_r2_skip_one_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let r2 = dir.join("r2");
        let out = dir.join("out");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(
            &r2,
            "#!/usr/bin/env sh\ncase \" $* \" in\n  *\" -m 0x4120 \"*) exit 139;;\n  *) printf '%s\\n' '[{\"name\":\"sym.thumb_func\",\"offset\":16672,\"size\":64,\"realsz\":64,\"maxaddr\":16674}]' '{\"addr\":16672,\"ops\":[{\"offset\":16672,\"bytes\":\"b5f0\",\"disasm\":\"push {r4, lr}\"}]}';;\nesac\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = std::fs::metadata(&r2).unwrap().permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&r2, perm).unwrap();
        }

        let summary = run_thumb_analysis(
            &thumb_tools(&r2),
            &[0u8; 0x180],
            0x4000,
            &[(0x4100, 0x20), (0x4120, 0x20), (0x4140, 0x20)],
            &out,
        )
        .unwrap();

        assert_eq!(summary.regions_succeeded, 2);
        assert_eq!(summary.regions_failed, 1);
        assert_eq!(summary.radare2_runs, 2);
        assert_eq!(summary.substantial, 2);
        let bytes = std::fs::read(out.join("thumb_functions.json")).unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let functions = doc["functions"].as_array().unwrap();
        assert_eq!(functions.len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn all_failed_thumb_regions_return_error_without_replacing_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let r2 = dir.path().join("r2");
        std::fs::write(&r2, "#!/bin/sh\nexit 1\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&r2).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&r2, permissions).unwrap();
        let sidecar = dir.path().join("thumb_functions.json");
        std::fs::write(&sidecar, b"old").unwrap();

        let err = run_thumb_analysis(
            &thumb_tools(&r2),
            &[0u8; 0x100],
            0x4000,
            &[(0x4000, 0x20), (0x4040, 0x20)],
            dir.path(),
        )
        .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("failed for every requested region"));
        let first = message.find("0x4000:").unwrap();
        let second = message.find("0x4040:").unwrap();
        assert!(first < second, "region failures must retain request order");
        assert_eq!(message.matches("radare2 exited with status 1").count(), 2);
        assert_eq!(std::fs::read(sidecar).unwrap(), b"old");
    }

    #[cfg(unix)]
    #[test]
    fn modern_addr_inventory_pdfj_and_operations_reach_output() {
        let dir = tempfile::tempdir().unwrap();
        let r2 = dir.path().join("r2");
        std::fs::write(
            &r2,
            "#!/bin/sh\nprintf '%s\\n' '[{\"name\":\"sym.thumb_func\",\"addr\":16672,\"size\":64,\"realsz\":2,\"maxaddr\":16674}]' '{\"addr\":16672,\"ops\":[{\"addr\":16672,\"bytes\":\"7047\",\"disasm\":\"bx lr\"}]}'\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&r2).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&r2, permissions).unwrap();
        let mut image = vec![0u8; 0x200];
        image[0x120..0x122].copy_from_slice(&[0x70, 0x47]);
        let summary = run_thumb_analysis(
            &thumb_tools(&r2),
            &image,
            0x4000,
            &[(0x4120, 2)],
            dir.path(),
        )
        .unwrap();
        assert_eq!(summary.substantial, 0);
        let artifact: serde_json::Value = serde_json::from_slice(
            &std::fs::read(dir.path().join("thumb_functions.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(artifact["functions"][0]["entry"], "0x4120");
        assert_eq!(artifact["format"], crate::thumb_analysis::THUMB_V3_FORMAT);
        assert_eq!(
            artifact["functions"][0]["decode_ranges"][0]["start"],
            "0x4120"
        );
    }

    #[cfg(unix)]
    #[test]
    fn invalid_region_requests_fail_before_spawning() {
        let cases = [
            ("zero-length", vec![(0x4000, 0)], "zero length"),
            ("checked-add-overflow", vec![(u32::MAX - 1, 4)], "overflows"),
            ("out-of-image", vec![(0x40f0, 0x20)], "outside image"),
            (
                "unsorted",
                vec![(0x4040, 0x20), (0x4000, 0x20)],
                "not sorted",
            ),
            (
                "overlapping",
                vec![(0x4000, 0x40), (0x4020, 0x40)],
                "overlap",
            ),
        ];

        for (name, regions, expected) in cases {
            let dir = tempfile::tempdir().unwrap();
            let r2 = dir.path().join("r2");
            let sentinel = dir.path().join("spawned");
            std::fs::write(
                &r2,
                format!("#!/bin/sh\n: > '{}'\nexit 0\n", sentinel.display()),
            )
            .unwrap();
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = std::fs::metadata(&r2).unwrap().permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(&r2, permissions).unwrap();
            let out = dir.path().join("out");

            let err = run_thumb_analysis(&thumb_tools(&r2), &[0u8; 0x100], 0x4000, &regions, &out)
                .err()
                .unwrap_or_else(|| panic!("{name}: invalid request must fail"));
            assert!(
                matches!(err, Error::Serialize(message) if message.contains(expected)),
                "{name}: wrong validation error"
            );
            assert!(!sentinel.exists(), "{name}: tool must not be spawned");
            assert!(!out.exists(), "{name}: output must not be created");
        }
    }

    #[cfg(unix)]
    #[test]
    fn noncanonical_runtime_executable_path_fails_before_output_creation() {
        let dir = tempfile::tempdir().unwrap();
        let tools = crate::thumb_analysis::ThumbTools {
            radare2: crate::thumb_analysis::ProducerIdentity {
                producer: crate::thumb_analysis::ThumbProducer::Radare2,
                executable: std::path::PathBuf::from("/tmp//r2/"),
                version: "radare2 test 1.0".into(),
                command: crate::thumb_analysis::ThumbProducer::Radare2.command(),
            },
            rizin: None,
        };
        let out = dir.path().join("out");

        let error =
            run_thumb_analysis(&tools, &[0x70, 0x47], 0x4000, &[(0x4000, 2)], &out).unwrap_err();

        assert!(
            error.to_string().contains("canonical absolute path"),
            "{error}"
        );
        assert!(
            !out.exists(),
            "identity validation must precede output writes"
        );
    }

    #[cfg(unix)]
    #[test]
    fn mapped_image_overflow_fails_before_spawning() {
        let dir = tempfile::tempdir().unwrap();
        let radare2 = dir.path().join("r2");
        let sentinel = dir.path().join("spawned");
        std::fs::write(
            &radare2,
            format!("#!/bin/sh\n: > '{}'\nexit 0\n", sentinel.display()),
        )
        .unwrap();
        make_executable(&radare2);
        let out = dir.path().join("out");

        let error = run_thumb_analysis(
            &thumb_tools(&radare2),
            &[0u8; 0x20],
            u32::MAX - 0x0f,
            &[(u32::MAX - 0x0f, 8)],
            &out,
        )
        .unwrap_err();

        assert!(error.to_string().contains("mapped image"), "{error}");
        assert!(!sentinel.exists());
        assert!(!out.exists());
    }

    #[test]
    fn noisy_radare2_stdout_still_pairs_and_normalizes_pdfj() {
        let stdout = br#"Warning: run r2 with -e bin.cache=true
        [{"name":"sym.thumb_func","offset":16672,"size":4096,"realsz":48,"maxaddr":16720}]
INFO: analyzing functions
{"addr":16672,"ops":[{"offset":16672,"bytes":"b5f0","disasm":"push {r4, lr}","refs":[{"addr":36864,"type":"DATA"}]}]}
Warning: analysis completed
"#;

        let pairs = radare2_thumb_function_pdfjs(stdout);
        assert_eq!(pairs.len(), 1);
        let entry = normalize_radare2_function(&pairs[0].0, &pairs[0].1).unwrap();

        assert_eq!(entry["name"], "sym.thumb_func");
        assert_eq!(entry["entry"], "0x4120");
        assert_eq!(entry["body"], "0x00004120      b5f0      push {r4, lr}\n");
        assert_eq!(entry["data_refs"][0], "0x9000");
    }

    #[test]
    fn radare2_thumb_rejects_non_empty_stdout_without_parseable_json() {
        let stdout =
            b"Warning: analysis recovered functions but emitted logs only\nINFO: no JSON here\n";

        let err = parse_checked_radare2_thumb_output(stdout, 0x4000).unwrap_err();

        assert!(matches!(err, Error::Serialize(message) if message.contains("no parseable JSON")));
    }

    #[test]
    fn radare2_thumb_rejects_empty_stdout() {
        let err = parse_checked_radare2_thumb_output(b"", 0x4000).unwrap_err();

        assert!(matches!(err, Error::Serialize(message) if message.contains("no parseable JSON")));
    }

    #[test]
    fn radare2_thumb_rejects_whitespace_only_stdout() {
        let err = parse_checked_radare2_thumb_output(b" \n\t\r", 0x4000).unwrap_err();

        assert!(matches!(err, Error::Serialize(message) if message.contains("no parseable JSON")));
    }

    #[test]
    fn radare2_thumb_rejects_parseable_json_without_function_inventory_array() {
        let stdout = br#"Warning: noisy prelude
{"addr":16384,"ops":[{"offset":16384,"bytes":"b5f0","disasm":"push {r4, lr}"}]}
"#;

        let err = parse_checked_radare2_thumb_output(stdout, 0x4000).unwrap_err();

        assert!(
            matches!(err, Error::Serialize(message) if message.contains("no aflj function inventory"))
        );
    }

    #[test]
    fn radare2_thumb_rejects_empty_function_inventory_array() {
        let err = parse_checked_radare2_thumb_output(b"[]", 0x4000).unwrap_err();

        assert!(
            matches!(err, Error::Serialize(message) if message.contains("no aflj function inventory"))
        );

        let dir = tempfile::tempdir().unwrap();
        let stdout_path = dir.path().join("capture.stdout");
        std::fs::write(&stdout_path, b"[]").unwrap();
        let err = process_region_streaming(&stdout_path, &[0u8; 0x100], 0x4000, 0x4000, dir.path())
            .err()
            .expect("empty inventory must fail the region");
        assert!(
            matches!(err, Error::Serialize(message) if message.contains("no aflj function inventory"))
        );
    }

    #[test]
    fn radare2_thumb_rejects_non_empty_inventory_with_zero_paired_bodies() {
        let stdout = b"Warning: noisy prelude\n\
        [{\"name\":\"sym.thumb_func\",\"offset\":16384,\"size\":64,\"realsz\":64,\"maxaddr\":16386}]\n\
        INFO: no pdfj body followed\n";

        let err = parse_checked_radare2_thumb_output(stdout, 0x4000).unwrap_err();
        assert!(matches!(err, Error::Serialize(message)
            if message.contains("zero paired pdfj bodies") && message.contains("0x4000")));
    }

    #[test]
    fn process_region_streaming_rejects_zero_paired_bodies() {
        let stdout = b"Warning: noisy prelude\n\
        [{\"name\":\"sym.thumb_func\",\"offset\":16384,\"size\":64,\"realsz\":64,\"maxaddr\":16386}]\n\
        INFO: no pdfj body followed\n";
        let dir = tempfile::tempdir().unwrap();
        let stdout_path = dir.path().join("capture.stdout");
        std::fs::write(&stdout_path, stdout).unwrap();

        let err = process_region_streaming(&stdout_path, &[0u8; 0x100], 0x4000, 0x4000, dir.path())
            .err()
            .expect("non-empty inventory without paired bodies must fail");
        assert!(matches!(err, Error::Serialize(message)
            if message.contains("zero paired pdfj bodies") && message.contains("0x4000")));
    }

    #[test]
    fn radare2_thumb_retains_paired_empty_pdfj_body_for_quarantine() {
        let stdout = br#"Warning: noisy prelude
        [{"name":"sym.thumb_func","offset":16384,"size":64,"realsz":64,"maxaddr":16386}]
{"addr":16384,"ops":[]}
"#;

        let parsed = parse_checked_radare2_thumb_output(stdout, 0x4000).unwrap();
        assert_eq!(parsed.records.len(), 1);
        assert!(parsed.records[0].1.is_some());
    }

    #[test]
    fn radare2_thumb_retains_partial_pdfj_recovery_for_per_record_quarantine() {
        let stdout = br#"Warning: noisy prelude
        [{"name":"sym.first","offset":16384,"size":64,"realsz":64,"maxaddr":16386},{"name":"sym.second","offset":16448,"size":64,"realsz":64,"maxaddr":16450}]
{"addr":16384,"ops":[{"offset":16384,"bytes":"b5f0","disasm":"push {r4, lr}"}]}
INFO: second pdfj body was noisy and not parseable
"#;

        let parsed = parse_checked_radare2_thumb_output(stdout, 0x4000).unwrap();
        assert_eq!(parsed.records.len(), 2);
        assert!(parsed.records[0].1.is_some());
        assert!(parsed.records[1].1.is_none());
    }

    #[test]
    fn radare2_thumb_does_not_reuse_entry_matched_pdfj_as_positional_fallback() {
        let stdout = br#"Warning: noisy prelude
        [{"name":"sym.first","offset":16384,"size":64,"realsz":64,"maxaddr":16386},{"name":"sym.second","offset":16448,"size":64,"realsz":64,"maxaddr":16450}]
{"addr":16448,"ops":[{"offset":16448,"bytes":"4770","disasm":"bx lr"}]}
"#;

        let parsed = parse_checked_radare2_thumb_output(stdout, 0x4000).unwrap();
        assert!(parsed.records[0].1.is_none());
        assert!(parsed.records[1].1.is_some());
    }

    #[test]
    fn radare2_thumb_rejects_positional_pdfj_with_different_parseable_entry() {
        let stdout = br#"Warning: noisy prelude
        [{"name":"sym.first","offset":16384,"size":64,"realsz":64,"maxaddr":16386},{"name":"sym.second","offset":16448,"size":64,"realsz":64,"maxaddr":16450}]
{"addr":20480,"ops":[{"offset":20480,"bytes":"00bf","disasm":"nop"}]}
{"addr":16448,"ops":[{"offset":16448,"bytes":"4770","disasm":"bx lr"}]}
"#;

        let err = parse_checked_radare2_thumb_output(stdout, 0x4000).unwrap_err();

        assert!(matches!(err, Error::Serialize(message) if message.contains("orphan pdfj")));
    }

    #[test]
    fn radare2_thumb_rejects_non_zero_process_status() {
        let err =
            check_thumb_backend_status(ThumbProducer::Radare2, false, Some(7), 0x4000).unwrap_err();

        assert!(
            matches!(err, Error::Serialize(message) if message.contains("exited with status 7"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn radare2_thumb_maps_raw_blob_at_region_address() {
        let dir = std::env::temp_dir().join(format!("pme_r2_map_addr_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let r2 = dir.join("r2");
        let out = dir.join("out");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(
            &r2,
            "#!/usr/bin/env sh\nprintf '%s\\n' \"$@\" > \"$0.argv\"\ncat <<'EOF'\n[{\"name\":\"sym.thumb_func\",\"offset\":16672,\"size\":64,\"realsz\":64,\"maxaddr\":16674}]\n{\"addr\":16672,\"ops\":[{\"offset\":16672,\"bytes\":\"b5f0\",\"disasm\":\"push {r4, lr}\"}]}\nEOF\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = std::fs::metadata(&r2).unwrap().permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&r2, perm).unwrap();
        }

        let summary = run_thumb_analysis(
            &thumb_tools(&r2),
            &[0u8; 0x180],
            0x4000,
            &[(0x4120, 0x20)],
            &out,
        )
        .unwrap();

        assert_eq!(summary.substantial, 1);
        let argv = std::fs::read_to_string(r2.with_file_name("r2.argv")).unwrap();
        let args: Vec<_> = argv.lines().collect();
        assert_eq!(args[0..4], ["-a", "arm", "-b", "16"]);
        let map = args.iter().position(|arg| *arg == "-m").unwrap();
        assert_eq!(args[map + 1], "0x4120");
        assert!(
            !args.contains(&"-B"),
            "raw carved blobs must use r2 map address (-m), not binary base (-B): {args:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_radare2_region_rejects_unnormalizable_raw_function() {
        let dir = std::env::temp_dir().join(format!("pme_r2_bad_normalize_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let r2 = dir.join("r2");
        let out = dir.join("out");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(
            &r2,
            "#!/usr/bin/env sh\ncat <<'EOF'\n[{\"name\":\"sym.no_entry\",\"size\":64,\"realsz\":2,\"maxaddr\":16386}]\n{\"ops\":[{\"type\":\"nop\"},{\"offset\":16416,\"bytes\":\"b5f0\",\"disasm\":\"push {r4, lr}\"}]}\nEOF\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = std::fs::metadata(&r2).unwrap().permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&r2, perm).unwrap();
        }

        // Under parallel test execution (multiple tests in this module write +
        // exec stub `r2` scripts concurrently) the kernel occasionally returns
        // ETXTBSY from execve on the freshly-written stub. Retry only on that
        // specific transient kind; any other Io failure escalates immediately
        // so it isn't masked. The assertion below still verifies the expected
        // non-Io failure mode.
        let mut last = None;
        for attempt in 0..5u32 {
            match run_radare2_region(&r2, &[0u8; 16], 0x4000, 0x4000, 16, &out) {
                Ok(_) => break,
                Err(e) if matches!(e, Error::Io(ref io) if io.kind() == std::io::ErrorKind::ExecutableFileBusy) =>
                {
                    last = Some(e);
                    std::thread::sleep(std::time::Duration::from_millis(5 * attempt as u64));
                    continue;
                }
                Err(e) => {
                    last = Some(e);
                    break;
                }
            }
        }
        let err = last.expect("expected an error from run_radare2_region");

        assert!(
            matches!(err, Error::Serialize(message) if message.contains("unassignable aflj") && message.contains("0x4000"))
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pdfj_refs_and_body_use_realistic_ops() {
        let pdfj = serde_json::json!({
            "ops": [
                {
                    "addr": 0x4120u64,
                    "bytes": "b5f0",
                    "disasm": "push {r4, lr}",
                    "ptr": 0xaaaa_u64,
                    "refs": [
                        {"to": 0x9004u64, "type": "DATA"},
                        {"to": 0x8120u64, "type": "code"}
                    ]
                },
                {
                    "addr": 0x4122u64,
                    "bytes": "4b02",
                    "disasm": "ldr r3, [pc, 8]",
                    "refptr": 4u64,
                    "refs": [
                        {"addr": 0x9000u64, "kind": "str"},
                        {"to": 0x9008u64, "perm": "read"},
                        {"to": 0xbeef_u64}
                    ],
                    "xrefs": [{"to": 0x7000u64, "type": "DATA"}]
                },
                {
                    "addr": 0x4124u64,
                    "bytes": "d001",
                    "disasm": "beq 0x412a",
                    "jump": 0x412au64,
                    "fail": 0x4126u64,
                    "refs": [{"to": 0x412au64, "type": "jump"}]
                },
                {
                    "addr": 0x4126u64,
                    "bytes": "4770",
                    "disasm": "bx lr",
                    "refs": [{"to": 0x9004u64, "name": "str.duplicate"}]
                }
            ]
        });

        assert_eq!(
            data_refs_from_pdfj(&pdfj),
            vec!["0x9000", "0x9004", "0x9008"]
        );
        assert_eq!(
            operation_body(&pdfj),
            "0x00004120      b5f0      push {r4, lr}\n\
             0x00004122      4b02      ldr r3, [pc, 8]\n\
             0x00004124      d001      beq 0x412a\n\
             0x00004126      4770      bx lr\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn run_thumb_analysis_emits_v3_format_and_producer_identity() {
        let dir = std::env::temp_dir().join(format!("pme_r2_v3_fmt_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let r2 = dir.join("r2");
        let out = dir.join("out");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(
            &r2,
            "#!/usr/bin/env sh\ncat <<'EOF'\n[{\"name\":\"sym.thumb_func\",\"offset\":16672,\"size\":4096,\"realsz\":32,\"maxaddr\":16674}]\n{\"addr\":16672,\"ops\":[{\"offset\":16672,\"bytes\":\"b5f0\",\"disasm\":\"push {r4, lr}\"}]}\nEOF\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = std::fs::metadata(&r2).unwrap().permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&r2, perm).unwrap();
        }

        let tools = thumb_tools(&r2);
        let summary =
            run_thumb_analysis(&tools, &[0u8; 0x180], 0x4000, &[(0x4120, 0x20)], &out).unwrap();
        let bytes = std::fs::read(out.join("thumb_functions.json")).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["format"], crate::thumb_analysis::THUMB_V3_FORMAT);
        assert_eq!(v["producers"][0]["id"], "radare2");
        assert_eq!(v["producers"][0]["version"], tools.radare2.version);
        assert_eq!(summary.substantial, 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn run_thumb_analysis_preserves_region_function_order_and_cleans_spills() {
        let dir = tempfile::tempdir().unwrap();
        let r2 = dir.path().join("r2");
        // Regions carve to thumb/<addr:08x>.bin, so the stub dispatches on the
        // carved blob name in its last argument.
        std::fs::write(
            &r2,
            "#!/usr/bin/env sh\ncase \"$*\" in *00004000.bin*) cat <<'EOF'\n[{\"name\":\"sym.a1\",\"offset\":16384,\"size\":4096,\"realsz\":64,\"maxaddr\":16386},{\"name\":\"sym.a2\",\"offset\":16448,\"size\":4096,\"realsz\":16,\"maxaddr\":16450}]\n{\"addr\":16384,\"ops\":[{\"offset\":16384,\"bytes\":\"b5f0\",\"disasm\":\"push {r4, lr}\"}]}\nEOF\n;; *) cat <<'EOF'\n[{\"name\":\"sym.b1\",\"offset\":32768,\"size\":4096,\"realsz\":64,\"maxaddr\":32770}]\n{\"addr\":32768,\"ops\":[{\"offset\":32768,\"bytes\":\"b5f0\",\"disasm\":\"push {r4, lr}\"}]}\nEOF\n;; esac\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = std::fs::metadata(&r2).unwrap().permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&r2, perm).unwrap();
        }
        let out = dir.path().join("out");
        std::fs::create_dir_all(&out).unwrap();
        let pdfj_a =
            json!({"addr":16384,"ops":[{"offset":16384,"bytes":"b5f0","disasm":"push {r4, lr}"}]});
        let pdfj_b =
            json!({"addr":32768,"ops":[{"offset":32768,"bytes":"b5f0","disasm":"push {r4, lr}"}]});
        let mut image = vec![0u8; 0x1_0000];
        populate_test_image_from_pdfj(&mut image, &pdfj_a);
        populate_test_image_from_pdfj(&mut image, &pdfj_b);
        let summary = run_thumb_analysis(
            &thumb_tools(&r2),
            &image,
            0,
            &[(0x4000, 0x100), (0x8000, 0x100)],
            &out,
        )
        .unwrap();
        let written = std::fs::read(out.join("thumb_functions.json")).unwrap();
        let artifact: serde_json::Value = serde_json::from_slice(&written).unwrap();
        assert_eq!(summary.substantial, 2);
        assert_eq!(summary.raw, 3);
        assert_eq!(summary.accepted, 2);
        assert_eq!(summary.quarantined, 1);
        assert_eq!(artifact["functions"][0]["name"], "sym.a1");
        assert_eq!(artifact["functions"][1]["name"], "sym.a2");
        assert_eq!(artifact["functions"][2]["name"], "sym.b1");
        assert_eq!(
            artifact["regions"][0]["function_runs"][0]["first_function"],
            0
        );
        assert_eq!(
            artifact["regions"][1]["function_runs"][0]["first_function"],
            2
        );
        let thumb = out.join("thumb");
        assert!(thumb.join("00004000.radare2.stdout").exists());
        assert!(thumb.join("00008000.radare2.stdout").exists());
        let leftovers: Vec<_> = std::fs::read_dir(&thumb)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".frags"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "spill files must be removed after assembly"
        );
    }

    fn scanner_values(stdout: &[u8]) -> Vec<serde_json::Value> {
        let mut scanner = ValueScanner::new(std::io::Cursor::new(stdout.to_vec()));
        let mut out = Vec::new();
        while let Some(bytes) = scanner.next_value().unwrap() {
            out.push(serde_json::from_str(&String::from_utf8_lossy(bytes)).unwrap());
        }
        out
    }

    #[test]
    fn scanner_matches_legacy_values_on_all_fixtures() {
        let fixtures: Vec<&[u8]> = vec![
            b"",
            b"Warning: noisy prelude\n[{\"name\":\"f\",\"offset\":1,\"size\":2,\"realsz\":2,\"maxaddr\":3}]\nINFO: tail\n",
            b"[{\"name\":\"f\",\"offset\":1,\"size\":2,\"realsz\":2,\"maxaddr\":3}]",
            b"[{ \"ops\": [] }]  [ { \"ops\": [ { \"offset\": 1 } ] } ]",
            b"{\"a\": \"has } ] { brackets [ inside \"} trailing",
            b"{\"a\": \"esc \\\" ] quote\"}[1,2,3]",
            b"[]not json at all[{\"x\":1}",
            b"[unbalanced {\"a\":1",
            b"[\"scalar\"]\n42\n\"str\"",
            b"[{\"deep\":[{\"deeper\":[1,2,{\"ops\":[]}]}]}]",
            b"{\"unicode\": \"\xc3\xa9\xf0\x9f\x98\x80\"} [\"after\"]",
            b"[{\"name\": \"caf\xc3\xa9\xed\xa0\x80\"}] [\"tail\"]",
            b"[{\"a\":1}}[{\"b\":2}]",
        ];
        for (i, fixture) in fixtures.iter().enumerate() {
            assert_eq!(
                scanner_values(fixture),
                radare2_json_values(fixture),
                "fixture {i}: {fixture:?}"
            );
        }
        assert_eq!(
            scanner_values(fixtures[2]).len(),
            1,
            "differential must be non-vacuous"
        );
    }

    #[test]
    fn scanner_survives_value_split_across_read_boundary() {
        struct ByteAtATime<R: Read>(R);
        impl<R: Read> Read for ByteAtATime<R> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.0.read(&mut buf[..1])
            }
        }
        let payload = b"noise[{\"a\":[1,2,3,{\"b\":\"}\\\"]\"}]}]noise{\"c\":1}";
        let mut scanner = ValueScanner::new(ByteAtATime(std::io::Cursor::new(payload.to_vec())));
        let mut values = Vec::new();
        while let Some(bytes) = scanner.next_value().unwrap() {
            values.push(serde_json::from_slice::<serde_json::Value>(bytes).unwrap());
        }
        assert_eq!(values.len(), 2);
    }

    #[test]
    fn scanner_borrows_stay_stable_until_next_call() {
        let payload = b"[{\"a\":1}] {\"b\":2}";
        let mut scanner = ValueScanner::new(std::io::Cursor::new(payload.to_vec()));
        let first = scanner.next_value().unwrap().unwrap().to_vec();
        let second = scanner.next_value().unwrap().unwrap().to_vec();
        assert_eq!(first, b"[{\"a\":1}]");
        assert_eq!(second, b"{\"b\":2}");
    }

    fn inventory_of(stdout: &[u8]) -> (usize, Option<Vec<FunctionRecord>>) {
        let mut scanner = ValueScanner::new(std::io::Cursor::new(stdout.to_vec()));
        scan_for_inventory(&mut scanner).unwrap()
    }

    #[test]
    fn inventory_scan_agrees_with_legacy_detection() {
        let fixtures: Vec<&[u8]> = vec![
            b"Warning: prelude\n[{\"name\":\"f0\",\"offset\":16384,\"size\":64,\"realsz\":64,\"maxaddr\":16386},{\"name\":\"f1\",\"offset\":16448,\"size\":2,\"realsz\":2,\"maxaddr\":16450}]",
            b"[]",
            b"[\"scalar\"]",
            b"[{\"ops\":[]}]",
            b"{\"ops\":[]}\n[{\"name\":\"f\",\"offset\":1,\"size\":2,\"realsz\":2,\"maxaddr\":3}]",
            b"no json",
            b"[{\"name\":\"f\",\"offset\":\"0x100\",\"size\":\"32\",\"realsz\":\"32\",\"maxaddr\":\"0x102\"}]",
        ];
        for (i, fixture) in fixtures.iter().enumerate() {
            let legacy_values = radare2_json_values(fixture);
            let legacy = legacy_values.iter().find(|v| is_aflj_function_inventory(v));
            let (count, records) = inventory_of(fixture);
            match (&legacy, &records) {
                (None, None) => {}
                (Some(l), Some(recs)) => {
                    assert_eq!(recs.len(), l.as_array().unwrap().len(), "fixture {i}")
                }
                other => panic!("fixture {i}: legacy vs streaming mismatch: {other:?}"),
            }
            assert_eq!(count, legacy_values.len(), "fixture {i} value count");
        }
    }

    #[test]
    fn inventory_scan_rejects_more_than_execution_function_limit() {
        use std::fmt::Write as _;

        let count = crate::execution_ranges::MAX_EXECUTION_FUNCTIONS + 1;
        let mut payload = String::with_capacity(count * 48);
        payload.push('[');
        for index in 0..count {
            if index != 0 {
                payload.push(',');
            }
            write!(payload, r#"{{"offset":4096,"maxaddr":4098,"realsz":2}}"#).unwrap();
        }
        payload.push(']');
        let mut scanner = ValueScanner::new(std::io::Cursor::new(payload.into_bytes()));

        let error = scan_for_inventory(&mut scanner).unwrap_err();

        assert!(
            error.to_string().contains("function count exceeds"),
            "{error}"
        );
    }

    #[test]
    fn inventory_records_adapt_radare2_boundary_fields() {
        let (_, records) = inventory_of(
            b"[{\"name\":\"f0\",\"offset\":16384,\"size\":64,\"realsz\":32,\"maxaddr\":16400},{\"offset\":\"0x40\"}]",
        );
        let records = records.unwrap();
        assert_eq!(
            records[0],
            FunctionRecord {
                entry: Some(16384),
                end: Some(16400),
                real_size: Some(32),
                bounding_size: Some(64),
                name: Some("f0".to_string())
            }
        );
        assert_eq!(
            records[1],
            FunctionRecord {
                entry: Some(0x40),
                end: None,
                real_size: None,
                bounding_size: None,
                name: None
            }
        );
    }

    #[test]
    fn fragment_render_matches_whole_document_pretty_slices() {
        let fns = vec![
            json!({"name":"thumb_a","entry":"0x100","end":"0x120","size":32,"body_kind":"thumb_disassembly","body":"","data_refs":[],"decode_ranges":[{"isa":"thumb","start":"0x100","end":"0x120"}],"decode_range_errors":[]}),
            json!({"name":"b","entry":"0x200","end":"0x208","size":8,"body_kind":"thumb_disassembly","body":"0x00000200      b5f0      push {r4, lr}\n","data_refs":["0x9000"],"decode_ranges":[],"decode_range_errors":[{"kind":"missing_operation_body","address":"0x200","end":null}]}),
        ];
        let whole = serde_json::to_string_pretty(&json!({
            "format": "pixel-modem-extractor-thumb-functions-v2",
            "functions": fns.clone(),
        }))
        .unwrap();
        let joined = fns
            .iter()
            .map(|f| render_fragment(f).unwrap())
            .collect::<Vec<_>>()
            .join(",\n");
        assert_eq!(
            format!(
                "{{\n  \"format\": \"pixel-modem-extractor-thumb-functions-v2\",\n  \"functions\": [\n{joined}\n  ]\n}}"
            ),
            whole
        );
    }

    #[test]
    fn fragment_render_handles_empty_containers_and_escapes() {
        let f = json!({"a": [], "b": {}, "s": "quote\" back\\slash\nnewline"});
        let rendered = render_fragment(&f).unwrap();
        let whole = serde_json::to_string_pretty(&json!({"functions": [f]})).unwrap();
        let inner = whole
            .trim_start_matches("{\n  \"functions\": [\n")
            .trim_end_matches("\n  ]\n}");
        assert_eq!(rendered, inner);
    }

    #[test]
    fn spill_roundtrip_preserves_fragments_in_fn_order() {
        let dir = tempfile::tempdir().unwrap();
        let mut writer = SpillWriter::create(dir.path().join("t.frags")).unwrap();
        writer.push(2, "frag-two").unwrap();
        writer.push(0, "frag-zero").unwrap();
        writer.push(1, "frag-one").unwrap();
        let spill = writer.finish().unwrap();
        let mut out = Vec::new();
        spill.emit(&mut out).unwrap();
        assert_eq!(out, b"frag-zerofrag-onefrag-two");
    }

    fn legacy_region_functions(
        stdout: &[u8],
        image: &[u8],
        load_addr: u32,
        addr: u32,
    ) -> Result<Vec<serde_json::Value>> {
        let parsed = parse_checked_radare2_thumb_output(stdout, addr)?;
        let mut all = Vec::new();
        for (f, pdfj) in &parsed.records {
            all.push(normalize_radare2_function_checked(
                f,
                pdfj.as_ref(),
                image,
                load_addr,
                addr,
            )?);
        }
        Ok(all)
    }

    fn in_memory_region_fragments(
        stdout: &[u8],
        image: &[u8],
        load_addr: u32,
        addr: u32,
    ) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        for (index, function) in legacy_region_functions(stdout, image, load_addr, addr)?
            .into_iter()
            .enumerate()
        {
            out.extend_from_slice(render_v3_fragment(&function, index)?.as_bytes());
        }
        Ok(out)
    }

    fn streaming_region_fragments(
        stdout: &[u8],
        image: &[u8],
        load_addr: u32,
        addr: u32,
    ) -> Result<Vec<u8>> {
        let dir = tempfile::tempdir().unwrap();
        let stdout_path = dir.path().join("capture.stdout");
        std::fs::write(&stdout_path, stdout).unwrap();
        let outcome = process_region_streaming(&stdout_path, image, load_addr, addr, dir.path())?;
        let mut out = Vec::new();
        outcome.spill.emit(&mut out)?;
        Ok(out)
    }

    #[test]
    fn streaming_region_matches_in_memory_oracle_on_all_fixtures() {
        let fixtures: Vec<&[u8]> = vec![
            // normal pair
            b"[{\"name\":\"sym.a\",\"offset\":16384,\"size\":64,\"realsz\":64,\"maxaddr\":16386},{\"name\":\"sym.b\",\"offset\":16448,\"size\":64,\"realsz\":64,\"maxaddr\":16450}]\n{\"addr\":16384,\"ops\":[{\"offset\":16384,\"bytes\":\"b5f0\",\"disasm\":\"push {r4, lr}\"}]}\n{\"addr\":16448,\"ops\":[{\"offset\":16448,\"bytes\":\"4770\",\"disasm\":\"bx lr\"}]}\n",
            // positional fallback: entry-less pdfj pairs by position
            b"[{\"name\":\"sym.a\",\"offset\":16384,\"size\":64,\"realsz\":64,\"maxaddr\":16386}]\n{\"ops\":[{\"offset\":16384,\"bytes\":\"b5f0\",\"disasm\":\"push {r4, lr}\"}]}\n",
            // pdfjs nested in an array after the inventory
            b"[{\"name\":\"sym.a\",\"offset\":16384,\"size\":64,\"realsz\":64,\"maxaddr\":16386},{\"name\":\"sym.b\",\"offset\":16448,\"size\":64,\"realsz\":64,\"maxaddr\":16450}]\n[{\"addr\":16384,\"ops\":[{\"offset\":16384,\"bytes\":\"b5f0\",\"disasm\":\"push\"}]},{\"addr\":16448,\"ops\":[{\"offset\":16448,\"bytes\":\"4770\",\"disasm\":\"bx lr\"}]}]\n",
            // duplicate entries: two fns and two pdfjs share one entry
            b"[{\"name\":\"sym.a\",\"offset\":16384,\"size\":64,\"realsz\":64,\"maxaddr\":16386},{\"name\":\"sym.a2\",\"offset\":16384,\"size\":32,\"realsz\":32,\"maxaddr\":16386}]\n{\"addr\":16384,\"ops\":[{\"offset\":16384,\"bytes\":\"b5f0\",\"disasm\":\"push\"}]}\n{\"addr\":16384,\"ops\":[{\"offset\":16384,\"bytes\":\"4770\",\"disasm\":\"bx lr\"}]}\n",
            // never-paired fn quarantines with empty body/data_refs
            b"[{\"name\":\"sym.a\",\"offset\":16384,\"size\":64,\"realsz\":64,\"maxaddr\":16386},{\"name\":\"sym.b\",\"offset\":16448,\"size\":64,\"realsz\":64,\"maxaddr\":16450}]\n{\"addr\":16448,\"ops\":[{\"offset\":16448,\"bytes\":\"4770\",\"disasm\":\"bx lr\"}]}\n",
            // leading + trailing noise
            b"Warning: noisy prelude\n[{\"name\":\"sym.a\",\"offset\":16384,\"size\":64,\"realsz\":64,\"maxaddr\":16386}]\n{\"addr\":16384,\"ops\":[{\"offset\":16384,\"bytes\":\"b5f0\",\"disasm\":\"push\"}]}\nINFO: tail\n",
            // entry-matched pdfj is NOT reused as positional fallback (pinned case)
            b"[{\"name\":\"sym.first\",\"offset\":16384,\"size\":64,\"realsz\":64,\"maxaddr\":16386},{\"name\":\"sym.second\",\"offset\":16448,\"size\":64,\"realsz\":64,\"maxaddr\":16450}]\n{\"addr\":16448,\"ops\":[{\"offset\":16448,\"bytes\":\"4770\",\"disasm\":\"bx lr\"}]}\n",
        ];
        for (i, stdout) in fixtures.iter().enumerate() {
            let mut image = vec![0u8; 0x1_0000];
            for (_, pdfj) in radare2_thumb_function_pdfjs(stdout) {
                populate_test_image_from_pdfj(&mut image, &pdfj);
            }
            let expected = in_memory_region_fragments(stdout, &image, 0, 0x4000)
                .unwrap_or_else(|e| panic!("fixture {i} in-memory: {e}"));
            let streaming = streaming_region_fragments(stdout, &image, 0, 0x4000)
                .unwrap_or_else(|e| panic!("fixture {i} streaming: {e}"));
            assert_eq!(expected, streaming, "fixture {i} must be byte-identical");
        }
    }

    #[test]
    fn streaming_region_error_messages_match_legacy() {
        let fixtures: Vec<&[u8]> = vec![
            b"",
            b"only noise\nand more noise",
            b"\"scalar\" 42",
            b"[{\"name\":\"x\",\"size\":8,\"realsz\":8,\"maxaddr\":2}]",
            b"[{\"name\":\"f\",\"offset\":16384,\"size\":64,\"realsz\":64,\"maxaddr\":16386}]\n{\"addr\":20480,\"ops\":[{\"offset\":20480,\"bytes\":\"00bf\",\"disasm\":\"nop\"}]}\n",
            b"[{\"name\":\"f\",\"offset\":8589934592,\"size\":64,\"realsz\":64,\"maxaddr\":8589934594}]",
            // nested-array pdfjs where one element never pairs: orphan verdict
            b"[{\"name\":\"sym.a\",\"offset\":16384,\"size\":64,\"realsz\":64,\"maxaddr\":16386}]\n[{\"addr\":16384,\"ops\":[{\"offset\":16384,\"bytes\":\"b5f0\",\"disasm\":\"push\"}]},{\"addr\":9999,\"ops\":[]}]\n",
        ];
        for (i, stdout) in fixtures.iter().enumerate() {
            let image = vec![0u8; 0x1_0000];
            let legacy = legacy_region_functions(stdout, &image, 0, 0x4000)
                .unwrap_err()
                .to_string();
            let streaming = streaming_region_fragments(stdout, &image, 0, 0x4000)
                .unwrap_err()
                .to_string();
            assert_eq!(legacy, streaming, "fixture {i} error strings must match");
        }
    }

    #[test]
    fn streaming_region_stats_match_document_derived_counts() {
        let stdout = b"[{\"name\":\"sym.a\",\"offset\":16384,\"size\":4096,\"realsz\":64,\"maxaddr\":16386},{\"name\":\"sym.b\",\"offset\":16448,\"size\":4096,\"realsz\":16,\"maxaddr\":16450}]\n{\"addr\":16384,\"ops\":[{\"offset\":16384,\"bytes\":\"b5f0\",\"disasm\":\"push {r4, lr}\"}]}\n";
        let mut image = vec![0u8; 0x1_0000];
        for (_, pdfj) in radare2_thumb_function_pdfjs(stdout) {
            populate_test_image_from_pdfj(&mut image, &pdfj);
        }
        let dir = tempfile::tempdir().unwrap();
        let stdout_path = dir.path().join("capture.stdout");
        std::fs::write(&stdout_path, stdout).unwrap();
        let outcome =
            process_region_streaming(&stdout_path, &image, 0, 0x4000, dir.path()).unwrap();
        let functions = legacy_region_functions(stdout, &image, 0, 0x4000).unwrap();
        let substantial = functions
            .iter()
            .filter(|f| f["size"].as_u64().unwrap_or(0) >= 32)
            .count();
        let accepted = functions
            .iter()
            .filter(|f| !f["decode_ranges"].as_array().unwrap().is_empty())
            .count();
        assert_eq!(outcome.stats.raw, functions.len());
        assert_eq!(outcome.stats.substantial, substantial);
        assert_eq!(outcome.stats.accepted, accepted);
    }

    /// Env-gated production replay for retained radare2 captures. V3
    /// intentionally changed function boundaries, so this checks that real
    /// inventories carry the required v3 fields and still normalize with
    /// conserving counts rather than comparing against legacy v2 bytes.
    #[test]
    fn streaming_replays_retained_production_thumb_captures_with_v3_boundaries() {
        let Ok(root) = std::env::var("PME_GOLDEN_DIR") else {
            return;
        };
        let decomposed = std::path::Path::new(&root);
        let main_dir = decomposed.join("images/02_MAIN/decompiled");
        let thumb_dir = main_dir.join("thumb");
        let image_path = decomposed.join("images/02_MAIN/02_MAIN.bin");
        if !thumb_dir.is_dir() || !image_path.is_file() {
            return;
        }
        let image = std::fs::read(&image_path).expect("read retained 02_MAIN.bin");
        let load_addr =
            crate::manifest::load_addr_for_image(&decomposed.join("manifest.json"), "02_MAIN")
                .expect("manifest parses")
                .expect("MAIN load addr present") as u32;
        let mut addrs: Vec<u32> = std::fs::read_dir(&thumb_dir)
            .expect("read thumb dir")
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| {
                let name = entry.file_name();
                let name = name.to_str()?;
                let stem = name
                    .strip_suffix(".radare2.stdout")
                    .or_else(|| name.strip_suffix(".stdout"))?;
                u32::from_str_radix(stem, 16).ok()
            })
            .collect();
        addrs.sort_unstable();
        assert!(!addrs.is_empty(), "retained tree carries thumb captures");
        let work = tempfile::tempdir().expect("tempdir");
        let mut total = 0usize;
        for addr in addrs {
            let capture = [
                thumb_dir.join(format!("{addr:08x}.radare2.stdout")),
                thumb_dir.join(format!("{addr:08x}.stdout")),
            ]
            .into_iter()
            .find(|path| path.is_file())
            .expect("retained capture path");
            let outcome = process_region_streaming(&capture, &image, load_addr, addr, work.path())
                .unwrap_or_else(|e| panic!("region 0x{addr:08x} replays: {e}"));
            assert!(outcome.stats.accepted <= outcome.stats.raw);
            total += outcome.stats.raw;
        }
        assert!(total > 0, "retained captures yielded no functions");
    }
}
