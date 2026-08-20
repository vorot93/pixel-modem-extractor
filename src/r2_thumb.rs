//! Streaming radare2 Thumb producer: carves dense-Thumb regions, streams r2
//! stdout to capped on-disk captures, and turns each capture into
//! `thumb_functions.json` with bounded memory (Stage 1 of the memory-envelope
//! lever; see the design spec under ~/.superpowers/pixel-modem-extractor/).

use crate::error::{Error, Result};
use crate::execution_ranges::{
    DecodeIsa, DecodeRange, DecodeRangeErrorKind, ExecutionIdentity, ExecutionProjection,
    TaggedExecutionRecord, ValidatedInventory, canonicalize_errors,
    canonicalize_instruction_extents, error, invalid, projection_to_json,
    validate_inventory_record,
};
use serde::Deserializer as _;
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::json;
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};

const THUMB_FUNCTIONS_FORMAT: &str = "pixel-modem-extractor-thumb-functions-v2";

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

fn pdfj_body(pdfj: &serde_json::Value) -> String {
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

fn radare2_function_entry(raw: &serde_json::Value) -> Option<u64> {
    raw.get("offset")
        .or_else(|| raw.get("addr"))
        .and_then(json_u64)
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

/// Streaming, noise-tolerant scanner for radare2 stdout: yields one
/// top-level JSON value's bytes at a time, byte-for-byte equivalent to the
/// legacy in-memory `radare2_json_values`/`balanced_json_end` pair (kept as
/// the `#[cfg(test)]` oracle). Memory is bounded by the largest single
/// top-level value plus one read chunk.
pub(super) struct ValueScanner<R> {
    reader: R,
    buf: Vec<u8>,
    eof: bool,
    out: Vec<u8>,
}

const SCANNER_CHUNK_BYTES: usize = 64 * 1024;

impl<R: Read> ValueScanner<R> {
    pub(super) fn new(reader: R) -> Self {
        Self {
            reader,
            buf: Vec::new(),
            eof: false,
            out: Vec::new(),
        }
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
                self.buf.clear();
                if !self.fill()? {
                    return Ok(None);
                }
                continue;
            }
            if noise > 0 {
                self.buf.drain(..noise);
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
                if !self.fill()? {
                    self.buf.drain(..1);
                }
                continue;
            };
            let text = String::from_utf8_lossy(&self.buf[..=end]);
            if serde_json::from_str::<serde::de::IgnoredAny>(&text).is_ok() {
                self.out.clear();
                self.out.extend_from_slice(&self.buf[..=end]);
                self.buf.drain(..=end);
                return Ok(Some(&self.out));
            }
            self.buf.drain(..1);
        }
    }
}

/// Compact per-function record from the aflj inventory — the only fields
/// `normalize_radare2_function_checked` consumes from the raw element.
/// Rebuilding a raw element from these fields reproduces the original
/// normalization byte-for-byte: both `json_u64` paths (number or numeric
/// string) resolve to the same u64, and a non-string `name` resolves to the
/// same default.
#[derive(Debug, Clone, PartialEq)]
struct FnRec {
    entry: Option<u64>,
    size: u64,
    name: Option<String>,
}

fn fn_rec_from_value(raw: &serde_json::Value) -> FnRec {
    FnRec {
        entry: radare2_function_entry(raw),
        size: raw.get("size").and_then(json_u64).unwrap_or(0),
        name: raw
            .get("name")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
    }
}

/// Sentinel aborting a seq probe when an element disqualifies the array as
/// the aflj inventory (non-object element, or an object carrying `ops`).
const NOT_INVENTORY: &str = "\u{0}pme-not-inventory";

fn parse_inventory_value(bytes: &[u8]) -> Option<Vec<FnRec>> {
    use serde::Deserializer;

    let text = String::from_utf8_lossy(bytes);
    let mut de = serde_json::Deserializer::from_str(&text);
    match de.deserialize_seq(InventoryProbe) {
        Ok(records) if !records.is_empty() => Some(records),
        _ => None,
    }
}

struct InventoryProbe;

impl<'de> serde::de::Visitor<'de> for InventoryProbe {
    type Value = Vec<FnRec>;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("aflj function inventory array")
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(
        self,
        mut seq: A,
    ) -> std::result::Result<Self::Value, A::Error> {
        let mut records = Vec::new();
        while let Some(element) = seq.next_element::<serde_json::Value>()? {
            let disqualified = match element.as_object() {
                None => true,
                Some(object) => object.contains_key("ops"),
            };
            if disqualified {
                return Err(serde::de::Error::custom(NOT_INVENTORY));
            }
            records.push(fn_rec_from_value(&element));
        }
        Ok(records)
    }
}

/// Stream values until the first aflj inventory; returns the count of values
/// seen and the compact records. Leaves the scanner positioned after the
/// inventory value. The count matches legacy `values.len()` for the zero
/// check because a found inventory implies >= 1 and an unfound one exhausts
/// the stream.
fn scan_for_inventory<R: Read>(
    scanner: &mut ValueScanner<R>,
) -> std::io::Result<(usize, Option<Vec<FnRec>>)> {
    let mut values = 0usize;
    while let Some(bytes) = scanner.next_value()? {
        values += 1;
        if let Some(records) = parse_inventory_value(bytes) {
            return Ok((values, Some(records)));
        }
    }
    Ok((values, None))
}

/// Render one normalized function `Value` as its bytes inside the final
/// document's `functions` array (depth 2: every pretty-printed line gets a
/// 4-space prefix). Byte-identity with `to_string_pretty` of the wrapped
/// document relies on serde_json's `Map` being a `BTreeMap` (sorted keys, no
/// `preserve_order` feature) and on pretty output being pure indentation —
/// pinned by tests.
fn render_fragment(value: &serde_json::Value) -> Result<String> {
    let pretty =
        serde_json::to_string_pretty(value).map_err(|e| Error::Serialize(e.to_string()))?;
    Ok(pretty
        .split('\n')
        .map(|line| format!("    {line}"))
        .collect::<Vec<_>>()
        .join("\n"))
}

/// One spilled fragment's location; the stream slot is
/// `[u32 LE fn_idx][u32 LE len][fragment bytes]`.
struct FragmentSlot {
    fn_idx: u32,
    offset: u64,
    len: u32,
}

/// Append-only per-region fragment spill at `thumb/<addr:08x>.frags`. Only
/// the `(fn_idx, offset, len)` index stays in memory (~16 B/function);
/// fragment text lives on disk until assembly.
struct SpillWriter {
    path: PathBuf,
    file: std::fs::File,
    offset: u64,
    slots: Vec<FragmentSlot>,
}

impl SpillWriter {
    fn create(path: PathBuf) -> std::io::Result<Self> {
        let file = std::fs::File::create(&path)?;
        Ok(Self {
            path,
            file,
            offset: 0,
            slots: Vec::new(),
        })
    }

    fn push(&mut self, fn_idx: u32, fragment: &str) -> std::io::Result<()> {
        let bytes = fragment.as_bytes();
        assert!(
            bytes.len() <= u32::MAX as usize,
            "fragment length overflows u32"
        );
        self.file.write_all(&fn_idx.to_le_bytes())?;
        self.file.write_all(&(bytes.len() as u32).to_le_bytes())?;
        self.file.write_all(bytes)?;
        self.slots.push(FragmentSlot {
            fn_idx,
            offset: self.offset + 8,
            len: bytes.len() as u32,
        });
        self.offset += 8 + bytes.len() as u64;
        Ok(())
    }

    fn finish(mut self) -> std::io::Result<Spill> {
        self.file.flush()?;
        let mut slots = self.slots;
        slots.sort_unstable_by_key(|slot| slot.fn_idx);
        Ok(Spill {
            path: self.path,
            slots,
        })
    }
}

/// A finished, readable spill: fragments stream back in `fn_idx` order (=
/// aflj order = the legacy emission order).
struct Spill {
    path: PathBuf,
    slots: Vec<FragmentSlot>,
}

impl Spill {
    fn emit_slot<W: Write>(&self, writer: &mut W, slot: &FragmentSlot) -> std::io::Result<()> {
        use std::io::Seek;
        let mut file = std::fs::File::open(&self.path)?;
        file.seek(std::io::SeekFrom::Start(slot.offset))?;
        let mut remaining = slot.len as usize;
        let mut buffer = vec![0u8; 64 * 1024];
        while remaining > 0 {
            let n = buffer.len().min(remaining);
            file.read_exact(&mut buffer[..n])?;
            writer.write_all(&buffer[..n])?;
            remaining -= n;
        }
        Ok(())
    }

    #[cfg(test)]
    fn emit<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        for slot in &self.slots {
            self.emit_slot(writer, slot)?;
        }
        Ok(())
    }
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

/// A region whose r2 run failed and was skipped fail-closed.
struct SkippedRegion {
    addr: u32,
    reason: String,
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

/// Process one captured `.stdout` with bounded memory: stream the inventory
/// into `FnRec`s (A), entry-match arriving pdfjs normalizing and spilling
/// immediately (B1), positional-fallback re-stream (B2), normalize the
/// never-paired remainder with `pdfj = None` (C), then the verdicts in the
/// legacy precedence order — no-JSON, unassignable, orphan, u32-domain.
/// Any `Err` removes the partial spill.
fn process_region_streaming(
    stdout_path: &Path,
    image: &[u8],
    load_addr: u32,
    addr: u32,
    thumb_dir: &Path,
) -> Result<RegionOutcome> {
    let spill_path = thumb_dir.join(format!("{addr:08x}.frags"));
    match process_region_inner(stdout_path, image, load_addr, addr, &spill_path) {
        Ok(outcome) => Ok(outcome),
        Err(error) => {
            let _ = std::fs::remove_file(&spill_path);
            Err(error)
        }
    }
}

fn process_region_inner(
    stdout_path: &Path,
    image: &[u8],
    load_addr: u32,
    addr: u32,
    spill_path: &Path,
) -> Result<RegionOutcome> {
    let file = std::fs::File::open(stdout_path)?;
    let mut scanner = ValueScanner::new(std::io::BufReader::new(file));

    // Pass A — compact inventory, then the legacy verdicts known up front.
    let (value_count, inventory) = scan_for_inventory(&mut scanner)?;
    if value_count == 0 {
        return Err(Error::Serialize(format!(
            "radare2 produced no parseable JSON for Thumb region 0x{addr:x}"
        )));
    }
    let Some(fns) = inventory else {
        return Err(Error::Serialize(format!(
            "radare2 produced parseable JSON but no aflj function inventory for Thumb region 0x{addr:x}"
        )));
    };
    let unassignable = fns.iter().filter(|f| f.entry.is_none()).count();
    if unassignable > 0 {
        return Err(Error::Serialize(format!(
            "radare2 reported {unassignable} unassignable aflj function {} for Thumb region 0x{addr:x}",
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
        substantial: fns.iter().filter(|f| f.size >= 32).count(),
        accepted: 0,
    };

    // B1 — entry-matching on the same scanner. Greedy first-unpaired-fn
    // assignment is equivalent to the legacy fn-outer scan: per entry key
    // both orderings pair the i-th fn of the key with the i-th pdfj of the
    // key; different keys never compete.
    for_each_pdfj_position(&mut scanner, |position, pdfj| {
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
            )?;
        }
        Ok(())
    })
    .map_err(region_iter_err)?;

    // B2 — positional fallback over a fresh stream of the same capture.
    let file = std::fs::File::open(stdout_path)?;
    let mut scanner = ValueScanner::new(std::io::BufReader::new(file));
    scan_for_inventory(&mut scanner)?; // deterministic re-detection; discard
    for_each_pdfj_position(&mut scanner, |position, pdfj| {
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
            )?;
        }
        Ok(())
    })
    .map_err(region_iter_err)?;

    // Verdicts in legacy precedence: orphan before u32-domain.
    let orphan = pdfj_used.iter().filter(|used| !**used).count();
    if orphan > 0 {
        return Err(Error::Serialize(format!(
            "radare2 produced {orphan} orphan pdfj {} for Thumb region 0x{addr:x}",
            if orphan == 1 { "body" } else { "bodies" }
        )));
    }
    if overflow.contains(&true) {
        return Err(Error::Serialize(format!(
            "radare2 function entry is outside the canonical u32 address domain for Thumb region 0x{addr:x}"
        )));
    }

    // Pass C — never-paired functions normalize with pdfj = None.
    for (fn_idx, rec) in fns.iter().enumerate() {
        if !paired[fn_idx] {
            normalize_and_spill(
                &mut spill, &mut stats, fn_idx, rec, None, image, load_addr, addr,
            )?;
        }
    }

    assert!(
        stats.accepted <= stats.raw,
        "radare2 Thumb projection count is not conserving for region 0x{addr:x}"
    );
    let spill = spill.finish()?;
    Ok(RegionOutcome { spill, stats })
}

/// Rebuild the minimal raw aflj element `normalize_radare2_function_checked`
/// consumes, normalize it, classify the projection from the emitted JSON
/// (exactly how `run_radare2_thumb` classified accepted), and spill the
/// fragment. `rec.entry` must be `Some` (unassignable rejected upstream).
#[allow(clippy::too_many_arguments)]
fn normalize_and_spill(
    spill: &mut SpillWriter,
    stats: &mut RegionStats,
    fn_idx: usize,
    rec: &FnRec,
    pdfj: Option<&serde_json::Value>,
    image: &[u8],
    load_addr: u32,
    addr: u32,
) -> Result<()> {
    let entry = rec.entry.expect("unassignable rejected upstream");
    let mut raw = serde_json::Map::new();
    raw.insert("offset".to_string(), json!(entry));
    raw.insert("size".to_string(), json!(rec.size));
    if let Some(name) = &rec.name {
        raw.insert("name".to_string(), json!(name));
    }
    let raw = serde_json::Value::Object(raw);
    let normalized = normalize_radare2_function_checked(&raw, pdfj, image, load_addr, addr)?;
    if normalized
        .get("decode_ranges")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|ranges| !ranges.is_empty())
    {
        stats.accepted += 1;
    }
    let fragment = render_fragment(&normalized)?;
    spill.push(fn_idx as u32, &fragment)?;
    Ok(())
}

/// Byte-exact framing of an assembled thumb-functions document, shared by the
/// streaming producer (`assemble_into`) and the streaming enricher:
/// `serde_json::to_string_pretty` of `{"format": ..., "functions": [...]}` with
/// a BTreeMap top level renders exactly these bytes (pinned by the
/// fragment-render tests).
const THUMB_DOC_OPEN: &[u8] =
    b"{\n  \"format\": \"pixel-modem-extractor-thumb-functions-v2\",\n  \"functions\": [\n";
const THUMB_DOC_CLOSE: &[u8] = b"\n  ]\n}";
const THUMB_DOC_EMPTY: &[u8] =
    b"{\n  \"format\": \"pixel-modem-extractor-thumb-functions-v2\",\n  \"functions\": []\n}";
const THUMB_DOC_FRAGMENT_SEP: &[u8] = b",\n";

/// Stream header, fragments (spills in region order, slots in fn order,
/// comma-newline joined), and footer into `writer`. Zero total fragments
/// renders the empty `functions` array inline, exactly as `to_string_pretty`.
fn assemble_into<W: Write>(writer: &mut W, spills: &[&Spill]) -> Result<()> {
    let total: usize = spills.iter().map(|spill| spill.slots.len()).sum();
    if total == 0 {
        writer.write_all(THUMB_DOC_EMPTY).map_err(Error::from)?;
        return Ok(());
    }
    writer.write_all(THUMB_DOC_OPEN).map_err(Error::from)?;
    let mut first = true;
    for spill in spills {
        for slot in &spill.slots {
            if !first {
                writer
                    .write_all(THUMB_DOC_FRAGMENT_SEP)
                    .map_err(Error::from)?;
            }
            first = false;
            spill.emit_slot(writer, slot).map_err(Error::from)?;
        }
    }
    writer.write_all(THUMB_DOC_CLOSE).map_err(Error::from)?;
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
    Ok(parsed)
}

fn check_radare2_thumb_status(success: bool, code: Option<i32>, addr: u32) -> Result<()> {
    if success {
        return Ok(());
    }
    let status = code
        .map(|code| format!("status {code}"))
        .unwrap_or_else(|| "unknown status".to_string());
    Err(Error::Serialize(format!(
        "radare2 exited with {status} for Thumb region 0x{addr:x}"
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

fn normalize_radare2_function_checked(
    raw: &serde_json::Value,
    pdfj: Option<&serde_json::Value>,
    image: &[u8],
    load_addr: u32,
    region_addr: u32,
) -> Result<serde_json::Value> {
    let entry_u64 = radare2_function_entry(raw).ok_or_else(|| {
        Error::Serialize(format!(
            "radare2 function lacks entry/addr for Thumb region 0x{region_addr:x}"
        ))
    })?;
    let size = raw.get("size").and_then(json_u64).unwrap_or(0);
    let name = raw
        .get("name")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| format!("thumb_{entry_u64:x}"));
    let entry = u32::try_from(entry_u64).map_err(|_| Error::Serialize(format!(
        "radare2 function entry is outside the canonical u32 address domain for Thumb region 0x{region_addr:x}"
    )))?;
    let projection = radare2_execution_projection(entry, pdfj, image, load_addr);
    let body = pdfj.map(pdfj_body).unwrap_or_default();
    let data_refs = pdfj.map(data_refs_from_pdfj).unwrap_or_default();
    let mut output = serde_json::json!({
        "name": name,
        "entry": json_hex(entry_u64),
        "end": json_hex(entry_u64.saturating_add(size)),
        "size": size,
        "body_kind": "thumb_disassembly",
        "body": body,
        "data_refs": data_refs,
    });
    let tags = projection_to_json(&projection)?;
    output
        .as_object_mut()
        .expect("JSON object")
        .extend(tags.as_object().expect("JSON object").clone());
    Ok(output)
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

fn radare2_execution_projection(
    entry: u32,
    pdfj: Option<&serde_json::Value>,
    image: &[u8],
    load_addr: u32,
) -> ExecutionProjection {
    let Some(pdfj) = pdfj else {
        return ExecutionProjection::Quarantined(vec![error(
            DecodeRangeErrorKind::MissingOperationBody,
            entry,
            None,
        )]);
    };
    let Some(ops) = pdfj.get("ops").and_then(serde_json::Value::as_array) else {
        return ExecutionProjection::Quarantined(vec![error(
            DecodeRangeErrorKind::EmptyProjection,
            entry,
            None,
        )]);
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
        extents.push(DecodeRange {
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
    match canonicalize_instruction_extents(
        entry,
        extents,
        load_addr,
        image.len().try_into().unwrap_or(u32::MAX),
    ) {
        ExecutionProjection::Accepted(ranges) if errors.is_empty() => {
            ExecutionProjection::Accepted(ranges)
        }
        ExecutionProjection::Accepted(_) => {
            ExecutionProjection::Quarantined(canonicalize_errors(errors))
        }
        ExecutionProjection::Quarantined(mut canonical_errors) => {
            canonical_errors.extend(errors);
            ExecutionProjection::Quarantined(canonicalize_errors(canonical_errors))
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

/// Defensive upper bound on a single Thumb region's r2 stdout. Grounded in
/// production: 02_MAIN's largest dense-Thumb region (`410b0000`, ~20 MiB
/// carved .bin, ~71 k functions) emits ~1.82 GiB of `aflj;pdfj @@f` JSON
/// (~25 KiB/function). 4 GiB is ~2× that peak, with headroom for r2 version
/// differences and slightly larger images. Exceeding it indicates genuine
/// r2 pathology (infinite loop, corrupt input triggering verbose output) —
/// fail-closed rather than OOM the host.
const R2_STDOUT_CAP_BYTES: usize = 4 * 1024 * 1024 * 1024;

/// Chunk size for `stream_to_cap`. Smaller than the typical Linux pipe
/// buffer (64 KiB since 2.6.11), so size checks fire promptly when r2 emits
/// fast; large enough that per-chunk write overhead is negligible.
const STREAM_CHUNK_BYTES: usize = 8 * 1024;

/// Stream up to `cap` bytes from `reader` to `writer`. Returns the number
/// of bytes written on EOF. If input would exceed `cap`, returns
/// `Err(io::Error)` with `ErrorKind::Other` and a cap-exceeded message;
/// the caller is responsible for process cleanup (kill, reap, remove
/// partial file).
///
/// Pure I/O — no child-process coupling, no filesystem assumptions. Testable
/// with `Cursor<Vec<u8>>` readers and `Vec<u8>` writers.
fn stream_to_cap<R: std::io::Read, W: std::io::Write>(
    reader: &mut R,
    writer: &mut W,
    cap: usize,
) -> std::io::Result<usize> {
    let mut chunk = vec![0u8; STREAM_CHUNK_BYTES];
    let mut written: usize = 0;
    loop {
        let n = reader.read(&mut chunk)?;
        if n == 0 {
            return Ok(written);
        }
        // Check before writing so we never write past the cap.
        if written + n > cap {
            // Write up to the cap (so the caller sees a partial file of
            // exactly `cap` bytes if they inspect it before cleanup).
            let allowed = cap - written;
            writer.write_all(&chunk[..allowed])?;
            return Err(std::io::Error::other(format!(
                "stream_to_cap: input exceeded {cap} bytes"
            )));
        }
        writer.write_all(&chunk[..n])?;
        written += n;
    }
}

/// Cap on radare2's own virtual address space (`RLIMIT_AS`) while it analyzes one
/// Thumb region. Grounded in measurement: healthy `aaa` on the densest real
/// regions peaks ~1.5 GiB RSS (mustang `02_MAIN`'s 19 MiB region) and completes,
/// while a pathological region — cheetah `01_MAIN`'s `0x42310000`, only 4 MiB —
/// runs away to 90+ GiB and OOM-kills the host. 16 GiB is ~10x the measured
/// healthy peak (ample headroom for larger images) yet far below the host RAM
/// needed for the rest of a full decompose anyway (Ghidra's JVM et al.; a
/// decompose peaked ~56 GiB back when r2 output was buffered whole — that
/// producer is streaming now), so a
/// runaway region hits the limit and fails closed (r2 gets `ENOMEM` and exits)
/// rather than exhausting host memory. Same "fail-closed rather than OOM the host"
/// intent as [`R2_STDOUT_CAP_BYTES`], but for r2's *own* memory rather than the
/// stdout we read back from it.
const R2_ADDRESS_SPACE_CAP_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// Apply [`R2_ADDRESS_SPACE_CAP_BYTES`] to `cmd` as a soft+hard `RLIMIT_AS`, so a
/// runaway radare2 is denied further allocations by the kernel and exits instead
/// of OOM-killing the host. Unix-only; a no-op elsewhere (Windows has no portable
/// per-child address-space limit — the same platform gap documented on
/// `spawn_in_own_process_group` in `decompile.rs`).
#[cfg(unix)]
fn limit_r2_address_space(cmd: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: the closure runs in the forked child between `fork(2)` and
    // `execvp(2)`. It calls only `setrlimit` (async-signal-safe) and reads a
    // `const`; it touches no shared state and allocates nothing.
    unsafe {
        cmd.pre_exec(|| {
            let limit = libc::rlimit {
                rlim_cur: R2_ADDRESS_SPACE_CAP_BYTES as libc::rlim_t,
                rlim_max: R2_ADDRESS_SPACE_CAP_BYTES as libc::rlim_t,
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
fn limit_r2_address_space(_cmd: &mut std::process::Command) {}

/// Analyze an image's dense Thumb-2 regions with radare2, streaming. Each
/// region is carved out, analyzed as ARM/Thumb (`-a arm -b 16`) based at
/// its load address, and its normalized functions spill to
/// `thumb/<addr:08x>.frags`; the final `thumb_functions.json` is assembled
/// atomically (complete-old-or-complete-new) from the spills in region
/// order / fn order — byte-identical to the former whole-`Value` rendering,
/// with peak memory O(largest single JSON value + one fragment) instead of
/// O(all functions). The carved blobs and `.stdout` captures are kept under
/// `out_dir/thumb/` for follow-up. Returns the count of substantial
/// (>= 32-byte) functions recovered. Per-region failures are tolerated:
/// one runaway region does not zero the others.
pub fn run_radare2_thumb(
    r2: &Path,
    image: &[u8],
    load_addr: u32,
    regions: &[(u32, u32)],
    out_dir: &Path,
) -> Result<usize> {
    let thumb_dir = out_dir.join("thumb");
    std::fs::create_dir_all(&thumb_dir)?;
    let mut spills: Vec<Spill> = Vec::new();
    let mut skipped: Vec<SkippedRegion> = Vec::new();
    let mut substantial = 0usize;
    let mut accepted = 0usize;
    let mut total = 0usize;
    for &(addr, len) in regions {
        match run_radare2_thumb_region(r2, image, load_addr, addr, len, &thumb_dir) {
            Ok(Some(outcome)) => {
                substantial += outcome.stats.substantial;
                accepted += outcome.stats.accepted;
                total += outcome.stats.raw;
                spills.push(outcome.spill);
            }
            Ok(None) => {}
            Err(reason) => skipped.push(SkippedRegion {
                addr,
                reason: reason.to_string(),
            }),
        }
    }
    for region in &skipped {
        tracing::warn!(
            "radare2: Thumb region 0x{:x} skipped (analysis failed, fail-closed): {}",
            region.addr,
            region.reason
        );
    }
    tracing::info!(
        "radare2: Thumb execution projections accepted={accepted} quarantined={} regions_skipped={}",
        total - accepted,
        skipped.len()
    );
    assemble_thumb_functions_json(&out_dir.join("thumb_functions.json"), &spills)?;
    Ok(substantial)
}

/// Atomically stream header → spills → footer into `thumb_functions.json`,
/// then delete the spills. A failure before `commit` leaves any prior file
/// intact.
fn assemble_thumb_functions_json(out_path: &Path, spills: &[Spill]) -> Result<()> {
    let refs: Vec<&Spill> = spills.iter().collect();
    let mut file = atomic_write_file::AtomicWriteFile::open(out_path)?;
    assemble_into(&mut file, &refs)?;
    file.commit()?;
    for spill in spills {
        let _ = std::fs::remove_file(&spill.path);
    }
    Ok(())
}

/// Analyze one dense Thumb-2 region with radare2 and return its finished
/// fragment spill plus per-region stats. Carves the region to
/// `thumb_dir/<addr>.bin`, runs `aaa;aflj;pdfj @@f` under
/// [`limit_r2_address_space`], streams stdout to a capped `<addr>.stdout`,
/// then processes that capture via [`process_region_streaming`]. Returns
/// `Err` on any per-region failure — r2 spawn/kill/non-zero exit (the
/// address-space cap firing lands here), a stdout-cap exceed, malformed
/// output, or a non-conserving projection; [`run_radare2_thumb`] records
/// those as skips rather than aborting. An empty region (offset past the
/// image end) yields `Ok(None)`.
fn run_radare2_thumb_region(
    r2: &Path,
    image: &[u8],
    load_addr: u32,
    addr: u32,
    len: u32,
    thumb_dir: &Path,
) -> Result<Option<RegionOutcome>> {
    let off = addr.wrapping_sub(load_addr) as usize;
    if off >= image.len() {
        return Ok(None);
    }
    let end = off.saturating_add(len as usize).min(image.len());
    let bin = thumb_dir.join(format!("{addr:08x}.bin"));
    std::fs::write(&bin, &image[off..end])?;
    // Stream r2 stdout to a per-region temp file. The file is kept after parse
    // for debugging (disk is cheap; --prune drops it with the rest of `thumb/`).
    // Cap is `R2_STDOUT_CAP_BYTES` (4 GiB) — see the const's doc comment.
    let mut cmd = std::process::Command::new(r2);
    cmd.args(["-a", "arm", "-b", "16", "-m"])
        .arg(format!("0x{addr:x}"))
        .args(["-q", "-c", "aaa;aflj;pdfj @@f"])
        .arg(&bin)
        .stderr(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped());
    limit_r2_address_space(&mut cmd);
    let mut child = cmd.spawn()?;
    let mut stdout = child.stdout.take().expect("piped stdout");
    let stdout_path = thumb_dir.join(format!("{addr:08x}.stdout"));
    let mut file = std::fs::File::create(&stdout_path)?;

    let cap_err = stream_to_cap(&mut stdout, &mut file, R2_STDOUT_CAP_BYTES);
    drop(file); // close + flush before any read-back or removal
    drop(stdout); // drop the pipe handle explicitly

    if let Err(e) = cap_err {
        // Cap exceeded OR genuine I/O error. Either way: kill, reap, remove the
        // partial file (no value in keeping truncated output), return Err. The
        // `ErrorKind::Other` discrimination is the cap-exceed signal from
        // `stream_to_cap`; a genuine I/O error could in rare cases also surface as
        // `Other`, but the cleanup path is identical, so a misclassification only
        // changes the error message.
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_file(&stdout_path);
        if e.kind() == std::io::ErrorKind::Other {
            return Err(Error::ToolNotFound(format!(
                "radare2 emitted > {R2_STDOUT_CAP_BYTES} bytes for region {addr:08x}; capped to prevent OOM"
            )));
        }
        // Genuine I/O error during streaming — propagate as Error::Io.
        return Err(e.into());
    }

    let status = child.wait()?;
    check_radare2_thumb_status(status.success(), status.code(), addr)?;

    process_region_streaming(&stdout_path, image, load_addr, addr, thumb_dir).map(Some)
}

/// Streaming validation of `thumb_functions.json` for the terminal-inventory
/// pair: identical verdicts, counts, and error strings to the former
/// whole-`Value` `read_json` leg, with memory bounded by one record (body
/// strings exist only in the transient per-element `Value`).
///
/// Requires the canonical shape of our own writer (`format` before
/// `functions`, no unknown or duplicate keys; serde_json's sorted BTreeMap
/// guarantees the order); anything else is rejected fail-closed. Semantic
/// verdicts are stashed during the scan and decided only after the whole
/// document parses, mirroring the legacy precedence — document parse error,
/// then shape, then first non-u64 size (the legacy fold aborts before the
/// mismatch check), then substantial mismatch, then first per-record
/// validation error in record order.
pub(crate) fn validate_thumb_inventory_streaming(
    thumb_functions_path: &Path,
    image_start: u32,
    image_len: u32,
    expected_substantial: usize,
) -> Result<(ValidatedInventory, usize)> {
    let file = std::fs::File::open(thumb_functions_path)?;
    let mut de = serde_json::Deserializer::from_reader(std::io::BufReader::new(file));
    let mut scan = ThumbScan::new(image_start, image_len);
    let parsed = de.deserialize_any(ThumbInventoryVisitor { scan: &mut scan });
    match parsed.and_then(|()| de.end()) {
        Ok(()) => scan.finish(expected_substantial),
        Err(error) => Err(map_thumb_validation_error(error)),
    }
}

/// Only genuine document parse failures reach this mapping; every semantic
/// verdict bypasses the serde channel so the legacy strings survive verbatim
/// (serde appends ` at line L column C` to custom visitor errors).
fn map_thumb_validation_error(error: serde_json::Error) -> Error {
    Error::Serialize(format!("parse Thumb functions inventory: {error}"))
}

/// Accumulates the streaming scan. Each error tier keeps only its first error
/// so later records cannot preempt an earlier verdict; tiers fire in the
/// legacy order at [`ThumbScan::finish`].
struct ThumbScan {
    image_start: u32,
    image_len: u32,
    raw_count: usize,
    substantial: usize,
    accepted: usize,
    quarantined: usize,
    accepted_identities: BTreeSet<ExecutionIdentity>,
    records: Vec<TaggedExecutionRecord>,
    saw_format: bool,
    saw_functions: bool,
    shape_error: Option<Error>,
    size_error: Option<Error>,
    validation_error: Option<Error>,
}

impl ThumbScan {
    fn new(image_start: u32, image_len: u32) -> Self {
        Self {
            image_start,
            image_len,
            raw_count: 0,
            substantial: 0,
            accepted: 0,
            quarantined: 0,
            accepted_identities: BTreeSet::new(),
            records: Vec::new(),
            saw_format: false,
            saw_functions: false,
            shape_error: None,
            size_error: None,
            validation_error: None,
        }
    }

    fn shape_invalid(&mut self, message: &str) {
        self.shape_error
            .get_or_insert_with(|| Error::Serialize(message.to_owned()));
    }

    fn record(&mut self, record: serde_json::Value) {
        self.raw_count += 1;
        if self.shape_error.is_some() {
            return;
        }
        if self.size_error.is_none() {
            let Some(size) = record.get("size").and_then(serde_json::Value::as_u64) else {
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
        match validate_inventory_record(&record, self.image_start, self.image_len) {
            Ok((tagged, _, identity)) => match identity {
                Some(identity) => match self.accepted.checked_add(1) {
                    Some(accepted) => {
                        self.accepted = accepted;
                        self.accepted_identities.insert(identity);
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

    fn finish(self, expected_substantial: usize) -> Result<(ValidatedInventory, usize)> {
        if let Some(error) = self.shape_error {
            return Err(error);
        }
        if let Some(error) = self.size_error {
            return Err(error);
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
        Ok((
            ValidatedInventory {
                raw_count: self.raw_count,
                accepted: self.accepted,
                quarantined: self.quarantined,
                accepted_identities: self.accepted_identities.into_iter().collect(),
                records: self.records,
            },
            self.substantial,
        ))
    }
}

struct ThumbInventoryVisitor<'a> {
    scan: &'a mut ThumbScan,
}

impl<'de, 'a> Visitor<'de> for ThumbInventoryVisitor<'a> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a Thumb functions inventory object")
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "format" if !self.scan.saw_format => {
                    self.scan.saw_format = true;
                    let value = map.next_value::<serde_json::Value>()?;
                    if value.as_str() != Some(THUMB_FUNCTIONS_FORMAT) {
                        self.scan
                            .shape_invalid("unsupported Thumb functions inventory format");
                    }
                }
                "functions" if self.scan.saw_format && !self.scan.saw_functions => {
                    self.scan.saw_functions = true;
                    map.next_value_seed(FunctionsSeq {
                        scan: &mut *self.scan,
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

struct FunctionsSeq<'a> {
    scan: &'a mut ThumbScan,
}

impl<'de, 'a> DeserializeSeed<'de> for FunctionsSeq<'a> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }
}

impl<'de, 'a> Visitor<'de> for FunctionsSeq<'a> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a Thumb functions array")
    }

    fn visit_seq<A>(self, mut seq: A) -> std::result::Result<(), A::Error>
    where
        A: SeqAccess<'de>,
    {
        while let Some(record) = seq.next_element::<serde_json::Value>()? {
            self.scan.record(record);
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

/// Phase 2: enrich a v1 (or v2 asm-only) `thumb_functions.json` with per-function
/// `body_c` sourced from a `decompiled.c`. Bumps `format` to v2 iff at least one
/// `body_c` is populated; otherwise leaves the file untouched. Idempotent;
/// returns the count of functions whose `body_c` was populated (including
/// re-population on an idempotent re-run).
///
/// `decompiled.c` is parsed by scanning for ExportDecomp.java's per-function
/// header line
///
/// ```text
/// // <name> @ <entrypoint>
/// <return-type> <name>(<params>)
/// {
///   ...
/// }
/// ```
///
/// and keying each captured body by the normalized entry address
/// (`normalize_thumb_addr` clears Ghidra's Thumb T-bit so `40e1201` and `40e1200`
/// agree). Matching against `thumb_functions.json` is likewise by the normalized
/// `entry` field — Phase 2.1 switched this from name-based to address-based
/// matching because radare2's `thumb_<addr>` names never align with Ghidra's
/// `FUN_<addr>`/recovered names.
///
/// Streaming, atomic, bounded: `decompiled.c` streams through
/// `collect_decompiled_c_bodies` and the JSON is rewritten through a
/// `serde_json` stream visitor into an `AtomicWriteFile` on the target path —
/// memory is bounded by the largest single body or function record, and the
/// output is byte-identical to the retired whole-file rewriter (kept test-only
/// as `thumb_enrich_whole`, the differential oracle). `populated == 0` discards
/// the uncommitted temp (`Drop` removes it) and leaves the original
/// byte-identical.
///
/// Fail-closed: a malformed `decompiled.c`, an unreadable or invalid-JSON
/// `thumb_functions.json`, or a document outside the canonical shape — an
/// object with exactly the keys `format` then `functions` (an array) — returns
/// `Err` with the on-disk file unchanged.
pub fn thumb_enrich(decompiled_c_path: &Path, thumb_functions_json_path: &Path) -> Result<usize> {
    let bodies = collect_decompiled_c_bodies(decompiled_c_path)?;
    let file = std::fs::File::open(thumb_functions_json_path)?;
    let mut de = serde_json::Deserializer::from_reader(std::io::BufReader::new(file));
    let mut scan = EnrichScan::new(
        &bodies,
        atomic_write_file::AtomicWriteFile::open(thumb_functions_json_path)?,
    );
    let parsed = de
        .deserialize_any(ThumbEnrichVisitor { scan: &mut scan })
        .and_then(|()| de.end());
    match parsed {
        Ok(()) => scan.finish_document()?,
        Err(error) => {
            return Err(scan.failure.take().unwrap_or_else(|| {
                Error::Serialize(format!(
                    "parse {}: {error}",
                    thumb_functions_json_path.display()
                ))
            }));
        }
    }
    let EnrichScan { out, populated, .. } = scan;
    if populated == 0 {
        return Ok(0);
    }
    out.commit()?;
    Ok(populated)
}

/// Abort sentinel for callback failures inside the enrich stream: the real,
/// typed error is stashed in `EnrichScan::failure` and this serde-channel copy
/// is never surfaced.
const ENRICH_STREAM_ABORT: &str = "\u{0}pme-enrich-stream-abort";

/// Rejects documents outside the canonical shape (an object with exactly the
/// keys `format` then `functions`, the latter an array); replaces the legacy
/// silent `Ok(0)` fail-open.
const NON_CANONICAL_THUMB_DOC: &str = "thumb functions document is not canonical: expected an object with exactly the keys format then functions";

/// Streaming rewrite state: enriches each `functions` element in arrival order
/// and frames the output document incrementally (open-list header before the
/// first fragment, footer at finish), so memory stays bounded by the largest
/// single element. The `AtomicWriteFile` temp is committed by the caller only
/// when at least one `body_c` was populated.
struct EnrichScan<'a> {
    bodies: &'a HashMap<String, String>,
    out: atomic_write_file::AtomicWriteFile,
    populated: usize,
    failure: Option<Error>,
    saw_format: bool,
    saw_functions: bool,
    wrote_open: bool,
}

impl<'a> EnrichScan<'a> {
    fn new(bodies: &'a HashMap<String, String>, out: atomic_write_file::AtomicWriteFile) -> Self {
        Self {
            bodies,
            out,
            populated: 0,
            failure: None,
            saw_format: false,
            saw_functions: false,
            wrote_open: false,
        }
    }

    /// Enrich one element exactly as the whole-file oracle did — match the
    /// `entry` field through `normalize_thumb_addr`, insert `body_c` on a hit,
    /// count it — then render and stream the fragment.
    fn enrich_element(&mut self, mut element: serde_json::Value) -> Result<()> {
        let mut enriched = false;
        if let Some(entry) = element.get("entry").and_then(serde_json::Value::as_str)
            && let Some(canonical) = normalize_thumb_addr(entry)
            && let Some(body) = self.bodies.get(&canonical)
        {
            element.as_object_mut().unwrap().insert(
                "body_c".to_string(),
                serde_json::Value::String(body.clone()),
            );
            enriched = true;
        }
        let fragment = render_fragment(&element)?;
        self.populated += usize::from(enriched);
        if self.wrote_open {
            self.out
                .write_all(THUMB_DOC_FRAGMENT_SEP)
                .map_err(Error::from)?;
        } else {
            self.out.write_all(THUMB_DOC_OPEN).map_err(Error::from)?;
            self.wrote_open = true;
        }
        self.out
            .write_all(fragment.as_bytes())
            .map_err(Error::from)?;
        Ok(())
    }

    fn finish_document(&mut self) -> std::io::Result<()> {
        if self.wrote_open {
            self.out.write_all(THUMB_DOC_CLOSE)
        } else {
            self.out.write_all(THUMB_DOC_EMPTY)
        }
    }
}

struct ThumbEnrichVisitor<'a, 'b> {
    scan: &'b mut EnrichScan<'a>,
}

impl<'de, 'a, 'b> Visitor<'de> for ThumbEnrichVisitor<'a, 'b> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a canonical thumb functions document")
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "format" if !self.scan.saw_format && !self.scan.saw_functions => {
                    self.scan.saw_format = true;
                    map.next_value::<IgnoredAny>()?;
                }
                "functions" if self.scan.saw_format && !self.scan.saw_functions => {
                    self.scan.saw_functions = true;
                    map.next_value_seed(FunctionsEnrichSeq {
                        scan: &mut *self.scan,
                    })?;
                }
                _ => return Err(serde::de::Error::custom(NON_CANONICAL_THUMB_DOC)),
            }
        }
        if !self.scan.saw_functions {
            return Err(serde::de::Error::custom(NON_CANONICAL_THUMB_DOC));
        }
        Ok(())
    }
}

struct FunctionsEnrichSeq<'a, 'b> {
    scan: &'b mut EnrichScan<'a>,
}

impl<'de, 'a, 'b> DeserializeSeed<'de> for FunctionsEnrichSeq<'a, 'b> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }
}

impl<'de, 'a, 'b> Visitor<'de> for FunctionsEnrichSeq<'a, 'b> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a thumb functions array")
    }

    fn visit_seq<A>(self, mut seq: A) -> std::result::Result<(), A::Error>
    where
        A: SeqAccess<'de>,
    {
        while let Some(element) = seq.next_element::<serde_json::Value>()? {
            if let Err(error) = self.scan.enrich_element(element) {
                self.scan.failure = Some(error);
                return Err(serde::de::Error::custom(ENRICH_STREAM_ABORT));
            }
        }
        Ok(())
    }
}

/// Retired whole-file `thumb_enrich`, kept verbatim as the differential oracle
/// for the streaming rewrite; test-only.
#[cfg(test)]
fn thumb_enrich_whole(decompiled_c_path: &Path, thumb_functions_json_path: &Path) -> Result<usize> {
    // std::io::Error auto-converts via Error::Io(#[from]) — `?` propagates directly.
    let c_text = std::fs::read_to_string(decompiled_c_path)?;

    // Phase 2.1: parse decompiled.c into {normalized_entry_address -> body_text}.
    let bodies = parse_decompiled_c_function_bodies_by_addr(&c_text);

    // Read thumb_functions.json, augment in memory, decide whether to rewrite.
    let raw = std::fs::read(thumb_functions_json_path)?;
    let mut v: serde_json::Value = serde_json::from_slice(&raw).map_err(|e| {
        Error::Serialize(format!(
            "parse {}: {e}",
            thumb_functions_json_path.display()
        ))
    })?;

    let mut populated = 0usize;
    if let Some(funcs) = v.get_mut("functions").and_then(|f| f.as_array_mut()) {
        for f in funcs {
            // Phase 2.1: match by `entry` (address), not by `name`. The `name`
            // field is radare2's `thumb_<addr>` placeholder and never aligns
            // with Ghidra's `FUN_<addr>`/recovered names — Phase 2's bug.
            let Some(entry_str) = f.get("entry").and_then(|n| n.as_str()) else {
                continue;
            };
            let Some(canonical) = normalize_thumb_addr(entry_str) else {
                continue;
            };
            if let Some(body) = bodies.get(&canonical) {
                f.as_object_mut().unwrap().insert(
                    "body_c".to_string(),
                    serde_json::Value::String(body.clone()),
                );
                populated += 1;
            }
        }
    }

    if populated == 0 {
        return Ok(0); // Leave file byte-identical (do not rewrite).
    }

    // Bump format to v2 on first population.
    if let Some(obj) = v.as_object_mut() {
        obj.insert(
            "format".to_string(),
            serde_json::Value::String("pixel-modem-extractor-thumb-functions-v2".to_string()),
        );
    }

    let out = serde_json::to_string_pretty(&v)
        .map_err(|e| Error::Serialize(format!("re-serialize thumb_functions.json: {e}")))?;
    std::fs::write(thumb_functions_json_path, out)?;
    Ok(populated)
}

/// Canonical comparison form for a Thumb entry address: lowercase hex string
/// with no `0x` prefix, no leading zeros, low bit cleared (kills Ghidra's Thumb
/// T-bit so `40e1201` and `40e1200` both become `40e1200`). Returns None if `s`
/// doesn't parse as a non-empty hex string.
///
/// This is the **Phase 2.1 invariant** — both `thumb_enrich`'s parser (over
/// `decompiled.c`'s `// <name> @ <addr>` headers) and matcher (over
/// `thumb_functions.json`'s `entry` fields) MUST apply the same normalization,
/// or matching silently breaks. The inline `thumb_enrich_populates_body_c_
/// with_tbit_set` test is the regression sentinel.
fn normalize_thumb_addr(s: &str) -> Option<String> {
    let trimmed = s.trim();
    let stripped = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if stripped.is_empty() || !stripped.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let val = u64::from_str_radix(stripped, 16).ok()?;
    Some(format!("{:x}", val & !1))
}

#[cfg(test)]
mod normalize_thumb_addr_tests {
    use super::*;

    #[test]
    fn strips_0x_prefix_and_leading_zeros() {
        assert_eq!(
            normalize_thumb_addr("0x000040e1200").as_deref(),
            Some("40e1200")
        );
        assert_eq!(
            normalize_thumb_addr("0X40E1200").as_deref(),
            Some("40e1200")
        );
        assert_eq!(normalize_thumb_addr("40e1200").as_deref(), Some("40e1200"));
    }

    #[test]
    fn clears_thumb_tbit() {
        assert_eq!(
            normalize_thumb_addr("0x40e1201").as_deref(),
            Some("40e1200")
        );
        assert_eq!(
            normalize_thumb_addr("00040e1201").as_deref(),
            Some("40e1200")
        );
    }

    #[test]
    fn rejects_non_hex() {
        assert_eq!(normalize_thumb_addr("not-an-addr"), None);
        assert_eq!(normalize_thumb_addr(""), None);
        assert_eq!(normalize_thumb_addr("0xZZZ"), None);
    }
}

/// Parse a `decompiled.c` text into a map of `{normalized_entry_address ->
/// body_text}`, where `body_text` is the full function including signature and
/// braces. ExportDecomp.java emits one header per function:
///
/// ```text
/// // <name> @ <entrypoint>
/// <return-type> <name>(<params>)
/// {
///   ...
/// }
/// ```
///
/// where `<entrypoint>` is `fn.getEntryPoint().toString()`. For ARM Thumb in
/// Ghidra 12 with `ARM:LE:32:v7`, Thumb entry points carry the T-bit (odd);
/// `normalize_thumb_addr` clears it so the canonical key matches radare2's
/// even-form `entry` field. Functions whose header lacks ` @ <addr>` are
/// silently skipped (no key to insert under) — same fail-soft posture as the
/// prior name-based parser. Retired from production by
/// `collect_decompiled_c_bodies`; kept as the whole-string differential
/// oracle, test-only.
#[cfg(test)]
fn parse_decompiled_c_function_bodies_by_addr(c_text: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let lines: Vec<&str> = c_text.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        // Match the ExportDecomp header: starts with `//`, contains ` @ `.
        let addr_str = line
            .trim()
            .strip_prefix("//")
            .and_then(|rest| rest.rsplit_once(" @ "))
            .map(|(_, addr)| addr.trim())
            .filter(|addr| !addr.is_empty());
        let Some(addr_str) = addr_str else {
            i += 1;
            continue;
        };
        // Bounded lookahead: commit only when `{` appears within the next 1–8
        // lines. Real ExportDecomp.java output is bi-modal: offset-4 headers
        // (single-line signatures, ~58% of production 02_MAIN) and offset-6
        // headers (2-line signatures, ~35%). The 8-line bound captures 99.6% of
        // real headers in the production histogram. Without this bound, a header-shaped
        // non-header could commit at position N and absorb following lines into
        // the wrong address's body until the next real function's `{` — same
        // rationale as the prior parser's lookahead.
        let start = i;
        let opens_brace_within_8 =
            (start + 1..std::cmp::min(start + 9, lines.len())).any(|j| lines[j].contains('{'));
        if !opens_brace_within_8 {
            i = start + 1;
            continue;
        }
        // Capture from this line through the matching closing brace at depth 0.
        // State machine tracks string/char literals + line/block comments so a `}`
        // inside `"expected }"`, `'}'`, or `// close }` doesn't truncate the body.
        // Mirrors the string-aware scanning used by the production
        // `r2_thumb::ValueScanner` (`balanced_json_end` is its `#[cfg(test)]`
        // oracle).
        let mut depth = 0i32;
        let mut saw_brace = false;
        let mut body = String::new();
        let mut in_string = false;
        let mut in_char = false;
        let mut escaped = false;
        let mut in_block_comment = false;
        while i < lines.len() {
            let l = lines[i];
            let mut chars = l.chars().peekable();
            while let Some(ch) = chars.next() {
                if in_block_comment {
                    if ch == '*' && chars.peek() == Some(&'/') {
                        chars.next();
                        in_block_comment = false;
                    }
                    continue;
                }
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
                if in_char {
                    if escaped {
                        escaped = false;
                    } else if ch == '\\' {
                        escaped = true;
                    } else if ch == '\'' {
                        in_char = false;
                    }
                    continue;
                }
                match ch {
                    '"' => in_string = true,
                    '\'' => in_char = true,
                    '/' => {
                        if chars.peek() == Some(&'/') {
                            chars.next();
                            break; // rest of line is a line comment
                        } else if chars.peek() == Some(&'*') {
                            chars.next();
                            in_block_comment = true;
                        }
                    }
                    '{' => {
                        depth += 1;
                        saw_brace = true;
                    }
                    '}' => depth -= 1,
                    _ => {}
                }
            }
            body.push_str(l);
            body.push('\n');
            if saw_brace && depth <= 0 {
                break;
            }
            i += 1;
        }
        if let Some(canonical) = normalize_thumb_addr(addr_str) {
            out.insert(canonical, body);
        }
        i += 1;
    }
    out
}

/// Streaming Pass-1 body collector for `thumb_enrich`: implements the exact
/// grammar of the whole-string oracle
/// `parse_decompiled_c_function_bodies_by_addr` (the differential fixtures pin
/// the equivalence) but reads `decompiled.c` line-by-line through `BufReader` —
/// never whole-file — so memory is bounded by the largest single body plus an
/// 8-line lookahead window. Any io failure (missing file, non-UTF-8 input)
/// propagates as `Err` (same failure class as the oracle-side
/// `read_to_string?`).
fn collect_decompiled_c_bodies(path: &Path) -> Result<HashMap<String, String>> {
    let file = std::fs::File::open(path)?;
    let mut source = LineSource::new(std::io::BufReader::new(file));
    let mut out = HashMap::new();
    while let Some(line) = source.next_line()? {
        let Some(addr_str) = decompiled_c_header_addr(&line) else {
            continue;
        };
        let mut window: VecDeque<String> = VecDeque::with_capacity(8);
        let mut opens_brace = false;
        while window.len() < 8 {
            let Some(next) = source.next_line()? else {
                break;
            };
            opens_brace |= next.contains('{');
            window.push_back(next);
            if opens_brace {
                break;
            }
        }
        if !opens_brace {
            source.push_front_all(window);
            continue;
        }
        let mut scan = BodyScan::default();
        let mut body = String::new();
        let mut closed = scan.push_line(&line, &mut body);
        while !closed {
            let next = window
                .pop_front()
                .map_or_else(|| source.next_line(), |line| Ok(Some(line)));
            let Some(next) = next? else { break };
            closed = scan.push_line(&next, &mut body);
        }
        source.push_front_all(window);
        if let Some(canonical) = normalize_thumb_addr(addr_str) {
            out.insert(canonical, body);
        }
    }
    Ok(out)
}

/// ExportDecomp.java header shape, as the oracle matches it: a trimmed line
/// starting `//`, the last ` @ ` occurrence as separator, and a non-empty
/// trimmed address tail.
fn decompiled_c_header_addr(line: &str) -> Option<&str> {
    line.trim()
        .strip_prefix("//")
        .and_then(|rest| rest.rsplit_once(" @ "))
        .map(|(_, addr)| addr.trim())
        .filter(|addr| !addr.is_empty())
}

/// Line reader with a pushback queue: lines consumed while probing a
/// lookahead window can be re-scanned as headers, mirroring the oracle's
/// resume rule (a header without `{` in its window restarts at the very
/// next line).
struct LineSource<B: BufRead> {
    lines: std::io::Lines<B>,
    pushback: VecDeque<String>,
}

impl<B: BufRead> LineSource<B> {
    fn new(reader: B) -> Self {
        Self {
            lines: reader.lines(),
            pushback: VecDeque::new(),
        }
    }

    fn next_line(&mut self) -> std::io::Result<Option<String>> {
        if let Some(line) = self.pushback.pop_front() {
            return Ok(Some(line));
        }
        self.lines.next().transpose()
    }

    fn push_front_all(&mut self, lines: VecDeque<String>) {
        for line in lines.into_iter().rev() {
            self.pushback.push_front(line);
        }
    }
}

/// Per-body brace scanner: a line closes the body iff an opening brace was
/// seen and brace depth — counted string-, char-, and comment-aware over the
/// whole line — is <= 0. Scan state persists across a body's lines; each
/// body starts from a fresh scan.
#[derive(Default)]
struct BodyScan {
    depth: i32,
    saw_brace: bool,
    in_string: bool,
    in_char: bool,
    escaped: bool,
    in_block_comment: bool,
}

impl BodyScan {
    /// Scan `line`, append it (plus '\n') to `body`, and report whether the
    /// body is complete after it.
    fn push_line(&mut self, line: &str, body: &mut String) -> bool {
        let mut chars = line.chars().peekable();
        while let Some(ch) = chars.next() {
            if self.in_block_comment {
                if ch == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    self.in_block_comment = false;
                }
                continue;
            }
            if self.in_string {
                if self.escaped {
                    self.escaped = false;
                } else if ch == '\\' {
                    self.escaped = true;
                } else if ch == '"' {
                    self.in_string = false;
                }
                continue;
            }
            if self.in_char {
                if self.escaped {
                    self.escaped = false;
                } else if ch == '\\' {
                    self.escaped = true;
                } else if ch == '\'' {
                    self.in_char = false;
                }
                continue;
            }
            match ch {
                '"' => self.in_string = true,
                '\'' => self.in_char = true,
                '/' => {
                    if chars.peek() == Some(&'/') {
                        chars.next();
                        break;
                    } else if chars.peek() == Some(&'*') {
                        chars.next();
                        self.in_block_comment = true;
                    }
                }
                '{' => {
                    self.depth += 1;
                    self.saw_brace = true;
                }
                '}' => self.depth -= 1,
                _ => {}
            }
        }
        body.push_str(line);
        body.push('\n');
        self.saw_brace && self.depth <= 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_radare2_function_records_body_and_refs() {
        let raw = serde_json::json!({
            "name": "sym.thumb_func",
            "offset": 0x4120u64,
            "size": 48u64
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
            serde_json::json!([{"isa":"thumb", "start":"0x4120", "end":"0x4124"}]),
            "out-of-order pdfj operations must normalize into an exact tagged Thumb range"
        );
        assert_eq!(entry["decode_range_errors"], serde_json::json!([]));
    }

    #[test]
    fn radare2_pdfj_quarantines_all_faults_without_salvaging_a_prefix() {
        let pdfj = serde_json::json!({"ops": [
            {"offset": 0x4000u64, "bytes": "00bf"},
            {"offset": 0x4002u64, "bytes": "0"},
            {"offset": 0x4003u64, "bytes": "00bf"},
            {"offset": 0x4010u64, "bytes": "00bf"}
        ]});
        let projection = radare2_execution_projection(0x4000, Some(&pdfj), &[0; 8], 0x4000);
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
        let projection = radare2_execution_projection(
            0x4000,
            Some(&pdfj),
            &[0x00, 0xbf, 0xf0, 0xb5, 0x00, 0x00],
            0x4000,
        );
        assert_eq!(
            projection_to_json(&projection).unwrap(),
            serde_json::json!({
                "decode_ranges": [{"isa":"thumb", "start":"0x4000", "end":"0x4006"}],
                "decode_range_errors": [],
            })
        );
    }

    #[test]
    fn radare2_pdfj_preserves_gaps_and_ignores_legacy_size_as_an_extent() {
        let raw = serde_json::json!({"offset": 0x4000u64, "size": 0x1000u64});
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
        assert_eq!(entry["size"], 0x1000);
        assert_eq!(
            entry["decode_ranges"],
            serde_json::json!([
                {"isa":"thumb", "start":"0x4000", "end":"0x4002"},
                {"isa":"thumb", "start":"0x4004", "end":"0x4006"}
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
                radare2_execution_projection(entry, Some(&pdfj), image, 0x4000)
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
        let projection = radare2_execution_projection(0x4000, None, &[0, 0], 0x4000);
        assert_eq!(
            projection_to_json(&projection).unwrap(),
            serde_json::json!({
                "decode_ranges": [],
                "decode_range_errors": [{"kind":"missing_operation_body", "address":"0x4000", "end":null}],
            })
        );
    }

    #[test]
    fn stream_to_cap_streams_chunks_until_eof() {
        let input = vec![0xABu8; 100 * 1024]; // 100 KiB
        let mut reader = std::io::Cursor::new(&input[..]);
        let mut writer: Vec<u8> = Vec::new();
        let n = stream_to_cap(&mut reader, &mut writer, 1024 * 1024).unwrap();
        assert_eq!(n, 100 * 1024);
        assert_eq!(writer, input);
    }

    #[test]
    fn stream_to_cap_returns_err_on_cap_exceed() {
        let cap = 1024;
        let input = vec![0xCDu8; cap + 1];
        let mut reader = std::io::Cursor::new(&input[..]);
        let mut writer: Vec<u8> = Vec::new();
        let err = stream_to_cap(&mut reader, &mut writer, cap).unwrap_err();
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
    fn stream_to_cap_handles_empty_input() {
        let mut reader = std::io::Cursor::new(b"" as &[u8]);
        let mut writer: Vec<u8> = Vec::new();
        let n = stream_to_cap(&mut reader, &mut writer, 1024).unwrap();
        assert_eq!(n, 0);
        assert!(writer.is_empty());
    }

    #[test]
    fn stream_to_cap_handles_exact_cap_input() {
        // Equal-to-cap is OK; exceeds is not. Boundary sentinel.
        let cap = 4096;
        let input = vec![0xEFu8; cap];
        let mut reader = std::io::Cursor::new(&input[..]);
        let mut writer: Vec<u8> = Vec::new();
        let n = stream_to_cap(&mut reader, &mut writer, cap).unwrap();
        assert_eq!(n, cap);
        assert_eq!(writer, input);
    }

    #[test]
    fn r2_stdout_cap_bytes_is_4_gib() {
        // Regression sentinel against accidental value drift.
        assert_eq!(R2_STDOUT_CAP_BYTES, 4 * 1024 * 1024 * 1024);
    }

    #[cfg(unix)]
    #[test]
    fn r2_address_space_cap_is_applied_to_child_process() {
        // `limit_r2_address_space` must set RLIMIT_AS on the spawned child so a
        // runaway r2 gets ENOMEM (and fails closed) instead of OOM-killing the
        // host. Observe it through a child `ulimit -v`, which reports the soft
        // address-space limit in KiB.
        let mut cmd = std::process::Command::new("bash");
        cmd.args(["-c", "ulimit -v"]);
        limit_r2_address_space(&mut cmd);
        let out = cmd.output().expect("spawn bash for ulimit probe");
        let printed = String::from_utf8_lossy(&out.stdout);
        let expected_kib = (R2_ADDRESS_SPACE_CAP_BYTES / 1024).to_string();
        assert_eq!(printed.trim(), expected_kib);
    }

    #[test]
    fn one_failed_thumb_region_does_not_drop_the_others() {
        // A region whose r2 run fails (spawn/kill/address-space-cap/malformed
        // output) is recorded and skipped, never aborting the stage: the sibling
        // regions' functions still reach thumb_functions.json. Regression guard
        // for the address-space-cap fail-closed path — one runaway region (e.g.
        // cheetah 01_MAIN 0x42310000) must degrade Thumb coverage locally, not
        // zero it out. Exercises the production fold in `run_radare2_thumb`
        // through a stub r2 that fails exactly one region by its -m address.
        let dir = std::env::temp_dir().join(format!("pme_r2_skip_one_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let r2 = dir.join("r2");
        let out = dir.join("out");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(
            &r2,
            "#!/usr/bin/env sh\ncase \" $* \" in\n  *\" -m 0x4120 \"*) exit 139;;\n  *) printf '%s\\n' '[{\"name\":\"sym.thumb_func\",\"offset\":16672,\"size\":64}]' '{\"addr\":16672,\"ops\":[{\"offset\":16672,\"bytes\":\"b5f0\",\"disasm\":\"push {r4, lr}\"}]}';;\nesac\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = std::fs::metadata(&r2).unwrap().permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&r2, perm).unwrap();
        }

        let count = run_radare2_thumb(
            &r2,
            &[0u8; 0x180],
            0x4000,
            &[(0x4100, 0x20), (0x4120, 0x20), (0x4140, 0x20)],
            &out,
        )
        .unwrap();

        assert_eq!(count, 2, "surviving regions' functions must be kept");
        let bytes = std::fs::read(out.join("thumb_functions.json")).unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let functions = doc["functions"].as_array().unwrap();
        assert_eq!(functions.len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn noisy_radare2_stdout_still_pairs_and_normalizes_pdfj() {
        let stdout = br#"Warning: run r2 with -e bin.cache=true
[{"name":"sym.thumb_func","offset":16672,"size":48}]
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
    }

    #[test]
    fn radare2_thumb_retains_known_functions_without_parseable_pdfj_bodies() {
        let stdout = b"Warning: noisy prelude
[{\"name\":\"sym.thumb_func\",\"offset\":16384,\"size\":64}]
INFO: no pdfj body followed
";

        let parsed = parse_checked_radare2_thumb_output(stdout, 0x4000).unwrap();
        assert_eq!(parsed.records.len(), 1);
        assert!(
            parsed.records[0].1.is_none(),
            "missing bodies are record quarantines, not producer failure"
        );
    }

    #[test]
    fn radare2_thumb_retains_paired_empty_pdfj_body_for_quarantine() {
        let stdout = br#"Warning: noisy prelude
[{"name":"sym.thumb_func","offset":16384,"size":64}]
{"addr":16384,"ops":[]}
"#;

        let parsed = parse_checked_radare2_thumb_output(stdout, 0x4000).unwrap();
        assert_eq!(parsed.records.len(), 1);
        assert!(parsed.records[0].1.is_some());
    }

    #[test]
    fn radare2_thumb_retains_partial_pdfj_recovery_for_per_record_quarantine() {
        let stdout = br#"Warning: noisy prelude
[{"name":"sym.first","offset":16384,"size":64},{"name":"sym.second","offset":16448,"size":64}]
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
[{"name":"sym.first","offset":16384,"size":64},{"name":"sym.second","offset":16448,"size":64}]
{"addr":16448,"ops":[{"offset":16448,"bytes":"4770","disasm":"bx lr"}]}
"#;

        let parsed = parse_checked_radare2_thumb_output(stdout, 0x4000).unwrap();
        assert!(parsed.records[0].1.is_none());
        assert!(parsed.records[1].1.is_some());
    }

    #[test]
    fn radare2_thumb_rejects_positional_pdfj_with_different_parseable_entry() {
        let stdout = br#"Warning: noisy prelude
[{"name":"sym.first","offset":16384,"size":64},{"name":"sym.second","offset":16448,"size":64}]
{"addr":20480,"ops":[{"offset":20480,"bytes":"00bf","disasm":"nop"}]}
{"addr":16448,"ops":[{"offset":16448,"bytes":"4770","disasm":"bx lr"}]}
"#;

        let err = parse_checked_radare2_thumb_output(stdout, 0x4000).unwrap_err();

        assert!(matches!(err, Error::Serialize(message) if message.contains("orphan pdfj")));
    }

    #[test]
    fn radare2_thumb_rejects_non_zero_process_status() {
        let err = check_radare2_thumb_status(false, Some(7), 0x4000).unwrap_err();

        assert!(
            matches!(err, Error::Serialize(message) if message.contains("exited with status 7"))
        );
    }

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
            "#!/usr/bin/env sh\nprintf '%s\\n' \"$@\" > \"$0.argv\"\ncat <<'EOF'\n[{\"name\":\"sym.thumb_func\",\"offset\":16672,\"size\":64}]\n{\"addr\":16672,\"ops\":[{\"offset\":16672,\"bytes\":\"b5f0\",\"disasm\":\"push {r4, lr}\"}]}\nEOF\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = std::fs::metadata(&r2).unwrap().permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&r2, perm).unwrap();
        }

        let count = run_radare2_thumb(&r2, &[0u8; 0x180], 0x4000, &[(0x4120, 0x20)], &out).unwrap();

        assert_eq!(count, 1);
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
    fn run_radare2_thumb_region_rejects_unnormalizable_raw_function() {
        let dir = std::env::temp_dir().join(format!("pme_r2_bad_normalize_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let r2 = dir.join("r2");
        let out = dir.join("out");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(
            &r2,
            "#!/usr/bin/env sh\ncat <<'EOF'\n[{\"name\":\"sym.no_entry\",\"size\":64}]\n{\"ops\":[{\"type\":\"nop\"},{\"offset\":16416,\"bytes\":\"b5f0\",\"disasm\":\"push {r4, lr}\"}]}\nEOF\n",
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
            match run_radare2_thumb_region(&r2, &[0u8; 16], 0x4000, 0x4000, 16, &out) {
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
        let err = last.expect("expected an error from run_radare2_thumb_region");

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
            pdfj_body(&pdfj),
            "0x00004120      b5f0      push {r4, lr}\n\
             0x00004122      4b02      ldr r3, [pc, 8]\n\
             0x00004124      d001      beq 0x412a\n\
             0x00004126      4770      bx lr\n"
        );
    }

    #[test]
    fn run_radare2_thumb_emits_v2_format_string() {
        // Phase 2 bumps thumb_functions.json format to v2; the body_c field arrives
        // in the enrich step. Uses the stub-r2 pattern (cf. radare2_thumb_maps_raw_blob_at_region_address)
        // so the test is hermetic and does not require a real r2 on PATH.
        let dir = std::env::temp_dir().join(format!("pme_r2_v2_fmt_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let r2 = dir.join("r2");
        let out = dir.join("out");
        std::fs::create_dir_all(&out).unwrap();
        // Stub r2 emits a single Thumb function at 0x4120 (16672) + matching pdfj —
        // the same shape as radare2_thumb_maps_raw_blob_at_region_address's stub.
        // run_radare2_thumb then writes the wrapper JSON regardless of inventory
        // content; we only need to verify the format string.
        std::fs::write(
            &r2,
            "#!/usr/bin/env sh\ncat <<'EOF'\n[{\"name\":\"sym.thumb_func\",\"offset\":16672,\"size\":32}]\n{\"addr\":16672,\"ops\":[{\"offset\":16672,\"bytes\":\"b5f0\",\"disasm\":\"push {r4, lr}\"}]}\nEOF\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = std::fs::metadata(&r2).unwrap().permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&r2, perm).unwrap();
        }

        let _ = run_radare2_thumb(&r2, &[0u8; 0x180], 0x4000, &[(0x4120, 0x20)], &out).unwrap();
        let bytes = std::fs::read(out.join("thumb_functions.json")).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            v["format"], "pixel-modem-extractor-thumb-functions-v2",
            "Phase 2 bumps the format to v2 (body_c field arrives in the enrich step)"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_radare2_thumb_multi_region_is_legacy_order_and_cleans_spills() {
        let dir = tempfile::tempdir().unwrap();
        let r2 = dir.path().join("r2");
        // Regions carve to thumb/<addr:08x>.bin, so the stub dispatches on the
        // carved blob name in its last argument.
        std::fs::write(
            &r2,
            "#!/usr/bin/env sh\ncase \"$*\" in *00004000.bin*) cat <<'EOF'\n[{\"name\":\"sym.a1\",\"offset\":16384,\"size\":64},{\"name\":\"sym.a2\",\"offset\":16448,\"size\":16}]\n{\"addr\":16384,\"ops\":[{\"offset\":16384,\"bytes\":\"b5f0\",\"disasm\":\"push {r4, lr}\"}]}\nEOF\n;; *) cat <<'EOF'\n[{\"name\":\"sym.b1\",\"offset\":32768,\"size\":64}]\n{\"addr\":32768,\"ops\":[{\"offset\":32768,\"bytes\":\"b5f0\",\"disasm\":\"push {r4, lr}\"}]}\nEOF\n;; esac\n",
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
        let substantial =
            run_radare2_thumb(&r2, &image, 0, &[(0x4000, 0x100), (0x8000, 0x100)], &out).unwrap();
        let written = std::fs::read(out.join("thumb_functions.json")).unwrap();
        let expected = {
            let fns = vec![
                normalize_radare2_function_checked(
                    &json!({"name":"sym.a1","offset":16384,"size":64}),
                    Some(&pdfj_a),
                    &image,
                    0,
                    0x4000,
                )
                .unwrap(),
                normalize_radare2_function_checked(
                    &json!({"name":"sym.a2","offset":16448,"size":16}),
                    None,
                    &image,
                    0,
                    0x4000,
                )
                .unwrap(),
                normalize_radare2_function_checked(
                    &json!({"name":"sym.b1","offset":32768,"size":64}),
                    Some(&pdfj_b),
                    &image,
                    0,
                    0x8000,
                )
                .unwrap(),
            ];
            serde_json::to_string_pretty(&json!({
                "format": "pixel-modem-extractor-thumb-functions-v2",
                "functions": fns,
            }))
            .unwrap()
        };
        assert_eq!(
            substantial, 2,
            "a1 (64) and b1 (64); a2 (16) is not substantial"
        );
        assert_eq!(written, expected.as_bytes());
        let thumb = out.join("thumb");
        assert!(thumb.join("00004000.stdout").exists());
        assert!(thumb.join("00008000.stdout").exists());
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
            b"Warning: noisy prelude\n[{\"name\":\"f\",\"offset\":1,\"size\":2}]\nINFO: tail\n",
            b"[{\"name\":\"f\",\"offset\":1,\"size\":2}]",
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

    fn inventory_of(stdout: &[u8]) -> (usize, Option<Vec<FnRec>>) {
        let mut scanner = ValueScanner::new(std::io::Cursor::new(stdout.to_vec()));
        scan_for_inventory(&mut scanner).unwrap()
    }

    #[test]
    fn inventory_scan_agrees_with_legacy_detection() {
        let fixtures: Vec<&[u8]> = vec![
            b"Warning: prelude\n[{\"name\":\"f0\",\"offset\":16384,\"size\":64},{\"name\":\"f1\",\"offset\":16448}]",
            b"[]",
            b"[\"scalar\"]",
            b"[{\"ops\":[]}]",
            b"{\"ops\":[]}\n[{\"name\":\"f\",\"offset\":1}]",
            b"no json",
            b"[{\"name\":\"f\",\"offset\":\"0x100\",\"size\":\"32\"}]",
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
    fn fn_rec_fields_match_normalize_inputs() {
        let (_, records) =
            inventory_of(b"[{\"name\":\"f0\",\"offset\":16384,\"size\":64},{\"offset\":\"0x40\"}]");
        let records = records.unwrap();
        assert_eq!(
            records[0],
            FnRec {
                entry: Some(16384),
                size: 64,
                name: Some("f0".to_string())
            }
        );
        assert_eq!(
            records[1],
            FnRec {
                entry: Some(0x40),
                size: 0,
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
    fn assemble_into_empty_renders_inline_empty_functions() {
        let mut out = Vec::new();
        assemble_into(&mut out, &[]).unwrap();
        let expected = serde_json::to_string_pretty(&json!({
            "format": "pixel-modem-extractor-thumb-functions-v2",
            "functions": [],
        }))
        .unwrap();
        assert_eq!(out, expected.as_bytes());
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

    fn legacy_region_document(
        stdout: &[u8],
        image: &[u8],
        load_addr: u32,
        addr: u32,
    ) -> Result<Vec<u8>> {
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
        let wrapped = json!({
            "format": "pixel-modem-extractor-thumb-functions-v2",
            "functions": all,
        });
        Ok(serde_json::to_string_pretty(&wrapped).unwrap().into_bytes())
    }

    fn streaming_region_document(
        stdout: &[u8],
        image: &[u8],
        load_addr: u32,
        addr: u32,
    ) -> Result<Vec<u8>> {
        let dir = tempfile::tempdir().unwrap();
        let stdout_path = dir.path().join("capture.stdout");
        std::fs::write(&stdout_path, stdout).unwrap();
        let outcome = process_region_streaming(&stdout_path, image, load_addr, addr, dir.path())?;
        let spills = [outcome.spill];
        let refs: Vec<&Spill> = spills.iter().collect();
        let mut out = Vec::new();
        assemble_into(&mut out, &refs)?;
        Ok(out)
    }

    #[test]
    fn streaming_region_matches_legacy_oracle_on_all_fixtures() {
        let fixtures: Vec<&[u8]> = vec![
            // normal pair
            b"[{\"name\":\"sym.a\",\"offset\":16384,\"size\":64},{\"name\":\"sym.b\",\"offset\":16448,\"size\":64}]\n{\"addr\":16384,\"ops\":[{\"offset\":16384,\"bytes\":\"b5f0\",\"disasm\":\"push {r4, lr}\"}]}\n{\"addr\":16448,\"ops\":[{\"offset\":16448,\"bytes\":\"4770\",\"disasm\":\"bx lr\"}]}\n",
            // positional fallback: entry-less pdfj pairs by position
            b"[{\"name\":\"sym.a\",\"offset\":16384,\"size\":64}]\n{\"ops\":[{\"offset\":16384,\"bytes\":\"b5f0\",\"disasm\":\"push {r4, lr}\"}]}\n",
            // pdfjs nested in an array after the inventory
            b"[{\"name\":\"sym.a\",\"offset\":16384,\"size\":64},{\"name\":\"sym.b\",\"offset\":16448,\"size\":64}]\n[{\"addr\":16384,\"ops\":[{\"offset\":16384,\"bytes\":\"b5f0\",\"disasm\":\"push\"}]},{\"addr\":16448,\"ops\":[{\"offset\":16448,\"bytes\":\"4770\",\"disasm\":\"bx lr\"}]}]\n",
            // duplicate entries: two fns and two pdfjs share one entry
            b"[{\"name\":\"sym.a\",\"offset\":16384,\"size\":64},{\"name\":\"sym.a2\",\"offset\":16384,\"size\":32}]\n{\"addr\":16384,\"ops\":[{\"offset\":16384,\"bytes\":\"b5f0\",\"disasm\":\"push\"}]}\n{\"addr\":16384,\"ops\":[{\"offset\":16384,\"bytes\":\"4770\",\"disasm\":\"bx lr\"}]}\n",
            // never-paired fn quarantines with empty body/data_refs
            b"[{\"name\":\"sym.a\",\"offset\":16384,\"size\":64},{\"name\":\"sym.b\",\"offset\":16448,\"size\":64}]\n{\"addr\":16448,\"ops\":[{\"offset\":16448,\"bytes\":\"4770\",\"disasm\":\"bx lr\"}]}\n",
            // leading + trailing noise
            b"Warning: noisy prelude\n[{\"name\":\"sym.a\",\"offset\":16384,\"size\":64}]\nINFO: tail\n",
            // entry-matched pdfj is NOT reused as positional fallback (pinned case)
            b"[{\"name\":\"sym.first\",\"offset\":16384,\"size\":64},{\"name\":\"sym.second\",\"offset\":16448,\"size\":64}]\n{\"addr\":16448,\"ops\":[{\"offset\":16448,\"bytes\":\"4770\",\"disasm\":\"bx lr\"}]}\n",
        ];
        for (i, stdout) in fixtures.iter().enumerate() {
            let mut image = vec![0u8; 0x1_0000];
            for (_, pdfj) in radare2_thumb_function_pdfjs(stdout) {
                populate_test_image_from_pdfj(&mut image, &pdfj);
            }
            let legacy = legacy_region_document(stdout, &image, 0, 0x4000)
                .unwrap_or_else(|e| panic!("fixture {i} legacy: {e}"));
            let streaming = streaming_region_document(stdout, &image, 0, 0x4000)
                .unwrap_or_else(|e| panic!("fixture {i} streaming: {e}"));
            assert_eq!(legacy, streaming, "fixture {i} must be byte-identical");
        }
    }

    #[test]
    fn streaming_region_error_messages_match_legacy() {
        let fixtures: Vec<&[u8]> = vec![
            b"",
            b"only noise\nand more noise",
            b"\"scalar\" 42",
            b"[{\"name\":\"x\",\"size\":8}]",
            b"[{\"name\":\"f\",\"offset\":16384,\"size\":64}]\n{\"addr\":20480,\"ops\":[{\"offset\":20480,\"bytes\":\"00bf\",\"disasm\":\"nop\"}]}\n",
            b"[{\"name\":\"f\",\"offset\":8589934592,\"size\":64}]",
            // nested-array pdfjs where one element never pairs: orphan verdict
            b"[{\"name\":\"sym.a\",\"offset\":16384,\"size\":64}]\n[{\"addr\":16384,\"ops\":[{\"offset\":16384,\"bytes\":\"b5f0\",\"disasm\":\"push\"}]},{\"addr\":9999,\"ops\":[]}]\n",
        ];
        for (i, stdout) in fixtures.iter().enumerate() {
            let image = vec![0u8; 0x1_0000];
            let legacy = legacy_region_document(stdout, &image, 0, 0x4000)
                .unwrap_err()
                .to_string();
            let streaming = streaming_region_document(stdout, &image, 0, 0x4000)
                .unwrap_err()
                .to_string();
            assert_eq!(legacy, streaming, "fixture {i} error strings must match");
        }
    }

    #[test]
    fn streaming_region_stats_match_document_derived_counts() {
        let stdout = b"[{\"name\":\"sym.a\",\"offset\":16384,\"size\":64},{\"name\":\"sym.b\",\"offset\":16448,\"size\":16}]\n{\"addr\":16384,\"ops\":[{\"offset\":16384,\"bytes\":\"b5f0\",\"disasm\":\"push {r4, lr}\"}]}\n";
        let mut image = vec![0u8; 0x1_0000];
        for (_, pdfj) in radare2_thumb_function_pdfjs(stdout) {
            populate_test_image_from_pdfj(&mut image, &pdfj);
        }
        let dir = tempfile::tempdir().unwrap();
        let stdout_path = dir.path().join("capture.stdout");
        std::fs::write(&stdout_path, stdout).unwrap();
        let outcome =
            process_region_streaming(&stdout_path, &image, 0, 0x4000, dir.path()).unwrap();
        let doc: serde_json::Value =
            serde_json::from_slice(&streaming_region_document(stdout, &image, 0, 0x4000).unwrap())
                .unwrap();
        let functions = doc["functions"].as_array().unwrap();
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

    fn write_thumb_doc(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
        let path = dir.join("thumb_functions.json");
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn streaming_validation_counts_match() {
        let dir = tempfile::tempdir().unwrap();
        let doc = r#"{
  "format": "pixel-modem-extractor-thumb-functions-v2",
  "functions": [
    {"name":"thumb_a","entry":"0x4000","end":"0x4020","size":32,"body_kind":"thumb_disassembly","body":"","data_refs":[],"decode_ranges":[{"isa":"thumb","start":"0x4000","end":"0x4020"}],"decode_range_errors":[]},
    {"name":"thumb_b","entry":"0x5000","end":"0x5008","size":8,"body_kind":"thumb_disassembly","body":"","data_refs":[],"decode_ranges":[],"decode_range_errors":[{"kind":"missing_operation_body","address":"0x5000","end":null}]}
  ]
}"#;
        let path = write_thumb_doc(dir.path(), doc);
        let (inventory, substantial) =
            validate_thumb_inventory_streaming(&path, 0x4000, 0x2000, 1).unwrap();
        assert_eq!(substantial, 1);
        assert_eq!(inventory.raw_count, 2);
        assert_eq!(inventory.accepted, 1);
        assert_eq!(inventory.quarantined, 1);
    }

    #[test]
    fn streaming_validation_errors_match_legacy_strings() {
        let dir = tempfile::tempdir().unwrap();
        let fmt = "pixel-modem-extractor-thumb-functions-v2";
        let size_string_doc = format!(r#"{{"format":"{fmt}","functions":[{{"size":"32"}}]}}"#);
        let size_small_doc = format!(r#"{{"format":"{fmt}","functions":[{{"size":8}}]}}"#);
        let empty_functions_doc = format!(r#"{{"format":"{fmt}","functions":[]}}"#);
        let cases: Vec<(&str, &str, usize)> = vec![
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
                &size_string_doc,
                "Thumb function size must be an unsigned integer",
                0,
            ),
            (
                &size_small_doc,
                "Thumb substantial count mismatch: expected 1, found 0",
                1,
            ),
            (
                &empty_functions_doc,
                "Thumb substantial count mismatch: expected 1, found 0",
                1,
            ),
        ];
        for (i, (doc, message, expected)) in cases.iter().enumerate() {
            let path = write_thumb_doc(dir.path(), doc);
            let err =
                validate_thumb_inventory_streaming(&path, 0x4000, 0x2000, *expected).unwrap_err();
            assert_eq!(err.to_string(), format!("serialize: {message}"), "case {i}");
        }
        let path = write_thumb_doc(dir.path(), "[1,2]");
        let err = validate_thumb_inventory_streaming(&path, 0x4000, 0x2000, 0).unwrap_err();
        assert_eq!(
            err.to_string(),
            "serialize: Thumb functions inventory must be an object"
        );
    }

    /// The retired whole-file `read_json` thumb leg, kept verbatim as the
    /// differential oracle for the streaming validator.
    fn legacy_thumb_validation(
        path: &Path,
        image_start: u32,
        image_len: u32,
        expected_substantial: usize,
    ) -> Result<(crate::execution_ranges::ValidatedInventory, usize)> {
        let bytes = std::fs::read(path)?;
        let thumb_json: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
            Error::Serialize(format!("parse Thumb functions inventory: {error}"))
        })?;
        let object = thumb_json.as_object().ok_or_else(|| {
            Error::Serialize("Thumb functions inventory must be an object".into())
        })?;
        if object.get("format").and_then(serde_json::Value::as_str)
            != Some("pixel-modem-extractor-thumb-functions-v2")
        {
            return Err(Error::Serialize(
                "unsupported Thumb functions inventory format".into(),
            ));
        }
        let records = object
            .get("functions")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                Error::Serialize("Thumb functions inventory lacks functions array".into())
            })?;
        let substantial = records.iter().try_fold(0usize, |count, record| {
            let size = record
                .get("size")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| {
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
        let inventory = crate::execution_ranges::validate_inventory_records(
            records,
            records.len(),
            image_start,
            image_len,
        )?;
        Ok((inventory, substantial))
    }

    #[test]
    fn streaming_validation_matches_legacy_on_well_formed_documents() {
        let dir = tempfile::tempdir().unwrap();
        let doc = r#"{
  "format": "pixel-modem-extractor-thumb-functions-v2",
  "functions": [
    {"name":"thumb_a","entry":"0x4000","end":"0x4020","size":32,"body_kind":"thumb_disassembly","body":"","data_refs":[],"decode_ranges":[{"isa":"thumb","start":"0x4000","end":"0x4020"}],"decode_range_errors":[]},
    {"name":"thumb_b","entry":"0x5000","end":"0x5008","size":8,"body_kind":"thumb_disassembly","body":"","data_refs":[],"decode_ranges":[],"decode_range_errors":[{"kind":"missing_operation_body","address":"0x5000","end":null}]}
  ]
}"#;
        let path = write_thumb_doc(dir.path(), doc);
        let legacy = legacy_thumb_validation(&path, 0x4000, 0x2000, 1).unwrap();
        let streaming = validate_thumb_inventory_streaming(&path, 0x4000, 0x2000, 1).unwrap();
        assert_eq!(legacy, streaming);
        assert_eq!(streaming.0.records.len(), 2);
        assert_eq!(streaming.0.records[0].entry, 0x4000);
        assert_eq!(streaming.0.records[1].entry, 0x5000);
        assert_eq!(streaming.0.accepted_identities.len(), 1);
    }

    #[test]
    fn streaming_validation_error_verdicts_match_legacy() {
        let fmt = "pixel-modem-extractor-thumb-functions-v2";
        let size_string_doc = format!(r#"{{"format":"{fmt}","functions":[{{"size":"32"}}]}}"#);
        let size_small_doc = format!(r#"{{"format":"{fmt}","functions":[{{"size":8}}]}}"#);
        let size_only_doc = format!(r#"{{"format":"{fmt}","functions":[{{"size":32}}]}}"#);
        let size_then_string_doc =
            format!(r#"{{"format":"{fmt}","functions":[{{"size":32}},{{"size":"x"}}]}}"#);
        let two_size_only_doc =
            format!(r#"{{"format":"{fmt}","functions":[{{"size":32}},{{"size":32}}]}}"#);
        let trailing_doc = format!(r#"{{"format":"{fmt}","functions":[]}} trailing"#);
        let truncated_doc = format!(r#"{{"format":"{fmt}","functions":[}}"#);
        let cases: Vec<(&str, usize)> = vec![
            (
                r#"{"format":"pixel-modem-extractor-thumb-functions-v2"}"#,
                0,
            ),
            (r#"{"functions":[]}"#, 0),
            (r#"{"format":"wrong","functions":[]}"#, 0),
            (&size_string_doc, 0),
            (&size_small_doc, 1),
            (
                r#"{"format":"pixel-modem-extractor-thumb-functions-v2","functions":[]}"#,
                1,
            ),
            ("[1,2]", 0),
            ("", 0),
            (&size_only_doc, 1),
            (&size_then_string_doc, 0),
            (&two_size_only_doc, 1),
            (&trailing_doc, 0),
            (&truncated_doc, 0),
        ];
        let dir = tempfile::tempdir().unwrap();
        for (i, (doc, expected)) in cases.iter().enumerate() {
            let path = write_thumb_doc(dir.path(), doc);
            let legacy = legacy_thumb_validation(&path, 0x4000, 0x2000, *expected)
                .map_err(|error| error.to_string());
            let streaming = validate_thumb_inventory_streaming(&path, 0x4000, 0x2000, *expected)
                .map_err(|error| error.to_string());
            assert_eq!(legacy, streaming, "case {i} must be legacy-identical");
        }
    }

    #[test]
    fn streaming_validation_rejects_non_canonical_key_order_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_thumb_doc(
            dir.path(),
            r#"{"functions":[],"format":"pixel-modem-extractor-thumb-functions-v2"}"#,
        );
        let err = validate_thumb_inventory_streaming(&path, 0x4000, 0x2000, 0).unwrap_err();
        assert_eq!(
            err.to_string(),
            "serialize: unsupported Thumb functions inventory format"
        );
    }

    /// Invert, in place, the finalize post-processing stamped into a retained
    /// golden `thumb_functions.json`: symbolicate's `annotations` +
    /// `original_name` stamps (restoring `name` from `original_name`) always,
    /// and thumb_enrich's `body_c` when `strip_body_c`. Re-serializing an
    /// inverted document is exact because `serde_json`'s `Map` is a sorted
    /// `BTreeMap` (no `preserve_order` feature), so removal and insertion
    /// cannot disturb key order.
    fn invert_golden_records(value: &mut serde_json::Value, strip_body_c: bool) {
        for record in value
            .get_mut("functions")
            .and_then(serde_json::Value::as_array_mut)
            .expect("golden functions array")
        {
            let record = record.as_object_mut().expect("function record object");
            if strip_body_c {
                record.remove("body_c");
            }
            record.remove("annotations");
            if let Some(original_name) = record.remove("original_name") {
                record.insert("name".into(), original_name);
            }
        }
    }

    /// Env-gated production replay: reprocesses a retained golden mustang
    /// decompose tree's real r2 captures through the streaming pipeline and
    /// asserts byte-identity with the producer surface reconstructed from the
    /// retained `thumb_functions.json`. That file is not the raw r2-stage
    /// output: after the thumb stage, decompose's finalize passes rewrite it
    /// in place — symbolicate stamps `annotations` and `original_name` (plus
    /// a recovered `name`) into every record, and thumb_enrich adds a
    /// Ghidra-derived `body_c`. The test inverts that deterministic
    /// post-processing — drops `body_c` and `annotations`, restores `name`
    /// from `original_name` — and re-serializes, so byte-identity of the
    /// replay with the inverted golden is byte-identity of the streaming
    /// producer with the legacy producer on this production data (validated
    /// in the Stage-1 spike). Skips cleanly (passes trivially) unless
    /// `PME_GOLDEN_DIR` names an unpruned mustang tree with retained
    /// `thumb/*.stdout`; a cheetah layout, pruned tree, or missing captures
    /// are skips, not failures.
    #[test]
    fn streaming_replays_retained_production_thumb_captures_byte_identically() {
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
        let mut golden: serde_json::Value = serde_json::from_reader(
            std::fs::File::open(main_dir.join("thumb_functions.json"))
                .expect("open retained thumb_functions.json"),
        )
        .expect("retained thumb_functions.json parses");
        invert_golden_records(&mut golden, true);
        let expected = serde_json::to_string_pretty(&golden)
            .expect("invert golden post-processing")
            .into_bytes();
        drop(golden);
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
                let (stem, ext) = name.split_once('.')?;
                (ext == "stdout").then_some(u32::from_str_radix(stem, 16).ok())?
            })
            .collect();
        addrs.sort_unstable();
        assert!(!addrs.is_empty(), "retained tree carries thumb captures");
        let work = tempfile::tempdir().expect("tempdir");
        let mut spills = Vec::new();
        for addr in addrs {
            let outcome = process_region_streaming(
                &thumb_dir.join(format!("{addr:08x}.stdout")),
                &image,
                load_addr,
                addr,
                work.path(),
            )
            .unwrap_or_else(|e| panic!("region 0x{addr:08x} replays: {e}"));
            spills.push(outcome.spill);
        }
        let assembled = work.path().join("thumb_functions.json");
        assemble_thumb_functions_json(&assembled, &spills).unwrap();
        let got = std::fs::read(&assembled).unwrap();
        if got != expected {
            assert_eq!(
                got.len(),
                expected.len(),
                "replay byte count differs from inverted golden"
            );
            let index = got
                .iter()
                .zip(&expected)
                .position(|(a, b)| a != b)
                .expect("equal-length buffers differ at some byte");
            let lo = index.saturating_sub(60);
            let hi = (lo + 120).min(got.len());
            panic!(
                "first differing byte at {index}: replay {:?} vs inverted golden {:?}",
                String::from_utf8_lossy(&got[lo..hi]),
                String::from_utf8_lossy(&expected[lo..hi])
            );
        }
    }

    /// Env-gated production A/B: enriches the real 02_MAIN production inputs
    /// from a retained golden mustang tree with BOTH enrichers — the streaming
    /// `thumb_enrich` and `thumb_enrich_whole` (the `#[cfg(test)]` oracle kept
    /// verbatim from the whole-file implementation Stage 2 replaced) — and
    /// asserts the two outputs are byte-for-byte identical with equal
    /// `populated` counts. The input is the producer surface: the golden
    /// `thumb_functions.json` with both finalize post-processing layers
    /// inverted (`invert_golden_records(…, true)`, the same inversion the
    /// Stage-1 replay verifies against), written to two temp copies enriched
    /// in place; `decompiled.c` is the tree's retained final file, read-only.
    /// The golden file itself cannot serve as the expected side of this
    /// comparison: its embedded `body_c` carries two enrich generations —
    /// pass-1 residue from a `decompiled.c` that pass 2 overwrote, plus the
    /// post-pass-2 bodies — so it is not the output of any single enrich run
    /// over any reconstructible input. Byte-identity of the two sides here is
    /// byte-identity of the streaming enricher with the whole-file
    /// implementation that produced the golden, on the real 632 MB production
    /// input. Skips cleanly (passes trivially) unless `PME_GOLDEN_DIR` names
    /// an unpruned mustang tree retaining both files; a cheetah layout or
    /// pruned tree is a skip, not a failure.
    #[test]
    fn streaming_enrich_ab_matches_oracle_on_production_inputs() {
        let Ok(root) = std::env::var("PME_GOLDEN_DIR") else {
            return;
        };
        let main_dir = std::path::Path::new(&root).join("images/02_MAIN/decompiled");
        let golden_c = main_dir.join("decompiled.c");
        let golden_json = main_dir.join("thumb_functions.json");
        if !golden_c.is_file() || !golden_json.is_file() {
            return;
        }
        let work = tempfile::tempdir().unwrap();
        let mut doc: serde_json::Value =
            serde_json::from_reader(std::fs::File::open(&golden_json).unwrap()).unwrap();
        invert_golden_records(&mut doc, true);
        let input = serde_json::to_vec_pretty(&doc).unwrap();
        drop(doc);
        let oracle_json = work.path().join("oracle_thumb_functions.json");
        let streaming_json = work.path().join("streaming_thumb_functions.json");
        std::fs::write(&oracle_json, &input).unwrap();
        std::fs::write(&streaming_json, &input).unwrap();
        drop(input);
        let oracle = thumb_enrich_whole(&golden_c, &oracle_json).unwrap();
        let streaming = thumb_enrich(&golden_c, &streaming_json).unwrap();
        assert_eq!(
            oracle, streaming,
            "populated counts differ: whole-file oracle vs streaming"
        );
        assert!(
            streaming > 77_000,
            "expected ~77-81k populated body_c entries, got {streaming}"
        );
        let oracle_out = std::fs::read(&oracle_json).unwrap();
        let streaming_out = std::fs::read(&streaming_json).unwrap();
        assert_eq!(
            oracle_out.len(),
            streaming_out.len(),
            "enrich A/B byte count differs: whole-file oracle vs streaming"
        );
        if oracle_out != streaming_out {
            let index = oracle_out
                .iter()
                .zip(&streaming_out)
                .position(|(a, b)| a != b)
                .expect("equal-length buffers differ at some byte");
            let lo = index.saturating_sub(60);
            let hi = (lo + 120).min(oracle_out.len());
            panic!(
                "enrich A/B diverges at {index}: oracle {:?} vs streaming {:?}",
                String::from_utf8_lossy(&oracle_out[lo..hi]),
                String::from_utf8_lossy(&streaming_out[lo..hi])
            );
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("pme_{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn thumb_enrich_populates_body_c_for_matching_entry() {
        let root = temp_dir("thumb_enrich_match");
        let c_path = root.join("decompiled.c");
        // ExportDecomp.java emits "// <name> @ <addr>\n<C>\n\n" per function.
        // Ghidra's pre-pass-2 names are `FUN_<addr>`; here the entry-address
        // (00040e1200, even form) is what thumb_enrich matches by.
        std::fs::write(
            &c_path,
            "// FUN_40e1200 @ 00040e1200\nvoid FUN_40e1200(int a)\n{\n  return;\n}\n\n",
        )
        .unwrap();
        let thumb_path = root.join("thumb_functions.json");
        std::fs::write(
            &thumb_path,
            r#"{
            "format": "pixel-modem-extractor-thumb-functions-v1",
            "functions": [
                {"entry": "0x40e1200", "name": "thumb_40e1200", "size": 8,
                 "body_kind": "thumb_disassembly", "body": "movs r0, 0", "data_refs": []},
                {"entry": "0x40efffc", "name": "thumb_40efffc", "size": 4,
                 "body_kind": "thumb_disassembly", "body": "bx lr", "data_refs": []}
            ]
        }"#,
        )
        .unwrap();

        let n = thumb_enrich(&c_path, &thumb_path).unwrap();
        assert_eq!(n, 1, "exactly one function matched by address");

        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&thumb_path).unwrap()).unwrap();
        assert_eq!(v["format"], "pixel-modem-extractor-thumb-functions-v2");
        assert!(v["functions"][0]["body_c"].is_string());
        assert!(
            v["functions"][0]["body_c"]
                .as_str()
                .unwrap()
                .contains("FUN_40e1200"),
            "body_c is the Ghidra C body (pre-pass-2 form): {}",
            v["functions"][0]["body_c"]
        );
        assert!(
            v["functions"][1].get("body_c").is_none(),
            "no address match -> no body_c"
        );
    }

    #[test]
    fn thumb_enrich_handles_real_exportdecomp_format_with_two_blank_lines() {
        // Regression sentinel: real ExportDecomp.java output has TWO blank lines
        // between the `// FUN_<addr> @ <addr>` comment header and the opening `{`
        // (one after the header, one after the signature). The original
        // parser used 1–2 line lookahead for `{`, which worked on synthetic
        // fixtures (1 blank line) but matched 0 bodies on real production output.
        let root = temp_dir("thumb_enrich_real_format");
        let c_path = root.join("decompiled.c");
        std::fs::write(
            &c_path,
            "// FUN_40e1200 @ 00040e1200\n\nvoid FUN_40e1200(int a)\n\n{\n  return;\n}\n\n",
        )
        .unwrap();
        let thumb_path = root.join("thumb_functions.json");
        std::fs::write(
            &thumb_path,
            r#"{"format":"pixel-modem-extractor-thumb-functions-v1","functions":[
            {"entry":"0x40e1200","name":"thumb_40e1200","size":4,
             "body_kind":"thumb_disassembly","body":"bx lr","data_refs":[]}]}"#,
        )
        .unwrap();

        let n = thumb_enrich(&c_path, &thumb_path).unwrap();
        assert_eq!(
            n, 1,
            "real ExportDecomp format (2 blank lines between header and `{{`) must match"
        );
        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&thumb_path).unwrap()).unwrap();
        assert!(v["functions"][0]["body_c"].is_string());
    }

    #[test]
    fn thumb_enrich_handles_real_exportdecomp_offset_6_multiline_sig() {
        // Regression sentinel for the second peak in real ExportDecomp.java's
        // header-to-`{` offset distribution: 2-line signatures produce
        // offset-6 headers (header, blank, sig-line-1, sig-line-2, blank, `{`).
        // Captured by histogram analysis on production 02_MAIN.
        let root = temp_dir("thumb_enrich_real_offset_6");
        let c_path = root.join("decompiled.c");
        std::fs::write(
            &c_path,
            "// FUN_40e1200 @ 00040e1200\n\nvoid FUN_40e1200(\n    int a,\n    int b)\n\n{\n  return;\n}\n\n",
        )
        .unwrap();
        let thumb_path = root.join("thumb_functions.json");
        std::fs::write(
            &thumb_path,
            r#"{"format":"pixel-modem-extractor-thumb-functions-v1","functions":[
            {"entry":"0x40e1200","name":"thumb_40e1200","size":4,
             "body_kind":"thumb_disassembly","body":"bx lr","data_refs":[]}]}"#,
        )
        .unwrap();

        let n = thumb_enrich(&c_path, &thumb_path).unwrap();
        assert_eq!(
            n, 1,
            "real ExportDecomp format with 2-line signature (offset-6 header) must match"
        );
        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&thumb_path).unwrap()).unwrap();
        assert!(v["functions"][0]["body_c"].is_string());
    }

    #[test]
    fn thumb_enrich_populates_body_c_with_tbit_set() {
        let root = temp_dir("thumb_enrich_tbit");
        let c_path = root.join("decompiled.c");
        // Ghidra emits Thumb entry points with the T-bit set (odd address).
        // radare2's matching `entry` is the even form. Phase 2.1's normalization
        // clears the low bit on both sides so they agree.
        std::fs::write(
            &c_path,
            "// FUN_40e1200 @ 00040e1201\nvoid FUN_40e1200(void)\n{\n  return;\n}\n\n",
        )
        .unwrap();
        let thumb_path = root.join("thumb_functions.json");
        std::fs::write(
            &thumb_path,
            r#"{"format":"pixel-modem-extractor-thumb-functions-v1","functions":[
            {"entry":"0x40e1200","name":"thumb_40e1200","size":4,
             "body_kind":"thumb_disassembly","body":"bx lr","data_refs":[]}]}"#,
        )
        .unwrap();

        let n = thumb_enrich(&c_path, &thumb_path).unwrap();
        assert_eq!(
            n, 1,
            "T-bit normalization: 40e1201 (Ghidra) matches 40e1200 (radare2)"
        );
        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&thumb_path).unwrap()).unwrap();
        assert!(v["functions"][0]["body_c"].is_string());
    }

    #[test]
    fn thumb_enrich_zero_matches_leaves_file_unchanged() {
        let root = temp_dir("thumb_enrich_no_match");
        let c_path = root.join("decompiled.c");
        std::fs::write(
            &c_path,
            "// FUN_deadbeef @ 00deadbeef\nvoid FUN_deadbeef(void)\n{\n}\n\n",
        )
        .unwrap();
        let thumb_path = root.join("thumb_functions.json");
        let original = r#"{
            "format": "pixel-modem-extractor-thumb-functions-v1",
            "functions": [
                {"entry": "0x40e1200", "name": "thumb_40e1200", "size": 8,
                 "body_kind": "thumb_disassembly", "body": "movs r0, 0", "data_refs": []}
            ]
        }"#;
        std::fs::write(&thumb_path, original).unwrap();

        let n = thumb_enrich(&c_path, &thumb_path).unwrap();
        assert_eq!(n, 0);
        // File is byte-identical (format stays v1 because no body_c was populated).
        assert_eq!(std::fs::read_to_string(&thumb_path).unwrap(), original);
    }

    #[test]
    fn thumb_enrich_is_idempotent() {
        let root = temp_dir("thumb_enrich_idem");
        let c_path = root.join("decompiled.c");
        std::fs::write(
            &c_path,
            "// FUN_40e1200 @ 00040e1200\nvoid FUN_40e1200(void)\n{\n  return;\n}\n\n",
        )
        .unwrap();
        let thumb_path = root.join("thumb_functions.json");
        std::fs::write(
            &thumb_path,
            r#"{"format":"pixel-modem-extractor-thumb-functions-v1","functions":[
            {"entry":"0x40e1200","name":"thumb_40e1200","size":4,
             "body_kind":"thumb_disassembly","body":"bx lr","data_refs":[]}]}"#,
        )
        .unwrap();

        let _ = thumb_enrich(&c_path, &thumb_path).unwrap();
        let after_first = std::fs::read_to_string(&thumb_path).unwrap();
        let _ = thumb_enrich(&c_path, &thumb_path).unwrap();
        let after_second = std::fs::read_to_string(&thumb_path).unwrap();
        assert_eq!(
            after_first, after_second,
            "second run is a no-op on the same inputs"
        );
    }

    #[test]
    fn thumb_enrich_fail_closed_on_malformed_decompiled_c() {
        let root = temp_dir("thumb_enrich_bad_c");
        let c_path = root.join("decompiled.c");
        // Not valid UTF-8.
        std::fs::write(&c_path, [0xff, 0xfe, 0xfd, 0xfc]).unwrap();
        let thumb_path = root.join("thumb_functions.json");
        let original = r#"{"format":"pixel-modem-extractor-thumb-functions-v1","functions":[]}"#;
        std::fs::write(&thumb_path, original).unwrap();

        let err = thumb_enrich(&c_path, &thumb_path).unwrap_err();
        // The on-disk JSON is unchanged.
        assert_eq!(std::fs::read_to_string(&thumb_path).unwrap(), original);
        // Surfaced as a typed error (any variant — just confirm it's not silent).
        let _ = format!("{err}");
    }

    #[test]
    fn thumb_enrich_brace_in_string_does_not_truncate_body() {
        // A `}` inside a C string literal must NOT be counted as a closing brace.
        // Before the string-aware counter, this truncated `body_c` at the first
        // in-string `}`. Block and line comments are exercised too.
        let root = temp_dir("thumb_enrich_brace_in_string");
        let c_path = root.join("decompiled.c");
        let c = "// FUN_40e1300 @ 00040e1300\n\
                 void FUN_40e1300(void)\n\
                 {\n\
                 \x20 const char *s = \"expected } close\";\n\
                 \x20 /* block comment with } brace */\n\
                 \x20 // line comment with } brace\n\
                 \x20 helper_call();\n\
                 \x20 return;\n\
                 }\n\n";
        std::fs::write(&c_path, c).unwrap();
        let thumb_path = root.join("thumb_functions.json");
        std::fs::write(
            &thumb_path,
            r#"{"format":"pixel-modem-extractor-thumb-functions-v1","functions":[
            {"entry":"0x40e1300","name":"thumb_40e1300","size":4,
             "body_kind":"thumb_disassembly","body":"bx lr","data_refs":[]}]}"#,
        )
        .unwrap();

        let n = thumb_enrich(&c_path, &thumb_path).unwrap();
        assert_eq!(n, 1);
        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&thumb_path).unwrap()).unwrap();
        let body_c = v["functions"][0]["body_c"].as_str().unwrap();
        assert!(
            body_c.contains("helper_call"),
            "body_c was truncated by an in-string/comment brace:\n{body_c}"
        );
        assert!(body_c.contains("expected } close"));
    }

    #[allow(clippy::type_complexity)]
    fn enrich_case(
        c_text: &str,
        thumb_json: &str,
    ) -> (
        Result<usize>,
        Result<usize>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let c = dir.path().join("a.c");
        std::fs::write(&c, c_text).unwrap();
        let (p1, p2) = (dir.path().join("1.json"), dir.path().join("2.json"));
        std::fs::write(&p1, thumb_json).unwrap();
        std::fs::write(&p2, thumb_json).unwrap();
        let r1 = thumb_enrich(&c, &p1);
        let r2 = thumb_enrich_whole(&c, &p2);
        let b1 = std::fs::read(&p1).ok();
        let b2 = std::fs::read(&p2).ok();
        (r1, r2, b1, b2)
    }

    const V1_HEADER: &str = "{\"format\":\"pixel-modem-extractor-thumb-functions\",\"functions\":";
    const V2_HEADER: &str =
        "{\"format\":\"pixel-modem-extractor-thumb-functions-v2\",\"functions\":";

    #[test]
    fn streaming_enrich_matches_oracle_on_canonical_inputs() {
        let body = "\n\n// thumb_100 @ 0x100\nvoid f(void)\n{\n  a;\n}\n";
        let e0 = "{\"name\":\"thumb_100\",\"entry\":\"0x100\",\"end\":\"0x108\",\"size\":8,\"body_kind\":\"thumb_disassembly\",\"body\":\"\",\"data_refs\":[],\"decode_ranges\":[],\"decode_range_errors\":[]}";
        let e1 = "{\"name\":\"x\",\"entry\":\"0x104\",\"end\":\"0x10c\",\"size\":8,\"body_kind\":\"thumb_disassembly\",\"body\":\"d\",\"data_refs\":[],\"decode_ranges\":[],\"decode_range_errors\":[]}";
        let cases: Vec<(String, String, usize)> = vec![
            (body.into(), format!("{V2_HEADER}[{e0}]}}"), 1), // match, v2 stays v2
            (body.into(), format!("{V1_HEADER}[{e0}]}}"), 1), // v1 bumped to v2
            (body.into(), format!("{V2_HEADER}[{e1}]}}"), 0), // no match -> untouched, Ok(0)
            (body.into(), format!("{V2_HEADER}[]}}"), 0),     // empty functions
            (body.into(), format!("{V2_HEADER}[{e0},{e1}]}}"), 1), // partial match
        ];
        for (i, (c, j, _)) in cases.iter().enumerate() {
            let (r1, r2, b1, b2) = enrich_case(c, j);
            assert_eq!(r1.unwrap(), r2.unwrap(), "counts fixture {i}");
            assert_eq!(b1, b2, "bytes fixture {i}");
        }
        // T-bit: header 0x101 matches entry 0x100
        let (r1, r2, b1, b2) = enrich_case(
            "\n\n// f @ 0x101\nvoid f(void)\n{\n  a;\n}\n",
            &format!("{V2_HEADER}[{e0}]}}"),
        );
        let (n1, n2) = (r1.unwrap(), r2.unwrap());
        assert_eq!(n1, 1);
        assert_eq!((n1, b1), (n2, b2));
    }

    #[test]
    fn streaming_enrich_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let c = dir.path().join("a.c");
        std::fs::write(&c, "\n\n// thumb_100 @ 0x100\nvoid f(void)\n{\n  a;\n}\n").unwrap();
        let p = dir.path().join("t.json");
        std::fs::write(
            &p,
            format!("{V2_HEADER}[{{\"name\":\"thumb_100\",\"entry\":\"0x100\",\"size\":8}}]}}"),
        )
        .unwrap();
        let n1 = thumb_enrich(&c, &p).unwrap();
        let bytes1 = std::fs::read(&p).unwrap();
        let n2 = thumb_enrich(&c, &p).unwrap();
        let bytes2 = std::fs::read(&p).unwrap();
        assert_eq!((n1, n2), (1, 1));
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn streaming_enrich_rejects_non_canonical_documents() {
        let dir = tempfile::tempdir().unwrap();
        let c = dir.path().join("a.c");
        std::fs::write(&c, "x").unwrap();
        for (i, doc) in [
            format!("{V2_HEADER}[]}}"),       // canonical control -> Ok
            "{\"functions\":[]}".to_string(), // missing format key
            format!("{}[]}}", V2_HEADER.replace("functions", "other")), // wrong second key
            "[1,2]".to_string(),              // not an object
            format!("{V2_HEADER}{{}}}}"),     // functions not an array
        ]
        .into_iter()
        .enumerate()
        {
            let p = dir.path().join(format!("t{i}.json"));
            std::fs::write(&p, &doc).unwrap();
            let res = thumb_enrich(&c, &p);
            if i == 0 {
                assert!(res.is_ok(), "canonical control must pass");
            } else {
                assert!(res.is_err(), "doc {i} must fail closed: {doc}");
                assert_eq!(
                    std::fs::read(&p).unwrap(),
                    doc.as_bytes(),
                    "no write on error"
                );
            }
        }
    }

    #[test]
    fn parse_decompiled_c_does_not_treat_char_literal_brace_as_body_end() {
        let text = "\
// FUN_10 @ 00000010\n\
void FUN_10(void)\n\
{\n\
  char c = '}';\n\
  helper();\n\
}\n\
// FUN_20 @ 00000020\n\
void FUN_20(void)\n\
{\n\
  return;\n\
}\n";
        let bodies = parse_decompiled_c_function_bodies_by_addr(text);
        // Keys are normalize_thumb_addr output (strip leading zeros, clear T-bit).
        let body = bodies.get("10").expect("entry 0x10");
        assert!(body.contains("helper();"), "{body}");
        assert!(!body.contains("FUN_20"), "{body}");
        assert!(bodies.contains_key("20"));
    }

    #[test]
    fn parse_decompiled_c_tracks_escaped_char_literals() {
        let text = "\
// FUN_10 @ 00000010\n\
void FUN_10(void)\n\
{\n\
  char q = '\\'';\n\
  char b = '}';\n\
  done();\n\
}\n";
        let bodies = parse_decompiled_c_function_bodies_by_addr(text);
        let body = bodies.get("10").expect("entry 0x10");
        assert!(body.contains("done();"), "{body}");
        assert!(
            body.ends_with("}\n") || body.trim_end().ends_with('}'),
            "{body}"
        );
    }

    fn bodies_fixtures() -> Vec<String> {
        vec![
            // offset-4: single-line signature between two blank lines
            "\n\n// FUN_100 @ 0x100\nvoid FUN_100(void)\n{\n  return;\n}\n\n".into(),
            // offset-6: two-line signature
            "\n\n// FUN_200 @ 0x200\nvoid FUN_200(\n    int a)\n{\n  a;\n}\n".into(),
            // T-bit set on the header address
            "// f @ 40e1201\nvoid f(void)\n{\n  x;\n}\n".into(),
            // header with 0x + leading zeros; body with braces in strings
            "// f @ 0x00040e1200\nint f(void)\n{\n  return \"}{\"[0];\n}\n".into(),
            // header never followed by { within 8 lines -> not captured
            "// g @ 0x300\nvoid g(void);\n\n\n\n\n\n\n\n\n{\n}\n".into(),
            // two functions back to back; second header inside first capture window
            "// a @ 0x10\nvoid a(void)\n{\n}\n// b @ 0x20\nvoid b(void)\n{\n}\n".into(),
            // 8-line boundary: { on exactly the 8th line after header -> captured
            "// h @ 0x40\nvoid h(\n   int a,\n   int b,\n   int c,\n   int d,\n   int e)\n{\n}\n"
                .into(),
            String::new(),
        ]
    }

    #[test]
    fn streaming_bodies_match_oracle_on_all_fixtures() {
        let dir = tempfile::tempdir().unwrap();
        for (i, text) in bodies_fixtures().iter().enumerate() {
            let path = dir.path().join(format!("f{i}.c"));
            std::fs::write(&path, text).unwrap();
            let streamed = collect_decompiled_c_bodies(&path).unwrap();
            let oracle = parse_decompiled_c_function_bodies_by_addr(text);
            assert_eq!(streamed, oracle, "fixture {i}: {text:?}");
        }
    }

    #[test]
    fn streaming_bodies_missing_file_is_io_error() {
        let err = collect_decompiled_c_bodies(Path::new("/nonexistent/x.c")).unwrap_err();
        assert!(matches!(err, crate::error::Error::Io(_)));
    }
}
