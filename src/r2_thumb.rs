//! Streaming radare2 Thumb producer: carves dense-Thumb regions, streams r2
//! stdout to capped on-disk captures, and turns each capture into
//! `thumb_functions.json` with bounded memory (Stage 1 of the memory-envelope
//! lever; see the design spec under ~/.superpowers/pixel-modem-extractor/).

use crate::error::{Error, Result};
use crate::execution_ranges::{
    DecodeIsa, DecodeRange, DecodeRangeErrorKind, ExecutionProjection, canonicalize_errors,
    canonicalize_instruction_extents, error, inventory_count_conserved, parse_projection,
    projection_to_json,
};
use std::path::Path;

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
#[cfg(test)]
pub(super) struct ValueScanner<R> {
    reader: R,
    buf: Vec<u8>,
    eof: bool,
    out: Vec<u8>,
}

#[cfg(test)]
const SCANNER_CHUNK_BYTES: usize = 64 * 1024;

#[cfg(test)]
impl<R: std::io::Read> ValueScanner<R> {
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

#[derive(Debug)]
struct Radare2ThumbOutput {
    json_value_count: usize,
    has_function_inventory: bool,
    records: Vec<(serde_json::Value, Option<serde_json::Value>)>,
    unassignable_function_count: usize,
    orphan_pdfj_count: usize,
}

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
/// healthy peak (ample headroom for larger images) yet far below the RAM of any
/// machine that can run this pipeline (a full decompose peaks ~56 GiB), so a
/// runaway region hits the limit and fails closed (r2 gets `ENOMEM` and exits)
/// rather than exhausting host memory. Same "fail-closed rather than OOM the host"
/// intent as [`R2_STDOUT_CAP_BYTES`], but for r2's *own* memory rather than the
/// stdout we read back from it.
const R2_ADDRESS_SPACE_CAP_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// Apply [`R2_ADDRESS_SPACE_CAP_BYTES`] to `cmd` as a soft+hard `RLIMIT_AS`, so a
/// runaway radare2 is denied further allocations by the kernel and exits instead
/// of OOM-killing the host. Unix-only; a no-op elsewhere (Windows has no portable
/// per-child address-space limit — the same platform gap documented on
/// [`spawn_in_own_process_group`]).
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

/// A Thumb region whose radare2 analysis failed and was skipped so the rest of
/// the image's regions still produce output. `reason` is the underlying error
/// text (r2 spawn/kill/non-zero exit — including the address-space cap firing on
/// a pathological blob — a stdout-cap exceed, or malformed output).
struct SkippedRegion {
    addr: u32,
    reason: String,
}

/// Fold per-region radare2 outcomes into the surviving functions plus the list of
/// skipped regions. A region's `Err` is recorded, never propagated, so one
/// runaway or malformed region degrades Thumb coverage locally instead of
/// aborting the whole stage and zeroing `thumb_functions.json`.
fn collect_thumb_regions(
    region_results: Vec<(u32, Result<Vec<serde_json::Value>>)>,
) -> (Vec<serde_json::Value>, Vec<SkippedRegion>) {
    let mut all = Vec::new();
    let mut skipped = Vec::new();
    for (addr, result) in region_results {
        match result {
            Ok(functions) => all.extend(functions),
            Err(e) => skipped.push(SkippedRegion {
                addr,
                reason: e.to_string(),
            }),
        }
    }
    (all, skipped)
}

/// Analyze an image's dense Thumb-2 regions with radare2. Each region is carved out,
/// analyzed as ARM/Thumb (`-a arm -b 16`) based at its load address, and its
/// `aflj`/`pdfj` function output merged into `out_dir/thumb_functions.json` (the carved
/// blobs are kept under `out_dir/thumb/` for follow-up). Returns the count of substantial
/// (>= 32-byte) functions recovered. Per-region failures are tolerated (see
/// [`collect_thumb_regions`]): one runaway region does not zero the others.
pub fn run_radare2_thumb(
    r2: &Path,
    image: &[u8],
    load_addr: u32,
    regions: &[(u32, u32)],
    out_dir: &Path,
) -> Result<usize> {
    let thumb_dir = out_dir.join("thumb");
    std::fs::create_dir_all(&thumb_dir)?;
    // Analyze each region independently and tolerate per-region failure: a region
    // whose r2 run fails — most consequentially the address-space cap firing on a
    // pathological blob — is recorded and skipped so the remaining regions still
    // populate thumb_functions.json instead of the whole stage aborting.
    let region_results: Vec<(u32, Result<Vec<serde_json::Value>>)> = regions
        .iter()
        .map(|&(addr, len)| {
            (
                addr,
                run_radare2_thumb_region(r2, image, load_addr, addr, len, &thumb_dir),
            )
        })
        .collect();
    let (all, skipped) = collect_thumb_regions(region_results);
    for region in &skipped {
        tracing::warn!(
            "radare2: Thumb region 0x{:x} skipped (analysis failed, fail-closed): {}",
            region.addr,
            region.reason
        );
    }
    let substantial = all
        .iter()
        .filter(|f| {
            f.get("size")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0)
                >= 32
        })
        .count();
    let accepted = all
        .iter()
        .filter(|function| {
            function
                .get("decode_ranges")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|ranges| !ranges.is_empty())
        })
        .count();
    tracing::info!(
        "radare2: Thumb execution projections accepted={accepted} quarantined={} regions_skipped={}",
        all.len() - accepted,
        skipped.len()
    );
    let wrapped = serde_json::json!({
        "format": "pixel-modem-extractor-thumb-functions-v2",
        "functions": all,
    });
    std::fs::write(
        out_dir.join("thumb_functions.json"),
        serde_json::to_string_pretty(&wrapped).map_err(|e| Error::Serialize(e.to_string()))?,
    )?;
    Ok(substantial)
}

/// Analyze one dense Thumb-2 region with radare2 and return its normalized
/// functions. Carves the region to `thumb_dir/<addr>.bin`, runs
/// `aaa;aflj;pdfj @@f` under [`limit_r2_address_space`], streams stdout to a
/// capped `<addr>.stdout`, and normalizes each paired function. Returns `Err` on
/// any per-region failure — r2 spawn/kill/non-zero exit (the address-space cap
/// firing lands here), a stdout-cap exceed, malformed output, or a non-conserving
/// projection; [`run_radare2_thumb`] records those as skips rather than aborting.
/// An empty region (offset past the image end) yields `Ok` with no functions.
fn run_radare2_thumb_region(
    r2: &Path,
    image: &[u8],
    load_addr: u32,
    addr: u32,
    len: u32,
    thumb_dir: &Path,
) -> Result<Vec<serde_json::Value>> {
    let off = addr.wrapping_sub(load_addr) as usize;
    if off >= image.len() {
        return Ok(Vec::new());
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

    // Read the streamed file back for parsing. Memory peak here is ~file size
    // (the parse path holds the bytes + builds JSON Value trees). Acceptable on
    // research machines; a future streaming-JSON-parser follow-up would reduce
    // this — see CONTRIBUTING's radare2 invariant.
    let stdout_bytes = std::fs::read(&stdout_path)?;
    let parsed = parse_checked_radare2_thumb_output(&stdout_bytes, addr)?;
    let raw_record_count = parsed.records.len();
    let mut region_fns: Vec<serde_json::Value> = Vec::with_capacity(raw_record_count);
    for (f, pdfj) in parsed.records {
        region_fns.push(normalize_radare2_function_checked(
            &f,
            pdfj.as_ref(),
            image,
            load_addr,
            addr,
        )?);
    }
    let projections = region_fns
        .iter()
        .map(parse_projection)
        .collect::<Result<Vec<_>>>()?;
    if !inventory_count_conserved(raw_record_count, &projections) {
        return Err(Error::Serialize(format!(
            "radare2 Thumb projection count is not conserving for region 0x{addr:x}"
        )));
    }
    Ok(region_fns)
}

#[cfg(test)]
mod tests {
    use std::io::Read;

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
        // zero it out.
        let region_results: Vec<(u32, Result<Vec<serde_json::Value>>)> = vec![
            (0x40010000, Ok(vec![serde_json::json!({"name": "thumb_a"})])),
            (
                0x42310000,
                Err(Error::Serialize(
                    "radare2 exited with status 139 for Thumb region 0x42310000".into(),
                )),
            ),
            (
                0x43a00000,
                Ok(vec![
                    serde_json::json!({"name": "thumb_b"}),
                    serde_json::json!({"name": "thumb_c"}),
                ]),
            ),
        ];
        let (functions, skipped) = collect_thumb_regions(region_results);
        assert_eq!(
            functions.len(),
            3,
            "surviving regions' functions must be kept"
        );
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].addr, 0x42310000);
        assert!(skipped[0].reason.contains("139"));
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

    fn scanner_values(stdout: &[u8]) -> Vec<serde_json::Value> {
        let mut scanner = ValueScanner::new(std::io::Cursor::new(stdout.to_vec()));
        let mut out = Vec::new();
        while let Some(bytes) = scanner.next_value().unwrap() {
            out.push(serde_json::from_slice(bytes).unwrap());
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
            b"[{\"a\":1}}[{\"b\":2}]",
        ];
        for (i, fixture) in fixtures.iter().enumerate() {
            assert_eq!(
                scanner_values(fixture),
                radare2_json_values(fixture),
                "fixture {i}: {fixture:?}"
            );
        }
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
}
