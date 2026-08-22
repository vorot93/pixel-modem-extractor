//! Symbolicate the decompiled modem: recover function names and inline
//! log/assert/file annotations from evidence the pipeline already produces
//! (the pw_tokenizer DB, `__func__` strings, attributed strings, existing
//! attribution), then rewrite the artifacts in place + emit `symbols.json`.
//! Pure-Rust; ARM and Thumb. Fail-closed and tiered. Two evidence sources yield
//! a real (`Recovered`) rename: `__func__`, and a `{name, fn}` registration
//! table whose pointer resolves to a known function entry (see
//! `symbolicate/reg_table.rs`). A token or a uniquely-referenced identifier
//! string yields a marked `guess_…` name (`Provisional`). Provisional names are
//! never applied to Ghidra as an authoritative (`USER_DEFINED`) symbol;
//! string-ref guesses specifically are computed only by the post-globals
//! finalize rewrite, so they never even appear in Ghidra's pass-2 input.
//! Registration names, being `Recovered`, are computed at the symbol_map stage
//! and therefore *do* reach Ghidra pass 2. Everything else is a comment.
//! Precedence: `__func__` > registration > token > string-ref.
//! See `symbolicate/name_guess.rs` for the string-reference classifier.
use crate::disasm_index::DisasmIndex;
use crate::error::{Error, Result};
use crate::execution_ranges::{ExecutionIdentity, FunctionOwner};
use crate::recover_source::Tool;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

pub mod name_guess;
pub mod reg_table;

pub const GUESS_PREFIX: &str = "guess_";

#[cfg(test)]
static TEST_IMAGE: [u8; 0x10_000] = [0; 0x10_000];

#[cfg(test)]
fn test_runtime() -> crate::runtime_image::RuntimeImage<'static> {
    crate::runtime_image::RuntimeImage::from_plan(&TEST_IMAGE, 0, None).unwrap()
}

pub struct Opts {
    pub token_db: Option<PathBuf>,
    /// Whether `decompiled.c` / `disasm.lst` are text-rewritten in place. The
    /// standalone `symbolicate` subcommand sets `true`; the `decompose` two-pass
    /// path (which regenerates `decompiled.c` from Ghidra in pass 2) sets `false`.
    pub rewrite_decompiled_c: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    Recovered,
    Provisional,
    None,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Evidence {
    pub kind: &'static str, // "func" | "token" | "file"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Symbol {
    pub address: String,    // "0x40e1bff4"
    pub arch: &'static str, // "arm" | "thumb"
    /// Which recovery tool produced the function record this symbol describes.
    /// A valid multi-run v3 artifact can hold a radare2 and a Rizin record at
    /// the same entry, so `(tool, address)` — not the address alone — is what
    /// identifies the record a symbol belongs to.
    pub tool: Tool,
    #[serde(skip)]
    pub(crate) owner: FunctionOwner,
    #[serde(skip)]
    pub(crate) execution_blake3: Option<[u8; 32]>,
    pub original_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub tier: Tier,
    pub evidence: Vec<Evidence>,
    pub annotations: Vec<String>,
}

pub struct RawEvidence {
    pub func_name: Option<String>,  // __func__ ground truth
    pub tokens: Vec<(u32, String)>, // (token, raw DB string)
    pub file: Option<String>,       // attributed source path
    pub file_strings: Vec<String>,  // that file's attributed_strings
    pub ident_guess: Option<(String, name_guess::Class)>, // string_ref_guess output
    /// Authoritative name recovered from a `{name, fn}` registration table
    /// (`reg_table::scan`). Outranks tokens and string-ref; only `__func__` wins.
    pub registration: Option<String>,
}

/// One function to symbolicate (unifies ARM + Thumb).
pub struct FuncRec<'a> {
    pub arch: &'static str, // "arm" | "thumb"
    pub name: String,       // original, e.g. "FUN_40e1bff4"
    pub entry: u64,
    pub end: u64,
    pub data_refs: Vec<u64>,
    /// ARM: a zero-copy view of the `disasm.lst` lines in range (borrowed
    /// from the one loaded buffer — the memory-envelope lever for the
    /// pathological wide-range Ghidra records that would otherwise each
    /// copy ~hundreds of MB of owned text); Thumb: the owned `body` from
    /// `thumb_functions.json`.
    pub disasm: std::borrow::Cow<'a, str>,
    /// Which recovery tool produced this function record. ARM/`functions.json`
    /// is Ghidra; each Thumb record retains its artifact run owner. The concrete
    /// owner and execution digest below form the source-attribution key.
    pub tool: Tool,
    pub(crate) owner: FunctionOwner,
    pub(crate) execution_blake3: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct FunctionEvidenceKey {
    owner: FunctionOwner,
    entry: u64,
    execution_blake3: Option<[u8; 32]>,
}

/// 32-bit constants materialized by `movw`/`movt` (and lone `movw`) in a block
/// of disassembly text. Tracks the last `movw #imm` per destination register; a
/// later `movt` on the same register combines to a full value. Register- and
/// format-agnostic across Ghidra (`movw r0,#0x..`) and Thumb backends (`movw r0, 0x..`),
/// tolerating condition suffixes (`movweq`/`movtne`). Emits noise (every lone
/// `movw` value); harmless — callers only keep values that match a token.
pub fn reconstruct_immediates(disasm: &str) -> BTreeSet<u32> {
    let mut last_movw: HashMap<String, u32> = HashMap::new();
    let mut out = BTreeSet::new();
    for line in disasm.lines() {
        if let Some((reg, imm)) = parse_mov(line, "movw") {
            last_movw.insert(reg, imm & 0xffff);
            out.insert(imm & 0xffff);
        } else if let Some((reg, imm)) = parse_mov(line, "movt") {
            let lo = last_movw.get(&reg).copied().unwrap_or(0) & 0xffff;
            out.insert(((imm & 0xffff) << 16) | lo);
        }
    }
    out
}

/// One PC-tagged register-load event: a `movw`+`movt` pair (or lone `movw`)
/// materialized `value` into `register` at `pc`. See `reconstruct_load_events`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadEvent {
    pub pc: u32,
    pub register: String,
    pub value: u32,
}

/// PC-tagged sibling of `reconstruct_immediates`. Same register-aware
/// movw/movt tracker, same Ghidra/Thumb-backend format-agnosticism. Emits a
/// `LoadEvent` for every value `reconstruct_immediates` would emit, plus
/// the PC at which the value became complete (the `movt` PC for a pair; the
/// `movw` PC for a lone `movw` with high bits zero).
///
/// Phase 3.0.1 globals use this to anchor each candidate global to the
/// instruction where it entered a register, enabling proximity matching
/// against nearby string loads.
pub fn reconstruct_load_events(disasm: &str) -> Vec<LoadEvent> {
    let mut last_movw: HashMap<String, u32> = HashMap::new();
    let mut out = Vec::new();
    for line in disasm.lines() {
        let pc = crate::disasm_index::line_addr(line)
            .map(|a| a as u32)
            .unwrap_or(0);
        if let Some((reg, imm)) = parse_mov(line, "movw") {
            last_movw.insert(reg.clone(), imm & 0xffff);
            out.push(LoadEvent {
                pc,
                register: reg,
                value: imm & 0xffff,
            });
        } else if let Some((reg, imm)) = parse_mov(line, "movt") {
            let lo = last_movw.get(&reg).copied().unwrap_or(0) & 0xffff;
            out.push(LoadEvent {
                pc,
                register: reg,
                value: ((imm & 0xffff) << 16) | lo,
            });
        }
    }
    out
}

/// Parse a `movw`/`movt`-family line into `(dest_register, immediate)`.
fn parse_mov(line: &str, op: &str) -> Option<(String, u32)> {
    let pos = line.find(op)?;
    if pos > 0 && !line.as_bytes()[pos - 1].is_ascii_whitespace() {
        return None;
    }
    let rest = line[pos + op.len()..]
        .trim_start_matches(|c: char| c.is_ascii_alphabetic()) // condition suffix
        .trim_start();
    let comma = rest.find(',')?;
    let reg = rest[..comma].trim().to_string();
    if reg.is_empty() {
        return None;
    }
    let tok = rest[comma + 1..]
        .trim()
        .trim_start_matches('#')
        .split(|c: char| c == ',' || c.is_whitespace())
        .next()?;
    let val = match tok.strip_prefix("0x").or(tok.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16).ok()?,
        None => tok.parse::<u32>().ok()?,
    };
    Some((reg, val))
}

/// token -> string, de-duplicated. First **live** (non-`date_removed`) entry
/// wins; if every entry for a token is marked removed, falls back to the first
/// removed entry. A stale removed entry must not win over a live one for the
/// same token (the DB can list both).
pub fn token_map(db: &crate::tokens::Database) -> HashMap<u32, String> {
    let mut live: HashMap<u32, String> = HashMap::new();
    let mut removed: HashMap<u32, String> = HashMap::new();
    for e in &db.entries {
        if e.date_removed.is_some() {
            removed.entry(e.token).or_insert_with(|| e.string.clone());
        } else {
            live.entry(e.token).or_insert_with(|| e.string.clone());
        }
    }
    // Tokens that only ever had removed entries fall back to the first removed one.
    for (k, v) in removed {
        live.entry(k).or_insert(v);
    }
    live
}

/// Split a pw_tokenizer entry into `(format, domain)`. The Shannon build wraps
/// entries as `■format♦<fmt>■domain♦<domain>`; plain strings return `(s, None)`.
pub fn parse_token_string(s: &str) -> (String, Option<String>) {
    const FMT: &str = "■format♦";
    const DOM: &str = "■domain♦";
    if let Some(rest) = s.strip_prefix(FMT) {
        if let Some(i) = rest.find(DOM) {
            let dom = rest[i + DOM.len()..].to_string();
            return (
                rest[..i].to_string(),
                if dom.is_empty() { None } else { Some(dom) },
            );
        }
        return (rest.to_string(), None);
    }
    (s.to_string(), None)
}

/// A deterministic, bounded name slug from a format string (+ optional domain):
/// lowercase alphanumeric words joined by `_`, domain first (≤2 words) then
/// format (≤4 words). Used only inside a marked `guess_…_<addr>` name.
pub fn slugify(format: &str, domain: Option<&str>) -> String {
    let mut parts = Vec::new();
    if let Some(d) = domain {
        parts.push(sanitize_words(d, 2));
    }
    parts.push(sanitize_words(format, 4));
    let joined = parts
        .into_iter()
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("_");
    if joined.is_empty() {
        "log".to_string()
    } else {
        joined
    }
}

fn sanitize_words(s: &str, max_words: usize) -> String {
    s.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .take(max_words)
        .map(|w| w.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join("_")
}

/// Coerce a string into a valid C identifier: non-`[A-Za-z0-9_]` → `_`, and a
/// leading digit gets a `_` prefix.
fn sanitize_ident(s: &str) -> String {
    let mut out: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if out.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        out.insert(0, '_');
    }
    out
}

/// Apply the tiered, fail-closed naming policy for one function. Only `func_name`
/// yields a real rename; only a token yields a `guess_…_<addr>`; file/strings are
/// comments. Returns `(name, tier, evidence, annotations)`. `addr_hex` is bare
/// (e.g. "40e1bff4").
pub fn decide(
    addr_hex: &str,
    raw: &RawEvidence,
) -> (Option<String>, Tier, Vec<Evidence>, Vec<String>) {
    let mut ev = Vec::new();
    let mut ann = Vec::new();

    for (tok, s) in &raw.tokens {
        let (fmt, dom) = parse_token_string(s);
        ev.push(Evidence {
            kind: "token",
            token: Some(format!("0x{tok:08x}")),
            domain: dom.clone(),
            format: Some(fmt.clone()),
            ..Default::default()
        });
        ann.push(match &dom {
            Some(d) => format!("logs: {fmt:?} [{d}]"),
            None => format!("logs: {fmt:?}"),
        });
    }
    if let Some(f) = &raw.file {
        ev.push(Evidence {
            kind: "file",
            path: Some(f.clone()),
            ..Default::default()
        });
        ann.push(format!("file: {f}"));
    }
    if !raw.file_strings.is_empty() {
        let joined = raw
            .file_strings
            .iter()
            .take(6)
            .map(|s| format!("{s:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        ann.push(format!("file-strings: {joined}"));
    }

    // Registration evidence is always recorded (even when `__func__` outranks it
    // for the name), so the table provenance survives in `symbols.json`.
    if let Some(reg) = &raw.registration {
        ev.push(Evidence {
            kind: "registration",
            value: Some(reg.clone()),
            ..Default::default()
        });
        ann.push(format!("registration: {reg:?}"));
    }

    if let Some(fname) = &raw.func_name {
        ev.insert(
            0,
            Evidence {
                kind: "func",
                value: Some(fname.clone()),
                ..Default::default()
            },
        );
        return (Some(sanitize_ident(fname)), Tier::Recovered, ev, ann);
    }
    // Authoritative table-recovered name: bare, `Recovered`, below `__func__`
    // but above every guess tier.
    if let Some(reg) = &raw.registration {
        return (Some(sanitize_ident(reg)), Tier::Recovered, ev, ann);
    }
    if let Some((_tok, s)) = raw.tokens.first() {
        let (fmt, dom) = parse_token_string(s);
        let name = format!("{GUESS_PREFIX}{}_{addr_hex}", slugify(&fmt, dom.as_deref()));
        return (Some(name), Tier::Provisional, ev, ann);
    }
    if let Some((id, class)) = &raw.ident_guess {
        ev.push(Evidence {
            kind: "string_ref",
            value: Some(id.clone()),
            class: Some(class.as_str()),
            ..Default::default()
        });
        ann.push(match class {
            name_guess::Class::TypeLabel => format!("handles-type: {id:?}"),
            name_guess::Class::FnName => format!("ident-ref: {id:?}"),
        });
        let name = format!("{GUESS_PREFIX}{}_{addr_hex}", sanitize_ident(id));
        return (Some(name), Tier::Provisional, ev, ann);
    }
    (None, Tier::None, ev, ann)
}

/// Disambiguate duplicate `recovered` names by appending `_<addr>`. Provisional
/// names already embed the address, so they never collide.
pub fn finalize_names(symbols: &mut [Symbol]) {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for s in symbols.iter() {
        if let Some(n) = &s.name {
            *counts.entry(n.clone()).or_default() += 1;
        }
    }
    for s in symbols.iter_mut() {
        if s.tier == Tier::Recovered
            && let Some(n) = &s.name
            && counts.get(n).copied().unwrap_or(0) > 1
        {
            let addr = s.address.trim_start_matches("0x");
            s.name = Some(format!("{n}_{addr}"));
        }
    }
}

/// vaddr -> string for every printable-ASCII run of length ≥ `min_run`
/// (vaddr = load_addr + file offset). Reuses `source_tree::extract_strings`.
pub fn build_string_map(image: &[u8], load_addr: u64, min_run: usize) -> HashMap<u64, String> {
    crate::source_tree::extract_strings(image, min_run)
        .into_iter()
        .map(|(off, b)| {
            (
                load_addr + off as u64,
                String::from_utf8_lossy(b).into_owned(),
            )
        })
        .collect()
}

/// Recover a function's `__func__` name: it must reference a `__FILE__`
/// occurrence vaddr (proving an assert/log site), and exactly one *distinct*
/// `data_refs` identifier must resolve (unambiguous → fail-closed). Dedup by
/// string content first: analysis backends can emit the same `__func__` ref twice
/// (e.g. two asserts in one function) and that legitimate duplicate must not
/// make a single identifier look ambiguous.
pub fn recover_func_name(
    data_refs: &[u64],
    file_occ: &HashSet<u64>,
    strings: &HashMap<u64, String>,
) -> Option<String> {
    if !data_refs.iter().any(|r| file_occ.contains(r)) {
        return None;
    }
    name_guess::unique_ident(data_refs, strings)
}

fn parse_hex(s: &str) -> Result<u64> {
    let t = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(t, 16).map_err(|e| Error::Serialize(format!("bad hex {s}: {e}")))
}

fn parse_execution_blake3(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::Serialize(
            "execution_blake3 must be 64 lowercase hexadecimal characters".into(),
        ));
    }
    let mut digest = [0u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| Error::Serialize("execution_blake3 contains invalid hex".into()))?;
    }
    Ok(digest)
}

#[derive(Deserialize)]
struct ArmFnJson {
    name: String,
    #[serde(default)]
    original_name: Option<String>,
    entry: String,
    end: String,
    #[serde(default)]
    data_refs: Vec<String>,
}

fn load_functions<'a>(
    decompiled: &Path,
    index: &DisasmIndex<'a>,
    runtime: &crate::runtime_image::RuntimeImage<'_>,
) -> Result<Vec<FuncRec<'a>>> {
    let path = decompiled.join("functions.json");
    let bytes = std::fs::read(&path)?;
    let raw: Vec<serde_json::Value> =
        serde_json::from_slice(&bytes).map_err(|e| Error::Serialize(e.to_string()))?;
    let inventory =
        crate::execution_ranges::validate_ghidra_inventory_records(&raw, raw.len(), runtime)?;
    let mut out = Vec::with_capacity(raw.len());
    for (value, tagged) in raw.into_iter().zip(inventory.records) {
        let f: ArmFnJson =
            serde_json::from_value(value).map_err(|e| Error::Serialize(e.to_string()))?;
        let entry = parse_hex(&f.entry)?;
        let end = parse_hex(&f.end)?;
        let execution =
            crate::execution_ranges::execution_identity(tagged.entry, &tagged.projection)?;
        let data_refs = f
            .data_refs
            .iter()
            .map(|r| parse_hex(r))
            .collect::<Result<Vec<_>>>()?;
        let disasm = match &execution {
            Some(execution) if execution.decode_ranges.len() == 1 => {
                let range = execution.decode_ranges[0];
                index.slice_cow(u64::from(range.start), u64::from(range.end))
            }
            Some(execution) => {
                let mut text = String::new();
                for range in &execution.decode_ranges {
                    text.push_str(&index.slice_cow(u64::from(range.start), u64::from(range.end)));
                }
                std::borrow::Cow::Owned(text)
            }
            None => std::borrow::Cow::Borrowed(""),
        };
        out.push(FuncRec {
            arch: "arm",
            name: f.original_name.unwrap_or(f.name),
            entry,
            end,
            data_refs,
            disasm,
            tool: Tool::Ghidra,
            owner: FunctionOwner::Ghidra,
            execution_blake3: execution.map(|execution| execution.execution_blake3),
        });
    }
    Ok(out)
}

fn thumb_runtime<'a>(
    image_dir: &Path,
    image: &'a [u8],
    load_addr: u64,
) -> Result<crate::runtime_image::RuntimeImage<'a>> {
    let Ok(start) = u32::try_from(load_addr) else {
        return Err(Error::Serialize(
            "symbolicate: raw image mapping does not fit the canonical u32 domain".into(),
        ));
    };
    let root = std::fs::canonicalize(image_dir)?;
    let map = root.join("scatter/load_map.json");
    crate::runtime_image::RuntimeImage::from_artifact(
        image,
        start,
        &root,
        map.try_exists()?.then_some(map.as_path()),
    )
}

fn load_thumb_functions<'a>(
    decompiled: &Path,
    runtime: &crate::runtime_image::RuntimeImage<'_>,
) -> Result<Vec<FuncRec<'a>>> {
    let path = decompiled.join("thumb_functions.json");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let functions = crate::thumb_analysis::read_thumb_functions_streaming(&path, runtime)?;
    let mut out = Vec::with_capacity(functions.len());
    for owned in functions {
        let f = owned.function;
        let entry = parse_hex(&f.entry)?;
        let end = if f.end.is_empty() {
            entry
        } else {
            parse_hex(&f.end)?
        };
        let data_refs = f
            .data_refs
            .iter()
            .map(|r| parse_hex(r))
            .collect::<Result<Vec<_>>>()?;
        out.push(FuncRec {
            arch: "thumb",
            name: f.original_name.unwrap_or(f.name),
            entry,
            end,
            data_refs,
            disasm: std::borrow::Cow::Owned(f.body),
            tool: owned.owner.analysis_tool(),
            owner: owned.owner,
            execution_blake3: owned
                .execution
                .as_ref()
                .map(|execution| execution.execution_blake3),
        });
    }
    Ok(out)
}

#[derive(Deserialize)]
struct StManifest {
    #[serde(default)]
    files: HashMap<String, StFile>,
}
#[derive(Deserialize)]
struct StFile {
    #[serde(default)]
    occurrences: Vec<StOcc>,
    #[serde(default)]
    attributed_strings: Vec<String>,
}
#[derive(Deserialize)]
struct StOcc {
    vaddr: String,
}

/// `(all __FILE__ occurrence vaddrs, path -> attributed_strings)`.
type FileOccurrences = (HashSet<u64>, HashMap<String, Vec<String>>);

/// `(all __FILE__ occurrence vaddrs, path -> attributed_strings)` from the
/// source_tree manifest.
fn load_file_occurrences(source_tree: &Path) -> Result<FileOccurrences> {
    let bytes = std::fs::read(source_tree.join("manifest.json"))?;
    let m: StManifest =
        serde_json::from_slice(&bytes).map_err(|e| Error::Serialize(e.to_string()))?;
    let mut occ = HashSet::new();
    let mut strs = HashMap::new();
    for (path, f) in m.files {
        for o in f.occurrences {
            occ.insert(parse_hex(&o.vaddr)?);
        }
        strs.insert(path, f.attributed_strings);
    }
    Ok((occ, strs))
}

#[derive(Deserialize)]
struct RiIndex {
    #[serde(default)]
    sources: HashMap<String, RiSource>,
}
#[derive(Deserialize)]
struct RiSource {
    #[serde(default)]
    functions: Vec<RiFn>,
}
#[derive(Deserialize)]
struct RiFn {
    tool: Tool,
    #[serde(default)]
    region_index: Option<usize>,
    #[serde(default)]
    run_index: Option<usize>,
    #[serde(default)]
    execution_blake3: Option<String>,
    entry: String,
}

/// `(owner, entry-vaddr, execution digest) -> attributed source path` from
/// `recovered_index.json`. Distinct executions may claim the same entry; one
/// exact identity naming two paths is a hard failure. Returned as a `BTreeMap`
/// (not `HashMap`) so repeated loads and conflict path order are deterministic.
fn load_attribution(source_tree: &Path) -> Result<BTreeMap<FunctionEvidenceKey, String>> {
    let path = source_tree.join("recovered_index.json");
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let bytes = std::fs::read(&path)?;
    let idx: RiIndex =
        serde_json::from_slice(&bytes).map_err(|e| Error::Serialize(e.to_string()))?;
    // Walk sources in path order so first-seen conflict path is stable.
    let sources: BTreeMap<String, RiSource> = idx.sources.into_iter().collect();
    let mut m = BTreeMap::new();
    for (src, s) in sources {
        for f in s.functions {
            let entry = parse_hex(&f.entry)?;
            let owner = match (f.tool, f.region_index, f.run_index) {
                (Tool::Ghidra, None, None) => FunctionOwner::Ghidra,
                (Tool::Ghidra, _, _) => {
                    return Err(Error::Serialize(
                        "Ghidra source attribution cannot have Thumb run coordinates".into(),
                    ));
                }
                (producer, None, None) => FunctionOwner::Legacy { producer },
                (producer, Some(region_index), Some(run_index)) => FunctionOwner::Run {
                    producer,
                    region_index,
                    run_index,
                },
                (_, _, _) => {
                    return Err(Error::Serialize(
                        "source attribution run coordinates must be both present or both absent"
                            .into(),
                    ));
                }
            };
            let execution_blake3 = f
                .execution_blake3
                .as_deref()
                .map(parse_execution_blake3)
                .transpose()?;
            let key = FunctionEvidenceKey {
                owner,
                entry,
                execution_blake3,
            };
            match m.get(&key) {
                Some(prev) if prev == &src => {} // same identity + same path: idempotent
                Some(prev) => {
                    let tool = match f.tool {
                        Tool::Ghidra => "ghidra",
                        Tool::Radare2 => "radare2",
                        Tool::Rizin => "rizin",
                    };
                    return Err(Error::DecomposeIncomplete(format!(
                        "source attribution conflict for {tool} entry 0x{entry:x}: \
                         {prev:?} vs {src:?}"
                    )));
                }
                None => {
                    m.insert(key, src.clone());
                }
            }
        }
    }
    Ok(m)
}

#[derive(Serialize)]
struct Counts {
    functions: usize,
    renamed_recovered: usize,
    named_provisional: usize,
    annotated_only: usize,
    untouched: usize,
}

fn counts(symbols: &[Symbol]) -> Counts {
    let recovered = symbols.iter().filter(|s| s.tier == Tier::Recovered).count();
    let provisional = symbols
        .iter()
        .filter(|s| s.tier == Tier::Provisional)
        .count();
    let annotated = symbols
        .iter()
        .filter(|s| s.tier == Tier::None && !s.annotations.is_empty())
        .count();
    let untouched = symbols
        .iter()
        .filter(|s| s.tier == Tier::None && s.annotations.is_empty())
        .count();
    Counts {
        functions: symbols.len(),
        renamed_recovered: recovered,
        named_provisional: provisional,
        annotated_only: annotated,
        untouched,
    }
}

#[derive(Serialize)]
struct SymbolsFile<'a> {
    tool_version: &'static str,
    image: &'a str,
    inputs: HashMap<String, String>,
    counts: Counts,
    symbols: &'a [Symbol],
}

/// Write `symbols.json` into the image's `decompiled/` dir; return its path.
fn write_symbols_json(
    decompiled: &Path,
    image: &str,
    symbols: &[Symbol],
    inputs: HashMap<String, String>,
) -> Result<PathBuf> {
    let file = SymbolsFile {
        tool_version: env!("CARGO_PKG_VERSION"),
        image,
        inputs,
        counts: counts(symbols),
        symbols,
    };
    let json = serde_json::to_string_pretty(&file).map_err(|e| Error::Serialize(e.to_string()))?;
    let path = decompiled.join("symbols.json");
    std::fs::write(&path, json)?;
    Ok(path)
}

/// Serializable shape of `<out>/ghidra/symbol_maps/<label>.json`, consumed by
/// `ApplySymbols.java` during pass 2. Field order matches the schema in the
/// Phase-1 design spec.
#[derive(Debug, Serialize)]
struct SymbolMapFile<'a> {
    tool_version: &'static str,
    image: &'a str,
    source_blake3: &'a str,
    functions_blake3: &'a str,
    symbols: Vec<SymbolMapEntry<'a>>,
}

#[derive(Debug, Serialize)]
struct SymbolMapEntry<'a> {
    entry: &'a str,
    arch: &'a str,
    original_name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    tier: &'a Tier,
    annotations: &'a [String],
}

/// Serialize a per-image symbol map to `out_path`. Returns `out_path` on success.
pub fn write_symbol_map(
    out_path: &Path,
    image_label: &str,
    symbols: &[Symbol],
    source_blake3: &str,
    functions_blake3: &str,
) -> Result<PathBuf> {
    let entries: Vec<SymbolMapEntry<'_>> = symbols
        .iter()
        .map(|s| SymbolMapEntry {
            entry: &s.address,
            arch: s.arch,
            original_name: &s.original_name,
            name: s.name.as_deref(),
            tier: &s.tier,
            annotations: &s.annotations,
        })
        .collect();
    let file = SymbolMapFile {
        tool_version: env!("CARGO_PKG_VERSION"),
        image: image_label,
        source_blake3,
        functions_blake3,
        symbols: entries,
    };
    let json = serde_json::to_string_pretty(&file).map_err(|e| Error::Serialize(e.to_string()))?;
    std::fs::write(out_path, json)?;
    Ok(out_path.to_path_buf())
}

const SENTINEL: &str = "// pixel-modem-extractor: symbolicated\n";

/// Global `original_name -> name` substitution over decompiled text (safe: replace
/// longer original names first to avoid prefix collisions; e.g. shorter `thumb_40e1200`
/// must not fire inside longer `thumb_40e12000`). Prepends a sentinel; idempotent
/// (returns the input unchanged if already symbolicated).
fn rewrite_text(text: &str, symbols: &[Symbol]) -> String {
    if text.starts_with(SENTINEL) {
        return text.to_string();
    }
    let renames = build_rename_map(symbols);
    let out = apply_rename_map(text, &renames);
    format!("{SENTINEL}{out}")
}

/// Per-symbol `(original_name, name)` rename pairs, longest-first to avoid prefix
/// collisions (e.g. shorter `thumb_40e1200` must not fire inside longer
/// `thumb_40e12000`). New names never start with `FUN_`/`thumb_`, so no
/// replacement can re-introduce a match. Shared by the file-level rewrite
/// (`rewrite_text`) and the per-field `body_c` rewrite.
fn build_rename_map(symbols: &[Symbol]) -> Vec<(&str, &str)> {
    let mut renames: Vec<(&str, &str)> = symbols
        .iter()
        .filter_map(|s| match &s.name {
            Some(name) if name != &s.original_name => {
                Some((s.original_name.as_str(), name.as_str()))
            }
            _ => None,
        })
        .collect();
    renames.sort_by_key(|b| std::cmp::Reverse(b.0.len()));
    renames
}

/// Apply the rename map by whole-identifier replacement, not substring
/// substitution. Walks the text matching `[A-Za-z0-9_]+` (one C identifier at
/// a time) and substitutes only when the captured ident equals an entry in
/// `renames` — so `FUN_40001000` does NOT fire inside `FUN_40001000_extra` or
/// inside an unrelated comment/string. `str::replace` was wrong here: it would
/// corrupt prefix matches in body text. No sentinel.
fn apply_rename_map(text: &str, renames: &[(&str, &str)]) -> String {
    if renames.is_empty() {
        return text.to_string();
    }
    let map: HashMap<&str, &str> = renames.iter().copied().collect();
    // One compilation regardless of map size; the closure looks up each captured
    // identifier verbatim. Safe because original_names are themselves C idents.
    let re = regex::Regex::new(r"[A-Za-z0-9_]+").expect("static pattern compiles");
    re.replace_all(text, |caps: &regex::Captures| -> String {
        let matched = caps.get(0).expect("capture 0 is the whole match").as_str();
        map.get(matched).copied().unwrap_or(matched).to_string()
    })
    .into_owned()
}

/// Set `name` + `original_name` + `annotations` on each entry of `functions.json`
/// and `thumb_functions.json`, matched by concrete owner, entry, and execution
/// digest. Both files are rewritten element-by-element through the shared
/// streaming rewriters (`thumb_analysis::stream_rewrite_json_array` /
/// `stream_rewrite_thumb_functions`) with no whole-document mutation tree. The
/// retired whole-file implementation is kept test-only as
/// `rewrite_functions_json_whole`, the differential oracle.
/// `pub(crate)` so `decompose`'s route tests can drive the real finalize
/// rewriter when modeling the symbol-route input-rewrite sequence.
pub(crate) fn rewrite_functions_json(
    decompiled: &Path,
    runtime: &crate::runtime_image::RuntimeImage<'_>,
    symbols: &[Symbol],
) -> Result<()> {
    // Numeric address spelling does not matter, while concrete ownership and
    // authenticated execution remain identity-bearing.
    let by_owner: HashMap<FunctionEvidenceKey, &Symbol> = symbols
        .iter()
        .filter_map(|symbol| {
            parse_hex(&symbol.address).ok().map(|entry| {
                (
                    FunctionEvidenceKey {
                        owner: symbol.owner,
                        entry,
                        execution_blake3: symbol.execution_blake3,
                    },
                    symbol,
                )
            })
        })
        .collect();

    let stamp = |owner: FunctionOwner,
                 execution: Option<&ExecutionIdentity>,
                 item: &mut serde_json::Value|
     -> Result<()> {
        let Some(addr) = item
            .get("entry")
            .and_then(|v| v.as_str())
            .and_then(|e| parse_hex(e).ok())
        else {
            return Ok(());
        };
        let key = FunctionEvidenceKey {
            owner,
            entry: addr,
            execution_blake3: execution.map(|execution| execution.execution_blake3),
        };
        let Some(sym) = by_owner.get(&key) else {
            return Ok(());
        };
        let Some(obj) = item.as_object_mut() else {
            return Ok(());
        };
        if obj.contains_key("original_name") {
            return Ok(()); // already symbolicated — idempotent re-run
        }
        // Source original_name from the Symbol record, not from obj["name"]:
        // on the Phase-1 two-pass path, obj["name"] already holds the
        // recovered name (pass 2 renamed in-program before regenerating
        // functions.json). The Symbol preserves the true original.
        obj.insert(
            "original_name".into(),
            serde_json::Value::String(sym.original_name.clone()),
        );
        if let Some(name) = &sym.name {
            obj.insert("name".into(), serde_json::Value::String(name.clone()));
        }
        obj.insert(
            "annotations".into(),
            serde_json::Value::Array(
                sym.annotations
                    .iter()
                    .cloned()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
        Ok(())
    };

    // functions.json (a bare array) is always Ghidra's inventory.
    let fpath = decompiled.join("functions.json");
    if fpath.exists() {
        let source = std::fs::read(&fpath)?;
        let records: Vec<serde_json::Value> = serde_json::from_slice(&source)
            .map_err(|error| Error::Serialize(format!("parse {}: {error}", fpath.display())))?;
        let validated = crate::execution_ranges::validate_ghidra_inventory_records(
            &records,
            records.len(),
            runtime,
        )?;
        let executions = validated
            .records
            .iter()
            .map(|record| {
                crate::execution_ranges::execution_identity(record.entry, &record.projection)
            })
            .collect::<Result<Vec<_>>>()?;
        let mut function_index = 0usize;
        crate::thumb_analysis::stream_rewrite_json_array(&fpath, &source, |item| {
            let execution = executions.get(function_index).ok_or_else(|| {
                Error::Serialize("Ghidra function count changed during mutation".into())
            })?;
            function_index += 1;
            stamp(FunctionOwner::Ghidra, execution.as_ref(), item)
        })?;
        if function_index != executions.len() {
            return Err(Error::Serialize(
                "Ghidra function count changed during mutation".into(),
            ));
        }
    }

    // thumb_functions.json ({ "functions": [...] }); the mutator resolves each
    // record's validated run owner.
    let tpath = decompiled.join("thumb_functions.json");
    if tpath.exists() {
        crate::thumb_analysis::stream_rewrite_thumb_functions(
            &tpath,
            runtime,
            |owner, execution, item| stamp(owner, execution, item),
        )?;
    }
    Ok(())
}

/// Retired whole-file `rewrite_functions_json`, kept verbatim as the
/// differential oracle for the streaming rewrite; test-only.
#[cfg(test)]
fn rewrite_functions_json_whole(decompiled: &Path, symbols: &[Symbol]) -> Result<()> {
    let by_addr: HashMap<u64, &Symbol> = symbols
        .iter()
        .filter_map(|s| parse_hex(&s.address).ok().map(|a| (a, s)))
        .collect();

    let apply = |arr: &mut [serde_json::Value]| {
        for item in arr.iter_mut() {
            let Some(addr) = item
                .get("entry")
                .and_then(|v| v.as_str())
                .and_then(|e| parse_hex(e).ok())
            else {
                continue;
            };
            let Some(sym) = by_addr.get(&addr) else {
                continue;
            };
            let Some(obj) = item.as_object_mut() else {
                continue;
            };
            if obj.contains_key("original_name") {
                continue; // already symbolicated — idempotent re-run
            }
            obj.insert(
                "original_name".into(),
                serde_json::Value::String(sym.original_name.clone()),
            );
            if let Some(name) = &sym.name {
                obj.insert("name".into(), serde_json::Value::String(name.clone()));
            }
            obj.insert(
                "annotations".into(),
                serde_json::Value::Array(
                    sym.annotations
                        .iter()
                        .cloned()
                        .map(serde_json::Value::String)
                        .collect(),
                ),
            );
        }
    };

    // functions.json (a bare array)
    let fpath = decompiled.join("functions.json");
    if fpath.exists() {
        let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&fpath)?)
            .map_err(|e| Error::Serialize(e.to_string()))?;
        if let Some(arr) = v.as_array_mut() {
            apply(arr);
        }
        std::fs::write(
            &fpath,
            serde_json::to_string_pretty(&v).map_err(|e| Error::Serialize(e.to_string()))?,
        )?;
    }

    // thumb_functions.json ({ "functions": [...] })
    let tpath = decompiled.join("thumb_functions.json");
    if tpath.exists() {
        let mut artifact = crate::thumb_analysis::read_thumb_artifact(&tpath, &test_runtime())?;
        apply(artifact.function_values_mut());
        artifact.write_atomic(&tpath)?;
    }
    Ok(())
}

/// Rewrite `decompiled.c` and `disasm.lst` in place (text substitution) if present.
/// Also rewrites the `body_c` field of each entry in `thumb_functions.json`
/// (when present) using the same rename map — symmetric with `decompiled.c`
/// since `body_c` is sourced from it. Gated at the call site by
/// `FinalizeOpts::rewrite_decompiled_c`.
fn rewrite_text_files(
    decompiled: &Path,
    runtime: &crate::runtime_image::RuntimeImage<'_>,
    symbols: &[Symbol],
) -> Result<()> {
    for name in ["decompiled.c", "disasm.lst"] {
        let p = decompiled.join(name);
        if p.exists() {
            let text = std::fs::read_to_string(&p)?;
            std::fs::write(&p, rewrite_text(&text, symbols))?;
        }
    }
    rewrite_body_c_in_thumb_functions(decompiled, runtime, symbols)?;
    Ok(())
}

/// Walk `thumb_functions.json` and apply the `original_name -> name` rename map
/// to each function's `body_c` field (when present). Mirrors the `decompiled.c`
/// text substitution — Phase-2's `body_c` is sourced from `decompiled.c`, so on
/// the standalone-`symbolicate` path (against a pre-Phase-2 tree) the same
/// rename must apply. Idempotent: after the first pass the original names are
/// gone from `body_c`, so subsequent passes are no-ops.
///
/// **Dead on the two-pass `decompose` path under Phase 2.1.** Phase 2.1's
/// post-pass-2 `thumb_enrich` re-runs against the pass-2-regenerated
/// `decompiled.c` (which has recovered names baked in by `ApplySymbols`), so
/// `body_c` is born with recovered names directly — and `FinalizeOpts::
/// rewrite_decompiled_c` is `false` on that path, skipping this rewrite. Live
/// on the standalone `symbolicate` subcommand and on `decompose
/// --no-symbol-pass` (where `rewrite_decompiled_c` is `true`).
fn rewrite_body_c_in_thumb_functions(
    decompiled: &Path,
    runtime: &crate::runtime_image::RuntimeImage<'_>,
    symbols: &[Symbol],
) -> Result<()> {
    let path = decompiled.join("thumb_functions.json");
    if !path.exists() {
        return Ok(());
    }
    let renames = build_rename_map(symbols);
    crate::thumb_analysis::stream_rewrite_thumb_functions(&path, runtime, |_, _, func| {
        let Some(obj) = func.as_object_mut() else {
            return Ok(());
        };
        let Some(body_c) = obj.get("body_c").and_then(|v| v.as_str()) else {
            return Ok(());
        };
        let renamed = apply_rename_map(body_c, &renames);
        if renamed != body_c {
            obj.insert("body_c".into(), serde_json::Value::String(renamed));
        }
        Ok(())
    })
}

/// Retired whole-file `rewrite_body_c_in_thumb_functions`, kept verbatim as
/// the differential oracle for the streaming rewrite; test-only.
#[cfg(test)]
fn rewrite_body_c_in_thumb_functions_whole(decompiled: &Path, symbols: &[Symbol]) -> Result<()> {
    let path = decompiled.join("thumb_functions.json");
    if !path.exists() {
        return Ok(());
    }
    let mut artifact = crate::thumb_analysis::read_thumb_artifact(&path, &test_runtime())?;
    let renames = build_rename_map(symbols);
    for function in artifact.function_values_mut() {
        let Some(obj) = function.as_object_mut() else {
            continue;
        };
        let Some(body_c) = obj.get("body_c").and_then(|value| value.as_str()) else {
            continue;
        };
        let renamed = apply_rename_map(body_c, &renames);
        if renamed != body_c {
            obj.insert("body_c".into(), serde_json::Value::String(renamed));
        }
    }
    artifact.write_atomic(&path)?;
    Ok(())
}

/// Tunable parameters for `finalize_image`. Today a single flag controls whether
/// `decompiled.c` / `disasm.lst` are text-rewritten; on the `decompose` two-pass
/// path (Phase 1+), pass 2 regenerates `decompiled.c` and the rewrite is skipped.
pub struct FinalizeOpts {
    pub rewrite_decompiled_c: bool,
}

/// A function name that is already a real identifier (not an analysis-backend
/// default nor a marked guess). Used to reject identifiers that name a *known*
/// function elsewhere in the image.
fn is_real_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with("FUN_")
        && !name.starts_with("fcn.")
        && !name.starts_with("thunk")
        && !name.starts_with(GUESS_PREFIX)
}

/// Recovered global names from a per-image `globals.json` (`.globals[].name`).
/// Empty on any read/parse failure — the tier that consumes it is gated on the
/// file's presence separately.
fn load_global_names(path: &Path) -> HashSet<String> {
    let Ok(bytes) = std::fs::read(path) else {
        return HashSet::new();
    };
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return HashSet::new();
    };
    v.get("globals")
        .and_then(|g| g.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|g| g.get("name").and_then(|n| n.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// `(cand_idents, ident_count)`: the string-ref-specific precompute in
/// `build_map`, gated by `string_ref_enabled`. `global_names` / `fn_names` are
/// computed unconditionally above it (the registration tier shares them).
type StringRefPrecompute = (Vec<Option<String>>, HashMap<String, usize>);

/// Pure: build the per-image `Symbol` set from pass-1 outputs. No file writes.
pub(crate) fn build_map(
    image_dir: &Path,
    image_label: &str,
    tokens: &HashMap<u32, String>,
    manifest: &Path,
) -> Result<Vec<Symbol>> {
    let decompiled = image_dir.join("decompiled");
    let disasm = std::fs::read_to_string(decompiled.join("disasm.lst")).unwrap_or_default();
    let index = crate::disasm_index::DisasmIndex::new(&disasm);

    let source_tree = image_dir.join("source_tree");
    let (file_occ, file_strings) = if source_tree.join("manifest.json").exists() {
        load_file_occurrences(&source_tree)?
    } else {
        (HashSet::new(), HashMap::new())
    };
    let attribution = load_attribution(&source_tree)?;

    // Loaded before the function inventories so the Thumb artifact can be
    // validated against the image it was produced for.
    let raw_image_path = image_dir.join(format!("{image_label}.bin"));
    let image_and_load: Option<(Vec<u8>, u64)> = match crate::manifest::load_addr_for_image(
        manifest,
        image_label,
    )? {
        Some(load_addr) if raw_image_path.exists() => {
            Some((std::fs::read(&raw_image_path)?, load_addr))
        }
        _ => {
            if !file_occ.is_empty() {
                tracing::warn!(
                    "symbolicate: {image_label}: raw image or load_addr missing — skipping __func__ recovery"
                );
            }
            None
        }
    };

    let runtime = image_and_load
        .as_ref()
        .map(|(image, load_addr)| thumb_runtime(image_dir, image, *load_addr))
        .transpose()?
        .ok_or_else(|| {
            Error::Serialize(
                "symbolicate: function inventory requires its raw image and load address".into(),
            )
        })?;
    let mut funcs = load_functions(&decompiled, &index, &runtime)?;
    if decompiled.join("thumb_functions.json").exists() {
        funcs.extend(load_thumb_functions(&decompiled, &runtime)?);
    }

    let string_map = match &image_and_load {
        Some((img, load_addr)) => build_string_map(img, *load_addr, 3),
        None => HashMap::new(),
    };

    // Recovered (`__func__`) names, computed once and reused below.
    let recovered_names: Vec<Option<String>> = funcs
        .iter()
        .map(|f| {
            if string_map.is_empty() {
                None
            } else {
                recover_func_name(&f.data_refs, &file_occ, &string_map)
            }
        })
        .collect();

    // Known function names (real + `__func__`-recovered) and recovered globals.
    // Both reject an ambiguous guess/registration name; computed unconditionally
    // so the registration tier can use them without the string-ref globals gate.
    // `global_names` is best-effort: the symbol_map stage runs before
    // `globals.json` exists, so it is empty there (registration still fires).
    let mut fn_names: HashSet<String> = HashSet::new();
    for (i, f) in funcs.iter().enumerate() {
        if is_real_name(&f.name) {
            fn_names.insert(f.name.clone());
        }
        if let Some(n) = &recovered_names[i] {
            fn_names.insert(n.clone());
        }
    }
    let globals_path = decompiled.join("globals.json");
    let global_names = if globals_path.exists() {
        load_global_names(&globals_path)
    } else {
        HashSet::new()
    };

    // Registration-table tier (authoritative). Scans the raw image for
    // `{name, fn}` tables whose pointer resolves to a known function entry.
    let reg_names: HashMap<u64, String> = match &image_and_load {
        Some((img, load_addr)) => {
            let fn_entries: HashMap<u64, &'static str> =
                funcs.iter().map(|f| (f.entry, f.arch)).collect();
            reg_table::scan(img, *load_addr, &fn_entries, &global_names, &fn_names).names
        }
        None => HashMap::new(),
    };

    // String-reference guess tier (fail-closed, lowest precedence). Active only
    // when the raw image (=> non-empty string_map) and globals.json are present.
    let string_ref_enabled = !string_map.is_empty() && globals_path.exists();
    let (cand_idents, ident_count): StringRefPrecompute = if string_ref_enabled {
        let cand_idents: Vec<Option<String>> = funcs
            .iter()
            .map(|f| name_guess::unique_ident(&f.data_refs, &string_map))
            .collect();
        let mut ident_count: HashMap<String, usize> = HashMap::new();
        for id in cand_idents.iter().flatten() {
            *ident_count.entry(id.clone()).or_default() += 1;
        }
        (cand_idents, ident_count)
    } else {
        (vec![None; funcs.len()], HashMap::new())
    };

    let mut symbols = Vec::with_capacity(funcs.len());
    for (i, f) in funcs.iter().enumerate() {
        let addr_hex = format!("{:08x}", f.entry);
        let mut imms = reconstruct_immediates(&f.disasm);
        imms.extend(f.data_refs.iter().filter_map(|r| u32::try_from(*r).ok()));
        let mut hits: Vec<(u32, String)> = imms
            .iter()
            .filter_map(|v| tokens.get(v).map(|s| (*v, s.clone())))
            .collect();
        hits.sort_by_key(|(t, _)| *t);

        let func_name = recovered_names[i].clone();
        let file = attribution
            .get(&FunctionEvidenceKey {
                owner: f.owner,
                entry: f.entry,
                execution_blake3: f.execution_blake3,
            })
            .cloned();
        let fstrings = file
            .as_ref()
            .and_then(|p| file_strings.get(p))
            .cloned()
            .unwrap_or_default();

        // Lowest precedence: only when neither `__func__` nor a token fired.
        let ident_guess = if string_ref_enabled
            && func_name.is_none()
            && hits.is_empty()
            && !is_real_name(&f.name)
        {
            name_guess::string_ref_guess(
                cand_idents[i].as_deref(),
                &ident_count,
                &global_names,
                &fn_names,
            )
        } else {
            None
        };

        let raw = RawEvidence {
            func_name,
            tokens: hits,
            file,
            file_strings: fstrings,
            ident_guess,
            // Authoritative, but must not clobber a pre-existing real (non-FUN_)
            // name (e.g. a Ghidra FID match) — like the string-ref tier, defer.
            registration: if is_real_name(&f.name) {
                None
            } else {
                reg_names.get(&f.entry).cloned()
            },
        };
        let (name, tier, evidence, annotations) = decide(&addr_hex, &raw);
        symbols.push(Symbol {
            address: format!("0x{addr_hex}"),
            arch: f.arch,
            tool: f.tool,
            owner: f.owner,
            execution_blake3: f.execution_blake3,
            original_name: f.name.clone(),
            name,
            tier,
            evidence,
            annotations,
        });
    }
    finalize_names(&mut symbols);
    Ok(symbols)
}

/// Apply the built symbols to a per-image `decompiled/` dir in place; returns
/// the `symbols.json` path. `rewrite_decompiled_c = false` skips the text
/// rewrite of `decompiled.c` / `disasm.lst` (the two-pass decompose path
/// regenerates them from Ghidra).
fn finalize_image(
    image_dir: &Path,
    image_label: &str,
    runtime: &crate::runtime_image::RuntimeImage<'_>,
    symbols: &[Symbol],
    opts: &FinalizeOpts,
) -> Result<PathBuf> {
    let decompiled = image_dir.join("decompiled");
    let mut inputs = HashMap::new();
    if let Ok(b) = std::fs::read(decompiled.join("functions.json")) {
        inputs.insert(
            "functions_json_blake3".into(),
            crate::manifest::blake3_bytes(&b),
        );
    }

    rewrite_functions_json(&decompiled, runtime, symbols)?;
    if opts.rewrite_decompiled_c {
        rewrite_text_files(&decompiled, runtime, symbols)?;
    }
    write_symbols_json(&decompiled, image_label, symbols, inputs)
}

/// Backward-compatible wrapper: build_map + finalize_image with the rewrite on.
/// Only referenced by tests now that `run` threads `Opts.rewrite_decompiled_c`
/// directly into `finalize_image`.
#[cfg(test)]
fn symbolicate_image(
    image_dir: &Path,
    image_label: &str,
    tokens: &HashMap<u32, String>,
    manifest: &Path,
) -> Result<PathBuf> {
    let symbols = build_map(image_dir, image_label, tokens, manifest)?;
    let image = std::fs::read(image_dir.join(format!("{image_label}.bin")))?;
    let load_addr = crate::manifest::load_addr_for_image(manifest, image_label)?
        .ok_or_else(|| Error::Serialize(format!("load_addr missing for {image_label}")))?;
    let runtime = thumb_runtime(image_dir, &image, load_addr)?;
    finalize_image(
        image_dir,
        image_label,
        &runtime,
        &symbols,
        &FinalizeOpts {
            rewrite_decompiled_c: true,
        },
    )
}

/// Symbolicate every image under `<root>/images/*` that has a `decompiled/` dir.
/// `opts.token_db` is the raw pw_token_db (TOKENS); without it, token evidence is
/// skipped. Returns `root`.
pub fn run(root: &Path, opts: &Opts) -> Result<PathBuf> {
    let tokens = match &opts.token_db {
        Some(p) if p.exists() => token_map(&crate::tokens::parse(&std::fs::read(p)?)?),
        _ => {
            tracing::warn!("symbolicate: no token DB — token evidence skipped");
            HashMap::new()
        }
    };
    let manifest = root.join("manifest.json");
    let images = root.join("images");
    let mut count = 0usize;
    for entry in std::fs::read_dir(&images)? {
        let dir = entry?.path();
        let label = dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        if !dir.join("decompiled").join("functions.json").exists() {
            continue;
        }
        let symbols = build_map(&dir, &label, &tokens, &manifest)?;
        let image = std::fs::read(dir.join(format!("{label}.bin")))?;
        let load_addr = crate::manifest::load_addr_for_image(&manifest, &label)?
            .ok_or_else(|| Error::Serialize(format!("load_addr missing for {label}")))?;
        let runtime = thumb_runtime(&dir, &image, load_addr)?;
        let out = finalize_image(
            &dir,
            &label,
            &runtime,
            &symbols,
            &FinalizeOpts {
                rewrite_decompiled_c: opts.rewrite_decompiled_c,
            },
        )?;
        println!("symbolicated {label} -> {}", out.display());
        count += 1;
    }
    println!("symbolicate: {count} image(s)");
    Ok(root.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ghidra_function(name: &str, entry: u32, end: u32, data_refs: &[u32]) -> serde_json::Value {
        ghidra_function_in_image(name, entry, end, data_refs, &TEST_IMAGE, 0)
    }

    fn ghidra_function_in_image(
        name: &str,
        entry: u32,
        end: u32,
        data_refs: &[u32],
        image: &[u8],
        load_addr: u32,
    ) -> serde_json::Value {
        let start = (entry - load_addr) as usize;
        let finish = (end - load_addr) as usize;
        serde_json::json!({
            "name": name,
            "primary_source": "default",
            "entry": format!("0x{entry:x}"),
            "end": format!("0x{end:x}"),
            "size": u64::from(end - entry),
            "decode_ranges": [{
                "isa": "arm",
                "start": format!("0x{entry:x}"),
                "end": format!("0x{end:x}"),
                "blake3": blake3::hash(&image[start..finish]).to_hex().to_string(),
            }],
            "decode_range_errors": [],
            "data_refs": data_refs.iter().map(|address| format!("0x{address:x}")).collect::<Vec<_>>(),
        })
    }

    fn write_test_ghidra_function(dir: &Path, name: &str, entry: u32, end: u32) -> [u8; 32] {
        std::fs::write(
            dir.join("functions.json"),
            serde_json::to_vec(&vec![ghidra_function(name, entry, end, &[])]).unwrap(),
        )
        .unwrap();
        load_functions(dir, &DisasmIndex::new(""), &test_runtime()).unwrap()[0]
            .execution_blake3
            .unwrap()
    }

    #[test]
    fn tier_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&Tier::Recovered).unwrap(),
            "\"recovered\""
        );
        assert_eq!(serde_json::to_string(&Tier::None).unwrap(), "\"none\"");
    }

    #[test]
    fn reconstructs_movw_movt_pairs() {
        // radare2 Thumb style: movw + movt on r0 -> 0x446814a2
        let d = "0x40e2 movw r0, 0x14a2\n0x40e6 movt r0, 0x4468\n";
        assert!(reconstruct_immediates(d).contains(&0x4468_14a2));
        // Ghidra '#' style, condition suffix, out-of-order regs
        let g = "movw r3,#0x00cc\nmovweq r0,#0xcc9\nmovt r3,#0x0001\n";
        let s = reconstruct_immediates(g);
        assert!(s.contains(&0x0001_00cc)); // r3 pair
        assert!(s.contains(&0x0000_0cc9)); // lone movw (r0)
        // no false 32-bit value when movt has no preceding movw on that reg
        assert!(reconstruct_immediates("movt r5,#0x1234\n").contains(&0x1234_0000));
    }

    #[test]
    fn reconstruct_load_events_pc_tagged() {
        // radare2 Thumb style: movw + movt on r0 -> value 0x4468_14a2 at movt's PC.
        let d = "0x40e2: movw r0, 0x14a2\n0x40e6: movt r0, 0x4468\n";
        let events = reconstruct_load_events(d);
        assert!(
            events
                .iter()
                .any(|e| e.pc == 0x40e6 && e.register == "r0" && e.value == 0x4468_14a2)
        );
    }

    #[test]
    fn reconstruct_load_events_handles_lone_movw() {
        // Lone movw (no movt): value is low-16-bits, high bits zero; pc is movw's.
        let d = "0x10: movw r3, 0x00cc\n";
        let events = reconstruct_load_events(d);
        assert!(
            events
                .iter()
                .any(|e| e.pc == 0x10 && e.register == "r3" && e.value == 0x0000_00cc)
        );
    }

    #[test]
    fn reconstruct_load_events_matches_reconstruct_immediates_values() {
        // Every value reconstruct_immediates emits, reconstruct_load_events also
        // emits (with some PC). Drift sentinel.
        let d = "0x10: movw r0, 0x1\n0x14: movt r0, 0x2\n0x20: movw r5, 0x9\n";
        let immediate_set: BTreeSet<u32> = reconstruct_immediates(d).into_iter().collect();
        let event_set: BTreeSet<u32> = reconstruct_load_events(d)
            .into_iter()
            .map(|e| e.value)
            .collect();
        assert_eq!(immediate_set, event_set);
    }

    #[test]
    fn reconstruct_load_events_pc_is_movt_pc_not_movw_pc() {
        // The PC is where the value becomes complete (movt's PC), not where the
        // pair started (movw's PC). Load-bearing for proximity matching.
        let d = "0x100: movw r0, 0x10\n0x200: movt r0, 0x20\n";
        let events = reconstruct_load_events(d);
        let pair_event = events.iter().find(|e| e.value == 0x200010).unwrap();
        assert_eq!(pair_event.pc, 0x200); // movt's PC, not movw's PC (0x100)
    }

    #[test]
    fn parses_format_and_domain() {
        let (f, d) = parse_token_string("■format♦RRC Reestablishment (%d)■domain♦LTE_RRC_METRICS");
        assert_eq!(f, "RRC Reestablishment (%d)");
        assert_eq!(d.as_deref(), Some("LTE_RRC_METRICS"));
        // plain string (no markers) passes through with no domain
        assert_eq!(parse_token_string("Latency"), ("Latency".to_string(), None));
    }

    #[test]
    fn slug_is_deterministic_and_bounded() {
        let s = slugify(
            "RRC Reestablishment Request (stack_id: %d)",
            Some("LTE_RRC_METRICS"),
        );
        assert_eq!(s, "lte_rrc_rrc_reestablishment_request_stack");
        assert_eq!(slugify("", None), "log");
    }

    #[test]
    fn token_map_dedups_by_token() {
        use crate::tokens::{Database, Entry};
        let db = Database {
            reserved: 0,
            entries: vec![
                Entry {
                    token: 1,
                    date_removed: None,
                    string: "first".into(),
                },
                Entry {
                    token: 1,
                    date_removed: None,
                    string: "second".into(),
                },
                Entry {
                    token: 2,
                    date_removed: None,
                    string: "B".into(),
                },
            ],
        };
        let m = token_map(&db);
        assert_eq!(m.len(), 2);
        assert_eq!(m[&1], "first"); // first live string wins on a collision
        assert_eq!(m[&2], "B");
    }

    #[test]
    fn token_map_prefers_live_over_removed() {
        // A stale removed entry ahead of the live one must NOT win.
        use crate::tokens::{Database, Date, Entry};
        let db = Database {
            reserved: 0,
            entries: vec![
                Entry {
                    token: 7,
                    date_removed: Some(Date {
                        year: 2020,
                        month: 1,
                        day: 2,
                    }),
                    string: "stale".into(),
                },
                Entry {
                    token: 7,
                    date_removed: None,
                    string: "live".into(),
                },
            ],
        };
        let m = token_map(&db);
        assert_eq!(m[&7], "live");

        // And the all-removed case still falls back to the first entry.
        let db2 = Database {
            reserved: 0,
            entries: vec![Entry {
                token: 8,
                date_removed: Some(Date {
                    year: 2021,
                    month: 3,
                    day: 4,
                }),
                string: "only_removed".into(),
            }],
        };
        let m2 = token_map(&db2);
        assert_eq!(m2[&8], "only_removed");
    }

    #[test]
    fn sanitize_ident_makes_valid_c_identifier() {
        assert_eq!(sanitize_ident("LteRrc_Handle"), "LteRrc_Handle");
        assert_eq!(sanitize_ident("9bad-name"), "_9bad_name");
    }

    #[test]
    fn recover_func_name_dedups_repeated_identifier() {
        // Two data_refs pointing to the same __func__ string used to fail the
        // "exactly one identifier" gate (idents.len() == 2) and drop a real name.
        let file_occ = HashSet::from([100u64]);
        let mut strings = HashMap::new();
        strings.insert(100, "path/file.c".to_string()); // __FILE__ ref
        strings.insert(200, "do_thing".to_string()); // __func__ ref (referenced twice)
        // data_refs visits vaddr 200 twice (two asserts in one function).
        let data_refs = vec![100u64, 200, 200];
        let name = recover_func_name(&data_refs, &file_occ, &strings);
        assert_eq!(name.as_deref(), Some("do_thing"));
    }

    #[test]
    fn apply_rename_map_does_not_substring_match() {
        // FUN_10 must not fire inside FUN_100, FUN_10_x, or a comment containing it.
        let text = "FUN_10 FUN_100 FUN_10_x /* call FUN_10 here */\nthumb_10";
        let renames: [(&str, &str); 2] = [("FUN_10", "alpha"), ("thumb_10", "beta")];
        let out = apply_rename_map(text, &renames);
        // Only the exact-identifier FUN_10 (first token) and thumb_10 (last) rename;
        // FUN_100 and FUN_10_x are left intact (no false prefix match).
        assert_eq!(out, "alpha FUN_100 FUN_10_x /* call alpha here */\nbeta");
    }

    fn raw() -> RawEvidence {
        RawEvidence {
            func_name: None,
            tokens: vec![],
            file: None,
            file_strings: vec![],
            ident_guess: None,
            registration: None,
        }
    }

    #[test]
    fn func_name_is_a_recovered_rename() {
        let r = RawEvidence {
            func_name: Some("LteRrc_Reestab".into()),
            ..raw()
        };
        let (name, tier, ev, _ann) = decide("40e1bff4", &r);
        assert_eq!(name.as_deref(), Some("LteRrc_Reestab"));
        assert_eq!(tier, Tier::Recovered);
        assert_eq!(ev[0].kind, "func");
    }

    #[test]
    fn token_yields_marked_guess_and_annotation() {
        let r = RawEvidence {
            tokens: vec![(
                0x3c2a,
                "■format♦RRC Reestab (%d)■domain♦LTE_RRC_METRICS".into(),
            )],
            ..raw()
        };
        let (name, tier, _ev, ann) = decide("40e1bff4", &r);
        let name = name.unwrap();
        assert!(name.starts_with(GUESS_PREFIX), "not marked: {name}");
        assert!(name.ends_with("40e1bff4"), "no address: {name}");
        assert_eq!(tier, Tier::Provisional);
        assert!(
            ann.iter()
                .any(|a| a.contains("RRC Reestab") && a.contains("LTE_RRC_METRICS"))
        );
    }

    #[test]
    fn file_and_strings_are_comments_only() {
        let r = RawEvidence {
            file: Some("HEDGE/LteRrc.c".into()),
            file_strings: vec!["reest_reason".into()],
            ..raw()
        };
        let (name, tier, _ev, ann) = decide("40e1bff4", &r);
        assert_eq!(name, None);
        assert_eq!(tier, Tier::None);
        assert!(ann.iter().any(|a| a.starts_with("file: HEDGE/LteRrc.c")));
        assert!(ann.iter().any(|a| a.starts_with("file-strings:")));
    }

    #[test]
    fn ident_guess_yields_marked_string_ref_guess() {
        let r = RawEvidence {
            ident_guess: Some(("RF_SM_Set_ET_Voltage".into(), name_guess::Class::FnName)),
            ..raw()
        };
        let (name, tier, ev, ann) = decide("40e1bff4", &r);
        let name = name.unwrap();
        assert!(name.starts_with(GUESS_PREFIX), "not marked: {name}");
        assert!(name.contains("RF_SM_Set_ET_Voltage"));
        assert!(name.ends_with("40e1bff4"), "no address: {name}");
        assert_eq!(tier, Tier::Provisional);
        let e = ev.iter().find(|e| e.kind == "string_ref").unwrap();
        assert_eq!(e.class, Some("fn_name"));
        assert!(ann.iter().any(|a| a.contains("RF_SM_Set_ET_Voltage")));
    }

    #[test]
    fn func_name_beats_ident_guess() {
        let r = RawEvidence {
            func_name: Some("Real_Name".into()),
            ident_guess: Some(("Other".into(), name_guess::Class::FnName)),
            ..raw()
        };
        let (name, tier, _ev, _ann) = decide("40e1bff4", &r);
        assert_eq!(name.as_deref(), Some("Real_Name"));
        assert_eq!(tier, Tier::Recovered);
    }

    #[test]
    fn token_beats_ident_guess() {
        let r = RawEvidence {
            tokens: vec![(0x3c2a, "■format♦hi■domain♦D".into())],
            ident_guess: Some(("Other".into(), name_guess::Class::FnName)),
            ..raw()
        };
        let (_name, tier, ev, _ann) = decide("40e1bff4", &r);
        assert_eq!(tier, Tier::Provisional);
        assert!(ev.iter().any(|e| e.kind == "token"));
        assert!(!ev.iter().any(|e| e.kind == "string_ref"));
    }

    #[test]
    fn registration_is_a_recovered_bare_name() {
        let r = RawEvidence {
            registration: Some("AtiParsePlusCOPS".into()),
            ..raw()
        };
        let (name, tier, ev, _ann) = decide("411b8f04", &r);
        assert_eq!(name.as_deref(), Some("AtiParsePlusCOPS")); // bare, no guess_ prefix
        assert_eq!(tier, Tier::Recovered);
        assert!(ev.iter().any(|e| e.kind == "registration"));
    }

    #[test]
    fn func_name_beats_registration() {
        let r = RawEvidence {
            func_name: Some("Real_Name".into()),
            registration: Some("Registered_Name".into()),
            ..raw()
        };
        let (name, tier, ev, _ann) = decide("411b8f04", &r);
        assert_eq!(name.as_deref(), Some("Real_Name"));
        assert_eq!(tier, Tier::Recovered);
        // the registration name is still recorded as evidence
        assert!(ev.iter().any(|e| e.kind == "registration"));
    }

    #[test]
    fn registration_beats_token_and_string_ref() {
        let r = RawEvidence {
            registration: Some("PICH_HISR".into()),
            tokens: vec![(0x3c2a, "■format♦hi■domain♦D".into())],
            ident_guess: Some(("Other".into(), name_guess::Class::FnName)),
            ..raw()
        };
        let (name, tier, _ev, _ann) = decide("437436f0", &r);
        assert_eq!(name.as_deref(), Some("PICH_HISR")); // bare authoritative name wins
        assert_eq!(tier, Tier::Recovered);
    }

    #[test]
    fn recovered_name_collisions_get_address_suffix() {
        let mut syms = vec![
            Symbol {
                address: "0xaa".into(),
                arch: "arm",
                tool: crate::recover_source::Tool::Ghidra,
                owner: FunctionOwner::Ghidra,
                execution_blake3: None,
                original_name: "FUN_aa".into(),
                name: Some("dup".into()),
                tier: Tier::Recovered,
                evidence: vec![],
                annotations: vec![],
            },
            Symbol {
                address: "0xbb".into(),
                arch: "arm",
                tool: crate::recover_source::Tool::Ghidra,
                owner: FunctionOwner::Ghidra,
                execution_blake3: None,
                original_name: "FUN_bb".into(),
                name: Some("dup".into()),
                tier: Tier::Recovered,
                evidence: vec![],
                annotations: vec![],
            },
        ];
        finalize_names(&mut syms);
        assert_eq!(syms[0].name.as_deref(), Some("dup_aa"));
        assert_eq!(syms[1].name.as_deref(), Some("dup_bb"));
    }

    #[test]
    fn string_map_uses_load_addr_offset() {
        // "hi" at offset 1 -> vaddr load_addr+1
        let img = b"\x00hi\x00AB\x00"; // "hi" @1, "AB" @4
        let m = build_string_map(img, 0x4000_0000, 2);
        assert_eq!(m.get(&0x4000_0001).map(String::as_str), Some("hi"));
        assert_eq!(m.get(&0x4000_0004).map(String::as_str), Some("AB"));
    }

    #[test]
    fn recover_func_name_needs_file_ref_and_unique_ident() {
        let mut strings = HashMap::new();
        strings.insert(0x100u64, "LteRrc.c".to_string()); // __FILE__
        strings.insert(0x200u64, "LteRrc_Reestab".to_string()); // __func__
        let file_occ: HashSet<u64> = [0x100u64].into_iter().collect();
        // function references both the file string and the identifier -> recovered
        assert_eq!(
            recover_func_name(&[0x100, 0x200], &file_occ, &strings),
            Some("LteRrc_Reestab".to_string())
        );
        // no __FILE__ ref -> None (not an assert site)
        assert_eq!(recover_func_name(&[0x200], &file_occ, &strings), None);
        // two identifier candidates -> ambiguous -> None (fail-closed)
        strings.insert(0x300u64, "Another_Ident".to_string());
        assert_eq!(
            recover_func_name(&[0x100, 0x200, 0x300], &file_occ, &strings),
            None
        );
    }

    #[test]
    fn parse_hex_accepts_prefixed_and_bare() {
        assert_eq!(parse_hex("0x40e1bff4").unwrap(), 0x40e1_bff4);
        assert!(parse_hex("nope").is_err());
    }

    #[test]
    fn loads_arm_functions_and_slices_disasm() {
        let dir = tmp("pme_sym_load_arm");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("functions.json"),
            serde_json::to_vec(&vec![ghidra_function("FUN_10", 0x10, 0x18, &[0x200])]).unwrap(),
        )
        .unwrap();
        let disasm = "0x10: 41f2 movw r0, 0x1\n0x14: c0f2 movt r0, 0x2\n0x20: other\n";
        let index = DisasmIndex::new(disasm);
        let fns = load_functions(&dir, &index, &test_runtime()).unwrap();
        assert_eq!(fns.len(), 1);
        assert_eq!(fns[0].arch, "arm");
        assert_eq!(fns[0].entry, 0x10);
        assert!(fns[0].execution_blake3.is_some());
        assert_eq!(fns[0].data_refs, vec![0x200]);
        assert!(fns[0].disasm.contains("movw") && fns[0].disasm.contains("movt"));
        assert!(!fns[0].disasm.contains("0x20: other")); // out of [entry,end)
    }

    #[test]
    fn loaders_prefer_original_name_on_rerun() {
        let dir = tmp("pme_sym_orig");
        std::fs::create_dir_all(&dir).unwrap();
        // functions.json as left by a prior symbolicate run: `name` renamed, `original_name` kept
        let mut function = ghidra_function("guess_x_10", 0x10, 0x18, &[]);
        function["original_name"] = serde_json::json!("FUN_10");
        function["annotations"] = serde_json::json!([]);
        std::fs::write(
            dir.join("functions.json"),
            serde_json::to_vec(&vec![function]).unwrap(),
        )
        .unwrap();
        let index = DisasmIndex::new("");
        let fns = load_functions(&dir, &index, &test_runtime()).unwrap();
        assert_eq!(fns[0].name, "FUN_10"); // true original recovered, not the renamed value
    }

    #[test]
    fn loads_file_occurrences_and_attribution() {
        let dir = tmp("pme_sym_load_st");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("manifest.json"),
            r#"{"files":{"A/x.c":{"occurrences":[{"vaddr":"0x100"}],"attributed_strings":["reest"]}}}"#).unwrap();
        std::fs::write(
            dir.join("recovered_index.json"),
            r#"{"sources":{"A/x.c":{"functions":[{"tool":"ghidra","entry":"0x10"}]}}}"#,
        )
        .unwrap();
        let (occ, strs) = load_file_occurrences(&dir).unwrap();
        assert!(occ.contains(&0x100));
        assert_eq!(strs["A/x.c"], vec!["reest".to_string()]);
        let attr = load_attribution(&dir).unwrap();
        assert_eq!(
            attr.get(&FunctionEvidenceKey {
                owner: FunctionOwner::Ghidra,
                entry: 0x10,
                execution_blake3: None,
            })
            .map(String::as_str),
            Some("A/x.c")
        );
    }

    #[test]
    fn load_attribution_keeps_distinct_tool_claims_at_the_same_entry() {
        let dir = tmp("pme_sym_attr_tools");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("recovered_index.json"),
            r#"{"sources":{
            "ghidra/a.c":{"functions":[{"tool":"ghidra","entry":"0x10"}]},
            "r2/b.c":{"functions":[{"tool":"radare2","entry":"0x10"}]}
        }}"#,
        )
        .unwrap();
        let attr = load_attribution(&dir).unwrap();
        assert_eq!(
            attr.get(&FunctionEvidenceKey {
                owner: FunctionOwner::Ghidra,
                entry: 0x10,
                execution_blake3: None,
            })
            .map(String::as_str),
            Some("ghidra/a.c")
        );
        assert_eq!(
            attr.get(&FunctionEvidenceKey {
                owner: FunctionOwner::Legacy {
                    producer: Tool::Radare2,
                },
                entry: 0x10,
                execution_blake3: None,
            })
            .map(String::as_str),
            Some("r2/b.c")
        );
    }

    #[test]
    fn v3_thumb_producers_keep_distinct_attribution_keys() {
        let dir = tmp("pme_sym_v3_thumb_producer_keys");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("thumb_functions.json"),
            crate::thumb_analysis::ParsedThumbArtifact::future_multi_run_v3_fixture(),
        )
        .unwrap();
        let funcs = load_thumb_functions(&dir, &test_runtime()).unwrap();
        let digest = |digest: [u8; 32]| {
            digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        std::fs::write(
            dir.join("recovered_index.json"),
            serde_json::json!({
                "sources": {
                    "r2/a.c": {"functions": [{
                        "tool": "radare2",
                        "region_index": 0,
                        "run_index": 0,
                        "execution_blake3": digest(funcs[0].execution_blake3.unwrap()),
                        "entry": "0x1000"
                    }]},
                    "rizin/b.c": {"functions": [{
                        "tool": "rizin",
                        "region_index": 0,
                        "run_index": 1,
                        "execution_blake3": digest(funcs[1].execution_blake3.unwrap()),
                        "entry": "0x1000"
                    }]}
                }
            })
            .to_string(),
        )
        .unwrap();
        let attribution = load_attribution(&dir).unwrap();

        assert_eq!(funcs.len(), 2);
        assert_eq!(funcs[0].entry, funcs[1].entry);
        assert_eq!(funcs[0].tool, Tool::Radare2);
        assert_eq!(funcs[1].tool, Tool::Rizin);
        assert_eq!(
            funcs[0].owner,
            FunctionOwner::Run {
                producer: Tool::Radare2,
                region_index: 0,
                run_index: 0,
            }
        );
        assert_eq!(
            funcs[1].owner,
            FunctionOwner::Run {
                producer: Tool::Rizin,
                region_index: 0,
                run_index: 1,
            }
        );
        assert_eq!(
            attribution
                .get(&FunctionEvidenceKey {
                    owner: funcs[0].owner,
                    entry: funcs[0].entry,
                    execution_blake3: funcs[0].execution_blake3,
                })
                .map(String::as_str),
            Some("r2/a.c")
        );
        assert_eq!(
            attribution
                .get(&FunctionEvidenceKey {
                    owner: funcs[1].owner,
                    entry: funcs[1].entry,
                    execution_blake3: funcs[1].execution_blake3,
                })
                .map(String::as_str),
            Some("rizin/b.c")
        );
    }

    /// The valid multi-run v3 fixture carries a radare2 and a Rizin record at
    /// the same entry, so an address-only rewrite map stamps both from whichever
    /// symbol wins. Ownership must decide which record each symbol updates.
    #[test]
    fn finalize_rewrites_same_entry_records_by_producer_identity() {
        let dir = tmp("pme_sym_v3_owner_aware_rewrite");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("thumb_functions.json");
        std::fs::write(
            &path,
            crate::thumb_analysis::ParsedThumbArtifact::future_multi_run_v3_fixture(),
        )
        .unwrap();
        let artifact = crate::thumb_analysis::parse_thumb_artifact(
            crate::thumb_analysis::ParsedThumbArtifact::future_multi_run_v3_fixture(),
            &test_runtime(),
        )
        .unwrap();
        let executions = artifact
            .functions()
            .map(|function| (function.owner, function.execution.unwrap().execution_blake3))
            .collect::<Vec<_>>();
        let symbol = |index: usize, tool: Tool, name: &str| Symbol {
            address: "0x1000".into(),
            arch: "thumb",
            tool,
            owner: executions[index].0,
            execution_blake3: Some(executions[index].1),
            original_name: format!("original_{name}"),
            name: Some(name.to_string()),
            tier: Tier::Recovered,
            evidence: Vec::new(),
            annotations: vec![format!("annotation_{name}")],
        };

        rewrite_functions_json(
            &dir,
            &test_runtime(),
            &[
                symbol(0, Tool::Radare2, "from_radare2"),
                symbol(1, Tool::Rizin, "from_rizin"),
            ],
        )
        .unwrap();

        let document: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let functions = document["functions"].as_array().unwrap();
        assert_eq!(functions[0]["name"], "from_radare2");
        assert_eq!(functions[0]["original_name"], "original_from_radare2");
        assert_eq!(
            functions[0]["annotations"],
            serde_json::json!(["annotation_from_radare2"])
        );
        assert_eq!(functions[1]["name"], "from_rizin");
        assert_eq!(functions[1]["original_name"], "original_from_rizin");
        assert_eq!(
            functions[1]["annotations"],
            serde_json::json!(["annotation_from_rizin"])
        );
        // The rewrite must preserve run ownership and every provenance field.
        crate::thumb_analysis::parse_thumb_artifact(
            &std::fs::read(&path).unwrap(),
            &test_runtime(),
        )
        .unwrap();
    }

    #[test]
    fn load_attribution_fails_closed_on_same_tool_path_conflict() {
        let dir = tmp("pme_sym_attr_conflict");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("recovered_index.json"),
            r#"{"sources":{
            "a.c":{"functions":[{"tool":"ghidra","entry":"0x10"}]},
            "b.c":{"functions":[{"tool":"ghidra","entry":"0x10"}]}
        }}"#,
        )
        .unwrap();
        let err = load_attribution(&dir).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("ghidra"), "{msg}");
        assert!(msg.contains("0x10") || msg.contains("10"), "{msg}");
        assert!(msg.contains("a.c") && msg.contains("b.c"), "{msg}");
    }

    #[test]
    fn load_attribution_fails_closed_on_missing_tool() {
        let dir = tmp("pme_sym_attr_missing_tool");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("recovered_index.json"),
            r#"{"sources":{"A/x.c":{"functions":[{"entry":"0x10"}]}}}"#,
        )
        .unwrap();
        assert!(load_attribution(&dir).is_err());
    }

    #[test]
    fn load_attribution_is_deterministic_across_repeated_loads() {
        let dir = tmp("pme_sym_attr_det");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("recovered_index.json"),
            r#"{"sources":{
            "ghidra/a.c":{"functions":[{"tool":"ghidra","entry":"0x10"}]},
            "r2/b.c":{"functions":[{"tool":"radare2","entry":"0x10"}]}
        }}"#,
        )
        .unwrap();
        let first = format!("{:?}", load_attribution(&dir).unwrap());
        for _ in 0..32 {
            assert_eq!(format!("{:?}", load_attribution(&dir).unwrap()), first);
        }
    }

    // small helper: a fresh temp dir path (see std::env::temp_dir usage in repo tests)
    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    /// A symbol for the Rizin-owned record at 0x4000 in `consumer_v3_fixture`.
    fn thumb_symbol() -> Symbol {
        let artifact = crate::thumb_analysis::parse_thumb_artifact(
            crate::thumb_analysis::ParsedThumbArtifact::consumer_v3_fixture(),
            &test_runtime(),
        )
        .unwrap();
        let function = artifact.functions().next().unwrap();
        Symbol {
            address: "0x4000".into(),
            arch: "thumb",
            tool: crate::recover_source::Tool::Rizin,
            owner: function.owner,
            execution_blake3: Some(function.execution.unwrap().execution_blake3),
            original_name: "thumb_4000".into(),
            name: Some("recovered_thumb".into()),
            tier: Tier::Recovered,
            evidence: vec![],
            annotations: vec!["file: modem.c".into()],
        }
    }

    #[test]
    fn writes_symbols_json_with_counts() {
        let dir = tmp("pme_sym_emit");
        std::fs::create_dir_all(&dir).unwrap();
        let syms = vec![
            Symbol {
                address: "0x10".into(),
                arch: "arm",
                tool: crate::recover_source::Tool::Ghidra,
                owner: FunctionOwner::Ghidra,
                execution_blake3: None,
                original_name: "FUN_10".into(),
                name: Some("real".into()),
                tier: Tier::Recovered,
                evidence: vec![],
                annotations: vec![],
            },
            Symbol {
                address: "0x20".into(),
                arch: "thumb",
                tool: crate::recover_source::Tool::Radare2,
                owner: FunctionOwner::Legacy {
                    producer: Tool::Radare2,
                },
                execution_blake3: None,
                original_name: "thumb_20".into(),
                name: Some("guess_x_20".into()),
                tier: Tier::Provisional,
                evidence: vec![],
                annotations: vec![],
            },
            Symbol {
                address: "0x30".into(),
                arch: "arm",
                tool: crate::recover_source::Tool::Ghidra,
                owner: FunctionOwner::Ghidra,
                execution_blake3: None,
                original_name: "FUN_30".into(),
                name: None,
                tier: Tier::None,
                evidence: vec![],
                annotations: vec!["file: a.c".into()],
            },
        ];
        let p = write_symbols_json(&dir, "02_MAIN", &syms, HashMap::new()).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        assert_eq!(v["image"], "02_MAIN");
        assert_eq!(v["counts"]["renamed_recovered"], 1);
        assert_eq!(v["counts"]["named_provisional"], 1);
        assert_eq!(v["counts"]["annotated_only"], 1);
        assert_eq!(v["symbols"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn rewrite_text_substitutes_names_and_is_idempotent() {
        let syms = vec![Symbol {
            address: "0x40e1bff4".into(),
            arch: "arm",
            tool: crate::recover_source::Tool::Ghidra,
            owner: FunctionOwner::Ghidra,
            execution_blake3: None,
            original_name: "FUN_40e1bff4".into(),
            name: Some("real_fn".into()),
            tier: Tier::Recovered,
            evidence: vec![],
            annotations: vec!["file: a.c".into()],
        }];
        let src = "void FUN_40e1bff4(void) { FUN_40e1bff4(); }\n";
        let once = rewrite_text(src, &syms);
        assert!(once.contains("real_fn"));
        assert!(!once.contains("FUN_40e1bff4"));
        assert!(once.starts_with(SENTINEL));
        // idempotent: a second pass over already-rewritten text is a no-op
        assert_eq!(rewrite_text(&once, &syms), once);
    }

    #[test]
    fn rewrite_text_handles_prefix_collision() {
        // one original_name (`thumb_40e1200`) is a prefix of another (`thumb_40e12000`)
        let syms = vec![
            Symbol {
                address: "0x40e1200".into(),
                arch: "thumb",
                tool: crate::recover_source::Tool::Radare2,
                owner: FunctionOwner::Legacy {
                    producer: Tool::Radare2,
                },
                execution_blake3: None,
                original_name: "thumb_40e1200".into(),
                name: Some("guess_short_040e1200".into()),
                tier: Tier::Provisional,
                evidence: vec![],
                annotations: vec![],
            },
            Symbol {
                address: "0x40e12000".into(),
                arch: "thumb",
                tool: crate::recover_source::Tool::Radare2,
                owner: FunctionOwner::Legacy {
                    producer: Tool::Radare2,
                },
                execution_blake3: None,
                original_name: "thumb_40e12000".into(),
                name: Some("guess_long_40e12000".into()),
                tier: Tier::Provisional,
                evidence: vec![],
                annotations: vec![],
            },
        ];
        let src = "call thumb_40e1200(); call thumb_40e12000();\n";
        let out = rewrite_text(src, &syms);
        assert!(
            out.contains("guess_short_040e1200();"),
            "short mangled: {out}"
        );
        assert!(
            out.contains("guess_long_40e12000();"),
            "long mangled: {out}"
        );
        assert!(!out.contains("thumb_"), "leftover original token: {out}");
    }

    #[test]
    fn rewrite_functions_json_sets_name_and_annotations() {
        let dir = tmp("pme_sym_rw_json");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("functions.json"),
            serde_json::to_vec(&vec![ghidra_function("FUN_10", 0x10, 0x18, &[])]).unwrap(),
        )
        .unwrap();
        let execution_blake3 = load_functions(&dir, &DisasmIndex::new(""), &test_runtime())
            .unwrap()[0]
            .execution_blake3;
        let syms = vec![Symbol {
            address: "0x10".into(),
            arch: "arm",
            tool: crate::recover_source::Tool::Ghidra,
            owner: FunctionOwner::Ghidra,
            execution_blake3,
            original_name: "FUN_10".into(),
            name: Some("real".into()),
            tier: Tier::Recovered,
            evidence: vec![],
            annotations: vec!["logs: \"hi\"".into()],
        }];
        rewrite_functions_json(&dir, &test_runtime(), &syms).unwrap();
        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("functions.json")).unwrap()).unwrap();
        assert_eq!(v[0]["name"], "real");
        assert_eq!(v[0]["original_name"], "FUN_10");
        assert_eq!(v[0]["annotations"][0], "logs: \"hi\"");
    }

    #[test]
    fn rewrite_functions_json_keeps_symbol_original_name_when_name_already_renamed() {
        // Simulates the Phase-1 pass-2 state: functions.json's `name` is already the
        // recovered name, but the Symbol still carries the true original.
        let dir = tmp("pme_sym_prov");
        std::fs::create_dir_all(&dir).unwrap();
        let function = ghidra_function("real", 0x10, 0x18, &[]);
        std::fs::write(
            dir.join("functions.json"),
            // pass-2 state: name was renamed to "real" already; no original_name field yet.
            serde_json::to_vec(&vec![function]).unwrap(),
        )
        .unwrap();
        let execution_blake3 = load_functions(&dir, &DisasmIndex::new(""), &test_runtime())
            .unwrap()[0]
            .execution_blake3;
        let syms = vec![Symbol {
            address: "0x10".into(),
            arch: "arm",
            tool: crate::recover_source::Tool::Ghidra,
            owner: FunctionOwner::Ghidra,
            execution_blake3,
            original_name: "FUN_10".into(), // the true original
            name: Some("real".into()),
            tier: Tier::Recovered,
            evidence: vec![],
            annotations: vec![],
        }];
        rewrite_functions_json(&dir, &test_runtime(), &syms).unwrap();
        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("functions.json")).unwrap()).unwrap();
        assert_eq!(v[0]["name"], "real");
        // CRITICAL: original_name must come from the Symbol, not from the renamed
        // functions.json `name` field. If we read functions.json's name here we'd
        // record "real" and lose the original.
        assert_eq!(v[0]["original_name"], "FUN_10");
    }

    #[test]
    fn rewrite_functions_preserves_v3_provenance() {
        let dir = tmp("pme_sym_v3_rewrite_functions");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("thumb_functions.json");
        let original = crate::thumb_analysis::ParsedThumbArtifact::consumer_v3_fixture();
        std::fs::write(&path, original).unwrap();
        let before: serde_json::Value = serde_json::from_slice(original).unwrap();

        rewrite_functions_json(&dir, &test_runtime(), &[thumb_symbol()]).unwrap();

        let rewritten_bytes = std::fs::read(&path).unwrap();
        crate::thumb_analysis::parse_thumb_artifact(&rewritten_bytes, &test_runtime()).unwrap();
        let after: serde_json::Value = serde_json::from_slice(&rewritten_bytes).unwrap();
        assert_eq!(after["format"], before["format"]);
        assert_eq!(after["producers"], before["producers"]);
        assert_eq!(after["regions"], before["regions"]);
        assert_eq!(
            after["functions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|function| function["entry"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["0x4000", "0x4040"]
        );
        assert_eq!(after["functions"][0]["name"], "recovered_thumb");
        assert_eq!(after["functions"][0]["original_name"], "thumb_4000");
        assert_eq!(
            after["functions"][0]["annotations"],
            serde_json::json!(["file: modem.c"])
        );
        let mut before_function = before["functions"][0].clone();
        let mut after_function = after["functions"][0].clone();
        for field in ["name", "original_name", "annotations"] {
            before_function.as_object_mut().unwrap().remove(field);
            after_function.as_object_mut().unwrap().remove(field);
        }
        assert_eq!(after_function, before_function);
        assert_eq!(after["functions"][1], before["functions"][1]);
    }

    #[test]
    fn rewrite_body_c_preserves_v3_provenance() {
        let dir = tmp("pme_sym_v3_rewrite_body_c");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("thumb_functions.json");
        std::fs::write(
            &path,
            crate::thumb_analysis::ParsedThumbArtifact::consumer_v3_fixture(),
        )
        .unwrap();
        let mut artifact =
            crate::thumb_analysis::read_thumb_artifact(&path, &test_runtime()).unwrap();
        artifact.function_values_mut()[0]["body_c"] =
            serde_json::json!("void thumb_4000(void) { thumb_4000(); }");
        artifact.write_atomic(&path).unwrap();
        let before_bytes = std::fs::read(&path).unwrap();
        let before: serde_json::Value = serde_json::from_slice(&before_bytes).unwrap();

        rewrite_body_c_in_thumb_functions(&dir, &test_runtime(), &[thumb_symbol()]).unwrap();

        let rewritten_bytes = std::fs::read(&path).unwrap();
        crate::thumb_analysis::parse_thumb_artifact(&rewritten_bytes, &test_runtime()).unwrap();
        let after: serde_json::Value = serde_json::from_slice(&rewritten_bytes).unwrap();
        assert_eq!(after["format"], before["format"]);
        assert_eq!(after["producers"], before["producers"]);
        assert_eq!(after["regions"], before["regions"]);
        assert_eq!(
            after["functions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|function| function["entry"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["0x4000", "0x4040"]
        );
        assert_eq!(
            after["functions"][0]["body_c"],
            "void recovered_thumb(void) { recovered_thumb(); }"
        );
        let mut before_function = before["functions"][0].clone();
        let mut after_function = after["functions"][0].clone();
        before_function.as_object_mut().unwrap().remove("body_c");
        after_function.as_object_mut().unwrap().remove("body_c");
        assert_eq!(after_function, before_function);
        assert_eq!(after["functions"][1], before["functions"][1]);
    }

    #[test]
    fn v3_noop_mutation_is_byte_identical() {
        let dir = tmp("pme_sym_v3_noop_functions");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("thumb_functions.json");
        let original = crate::thumb_analysis::ParsedThumbArtifact::consumer_v3_fixture();
        std::fs::write(&path, original).unwrap();

        rewrite_functions_json(&dir, &test_runtime(), &[]).unwrap();

        assert_eq!(std::fs::read(path).unwrap(), original);
    }

    #[test]
    fn v3_body_c_noop_mutation_is_byte_identical() {
        let dir = tmp("pme_sym_v3_noop_body_c");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("thumb_functions.json");
        let original = crate::thumb_analysis::ParsedThumbArtifact::consumer_v3_fixture();
        std::fs::write(&path, original).unwrap();

        rewrite_body_c_in_thumb_functions(&dir, &test_runtime(), &[]).unwrap();

        assert_eq!(std::fs::read(path).unwrap(), original);
    }

    #[test]
    fn symbolicate_image_end_to_end() {
        let root = tmp("pme_sym_e2e");
        let dec = root.join("images/02_MAIN/decompiled");
        std::fs::create_dir_all(&dec).unwrap();
        let image = vec![0u8; 0x20];
        // one ARM function that materializes token 0x00000cc9 via movw
        std::fs::write(
            dec.join("functions.json"),
            serde_json::to_vec(&vec![ghidra_function_in_image(
                "FUN_10",
                0x10,
                0x18,
                &[],
                &image,
                0,
            )])
            .unwrap(),
        )
        .unwrap();
        std::fs::write(
            dec.join("disasm.lst"),
            "0x10: 41f2 movw r0, 0xcc9\n0x14: 4770 bx lr\n",
        )
        .unwrap();
        std::fs::write(dec.join("decompiled.c"), "void FUN_10(void){}\n").unwrap();
        std::fs::write(root.join("images/02_MAIN/02_MAIN.bin"), &image).unwrap();
        // token DB with token 0xcc9 -> a format string
        let db = crate::tokens::Database {
            reserved: 0,
            entries: vec![crate::tokens::Entry {
                token: 0xcc9,
                date_removed: None,
                string: "■format♦Latency %d■domain♦Perf".into(),
            }],
        };
        let tokmap = token_map(&db);
        let manifest = root.join("manifest.json");
        std::fs::write(&manifest, r#"{"toc":[{"name":"MAIN","load_addr":0}]}"#).unwrap();

        symbolicate_image(&root.join("images/02_MAIN"), "02_MAIN", &tokmap, &manifest).unwrap();

        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dec.join("symbols.json")).unwrap()).unwrap();
        assert_eq!(v["counts"]["named_provisional"], 1);
        let name = v["symbols"][0]["name"].as_str().unwrap();
        assert!(name.starts_with("guess_"), "not a marked guess: {name}");
        // decompiled.c rewritten in place
        let c = std::fs::read_to_string(dec.join("decompiled.c")).unwrap();
        assert!(c.contains("guess_") && !c.contains("FUN_10"));
    }

    #[test]
    fn build_map_returns_symbols_without_writing_files() {
        let root = tmp("pme_sym_build_map");
        let dec = root.join("images/02_MAIN/decompiled");
        std::fs::create_dir_all(&dec).unwrap();
        let image = vec![0u8; 0x20];
        std::fs::write(
            dec.join("functions.json"),
            serde_json::to_vec(&vec![ghidra_function_in_image(
                "FUN_10",
                0x10,
                0x18,
                &[],
                &image,
                0,
            )])
            .unwrap(),
        )
        .unwrap();
        std::fs::write(root.join("images/02_MAIN/02_MAIN.bin"), &image).unwrap();
        std::fs::write(
            dec.join("disasm.lst"),
            "0x10: 41f2 movw r0, 0xcc9\n0x14: 4770 bx lr\n",
        )
        .unwrap();
        let db = crate::tokens::Database {
            reserved: 0,
            entries: vec![crate::tokens::Entry {
                token: 0xcc9,
                date_removed: None,
                string: "■format♦Latency %d■domain♦Perf".into(),
            }],
        };
        let tokmap = token_map(&db);
        let manifest = root.join("manifest.json");
        std::fs::write(&manifest, r#"{"toc":[{"name":"MAIN","load_addr":0}]}"#).unwrap();

        let symbols =
            build_map(&root.join("images/02_MAIN"), "02_MAIN", &tokmap, &manifest).unwrap();

        assert_eq!(symbols.len(), 1);
        assert!(symbols[0].name.as_deref().unwrap().starts_with("guess_"));
        // Crucially: build_map does NOT write symbols.json yet.
        assert!(!dec.join("symbols.json").exists());
    }

    #[test]
    fn build_map_emits_string_ref_guess_when_globals_present() {
        let root = tmp("pme_sym_stringref");
        let dec = root.join("images/02_MAIN/decompiled");
        std::fs::create_dir_all(&dec).unwrap();
        // raw image: identifier "MyMod_DoInit" at offset 0x10 -> vaddr 0x40000010
        let mut img = vec![0u8; 0x40];
        img[0x10..0x10 + 12].copy_from_slice(b"MyMod_DoInit");
        std::fs::write(root.join("images/02_MAIN/02_MAIN.bin"), &img).unwrap();
        std::fs::write(
            dec.join("functions.json"),
            serde_json::to_vec(&vec![ghidra_function_in_image(
                "FUN_40000020",
                0x4000_0020,
                0x4000_0028,
                &[0x4000_0010],
                &img,
                0x4000_0000,
            )])
            .unwrap(),
        )
        .unwrap();
        std::fs::write(dec.join("disasm.lst"), "0x40000020: 4770 bx lr\n").unwrap();
        std::fs::write(dec.join("globals.json"), r#"{"globals":[]}"#).unwrap();
        let manifest = root.join("manifest.json");
        std::fs::write(
            &manifest,
            r#"{"toc":[{"name":"MAIN","load_addr":1073741824}]}"#,
        )
        .unwrap();

        let symbols = build_map(
            &root.join("images/02_MAIN"),
            "02_MAIN",
            &HashMap::new(),
            &manifest,
        )
        .unwrap();
        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].tier, Tier::Provisional);
        let name = symbols[0].name.as_deref().unwrap();
        assert!(name.starts_with("guess_MyMod_DoInit_"), "got {name}");
        assert!(symbols[0].evidence.iter().any(|e| e.kind == "string_ref"));
    }

    #[test]
    fn build_map_applies_registration_table_names() {
        let root = tmp("pme_sym_regtable");
        let dec = root.join("images/02_MAIN/decompiled");
        std::fs::create_dir_all(&dec).unwrap();
        // Raw image (load 0x40000000): three name strings + a {name,fn} table
        // at 0x10 pointing at three ARM function entries (0x200/0x240/0x280).
        let mut img = vec![0u8; 0x300];
        let put_str = |img: &mut [u8], off: usize, s: &str| {
            img[off..off + s.len()].copy_from_slice(s.as_bytes());
        };
        put_str(&mut img, 0x100, "Handler_One");
        put_str(&mut img, 0x120, "Handler_Two");
        put_str(&mut img, 0x140, "Handler_Three");
        let put_u32 = |img: &mut [u8], off: usize, v: u32| {
            img[off..off + 4].copy_from_slice(&v.to_le_bytes());
        };
        for (k, (na, fa)) in [
            (0x4000_0100u32, 0x4000_0200u32),
            (0x4000_0120, 0x4000_0240),
            (0x4000_0140, 0x4000_0280),
        ]
        .iter()
        .enumerate()
        {
            put_u32(&mut img, 0x10 + k * 8, *na);
            put_u32(&mut img, 0x10 + k * 8 + 4, *fa);
        }
        std::fs::write(root.join("images/02_MAIN/02_MAIN.bin"), &img).unwrap();
        std::fs::write(
            dec.join("functions.json"),
            serde_json::to_vec(&vec![
                ghidra_function_in_image(
                    "FUN_200",
                    0x4000_0200,
                    0x4000_0208,
                    &[],
                    &img,
                    0x4000_0000,
                ),
                ghidra_function_in_image(
                    "FUN_240",
                    0x4000_0240,
                    0x4000_0248,
                    &[],
                    &img,
                    0x4000_0000,
                ),
                ghidra_function_in_image(
                    "FUN_280",
                    0x4000_0280,
                    0x4000_0288,
                    &[],
                    &img,
                    0x4000_0000,
                ),
            ])
            .unwrap(),
        )
        .unwrap();
        std::fs::write(dec.join("disasm.lst"), "0x40000200: 4770 bx lr\n").unwrap();
        let manifest = root.join("manifest.json");
        std::fs::write(
            &manifest,
            r#"{"toc":[{"name":"MAIN","load_addr":1073741824}]}"#,
        )
        .unwrap();

        let symbols = build_map(
            &root.join("images/02_MAIN"),
            "02_MAIN",
            &HashMap::new(),
            &manifest,
        )
        .unwrap();

        let by_addr = |a: &str| symbols.iter().find(|s| s.address == a).unwrap();
        let s = by_addr("0x40000200");
        assert_eq!(s.name.as_deref(), Some("Handler_One"));
        assert_eq!(s.tier, Tier::Recovered);
        assert!(s.evidence.iter().any(|e| e.kind == "registration"));
        assert_eq!(by_addr("0x40000280").name.as_deref(), Some("Handler_Three"));
    }

    #[test]
    fn build_map_registration_does_not_override_an_existing_real_name() {
        let root = tmp("pme_sym_regtable_realname");
        let dec = root.join("images/02_MAIN/decompiled");
        std::fs::create_dir_all(&dec).unwrap();
        let mut img = vec![0u8; 0x300];
        let put_str = |img: &mut [u8], off: usize, s: &str| {
            img[off..off + s.len()].copy_from_slice(s.as_bytes());
        };
        put_str(&mut img, 0x100, "Handler_One");
        put_str(&mut img, 0x120, "Handler_Two");
        put_str(&mut img, 0x140, "Handler_Three");
        let put_u32 = |img: &mut [u8], off: usize, v: u32| {
            img[off..off + 4].copy_from_slice(&v.to_le_bytes());
        };
        for (k, (na, fa)) in [
            (0x4000_0100u32, 0x4000_0200u32),
            (0x4000_0120, 0x4000_0240),
            (0x4000_0140, 0x4000_0280),
        ]
        .iter()
        .enumerate()
        {
            put_u32(&mut img, 0x10 + k * 8, *na);
            put_u32(&mut img, 0x10 + k * 8 + 4, *fa);
        }
        std::fs::write(root.join("images/02_MAIN/02_MAIN.bin"), &img).unwrap();
        // 0x40000200 ALREADY has a real (non-FUN_) name — a table entry must not
        // clobber it; the two FUN_ entries are still named.
        std::fs::write(
            dec.join("functions.json"),
            serde_json::to_vec(&vec![
                ghidra_function_in_image(
                    "OS_Delete_Semaphore",
                    0x4000_0200,
                    0x4000_0208,
                    &[],
                    &img,
                    0x4000_0000,
                ),
                ghidra_function_in_image(
                    "FUN_240",
                    0x4000_0240,
                    0x4000_0248,
                    &[],
                    &img,
                    0x4000_0000,
                ),
                ghidra_function_in_image(
                    "FUN_280",
                    0x4000_0280,
                    0x4000_0288,
                    &[],
                    &img,
                    0x4000_0000,
                ),
            ])
            .unwrap(),
        )
        .unwrap();
        std::fs::write(dec.join("disasm.lst"), "0x40000200: 4770 bx lr\n").unwrap();
        let manifest = root.join("manifest.json");
        std::fs::write(
            &manifest,
            r#"{"toc":[{"name":"MAIN","load_addr":1073741824}]}"#,
        )
        .unwrap();

        let symbols = build_map(
            &root.join("images/02_MAIN"),
            "02_MAIN",
            &HashMap::new(),
            &manifest,
        )
        .unwrap();

        let by_addr = |a: &str| symbols.iter().find(|s| s.address == a).unwrap();
        let real = by_addr("0x40000200");
        assert_eq!(real.tier, Tier::None, "real name must not be overridden");
        assert!(real.name.is_none());
        assert!(!real.evidence.iter().any(|e| e.kind == "registration"));
        // the unnamed (FUN_) entries are still recovered
        assert_eq!(by_addr("0x40000280").name.as_deref(), Some("Handler_Three"));
    }

    #[test]
    fn build_map_does_not_string_ref_guess_an_already_real_name() {
        let root = tmp("pme_sym_stringref_realname");
        let dec = root.join("images/02_MAIN/decompiled");
        std::fs::create_dir_all(&dec).unwrap();
        // raw image: identifier "MyMod_DoInit" at offset 0x10 -> vaddr 0x40000010
        let mut img = vec![0u8; 0x40];
        img[0x10..0x10 + 12].copy_from_slice(b"MyMod_DoInit");
        std::fs::write(root.join("images/02_MAIN/02_MAIN.bin"), &img).unwrap();
        // Unlike the FUN_100 case above, this function's name is ALREADY real
        // (e.g. a Ghidra-FID match) — the string-ref tier must not displace it.
        std::fs::write(
            dec.join("functions.json"),
            serde_json::to_vec(&vec![ghidra_function_in_image(
                "MyRealFn",
                0x4000_0020,
                0x4000_0028,
                &[0x4000_0010],
                &img,
                0x4000_0000,
            )])
            .unwrap(),
        )
        .unwrap();
        std::fs::write(dec.join("disasm.lst"), "0x40000020: 4770 bx lr\n").unwrap();
        std::fs::write(dec.join("globals.json"), r#"{"globals":[]}"#).unwrap();
        let manifest = root.join("manifest.json");
        std::fs::write(
            &manifest,
            r#"{"toc":[{"name":"MAIN","load_addr":1073741824}]}"#,
        )
        .unwrap();

        let symbols = build_map(
            &root.join("images/02_MAIN"),
            "02_MAIN",
            &HashMap::new(),
            &manifest,
        )
        .unwrap();
        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].tier, Tier::None);
        assert!(
            symbols[0].name.is_none(),
            "real name must not be displaced by a string-ref guess"
        );
    }

    #[test]
    fn build_map_skips_string_ref_without_globals_json() {
        let root = tmp("pme_sym_stringref_off");
        let dec = root.join("images/02_MAIN/decompiled");
        std::fs::create_dir_all(&dec).unwrap();
        let mut img = vec![0u8; 0x40];
        img[0x10..0x10 + 12].copy_from_slice(b"MyMod_DoInit");
        std::fs::write(root.join("images/02_MAIN/02_MAIN.bin"), &img).unwrap();
        std::fs::write(
            dec.join("functions.json"),
            serde_json::to_vec(&vec![ghidra_function_in_image(
                "FUN_40000020",
                0x4000_0020,
                0x4000_0028,
                &[0x4000_0010],
                &img,
                0x4000_0000,
            )])
            .unwrap(),
        )
        .unwrap();
        std::fs::write(dec.join("disasm.lst"), "0x40000020: 4770 bx lr\n").unwrap();
        // no globals.json
        let manifest = root.join("manifest.json");
        std::fs::write(
            &manifest,
            r#"{"toc":[{"name":"MAIN","load_addr":1073741824}]}"#,
        )
        .unwrap();

        let symbols = build_map(
            &root.join("images/02_MAIN"),
            "02_MAIN",
            &HashMap::new(),
            &manifest,
        )
        .unwrap();
        assert_eq!(symbols[0].tier, Tier::None);
        assert!(symbols[0].name.is_none());
    }

    #[test]
    fn finalize_image_writes_symbols_json_when_given_symbols() {
        let root = tmp("pme_sym_finalize");
        let dec = root.join("images/02_MAIN/decompiled");
        std::fs::create_dir_all(&dec).unwrap();
        let execution_blake3 = write_test_ghidra_function(&dec, "FUN_10", 0x10, 0x18);
        let symbols = vec![Symbol {
            address: "0x10".into(),
            arch: "arm",
            tool: crate::recover_source::Tool::Ghidra,
            owner: FunctionOwner::Ghidra,
            execution_blake3: Some(execution_blake3),
            original_name: "FUN_10".into(),
            name: Some("real".into()),
            tier: Tier::Recovered,
            evidence: vec![],
            annotations: vec![],
        }];
        let opts = FinalizeOpts {
            rewrite_decompiled_c: true,
        };
        let path = finalize_image(
            &root.join("images/02_MAIN"),
            "02_MAIN",
            &test_runtime(),
            &symbols,
            &opts,
        )
        .unwrap();
        assert!(path.ends_with("symbols.json"));
        assert!(dec.join("symbols.json").exists());
        // functions.json was rewritten with original_name.
        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dec.join("functions.json")).unwrap()).unwrap();
        assert_eq!(v[0]["name"], "real");
        assert_eq!(v[0]["original_name"], "FUN_10");
    }

    #[test]
    fn write_symbol_map_round_trips() {
        let dir = tmp("pme_sym_map_rt");
        std::fs::create_dir_all(&dir).unwrap();
        let symbols = vec![
            Symbol {
                address: "0x40e1bff4".into(),
                arch: "arm",
                tool: crate::recover_source::Tool::Ghidra,
                owner: FunctionOwner::Ghidra,
                execution_blake3: None,
                original_name: "FUN_40e1bff4".into(),
                name: Some("LteRrc_Reestab".into()),
                tier: Tier::Recovered,
                evidence: vec![],
                annotations: vec!["logs: \"RRC Reestab (%d)\" [LTE_RRC_METRICS]".into()],
            },
            Symbol {
                address: "0x40e1c000".into(),
                arch: "arm",
                tool: crate::recover_source::Tool::Ghidra,
                owner: FunctionOwner::Ghidra,
                execution_blake3: None,
                original_name: "FUN_40e1c000".into(),
                name: None, // Tier::None — no rename
                tier: Tier::None,
                evidence: vec![],
                annotations: vec![],
            },
        ];
        let path =
            write_symbol_map(&dir.join("m.json"), "02_MAIN", &symbols, "abc", "def").unwrap();

        let parsed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(parsed["tool_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(parsed["image"], "02_MAIN");
        assert_eq!(parsed["source_blake3"], "abc");
        assert_eq!(parsed["functions_blake3"], "def");
        let syms = parsed["symbols"].as_array().unwrap();
        assert_eq!(syms.len(), 2);
        assert_eq!(syms[0]["entry"], "0x40e1bff4");
        assert_eq!(syms[0]["arch"], "arm");
        assert_eq!(syms[0]["original_name"], "FUN_40e1bff4");
        assert_eq!(syms[0]["name"], "LteRrc_Reestab");
        assert_eq!(syms[0]["tier"], "recovered");
        assert_eq!(
            syms[0]["annotations"][0],
            "logs: \"RRC Reestab (%d)\" [LTE_RRC_METRICS]"
        );
        // name omitted on Tier::None entries via skip_serializing_if
        assert!(syms[1].get("name").is_none() || syms[1]["name"].is_null());
        assert_eq!(syms[1]["tier"], "none");
    }

    #[test]
    fn finalize_image_with_rewrite_false_leaves_decompiled_c_untouched() {
        let root = tmp("pme_sym_no_rewrite");
        let dec = root.join("images/02_MAIN/decompiled");
        std::fs::create_dir_all(&dec).unwrap();
        let execution_blake3 = write_test_ghidra_function(&dec, "FUN_10", 0x10, 0x18);
        std::fs::write(dec.join("decompiled.c"), "void FUN_10(void) {}\n").unwrap();
        let symbols = vec![Symbol {
            address: "0x10".into(),
            arch: "arm",
            tool: crate::recover_source::Tool::Ghidra,
            owner: FunctionOwner::Ghidra,
            execution_blake3: Some(execution_blake3),
            original_name: "FUN_10".into(),
            name: Some("real".into()),
            tier: Tier::Recovered,
            evidence: vec![],
            annotations: vec![],
        }];
        finalize_image(
            &root.join("images/02_MAIN"),
            "02_MAIN",
            &test_runtime(),
            &symbols,
            &FinalizeOpts {
                rewrite_decompiled_c: false,
            },
        )
        .unwrap();
        // decompiled.c untouched
        assert_eq!(
            std::fs::read_to_string(dec.join("decompiled.c")).unwrap(),
            "void FUN_10(void) {}\n"
        );
        // symbols.json still emitted
        assert!(dec.join("symbols.json").exists());
    }

    fn write_thumb_functions_v3_with_body_c(dec: &std::path::Path) {
        let path = dec.join("thumb_functions.json");
        std::fs::write(
            &path,
            crate::thumb_analysis::ParsedThumbArtifact::consumer_v3_fixture(),
        )
        .unwrap();
        let mut artifact =
            crate::thumb_analysis::read_thumb_artifact(&path, &test_runtime()).unwrap();
        artifact.function_values_mut()[0]["body_c"] =
            serde_json::json!("void thumb_4000(void) { thumb_4000(); }");
        artifact.write_atomic(&path).unwrap();
    }

    fn stamping_symbols() -> Vec<Symbol> {
        let mut thumb = thumb_symbol();
        thumb.name = Some("RealName".into());
        thumb.annotations = vec!["log: boot".into()];
        let function = ghidra_function("FUN_10", 0x10, 0x18, &[]);
        let inventory = crate::execution_ranges::validate_ghidra_inventory_records(
            std::slice::from_ref(&function),
            1,
            &test_runtime(),
        )
        .unwrap();
        let execution_blake3 = inventory.accepted_executions[0].identity.execution_blake3;
        vec![
            thumb,
            Symbol {
                address: "0x00000010".into(),
                arch: "arm",
                tool: crate::recover_source::Tool::Ghidra,
                owner: FunctionOwner::Ghidra,
                execution_blake3: Some(execution_blake3),
                original_name: "FUN_10".into(),
                name: None,
                tier: Tier::Recovered,
                evidence: vec![],
                annotations: vec![],
            },
        ]
    }

    fn write_stamping_fixtures(dec: &std::path::Path) {
        std::fs::write(
            dec.join("functions.json"),
            serde_json::to_vec(&vec![
                ghidra_function("FUN_10", 0x10, 0x18, &[]),
                ghidra_function("FUN_20", 0x20, 0x28, &[]),
            ])
            .unwrap(),
        )
        .unwrap();
        std::fs::write(
            dec.join("thumb_functions.json"),
            crate::thumb_analysis::ParsedThumbArtifact::consumer_v3_fixture(),
        )
        .unwrap();
    }

    #[test]
    fn streaming_stamp_rewrite_matches_whole_oracle() {
        let mut dirs = Vec::new();
        for _ in 0..2 {
            let root = tmp(&format!("pme_sym_stamp_ab_{}", std::process::id()));
            let dec = root.join("decompiled");
            std::fs::create_dir_all(&dec).unwrap();
            write_stamping_fixtures(&dec);
            dirs.push(dec);
        }
        let symbols = stamping_symbols();
        rewrite_functions_json(&dirs[0], &test_runtime(), &symbols).unwrap();
        rewrite_functions_json_whole(&dirs[1], &symbols).unwrap();
        for name in ["functions.json", "thumb_functions.json"] {
            assert_eq!(
                std::fs::read(dirs[0].join(name)).unwrap(),
                std::fs::read(dirs[1].join(name)).unwrap(),
                "{name}: streaming must match the whole-file oracle"
            );
        }
        // Idempotent re-run: stable bytes.
        let before = std::fs::read(dirs[0].join("thumb_functions.json")).unwrap();
        rewrite_functions_json(&dirs[0], &test_runtime(), &symbols).unwrap();
        assert_eq!(
            before,
            std::fs::read(dirs[0].join("thumb_functions.json")).unwrap()
        );
    }

    #[test]
    fn streaming_body_c_rewrite_matches_whole_oracle() {
        let mut dirs = Vec::new();
        for _ in 0..2 {
            let root = tmp(&format!("pme_sym_bodyc_ab_{}", std::process::id()));
            let dec = root.join("decompiled");
            std::fs::create_dir_all(&dec).unwrap();
            write_thumb_functions_v3_with_body_c(&dec);
            dirs.push(dec);
        }
        let symbols = vec![real_name_symbol_for_4000()];
        rewrite_body_c_in_thumb_functions(&dirs[0], &test_runtime(), &symbols).unwrap();
        rewrite_body_c_in_thumb_functions_whole(&dirs[1], &symbols).unwrap();
        assert_eq!(
            std::fs::read(dirs[0].join("thumb_functions.json")).unwrap(),
            std::fs::read(dirs[1].join("thumb_functions.json")).unwrap()
        );
        let after = std::fs::read_to_string(dirs[0].join("thumb_functions.json")).unwrap();
        assert!(after.contains("RealName(void)"), "body_c renamed: {after}");
    }

    fn real_name_symbol_for_4000() -> Symbol {
        let mut symbol = thumb_symbol();
        symbol.name = Some("RealName".into());
        symbol.annotations.clear();
        symbol
    }

    #[test]
    fn finalize_image_preserves_body_c_when_rewrite_decompiled_c_false() {
        let root = tmp("pme_sym_body_c_preserve");
        let dec = root.join("images/02_MAIN/decompiled");
        std::fs::create_dir_all(&dec).unwrap();
        write_thumb_functions_v3_with_body_c(&dec);

        let symbols = vec![real_name_symbol_for_4000()];
        finalize_image(
            &root.join("images/02_MAIN"),
            "02_MAIN",
            &test_runtime(),
            &symbols,
            &FinalizeOpts {
                rewrite_decompiled_c: false,
            },
        )
        .unwrap();

        let after = std::fs::read_to_string(dec.join("thumb_functions.json")).unwrap();
        // body_c-specific: `thumb_4000(void)` appears only inside body_c text,
        // never as a field value (the `name` field legitimately becomes RealName
        // via the ungated rewrite_functions_json pass).
        assert!(
            after.contains("thumb_4000(void)"),
            "body_c must be byte-identical when rewrite_decompiled_c=false: {after}"
        );
        assert!(
            !after.contains("RealName(void)"),
            "body_c must not be renamed when rewrite_decompiled_c=false: {after}"
        );
    }

    #[test]
    fn finalize_image_renames_body_c_when_rewrite_decompiled_c_true() {
        let root = tmp("pme_sym_body_c_rename");
        let dec = root.join("images/02_MAIN/decompiled");
        std::fs::create_dir_all(&dec).unwrap();
        write_thumb_functions_v3_with_body_c(&dec);

        let symbols = vec![real_name_symbol_for_4000()];
        finalize_image(
            &root.join("images/02_MAIN"),
            "02_MAIN",
            &test_runtime(),
            &symbols,
            &FinalizeOpts {
                rewrite_decompiled_c: true,
            },
        )
        .unwrap();

        let after = std::fs::read_to_string(dec.join("thumb_functions.json")).unwrap();
        assert!(
            after.contains("RealName(void)"),
            "body_c must be renamed when rewrite_decompiled_c=true: {after}"
        );
        assert!(
            !after.contains("thumb_4000(void)"),
            "original name must be gone from body_c after rewrite: {after}"
        );
    }

    #[test]
    #[ignore = "measurement: PME_SYMBOLICATE_MEASURE=1 PME_GOLDEN_DIR=<tree>"]
    fn string_ref_yield_on_retained_tree() {
        if std::env::var("PME_SYMBOLICATE_MEASURE").ok().as_deref() != Some("1") {
            eprintln!("skip: set PME_SYMBOLICATE_MEASURE=1");
            return;
        }
        let Some(dir) = std::env::var_os("PME_GOLDEN_DIR").map(std::path::PathBuf::from) else {
            eprintln!("skip: set PME_GOLDEN_DIR");
            return;
        };
        if !dir.exists() {
            eprintln!("skip: PME_GOLDEN_DIR not found: {}", dir.display());
            return;
        }
        let manifest = dir.join("manifest.json");
        let image_dir = dir.join("images/02_MAIN");
        // Empty token map isolates the string-ref tier from token guesses.
        // build_map does not write, so the retained tree is not mutated.
        let symbols = build_map(&image_dir, "02_MAIN", &HashMap::new(), &manifest).unwrap();
        let string_ref = symbols
            .iter()
            .filter(|s| s.evidence.iter().any(|e| e.kind == "string_ref"))
            .count();
        eprintln!("02_MAIN string_ref guesses: {string_ref}");
        for s in symbols
            .iter()
            .filter(|s| s.evidence.iter().any(|e| e.kind == "string_ref"))
            .take(15)
        {
            eprintln!("  {} {}", s.address, s.name.as_deref().unwrap_or("?"));
        }
        assert!(
            string_ref > 4000,
            "string-ref yield unexpectedly low: {string_ref}"
        );
    }

    #[test]
    #[ignore = "measurement: PME_SYMBOLICATE_MEASURE=1 PME_GOLDEN_DIR=<tree>"]
    fn registration_yield_on_retained_tree() {
        if std::env::var("PME_SYMBOLICATE_MEASURE").ok().as_deref() != Some("1") {
            eprintln!("skip: set PME_SYMBOLICATE_MEASURE=1");
            return;
        }
        let Some(dir) = std::env::var_os("PME_GOLDEN_DIR").map(std::path::PathBuf::from) else {
            eprintln!("skip: set PME_GOLDEN_DIR");
            return;
        };
        // Find the model-dependent MAIN image (02_MAIN mustang / 01_MAIN cheetah).
        let Some(main) = std::fs::read_dir(dir.join("images"))
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .find(|n| n.ends_with("_MAIN"))
        else {
            eprintln!("skip: no *_MAIN image under {}", dir.display());
            return;
        };
        let symbols = build_map(
            &dir.join("images").join(&main),
            &main,
            &HashMap::new(),
            &dir.join("manifest.json"),
        )
        .unwrap();
        let regs: Vec<&Symbol> = symbols
            .iter()
            .filter(|s| s.evidence.iter().any(|e| e.kind == "registration"))
            .collect();
        let named = regs.iter().filter(|s| s.tier == Tier::Recovered).count();
        eprintln!(
            "{main} registration names: {} (recovered {named})",
            regs.len()
        );
        for s in regs.iter().take(20) {
            eprintln!("  {} {}", s.address, s.name.as_deref().unwrap_or("?"));
        }
        assert!(named > 50, "registration yield unexpectedly low: {named}");
    }
}
