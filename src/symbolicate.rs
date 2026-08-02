//! Symbolicate the decompiled modem: recover function names and inline
//! log/assert/file annotations from evidence the pipeline already produces
//! (the pw_tokenizer DB, `__func__` strings, attributed strings, existing
//! attribution), then rewrite the artifacts in place + emit `symbols.json`.
//! Pure-Rust; ARM and Thumb. Fail-closed and tiered: only `__func__` yields a
//! real rename, only a token yields a marked `guess_…` name, everything else is
//! a comment.
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

pub const GUESS_PREFIX: &str = "guess_";

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
}

#[derive(Debug, Clone, Serialize)]
pub struct Symbol {
    pub address: String,    // "0x40e1bff4"
    pub arch: &'static str, // "arm" | "thumb"
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
}

/// One function to symbolicate (unifies ARM + Thumb).
pub struct FuncRec {
    pub arch: &'static str, // "arm" | "thumb"
    pub name: String,       // original, e.g. "FUN_40e1bff4"
    pub entry: u64,
    pub end: u64,
    pub data_refs: Vec<u64>,
    pub disasm: String, // ARM: disasm.lst lines in range; Thumb: the `body`
}

/// 32-bit constants materialized by `movw`/`movt` (and lone `movw`) in a block
/// of disassembly text. Tracks the last `movw #imm` per destination register; a
/// later `movt` on the same register combines to a full value. Register- and
/// format-agnostic across Ghidra (`movw r0,#0x..`) and radare2 (`movw r0, 0x..`),
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
    if let Some((_tok, s)) = raw.tokens.first() {
        let (fmt, dom) = parse_token_string(s);
        let name = format!("{GUESS_PREFIX}{}_{addr_hex}", slugify(&fmt, dom.as_deref()));
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

/// A bare C identifier (3–64 chars), i.e. a plausible `__func__` value.
fn is_ident(s: &str) -> bool {
    let n = s.len();
    (3..=64).contains(&n)
        && s.chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Recover a function's `__func__` name: it must reference a `__FILE__`
/// occurrence vaddr (proving an assert/log site), and exactly one *distinct*
/// `data_refs` identifier must resolve (unambiguous → fail-closed). Dedup by
/// string content first: Ghidra/radare2 can emit the same `__func__` ref twice
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
    let mut seen: HashSet<&str> = HashSet::new();
    let idents: Vec<&String> = data_refs
        .iter()
        .filter_map(|r| strings.get(r))
        .filter(|s| is_ident(s))
        .filter(|s| seen.insert(s.as_str()))
        .collect();
    match idents.as_slice() {
        [only] => Some((*only).clone()),
        _ => None,
    }
}

fn parse_hex(s: &str) -> Result<u64> {
    let t = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(t, 16).map_err(|e| Error::Serialize(format!("bad hex {s}: {e}")))
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

#[derive(Deserialize)]
struct ThumbFileJson {
    #[serde(default)]
    functions: Vec<ThumbFnJson>,
}

#[derive(Deserialize)]
struct ThumbFnJson {
    name: String,
    #[serde(default)]
    original_name: Option<String>,
    entry: String,
    #[serde(default)]
    end: String,
    #[serde(default)]
    data_refs: Vec<String>,
    #[serde(default)]
    body: String,
}

/// Lines of `disasm.lst` whose leading hex address is in `[entry, end)`.
fn disasm_body_for(entry: u64, end: u64, lines_by_addr: &[(u64, &str)]) -> String {
    let mut out = String::new();
    for (addr, line) in lines_by_addr {
        if *addr >= entry && *addr < end {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// Parse the leading address of a `disasm.lst` line. The address is the text
/// before the first ": " (the bytes-column separator); tolerate an optional
/// address-space prefix (`ram:40010120:` -> `40010120`). Returns None for
/// non-address lines (comments, the sentinel, blanks).
fn line_addr(line: &str) -> Option<u64> {
    let head = line.trim_start().split_once(": ")?.0; // "40010120" or "ram:40010120"
    let tok = head.rsplit(':').next()?; // offset after an optional "space:" prefix
    parse_hex(tok).ok()
}

fn load_functions(decompiled: &Path, disasm: &str) -> Result<Vec<FuncRec>> {
    let path = decompiled.join("functions.json");
    let bytes = std::fs::read(&path)?;
    let raw: Vec<ArmFnJson> =
        serde_json::from_slice(&bytes).map_err(|e| Error::Serialize(e.to_string()))?;
    let lines_by_addr: Vec<(u64, &str)> = disasm
        .lines()
        .filter_map(|l| line_addr(l).map(|a| (a, l)))
        .collect();
    let mut out = Vec::with_capacity(raw.len());
    for f in raw {
        let entry = parse_hex(&f.entry)?;
        let end = parse_hex(&f.end)?;
        let data_refs = f
            .data_refs
            .iter()
            .map(|r| parse_hex(r))
            .collect::<Result<Vec<_>>>()?;
        out.push(FuncRec {
            arch: "arm",
            name: f.original_name.unwrap_or(f.name),
            entry,
            end,
            data_refs,
            disasm: disasm_body_for(entry, end, &lines_by_addr),
        });
    }
    Ok(out)
}

fn load_thumb_functions(decompiled: &Path) -> Result<Vec<FuncRec>> {
    let path = decompiled.join("thumb_functions.json");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = std::fs::read(&path)?;
    let file: ThumbFileJson =
        serde_json::from_slice(&bytes).map_err(|e| Error::Serialize(e.to_string()))?;
    let mut out = Vec::with_capacity(file.functions.len());
    for f in file.functions {
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
            disasm: f.body,
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
    entry: String,
}

/// function entry-vaddr -> attributed source path, from `recovered_index.json`.
fn load_attribution(source_tree: &Path) -> Result<HashMap<u64, String>> {
    let path = source_tree.join("recovered_index.json");
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let bytes = std::fs::read(&path)?;
    let idx: RiIndex =
        serde_json::from_slice(&bytes).map_err(|e| Error::Serialize(e.to_string()))?;
    let mut m = HashMap::new();
    for (src, s) in idx.sources {
        for f in s.functions {
            m.insert(parse_hex(&f.entry)?, src.clone());
        }
    }
    Ok(m)
}

#[derive(Deserialize)]
struct ExtractManifest {
    #[serde(default)]
    toc: Vec<TocEntry>,
}
#[derive(Deserialize)]
struct TocEntry {
    name: String,
    load_addr: u64,
}

/// The `load_addr` for a TOC image name (e.g. "MAIN") from the extract manifest.
pub(crate) fn load_load_addr(manifest: &Path, toc_name: &str) -> Result<Option<u64>> {
    if !manifest.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(manifest)?;
    let m: ExtractManifest =
        serde_json::from_slice(&bytes).map_err(|e| Error::Serialize(e.to_string()))?;
    Ok(m.toc
        .into_iter()
        .find(|t| t.name == toc_name)
        .map(|t| t.load_addr))
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
    source_sha256: &'a str,
    functions_sha256: &'a str,
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
    source_sha256: &str,
    functions_sha256: &str,
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
        source_sha256,
        functions_sha256,
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
/// and `thumb_functions.json` (matched by entry address), preserving all other
/// fields. Operates on `serde_json::Value` to avoid a lossy round-trip.
fn rewrite_functions_json(decompiled: &Path, symbols: &[Symbol]) -> Result<()> {
    // entry vaddr -> symbol (numeric, so "0x10" and "0x00000010" match).
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
        let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&tpath)?)
            .map_err(|e| Error::Serialize(e.to_string()))?;
        if let Some(arr) = v.get_mut("functions").and_then(|f| f.as_array_mut()) {
            apply(arr);
        }
        std::fs::write(
            &tpath,
            serde_json::to_string_pretty(&v).map_err(|e| Error::Serialize(e.to_string()))?,
        )?;
    }
    Ok(())
}

/// Rewrite `decompiled.c` and `disasm.lst` in place (text substitution) if present.
/// Also rewrites the `body_c` field of each entry in `thumb_functions.json`
/// (when present) using the same rename map — symmetric with `decompiled.c`
/// since `body_c` is sourced from it. Gated at the call site by
/// `FinalizeOpts::rewrite_decompiled_c`.
fn rewrite_text_files(decompiled: &Path, symbols: &[Symbol]) -> Result<()> {
    for name in ["decompiled.c", "disasm.lst"] {
        let p = decompiled.join(name);
        if p.exists() {
            let text = std::fs::read_to_string(&p)?;
            std::fs::write(&p, rewrite_text(&text, symbols))?;
        }
    }
    rewrite_body_c_in_thumb_functions(decompiled, symbols)?;
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
fn rewrite_body_c_in_thumb_functions(decompiled: &Path, symbols: &[Symbol]) -> Result<()> {
    let path = decompiled.join("thumb_functions.json");
    if !path.exists() {
        return Ok(());
    }
    let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)
        .map_err(|e| Error::Serialize(e.to_string()))?;
    if let Some(arr) = v.get_mut("functions").and_then(|f| f.as_array_mut()) {
        let renames = build_rename_map(symbols);
        for func in arr.iter_mut() {
            let Some(obj) = func.as_object_mut() else {
                continue;
            };
            let Some(body_c) = obj.get("body_c").and_then(|v| v.as_str()) else {
                continue;
            };
            let renamed = apply_rename_map(body_c, &renames);
            obj.insert("body_c".into(), serde_json::Value::String(renamed));
        }
    }
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&v).map_err(|e| Error::Serialize(e.to_string()))?,
    )?;
    Ok(())
}

/// TOC image name for a decompose label, e.g. "02_MAIN" -> "MAIN".
fn toc_name(label: &str) -> &str {
    label.split_once('_').map(|(_, n)| n).unwrap_or(label)
}

/// Tunable parameters for `finalize_image`. Today a single flag controls whether
/// `decompiled.c` / `disasm.lst` are text-rewritten; on the `decompose` two-pass
/// path (Phase 1+), pass 2 regenerates `decompiled.c` and the rewrite is skipped.
pub struct FinalizeOpts {
    pub rewrite_decompiled_c: bool,
}

/// Pure: build the per-image `Symbol` set from pass-1 outputs. No file writes.
pub(crate) fn build_map(
    image_dir: &Path,
    image_label: &str,
    tokens: &HashMap<u32, String>,
    manifest: &Path,
) -> Result<Vec<Symbol>> {
    let decompiled = image_dir.join("decompiled");
    let disasm = std::fs::read_to_string(decompiled.join("disasm.lst")).unwrap_or_default();

    let mut funcs = load_functions(&decompiled, &disasm)?;
    funcs.extend(load_thumb_functions(&decompiled)?);

    let source_tree = image_dir.join("source_tree");
    let (file_occ, file_strings) = if source_tree.join("manifest.json").exists() {
        load_file_occurrences(&source_tree)?
    } else {
        (HashSet::new(), HashMap::new())
    };
    let attribution = load_attribution(&source_tree)?;

    let raw_image_path = image_dir.join(format!("{image_label}.bin"));
    let string_map = match load_load_addr(manifest, toc_name(image_label))? {
        Some(load_addr) if raw_image_path.exists() => {
            build_string_map(&std::fs::read(&raw_image_path)?, load_addr, 3)
        }
        _ => {
            if !file_occ.is_empty() {
                tracing::warn!(
                    "symbolicate: {image_label}: raw image or load_addr missing — skipping __func__ recovery"
                );
            }
            HashMap::new()
        }
    };

    let mut symbols = Vec::with_capacity(funcs.len());
    for f in &funcs {
        let addr_hex = format!("{:08x}", f.entry);
        let mut imms = reconstruct_immediates(&f.disasm);
        imms.extend(f.data_refs.iter().filter_map(|r| u32::try_from(*r).ok()));
        let mut hits: Vec<(u32, String)> = imms
            .iter()
            .filter_map(|v| tokens.get(v).map(|s| (*v, s.clone())))
            .collect();
        hits.sort_by_key(|(t, _)| *t);

        let func_name = if string_map.is_empty() {
            None
        } else {
            recover_func_name(&f.data_refs, &file_occ, &string_map)
        };
        let file = attribution.get(&f.entry).cloned();
        let fstrings = file
            .as_ref()
            .and_then(|p| file_strings.get(p))
            .cloned()
            .unwrap_or_default();

        let raw = RawEvidence {
            func_name,
            tokens: hits,
            file,
            file_strings: fstrings,
        };
        let (name, tier, evidence, annotations) = decide(&addr_hex, &raw);
        symbols.push(Symbol {
            address: format!("0x{addr_hex}"),
            arch: f.arch,
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
    symbols: &[Symbol],
    opts: &FinalizeOpts,
) -> Result<PathBuf> {
    let decompiled = image_dir.join("decompiled");
    let mut inputs = HashMap::new();
    if let Ok(b) = std::fs::read(decompiled.join("functions.json")) {
        inputs.insert(
            "functions_json_sha256".into(),
            crate::manifest::sha256_bytes(&b),
        );
    }

    rewrite_functions_json(&decompiled, symbols)?;
    if opts.rewrite_decompiled_c {
        rewrite_text_files(&decompiled, symbols)?;
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
    finalize_image(
        image_dir,
        image_label,
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
        let out = finalize_image(
            &dir,
            &label,
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
    fn recovered_name_collisions_get_address_suffix() {
        let mut syms = vec![
            Symbol {
                address: "0xaa".into(),
                arch: "arm",
                original_name: "FUN_aa".into(),
                name: Some("dup".into()),
                tier: Tier::Recovered,
                evidence: vec![],
                annotations: vec![],
            },
            Symbol {
                address: "0xbb".into(),
                arch: "arm",
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
            r#"[{"name":"FUN_10","entry":"0x10","end":"0x18","data_refs":["0x200"]}]"#,
        )
        .unwrap();
        let disasm = "0x10: 41f2 movw r0, 0x1\n0x14: c0f2 movt r0, 0x2\n0x20: other\n";
        let fns = load_functions(&dir, disasm).unwrap();
        assert_eq!(fns.len(), 1);
        assert_eq!(fns[0].arch, "arm");
        assert_eq!(fns[0].entry, 0x10);
        assert_eq!(fns[0].data_refs, vec![0x200]);
        assert!(fns[0].disasm.contains("movw") && fns[0].disasm.contains("movt"));
        assert!(!fns[0].disasm.contains("0x20: other")); // out of [entry,end)
    }

    #[test]
    fn loaders_prefer_original_name_on_rerun() {
        let dir = tmp("pme_sym_orig");
        std::fs::create_dir_all(&dir).unwrap();
        // functions.json as left by a prior symbolicate run: `name` renamed, `original_name` kept
        std::fs::write(
            dir.join("functions.json"),
            r#"[{"name":"guess_x_10","original_name":"FUN_10","entry":"0x10","end":"0x18","data_refs":[]}]"#,
        )
        .unwrap();
        let fns = load_functions(&dir, "").unwrap();
        assert_eq!(fns[0].name, "FUN_10"); // true original recovered, not the renamed value
    }

    #[test]
    fn line_addr_parses_plain_and_space_qualified() {
        assert_eq!(
            line_addr("400100b4: 00402de9  stmdb sp!,{lr}"),
            Some(0x400100b4)
        );
        assert_eq!(line_addr("ram:40010120: 00  nop"), Some(0x40010120)); // space-qualified
        assert_eq!(line_addr("0x10: 41f2 movw r0, 0x1"), Some(0x10));
        assert_eq!(line_addr("// pixel-modem-extractor: symbolicated"), None); // sentinel
        assert_eq!(line_addr(""), None);
    }

    #[test]
    fn loads_file_occurrences_and_attribution() {
        let dir = tmp("pme_sym_load_st");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("manifest.json"),
            r#"{"files":{"A/x.c":{"occurrences":[{"vaddr":"0x100"}],"attributed_strings":["reest"]}}}"#).unwrap();
        std::fs::write(
            dir.join("recovered_index.json"),
            r#"{"sources":{"A/x.c":{"functions":[{"entry":"0x10"}]}}}"#,
        )
        .unwrap();
        let (occ, strs) = load_file_occurrences(&dir).unwrap();
        assert!(occ.contains(&0x100));
        assert_eq!(strs["A/x.c"], vec!["reest".to_string()]);
        let attr = load_attribution(&dir).unwrap();
        assert_eq!(attr.get(&0x10).map(String::as_str), Some("A/x.c"));
    }

    // small helper: a fresh temp dir path (see std::env::temp_dir usage in repo tests)
    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn writes_symbols_json_with_counts() {
        let dir = tmp("pme_sym_emit");
        std::fs::create_dir_all(&dir).unwrap();
        let syms = vec![
            Symbol {
                address: "0x10".into(),
                arch: "arm",
                original_name: "FUN_10".into(),
                name: Some("real".into()),
                tier: Tier::Recovered,
                evidence: vec![],
                annotations: vec![],
            },
            Symbol {
                address: "0x20".into(),
                arch: "thumb",
                original_name: "thumb_20".into(),
                name: Some("guess_x_20".into()),
                tier: Tier::Provisional,
                evidence: vec![],
                annotations: vec![],
            },
            Symbol {
                address: "0x30".into(),
                arch: "arm",
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
                original_name: "thumb_40e1200".into(),
                name: Some("guess_short_040e1200".into()),
                tier: Tier::Provisional,
                evidence: vec![],
                annotations: vec![],
            },
            Symbol {
                address: "0x40e12000".into(),
                arch: "thumb",
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
            r#"[{"name":"FUN_10","entry":"0x10","end":"0x18","data_refs":[]}]"#,
        )
        .unwrap();
        let syms = vec![Symbol {
            address: "0x10".into(),
            arch: "arm",
            original_name: "FUN_10".into(),
            name: Some("real".into()),
            tier: Tier::Recovered,
            evidence: vec![],
            annotations: vec!["logs: \"hi\"".into()],
        }];
        rewrite_functions_json(&dir, &syms).unwrap();
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
        std::fs::write(
            dir.join("functions.json"),
            // pass-2 state: name was renamed to "real" already; no original_name field yet.
            r#"[{"name":"real","entry":"0x10","end":"0x18","data_refs":[]}]"#,
        )
        .unwrap();
        let syms = vec![Symbol {
            address: "0x10".into(),
            arch: "arm",
            original_name: "FUN_10".into(), // the true original
            name: Some("real".into()),
            tier: Tier::Recovered,
            evidence: vec![],
            annotations: vec![],
        }];
        rewrite_functions_json(&dir, &syms).unwrap();
        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("functions.json")).unwrap()).unwrap();
        assert_eq!(v[0]["name"], "real");
        // CRITICAL: original_name must come from the Symbol, not from the renamed
        // functions.json `name` field. If we read functions.json's name here we'd
        // record "real" and lose the original.
        assert_eq!(v[0]["original_name"], "FUN_10");
    }

    #[test]
    fn symbolicate_image_end_to_end() {
        let root = tmp("pme_sym_e2e");
        let dec = root.join("images/02_MAIN/decompiled");
        std::fs::create_dir_all(&dec).unwrap();
        // one ARM function that materializes token 0x00000cc9 via movw
        std::fs::write(
            dec.join("functions.json"),
            r#"[{"name":"FUN_10","entry":"0x10","end":"0x18","data_refs":[]}]"#,
        )
        .unwrap();
        std::fs::write(
            dec.join("disasm.lst"),
            "0x10: 41f2 movw r0, 0xcc9\n0x14: 4770 bx lr\n",
        )
        .unwrap();
        std::fs::write(dec.join("decompiled.c"), "void FUN_10(void){}\n").unwrap();
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
        std::fs::write(
            &manifest,
            r#"{"toc":[{"name":"MAIN","load_addr":1073807360}]}"#,
        )
        .unwrap();

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
        std::fs::write(
            dec.join("functions.json"),
            r#"[{"name":"FUN_10","entry":"0x10","end":"0x18","data_refs":[]}]"#,
        )
        .unwrap();
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
    fn finalize_image_writes_symbols_json_when_given_symbols() {
        let root = tmp("pme_sym_finalize");
        let dec = root.join("images/02_MAIN/decompiled");
        std::fs::create_dir_all(&dec).unwrap();
        std::fs::write(
            dec.join("functions.json"),
            r#"[{"name":"FUN_10","entry":"0x10","end":"0x18","data_refs":[]}]"#,
        )
        .unwrap();
        let symbols = vec![Symbol {
            address: "0x10".into(),
            arch: "arm",
            original_name: "FUN_10".into(),
            name: Some("real".into()),
            tier: Tier::Recovered,
            evidence: vec![],
            annotations: vec![],
        }];
        let opts = FinalizeOpts {
            rewrite_decompiled_c: true,
        };
        let path =
            finalize_image(&root.join("images/02_MAIN"), "02_MAIN", &symbols, &opts).unwrap();
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
                original_name: "FUN_40e1bff4".into(),
                name: Some("LteRrc_Reestab".into()),
                tier: Tier::Recovered,
                evidence: vec![],
                annotations: vec!["logs: \"RRC Reestab (%d)\" [LTE_RRC_METRICS]".into()],
            },
            Symbol {
                address: "0x40e1c000".into(),
                arch: "arm",
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
        assert_eq!(parsed["source_sha256"], "abc");
        assert_eq!(parsed["functions_sha256"], "def");
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
        std::fs::write(
            dec.join("functions.json"),
            r#"[{"name":"FUN_10","entry":"0x10","end":"0x18","data_refs":[]}]"#,
        )
        .unwrap();
        std::fs::write(dec.join("decompiled.c"), "void FUN_10(void) {}\n").unwrap();
        let symbols = vec![Symbol {
            address: "0x10".into(),
            arch: "arm",
            original_name: "FUN_10".into(),
            name: Some("real".into()),
            tier: Tier::Recovered,
            evidence: vec![],
            annotations: vec![],
        }];
        finalize_image(
            &root.join("images/02_MAIN"),
            "02_MAIN",
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

    fn write_thumb_functions_v2_with_body_c(dec: &std::path::Path) {
        // v2 with one body_c already populated; the function name appears
        // verbatim in body_c so the test can detect a rewrite (or its absence).
        let original_json = r#"{
            "format": "pixel-modem-extractor-thumb-functions-v2",
            "functions": [
                {"entry": "0x40e1200", "name": "thumb_40e1200", "size": 8,
                 "body_kind": "thumb_disassembly", "body": "bx lr",
                 "body_c": "void thumb_40e1200(void) { return; }",
                 "data_refs": []}
            ]
        }"#;
        std::fs::write(dec.join("thumb_functions.json"), original_json).unwrap();
    }

    fn real_name_symbol_for_40e1200() -> Symbol {
        Symbol {
            address: "0x40e1200".into(),
            arch: "thumb",
            original_name: "thumb_40e1200".into(),
            name: Some("RealName".into()),
            tier: Tier::Recovered,
            evidence: vec![],
            annotations: vec![],
        }
    }

    #[test]
    fn finalize_image_preserves_body_c_when_rewrite_decompiled_c_false() {
        let root = tmp("pme_sym_body_c_preserve");
        let dec = root.join("images/02_MAIN/decompiled");
        std::fs::create_dir_all(&dec).unwrap();
        write_thumb_functions_v2_with_body_c(&dec);

        let symbols = vec![real_name_symbol_for_40e1200()];
        finalize_image(
            &root.join("images/02_MAIN"),
            "02_MAIN",
            &symbols,
            &FinalizeOpts {
                rewrite_decompiled_c: false,
            },
        )
        .unwrap();

        let after = std::fs::read_to_string(dec.join("thumb_functions.json")).unwrap();
        // body_c-specific: `thumb_40e1200(void)` appears only inside body_c text,
        // never as a field value (the `name` field legitimately becomes RealName
        // via the ungated rewrite_functions_json pass).
        assert!(
            after.contains("thumb_40e1200(void)"),
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
        write_thumb_functions_v2_with_body_c(&dec);

        let symbols = vec![real_name_symbol_for_40e1200()];
        finalize_image(
            &root.join("images/02_MAIN"),
            "02_MAIN",
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
            !after.contains("thumb_40e1200(void)"),
            "original name must be gone from body_c after rewrite: {after}"
        );
    }
}
