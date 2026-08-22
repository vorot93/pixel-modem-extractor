//! Phase 3.0: recover global variable names from direct textual evidence
//! (assertion / log strings that mention globals by name). For each function
//! in `functions.json` + `thumb_functions.json` with exactly one non-string
//! `data_ref`, scan its string references for a unique identifier token; if
//! exactly one survives, associate it with that data_ref. Conflicts (same
//! `address`, different `name` from different functions) are dropped.
//!
//! Record-only — does NOT touch the Ghidra program. Output is
//! `images/<label>/decompiled/globals.json` per image, format v1.
//!
//! Strict-single-source-of-truth posture (Phase 1's `Tier::Recovered`
//! extended cross-function). No function-name inference, no disassembly-
//! pattern disambiguation (Phase 3.0.1 territory).

use crate::error::{Error, Result};
use crate::execution_ranges::{ExecutionIdentity, FunctionOwner, execution_identity};
use crate::runtime_image::RuntimeImage;
use crate::source_tree::extract_strings;
use crate::symbolicate;
use atomic_write_file::AtomicWriteFile;
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};
use std::io::Write;
use std::path::Path;
use std::sync::OnceLock;

/// Format string for `globals.json` v1. Future revisions add fields without
/// breaking v1 readers (forward-compat posture identical to Phase 2's
/// `thumb_functions.json` v1→v2).
pub const FORMAT_V1: &str = "pixel-modem-extractor-globals-v1";

/// Phase 3.0.1 proximity window for ARM functions, in load-events (the count
/// of `movw`/`movt` lines strictly between two PCs — an approximation of the
/// design spec's instruction-count metric; the pre-check confirmed this
/// approximation grounds the K pinning). The production pre-check pinned this
/// value at 4; `CONTRIBUTING.md` records the metric and revalidation contract.
/// Do not edit ad hoc — rerun the pre-check if a new firmware variant regresses.
/// Mirrors Phase 2.1's `TIGHTEN_EXTRA` provenance rule (see
/// `src/ghidra/TameAnalysis.java`).
pub const K_ARM: usize = 4;

/// Phase 3.0.1 proximity window for Thumb functions. Same metric and
/// provenance as `K_ARM`. Pinned equal to `K_ARM` on this firmware: the
/// pre-check's 4×4 K_ARM × K_THUMB grid found maximum Recovered yield at
/// K=4/4 with no same-tier conflict explosion, so Thumb does not need a wider
/// window here.
pub const K_THUMB: usize = 4;

/// Defensive perf guard against Ghidra's occasional mis-estimation of function
/// boundaries, which produces synthetic "functions" spanning megabytes of
/// `disasm.lst` (production `02_MAIN` worst case: 37 MB disasm / ~865,534 load-
/// events / 9.3M instructions attributed to a single "function"). Real modem
/// functions are typically well under 1 MB; anything past 5 MB is almost
/// certainly a Ghidra artifact. `disasm_anchored_recovered_for_function` skips
/// such functions silently (returns an empty `Vec`) so Phase 3.0.1 doesn't
/// spend minutes in the O(sl × gl) matcher on a mis-estimated slice. This is a
/// perf guard, not a correctness requirement: Phase 3.0.1's coverage on
/// `02_MAIN` drops only by whatever globals the mega-slices would have
/// produced (recorded in production verification).
const MEGA_FN_THRESHOLD: u64 = 5 * 1024 * 1024;

/// Minimum identifier length. Filters out 1–2 char tokens (`id`, `pt`) that
/// are too generic to be meaningful global names.
const MIN_IDENT_LEN: usize = 3;

/// Generic identifier tokens filtered out of the candidate set. These appear
/// frequently in modem firmware strings (log macros, format specifiers,
/// C keywords) but are extremely unlikely to be global variable names.
/// Extend this set if production pre-checks surface other generic tokens
/// polluting the results.
///
/// Includes DBT and ASSERT adopted from source_tree.rs's STOPLIST to
/// neutralize the observed 0x4908bbac "DBT" attractor. Both are
/// underscoreless so the strict-identifier rule drops them today, but they
/// are listed explicitly so the filter holds if the underscore requirement
/// is ever relaxed.
const GENERIC_TOKENS: &[&str] = &[
    "NULL", "null", "true", "false", "TRUE", "FALSE", "void", "int", "char", "long", "short",
    "unsigned", "signed", "src", "main", "include", "define", "struct", "union", "enum", "return",
    "sizeof", "static", "const", "extern", "volatile", "ERROR", "WARN", "INFO", "DEBUG", "TRACE",
    "LOG", "LOGE", "LOGW", "LOGI", "LOGD", "LOGV", "err", "error", "status", "ret", "retval",
    "result",
    // Adopted from source_tree.rs's STOPLIST to neutralize the 0x4908bbac
    // observed "DBT" attractor and the ASSERT log-prefix.
    "DBT", "ASSERT",
];

/// Shared identifier-validation regex (Phase 3.0 inline rule hoisted here so
/// Phase 3.0's strict-rule loop and Phase 3.0.1's `filter_identifier_tokens`
/// stay byte-identical). `^[a-zA-Z_][a-zA-Z0-9_]{2,}$` — first char alpha or
/// `_`, total length >= 3.
fn ident_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^[a-zA-Z_][a-zA-Z0-9_]{2,}$").unwrap())
}

/// Extract the set of identifier candidate tokens from one string's content,
/// applying Phase 3.0's rules verbatim: split on non-`[A-Za-z0-9_]`, keep
/// tokens with `len >= MIN_IDENT_LEN`, containing at least one `_`, matching
/// `ident_regex`, and not in `GENERIC_TOKENS`. Hoisted out of `run`'s strict-
/// rule loop so Phase 3.0.1's per-string-load filtering reuses the exact same
/// rule — drift between the two paths would silently skew coverage.
///
/// Skips strings that ARE `__FILE__` source paths outright. A path like
/// `src/macr_drv/bar.c` (or `.../SMDT/SMDTCORE/Src/sv_SmdtIntfFt.cpp`) leaks
/// its underscored filename/component as an identifier candidate — on
/// production `02_MAIN` this named globals after the source file they happened
/// to be logged from. Mirrors `symbolicate::recover_func_name`, where
/// `is_ident` rejects paths outright (a path contains `/`/`.` and cannot be a
/// bare `__func__`). Centralizing the skip here means both call sites — the
/// strict-rule path in `run` and the disasm-anchored
/// `disasm_anchored_recovered_for_function` — apply it by construction. The
/// source-path test reuses `source_tree::is_src_path` so the definition cannot
/// drift from source-tree reconstruction.
fn filter_identifier_tokens(content: &str) -> BTreeSet<String> {
    if crate::source_tree::is_src_path(content) {
        return BTreeSet::new();
    }
    let generic: BTreeSet<&str> = GENERIC_TOKENS.iter().copied().collect();
    content
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .filter(|token| {
            token.len() >= MIN_IDENT_LEN
                && token.contains('_')
                && ident_regex().is_match(token)
                && !generic.contains(*token)
        })
        .map(String::from)
        .collect()
}

/// The arch attribution for a global — driven by which functions contributed
/// evidence. `Mixed` when at least one ARM and one Thumb function contributed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Arch {
    Arm,
    Thumb,
    Mixed,
}

/// Writer-faithful function-name overrides for globals evidence produced
/// before symbol finalization updates the function inventories.
#[derive(Debug, Clone, Default)]
pub struct FunctionEvidenceNameProjection {
    arm: HashMap<FunctionEvidenceKey, String>,
    thumb: HashMap<FunctionEvidenceKey, Option<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FunctionEvidenceKey {
    owner: FunctionOwner,
    entry: u64,
    execution_blake3: Option<[u8; 32]>,
}

impl FunctionEvidenceNameProjection {
    /// Each symbol projects only into its own ISA. A `Symbol` describes one
    /// function record, so an ARM entry and a Thumb entry that happen to share
    /// an address must not name each other.
    pub fn from_symbols(symbols: &[symbolicate::Symbol]) -> Self {
        let mut projection = Self::default();
        for symbol in symbols {
            let Some(address) = parse_numeric_symbol_address(&symbol.address) else {
                continue;
            };
            let key = FunctionEvidenceKey {
                owner: symbol.owner,
                entry: address,
                execution_blake3: symbol.execution_blake3,
            };
            match symbol.arch {
                "arm" => {
                    if let Some(name) = &symbol.name {
                        projection.arm.insert(key, name.clone());
                    }
                }
                // Thumb records the absence of a name too: an entry present
                // with `None` is a known function the writer left unnamed.
                "thumb" => {
                    projection.thumb.insert(key, symbol.name.clone());
                }
                _ => {}
            }
        }
        projection
    }

    pub fn name_for(&self, arch: Arch, entry: u64) -> Option<&str> {
        match arch {
            Arch::Arm => {
                let mut matches = self.arm.iter().filter(|(key, _)| key.entry == entry);
                let (_, name) = matches.next()?;
                matches.next().is_none().then_some(name.as_str())
            }
            Arch::Thumb => {
                let mut matches = self.thumb.iter().filter(|(key, _)| key.entry == entry);
                let (_, name) = matches.next()?;
                if matches.next().is_some() {
                    None
                } else {
                    name.as_deref()
                }
            }
            Arch::Mixed => None,
        }
    }

    fn name_for_identity(
        &self,
        arch: Arch,
        owner: FunctionOwner,
        entry: u64,
        execution_blake3: Option<[u8; 32]>,
    ) -> Option<&str> {
        let key = FunctionEvidenceKey {
            owner,
            entry,
            execution_blake3,
        };
        match arch {
            Arch::Arm => self.arm.get(&key).map(String::as_str),
            Arch::Thumb => self.thumb.get(&key).and_then(Option::as_deref),
            Arch::Mixed => None,
        }
    }
}

fn parse_numeric_symbol_address(address: &str) -> Option<u64> {
    let trimmed = address.trim();
    let digits = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(digits, 16).ok()
}

/// One piece of evidence for a `(address, name)` association. Either a string
/// that mentions the name, or a function whose `data_refs` were used.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Evidence {
    /// A string at `address` whose content `value` mentions the global name.
    String { address: String, value: String },
    /// A function at `address` whose `data_refs` produced the association.
    /// `name` is the writer-projected or already-finalized inventory name;
    /// `recovered_name` is present (and serialized) only when Phase 1 supplied
    /// a recovered name.
    Function {
        address: String,
        arch: Arch,
        name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        recovered_name: Option<String>,
    },
    /// Phase 3.0.1: a `movw`+`movt` pair at `pc` that materializes `address`
    /// (the global's address) into `register`. Provenance for the
    /// disasm-anchored algorithm; `pc` is movw's PC.
    GlobalLoad {
        pc: String,
        register: String,
        address: String,
    },
    /// Phase 3.0.1: a `movw`+`movt` pair at `pc` that materializes `address`
    /// (a string whose content contributed the recovered name) into
    /// `register`. Pairs with `GlobalLoad` for proximity matching.
    StringLoad {
        pc: String,
        register: String,
        address: String,
    },
}

/// One resolved global: a `(address, name)` pair plus its evidence trail.
#[derive(Debug, Clone, Serialize)]
pub struct Global {
    pub address: String,
    pub arch: Arch,
    pub name: String,
    /// `"recovered"` for Phase 3.0 strict-rule and Phase 3.0.1 disasm-anchored
    /// globals; `"provisional"` for Phase 3.0.1 name-prior globals (withheld
    /// from the file unless `GlobalsOpts::include_provisional`).
    pub tier: &'static str,
    /// Always `null` in Phase 3.0 (no type recovery yet). Surfaced as explicit
    /// null so consumers know the field exists and is intentionally absent.
    pub size: Option<usize>,
    pub evidence: Vec<Evidence>,
    /// Empty in Phase 3.0. Reserved for Phase 3.1+ annotations like
    /// `"mmio_candidate"`.
    pub annotations: Vec<String>,
}

/// Per-image outcome of the globals sweep. Returned by `run` so the caller
/// (`decompose::run`) can surface counts in `report.json`.
#[derive(Debug, Default)]
pub struct GlobalsReport {
    /// Count of `Global`s with `tier: "recovered"` written to `globals.json`.
    pub recovered_count: usize,
    /// Number of `(address, name)` associations dropped because a different
    /// name was proposed for the same address by another function. Strict-
    /// single-source-of-truth rule (Phase 1's `Tier::Recovered` extended
    /// cross-function).
    pub conflicts_dropped: usize,
    /// Phase 3.0.1: total tier:"provisional" globals the algorithm produced,
    /// before any suppression.
    pub provisional_generated: usize,
    /// Phase 3.0.1: subset dropped because a Recovered (addr, name') exists
    /// at the same address (gate-relevant metric).
    pub provisional_suppressed_by_recovered: usize,
}

impl GlobalsReport {
    pub fn empty() -> Self {
        Self {
            recovered_count: 0,
            conflicts_dropped: 0,
            provisional_generated: 0,
            provisional_suppressed_by_recovered: 0,
        }
    }
}

/// Phase 3.0.1 runtime options. The pipeline always passes through `globals::
/// run`; Phase 3.0's strict-rule path runs identically regardless of these
/// fields. `include_provisional` defaults to `false` — Provisional globals
/// are generated and counted but withheld from the serialized file unless
/// the consumer opts in via `--globals-provisional`.
#[derive(Debug, Clone)]
pub struct GlobalsOpts {
    pub include_provisional: bool,
    pub k_arm: usize,
    pub k_thumb: usize,
}

impl Default for GlobalsOpts {
    fn default() -> Self {
        Self {
            include_provisional: false,
            k_arm: K_ARM,
            k_thumb: K_THUMB,
        }
    }
}

/// Serialized form of `globals.json`. Field declaration order is alphabetical
/// to match `serde_json`'s default BTreeMap key ordering used by Phase 3.0's
/// `serde_json::json!{...}` write path — this keeps the Phase 3.0 output
/// byte-equivalent after the refactor (same `format`/`globals`/`image` top
/// level). The two new optional fields are skipped when `None`, so they are
/// absent from Phase 3.0's strict-rule output.
#[derive(Debug, Serialize)]
pub struct GlobalsFile {
    pub format: &'static str,
    pub globals: Vec<Global>,
    pub image: String,
    /// Surface 3.0.1-A visibility: set when Phase 3.0.1 couldn't run because
    /// `disasm.lst` was absent or unreadable (the read returns `Err`). Lets a
    /// consumer distinguish "Phase 3.0.1 ran and found nothing" from "Phase
    /// 3.0.1 couldn't run." NOT set for an empty-but-present (zero-byte)
    /// `disasm.lst` — that is a valid state: Phase 3.0.1's loops produce no
    /// output either way, but the absence-vs-empty distinction matters to
    /// consumers. Phase 3.0's own per-image failure surface is `globals_error`
    /// on `report.json`, not this field — this field is non-fatal only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase3_0_1_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provisional_suppressed: Option<usize>,
}

fn write_globals_json_with_before_commit<F>(
    path: &Path,
    bytes: &[u8],
    before_commit: F,
) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    let mut file = AtomicWriteFile::open(path)?;
    file.write_all(bytes)?;
    before_commit()?;
    file.commit()?;
    Ok(())
}

/// Phase 3.0: recover global variable names from direct textual evidence.
///
/// Reads `functions.json` + `thumb_functions.json` + `<label>.bin` from
/// `image_dir/decompiled/` and `image_dir/<label>.bin`. Writes
/// `image_dir/decompiled/globals.json` (format v1). Returns the per-image
/// outcome for surfacing in `report.json`.
///
/// `manifest` is the decompose top-level manifest (used to resolve the
/// image's load_addr for vaddr calculation). Mirrors `symbolicate::run`'s
/// signature.
///
/// `recovered_function_names` maps a function entry address (canonical:
/// lowercase hex, no `0x` prefix, no leading zeros, e.g. `"40e18dfe"`) to
/// Phase 1's recovered name. Pass an empty map when Phase 1 cross-reference
/// is unavailable; the resulting globals will simply have
/// `evidence[].recovered_name` absent.
///
/// Strict-single-source-of-truth: only functions with exactly one non-string
/// `data_ref` AND exactly one unique underscored identifier across their
/// string refs produce associations. Conflicts (same `address`, different
/// `name` from different functions) are dropped.
pub fn run(
    image_dir: &Path,
    image_label: &str,
    manifest: &Path,
    recovered_function_names: &HashMap<String, String>,
    opts: &GlobalsOpts,
) -> Result<GlobalsReport> {
    run_with_evidence_projection(
        image_dir,
        image_label,
        manifest,
        recovered_function_names,
        None,
        opts,
    )
}

pub fn run_with_evidence_projection(
    image_dir: &Path,
    image_label: &str,
    manifest: &Path,
    recovered_function_names: &HashMap<String, String>,
    evidence_names: Option<&FunctionEvidenceNameProjection>,
    opts: &GlobalsOpts,
) -> Result<GlobalsReport> {
    let decompiled = image_dir.join("decompiled");

    // 1. Resolve the image's load_addr from the manifest.
    let toc_name = crate::manifest::toc_name(image_label);
    let load_addr =
        crate::manifest::load_addr_for_image(manifest, image_label)?.ok_or_else(|| {
            Error::Serialize(format!(
                "globals: load_addr missing for {image_label} (toc name {toc_name})"
            ))
        })?;

    // 2. Read the raw image bytes (for string extraction). Missing or
    //    unreadable .bin is a Surface 3.0-A failure — propagate as Err (via
    //    Error::Io's #[from] std::io::Error conversion) so the caller records
    //    `globals_error` and skips writing globals.json for this image.
    let bin_path = image_dir.join(format!("{image_label}.bin"));
    let image_bytes = std::fs::read(&bin_path)?;
    let runtime_load_addr = u32::try_from(load_addr)
        .map_err(|_| Error::Serialize("globals: load_addr does not fit u32".into()))?;
    let runtime_root = std::fs::canonicalize(image_dir)?;
    let relative_map = Path::new("scatter/load_map.json");
    let runtime_map = runtime_root.join(relative_map);
    let runtime = RuntimeImage::from_artifact(
        &image_bytes,
        runtime_load_addr,
        &runtime_root,
        runtime_map.try_exists()?.then_some(runtime_map.as_path()),
    )?;

    // 3. Build string_map: {vaddr -> string_content}.
    let mut string_map: HashMap<u64, String> = HashMap::new();
    for (off, s) in extract_strings(&image_bytes, 3) {
        let vaddr = load_addr.wrapping_add(off as u64);
        string_map.insert(vaddr, String::from_utf8_lossy(s).to_string());
    }

    // 4. Read functions.json + thumb_functions.json into a unified list,
    //    enriching each Function's recovered_name from the cross-reference map.
    let mut all_funcs: Vec<Function> = Vec::new();

    let arm_path = decompiled.join("functions.json");
    if arm_path.exists() {
        let arm_text = std::fs::read_to_string(&arm_path)?;
        let arm_v: serde_json::Value = serde_json::from_str(&arm_text)
            .map_err(|e| Error::Serialize(format!("parse functions.json: {e}")))?;
        let records = arm_v
            .as_array()
            .ok_or_else(|| Error::Serialize("functions.json must be an array".into()))?;
        let inventory = crate::execution_ranges::validate_ghidra_inventory_records(
            records,
            records.len(),
            &runtime,
        )?;
        for (record, tagged) in records.iter().zip(inventory.records) {
            let execution = execution_identity(tagged.entry, &tagged.projection)?;
            if let Some(parsed) = parse_function(
                record,
                Arch::Arm,
                FunctionOwner::Ghidra,
                execution.as_ref(),
                recovered_function_names,
                evidence_names,
            ) {
                all_funcs.push(parsed);
            }
        }
    }

    let thumb_path = decompiled.join("thumb_functions.json");
    if thumb_path.exists() {
        for function in
            crate::thumb_analysis::read_thumb_functions_streaming(&thumb_path, &runtime)?
        {
            let value = serde_json::to_value(&function.function)
                .map_err(|error| Error::Serialize(error.to_string()))?;
            if let Some(parsed) = parse_function(
                &value,
                Arch::Thumb,
                function.owner,
                function.execution.as_ref(),
                recovered_function_names,
                evidence_names,
            ) {
                all_funcs.push(parsed);
            }
        }
    }

    // 5. Build proposals: addr -> name -> Vec<Contributor>. Three paths feed
    //    the same map (Phase 3.0 strict-rule, Phase 3.0.1 disasm-anchored
    //    Recovered, Phase 3.0.1 name-prior Provisional) so that same-tier
    //    conflicts resolve through one strict-drop rule and cross-tier
    //    (Recovered vs Provisional) precedence is applied at emission (step 6).
    //
    //    Phase 3.0 strict-single-source-of-truth: require at least one
    //    underscore in the identifier (real modem-firmware globals are
    //    conventionally g_/m_/s_/Asn_-prefixed). Phase 3.0.1's per-string
    //    filtering reuses the exact same rule via `filter_identifier_tokens`.
    let mut addr_to_proposals: HashMap<u64, HashMap<String, Vec<Contributor>>> = HashMap::new();

    // 5a. Phase 3.0 strict-rule path: functions with exactly one non-string
    //     data_ref (candidate) and exactly one unique identifier across their
    //     string refs. Evidence shape: [String, Function].
    for f in &all_funcs {
        // Filter data_refs: candidate_refs are non-string refs that fall
        // inside the image (>= load_addr). Sub-load-addr refs are out-of-image
        // noise (Ghidra occasionally emits linker/relocation artifacts as
        // small integers) and would inflate candidate counts, blocking
        // otherwise-clean recoveries.
        let candidate_refs: Vec<u64> = f
            .data_refs
            .iter()
            .copied()
            .filter(|a| !string_map.contains_key(a))
            .filter(|a| *a >= load_addr)
            .collect();
        if candidate_refs.len() != 1 {
            continue;
        }
        let global_addr = candidate_refs[0];

        // Collect identifier tokens across all string_refs. `__FILE__` source
        // paths are skipped inside the shared `filter_identifier_tokens`
        // helper (see its doc comment) — centralizing the skip there means
        // this path and the disasm-anchored path apply it identically.
        let mut unique_idents: BTreeSet<String> = BTreeSet::new();
        for s_addr in &f.data_refs {
            if let Some(s) = string_map.get(s_addr) {
                unique_idents.extend(filter_identifier_tokens(s));
            }
        }
        if unique_idents.len() != 1 {
            continue;
        }
        let name = unique_idents.into_iter().next().unwrap();

        addr_to_proposals
            .entry(global_addr)
            .or_default()
            .entry(name)
            .or_default()
            .push(Contributor {
                func: f.clone(),
                string_load: None,
                global_load: None,
                naming_string: None,
                tier: "recovered",
            });
    }

    // 5b. Phase 3.0.1 disasm-anchored Recovered path: functions with two or
    //     more non-string data_refs (multi-global — too ambiguous for Phase
    //     3.0's strict single-candidate rule). For each, reconstruct PC-
    //     tagged load events from the function's disasm slice, then anchor
    //     string-load/global-load pairs by proximity K. Evidence shape:
    //     [StringLoad, GlobalLoad, String, Function].
    //
    //     Surface 3.0.1-A (disasm-unreadable): best-effort read — a missing/
    //     unreadable `disasm.lst` means zero Phase 3.0.1 recoveries but does
    //     NOT fail the image (Phase 3.0's strict-rule output still emits).
    //     An `Err` here threads a message into `GlobalsFile.phase3_0_1_error`
    //     for serialized-output visibility, so a consumer can distinguish
    //     "Phase 3.0.1 ran and found nothing" from "Phase 3.0.1 couldn't run
    //     (no disasm)." An empty-but-present file (zero bytes) is a valid
    //     state and does NOT set the error field — only `Err` does. Mirrors
    //     `symbolicate::build_map`'s precedent (line 932).
    let disasm_path = decompiled.join("disasm.lst");
    let (disasm_text, phase3_0_1_error): (String, Option<String>) =
        match std::fs::read_to_string(&disasm_path) {
            Ok(s) => (s, None),
            Err(e) => (String::new(), Some(format!("read disasm.lst: {e}"))),
        };
    // Index disasm.lst ONCE per image (O(L)) so each Phase 3.0.1 per-function
    // slice lookup is O(log L + k) instead of O(L). Without this, the two
    // loops below scan the full 7.6M-line `02_MAIN` disasm per function (×
    // 107,955 ARM functions) → O(N·L) ≈ 8×10¹¹ ops, which blocked production
    // (150+ min, no `globals.json` emitted). See `crate::disasm_index::DisasmIndex`
    // for the sortedness invariant.
    let disasm_index = crate::disasm_index::DisasmIndex::new(&disasm_text);
    for f in &all_funcs {
        let candidate_refs: Vec<u64> = f
            .data_refs
            .iter()
            .copied()
            .filter(|a| !string_map.contains_key(a))
            .filter(|a| *a >= load_addr)
            .collect();
        if candidate_refs.len() < 2 {
            continue;
        }
        // Per-function disasm slice. ARM: slice disasm.lst by [entry, end).
        // Thumb: the canonical per-function `body` field from thumb_functions.json
        // (adapted analyzer output — different format from disasm.lst; do NOT
        // re-slice disasm.lst for Thumb).
        let (disasm_slice, k) = function_disassembly(f, &disasm_index, opts);
        let load_events = symbolicate::reconstruct_load_events(&disasm_slice);
        let recovered = disasm_anchored_recovered_for_function(f, &string_map, &load_events, k);
        for (addr, name, sl_ev, gl_ev) in recovered {
            // The StringLoad's address field is the naming string's vaddr —
            // pinned by the disasm event, not by a data_refs search (Thumb's
            // data_refs exclude movw/movt-resolved addresses).
            let naming_string = match &sl_ev {
                Evidence::StringLoad { address, .. } => {
                    u64::from_str_radix(address.trim_start_matches("0x"), 16).ok()
                }
                _ => None,
            };
            addr_to_proposals
                .entry(addr)
                .or_default()
                .entry(name)
                .or_default()
                .push(Contributor {
                    func: f.clone(),
                    string_load: Some(sl_ev),
                    global_load: Some(gl_ev),
                    naming_string,
                    tier: "recovered",
                });
        }
    }

    // 5c. Phase 3.0.1 name-prior Provisional path: handles the residue the
    //     disasm-anchored Recovered pass (5b) leaves behind — string-loads
    //     whose string carries ≥2 underscored identifiers AND whose window
    //     contains ≥2 globals. Recovered drops these as ambiguous; the name
    //     prior attempts to break the tie: if the function's `recovered_name`
    //     is module-prefixed (e.g. `LteRrc_CheckState` -> prefix `LteRrc`) and
    //     exactly one identifier in the string case-insensitively starts with
    //     that prefix, pick the global nearest (by load-event-index distance)
    //     to the string-load. Ties (two identifiers, or two globals at equal
    //     distance) -> drop. Names follow Phase 1's Tier::Provisional shape:
    //     `guess_<slug>_<addr_hex>` via `symbolicate::slugify` +
    //     `GUESS_PREFIX`. Evidence shape: [StringLoad, GlobalLoad, String,
    //     Function].
    //
    //     `provisional_generated` is incremented per emission regardless of
    //     `opts.include_provisional` — the flag controls materialization, not
    //     generation. Proposals always land in the unified map so step 6's
    //     cross-tier Recovered-beats-Provisional precedence can see both and
    //     increment `provisional_suppressed_by_recovered`.
    //
    //     Scenario 2 (firmware pre-check): this pass materializes zero
    //     entries on `02_MAIN` — only ~4 candidates survive the prefix filter,
    //     all dropped by the strict-drop / cross-tier rules. The path is
    //     exercised here for schema/surface correctness; the count is gated.
    let mut provisional_generated: usize = 0;
    for f in &all_funcs {
        let candidate_refs: Vec<u64> = f
            .data_refs
            .iter()
            .copied()
            .filter(|a| !string_map.contains_key(a))
            .filter(|a| *a >= load_addr)
            .collect();
        if candidate_refs.len() < 2 {
            continue;
        }
        let (disasm_slice, k) = function_disassembly(f, &disasm_index, opts);
        let load_events = symbolicate::reconstruct_load_events(&disasm_slice);
        let provisional = name_prior_provisional_for_function(f, &string_map, &load_events, k);
        provisional_generated += provisional.len();
        for (addr, name, sl_ev, gl_ev) in provisional {
            let naming_string = match &sl_ev {
                Evidence::StringLoad { address, .. } => {
                    u64::from_str_radix(address.trim_start_matches("0x"), 16).ok()
                }
                _ => None,
            };
            addr_to_proposals
                .entry(addr)
                .or_default()
                .entry(name)
                .or_default()
                .push(Contributor {
                    func: f.clone(),
                    string_load: Some(sl_ev),
                    global_load: Some(gl_ev),
                    naming_string,
                    tier: "provisional",
                });
        }
    }

    // 6. Build the output: one entry per (addr, name) where the addr had
    //    exactly one distinct name proposed, OR — when multiple distinct
    //    names were proposed — the cross-tier Recovered-beats-Provisional
    //    rule resolves a unique winner. Same-tier multi-name conflicts
    //    (Phase 3.0 vs Phase 3.0, Phase 3.0.1 Recovered vs Recovered,
    //    Phase 3.0.1 Provisional vs Provisional, or Phase 3.0 vs Phase
    //    3.0.1 Recovered — all "recovered" tier) drop via the existing
    //    strict-drop rule (counted in `conflicts_dropped`). When exactly
    //    one Recovered name and one-or-more Provisional names collide at
    //    the same addr, the Recovered wins; each Contributor under a
    //    Provisional name increments `provisional_suppressed_by_recovered`
    //    (per the design spec Step 1.5). The resulting Global's `tier` is
    //    `"recovered"` if any contributor was Recovered (Recovered names
    //    and Provisional `guess_…` names never collide within a single
    //    (addr, name) entry, so a mixed-tier entry is impossible in
    //    practice), else `"provisional"`. Provisional globals are withheld
    //    from the file unless `opts.include_provisional` — the count was
    //    already taken at helper-emit time, so withholding only suppresses
    //    materialization (cross-tier suppression has already been applied
    //    above by this point).
    let mut globals: Vec<Global> = Vec::new();
    let mut conflicts_dropped = 0usize;
    let mut provisional_suppressed_by_recovered = 0usize;
    // Provisional entries that survive to the output `Vec<Global>`.
    // `provisional_generated` (taken above) counts every name-prior
    // emission; this counts those actually written. The difference is
    // `provisional_suppressed` in the serialized file (covers all
    // suppression paths: opt-out flag, cross-tier Recovered win, same-
    // tier multi-name drop).
    let mut materialized_provisional = 0usize;
    // Iterate by ascending addr for deterministic output ordering.
    let mut sorted_addrs: Vec<u64> = addr_to_proposals.keys().copied().collect();
    sorted_addrs.sort_unstable();
    for addr in sorted_addrs {
        let proposals = addr_to_proposals.remove(&addr).unwrap();
        // Resolve the winning proposal for this addr, if any. A single
        // distinct name -> no conflict, that name wins. Multiple names ->
        // cross-tier Recovered-beats-Provisional precedence: exactly one
        // Recovered name suppresses every Provisional name at this addr;
        // any other multi-name case (multiple Recovered, or all-Provisional
        // with multiple names) falls back to the same-tier strict-drop.
        let winner: Option<(String, Vec<Contributor>)> = if proposals.len() == 1 {
            Some(proposals.into_iter().next().unwrap())
        } else {
            let mut recovered: Option<(String, Vec<Contributor>)> = None;
            let mut recovered_names: usize = 0;
            let mut provisional_contributors: usize = 0;
            for (name, contributors) in proposals {
                if contributors.iter().any(|c| c.tier == "recovered") {
                    recovered_names += 1;
                    if recovered.is_none() {
                        recovered = Some((name, contributors));
                    }
                } else {
                    // Within one (addr, name) entry all contributors share a
                    // tier (Recovered real-identifier names and Provisional
                    // `guess_…` names never coincide); `else` == all-
                    // Provisional. Sum contributor counts across all
                    // Provisional names at this addr.
                    provisional_contributors += contributors.len();
                }
            }
            if recovered_names == 1 && provisional_contributors > 0 {
                // Cross-tier win: keep the Recovered, suppress the Provisionals.
                provisional_suppressed_by_recovered += provisional_contributors;
                recovered
            } else {
                // Same-tier strict-drop. Covers: multiple Recovered names
                // (Phase 3.0 invariant), all-Provisional with multiple
                // names, and Phase 3.0 vs Phase 3.0.1 Recovered cross-path
                // conflicts. Per design spec Step 1.5, `conflicts_dropped`
                // counts once per addr with >1 surviving same-tier name.
                conflicts_dropped += 1;
                None
            }
        };
        let Some((name, mut contributors)) = winner else {
            continue;
        };
        // Resulting tier: Recovered wins over Provisional if both contributed
        // (defensive — within one (addr, name) entry all contributors share a
        // tier because Recovered names and `guess_…` names never coincide).
        let tier: &'static str = if contributors.iter().any(|c| c.tier == "recovered") {
            "recovered"
        } else {
            "provisional"
        };
        if tier == "provisional" && !opts.include_provisional {
            // Withhold materialization but keep `provisional_generated` (taken
            // at helper-emit time). Cross-tier Recovered-beats-Provisional
            // suppression (if any) was already applied earlier in this loop
            // and counted in `provisional_suppressed_by_recovered`; reaching
            // here means this Provisional survived precedence and would have
            // materialized but for the opt-in flag.
            continue;
        }
        // Sort contributors by function address ascending (deterministic
        // evidence ordering, mirrors Phase 3.0).
        contributors.sort_by_key(|c| (c.func.entry, c.func.owner, c.func.execution_blake3));
        let has_arm = contributors.iter().any(|c| c.func.arch == Arch::Arm);
        let has_thumb = contributors.iter().any(|c| c.func.arch == Arch::Thumb);
        let arch = match (has_arm, has_thumb) {
            (true, true) => Arch::Mixed,
            (true, false) => Arch::Arm,
            (false, true) => Arch::Thumb,
            (false, false) => unreachable!("no contributing functions"),
        };
        // Build evidence: per contributor, emit StringLoad + GlobalLoad first
        // (Phase 3.0.1 only), then the naming String, then Function. Phase 3.0
        // strict-rule contributors carry no StringLoad/GlobalLoad, so their
        // evidence is just [String, Function] — the regression sentinel
        // `phase3_0_strict_rule_path_emits_no_globalload_evidence` pins this.
        let evidence: Vec<Evidence> = contributors
            .iter()
            .flat_map(|c| {
                let mut entries = Vec::with_capacity(4);
                if let Some(sl) = &c.string_load {
                    entries.push(sl.clone());
                }
                if let Some(gl) = &c.global_load {
                    entries.push(gl.clone());
                }
                // The naming String evidence. Phase 3.0.1: pinned by the
                // StringLoad event (the disasm-anchored string that provided
                // the identifier). Phase 3.0: resolved from data_refs (lowest-
                // addressed string whose content mentions the name). When
                // multiple strings mention the name, the lowest-addressed is
                // chosen (deterministic).
                let naming_string_addr = c.naming_string.or_else(|| {
                    c.func
                        .data_refs
                        .iter()
                        .copied()
                        .filter(|a| string_map.get(a).is_some_and(|s| s.contains(name.as_str())))
                        .min()
                });
                if let Some(s_addr) = naming_string_addr {
                    let value = string_map.get(&s_addr).cloned().unwrap_or_default();
                    entries.push(Evidence::String {
                        address: format!("0x{s_addr:x}"),
                        value,
                    });
                }
                entries.push(Evidence::Function {
                    address: format!("0x{:x}", c.func.entry),
                    arch: c.func.arch,
                    name: c.func.ghidra_name.clone(),
                    recovered_name: c.func.recovered_name.clone(),
                });
                entries
            })
            .collect();

        globals.push(Global {
            address: format!("0x{addr:x}"),
            arch,
            name: name.clone(),
            tier,
            size: None,
            evidence,
            annotations: Vec::new(),
        });
        if tier == "provisional" {
            materialized_provisional += 1;
        }
    }

    let recovered_count = globals
        .iter()
        .filter(|global| global.tier == "recovered")
        .count();

    // 7. Write globals.json. Serialize the complete document before opening
    //    the atomic writer, then replace the destination only after every
    //    byte has been written successfully.
    //    Phase 3.0's strict-rule path leaves both new optional fields `None`,
    //    so they are absent from the output (byte-equivalent with Phase 3.0's
    //    prior `serde_json::json!{...}` write path). When `disasm.lst` was
    //    absent/unreadable (Surface 3.0.1-A), `phase3_0_1_error` carries the
    //    io message for consumer visibility; Phase 3.0's content is still
    //    written.
    let file = GlobalsFile {
        format: FORMAT_V1,
        globals,
        image: image_label.to_string(),
        phase3_0_1_error,
        provisional_suppressed: (provisional_generated > 0)
            .then_some(provisional_generated - materialized_provisional),
    };
    let out = serde_json::to_string_pretty(&file)
        .map_err(|e| Error::Serialize(format!("re-serialize globals.json: {e}")))?;
    write_globals_json_with_before_commit(
        &decompiled.join("globals.json"),
        out.as_bytes(),
        || Ok(()),
    )?;

    Ok(GlobalsReport {
        recovered_count,
        conflicts_dropped,
        provisional_generated,
        provisional_suppressed_by_recovered,
    })
}

/// One unified function record (ARM + Thumb). Internal to the algorithm.
#[derive(Debug, Clone)]
struct Function {
    entry: u64,
    owner: FunctionOwner,
    execution_blake3: Option<[u8; 32]>,
    decode_ranges: Vec<(u64, u64)>,
    arch: Arch,
    ghidra_name: String,
    recovered_name: Option<String>,
    data_refs: Vec<u64>,
    /// Thumb only: the per-function disassembly body from
    /// `thumb_functions.json`'s canonical `body` field (adapted analyzer output). `None`
    /// for ARM, which slices `disasm.lst` over each authenticated range
    /// (Ghidra's full-image disassembly uses a different format from Thumb's
    /// per-function body).
    body: Option<String>,
}

fn function_disassembly(
    function: &Function,
    index: &crate::disasm_index::DisasmIndex<'_>,
    opts: &GlobalsOpts,
) -> (String, usize) {
    match function.arch {
        Arch::Arm => {
            let mut disassembly = String::new();
            for (start, end) in &function.decode_ranges {
                disassembly.push_str(&index.slice_for(*start, *end));
            }
            (disassembly, opts.k_arm)
        }
        Arch::Thumb => (
            function
                .execution_blake3
                .and(function.body.clone())
                .unwrap_or_default(),
            opts.k_thumb,
        ),
        Arch::Mixed => (String::new(), 0),
    }
}

/// Parse one entry from `functions.json` or `thumb_functions.json` into a
/// unified `Function`. Returns None on missing required fields (silently
/// skipped — same posture as Phase 1's symbolicate loaders).
/// `recovered_function_names` enriches `Function.recovered_name` if Phase 1
/// supplied a name for this function's entry address.
fn parse_function(
    v: &serde_json::Value,
    arch: Arch,
    owner: FunctionOwner,
    execution: Option<&ExecutionIdentity>,
    recovered_function_names: &HashMap<String, String>,
    evidence_names: Option<&FunctionEvidenceNameProjection>,
) -> Option<Function> {
    let entry = v
        .get("entry")
        .and_then(|e| e.as_str())
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())?;
    let source_name = v
        .get("name")
        .and_then(|n| n.as_str())
        .map(String::from)
        .unwrap_or_else(|| format!("FUN_{entry:x}"));
    let execution_blake3 = execution.map(|execution| execution.execution_blake3);
    let ghidra_name = evidence_names
        .and_then(|projection| projection.name_for_identity(arch, owner, entry, execution_blake3))
        .map(str::to_owned)
        .unwrap_or(source_name);
    let data_refs: Vec<u64> = v
        .get("data_refs")
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|r| r.as_str())
                .filter_map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                .collect()
        })
        .unwrap_or_default();
    let body = v.get("body").and_then(|b| b.as_str()).map(String::from);
    let canonical = format!("{entry:x}");
    let recovered_name = recovered_function_names.get(&canonical).cloned();
    Some(Function {
        entry,
        owner,
        execution_blake3,
        decode_ranges: execution
            .map(|execution| {
                execution
                    .decode_ranges
                    .iter()
                    .map(|range| (u64::from(range.start), u64::from(range.end)))
                    .collect()
            })
            .unwrap_or_default(),
        arch,
        ghidra_name,
        recovered_name,
        data_refs,
        body,
    })
}

/// One function's contribution to a `(addr, name)` proposal. Phase 3.0's
/// strict-rule path pushes a `Contributor` with `string_load`/`global_load`
/// both `None` (evidence is `[String, Function]`). Phase 3.0.1's disasm-
/// anchored path pushes a `Contributor` carrying the `StringLoad`/`GlobalLoad`
/// evidence plus the naming string's vaddr (evidence is
/// `[StringLoad, GlobalLoad, String, Function]`).
#[derive(Clone)]
struct Contributor {
    func: Function,
    string_load: Option<Evidence>,
    global_load: Option<Evidence>,
    /// The naming string's vaddr — Phase 3.0.1's `StringLoad` pins which
    /// specific string provided the identifier; Phase 3.0 leaves this `None`
    /// and resolves the naming string from `data_refs` at emission.
    naming_string: Option<u64>,
    /// Tier this contributor belongs to. Phase 3.0 strict-rule and Phase 3.0.1
    /// disasm-anchored Recovered both set `"recovered"`; Phase 3.0.1 name-prior
    /// Provisional sets `"provisional"`. Used by the emission loop to (a)
    /// stamp the resulting `Global.tier` and (b) withhold materialization when
    /// `!opts.include_provisional`. Step 6 applies cross-tier precedence at
    /// the same addr (Recovered beats Provisional) using this field.
    tier: &'static str,
}

/// Phase 3.0.1 disasm-anchored Recovered pass for one multi-global function.
///
/// For each string-load event (a `movw`/`movt` pair materializing a string
/// whose content is in `string_map`), find the unique identifier token in
/// that string; if exactly one survives, look for a global-load event within
/// proximity `k` (in load-event-count distance). If exactly one global is in
/// the window, emit `(global_addr, name, StringLoad evidence, GlobalLoad
/// evidence)`. Ambiguous cases (zero or multiple identifiers, zero or
/// multiple globals in window) defer to the name-prior pass.
///
/// **Distance metric:** load-event-count — the number of `LoadEvent`s in
/// `load_events` between the string-load's index and the global-load's index
/// (`Vec::iter().position()` by PC). NOT raw instruction count. `k=4` means
/// "≤4 intervening movw/movt lines" ≈ "≤2 address-load pairs." The pre-check
/// confirmed this approximation grounds the K pinning; do not
/// silently switch metrics — `recovered_tier_requires_disasm_proximity_within_k`
/// is the regression sentinel.
///
/// **Thumb `data_refs` augmentation:** neither backend's adapted references are
/// guaranteed to include addresses materialized via `movw`/`movt` pairs (only
/// Ghidra resolves those into `data_refs` for ARM). Without augmentation, the
/// Thumb side produces 0 global-load events. For Thumb functions, the values
/// materialized in `load_events` (== `reconstruct_immediates` results, PC-
/// tagged) are unioned into the candidate set — mirroring `symbolicate.rs`'s
/// `imms.extend(f.data_refs...)` pattern. ARM needs no augmentation: Ghidra's
/// `data_refs` already include movw/movt-resolved addresses.
fn disasm_anchored_recovered_for_function(
    func: &Function,
    string_map: &HashMap<u64, String>,
    load_events: &[symbolicate::LoadEvent],
    k: usize,
) -> Vec<(u64, String, Evidence, Evidence)> {
    let mut out = Vec::new();
    // Bound exact authenticated execution coverage, never an address envelope.
    let execution_bytes = func
        .decode_ranges
        .iter()
        .try_fold(0u64, |total, (start, end)| {
            total.checked_add(end.saturating_sub(*start))
        })
        .unwrap_or(u64::MAX);
    if execution_bytes > MEGA_FN_THRESHOLD {
        return out;
    }
    if load_events.is_empty() {
        return out;
    }

    // Build the global-candidate address set: non-string data_refs, plus
    // (Thumb only) the values materialized in load_events.
    let mut non_string_refs: BTreeSet<u64> = func
        .data_refs
        .iter()
        .copied()
        .filter(|r| !string_map.contains_key(r))
        .collect();
    if func.arch == Arch::Thumb {
        for e in load_events {
            let v = e.value as u64;
            if !string_map.contains_key(&v) {
                non_string_refs.insert(v);
            }
        }
    }

    let string_loads: Vec<&symbolicate::LoadEvent> = load_events
        .iter()
        .filter(|e| string_map.contains_key(&(e.value as u64)))
        .collect();
    let global_loads: Vec<&symbolicate::LoadEvent> = load_events
        .iter()
        .filter(|e| non_string_refs.contains(&(e.value as u64)))
        .collect();

    // O(1) PC -> load_event index. The matching loop below is O(sl × gl); the
    // former `load_events.iter().position(...)` per pair made it O(sl × gl ×
    // E_f), which is intractable on Ghidra-mis-estimated mega-functions (E_f
    // up to ~865k on `02_MAIN`). PCs are unique in `load_events` (one event
    // per instruction address); `entry().or_insert` defensively keeps the
    // first index if a duplicate PC ever slips through, matching
    // `slice::position`'s first-match semantics exactly.
    let mut pc_to_idx: HashMap<u32, usize> = HashMap::with_capacity(load_events.len());
    for (i, e) in load_events.iter().enumerate() {
        pc_to_idx.entry(e.pc).or_insert(i);
    }

    for sl in string_loads {
        let content = string_map.get(&(sl.value as u64)).unwrap();
        let identifiers = filter_identifier_tokens(content);
        if identifiers.len() != 1 {
            continue;
        }
        let name = identifiers.into_iter().next().unwrap();

        // Proximity: global_loads whose load-event-index distance from sl is
        // within k. PC lookup is O(1) via `pc_to_idx`; PCs are unique in
        // `load_events`, so the index matches the old `position()` result.
        let sl_idx = pc_to_idx
            .get(&sl.pc)
            .expect("sl drawn from load_events; pc present in pc_to_idx");
        let in_window: Vec<&symbolicate::LoadEvent> = global_loads
            .iter()
            .filter_map(|gl| {
                let gl_idx = *pc_to_idx.get(&gl.pc)?;
                let dist = sl_idx.abs_diff(gl_idx);
                (dist <= k).then_some(*gl)
            })
            .collect();
        if in_window.len() != 1 {
            continue;
        }
        let gl = in_window[0];

        out.push((
            gl.value as u64,
            name,
            Evidence::StringLoad {
                pc: format!("0x{:x}", sl.pc),
                register: sl.register.clone(),
                address: format!("0x{:x}", sl.value),
            },
            Evidence::GlobalLoad {
                pc: format!("0x{:x}", gl.pc),
                register: gl.register.clone(),
                address: format!("0x{:x}", gl.value),
            },
        ));
    }
    out
}

/// Phase 3.0.1 name-prior Provisional pass for one multi-global function.
///
/// Handles the residue `disasm_anchored_recovered_for_function` leaves behind:
/// string-loads whose string carries ≥2 underscored identifiers AND whose
/// proximity window contains ≥2 globals (Recovered drops both cases as
/// ambiguous). The function's recovered name supplies the prior.
///
/// **Name prior rule (design spec Step 1.4):**
/// 1. `recovered_name` must be module-prefixed (`"LteRrc_CheckState"` -> prefix
///    `"LteRrc"`); the first character of the prefix must be ASCII uppercase.
/// 2. Exactly one identifier in the string must case-insensitively start with
///    the prefix (zero or multiple matches -> drop).
/// 3. Among globals within proximity `k` of the string-load, pick the one
///    nearest by load-event-index distance. A tie (two globals at equal
///    distance) -> drop.
///
/// Names follow Phase 1's `Tier::Provisional` shape: `guess_<slug>_<addr_hex>`,
/// where `slug = slugify(name_token, None)` and the prefix is `GUESS_PREFIX`.
///
/// **Scenario 2 (firmware pre-check):** on real `02_MAIN`, this pass
/// materializes zero entries. The pass is exercised for schema/surface
/// correctness; the synthetic unit tests cover the logic.
fn name_prior_provisional_for_function(
    func: &Function,
    string_map: &HashMap<u64, String>,
    load_events: &[symbolicate::LoadEvent],
    k: usize,
) -> Vec<(u64, String, Evidence, Evidence)> {
    let mut out = Vec::new();
    if load_events.is_empty() {
        return out;
    }

    // Name prior: function must have a module-prefixed recovered_name.
    let Some(recovered_name) = &func.recovered_name else {
        return out;
    };
    let Some(prefix) = recovered_name.split('_').next() else {
        return out;
    };
    if prefix.is_empty()
        || !prefix
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_uppercase())
    {
        return out;
    }

    // Mirror the Recovered pass's candidate construction (including Thumb augmentation):
    // the two passes must see the same globals so the residue invariant
    // (Provisional handles what Recovered dropped) holds.
    let mut non_string_refs: BTreeSet<u64> = func
        .data_refs
        .iter()
        .copied()
        .filter(|r| !string_map.contains_key(r))
        .collect();
    if func.arch == Arch::Thumb {
        for e in load_events {
            let v = e.value as u64;
            if !string_map.contains_key(&v) {
                non_string_refs.insert(v);
            }
        }
    }

    let string_loads: Vec<&symbolicate::LoadEvent> = load_events
        .iter()
        .filter(|e| string_map.contains_key(&(e.value as u64)))
        .collect();
    let global_loads: Vec<&symbolicate::LoadEvent> = load_events
        .iter()
        .filter(|e| non_string_refs.contains(&(e.value as u64)))
        .collect();

    // O(1) PC -> load_event index. See the same block in
    // `disasm_anchored_recovered_for_function` for rationale. Built per-helper
    // (not shared with Recovered): `run` invokes the two passes in separate
    // loops over `all_funcs`, so threading a shared map between them would
    // restructure both call sites for no gain. The O(E_f) build is dominated
    // by the O(sl × gl) matching it enables (was O(sl × gl × E_f)).
    let mut pc_to_idx: HashMap<u32, usize> = HashMap::with_capacity(load_events.len());
    for (i, e) in load_events.iter().enumerate() {
        pc_to_idx.entry(e.pc).or_insert(i);
    }

    for sl in string_loads {
        let content = string_map.get(&(sl.value as u64)).unwrap();
        let identifiers = filter_identifier_tokens(content);
        // Provisional fires only on the multi-identifier residue (Recovered
        // owns the unambiguous single-identifier case).
        if identifiers.len() < 2 {
            continue;
        }
        // Filter identifiers by case-insensitive prefix match against the
        // function-name prior. Exactly one match -> the name token.
        let matches: Vec<&String> = identifiers
            .iter()
            .filter(|i| i.len() >= prefix.len() && i[..prefix.len()].eq_ignore_ascii_case(prefix))
            .collect();
        if matches.len() != 1 {
            continue;
        }
        let name_token = matches[0];

        // Among globals within proximity k of the string-load, pick the
        // nearest by load-event-index distance. Ties -> drop.
        let sl_idx = pc_to_idx
            .get(&sl.pc)
            .expect("sl drawn from load_events; pc present in pc_to_idx");
        let in_window: Vec<(&symbolicate::LoadEvent, usize)> = global_loads
            .iter()
            .filter_map(|gl| {
                let gl_idx = *pc_to_idx.get(&gl.pc)?;
                let dist = sl_idx.abs_diff(gl_idx);
                (dist <= k).then_some((*gl, dist))
            })
            .collect();
        if in_window.is_empty() {
            continue;
        }
        let min_dist = in_window.iter().map(|(_, d)| *d).min().unwrap();
        let nearest: Vec<&symbolicate::LoadEvent> = in_window
            .into_iter()
            .filter(|(_, d)| *d == min_dist)
            .map(|(gl, _)| gl)
            .collect();
        if nearest.len() != 1 {
            continue; // tie -> drop
        }
        let gl = nearest[0];

        let slug = symbolicate::slugify(name_token, None);
        let guess_name = format!("{}{}_{:x}", symbolicate::GUESS_PREFIX, slug, gl.value);
        out.push((
            gl.value as u64,
            guess_name,
            Evidence::StringLoad {
                pc: format!("0x{:x}", sl.pc),
                register: sl.register.clone(),
                address: format!("0x{:x}", sl.value),
            },
            Evidence::GlobalLoad {
                pc: format!("0x{:x}", gl.pc),
                register: gl.register.clone(),
                address: format!("0x{:x}", gl.value),
            },
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use std::path::PathBuf;

    static TEST_IMAGE: [u8; 0x100] = [0; 0x100];

    fn test_runtime() -> RuntimeImage<'static> {
        RuntimeImage::from_plan(&TEST_IMAGE, 0x4000, None).unwrap()
    }

    fn tmp_root(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("pme_globals_{name}_{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn numeric_symbol_address_parser_covers_writer_boundaries() {
        for (input, expected) in [
            ("0", 0),
            ("00000000", 0),
            ("ff", 0xff),
            (" FF ", 0xff),
            ("0xff", 0xff),
            ("0XFF", 0xff),
            ("00000000000000FF", 0xff),
            ("ffffffffffffffff", u64::MAX),
            ("0xFFFFFFFFFFFFFFFF", u64::MAX),
        ] {
            assert_eq!(
                parse_numeric_symbol_address(input),
                Some(expected),
                "{input:?}"
            );
        }

        let malformed = [
            "",
            " ",
            "0x",
            "0X",
            "+1",
            "-1",
            "f f",
            "0x ff",
            "0x1_0",
            "xyz",
            "10000000000000000",
            "0x10000000000000000",
        ];
        for input in malformed {
            assert_eq!(parse_numeric_symbol_address(input), None, "{input:?}");
        }

        let symbols: Vec<_> = malformed
            .into_iter()
            .map(|address| symbolicate::Symbol {
                address: address.to_string(),
                arch: "arm",
                tool: crate::recover_source::Tool::Ghidra,
                owner: FunctionOwner::Ghidra,
                execution_blake3: None,
                original_name: "FUN_invalid".to_string(),
                name: Some("SHOULD_NOT_PROJECT".to_string()),
                tier: symbolicate::Tier::Recovered,
                evidence: Vec::new(),
                annotations: Vec::new(),
            })
            .collect();
        let projection = FunctionEvidenceNameProjection::from_symbols(&symbols);
        assert!(projection.arm.is_empty());
        assert!(projection.thumb.is_empty());
        assert_eq!(projection.name_for(Arch::Arm, 0), None);
        assert_eq!(projection.name_for(Arch::Thumb, 0), None);
    }

    #[test]
    fn function_name_projection_does_not_collapse_same_entry_thumb_runs() {
        let symbol = |owner, execution_blake3, name: &str| symbolicate::Symbol {
            address: "0x4000".into(),
            arch: "thumb",
            tool: crate::recover_source::Tool::Radare2,
            owner,
            execution_blake3: Some(execution_blake3),
            original_name: "thumb_4000".into(),
            name: Some(name.into()),
            tier: symbolicate::Tier::Recovered,
            evidence: Vec::new(),
            annotations: Vec::new(),
        };
        let symbols = vec![
            symbol(
                FunctionOwner::Run {
                    producer: crate::recover_source::Tool::Radare2,
                    region_index: 0,
                    run_index: 0,
                },
                [1; 32],
                "first_run",
            ),
            symbol(
                FunctionOwner::Run {
                    producer: crate::recover_source::Tool::Radare2,
                    region_index: 1,
                    run_index: 0,
                },
                [2; 32],
                "second_run",
            ),
        ];

        let projection = FunctionEvidenceNameProjection::from_symbols(&symbols);

        assert_eq!(projection.name_for(Arch::Thumb, 0x4000), None);
        let mut exact_names = projection
            .thumb
            .values()
            .filter_map(Option::as_deref)
            .collect::<Vec<_>>();
        exact_names.sort_unstable();
        assert_eq!(exact_names, ["first_run", "second_run"]);
    }

    /// Build a minimal image_dir with decompiled/functions.json +
    /// thumb_functions.json + <label>.bin + manifest.json, for the algorithm
    /// to read. Each helper below sets up the specific shape its test needs.
    struct Img {
        root: PathBuf,
        label: String,
    }
    impl Img {
        fn new(name: &str) -> Self {
            let root = tmp_root(name);
            let label = "02_MAIN".to_string();
            // Per decompose layout, the algorithm reads
            // `<image_dir>/decompiled/functions.json` where `image_dir` is
            // `<root>/<label>`. So the decompiled dir hangs off the label dir.
            fs::create_dir_all(root.join(&label).join("decompiled")).unwrap();
            // Minimal manifest at the root level.
            fs::write(
                root.join("manifest.json"),
                r#"{"toc":[{"name":"MAIN","load_addr":4096}]}"#,
            )
            .unwrap();
            Self { root, label }
        }
        fn image_dir(&self) -> PathBuf {
            self.root.join(&self.label)
        }
        fn label(&self) -> &str {
            &self.label
        }
        fn manifest(&self) -> PathBuf {
            self.root.join("manifest.json")
        }
        fn write_functions_json(&self, json: &str) {
            fs::write(
                self.image_dir().join("decompiled").join("functions.json"),
                json,
            )
            .unwrap();
        }
        fn write_thumb_functions_json(&self, json: &str) {
            fs::write(
                self.image_dir()
                    .join("decompiled")
                    .join("thumb_functions.json"),
                json,
            )
            .unwrap();
        }
        fn write_image_bin(&self, bytes: &[u8]) {
            // Image file is at <image_dir>/<label>.bin per decompose layout.
            fs::write(self.image_dir().join(format!("{}.bin", self.label)), bytes).unwrap();
        }
        fn write_manifest_load_addr(&self, load_addr: &str) {
            let load_addr = u64::from_str_radix(load_addr.trim_start_matches("0x"), 16).unwrap();
            fs::write(
                self.root.join("manifest.json"),
                format!(r#"{{"toc":[{{"name":"MAIN","load_addr":{load_addr}}}]}}"#),
            )
            .unwrap();
        }
    }

    /// Helper: build a minimal image whose raw bytes contain the strings at
    /// known vaddrs. Strings live at offset (vaddr - load_addr) in the .bin.
    fn image_with_strings(load_addr: u64, strings: &[(u64, &str)]) -> Vec<u8> {
        let max_end = strings
            .iter()
            .map(|(addr, s)| *addr as usize - load_addr as usize + s.len())
            .max()
            .unwrap_or(0)
            .max(1);
        let mut buf = vec![0u8; max_end + 1];
        for (addr, s) in strings {
            let off = *addr as usize - load_addr as usize;
            buf[off..off + s.len()].copy_from_slice(s.as_bytes());
        }
        buf
    }

    fn image_with_strings_through(load_addr: u64, strings: &[(u64, &str)], end: u64) -> Vec<u8> {
        let mut image = image_with_strings(load_addr, strings);
        image.resize((end - load_addr) as usize, 0);
        image
    }

    fn make_arm_function(entry: u64, data_refs: &[u64]) -> serde_json::Value {
        make_arm_function_range(entry, entry + 0x10, data_refs)
    }

    fn make_arm_function_range(entry: u64, end: u64, data_refs: &[u64]) -> serde_json::Value {
        let refs: Vec<String> = data_refs.iter().map(|a| format!("0x{a:x}")).collect();
        let size = end - entry;
        serde_json::json!({
            "name": format!("FUN_{entry:x}"),
            "primary_source": "default",
            "entry": format!("0x{entry:x}"),
            "end": format!("0x{end:x}"),
            "size": size,
            "decode_ranges": [{
                "isa": "arm",
                "start": format!("0x{entry:x}"),
                "end": format!("0x{end:x}"),
                "blake3": blake3::hash(&vec![0; size as usize]).to_hex().to_string(),
            }],
            "decode_range_errors": [],
            "data_refs": refs,
        })
    }

    fn ghidra_execution_blake3(
        function: &serde_json::Value,
        image: &[u8],
        load_addr: u32,
    ) -> [u8; 32] {
        let runtime = RuntimeImage::from_plan(image, load_addr, None).unwrap();
        crate::execution_ranges::validate_ghidra_inventory_records(
            std::slice::from_ref(function),
            1,
            &runtime,
        )
        .unwrap()
        .accepted_executions[0]
            .identity
            .execution_blake3
    }

    fn make_thumb_function(entry: u64, data_refs: &[u64]) -> serde_json::Value {
        let refs: Vec<String> = data_refs.iter().map(|a| format!("0x{a:x}")).collect();
        serde_json::json!({
            "entry": format!("0x{entry:x}"),
            "name": format!("thumb_{entry:x}"),
            "size": 8,
            "body_kind": "thumb_disassembly",
            "body": "b5 80 00 20 80 bd",
            "data_refs": refs,
        })
    }

    /// Convenience: call `run` with an empty recovered_function_names map
    /// and default `GlobalsOpts` (Phase 3.0.1 Recovered-only, K_ARM/K_THUMB
    /// at the pinned constants). Real CLI flags are wired into `GlobalsOpts`.
    fn run_no_names(img: &Img) -> Result<GlobalsReport> {
        let empty = HashMap::new();
        run(
            &img.image_dir(),
            img.label(),
            &img.manifest(),
            &empty,
            &GlobalsOpts::default(),
        )
    }

    #[test]
    fn loads_v3_thumb_functions() {
        let img = Img::new("loads_v3_thumb_functions");
        img.write_functions_json("[]");
        img.write_thumb_functions_json(
            std::str::from_utf8(crate::thumb_analysis::ParsedThumbArtifact::consumer_v3_fixture())
                .unwrap(),
        );
        let artifact = crate::thumb_analysis::read_thumb_artifact(
            &img.image_dir().join("decompiled/thumb_functions.json"),
            &test_runtime(),
        )
        .unwrap();
        assert!(
            artifact.functions().all(|function| {
                function.owner.analysis_tool() == crate::analysis_tool::AnalysisTool::Rizin
            }),
            "the downstream fixture must exercise Rizin-owned v3 records"
        );
        assert_eq!(
            artifact.functions().next().unwrap().value["data_refs"],
            serde_json::json!(["0x4020", "0x4060", "0x4070"])
        );
        img.write_manifest_load_addr("0x4000");
        // Globals knows the load address and image length, so it validates the
        // artifact against the image it was produced for: an image that does
        // not span the fixture's 0x4000..0x4080 v3 region is a hard input
        // error, not silently accepted evidence.
        let mut image = image_with_strings(0x4000, &[(0x4020, "g_thumb")]);
        img.write_image_bin(&image);
        assert!(
            run_no_names(&img)
                .unwrap_err()
                .to_string()
                .contains("region 0 is outside runtime image")
        );

        image.resize(0x80, 0);
        img.write_image_bin(&image);

        let report = run_no_names(&img).unwrap();
        assert_eq!(report.recovered_count, 1);
        let output: serde_json::Value = serde_json::from_slice(
            &fs::read(img.image_dir().join("decompiled").join("globals.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(output["globals"][0]["address"], "0x4060");
        assert_eq!(output["globals"][0]["name"], "g_thumb");
        assert_eq!(output["globals"][0]["arch"], "thumb");
        let evidence = output["globals"][0]["evidence"].as_array().unwrap();
        assert!(evidence.iter().any(|item| item["kind"] == "string_load"));
        assert!(evidence.iter().any(|item| item["kind"] == "global_load"));

        let malformed = crate::thumb_analysis::ParsedThumbArtifact::malformed_consumer_v3_fixture();
        img.write_thumb_functions_json(std::str::from_utf8(&malformed).unwrap());
        assert_eq!(
            run_no_names(&img).unwrap_err().to_string(),
            "serialize: invalid Thumb artifact: v3 run 0 stored counts do not match its functions"
        );
    }

    #[test]
    fn rejects_ghidra_range_hash_mismatch() {
        let img = Img::new("rejects_ghidra_hash_mismatch");
        let mut function = make_arm_function(0x2000, &[]);
        function["decode_ranges"][0]["blake3"] = serde_json::json!("00".repeat(32));
        img.write_functions_json(&serde_json::to_string(&vec![function]).unwrap());
        img.write_image_bin(&vec![0u8; 0x2000]);

        let error = run_no_names(&img).unwrap_err();

        assert!(error.to_string().contains("BLAKE3"), "{error}");
    }

    /// Build a `Function` for direct unit tests of
    /// `disasm_anchored_recovered_for_function`. The helper only inspects
    /// `arch` and `data_refs` (the disasm events are passed separately), so
    /// the other fields get inert defaults.
    fn sample_func(arch: Arch, data_refs: Vec<u64>) -> Function {
        Function {
            entry: 0,
            owner: FunctionOwner::Ghidra,
            execution_blake3: None,
            decode_ranges: Vec::new(),
            arch,
            ghidra_name: "sample".to_string(),
            recovered_name: None,
            data_refs,
            body: None,
        }
    }

    #[test]
    fn empty_report_inits_phase3_0_1_fields_to_zero() {
        let r = GlobalsReport::empty();
        assert_eq!(r.recovered_count, 0);
        assert_eq!(r.conflicts_dropped, 0);
        assert_eq!(r.provisional_generated, 0);
        assert_eq!(r.provisional_suppressed_by_recovered, 0);
    }

    #[test]
    fn evidence_globalload_serializes_with_pc_register_address() {
        let e = Evidence::GlobalLoad {
            pc: "0x40e6".into(),
            register: "r0".into(),
            address: "0x446814a2".into(),
        };
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["kind"], "global_load");
        assert_eq!(v["pc"], "0x40e6");
        assert_eq!(v["register"], "r0");
        assert_eq!(v["address"], "0x446814a2");
    }

    #[test]
    fn evidence_stringload_serializes_with_pc_register_address() {
        let e = Evidence::StringLoad {
            pc: "0x40e0".into(),
            register: "r1".into(),
            address: "0x40e22000".into(),
        };
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["kind"], "string_load");
        assert_eq!(v["pc"], "0x40e0");
    }

    #[test]
    fn globals_opts_default_is_recovered_only() {
        let o = GlobalsOpts::default();
        assert!(!o.include_provisional);
        assert_eq!(o.k_arm, K_ARM);
        assert_eq!(o.k_thumb, K_THUMB);
    }

    #[test]
    fn globals_file_omits_optional_fields_when_none() {
        let f = GlobalsFile {
            format: FORMAT_V1,
            image: "02_MAIN".into(),
            globals: vec![],
            provisional_suppressed: None,
            phase3_0_1_error: None,
        };
        let v = serde_json::to_string(&f).unwrap();
        assert!(!v.contains("provisional_suppressed"));
        assert!(!v.contains("phase3_0_1_error"));
    }

    #[test]
    fn globals_file_includes_provisional_suppressed_when_set() {
        let f = GlobalsFile {
            format: FORMAT_V1,
            image: "02_MAIN".into(),
            globals: vec![],
            provisional_suppressed: Some(7),
            phase3_0_1_error: None,
        };
        let v = serde_json::to_string(&f).unwrap();
        assert!(v.contains("\"provisional_suppressed\":7"));
    }

    #[test]
    fn recovers_name_when_function_has_single_global_and_unique_identifier() {
        let img = Img::new("happy_path");
        // Function at 0x2000 references: a string at 0x3000 ("g_foo invalid"),
        // and a non-string data_ref at 0x4000 (the global).
        img.write_functions_json(&format!(
            "[{}]",
            make_arm_function(0x2000, &[0x3000, 0x4000])
        ));
        img.write_thumb_functions_json(
            r#"{"format":"pixel-modem-extractor-thumb-functions-v2","functions":[]}"#,
        );
        // Image has the string at vaddr 0x3000; offset 0x3000 - 0x1000 = 0x2000.
        img.write_manifest_load_addr("0x1000");
        img.write_image_bin(&image_with_strings(0x1000, &[(0x3000, "g_foo invalid")]));

        let report = run_no_names(&img).unwrap();
        assert_eq!(report.recovered_count, 1);
        assert_eq!(report.conflicts_dropped, 0);

        let v: serde_json::Value = serde_json::from_slice(
            &fs::read(img.image_dir().join("decompiled").join("globals.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(v["format"], FORMAT_V1);
        assert_eq!(v["globals"].as_array().unwrap().len(), 1);
        assert_eq!(v["globals"][0]["address"], "0x4000");
        assert_eq!(v["globals"][0]["name"], "g_foo");
        assert_eq!(v["globals"][0]["tier"], "recovered");
        assert_eq!(v["globals"][0]["arch"], "arm");
        assert!(v["globals"][0]["size"].is_null());
        assert_eq!(v["globals"][0]["evidence"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn atomic_globals_write_preserves_existing_file_before_commit_failure() {
        let root = tmp_root("atomic_globals_before_commit_failure");
        let path = root.join("globals.json");
        let sentinel = b"existing globals.json sentinel\n";
        let candidate = b"{\n  \"format\": \"replacement candidate\"\n}";
        fs::write(&path, sentinel).unwrap();

        let error = write_globals_json_with_before_commit(&path, candidate, || {
            Err(Error::Serialize(
                "injected failure immediately before commit".into(),
            ))
        })
        .unwrap_err();

        assert!(matches!(
            error,
            Error::Serialize(ref reason)
                if reason == "injected failure immediately before commit"
        ));
        assert_eq!(fs::read(path).unwrap(), sentinel);
    }

    #[test]
    fn default_globals_json_writer_preserves_historical_v1_bytes() {
        // This drives `run` through its real pretty-serialization and file-write
        // path. The literal is the historical default v1 output: changing field
        // order, indentation, optional-field omission, or trailing-newline
        // behavior must fail byte-for-byte.
        let img = Img::new("default_v1_bytes");
        img.write_functions_json(&format!(
            "[{}]",
            make_arm_function(0x2000, &[0x3000, 0x4000])
        ));
        img.write_thumb_functions_json(
            r#"{"format":"pixel-modem-extractor-thumb-functions-v2","functions":[]}"#,
        );
        img.write_manifest_load_addr("0x1000");
        img.write_image_bin(&image_with_strings(0x1000, &[(0x3000, "g_foo invalid")]));
        fs::write(img.image_dir().join("decompiled").join("disasm.lst"), b"").unwrap();

        let report = run_no_names(&img).unwrap();
        assert_eq!(report.recovered_count, 1);
        let actual = fs::read(img.image_dir().join("decompiled").join("globals.json")).unwrap();
        let historical_v1 = br#"{
  "format": "pixel-modem-extractor-globals-v1",
  "globals": [
    {
      "address": "0x4000",
      "arch": "arm",
      "name": "g_foo",
      "tier": "recovered",
      "size": null,
      "evidence": [
        {
          "kind": "string",
          "address": "0x3000",
          "value": "g_foo invalid"
        },
        {
          "kind": "function",
          "address": "0x2000",
          "arch": "arm",
          "name": "FUN_2000"
        }
      ],
      "annotations": []
    }
  ],
  "image": "02_MAIN"
}"#;

        assert_eq!(actual, historical_v1);
    }

    #[test]
    fn early_projected_function_names_match_late_finalized_globals_bytes() {
        // This catches early globals serializing pass-1 placeholders, or using
        // recovered_name as the evidence name and thereby renaming a Thumb
        // function whose final symbol is an explicit null barrier.
        let late = Img::new("late_finalized_names");
        let early = Img::new("early_projected_names");
        let mut late_arm = vec![
            make_arm_function(0x2000, &[0x3000, 0x4000]),
            make_arm_function(0x2300, &[0x3300, 0x4300]),
        ];
        late_arm[0]["name"] = serde_json::json!("ARM_FINAL_2000");
        // Owner-aware finalize stamps the ARM record from the ARM symbol, so
        // the same-address Thumb symbol never renames it.
        late_arm[1]["name"] = serde_json::json!("COLLISION_FIRST_2300");
        let early_arm = vec![
            make_arm_function(0x2000, &[0x3000, 0x4000]),
            make_arm_function(0x2300, &[0x3300, 0x4300]),
        ];
        let mut late_thumb = vec![
            make_thumb_function(0x2100, &[0x3100, 0x4100]),
            make_thumb_function(0x2200, &[0x3200, 0x4200]),
        ];
        late_thumb[0]["name"] = serde_json::json!("THUMB_FINAL_2100");
        late_thumb[1]["name"] = serde_json::json!("fcn.2200");
        let mut early_thumb = late_thumb.clone();
        early_thumb[0]["name"] = serde_json::json!("fcn.2100");

        late.write_functions_json(&serde_json::to_string(&late_arm).unwrap());
        early.write_functions_json(&serde_json::to_string(&early_arm).unwrap());
        late.write_thumb_functions_json(
            &serde_json::json!({
                "format": "pixel-modem-extractor-thumb-functions-v2",
                "functions": late_thumb,
            })
            .to_string(),
        );
        early.write_thumb_functions_json(
            &serde_json::json!({
                "format": "pixel-modem-extractor-thumb-functions-v2",
                "functions": early_thumb,
            })
            .to_string(),
        );
        let image = image_with_strings(
            0x1000,
            &[
                (0x3000, "g_arm_2000 invalid"),
                (0x3100, "g_thumb_2100 invalid"),
                (0x3200, "g_shared_2200 invalid"),
                (0x3300, "g_collision_2300 invalid"),
            ],
        );
        for img in [&late, &early] {
            img.write_image_bin(&image);
            fs::write(img.image_dir().join("decompiled").join("disasm.lst"), b"").unwrap();
        }
        let arm_2000_execution = ghidra_execution_blake3(&early_arm[0], &image, 0x1000);
        let arm_2300_execution = ghidra_execution_blake3(&early_arm[1], &image, 0x1000);

        let symbols = vec![
            symbolicate::Symbol {
                address: "0x2000".into(),
                arch: "arm",
                tool: crate::recover_source::Tool::Ghidra,
                owner: FunctionOwner::Ghidra,
                execution_blake3: Some(arm_2000_execution),
                original_name: "FUN_2000".into(),
                name: Some("ARM_FINAL_2000".into()),
                tier: symbolicate::Tier::Recovered,
                evidence: vec![],
                annotations: vec![],
            },
            symbolicate::Symbol {
                address: "0x2100".into(),
                arch: "thumb",
                tool: crate::recover_source::Tool::Radare2,
                owner: FunctionOwner::Legacy {
                    producer: crate::recover_source::Tool::Radare2,
                },
                execution_blake3: None,
                original_name: "fcn.2100".into(),
                name: Some("THUMB_FINAL_2100".into()),
                tier: symbolicate::Tier::Provisional,
                evidence: vec![],
                annotations: vec![],
            },
            symbolicate::Symbol {
                address: "0x2200".into(),
                arch: "arm",
                tool: crate::recover_source::Tool::Ghidra,
                owner: FunctionOwner::Ghidra,
                execution_blake3: None,
                original_name: "FUN_2200".into(),
                name: Some("ARM_SHARED_2200".into()),
                tier: symbolicate::Tier::Recovered,
                evidence: vec![],
                annotations: vec![],
            },
            symbolicate::Symbol {
                address: "0x2200".into(),
                arch: "thumb",
                tool: crate::recover_source::Tool::Radare2,
                owner: FunctionOwner::Legacy {
                    producer: crate::recover_source::Tool::Radare2,
                },
                execution_blake3: None,
                original_name: "fcn.2200".into(),
                name: None,
                tier: symbolicate::Tier::None,
                evidence: vec![],
                annotations: vec![],
            },
            symbolicate::Symbol {
                address: "0x2300".into(),
                arch: "arm",
                tool: crate::recover_source::Tool::Ghidra,
                owner: FunctionOwner::Ghidra,
                execution_blake3: Some(arm_2300_execution),
                original_name: "FUN_2300".into(),
                name: Some("COLLISION_FIRST_2300".into()),
                tier: symbolicate::Tier::Recovered,
                evidence: vec![],
                annotations: vec![],
            },
            symbolicate::Symbol {
                address: "0x2300".into(),
                arch: "thumb",
                tool: crate::recover_source::Tool::Radare2,
                owner: FunctionOwner::Legacy {
                    producer: crate::recover_source::Tool::Radare2,
                },
                execution_blake3: None,
                original_name: "fcn.2300".into(),
                name: Some("COLLISION_FINAL_2300".into()),
                tier: symbolicate::Tier::Provisional,
                evidence: vec![],
                annotations: vec![],
            },
        ];
        let recovered_names = HashMap::from([
            ("2000".to_string(), "ARM_FINAL_2000".to_string()),
            ("2100".to_string(), "THUMB_FINAL_2100".to_string()),
            ("2200".to_string(), "ARM_SHARED_2200".to_string()),
            ("2300".to_string(), "COLLISION_FINAL_2300".to_string()),
        ]);
        let projection = FunctionEvidenceNameProjection::from_symbols(&symbols);

        let late_report = run(
            &late.image_dir(),
            late.label(),
            &late.manifest(),
            &recovered_names,
            &GlobalsOpts::default(),
        )
        .unwrap();
        let early_report = run_with_evidence_projection(
            &early.image_dir(),
            early.label(),
            &early.manifest(),
            &recovered_names,
            Some(&projection),
            &GlobalsOpts::default(),
        )
        .unwrap();

        assert_eq!(late_report.recovered_count, early_report.recovered_count);
        assert_eq!(
            late_report.conflicts_dropped,
            early_report.conflicts_dropped
        );
        assert_eq!(
            late_report.provisional_generated,
            early_report.provisional_generated
        );
        assert_eq!(
            late_report.provisional_suppressed_by_recovered,
            early_report.provisional_suppressed_by_recovered
        );
        let late_bytes =
            fs::read(late.image_dir().join("decompiled").join("globals.json")).unwrap();
        let early_bytes =
            fs::read(early.image_dir().join("decompiled").join("globals.json")).unwrap();
        let late_json: serde_json::Value = serde_json::from_slice(&late_bytes).unwrap();
        let early_json: serde_json::Value = serde_json::from_slice(&early_bytes).unwrap();
        assert_eq!(late_json["globals"], early_json["globals"]);
        assert_eq!(
            late_json["globals"]
                .as_array()
                .unwrap()
                .iter()
                .map(|global| global["address"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["0x4000", "0x4100", "0x4200", "0x4300"]
        );
        assert!(
            late_json["globals"]
                .as_array()
                .unwrap()
                .iter()
                .all(|global| global["tier"] == "recovered")
        );
        let shared = &late_json["globals"][2]["evidence"][1];
        assert_eq!(shared["arch"], "thumb");
        assert_eq!(shared["name"], "fcn.2200");
        assert_eq!(shared["recovered_name"], "ARM_SHARED_2200");
        assert_eq!(late_bytes, early_bytes);
    }

    #[test]
    fn skips_function_with_multiple_global_candidates() {
        let img = Img::new("multi_global");
        // Two non-string data_refs → ambiguous, skip.
        img.write_functions_json(&format!(
            "[{}]",
            make_arm_function(0x2000, &[0x3000, 0x4000, 0x5000])
        ));
        img.write_thumb_functions_json(
            r#"{"format":"pixel-modem-extractor-thumb-functions-v2","functions":[]}"#,
        );
        img.write_manifest_load_addr("0x1000");
        img.write_image_bin(&image_with_strings(0x1000, &[(0x3000, "g_foo invalid")]));

        let report = run_no_names(&img).unwrap();
        assert_eq!(report.recovered_count, 0);
    }

    #[test]
    fn skips_function_with_multiple_identifier_candidates() {
        let img = Img::new("multi_ident");
        // One non-string data_ref, but two distinct identifiers in the strings.
        img.write_functions_json(&format!(
            "[{}]",
            make_arm_function(0x2000, &[0x3000, 0x3100, 0x4000])
        ));
        img.write_thumb_functions_json(
            r#"{"format":"pixel-modem-extractor-thumb-functions-v2","functions":[]}"#,
        );
        img.write_manifest_load_addr("0x1000");
        img.write_image_bin(&image_with_strings(
            0x1000,
            &[(0x3000, "g_foo invalid"), (0x3100, "g_bar also bad")],
        ));

        let report = run_no_names(&img).unwrap();
        assert_eq!(report.recovered_count, 0);
    }

    #[test]
    fn drops_conflicting_assignments_same_addr_different_names() {
        let img = Img::new("conflict");
        // Two functions associate different names with addr 0x4000.
        img.write_functions_json(&format!(
            "[{},{}]",
            make_arm_function(0x2000, &[0x3000, 0x4000]), // string "g_foo" → 0x4000
            make_arm_function(0x2100, &[0x3100, 0x4000]), // string "g_bar" → 0x4000
        ));
        img.write_thumb_functions_json(
            r#"{"format":"pixel-modem-extractor-thumb-functions-v2","functions":[]}"#,
        );
        img.write_manifest_load_addr("0x1000");
        img.write_image_bin(&image_with_strings(
            0x1000,
            &[(0x3000, "g_foo invalid"), (0x3100, "g_bar invalid")],
        ));

        let report = run_no_names(&img).unwrap();
        assert_eq!(report.recovered_count, 0);
        assert_eq!(report.conflicts_dropped, 1);
    }

    #[test]
    fn reinforces_same_assignment_across_functions() {
        let img = Img::new("reinforce");
        // Two functions associate the SAME name with addr 0x4000.
        img.write_functions_json(&format!(
            "[{},{}]",
            make_arm_function(0x2000, &[0x3000, 0x4000]),
            make_arm_function(0x2100, &[0x3100, 0x4000]),
        ));
        img.write_thumb_functions_json(
            r#"{"format":"pixel-modem-extractor-thumb-functions-v2","functions":[]}"#,
        );
        img.write_manifest_load_addr("0x1000");
        img.write_image_bin(&image_with_strings(
            0x1000,
            &[(0x3000, "g_foo invalid"), (0x3100, "g_foo also")],
        ));

        let report = run_no_names(&img).unwrap();
        assert_eq!(report.recovered_count, 1);
        assert_eq!(report.conflicts_dropped, 0);

        let v: serde_json::Value = serde_json::from_slice(
            &fs::read(img.image_dir().join("decompiled").join("globals.json")).unwrap(),
        )
        .unwrap();
        // One entry, four evidence entries (2 strings + 2 functions).
        assert_eq!(v["globals"].as_array().unwrap().len(), 1);
        assert_eq!(v["globals"][0]["evidence"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn filters_generic_identifiers() {
        let img = Img::new("generic");
        // The only identifier is "NULL" — filtered out by GENERIC_TOKENS.
        img.write_functions_json(&format!(
            "[{}]",
            make_arm_function(0x2000, &[0x3000, 0x4000])
        ));
        img.write_thumb_functions_json(
            r#"{"format":"pixel-modem-extractor-thumb-functions-v2","functions":[]}"#,
        );
        img.write_manifest_load_addr("0x1000");
        img.write_image_bin(&image_with_strings(0x1000, &[(0x3000, "NULL is bad")]));

        let report = run_no_names(&img).unwrap();
        assert_eq!(report.recovered_count, 0);
    }

    #[test]
    fn dbt_attractor_filtered_by_stoplist() {
        // Regression guard for the STOPLIST adoption: `source_tree.rs`'s
        // STOPLIST is the baseline blocklist; GENERIC_TOKENS adopts its
        // identifier-relevant entries (`DBT`, `ASSERT`). On production
        // `02_MAIN` the `0x4908bbac` "DBT" attractor alone accounted for 11
        // of 190 raw proposals in the Phase 3.0 production pre-check.
        // Both are underscoreless so the strict-identifier rule drops them
        // today; GENERIC_TOKENS lists them explicitly so the filter holds
        // even if the underscore requirement is ever relaxed. Here a string
        // mixes the STOPLIST attractors with one real identifier — the real
        // identifier survives, the attractors do not.
        let img = Img::new("dbt_stoplist");
        img.write_functions_json(&format!(
            "[{}]",
            make_arm_function(0x2000, &[0x3000, 0x4000])
        ));
        img.write_thumb_functions_json(
            r#"{"format":"pixel-modem-extractor-thumb-functions-v2","functions":[]}"#,
        );
        img.write_manifest_load_addr("0x1000");
        img.write_image_bin(&image_with_strings(
            0x1000,
            &[(0x3000, "DBT: ASSERT g_real_name")],
        ));

        let report = run_no_names(&img).unwrap();
        assert_eq!(report.recovered_count, 1);
        let v: serde_json::Value = serde_json::from_slice(
            &fs::read(img.image_dir().join("decompiled").join("globals.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            v["globals"][0]["name"], "g_real_name",
            "STOPLIST attractors (DBT, ASSERT) must be filtered, leaving the real identifier"
        );
    }

    #[test]
    fn emits_empty_globals_json_when_nothing_recovers() {
        let img = Img::new("empty");
        // No functions at all → 0 globals. globals.json must still be written.
        img.write_functions_json("[]");
        img.write_thumb_functions_json(
            r#"{"format":"pixel-modem-extractor-thumb-functions-v2","functions":[]}"#,
        );
        img.write_manifest_load_addr("0x1000");
        img.write_image_bin(&[0u8; 16]);

        let report = run_no_names(&img).unwrap();
        assert_eq!(report.recovered_count, 0);

        let v: serde_json::Value = serde_json::from_slice(
            &fs::read(img.image_dir().join("decompiled").join("globals.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(v["format"], FORMAT_V1);
        assert!(v["globals"].as_array().unwrap().is_empty());
    }

    #[test]
    fn handles_arch_attribute_arm_thumb_mixed() {
        let img = Img::new("arch_mixed");
        // ARM function + Thumb function, same name + addr → arch: mixed.
        img.write_functions_json(&format!(
            "[{}]",
            make_arm_function(0x2000, &[0x3000, 0x4000])
        ));
        img.write_thumb_functions_json(&format!(
            r#"{{"format":"pixel-modem-extractor-thumb-functions-v2","functions":[{}]}}"#,
            make_thumb_function(0x2100, &[0x3100, 0x4000])
        ));
        img.write_manifest_load_addr("0x1000");
        img.write_image_bin(&image_with_strings(
            0x1000,
            &[(0x3000, "g_foo invalid"), (0x3100, "g_foo also")],
        ));

        let report = run_no_names(&img).unwrap();
        assert_eq!(report.recovered_count, 1);

        let v: serde_json::Value = serde_json::from_slice(
            &fs::read(img.image_dir().join("decompiled").join("globals.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(v["globals"][0]["arch"], "mixed");
        assert_eq!(v["globals"][0]["evidence"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn evidence_ordered_deterministically_by_function_address() {
        let img = Img::new("ordering");
        // Two functions at 0x2100 and 0x2000 — evidence should sort ascending.
        img.write_functions_json(&format!(
            "[{},{}]",
            make_arm_function(0x2100, &[0x3000, 0x4000]),
            make_arm_function(0x2000, &[0x3100, 0x4000]),
        ));
        img.write_thumb_functions_json(
            r#"{"format":"pixel-modem-extractor-thumb-functions-v2","functions":[]}"#,
        );
        img.write_manifest_load_addr("0x1000");
        img.write_image_bin(&image_with_strings(
            0x1000,
            &[(0x3000, "g_foo first"), (0x3100, "g_foo second")],
        ));

        let report = run_no_names(&img).unwrap();
        assert_eq!(report.recovered_count, 1);

        let v: serde_json::Value = serde_json::from_slice(
            &fs::read(img.image_dir().join("decompiled").join("globals.json")).unwrap(),
        )
        .unwrap();
        let ev = v["globals"][0]["evidence"].as_array().unwrap();
        assert_eq!(ev.len(), 4);
        // Function addresses (kind == "function") should sort ascending.
        // String entries also carry an `address`, so discriminate by kind.
        let fn_addrs: Vec<&str> = ev
            .iter()
            .filter(|e| e["kind"] == "function")
            .filter_map(|e| e.get("address").and_then(|a| a.as_str()))
            .collect();
        assert_eq!(fn_addrs, vec!["0x2000", "0x2100"]);
    }

    #[test]
    fn missing_raw_bytes_returns_err_surface_3_0_a() {
        let img = Img::new("no_bin");
        img.write_functions_json(&format!("[{}]", make_arm_function(0x2000, &[0x4000])));
        img.write_thumb_functions_json(
            r#"{"format":"pixel-modem-extractor-thumb-functions-v2","functions":[]}"#,
        );
        img.write_manifest_load_addr("0x1000");
        // Note: no write_image_bin call.

        let err = run_no_names(&img).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("no such file") || msg.contains("not found") || msg.contains("No such"),
            "expected io error message; got: {msg}"
        );
        // Confirm globals.json was NOT written (atomicity — Surface 3.0-A).
        assert!(
            !img.image_dir()
                .join("decompiled")
                .join("globals.json")
                .exists(),
            "globals.json must not be written on Surface 3.0-A failure"
        );
    }

    #[test]
    fn drops_candidate_refs_below_load_addr() {
        let img = Img::new("sub_load_addr");
        // Function at 0x2000 with three data_refs: a sub-load-addr noise ref
        // (0x500), a string ref (0x3000), and the actual global (0x4000).
        // Without the range filter, candidate_refs would be [0x500, 0x4000]
        // (len 2) → ambiguous, skip. With the range filter, 0x500 is dropped
        // as out-of-image noise → candidate_refs = [0x4000] → recover.
        img.write_functions_json(&format!(
            "[{}]",
            make_arm_function(0x2000, &[0x500, 0x3000, 0x4000])
        ));
        img.write_thumb_functions_json(
            r#"{"format":"pixel-modem-extractor-thumb-functions-v2","functions":[]}"#,
        );
        img.write_manifest_load_addr("0x1000");
        img.write_image_bin(&image_with_strings(0x1000, &[(0x3000, "g_foo invalid")]));

        let report = run_no_names(&img).unwrap();
        assert_eq!(report.recovered_count, 1);
        assert_eq!(report.conflicts_dropped, 0);
    }

    #[test]
    fn string_evidence_picks_the_string_that_contains_the_name_not_just_lowest_addr() {
        let img = Img::new("naming_string");
        // Function references: a non-naming string at 0x3000 (lower addr),
        // the naming string at 0x3200 (mentions "g_foo"), and the global at 0x4000.
        img.write_functions_json(&format!(
            "[{}]",
            make_arm_function(0x2000, &[0x3000, 0x3200, 0x4000])
        ));
        img.write_thumb_functions_json(
            r#"{"format":"pixel-modem-extractor-thumb-functions-v2","functions":[]}"#,
        );
        img.write_manifest_load_addr("0x1000");
        img.write_image_bin(&image_with_strings(
            0x1000,
            &[(0x3000, "unrelated log msg"), (0x3200, "g_foo invalid")],
        ));

        let report = run_no_names(&img).unwrap();
        assert_eq!(report.recovered_count, 1);

        let v: serde_json::Value = serde_json::from_slice(
            &fs::read(img.image_dir().join("decompiled").join("globals.json")).unwrap(),
        )
        .unwrap();
        let ev = v["globals"][0]["evidence"].as_array().unwrap();
        // String + Function pair.
        assert_eq!(ev.len(), 2);
        // The String evidence must point at 0x3200 (the naming string),
        // not 0x3000 (the lower-addressed but non-naming string).
        let string_evidence = ev.iter().find(|e| e["kind"] == "string").unwrap();
        assert_eq!(string_evidence["address"], "0x3200");
        assert!(string_evidence["value"].as_str().unwrap().contains("g_foo"));
    }

    #[test]
    fn recovered_tier_requires_disasm_proximity_within_k() {
        // String load at PC=X, global load at PC=X+K (within window): emits Recovered.
        // At PC=X+K+1 (just outside): does not. THE K-BOUNDARY SENTINEL.
        let string_addr = 0x40e22000;
        let global_addr = 0x40e30000;
        let string_map = HashMap::from([(string_addr, "g_foo is NULL".into())]);

        // Within window (K_ARM = const K_ARM):
        let disasm_in = "0x10: movw r0, 0x2000\n0x14: movt r0, 0x40e2\n0x18: movw r1, 0x0000\n0x1c: movt r1, 0x40e3\n";
        let events_in = symbolicate::reconstruct_load_events(disasm_in);
        let out_in = disasm_anchored_recovered_for_function(
            &sample_func(Arch::Arm, vec![string_addr, global_addr]),
            &string_map,
            &events_in,
            K_ARM,
        );
        assert!(out_in.iter().any(|(a, _, _, _)| *a == global_addr));

        // Just outside window (force K_ARM = 1 by passing directly):
        let out_out = disasm_anchored_recovered_for_function(
            &sample_func(Arch::Arm, vec![string_addr, global_addr]),
            &string_map,
            &events_in,
            1,
        );
        assert!(out_out.is_empty());
    }

    #[test]
    fn recovered_tier_drops_when_two_globals_in_window() {
        // Two global-loads in window + one identifier in string -> no Recovered
        // emission (ambiguous; defers to the name-prior pass).
        let string_addr = 0x40e22000;
        let g1 = 0x40e30000;
        let g2 = 0x40e31000;
        let string_map = HashMap::from([(string_addr, "g_only is NULL".into())]);
        let disasm = "0x10: movw r0, 0x2000\n0x14: movt r0, 0x40e2\n\
             0x18: movw r1, 0x0000\n0x1c: movt r1, 0x40e3\n\
             0x20: movw r2, 0x1000\n0x24: movt r2, 0x40e3\n";
        let events = symbolicate::reconstruct_load_events(disasm);
        let out = disasm_anchored_recovered_for_function(
            &sample_func(Arch::Arm, vec![string_addr, g1, g2]),
            &string_map,
            &events,
            K_ARM,
        );
        assert!(out.is_empty());
    }

    #[test]
    fn recovered_tier_drops_when_two_identifiers_in_string() {
        // One global-load in window + two identifiers in string -> no Recovered.
        let string_addr = 0x40e22000;
        let g1 = 0x40e30000;
        let string_map = HashMap::from([(string_addr, "g_foo and g_bar are NULL".into())]);
        let disasm = "0x10: movw r0, 0x2000\n0x14: movt r0, 0x40e2\n\
             0x18: movw r1, 0x0000\n0x1c: movt r1, 0x40e3\n";
        let events = symbolicate::reconstruct_load_events(disasm);
        let out = disasm_anchored_recovered_for_function(
            &sample_func(Arch::Arm, vec![string_addr, g1]),
            &string_map,
            &events,
            K_ARM,
        );
        assert!(out.is_empty());
    }

    #[test]
    fn recovered_tier_distinguishes_arm_and_thumb_k() {
        // Same disasm PCs; ARM with K_ARM vs Thumb with K_THUMB. The test
        // asserts the K-distance boundary is per-arch. (K_ARM == K_THUMB on
        // this firmware — pinned equal by the pre-check — so both branches
        // resolve to the same constant; this test confirms both constants
        // are wired and at least one path emits.)
        let string_addr = 0x40e22000;
        let global_addr = 0x40e30000;
        let string_map = HashMap::from([(string_addr, "g_foo is NULL".into())]);
        let disasm = "0x10: movw r0, 0x2000\n0x14: movt r0, 0x40e2\n\
             0x18: movw r1, 0x0000\n0x1c: movt r1, 0x40e3\n";
        let events = symbolicate::reconstruct_load_events(disasm);
        let arm_out = disasm_anchored_recovered_for_function(
            &sample_func(Arch::Arm, vec![string_addr, global_addr]),
            &string_map,
            &events,
            K_ARM,
        );
        let thumb_out = disasm_anchored_recovered_for_function(
            &sample_func(Arch::Thumb, vec![string_addr, global_addr]),
            &string_map,
            &events,
            K_THUMB,
        );
        // Both produce the global when K_ARM and K_THUMB both >= distance(0x14, 0x1c).
        assert!(
            arm_out.iter().any(|(a, _, _, _)| *a == global_addr)
                || thumb_out.iter().any(|(a, _, _, _)| *a == global_addr)
        );
    }

    #[test]
    fn mega_function_guard_skips_oversize_ranges() {
        // Ghidra occasionally mis-estimates function boundaries, producing
        // "functions" spanning megabytes of disasm (production `02_MAIN` worst
        // case: 37 MB disasm / ~865k load-events / 9.3M insns at one "function").
        // The mega-slice guard at the top of `disasm_anchored_recovered_for_function`
        // silently skips any function whose authenticated execution coverage
        // exceeds `MEGA_FN_THRESHOLD`. Real functions process normally.
        let string_addr = 0x40e22000;
        let global_addr = 0x40e30000;
        let string_map = HashMap::from([(string_addr, "g_foo is NULL".into())]);
        let disasm = "0x10: movw r0, 0x2000\n0x14: movt r0, 0x40e2\n\
              0x18: movw r1, 0x0000\n0x1c: movt r1, 0x40e3\n";
        let events = symbolicate::reconstruct_load_events(disasm);

        // Span strictly greater than MEGA_FN_THRESHOLD -> guard fires, empty.
        let mut mega = sample_func(Arch::Arm, vec![string_addr, global_addr]);
        mega.entry = 0x1000;
        mega.decode_ranges = vec![(mega.entry, mega.entry + MEGA_FN_THRESHOLD + 1)];
        let mega_out = disasm_anchored_recovered_for_function(&mega, &string_map, &events, K_ARM);
        assert!(
            mega_out.is_empty(),
            "mega-slice function (span > MEGA_FN_THRESHOLD) must be skipped"
        );

        // Same data_refs / events under a normal-sized span still emits — the
        // guard must not affect ordinary functions.
        let mut normal = sample_func(Arch::Arm, vec![string_addr, global_addr]);
        normal.entry = 0x1000;
        normal.decode_ranges = vec![(normal.entry, 0x2000)];
        let normal_out =
            disasm_anchored_recovered_for_function(&normal, &string_map, &events, K_ARM);
        assert!(
            normal_out.iter().any(|(a, _, _, _)| *a == global_addr),
            "normal-sized function must still emit Recovered"
        );
    }

    #[test]
    fn strict_rule_filters_file_fragment_identifiers() {
        // __FILE__ path components with underscores (e.g. the `macr_drv`
        // directory in `src/macr_drv/bar.c`) survive the identifier rule —
        // they have an underscore, match the regex, and aren't in
        // GENERIC_TOKENS — but they are not global names, they are path
        // fragments. The strict-rule path mirrors
        // `symbolicate::recover_func_name`, where `is_ident` rejects paths
        // outright: a string that IS a source path is skipped during
        // identifier extraction so its filename/component can't leak in as
        // a candidate name. Here the function's only string ref IS a
        // __FILE__ path whose only underscored token is a directory name;
        // without the filter that directory name would be recovered as the
        // global name.
        let img = Img::new("strict_file_fragment");
        img.write_functions_json(&format!(
            "[{}]",
            make_arm_function(0x2000, &[0x3000, 0x4000])
        ));
        img.write_thumb_functions_json(
            r#"{"format":"pixel-modem-extractor-thumb-functions-v2","functions":[]}"#,
        );
        img.write_manifest_load_addr("0x1000");
        // `macr_drv` is the only underscored token; without the __FILE__-
        // fragment filter it would be proposed as the global name.
        img.write_image_bin(&image_with_strings(
            0x1000,
            &[(0x3000, "src/macr_drv/bar.c")],
        ));

        let report = run_no_names(&img).unwrap();
        assert_eq!(
            report.recovered_count, 0,
            "strict-rule path must not propose __FILE__ path fragments as global names"
        );
    }

    #[test]
    fn disasm_path_filters_file_fragment_identifiers() {
        // Same __FILE__-fragment leakage as the strict-rule path (see
        // `strict_rule_filters_file_fragment_identifiers`), but exercising the
        // disasm-anchored helper directly. A string that IS a source path
        // leaks its underscored directory/filename as the only identifier
        // candidate (`macr_drv` here); without the `is_src_path` skip inside
        // the shared `filter_identifier_tokens` helper the disasm path would
        // recover `macr_drv` as the global name. Moving the skip into the
        // helper fixes both call sites by construction.
        let string_addr = 0x40e22000;
        let global_addr = 0x40e30000;
        let string_map = HashMap::from([(string_addr, "src/macr_drv/bar.c".into())]);
        let disasm = "0x10: movw r0, 0x2000\n0x14: movt r0, 0x40e2\n\
                      0x18: movw r1, 0x0000\n0x1c: movt r1, 0x40e3\n";
        let events = symbolicate::reconstruct_load_events(disasm);
        let out = disasm_anchored_recovered_for_function(
            &sample_func(Arch::Arm, vec![string_addr, global_addr]),
            &string_map,
            &events,
            K_ARM,
        );
        assert!(
            out.is_empty(),
            "disasm-anchored path must not propose __FILE__ path fragments as global names"
        );
    }

    #[test]
    fn phase3_0_strict_rule_path_emits_no_globalload_evidence() {
        // Phase 3.0's strict single-global case still emits; evidence shape
        // is [String, Function] (no GlobalLoad/StringLoad). Regression guard
        // against backfilling Phase 3.0's evidence with disasm-anchored entries.
        let img = Img::new("strict_no_gl");
        img.write_functions_json(&format!(
            "[{}]",
            make_arm_function(0x2000, &[0x3000, 0x4000])
        ));
        img.write_thumb_functions_json(
            r#"{"format":"pixel-modem-extractor-thumb-functions-v2","functions":[]}"#,
        );
        img.write_manifest_load_addr("0x1000");
        img.write_image_bin(&image_with_strings(0x1000, &[(0x3000, "g_foo invalid")]));

        let report = run_no_names(&img).unwrap();
        assert_eq!(report.recovered_count, 1);

        let v: serde_json::Value = serde_json::from_slice(
            &fs::read(img.image_dir().join("decompiled").join("globals.json")).unwrap(),
        )
        .unwrap();
        let ev = v["globals"][0]["evidence"].as_array().unwrap();
        assert!(
            !ev.iter()
                .any(|e| e["kind"] == "global_load" || e["kind"] == "string_load"),
            "Phase 3.0 strict-rule path must not emit disasm-anchored evidence"
        );
        assert_eq!(ev.len(), 2);
    }

    #[test]
    fn provisional_tier_requires_recovered_function_name() {
        // Function with no recovered_name -> never produces Provisional.
        let string_addr = 0x40e22000;
        let g1 = 0x40e30000;
        let g2 = 0x40e31000;
        let string_map =
            HashMap::from([(string_addr, "lteRrc_state and lteRrc_other are NULL".into())]);
        let disasm = "0x10: movw r0, 0x2000\n0x14: movt r0, 0x40e2\n\
             0x18: movw r1, 0x0000\n0x1c: movt r1, 0x40e3\n\
             0x20: movw r2, 0x1000\n0x24: movt r2, 0x40e3\n"
            .to_string();
        let events = symbolicate::reconstruct_load_events(&disasm);
        let mut func = sample_func(Arch::Arm, vec![string_addr, g1, g2]);
        func.recovered_name = None; // <-- no name prior available
        let out = name_prior_provisional_for_function(&func, &string_map, &events, K_ARM);
        assert!(out.is_empty());
    }

    #[test]
    fn provisional_tier_resolves_tie_via_name_prior() {
        // Two globals × two identifiers in window; function name "LteRrc_CheckState";
        // identifier "lteRrc_state" matches the prefix "LteRrc" -> Provisional emission.
        let string_addr = 0x40e22000;
        let g1 = 0x40e30000;
        let g2 = 0x40e31000;
        let string_map = HashMap::from([(
            string_addr,
            "lteRrc_state and otherModule_field are NULL".into(),
        )]);
        let disasm = "0x10: movw r0, 0x2000\n0x14: movt r0, 0x40e2\n\
             0x18: movw r1, 0x0000\n0x1c: movt r1, 0x40e3\n\
             0x20: movw r2, 0x1000\n0x24: movt r2, 0x40e3\n"
            .to_string();
        let events = symbolicate::reconstruct_load_events(&disasm);
        let mut func = sample_func(Arch::Arm, vec![string_addr, g1, g2]);
        func.recovered_name = Some("LteRrc_CheckState".into());
        let out = name_prior_provisional_for_function(&func, &string_map, &events, K_ARM);
        assert_eq!(out.len(), 1);
        let (addr, name, _, _) = &out[0];
        // Address is whichever global is nearest (by line-distance) to the string-load.
        assert!(*addr == g1 || *addr == g2);
        // Name shape: guess_<slug>_<addr_hex>. slug via symbolicate::slugify("lteRrc_state", None).
        let expected_slug = symbolicate::slugify("lteRrc_state", None);
        assert!(name.starts_with(&format!("{}{}", symbolicate::GUESS_PREFIX, expected_slug)));
        assert!(name.ends_with(&format!("_{:x}", addr)));
    }

    #[test]
    fn provisional_tier_dropped_when_name_prior_ambiguous() {
        // Two identifiers both start with the prefix -> name prior doesn't
        // disambiguate -> drop.
        let string_addr = 0x40e22000;
        let g1 = 0x40e30000;
        let g2 = 0x40e31000;
        let string_map =
            HashMap::from([(string_addr, "lteRrc_state and lteRrc_other are NULL".into())]);
        let disasm = "0x10: movw r0, 0x2000\n0x14: movt r0, 0x40e2\n\
             0x18: movw r1, 0x0000\n0x1c: movt r1, 0x40e3\n\
             0x20: movw r2, 0x1000\n0x24: movt r2, 0x40e3\n"
            .to_string();
        let events = symbolicate::reconstruct_load_events(&disasm);
        let mut func = sample_func(Arch::Arm, vec![string_addr, g1, g2]);
        func.recovered_name = Some("LteRrc_CheckState".into());
        let out = name_prior_provisional_for_function(&func, &string_map, &events, K_ARM);
        assert!(out.is_empty());
    }

    #[test]
    fn provisional_never_emitted_without_opt_in_flag() {
        // GlobalsOpts { include_provisional: false } -> no tier:"provisional" in
        // the serialized globals.json, but provisional_generated counts what
        // would have been emitted. End-to-end via run(); mirrors
        // provisional_tier_resolves_tie_via_name_prior over the ARM disasm slice.
        let img = Img::new("prov_no_opt");
        // load_addr near the string vaddr so the .bin stays small.
        img.write_manifest_load_addr("0x40e20000");
        let entry = 0x40e40000;
        let end = 0x40e40030;
        let string_addr = 0x40e22000u64;
        let g1 = 0x40e30000u64;
        let g2 = 0x40e31000u64;
        let func_json = serde_json::to_string(&vec![make_arm_function_range(
            entry,
            end,
            &[string_addr, g1, g2],
        )])
        .unwrap();
        img.write_functions_json(&func_json);
        img.write_thumb_functions_json(
            r#"{"format":"pixel-modem-extractor-thumb-functions-v2","functions":[]}"#,
        );
        // disasm.lst with PCs inside [entry, end) materializing the string and
        // two globals (same shape as the unit-test fixture).
        let disasm = "0x40e40010: movw r0, 0x2000\n0x40e40014: movt r0, 0x40e2\n\
                      0x40e40018: movw r1, 0x0000\n0x40e4001c: movt r1, 0x40e3\n\
                      0x40e40020: movw r2, 0x1000\n0x40e40024: movt r2, 0x40e3\n";
        fs::write(
            img.image_dir().join("decompiled").join("disasm.lst"),
            disasm,
        )
        .unwrap();
        img.write_image_bin(&image_with_strings_through(
            0x40e20000,
            &[(string_addr, "lteRrc_state and otherModule_field are NULL")],
            end,
        ));

        // recovered_function_names: entry canonical = lowercase hex, no 0x.
        let mut names = HashMap::new();
        names.insert(format!("{entry:x}"), "LteRrc_CheckState".to_string());

        // Default opts: include_provisional = false.
        let report = run(
            &img.image_dir(),
            img.label(),
            &img.manifest(),
            &names,
            &GlobalsOpts::default(),
        )
        .unwrap();

        // provisional_generated counts regardless of the opt-in flag.
        assert_eq!(report.provisional_generated, 1);

        // No tier:"provisional" in the serialized globals.json.
        let v: serde_json::Value = serde_json::from_slice(
            &fs::read(img.image_dir().join("decompiled").join("globals.json")).unwrap(),
        )
        .unwrap();
        let provisional_in_file = v["globals"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|g| g["tier"] == "provisional")
            .count();
        assert_eq!(provisional_in_file, 0);
    }

    #[test]
    fn recovered_count_excludes_materialized_provisional() {
        // `provisional_suppressed` distinguishes "no Provisional generated"
        // from "generated but withheld/suppressed". Spec contract:
        //   generated == 0                       -> field absent (None)
        //   generated > 0, all withheld/dropped  -> Some(generated)
        //   generated > 0, all materialized      -> Some(0)
        // Same fixture shape as `provisional_never_emitted_without_opt_in_flag`
        // plus a strict-rule Recovered proposal at a different address. With
        // the opt-in enabled, both tiers materialize in globals.json but only
        // the Recovered entry belongs in report.recovered_count.
        let mk = |tag: &str, include_provisional: bool| {
            let img = Img::new(tag);
            img.write_manifest_load_addr("0x40e20000");
            let provisional_entry = 0x40e40000;
            let provisional_end = 0x40e40030;
            let provisional_string_addr = 0x40e22000u64;
            let provisional_target = 0x40e30000u64;
            let provisional_other = 0x40e31000u64;
            let recovered_entry = 0x40e50000;
            let recovered_end = 0x40e50030;
            let recovered_string_addr = 0x40e22500u64;
            let recovered_target = 0x40e32000u64;
            let func_json = serde_json::to_string(&vec![
                make_arm_function_range(
                    provisional_entry,
                    provisional_end,
                    &[
                        provisional_string_addr,
                        provisional_target,
                        provisional_other,
                    ],
                ),
                make_arm_function_range(
                    recovered_entry,
                    recovered_end,
                    &[recovered_string_addr, recovered_target],
                ),
            ])
            .unwrap();
            img.write_functions_json(&func_json);
            img.write_thumb_functions_json(
                r#"{"format":"pixel-modem-extractor-thumb-functions-v2","functions":[]}"#,
            );
            let disasm = "0x40e40010: movw r0, 0x2000\n0x40e40014: movt r0, 0x40e2\n\
                          0x40e40018: movw r1, 0x0000\n0x40e4001c: movt r1, 0x40e3\n\
                          0x40e40020: movw r2, 0x1000\n0x40e40024: movt r2, 0x40e3\n";
            fs::write(
                img.image_dir().join("decompiled").join("disasm.lst"),
                disasm,
            )
            .unwrap();
            img.write_image_bin(&image_with_strings_through(
                0x40e20000,
                &[
                    (
                        provisional_string_addr,
                        "lteRrc_state and otherModule_field are NULL",
                    ),
                    (recovered_string_addr, "g_recovered is NULL"),
                ],
                recovered_end,
            ));
            let mut names = HashMap::new();
            names.insert(
                format!("{provisional_entry:x}"),
                "LteRrc_CheckState".to_string(),
            );
            let report = run(
                &img.image_dir(),
                img.label(),
                &img.manifest(),
                &names,
                &GlobalsOpts {
                    include_provisional,
                    ..GlobalsOpts::default()
                },
            )
            .unwrap();
            let v: serde_json::Value = serde_json::from_slice(
                &fs::read(img.image_dir().join("decompiled").join("globals.json")).unwrap(),
            )
            .unwrap();
            (report, v)
        };

        // Withheld (default opts): one Provisional generated, none materialized.
        let (report_out, v_out) = mk("prov_suppressed_out", false);
        assert_eq!(report_out.recovered_count, 1);
        assert_eq!(report_out.provisional_generated, 1);
        assert_eq!(v_out["provisional_suppressed"], 1);

        // Opt-in: one Provisional generated, one materialized -> Some(0).
        let (report_in, v_in) = mk("prov_suppressed_in", true);
        assert_eq!(report_in.recovered_count, 1);
        assert_eq!(report_in.provisional_generated, 1);
        assert_eq!(v_in["provisional_suppressed"], 0);
        let globals_file = &v_in;
        assert_eq!(globals_file["globals"].as_array().unwrap().len(), 2);
        assert_eq!(
            globals_file["globals"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|global| global["tier"] == "recovered")
                .count(),
            1
        );
        assert_eq!(
            globals_file["globals"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|global| global["tier"] == "provisional")
                .count(),
            1
        );
    }

    #[test]
    fn recovered_beats_provisional_at_same_address() {
        // Cross-tier precedence: one function contributes a Recovered
        // (addr, "g_foo") via Phase 3.0 strict-rule; another contributes a
        // Provisional (addr, "guess_..._addr") via the name-prior path. The
        // Recovered wins; the Provisional is suppressed and counted in
        // `provisional_suppressed_by_recovered`. `conflicts_dropped` stays 0.
        let img = Img::new("x_tier");
        img.write_manifest_load_addr("0x40e20000");

        let string_addr_r = 0x40e22000u64; // "g_foo is NULL" (1 identifier)
        let string_addr_p = 0x40e22500u64; // 2 identifiers, name-prior residue
        let g_target = 0x40e30000u64; // shared addr: Recovered and Provisional
        let g_other = 0x40e31000u64; // 2nd global in Provisional fn's window

        let entry_r = 0x40e40000; // strict-rule only; no disasm needed
        let end_r = 0x40e40030;
        let entry_p = 0x40e50000; // needs disasm for the Provisional pass
        let end_p = 0x40e50030;

        let func_json = serde_json::to_string(&vec![
            make_arm_function_range(entry_r, end_r, &[string_addr_r, g_target]),
            make_arm_function_range(entry_p, end_p, &[string_addr_p, g_target, g_other]),
        ])
        .unwrap();
        img.write_functions_json(&func_json);
        img.write_thumb_functions_json(
            r#"{"format":"pixel-modem-extractor-thumb-functions-v2","functions":[]}"#,
        );

        // disasm.lst with PCs inside [entry_p, end_p) materializing the
        // Provisional string-load + two global-loads (g_target nearer than
        // g_other by load-event-index distance → g_target is selected).
        let disasm = "0x40e50010: movw r0, 0x2500\n0x40e50014: movt r0, 0x40e2\n\
             0x40e50018: movw r1, 0x0000\n0x40e5001c: movt r1, 0x40e3\n\
             0x40e50020: movw r2, 0x1000\n0x40e50024: movt r2, 0x40e3\n"
            .to_string();
        fs::write(
            img.image_dir().join("decompiled").join("disasm.lst"),
            disasm,
        )
        .unwrap();

        img.write_image_bin(&image_with_strings_through(
            0x40e20000,
            &[
                (string_addr_r, "g_foo is NULL"),
                (string_addr_p, "lteRrc_state and otherModule_field are NULL"),
            ],
            end_p,
        ));

        // recovered_function_names: only the Provisional fn needs a name prior.
        // Canonical key is lowercase hex of entry, no 0x.
        let mut names = HashMap::new();
        names.insert(format!("{entry_p:x}"), "LteRrc_CheckState".to_string());

        let report = run(
            &img.image_dir(),
            img.label(),
            &img.manifest(),
            &names,
            &GlobalsOpts::default(),
        )
        .unwrap();

        // Recovered wins; Provisional suppressed.
        assert_eq!(report.recovered_count, 1);
        assert_eq!(report.conflicts_dropped, 0);
        assert_eq!(report.provisional_suppressed_by_recovered, 1);

        let v: serde_json::Value = serde_json::from_slice(
            &fs::read(img.image_dir().join("decompiled").join("globals.json")).unwrap(),
        )
        .unwrap();
        let globals = v["globals"].as_array().unwrap();
        assert_eq!(globals.len(), 1);
        assert_eq!(globals[0]["tier"], "recovered");
        assert_eq!(globals[0]["name"], "g_foo");
        assert_eq!(globals[0]["address"], format!("0x{g_target:x}"));
    }

    #[test]
    fn same_tier_conflict_drops_both_provisional() {
        // Two functions each emit a Provisional at the same addr with
        // different names (different identifier slugs). The Phase 3.0 strict-
        // drop rule extended to the Provisional tier: both drop,
        // `conflicts_dropped` increments, `provisional_suppressed_by_recovered`
        // stays 0 (no Recovered involved).
        let img = Img::new("prov_conflict");
        img.write_manifest_load_addr("0x40e20000");

        let string_addr_a = 0x40e22000u64;
        let string_addr_b = 0x40e22500u64;
        let g_shared = 0x40e30000u64; // both Provisionals target this addr
        let g_other_a = 0x40e31000u64;
        let g_other_b = 0x40e32000u64;

        let entry_a = 0x40e40000;
        let end_a = 0x40e40040;
        let entry_b = 0x40e50000;
        let end_b = 0x40e50040;

        let func_json = serde_json::to_string(&vec![
            make_arm_function_range(entry_a, end_a, &[string_addr_a, g_shared, g_other_a]),
            make_arm_function_range(entry_b, end_b, &[string_addr_b, g_shared, g_other_b]),
        ])
        .unwrap();
        img.write_functions_json(&func_json);
        img.write_thumb_functions_json(
            r#"{"format":"pixel-modem-extractor-thumb-functions-v2","functions":[]}"#,
        );

        // disasm.lst with both functions' instruction PCs. Each fn loads its
        // string and two globals; g_shared is the nearer global in each fn.
        let disasm = "0x40e40010: movw r0, 0x2000\n0x40e40014: movt r0, 0x40e2\n\
             0x40e40018: movw r1, 0x0000\n0x40e4001c: movt r1, 0x40e3\n\
             0x40e40020: movw r2, 0x1000\n0x40e40024: movt r2, 0x40e3\n\
             0x40e50010: movw r0, 0x2500\n0x40e50014: movt r0, 0x40e2\n\
             0x40e50018: movw r1, 0x0000\n0x40e5001c: movt r1, 0x40e3\n\
             0x40e50020: movw r2, 0x2000\n0x40e50024: movt r2, 0x40e3\n"
            .to_string();
        fs::write(
            img.image_dir().join("decompiled").join("disasm.lst"),
            disasm,
        )
        .unwrap();

        img.write_image_bin(&image_with_strings_through(
            0x40e20000,
            &[
                (string_addr_a, "lteRrc_state and otherModule_field are NULL"),
                (
                    string_addr_b,
                    "barModule_thing and otherModule_field are NULL",
                ),
            ],
            end_b,
        ));

        // Each fn gets a matching module prefix so its identifier prefix-matches.
        let mut names = HashMap::new();
        names.insert(format!("{entry_a:x}"), "LteRrc_CheckState".to_string());
        names.insert(format!("{entry_b:x}"), "BarModule_Handle".to_string());

        let report = run(
            &img.image_dir(),
            img.label(),
            &img.manifest(),
            &names,
            &GlobalsOpts::default(),
        )
        .unwrap();

        // Both Provisionals drop as a same-tier conflict; no Recovered involved.
        assert_eq!(report.recovered_count, 0);
        assert_eq!(report.conflicts_dropped, 1);
        assert_eq!(report.provisional_suppressed_by_recovered, 0);

        let v: serde_json::Value = serde_json::from_slice(
            &fs::read(img.image_dir().join("decompiled").join("globals.json")).unwrap(),
        )
        .unwrap();
        assert!(v["globals"].as_array().unwrap().is_empty());
    }

    #[test]
    fn surface_3_0_1_a_writes_phase3_0_content_with_error_when_disasm_missing() {
        // Fixture: Phase 3.0 inputs present (functions.json + thumb_functions.json
        // + .bin) but NO disasm.lst (Phase 3.0.1 input absent). Phase 3.0 strict-
        // rule path still emits; `phase3_0_1_error` is set so consumers can
        // distinguish "ran and found nothing" from "couldn't run".
        let img = Img::new("surface_3_0_1_a_missing_disasm");
        img.write_functions_json(&format!(
            "[{}]",
            make_arm_function(0x2000, &[0x3000, 0x4000])
        ));
        img.write_thumb_functions_json(
            r#"{"format":"pixel-modem-extractor-thumb-functions-v2","functions":[]}"#,
        );
        img.write_manifest_load_addr("0x1000");
        img.write_image_bin(&image_with_strings(0x1000, &[(0x3000, "g_foo invalid")]));
        // Intentionally no disasm.lst.

        let report = run_no_names(&img).unwrap();
        assert!(report.recovered_count > 0);
        assert_eq!(report.provisional_generated, 0);

        let v: serde_json::Value = serde_json::from_slice(
            &fs::read(img.image_dir().join("decompiled").join("globals.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(v["globals"].as_array().unwrap().len(), 1);
        let err = v["phase3_0_1_error"].as_str().unwrap();
        assert!(
            err.contains("disasm"),
            "expected phase3_0_1_error to mention disasm; got: {err}"
        );
        // Phase 3.0's field stays absent — it ran cleanly.
        assert!(
            v.get("globals_error").is_none(),
            "Phase 3.0 globals_error must be absent when Phase 3.0 ran cleanly"
        );
        // No Provisional generated -> field absent.
        assert!(v.get("provisional_suppressed").is_none());
    }

    #[test]
    fn surface_3_0_1_a_emits_no_globalload_evidence_when_disasm_missing() {
        // Same fixture; no emitted global carries GlobalLoad or StringLoad
        // evidence (Phase 3.0-only evidence shape). Regression sentinel.
        let img = Img::new("surface_3_0_1_a_no_globalload");
        img.write_functions_json(&format!(
            "[{}]",
            make_arm_function(0x2000, &[0x3000, 0x4000])
        ));
        img.write_thumb_functions_json(
            r#"{"format":"pixel-modem-extractor-thumb-functions-v2","functions":[]}"#,
        );
        img.write_manifest_load_addr("0x1000");
        img.write_image_bin(&image_with_strings(0x1000, &[(0x3000, "g_foo invalid")]));
        // Intentionally no disasm.lst.

        let _ = run_no_names(&img).unwrap();

        let v: serde_json::Value = serde_json::from_slice(
            &fs::read(img.image_dir().join("decompiled").join("globals.json")).unwrap(),
        )
        .unwrap();
        let globals = v["globals"].as_array().unwrap();
        assert!(!globals.is_empty());
        for g in globals {
            let kinds: Vec<&str> = g["evidence"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|e| e["kind"].as_str())
                .collect();
            assert!(
                !kinds
                    .iter()
                    .any(|k| *k == "global_load" || *k == "string_load"),
                "Phase 3.0-only evidence shape expected; got kinds: {kinds:?}"
            );
        }
    }
}
