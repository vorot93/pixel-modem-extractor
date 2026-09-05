//! Symbolicate the decompiled modem: recover function names and inline
//! log/assert/file annotations from evidence the pipeline already produces
//! (the pw_tokenizer DB, `__func__` strings, attributed strings, existing
//! attribution), then rewrite the artifacts in place + emit `symbols.json`.
//! Pure-Rust; ARM and Thumb. Fail-closed and tiered. Two evidence sources yield
//! a real (`Recovered`) name: `__func__`, a `{name, fn}` registration table
//! whose pointer resolves to a known function entry (see
//! `symbolicate/reg_table.rs`), an authenticated exception root, or a PAL task.
//! A token or a uniquely-referenced identifier string yields a marked
//! `guess_…` name (`Provisional`). Provisional names are never applied to
//! Ghidra as an authoritative (`USER_DEFINED`) symbol;
//! string-ref guesses specifically are computed only by the post-globals
//! finalize rewrite, so they never even appear in Ghidra's pass-2 input.
//! Registration names, being `Recovered`, are computed at the symbol_map stage
//! and therefore *do* reach Ghidra pass 2. Everything else is a comment.
//! Precedence from strongest to weakest: `__func__`, registration, ss,
//! exception_root, pal_task, startup, token, string-ref.
//! See `symbolicate/name_guess.rs` for the string-reference classifier.
use crate::decompile::{ExceptionApplicationRef, ExceptionDispositionKind, ExceptionPrimaryRef};
use crate::disasm_index::DisasmIndex;
use crate::error::{Error, Result};
pub use crate::execution_ranges::DecodeIsa;
use crate::execution_ranges::{ExecutionIdentity, FunctionEvidenceKey, FunctionOwner};
use crate::recover_source::{Confidence, Tool};
use crate::runtime_image::RuntimeImage;
use crate::trusted_fs::TrustedDirectory;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

pub mod name_guess;
pub mod reg_table;
pub(crate) mod role_evidence;
pub mod ss;
pub use crate::decompile::ExceptionPass2Context;

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

/// `symbols.json` format tag (v5 adds authenticated startup-metadata evidence).
pub const SYMBOLS_FORMAT: &str = "pixel-modem-extractor-symbols-v5";

/// Strict pass-2 map format name shared with the Java reader.
pub const SYMBOL_MAP_FORMAT: &str = "pixel-modem-extractor-symbol-map-v5";

/// Interface limits for the strict map (mirrored by `PalTasksSupport.java`).
pub const MAX_MAP_ANNOTATIONS_PER_DECISION: usize = 256;

/// Upper bound on creation entries in one pass-2 symbol map. The measured
/// corpus peak is ~4.2k (mustang MAIN, all tiers); the bound leaves 15x
/// headroom while keeping a malformed map bounded.
pub const MAX_MAP_CREATIONS: usize = 65_536;
pub const MAX_MAP_ANNOTATION_UTF8_BYTES: usize = 4096;
pub const MAX_MAP_ANNOTATION_AGGREGATE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_PRIMARY_CHARS: usize = 2000;

/// Explicit naming authority. Lower rank (ordinal) is stronger; the order is
/// the pinned precedence: `__func__`, registration, ss, exception_root, pal_task,
/// startup, token, string_ref. `file` and `dbt_source` evidence are annotation-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Authority {
    Func,
    Registration,
    Ss,
    ExceptionRoot,
    PalTask,
    Startup,
    Token,
    StringRef,
}

impl Authority {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Func => "func",
            Self::Registration => "registration",
            Self::Ss => "ss",
            Self::ExceptionRoot => "exception_root",
            Self::PalTask => "pal_task",
            Self::Startup => "startup",
            Self::Token => "token",
            Self::StringRef => "string_ref",
        }
    }
}

/// One firmware task attached to a function entry, as evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PalTaskRef {
    pub manifest_blake3: String,
    pub task_index: u32,
    pub name: String,
    pub slot: u32,
    pub priority: u8,
    pub stack_size: u32,
}

/// One PAL application group at a normalized entry: the desired primary plus
/// every attached task (role identities, in table order). Whether PAL owns a
/// retained primary is derived per Ghidra record from exact name equality.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PalApplicationRef {
    /// The application's declared ISA ("arm" | "thumb"): only records in the
    /// same ISA at this entry carry the evidence.
    pub isa: &'static str,
    pub desired_primary: String,
    pub tasks: Vec<PalTaskRef>,
}

/// The PAL state a pass-2 map binds: identity, dependency hashes, and the
/// application groups keyed by normalized entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PalPass2Context {
    pub identity: String,
    pub manifest_blake3: String,
    pub scatter_load_map_blake3: Option<String>,
    pub applications: BTreeMap<u32, PalApplicationRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExceptionRoleRef {
    table_kind: &'static str,
    table_address: u32,
    slot_address: u32,
    role: &'static str,
}

impl ExceptionRoleRef {
    const fn table_kind(&self) -> &'static str {
        self.table_kind
    }

    const fn table_address(&self) -> u32 {
        self.table_address
    }

    const fn slot_address(&self) -> u32 {
        self.slot_address
    }

    const fn role(&self) -> &'static str {
        self.role
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExceptionRoleRefSet {
    desired_primary: Option<String>,
    roles: Vec<ExceptionRoleRef>,
}

impl ExceptionRoleRefSet {
    fn from_role_application(application: &role_evidence::ExceptionRoleApplication) -> Self {
        Self {
            desired_primary: application.desired_primary().map(str::to_owned),
            roles: application
                .claims()
                .iter()
                .map(|claim| ExceptionRoleRef {
                    table_kind: claim.table_kind(),
                    table_address: claim.table_address(),
                    slot_address: claim.slot_address(),
                    role: claim.role(),
                })
                .collect(),
        }
    }

    #[cfg(test)]
    pub(crate) fn from_pass2(application: &ExceptionApplicationRef) -> Self {
        Self {
            desired_primary: application.desired_primary().map(str::to_owned),
            roles: application
                .roles()
                .iter()
                .map(|role| ExceptionRoleRef {
                    table_kind: role.table_kind(),
                    table_address: role.table_address(),
                    slot_address: role.slot_address(),
                    role: role.role(),
                })
                .collect(),
        }
    }

    fn desired_primary(&self) -> Option<&str> {
        self.desired_primary.as_deref()
    }

    fn roles(&self) -> &[ExceptionRoleRef] {
        &self.roles
    }

    fn matches_pass2(&self, application: &ExceptionApplicationRef) -> bool {
        self.desired_primary() == application.desired_primary()
            && self.roles.len() == application.roles().len()
            && self
                .roles
                .iter()
                .zip(application.roles())
                .all(|(role, applied)| {
                    role.table_kind() == applied.table_kind()
                        && role.table_address() == applied.table_address()
                        && role.slot_address() == applied.slot_address()
                        && role.role() == applied.role()
                })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PalRoleRefSet {
    desired_primary: String,
    tasks: Vec<PalTaskRef>,
}

impl PalRoleRefSet {
    fn from_role_application(
        application: &role_evidence::PalRoleApplication,
        manifest_blake3: [u8; 32],
    ) -> Self {
        Self {
            desired_primary: application.desired_primary().to_string(),
            tasks: application
                .tasks()
                .iter()
                .map(|task| PalTaskRef {
                    manifest_blake3: crate::manifest::blake3_fixed(manifest_blake3),
                    task_index: task.task_index(),
                    name: task.name().to_string(),
                    slot: task.slot(),
                    priority: task.priority(),
                    stack_size: task.stack_size(),
                })
                .collect(),
        }
    }

    #[cfg(test)]
    pub(crate) fn from_pass2(application: &PalApplicationRef) -> Self {
        Self {
            desired_primary: application.desired_primary.clone(),
            tasks: application.tasks.clone(),
        }
    }

    fn matches_pass2(&self, application: &PalApplicationRef) -> bool {
        self.desired_primary == application.desired_primary && self.tasks == application.tasks
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StartupRoleRefSet {
    desired_primary: String,
    role: &'static str,
    set_no_return: bool,
}

impl StartupRoleRefSet {
    fn from_role_application(application: &role_evidence::StartupRoleApplication) -> Self {
        Self {
            desired_primary: application.desired_primary().to_string(),
            role: application.role(),
            set_no_return: application.set_no_return(),
        }
    }

    #[cfg(test)]
    pub(crate) fn from_test(primary: &str, role: &'static str, set_no_return: bool) -> Self {
        Self {
            desired_primary: primary.to_string(),
            role,
            set_no_return,
        }
    }

    fn desired_primary(&self) -> &str {
        &self.desired_primary
    }

    fn role(&self) -> &'static str {
        self.role
    }

    fn set_no_return(&self) -> bool {
        self.set_no_return
    }
}

/// Tagged evidence variant. Every kind serializes with a `kind` tag plus its
/// own exact fields — no bag of unrelated optional members.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TaggedEvidence {
    Func {
        value: String,
    },
    Registration {
        value: String,
    },
    Ss {
        value: String,
    },
    ExceptionRoot {
        manifest_blake3: String,
        table_kind: &'static str,
        table_address: u32,
        slot_address: u32,
        role: &'static str,
    },
    PalTask {
        #[serde(flatten)]
        task: PalTaskRef,
    },
    Startup {
        manifest_blake3: String,
        role: &'static str,
        set_no_return: bool,
    },
    Token {
        token: String,
        format: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        domain: Option<String>,
    },
    File {
        path: String,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        strings: Vec<String>,
    },
    DbtSource {
        path: String,
    },
    StringRef {
        value: String,
        class: &'static str,
    },
}

impl TaggedEvidence {
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Func { .. } => "func",
            Self::Registration { .. } => "registration",
            Self::Ss { .. } => "ss",
            Self::ExceptionRoot { .. } => "exception_root",
            Self::PalTask { .. } => "pal_task",
            Self::Startup { .. } => "startup",
            Self::Token { .. } => "token",
            Self::File { .. } => "file",
            Self::DbtSource { .. } => "dbt_source",
            Self::StringRef { .. } => "string_ref",
        }
    }
}

/// One unresolved same-rank naming candidate: no name was applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NameConflict {
    pub authority: Authority,
    pub kind: &'static str,
    pub proposed_name: String,
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
    /// Validated execution identity digest for the record this symbol
    /// describes, when the record carries an accepted decode projection.
    /// Serialized as lowercase hex so `symbols.json` binds the symbol to its
    /// exact execution identity.
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_execution_digest"
    )]
    pub(crate) execution_blake3: Option<[u8; 32]>,
    /// The record's validated decode ranges (empty when absent/unaccepted).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub decode_ranges: Vec<DecodeRangeWire>,
    pub original_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub tier: Tier,
    pub evidence: Vec<TaggedEvidence>,
    pub annotations: Vec<String>,
    /// Same-rank unresolved naming candidates; empty when one ranked decision
    /// exists. No name is applied while this is non-empty.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub name_conflicts: Vec<NameConflict>,
}

impl Symbol {
    /// The record's actual decode ISA from its first validated decode range.
    /// Every Ghidra `functions.json` record carries the family label
    /// `arch: "arm"` regardless of Thumb decode ranges, so PAL application
    /// ISA matching must use this, not `arch`.
    pub fn decode_isa(&self) -> &str {
        self.decode_ranges.first().map_or(self.arch, |r| r.isa)
    }
}

/// One validated decode range as serialized in `symbols.json` and the strict
/// pass-2 map: exact ISA, u32 bounds, and lowercase BLAKE3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecodeRangeWire {
    pub isa: &'static str,
    pub start: String,
    pub end: String,
    pub blake3: String,
}

impl DecodeRangeWire {
    fn from_authenticated(range: &crate::execution_ranges::AuthenticatedDecodeRange) -> Self {
        Self {
            isa: match range.isa {
                crate::execution_ranges::DecodeIsa::Arm => "arm",
                crate::execution_ranges::DecodeIsa::Thumb => "thumb",
            },
            start: format!("0x{:08x}", range.start),
            end: format!("0x{:08x}", range.end),
            blake3: crate::manifest::blake3_fixed(range.blake3),
        }
    }
}

fn serialize_execution_digest<S: serde::Serializer>(
    digest: &Option<[u8; 32]>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    match digest {
        Some(digest) => serializer.serialize_str(&crate::manifest::blake3_fixed(*digest)),
        None => serializer.serialize_none(),
    }
}

pub(crate) struct RawEvidence {
    pub(crate) func_name: Option<String>,  // __func__ ground truth
    pub(crate) tokens: Vec<(u32, String)>, // (token, raw DB string)
    pub(crate) file: Option<String>,       // attributed source path
    pub(crate) file_strings: Vec<String>,  // that file's attributed_strings
    /// Distinct source paths attributed to this function by exact DBT trace
    /// attribution (`Confidence::DbtExact`), sorted. Annotation-only like
    /// `file`; `decide` caps the evidence/annotation pairs at six.
    pub(crate) dbt_sources: Vec<String>,
    pub(crate) ident_guess: Option<(String, name_guess::Class)>, // string_ref_guess output
    /// Authoritative name recovered from a `{name, fn}` registration table
    /// (`reg_table::scan`). Outranks exception_root, pal_task, token, and
    /// string-ref; only `__func__` wins.
    pub(crate) registration: Option<String>,
    /// Recovered `ss_*` name from a unique helper-callsite argument.
    /// Outranked by `__func__` and registration; outranks token and string-ref.
    pub(crate) ss: Option<String>,
    /// Manifest identity attached separately from the role-only projection.
    pub(crate) exception_manifest_blake3: Option<String>,
    /// The authenticated exception application at this exact entry and decode
    /// ISA. Occupies the `exception_root` authority rank.
    pub(crate) exception: Option<ExceptionRoleRefSet>,
    /// The exception primary proposed for this build purpose. Absence leaves
    /// the authenticated role rank as an empty blocker.
    pub(crate) exception_proposed_primary: Option<String>,
    /// The PAL application at this entry, when the PAL task manifest claims
    /// it. Occupies the `pal_task` authority rank.
    pub(crate) pal: Option<PalRoleRefSet>,
    /// The PAL primary proposed for this build purpose. Absence leaves the
    /// authenticated role rank as an empty blocker.
    pub(crate) pal_proposed_primary: Option<String>,
    /// Manifest identity attached separately from the role-only projection.
    pub(crate) startup_manifest_blake3: Option<String>,
    /// The authenticated startup application at this exact entry and decode
    /// ISA. Occupies the `startup` authority rank.
    pub(crate) startup: Option<StartupRoleRefSet>,
    /// The startup primary proposed for this build purpose. Absence leaves
    /// the authenticated role rank as an empty blocker.
    pub(crate) startup_proposed_primary: Option<String>,
}

/// One function to symbolicate (unifies ARM + Thumb).
pub struct FuncRec<'a> {
    pub arch: &'static str, // "arm" | "thumb"
    pub name: String,       // stable original, e.g. "FUN_40e1bff4"
    /// Primary currently carried by this concrete producer record. This can
    /// differ from `name` after an earlier idempotent symbolication rewrite.
    pub current_primary: String,
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
    pub(crate) execution: Option<ExecutionIdentity>,
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

/// One ranked naming candidate derived from the evidence.
struct NameCandidate {
    authority: Authority,
    kind: &'static str,
    proposed_name: String,
}

/// Apply the ranked, fail-closed naming policy for one function. Ranks are
/// the pinned precedence: `__func__`, registration, ss, exception_root, pal_task,
/// startup, token, string_ref. The strongest rank with a proposal wins and every weaker
/// candidate is retained as evidence. Two distinct names at the winning rank
/// apply neither: the sorted candidates are serialized as `name_conflicts`.
/// Shared exception/task roles and preserved role primaries block every weaker
/// rank while proposing no name of their own. Returns
/// `(name, tier, evidence, annotations, conflicts)`. `addr_hex` is bare, for
/// example `"40e1bff4"`.
#[allow(clippy::type_complexity)]
pub(crate) fn decide(
    addr_hex: &str,
    raw: &RawEvidence,
) -> (
    Option<String>,
    Tier,
    Vec<TaggedEvidence>,
    Vec<String>,
    Vec<NameConflict>,
) {
    let mut ev = Vec::new();
    let mut ann = Vec::new();
    let mut candidates: Vec<NameCandidate> = Vec::new();

    for (tok, s) in &raw.tokens {
        let (fmt, dom) = parse_token_string(s);
        ev.push(TaggedEvidence::Token {
            token: format!("0x{tok:08x}"),
            format: fmt.clone(),
            domain: dom.clone(),
        });
        ann.push(match &dom {
            Some(d) => format!("logs: {fmt:?} [{d}]"),
            None => format!("logs: {fmt:?}"),
        });
        let name = format!("{GUESS_PREFIX}{}_{addr_hex}", slugify(&fmt, dom.as_deref()));
        candidates.push(NameCandidate {
            authority: Authority::Token,
            kind: "token",
            proposed_name: name,
        });
    }
    if let Some(f) = &raw.file {
        ev.push(TaggedEvidence::File {
            path: f.clone(),
            strings: raw.file_strings.clone(),
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
    // DBT-exact source attribution is annotation-only, like `file` evidence:
    // it proposes no name and occupies no rank, so naming precedence is
    // untouched. Mirrors the file-strings take(6) bound: at most six
    // evidence/annotation pairs survive regardless of what the producer put
    // in `dbt_sources`.
    for path in raw.dbt_sources.iter().take(6) {
        ev.push(TaggedEvidence::DbtSource { path: path.clone() });
        ann.push(format!("dbt-source: {path}"));
    }

    // Registration evidence is always recorded (even when `__func__` outranks
    // it for the name), so the table provenance survives in `symbols.json`.
    if let Some(reg) = &raw.registration {
        ev.push(TaggedEvidence::Registration { value: reg.clone() });
        ann.push(format!("registration: {reg:?}"));
    }

    // Exception role evidence is retained in manifest table/slot order. An
    // applied preferred primary re-proposes its architectural name; a shared
    // or preserved application contributes a blocking rank with no proposal.
    // Missing manifest identity makes the whole source ineligible rather than
    // producing unauthenticated evidence.
    if let (Some(manifest_blake3), Some(app)) = (&raw.exception_manifest_blake3, &raw.exception) {
        for role in app.roles() {
            ev.push(TaggedEvidence::ExceptionRoot {
                manifest_blake3: manifest_blake3.clone(),
                table_kind: role.table_kind(),
                table_address: role.table_address(),
                slot_address: role.slot_address(),
                role: role.role(),
            });
            ann.push(format!(
                "exception root: {} table={}@{:#010x} slot={:#010x}",
                role.role(),
                role.table_kind(),
                role.table_address(),
                role.slot_address()
            ));
        }
        candidates.push(NameCandidate {
            authority: Authority::ExceptionRoot,
            kind: "exception_root",
            proposed_name: raw.exception_proposed_primary.clone().unwrap_or_default(),
        });
    }

    // PAL task evidence: one variant plus one annotation line per attached
    // task, retained regardless of which rank wins the name.
    if let Some(app) = &raw.pal {
        for task in &app.tasks {
            ev.push(TaggedEvidence::PalTask { task: task.clone() });
            ann.push(format!(
                "pal task: {} slot={:#010x} priority={} stack={}",
                task.name, task.slot, task.priority, task.stack_size
            ));
        }
        // A single-task application whose desired primary is current may
        // re-propose it. Shared or preserved entries still occupy this rank
        // with an empty proposal, blocking token/string-ref guesses.
        candidates.push(NameCandidate {
            authority: Authority::PalTask,
            kind: "pal_task",
            proposed_name: raw.pal_proposed_primary.clone().unwrap_or_default(),
        });
    }

    if let (Some(manifest_blake3), Some(app)) = (&raw.startup_manifest_blake3, &raw.startup) {
        ev.push(TaggedEvidence::Startup {
            manifest_blake3: manifest_blake3.clone(),
            role: app.role(),
            set_no_return: app.set_no_return(),
        });
        ann.push(format!(
            "startup: {} no_return={}",
            app.role(),
            app.set_no_return()
        ));
        candidates.push(NameCandidate {
            authority: Authority::Startup,
            kind: "startup",
            proposed_name: raw.startup_proposed_primary.clone().unwrap_or_default(),
        });
    }

    if let Some(fname) = &raw.func_name {
        ev.insert(
            0,
            TaggedEvidence::Func {
                value: fname.clone(),
            },
        );
        candidates.insert(
            0,
            NameCandidate {
                authority: Authority::Func,
                kind: "func",
                proposed_name: sanitize_ident(fname),
            },
        );
    }
    if let Some(reg) = &raw.registration {
        candidates.push(NameCandidate {
            authority: Authority::Registration,
            kind: "registration",
            proposed_name: sanitize_ident(reg),
        });
    }
    if let Some(ss) = &raw.ss {
        ev.push(TaggedEvidence::Ss { value: ss.clone() });
        candidates.push(NameCandidate {
            authority: Authority::Ss,
            kind: "ss",
            proposed_name: sanitize_ident(ss),
        });
    }
    if let Some((id, class)) = &raw.ident_guess {
        ev.push(TaggedEvidence::StringRef {
            value: id.clone(),
            class: class.as_str(),
        });
        ann.push(match class {
            name_guess::Class::TypeLabel => format!("handles-type: {id:?}"),
            name_guess::Class::FnName => format!("ident-ref: {id:?}"),
        });
        candidates.push(NameCandidate {
            authority: Authority::StringRef,
            kind: "string_ref",
            proposed_name: format!("{GUESS_PREFIX}{}_{addr_hex}", sanitize_ident(id)),
        });
    }

    // Resolve by rank. Duplicate proposals at one rank collapse; distinct
    // proposals at the winning rank are an unresolved conflict. Role evidence
    // may contribute an empty rank that blocks weaker guesses without naming.
    candidates.sort_by_key(|candidate| candidate.authority);
    let mut by_rank: Vec<(Authority, Vec<NameCandidate>)> = Vec::new();
    for candidate in candidates {
        if candidate.proposed_name.is_empty() {
            // The blocking marker contributes its rank but never a proposal.
            match by_rank.last_mut() {
                Some((authority, _)) if *authority == candidate.authority => {}
                _ => by_rank.push((candidate.authority, Vec::new())),
            }
            continue;
        }
        match by_rank.last_mut() {
            Some((authority, group)) if *authority == candidate.authority => {
                if !group
                    .iter()
                    .any(|existing| existing.proposed_name == candidate.proposed_name)
                {
                    group.push(candidate);
                }
            }
            _ => by_rank.push((candidate.authority, vec![candidate])),
        }
    }

    let Some((authority, group)) = by_rank.first() else {
        return (None, Tier::None, ev, ann, Vec::new());
    };
    if group.is_empty() {
        // A blocking role rank with no proposal: no name.
        return (None, Tier::None, ev, ann, Vec::new());
    }
    if group.len() > 1 {
        let mut conflicts: Vec<NameConflict> = group
            .iter()
            .map(|candidate| NameConflict {
                authority: *authority,
                kind: candidate.kind,
                proposed_name: candidate.proposed_name.clone(),
            })
            .collect();
        conflicts.sort_by(|a, b| {
            (a.authority, a.kind, &a.proposed_name).cmp(&(b.authority, b.kind, &b.proposed_name))
        });
        return (None, Tier::None, ev, ann, conflicts);
    }
    let winner = &group[0];
    let name = winner.proposed_name.clone();
    let tier = match winner.authority {
        Authority::Func
        | Authority::Registration
        | Authority::Ss
        | Authority::ExceptionRoot
        | Authority::PalTask
        | Authority::Startup => Tier::Recovered,
        Authority::Token | Authority::StringRef => Tier::Provisional,
    };
    (Some(name), tier, ev, ann, Vec::new())
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

fn load_functions_file<'a>(
    functions: File,
    index: &DisasmIndex<'a>,
    runtime: &crate::runtime_image::RuntimeImage<'_>,
) -> Result<Vec<FuncRec<'a>>> {
    let streamed = crate::execution_ranges::read_ghidra_inventory_file(functions, runtime)?;
    let mut out = Vec::with_capacity(streamed.functions.len());
    for record in streamed.functions {
        let entry = u64::from(record.entry);
        let end = u64::from(record.end);
        let execution = crate::execution_ranges::execution_identity(
            record.tagged.entry,
            &record.tagged.projection,
        )?;
        let data_refs = record
            .data_refs
            .iter()
            .map(|address| u64::from(*address))
            .collect();
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
        let current_primary = record.name;
        let name = record
            .original_name
            .unwrap_or_else(|| current_primary.clone());
        out.push(FuncRec {
            arch: "arm",
            name,
            current_primary,
            entry,
            end,
            data_refs,
            disasm,
            tool: Tool::Ghidra,
            owner: FunctionOwner::Ghidra,
            execution,
        });
    }
    Ok(out)
}

#[cfg(test)]
fn load_functions<'a>(
    decompiled: &Path,
    index: &DisasmIndex<'a>,
    runtime: &RuntimeImage<'_>,
) -> Result<Vec<FuncRec<'a>>> {
    load_functions_file(
        File::open(decompiled.join("functions.json"))?,
        index,
        runtime,
    )
}

#[cfg(test)]
fn thumb_runtime<'a>(
    image_dir: &Path,
    image: &'a [u8],
    load_addr: u64,
) -> Result<crate::runtime_image::RuntimeImage<'a>> {
    let start = u32::try_from(load_addr).map_err(|_| {
        Error::Serialize(
            "symbolicate: raw image mapping does not fit the canonical u32 domain".into(),
        )
    })?;
    crate::runtime_image::RuntimeImage::for_image_dir(image, start, image_dir)
}

fn load_thumb_functions_file<'a>(
    thumb_functions: File,
    runtime: &crate::runtime_image::RuntimeImage<'_>,
) -> Result<Vec<FuncRec<'a>>> {
    let functions = crate::thumb_analysis::read_thumb_functions_file(
        thumb_functions,
        runtime,
        "trusted Thumb functions inventory",
    )?;
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
        let current_primary = f.name;
        let name = f.original_name.unwrap_or_else(|| current_primary.clone());
        out.push(FuncRec {
            arch: "thumb",
            name,
            current_primary,
            entry,
            end,
            data_refs,
            disasm: std::borrow::Cow::Owned(f.body),
            tool: owned.owner.analysis_tool(),
            owner: owned.owner,
            execution: owned.execution,
        });
    }
    Ok(out)
}

#[cfg(test)]
fn load_thumb_functions<'a>(
    decompiled: &Path,
    runtime: &RuntimeImage<'_>,
) -> Result<Vec<FuncRec<'a>>> {
    load_thumb_functions_file(
        File::open(decompiled.join("thumb_functions.json"))?,
        runtime,
    )
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
#[cfg(test)]
fn load_file_occurrences(source_tree: &Path) -> Result<FileOccurrences> {
    let bytes = std::fs::read(source_tree.join("manifest.json"))?;
    load_file_occurrences_bytes(&bytes)
}

fn load_file_occurrences_bytes(bytes: &[u8]) -> Result<FileOccurrences> {
    let m: StManifest =
        serde_json::from_slice(bytes).map_err(|e| Error::Serialize(e.to_string()))?;
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
    confidence: Confidence,
}

/// One identity's winning source-path claim: the path plus the confidence
/// tier that won it (see `load_attribution`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct AttributionPath {
    path: String,
    confidence: Confidence,
}

fn tool_wire_name(tool: Tool) -> &'static str {
    match tool {
        Tool::Ghidra => "ghidra",
        Tool::Radare2 => "radare2",
        Tool::Rizin => "rizin",
    }
}

/// `(owner, entry-vaddr, execution digest) -> attributed source path` from
/// `recovered_index.json`. Distinct executions may claim the same entry. One
/// identity claiming several paths resolves by confidence rank: rows below
/// the strongest tier are dropped, and only a same-tier path conflict is a
/// hard failure (dbt_exact > direct > proximity). Returned as a `BTreeMap`
/// (not `HashMap`) so repeated loads and conflict path order are deterministic.
#[cfg(test)]
fn load_attribution(source_tree: &Path) -> Result<BTreeMap<FunctionEvidenceKey, AttributionPath>> {
    let path = source_tree.join("recovered_index.json");
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let bytes = std::fs::read(&path)?;
    load_attribution_bytes(&bytes)
}

fn load_attribution_bytes(bytes: &[u8]) -> Result<BTreeMap<FunctionEvidenceKey, AttributionPath>> {
    let idx: RiIndex =
        serde_json::from_slice(bytes).map_err(|e| Error::Serialize(e.to_string()))?;
    // Walk sources in path order so first-seen conflict path is stable.
    let sources: BTreeMap<String, RiSource> = idx.sources.into_iter().collect();
    let mut claims: BTreeMap<FunctionEvidenceKey, Vec<(String, Confidence, Tool)>> =
        BTreeMap::new();
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
                .map(crate::execution_ranges::parse_blake3)
                .transpose()?;
            let key = FunctionEvidenceKey {
                owner,
                entry,
                execution_blake3,
            };
            claims
                .entry(key)
                .or_default()
                .push((src.clone(), f.confidence, f.tool));
        }
    }
    let mut m = BTreeMap::new();
    for (key, rows) in claims {
        let top = rows
            .iter()
            .map(|(_, confidence, _)| *confidence)
            .max()
            .expect("at least one claim per identity");
        let top_paths: BTreeSet<&str> = rows
            .iter()
            .filter(|(_, confidence, _)| *confidence == top)
            .map(|(path, _, _)| path.as_str())
            .collect();
        if top_paths.len() > 1 {
            let ordered: Vec<&str> = top_paths.into_iter().collect();
            return Err(Error::DecomposeIncomplete(format!(
                "source attribution conflict for {} entry 0x{:x}: {:?} vs {:?}",
                tool_wire_name(rows[0].2),
                key.entry,
                ordered.first(),
                ordered.last()
            )));
        }
        let path = top_paths
            .into_iter()
            .next()
            .expect("one top-tier path")
            .to_string();
        m.insert(
            key,
            AttributionPath {
                path,
                confidence: top,
            },
        );
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
    format: &'static str,
    tool_version: &'static str,
    image: &'a str,
    inputs: HashMap<String, String>,
    counts: Counts,
    symbols: &'a [Symbol],
}

/// Write `symbols.json` into the image's `decompiled/` dir; return its path.
#[cfg(test)]
fn write_symbols_json(
    decompiled: &Path,
    image: &str,
    symbols: &[Symbol],
    inputs: HashMap<String, String>,
) -> Result<PathBuf> {
    let file = SymbolsFile {
        format: SYMBOLS_FORMAT,
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

fn write_symbols_json_trusted(
    decompiled: &TrustedDirectory,
    image: &str,
    symbols: &[Symbol],
    inputs: HashMap<String, String>,
) -> Result<()> {
    let file = SymbolsFile {
        format: SYMBOLS_FORMAT,
        tool_version: env!("CARGO_PKG_VERSION"),
        image,
        inputs,
        counts: counts(symbols),
        symbols,
    };
    let json =
        serde_json::to_string_pretty(&file).map_err(|error| Error::Serialize(error.to_string()))?;
    if decompiled.regular_file_exists("symbols.json", "final symbols artifact")?
        && read_open_file(
            decompiled.open_regular_file(Path::new("symbols.json"), "final symbols artifact")?,
        )? == json.as_bytes()
    {
        return Ok(());
    }
    let mut output = decompiled.atomic_write_file("symbols.json", "final symbols artifact")?;
    output.write_all(json.as_bytes())?;
    output.commit()?;
    Ok(())
}

/// Serializable shape of the strict pass-2 symbol map
/// (`pixel-modem-extractor-symbol-map-v5`), consumed first by
/// `ApplyThumbNames.java` (creation of named functions Ghidra never discovered),
/// then by `ApplySymbols.java` (application), and finally by
/// `ExportDecomp.java` (postflight identity comparison) through the shared
/// `PalTasksSupport` reader. Field order below is the canonical wire order; the
/// Java reader enforces it exactly.
#[derive(Serialize)]
struct SymbolMapFile<'a> {
    format: &'static str,
    image: ImageBlock<'a>,
    exception_roots: ExceptionBlock<'a>,
    pal: PalBlock<'a>,
    functions_blake3: &'a str,
    predecessor_symbol_pass2: Option<&'a str>,
    executions: Vec<ExecutionBlock<'a>>,
    thumb_creation_lineage: Vec<ThumbCreationLineageBlock>,
    symbols: Vec<DecisionBlock<'a>>,
    creations: Vec<CreationBlock<'a>>,
}

#[derive(Serialize)]
struct ExceptionBlock<'a> {
    identity: &'a str,
    manifest_blake3: Option<&'a str>,
}

#[derive(Serialize)]
struct ImageBlock<'a> {
    label: &'a str,
    base_addr: String,
    size: u64,
    blake3: &'a str,
}

#[derive(Serialize)]
struct PalBlock<'a> {
    identity: &'a str,
    manifest_blake3: Option<&'a str>,
    scatter_load_map_blake3: Option<&'a str>,
}

#[derive(Serialize)]
struct ExecutionBlock<'a> {
    producer: &'static str,
    entry: &'a str,
    execution_blake3: &'a str,
    decode_ranges: Vec<DecodeRangeWire>,
}

#[derive(Serialize)]
struct ThumbCreationLineageBlock {
    execution: usize,
    producer_execution_blake3: String,
    decode_ranges: Vec<DecodeRangeWire>,
}

#[derive(Serialize)]
struct DecisionBlock<'a> {
    execution: usize,
    original_primary: &'a str,
    original_source: &'a str,
    final_primary: &'a str,
    final_source: &'a str,
    action: &'static str,
    annotations: &'a [String],
    exception_transition: Option<ExceptionTransition>,
    pal_transition: Option<PalTransition>,
}

/// One function to *create* in the Ghidra program during pass 2: a named,
/// producer-authenticated Thumb execution whose entry Ghidra's own inventory
/// never discovered (dense-Thumb functions owned by radare2/Rizin). Ghidra
/// disassembles only inside the authenticated address set and passes the
/// explicit returned set to `CreateFunctionCmd`; the final body must remain
/// wholly inside those ranges, so a name never reaches the program without a
/// validated execution identity behind it.
#[derive(Serialize)]
struct CreationBlock<'a> {
    entry: String,
    execution_blake3: String,
    decode_ranges: &'a [DecodeRangeWire],
    final_primary: &'a str,
    final_source: &'static str,
}

#[derive(Serialize)]
struct PalTransition {
    from: &'static str,
    to: &'static str,
}

#[derive(Serialize)]
struct ExceptionTransition {
    from: &'static str,
    to: &'static str,
    authority: &'static str,
    original_primary: TransitionPrimary,
    final_primary: TransitionPrimary,
}

#[derive(Serialize)]
struct TransitionPrimary {
    symbol_id: u64,
    source: &'static str,
    name: String,
    name_blake3: String,
}

impl From<ExceptionPrimaryRef<'_>> for TransitionPrimary {
    fn from(primary: ExceptionPrimaryRef<'_>) -> Self {
        Self {
            symbol_id: primary.symbol_id(),
            source: primary.source(),
            name: primary.name().to_string(),
            name_blake3: primary.name_blake3().to_string(),
        }
    }
}

fn stronger_exception_authority(symbol: &Symbol) -> Option<&'static str> {
    if symbol
        .evidence
        .iter()
        .any(|evidence| matches!(evidence, TaggedEvidence::Func { .. }))
    {
        Some("func")
    } else if symbol
        .evidence
        .iter()
        .any(|evidence| matches!(evidence, TaggedEvidence::Registration { .. }))
    {
        Some("registration")
    } else {
        None
    }
}

/// One authenticated Ghidra execution plus its retained record identity (the
/// pass-1 primary the map binds as `original_primary`).
struct GhidraExecutionRecord {
    entry: u32,
    entry_text: String,
    execution_blake3: String,
    decode_ranges: Vec<DecodeRangeWire>,
    original_primary: String,
    original_source: String,
    /// First decode-range ISA ("arm" | "thumb") for the sort key.
    first_isa: &'static str,
    /// Entry of the in-program function this thunk forwards to, when the
    /// retained record carries the relation.
    thunk_of: Option<u32>,
    execution_digest: [u8; 32],
}

fn authenticate_nominated_thumb_execution(
    symbol: &Symbol,
    entry: u32,
    expected_digest: [u8; 32],
    runtime: &crate::runtime_image::RuntimeImage<'_>,
    budget: &mut crate::execution_ranges::ExecutionBudget,
) -> Result<ExecutionIdentity> {
    if symbol.owner.analysis_tool() != symbol.tool
        || !matches!(
            symbol.owner,
            FunctionOwner::Run {
                producer: crate::analysis_tool::AnalysisTool::Radare2
                    | crate::analysis_tool::AnalysisTool::Rizin,
                ..
            }
        )
    {
        return Err(Error::Serialize(
            "nominated producer execution is not owned by a strict-v3 Thumb run".into(),
        ));
    }
    if symbol.execution_blake3 != Some(expected_digest) {
        return Err(Error::Serialize(
            "nominated producer execution digest does not match its symbol".into(),
        ));
    }
    let symbol_entry = u32::try_from(parse_hex(&symbol.address)?).map_err(|_| {
        Error::Serialize("nominated producer execution entry does not fit u32".into())
    })?;
    if symbol_entry != entry {
        return Err(Error::Serialize(
            "nominated producer execution entry does not match its Ghidra execution".into(),
        ));
    }
    if symbol.decode_ranges.is_empty() {
        return Err(Error::Serialize(
            "nominated producer execution has no decode ranges".into(),
        ));
    }
    let charged_bytes = symbol.decode_ranges.iter().try_fold(0u64, |total, range| {
        if range.isa != "thumb" {
            return Err(Error::Serialize(
                "nominated producer execution is not Thumb-only".into(),
            ));
        }
        let start = u32::try_from(parse_hex(&range.start)?)
            .map_err(|_| Error::Serialize("nominated producer range start exceeds u32".into()))?;
        let end = u32::try_from(parse_hex(&range.end)?)
            .map_err(|_| Error::Serialize("nominated producer range end exceeds u32".into()))?;
        let length = end
            .checked_sub(start)
            .filter(|length| *length > 0)
            .ok_or_else(|| Error::Serialize("nominated producer range is empty or wraps".into()))?;
        total
            .checked_add(u64::from(length))
            .ok_or_else(|| Error::Serialize("nominated producer charged-byte overflow".into()))
    })?;
    budget.check_execution(symbol.decode_ranges.len(), charged_bytes)?;
    let mut extents = Vec::new();
    let mut expected_hashes = Vec::new();
    extents
        .try_reserve_exact(symbol.decode_ranges.len())
        .map_err(|_| Error::Serialize("nominated producer range allocation failed".into()))?;
    expected_hashes
        .try_reserve_exact(symbol.decode_ranges.len())
        .map_err(|_| Error::Serialize("nominated producer hash allocation failed".into()))?;
    for range in &symbol.decode_ranges {
        if range.isa != "thumb" {
            return Err(Error::Serialize(
                "nominated producer execution is not Thumb-only".into(),
            ));
        }
        let start = u32::try_from(parse_hex(&range.start)?)
            .map_err(|_| Error::Serialize("nominated producer range start exceeds u32".into()))?;
        let end = u32::try_from(parse_hex(&range.end)?)
            .map_err(|_| Error::Serialize("nominated producer range end exceeds u32".into()))?;
        extents.push(crate::execution_ranges::DecodeExtent {
            start,
            end,
            isa: crate::execution_ranges::DecodeIsa::Thumb,
        });
        expected_hashes.push(crate::execution_ranges::parse_blake3(&range.blake3)?);
    }
    if extents.first().map(|range| range.start) != Some(entry) {
        return Err(Error::Serialize(
            "nominated producer execution does not start at its entry".into(),
        ));
    }
    let identity = crate::execution_ranges::validate_execution(entry, extents, runtime, budget)?;
    if identity.decode_ranges.len() != symbol.decode_ranges.len()
        || identity
            .decode_ranges
            .iter()
            .zip(&symbol.decode_ranges)
            .any(|(authenticated, claimed)| {
                claimed.start != format!("0x{:08x}", authenticated.start)
                    || claimed.end != format!("0x{:08x}", authenticated.end)
            })
    {
        return Err(Error::Serialize(
            "nominated producer decode ranges are not canonical".into(),
        ));
    }
    if identity
        .decode_ranges
        .iter()
        .map(|range| range.blake3)
        .ne(expected_hashes.iter().copied())
    {
        return Err(Error::Serialize(
            "nominated producer decode-range BLAKE3 does not match runtime bytes".into(),
        ));
    }
    if identity.execution_blake3 != expected_digest {
        return Err(Error::Serialize(
            "nominated producer execution BLAKE3 does not match its ranges".into(),
        ));
    }
    Ok(identity)
}

fn build_thumb_creation_lineage(
    nominations: &[crate::execution_ranges::ThumbCreationNomination],
    executions: &[GhidraExecutionRecord],
    symbols: &[Symbol],
    runtime: &crate::runtime_image::RuntimeImage<'_>,
    range_usage: crate::execution_ranges::ExecutionRangeUsage,
) -> Result<Vec<ThumbCreationLineageBlock>> {
    type NominationKey = (u32, [u8; 32]);

    let mut budget = crate::execution_ranges::ExecutionBudget::from_range_usage(range_usage)?;
    let producer_keys = nominations
        .iter()
        .map(|nomination| (nomination.entry, nomination.producer_execution_blake3))
        .collect::<BTreeSet<_>>();
    let ghidra_keys = nominations
        .iter()
        .map(|nomination| (nomination.entry, nomination.ghidra_execution_blake3))
        .collect::<BTreeSet<_>>();
    let mut producer_index: BTreeMap<NominationKey, Option<&Symbol>> = BTreeMap::new();
    for symbol in symbols {
        if !matches!(
            symbol.owner,
            FunctionOwner::Run {
                producer: crate::analysis_tool::AnalysisTool::Radare2
                    | crate::analysis_tool::AnalysisTool::Rizin,
                ..
            }
        ) {
            continue;
        }
        let Some(digest) = symbol.execution_blake3 else {
            continue;
        };
        let entry = u32::try_from(parse_hex(&symbol.address)?).map_err(|_| {
            Error::Serialize("strict-v3 producer symbol entry does not fit u32".into())
        })?;
        let key = (entry, digest);
        if !producer_keys.contains(&key) {
            continue;
        }
        match producer_index.entry(key) {
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(Some(symbol));
            }
            std::collections::btree_map::Entry::Occupied(mut slot) => {
                slot.insert(None);
            }
        }
    }

    let mut ghidra_index: BTreeMap<NominationKey, Option<usize>> = BTreeMap::new();
    for (index, execution) in executions.iter().enumerate() {
        let key = (execution.entry, execution.execution_digest);
        if !ghidra_keys.contains(&key) {
            continue;
        }
        match ghidra_index.entry(key) {
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(Some(index));
            }
            std::collections::btree_map::Entry::Occupied(mut slot) => {
                slot.insert(None);
            }
        }
    }

    let mut lineage = Vec::new();
    let mut linked_executions = BTreeSet::new();
    let mut linked_producers = BTreeSet::new();
    for nomination in nominations {
        let ghidra_key = (nomination.entry, nomination.ghidra_execution_blake3);
        let Some(execution_index) = ghidra_index.get(&ghidra_key).copied().flatten() else {
            return Err(Error::Serialize(format!(
                "Thumb creation nomination at 0x{:08x} does not link exactly one Ghidra execution",
                nomination.entry
            )));
        };
        if executions[execution_index].first_isa != "thumb" {
            return Err(Error::Serialize(format!(
                "Thumb creation nomination at 0x{:08x} links a non-Thumb Ghidra execution",
                nomination.entry
            )));
        }
        if !linked_executions.insert(execution_index) {
            return Err(Error::Serialize(
                "duplicate Thumb creation lineage execution".into(),
            ));
        }
        if !linked_producers.insert(nomination.producer_execution_blake3) {
            return Err(Error::Serialize(
                "duplicate Thumb creation lineage producer digest".into(),
            ));
        }

        let producer_key = (nomination.entry, nomination.producer_execution_blake3);
        let symbol = match producer_index.get(&producer_key) {
            None => {
                return Err(Error::Serialize(format!(
                    "no nominated producer execution matches 0x{:08x}",
                    nomination.entry
                )));
            }
            Some(None) => {
                return Err(Error::Serialize(format!(
                    "ambiguous nominated producer execution at 0x{:08x}",
                    nomination.entry
                )));
            }
            Some(Some(symbol)) => *symbol,
        };
        let producer = authenticate_nominated_thumb_execution(
            symbol,
            nomination.entry,
            nomination.producer_execution_blake3,
            runtime,
            &mut budget,
        )?;
        lineage.push(ThumbCreationLineageBlock {
            execution: execution_index,
            producer_execution_blake3: crate::manifest::blake3_fixed(producer.execution_blake3),
            decode_ranges: producer
                .decode_ranges
                .iter()
                .map(DecodeRangeWire::from_authenticated)
                .collect(),
        });
    }
    lineage.sort_by_key(|row| row.execution);
    Ok(lineage)
}

/// The result of one successfully written pass-2 map.
#[derive(Debug)]
pub struct WrittenSymbolMap {
    pub path: PathBuf,
    /// BLAKE3 over the exact written map bytes.
    pub map_blake3: String,
    /// Plain BLAKE3 over the exact retained pass-1 `functions.json` bytes.
    pub functions_blake3: String,
    /// Accepted Ghidra executions covered (== decisions).
    pub execution_count: usize,
    /// Decisions that apply anything (a rename or at least one annotation) —
    /// together with `creation_count`, the pass-2 scheduling gate.
    pub applied_decision_count: usize,
    /// Named producer-authenticated Thumb entries Ghidra never discovered,
    /// to create in the Ghidra program during pass 2.
    pub creation_count: usize,
    /// Exact entry/name/source requests serialized in `creations`, retained
    /// for Rust-side terminal validation after Ghidra exports pass 2.
    pub creation_requests: Vec<Pass2CreationRequest>,
    /// Why named entries did not become creations (report diagnostics).
    pub creation_skips: Pass2CreationSkips,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pass2CreationRequest {
    pub entry: u32,
    pub final_primary: String,
    pub final_source: String,
}

fn map_string_check(value: &str, what: &str) -> Result<()> {
    if value.contains('\0') {
        return Err(Error::Serialize(format!(
            "symbol map {what} contains a NUL byte"
        )));
    }
    if value.contains('\u{fffd}') {
        // A replacement character means a lossy UTF-8 conversion upstream
        // (unpaired surrogates cannot exist in a Rust `str`, but lossy
        // decoding can smuggle the sentinel through).
        return Err(Error::Serialize(format!(
            "symbol map {what} contains an unpaired-surrogate sentinel"
        )));
    }
    Ok(())
}

fn check_map_limits(symbols: &[Symbol]) -> Result<()> {
    let mut aggregate: u64 = 0;
    for symbol in symbols {
        if symbol.annotations.len() > MAX_MAP_ANNOTATIONS_PER_DECISION {
            return Err(Error::Serialize(format!(
                "a symbol map decision carries {} annotations above the \
                 {MAX_MAP_ANNOTATIONS_PER_DECISION}-annotation limit",
                symbol.annotations.len()
            )));
        }
        for annotation in &symbol.annotations {
            let size = annotation.len();
            if size > MAX_MAP_ANNOTATION_UTF8_BYTES {
                return Err(Error::Serialize(format!(
                    "an annotation is {size} UTF-8 bytes above the \
                     {MAX_MAP_ANNOTATION_UTF8_BYTES}-byte limit"
                )));
            }
            map_string_check(annotation, "annotation")?;
            aggregate = aggregate
                .checked_add(size as u64)
                .ok_or_else(|| Error::Serialize("annotation aggregate overflow".into()))?;
            if aggregate > MAX_MAP_ANNOTATION_AGGREGATE_BYTES {
                return Err(Error::Serialize(
                    "symbol map annotations exceed the 64 MiB aggregate limit".into(),
                ));
            }
        }
        for name in [
            &symbol.original_name,
            symbol.name.as_deref().unwrap_or_default(),
        ] {
            if name.chars().count() > MAX_PRIMARY_CHARS {
                return Err(Error::Serialize(format!(
                    "a primary exceeds the {MAX_PRIMARY_CHARS}-character limit"
                )));
            }
            map_string_check(name, "primary")?;
        }
    }
    Ok(())
}

/// Assemble and atomically write the strict pass-2 symbol map for one image.
///
/// `image_dir` is the image's tree directory (`images/<label>` with
/// `decompiled/functions.json`); `functions_bytes` are the exact retained
/// pass-1 `functions.json` bytes (hashed verbatim, whitespace and terminal
/// newline included). Every accepted Ghidra execution is recomputed through
/// the `runtime` (`RuntimeImage` revalidates each declared range hash against
/// runtime storage, and `execution_identity` recomputes the domain-separated
/// digest), sorted by `(entry, first-ISA, execution_blake3)`, and covered by
/// exactly one decision in the same order. `symbols` are the ranked decisions
/// from [`build_map`]; each Ghidra-owned symbol's original name is
/// cross-checked against its retained record before publication.
#[allow(clippy::too_many_arguments)]
pub(crate) fn write_pass2_symbol_map(
    out_path: &Path,
    image_dir: &Path,
    image_label: &str,
    load_addr: u64,
    image_bytes: &[u8],
    symbols: &[Symbol],
    exception: Option<&ExceptionPass2Context>,
    pal: Option<&PalPass2Context>,
    runtime: &crate::runtime_image::RuntimeImage<'_>,
) -> Result<WrittenSymbolMap> {
    check_map_limits(symbols)?;

    let functions_path = image_dir.join("decompiled").join("functions.json");
    let functions_bytes = std::fs::read(&functions_path)?;
    let functions_blake3 = crate::manifest::blake3_bytes(&functions_bytes);
    let streamed =
        crate::execution_ranges::read_ghidra_inventory_streaming(&functions_path, runtime)?;
    let ghidra_entries: std::collections::HashSet<u32> = streamed
        .functions
        .iter()
        .map(|record| record.tagged.entry)
        .collect();
    let mut executions: Vec<GhidraExecutionRecord> = Vec::new();
    for record in streamed.functions {
        let Some(execution) = crate::execution_ranges::execution_identity(
            record.tagged.entry,
            &record.tagged.projection,
        )?
        else {
            continue;
        };
        let original_source = match record.primary_source.as_str() {
            "default" | "analysis" | "ai" | "imported" | "user_defined" => {
                record.primary_source.as_str()
            }
            other => {
                return Err(Error::Serialize(format!(
                    "retained function record carries an unknown primary source {other:?}"
                )));
            }
        };
        executions.push(GhidraExecutionRecord {
            entry: execution.entry,
            entry_text: format!("0x{:08x}", execution.entry),
            execution_blake3: crate::manifest::blake3_fixed(execution.execution_blake3),
            decode_ranges: execution
                .decode_ranges
                .iter()
                .map(DecodeRangeWire::from_authenticated)
                .collect(),
            original_primary: record.original_name.unwrap_or(record.name),
            original_source: original_source.to_string(),
            first_isa: match execution
                .decode_ranges
                .first()
                .map(|range| range.isa)
                .unwrap_or(crate::execution_ranges::DecodeIsa::Arm)
            {
                crate::execution_ranges::DecodeIsa::Arm => "arm",
                crate::execution_ranges::DecodeIsa::Thumb => "thumb",
            },
            thunk_of: record.thunk_of,
            execution_digest: execution.execution_blake3,
        });
    }
    executions.sort_by(|a, b| {
        (a.entry, a.first_isa, &a.execution_blake3).cmp(&(
            b.entry,
            b.first_isa,
            &b.execution_blake3,
        ))
    });
    let thumb_creation_lineage = build_thumb_creation_lineage(
        &streamed.thumb_creation_nominations,
        &executions,
        symbols,
        runtime,
        streamed.range_usage,
    )?;

    // One decision per execution, cross-checked against the Ghidra-owned
    // symbol for that exact execution identity.
    let mut decisions: Vec<DecisionBlock<'_>> = Vec::with_capacity(executions.len());
    let mut applied_decision_count = 0usize;
    let mut renamed: std::collections::HashMap<u32, &str> = std::collections::HashMap::new();
    for (index, execution) in executions.iter().enumerate() {
        let symbol = symbols
            .iter()
            .find(|symbol| {
                symbol.owner == FunctionOwner::Ghidra
                    && symbol.execution_blake3 == Some(execution.execution_digest)
            })
            .ok_or_else(|| {
                Error::Serialize(format!(
                    "no symbol covers the accepted Ghidra execution at 0x{:08x}",
                    execution.entry
                ))
            })?;
        if symbol.original_name != execution.original_primary {
            return Err(Error::Serialize(format!(
                "symbol original primary {:?} does not match the retained record {:?} at 0x{:08x}",
                symbol.original_name, execution.original_primary, execution.entry
            )));
        }
        let execution_isa = match execution.first_isa {
            "arm" => DecodeIsa::Arm,
            "thumb" => DecodeIsa::Thumb,
            _ => unreachable!("validated execution ISA"),
        };
        let exception_application =
            exception.and_then(|context| context.application(&(execution.entry, execution_isa)));
        if let Some(application) = exception_application {
            let current = application.current_primary();
            if current.name() != execution.original_primary
                || current.source() != execution.original_source
            {
                return Err(Error::Serialize(format!(
                    "exception application current primary does not match the retained Ghidra record at 0x{:08x}",
                    execution.entry
                )));
            }
        }
        let mut replay_original = None;
        let mut replay_final = None;
        let exception_transition = match exception_application.map(|app| app.disposition_kind()) {
            Some(ExceptionDispositionKind::ExceptionOwned) => {
                let application = exception_application.expect("matched application");
                let current = application.current_primary();
                let authority = stronger_exception_authority(symbol);
                let final_name = symbol.name.as_deref();
                match (authority, final_name) {
                    (Some(authority), Some(final_name))
                        if symbol.tier == Tier::Recovered && final_name != current.name() =>
                    {
                        Some(ExceptionTransition {
                            from: "exception_owned",
                            to: "pass2_owned",
                            authority,
                            original_primary: TransitionPrimary::from(current),
                            final_primary: TransitionPrimary {
                                symbol_id: current.symbol_id(),
                                source: "user_defined",
                                name: final_name.to_string(),
                                name_blake3: crate::manifest::blake3_bytes(final_name.as_bytes()),
                            },
                        })
                    }
                    _ => None,
                }
            }
            Some(ExceptionDispositionKind::Pass2Owned) => {
                let application = exception_application.expect("matched application");
                let authority = application
                    .transition_authority()
                    .expect("pass2-owned authority");
                let original = application
                    .transition_original()
                    .expect("pass2-owned original");
                let final_primary = application.transition_final().expect("pass2-owned final");
                replay_original = Some((original.name(), original.source()));
                replay_final = Some((final_primary.name(), final_primary.source()));
                Some(ExceptionTransition {
                    from: "exception_owned",
                    to: "pass2_owned",
                    authority,
                    original_primary: TransitionPrimary::from(original),
                    final_primary: TransitionPrimary::from(final_primary),
                })
            }
            Some(ExceptionDispositionKind::Preserved | ExceptionDispositionKind::NotRequested)
            | None => None,
        };
        let pal_transition = match pal
            .and_then(|ctx| ctx.applications.get(&execution.entry))
            .filter(|app| app.desired_primary == execution.original_primary)
        {
            // Only an exact rename of the applied task primary by a rank
            // above pal_task (a Recovered func/registration name differing
            // from the original) may transition; a pal-rank preserve never
            // does.
            Some(app)
                if exception_application.is_none()
                    && symbol
                        .name
                        .as_deref()
                        .is_some_and(|name| name != execution.original_primary)
                    && symbol.tier == Tier::Recovered =>
            {
                if app.isa != symbol.decode_isa() {
                    return Err(Error::Serialize(
                        "PAL application ISA does not match the record's decode ISA".into(),
                    ));
                }
                Some(PalTransition {
                    from: "pal_owned",
                    to: "pass2_owned",
                })
            }
            _ => None,
        };
        // Authorization envelope, mirrored by ApplySymbols: a rename may
        // displace only a default- or analysis-sourced primary, or an exact
        // registry-bound pal_owned task primary (the transition above).
        // Genuine imported and user-defined names stay protected — their
        // decisions downgrade to preserve (the evidence survives in
        // symbols.json).
        let rename_authorized = replay_final.is_none() && exception_transition.is_some()
            || pal_transition.is_some()
            || (exception_application.is_none()
                && matches!(execution.original_source.as_str(), "default" | "analysis"));
        let (original_primary, original_source, final_primary, final_source, action) =
            match (replay_original, replay_final) {
                (Some((original_name, original_source)), Some((final_name, final_source))) => (
                    original_name,
                    original_source,
                    final_name,
                    final_source,
                    "rename",
                ),
                _ => match &symbol.name {
                    Some(name) if name != &execution.original_primary && rename_authorized => {
                        let source = match symbol.tier {
                            Tier::Recovered => "user_defined",
                            Tier::Provisional | Tier::None => "analysis",
                        };
                        renamed.insert(execution.entry, name.as_str());
                        (
                            execution.original_primary.as_str(),
                            execution.original_source.as_str(),
                            name.as_str(),
                            source,
                            "rename",
                        )
                    }
                    _ => (
                        execution.original_primary.as_str(),
                        execution.original_source.as_str(),
                        execution.original_primary.as_str(),
                        execution.original_source.as_str(),
                        "preserve",
                    ),
                },
            };
        if action == "rename" || !symbol.annotations.is_empty() {
            applied_decision_count += 1;
        }
        decisions.push(DecisionBlock {
            execution: index,
            original_primary,
            original_source,
            final_primary,
            final_source,
            action,
            annotations: &symbol.annotations,
            exception_transition,
            pal_transition,
        });
    }

    // Ghidra mirrors a referenced function's post-rename primary onto every
    // thunk of it, recursively through thunk chains (the direct thunk of the
    // renamed target and every thunk of that thunk follow the new primary;
    // each thunk's own symbol source is left unchanged). A preserve decision
    // for such a thunk would fail ApplySymbols' postflight, so the map
    // encodes the drift it cannot forbid as an explicit `mirror` decision:
    // the final primary is the chain-root target's renamed primary, the
    // final source is the thunk's unchanged original source, and
    // ApplySymbols verifies without mutating (the mirror already happened
    // through the target's rename). A thunk with its own authorized rename
    // keeps that decision; the Java side orders thunk renames after
    // non-thunk renames so the independent name wins over Ghidra's mirror.
    let thunk_targets: std::collections::HashMap<u32, Option<u32>> = executions
        .iter()
        .map(|execution| (execution.entry, execution.thunk_of))
        .collect();
    for (decision, execution) in decisions.iter_mut().zip(&executions) {
        if decision.action != "preserve" {
            continue;
        }
        let execution_isa = match execution.first_isa {
            "arm" => DecodeIsa::Arm,
            "thumb" => DecodeIsa::Thumb,
            _ => unreachable!("validated execution ISA"),
        };
        if exception.is_some_and(|context| {
            context
                .application(&(execution.entry, execution_isa))
                .is_some()
        }) {
            continue;
        }
        let mut target = execution.thunk_of;
        let mut hops = 0usize;
        while let Some(target_entry) = target {
            if let Some(&mirrored) = renamed.get(&target_entry) {
                decision.final_primary = mirrored;
                decision.action = "mirror";
                break;
            }
            // A cycle or an unbounded chain cannot occur in a validated
            // Ghidra inventory (thunk graphs are acyclic), but the hop bound
            // keeps a malformed map from spinning here regardless.
            hops += 1;
            if hops > executions.len() {
                break;
            }
            target = thunk_targets.get(&target_entry).copied().flatten();
        }
    }

    // Creations: named, producer-authenticated Thumb executions whose entry
    // Ghidra's inventory never discovered. Only a symbol with a decided name
    // AND an authenticated execution identity (accepted decode ranges) may
    // create a Ghidra function; entries Ghidra knows stay on the rename path
    // above. Two named symbols at one entry with different names are an
    // ambiguity refused (never arbitrated), and a creation whose name
    // collides with any decision's final primary or another creation's name
    // is skipped — the tool never invents suffixed variants (the
    // ApplyGlobals skip precedent).
    let taken_names: std::collections::HashSet<&str> = decisions
        .iter()
        .map(|decision| decision.final_primary)
        .collect();
    let mut creation_candidates: BTreeMap<u32, Vec<&Symbol>> = BTreeMap::new();
    for symbol in symbols {
        if !matches!(
            symbol.owner,
            FunctionOwner::Run {
                producer: crate::analysis_tool::AnalysisTool::Radare2
                    | crate::analysis_tool::AnalysisTool::Rizin,
                ..
            }
        ) || symbol.name.is_none()
            || symbol.execution_blake3.is_none()
            || symbol.decode_ranges.is_empty()
        {
            continue;
        }
        let Ok(entry) = u32::from_str_radix(symbol.address.trim_start_matches("0x"), 16) else {
            continue;
        };
        let entry = entry & !1;
        if ghidra_entries.contains(&entry) {
            continue;
        }
        creation_candidates.entry(entry).or_default().push(symbol);
    }
    let mut creation_skips: Pass2CreationSkips = Default::default();
    let mut eligible = Vec::new();
    for (entry, candidates) in creation_candidates {
        let symbol = candidates[0];
        let primary = symbol.name.as_deref().expect("named candidate");
        let final_source = match symbol.tier {
            Tier::Recovered => "user_defined",
            Tier::Provisional | Tier::None => "analysis",
        };
        if candidates.iter().any(|candidate| {
            candidate.name.as_deref() != Some(primary)
                || candidate.owner != symbol.owner
                || candidate.execution_blake3 != symbol.execution_blake3
                || candidate.decode_ranges != symbol.decode_ranges
                || match candidate.tier {
                    Tier::Recovered => "user_defined",
                    Tier::Provisional | Tier::None => "analysis",
                } != final_source
        }) {
            creation_skips.ambiguous += 1;
            continue;
        }
        if primary.chars().count() > MAX_PRIMARY_CHARS {
            creation_skips.name_limit += 1;
            continue;
        }
        map_string_check(primary, "creation primary")?;
        let first_start = symbol
            .decode_ranges
            .first()
            .and_then(|range| u32::from_str_radix(range.start.trim_start_matches("0x"), 16).ok());
        if first_start != Some(entry) {
            creation_skips.not_entry_start += 1;
            continue;
        }
        eligible.push((entry, symbol, primary, final_source));
    }
    let mut name_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for (_, _, primary, _) in &eligible {
        *name_counts.entry(primary).or_default() += 1;
    }
    let mut creations: Vec<CreationBlock<'_>> = Vec::new();
    let mut creation_requests = Vec::new();
    for (entry, symbol, primary, final_source) in eligible {
        if taken_names.contains(primary) || name_counts[primary] != 1 {
            creation_skips.collision += 1;
            continue;
        }
        if creations.len() >= MAX_MAP_CREATIONS {
            creation_skips.limit += 1;
            continue;
        }
        creation_requests.push(Pass2CreationRequest {
            entry,
            final_primary: primary.to_string(),
            final_source: final_source.to_string(),
        });
        creations.push(CreationBlock {
            entry: format!("0x{entry:08x}"),
            execution_blake3: crate::manifest::blake3_fixed(
                symbol.execution_blake3.expect("authenticated candidate"),
            ),
            decode_ranges: &symbol.decode_ranges,
            final_primary: primary,
            final_source,
        });
    }

    let (exception_identity, exception_manifest_blake3) = match exception {
        None => ("none", None),
        Some(context) => (context.identity(), Some(context.manifest_blake3())),
    };
    let (pal_identity, manifest_blake3, scatter_blake3) = match pal {
        None => ("none", None, None),
        Some(ctx) => (
            ctx.identity.as_str(),
            Some(ctx.manifest_blake3.as_str()),
            ctx.scatter_load_map_blake3.as_deref(),
        ),
    };
    let image_size = u64::try_from(image_bytes.len())
        .map_err(|_| Error::Serialize("image size does not fit the map domain".into()))?;
    let creation_count_value = creations.len();
    let file = SymbolMapFile {
        format: SYMBOL_MAP_FORMAT,
        image: ImageBlock {
            label: image_label,
            base_addr: format!("0x{load_addr:08x}"),
            size: image_size,
            blake3: &crate::manifest::blake3_bytes(image_bytes),
        },
        exception_roots: ExceptionBlock {
            identity: exception_identity,
            manifest_blake3: exception_manifest_blake3,
        },
        pal: PalBlock {
            identity: pal_identity,
            manifest_blake3,
            scatter_load_map_blake3: scatter_blake3,
        },
        functions_blake3: &functions_blake3,
        predecessor_symbol_pass2: exception
            .and_then(ExceptionPass2Context::predecessor_symbol_pass2),
        executions: executions
            .iter()
            .map(|execution| ExecutionBlock {
                producer: "ghidra",
                entry: &execution.entry_text,
                execution_blake3: &execution.execution_blake3,
                decode_ranges: execution.decode_ranges.clone(),
            })
            .collect(),
        thumb_creation_lineage,
        symbols: decisions,
        creations,
    };
    let mut bytes =
        serde_json::to_vec_pretty(&file).map_err(|e| Error::Serialize(e.to_string()))?;
    bytes.push(b'\n');
    let map_blake3 = crate::manifest::blake3_bytes(&bytes);
    let mut writer = atomic_write_file::AtomicWriteFile::open(out_path)?;
    use std::io::Write as _;
    writer
        .write_all(&bytes)
        .map_err(|e| Error::Serialize(format!("atomic symbol map write failed: {e}")))?;
    writer
        .commit()
        .map_err(|e| Error::Serialize(format!("atomic symbol map commit failed: {e}")))?;

    Ok(WrittenSymbolMap {
        path: out_path.to_path_buf(),
        map_blake3,
        functions_blake3,
        execution_count: executions.len(),
        applied_decision_count,
        creation_count: creation_count_value,
        creation_requests,
        creation_skips,
    })
}

/// Why named thumb-only entries did not become creation candidates. All
/// counts are report-facing diagnostics; a skip never fails the map.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Pass2CreationSkips {
    /// Two named symbols at one entry with different names.
    pub ambiguous: usize,
    /// The requested name collides with a decision's or another creation's
    /// final primary.
    pub collision: usize,
    /// The requested name exceeds `MAX_PRIMARY_CHARS`.
    pub name_limit: usize,
    /// The map already carries `MAX_MAP_CREATIONS` creations.
    pub limit: usize,
    /// The first authenticated decode range does not start at the (Thumb-bit
    /// stripped) entry, so ApplyThumbNames cannot declare TMode from the entry
    /// over that range. Skip rather than emit a map the Java reader rejects.
    pub not_entry_start: usize,
}

/// The complete result of preparing one image's pass-2 symbol map: the
/// written map plus the downstream orchestration indexes derived from the
/// same symbol set.
pub struct Pass2MapBundle {
    pub map: WrittenSymbolMap,
    pub symbols: Vec<Symbol>,
    /// Canonical (bare-lowercase-hex) entry -> final name, for globals
    /// recovery.
    pub function_names: HashMap<String, String>,
    pub evidence_name_projection: crate::globals::FunctionEvidenceNameProjection,
}

/// Build the ranked symbol set for one image and write its strict pass-2 map
/// to `map_out_path`. One call covers: `build_map` (ranked decisions), the
/// exact retained-file hash, the runtime-recomputed execution inventory, the
/// decision cross-checks, and the atomic v4 write.
pub fn prepare_pass2_symbol_map(
    map_out_path: &Path,
    image_dir: &Path,
    image_label: &str,
    tokens: &HashMap<u32, String>,
    manifest: &Path,
    exception_application: Option<&ExceptionPass2Context>,
    pal_application: Option<&PalPass2Context>,
) -> Result<Pass2MapBundle> {
    let load_addr = crate::manifest::load_addr_for_image(manifest, image_label)?
        .ok_or_else(|| Error::Serialize(format!("load_addr missing for {image_label}")))?;
    let image_base = u32::try_from(load_addr).map_err(|_| {
        Error::Serialize(format!(
            "load_addr for {image_label} exceeds the u32 address domain"
        ))
    })?;
    let context = role_evidence::CurrentSymbolicationContext::from_retained(
        image_dir,
        image_label,
        crate::manifest::toc_name(image_label),
        image_base,
    )?;
    context.validate(image_dir, |_, image_bytes, runtime, roles| {
        prepare_pass2_symbol_map_from_runtime(
            map_out_path,
            image_dir,
            image_label,
            tokens,
            load_addr,
            image_bytes,
            runtime,
            roles,
            exception_application,
            pal_application,
        )
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_pass2_symbol_map_from_runtime(
    map_out_path: &Path,
    image_dir: &Path,
    image_label: &str,
    tokens: &HashMap<u32, String>,
    load_addr: u64,
    image_bytes: &[u8],
    runtime: &RuntimeImage<'_>,
    roles: &role_evidence::AuthenticatedRoleEvidence,
    exception_application: Option<&ExceptionPass2Context>,
    pal_application: Option<&PalPass2Context>,
) -> Result<Pass2MapBundle> {
    let (symbols, _) = build_map_from_runtime(
        image_dir,
        tokens,
        image_bytes,
        load_addr,
        runtime,
        roles,
        SymbolBuildPurpose::Pass2 {
            exception_application,
            pal_application,
        },
    )?;
    let map = write_pass2_symbol_map(
        map_out_path,
        image_dir,
        image_label,
        load_addr,
        image_bytes,
        &symbols,
        exception_application,
        pal_application,
        runtime,
    )?;
    let function_names = symbols
        .iter()
        .filter_map(|symbol| {
            let name = symbol.name.as_ref()?;
            let entry = u64::from_str_radix(symbol.address.trim_start_matches("0x"), 16).ok()?;
            Some((format!("{entry:x}"), name.clone()))
        })
        .collect();
    let evidence_name_projection =
        crate::globals::FunctionEvidenceNameProjection::from_symbols(&symbols);
    Ok(Pass2MapBundle {
        map,
        symbols,
        function_names,
        evidence_name_projection,
    })
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

fn symbol_index(symbols: &[Symbol]) -> HashMap<FunctionEvidenceKey, &Symbol> {
    symbols
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
        .collect()
}

fn stamp_function_record(
    by_owner: &HashMap<FunctionEvidenceKey, &Symbol>,
    owner: FunctionOwner,
    execution: Option<&ExecutionIdentity>,
    item: &mut serde_json::Value,
) -> Result<()> {
    let Some(addr) = item
        .get("entry")
        .and_then(|value| value.as_str())
        .and_then(|entry| parse_hex(entry).ok())
    else {
        return Ok(());
    };
    let key = FunctionEvidenceKey {
        owner,
        entry: addr,
        execution_blake3: execution.map(|execution| execution.execution_blake3),
    };
    let Some(symbol) = by_owner.get(&key) else {
        return Ok(());
    };
    let Some(object) = item.as_object_mut() else {
        return Ok(());
    };
    if object.contains_key("original_name") {
        return Ok(());
    }
    object.insert(
        "original_name".into(),
        serde_json::Value::String(symbol.original_name.clone()),
    );
    if let Some(name) = &symbol.name {
        object.insert("name".into(), serde_json::Value::String(name.clone()));
    }
    object.insert(
        "annotations".into(),
        serde_json::Value::Array(
            symbol
                .annotations
                .iter()
                .cloned()
                .map(serde_json::Value::String)
                .collect(),
        ),
    );
    Ok(())
}

fn ghidra_execution_identities(
    functions: File,
    runtime: &RuntimeImage<'_>,
) -> Result<Vec<Option<ExecutionIdentity>>> {
    crate::execution_ranges::read_ghidra_inventory_file(functions, runtime)?
        .inventory
        .records
        .iter()
        .map(|record| crate::execution_ranges::execution_identity(record.entry, &record.projection))
        .collect()
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
#[cfg(test)]
pub(crate) fn rewrite_functions_json(
    decompiled: &Path,
    runtime: &crate::runtime_image::RuntimeImage<'_>,
    symbols: &[Symbol],
) -> Result<()> {
    // Numeric address spelling does not matter, while concrete ownership and
    // authenticated execution remain identity-bearing.
    let by_owner = symbol_index(symbols);

    // functions.json (a bare array) is always Ghidra's inventory.
    let fpath = decompiled.join("functions.json");
    if fpath.exists() {
        let source = std::fs::read(&fpath)?;
        let executions = ghidra_execution_identities(File::open(&fpath)?, runtime)?;
        let mut function_index = 0usize;
        crate::thumb_analysis::stream_rewrite_json_array(&fpath, &source, |item| {
            let execution = executions.get(function_index).ok_or_else(|| {
                Error::Serialize("Ghidra function count changed during mutation".into())
            })?;
            function_index += 1;
            stamp_function_record(&by_owner, FunctionOwner::Ghidra, execution.as_ref(), item)
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
            |owner, execution, item| stamp_function_record(&by_owner, owner, execution, item),
        )?;
    }
    Ok(())
}

fn rewrite_functions_json_trusted(
    decompiled: &TrustedDirectory,
    runtime: &RuntimeImage<'_>,
    symbols: &[Symbol],
) -> Result<()> {
    let by_owner = symbol_index(symbols);
    let source = read_open_file(decompiled.open_regular_file(
        Path::new("functions.json"),
        "final symbolication Ghidra functions",
    )?)?;
    let executions = ghidra_execution_identities(
        decompiled.open_regular_file(
            Path::new("functions.json"),
            "final symbolication Ghidra functions",
        )?,
        runtime,
    )?;
    let function_index = std::cell::Cell::new(0usize);
    crate::thumb_analysis::stream_rewrite_json_array_trusted(
        decompiled,
        "functions.json",
        &source,
        || {
            function_index.set(0);
            |item| {
                let index = function_index.get();
                let execution = executions.get(index).ok_or_else(|| {
                    Error::Serialize("Ghidra function count changed during mutation".into())
                })?;
                function_index.set(index + 1);
                stamp_function_record(&by_owner, FunctionOwner::Ghidra, execution.as_ref(), item)
            }
        },
    )?;
    if function_index.get() != executions.len() {
        return Err(Error::Serialize(
            "Ghidra function count changed during mutation".into(),
        ));
    }

    if decompiled.regular_file_exists(
        "thumb_functions.json",
        "final symbolication Thumb functions",
    )? {
        crate::thumb_analysis::stream_rewrite_thumb_functions_trusted(
            decompiled,
            "thumb_functions.json",
            runtime,
            || |owner, execution, item| stamp_function_record(&by_owner, owner, execution, item),
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
#[cfg(test)]
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

fn rewrite_text_files_trusted(
    decompiled: &TrustedDirectory,
    runtime: &RuntimeImage<'_>,
    symbols: &[Symbol],
) -> Result<()> {
    for name in ["decompiled.c", "disasm.lst"] {
        let context = format!("final symbolication {name}");
        if !decompiled.regular_file_exists(name, &context)? {
            continue;
        }
        let source = read_open_file(decompiled.open_regular_file(Path::new(name), &context)?)?;
        let text = String::from_utf8(source).map_err(|error| {
            Error::Serialize(format!("final symbolication {name} is not UTF-8: {error}"))
        })?;
        let rewritten = rewrite_text(&text, symbols);
        if rewritten == text {
            continue;
        }
        let mut output = decompiled.atomic_write_file(name, &context)?;
        output.write_all(rewritten.as_bytes())?;
        output.commit()?;
    }
    rewrite_body_c_in_thumb_functions_trusted(decompiled, runtime, symbols)
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
#[cfg(test)]
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

fn rewrite_body_c_in_thumb_functions_trusted(
    decompiled: &TrustedDirectory,
    runtime: &RuntimeImage<'_>,
    symbols: &[Symbol],
) -> Result<()> {
    if !decompiled.regular_file_exists(
        "thumb_functions.json",
        "final symbolication Thumb functions",
    )? {
        return Ok(());
    }
    let renames = build_rename_map(symbols);
    crate::thumb_analysis::stream_rewrite_thumb_functions_trusted(
        decompiled,
        "thumb_functions.json",
        runtime,
        || {
            |_, _, function| {
                let Some(object) = function.as_object_mut() else {
                    return Ok(());
                };
                let Some(body_c) = object.get("body_c").and_then(|value| value.as_str()) else {
                    return Ok(());
                };
                let renamed = apply_rename_map(body_c, &renames);
                if renamed != body_c {
                    object.insert("body_c".into(), serde_json::Value::String(renamed));
                }
                Ok(())
            }
        },
    )
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
fn load_global_names_bytes(bytes: &[u8]) -> HashSet<String> {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(bytes) else {
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

struct SymbolicationInputFiles {
    disasm: Option<File>,
    source_manifest: Option<File>,
    source_index: Option<File>,
    functions: File,
    thumb_functions: Option<File>,
    globals: Option<File>,
}

impl SymbolicationInputFiles {
    fn from_path(image_dir: &Path) -> Result<Self> {
        let decompiled = image_dir.join("decompiled");
        let source_tree = image_dir.join("source_tree");
        Ok(Self {
            disasm: open_optional_path_file(&decompiled.join("disasm.lst"))?,
            source_manifest: open_optional_path_file(&source_tree.join("manifest.json"))?,
            source_index: open_optional_path_file(&source_tree.join("recovered_index.json"))?,
            functions: File::open(decompiled.join("functions.json"))?,
            thumb_functions: open_optional_path_file(&decompiled.join("thumb_functions.json"))?,
            globals: open_optional_path_file(&decompiled.join("globals.json"))?,
        })
    }

    fn from_trusted(image: &TrustedDirectory) -> Result<(TrustedDirectory, Self)> {
        let decompiled = image
            .open_directory_child("decompiled", "final symbolication decompiled directory")?
            .ok_or_else(|| {
                Error::Serialize("final symbolication decompiled directory is missing".into())
            })?;
        let source_tree = image
            .open_directory_child("source_tree", "final symbolication source-tree directory")?;
        let source_manifest = match &source_tree {
            Some(source_tree) => open_optional_trusted_file(
                source_tree,
                "manifest.json",
                "final symbolication source-tree manifest",
            )?,
            None => None,
        };
        let source_index = match &source_tree {
            Some(source_tree) => open_optional_trusted_file(
                source_tree,
                "recovered_index.json",
                "final symbolication recovered source index",
            )?,
            None => None,
        };
        let files = Self {
            disasm: open_optional_trusted_file(
                &decompiled,
                "disasm.lst",
                "final symbolication disassembly",
            )?,
            source_manifest,
            source_index,
            functions: decompiled.open_regular_file(
                Path::new("functions.json"),
                "final symbolication Ghidra functions",
            )?,
            thumb_functions: open_optional_trusted_file(
                &decompiled,
                "thumb_functions.json",
                "final symbolication Thumb functions",
            )?,
            globals: open_optional_trusted_file(
                &decompiled,
                "globals.json",
                "final symbolication globals",
            )?,
        };
        Ok((decompiled, files))
    }
}

fn open_optional_path_file(path: &Path) -> Result<Option<File>> {
    match File::open(path) {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn open_optional_trusted_file(
    directory: &TrustedDirectory,
    file_name: &str,
    context: &str,
) -> Result<Option<File>> {
    if !directory.regular_file_exists(file_name, context)? {
        return Ok(None);
    }
    directory
        .open_regular_file(Path::new(file_name), context)
        .map(Some)
}

fn read_open_file(mut file: File) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[derive(Clone, Copy)]
pub(crate) enum SymbolBuildPurpose<'a> {
    Pass2 {
        exception_application: Option<&'a ExceptionPass2Context>,
        pal_application: Option<&'a PalPass2Context>,
    },
    FinalArtifact,
}

fn pass2_role_owns_current_primary(
    owner: FunctionOwner,
    exception: Option<&ExceptionApplicationRef>,
    pal: Option<&PalApplicationRef>,
    current_primary: &str,
) -> bool {
    owner == FunctionOwner::Ghidra
        && (exception.is_some_and(ExceptionApplicationRef::owns_current_primary)
            || pal.is_some_and(|application| application.desired_primary == current_primary))
}

fn registration_for_record(
    current_primary: &str,
    role_owns_current_primary: bool,
    candidate: Option<&String>,
) -> Option<String> {
    if is_real_name(current_primary) && !role_owns_current_primary {
        None
    } else {
        candidate.cloned()
    }
}

/// Per-image ss discovery outcome carried beside `build_map` symbols.
/// Absent → all None; Present → Some(counts); Failed → error Some, counts None.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SsReport {
    pub recovered: Option<usize>,
    pub conflicts: Option<usize>,
    pub error: Option<String>,
}

impl SsReport {
    const fn absent() -> Self {
        Self {
            recovered: None,
            conflicts: None,
            error: None,
        }
    }
}

fn ss_container_from_func(f: &FuncRec<'_>) -> Option<ss::SsContainer> {
    let entry = u32::try_from(f.entry).ok()?;
    let execution = f.execution.as_ref()?;
    let first = execution.decode_ranges.first()?;
    let isa = first.isa;
    Some(ss::SsContainer {
        entry,
        isa,
        ranges: execution
            .decode_ranges
            .iter()
            .map(|range| (range.start, range.end))
            .collect(),
        ghidra: f.owner == FunctionOwner::Ghidra,
    })
}

fn ss_name_for(
    entry: u64,
    isa: DecodeIsa,
    names: &BTreeMap<(u32, DecodeIsa), String>,
) -> Option<String> {
    let entry = u32::try_from(entry).ok()?;
    names.get(&(entry, isa)).cloned().or_else(|| {
        let stripped = entry & !1;
        (stripped != entry)
            .then(|| names.get(&(stripped, isa)).cloned())
            .flatten()
    })
}

/// Pure: build the per-image `Symbol` set from pass-1 outputs. No file writes.
/// `pal` supplies the authenticated PAL task state when the generation claims
/// one; it attaches `pal_task` evidence per exact entry and lets the
/// registration rank displace an applied task primary (which is a "real"
/// name every other tier must defer to).
#[cfg(test)]
pub(crate) fn build_map(
    image_dir: &Path,
    image_label: &str,
    tokens: &HashMap<u32, String>,
    manifest: &Path,
    roles: &role_evidence::AuthenticatedRoleEvidence,
    purpose: SymbolBuildPurpose<'_>,
) -> Result<(Vec<Symbol>, SsReport)> {
    let load_addr = crate::manifest::load_addr_for_image(manifest, image_label)?
        .ok_or_else(|| Error::Serialize(format!("load_addr missing for {image_label}")))?;
    let image_bytes = std::fs::read(image_dir.join(format!("{image_label}.bin")))?;
    let runtime = thumb_runtime(image_dir, &image_bytes, load_addr)?;
    build_map_from_runtime(
        image_dir,
        tokens,
        &image_bytes,
        load_addr,
        &runtime,
        roles,
        purpose,
    )
}

#[cfg(test)]
pub(crate) fn build_final_map_from_runtime(
    image_dir: &Path,
    tokens: &HashMap<u32, String>,
    image_bytes: &[u8],
    load_addr: u64,
    runtime: &RuntimeImage<'_>,
    roles: &role_evidence::AuthenticatedRoleEvidence,
) -> Result<(Vec<Symbol>, SsReport)> {
    build_map_from_runtime(
        image_dir,
        tokens,
        image_bytes,
        load_addr,
        runtime,
        roles,
        SymbolBuildPurpose::FinalArtifact,
    )
}

fn build_final_map_from_trusted(
    image: &TrustedDirectory,
    tokens: &HashMap<u32, String>,
    image_bytes: &[u8],
    load_addr: u64,
    runtime: &RuntimeImage<'_>,
    roles: &role_evidence::AuthenticatedRoleEvidence,
) -> Result<(TrustedDirectory, Vec<Symbol>, SsReport)> {
    let (decompiled, inputs) = SymbolicationInputFiles::from_trusted(image)?;
    let (symbols, ss) = build_map_from_input_files(
        inputs,
        tokens,
        image_bytes,
        load_addr,
        runtime,
        roles,
        SymbolBuildPurpose::FinalArtifact,
    )?;
    Ok((decompiled, symbols, ss))
}

#[allow(clippy::too_many_arguments)]
fn build_map_from_runtime(
    image_dir: &Path,
    tokens: &HashMap<u32, String>,
    image_bytes: &[u8],
    load_addr: u64,
    runtime: &RuntimeImage<'_>,
    roles: &role_evidence::AuthenticatedRoleEvidence,
    purpose: SymbolBuildPurpose<'_>,
) -> Result<(Vec<Symbol>, SsReport)> {
    if let SymbolBuildPurpose::Pass2 {
        exception_application,
        pal_application,
    } = purpose
    {
        if let Some(application) = exception_application {
            let evidence = roles.exception().present().ok_or_else(|| {
                Error::Serialize(
                    "exception pass-2 application has no authenticated role evidence".into(),
                )
            })?;
            if application.identity() != evidence.identity()
                || application.manifest_blake3()
                    != crate::manifest::blake3_fixed(evidence.manifest_blake3())
            {
                return Err(Error::Serialize(
                    "exception pass-2 application does not match authenticated role evidence"
                        .into(),
                ));
            }
        }
        if let Some(application) = pal_application {
            let evidence = roles.pal().present().ok_or_else(|| {
                Error::Serialize("PAL pass-2 application has no authenticated role evidence".into())
            })?;
            if application.identity != evidence.identity()
                || application.manifest_blake3
                    != crate::manifest::blake3_fixed(evidence.manifest_blake3())
                || application.scatter_load_map_blake3
                    != evidence
                        .scatter_load_map_blake3()
                        .map(crate::manifest::blake3_fixed)
            {
                return Err(Error::Serialize(
                    "PAL pass-2 application does not match authenticated role evidence".into(),
                ));
            }
        }
    }
    build_map_from_input_files(
        SymbolicationInputFiles::from_path(image_dir)?,
        tokens,
        image_bytes,
        load_addr,
        runtime,
        roles,
        purpose,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_map_from_input_files(
    mut inputs: SymbolicationInputFiles,
    tokens: &HashMap<u32, String>,
    image_bytes: &[u8],
    load_addr: u64,
    runtime: &RuntimeImage<'_>,
    roles: &role_evidence::AuthenticatedRoleEvidence,
    purpose: SymbolBuildPurpose<'_>,
) -> Result<(Vec<Symbol>, SsReport)> {
    let disasm = match inputs.disasm.take() {
        Some(file) => String::from_utf8(read_open_file(file)?).unwrap_or_default(),
        None => String::new(),
    };
    let index = crate::disasm_index::DisasmIndex::new(&disasm);

    let (file_occ, file_strings) = match inputs.source_manifest.take() {
        Some(file) => load_file_occurrences_bytes(&read_open_file(file)?)?,
        None => (HashSet::new(), HashMap::new()),
    };
    let attribution = match inputs.source_index.take() {
        Some(file) => load_attribution_bytes(&read_open_file(file)?)?,
        None => BTreeMap::new(),
    };

    let mut funcs = load_functions_file(inputs.functions, &index, runtime)?;
    if let Some(thumb_functions) = inputs.thumb_functions {
        funcs.extend(load_thumb_functions_file(thumb_functions, runtime)?);
    }

    let string_map = build_string_map(image_bytes, load_addr, 3);

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
        if is_real_name(&f.current_primary) {
            fn_names.insert(f.current_primary.clone());
        }
        if is_real_name(&f.name) {
            fn_names.insert(f.name.clone());
        }
        if let Some(n) = &recovered_names[i] {
            fn_names.insert(n.clone());
        }
    }
    let globals_present = inputs.globals.is_some();
    let global_names = match inputs.globals {
        Some(file) => load_global_names_bytes(&read_open_file(file)?),
        None => HashSet::new(),
    };

    // Registration-table tier (authoritative). Scans the raw image for
    // `{name, fn}` tables whose pointer resolves to a known function entry.
    let fn_entries: HashMap<u64, &'static str> = funcs.iter().map(|f| (f.entry, f.arch)).collect();
    let reg_names: HashMap<u64, String> = reg_table::scan(
        image_bytes,
        load_addr,
        &fn_entries,
        &global_names,
        &fn_names,
    )
    .names;

    let containers: Vec<ss::SsContainer> =
        funcs.iter().filter_map(ss_container_from_func).collect();
    let (ss_report, ss_names) = match ss::discover(runtime, &containers, &global_names, &fn_names) {
        ss::SsOutcome::Absent => (SsReport::absent(), BTreeMap::new()),
        ss::SsOutcome::Present(plan) => (
            SsReport {
                recovered: Some(plan.names.len()),
                conflicts: Some(plan.conflicts),
                error: None,
            },
            plan.names,
        ),
        ss::SsOutcome::Failed(error) => (
            SsReport {
                recovered: None,
                conflicts: None,
                error: Some(error.to_string()),
            },
            BTreeMap::new(),
        ),
    };

    // String-reference guess tier (fail-closed, lowest precedence). Active only
    // when the raw image (=> non-empty string_map) and globals.json are present.
    let string_ref_enabled = !string_map.is_empty() && globals_present;
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
        // PAL applications match on the record's actual decode ISA — Ghidra
        // records carry the family label "arm" even for Thumb projections.
        let record_isa = f
            .execution
            .as_ref()
            .and_then(|e| e.decode_ranges.first())
            .map_or(f.arch, |range| match range.isa {
                crate::execution_ranges::DecodeIsa::Arm => "arm",
                crate::execution_ranges::DecodeIsa::Thumb => "thumb",
            });
        let record_decode_isa = match record_isa {
            "arm" => DecodeIsa::Arm,
            "thumb" => DecodeIsa::Thumb,
            _ => {
                return Err(Error::Serialize(format!(
                    "symbolicate: unsupported record decode ISA {record_isa:?}"
                )));
            }
        };
        let entry = u32::try_from(f.entry).ok();
        let exception_set = roles.exception().present();
        let exception_application = exception_set
            .and_then(|set| entry.and_then(|entry| set.application(entry, record_decode_isa)));
        let exception_app = exception_application.map(ExceptionRoleRefSet::from_role_application);
        let exception_manifest_blake3 = exception_set
            .filter(|_| exception_application.is_some())
            .map(|set| crate::manifest::blake3_fixed(set.manifest_blake3()));
        let pal_set = roles.pal().present();
        let pal_application = pal_set
            .and_then(|set| entry.and_then(|entry| set.application(entry, record_decode_isa)));
        let pal_app = pal_application.map(|application| {
            PalRoleRefSet::from_role_application(
                application,
                pal_set.expect("matched PAL application").manifest_blake3(),
            )
        });
        let startup_set = roles.startup().present();
        let startup_application = startup_set
            .and_then(|set| entry.and_then(|entry| set.application(entry, record_decode_isa)));
        let startup_app = startup_application.map(StartupRoleRefSet::from_role_application);
        let startup_manifest_blake3 = startup_set
            .filter(|_| startup_application.is_some())
            .map(|set| crate::manifest::blake3_fixed(set.manifest_blake3()));
        let (
            exception_proposed_primary,
            pal_proposed_primary,
            startup_proposed_primary,
            role_owns_current_primary,
        ) = match purpose {
            SymbolBuildPurpose::Pass2 {
                exception_application: exception_context,
                pal_application: pal_context,
            } => {
                let applied_exception = exception_context.and_then(|context| {
                    entry.and_then(|entry| context.application(&(entry, record_decode_isa)))
                });
                if let Some(applied) = applied_exception {
                    let role = exception_app.as_ref().ok_or_else(|| {
                        Error::Serialize(format!(
                            "exception application at 0x{:08x} has no authenticated role evidence",
                            f.entry
                        ))
                    })?;
                    if !role.matches_pass2(applied) {
                        return Err(Error::Serialize(format!(
                            "exception application at 0x{:08x} differs from authenticated role evidence",
                            f.entry
                        )));
                    }
                    if f.owner == FunctionOwner::Ghidra
                        && applied.current_primary().name() != f.current_primary
                    {
                        return Err(Error::Serialize(format!(
                            "exception application current primary does not match the retained record at 0x{:08x}",
                            f.entry
                        )));
                    }
                }
                let applied_pal = pal_context
                    .and_then(|context| entry.and_then(|entry| context.applications.get(&entry)))
                    .filter(|application| application.isa == record_isa);
                if let Some(applied) = applied_pal {
                    let role = pal_app.as_ref().ok_or_else(|| {
                        Error::Serialize(format!(
                            "PAL application at 0x{:08x} has no authenticated role evidence",
                            f.entry
                        ))
                    })?;
                    if !role.matches_pass2(applied) {
                        return Err(Error::Serialize(format!(
                            "PAL application at 0x{:08x} differs from authenticated role evidence",
                            f.entry
                        )));
                    }
                }
                let startup_proposed_primary = startup_app
                    .as_ref()
                    .map(|role| role.desired_primary().to_string());
                let role_owns_current_primary = pass2_role_owns_current_primary(
                    f.owner,
                    applied_exception,
                    applied_pal,
                    &f.current_primary,
                ) || startup_proposed_primary
                    .as_deref()
                    .is_some_and(|primary| primary == f.current_primary);
                (
                    applied_exception
                        .filter(|application| application.proposes_exception_primary())
                        .and_then(|_| exception_app.as_ref()?.desired_primary().map(str::to_owned)),
                    applied_pal
                        .filter(|_| pal_app.as_ref().is_some_and(|role| role.tasks.len() == 1))
                        .filter(|_| {
                            pal_app
                                .as_ref()
                                .is_some_and(|role| role.desired_primary == f.current_primary)
                        })
                        .and_then(|_| pal_app.as_ref().map(|role| role.desired_primary.clone())),
                    startup_proposed_primary,
                    role_owns_current_primary,
                )
            }
            SymbolBuildPurpose::FinalArtifact => {
                let exception_proposed_primary = exception_app
                    .as_ref()
                    .and_then(ExceptionRoleRefSet::desired_primary)
                    .filter(|primary| *primary == f.current_primary)
                    .map(str::to_owned);
                let pal_proposed_primary = pal_app
                    .as_ref()
                    .filter(|role| {
                        role.tasks.len() == 1 && role.desired_primary == f.current_primary
                    })
                    .map(|role| role.desired_primary.clone());
                let startup_proposed_primary = startup_app
                    .as_ref()
                    .map(StartupRoleRefSet::desired_primary)
                    .filter(|primary| *primary == f.current_primary)
                    .map(str::to_owned);
                let role_owns_current_primary = exception_proposed_primary.is_some()
                    || pal_proposed_primary.is_some()
                    || startup_proposed_primary.is_some();
                (
                    exception_proposed_primary,
                    pal_proposed_primary,
                    startup_proposed_primary,
                    role_owns_current_primary,
                )
            }
        };
        let claim = attribution.get(&FunctionEvidenceKey {
            owner: f.owner,
            entry: f.entry,
            execution_blake3: f.execution.as_ref().map(|e| e.execution_blake3),
        });
        let file = claim.map(|claim| claim.path.clone());
        // Exact DBT trace attribution rides the same lookup: only a DbtExact
        // winner carries dbt-source evidence. Attribution resolves to one
        // path per key, so the list is distinct and sorted by construction.
        let dbt_sources = match claim {
            Some(claim) if claim.confidence == Confidence::DbtExact => vec![claim.path.clone()],
            _ => Vec::new(),
        };
        let fstrings = file
            .as_ref()
            .and_then(|p| file_strings.get(p))
            .cloned()
            .unwrap_or_default();

        // Lowest precedence: only when neither `__func__` nor a token fired.
        let ident_guess = if string_ref_enabled
            && func_name.is_none()
            && hits.is_empty()
            && !is_real_name(&f.current_primary)
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

        // A role-owned primary may be displaced by stronger registration
        // evidence. A preserved foreign primary remains authoritative.
        let raw = RawEvidence {
            func_name,
            tokens: hits,
            file,
            file_strings: fstrings,
            dbt_sources,
            ident_guess,
            registration: registration_for_record(
                &f.current_primary,
                role_owns_current_primary,
                reg_names.get(&f.entry),
            ),
            ss: ss_name_for(f.entry, record_decode_isa, &ss_names),
            exception_manifest_blake3,
            exception: exception_app,
            exception_proposed_primary,
            pal: pal_app,
            pal_proposed_primary,
            startup_manifest_blake3,
            startup: startup_app,
            startup_proposed_primary,
        };
        let (name, tier, evidence, annotations, name_conflicts) = decide(&addr_hex, &raw);
        symbols.push(Symbol {
            address: format!("0x{addr_hex}"),
            arch: f.arch,
            tool: f.tool,
            owner: f.owner,
            execution_blake3: f.execution.as_ref().map(|e| e.execution_blake3),
            decode_ranges: f
                .execution
                .as_ref()
                .map(|e| {
                    e.decode_ranges
                        .iter()
                        .map(DecodeRangeWire::from_authenticated)
                        .collect()
                })
                .unwrap_or_default(),
            original_name: f.name.clone(),
            name,
            tier,
            evidence,
            annotations,
            name_conflicts,
        });
    }
    finalize_names(&mut symbols);
    Ok((symbols, ss_report))
}

/// Apply the built symbols to a per-image `decompiled/` dir in place; returns
/// the `symbols.json` path. `rewrite_decompiled_c = false` skips the text
/// rewrite of `decompiled.c` / `disasm.lst` (the two-pass decompose path
/// regenerates them from Ghidra).
#[cfg(test)]
fn finalize_image(
    image_dir: &Path,
    image_label: &str,
    runtime: &crate::runtime_image::RuntimeImage<'_>,
    symbols: &[Symbol],
    opts: &FinalizeOpts,
) -> Result<PathBuf> {
    let decompiled = image_dir.join("decompiled");
    rewrite_functions_json(&decompiled, runtime, symbols)?;
    if opts.rewrite_decompiled_c {
        rewrite_text_files(&decompiled, runtime, symbols)?;
    }
    let mut inputs = HashMap::new();
    let functions = std::fs::read(decompiled.join("functions.json"))?;
    inputs.insert(
        "functions_json_blake3".into(),
        crate::manifest::blake3_bytes(&functions),
    );
    write_symbols_json(&decompiled, image_label, symbols, inputs)
}

fn finalize_image_trusted(
    image_dir: &Path,
    decompiled: &TrustedDirectory,
    image_label: &str,
    runtime: &RuntimeImage<'_>,
    symbols: &[Symbol],
    opts: &FinalizeOpts,
) -> Result<PathBuf> {
    rewrite_functions_json_trusted(decompiled, runtime, symbols)?;
    if opts.rewrite_decompiled_c {
        rewrite_text_files_trusted(decompiled, runtime, symbols)?;
    }
    let functions = read_open_file(decompiled.open_regular_file(
        Path::new("functions.json"),
        "final symbolication Ghidra functions",
    )?)?;
    let inputs = HashMap::from([(
        "functions_json_blake3".into(),
        crate::manifest::blake3_bytes(&functions),
    )]);
    write_symbols_json_trusted(decompiled, image_label, symbols, inputs)?;
    Ok(image_dir.join("decompiled/symbols.json"))
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
    let image = std::fs::read(image_dir.join(format!("{image_label}.bin")))?;
    let load_addr = crate::manifest::load_addr_for_image(manifest, image_label)?
        .ok_or_else(|| Error::Serialize(format!("load_addr missing for {image_label}")))?;
    let runtime = thumb_runtime(image_dir, &image, load_addr)?;
    let context = role_evidence::CurrentSymbolicationContext::new(
        role_evidence::RuntimeBinding::new(
            image_label,
            crate::manifest::toc_name(image_label),
            u32::try_from(load_addr)
                .map_err(|_| Error::Serialize("test load address exceeds u32".into()))?,
            *blake3::hash(&image).as_bytes(),
            role_evidence::ArtifactState::Unmanaged,
        ),
        role_evidence::ArtifactState::Unmanaged,
        role_evidence::ArtifactState::Unmanaged,
        role_evidence::ArtifactState::Unmanaged,
    )?;
    let (symbols, _) = build_final_map_from_runtime(
        image_dir,
        tokens,
        &image,
        load_addr,
        &runtime,
        context.roles(),
    )?;
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

fn load_symbolication_tokens(opts: &Opts) -> Result<HashMap<u32, String>> {
    match &opts.token_db {
        Some(path) if path.exists() => Ok(token_map(&crate::tokens::parse(&std::fs::read(path)?)?)),
        _ => {
            tracing::warn!("symbolicate: no token DB — token evidence skipped");
            Ok(HashMap::new())
        }
    }
}

pub(crate) fn run_current(
    root: &Path,
    opts: &Opts,
    contexts: &HashMap<String, std::sync::Arc<role_evidence::CurrentSymbolicationContext>>,
) -> Result<PathBuf> {
    let root = std::fs::canonicalize(root)?;
    let images = root.join("images");
    let tokens = load_symbolication_tokens(opts)?;
    let mut labels = contexts.keys().cloned().collect::<Vec<_>>();
    labels.sort();

    for label in &labels {
        let image_dir = images.join(label);
        contexts[label].validate(&image_dir, |_, _, _, _| Ok(()))?;
    }

    for label in &labels {
        let image_dir = images.join(label);
        let output =
            contexts[label].validate(&image_dir, |trusted_image, image, runtime, roles| {
                let (decompiled, symbols, _) = build_final_map_from_trusted(
                    trusted_image,
                    &tokens,
                    image,
                    u64::from(contexts[label].runtime().image_base()),
                    runtime,
                    roles,
                )?;
                finalize_image_trusted(
                    &image_dir,
                    &decompiled,
                    label,
                    runtime,
                    &symbols,
                    &FinalizeOpts {
                        rewrite_decompiled_c: opts.rewrite_decompiled_c,
                    },
                )
            })?;
        println!("symbolicated {label} -> {}", output.display());
    }
    println!("symbolicate: {} image(s)", labels.len());
    Ok(root)
}

/// Symbolicate every image under `<root>/images/*` that has a `decompiled/` dir.
/// `opts.token_db` is the raw pw_token_db (TOKENS); without it, token evidence is
/// skipped. Returns `root`.
pub fn run(root: &Path, opts: &Opts) -> Result<PathBuf> {
    let root = std::fs::canonicalize(root)?;
    let manifest = root.join("manifest.json");
    let images = root.join("images");
    let mut contexts = HashMap::new();
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
        let load_addr = crate::manifest::load_addr_for_image(&manifest, &label)?
            .ok_or_else(|| Error::Serialize(format!("load_addr missing for {label}")))?;
        let load_addr = u32::try_from(load_addr).map_err(|_| {
            Error::Serialize(format!(
                "load_addr for {label} exceeds the u32 address domain"
            ))
        })?;
        let context = role_evidence::CurrentSymbolicationContext::from_retained(
            &dir,
            &label,
            crate::manifest::toc_name(&label),
            load_addr,
        )?;
        contexts.insert(label, std::sync::Arc::new(context));
    }
    run_current(&root, opts, &contexts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_map(
        image_dir: &Path,
        image_label: &str,
        tokens: &HashMap<u32, String>,
        manifest: &Path,
        exception_application: Option<&ExceptionPass2Context>,
        pal_application: Option<&PalPass2Context>,
    ) -> Result<Vec<Symbol>> {
        let load_addr = crate::manifest::load_addr_for_image(manifest, image_label)?
            .ok_or_else(|| Error::Serialize(format!("load_addr missing for {image_label}")))?;
        let image_base = u32::try_from(load_addr)
            .map_err(|_| Error::Serialize("test load address exceeds u32".into()))?;
        let image = std::fs::read(image_dir.join(format!("{image_label}.bin")))?;
        let binding = role_evidence::RuntimeBinding::new(
            image_label,
            crate::manifest::toc_name(image_label),
            image_base,
            *blake3::hash(&image).as_bytes(),
            role_evidence::ArtifactState::Unmanaged,
        );
        let context = if image_dir.join("exception_roots/roots.json").is_file()
            || image_dir.join("pal_tasks/tasks.json").is_file()
        {
            role_evidence::CurrentSymbolicationContext::from_retained(
                image_dir,
                image_label,
                crate::manifest::toc_name(image_label),
                image_base,
            )?
        } else if let Some(pal) = pal_application {
            role_evidence::context_from_test_pal_pass2(binding, pal)?
        } else {
            role_evidence::CurrentSymbolicationContext::new(
                binding,
                role_evidence::ArtifactState::Unmanaged,
                role_evidence::ArtifactState::Unmanaged,
                role_evidence::ArtifactState::Unmanaged,
            )?
        };
        let (symbols, _) = super::build_map(
            image_dir,
            image_label,
            tokens,
            manifest,
            context.roles(),
            SymbolBuildPurpose::Pass2 {
                exception_application,
                pal_application,
            },
        )?;
        Ok(symbols)
    }

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
            .execution
            .as_ref()
            .map(|e| e.execution_blake3)
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
            dbt_sources: vec![],
            ident_guess: None,
            registration: None,
            ss: None,
            exception_manifest_blake3: None,
            exception: None,
            exception_proposed_primary: None,
            pal: None,
            pal_proposed_primary: None,
            startup_manifest_blake3: None,
            startup: None,
            startup_proposed_primary: None,
        }
    }

    #[test]
    fn func_name_is_a_recovered_rename() {
        let r = RawEvidence {
            func_name: Some("LteRrc_Reestab".into()),
            ..raw()
        };
        let (name, tier, ev, _ann, _) = decide("40e1bff4", &r);
        assert_eq!(name.as_deref(), Some("LteRrc_Reestab"));
        assert_eq!(tier, Tier::Recovered);
        assert_eq!(ev[0].kind(), "func");
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
        let (name, tier, _ev, ann, _) = decide("40e1bff4", &r);
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
        let (name, tier, _ev, ann, _) = decide("40e1bff4", &r);
        assert_eq!(name, None);
        assert_eq!(tier, Tier::None);
        assert!(ann.iter().any(|a| a.starts_with("file: HEDGE/LteRrc.c")));
        assert!(ann.iter().any(|a| a.starts_with("file-strings:")));
    }

    #[test]
    fn dbt_exact_attribution_yields_dbt_source_evidence_and_annotation() {
        let r = RawEvidence {
            dbt_sources: vec!["modem/pal/msg.c".into()],
            ..raw()
        };
        let (name, tier, ev, ann, conflicts) = decide("40e1bff4", &r);
        // Annotation-only: no name proposal, no rank occupied, record-only tier.
        assert_eq!(name, None);
        assert_eq!(tier, Tier::None);
        assert!(conflicts.is_empty());
        assert!(ann.iter().any(|a| a == "dbt-source: modem/pal/msg.c"));
        assert!(ev.iter().any(|e| matches!(
            e,
            TaggedEvidence::DbtSource { path } if path == "modem/pal/msg.c"
        )));
    }

    #[test]
    fn dbt_annotations_are_bounded_to_six_distinct_paths() {
        let r = RawEvidence {
            dbt_sources: (1..=8).map(|i| format!("src/f{i}.c")).collect(),
            ..raw()
        };
        let (_name, tier, ev, ann, _) = decide("40e1bff4", &r);
        assert_eq!(tier, Tier::None);
        let dbt_ann: Vec<&String> = ann
            .iter()
            .filter(|a| a.starts_with("dbt-source: "))
            .collect();
        assert_eq!(dbt_ann.len(), 6, "annotations were {ann:?}");
        assert_eq!(dbt_ann[0], "dbt-source: src/f1.c");
        assert_eq!(dbt_ann[5], "dbt-source: src/f6.c");
        assert_eq!(ev.iter().filter(|e| e.kind() == "dbt_source").count(), 6);
    }

    #[test]
    fn dbt_evidence_never_changes_a_winning_name_or_tier() {
        // A recovered __func__ plus dbt evidence: the annotation rides along
        // without touching the name or tier the stronger evidence won.
        let r = RawEvidence {
            func_name: Some("Real_Name".into()),
            dbt_sources: vec!["modem/pal/msg.c".into()],
            ..raw()
        };
        let (name, tier, _ev, ann, _) = decide("40e1bff4", &r);
        assert_eq!(name.as_deref(), Some("Real_Name"));
        assert_eq!(tier, Tier::Recovered);
        assert!(ann.iter().any(|a| a == "dbt-source: modem/pal/msg.c"));
    }

    #[test]
    fn ident_guess_yields_marked_string_ref_guess() {
        let r = RawEvidence {
            ident_guess: Some(("RF_SM_Set_ET_Voltage".into(), name_guess::Class::FnName)),
            ..raw()
        };
        let (name, tier, ev, ann, _) = decide("40e1bff4", &r);
        let name = name.unwrap();
        assert!(name.starts_with(GUESS_PREFIX), "not marked: {name}");
        assert!(name.contains("RF_SM_Set_ET_Voltage"));
        assert!(name.ends_with("40e1bff4"), "no address: {name}");
        assert_eq!(tier, Tier::Provisional);
        let e = ev
            .iter()
            .find_map(|e| match e {
                TaggedEvidence::StringRef { value, class } => Some((value, *class)),
                _ => None,
            })
            .unwrap();
        assert_eq!(e.1, "fn_name");
        assert!(ann.iter().any(|a| a.contains("RF_SM_Set_ET_Voltage")));
    }

    #[test]
    fn func_name_beats_ident_guess() {
        let r = RawEvidence {
            func_name: Some("Real_Name".into()),
            ident_guess: Some(("Other".into(), name_guess::Class::FnName)),
            ..raw()
        };
        let (name, tier, _ev, _ann, _) = decide("40e1bff4", &r);
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
        let (name, tier, ev, _ann, _) = decide("40e1bff4", &r);
        let name = name.unwrap();
        assert!(name.contains("hi"), "token must outrank string_ref: {name}");
        assert_eq!(tier, Tier::Provisional);
        // Lower-rank evidence is retained, never dropped.
        assert!(ev.iter().any(|e| e.kind() == "token"));
        assert!(ev.iter().any(|e| e.kind() == "string_ref"));
    }

    #[test]
    fn registration_is_a_recovered_bare_name() {
        let r = RawEvidence {
            registration: Some("AtiParsePlusCOPS".into()),
            ..raw()
        };
        let (name, tier, ev, _ann, _) = decide("411b8f04", &r);
        assert_eq!(name.as_deref(), Some("AtiParsePlusCOPS")); // bare, no guess_ prefix
        assert_eq!(tier, Tier::Recovered);
        assert!(ev.iter().any(|e| e.kind() == "registration"));
    }

    #[test]
    fn func_name_beats_registration() {
        let r = RawEvidence {
            func_name: Some("Real_Name".into()),
            registration: Some("Registered_Name".into()),
            ..raw()
        };
        let (name, tier, ev, _ann, _) = decide("411b8f04", &r);
        assert_eq!(name.as_deref(), Some("Real_Name"));
        assert_eq!(tier, Tier::Recovered);
        // the registration name is still recorded as evidence
        assert!(ev.iter().any(|e| e.kind() == "registration"));
    }

    #[test]
    fn registration_beats_token_and_string_ref() {
        let r = RawEvidence {
            registration: Some("PICH_HISR".into()),
            tokens: vec![(0x3c2a, "■format♦hi■domain♦D".into())],
            ident_guess: Some(("Other".into(), name_guess::Class::FnName)),
            ..raw()
        };
        let (name, tier, _ev, _ann, _) = decide("437436f0", &r);
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
                decode_ranges: Vec::new(),
                name_conflicts: Vec::new(),
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
                decode_ranges: Vec::new(),
                name_conflicts: Vec::new(),
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
        assert!(fns[0].execution.is_some());
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
            r#"{"sources":{"A/x.c":{"functions":[{"tool":"ghidra","entry":"0x10","confidence":"direct"}]}}}"#,
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
            .map(|claim| (claim.path.as_str(), claim.confidence)),
            Some(("A/x.c", Confidence::Direct))
        );
    }

    #[test]
    fn load_attribution_keeps_distinct_tool_claims_at_the_same_entry() {
        let dir = tmp("pme_sym_attr_tools");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("recovered_index.json"),
            r#"{"sources":{
            "ghidra/a.c":{"functions":[{"tool":"ghidra","entry":"0x10","confidence":"direct"}]},
            "r2/b.c":{"functions":[{"tool":"radare2","entry":"0x10","confidence":"direct"}]}
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
            .map(|claim| claim.path.as_str()),
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
            .map(|claim| claim.path.as_str()),
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
                        "execution_blake3": digest(funcs[0].execution.as_ref().unwrap().execution_blake3),
                        "entry": "0x1000",
                        "confidence": "direct"
                    }]},
                    "rizin/b.c": {"functions": [{
                        "tool": "rizin",
                        "region_index": 0,
                        "run_index": 1,
                        "execution_blake3": digest(funcs[1].execution.as_ref().unwrap().execution_blake3),
                        "entry": "0x1000",
                        "confidence": "direct"
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
                    execution_blake3: funcs[0].execution.as_ref().map(|e| e.execution_blake3),
                })
                .map(|claim| claim.path.as_str()),
            Some("r2/a.c")
        );
        assert_eq!(
            attribution
                .get(&FunctionEvidenceKey {
                    owner: funcs[1].owner,
                    entry: funcs[1].entry,
                    execution_blake3: funcs[1].execution.as_ref().map(|e| e.execution_blake3),
                })
                .map(|claim| claim.path.as_str()),
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
            decode_ranges: Vec::new(),
            name_conflicts: Vec::new(),
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
            "a.c":{"functions":[{"tool":"ghidra","entry":"0x10","confidence":"direct"}]},
            "b.c":{"functions":[{"tool":"ghidra","entry":"0x10","confidence":"direct"}]}
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
    fn load_attribution_resolves_conflicts_by_confidence() {
        // One identity claimed by a proximity row (a.c) and a dbt_exact row
        // (b.c): the stronger tier wins, no error. Two same-tier (dbt_exact)
        // claims for one identity remain a hard failure.
        let dir = tmp("pme_sym_attr_tiered");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("recovered_index.json"),
            r#"{"sources":{
            "a.c":{"functions":[{"tool":"ghidra","entry":"0x10","confidence":"proximity"}]},
            "b.c":{"functions":[{"tool":"ghidra","entry":"0x10","confidence":"dbt_exact"}]}
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
            .map(|claim| (claim.path.as_str(), claim.confidence)),
            Some(("b.c", Confidence::DbtExact))
        );

        std::fs::write(
            dir.join("recovered_index.json"),
            r#"{"sources":{
            "c.c":{"functions":[{"tool":"ghidra","entry":"0x20","confidence":"dbt_exact"}]},
            "d.c":{"functions":[{"tool":"ghidra","entry":"0x20","confidence":"dbt_exact"}]}
        }}"#,
        )
        .unwrap();
        let err = load_attribution(&dir).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("c.c") && msg.contains("d.c"), "{msg}");
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
            "ghidra/a.c":{"functions":[{"tool":"ghidra","entry":"0x10","confidence":"direct"}]},
            "r2/b.c":{"functions":[{"tool":"radare2","entry":"0x10","confidence":"direct"}]}
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
            decode_ranges: Vec::new(),
            name_conflicts: Vec::new(),
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
                decode_ranges: Vec::new(),
                name_conflicts: Vec::new(),
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
                decode_ranges: Vec::new(),
                name_conflicts: Vec::new(),
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
                decode_ranges: Vec::new(),
                name_conflicts: Vec::new(),
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
            decode_ranges: Vec::new(),
            name_conflicts: Vec::new(),
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
                decode_ranges: Vec::new(),
                name_conflicts: Vec::new(),
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
                decode_ranges: Vec::new(),
                name_conflicts: Vec::new(),
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
        let mut function = ghidra_function("FUN_10", 0x10, 0x18, &[]);
        function["thumb_creation_producer_blake3"] = serde_json::json!("11".repeat(32));
        std::fs::write(
            dir.join("functions.json"),
            serde_json::to_vec(&vec![function]).unwrap(),
        )
        .unwrap();
        let execution_blake3 = load_functions(&dir, &DisasmIndex::new(""), &test_runtime())
            .unwrap()[0]
            .execution
            .as_ref()
            .map(|e| e.execution_blake3);
        let syms = vec![Symbol {
            address: "0x10".into(),
            arch: "arm",
            tool: crate::recover_source::Tool::Ghidra,
            owner: FunctionOwner::Ghidra,
            execution_blake3,
            decode_ranges: Vec::new(),
            name_conflicts: Vec::new(),
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
        assert_eq!(v[0]["thumb_creation_producer_blake3"], "11".repeat(32));
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
            .execution
            .as_ref()
            .map(|e| e.execution_blake3);
        let syms = vec![Symbol {
            address: "0x10".into(),
            arch: "arm",
            tool: crate::recover_source::Tool::Ghidra,
            owner: FunctionOwner::Ghidra,
            execution_blake3,
            decode_ranges: Vec::new(),
            name_conflicts: Vec::new(),
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
    fn dbt_exact_attribution_surfaces_in_symbols_json() {
        let root = tmp("pme_sym_dbt_source");
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
        std::fs::write(dec.join("disasm.lst"), "0x10: 4770 bx lr\n").unwrap();
        std::fs::write(dec.join("decompiled.c"), "void FUN_10(void){}\n").unwrap();
        std::fs::write(root.join("images/02_MAIN/02_MAIN.bin"), &image).unwrap();
        let manifest = root.join("manifest.json");
        std::fs::write(&manifest, r#"{"toc":[{"name":"MAIN","load_addr":0}]}"#).unwrap();
        // One dbt_exact claim for this execution identity; a direct claim for
        // a different entry proves the population is key- and tier-gated.
        let (_, digest) = identity_for(&root.join("images/02_MAIN"), 0x10, &image, 0);
        let source_tree = root.join("images/02_MAIN/source_tree");
        std::fs::create_dir_all(&source_tree).unwrap();
        std::fs::write(
            source_tree.join("recovered_index.json"),
            format!(
                r#"{{"sources":{{
                "modem/pal/msg.c":{{"functions":[{{"tool":"ghidra","execution_blake3":"{digest}","entry":"0x10","confidence":"dbt_exact"}}]}},
                "other/prox.c":{{"functions":[{{"tool":"ghidra","entry":"0x14","confidence":"proximity"}}]}}
            }}}}"#
            ),
        )
        .unwrap();

        symbolicate_image(
            &root.join("images/02_MAIN"),
            "02_MAIN",
            &HashMap::new(),
            &manifest,
        )
        .unwrap();

        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dec.join("symbols.json")).unwrap()).unwrap();
        assert_eq!(v["format"], "pixel-modem-extractor-symbols-v5");
        assert_eq!(v["symbols"].as_array().unwrap().len(), 1);
        let symbol = &v["symbols"][0];
        let evidence = symbol["evidence"].as_array().unwrap();
        assert!(
            evidence
                .iter()
                .any(|e| e["kind"] == "dbt_source" && e["path"] == "modem/pal/msg.c")
        );
        let annotations = symbol["annotations"].as_array().unwrap();
        assert!(
            annotations
                .iter()
                .any(|a| a == "dbt-source: modem/pal/msg.c"),
            "annotations were {annotations:?}"
        );
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

        let symbols = build_map(
            &root.join("images/02_MAIN"),
            "02_MAIN",
            &tokmap,
            &manifest,
            None,
            None,
        )
        .unwrap();

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
            None,
            None,
        )
        .unwrap();
        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].tier, Tier::Provisional);
        let name = symbols[0].name.as_deref().unwrap();
        assert!(name.starts_with("guess_MyMod_DoInit_"), "got {name}");
        assert!(symbols[0].evidence.iter().any(|e| e.kind() == "string_ref"));
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
            None,
            None,
        )
        .unwrap();

        let by_addr = |a: &str| symbols.iter().find(|s| s.address == a).unwrap();
        let s = by_addr("0x40000200");
        assert_eq!(s.name.as_deref(), Some("Handler_One"));
        assert_eq!(s.tier, Tier::Recovered);
        assert!(s.evidence.iter().any(|e| e.kind() == "registration"));
        assert_eq!(by_addr("0x40000280").name.as_deref(), Some("Handler_Three"));
    }

    #[test]
    fn decide_ss_outranked_by_registration() {
        let r = RawEvidence {
            registration: Some("Handler_One".into()),
            ss: Some("ss_Foo".into()),
            ..raw()
        };
        let (name, tier, ev, _, _) = decide("40010050", &r);
        assert_eq!(name.as_deref(), Some("Handler_One"));
        assert_eq!(tier, Tier::Recovered);
        assert!(ev.iter().any(|e| e.kind() == "registration"));
        assert!(ev.iter().any(|e| e.kind() == "ss"));
    }

    #[test]
    fn decide_ss_outranks_token() {
        let r = RawEvidence {
            ss: Some("ss_Foo".into()),
            tokens: vec![(0x3c2a, "■format♦tok■domain♦D".into())],
            ..raw()
        };
        let (name, tier, ev, _, _) = decide("40010050", &r);
        assert_eq!(name.as_deref(), Some("ss_Foo"));
        assert_eq!(tier, Tier::Recovered);
        assert!(ev.iter().any(|e| e.kind() == "ss"));
        assert!(ev.iter().any(|e| e.kind() == "token"));
    }

    #[test]
    fn build_map_applies_ss_names_from_helper_callsite() {
        let root = tmp("pme_sym_ss_callsite");
        let dec = root.join("images/02_MAIN/decompiled");
        std::fs::create_dir_all(&dec).unwrap();
        const BASE: u32 = 0x4001_0000;
        const A32_ADD_R0_PC_24: [u8; 4] = [0x18, 0x00, 0x8f, 0xe2];
        const A32_BX_LR: [u8; 4] = [0x1e, 0xff, 0x2f, 0xe1];
        let a32_bl = |pc: u32, target: u32| -> [u8; 4] {
            let imm24 = target.wrapping_sub(pc.wrapping_add(8)) / 4;
            (0xeb00_0000 | (imm24 & 0x00ff_ffff)).to_le_bytes()
        };
        let mut img = vec![0u8; 0x80];
        img[0..4].copy_from_slice(&A32_ADD_R0_PC_24);
        img[4..8].copy_from_slice(&0xeb00000du32.to_le_bytes());
        img[8..12].copy_from_slice(&A32_BX_LR);
        img[32..32 + ss::SEED.len()].copy_from_slice(ss::SEED);
        img[0x40..0x44].copy_from_slice(&A32_BX_LR);
        img[0x50..0x54].copy_from_slice(&A32_ADD_R0_PC_24);
        img[0x54..0x58].copy_from_slice(&a32_bl(0x54, 0x40));
        img[0x58..0x5c].copy_from_slice(&A32_BX_LR);
        img[0x70..0x76].copy_from_slice(b"ss_Foo");
        std::fs::write(root.join("images/02_MAIN/02_MAIN.bin"), &img).unwrap();
        std::fs::write(
            dec.join("functions.json"),
            serde_json::to_vec(&vec![
                ghidra_function_in_image("FUN_40010000", BASE, BASE + 0x10, &[], &img, BASE),
                ghidra_function_in_image("FUN_40010050", BASE + 0x50, BASE + 0x60, &[], &img, BASE),
            ])
            .unwrap(),
        )
        .unwrap();
        std::fs::write(dec.join("disasm.lst"), "").unwrap();
        let manifest = root.join("manifest.json");
        std::fs::write(
            &manifest,
            r#"{"toc":[{"name":"MAIN","load_addr":1073807360}]}"#,
        )
        .unwrap();

        let image_dir = root.join("images/02_MAIN");
        let context = role_evidence::CurrentSymbolicationContext::new(
            role_evidence::RuntimeBinding::new(
                "02_MAIN",
                crate::manifest::toc_name("02_MAIN"),
                BASE,
                *blake3::hash(&img).as_bytes(),
                role_evidence::ArtifactState::Unmanaged,
            ),
            role_evidence::ArtifactState::Unmanaged,
            role_evidence::ArtifactState::Unmanaged,
            role_evidence::ArtifactState::Unmanaged,
        )
        .unwrap();
        let (symbols, report) = super::build_map(
            &image_dir,
            "02_MAIN",
            &HashMap::new(),
            &manifest,
            context.roles(),
            SymbolBuildPurpose::Pass2 {
                exception_application: None,
                pal_application: None,
            },
        )
        .unwrap();

        let by_addr = |a: &str| symbols.iter().find(|s| s.address == a).unwrap();
        let seed = by_addr("0x40010000");
        assert_eq!(seed.name.as_deref(), Some("ss_DecodeGmmFacilityMsg"));
        assert_eq!(seed.tier, Tier::Recovered);
        assert!(seed.evidence.iter().any(|e| e.kind() == "ss"));
        let foo = by_addr("0x40010050");
        assert_eq!(foo.name.as_deref(), Some("ss_Foo"));
        assert_eq!(foo.tier, Tier::Recovered);
        assert!(foo.evidence.iter().any(|e| e.kind() == "ss"));
        assert_eq!(report.recovered, Some(2));
        assert_eq!(report.conflicts, Some(0));
        assert_eq!(report.error, None);
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
            None,
            None,
        )
        .unwrap();

        let by_addr = |a: &str| symbols.iter().find(|s| s.address == a).unwrap();
        let real = by_addr("0x40000200");
        assert_eq!(real.tier, Tier::None, "real name must not be overridden");
        assert!(real.name.is_none());
        assert!(!real.evidence.iter().any(|e| e.kind() == "registration"));
        // the unnamed (FUN_) entries are still recovered
        assert_eq!(by_addr("0x40000280").name.as_deref(), Some("Handler_Three"));
    }

    #[test]
    fn pass2_preserved_pal_primary_from_current_context_blocks_registration() {
        let root = tmp("pme_sym_regtable_preserved_pal");
        let dec = root.join("images/02_MAIN/decompiled");
        std::fs::create_dir_all(&dec).unwrap();
        let mut image = vec![0u8; 0x300];
        for (offset, name) in [
            (0x100, "Handler_One"),
            (0x120, "Handler_Two"),
            (0x140, "Handler_Three"),
        ] {
            image[offset..offset + name.len()].copy_from_slice(name.as_bytes());
        }
        for (index, (name, function)) in [
            (0x4000_0100u32, 0x4000_0200u32),
            (0x4000_0120, 0x4000_0240),
            (0x4000_0140, 0x4000_0280),
        ]
        .into_iter()
        .enumerate()
        {
            let offset = 0x10 + index * 8;
            image[offset..offset + 4].copy_from_slice(&name.to_le_bytes());
            image[offset + 4..offset + 8].copy_from_slice(&function.to_le_bytes());
        }
        std::fs::write(root.join("images/02_MAIN/02_MAIN.bin"), &image).unwrap();
        std::fs::write(
            dec.join("functions.json"),
            serde_json::to_vec(&vec![
                ghidra_function_in_image(
                    "foreign_task_primary",
                    0x4000_0200,
                    0x4000_0208,
                    &[],
                    &image,
                    0x4000_0000,
                ),
                ghidra_function_in_image(
                    "FUN_240",
                    0x4000_0240,
                    0x4000_0248,
                    &[],
                    &image,
                    0x4000_0000,
                ),
                ghidra_function_in_image(
                    "FUN_280",
                    0x4000_0280,
                    0x4000_0288,
                    &[],
                    &image,
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
        let pal = pal_ctx(
            "v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:1:1",
            vec![(0x4000_0200, pal_app("pal_TaskEntry_alpha", &[("alpha", 0)]))],
        );

        let symbols = build_map(
            &root.join("images/02_MAIN"),
            "02_MAIN",
            &HashMap::new(),
            &manifest,
            None,
            Some(&pal),
        )
        .unwrap();

        let preserved = symbols
            .iter()
            .find(|symbol| symbol.address == "0x40000200")
            .unwrap();
        assert_eq!(preserved.tier, Tier::None);
        assert!(preserved.name.is_none());
        assert!(
            !preserved
                .evidence
                .iter()
                .any(|evidence| evidence.kind() == "registration")
        );
    }

    #[test]
    fn preserved_exception_and_pal_primaries_block_registration() {
        let candidate = "registration_candidate".to_string();
        let preserved = crate::decompile::test_context_from_fixture(
            crate::decompile::TestExceptionContextState::PreservedReset,
        );
        let preserved_exception = preserved
            .application(&(EXCEPTION_RESET_ENTRY, DecodeIsa::Arm))
            .unwrap();
        assert!(!pass2_role_owns_current_primary(
            FunctionOwner::Ghidra,
            Some(preserved_exception),
            None,
            "foreign_primary",
        ));
        assert_eq!(
            registration_for_record("foreign_primary", false, Some(&candidate)),
            None
        );

        let owned = crate::decompile::test_context_from_fixture(
            crate::decompile::TestExceptionContextState::Fresh,
        );
        let owned_exception = owned
            .application(&(EXCEPTION_RESET_ENTRY, DecodeIsa::Arm))
            .unwrap();
        assert!(pass2_role_owns_current_primary(
            FunctionOwner::Ghidra,
            Some(owned_exception),
            None,
            "Reset",
        ));
        assert_eq!(
            registration_for_record("Reset", true, Some(&candidate)),
            Some(candidate.clone())
        );

        let pal = pal_app("pal_TaskEntry_alpha", &[("alpha", 0)]);
        assert!(!pass2_role_owns_current_primary(
            FunctionOwner::Ghidra,
            None,
            Some(&pal),
            "foreign_task_primary",
        ));
        assert_eq!(
            registration_for_record("foreign_task_primary", false, Some(&candidate)),
            None
        );
        assert!(pass2_role_owns_current_primary(
            FunctionOwner::Ghidra,
            None,
            Some(&pal),
            "pal_TaskEntry_alpha",
        ));
        assert_eq!(
            registration_for_record("pal_TaskEntry_alpha", true, Some(&candidate)),
            Some(candidate)
        );
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
            None,
            None,
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
            None,
            None,
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
            decode_ranges: Vec::new(),
            name_conflicts: Vec::new(),
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
            decode_ranges: Vec::new(),
            name_conflicts: Vec::new(),
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
                decode_ranges: Vec::new(),
                name_conflicts: Vec::new(),
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
        std::fs::write(dec.join("functions.json"), b"[]").unwrap();
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
        std::fs::write(dec.join("functions.json"), b"[]").unwrap();
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

    #[cfg(unix)]
    #[test]
    fn finalization_namespace_swap_does_not_mutate_replacement_tree() {
        let root = tmp("pme_sym_finalize_namespace_swap");
        let image_dir = root.join("images/00_BOOT");
        let decompiled = image_dir.join("decompiled");
        std::fs::create_dir_all(&decompiled).unwrap();
        let image = vec![0u8; 0x10];
        let functions = serde_json::to_vec(&vec![ghidra_function_in_image(
            "FUN_4000",
            0x4000,
            0x4004,
            &[],
            &image,
            0x4000,
        )])
        .unwrap();
        std::fs::write(image_dir.join("00_BOOT.bin"), &image).unwrap();
        std::fs::write(decompiled.join("functions.json"), &functions).unwrap();
        let context = role_evidence::CurrentSymbolicationContext::new(
            role_evidence::RuntimeBinding::new(
                "00_BOOT",
                "BOOT",
                0x4000,
                *blake3::hash(&image).as_bytes(),
                role_evidence::ArtifactState::Unmanaged,
            ),
            role_evidence::ArtifactState::Unmanaged,
            role_evidence::ArtifactState::Unmanaged,
            role_evidence::ArtifactState::Unmanaged,
        )
        .unwrap();
        let detached = root.join("detached-image");
        let replacement_symbols = b"replacement symbols";

        let result = context.validate(&image_dir, |trusted_image, _, runtime, _| {
            std::fs::rename(&image_dir, &detached)?;
            std::fs::create_dir_all(&decompiled)?;
            std::fs::write(image_dir.join("00_BOOT.bin"), &image)?;
            std::fs::write(decompiled.join("functions.json"), &functions)?;
            std::fs::write(decompiled.join("symbols.json"), replacement_symbols)?;
            let retained_decompiled = trusted_image
                .open_directory_child("decompiled", "namespace-swap retained decompiled directory")?
                .unwrap();
            finalize_image_trusted(
                &image_dir,
                &retained_decompiled,
                "00_BOOT",
                runtime,
                &[],
                &FinalizeOpts {
                    rewrite_decompiled_c: false,
                },
            )
        });

        let error = result.unwrap_err().to_string();
        assert!(error.contains("path binding changed"), "{error}");
        assert_eq!(
            std::fs::read(decompiled.join("symbols.json")).unwrap(),
            replacement_symbols
        );
        assert_eq!(
            std::fs::read(decompiled.join("functions.json")).unwrap(),
            functions
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
        let symbols = build_map(
            &image_dir,
            "02_MAIN",
            &HashMap::new(),
            &manifest,
            None,
            None,
        )
        .unwrap();
        let string_ref = symbols
            .iter()
            .filter(|s| s.evidence.iter().any(|e| e.kind() == "string_ref"))
            .count();
        eprintln!("02_MAIN string_ref guesses: {string_ref}");
        for s in symbols
            .iter()
            .filter(|s| s.evidence.iter().any(|e| e.kind() == "string_ref"))
            .take(15)
        {
            eprintln!("  {} {}", s.address, s.name.as_deref().unwrap_or("?"));
        }
        assert!(
            string_ref > 4000,
            "string-ref yield unexpectedly low: {string_ref}"
        );
    }

    // ------------------------------------------------------------------
    // Task 11+: ranked authority + strict symbol-map v4
    // ------------------------------------------------------------------

    fn pal_ref(name: &str, index: u32) -> PalTaskRef {
        PalTaskRef {
            manifest_blake3: "b".repeat(64),
            task_index: index,
            name: name.to_string(),
            slot: 0x4001_0100,
            priority: 30,
            stack_size: 4096,
        }
    }

    fn pal_app(desired: &str, tasks: &[(&str, u32)]) -> PalApplicationRef {
        PalApplicationRef {
            isa: "arm",
            desired_primary: desired.to_string(),
            tasks: tasks
                .iter()
                .map(|&(name, index)| pal_ref(name, index))
                .collect(),
        }
    }

    fn pal_app_isa(isa: &'static str, desired: &str, tasks: &[(&str, u32)]) -> PalApplicationRef {
        PalApplicationRef {
            isa,
            ..pal_app(desired, tasks)
        }
    }

    fn raw_with_pal(pal: Option<PalApplicationRef>) -> RawEvidence {
        let pal_proposed_primary = pal
            .as_ref()
            .filter(|application| application.tasks.len() == 1)
            .map(|application| application.desired_primary.clone());
        RawEvidence {
            pal: pal.as_ref().map(PalRoleRefSet::from_pass2),
            pal_proposed_primary,
            ..raw()
        }
    }

    #[test]
    fn ss_authority_ranks_between_registration_and_exception_root() {
        assert!(Authority::Registration < Authority::Ss);
        assert!(Authority::Ss < Authority::ExceptionRoot);
        assert_eq!(Authority::Ss.as_str(), "ss");
    }

    #[test]
    fn tagged_evidence_ss_kind_is_ss() {
        let ev = TaggedEvidence::Ss {
            value: "ss_DecodeGmmFacilityMsg".into(),
        };
        assert_eq!(ev.kind(), "ss");
    }

    #[test]
    fn ranked_authority_orders_func_registration_pal_task_token_string_ref() {
        // Pairwise: each stronger rank wins over every weaker rank.
        let func = Some("Func_Winner".to_string());
        let registration = Some("Reg_Winner".to_string());
        let token = vec![(0x3c2a, "■format♦tok■domain♦D".into())];
        let ident = Some(("StringRef_Guess".to_string(), name_guess::Class::FnName));
        let pal_application = pal_app("pal_TaskEntry_alpha", &[("alpha", 0)]);
        let pal = Some(PalRoleRefSet::from_pass2(&pal_application));
        let pal_proposed_primary = Some("pal_TaskEntry_alpha".to_string());

        let (name, tier, _, _, _) = decide(
            "40e1bff4",
            &RawEvidence {
                func_name: func.clone(),
                registration: registration.clone(),
                tokens: token.clone(),
                ident_guess: ident.clone(),
                pal: pal.clone(),
                pal_proposed_primary: pal_proposed_primary.clone(),
                ..raw()
            },
        );
        assert_eq!(name.as_deref(), Some("Func_Winner"));
        assert_eq!(tier, Tier::Recovered);

        let (name, tier, _, _, _) = decide(
            "40e1bff4",
            &RawEvidence {
                registration,
                tokens: token.clone(),
                ident_guess: ident,
                pal: pal.clone(),
                pal_proposed_primary: pal_proposed_primary.clone(),
                ..raw()
            },
        );
        assert_eq!(name.as_deref(), Some("Reg_Winner"));
        assert_eq!(tier, Tier::Recovered);

        let (name, tier, _, _, _) = decide(
            "40e1bff4",
            &RawEvidence {
                tokens: token,
                ident_guess: Some(("Other".into(), name_guess::Class::FnName)),
                pal,
                pal_proposed_primary,
                ..raw()
            },
        );
        // pal_task outranks token: the task primary wins, never the guess.
        assert_eq!(name.as_deref(), Some("pal_TaskEntry_alpha"));
        assert_eq!(tier, Tier::Recovered);
        assert!(!name.unwrap().starts_with(GUESS_PREFIX));

        let (name, tier, _, _, _) = decide(
            "40e1bff4",
            &RawEvidence {
                tokens: vec![(0x3c2a, "■format♦tok■domain♦D".into())],
                ident_guess: Some(("Other".into(), name_guess::Class::FnName)),
                ..raw()
            },
        );
        // token outranks string_ref: a guess_ name, but from the token slug.
        let name = name.unwrap();
        assert!(name.starts_with(GUESS_PREFIX) && name.contains("tok"));
        assert_eq!(tier, Tier::Provisional);
    }

    #[test]
    fn lower_rank_evidence_is_retained_under_stronger_names() {
        let r = raw_with_pal(Some(pal_app("pal_TaskEntry_alpha", &[("alpha", 0)])));
        let r = RawEvidence {
            func_name: Some("Func_Winner".into()),
            registration: Some("Reg_Loser".into()),
            tokens: vec![(0x3c2a, "■format♦tok■domain♦D".into())],
            file: Some("HEDGE/x.c".into()),
            ..r
        };
        let (name, _, ev, _, _) = decide("40e1bff4", &r);
        assert_eq!(name.as_deref(), Some("Func_Winner"));
        let kinds: Vec<&str> = ev.iter().map(TaggedEvidence::kind).collect();
        for expected in ["func", "registration", "token", "file", "pal_task"] {
            assert!(
                kinds.contains(&expected),
                "evidence lost the {expected} rank: {kinds:?}"
            );
        }
    }

    #[test]
    fn same_rank_conflict_applies_no_name() {
        // Two tokens whose distinct format strings yield distinct names.
        let r = RawEvidence {
            tokens: vec![
                (0x1, "■format♦first_name■domain♦D".into()),
                (0x2, "■format♦second_name■domain♦D".into()),
            ],
            ..raw()
        };
        let (name, tier, _, _, conflicts) = decide("40e1bff4", &r);
        assert!(
            name.is_none(),
            "a same-rank conflict applied a name: {name:?}"
        );
        assert_eq!(tier, Tier::None);
        assert_eq!(conflicts.len(), 2, "both candidates must be serialized");
        let names: Vec<&str> = conflicts.iter().map(|c| c.proposed_name.as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted, "conflict candidates are not sorted");
        assert!(
            conflicts
                .iter()
                .all(|c| c.authority == Authority::Token && c.kind == "token")
        );
        // Same slug from two tokens is one proposal, not a conflict.
        let r = RawEvidence {
            tokens: vec![
                (0x1, "■format♦same_name■domain♦D".into()),
                (0x2, "■format♦same_name■domain♦D".into()),
            ],
            ..raw()
        };
        let (name, tier, _, _, conflicts) = decide("40e1bff4", &r);
        assert!(conflicts.is_empty());
        assert!(name.as_deref().unwrap().contains("same_name"));
        assert_eq!(tier, Tier::Provisional);
    }

    #[test]
    fn shared_task_roles_propose_no_pal_name_and_block_lower_ranks() {
        let shared = pal_app(
            "pal_TaskEntry_shared_40010430",
            &[("delta_one", 3), ("delta_two", 4)],
        );
        // Token guesses must not rename a shared task entry.
        let r = RawEvidence {
            tokens: vec![(0x3c2a, "■format♦tok■domain♦D".into())],
            ..raw_with_pal(Some(shared))
        };
        let (name, tier, _, _, _) = decide("40e1bff4", &r);
        assert!(
            name.is_none(),
            "shared task roles proposed a name: {name:?}"
        );
        assert_eq!(tier, Tier::None);
        // A stronger rank still wins over the shared role blocker.
        let r = RawEvidence {
            func_name: Some("Func_Winner".into()),
            ..raw_with_pal(Some(pal_app(
                "pal_TaskEntry_shared_40010430",
                &[("delta_one", 3), ("delta_two", 4)],
            )))
        };
        let (name, tier, _, _, _) = decide("40e1bff4", &r);
        assert_eq!(name.as_deref(), Some("Func_Winner"));
        assert_eq!(tier, Tier::Recovered);
    }

    #[test]
    fn pal_annotation_survives_stronger_rename() {
        let r = RawEvidence {
            func_name: Some("Func_Winner".into()),
            ..raw_with_pal(Some(pal_app("pal_TaskEntry_alpha", &[("alpha", 0)])))
        };
        let (name, _, _, ann, _) = decide("40e1bff4", &r);
        assert_eq!(name.as_deref(), Some("Func_Winner"));
        assert!(
            ann.iter().any(|a| a.starts_with("pal task: alpha")),
            "PAL annotation lost under a stronger rename: {ann:?}"
        );
    }

    #[test]
    fn provisional_evidence_never_replaces_a_pal_primary() {
        let r = RawEvidence {
            tokens: vec![(0x3c2a, "■format♦tok■domain♦D".into())],
            ident_guess: Some(("Other".into(), name_guess::Class::FnName)),
            ..raw_with_pal(Some(pal_app("pal_TaskEntry_alpha", &[("alpha", 0)])))
        };
        let (name, tier, _, _, _) = decide("40e1bff4", &r);
        assert_eq!(name.as_deref(), Some("pal_TaskEntry_alpha"));
        assert_eq!(tier, Tier::Recovered);
    }

    fn startup_role(primary: &str, role: &'static str) -> StartupRoleRefSet {
        StartupRoleRefSet::from_test(primary, role, false)
    }

    fn raw_with_startup(primary: &str, role: &'static str) -> RawEvidence {
        RawEvidence {
            startup_manifest_blake3: Some("c".repeat(64)),
            startup: Some(startup_role(primary, role)),
            startup_proposed_primary: Some(primary.to_string()),
            ..raw()
        }
    }

    #[test]
    fn startup_ranks_below_pal_and_above_token() {
        let token = vec![(0x3c2a, "■format♦tok■domain♦D".into())];
        let pal = Some(PalRoleRefSet::from_pass2(&pal_app(
            "pal_TaskEntry_alpha",
            &[("alpha", 0)],
        )));
        let pal_proposed_primary = Some("pal_TaskEntry_alpha".to_string());

        let (name, tier, _, _, _) = decide(
            "40e1bff4",
            &RawEvidence {
                tokens: token.clone(),
                pal: pal.clone(),
                pal_proposed_primary: pal_proposed_primary.clone(),
                startup_manifest_blake3: Some("c".repeat(64)),
                startup: Some(startup_role("hw_Init", "hardware_init")),
                startup_proposed_primary: Some("hw_Init".into()),
                ..raw()
            },
        );
        assert_eq!(name.as_deref(), Some("pal_TaskEntry_alpha"));
        assert_eq!(tier, Tier::Recovered);

        let (name, tier, evidence, _, _) = decide(
            "40e1bff4",
            &RawEvidence {
                tokens: token,
                startup_manifest_blake3: Some("c".repeat(64)),
                startup: Some(startup_role("hw_Init", "hardware_init")),
                startup_proposed_primary: Some("hw_Init".into()),
                ..raw()
            },
        );
        assert_eq!(name.as_deref(), Some("hw_Init"));
        assert_eq!(tier, Tier::Recovered);
        assert!(
            evidence.iter().any(|item| item.kind() == "startup"),
            "startup evidence missing under a token: {evidence:?}"
        );
        assert!(!name.unwrap().starts_with(GUESS_PREFIX));
    }

    #[test]
    fn stronger_primary_keeps_startup_evidence() {
        let r = RawEvidence {
            func_name: Some("Func_Winner".into()),
            registration: Some("Reg_Loser".into()),
            tokens: vec![(0x3c2a, "■format♦tok■domain♦D".into())],
            ..raw_with_startup("hw_Init", "hardware_init")
        };
        let (name, tier, ev, _, _) = decide("40e1bff4", &r);
        assert_eq!(name.as_deref(), Some("Func_Winner"));
        assert_eq!(tier, Tier::Recovered);
        let kinds: Vec<&str> = ev.iter().map(TaggedEvidence::kind).collect();
        assert!(
            kinds.contains(&"startup"),
            "stronger primary dropped startup evidence: {kinds:?}"
        );
        assert!(kinds.contains(&"func"));
        assert!(kinds.contains(&"token"));
    }

    #[test]
    fn symbols_and_maps_write_v5() {
        assert_eq!(SYMBOLS_FORMAT, "pixel-modem-extractor-symbols-v5");
        assert_eq!(SYMBOL_MAP_FORMAT, "pixel-modem-extractor-symbol-map-v5");

        let root = tmp("pme_sym_v5_write");
        let dec = root.join("decompiled");
        std::fs::create_dir_all(&dec).unwrap();
        let symbols_path = write_symbols_json(&dec, "02_MAIN", &[], HashMap::new()).unwrap();
        let symbols: serde_json::Value =
            serde_json::from_slice(&std::fs::read(symbols_path).unwrap()).unwrap();
        assert_eq!(symbols["format"], "pixel-modem-extractor-symbols-v5");

        let dir = map_fixture_tree("v5_write");
        let image = vec![0u8; 0x20];
        let load_addr = 0u32;
        write_map_functions(
            &dir,
            &[ghidra_function_in_image(
                "FUN_10",
                0x10,
                0x18,
                &[],
                &image,
                load_addr,
            )],
        );
        let (identity, _) = identity_for(&dir, 0x10, &image, load_addr);
        let mut symbol = ghidra_symbol_at(0x10, identity.execution_blake3, None);
        symbol.original_name = "FUN_10".into();
        let map_path = dir.join("map.json");
        write_pass2_symbol_map(
            &map_path,
            &dir,
            "02_MAIN",
            u64::from(load_addr),
            &image,
            &[symbol],
            None,
            None,
            &runtime_for(&image, load_addr),
        )
        .unwrap();
        let map: serde_json::Value =
            serde_json::from_slice(&std::fs::read(map_path).unwrap()).unwrap();
        assert_eq!(map["format"], "pixel-modem-extractor-symbol-map-v5");
    }

    // A fixture image directory with a valid single-argument Ghidra inventory
    // (`primary_source` per record), for the map writer tests.
    fn map_fixture_tree(tag: &str) -> PathBuf {
        let dir = tmp(&format!("pme_sym_v2_map_{tag}_{}", std::process::id()));
        let dec = dir.join("decompiled");
        std::fs::create_dir_all(&dec).unwrap();
        dir
    }

    fn write_map_functions(dir: &Path, records: &[serde_json::Value]) -> Vec<u8> {
        let bytes = serde_json::to_vec_pretty(records).unwrap();
        std::fs::write(dir.join("decompiled/functions.json"), &bytes).unwrap();
        bytes
    }

    fn ghidra_symbol_at(entry: u32, execution: [u8; 32], name: Option<&str>) -> Symbol {
        Symbol {
            address: format!("0x{entry:08x}"),
            arch: "arm",
            tool: crate::recover_source::Tool::Ghidra,
            owner: FunctionOwner::Ghidra,
            execution_blake3: Some(execution),
            decode_ranges: Vec::new(),
            original_name: format!("FUN_{entry:08x}"),
            name: name.map(str::to_string),
            tier: Tier::Recovered,
            evidence: Vec::new(),
            annotations: Vec::new(),
            name_conflicts: Vec::new(),
        }
    }

    fn identity_for(
        dir: &Path,
        entry: u32,
        image: &[u8],
        load_addr: u32,
    ) -> (ExecutionIdentity, String) {
        let runtime =
            crate::runtime_image::RuntimeImage::from_plan(image, load_addr, None).unwrap();
        let bytes = std::fs::read(dir.join("decompiled/functions.json")).unwrap();
        let records: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();
        let inventory = crate::execution_ranges::validate_ghidra_inventory_records(
            &records,
            records.len(),
            &runtime,
        )
        .unwrap();
        let tagged = inventory.records.iter().find(|r| r.entry == entry).unwrap();
        let identity =
            crate::execution_ranges::execution_identity(tagged.entry, &tagged.projection)
                .unwrap()
                .unwrap();
        let digest = identity
            .execution_blake3
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        (identity, digest)
    }

    fn runtime_for(image: &[u8], load_addr: u32) -> crate::runtime_image::RuntimeImage<'_> {
        crate::runtime_image::RuntimeImage::from_plan(image, load_addr, None).unwrap()
    }

    fn authenticated_thumb_identity(
        image: &[u8],
        load_addr: u32,
        entry: u32,
        ranges: &[(u32, u32)],
    ) -> ExecutionIdentity {
        let mut budget = crate::execution_ranges::ExecutionBudget::default();
        crate::execution_ranges::validate_execution(
            entry,
            ranges
                .iter()
                .map(|&(start, end)| crate::execution_ranges::DecodeExtent {
                    start,
                    end,
                    isa: crate::execution_ranges::DecodeIsa::Thumb,
                })
                .collect(),
            &runtime_for(image, load_addr),
            &mut budget,
        )
        .unwrap()
    }

    fn strict_thumb_symbol(
        entry: u32,
        identity: &ExecutionIdentity,
        region_index: usize,
    ) -> Symbol {
        Symbol {
            address: format!("0x{entry:08x}"),
            arch: "thumb",
            tool: crate::recover_source::Tool::Radare2,
            owner: FunctionOwner::Run {
                producer: crate::analysis_tool::AnalysisTool::Radare2,
                region_index,
                run_index: 0,
            },
            execution_blake3: Some(identity.execution_blake3),
            decode_ranges: identity
                .decode_ranges
                .iter()
                .map(DecodeRangeWire::from_authenticated)
                .collect(),
            original_name: format!("thumb_{entry:08x}"),
            name: None,
            tier: Tier::None,
            evidence: Vec::new(),
            annotations: Vec::new(),
            name_conflicts: Vec::new(),
        }
    }

    struct ThumbLineageFixture {
        dir: PathBuf,
        image: Vec<u8>,
        load_addr: u32,
        owned_entry: u32,
        owned_producer: ExecutionIdentity,
        ordinary_entry: u32,
        ordinary_producer: ExecutionIdentity,
        symbols: Vec<Symbol>,
    }

    fn thumb_lineage_fixture(tag: &str) -> ThumbLineageFixture {
        let dir = map_fixture_tree(tag);
        let image = (0..0x400).map(|value| value as u8).collect::<Vec<_>>();
        let load_addr = 0x4000_0000u32;
        let owned_entry = load_addr + 0x100;
        let ordinary_entry = load_addr + 0x200;
        let owned_producer = authenticated_thumb_identity(
            &image,
            load_addr,
            owned_entry,
            &[(owned_entry, owned_entry + 8)],
        );
        let ordinary_producer = authenticated_thumb_identity(
            &image,
            load_addr,
            ordinary_entry,
            &[(ordinary_entry, ordinary_entry + 8)],
        );

        let mut owned = ghidra_function_in_image(
            "FUN_owned",
            owned_entry,
            owned_entry + 4,
            &[],
            &image,
            load_addr,
        );
        owned["decode_ranges"][0]["isa"] = serde_json::json!("thumb");
        owned["thumb_creation_producer_blake3"] = serde_json::json!(crate::manifest::blake3_fixed(
            owned_producer.execution_blake3
        ));
        let mut ordinary = ghidra_function_in_image(
            "FUN_ordinary",
            ordinary_entry,
            ordinary_entry + 4,
            &[],
            &image,
            load_addr,
        );
        ordinary["decode_ranges"][0]["isa"] = serde_json::json!("thumb");
        write_map_functions(&dir, &[ordinary, owned]);

        let (owned_ghidra, _) = identity_for(&dir, owned_entry, &image, load_addr);
        let (ordinary_ghidra, _) = identity_for(&dir, ordinary_entry, &image, load_addr);
        assert_ne!(
            owned_ghidra.execution_blake3, owned_producer.execution_blake3,
            "fixture must exercise independent producer and Ghidra identities"
        );
        let mut owned_symbol = ghidra_symbol_at(owned_entry, owned_ghidra.execution_blake3, None);
        owned_symbol.original_name = "FUN_owned".into();
        let mut ordinary_symbol =
            ghidra_symbol_at(ordinary_entry, ordinary_ghidra.execution_blake3, None);
        ordinary_symbol.original_name = "FUN_ordinary".into();
        let symbols = vec![
            ordinary_symbol,
            strict_thumb_symbol(ordinary_entry, &ordinary_producer, 1),
            owned_symbol,
            strict_thumb_symbol(owned_entry, &owned_producer, 0),
        ];

        ThumbLineageFixture {
            dir,
            image,
            load_addr,
            owned_entry,
            owned_producer,
            ordinary_entry,
            ordinary_producer,
            symbols,
        }
    }

    #[test]
    fn map_emits_only_nominated_owned_thumb_lineage_in_canonical_order() {
        let fixture = thumb_lineage_fixture("thumb_lineage");
        let map_path = fixture.dir.join("map.json");
        let written = write_pass2_symbol_map(
            &map_path,
            &fixture.dir,
            "02_MAIN",
            u64::from(fixture.load_addr),
            &fixture.image,
            &fixture.symbols,
            None,
            None,
            &runtime_for(&fixture.image, fixture.load_addr),
        )
        .unwrap();

        assert_eq!(written.execution_count, 2);
        assert_eq!(written.creation_count, 0);
        let bytes = std::fs::read(&map_path).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        let executions_at = text.find("\n  \"executions\":").unwrap();
        let lineage_at = text.find("\n  \"thumb_creation_lineage\":").unwrap();
        let symbols_at = text.find("\n  \"symbols\":").unwrap();
        assert!(executions_at < lineage_at && lineage_at < symbols_at);

        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let lineage = parsed["thumb_creation_lineage"].as_array().unwrap();
        assert_eq!(lineage.len(), 1, "ordinary overlap leaked into lineage");
        assert_eq!(lineage[0]["execution"], 0);
        assert_eq!(
            lineage[0]["producer_execution_blake3"],
            crate::manifest::blake3_fixed(fixture.owned_producer.execution_blake3)
        );
        assert_eq!(
            lineage[0]["decode_ranges"],
            serde_json::to_value(
                fixture
                    .owned_producer
                    .decode_ranges
                    .iter()
                    .map(DecodeRangeWire::from_authenticated)
                    .collect::<Vec<_>>()
            )
            .unwrap()
        );
    }

    fn build_lineage_with_prior_usage(
        fixture: &ThumbLineageFixture,
        range_usage: crate::execution_ranges::ExecutionRangeUsage,
    ) -> Result<Vec<ThumbCreationLineageBlock>> {
        let (ghidra, _) = identity_for(
            &fixture.dir,
            fixture.owned_entry,
            &fixture.image,
            fixture.load_addr,
        );
        let executions = vec![GhidraExecutionRecord {
            entry: fixture.owned_entry,
            entry_text: format!("0x{:08x}", fixture.owned_entry),
            execution_blake3: crate::manifest::blake3_fixed(ghidra.execution_blake3),
            decode_ranges: ghidra
                .decode_ranges
                .iter()
                .map(DecodeRangeWire::from_authenticated)
                .collect(),
            original_primary: "FUN_owned".into(),
            original_source: "default".into(),
            first_isa: "thumb",
            thunk_of: None,
            execution_digest: ghidra.execution_blake3,
        }];
        let nominations = [crate::execution_ranges::ThumbCreationNomination {
            entry: fixture.owned_entry,
            producer_execution_blake3: fixture.owned_producer.execution_blake3,
            ghidra_execution_blake3: ghidra.execution_blake3,
        }];

        build_thumb_creation_lineage(
            &nominations,
            &executions,
            &fixture.symbols,
            &runtime_for(&fixture.image, fixture.load_addr),
            range_usage,
        )
    }

    #[test]
    fn map_lineage_accepts_the_exact_combined_range_and_byte_boundary() {
        let fixture = thumb_lineage_fixture("combined_lineage_boundary");
        let lineage = build_lineage_with_prior_usage(
            &fixture,
            crate::execution_ranges::ExecutionRangeUsage {
                range_count: crate::execution_ranges::MAX_EXECUTION_RANGES - 1,
                charged_bytes: crate::execution_ranges::MAX_EXECUTION_CHARGED_BYTES - 8,
            },
        )
        .unwrap();

        assert_eq!(lineage.len(), 1);
    }

    #[test]
    fn map_lineage_rejects_combined_range_or_byte_usage_one_over_the_limit() {
        let fixture = thumb_lineage_fixture("combined_lineage_over_limit");
        let cases = [
            (
                crate::execution_ranges::ExecutionRangeUsage {
                    range_count: crate::execution_ranges::MAX_EXECUTION_RANGES,
                    charged_bytes: crate::execution_ranges::MAX_EXECUTION_CHARGED_BYTES - 8,
                },
                "execution range count exceeds the supported limit",
            ),
            (
                crate::execution_ranges::ExecutionRangeUsage {
                    range_count: crate::execution_ranges::MAX_EXECUTION_RANGES - 1,
                    charged_bytes: crate::execution_ranges::MAX_EXECUTION_CHARGED_BYTES - 7,
                },
                "execution charged bytes exceed the supported limit",
            ),
        ];

        for (range_usage, expected) in cases {
            let error = build_lineage_with_prior_usage(&fixture, range_usage)
                .err()
                .expect("combined usage above a map limit must fail")
                .to_string();
            assert!(error.contains(expected), "{error}");
        }
    }

    #[test]
    fn map_requires_empty_thumb_lineage_without_nominations() {
        let fixture = thumb_lineage_fixture("empty_thumb_lineage");
        let functions_path = fixture.dir.join("decompiled/functions.json");
        let mut records: Vec<serde_json::Value> =
            serde_json::from_slice(&std::fs::read(&functions_path).unwrap()).unwrap();
        for record in &mut records {
            record
                .as_object_mut()
                .unwrap()
                .remove("thumb_creation_producer_blake3");
        }
        write_map_functions(&fixture.dir, &records);

        let map_path = fixture.dir.join("map.json");
        write_pass2_symbol_map(
            &map_path,
            &fixture.dir,
            "02_MAIN",
            u64::from(fixture.load_addr),
            &fixture.image,
            &fixture.symbols,
            None,
            None,
            &runtime_for(&fixture.image, fixture.load_addr),
        )
        .unwrap();
        let parsed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(map_path).unwrap()).unwrap();
        assert_eq!(parsed["thumb_creation_lineage"], serde_json::json!([]));
    }

    #[test]
    fn map_rejects_missing_or_ambiguous_nominated_producer_execution() {
        let fixture = thumb_lineage_fixture("missing_thumb_lineage");
        let symbols = fixture
            .symbols
            .iter()
            .filter(|symbol| {
                symbol.execution_blake3 != Some(fixture.owned_producer.execution_blake3)
            })
            .cloned()
            .collect::<Vec<_>>();
        let error = write_pass2_symbol_map(
            &fixture.dir.join("missing-map.json"),
            &fixture.dir,
            "02_MAIN",
            u64::from(fixture.load_addr),
            &fixture.image,
            &symbols,
            None,
            None,
            &runtime_for(&fixture.image, fixture.load_addr),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("nominated producer execution"), "{error}");

        let mut symbols = fixture.symbols.clone();
        let mut duplicate = symbols
            .iter()
            .find(|symbol| symbol.execution_blake3 == Some(fixture.owned_producer.execution_blake3))
            .unwrap()
            .clone();
        duplicate.owner = FunctionOwner::Run {
            producer: crate::analysis_tool::AnalysisTool::Radare2,
            region_index: 9,
            run_index: 0,
        };
        symbols.push(duplicate);
        let error = write_pass2_symbol_map(
            &fixture.dir.join("ambiguous-map.json"),
            &fixture.dir,
            "02_MAIN",
            u64::from(fixture.load_addr),
            &fixture.image,
            &symbols,
            None,
            None,
            &runtime_for(&fixture.image, fixture.load_addr),
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("ambiguous nominated producer execution"),
            "{error}"
        );
    }

    #[test]
    fn map_reauthenticates_nominated_producer_ranges() {
        let fixture = thumb_lineage_fixture("authenticate_thumb_lineage");
        let mut symbols = fixture.symbols.clone();
        let producer = symbols
            .iter_mut()
            .find(|symbol| symbol.execution_blake3 == Some(fixture.owned_producer.execution_blake3))
            .unwrap();
        producer.decode_ranges[0].blake3 = "00".repeat(32);
        let error = write_pass2_symbol_map(
            &fixture.dir.join("map.json"),
            &fixture.dir,
            "02_MAIN",
            u64::from(fixture.load_addr),
            &fixture.image,
            &symbols,
            None,
            None,
            &runtime_for(&fixture.image, fixture.load_addr),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("runtime bytes"), "{error}");
    }

    #[test]
    fn map_sorts_multiple_thumb_lineage_rows_by_ghidra_execution() {
        let fixture = thumb_lineage_fixture("sorted_thumb_lineage");
        let functions_path = fixture.dir.join("decompiled/functions.json");
        let mut records: Vec<serde_json::Value> =
            serde_json::from_slice(&std::fs::read(&functions_path).unwrap()).unwrap();
        let ordinary = records
            .iter_mut()
            .find(|record| record["entry"] == format!("0x{:x}", fixture.ordinary_entry))
            .unwrap();
        ordinary["thumb_creation_producer_blake3"] = serde_json::json!(
            crate::manifest::blake3_fixed(fixture.ordinary_producer.execution_blake3)
        );
        write_map_functions(&fixture.dir, &records);

        let map_path = fixture.dir.join("map.json");
        write_pass2_symbol_map(
            &map_path,
            &fixture.dir,
            "02_MAIN",
            u64::from(fixture.load_addr),
            &fixture.image,
            &fixture.symbols,
            None,
            None,
            &runtime_for(&fixture.image, fixture.load_addr),
        )
        .unwrap();
        let parsed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(map_path).unwrap()).unwrap();
        let rows = parsed["thumb_creation_lineage"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["execution"], 0);
        assert_eq!(rows[1]["execution"], 1);
        assert_eq!(
            rows[0]["producer_execution_blake3"],
            crate::manifest::blake3_fixed(fixture.owned_producer.execution_blake3)
        );
        assert_eq!(
            rows[1]["producer_execution_blake3"],
            crate::manifest::blake3_fixed(fixture.ordinary_producer.execution_blake3)
        );
    }

    #[test]
    fn map_rejects_non_thumb_and_non_entry_first_nominated_ranges() {
        let fixture = thumb_lineage_fixture("non_thumb_lineage");
        let mut symbols = fixture.symbols.clone();
        let producer = symbols
            .iter_mut()
            .find(|symbol| symbol.execution_blake3 == Some(fixture.owned_producer.execution_blake3))
            .unwrap();
        producer.decode_ranges[0].isa = "arm";
        let error = write_pass2_symbol_map(
            &fixture.dir.join("non-thumb-map.json"),
            &fixture.dir,
            "02_MAIN",
            u64::from(fixture.load_addr),
            &fixture.image,
            &symbols,
            None,
            None,
            &runtime_for(&fixture.image, fixture.load_addr),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("Thumb-only"), "{error}");

        let mut symbols = fixture.symbols.clone();
        let producer = symbols
            .iter_mut()
            .find(|symbol| symbol.execution_blake3 == Some(fixture.owned_producer.execution_blake3))
            .unwrap();
        producer.decode_ranges[0].start = format!("0x{:08x}", fixture.owned_entry + 2);
        let error = write_pass2_symbol_map(
            &fixture.dir.join("non-entry-map.json"),
            &fixture.dir,
            "02_MAIN",
            u64::from(fixture.load_addr),
            &fixture.image,
            &symbols,
            None,
            None,
            &runtime_for(&fixture.image, fixture.load_addr),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("start at its entry"), "{error}");
    }

    #[test]
    fn map_rejects_nominated_ranges_that_conflict_with_their_digest() {
        let fixture = thumb_lineage_fixture("digest_conflict_lineage");
        let mut symbols = fixture.symbols.clone();
        let producer = symbols
            .iter_mut()
            .find(|symbol| symbol.execution_blake3 == Some(fixture.owned_producer.execution_blake3))
            .unwrap();
        producer.decode_ranges[0].end = format!("0x{:08x}", fixture.owned_entry + 6);
        producer.decode_ranges[0].blake3 =
            crate::manifest::blake3_bytes(&fixture.image[0x100..0x106]);
        let error = write_pass2_symbol_map(
            &fixture.dir.join("map.json"),
            &fixture.dir,
            "02_MAIN",
            u64::from(fixture.load_addr),
            &fixture.image,
            &symbols,
            None,
            None,
            &runtime_for(&fixture.image, fixture.load_addr),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("does not match its ranges"), "{error}");
    }

    const EXCEPTION_TEST_BASE: u32 = 0x4001_0000;
    const EXCEPTION_RESET_ENTRY: u32 = 0x4001_0200;
    const EXCEPTION_SHARED_ENTRY: u32 = 0x4001_0280;

    fn exception_fixture_image() -> Vec<u8> {
        include_bytes!("../tests/fixtures/exception_roots/synthetic.bin").to_vec()
    }

    fn exception_execution_symbols(
        dir: &Path,
        image: &[u8],
        records: &[(u32, &str, &str)],
    ) -> Vec<Symbol> {
        let records_json = records
            .iter()
            .map(|(entry, name, source)| {
                let mut record = ghidra_function_in_image(
                    name,
                    *entry,
                    *entry + 4,
                    &[],
                    image,
                    EXCEPTION_TEST_BASE,
                );
                record["primary_source"] = serde_json::json!(source);
                record
            })
            .collect::<Vec<_>>();
        write_map_functions(dir, &records_json);
        records
            .iter()
            .map(|(entry, name, _)| {
                let (identity, _) = identity_for(dir, *entry, image, EXCEPTION_TEST_BASE);
                let mut symbol = ghidra_symbol_at(*entry, identity.execution_blake3, None);
                symbol.original_name = (*name).to_string();
                symbol
            })
            .collect()
    }

    fn exception_build_map_tree(tag: &str, decode_isa: &str, name: &str) -> PathBuf {
        let parent = tmp(&format!(
            "pme_sym_exception_final_{tag}_{}",
            std::process::id()
        ));
        let root = parent.join("00_BOOT");
        std::fs::create_dir_all(root.join("decompiled")).unwrap();
        let image = exception_fixture_image();
        std::fs::write(root.join("00_BOOT.bin"), &image).unwrap();
        std::fs::create_dir(root.join("exception_roots")).unwrap();
        std::fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/exception_roots/roots.json"),
            root.join("exception_roots/roots.json"),
        )
        .unwrap();
        let entry = 0x4001_0220u32;
        let instruction_size = if decode_isa == "thumb" { 2 } else { 4 };
        let start = (entry - EXCEPTION_TEST_BASE) as usize;
        let end = start + instruction_size;
        let record = serde_json::json!({
            "name": name,
            "primary_source": if name.starts_with("FUN_") { "default" } else { "analysis" },
            "entry": format!("0x{entry:x}"),
            "end": format!("0x{:x}", entry + instruction_size as u32),
            "size": instruction_size,
            "decode_ranges": [{
                "isa": decode_isa,
                "start": format!("0x{entry:x}"),
                "end": format!("0x{:x}", entry + instruction_size as u32),
                "blake3": crate::manifest::blake3_bytes(&image[start..end]),
            }],
            "decode_range_errors": [],
            "data_refs": [],
        });
        write_map_functions(&root, &[record]);
        std::fs::write(
            root.join("manifest.json"),
            serde_json::to_vec(&serde_json::json!({
                "toc": [{"name": "BOOT", "load_addr": EXCEPTION_TEST_BASE}],
            }))
            .unwrap(),
        )
        .unwrap();
        root
    }

    fn standalone_exception_tree(tag: &str) -> (PathBuf, PathBuf) {
        let staged = exception_build_map_tree(tag, "thumb", "UndefinedInstruction");
        let root = staged.parent().unwrap().to_path_buf();
        let manifest = std::fs::read(staged.join("manifest.json")).unwrap();
        std::fs::remove_file(staged.join("manifest.json")).unwrap();
        std::fs::create_dir(root.join("images")).unwrap();
        let image_dir = root.join("images/00_BOOT");
        std::fs::rename(&staged, &image_dir).unwrap();
        std::fs::write(root.join("manifest.json"), manifest).unwrap();
        (root, image_dir)
    }

    fn add_same_entry_thumb_producers(root: &Path, image: &[u8]) {
        let entry = 0x4001_0220u32;
        let mut artifact = std::str::from_utf8(
            crate::thumb_analysis::ParsedThumbArtifact::future_multi_run_v3_fixture(),
        )
        .unwrap()
        .to_string();
        for (from, to) in [
            ("0x1000", format!("0x{entry:x}")),
            ("0x1002", format!("0x{:x}", entry + 2)),
            ("0x1010", format!("0x{:x}", entry + 0x10)),
            ("0x1080", format!("0x{:x}", entry + 0x80)),
            ("0x1090", format!("0x{:x}", entry + 0x90)),
            ("0x1100", format!("0x{:x}", entry + 0x100)),
            ("00001000", format!("{entry:08x}")),
        ] {
            artifact = artifact.replace(from, &to);
        }
        let offset = usize::try_from(entry - EXCEPTION_TEST_BASE).unwrap();
        artifact = artifact.replacen(
            "1ad48f49627079d806b802c74f40c39d55fe1d78b3faf0f8017aec62cec42122",
            &crate::manifest::blake3_bytes(&image[offset..offset + 2]),
            1,
        );
        let repeated = "e572dff82304700b856a555ac3a4558d0df3646a3727816500270a93c66aac1e";
        artifact = artifact.replacen(
            repeated,
            &crate::manifest::blake3_bytes(&image[offset..offset + 0x10]),
            1,
        );
        artifact = artifact.replacen(
            repeated,
            &crate::manifest::blake3_bytes(&image[offset + 0x80..offset + 0x90]),
            1,
        );
        std::fs::write(root.join("decompiled/thumb_functions.json"), artifact).unwrap();
    }

    #[test]
    fn final_artifact_keeps_authenticated_exception_and_pal_evidence() {
        let root =
            exception_build_map_tree("final_exception_evidence", "thumb", "UndefinedInstruction");
        let image = exception_fixture_image();
        let runtime = runtime_for(&image, EXCEPTION_TEST_BASE);
        let context = role_evidence::CurrentSymbolicationContext::from_retained(
            &root,
            "00_BOOT",
            "BOOT",
            EXCEPTION_TEST_BASE,
        )
        .unwrap();

        let (symbols, _) = build_final_map_from_runtime(
            &root,
            &HashMap::new(),
            &image,
            u64::from(EXCEPTION_TEST_BASE),
            &runtime,
            context.roles(),
        )
        .unwrap();
        let symbol = symbols
            .iter()
            .find(|symbol| symbol.address == "0x40010220")
            .unwrap();

        assert_eq!(symbol.name.as_deref(), Some("UndefinedInstruction"));
        assert_eq!(symbol.tier, Tier::Recovered);
        assert!(symbol.evidence.iter().any(|evidence| matches!(
            evidence,
            TaggedEvidence::ExceptionRoot {
                role: "undefined_instruction",
                ..
            }
        )));

        let (_pal_root, pal_dir) = role_evidence::retained_pal_fixture_tree(false);
        let pal_image = std::fs::read(pal_dir.join("02_MAIN.bin")).unwrap();
        let pal_context = role_evidence::CurrentSymbolicationContext::from_retained(
            &pal_dir,
            "02_MAIN",
            "MAIN",
            crate::pal_tasks::test_support::BASE,
        )
        .unwrap();
        let application = &pal_context.roles().pal().present().unwrap().applications()[0];
        assert_eq!(application.isa(), DecodeIsa::Thumb);
        let entry = application.entry();
        let start = usize::try_from(entry - crate::pal_tasks::test_support::BASE).unwrap();
        std::fs::create_dir(pal_dir.join("decompiled")).unwrap();
        let mut record = ghidra_function_in_image(
            application.desired_primary(),
            entry,
            entry + 2,
            &[],
            &pal_image,
            crate::pal_tasks::test_support::BASE,
        );
        record["primary_source"] = serde_json::json!("analysis");
        record["decode_ranges"][0]["isa"] = serde_json::json!("thumb");
        record["decode_ranges"][0]["blake3"] =
            serde_json::json!(crate::manifest::blake3_bytes(&pal_image[start..start + 2]));
        write_map_functions(&pal_dir, &[record]);

        let (pal_symbols, _) = build_final_map_from_runtime(
            &pal_dir,
            &HashMap::new(),
            &pal_image,
            u64::from(crate::pal_tasks::test_support::BASE),
            &runtime_for(&pal_image, crate::pal_tasks::test_support::BASE),
            pal_context.roles(),
        )
        .unwrap();
        let pal_symbol = pal_symbols
            .iter()
            .find(|symbol| symbol.address == format!("0x{entry:08x}"))
            .unwrap();
        assert_eq!(pal_symbol.name.as_deref(), Some("pal_TaskEntry_first_task"));
        assert!(pal_symbol.evidence.iter().any(|evidence| matches!(
            evidence,
            TaggedEvidence::PalTask { task } if task.name == "first_task"
        )));
    }

    #[test]
    fn standalone_reauthenticates_retained_role_artifacts() {
        let (root, image_dir) = standalone_exception_tree("standalone_reauthenticate");
        let opts = Opts {
            token_db: None,
            rewrite_decompiled_c: false,
        };

        run(&root, &opts).unwrap();
        let symbols_path = image_dir.join("decompiled/symbols.json");
        let first = std::fs::read(&symbols_path).unwrap();
        let artifact: serde_json::Value = serde_json::from_slice(&first).unwrap();
        assert!(
            artifact["symbols"]
                .as_array()
                .unwrap()
                .iter()
                .any(|symbol| {
                    symbol["evidence"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|evidence| {
                            evidence["kind"] == "exception_root"
                                && evidence["role"] == "undefined_instruction"
                        })
                })
        );

        run(&root, &opts).unwrap();
        assert_eq!(std::fs::read(symbols_path).unwrap(), first);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn standalone_idempotent_replay_opens_no_atomic_writer() {
        use std::os::unix::fs::PermissionsExt as _;

        let (root, image_dir) = standalone_exception_tree("standalone_read_only_replay");
        let decompiled = image_dir.join("decompiled");
        std::fs::write(
            decompiled.join("decompiled.c"),
            "void UndefinedInstruction(void) {}\n",
        )
        .unwrap();
        std::fs::write(decompiled.join("disasm.lst"), "0x40010220: 4770 bx lr\n").unwrap();
        let opts = Opts {
            token_db: None,
            rewrite_decompiled_c: true,
        };
        run(&root, &opts).unwrap();
        let before = std::fs::read_dir(&decompiled)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                (
                    path.file_name().unwrap().to_owned(),
                    std::fs::read(path).unwrap(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let original_mode = std::fs::metadata(&decompiled).unwrap().permissions().mode();
        std::fs::set_permissions(&decompiled, std::fs::Permissions::from_mode(0o555)).unwrap();

        let result = run(&root, &opts);

        std::fs::set_permissions(&decompiled, std::fs::Permissions::from_mode(original_mode))
            .unwrap();
        result.expect("an idempotent replay must not require a writable artifact directory");
        let after = std::fs::read_dir(&decompiled)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                (
                    path.file_name().unwrap().to_owned(),
                    std::fs::read(path).unwrap(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(after, before);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn standalone_pruned_tree_fails_before_any_mutation() {
        let (root, image_dir) = standalone_exception_tree("standalone_pruned");
        let decompiled = image_dir.join("decompiled");
        for (name, bytes) in [
            ("thumb_functions.json", b"THUMB".as_slice()),
            ("decompiled.c", b"DECOMPILED".as_slice()),
            ("disasm.lst", b"DISASM".as_slice()),
            ("symbols.json", b"SYMBOLS".as_slice()),
        ] {
            std::fs::write(decompiled.join(name), bytes).unwrap();
        }
        let watched = [
            "functions.json",
            "thumb_functions.json",
            "decompiled.c",
            "disasm.lst",
            "symbols.json",
        ];
        let before = watched
            .iter()
            .map(|name| (*name, std::fs::read(decompiled.join(name)).unwrap()))
            .collect::<Vec<_>>();
        std::fs::remove_file(image_dir.join("00_BOOT.bin")).unwrap();

        run(
            &root,
            &Opts {
                token_db: None,
                rewrite_decompiled_c: true,
            },
        )
        .unwrap_err();

        for (name, bytes) in before {
            assert_eq!(std::fs::read(decompiled.join(name)).unwrap(), bytes);
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn final_artifact_uses_actual_primary_and_blocks_weaker_guesses() {
        let root = exception_build_map_tree(
            "final_exception_blocker",
            "thumb",
            "firmware_native_primary",
        );
        let image = exception_fixture_image();
        let runtime = runtime_for(&image, EXCEPTION_TEST_BASE);
        let functions_path = root.join("decompiled/functions.json");
        let mut functions: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&functions_path).unwrap()).unwrap();
        functions[0]["original_name"] = serde_json::json!("UndefinedInstruction");
        functions[0]["data_refs"] = serde_json::json!(["0x0"]);
        std::fs::write(&functions_path, serde_json::to_vec(&functions).unwrap()).unwrap();
        let context = role_evidence::CurrentSymbolicationContext::from_retained(
            &root,
            "00_BOOT",
            "BOOT",
            EXCEPTION_TEST_BASE,
        )
        .unwrap();
        let tokens = HashMap::from([(0u32, "■format♦weaker_token_name■domain♦test".to_string())]);

        let (symbols, _) = build_final_map_from_runtime(
            &root,
            &tokens,
            &image,
            u64::from(EXCEPTION_TEST_BASE),
            &runtime,
            context.roles(),
        )
        .unwrap();
        let symbol = symbols
            .iter()
            .find(|symbol| symbol.address == "0x40010220")
            .unwrap();

        assert!(symbol.name.is_none());
        assert_eq!(symbol.original_name, "UndefinedInstruction");
        assert_eq!(symbol.tier, Tier::None);
        assert!(symbol.evidence.iter().any(|evidence| matches!(
            evidence,
            TaggedEvidence::ExceptionRoot {
                role: "undefined_instruction",
                ..
            }
        )));
    }

    #[test]
    fn final_artifact_attaches_roles_to_each_exact_owner_entry_and_isa() {
        let root =
            exception_build_map_tree("final_exception_owner_isa", "thumb", "UndefinedInstruction");
        let image = exception_fixture_image();
        add_same_entry_thumb_producers(&root, &image);
        let runtime = runtime_for(&image, EXCEPTION_TEST_BASE);
        let context = role_evidence::CurrentSymbolicationContext::from_retained(
            &root,
            "00_BOOT",
            "BOOT",
            EXCEPTION_TEST_BASE,
        )
        .unwrap();

        let (symbols, _) = build_final_map_from_runtime(
            &root,
            &HashMap::new(),
            &image,
            u64::from(EXCEPTION_TEST_BASE),
            &runtime,
            context.roles(),
        )
        .unwrap();
        let matching = symbols
            .iter()
            .filter(|symbol| symbol.address == "0x40010220")
            .collect::<Vec<_>>();
        assert_eq!(
            matching.len(),
            3,
            "owners/addresses: {:?}",
            symbols
                .iter()
                .map(|symbol| (symbol.owner, symbol.address.as_str()))
                .collect::<Vec<_>>()
        );
        assert_eq!(matching[0].owner, FunctionOwner::Ghidra);
        assert_eq!(
            matching[1].owner,
            FunctionOwner::Run {
                producer: Tool::Radare2,
                region_index: 0,
                run_index: 0,
            }
        );
        assert_eq!(
            matching[2].owner,
            FunctionOwner::Run {
                producer: Tool::Rizin,
                region_index: 0,
                run_index: 1,
            }
        );
        assert!(
            matching
                .iter()
                .all(|symbol| symbol.execution_blake3.is_some())
        );
        assert_eq!(matching[0].execution_blake3, matching[1].execution_blake3);
        assert_ne!(matching[1].execution_blake3, matching[2].execution_blake3);
        assert!(
            matching
                .iter()
                .all(|symbol| symbol.evidence.iter().any(|evidence| matches!(
                    evidence,
                    TaggedEvidence::ExceptionRoot {
                        role: "undefined_instruction",
                        ..
                    }
                )))
        );

        let arm_root =
            exception_build_map_tree("final_exception_owner_isa_mismatch", "arm", "FUN_40010220");
        let arm_context = role_evidence::CurrentSymbolicationContext::from_retained(
            &arm_root,
            "00_BOOT",
            "BOOT",
            EXCEPTION_TEST_BASE,
        )
        .unwrap();
        let (arm_symbols, _) = build_final_map_from_runtime(
            &arm_root,
            &HashMap::new(),
            &image,
            u64::from(EXCEPTION_TEST_BASE),
            &runtime,
            arm_context.roles(),
        )
        .unwrap();
        assert!(arm_symbols.iter().all(|symbol| {
            !symbol
                .evidence
                .iter()
                .any(|evidence| matches!(evidence, TaggedEvidence::ExceptionRoot { .. }))
        }));
    }

    #[test]
    fn pass2_role_attachment_comes_from_immutable_evidence() {
        let root = exception_build_map_tree(
            "pass2_immutable_exception_evidence",
            "thumb",
            "UndefinedInstruction",
        );
        let image = exception_fixture_image();
        let runtime = runtime_for(&image, EXCEPTION_TEST_BASE);
        let context = role_evidence::CurrentSymbolicationContext::from_retained(
            &root,
            "00_BOOT",
            "BOOT",
            EXCEPTION_TEST_BASE,
        )
        .unwrap();

        let (symbols, _) = build_map_from_runtime(
            &root,
            &HashMap::new(),
            &image,
            u64::from(EXCEPTION_TEST_BASE),
            &runtime,
            context.roles(),
            SymbolBuildPurpose::Pass2 {
                exception_application: None,
                pal_application: None,
            },
        )
        .unwrap();
        let symbol = symbols
            .iter()
            .find(|symbol| symbol.address == "0x40010220")
            .unwrap();
        assert!(symbol.name.is_none());
        assert!(symbol.evidence.iter().any(|evidence| matches!(
            evidence,
            TaggedEvidence::ExceptionRoot {
                role: "undefined_instruction",
                ..
            }
        )));
    }

    /// Two-entry fixture: writes functions.json, derives each execution
    /// identity through the test runtime, and returns the symbols + records.
    type ExecutionFixture = (u32, ExecutionIdentity, String, &'static str);

    fn two_execution_fixture(
        dir: &Path,
        image: &[u8],
        load_addr: u32,
        sources: [&'static str; 2],
    ) -> (Vec<Symbol>, Vec<ExecutionFixture>) {
        let first = ghidra_function_in_image(
            &format!("FUN_{:08x}", load_addr + 0x100),
            load_addr + 0x100,
            load_addr + 0x108,
            &[],
            image,
            load_addr,
        );
        let mut first = first;
        first["primary_source"] = serde_json::json!(sources[0]);
        let second = ghidra_function_in_image(
            &format!("FUN_{:08x}", load_addr + 0x200),
            load_addr + 0x200,
            load_addr + 0x208,
            &[],
            image,
            load_addr,
        );
        let mut second = second;
        second["primary_source"] = serde_json::json!(sources[1]);
        write_map_functions(dir, &[second, first]); // deliberately unsorted

        let mut out = Vec::new();
        for entry in [load_addr + 0x100, load_addr + 0x200] {
            let (identity, digest) = identity_for(dir, entry, image, load_addr);
            let source = if entry == load_addr + 0x100 {
                sources[0]
            } else {
                sources[1]
            };
            out.push((entry, identity, digest, source));
        }
        let symbols = vec![
            ghidra_symbol_at(load_addr + 0x100, out[0].1.execution_blake3, None),
            ghidra_symbol_at(load_addr + 0x200, out[1].1.execution_blake3, None),
        ];
        (symbols, out)
    }

    #[test]
    fn map_creates_only_from_named_strict_v3_thumb_runs() {
        let dir = map_fixture_tree("creations");
        let image = vec![0u8; 0x400];
        let load_addr = 0x4000_0000u32;
        // One Ghidra function (renamed) and two named thumb-only symbols at
        // entries Ghidra never discovered. Readable legacy evidence is not
        // creation authority; only the concrete strict-v3 run may create.
        let ghidra_entry = load_addr + 0x100;
        let legacy_entry = load_addr + 0x280;
        let strict_v3_entry = load_addr + 0x300;
        let record = ghidra_function_in_image(
            "FUN_target",
            ghidra_entry,
            ghidra_entry + 8,
            &[],
            &image,
            load_addr,
        );
        write_map_functions(&dir, &[record]);

        let (identity, _) = identity_for(&dir, ghidra_entry, &image, load_addr);
        let mut ghidra_symbol = ghidra_symbol_at(ghidra_entry, identity.execution_blake3, None);
        ghidra_symbol.original_name = "FUN_target".into();
        ghidra_symbol.name = Some("RealName".into());
        ghidra_symbol.tier = Tier::Recovered;

        let thumb_symbol = |entry, owner, digest, name: &str| Symbol {
            address: format!("0x{entry:08x}"),
            arch: "thumb",
            tool: crate::recover_source::Tool::Radare2,
            owner,
            execution_blake3: Some(digest),
            decode_ranges: vec![DecodeRangeWire {
                isa: "thumb",
                start: format!("0x{entry:x}"),
                end: format!("0x{:x}", entry + 4),
                blake3: blake3::hash(
                    &image[(entry - load_addr) as usize..(entry - load_addr + 4) as usize],
                )
                .to_hex()
                .to_string(),
            }],
            name_conflicts: Vec::new(),
            original_name: "thumb_only".into(),
            name: Some(name.into()),
            tier: Tier::Recovered,
            evidence: vec![],
            annotations: vec![],
        };
        let legacy_symbol = thumb_symbol(
            legacy_entry,
            FunctionOwner::Legacy {
                producer: crate::analysis_tool::AnalysisTool::Radare2,
            },
            [7u8; 32],
            "LegacyName",
        );
        let strict_v3_digest = [8u8; 32];
        let strict_v3_symbol = thumb_symbol(
            strict_v3_entry,
            FunctionOwner::Run {
                producer: crate::analysis_tool::AnalysisTool::Radare2,
                region_index: 2,
                run_index: 1,
            },
            strict_v3_digest,
            "AtiParsePlusCOPS",
        );

        let map_path = dir.join("map.json");
        let written = write_pass2_symbol_map(
            &map_path,
            &dir,
            "02_MAIN",
            u64::from(load_addr),
            &image,
            &[ghidra_symbol, legacy_symbol, strict_v3_symbol],
            None,
            None,
            &runtime_for(&image, load_addr),
        )
        .unwrap();
        assert_eq!(written.creation_count, 1);
        assert_eq!(
            written.creation_requests,
            vec![Pass2CreationRequest {
                entry: strict_v3_entry,
                final_primary: "AtiParsePlusCOPS".to_string(),
                final_source: "user_defined".to_string(),
            }]
        );
        assert_eq!(written.creation_skips.ambiguous, 0);
        assert_eq!(written.creation_skips.collision, 0);

        let parsed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&map_path).unwrap()).unwrap();
        let creations = parsed["creations"].as_array().unwrap();
        assert_eq!(creations.len(), 1);
        assert_eq!(creations[0]["entry"], format!("0x{strict_v3_entry:08x}"));
        assert_eq!(creations[0]["final_primary"], "AtiParsePlusCOPS");
        assert_eq!(creations[0]["final_source"], "user_defined");
        assert_eq!(
            creations[0]["execution_blake3"],
            strict_v3_digest
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        assert_eq!(creations[0]["decode_ranges"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn map_counts_rename_with_annotations_as_one_applicable_decision() {
        let dir = map_fixture_tree("rename_with_annotations");
        let image = vec![0u8; 0x200];
        let image_path = dir.join("02_MAIN.bin");
        std::fs::write(&image_path, &image).unwrap();
        let load_addr = 0x4000_0000u32;
        let entry = load_addr + 0x100;
        let record =
            ghidra_function_in_image("FUN_target", entry, entry + 8, &[], &image, load_addr);
        write_map_functions(&dir, &[record]);
        let (identity, _) = identity_for(&dir, entry, &image, load_addr);
        let mut symbol = ghidra_symbol_at(entry, identity.execution_blake3, Some("RealName"));
        symbol.original_name = "FUN_target".into();
        symbol.annotations = vec!["source: registration table".into()];

        let map_path = dir.join("map.json");
        let written = write_pass2_symbol_map(
            &map_path,
            &dir,
            "02_MAIN",
            u64::from(load_addr),
            &image,
            &[symbol],
            None,
            None,
            &runtime_for(&image, load_addr),
        )
        .unwrap();
        assert_eq!(written.execution_count, 1);
        assert_eq!(written.applied_decision_count, 1);

        let prepared = crate::decompile::PreparedSymbolPass2Map::new(
            &map_path,
            &dir.join("decompiled/functions.json"),
            &image_path,
            "02_MAIN",
            written.execution_count,
            written.applied_decision_count,
            written.creation_requests,
        )
        .unwrap();
        assert_eq!(prepared.applied_decision_count(), 1);
    }

    #[test]
    fn map_skips_ambiguous_and_colliding_creations() {
        let dir = map_fixture_tree("creation_skips");
        let image = vec![0u8; 0x400];
        let load_addr = 0x4000_0000u32;
        let ghidra_entry = load_addr + 0x100;
        let ambiguous_entry = load_addr + 0x200;
        let colliding_entry = load_addr + 0x300;
        let record = ghidra_function_in_image(
            "FUN_target",
            ghidra_entry,
            ghidra_entry + 8,
            &[],
            &image,
            load_addr,
        );
        write_map_functions(&dir, &[record]);
        let (identity, _) = identity_for(&dir, ghidra_entry, &image, load_addr);
        let mut ghidra_symbol = ghidra_symbol_at(ghidra_entry, identity.execution_blake3, None);
        ghidra_symbol.original_name = "FUN_target".into();
        ghidra_symbol.name = Some("SharedName".into());
        ghidra_symbol.tier = Tier::Recovered;

        let mk = |entry: u32, name: Option<&str>| Symbol {
            address: format!("0x{entry:08x}"),
            arch: "thumb",
            tool: crate::recover_source::Tool::Radare2,
            owner: FunctionOwner::Run {
                producer: crate::analysis_tool::AnalysisTool::Radare2,
                region_index: 0,
                run_index: 0,
            },
            execution_blake3: Some([9u8; 32]),
            decode_ranges: vec![DecodeRangeWire {
                isa: "thumb",
                start: format!("0x{entry:x}"),
                end: format!("0x{:x}", entry + 4),
                blake3: blake3::hash(
                    &image[(entry - load_addr) as usize..(entry - load_addr + 4) as usize],
                )
                .to_hex()
                .to_string(),
            }],
            name_conflicts: Vec::new(),
            original_name: "thumb_only".into(),
            name: name.map(str::to_string),
            tier: Tier::Provisional,
            evidence: vec![],
            annotations: vec![],
        };
        // Two different names at one entry -> ambiguous skip.
        // One name colliding with the decision's final primary -> collision skip.
        let symbols = vec![
            ghidra_symbol,
            mk(ambiguous_entry, Some("NameA")),
            mk(ambiguous_entry, Some("NameB")),
            mk(colliding_entry, Some("SharedName")),
        ];
        let map_path = dir.join("map.json");
        let written = write_pass2_symbol_map(
            &map_path,
            &dir,
            "02_MAIN",
            u64::from(load_addr),
            &image,
            &symbols,
            None,
            None,
            &runtime_for(&image, load_addr),
        )
        .unwrap();
        assert_eq!(written.creation_count, 0);
        assert_eq!(written.creation_skips.ambiguous, 1);
        assert_eq!(written.creation_skips.collision, 1);
        let parsed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&map_path).unwrap()).unwrap();
        assert_eq!(parsed["creations"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn map_skips_same_entry_with_distinct_execution_identities() {
        let dir = map_fixture_tree("creation_identity_ambiguity");
        let image = vec![0u8; 0x400];
        let load_addr = 0x4000_0000u32;
        let ghidra_entry = load_addr + 0x100;
        let thumb_entry = load_addr + 0x200;
        let record = ghidra_function_in_image(
            "FUN_target",
            ghidra_entry,
            ghidra_entry + 8,
            &[],
            &image,
            load_addr,
        );
        write_map_functions(&dir, &[record]);
        let (identity, _) = identity_for(&dir, ghidra_entry, &image, load_addr);
        let mut ghidra_symbol = ghidra_symbol_at(ghidra_entry, identity.execution_blake3, None);
        ghidra_symbol.original_name = "FUN_target".into();
        let range = DecodeRangeWire {
            isa: "thumb",
            start: format!("0x{thumb_entry:08x}"),
            end: format!("0x{:08x}", thumb_entry + 4),
            blake3: blake3::hash(
                &image[(thumb_entry - load_addr) as usize..(thumb_entry - load_addr + 4) as usize],
            )
            .to_hex()
            .to_string(),
        };
        let mk = |owner, digest| Symbol {
            address: format!("0x{thumb_entry:08x}"),
            arch: "thumb",
            tool: crate::recover_source::Tool::Radare2,
            owner,
            execution_blake3: Some([digest; 32]),
            decode_ranges: vec![range.clone()],
            name_conflicts: Vec::new(),
            original_name: "thumb_only".into(),
            name: Some("AtiParsePlusCOPS".into()),
            tier: Tier::Recovered,
            evidence: vec![],
            annotations: vec![],
        };
        let symbols = vec![
            ghidra_symbol,
            mk(
                FunctionOwner::Run {
                    producer: crate::analysis_tool::AnalysisTool::Radare2,
                    region_index: 0,
                    run_index: 0,
                },
                7,
            ),
            mk(
                FunctionOwner::Run {
                    producer: crate::analysis_tool::AnalysisTool::Radare2,
                    region_index: 1,
                    run_index: 0,
                },
                8,
            ),
        ];
        let map_path = dir.join("map.json");

        let written = write_pass2_symbol_map(
            &map_path,
            &dir,
            "02_MAIN",
            u64::from(load_addr),
            &image,
            &symbols,
            None,
            None,
            &runtime_for(&image, load_addr),
        )
        .unwrap();

        assert_eq!(written.creation_count, 0);
        assert_eq!(written.creation_skips.ambiguous, 1);
    }

    #[test]
    fn map_skips_every_entry_requesting_the_same_creation_name() {
        let dir = map_fixture_tree("creation_duplicate_names");
        let image = vec![0u8; 0x400];
        let load_addr = 0x4000_0000u32;
        let ghidra_entry = load_addr + 0x100;
        let record = ghidra_function_in_image(
            "FUN_target",
            ghidra_entry,
            ghidra_entry + 8,
            &[],
            &image,
            load_addr,
        );
        write_map_functions(&dir, &[record]);
        let (identity, _) = identity_for(&dir, ghidra_entry, &image, load_addr);
        let mut ghidra_symbol = ghidra_symbol_at(ghidra_entry, identity.execution_blake3, None);
        ghidra_symbol.original_name = "FUN_target".into();
        let mk = |entry: u32| Symbol {
            address: format!("0x{entry:08x}"),
            arch: "thumb",
            tool: crate::recover_source::Tool::Radare2,
            owner: FunctionOwner::Run {
                producer: crate::analysis_tool::AnalysisTool::Radare2,
                region_index: 0,
                run_index: 0,
            },
            execution_blake3: Some([7u8; 32]),
            decode_ranges: vec![DecodeRangeWire {
                isa: "thumb",
                start: format!("0x{entry:08x}"),
                end: format!("0x{:08x}", entry + 4),
                blake3: blake3::hash(
                    &image[(entry - load_addr) as usize..(entry - load_addr + 4) as usize],
                )
                .to_hex()
                .to_string(),
            }],
            name_conflicts: Vec::new(),
            original_name: "thumb_only".into(),
            name: Some("SharedCreationName".into()),
            tier: Tier::Recovered,
            evidence: vec![],
            annotations: vec![],
        };
        let symbols = vec![ghidra_symbol, mk(load_addr + 0x200), mk(load_addr + 0x300)];
        let map_path = dir.join("map.json");

        let written = write_pass2_symbol_map(
            &map_path,
            &dir,
            "02_MAIN",
            u64::from(load_addr),
            &image,
            &symbols,
            None,
            None,
            &runtime_for(&image, load_addr),
        )
        .unwrap();

        assert_eq!(written.creation_count, 0);
        assert_eq!(written.creation_skips.collision, 2);
    }

    #[test]
    fn map_serializes_creations_in_entry_order() {
        let dir = map_fixture_tree("creation_order");
        let image = vec![0u8; 0x400];
        let load_addr = 0x4000_0000u32;
        let ghidra_entry = load_addr + 0x100;
        let record = ghidra_function_in_image(
            "FUN_target",
            ghidra_entry,
            ghidra_entry + 8,
            &[],
            &image,
            load_addr,
        );
        write_map_functions(&dir, &[record]);
        let (identity, _) = identity_for(&dir, ghidra_entry, &image, load_addr);
        let mut ghidra_symbol = ghidra_symbol_at(ghidra_entry, identity.execution_blake3, None);
        ghidra_symbol.original_name = "FUN_target".into();
        let mk = |entry: u32, name: &str| Symbol {
            address: format!("0x{entry:08x}"),
            arch: "thumb",
            tool: crate::recover_source::Tool::Radare2,
            owner: FunctionOwner::Run {
                producer: crate::analysis_tool::AnalysisTool::Radare2,
                region_index: 0,
                run_index: 0,
            },
            execution_blake3: Some([entry as u8; 32]),
            decode_ranges: vec![DecodeRangeWire {
                isa: "thumb",
                start: format!("0x{entry:08x}"),
                end: format!("0x{:08x}", entry + 4),
                blake3: blake3::hash(
                    &image[(entry - load_addr) as usize..(entry - load_addr + 4) as usize],
                )
                .to_hex()
                .to_string(),
            }],
            name_conflicts: Vec::new(),
            original_name: "thumb_only".into(),
            name: Some(name.into()),
            tier: Tier::Recovered,
            evidence: vec![],
            annotations: vec![],
        };
        let symbols = vec![
            ghidra_symbol,
            mk(load_addr + 0x300, "NameThree"),
            mk(load_addr + 0x180, "NameOne"),
            mk(load_addr + 0x280, "NameTwo"),
        ];
        let map_path = dir.join("map.json");

        write_pass2_symbol_map(
            &map_path,
            &dir,
            "02_MAIN",
            u64::from(load_addr),
            &image,
            &symbols,
            None,
            None,
            &runtime_for(&image, load_addr),
        )
        .unwrap();

        let parsed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&map_path).unwrap()).unwrap();
        let entries: Vec<&str> = parsed["creations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|creation| creation["entry"].as_str().unwrap())
            .collect();
        assert_eq!(entries, vec!["0x40000180", "0x40000280", "0x40000300"]);
    }

    #[test]
    fn map_skips_creation_whose_first_decode_range_does_not_start_at_entry() {
        let dir = map_fixture_tree("creation_first_range");
        let image = vec![0u8; 0x400];
        let load_addr = 0x4000_0000u32;
        let ghidra_entry = load_addr + 0x100;
        let ok_entry = load_addr + 0x300;
        let split_entry = load_addr + 0x280;
        let prior = load_addr + 0x200;
        let record = ghidra_function_in_image(
            "FUN_target",
            ghidra_entry,
            ghidra_entry + 8,
            &[],
            &image,
            load_addr,
        );
        write_map_functions(&dir, &[record]);
        let (identity, _) = identity_for(&dir, ghidra_entry, &image, load_addr);
        let mut ghidra_symbol = ghidra_symbol_at(ghidra_entry, identity.execution_blake3, None);
        ghidra_symbol.original_name = "FUN_target".into();
        ghidra_symbol.name = Some("RealName".into());
        ghidra_symbol.tier = Tier::Recovered;

        let range = |start: u32, end: u32| DecodeRangeWire {
            isa: "thumb",
            start: format!("0x{start:08x}"),
            end: format!("0x{end:08x}"),
            blake3: blake3::hash(&image[(start - load_addr) as usize..(end - load_addr) as usize])
                .to_hex()
                .to_string(),
        };
        let mk = |entry: u32, ranges: Vec<DecodeRangeWire>, name: &str| Symbol {
            address: format!("0x{entry:08x}"),
            arch: "thumb",
            tool: crate::recover_source::Tool::Radare2,
            owner: FunctionOwner::Run {
                producer: crate::analysis_tool::AnalysisTool::Radare2,
                region_index: 0,
                run_index: 0,
            },
            execution_blake3: Some([7u8; 32]),
            decode_ranges: ranges,
            name_conflicts: Vec::new(),
            original_name: "thumb_only".into(),
            name: Some(name.into()),
            tier: Tier::Recovered,
            evidence: vec![],
            annotations: vec![],
        };
        let symbols = vec![
            ghidra_symbol,
            mk(
                ok_entry,
                vec![range(ok_entry, ok_entry + 4)],
                "AtiParsePlusCOPS",
            ),
            mk(
                split_entry,
                vec![range(prior, prior + 8), range(split_entry, split_entry + 4)],
                "AtiParsePlusCUSD",
            ),
        ];
        let map_path = dir.join("map.json");
        let written = write_pass2_symbol_map(
            &map_path,
            &dir,
            "02_MAIN",
            u64::from(load_addr),
            &image,
            &symbols,
            None,
            None,
            &runtime_for(&image, load_addr),
        )
        .unwrap();
        assert_eq!(written.creation_count, 1);
        assert_eq!(written.creation_skips.not_entry_start, 1);
        let parsed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&map_path).unwrap()).unwrap();
        let creations = parsed["creations"].as_array().unwrap();
        assert_eq!(creations.len(), 1);
        assert_eq!(creations[0]["entry"], format!("0x{ok_entry:08x}"));
        assert_eq!(creations[0]["final_primary"], "AtiParsePlusCOPS");
    }

    #[test]
    fn map_emits_mirror_decisions_for_thunk_chains_of_renamed_targets() {
        let dir = map_fixture_tree("thunk_chain");
        let image = vec![0u8; 0x400];
        let load_addr = 0x4000_0000u32;
        let target_entry = load_addr + 0x100;
        let direct_entry = load_addr + 0x200;
        let chained_entry = load_addr + 0x300;
        let mut target = ghidra_function_in_image(
            "FUN_target",
            target_entry,
            target_entry + 8,
            &[],
            &image,
            load_addr,
        );
        target["name"] = serde_json::json!("FUN_target");
        let mut direct = ghidra_function_in_image(
            "thunk_FUN_target",
            direct_entry,
            direct_entry + 4,
            &[],
            &image,
            load_addr,
        );
        direct["thunk_of"] = serde_json::json!(format!("0x{target_entry:x}"));
        let mut chained = ghidra_function_in_image(
            "thunk_thunk_FUN_target",
            chained_entry,
            chained_entry + 4,
            &[],
            &image,
            load_addr,
        );
        chained["thunk_of"] = serde_json::json!(format!("0x{direct_entry:x}"));
        write_map_functions(&dir, &[chained, direct, target]);

        let mut symbols = Vec::new();
        for entry in [target_entry, direct_entry, chained_entry] {
            let (identity, _) = identity_for(&dir, entry, &image, load_addr);
            let mut symbol = ghidra_symbol_at(entry, identity.execution_blake3, None);
            symbol.original_name = if entry == target_entry {
                "FUN_target".to_string()
            } else if entry == direct_entry {
                "thunk_FUN_target".to_string()
            } else {
                "thunk_thunk_FUN_target".to_string()
            };
            if entry == target_entry {
                symbol.name = Some("AtiParsePlusCOPS".to_string());
                symbol.tier = Tier::Recovered;
            }
            symbols.push(symbol);
        }

        let map_path = dir.join("map.json");
        let written = write_pass2_symbol_map(
            &map_path,
            &dir,
            "02_MAIN",
            u64::from(load_addr),
            &image,
            &symbols,
            None,
            None,
            &runtime_for(&image, load_addr),
        )
        .unwrap();
        assert_eq!(written.execution_count, 3);

        let parsed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&map_path).unwrap()).unwrap();
        let decisions = parsed["symbols"].as_array().unwrap();
        let by_original = |name: &str| {
            decisions
                .iter()
                .find(|d| d["original_primary"] == name)
                .unwrap_or_else(|| panic!("no decision for {name}"))
                .clone()
        };
        let target_decision = by_original("FUN_target");
        assert_eq!(target_decision["action"], "rename");
        assert_eq!(target_decision["final_primary"], "AtiParsePlusCOPS");
        // Ghidra mirrors the renamed primary onto every thunk in the chain,
        // recursively; the map must expect exactly that, keeping each
        // thunk's own source.
        let direct_decision = by_original("thunk_FUN_target");
        assert_eq!(direct_decision["action"], "mirror");
        assert_eq!(direct_decision["final_primary"], "AtiParsePlusCOPS");
        assert_eq!(direct_decision["final_source"], "default");
        let chained_decision = by_original("thunk_thunk_FUN_target");
        assert_eq!(chained_decision["action"], "mirror");
        assert_eq!(chained_decision["final_primary"], "AtiParsePlusCOPS");
        assert_eq!(chained_decision["final_source"], "default");
        // A mirror never counts as an applied decision.
        assert_eq!(written.applied_decision_count, 1);
    }

    #[test]
    fn map_v4_binds_authenticated_exception_context_and_stronger_transition() {
        let dir = map_fixture_tree("exception_transition");
        let image = exception_fixture_image();
        let mut symbols = exception_execution_symbols(
            &dir,
            &image,
            &[(EXCEPTION_RESET_ENTRY, "Reset", "analysis")],
        );
        symbols[0].name = Some("registered_reset".into());
        symbols[0].evidence = vec![TaggedEvidence::Registration {
            value: "registered_reset".into(),
        }];
        let exception = crate::decompile::test_context_from_fixture(
            crate::decompile::TestExceptionContextState::Fresh,
        );
        let map_path = dir.join("map.json");

        write_pass2_symbol_map(
            &map_path,
            &dir,
            "00_BOOT",
            u64::from(EXCEPTION_TEST_BASE),
            &image,
            &symbols,
            Some(&exception),
            None,
            &runtime_for(&image, EXCEPTION_TEST_BASE),
        )
        .unwrap();

        let parsed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&map_path).unwrap()).unwrap();
        assert_eq!(parsed["format"], "pixel-modem-extractor-symbol-map-v5");
        assert_eq!(parsed["exception_roots"]["identity"], exception.identity());
        assert_eq!(
            parsed["exception_roots"]["manifest_blake3"],
            exception.manifest_blake3()
        );
        assert!(parsed["predecessor_symbol_pass2"].is_null());
        let transition = &parsed["symbols"][0]["exception_transition"];
        assert_eq!(transition["from"], "exception_owned");
        assert_eq!(transition["to"], "pass2_owned");
        assert_eq!(transition["authority"], "registration");
        assert_eq!(transition["original_primary"]["name"], "Reset");
        assert_eq!(transition["original_primary"]["source"], "analysis");
        assert_eq!(transition["final_primary"]["name"], "registered_reset");
        assert_eq!(transition["final_primary"]["source"], "user_defined");

        symbols[0].evidence.clear();
        let unproven_path = dir.join("unproven-map.json");
        write_pass2_symbol_map(
            &unproven_path,
            &dir,
            "00_BOOT",
            u64::from(EXCEPTION_TEST_BASE),
            &image,
            &symbols,
            Some(&exception),
            None,
            &runtime_for(&image, EXCEPTION_TEST_BASE),
        )
        .unwrap();
        let unproven: serde_json::Value =
            serde_json::from_slice(&std::fs::read(unproven_path).unwrap()).unwrap();
        assert_eq!(unproven["symbols"][0]["action"], "preserve");
        assert!(unproven["symbols"][0]["exception_transition"].is_null());
    }

    #[test]
    fn map_preserves_authenticated_non_owned_exception_primaries() {
        let dir = map_fixture_tree("exception_non_owned_preserve");
        let image = exception_fixture_image();
        let mut symbols = exception_execution_symbols(
            &dir,
            &image,
            &[
                (EXCEPTION_RESET_ENTRY, "foreign_primary", "imported"),
                (EXCEPTION_SHARED_ENTRY, "FUN_40010280", "default"),
            ],
        );
        symbols[0].name = Some("strong_func_name".into());
        symbols[0].evidence = vec![TaggedEvidence::Func {
            value: "strong_func_name".into(),
        }];
        symbols[1].name = Some("strong_registration_name".into());
        symbols[1].evidence = vec![TaggedEvidence::Registration {
            value: "strong_registration_name".into(),
        }];
        let exception = crate::decompile::test_context_from_fixture(
            crate::decompile::TestExceptionContextState::PreservedReset,
        );
        let map_path = dir.join("map.json");

        write_pass2_symbol_map(
            &map_path,
            &dir,
            "00_BOOT",
            u64::from(EXCEPTION_TEST_BASE),
            &image,
            &symbols,
            Some(&exception),
            None,
            &runtime_for(&image, EXCEPTION_TEST_BASE),
        )
        .unwrap();

        let map: serde_json::Value =
            serde_json::from_slice(&std::fs::read(map_path).unwrap()).unwrap();
        for (decision, current_name, current_source) in [
            (&map["symbols"][0], "foreign_primary", "imported"),
            (&map["symbols"][1], "FUN_40010280", "default"),
        ] {
            assert_eq!(decision["action"], "preserve");
            assert_eq!(decision["final_primary"], current_name);
            assert_eq!(decision["final_source"], current_source);
            assert!(decision["exception_transition"].is_null());
        }
    }

    #[test]
    fn map_pass2_owned_context_reproduces_transition_and_predecessor() {
        let dir = map_fixture_tree("exception_pass2_owned");
        let image = exception_fixture_image();
        let mut symbols = exception_execution_symbols(
            &dir,
            &image,
            &[(EXCEPTION_RESET_ENTRY, "registered_reset", "user_defined")],
        );
        symbols[0].name = Some("newer_func_evidence".into());
        symbols[0].evidence = vec![TaggedEvidence::Func {
            value: "newer_func_evidence".into(),
        }];
        let exception = crate::decompile::test_context_from_fixture(
            crate::decompile::TestExceptionContextState::Pass2OwnedReset,
        );
        let map_path = dir.join("map.json");

        write_pass2_symbol_map(
            &map_path,
            &dir,
            "00_BOOT",
            u64::from(EXCEPTION_TEST_BASE),
            &image,
            &symbols,
            Some(&exception),
            None,
            &runtime_for(&image, EXCEPTION_TEST_BASE),
        )
        .unwrap();

        let map: serde_json::Value =
            serde_json::from_slice(&std::fs::read(map_path).unwrap()).unwrap();
        assert_eq!(
            map["predecessor_symbol_pass2"],
            exception.predecessor_symbol_pass2().unwrap()
        );
        let decision = &map["symbols"][0];
        assert_eq!(decision["action"], "rename");
        assert_eq!(decision["original_primary"], "Reset");
        assert_eq!(decision["original_source"], "analysis");
        assert_eq!(decision["final_primary"], "registered_reset");
        assert_eq!(decision["final_source"], "user_defined");
        assert_eq!(
            decision["exception_transition"]["authority"],
            "registration"
        );
        assert_eq!(
            decision["exception_transition"]["original_primary"]["symbol_id"],
            100
        );
        assert_eq!(
            decision["exception_transition"]["final_primary"]["name"],
            "registered_reset"
        );
    }

    #[test]
    fn map_rejects_authenticated_exception_primary_mismatch() {
        let dir = map_fixture_tree("exception_primary_mismatch");
        let image = exception_fixture_image();
        let mut symbols = exception_execution_symbols(
            &dir,
            &image,
            &[(EXCEPTION_RESET_ENTRY, "NotReset", "analysis")],
        );
        symbols[0].name = Some("registered_reset".into());
        symbols[0].evidence = vec![TaggedEvidence::Registration {
            value: "registered_reset".into(),
        }];
        let exception = crate::decompile::test_context_from_fixture(
            crate::decompile::TestExceptionContextState::Fresh,
        );

        let error = write_pass2_symbol_map(
            &dir.join("map.json"),
            &dir,
            "00_BOOT",
            u64::from(EXCEPTION_TEST_BASE),
            &image,
            &symbols,
            Some(&exception),
            None,
            &runtime_for(&image, EXCEPTION_TEST_BASE),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("current primary"), "{error}");
    }

    #[test]
    fn map_v4_field_order_is_exact_and_functions_blake3_covers_retained_bytes() {
        let dir = map_fixture_tree("order");
        let image = vec![0u8; 0x400];
        let load_addr = 0x4000_0000u32;
        let (symbols, _) = two_execution_fixture(&dir, &image, load_addr, ["default", "default"]);
        let map_path = dir.join("map.json");
        let written = write_pass2_symbol_map(
            &map_path,
            &dir,
            "02_MAIN",
            u64::from(load_addr),
            &image,
            &symbols,
            None,
            None,
            &runtime_for(&image, load_addr),
        )
        .unwrap();

        let text = std::fs::read_to_string(&map_path).unwrap();
        // Top-level order is part of the canonical v4 map contract.
        let top: Vec<&str> = [
            "format",
            "image",
            "exception_roots",
            "pal",
            "functions_blake3",
            "predecessor_symbol_pass2",
            "executions",
            "thumb_creation_lineage",
            "symbols",
            "creations",
        ]
        .to_vec();
        let mut positions: Vec<usize> = Vec::new();
        for key in &top {
            let needle = format!("\"{key}\":");
            let at = text
                .find(&needle)
                .unwrap_or_else(|| panic!("no {key} in map"));
            positions.push(at);
            assert_eq!(
                text[..at].matches('{').count() - text[..at].matches('}').count(),
                1,
                "key {key} is not top-level"
            );
        }
        assert!(
            positions.windows(2).all(|w| w[0] < w[1]),
            "top-level keys out of order: {top:?}"
        );
        // image block: label,base_addr,size,blake3.
        let image_block = text
            .split("\"image\": {")
            .nth(1)
            .unwrap()
            .split("},")
            .next()
            .unwrap();
        let mut positions: Vec<usize> = Vec::new();
        for key in ["label", "base_addr", "size", "blake3"] {
            positions.push(image_block.find(&format!("\"{key}\":")).unwrap());
        }
        assert!(positions.windows(2).all(|w| w[0] < w[1]));
        let exception_block = text
            .split("\"exception_roots\": {")
            .nth(1)
            .unwrap()
            .split("},")
            .next()
            .unwrap();
        assert!(exception_block.contains("\"identity\": \"none\""));
        assert!(exception_block.contains("\"manifest_blake3\": null"));
        // PAL block for none: identity + null hashes.
        let pal_block = text
            .split("\"pal\": {")
            .nth(1)
            .unwrap()
            .split("},")
            .next()
            .unwrap();
        assert!(pal_block.contains("\"identity\": \"none\""));
        assert!(pal_block.contains("\"manifest_blake3\": null"));
        assert!(pal_block.contains("\"scatter_load_map_blake3\": null"));
        // Execution records: producer,entry,execution_blake3,decode_ranges.
        let execution_block = text
            .split("\"executions\": [")
            .nth(1)
            .unwrap()
            .split("],\n  \"thumb_creation_lineage\"")
            .next()
            .unwrap();
        for key in ["producer", "entry", "execution_blake3", "decode_ranges"] {
            assert!(execution_block.contains(&format!("\"{key}\":")));
        }
        assert!(text.contains("\"thumb_creation_lineage\": []"));
        // Decision authorization fields follow the evidence-independent fields.
        let symbols_block = text.split("\"symbols\": [").nth(1).unwrap();
        let mut positions: Vec<usize> = Vec::new();
        for key in [
            "execution",
            "original_primary",
            "original_source",
            "final_primary",
            "final_source",
            "action",
            "annotations",
            "exception_transition",
            "pal_transition",
        ] {
            positions.push(symbols_block.find(&format!("\"{key}\":")).unwrap());
        }
        assert!(positions.windows(2).all(|w| w[0] < w[1]));

        // functions_blake3 is the plain BLAKE3 over the exact retained bytes,
        // including the pretty-print whitespace and terminal newline we wrote.
        let retained = std::fs::read(dir.join("decompiled/functions.json")).unwrap();
        assert_eq!(
            written.functions_blake3,
            crate::manifest::blake3_bytes(&retained)
        );
        assert_eq!(written.execution_count, 2);
        assert_eq!(
            written.map_blake3,
            crate::manifest::blake3_bytes(std::fs::read(&map_path).unwrap().as_slice())
        );
    }

    #[test]
    fn map_covers_every_accepted_ghidra_execution_once_in_sorted_order() {
        let dir = map_fixture_tree("coverage");
        let image = vec![0u8; 0x400];
        let load_addr = 0x4000_0000u32;
        // Third record: quarantined (decode errors, no accepted projection).
        let mut quarantined = ghidra_function_in_image(
            "FUN_00000300",
            load_addr + 0x300,
            load_addr + 0x308,
            &[],
            &image,
            load_addr,
        );
        quarantined["decode_ranges"] = serde_json::json!([]);
        quarantined["decode_range_errors"] = serde_json::json!([{
            "kind": "missing_isa_context",
            "address": format!("0x{:08x}", load_addr + 0x300),
            "end": format!("0x{:08x}", load_addr + 0x308),
        }]);

        let (mut symbols, executions) =
            two_execution_fixture(&dir, &image, load_addr, ["default", "default"]);
        let quarantined_entry = load_addr + 0x300;
        symbols.push(Symbol {
            address: format!("0x{quarantined_entry:08x}"),
            arch: "thumb",
            tool: crate::recover_source::Tool::Radare2,
            owner: FunctionOwner::Run {
                producer: crate::analysis_tool::AnalysisTool::Radare2,
                region_index: 1,
                run_index: 0,
            },
            execution_blake3: Some([0x33; 32]),
            decode_ranges: vec![DecodeRangeWire {
                isa: "thumb",
                start: format!("0x{quarantined_entry:x}"),
                end: format!("0x{:x}", quarantined_entry + 4),
                blake3: blake3::hash(&image[0x300..0x304]).to_hex().to_string(),
            }],
            original_name: "thumb_at_quarantined_ghidra_entry".into(),
            name: Some("RecoveredAtQuarantinedEntry".into()),
            tier: Tier::Recovered,
            evidence: Vec::new(),
            annotations: Vec::new(),
            name_conflicts: Vec::new(),
        });
        let bytes = std::fs::read(dir.join("decompiled/functions.json")).unwrap();
        let mut records: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();
        records.push(quarantined);
        write_map_functions(&dir, &records);

        let map_path = dir.join("map.json");
        let written = write_pass2_symbol_map(
            &map_path,
            &dir,
            "02_MAIN",
            u64::from(load_addr),
            &image,
            &symbols,
            None,
            None,
            &runtime_for(&image, load_addr),
        )
        .unwrap();
        assert_eq!(written.execution_count, 2, "quarantined record leaked in");
        assert_eq!(
            written.creation_count, 0,
            "a retained quarantined Ghidra entry authorized Thumb creation"
        );
        assert!(written.creation_requests.is_empty());

        let parsed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&map_path).unwrap()).unwrap();
        let executions_json = parsed["executions"].as_array().unwrap();
        let entries: Vec<u64> = executions_json
            .iter()
            .map(|e| {
                u64::from_str_radix(e["entry"].as_str().unwrap().trim_start_matches("0x"), 16)
                    .unwrap()
            })
            .collect();
        assert_eq!(
            entries,
            vec![u64::from(load_addr + 0x100), u64::from(load_addr + 0x200)],
            "executions are not sorted by entry"
        );
        assert!(executions_json.iter().all(|e| e["producer"] == "ghidra"));
        let decisions = parsed["symbols"].as_array().unwrap();
        assert_eq!(decisions.len(), 2);
        for (index, decision) in decisions.iter().enumerate() {
            assert_eq!(decision["execution"], index as u64);
        }
        // Every declared execution_blake3 matches the recomputed identity.
        for (execution, json) in executions.iter().zip(executions_json) {
            assert_eq!(json["execution_blake3"], execution.2);
        }
    }

    #[test]
    fn map_preserves_all_four_primary_sources_and_action_rules() {
        for source in ["default", "analysis", "imported", "user_defined"] {
            let dir = map_fixture_tree(&format!("source_{source}"));
            let image = vec![0u8; 0x400];
            let load_addr = 0x4000_0000u32;
            let (mut symbols, _) =
                two_execution_fixture(&dir, &image, load_addr, [source, "default"]);
            // First execution: a recovered rename; second: plain preserve.
            symbols[0].name = Some("Recovered_Name".into());
            symbols[0].tier = Tier::Recovered;
            let map_path = dir.join("map.json");
            write_pass2_symbol_map(
                &map_path,
                &dir,
                "02_MAIN",
                u64::from(load_addr),
                &image,
                &symbols,
                None,
                None,
                &runtime_for(&image, load_addr),
            )
            .unwrap();
            let parsed: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&map_path).unwrap()).unwrap();
            let decisions = parsed["symbols"].as_array().unwrap();
            assert_eq!(decisions[0]["original_source"], source);
            assert_eq!(decisions[0]["pal_transition"], serde_json::Value::Null);
            match source {
                // A recovered rename displaces default and analysis primaries.
                "default" | "analysis" => {
                    assert_eq!(decisions[0]["action"], "rename");
                    assert_eq!(decisions[0]["final_source"], "user_defined");
                }
                // Genuine imported and user-defined names stay protected: the
                // decision downgrades to preserve with identical fields.
                "imported" | "user_defined" => {
                    assert_eq!(decisions[0]["action"], "preserve");
                    assert_eq!(decisions[0]["final_source"], source);
                    assert_eq!(
                        decisions[0]["final_primary"],
                        decisions[0]["original_primary"]
                    );
                }
                other => panic!("unknown source {other}"),
            }
            assert_eq!(decisions[1]["action"], "preserve");
            assert_eq!(decisions[1]["original_source"], "default");
            assert_eq!(decisions[1]["final_source"], "default");
            assert_eq!(
                decisions[1]["final_primary"],
                decisions[1]["original_primary"]
            );
        }
    }

    fn pal_ctx(identity: &str, applications: Vec<(u32, PalApplicationRef)>) -> PalPass2Context {
        PalPass2Context {
            identity: identity.to_string(),
            manifest_blake3: "b".repeat(64),
            scatter_load_map_blake3: Some("c".repeat(64)),
            applications: applications.into_iter().collect(),
        }
    }

    /// Rewrite the first record's primary name in the retained functions.json
    /// (the PAL-applied-primary fixture state) and return the updated bytes.
    fn retitle_first_record(dir: &Path, name: &str) {
        let bytes = std::fs::read(dir.join("decompiled/functions.json")).unwrap();
        let mut records: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();
        let index = records
            .iter()
            .position(|record| {
                record["entry"]
                    .as_str()
                    .unwrap()
                    .trim_start_matches("0x")
                    .parse::<u32>()
                    .map(|entry| format!("{entry:08x}").contains("100"))
                    .unwrap_or(false)
            })
            .or_else(|| {
                records
                    .iter()
                    .position(|record| record["name"].as_str().is_some_and(|n| n.ends_with("100")))
            })
            .expect("fixture record at +0x100");
        records[index]["name"] = serde_json::json!(name);
        std::fs::write(
            dir.join("decompiled/functions.json"),
            serde_json::to_vec_pretty(&records).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn map_pal_transition_only_on_authorized_pal_rename() {
        let dir = map_fixture_tree("transition");
        let image = vec![0u8; 0x400];
        let load_addr = 0x4000_0000u32;
        let (mut symbols, executions) =
            two_execution_fixture(&dir, &image, load_addr, ["analysis", "default"]);
        retitle_first_record(&dir, "pal_TaskEntry_alpha");

        // Entry +0x100 is the PAL-applied primary (original name == desired);
        // a recovered rename over it carries the exact transition. Entry +0x200
        // has a provisional rename: never a transition.
        symbols[0].original_name = "pal_TaskEntry_alpha".into();
        symbols[0].name = Some("Func_Winner".into());
        symbols[0].tier = Tier::Recovered;
        symbols[0].evidence = vec![TaggedEvidence::Registration {
            value: "Func_Winner".into(),
        }];
        symbols[1].name = Some("guess_tok_00000200".into());
        symbols[1].tier = Tier::Provisional;

        let pal = pal_ctx(
            "v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:2:1",
            vec![(
                load_addr + 0x100,
                pal_app("pal_TaskEntry_alpha", &[("alpha", 0)]),
            )],
        );
        let map_path = dir.join("map.json");
        write_pass2_symbol_map(
            &map_path,
            &dir,
            "02_MAIN",
            u64::from(load_addr),
            &image,
            &symbols,
            None,
            Some(&pal),
            &runtime_for(&image, load_addr),
        )
        .unwrap();

        let parsed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&map_path).unwrap()).unwrap();
        assert_eq!(parsed["pal"]["identity"], pal.identity);
        assert_eq!(parsed["pal"]["manifest_blake3"], "b".repeat(64));
        assert_eq!(parsed["pal"]["scatter_load_map_blake3"], "c".repeat(64));
        let decisions = parsed["symbols"].as_array().unwrap();
        assert_eq!(
            decisions[0]["pal_transition"],
            serde_json::json!({"from": "pal_owned", "to": "pass2_owned"})
        );
        // A provisional rename never carries a transition.
        assert_eq!(decisions[1]["action"], "rename");
        assert_eq!(decisions[1]["final_source"], "analysis");
        assert_eq!(decisions[1]["pal_transition"], serde_json::Value::Null);

        // A rename of an entry whose original primary is NOT the desired PAL
        // primary carries no transition even under a present PAL context.
        let dir2 = map_fixture_tree("transition_nonmatching");
        let (mut symbols2, _) =
            two_execution_fixture(&dir2, &image, load_addr, ["analysis", "default"]);
        retitle_first_record(&dir2, "unrelated_existing");
        symbols2[0].original_name = "unrelated_existing".into();
        symbols2[0].name = Some("Func_Winner".into());
        symbols2[0].tier = Tier::Recovered;
        symbols2[0].evidence = vec![TaggedEvidence::Registration {
            value: "Func_Winner".into(),
        }];
        let map_path2 = dir2.join("map.json");
        write_pass2_symbol_map(
            &map_path2,
            &dir2,
            "02_MAIN",
            u64::from(load_addr),
            &image,
            &symbols2,
            None,
            Some(&pal),
            &runtime_for(&image, load_addr),
        )
        .unwrap();
        let parsed2: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&map_path2).unwrap()).unwrap();
        assert_eq!(
            parsed2["symbols"][0]["pal_transition"],
            serde_json::Value::Null
        );
        let _ = executions;
    }

    #[test]
    fn map_rejects_annotation_and_primary_limits() {
        let dir = map_fixture_tree("limits");
        let image = vec![0u8; 0x400];
        let load_addr = 0x4000_0000u32;
        let base = |symbols: Vec<Symbol>| {
            let dir = dir.clone();
            let map_path = dir.join("map.json");
            write_pass2_symbol_map(
                &map_path,
                &dir,
                "02_MAIN",
                u64::from(load_addr),
                &image,
                &symbols,
                None,
                None,
                &runtime_for(&image, load_addr),
            )
        };

        let (mut symbols, _) =
            two_execution_fixture(&dir, &image, load_addr, ["default", "default"]);
        symbols[0].annotations = (0..257).map(|i| format!("ann{i}")).collect();
        let err = base(symbols.clone()).unwrap_err().to_string();
        assert!(err.contains("256"), "{err}");

        let (mut symbols, _) =
            two_execution_fixture(&dir, &image, load_addr, ["default", "default"]);
        symbols[0].annotations = vec!["x".repeat(4097)];
        let err = base(symbols.clone()).unwrap_err().to_string();
        assert!(err.contains("4096"), "{err}");

        let (mut symbols, _) =
            two_execution_fixture(&dir, &image, load_addr, ["default", "default"]);
        symbols[0].name = Some("n".repeat(2001));
        let err = base(symbols).unwrap_err().to_string();
        assert!(err.contains("2000"), "{err}");
    }

    #[test]
    fn map_rejects_nul_and_unpaired_surrogates() {
        let dir = map_fixture_tree("strings");
        let image = vec![0u8; 0x400];
        let load_addr = 0x4000_0000u32;
        let (mut symbols, _) =
            two_execution_fixture(&dir, &image, load_addr, ["default", "default"]);
        symbols[0].annotations = vec!["bad\u{0}nul".into()];
        let err = write_pass2_symbol_map(
            &dir.join("map.json"),
            &dir,
            "02_MAIN",
            u64::from(load_addr),
            &image,
            &symbols,
            None,
            None,
            &runtime_for(&image, load_addr),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("NUL"), "{err}");
    }

    #[test]
    fn map_cross_checks_symbol_original_name_against_retained_record() {
        let dir = map_fixture_tree("crosscheck");
        let image = vec![0u8; 0x400];
        let load_addr = 0x4000_0000u32;
        let (mut symbols, _) =
            two_execution_fixture(&dir, &image, load_addr, ["default", "default"]);
        symbols[0].original_name = "NOT_THE_RECORD_NAME".into();
        let err = write_pass2_symbol_map(
            &dir.join("map.json"),
            &dir,
            "02_MAIN",
            u64::from(load_addr),
            &image,
            &symbols,
            None,
            None,
            &runtime_for(&image, load_addr),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("original primary"), "{err}");
    }

    #[test]
    fn build_map_attaches_pal_evidence_without_merging_identities() {
        let root = tmp(&format!("pme_sym_pal_build_{}", std::process::id()));
        let dec = root.join("decompiled");
        std::fs::create_dir_all(&dec).unwrap();
        let mut image = vec![0u8; 0x300];
        image[0x100..0x104].copy_from_slice(&[0x01, 0x00, 0x80, 0xe0]);
        image[0x104..0x108].copy_from_slice(&[0x1e, 0xff, 0x2f, 0xe1]);
        std::fs::write(root.join("02_MAIN.bin"), &image).unwrap();
        std::fs::write(
            dec.join("functions.json"),
            serde_json::to_vec(&vec![ghidra_function_in_image(
                "pal_TaskEntry_alpha",
                0x100,
                0x108,
                &[],
                &image,
                0,
            )])
            .unwrap(),
        )
        .unwrap();
        let manifest = root.join("manifest.json");
        std::fs::write(&manifest, r#"{"toc":[{"name":"MAIN","load_addr":0}]}"#).unwrap();

        let pal = pal_ctx(
            "v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:1:0",
            vec![(0x100, pal_app("pal_TaskEntry_alpha", &[("alpha", 0)]))],
        );
        let symbols = build_map(
            &root,
            "02_MAIN",
            &HashMap::new(),
            &manifest,
            None,
            Some(&pal),
        )
        .unwrap();

        // The Ghidra record at the application entry carries pal_task evidence
        // and the recovered task primary; the Thumb records (same tree, other
        // owners) carry none.
        let ghidra_symbol = symbols
            .iter()
            .find(|s| s.owner == FunctionOwner::Ghidra && s.address == "0x00000100")
            .unwrap();
        assert!(
            ghidra_symbol
                .evidence
                .iter()
                .any(|e| matches!(&e, TaggedEvidence::PalTask { task } if task.name == "alpha"))
        );
        assert_eq!(ghidra_symbol.name.as_deref(), Some("pal_TaskEntry_alpha"));
        assert_eq!(ghidra_symbol.tier, Tier::Recovered);
        // The PAL annotation line survives every stronger rename (decide()
        // attaches it whenever pal evidence exists, regardless of winner).
        assert!(
            ghidra_symbol
                .annotations
                .iter()
                .any(|annotation| annotation.starts_with("pal task: alpha")),
            "PAL annotation missing: {:?}",
            ghidra_symbol.annotations
        );
        assert!(
            symbols
                .iter()
                .filter(|s| s.owner != FunctionOwner::Ghidra)
                .all(|s| !s
                    .evidence
                    .iter()
                    .any(|e| matches!(&e, TaggedEvidence::PalTask { .. }))),
            "pal evidence must attach per exact entry"
        );
    }

    /// One Ghidra `functions.json` record whose validated decode projection is
    /// Thumb (`bx lr`, 2 bytes). Every Ghidra record carries the family label
    /// `arch: "arm"` regardless — PAL applications must therefore match on the
    /// record's actual decode ISA, not the label.
    fn thumb_ghidra_record_tree(tag: &str, record_name: &str, data_refs: &[u32]) -> PathBuf {
        let root = tmp(&format!("pme_sym_pal_thumb_{tag}_{}", std::process::id()));
        let dec = root.join("decompiled");
        std::fs::create_dir_all(&dec).unwrap();
        let mut image = vec![0u8; 0x300];
        image[0x100..0x102].copy_from_slice(&[0x70, 0x47]); // thumb: bx lr
        std::fs::write(root.join("02_MAIN.bin"), &image).unwrap();
        let record = serde_json::json!({
            "name": record_name,
            "primary_source": "analysis",
            "entry": "0x100",
            "end": "0x102",
            "size": 2,
            "decode_ranges": [{
                "isa": "thumb",
                "start": "0x100",
                "end": "0x102",
                "blake3": crate::manifest::blake3_bytes(&image[0x100..0x102]),
            }],
            "decode_range_errors": [],
            "data_refs": data_refs.iter().map(|r| format!("0x{r:x}")).collect::<Vec<_>>(),
        });
        std::fs::write(
            dec.join("functions.json"),
            serde_json::to_vec(&vec![record]).unwrap(),
        )
        .unwrap();
        let manifest = root.join("manifest.json");
        std::fs::write(&manifest, r#"{"toc":[{"name":"MAIN","load_addr":0}]}"#).unwrap();
        root
    }

    #[test]
    fn build_map_attaches_pal_evidence_by_decode_isa_not_arch_label() {
        // Layer 1: a Thumb-ISA application attaches its evidence to a Ghidra
        // record whose validated projection is Thumb (the family label is
        // "arm"), and a token guess at that record never displaces the task
        // primary. With the label comparison, the evidence silently failed to
        // attach and the provisional token name won.
        let root = thumb_ghidra_record_tree("attach", "pal_TaskEntry_gamma", &[0x20]);
        let tokens = HashMap::from([(0x20u32, "■format♦gamma tok■domain♦D".to_string())]);
        let manifest = root.join("manifest.json");
        let pal = pal_ctx(
            "v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:1:0",
            vec![(
                0x100,
                pal_app_isa("thumb", "pal_TaskEntry_gamma", &[("gamma", 2)]),
            )],
        );
        let symbols = build_map(&root, "02_MAIN", &tokens, &manifest, None, Some(&pal)).unwrap();

        let gamma = symbols
            .iter()
            .find(|s| s.owner == FunctionOwner::Ghidra && s.address == "0x00000100")
            .unwrap();
        assert!(
            gamma
                .evidence
                .iter()
                .any(|e| matches!(&e, TaggedEvidence::PalTask { task } if task.name == "gamma")),
            "the thumb-ISA application did not attach: {:?}",
            gamma.evidence
        );
        assert_eq!(gamma.name.as_deref(), Some("pal_TaskEntry_gamma"));
        assert_eq!(gamma.tier, Tier::Recovered);
        assert!(
            gamma
                .annotations
                .iter()
                .any(|annotation| annotation.starts_with("pal task: gamma")),
            "PAL annotation missing: {:?}",
            gamma.annotations
        );

        // An ARM-ISA application at the same thumb record attaches nothing
        // (and, without other evidence, no name is applied at all).
        let root = thumb_ghidra_record_tree("mismatch", "FUN_00000100", &[]);
        let pal = pal_ctx(
            "v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:1:0",
            vec![(0x100, pal_app("pal_TaskEntry_alpha", &[("alpha", 0)]))],
        );
        let symbols = build_map(
            &root,
            "02_MAIN",
            &HashMap::new(),
            &manifest,
            None,
            Some(&pal),
        )
        .unwrap();
        let record = symbols
            .iter()
            .find(|s| s.owner == FunctionOwner::Ghidra && s.address == "0x00000100")
            .unwrap();
        assert!(
            !record
                .evidence
                .iter()
                .any(|e| matches!(&e, TaggedEvidence::PalTask { .. })),
            "an ISA-mismatched application attached: {:?}",
            record.evidence
        );
        assert!(record.name.is_none());
    }

    #[test]
    fn exception_build_map_attaches_authenticated_evidence_by_exact_entry_and_decode_isa() {
        let exception = crate::decompile::test_context_from_fixture(
            crate::decompile::TestExceptionContextState::Fresh,
        );
        let root = exception_build_map_tree("exception_attach", "thumb", "UndefinedInstruction");
        let symbols = build_map(
            &root,
            "00_BOOT",
            &HashMap::new(),
            &root.join("manifest.json"),
            Some(&exception),
            None,
        )
        .unwrap();
        let attached = symbols
            .iter()
            .find(|symbol| symbol.owner == FunctionOwner::Ghidra)
            .unwrap();
        assert_eq!(attached.name.as_deref(), Some("UndefinedInstruction"));
        assert_eq!(attached.tier, Tier::Recovered);
        assert!(attached.evidence.iter().any(|evidence| matches!(
            evidence,
            TaggedEvidence::ExceptionRoot {
                role: "undefined_instruction",
                ..
            }
        )));

        let root = exception_build_map_tree("exception_attach_wrong_isa", "arm", "FUN_40010220");
        let symbols = build_map(
            &root,
            "00_BOOT",
            &HashMap::new(),
            &root.join("manifest.json"),
            Some(&exception),
            None,
        )
        .unwrap();
        let unattached = symbols
            .iter()
            .find(|symbol| symbol.owner == FunctionOwner::Ghidra)
            .unwrap();
        assert!(
            !unattached
                .evidence
                .iter()
                .any(|evidence| matches!(evidence, TaggedEvidence::ExceptionRoot { .. }))
        );
        assert!(unattached.name.is_none());
    }

    #[test]
    fn exception_current_primary_check_is_scoped_to_ghidra_owner() {
        let exception = crate::decompile::test_context_from_fixture(
            crate::decompile::TestExceptionContextState::Fresh,
        );
        let root =
            exception_build_map_tree("exception_owner_scope", "thumb", "UndefinedInstruction");
        let image = exception_fixture_image();
        let entry = 0x4001_0220u32;
        let start = (entry - EXCEPTION_TEST_BASE) as usize;
        let mut thumb =
            std::str::from_utf8(crate::thumb_analysis::ParsedThumbArtifact::consumer_v3_fixture())
                .unwrap()
                .to_string();
        for (from, to) in [
            ("0x4000", "0x40010220"),
            ("0x4008", "0x40010228"),
            ("0x4020", "0x40010240"),
            ("0x4040", "0x40010260"),
            ("0x4042", "0x40010262"),
            ("0x4060", "0x40010280"),
            ("0x4070", "0x40010290"),
            ("0x4080", "0x400102a0"),
            ("00004000.rizin.stdout", "40010220.rizin.stdout"),
        ] {
            thumb = thumb.replace(from, to);
        }
        thumb = thumb.replace(
            "71e0a99173564931c0b8acc52d2685a8e39c64dc52e3d02390fdac2a12b155cb",
            &crate::manifest::blake3_bytes(&image[start..start + 8]),
        );
        std::fs::write(root.join("decompiled/thumb_functions.json"), thumb).unwrap();

        let symbols = build_map(
            &root,
            "00_BOOT",
            &HashMap::new(),
            &root.join("manifest.json"),
            Some(&exception),
            None,
        )
        .unwrap();

        let same_entry = symbols
            .iter()
            .filter(|symbol| symbol.address == "0x40010220")
            .collect::<Vec<_>>();
        assert_eq!(same_entry.len(), 2);
        assert!(
            same_entry
                .iter()
                .any(|symbol| symbol.owner == FunctionOwner::Ghidra)
        );
        assert!(
            same_entry
                .iter()
                .any(|symbol| matches!(symbol.owner, FunctionOwner::Run { .. }))
        );
        assert!(
            same_entry
                .iter()
                .all(|symbol| symbol.evidence.iter().any(|evidence| matches!(
                    evidence,
                    TaggedEvidence::ExceptionRoot {
                        role: "undefined_instruction",
                        ..
                    }
                )))
        );
    }

    #[test]
    fn map_pal_transition_matches_thumb_decode_isa() {
        // Layer 2: the map writer's transition ISA check must compare the
        // application ISA against the record's decode ISA, so the authorized
        // registration rename of an applied Thumb task primary carries the
        // exact pal_transition instead of an arch-label mismatch error.
        let root = thumb_ghidra_record_tree("transition", "pal_TaskEntry_gamma", &[]);
        let image = std::fs::read(root.join("02_MAIN.bin")).unwrap();
        let load_addr = 0u32;
        let (identity, _) = identity_for(&root, 0x100, &image, load_addr);
        let decode_ranges = identity
            .decode_ranges
            .iter()
            .map(DecodeRangeWire::from_authenticated)
            .collect::<Vec<_>>();
        let symbols = vec![Symbol {
            address: "0x00000100".into(),
            arch: "arm", // the Ghidra family label, deliberately not the decode ISA
            tool: crate::recover_source::Tool::Ghidra,
            owner: FunctionOwner::Ghidra,
            execution_blake3: Some(identity.execution_blake3),
            decode_ranges,
            original_name: "pal_TaskEntry_gamma".into(),
            name: Some("gamma_task_fn".into()), // registration-rank rename
            tier: Tier::Recovered,
            evidence: vec![TaggedEvidence::Registration {
                value: "gamma_task_fn".into(),
            }],
            annotations: vec!["pal task: gamma slot=0x40010180 priority=7 stack=1024".into()],
            name_conflicts: Vec::new(),
        }];
        let pal = pal_ctx(
            "v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:1:0",
            vec![(
                0x100,
                pal_app_isa("thumb", "pal_TaskEntry_gamma", &[("gamma", 2)]),
            )],
        );
        let map_path = root.join("map.json");
        write_pass2_symbol_map(
            &map_path,
            &root,
            "02_MAIN",
            u64::from(load_addr),
            &image,
            &symbols,
            None,
            Some(&pal),
            &runtime_for(&image, load_addr),
        )
        .unwrap();
        let parsed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&map_path).unwrap()).unwrap();
        assert_eq!(
            parsed["symbols"][0]["pal_transition"],
            serde_json::json!({"from": "pal_owned", "to": "pass2_owned"}),
            "the thumb task rename lost its authorized transition: {parsed}"
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
            None,
            None,
        )
        .unwrap();
        let regs: Vec<&Symbol> = symbols
            .iter()
            .filter(|s| s.evidence.iter().any(|e| e.kind() == "registration"))
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
