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

use serde::Serialize;

/// Format string for `globals.json` v1. Future revisions add fields without
/// breaking v1 readers (forward-compat posture identical to Phase 2's
/// `thumb_functions.json` v1→v2).
pub const FORMAT_V1: &str = "pixel-modem-extractor-globals-v1";

/// Minimum identifier length. Filters out 1–2 char tokens (`id`, `pt`) that
/// are too generic to be meaningful global names.
#[expect(dead_code, reason = "consumed by globals::run in Phase 3.0 Task 4")]
const MIN_IDENT_LEN: usize = 3;

/// Generic identifier tokens filtered out of the candidate set. These appear
/// frequently in modem firmware strings (log macros, format specifiers,
/// C keywords) but are extremely unlikely to be global variable names.
/// Extend this set if the pre-check (Task 1) surfaces other generic tokens
/// polluting the results.
#[expect(dead_code, reason = "consumed by globals::run in Phase 3.0 Task 4")]
const GENERIC_TOKENS: &[&str] = &[
    "NULL", "null", "true", "false", "TRUE", "FALSE",
    "void", "int", "char", "long", "short", "unsigned", "signed",
    "src", "main", "include", "define", "struct", "union", "enum",
    "return", "sizeof", "static", "const", "extern", "volatile",
    "ERROR", "WARN", "INFO", "DEBUG", "TRACE",
    "LOG", "LOGE", "LOGW", "LOGI", "LOGD", "LOGV",
    "err", "error", "status", "ret", "retval", "result",
];

/// The arch attribution for a global — driven by which functions contributed
/// evidence. `Mixed` when at least one ARM and one Thumb function contributed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Arch {
    Arm,
    Thumb,
    Mixed,
}

/// One piece of evidence for a `(address, name)` association. Either a string
/// that mentions the name, or a function whose `data_refs` were used.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind")]
pub enum Evidence {
    /// A string at `address` whose content `value` mentions the global name.
    String {
        address: String,
        value: String,
    },
    /// A function at `address` whose `data_refs` produced the association.
    /// `name` is the Ghidra-side `FUN_<addr>` placeholder; `recovered_name`
    /// is present (and serialized) only when Phase 1 supplied a recovered name.
    Function {
        address: String,
        arch: Arch,
        name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        recovered_name: Option<String>,
    },
}

/// One resolved global: a `(address, name)` pair plus its evidence trail.
#[derive(Debug, Clone, Serialize)]
pub struct Global {
    pub address: String,
    pub arch: Arch,
    pub name: String,
    /// Always `"recovered"` in Phase 3.0. Future Phase 3.0.1 may add
    /// `"provisional"` for function-name-inferred globals.
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
}

impl GlobalsReport {
    pub fn empty() -> Self {
        Self { recovered_count: 0, conflicts_dropped: 0 }
    }
}
