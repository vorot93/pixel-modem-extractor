//! `decompose` — the exhaustive one-command pipeline. Runs extraction, decompiles
//! every modem image (Ghidra plus configured dense-Thumb analyzers), and runs every
//! decoder, marshaling all outputs into one per-image tree with a machine-readable
//! `report.json`. Best-effort:
//! a stage failure is recorded and the run continues; the process exits non-zero if
//! anything failed. `--prune` reduces the tree to only the terminal ("leaf") artifacts.

use crate::decompile::{self, ImageOutcome};
use crate::error::{Error, Result};
use crate::{
    decode_rf, global_shapes, global_types, globals, hwcfg, manifest, model, pipeline,
    recover_source, source_tree, symbolicate, tokens,
};
use serde::Serialize;
use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct Opts {
    pub no_verify: bool,
    pub prune: bool,
    pub ghidra_home: Option<PathBuf>,
    pub processor: String,
    /// Skip the Phase-1 symbolication pass 2 (escape hatch). When true, decompose
    /// uses today's single-pass decompile behavior and emits no symbol_map or
    /// pass-2 artifacts.
    pub no_symbol_pass: bool,
    /// Phase 2 escape hatch: when true, `TameAnalysis` runs in `datamark` mode
    /// (Phase-1 behavior) and `thumb_enrich` does not run for either pass.
    /// The public `--no-thumb-decompile` clap flag wires to this field.
    pub no_thumb_decompile: bool,
    /// Enable Rizin as a failure-only fallback for dense Thumb regions.
    /// radare2 remains required and is always attempted first. Default false.
    pub rizin_fallback: bool,
    /// Phase 2 / Surface B: test-only override that bypasses
    /// `baseline * wall_clock_multiplier` and supplies an absolute wall-clock
    /// budget for the tighten-watch kill decision. Wired to the hidden
    /// `--tighten-wall-clock-budget-sec` flag. Production callers leave `None`.
    pub tighten_wall_clock_budget_override: Option<std::time::Duration>,
    /// Phase 3.0.1: emit tier:"provisional" globals (name-prior tiebreakers).
    /// Wired to `--globals-provisional`. Off by default; Recovered-tier
    /// globals always emit.
    pub globals_provisional: bool,
    /// Phase 3.0.1 test-only: override the ARM proximity window (`K_ARM`).
    /// Wired to the hidden `--globals-k-arm`. `None` -> use `globals::K_ARM`.
    pub globals_k_arm: Option<usize>,
    /// Phase 3.0.1 test-only: override the Thumb proximity window (`K_THUMB`).
    /// Wired to the hidden `--globals-k-thumb`. `None` -> use `globals::K_THUMB`.
    pub globals_k_thumb: Option<usize>,
    /// Phase 3.2 type-application escape hatch: when true, `derive_global_types_maps`
    /// is not called and pass 2 receives no global-type input, so
    /// `ApplyGlobalTypes.java` does not run. Recovered shapes are still
    /// written to the `global_shapes.json` sidecar; only the `decompiled.c`
    /// `undefinedN` application is skipped. Wired to `--no-apply-global-types`.
    /// Default: apply.
    pub no_apply_global_types: bool,
    /// Opaque-image escape hatch: when true, images whose battery is
    /// unanimously opaque still run Ghidra + configured Thumb analyzers
    /// (run-everything behavior, for research). Default false (skip —
    /// nothing is recoverable from those bytes under the standard import).
    /// Wired to `--no-skip-opaque`.
    pub no_skip_opaque: bool,
}

#[derive(Debug, Serialize)]
pub struct ImageReport {
    pub image: String,
    pub status: &'static str, // "analyzed" | "failed" | "skipped"
    /// Battery verdict for the image bytes ("opaque"/"not_opaque"), consistent
    /// with manifest.json's `battery.label` for the same image — including on
    /// `--no-skip-opaque` runs, where an analyzed row can still be "opaque".
    /// Failed rows omit it (the Ghidra run itself is the headline for those).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification: Option<&'static str>,
    /// Why a skipped image was skipped: "opaque" (unanimous battery verdict;
    /// no Ghidra or Thumb analyzer ran, no decompiled/ sidecars exist).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped_reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub functions: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumb_functions: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumb_regions_requested: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumb_regions_succeeded: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumb_regions_failed: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumb_radare2_runs: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumb_rizin_runs: Option<usize>,
    /// Current Ghidra records with accepted execution projections.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ghidra_execution_accepted: Option<usize>,
    /// Current Ghidra records retained as whole-record quarantines.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ghidra_execution_quarantined: Option<usize>,
    /// Current retained Thumb records with accepted execution projections.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumb_execution_accepted: Option<usize>,
    /// Current retained Thumb records retained as whole-record quarantines.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumb_execution_quarantined: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumb_error: Option<String>,
    /// Reason-only terminal-validation failure: Ghidra completed but the export
    /// pair could not be certified as this run's output. Present exactly when
    /// the outcome is `ImageOutcome::TerminalInvalid`, which reports no `exit`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pass2_applied: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pass2_creation_candidates: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pass2_creation_map_skips: Option<symbolicate::Pass2CreationSkips>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pass2_created: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pass2_creation_reapplied: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pass2_creation_skipped_existing: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pass2_creation_skipped_collision: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pass2_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub globals_applied: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub globals_apply_skipped: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub globals_apply_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumb_decompiled: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumb_tighten_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumb_enrich_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub globals_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub globals_recovered: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub globals_provisional: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub globals_provisional_suppressed: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_shapes_inferred: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_shapes_no_evidence: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_shapes_conflicting: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_shape_observations: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_shapes_ghidra_quarantined: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_shapes_thumb_quarantined: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_shapes_quarantine_errors: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_shapes_decode_failures: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_shapes_state_barriers: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_shapes_error: Option<String>,
    /// Count of `undefinedN` types `ApplyGlobalTypes.java` applied. `None` means
    /// type application did not run for this image; `Some(0)` is executed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_types_applied: Option<usize>,
    /// `global_types_applied + global_types_skipped` — the count of apply-worthy
    /// scalar shapes offered to pass 2 for this image (the `global_types_maps`
    /// entry's `count()`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_types_candidates: Option<usize>,
    /// Count of recovered shapes this image's `global_shapes.json` held that
    /// were not apply-worthy (not width 1/2/4/8, `no_evidence`, conflicting,
    /// or array) — from `global_types::select_from_shapes_json`'s `Selection`.
    /// Present whenever type-map derivation ran (the normal route with type
    /// application enabled); `None` under `--no-apply-global-types` or
    /// `--no-symbol-pass`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_types_ineligible: Option<usize>,
    /// Sum of the `ApplyGlobalTypes.java` skip buckets for an executed success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_types_skipped: Option<usize>,
    /// Reason-only type-application failure (error/missing/duplicate/malformed/
    /// wrong-image/non-conserving summary, or a missing pass-2 image result).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_types_error: Option<String>,
    /// The eleven current-run `ApplyExceptionRoots` counters. The group is
    /// all-or-none: `Some(0)` is an executed zero category, while `None`
    /// means application did not run or did not complete for this image.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exception_tables: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exception_roles: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exception_roots: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exception_functions_created: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exception_functions_reapplied: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exception_functions_existing: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exception_names_applied: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exception_names_reapplied: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exception_names_preserved: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exception_names_not_requested: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exception_shared_entries: Option<usize>,
    /// Reason-only exception application/currentness failure. Exclusive with
    /// every numeric exception field above.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exception_error: Option<String>,
    /// The seven current-run PAL application counters, carried only by
    /// images whose pass-1 import applied a configured PAL task map
    /// (`ImageResult.pal_applied`); every image without one omits all seven.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pal_tasks: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pal_entries: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pal_functions_created: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pal_functions_existing: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pal_names_applied: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pal_names_preserved: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pal_shared_entries: Option<usize>,
    /// The six `debug_traces` catalog/reference counters plus the refs
    /// producers, carried only by the MAIN image whose `debug_traces` stage
    /// ran (an ok row, including a successful clean absence with zero
    /// counts); every other image omits all seven. Like the
    /// `global_shapes_*` group these are patched post-hoc onto the
    /// `decompile` stage's rows — `ImageReport::from_result` always nulls
    /// them — so they MUST be re-applied after every later
    /// `refresh_decompile_stage_images` /
    /// `install_decompile_stage_image_snapshot` call site; see
    /// `DbtCounters` and `reapply_dbt_outcomes`. `None` = the dbt stages
    /// did not run; `Some(0)` = ran, zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dbt_records: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dbt_files: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dbt_messages: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dbt_quarantined: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dbt_unresolved_messages: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dbt_references: Option<usize>,
    /// Distinct producers of the attributed references (wire names, e.g.
    /// `["ghidra"]`); empty when the refs leg produced nothing. Same
    /// all-or-none group as the six counters above.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dbt_refs_producers: Option<Vec<String>>,
}

impl ImageReport {
    pub fn from_result(r: &decompile::ImageResult) -> Self {
        let (status, classification, skipped_reason, functions, exit) = match r.outcome {
            ImageOutcome::Analyzed(n) => (
                if r.thumb_error.is_some() {
                    "failed"
                } else {
                    "analyzed"
                },
                r.classification,
                None,
                Some(n),
                None,
            ),
            ImageOutcome::Failed(code) => ("failed", None, None, None, Some(code)),
            // Ghidra completed, so there is no analyzeHeadless exit code to
            // report; `terminal_error` carries the actionable reason.
            ImageOutcome::TerminalInvalid => ("failed", r.classification, None, None, None),
            // No analysis process ran for a unanimously opaque image.
            ImageOutcome::SkippedOpaque(_) => {
                ("skipped", Some("opaque"), Some("opaque"), None, None)
            }
        };
        let exception = if r.exception_error.is_none() {
            r.exception_roots_applied.as_ref()
        } else {
            None
        };
        ImageReport {
            image: r.label.clone(),
            status,
            classification,
            skipped_reason,
            functions,
            thumb_functions: r.thumb_functions,
            thumb_regions_requested: r.thumb_regions_requested,
            thumb_regions_succeeded: r.thumb_regions_succeeded,
            thumb_regions_failed: r.thumb_regions_failed,
            thumb_radare2_runs: r.thumb_radare2_runs,
            thumb_rizin_runs: r.thumb_rizin_runs,
            ghidra_execution_accepted: r.ghidra_execution_accepted,
            ghidra_execution_quarantined: r.ghidra_execution_quarantined,
            thumb_execution_accepted: r.thumb_execution_accepted,
            thumb_execution_quarantined: r.thumb_execution_quarantined,
            thumb_error: r.thumb_error.clone(),
            terminal_error: r.terminal_error.clone(),
            exit,
            pass2_applied: r.pass2_applied,
            pass2_creation_candidates: r.pass2_creation_plan.as_ref().map(|plan| plan.candidates),
            pass2_creation_map_skips: r.pass2_creation_plan.as_ref().map(|plan| plan.skips),
            pass2_created: r.pass2_thumb_names.as_ref().map(|summary| summary.created),
            pass2_creation_reapplied: r
                .pass2_thumb_names
                .as_ref()
                .map(|summary| summary.reapplied),
            pass2_creation_skipped_existing: r
                .pass2_thumb_names
                .as_ref()
                .map(|summary| summary.skipped_existing),
            pass2_creation_skipped_collision: r
                .pass2_thumb_names
                .as_ref()
                .map(|summary| summary.skipped_collision),
            pass2_error: r.pass2_error.clone(),
            globals_applied: r.globals_applied,
            globals_apply_skipped: r.globals_apply_skipped,
            globals_apply_error: r.globals_apply_error.clone(),
            thumb_decompiled: r.thumb_decompiled,
            thumb_tighten_error: r.thumb_tighten_error.clone(),
            thumb_enrich_error: r.thumb_enrich_error.clone(),
            globals_error: r.globals_error.clone(),
            globals_recovered: r.globals_recovered,
            globals_provisional: r.globals_provisional,
            globals_provisional_suppressed: r.globals_provisional_suppressed,
            global_shapes_inferred: None,
            global_shapes_no_evidence: None,
            global_shapes_conflicting: None,
            global_shape_observations: None,
            global_shapes_ghidra_quarantined: None,
            global_shapes_thumb_quarantined: None,
            global_shapes_quarantine_errors: None,
            global_shapes_decode_failures: None,
            global_shapes_state_barriers: None,
            global_shapes_error: None,
            global_types_applied: None,
            global_types_candidates: None,
            global_types_ineligible: None,
            global_types_skipped: None,
            global_types_error: None,
            exception_tables: exception.map(decompile::AppliedExceptionRoots::tables),
            exception_roles: exception.map(decompile::AppliedExceptionRoots::roles),
            exception_roots: exception.map(decompile::AppliedExceptionRoots::entries),
            exception_functions_created: exception
                .map(decompile::AppliedExceptionRoots::functions_created),
            exception_functions_reapplied: exception
                .map(decompile::AppliedExceptionRoots::functions_reapplied),
            exception_functions_existing: exception
                .map(decompile::AppliedExceptionRoots::functions_existing),
            exception_names_applied: exception.map(decompile::AppliedExceptionRoots::names_applied),
            exception_names_reapplied: exception
                .map(decompile::AppliedExceptionRoots::names_reapplied),
            exception_names_preserved: exception
                .map(decompile::AppliedExceptionRoots::names_preserved),
            exception_names_not_requested: exception
                .map(decompile::AppliedExceptionRoots::names_not_requested),
            exception_shared_entries: exception
                .map(decompile::AppliedExceptionRoots::shared_entries),
            exception_error: r.exception_error.clone(),
            pal_tasks: r.pal_applied.as_ref().map(|pal| pal.tasks),
            pal_entries: r.pal_applied.as_ref().map(|pal| pal.entries),
            pal_functions_created: r.pal_applied.as_ref().map(|pal| pal.functions_created),
            pal_functions_existing: r.pal_applied.as_ref().map(|pal| pal.functions_existing),
            pal_names_applied: r.pal_applied.as_ref().map(|pal| pal.names_applied),
            pal_names_preserved: r.pal_applied.as_ref().map(|pal| pal.names_preserved),
            pal_shared_entries: r.pal_applied.as_ref().map(|pal| pal.shared_entries),
            dbt_records: None,
            dbt_files: None,
            dbt_messages: None,
            dbt_quarantined: None,
            dbt_unresolved_messages: None,
            dbt_references: None,
            dbt_refs_producers: None,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct StageReport {
    pub stage: &'static str,
    pub status: &'static str, // "ok" | "skipped" | "failed"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub images: Vec<ImageReport>,
    pub duration_ms: u128,
}

impl StageReport {
    fn ok(stage: &'static str, output: &str, ms: u128) -> Self {
        StageReport {
            stage,
            status: "ok",
            output: Some(output.to_string()),
            reason: None,
            error: None,
            images: Vec::new(),
            duration_ms: ms,
        }
    }
    fn skipped(stage: &'static str, reason: &str) -> Self {
        StageReport {
            stage,
            status: "skipped",
            output: None,
            reason: Some(reason.to_string()),
            error: None,
            images: Vec::new(),
            duration_ms: 0,
        }
    }
    fn failed(stage: &'static str, error: String, ms: u128) -> Self {
        StageReport {
            stage,
            status: "failed",
            output: None,
            reason: None,
            error: Some(error),
            images: Vec::new(),
            duration_ms: ms,
        }
    }
    fn decompile(images: Vec<ImageReport>, ms: u128) -> Self {
        let any_failed = images.iter().any(|i| i.status == "failed");
        StageReport {
            stage: "decompile",
            status: if any_failed { "failed" } else { "ok" },
            output: Some("images/".to_string()),
            reason: None,
            error: None,
            images,
            duration_ms: ms,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AnalysisTools {
    pub headless: String,
    pub radare2: String,
    pub radare2_version: String,
    pub rizin_fallback: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rizin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rizin_version: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub tool_version: String,
    pub source_image: String,
    pub source_blake3: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modem_generation: Option<String>,
    pub out: String,
    pub ghidra: AnalysisTools,
    /// Whether `--prune` was requested.
    pub prune_requested: bool,
    /// Whether the leaves-only sweep actually completed. A failed sweep leaves
    /// a partially cleaned tree, so automation must not read intent as state.
    pub pruned: bool,
    pub ok: bool,
    pub stages: Vec<StageReport>,
}

impl Report {
    fn is_ok(stages: &[StageReport]) -> bool {
        !stages.iter().any(|s| s.status == "failed")
    }
}

/// Ghidra and radare2 are hard requirements. Rizin is discovered only for an
/// explicit fallback opt-in; every configured tool must be usable before output.
fn preflight(
    headless: Result<PathBuf>,
    radare2: Result<crate::thumb_analysis::ProducerIdentity>,
    rizin_fallback: bool,
    discover_rizin: impl FnOnce() -> Result<crate::thumb_analysis::ProducerIdentity>,
) -> Result<(PathBuf, crate::thumb_analysis::ThumbTools)> {
    let headless = headless?;
    let radare2 = radare2?;
    let rizin = decompile::discover_configured_rizin(rizin_fallback, discover_rizin)?;
    Ok((
        headless,
        crate::thumb_analysis::ThumbTools { radare2, rizin },
    ))
}

fn analysis_tools(
    headless: &Path,
    opts: &Opts,
    thumb_tools: &crate::thumb_analysis::ThumbTools,
) -> AnalysisTools {
    AnalysisTools {
        headless: headless.display().to_string(),
        radare2: thumb_tools.radare2.executable.display().to_string(),
        radare2_version: thumb_tools.radare2.version.clone(),
        rizin_fallback: opts.rizin_fallback,
        rizin: thumb_tools
            .rizin
            .as_ref()
            .map(|identity| identity.executable.display().to_string()),
        rizin_version: thumb_tools
            .rizin
            .as_ref()
            .map(|identity| identity.version.clone()),
    }
}

fn run_decompile_report(
    modem_bin: &Path,
    opts: &decompile::Opts,
    out: &Path,
    thumb_tools: &crate::thumb_analysis::ThumbTools,
) -> Result<decompile::DecompileReport> {
    run_decompile_report_with(
        modem_bin,
        opts,
        out,
        thumb_tools,
        decompile::run_report_with_thumb_tools,
    )
}

fn run_decompile_report_with(
    modem_bin: &Path,
    opts: &decompile::Opts,
    out: &Path,
    thumb_tools: &crate::thumb_analysis::ThumbTools,
    run_report: impl FnOnce(
        &Path,
        &decompile::Opts,
        &Path,
        &crate::thumb_analysis::ThumbTools,
    ) -> Result<decompile::DecompileReport>,
) -> Result<decompile::DecompileReport> {
    run_report(modem_bin, opts, out, thumb_tools)
}

/// The single `<out>/rootfs/images/<sub>/` directory `extract` produced.
fn rootfs_image_dir(out: &Path) -> Result<PathBuf> {
    let base = out.join("rootfs").join("images");
    // Guard the read so a wholly-absent base yields a typed NotFound (not a raw Io error),
    // matching the empty-directory case below.
    if base.is_dir() {
        for entry in std::fs::read_dir(&base)? {
            let p = entry?.path();
            if p.is_dir() {
                return Ok(p);
            }
        }
    }
    Err(Error::NotFound(format!(
        "no rootfs image dir under {}",
        base.display()
    )))
}

/// The `images/` subdir holding the modem's MAIN code image. The split names
/// images `<NN>_<TOCNAME>`, and the index prefix varies by model (mustang:
/// `02_MAIN`; cheetah: `01_MAIN`) — but the TOC name `MAIN` is stable, so select
/// the lexicographically-first child whose name ends with `_MAIN`. `None` if absent.
fn main_image_dir_name(images_dir: &Path) -> Option<String> {
    let mut names: Vec<String> = std::fs::read_dir(images_dir)
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().to_str().map(str::to_owned))
        .collect();
    names.sort();
    names.into_iter().find(|n| n.ends_with("_MAIN"))
}

/// Move one image's decompile artifacts into its unified folder:
///   `<ghidra>/images/<label>`   (slice file) -> `<images>/<label>/<label>.bin`
///   current `<ghidra>/export/<label>/`          -> `<images>/<label>/decompiled/`
///   present `<ghidra>/scatter/<label>/`         -> `<images>/<label>/scatter/`
///   present `<ghidra>/exception_roots/<label>/roots.json`
///                                -> `<images>/<label>/exception_roots/roots.json`
///   present `<ghidra>/pal_tasks/<label>/tasks.json`
///                                             -> `<images>/<label>/pal_tasks/tasks.json`
///   current raw-only scatter state              -> remove terminal `scatter/`
///   explicit exception-root absence              -> remove owned terminal manifest
///   explicit PAL absence                        -> remove terminal `pal_tasks/`
///
/// Every subsystem follows explicit ownership: its `Unmanaged` state leaves
/// terminal and source bytes untouched. Exception generation completes before
/// Ghidra, so a later analysis failure does not downgrade that independent
/// state even though scatter/PAL terminal state does become unmanaged.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ExceptionMarshalStatus {
    Present,
    Absent,
    Unmanaged,
    Failed(String),
}

fn record_exception_marshal_status(
    image: &mut decompile::ImageResult,
    status: &ExceptionMarshalStatus,
) {
    match status {
        ExceptionMarshalStatus::Present => {}
        ExceptionMarshalStatus::Absent => {
            image.exception_roots_applied = None;
            image.exception_error = None;
        }
        ExceptionMarshalStatus::Unmanaged => {
            image.exception_roots_applied = None;
            if image.exception_error.is_none() {
                image.exception_error =
                    Some("current exception-root generation state is unmanaged".to_string());
            }
        }
        ExceptionMarshalStatus::Failed(reason) => {
            image.exception_roots_applied = None;
            if image.exception_error.is_none() {
                image.exception_error = Some(reason.clone());
            }
        }
    }
}

struct MarshalImageStages {
    exception: ExceptionMarshalStatus,
    pal: Result<()>,
}

fn marshal_image_stages(
    ghidra_dir: &Path,
    images_dir: &Path,
    label: &str,
    export_current: bool,
    runtime: &decompile::RuntimeAnalysisState,
    exception_scatter_state: decompile::RuntimeScatterState,
    image_start: u32,
) -> Result<MarshalImageStages> {
    let dest = images_dir.join(label);
    std::fs::create_dir_all(&dest)?;
    let slice = ghidra_dir.join("images").join(label);
    if slice.exists() {
        std::fs::rename(&slice, dest.join(format!("{label}.bin")))?;
    }
    let export = ghidra_dir.join("export").join(label);
    if export_current {
        let metadata = std::fs::symlink_metadata(&export).map_err(|error| {
            Error::DecomposeIncomplete(format!(
                "missing current export for {label}: {}: {error}",
                export.display()
            ))
        })?;
        if !metadata.file_type().is_dir() {
            return Err(Error::DecomposeIncomplete(format!(
                "current export for {label} is not a real directory: {}",
                export.display()
            )));
        }
        std::fs::rename(&export, dest.join("decompiled"))?;
    }
    let scatter = ghidra_dir.join("scatter").join(label);
    let scatter_dest = dest.join("scatter");
    let scatter_state = if matches!(
        runtime.exception,
        decompile::RuntimeExceptionState::Present(_)
    ) {
        // Exception generation is independent of the later Ghidra outcome.
        // Keep its runtime dependency terminal even when scatter/PAL state was
        // downgraded for a failed analysis.
        exception_scatter_state
    } else {
        runtime.scatter
    };
    match scatter_state {
        decompile::RuntimeScatterState::Unmanaged => {}
        decompile::RuntimeScatterState::Absent => remove_any(&scatter_dest)?,
        decompile::RuntimeScatterState::Present => {
            if !scatter.try_exists()? {
                return Err(Error::DecomposeIncomplete(format!(
                    "missing current scatter map for {label}: {}",
                    scatter.display()
                )));
            }
            remove_any(&scatter_dest)?;
            std::fs::rename(&scatter, scatter_dest)?;
        }
    }
    let exception = match marshal_exception_roots(
        ghidra_dir,
        images_dir,
        label,
        &runtime.exception,
        image_start,
        exception_scatter_state,
    ) {
        Ok(()) => match runtime.exception {
            decompile::RuntimeExceptionState::Present(_) => ExceptionMarshalStatus::Present,
            decompile::RuntimeExceptionState::Absent => ExceptionMarshalStatus::Absent,
            decompile::RuntimeExceptionState::Unmanaged => ExceptionMarshalStatus::Unmanaged,
        },
        Err(error) => ExceptionMarshalStatus::Failed(error.to_string()),
    };
    let mut rename = |from: &Path, to: &Path| std::fs::rename(from, to);
    let pal = marshal_pal_tasks_with(
        ghidra_dir,
        images_dir,
        label,
        &runtime.tasks,
        image_start,
        runtime.scatter,
        &mut rename,
    );
    Ok(MarshalImageStages { exception, pal })
}

#[cfg(test)]
fn marshal_image(
    ghidra_dir: &Path,
    images_dir: &Path,
    label: &str,
    export_current: bool,
    runtime: &decompile::RuntimeAnalysisState,
    exception_scatter_state: decompile::RuntimeScatterState,
    image_start: u32,
) -> Result<ExceptionMarshalStatus> {
    let stages = marshal_image_stages(
        ghidra_dir,
        images_dir,
        label,
        export_current,
        runtime,
        exception_scatter_state,
        image_start,
    )?;
    stages.pal?;
    Ok(stages.exception)
}

/// The terminal `pal_tasks/tasks.json` file name, shared by the marshal
/// commit and the terminal validation paths.
const PAL_MANIFEST_FILE: &str = "tasks.json";

/// The terminal exception-root manifest leaf, shared by marshalling,
/// terminal context construction, pass-2 restaging, and prune tests.
const EXCEPTION_MANIFEST_FILE: &str = "roots.json";

fn marshal_exception_roots(
    ghidra_dir: &Path,
    images_dir: &Path,
    label: &str,
    state: &decompile::RuntimeExceptionState,
    image_start: u32,
    scatter_state: decompile::RuntimeScatterState,
) -> Result<()> {
    let mut rename = |from: &Path, to: &Path| std::fs::rename(from, to);
    marshal_exception_roots_with(
        ghidra_dir,
        images_dir,
        label,
        state,
        image_start,
        scatter_state,
        &mut rename,
    )
}

/// Marshal exactly one owned exception-root manifest. Validation authenticates
/// the source kit manifest against the already-terminal raw/scatter bytes
/// before the destination leaf is touched. The rename is the atomic commit.
fn marshal_exception_roots_with<R>(
    ghidra_dir: &Path,
    images_dir: &Path,
    label: &str,
    state: &decompile::RuntimeExceptionState,
    image_start: u32,
    scatter_state: decompile::RuntimeScatterState,
    rename: &mut R,
) -> Result<()>
where
    R: FnMut(&Path, &Path) -> std::io::Result<()>,
{
    let image_dir = images_dir.join(label);
    let terminal_dir = image_dir.join("exception_roots");
    let terminal_manifest = terminal_dir.join(EXCEPTION_MANIFEST_FILE);
    match state {
        decompile::RuntimeExceptionState::Unmanaged => return Ok(()),
        decompile::RuntimeExceptionState::Absent => {
            crate::exception_roots::clear_materialized(ghidra_dir, label)
                .map_err(|error| Error::BadExceptionRoots(error.to_string()))?;
            let Some(image) = crate::trusted_fs::TrustedDirectory::open_existing(
                &image_dir,
                "terminal exception image directory",
            )
            .map_err(|error| Error::BadExceptionRoots(error.to_string()))?
            else {
                return Ok(());
            };
            let Some(exception) = image
                .open_directory_child("exception_roots", "terminal exception directory")
                .map_err(|error| Error::BadExceptionRoots(error.to_string()))?
            else {
                return Ok(());
            };
            exception
                .unlink_regular_file_if_exists(
                    EXCEPTION_MANIFEST_FILE,
                    "terminal exception manifest",
                )
                .map_err(|error| Error::BadExceptionRoots(error.to_string()))?;
            return Ok(());
        }
        decompile::RuntimeExceptionState::Present(map) => {
            let source = ghidra_dir.join(&map.relative_path);
            validate_terminal_exception_manifest(
                &image_dir,
                label,
                image_start,
                scatter_state,
                &source,
                map,
            )?;
            let image = crate::trusted_fs::TrustedDirectory::new(
                &image_dir,
                "terminal exception image directory",
            )
            .map_err(|error| Error::BadExceptionRoots(error.to_string()))?;
            let exception = image
                .open_or_create_directory_child("exception_roots", "terminal exception directory")
                .map_err(|error| Error::BadExceptionRoots(error.to_string()))?;
            exception
                .require_regular_file_or_absent(
                    EXCEPTION_MANIFEST_FILE,
                    "terminal exception manifest",
                )
                .map_err(|error| Error::BadExceptionRoots(error.to_string()))?;
            rename(&source, &terminal_manifest).map_err(|error| {
                Error::DecomposeIncomplete(format!(
                    "exception-root manifest commit for {label} failed: {error}"
                ))
            })?;
        }
    }
    Ok(())
}

fn validate_terminal_exception_manifest(
    image_dir: &Path,
    label: &str,
    image_start: u32,
    scatter_state: decompile::RuntimeScatterState,
    manifest: &Path,
    expected: &crate::exception_roots::MaterializedExceptionRoots,
) -> Result<crate::exception_roots::ValidatedExceptionRoots> {
    let raw = std::fs::read(image_dir.join(format!("{label}.bin")))?;
    let scatter_present = exception_scatter_present(label, scatter_state)?;
    let scatter_load_map_blake3 = if scatter_present {
        let bytes = std::fs::read(image_dir.join("scatter/load_map.json"))?;
        Some(*blake3::hash(&bytes).as_bytes())
    } else {
        None
    };
    let runtime = if scatter_present {
        crate::runtime_image::RuntimeImage::for_image_dir(&raw, image_start, image_dir)?
    } else {
        // Ignore a stale terminal scatter directory for structurally raw-only
        // images. Currentness comes from the generation state above.
        crate::runtime_image::RuntimeImage::from_plan(&raw, image_start, None)?
    };
    let validated = crate::exception_roots::read_with_identity(
        manifest,
        &runtime,
        crate::exception_roots::ExceptionArtifactContext {
            label,
            toc_name: crate::manifest::toc_name(label),
            image_blake3: *blake3::hash(&raw).as_bytes(),
            scatter_load_map_blake3,
        },
        &expected.identity,
    )
    .map_err(|error| Error::BadExceptionRoots(error.to_string()))?;
    let manifest_blake3 = crate::manifest::blake3_fixed(validated.manifest_blake3);
    if manifest_blake3 != expected.blake3
        || validated.plan.tables.len() != expected.tables
        || validated.plan.roots.len() != expected.roots
    {
        return Err(Error::DecomposeIncomplete(format!(
            "current exception-root manifest metadata for {label} does not match generation state"
        )));
    }
    Ok(validated)
}

fn exception_scatter_present(label: &str, state: decompile::RuntimeScatterState) -> Result<bool> {
    match state {
        decompile::RuntimeScatterState::Present => Ok(true),
        decompile::RuntimeScatterState::Absent => Ok(false),
        // Scatter discovery is structurally MAIN-only. Every other image's
        // exception discovery used a raw-only RuntimeImage even though the
        // shared scatter state correctly remains unmanaged for that label.
        decompile::RuntimeScatterState::Unmanaged if crate::manifest::toc_name(label) != "MAIN" => {
            Ok(false)
        }
        decompile::RuntimeScatterState::Unmanaged => Err(Error::DecomposeIncomplete(format!(
            "current scatter state for exception roots in {label} is unmanaged"
        ))),
    }
}

#[derive(Debug, Default)]
struct ExceptionMarshalTally {
    images: usize,
    tables: usize,
    roots: usize,
}

impl ExceptionMarshalTally {
    fn record(&mut self, map: &crate::exception_roots::MaterializedExceptionRoots) -> Result<()> {
        let add = |total: usize, count: usize| {
            total.checked_add(count).ok_or_else(|| {
                Error::DecomposeIncomplete("exception-root marshalling totals overflow".to_string())
            })
        };
        self.images = add(self.images, 1)?;
        self.tables = add(self.tables, map.tables)?;
        self.roots = add(self.roots, map.roots)?;
        Ok(())
    }
}

fn exception_roots_stage(
    tally: Option<&ExceptionMarshalTally>,
    absent_images: usize,
    errors: &[(String, String)],
    duration_ms: u128,
) -> StageReport {
    let Some(tally) = tally else {
        return StageReport::failed(
            "exception_roots",
            "pass 1 state unavailable".to_string(),
            duration_ms,
        );
    };
    if !errors.is_empty() {
        let error = errors
            .iter()
            .map(|(label, reason)| format!("{label}: {reason}"))
            .collect::<Vec<_>>()
            .join("; ");
        return StageReport::failed("exception_roots", error, duration_ms);
    }
    if tally.images == 0 && absent_images > 0 {
        return StageReport::skipped("exception_roots", "no exception vector tables");
    }
    StageReport::ok(
        "exception_roots",
        &format!(
            "images/*/exception_roots/roots.json (images={}, tables={}, roots={})",
            tally.images, tally.tables, tally.roots
        ),
        duration_ms,
    )
}

/// Marshal one image's PAL task manifest under explicit-state ownership:
///
/// - `Unmanaged` — no terminal mutation, no source consumption.
/// - `Absent` — remove the owned terminal `pal_tasks/` directory (a
///   successful no-candidate result means no current manifest may remain).
/// - `Present(map)` — type-validate and authenticate the source manifest
///   against the terminal raw/scatter bytes *first* (fail-closed on any
///   mismatch, before a single terminal byte changes), then atomically
///   replace the terminal manifest bytes (`rename` is the commit) and
///   remove the emptied source label directory only after that commit.
///   A failed validation or rename leaves the old complete terminal bytes
///   in place and the source unconsumed; neither side becomes current.
fn marshal_pal_tasks_with<R>(
    ghidra_dir: &Path,
    images_dir: &Path,
    label: &str,
    pal_state: &decompile::RuntimeTaskState,
    image_start: u32,
    scatter_state: decompile::RuntimeScatterState,
    rename: &mut R,
) -> Result<()>
where
    R: FnMut(&Path, &Path) -> std::io::Result<()>,
{
    let image_dir = images_dir.join(label);
    let pal_dir = image_dir.join("pal_tasks");
    let map = match pal_state {
        decompile::RuntimeTaskState::Unmanaged => return Ok(()),
        decompile::RuntimeTaskState::Absent => return remove_any(&pal_dir),
        decompile::RuntimeTaskState::Present(map) => map,
    };
    let source = ghidra_dir.join(&map.relative_path);
    if !source.is_file() {
        return Err(Error::DecomposeIncomplete(format!(
            "missing current PAL task manifest for {label}: {}",
            source.display()
        )));
    }
    validate_terminal_pal_manifest(
        &image_dir,
        label,
        image_start,
        scatter_state,
        &source,
        &map.identity,
    )?;
    // The terminal directory must be a real directory before the commit;
    // anything else (absent, a stray file, a symlink) is replaced.
    match std::fs::symlink_metadata(&pal_dir) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => remove_any(&pal_dir)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    std::fs::create_dir_all(&pal_dir)?;
    rename(&source, &pal_dir.join(PAL_MANIFEST_FILE)).map_err(|error| {
        Error::DecomposeIncomplete(format!(
            "pal task manifest commit for {label} failed: {error}"
        ))
    })?;
    // The commit already moved the manifest; the emptied source label
    // directory is post-commit cleanup, so a failure here can only warn.
    if let Some(parent) = source.parent()
        && let Err(error) = std::fs::remove_dir(parent)
    {
        tracing::warn!(
            "pal task manifest for {label} committed but the source directory {} \
             could not be removed: {error}",
            parent.display()
        );
    }
    Ok(())
}

/// Type-validate and authenticate a PAL task manifest (`manifest`) against
/// the terminal raw/scatter bytes of `image_dir`: rebuild the runtime view
/// over `<image_dir>/{<label>.bin,scatter/}`, derive the expected artifact
/// context (image BLAKE3, scatter load-map dependency from the explicit
/// scatter state — never from artifact existence), run the strict
/// fail-closed reader, and pin the reader's identity against
/// `expected_identity`. Any mismatch is a typed error; nothing is mutated.
fn validate_terminal_pal_manifest(
    image_dir: &Path,
    label: &str,
    image_start: u32,
    scatter_state: decompile::RuntimeScatterState,
    manifest: &Path,
    expected_identity: &str,
) -> Result<crate::pal_tasks::ValidatedTaskArtifact> {
    let raw = std::fs::read(image_dir.join(format!("{label}.bin")))?;
    let runtime = crate::runtime_image::RuntimeImage::for_image_dir(&raw, image_start, image_dir)?;
    let scatter_load_map_blake3 = match scatter_state {
        decompile::RuntimeScatterState::Present => {
            let bytes = std::fs::read(image_dir.join("scatter").join("load_map.json"))?;
            Some(*blake3::hash(&bytes).as_bytes())
        }
        decompile::RuntimeScatterState::Absent | decompile::RuntimeScatterState::Unmanaged => None,
    };
    let context = crate::pal_tasks::TaskArtifactContext {
        label,
        image_blake3: *blake3::hash(&raw).as_bytes(),
        scatter_load_map_blake3,
    };
    let artifact = crate::pal_tasks::read(manifest, &runtime, context)
        .map_err(|error| Error::BadPalTasks(error.to_string()))?;
    if artifact.identity != expected_identity {
        return Err(Error::DecomposeIncomplete(format!(
            "current PAL task manifest for {label} has identity {}, expected {expected_identity}",
            artifact.identity
        )));
    }
    Ok(artifact)
}

/// The deterministic per-run PAL marshalling totals, accumulated from the
/// explicit `Present` states the pass-1 marshal committed.
#[derive(Debug, Default)]
struct PalMarshalTally {
    images: usize,
    tasks: usize,
    entries: usize,
}

impl PalMarshalTally {
    fn record(&mut self, map: &crate::pal_tasks::MaterializedTaskMap) -> Result<()> {
        let add = |total: usize, count: usize| {
            total.checked_add(count).ok_or_else(|| {
                Error::DecomposeIncomplete("PAL task marshalling totals overflow".to_string())
            })
        };
        self.images = add(self.images, 1)?;
        self.tasks = add(self.tasks, map.task_records)?;
        self.entries = add(self.entries, map.distinct_entries)?;
        Ok(())
    }
}

/// The `pal_tasks` stage. A completed marshal loop reports `ok` with the
/// deterministic totals (the only nondeterministic field is the stage
/// duration); a loop with no committed map — a successful no-candidate
/// absence, or no recognized MAIN at all — reports the successful skip
/// `no PAL task initializer`. `None` means the pass-1 decompile command
/// itself failed (e.g. malformed PAL generation): the failure already owns
/// the `decompile` stage, so this stage defers to it instead of claiming a
/// successful absence.
fn pal_tasks_stage(tally: Option<&PalMarshalTally>, duration_ms: u128) -> StageReport {
    let Some(tally) = tally else {
        return StageReport::skipped("pal_tasks", "pass 1 failed");
    };
    if tally.images == 0 {
        return StageReport::skipped("pal_tasks", "no PAL task initializer");
    }
    StageReport::ok(
        "pal_tasks",
        &format!(
            "images/*/pal_tasks/tasks.json (images={}, tasks={}, entries={})",
            tally.images, tally.tasks, tally.entries
        ),
        duration_ms,
    )
}

/// The per-image `dbt_*` report counters the `debug_traces` /
/// `debug_traces_refs` stages produce for the MAIN image, retained across
/// the symbol route's later rebuilds of the decompile stage's `ImageReport`s
/// (from `decompile::ImageResult` via `ImageReport::from_result`, which
/// always nulls the seven `dbt_*` fields — `ImageResult` has no such fields
/// to preserve them from; the same hazard `global_shapes_*` and
/// `global_types_*` survive via their own reappliers). Without re-applying
/// this retained outcome after each rebuild — `RunGlobals(RecordOnly)`'s
/// refresh on `--no-symbol-pass`, and `DispatchPass2`'s
/// `install_decompile_stage_image_snapshot` / `refresh_decompile_stage_images`
/// on the normal route — the patch is silently discarded and `dbt_*` never
/// reaches `report.json`. See `reapply_dbt_outcomes`.
#[derive(Debug, Clone)]
struct DbtCounters {
    label: String,
    records: usize,
    files: usize,
    messages: usize,
    quarantined: usize,
    unresolved_messages: usize,
    references: usize,
    refs_producers: Vec<String>,
}

/// Apply one retained outcome to `image`, mirroring exactly what the first
/// patch after `run_debug_traces_stages` did.
fn apply_dbt_counters(image: &mut ImageReport, counters: &DbtCounters) {
    image.dbt_records = Some(counters.records);
    image.dbt_files = Some(counters.files);
    image.dbt_messages = Some(counters.messages);
    image.dbt_quarantined = Some(counters.quarantined);
    image.dbt_unresolved_messages = Some(counters.unresolved_messages);
    image.dbt_references = Some(counters.references);
    image.dbt_refs_producers = Some(counters.refs_producers.clone());
}

/// Re-apply the retained `dbt_*` counters onto the MAIN image's row by
/// label. Called after the stages first run and after every later rebuild
/// of the decompile stage's `ImageReport`s (see `DbtCounters`'s doc comment
/// for why those rebuilds otherwise discard this data). `None` (no MAIN
/// image, no MAIN binary, or a failed catalog stage) leaves every row
/// untouched — the rows are always a fresh rebuild at the call sites, so
/// their `dbt_*` fields are already `None` there.
fn reapply_dbt_outcomes(report_images: &mut [ImageReport], outcomes: &Option<DbtCounters>) {
    if let Some(counters) = outcomes {
        for image in report_images {
            if image.image == counters.label {
                apply_dbt_counters(image, counters);
            }
        }
    }
}

/// The `debug_traces` catalog outcome, carrying the runtime view and the
/// identity the refs stage must re-validate through (same runtime, same
/// expected context). `raw` — the bytes the runtime borrows — must outlive
/// this value in the caller.
enum DebugTracesCatalog<'a> {
    Published {
        runtime: crate::runtime_image::RuntimeImage<'a>,
        ctx: crate::dbt_traces::artifact::DbtContext<'a>,
        counts: crate::dbt_traces::artifact::CatalogCounts,
    },
    /// Zero candidates: `publish` is the single owner of absence semantics
    /// and already cleared the owned directory; the stage is ok with zero
    /// counts.
    CleanAbsence,
}

/// The `debug_traces` stage's output summary: the catalog location plus the
/// counts it published (all zeros for a clean absence).
fn debug_traces_stage_output(
    main_name: &str,
    counts: &crate::dbt_traces::artifact::CatalogCounts,
) -> String {
    format!(
        "images/{main_name}/debug_traces (records={}, files={}, messages={}, quarantined={}, unresolved_messages={})",
        counts.records,
        counts.files,
        counts.messages,
        counts.quarantined,
        counts.unresolved_messages
    )
}

/// Run the `debug_traces` / `debug_traces_refs` stages for the MAIN split
/// dir, recording both stage rows in order — between `thumb_enrich` and
/// `source_tree` — or both as skipped (`"no MAIN image"` / `"no MAIN image
/// binary"`) when the MAIN inputs are absent. Returns the retained
/// per-image counters; `None` means the catalog stage did not produce a
/// current catalog (failed, or no MAIN inputs at all).
fn run_debug_traces_stages(
    stages: &mut Vec<StageReport>,
    out: &Path,
    images_dir: &Path,
) -> Option<DbtCounters> {
    let Some(main_name) = main_image_dir_name(images_dir) else {
        stages.push(StageReport::skipped("debug_traces", "no MAIN image"));
        stages.push(StageReport::skipped("debug_traces_refs", "no MAIN image"));
        return None;
    };
    let main_img_dir = images_dir.join(&main_name);
    let main_bin = main_img_dir.join(format!("{main_name}.bin"));
    if !main_bin.exists() {
        stages.push(StageReport::skipped("debug_traces", "no MAIN image binary"));
        stages.push(StageReport::skipped(
            "debug_traces_refs",
            "no MAIN image binary",
        ));
        return None;
    }
    run_debug_traces_stage(stages, out, &main_name, &main_img_dir, &main_bin)
}

/// Discover and publish the DBT debug-trace catalog for the MAIN image,
/// then run the `debug_traces_refs` attribution stage over the published
/// catalog. Both rows are recorded in `stages`. Failure of the catalog leg
/// clears the owned output (authenticated absence) and skips refs; a
/// successful clean absence is an ok row with zero counts. Returns the
/// retained per-image counters, or `None` when the catalog leg failed.
fn run_debug_traces_stage(
    stages: &mut Vec<StageReport>,
    out: &Path,
    main_name: &str,
    main_img_dir: &Path,
    main_bin: &Path,
) -> Option<DbtCounters> {
    let started = Instant::now();
    // The raw MAIN bytes must outlive the runtime view both stages share.
    let raw = std::fs::read(main_bin);
    let catalog = match raw {
        Ok(ref raw) => run_debug_traces_catalog(raw, out, main_name, main_img_dir),
        Err(error) => Err(error.into()),
    };
    match catalog {
        Err(error) => {
            let _ = crate::dbt_traces::artifact::clear(main_img_dir);
            stages.push(StageReport::failed(
                "debug_traces",
                error.to_string(),
                started.elapsed().as_millis(),
            ));
            stages.push(StageReport::skipped(
                "debug_traces_refs",
                "no debug traces catalog",
            ));
            None
        }
        Ok(DebugTracesCatalog::CleanAbsence) => {
            stages.push(StageReport::ok(
                "debug_traces",
                &debug_traces_stage_output(
                    main_name,
                    &crate::dbt_traces::artifact::CatalogCounts {
                        records: 0,
                        files: 0,
                        messages: 0,
                        quarantined: 0,
                        unresolved_messages: 0,
                        occurrences: 0,
                    },
                ),
                started.elapsed().as_millis(),
            ));
            stages.push(StageReport::skipped(
                "debug_traces_refs",
                "no debug traces catalog",
            ));
            Some(DbtCounters {
                label: main_name.to_string(),
                records: 0,
                files: 0,
                messages: 0,
                quarantined: 0,
                unresolved_messages: 0,
                references: 0,
                refs_producers: Vec::new(),
            })
        }
        Ok(DebugTracesCatalog::Published {
            runtime,
            ctx,
            counts,
        }) => {
            stages.push(StageReport::ok(
                "debug_traces",
                &debug_traces_stage_output(main_name, &counts),
                started.elapsed().as_millis(),
            ));
            let (references, refs_producers) =
                run_debug_traces_refs_stage(stages, main_name, main_img_dir, &runtime, &ctx);
            Some(DbtCounters {
                label: main_name.to_string(),
                records: counts.records,
                files: counts.files,
                messages: counts.messages,
                quarantined: counts.quarantined,
                unresolved_messages: counts.unresolved_messages,
                references,
                refs_producers,
            })
        }
    }
}

/// Build the MAIN runtime view, bind its identity (image hash plus the
/// explicit scatter state pass 1 marshalled to disk — never derived from
/// `debug_traces` artifact existence), then discover and publish the
/// catalog by rename-swap. The spill directory is removed on every exit
/// path after discovery starts.
fn run_debug_traces_catalog<'raw>(
    raw: &'raw [u8],
    out: &Path,
    main_name: &'raw str,
    main_img_dir: &Path,
) -> Result<DebugTracesCatalog<'raw>> {
    let load_address = u32::try_from(
        manifest::load_addr_for_image(&out.join("manifest.json"), main_name)?
            .ok_or_else(|| Error::Serialize(format!("load_addr missing for {main_name}")))?,
    )
    .map_err(|_| Error::Serialize(format!("load_addr for {main_name} does not fit u32")))?;
    let runtime =
        crate::runtime_image::RuntimeImage::for_image_dir(raw, load_address, main_img_dir)?;
    let scatter_path = main_img_dir.join("scatter").join("load_map.json");
    let scatter_load_map_blake3 = if scatter_path.exists() {
        Some(crate::execution_ranges::parse_blake3(
            &manifest::blake3_file(&scatter_path)?,
        )?)
    } else {
        None
    };
    let image_blake3 = runtime.hash_range(load_address, raw.len() as u32)?;
    let ctx = crate::dbt_traces::artifact::DbtContext {
        label: main_name,
        image_blake3,
        scatter_load_map_blake3,
    };
    let spill = main_img_dir.join(format!("dbt_spill+{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&spill);
    let published = (|| -> Result<Option<crate::dbt_traces::artifact::MaterializedCatalog>> {
        let discovery = crate::dbt_traces::discover::discover(&runtime, &spill)?;
        Ok(crate::dbt_traces::artifact::publish(
            &discovery,
            &runtime,
            &ctx,
            main_img_dir,
            true,
        )?)
    })();
    let _ = std::fs::remove_dir_all(&spill);
    match published? {
        None => Ok(DebugTracesCatalog::CleanAbsence),
        Some(map) => Ok(DebugTracesCatalog::Published {
            runtime,
            ctx,
            counts: map.counts,
        }),
    }
}

/// Run the `debug_traces_refs` stage: re-validate the published catalog
/// through the strict reader (same runtime, same expected identity), then
/// attribute every record address over the authenticated function
/// inventories pass 1 wrote under `main_img_dir/decompiled/`. Skips with a
/// reason when the catalog or the function inventories are absent; a
/// failure removes `references.json` (authenticated absence — `attribute`
/// owns the removal on its own error paths, this covers the rest) and
/// records a failed row. Returns `(reference count, producer names)` —
/// `(0, [])` whenever the stage did not attribute.
fn run_debug_traces_refs_stage(
    stages: &mut Vec<StageReport>,
    main_name: &str,
    main_img_dir: &Path,
    runtime: &crate::runtime_image::RuntimeImage<'_>,
    ctx: &crate::dbt_traces::artifact::DbtContext<'_>,
) -> (usize, Vec<String>) {
    let started = Instant::now();
    let catalog_dir = main_img_dir.join("debug_traces");
    if !catalog_dir.join("manifest.json").exists() {
        stages.push(StageReport::skipped(
            "debug_traces_refs",
            "no debug traces catalog",
        ));
        return (0, Vec::new());
    }
    let decompiled_dir = main_img_dir.join("decompiled");
    // The refs inputs bind both inventory files' content hashes; the Ghidra
    // inventory is the non-optional leg (`RefsInputs::functions_blake3`).
    // Ghidra-only is the valid degenerate (thumb binds null); without the
    // Ghidra inventory there is nothing to hash or attribute through.
    if !decompiled_dir.join("functions.json").exists() {
        stages.push(StageReport::skipped(
            "debug_traces_refs",
            "no function inventories",
        ));
        return (0, Vec::new());
    }
    let result = (|| -> Result<(usize, Vec<String>)> {
        let outcome =
            crate::dbt_traces::attribute_published(runtime, ctx, &catalog_dir, &decompiled_dir)?;
        let producers = outcome
            .producers
            .iter()
            .map(|producer| crate::dbt_traces::refs::producer_name(*producer).to_string())
            .collect();
        Ok((outcome.count, producers))
    })();
    match result {
        Ok((count, producers)) => {
            stages.push(StageReport::ok(
                "debug_traces_refs",
                &format!(
                    "images/{main_name}/debug_traces/references.json \
                     (references={count}, producers=[{}])",
                    producers.join(",")
                ),
                started.elapsed().as_millis(),
            ));
            (count, producers)
        }
        Err(error) => {
            let _ = std::fs::remove_file(catalog_dir.join("references.json"));
            stages.push(StageReport::failed(
                "debug_traces_refs",
                error.to_string(),
                started.elapsed().as_millis(),
            ));
            (0, Vec::new())
        }
    }
}

/// After pass 2, ExportDecomp.java has overwritten {ghidra}/export/{label}/
/// with exactly three files it owns: `decompiled.c`, `disasm.lst`,
/// `functions.json`. Merge those into `images/<label>/decompiled/`, replacing
/// only the three owned paths. Every other destination entry (e.g.
/// `thumb_functions.json`, `thumb/`) is owned by another stage and must remain
/// byte-for-byte unchanged. The slice file (`<label>.bin`) is already in place
/// from pass 1; do not touch it.
fn refresh_decompiled(
    ghidra_dir: &Path,
    images_dir: &Path,
    image: &decompile::ImageResult,
) -> Result<decompile::TerminalInventorySummary> {
    let mut rename = |from: &Path, to: &Path| std::fs::rename(from, to);
    let mut validate = decompile::validate_image_terminal_inventory;
    refresh_decompiled_with(ghidra_dir, images_dir, image, &mut rename, &mut validate)
}

fn refresh_decompiled_and_update(
    ghidra_dir: &Path,
    images_dir: &Path,
    image: &mut decompile::ImageResult,
) -> Result<()> {
    let summary = refresh_decompiled(ghidra_dir, images_dir, image)?;
    match image.outcome {
        ImageOutcome::Analyzed(_) => image.outcome = ImageOutcome::Analyzed(summary.ghidra.raw),
        _ => {
            return Err(Error::Serialize(
                "pass-2 refresh belongs to a non-analyzed image".into(),
            ));
        }
    }
    image.ghidra_execution_accepted = Some(summary.ghidra.accepted);
    image.ghidra_execution_quarantined = Some(summary.ghidra.quarantined);
    image.thumb_functions = summary.thumb_substantial;
    image.thumb_execution_accepted = summary.thumb.map(|thumb| thumb.accepted);
    image.thumb_execution_quarantined = summary.thumb.map(|thumb| thumb.quarantined);
    Ok(())
}

fn pass1_creation_baseline(image: &decompile::ImageResult) -> Result<decompile::ImageResult> {
    let mut retained = image.clone();
    let Some(summary) = retained.pass2_thumb_names.as_mut() else {
        return Ok(retained);
    };
    let owned = summary
        .created
        .checked_add(summary.reapplied)
        .ok_or_else(|| Error::Serialize("pass-1 creation baseline count overflow".into()))?;
    summary.created = 0;
    summary.reapplied = 0;
    summary.skipped_collision = summary
        .skipped_collision
        .checked_add(owned)
        .ok_or_else(|| Error::Serialize("pass-1 creation baseline count overflow".into()))?;
    Ok(retained)
}

fn retained_creation_baseline(image: &decompile::ImageResult) -> Result<decompile::ImageResult> {
    let mut retained = image.clone();
    let Some(summary) = retained.pass2_thumb_names.as_mut() else {
        return Ok(retained);
    };
    let newly_created = summary.created;
    summary.created = summary.reapplied;
    summary.reapplied = 0;
    summary.skipped_collision = summary
        .skipped_collision
        .checked_add(newly_created)
        .ok_or_else(|| Error::Serialize("retained creation baseline count overflow".into()))?;
    Ok(retained)
}

fn committed_creation_view(image: &decompile::ImageResult) -> Result<decompile::ImageResult> {
    let mut committed = image.clone();
    let Some(summary) = committed.pass2_thumb_names.as_mut() else {
        return Ok(committed);
    };
    let newly_created = summary.created;
    if newly_created == 0 {
        return Ok(committed);
    }
    summary.created = 0;
    summary.reapplied = summary
        .reapplied
        .checked_add(newly_created)
        .ok_or_else(|| Error::Serialize("committed creation count overflow".into()))?;
    Ok(committed)
}

fn unpublished_replay_view(image: &decompile::ImageResult) -> Result<decompile::ImageResult> {
    let mut unpublished = image.clone();
    let Some(summary) = unpublished.pass2_thumb_names.as_mut() else {
        return Ok(unpublished);
    };
    summary.created = summary
        .created
        .checked_add(summary.reapplied)
        .ok_or_else(|| Error::Serialize("unpublished replay count overflow".into()))?;
    summary.reapplied = 0;
    Ok(unpublished)
}

fn refresh_decompiled_with<R, V>(
    ghidra_dir: &Path,
    images_dir: &Path,
    image: &decompile::ImageResult,
    rename: &mut R,
    validate: &mut V,
) -> Result<decompile::TerminalInventorySummary>
where
    R: FnMut(&Path, &Path) -> std::io::Result<()>,
    V: FnMut(
        &Path,
        &Path,
        &decompile::ImageResult,
        Option<&decompile::TerminalInventorySummary>,
    ) -> Result<decompile::TerminalInventorySummary>,
{
    const OWNED: &[&str] = &["decompiled.c", "disasm.lst", "functions.json"];
    let label = &image.label;

    let export = ghidra_dir.join("export").join(label);
    if !export.exists() {
        return Err(Error::DecomposeIncomplete(format!(
            "missing pass-2 export for {label}: {}",
            export.display()
        )));
    }

    // Validate the full export set before any destination mutation.
    let mut entries = Vec::new();
    for ent in std::fs::read_dir(&export)? {
        let ent = ent?;
        let name = ent.file_name();
        let name = name.to_string_lossy().into_owned();
        let ft = ent.file_type()?;
        if !ft.is_file() {
            return Err(Error::DecomposeIncomplete(format!(
                "invalid pass-2 export for {label}: entry `{name}` is not a regular file"
            )));
        }
        entries.push(name);
    }
    entries.sort();
    let mut expected: Vec<String> = OWNED.iter().map(|s| (*s).to_string()).collect();
    expected.sort();
    if entries != expected {
        return Err(Error::DecomposeIncomplete(format!(
            "invalid pass-2 export for {label}: expected exactly {OWNED:?}, found {entries:?}"
        )));
    }

    let dest = images_dir.join(label).join("decompiled");
    let (retained, staged_image) = if dest.exists() {
        // A prior saved-project transaction can commit before export or host
        // publication fails. Prefer pristine pass 1; only fall back to the
        // fully-published replay baseline when pass 1 does not validate.
        let pass1_image = pass1_creation_baseline(image)?;
        match validate(
            &dest.join("functions.json"),
            &dest.join("thumb_functions.json"),
            &pass1_image,
            None,
        ) {
            Ok(summary) => (Some(summary), unpublished_replay_view(image)?),
            Err(pass1_error) => {
                let replayed_image = retained_creation_baseline(image)?;
                if replayed_image.pass2_thumb_names == pass1_image.pass2_thumb_names {
                    return Err(pass1_error);
                }
                let summary = validate(
                    &dest.join("functions.json"),
                    &dest.join("thumb_functions.json"),
                    &replayed_image,
                    None,
                )?;
                (Some(summary), image.clone())
            }
        }
    } else {
        (None, image.clone())
    };
    let staged = validate(
        &export.join("functions.json"),
        &dest.join("thumb_functions.json"),
        &staged_image,
        retained.as_ref(),
    )?;
    if !dest.exists() {
        // First-time placement (no pass-1 tree): rename the whole validated
        // export directory into place, same as the historical happy path.
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        rename(&export, &dest)?;
        let committed_image = committed_creation_view(image)?;
        let final_summary = match validate(
            &dest.join("functions.json"),
            &dest.join("thumb_functions.json"),
            &committed_image,
            Some(&staged),
        ) {
            Ok(summary) => summary,
            Err(error) => {
                return match rename(&dest, &export) {
                    Ok(()) => Err(error),
                    Err(rollback) => Err(transaction_rollback_error(error, &[rollback])),
                };
            }
        };
        return Ok(final_summary);
    }

    // Destination exists: move the old owned trio aside, install the staged
    // trio, and roll both sets back on any replacement or final-validation
    // failure. Sidecars never enter the transaction.
    let backup = dest
        .parent()
        .expect("decompiled destination always has an image parent")
        .join(".decompiled.refresh-backup");
    match std::fs::create_dir(&backup) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(Error::DecomposeIncomplete(format!(
                "stale pass-2 refresh backup for {label}: {}",
                backup.display()
            )));
        }
        Err(error) => return Err(error.into()),
    }
    let mut backed_up = Vec::new();
    for name in OWNED {
        if let Err(error) = rename(&dest.join(name), &backup.join(name)) {
            let rollback_errors =
                rollback_refresh(&export, &dest, &backup, &[], &backed_up, rename);
            return Err(transaction_rollback_error(error.into(), &rollback_errors));
        }
        backed_up.push(*name);
    }
    let mut installed = Vec::new();
    for name in OWNED {
        if let Err(error) = rename(&export.join(name), &dest.join(name)) {
            let rollback_errors =
                rollback_refresh(&export, &dest, &backup, &installed, &backed_up, rename);
            return Err(transaction_rollback_error(error.into(), &rollback_errors));
        }
        installed.push(*name);
    }
    let final_summary = match validate(
        &dest.join("functions.json"),
        &dest.join("thumb_functions.json"),
        &staged_image,
        Some(retained.as_ref().unwrap_or(&staged)),
    ) {
        Ok(summary) => summary,
        Err(error) => {
            let rollback_errors =
                rollback_refresh(&export, &dest, &backup, &installed, &backed_up, rename);
            return Err(transaction_rollback_error(error, &rollback_errors));
        }
    };

    // Validation is the commit point. Cleanup failures cannot make the
    // destination partially old/new, so retain recoverable artifacts and warn.
    for name in OWNED {
        if let Err(error) = std::fs::remove_file(backup.join(name)) {
            tracing::warn!(
                "pass-2 refresh for {label} committed but could not remove backup {name}: {error}"
            );
        }
    }
    if let Err(error) = std::fs::remove_dir(&backup) {
        tracing::warn!(
            "pass-2 refresh for {label} committed but could not remove backup directory: {error}"
        );
    }
    if let Err(error) = std::fs::remove_dir(&export) {
        tracing::warn!(
            "pass-2 refresh for {label} committed but could not remove empty export directory: {error}"
        );
    }
    Ok(final_summary)
}

fn rollback_refresh<R>(
    export: &Path,
    dest: &Path,
    backup: &Path,
    installed: &[&str],
    backed_up: &[&str],
    rename: &mut R,
) -> Vec<std::io::Error>
where
    R: FnMut(&Path, &Path) -> std::io::Result<()>,
{
    let mut errors = Vec::new();
    for name in installed.iter().rev() {
        if let Err(error) = rename(&dest.join(name), &export.join(name)) {
            errors.push(error);
        }
    }
    for name in backed_up.iter().rev() {
        if let Err(error) = rename(&backup.join(name), &dest.join(name)) {
            errors.push(error);
        }
    }
    if let Err(error) = std::fs::remove_dir(backup) {
        errors.push(error);
    }
    errors
}

fn transaction_rollback_error(original: Error, rollback_errors: &[std::io::Error]) -> Error {
    if rollback_errors.is_empty() {
        return original;
    }
    let rollback = rollback_errors
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ");
    Error::DecomposeIncomplete(format!(
        "pass-2 refresh failed: {original}; rollback also failed: {rollback}"
    ))
}

fn refresh_pass2_outputs(
    outcomes: &HashMap<String, decompile::Pass2ProcessOutcome>,
    images: &mut [decompile::ImageResult],
    ghidra_dir: &Path,
    images_dir: &Path,
) -> (usize, Vec<(String, String)>) {
    refresh_pass2_outputs_with(outcomes, images, |image| {
        refresh_decompiled_and_update(ghidra_dir, images_dir, image)
    })
}

fn refresh_pass2_outputs_with<F>(
    outcomes: &HashMap<String, decompile::Pass2ProcessOutcome>,
    images: &mut [decompile::ImageResult],
    mut refresh: F,
) -> (usize, Vec<(String, String)>)
where
    F: FnMut(&mut decompile::ImageResult) -> Result<()>,
{
    let mut labels: Vec<&str> = outcomes.keys().map(String::as_str).collect();
    labels.sort_unstable();
    let mut refreshed = 0usize;
    let mut errors = Vec::new();

    for label in labels {
        match &outcomes[label] {
            decompile::Pass2ProcessOutcome::Failed(reason) => {
                errors.push((label.to_string(), reason.clone()));
            }
            decompile::Pass2ProcessOutcome::ProcessSucceeded => {
                let Some(index) = images.iter().position(|image| image.label == label) else {
                    errors.push((
                        label.to_string(),
                        "refresh: image absent from pass-2 report".to_string(),
                    ));
                    continue;
                };
                match refresh(&mut images[index]) {
                    Ok(()) => refreshed += 1,
                    Err(error) => {
                        let reason = format!("refresh: {error}");
                        images[index].pass2_error = Some(reason.clone());
                        errors.push((label.to_string(), reason));
                    }
                }
            }
        }
    }
    (refreshed, errors)
}

fn decompile_pass2_stage(
    scheduled_count: usize,
    refreshed_count: usize,
    mut errors: Vec<(String, String)>,
    duration_ms: u128,
) -> StageReport {
    if scheduled_count == 0 {
        return StageReport::skipped("decompile_pass2", "no prepared maps");
    }
    errors.sort();
    if errors.is_empty() && refreshed_count == scheduled_count {
        return StageReport::ok(
            "decompile_pass2",
            &format!("{refreshed_count} image(s) refreshed"),
            duration_ms,
        );
    }
    if errors.is_empty() {
        errors.push((
            "<pass2>".to_string(),
            format!("refreshed {refreshed_count} of {scheduled_count} scheduled images"),
        ));
    }
    StageReport {
        stage: "decompile_pass2",
        status: "failed",
        output: Some(format!(
            "{refreshed_count} of {scheduled_count} image(s) refreshed"
        )),
        reason: None,
        error: Some(
            errors
                .into_iter()
                .map(|(label, message)| format!("{label}: {message}"))
                .collect::<Vec<_>>()
                .join("\n"),
        ),
        images: Vec::new(),
        duration_ms,
    }
}

/// Phase 2: run `decompile::thumb_enrich` (streaming) against each image's
/// `images/<label>/decompiled/{decompiled.c,thumb_functions.json}`. Mutates each
/// `ImageResult.thumb_decompiled` (count) or `thumb_enrich_error` (failure text)
/// in place. Returns the per-image outcome so the caller can build a StageReport.
///
/// Missing `thumb_functions.json`:
/// - `thumb_functions == None` → legitimate "no Thumb regions"; skip silently.
/// - `thumb_functions == Some(_)` → Thumb analysis reported output but the JSON
///   is gone (e.g. destroyed by a buggy pass-2 refresh); record
///   `thumb_enrich_error` and a stage error so the loss cannot go green.
fn run_thumb_enrich_per_image(
    images: &mut [decompile::ImageResult],
    images_dir: &Path,
) -> ThumbEnrichOutcome {
    let mut outcome = ThumbEnrichOutcome::default();
    for ir in images {
        let label = &ir.label;
        let decompiled_c = images_dir
            .join(label)
            .join("decompiled")
            .join("decompiled.c");
        let thumb_json = images_dir
            .join(label)
            .join("decompiled")
            .join("thumb_functions.json");
        if !thumb_json.exists() {
            if ir.thumb_functions.is_some() {
                let msg = "thumb_functions.json missing after Thumb analysis reported functions"
                    .to_string();
                ir.thumb_enrich_error = Some(msg.clone());
                outcome.errors.push((label.clone(), msg));
            }
            continue;
        }
        let image_dir = images_dir.join(label);
        let runtime = (|| {
            let raw = std::fs::read(image_dir.join(format!("{label}.bin")))?;
            let runtime = crate::runtime_image::RuntimeImage::for_image_dir(
                &raw,
                ir.image_start,
                &image_dir,
            )?;
            decompile::thumb_enrich(&decompiled_c, &thumb_json, &runtime)
        })();
        match runtime {
            Ok(n) => {
                ir.thumb_decompiled = Some(n);
                outcome.counts.push((label.clone(), n));
            }
            Err(e) => {
                let msg = format!("{e:#}");
                ir.thumb_enrich_error = Some(msg.clone());
                outcome.errors.push((label.clone(), msg));
            }
        }
    }
    outcome
}

/// Per-image outcome of a `thumb_enrich` sweep.
#[derive(Default)]
struct ThumbEnrichOutcome {
    errors: Vec<(String, String)>,
    counts: Vec<(String, usize)>,
}

/// Build a `thumb_enrich` StageReport from the per-image loop output.
fn thumb_enrich_stage(
    stage: &'static str,
    outcome: ThumbEnrichOutcome,
    duration_ms: u128,
) -> StageReport {
    let ThumbEnrichOutcome { errors, counts } = outcome;
    StageReport {
        stage,
        status: if errors.is_empty() { "ok" } else { "failed" },
        output: Some(format!("{} image(s) enriched", counts.len())),
        reason: None,
        error: errors.first().map(|(_, e)| e.clone()),
        images: Vec::new(),
        duration_ms,
    }
}

/// Refresh the last `decompile` stage's per-image entries from the current
/// `ImageResult` slice. Used after later orchestration mutates reporting fields
/// (globals preparation/application and both `thumb_enrich` sweeps) so the
/// serialized stage does not retain its initial pass-1 snapshot. Preserves the
/// stage's other fields (status, duration_ms, output, etc.).
fn refresh_decompile_stage_images(stages: &mut [StageReport], images: &[decompile::ImageResult]) {
    install_decompile_stage_image_snapshot(
        stages,
        images.iter().map(ImageReport::from_result).collect(),
    );
}

fn install_decompile_stage_image_snapshot(stages: &mut [StageReport], images: Vec<ImageReport>) {
    let Some(pos) = stages.iter().rposition(|s| s.stage == "decompile") else {
        return;
    };
    stages[pos].images = images;
}

/// Borrow the `decompile` stage's per-image entries mutably, or an empty
/// slice if that stage has not been pushed yet. Used by `global_types_apply_stage`
/// to patch the `global_types_*` fields onto the already-installed `ImageReport`s
/// — those fields are never set by `ImageReport::from_result` (see its call
/// sites), so unlike `globals_applied` they need an explicit post-hoc patch.
fn decompile_stage_images_mut(stages: &mut [StageReport]) -> &mut [ImageReport] {
    match stages.iter().rposition(|s| s.stage == "decompile") {
        Some(pos) => stages[pos].images.as_mut_slice(),
        None => &mut [],
    }
}

/// Phase 3.0 helper: load Phase 1's `symbols.json` and build a lookup map
/// from function entry address (canonical: lowercase hex, no `0x`, no
/// leading zeros) to recovered name. Used to enrich `globals::run`'s
/// evidence with `recovered_name`. Returns an empty map if `symbols.json`
/// is absent or unreadable (defensive — globals stage degrades gracefully).
fn load_recovered_function_names(symbols_path: &Path) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Ok(bytes) = std::fs::read(symbols_path) else {
        return out;
    };
    let Ok(v): std::result::Result<serde_json::Value, _> = serde_json::from_slice(&bytes) else {
        return out;
    };
    let Some(symbols) = v.get("symbols").and_then(|s| s.as_array()) else {
        return out;
    };
    for sym in symbols {
        let Some(addr_str) = sym.get("address").and_then(|a| a.as_str()) else {
            continue;
        };
        let Some(canonical) = canonical_function_address(addr_str) else {
            continue;
        };
        if let Some(name) = sym.get("name").and_then(|n| n.as_str()) {
            out.insert(canonical, name.to_string());
        }
    }
    out
}

/// Canonicalize a function address exactly as the `symbols.json` loader does:
/// strip a lowercase `0x` prefix, parse hexadecimal, then format as lowercase
/// hexadecimal without a prefix or leading zeroes.
fn canonical_function_address(address: &str) -> Option<String> {
    let addr = u64::from_str_radix(address.trim_start_matches("0x"), 16).ok()?;
    Some(format!("{addr:x}"))
}

/// Remove a file or directory if present; a missing path is not an error.
fn remove_any(path: &Path) -> Result<()> {
    if path.is_dir() {
        std::fs::remove_dir_all(path)?;
    } else if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

/// Leaves-only sweep: drop every intermediate, keep terminal artifacts + report/manifest.
fn prune(out: &Path) -> Result<()> {
    remove_any(&out.join("modem.ext4"))?;
    remove_any(&out.join("rootfs"))?;
    remove_any(&out.join("rf_cfg_decompressed"))?;
    remove_any(&out.join("ghidra"))?;
    let images = out.join("images");
    if images.is_dir() {
        for entry in std::fs::read_dir(&images)? {
            let dir = entry?.path();
            if dir.is_dir()
                && let Some(label) = dir.file_name().and_then(|n| n.to_str())
            {
                remove_any(&dir.join(format!("{label}.bin")))?;
                remove_any(&dir.join("decompiled/thumb"))?;
            }
        }
    }
    Ok(())
}

/// Run a `Result<PathBuf>`-returning stage, recording ok/failed with timing.
fn run_stage(
    stages: &mut Vec<StageReport>,
    name: &'static str,
    output: &str,
    f: impl FnOnce() -> Result<PathBuf>,
) {
    let t = Instant::now();
    match f() {
        Ok(_) => stages.push(StageReport::ok(name, output, t.elapsed().as_millis())),
        Err(e) => stages.push(StageReport::failed(
            name,
            e.to_string(),
            t.elapsed().as_millis(),
        )),
    }
}

/// Write `report.json`; return its path on full success, or `Err` if any stage failed.
#[allow(clippy::too_many_arguments)]
fn finalize(
    out: &Path,
    img: &Path,
    opts: &Opts,
    headless: &Path,
    thumb_tools: &crate::thumb_analysis::ThumbTools,
    stages: Vec<StageReport>,
    modem_generation: Option<String>,
    pruned: bool,
) -> Result<PathBuf> {
    let ok = Report::is_ok(&stages);
    let report = Report {
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        source_image: img.display().to_string(),
        source_blake3: manifest::blake3_file(img).unwrap_or_default(),
        modem_generation,
        out: out.display().to_string(),
        ghidra: analysis_tools(headless, opts, thumb_tools),
        prune_requested: opts.prune,
        pruned,
        ok,
        stages,
    };
    let path = out.join("report.json");
    let json =
        serde_json::to_string_pretty(&report).map_err(|e| Error::Serialize(e.to_string()))?;
    std::fs::write(&path, json)?;
    if ok {
        Ok(path)
    } else {
        Err(Error::DecomposeIncomplete(format!(
            "one or more stages failed; see {}",
            path.display()
        )))
    }
}

/// A successfully written function symbol map and the canonical name index
/// retained for downstream orchestration.
struct PreparedFunctionMap {
    pass2_map: Option<decompile::PreparedSymbolPass2Map>,
    creation_plan: decompile::Pass2CreationPlan,
    function_names: HashMap<String, String>,
    evidence_name_projection: globals::FunctionEvidenceNameProjection,
}

type FunctionNameIndexes = HashMap<String, HashMap<String, String>>;

#[derive(Default)]
struct PreparedGlobalsFunctionInputs {
    recovered_names: FunctionNameIndexes,
    evidence_names: HashMap<String, globals::FunctionEvidenceNameProjection>,
}

/// A successfully written globals map retained for pass-2 application.
struct PreparedGlobalMap {
    pass2_map: decompile::PreparedPass2Map,
}

/// One complete globals sweep: typed pass-2 inputs and the aggregate report.
struct GlobalsStageOutcome {
    maps: HashMap<String, PreparedGlobalMap>,
    stage: StageReport,
}

/// Per-image symbol map outcome from [`build_and_write_symbol_maps`]: the
/// successful `(label, prepared map)` entries plus any per-image errors.
type SymbolMapsResult = (HashMap<String, PreparedFunctionMap>, Vec<(String, String)>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GlobalsRouteMode {
    PrepareApplicationInput,
    RecordOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SymbolRouteStep {
    PrepareNamesAndProjection,
    Finalize {
        rewrite_decompiled_c: bool,
    },
    LoadFinalizedNames,
    RunGlobals(GlobalsRouteMode),
    RunGlobalShapes,
    DispatchPass2,
    /// Records the `global_types_apply` stage from the pass-2 outcomes.
    /// Pure reporting — runs no script, writes no file — so it sits between
    /// `DispatchPass2` (whose rebuilds null the five `global_types_*` fields
    /// it patches back in) and `Finalize`.
    ApplyGlobalTypes,
    /// Normal-route only: re-run the `global_shapes` stage after the route's
    /// LAST input rewrite — `Finalize`'s symbolicate pass stamps both
    /// functions.json and thumb_functions.json — and re-commit the sidecar
    /// over the tree's FINAL inputs. See `orchestrate_symbol_route`.
    RefreshGlobalShapes,
}

fn orchestrate_symbol_route(no_symbol_pass: bool, mut run_step: impl FnMut(SymbolRouteStep)) {
    if no_symbol_pass {
        // Two finalizes. globals recovery consumes the finalized function names
        // (LoadFinalizedNames reads them off disk, since this route skips the
        // in-memory projection the normal route uses), so it must follow a finalize.
        // But the string-ref tier (inside finalize's build_map) needs globals.json
        // to exist. So: (1) finalize to produce recovered/token names for globals,
        // deferring the decompiled.c rewrite so its idempotency sentinel does not
        // block pass 2; (2) run globals (writes globals.json); (3) finalize again —
        // now the string-ref tier activates, and this pass rewrites decompiled.c
        // with the full name set. See AGENTS (symbolication) for the rationale.
        run_step(SymbolRouteStep::Finalize {
            rewrite_decompiled_c: false,
        });
        run_step(SymbolRouteStep::LoadFinalizedNames);
        run_step(SymbolRouteStep::RunGlobals(GlobalsRouteMode::RecordOnly));
        run_step(SymbolRouteStep::Finalize {
            rewrite_decompiled_c: true,
        });
        // This route has no pass 2 to feed (RunGlobalShapes only matters as
        // pass-2 input on the normal route below), so shape recovery just
        // needs to run once, after globals.json exists, to produce the
        // sidecar. Keep it last so its position/timing on this route is
        // unchanged by the normal-route reorder below. No input is rewritten
        // after this point, so — unlike the normal route — there is nothing
        // to re-commit and no RefreshGlobalShapes/ApplyGlobalTypes steps.
        run_step(SymbolRouteStep::RunGlobalShapes);
    } else {
        run_step(SymbolRouteStep::PrepareNamesAndProjection);
        run_step(SymbolRouteStep::RunGlobals(
            GlobalsRouteMode::PrepareApplicationInput,
        ));
        // First shape sweep — after globals.json exists, before pass 2 — so
        // DispatchPass2 can derive the strict `undefinedN` apply-map from
        // global_shapes.json and a later pass-2 script can apply the
        // recovered shapes as types alongside ApplyGlobals. This is
        // input-safe: the shape stage reads only the raw image, globals.json,
        // and the pass-1 functions.json / thumb_functions.json inventory,
        // never decompiled.c; and pass 2 is `-process -noanalysis`, so it
        // never changes function boundaries — the pass-1 inventory the shape
        // stage consumes is identical pre/post pass 2. See AGENTS
        // (Phase 3.2) for the full rationale.
        run_step(SymbolRouteStep::RunGlobalShapes);
        run_step(SymbolRouteStep::DispatchPass2);
        run_step(SymbolRouteStep::ApplyGlobalTypes);
        run_step(SymbolRouteStep::Finalize {
            rewrite_decompiled_c: false,
        });
        // The first sweep's committed sidecar is born stale — twice over.
        // Inside DispatchPass2, pass 2's ownership-aware refresh rewrites
        // functions.json and thumb_enrich_post_pass2 rewrites
        // thumb_functions.json; then Finalize — the route's LAST input
        // rewriter — stamps name/original_name/annotations into BOTH files
        // via symbolicate's rewrite_functions_json (measured e2e: those
        // writes land after the earlier rewrites, so a re-commit placed
        // between DispatchPass2 and Finalize is re-staled). Re-run the stage
        // once more, after Finalize, so the committed sidecar (and the
        // single stage entry, replaced in place) hashes the tree's FINAL
        // inputs. Nothing after this point rewrites a hashed input:
        // decode_rf/hardware_config write only under rf/. Idempotent by the
        // reorder's safety argument above: identical inventories → identical
        // decode inputs and totals; the input hashes and the observation
        // context names (functions.json names rewritten by pass 2 / finalize)
        // may differ.
        run_step(SymbolRouteStep::RefreshGlobalShapes);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PostSymbolStep {
    DecodeRf,
    HardwareConfig,
}

fn orchestrate_post_symbol_route(mut run_step: impl FnMut(PostSymbolStep)) {
    run_step(PostSymbolStep::DecodeRf);
    run_step(PostSymbolStep::HardwareConfig);
}

const SYMBOL_MAP_ERROR_MAX_CHARS: usize = 2_048;
const SYMBOL_MAP_ERROR_TRUNCATION_MARKER: &str = " [truncated]";

fn truncate_symbol_map_error(message: String) -> String {
    if message.chars().count() <= SYMBOL_MAP_ERROR_MAX_CHARS {
        return message;
    }
    let keep = SYMBOL_MAP_ERROR_MAX_CHARS - SYMBOL_MAP_ERROR_TRUNCATION_MARKER.chars().count();
    let mut truncated: String = message.chars().take(keep).collect();
    truncated.push_str(SYMBOL_MAP_ERROR_TRUNCATION_MARKER);
    truncated
}

fn symbol_map_stage(
    function_maps: &HashMap<String, PreparedFunctionMap>,
    mut errors: Vec<(String, String)>,
    duration_ms: u128,
) -> StageReport {
    let has_output = function_maps
        .values()
        .any(|prepared| prepared.pass2_map.is_some());
    if !errors.is_empty() {
        errors.sort();
        let error = errors
            .into_iter()
            .map(|(label, message)| format!("{label}: {}", truncate_symbol_map_error(message)))
            .collect::<Vec<_>>()
            .join("\n");
        return StageReport {
            stage: "symbol_map",
            status: "failed",
            output: has_output.then(|| "ghidra/symbol_maps/".to_string()),
            reason: None,
            error: Some(error),
            images: Vec::new(),
            duration_ms,
        };
    }
    if !has_output {
        StageReport::skipped("symbol_map", "no symbols recovered")
    } else {
        StageReport::ok("symbol_map", "ghidra/symbol_maps/", duration_ms)
    }
}

/// Prepare the in-memory result for a function symbol map that was written by
/// `symbolicate::prepare_pass2_symbol_map`. The pass-2 map is retained only
/// when at least one decision applies something (a rename or an annotation).
fn prepare_function_map(
    label: &str,
    image_dir: &Path,
    _map_path: &Path,
    bundle: symbolicate::Pass2MapBundle,
) -> (PreparedFunctionMap, Option<String>) {
    let symbolicate::Pass2MapBundle {
        map,
        symbols,
        function_names,
        evidence_name_projection,
    } = bundle;
    let creation_plan = decompile::Pass2CreationPlan {
        candidates: map.creation_count,
        skips: map.creation_skips,
        requests: map.creation_requests,
    };
    let (pass2_map, validation_error) = if map.applied_decision_count > 0 || map.creation_count > 0
    {
        let functions_path = image_dir.join("decompiled").join("functions.json");
        let image_path = image_dir.join(format!("{label}.bin"));
        match decompile::PreparedSymbolPass2Map::new(
            &map.path,
            &functions_path,
            &image_path,
            label,
            map.execution_count,
            map.applied_decision_count,
            creation_plan.requests.clone(),
        ) {
            Ok(prepared) if prepared.map_blake3() == map.map_blake3 => (Some(prepared), None),
            Ok(_) => (
                None,
                Some("function map validation: written map identity changed".to_string()),
            ),
            Err(error) => (None, Some(format!("function map validation: {error}"))),
        }
    } else {
        (None, None)
    };
    let _ = symbols;
    (
        PreparedFunctionMap {
            pass2_map,
            creation_plan,
            function_names,
            evidence_name_projection,
        },
        validation_error,
    )
}

fn retain_pass2_creation_plans(
    images: &mut [decompile::ImageResult],
    function_maps: &HashMap<String, PreparedFunctionMap>,
) {
    for image in images {
        image.pass2_creation_plan = function_maps
            .get(&image.label)
            .map(|prepared| prepared.creation_plan.clone());
    }
}

fn take_globals_function_inputs(
    function_maps: &mut HashMap<String, PreparedFunctionMap>,
) -> PreparedGlobalsFunctionInputs {
    let mut inputs = PreparedGlobalsFunctionInputs::default();
    for (label, prepared) in function_maps {
        inputs
            .recovered_names
            .insert(label.clone(), std::mem::take(&mut prepared.function_names));
        inputs.evidence_names.insert(
            label.clone(),
            std::mem::take(&mut prepared.evidence_name_projection),
        );
    }
    inputs
}

/// One image's terminal PAL state, resolved once after the pass-1 marshal:
/// the validated terminal manifest (`images/<label>/pal_tasks/tasks.json`),
/// its identity, the canonical manifest path pass-2 arguments consume, the
/// terminal scatter manifest path (present-state images only), and the
/// symbolicate pass-2 context derived from the same validated artifact.
struct TerminalPalMap {
    identity: String,
    manifest_path: PathBuf,
    scatter_manifest: Option<PathBuf>,
    context: symbolicate::PalPass2Context,
}

/// One image's authenticated exception-root state, reconstructed from the
/// explicit current run after terminal marshalling. The canonical kit copies
/// are the only paths passed to Ghidra; `context` binds those manifest bytes to
/// the terminal raw/scatter bytes and exact pass-1 application summary.
struct TerminalExceptionMap {
    identity: String,
    manifest_path: PathBuf,
    scatter_manifest: Option<PathBuf>,
    context: decompile::ExceptionPass2Context,
}

struct StagedExceptionFiles {
    manifest_path: PathBuf,
    scatter_manifest: Option<PathBuf>,
    scatter_load_map_blake3: Option<[u8; 32]>,
}

fn copy_exception_file(
    source_root: &crate::trusted_fs::TrustedDirectory,
    source_relative: &Path,
    target_dir: &crate::trusted_fs::TrustedDirectory,
    target_name: &str,
    context: &str,
) -> Result<[u8; 32]> {
    let mut source = source_root
        .open_regular_file(source_relative, context)
        .map_err(|error| Error::BadExceptionRoots(error.to_string()))?;
    let mut target = target_dir
        .atomic_write_file(target_name, context)
        .map_err(|error| Error::BadExceptionRoots(error.to_string()))?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        target.write_all(&buffer[..read])?;
    }
    target.commit()?;
    Ok(*hasher.finalize().as_bytes())
}

fn canonical_staged_path(ghidra_dir: &Path, relative: &Path, context: &str) -> Result<PathBuf> {
    let canonical_root = std::fs::canonicalize(ghidra_dir)?;
    let expected = canonical_root.join(relative);
    let canonical = std::fs::canonicalize(ghidra_dir.join(relative))?;
    if canonical != expected || !canonical.is_file() {
        return Err(Error::DecomposeIncomplete(format!(
            "{context} is not a canonical regular file contained in the Ghidra kit: {}",
            canonical.display()
        )));
    }
    Ok(canonical)
}

fn stage_terminal_scatter_files(
    image_dir: &Path,
    ghidra_dir: &Path,
    label: &str,
    image_base: u32,
    raw: &[u8],
) -> Result<(PathBuf, [u8; 32])> {
    let digest = crate::scatter::restage_materialized(
        image_dir,
        &image_dir.join("scatter/load_map.json"),
        raw,
        image_base,
        label,
        ghidra_dir,
    )?;
    let relative = Path::new("scatter").join(label).join("load_map.json");
    Ok((
        canonical_staged_path(ghidra_dir, &relative, "pass-2 scatter artifact manifest")?,
        digest,
    ))
}

fn stage_terminal_exception_files(
    image_dir: &Path,
    ghidra_dir: &Path,
    label: &str,
    image_base: u32,
    scatter_state: decompile::RuntimeScatterState,
    expected_manifest_blake3: &str,
) -> Result<StagedExceptionFiles> {
    let scatter_present = exception_scatter_present(label, scatter_state)?;
    let source =
        crate::trusted_fs::TrustedDirectory::new(image_dir, "terminal exception image directory")
            .map_err(|error| Error::BadExceptionRoots(error.to_string()))?;
    let kit = crate::trusted_fs::TrustedDirectory::new(ghidra_dir, "Ghidra kit directory")
        .map_err(|error| Error::BadExceptionRoots(error.to_string()))?;

    let exception_root = kit
        .open_or_create_directory_child("exception_roots", "kit exception-root directory")
        .and_then(|directory| {
            directory.open_or_create_directory_child(label, "kit exception image directory")
        })
        .map_err(|error| Error::BadExceptionRoots(error.to_string()))?;
    let manifest_blake3 = copy_exception_file(
        &source,
        Path::new("exception_roots")
            .join(EXCEPTION_MANIFEST_FILE)
            .as_path(),
        &exception_root,
        EXCEPTION_MANIFEST_FILE,
        "terminal exception manifest restage",
    )?;
    if crate::manifest::blake3_fixed(manifest_blake3) != expected_manifest_blake3 {
        return Err(Error::DecomposeIncomplete(format!(
            "terminal exception manifest for {label} changed after generation"
        )));
    }

    let kit_images = kit
        .open_or_create_directory_child("images", "kit image directory")
        .map_err(|error| Error::BadExceptionRoots(error.to_string()))?;
    copy_exception_file(
        &source,
        Path::new(&format!("{label}.bin")),
        &kit_images,
        label,
        "terminal exception raw-image restage",
    )?;

    let (scatter_manifest, scatter_load_map_blake3) = if scatter_present {
        let raw = std::fs::read(ghidra_dir.join("images").join(label))?;
        let (manifest, digest) =
            stage_terminal_scatter_files(image_dir, ghidra_dir, label, image_base, &raw)?;
        (Some(manifest), Some(digest))
    } else {
        (None, None)
    };
    let relative = Path::new("exception_roots")
        .join(label)
        .join(EXCEPTION_MANIFEST_FILE);
    Ok(StagedExceptionFiles {
        manifest_path: canonical_staged_path(ghidra_dir, &relative, "pass-2 exception manifest")?,
        scatter_manifest,
        scatter_load_map_blake3,
    })
}

/// Reconstruct strict pass-2 exception contexts only for explicit present
/// application state. Opaque skips retain generation output but have no Ghidra
/// application summary, so they intentionally produce no context.
fn load_terminal_exception_maps(
    images_dir: &Path,
    report: &decompile::DecompileReport,
    ghidra_dir: &Path,
) -> (HashMap<String, TerminalExceptionMap>, Vec<(String, String)>) {
    let mut maps = HashMap::new();
    let mut errors = Vec::new();
    for image in &report.images {
        let state = explicit_runtime_state(report, image);
        match state.exception {
            decompile::RuntimeExceptionState::Unmanaged => continue,
            decompile::RuntimeExceptionState::Absent => {
                if let Err(error) =
                    crate::exception_roots::clear_materialized(ghidra_dir, &image.label)
                {
                    errors.push((
                        image.label.clone(),
                        format!("pass-2 exception absence restage: {error}"),
                    ));
                }
                continue;
            }
            decompile::RuntimeExceptionState::Present(map) => {
                let Some(applied) = image.exception_roots_applied.as_ref() else {
                    if matches!(image.outcome, ImageOutcome::Analyzed(_)) {
                        errors.push((
                            image.label.clone(),
                            "current exception application summary is missing".to_string(),
                        ));
                    }
                    continue;
                };
                let label = &image.label;
                let image_dir = images_dir.join(label);
                let staged = stage_terminal_exception_files(
                    &image_dir,
                    ghidra_dir,
                    label,
                    image.image_start,
                    report.runtime_scatter_state(label),
                    &map.blake3,
                );
                let result = staged.and_then(|staged| {
                    let context = decompile::read_exception_pass2_context(
                        decompile::ExceptionPass2ContextInput {
                            manifest_path: &staged.manifest_path,
                            image_dir: &image_dir,
                            image_label: label,
                            toc_name: crate::manifest::toc_name(label),
                            image_base: image.image_start,
                            expected_identity: &map.identity,
                            expected_scatter_load_map_blake3: staged.scatter_load_map_blake3,
                            applied,
                        },
                    )?;
                    Ok(TerminalExceptionMap {
                        identity: map.identity.clone(),
                        manifest_path: staged.manifest_path,
                        scatter_manifest: staged.scatter_manifest,
                        context,
                    })
                });
                match result {
                    Ok(terminal) => {
                        maps.insert(label.clone(), terminal);
                    }
                    Err(error) => {
                        let _ = crate::exception_roots::clear_materialized(ghidra_dir, label);
                        errors.push((
                            label.clone(),
                            format!("terminal exception manifest: {error}"),
                        ));
                    }
                }
            }
        }
    }
    (maps, errors)
}

fn record_terminal_exception_errors(
    report: &mut decompile::DecompileReport,
    errors: &[(String, String)],
) {
    for (label, reason) in errors {
        if let Some(image) = report.images.iter_mut().find(|image| image.label == *label) {
            image.exception_roots_applied = None;
            image.exception_error = Some(reason.clone());
        }
    }
}

/// Re-read every explicit `Present` image's terminal PAL manifest against
/// the terminal raw/scatter bytes (validating the committed tree, never
/// trusting directory existence) and derive the pass-2 symbolicate context.
/// A label whose terminal manifest fails validation is returned as an
/// error — the symbol map and pass 2 must not bind a manifest the strict
/// reader rejects.
fn load_terminal_pal_maps(
    images_dir: &Path,
    report: &decompile::DecompileReport,
    ghidra_dir: &Path,
) -> (HashMap<String, TerminalPalMap>, Vec<(String, String)>) {
    let mut maps = HashMap::new();
    let mut errors = Vec::new();
    for image in &report.images {
        let state = explicit_runtime_state(report, image);
        let map = match state.tasks {
            decompile::RuntimeTaskState::Present(ref map) => map.clone(),
            _ => continue,
        };
        let label = &image.label;
        let image_dir = images_dir.join(label);
        let terminal_manifest = image_dir.join("pal_tasks").join(PAL_MANIFEST_FILE);
        let terminal_scatter = match state.scatter {
            decompile::RuntimeScatterState::Present => {
                Some(image_dir.join("scatter").join("load_map.json"))
            }
            _ => None,
        };
        match validate_terminal_pal_manifest(
            &image_dir,
            label,
            image.image_start,
            state.scatter,
            &terminal_manifest,
            &map.identity,
        ) {
            Ok(artifact) => {
                // Pass-2 manifest arguments must sit inside the Ghidra kit
                // root (see `stage_pass2_manifest`); a restage failure is a
                // fail-closed per-image error, never a silent skip.
                let restage = (|| -> Result<(PathBuf, Option<PathBuf>)> {
                    let staged_manifest = ghidra_dir
                        .join("pal_tasks")
                        .join(label)
                        .join(PAL_MANIFEST_FILE);
                    stage_pass2_manifest(&terminal_manifest, &staged_manifest)?;
                    // Both PAL and exception-root validators open every
                    // file-backed scatter payload relative to the map. Copy
                    // the raw bytes first, then restage the complete strict
                    // artifact rather than only its load_map.json.
                    let staged_raw = ghidra_dir.join("images").join(label);
                    std::fs::create_dir_all(staged_raw.parent().expect("raw image parent"))?;
                    std::fs::copy(image_dir.join(format!("{label}.bin")), &staged_raw)?;
                    let staged_scatter = match &terminal_scatter {
                        Some(_) => {
                            let raw = std::fs::read(&staged_raw)?;
                            let (staged, digest) = stage_terminal_scatter_files(
                                &image_dir,
                                ghidra_dir,
                                label,
                                image.image_start,
                                &raw,
                            )?;
                            if Some(digest) != artifact.scatter_load_map_blake3 {
                                return Err(Error::BadScatter(
                                    "pass-2 PAL scatter digest does not match the task manifest"
                                        .into(),
                                ));
                            }
                            Some(staged)
                        }
                        None => None,
                    };
                    Ok((staged_manifest, staged_scatter))
                })();
                match restage {
                    Ok((manifest_path, scatter_manifest)) => {
                        maps.insert(
                            label.clone(),
                            TerminalPalMap {
                                identity: artifact.identity.clone(),
                                manifest_path,
                                scatter_manifest,
                                context: pal_pass2_context(&artifact),
                            },
                        );
                    }
                    Err(error) => errors.push((
                        label.clone(),
                        format!("pass-2 PAL manifest restage: {error}"),
                    )),
                }
            }
            Err(error) => errors.push((label.clone(), format!("terminal PAL manifest: {error}"))),
        }
    }
    (maps, errors)
}

/// The coherent runtime analysis state of one image. A failed or
/// terminal-invalid Ghidra run owns no current terminal scatter or PAL state,
/// but it does not invalidate exception-root generation that completed before
/// Ghidra started.
fn explicit_runtime_state(
    report: &decompile::DecompileReport,
    image: &decompile::ImageResult,
) -> decompile::RuntimeAnalysisState {
    let mut runtime = report.runtime_analysis_state(&image.label);
    if matches!(
        image.outcome,
        ImageOutcome::Failed(_) | ImageOutcome::TerminalInvalid
    ) {
        runtime.scatter = decompile::RuntimeScatterState::Unmanaged;
        runtime.tasks = decompile::RuntimeTaskState::Unmanaged;
    }
    runtime
}

/// Derive the symbolicate pass-2 PAL context from a validated artifact:
/// the identity and dependency hashes the map's `pal` block binds, plus
/// every application group keyed by normalized entry with its full task
/// refs. `applied` is recomputed per record inside `build_map`, so the
/// context-level value carries no information.
fn pal_pass2_context(
    artifact: &crate::pal_tasks::ValidatedTaskArtifact,
) -> symbolicate::PalPass2Context {
    let manifest_blake3 = crate::manifest::blake3_fixed(artifact.manifest_blake3);
    let scatter_load_map_blake3 = artifact
        .scatter_load_map_blake3
        .map(crate::manifest::blake3_fixed);
    let tasks_by_index = |index: u32| {
        artifact
            .plan
            .tasks
            .iter()
            .find(|task| task.index == index)
            .expect("validated applications reference parsed task indices")
    };
    let mut applications = std::collections::BTreeMap::new();
    for application in &artifact.plan.applications {
        let tasks = application
            .task_indices
            .iter()
            .map(|index| {
                let task = tasks_by_index(*index);
                symbolicate::PalTaskRef {
                    manifest_blake3: manifest_blake3.clone(),
                    task_index: task.index,
                    name: task.name.clone(),
                    slot: task.slot,
                    priority: task.priority,
                    stack_size: task.stack_size,
                }
            })
            .collect();
        applications.insert(
            application.entry,
            symbolicate::PalApplicationRef {
                isa: match application.isa {
                    crate::pal_tasks::TaskIsa::Arm => "arm",
                    crate::pal_tasks::TaskIsa::Thumb => "thumb",
                },
                desired_primary: application.desired_primary.clone(),
                applied: true,
                tasks,
            },
        );
    }
    symbolicate::PalPass2Context {
        identity: artifact.identity.clone(),
        manifest_blake3,
        scatter_load_map_blake3,
        applications,
    }
}

/// Re-materialize one terminal manifest at its pass-1 source location under
/// the Ghidra kit root. The pass-1 marshal moves the terminal bytes to
/// `images/<label>/`, but `ApplySymbols`/`ExportDecomp` authenticate every
/// manifest argument as canonically contained in the kit root they are
/// handed — pass 2 runs against `<out>/ghidra`, so the terminal bytes are
/// copied back. The copies are intermediate pass-2 state under the pruned
/// `ghidra/` tree; the terminal artifacts stay authoritative.
fn stage_pass2_manifest(terminal: &Path, staged: &Path) -> Result<()> {
    std::fs::create_dir_all(staged.parent().expect("staged manifest parent"))?;
    std::fs::copy(terminal, staged)?;
    Ok(())
}

fn prepare_pass2_inputs(
    function_maps: &HashMap<String, PreparedFunctionMap>,
    global_maps: &HashMap<String, PreparedGlobalMap>,
    global_types_maps: &HashMap<String, decompile::PreparedPass2Map>,
    exceptions: &HashMap<String, TerminalExceptionMap>,
    pal: &HashMap<String, TerminalPalMap>,
) -> HashMap<String, decompile::Pass2Input> {
    let mut inputs = HashMap::new();
    for (label, prepared) in function_maps {
        let Some(pass2_map) = &prepared.pass2_map else {
            continue;
        };
        let input = inputs
            .entry(label.clone())
            .or_insert_with(decompile::Pass2Input::default);
        input.function_map = Some(pass2_map.clone());
    }
    for (label, prepared) in global_maps {
        let input = inputs
            .entry(label.clone())
            .or_insert_with(decompile::Pass2Input::default);
        input.global_map = Some(prepared.pass2_map.clone());
    }
    for (label, map) in global_types_maps {
        let input = inputs
            .entry(label.clone())
            .or_insert_with(decompile::Pass2Input::default);
        input.global_types_map = Some(map.clone());
    }
    for (label, terminal) in exceptions {
        let Some(input) = inputs.get_mut(label) else {
            continue;
        };
        input.exception_context = Some(terminal.context.clone());
        input.exception_identity = terminal.identity.clone();
        input.exception_manifest = Some(terminal.manifest_path.clone());
        input.scatter_manifest = terminal.scatter_manifest.clone();
    }
    // Pass-2 PAL wiring: every scheduled image whose run carried a present
    // PAL map agrees on that identity and receives the canonical terminal
    // task/scatter manifest paths; images without PAL state keep the
    // `none`/`-` arguments (absence validation).
    for (label, terminal) in pal {
        let Some(input) = inputs.get_mut(label) else {
            continue;
        };
        input.pal_identity = terminal.identity.clone();
        input.pal_manifest = Some(terminal.manifest_path.clone());
        input.scatter_manifest = terminal.scatter_manifest.clone();
    }
    inputs
}

/// Read each image's `global_shapes.json`, select apply-worthy scalar types,
/// and write the strict apply-map under `ghidra_dir/global_types_maps/<label>.json`
/// (mirroring `ghidra_dir/symbol_maps/<label>.json`). Returns the prepared
/// maps — only for images with >=1 candidate — keyed by label, plus the
/// per-label ineligible count for the report.
///
/// An image with no `global_shapes.json` never reached the shape stage;
/// that is normal and is skipped without comment. A shapes file that fails
/// to parse, or a map that fails to write or validate, is logged and that
/// image degrades to names-only pass-2 input (fail-closed).
fn derive_global_types_maps(
    images_dir: &Path,
    ghidra_dir: &Path,
) -> (
    HashMap<String, decompile::PreparedPass2Map>,
    HashMap<String, usize>,
) {
    let mut maps = HashMap::new();
    let mut ineligible = HashMap::new();
    let entries = match std::fs::read_dir(images_dir) {
        Ok(entries) => entries,
        Err(error) => {
            tracing::warn!("images_dir unreadable, no global-type maps derived: {error}");
            return (maps, ineligible);
        }
    };
    for entry in entries.flatten() {
        let label = entry.file_name().to_string_lossy().into_owned();
        let shapes = entry.path().join("decompiled").join("global_shapes.json");
        // No global_shapes.json means this image never reached the shape
        // stage (e.g. no code image) — expected, so skip quietly.
        let Ok(bytes) = std::fs::read(&shapes) else {
            continue;
        };
        let sel = match global_types::select_from_shapes_json(&bytes) {
            Ok(sel) => sel,
            Err(error) => {
                tracing::warn!(
                    "{label}: global_shapes.json unreadable, skipping global-type apply: {error}"
                );
                continue;
            }
        };
        ineligible.insert(label.clone(), sel.ineligible);
        let map_path = ghidra_dir
            .join("global_types_maps")
            .join(format!("{label}.json"));
        match global_types::write_type_map(&map_path, &label, &sel) {
            Ok(Some(count)) => match decompile::PreparedPass2Map::new(&map_path, count) {
                Ok(map) => {
                    maps.insert(label, map);
                }
                Err(error) => {
                    tracing::warn!(
                        "{label}: global-types map failed validation, skipping global-type apply: {error}"
                    );
                }
            },
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(
                    "{label}: failed to write global-types map, skipping global-type apply: {error}"
                );
            }
        }
    }
    (maps, ineligible)
}

fn globals_apply_stage(
    no_symbol_pass: bool,
    prepared_globals: &HashMap<String, PreparedGlobalMap>,
    images: Option<&[decompile::ImageResult]>,
    duration_ms: u128,
) -> StageReport {
    if no_symbol_pass {
        return StageReport::skipped("globals_apply", "--no-symbol-pass");
    }
    if prepared_globals.is_empty() {
        return StageReport::skipped("globals_apply", "no recovered globals");
    }

    let mut labels: Vec<&str> = prepared_globals.keys().map(String::as_str).collect();
    labels.sort_unstable();
    let mut processed = 0usize;
    let mut applied_total = 0usize;
    let mut skipped_total = 0usize;
    let mut first_error = None;

    if let Some(images) = images {
        for image in images {
            let Ok(index) = labels.binary_search(&image.label.as_str()) else {
                continue;
            };
            let label = labels.remove(index);
            if let Some(error) = &image.pass2_error {
                first_error.get_or_insert_with(|| format!("{label}: {error}"));
                continue;
            }
            if let Some(error) = &image.globals_apply_error {
                first_error.get_or_insert_with(|| format!("{label}: {error}"));
                continue;
            }
            let (Some(applied), Some(skipped)) =
                (image.globals_applied, image.globals_apply_skipped)
            else {
                first_error.get_or_insert_with(|| {
                    format!("{label}: no valid ApplyGlobals success summary")
                });
                continue;
            };
            let Some(classified) = applied.checked_add(skipped) else {
                first_error
                    .get_or_insert_with(|| format!("{label}: global application counts overflow"));
                continue;
            };
            let expected = prepared_globals[label].pass2_map.count();
            if classified != expected {
                first_error.get_or_insert_with(|| {
                    format!(
                        "{label}: global application counts do not match prepared globals: \
                         {classified} != {expected}"
                    )
                });
                continue;
            }
            let (Some(next_applied), Some(next_skipped)) = (
                applied_total.checked_add(applied),
                skipped_total.checked_add(skipped),
            ) else {
                first_error
                    .get_or_insert_with(|| format!("{label}: global application totals overflow"));
                continue;
            };
            applied_total = next_applied;
            skipped_total = next_skipped;
            processed += 1;
        }
    }
    for label in labels {
        first_error.get_or_insert_with(|| format!("{label}: missing pass-2 image result"));
    }

    StageReport {
        stage: "globals_apply",
        status: if first_error.is_some() {
            "failed"
        } else {
            "ok"
        },
        output: Some(format!(
            "{processed} image(s) processed; {applied_total} globals applied; \
             {skipped_total} skipped"
        )),
        reason: None,
        error: first_error,
        images: Vec::new(),
        duration_ms,
    }
}

/// Set `global_types_ineligible` on every matching `report_images` entry.
/// Runs independent of whether application itself ran or was skipped —
/// `ineligible` comes from `derive_global_types_maps`, which counts every
/// image with a `global_shapes.json`, not only the ones apply-worthy enough
/// to reach pass 2 (see its doc comment).
fn record_global_types_ineligible(
    report_images: &mut [ImageReport],
    ineligible: &HashMap<String, usize>,
) {
    for (label, count) in ineligible {
        if let Some(image) = report_images.iter_mut().find(|image| &image.image == label) {
            image.global_types_ineligible = Some(*count);
        }
    }
}

fn record_global_types_error(report_images: &mut [ImageReport], label: &str, reason: &str) {
    if let Some(image) = report_images.iter_mut().find(|image| image.image == label) {
        image.global_types_error = Some(reason.to_string());
    }
}

/// Apply-global-types aggregation, mirroring `globals_apply_stage`'s skip
/// policy and per-label consistency check (same-shape strict-conservation
/// loop over `image.global_types_applied` / `global_types_apply_skipped` /
/// `global_types_apply_error`). Additionally patches `report_images` (the
/// `decompile` stage's already-installed `ImageReport`s) in place with
/// `global_types_applied` / `global_types_skipped` / `global_types_error` /
/// `global_types_candidates`, because — unlike `globals_applied` — those
/// fields are never copied by `ImageReport::from_result`; `global_types_ineligible`
/// in particular has no `decompile::ImageResult` counterpart at all, only
/// `derive_global_types_maps`'s `ineligible` map.
///
/// Callers on the normal route MUST pass a `report_images` slice that has
/// already been through this call's `DispatchPass2` invocation of
/// `refresh_decompile_stage_images` (i.e. call this function *after* that
/// refresh, not alongside `globals_apply_stage`). `refresh_decompile_stage_images`
/// rebuilds `stages[decompile_pos].images` from `decompile::ImageResult` via
/// `ImageReport::from_result`, which always nulls the five `global_types_*`
/// fields — a patch applied before that refresh would be silently discarded.
fn global_types_apply_stage(
    no_symbol_pass: bool,
    no_apply_global_types: bool,
    global_types_maps: &HashMap<String, decompile::PreparedPass2Map>,
    ineligible: &HashMap<String, usize>,
    images: Option<&[decompile::ImageResult]>,
    report_images: &mut [ImageReport],
    duration_ms: u128,
) -> StageReport {
    record_global_types_ineligible(report_images, ineligible);

    if no_symbol_pass {
        return StageReport::skipped("global_types_apply", "--no-symbol-pass");
    }
    if no_apply_global_types {
        return StageReport::skipped("global_types_apply", "--no-apply-global-types");
    }
    if global_types_maps.is_empty() {
        return StageReport::skipped("global_types_apply", "no recovered scalar shapes");
    }

    let mut labels: Vec<&str> = global_types_maps.keys().map(String::as_str).collect();
    labels.sort_unstable();
    let mut processed = 0usize;
    let mut applied_total = 0usize;
    let mut skipped_total = 0usize;
    let mut first_error = None;

    if let Some(images) = images {
        for image in images {
            let Ok(index) = labels.binary_search(&image.label.as_str()) else {
                continue;
            };
            let label = labels.remove(index);
            if let Some(error) = &image.pass2_error {
                first_error.get_or_insert_with(|| format!("{label}: {error}"));
                record_global_types_error(report_images, label, error);
                continue;
            }
            if let Some(error) = &image.global_types_apply_error {
                first_error.get_or_insert_with(|| format!("{label}: {error}"));
                record_global_types_error(report_images, label, error);
                continue;
            }
            let (Some(applied), Some(skipped)) =
                (image.global_types_applied, image.global_types_apply_skipped)
            else {
                let reason = "no valid ApplyGlobalTypes success summary";
                first_error.get_or_insert_with(|| format!("{label}: {reason}"));
                record_global_types_error(report_images, label, reason);
                continue;
            };
            let Some(classified) = applied.checked_add(skipped) else {
                let reason = "global-type application counts overflow";
                first_error.get_or_insert_with(|| format!("{label}: {reason}"));
                record_global_types_error(report_images, label, reason);
                continue;
            };
            let expected = global_types_maps[label].count();
            if classified != expected {
                let reason = format!(
                    "global-type application counts do not match prepared types: \
                     {classified} != {expected}"
                );
                first_error.get_or_insert_with(|| format!("{label}: {reason}"));
                record_global_types_error(report_images, label, &reason);
                continue;
            }
            let (Some(next_applied), Some(next_skipped)) = (
                applied_total.checked_add(applied),
                skipped_total.checked_add(skipped),
            ) else {
                let reason = "global-type application totals overflow";
                first_error.get_or_insert_with(|| format!("{label}: {reason}"));
                record_global_types_error(report_images, label, reason);
                continue;
            };
            applied_total = next_applied;
            skipped_total = next_skipped;
            processed += 1;
            if let Some(report_image) = report_images.iter_mut().find(|ri| ri.image == label) {
                report_image.global_types_applied = Some(applied);
                report_image.global_types_skipped = Some(skipped);
                report_image.global_types_candidates = Some(classified);
                report_image.global_types_error = None;
            }
        }
    }
    for label in labels {
        let reason = "missing pass-2 image result";
        first_error.get_or_insert_with(|| format!("{label}: {reason}"));
        record_global_types_error(report_images, label, reason);
    }

    StageReport {
        stage: "global_types_apply",
        status: if first_error.is_some() {
            "failed"
        } else {
            "ok"
        },
        output: Some(format!(
            "{processed} image(s) processed; {applied_total} global types applied; \
             {skipped_total} skipped"
        )),
        reason: None,
        error: first_error,
        images: Vec::new(),
        duration_ms,
    }
}

fn load_finalized_function_name_indexes(
    images_dir: &Path,
    images: &[decompile::ImageResult],
) -> FunctionNameIndexes {
    images
        .iter()
        .map(|image| {
            let symbols_path = images_dir
                .join(&image.label)
                .join("decompiled")
                .join("symbols.json");
            (
                image.label.clone(),
                load_recovered_function_names(&symbols_path),
            )
        })
        .collect()
}

fn run_globals_stage_with<F>(
    images: &mut [decompile::ImageResult],
    images_dir: &Path,
    manifest: &Path,
    function_inputs: &PreparedGlobalsFunctionInputs,
    opts: &globals::GlobalsOpts,
    mut run_image: F,
) -> GlobalsStageOutcome
where
    F: FnMut(
        &Path,
        &str,
        &Path,
        &HashMap<String, String>,
        Option<&globals::FunctionEvidenceNameProjection>,
        &globals::GlobalsOpts,
    ) -> Result<globals::GlobalsReport>,
{
    let started = Instant::now();
    let mut maps = HashMap::new();
    let mut errors: Vec<(String, String)> = Vec::new();
    let mut counts: Vec<(String, usize)> = Vec::new();
    let mut conflicts = 0usize;
    let mut provisional_total = 0usize;
    let mut provisional_suppressed_total = 0usize;
    let empty_names = HashMap::new();

    for image in images {
        let label = image.label.clone();
        // Unanimously-opaque images never ran Ghidra: no `decompiled/`
        // sidecars exist, so there is nothing to recover and no directory
        // to write `globals.json` into — skip like a missing `.bin`.
        if matches!(image.outcome, ImageOutcome::SkippedOpaque(_)) {
            continue;
        }
        let image_dir = images_dir.join(&label);
        if !image_dir.join(format!("{label}.bin")).exists() {
            continue;
        }
        let names = function_inputs
            .recovered_names
            .get(&label)
            .unwrap_or(&empty_names);
        let evidence_names = function_inputs.evidence_names.get(&label);
        match run_image(&image_dir, &label, manifest, names, evidence_names, opts) {
            Ok(report) => {
                image.globals_recovered = Some(report.recovered_count);
                image.globals_provisional = Some(report.provisional_generated);
                image.globals_provisional_suppressed =
                    Some(report.provisional_suppressed_by_recovered);
                conflicts += report.conflicts_dropped;
                provisional_total += report.provisional_generated;
                provisional_suppressed_total += report.provisional_suppressed_by_recovered;
                counts.push((label.clone(), report.recovered_count));
                if let Some(count) = NonZeroUsize::new(report.recovered_count) {
                    let map_path = image_dir.join("decompiled").join("globals.json");
                    match decompile::PreparedPass2Map::new(&map_path, count) {
                        Ok(pass2_map) => {
                            maps.insert(label, PreparedGlobalMap { pass2_map });
                        }
                        Err(error) => {
                            let message = format!("globals map validation: {error}");
                            image.globals_error = Some(message.clone());
                            errors.push((label, message));
                        }
                    }
                }
            }
            Err(error) => {
                let message = format!("{error:#}");
                image.globals_error = Some(message.clone());
                errors.push((label, message));
            }
        }
    }

    let recovered_total: usize = counts.iter().map(|(_, count)| count).sum();
    let stage = StageReport {
        stage: "globals",
        status: if errors.is_empty() { "ok" } else { "failed" },
        output: Some(format!(
            "{} image(s) processed; {} recovered globals total; {} conflicts dropped; \
             {} provisional generated ({} suppressed by Recovered)",
            counts.len(),
            recovered_total,
            conflicts,
            provisional_total,
            provisional_suppressed_total,
        )),
        reason: None,
        error: errors.first().map(|(_, error)| error.clone()),
        images: Vec::new(),
        duration_ms: started.elapsed().as_millis(),
    };

    GlobalsStageOutcome { maps, stage }
}

fn run_globals_stage(
    images: &mut [decompile::ImageResult],
    images_dir: &Path,
    manifest: &Path,
    function_inputs: &PreparedGlobalsFunctionInputs,
    opts: &globals::GlobalsOpts,
) -> GlobalsStageOutcome {
    run_globals_stage_with(
        images,
        images_dir,
        manifest,
        function_inputs,
        opts,
        globals::run_with_evidence_projection,
    )
}

const GLOBAL_SHAPES_REASON_MAX_CHARS: usize = 2_048;

struct GlobalShapesCurrentRun {
    ghidra_records: usize,
    ghidra_accepted: usize,
    ghidra_quarantined: usize,
    thumb_substantial: Option<usize>,
    thumb_accepted: Option<usize>,
    thumb_quarantined: Option<usize>,
    recovered: usize,
}

fn bound_global_shapes_reason(reason: &str) -> String {
    reason
        .chars()
        .take(GLOBAL_SHAPES_REASON_MAX_CHARS)
        .collect()
}

fn clear_global_shapes_fields(image: &mut ImageReport) {
    image.global_shapes_inferred = None;
    image.global_shapes_no_evidence = None;
    image.global_shapes_conflicting = None;
    image.global_shape_observations = None;
    image.global_shapes_ghidra_quarantined = None;
    image.global_shapes_thumb_quarantined = None;
    image.global_shapes_quarantine_errors = None;
    image.global_shapes_decode_failures = None;
    image.global_shapes_state_barriers = None;
    image.global_shapes_error = None;
}

fn apply_global_shapes_success(
    image: &mut ImageReport,
    report: &global_shapes::GlobalShapesReport,
) {
    image.global_shapes_inferred = Some(report.inferred);
    image.global_shapes_no_evidence = Some(report.no_evidence);
    image.global_shapes_conflicting = Some(report.conflicting);
    image.global_shape_observations = Some(report.observations);
    image.global_shapes_ghidra_quarantined = Some(report.ghidra_quarantined);
    image.global_shapes_thumb_quarantined = Some(report.thumb_quarantined);
    image.global_shapes_quarantine_errors = Some(report.quarantine_errors);
    image.global_shapes_decode_failures = Some(report.decode_failures);
    image.global_shapes_state_barriers = Some(report.state_barriers);
    image.global_shapes_error = None;
}

/// Currentness check for the `global_shapes` stage. Binds from the
/// post-globals `decompile::ImageResult`s — never from the decompile
/// stage-report `ImageReport`s: on the normal route, `RunGlobalShapes` runs
/// before `DispatchPass2`, and the stage report deliberately withholds the
/// globals preparation fields until pass 2's outcome ("no pre-application
/// snapshot"), so the report is always stale for exactly the fields checked
/// last here.
fn current_global_shapes_run(
    result: &decompile::ImageResult,
) -> std::result::Result<GlobalShapesCurrentRun, String> {
    let ImageOutcome::Analyzed(ghidra_records) = result.outcome else {
        return Err("missing current ARM inventory".into());
    };
    let (Some(ghidra_accepted), Some(ghidra_quarantined)) = (
        result.ghidra_execution_accepted,
        result.ghidra_execution_quarantined,
    ) else {
        return Err("missing current ARM inventory".into());
    };
    match ghidra_accepted.checked_add(ghidra_quarantined) {
        Some(sum) if sum == ghidra_records => {}
        _ => {
            return Err("ghidra execution counts do not equal functions".into());
        }
    }
    if result.thumb_error.is_some() {
        return Err("current Thumb inventory failed".into());
    }
    let (thumb_substantial, thumb_accepted, thumb_quarantined) = match (
        result.thumb_functions,
        result.thumb_execution_accepted,
        result.thumb_execution_quarantined,
    ) {
        (None, None, None) => (None, None, None),
        (Some(substantial), Some(accepted), Some(quarantined)) => {
            (Some(substantial), Some(accepted), Some(quarantined))
        }
        _ => {
            return Err("thumb inventory fields must be all present or all absent".into());
        }
    };
    if result.globals_error.is_some() {
        return Err("current globals failed".into());
    }
    let Some(recovered) = result.globals_recovered else {
        return Err("missing current recovered globals".into());
    };
    Ok(GlobalShapesCurrentRun {
        ghidra_records,
        ghidra_accepted,
        ghidra_quarantined,
        thumb_substantial,
        thumb_accepted,
        thumb_quarantined,
        recovered,
    })
}

fn record_global_shapes_failure(image: &mut ImageReport, reason: String) -> String {
    let reason = bound_global_shapes_reason(&reason);
    image.global_shapes_error = Some(reason.clone());
    reason
}

/// Per-image outcome of a `global_shapes` sweep, retained by
/// `run_global_shapes_stage_with` across the normal route's later
/// `DispatchPass2` step. On that route, `RunGlobalShapes` runs *before*
/// `DispatchPass2` (the shape-stage reorder), and `DispatchPass2`'s own
/// `refresh_decompile_stage_images` / `install_decompile_stage_image_snapshot`
/// calls rebuild `stages[decompile_pos].images` from `decompile::ImageResult`
/// via `ImageReport::from_result`, which always nulls the nine
/// `global_shapes_*` fields (`ImageResult` has no such fields to preserve
/// them from — same reason `global_types_apply_stage`'s five fields need the
/// same treatment). Without re-applying this retained outcome afterward, the
/// `RunGlobalShapes` patch is silently discarded and `global_shapes_*` never
/// reaches `report.json` on the normal route. See `reapply_global_shapes_outcomes`.
enum GlobalShapesOutcome {
    Success(global_shapes::GlobalShapesReport),
    Failure(String),
}

/// Apply one retained outcome to `image`, mirroring exactly what
/// `run_global_shapes_stage_with`'s loop did the first time (clear, then
/// either the success counts or the bounded failure reason).
fn apply_global_shapes_outcome(image: &mut ImageReport, outcome: &GlobalShapesOutcome) {
    clear_global_shapes_fields(image);
    match outcome {
        GlobalShapesOutcome::Success(report) => apply_global_shapes_success(image, report),
        GlobalShapesOutcome::Failure(reason) => {
            image.global_shapes_error = Some(reason.clone());
        }
    }
}

/// Re-apply every retained `global_shapes` outcome onto `report_images` by
/// label. Called from `DispatchPass2` after every point that rebuilds the
/// `decompile` stage's `ImageReport`s (see `GlobalShapesOutcome`'s doc
/// comment for why that rebuild otherwise discards this data). A label
/// absent from `outcomes` (no code image, or the whole stage was skipped) is
/// left untouched — `report_images` is always a fresh rebuild at the call
/// site, so its `global_shapes_*` fields are already `None` there.
fn reapply_global_shapes_outcomes(
    report_images: &mut [ImageReport],
    outcomes: &HashMap<String, GlobalShapesOutcome>,
) {
    for image in report_images {
        if let Some(outcome) = outcomes.get(&image.image) {
            apply_global_shapes_outcome(image, outcome);
        }
    }
}

fn global_shapes_stage_output(
    completed: usize,
    eligible: usize,
    totals: &global_shapes::GlobalShapesReport,
) -> String {
    format!(
        "images/*/decompiled/global_shapes.json (completed={completed}/{eligible}, inferred={}, no_evidence={}, conflicting={}, observations={}, ghidra_quarantined={}, thumb_quarantined={}, quarantine_errors={}, decode_failures={}, state_barriers={})",
        totals.inferred,
        totals.no_evidence,
        totals.conflicting,
        totals.observations,
        totals.ghidra_quarantined,
        totals.thumb_quarantined,
        totals.quarantine_errors,
        totals.decode_failures,
        totals.state_barriers,
    )
}

fn add_global_shapes_totals(
    totals: &mut global_shapes::GlobalShapesReport,
    report: &global_shapes::GlobalShapesReport,
) {
    totals.inferred += report.inferred;
    totals.no_evidence += report.no_evidence;
    totals.conflicting += report.conflicting;
    totals.observations += report.observations;
    totals.ghidra_quarantined += report.ghidra_quarantined;
    totals.thumb_quarantined += report.thumb_quarantined;
    totals.quarantine_errors += report.quarantine_errors;
    totals.decode_failures += report.decode_failures;
    totals.state_barriers += report.state_barriers;
}

/// Record `report` as the single `global_shapes` stage entry: replace any
/// earlier entry from a previous sweep in place (keeping its list position),
/// or push when none exists. The normal route runs the stage twice — the
/// first sweep (pre-pass-2, feeding `derive_global_types_maps`) and the final
/// re-commit after pass 2 / `thumb_enrich_post_pass2` / `symbolicate_finalize`
/// rewrite the sidecar's hashed inputs — and the report must carry exactly
/// one entry reflecting the FINAL sweep's totals.
fn record_global_shapes_stage(stages: &mut Vec<StageReport>, report: StageReport) {
    match stages
        .iter()
        .rposition(|stage| stage.stage == "global_shapes")
    {
        Some(pos) => stages[pos] = report,
        None => stages.push(report),
    }
}

/// Runs the `global_shapes` sweep and returns every image's retained
/// [`GlobalShapesOutcome`] (keyed by label) alongside recording the sweep's
/// stage report in `stages` — replacing any earlier `global_shapes` entry in
/// place, so a normal-route caller may re-run the stage after a later input
/// rewrite and the final sweep's numbers become the committed truth (see
/// `record_global_shapes_stage`). The retained outcomes let a caller
/// re-apply the report-field patch after a later rebuild — see
/// `GlobalShapesOutcome` and `reapply_global_shapes_outcomes`.
fn run_global_shapes_stage_with(
    stages: &mut Vec<StageReport>,
    images_dir: &Path,
    manifest_path: &Path,
    current_results: &[decompile::ImageResult],
    mut run_image: impl for<'a> FnMut(
        &global_shapes::RunRequest<'a>,
    ) -> Result<global_shapes::GlobalShapesReport>,
) -> HashMap<String, GlobalShapesOutcome> {
    let Some(decompile_pos) = stages.iter().rposition(|stage| stage.stage == "decompile") else {
        record_global_shapes_stage(
            stages,
            StageReport::skipped("global_shapes", "no code image"),
        );
        return HashMap::new();
    };
    if stages[decompile_pos].images.is_empty() {
        record_global_shapes_stage(
            stages,
            StageReport::skipped("global_shapes", "no code image"),
        );
        return HashMap::new();
    }

    let started = Instant::now();
    let eligible = stages[decompile_pos].images.len();
    // Currentness binds from these post-globals ImageResults by label — see
    // `current_global_shapes_run`'s doc comment for why the stage-report
    // ImageReports cannot serve. A stage-report image with no matching
    // ImageResult fails closed below ("missing current image result").
    let current_by_label: HashMap<&str, &decompile::ImageResult> = current_results
        .iter()
        .map(|result| (result.label.as_str(), result))
        .collect();
    let mut completed = 0usize;
    let mut totals = global_shapes::GlobalShapesReport {
        inferred: 0,
        no_evidence: 0,
        conflicting: 0,
        observations: 0,
        ghidra_quarantined: 0,
        thumb_quarantined: 0,
        quarantine_errors: 0,
        decode_failures: 0,
        state_barriers: 0,
        interprocedural_dropped: 0,
    };
    let mut errors: Vec<(String, String)> = Vec::new();
    let mut outcomes: HashMap<String, GlobalShapesOutcome> = HashMap::new();

    for image in &mut stages[decompile_pos].images {
        clear_global_shapes_fields(image);
        let label = image.image.clone();
        let Some(result) = current_by_label.get(label.as_str()) else {
            let reason = record_global_shapes_failure(image, "missing current image result".into());
            outcomes.insert(label.clone(), GlobalShapesOutcome::Failure(reason.clone()));
            errors.push((label, reason));
            continue;
        };
        // Unanimously-opaque images never ran Ghidra: no inventory, no
        // `globals.json`, no sidecar to commit. The fields were just cleared
        // above; skip quietly (nothing was recovered, nothing is stale).
        if matches!(result.outcome, ImageOutcome::SkippedOpaque(_)) {
            continue;
        }
        let current = match current_global_shapes_run(result) {
            Ok(current) => current,
            Err(reason) => {
                let reason = record_global_shapes_failure(image, reason);
                outcomes.insert(label.clone(), GlobalShapesOutcome::Failure(reason.clone()));
                errors.push((label, reason));
                continue;
            }
        };
        let image_dir = images_dir.join(&label);
        let request = global_shapes::RunRequest {
            image_dir: &image_dir,
            image_label: &label,
            manifest_path,
            expected_ghidra_records: current.ghidra_records,
            expected_ghidra_accepted: current.ghidra_accepted,
            expected_ghidra_quarantined: current.ghidra_quarantined,
            expected_thumb_substantial: current.thumb_substantial,
            expected_thumb_accepted: current.thumb_accepted,
            expected_thumb_quarantined: current.thumb_quarantined,
            expected_recovered_globals: current.recovered,
        };
        match run_image(&request) {
            Ok(report) => {
                apply_global_shapes_success(image, &report);
                add_global_shapes_totals(&mut totals, &report);
                completed += 1;
                outcomes.insert(label, GlobalShapesOutcome::Success(report));
            }
            Err(error) => {
                let reason = record_global_shapes_failure(image, error.to_string());
                outcomes.insert(label.clone(), GlobalShapesOutcome::Failure(reason.clone()));
                errors.push((label, reason));
            }
        }
    }

    let error = if errors.is_empty() {
        None
    } else {
        Some(
            errors
                .into_iter()
                .map(|(label, reason)| format!("{label}: {reason}"))
                .collect::<Vec<_>>()
                .join("; "),
        )
    };
    record_global_shapes_stage(
        stages,
        StageReport {
            stage: "global_shapes",
            status: if error.is_some() { "failed" } else { "ok" },
            output: Some(global_shapes_stage_output(completed, eligible, &totals)),
            reason: None,
            error,
            images: Vec::new(),
            duration_ms: started.elapsed().as_millis(),
        },
    );
    outcomes
}

fn run_global_shapes_stage(
    stages: &mut Vec<StageReport>,
    images_dir: &Path,
    manifest_path: &Path,
    current_results: &[decompile::ImageResult],
) -> HashMap<String, GlobalShapesOutcome> {
    run_global_shapes_stage_with(
        stages,
        images_dir,
        manifest_path,
        current_results,
        global_shapes::run_image,
    )
}

/// Record global preparation without exposing a normal-route intermediate
/// image snapshot. The disabled route may refresh here because application is
/// conclusively uninvoked; the normal route must wait for its pass-2 outcome.
fn record_globals_stage(
    stages: &mut Vec<StageReport>,
    outcome: GlobalsStageOutcome,
    images: &[decompile::ImageResult],
    application_uninvoked: bool,
) -> HashMap<String, PreparedGlobalMap> {
    stages.push(outcome.stage);
    if application_uninvoked {
        refresh_decompile_stage_images(stages, images);
    }
    outcome.maps
}

/// Build the per-image symbol map from pass-1 outputs and write each to
/// `<out>/ghidra/symbol_maps/<label>.json`. Returns `(successes, errors)`:
/// each success is `(label, PreparedFunctionMap)`; each error is `(label,
/// message)`. Surfaces
/// I/O / parse failures (token DB, build_map, the v3 map write) so the caller
/// can distinguish "no symbols recovered" from "stage errored" — the previous
/// all-`unwrap_or_default` / `.is_ok()` shape silently swallowed real failures
/// into a benign-looking `symbol_map: skipped`.
///
/// Ordering is load-bearing: this runs at the `symbol_map` stage, before
/// `globals.json` exists, so `symbolicate::build_map`'s string-ref tier is
/// inert here and none of its guesses land in this stage's output — which is
/// exactly what `ApplySymbols.java` (Ghidra pass 2) consumes as input. Moving
/// this call to after the globals stage would silently start baking
/// string-ref guesses into Ghidra as `ANALYSIS`-source names.
fn build_and_write_symbol_maps(
    out: &Path,
    images_dir: &Path,
    token_db: &Path,
    manifest: &Path,
    exceptions: &HashMap<String, TerminalExceptionMap>,
    pal: &HashMap<String, TerminalPalMap>,
) -> SymbolMapsResult {
    let mut errors: Vec<(String, String)> = Vec::new();
    let tokens = if token_db.exists() {
        match std::fs::read(token_db)
            .map_err(|e| e.to_string())
            .and_then(|b| crate::tokens::parse(&b).map_err(|e| e.to_string()))
        {
            Ok(db) => symbolicate::token_map(&db),
            Err(msg) => {
                errors.push((
                    "<token_db>".to_string(),
                    format!("failed to load token db {}: {msg}", token_db.display()),
                ));
                HashMap::new()
            }
        }
    } else {
        HashMap::new()
    };
    let maps_dir = out.join("ghidra").join("symbol_maps");
    if let Err(e) = std::fs::create_dir_all(&maps_dir) {
        // Without the maps dir we can't write anything; record once and bail.
        errors.push(("<maps_dir>".into(), format!("create_dir_all: {e}")));
        return (HashMap::new(), errors);
    }
    let mut out_maps = HashMap::new();
    let entries = match std::fs::read_dir(images_dir) {
        Ok(e) => e,
        Err(e) => {
            errors.push((
                "<images_dir>".into(),
                format!("read_dir {}: {e}", images_dir.display()),
            ));
            return (out_maps, errors);
        }
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        let Some(label) = dir.file_name().and_then(|n| n.to_str()).map(str::to_string) else {
            continue;
        };
        if !dir.join("decompiled").join("functions.json").exists() {
            continue;
        }
        let map_path = maps_dir.join(format!("{label}.json"));
        // The PAL context comes from the explicit terminal state validated
        // against the terminal raw/scatter bytes — never from the existence
        // of a stale `pal_tasks/` directory. Images without a present map
        // bind identity `none` and null PAL hashes.
        let bundle = symbolicate::prepare_pass2_symbol_map(
            &map_path,
            &dir,
            &label,
            &tokens,
            manifest,
            exceptions.get(&label).map(|terminal| &terminal.context),
            pal.get(&label).map(|terminal| &terminal.context),
        );
        match bundle {
            Ok(bundle) => {
                let (prepared, validation_error) =
                    prepare_function_map(&label, &dir, &map_path, bundle);
                if let Some(error) = validation_error {
                    errors.push((label.clone(), error));
                }
                out_maps.insert(label, prepared);
            }
            Err(e) => {
                errors.push((label.clone(), format!("build_map: {e}")));
            }
        }
    }
    (out_maps, errors)
}

/// Exhaustive pipeline into one per-image tree. Ghidra and radare2 are required;
/// configured Rizin fallback is also probed first. Best-effort across stages;
/// writes `report.json`; `Err` if any stage failed.
pub fn run(img: &Path, opts: &Opts, out: &Path) -> Result<PathBuf> {
    // 1. Preflight every required or configured tool before anything is written.
    let (headless, thumb_tools) = preflight(
        decompile::find_headless(opts.ghidra_home.as_deref()).map(|g| g.headless),
        crate::thumb_analysis::discover_radare2(),
        opts.rizin_fallback,
        crate::thumb_analysis::discover_rizin,
    )?;
    std::fs::create_dir_all(out)?;
    let mut stages: Vec<StageReport> = Vec::new();
    let mut modem_label: Option<String> = None;

    // 2. Extract.
    let t = Instant::now();
    match pipeline::extract(img, out, !opts.no_verify) {
        Ok(_) => {
            let _ = std::fs::remove_dir_all(out.join("modem.bin.split")); // superseded by images/
            stages.push(StageReport::ok(
                "extract",
                "manifest.json",
                t.elapsed().as_millis(),
            ));
            modem_label = manifest::read_fbpk_name(&out.join("manifest.json"))
                .as_deref()
                .and_then(model::modem_generation);
        }
        Err(e) => {
            stages.push(StageReport::failed(
                "extract",
                e.to_string(),
                t.elapsed().as_millis(),
            ));
            return finalize(
                out,
                img,
                opts,
                &headless,
                &thumb_tools,
                stages,
                modem_label.clone(),
                // These early returns precede the prune stage.
                false,
            ); // nothing to analyze
        }
    }
    let rootfs = match rootfs_image_dir(out) {
        Ok(p) => p,
        Err(e) => {
            stages.push(StageReport::failed("locate_rootfs", e.to_string(), 0));
            return finalize(
                out,
                img,
                opts,
                &headless,
                &thumb_tools,
                stages,
                modem_label.clone(),
                false,
            );
        }
    };
    let modem_bin = rootfs.join("modem.bin");
    let images_dir = out.join("images");

    // 3. Decompile pass 1 (analyze + inventory + initial decompiled.c) into
    //    out/ghidra, then marshal into per-image folders.
    let t = Instant::now();
    let ghidra_dir = out.join("ghidra");
    let dopts = decompile::Opts {
        run: true,
        image: None,
        ghidra_home: opts.ghidra_home.clone(),
        processor: opts.processor.clone(),
        no_thumb_decompile: opts.no_thumb_decompile,
        rizin_fallback: opts.rizin_fallback,
        tighten_wall_clock_budget_override: opts.tighten_wall_clock_budget_override,
        no_skip_opaque: opts.no_skip_opaque,
    };
    let mut pass1_report = match run_decompile_report(&modem_bin, &dopts, &ghidra_dir, &thumb_tools)
    {
        Ok(mut rep) => {
            let mut image_reports = Vec::new();
            let mut marshal_err = None;
            let mut pal_tally = PalMarshalTally::default();
            let mut exception_tally = ExceptionMarshalTally::default();
            let mut exception_absent = 0usize;
            let mut exception_errors = Vec::new();
            // The terminal artifact stages share this marshal-loop clock;
            // neither duplicates the decompile stage's pass-1 duration.
            let pal_started = Instant::now();
            for index in 0..rep.images.len() {
                // A rejected export is as unusable as a failed Ghidra run, so
                // its runtime scatter and PAL task state stay unmanaged
                // either way — currentness is explicit state, never artifact
                // existence.
                let runtime_state = explicit_runtime_state(&rep, &rep.images[index]);
                let exception_scatter_state = rep.runtime_scatter_state(&rep.images[index].label);
                let export_current = rep.export_is_current(&rep.images[index].label);
                let ir = &mut rep.images[index];
                let marshal_stages = match marshal_image_stages(
                    &ghidra_dir,
                    &images_dir,
                    &ir.label,
                    export_current,
                    &runtime_state,
                    exception_scatter_state,
                    ir.image_start,
                ) {
                    Ok(stages) => stages,
                    Err(error) => {
                        let reason = error.to_string();
                        record_exception_marshal_status(
                            ir,
                            &ExceptionMarshalStatus::Failed(format!(
                                "pass-1 marshal stopped before exception commit: {reason}"
                            )),
                        );
                        exception_errors.push((ir.label.clone(), reason.clone()));
                        marshal_err = Some(reason);
                        break;
                    }
                };
                record_exception_marshal_status(ir, &marshal_stages.exception);
                match marshal_stages.exception {
                    ExceptionMarshalStatus::Present => {
                        let decompile::RuntimeExceptionState::Present(map) =
                            &runtime_state.exception
                        else {
                            unreachable!("present marshal status requires present generation state")
                        };
                        if let Err(error) = exception_tally.record(map) {
                            exception_errors.push((ir.label.clone(), error.to_string()));
                        }
                    }
                    ExceptionMarshalStatus::Absent => exception_absent += 1,
                    ExceptionMarshalStatus::Unmanaged => exception_errors.push((
                        ir.label.clone(),
                        "current exception-root generation state is unmanaged".to_string(),
                    )),
                    ExceptionMarshalStatus::Failed(error) => {
                        exception_errors.push((ir.label.clone(), error));
                    }
                }
                if let Err(error) = marshal_stages.pal {
                    marshal_err.get_or_insert_with(|| error.to_string());
                    image_reports.push(ImageReport::from_result(ir));
                    continue;
                }
                if let decompile::RuntimeTaskState::Present(map) = &runtime_state.tasks
                    && let Err(e) = pal_tally.record(map)
                {
                    marshal_err.get_or_insert_with(|| e.to_string());
                    image_reports.push(ImageReport::from_result(ir));
                    continue;
                }
                image_reports.push(ImageReport::from_result(ir));
            }
            match marshal_err {
                None => {
                    stages.push(StageReport::decompile(
                        image_reports,
                        t.elapsed().as_millis(),
                    ));
                    stages.push(exception_roots_stage(
                        Some(&exception_tally),
                        exception_absent,
                        &exception_errors,
                        pal_started.elapsed().as_millis(),
                    ));
                    stages.push(pal_tasks_stage(
                        Some(&pal_tally),
                        pal_started.elapsed().as_millis(),
                    ));
                }
                Some(err) => {
                    stages.push(StageReport::failed(
                        "decompile",
                        format!("marshal: {err}"),
                        t.elapsed().as_millis(),
                    ));
                    stages.push(exception_roots_stage(
                        Some(&exception_tally),
                        exception_absent,
                        &exception_errors,
                        pal_started.elapsed().as_millis(),
                    ));
                    stages.push(StageReport::skipped("pal_tasks", "pass 1 marshal failed"));
                }
            }
            Some(rep)
        }
        Err(e) => {
            stages.push(StageReport::failed(
                "decompile",
                e.to_string(),
                t.elapsed().as_millis(),
            ));
            stages.push(exception_roots_stage(None, 0, &[], 0));
            // The failed decompile command owns the failure (e.g. malformed
            // PAL generation); the PAL stage defers to it.
            stages.push(pal_tasks_stage(None, 0));
            None
        }
    };

    // 3b. Phase 2 — thumb_enrich (pass 1). Pure-Rust pass over each image's
    //     pass-1 `decompiled.c` to populate `body_c` in `thumb_functions.json`.
    //     Skipped entirely when `--no-thumb-decompile` is set (Stage 10 wires
    //     the public flag; today it defaults to false). Mutates `pass1_report`
    //     in place so the counts flow into the pass-2 input.
    if opts.no_thumb_decompile {
        stages.push(StageReport::skipped("thumb_enrich", "--no-thumb-decompile"));
    } else if let Some(rep) = pass1_report.as_mut() {
        let enrich_started = Instant::now();
        let outcome = run_thumb_enrich_per_image(&mut rep.images, &images_dir);
        stages.push(thumb_enrich_stage(
            "thumb_enrich",
            outcome,
            enrich_started.elapsed().as_millis(),
        ));
        // Refresh the decompile stage's per-image reports with Phase 2 fields
        // (`thumb_decompiled` / `thumb_enrich_error`). Without this refresh,
        // the decompile StageReport carries the pre-enrich snapshot and the
        // Phase 2 headline metric is invisible in report.json — `thumb_enrich`
        // populated 80k+ body_c on production but the count never surfaced
        // (found during Phase 2.1 followup verification on a real `02_MAIN`
        // under `--no-symbol-pass`). Mirrors the post-pass-2 refresh below.
        refresh_decompile_stage_images(&mut stages, &rep.images);
    } else {
        // Pass 1 failed entirely (no pass1_report). Record explicit skipped
        // entries so the report shape stays predictable. The post-pass-2
        // enrich is also unreachable here; record it once. (When
        // --no-symbol-pass is also set, step 7 records thumb_enrich_post_pass2
        // with "--no-symbol-pass" — guard to avoid a duplicate entry.)
        stages.push(StageReport::skipped("thumb_enrich", "pass 1 failed"));
        if !opts.no_symbol_pass {
            stages.push(StageReport::skipped(
                "thumb_enrich_post_pass2",
                "pass 1 failed",
            ));
        }
    }

    // 3c. DBT debug-trace catalog + reference attribution — MAIN only,
    //     between thumb_enrich and the source tree: exact DBT record
    //     evidence (file + line) outranks adjacency-derived attribution
    //     for the same functions, so it is recorded before source
    //     attribution consumes the inventories.
    let dbt_outcomes = run_debug_traces_stages(&mut stages, out, &images_dir);
    // Patch the counters onto the decompile stage's MAIN row; every later
    // rebuild of those rows must re-apply them (see `DbtCounters`).
    reapply_dbt_outcomes(decompile_stage_images_mut(&mut stages), &dbt_outcomes);

    // 4. Source tree — MAIN image only. The MAIN split-dir name is
    //    model-dependent ("02_MAIN" on mustang/S5400, "01_MAIN" on cheetah/S5300);
    //    the TOC name "MAIN" is the stable key, so locate the `*_MAIN` split dir.
    if let Some(main_name) = main_image_dir_name(&images_dir).as_deref() {
        let main_img_dir = images_dir.join(main_name);
        let main_bin = main_img_dir.join(format!("{main_name}.bin"));
        if main_bin.exists() {
            let st_out = main_img_dir.join("source_tree");
            let st_opts = source_tree::Opts {
                no_attribution: false,
                gap: 4,
                shared_pct: 0.05,
                min_run: 3,
                modem_label: modem_label.clone(),
            };
            run_stage(
                &mut stages,
                "source_tree",
                &format!("images/{main_name}/source_tree"),
                || source_tree::run(&main_bin, &st_out, &st_opts),
            );
        } else {
            stages.push(StageReport::skipped("source_tree", "no MAIN image binary"));
        }

        let source_tree_dir = main_img_dir.join("source_tree");
        let decompiled_dir = main_img_dir.join("decompiled");
        if source_tree_dir.join("manifest.json").exists()
            && source_tree_dir.join("tree").is_dir()
            && decompiled_dir.join("functions.json").exists()
            && decompiled_dir.join("decompiled.c").exists()
        {
            run_stage(
                &mut stages,
                "source_attribution",
                &format!("images/{main_name}/source_tree/recovered_index.json"),
                || {
                    let raw = std::fs::read(&main_bin)?;
                    let load_address =
                        manifest::load_addr_for_image(&out.join("manifest.json"), main_name)?
                            .ok_or_else(|| {
                                Error::Serialize(format!("load_addr missing for {main_name}"))
                            })?;
                    let load_address = u32::try_from(load_address).map_err(|_| {
                        Error::Serialize(format!("load_addr for {main_name} does not fit u32"))
                    })?;
                    let runtime = crate::runtime_image::RuntimeImage::for_image_dir(
                        &raw,
                        load_address,
                        &main_img_dir,
                    )?;
                    // Fail closed on a tampered dbt artifact: an invalid
                    // references.json fails the stage rather than being
                    // silently ignored; an absent one attributes nothing.
                    let dbt = crate::dbt_traces::exact::load_exact_index(&main_img_dir)?;
                    recover_source::run(
                        &source_tree_dir,
                        &decompiled_dir,
                        &runtime,
                        &source_tree_dir.join("recovered_index.json"),
                        &recover_source::Opts::default(),
                        dbt.as_ref(),
                    )
                },
            );
        } else {
            stages.push(StageReport::skipped(
                "source_attribution",
                "no MAIN source tree or decompiler artifacts",
            ));
        }
    } else {
        stages.push(StageReport::skipped("source_tree", "no MAIN image"));
        stages.push(StageReport::skipped("source_attribution", "no MAIN image"));
    }

    // 5. decode_tokens — MOVED EARLIER (Phase 1) so the symbol map can use it.
    let token_db = rootfs.join("pw_token_db");
    if token_db.exists() {
        run_stage(&mut stages, "decode_tokens", "tokens", || {
            tokens::run(&token_db, &out.join("tokens"))
        });
    } else {
        stages.push(StageReport::skipped("decode_tokens", "no pw_token_db"));
    }

    // 6. Build the per-image symbol map from pass-1 outputs + attribution +
    //    tokens. Writes <out>/ghidra/symbol_maps/<label>.json per image.
    //    First resolve terminal exception-root and PAL maps (normal route
    //    only). Their symbol-map blocks and pass-2 arguments bind identities
    //    validated against terminal raw/scatter bytes; a terminal manifest
    //    the strict reader rejects fails the symbol-map stage rather than
    //    binding unauthenticated state.
    let mut terminal_exception_maps: HashMap<String, TerminalExceptionMap> = HashMap::new();
    let mut terminal_pal_maps: HashMap<String, TerminalPalMap> = HashMap::new();
    let t = Instant::now();
    let (mut function_maps, symbol_map_errors) = if opts.no_symbol_pass {
        (HashMap::new(), Vec::new())
    } else {
        let (exception_maps, exception_errors, pal_maps, pal_errors) = match pass1_report.as_ref() {
            Some(report) => {
                let (exception_maps, exception_errors) =
                    load_terminal_exception_maps(&images_dir, report, &ghidra_dir);
                let (pal_maps, pal_errors) =
                    load_terminal_pal_maps(&images_dir, report, &ghidra_dir);
                (exception_maps, exception_errors, pal_maps, pal_errors)
            }
            None => (HashMap::new(), Vec::new(), HashMap::new(), Vec::new()),
        };
        if let Some(report) = pass1_report.as_mut() {
            record_terminal_exception_errors(report, &exception_errors);
        }
        terminal_exception_maps = exception_maps;
        terminal_pal_maps = pal_maps;
        let (maps, errors) = build_and_write_symbol_maps(
            out,
            &images_dir,
            &token_db,
            &out.join("manifest.json"),
            &terminal_exception_maps,
            &terminal_pal_maps,
        );
        let mut errors = errors;
        for (label, error) in exception_errors {
            errors.push((label, error));
        }
        for (label, error) in pal_errors {
            errors.push((label, error));
        }
        (maps, errors)
    };
    if opts.no_symbol_pass {
        stages.push(StageReport::skipped("symbol_map", "--no-symbol-pass"));
    } else {
        stages.push(symbol_map_stage(
            &function_maps,
            symbol_map_errors,
            t.elapsed().as_millis(),
        ));
    }
    if let Some(report) = pass1_report.as_mut() {
        retain_pass2_creation_plans(&mut report.images, &function_maps);
    }

    // Phase 3.0 globals options are route-independent.
    let globals_opts = globals::GlobalsOpts {
        include_provisional: opts.globals_provisional,
        k_arm: opts.globals_k_arm.unwrap_or(globals::K_ARM),
        k_thumb: opts.globals_k_thumb.unwrap_or(globals::K_THUMB),
    };

    let mut function_inputs = None;
    let mut prepared_global_maps = HashMap::new();
    // Captured from `RunGlobalShapes` (which runs before `DispatchPass2` on
    // the normal route) and re-applied inside `DispatchPass2` after every
    // rebuild of the `decompile` stage's `ImageReport`s — see
    // `GlobalShapesOutcome`'s doc comment for why the rebuild otherwise
    // discards `RunGlobalShapes`'s report-field patch. On the normal route
    // the later `RefreshGlobalShapes` step replaces this map wholesale with
    // the FINAL sweep's outcomes.
    let mut global_shapes_outcomes: HashMap<String, GlobalShapesOutcome> = HashMap::new();
    // Threading from `DispatchPass2` to the follow-on `ApplyGlobalTypes`
    // step: the pre-pass-2 derived type maps / ineligible counts, and the
    // pass-2 duration (mirrored into each branch's `globals_apply_stage`
    // entry, then reused by `global_types_apply_stage`).
    let mut global_types_maps: HashMap<String, decompile::PreparedPass2Map> = HashMap::new();
    let mut global_types_ineligible: HashMap<String, usize> = HashMap::new();
    let mut pass2_elapsed_ms = 0u128;
    // Pass-1 ImageResults retained across `run_two_pass`'s by-value
    // consumption of `rep`: on the infrastructure-Err branch (pass 2
    // processed zero images) `pass1_report` ends up `None`, but Finalize
    // still rewrites the sidecar's hashed inputs, so `RefreshGlobalShapes`
    // must still re-run — binding currentness from these, since the pass-1
    // inventories remain the current truth when pass 2 never touched an
    // image. The clone precedes the `run_two_pass` match, so the `Ok(pass2)`
    // arm populates it too (unused there); it stays empty only when there is
    // no pass-1 report or pass 2 scheduled zero images.
    let mut retained_pass1_images: Vec<decompile::ImageResult> = Vec::new();
    orchestrate_symbol_route(opts.no_symbol_pass, |step| match step {
        SymbolRouteStep::PrepareNamesAndProjection => {
            function_inputs = Some(take_globals_function_inputs(&mut function_maps));
        }
        SymbolRouteStep::Finalize {
            rewrite_decompiled_c,
        } => {
            run_stage(
                &mut stages,
                "symbolicate_finalize",
                "images/*/decompiled/symbols.json",
                || {
                    symbolicate::run(
                        out,
                        &symbolicate::Opts {
                            token_db: token_db.exists().then(|| token_db.clone()),
                            rewrite_decompiled_c,
                        },
                    )
                },
            );
        }
        SymbolRouteStep::LoadFinalizedNames => {
            let recovered_names = pass1_report
                .as_ref()
                .map(|report| load_finalized_function_name_indexes(&images_dir, &report.images))
                .unwrap_or_default();
            function_inputs = Some(PreparedGlobalsFunctionInputs {
                recovered_names,
                evidence_names: HashMap::new(),
            });
        }
        SymbolRouteStep::RunGlobals(mode) => {
            let function_inputs = function_inputs
                .take()
                .expect("route prepares function inputs before globals");
            let active_images = pass1_report
                .as_mut()
                .map(|report| report.images.as_mut_slice())
                .unwrap_or(&mut []);
            let globals_outcome = run_globals_stage(
                active_images,
                &images_dir,
                &out.join("manifest.json"),
                &function_inputs,
                &globals_opts,
            );
            drop(function_inputs);
            let refresh_source = pass1_report
                .as_ref()
                .map(|report| report.images.as_slice())
                .unwrap_or(&[]);
            let application_uninvoked = mode == GlobalsRouteMode::RecordOnly;
            let maps = record_globals_stage(
                &mut stages,
                globals_outcome,
                refresh_source,
                application_uninvoked,
            );
            if application_uninvoked {
                // `record_globals_stage` just refreshed the decompile stage's
                // rows (application is conclusively uninvoked on this
                // route), which rebuilt them via `ImageReport::from_result`
                // and nulled the `dbt_*` counters patched before this route
                // ran — re-apply the retained outcome (see `DbtCounters`).
                reapply_dbt_outcomes(decompile_stage_images_mut(&mut stages), &dbt_outcomes);
                stages.push(StageReport::skipped("decompile_pass2", "--no-symbol-pass"));
                stages.push(globals_apply_stage(true, &HashMap::new(), None, 0));
                // No pass 2 on this route, so `derive_global_types_maps` never
                // runs and there is no ineligible map to patch; report_images
                // is irrelevant since `no_symbol_pass` short-circuits first.
                stages.push(global_types_apply_stage(
                    true,
                    opts.no_apply_global_types,
                    &HashMap::new(),
                    &HashMap::new(),
                    None,
                    &mut [],
                    0,
                ));
                stages.push(StageReport::skipped(
                    "thumb_enrich_post_pass2",
                    "--no-symbol-pass",
                ));
            } else {
                prepared_global_maps = maps;
            }
        }
        SymbolRouteStep::RunGlobalShapes => {
            let current_results = pass1_report
                .as_ref()
                .map(|report| report.images.as_slice())
                .unwrap_or(&[]);
            global_shapes_outcomes = run_global_shapes_stage(
                &mut stages,
                &images_dir,
                &out.join("manifest.json"),
                current_results,
            );
        }
        SymbolRouteStep::DispatchPass2 => {
            // Derive the strict `undefinedN` apply-map from `global_shapes.json`
            // (written by `RunGlobalShapes` above) before pass 2 runs, so
            // `ApplyGlobalTypes.java` has real input alongside `ApplyGlobals`.
            (global_types_maps, global_types_ineligible) = if opts.no_apply_global_types {
                (HashMap::new(), HashMap::new())
            } else {
                derive_global_types_maps(&images_dir, &ghidra_dir)
            };
            let inputs = prepare_pass2_inputs(
                &function_maps,
                &prepared_global_maps,
                &global_types_maps,
                &terminal_exception_maps,
                &terminal_pal_maps,
            );
            let scheduled_count = inputs.len();
            drop(std::mem::take(&mut function_maps));

            if let Some(rep) = pass1_report.take() {
                let fallback_images: Vec<ImageReport> =
                    rep.images.iter().map(ImageReport::from_result).collect();
                let pass2_started = Instant::now();
                if scheduled_count == 0 {
                    stages.push(decompile_pass2_stage(0, 0, Vec::new(), 0));
                    stages.push(globals_apply_stage(
                        false,
                        &prepared_global_maps,
                        Some(&rep.images),
                        0,
                    ));
                    pass1_report = Some(rep);
                } else {
                    // Retain before `run_two_pass` consumes `rep` by value —
                    // see `retained_pass1_images`'s declaration for why the
                    // Err branch below still needs these.
                    retained_pass1_images = rep.images.clone();
                    match decompile::run_two_pass(rep, &dopts, &ghidra_dir, &inputs) {
                        Ok(mut pass2) => {
                            let (refreshed_count, errors) = refresh_pass2_outputs(
                                &pass2.outcomes,
                                &mut pass2.report.images,
                                &ghidra_dir,
                                &images_dir,
                            );
                            let elapsed = pass2_started.elapsed().as_millis();
                            pass2_elapsed_ms = elapsed;
                            stages.push(decompile_pass2_stage(
                                scheduled_count,
                                refreshed_count,
                                errors,
                                elapsed,
                            ));
                            stages.push(globals_apply_stage(
                                false,
                                &prepared_global_maps,
                                Some(&pass2.report.images),
                                elapsed,
                            ));
                            pass1_report = Some(pass2.report);
                        }
                        Err(error) => {
                            let elapsed = pass2_started.elapsed().as_millis();
                            pass2_elapsed_ms = elapsed;
                            stages.push(decompile_pass2_stage(
                                scheduled_count,
                                0,
                                vec![("<pass2>".to_string(), error.to_string())],
                                elapsed,
                            ));
                            install_decompile_stage_image_snapshot(&mut stages, fallback_images);
                            stages.push(globals_apply_stage(
                                false,
                                &prepared_global_maps,
                                None,
                                elapsed,
                            ));
                        }
                    }
                }
            } else {
                let errors = if scheduled_count > 0 {
                    vec![(
                        "<pass2>".to_string(),
                        "missing pass-1 decompile report".to_string(),
                    )]
                } else {
                    Vec::new()
                };
                stages.push(decompile_pass2_stage(scheduled_count, 0, errors, 0));
                stages.push(globals_apply_stage(false, &prepared_global_maps, None, 0));
            }

            if let Some(report) = pass1_report.as_mut() {
                if opts.no_thumb_decompile {
                    stages.push(StageReport::skipped(
                        "thumb_enrich_post_pass2",
                        "--no-thumb-decompile",
                    ));
                } else {
                    let enrich_started = Instant::now();
                    let outcome = run_thumb_enrich_per_image(&mut report.images, &images_dir);
                    stages.push(thumb_enrich_stage(
                        "thumb_enrich_post_pass2",
                        outcome,
                        enrich_started.elapsed().as_millis(),
                    ));
                }
                refresh_decompile_stage_images(&mut stages, &report.images);
            }

            // This call must run after every rebuild of
            // `stages[decompile_pos].images` above — the final
            // `refresh_decompile_stage_images` just above, but also the
            // `Err(error)` branch's earlier `install_decompile_stage_image_snapshot`
            // (installs `fallback_images`, reached when `pass1_report` stays
            // `None` and the refresh above never runs). Both rebuilds go
            // through `ImageReport::from_result`, which always nulls the
            // nine `global_shapes_*` fields, so patching them any earlier
            // would be silently discarded (this exact bug shipped for
            // `global_shapes_*` in the shape-stage reorder — RunGlobalShapes's
            // in-place patch ran before DispatchPass2 existed to refresh over
            // it — until this fix; see `GlobalShapesOutcome`'s doc comment).
            // Placing it once, unconditionally, here — after every branch
            // above has run, regardless of which one fired — fixes every
            // rebuild site in one place instead of duplicating a fix-up per
            // branch. The five `global_types_*` fields get the same treatment
            // one step later, in `ApplyGlobalTypes`.
            reapply_global_shapes_outcomes(
                decompile_stage_images_mut(&mut stages),
                &global_shapes_outcomes,
            );
            // Same hazard, same fix: the `dbt_*` counters were patched
            // before this route ran (step 3c), and every DispatchPass2
            // rebuild above nulls them along with the shape fields.
            reapply_dbt_outcomes(decompile_stage_images_mut(&mut stages), &dbt_outcomes);
        }
        SymbolRouteStep::RefreshGlobalShapes => {
            // Re-run the stage after the route's LAST rewrite of the
            // sidecar's hashed inputs — Finalize's symbolicate pass just
            // stamped both functions.json and thumb_functions.json (on top
            // of DispatchPass2's earlier pass-2 refresh and
            // thumb_enrich_post_pass2 rewrites) — so the re-committed
            // sidecar (and the single stage entry, replaced in place)
            // hashes the tree's FINAL inputs; nothing after this point
            // writes a hashed input (decode_rf/hardware_config write only
            // under rf/). Always runs: Finalize rewrites inputs on every
            // normal-route branch, including the pass-2 infrastructure
            // failure where `pass1_report` is `None` — currentness binds
            // there from the pass-1 ImageResults retained by DispatchPass2
            // (pass 2 processed zero images, so the pass-1 inventories are
            // still the current truth). The returned outcome map replaces
            // the first sweep's so the report fields reflect this FINAL run.
            let current_results = pass1_report
                .as_ref()
                .map(|report| report.images.as_slice())
                .unwrap_or(&retained_pass1_images);
            global_shapes_outcomes = run_global_shapes_stage(
                &mut stages,
                &images_dir,
                &out.join("manifest.json"),
                current_results,
            );
        }
        SymbolRouteStep::ApplyGlobalTypes => {
            // Reading `pass1_report` here (rather than threading a separate
            // captured value through each branch above) is deliberate: it is
            // `Some` in exactly the DispatchPass2 branches that passed
            // `Some(&images)` to `globals_apply_stage` (scheduled_count==0,
            // and Ok(pass2)), and `None` in exactly the branches that passed
            // `None` (run_two_pass Err, and no pass-1 report at all) — so it
            // already carries the right value per branch. Must run after
            // every DispatchPass2 rebuild of the decompile stage's
            // `ImageReport`s: those rebuilds null the five `global_types_*`
            // fields this stage patches back in. Pure reporting — it writes
            // no file, so the later `RefreshGlobalShapes` re-commit (whose
            // in-place patch touches only the nine disjoint
            // `global_shapes_*` fields) cannot disturb it.
            let post_dispatch_images = pass1_report.as_ref().map(|report| report.images.as_slice());
            let global_types_stage = global_types_apply_stage(
                false,
                opts.no_apply_global_types,
                &global_types_maps,
                &global_types_ineligible,
                post_dispatch_images,
                decompile_stage_images_mut(&mut stages),
                pass2_elapsed_ms,
            );
            stages.push(global_types_stage);
        }
    });

    // Remaining post-symbol stages: the RF and hardware decoders. Global
    // shape recovery no longer lives here — both symbol routes now run it
    // via `SymbolRouteStep::RunGlobalShapes` above (before pass 2 on the
    // normal route, at the end on `--no-symbol-pass`). Both symbol routes
    // share this exact post-symbol sequence.
    let rf_dir = out.join("rf_cfg_decompressed");
    let hwcfg_path = rootfs.join("hardware_config.json");
    let rf_present = std::fs::read_dir(&rf_dir)
        .map(|mut it| it.next().is_some())
        .unwrap_or(false);

    orchestrate_post_symbol_route(|step| match step {
        PostSymbolStep::DecodeRf => {
            if hwcfg_path.exists() && rf_present {
                run_stage(&mut stages, "decode_rf", "rf/decoded", || {
                    decode_rf::run(&rf_dir, &hwcfg_path, &out.join("rf").join("decoded"))
                });
            } else {
                stages.push(StageReport::skipped(
                    "decode_rf",
                    "no hardware_config.json or no RF_CFG_* blobs",
                ));
            }
        }
        PostSymbolStep::HardwareConfig => {
            if hwcfg_path.exists() {
                let rf_arg = rf_present.then(|| (rf_dir.clone(), "rf_cfg_decompressed"));
                run_stage(&mut stages, "hardware_config", "rf/hwcfg_summary", || {
                    hwcfg::run(
                        &hwcfg_path,
                        rf_arg.as_ref().map(|(p, l)| (p.as_path(), *l)),
                        &out.join("rf").join("hwcfg_summary"),
                    )
                });
            } else {
                stages.push(StageReport::skipped(
                    "hardware_config",
                    "no hardware_config.json",
                ));
            }
        }
    });

    // 6. Prune (opt-in) then write the report.
    let pruned = run_prune_stage(&mut stages, opts.prune, || prune(out));
    finalize(
        out,
        img,
        opts,
        &headless,
        &thumb_tools,
        stages,
        modem_label.clone(),
        pruned,
    )
}

/// Run the opt-in leaves-only sweep, recording a failed stage when it does not
/// complete. Returns whether the tree was actually pruned, so `report.json`
/// reports successful state rather than intent.
fn run_prune_stage(
    stages: &mut Vec<StageReport>,
    requested: bool,
    prune: impl FnOnce() -> Result<()>,
) -> bool {
    if !requested {
        return false;
    }
    match prune() {
        Ok(()) => true,
        Err(error) => {
            stages.push(StageReport::failed("prune", error.to_string(), 0));
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_symbol(
        address: &str,
        arch: &'static str,
        name: Option<&str>,
        tier: symbolicate::Tier,
    ) -> symbolicate::Symbol {
        symbolicate::Symbol {
            address: address.to_string(),
            arch,
            tool: if arch == "thumb" {
                crate::recover_source::Tool::Radare2
            } else {
                crate::recover_source::Tool::Ghidra
            },
            owner: if arch == "thumb" {
                crate::execution_ranges::FunctionOwner::Legacy {
                    producer: crate::recover_source::Tool::Radare2,
                }
            } else {
                crate::execution_ranges::FunctionOwner::Ghidra
            },
            execution_blake3: None,
            decode_ranges: Vec::new(),
            name_conflicts: Vec::new(),
            original_name: format!("original_{address}"),
            name: name.map(str::to_string),
            tier,
            evidence: Vec::new(),
            annotations: Vec::new(),
        }
    }

    fn analyzed_image(label: &str) -> decompile::ImageResult {
        decompile::ImageResult {
            label: label.into(),
            outcome: ImageOutcome::Analyzed(1),
            classification: Some("not_opaque"),
            thumb_functions: None,
            thumb_regions_requested: None,
            thumb_regions_succeeded: None,
            thumb_regions_failed: None,
            thumb_radare2_runs: None,
            thumb_rizin_runs: None,
            ghidra_execution_accepted: None,
            ghidra_execution_quarantined: None,
            thumb_execution_accepted: None,
            thumb_execution_quarantined: None,
            image_start: 0,
            image_len: 0,
            thumb_error: None,
            terminal_error: None,
            pass2_applied: None,
            pass2_creation_plan: None,
            pass2_thumb_names: None,
            pass2_error: None,
            thumb_decompiled: None,
            thumb_tighten_error: None,
            thumb_enrich_error: None,
            globals_error: None,
            globals_recovered: None,
            globals_applied: None,
            globals_apply_skipped: None,
            globals_apply_error: None,
            global_types_applied: None,
            global_types_apply_skipped: None,
            global_types_apply_error: None,
            globals_provisional: None,
            globals_provisional_suppressed: None,
            exception_state: decompile::RuntimeExceptionState::Unmanaged,
            exception_roots_applied: None,
            exception_error: None,
            pal_applied: None,
        }
    }

    fn runtime_state(
        scatter: decompile::RuntimeScatterState,
        tasks: decompile::RuntimeTaskState,
        exception: decompile::RuntimeExceptionState,
    ) -> decompile::RuntimeAnalysisState {
        decompile::RuntimeAnalysisState {
            scatter,
            exception,
            tasks,
        }
    }

    fn producer_identity(
        producer: crate::thumb_analysis::ThumbProducer,
        executable: &str,
        version: &str,
    ) -> crate::thumb_analysis::ProducerIdentity {
        crate::thumb_analysis::ProducerIdentity {
            producer,
            executable: executable.into(),
            version: version.into(),
            command: producer.command(),
        }
    }

    fn analysis_opts(rizin_fallback: bool) -> Opts {
        Opts {
            no_verify: false,
            prune: false,
            ghidra_home: None,
            processor: "ARM:LE:32:v7".into(),
            no_symbol_pass: false,
            no_thumb_decompile: false,
            rizin_fallback,
            tighten_wall_clock_budget_override: None,
            globals_provisional: false,
            globals_k_arm: None,
            globals_k_thumb: None,
            no_apply_global_types: false,
            no_skip_opaque: false,
        }
    }

    fn tagged_functions(name: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!([{
            "name": name,
            "primary_source": "default",
            "entry": "0x4000",
            "end": "0x4004",
            "size": 4,
            "decode_ranges": [{
                "isa":"arm",
                "start":"0x4000",
                "end":"0x4004",
                "blake3":"ec2bd03bf86b935fa34d71ad7ebb049f1f10f87d343e521511d8f9e6625620cd"
            }],
            "decode_range_errors": [],
            "data_refs": []
        }]))
        .unwrap()
    }

    #[test]
    fn image_report_serializes_skipped_opaque_outcome() {
        let mut image = analyzed_image("01_PSP");
        image.outcome = ImageOutcome::SkippedOpaque(crate::classify::classify(
            &crate::classify::test_uniform_blob(256 * 1024),
        ));
        image.classification = Some("opaque");
        let json = serde_json::to_value(ImageReport::from_result(&image)).unwrap();
        assert_eq!(json["status"], "skipped");
        assert_eq!(json["classification"], "opaque");
        assert_eq!(json["skipped_reason"], "opaque");
        assert!(json.get("functions").is_none());
        assert!(json.get("exit").is_none());
    }

    #[test]
    fn image_report_serializes_analyzed_opaque_classification() {
        // The escape hatch ran Ghidra anyway (--no-skip-opaque) on a
        // unanimously-opaque image: the row is analyzed but still labeled by
        // the battery verdict — the same measurement manifest.json records.
        let mut image = analyzed_image("01_PSP");
        image.outcome = ImageOutcome::Analyzed(0);
        image.classification = Some("opaque");
        let json = serde_json::to_value(ImageReport::from_result(&image)).unwrap();
        assert_eq!(json["status"], "analyzed");
        assert_eq!(json["classification"], "opaque");
        assert!(json.get("skipped_reason").is_none());
    }

    #[test]
    fn image_report_serializes_analyzed_classification() {
        let json =
            serde_json::to_value(ImageReport::from_result(&analyzed_image("02_MAIN"))).unwrap();
        assert_eq!(json["status"], "analyzed");
        assert_eq!(json["classification"], "not_opaque");
        assert!(json.get("skipped_reason").is_none());
        assert!(json["functions"].is_u64());
    }

    #[test]
    fn image_report_keeps_partial_thumb_success_analyzed() {
        let mut image = analyzed_image("02_MAIN");
        image.thumb_functions = Some(7);
        image.thumb_regions_requested = Some(3);
        image.thumb_regions_succeeded = Some(2);
        image.thumb_regions_failed = Some(1);
        image.thumb_radare2_runs = Some(1);
        image.thumb_rizin_runs = Some(1);

        let json = serde_json::to_value(ImageReport::from_result(&image)).unwrap();

        assert_eq!(
            json,
            serde_json::json!({
                "image": "02_MAIN",
                "status": "analyzed",
                "classification": "not_opaque",
                "functions": 1,
                "thumb_functions": 7,
                "thumb_regions_requested": 3,
                "thumb_regions_succeeded": 2,
                "thumb_regions_failed": 1,
                "thumb_radare2_runs": 1,
                "thumb_rizin_runs": 1
            })
        );
        assert!(json.get("thumb_error").is_none());
    }

    fn tagged_thumb_functions() -> Vec<u8> {
        br#"{
  "format": "pixel-modem-extractor-thumb-functions-v3",
  "producers": [
    {
      "id": "radare2",
      "executable": "/usr/bin/r2",
      "version": "radare2 6.1.4",
      "command": "aaa;aflj;pdfj @@f"
    }
  ],
  "regions": [
    {
      "start": "0x4000",
      "end": "0x4040",
      "attempts": [
        {
          "producer": "radare2",
          "status": "succeeded",
          "stdout": {
            "path": "thumb/00004000.radare2.stdout",
            "bytes": 64,
            "blake3": "0000000000000000000000000000000000000000000000000000000000000000"
          },
          "error": null
        }
      ],
      "function_runs": [
        {
          "producer": "radare2",
          "first_function": 0,
          "function_count": 1,
          "substantial": 1,
          "accepted": 1,
          "quarantined": 0
        }
      ]
    }
  ],
  "functions": [
    {
      "body": "0x4000: nop\n",
      "body_kind": "thumb_disassembly",
      "data_refs": [],
      "decode_range_errors": [],
      "decode_ranges": [
        {
          "end": "0x4008",
          "isa": "thumb",
          "start": "0x4000",
          "blake3": "71e0a99173564931c0b8acc52d2685a8e39c64dc52e3d02390fdac2a12b155cb"
        }
      ],
      "end": "0x4020",
      "entry": "0x4000",
      "name": "thumb_4000",
      "size": 32
    }
  ]
}"#
        .to_vec()
    }

    fn tagged_image(label: &str, with_thumb: bool) -> decompile::ImageResult {
        let mut image = analyzed_image(label);
        image.ghidra_execution_accepted = Some(1);
        image.ghidra_execution_quarantined = Some(0);
        image.image_start = 0x4000;
        image.image_len = 0x40;
        if with_thumb {
            image.thumb_functions = Some(1);
            image.thumb_execution_accepted = Some(1);
            image.thumb_execution_quarantined = Some(0);
        }
        image
    }

    fn prepared_test_map(name: &str, count: usize) -> decompile::PreparedPass2Map {
        let dir = PathBuf::from("target").join("pme_task8r_decompose_maps");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, name).unwrap();
        decompile::PreparedPass2Map::new(&path, NonZeroUsize::new(count).unwrap()).unwrap()
    }

    fn prepared_symbol_test_map(
        name: &str,
        label: &str,
        count: usize,
    ) -> decompile::PreparedSymbolPass2Map {
        let dir = PathBuf::from("target").join("pme_task11_decompose_maps");
        std::fs::create_dir_all(&dir).unwrap();
        let map_path = dir.join(format!("{name}-map.json"));
        let functions_path = dir.join(format!("{name}-functions.json"));
        let image_path = dir.join(format!("{name}-image.bin"));
        std::fs::write(&map_path, name.as_bytes()).unwrap();
        std::fs::write(&functions_path, b"functions").unwrap();
        std::fs::write(&image_path, b"image").unwrap();
        decompile::PreparedSymbolPass2Map::new(
            &map_path,
            &functions_path,
            &image_path,
            label,
            count,
            count,
            Vec::new(),
        )
        .unwrap()
    }

    /// A fabricated [`symbolicate::Pass2MapBundle`] with the same
    /// function-name index and evidence projection the real preparation
    /// derives from `symbols`.
    fn test_bundle(
        map_path: &Path,
        symbols: Vec<symbolicate::Symbol>,
        execution_count: usize,
        applied_decision_count: usize,
    ) -> symbolicate::Pass2MapBundle {
        let function_names = symbols
            .iter()
            .filter_map(|symbol| {
                let name = symbol.name.as_ref()?;
                let entry =
                    u64::from_str_radix(symbol.address.trim_start_matches("0x"), 16).ok()?;
                Some((format!("{entry:x}"), name.clone()))
            })
            .collect();
        let evidence_name_projection =
            globals::FunctionEvidenceNameProjection::from_symbols(&symbols);
        let map_blake3 = crate::manifest::blake3_file(map_path).unwrap_or_else(|_| "0".repeat(64));
        symbolicate::Pass2MapBundle {
            map: symbolicate::WrittenSymbolMap {
                creation_count: 0,
                creation_requests: Vec::new(),
                creation_skips: Default::default(),
                path: map_path.to_path_buf(),
                map_blake3,
                functions_blake3: "1".repeat(64),
                execution_count,
                applied_decision_count,
            },
            symbols,
            function_names,
            evidence_name_projection,
        }
    }

    fn prepared_global_map(name: &str, count: usize) -> PreparedGlobalMap {
        PreparedGlobalMap {
            pass2_map: prepared_test_map(name, count),
        }
    }

    #[test]
    fn prepared_function_map_keeps_every_named_symbol_with_loader_canonical_addresses() {
        // This catches a preparation path that either filters to Recovered symbols
        // or retains the source address spelling instead of the symbols.json
        // loader's canonical lowercase, unprefixed hexadecimal key.
        let symbols = vec![
            symbolicate::Symbol {
                address: "0x0000ABCD".into(),
                arch: "arm",
                tool: crate::recover_source::Tool::Ghidra,
                owner: crate::execution_ranges::FunctionOwner::Ghidra,
                execution_blake3: None,
                decode_ranges: Vec::new(),
                name_conflicts: Vec::new(),
                original_name: "FUN_abcd".into(),
                name: Some("recovered_name".into()),
                tier: symbolicate::Tier::Recovered,
                evidence: vec![],
                annotations: vec![],
            },
            symbolicate::Symbol {
                address: "000000EF".into(),
                arch: "thumb",
                tool: crate::recover_source::Tool::Radare2,
                owner: crate::execution_ranges::FunctionOwner::Legacy {
                    producer: crate::recover_source::Tool::Radare2,
                },
                execution_blake3: None,
                decode_ranges: Vec::new(),
                name_conflicts: Vec::new(),
                original_name: "thumb_ef".into(),
                name: Some("provisional_name".into()),
                tier: symbolicate::Tier::Provisional,
                evidence: vec![],
                annotations: vec![],
            },
            symbolicate::Symbol {
                address: "0x00000012".into(),
                arch: "arm",
                tool: crate::recover_source::Tool::Ghidra,
                owner: crate::execution_ranges::FunctionOwner::Ghidra,
                execution_blake3: None,
                decode_ranges: Vec::new(),
                name_conflicts: Vec::new(),
                original_name: "FUN_12".into(),
                name: None,
                tier: symbolicate::Tier::None,
                evidence: vec![],
                annotations: vec![],
            },
        ];

        let image_dir = PathBuf::from("target/pme_task11_function_index_image");
        let map_path = PathBuf::from("target/pme_task11_decompose_maps/function-index.json");
        std::fs::create_dir_all(image_dir.join("decompiled")).unwrap();
        std::fs::create_dir_all(map_path.parent().unwrap()).unwrap();
        std::fs::write(&map_path, b"map").unwrap();
        std::fs::write(image_dir.join("decompiled/functions.json"), b"functions").unwrap();
        std::fs::write(image_dir.join("02_MAIN.bin"), b"image").unwrap();
        let (prepared, validation_error) = prepare_function_map(
            "02_MAIN",
            &image_dir,
            &map_path,
            test_bundle(&map_path, symbols, 4, 2),
        );

        assert!(validation_error.is_none());
        assert_eq!(prepared.pass2_map.as_ref().unwrap().execution_count(), 4);
        assert_eq!(
            prepared.function_names,
            HashMap::from([
                ("abcd".to_string(), "recovered_name".to_string()),
                ("ef".to_string(), "provisional_name".to_string()),
            ])
        );
    }

    #[test]
    fn prepared_function_map_schedules_creation_only_map() {
        let image_dir = PathBuf::from("target/pme_pass2_creation_only_image");
        let map_path = PathBuf::from("target/pme_task11_decompose_maps/creation-only.json");
        std::fs::create_dir_all(image_dir.join("decompiled")).unwrap();
        std::fs::create_dir_all(map_path.parent().unwrap()).unwrap();
        std::fs::write(&map_path, b"map").unwrap();
        std::fs::write(image_dir.join("decompiled/functions.json"), b"functions").unwrap();
        std::fs::write(image_dir.join("02_MAIN.bin"), b"image").unwrap();
        let mut bundle = test_bundle(&map_path, Vec::new(), 0, 0);
        bundle.map.creation_count = 2;
        bundle.map.creation_requests = vec![
            symbolicate::Pass2CreationRequest {
                entry: 0x4000,
                final_primary: "created_a".to_string(),
                final_source: "analysis".to_string(),
            },
            symbolicate::Pass2CreationRequest {
                entry: 0x4002,
                final_primary: "created_b".to_string(),
                final_source: "analysis".to_string(),
            },
        ];
        bundle.map.creation_skips = symbolicate::Pass2CreationSkips {
            ambiguous: 3,
            collision: 4,
            name_limit: 5,
            limit: 6,
            not_entry_start: 7,
        };

        let (prepared, validation_error) =
            prepare_function_map("02_MAIN", &image_dir, &map_path, bundle);

        assert!(validation_error.is_none());
        assert!(
            prepared.pass2_map.is_some(),
            "a creation-only map must schedule pass 2"
        );
        assert_eq!(prepared.pass2_map.as_ref().unwrap().creation_count(), 2);
        assert_eq!(prepared.creation_plan.candidates, 2);
        assert_eq!(prepared.creation_plan.skips.ambiguous, 3);
        assert_eq!(prepared.creation_plan.skips.collision, 4);
        assert_eq!(prepared.creation_plan.skips.name_limit, 5);
        assert_eq!(prepared.creation_plan.skips.limit, 6);
        assert_eq!(prepared.creation_plan.skips.not_entry_start, 7);
        let function_maps = HashMap::from([("02_MAIN".to_string(), prepared)]);
        let mut images = vec![analyzed_image("02_MAIN")];
        retain_pass2_creation_plans(&mut images, &function_maps);
        assert_eq!(
            images[0].pass2_creation_plan.as_ref().unwrap().candidates,
            2
        );
        let stage = symbol_map_stage(&function_maps, Vec::new(), 0);
        assert_eq!(stage.status, "ok");
    }

    #[test]
    fn prepared_function_map_builds_writer_faithful_evidence_name_projection() {
        // This catches collapsing the writer-finalized Function evidence name
        // into the all-tier recovered-name index. ARM applies the last non-null
        // map entry, while Thumb rewrite observes a final null as a barrier.
        let symbols = vec![
            test_symbol(
                "0x0000ABCD",
                "arm",
                Some("ARM_SHARED"),
                symbolicate::Tier::Recovered,
            ),
            test_symbol("0000abcd", "thumb", None, symbolicate::Tier::None),
            test_symbol(
                "0x000000EF",
                "arm",
                Some("RECOVERED_EF"),
                symbolicate::Tier::Recovered,
            ),
            test_symbol(
                "000000ef",
                "thumb",
                Some("PROVISIONAL_EF"),
                symbolicate::Tier::Provisional,
            ),
            test_symbol(
                "0x000000A2",
                "arm",
                Some("UPPER_A2"),
                symbolicate::Tier::Recovered,
            ),
            test_symbol(
                "not-hex",
                "thumb",
                Some("MALFORMED"),
                symbolicate::Tier::Recovered,
            ),
        ];

        let image_dir = PathBuf::from("target/pme_task11_function_projection_image");
        let map_path = PathBuf::from("target/pme_task11_decompose_maps/function-projection.json");
        std::fs::create_dir_all(image_dir.join("decompiled")).unwrap();
        std::fs::create_dir_all(map_path.parent().unwrap()).unwrap();
        std::fs::write(&map_path, b"map").unwrap();
        std::fs::write(image_dir.join("decompiled/functions.json"), b"functions").unwrap();
        std::fs::write(image_dir.join("02_MAIN.bin"), b"image").unwrap();
        let (prepared, validation_error) = prepare_function_map(
            "02_MAIN",
            &image_dir,
            &map_path,
            test_bundle(&map_path, symbols, 4, 4),
        );

        assert!(validation_error.is_none());
        assert_eq!(
            prepared.function_names,
            HashMap::from([
                ("abcd".to_string(), "ARM_SHARED".to_string()),
                ("ef".to_string(), "PROVISIONAL_EF".to_string()),
                ("a2".to_string(), "UPPER_A2".to_string()),
            ])
        );
        let projection = &prepared.evidence_name_projection;
        assert_eq!(
            projection.name_for(globals::Arch::Arm, 0xabcd),
            Some("ARM_SHARED")
        );
        // Each ISA projects only its own symbol: the ARM entry at 0xef keeps
        // its own recovered name instead of the Thumb entry's.
        assert_eq!(
            projection.name_for(globals::Arch::Arm, 0xef),
            Some("RECOVERED_EF")
        );
        assert_eq!(
            projection.name_for(globals::Arch::Arm, 0xa2),
            Some("UPPER_A2")
        );
        assert_eq!(projection.name_for(globals::Arch::Thumb, 0xabcd), None);
        assert_eq!(
            projection.name_for(globals::Arch::Thumb, 0xef),
            Some("PROVISIONAL_EF")
        );
        // 0xa2 has only an ARM symbol, so no Thumb record is renamed there.
        assert_eq!(projection.name_for(globals::Arch::Thumb, 0xa2), None);
    }

    #[test]
    fn prepared_pass2_inputs_preserve_combined_function_only_and_globals_only_images() {
        // This catches a union that drops an image present on only one side,
        // loses a prepared count, or attaches the wrong image's map path.
        let function_maps = HashMap::from([
            (
                "02_MAIN".to_string(),
                PreparedFunctionMap {
                    pass2_map: Some(prepared_symbol_test_map("functions-02_MAIN", "02_MAIN", 3)),
                    creation_plan: Default::default(),
                    function_names: HashMap::new(),
                    evidence_name_projection: Default::default(),
                },
            ),
            (
                "03_APM".to_string(),
                PreparedFunctionMap {
                    pass2_map: Some(prepared_symbol_test_map("functions-03_APM", "03_APM", 2)),
                    creation_plan: Default::default(),
                    function_names: HashMap::new(),
                    evidence_name_projection: Default::default(),
                },
            ),
        ]);
        let global_maps = HashMap::from([
            (
                "02_MAIN".to_string(),
                prepared_global_map("globals-02_MAIN.json", 5),
            ),
            (
                "04_VSS".to_string(),
                prepared_global_map("globals-04_VSS.json", 7),
            ),
        ]);

        let inputs = prepare_pass2_inputs(
            &function_maps,
            &global_maps,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
        );

        assert_eq!(inputs.len(), 3);
        assert_eq!(
            inputs["02_MAIN"]
                .function_map
                .as_ref()
                .unwrap()
                .execution_count(),
            3
        );
        assert_eq!(inputs["02_MAIN"].global_map.as_ref().unwrap().count(), 5);
        assert_eq!(
            inputs["03_APM"]
                .function_map
                .as_ref()
                .unwrap()
                .execution_count(),
            2
        );
        assert!(inputs["03_APM"].global_map.is_none());
        assert!(inputs["04_VSS"].function_map.is_none());
        assert_eq!(inputs["04_VSS"].global_map.as_ref().unwrap().count(), 7);
    }

    #[test]
    fn prepare_pass2_inputs_threads_global_types_map() {
        let root = std::env::temp_dir().join(format!("pme_p2t_{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let tp = root.join("global_types.json");
        std::fs::write(&tp, r#"{"format":"pixel-modem-extractor-global-types-v1","image":"02_MAIN","types":[{"address":"0x40010000","width":4}]}"#).unwrap();
        let mut types = HashMap::new();
        types.insert(
            "02_MAIN".to_string(),
            decompile::PreparedPass2Map::new(&tp, std::num::NonZeroUsize::new(1).unwrap()).unwrap(),
        );
        let inputs = prepare_pass2_inputs(
            &HashMap::new(),
            &HashMap::new(),
            &types,
            &HashMap::new(),
            &HashMap::new(),
        );
        assert!(inputs["02_MAIN"].global_types_map.is_some());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn initial_map_validation_isolates_function_and_global_inputs() {
        let root = std::env::temp_dir().join(format!(
            "pmetask8rinitialmapvalidation{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let main_symbols = vec![test_symbol(
            "0x40",
            "arm",
            Some("RecoveredMain"),
            symbolicate::Tier::Recovered,
        )];
        let other_symbols = vec![test_symbol(
            "0x80",
            "arm",
            Some("RecoveredOther"),
            symbolicate::Tier::Recovered,
        )];

        // An invalid function map omits only that component. Its names and
        // writer-faithful projection survive, while the valid global sibling
        // and both components of an unaffected image remain schedulable.
        std::fs::create_dir_all(root.join("decompiled")).unwrap();
        std::fs::write(
            root.join("decompiled/functions.json"),
            b"retained functions",
        )
        .unwrap();
        std::fs::write(root.join("02_MAIN.bin"), b"image main").unwrap();
        std::fs::write(root.join("03_APM.bin"), b"image other").unwrap();
        let missing_map = root.join("missing-functions.json");
        let (invalid_function, function_error) = prepare_function_map(
            "02_MAIN",
            &root,
            &missing_map,
            test_bundle(&missing_map, main_symbols.clone(), 1, 1),
        );
        assert!(function_error.is_some());
        assert!(invalid_function.pass2_map.is_none());
        assert_eq!(invalid_function.function_names["40"], "RecoveredMain");
        assert_eq!(
            invalid_function
                .evidence_name_projection
                .name_for(globals::Arch::Arm, 0x40),
            Some("RecoveredMain")
        );

        let main_globals_path = root.join("globals-main.json");
        let other_globals_path = root.join("globals-other.json");
        std::fs::write(&main_globals_path, b"globals main").unwrap();
        std::fs::write(&other_globals_path, b"globals other").unwrap();
        let other_map_path = root.join("functions-other.json");
        std::fs::write(&other_map_path, b"functions other map").unwrap();
        let valid_main_global = PreparedGlobalMap {
            pass2_map: decompile::PreparedPass2Map::new(
                &main_globals_path,
                NonZeroUsize::new(1).unwrap(),
            )
            .unwrap(),
        };
        let valid_other_global = PreparedGlobalMap {
            pass2_map: decompile::PreparedPass2Map::new(
                &other_globals_path,
                NonZeroUsize::new(2).unwrap(),
            )
            .unwrap(),
        };
        let (valid_other_function, other_function_error) = prepare_function_map(
            "03_APM",
            &root,
            &other_map_path,
            test_bundle(&other_map_path, other_symbols.clone(), 1, 1),
        );
        assert!(other_function_error.is_none());
        let inputs = prepare_pass2_inputs(
            &HashMap::from([
                ("02_MAIN".to_string(), invalid_function),
                ("03_APM".to_string(), valid_other_function),
            ]),
            &HashMap::from([
                ("02_MAIN".to_string(), valid_main_global),
                ("03_APM".to_string(), valid_other_global),
            ]),
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
        );
        assert!(inputs["02_MAIN"].function_map.is_none());
        assert_eq!(inputs["02_MAIN"].global_map.as_ref().unwrap().count(), 1);
        assert_eq!(
            inputs["03_APM"]
                .function_map
                .as_ref()
                .unwrap()
                .execution_count(),
            1
        );
        assert_eq!(inputs["03_APM"].global_map.as_ref().unwrap().count(), 2);

        // A valid function map survives a global-map validation failure. The
        // failed image retains its counts and labelled error, while a second
        // image retains its independently valid global map and accounting.
        let main_map_path = root.join("functions-main.json");
        std::fs::write(&main_map_path, b"functions main map").unwrap();
        let (valid_main_function, main_function_error) = prepare_function_map(
            "02_MAIN",
            &root,
            &main_map_path,
            test_bundle(&main_map_path, main_symbols.clone(), 1, 1),
        );
        assert!(main_function_error.is_none());
        let other_map_path = root.join("functions-other-second.json");
        std::fs::write(&other_map_path, b"functions other second map").unwrap();
        let (valid_other_function, other_function_error) = prepare_function_map(
            "03_APM",
            &root,
            &other_map_path,
            test_bundle(&other_map_path, other_symbols.clone(), 1, 1),
        );
        assert!(other_function_error.is_none());
        let images_dir = root.join("images");
        for label in ["02_MAIN", "03_APM"] {
            let image_dir = images_dir.join(label);
            std::fs::create_dir_all(image_dir.join("decompiled")).unwrap();
            std::fs::write(image_dir.join(format!("{label}.bin")), b"image").unwrap();
        }
        let mut images = vec![analyzed_image("02_MAIN"), analyzed_image("03_APM")];
        let outcome = run_globals_stage_with(
            &mut images,
            &images_dir,
            &root.join("manifest.json"),
            &PreparedGlobalsFunctionInputs::default(),
            &globals::GlobalsOpts::default(),
            |image_dir, label, _, _, _, _| {
                let (recovered_count, provisional_generated) = if label == "02_MAIN" {
                    (1, 3)
                } else {
                    std::fs::write(image_dir.join("decompiled/globals.json"), b"globals").unwrap();
                    (2, 4)
                };
                Ok(globals::GlobalsReport {
                    recovered_count,
                    conflicts_dropped: 0,
                    provisional_generated,
                    provisional_suppressed_by_recovered: 1,
                })
            },
        );
        assert!(!outcome.maps.contains_key("02_MAIN"));
        assert_eq!(outcome.maps["03_APM"].pass2_map.count(), 2);
        assert_eq!(outcome.stage.status, "failed");
        assert!(
            images[0]
                .globals_error
                .as_deref()
                .is_some_and(|error| error.contains("globals map validation"))
        );
        assert_eq!(images[0].globals_recovered, Some(1));
        assert_eq!(images[0].globals_provisional, Some(3));
        assert_eq!(images[0].globals_provisional_suppressed, Some(1));
        assert_eq!(images[1].globals_error, None);
        assert_eq!(images[1].globals_recovered, Some(2));
        assert_eq!(images[1].globals_provisional, Some(4));
        assert_eq!(images[1].globals_provisional_suppressed, Some(1));
        let inputs = prepare_pass2_inputs(
            &HashMap::from([
                ("02_MAIN".to_string(), valid_main_function),
                ("03_APM".to_string(), valid_other_function),
            ]),
            &outcome.maps,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
        );
        assert_eq!(
            inputs["02_MAIN"]
                .function_map
                .as_ref()
                .unwrap()
                .execution_count(),
            1
        );
        assert!(inputs["02_MAIN"].global_map.is_none());
        assert_eq!(
            inputs["03_APM"]
                .function_map
                .as_ref()
                .unwrap()
                .execution_count(),
            1
        );
        assert_eq!(inputs["03_APM"].global_map.as_ref().unwrap().count(), 2);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn symbol_map_stage_preserves_all_mixed_errors_and_survivors() {
        let function_maps = HashMap::from([(
            "02_MAIN".to_string(),
            PreparedFunctionMap {
                pass2_map: Some(prepared_symbol_test_map("mixed-survivor", "02_MAIN", 3)),
                creation_plan: Default::default(),
                function_names: HashMap::new(),
                evidence_name_projection: Default::default(),
            },
        )]);
        let long_message = "界".repeat(2_100);
        let stage = symbol_map_stage(
            &function_maps,
            vec![
                ("04_VSS".to_string(), "zeta failure".to_string()),
                ("02_MAIN".to_string(), "beta failure".to_string()),
                ("01_PSP".to_string(), long_message),
                ("02_MAIN".to_string(), "alpha failure".to_string()),
            ],
            11,
        );

        assert_eq!(stage.status, "failed");
        assert_eq!(stage.output.as_deref(), Some("ghidra/symbol_maps/"));
        let error = stage.error.as_deref().unwrap();
        let lines: Vec<&str> = error.lines().collect();
        assert_eq!(lines.len(), 4);
        assert!(lines[0].starts_with("01_PSP: "));
        assert!(lines[0].ends_with(" [truncated]"));
        assert!(lines[0].strip_prefix("01_PSP: ").unwrap().chars().count() <= 2_048);
        assert_eq!(lines[1], "02_MAIN: alpha failure");
        assert_eq!(lines[2], "02_MAIN: beta failure");
        assert_eq!(lines[3], "04_VSS: zeta failure");
        assert_eq!(error.matches("02_MAIN: alpha failure").count(), 1);
        assert_eq!(error.matches("02_MAIN: beta failure").count(), 1);
        assert_eq!(error.matches("04_VSS: zeta failure").count(), 1);
        assert!(!Report::is_ok(&[stage]));

        let inputs = prepare_pass2_inputs(
            &function_maps,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
        );
        assert_eq!(
            inputs["02_MAIN"]
                .function_map
                .as_ref()
                .unwrap()
                .execution_count(),
            3
        );
    }

    #[test]
    fn pass2_refresh_skips_unscheduled_stale_export() {
        let mut images = vec![analyzed_image("02_MAIN")];
        let mut calls = Vec::new();

        let (refreshed, errors) =
            refresh_pass2_outputs_with(&HashMap::new(), &mut images, |image| {
                calls.push(image.label.clone());
                Ok(())
            });

        assert_eq!(refreshed, 0);
        assert!(errors.is_empty());
        assert!(calls.is_empty());
    }

    #[test]
    fn pass2_refresh_skips_failed_process_export() {
        let mut images = vec![analyzed_image("02_MAIN")];
        let outcomes = HashMap::from([(
            "02_MAIN".to_string(),
            decompile::Pass2ProcessOutcome::Failed("analyzeHeadless exit 7".to_string()),
        )]);
        let mut calls = Vec::new();

        let (refreshed, errors) = refresh_pass2_outputs_with(&outcomes, &mut images, |image| {
            calls.push(image.label.clone());
            Ok(())
        });

        assert_eq!(refreshed, 0);
        assert_eq!(
            errors,
            vec![("02_MAIN".to_string(), "analyzeHeadless exit 7".to_string())]
        );
        assert!(calls.is_empty());
    }

    #[test]
    fn pass2_refresh_requires_export_after_success() {
        let root =
            std::env::temp_dir().join(format!("pme_task8r_missing_export_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let mut images = vec![analyzed_image("02_MAIN")];
        let outcomes = HashMap::from([(
            "02_MAIN".to_string(),
            decompile::Pass2ProcessOutcome::ProcessSucceeded,
        )]);

        let (refreshed, errors) = refresh_pass2_outputs_with(&outcomes, &mut images, |image| {
            refresh_decompiled_and_update(&root.join("ghidra"), &root.join("images"), image)
        });

        assert_eq!(refreshed, 0);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].1.contains("missing pass-2 export"));
        assert!(images[0].pass2_error.as_deref().is_some_and(
            |error| error.contains("refresh:") && error.contains("missing pass-2 export")
        ));
    }

    #[test]
    fn pass2_refresh_records_invalid_export_failure() {
        let root =
            std::env::temp_dir().join(format!("pme_task8r_invalid_export_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let export = root.join("ghidra/export/02_MAIN");
        let destination = root.join("images/02_MAIN/decompiled");
        std::fs::create_dir_all(&export).unwrap();
        std::fs::create_dir_all(&destination).unwrap();
        std::fs::write(export.join("decompiled.c"), b"new").unwrap();
        std::fs::write(destination.join("decompiled.c"), b"old").unwrap();
        let mut images = vec![analyzed_image("02_MAIN")];
        let outcomes = HashMap::from([(
            "02_MAIN".to_string(),
            decompile::Pass2ProcessOutcome::ProcessSucceeded,
        )]);

        let (refreshed, errors) = refresh_pass2_outputs_with(&outcomes, &mut images, |image| {
            refresh_decompiled_and_update(&root.join("ghidra"), &root.join("images"), image)
        });

        assert_eq!(refreshed, 0);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].1.contains("invalid pass-2 export"));
        assert_eq!(
            std::fs::read(destination.join("decompiled.c")).unwrap(),
            b"old"
        );
        assert!(images[0].pass2_error.as_deref().is_some_and(
            |error| error.contains("refresh:") && error.contains("invalid pass-2 export")
        ));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn decompile_pass2_stage_fails_function_only_errors() {
        let stage = decompile_pass2_stage(
            1,
            0,
            vec![("02_MAIN".to_string(), "function process failed".to_string())],
            7,
        );

        assert_eq!(stage.status, "failed");
        assert_eq!(
            stage.error.as_deref(),
            Some("02_MAIN: function process failed")
        );
        assert!(!Report::is_ok(&[stage]));
    }

    #[test]
    fn globals_apply_stage_uses_exact_skip_policies() {
        // This catches disabled application being reported as an executed
        // result, or the normal zero-input route losing its distinct reason.
        let prepared = HashMap::from([(
            "02_MAIN".to_string(),
            prepared_global_map("skip-globals-02_MAIN.json", 1),
        )]);
        let images = vec![analyzed_image("02_MAIN")];

        let disabled = globals_apply_stage(true, &prepared, Some(&images), 99);
        assert_eq!(
            serde_json::to_value(disabled).unwrap(),
            serde_json::json!({
                "stage": "globals_apply",
                "status": "skipped",
                "reason": "--no-symbol-pass",
                "duration_ms": 0
            })
        );

        let no_recovered = globals_apply_stage(false, &HashMap::new(), Some(&images), 99);
        assert_eq!(
            serde_json::to_value(no_recovered).unwrap(),
            serde_json::json!({
                "stage": "globals_apply",
                "status": "skipped",
                "reason": "no recovered globals",
                "duration_ms": 0
            })
        );
    }

    #[test]
    fn globals_apply_stage_aggregates_valid_executed_zero_and_skips_without_function_metrics() {
        // This catches legitimate skips being treated as failure, executed zero
        // being treated as absent, or global counts being folded into the
        // independent function-only pass2_applied metric.
        let prepared = HashMap::from([
            (
                "02_MAIN".to_string(),
                prepared_global_map("aggregate-globals-02_MAIN.json", 2),
            ),
            (
                "03_APM".to_string(),
                prepared_global_map("aggregate-globals-03_APM.json", 4),
            ),
        ]);
        let mut main = analyzed_image("02_MAIN");
        main.pass2_applied = Some(7);
        main.globals_applied = Some(2);
        main.globals_apply_skipped = Some(0);
        let mut apm = analyzed_image("03_APM");
        apm.pass2_applied = None;
        apm.globals_applied = Some(0);
        apm.globals_apply_skipped = Some(4);
        let mut unrelated = analyzed_image("04_VSS");
        unrelated.pass2_error = Some("unrelated function-only failure".into());
        let images = vec![main, apm, unrelated];

        let stage = globals_apply_stage(false, &prepared, Some(&images), 17);
        assert_eq!(
            serde_json::to_value(stage).unwrap(),
            serde_json::json!({
                "stage": "globals_apply",
                "status": "ok",
                "output": "2 image(s) processed; 2 globals applied; 4 skipped",
                "duration_ms": 17
            })
        );
        assert_eq!(images[0].pass2_applied, Some(7));
        assert_eq!(images[1].pass2_applied, None);
    }

    #[test]
    fn globals_apply_stage_fails_closed_for_every_invalid_prepared_image_outcome() {
        // These are the real reason-only outcomes produced by pass-2 parsing for a
        // status:error line and each strict success-summary contract failure.
        let summary_errors = [
            "global map rejected",
            "missing ApplyGlobals summary",
            "malformed ApplyGlobals summary: expected value at line 1 column 1",
            "ApplyGlobals summary image \"04_VSS\" does not match \"02_MAIN\"",
            "ApplyGlobals summary does not conserve candidates: 1 != 2",
        ];
        let prepared = HashMap::from([(
            "02_MAIN".to_string(),
            prepared_global_map("invalid-globals-02_MAIN.json", 2),
        )]);

        for reason in summary_errors {
            let mut image = analyzed_image("02_MAIN");
            image.globals_apply_error = Some(reason.into());
            let stage = globals_apply_stage(false, &prepared, Some(&[image]), 5);
            assert_eq!(stage.status, "failed", "reason: {reason}");
            assert_eq!(
                stage.error.as_deref(),
                Some(format!("02_MAIN: {reason}").as_str()),
                "first actionable summary error must be retained"
            );
            assert_eq!(
                stage.output.as_deref(),
                Some("0 image(s) processed; 0 globals applied; 0 skipped")
            );
        }

        let mut process_failed = analyzed_image("02_MAIN");
        process_failed.pass2_error = Some("analyzeHeadless exit 7; stderr tail:\nboom".into());
        let stage = globals_apply_stage(false, &prepared, Some(&[process_failed]), 6);
        assert_eq!(stage.status, "failed");
        assert_eq!(
            stage.error.as_deref(),
            Some("02_MAIN: analyzeHeadless exit 7; stderr tail:\nboom")
        );

        let no_summary = analyzed_image("02_MAIN");
        let stage = globals_apply_stage(false, &prepared, Some(&[no_summary]), 7);
        assert_eq!(stage.status, "failed");
        assert_eq!(
            stage.error.as_deref(),
            Some("02_MAIN: no valid ApplyGlobals success summary")
        );

        let stage = globals_apply_stage(false, &prepared, None, 8);
        assert_eq!(stage.status, "failed");
        assert_eq!(
            stage.error.as_deref(),
            Some("02_MAIN: missing pass-2 image result")
        );
    }

    #[test]
    fn globals_apply_stage_keeps_first_actionable_error_in_image_order() {
        // This catches HashMap iteration or label sorting replacing the first
        // pipeline image's actionable failure with a later image's error.
        let prepared = HashMap::from([
            (
                "02_MAIN".to_string(),
                prepared_global_map("order-globals-02_MAIN.json", 1),
            ),
            (
                "03_APM".to_string(),
                prepared_global_map("order-globals-03_APM.json", 1),
            ),
        ]);
        let mut apm = analyzed_image("03_APM");
        apm.globals_apply_error = Some("first pipeline-image error".into());
        let mut main = analyzed_image("02_MAIN");
        main.pass2_error = Some("later pipeline-image error".into());

        let stage = globals_apply_stage(false, &prepared, Some(&[apm, main]), 4);

        assert_eq!(stage.status, "failed");
        assert_eq!(
            stage.error.as_deref(),
            Some("03_APM: first pipeline-image error")
        );
    }

    #[test]
    fn globals_apply_stage_rejects_either_one_sided_success_pair() {
        // This catches either half of the applied/skipped pair being accepted
        // as an executed success when the other half is absent.
        let prepared = HashMap::from([(
            "02_MAIN".to_string(),
            prepared_global_map("pair-globals-02_MAIN.json", 1),
        )]);

        for (applied, skipped) in [(Some(1), None), (None, Some(1))] {
            let mut image = analyzed_image("02_MAIN");
            image.globals_applied = applied;
            image.globals_apply_skipped = skipped;

            let stage = globals_apply_stage(false, &prepared, Some(&[image]), 3);

            assert_eq!(stage.status, "failed");
            assert_eq!(
                stage.error.as_deref(),
                Some("02_MAIN: no valid ApplyGlobals success summary")
            );
            assert_eq!(
                stage.output.as_deref(),
                Some("0 image(s) processed; 0 globals applied; 0 skipped")
            );
        }
    }

    #[test]
    fn globals_apply_stage_rejects_per_image_overflow_and_prepared_count_mismatch() {
        // This catches wrapping the per-image applied+skipped sum or accepting
        // a conserving pair for a different prepared Recovered count.
        let overflow_prepared = HashMap::from([(
            "02_MAIN".to_string(),
            prepared_global_map("overflow-globals-02_MAIN.json", usize::MAX),
        )]);
        let mut overflow = analyzed_image("02_MAIN");
        overflow.globals_applied = Some(usize::MAX);
        overflow.globals_apply_skipped = Some(1);
        let overflow_stage = globals_apply_stage(false, &overflow_prepared, Some(&[overflow]), 4);
        assert_eq!(overflow_stage.status, "failed");
        assert_eq!(
            overflow_stage.error.as_deref(),
            Some("02_MAIN: global application counts overflow")
        );

        let mismatch_prepared = HashMap::from([(
            "02_MAIN".to_string(),
            prepared_global_map("mismatch-globals-02_MAIN.json", 3),
        )]);
        let mut mismatch = analyzed_image("02_MAIN");
        mismatch.globals_applied = Some(1);
        mismatch.globals_apply_skipped = Some(1);
        let mismatch_stage = globals_apply_stage(false, &mismatch_prepared, Some(&[mismatch]), 5);
        assert_eq!(mismatch_stage.status, "failed");
        assert_eq!(
            mismatch_stage.error.as_deref(),
            Some("02_MAIN: global application counts do not match prepared globals: 2 != 3")
        );
    }

    #[test]
    fn globals_apply_stage_rejects_aggregate_overflow_and_keeps_prior_totals() {
        // This catches wrapping aggregate totals. The first valid image's
        // contribution remains visible when the next addition overflows.
        let prepared = HashMap::from([
            (
                "02_MAIN".to_string(),
                prepared_global_map("aggregate-overflow-globals-02_MAIN.json", usize::MAX),
            ),
            (
                "03_APM".to_string(),
                prepared_global_map("aggregate-overflow-globals-03_APM.json", 1),
            ),
        ]);
        let mut main = analyzed_image("02_MAIN");
        main.globals_applied = Some(usize::MAX);
        main.globals_apply_skipped = Some(0);
        let mut apm = analyzed_image("03_APM");
        apm.globals_applied = Some(1);
        apm.globals_apply_skipped = Some(0);

        let stage = globals_apply_stage(false, &prepared, Some(&[main, apm]), 6);

        assert_eq!(stage.status, "failed");
        assert_eq!(
            stage.error.as_deref(),
            Some("03_APM: global application totals overflow")
        );
        let expected_output = format!(
            "1 image(s) processed; {} globals applied; 0 skipped",
            usize::MAX
        );
        assert_eq!(stage.output.as_deref(), Some(expected_output.as_str()));
    }

    #[test]
    fn globals_apply_failure_retains_other_success_totals_and_fails_overall_report() {
        // This catches an error zeroing a prior prepared image's successful
        // totals or failing to propagate through the top-level report policy.
        let prepared = HashMap::from([
            (
                "02_MAIN".to_string(),
                prepared_global_map("partial-globals-02_MAIN.json", 5),
            ),
            (
                "03_APM".to_string(),
                prepared_global_map("partial-globals-03_APM.json", 1),
            ),
        ]);
        let mut main = analyzed_image("02_MAIN");
        main.globals_applied = Some(2);
        main.globals_apply_skipped = Some(3);
        let mut apm = analyzed_image("03_APM");
        apm.globals_apply_error = Some("global map rejected".into());

        let stage = globals_apply_stage(false, &prepared, Some(&[main, apm]), 7);

        assert_eq!(stage.status, "failed");
        assert_eq!(stage.error.as_deref(), Some("03_APM: global map rejected"));
        assert_eq!(
            stage.output.as_deref(),
            Some("1 image(s) processed; 2 globals applied; 3 skipped")
        );
        assert!(!Report::is_ok(&[stage]));
    }

    #[test]
    fn global_types_apply_stage_uses_exact_skip_policies() {
        // Mirrors globals_apply_stage_uses_exact_skip_policies: this catches
        // disabled application, the --no-apply-global-types escape hatch, and
        // the zero-candidate route losing their distinct reasons.
        let maps = HashMap::from([(
            "02_MAIN".to_string(),
            prepared_test_map("skip-types-02_MAIN.json", 1),
        )]);
        let images = vec![analyzed_image("02_MAIN")];
        let mut report_images = vec![ImageReport::from_result(&analyzed_image("02_MAIN"))];

        let disabled = global_types_apply_stage(
            true,
            false,
            &maps,
            &HashMap::new(),
            Some(&images),
            &mut report_images,
            99,
        );
        assert_eq!(
            serde_json::to_value(disabled).unwrap(),
            serde_json::json!({
                "stage": "global_types_apply",
                "status": "skipped",
                "reason": "--no-symbol-pass",
                "duration_ms": 0
            })
        );

        let flag_disabled = global_types_apply_stage(
            false,
            true,
            &maps,
            &HashMap::new(),
            Some(&images),
            &mut report_images,
            99,
        );
        assert_eq!(
            serde_json::to_value(flag_disabled).unwrap(),
            serde_json::json!({
                "stage": "global_types_apply",
                "status": "skipped",
                "reason": "--no-apply-global-types",
                "duration_ms": 0
            })
        );

        let no_recovered = global_types_apply_stage(
            false,
            false,
            &HashMap::new(),
            &HashMap::new(),
            Some(&images),
            &mut report_images,
            99,
        );
        assert_eq!(
            serde_json::to_value(no_recovered).unwrap(),
            serde_json::json!({
                "stage": "global_types_apply",
                "status": "skipped",
                "reason": "no recovered scalar shapes",
                "duration_ms": 0
            })
        );
    }

    #[test]
    fn global_types_apply_stage_aggregates_and_patches_report_images() {
        // This catches the aggregate stage losing headline counts, or the
        // per-image ImageReport patch (applied/skipped/candidates/ineligible)
        // going missing — the whole reason this stage exists instead of
        // relying on ImageReport::from_result like globals_applied does.
        let maps = HashMap::from([
            (
                "02_MAIN".to_string(),
                prepared_test_map("aggregate-types-02_MAIN.json", 5),
            ),
            (
                "03_APM".to_string(),
                prepared_test_map("aggregate-types-03_APM.json", 2),
            ),
        ]);
        let ineligible = HashMap::from([("02_MAIN".to_string(), 4usize)]);
        let mut main = analyzed_image("02_MAIN");
        main.global_types_applied = Some(3);
        main.global_types_apply_skipped = Some(2);
        let mut apm = analyzed_image("03_APM");
        apm.global_types_applied = Some(2);
        apm.global_types_apply_skipped = Some(0);
        let images = vec![main, apm];
        let mut report_images = vec![
            ImageReport::from_result(&analyzed_image("02_MAIN")),
            ImageReport::from_result(&analyzed_image("03_APM")),
        ];

        let stage = global_types_apply_stage(
            false,
            false,
            &maps,
            &ineligible,
            Some(&images),
            &mut report_images,
            17,
        );

        assert_eq!(
            serde_json::to_value(&stage).unwrap(),
            serde_json::json!({
                "stage": "global_types_apply",
                "status": "ok",
                "output": "2 image(s) processed; 5 global types applied; 2 skipped",
                "duration_ms": 17
            })
        );
        assert_eq!(report_images[0].global_types_applied, Some(3));
        assert_eq!(report_images[0].global_types_skipped, Some(2));
        assert_eq!(report_images[0].global_types_candidates, Some(5));
        assert_eq!(report_images[0].global_types_ineligible, Some(4));
        assert!(report_images[0].global_types_error.is_none());
        assert_eq!(report_images[1].global_types_applied, Some(2));
        assert_eq!(report_images[1].global_types_skipped, Some(0));
        assert_eq!(report_images[1].global_types_candidates, Some(2));
        assert!(report_images[1].global_types_ineligible.is_none());
    }

    #[test]
    fn global_types_apply_stage_records_ineligible_even_when_application_is_skipped() {
        // A `global_shapes.json` with only ineligible shapes (e.g. all
        // no_evidence/array/conflicting) produces an empty `maps` but a
        // non-empty `ineligible` — the stage is skipped, but the per-image
        // count must still surface for diagnostics.
        let ineligible = HashMap::from([("02_MAIN".to_string(), 6usize)]);
        let mut report_images = vec![ImageReport::from_result(&analyzed_image("02_MAIN"))];

        let stage = global_types_apply_stage(
            false,
            false,
            &HashMap::new(),
            &ineligible,
            None,
            &mut report_images,
            0,
        );

        assert_eq!(stage.status, "skipped");
        assert_eq!(stage.reason.as_deref(), Some("no recovered scalar shapes"));
        assert_eq!(report_images[0].global_types_ineligible, Some(6));
        assert!(report_images[0].global_types_applied.is_none());
    }

    #[test]
    fn global_types_apply_stage_fails_closed_and_records_per_image_error() {
        // Mirrors globals_apply_stage_fails_closed_for_every_invalid_prepared_image_outcome:
        // a per-image ApplyGlobalTypes contract failure must fail the stage
        // and land on that image's global_types_error, without fabricating
        // applied/skipped/candidates.
        let maps = HashMap::from([(
            "02_MAIN".to_string(),
            prepared_test_map("invalid-types-02_MAIN.json", 2),
        )]);
        let mut image = analyzed_image("02_MAIN");
        image.global_types_apply_error = Some("global-type map rejected".into());
        let mut report_images = vec![ImageReport::from_result(&analyzed_image("02_MAIN"))];

        let stage = global_types_apply_stage(
            false,
            false,
            &maps,
            &HashMap::new(),
            Some(&[image]),
            &mut report_images,
            5,
        );

        assert_eq!(stage.status, "failed");
        assert_eq!(
            stage.error.as_deref(),
            Some("02_MAIN: global-type map rejected")
        );
        assert_eq!(
            stage.output.as_deref(),
            Some("0 image(s) processed; 0 global types applied; 0 skipped")
        );
        assert_eq!(
            report_images[0].global_types_error.as_deref(),
            Some("global-type map rejected")
        );
        assert!(report_images[0].global_types_applied.is_none());
        assert!(report_images[0].global_types_candidates.is_none());
    }

    #[test]
    fn global_types_apply_stage_records_missing_pass2_image_result() {
        let maps = HashMap::from([(
            "02_MAIN".to_string(),
            prepared_test_map("missing-types-02_MAIN.json", 1),
        )]);
        let mut report_images = vec![ImageReport::from_result(&analyzed_image("02_MAIN"))];

        let stage = global_types_apply_stage(
            false,
            false,
            &maps,
            &HashMap::new(),
            None,
            &mut report_images,
            8,
        );

        assert_eq!(stage.status, "failed");
        assert_eq!(
            stage.error.as_deref(),
            Some("02_MAIN: missing pass-2 image result")
        );
        assert_eq!(
            report_images[0].global_types_error.as_deref(),
            Some("missing pass-2 image result")
        );
    }

    #[test]
    fn globals_stage_refreshes_only_when_application_is_known_uninvoked() {
        // This catches the normal route installing a pre-application snapshot
        // and relying on a later overwrite. The disabled route may refresh
        // immediately because application is known not to run.
        let mut raw = analyzed_image("02_MAIN");
        raw.globals_recovered = Some(2);
        let initial = vec![ImageReport::from_result(&analyzed_image("02_MAIN"))];
        let outcome = || GlobalsStageOutcome {
            maps: HashMap::new(),
            stage: StageReport::ok("globals", "globals.json", 1),
        };

        let mut normal_stages = vec![StageReport::decompile(initial, 10)];
        let _ = record_globals_stage(
            &mut normal_stages,
            outcome(),
            std::slice::from_ref(&raw),
            false,
        );
        assert_eq!(normal_stages[0].images[0].globals_recovered, None);

        let mut disabled_stages = vec![StageReport::decompile(
            vec![ImageReport::from_result(&analyzed_image("02_MAIN"))],
            10,
        )];
        let _ = record_globals_stage(
            &mut disabled_stages,
            outcome(),
            std::slice::from_ref(&raw),
            true,
        );
        assert_eq!(disabled_stages[0].images[0].globals_recovered, Some(2));
    }

    #[test]
    fn pass2_error_installs_captured_post_globals_snapshot_only_after_outcome() {
        // This catches removal of the forbidden pre-application refresh also
        // losing global-preparation fields when run_two_pass consumes the raw
        // report and returns an early Err.
        let mut raw = analyzed_image("02_MAIN");
        raw.globals_recovered = Some(2);
        let fallback = vec![ImageReport::from_result(&raw)];
        let mut stages = vec![StageReport::decompile(
            vec![ImageReport::from_result(&analyzed_image("02_MAIN"))],
            10,
        )];
        assert_eq!(stages[0].images[0].globals_recovered, None);

        install_decompile_stage_image_snapshot(&mut stages, fallback);

        assert_eq!(stages[0].images[0].globals_recovered, Some(2));
        assert!(stages[0].images[0].globals_applied.is_none());
        assert!(stages[0].images[0].globals_apply_skipped.is_none());
        assert!(stages[0].images[0].globals_apply_error.is_none());
    }

    #[test]
    fn globals_stage_runs_each_raw_image_once_and_prepares_only_recovered_inputs() {
        // This catches a sweep that skips or repeats an eligible raw image, loses
        // the prepared all-tier function-name index, creates an application input
        // for zero Recovered globals, or counts Provisional globals as applicable.
        let root =
            std::env::temp_dir().join(format!("pme_globals_stage_success_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let images_dir = root.join("images");
        for (label, bytes) in [
            ("02_MAIN", b"main bytes".as_slice()),
            ("03_APM", b"apm bytes".as_slice()),
            ("04_VSS", b"vss bytes".as_slice()),
        ] {
            let image_dir = images_dir.join(label);
            std::fs::create_dir_all(image_dir.join("decompiled")).unwrap();
            std::fs::write(image_dir.join(format!("{label}.bin")), bytes).unwrap();
        }
        let mut images = vec![
            analyzed_image("02_MAIN"),
            analyzed_image("03_APM"),
            analyzed_image("04_VSS"),
            analyzed_image("05_DBGCORE"),
        ];
        let mut function_maps = HashMap::from([(
            "02_MAIN".to_string(),
            PreparedFunctionMap {
                pass2_map: Some(prepared_symbol_test_map(
                    "globals-stage-functions",
                    "02_MAIN",
                    2,
                )),
                creation_plan: Default::default(),
                function_names: HashMap::from([
                    ("40".to_string(), "RecoveredMain".to_string()),
                    ("44".to_string(), "guess_main_44".to_string()),
                ]),
                evidence_name_projection: Default::default(),
            },
        )]);
        let function_inputs = take_globals_function_inputs(&mut function_maps);
        let mut calls = Vec::new();

        let outcome = run_globals_stage_with(
            &mut images,
            &images_dir,
            &root.join("manifest.json"),
            &function_inputs,
            &globals::GlobalsOpts::default(),
            |image_dir, label, _, names, evidence_names, _| {
                assert_eq!(evidence_names.is_some(), label == "02_MAIN");
                calls.push((
                    label.to_string(),
                    std::fs::read(image_dir.join(format!("{label}.bin"))).unwrap(),
                    names.clone(),
                ));
                let report = match label {
                    "02_MAIN" => globals::GlobalsReport {
                        recovered_count: 2,
                        conflicts_dropped: 1,
                        provisional_generated: 5,
                        provisional_suppressed_by_recovered: 1,
                    },
                    "03_APM" => globals::GlobalsReport {
                        recovered_count: 0,
                        conflicts_dropped: 2,
                        provisional_generated: 3,
                        provisional_suppressed_by_recovered: 2,
                    },
                    "04_VSS" => globals::GlobalsReport {
                        recovered_count: 4,
                        conflicts_dropped: 0,
                        provisional_generated: 9,
                        provisional_suppressed_by_recovered: 0,
                    },
                    _ => unreachable!("image without raw bytes must not run"),
                };
                if report.recovered_count > 0 {
                    std::fs::write(image_dir.join("decompiled/globals.json"), b"globals").unwrap();
                }
                Ok(report)
            },
        );

        assert_eq!(
            calls,
            vec![
                (
                    "02_MAIN".to_string(),
                    b"main bytes".to_vec(),
                    HashMap::from([
                        ("40".to_string(), "RecoveredMain".to_string()),
                        ("44".to_string(), "guess_main_44".to_string()),
                    ]),
                ),
                ("03_APM".to_string(), b"apm bytes".to_vec(), HashMap::new()),
                ("04_VSS".to_string(), b"vss bytes".to_vec(), HashMap::new()),
            ],
            "each image with raw bytes must run exactly once with its prepared names"
        );
        assert_eq!(images[0].globals_recovered, Some(2));
        assert_eq!(images[0].globals_provisional, Some(5));
        assert_eq!(images[0].globals_provisional_suppressed, Some(1));
        assert_eq!(images[1].globals_recovered, Some(0));
        assert_eq!(images[2].globals_recovered, Some(4));
        assert_eq!(images[2].globals_provisional, Some(9));
        assert!(images[3].globals_recovered.is_none());
        assert_eq!(outcome.maps.len(), 2);
        assert_eq!(outcome.maps["02_MAIN"].pass2_map.count(), 2);
        assert_eq!(outcome.maps["04_VSS"].pass2_map.count(), 4);
        assert_eq!(
            outcome.maps["04_VSS"].pass2_map.path(),
            images_dir
                .join("04_VSS")
                .join("decompiled")
                .join("globals.json")
                .canonicalize()
                .unwrap()
        );
        assert!(!outcome.maps.contains_key("03_APM"));
        assert_eq!(outcome.stage.stage, "globals");
        assert_eq!(outcome.stage.status, "ok");
        assert_eq!(
            outcome.stage.output.as_deref(),
            Some(
                "3 image(s) processed; 6 recovered globals total; 3 conflicts dropped; \
                 17 provisional generated (3 suppressed by Recovered)"
            )
        );
        assert!(outcome.stage.error.is_none());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn globals_stage_failure_keeps_function_map_and_surfaces_failed_image() {
        // This catches an image-level globals error that consumes or deletes its
        // function-only pass-2 input, suppresses the error/report failure, or
        // prevents later images from producing usable globals inputs.
        let root =
            std::env::temp_dir().join(format!("pme_globals_stage_failure_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let images_dir = root.join("images");
        for label in ["02_MAIN", "04_VSS"] {
            let image_dir = images_dir.join(label);
            std::fs::create_dir_all(image_dir.join("decompiled")).unwrap();
            std::fs::write(image_dir.join(format!("{label}.bin")), label).unwrap();
        }
        let mut images = vec![analyzed_image("02_MAIN"), analyzed_image("04_VSS")];
        let mut function_maps = HashMap::from([(
            "02_MAIN".to_string(),
            PreparedFunctionMap {
                pass2_map: Some(prepared_symbol_test_map("failure-functions", "02_MAIN", 1)),
                creation_plan: Default::default(),
                function_names: HashMap::from([("40".to_string(), "RecoveredMain".to_string())]),
                evidence_name_projection: Default::default(),
            },
        )]);
        let function_inputs = take_globals_function_inputs(&mut function_maps);

        let outcome = run_globals_stage_with(
            &mut images,
            &images_dir,
            &root.join("manifest.json"),
            &function_inputs,
            &globals::GlobalsOpts::default(),
            |image_dir, label, _, _, _, _| {
                if label == "02_MAIN" {
                    Err(Error::Serialize("malformed functions.json".into()))
                } else {
                    std::fs::write(image_dir.join("decompiled/globals.json"), b"globals").unwrap();
                    Ok(globals::GlobalsReport {
                        recovered_count: 1,
                        conflicts_dropped: 0,
                        provisional_generated: 0,
                        provisional_suppressed_by_recovered: 0,
                    })
                }
            },
        );

        assert_eq!(
            function_maps["02_MAIN"]
                .pass2_map
                .as_ref()
                .unwrap()
                .execution_count(),
            1
        );
        assert!(!outcome.maps.contains_key("02_MAIN"));
        assert_eq!(outcome.maps["04_VSS"].pass2_map.count(), 1);
        assert_eq!(
            images[0].globals_error.as_deref(),
            Some("serialize: malformed functions.json")
        );
        assert!(images[0].globals_recovered.is_none());
        assert_eq!(images[1].globals_recovered, Some(1));
        assert_eq!(outcome.stage.status, "failed");
        assert_eq!(
            outcome.stage.error.as_deref(),
            Some("serialize: malformed functions.json")
        );
        assert_eq!(
            outcome.stage.output.as_deref(),
            Some(
                "1 image(s) processed; 1 recovered globals total; 0 conflicts dropped; \
                 0 provisional generated (0 suppressed by Recovered)"
            )
        );

        let inputs = prepare_pass2_inputs(
            &function_maps,
            &outcome.maps,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
        );
        assert_eq!(
            inputs["02_MAIN"]
                .function_map
                .as_ref()
                .unwrap()
                .execution_count(),
            1
        );
        assert!(inputs["02_MAIN"].function_map.is_some());
        assert!(inputs["02_MAIN"].global_map.is_none());
        images[1].globals_applied = Some(0);
        images[1].globals_apply_skipped = Some(1);
        let apply_stage = globals_apply_stage(false, &outcome.maps, Some(&images), 0);
        assert_eq!(apply_stage.status, "ok");
        assert_eq!(
            apply_stage.output.as_deref(),
            Some("1 image(s) processed; 0 globals applied; 1 skipped")
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn sole_global_preparation_failure_skips_application_but_keeps_function_only_input() {
        // This catches the separate `globals` preparation failure being
        // misreported as an invocation, or consuming the same image's valid
        // function-only pass-2 work.
        let root = std::env::temp_dir().join(format!(
            "pme_globals_stage_sole_failure_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let images_dir = root.join("images");
        let image_dir = images_dir.join("02_MAIN");
        std::fs::create_dir_all(image_dir.join("decompiled")).unwrap();
        std::fs::write(image_dir.join("02_MAIN.bin"), b"main bytes").unwrap();
        let mut images = vec![analyzed_image("02_MAIN")];
        let mut function_maps = HashMap::from([(
            "02_MAIN".to_string(),
            PreparedFunctionMap {
                pass2_map: Some(prepared_symbol_test_map(
                    "sole-failure-functions",
                    "02_MAIN",
                    3,
                )),
                creation_plan: Default::default(),
                function_names: HashMap::new(),
                evidence_name_projection: Default::default(),
            },
        )]);

        let function_inputs = take_globals_function_inputs(&mut function_maps);
        let outcome = run_globals_stage_with(
            &mut images,
            &images_dir,
            &root.join("manifest.json"),
            &function_inputs,
            &globals::GlobalsOpts::default(),
            |_, _, _, _, _, _| Err(Error::Serialize("malformed functions.json".into())),
        );
        let inputs = prepare_pass2_inputs(
            &function_maps,
            &outcome.maps,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
        );
        let apply_stage = globals_apply_stage(false, &outcome.maps, Some(&images), 12);

        assert_eq!(outcome.stage.status, "failed");
        assert!(outcome.maps.is_empty());
        assert_eq!(
            inputs["02_MAIN"]
                .function_map
                .as_ref()
                .unwrap()
                .execution_count(),
            3
        );
        assert!(inputs["02_MAIN"].function_map.is_some());
        assert!(inputs["02_MAIN"].global_map.is_none());
        assert_eq!(apply_stage.status, "skipped");
        assert_eq!(apply_stage.reason.as_deref(), Some("no recovered globals"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pass2_success_refreshes_despite_globals_summary_error() {
        // This catches aggregate reporting short-circuiting the already-safe
        // refresh of an independently successful same-process function export.
        let root = std::env::temp_dir().join(format!(
            "pme_globals_apply_refresh_isolation_{}",
            std::process::id()
        ));
        let ghidra_dir = root.join("ghidra");
        let images_dir = root.join("images");
        let export = ghidra_dir.join("export").join("02_MAIN");
        let destination = images_dir.join("02_MAIN").join("decompiled");
        std::fs::create_dir_all(&export).unwrap();
        std::fs::create_dir_all(&destination).unwrap();
        std::fs::write(
            export.join("decompiled.c"),
            "void refreshed_function(void) {}",
        )
        .unwrap();
        std::fs::write(export.join("disasm.lst"), "refreshed disassembly").unwrap();
        std::fs::write(export.join("functions.json"), tagged_functions("refreshed")).unwrap();
        std::fs::write(destination.join("decompiled.c"), "stale decompiled.c").unwrap();
        std::fs::write(destination.join("disasm.lst"), "stale disasm.lst").unwrap();
        std::fs::write(
            destination.join("functions.json"),
            tagged_functions("stale"),
        )
        .unwrap();
        let thumb_sidecar = tagged_thumb_functions();
        std::fs::write(destination.join("thumb_functions.json"), &thumb_sidecar).unwrap();
        std::fs::write(images_dir.join("02_MAIN/02_MAIN.bin"), vec![0u8; 0x40]).unwrap();
        let prepared = HashMap::from([(
            "02_MAIN".to_string(),
            prepared_global_map("refresh-globals-02_MAIN.json", 1),
        )]);
        let mut image = tagged_image("02_MAIN", true);
        image.pass2_applied = Some(1);
        image.globals_apply_error = Some("global map rejected".into());

        let outcomes = HashMap::from([(
            "02_MAIN".to_string(),
            decompile::Pass2ProcessOutcome::ProcessSucceeded,
        )]);
        let (refreshed, refresh_errors) =
            refresh_pass2_outputs_with(&outcomes, std::slice::from_mut(&mut image), |image| {
                refresh_decompiled_and_update(&ghidra_dir, &images_dir, image)
            });
        let pass2_stage = decompile_pass2_stage(1, refreshed, refresh_errors, 8);
        let stage = globals_apply_stage(false, &prepared, Some(&[image]), 9);

        assert_eq!(pass2_stage.status, "ok");
        assert_eq!(stage.status, "failed");
        assert_eq!(stage.error.as_deref(), Some("02_MAIN: global map rejected"));
        assert_eq!(
            std::fs::read_to_string(destination.join("decompiled.c")).unwrap(),
            "void refreshed_function(void) {}"
        );
        assert_eq!(
            std::fs::read(destination.join("thumb_functions.json")).unwrap(),
            thumb_sidecar
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn direct_symbol_routes_preserve_exact_once_order() {
        let mut normal = Vec::new();
        orchestrate_symbol_route(false, |step| normal.push(step));
        assert_eq!(
            normal,
            vec![
                SymbolRouteStep::PrepareNamesAndProjection,
                SymbolRouteStep::RunGlobals(GlobalsRouteMode::PrepareApplicationInput),
                // First shapes sweep runs before pass 2 (input-safe reorder),
                // so DispatchPass2 can derive the global-types apply-map from
                // global_shapes.json and a later pass-2 script can apply them
                // as types alongside ApplyGlobals.
                SymbolRouteStep::RunGlobalShapes,
                SymbolRouteStep::DispatchPass2,
                SymbolRouteStep::ApplyGlobalTypes,
                // Finalize is the LAST rewriter of the sidecar's hashed
                // inputs: symbolicate_finalize's rewrite_functions_json
                // stamps name/original_name/annotations into BOTH
                // functions.json and thumb_functions.json (its Ghidra-export
                // refresh and thumb enrichment touch the same two files), so
                // the FINAL shapes sweep must re-commit the sidecar after it —
                // not merely after DispatchPass2's earlier rewrites. Measured
                // e2e: finalize's writes land ~1 minute after the
                // DispatchPass2-era re-commit, re-staling every sidecar.
                SymbolRouteStep::Finalize {
                    rewrite_decompiled_c: false,
                },
                SymbolRouteStep::RefreshGlobalShapes,
            ]
        );
        for step in [
            SymbolRouteStep::RunGlobals(GlobalsRouteMode::PrepareApplicationInput),
            SymbolRouteStep::RunGlobalShapes,
            SymbolRouteStep::DispatchPass2,
            SymbolRouteStep::RefreshGlobalShapes,
            SymbolRouteStep::ApplyGlobalTypes,
        ] {
            assert_eq!(
                normal.iter().filter(|visited| **visited == step).count(),
                1,
                "{step:?} must run exactly once on the normal route"
            );
        }

        let mut disabled = Vec::new();
        orchestrate_symbol_route(true, |step| disabled.push(step));
        assert_eq!(
            disabled,
            vec![
                // First finalize produces recovered/token names for LoadFinalizedNames to
                // feed globals; it does NOT rewrite decompiled.c (so the idempotency sentinel
                // does not block the second rewrite). string-ref is inert here (no globals.json).
                SymbolRouteStep::Finalize {
                    rewrite_decompiled_c: false,
                },
                SymbolRouteStep::LoadFinalizedNames,
                SymbolRouteStep::RunGlobals(GlobalsRouteMode::RecordOnly),
                // Second finalize runs after globals.json exists, so the string-ref tier
                // activates; this pass rewrites decompiled.c with the full name set.
                SymbolRouteStep::Finalize {
                    rewrite_decompiled_c: true,
                },
                // This route has no pass 2 to feed, so shapes just need to run
                // once, after globals.json exists — unchanged last-position
                // timing versus the pre-reorder post-symbol-route placement.
                // Nothing rewrites the sidecar's inputs after this point, so
                // there is no re-commit step on this route.
                SymbolRouteStep::RunGlobalShapes,
            ]
        );
        assert_eq!(
            disabled
                .iter()
                .filter(|step| matches!(step, SymbolRouteStep::RunGlobals(_)))
                .count(),
            1
        );
        assert_eq!(
            disabled
                .iter()
                .filter(|step| matches!(step, SymbolRouteStep::RunGlobalShapes))
                .count(),
            1
        );
        assert!(!disabled.iter().any(|step| matches!(
            step,
            SymbolRouteStep::RunGlobals(GlobalsRouteMode::PrepareApplicationInput)
                | SymbolRouteStep::DispatchPass2
                | SymbolRouteStep::RefreshGlobalShapes
                | SymbolRouteStep::ApplyGlobalTypes
        )));

        let mut post = Vec::new();
        orchestrate_post_symbol_route(|step| post.push(step));
        assert_eq!(
            post,
            vec![PostSymbolStep::DecodeRf, PostSymbolStep::HardwareConfig]
        );

        // Combined: on the normal route, RunGlobalShapes precedes
        // DispatchPass2 (the whole point of the reorder); ApplyGlobalTypes
        // reports type application off the pass-2 outcomes; the closing
        // Finalize is the last input rewriter, and RefreshGlobalShapes
        // re-commits the sidecar over the tree's FINAL inputs strictly after
        // it — before the post-symbol RF/hwcfg stages (which rewrite no
        // hashed input).
        let mut combined = Vec::new();
        orchestrate_symbol_route(false, |step| combined.push(format!("{step:?}")));
        orchestrate_post_symbol_route(|step| combined.push(format!("{step:?}")));
        let shapes = combined
            .iter()
            .position(|step| step == "RunGlobalShapes")
            .expect("normal route runs RunGlobalShapes");
        let dispatch_pass2 = combined
            .iter()
            .position(|step| step == "DispatchPass2")
            .expect("normal route dispatches pass 2");
        let apply_types = combined
            .iter()
            .position(|step| step == "ApplyGlobalTypes")
            .expect("normal route reports global-types application");
        let finalize = combined
            .iter()
            .position(|step| step.starts_with("Finalize"))
            .expect("normal route ends with Finalize");
        let refresh_shapes = combined
            .iter()
            .position(|step| step == "RefreshGlobalShapes")
            .expect("normal route re-commits global_shapes after symbolicate_finalize");
        let decode_rf = combined.iter().position(|step| step == "DecodeRf").unwrap();
        let hardware = combined
            .iter()
            .position(|step| step == "HardwareConfig")
            .unwrap();
        assert!(
            shapes < dispatch_pass2
                && dispatch_pass2 < apply_types
                && apply_types < finalize
                && finalize < refresh_shapes
                && refresh_shapes < decode_rf
                && decode_rf < hardware,
            "{combined:?}"
        );
        assert_eq!(
            combined
                .iter()
                .filter(|step| step.as_str() == "RunGlobalShapes")
                .count(),
            1
        );
        assert_eq!(
            combined
                .iter()
                .filter(|step| step.as_str() == "RefreshGlobalShapes")
                .count(),
            1
        );
    }

    #[test]
    fn late_no_symbol_globals_uses_every_finalized_non_null_name_once() {
        // This catches the --no-symbol-pass route running globals before
        // symbolicate_finalize, bypassing the defensive symbols.json loader, or
        // filtering finalized Provisional names out of the cross-reference.
        let root = std::env::temp_dir().join(format!(
            "pme_globals_stage_no_symbol_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let images_dir = root.join("images");
        let image_dir = images_dir.join("02_MAIN");
        std::fs::create_dir_all(image_dir.join("decompiled")).unwrap();
        std::fs::write(image_dir.join("02_MAIN.bin"), b"raw bytes").unwrap();
        std::fs::write(
            image_dir.join("decompiled").join("symbols.json"),
            r#"{"symbols":[
                {"address":"0x00000040","name":"RecoveredMain"},
                {"address":"00000044","name":"guess_main_44"},
                {"address":"0x48","name":null},
                {"address":"not-hex","name":"MalformedAddress"}
            ]}"#,
        )
        .unwrap();
        let mut images = vec![analyzed_image("02_MAIN")];
        let function_inputs = PreparedGlobalsFunctionInputs {
            recovered_names: load_finalized_function_name_indexes(&images_dir, &images),
            evidence_names: HashMap::new(),
        };
        let mut calls = 0usize;

        let outcome = run_globals_stage_with(
            &mut images,
            &images_dir,
            &root.join("manifest.json"),
            &function_inputs,
            &globals::GlobalsOpts::default(),
            |image_dir, label, _, names, evidence_names, _| {
                calls += 1;
                assert_eq!(label, "02_MAIN");
                assert!(evidence_names.is_none());
                assert_eq!(
                    names,
                    &HashMap::from([
                        ("40".to_string(), "RecoveredMain".to_string()),
                        ("44".to_string(), "guess_main_44".to_string()),
                    ])
                );
                std::fs::write(image_dir.join("decompiled/globals.json"), b"globals").unwrap();
                Ok(globals::GlobalsReport {
                    recovered_count: 1,
                    conflicts_dropped: 0,
                    provisional_generated: 0,
                    provisional_suppressed_by_recovered: 0,
                })
            },
        );

        assert_eq!(calls, 1);
        assert_eq!(outcome.maps["02_MAIN"].pass2_map.count(), 1);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn direct_normal_route_moves_globals_payload_and_retains_only_typed_maps() {
        let mut function_maps = HashMap::from([(
            "02_MAIN".to_string(),
            PreparedFunctionMap {
                pass2_map: Some(prepared_symbol_test_map("moved-functions", "02_MAIN", 1)),
                creation_plan: Default::default(),
                function_names: HashMap::from([("40".to_string(), "RecoveredMain".to_string())]),
                evidence_name_projection: globals::FunctionEvidenceNameProjection::default(),
            },
        )]);

        let function_inputs = take_globals_function_inputs(&mut function_maps);

        assert_eq!(
            function_inputs.recovered_names["02_MAIN"]["40"],
            "RecoveredMain"
        );
        assert!(function_inputs.evidence_names.contains_key("02_MAIN"));
        assert!(function_maps["02_MAIN"].function_names.is_empty());
        assert!(
            function_maps["02_MAIN"]
                .evidence_name_projection
                .name_for(globals::Arch::Arm, 0x40)
                .is_none()
        );
        assert_eq!(
            function_maps["02_MAIN"]
                .pass2_map
                .as_ref()
                .unwrap()
                .execution_count(),
            1
        );
    }

    #[test]
    fn report_serializes_and_ok_reflects_failure() {
        let thumb_tools = crate::thumb_analysis::ThumbTools {
            radare2: producer_identity(
                crate::thumb_analysis::ThumbProducer::Radare2,
                "/usr/bin/r2",
                "radare2 6.1.4",
            ),
            rizin: Some(producer_identity(
                crate::thumb_analysis::ThumbProducer::Rizin,
                "/usr/bin/rizin",
                "rizin 0.8.2",
            )),
        };
        let stages = vec![
            StageReport::ok("extract", "manifest.json", 5),
            StageReport::decompile(
                vec![
                    ImageReport {
                        image: "02_MAIN".into(),
                        status: "analyzed",
                        classification: Some("not_opaque"),
                        skipped_reason: None,
                        functions: Some(3),
                        thumb_functions: Some(1),
                        thumb_regions_requested: None,
                        thumb_regions_succeeded: None,
                        thumb_regions_failed: None,
                        thumb_radare2_runs: None,
                        thumb_rizin_runs: None,
                        ghidra_execution_accepted: None,
                        ghidra_execution_quarantined: None,
                        thumb_execution_accepted: None,
                        thumb_execution_quarantined: None,
                        thumb_error: None,
                        terminal_error: None,
                        exit: None,
                        pass2_applied: None,
                        pass2_creation_candidates: None,
                        pass2_creation_map_skips: None,
                        pass2_created: None,
                        pass2_creation_reapplied: None,
                        pass2_creation_skipped_existing: None,
                        pass2_creation_skipped_collision: None,
                        pass2_error: None,
                        globals_applied: None,
                        globals_apply_skipped: None,
                        globals_apply_error: None,
                        thumb_decompiled: None,
                        thumb_tighten_error: None,
                        thumb_enrich_error: None,
                        globals_error: None,
                        globals_recovered: None,
                        globals_provisional: None,
                        globals_provisional_suppressed: None,
                        global_shapes_inferred: None,
                        global_shapes_no_evidence: None,
                        global_shapes_conflicting: None,
                        global_shape_observations: None,
                        global_shapes_ghidra_quarantined: None,
                        global_shapes_thumb_quarantined: None,
                        global_shapes_quarantine_errors: None,
                        global_shapes_decode_failures: None,
                        global_shapes_state_barriers: None,
                        global_shapes_error: None,
                        global_types_applied: None,
                        global_types_candidates: None,
                        global_types_ineligible: None,
                        global_types_skipped: None,
                        global_types_error: None,
                        exception_tables: None,
                        exception_roles: None,
                        exception_roots: None,
                        exception_functions_created: None,
                        exception_functions_reapplied: None,
                        exception_functions_existing: None,
                        exception_names_applied: None,
                        exception_names_reapplied: None,
                        exception_names_preserved: None,
                        exception_names_not_requested: None,
                        exception_shared_entries: None,
                        exception_error: None,
                        pal_tasks: None,
                        pal_entries: None,
                        pal_functions_created: None,
                        pal_functions_existing: None,
                        pal_names_applied: None,
                        pal_names_preserved: None,
                        pal_shared_entries: None,
                        dbt_records: None,
                        dbt_files: None,
                        dbt_messages: None,
                        dbt_quarantined: None,
                        dbt_unresolved_messages: None,
                        dbt_references: None,
                        dbt_refs_producers: None,
                    },
                    ImageReport {
                        image: "04_VSS".into(),
                        status: "failed",
                        classification: None,
                        skipped_reason: None,
                        functions: None,
                        thumb_functions: None,
                        thumb_regions_requested: None,
                        thumb_regions_succeeded: None,
                        thumb_regions_failed: None,
                        thumb_radare2_runs: None,
                        thumb_rizin_runs: None,
                        ghidra_execution_accepted: None,
                        ghidra_execution_quarantined: None,
                        thumb_execution_accepted: None,
                        thumb_execution_quarantined: None,
                        thumb_error: None,
                        terminal_error: None,
                        exit: Some(1),
                        pass2_applied: None,
                        pass2_creation_candidates: None,
                        pass2_creation_map_skips: None,
                        pass2_created: None,
                        pass2_creation_reapplied: None,
                        pass2_creation_skipped_existing: None,
                        pass2_creation_skipped_collision: None,
                        pass2_error: None,
                        globals_applied: None,
                        globals_apply_skipped: None,
                        globals_apply_error: None,
                        thumb_decompiled: None,
                        thumb_tighten_error: None,
                        thumb_enrich_error: None,
                        globals_error: None,
                        globals_recovered: None,
                        globals_provisional: None,
                        globals_provisional_suppressed: None,
                        global_shapes_inferred: None,
                        global_shapes_no_evidence: None,
                        global_shapes_conflicting: None,
                        global_shape_observations: None,
                        global_shapes_ghidra_quarantined: None,
                        global_shapes_thumb_quarantined: None,
                        global_shapes_quarantine_errors: None,
                        global_shapes_decode_failures: None,
                        global_shapes_state_barriers: None,
                        global_shapes_error: None,
                        global_types_applied: None,
                        global_types_candidates: None,
                        global_types_ineligible: None,
                        global_types_skipped: None,
                        global_types_error: None,
                        exception_tables: None,
                        exception_roles: None,
                        exception_roots: None,
                        exception_functions_created: None,
                        exception_functions_reapplied: None,
                        exception_functions_existing: None,
                        exception_names_applied: None,
                        exception_names_reapplied: None,
                        exception_names_preserved: None,
                        exception_names_not_requested: None,
                        exception_shared_entries: None,
                        exception_error: None,
                        pal_tasks: None,
                        pal_entries: None,
                        pal_functions_created: None,
                        pal_functions_existing: None,
                        pal_names_applied: None,
                        pal_names_preserved: None,
                        pal_shared_entries: None,
                        dbt_records: None,
                        dbt_files: None,
                        dbt_messages: None,
                        dbt_quarantined: None,
                        dbt_unresolved_messages: None,
                        dbt_references: None,
                        dbt_refs_producers: None,
                    },
                ],
                10,
            ),
            StageReport::skipped("decode_tokens", "no pw_token_db"),
            StageReport::ok(
                "source_attribution",
                "images/02_MAIN/source_tree/recovered_index.json",
                7,
            ),
        ];
        assert!(!Report::is_ok(&stages), "a failed image => not ok");

        let report = Report {
            tool_version: "1.0.0".into(),
            source_image: "radio.img".into(),
            source_blake3: "abc".into(),
            modem_generation: None,
            out: "radio.decomposed".into(),
            ghidra: analysis_tools(
                Path::new("/g/analyzeHeadless"),
                &analysis_opts(true),
                &thumb_tools,
            ),
            prune_requested: false,
            pruned: false,
            ok: Report::is_ok(&stages),
            stages,
        };
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&report).unwrap()).unwrap();
        assert_eq!(v["ok"], false);
        assert_eq!(v["stages"][0]["stage"], "extract");
        assert_eq!(v["stages"][1]["status"], "failed");
        assert_eq!(v["stages"][1]["images"][0]["functions"], 3);
        assert_eq!(v["stages"][1]["images"][1]["exit"], 1);
        assert_eq!(v["stages"][2]["status"], "skipped");
        assert_eq!(v["stages"][2]["reason"], "no pw_token_db");
        assert_eq!(
            v["ghidra"],
            serde_json::json!({
                "headless": "/g/analyzeHeadless",
                "radare2": "/usr/bin/r2",
                "radare2_version": "radare2 6.1.4",
                "rizin_fallback": true,
                "rizin": "/usr/bin/rizin",
                "rizin_version": "rizin 0.8.2"
            })
        );
        let stage = |name: &str| {
            v["stages"]
                .as_array()
                .unwrap()
                .iter()
                .find(|s| s["stage"] == name)
                .unwrap_or_else(|| panic!("missing stage {name}"))
        };
        assert_eq!(
            stage("source_attribution")["output"],
            "images/02_MAIN/source_tree/recovered_index.json"
        );

        // skip_serializing_if must actually omit fields — guards against the attrs being dropped
        assert!(
            v["stages"][0].get("images").is_none(),
            "ok stage omits empty images"
        );
        assert!(
            v["stages"][0].get("reason").is_none(),
            "ok stage omits reason"
        );
        assert!(
            v["stages"][0].get("error").is_none(),
            "ok stage omits error"
        );
        assert!(
            v["stages"][1]["images"][0].get("exit").is_none(),
            "analyzed image omits exit"
        );
        assert!(
            v["stages"][1]["images"][0].get("thumb_error").is_none(),
            "successful image omits thumb_error"
        );
        assert!(
            v["stages"][1]["images"][1].get("functions").is_none(),
            "failed image omits functions"
        );
        assert!(
            v["stages"][1]["images"][1].get("thumb_functions").is_none(),
            "failed image omits thumb_functions"
        );
        assert!(
            v["stages"][2].get("output").is_none(),
            "skipped stage omits output"
        );
        assert!(
            v["stages"][2].get("images").is_none(),
            "skipped stage omits images"
        );
    }

    #[test]
    fn report_ok_when_no_failures() {
        let stages = vec![
            StageReport::ok("extract", "manifest.json", 1),
            StageReport::skipped("decode_tokens", "no pw_token_db"),
        ];
        assert!(Report::is_ok(&stages));
    }

    #[test]
    fn analysis_tools_serialize_exact_enabled_and_disabled_identities() {
        let radare2 = producer_identity(
            crate::thumb_analysis::ThumbProducer::Radare2,
            "/usr/bin/r2",
            "radare2 6.1.4",
        );
        let rizin = producer_identity(
            crate::thumb_analysis::ThumbProducer::Rizin,
            "/usr/bin/rizin",
            "rizin 0.8.2",
        );
        for (enabled, expected) in [
            (
                false,
                serde_json::json!({
                    "headless": "/g/analyzeHeadless",
                    "radare2": "/usr/bin/r2",
                    "radare2_version": "radare2 6.1.4",
                    "rizin_fallback": false
                }),
            ),
            (
                true,
                serde_json::json!({
                    "headless": "/g/analyzeHeadless",
                    "radare2": "/usr/bin/r2",
                    "radare2_version": "radare2 6.1.4",
                    "rizin_fallback": true,
                    "rizin": "/usr/bin/rizin",
                    "rizin_version": "rizin 0.8.2"
                }),
            ),
        ] {
            let tools = crate::thumb_analysis::ThumbTools {
                radare2: radare2.clone(),
                rizin: enabled.then(|| rizin.clone()),
            };
            let json = serde_json::to_value(analysis_tools(
                Path::new("/g/analyzeHeadless"),
                &analysis_opts(enabled),
                &tools,
            ))
            .unwrap();
            assert_eq!(json, expected);
        }
    }

    #[test]
    fn image_report_distinguishes_uninvoked_executed_zero_and_failed_global_application() {
        // This catches the ImageReport mirror dropping the raw pass-2 outcome,
        // collapsing executed zero into absent, or serializing stale success
        // counts together with an application error.
        let mut uninvoked = analyzed_image("02_MAIN");
        uninvoked.pass2_applied = Some(3);
        let uninvoked_json = serde_json::to_value(ImageReport::from_result(&uninvoked)).unwrap();
        assert_eq!(
            uninvoked_json,
            serde_json::json!({
                "image": "02_MAIN",
                "status": "analyzed",
                "classification": "not_opaque",
                "functions": 1,
                "pass2_applied": 3
            })
        );

        let mut executed_zero = analyzed_image("03_APM");
        executed_zero.pass2_applied = Some(2);
        executed_zero.globals_applied = Some(0);
        executed_zero.globals_apply_skipped = Some(4);
        let executed_zero_json =
            serde_json::to_value(ImageReport::from_result(&executed_zero)).unwrap();
        assert_eq!(
            executed_zero_json,
            serde_json::json!({
                "image": "03_APM",
                "status": "analyzed",
                "classification": "not_opaque",
                "functions": 1,
                "pass2_applied": 2,
                "globals_applied": 0,
                "globals_apply_skipped": 4
            })
        );

        let mut failed = analyzed_image("04_VSS");
        failed.globals_apply_error = Some("missing ApplyGlobals summary".into());
        let failed_json = serde_json::to_value(ImageReport::from_result(&failed)).unwrap();
        assert_eq!(
            failed_json,
            serde_json::json!({
                "image": "04_VSS",
                "status": "analyzed",
                "classification": "not_opaque",
                "functions": 1,
                "globals_apply_error": "missing ApplyGlobals summary"
            })
        );
    }

    #[test]
    fn decompile_report_marks_analyzed_image_failed_on_thumb_error() {
        let image = ImageReport::from_result(&decompile::ImageResult {
            label: "02_MAIN".into(),
            outcome: ImageOutcome::Analyzed(42),
            classification: Some("not_opaque"),
            thumb_functions: None,
            thumb_regions_requested: None,
            thumb_regions_succeeded: None,
            thumb_regions_failed: None,
            thumb_radare2_runs: None,
            thumb_rizin_runs: None,
            ghidra_execution_accepted: None,
            ghidra_execution_quarantined: None,
            thumb_execution_accepted: None,
            thumb_execution_quarantined: None,
            image_start: 0,
            image_len: 0,
            thumb_error: Some("radare2 parser rejected empty stdout".into()),
            terminal_error: None,
            pass2_applied: None,
            pass2_creation_plan: None,
            pass2_thumb_names: None,
            pass2_error: None,
            thumb_decompiled: None,
            thumb_tighten_error: None,
            thumb_enrich_error: None,
            globals_error: None,
            globals_recovered: None,
            globals_applied: None,
            globals_apply_skipped: None,
            globals_apply_error: None,
            global_types_applied: None,
            global_types_apply_skipped: None,
            global_types_apply_error: None,
            globals_provisional: None,
            globals_provisional_suppressed: None,
            exception_state: decompile::RuntimeExceptionState::Unmanaged,
            exception_roots_applied: None,
            exception_error: None,
            pal_applied: None,
        });
        assert_eq!(image.status, "failed");
        assert_eq!(image.functions, Some(42));
        assert_eq!(
            image.thumb_error.as_deref(),
            Some("radare2 parser rejected empty stdout")
        );

        let stage = StageReport::decompile(vec![image], 3);
        assert_eq!(stage.status, "failed");

        let v: serde_json::Value = serde_json::to_value(&stage).unwrap();
        assert_eq!(
            v["images"][0]["thumb_error"],
            "radare2 parser rejected empty stdout"
        );
    }

    #[test]
    fn decompile_report_keeps_analyzed_status_without_thumb_outcome() {
        let image = ImageReport::from_result(&decompile::ImageResult {
            label: "01_BOOT".into(),
            outcome: ImageOutcome::Analyzed(7),
            classification: Some("not_opaque"),
            thumb_functions: None,
            thumb_regions_requested: None,
            thumb_regions_succeeded: None,
            thumb_regions_failed: None,
            thumb_radare2_runs: None,
            thumb_rizin_runs: None,
            ghidra_execution_accepted: None,
            ghidra_execution_quarantined: None,
            thumb_execution_accepted: None,
            thumb_execution_quarantined: None,
            image_start: 0,
            image_len: 0,
            thumb_error: None,
            terminal_error: None,
            pass2_applied: None,
            pass2_creation_plan: None,
            pass2_thumb_names: None,
            pass2_error: None,
            thumb_decompiled: None,
            thumb_tighten_error: None,
            thumb_enrich_error: None,
            globals_error: None,
            globals_recovered: None,
            globals_applied: None,
            globals_apply_skipped: None,
            globals_apply_error: None,
            global_types_applied: None,
            global_types_apply_skipped: None,
            global_types_apply_error: None,
            globals_provisional: None,
            globals_provisional_suppressed: None,
            exception_state: decompile::RuntimeExceptionState::Unmanaged,
            exception_roots_applied: None,
            exception_error: None,
            pal_applied: None,
        });

        assert_eq!(image.status, "analyzed");
        assert_eq!(image.functions, Some(7));
        assert!(image.thumb_functions.is_none());
        assert!(image.thumb_error.is_none());
    }

    #[test]
    fn image_report_carries_current_execution_projection_counters() {
        let mut result = tagged_image("02_MAIN", true);
        result.outcome = ImageOutcome::Analyzed(1);

        let image = ImageReport::from_result(&result);

        assert_eq!(image.functions, Some(1));
        assert_eq!(image.ghidra_execution_accepted, Some(1));
        assert_eq!(image.ghidra_execution_quarantined, Some(0));
        assert_eq!(image.thumb_functions, Some(1));
        assert_eq!(image.thumb_execution_accepted, Some(1));
        assert_eq!(image.thumb_execution_quarantined, Some(0));
    }

    #[test]
    fn terminal_inventory_rejects_current_report_count_mismatch() {
        let root = std::env::temp_dir().join(format!(
            "pme_terminal_count_mismatch_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("functions.json"), tagged_functions("current")).unwrap();
        let mut image = tagged_image("02_MAIN", false);
        image.outcome = ImageOutcome::Analyzed(2);

        assert!(
            decompile::validate_image_terminal_inventory(
                &root.join("functions.json"),
                &root.join("thumb_functions.json"),
                &image,
                None,
            )
            .is_err()
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn run_thumb_enrich_per_image_populates_count_and_skips_images_without_thumb_json() {
        let root =
            std::env::temp_dir().join(format!("pme_thumb_enrich_loop_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        // Image A: has thumb_functions.json + matching decompiled.c.
        let dec_a = root.join("images").join("02_MAIN").join("decompiled");
        std::fs::create_dir_all(&dec_a).unwrap();
        std::fs::write(
            dec_a.join("decompiled.c"),
            // Phase 2.1: thumb_enrich parses ExportDecomp.java's
            // `// <name> @ <addr>` header (address-keyed, T-bit normalized);
            // the function entry `0x4000` matches the normalized `00004000`.
            "// FUN_4000 @ 00004000\nvoid FUN_4000(void)\n{\n  return;\n}\n\n",
        )
        .unwrap();
        std::fs::write(dec_a.join("thumb_functions.json"), tagged_thumb_functions()).unwrap();
        std::fs::write(root.join("images/02_MAIN/02_MAIN.bin"), vec![0u8; 0x40]).unwrap();
        // Image B: no thumb_functions.json (no Thumb regions on this image).
        let dec_b = root.join("images").join("01_BOOT").join("decompiled");
        std::fs::create_dir_all(&dec_b).unwrap();

        let mut images = vec![
            decompile::ImageResult {
                label: "02_MAIN".into(),
                outcome: ImageOutcome::Analyzed(10),
                classification: Some("not_opaque"),
                thumb_functions: Some(1),
                thumb_regions_requested: None,
                thumb_regions_succeeded: None,
                thumb_regions_failed: None,
                thumb_radare2_runs: None,
                thumb_rizin_runs: None,
                ghidra_execution_accepted: None,
                ghidra_execution_quarantined: None,
                thumb_execution_accepted: None,
                thumb_execution_quarantined: None,
                image_start: 0x4000,
                image_len: 0x40,
                thumb_error: None,
                terminal_error: None,
                pass2_applied: None,
                pass2_creation_plan: None,
                pass2_thumb_names: None,
                pass2_error: None,
                thumb_decompiled: None,
                thumb_tighten_error: None,
                thumb_enrich_error: None,
                globals_error: None,
                globals_recovered: None,
                globals_applied: None,
                globals_apply_skipped: None,
                globals_apply_error: None,
                global_types_applied: None,
                global_types_apply_skipped: None,
                global_types_apply_error: None,
                globals_provisional: None,
                globals_provisional_suppressed: None,
                exception_state: decompile::RuntimeExceptionState::Unmanaged,
                exception_roots_applied: None,
                exception_error: None,
                pal_applied: None,
            },
            decompile::ImageResult {
                label: "01_BOOT".into(),
                outcome: ImageOutcome::Analyzed(3),
                classification: Some("not_opaque"),
                thumb_functions: None,
                thumb_regions_requested: None,
                thumb_regions_succeeded: None,
                thumb_regions_failed: None,
                thumb_radare2_runs: None,
                thumb_rizin_runs: None,
                ghidra_execution_accepted: None,
                ghidra_execution_quarantined: None,
                thumb_execution_accepted: None,
                thumb_execution_quarantined: None,
                image_start: 0,
                image_len: 0,
                thumb_error: None,
                terminal_error: None,
                pass2_applied: None,
                pass2_creation_plan: None,
                pass2_thumb_names: None,
                pass2_error: None,
                thumb_decompiled: None,
                thumb_tighten_error: None,
                thumb_enrich_error: None,
                globals_error: None,
                globals_recovered: None,
                globals_applied: None,
                globals_apply_skipped: None,
                globals_apply_error: None,
                global_types_applied: None,
                global_types_apply_skipped: None,
                global_types_apply_error: None,
                globals_provisional: None,
                globals_provisional_suppressed: None,
                exception_state: decompile::RuntimeExceptionState::Unmanaged,
                exception_roots_applied: None,
                exception_error: None,
                pal_applied: None,
            },
        ];
        let images_dir = root.join("images");
        let outcome = run_thumb_enrich_per_image(&mut images, &images_dir);

        assert_eq!(outcome.counts.len(), 1, "only 02_MAIN had a thumb json");
        assert_eq!(outcome.counts[0].0, "02_MAIN");
        assert_eq!(outcome.counts[0].1, 1, "one body_c populated");
        assert!(outcome.errors.is_empty());
        assert_eq!(images[0].thumb_decompiled, Some(1));
        assert!(images[0].thumb_enrich_error.is_none());
        // Image B without thumb json is unchanged.
        assert!(images[1].thumb_decompiled.is_none());
        assert!(images[1].thumb_enrich_error.is_none());

        // The StageReport shape produced from this outcome.
        let stage = thumb_enrich_stage("thumb_enrich", outcome, 0);
        assert_eq!(stage.stage, "thumb_enrich");
        assert_eq!(stage.status, "ok");
        assert_eq!(stage.output.as_deref(), Some("1 image(s) enriched"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn run_thumb_enrich_per_image_reports_missing_json_after_thumb_success() {
        let root = std::env::temp_dir().join(format!(
            "pme_thumb_enrich_missing_json_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        // decompiled.c present; thumb_functions.json deliberately absent.
        let dec = root.join("images").join("02_MAIN").join("decompiled");
        std::fs::create_dir_all(&dec).unwrap();
        std::fs::write(
            dec.join("decompiled.c"),
            "// FUN_40e1200 @ 00040e1200\nvoid FUN_40e1200(void)\n{\n  return;\n}\n\n",
        )
        .unwrap();

        let mut images = vec![decompile::ImageResult {
            label: "02_MAIN".into(),
            outcome: ImageOutcome::Analyzed(10),
            classification: Some("not_opaque"),
            // In-memory result says radare2 produced Thumb output.
            thumb_functions: Some(5),
            thumb_regions_requested: None,
            thumb_regions_succeeded: None,
            thumb_regions_failed: None,
            thumb_radare2_runs: None,
            thumb_rizin_runs: None,
            ghidra_execution_accepted: None,
            ghidra_execution_quarantined: None,
            thumb_execution_accepted: None,
            thumb_execution_quarantined: None,
            image_start: 0,
            image_len: 0,
            thumb_error: None,
            terminal_error: None,
            pass2_applied: None,
            pass2_creation_plan: None,
            pass2_thumb_names: None,
            pass2_error: None,
            thumb_decompiled: None,
            thumb_tighten_error: None,
            thumb_enrich_error: None,
            globals_error: None,
            globals_recovered: None,
            globals_applied: None,
            globals_apply_skipped: None,
            globals_apply_error: None,
            global_types_applied: None,
            global_types_apply_skipped: None,
            global_types_apply_error: None,
            globals_provisional: None,
            globals_provisional_suppressed: None,
            exception_state: decompile::RuntimeExceptionState::Unmanaged,
            exception_roots_applied: None,
            exception_error: None,
            pal_applied: None,
        }];
        let outcome = run_thumb_enrich_per_image(&mut images, &root.join("images"));

        assert!(
            outcome.counts.is_empty(),
            "missing JSON must not count as enriched"
        );
        assert_eq!(outcome.errors.len(), 1, "must surface one per-image error");
        assert_eq!(outcome.errors[0].0, "02_MAIN");
        assert!(
            outcome.errors[0].1.contains("thumb_functions.json")
                || outcome.errors[0].1.contains("missing"),
            "error text must name the missing artifact, got: {}",
            outcome.errors[0].1
        );
        assert!(images[0].thumb_decompiled.is_none());
        assert!(
            images[0].thumb_enrich_error.is_some(),
            "ImageResult.thumb_enrich_error must be set"
        );

        let stage = thumb_enrich_stage("thumb_enrich_post_pass2", outcome, 0);
        assert_eq!(stage.status, "failed");
        assert!(stage.error.is_some());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn refresh_decompile_stage_images_surfaces_post_enrich_fields() {
        // Phase 2.1 followup regression: the `decompile` StageReport is pushed
        // before thumb_enrich runs, so its per-image entries carry pre-enrich
        // state (thumb_decompiled = None). After thumb_enrich mutates each
        // ImageResult.thumb_decompiled, refresh_decompile_stage_images must
        // re-marshal the image entries from the updated ImageResult slice so
        // the report surfaces the post-enrich count. Without this refresh,
        // thumb_enrich populated 80k+ body_c on production but the count was
        // invisible in report.json under `--no-symbol-pass`.
        let pre_enrich_images = vec![ImageReport {
            image: "02_MAIN".into(),
            status: "analyzed",
            classification: Some("not_opaque"),
            skipped_reason: None,
            functions: Some(107_955),
            thumb_functions: Some(117_444),
            thumb_regions_requested: None,
            thumb_regions_succeeded: None,
            thumb_regions_failed: None,
            thumb_radare2_runs: None,
            thumb_rizin_runs: None,
            ghidra_execution_accepted: None,
            ghidra_execution_quarantined: None,
            thumb_execution_accepted: None,
            thumb_execution_quarantined: None,
            thumb_error: None,
            terminal_error: None,
            exit: None,
            pass2_applied: None,
            pass2_creation_candidates: None,
            pass2_creation_map_skips: None,
            pass2_created: None,
            pass2_creation_reapplied: None,
            pass2_creation_skipped_existing: None,
            pass2_creation_skipped_collision: None,
            pass2_error: None,
            globals_applied: None,
            globals_apply_skipped: None,
            globals_apply_error: None,
            thumb_decompiled: None, // pre-enrich
            thumb_tighten_error: None,
            thumb_enrich_error: None,
            globals_error: None,
            globals_recovered: None,
            globals_provisional: None,
            globals_provisional_suppressed: None,
            global_shapes_inferred: None,
            global_shapes_no_evidence: None,
            global_shapes_conflicting: None,
            global_shape_observations: None,
            global_shapes_ghidra_quarantined: None,
            global_shapes_thumb_quarantined: None,
            global_shapes_quarantine_errors: None,
            global_shapes_decode_failures: None,
            global_shapes_state_barriers: None,
            global_shapes_error: None,
            global_types_applied: None,
            global_types_candidates: None,
            global_types_ineligible: None,
            global_types_skipped: None,
            global_types_error: None,
            exception_tables: None,
            exception_roles: None,
            exception_roots: None,
            exception_functions_created: None,
            exception_functions_reapplied: None,
            exception_functions_existing: None,
            exception_names_applied: None,
            exception_names_reapplied: None,
            exception_names_preserved: None,
            exception_names_not_requested: None,
            exception_shared_entries: None,
            exception_error: None,
            pal_tasks: None,
            pal_entries: None,
            pal_functions_created: None,
            pal_functions_existing: None,
            pal_names_applied: None,
            pal_names_preserved: None,
            pal_shared_entries: None,
            dbt_records: None,
            dbt_files: None,
            dbt_messages: None,
            dbt_quarantined: None,
            dbt_unresolved_messages: None,
            dbt_references: None,
            dbt_refs_producers: None,
        }];
        let mut stages = vec![StageReport::decompile(pre_enrich_images, 12345)];

        // Simulate thumb_enrich mutating ImageResult.
        let post_enrich_images = vec![decompile::ImageResult {
            label: "02_MAIN".into(),
            outcome: decompile::ImageOutcome::Analyzed(107_955),
            classification: Some("not_opaque"),
            thumb_functions: Some(117_444),
            thumb_regions_requested: None,
            thumb_regions_succeeded: None,
            thumb_regions_failed: None,
            thumb_radare2_runs: None,
            thumb_rizin_runs: None,
            ghidra_execution_accepted: None,
            ghidra_execution_quarantined: None,
            thumb_execution_accepted: None,
            thumb_execution_quarantined: None,
            image_start: 0,
            image_len: 0,
            thumb_error: None,
            terminal_error: None,
            pass2_applied: None,
            pass2_creation_plan: None,
            pass2_thumb_names: None,
            pass2_error: None,
            thumb_decompiled: Some(81_763), // post-enrich
            thumb_tighten_error: None,
            thumb_enrich_error: None,
            globals_error: None,
            globals_recovered: None,
            globals_applied: None,
            globals_apply_skipped: None,
            globals_apply_error: None,
            global_types_applied: None,
            global_types_apply_skipped: None,
            global_types_apply_error: None,
            globals_provisional: None,
            globals_provisional_suppressed: None,
            exception_state: decompile::RuntimeExceptionState::Unmanaged,
            exception_roots_applied: None,
            exception_error: None,
            pal_applied: None,
        }];

        refresh_decompile_stage_images(&mut stages, &post_enrich_images);

        // The decompile stage entry is updated in place; duration_ms preserved.
        assert_eq!(stages[0].stage, "decompile");
        assert_eq!(stages[0].duration_ms, 12345);
        assert_eq!(stages[0].images.len(), 1);
        assert_eq!(
            stages[0].images[0].thumb_decompiled,
            Some(81_763),
            "refresh must surface the post-enrich thumb_decompiled count"
        );
    }

    #[test]
    fn refresh_decompile_stage_images_no_op_when_no_decompile_stage() {
        // Defensive: if no `decompile` stage exists (e.g. earlier marshal
        // failure pushed a `failed` stage instead), refresh is a no-op.
        let mut stages: Vec<StageReport> = vec![StageReport::skipped("extract", "test")];
        let images = vec![];
        refresh_decompile_stage_images(&mut stages, &images);
        assert_eq!(stages.len(), 1, "no decompile stage to refresh");
    }

    #[test]
    fn run_thumb_enrich_per_image_records_error_on_missing_decompiled_c() {
        let root =
            std::env::temp_dir().join(format!("pme_thumb_enrich_err_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dec = root.join("images").join("02_MAIN").join("decompiled");
        std::fs::create_dir_all(&dec).unwrap();
        // thumb_functions.json exists but decompiled.c is absent -> Err.
        std::fs::write(
            dec.join("thumb_functions.json"),
            r#"{"format":"pixel-modem-extractor-thumb-functions-v1","functions":[]}"#,
        )
        .unwrap();

        let mut images = vec![decompile::ImageResult {
            label: "02_MAIN".into(),
            outcome: ImageOutcome::Analyzed(0),
            classification: Some("not_opaque"),
            thumb_functions: Some(0),
            thumb_regions_requested: None,
            thumb_regions_succeeded: None,
            thumb_regions_failed: None,
            thumb_radare2_runs: None,
            thumb_rizin_runs: None,
            ghidra_execution_accepted: None,
            ghidra_execution_quarantined: None,
            thumb_execution_accepted: None,
            thumb_execution_quarantined: None,
            image_start: 0,
            image_len: 0,
            thumb_error: None,
            terminal_error: None,
            pass2_applied: None,
            pass2_creation_plan: None,
            pass2_thumb_names: None,
            pass2_error: None,
            thumb_decompiled: None,
            thumb_tighten_error: None,
            thumb_enrich_error: None,
            globals_error: None,
            globals_recovered: None,
            globals_applied: None,
            globals_apply_skipped: None,
            globals_apply_error: None,
            global_types_applied: None,
            global_types_apply_skipped: None,
            global_types_apply_error: None,
            globals_provisional: None,
            globals_provisional_suppressed: None,
            exception_state: decompile::RuntimeExceptionState::Unmanaged,
            exception_roots_applied: None,
            exception_error: None,
            pal_applied: None,
        }];
        let outcome = run_thumb_enrich_per_image(&mut images, &root.join("images"));
        assert_eq!(outcome.counts.len(), 0);
        assert_eq!(
            outcome.errors.len(),
            1,
            "missing decompiled.c surfaces as error"
        );
        assert!(images[0].thumb_decompiled.is_none());
        assert!(images[0].thumb_enrich_error.is_some());

        let stage = thumb_enrich_stage("thumb_enrich", outcome, 0);
        assert_eq!(stage.status, "failed");
        assert!(stage.error.is_some());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn preflight_requires_primary_tools_and_discovers_rizin_only_when_enabled() {
        let g = PathBuf::from("/opt/ghidra/support/analyzeHeadless");
        let r = producer_identity(
            crate::thumb_analysis::ThumbProducer::Radare2,
            "/usr/bin/r2",
            "radare2 6.1.4",
        );
        let z = producer_identity(
            crate::thumb_analysis::ThumbProducer::Rizin,
            "/usr/bin/rizin",
            "rizin 0.8.2",
        );

        let (_, tools) = preflight(Ok(g.clone()), Ok(r.clone()), false, || -> Result<_> {
            panic!("disabled Rizin fallback must not run discovery")
        })
        .unwrap();
        assert_eq!(tools.radare2, r);
        assert!(tools.rizin.is_none());

        let (_, tools) = preflight(Ok(g.clone()), Ok(r.clone()), true, || Ok(z.clone())).unwrap();
        assert_eq!(tools.rizin, Some(z));

        assert!(matches!(
            preflight(
                Err(Error::GhidraNotFound("x".into())),
                Ok(r.clone()),
                false,
                || unreachable!()
            ),
            Err(Error::GhidraNotFound(_))
        ));
        assert!(matches!(
            preflight(
                Ok(g.clone()),
                Err(Error::ToolNotFound("radare2 unavailable".into())),
                false,
                || unreachable!()
            ),
            Err(Error::ToolNotFound(_))
        ));
        assert!(matches!(
            preflight(Ok(g), Ok(r), true, || {
                Err(Error::ToolNotFound("Rizin unavailable".into()))
            }),
            Err(Error::ToolNotFound(reason)) if reason == "Rizin unavailable"
        ));
    }

    #[test]
    fn preflight_tools_reach_decompile_and_report_unchanged() {
        let headless = PathBuf::from("/preflight/ghidra/analyzeHeadless");
        let mut radare2 = producer_identity(
            crate::thumb_analysis::ThumbProducer::Radare2,
            "/preflight/r2-exact",
            "radare2 exact version",
        );
        radare2.command = "radare2 exact command";
        let mut rizin = producer_identity(
            crate::thumb_analysis::ThumbProducer::Rizin,
            "/preflight/rizin-exact",
            "rizin exact version",
        );
        rizin.command = "rizin exact command";
        let expected = crate::thumb_analysis::ThumbTools {
            radare2: radare2.clone(),
            rizin: Some(rizin.clone()),
        };
        let (observed_headless, tools) =
            preflight(Ok(headless.clone()), Ok(radare2), true, || Ok(rizin)).unwrap();
        let decompile_opts = decompile::Opts {
            run: true,
            image: None,
            ghidra_home: None,
            processor: "ARM:LE:32:v7".into(),
            no_thumb_decompile: false,
            rizin_fallback: true,
            tighten_wall_clock_budget_override: None,
            no_skip_opaque: false,
        };
        let opts = Opts {
            no_verify: false,
            prune: false,
            ghidra_home: None,
            processor: "ARM:LE:32:v7".into(),
            no_symbol_pass: false,
            no_thumb_decompile: false,
            rizin_fallback: true,
            tighten_wall_clock_budget_override: None,
            globals_provisional: false,
            globals_k_arm: None,
            globals_k_thumb: None,
            no_apply_global_types: false,
            no_skip_opaque: false,
        };
        let decompile_calls = std::cell::Cell::new(0);

        assert_eq!(observed_headless, headless);
        assert_eq!(tools, expected);
        let error = run_decompile_report_with(
            Path::new("/input/modem.bin"),
            &decompile_opts,
            Path::new("/output/ghidra"),
            &tools,
            |modem_bin, observed_opts, out, observed_tools| {
                decompile_calls.set(decompile_calls.get() + 1);
                assert_eq!(modem_bin, Path::new("/input/modem.bin"));
                assert_eq!(out, Path::new("/output/ghidra"));
                assert!(observed_opts.run);
                assert!(observed_opts.rizin_fallback);
                assert!(std::ptr::eq(observed_tools, &tools));
                assert_eq!(observed_tools, &expected);
                Err(Error::Serialize("captured decompose ThumbTools".into()))
            },
        )
        .unwrap_err();
        assert!(
            matches!(error, Error::Serialize(reason) if reason == "captured decompose ThumbTools")
        );
        assert_eq!(decompile_calls.get(), 1);
        assert_eq!(
            serde_json::to_value(analysis_tools(&observed_headless, &opts, &tools)).unwrap(),
            serde_json::json!({
                "headless": "/preflight/ghidra/analyzeHeadless",
                "radare2": "/preflight/r2-exact",
                "radare2_version": "radare2 exact version",
                "rizin_fallback": true,
                "rizin": "/preflight/rizin-exact",
                "rizin_version": "rizin exact version"
            })
        );
    }

    #[test]
    fn marshal_moves_slice_export_and_scatter() {
        let root = std::env::temp_dir().join(format!("pme_marshal_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let ghidra = root.join("ghidra");
        std::fs::create_dir_all(ghidra.join("images")).unwrap();
        std::fs::create_dir_all(ghidra.join("export").join("02_MAIN")).unwrap();
        std::fs::create_dir_all(ghidra.join("scatter").join("02_MAIN").join("blocks")).unwrap();
        std::fs::write(ghidra.join("images").join("02_MAIN"), b"slice").unwrap();
        std::fs::write(ghidra.join("export").join("02_MAIN").join("out.c"), b"// c").unwrap();
        std::fs::write(
            ghidra.join("scatter").join("02_MAIN").join("load_map.json"),
            b"{\"format\":\"scatter-test\"}",
        )
        .unwrap();
        std::fs::write(
            ghidra
                .join("scatter")
                .join("02_MAIN")
                .join("blocks")
                .join("04-decompress1.bin"),
            b"payload",
        )
        .unwrap();

        let images = root.join("images");
        std::fs::create_dir_all(images.join("02_MAIN").join("scatter")).unwrap();
        std::fs::write(
            images.join("02_MAIN").join("scatter").join("stale.bin"),
            b"stale",
        )
        .unwrap();
        std::fs::write(images.join("02_MAIN").join("sibling.bin"), b"sibling").unwrap();
        marshal_image(
            &ghidra,
            &images,
            "02_MAIN",
            true,
            &runtime_state(
                decompile::RuntimeScatterState::Present,
                decompile::RuntimeTaskState::Unmanaged,
                decompile::RuntimeExceptionState::Unmanaged,
            ),
            decompile::RuntimeScatterState::Present,
            PAL_BASE,
        )
        .unwrap();

        assert_eq!(
            std::fs::read(images.join("02_MAIN").join("02_MAIN.bin")).unwrap(),
            b"slice"
        );
        assert!(
            images
                .join("02_MAIN")
                .join("decompiled")
                .join("out.c")
                .exists()
        );
        assert_eq!(
            std::fs::read(images.join("02_MAIN").join("scatter").join("load_map.json")).unwrap(),
            b"{\"format\":\"scatter-test\"}"
        );
        assert_eq!(
            std::fs::read(
                images
                    .join("02_MAIN")
                    .join("scatter")
                    .join("blocks")
                    .join("04-decompress1.bin")
            )
            .unwrap(),
            b"payload"
        );
        assert!(
            !images
                .join("02_MAIN")
                .join("scatter")
                .join("stale.bin")
                .exists(),
            "the owned destination is replaced"
        );
        assert_eq!(
            std::fs::read(images.join("02_MAIN").join("sibling.bin")).unwrap(),
            b"sibling",
            "sibling per-image artifacts are preserved"
        );
        assert!(
            !ghidra.join("images").join("02_MAIN").exists(),
            "moved, not copied"
        );
        assert!(
            !ghidra.join("scatter").join("02_MAIN").exists(),
            "scatter artifacts are moved, not copied"
        );
    }

    #[test]
    fn marshal_reused_tree_replaces_a_valid_map_with_current_raw_only_state() {
        let root =
            std::env::temp_dir().join(format!("pme_marshal_raw_only_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let ghidra = root.join("ghidra");
        let current = ghidra.join("scatter/02_MAIN");
        std::fs::create_dir_all(current.join("blocks")).unwrap();
        std::fs::write(current.join("load_map.json"), b"current map").unwrap();
        std::fs::write(current.join("blocks/04-decompress1.bin"), b"payload").unwrap();
        let images = root.join("images");

        marshal_image(
            &ghidra,
            &images,
            "02_MAIN",
            false,
            &runtime_state(
                decompile::RuntimeScatterState::Present,
                decompile::RuntimeTaskState::Unmanaged,
                decompile::RuntimeExceptionState::Unmanaged,
            ),
            decompile::RuntimeScatterState::Present,
            PAL_BASE,
        )
        .unwrap();
        let scatter = images.join("02_MAIN/scatter");
        assert_eq!(
            std::fs::read(scatter.join("load_map.json")).unwrap(),
            b"current map"
        );
        std::fs::write(images.join("02_MAIN/sibling.bin"), b"preserve").unwrap();

        marshal_image(
            &ghidra,
            &images,
            "02_MAIN",
            false,
            &runtime_state(
                decompile::RuntimeScatterState::Absent,
                decompile::RuntimeTaskState::Unmanaged,
                decompile::RuntimeExceptionState::Unmanaged,
            ),
            decompile::RuntimeScatterState::Absent,
            PAL_BASE,
        )
        .unwrap();

        assert!(
            !scatter.exists(),
            "current NoCandidate must remove the stale map"
        );
        assert_eq!(
            std::fs::read(images.join("02_MAIN/sibling.bin")).unwrap(),
            b"preserve"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn marshal_noncurrent_run_preserves_terminal_artifacts_and_partial_sources() {
        let root =
            std::env::temp_dir().join(format!("pme_marshal_noncurrent_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let ghidra = root.join("ghidra");
        let partial_export = ghidra.join("export/02_MAIN");
        let uncommitted_scatter = ghidra.join("scatter/02_MAIN");
        std::fs::create_dir_all(&partial_export).unwrap();
        std::fs::create_dir_all(&uncommitted_scatter).unwrap();
        std::fs::write(partial_export.join("functions.json"), b"partial").unwrap();
        std::fs::write(uncommitted_scatter.join("load_map.json"), b"new").unwrap();

        let images = root.join("images");
        let terminal = images.join("02_MAIN");
        std::fs::create_dir_all(terminal.join("decompiled")).unwrap();
        std::fs::create_dir_all(terminal.join("scatter")).unwrap();
        std::fs::write(terminal.join("decompiled/functions.json"), b"old export").unwrap();
        std::fs::write(terminal.join("scatter/load_map.json"), b"old map").unwrap();

        marshal_image(
            &ghidra,
            &images,
            "02_MAIN",
            false,
            &runtime_state(
                decompile::RuntimeScatterState::Unmanaged,
                decompile::RuntimeTaskState::Unmanaged,
                decompile::RuntimeExceptionState::Unmanaged,
            ),
            decompile::RuntimeScatterState::Unmanaged,
            PAL_BASE,
        )
        .unwrap();

        assert_eq!(
            std::fs::read(terminal.join("decompiled/functions.json")).unwrap(),
            b"old export"
        );
        assert_eq!(
            std::fs::read(terminal.join("scatter/load_map.json")).unwrap(),
            b"old map"
        );
        assert!(partial_export.join("functions.json").exists());
        assert!(uncommitted_scatter.join("load_map.json").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn marshal_propagates_scatter_probe_errors() {
        let root =
            std::env::temp_dir().join(format!("pme_marshal_probe_error_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let ghidra = root.join("ghidra");
        std::fs::create_dir_all(&ghidra).unwrap();
        std::os::unix::fs::symlink("scatter", ghidra.join("scatter")).unwrap();
        let retained = root.join("images/02_MAIN/scatter/load_map.json");
        std::fs::create_dir_all(retained.parent().unwrap()).unwrap();
        std::fs::write(&retained, b"retained").unwrap();

        let error = marshal_image(
            &ghidra,
            &root.join("images"),
            "02_MAIN",
            false,
            &runtime_state(
                decompile::RuntimeScatterState::Present,
                decompile::RuntimeTaskState::Unmanaged,
                decompile::RuntimeExceptionState::Unmanaged,
            ),
            decompile::RuntimeScatterState::Present,
            PAL_BASE,
        )
        .expect_err("a scatter metadata error must not be treated as absence");

        assert!(matches!(error, Error::Io(_)));
        assert_eq!(std::fs::read(retained).unwrap(), b"retained");
        let _ = std::fs::remove_dir_all(&root);
    }

    // -------------------------------------------------------------------
    // Exception-root terminal marshalling and reporting (Task 9)
    // -------------------------------------------------------------------

    const EXCEPTION_BASE: u32 = 0x4001_0000;
    const EXCEPTION_LABEL: &str = "00_BOOT";

    struct ExceptionMarshalFixture {
        _root: tempfile::TempDir,
        ghidra_dir: PathBuf,
        images_dir: PathBuf,
        image_dir: PathBuf,
        source_manifest: PathBuf,
        terminal_manifest: PathBuf,
        state: decompile::RuntimeExceptionState,
        image_start: u32,
        scatter_state: decompile::RuntimeScatterState,
        manifest_bytes: Vec<u8>,
    }

    impl ExceptionMarshalFixture {
        fn present() -> Self {
            Self::present_for(EXCEPTION_LABEL, "BOOT")
        }

        fn present_for(label: &str, toc_name: &str) -> Self {
            let root = tempfile::tempdir().unwrap();
            let ghidra_dir = root.path().join("ghidra");
            let images_dir = root.path().join("images");
            let image_dir = images_dir.join(label);
            std::fs::create_dir_all(&ghidra_dir).unwrap();
            std::fs::create_dir_all(&image_dir).unwrap();
            let raw = exception_root_fixture_bytes();
            std::fs::write(image_dir.join(format!("{label}.bin")), &raw).unwrap();
            let runtime =
                crate::runtime_image::RuntimeImage::from_plan(&raw, EXCEPTION_BASE, None).unwrap();
            let plan = crate::exception_roots::discover(&runtime, label, toc_name)
                .unwrap()
                .expect("fixture has a complete exception table");
            let map = crate::exception_roots::materialize(
                &plan,
                crate::exception_roots::ExceptionArtifactContext {
                    label,
                    toc_name,
                    image_blake3: *blake3::hash(&raw).as_bytes(),
                    scatter_load_map_blake3: None,
                },
                &ghidra_dir,
            )
            .unwrap();
            let source_manifest = ghidra_dir.join(&map.relative_path);
            let manifest_bytes = std::fs::read(&source_manifest).unwrap();
            let terminal_manifest = image_dir.join("exception_roots/roots.json");
            Self {
                _root: root,
                ghidra_dir,
                images_dir,
                image_dir,
                source_manifest,
                terminal_manifest,
                state: decompile::RuntimeExceptionState::Present(map),
                image_start: EXCEPTION_BASE,
                // Scatter discovery is structurally MAIN-only. Production
                // records non-MAIN images as unmanaged, while exception-root
                // discovery still builds their runtime view explicitly raw-only.
                scatter_state: decompile::RuntimeScatterState::Unmanaged,
                manifest_bytes,
            }
        }

        fn absent() -> Self {
            let mut fixture = Self::present();
            fixture.state = decompile::RuntimeExceptionState::Absent;
            fixture
        }
    }

    fn exception_root_fixture_bytes() -> Vec<u8> {
        let mut raw = vec![0u8; 0x400];
        let targets = [0x200u32, 0x220, 0x240, 0x260, 0x280, 0x2c0, 0x2a0, 0x2c0];
        for (index, offset) in targets.into_iter().enumerate() {
            let slot = EXCEPTION_BASE + u32::try_from(index).unwrap() * 4;
            let target = EXCEPTION_BASE + offset;
            let displacement = (i64::from(target) - (i64::from(slot) + 8)) / 4;
            let branch = 0xea00_0000 | u32::try_from(displacement & 0x00ff_ffff).unwrap();
            raw[index * 4..index * 4 + 4].copy_from_slice(&branch.to_le_bytes());
            let target_offset = usize::try_from(offset).unwrap();
            raw[target_offset..target_offset + 4].copy_from_slice(&0xe12f_ff1eu32.to_le_bytes());
        }
        raw
    }

    fn exception_map(
        state: &decompile::RuntimeExceptionState,
    ) -> &crate::exception_roots::MaterializedExceptionRoots {
        match state {
            decompile::RuntimeExceptionState::Present(map) => map,
            _ => panic!("fixture exception state is present"),
        }
    }

    #[test]
    fn marshal_exception_present_validates_before_terminal_replace() {
        let fixture = ExceptionMarshalFixture::present();
        std::fs::create_dir_all(fixture.terminal_manifest.parent().unwrap()).unwrap();
        std::fs::write(&fixture.terminal_manifest, b"old-complete-manifest").unwrap();
        let error = marshal_exception_roots_with(
            &fixture.ghidra_dir,
            &fixture.images_dir,
            EXCEPTION_LABEL,
            &fixture.state,
            fixture.image_start,
            fixture.scatter_state,
            &mut |_from, _to| Err(std::io::Error::other("injected rename failure")),
        )
        .unwrap_err();
        assert!(error.to_string().contains("injected rename failure"));
        assert_eq!(
            std::fs::read(&fixture.terminal_manifest).unwrap(),
            b"old-complete-manifest"
        );
        assert_eq!(
            std::fs::read(&fixture.source_manifest).unwrap(),
            fixture.manifest_bytes
        );
    }

    #[test]
    fn marshal_exception_present_replaces_only_owned_manifest() {
        let fixture = ExceptionMarshalFixture::present();
        std::fs::create_dir_all(fixture.terminal_manifest.parent().unwrap()).unwrap();
        std::fs::write(&fixture.terminal_manifest, b"stale").unwrap();
        let foreign = fixture.image_dir.join("exception_roots/foreign.bin");
        std::fs::write(&foreign, b"foreign").unwrap();
        let stale_scatter = fixture.image_dir.join("scatter/load_map.json");
        std::fs::create_dir_all(stale_scatter.parent().unwrap()).unwrap();
        std::fs::write(&stale_scatter, b"stale-non-main-scatter").unwrap();

        marshal_exception_roots(
            &fixture.ghidra_dir,
            &fixture.images_dir,
            EXCEPTION_LABEL,
            &fixture.state,
            fixture.image_start,
            fixture.scatter_state,
        )
        .unwrap();

        assert_eq!(
            std::fs::read(&fixture.terminal_manifest).unwrap(),
            fixture.manifest_bytes
        );
        assert!(!fixture.source_manifest.exists());
        assert_eq!(std::fs::read(foreign).unwrap(), b"foreign");
        assert_eq!(
            std::fs::read(stale_scatter).unwrap(),
            b"stale-non-main-scatter",
            "raw-only exception validation must neither consume nor trust stale scatter"
        );
    }

    #[test]
    fn marshal_exception_absent_clears_only_owned_manifests() {
        let fixture = ExceptionMarshalFixture::absent();
        std::fs::create_dir_all(fixture.terminal_manifest.parent().unwrap()).unwrap();
        std::fs::write(&fixture.terminal_manifest, b"stale").unwrap();
        let foreign = fixture.image_dir.join("exception_roots/foreign.bin");
        std::fs::write(&foreign, b"foreign").unwrap();

        marshal_exception_roots(
            &fixture.ghidra_dir,
            &fixture.images_dir,
            EXCEPTION_LABEL,
            &fixture.state,
            fixture.image_start,
            fixture.scatter_state,
        )
        .unwrap();

        assert!(!fixture.terminal_manifest.exists());
        assert!(!fixture.source_manifest.exists());
        assert!(fixture.terminal_manifest.parent().unwrap().is_dir());
        assert_eq!(std::fs::read(foreign).unwrap(), b"foreign");
    }

    #[test]
    fn marshal_exception_unmanaged_preserves_terminal_and_source_bytes() {
        let mut fixture = ExceptionMarshalFixture::present();
        fixture.state = decompile::RuntimeExceptionState::Unmanaged;
        std::fs::create_dir_all(fixture.terminal_manifest.parent().unwrap()).unwrap();
        std::fs::write(&fixture.terminal_manifest, b"old-terminal").unwrap();
        std::fs::write(&fixture.source_manifest, b"old-source").unwrap();

        marshal_exception_roots(
            &fixture.ghidra_dir,
            &fixture.images_dir,
            EXCEPTION_LABEL,
            &fixture.state,
            fixture.image_start,
            fixture.scatter_state,
        )
        .unwrap();

        assert_eq!(
            std::fs::read(&fixture.terminal_manifest).unwrap(),
            b"old-terminal"
        );
        assert_eq!(
            std::fs::read(&fixture.source_manifest).unwrap(),
            b"old-source"
        );
    }

    #[test]
    fn marshal_exception_strict_context_mismatch_preserves_old_manifest() {
        let fixture = ExceptionMarshalFixture::present();
        std::fs::create_dir_all(fixture.terminal_manifest.parent().unwrap()).unwrap();
        std::fs::write(&fixture.terminal_manifest, b"old-terminal").unwrap();
        std::fs::write(
            fixture.image_dir.join(format!("{EXCEPTION_LABEL}.bin")),
            vec![0u8; 0x400],
        )
        .unwrap();

        let error = marshal_exception_roots(
            &fixture.ghidra_dir,
            &fixture.images_dir,
            EXCEPTION_LABEL,
            &fixture.state,
            fixture.image_start,
            fixture.scatter_state,
        )
        .unwrap_err();

        assert!(error.to_string().contains("exception"));
        assert_eq!(
            std::fs::read(&fixture.terminal_manifest).unwrap(),
            b"old-terminal"
        );
        assert!(fixture.source_manifest.is_file());
    }

    #[test]
    fn marshal_image_reports_exception_failure_without_hiding_later_images() {
        let fixture = ExceptionMarshalFixture::present();
        std::fs::create_dir_all(fixture.terminal_manifest.parent().unwrap()).unwrap();
        std::fs::write(&fixture.terminal_manifest, b"old-terminal").unwrap();
        std::fs::write(&fixture.source_manifest, b"not a current manifest").unwrap();

        let status = marshal_image(
            &fixture.ghidra_dir,
            &fixture.images_dir,
            EXCEPTION_LABEL,
            false,
            &runtime_state(
                fixture.scatter_state,
                decompile::RuntimeTaskState::Unmanaged,
                fixture.state.clone(),
            ),
            fixture.scatter_state,
            fixture.image_start,
        )
        .expect("exception marshalling has its own stage failure surface");

        assert!(
            matches!(status, ExceptionMarshalStatus::Failed(reason) if reason.contains("exception"))
        );
        assert_eq!(
            std::fs::read(&fixture.terminal_manifest).unwrap(),
            b"old-terminal"
        );
    }

    #[test]
    fn exception_roots_stage_reports_tallies_absence_and_failures() {
        let fixture = ExceptionMarshalFixture::present();
        let mut tally = ExceptionMarshalTally::default();
        tally.record(exception_map(&fixture.state)).unwrap();
        let ok = exception_roots_stage(Some(&tally), 0, &[], 9);
        assert_eq!(ok.stage, "exception_roots");
        assert_eq!(ok.status, "ok");
        assert_eq!(
            ok.output.as_deref(),
            Some("images/*/exception_roots/roots.json (images=1, tables=1, roots=7)")
        );
        assert_eq!(ok.duration_ms, 9);

        let skipped = exception_roots_stage(Some(&ExceptionMarshalTally::default()), 2, &[], 4);
        assert_eq!(skipped.status, "skipped");
        assert_eq!(
            skipped.reason.as_deref(),
            Some("no exception vector tables")
        );

        let failed = exception_roots_stage(
            Some(&ExceptionMarshalTally::default()),
            1,
            &[(
                "01_MAIN".into(),
                "current exception state is unmanaged".into(),
            )],
            5,
        );
        assert_eq!(failed.status, "failed");
        assert!(failed.error.as_deref().unwrap().contains("01_MAIN"));

        let unavailable = exception_roots_stage(None, 0, &[], 0);
        assert_eq!(unavailable.status, "failed");
        assert_eq!(
            unavailable.error.as_deref(),
            Some("pass 1 state unavailable")
        );
    }

    fn image_result_with_current_exception_manifest(
        outcome: ImageOutcome,
    ) -> decompile::ImageResult {
        let fixture = ExceptionMarshalFixture::present();
        let map = exception_map(&fixture.state).clone();
        let mut result = analyzed_image(EXCEPTION_LABEL);
        result.outcome = outcome;
        result.image_start = fixture.image_start;
        result.image_len = u32::try_from(exception_root_fixture_bytes().len()).unwrap();
        result.exception_state = decompile::RuntimeExceptionState::Present(map);
        result
    }

    #[test]
    fn image_report_serializes_exception_roots() {
        let fixture = ExceptionMarshalFixture::present();
        let map = exception_map(&fixture.state);
        let mut result = analyzed_image(EXCEPTION_LABEL);
        result.exception_state = fixture.state.clone();
        result.exception_roots_applied = Some(decompile::test_applied_exception_roots(
            EXCEPTION_LABEL,
            &map.identity,
        ));
        let report = ImageReport::from_result(&result);
        assert_eq!(report.exception_tables, Some(1));
        assert_eq!(report.exception_roles, Some(8));
        assert_eq!(report.exception_roots, Some(7));
        assert_eq!(report.exception_functions_created, Some(5));
        assert_eq!(report.exception_functions_reapplied, Some(0));
        assert_eq!(report.exception_functions_existing, Some(2));
        assert_eq!(report.exception_names_applied, Some(5));
        assert_eq!(report.exception_names_reapplied, Some(0));
        assert_eq!(report.exception_names_preserved, Some(1));
        assert_eq!(report.exception_names_not_requested, Some(1));
        assert_eq!(report.exception_shared_entries, Some(1));
        assert_eq!(report.exception_error, None);
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["exception_functions_reapplied"], 0);
        assert_eq!(json["exception_names_reapplied"], 0);

        result.exception_error = Some("strict context failed".into());
        let failed = ImageReport::from_result(&result);
        let json = serde_json::to_value(&failed).unwrap();
        assert_eq!(json["exception_error"], "strict context failed");
        for field in [
            "exception_tables",
            "exception_roles",
            "exception_roots",
            "exception_functions_created",
            "exception_functions_reapplied",
            "exception_functions_existing",
            "exception_names_applied",
            "exception_names_reapplied",
            "exception_names_preserved",
            "exception_names_not_requested",
            "exception_shared_entries",
        ] {
            assert!(
                json.get(field).is_none(),
                "{field} must be exclusive with error"
            );
        }

        let plain =
            serde_json::to_value(ImageReport::from_result(&analyzed_image("03_VSS"))).unwrap();
        assert!(plain.get("exception_roots").is_none());
        assert!(plain.get("exception_error").is_none());
    }

    #[test]
    fn exception_marshal_failure_survives_report_refresh_without_stale_counts() {
        let fixture = ExceptionMarshalFixture::present();
        let map = exception_map(&fixture.state);
        let mut result = image_result_with_current_exception_manifest(ImageOutcome::Analyzed(1));
        result.exception_roots_applied = Some(decompile::test_applied_exception_roots(
            EXCEPTION_LABEL,
            &map.identity,
        ));

        record_exception_marshal_status(
            &mut result,
            &ExceptionMarshalStatus::Failed("injected terminal failure".to_string()),
        );
        let mut stages = vec![StageReport::decompile(
            vec![ImageReport::from_result(&analyzed_image(EXCEPTION_LABEL))],
            0,
        )];
        refresh_decompile_stage_images(&mut stages, &[result]);
        let report = &stages[0].images[0];

        assert_eq!(report.exception_tables, None);
        assert_eq!(report.exception_roots, None);
        assert_eq!(
            report.exception_error.as_deref(),
            Some("injected terminal failure")
        );
    }

    #[test]
    fn exception_marshal_preserves_the_pass1_root_cause() {
        let mut result = analyzed_image(EXCEPTION_LABEL);
        result.exception_error = Some("specific ApplyExceptionRoots failure".to_string());

        record_exception_marshal_status(&mut result, &ExceptionMarshalStatus::Unmanaged);

        assert_eq!(
            result.exception_error.as_deref(),
            Some("specific ApplyExceptionRoots failure")
        );

        record_exception_marshal_status(
            &mut result,
            &ExceptionMarshalStatus::Failed("later marshal failure".to_string()),
        );
        assert_eq!(
            result.exception_error.as_deref(),
            Some("specific ApplyExceptionRoots failure")
        );
    }

    #[test]
    fn terminal_exception_context_error_replaces_application_counts() {
        let fixture = ExceptionMarshalFixture::present();
        let mut report = current_exception_report(&fixture);

        record_terminal_exception_errors(
            &mut report,
            &[(
                EXCEPTION_LABEL.to_string(),
                "terminal bytes drifted".to_string(),
            )],
        );
        let image = ImageReport::from_result(&report.images[0]);

        assert_eq!(image.exception_tables, None);
        assert_eq!(image.exception_roots, None);
        assert_eq!(
            image.exception_error.as_deref(),
            Some("terminal bytes drifted")
        );
    }

    #[test]
    fn opaque_skip_can_marshal_generation_manifest_without_application_counts() {
        let result = image_result_with_current_exception_manifest(ImageOutcome::SkippedOpaque(
            crate::classify::classify(&crate::classify::test_uniform_blob(256 * 1024)),
        ));
        let report = ImageReport::from_result(&result);
        assert!(matches!(
            result.exception_state,
            decompile::RuntimeExceptionState::Present(_)
        ));
        assert_eq!(report.exception_roots, None);
        assert_eq!(report.exception_functions_created, None);
        assert_eq!(report.exception_error, None);
    }

    #[test]
    fn failed_ghidra_does_not_downgrade_current_exception_generation() {
        let fixture = ExceptionMarshalFixture::present();
        let mut report = current_exception_report(&fixture);
        report.images[0].outcome = ImageOutcome::Failed(1);

        let state = explicit_runtime_state(&report, &report.images[0]);

        assert!(matches!(
            state.exception,
            decompile::RuntimeExceptionState::Present(_)
        ));
        assert_eq!(state.scatter, decompile::RuntimeScatterState::Unmanaged);
        assert_eq!(state.tasks, decompile::RuntimeTaskState::Unmanaged);
    }

    #[test]
    fn failed_main_marshals_exception_against_generation_scatter_state() {
        let fixture = ExceptionMarshalFixture::present_for("02_MAIN", "MAIN");
        std::fs::create_dir_all(fixture.image_dir.join("scatter")).unwrap();
        std::fs::write(
            fixture.image_dir.join("scatter/load_map.json"),
            b"stale-scatter",
        )
        .unwrap();
        let mut image = analyzed_image("02_MAIN");
        image.outcome = ImageOutcome::Failed(1);
        image.image_start = fixture.image_start;
        image.image_len = u32::try_from(exception_root_fixture_bytes().len()).unwrap();
        image.exception_state = fixture.state.clone();
        let report = decompile::test_decompile_report(
            vec![image],
            HashMap::from([(
                "02_MAIN".to_string(),
                decompile::RuntimeScatterState::Absent,
            )]),
        );
        let runtime = explicit_runtime_state(&report, &report.images[0]);

        let status = marshal_image(
            &fixture.ghidra_dir,
            &fixture.images_dir,
            "02_MAIN",
            false,
            &runtime,
            report.runtime_scatter_state("02_MAIN"),
            fixture.image_start,
        )
        .unwrap();

        assert_eq!(status, ExceptionMarshalStatus::Present);
        assert!(!fixture.image_dir.join("scatter").exists());
        assert_eq!(
            std::fs::read(&fixture.terminal_manifest).unwrap(),
            fixture.manifest_bytes
        );
    }

    fn current_exception_report(fixture: &ExceptionMarshalFixture) -> decompile::DecompileReport {
        let map = exception_map(&fixture.state);
        let mut image = analyzed_image(EXCEPTION_LABEL);
        image.image_start = fixture.image_start;
        image.image_len = u32::try_from(exception_root_fixture_bytes().len()).unwrap();
        image.exception_state = fixture.state.clone();
        image.exception_roots_applied = Some(decompile::test_applied_exception_roots(
            EXCEPTION_LABEL,
            &map.identity,
        ));
        decompile::test_decompile_report(
            vec![image],
            HashMap::from([(
                EXCEPTION_LABEL.to_string(),
                decompile::RuntimeScatterState::Unmanaged,
            )]),
        )
    }

    #[test]
    fn terminal_exception_context_is_strict_and_restaged_byte_identically() {
        let fixture = ExceptionMarshalFixture::present();
        marshal_exception_roots(
            &fixture.ghidra_dir,
            &fixture.images_dir,
            EXCEPTION_LABEL,
            &fixture.state,
            fixture.image_start,
            fixture.scatter_state,
        )
        .unwrap();
        let stale_scatter = fixture.image_dir.join("scatter/load_map.json");
        std::fs::create_dir_all(stale_scatter.parent().unwrap()).unwrap();
        std::fs::write(&stale_scatter, b"stale-non-main-scatter").unwrap();
        let report = current_exception_report(&fixture);

        let (maps, errors) =
            load_terminal_exception_maps(&fixture.images_dir, &report, &fixture.ghidra_dir);

        assert!(errors.is_empty(), "{errors:?}");
        let terminal = &maps[EXCEPTION_LABEL];
        assert_eq!(terminal.identity, exception_map(&fixture.state).identity);
        assert_eq!(terminal.context.identity(), terminal.identity);
        assert_eq!(
            std::fs::read(&terminal.manifest_path).unwrap(),
            fixture.manifest_bytes
        );
        assert_eq!(
            terminal.manifest_path,
            std::fs::canonicalize(
                fixture
                    .ghidra_dir
                    .join("exception_roots/00_BOOT/roots.json")
            )
            .unwrap()
        );
        assert_eq!(
            std::fs::read(fixture.ghidra_dir.join("images/00_BOOT")).unwrap(),
            exception_root_fixture_bytes()
        );
        assert!(terminal.scatter_manifest.is_none());
        assert_eq!(
            std::fs::read(stale_scatter).unwrap(),
            b"stale-non-main-scatter"
        );
    }

    #[test]
    fn terminal_exception_restage_includes_authenticated_scatter_payloads() {
        let root = tempfile::tempdir().unwrap();
        let ghidra_dir = root.path().join("ghidra");
        let producer_dir = root.path().join("producer");
        let image_dir = root.path().join("images").join(EXCEPTION_LABEL);
        std::fs::create_dir_all(&ghidra_dir).unwrap();
        std::fs::create_dir_all(&producer_dir).unwrap();
        std::fs::create_dir_all(&image_dir).unwrap();

        let fixture_dir =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/exception_roots/scatter");
        let raw = std::fs::read(fixture_dir.join("synthetic.bin")).unwrap();
        std::fs::write(image_dir.join(format!("{EXCEPTION_LABEL}.bin")), &raw).unwrap();
        let plan = crate::scatter::discover(&raw, EXCEPTION_BASE)
            .unwrap()
            .expect("fixture has a discoverable scatter map");
        let materialized =
            crate::scatter::materialize(&plan, &raw, EXCEPTION_LABEL, &producer_dir).unwrap();
        std::fs::rename(
            producer_dir.join("scatter").join(EXCEPTION_LABEL),
            image_dir.join("scatter"),
        )
        .unwrap();

        let manifest_bytes = std::fs::read(fixture_dir.join(EXCEPTION_MANIFEST_FILE)).unwrap();
        let terminal_manifest = image_dir
            .join("exception_roots")
            .join(EXCEPTION_MANIFEST_FILE);
        std::fs::create_dir_all(terminal_manifest.parent().unwrap()).unwrap();
        std::fs::write(&terminal_manifest, &manifest_bytes).unwrap();
        assert_eq!(
            materialized.blake3,
            crate::manifest::blake3_file(&image_dir.join("scatter/load_map.json")).unwrap()
        );

        let staged = stage_terminal_exception_files(
            &image_dir,
            &ghidra_dir,
            EXCEPTION_LABEL,
            EXCEPTION_BASE,
            decompile::RuntimeScatterState::Present,
            &crate::manifest::blake3_bytes(&manifest_bytes),
        )
        .unwrap();

        let staged_runtime = crate::runtime_image::RuntimeImage::from_artifact(
            &raw,
            EXCEPTION_BASE,
            &ghidra_dir,
            staged.scatter_manifest.as_deref(),
        )
        .expect("the staged scatter map must retain every authenticated payload");
        assert_eq!(
            staged_runtime
                .read_exact(EXCEPTION_BASE + 0x1000, 2)
                .unwrap()
                .as_ref(),
            &raw[0x2c0..0x2c2]
        );
    }

    #[test]
    fn terminal_exception_context_rejects_drift_without_restaging() {
        let fixture = ExceptionMarshalFixture::present();
        marshal_exception_roots(
            &fixture.ghidra_dir,
            &fixture.images_dir,
            EXCEPTION_LABEL,
            &fixture.state,
            fixture.image_start,
            fixture.scatter_state,
        )
        .unwrap();
        std::fs::write(
            fixture.image_dir.join(format!("{EXCEPTION_LABEL}.bin")),
            vec![0u8; 0x400],
        )
        .unwrap();
        let report = current_exception_report(&fixture);

        let (maps, errors) =
            load_terminal_exception_maps(&fixture.images_dir, &report, &fixture.ghidra_dir);

        assert!(maps.is_empty());
        assert_eq!(errors.len(), 1);
        assert!(errors[0].1.contains("terminal exception"));
        assert!(!fixture.source_manifest.exists());
    }

    #[test]
    fn terminal_exception_context_requires_explicit_application_state() {
        let fixture = ExceptionMarshalFixture::present();
        marshal_exception_roots(
            &fixture.ghidra_dir,
            &fixture.images_dir,
            EXCEPTION_LABEL,
            &fixture.state,
            fixture.image_start,
            fixture.scatter_state,
        )
        .unwrap();
        std::fs::create_dir_all(fixture.source_manifest.parent().unwrap()).unwrap();
        std::fs::write(&fixture.source_manifest, b"stale-kit-bytes").unwrap();
        let mut image = image_result_with_current_exception_manifest(ImageOutcome::SkippedOpaque(
            crate::classify::classify(&crate::classify::test_uniform_blob(256 * 1024)),
        ));
        image.image_start = fixture.image_start;
        image.image_len = u32::try_from(exception_root_fixture_bytes().len()).unwrap();
        image.exception_state = fixture.state.clone();
        let report = decompile::test_decompile_report(
            vec![image],
            HashMap::from([(
                EXCEPTION_LABEL.to_string(),
                decompile::RuntimeScatterState::Absent,
            )]),
        );

        let (maps, errors) =
            load_terminal_exception_maps(&fixture.images_dir, &report, &fixture.ghidra_dir);

        assert!(maps.is_empty());
        assert!(errors.is_empty());
        assert_eq!(
            std::fs::read(&fixture.source_manifest).unwrap(),
            b"stale-kit-bytes",
            "missing application state must not probe or consume a stale kit manifest"
        );
    }

    #[test]
    fn terminal_exception_context_skips_failed_image_without_application_state() {
        let fixture = ExceptionMarshalFixture::present();
        marshal_exception_roots(
            &fixture.ghidra_dir,
            &fixture.images_dir,
            EXCEPTION_LABEL,
            &fixture.state,
            fixture.image_start,
            fixture.scatter_state,
        )
        .unwrap();
        let mut report = current_exception_report(&fixture);
        report.images[0].outcome = ImageOutcome::Failed(1);
        report.images[0].exception_roots_applied = None;

        let (maps, errors) =
            load_terminal_exception_maps(&fixture.images_dir, &report, &fixture.ghidra_dir);

        assert!(maps.is_empty());
        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn exception_prepare_pass2_inputs_wires_context_identity_and_manifest() {
        let fixture = ExceptionMarshalFixture::present();
        marshal_exception_roots(
            &fixture.ghidra_dir,
            &fixture.images_dir,
            EXCEPTION_LABEL,
            &fixture.state,
            fixture.image_start,
            fixture.scatter_state,
        )
        .unwrap();
        let report = current_exception_report(&fixture);
        let (exceptions, errors) =
            load_terminal_exception_maps(&fixture.images_dir, &report, &fixture.ghidra_dir);
        assert!(errors.is_empty(), "{errors:?}");
        let function_maps = HashMap::from([(
            EXCEPTION_LABEL.to_string(),
            PreparedFunctionMap {
                pass2_map: Some(prepared_symbol_test_map(
                    "exception_wire",
                    EXCEPTION_LABEL,
                    1,
                )),
                creation_plan: Default::default(),
                function_names: HashMap::new(),
                evidence_name_projection: Default::default(),
            },
        )]);

        let inputs = prepare_pass2_inputs(
            &function_maps,
            &HashMap::new(),
            &HashMap::new(),
            &exceptions,
            &HashMap::new(),
        );
        let input = &inputs[EXCEPTION_LABEL];
        let terminal = &exceptions[EXCEPTION_LABEL];
        assert_eq!(input.exception_identity, terminal.identity);
        assert_eq!(
            input.exception_manifest.as_deref(),
            Some(terminal.manifest_path.as_path())
        );
        assert_eq!(
            input
                .exception_context
                .as_ref()
                .map(|context| context.identity()),
            Some(terminal.identity.as_str())
        );
    }

    // -------------------------------------------------------------------
    // PAL task marshalling, stage, and pass-2 wiring (Task 13)
    // -------------------------------------------------------------------

    use crate::pal_tasks::test_support::BASE as PAL_BASE;
    use crate::pal_tasks::{self, TaskArtifactContext};

    fn pal_temp_root(tag: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("pme_pal_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    fn materialized_map_fixture(
        label: &str,
        task_records: usize,
        distinct_entries: usize,
    ) -> pal_tasks::MaterializedTaskMap {
        pal_tasks::MaterializedTaskMap {
            relative_path: format!("pal_tasks/{label}/tasks.json"),
            blake3: "a".repeat(64),
            identity: format!("v1:{}:{task_records}:{distinct_entries}", "b".repeat(64)),
            task_records,
            distinct_entries,
        }
    }

    /// Discover and materialize a real PAL task manifest for the raw-only
    /// discoverable fixture, rooted at `ghidra`, returning the explicit
    /// `Present` state plus the manifest bytes.
    fn materialize_raw_pal_fixture(
        ghidra: &Path,
        label: &str,
    ) -> (decompile::RuntimeTaskState, Vec<u8>) {
        let image_bytes = crate::pal_tasks::test_support::craft_discoverable_pal_main_image();
        let runtime = crate::runtime_image::RuntimeImage::from_plan(&image_bytes, PAL_BASE, None)
            .expect("raw fixture runtime");
        materialize_pal_plan(&image_bytes, &runtime, None, ghidra, label)
    }

    fn materialize_pal_plan(
        image_bytes: &[u8],
        runtime: &crate::runtime_image::RuntimeImage<'_>,
        scatter_blake3: Option<[u8; 32]>,
        ghidra: &Path,
        label: &str,
    ) -> (decompile::RuntimeTaskState, Vec<u8>) {
        let plan = pal_tasks::discover(runtime, label)
            .expect("fixture discovery succeeds")
            .expect("fixture has a discoverable PAL table");
        let context = TaskArtifactContext {
            label,
            image_blake3: *blake3::hash(image_bytes).as_bytes(),
            scatter_load_map_blake3: scatter_blake3,
        };
        let map = pal_tasks::materialize(&plan, context, ghidra).expect("fixture materializes");
        let bytes = std::fs::read(ghidra.join("pal_tasks").join(label).join("tasks.json")).unwrap();
        (decompile::RuntimeTaskState::Present(map), bytes)
    }

    /// Marshal scaffolding: the slice in the kit position, a stale complete
    /// terminal manifest, and (optionally) a pass-1 export.
    fn pal_marshal_tree(ghidra: &Path, images: &Path, label: &str, image_bytes: &[u8]) {
        std::fs::create_dir_all(ghidra.join("images")).unwrap();
        std::fs::write(ghidra.join("images").join(label), image_bytes).unwrap();
        let old = images.join(label).join("pal_tasks");
        std::fs::create_dir_all(&old).unwrap();
        std::fs::write(old.join("tasks.json"), b"old complete terminal bytes").unwrap();
    }

    #[test]
    fn pal_marshal_honors_explicit_state() {
        let root = pal_temp_root("marshal_states");
        let ghidra = root.join("ghidra");
        let images = root.join("images");
        let label = "02_MAIN";
        let (present, manifest_bytes) = materialize_raw_pal_fixture(&ghidra, label);
        let map = match present.clone() {
            decompile::RuntimeTaskState::Present(map) => map,
            _ => panic!("fixture state is Present"),
        };
        let source_manifest = ghidra.join("pal_tasks").join(label).join("tasks.json");
        assert_eq!(std::fs::read(&source_manifest).unwrap(), manifest_bytes);
        pal_marshal_tree(&ghidra, &images, label, &craft_bytes());

        // Present: type-validate + authenticate against the terminal raw
        // bytes, then atomically replace the terminal manifest and consume
        // the source.
        marshal_image(
            &ghidra,
            &images,
            label,
            false,
            &runtime_state(
                decompile::RuntimeScatterState::Absent,
                decompile::RuntimeTaskState::Present(map.clone()),
                decompile::RuntimeExceptionState::Unmanaged,
            ),
            decompile::RuntimeScatterState::Absent,
            PAL_BASE,
        )
        .unwrap();
        let terminal_manifest = images.join(label).join("pal_tasks").join("tasks.json");
        assert_eq!(std::fs::read(&terminal_manifest).unwrap(), manifest_bytes);
        assert!(
            !source_manifest.exists(),
            "the source manifest is consumed by the commit"
        );
        assert!(
            !ghidra.join("pal_tasks").join(label).exists(),
            "the owned source label directory is removed after commit"
        );
        assert_eq!(
            std::fs::read(images.join(label).join(format!("{label}.bin"))).unwrap(),
            craft_bytes(),
            "the slice marshal is unchanged"
        );

        // Unmanaged: the terminal state and any leftover source are left
        // untouched — currentness never comes from artifact existence.
        std::fs::create_dir_all(source_manifest.parent().unwrap()).unwrap();
        std::fs::write(&source_manifest, b"leftover source bytes").unwrap();
        marshal_image(
            &ghidra,
            &images,
            label,
            false,
            &runtime_state(
                decompile::RuntimeScatterState::Absent,
                decompile::RuntimeTaskState::Unmanaged,
                decompile::RuntimeExceptionState::Unmanaged,
            ),
            decompile::RuntimeScatterState::Absent,
            PAL_BASE,
        )
        .unwrap();
        assert_eq!(std::fs::read(&terminal_manifest).unwrap(), manifest_bytes);
        assert_eq!(
            std::fs::read(&source_manifest).unwrap(),
            b"leftover source bytes"
        );

        // Absent: a successful no-candidate result removes the owned
        // terminal directory.
        marshal_image(
            &ghidra,
            &images,
            label,
            false,
            &runtime_state(
                decompile::RuntimeScatterState::Absent,
                decompile::RuntimeTaskState::Absent,
                decompile::RuntimeExceptionState::Unmanaged,
            ),
            decompile::RuntimeScatterState::Absent,
            PAL_BASE,
        )
        .unwrap();
        assert!(!images.join(label).join("pal_tasks").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    fn craft_bytes() -> Vec<u8> {
        crate::pal_tasks::test_support::craft_discoverable_pal_main_image()
    }

    #[test]
    fn pal_marshal_failure_preserves_old_complete_bytes() {
        let root = pal_temp_root("marshal_failure");
        let ghidra = root.join("ghidra");
        let images = root.join("images");
        let label = "02_MAIN";

        // Authentication failure: a corrupt source manifest must fail
        // closed before any terminal mutation.
        let (present, _manifest_bytes) = materialize_raw_pal_fixture(&ghidra, label);
        let source_manifest = ghidra.join("pal_tasks").join(label).join("tasks.json");
        pal_marshal_tree(&ghidra, &images, label, &craft_bytes());
        std::fs::write(&source_manifest, b"{not a manifest").unwrap();
        let terminal_manifest = images.join(label).join("pal_tasks").join("tasks.json");
        let error = marshal_image(
            &ghidra,
            &images,
            label,
            false,
            &runtime_state(
                decompile::RuntimeScatterState::Absent,
                present.clone(),
                decompile::RuntimeExceptionState::Unmanaged,
            ),
            decompile::RuntimeScatterState::Absent,
            PAL_BASE,
        )
        .expect_err("a corrupt source manifest must fail closed");
        assert!(error.to_string().to_lowercase().contains("pal"));
        assert_eq!(
            std::fs::read(&terminal_manifest).unwrap(),
            b"old complete terminal bytes"
        );
        assert_eq!(
            std::fs::read(&source_manifest).unwrap(),
            b"{not a manifest",
            "the failed validation must not consume the source"
        );

        // Rename (commit) failure: the old complete terminal bytes remain
        // and the source is not consumed.
        let (present, manifest_bytes) = materialize_raw_pal_fixture(&ghidra, label);
        std::fs::write(&source_manifest, &manifest_bytes).unwrap();
        let mut failing_rename =
            |_: &Path, _: &Path| Err(std::io::Error::other("injected pal commit failure"));
        let error = marshal_pal_tasks_with(
            &ghidra,
            &images,
            label,
            &present,
            PAL_BASE,
            decompile::RuntimeScatterState::Absent,
            &mut failing_rename,
        )
        .expect_err("an injected rename failure must surface");
        assert!(error.to_string().contains("injected pal commit failure"));
        assert_eq!(
            std::fs::read(&terminal_manifest).unwrap(),
            b"old complete terminal bytes",
            "rename failure must leave the old complete terminal bytes"
        );
        assert_eq!(
            std::fs::read(&source_manifest).unwrap(),
            manifest_bytes,
            "rename failure must not consume the source"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pal_marshal_failure_does_not_block_exception_terminal_commit() {
        let root = pal_temp_root("marshal_failure_after_exception");
        let ghidra = root.join("ghidra");
        let images = root.join("images");
        let label = "02_MAIN";
        let (present, _) = materialize_raw_pal_fixture(&ghidra, label);
        pal_marshal_tree(&ghidra, &images, label, &craft_bytes());
        std::fs::write(
            ghidra.join("pal_tasks").join(label).join("tasks.json"),
            b"{not a manifest",
        )
        .unwrap();
        let terminal_exception = images.join(label).join("exception_roots/roots.json");
        std::fs::create_dir_all(terminal_exception.parent().unwrap()).unwrap();
        std::fs::write(&terminal_exception, b"stale exception state").unwrap();

        let error = marshal_image(
            &ghidra,
            &images,
            label,
            false,
            &runtime_state(
                decompile::RuntimeScatterState::Absent,
                present,
                decompile::RuntimeExceptionState::Absent,
            ),
            decompile::RuntimeScatterState::Absent,
            PAL_BASE,
        )
        .expect_err("the malformed PAL manifest still fails the image marshal");

        assert!(error.to_string().to_lowercase().contains("pal"));
        assert!(
            !terminal_exception.exists(),
            "exception absence commits independently before PAL validation"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pal_marshal_authenticates_scatter_backed_manifest() {
        let root = pal_temp_root("marshal_scatter");
        let ghidra = root.join("ghidra");
        let images = root.join("images");
        let label = "02_MAIN";
        let image_bytes = crate::pal_tasks::test_support::craft_scatter_pal_main_image();

        let scatter_plan = crate::scatter::discover(&image_bytes, PAL_BASE)
            .unwrap()
            .expect("fixture has a discoverable scatter map");
        let scatter_map =
            crate::scatter::materialize(&scatter_plan, &image_bytes, label, &ghidra).unwrap();
        let runtime = crate::runtime_image::RuntimeImage::from_artifact(
            &image_bytes,
            PAL_BASE,
            &ghidra,
            Some(&ghidra.join(&scatter_map.relative_path)),
        )
        .unwrap();
        let scatter_blake3 = crate::execution_ranges::parse_blake3(&scatter_map.blake3).unwrap();
        let (present, manifest_bytes) =
            materialize_pal_plan(&image_bytes, &runtime, Some(scatter_blake3), &ghidra, label);

        pal_marshal_tree(&ghidra, &images, label, &image_bytes);
        marshal_image(
            &ghidra,
            &images,
            label,
            false,
            &runtime_state(
                decompile::RuntimeScatterState::Present,
                present.clone(),
                decompile::RuntimeExceptionState::Unmanaged,
            ),
            decompile::RuntimeScatterState::Present,
            PAL_BASE,
        )
        .unwrap();
        assert_eq!(
            std::fs::read(images.join(label).join("pal_tasks").join("tasks.json")).unwrap(),
            manifest_bytes
        );
        assert!(
            images
                .join(label)
                .join("scatter")
                .join("load_map.json")
                .exists(),
            "the scatter marshal is unchanged"
        );

        // The scatter dependency is authenticated, not assumed: the same
        // validated map marshalled with an absent scatter dependency fails
        // closed and leaves the terminal bytes complete.
        let mut rename = |from: &Path, to: &Path| std::fs::rename(from, to);
        let error = marshal_pal_tasks_with(
            &ghidra,
            &images,
            label,
            &present,
            PAL_BASE,
            decompile::RuntimeScatterState::Absent,
            &mut rename,
        )
        .expect_err("a mismatched scatter dependency must fail closed");
        assert!(error.to_string().to_lowercase().contains("scatter"));
        assert_eq!(
            std::fs::read(images.join(label).join("pal_tasks").join("tasks.json")).unwrap(),
            manifest_bytes
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn terminal_pal_restage_includes_authenticated_scatter_payloads() {
        let root = pal_temp_root("pass2_scatter_payloads");
        let ghidra = root.join("ghidra");
        let images = root.join("images");
        let label = "02_MAIN";
        let image_bytes = crate::pal_tasks::test_support::craft_scatter_pal_main_image();
        let scatter_plan = crate::scatter::discover(&image_bytes, PAL_BASE)
            .unwrap()
            .expect("fixture has a discoverable scatter map");
        let scatter_map =
            crate::scatter::materialize(&scatter_plan, &image_bytes, label, &ghidra).unwrap();
        let runtime = crate::runtime_image::RuntimeImage::from_artifact(
            &image_bytes,
            PAL_BASE,
            &ghidra,
            Some(&ghidra.join(&scatter_map.relative_path)),
        )
        .unwrap();
        let scatter_blake3 = crate::execution_ranges::parse_blake3(&scatter_map.blake3).unwrap();
        let (present, _) =
            materialize_pal_plan(&image_bytes, &runtime, Some(scatter_blake3), &ghidra, label);
        pal_marshal_tree(&ghidra, &images, label, &image_bytes);
        marshal_image(
            &ghidra,
            &images,
            label,
            false,
            &runtime_state(
                decompile::RuntimeScatterState::Present,
                present.clone(),
                decompile::RuntimeExceptionState::Unmanaged,
            ),
            decompile::RuntimeScatterState::Present,
            PAL_BASE,
        )
        .unwrap();

        let mut image = analyzed_image(label);
        image.image_start = PAL_BASE;
        image.image_len = u32::try_from(image_bytes.len()).unwrap();
        let mut report = decompile::test_decompile_report(
            vec![image],
            HashMap::from([(label.to_string(), decompile::RuntimeScatterState::Present)]),
        );
        decompile::test_set_runtime_task_state(&mut report, label, present);

        let (maps, errors) = load_terminal_pal_maps(&images, &report, &ghidra);

        assert!(errors.is_empty(), "{errors:?}");
        let terminal = &maps[label];
        crate::runtime_image::RuntimeImage::from_artifact(
            &image_bytes,
            PAL_BASE,
            &ghidra,
            terminal.scatter_manifest.as_deref(),
        )
        .expect("the staged PAL scatter map must retain every authenticated payload");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pal_stage_reports_ok_with_deterministic_counts_for_present_map() {
        let mut tally = PalMarshalTally::default();
        tally
            .record(&materialized_map_fixture("02_MAIN", 2, 1))
            .unwrap();
        let stage = pal_tasks_stage(Some(&tally), 9);
        assert_eq!(stage.stage, "pal_tasks");
        assert_eq!(stage.status, "ok");
        assert_eq!(
            stage.output.as_deref(),
            Some("images/*/pal_tasks/tasks.json (images=1, tasks=2, entries=1)")
        );
        assert_eq!(stage.duration_ms, 9);

        tally
            .record(&materialized_map_fixture("01_PSP", 3, 2))
            .unwrap();
        let stage = pal_tasks_stage(Some(&tally), 9);
        assert_eq!(
            stage.output.as_deref(),
            Some("images/*/pal_tasks/tasks.json (images=2, tasks=5, entries=3)")
        );

        // Checked arithmetic: totals that overflow are the typed error,
        // never a silent wrap.
        let mut overflow = PalMarshalTally::default();
        overflow
            .record(&materialized_map_fixture("02_MAIN", usize::MAX, 0))
            .unwrap();
        assert!(
            overflow
                .record(&materialized_map_fixture("01_PSP", 1, 0))
                .is_err()
        );
    }

    #[test]
    fn pal_stage_reports_skipped_no_initializer_on_successful_absence() {
        let tally = PalMarshalTally::default();
        let stage = pal_tasks_stage(Some(&tally), 9);
        assert_eq!(stage.stage, "pal_tasks");
        assert_eq!(stage.status, "skipped");
        assert_eq!(stage.reason.as_deref(), Some("no PAL task initializer"));
        assert!(stage.output.is_none());
    }

    #[test]
    fn pal_stage_follows_command_failure() {
        // A failed decompile command (e.g. malformed PAL generation) owns
        // the failure in the `decompile` stage; the PAL stage defers to it
        // instead of claiming a successful absence.
        let stage = pal_tasks_stage(None, 9);
        assert_eq!(stage.stage, "pal_tasks");
        assert_eq!(stage.status, "skipped");
        assert_eq!(stage.reason.as_deref(), Some("pass 1 failed"));
        assert_ne!(stage.reason.as_deref(), Some("no PAL task initializer"));
    }

    #[test]
    fn pal_image_report_carries_every_counter_only_for_configured_maps() {
        let mut image = analyzed_image("02_MAIN");
        image.pal_applied = Some(decompile::AppliedPalTasks {
            tasks: 2,
            entries: 3,
            functions_created: 2,
            functions_existing: 1,
            names_applied: 2,
            names_preserved: 1,
            shared_entries: 1,
        });
        let report = ImageReport::from_result(&image);
        assert_eq!(report.pal_tasks, Some(2));
        assert_eq!(report.pal_entries, Some(3));
        assert_eq!(report.pal_functions_created, Some(2));
        assert_eq!(report.pal_functions_existing, Some(1));
        assert_eq!(report.pal_names_applied, Some(2));
        assert_eq!(report.pal_names_preserved, Some(1));
        assert_eq!(report.pal_shared_entries, Some(1));

        let json = serde_json::to_value(&report).unwrap();
        for key in [
            "pal_tasks",
            "pal_entries",
            "pal_functions_created",
            "pal_functions_existing",
            "pal_names_applied",
            "pal_names_preserved",
            "pal_shared_entries",
        ] {
            assert!(json.get(key).and_then(serde_json::Value::as_u64).is_some());
        }

        // No configured map: every optional counter is omitted.
        let plain = ImageReport::from_result(&analyzed_image("01_PSP"));
        let json = serde_json::to_value(&plain).unwrap();
        for key in [
            "pal_tasks",
            "pal_entries",
            "pal_functions_created",
            "pal_functions_existing",
            "pal_names_applied",
            "pal_names_preserved",
            "pal_shared_entries",
        ] {
            assert!(json.get(key).is_none(), "{key} must be omitted: {json}");
        }
    }

    #[test]
    fn pal_pass2_context_binds_validated_artifact() {
        let root = pal_temp_root("pass2_context");
        let ghidra = root.join("ghidra");
        let images = root.join("images");
        let label = "02_MAIN";
        let (present, manifest_bytes) = materialize_raw_pal_fixture(&ghidra, label);
        pal_marshal_tree(&ghidra, &images, label, &craft_bytes());
        marshal_image(
            &ghidra,
            &images,
            label,
            false,
            &runtime_state(
                decompile::RuntimeScatterState::Absent,
                present.clone(),
                decompile::RuntimeExceptionState::Unmanaged,
            ),
            decompile::RuntimeScatterState::Absent,
            PAL_BASE,
        )
        .unwrap();

        let image_dir = images.join(label);
        let artifact = validate_terminal_pal_manifest(
            &image_dir,
            label,
            PAL_BASE,
            decompile::RuntimeScatterState::Absent,
            &image_dir.join("pal_tasks").join("tasks.json"),
            "mismatched-identity",
        )
        .err()
        .expect("an identity mismatch must fail closed");
        assert!(artifact.to_string().contains("identity"));

        let artifact = validate_terminal_pal_manifest(
            &image_dir,
            label,
            PAL_BASE,
            decompile::RuntimeScatterState::Absent,
            &image_dir.join("pal_tasks").join("tasks.json"),
            &identity_of(&present),
        )
        .unwrap();
        assert_eq!(artifact.image_label, label);

        let context = pal_pass2_context(&artifact);
        assert_eq!(context.identity, identity_of(&present));
        assert_eq!(
            context.manifest_blake3,
            crate::manifest::blake3_bytes(&manifest_bytes)
        );
        assert_eq!(context.scatter_load_map_blake3, None);
        assert_eq!(
            context.applications.len(),
            2,
            "the two fixture tasks allocate two application groups"
        );
        let names: std::collections::BTreeSet<String> = context
            .applications
            .values()
            .flat_map(|app| app.tasks.iter().map(|task| task.name.clone()))
            .collect();
        assert_eq!(
            names,
            ["first_task", "second_task"]
                .into_iter()
                .map(str::to_string)
                .collect()
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    fn identity_of(state: &decompile::RuntimeTaskState) -> String {
        match state {
            decompile::RuntimeTaskState::Present(map) => map.identity.clone(),
            _ => panic!("fixture state is Present"),
        }
    }

    #[test]
    fn pal_prepare_pass2_inputs_wires_identity_and_manifests() {
        let root = pal_temp_root("pass2_inputs");
        let images = root.join("images");
        let label = "02_MAIN";
        let manifest_path = images.join(label).join("pal_tasks").join("tasks.json");
        let scatter_path = images.join(label).join("scatter").join("load_map.json");
        std::fs::create_dir_all(manifest_path.parent().unwrap()).unwrap();
        std::fs::create_dir_all(scatter_path.parent().unwrap()).unwrap();
        std::fs::write(&manifest_path, b"manifest").unwrap();
        std::fs::write(&scatter_path, b"scatter").unwrap();

        let identity = format!("v1:{}:2:0", "c".repeat(64));
        let pal = HashMap::from([(
            label.to_string(),
            TerminalPalMap {
                identity: identity.clone(),
                manifest_path: manifest_path.clone(),
                scatter_manifest: Some(scatter_path.clone()),
                context: symbolicate::PalPass2Context {
                    identity: identity.clone(),
                    manifest_blake3: "d".repeat(64),
                    scatter_load_map_blake3: None,
                    applications: Default::default(),
                },
            },
        )]);
        let mut function_maps = HashMap::new();
        let prepared = PreparedFunctionMap {
            pass2_map: Some(prepared_symbol_test_map("pal_wire", label, 1)),
            creation_plan: Default::default(),
            function_names: HashMap::new(),
            evidence_name_projection: Default::default(),
        };
        function_maps.insert(label.to_string(), prepared);
        // A second image with maps but no PAL state keeps today's
        // none/-/- arguments.
        function_maps.insert(
            "01_PSP".to_string(),
            PreparedFunctionMap {
                pass2_map: Some(prepared_symbol_test_map("pal_wire_psp", "01_PSP", 1)),
                creation_plan: Default::default(),
                function_names: HashMap::new(),
                evidence_name_projection: Default::default(),
            },
        );

        let inputs = prepare_pass2_inputs(
            &function_maps,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            &pal,
        );
        let wired = &inputs[label];
        assert_eq!(wired.pal_identity, identity);
        assert_eq!(wired.pal_manifest.as_deref(), Some(manifest_path.as_path()));
        assert_eq!(
            wired.scatter_manifest.as_deref(),
            Some(scatter_path.as_path())
        );
        let unwired = &inputs["01_PSP"];
        assert_eq!(unwired.pal_identity, "");
        assert!(unwired.pal_manifest.is_none());
        assert!(unwired.scatter_manifest.is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn refresh_decompiled_replaces_ghidra_outputs_and_preserves_sidecars() {
        let root =
            std::env::temp_dir().join(format!("pme_refresh_preserve_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let ghidra = root.join("ghidra");
        let images = root.join("images");
        let label = "02_MAIN";

        // Destination: pass-1 tree with old Ghidra trio plus globals, Thumb,
        // and an unrelated future sidecar.
        let dest = images.join(label).join("decompiled");
        std::fs::create_dir_all(dest.join("thumb")).unwrap();
        std::fs::write(dest.join("decompiled.c"), b"OLD_C").unwrap();
        std::fs::write(dest.join("disasm.lst"), b"OLD_LST").unwrap();
        let old_functions = tagged_functions("old_name");
        let new_functions = tagged_functions("new_name");
        std::fs::write(dest.join("functions.json"), &old_functions).unwrap();
        let thumb_json = tagged_thumb_functions();
        let thumb_stdout = b"r2-stdout-bytes-must-survive";
        let globals_json = b"{\"format\":\"pixel-modem-extractor-globals-v1\",\"globals\":[]}";
        let future_sidecar = b"future-sidecar-bytes-must-survive";
        std::fs::write(dest.join("thumb_functions.json"), &thumb_json).unwrap();
        std::fs::write(dest.join("thumb").join("410b0000.stdout"), thumb_stdout).unwrap();
        std::fs::write(dest.join("globals.json"), globals_json).unwrap();
        let global_shapes_json = b"{\"sentinel\":true}";
        std::fs::write(dest.join("global_shapes.json"), global_shapes_json).unwrap();
        std::fs::write(dest.join("future-sidecar.bin"), future_sidecar).unwrap();
        // The marshalled PAL task manifest is a sibling of `decompiled/` and
        // outside Ghidra's three-file refresh ownership: it must survive the
        // pass-2 refresh byte-for-byte.
        let pal_manifest = b"{\"format\":\"pixel-modem-extractor-pal-tasks-v1\"}";
        std::fs::create_dir_all(images.join(label).join("pal_tasks")).unwrap();
        std::fs::write(
            images.join(label).join("pal_tasks").join("tasks.json"),
            pal_manifest,
        )
        .unwrap();
        std::fs::write(
            images.join(label).join(format!("{label}.bin")),
            vec![0u8; 0x40],
        )
        .unwrap();

        // Pass-2 export: exactly the three Ghidra-owned files, new contents.
        let export = ghidra.join("export").join(label);
        std::fs::create_dir_all(&export).unwrap();
        std::fs::write(export.join("decompiled.c"), b"NEW_C").unwrap();
        std::fs::write(export.join("disasm.lst"), b"NEW_LST").unwrap();
        std::fs::write(export.join("functions.json"), &new_functions).unwrap();

        let image = tagged_image(label, true);
        refresh_decompiled(&ghidra, &images, &image).unwrap();

        assert_eq!(std::fs::read(dest.join("decompiled.c")).unwrap(), b"NEW_C");
        assert_eq!(std::fs::read(dest.join("disasm.lst")).unwrap(), b"NEW_LST");
        assert_eq!(
            std::fs::read(dest.join("functions.json")).unwrap(),
            new_functions
        );
        assert_eq!(
            std::fs::read(dest.join("thumb_functions.json")).unwrap(),
            thumb_json,
            "thumb_functions.json must be byte-identical"
        );
        assert_eq!(
            std::fs::read(dest.join("thumb").join("410b0000.stdout")).unwrap(),
            thumb_stdout,
            "thumb/*.stdout must be byte-identical"
        );
        assert_eq!(
            std::fs::read(dest.join("globals.json")).unwrap(),
            globals_json,
            "globals.json must be byte-identical"
        );
        assert_eq!(
            std::fs::read(dest.join("global_shapes.json")).unwrap(),
            global_shapes_json,
            "global_shapes.json must be byte-identical"
        );
        assert_eq!(
            std::fs::read(dest.join("future-sidecar.bin")).unwrap(),
            future_sidecar,
            "unrelated sidecars must be byte-identical"
        );
        assert_eq!(
            std::fs::read(images.join(label).join("pal_tasks").join("tasks.json")).unwrap(),
            pal_manifest,
            "the PAL task manifest is outside the pass-2 refresh transaction \
             and must be byte-identical"
        );
        assert!(
            !export.exists(),
            "validated export dir must be removed after successful replace"
        );
        assert!(
            !images
                .join(label)
                .join(".decompiled.refresh-backup")
                .exists(),
            "successful refresh must remove the transaction backup"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn refresh_decompiled_validates_retained_inventory_before_creation_delta() {
        let root = tempfile::tempdir().unwrap();
        let ghidra = root.path().join("ghidra");
        let images = root.path().join("images");
        let label = "02_MAIN";
        let dest = images.join(label).join("decompiled");
        let export = ghidra.join("export").join(label);
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::create_dir_all(&export).unwrap();
        std::fs::write(images.join(label).join(format!("{label}.bin")), [0u8; 0x40]).unwrap();
        let retained = tagged_functions("retained");
        let created = serde_json::json!({
            "name": "created_thumb",
            "primary_source": "analysis",
            "entry": "0x4004",
            "end": "0x4008",
            "size": 4,
            "decode_ranges": [{
                "isa": "thumb",
                "start": "0x4004",
                "end": "0x4008",
                "blake3": "ec2bd03bf86b935fa34d71ad7ebb049f1f10f87d343e521511d8f9e6625620cd"
            }],
            "decode_range_errors": [],
            "data_refs": []
        });
        let mut staged: Vec<serde_json::Value> = serde_json::from_slice(&retained).unwrap();
        staged.push(created);
        let staged_bytes = serde_json::to_vec(&staged).unwrap();
        for (name, old, new) in [
            ("decompiled.c", b"OLD_C".as_slice(), b"NEW_C".as_slice()),
            ("disasm.lst", b"OLD_LST".as_slice(), b"NEW_LST".as_slice()),
            (
                "functions.json",
                retained.as_slice(),
                staged_bytes.as_slice(),
            ),
        ] {
            std::fs::write(dest.join(name), old).unwrap();
            std::fs::write(export.join(name), new).unwrap();
        }
        let mut image = tagged_image(label, false);
        image.pass2_creation_plan = Some(decompile::Pass2CreationPlan {
            candidates: 1,
            skips: Default::default(),
            requests: vec![symbolicate::Pass2CreationRequest {
                entry: 0x4004,
                final_primary: "created_thumb".to_string(),
                final_source: "analysis".to_string(),
            }],
        });
        image.pass2_thumb_names = Some(decompile::AppliedThumbNames {
            candidates: 1,
            created: 1,
            reapplied: 0,
            skipped_existing: 0,
            skipped_collision: 0,
        });

        let outcomes = HashMap::from([(
            label.to_string(),
            decompile::Pass2ProcessOutcome::ProcessSucceeded,
        )]);
        let (refreshed, errors) = refresh_pass2_outputs(
            &outcomes,
            std::slice::from_mut(&mut image),
            &ghidra,
            &images,
        );

        assert_eq!(refreshed, 1);
        assert!(errors.is_empty());
        assert!(matches!(image.outcome, ImageOutcome::Analyzed(2)));
        assert_eq!(image.ghidra_execution_accepted, Some(2));
        assert_eq!(image.ghidra_execution_quarantined, Some(0));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(
                &std::fs::read(dest.join("functions.json")).unwrap()
            )
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
            2
        );
    }

    #[test]
    fn refresh_decompiled_first_placement_applies_creation_delta_once() {
        let root = tempfile::tempdir().unwrap();
        let ghidra = root.path().join("ghidra");
        let images = root.path().join("images");
        let label = "02_MAIN";
        let dest = images.join(label).join("decompiled");
        let export = ghidra.join("export").join(label);
        std::fs::create_dir_all(&export).unwrap();
        std::fs::create_dir_all(images.join(label)).unwrap();
        std::fs::write(images.join(label).join(format!("{label}.bin")), [0u8; 0x40]).unwrap();
        let retained = tagged_functions("retained");
        let created = serde_json::json!({
            "name": "created_thumb",
            "primary_source": "analysis",
            "entry": "0x4004",
            "end": "0x4008",
            "size": 4,
            "decode_ranges": [{
                "isa": "thumb",
                "start": "0x4004",
                "end": "0x4008",
                "blake3": "ec2bd03bf86b935fa34d71ad7ebb049f1f10f87d343e521511d8f9e6625620cd"
            }],
            "decode_range_errors": [],
            "data_refs": []
        });
        let mut staged: Vec<serde_json::Value> = serde_json::from_slice(&retained).unwrap();
        staged.push(created);
        for (name, bytes) in [
            ("decompiled.c", b"NEW_C".as_slice()),
            ("disasm.lst", b"NEW_LST".as_slice()),
            (
                "functions.json",
                serde_json::to_vec(&staged).unwrap().as_slice(),
            ),
        ] {
            std::fs::write(export.join(name), bytes).unwrap();
        }
        let mut image = tagged_image(label, false);
        image.pass2_creation_plan = Some(decompile::Pass2CreationPlan {
            candidates: 1,
            skips: Default::default(),
            requests: vec![symbolicate::Pass2CreationRequest {
                entry: 0x4004,
                final_primary: "created_thumb".to_string(),
                final_source: "analysis".to_string(),
            }],
        });
        image.pass2_thumb_names = Some(decompile::AppliedThumbNames {
            candidates: 1,
            created: 1,
            reapplied: 0,
            skipped_existing: 0,
            skipped_collision: 0,
        });

        refresh_decompiled(&ghidra, &images, &image)
            .expect("final validation must not apply the creation delta twice");

        assert!(dest.join("functions.json").is_file());
        assert!(!export.exists());
    }

    #[test]
    fn refresh_decompiled_replay_accepts_published_or_unpublished_owned_creation() {
        for published in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let ghidra = root.path().join("ghidra");
            let images = root.path().join("images");
            let label = "02_MAIN";
            let dest = images.join(label).join("decompiled");
            let export = ghidra.join("export").join(label);
            std::fs::create_dir_all(&dest).unwrap();
            std::fs::create_dir_all(&export).unwrap();
            std::fs::write(images.join(label).join(format!("{label}.bin")), [0u8; 0x40]).unwrap();
            let retained = tagged_functions("retained");
            let created = serde_json::json!({
                "name": "created_thumb",
                "primary_source": "analysis",
                "entry": "0x4004",
                "end": "0x4008",
                "size": 4,
                "decode_ranges": [{
                    "isa": "thumb",
                    "start": "0x4004",
                    "end": "0x4008",
                    "blake3": "ec2bd03bf86b935fa34d71ad7ebb049f1f10f87d343e521511d8f9e6625620cd"
                }],
                "decode_range_errors": [],
                "data_refs": []
            });
            let mut replayed: Vec<serde_json::Value> = serde_json::from_slice(&retained).unwrap();
            replayed.push(created);
            let replayed = serde_json::to_vec(&replayed).unwrap();
            let prior_functions = if published {
                replayed.as_slice()
            } else {
                retained.as_slice()
            };
            for (name, old, new) in [
                ("decompiled.c", b"OLD_C".as_slice(), b"NEW_C".as_slice()),
                ("disasm.lst", b"OLD_LST".as_slice(), b"NEW_LST".as_slice()),
                ("functions.json", prior_functions, replayed.as_slice()),
            ] {
                std::fs::write(dest.join(name), old).unwrap();
                std::fs::write(export.join(name), new).unwrap();
            }
            let mut image = tagged_image(label, false);
            image.pass2_creation_plan = Some(decompile::Pass2CreationPlan {
                candidates: 1,
                skips: Default::default(),
                requests: vec![symbolicate::Pass2CreationRequest {
                    entry: 0x4004,
                    final_primary: "created_thumb".to_string(),
                    final_source: "analysis".to_string(),
                }],
            });
            image.pass2_thumb_names = Some(decompile::AppliedThumbNames {
                candidates: 1,
                created: 0,
                reapplied: 1,
                skipped_existing: 0,
                skipped_collision: 0,
            });

            refresh_decompiled(&ghidra, &images, &image)
                .unwrap_or_else(|error| panic!("published={published}: {error}"));

            assert_eq!(
                std::fs::read(dest.join("functions.json")).unwrap(),
                replayed
            );
            assert!(!export.exists());
        }
    }

    #[test]
    fn refresh_decompiled_rolls_back_second_and_third_replacement_failures() {
        for fail_at in [2usize, 3] {
            let root = std::env::temp_dir().join(format!(
                "pme_refresh_replace_failure_{}_{}",
                fail_at,
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&root);
            let ghidra = root.join("ghidra");
            let images = root.join("images");
            let label = "02_MAIN";
            let dest = images.join(label).join("decompiled");
            let export = ghidra.join("export").join(label);
            std::fs::create_dir_all(&dest).unwrap();
            std::fs::create_dir_all(&export).unwrap();
            let old_functions = tagged_functions("old_name");
            let new_functions = tagged_functions("new_name");
            for (name, old, new) in [
                ("decompiled.c", b"OLD_C".as_slice(), b"NEW_C".as_slice()),
                ("disasm.lst", b"OLD_LST".as_slice(), b"NEW_LST".as_slice()),
                (
                    "functions.json",
                    old_functions.as_slice(),
                    new_functions.as_slice(),
                ),
            ] {
                std::fs::write(dest.join(name), old).unwrap();
                std::fs::write(export.join(name), new).unwrap();
            }
            std::fs::write(dest.join("sidecar.bin"), b"SIDE").unwrap();
            let image = tagged_image(label, false);
            let mut replacements = 0usize;
            let mut rename = |from: &Path, to: &Path| {
                if from.parent() == Some(export.as_path()) && to.parent() == Some(dest.as_path()) {
                    replacements += 1;
                    if replacements == fail_at {
                        return Err(std::io::Error::other(format!(
                            "injected replacement failure {fail_at}"
                        )));
                    }
                }
                std::fs::rename(from, to)
            };
            let mut validate = decompile::validate_image_terminal_inventory;

            assert!(
                refresh_decompiled_with(&ghidra, &images, &image, &mut rename, &mut validate,)
                    .is_err()
            );
            assert_eq!(std::fs::read(dest.join("decompiled.c")).unwrap(), b"OLD_C");
            assert_eq!(std::fs::read(dest.join("disasm.lst")).unwrap(), b"OLD_LST");
            assert_eq!(
                std::fs::read(dest.join("functions.json")).unwrap(),
                old_functions
            );
            assert_eq!(std::fs::read(dest.join("sidecar.bin")).unwrap(), b"SIDE");
            assert_eq!(
                std::fs::read(export.join("decompiled.c")).unwrap(),
                b"NEW_C"
            );
            assert_eq!(
                std::fs::read(export.join("disasm.lst")).unwrap(),
                b"NEW_LST"
            );
            assert_eq!(
                std::fs::read(export.join("functions.json")).unwrap(),
                new_functions
            );
            let _ = std::fs::remove_dir_all(&root);
        }
    }

    #[test]
    fn refresh_decompiled_rolls_back_failed_final_validation() {
        let root = std::env::temp_dir().join(format!(
            "pme_refresh_final_validation_failure_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let ghidra = root.join("ghidra");
        let images = root.join("images");
        let label = "02_MAIN";
        let dest = images.join(label).join("decompiled");
        let export = ghidra.join("export").join(label);
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::create_dir_all(&export).unwrap();
        let old_functions = tagged_functions("old_name");
        let new_functions = tagged_functions("new_name");
        for (name, old, new) in [
            ("decompiled.c", b"OLD_C".as_slice(), b"NEW_C".as_slice()),
            ("disasm.lst", b"OLD_LST".as_slice(), b"NEW_LST".as_slice()),
            (
                "functions.json",
                old_functions.as_slice(),
                new_functions.as_slice(),
            ),
        ] {
            std::fs::write(dest.join(name), old).unwrap();
            std::fs::write(export.join(name), new).unwrap();
        }
        std::fs::write(dest.join("sidecar.bin"), b"SIDE").unwrap();
        let image = tagged_image(label, false);
        let mut validation_calls = 0usize;
        let mut validate =
            |ghidra_functions: &Path,
             thumb_functions: &Path,
             image: &decompile::ImageResult,
             expected: Option<&decompile::TerminalInventorySummary>| {
                validation_calls += 1;
                let summary = decompile::validate_image_terminal_inventory(
                    ghidra_functions,
                    thumb_functions,
                    image,
                    expected,
                )?;
                if validation_calls == 3 {
                    return Err(Error::DecomposeIncomplete(
                        "injected final validation failure".into(),
                    ));
                }
                Ok(summary)
            };
        let mut rename = |from: &Path, to: &Path| std::fs::rename(from, to);

        assert!(
            refresh_decompiled_with(&ghidra, &images, &image, &mut rename, &mut validate,).is_err()
        );
        assert_eq!(std::fs::read(dest.join("decompiled.c")).unwrap(), b"OLD_C");
        assert_eq!(std::fs::read(dest.join("disasm.lst")).unwrap(), b"OLD_LST");
        assert_eq!(
            std::fs::read(dest.join("functions.json")).unwrap(),
            old_functions
        );
        assert_eq!(std::fs::read(dest.join("sidecar.bin")).unwrap(), b"SIDE");
        assert_eq!(
            std::fs::read(export.join("decompiled.c")).unwrap(),
            b"NEW_C"
        );
        assert_eq!(
            std::fs::read(export.join("disasm.lst")).unwrap(),
            b"NEW_LST"
        );
        assert_eq!(
            std::fs::read(export.join("functions.json")).unwrap(),
            new_functions
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn refresh_decompiled_first_placement_rolls_back_failed_final_validation() {
        let root = std::env::temp_dir().join(format!(
            "pme_refresh_first_final_validation_failure_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let ghidra = root.join("ghidra");
        let images = root.join("images");
        let label = "02_MAIN";
        let dest = images.join(label).join("decompiled");
        let export = ghidra.join("export").join(label);
        std::fs::create_dir_all(&export).unwrap();
        let functions = tagged_functions("new_name");
        std::fs::write(export.join("decompiled.c"), b"NEW_C").unwrap();
        std::fs::write(export.join("disasm.lst"), b"NEW_LST").unwrap();
        std::fs::write(export.join("functions.json"), &functions).unwrap();
        let image = tagged_image(label, false);
        let mut validation_calls = 0usize;
        let mut validate =
            |ghidra_functions: &Path,
             thumb_functions: &Path,
             image: &decompile::ImageResult,
             expected: Option<&decompile::TerminalInventorySummary>| {
                validation_calls += 1;
                let summary = decompile::validate_image_terminal_inventory(
                    ghidra_functions,
                    thumb_functions,
                    image,
                    expected,
                )?;
                if validation_calls == 2 {
                    return Err(Error::DecomposeIncomplete(
                        "injected final validation failure".into(),
                    ));
                }
                Ok(summary)
            };
        let mut rename = |from: &Path, to: &Path| std::fs::rename(from, to);

        assert!(
            refresh_decompiled_with(&ghidra, &images, &image, &mut rename, &mut validate,).is_err()
        );
        assert!(
            !dest.exists(),
            "failed first placement must not look current"
        );
        assert_eq!(
            std::fs::read(export.join("decompiled.c")).unwrap(),
            b"NEW_C"
        );
        assert_eq!(
            std::fs::read(export.join("disasm.lst")).unwrap(),
            b"NEW_LST"
        );
        assert_eq!(
            std::fs::read(export.join("functions.json")).unwrap(),
            functions
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn refresh_decompiled_rejects_invalid_export_without_mutating_destination() {
        let root = std::env::temp_dir().join(format!("pme_refresh_reject_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let ghidra = root.join("ghidra");
        let images = root.join("images");
        let label = "02_MAIN";
        let dest = images.join(label).join("decompiled");
        std::fs::create_dir_all(dest.join("thumb")).unwrap();

        // Snapshot-worthy destination contents.
        let old_c = b"KEEP_C";
        let old_lst = b"KEEP_LST";
        let old_fn = b"KEEP_FN";
        let thumb_json = b"KEEP_THUMB_JSON";
        let thumb_stdout = b"KEEP_STDOUT";
        std::fs::write(dest.join("decompiled.c"), old_c).unwrap();
        std::fs::write(dest.join("disasm.lst"), old_lst).unwrap();
        std::fs::write(dest.join("functions.json"), old_fn).unwrap();
        std::fs::write(dest.join("thumb_functions.json"), thumb_json).unwrap();
        std::fs::write(dest.join("thumb").join("410b0000.stdout"), thumb_stdout).unwrap();
        let image = tagged_image(label, false);

        let assert_dest_untouched = |dest: &std::path::Path| {
            assert_eq!(std::fs::read(dest.join("decompiled.c")).unwrap(), old_c);
            assert_eq!(std::fs::read(dest.join("disasm.lst")).unwrap(), old_lst);
            assert_eq!(std::fs::read(dest.join("functions.json")).unwrap(), old_fn);
            assert_eq!(
                std::fs::read(dest.join("thumb_functions.json")).unwrap(),
                thumb_json
            );
            assert_eq!(
                std::fs::read(dest.join("thumb").join("410b0000.stdout")).unwrap(),
                thumb_stdout
            );
        };

        // Case A: incomplete export (missing functions.json).
        let export = ghidra.join("export").join(label);
        std::fs::create_dir_all(&export).unwrap();
        std::fs::write(export.join("decompiled.c"), b"NEW_C").unwrap();
        std::fs::write(export.join("disasm.lst"), b"NEW_LST").unwrap();
        // deliberately omit functions.json
        let err = refresh_decompiled(&ghidra, &images, &image).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("invalid pass-2 export") || msg.contains("expected exactly"),
            "incomplete export must error clearly, got: {msg}"
        );
        assert_dest_untouched(&dest);
        assert!(export.exists(), "failed validation must not consume export");

        // Case B: unexpected extra entry.
        std::fs::write(export.join("functions.json"), b"NEW_FN").unwrap();
        std::fs::write(export.join("extra.txt"), b"nope").unwrap();
        let err = refresh_decompiled(&ghidra, &images, &image).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("invalid pass-2 export") || msg.contains("expected exactly"),
            "unexpected entry must error clearly, got: {msg}"
        );
        assert_dest_untouched(&dest);

        // Case C: non-file entry (subdirectory) in export.
        let _ = std::fs::remove_file(export.join("extra.txt"));
        std::fs::create_dir(export.join("subdir")).unwrap();
        let err = refresh_decompiled(&ghidra, &images, &image).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("not a regular file") || msg.contains("invalid pass-2 export"),
            "non-file export entry must error clearly, got: {msg}"
        );
        assert_dest_untouched(&dest);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn refresh_decompiled_rejects_stale_terminal_pair_before_any_replacement() {
        let root = std::env::temp_dir().join(format!(
            "pme_refresh_terminal_reject_{}",
            std::process::id()
        ));
        let ghidra = root.join("ghidra");
        let images = root.join("images");
        let label = "02_MAIN";
        let dest = images.join(label).join("decompiled");
        let export = ghidra.join("export").join(label);
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::create_dir_all(&export).unwrap();
        let old_functions = serde_json::to_vec(&serde_json::json!([{
            "name":"current", "primary_source":"default", "entry":"0x4000", "end":"0x4004", "size":4,
            "decode_ranges":[{"isa":"arm","start":"0x4000","end":"0x4004","blake3":"ec2bd03bf86b935fa34d71ad7ebb049f1f10f87d343e521511d8f9e6625620cd"}],
            "decode_range_errors":[], "data_refs":[]
        }]))
        .unwrap();
        for (name, old, staged) in [
            ("decompiled.c", b"OLD_C".as_slice(), b"NEW_C".as_slice()),
            ("disasm.lst", b"OLD_LST".as_slice(), b"NEW_LST".as_slice()),
            (
                "functions.json",
                old_functions.as_slice(),
                br#"[{"name":"stale","entry":"0x4000","end":"0x4004","size":4,"data_refs":[]}]"#,
            ),
        ] {
            std::fs::write(dest.join(name), old).unwrap();
            std::fs::write(export.join(name), staged).unwrap();
        }
        let image = decompile::ImageResult {
            label: label.into(),
            outcome: ImageOutcome::Analyzed(1),
            classification: Some("not_opaque"),
            thumb_functions: None,
            thumb_regions_requested: None,
            thumb_regions_succeeded: None,
            thumb_regions_failed: None,
            thumb_radare2_runs: None,
            thumb_rizin_runs: None,
            ghidra_execution_accepted: Some(1),
            ghidra_execution_quarantined: Some(0),
            thumb_execution_accepted: None,
            thumb_execution_quarantined: None,
            image_start: 0x4000,
            image_len: 0x10,
            thumb_error: None,
            terminal_error: None,
            pass2_applied: None,
            pass2_creation_plan: None,
            pass2_thumb_names: None,
            pass2_error: None,
            thumb_decompiled: None,
            thumb_tighten_error: None,
            thumb_enrich_error: None,
            globals_error: None,
            globals_recovered: None,
            globals_applied: None,
            globals_apply_skipped: None,
            globals_apply_error: None,
            global_types_applied: None,
            global_types_apply_skipped: None,
            global_types_apply_error: None,
            globals_provisional: None,
            globals_provisional_suppressed: None,
            exception_state: decompile::RuntimeExceptionState::Unmanaged,
            exception_roots_applied: None,
            exception_error: None,
            pal_applied: None,
        };

        assert!(refresh_decompiled(&ghidra, &images, &image).is_err());
        assert_eq!(std::fs::read(dest.join("decompiled.c")).unwrap(), b"OLD_C");
        assert_eq!(std::fs::read(dest.join("disasm.lst")).unwrap(), b"OLD_LST");
        assert_eq!(
            std::fs::read(dest.join("functions.json")).unwrap(),
            old_functions
        );
        assert!(export.exists(), "failed validation retains staged evidence");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn prune_keeps_only_leaves() {
        let out = std::env::temp_dir().join(format!("pme_prune_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&out);
        std::fs::create_dir_all(out.join("rootfs").join("images").join("g5400i")).unwrap();
        std::fs::create_dir_all(out.join("rf_cfg_decompressed")).unwrap();
        std::fs::create_dir_all(out.join("ghidra").join("ghidra_project")).unwrap();
        std::fs::write(out.join("modem.ext4"), b"ext4").unwrap();
        std::fs::create_dir_all(out.join("images").join("02_MAIN").join("decompiled")).unwrap();
        std::fs::write(
            out.join("images").join("02_MAIN").join("02_MAIN.bin"),
            b"slice",
        )
        .unwrap();
        std::fs::write(
            out.join("images")
                .join("02_MAIN")
                .join("decompiled")
                .join("out.c"),
            b"// c",
        )
        .unwrap();
        std::fs::write(
            out.join("images/02_MAIN/decompiled/global_shapes.json"),
            b"{\"sentinel\":true}",
        )
        .unwrap();
        std::fs::write(
            out.join("images/02_MAIN/decompiled/thumb_functions.json"),
            b"{\"format\":\"thumb-sentinel\"}",
        )
        .unwrap();
        std::fs::create_dir_all(out.join("images/02_MAIN/decompiled/thumb")).unwrap();
        std::fs::write(
            out.join("images/02_MAIN/decompiled/thumb/40000000.radare2.stdout"),
            b"capture",
        )
        .unwrap();
        std::fs::create_dir_all(out.join("images/02_MAIN/scatter/blocks")).unwrap();
        std::fs::write(
            out.join("images/02_MAIN/scatter/load_map.json"),
            b"{\"format\":\"scatter-test\"}",
        )
        .unwrap();
        std::fs::write(
            out.join("images/02_MAIN/scatter/blocks/04-decompress1.bin"),
            b"payload",
        )
        .unwrap();
        // The marshalled PAL task manifest is a terminal leaf: prune keeps
        // the directory and never prunes anything below it.
        std::fs::create_dir_all(out.join("images/02_MAIN/pal_tasks")).unwrap();
        std::fs::write(
            out.join("images/02_MAIN/pal_tasks/tasks.json"),
            b"{\"format\":\"pixel-modem-extractor-pal-tasks-v1\"}",
        )
        .unwrap();
        std::fs::create_dir_all(out.join("images/02_MAIN/exception_roots")).unwrap();
        std::fs::write(
            out.join("images/02_MAIN/exception_roots/roots.json"),
            b"{\"format\":\"pixel-modem-extractor-exception-roots-v1\"}",
        )
        .unwrap();
        std::fs::create_dir_all(out.join("rf").join("decoded")).unwrap();
        std::fs::create_dir_all(out.join("tokens")).unwrap();
        std::fs::write(out.join("manifest.json"), b"{}").unwrap();

        prune(&out).unwrap();
        // A second sweep over an already-pruned tree is a no-op, not an error:
        // every removal treats an absent path as done.
        prune(&out).unwrap();

        assert!(!out.join("modem.ext4").exists());
        assert!(!out.join("rootfs").exists());
        assert!(!out.join("rf_cfg_decompressed").exists());
        assert!(!out.join("ghidra").exists());
        assert!(
            !out.join("images")
                .join("02_MAIN")
                .join("02_MAIN.bin")
                .exists()
        );
        assert!(
            out.join("images")
                .join("02_MAIN")
                .join("decompiled")
                .join("out.c")
                .exists()
        );
        assert_eq!(
            std::fs::read(out.join("images/02_MAIN/decompiled/global_shapes.json")).unwrap(),
            b"{\"sentinel\":true}"
        );
        assert_eq!(
            std::fs::read(out.join("images/02_MAIN/decompiled/thumb_functions.json")).unwrap(),
            b"{\"format\":\"thumb-sentinel\"}"
        );
        assert!(!out.join("images/02_MAIN/decompiled/thumb").exists());
        assert_eq!(
            std::fs::read(out.join("images/02_MAIN/scatter/load_map.json")).unwrap(),
            b"{\"format\":\"scatter-test\"}"
        );
        assert_eq!(
            std::fs::read(out.join("images/02_MAIN/scatter/blocks/04-decompress1.bin")).unwrap(),
            b"payload"
        );
        assert_eq!(
            std::fs::read(out.join("images/02_MAIN/pal_tasks/tasks.json")).unwrap(),
            b"{\"format\":\"pixel-modem-extractor-pal-tasks-v1\"}",
            "the PAL task manifest is a retained leaf"
        );
        assert_eq!(
            std::fs::read(out.join("images/02_MAIN/exception_roots/roots.json")).unwrap(),
            b"{\"format\":\"pixel-modem-extractor-exception-roots-v1\"}",
            "the exception-root manifest is a retained leaf"
        );
        assert!(out.join("rf").join("decoded").exists());
        assert!(out.join("tokens").exists());
        assert!(out.join("manifest.json").exists());
    }

    /// `report.json` must describe the tree that exists, not the flag that was
    /// passed: a failed sweep leaves a partially cleaned tree, so automation
    /// reading `pruned: true` would act on artifacts that are still present.
    #[test]
    fn prune_report_distinguishes_request_from_successful_completion() {
        let mut stages = Vec::new();
        assert!(!run_prune_stage(&mut stages, false, || panic!(
            "prune must not run unless requested"
        )));
        assert!(stages.is_empty());

        assert!(run_prune_stage(&mut stages, true, || Ok(())));
        assert!(stages.is_empty());

        assert!(!run_prune_stage(&mut stages, true, || Err(
            Error::Serialize("ghidra/ could not be removed".into())
        )));
        assert_eq!(stages.len(), 1);
        assert_eq!(stages[0].stage, "prune");
        assert_eq!(stages[0].status, "failed");
        assert!(
            stages[0]
                .error
                .as_deref()
                .is_some_and(|error| error.contains("could not be removed"))
        );
    }

    #[test]
    fn report_serializes_prune_request_and_completion_separately() {
        let report = Report {
            tool_version: "test".into(),
            source_image: "radio.img".into(),
            source_blake3: String::new(),
            modem_generation: None,
            out: "out".into(),
            ghidra: AnalysisTools {
                headless: "analyzeHeadless".into(),
                radare2: "/usr/bin/r2".into(),
                radare2_version: "radare2 6.1.4".into(),
                rizin_fallback: false,
                rizin: None,
                rizin_version: None,
            },
            prune_requested: true,
            pruned: false,
            ok: false,
            stages: Vec::new(),
        };

        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&report).unwrap()).unwrap();

        assert_eq!(json["prune_requested"], true);
        assert_eq!(json["pruned"], false);
    }

    #[test]
    fn rootfs_image_dir_finds_single_subdir() {
        let out = std::env::temp_dir().join(format!("pme_rootfs_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&out);
        std::fs::create_dir_all(out.join("rootfs").join("images").join("g5400i-abc")).unwrap();
        let d = rootfs_image_dir(&out).unwrap();
        assert!(d.ends_with("g5400i-abc"));
    }

    #[test]
    fn rootfs_image_dir_errors_notfound_when_absent() {
        let out = std::env::temp_dir().join(format!("pme_rootfs_absent_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&out);
        // <out>/rootfs/images/ doesn't exist at all -> typed NotFound, not a raw Io error
        assert!(matches!(rootfs_image_dir(&out), Err(Error::NotFound(_))));
    }

    #[test]
    #[allow(non_snake_case)]
    fn main_image_dir_name_finds_the_MAIN_split() {
        // cheetah layout: MAIN is 01_MAIN
        let tmp = std::env::temp_dir().join("pme_main_dir_cheetah");
        let _ = std::fs::remove_dir_all(&tmp);
        for d in ["00_BOOT", "01_MAIN", "02_VSS", "03_APM"] {
            std::fs::create_dir_all(tmp.join(d)).unwrap();
        }
        assert_eq!(main_image_dir_name(&tmp).as_deref(), Some("01_MAIN"));

        // mustang layout: MAIN is 02_MAIN
        let tmp2 = std::env::temp_dir().join("pme_main_dir_mustang");
        let _ = std::fs::remove_dir_all(&tmp2);
        for d in ["00_BOOT", "01_PSP", "02_MAIN", "05_DBGCORE"] {
            std::fs::create_dir_all(tmp2.join(d)).unwrap();
        }
        assert_eq!(main_image_dir_name(&tmp2).as_deref(), Some("02_MAIN"));

        // no MAIN image
        let tmp3 = std::env::temp_dir().join("pme_main_dir_none");
        let _ = std::fs::remove_dir_all(&tmp3);
        std::fs::create_dir_all(tmp3.join("00_BOOT")).unwrap();
        assert_eq!(main_image_dir_name(&tmp3), None);
    }

    #[test]
    fn image_report_serializes_phase2_fields_as_none_when_absent() {
        let r = decompile::ImageResult {
            label: "02_MAIN".into(),
            outcome: decompile::ImageOutcome::Analyzed(10),
            classification: Some("not_opaque"),
            thumb_functions: Some(5),
            thumb_regions_requested: None,
            thumb_regions_succeeded: None,
            thumb_regions_failed: None,
            thumb_radare2_runs: None,
            thumb_rizin_runs: None,
            ghidra_execution_accepted: None,
            ghidra_execution_quarantined: None,
            thumb_execution_accepted: None,
            thumb_execution_quarantined: None,
            image_start: 0,
            image_len: 0,
            thumb_error: None,
            terminal_error: None,
            pass2_applied: None,
            pass2_creation_plan: None,
            pass2_thumb_names: None,
            pass2_error: None,
            thumb_decompiled: None,
            thumb_tighten_error: None,
            thumb_enrich_error: None,
            globals_error: None,
            globals_recovered: None,
            globals_applied: None,
            globals_apply_skipped: None,
            globals_apply_error: None,
            global_types_applied: None,
            global_types_apply_skipped: None,
            global_types_apply_error: None,
            globals_provisional: None,
            globals_provisional_suppressed: None,
            exception_state: decompile::RuntimeExceptionState::Unmanaged,
            exception_roots_applied: None,
            exception_error: None,
            pal_applied: None,
        };
        let report = ImageReport::from_result(&r);
        let json = serde_json::to_string(&report).unwrap();
        // New fields must serialize as absent (skip_serializing_if = Option::is_none).
        assert!(!json.contains("thumb_decompiled"));
        assert!(!json.contains("thumb_tighten_error"));
        assert!(!json.contains("thumb_enrich_error"));
    }

    #[test]
    fn image_report_serializes_phase2_fields_when_set() {
        let r = decompile::ImageResult {
            label: "02_MAIN".into(),
            outcome: decompile::ImageOutcome::Analyzed(10),
            classification: Some("not_opaque"),
            thumb_functions: Some(5),
            thumb_regions_requested: None,
            thumb_regions_succeeded: None,
            thumb_regions_failed: None,
            thumb_radare2_runs: None,
            thumb_rizin_runs: None,
            ghidra_execution_accepted: None,
            ghidra_execution_quarantined: None,
            thumb_execution_accepted: None,
            thumb_execution_quarantined: None,
            image_start: 0,
            image_len: 0,
            thumb_error: None,
            terminal_error: None,
            pass2_applied: None,
            pass2_creation_plan: None,
            pass2_thumb_names: None,
            pass2_error: None,
            thumb_decompiled: Some(3),
            thumb_tighten_error: None,
            thumb_enrich_error: Some("malformed decompiled.c".into()),
            globals_error: None,
            globals_recovered: None,
            globals_applied: None,
            globals_apply_skipped: None,
            globals_apply_error: None,
            global_types_applied: None,
            global_types_apply_skipped: None,
            global_types_apply_error: None,
            globals_provisional: None,
            globals_provisional_suppressed: None,
            exception_state: decompile::RuntimeExceptionState::Unmanaged,
            exception_roots_applied: None,
            exception_error: None,
            pal_applied: None,
        };
        let report = ImageReport::from_result(&r);
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"thumb_decompiled\":3"));
        assert!(!json.contains("thumb_tighten_error"));
        assert!(json.contains("\"thumb_enrich_error\":\"malformed decompiled.c\""));
    }

    #[test]
    fn image_report_serializes_pass2_creation_plan_and_runtime_conservation() {
        let mut result = analyzed_image("02_MAIN");
        result.pass2_creation_plan = Some(decompile::Pass2CreationPlan {
            candidates: 3,
            skips: symbolicate::Pass2CreationSkips {
                ambiguous: 1,
                collision: 2,
                name_limit: 3,
                limit: 4,
                not_entry_start: 5,
            },
            requests: Vec::new(),
        });
        result.pass2_thumb_names = Some(decompile::AppliedThumbNames {
            candidates: 3,
            created: 1,
            reapplied: 0,
            skipped_existing: 1,
            skipped_collision: 1,
        });

        let json = serde_json::to_value(ImageReport::from_result(&result)).unwrap();

        assert_eq!(json["pass2_creation_candidates"], 3);
        assert_eq!(json["pass2_creation_map_skips"]["ambiguous"], 1);
        assert_eq!(json["pass2_creation_map_skips"]["collision"], 2);
        assert_eq!(json["pass2_creation_map_skips"]["name_limit"], 3);
        assert_eq!(json["pass2_creation_map_skips"]["limit"], 4);
        assert_eq!(json["pass2_creation_map_skips"]["not_entry_start"], 5);
        assert_eq!(json["pass2_created"], 1);
        assert_eq!(json["pass2_creation_reapplied"], 0);
        assert_eq!(json["pass2_creation_skipped_existing"], 1);
        assert_eq!(json["pass2_creation_skipped_collision"], 1);
    }

    #[test]
    fn image_report_serializes_phase3_globals_fields_as_none_when_absent() {
        let r = decompile::ImageResult {
            label: "02_MAIN".into(),
            outcome: decompile::ImageOutcome::Analyzed(10),
            classification: Some("not_opaque"),
            thumb_functions: Some(5),
            thumb_regions_requested: None,
            thumb_regions_succeeded: None,
            thumb_regions_failed: None,
            thumb_radare2_runs: None,
            thumb_rizin_runs: None,
            ghidra_execution_accepted: None,
            ghidra_execution_quarantined: None,
            thumb_execution_accepted: None,
            thumb_execution_quarantined: None,
            image_start: 0,
            image_len: 0,
            thumb_error: None,
            terminal_error: None,
            pass2_applied: None,
            pass2_creation_plan: None,
            pass2_thumb_names: None,
            pass2_error: None,
            thumb_decompiled: None,
            thumb_tighten_error: None,
            thumb_enrich_error: None,
            globals_recovered: None,
            globals_error: None,
            globals_applied: None,
            globals_apply_skipped: None,
            globals_apply_error: None,
            global_types_applied: None,
            global_types_apply_skipped: None,
            global_types_apply_error: None,
            globals_provisional: None,
            globals_provisional_suppressed: None,
            exception_state: decompile::RuntimeExceptionState::Unmanaged,
            exception_roots_applied: None,
            exception_error: None,
            pal_applied: None,
        };
        let report = ImageReport::from_result(&r);
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("globals_recovered"));
        assert!(!json.contains("globals_error"));
        assert!(!json.contains("\"globals_provisional\""));
        assert!(!json.contains("\"globals_provisional_suppressed\""));
    }

    #[test]
    fn image_report_serializes_phase3_globals_fields_when_set() {
        let r = decompile::ImageResult {
            label: "02_MAIN".into(),
            outcome: decompile::ImageOutcome::Analyzed(10),
            classification: Some("not_opaque"),
            thumb_functions: Some(5),
            thumb_regions_requested: None,
            thumb_regions_succeeded: None,
            thumb_regions_failed: None,
            thumb_radare2_runs: None,
            thumb_rizin_runs: None,
            ghidra_execution_accepted: None,
            ghidra_execution_quarantined: None,
            thumb_execution_accepted: None,
            thumb_execution_quarantined: None,
            image_start: 0,
            image_len: 0,
            thumb_error: None,
            terminal_error: None,
            pass2_applied: None,
            pass2_creation_plan: None,
            pass2_thumb_names: None,
            pass2_error: None,
            thumb_decompiled: None,
            thumb_tighten_error: None,
            thumb_enrich_error: None,
            globals_recovered: Some(137),
            exception_state: decompile::RuntimeExceptionState::Unmanaged,
            exception_roots_applied: None,
            exception_error: None,
            pal_applied: None,
            globals_error: Some("malformed functions.json".into()),
            globals_applied: None,
            globals_apply_skipped: None,
            globals_apply_error: None,
            global_types_applied: None,
            global_types_apply_skipped: None,
            global_types_apply_error: None,
            globals_provisional: Some(50),
            globals_provisional_suppressed: Some(3),
        };
        let report = ImageReport::from_result(&r);
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"globals_recovered\":137"));
        assert!(json.contains("\"globals_error\":\"malformed functions.json\""));
        assert!(json.contains("\"globals_provisional\":50"));
        assert!(json.contains("\"globals_provisional_suppressed\":3"));
        assert!(!json.contains("global_shapes_inferred"));
        assert!(!json.contains("global_shapes_error"));
    }

    fn absent_global_shapes_keys(value: &serde_json::Value) {
        for key in [
            "global_shapes_inferred",
            "global_shapes_no_evidence",
            "global_shapes_conflicting",
            "global_shape_observations",
            "global_shapes_ghidra_quarantined",
            "global_shapes_thumb_quarantined",
            "global_shapes_quarantine_errors",
            "global_shapes_decode_failures",
            "global_shapes_state_barriers",
            "global_shapes_error",
        ] {
            assert!(value.get(key).is_none(), "{key} must be omitted");
        }
    }

    fn set_zero_global_shapes(image: &mut ImageReport) {
        image.global_shapes_inferred = Some(0);
        image.global_shapes_no_evidence = Some(0);
        image.global_shapes_conflicting = Some(0);
        image.global_shape_observations = Some(0);
        image.global_shapes_ghidra_quarantined = Some(0);
        image.global_shapes_thumb_quarantined = Some(0);
        image.global_shapes_quarantine_errors = Some(0);
        image.global_shapes_decode_failures = Some(0);
        image.global_shapes_state_barriers = Some(0);
        image.global_shapes_error = None;
    }

    fn zero_shapes_report() -> global_shapes::GlobalShapesReport {
        global_shapes::GlobalShapesReport {
            inferred: 0,
            no_evidence: 0,
            conflicting: 0,
            observations: 0,
            ghidra_quarantined: 0,
            thumb_quarantined: 0,
            quarantine_errors: 0,
            decode_failures: 0,
            state_barriers: 0,
            interprocedural_dropped: 0,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn eligible_shape_result(
        label: &str,
        functions: usize,
        accepted: usize,
        quarantined: usize,
        thumb_functions: Option<usize>,
        thumb_accepted: Option<usize>,
        thumb_quarantined: Option<usize>,
        recovered: usize,
    ) -> decompile::ImageResult {
        let mut result = analyzed_image(label);
        result.outcome = ImageOutcome::Analyzed(functions);
        result.ghidra_execution_accepted = Some(accepted);
        result.ghidra_execution_quarantined = Some(quarantined);
        result.thumb_functions = thumb_functions;
        result.thumb_execution_accepted = thumb_accepted;
        result.thumb_execution_quarantined = thumb_quarantined;
        result.globals_recovered = Some(recovered);
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn eligible_shape_image(
        label: &str,
        functions: usize,
        accepted: usize,
        quarantined: usize,
        thumb_functions: Option<usize>,
        thumb_accepted: Option<usize>,
        thumb_quarantined: Option<usize>,
        recovered: usize,
    ) -> ImageReport {
        ImageReport::from_result(&eligible_shape_result(
            label,
            functions,
            accepted,
            quarantined,
            thumb_functions,
            thumb_accepted,
            thumb_quarantined,
            recovered,
        ))
    }

    fn empty_globals_json(label: &str) -> String {
        format!(
            r#"{{"format":"pixel-modem-extractor-globals-v1","image":"{label}","globals":[],"phase3_0_1_error":null,"provisional_suppressed":0}}"#
        )
    }

    fn write_empty_shape_image(images_dir: &Path, label: &str) {
        let image_dir = images_dir.join(label);
        let decompiled = image_dir.join("decompiled");
        std::fs::create_dir_all(&decompiled).unwrap();
        std::fs::write(image_dir.join(format!("{label}.bin")), vec![0u8; 0x40]).unwrap();
        std::fs::write(decompiled.join("functions.json"), tagged_functions(label)).unwrap();
        std::fs::write(decompiled.join("globals.json"), empty_globals_json(label)).unwrap();
    }

    fn write_shape_manifest(path: &Path, labels: &[&str]) {
        let toc: Vec<String> = labels
            .iter()
            .map(|label| {
                let name = label
                    .rsplit_once('_')
                    .map(|(_, name)| name)
                    .unwrap_or(label);
                format!(r#"{{"name":"{name}","load_addr":16384}}"#)
            })
            .collect();
        std::fs::write(path, format!(r#"{{"toc":[{}]}}"#, toc.join(","))).unwrap();
    }

    fn last_stage(stages: &[StageReport]) -> &StageReport {
        stages.last().expect("stage report")
    }

    fn assert_nine_shape_counts(image: &ImageReport, expected: Option<usize>) {
        assert_eq!(image.global_shapes_inferred, expected);
        assert_eq!(image.global_shapes_no_evidence, expected);
        assert_eq!(image.global_shapes_conflicting, expected);
        assert_eq!(image.global_shape_observations, expected);
        assert_eq!(image.global_shapes_ghidra_quarantined, expected);
        assert_eq!(image.global_shapes_thumb_quarantined, expected);
        assert_eq!(image.global_shapes_quarantine_errors, expected);
        assert_eq!(image.global_shapes_decode_failures, expected);
        assert_eq!(image.global_shapes_state_barriers, expected);
    }

    #[test]
    fn image_report_serializes_global_shapes_fields_as_none_when_absent() {
        let report = ImageReport::from_result(&analyzed_image("02_MAIN"));
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "image": "02_MAIN",
                "status": "analyzed",
                "classification": "not_opaque",
                "functions": 1
            })
        );
        absent_global_shapes_keys(&value);
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("thumb_decompiled"));
        assert!(!json.contains("globals_recovered"));
        assert!(!json.contains("global_shapes_"));
        assert!(!json.contains("global_shape_observations"));
    }

    #[test]
    fn image_report_serializes_global_shapes_zero_success() {
        let mut report = ImageReport::from_result(&analyzed_image("02_MAIN"));
        set_zero_global_shapes(&mut report);
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "image": "02_MAIN",
                "status": "analyzed",
                "classification": "not_opaque",
                "functions": 1,
                "global_shapes_inferred": 0,
                "global_shapes_no_evidence": 0,
                "global_shapes_conflicting": 0,
                "global_shape_observations": 0,
                "global_shapes_ghidra_quarantined": 0,
                "global_shapes_thumb_quarantined": 0,
                "global_shapes_quarantine_errors": 0,
                "global_shapes_decode_failures": 0,
                "global_shapes_state_barriers": 0
            })
        );
        assert!(value.get("global_shapes_error").is_none());
    }

    #[test]
    fn image_report_serializes_global_shapes_nonzero_success() {
        let mut report = ImageReport::from_result(&analyzed_image("02_MAIN"));
        report.global_shapes_inferred = Some(4);
        report.global_shapes_no_evidence = Some(5);
        report.global_shapes_conflicting = Some(1);
        report.global_shape_observations = Some(9);
        report.global_shapes_ghidra_quarantined = Some(2);
        report.global_shapes_thumb_quarantined = Some(3);
        report.global_shapes_quarantine_errors = Some(6);
        report.global_shapes_decode_failures = Some(7);
        report.global_shapes_state_barriers = Some(8);
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["global_shapes_inferred"], 4);
        assert_eq!(value["global_shapes_no_evidence"], 5);
        assert_eq!(value["global_shapes_conflicting"], 1);
        assert_eq!(value["global_shape_observations"], 9);
        assert_eq!(value["global_shapes_ghidra_quarantined"], 2);
        assert_eq!(value["global_shapes_thumb_quarantined"], 3);
        assert_eq!(value["global_shapes_quarantine_errors"], 6);
        assert_eq!(value["global_shapes_decode_failures"], 7);
        assert_eq!(value["global_shapes_state_barriers"], 8);
        assert!(value.get("global_shapes_error").is_none());
    }

    #[test]
    fn image_report_serializes_global_shapes_failure_omits_counts() {
        let mut result = tagged_image("02_MAIN", true);
        result.outcome = ImageOutcome::Analyzed(1);
        let mut report = ImageReport::from_result(&result);
        report.global_shapes_error = Some("malformed functions.json".into());
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["ghidra_execution_accepted"], 1);
        assert_eq!(value["ghidra_execution_quarantined"], 0);
        assert_eq!(value["thumb_execution_accepted"], 1);
        assert_eq!(value["thumb_execution_quarantined"], 0);
        assert_eq!(value["global_shapes_error"], "malformed functions.json");
        for key in [
            "global_shapes_inferred",
            "global_shapes_no_evidence",
            "global_shapes_conflicting",
            "global_shape_observations",
            "global_shapes_ghidra_quarantined",
            "global_shapes_thumb_quarantined",
            "global_shapes_quarantine_errors",
            "global_shapes_decode_failures",
            "global_shapes_state_barriers",
        ] {
            assert!(
                value.get(key).is_none(),
                "{key} must stay absent on failure"
            );
        }
    }

    #[test]
    fn image_report_serializes_global_types_fields() {
        let mut image = ImageReport::from_result(&analyzed_image("02_MAIN"));
        image.global_types_applied = Some(120);
        image.global_types_candidates = Some(123);
        image.global_types_ineligible = Some(4);
        image.global_types_skipped = Some(3);
        let v = serde_json::to_value(&image).unwrap();
        assert_eq!(v["global_types_applied"], 120);
        assert_eq!(v["global_types_candidates"], 123);
        assert_eq!(v["global_types_ineligible"], 4);
        assert_eq!(v["global_types_skipped"], 3);
        assert!(v.get("global_types_error").is_none());
    }

    #[test]
    fn image_report_serializes_global_types_fields_as_none_when_absent() {
        let report = ImageReport::from_result(&analyzed_image("02_MAIN"));
        let value = serde_json::to_value(&report).unwrap();
        for key in [
            "global_types_applied",
            "global_types_candidates",
            "global_types_ineligible",
            "global_types_skipped",
            "global_types_error",
        ] {
            assert!(value.get(key).is_none(), "{key} must be omitted");
        }
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("global_types_"));
    }

    #[test]
    fn global_shapes_stage_invokes_each_eligible_image_once_in_pipeline_order() {
        let root = std::env::temp_dir().join(format!(
            "pme_global_shapes_stage_order_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let images_dir = root.join("images");
        let manifest = root.join("manifest.json");
        let mut stages = vec![
            StageReport::ok("extract", "manifest.json", 1),
            StageReport::decompile(
                vec![
                    eligible_shape_image("02_MAIN", 2, 1, 1, Some(1), Some(1), Some(0), 3),
                    eligible_shape_image("03_APM", 1, 1, 0, None, None, None, 0),
                ],
                10,
            ),
        ];
        let mut calls = Vec::new();
        let current = [
            eligible_shape_result("02_MAIN", 2, 1, 1, Some(1), Some(1), Some(0), 3),
            eligible_shape_result("03_APM", 1, 1, 0, None, None, None, 0),
        ];
        run_global_shapes_stage_with(&mut stages, &images_dir, &manifest, &current, |request| {
            calls.push((
                request.image_label.to_string(),
                request.image_dir.to_path_buf(),
                request.manifest_path.to_path_buf(),
                request.expected_ghidra_records,
                request.expected_ghidra_accepted,
                request.expected_ghidra_quarantined,
                request.expected_thumb_substantial,
                request.expected_thumb_accepted,
                request.expected_thumb_quarantined,
                request.expected_recovered_globals,
            ));
            Ok(global_shapes::GlobalShapesReport {
                inferred: if request.image_label == "02_MAIN" {
                    2
                } else {
                    0
                },
                no_evidence: if request.image_label == "02_MAIN" {
                    1
                } else {
                    0
                },
                conflicting: 0,
                observations: if request.image_label == "02_MAIN" {
                    4
                } else {
                    0
                },
                ghidra_quarantined: request.expected_ghidra_quarantined,
                thumb_quarantined: request.expected_thumb_quarantined.unwrap_or(0),
                quarantine_errors: 1,
                decode_failures: 0,
                state_barriers: 0,
                interprocedural_dropped: 0,
            })
        });

        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, "02_MAIN");
        assert_eq!(calls[0].1, images_dir.join("02_MAIN"));
        assert_eq!(calls[0].2, manifest);
        assert_eq!(calls[0].3, 2);
        assert_eq!(calls[0].4, 1);
        assert_eq!(calls[0].5, 1);
        assert_eq!(calls[0].6, Some(1));
        assert_eq!(calls[0].7, Some(1));
        assert_eq!(calls[0].8, Some(0));
        assert_eq!(calls[0].9, 3);
        assert_eq!(calls[1].0, "03_APM");
        assert_eq!(calls[1].9, 0);
        assert_eq!(calls[1].6, None);
        assert_eq!(calls[1].7, None);
        assert_eq!(calls[1].8, None);
        assert_eq!(stages.len(), 3);
        assert!(stages[0].images.is_empty());
        assert!(last_stage(&stages).images.is_empty());
        assert_eq!(last_stage(&stages).stage, "global_shapes");
        assert_eq!(last_stage(&stages).status, "ok");
        assert_eq!(
            last_stage(&stages).output.as_deref(),
            Some(
                "images/*/decompiled/global_shapes.json (completed=2/2, inferred=2, no_evidence=1, conflicting=0, observations=4, ghidra_quarantined=1, thumb_quarantined=0, quarantine_errors=2, decode_failures=0, state_barriers=0)"
            )
        );
        assert!(last_stage(&stages).error.is_none());
        assert_eq!(stages[1].images[0].global_shapes_inferred, Some(2));
        assert_eq!(stages[1].images[0].global_shapes_no_evidence, Some(1));
        assert_eq!(stages[1].images[1].global_shapes_inferred, Some(0));
        assert_eq!(stages[1].status, "ok");
        assert_eq!(stages[1].images[0].status, "analyzed");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn global_shapes_final_rerun_recommits_sidecar_over_rewritten_inputs() {
        // Task 6c-2 regression (fix round 1): the normal route's first sweep
        // runs before DispatchPass2, but three later steps rewrite the
        // sidecar's hashed inputs — pass 2's ownership-aware refresh
        // (functions.json), thumb_enrich_post_pass2 (thumb_functions.json),
        // and symbolicate_finalize (BOTH files: name/original_name/
        // annotations stamps) — so any commit earlier than after Finalize is
        // born stale (the first implementation re-committed after
        // thumb_enrich_post_pass2 and was re-staled by finalize's writes;
        // measured e2e mtimes: finalize rewrites both files ~1 minute after
        // that re-commit). The route answer — re-run the REAL stage after the
        // last input rewriter — is modeled here by calling the stage wrapper
        // twice over a fixture, replaying all three rewrites in order between
        // the sweeps (the finalize one through the real
        // symbolicate::rewrite_functions_json), and asserting the tree ends
        // with exactly one global_shapes stage entry whose committed sidecar
        // hashes the FINAL files.
        let root = std::env::temp_dir().join(format!(
            "pme_global_shapes_final_rerun_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let images_dir = root.join("images");
        let manifest_path = root.join("manifest.json");
        std::fs::create_dir_all(&images_dir).unwrap();
        write_shape_manifest(&manifest_path, &["02_MAIN"]);
        write_empty_shape_image(&images_dir, "02_MAIN");
        let decompiled = images_dir.join("02_MAIN").join("decompiled");
        let functions_path = decompiled.join("functions.json");
        let thumb_path = decompiled.join("thumb_functions.json");
        std::fs::write(&thumb_path, tagged_thumb_functions()).unwrap();

        let current = [eligible_shape_result(
            "02_MAIN",
            1,
            1,
            0,
            Some(1),
            Some(1),
            Some(0),
            0,
        )];
        let mut stages = vec![StageReport::decompile(
            vec![eligible_shape_image(
                "02_MAIN",
                1,
                1,
                0,
                Some(1),
                Some(1),
                Some(0),
                0,
            )],
            10,
        )];

        let pass1_functions = std::fs::read(&functions_path).unwrap();
        let pass1_thumb = std::fs::read(&thumb_path).unwrap();
        let first_outcomes =
            run_global_shapes_stage(&mut stages, &images_dir, &manifest_path, &current);
        assert_eq!(first_outcomes.len(), 1);
        let sidecar = decompiled.join("global_shapes.json");
        let first_sidecar: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&sidecar).unwrap()).unwrap();
        assert_eq!(
            first_sidecar["inputs"]["functions_blake3"],
            serde_json::Value::String(manifest::blake3_bytes(&pass1_functions))
        );
        assert_eq!(
            first_sidecar["inputs"]["thumb_functions_blake3"],
            serde_json::Value::String(manifest::blake3_bytes(&pass1_thumb))
        );

        // Simulate the route's post-first-sweep input rewrites in execution
        // order: (1) pass 2's ownership-aware refresh rewrites functions.json
        // (recovered names, same inventory); (2) thumb_enrich_post_pass2
        // rewrites thumb_functions.json (body_c populated, same counts);
        // (3) symbolicate_finalize rewrites BOTH files again —
        // rewrite_functions_json stamps name/original_name/annotations into
        // every entry matched by address, and it runs AFTER the old
        // RefreshGlobalShapes slot (between ApplyGlobalTypes and the route's
        // end), which is exactly why the re-commit must follow Finalize.
        // Drive the REAL finalize rewriter, not a byte simulation.
        let pass2_functions = tagged_functions("recovered_4000");
        std::fs::write(&functions_path, &pass2_functions).unwrap();
        let raw = std::fs::read(images_dir.join("02_MAIN/02_MAIN.bin")).unwrap();
        let runtime = crate::runtime_image::RuntimeImage::from_plan(&raw, 0x4000, None).unwrap();
        let functions: serde_json::Value = serde_json::from_slice(&pass2_functions).unwrap();
        let ghidra_inventory = crate::execution_ranges::validate_ghidra_inventory_records(
            functions.as_array().unwrap(),
            1,
            &runtime,
        )
        .unwrap();
        let mut thumb_artifact =
            crate::thumb_analysis::read_thumb_artifact(&thumb_path, &runtime).unwrap();
        let thumb_function = thumb_artifact.functions().next().unwrap();
        let thumb_owner = thumb_function.owner;
        let thumb_execution_blake3 = thumb_function.execution.unwrap().execution_blake3;
        thumb_artifact.function_values_mut()[0]["body_c"] = "movs r0, r0".into();
        thumb_artifact.write_atomic(&thumb_path).unwrap();
        let rewritten_thumb = std::fs::read(&thumb_path).unwrap();
        // One symbol per owned execution: the Ghidra ARM entry and concrete
        // Thumb run at the same address are stamped from their own symbols.
        let mut ghidra_symbol = test_symbol(
            "0x4000",
            "arm",
            Some("Recovered_4000"),
            symbolicate::Tier::Recovered,
        );
        ghidra_symbol.execution_blake3 = Some(
            ghidra_inventory.accepted_executions[0]
                .identity
                .execution_blake3,
        );
        let mut thumb_symbol = test_symbol(
            "0x4000",
            "thumb",
            Some("Recovered_thumb_4000"),
            symbolicate::Tier::Recovered,
        );
        thumb_symbol.owner = thumb_owner;
        thumb_symbol.execution_blake3 = Some(thumb_execution_blake3);
        symbolicate::rewrite_functions_json(&decompiled, &runtime, &[ghidra_symbol, thumb_symbol])
            .unwrap();
        let final_functions = std::fs::read(&functions_path).unwrap();
        let final_thumb = std::fs::read(&thumb_path).unwrap();
        assert_ne!(
            final_functions, pass2_functions,
            "the finalize stamp must change functions.json bytes"
        );
        assert_ne!(
            final_thumb, rewritten_thumb,
            "the finalize stamp must change thumb_functions.json bytes"
        );

        // The final re-run (the route's RefreshGlobalShapes step, after
        // Finalize): same current inventories — pass 2 is -noanalysis, so
        // function boundaries never move between the sweeps.
        let final_outcomes =
            run_global_shapes_stage(&mut stages, &images_dir, &manifest_path, &current);

        // Exactly one global_shapes entry: the re-run replaced the first
        // sweep's entry in place (stages stays [decompile, global_shapes]).
        let shapes_positions: Vec<usize> = stages
            .iter()
            .enumerate()
            .filter(|(_, stage)| stage.stage == "global_shapes")
            .map(|(index, _)| index)
            .collect();
        assert_eq!(
            shapes_positions,
            vec![1],
            "the re-run must replace the first sweep's entry in place: {shapes_positions:?}"
        );
        assert_eq!(stages[1].status, "ok");
        assert_eq!(
            stages[1].output.as_deref(),
            Some(
                "images/*/decompiled/global_shapes.json (completed=1/1, inferred=0, no_evidence=0, conflicting=0, observations=0, ghidra_quarantined=0, thumb_quarantined=0, quarantine_errors=0, decode_failures=0, state_barriers=0)"
            )
        );

        // The committed sidecar hashes the FINAL files — post-finalize bytes,
        // not the pass-1 or even the pass-2/thumb-era ones.
        let final_sidecar: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&sidecar).unwrap()).unwrap();
        assert_eq!(
            final_sidecar["inputs"]["functions_blake3"],
            serde_json::Value::String(manifest::blake3_bytes(&final_functions))
        );
        assert_ne!(
            final_sidecar["inputs"]["functions_blake3"],
            first_sidecar["inputs"]["functions_blake3"]
        );
        assert_ne!(
            final_sidecar["inputs"]["functions_blake3"],
            serde_json::Value::String(manifest::blake3_bytes(&pass2_functions)),
            "the final commit must reflect the finalize rewrite, not stop at pass 2's"
        );
        assert_eq!(
            final_sidecar["inputs"]["thumb_functions_blake3"],
            serde_json::Value::String(manifest::blake3_bytes(&final_thumb))
        );
        assert_ne!(
            final_sidecar["inputs"]["thumb_functions_blake3"],
            first_sidecar["inputs"]["thumb_functions_blake3"]
        );
        assert_ne!(
            final_sidecar["inputs"]["thumb_functions_blake3"],
            serde_json::Value::String(manifest::blake3_bytes(&rewritten_thumb)),
            "the final commit must reflect the finalize rewrite, not stop at thumb_enrich's"
        );
        // Un-rewritten inputs keep their hashes.
        assert_eq!(
            final_sidecar["inputs"]["image_blake3"],
            first_sidecar["inputs"]["image_blake3"]
        );
        assert_eq!(
            final_sidecar["inputs"]["globals_blake3"],
            first_sidecar["inputs"]["globals_blake3"]
        );

        // The retained outcome map reflects the FINAL run and the decompile
        // stage image keeps its nine report fields after the in-place re-patch.
        assert!(matches!(
            final_outcomes.get("02_MAIN"),
            Some(GlobalShapesOutcome::Success(_))
        ));
        assert_eq!(final_outcomes.len(), 1);
        assert_nine_shape_counts(&stages[0].images[0], Some(0));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn global_shapes_stage_invokes_zero_recovered_and_skips_unready_images() {
        let root = std::env::temp_dir().join(format!(
            "pme_global_shapes_stage_gates_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let images_dir = root.join("images");
        let manifest = root.join("manifest.json");
        let missing_arm = eligible_shape_image("00_BOOT", 1, 1, 0, None, None, None, 0);
        let mut missing_arm = ImageReport {
            functions: None,
            ghidra_execution_accepted: None,
            ghidra_execution_quarantined: None,
            ..missing_arm
        };
        missing_arm.global_shapes_inferred = Some(9);
        let mut thumb_failed = eligible_shape_image("01_PSP", 1, 1, 0, None, None, None, 0);
        thumb_failed.thumb_error = Some("radare2 failed".into());
        let mut missing_globals = eligible_shape_image("04_VSS", 1, 1, 0, None, None, None, 0);
        missing_globals.globals_recovered = None;
        let mut globals_failed = eligible_shape_image("05_DBGCORE", 1, 1, 0, None, None, None, 4);
        globals_failed.globals_error = Some("old globals stale".into());
        let zero = eligible_shape_image("03_APM", 1, 1, 0, None, None, None, 0);
        let mut stages = vec![StageReport::decompile(
            vec![
                missing_arm,
                thumb_failed,
                missing_globals,
                globals_failed,
                zero,
            ],
            4,
        )];
        let mut calls = Vec::new();
        let mut missing_arm_current =
            eligible_shape_result("00_BOOT", 1, 1, 0, None, None, None, 0);
        missing_arm_current.outcome = ImageOutcome::Failed(-1);
        let mut thumb_failed_current =
            eligible_shape_result("01_PSP", 1, 1, 0, None, None, None, 0);
        thumb_failed_current.thumb_error = Some("radare2 failed".into());
        let mut missing_globals_current =
            eligible_shape_result("04_VSS", 1, 1, 0, None, None, None, 0);
        missing_globals_current.globals_recovered = None;
        let mut globals_failed_current =
            eligible_shape_result("05_DBGCORE", 1, 1, 0, None, None, None, 4);
        globals_failed_current.globals_error = Some("old globals stale".into());
        let current = [
            missing_arm_current,
            thumb_failed_current,
            missing_globals_current,
            globals_failed_current,
            eligible_shape_result("03_APM", 1, 1, 0, None, None, None, 0),
        ];
        run_global_shapes_stage_with(&mut stages, &images_dir, &manifest, &current, |request| {
            calls.push(request.image_label.to_string());
            assert_eq!(request.expected_recovered_globals, 0);
            Ok(zero_shapes_report())
        });

        assert_eq!(calls, vec!["03_APM".to_string()]);
        assert_eq!(stages[0].status, "ok");
        assert_eq!(stages[0].images[0].status, "analyzed");
        assert_eq!(
            stages[0].images[0].global_shapes_error.as_deref(),
            Some("missing current ARM inventory")
        );
        assert_nine_shape_counts(&stages[0].images[0], None);
        assert_eq!(
            stages[0].images[1].global_shapes_error.as_deref(),
            Some("current Thumb inventory failed")
        );
        assert_eq!(
            stages[0].images[2].global_shapes_error.as_deref(),
            Some("missing current recovered globals")
        );
        assert_eq!(
            stages[0].images[3].global_shapes_error.as_deref(),
            Some("current globals failed")
        );
        assert_nine_shape_counts(&stages[0].images[4], Some(0));
        assert!(stages[0].images[4].global_shapes_error.is_none());
        assert_eq!(last_stage(&stages).status, "failed");
        assert!(!Report::is_ok(&stages));
        assert_eq!(
            last_stage(&stages).error.as_deref(),
            Some(
                "00_BOOT: missing current ARM inventory; 01_PSP: current Thumb inventory failed; 04_VSS: missing current recovered globals; 05_DBGCORE: current globals failed"
            )
        );
        assert_eq!(
            last_stage(&stages).output.as_deref(),
            Some(
                "images/*/decompiled/global_shapes.json (completed=1/5, inferred=0, no_evidence=0, conflicting=0, observations=0, ghidra_quarantined=0, thumb_quarantined=0, quarantine_errors=0, decode_failures=0, state_barriers=0)"
            )
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn global_shapes_stage_one_analyzer_failure_does_not_prevent_later_images() {
        let root = std::env::temp_dir().join(format!(
            "pme_global_shapes_stage_continue_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let images_dir = root.join("images");
        let manifest = root.join("manifest.json");
        let mut first = eligible_shape_image("02_MAIN", 1, 1, 0, None, None, None, 1);
        first.global_shapes_inferred = Some(8);
        let mut stages = vec![StageReport::decompile(
            vec![
                first,
                eligible_shape_image("03_APM", 1, 1, 0, None, None, None, 0),
            ],
            6,
        )];
        let current = [
            eligible_shape_result("02_MAIN", 1, 1, 0, None, None, None, 1),
            eligible_shape_result("03_APM", 1, 1, 0, None, None, None, 0),
        ];
        run_global_shapes_stage_with(&mut stages, &images_dir, &manifest, &current, |request| {
            if request.image_label == "02_MAIN" {
                return Err(Error::Serialize("é".repeat(3_000)));
            }
            Ok(zero_shapes_report())
        });

        let reason = stages[0].images[0]
            .global_shapes_error
            .as_ref()
            .expect("bounded reason");
        assert_eq!(reason.chars().count(), 2_048);
        assert!(reason.starts_with("serialize: "));
        assert_nine_shape_counts(&stages[0].images[0], None);
        assert_eq!(stages[0].images[0].status, "analyzed");
        assert_nine_shape_counts(&stages[0].images[1], Some(0));
        assert_eq!(last_stage(&stages).status, "failed");
        assert!(
            last_stage(&stages)
                .error
                .as_deref()
                .unwrap()
                .starts_with("02_MAIN: serialize: ")
        );
        assert!(
            !last_stage(&stages)
                .error
                .as_deref()
                .unwrap()
                .contains("03_APM")
        );
        assert_eq!(
            last_stage(&stages).output.as_deref(),
            Some(
                "images/*/decompiled/global_shapes.json (completed=1/2, inferred=0, no_evidence=0, conflicting=0, observations=0, ghidra_quarantined=0, thumb_quarantined=0, quarantine_errors=0, decode_failures=0, state_barriers=0)"
            )
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn global_shapes_stage_skips_when_no_decompile_images() {
        let root = std::env::temp_dir().join(format!(
            "pme_global_shapes_stage_skip_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let mut empty = vec![StageReport::decompile(Vec::new(), 2)];
        let mut called = false;
        run_global_shapes_stage_with(&mut empty, &root, &root.join("manifest.json"), &[], |_| {
            called = true;
            Ok(zero_shapes_report())
        });
        assert!(!called);
        assert_eq!(empty.len(), 2);
        assert_eq!(empty[1].stage, "global_shapes");
        assert_eq!(empty[1].status, "skipped");
        assert_eq!(empty[1].reason.as_deref(), Some("no code image"));
        assert_eq!(empty[1].duration_ms, 0);
        assert!(empty[1].images.is_empty());

        let mut missing = vec![StageReport::ok("extract", "manifest.json", 1)];
        run_global_shapes_stage_with(
            &mut missing,
            &root,
            &root.join("manifest.json"),
            &[],
            |_| {
                called = true;
                Ok(zero_shapes_report())
            },
        );
        assert!(!called);
        assert_eq!(missing[1].status, "skipped");
        assert_eq!(missing[1].reason.as_deref(), Some("no code image"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn global_shapes_stage_rejects_ghidra_count_mismatch_without_calling_analyzer() {
        let mut stages = vec![StageReport::decompile(
            vec![eligible_shape_image(
                "02_MAIN", 2, 1, 0, None, None, None, 0,
            )],
            1,
        )];
        let mut called = false;
        let current = [eligible_shape_result(
            "02_MAIN", 2, 1, 0, None, None, None, 0,
        )];
        run_global_shapes_stage_with(
            &mut stages,
            Path::new("/tmp"),
            Path::new("/tmp/manifest.json"),
            &current,
            |_| {
                called = true;
                Ok(zero_shapes_report())
            },
        );
        assert!(!called);
        assert_eq!(
            stages[0].images[0].global_shapes_error.as_deref(),
            Some("ghidra execution counts do not equal functions")
        );
        assert_nine_shape_counts(&stages[0].images[0], None);
        assert_eq!(last_stage(&stages).status, "failed");
    }

    #[test]
    fn global_shapes_stage_rejects_mixed_thumb_fields_without_calling_analyzer() {
        let mut mixed = eligible_shape_image("02_MAIN", 1, 1, 0, Some(1), None, None, 0);
        mixed.ghidra_execution_accepted = Some(1);
        let mut stages = vec![StageReport::decompile(vec![mixed], 1)];
        let mut called = false;
        let current = [eligible_shape_result(
            "02_MAIN",
            1,
            1,
            0,
            Some(1),
            None,
            None,
            0,
        )];
        run_global_shapes_stage_with(
            &mut stages,
            Path::new("/tmp"),
            Path::new("/tmp/manifest.json"),
            &current,
            |_| {
                called = true;
                Ok(zero_shapes_report())
            },
        );
        assert!(!called);
        assert_eq!(
            stages[0].images[0].global_shapes_error.as_deref(),
            Some("thumb inventory fields must be all present or all absent")
        );
        assert_eq!(last_stage(&stages).status, "failed");
    }

    #[test]
    fn global_shapes_stage_analyzes_pass2_fallback_snapshot() {
        let root = std::env::temp_dir().join(format!(
            "pme_global_shapes_stage_fallback_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let images_dir = root.join("images");
        let manifest = root.join("manifest.json");
        write_empty_shape_image(&images_dir, "02_MAIN");
        write_empty_shape_image(&images_dir, "03_APM");
        write_shape_manifest(&manifest, &["02_MAIN", "03_APM"]);

        let mut raw = tagged_image("02_MAIN", false);
        raw.globals_recovered = Some(0);
        let mut later = tagged_image("03_APM", false);
        later.globals_recovered = Some(0);
        let fallback = vec![
            ImageReport::from_result(&raw),
            ImageReport::from_result(&later),
        ];
        let mut stages = vec![
            StageReport::decompile(
                vec![
                    ImageReport::from_result(&analyzed_image("02_MAIN")),
                    ImageReport::from_result(&analyzed_image("03_APM")),
                ],
                10,
            ),
            StageReport::failed("decompile_pass2", "process failed".into(), 5),
        ];
        install_decompile_stage_image_snapshot(&mut stages, fallback);
        run_global_shapes_stage(&mut stages, &images_dir, &manifest, &[raw, later]);

        assert_eq!(stages[0].images[0].globals_recovered, Some(0));
        assert_nine_shape_counts(&stages[0].images[0], Some(0));
        assert_nine_shape_counts(&stages[0].images[1], Some(0));
        assert!(stages[0].images[0].global_shapes_error.is_none());
        assert_eq!(last_stage(&stages).stage, "global_shapes");
        assert_eq!(last_stage(&stages).status, "ok");
        assert!(
            images_dir
                .join("02_MAIN/decompiled/global_shapes.json")
                .is_file()
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn global_shapes_stage_malformed_terminal_functions_fail_and_continue() {
        let root = std::env::temp_dir().join(format!(
            "pme_global_shapes_stage_malformed_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let images_dir = root.join("images");
        let manifest = root.join("manifest.json");
        write_empty_shape_image(&images_dir, "02_MAIN");
        write_empty_shape_image(&images_dir, "03_APM");
        write_shape_manifest(&manifest, &["02_MAIN", "03_APM"]);
        std::fs::write(
            images_dir.join("02_MAIN/decompiled/functions.json"),
            b"not-json",
        )
        .unwrap();

        let mut stages = vec![StageReport::decompile(
            vec![
                eligible_shape_image("02_MAIN", 1, 1, 0, None, None, None, 0),
                eligible_shape_image("03_APM", 1, 1, 0, None, None, None, 0),
            ],
            8,
        )];
        let current = [
            eligible_shape_result("02_MAIN", 1, 1, 0, None, None, None, 0),
            eligible_shape_result("03_APM", 1, 1, 0, None, None, None, 0),
        ];
        run_global_shapes_stage(&mut stages, &images_dir, &manifest, &current);

        assert!(stages[0].images[0].global_shapes_error.is_some());
        assert_nine_shape_counts(&stages[0].images[0], None);
        assert_nine_shape_counts(&stages[0].images[1], Some(0));
        assert_eq!(last_stage(&stages).status, "failed");
        assert!(
            last_stage(&stages)
                .error
                .as_deref()
                .unwrap()
                .starts_with("02_MAIN: ")
        );
        assert!(
            !last_stage(&stages)
                .error
                .as_deref()
                .unwrap()
                .contains("03_APM")
        );
        assert_eq!(
            last_stage(&stages).output.as_deref(),
            Some(
                "images/*/decompiled/global_shapes.json (completed=1/2, inferred=0, no_evidence=0, conflicting=0, observations=0, ghidra_quarantined=0, thumb_quarantined=0, quarantine_errors=0, decode_failures=0, state_barriers=0)"
            )
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn global_shapes_stage_preserves_old_sidecars_when_current_globals_failed() {
        let root = std::env::temp_dir().join(format!(
            "pme_global_shapes_stage_stale_globals_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let images_dir = root.join("images");
        let manifest = root.join("manifest.json");
        write_empty_shape_image(&images_dir, "02_MAIN");
        write_empty_shape_image(&images_dir, "03_APM");
        write_shape_manifest(&manifest, &["02_MAIN", "03_APM"]);
        let old_globals = b"{\"old\":true}";
        let old_shapes = b"older global_shapes.json";
        std::fs::write(
            images_dir.join("02_MAIN/decompiled/globals.json"),
            old_globals,
        )
        .unwrap();
        std::fs::write(
            images_dir.join("02_MAIN/decompiled/global_shapes.json"),
            old_shapes,
        )
        .unwrap();

        let mut failed = eligible_shape_image("02_MAIN", 1, 1, 0, None, None, None, 4);
        failed.globals_error = Some("globals stage failed".into());
        let mut called = Vec::new();
        let mut stages = vec![StageReport::decompile(
            vec![
                failed,
                eligible_shape_image("03_APM", 1, 1, 0, None, None, None, 0),
            ],
            3,
        )];
        let mut failed_current = eligible_shape_result("02_MAIN", 1, 1, 0, None, None, None, 4);
        failed_current.globals_error = Some("globals stage failed".into());
        let current = [
            failed_current,
            eligible_shape_result("03_APM", 1, 1, 0, None, None, None, 0),
        ];
        run_global_shapes_stage_with(&mut stages, &images_dir, &manifest, &current, |request| {
            called.push(request.image_label.to_string());
            global_shapes::run_image(request)
        });

        assert_eq!(called, vec!["03_APM".to_string()]);
        assert_eq!(
            std::fs::read(images_dir.join("02_MAIN/decompiled/globals.json")).unwrap(),
            old_globals
        );
        assert_eq!(
            std::fs::read(images_dir.join("02_MAIN/decompiled/global_shapes.json")).unwrap(),
            old_shapes
        );
        assert_eq!(
            stages[0].images[0].global_shapes_error.as_deref(),
            Some("current globals failed")
        );
        assert_nine_shape_counts(&stages[0].images[1], Some(0));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn global_shapes_stage_stale_or_missing_thumb_fails_currentness_and_continues() {
        let root = std::env::temp_dir().join(format!(
            "pme_global_shapes_stage_thumb_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let images_dir = root.join("images");
        let manifest = root.join("manifest.json");
        write_empty_shape_image(&images_dir, "02_MAIN");
        write_empty_shape_image(&images_dir, "04_VSS");
        write_empty_shape_image(&images_dir, "03_APM");
        write_shape_manifest(&manifest, &["02_MAIN", "04_VSS", "03_APM"]);
        std::fs::write(
            images_dir.join("02_MAIN/decompiled/thumb_functions.json"),
            tagged_thumb_functions(),
        )
        .unwrap();
        let old_shapes = b"stale-shapes";
        std::fs::write(
            images_dir.join("02_MAIN/decompiled/global_shapes.json"),
            old_shapes,
        )
        .unwrap();

        let mut stages = vec![StageReport::decompile(
            vec![
                eligible_shape_image("02_MAIN", 1, 1, 0, None, None, None, 0),
                eligible_shape_image("04_VSS", 1, 1, 0, Some(0), Some(0), Some(0), 0),
                eligible_shape_image("03_APM", 1, 1, 0, None, None, None, 0),
            ],
            9,
        )];
        let current = [
            eligible_shape_result("02_MAIN", 1, 1, 0, None, None, None, 0),
            eligible_shape_result("04_VSS", 1, 1, 0, Some(0), Some(0), Some(0), 0),
            eligible_shape_result("03_APM", 1, 1, 0, None, None, None, 0),
        ];
        run_global_shapes_stage(&mut stages, &images_dir, &manifest, &current);

        assert!(
            stages[0].images[0]
                .global_shapes_error
                .as_deref()
                .unwrap()
                .contains("unexpected thumb_functions.json")
        );
        assert_eq!(
            std::fs::read(images_dir.join("02_MAIN/decompiled/global_shapes.json")).unwrap(),
            old_shapes
        );
        assert!(stages[0].images[1].global_shapes_error.is_some());
        assert_nine_shape_counts(&stages[0].images[1], None);
        assert_nine_shape_counts(&stages[0].images[2], Some(0));
        assert_eq!(last_stage(&stages).status, "failed");
        assert!(
            last_stage(&stages)
                .error
                .as_deref()
                .unwrap()
                .starts_with("02_MAIN: ")
        );
        assert!(
            last_stage(&stages)
                .error
                .as_deref()
                .unwrap()
                .contains("04_VSS: ")
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn global_shapes_stage_empty_recovered_writes_current_empty_sidecar() {
        let root = std::env::temp_dir().join(format!(
            "pme_global_shapes_stage_empty_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let images_dir = root.join("images");
        let manifest = root.join("manifest.json");
        write_empty_shape_image(&images_dir, "02_MAIN");
        write_shape_manifest(&manifest, &["02_MAIN"]);
        let globals_before =
            std::fs::read(images_dir.join("02_MAIN/decompiled/globals.json")).unwrap();

        let mut stages = vec![StageReport::decompile(
            vec![eligible_shape_image(
                "02_MAIN", 1, 1, 0, None, None, None, 0,
            )],
            2,
        )];
        let current = [eligible_shape_result(
            "02_MAIN", 1, 1, 0, None, None, None, 0,
        )];
        run_global_shapes_stage(&mut stages, &images_dir, &manifest, &current);

        assert_eq!(last_stage(&stages).status, "ok");
        assert_nine_shape_counts(&stages[0].images[0], Some(0));
        let sidecar =
            std::fs::read_to_string(images_dir.join("02_MAIN/decompiled/global_shapes.json"))
                .unwrap();
        let value: serde_json::Value = serde_json::from_str(&sidecar).unwrap();
        assert_eq!(value["format"], "pixel-modem-extractor-global-shapes-v4");
        assert_eq!(value["globals"], serde_json::json!([]));
        assert_eq!(
            std::fs::read(images_dir.join("02_MAIN/decompiled/globals.json")).unwrap(),
            globals_before
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn global_shapes_stage_both_routes_enter_wrapper_exactly_once() {
        // Both symbol routes must reach `run_global_shapes_stage_with` from
        // the `RunGlobalShapes` step, but at different points: the normal
        // route runs the first sweep *before* DispatchPass2 (the input-safe
        // reorder — shapes must be ready for a later pass-2 apply step; the
        // route's second, re-committing entry after Finalize is pinned by
        // `direct_symbol_routes_preserve_exact_once_order` and exercised by
        // `global_shapes_final_rerun_recommits_sidecar_over_rewritten_inputs`);
        // `--no-symbol-pass` has no pass 2 to feed, so it runs shapes once,
        // last, after globals.json exists (RunGlobals(RecordOnly), the "skip"
        // event below).
        let root = std::env::temp_dir().join(format!(
            "pme_global_shapes_stage_routes_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let images_dir = root.join("images");
        let manifest = root.join("manifest.json");
        write_empty_shape_image(&images_dir, "02_MAIN");
        write_shape_manifest(&manifest, &["02_MAIN"]);

        for no_symbol_pass in [false, true] {
            let mut events = Vec::new();
            let mut wrapper_calls = 0usize;
            let current = [eligible_shape_result(
                "02_MAIN", 1, 1, 0, None, None, None, 0,
            )];
            orchestrate_symbol_route(no_symbol_pass, |step| match step {
                SymbolRouteStep::DispatchPass2 => events.push("refresh".into()),
                SymbolRouteStep::RunGlobals(GlobalsRouteMode::RecordOnly) => {
                    events.push("skip".into())
                }
                SymbolRouteStep::RunGlobalShapes => {
                    events.push("global_shapes".into());
                    let mut stages = vec![StageReport::decompile(
                        vec![eligible_shape_image(
                            "02_MAIN", 1, 1, 0, None, None, None, 0,
                        )],
                        1,
                    )];
                    run_global_shapes_stage_with(
                        &mut stages,
                        &images_dir,
                        &manifest,
                        &current,
                        |request| {
                            wrapper_calls += 1;
                            assert_eq!(request.image_label, "02_MAIN");
                            global_shapes::run_image(request)
                        },
                    );
                    assert_eq!(last_stage(&stages).stage, "global_shapes");
                    assert_eq!(last_stage(&stages).status, "ok");
                    assert_nine_shape_counts(&stages[0].images[0], Some(0));
                }
                other => events.push(format!("{other:?}")),
            });
            orchestrate_post_symbol_route(|step| match step {
                PostSymbolStep::DecodeRf => events.push("decode_rf".into()),
                PostSymbolStep::HardwareConfig => events.push("hardware_config".into()),
            });

            assert_eq!(
                wrapper_calls, 1,
                "both routes must enter the same wrapper once (no_symbol_pass={no_symbol_pass})"
            );
            let shapes = events
                .iter()
                .position(|event| event == "global_shapes")
                .expect("global_shapes event");
            assert_eq!(
                events
                    .iter()
                    .filter(|event| *event == "global_shapes")
                    .count(),
                1
            );
            let terminal = if no_symbol_pass { "skip" } else { "refresh" };
            let terminal_pos = events
                .iter()
                .position(|event| event == terminal)
                .unwrap_or_else(|| panic!("{terminal} event missing: {events:?}"));
            if no_symbol_pass {
                assert!(
                    terminal_pos < shapes,
                    "on --no-symbol-pass, global_shapes must follow {terminal}: {events:?}"
                );
            } else {
                assert!(
                    shapes < terminal_pos,
                    "on the normal route, global_shapes must precede {terminal} \
                     (input-safe reorder before pass 2): {events:?}"
                );
            }
            let decode_rf = events
                .iter()
                .position(|event| event == "decode_rf")
                .unwrap();
            let hardware = events
                .iter()
                .position(|event| event == "hardware_config")
                .unwrap();
            assert!(shapes < decode_rf && decode_rf < hardware, "{events:?}");
        }

        let sidecar =
            std::fs::read(images_dir.join("02_MAIN/decompiled/global_shapes.json")).unwrap();
        assert!(images_dir.join("02_MAIN/decompiled/globals.json").is_file());
        assert!(!sidecar.is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn global_shapes_outcomes_survive_refresh_decompile_stage_images() {
        // Regression test (plain unit test — no PME_GOLDEN_DIR — so a
        // re-regression fails normal CI, not only the gated golden) for the
        // shape-recovery clobber a code review found: on the normal route,
        // `RunGlobalShapes` patches `global_shapes_*` onto
        // `stages[decompile_pos].images` *before* `DispatchPass2` runs.
        // `DispatchPass2`'s own `refresh_decompile_stage_images` later
        // rebuilds those same `ImageReport`s from `decompile::ImageResult`
        // via `ImageReport::from_result`, which always nulls
        // `global_shapes_*` (`ImageResult` has no such fields to preserve
        // them from) — silently discarding the patch unless
        // `reapply_global_shapes_outcomes` runs afterward.
        let mut stages = vec![StageReport::decompile(
            vec![
                eligible_shape_image("02_MAIN", 1, 1, 0, None, None, None, 0),
                eligible_shape_image("03_APM", 1, 1, 0, None, None, None, 0),
            ],
            1,
        )];
        let current = [
            eligible_shape_result("02_MAIN", 1, 1, 0, None, None, None, 0),
            eligible_shape_result("03_APM", 1, 1, 0, None, None, None, 0),
        ];
        let outcomes = run_global_shapes_stage_with(
            &mut stages,
            Path::new("unused-images-dir"),
            Path::new("unused-manifest"),
            &current,
            |request| {
                if request.image_label == "02_MAIN" {
                    Ok(global_shapes::GlobalShapesReport {
                        inferred: 2,
                        no_evidence: 1,
                        conflicting: 0,
                        observations: 4,
                        ghidra_quarantined: 0,
                        thumb_quarantined: 0,
                        quarantine_errors: 0,
                        decode_failures: 0,
                        state_barriers: 0,
                        interprocedural_dropped: 0,
                    })
                } else {
                    Err(Error::DecomposeIncomplete("boom".into()))
                }
            },
        );

        // Sanity: the initial in-place patch (success + failure) landed.
        assert_eq!(stages[0].images[0].global_shapes_inferred, Some(2));
        assert_eq!(stages[0].images[0].global_shape_observations, Some(4));
        assert_eq!(
            stages[0].images[1].global_shapes_error.as_deref(),
            Some("decompose incomplete: boom")
        );

        // Simulate DispatchPass2's final refresh: rebuild from a fresh
        // ImageResult slice, exactly like the real pass-2 dispatch does.
        let post_pass2_images = vec![analyzed_image("02_MAIN"), analyzed_image("03_APM")];
        refresh_decompile_stage_images(&mut stages, &post_pass2_images);

        // Prove the regression is real: the refresh alone nulls everything,
        // both the success counts and the failure reason.
        assert_nine_shape_counts(&stages[0].images[0], None);
        assert!(stages[0].images[1].global_shapes_error.is_none());

        // The fix: re-applying the retained outcomes restores both.
        reapply_global_shapes_outcomes(decompile_stage_images_mut(&mut stages), &outcomes);
        assert_eq!(stages[0].images[0].global_shapes_inferred, Some(2));
        assert_eq!(stages[0].images[0].global_shapes_no_evidence, Some(1));
        assert_eq!(stages[0].images[0].global_shape_observations, Some(4));
        assert!(stages[0].images[0].global_shapes_error.is_none());
        assert_eq!(
            stages[0].images[1].global_shapes_error.as_deref(),
            Some("decompose incomplete: boom")
        );
        assert_nine_shape_counts(&stages[0].images[1], None);
    }

    #[test]
    fn reapply_global_shapes_outcomes_leaves_unlisted_images_untouched() {
        let mut images = vec![ImageReport::from_result(&analyzed_image("02_MAIN"))];
        let outcomes = HashMap::new(); // no retained outcome for 02_MAIN
        reapply_global_shapes_outcomes(&mut images, &outcomes);
        assert_nine_shape_counts(&images[0], None);
        assert!(images[0].global_shapes_error.is_none());
    }

    #[test]
    fn dbt_counters_survive_refresh_decompile_stage_images() {
        // The dbt twin of `global_shapes_outcomes_survive_refresh_...`:
        // the `dbt_*` counters are patched between `thumb_enrich` and the
        // source tree, before both the `RunGlobals(RecordOnly)` refresh and
        // `DispatchPass2`'s rebuilds, which null them via
        // `ImageReport::from_result` — unless `reapply_dbt_outcomes` runs
        // afterward.
        let counters = DbtCounters {
            label: "02_MAIN".to_string(),
            records: 7,
            files: 2,
            messages: 5,
            quarantined: 1,
            unresolved_messages: 3,
            references: 4,
            refs_producers: vec!["ghidra".to_string()],
        };
        let mut stages = vec![StageReport::decompile(
            vec![
                ImageReport::from_result(&analyzed_image("02_MAIN")),
                ImageReport::from_result(&analyzed_image("03_APM")),
            ],
            1,
        )];
        reapply_dbt_outcomes(
            decompile_stage_images_mut(&mut stages),
            &Some(counters.clone()),
        );

        // The initial patch landed on the MAIN row only.
        assert_eq!(stages[0].images[0].dbt_records, Some(7));
        assert_eq!(stages[0].images[0].dbt_references, Some(4));
        assert_eq!(
            stages[0].images[0].dbt_refs_producers,
            Some(vec!["ghidra".to_string()])
        );
        assert!(stages[0].images[1].dbt_records.is_none());

        // Simulate the later rebuild: the refresh alone nulls everything.
        let rebuilt = vec![analyzed_image("02_MAIN"), analyzed_image("03_APM")];
        refresh_decompile_stage_images(&mut stages, &rebuilt);
        assert!(stages[0].images[0].dbt_records.is_none());
        assert!(stages[0].images[0].dbt_refs_producers.is_none());

        // The fix: re-applying the retained outcome restores it, still
        // only on the MAIN row.
        reapply_dbt_outcomes(decompile_stage_images_mut(&mut stages), &Some(counters));
        assert_eq!(stages[0].images[0].dbt_records, Some(7));
        assert_eq!(stages[0].images[0].dbt_files, Some(2));
        assert_eq!(stages[0].images[0].dbt_messages, Some(5));
        assert_eq!(stages[0].images[0].dbt_quarantined, Some(1));
        assert_eq!(stages[0].images[0].dbt_unresolved_messages, Some(3));
        assert_eq!(stages[0].images[0].dbt_references, Some(4));
        assert_eq!(
            stages[0].images[0].dbt_refs_producers,
            Some(vec!["ghidra".to_string()])
        );
        assert!(stages[0].images[1].dbt_records.is_none());
    }

    #[test]
    fn reapply_dbt_outcomes_none_leaves_rows_untouched() {
        let mut images = vec![ImageReport::from_result(&analyzed_image("02_MAIN"))];
        reapply_dbt_outcomes(&mut images, &None);
        assert!(images[0].dbt_records.is_none());
        assert!(images[0].dbt_refs_producers.is_none());
    }

    #[test]
    fn debug_traces_stages_skip_with_reasons_when_main_inputs_are_absent() {
        let root = std::env::temp_dir().join(format!("pme_dbt_stage_skips_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let images_dir = root.join("images");
        std::fs::create_dir_all(&images_dir).unwrap();

        // No MAIN split dir at all.
        let mut stages = Vec::new();
        let outcomes = run_debug_traces_stages(&mut stages, &root, &images_dir);
        assert!(outcomes.is_none());
        let names: Vec<&'static str> = stages.iter().map(|stage| stage.stage).collect();
        assert_eq!(names, ["debug_traces", "debug_traces_refs"]);
        for stage in &stages {
            assert_eq!(stage.status, "skipped");
            assert_eq!(stage.reason.as_deref(), Some("no MAIN image"));
        }

        // A MAIN split dir without its binary.
        std::fs::create_dir_all(images_dir.join("02_MAIN")).unwrap();
        let mut stages = Vec::new();
        let outcomes = run_debug_traces_stages(&mut stages, &root, &images_dir);
        assert!(outcomes.is_none());
        let names: Vec<&'static str> = stages.iter().map(|stage| stage.stage).collect();
        assert_eq!(names, ["debug_traces", "debug_traces_refs"]);
        for stage in &stages {
            assert_eq!(stage.status, "skipped");
            assert_eq!(stage.reason.as_deref(), Some("no MAIN image binary"));
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn global_shapes_stage_binds_currentness_from_image_results_before_pass2() {
        // The exact e2e shape that failed live: on the normal route,
        // RunGlobalShapes runs right after the globals stage and before
        // DispatchPass2, and the decompile stage report deliberately withholds
        // globals fields until pass 2's outcome ("no pre-application snapshot"
        // — see globals_stage_refreshes_only_when_application_is_known_uninvoked).
        // Currentness must therefore bind from the post-globals
        // decompile::ImageResults (mutated in place by the globals stage), not
        // from the stage-report ImageReports.
        let root = std::env::temp_dir().join(format!(
            "pme_global_shapes_currentness_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let images_dir = root.join("images");
        let manifest = root.join("manifest.json");
        write_empty_shape_image(&images_dir, "02_MAIN");
        write_shape_manifest(&manifest, &["02_MAIN"]);

        // Stage-report image: the normal-route shape — inventory counts
        // present, globals fields withheld (None).
        let mut withheld = eligible_shape_image("02_MAIN", 1, 1, 0, None, None, None, 0);
        withheld.globals_recovered = None;
        assert!(
            withheld.globals_recovered.is_none(),
            "fixture must reproduce the withheld normal-route snapshot"
        );
        let mut stages = vec![StageReport::decompile(vec![withheld], 2)];

        // Post-globals ImageResult: globals_recovered set, as the globals
        // stage does in place (image.globals_recovered = Some(...)).
        let mut raw = analyzed_image("02_MAIN");
        raw.ghidra_execution_accepted = Some(1);
        raw.ghidra_execution_quarantined = Some(0);
        raw.globals_recovered = Some(0);
        assert_eq!(raw.globals_recovered, Some(0));

        run_global_shapes_stage(
            &mut stages,
            &images_dir,
            &manifest,
            std::slice::from_ref(&raw),
        );

        assert_eq!(
            last_stage(&stages).status,
            "ok",
            "stage must not fail: {stages:?}"
        );
        assert!(stages[0].images[0].global_shapes_error.is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn global_shapes_stage_fails_closed_when_image_result_is_missing() {
        // A stage-report image with no matching current ImageResult must fail
        // closed per-image — this also pins the handler wiring's
        // `unwrap_or(&[])` fallback: whenever pass-1 results are absent, the
        // decompile stage has no images and the stage skips ("no code image"),
        // so this per-image miss is the only way the empty slice can be
        // observed, and it must be an explicit failure, never a silent skip.
        let mut stages = vec![StageReport::decompile(
            vec![eligible_shape_image(
                "02_MAIN", 1, 1, 0, None, None, None, 0,
            )],
            1,
        )];
        let mut called = false;
        run_global_shapes_stage_with(
            &mut stages,
            Path::new("/tmp"),
            Path::new("/tmp/manifest.json"),
            &[],
            |_| {
                called = true;
                Ok(zero_shapes_report())
            },
        );
        assert!(!called);
        assert_eq!(
            stages[0].images[0].global_shapes_error.as_deref(),
            Some("missing current image result")
        );
        assert_nine_shape_counts(&stages[0].images[0], None);
        assert_eq!(last_stage(&stages).status, "failed");
        assert_eq!(
            last_stage(&stages).error.as_deref(),
            Some("02_MAIN: missing current image result")
        );
    }

    #[test]
    fn symbolicate_stage_runs_over_a_crafted_tree() {
        let root = std::env::temp_dir().join(format!("pme_decompose_sym_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dec = root.join("images/02_MAIN/decompiled");
        std::fs::create_dir_all(&dec).unwrap();
        let image = vec![0u8; 0x20];
        std::fs::write(
            dec.join("functions.json"),
            serde_json::to_vec(&serde_json::json!([{
                "name": "FUN_10",
                "primary_source": "default",
                "entry": "0x10",
                "end": "0x18",
                "size": 8,
                "decode_ranges": [{
                    "isa": "arm",
                    "start": "0x10",
                    "end": "0x18",
                    "blake3": blake3::hash(&image[0x10..0x18]).to_hex().to_string(),
                }],
                "decode_range_errors": [],
                "data_refs": [],
            }]))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(dec.join("disasm.lst"), "0x10: movw r0, 0xcc9\n").unwrap();
        std::fs::write(root.join("images/02_MAIN/02_MAIN.bin"), image).unwrap();
        std::fs::write(
            root.join("manifest.json"),
            r#"{"toc":[{"name":"MAIN","load_addr":0}]}"#,
        )
        .unwrap();

        // no token DB -> token evidence skipped, but the pass still writes symbols.json
        let out = crate::symbolicate::run(
            &root,
            &crate::symbolicate::Opts {
                token_db: None,
                rewrite_decompiled_c: true,
            },
        )
        .unwrap();
        assert_eq!(out, root);
        assert!(dec.join("symbols.json").exists());
        let _ = std::fs::remove_dir_all(&root);
    }
}
