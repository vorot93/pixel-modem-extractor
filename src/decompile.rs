//! Decompile the modem TOC code images with Ghidra. Pure-Rust generation always
//! emits a self-contained Ghidra import kit (per-image slices, a machine-readable
//! `ghidra_load.json` load spec, a turnkey `run_ghidra.sh`, and an embedded Java
//! exporter); the opt-in `--run` drives `analyzeHeadless` headless to export
//! decompiled C, a disassembly listing, a function inventory, and a saved project,
//! with radare2 primary and optional failure-only Rizin covering dense Thumb regions.
//! Generation discovers MAIN scatter once, builds one runtime view per embedded
//! image, discovers exception roots for every image, then discovers MAIN PAL
//! tasks from the shared view. Every kit and run therefore carries explicit
//! current state rather than inferring it from artifact existence.

use crate::{
    error::{Error, Result},
    exception_roots::{self, ExceptionArtifactContext, MaterializedExceptionRoots},
    execution_ranges::{OwnedExecutionIdentity, TaggedExecutionRecord, parse_blake3},
    pal_tasks::{self, TaskArtifactContext},
    runtime_image::RuntimeImage,
    scatter,
    toc::Toc,
};
use serde::Serialize;
use std::{
    collections::{BTreeSet, HashMap, VecDeque},
    ffi::{OsStr, OsString},
    io::BufRead,
    num::NonZeroUsize,
    path::{Path, PathBuf},
};

#[path = "exception_pass2.rs"]
mod exception_pass2;

const EXPORT_DECOMP_JAVA: &str = include_str!("ghidra/ExportDecomp.java");
const TAME_ANALYSIS_JAVA: &str = include_str!("ghidra/TameAnalysis.java");
const APPLY_SYMBOLS_JAVA: &str = include_str!("ghidra/ApplySymbols.java");
const APPLY_GLOBALS_JAVA: &str = include_str!("ghidra/ApplyGlobals.java");
const APPLY_GLOBAL_TYPES_JAVA: &str = include_str!("ghidra/ApplyGlobalTypes.java");
const APPLY_SCATTER_LOAD_JAVA: &str = include_str!("ghidra/ApplyScatterLoad.java");
const APPLY_THUMB_NAMES_JAVA: &str = include_str!("ghidra/ApplyThumbNames.java");
const APPLY_PAL_TASKS_JAVA: &str = include_str!("ghidra/ApplyPalTasks.java");
const APPLY_EXCEPTION_ROOTS_JAVA: &str = include_str!("ghidra/ApplyExceptionRoots.java");
const PME_SCRIPT_SUPPORT_JAVA: &str = include_str!("ghidra/PmeScriptSupport.java");
const PAL_TASKS_SUPPORT_JAVA: &str = include_str!("ghidra/PalTasksSupport.java");
const EXCEPTION_ROOTS_SUPPORT_JAVA: &str = include_str!("ghidra/ExceptionRootsSupport.java");
const GLOBALS_APPLY_ERROR_MAX_CHARS: usize = 2_048;

#[cfg(test)]
static TEST_IMAGE: [u8; 0x10_000] = [0; 0x10_000];

#[cfg(test)]
fn test_runtime() -> RuntimeImage<'static> {
    RuntimeImage::from_plan(&TEST_IMAGE, 0, None).unwrap()
}

/// Ghidra project name passed to `analyzeHeadless` (the directory is
/// `<root>/ghidra_project`). Shared by pass 1 (`-import`) and pass 2
/// (`-process`) so the two argument vectors never drift on a rename.
const GHIDRA_PROJECT_NAME: &str = "pixel-modem";
const GHIDRA_EXPORT_FILES: [&str; 3] = ["functions.json", "disasm.lst", "decompiled.c"];
const GHIDRA_EXPORT_COMPLETION: &str = "pixel-modem-extractor-ghidra-export-v4";

/// Exact v4 completion-marker bytes. Each identity is this run's explicit
/// present identity or `none`; `symbol_map` is the lowercase pass-2 map BLAKE3
/// or `none`. Rust-driven and generated runs compare these bytes verbatim.
pub fn export_completion_marker(
    exception_identity: &str,
    pal_identity: &str,
    symbol_map: &str,
) -> Vec<u8> {
    format!(
        "{GHIDRA_EXPORT_COMPLETION}\nexception_roots={exception_identity}\npal_tasks={pal_identity}\nsymbol_map={symbol_map}\n"
    )
    .into_bytes()
}

#[derive(Debug, Clone)]
pub struct Opts {
    pub run: bool,
    pub image: Option<String>,
    pub ghidra_home: Option<PathBuf>,
    pub processor: String,
    /// Phase 2 escape hatch: when true, `TameAnalysis` runs in `datamark` mode.
    /// Dense Thumb regions are marked as data for Ghidra, the configured host
    /// analyzers still emit strict v3, and `thumb_enrich` does not add `body_c`.
    pub no_thumb_decompile: bool,
    /// Enable Rizin as a failure-only fallback for dense Thumb regions.
    /// radare2 remains required and is always attempted first. Default false.
    pub rizin_fallback: bool,
    /// Phase 2 / Surface B: test-only override that bypasses
    /// `baseline * wall_clock_multiplier` and supplies an absolute wall-clock
    /// budget for the tighten-watch kill decision. Wired to the hidden
    /// `--tighten-wall-clock-budget-sec` flag (Section 7 verification).
    /// Production callers leave this `None`.
    pub tighten_wall_clock_budget_override: Option<std::time::Duration>,
    /// Opaque-image escape hatch: when true, images whose battery is
    /// unanimously opaque still run Ghidra + configured Thumb analyzers
    /// (run-everything behavior, for research). Default false (skip —
    /// nothing is recoverable from those bytes under the standard import).
    pub no_skip_opaque: bool,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SourceRef {
    pub path: String,
    pub blake3: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct ImageSpec {
    pub name: String,
    pub file: String,
    pub size: u32,
    pub base_addr: String,
    pub entry_point: String,
    pub blake3: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_load_map: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exception_root_map: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pal_task_map: Option<String>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct LoadSpec {
    pub tool_version: String,
    pub source: SourceRef,
    pub processor: String,
    pub images: Vec<ImageSpec>,
}

pub fn build_load_spec(
    toc: &Toc,
    data: &[u8],
    source_name: &str,
    processor: &str,
) -> Result<LoadSpec> {
    let images = toc
        .embedded()
        .into_iter()
        .map(|e| {
            let label = e.label();
            let start = e.offset as usize;
            let end = start + e.size as usize;
            // Defensive: a directly-constructed / malformed TOC could point past the
            // buffer. (The wired path validates ranges via `split_to_dir` first, so
            // this never trips there — it only protects a direct caller.)
            if end > data.len() {
                return Err(Error::SizeMismatch {
                    name: label,
                    expected: e.size as u64,
                    actual: data.len().saturating_sub(start) as u64,
                });
            }
            let file = format!("images/{label}");
            Ok(ImageSpec {
                name: label,
                file,
                size: e.size,
                base_addr: format!("0x{:08x}", e.load_addr),
                entry_point: format!("0x{:08x}", e.load_addr),
                blake3: crate::manifest::blake3_bytes(&data[start..end]),
                runtime_load_map: None,
                exception_root_map: None,
                pal_task_map: None,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(LoadSpec {
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        source: SourceRef {
            path: source_name.to_string(),
            blake3: crate::manifest::blake3_bytes(data),
        },
        processor: processor.to_string(),
        images,
    })
}

/// A scheduled PAL invocation for one image: the task-manifest path relative
/// to `root` plus the exact expected PAL identity the scripts must agree on.
#[derive(Debug, Clone, Copy)]
pub struct PalScriptPlan<'a> {
    pub manifest: &'a str,
    pub identity: &'a str,
}

/// A scheduled exception-root invocation for one image: the manifest path
/// relative to `root` plus the exact expected identity shared by every
/// pass-1 script and terminal marker.
#[derive(Debug, Clone, Copy)]
pub struct ExceptionRootScriptPlan<'a> {
    pub manifest: &'a str,
    pub identity: &'a str,
}

/// The `analyzeHeadless` argument vector for one image — the single source of
/// truth used both to serialize `run_ghidra.sh` and to spawn under `--run`.
/// `root` is the path prefix (an absolute out dir for `--run`, or `$HERE` in the
/// shell script). NOTE: `-loader-baseAddr` is hex WITHOUT a `0x` prefix.
///
/// `mode` is "tighten" (Phase 2+ default — attempt Thumb) or "datamark" (Phase-1
/// fallback — mark regions as data). When "tighten", the `thumb_regions` arg is
/// ignored (no data-marks passed to the script). Immediately after the mode the
/// pre-script consumes exception-root then PAL identities, each `none` unless
/// this run's generation loop measured a present manifest.
///
/// `pal` schedules the PAL task-manifest application for this image, built
/// from this run's present generation state. When present the pre-script
/// order is `ApplyScatterLoad`, `ApplyExceptionRoots`, `ApplyPalTasks`,
/// `TameAnalysis`, and `TameAnalysis`/`ExportDecomp` receive both identities; a
/// PAL map without a scatter map passes `-` as `ApplyPalTasks`'s scatter argument.
#[allow(clippy::too_many_arguments)]
fn headless_args(
    root: &str,
    label: &str,
    processor: &str,
    base_addr: u32,
    runtime_load_map: Option<&str>,
    exception_roots: Option<ExceptionRootScriptPlan<'_>>,
    pal: Option<PalScriptPlan<'_>>,
    thumb_regions: &[(u32, u32)],
    mode: &str,
) -> Vec<String> {
    let mut args = vec![
        format!("{root}/ghidra_project"),
        GHIDRA_PROJECT_NAME.to_string(),
        "-import".to_string(),
        format!("{root}/images/{label}"),
        "-processor".to_string(),
        processor.to_string(),
        "-loader".to_string(),
        "BinaryLoader".to_string(),
        "-loader-baseAddr".to_string(),
        format!("{base_addr:08x}"),
        "-scriptPath".to_string(),
        format!("{root}/scripts"),
    ];
    if let Some(relative_path) = runtime_load_map {
        args.extend([
            "-preScript".to_string(),
            "ApplyScatterLoad.java".to_string(),
            root.to_string(),
            label.to_string(),
            format!("{root}/{relative_path}"),
        ]);
    }
    let scatter_argument = runtime_load_map
        .map(|scatter_relative| format!("{root}/{scatter_relative}"))
        .unwrap_or_else(|| "-".to_string());
    if let Some(plan) = exception_roots {
        args.extend([
            "-preScript".to_string(),
            "ApplyExceptionRoots.java".to_string(),
            root.to_string(),
            label.to_string(),
            format!("{root}/{}", plan.manifest),
            scatter_argument.clone(),
            plan.identity.to_string(),
        ]);
    }
    if let Some(plan) = pal {
        args.extend([
            "-preScript".to_string(),
            "ApplyPalTasks.java".to_string(),
            root.to_string(),
            label.to_string(),
            format!("{root}/{}", plan.manifest),
            scatter_argument.clone(),
        ]);
    }
    // Pre-script (runs before auto-analysis): TameAnalysis takes `mode`, the
    // expected exception identity, then the expected PAL identity. In
    // `datamark` mode it also disables the Aggressive Instruction
    // Finder and marks the dense high-entropy regions passed below (each as
    // "addrHex:lenHex") as data. In `tighten` mode no regions are passed.
    args.extend([
        "-preScript".to_string(),
        "TameAnalysis.java".to_string(),
        mode.to_string(),
        exception_roots
            .map(|plan| plan.identity.to_string())
            .unwrap_or_else(|| "none".to_string()),
        pal.map(|plan| plan.identity.to_string())
            .unwrap_or_else(|| "none".to_string()),
    ]);
    if mode == "datamark" {
        for (addr, len) in thumb_regions {
            args.push(format!("{addr:08x}:{len:x}"));
        }
    }
    // ExportDecomp receives explicit exception/PAL identity-manifest pairs,
    // the shared scatter dependency, and the pass-1 symbol-map pair. No
    // script infers currentness from path or project-state existence.
    let (exception_identity, exception_manifest) = match exception_roots {
        Some(plan) => (
            plan.identity.to_string(),
            format!("{root}/{}", plan.manifest),
        ),
        None => ("none".to_string(), "-".to_string()),
    };
    let (pal_identity, pal_manifest) = match pal {
        Some(plan) => (
            plan.identity.to_string(),
            format!("{root}/{}", plan.manifest),
        ),
        None => ("none".to_string(), "-".to_string()),
    };
    args.extend([
        "-postScript".to_string(),
        "ExportDecomp.java".to_string(),
        format!("{root}/export/{label}"),
        root.to_string(),
        label.to_string(),
        exception_identity,
        exception_manifest,
        pal_identity,
        pal_manifest,
        scatter_argument,
        "-".to_string(),
        "none".to_string(),
        "-overwrite".to_string(),
    ]);
    args
}

/// Resolve the mode from Opts: datamark when the escape hatch is set, else tighten.
fn mode_from_opts(opts: &Opts) -> &'static str {
    if opts.no_thumb_decompile {
        "datamark"
    } else {
        "tighten"
    }
}

/// One unique, space-free Java/XDG state directory for a headless run —
/// the in-process equivalent of the generated script's `mktemp -d` state
/// home and cleanup trap. Ghidra user settings, cache, and temp files
/// never leak between runs, and the `-D…` tokens (word-split unquoted by
/// `analyzeHeadless`) can never inherit a space from the kit root. The
/// directory is removed on drop.
#[derive(Debug)]
struct GhidraStateHome {
    path: PathBuf,
}

impl GhidraStateHome {
    fn new() -> Result<Self> {
        let base = std::env::temp_dir();
        let prefix = format!("pixel-modem-ghidra-{}", std::process::id());
        if base
            .to_string_lossy()
            .bytes()
            .any(|byte| byte == b' ' || byte == b'\t')
        {
            return Err(Error::GhidraStateHome(format!(
                "the system temp directory {} is not space-free; Ghidra's word-split Java options cannot address it",
                base.display()
            )));
        }
        for attempt in 0..u32::MAX {
            let candidate = base.join(format!("{prefix}-{attempt:08x}"));
            match std::fs::create_dir(&candidate) {
                Ok(()) => return Ok(Self { path: candidate }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(Error::GhidraStateHome(
            "no unique Ghidra state directory remains under the system temp directory".into(),
        ))
    }

    fn config_home(&self) -> PathBuf {
        self.path.join("ghidra_config")
    }

    fn cache_home(&self) -> PathBuf {
        self.path.join("ghidra_cache")
    }

    fn temp_home(&self) -> PathBuf {
        self.path.join("ghidra_tmp")
    }

    fn create_subdirs(&self) -> Result<()> {
        std::fs::create_dir_all(self.config_home())?;
        std::fs::create_dir_all(self.cache_home())?;
        std::fs::create_dir_all(self.temp_home())?;
        Ok(())
    }
}

impl Drop for GhidraStateHome {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.path) {
            tracing::warn!(
                "failed to clean up the Ghidra state directory {}: {error}",
                self.path.display()
            );
        }
    }
}

fn ghidra_java_options(state: &GhidraStateHome, existing: Option<&OsStr>) -> OsString {
    let local = format!(
        "-Dapplication.settingsdir={} -Dapplication.cachedir={} -Dapplication.tempdir={} -Djava.io.tmpdir={}",
        state.config_home().display(),
        state.cache_home().display(),
        state.temp_home().display(),
        state.temp_home().display()
    );
    let mut options = OsString::new();
    if let Some(existing) = existing.filter(|s| !s.is_empty()) {
        options.push(existing);
        options.push(" ");
    }
    options.push(local);
    options
}

fn headless_command(
    headless: &Path,
    args: &[String],
    state: &GhidraStateHome,
    java_home: Option<&Path>,
) -> std::process::Command {
    let mut command = std::process::Command::new(headless);
    command.args(args);
    command.env("XDG_CONFIG_HOME", state.config_home());
    command.env("XDG_CACHE_HOME", state.cache_home());
    command.env(
        "GHIDRA_HEADLESS_JAVA_OPTIONS",
        ghidra_java_options(
            state,
            std::env::var_os("GHIDRA_HEADLESS_JAVA_OPTIONS").as_deref(),
        ),
    );
    // Homebrew's analyzeHeadless (unlike its ghidraRun wrapper) doesn't pin a JDK; supply
    // one only when discovery found a wrapper that pins it and the caller left JAVA_HOME unset.
    if let Some(jh) = java_home {
        command.env("JAVA_HOME", jh);
    }
    command
}

/// Run one headless command to completion with stdout captured (stderr
/// still inherited, so Ghidra's diagnostics stay visible live). Returns
/// the exit status plus the captured stdout text. The child runs in its
/// own process group; if capture fails (read error or retention-ceiling
/// breach) the whole tree is killed and reaped before the error returns.
fn headless_stdout_status(
    mut command: std::process::Command,
) -> std::io::Result<(std::process::ExitStatus, String)> {
    use std::io::BufRead as _;

    command.stdout(std::process::Stdio::piped());
    spawn_in_own_process_group(&mut command);
    let mut child = command.spawn()?;
    let child_pid = child.id();
    let mut stdout = String::new();
    if let Some(piped) = child.stdout.take() {
        for line in std::io::BufReader::new(piped).lines() {
            match line {
                Ok(line) => {
                    if let Err(error) = push_captured_line(&mut stdout, &line) {
                        // Fail closed on runaway stdout: tear down the whole
                        // tree so no JVM survives holding the project lock.
                        let _ = child.kill();
                        kill_process_group(child_pid);
                        let _ = child.wait();
                        return Err(error);
                    }
                    println!("{line}");
                }
                Err(error) => {
                    let _ = child.kill();
                    kill_process_group(child_pid);
                    let _ = child.wait();
                    return Err(error);
                }
            }
        }
    }
    let status = child.wait()?;
    Ok((status, stdout))
}

/// Ceiling on one image's retained headless stdout. The strict summary
/// and marker parsing only needs the bounded `ApplyPalTasks`/export
/// lines; a run whose stdout grows past this is a runaway logger, and
/// retention fails closed with a clear error instead of growing without
/// bound or silently truncating.
const MAX_CAPTURED_STDOUT_BYTES: usize = 16 * 1024 * 1024;

/// Append one captured stdout line under checked arithmetic, failing
/// closed when the retained buffer would exceed the ceiling.
fn push_captured_line(buffer: &mut String, line: &str) -> std::io::Result<()> {
    let ceiling = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "captured headless stdout exceeds the {MAX_CAPTURED_STDOUT_BYTES} byte ceiling"
            ),
        )
    };
    let addition = line.len().checked_add(1).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "captured headless stdout line length overflows",
        )
    })?;
    let total = buffer.len().checked_add(addition).ok_or_else(ceiling)?;
    if total > MAX_CAPTURED_STDOUT_BYTES {
        return Err(ceiling());
    }
    buffer.push_str(line);
    buffer.push('\n');
    Ok(())
}

/// True if this image should be analyzed under `--run`: no `--image` filter, or
/// the filter matches the canonical label (e.g. "02_MAIN") or the bare TOC name (e.g. "MAIN").
fn image_matches(want: Option<&str>, label: &str, name: &str) -> bool {
    want.is_none() || want == Some(label) || want == Some(name)
}

/// The `--run` skip decision (pure — no process spawn, no I/O): `Some(stats)`
/// iff `classify`'s battery is unanimously opaque, meaning Ghidra's standard
/// import recovers nothing (0 functions, 0-byte exports; measured on mustang
/// `01_PSP` — see the spike capture in AGENTS). `None` sends the image
/// to Ghidra exactly as today; a partially-encrypted image is never skipped
/// (any single test refusal fails closed to `not_opaque`).
fn opaque_skip(bytes: &[u8]) -> Option<crate::classify::BatteryStats> {
    let stats = crate::classify::classify(bytes);
    stats.opaque.then_some(stats)
}

/// One image's `--run` result: analyzed (with the function count ExportDecomp
/// recorded), `analyzeHeadless` exited non-zero, the export was rejected by
/// terminal/currentness validation, or skipped because the opaque battery was
/// unanimously opaque (no Ghidra or Thumb-analyzer process was spawned; the
/// carried stats are what the skip decision measured). Recorded per image so a
/// full run reports every partition instead of aborting on the first failure.
#[derive(Debug, Clone)]
pub enum ImageOutcome {
    Analyzed(usize),
    /// `analyzeHeadless` did not run to completion; carries its exit code.
    Failed(i32),
    /// Ghidra completed but the terminal execution inventory or current-run
    /// Thumb validation rejected the export. Distinct from `Failed` so a
    /// successful Ghidra run with stale or failed Thumb output is never
    /// reported as a Ghidra failure, and so the reason survives as
    /// `ImageResult::terminal_error` instead of collapsing to `exit: -1`.
    TerminalInvalid,
    SkippedOpaque(crate::classify::BatteryStats),
}

/// One image's structured `--run` outcome, surfaced for callers that orchestrate
/// (e.g. `decompose`) rather than just print. `Clone` because the normal
/// symbol route retains the pass-1 results across pass 2's by-value
/// consumption of the report (see `retained_pass1_images` in `decompose`).
#[derive(Debug, Clone)]
pub struct ImageResult {
    pub label: String,
    pub outcome: ImageOutcome,
    /// Battery verdict for the image bytes ("opaque"/"not_opaque"), measured
    /// by the `--run` loop before any Ghidra work — consistent with
    /// manifest.json's `battery.label` for the same image (including under
    /// `--no-skip-opaque`). `None` only where no battery ran (test
    /// construction); failed rows omit it in report.json.
    pub classification: Option<&'static str>,
    pub thumb_functions: Option<usize>,
    /// Dense Thumb regions requested from the configured analysis backends.
    pub thumb_regions_requested: Option<usize>,
    /// Requested Thumb regions with a successful terminal attempt.
    pub thumb_regions_succeeded: Option<usize>,
    /// Requested Thumb regions for which every configured attempt failed.
    pub thumb_regions_failed: Option<usize>,
    /// Number of successful radare2-owned function runs.
    pub thumb_radare2_runs: Option<usize>,
    /// Number of successful Rizin-owned function runs.
    pub thumb_rizin_runs: Option<usize>,
    /// Current Ghidra source records with a validated accepted projection.
    pub ghidra_execution_accepted: Option<usize>,
    /// Current Ghidra source records retained as whole-record quarantines.
    pub ghidra_execution_quarantined: Option<usize>,
    /// Current retained Thumb records with a validated accepted projection.
    pub thumb_execution_accepted: Option<usize>,
    /// Current retained Thumb records retained as whole-record quarantines.
    pub thumb_execution_quarantined: Option<usize>,
    /// Raw-image mapping used to validate terminal execution ranges.
    pub(crate) image_start: u32,
    pub(crate) image_len: u32,
    /// Reason-only Thumb-stage failure text; `label` already identifies the image.
    pub thumb_error: Option<String>,
    /// Reason-only terminal-validation failure text: Ghidra completed but the
    /// export pair could not be certified as this run's output. Always set
    /// alongside `ImageOutcome::TerminalInvalid`; when the Thumb sidecar is the
    /// stage that rejected it, `thumb_error` carries the reason too.
    pub terminal_error: Option<String>,
    /// Pass-2 (symbolication) outcome: count of names `ApplySymbols.java`
    /// reported applying. `None` when no function-map invocation occurred
    /// (including a globals-only invocation) or no valid function summary was parsed.
    pub pass2_applied: Option<usize>,
    /// Creation candidates and map-build refusals prepared after pass 1.
    /// `None` means no symbol map was successfully built for this image.
    pub pass2_creation_plan: Option<Pass2CreationPlan>,
    /// Pass-2 creation outcome from `ApplyThumbNames.java`. Every prepared
    /// creation candidate is classified exactly once; `None` means no
    /// function-map invocation completed with a valid current-run summary.
    pub pass2_thumb_names: Option<AppliedThumbNames>,
    /// Reason-only pass-2 failure text: late typed-map validation, analyzeHeadless
    /// spawn/non-zero process failure, or caller-owned-export refresh failure.
    pub pass2_error: Option<String>,
    /// Phase 2: count of Thumb functions whose `body_c` was populated by
    /// `thumb_enrich` from the regenerated `decompiled.c`. `None` when Phase 2
    /// did not run for this image (no Thumb regions, or `--no-thumb-decompile`).
    pub thumb_decompiled: Option<usize>,
    /// Phase 2 / Surface B: reason-only text set when the runtime wall-clock
    /// or log-spam watch killed the tightened run and fell back to `datamark`.
    pub thumb_tighten_error: Option<String>,
    /// Phase 2 / Surface C: reason-only text set when `thumb_enrich` could not
    /// parse `decompiled.c` (malformed output). `thumb_functions.json` is left
    /// intact so downstream stages can keep using the producer artifact.
    pub thumb_enrich_error: Option<String>,
    /// Phase 3.0 / Surface 3.0-A: reason-only text set when `globals::run`
    /// returned Err for this image (e.g. malformed functions.json, raw image
    /// unreadable).
    pub globals_error: Option<String>,
    /// Phase 3.0: count of globals with `tier: "recovered"` written to
    /// `globals.json` for this image. `None` when Phase 3.0 didn't run for
    /// this image (no raw image bytes, or globals stage skipped).
    pub globals_recovered: Option<usize>,
    /// Count of Recovered global names applied by `ApplyGlobals.java`.
    /// `None` means global application did not run; `Some(0)` is executed.
    pub globals_applied: Option<usize>,
    /// Sum of all four `ApplyGlobals.java` skip categories for an executed
    /// successful application.
    pub globals_apply_skipped: Option<usize>,
    /// Reason-only global-application failure from a valid error summary or a
    /// missing, duplicate, malformed, wrong-image, or non-conserving summary.
    pub globals_apply_error: Option<String>,
    /// Count of `undefinedN` types `ApplyGlobalTypes.java` applied. `None` when
    /// type application did not run for this image; `Some(0)` is executed.
    pub global_types_applied: Option<usize>,
    /// Sum of the `ApplyGlobalTypes.java` skip buckets for an executed success.
    pub global_types_apply_skipped: Option<usize>,
    /// Reason-only type-application failure (error/missing/duplicate/malformed/
    /// wrong-image/non-conserving summary).
    pub global_types_apply_error: Option<String>,
    /// Phase 3.0.1: total tier:"provisional" globals generated for this image
    /// (before any suppression). None when Phase 3.0.1 didn't run for this image.
    pub globals_provisional: Option<usize>,
    /// Phase 3.0.1: subset dropped because a Recovered (addr, name') exists at
    /// the same address (tier-conflict suppression — the gate-relevant metric).
    /// None when Phase 3.0.1 didn't run for this image; Some(0) is a valid value.
    pub globals_provisional_suppressed: Option<usize>,
    /// Explicit generation state measured before any image filter or opaque
    /// skip. Physical artifact existence is never substituted for this state.
    pub(crate) exception_state: RuntimeExceptionState,
    /// Strict current-run `ApplyExceptionRoots` summary for a present map.
    /// `None` means application did not complete or was not invoked.
    pub exception_roots_applied: Option<AppliedExceptionRoots>,
    /// Reason-only exception application/currentness failure. Exclusive with
    /// `exception_roots_applied`; process failures remain on `outcome`.
    pub exception_error: Option<String>,
    /// The current-run `ApplyPalTasks` summary for a present PAL map:
    /// task count, application entries, created/existing functions, names
    /// applied/preserved, and shared entries. `None` when no PAL map was
    /// applied for this image; a missing, duplicate, or malformed summary
    /// (or a wrong completion marker) rejects the image instead.
    pub pal_applied: Option<AppliedPalTasks>,
}

/// The parsed `ApplyPalTasks: {json}` current-run summary line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedPalTasks {
    pub tasks: usize,
    pub entries: usize,
    pub functions_created: usize,
    pub functions_existing: usize,
    pub names_applied: usize,
    pub names_preserved: usize,
    pub shared_entries: usize,
}

pub use self::exception_pass2::{
    AppliedExceptionRoots, ExceptionPass2Context, ExceptionPass2ContextInput,
    read_exception_pass2_context,
};
pub(crate) use self::exception_pass2::{
    ExceptionApplicationRef, ExceptionDispositionKind, ExceptionPrimaryRef,
};
#[cfg(test)]
pub(crate) use self::exception_pass2::{TestExceptionContextState, test_context_from_fixture};

/// The parsed `ApplyThumbNames: {json}` current-run summary for one scheduled
/// symbol map. Every candidate is classified exactly once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedThumbNames {
    pub candidates: usize,
    pub created: usize,
    pub reapplied: usize,
    pub skipped_existing: usize,
    pub skipped_collision: usize,
}

/// Static pass-2 creation diagnostics retained from symbol-map construction.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Pass2CreationPlan {
    pub candidates: usize,
    pub skips: crate::symbolicate::Pass2CreationSkips,
    pub(crate) requests: Vec<crate::symbolicate::Pass2CreationRequest>,
}

#[derive(Clone, Copy)]
pub(crate) struct TerminalCreationExpectation<'a> {
    summary: &'a AppliedThumbNames,
    requests: &'a [crate::symbolicate::Pass2CreationRequest],
}

/// A decompile run's per-image outcomes plus the `ghidra_load.json` path.
#[derive(Debug)]
pub struct DecompileReport {
    pub images: Vec<ImageResult>,
    pub spec_path: PathBuf,
    current_exports: BTreeSet<String>,
    runtime_scatter: HashMap<String, RuntimeScatterState>,
    runtime_exception_roots: HashMap<String, RuntimeExceptionState>,
    runtime_tasks: HashMap<String, RuntimeTaskState>,
}

impl DecompileReport {
    pub(crate) fn export_is_current(&self, label: &str) -> bool {
        self.current_exports.contains(label)
    }

    pub(crate) fn runtime_scatter_state(&self, label: &str) -> RuntimeScatterState {
        self.runtime_scatter
            .get(label)
            .copied()
            .unwrap_or(RuntimeScatterState::Unmanaged)
    }

    pub(crate) fn runtime_task_state(&self, label: &str) -> RuntimeTaskState {
        self.runtime_tasks
            .get(label)
            .cloned()
            .unwrap_or(RuntimeTaskState::Unmanaged)
    }

    pub(crate) fn runtime_exception_state(&self, label: &str) -> RuntimeExceptionState {
        self.runtime_exception_roots
            .get(label)
            .cloned()
            .unwrap_or(RuntimeExceptionState::Unmanaged)
    }

    /// One image's coherent runtime analysis state: the scatter and PAL
    /// task states the generation loop measured for this run.
    pub(crate) fn runtime_analysis_state(&self, label: &str) -> RuntimeAnalysisState {
        RuntimeAnalysisState {
            scatter: self.runtime_scatter_state(label),
            tasks: self.runtime_task_state(label),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeScatterState {
    Unmanaged,
    Absent,
    Present,
}

/// The runtime PAL task state of one image, measured by this run's
/// generation loop: never managed for an unrecognized image (`Unmanaged`),
/// explicitly absent for a recognized MAIN whose discovery completed with
/// no candidate, and present with the authenticated manifest identity a
/// failed discovery/publication can never fabricate (`Present`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RuntimeTaskState {
    Unmanaged,
    Absent,
    Present(crate::pal_tasks::MaterializedTaskMap),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RuntimeExceptionState {
    Unmanaged,
    Absent,
    Present(MaterializedExceptionRoots),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuntimeAnalysisState {
    pub scatter: RuntimeScatterState,
    pub tasks: RuntimeTaskState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExecutionInventoryCounts {
    pub raw: usize,
    pub accepted: usize,
    pub quarantined: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TerminalInventorySummary {
    pub ghidra: ExecutionInventoryCounts,
    pub thumb: Option<ExecutionInventoryCounts>,
    pub thumb_substantial: Option<usize>,
    pub(crate) thumb_metadata: Option<crate::thumb_analysis::ThumbTerminalMetadata>,
    pub accepted_identities: Vec<OwnedExecutionIdentity>,
    pub ghidra_records: Vec<TaggedExecutionRecord>,
    pub thumb_records: Vec<TaggedExecutionRecord>,
}

fn inventory_counts(
    inventory: &crate::execution_ranges::ValidatedInventory,
) -> ExecutionInventoryCounts {
    ExecutionInventoryCounts {
        raw: inventory.raw_count,
        accepted: inventory.accepted,
        quarantined: inventory.quarantined,
    }
}

fn validate_thumb_analysis_currentness(
    terminal: &TerminalInventorySummary,
    expected_tools: &crate::thumb_analysis::ThumbTools,
    expected_region_requests: &[(u32, u32)],
    expected: &crate::thumb_analysis::ThumbAnalysisSummary,
) -> Result<()> {
    terminal.thumb.ok_or_else(|| {
        Error::Serialize("current Thumb analysis lacks a terminal inventory".into())
    })?;
    let metadata = terminal.thumb_metadata.as_ref().ok_or_else(|| {
        Error::Serialize("current Thumb analysis lacks terminal provenance metadata".into())
    })?;
    if metadata.format != crate::thumb_analysis::ThumbFormat::V3 {
        return Err(Error::Serialize(format!(
            "current Thumb artifact format mismatch: expected {}, found {}",
            crate::thumb_analysis::ThumbFormat::V3.as_str(),
            metadata.format.as_str(),
        )));
    }
    if expected.rizin_runs > 0 && expected_tools.rizin.is_none() {
        return Err(Error::Serialize(
            "current Thumb analysis lost its Rizin producer identity".into(),
        ));
    }
    let mut expected_producers = vec![&expected_tools.radare2];
    let rizin_attempted =
        expected.rizin_runs > 0 || (expected.regions_failed > 0 && expected_tools.rizin.is_some());
    if rizin_attempted {
        expected_producers.push(
            expected_tools
                .rizin
                .as_ref()
                .expect("Rizin attempt requires configured identity"),
        );
    }
    if metadata.producers.len() != expected_producers.len() {
        let expected = expected_producers
            .iter()
            .map(|producer| producer.producer.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let found = metadata
            .producers
            .iter()
            .map(|producer| producer.producer.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(Error::Serialize(format!(
            "current Thumb producer configuration mismatch: expected exactly [{expected}], found [{found}]"
        )));
    }
    for (expected_producer, observed_producer) in
        expected_producers.into_iter().zip(&metadata.producers)
    {
        if observed_producer.producer != expected_producer.producer {
            return Err(Error::Serialize(format!(
                "current Thumb producer identity mismatch: expected {}, found {}",
                expected_producer.producer.as_str(),
                observed_producer.producer.as_str(),
            )));
        }
        let producer = expected_producer.producer.as_str();
        if observed_producer.executable != expected_producer.executable {
            return Err(Error::Serialize(format!(
                "current Thumb {producer} executable mismatch: expected {}, found {}",
                expected_producer.executable.display(),
                observed_producer.executable.display(),
            )));
        }
        if observed_producer.version != expected_producer.version {
            return Err(Error::Serialize(format!(
                "current Thumb {producer} version mismatch: expected {:?}, found {:?}",
                expected_producer.version, observed_producer.version,
            )));
        }
        if observed_producer.command != expected_producer.command {
            return Err(Error::Serialize(format!(
                "current Thumb {producer} command mismatch: expected {:?}, found {:?}",
                expected_producer.command, observed_producer.command,
            )));
        }
    }
    for (field, expected, observed) in [
        (
            "regions_requested",
            expected.regions_requested,
            metadata.summary.regions_requested,
        ),
        (
            "regions_succeeded",
            expected.regions_succeeded,
            metadata.summary.regions_succeeded,
        ),
        (
            "regions_failed",
            expected.regions_failed,
            metadata.summary.regions_failed,
        ),
        (
            "radare2_runs",
            expected.radare2_runs,
            metadata.summary.radare2_runs,
        ),
        (
            "rizin_runs",
            expected.rizin_runs,
            metadata.summary.rizin_runs,
        ),
        ("raw", expected.raw, metadata.summary.raw),
        (
            "substantial",
            expected.substantial,
            metadata.summary.substantial,
        ),
        ("accepted", expected.accepted, metadata.summary.accepted),
        (
            "quarantined",
            expected.quarantined,
            metadata.summary.quarantined,
        ),
    ] {
        if observed != expected {
            return Err(Error::Serialize(format!(
                "current Thumb {field} mismatch: expected {expected}, found {observed}"
            )));
        }
    }
    let expected_regions = expected_region_requests
        .iter()
        .map(|&(start, len)| {
            start
                .checked_add(len)
                .map(|end| (start, end))
                .ok_or_else(|| {
                    Error::Serialize(format!(
                        "current Thumb region 0x{start:x} length 0x{len:x} overflows u32"
                    ))
                })
        })
        .collect::<Result<Vec<_>>>()?;
    if metadata.regions != expected_regions {
        let render = |regions: &[(u32, u32)]| {
            format!(
                "[{}]",
                regions
                    .iter()
                    .map(|(start, end)| format!("(0x{start:x}, 0x{end:x})"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        return Err(Error::Serialize(format!(
            "current Thumb region ledger mismatch: expected {}, found {}",
            render(&expected_regions),
            render(&metadata.regions),
        )));
    }
    Ok(())
}

/// A rejected terminal export, tagged with the stage responsible. A Thumb-side
/// rejection also means the Thumb stage left no current sidecar, so it feeds
/// `thumb_error`; a Ghidra-side rejection is not a Thumb failure and must not
/// be reported as one.
pub(crate) struct TerminalValidationFailure {
    pub thumb: bool,
    pub error: Error,
}

impl TerminalValidationFailure {
    fn ghidra(error: Error) -> Self {
        Self {
            thumb: false,
            error,
        }
    }

    fn thumb(error: Error) -> Self {
        Self { thumb: true, error }
    }
}

/// Validate one complete terminal Ghidra/optional-Thumb pair. When
/// `expected_current` is supplied, every normalized tagged source record must
/// match the already-validated current producer result before refresh.
/// A pass-2 creation expectation permits only the reported created count and
/// binds every addition to an exact map entry/name/source while preserving
/// every retained Ghidra execution record.
pub(crate) fn validate_terminal_inventory_pair(
    ghidra_functions_path: &Path,
    thumb_functions_path: &Path,
    runtime: &RuntimeImage<'_>,
    expected_thumb_substantial: Option<usize>,
    expected_current: Option<&TerminalInventorySummary>,
    creation: Option<TerminalCreationExpectation<'_>>,
) -> Result<TerminalInventorySummary> {
    validate_terminal_inventory_pair_staged(
        ghidra_functions_path,
        thumb_functions_path,
        runtime,
        expected_thumb_substantial,
        expected_current,
        creation,
    )
    .map_err(|failure| failure.error)
}

fn retained_ghidra_record_delta(
    staged: &[TaggedExecutionRecord],
    retained: &[TaggedExecutionRecord],
) -> Option<usize> {
    let mut staged: Vec<_> = staged.iter().collect();
    let mut retained: Vec<_> = retained.iter().collect();
    staged.sort_unstable();
    retained.sort_unstable();
    let (mut staged_index, mut retained_index, mut additions) = (0, 0, 0usize);
    while staged_index < staged.len() {
        if retained_index == retained.len() {
            return additions.checked_add(staged.len() - staged_index);
        }
        match staged[staged_index].cmp(retained[retained_index]) {
            std::cmp::Ordering::Less => {
                additions = additions.checked_add(1)?;
                staged_index += 1;
            }
            std::cmp::Ordering::Equal => {
                staged_index += 1;
                retained_index += 1;
            }
            std::cmp::Ordering::Greater => return None,
        }
    }
    (retained_index == retained.len()).then_some(additions)
}

fn validate_terminal_creation_functions(
    staged: &[crate::execution_ranges::GhidraFunctionFields],
    retained: Option<&[TaggedExecutionRecord]>,
    expected: TerminalCreationExpectation<'_>,
) -> Result<()> {
    if expected.requests.len() != expected.summary.candidates {
        return Err(Error::Serialize(
            "prepared creation requests do not match the reported candidate count".into(),
        ));
    }
    let classified = expected
        .summary
        .created
        .checked_add(expected.summary.reapplied)
        .and_then(|count| count.checked_add(expected.summary.skipped_existing))
        .and_then(|count| count.checked_add(expected.summary.skipped_collision))
        .ok_or_else(|| Error::Serialize("creation summary count overflow".into()))?;
    if classified != expected.summary.candidates {
        return Err(Error::Serialize(
            "creation summary does not conserve candidates".into(),
        ));
    }

    let mut staged_by_entry = std::collections::BTreeMap::new();
    for function in staged {
        if staged_by_entry.insert(function.entry, function).is_some() {
            return Err(Error::Serialize(format!(
                "terminal Ghidra inventory repeats entry 0x{:x}",
                function.entry
            )));
        }
    }
    let mut requests_by_entry = std::collections::BTreeMap::new();
    for request in expected.requests {
        if !matches!(request.final_source.as_str(), "analysis" | "user_defined") {
            return Err(Error::Serialize(format!(
                "creation request at 0x{:x} has invalid source {:?}",
                request.entry, request.final_source
            )));
        }
        if requests_by_entry.insert(request.entry, request).is_some() {
            return Err(Error::Serialize(format!(
                "creation requests repeat entry 0x{:x}",
                request.entry
            )));
        }
    }

    let exact_requests = expected
        .requests
        .iter()
        .filter(|request| {
            staged_by_entry.get(&request.entry).is_some_and(|function| {
                function.name == request.final_primary
                    && function.primary_source == request.final_source
                    && matches!(
                        &function.tagged.projection,
                        crate::execution_ranges::ExecutionProjection::Accepted(ranges)
                            if ranges.iter().any(|range| {
                                range.start == function.entry
                                    && range.isa
                                        == crate::execution_ranges::DecodeIsa::Thumb
                            })
                    )
            })
        })
        .count();
    let expected_exact = expected
        .summary
        .created
        .checked_add(expected.summary.reapplied)
        .ok_or_else(|| Error::Serialize("creation exact-match count overflow".into()))?;
    if exact_requests != expected_exact {
        return Err(Error::Serialize(format!(
            "terminal creation identities do not match created + reapplied: expected {expected_exact}, found {exact_requests}"
        )));
    }

    let Some(retained) = retained else {
        return Ok(());
    };
    let mut retained_entries = BTreeSet::new();
    for record in retained {
        if !retained_entries.insert(record.entry) {
            return Err(Error::Serialize(format!(
                "retained Ghidra inventory repeats entry 0x{:x}",
                record.entry
            )));
        }
        let function = staged_by_entry.get(&record.entry).ok_or_else(|| {
            Error::Serialize(format!(
                "terminal Ghidra inventory lost retained entry 0x{:x}",
                record.entry
            ))
        })?;
        if function.tagged != *record {
            return Err(Error::Serialize(format!(
                "terminal Ghidra inventory changed retained entry 0x{:x}",
                record.entry
            )));
        }
    }

    let additions: Vec<_> = staged
        .iter()
        .filter(|function| !retained_entries.contains(&function.entry))
        .collect();
    if additions.len() != expected.summary.created {
        return Err(Error::Serialize(format!(
            "terminal Ghidra inventory added {} functions, expected {}",
            additions.len(),
            expected.summary.created
        )));
    }
    for function in additions {
        let request = requests_by_entry.get(&function.entry).ok_or_else(|| {
            Error::Serialize(format!(
                "terminal Ghidra inventory added unrequested entry 0x{:x}",
                function.entry
            ))
        })?;
        if function.name != request.final_primary || function.primary_source != request.final_source
        {
            return Err(Error::Serialize(format!(
                "terminal Ghidra creation at 0x{:x} changed its requested name or source",
                function.entry
            )));
        }
        let accepted_thumb_entry = match &function.tagged.projection {
            crate::execution_ranges::ExecutionProjection::Accepted(ranges) => {
                ranges.iter().any(|range| {
                    range.start == function.entry
                        && range.isa == crate::execution_ranges::DecodeIsa::Thumb
                })
            }
            crate::execution_ranges::ExecutionProjection::Quarantined(_) => false,
        };
        if !accepted_thumb_entry {
            return Err(Error::Serialize(format!(
                "terminal Ghidra creation at 0x{:x} lacks a Thumb projection at its entry",
                function.entry
            )));
        }
    }
    Ok(())
}

pub(crate) fn validate_terminal_inventory_pair_staged(
    ghidra_functions_path: &Path,
    thumb_functions_path: &Path,
    runtime: &RuntimeImage<'_>,
    expected_thumb_substantial: Option<usize>,
    expected_current: Option<&TerminalInventorySummary>,
    creation: Option<TerminalCreationExpectation<'_>>,
) -> std::result::Result<TerminalInventorySummary, TerminalValidationFailure> {
    let allowed_new_ghidra = creation.map_or(0, |expected| expected.summary.created);
    let streamed =
        crate::execution_ranges::read_ghidra_inventory_streaming(ghidra_functions_path, runtime)
            .map_err(TerminalValidationFailure::ghidra)?;
    let ghidra_functions = streamed.functions;
    let ghidra = streamed.inventory;
    let mut accepted_identities: BTreeSet<OwnedExecutionIdentity> =
        ghidra.accepted_executions.iter().cloned().collect();

    let (thumb, thumb_substantial, thumb_metadata, thumb_records) = match expected_thumb_substantial
    {
        None => {
            if thumb_functions_path.exists() {
                return Err(TerminalValidationFailure::thumb(Error::Serialize(
                    "unexpected Thumb inventory without a current producer result".into(),
                )));
            }
            (None, None, None, Vec::new())
        }
        Some(expected_substantial) => {
            let validated = crate::thumb_analysis::validate_thumb_inventory_streaming(
                thumb_functions_path,
                runtime,
                expected_substantial,
            )
            .map_err(TerminalValidationFailure::thumb)?;
            let inventory = validated.inventory;
            let metadata = validated.metadata;
            accepted_identities.extend(inventory.accepted_executions.iter().cloned());
            (
                Some(inventory_counts(&inventory)),
                Some(metadata.summary.substantial),
                Some(metadata),
                inventory.records,
            )
        }
    };

    let summary = TerminalInventorySummary {
        ghidra: inventory_counts(&ghidra),
        thumb,
        thumb_substantial,
        thumb_metadata,
        accepted_identities: accepted_identities.into_iter().collect(),
        ghidra_records: ghidra.records,
        thumb_records,
    };
    if expected_current.is_none()
        && let Some(creation) = creation
    {
        validate_terminal_creation_functions(&ghidra_functions, None, creation)
            .map_err(TerminalValidationFailure::ghidra)?;
    }
    if let Some(expected) = expected_current {
        let thumb_unchanged = summary.thumb_metadata == expected.thumb_metadata
            && summary.thumb == expected.thumb
            && summary.thumb_substantial == expected.thumb_substantial
            && summary.thumb_records == expected.thumb_records;
        // With creations allowed, every count delta must be exactly the
        // creation allowance on the Ghidra accepted/raw pair; the identities
        // grow by the same amount. Record-level equality of the pass-1 set
        // is enforced in-process by ExportDecomp's map postflight.
        let ghidra_ok = if let Some(creation) = creation {
            summary.ghidra.quarantined == expected.ghidra.quarantined
                && expected.ghidra.raw.checked_add(allowed_new_ghidra) == Some(summary.ghidra.raw)
                && expected.ghidra.accepted.checked_add(allowed_new_ghidra)
                    == Some(summary.ghidra.accepted)
                && expected
                    .accepted_identities
                    .len()
                    .checked_add(allowed_new_ghidra)
                    == Some(summary.accepted_identities.len())
                && retained_ghidra_record_delta(&summary.ghidra_records, &expected.ghidra_records)
                    == Some(allowed_new_ghidra)
                && validate_terminal_creation_functions(
                    &ghidra_functions,
                    Some(&expected.ghidra_records),
                    creation,
                )
                .is_ok()
        } else {
            summary.ghidra == expected.ghidra
                && summary.ghidra_records == expected.ghidra_records
                && summary.accepted_identities == expected.accepted_identities
        };
        if !thumb_unchanged || !ghidra_ok {
            // The comparison spans both stages; a differing Thumb ledger is the
            // only way this can be a Thumb-stage problem.
            let thumb = !thumb_unchanged;
            return Err(TerminalValidationFailure {
                thumb,
                error: Error::Serialize(
                    "terminal execution inventory differs from the current producer result".into(),
                ),
            });
        }
    }
    Ok(summary)
}

pub(crate) fn validate_image_terminal_inventory(
    ghidra_functions_path: &Path,
    thumb_functions_path: &Path,
    image: &ImageResult,
    expected_current: Option<&TerminalInventorySummary>,
) -> Result<TerminalInventorySummary> {
    let image_dir = thumb_functions_path
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| Error::Serialize("Thumb inventory has no image directory".into()))?;
    let raw = std::fs::read(image_dir.join(format!("{}.bin", image.label)))?;
    if u32::try_from(raw.len()).ok() != Some(image.image_len) {
        return Err(Error::Serialize(
            "terminal raw image length does not match the producer report".into(),
        ));
    }
    let runtime = RuntimeImage::for_image_dir(&raw, image.image_start, image_dir)?;
    // Pass-2 creation (ApplyThumbNames) may grow the Ghidra inventory only by
    // exact entry/name/source requests retained from this run's symbol map.
    let creation = match (
        image.pass2_thumb_names.as_ref(),
        image.pass2_creation_plan.as_ref(),
    ) {
        (None, _) => None,
        (Some(_), None) => {
            return Err(Error::Serialize(
                "ApplyThumbNames summary has no prepared creation plan".into(),
            ));
        }
        (Some(summary), Some(plan)) => {
            if summary.candidates != plan.candidates || plan.requests.len() != plan.candidates {
                return Err(Error::Serialize(
                    "ApplyThumbNames summary does not match the prepared creation plan".into(),
                ));
            }
            Some(TerminalCreationExpectation {
                summary,
                requests: &plan.requests,
            })
        }
    };
    let current_owned_creations = creation
        .map(|expected| {
            expected
                .summary
                .created
                .checked_add(expected.summary.reapplied)
                .ok_or_else(|| Error::Serialize("current creation count overflow".into()))
        })
        .transpose()?
        .unwrap_or(0);
    let summary = validate_terminal_inventory_pair(
        ghidra_functions_path,
        thumb_functions_path,
        &runtime,
        image.thumb_functions,
        expected_current,
        creation,
    )?;
    let raw_functions = match image.outcome {
        ImageOutcome::Analyzed(raw) => raw,
        ImageOutcome::Failed(_) | ImageOutcome::TerminalInvalid => {
            return Err(Error::Serialize(
                "failed image has no current terminal inventory".into(),
            ));
        }
        ImageOutcome::SkippedOpaque(_) => {
            return Err(Error::Serialize(
                "skipped image has no current terminal inventory".into(),
            ));
        }
    };
    let reported = (
        image.ghidra_execution_accepted,
        image.ghidra_execution_quarantined,
        image.thumb_execution_accepted,
        image.thumb_execution_quarantined,
    );
    let validated = (
        Some(summary.ghidra.accepted),
        Some(summary.ghidra.quarantined),
        summary.thumb.map(|thumb| thumb.accepted),
        summary.thumb.map(|thumb| thumb.quarantined),
    );
    // The producer report is the pass-1 baseline. Current output includes
    // both creations made now and exact owned creations replayed from an
    // earlier application of this same map.
    let expected_validated = (
        reported
            .0
            .and_then(|count| count.checked_add(current_owned_creations)),
        reported.1,
        reported.2,
        reported.3,
    );
    if raw_functions.checked_add(current_owned_creations) != Some(summary.ghidra.raw)
        || validated != expected_validated
    {
        return Err(Error::Serialize(format!(
            "terminal inventory counters do not match current producer report: raw {raw_functions}, reported {reported:?}, validated {validated:?}"
        )));
    }
    Ok(summary)
}

/// Count the functions ExportDecomp.java recorded for an image — its `functions.json`
/// is a JSON array. A missing or unparseable file counts as 0, so a silently-empty
/// partition (e.g. a compressed/encrypted one, which yields no disassembly) reads as
/// 0 functions rather than erroring.
fn count_functions(export_dir: &Path) -> usize {
    std::fs::read(export_dir.join("functions.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| v.as_array().map(|a| a.len()))
        .unwrap_or(0)
}

#[derive(Debug, Clone)]
struct GhidraExportRun {
    directory: PathBuf,
    completion: PathBuf,
}

impl GhidraExportRun {
    fn new(root: &Path, label: &str) -> Self {
        let export_root = root.join("export");
        Self {
            directory: export_root.join(label),
            completion: export_root.join(format!("{label}.complete")),
        }
    }

    fn invalidate(&self) -> std::io::Result<()> {
        let mut first_error = None;
        if let Err(error) = remove_file_if_present(&self.completion) {
            first_error = Some(error);
        }
        for name in GHIDRA_EXPORT_FILES {
            if let Err(error) = remove_file_if_present(&self.directory.join(name))
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        if let Some(error) = first_error {
            Err(error)
        } else {
            Ok(())
        }
    }

    fn validate_current(
        &self,
        exception_identity: &str,
        pal_identity: &str,
        symbol_map: &str,
    ) -> std::result::Result<(), String> {
        for name in GHIDRA_EXPORT_FILES {
            let path = self.directory.join(name);
            let metadata = std::fs::symlink_metadata(&path)
                .map_err(|error| format!("current Ghidra export lacks {name}: {error}"))?;
            if !metadata.file_type().is_file() {
                return Err(format!(
                    "current Ghidra export {name} is not a regular file"
                ));
            }
        }
        let marker = std::fs::read(&self.completion)
            .map_err(|error| format!("current Ghidra export lacks completion marker: {error}"))?;
        let expected = export_completion_marker(exception_identity, pal_identity, symbol_map);
        if marker != expected {
            return Err("current Ghidra export has an invalid completion marker".to_string());
        }
        Ok(())
    }
}

struct GhidraExportAttempt {
    run: GhidraExportRun,
    current: bool,
}

impl GhidraExportAttempt {
    fn begin(root: &Path, label: &str) -> std::io::Result<Self> {
        let run = GhidraExportRun::new(root, label);
        run.invalidate()?;
        Ok(Self {
            run,
            current: false,
        })
    }

    fn mark_current(&mut self) {
        self.current = true;
    }
}

impl std::ops::Deref for GhidraExportAttempt {
    type Target = GhidraExportRun;

    fn deref(&self) -> &Self::Target {
        &self.run
    }
}

impl Drop for GhidraExportAttempt {
    fn drop(&mut self) {
        if !self.current
            && let Err(error) = self.run.invalidate()
        {
            tracing::warn!(
                "failed to scrub incomplete Ghidra export {}: {error}",
                self.run.directory.display()
            );
        }
    }
}

fn remove_file_if_present(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn generation_only_hint(out: &Path) -> String {
    format!(
        "(generation only; pass --run to drive Ghidra plus radare2 primary for dense Thumb regions, with optional failure-only Rizin via --rizin-fallback; or run {}/run_ghidra.sh for Ghidra-only import/export)",
        out.display()
    )
}

/// Shannon entropy (bits/byte) of a window. Native ARM code sits around 5–6;
/// compressed/encrypted data sits near 7–8, giving a clean split for §`thumb_regions`.
fn window_entropy(w: &[u8]) -> f64 {
    if w.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in w {
        counts[b as usize] += 1;
    }
    let n = w.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// Detect large dense-Thumb regions in an image by entropy. MAIN interleaves ARM/A32
/// code with multi-MB Thumb-2 blobs — the upper protocol stack (IMS/VoLTE/SIP, RRC,
/// NAS, L1/PHY, 5G-NR). Thumb-2 is denser than A32 (~7 bits/byte vs ~5-6), so high
/// entropy marks the Thumb regions. Tighten mode lets Ghidra analyze them under the
/// overlap-repair watch; datamark mode marks them as data. Independently, the host
/// analyzes every detected region with radare2 primary and optional Rizin fallback.
///
/// Windows above `ENTROPY_THRESHOLD` are merged; only regions ≥ `MIN_REGION` are
/// returned, so small high-entropy spans (A32 constant pools) aren't misclassified.
/// Returns `(absolute_address, length)` per region.
fn thumb_regions(bytes: &[u8], load_addr: u32) -> Vec<(u32, u32)> {
    const WINDOW: usize = 64 * 1024;
    const ENTROPY_THRESHOLD: f64 = 6.5;
    const MIN_REGION: usize = 1024 * 1024; // 1 MiB

    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut open: Option<usize> = None;
    let mut off = 0;
    while off < bytes.len() {
        let end = (off + WINDOW).min(bytes.len());
        if window_entropy(&bytes[off..end]) > ENTROPY_THRESHOLD {
            open.get_or_insert(off);
        } else if let Some(start) = open.take() {
            spans.push((start, off));
        }
        off = end;
    }
    if let Some(start) = open.take() {
        spans.push((start, bytes.len()));
    }
    spans
        .into_iter()
        .filter(|(s, e)| e - s >= MIN_REGION)
        .map(|(s, e)| (load_addr.wrapping_add(s as u32), (e - s) as u32))
        .collect()
}

/// Phase 2 / Surface B: thresholds for killing a tightened Ghidra run that is
/// spinning on `ClearFlowAndRepairCmd` overlapping-function repair. Defaults
/// are conservative; the `--tighten-wall-clock-budget-sec` test-only flag
/// supplies an absolute override that bypasses `baseline * wall_clock_multiplier`
/// (used by Section 7 verification).
#[derive(Debug, Clone, Copy)]
pub struct TightenBudget {
    /// Multiplied by the pass-1 baseline wall-clock to get the per-image budget.
    pub wall_clock_multiplier: u32,
    /// Hard cap on `ClearFlowAndRepairCmd`-related log lines.
    pub log_spam_max: usize,
}

impl Default for TightenBudget {
    fn default() -> Self {
        Self {
            wall_clock_multiplier: 4,
            log_spam_max: 100_000,
        }
    }
}

/// Reason the watch killed a tightened run. Surfaced in `thumb_tighten_error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillReason {
    WallClock,
    LogSpam,
}

impl std::fmt::Display for KillReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KillReason::WallClock => write!(f, "exceeded wall-clock budget"),
            KillReason::LogSpam => write!(f, "exceeded ClearFlowAndRepairCmd log-spam threshold"),
        }
    }
}

/// Decide whether to kill a tightened Ghidra run. Pure; testable without Ghidra.
///
/// The wall-clock budget is `baseline * budget.wall_clock_multiplier`, unless
/// `wall_clock_override` is `Some(d)` — then the budget is `d` directly (the
/// `--tighten-wall-clock-budget-sec` test-only override). `baseline` is the
/// pass-1 wall-clock recorded for this image.
pub fn should_kill_tighten(
    elapsed: std::time::Duration,
    repair_log_lines: usize,
    budget: &TightenBudget,
    baseline: std::time::Duration,
    wall_clock_override: Option<std::time::Duration>,
) -> Option<KillReason> {
    let wall_budget =
        wall_clock_override.or_else(|| baseline.checked_mul(budget.wall_clock_multiplier))?;
    if elapsed > wall_budget {
        return Some(KillReason::WallClock);
    }
    if repair_log_lines > budget.log_spam_max {
        return Some(KillReason::LogSpam);
    }
    None
}

/// Phase 2 / Surface B: per-image tighten baseline extrapolated from the
/// image's dense-Thumb byte count. Grounded in initial measurement — Ghidra
/// 12.1.2 under `Tighten`-mode `TameAnalysis` converged on a 2 MiB dense-Thumb
/// sample in 80 s, i.e. ~40 s/MiB. Below the 60 s floor the heuristic keeps the
/// watch meaningful on tiny regions (a 0-MiB image still gets a 60 s baseline,
/// which combined with the default 4× multiplier yields a 240 s ceiling).
///
/// `should_kill_tighten` multiplies this by `TightenBudget::wall_clock_multiplier`
/// (default 4×) unless the test-only `--tighten-wall-clock-budget-sec` override
/// supplies an absolute budget. For a real `02_MAIN` (~42 MiB dense Thumb across
/// 5 regions) this gives baseline ≈ 1 680 s (~28 min) and a default budget of
/// ~112 min — generous enough to not fire prematurely on real firmware, tight
/// enough to catch a true overlap-repair spin (which runs for hours otherwise).
pub fn tighten_baseline_for_dense_thumb_bytes(dense_thumb_bytes: usize) -> std::time::Duration {
    const SECONDS_PER_MIB: u64 = 40;
    const FLOOR_SECONDS: u64 = 60;
    let mib = (dense_thumb_bytes / (1024 * 1024)) as u64;
    std::time::Duration::from_secs(FLOOR_SECONDS.max(mib.saturating_mul(SECONDS_PER_MIB)))
}

/// Phase 2 / Surface B (Unix): spawn helper that puts the Ghidra `analyzeHeadless`
/// process in its own process group so the Surface B watch can kill the whole
/// tree (bash launcher + Java grandchild) with one `killpg`. Without this the
/// SIGKILL from `child.kill()` only reaps the bash launcher; the JVM is
/// orphaned to init and keeps holding the Ghidra project lock, which then
/// makes the datamark retry fail with `LockException` (the bug fixed by this
/// module).
///
/// On non-Unix targets this is a no-op (Windows users fall back to
/// `--no-thumb-decompile` if the tighten-watch fires — there is no
/// cross-platform process-group kill in std).
#[cfg(unix)]
fn spawn_in_own_process_group(cmd: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
    cmd.process_group(0);
}

#[cfg(not(unix))]
fn spawn_in_own_process_group(_cmd: &mut std::process::Command) {
    // No portable process-group kill in std; on Windows the JVM is orphaned
    // by `child.kill()`. Use `--no-thumb-decompile` if Surface B fires.
}

/// Phase 2 / Surface B (Unix): send SIGKILL to the entire process group led
/// by `child`. Best-effort — the caller has already SIGKILLed the immediate
/// child via `child.kill()`. Negative PID means "the process group".
#[cfg(unix)]
fn kill_process_group(child_pid: u32) {
    // SAFETY: `libc::kill` is async-signal-safe and thread-safe; the only
    // failure modes are ESRCH (already gone — fine), EPERM (not our child,
    // shouldn't happen for our own spawn), or EINVAL (bad signal — static
    // input). We discard the return value because every failure mode is
    // either benign or impossible.
    unsafe {
        let _ = libc::kill(-(child_pid as libc::pid_t), libc::SIGKILL);
    }
}

#[cfg(not(unix))]
fn kill_process_group(_child_pid: u32) {
    // No portable killpg; on Windows `child.kill()` orphans the JVM.
}

/// POSIX shell-quote: wrap the input in single quotes, escaping any embedded
/// single quote as `'\''`. Robust against `"`, `$`, backticks, semicolons,
/// spaces, and any other shell metacharacter. The generated script uses this
/// for every non-path argument, including the user-controlled processor.
/// Empty string → `''`.
fn shell_quote(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

fn shell_arg(arg: &str) -> String {
    if let Some(suffix) = arg.strip_prefix("$HERE") {
        format!("\"${{HERE}}{}\"", suffix.replace('"', "\\\""))
    } else {
        shell_quote(arg)
    }
}

/// Write a turnkey `run_ghidra.sh` (one `analyzeHeadless` invocation per image),
/// built from `headless_args` against a relocatable `$HERE` root. Ghidra's
/// Java/XDG state lives in one unique, space-free `mktemp -d` directory removed
/// by the cleanup trap, so no cross-run state ever leaks and a `$HERE`
/// containing spaces cannot corrupt the word-split `-D` tokens.
fn write_run_script(
    out: &Path,
    toc: &Toc,
    processor: &str,
    runtime_load_maps: &HashMap<String, String>,
    runtime_exception_states: &HashMap<String, RuntimeExceptionState>,
    runtime_task_states: &HashMap<String, RuntimeTaskState>,
) -> Result<()> {
    let mut s = String::new();
    s.push_str("#!/usr/bin/env sh\n");
    s.push_str(
        "# Generated by pixel-modem-extractor decompile. Drives Ghidra headless per image.\n",
    );
    s.push_str("set -eu\n");
    s.push_str(": \"${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR to your Ghidra install root}\"\n");
    // Upstream ships analyzeHeadless under support/; Homebrew nests it under libexec/support/.
    s.push_str("if [ -x \"$GHIDRA_INSTALL_DIR/support/analyzeHeadless\" ]; then\n");
    s.push_str("  HEADLESS=\"$GHIDRA_INSTALL_DIR/support/analyzeHeadless\"\n");
    s.push_str("elif [ -x \"$GHIDRA_INSTALL_DIR/libexec/support/analyzeHeadless\" ]; then\n");
    s.push_str("  HEADLESS=\"$GHIDRA_INSTALL_DIR/libexec/support/analyzeHeadless\"\n");
    s.push_str("else\n");
    s.push_str("  echo \"analyzeHeadless not found under $GHIDRA_INSTALL_DIR (looked in support/ and libexec/support/)\" >&2\n");
    s.push_str("  exit 1\n");
    s.push_str("fi\n");
    s.push_str("HERE=\"$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd -P)\"\n");
    // A unique, space-free state directory: the `-D…` tokens below are
    // word-split unquoted by analyzeHeadless itself, and reusing a kit-local
    // directory would leak Java/cache state across runs of the same kit.
    s.push_str("STATE_HOME=\"$(mktemp -d \"${TMPDIR:-/tmp}/pixel-modem-ghidra.XXXXXXXX\")\"\n");
    // A spaced TMPDIR would reintroduce exactly the word-split breakage the
    // `-D` tokens' space-free requirement exists to prevent; fail closed
    // with a clear message instead of failing obscurely inside Ghidra.
    s.push_str("case \"$STATE_HOME\" in\n");
    s.push_str("  *[\\ \\\t]*)\n");
    s.push_str("    echo \"the temp directory path contains whitespace; set TMPDIR to a space-free directory\" >&2\n");
    s.push_str("    exit 1\n");
    s.push_str("    ;;\n");
    s.push_str("esac\n");
    s.push_str("cleanup() { rm -rf \"$STATE_HOME\"; }\n");
    s.push_str("trap cleanup EXIT\n");
    s.push_str("trap 'exit 130' INT\n");
    s.push_str("trap 'exit 143' TERM\n");
    s.push_str("export XDG_CONFIG_HOME=\"$STATE_HOME/ghidra_config\"\n");
    s.push_str("export XDG_CACHE_HOME=\"$STATE_HOME/ghidra_cache\"\n");
    s.push_str("GHIDRA_LOCAL_JAVA_OPTIONS=\"-Dapplication.settingsdir=$STATE_HOME/ghidra_config -Dapplication.cachedir=$STATE_HOME/ghidra_cache -Dapplication.tempdir=$STATE_HOME/ghidra_tmp -Djava.io.tmpdir=$STATE_HOME/ghidra_tmp\"\n");
    s.push_str("if [ \"${GHIDRA_HEADLESS_JAVA_OPTIONS+x}\" ]; then\n");
    s.push_str("  export GHIDRA_HEADLESS_JAVA_OPTIONS=\"$GHIDRA_HEADLESS_JAVA_OPTIONS $GHIDRA_LOCAL_JAVA_OPTIONS\"\n");
    s.push_str("else\n");
    s.push_str("  export GHIDRA_HEADLESS_JAVA_OPTIONS=\"$GHIDRA_LOCAL_JAVA_OPTIONS\"\n");
    s.push_str("fi\n");
    s.push_str("mkdir -p \"$HERE/ghidra_project\" \"$HERE/export\" \"$STATE_HOME/ghidra_config\" \"$STATE_HOME/ghidra_cache\" \"$STATE_HOME/ghidra_tmp\"\n");
    for e in toc.embedded() {
        // `run_ghidra.sh` runs in tighten mode (production default), which does
        // not data-mark regions — `headless_args` ignores the slice. Pass an
        // empty slice and skip the entropy scan; the regions are computed in
        // `run_report` under `--run` only when `mode=datamark` actually needs them.
        let mode = "tighten";
        let label = e.label();
        let exception_plan = match runtime_exception_states.get(&label) {
            Some(RuntimeExceptionState::Present(map)) => Some(ExceptionRootScriptPlan {
                manifest: &map.relative_path,
                identity: &map.identity,
            }),
            _ => None,
        };
        let pal_plan = match runtime_task_states.get(&label) {
            Some(RuntimeTaskState::Present(map)) => Some(PalScriptPlan {
                manifest: &map.relative_path,
                identity: &map.identity,
            }),
            _ => None,
        };
        let export_dir = format!("$HERE/export/{label}");
        let completion = format!("$HERE/export/{label}.complete");
        let mut cleanup = format!("rm -f {}", shell_arg(&completion));
        for name in GHIDRA_EXPORT_FILES {
            cleanup.push(' ');
            cleanup.push_str(&shell_arg(&format!("{export_dir}/{name}")));
        }
        s.push_str(&cleanup);
        s.push('\n');
        let args = headless_args(
            "$HERE",
            &label,
            processor,
            e.load_addr,
            runtime_load_maps.get(&label).map(String::as_str),
            exception_plan,
            pal_plan,
            &[],
            mode,
        );
        s.push_str("if \"$HEADLESS\"");
        let mut processor_value = false;
        for arg in &args {
            s.push(' ');
            if processor_value {
                s.push_str(&shell_quote(arg));
            } else {
                s.push_str(&shell_arg(arg));
            }
            processor_value = arg == "-processor";
        }
        for name in GHIDRA_EXPORT_FILES {
            s.push_str(&format!(
                " && test -f {}",
                shell_arg(&format!("{export_dir}/{name}"))
            ));
        }
        // The exact four-line v4 marker is constructed from the same current
        // per-image exception/PAL generation state as the invocation.
        let exception_identity = exception_plan.map(|plan| plan.identity).unwrap_or("none");
        let pal_identity = pal_plan.map(|plan| plan.identity).unwrap_or("none");
        let marker = export_completion_marker(exception_identity, pal_identity, "none");
        let marker_lines: Vec<String> = String::from_utf8(marker)
            .expect("the completion marker is ASCII")
            .lines()
            .map(shell_quote)
            .collect();
        s.push_str(&format!(
            " && printf '%s\\n' {} | cmp -s - {}; then\n",
            marker_lines.join(" "),
            shell_arg(&completion)
        ));
        s.push_str("  :\n");
        s.push_str("else\n");
        s.push_str("  status=$?\n");
        s.push_str("  ");
        s.push_str(&cleanup);
        s.push_str(" || true\n");
        s.push_str("  exit \"$status\"\n");
        s.push_str("fi\n");
    }
    let path = out.join("run_ghidra.sh");
    std::fs::write(&path, s)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = std::fs::metadata(&path)?.permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&path, perm)?;
    }
    Ok(())
}

/// The generation loop's per-image runtime analysis products: scatter
/// paths/states plus explicit exception-root and PAL task states. Every entry
/// is measured by this run; currentness is never inferred from artifact
/// existence on disk.
struct RuntimeAnalysis {
    scatter_paths: HashMap<String, String>,
    scatter_states: HashMap<String, RuntimeScatterState>,
    exception_roots: HashMap<String, RuntimeExceptionState>,
    tasks: HashMap<String, RuntimeTaskState>,
}

fn generate_runtime_analysis(toc: &Toc, data: &[u8], out: &Path) -> Result<RuntimeAnalysis> {
    generate_runtime_analysis_with(
        toc,
        data,
        out,
        |image, base| scatter::discover(image, base).map_err(|error| error.to_string()),
        exception_roots::discover,
        exception_roots::materialize,
        exception_roots::clear_materialized,
        pal_tasks::discover,
    )
}

/// Generate the runtime-analysis artifacts in dependency order: MAIN scatter
/// once, one runtime view per embedded image, exception roots for every image,
/// then MAIN PAL against the already-built view. Publication is atomic
/// replacement; an owned artifact is cleared only after successful absence.
/// Any discovery, publication, or clear error returns no consumable current state.
// Keep discovery, publication, and clear independently injectable so each
// currentness boundary has deterministic failure coverage.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn generate_runtime_analysis_with(
    toc: &Toc,
    data: &[u8],
    out: &Path,
    mut discover_scatter: impl FnMut(
        &[u8],
        u32,
    ) -> std::result::Result<Option<scatter::LoadPlan>, String>,
    mut discover_exception_roots: impl FnMut(
        &RuntimeImage<'_>,
        &str,
        &str,
    ) -> std::result::Result<
        Option<exception_roots::ExceptionRootPlan>,
        exception_roots::ExceptionRootError,
    >,
    mut materialize_exception_roots: impl FnMut(
        &exception_roots::ExceptionRootPlan,
        ExceptionArtifactContext<'_>,
        &Path,
    ) -> std::result::Result<
        MaterializedExceptionRoots,
        exception_roots::ExceptionRootError,
    >,
    mut clear_exception_roots: impl FnMut(
        &Path,
        &str,
    ) -> std::result::Result<
        (),
        exception_roots::ExceptionRootError,
    >,
    mut discover_tasks: impl FnMut(
        &RuntimeImage<'_>,
        &str,
    ) -> std::result::Result<
        Option<pal_tasks::TaskPlan>,
        pal_tasks::PalTaskError,
    >,
) -> Result<RuntimeAnalysis> {
    let mut scatter_paths = HashMap::new();
    let mut scatter_states = HashMap::new();
    let mut scatter_blake3s = HashMap::new();
    let mut exception_states = HashMap::new();
    let mut tasks = HashMap::new();
    let entries = toc.embedded();

    // Scatter is structurally MAIN-only and discovered exactly once. All
    // later consumers use this materialized result rather than rediscovering
    // from bytes or inferring currentness from a path.
    if let Some(entry) = entries.iter().copied().find(|entry| entry.name == "MAIN") {
        let label = entry.label();
        let start = entry.offset as usize;
        let end = start + entry.size as usize;
        let image = &data[start..end];
        let scatter_plan = discover_scatter(image, entry.load_addr).map_err(Error::BadScatter)?;
        match scatter_plan {
            Some(plan) => {
                let materialized = scatter::materialize(&plan, image, &label, out)?;
                tracing::info!(
                    "scatter: {label} runtime load map -> {}",
                    materialized.relative_path
                );
                scatter_states.insert(label.clone(), RuntimeScatterState::Present);
                scatter_paths.insert(label.clone(), materialized.relative_path.clone());
                scatter_blake3s.insert(label, parse_blake3(&materialized.blake3)?);
            }
            None => {
                scatter::clear_materialized(out, &label)?;
                tracing::info!("scatter: {label} has no load-map candidate; keeping raw mapping");
                scatter_states.insert(label, RuntimeScatterState::Absent);
            }
        }
    }

    // Build every runtime view once. Exception discovery and MAIN PAL share
    // these exact views, including the one current scatter artifact above.
    let mut runtimes = Vec::with_capacity(entries.len());
    for entry in entries {
        let label = entry.label();
        let start = entry.offset as usize;
        let end = start + entry.size as usize;
        let image = data.get(start..end).ok_or_else(|| Error::SizeMismatch {
            name: label.clone(),
            expected: entry.size as u64,
            actual: data.len().saturating_sub(start) as u64,
        })?;
        let runtime = RuntimeImage::from_artifact(
            image,
            entry.load_addr,
            out,
            scatter_paths
                .get(&label)
                .map(|path| out.join(path))
                .as_deref(),
        )?;
        runtimes.push((entry, label, image, runtime));
    }

    // Architectural exception roots are image-generic. A later image filter
    // or opaque classification cannot suppress this generation-time proof.
    for (entry, label, image, runtime) in &runtimes {
        let context = ExceptionArtifactContext {
            label,
            toc_name: &entry.name,
            image_blake3: *blake3::hash(image).as_bytes(),
            scatter_load_map_blake3: scatter_blake3s.get(label).copied(),
        };
        match discover_exception_roots(runtime, label, &entry.name)? {
            Some(plan) => {
                let materialized = materialize_exception_roots(&plan, context, out)?;
                tracing::info!(
                    "exception roots: {label} -> {} ({})",
                    materialized.relative_path,
                    materialized.identity
                );
                exception_states
                    .insert(label.clone(), RuntimeExceptionState::Present(materialized));
            }
            None => {
                clear_exception_roots(out, label)?;
                tracing::info!("exception roots: {label} has no vector-table candidate");
                exception_states.insert(label.clone(), RuntimeExceptionState::Absent);
            }
        }
    }

    // PAL remains MAIN-only and consumes the same runtime object exception
    // discovery just used; there is no path-based scatter rediscovery.
    if let Some((_, label, image, runtime)) = runtimes
        .iter()
        .find(|(entry, _, _, _)| entry.name == "MAIN")
    {
        let context = TaskArtifactContext {
            label,
            image_blake3: *blake3::hash(image).as_bytes(),
            scatter_load_map_blake3: scatter_blake3s.get(label).copied(),
        };
        match discover_tasks(runtime, label)? {
            Some(plan) => {
                let materialized = pal_tasks::materialize(&plan, context, out)?;
                tracing::info!(
                    "pal: {label} task map -> {} ({})",
                    materialized.relative_path,
                    materialized.identity
                );
                tasks.insert(label.clone(), RuntimeTaskState::Present(materialized));
            }
            None => {
                pal_tasks::clear_materialized(out, label)?;
                tracing::info!("pal: {label} has no task-table candidate; keeping raw analysis");
                tasks.insert(label.clone(), RuntimeTaskState::Absent);
            }
        }
    }
    Ok(RuntimeAnalysis {
        scatter_paths,
        scatter_states,
        exception_roots: exception_states,
        tasks,
    })
}

/// Build the Ghidra import kit (always) and, with `--run`, drive `analyzeHeadless` per
/// image — returning the structured per-image outcomes plus the `ghidra_load.json` path.
/// Unlike [`run`], this never errors on a per-image analysis failure: every partition is
/// attempted and recorded, so an orchestrator (e.g. `decompose`) decides what a failure means.
/// Analyzer discovery occurs once before any modem or output work.
pub fn run_report(modem_bin: &Path, opts: &Opts, out: &Path) -> Result<DecompileReport> {
    run_report_with_discovery(
        modem_bin,
        opts,
        out,
        crate::thumb_analysis::discover_radare2,
        crate::thumb_analysis::discover_rizin,
    )
}

fn run_report_with_discovery(
    modem_bin: &Path,
    opts: &Opts,
    out: &Path,
    discover_radare2: impl FnOnce() -> Result<crate::thumb_analysis::ProducerIdentity>,
    discover_rizin: impl FnOnce() -> Result<crate::thumb_analysis::ProducerIdentity>,
) -> Result<DecompileReport> {
    if !opts.run {
        let _rizin = discover_configured_rizin(opts.rizin_fallback, discover_rizin)?;
        return run_report_impl(
            modem_bin,
            opts,
            out,
            None,
            crate::thumb_analysis::run_thumb_analysis,
        );
    }

    // radare2 is the required dense-Thumb primary, so its discovery failure is
    // a hard preflight: deferring it would probe Rizin, parse the modem, create
    // the output tree, and spend a full Ghidra run before failing — and could
    // even succeed for an image with no dense Thumb region.
    let radare2 = discover_radare2()?;
    let rizin = discover_configured_rizin(opts.rizin_fallback, discover_rizin)?;
    let thumb_tools = crate::thumb_analysis::ThumbTools { radare2, rizin };
    run_report_with_thumb_tools(modem_bin, opts, out, &thumb_tools)
}

/// Run with identities already retained by an orchestrator's preflight. This path performs no
/// analyzer discovery, ensuring analysis and outer reporting observe the same tool identities.
pub(crate) fn run_report_with_thumb_tools(
    modem_bin: &Path,
    opts: &Opts,
    out: &Path,
    thumb_tools: &crate::thumb_analysis::ThumbTools,
) -> Result<DecompileReport> {
    run_report_with_thumb_tools_and_analyzer(
        modem_bin,
        opts,
        out,
        thumb_tools,
        crate::thumb_analysis::run_thumb_analysis,
    )
}

fn run_report_with_thumb_tools_and_analyzer(
    modem_bin: &Path,
    opts: &Opts,
    out: &Path,
    thumb_tools: &crate::thumb_analysis::ThumbTools,
    analyze_thumb: impl FnMut(
        &crate::thumb_analysis::ThumbTools,
        &[u8],
        u32,
        &[(u32, u32)],
        &Path,
    ) -> Result<crate::thumb_analysis::ThumbAnalysisSummary>,
) -> Result<DecompileReport> {
    run_report_impl(modem_bin, opts, out, Some(thumb_tools), analyze_thumb)
}

fn run_report_impl(
    modem_bin: &Path,
    opts: &Opts,
    out: &Path,
    thumb_tools: Option<&crate::thumb_analysis::ThumbTools>,
    mut analyze_thumb: impl FnMut(
        &crate::thumb_analysis::ThumbTools,
        &[u8],
        u32,
        &[(u32, u32)],
        &Path,
    ) -> Result<crate::thumb_analysis::ThumbAnalysisSummary>,
) -> Result<DecompileReport> {
    let data = std::fs::read(modem_bin)?;
    let toc = Toc::parse(&data)?;
    std::fs::create_dir_all(out)?;

    // 1. per-image slices -> out/images/NN_NAME (validates ranges; CRC advisory only)
    toc.split_to_dir(&data, &out.join("images"), false)?;

    let runtime_analysis = generate_runtime_analysis(&toc, &data, out)?;

    // 2. embedded Java scripts -> out/scripts/{ApplyScatterLoad,
    //    ApplyExceptionRoots,ApplyPalTasks,PmeScriptSupport,
    //    ExceptionRootsSupport,PalTasksSupport,TameAnalysis,ApplyThumbNames,
    //    ApplySymbols,ApplyGlobals,ApplyGlobalTypes,ExportDecomp}.java
    //    (TameAnalysis pre-script tames Ghidra's auto-analysis; ExportDecomp post-script
    //    writes the decompiled C / disasm listing / function inventory; ApplyThumbNames,
    //    ApplySymbols, ApplyGlobals, and ApplyGlobalTypes are staged for pass-2 application;
    //    ApplyExceptionRoots and ApplyPalTasks transactionally seed their
    //    functions before analysis; PmeScriptSupport owns generic script
    //    utilities, while each domain support owns its strict schema - no
    //    script may grow a second parser.)
    let scripts = out.join("scripts");
    std::fs::create_dir_all(&scripts)?;
    std::fs::write(
        scripts.join("ApplyScatterLoad.java"),
        APPLY_SCATTER_LOAD_JAVA,
    )?;
    std::fs::write(scripts.join("ApplyPalTasks.java"), APPLY_PAL_TASKS_JAVA)?;
    std::fs::write(
        scripts.join("ApplyExceptionRoots.java"),
        APPLY_EXCEPTION_ROOTS_JAVA,
    )?;
    std::fs::write(
        scripts.join("PmeScriptSupport.java"),
        PME_SCRIPT_SUPPORT_JAVA,
    )?;
    std::fs::write(scripts.join("PalTasksSupport.java"), PAL_TASKS_SUPPORT_JAVA)?;
    std::fs::write(
        scripts.join("ExceptionRootsSupport.java"),
        EXCEPTION_ROOTS_SUPPORT_JAVA,
    )?;
    std::fs::write(scripts.join("TameAnalysis.java"), TAME_ANALYSIS_JAVA)?;
    std::fs::write(scripts.join("ExportDecomp.java"), EXPORT_DECOMP_JAVA)?;
    std::fs::write(scripts.join("ApplySymbols.java"), APPLY_SYMBOLS_JAVA)?;
    std::fs::write(scripts.join("ApplyThumbNames.java"), APPLY_THUMB_NAMES_JAVA)?;
    std::fs::write(scripts.join("ApplyGlobals.java"), APPLY_GLOBALS_JAVA)?;
    std::fs::write(
        scripts.join("ApplyGlobalTypes.java"),
        APPLY_GLOBAL_TYPES_JAVA,
    )?;

    // 3. machine-readable load spec -> out/ghidra_load.json
    let source_name = modem_bin
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("modem.bin");
    let mut spec = build_load_spec(&toc, &data, source_name, &opts.processor)?;
    for image in &mut spec.images {
        image.runtime_load_map = runtime_analysis.scatter_paths.get(&image.name).cloned();
        image.exception_root_map = match runtime_analysis.exception_roots.get(&image.name) {
            Some(RuntimeExceptionState::Present(map)) => Some(map.relative_path.clone()),
            _ => None,
        };
        image.pal_task_map = match runtime_analysis.tasks.get(&image.name) {
            Some(RuntimeTaskState::Present(map)) => Some(map.relative_path.clone()),
            _ => None,
        };
    }
    let spec_path = out.join("ghidra_load.json");
    std::fs::write(
        &spec_path,
        serde_json::to_string_pretty(&spec).map_err(|e| Error::Serialize(e.to_string()))?,
    )?;

    // 4. turnkey shell script -> out/run_ghidra.sh
    write_run_script(
        out,
        &toc,
        &opts.processor,
        &runtime_analysis.scatter_paths,
        &runtime_analysis.exception_roots,
        &runtime_analysis.tasks,
    )?;

    // 5. optional: drive Ghidra headless and the configured dense-Thumb analyzers per image
    let mut image_results: Vec<ImageResult> = Vec::new();
    let mut current_exports = BTreeSet::new();
    if opts.run {
        let install = find_ghidra(opts)?;
        let java_home =
            resolve_java_home(std::env::var_os("JAVA_HOME"), install.ghidra_run.as_deref());
        // analyzeHeadless needs the project dir to exist; use an absolute (canonical) root so
        // the spawned invocation is cwd-independent (the generated run_ghidra.sh uses $HERE).
        let root = std::fs::canonicalize(out)?;
        std::fs::create_dir_all(root.join("ghidra_project"))?;
        // One RAII Java/XDG state home for the whole run: unique,
        // space-free, and removed when the run ends.
        let state_home = GhidraStateHome::new()?;
        state_home.create_subdirs()?;
        let root_str = root.to_string_lossy().into_owned();
        let want = opts.image.as_deref();
        // Analyze every selected image, recording each outcome rather than aborting on the
        // first failure — so a heavy or unanalyzable partition (the ~87 MB MAIN, or an
        // encrypted one) can't sink the rest of a full run.
        struct RunResult {
            label: String,
            outcome: ImageOutcome,
            /// Battery verdict for the image bytes ("opaque"/"not_opaque"),
            /// measured before any Ghidra work regardless of `no_skip_opaque`
            /// — so report.json's `classification` agrees with manifest.json's
            /// `battery.label` even on escape-hatch runs.
            classification: &'static str,
            thumb_functions: Option<usize>,
            thumb_summary: Option<crate::thumb_analysis::ThumbAnalysisSummary>,
            terminal_inventory: Option<TerminalInventorySummary>,
            image_start: u32,
            image_len: u32,
            thumb_error: Option<String>,
            terminal_error: Option<String>,
            tighten_error: Option<String>,
            // When the tighten-watch kills the run, we re-spawn as datamark
            // and there is no `thumb_enrich` to run later; mark the count
            // definitively zero so downstream stages don't enqueue
            // work against an empty decompiled.c.
            thumb_decompiled: Option<usize>,
            exception_state: RuntimeExceptionState,
            exception_roots_applied: Option<AppliedExceptionRoots>,
            exception_error: Option<String>,
            /// The current-run `ApplyPalTasks` summary when a present PAL
            /// map was applied by this run's import.
            pal_applied: Option<AppliedPalTasks>,
        }
        let mut results: Vec<RunResult> = Vec::new();
        for e in toc.embedded() {
            let label = e.label();
            if !image_matches(want, &label, &e.name) {
                continue;
            }
            let exception_state = runtime_analysis
                .exception_roots
                .get(&label)
                .cloned()
                .unwrap_or(RuntimeExceptionState::Unmanaged);
            let start = (e.offset as usize).min(data.len());
            let end = (e.offset as usize + e.size as usize).min(data.len());
            let img = &data[start..end];
            // Battery verdict for the image bytes — computed for EVERY selected
            // image, before any Ghidra work and regardless of `no_skip_opaque`,
            // so the per-image classification carried into report.json is the
            // same measurement manifest.json's `battery.label` records.
            let opaque_stats = opaque_skip(img);
            let classification: &'static str = if opaque_stats.is_some() {
                "opaque"
            } else {
                "not_opaque"
            };
            let mode = mode_from_opts(opts);
            let mut export_attempt = match GhidraExportAttempt::begin(&root, &label) {
                Ok(attempt) => attempt,
                Err(error) => {
                    tracing::warn!(
                        "ghidra: {label} failed to invalidate prior export before {mode} or opaque skip: {error}"
                    );
                    results.push(RunResult {
                        label,
                        outcome: ImageOutcome::Failed(-1),
                        classification,
                        thumb_functions: None,
                        thumb_summary: None,
                        terminal_inventory: None,
                        image_start: e.load_addr,
                        image_len: e.size,
                        thumb_error: None,
                        terminal_error: None,
                        tighten_error: None,
                        thumb_decompiled: None,
                        exception_state,
                        exception_roots_applied: None,
                        exception_error: None,
                        pal_applied: None,
                    });
                    continue;
                }
            };
            // Opaque-image gate, BEFORE any Ghidra project work: a unanimous
            // battery verdict means there is no code to recover, so bypass the
            // entire per-image Ghidra + Thumb-analysis block (no import, no tighten
            // watch, no export, no Thumb analysis) but still record a
            // RunResult — `--image 01_PSP` stays a successful non-empty run.
            // `--no-skip-opaque` restores run-everything behavior.
            if !opts.no_skip_opaque
                && let Some(stats) = opaque_stats
            {
                tracing::warn!(
                    "{label}: unanimously opaque battery — skipping Ghidra (H={:.4}, χ²/df={:.4}, SCC={:.4}, wmin={:.4}, frac={:.4}); --no-skip-opaque forces a run",
                    stats.entropy_bits,
                    stats.chi2_per_df,
                    stats.serial_correlation,
                    stats.window_min,
                    stats.frac_windows_high
                );
                results.push(RunResult {
                    label,
                    outcome: ImageOutcome::SkippedOpaque(stats),
                    classification,
                    thumb_functions: None,
                    thumb_summary: None,
                    terminal_inventory: None,
                    image_start: e.load_addr,
                    image_len: e.size,
                    thumb_error: None,
                    terminal_error: None,
                    tighten_error: None,
                    thumb_decompiled: None,
                    exception_state,
                    exception_roots_applied: None,
                    exception_error: None,
                    pal_applied: None,
                });
                continue;
            }
            let regions = thumb_regions(img, e.load_addr);
            tracing::info!(
                "ghidra: analyzing {label} (base 0x{:08x}, mode={mode})",
                e.load_addr
            );
            // Phase-1 datamark framing only — in tighten mode the regions are NOT
            // data-marked (Ghidra is allowed to try), so the "marked as data"
            // message would be misleading.
            if mode == "datamark" && !regions.is_empty() {
                tracing::info!(
                    "ghidra: {label} has {} dense Thumb-2 region(s) — marked as data (Thumb analysis handles them)",
                    regions.len()
                );
            }
            let exception_plan = match &exception_state {
                RuntimeExceptionState::Present(map) => Some(ExceptionRootScriptPlan {
                    manifest: &map.relative_path,
                    identity: &map.identity,
                }),
                RuntimeExceptionState::Unmanaged | RuntimeExceptionState::Absent => None,
            };
            let exception_identity = exception_plan
                .map(|plan| plan.identity.to_string())
                .unwrap_or_else(|| "none".to_string());
            let pal_plan = match runtime_analysis.tasks.get(&label) {
                Some(RuntimeTaskState::Present(map)) => Some(PalScriptPlan {
                    manifest: &map.relative_path,
                    identity: &map.identity,
                }),
                _ => None,
            };
            let pal_identity = pal_plan
                .map(|plan| plan.identity.to_string())
                .unwrap_or_else(|| "none".to_string());
            let args = headless_args(
                &root_str,
                &label,
                &opts.processor,
                e.load_addr,
                runtime_analysis
                    .scatter_paths
                    .get(&label)
                    .map(String::as_str),
                exception_plan,
                pal_plan,
                &regions,
                mode,
            );
            // Surface B: in tighten mode, spawn with piped stdout so we can
            // count `ClearFlowAndRepairCmd` log lines and kill the runaway
            // overlap-repair loop before it sinks the whole run. On kill we
            // fall back to `datamark` (Phase-1 behavior). In datamark mode
            // there is no watch — stdout is still captured so the strict
            // `ApplyPalTasks` summary of this run can be parsed.
            let mut tighten_error: Option<String> = None;
            // When the tighten-watch kills the run, we re-spawn as datamark
            // and there is no `thumb_enrich` to run later; mark the count
            // definitively zero so downstream stages don't enqueue
            // work against an empty decompiled.c.
            let mut thumb_decompiled_override: Option<usize> = None;
            let mut captured_stdout = String::new();
            let status: Option<std::process::ExitStatus> = if mode == "tighten" {
                let mut cmd =
                    headless_command(&install.headless, &args, &state_home, java_home.as_deref());
                cmd.stdout(std::process::Stdio::piped());
                // Spawn `analyzeHeadless` in its own process group so the
                // Surface B watch can kill the whole tree (bash launcher +
                // Java grandchild) with one `killpg`. Without this the JVM
                // is orphaned to init by `child.kill()`, keeps holding the
                // Ghidra project lock, and the datamark retry fails with
                // LockException (the bug this path fixes).
                spawn_in_own_process_group(&mut cmd);
                let started = std::time::Instant::now();
                let mut child = cmd.spawn()?;
                let child_pid = child.id();
                let stdout = child.stdout.take().expect("piped stdout");
                let reader = std::io::BufReader::new(stdout);
                let budget = TightenBudget::default();
                // `decompile --run` has no prior baseline (radare2 ran first
                // in `decompose`, not here). Extrapolate from this image's
                // dense-Thumb byte count (prior measurement: ~40 s/MiB on Ghidra
                // 12.1.2 in Tighten mode; floor 60 s for tiny regions). With
                // the default 4× multiplier: 42 MiB dense Thumb (real 02_MAIN)
                // → baseline 1 680 s, budget ~112 min — generous enough to
                // not fire prematurely on production images, tight enough to
                // catch a true overlap-repair spin (which otherwise runs for
                // hours). The test-only
                // `--tighten-wall-clock-budget-sec` override bypasses this.
                let dense_thumb_bytes: usize = regions.iter().map(|(_, len)| *len as usize).sum();
                let baseline = tighten_baseline_for_dense_thumb_bytes(dense_thumb_bytes);
                let mut killed: Option<KillReason> = None;
                let mut repair_lines = 0usize;
                // Retention ceiling failure for the captured stdout: set
                // inside the drain loop, acted on (kill + fail closed)
                // once the loop exits.
                let mut stdout_overflow: Option<std::io::Error> = None;
                // Surface B must also fire on a *silent* spin (GC storm, deadlock,
                // blocked-on-IO) where Ghidra stops emitting stdout — `BufRead::lines`
                // blocks on the read and the wall-clock budget would otherwise never
                // be checked. Drain on a thread, poll via `recv_timeout`, and check
                // the budget on every poll so a silent hang is still killed.
                // The drain thread is fire-and-forget: it exits naturally when the
                // child's stdout closes (either the child exited normally after the
                // loop, or it gets killed in the Some-branch below). Detaching is
                // safe — its only job is to keep the pipe drained so the child
                // never blocks on a full stdout buffer.
                let (tx, rx) = std::sync::mpsc::channel::<std::io::Result<String>>();
                let _drain = std::thread::spawn(move || {
                    use std::io::BufRead;
                    for line in reader.lines() {
                        if tx.send(line).is_err() {
                            break; // main loop dropped rx — stop draining
                        }
                    }
                });
                loop {
                    match rx.recv_timeout(std::time::Duration::from_millis(500)) {
                        Ok(Ok(line)) => {
                            if let Err(error) = push_captured_line(&mut captured_stdout, &line) {
                                stdout_overflow = Some(error);
                                break;
                            }
                            // Match case-insensitively on the symbols Ghidra emits
                            // while looping on overlapping-function repair. The
                            // exact log shape is an implementation detail, so the
                            // match is deliberately broad: any one of these
                            // substrings counts.
                            let lower = line.to_ascii_lowercase();
                            if lower.contains("clearflowandrepaircmd")
                                || lower.contains("repair")
                                || lower.contains("overlap")
                            {
                                repair_lines = repair_lines.saturating_add(1);
                            }
                        }
                        Ok(Err(_)) => break, // reader errored; wait() reports the real exit
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                            // No new line in 500 ms — keep checking the wall-clock
                            // budget so a silent spin is caught.
                        }
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break, // reader EOF
                    }
                    if let Some(reason) = should_kill_tighten(
                        started.elapsed(),
                        repair_lines,
                        &budget,
                        baseline,
                        opts.tighten_wall_clock_budget_override,
                    ) {
                        killed = Some(reason);
                        break;
                    }
                }
                // (Drain thread exits when the child's stdout closes below.)
                if let Some(error) = stdout_overflow {
                    // Fail closed on runaway stdout: tear down the whole
                    // tree so no JVM survives holding the project lock.
                    let _ = child.kill();
                    kill_process_group(child_pid);
                    let _ = child.wait();
                    return Err(Error::Io(error));
                }
                match killed {
                    Some(reason) => {
                        tracing::warn!(
                            "ghidra: {label} tighten run killed ({reason}); re-spawning as datamark"
                        );
                        // Best-effort: signal the immediate child, then the
                        // whole process group (the bash launcher SIGKILLed by
                        // `child.kill()` only reaps itself — the Java grandchild
                        // is in the same group and would otherwise survive,
                        // holding the project lock). Then reap the immediate
                        // child so we don't leak a zombie into the re-spawn.
                        let _ = child.kill();
                        kill_process_group(child_pid);
                        let _ = child.wait();
                        // `killpg(SIGKILL)` + `child.wait()` reap the JVM at the
                        // kernel level, which releases Ghidra's OS `FileChannel`
                        // project lock immediately — the datamark retry's project
                        // open will succeed without a userspace wait. (A prior
                        // spin-wait on the sentinel lock file was removed: it
                        // polled `Path::exists()`, which kept returning `true`
                        // because no JVM shutdown hook runs to delete the
                        // sentinel after SIGKILL, so it always hit its 10 s cap.)
                        tighten_error =
                            Some(format!("tighten killed: {reason}; retrying as datamark"));
                        thumb_decompiled_override = Some(0);
                        let datamark_args = headless_args(
                            &root_str,
                            &label,
                            &opts.processor,
                            e.load_addr,
                            runtime_analysis
                                .scatter_paths
                                .get(&label)
                                .map(String::as_str),
                            exception_plan,
                            pal_plan,
                            &regions,
                            "datamark",
                        );
                        let retry_run = match export_attempt.invalidate() {
                            Ok(()) => Some(headless_stdout_status(headless_command(
                                &install.headless,
                                &datamark_args,
                                &state_home,
                                java_home.as_deref(),
                            ))?),
                            Err(error) => {
                                tracing::warn!(
                                    "ghidra: {label} failed to invalidate tighten output before datamark retry: {error}"
                                );
                                None
                            }
                        };
                        if let Some((retry_status, _)) = &retry_run {
                            if retry_status.success() {
                                tracing::info!(
                                    "ghidra: {label} datamark retry succeeded after tighten kill"
                                );
                            } else {
                                tracing::warn!(
                                    "ghidra: {label} datamark retry failed (exit {}) after tighten kill",
                                    retry_status.code().unwrap_or(-1)
                                );
                            }
                        }
                        match retry_run {
                            Some((status, stdout)) => {
                                captured_stdout = stdout;
                                Some(status)
                            }
                            None => None,
                        }
                    }
                    None => Some(child.wait()?),
                }
            } else {
                let (status, stdout) = headless_stdout_status(headless_command(
                    &install.headless,
                    &args,
                    &state_home,
                    java_home.as_deref(),
                ))?;
                captured_stdout = stdout;
                Some(status)
            };
            let mut exception_roots_applied: Option<AppliedExceptionRoots> = None;
            let mut exception_error = None;
            let mut pal_applied: Option<AppliedPalTasks> = None;
            let mut terminal_error = None;
            let mut outcome = match status.as_ref() {
                Some(status) if status.success() => {
                    // Currentness is explicit and conserving: exact v4 marker,
                    // one strict exception summary when present, then the PAL
                    // summary under its independent present-state rule.
                    if let Err(reason) =
                        export_attempt.validate_current(&exception_identity, &pal_identity, "none")
                    {
                        tracing::warn!(
                            "ghidra: {label} current export is not this run's: {reason}"
                        );
                        if matches!(exception_state, RuntimeExceptionState::Present(_)) {
                            exception_error = Some(reason.clone());
                        }
                        terminal_error = Some(reason);
                        ImageOutcome::TerminalInvalid
                    } else {
                        let expected_exception_roots = match &exception_state {
                            RuntimeExceptionState::Present(map) => Some(map),
                            RuntimeExceptionState::Unmanaged | RuntimeExceptionState::Absent => {
                                None
                            }
                        };
                        let coordinated = coordinate_application_summaries(
                            &captured_stdout,
                            &label,
                            expected_exception_roots,
                            pal_plan,
                        );
                        exception_roots_applied = coordinated.exception_roots_applied;
                        exception_error = coordinated.exception_error;
                        pal_applied = coordinated.pal_applied;
                        terminal_error = coordinated.terminal_error;
                        if let Some(reason) = &terminal_error {
                            tracing::warn!(
                                "ghidra: {label} current export is not this run's: {reason}"
                            );
                            ImageOutcome::TerminalInvalid
                        } else {
                            ImageOutcome::Analyzed(count_functions(&export_attempt.directory))
                        }
                    }
                }
                Some(status) => {
                    let code = status.code().unwrap_or(-1);
                    tracing::warn!("ghidra: {label} failed (analyzeHeadless exit {code})");
                    ImageOutcome::Failed(code)
                }
                None => ImageOutcome::Failed(-1),
            };
            // After the Ghidra attempt, analyze dense Thumb through the configured
            // radare2-primary route regardless of tighten/datamark mode.
            let (thumb_summary, mut thumb_error) = if regions.is_empty() {
                (None, None)
            } else if let Some(thumb_tools) = thumb_tools {
                match analyze_thumb(
                    thumb_tools,
                    img,
                    e.load_addr,
                    &regions,
                    &root.join("export").join(&label),
                ) {
                    Ok(summary) => {
                        tracing::info!(
                            "Thumb: {label} regions requested={} succeeded={} failed={} radare2_runs={} rizin_runs={} raw={} substantial={} accepted={} quarantined={}",
                            summary.regions_requested,
                            summary.regions_succeeded,
                            summary.regions_failed,
                            summary.radare2_runs,
                            summary.rizin_runs,
                            summary.raw,
                            summary.substantial,
                            summary.accepted,
                            summary.quarantined,
                        );
                        (Some(summary), None)
                    }
                    Err(err) => {
                        tracing::warn!("Thumb: {label} failed: {err}");
                        (None, Some(err.to_string()))
                    }
                }
            } else {
                // Only the generation-only route reaches this: `--run` fails
                // preflight when radare2 is missing, so no analyzed image can
                // ever be published without its required primary.
                let err = format!(
                    "{} Thumb region(s) left unanalyzed because no analyzer was configured",
                    regions.len(),
                );
                tracing::warn!("{label}: {err}");
                (None, Some(err))
            };
            let thumb_functions = thumb_summary.as_ref().map(|summary| summary.substantial);
            let terminal_inventory = if matches!(outcome, ImageOutcome::Analyzed(_)) {
                let export = root.join("export").join(&label);
                // `root` is already canonical; re-canonicalizing here (with a
                // silent fallback) could only mask an I/O failure as a later,
                // misleading digest-mismatch rejection.
                let runtime = RuntimeImage::from_artifact(
                    img,
                    e.load_addr,
                    &root,
                    runtime_analysis
                        .scatter_paths
                        .get(&label)
                        .map(|path| root.join(path))
                        .as_deref(),
                );
                let validation = runtime
                    .map_err(TerminalValidationFailure::ghidra)
                    .and_then(|runtime| {
                        validate_terminal_inventory_pair_staged(
                            &export.join("functions.json"),
                            &export.join("thumb_functions.json"),
                            &runtime,
                            thumb_functions,
                            None,
                            None,
                        )
                    })
                    .and_then(|summary| {
                        let Some(expected) = &thumb_summary else {
                            return Ok(summary);
                        };
                        let expected_tools = thumb_tools.ok_or_else(|| {
                            TerminalValidationFailure::thumb(Error::Serialize(
                                "current Thumb analysis lost its injected tool identities".into(),
                            ))
                        })?;
                        validate_thumb_analysis_currentness(
                            &summary,
                            expected_tools,
                            &regions,
                            expected,
                        )
                        .map_err(TerminalValidationFailure::thumb)?;
                        Ok(summary)
                    });
                match validation {
                    Ok(summary) => {
                        outcome = ImageOutcome::Analyzed(summary.ghidra.raw);
                        Some(summary)
                    }
                    Err(failure) => {
                        let reason = failure.error.to_string();
                        tracing::warn!(
                            "terminal execution inventory for {label} failed validation: {reason}"
                        );
                        // Ghidra ran to completion, so this is not a Ghidra
                        // process failure. A Thumb-stage rejection also means
                        // no current sidecar; keep any root-cause `thumb_error`
                        // the analysis stage already recorded.
                        if failure.thumb {
                            thumb_error.get_or_insert_with(|| reason.clone());
                        }
                        terminal_error = Some(reason);
                        outcome = ImageOutcome::TerminalInvalid;
                        None
                    }
                }
            } else {
                None
            };
            if terminal_inventory.is_some() && matches!(outcome, ImageOutcome::Analyzed(_)) {
                export_attempt.mark_current();
            }
            if matches!(outcome, ImageOutcome::Analyzed(0)) {
                tracing::warn!(
                    "ghidra: {label} yielded 0 functions — no decompilable code (e.g. a compressed/encrypted partition)"
                );
            }
            results.push(RunResult {
                label,
                outcome,
                classification,
                thumb_functions,
                thumb_summary,
                terminal_inventory,
                image_start: e.load_addr,
                image_len: e.size,
                thumb_error,
                terminal_error,
                tighten_error,
                thumb_decompiled: thumb_decompiled_override,
                exception_state,
                exception_roots_applied,
                exception_error,
                pal_applied,
            });
        }
        if results.is_empty() {
            return Err(Error::NotFound(match &opts.image {
                Some(img) => format!("no image matched --image {img}"),
                None => "no embedded images found in TOC".to_string(),
            }));
        }
        let skipped_opaque = results
            .iter()
            .filter(|r| matches!(r.outcome, ImageOutcome::SkippedOpaque(_)))
            .count();
        println!(
            "ghidra: analyzed {} image(s), skipped {skipped_opaque} opaque (--no-skip-opaque to force) -> {}",
            results.len() - skipped_opaque,
            out.join("export").display()
        );
        for r in &results {
            let t = if let Some(n) = r.thumb_functions {
                format!("  + {n} Thumb fn(s)")
            } else if let Some(err) = &r.thumb_error {
                format!("  + Thumb FAILED [{err}]")
            } else {
                String::new()
            };
            let k = if let Some(err) = &r.tighten_error {
                format!("  + tighten KILLED [{err}]")
            } else {
                String::new()
            };
            match r.outcome {
                ImageOutcome::Analyzed(n) => {
                    println!("  {:<11} {} A32 function(s){t}{k}", r.label, n)
                }
                ImageOutcome::Failed(code) => {
                    println!("  {:<11} FAILED (exit {code}){t}{k}", r.label)
                }
                ImageOutcome::TerminalInvalid => {
                    let reason = r.terminal_error.as_deref().unwrap_or("unknown reason");
                    println!("  {:<11} FAILED (terminal: {reason}){t}{k}", r.label)
                }
                ImageOutcome::SkippedOpaque(_) => {
                    println!(
                        "  {:<11} SKIPPED (unanimously opaque battery; --no-skip-opaque forces a run)",
                        r.label
                    )
                }
            }
        }
        image_results = results
            .into_iter()
            .map(|r| {
                if r.terminal_inventory.is_some() && matches!(&r.outcome, ImageOutcome::Analyzed(_))
                {
                    current_exports.insert(r.label.clone());
                }
                ImageResult {
                    label: r.label,
                    outcome: r.outcome,
                    classification: Some(r.classification),
                    thumb_functions: r.thumb_functions,
                    thumb_regions_requested: r
                        .thumb_summary
                        .map(|summary| summary.regions_requested),
                    thumb_regions_succeeded: r
                        .thumb_summary
                        .map(|summary| summary.regions_succeeded),
                    thumb_regions_failed: r.thumb_summary.map(|summary| summary.regions_failed),
                    thumb_radare2_runs: r.thumb_summary.map(|summary| summary.radare2_runs),
                    thumb_rizin_runs: r.thumb_summary.map(|summary| summary.rizin_runs),
                    ghidra_execution_accepted: r
                        .terminal_inventory
                        .as_ref()
                        .map(|inventory| inventory.ghidra.accepted),
                    ghidra_execution_quarantined: r
                        .terminal_inventory
                        .as_ref()
                        .map(|inventory| inventory.ghidra.quarantined),
                    thumb_execution_accepted: r
                        .terminal_inventory
                        .as_ref()
                        .and_then(|inventory| inventory.thumb.map(|thumb| thumb.accepted)),
                    thumb_execution_quarantined: r
                        .terminal_inventory
                        .as_ref()
                        .and_then(|inventory| inventory.thumb.map(|thumb| thumb.quarantined)),
                    image_start: r.image_start,
                    image_len: r.image_len,
                    thumb_error: r.thumb_error,
                    terminal_error: r.terminal_error,
                    pass2_applied: None,
                    pass2_creation_plan: None,
                    pass2_thumb_names: None,
                    pass2_error: None,
                    thumb_decompiled: r.thumb_decompiled,
                    thumb_tighten_error: r.tighten_error,
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
                    exception_state: r.exception_state,
                    exception_roots_applied: r.exception_roots_applied,
                    exception_error: r.exception_error,
                    pal_applied: r.pal_applied,
                }
            })
            .collect();
    }

    println!("decompile kit -> {}", out.display());
    for img in &spec.images {
        println!(
            "  {:<11} base {}  size {}",
            img.name, img.base_addr, img.size
        );
    }
    if !opts.run {
        println!("{}", generation_only_hint(out));
    }
    Ok(DecompileReport {
        images: image_results,
        spec_path,
        current_exports,
        runtime_scatter: runtime_analysis.scatter_states,
        runtime_exception_roots: runtime_analysis.exception_roots,
        runtime_tasks: runtime_analysis.tasks,
    })
}

/// Convert structured per-image outcomes into the standalone `decompile` failure,
/// after every selected image has had a chance to run.
fn report_failure(report: &DecompileReport) -> Option<Error> {
    for image in &report.images {
        if image.exception_state != report.runtime_exception_state(&image.label) {
            return Some(Error::DecomposeIncomplete(format!(
                "exception-root state drifted for {}",
                image.label
            )));
        }
    }
    // Only a real `analyzeHeadless` failure is a Ghidra failure.
    if let Some(code) = report.images.iter().find_map(|r| match r.outcome {
        ImageOutcome::Failed(c) => Some(c),
        ImageOutcome::Analyzed(_)
        | ImageOutcome::TerminalInvalid
        | ImageOutcome::SkippedOpaque(_) => None,
    }) {
        let failed: Vec<&str> = report
            .images
            .iter()
            .filter_map(|r| {
                matches!(r.outcome, ImageOutcome::Failed(_)).then_some(r.label.as_str())
            })
            .collect();
        return Some(Error::GhidraFailed {
            image: failed.join(", "),
            code,
        });
    }
    if let Some(reasons) = labelled_reasons(report, |image| image.exception_error.as_deref()) {
        return Some(Error::DecomposeIncomplete(format!(
            "exception-root application failed on {reasons}"
        )));
    }
    // Thumb-stage reasons come first: for a rejected export they are the root
    // cause, and the terminal reason is its consequence.
    if let Some(reasons) = labelled_reasons(report, |image| image.thumb_error.as_deref()) {
        return Some(Error::DecomposeIncomplete(format!(
            "Thumb analysis failed on {reasons}"
        )));
    }
    if let Some(reasons) = labelled_reasons(report, |image| image.terminal_error.as_deref()) {
        return Some(Error::DecomposeIncomplete(format!(
            "terminal inventory validation failed on {reasons}"
        )));
    }
    None
}

/// `"<label>: <reason>, …"` over every image carrying a reason, or `None`.
fn labelled_reasons(
    report: &DecompileReport,
    reason: impl Fn(&ImageResult) -> Option<&str>,
) -> Option<String> {
    let labelled: Vec<String> = report
        .images
        .iter()
        .filter_map(|image| reason(image).map(|reason| format!("{}: {reason}", image.label)))
        .collect();
    (!labelled.is_empty()).then(|| labelled.join(", "))
}

pub(crate) fn discover_configured_rizin(
    enabled: bool,
    discover: impl FnOnce() -> Result<crate::thumb_analysis::ProducerIdentity>,
) -> Result<Option<crate::thumb_analysis::ProducerIdentity>> {
    if enabled {
        discover().map(Some)
    } else {
        Ok(None)
    }
}

/// A canonical retained file (absolute path + the BLAKE3 the driver computed
/// over its exact bytes at preparation time).
#[derive(Debug, Clone)]
pub struct RetainedPass2File {
    absolute_path: PathBuf,
    blake3: String,
}

impl RetainedPass2File {
    pub fn prepare(path: &Path, what: &str) -> Result<Self> {
        let absolute_path = std::fs::canonicalize(path)?;
        if !absolute_path.is_file() {
            return Err(Error::DecomposeIncomplete(format!(
                "{what} is not a regular file: {}",
                absolute_path.display()
            )));
        }
        let blake3 = crate::manifest::blake3_file(&absolute_path)?;
        Ok(Self {
            absolute_path,
            blake3,
        })
    }

    pub fn path(&self) -> &Path {
        &self.absolute_path
    }

    pub fn blake3(&self) -> &str {
        &self.blake3
    }

    fn validate_for_spawn(&self, what: &str) -> Result<()> {
        if !self.absolute_path.is_absolute() || !self.absolute_path.is_file() {
            return Err(Error::DecomposeIncomplete(format!(
                "{what} is no longer an absolute regular file: {}",
                self.absolute_path.display()
            )));
        }
        let canonical = std::fs::canonicalize(&self.absolute_path)?;
        if canonical != self.absolute_path {
            return Err(Error::DecomposeIncomplete(format!(
                "{what} canonical identity changed: {} -> {}",
                self.absolute_path.display(),
                canonical.display()
            )));
        }
        let current = crate::manifest::blake3_file(&self.absolute_path)?;
        if current != self.blake3 {
            return Err(Error::DecomposeIncomplete(format!(
                "{what} contents changed after preparation: {}",
                self.absolute_path.display()
            )));
        }
        Ok(())
    }
}

/// The authenticated function-map input for pass 2: the strict v4 symbol map
/// and the retained pass-1 files it binds, plus the image identity the
/// twelve-argument `ApplySymbols` and ten-argument `ExportDecomp` contracts
/// consume. The PAL identity and its manifest paths live on
/// [`Pass2Input`] — a pass-2 run may carry PAL state without a function map.
/// The driver computes every expected hash from retained current inputs
/// before spawning pass 2.
#[derive(Debug, Clone)]
pub struct PreparedSymbolPass2Map {
    map: RetainedPass2File,
    functions: RetainedPass2File,
    image: RetainedPass2File,
    image_label: String,
    execution_count: usize,
    applied_decision_count: usize,
    creation_requests: Vec<crate::symbolicate::Pass2CreationRequest>,
}

impl PreparedSymbolPass2Map {
    pub fn new(
        map_path: &Path,
        functions_path: &Path,
        image_path: &Path,
        image_label: &str,
        execution_count: usize,
        applied_decision_count: usize,
        creation_requests: Vec<crate::symbolicate::Pass2CreationRequest>,
    ) -> Result<Self> {
        if applied_decision_count > execution_count {
            return Err(Error::DecomposeIncomplete(
                "pass-2 applicable decisions exceed the execution count".into(),
            ));
        }
        if applied_decision_count == 0 && creation_requests.is_empty() {
            return Err(Error::DecomposeIncomplete(
                "pass-2 function map has no applicable decisions or creations".into(),
            ));
        }
        let mut prior_entry = None;
        let mut names = BTreeSet::new();
        for request in &creation_requests {
            if prior_entry.is_some_and(|entry| request.entry <= entry) {
                return Err(Error::DecomposeIncomplete(
                    "pass-2 creation requests are not in unique entry order".into(),
                ));
            }
            prior_entry = Some(request.entry);
            if !names.insert(request.final_primary.as_str()) {
                return Err(Error::DecomposeIncomplete(
                    "pass-2 creation requests repeat a primary name".into(),
                ));
            }
            if !matches!(request.final_source.as_str(), "analysis" | "user_defined") {
                return Err(Error::DecomposeIncomplete(format!(
                    "pass-2 creation request has invalid source {:?}",
                    request.final_source
                )));
            }
        }
        Ok(Self {
            map: RetainedPass2File::prepare(map_path, "pass-2 symbol map")?,
            functions: RetainedPass2File::prepare(
                functions_path,
                "retained pass-1 functions.json",
            )?,
            image: RetainedPass2File::prepare(image_path, "raw image")?,
            image_label: image_label.to_string(),
            execution_count,
            applied_decision_count,
            creation_requests,
        })
    }

    pub fn path(&self) -> &Path {
        self.map.path()
    }

    pub fn map_blake3(&self) -> &str {
        self.map.blake3()
    }

    pub fn functions_blake3(&self) -> &str {
        self.functions.blake3()
    }

    pub fn image_blake3(&self) -> &str {
        self.image.blake3()
    }

    /// The image label this map was built for; the spawn boundary refuses to
    /// mix maps across labels.
    pub fn image_label(&self) -> &str {
        &self.image_label
    }

    /// The number of accepted Ghidra executions the map covers (also the
    /// decision count).
    pub fn execution_count(&self) -> usize {
        self.execution_count
    }

    pub fn applied_decision_count(&self) -> usize {
        self.applied_decision_count
    }

    pub fn creation_count(&self) -> usize {
        self.creation_requests.len()
    }

    pub(crate) fn creation_requests(&self) -> &[crate::symbolicate::Pass2CreationRequest] {
        &self.creation_requests
    }

    /// The exact `PixelModemExtractor.SymbolPass2` property value
    /// `ApplySymbols` sets on success:
    /// `v3:<symbol-map-blake3>:<pass1-functions-blake3>:<execution-count>`.
    pub fn pass2_property(&self) -> String {
        format!(
            "v3:{}:{}:{}",
            self.map.blake3(),
            self.functions.blake3(),
            self.execution_count
        )
    }

    fn validate_for_spawn(&self) -> Result<()> {
        self.map.validate_for_spawn("pass-2 symbol map")?;
        self.functions
            .validate_for_spawn("retained pass-1 functions.json")?;
        self.image.validate_for_spawn("raw image")?;
        Ok(())
    }
}

/// The simpler path/count map type consumed by `ApplyGlobals` and
/// `ApplyGlobalTypes`; the authenticated function-map contract above is
/// deliberately not forced onto those unrelated maps.
#[derive(Debug, Clone)]
pub struct PreparedPass2Map {
    absolute_path: PathBuf,
    count: NonZeroUsize,
}

impl PreparedPass2Map {
    pub fn new(path: &Path, count: NonZeroUsize) -> Result<Self> {
        let absolute_path = std::fs::canonicalize(path)?;
        if !absolute_path.is_file() {
            return Err(Error::DecomposeIncomplete(format!(
                "pass-2 map is not a regular file: {}",
                absolute_path.display()
            )));
        }
        Ok(Self {
            absolute_path,
            count,
        })
    }

    pub fn path(&self) -> &Path {
        &self.absolute_path
    }

    pub fn count(&self) -> usize {
        self.count.get()
    }

    fn validate_for_spawn(&self) -> Result<()> {
        if !self.absolute_path.is_absolute() || !self.absolute_path.is_file() {
            return Err(Error::DecomposeIncomplete(format!(
                "pass-2 map is no longer an absolute regular file: {}",
                self.absolute_path.display()
            )));
        }
        let canonical = std::fs::canonicalize(&self.absolute_path)?;
        if canonical != self.absolute_path {
            return Err(Error::DecomposeIncomplete(format!(
                "pass-2 map canonical identity changed: {} -> {}",
                self.absolute_path.display(),
                canonical.display()
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct Pass2Input {
    pub function_map: Option<PreparedSymbolPass2Map>,
    pub global_map: Option<PreparedPass2Map>,
    pub global_types_map: Option<PreparedPass2Map>,
    /// Explicit current exception-root state. Task 9 constructs this pair from
    /// the terminal validated artifact; pass 2 never probes for one.
    pub exception_identity: String,
    pub exception_manifest: Option<PathBuf>,
    /// The PAL identity the pass-2 scripts must agree on (`none` when the
    /// orchestrator drives no PAL state) plus the canonical task/scatter
    /// manifest paths when a PAL state is present.
    pub pal_identity: String,
    pub pal_manifest: Option<PathBuf>,
    pub scatter_manifest: Option<PathBuf>,
}

impl Pass2Input {
    fn has_maps(&self) -> bool {
        self.function_map.is_some() || self.global_map.is_some() || self.global_types_map.is_some()
    }

    fn pal_identity_or_none(&self) -> &str {
        if self.pal_identity.is_empty() {
            "none"
        } else {
            &self.pal_identity
        }
    }

    fn exception_args(&self) -> Result<(String, String)> {
        let identity = if self.exception_identity.is_empty() {
            "none"
        } else {
            self.exception_identity.as_str()
        };
        if identity == "none" {
            if self.exception_manifest.is_some() {
                return Err(Error::DecomposeIncomplete(
                    "pass-2 exception identity none carries a manifest".into(),
                ));
            }
            return Ok(("none".to_string(), "-".to_string()));
        }

        let parts = identity.split(':').collect::<Vec<_>>();
        if parts.len() != 4
            || parts[0] != "v1"
            || parts[1].len() != 64
            || !parts[1]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || parts[2]
                .parse::<usize>()
                .ok()
                .is_none_or(|count| !(1..=crate::exception_roots::MAX_TABLES).contains(&count))
            || parts[3]
                .parse::<usize>()
                .ok()
                .is_none_or(|count| !(1..=crate::exception_roots::MAX_ROOTS).contains(&count))
        {
            return Err(Error::DecomposeIncomplete(
                "pass-2 exception identity is not the strict v1 grammar".into(),
            ));
        }
        let manifest = self.exception_manifest.as_ref().ok_or_else(|| {
            Error::DecomposeIncomplete(
                "a present pass-2 exception identity requires its manifest".into(),
            )
        })?;
        let canonical = std::fs::canonicalize(manifest)?;
        if canonical != *manifest || !canonical.is_file() {
            return Err(Error::DecomposeIncomplete(format!(
                "pass-2 exception manifest is not a canonical regular file: {}",
                manifest.display()
            )));
        }
        if crate::manifest::blake3_file(&canonical)? != parts[1] {
            return Err(Error::DecomposeIncomplete(
                "pass-2 exception manifest does not match its identity BLAKE3".into(),
            ));
        }
        Ok((
            identity.to_string(),
            canonical.to_string_lossy().into_owned(),
        ))
    }
}

/// The `analyzeHeadless` argument vector for pass 2 of `run_two_pass`. Runs in
/// `-process` mode on the existing project so there is no re-import and no
/// re-analysis: `ApplyThumbNames.java` first authenticates and applies the
/// symbol map's creation section before any other pass-2 mutation; then the
/// requested `ApplySymbols.java`, `ApplyGlobals.java`, and
/// `ApplyGlobalTypes.java` scripts run in that order, followed by
/// `ExportDecomp.java`.
///
/// `ApplyThumbNames` consumes exactly ten arguments (kit root, image label,
/// image BLAKE3, exception identity/manifest, scatter manifest, retained
/// pass-1 functions.json and its BLAKE3, symbol map and its BLAKE3).
/// `ApplySymbols` consumes exactly twelve arguments (kit root, image label,
/// image BLAKE3, exception identity/manifest, PAL identity, task/scatter
/// manifests, retained pass-1 functions.json, its BLAKE3, symbol map, its BLAKE3) and
/// `ExportDecomp` exactly ten (output directory, kit root, image label,
/// exception identity/manifest, PAL identity/manifest, scatter manifest,
/// pass-1 symbol map, expected map BLAKE3).
fn headless_process_args(
    root: &str,
    label: &str,
    input: &Pass2Input,
) -> Result<Option<Vec<String>>> {
    let function_map = input.function_map.as_ref();
    let global_map = input.global_map.as_ref();
    let global_types_map = input.global_types_map.as_ref();
    if !input.has_maps() {
        return Ok(None);
    }

    if let Some(map) = function_map {
        map.validate_for_spawn()?;
    }
    if let Some(map) = global_map {
        map.validate_for_spawn()?;
    }
    if let Some(map) = global_types_map {
        map.validate_for_spawn()?;
    }

    let (exception_identity, exception_manifest) = input.exception_args()?;
    let pal_identity = input.pal_identity_or_none().to_string();
    let pal_manifest = input
        .pal_manifest
        .as_ref()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|| "-".to_string());
    let scatter_manifest = input
        .scatter_manifest
        .as_ref()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|| "-".to_string());

    let mut args = vec![
        format!("{root}/ghidra_project"),
        GHIDRA_PROJECT_NAME.to_string(),
        "-process".to_string(),
        label.to_string(),
        "-noanalysis".to_string(),
        "-scriptPath".to_string(),
        format!("{root}/scripts"),
    ];
    // Creation preflight must precede every other pass-2 mutation. A failure
    // here leaves function/global/type application untouched; a later failure
    // can safely replay an already-owned creation.
    if let Some(map) = function_map {
        args.extend([
            "-postScript".to_string(),
            "ApplyThumbNames.java".to_string(),
            root.to_string(),
            label.to_string(),
            map.image_blake3().to_string(),
            exception_identity.clone(),
            exception_manifest.clone(),
            scatter_manifest.clone(),
            map.functions.path().to_string_lossy().into_owned(),
            map.functions_blake3().to_string(),
            map.path().to_string_lossy().into_owned(),
            map.map_blake3().to_string(),
        ]);
    }
    if let Some(map) = function_map {
        if map.image_label() != label {
            return Err(Error::DecomposeIncomplete(format!(
                "pass-2 symbol map was built for image {:?}, not {label:?}",
                map.image_label()
            )));
        }
        args.extend([
            "-postScript".to_string(),
            "ApplySymbols.java".to_string(),
            root.to_string(),
            map.image_label().to_string(),
            map.image_blake3().to_string(),
            exception_identity.clone(),
            exception_manifest.clone(),
            pal_identity.clone(),
            pal_manifest.clone(),
            scatter_manifest.clone(),
            map.functions.path().to_string_lossy().into_owned(),
            map.functions_blake3().to_string(),
            map.path().to_string_lossy().into_owned(),
            map.map_blake3().to_string(),
        ]);
    }
    if let Some(map) = global_map {
        args.extend([
            "-postScript".to_string(),
            "ApplyGlobals.java".to_string(),
            map.path().to_string_lossy().into_owned(),
        ]);
    }
    if let Some(map) = global_types_map {
        args.extend([
            "-postScript".to_string(),
            "ApplyGlobalTypes.java".to_string(),
            map.path().to_string_lossy().into_owned(),
        ]);
    }
    let map_argument = function_map
        .map(|map| map.path().to_string_lossy().into_owned())
        .unwrap_or_else(|| "-".to_string());
    let map_hash = function_map
        .map(|map| map.map_blake3().to_string())
        .unwrap_or_else(|| "none".to_string());
    args.extend([
        "-postScript".to_string(),
        "ExportDecomp.java".to_string(),
        format!("{root}/export/{label}"),
        root.to_string(),
        label.to_string(),
        exception_identity,
        exception_manifest,
        pal_identity,
        pal_manifest,
        scatter_manifest,
        map_argument,
        map_hash,
    ]);
    Ok(Some(args))
}

fn tail_text(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        text.to_string()
    } else {
        text.chars()
            .rev()
            .take(max_chars)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect()
    }
}

/// Extract the `N` from the summary line
/// `ApplySymbols: image=<image> applied N names, M plate comments over E
/// executions`. `None` when the line is missing or the count is not an
/// integer — the caller treats `None` as "no information from pass 2".
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplyThumbNamesWire {
    image: String,
    status: String,
    candidates: usize,
    created: usize,
    reapplied: usize,
    skipped_existing: usize,
    skipped_collision: usize,
}

fn parse_apply_thumb_names_summary(
    stdout: &str,
    expected_image: &str,
    expected_candidates: usize,
) -> std::result::Result<AppliedThumbNames, String> {
    let mut payloads = stdout
        .lines()
        .filter_map(|line| line.strip_prefix("ApplyThumbNames: "));
    let payload = payloads
        .next()
        .ok_or_else(|| "missing ApplyThumbNames summary".to_string())?;
    if payloads.next().is_some() {
        return Err("duplicate ApplyThumbNames summary".to_string());
    }
    let wire: ApplyThumbNamesWire = serde_json::from_str(payload)
        .map_err(|error| format!("malformed ApplyThumbNames summary: {error}"))?;
    if wire.image != expected_image {
        return Err(format!(
            "ApplyThumbNames summary image {:?} does not match {:?}",
            wire.image, expected_image
        ));
    }
    if wire.status != "ok" {
        return Err(format!(
            "unknown ApplyThumbNames summary status {:?}",
            wire.status
        ));
    }
    if wire.candidates != expected_candidates {
        return Err(format!(
            "ApplyThumbNames summary candidates {} do not match prepared map {expected_candidates}",
            wire.candidates
        ));
    }
    let classified = wire
        .created
        .checked_add(wire.reapplied)
        .and_then(|count| count.checked_add(wire.skipped_existing))
        .and_then(|count| count.checked_add(wire.skipped_collision))
        .ok_or_else(|| "ApplyThumbNames summary count overflow".to_string())?;
    if classified != wire.candidates {
        return Err(format!(
            "non-conserving ApplyThumbNames summary: candidates {}, classified {classified}",
            wire.candidates
        ));
    }
    Ok(AppliedThumbNames {
        candidates: wire.candidates,
        created: wire.created,
        reapplied: wire.reapplied,
        skipped_existing: wire.skipped_existing,
        skipped_collision: wire.skipped_collision,
    })
}

fn parse_pass2_summary(stdout: &str) -> Option<usize> {
    for line in stdout.lines() {
        let Some(rest) = line.strip_prefix("ApplySymbols:") else {
            continue;
        };
        let Some(idx) = rest.find("applied ") else {
            continue;
        };
        let after = &rest[idx + "applied ".len()..];
        let end = after.find(' ').unwrap_or(after.len());
        if let Ok(n) = after[..end].parse::<usize>() {
            return Some(n);
        }
    }
    None
}

#[derive(Default)]
struct CoordinatedApplicationSummaries {
    exception_roots_applied: Option<AppliedExceptionRoots>,
    exception_error: Option<String>,
    pal_applied: Option<AppliedPalTasks>,
    terminal_error: Option<String>,
}

fn coordinate_application_summaries(
    stdout: &str,
    expected_image: &str,
    expected_exception_roots: Option<&MaterializedExceptionRoots>,
    pal_plan: Option<PalScriptPlan<'_>>,
) -> CoordinatedApplicationSummaries {
    let mut coordinated = CoordinatedApplicationSummaries::default();
    if let Some(expected) = expected_exception_roots {
        match parse_apply_exception_roots_summary(stdout, expected_image, &expected.identity)
            .and_then(|summary| {
                validate_applied_exception_roots(&summary, expected)?;
                Ok(summary)
            }) {
            Ok(summary) => coordinated.exception_roots_applied = Some(summary),
            Err(reason) => {
                coordinated.exception_error = Some(reason.clone());
                coordinated.terminal_error = Some(reason);
            }
        }
    }
    if let Some(plan) = pal_plan {
        match parse_apply_pal_tasks_summary(stdout, expected_image, plan.identity) {
            Ok(summary) => coordinated.pal_applied = Some(summary),
            Err(reason) => {
                if coordinated.terminal_error.is_none() {
                    coordinated.terminal_error = Some(reason);
                }
            }
        }
    }
    coordinated
}

fn parse_apply_exception_roots_summary(
    stdout: &str,
    expected_image: &str,
    expected_identity: &str,
) -> std::result::Result<AppliedExceptionRoots, String> {
    exception_pass2::parse_for_decompile(stdout, expected_image, expected_identity)
}

fn validate_applied_exception_roots(
    applied: &AppliedExceptionRoots,
    expected: &MaterializedExceptionRoots,
) -> std::result::Result<(), String> {
    let expected_roles = expected
        .tables
        .checked_mul(exception_roots::VECTOR_SLOTS)
        .ok_or_else(|| "expected exception-root role count overflows".to_string())?;
    if applied.tables() != expected.tables
        || applied.roles() != expected_roles
        || applied.entries() != expected.roots
    {
        return Err(format!(
            "ApplyExceptionRoots summary does not match the current manifest: tables {} != {}, roles {} != {}, entries {} != {}",
            applied.tables(),
            expected.tables,
            applied.roles(),
            expected_roles,
            applied.entries(),
            expected.roots
        ));
    }
    Ok(())
}

/// Parse the strict `ApplyPalTasks: {json}` current-run summary of one
/// successful PAL application: exactly one line, a JSON object whose
/// image, `ok` status, and identity match this run's scheduled map, and
/// the seven current-run counters. A missing, duplicate, or malformed
/// summary is the typed reason string — the caller rejects the image as
/// terminal-invalid.
fn parse_apply_pal_tasks_summary(
    stdout: &str,
    expected_image: &str,
    expected_identity: &str,
) -> std::result::Result<AppliedPalTasks, String> {
    let mut payloads = stdout
        .lines()
        .filter_map(|line| line.strip_prefix("ApplyPalTasks: "));
    let payload = payloads
        .next()
        .ok_or_else(|| "missing ApplyPalTasks summary".to_string())?;
    if payloads.next().is_some() {
        return Err("duplicate ApplyPalTasks summaries".to_string());
    }

    let value: serde_json::Value = serde_json::from_str(payload)
        .map_err(|error| format!("malformed ApplyPalTasks summary: {error}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "ApplyPalTasks summary is not an object".to_string())?;
    let image = object
        .get("image")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "ApplyPalTasks summary image is not a string".to_string())?;
    if image != expected_image {
        return Err(format!(
            "ApplyPalTasks summary image {image:?} does not match {expected_image:?}"
        ));
    }
    let status = object
        .get("status")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "ApplyPalTasks summary status is not a string".to_string())?;
    if status != "ok" {
        return Err(format!(
            "ApplyPalTasks summary status {status:?} is not \"ok\""
        ));
    }
    let identity = object
        .get("identity")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "ApplyPalTasks summary identity is not a string".to_string())?;
    if identity != expected_identity {
        return Err("ApplyPalTasks summary identity does not match this run's PAL map".to_string());
    }
    let count = |field: &str| -> std::result::Result<usize, String> {
        let count = object
            .get(field)
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| format!("ApplyPalTasks summary {field} is not an unsigned integer"))?;
        usize::try_from(count)
            .map_err(|_| format!("ApplyPalTasks summary {field} does not fit usize"))
    };
    Ok(AppliedPalTasks {
        tasks: count("tasks")?,
        entries: count("entries")?,
        functions_created: count("functions_created")?,
        functions_existing: count("functions_existing")?,
        names_applied: count("names_applied")?,
        names_preserved: count("names_preserved")?,
        shared_entries: count("shared_entries")?,
    })
}

#[derive(Debug, PartialEq, Eq)]
enum ApplyGlobalsSummary {
    Ok {
        candidates: usize,
        applied: usize,
        skipped_outside_memory: usize,
        skipped_missing: usize,
        skipped_non_default: usize,
        skipped_rejected: usize,
    },
    Error {
        reason: String,
    },
}

impl ApplyGlobalsSummary {
    fn applied_and_skipped(&self) -> Option<(usize, usize)> {
        let Self::Ok {
            applied,
            skipped_outside_memory,
            skipped_missing,
            skipped_non_default,
            skipped_rejected,
            ..
        } = self
        else {
            return None;
        };
        let skipped = skipped_outside_memory
            .checked_add(*skipped_missing)?
            .checked_add(*skipped_non_default)?
            .checked_add(*skipped_rejected)?;
        Some((*applied, skipped))
    }
}

fn apply_globals_count(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> std::result::Result<usize, String> {
    let count = object
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("ApplyGlobals summary {field} is not an unsigned integer"))?;
    usize::try_from(count)
        .map_err(|_| format!("ApplyGlobals summary {field} does not fit in usize"))
}

fn parse_apply_globals_summary(
    stdout: &str,
    expected_image: &str,
) -> std::result::Result<ApplyGlobalsSummary, String> {
    let mut payloads = stdout
        .lines()
        .filter_map(|line| line.strip_prefix("ApplyGlobals: "));
    let payload = payloads
        .next()
        .ok_or_else(|| "missing ApplyGlobals summary".to_string())?;
    if payloads.next().is_some() {
        return Err("duplicate ApplyGlobals summaries".to_string());
    }

    let value: serde_json::Value = serde_json::from_str(payload)
        .map_err(|error| format!("malformed ApplyGlobals summary: {error}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "ApplyGlobals summary is not an object".to_string())?;
    let image = object
        .get("image")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "ApplyGlobals summary image is not a string".to_string())?;
    if image != expected_image {
        return Err(format!(
            "ApplyGlobals summary image {image:?} does not match {expected_image:?}"
        ));
    }
    let status = object
        .get("status")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "ApplyGlobals summary status is not a string".to_string())?;

    match status {
        "ok" => {
            let candidates = apply_globals_count(object, "candidates")?;
            let applied = apply_globals_count(object, "applied")?;
            let skipped_outside_memory = apply_globals_count(object, "skipped_outside_memory")?;
            let skipped_missing = apply_globals_count(object, "skipped_missing")?;
            let skipped_non_default = apply_globals_count(object, "skipped_non_default")?;
            let skipped_rejected = apply_globals_count(object, "skipped_rejected")?;
            let classified = applied
                .checked_add(skipped_outside_memory)
                .and_then(|count| count.checked_add(skipped_missing))
                .and_then(|count| count.checked_add(skipped_non_default))
                .and_then(|count| count.checked_add(skipped_rejected))
                .ok_or_else(|| "ApplyGlobals summary counts overflow".to_string())?;
            if classified != candidates {
                return Err(format!(
                    "ApplyGlobals summary does not conserve candidates: {classified} != {candidates}"
                ));
            }
            Ok(ApplyGlobalsSummary::Ok {
                candidates,
                applied,
                skipped_outside_memory,
                skipped_missing,
                skipped_non_default,
                skipped_rejected,
            })
        }
        "error" => {
            let reason = object
                .get("error")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "ApplyGlobals error summary has no string error".to_string())?;
            let reason_chars = reason.chars().count();
            if reason.is_empty() || reason_chars > GLOBALS_APPLY_ERROR_MAX_CHARS {
                return Err(format!(
                    "ApplyGlobals error reason length {reason_chars} is outside 1..={GLOBALS_APPLY_ERROR_MAX_CHARS}"
                ));
            }
            Ok(ApplyGlobalsSummary::Error {
                reason: reason.to_string(),
            })
        }
        other => Err(format!("unknown ApplyGlobals status {other:?}")),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ApplyGlobalTypesSummary {
    Ok {
        candidates: usize,
        applied: usize,
        skipped_outside_memory: usize,
        skipped_collision: usize,
    },
    Error {
        reason: String,
    },
}

impl ApplyGlobalTypesSummary {
    fn applied_and_skipped(&self) -> Option<(usize, usize)> {
        let Self::Ok {
            applied,
            skipped_outside_memory,
            skipped_collision,
            ..
        } = self
        else {
            return None;
        };
        let skipped = skipped_outside_memory.checked_add(*skipped_collision)?;
        Some((*applied, skipped))
    }
}

fn apply_global_types_count(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> std::result::Result<usize, String> {
    let count = object
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("ApplyGlobalTypes summary {field} is not an unsigned integer"))?;
    usize::try_from(count)
        .map_err(|_| format!("ApplyGlobalTypes summary {field} does not fit in usize"))
}

fn parse_apply_global_types_summary(
    stdout: &str,
    expected_image: &str,
) -> std::result::Result<ApplyGlobalTypesSummary, String> {
    let mut payloads = stdout
        .lines()
        .filter_map(|line| line.strip_prefix("ApplyGlobalTypes: "));
    let payload = payloads
        .next()
        .ok_or_else(|| "missing ApplyGlobalTypes summary".to_string())?;
    if payloads.next().is_some() {
        return Err("duplicate ApplyGlobalTypes summaries".to_string());
    }
    let value: serde_json::Value = serde_json::from_str(payload)
        .map_err(|error| format!("malformed ApplyGlobalTypes summary: {error}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "ApplyGlobalTypes summary is not an object".to_string())?;
    let image = object
        .get("image")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "ApplyGlobalTypes summary image is not a string".to_string())?;
    if image != expected_image {
        return Err(format!(
            "ApplyGlobalTypes summary image {image:?} does not match {expected_image:?}"
        ));
    }
    let status = object
        .get("status")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "ApplyGlobalTypes summary status is not a string".to_string())?;
    match status {
        "error" => {
            let reason = object
                .get("error")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "ApplyGlobalTypes error summary has no string error".to_string())?;
            let reason_chars = reason.chars().count();
            if reason.is_empty() || reason_chars > GLOBALS_APPLY_ERROR_MAX_CHARS {
                return Err(format!(
                    "ApplyGlobalTypes error reason length {reason_chars} is outside 1..={GLOBALS_APPLY_ERROR_MAX_CHARS}"
                ));
            }
            Ok(ApplyGlobalTypesSummary::Error {
                reason: reason.to_string(),
            })
        }
        "ok" => {
            let candidates = apply_global_types_count(object, "candidates")?;
            let applied = apply_global_types_count(object, "applied")?;
            let skipped_outside_memory =
                apply_global_types_count(object, "skipped_outside_memory")?;
            let skipped_collision = apply_global_types_count(object, "skipped_collision")?;
            let classified = applied
                .checked_add(skipped_outside_memory)
                .and_then(|n| n.checked_add(skipped_collision))
                .ok_or_else(|| "ApplyGlobalTypes counts overflow".to_string())?;
            if classified != candidates {
                return Err("ApplyGlobalTypes summary does not conserve candidates".to_string());
            }
            Ok(ApplyGlobalTypesSummary::Ok {
                candidates,
                applied,
                skipped_outside_memory,
                skipped_collision,
            })
        }
        other => Err(format!(
            "ApplyGlobalTypes summary status {other} is not ok/error"
        )),
    }
}

/// Pass 2 of two-pass decompile. Accepts the pass-1 `report` (callers run pass 1
/// via `run_report` separately and pass its result here — running pass 1 again
/// would triple Ghidra time on `02_MAIN`). Pass 2 runs only for images whose
/// `inputs.get(&label)` contains at least one prepared function, global, or
/// global-types map (a function map may be creation-only). This function records
/// late map validation and spawn/non-zero process failures into
/// `ImageResult.pass2_error`, rather than propagating them — pass 1 already
/// produced a valid `decompiled.c`. The caller additionally records owned-export
/// refresh failures in `pass2_error`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pass2ProcessOutcome {
    ProcessSucceeded,
    Failed(String),
}

fn reset_pass2_runtime_results(image: &mut ImageResult) {
    image.pass2_error = None;
    image.pass2_applied = None;
    image.pass2_thumb_names = None;
    image.globals_applied = None;
    image.globals_apply_skipped = None;
    image.globals_apply_error = None;
    image.global_types_applied = None;
    image.global_types_apply_skipped = None;
    image.global_types_apply_error = None;
}

#[derive(Debug)]
pub struct Pass2RunReport {
    pub report: DecompileReport,
    pub outcomes: HashMap<String, Pass2ProcessOutcome>,
}

pub fn run_two_pass(
    mut report: DecompileReport,
    opts: &Opts,
    out: &Path,
    inputs: &HashMap<String, Pass2Input>,
) -> Result<Pass2RunReport> {
    let mut outcomes = HashMap::new();
    if !opts.run {
        return Ok(Pass2RunReport { report, outcomes });
    }
    let install = find_ghidra(opts)?;
    let java_home = resolve_java_home(std::env::var_os("JAVA_HOME"), install.ghidra_run.as_deref());
    let root = std::fs::canonicalize(out)?;
    let root_str = root.to_string_lossy().into_owned();
    // One RAII Java/XDG state home for the whole pass-2 run.
    let state_home = GhidraStateHome::new()?;
    state_home.create_subdirs()?;

    for image in &mut report.images {
        reset_pass2_runtime_results(image);
    }

    for (label, input) in inputs {
        if input.has_maps() && !report.images.iter().any(|image| image.label == *label) {
            outcomes.insert(
                label.clone(),
                Pass2ProcessOutcome::Failed("input label absent from pass-1 report".to_string()),
            );
        }
    }

    for ir in &mut report.images {
        let Some(input) = inputs.get(&ir.label) else {
            continue;
        };
        if let Some(map) = input.function_map.as_ref() {
            match ir.pass2_creation_plan.as_ref() {
                Some(plan)
                    if plan.candidates != map.creation_count()
                        || plan.requests != map.creation_requests() =>
                {
                    let reason = "map validation: prepared creation plan changed".to_string();
                    ir.pass2_error = Some(reason.clone());
                    outcomes.insert(ir.label.clone(), Pass2ProcessOutcome::Failed(reason));
                    continue;
                }
                Some(_) => {}
                None => {
                    ir.pass2_creation_plan = Some(Pass2CreationPlan {
                        candidates: map.creation_count(),
                        skips: Default::default(),
                        requests: map.creation_requests().to_vec(),
                    });
                }
            }
        }
        let args = match headless_process_args(&root_str, &ir.label, input) {
            Ok(Some(args)) => args,
            Ok(None) => continue,
            Err(error) => {
                let reason = format!("map validation: {error}");
                ir.pass2_error = Some(reason.clone());
                outcomes.insert(ir.label.clone(), Pass2ProcessOutcome::Failed(reason));
                continue;
            }
        };

        let applies_functions = input.function_map.is_some();
        let applies_globals = input.global_map.is_some();

        tracing::info!("ghidra: pass 2 application for {}", ir.label);
        let mut export_attempt = match GhidraExportAttempt::begin(&root, &ir.label) {
            Ok(attempt) => attempt,
            Err(error) => {
                let reason = format!("export invalidation: {error}");
                ir.pass2_error = Some(reason.clone());
                outcomes.insert(ir.label.clone(), Pass2ProcessOutcome::Failed(reason));
                continue;
            }
        };
        // Spawn failure (e.g. executable bit lost, Ghidra uninstalled mid-run)
        // lands in `pass2_error` per image instead of propagating — pass 1
        // already produced a valid `decompiled.c` for every image.
        let output =
            match headless_command(&install.headless, &args, &state_home, java_home.as_deref())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .output()
            {
                Ok(o) => o,
                Err(e) => {
                    let reason = format!("spawn: {e}");
                    ir.pass2_error = Some(reason.clone());
                    outcomes.insert(ir.label.clone(), Pass2ProcessOutcome::Failed(reason));
                    continue;
                }
            };
        if output.status.success() {
            let symbol_map_hash = input
                .function_map
                .as_ref()
                .map(|map| map.map_blake3().to_string())
                .unwrap_or_else(|| "none".to_string());
            let pal_identity = input.pal_identity_or_none().to_string();
            if let Err(error) =
                export_attempt.validate_current("none", &pal_identity, &symbol_map_hash)
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                let reason = format!(
                    "incomplete current export: {error}\nstdout tail:\n{}\nstderr tail:\n{}",
                    tail_text(&stdout, 2048),
                    tail_text(&stderr, 2048)
                );
                ir.pass2_error = Some(reason.clone());
                outcomes.insert(ir.label.clone(), Pass2ProcessOutcome::Failed(reason));
                continue;
            }
            let stdout = String::from_utf8_lossy(&output.stdout);
            if applies_functions {
                ir.pass2_applied = parse_pass2_summary(&stdout);
                let expected_candidates = input
                    .function_map
                    .as_ref()
                    .expect("applies_functions requires a function map")
                    .creation_count();
                match parse_apply_thumb_names_summary(&stdout, &ir.label, expected_candidates) {
                    Ok(summary) => ir.pass2_thumb_names = Some(summary),
                    Err(error) => {
                        let reason = format!("ApplyThumbNames summary: {error}");
                        ir.pass2_error = Some(reason.clone());
                        outcomes.insert(ir.label.clone(), Pass2ProcessOutcome::Failed(reason));
                        continue;
                    }
                }
            }
            export_attempt.mark_current();
            if applies_globals {
                match parse_apply_globals_summary(&stdout, &ir.label) {
                    Ok(summary @ ApplyGlobalsSummary::Ok { .. }) => {
                        let (applied, skipped) = summary
                            .applied_and_skipped()
                            .expect("ok summary has checked counts");
                        ir.globals_applied = Some(applied);
                        ir.globals_apply_skipped = Some(skipped);
                    }
                    Ok(ApplyGlobalsSummary::Error { reason }) | Err(reason) => {
                        ir.globals_apply_error = Some(reason);
                    }
                }
            }
            if input.global_types_map.is_some() {
                match parse_apply_global_types_summary(&stdout, &ir.label) {
                    Ok(summary) => match summary.applied_and_skipped() {
                        Some((applied, skipped)) => {
                            ir.global_types_applied = Some(applied);
                            ir.global_types_apply_skipped = Some(skipped);
                        }
                        None => {
                            if let ApplyGlobalTypesSummary::Error { reason } = summary {
                                ir.global_types_apply_error = Some(reason);
                            }
                        }
                    },
                    Err(reason) => ir.global_types_apply_error = Some(reason),
                }
            }
            outcomes.insert(ir.label.clone(), Pass2ProcessOutcome::ProcessSucceeded);
        } else {
            let code = output.status.code().unwrap_or(-1);
            tracing::warn!("ghidra: pass 2 for {} failed (exit {code})", ir.label);
            // Java stack traces and Ghidra script compile errors land on stderr;
            // keep the tail so the report stays actionable without bloating.
            let stderr = String::from_utf8_lossy(&output.stderr);
            let tail: String = if stderr.len() > 2048 {
                stderr
                    .chars()
                    .rev()
                    .take(2048)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect()
            } else {
                stderr.into_owned()
            };
            let reason = format!("analyzeHeadless exit {code}; stderr tail:\n{tail}");
            ir.pass2_error = Some(reason.clone());
            outcomes.insert(ir.label.clone(), Pass2ProcessOutcome::Failed(reason));
        }
    }
    Ok(Pass2RunReport { report, outcomes })
}

/// Generate the kit and (with `--run`) drive Ghidra plus configured dense-Thumb
/// analyzers; non-zero if any selected image failed either analysis path.
pub fn run(modem_bin: &Path, opts: &Opts, out: &Path) -> Result<PathBuf> {
    let report = run_report(modem_bin, opts, out)?;
    // Non-zero exit if any image failed — but only after all were attempted (run_report
    // records every partition), so a CI/script run still sees failure while keeping every
    // partition's results.
    if let Some(err) = report_failure(&report) {
        return Err(err);
    }
    Ok(report.spec_path)
}

/// A located Ghidra headless launcher plus the `ghidraRun` wrapper it was found
/// through, if any. The wrapper is the only source of a packager-pinned `JAVA_HOME`
/// (Homebrew's), read by the `--run` path — never by pure discovery.
#[derive(Debug, Clone, PartialEq)]
pub struct GhidraInstall {
    pub headless: PathBuf,
    pub ghidra_run: Option<PathBuf>,
}

/// First existing `analyzeHeadless` under `root`: the upstream tarball layout
/// (`support/`), then Homebrew's, which nests the whole dist under `libexec/`.
fn headless_in_root(root: &Path) -> Option<PathBuf> {
    [
        root.join("support").join("analyzeHeadless"),
        root.join("libexec").join("support").join("analyzeHeadless"),
    ]
    .into_iter()
    .find(|p| p.exists())
}

/// The `ghidraRun` wrapper for a discovered root, if present: Homebrew ships it at
/// `bin/ghidraRun`, upstream at the dist root. Only Homebrew's pins a `JAVA_HOME`.
fn wrapper_in_root(root: &Path) -> Option<PathBuf> {
    [root.join("bin").join("ghidraRun"), root.join("ghidraRun")]
        .into_iter()
        .find(|p| p.exists())
}

/// Candidate install roots implied by a (canonicalized) `ghidraRun` path: the directory
/// holding it (upstream ships it at the dist root) and that directory's parent (Homebrew
/// ships it at `<root>/bin/ghidraRun`).
fn roots_from_ghidra_run(run: &Path) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(dir) = run.parent() {
        roots.push(dir.to_path_buf());
        if let Some(parent) = dir.parent() {
            roots.push(parent.to_path_buf());
        }
    }
    roots
}

/// The `JAVA_HOME` a `ghidraRun` wrapper pins, if any. Homebrew's wrapper assigns
/// `JAVA_HOME="${JAVA_HOME:-<path>}"` (respecting an existing value); upstream's pins
/// nothing. Returns the default only when it parses unambiguously and the directory
/// exists — so a bad parse never overrides Ghidra's own JDK search.
fn java_home_from_ghidra_run(run: &Path) -> Option<PathBuf> {
    let text = std::fs::read_to_string(run).ok()?;
    for line in text.lines() {
        // Prefer the `${JAVA_HOME:-<default>}` form; fall back to a plain assignment.
        let candidate = if let Some(i) = line.find("${JAVA_HOME:-") {
            let rest = &line[i + "${JAVA_HOME:-".len()..];
            rest.find('}').map(|j| &rest[..j])
        } else if let Some(i) = line.find("JAVA_HOME=\"") {
            let rest = &line[i + "JAVA_HOME=\"".len()..];
            rest.find('"').map(|j| &rest[..j])
        } else {
            None
        };
        if let Some(c) = candidate {
            let c = c.trim();
            if !c.is_empty() && Path::new(c).exists() {
                return Some(PathBuf::from(c));
            }
        }
    }
    None
}

/// The `JAVA_HOME` to inject into the `analyzeHeadless` child, or `None` to leave it to
/// Ghidra. Ghidra rejects a mismatched `JAVA_HOME` rather than falling back, so never
/// override one the caller already set; otherwise reuse the wrapper's pinned JDK if any.
fn resolve_java_home(
    env_java_home: Option<OsString>,
    ghidra_run: Option<&Path>,
) -> Option<PathBuf> {
    if env_java_home.is_some() {
        return None;
    }
    ghidra_run.and_then(java_home_from_ghidra_run)
}

/// Pure discovery (no env reads — see `find_headless`): the first of (`--ghidra-home`,
/// `$GHIDRA_INSTALL_DIR`, a `PATH` dir) that yields an `analyzeHeadless`. Each `--ghidra-home`
/// / env candidate is treated as an install *root* and probed for both the upstream and
/// Homebrew layouts; on `PATH`, a bare `analyzeHeadless` wins, else a `ghidraRun` wrapper is
/// canonicalized and its root probed.
fn locate_tools(
    ghidra_home: Option<&Path>,
    env_dir: Option<&Path>,
    path_dirs: &[PathBuf],
    default_root: Option<&Path>,
) -> Option<GhidraInstall> {
    for root in [ghidra_home, env_dir].into_iter().flatten() {
        if let Some(headless) = headless_in_root(root) {
            return Some(GhidraInstall {
                headless,
                ghidra_run: wrapper_in_root(root),
            });
        }
    }
    for dir in path_dirs {
        let bare = dir.join("analyzeHeadless");
        if bare.exists() {
            return Some(GhidraInstall {
                headless: bare,
                ghidra_run: None,
            });
        }
        // Homebrew exposes only a `ghidraRun` symlink on PATH; resolve it to the real
        // install root. A missing or dangling wrapper canonicalizes to Err -> skip.
        let Ok(canon) = std::fs::canonicalize(dir.join("ghidraRun")) else {
            continue;
        };
        for root in roots_from_ghidra_run(&canon) {
            if let Some(headless) = headless_in_root(&root) {
                return Some(GhidraInstall {
                    headless,
                    ghidra_run: Some(canon),
                });
            }
        }
    }
    // Last resort: a conventional install root (e.g. `/opt/ghidra` on Linux),
    // probed only after every explicit source misses — so a distro/manual install
    // is found without an env var or flag.
    if let Some(root) = default_root
        && let Some(headless) = headless_in_root(root)
    {
        return Some(GhidraInstall {
            headless,
            ghidra_run: wrapper_in_root(root),
        });
    }
    None
}

/// Conventional Linux install prefix, probed as a last resort after `--ghidra-home`,
/// `$GHIDRA_INSTALL_DIR`, and `PATH` all miss — so a distro/manual `/opt/ghidra` install
/// works with no env var or flag. (The Ghidra-e2e test harness uses the same fallback.)
const DEFAULT_GHIDRA_ROOT: &str = "/opt/ghidra";

/// Locate the Ghidra headless launcher: `--ghidra-home` → `$GHIDRA_INSTALL_DIR` → `PATH`
/// (a bare `analyzeHeadless`, or resolved from a `ghidraRun` wrapper) → `/opt/ghidra`. Each
/// root is probed for both the upstream (`support/`) and Homebrew (`libexec/support/`) layouts.
pub fn find_headless(ghidra_home: Option<&Path>) -> Result<GhidraInstall> {
    let env_dir = std::env::var_os("GHIDRA_INSTALL_DIR").map(PathBuf::from);
    let path_dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    locate_tools(
        ghidra_home,
        env_dir.as_deref(),
        &path_dirs,
        Some(Path::new(DEFAULT_GHIDRA_ROOT)),
    )
    .ok_or_else(|| {
        Error::GhidraNotFound(
            "tried --ghidra-home, $GHIDRA_INSTALL_DIR, PATH, and /opt/ghidra; if Ghidra was \
             installed via Homebrew, pass --ghidra-home \"$(brew --prefix ghidra)\" or add its \
             bin to PATH"
                .into(),
        )
    })
}

fn find_ghidra(opts: &Opts) -> Result<GhidraInstall> {
    find_headless(opts.ghidra_home.as_deref())
}

/// Locate the required `radare2` primary (`r2`) on `PATH`. `None` if it is not installed.
pub fn find_radare2() -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|d| d.join("r2"))
        .find(|p| p.exists())
}

/// Phase 2: enrich a `thumb_functions.json` with per-function `body_c` sourced
/// from a `decompiled.c`. Only current v3 artifacts are mutable; retained v1/v2
/// artifacts are read-only replay inputs and fail before a writer is opened. A
/// semantic no-op leaves the file byte-identical. Idempotent.
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
/// matching because analyzer-generated names do not reliably align with Ghidra's
/// `FUN_<addr>`/recovered names. Returns the count of functions whose `body_c`
/// was populated.
///
/// Both inputs stream: the C file is read line-by-line into the address-to-body
/// map and a current v3 artifact is rewritten one function at a time through
/// the shared atomic mutator. No whole artifact `Value` tree is materialized.
/// Legacy or malformed input fails closed with the on-disk artifact unchanged.
pub(crate) fn thumb_enrich(
    decompiled_c_path: &Path,
    thumb_functions_json_path: &Path,
    runtime: &RuntimeImage<'_>,
) -> Result<usize> {
    let bodies = collect_decompiled_c_bodies(decompiled_c_path)?;
    let mut populated = 0usize;
    crate::thumb_analysis::stream_rewrite_thumb_functions(
        thumb_functions_json_path,
        runtime,
        |_, _, function| {
            // Phase 2.1: match by `entry` (address), not by `name`. The `name`
            // field is analyzer-generated and does not reliably align with
            // Ghidra's `FUN_<addr>`/recovered names — Phase 2's bug.
            let Some(entry_str) = function.get("entry").and_then(|name| name.as_str()) else {
                return Ok(());
            };
            let Some(canonical) = normalize_thumb_addr(entry_str) else {
                return Ok(());
            };
            if let Some(body) = bodies.get(&canonical) {
                function.as_object_mut().unwrap().insert(
                    "body_c".to_string(),
                    serde_json::Value::String(body.clone()),
                );
                populated += 1;
            }
            Ok(())
        },
    )?;
    Ok(populated)
}

/// Whole-file differential oracle for the streaming enricher.
#[cfg(test)]
fn thumb_enrich_whole(decompiled_c_path: &Path, thumb_functions_json_path: &Path) -> Result<usize> {
    let c_text = std::fs::read_to_string(decompiled_c_path)?;
    let bodies = parse_decompiled_c_function_bodies_by_addr(&c_text);
    let mut artifact =
        crate::thumb_analysis::read_thumb_artifact(thumb_functions_json_path, &test_runtime())?;
    let mut populated = 0usize;
    for function in artifact.function_values_mut() {
        let Some(entry) = function.get("entry").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let Some(entry) = normalize_thumb_addr(entry) else {
            continue;
        };
        if let Some(body) = bodies.get(&entry) {
            function.as_object_mut().unwrap().insert(
                "body_c".to_string(),
                serde_json::Value::String(body.clone()),
            );
            populated += 1;
        }
    }
    artifact.write_atomic(thumb_functions_json_path)?;
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
/// prior name-based parser. This whole-string implementation is retained only
/// as the differential oracle for the streaming collector.
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
        // `thumb_analysis::stream::ValueScanner` (`balanced_json_end` is its `#[cfg(test)]`
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

fn collect_decompiled_c_bodies(path: &Path) -> Result<HashMap<String, String>> {
    let file = std::fs::File::open(path)?;
    let mut source = LineSource::new(std::io::BufReader::new(file));
    let mut out = HashMap::new();
    while let Some(line) = source.next_line()? {
        let Some(addr_str) = decompiled_c_header_addr(&line) else {
            continue;
        };
        let mut window = VecDeque::with_capacity(8);
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

fn decompiled_c_header_addr(line: &str) -> Option<&str> {
    line.trim()
        .strip_prefix("//")
        .and_then(|rest| rest.rsplit_once(" @ "))
        .map(|(_, addr)| addr.trim())
        .filter(|addr| !addr.is_empty())
}

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
    use crate::execution_ranges::DecodeIsa;

    /// Build a minimal valid `modem.bin`: a `TOC\0` header + one 32-byte entry per
    /// image (name, offset, load_addr, size, crc=0, index), with payloads packed
    /// directly after the entry table.
    fn craft_modem_bin(images: &[(&str, u32, u32, &[u8])]) -> Vec<u8> {
        let entry_off = 0x20usize;
        let stride = 0x20usize;
        let table_end = entry_off + images.len() * stride;
        let mut offsets = Vec::new();
        let mut total = table_end;
        for (_, _, _, p) in images {
            offsets.push(total);
            total += p.len();
        }
        let mut buf = vec![0u8; total];
        buf[0..4].copy_from_slice(b"TOC\0");
        buf[0x1c..0x20].copy_from_slice(&(images.len() as u32).to_le_bytes());
        for (i, (name, addr, index, payload)) in images.iter().enumerate() {
            let e = entry_off + i * stride;
            let nb = name.as_bytes();
            let n = nb.len().min(12);
            buf[e..e + n].copy_from_slice(&nb[..n]);
            buf[e + 12..e + 16].copy_from_slice(&(offsets[i] as u32).to_le_bytes());
            buf[e + 16..e + 20].copy_from_slice(&addr.to_le_bytes());
            buf[e + 20..e + 24].copy_from_slice(&(payload.len() as u32).to_le_bytes());
            buf[e + 24..e + 28].copy_from_slice(&0u32.to_le_bytes());
            buf[e + 28..e + 32].copy_from_slice(&index.to_le_bytes());
            buf[offsets[i]..offsets[i] + payload.len()].copy_from_slice(payload);
        }
        buf
    }

    const SCATTER_BASE: u32 = 0x1000_0000;

    fn write_test_u32(image: &mut [u8], offset: usize, value: u32) {
        image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_test_descriptor(
        image: &mut [u8],
        table_offset: usize,
        index: usize,
        source: u32,
        destination: u32,
        size: u32,
        handler: u32,
    ) {
        let offset = table_offset + index * 16;
        write_test_u32(image, offset, source);
        write_test_u32(image, offset + 4, destination);
        write_test_u32(image, offset + 8, size);
        write_test_u32(image, offset + 12, handler);
    }

    fn scatter_main_image() -> Vec<u8> {
        const IMAGE_LEN: usize = 0x1000;
        const LOADER_OFFSET: usize = 0x40;
        const LITERAL_OFFSET: usize = 0x80;
        const TABLE_OFFSET: usize = 0x200;
        const TABLE_LEN: u32 = 6 * 16;
        const NULL_HANDLER: u32 = SCATTER_BASE + 0x600;
        const COPY_HANDLER: u32 = SCATTER_BASE + 0x601;
        const DECOMPRESS1_HANDLER: u32 = SCATTER_BASE + 0x604;
        const ZERO_HANDLER: u32 = SCATTER_BASE + 0x609;
        const SENTINEL_SOURCE: u32 = SCATTER_BASE + 0x680;
        const SELF_COPY_SOURCE: u32 = SCATTER_BASE + 0x700;
        const COPY_SOURCE: u32 = SCATTER_BASE + 0x710;
        const DECOMPRESS1_SOURCE: u32 = SCATTER_BASE + 0x720;
        const ZERO_SOURCE: u32 = SCATTER_BASE + 0x730;

        let mut image = vec![0; IMAGE_LEN];
        // ADD r0, pc, #0x38; LDMIA r0, {r10,r11}; ADD r10/r11, r0.
        write_test_u32(&mut image, LOADER_OFFSET, 0xe28f_0038);
        write_test_u32(&mut image, LOADER_OFFSET + 4, 0xe890_0c00);
        write_test_u32(&mut image, LOADER_OFFSET + 8, 0xe08a_a000);
        write_test_u32(&mut image, LOADER_OFFSET + 12, 0xe08b_b000);
        let literal_address = SCATTER_BASE + LITERAL_OFFSET as u32;
        let table_address = SCATTER_BASE + TABLE_OFFSET as u32;
        write_test_u32(
            &mut image,
            LITERAL_OFFSET,
            table_address.wrapping_sub(literal_address),
        );
        write_test_u32(
            &mut image,
            LITERAL_OFFSET + 4,
            (table_address + TABLE_LEN).wrapping_sub(literal_address),
        );

        image[0x700..0x704].copy_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        image[0x710..0x714].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        image[0x720..0x722].copy_from_slice(&[0x22, 0xaa]);
        for (index, source, destination, size, handler) in [
            (0, SENTINEL_SOURCE, 0, 0, NULL_HANDLER),
            (1, 0, SENTINEL_SOURCE, 0, NULL_HANDLER),
            (2, SELF_COPY_SOURCE, SELF_COPY_SOURCE, 4, COPY_HANDLER),
            (3, COPY_SOURCE, 0x2000_0100, 4, COPY_HANDLER),
            (4, DECOMPRESS1_SOURCE, 0x2000_0200, 3, DECOMPRESS1_HANDLER),
            (5, ZERO_SOURCE, 0x2000_0300, 5, ZERO_HANDLER),
        ] {
            write_test_descriptor(
                &mut image,
                TABLE_OFFSET,
                index,
                source,
                destination,
                size,
                handler,
            );
        }
        image
    }

    fn generation_opts(image: Option<&str>) -> Opts {
        Opts {
            run: false,
            image: image.map(str::to_string),
            ghidra_home: None,
            processor: "ARM:LE:32:v7".into(),
            no_thumb_decompile: false,
            rizin_fallback: false,
            tighten_wall_clock_budget_override: None,
            no_skip_opaque: false,
        }
    }

    // -------------------------------------------------------------------
    // Runtime PAL discovery fixtures (Task 12): discoverable MAIN images
    // built from the shared PAL fixture machinery in
    // `pal_tasks::discover::test_support` — the only producer of a
    // complete, discoverable plan.
    // -------------------------------------------------------------------

    use crate::pal_tasks::test_support::{
        BASE as PAL_BASE, craft_ambiguous_pal_main_image, craft_discoverable_pal_main_image,
        craft_scatter_pal_main_image,
    };

    fn test_identity(
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

    #[cfg(unix)]
    fn write_executable(path: &Path, body: &str) {
        use std::os::unix::fs::PermissionsExt;

        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions).unwrap();
    }

    #[cfg(unix)]
    fn write_fake_headless(home: &Path) {
        let headless = home.join("support/analyzeHeadless");
        write_executable(
            &headless,
            r#"#!/bin/sh
set -eu
export_dir=
exception_identity=none
pal_identity=none
map_hash=none
state=0
for arg in "$@"; do
  if [ "$arg" = "ExportDecomp.java" ]; then
    state=1
    continue
  fi
  case "$state" in
    1) export_dir=$arg; state=2 ;;
    2) state=3 ;;
    3) state=4 ;;
    4) exception_identity=$arg; state=5 ;;
    5) state=6 ;;
    6) pal_identity=$arg; state=7 ;;
    7) state=8 ;;
    8) state=9 ;;
    9) state=10 ;;
    10) map_hash=$arg; state=0 ;;
    *) : ;;
  esac
done
test -n "$export_dir"
mkdir -p "$export_dir"
printf '%s
' '[]' > "$export_dir/functions.json"
: > "$export_dir/disasm.lst"
: > "$export_dir/decompiled.c"
export_root=$(dirname "$export_dir")
label=$(basename "$export_dir")
printf '%s
' 'pixel-modem-extractor-ghidra-export-v4' "exception_roots=$exception_identity" "pal_tasks=$pal_identity" "symbol_map=$map_hash" > "$export_root/$label.complete"
"#,
        );
    }

    /// One full `--run` over a discoverable MAIN with a fake recording
    /// headless: the in-process spawn argv equals `headless_args` over the
    /// canonical kit root exactly, the generated script embeds the same
    /// argv over `$HERE`, the two differ only in root expansion, and the
    /// run consumes the strict `ApplyPalTasks` summary and identity-bound
    /// v4 marker. Exercised under tighten (default), datamark
    /// (`--no-thumb-decompile`), and a scatter+PAL MAIN.
    #[cfg(unix)]
    #[test]
    fn pal_runtime_argv_is_identical_generated_and_in_process() {
        let dir = tempfile::tempdir().unwrap();
        let ghidra_home = dir.path().join("fake-ghidra");
        write_recording_headless(&ghidra_home);
        let tools = crate::thumb_analysis::ThumbTools {
            radare2: test_identity(
                crate::thumb_analysis::ThumbProducer::Radare2,
                "/tools/r2",
                "radare2 argv fixture",
            ),
            rizin: None,
        };

        let run_once = |image_bytes: &[u8], scatter: bool, datamark: bool, case: &str| {
            let buf = craft_modem_bin(&[("MAIN", PAL_BASE, 3, image_bytes)]);
            let modem = dir.path().join(format!("modem-{case}.bin"));
            std::fs::write(&modem, buf).unwrap();
            let out = dir.path().join(format!("out-{case}"));
            let mut opts = generation_opts(None);
            opts.run = true;
            opts.ghidra_home = Some(ghidra_home.clone());
            opts.no_thumb_decompile = datamark;
            let report = run_report_with_thumb_tools(&modem, &opts, &out, &tools)
                .unwrap_or_else(|error| panic!("{case}: {error}"));

            let image = &report.images[0];
            assert_eq!(image.label, "02_MAIN");
            assert!(
                matches!(image.outcome, ImageOutcome::Analyzed(_)),
                "{case}: outcome was not Analyzed: {:?} (terminal_error={:?})",
                image.outcome,
                image.terminal_error
            );
            assert_eq!(
                image.pal_applied,
                Some(AppliedPalTasks {
                    tasks: 2,
                    entries: 2,
                    functions_created: 2,
                    functions_existing: 0,
                    names_applied: 2,
                    names_preserved: 0,
                    shared_entries: 0,
                }),
                "{case}: the strict ApplyPalTasks summary must be parsed"
            );

            let root = std::fs::canonicalize(&out).unwrap();
            let root_str = root.to_string_lossy().into_owned();
            let mode = if datamark { "datamark" } else { "tighten" };
            let RuntimeTaskState::Present(map) = report.runtime_analysis_state("02_MAIN").tasks
            else {
                panic!("{case}: the run must carry a present PAL map");
            };
            let scatter_arg = if scatter {
                Some("scatter/02_MAIN/load_map.json")
            } else {
                None
            };

            // In-process: the recorded argv is exactly `headless_args` over
            // the canonical kit root.
            let expected = headless_args(
                &root_str,
                "02_MAIN",
                "ARM:LE:32:v7",
                PAL_BASE,
                scatter_arg,
                None,
                Some(PalScriptPlan {
                    manifest: &map.relative_path,
                    identity: &map.identity,
                }),
                &[],
                mode,
            );
            let recorded: Vec<String> =
                std::fs::read_to_string(root.join("export/02_MAIN/argv.txt"))
                    .unwrap()
                    .lines()
                    .map(str::to_string)
                    .collect();
            assert_eq!(recorded, expected, "{case}: in-process argv");

            // Generated script: for the production (tighten) route the
            // script embeds the same argv over `$HERE` with the exact
            // shell quoting; the datamark in-process spawn is compared
            // against `headless_args` in its own mode (the generated
            // script is always the tighten route).
            let script = std::fs::read_to_string(out.join("run_ghidra.sh")).unwrap();
            let generated = headless_args(
                "$HERE",
                "02_MAIN",
                "ARM:LE:32:v7",
                PAL_BASE,
                scatter_arg,
                None,
                Some(PalScriptPlan {
                    manifest: &map.relative_path,
                    identity: &map.identity,
                }),
                &[],
                mode,
            );
            if !datamark {
                let mut quoted: Vec<String> = Vec::with_capacity(generated.len());
                let mut processor_value = false;
                for arg in &generated {
                    if processor_value {
                        quoted.push(shell_quote(arg));
                    } else {
                        quoted.push(shell_arg(arg));
                    }
                    processor_value = arg == "-processor";
                }
                let invocation = format!("if \"$HEADLESS\" {}", quoted.join(" "));
                assert!(
                    script.contains(&invocation),
                    "{case}: run_ghidra.sh must embed the exact generated argv:\n{script}\nexpected {invocation}"
                );
            }
            for (recorded_arg, generated_arg) in recorded.iter().zip(generated.iter()) {
                let expanded = if generated_arg == "$HERE" {
                    root_str.clone()
                } else {
                    generated_arg.replace("$HERE", &root_str)
                };
                assert_eq!(
                    recorded_arg, &expanded,
                    "{case}: argv must differ only in root expansion ({generated_arg})"
                );
            }
            // The scatter argument of ApplyPalTasks mirrors scatter presence.
            let pal_at = recorded
                .iter()
                .position(|arg| arg == "ApplyPalTasks.java")
                .unwrap();
            assert_eq!(
                recorded[pal_at + 4],
                if scatter {
                    format!("{root_str}/scatter/02_MAIN/load_map.json")
                } else {
                    "-".to_string()
                },
                "{case}: ApplyPalTasks scatter argument"
            );
            // The mode dispatches as configured, after ApplyPalTasks.
            let tame_at = recorded
                .iter()
                .position(|arg| arg == "TameAnalysis.java")
                .unwrap();
            assert!(
                pal_at < tame_at,
                "{case}: ApplyPalTasks precedes TameAnalysis"
            );
            assert_eq!(recorded[tame_at + 1], mode);
            assert_eq!(recorded[tame_at + 2], "none");
            assert_eq!(recorded[tame_at + 3], map.identity);
        };

        run_once(
            &craft_discoverable_pal_main_image(),
            false,
            false,
            "pal_tighten",
        );
        run_once(
            &craft_discoverable_pal_main_image(),
            false,
            true,
            "pal_datamark",
        );
        run_once(&craft_scatter_pal_main_image(), true, false, "pal_scatter");
    }

    #[cfg(unix)]
    #[test]
    fn exception_runtime_applies_present_generation_state() {
        let dir = tempfile::tempdir().unwrap();
        let fixture = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/exception_roots/synthetic.bin"),
        )
        .unwrap();
        let modem = dir.path().join("modem.bin");
        std::fs::write(
            &modem,
            craft_modem_bin(&[("BOOT", 0x4001_0000, 1, &fixture)]),
        )
        .unwrap();
        let ghidra_home = dir.path().join("fake-ghidra");
        write_recording_headless(&ghidra_home);
        let out = dir.path().join("out");
        let mut opts = generation_opts(None);
        opts.run = true;
        opts.ghidra_home = Some(ghidra_home);
        opts.no_skip_opaque = true;
        let tools = crate::thumb_analysis::ThumbTools {
            radare2: test_identity(
                crate::thumb_analysis::ThumbProducer::Radare2,
                "/tools/r2",
                "radare2 exception fixture",
            ),
            rizin: None,
        };

        let report = run_report_with_thumb_tools(&modem, &opts, &out, &tools).unwrap();
        let image = &report.images[0];
        let RuntimeExceptionState::Present(map) = &image.exception_state else {
            panic!("the selected image must retain its present generation state");
        };
        let applied = image.exception_roots_applied.as_ref().unwrap();
        assert_eq!(applied.tables(), 1);
        assert_eq!(applied.roles(), 8);
        assert_eq!(applied.entries(), 7);
        assert_eq!(applied.functions_created(), 7);
        assert_eq!(applied.functions_reapplied(), 0);
        assert_eq!(applied.functions_existing(), 0);
        assert_eq!(applied.names_applied(), 6);
        assert_eq!(applied.names_reapplied(), 0);
        assert_eq!(applied.names_preserved(), 0);
        assert_eq!(applied.names_not_requested(), 1);
        assert_eq!(applied.shared_entries(), 1);
        assert_eq!(image.exception_error, None);
        assert!(matches!(image.outcome, ImageOutcome::Analyzed(_)));
        assert_eq!(
            std::fs::read(out.join("export/00_BOOT.complete")).unwrap(),
            export_completion_marker(&map.identity, "none", "none")
        );
        for (name, bytes) in [
            (
                "ApplyExceptionRoots.java",
                APPLY_EXCEPTION_ROOTS_JAVA.as_bytes(),
            ),
            (
                "ExceptionRootsSupport.java",
                EXCEPTION_ROOTS_SUPPORT_JAVA.as_bytes(),
            ),
        ] {
            assert_eq!(
                std::fs::read(out.join("scripts").join(name)).unwrap(),
                bytes,
                "generated kit did not stage {name}"
            );
        }

        let argv = std::fs::read_to_string(out.join("export/00_BOOT/argv.txt")).unwrap();
        let argv = argv.lines().collect::<Vec<_>>();
        let exception_at = argv
            .iter()
            .position(|arg| *arg == "ApplyExceptionRoots.java")
            .unwrap();
        let tame_at = argv
            .iter()
            .position(|arg| *arg == "TameAnalysis.java")
            .unwrap();
        assert!(exception_at < tame_at);
        assert_eq!(argv[exception_at + 4], "-");
        assert_eq!(argv[exception_at + 5], map.identity);
        assert_eq!(
            &argv[tame_at + 1..=tame_at + 3],
            ["tighten", &map.identity, "none"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn exception_runtime_rejects_bad_summaries_and_marker_without_stale_exports() {
        let fixture = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/exception_roots/synthetic.bin"),
        )
        .unwrap();
        for (case, mutate, expected) in [
            ("missing", "missing", "missing ApplyExceptionRoots summary"),
            (
                "duplicate",
                "duplicate",
                "duplicate ApplyExceptionRoots summaries",
            ),
            (
                "malformed",
                "malformed",
                "malformed ApplyExceptionRoots summary",
            ),
            (
                "wrong_summary_identity",
                "wrong_summary_identity",
                "summary identity does not match",
            ),
            (
                "wrong_marker_identity",
                "wrong_marker_identity",
                "invalid completion marker",
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let modem = dir.path().join("modem.bin");
            std::fs::write(
                &modem,
                craft_modem_bin(&[("BOOT", 0x4001_0000, 1, &fixture)]),
            )
            .unwrap();
            let ghidra_home = dir.path().join("fake-ghidra");
            write_recording_headless(&ghidra_home);
            let headless = ghidra_home.join("support/analyzeHeadless");
            let mut script = std::fs::read_to_string(&headless).unwrap();
            let summary_line = script
                .lines()
                .find(|line| line.contains("printf 'ApplyExceptionRoots:"))
                .unwrap()
                .to_string();
            match mutate {
                "missing" => script = script.replace(&format!("{summary_line}\n"), "  :\n"),
                "duplicate" => {
                    script = script.replace(
                        &format!("{summary_line}\n"),
                        &format!("{summary_line}\n{summary_line}\n"),
                    )
                }
                "malformed" => script = script.replace("\"tables\":1", "\"tables\":\"bad\""),
                "wrong_summary_identity" => {
                    script = script.replace(
                        "\"$label\" \"$exception_identity\"",
                        "\"$label\" \"v1:wrong\"",
                    )
                }
                "wrong_marker_identity" => {
                    script = script.replace(
                        "\"exception_roots=$exception_identity\"",
                        "\"exception_roots=v1:wrong\"",
                    )
                }
                _ => unreachable!(),
            }
            write_executable(&headless, &script);

            let out = dir.path().join(format!("out-{case}"));
            let mut opts = generation_opts(None);
            opts.run = true;
            opts.ghidra_home = Some(ghidra_home);
            opts.no_skip_opaque = true;
            let tools = crate::thumb_analysis::ThumbTools {
                radare2: test_identity(
                    crate::thumb_analysis::ThumbProducer::Radare2,
                    "/tools/r2",
                    "radare2 exception fixture",
                ),
                rizin: None,
            };
            let report = run_report_with_thumb_tools(&modem, &opts, &out, &tools).unwrap();
            let image = &report.images[0];
            assert!(
                matches!(image.outcome, ImageOutcome::TerminalInvalid),
                "{case}: {:?}",
                image.outcome
            );
            assert_eq!(image.exception_roots_applied, None, "{case}");
            assert!(
                image
                    .exception_error
                    .as_deref()
                    .is_some_and(|reason| reason.contains(expected)),
                "{case}: {:?}",
                image.exception_error
            );
            assert!(!out.join("export/00_BOOT.complete").exists(), "{case}");
            for name in GHIDRA_EXPORT_FILES {
                assert!(
                    !out.join("export/00_BOOT").join(name).exists(),
                    "{case}: {name}"
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn opaque_skip_retains_present_exception_generation_state_without_application() {
        fn copy_raw_storage(value: &serde_json::Value, fixture: &[u8], image: &mut [u8]) {
            match value {
                serde_json::Value::Array(values) => {
                    for value in values {
                        copy_raw_storage(value, fixture, image);
                    }
                }
                serde_json::Value::Object(object) => {
                    if object.get("kind").and_then(serde_json::Value::as_str) == Some("raw")
                        && let (Some(address), Some(size)) = (
                            object.get("address").and_then(serde_json::Value::as_str),
                            object.get("size").and_then(serde_json::Value::as_u64),
                        )
                    {
                        let start = usize::from_str_radix(address.trim_start_matches("0x"), 16)
                            .unwrap()
                            - 0x4001_0000;
                        let end = start + size as usize;
                        image[start..end].copy_from_slice(&fixture[start..end]);
                    }
                    for value in object.values() {
                        copy_raw_storage(value, fixture, image);
                    }
                }
                _ => {}
            }
        }

        let fixture = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/exception_roots/synthetic.bin"),
        )
        .unwrap();
        let manifest: serde_json::Value = serde_json::from_slice(
            &std::fs::read(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/exception_roots/roots.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let mut image = vec![0u8; 1024 * 1024];
        let mut state = 0x41c6_ce57u32;
        for byte in &mut image {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *byte = state as u8;
        }
        copy_raw_storage(&manifest, &fixture, &mut image);
        assert!(
            opaque_skip(&image).is_some(),
            "the fixture must hit the opaque gate"
        );

        let dir = tempfile::tempdir().unwrap();
        let modem = dir.path().join("modem.bin");
        std::fs::write(&modem, craft_modem_bin(&[("BOOT", 0x4001_0000, 1, &image)])).unwrap();
        let ghidra_home = dir.path().join("fake-ghidra");
        write_recording_headless(&ghidra_home);
        let out = dir.path().join("out");
        let mut opts = generation_opts(None);
        opts.run = true;
        opts.ghidra_home = Some(ghidra_home);
        let tools = crate::thumb_analysis::ThumbTools {
            radare2: test_identity(
                crate::thumb_analysis::ThumbProducer::Radare2,
                "/tools/r2",
                "radare2 opaque fixture",
            ),
            rizin: None,
        };
        let report = run_report_with_thumb_tools(&modem, &opts, &out, &tools).unwrap();
        let image = &report.images[0];
        assert!(matches!(
            image.exception_state,
            RuntimeExceptionState::Present(_)
        ));
        assert!(matches!(image.outcome, ImageOutcome::SkippedOpaque(_)));
        assert_eq!(image.exception_roots_applied, None);
        assert_eq!(image.exception_error, None);
        assert!(!out.join("export/00_BOOT/argv.txt").exists());
        assert!(!out.join("export/00_BOOT.complete").exists());
    }

    #[cfg(unix)]
    #[test]
    fn tighten_fallback_reapplies_the_same_exception_state_in_datamark_mode() {
        let dir = tempfile::tempdir().unwrap();
        let fixture = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/exception_roots/synthetic.bin"),
        )
        .unwrap();
        let modem = dir.path().join("modem.bin");
        std::fs::write(
            &modem,
            craft_modem_bin(&[("BOOT", 0x4001_0000, 1, &fixture)]),
        )
        .unwrap();
        let ghidra_home = dir.path().join("fake-ghidra");
        write_recording_headless(&ghidra_home);
        let out = dir.path().join("out");
        let mut opts = generation_opts(None);
        opts.run = true;
        opts.ghidra_home = Some(ghidra_home);
        opts.no_skip_opaque = true;
        opts.tighten_wall_clock_budget_override = Some(std::time::Duration::ZERO);
        let tools = crate::thumb_analysis::ThumbTools {
            radare2: test_identity(
                crate::thumb_analysis::ThumbProducer::Radare2,
                "/tools/r2",
                "radare2 fallback fixture",
            ),
            rizin: None,
        };

        let report = run_report_with_thumb_tools(&modem, &opts, &out, &tools).unwrap();
        let image = &report.images[0];
        assert!(matches!(image.outcome, ImageOutcome::Analyzed(_)));
        assert!(
            image
                .thumb_tighten_error
                .as_deref()
                .is_some_and(|reason| reason.contains("retrying as datamark"))
        );
        assert_eq!(image.thumb_decompiled, Some(0));
        assert!(image.exception_roots_applied.is_some());
        assert_eq!(image.exception_error, None);
        let RuntimeExceptionState::Present(map) = &image.exception_state else {
            panic!("fallback lost present exception state");
        };
        let argv = std::fs::read_to_string(out.join("export/00_BOOT/argv.txt")).unwrap();
        let argv = argv.lines().collect::<Vec<_>>();
        let tame = argv
            .iter()
            .position(|argument| *argument == "TameAnalysis.java")
            .unwrap();
        assert_eq!(
            &argv[tame + 1..=tame + 3],
            ["datamark", &map.identity, "none"]
        );
        assert_eq!(
            std::fs::read(out.join("export/00_BOOT.complete")).unwrap(),
            export_completion_marker(&map.identity, "none", "none")
        );
    }

    /// A fake `analyzeHeadless` that additionally records its full argv
    /// (one argument per line, under the image's export directory) and
    /// prints strict exception-root and PAL success summaries with the
    /// identities ExportDecomp was given — so the in-process route's exact
    /// spawn argv, marker identities, and summary parsing are observable.
    #[cfg(unix)]
    fn write_recording_headless(home: &Path) {
        let headless = home.join("support/analyzeHeadless");
        write_executable(
            &headless,
            r#"#!/bin/sh
set -eu
export_dir=
exception_identity=none
pal_identity=none
map_hash=none
exception_applied=0
applied=0
state=0
for arg in "$@"; do
  [ "$arg" = "ApplyExceptionRoots.java" ] && exception_applied=1
  [ "$arg" = "ApplyPalTasks.java" ] && applied=1
  if [ "$arg" = "ExportDecomp.java" ]; then
    state=1
    continue
  fi
  case "$state" in
    1) export_dir=$arg; state=2 ;;
    2) state=3 ;;
    3) state=4 ;;
    4) exception_identity=$arg; state=5 ;;
    5) state=6 ;;
    6) pal_identity=$arg; state=7 ;;
    7) state=8 ;;
    8) state=9 ;;
    9) state=10 ;;
    10) map_hash=$arg; state=0 ;;
    *) : ;;
  esac
done
test -n "$export_dir"
mkdir -p "$export_dir"
printf '%s\n' "$@" > "$export_dir/argv.txt"
printf '%s
' '[]' > "$export_dir/functions.json"
: > "$export_dir/disasm.lst"
: > "$export_dir/decompiled.c"
export_root=$(dirname "$export_dir")
label=$(basename "$export_dir")
if [ "$exception_applied" = 1 ]; then
  printf 'ApplyExceptionRoots: {"image":"%s","status":"ok","identity":"%s","symbol_pass2":null,"tables":1,"roles":8,"entries":7,"functions_created":7,"functions_reapplied":0,"functions_existing":0,"names_applied":6,"names_reapplied":0,"names_preserved":0,"names_not_requested":1,"shared_entries":1,"applications":[{"entry":"0x40010200","isa":"arm","function_result":"created","name_result":"applied","shared":false,"primary_disposition":"exception_owned","current_primary":{"symbol_id":10,"source":"analysis","name":"Reset","name_blake3":"0d1d0ead7580ab6516b3a9d29c2e4f2deb32e1c89b4df2430e1032abed999a2b"},"transition":null},{"entry":"0x40010220","isa":"thumb","function_result":"created","name_result":"applied","shared":false,"primary_disposition":"exception_owned","current_primary":{"symbol_id":11,"source":"analysis","name":"UndefinedInstruction","name_blake3":"715fe00f95685fc6af937f3a3079d0adc2bbb17b414183d0f627dbaf1c854d44"},"transition":null},{"entry":"0x40010240","isa":"arm","function_result":"created","name_result":"applied","shared":false,"primary_disposition":"exception_owned","current_primary":{"symbol_id":12,"source":"analysis","name":"SupervisorCall","name_blake3":"65141a0d03c5f9e990718f5d96455fac812883d8c1ebebe6aff6c075696a0b3f"},"transition":null},{"entry":"0x40010260","isa":"thumb","function_result":"created","name_result":"applied","shared":false,"primary_disposition":"exception_owned","current_primary":{"symbol_id":13,"source":"analysis","name":"PrefetchAbort","name_blake3":"2284c4117b9106b82fd8829c308230541944069ef71de3c0ab6048e766facb56"},"transition":null},{"entry":"0x40010280","isa":"arm","function_result":"created","name_result":"not_requested","shared":true,"primary_disposition":"not_requested","current_primary":{"symbol_id":14,"source":"default","name":"FUN_400102c0","name_blake3":"540e5a978812bce06f547b4c4d75b5817b3a6371b207ee5102361da0263bced4"},"transition":null},{"entry":"0x400102a0","isa":"arm","function_result":"created","name_result":"applied","shared":false,"primary_disposition":"exception_owned","current_primary":{"symbol_id":15,"source":"analysis","name":"ExistingIrq","name_blake3":"3950983f0d306d9cca4541556cff660fc2094dc5476df3f36bfa6e35afb8e20e"},"transition":null},{"entry":"0x400102c0","isa":"thumb","function_result":"created","name_result":"applied","shared":false,"primary_disposition":"exception_owned","current_primary":{"symbol_id":16,"source":"analysis","name":"DataAbort","name_blake3":"3fc2b1d7338304093e20b37543550aca715e6bd9e6475512c1e068425b615358"},"transition":null}]}\n' "$label" "$exception_identity"
fi
if [ "$applied" = 1 ]; then
  printf 'ApplyPalTasks: {"image":"%s","status":"ok","identity":"%s","tasks":2,"entries":2,"functions_created":2,"functions_existing":0,"names_applied":2,"names_preserved":0,"shared_entries":0}\n' "$label" "$pal_identity"
fi
printf '%s
' 'pixel-modem-extractor-ghidra-export-v4' "exception_roots=$exception_identity" "pal_tasks=$pal_identity" "symbol_map=$map_hash" > "$export_root/$label.complete"
"#,
        );
    }

    #[cfg(unix)]
    fn write_fake_radare2(path: &Path, succeeds: bool) {
        let body = if succeeds {
            r#"#!/bin/sh
printf '%s\n' '[{"name":"sym.thumb_func","addr":1073807360,"size":2,"realsz":2,"minaddr":1073807360,"maxaddr":1073807362}]' '{"addr":1073807360,"ops":[{"addr":1073807360,"bytes":"0001","disasm":"lsls r0, r0, 4"}]}'
"#
        } else {
            "#!/bin/sh\nexit 9\n"
        };
        write_executable(path, body);
    }

    #[test]
    fn headless_args_base_addr_is_hex_without_0x() {
        let args = headless_args(
            "/out",
            "02_MAIN",
            "ARM:LE:32:v7",
            0x4001_0000,
            None,
            None,
            None,
            &[(0x4109_0000, 0x288_0000)],
            "datamark",
        );
        assert_eq!(args[0], "/out/ghidra_project");
        assert_eq!(args[1], "pixel-modem");
        let imp = args.iter().position(|a| a == "-import").unwrap();
        assert_eq!(args[imp + 1], "/out/images/02_MAIN");
        let proc = args.iter().position(|a| a == "-processor").unwrap();
        assert_eq!(args[proc + 1], "ARM:LE:32:v7");
        let ld = args.iter().position(|a| a == "-loader").unwrap();
        assert_eq!(args[ld + 1], "BinaryLoader");
        let ba = args.iter().position(|a| a == "-loader-baseAddr").unwrap();
        assert_eq!(args[ba + 1], "40010000"); // hex, NO 0x
        assert!(!args[ba + 1].contains("0x"));
        let ps = args.iter().position(|a| a == "-postScript").unwrap();
        assert_eq!(args[ps + 1], "ExportDecomp.java");
        assert_eq!(args[ps + 2], "/out/export/02_MAIN");
        // pre-script wires TameAnalysis.java, then mode, expected exception
        // identity, expected PAL identity, and the data-region args (only in
        // datamark mode), before the post-script.
        let pre = args.iter().position(|a| a == "-preScript").unwrap();
        assert_eq!(args[pre + 1], "TameAnalysis.java");
        assert_eq!(args[pre + 2], "datamark");
        assert_eq!(args[pre + 3], "none"); // expected exception identity
        assert_eq!(args[pre + 4], "none"); // expected PAL identity
        assert_eq!(args[pre + 5], "41090000:2880000"); // addrHex:lenHex
        assert!(pre < ps, "pre-script must precede post-script");
        assert!(args.iter().any(|a| a == "-overwrite"));
        // base 0 -> zero-padded "00000000"; no data regions -> -postScript
        // directly follows the identity arg
        let z = headless_args(
            "/o",
            "00_BOOT",
            "ARM:LE:32:v7",
            0,
            None,
            None,
            None,
            &[],
            "datamark",
        );
        let zpre = z.iter().position(|a| a == "-preScript").unwrap();
        assert_eq!(z[zpre + 1], "TameAnalysis.java");
        assert_eq!(z[zpre + 2], "datamark");
        assert_eq!(z[zpre + 3], "none");
        assert_eq!(z[zpre + 4], "none");
        assert_eq!(z[zpre + 5], "-postScript");
        let bz = z.iter().position(|a| a == "-loader-baseAddr").unwrap();
        assert_eq!(z[bz + 1], "00000000");
    }

    #[test]
    fn headless_args_passes_tighten_mode() {
        let args = headless_args(
            "$HERE",
            "02_MAIN",
            "ARM:LE:32:v7",
            0x40e00000,
            None,
            None,
            None,
            &[(0x40e12000, 0x100000)],
            "tighten",
        );
        let pre_idx = args.iter().position(|a| a == "TameAnalysis.java").unwrap();
        // The next three args are mode, exception identity, and PAL identity.
        assert_eq!(args[pre_idx + 1], "tighten");
        assert_eq!(args[pre_idx + 2], "none");
        assert_eq!(args[pre_idx + 3], "none");
        // No addrHex:lenHex follows (tighten mode does not data-mark).
        assert!(
            !args[pre_idx + 4..].iter().any(|a| a.contains(':')),
            "tighten mode must not pass region args: {:?}",
            &args[pre_idx + 3..]
        );
    }

    #[test]
    fn headless_args_passes_datamark_mode_and_regions() {
        let args = headless_args(
            "$HERE",
            "02_MAIN",
            "ARM:LE:32:v7",
            0x40e00000,
            None,
            None,
            None,
            &[(0x40e12000, 0x100000)],
            "datamark",
        );
        let pre_idx = args.iter().position(|a| a == "TameAnalysis.java").unwrap();
        assert_eq!(args[pre_idx + 1], "datamark");
        assert_eq!(args[pre_idx + 2], "none");
        assert_eq!(args[pre_idx + 3], "none");
        assert!(args[pre_idx + 4..].iter().any(|a| a == "40e12000:100000"));
    }

    #[test]
    fn tame_analysis_args_pass_none_identities_after_mode() {
        // The strict contract consumes mode, exception identity, then PAL
        // identity. Both identities sit before any datamark region.
        let datamark = headless_args(
            "$HERE",
            "02_MAIN",
            "ARM:LE:32:v7",
            0x40e00000,
            None,
            None,
            None,
            &[(0x40e12000, 0x100000)],
            "datamark",
        );
        let tame_at = datamark
            .iter()
            .position(|arg| arg == "TameAnalysis.java")
            .unwrap();
        assert_eq!(
            &datamark[tame_at + 1..=tame_at + 4],
            ["datamark", "none", "none", "40e12000:100000"]
        );
        let tighten = headless_args(
            "$HERE",
            "02_MAIN",
            "ARM:LE:32:v7",
            0x40e00000,
            None,
            None,
            None,
            &[(0x40e12000, 0x100000)],
            "tighten",
        );
        let tame_at = tighten
            .iter()
            .position(|arg| arg == "TameAnalysis.java")
            .unwrap();
        assert_eq!(
            &tighten[tame_at + 1..=tame_at + 3],
            ["tighten", "none", "none"]
        );

        // The generated turnkey script (the other argument source) carries
        // the same identity spelling for every image invocation.
        let buf = craft_modem_bin(&[("BOOT", 0x0, 1, &[0u8; 4])]);
        let dir = std::env::temp_dir().join(format!("pme_tame_none_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let modem = dir.join("modem.bin");
        std::fs::write(&modem, &buf).unwrap();
        let out = dir.join("out");
        run(&modem, &generation_opts(None), &out).unwrap();
        let script = std::fs::read_to_string(out.join("run_ghidra.sh")).unwrap();
        assert!(
            script.contains("'TameAnalysis.java' 'tighten' 'none' 'none'"),
            "run_ghidra.sh must pass both none identities after the mode:\n{script}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tame_analysis_source_contract_uses_pal_tasks_support() {
        // TameAnalysis must run as a strict HeadlessScript transaction that
        // delegates PAL property/absence validation and the preservation
        // digests to the one shared support class — it may not own a second
        // registry parser or a second copy of a digest domain.
        for required in [
            "extends HeadlessScript",
            "PalTasksSupport.validateAbsent",
            "PalTasksSupport.validateAppliedIdentity",
            "PalTasksSupport.codeUnitsDigestHex",
            "PalTasksSupport.functionBodiesDigestHex",
            "PalTasksSupport.memoryDigestHex",
            "ExceptionRootsSupport.validateAbsent",
            "ExceptionRootsSupport.validateAppliedIdentity",
        ] {
            assert!(
                TAME_ANALYSIS_JAVA.contains(required),
                "TameAnalysis.java must use {required:?}"
            );
        }
        for forbidden in [
            "OWNERSHIP_MAP",
            "PAL_PROPERTY",
            "getStringPropertyMap",
            "parseRegistry",
            "pixel-modem-extractor-code-units-v1",
            "pixel-modem-extractor-function-bodies-v1",
        ] {
            assert!(
                !TAME_ANALYSIS_JAVA.contains(forbidden),
                "TameAnalysis.java redefines the PalTasksSupport surface {forbidden:?}"
            );
        }
        // The shared class owns the two new digest domains and their stream
        // limits; TameAnalysis pins its own datamark limits.
        for owned in [
            "pixel-modem-extractor-code-units-v1",
            "pixel-modem-extractor-function-bodies-v1",
            "MAX_CODE_UNITS = 4_194_304",
            "MAX_FUNCTIONS = 262_144",
        ] {
            assert!(
                PAL_TASKS_SUPPORT_JAVA.contains(owned),
                "PalTasksSupport.java must own {owned:?}"
            );
        }
        for pinned in [
            "budgetMsOverride(\"PME_TAME_PHASE_BUDGET_MS\", 15 * 60_000L)",
            "MAX_REGIONS = 4096",
            "MAX_REGION_AGGREGATE_BYTES = 512L * 1024L * 1024L",
            "MAX_STREAM_RECORDS = 1_000_000",
            "MAX_METADATA_BYTES = 64L * 1024L * 1024L",
            "MAX_ARRAY_BYTES = 16 * 1024 * 1024",
        ] {
            assert!(
                TAME_ANALYSIS_JAVA.contains(pinned),
                "TameAnalysis.java must pin the exact limit {pinned:?}"
            );
        }
    }

    #[test]
    fn export_source_contract_reauthenticates_exception_roots_and_emits_v4() {
        for required in [
            "ExceptionRootsSupport.preflight",
            "ExceptionRootsSupport.validateApplied",
            "ExceptionRootsSupport.validateAbsent",
            "pixel-modem-extractor-ghidra-export-v4",
            "exception_roots=",
        ] {
            assert!(
                EXPORT_DECOMP_JAVA.contains(required),
                "ExportDecomp.java must contain {required:?}"
            );
        }
        assert!(!EXPORT_DECOMP_JAVA.contains("pixel-modem-extractor-ghidra-export-v3"));
    }

    #[test]
    fn headless_args_applies_scatter_before_tame_analysis() {
        let args = headless_args(
            "/out",
            "02_MAIN",
            "ARM:LE:32:v7",
            SCATTER_BASE,
            Some("scatter/02_MAIN/load_map.json"),
            None,
            None,
            &[],
            "tighten",
        );
        let apply = args
            .iter()
            .position(|arg| arg == "ApplyScatterLoad.java")
            .unwrap();
        let tame = args
            .iter()
            .position(|arg| arg == "TameAnalysis.java")
            .unwrap();
        assert_eq!(
            &args[apply - 1..=apply + 3],
            [
                "-preScript",
                "ApplyScatterLoad.java",
                "/out",
                "02_MAIN",
                "/out/scatter/02_MAIN/load_map.json",
            ]
        );
        assert!(apply < tame);

        let raw_only = headless_args(
            "/out",
            "00_BOOT",
            "ARM:LE:32:v7",
            0,
            None,
            None,
            None,
            &[],
            "tighten",
        );
        assert!(!raw_only.iter().any(|arg| arg == "ApplyScatterLoad.java"));
    }

    #[test]
    fn pal_pre_script_order_and_nullability() {
        let pal_plan = PalScriptPlan {
            manifest: "pal_tasks/02_MAIN/tasks.json",
            identity: "v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:2:0",
        };
        // Present PAL map plus a scatter map: the pre-script order is
        // ApplyScatterLoad, ApplyPalTasks, TameAnalysis, and ApplyPalTasks
        // consumes the four canonical arguments verbatim. The exception-root
        // slot is independently absent in this PAL-specific test.
        let both = headless_args(
            "/out",
            "02_MAIN",
            "ARM:LE:32:v7",
            SCATTER_BASE,
            Some("scatter/02_MAIN/load_map.json"),
            None,
            Some(pal_plan),
            &[],
            "tighten",
        );
        let scatter_at = both
            .iter()
            .position(|arg| arg == "ApplyScatterLoad.java")
            .unwrap();
        let pal_at = both
            .iter()
            .position(|arg| arg == "ApplyPalTasks.java")
            .expect("a present PAL map must schedule ApplyPalTasks");
        let tame_at = both
            .iter()
            .position(|arg| arg == "TameAnalysis.java")
            .unwrap();
        assert!(scatter_at < pal_at && pal_at < tame_at);
        assert_eq!(
            &both[pal_at - 1..=pal_at + 4],
            [
                "-preScript",
                "ApplyPalTasks.java",
                "/out",
                "02_MAIN",
                "/out/pal_tasks/02_MAIN/tasks.json",
                "/out/scatter/02_MAIN/load_map.json",
            ]
        );

        // Present PAL map without a scatter map: no scatter pre-script, and
        // ApplyPalTasks receives the literal `-` scatter dependency.
        let pal_only = headless_args(
            "/out",
            "02_MAIN",
            "ARM:LE:32:v7",
            SCATTER_BASE,
            None,
            None,
            Some(pal_plan),
            &[],
            "tighten",
        );
        let pal_only_at = pal_only
            .iter()
            .position(|arg| arg == "ApplyPalTasks.java")
            .unwrap();
        let tame_only_at = pal_only
            .iter()
            .position(|arg| arg == "TameAnalysis.java")
            .unwrap();
        assert!(pal_only_at < tame_only_at);
        assert!(!pal_only.iter().any(|arg| arg == "ApplyScatterLoad.java"));
        assert_eq!(
            pal_only[tame_only_at + 3],
            "v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:2:0"
        );
        assert_eq!(pal_only[pal_only_at + 4], "-");

        // Current-none paths omit ApplyPalTasks entirely.
        let none = headless_args(
            "/out",
            "02_MAIN",
            "ARM:LE:32:v7",
            SCATTER_BASE,
            Some("scatter/02_MAIN/load_map.json"),
            None,
            None,
            &[],
            "tighten",
        );
        assert!(!none.iter().any(|arg| arg == "ApplyPalTasks.java"));
    }

    #[test]
    fn headless_args_order_exception_roots_before_pal() {
        let exception = ExceptionRootScriptPlan {
            manifest: "exception_roots/02_MAIN/roots.json",
            identity: "v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:1:7",
        };
        let pal = PalScriptPlan {
            manifest: "pal_tasks/02_MAIN/tasks.json",
            identity: "v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:2:0",
        };
        let args = headless_args(
            "/out",
            "02_MAIN",
            "ARM:LE:32:v7",
            SCATTER_BASE,
            Some("scatter/02_MAIN/load_map.json"),
            Some(exception),
            Some(pal),
            &[],
            "tighten",
        );

        let scatter_at = args
            .iter()
            .position(|arg| arg == "ApplyScatterLoad.java")
            .unwrap();
        let exception_at = args
            .iter()
            .position(|arg| arg == "ApplyExceptionRoots.java")
            .unwrap();
        let pal_at = args
            .iter()
            .position(|arg| arg == "ApplyPalTasks.java")
            .unwrap();
        let tame_at = args
            .iter()
            .position(|arg| arg == "TameAnalysis.java")
            .unwrap();
        assert!(scatter_at < exception_at && exception_at < pal_at && pal_at < tame_at);
        assert_eq!(
            &args[exception_at - 1..=exception_at + 5],
            [
                "-preScript",
                "ApplyExceptionRoots.java",
                "/out",
                "02_MAIN",
                "/out/exception_roots/02_MAIN/roots.json",
                "/out/scatter/02_MAIN/load_map.json",
                exception.identity,
            ]
        );
        assert_eq!(
            &args[tame_at + 1..=tame_at + 3],
            ["tighten", exception.identity, pal.identity]
        );
    }

    #[test]
    fn headless_args_cover_exception_scatter_pal_presence_matrix() {
        let exception = ExceptionRootScriptPlan {
            manifest: "exception_roots/02_MAIN/roots.json",
            identity: "v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:1:7",
        };
        let pal = PalScriptPlan {
            manifest: "pal_tasks/02_MAIN/tasks.json",
            identity: "v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:2:0",
        };
        for scatter_present in [false, true] {
            for exception_present in [false, true] {
                for pal_present in [false, true] {
                    let scatter = scatter_present.then_some("scatter/02_MAIN/load_map.json");
                    let args = headless_args(
                        "/out",
                        "02_MAIN",
                        "ARM:LE:32:v7",
                        SCATTER_BASE,
                        scatter,
                        exception_present.then_some(exception),
                        pal_present.then_some(pal),
                        &[],
                        "tighten",
                    );
                    let position = |name: &str| args.iter().position(|argument| argument == name);
                    assert_eq!(position("ApplyScatterLoad.java").is_some(), scatter_present);
                    assert_eq!(
                        position("ApplyExceptionRoots.java").is_some(),
                        exception_present
                    );
                    assert_eq!(position("ApplyPalTasks.java").is_some(), pal_present);
                    let tame = position("TameAnalysis.java").unwrap();
                    if let Some(exception_at) = position("ApplyExceptionRoots.java") {
                        assert!(exception_at < tame);
                        assert_eq!(
                            args[exception_at + 4],
                            scatter.map_or("-", |_| { "/out/scatter/02_MAIN/load_map.json" })
                        );
                    }
                    if let Some(pal_at) = position("ApplyPalTasks.java") {
                        assert!(pal_at < tame);
                        assert_eq!(
                            args[pal_at + 4],
                            scatter.map_or("-", |_| { "/out/scatter/02_MAIN/load_map.json" })
                        );
                    }
                    assert_eq!(
                        args[tame + 2],
                        if exception_present {
                            exception.identity
                        } else {
                            "none"
                        }
                    );
                    assert_eq!(
                        args[tame + 3],
                        if pal_present { pal.identity } else { "none" }
                    );
                    let export = position("ExportDecomp.java").unwrap();
                    assert_eq!(args[export + 4], args[tame + 2]);
                    assert_eq!(args[export + 6], args[tame + 3]);
                    assert_eq!(
                        args[export + 8],
                        scatter.map_or("-", |_| "/out/scatter/02_MAIN/load_map.json")
                    );
                }
            }
        }
    }

    #[test]
    fn pal_pre_script_remains_under_no_thumb_decompile() {
        // --no-thumb-decompile suppresses dense-Thumb discovery, not
        // firmware-authoritative task entries: datamark mode still schedules
        // ApplyPalTasks ahead of TameAnalysis, with `-` when scatter is absent;
        // the independently absent exception identity remains explicit.
        // The mode routes through the option plumbing (mode_from_opts), not a
        // literal, so an Opts-to-mode regression fails here.
        let mut opts = generation_opts(Some("02_MAIN"));
        opts.no_thumb_decompile = true;
        let mode = mode_from_opts(&opts);
        let plan = PalScriptPlan {
            manifest: "pal_tasks/02_MAIN/tasks.json",
            identity: "v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:2:0",
        };
        let args = headless_args(
            "$HERE",
            "02_MAIN",
            "ARM:LE:32:v7",
            0x40e00000,
            None,
            None,
            Some(plan),
            &[(0x40e12000, 0x100000)],
            mode,
        );
        let pal_at = args
            .iter()
            .position(|arg| arg == "ApplyPalTasks.java")
            .expect("datamark mode must keep ApplyPalTasks");
        let tame_at = args
            .iter()
            .position(|arg| arg == "TameAnalysis.java")
            .unwrap();
        assert!(pal_at < tame_at);
        assert_eq!(
            &args[pal_at - 1..=pal_at],
            ["-preScript", "ApplyPalTasks.java"]
        );
        assert_eq!(args[pal_at + 4], "-");
        assert_eq!(args[tame_at + 1], "datamark");
        assert_eq!(args[tame_at + 2], "none");
        assert_eq!(
            args[tame_at + 3],
            "v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:2:0"
        );
        assert!(args[tame_at + 4..].iter().any(|a| a == "40e12000:100000"));
    }

    #[test]
    fn captured_stdout_retention_fails_closed_at_the_ceiling() {
        let mut buffer = String::new();
        let line = "x".repeat(64);
        while buffer.len() + line.len() < MAX_CAPTURED_STDOUT_BYTES {
            push_captured_line(&mut buffer, &line).unwrap();
        }
        let error = push_captured_line(&mut buffer, &line)
            .expect_err("retention past the ceiling must fail closed");
        assert!(error.to_string().contains("ceiling"));
    }

    #[test]
    fn prepared_pass2_map_canonicalizes_relative_regular_file() {
        let root =
            std::env::temp_dir().join(format!("pmetask8rrelativemaps{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        assert!(
            root.components()
                .all(|component| !component.as_os_str().to_string_lossy().starts_with('.'))
        );
        let function_path = root.join("functions.json");
        let global_path = root.join("globals.json");
        let map_path = root.join("symbol_map.json");
        let image_path = root.join("02_MAIN.bin");
        std::fs::write(&function_path, b"functions").unwrap();
        std::fs::write(&global_path, b"globals").unwrap();
        std::fs::write(&map_path, b"map").unwrap();
        std::fs::write(&image_path, b"image").unwrap();
        let relative_function_path = relative_spelling_from_current_dir(&function_path);
        let relative_global_path = relative_spelling_from_current_dir(&global_path);
        let relative_map_path = relative_spelling_from_current_dir(&map_path);
        assert!(relative_function_path.is_relative());
        assert!(relative_global_path.is_relative());
        assert!(relative_map_path.is_relative());

        let input = Pass2Input {
            function_map: Some(
                PreparedSymbolPass2Map::new(
                    &relative_map_path,
                    &relative_function_path,
                    &image_path,
                    "02_MAIN",
                    1,
                    1,
                    Vec::new(),
                )
                .unwrap(),
            ),
            global_map: Some(
                PreparedPass2Map::new(
                    &relative_global_path,
                    std::num::NonZeroUsize::new(2).unwrap(),
                )
                .unwrap(),
            ),
            global_types_map: None,
            ..Pass2Input::default()
        };
        let args = headless_process_args("/out", "02_MAIN", &input)
            .unwrap()
            .expect("typed maps schedule pass two");
        // ApplySymbols' ninth argument is the retained functions.json; the
        // map itself is the eleventh.
        let apply_at = args
            .iter()
            .position(|arg| arg == "ApplySymbols.java")
            .unwrap();
        let function_argument = &args[apply_at + 9];
        let map_argument = &args[apply_at + 11];
        let global_argument = &args[args
            .iter()
            .position(|arg| arg == "ApplyGlobals.java")
            .unwrap()
            + 1];

        assert_eq!(
            Path::new(function_argument),
            std::fs::canonicalize(&function_path).unwrap()
        );
        assert_eq!(
            Path::new(map_argument),
            std::fs::canonicalize(&map_path).unwrap()
        );
        assert_eq!(
            Path::new(global_argument),
            std::fs::canonicalize(&global_path).unwrap()
        );
        assert!(Path::new(function_argument).is_absolute());
        assert!(Path::new(map_argument).is_absolute());
        assert!(Path::new(global_argument).is_absolute());
        assert!(Path::new(function_argument).is_file());
        assert!(Path::new(map_argument).is_file());
        assert!(Path::new(global_argument).is_file());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn prepared_pass2_map_rejects_missing_and_non_regular_paths() {
        let root =
            PathBuf::from("target").join(format!("pme_task8r_invalid_maps_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let missing = root.join("missing.json");

        assert!(PreparedPass2Map::new(&missing, NonZeroUsize::new(1).unwrap()).is_err());
        assert!(PreparedPass2Map::new(&root, NonZeroUsize::new(1).unwrap()).is_err());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn prepared_symbol_map_rejects_noop_function_input() {
        let root = tempfile::tempdir().unwrap();
        let map = root.path().join("symbol_map.json");
        let functions = root.path().join("functions.json");
        let image = root.path().join("02_MAIN.bin");
        std::fs::write(&map, b"map").unwrap();
        std::fs::write(&functions, b"functions").unwrap();
        std::fs::write(&image, b"image").unwrap();

        let error =
            PreparedSymbolPass2Map::new(&map, &functions, &image, "02_MAIN", 1, 0, Vec::new())
                .expect_err("preserve-only executions and zero creations must not schedule pass 2");

        assert!(
            error
                .to_string()
                .contains("no applicable decisions or creations")
        );
    }

    #[test]
    fn validated_headless_process_args_rejects_late_disappearance() {
        for missing_map in ["functions.json", "globals.json", "symbol_map.json"] {
            let root = std::env::temp_dir().join(format!(
                "pmetask8rlatemap{}{}",
                missing_map.trim_end_matches(".json"),
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();
            let function_path = root.join("functions.json");
            let global_path = root.join("globals.json");
            let map_path = root.join("symbol_map.json");
            let image_path = root.join("02_MAIN.bin");
            std::fs::write(&function_path, b"functions").unwrap();
            std::fs::write(&global_path, b"globals").unwrap();
            std::fs::write(&map_path, b"map").unwrap();
            std::fs::write(&image_path, b"image").unwrap();
            let input = Pass2Input {
                function_map: Some(
                    PreparedSymbolPass2Map::new(
                        &map_path,
                        &relative_spelling_from_current_dir(&function_path),
                        &image_path,
                        "02_MAIN",
                        1,
                        1,
                        Vec::new(),
                    )
                    .unwrap(),
                ),
                global_map: Some(
                    PreparedPass2Map::new(
                        &relative_spelling_from_current_dir(&global_path),
                        NonZeroUsize::new(2).unwrap(),
                    )
                    .unwrap(),
                ),
                global_types_map: None,
                ..Pass2Input::default()
            };
            std::fs::remove_file(root.join(missing_map)).unwrap();
            let mut spawn_called = false;

            let result = headless_process_args("/out", "02_MAIN", &input).inspect(|args| {
                spawn_called = args.is_some();
            });

            let error = result.unwrap_err();
            assert!(error.to_string().contains("no longer"));
            assert!(
                !spawn_called,
                "invalid combined input reached the spawn boundary"
            );
            for survivor in ["functions.json", "globals.json", "symbol_map.json"] {
                if survivor != missing_map {
                    assert!(root.join(survivor).is_file());
                }
            }
            let _ = std::fs::remove_dir_all(&root);
        }
    }

    #[test]
    fn validated_headless_process_args_rejects_late_content_change() {
        let root = tempfile::tempdir().unwrap();
        let function_path = root.path().join("functions.json");
        let map_path = root.path().join("symbol_map.json");
        let image_path = root.path().join("02_MAIN.bin");
        std::fs::write(&function_path, b"functions").unwrap();
        std::fs::write(&map_path, b"original map").unwrap();
        std::fs::write(&image_path, b"image").unwrap();
        let input = Pass2Input {
            function_map: Some(
                PreparedSymbolPass2Map::new(
                    &map_path,
                    &function_path,
                    &image_path,
                    "02_MAIN",
                    1,
                    1,
                    Vec::new(),
                )
                .unwrap(),
            ),
            ..Pass2Input::default()
        };
        std::fs::write(&map_path, b"changed map").unwrap();

        let error = headless_process_args("/out", "02_MAIN", &input)
            .expect_err("retained map content changed after preparation");

        assert!(error.to_string().contains("contents changed"));
    }

    #[test]
    fn pass2_runtime_results_clear_even_when_component_is_not_scheduled() {
        let mut image = ImageResult {
            label: "02_MAIN".into(),
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
            image_start: 0,
            image_len: 1,
            thumb_error: None,
            terminal_error: None,
            pass2_applied: Some(7),
            pass2_creation_plan: None,
            pass2_thumb_names: Some(AppliedThumbNames {
                candidates: 1,
                created: 1,
                reapplied: 0,
                skipped_existing: 0,
                skipped_collision: 0,
            }),
            pass2_error: Some("stale".into()),
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
            exception_state: RuntimeExceptionState::Unmanaged,
            exception_roots_applied: None,
            exception_error: None,
            pal_applied: None,
        };
        reset_pass2_runtime_results(&mut image);

        assert_eq!(image.pass2_applied, None);
        assert_eq!(image.pass2_thumb_names, None);
        assert_eq!(image.pass2_error, None);
    }

    fn relative_spelling_from_current_dir(path: &Path) -> PathBuf {
        let current_dir = std::env::current_dir().unwrap();
        let current_components: Vec<_> = current_dir.components().collect();
        let target_components: Vec<_> = path.components().collect();
        let common = current_components
            .iter()
            .zip(&target_components)
            .take_while(|(left, right)| left == right)
            .count();
        assert!(
            common > 0,
            "temporary path and current directory have no common root"
        );

        let mut relative = PathBuf::new();
        for _ in common..current_components.len() {
            relative.push("..");
        }
        for component in &target_components[common..] {
            relative.push(component.as_os_str());
        }
        relative
    }

    fn pass2_test_root(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("pme_{tag}_{}", std::process::id()));
        std::fs::create_dir_all(root.join("scripts")).unwrap();
        root
    }

    fn pass2_test_map(name: &str, count: usize) -> Option<PreparedPass2Map> {
        let count = NonZeroUsize::new(count)?;
        let dir = PathBuf::from("target").join("pme_task8r_pass2_args");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, name).unwrap();
        Some(PreparedPass2Map::new(&path, count).unwrap())
    }

    /// A `PreparedSymbolPass2Map` over three dummy retained files; the hashes
    /// are computed from the dummy bytes so argv pins can assert them.
    fn pass2_symbol_test_map(tag: &str, label: &str) -> PreparedSymbolPass2Map {
        let dir = PathBuf::from("target").join(format!("pme_task11_pass2_args_{tag}"));
        std::fs::create_dir_all(&dir).unwrap();
        let map_path = dir.join(format!("{tag}_map.json"));
        let functions_path = dir.join(format!("{tag}_functions.json"));
        let image_path = dir.join(format!("{tag}_image.bin"));
        std::fs::write(&map_path, format!("{tag} map bytes")).unwrap();
        std::fs::write(&functions_path, format!("{tag} functions bytes")).unwrap();
        std::fs::write(&image_path, format!("{tag} image bytes")).unwrap();
        PreparedSymbolPass2Map::new(
            &map_path,
            &functions_path,
            &image_path,
            label,
            3,
            3,
            Vec::new(),
        )
        .unwrap()
    }

    fn pass2_input(function_count: usize, global_count: usize) -> Pass2Input {
        Pass2Input {
            function_map: (function_count > 0).then(|| pass2_symbol_test_map("input", "02_MAIN")),
            global_map: pass2_test_map("globals.json", global_count),
            global_types_map: None,
            ..Pass2Input::default()
        }
    }

    #[test]
    fn pass2_args_wire_twelve_apply_symbols_and_ten_export_arguments() {
        let symbol_map = pass2_symbol_test_map("wired", "02_MAIN");
        let input = Pass2Input {
            function_map: Some(symbol_map.clone()),
            global_map: pass2_test_map("globals.json", 1),
            global_types_map: None,
            ..Pass2Input::default()
        };
        let args = headless_process_args("/out", "02_MAIN", &input)
            .unwrap()
            .expect("non-empty prepared input must invoke pass two");
        let functions_path = symbol_map.functions.path().to_string_lossy().into_owned();
        let map_path = symbol_map.path().to_string_lossy().into_owned();

        let thumb_at = args
            .iter()
            .position(|arg| arg == "ApplyThumbNames.java")
            .unwrap();
        let expected_thumb = [
            "/out",
            "02_MAIN",
            symbol_map.image_blake3(),
            "none",
            "-",
            "-",
            &functions_path,
            symbol_map.functions_blake3(),
            &map_path,
            symbol_map.map_blake3(),
        ];
        assert_eq!(
            &args[thumb_at + 1..=thumb_at + 10],
            expected_thumb,
            "ApplyThumbNames must consume exactly its ten preflight arguments"
        );
        assert_eq!(args[thumb_at + 11], "-postScript");

        let apply_at = args
            .iter()
            .position(|arg| arg == "ApplySymbols.java")
            .unwrap();
        let expected_apply = [
            "/out",
            "02_MAIN",
            symbol_map.image_blake3(),
            "none",
            "-",
            "none",
            "-",
            "-",
            &functions_path,
            symbol_map.functions_blake3(),
            &map_path,
            symbol_map.map_blake3(),
        ];
        assert_eq!(
            &args[apply_at + 1..=apply_at + 12],
            expected_apply,
            "ApplySymbols must consume exactly its twelve arguments"
        );
        assert_eq!(args[apply_at + 13], "-postScript");

        let export_at = args
            .iter()
            .position(|arg| arg == "ExportDecomp.java")
            .unwrap();
        let expected_export = [
            "/out/export/02_MAIN",
            "/out",
            "02_MAIN",
            "none",
            "-",
            "none",
            "-",
            "-",
            &map_path,
            symbol_map.map_blake3(),
        ];
        assert_eq!(
            &args[export_at + 1..=export_at + 10],
            expected_export,
            "ExportDecomp must consume exactly its ten arguments"
        );
        let apply_position = apply_at;
        let thumb_position = thumb_at;
        assert!(
            thumb_position < apply_position
                && args
                    .iter()
                    .position(|arg| arg == "ApplyGlobals.java")
                    .is_some_and(|globals| globals > apply_position)
                && apply_position < export_at,
            "order must be ApplyThumbNames -> ApplySymbols -> ApplyGlobals -> ExportDecomp"
        );
    }

    #[test]
    fn exception_pass2_uses_one_shared_phase_validator() {
        for required in [
            "enum Pass2MapPhase",
            "BEFORE_MUTATION",
            "AFTER_MUTATION",
            "TERMINAL",
            "class Pass2MapState",
        ] {
            assert!(
                EXCEPTION_ROOTS_SUPPORT_JAVA.contains(required),
                "ExceptionRootsSupport is missing {required}"
            );
        }
        assert!(
            APPLY_THUMB_NAMES_JAVA.contains("Pass2MapPhase.BEFORE_MUTATION"),
            "ApplyThumbNames must preflight complete exception state before mutation"
        );
        assert!(
            APPLY_SYMBOLS_JAVA.contains("Pass2MapPhase.BEFORE_MUTATION")
                && APPLY_SYMBOLS_JAVA.contains("Pass2MapPhase.AFTER_MUTATION"),
            "ApplySymbols must reuse the shared before/after state"
        );
        assert!(
            EXPORT_DECOMP_JAVA.contains("retainTerminalPass2MapState")
                && EXPORT_DECOMP_JAVA.contains("Pass2MapPhase.TERMINAL")
                && !EXPORT_DECOMP_JAVA.contains("readSymbolMapForExport"),
            "ExportDecomp must retain the shared terminal state instead of using a partial map read"
        );
    }

    #[test]
    fn pass2_args_pass1_export_argv_is_dash_none_in_every_mode() {
        // Pass 1 and the generated single-pass script receive `-`/`none`: no
        // symbol map, literal `none` hash, identity `none`, manifest `-`; the
        // scatter argument mirrors ApplyScatterLoad scheduling.
        for (mode, scatter) in [("tighten", None), ("datamark", None)] {
            let args = headless_args(
                "/out",
                "00_BOOT",
                "ARM:LE:32:v7",
                0,
                scatter,
                None,
                None,
                &[],
                mode,
            );
            let export_at = args
                .iter()
                .position(|arg| arg == "ExportDecomp.java")
                .unwrap();
            assert_eq!(
                &args[export_at + 1..=export_at + 10],
                [
                    "/out/export/00_BOOT",
                    "/out",
                    "00_BOOT",
                    "none",
                    "-",
                    "none",
                    "-",
                    "-",
                    "-",
                    "none",
                ]
            );
        }
        // A scheduled scatter map is passed through to ExportDecomp.
        let args = headless_args(
            "/out",
            "02_MAIN",
            "ARM:LE:32:v7",
            SCATTER_BASE,
            Some("scatter/02_MAIN/load_map.json"),
            None,
            None,
            &[],
            "tighten",
        );
        let export_at = args
            .iter()
            .position(|arg| arg == "ExportDecomp.java")
            .unwrap();
        assert_eq!(args[export_at + 8], "/out/scatter/02_MAIN/load_map.json");
    }

    #[test]
    fn completion_marker_v4_binds_exception_pal_and_symbol_map() {
        assert_eq!(
            export_completion_marker("none", "none", "none"),
            b"pixel-modem-extractor-ghidra-export-v4\nexception_roots=none\npal_tasks=none\nsymbol_map=none\n",
        );
        let identity = "v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:7:1";
        assert_eq!(
            export_completion_marker("none", identity, "none"),
            format!(
                "pixel-modem-extractor-ghidra-export-v4\nexception_roots=none\npal_tasks={identity}\nsymbol_map=none\n"
            )
            .as_bytes(),
        );
        let hash = "b".repeat(64);
        assert_eq!(
            export_completion_marker("none", identity, &hash),
            format!(
                "pixel-modem-extractor-ghidra-export-v4\nexception_roots=none\npal_tasks={identity}\nsymbol_map={hash}\n"
            )
            .as_bytes(),
        );

        // The generated turnkey script constructs the same expected bytes for
        // its PAL-none single-pass invocations.
        let buf = craft_modem_bin(&[("BOOT", 0x0, 1, &[0u8; 4])]);
        let dir = std::env::temp_dir().join(format!("pme_marker_v4_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let modem = dir.join("modem.bin");
        std::fs::write(&modem, &buf).unwrap();
        let out = dir.join("out");
        run(&modem, &generation_opts(None), &out).unwrap();
        let script = std::fs::read_to_string(out.join("run_ghidra.sh")).unwrap();
        assert!(
            script.contains(
                "printf '%s\\n' 'pixel-modem-extractor-ghidra-export-v4' 'exception_roots=none' 'pal_tasks=none' 'symbol_map=none'"
            ),
            "run_ghidra.sh must compare the exact v4 marker:\n{script}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn export_completion_marker_binds_exception_roots() {
        assert_eq!(
            export_completion_marker("v1:roots", "v1:pal", "maphash"),
            b"pixel-modem-extractor-ghidra-export-v4\nexception_roots=v1:roots\npal_tasks=v1:pal\nsymbol_map=maphash\n"
        );
    }

    #[test]
    fn completion_marker_rejects_stale_inputs() {
        let root = tempfile::tempdir().unwrap();
        let run = GhidraExportRun::new(root.path(), "02_MAIN");
        std::fs::create_dir_all(&run.directory).unwrap();
        for name in GHIDRA_EXPORT_FILES {
            std::fs::write(run.directory.join(name), b"current\n").unwrap();
        }
        let identity = "v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:2:0";
        let hash = "c".repeat(64);

        // A stale PAL identity under a marker that binds a map hash.
        std::fs::write(
            &run.completion,
            export_completion_marker("none", identity, &hash),
        )
        .unwrap();
        assert!(run.validate_current("none", identity, &hash).is_ok());
        assert!(run.validate_current("v1:stale", identity, &hash).is_err());
        assert!(run.validate_current("none", "none", &hash).is_err());
        assert!(run.validate_current("none", identity, "none").is_err());
        // A truncated or extended marker never normalizes through.
        let exact = export_completion_marker("none", "none", "none");
        std::fs::write(&run.completion, &exact[..exact.len() - 1]).unwrap();
        assert!(run.validate_current("none", "none", "none").is_err());
        std::fs::write(&run.completion, [exact.as_slice(), b"trailing\n"].concat()).unwrap();
        assert!(run.validate_current("none", "none", "none").is_err());
    }

    #[test]
    fn pass2_args_pass2_property_binds_map_functions_and_execution_count() {
        let symbol_map = pass2_symbol_test_map("property", "02_MAIN");
        assert_eq!(
            symbol_map.pass2_property(),
            format!(
                "v3:{}:{}:3",
                symbol_map.map_blake3(),
                symbol_map.functions_blake3()
            )
        );
    }

    #[test]
    fn pass2_args_reject_map_built_for_a_different_label() {
        let mismatched = pass2_symbol_test_map("label", "03_APM");
        let input = Pass2Input {
            function_map: Some(mismatched),
            ..Pass2Input::default()
        };
        let error = headless_process_args("/out", "02_MAIN", &input)
            .unwrap_err()
            .to_string();
        assert!(error.contains("03_APM"), "{error}");
    }

    #[test]
    fn pass2_args_pass_pal_identity_and_manifests_through() {
        let root = pass2_test_root("pal_args");
        let manifest = root.join("tasks.json");
        let scatter = root.join("load_map.json");
        std::fs::write(&manifest, b"manifest").unwrap();
        std::fs::write(&scatter, b"scatter").unwrap();
        let identity = "v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:2:1";
        let manifest_arg = manifest.to_string_lossy().into_owned();
        let scatter_arg = scatter.to_string_lossy().into_owned();
        let input = Pass2Input {
            function_map: Some(pass2_symbol_test_map("palwired", "02_MAIN")),
            pal_identity: identity.to_string(),
            pal_manifest: Some(manifest.clone()),
            scatter_manifest: Some(scatter.clone()),
            ..Pass2Input::default()
        };
        let args = headless_process_args(root.to_str().unwrap(), "02_MAIN", &input)
            .unwrap()
            .unwrap();
        let apply_at = args
            .iter()
            .position(|arg| arg == "ApplySymbols.java")
            .unwrap();
        assert_eq!(
            &args[apply_at + 6..=apply_at + 8],
            [identity, manifest_arg.as_str(), scatter_arg.as_str()]
        );
        let export_at = args
            .iter()
            .position(|arg| arg == "ExportDecomp.java")
            .unwrap();
        assert_eq!(
            &args[export_at + 6..=export_at + 8],
            [identity, manifest_arg.as_str(), scatter_arg.as_str()]
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn pass2_args_pass_exception_identity_and_manifest_through() {
        let root = pass2_test_root("exception_args");
        let manifest = root.join("roots.json");
        std::fs::write(&manifest, b"manifest").unwrap();
        let identity = format!(
            "v1:{}:1:1",
            crate::manifest::blake3_file(&manifest).unwrap()
        );
        let manifest_arg = manifest.to_string_lossy().into_owned();
        let input = Pass2Input {
            function_map: Some(pass2_symbol_test_map("exception_wired", "02_MAIN")),
            exception_identity: identity.clone(),
            exception_manifest: Some(manifest.clone()),
            ..Pass2Input::default()
        };

        let args = headless_process_args(root.to_str().unwrap(), "02_MAIN", &input)
            .unwrap()
            .unwrap();
        let apply_at = args
            .iter()
            .position(|arg| arg == "ApplySymbols.java")
            .unwrap();
        assert_eq!(
            &args[apply_at + 4..=apply_at + 5],
            [identity.as_str(), manifest_arg.as_str()]
        );
        let export_at = args
            .iter()
            .position(|arg| arg == "ExportDecomp.java")
            .unwrap();
        assert_eq!(
            &args[export_at + 4..=export_at + 5],
            [identity.as_str(), manifest_arg.as_str()]
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn pass2_args_wires_globals_only_then_export() {
        let input = pass2_input(0, 1);
        let args = headless_process_args("/out", "02_MAIN", &input)
            .unwrap()
            .expect("prepared global input must invoke pass two");
        let global_path = input.global_map.as_ref().unwrap().path().to_string_lossy();

        assert_eq!(
            args,
            vec![
                "/out/ghidra_project",
                "pixel-modem",
                "-process",
                "02_MAIN",
                "-noanalysis",
                "-scriptPath",
                "/out/scripts",
                "-postScript",
                "ApplyGlobals.java",
                global_path.as_ref(),
                "-postScript",
                "ExportDecomp.java",
                "/out/export/02_MAIN",
                "/out",
                "02_MAIN",
                "none",
                "-",
                "none",
                "-",
                "-",
                "-",
                "none",
            ]
        );
        assert!(!args.iter().any(|argument| argument == "ApplySymbols.java"));
    }

    #[test]
    fn headless_process_args_skips_when_prepared_counts_are_zero() {
        assert!(
            headless_process_args("/out", "02_MAIN", &pass2_input(0, 0))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn pass2_args_insert_apply_global_types_between_globals_and_export() {
        let root = pass2_test_root("gt_args");
        let input = Pass2Input {
            function_map: Some(pass2_symbol_test_map("gt", "02_MAIN")),
            global_map: pass2_test_map("globals.json", 1),
            global_types_map: pass2_test_map("global_types.json", 1),
            ..Pass2Input::default()
        };
        let args = headless_process_args(root.to_str().unwrap(), "02_MAIN", &input)
            .unwrap()
            .unwrap();
        let joined = args.join(" ");
        let g = joined.find("ApplyGlobals.java").unwrap();
        let t = joined.find("ApplyGlobalTypes.java").unwrap();
        let e = joined.find("ExportDecomp.java").unwrap();
        assert!(
            g < t && t < e,
            "order must be ApplyGlobals -> ApplyGlobalTypes -> ExportDecomp"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn pass2_args_present_for_types_only_input() {
        let root = pass2_test_root("gt_only");
        let input = Pass2Input {
            function_map: None,
            global_map: None,
            global_types_map: pass2_test_map("global_types.json", 1),
            ..Pass2Input::default()
        };
        assert!(
            headless_process_args(root.to_str().unwrap(), "02_MAIN", &input)
                .unwrap()
                .is_some()
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// Omitting `global_types_map` from the absent-label preflight loses the
    /// promised per-label failure and leaves only an aggregate count mismatch.
    #[test]
    fn global_types_only_absent_pass1_label_gets_explicit_failed_outcome() {
        let dir = tempfile::tempdir().unwrap();
        let ghidra_home = dir.path().join("fake-ghidra");
        std::fs::create_dir_all(ghidra_home.join("support")).unwrap();
        std::fs::write(ghidra_home.join("support/analyzeHeadless"), b"unused").unwrap();
        let out = dir.path().join("out");
        std::fs::create_dir_all(&out).unwrap();
        let type_map_path = dir.path().join("global-types.json");
        std::fs::write(&type_map_path, b"type map").unwrap();
        let input = Pass2Input {
            global_types_map: Some(
                PreparedPass2Map::new(&type_map_path, NonZeroUsize::new(1).unwrap()).unwrap(),
            ),
            ..Pass2Input::default()
        };
        let report = DecompileReport {
            images: Vec::new(),
            spec_path: out.join("ghidra_load.json"),
            current_exports: BTreeSet::new(),
            runtime_scatter: HashMap::new(),
            runtime_exception_roots: HashMap::new(),
            runtime_tasks: HashMap::new(),
        };
        let mut opts = generation_opts(None);
        opts.run = true;
        opts.ghidra_home = Some(ghidra_home);

        let result = run_two_pass(
            report,
            &opts,
            &out,
            &HashMap::from([("07_MISSING".to_string(), input)]),
        )
        .unwrap();

        assert_eq!(
            result.outcomes.get("07_MISSING"),
            Some(&Pass2ProcessOutcome::Failed(
                "input label absent from pass-1 report".to_string()
            ))
        );
    }

    #[test]
    fn parse_pass2_summary_reads_applied_count() {
        let stdout = "...\nApplySymbols: image=02_MAIN applied 42 names, 7 plate comments over 6 executions\n";
        assert_eq!(parse_pass2_summary(stdout), Some(42));
        // Missing / malformed summary -> None (caller treats as "no info").
        assert_eq!(parse_pass2_summary("nothing useful\n"), None);
        assert_eq!(parse_pass2_summary(""), None);
    }

    #[test]
    fn parse_apply_pal_tasks_summary_is_strict() {
        let identity = "v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:2:0";
        let ok = format!(
            "ApplyPalTasks: {{\"image\":\"02_MAIN\",\"status\":\"ok\",\"identity\":\"{identity}\",\"tasks\":2,\"entries\":2,\"functions_created\":2,\"functions_existing\":0,\"names_applied\":2,\"names_preserved\":0,\"shared_entries\":0}}"
        );
        assert_eq!(
            parse_apply_pal_tasks_summary(&ok, "02_MAIN", identity).unwrap(),
            AppliedPalTasks {
                tasks: 2,
                entries: 2,
                functions_created: 2,
                functions_existing: 0,
                names_applied: 2,
                names_preserved: 0,
                shared_entries: 0,
            }
        );

        // Missing, duplicate, malformed, wrong-image, wrong-identity, and
        // non-ok summaries are each the typed rejection.
        assert_eq!(
            parse_apply_pal_tasks_summary("no summary here\n", "02_MAIN", identity).unwrap_err(),
            "missing ApplyPalTasks summary"
        );
        assert!(
            parse_apply_pal_tasks_summary(&format!("{ok}\n{ok}\n"), "02_MAIN", identity)
                .unwrap_err()
                .contains("duplicate")
        );
        assert!(
            parse_apply_pal_tasks_summary("ApplyPalTasks: {not json}", "02_MAIN", identity)
                .unwrap_err()
                .contains("malformed")
        );
        assert!(
            parse_apply_pal_tasks_summary(&ok, "00_BOOT", identity)
                .unwrap_err()
                .contains("does not match")
        );
        assert!(
            parse_apply_pal_tasks_summary(&ok, "02_MAIN", "none")
                .unwrap_err()
                .contains("identity")
        );
        let error_status = format!(
            "ApplyPalTasks: {{\"image\":\"02_MAIN\",\"status\":\"error\",\"identity\":\"{identity}\",\"tasks\":0,\"entries\":0,\"functions_created\":0,\"functions_existing\":0,\"names_applied\":0,\"names_preserved\":0,\"shared_entries\":0}}"
        );
        assert!(
            parse_apply_pal_tasks_summary(&error_status, "02_MAIN", identity)
                .unwrap_err()
                .contains("is not")
        );
        // A counter that is not an unsigned integer rejects the summary.
        let bad_count = format!(
            "ApplyPalTasks: {{\"image\":\"02_MAIN\",\"status\":\"ok\",\"identity\":\"{identity}\",\"tasks\":\"two\",\"entries\":2,\"functions_created\":2,\"functions_existing\":0,\"names_applied\":2,\"names_preserved\":0,\"shared_entries\":0}}"
        );
        assert!(
            parse_apply_pal_tasks_summary(&bad_count, "02_MAIN", identity)
                .unwrap_err()
                .contains("tasks")
        );
    }

    #[test]
    fn valid_exception_summary_survives_pal_summary_failure() {
        let manifest_blake3 = "a".repeat(64);
        let roots_identity = format!("v1:{manifest_blake3}:1:7");
        let roots = MaterializedExceptionRoots {
            relative_path: "exception_roots/02_MAIN/roots.json".into(),
            blake3: manifest_blake3,
            identity: roots_identity.clone(),
            tables: 1,
            roots: 7,
        };
        let pal_identity = format!("v1:{}:2:2", "b".repeat(64));
        let stdout = format!(
            "{}\nApplyPalTasks: {{not json}}",
            exception_pass2::test_summary_for("02_MAIN", &roots_identity)
        );

        let coordinated = coordinate_application_summaries(
            &stdout,
            "02_MAIN",
            Some(&roots),
            Some(PalScriptPlan {
                manifest: "pal_tasks/02_MAIN/tasks.json",
                identity: &pal_identity,
            }),
        );

        let applied = coordinated.exception_roots_applied.as_ref().unwrap();
        assert_eq!(applied.entries(), 7);
        assert_eq!(applied.functions_created(), 5);
        assert_eq!(applied.functions_existing(), 2);
        assert_eq!(applied.names_applied(), 5);
        assert_eq!(applied.names_preserved(), 1);
        assert_eq!(applied.names_not_requested(), 1);
        assert_eq!(coordinated.exception_error, None);
        assert_eq!(coordinated.pal_applied, None);
        assert!(
            coordinated
                .terminal_error
                .as_deref()
                .is_some_and(|reason| reason.contains("malformed ApplyPalTasks summary"))
        );
    }

    #[test]
    fn valid_pal_summary_survives_exception_summary_failure() {
        let manifest_blake3 = "a".repeat(64);
        let roots = MaterializedExceptionRoots {
            relative_path: "exception_roots/02_MAIN/roots.json".into(),
            blake3: manifest_blake3.clone(),
            identity: format!("v1:{manifest_blake3}:1:7"),
            tables: 1,
            roots: 7,
        };
        let pal_identity = format!("v1:{}:2:2", "b".repeat(64));
        let stdout = format!(
            "ApplyExceptionRoots: {{not json}}\nApplyPalTasks: {{\"image\":\"02_MAIN\",\"status\":\"ok\",\"identity\":\"{pal_identity}\",\"tasks\":2,\"entries\":2,\"functions_created\":2,\"functions_existing\":0,\"names_applied\":2,\"names_preserved\":0,\"shared_entries\":0}}"
        );

        let coordinated = coordinate_application_summaries(
            &stdout,
            "02_MAIN",
            Some(&roots),
            Some(PalScriptPlan {
                manifest: "pal_tasks/02_MAIN/tasks.json",
                identity: &pal_identity,
            }),
        );

        assert_eq!(coordinated.exception_roots_applied, None);
        assert!(
            coordinated
                .exception_error
                .as_deref()
                .is_some_and(|reason| reason.contains("malformed ApplyExceptionRoots summary"))
        );
        assert_eq!(
            coordinated.pal_applied,
            Some(AppliedPalTasks {
                tasks: 2,
                entries: 2,
                functions_created: 2,
                functions_existing: 0,
                names_applied: 2,
                names_preserved: 0,
                shared_entries: 0,
            })
        );
        assert!(
            coordinated
                .terminal_error
                .as_deref()
                .is_some_and(|reason| reason.contains("malformed ApplyExceptionRoots summary"))
        );
    }

    fn ok_globals_summary(
        candidates: usize,
        applied: usize,
        outside: usize,
        missing: usize,
        non_default: usize,
        rejected: usize,
    ) -> String {
        format!(
            "ApplyGlobals: {{\"image\":\"02_MAIN\",\"status\":\"ok\",\
             \"candidates\":{candidates},\"applied\":{applied},\
             \"skipped_outside_memory\":{outside},\"skipped_missing\":{missing},\
             \"skipped_non_default\":{non_default},\"skipped_rejected\":{rejected}}}"
        )
    }

    #[test]
    fn parse_apply_globals_summary_accepts_executed_zero() {
        let summary =
            parse_apply_globals_summary(&ok_globals_summary(0, 0, 0, 0, 0, 0), "02_MAIN").unwrap();

        assert_eq!(
            summary,
            ApplyGlobalsSummary::Ok {
                candidates: 0,
                applied: 0,
                skipped_outside_memory: 0,
                skipped_missing: 0,
                skipped_non_default: 0,
                skipped_rejected: 0,
            }
        );
    }

    #[test]
    fn parse_apply_globals_summary_accepts_conserving_skip_categories() {
        let summary =
            parse_apply_globals_summary(&ok_globals_summary(5, 1, 1, 1, 1, 1), "02_MAIN").unwrap();

        assert_eq!(summary.applied_and_skipped(), Some((1, 4)));
    }

    #[test]
    fn parse_apply_globals_summary_rejects_wrong_image() {
        assert!(
            parse_apply_globals_summary(&ok_globals_summary(0, 0, 0, 0, 0, 0), "04_VSS").is_err()
        );
    }

    #[test]
    fn parse_apply_globals_summary_requires_exactly_one_interface_line() {
        let valid = ok_globals_summary(0, 0, 0, 0, 0, 0);
        assert!(parse_apply_globals_summary("ordinary Ghidra output", "02_MAIN").is_err());
        assert!(parse_apply_globals_summary(&format!("{valid}\n{valid}"), "02_MAIN").is_err());
    }

    #[test]
    fn parse_apply_globals_summary_rejects_malformed_json_and_counts() {
        for stdout in [
            "ApplyGlobals: {",
            "ApplyGlobals: {\"image\":\"02_MAIN\",\"status\":\"ok\",\"candidates\":\"1\",\"applied\":1,\"skipped_outside_memory\":0,\"skipped_missing\":0,\"skipped_non_default\":0,\"skipped_rejected\":0}",
            "ApplyGlobals: {\"image\":\"02_MAIN\",\"status\":\"ok\",\"candidates\":-1,\"applied\":0,\"skipped_outside_memory\":0,\"skipped_missing\":0,\"skipped_non_default\":0,\"skipped_rejected\":0}",
        ] {
            assert!(
                parse_apply_globals_summary(stdout, "02_MAIN").is_err(),
                "malformed summary unexpectedly accepted: {stdout}"
            );
        }
    }

    #[test]
    fn parse_apply_globals_summary_rejects_unknown_status() {
        assert!(
            parse_apply_globals_summary(
                "ApplyGlobals: {\"image\":\"02_MAIN\",\"status\":\"skipped\"}",
                "02_MAIN",
            )
            .is_err()
        );
    }

    #[test]
    fn parse_apply_globals_summary_accepts_only_bounded_error_reason() {
        let summary = parse_apply_globals_summary(
            "ApplyGlobals: {\"image\":\"02_MAIN\",\"status\":\"error\",\"error\":\"bad format\"}",
            "02_MAIN",
        )
        .unwrap();
        assert_eq!(
            summary,
            ApplyGlobalsSummary::Error {
                reason: "bad format".to_string()
            }
        );

        let max_reason = "🛰".repeat(2_048);
        let at_limit = format!(
            "ApplyGlobals: {{\"image\":\"02_MAIN\",\"status\":\"error\",\"error\":\"{max_reason}\"}}"
        );
        assert!(parse_apply_globals_summary(&at_limit, "02_MAIN").is_ok());

        let over_limit = format!(
            "ApplyGlobals: {{\"image\":\"02_MAIN\",\"status\":\"error\",\"error\":\"{}\"}}",
            "🛰".repeat(2_049)
        );
        assert!(parse_apply_globals_summary(&over_limit, "02_MAIN").is_err());
    }

    #[test]
    fn parse_apply_globals_summary_rejects_non_conserving_counts() {
        assert!(
            parse_apply_globals_summary(&ok_globals_summary(6, 1, 1, 1, 1, 1), "02_MAIN").is_err()
        );
    }

    #[test]
    fn parse_thumb_names_summary_reads_conserving_json() {
        let line = r#"ApplyThumbNames: {"image":"02_MAIN","status":"ok","candidates":3,"created":1,"reapplied":0,"skipped_existing":1,"skipped_collision":1}"#;
        assert_eq!(
            parse_apply_thumb_names_summary(line, "02_MAIN", 3).unwrap(),
            AppliedThumbNames {
                candidates: 3,
                created: 1,
                reapplied: 0,
                skipped_existing: 1,
                skipped_collision: 1,
            }
        );
    }

    #[test]
    fn parse_thumb_names_summary_requires_exactly_one_interface_line() {
        let line = r#"ApplyThumbNames: {"image":"02_MAIN","status":"ok","candidates":0,"created":0,"reapplied":0,"skipped_existing":0,"skipped_collision":0}"#;
        assert!(parse_apply_thumb_names_summary("ordinary Ghidra output", "02_MAIN", 0).is_err());
        assert!(parse_apply_thumb_names_summary(&format!("{line}\n{line}"), "02_MAIN", 0).is_err());
    }

    #[test]
    fn parse_thumb_names_summary_rejects_non_conserving_counts() {
        let line = r#"ApplyThumbNames: {"image":"02_MAIN","status":"ok","candidates":4,"created":1,"reapplied":0,"skipped_existing":1,"skipped_collision":1}"#;
        assert!(parse_apply_thumb_names_summary(line, "02_MAIN", 4).is_err());
    }

    #[test]
    fn parse_thumb_names_summary_rejects_non_ok_or_incomplete_payloads() {
        for line in [
            r#"ApplyThumbNames: {"image":"02_MAIN","status":"error","candidates":1,"created":1,"reapplied":0,"skipped_existing":0,"skipped_collision":0}"#,
            r#"ApplyThumbNames: {"image":"02_MAIN","status":"ok","created":1}"#,
            r#"ApplyThumbNames: {"image":"02_MAIN","status":"ok","candidates":1,"created":-1,"reapplied":0,"skipped_existing":0,"skipped_collision":0}"#,
        ] {
            assert!(
                parse_apply_thumb_names_summary(line, "02_MAIN", 1).is_err(),
                "malformed summary unexpectedly accepted: {line}"
            );
        }
    }

    #[test]
    fn parse_thumb_names_summary_rejects_wrong_image_or_candidate_count() {
        let line = r#"ApplyThumbNames: {"image":"02_MAIN","status":"ok","candidates":3,"created":1,"reapplied":0,"skipped_existing":1,"skipped_collision":1}"#;
        assert!(parse_apply_thumb_names_summary(line, "01_MAIN", 3).is_err());
        assert!(parse_apply_thumb_names_summary(line, "02_MAIN", 4).is_err());
    }

    #[test]
    fn parse_apply_global_types_summary_reads_counts() {
        let line = r#"ApplyGlobalTypes: {"image":"02_MAIN","status":"ok","candidates":3,"applied":2,"skipped_outside_memory":0,"skipped_collision":1}"#;
        let s = parse_apply_global_types_summary(line, "02_MAIN").unwrap();
        assert_eq!(s.applied_and_skipped(), Some((2, 1)));
    }

    #[test]
    fn parse_apply_global_types_summary_rejects_wrong_image() {
        let line = r#"ApplyGlobalTypes: {"image":"OTHER","status":"ok","candidates":0,"applied":0,"skipped_outside_memory":0,"skipped_collision":0}"#;
        assert!(parse_apply_global_types_summary(line, "02_MAIN").is_err());
    }

    #[test]
    fn parse_apply_global_types_summary_rejects_error_status_without_string_reason() {
        for stdout in [
            r#"ApplyGlobalTypes: {"image":"02_MAIN","status":"error"}"#,
            r#"ApplyGlobalTypes: {"image":"02_MAIN","status":"error","error":42}"#,
        ] {
            assert!(
                parse_apply_global_types_summary(stdout, "02_MAIN").is_err(),
                "fail-open error summary unexpectedly accepted: {stdout}"
            );
        }
    }

    #[test]
    fn parse_apply_global_types_summary_accepts_only_bounded_error_reason() {
        let summary = parse_apply_global_types_summary(
            r#"ApplyGlobalTypes: {"image":"02_MAIN","status":"error","error":"bad format"}"#,
            "02_MAIN",
        )
        .unwrap();
        assert_eq!(
            summary,
            ApplyGlobalTypesSummary::Error {
                reason: "bad format".to_string()
            }
        );

        let max_reason = "🛰".repeat(2_048);
        let at_limit = format!(
            "ApplyGlobalTypes: {{\"image\":\"02_MAIN\",\"status\":\"error\",\"error\":\"{max_reason}\"}}"
        );
        assert!(parse_apply_global_types_summary(&at_limit, "02_MAIN").is_ok());

        let over_limit = format!(
            "ApplyGlobalTypes: {{\"image\":\"02_MAIN\",\"status\":\"error\",\"error\":\"{}\"}}",
            "🛰".repeat(2_049)
        );
        assert!(parse_apply_global_types_summary(&over_limit, "02_MAIN").is_err());
    }

    #[test]
    fn headless_command_pins_unique_space_free_state_dirs() {
        let state = GhidraStateHome::new().unwrap();
        let args = vec!["/tmp/pme-out/ghidra_project".to_string()];
        let cmd = headless_command(
            Path::new("/opt/ghidra/support/analyzeHeadless"),
            &args,
            &state,
            None,
        );

        let spelling = state.path.to_string_lossy();
        assert!(
            !spelling.bytes().any(|byte| byte == b' ' || byte == b'\t'),
            "state home must be space-free: {spelling}"
        );
        assert!(state.path.is_dir());
        assert_eq!(
            cmd.get_envs()
                .find(|(key, _)| *key == std::ffi::OsStr::new("XDG_CONFIG_HOME")),
            Some((
                std::ffi::OsStr::new("XDG_CONFIG_HOME"),
                Some(state.config_home().as_os_str())
            ))
        );
        assert_eq!(
            cmd.get_envs()
                .find(|(key, _)| *key == std::ffi::OsStr::new("XDG_CACHE_HOME")),
            Some((
                std::ffi::OsStr::new("XDG_CACHE_HOME"),
                Some(state.cache_home().as_os_str())
            ))
        );

        // Each state home is unique, and drop removes the directory.
        let path = state.path.clone();
        let second = GhidraStateHome::new().unwrap();
        assert_ne!(path, second.path);
        drop(state);
        assert!(!path.exists(), "drop must remove the state home");
    }

    #[test]
    fn java_home_from_ghidra_run_reads_homebrew_pin() {
        let base = std::env::temp_dir().join(format!("pme_jh_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        // A real directory to stand in for the JDK (must exist to be accepted).
        let jdk = base.join("jdk21");
        std::fs::create_dir_all(&jdk).unwrap();
        let wrapper = base.join("ghidraRun");
        std::fs::write(
            &wrapper,
            format!(
                "#!/bin/bash\nJAVA_HOME=\"${{JAVA_HOME:-{}}}\" exec \"/x/libexec/ghidraRun\" \"$@\"\n",
                jdk.display()
            ),
        )
        .unwrap();
        assert_eq!(java_home_from_ghidra_run(&wrapper), Some(jdk.clone()));

        // Unpinned (upstream-style) wrapper -> None.
        let plain = base.join("ghidraRun_plain");
        std::fs::write(&plain, b"#!/bin/bash\nexec ghidraRun \"$@\"\n").unwrap();
        assert!(java_home_from_ghidra_run(&plain).is_none());

        // Pinned but nonexistent path -> None (never inject a bad JAVA_HOME).
        let missing = base.join("ghidraRun_missing");
        std::fs::write(
            &missing,
            b"#!/bin/bash\nJAVA_HOME=\"${JAVA_HOME:-/no/such/jdk/here}\" exec x\n",
        )
        .unwrap();
        assert!(java_home_from_ghidra_run(&missing).is_none());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn resolve_java_home_never_overrides_existing_env() {
        let base = std::env::temp_dir().join(format!("pme_rjh_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let jdk = base.join("jdk");
        std::fs::create_dir_all(&jdk).unwrap();
        let wrapper = base.join("ghidraRun");
        std::fs::write(
            &wrapper,
            format!(
                "#!/bin/bash\nJAVA_HOME=\"${{JAVA_HOME:-{}}}\" exec x\n",
                jdk.display()
            ),
        )
        .unwrap();

        // env already sets JAVA_HOME -> do not override, regardless of the wrapper.
        assert!(resolve_java_home(Some(OsString::from("/whatever")), Some(&wrapper)).is_none());
        // env unset + pinned wrapper -> use the wrapper's JDK.
        assert_eq!(resolve_java_home(None, Some(&wrapper)), Some(jdk.clone()));
        // env unset + no wrapper -> None.
        assert!(resolve_java_home(None, None).is_none());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn headless_command_injects_java_home_when_given() {
        let state = GhidraStateHome::new().unwrap();
        let args = vec!["/tmp/pme-out/ghidra_project".to_string()];
        let jh = PathBuf::from("/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home");
        let cmd = headless_command(
            Path::new("/opt/ghidra/support/analyzeHeadless"),
            &args,
            &state,
            Some(&jh),
        );
        assert_eq!(
            cmd.get_envs()
                .find(|(k, _)| *k == std::ffi::OsStr::new("JAVA_HOME")),
            Some((std::ffi::OsStr::new("JAVA_HOME"), Some(jh.as_os_str())))
        );

        // Without a java_home, no JAVA_HOME override is added to the child.
        let cmd = headless_command(
            Path::new("/opt/ghidra/support/analyzeHeadless"),
            &args,
            &state,
            None,
        );
        assert!(
            cmd.get_envs()
                .all(|(k, _)| k != std::ffi::OsStr::new("JAVA_HOME"))
        );
    }

    #[test]
    fn generation_only_hint_mentions_radare2_thumb_regions() {
        let hint = generation_only_hint(Path::new("/tmp/pme-out"));

        assert!(hint.contains("--run"), "hint:\n{hint}");
        assert!(hint.contains("Ghidra"), "hint:\n{hint}");
        assert!(hint.contains("radare2"), "hint:\n{hint}");
        assert!(hint.contains("Thumb"), "hint:\n{hint}");
        assert!(hint.contains("Ghidra-only"), "hint:\n{hint}");
    }

    #[test]
    fn ghidra_java_options_preserve_existing_and_pin_state_home_dirs() {
        let state = GhidraStateHome::new().unwrap();
        let options =
            ghidra_java_options(&state, Some(std::ffi::OsStr::new("-Dexisting.option=1")));
        let options = options.to_string_lossy();

        assert!(
            options.contains("-Dexisting.option=1"),
            "options: {options}"
        );
        let config = format!(
            "-Dapplication.settingsdir={}",
            state.config_home().display()
        );
        let cache = format!("-Dapplication.cachedir={}", state.cache_home().display());
        let temp = format!("-Dapplication.tempdir={}", state.temp_home().display());
        assert!(options.contains(&config), "options: {options}");
        assert!(options.contains(&cache), "options: {options}");
        assert!(options.contains(&temp), "options: {options}");
        assert!(
            options.contains(&format!("-Djava.io.tmpdir={}", state.temp_home().display())),
            "options: {options}"
        );
    }

    #[test]
    fn thumb_regions_detect_large_high_entropy_blob() {
        // 0.5 MiB zeros | 1.5 MiB high-entropy (0..=255 repeating) | 0.5 MiB zeros
        let mut buf = vec![0u8; 512 * 1024];
        buf.extend((0u32..1536 * 1024).map(|i| (i % 256) as u8));
        buf.resize(buf.len() + 512 * 1024, 0);

        let regions = thumb_regions(&buf, 0x4001_0000);
        assert_eq!(regions.len(), 1, "exactly one dense Thumb region");
        let (addr, len) = regions[0];
        assert_eq!(addr, 0x4001_0000 + 512 * 1024); // starts after the zero prefix
        assert_eq!(len, 1536 * 1024); // the 1.5 MiB blob

        // nothing for an all-zero buffer, nor for a sub-1MiB high-entropy span
        assert!(thumb_regions(&[0u8; 4096], 0).is_empty());
        let small: Vec<u8> = (0u32..256 * 1024).map(|i| (i % 256) as u8).collect();
        assert!(thumb_regions(&small, 0).is_empty());
    }

    #[test]
    fn should_kill_tighten_returns_none_under_budget() {
        let budget = TightenBudget {
            wall_clock_multiplier: 4,
            log_spam_max: 100_000,
        };
        // 60s elapsed vs. 100s baseline * 4 = 400s budget -> well under.
        assert_eq!(
            should_kill_tighten(
                std::time::Duration::from_secs(60),
                1000,
                &budget,
                std::time::Duration::from_secs(100),
                None,
            ),
            None
        );
    }

    #[test]
    fn should_kill_tighten_returns_wall_clock_over_budget() {
        let budget = TightenBudget {
            wall_clock_multiplier: 4,
            log_spam_max: 100_000,
        };
        // 600s elapsed vs. 100s baseline * 4 = 400s budget -> over.
        assert!(matches!(
            should_kill_tighten(
                std::time::Duration::from_secs(600),
                1000,
                &budget,
                std::time::Duration::from_secs(100),
                None,
            ),
            Some(KillReason::WallClock)
        ));
    }

    #[test]
    fn should_kill_tighten_returns_log_spam_over_threshold() {
        let budget = TightenBudget {
            wall_clock_multiplier: 4,
            log_spam_max: 100_000,
        };
        // Wall-clock well under (10s vs. 5s * 4 = 20s); repair-log count over.
        assert!(matches!(
            should_kill_tighten(
                std::time::Duration::from_secs(10),
                200_000,
                &budget,
                std::time::Duration::from_secs(5),
                None,
            ),
            Some(KillReason::LogSpam)
        ));
    }

    #[test]
    fn should_kill_tighten_override_replaces_baseline_multiplier() {
        let budget = TightenBudget {
            wall_clock_multiplier: 4,
            log_spam_max: 100_000,
        };
        // Override of 30s wins over baseline * multiplier (which would be 400s);
        // 60s elapsed > 30s -> kill on wall-clock.
        assert!(matches!(
            should_kill_tighten(
                std::time::Duration::from_secs(60),
                0,
                &budget,
                std::time::Duration::from_secs(100),
                Some(std::time::Duration::from_secs(30)),
            ),
            Some(KillReason::WallClock)
        ));
        // Override of 90s; 60s elapsed; still under -> None.
        assert_eq!(
            should_kill_tighten(
                std::time::Duration::from_secs(60),
                0,
                &budget,
                std::time::Duration::from_secs(100),
                Some(std::time::Duration::from_secs(90)),
            ),
            None
        );
    }

    #[test]
    fn tighten_baseline_for_dense_thumb_bytes_floor_60s_for_small_input() {
        // Sub-1-MiB inputs floor at the 60 s heuristic so a tiny region
        // doesn't collapse the budget below the watch's calibrated minimum.
        assert_eq!(
            tighten_baseline_for_dense_thumb_bytes(0),
            std::time::Duration::from_secs(60)
        );
        assert_eq!(
            tighten_baseline_for_dense_thumb_bytes(1024 * 1024),
            std::time::Duration::from_secs(60)
        );
    }

    #[test]
    fn tighten_baseline_for_dense_thumb_bytes_extrapolates_40s_per_mib() {
        // Grounding: 80 s tighten on a 2 MiB sample ~= 40 s/MiB.
        // 2 MiB -> 80 s, 10 MiB -> 400 s, 42 MiB -> 1680 s (~28 min).
        assert_eq!(
            tighten_baseline_for_dense_thumb_bytes(2 * 1024 * 1024),
            std::time::Duration::from_secs(80)
        );
        assert_eq!(
            tighten_baseline_for_dense_thumb_bytes(10 * 1024 * 1024),
            std::time::Duration::from_secs(400)
        );
        assert_eq!(
            tighten_baseline_for_dense_thumb_bytes(42 * 1024 * 1024),
            std::time::Duration::from_secs(1680)
        );
    }

    #[test]
    fn terminal_inventory_pair_validates_current_tags_counts_and_complete_identities() {
        let root = std::env::temp_dir().join(format!("pme_terminal_pair_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let ghidra = root.join("functions.json");
        let thumb = root.join("thumb_functions.json");
        std::fs::write(
            &ghidra,
            serde_json::to_vec(&serde_json::json!([
                {
                    "name":"arm_fn", "primary_source":"default", "entry":"0x4000", "end":"0x4004", "size":4,
                    "decode_ranges":[{"isa":"arm","start":"0x4000","end":"0x4004","blake3":"ec2bd03bf86b935fa34d71ad7ebb049f1f10f87d343e521511d8f9e6625620cd"}],
                    "decode_range_errors":[], "data_refs":[]
                },
                {
                    "name":"quarantined", "primary_source":"analysis", "entry":"0x4008", "end":"0x400c", "size":4,
                    "decode_ranges":[],
                    "decode_range_errors":[{"kind":"missing_isa_context","address":"0x4008","end":"0x400c"}],
                    "data_refs":[]
                }
            ]))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(
            &thumb,
            serde_json::to_vec(&serde_json::json!({
                "format":"pixel-modem-extractor-thumb-functions-v2",
                "functions":[{
                    "name":"thumb_fn", "entry":"0x4000", "end":"0x4004", "size":4,
                    "decode_ranges":[{"isa":"thumb","start":"0x4000","end":"0x4004"}],
                    "decode_range_errors":[], "body_kind":"thumb_disassembly", "body":"", "data_refs":[]
                }]
            }))
            .unwrap(),
        )
        .unwrap();

        let summary =
            validate_terminal_inventory_pair(&ghidra, &thumb, &test_runtime(), Some(0), None, None)
                .unwrap();

        assert_eq!(summary.ghidra.raw, 2);
        assert_eq!(summary.ghidra.accepted, 1);
        assert_eq!(summary.ghidra.quarantined, 1);
        assert_eq!(summary.thumb.unwrap().raw, 1);
        assert_eq!(summary.accepted_identities.len(), 2);
        assert!(
            summary
                .accepted_identities
                .iter()
                .any(|execution| execution.identity.decode_ranges[0].isa == DecodeIsa::Arm)
        );
        assert!(
            summary
                .accepted_identities
                .iter()
                .any(|execution| execution.identity.decode_ranges[0].isa == DecodeIsa::Thumb)
        );
        assert!(
            validate_terminal_inventory_pair(&ghidra, &thumb, &test_runtime(), None, None, None,)
                .is_err(),
            "an unexpected retained Thumb inventory is stale current-run state"
        );

        let malformed = serde_json::json!([{
            "name":"stale", "entry":"0x4000", "end":"0x4004", "size":4,
            "data_refs":[]
        }]);
        std::fs::write(&ghidra, serde_json::to_vec(&malformed).unwrap()).unwrap();
        assert!(
            validate_terminal_inventory_pair(
                &ghidra,
                &thumb,
                &test_runtime(),
                Some(0),
                Some(&summary),
                None,
            )
            .is_err(),
            "a stale pass-1 Ghidra inventory without mandatory ranges must fail"
        );

        std::fs::write(
            &ghidra,
            serde_json::to_vec(&serde_json::json!([
                {
                    "name":"arm_fn", "primary_source":"default", "entry":"0x4000", "end":"0x4004", "size":4,
                    "decode_ranges":[{"isa":"arm","start":"0x4000","end":"0x4004","blake3":"ec2bd03bf86b935fa34d71ad7ebb049f1f10f87d343e521511d8f9e6625620cd"}],
                    "decode_range_errors":[], "data_refs":[]
                },
                {
                    "name":"quarantined", "primary_source":"analysis", "entry":"0x4008", "end":"0x400c", "size":4,
                    "decode_ranges":[],
                    "decode_range_errors":[{"kind":"invalid_isa_context","address":"0x4008","end":"0x400c"}],
                    "data_refs":[]
                }
            ]))
            .unwrap(),
        )
        .unwrap();
        assert!(
            validate_terminal_inventory_pair(
                &ghidra,
                &thumb,
                &test_runtime(),
                Some(0),
                Some(&summary),
                None,
            )
            .is_err(),
            "pass 2 must not silently change a current quarantine projection"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    fn terminal_ghidra_record(
        entry: u32,
        isa: &str,
        name: &str,
        primary_source: &str,
    ) -> serde_json::Value {
        let end = entry + 4;
        serde_json::json!({
            "name": name,
            "primary_source": primary_source,
            "entry": format!("0x{entry:x}"),
            "end": format!("0x{end:x}"),
            "size": 4,
            "decode_ranges": [{
                "isa": isa,
                "start": format!("0x{entry:x}"),
                "end": format!("0x{end:x}"),
                "blake3": crate::manifest::blake3_bytes(&[0; 4]),
            }],
            "decode_range_errors": [],
            "data_refs": [],
        })
    }

    #[test]
    fn terminal_inventory_rejects_retained_identity_substitution_with_matching_growth() {
        let root = tempfile::tempdir().unwrap();
        let ghidra = root.path().join("functions.json");
        let absent_thumb = root.path().join("thumb_functions.json");
        let a = terminal_ghidra_record(0x4000, "arm", "a", "default");
        let b = terminal_ghidra_record(0x4004, "arm", "b", "default");
        std::fs::write(&ghidra, serde_json::to_vec(&vec![a, b.clone()]).unwrap()).unwrap();
        let retained = validate_terminal_inventory_pair(
            &ghidra,
            &absent_thumb,
            &test_runtime(),
            None,
            None,
            None,
        )
        .unwrap();

        let c = terminal_ghidra_record(0x4008, "thumb", "created_c", "analysis");
        let d = terminal_ghidra_record(0x400c, "thumb", "created_d", "analysis");
        std::fs::write(&ghidra, serde_json::to_vec(&vec![b, c, d]).unwrap()).unwrap();
        let summary = AppliedThumbNames {
            candidates: 1,
            created: 1,
            reapplied: 0,
            skipped_existing: 0,
            skipped_collision: 0,
        };
        let request = crate::symbolicate::Pass2CreationRequest {
            entry: 0x4008,
            final_primary: "created_c".to_string(),
            final_source: "analysis".to_string(),
        };

        assert!(
            validate_terminal_inventory_pair(
                &ghidra,
                &absent_thumb,
                &test_runtime(),
                None,
                Some(&retained),
                Some(TerminalCreationExpectation {
                    summary: &summary,
                    requests: std::slice::from_ref(&request),
                }),
            )
            .is_err(),
            "aggregate growth must not hide replacement of a retained identity"
        );
    }

    #[test]
    fn terminal_inventory_binds_created_entry_name_and_source_to_the_map() {
        let root = tempfile::tempdir().unwrap();
        let ghidra = root.path().join("functions.json");
        let absent_thumb = root.path().join("thumb_functions.json");
        let retained_record = terminal_ghidra_record(0x4000, "arm", "retained", "default");
        std::fs::write(
            &ghidra,
            serde_json::to_vec(&vec![retained_record.clone()]).unwrap(),
        )
        .unwrap();
        let retained = validate_terminal_inventory_pair(
            &ghidra,
            &absent_thumb,
            &test_runtime(),
            None,
            None,
            None,
        )
        .unwrap();
        let summary = AppliedThumbNames {
            candidates: 1,
            created: 1,
            reapplied: 0,
            skipped_existing: 0,
            skipped_collision: 0,
        };
        let request = crate::symbolicate::Pass2CreationRequest {
            entry: 0x4008,
            final_primary: "created".to_string(),
            final_source: "analysis".to_string(),
        };

        std::fs::write(
            &ghidra,
            serde_json::to_vec(&vec![
                retained_record.clone(),
                terminal_ghidra_record(0x4008, "arm", "created", "analysis"),
            ])
            .unwrap(),
        )
        .unwrap();
        assert!(
            validate_terminal_inventory_pair(
                &ghidra,
                &absent_thumb,
                &test_runtime(),
                None,
                None,
                Some(TerminalCreationExpectation {
                    summary: &summary,
                    requests: std::slice::from_ref(&request),
                }),
            )
            .is_err(),
            "first placement must require an accepted Thumb range at the entry"
        );

        std::fs::write(
            &ghidra,
            serde_json::to_vec(&vec![
                retained_record.clone(),
                terminal_ghidra_record(0x4008, "thumb", "created", "analysis"),
            ])
            .unwrap(),
        )
        .unwrap();
        assert!(
            validate_terminal_inventory_pair(
                &ghidra,
                &absent_thumb,
                &test_runtime(),
                None,
                Some(&retained),
                Some(TerminalCreationExpectation {
                    summary: &summary,
                    requests: std::slice::from_ref(&request),
                }),
            )
            .is_ok()
        );

        for created in [
            terminal_ghidra_record(0x400c, "thumb", "created", "analysis"),
            terminal_ghidra_record(0x4008, "thumb", "wrong", "analysis"),
            terminal_ghidra_record(0x4008, "thumb", "created", "user_defined"),
            terminal_ghidra_record(0x4008, "arm", "created", "analysis"),
        ] {
            std::fs::write(
                &ghidra,
                serde_json::to_vec(&vec![retained_record.clone(), created]).unwrap(),
            )
            .unwrap();
            assert!(
                validate_terminal_inventory_pair(
                    &ghidra,
                    &absent_thumb,
                    &test_runtime(),
                    None,
                    Some(&retained),
                    Some(TerminalCreationExpectation {
                        summary: &summary,
                        requests: std::slice::from_ref(&request),
                    }),
                )
                .is_err(),
                "unrequested or drifted created function was accepted"
            );
        }
    }

    #[test]
    fn terminal_creation_accepts_later_thumb_range_starting_at_entry() {
        let root = tempfile::tempdir().unwrap();
        let ghidra = root.path().join("functions.json");
        let absent_thumb = root.path().join("thumb_functions.json");
        let retained_record = terminal_ghidra_record(0x4000, "arm", "retained", "default");
        std::fs::write(
            &ghidra,
            serde_json::to_vec(&vec![retained_record.clone()]).unwrap(),
        )
        .unwrap();
        let retained = validate_terminal_inventory_pair(
            &ghidra,
            &absent_thumb,
            &test_runtime(),
            None,
            None,
            None,
        )
        .unwrap();
        let created = serde_json::json!({
            "name": "created",
            "primary_source": "analysis",
            "entry": "0x4008",
            "end": "0x400c",
            "size": 6,
            "decode_ranges": [
                {
                    "isa": "thumb",
                    "start": "0x4004",
                    "end": "0x4006",
                    "blake3": crate::manifest::blake3_bytes(&[0; 2]),
                },
                {
                    "isa": "thumb",
                    "start": "0x4008",
                    "end": "0x400c",
                    "blake3": crate::manifest::blake3_bytes(&[0; 4]),
                }
            ],
            "decode_range_errors": [],
            "data_refs": [],
        });
        std::fs::write(
            &ghidra,
            serde_json::to_vec(&vec![retained_record, created]).unwrap(),
        )
        .unwrap();
        let summary = AppliedThumbNames {
            candidates: 1,
            created: 1,
            reapplied: 0,
            skipped_existing: 0,
            skipped_collision: 0,
        };
        let request = crate::symbolicate::Pass2CreationRequest {
            entry: 0x4008,
            final_primary: "created".to_string(),
            final_source: "analysis".to_string(),
        };

        validate_terminal_inventory_pair(
            &ghidra,
            &absent_thumb,
            &test_runtime(),
            None,
            Some(&retained),
            Some(TerminalCreationExpectation {
                summary: &summary,
                requests: std::slice::from_ref(&request),
            }),
        )
        .expect("any accepted Thumb range may start at the function entry");
    }

    const TERMINAL_V3_ARTIFACT: &str = r#"{
  "format": "pixel-modem-extractor-thumb-functions-v3",
  "producers": [
    {
      "id": "radare2",
      "executable": "/usr/bin/r2",
      "version": "radare2 test 1.0",
      "command": "aaa;aflj;pdfj @@f"
    }
  ],
  "regions": [
    {
      "start": "0x4000",
      "end": "0x4010",
      "attempts": [
        {
          "producer": "radare2",
          "status": "succeeded",
          "stdout": {
            "path": "thumb/00004000.radare2.stdout",
            "bytes": 2,
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
          "substantial": 0,
          "accepted": 1,
          "quarantined": 0
        }
      ]
    }
  ],
  "functions": [
    {
      "body": "0x00004000      7047      bx lr\n",
      "body_kind": "thumb_disassembly",
      "data_refs": [],
      "decode_range_errors": [],
      "decode_ranges": [
        {
          "end": "0x4002",
          "isa": "thumb",
          "start": "0x4000",
          "blake3": "1ad48f49627079d806b802c74f40c39d55fe1d78b3faf0f8017aec62cec42122"
        }
      ],
      "end": "0x4002",
      "entry": "0x4000",
      "name": "sym.thumb",
      "size": 2
    }
  ]
}"#;

    const TERMINAL_MIXED_V3_ARTIFACT: &str = r#"{
  "format": "pixel-modem-extractor-thumb-functions-v3",
  "producers": [
    {
      "id": "radare2",
      "executable": "/usr/bin/r2",
      "version": "radare2 test 1.0",
      "command": "aaa;aflj;pdfj @@f"
    },
    {
      "id": "rizin",
      "executable": "/usr/bin/rizin",
      "version": "rizin test 1.0",
      "command": "aaa;aflj;pdfj @@F;axlj"
    }
  ],
  "regions": [
    {
      "start": "0x4000",
      "end": "0x4002",
      "attempts": [
        {
          "producer": "radare2",
          "status": "succeeded",
          "stdout": {
            "path": "thumb/00004000.radare2.stdout",
            "bytes": 2,
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
          "substantial": 0,
          "accepted": 1,
          "quarantined": 0
        }
      ]
    },
    {
      "start": "0x4010",
      "end": "0x4012",
      "attempts": [
        {
          "producer": "radare2",
          "status": "failed",
          "stdout": {
            "path": "thumb/00004010.radare2.stdout",
            "bytes": 0,
            "blake3": "1111111111111111111111111111111111111111111111111111111111111111"
          },
          "error": "radare2 exited with status 1 for Thumb region 0x4010"
        },
        {
          "producer": "rizin",
          "status": "succeeded",
          "stdout": {
            "path": "thumb/00004010.rizin.stdout",
            "bytes": 2,
            "blake3": "2222222222222222222222222222222222222222222222222222222222222222"
          },
          "error": null
        }
      ],
      "function_runs": [
        {
          "producer": "rizin",
          "first_function": 1,
          "function_count": 1,
          "substantial": 0,
          "accepted": 1,
          "quarantined": 0
        }
      ]
    }
  ],
  "functions": [
    {
      "body": "0x00004000      7047      bx lr\n",
      "body_kind": "thumb_disassembly",
      "data_refs": [],
      "decode_range_errors": [],
      "decode_ranges": [{"end":"0x4002","isa":"thumb","start":"0x4000","blake3":"1ad48f49627079d806b802c74f40c39d55fe1d78b3faf0f8017aec62cec42122"}],
      "end": "0x4002",
      "entry": "0x4000",
      "name": "sym.r2",
      "size": 2
    },
    {
      "body": "0x00004010      7047      bx lr\n",
      "body_kind": "thumb_disassembly",
      "data_refs": [],
      "decode_range_errors": [],
      "decode_ranges": [{"end":"0x4012","isa":"thumb","start":"0x4010","blake3":"1ad48f49627079d806b802c74f40c39d55fe1d78b3faf0f8017aec62cec42122"}],
      "end": "0x4012",
      "entry": "0x4010",
      "name": "sym.rizin",
      "size": 2
    }
  ]
}"#;

    const TERMINAL_V2_ARTIFACT: &str = r#"{
  "format": "pixel-modem-extractor-thumb-functions-v2",
  "functions": [
    {
      "body": "0x00004000      7047      bx lr\n",
      "body_kind": "thumb_disassembly",
      "data_refs": [],
      "decode_range_errors": [],
      "decode_ranges": [
        {
          "end": "0x4002",
          "isa": "thumb",
          "start": "0x4000"
        }
      ],
      "end": "0x4002",
      "entry": "0x4000",
      "name": "sym.thumb",
      "size": 2
    }
  ]
}"#;

    fn terminal_radare2_identity() -> crate::thumb_analysis::ProducerIdentity {
        crate::thumb_analysis::ProducerIdentity {
            producer: crate::thumb_analysis::ThumbProducer::Radare2,
            executable: "/usr/bin/r2".into(),
            version: "radare2 test 1.0".into(),
            command: crate::thumb_analysis::ThumbProducer::Radare2.command(),
        }
    }

    fn terminal_rizin_identity() -> crate::thumb_analysis::ProducerIdentity {
        crate::thumb_analysis::ProducerIdentity {
            producer: crate::thumb_analysis::ThumbProducer::Rizin,
            executable: "/usr/bin/rizin".into(),
            version: "rizin test 1.0".into(),
            command: crate::thumb_analysis::ThumbProducer::Rizin.command(),
        }
    }

    fn terminal_thumb_summary() -> crate::thumb_analysis::ThumbAnalysisSummary {
        crate::thumb_analysis::ThumbAnalysisSummary {
            regions_requested: 1,
            regions_succeeded: 1,
            regions_failed: 0,
            radare2_runs: 1,
            rizin_runs: 0,
            raw: 1,
            substantial: 0,
            accepted: 1,
            quarantined: 0,
        }
    }

    fn terminal_inventory_for_artifact(artifact: &str) -> TerminalInventorySummary {
        let root = tempfile::tempdir().unwrap();
        let ghidra = root.path().join("functions.json");
        let thumb = root.path().join("thumb_functions.json");
        std::fs::write(&ghidra, b"[]").unwrap();
        std::fs::write(&thumb, artifact).unwrap();
        validate_terminal_inventory_pair(&ghidra, &thumb, &test_runtime(), Some(0), None, None)
            .unwrap()
    }

    fn currentness_error(
        artifact: &str,
        identity: &crate::thumb_analysis::ProducerIdentity,
        summary: &crate::thumb_analysis::ThumbAnalysisSummary,
    ) -> String {
        currentness_error_for_terminal(
            &terminal_inventory_for_artifact(artifact),
            identity,
            &[(0x4000, 0x10)],
            summary,
        )
    }

    fn currentness_error_for_terminal(
        terminal: &TerminalInventorySummary,
        identity: &crate::thumb_analysis::ProducerIdentity,
        regions: &[(u32, u32)],
        summary: &crate::thumb_analysis::ThumbAnalysisSummary,
    ) -> String {
        let tools = crate::thumb_analysis::ThumbTools {
            radare2: identity.clone(),
            rizin: None,
        };
        validate_thumb_analysis_currentness(terminal, &tools, regions, summary)
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn terminal_inventory_currentness_rejects_matching_v2_when_current_run_requires_v3() {
        assert_eq!(
            currentness_error(
                TERMINAL_V2_ARTIFACT,
                &terminal_radare2_identity(),
                &terminal_thumb_summary(),
            ),
            "serialize: current Thumb artifact format mismatch: expected pixel-modem-extractor-thumb-functions-v3, found pixel-modem-extractor-thumb-functions-v2"
        );
    }

    #[test]
    fn terminal_inventory_currentness_compares_complete_radare2_identity() {
        let expected = terminal_radare2_identity();
        let summary = terminal_thumb_summary();
        let cases = [
            (
                TERMINAL_V3_ARTIFACT.to_owned(),
                crate::thumb_analysis::ProducerIdentity {
                    producer: crate::thumb_analysis::ThumbProducer::Rizin,
                    ..expected.clone()
                },
                "serialize: current Thumb producer identity mismatch: expected rizin, found radare2",
            ),
            (
                TERMINAL_V3_ARTIFACT.replacen("/usr/bin/r2", "/opt/r2", 1),
                expected.clone(),
                "serialize: current Thumb radare2 executable mismatch: expected /usr/bin/r2, found /opt/r2",
            ),
            (
                TERMINAL_V3_ARTIFACT.replacen("radare2 test 1.0", "radare2 stale 0.9", 1),
                expected.clone(),
                "serialize: current Thumb radare2 version mismatch: expected \"radare2 test 1.0\", found \"radare2 stale 0.9\"",
            ),
            (
                TERMINAL_V3_ARTIFACT.to_owned(),
                crate::thumb_analysis::ProducerIdentity {
                    command: crate::thumb_analysis::ThumbProducer::Rizin.command(),
                    ..expected
                },
                "serialize: current Thumb radare2 command mismatch: expected \"aaa;aflj;pdfj @@F;axlj\", found \"aaa;aflj;pdfj @@f\"",
            ),
        ];

        for (artifact, expected, message) in cases {
            assert_eq!(currentness_error(&artifact, &expected, &summary), message);
        }
    }

    #[test]
    fn terminal_inventory_currentness_accepts_exact_mixed_producer_ownership() {
        let terminal = terminal_inventory_for_artifact(TERMINAL_MIXED_V3_ARTIFACT);
        let tools = crate::thumb_analysis::ThumbTools {
            radare2: terminal_radare2_identity(),
            rizin: Some(terminal_rizin_identity()),
        };
        let summary = crate::thumb_analysis::ThumbAnalysisSummary {
            regions_requested: 2,
            regions_succeeded: 2,
            regions_failed: 0,
            radare2_runs: 1,
            rizin_runs: 1,
            raw: 2,
            substantial: 0,
            accepted: 2,
            quarantined: 0,
        };

        validate_thumb_analysis_currentness(
            &terminal,
            &tools,
            &[(0x4000, 2), (0x4010, 2)],
            &summary,
        )
        .unwrap();
    }

    #[test]
    fn terminal_inventory_currentness_rejects_stale_rizin_identity() {
        let stale = TERMINAL_MIXED_V3_ARTIFACT.replacen("rizin test 1.0", "rizin stale 0.9", 1);
        let terminal = terminal_inventory_for_artifact(&stale);
        let tools = crate::thumb_analysis::ThumbTools {
            radare2: terminal_radare2_identity(),
            rizin: Some(terminal_rizin_identity()),
        };
        let summary = crate::thumb_analysis::ThumbAnalysisSummary {
            regions_requested: 2,
            regions_succeeded: 2,
            regions_failed: 0,
            radare2_runs: 1,
            rizin_runs: 1,
            raw: 2,
            substantial: 0,
            accepted: 2,
            quarantined: 0,
        };

        let error = validate_thumb_analysis_currentness(
            &terminal,
            &tools,
            &[(0x4000, 2), (0x4010, 2)],
            &summary,
        )
        .unwrap_err();

        assert_eq!(
            error.to_string(),
            "serialize: current Thumb rizin version mismatch: expected \"rizin test 1.0\", found \"rizin stale 0.9\""
        );
    }

    #[test]
    fn terminal_inventory_currentness_compares_every_thumb_summary_field() {
        let expected = terminal_thumb_summary();
        let cases = [
            ("regions_requested", 1, 2),
            ("regions_succeeded", 1, 0),
            ("regions_failed", 0, 1),
            ("radare2_runs", 1, 0),
            ("rizin_runs", 0, 1),
            ("raw", 1, 2),
            ("substantial", 0, 1),
            ("accepted", 1, 0),
            ("quarantined", 0, 1),
        ];

        for (field, expected_value, found_value) in cases {
            let mut terminal = terminal_inventory_for_artifact(TERMINAL_V3_ARTIFACT);
            let observed = &mut terminal.thumb_metadata.as_mut().unwrap().summary;
            match field {
                "regions_requested" => observed.regions_requested = found_value,
                "regions_succeeded" => observed.regions_succeeded = found_value,
                "regions_failed" => observed.regions_failed = found_value,
                "radare2_runs" => observed.radare2_runs = found_value,
                "rizin_runs" => observed.rizin_runs = found_value,
                "raw" => observed.raw = found_value,
                "substantial" => observed.substantial = found_value,
                "accepted" => observed.accepted = found_value,
                "quarantined" => observed.quarantined = found_value,
                _ => unreachable!(),
            }
            assert_eq!(
                currentness_error_for_terminal(
                    &terminal,
                    &terminal_radare2_identity(),
                    &[(0x4000, 0x10)],
                    &expected
                ),
                format!(
                    "serialize: current Thumb {field} mismatch: expected {expected_value}, found {found_value}"
                )
            );
        }
    }

    #[test]
    fn terminal_inventory_currentness_rejects_stale_region_counts_and_ledger_shape() {
        let extra_failed_region = TERMINAL_V3_ARTIFACT.replacen(
            "      ]\n    }\n  ],\n  \"functions\"",
            "      ]\n    },\n    {\n      \"start\": \"0x4010\",\n      \"end\": \"0x4020\",\n      \"attempts\": [\n        {\n          \"producer\": \"radare2\",\n          \"status\": \"failed\",\n          \"stdout\": null,\n          \"error\": \"stale failed attempt\"\n        }\n      ],\n      \"function_runs\": []\n    }\n  ],\n  \"functions\"",
            1,
        );
        assert_eq!(
            currentness_error(
                &extra_failed_region,
                &terminal_radare2_identity(),
                &terminal_thumb_summary(),
            ),
            "serialize: current Thumb regions_requested mismatch: expected 1, found 2"
        );

        let changed_region =
            TERMINAL_V3_ARTIFACT.replacen("\"end\": \"0x4010\"", "\"end\": \"0x4018\"", 1);
        assert_eq!(
            currentness_error(
                &changed_region,
                &terminal_radare2_identity(),
                &terminal_thumb_summary(),
            ),
            "serialize: current Thumb region ledger mismatch: expected [(0x4000, 0x4010)], found [(0x4000, 0x4018)]"
        );
    }

    #[test]
    fn terminal_inventory_currentness_rejects_rizin_configuration_with_matching_totals() {
        let with_rizin = TERMINAL_V3_ARTIFACT
            .replacen(
                "    }\n  ],\n  \"regions\"",
                "    },\n    {\n      \"id\": \"rizin\",\n      \"executable\": \"/usr/bin/rizin\",\n      \"version\": \"rizin test 1.0\",\n      \"command\": \"aaa;aflj;pdfj @@F;axlj\"\n    }\n  ],\n  \"regions\"",
                1,
            )
            .replacen(
                "          \"error\": null\n        }\n      ],",
                "          \"error\": null\n        },\n        {\n          \"producer\": \"rizin\",\n          \"status\": \"failed\",\n          \"stdout\": null,\n          \"error\": \"stale fallback attempt\"\n        }\n      ],",
                1,
            );
        assert_eq!(
            currentness_error(
                &with_rizin,
                &terminal_radare2_identity(),
                &terminal_thumb_summary(),
            ),
            "serialize: current Thumb producer configuration mismatch: expected exactly [radare2], found [radare2, rizin]"
        );
    }

    #[test]
    fn terminal_inventory_currentness_accepts_matching_v3_provenance_and_summary() {
        validate_thumb_analysis_currentness(
            &terminal_inventory_for_artifact(TERMINAL_V3_ARTIFACT),
            &crate::thumb_analysis::ThumbTools {
                radare2: terminal_radare2_identity(),
                rizin: None,
            },
            &[(0x4000, 0x10)],
            &terminal_thumb_summary(),
        )
        .unwrap();
    }

    #[test]
    fn run_report_without_run_has_spec_and_empty_images() {
        let buf = craft_modem_bin(&[
            ("BOOT", 0x0, 1, &[0u8; 4]),
            ("MAIN", 0x4001_0000, 3, &[0u8; 8]),
        ]);
        let dir = std::env::temp_dir().join(format!("pme_run_report_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let modem = dir.join("modem.bin");
        std::fs::write(&modem, &buf).unwrap();
        let opts = Opts {
            run: false,
            image: None,
            ghidra_home: None,
            processor: "ARM:LE:32:v7".into(),
            no_thumb_decompile: false,
            rizin_fallback: false,
            tighten_wall_clock_budget_override: None,
            no_skip_opaque: false,
        };

        let rep = run_report(&modem, &opts, &dir.join("out")).unwrap();

        assert!(rep.spec_path.ends_with("ghidra_load.json"));
        assert!(rep.spec_path.exists());
        assert!(rep.images.is_empty(), "no images analyzed without --run");
    }

    #[test]
    fn generation_only_materializes_main_scatter_map() {
        let main = scatter_main_image();
        let buf = craft_modem_bin(&[("BOOT", 0, 1, &[0u8; 4]), ("MAIN", SCATTER_BASE, 3, &main)]);
        let dir = tempfile::tempdir().unwrap();
        let modem = dir.path().join("modem.bin");
        let out = dir.path().join("out");
        std::fs::write(&modem, buf).unwrap();

        run_report(&modem, &generation_opts(None), &out).unwrap();

        assert!(out.join("scripts/ApplyScatterLoad.java").is_file());
        assert!(out.join("scatter/02_MAIN/load_map.json").is_file());
        assert_eq!(
            std::fs::read(out.join("scatter/02_MAIN/blocks/03-copy.bin")).unwrap(),
            [0x11, 0x22, 0x33, 0x44]
        );
        assert_eq!(
            std::fs::read(out.join("scatter/02_MAIN/blocks/04-decompress1.bin")).unwrap(),
            [0xaa, 0, 0]
        );
        let spec: serde_json::Value =
            serde_json::from_slice(&std::fs::read(out.join("ghidra_load.json")).unwrap()).unwrap();
        let main = spec["images"]
            .as_array()
            .unwrap()
            .iter()
            .find(|image| image["name"] == "02_MAIN")
            .unwrap();
        assert_eq!(main["runtime_load_map"], "scatter/02_MAIN/load_map.json");
    }

    #[test]
    fn generation_only_no_candidate_omits_runtime_load_map() {
        let buf = craft_modem_bin(&[("MAIN", SCATTER_BASE, 3, &[0u8; 64])]);
        let dir = tempfile::tempdir().unwrap();
        let modem = dir.path().join("modem.bin");
        let out = dir.path().join("out");
        let stale = out.join("scatter/02_MAIN/stale.bin");
        std::fs::create_dir_all(stale.parent().unwrap()).unwrap();
        std::fs::write(&stale, b"stale").unwrap();
        std::fs::write(&modem, buf).unwrap();

        run_report(&modem, &generation_opts(None), &out).unwrap();

        let spec: serde_json::Value =
            serde_json::from_slice(&std::fs::read(out.join("ghidra_load.json")).unwrap()).unwrap();
        assert!(spec["images"][0].get("runtime_load_map").is_none());
        let script = std::fs::read_to_string(out.join("run_ghidra.sh")).unwrap();
        assert!(!script.contains("ApplyScatterLoad.java"));
        assert!(!out.join("scatter/02_MAIN").exists());
    }

    #[test]
    fn image_filter_does_not_change_generated_main_map() {
        let main = scatter_main_image();
        let buf = craft_modem_bin(&[("BOOT", 0, 1, &[0u8; 4]), ("MAIN", SCATTER_BASE, 3, &main)]);
        let dir = tempfile::tempdir().unwrap();
        let modem = dir.path().join("modem.bin");
        let out = dir.path().join("out");
        std::fs::write(&modem, buf).unwrap();

        run_report(&modem, &generation_opts(Some("BOOT")), &out).unwrap();

        assert!(out.join("scatter/02_MAIN/load_map.json").is_file());
        let spec: serde_json::Value =
            serde_json::from_slice(&std::fs::read(out.join("ghidra_load.json")).unwrap()).unwrap();
        assert_eq!(
            spec["images"][1]["runtime_load_map"],
            "scatter/02_MAIN/load_map.json"
        );
    }

    #[test]
    fn plausible_malformed_main_returns_bad_scatter() {
        let mut main = scatter_main_image();
        write_test_u32(&mut main, 0x200 + 5 * 16 + 8, 0);
        let buf = craft_modem_bin(&[("MAIN", SCATTER_BASE, 3, &main)]);
        let dir = tempfile::tempdir().unwrap();
        let modem = dir.path().join("modem.bin");
        let out = dir.path().join("out");
        std::fs::write(&modem, buf).unwrap();

        let error = run_report(&modem, &generation_opts(None), &out).unwrap_err();

        assert!(matches!(error, Error::BadScatter(reason) if reason.contains("entry Some(5)")));
        assert!(!out.join("ghidra_load.json").exists());
    }

    #[test]
    fn pal_generation_state_is_explicit() {
        // Unmanaged: no recognized MAIN ever enters PAL discovery, and an
        // unknown label never resolves to a managed state.
        let buf = craft_modem_bin(&[("BOOT", 0, 1, &[0u8; 4])]);
        let dir = tempfile::tempdir().unwrap();
        let modem = dir.path().join("modem.bin");
        let out = dir.path().join("out");
        std::fs::write(&modem, buf).unwrap();
        let report = run_report(&modem, &generation_opts(None), &out).unwrap();
        assert_eq!(
            report.runtime_analysis_state("00_BOOT"),
            RuntimeAnalysisState {
                scatter: RuntimeScatterState::Unmanaged,
                tasks: RuntimeTaskState::Unmanaged,
            }
        );
        assert_eq!(
            report.runtime_analysis_state("missing"),
            RuntimeAnalysisState {
                scatter: RuntimeScatterState::Unmanaged,
                tasks: RuntimeTaskState::Unmanaged,
            }
        );
        assert!(!out.join("pal_tasks").exists());

        // Absent: a recognized MAIN with no PAL candidate clears the owned
        // manifest only after the successful no-candidate result.
        let buf = craft_modem_bin(&[("MAIN", SCATTER_BASE, 3, &[0u8; 64])]);
        let dir = tempfile::tempdir().unwrap();
        let modem = dir.path().join("modem.bin");
        let out = dir.path().join("out");
        std::fs::write(&modem, buf).unwrap();
        let stale_manifest = out.join("pal_tasks/02_MAIN/tasks.json");
        std::fs::create_dir_all(stale_manifest.parent().unwrap()).unwrap();
        std::fs::write(&stale_manifest, b"stale").unwrap();
        let report = run_report(&modem, &generation_opts(None), &out).unwrap();
        assert_eq!(
            report.runtime_analysis_state("02_MAIN").tasks,
            RuntimeTaskState::Absent
        );
        assert!(!out.join("pal_tasks/02_MAIN").exists());
        let spec: serde_json::Value =
            serde_json::from_slice(&std::fs::read(out.join("ghidra_load.json")).unwrap()).unwrap();
        assert!(spec["images"][0].get("pal_task_map").is_none());

        // Present: a discoverable MAIN publishes the manifest atomically
        // and reports the exact map identity; `pal_task_map` appears only
        // on the recognized MAIN and the generated script carries the
        // exact ApplyPalTasks argv under no-scatter (`-`).
        let main = craft_discoverable_pal_main_image();
        let buf = craft_modem_bin(&[("BOOT", 0, 1, &[0u8; 4]), ("MAIN", PAL_BASE, 3, &main)]);
        let dir = tempfile::tempdir().unwrap();
        let modem = dir.path().join("modem.bin");
        let out = dir.path().join("out");
        std::fs::write(&modem, buf).unwrap();
        let report = run_report(&modem, &generation_opts(None), &out).unwrap();
        let RuntimeTaskState::Present(map) = report.runtime_analysis_state("02_MAIN").tasks else {
            panic!("discoverable MAIN must report a present PAL map");
        };
        assert_eq!(map.relative_path, "pal_tasks/02_MAIN/tasks.json");
        assert_eq!(map.task_records, 2);
        assert_eq!(map.distinct_entries, 0);
        let manifest_path = out.join(&map.relative_path);
        let manifest_bytes = std::fs::read(&manifest_path).unwrap();
        assert_eq!(
            map.identity,
            format!(
                "v1:{}:{}:{}",
                crate::manifest::blake3_bytes(&manifest_bytes),
                map.task_records,
                map.distinct_entries
            )
        );
        assert_eq!(map.blake3, crate::manifest::blake3_bytes(&manifest_bytes));
        let spec: serde_json::Value =
            serde_json::from_slice(&std::fs::read(out.join("ghidra_load.json")).unwrap()).unwrap();
        let boot = &spec["images"][0];
        let main_entry = &spec["images"][1];
        assert_eq!(boot["name"], "00_BOOT");
        assert!(boot.get("pal_task_map").is_none());
        assert_eq!(main_entry["pal_task_map"], "pal_tasks/02_MAIN/tasks.json");
        let script = std::fs::read_to_string(out.join("run_ghidra.sh")).unwrap();
        let expected = headless_args(
            "$HERE",
            "02_MAIN",
            "ARM:LE:32:v7",
            PAL_BASE,
            None,
            None,
            Some(PalScriptPlan {
                manifest: &map.relative_path,
                identity: &map.identity,
            }),
            &[],
            "tighten",
        );
        let quoted: Vec<String> = expected
            .iter()
            .map(|arg| {
                if arg == "$HERE" {
                    "\"${HERE}\"".to_string()
                } else {
                    shell_arg(arg)
                }
            })
            .collect();
        let invocation = format!("if \"$HEADLESS\" {}", quoted.join(" "));
        assert!(
            script.contains(&invocation),
            "run_ghidra.sh must carry the exact PAL argv:\n{script}\nexpected {invocation}"
        );
        assert!(
            script.contains(&format!(
                "printf '%s\\n' 'pixel-modem-extractor-ghidra-export-v4' 'exception_roots=none' 'pal_tasks={}' 'symbol_map=none'",
                map.identity
            )),
            "run_ghidra.sh must compare the exact present-PAL v4 marker:\n{script}"
        );

        // Malformed: an ambiguous MAIN is the typed BadPalTasks error and
        // returns no consumable state — no spec is published, and the
        // older manifest bytes are never pre-cleared.
        let main = craft_ambiguous_pal_main_image();
        let buf = craft_modem_bin(&[("MAIN", PAL_BASE, 3, &main)]);
        let dir = tempfile::tempdir().unwrap();
        let modem = dir.path().join("modem.bin");
        let out = dir.path().join("out");
        std::fs::write(&modem, buf).unwrap();
        let stale_manifest = out.join("pal_tasks/02_MAIN/tasks.json");
        std::fs::create_dir_all(stale_manifest.parent().unwrap()).unwrap();
        std::fs::write(&stale_manifest, b"older complete bytes").unwrap();
        let error = run_report(&modem, &generation_opts(None), &out).unwrap_err();
        assert!(matches!(error, Error::BadPalTasks(reason) if reason.contains("ambiguous")));
        assert!(!out.join("ghidra_load.json").exists());
        assert_eq!(
            std::fs::read(&stale_manifest).unwrap(),
            b"older complete bytes",
            "a failed discovery must never pre-clear older physical bytes"
        );
    }

    #[test]
    fn pal_load_spec_is_filter_independent() {
        // The --image filter selects Ghidra runs, never generation: PAL
        // discovery and publication run for MAIN even when the filter
        // selects another image.
        let main = craft_discoverable_pal_main_image();
        let buf = craft_modem_bin(&[("BOOT", 0, 1, &[0u8; 4]), ("MAIN", PAL_BASE, 3, &main)]);
        let dir = tempfile::tempdir().unwrap();
        let modem = dir.path().join("modem.bin");
        let out = dir.path().join("out");
        std::fs::write(&modem, buf).unwrap();

        let report = run_report(&modem, &generation_opts(Some("BOOT")), &out).unwrap();

        let RuntimeTaskState::Present(map) = report.runtime_analysis_state("02_MAIN").tasks else {
            panic!("PAL generation must stay filter-independent");
        };
        assert!(out.join(&map.relative_path).is_file());
        let spec: serde_json::Value =
            serde_json::from_slice(&std::fs::read(out.join("ghidra_load.json")).unwrap()).unwrap();
        assert_eq!(
            spec["images"][1]["pal_task_map"],
            "pal_tasks/02_MAIN/tasks.json"
        );
        assert!(report.images.is_empty());
    }

    #[test]
    fn generation_discovers_exception_roots_for_every_embedded_image() {
        let buf = craft_modem_bin(&[
            ("BOOT", 0, 1, &[0u8; 64]),
            ("MAIN", 0x4001_0000, 3, &[0u8; 64]),
            ("VSS", 0x5000_0000, 4, &[0u8; 64]),
        ]);
        let toc = Toc::parse(&buf).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let scatter_calls = std::cell::Cell::new(0);
        let pal_calls = std::cell::Cell::new(0);
        let exception_calls = std::cell::RefCell::new(Vec::new());

        let analysis = generate_runtime_analysis_with(
            &toc,
            &buf,
            dir.path(),
            |_image, _base| {
                scatter_calls.set(scatter_calls.get() + 1);
                Ok(None)
            },
            |_runtime, label, toc_name| {
                exception_calls
                    .borrow_mut()
                    .push((label.to_string(), toc_name.to_string()));
                Ok(None)
            },
            exception_roots::materialize,
            exception_roots::clear_materialized,
            |_runtime, _label| {
                pal_calls.set(pal_calls.get() + 1);
                Ok(None)
            },
        )
        .unwrap();

        assert_eq!(scatter_calls.get(), 1, "scatter remains MAIN-only");
        assert_eq!(pal_calls.get(), 1, "PAL remains MAIN-only");
        assert_eq!(
            exception_calls.into_inner(),
            [
                ("00_BOOT".to_string(), "BOOT".to_string()),
                ("02_MAIN".to_string(), "MAIN".to_string()),
                ("03_VSS".to_string(), "VSS".to_string()),
            ],
            "every embedded image must be offered to exception discovery in TOC order"
        );
        for label in ["00_BOOT", "02_MAIN", "03_VSS"] {
            assert_eq!(
                analysis.exception_roots.get(label),
                Some(&RuntimeExceptionState::Absent),
                "successful no-candidate discovery must be explicit for {label}"
            );
        }
    }

    #[test]
    fn generation_exception_state_is_explicit_filter_independent_and_clears_stale_manifest() {
        let fixture = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/exception_roots/synthetic.bin"),
        )
        .unwrap();
        let buf = craft_modem_bin(&[
            ("BOOT", 0x4001_0000, 1, &fixture),
            ("VSS", 0x5000_0000, 4, &[0u8; 64]),
        ]);
        let dir = tempfile::tempdir().unwrap();
        let modem = dir.path().join("modem.bin");
        let out = dir.path().join("out");
        std::fs::write(&modem, buf).unwrap();
        let stale = out.join("exception_roots/03_VSS/roots.json");
        std::fs::create_dir_all(stale.parent().unwrap()).unwrap();
        std::fs::write(&stale, b"stale").unwrap();

        let report = run_report(&modem, &generation_opts(Some("VSS")), &out).unwrap();

        let RuntimeExceptionState::Present(map) = report.runtime_exception_state("00_BOOT") else {
            panic!("the structurally valid BOOT fixture must publish exception roots");
        };
        assert_eq!(map.relative_path, "exception_roots/00_BOOT/roots.json");
        assert_eq!(map.tables, 1);
        assert_eq!(map.roots, 7);
        assert!(out.join(&map.relative_path).is_file());
        assert_eq!(
            report.runtime_exception_state("03_VSS"),
            RuntimeExceptionState::Absent
        );
        assert_eq!(
            report.runtime_exception_state("missing"),
            RuntimeExceptionState::Unmanaged
        );
        assert!(
            !stale.exists(),
            "successful absence clears the owned manifest even when its directory remains"
        );
        let spec: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&report.spec_path).unwrap()).unwrap();
        assert_eq!(
            spec["images"][0]["exception_root_map"],
            "exception_roots/00_BOOT/roots.json"
        );
        assert!(spec["images"][1].get("exception_root_map").is_none());
        assert!(
            report.images.is_empty(),
            "the image filter selects only later runs"
        );
    }

    fn write_prior_exception_manifest(root: &Path, label: &str) -> (PathBuf, Vec<u8>) {
        let bytes = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/exception_roots/roots.json"),
        )
        .unwrap();
        let path = root.join(format!("exception_roots/{label}/roots.json"));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        (path, bytes)
    }

    #[test]
    fn generation_exception_discovery_failure_preserves_stale_manifest_without_current_state() {
        let fixture = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/exception_roots/synthetic.bin"),
        )
        .unwrap();
        let data = craft_modem_bin(&[("BOOT", 0x4001_0000, 1, &fixture)]);
        let toc = Toc::parse(&data).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (stale, prior_bytes) = write_prior_exception_manifest(dir.path(), "00_BOOT");

        let result = generate_runtime_analysis_with(
            &toc,
            &data,
            dir.path(),
            |_image, _base| Ok(None),
            |_runtime, _label, _toc_name| {
                Err(exception_roots::ExceptionRootError::Artifact(
                    "injected discovery failure".into(),
                ))
            },
            |_plan, _context, _root| panic!("discovery failure must not publish"),
            |_root, _label| panic!("discovery failure must not clear"),
            |_runtime, _label| panic!("a BOOT-only fixture must not discover PAL"),
        );

        let Err(error) = result else {
            panic!("discovery failure returned consumable current state");
        };
        assert!(error.to_string().contains("injected discovery failure"));
        assert_eq!(std::fs::read(stale).unwrap(), prior_bytes);
    }

    #[test]
    fn generation_exception_publication_failure_preserves_stale_manifest_without_current_state() {
        let fixture = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/exception_roots/synthetic.bin"),
        )
        .unwrap();
        let data = craft_modem_bin(&[("BOOT", 0x4001_0000, 1, &fixture)]);
        let toc = Toc::parse(&data).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (stale, prior_bytes) = write_prior_exception_manifest(dir.path(), "00_BOOT");

        let result = generate_runtime_analysis_with(
            &toc,
            &data,
            dir.path(),
            |_image, _base| Ok(None),
            exception_roots::discover,
            |_plan, _context, _root| {
                Err(exception_roots::ExceptionRootError::Artifact(
                    "injected publication failure".into(),
                ))
            },
            |_root, _label| panic!("present discovery must not clear"),
            |_runtime, _label| panic!("a BOOT-only fixture must not discover PAL"),
        );

        let Err(error) = result else {
            panic!("publication failure returned consumable current state");
        };
        assert!(error.to_string().contains("injected publication failure"));
        assert_eq!(std::fs::read(stale).unwrap(), prior_bytes);
    }

    #[test]
    fn generation_exception_clear_failure_preserves_stale_manifest_without_current_state() {
        let data = craft_modem_bin(&[("BOOT", 0x4001_0000, 1, &[0u8; 64])]);
        let toc = Toc::parse(&data).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (stale, prior_bytes) = write_prior_exception_manifest(dir.path(), "00_BOOT");

        let result = generate_runtime_analysis_with(
            &toc,
            &data,
            dir.path(),
            |_image, _base| Ok(None),
            |_runtime, _label, _toc_name| Ok(None),
            |_plan, _context, _root| panic!("absent discovery must not publish"),
            |_root, _label| {
                Err(exception_roots::ExceptionRootError::Artifact(
                    "injected clear failure".into(),
                ))
            },
            |_runtime, _label| panic!("a BOOT-only fixture must not discover PAL"),
        );

        let Err(error) = result else {
            panic!("clear failure returned consumable current state");
        };
        assert!(error.to_string().contains("injected clear failure"));
        assert_eq!(std::fs::read(stale).unwrap(), prior_bytes);
    }

    #[test]
    fn pal_generation_reuses_scatter_discovery() {
        // One MAIN generation loop: the single scatter discovery result
        // feeds both the scatter artifact and the RuntimeImage PAL
        // discovery consumes — scatter is never discovered twice, PAL
        // discovery runs exactly once, over a raw-only MAIN with no PAL
        // evidence and over a scatter+PAL MAIN alike.
        let scatter_main = scatter_main_image();
        let buf = craft_modem_bin(&[("MAIN", SCATTER_BASE, 3, &scatter_main)]);
        let data = buf.clone();
        let toc = Toc::parse(&data).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let scatter_calls = std::cell::Cell::new(0);
        let pal_calls = std::cell::Cell::new(0);
        let maps = generate_runtime_analysis_with(
            &toc,
            &data,
            dir.path(),
            |image, base| {
                scatter_calls.set(scatter_calls.get() + 1);
                scatter::discover(image, base).map_err(|error| error.to_string())
            },
            exception_roots::discover,
            exception_roots::materialize,
            exception_roots::clear_materialized,
            |runtime, label| {
                pal_calls.set(pal_calls.get() + 1);
                crate::pal_tasks::discover(runtime, label)
            },
        )
        .unwrap();
        assert_eq!(scatter_calls.get(), 1);
        assert_eq!(pal_calls.get(), 1);
        assert_eq!(
            maps.scatter_states.get("02_MAIN"),
            Some(&RuntimeScatterState::Present)
        );
        assert_eq!(maps.tasks.get("02_MAIN"), Some(&RuntimeTaskState::Absent));

        let main = craft_discoverable_pal_main_image();
        let buf = craft_modem_bin(&[("MAIN", PAL_BASE, 3, &main)]);
        let toc = Toc::parse(&buf).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let scatter_calls = std::cell::Cell::new(0);
        let pal_calls = std::cell::Cell::new(0);
        let maps = generate_runtime_analysis_with(
            &toc,
            &buf,
            dir.path(),
            |image, base| {
                scatter_calls.set(scatter_calls.get() + 1);
                scatter::discover(image, base).map_err(|error| error.to_string())
            },
            exception_roots::discover,
            exception_roots::materialize,
            exception_roots::clear_materialized,
            |runtime, label| {
                pal_calls.set(pal_calls.get() + 1);
                crate::pal_tasks::discover(runtime, label)
            },
        )
        .unwrap();
        assert_eq!(scatter_calls.get(), 1);
        assert_eq!(pal_calls.get(), 1);
        assert_eq!(
            maps.scatter_states.get("02_MAIN"),
            Some(&RuntimeScatterState::Absent)
        );
        assert!(matches!(
            maps.tasks.get("02_MAIN"),
            Some(RuntimeTaskState::Present(_))
        ));

        // A MAIN with both a scatter loader and a discoverable PAL table:
        // still exactly one scatter discovery (the RuntimeImage over the
        // published artifact is not a second discovery) and one PAL
        // discovery, with both states present.
        let main = craft_scatter_pal_main_image();
        let buf = craft_modem_bin(&[("MAIN", PAL_BASE, 3, &main)]);
        let toc = Toc::parse(&buf).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let scatter_calls = std::cell::Cell::new(0);
        let pal_calls = std::cell::Cell::new(0);
        let maps = generate_runtime_analysis_with(
            &toc,
            &buf,
            dir.path(),
            |image, base| {
                scatter_calls.set(scatter_calls.get() + 1);
                scatter::discover(image, base).map_err(|error| error.to_string())
            },
            exception_roots::discover,
            exception_roots::materialize,
            exception_roots::clear_materialized,
            |runtime, label| {
                pal_calls.set(pal_calls.get() + 1);
                crate::pal_tasks::discover(runtime, label)
            },
        )
        .unwrap();
        assert_eq!(scatter_calls.get(), 1);
        assert_eq!(pal_calls.get(), 1);
        assert_eq!(
            maps.scatter_states.get("02_MAIN"),
            Some(&RuntimeScatterState::Present)
        );
        assert!(
            maps.scatter_paths
                .get("02_MAIN")
                .is_some_and(|path| path == "scatter/02_MAIN/load_map.json")
        );
        assert!(matches!(
            maps.tasks.get("02_MAIN"),
            Some(RuntimeTaskState::Present(_))
        ));
    }

    #[test]
    fn run_script_expands_here_for_import_and_scatter_paths() {
        let main = scatter_main_image();
        let buf = craft_modem_bin(&[("MAIN", SCATTER_BASE, 3, &main)]);
        let dir = tempfile::tempdir().unwrap();
        let modem = dir.path().join("modem.bin");
        let out = dir.path().join("out");
        std::fs::write(&modem, buf).unwrap();
        let processor = "$HERE/processor'; touch injected; echo '";
        let mut opts = generation_opts(None);
        opts.processor = processor.to_string();

        run_report(&modem, &opts, &out).unwrap();

        let script = std::fs::read_to_string(out.join("run_ghidra.sh")).unwrap();
        assert!(
            script.contains("\"${HERE}/images/02_MAIN\""),
            "script:\n{script}"
        );
        assert!(
            script.contains("\"${HERE}/scatter/02_MAIN/load_map.json\""),
            "script:\n{script}"
        );
        assert!(script.contains("\"${HERE}\""), "script:\n{script}");
        assert!(!script.contains("'$HERE/images/02_MAIN'"));
        assert!(!script.contains("'$HERE/scatter/02_MAIN/load_map.json'"));
        for path in [
            "${HERE}/export/02_MAIN.complete",
            "${HERE}/export/02_MAIN/functions.json",
            "${HERE}/export/02_MAIN/disasm.lst",
            "${HERE}/export/02_MAIN/decompiled.c",
        ] {
            assert!(script.contains(path), "missing {path} in script:\n{script}");
        }
        assert!(
            script.contains(GHIDRA_EXPORT_COMPLETION),
            "missing exact completion contract in script:\n{script}"
        );
        assert!(
            script.contains("cmp -s -"),
            "marker validation must compare exact bytes:\n{script}"
        );
        assert!(
            !script.contains("$(cat "),
            "command substitution normalizes marker newlines:\n{script}"
        );
        assert!(
            script.contains(&shell_quote(processor)),
            "script:\n{script}"
        );
        assert!(!script.contains("\"${HERE}/processor"));
    }

    #[test]
    fn report_failure_returns_thumb_error_when_only_thumb_failed() {
        let report = DecompileReport {
            images: vec![ImageResult {
                label: "02_MAIN".into(),
                outcome: ImageOutcome::Analyzed(12),
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
                exception_state: RuntimeExceptionState::Unmanaged,
                exception_roots_applied: None,
                exception_error: None,
                pal_applied: None,
            }],
            spec_path: PathBuf::from("ghidra_load.json"),
            current_exports: BTreeSet::new(),
            runtime_scatter: HashMap::new(),
            runtime_exception_roots: HashMap::new(),
            runtime_tasks: HashMap::new(),
        };

        let err = report_failure(&report).expect("thumb error should fail standalone run");
        assert_eq!(
            err.to_string(),
            "decompose incomplete: Thumb analysis failed on 02_MAIN: radare2 parser rejected empty stdout"
        );
    }

    fn exception_report(
        outcome: ImageOutcome,
        exception_state: RuntimeExceptionState,
        runtime_exception_state: Option<RuntimeExceptionState>,
        exception_error: Option<&str>,
        terminal_error: Option<&str>,
    ) -> DecompileReport {
        let mut runtime_exception_roots = HashMap::new();
        if let Some(state) = runtime_exception_state {
            runtime_exception_roots.insert("02_MAIN".to_string(), state);
        }
        DecompileReport {
            images: vec![ImageResult {
                label: "02_MAIN".into(),
                outcome,
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
                terminal_error: terminal_error.map(str::to_string),
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
                exception_state,
                exception_roots_applied: None,
                exception_error: exception_error.map(str::to_string),
                pal_applied: None,
            }],
            spec_path: PathBuf::from("ghidra_load.json"),
            current_exports: BTreeSet::new(),
            runtime_scatter: HashMap::new(),
            runtime_exception_roots,
            runtime_tasks: HashMap::new(),
        }
    }

    #[test]
    fn report_failure_surfaces_exception_error_before_generic_terminal_error() {
        let state = RuntimeExceptionState::Present(MaterializedExceptionRoots {
            relative_path: "exception_roots/02_MAIN/roots.json".into(),
            blake3: "b".repeat(64),
            identity: format!("v1:{}:1:7", "b".repeat(64)),
            tables: 1,
            roots: 7,
        });
        let report = exception_report(
            ImageOutcome::TerminalInvalid,
            state.clone(),
            Some(state),
            Some("missing ApplyExceptionRoots summary"),
            Some("invalid terminal output"),
        );

        let error = report_failure(&report).expect("exception application must fail");
        assert_eq!(
            error.to_string(),
            "decompose incomplete: exception-root application failed on 02_MAIN: missing ApplyExceptionRoots summary"
        );
    }

    #[test]
    fn report_failure_rejects_exception_generation_state_drift() {
        let report = exception_report(
            ImageOutcome::Analyzed(1),
            RuntimeExceptionState::Absent,
            None,
            None,
            None,
        );

        let error = report_failure(&report).expect("state drift must fail closed");
        assert_eq!(
            error.to_string(),
            "decompose incomplete: exception-root state drifted for 02_MAIN"
        );
    }

    #[test]
    fn disabled_rizin_fallback_skips_discovery() {
        let identity = discover_configured_rizin(false, || -> Result<_> {
            panic!("disabled Rizin fallback must not run discovery")
        })
        .unwrap();

        assert!(identity.is_none());
    }

    #[test]
    fn enabled_rizin_fallback_propagates_discovery_failure() {
        let error = discover_configured_rizin(true, || {
            Err(Error::ToolNotFound("configured Rizin is unusable".into()))
        })
        .unwrap_err();

        assert!(
            matches!(error, Error::ToolNotFound(reason) if reason == "configured Rizin is unusable")
        );
    }

    #[test]
    fn run_report_discovers_each_configured_thumb_tool_once_before_output() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        let mut opts = generation_opts(None);
        opts.run = true;
        opts.rizin_fallback = true;
        let radare2_calls = std::cell::Cell::new(0);
        let rizin_calls = std::cell::Cell::new(0);

        let error = run_report_with_discovery(
            &dir.path().join("missing-modem.bin"),
            &opts,
            &out,
            || {
                radare2_calls.set(radare2_calls.get() + 1);
                Ok(test_identity(
                    crate::thumb_analysis::ThumbProducer::Radare2,
                    "/tools/r2",
                    "radare2 exact",
                ))
            },
            || {
                rizin_calls.set(rizin_calls.get() + 1);
                Ok(test_identity(
                    crate::thumb_analysis::ThumbProducer::Rizin,
                    "/tools/rizin",
                    "rizin exact",
                ))
            },
        )
        .unwrap_err();

        assert!(matches!(error, Error::Io(_)));
        assert_eq!(radare2_calls.get(), 1);
        assert_eq!(rizin_calls.get(), 1);
        assert!(!out.exists());
    }

    /// radare2 is the required primary for `--run`, so a discovery failure is a
    /// hard preflight: no Rizin probe, no Ghidra work, no output tree, and no
    /// chance of a "successful" run that simply found no dense region.
    #[cfg(unix)]
    #[test]
    fn missing_radare2_fails_preflight_before_rizin_ghidra_or_output() {
        let dir = tempfile::tempdir().unwrap();
        let ghidra_home = dir.path().join("fake-ghidra");
        write_fake_headless(&ghidra_home);
        let image: Vec<u8> = (0u32..1536 * 1024).map(|value| value as u8).collect();
        let modem = dir.path().join("modem.bin");
        std::fs::write(&modem, craft_modem_bin(&[("MAIN", 0x4001_0000, 3, &image)])).unwrap();
        let out = dir.path().join("out");
        let mut opts = generation_opts(None);
        opts.run = true;
        opts.rizin_fallback = true;
        opts.ghidra_home = Some(ghidra_home.clone());
        let rizin_calls = std::cell::Cell::new(0);

        let error = run_report_with_discovery(
            &modem,
            &opts,
            &out,
            || Err(Error::ToolNotFound("radare2 (r2) not found on PATH".into())),
            || {
                rizin_calls.set(rizin_calls.get() + 1);
                Ok(test_identity(
                    crate::thumb_analysis::ThumbProducer::Rizin,
                    "/tools/rizin",
                    "rizin exact",
                ))
            },
        )
        .unwrap_err();

        assert!(
            matches!(&error, Error::ToolNotFound(reason) if reason.contains("radare2")),
            "{error}"
        );
        assert_eq!(rizin_calls.get(), 0, "Rizin was discovered without radare2");
        // The whole output tree — image slices, the import kit, and Ghidra's
        // export root — lives under `out`, so its absence proves nothing ran.
        assert!(!out.exists(), "preflight failure mutated the output tree");
    }

    #[cfg(unix)]
    #[test]
    fn injected_thumb_tools_reach_analysis_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let ghidra_home = dir.path().join("fake-ghidra");
        write_fake_headless(&ghidra_home);
        let image: Vec<u8> = (0u32..1536 * 1024).map(|value| value as u8).collect();
        let modem = dir.path().join("modem.bin");
        std::fs::write(&modem, craft_modem_bin(&[("MAIN", 0x4001_0000, 3, &image)])).unwrap();
        let out = dir.path().join("out");
        let mut opts = generation_opts(None);
        opts.run = true;
        opts.ghidra_home = Some(ghidra_home);
        opts.no_thumb_decompile = true;
        opts.rizin_fallback = true;
        opts.no_skip_opaque = true;
        let mut expected = crate::thumb_analysis::ThumbTools {
            radare2: test_identity(
                crate::thumb_analysis::ThumbProducer::Radare2,
                "/preflight/r2",
                "radare2 preflight",
            ),
            rizin: Some(test_identity(
                crate::thumb_analysis::ThumbProducer::Rizin,
                "/preflight/rizin",
                "rizin preflight",
            )),
        };
        expected.radare2.command = "radare2 preflight command";
        expected.rizin.as_mut().unwrap().command = "rizin preflight command";
        let observed = std::cell::RefCell::new(Vec::new());

        let report = run_report_with_thumb_tools_and_analyzer(
            &modem,
            &opts,
            &out,
            &expected,
            |tools, _, _, _, _| {
                observed.borrow_mut().push(tools.clone());
                Err(Error::Serialize("captured injected ThumbTools".into()))
            },
        )
        .unwrap();

        assert_eq!(observed.into_inner(), vec![expected]);
        assert_eq!(
            report.images[0].thumb_error.as_deref(),
            Some("serialize: captured injected ThumbTools")
        );
    }

    #[cfg(unix)]
    #[test]
    fn fake_radare2_route_emits_strict_v3_and_all_region_failure_preserves_sidecars() {
        let dir = tempfile::tempdir().unwrap();
        let ghidra_home = dir.path().join("fake-ghidra");
        write_fake_headless(&ghidra_home);
        let image: Vec<u8> = (0u32..1536 * 1024).map(|value| value as u8).collect();
        let modem = dir.path().join("modem.bin");
        std::fs::write(&modem, craft_modem_bin(&[("MAIN", 0x4001_0000, 3, &image)])).unwrap();
        let mut opts = generation_opts(None);
        opts.run = true;
        opts.ghidra_home = Some(ghidra_home);
        opts.no_thumb_decompile = true;
        opts.no_skip_opaque = true;

        let radare2 = dir.path().join("tools/r2-success");
        write_fake_radare2(&radare2, true);
        let radare2 = std::fs::canonicalize(radare2).unwrap();
        let tools = crate::thumb_analysis::ThumbTools {
            radare2: crate::thumb_analysis::ProducerIdentity {
                producer: crate::thumb_analysis::ThumbProducer::Radare2,
                executable: radare2.clone(),
                version: "radare2 route fixture 1.0".into(),
                command: crate::thumb_analysis::ThumbProducer::Radare2.command(),
            },
            rizin: None,
        };
        let out = dir.path().join("success");

        let report = run_report_with_thumb_tools(&modem, &opts, &out, &tools).unwrap();
        let image_result = &report.images[0];
        assert_eq!(image_result.thumb_functions, Some(0));
        assert_eq!(image_result.thumb_regions_requested, Some(1));
        assert_eq!(image_result.thumb_regions_succeeded, Some(1));
        assert_eq!(image_result.thumb_regions_failed, Some(0));
        assert_eq!(image_result.thumb_radare2_runs, Some(1));
        assert_eq!(image_result.thumb_rizin_runs, Some(0));
        assert_eq!(image_result.thumb_execution_accepted, Some(1));
        assert_eq!(image_result.thumb_execution_quarantined, Some(0));
        assert!(image_result.thumb_error.is_none());

        let export = out.join("export/02_MAIN");
        let sidecar = export.join("thumb_functions.json");
        let sidecar_bytes = std::fs::read(&sidecar).unwrap();
        let artifact: serde_json::Value = serde_json::from_slice(&sidecar_bytes).unwrap();
        assert_eq!(
            artifact["format"],
            "pixel-modem-extractor-thumb-functions-v3"
        );
        assert_eq!(artifact.as_object().unwrap().len(), 4);
        assert_eq!(
            artifact["producers"],
            serde_json::json!([{
                "id": "radare2",
                "executable": radare2.display().to_string(),
                "version": "radare2 route fixture 1.0",
                "command": "aaa;aflj;pdfj @@f"
            }])
        );
        assert_eq!(artifact["regions"].as_array().unwrap().len(), 1);
        let region = &artifact["regions"][0];
        assert_eq!(region["start"], "0x40010000");
        assert_eq!(region["end"], "0x40190000");
        assert_eq!(region["attempts"].as_array().unwrap().len(), 1);
        assert_eq!(region["attempts"][0]["producer"], "radare2");
        assert_eq!(region["attempts"][0]["status"], "succeeded");
        assert!(region["attempts"][0]["error"].is_null());
        let capture = &region["attempts"][0]["stdout"];
        assert_eq!(capture["path"], "thumb/40010000.radare2.stdout");
        let capture_bytes = std::fs::read(export.join(capture["path"].as_str().unwrap())).unwrap();
        assert_eq!(capture["bytes"], capture_bytes.len() as u64);
        assert_eq!(
            capture["blake3"],
            crate::manifest::blake3_bytes(&capture_bytes)
        );
        assert_eq!(
            region["function_runs"],
            serde_json::json!([{
                "producer": "radare2",
                "first_function": 0,
                "function_count": 1,
                "substantial": 0,
                "accepted": 1,
                "quarantined": 0
            }])
        );
        assert_eq!(artifact["functions"].as_array().unwrap().len(), 1);

        let failing_radare2 = dir.path().join("tools/r2-failure");
        write_fake_radare2(&failing_radare2, false);
        let failing_tools = crate::thumb_analysis::ThumbTools {
            radare2: crate::thumb_analysis::ProducerIdentity {
                producer: crate::thumb_analysis::ThumbProducer::Radare2,
                executable: std::fs::canonicalize(failing_radare2).unwrap(),
                version: "radare2 route fixture failure".into(),
                command: crate::thumb_analysis::ThumbProducer::Radare2.command(),
            },
            rizin: None,
        };
        let fresh_failure_out = dir.path().join("fresh-failure");
        let failed =
            run_report_with_thumb_tools(&modem, &opts, &fresh_failure_out, &failing_tools).unwrap();
        assert!(
            failed.images[0]
                .thumb_error
                .as_deref()
                .is_some_and(|error| error.contains("failed for every requested region"))
        );
        assert!(
            !fresh_failure_out
                .join("export/02_MAIN/thumb_functions.json")
                .exists()
        );

        // Rerunning over a tree that still holds the prior sidecar: Ghidra
        // succeeds, the Thumb stage fails every region, and terminal validation
        // rejects the retained sidecar as not current. That is a Thumb/terminal
        // failure, never "Ghidra failed" with a fabricated `exit: -1`.
        let before = std::fs::read(&sidecar).unwrap();
        let failed = run_report_with_thumb_tools(&modem, &opts, &out, &failing_tools).unwrap();
        let stale = &failed.images[0];
        assert!(matches!(stale.outcome, ImageOutcome::TerminalInvalid));
        assert!(
            stale
                .terminal_error
                .as_deref()
                .is_some_and(|reason| reason.contains("without a current producer result")),
            "{:?}",
            stale.terminal_error
        );
        // The all-region failure stays the reported root cause.
        assert!(
            stale
                .thumb_error
                .as_deref()
                .is_some_and(|error| error.contains("failed for every requested region"))
        );
        assert!(
            matches!(
                report_failure(&failed),
                Some(Error::DecomposeIncomplete(ref reason))
                    if reason.contains("Thumb analysis failed")
            ),
            "{:?}",
            report_failure(&failed)
        );
        assert_eq!(std::fs::read(&sidecar).unwrap(), before);
    }

    /// A current-run v3 ledger that disagrees with the retained sidecar is a
    /// Thumb/terminal failure with an actionable reason, not `exit: -1` from a
    /// Ghidra run that in fact succeeded.
    #[cfg(unix)]
    #[test]
    fn post_analysis_currentness_mismatch_is_terminal_not_a_ghidra_failure() {
        let dir = tempfile::tempdir().unwrap();
        let ghidra_home = dir.path().join("fake-ghidra");
        write_fake_headless(&ghidra_home);
        let image: Vec<u8> = (0u32..1536 * 1024).map(|value| value as u8).collect();
        let modem = dir.path().join("modem.bin");
        std::fs::write(&modem, craft_modem_bin(&[("MAIN", 0x4001_0000, 3, &image)])).unwrap();
        let mut opts = generation_opts(None);
        opts.run = true;
        opts.ghidra_home = Some(ghidra_home);
        opts.no_thumb_decompile = true;
        opts.no_skip_opaque = true;
        let radare2 = dir.path().join("tools/r2-success");
        write_fake_radare2(&radare2, true);
        let tools = crate::thumb_analysis::ThumbTools {
            radare2: crate::thumb_analysis::ProducerIdentity {
                producer: crate::thumb_analysis::ThumbProducer::Radare2,
                executable: std::fs::canonicalize(radare2).unwrap(),
                version: "radare2 currentness fixture".into(),
                command: crate::thumb_analysis::ThumbProducer::Radare2.command(),
            },
            rizin: None,
        };
        let out = dir.path().join("mismatch");

        let report = run_report_with_thumb_tools_and_analyzer(
            &modem,
            &opts,
            &out,
            &tools,
            |tools, image, load_addr, regions, out_dir| {
                // Produce a real v3 sidecar, then report a run ledger that
                // claims one more radare2 run than the artifact records.
                let mut summary = crate::thumb_analysis::run_thumb_analysis(
                    tools, image, load_addr, regions, out_dir,
                )?;
                summary.radare2_runs += 1;
                Ok(summary)
            },
        )
        .unwrap();

        let mismatched = &report.images[0];
        assert!(matches!(mismatched.outcome, ImageOutcome::TerminalInvalid));
        assert!(
            mismatched
                .terminal_error
                .as_deref()
                .is_some_and(|reason| reason.contains("radare2_runs")),
            "{:?}",
            mismatched.terminal_error
        );
        assert_eq!(
            mismatched.thumb_error.as_deref(),
            mismatched.terminal_error.as_deref(),
            "a Thumb-stage rejection must populate thumb_error"
        );
        assert!(
            matches!(
                report_failure(&report),
                Some(Error::DecomposeIncomplete(ref reason))
                    if reason.contains("Thumb analysis failed")
            ),
            "{:?}",
            report_failure(&report)
        );
    }

    /// Low-entropy ARM-ish pattern half for the partial-encryption guard
    /// (mirrors classify.rs's test pattern: 16 distinct bytes).
    fn arm_ish_pattern_blob(len: usize) -> Vec<u8> {
        const PATTERN: [u8; 16] = [
            0x00, 0xBF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
            0xDD, 0xEE,
        ];
        (0..len).map(|i| PATTERN[i % 16]).collect()
    }

    #[test]
    fn opaque_skip_decision_is_the_pure_gate() {
        // A uniform blob is unanimously opaque -> Some(stats), the pure
        // decision path that returns before any process spawn.
        let stats = opaque_skip(&crate::classify::test_uniform_blob(256 * 1024))
            .expect("uniform blob is unanimously opaque");
        assert!(stats.opaque);

        // Half-and-half (uniform half + code half): window_min and
        // frac_windows_high refuse -> None -> the image goes to Ghidra.
        let mut half_and_half = crate::classify::test_uniform_blob(128 * 1024);
        half_and_half.extend(arm_ish_pattern_blob(128 * 1024));
        assert!(opaque_skip(&half_and_half).is_none());
    }

    #[test]
    fn skipped_opaque_result_is_not_a_failure_and_expects_no_export() {
        // A SkippedOpaque RunResult is a successful outcome: report_failure
        // must return None, so `decompile --run --image 01_PSP` exits 0 and
        // no export/<label>/ expectations are validated for it (the skip
        // branch returns before any Ghidra/Thumb-analyzer spawn; exhaustive match
        // sites are enforced by compiling).
        let report = DecompileReport {
            images: vec![ImageResult {
                label: "01_PSP".into(),
                outcome: ImageOutcome::SkippedOpaque(crate::classify::classify(
                    &crate::classify::test_uniform_blob(256 * 1024),
                )),
                classification: Some("opaque"),
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
                exception_state: RuntimeExceptionState::Unmanaged,
                exception_roots_applied: None,
                exception_error: None,
                pal_applied: None,
            }],
            spec_path: PathBuf::from("ghidra_load.json"),
            current_exports: BTreeSet::new(),
            runtime_scatter: HashMap::new(),
            runtime_exception_roots: HashMap::new(),
            runtime_tasks: HashMap::new(),
        };
        assert!(report_failure(&report).is_none());
    }

    #[test]
    fn report_failure_does_not_duplicate_label_for_missing_radare2() {
        let report = DecompileReport {
            images: vec![ImageResult {
                label: "02_MAIN".into(),
                outcome: ImageOutcome::Analyzed(12),
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
                thumb_error: Some(
                    "1 Thumb region(s) left unanalyzed — radare2 (r2) not on PATH; Ghidra can't analyze them"
                        .into(),
                ),
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
                exception_state: RuntimeExceptionState::Unmanaged,
                exception_roots_applied: None,
                exception_error: None,
                pal_applied: None,
            }],
            spec_path: PathBuf::from("ghidra_load.json"),
            current_exports: BTreeSet::new(),
            runtime_scatter: HashMap::new(),
            runtime_exception_roots: HashMap::new(),
            runtime_tasks: HashMap::new(),
        };

        let err = report_failure(&report).expect("thumb error should fail standalone run");
        assert_eq!(
            err.to_string(),
            "decompose incomplete: Thumb analysis failed on 02_MAIN: 1 Thumb region(s) left unanalyzed — radare2 (r2) not on PATH; Ghidra can't analyze them"
        );
    }

    #[test]
    fn image_result_carries_phase3_0_1_fields() {
        let r = ImageResult {
            label: "02_MAIN".into(),
            outcome: ImageOutcome::Analyzed(10),
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
            globals_recovered: Some(968),
            globals_applied: None,
            globals_apply_skipped: None,
            globals_apply_error: None,
            global_types_applied: None,
            global_types_apply_skipped: None,
            global_types_apply_error: None,
            globals_provisional: Some(42),
            globals_provisional_suppressed: Some(7),
            exception_state: RuntimeExceptionState::Unmanaged,
            exception_roots_applied: None,
            exception_error: None,
            pal_applied: None,
        };
        assert_eq!(r.globals_provisional, Some(42));
        assert_eq!(r.globals_provisional_suppressed, Some(7));
    }

    #[test]
    fn run_generation_only_writes_kit() {
        let buf = craft_modem_bin(&[
            ("BOOT", 0x0, 1, &[0u8; 4]),
            ("MAIN", 0x4001_0000, 3, &[0u8; 8]),
        ]);
        let dir = std::env::temp_dir().join(format!("pme_decompile_gen_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let modem = dir.join("modem.bin");
        std::fs::write(&modem, &buf).unwrap();
        let out = dir.join("out");
        let opts = Opts {
            run: false,
            image: None,
            ghidra_home: None,
            processor: "ARM:LE:32:v7".into(),
            no_thumb_decompile: false,
            rizin_fallback: false,
            tighten_wall_clock_budget_override: None,
            no_skip_opaque: false,
        };
        run(&modem, &opts, &out).unwrap();

        assert!(out.join("images").join("00_BOOT").exists());
        assert!(out.join("images").join("02_MAIN").exists());
        assert!(out.join("scripts").join("TameAnalysis.java").exists());
        assert!(out.join("scripts").join("ExportDecomp.java").exists());

        let spec: serde_json::Value =
            serde_json::from_slice(&std::fs::read(out.join("ghidra_load.json")).unwrap()).unwrap();
        assert_eq!(spec["processor"], "ARM:LE:32:v7");
        assert_eq!(spec["images"][0]["name"], "00_BOOT");
        assert_eq!(spec["images"][0]["base_addr"], "0x00000000");
        assert_eq!(spec["images"][0]["file"], "images/00_BOOT");
        assert_eq!(spec["images"][1]["base_addr"], "0x40010000");

        let sh = std::fs::read_to_string(out.join("run_ghidra.sh")).unwrap();
        assert!(sh.contains("analyzeHeadless"));
        assert!(
            sh.contains("TameAnalysis.java"),
            "run script must wire the pre-script:\n{sh}"
        );
        assert!(sh.contains("'-loader-baseAddr' '40010000'"), "sh:\n{sh}");
        assert!(!sh.contains("0x40010000"));
        assert!(
            sh.contains("mkdir -p \"$HERE/ghidra_project\""),
            "run_ghidra.sh must create the project dir:\n{sh}"
        );
        assert!(
            sh.contains(
                "STATE_HOME=\"$(mktemp -d \"${TMPDIR:-/tmp}/pixel-modem-ghidra.XXXXXXXX\")\""
            ),
            "run_ghidra.sh must derive its state home from a unique space-free mktemp -d:\n{sh}"
        );
        assert!(
            sh.contains("case \"$STATE_HOME\" in")
                && sh.contains("the temp directory path contains whitespace; set TMPDIR to a space-free directory"),
            "run_ghidra.sh must fail closed on a space-containing TMPDIR instead of word-splitting the -D tokens:\n{sh}"
        );
        assert!(
            sh.contains("trap cleanup EXIT")
                && sh.contains("cleanup() { rm -rf \"$STATE_HOME\"; }"),
            "run_ghidra.sh must remove its state home through the cleanup trap:\n{sh}"
        );
        assert!(
            sh.contains("export XDG_CONFIG_HOME=\"$STATE_HOME/ghidra_config\""),
            "run_ghidra.sh must keep Ghidra config under the state home:\n{sh}"
        );
        assert!(
            sh.contains("export XDG_CACHE_HOME=\"$STATE_HOME/ghidra_cache\""),
            "run_ghidra.sh must keep Ghidra cache under the state home:\n{sh}"
        );
        assert!(
            sh.contains("-Dapplication.tempdir=$STATE_HOME/ghidra_tmp"),
            "run_ghidra.sh must keep Ghidra temp files under the state home:\n{sh}"
        );
        assert!(
            !sh.contains("$HERE/ghidra_config") && !sh.contains("$HERE/ghidra_tmp"),
            "run_ghidra.sh must not leak Java/XDG state into the kit root:\n{sh}"
        );
        assert!(
            sh.contains("GHIDRA_HEADLESS_JAVA_OPTIONS=\"$GHIDRA_HEADLESS_JAVA_OPTIONS $GHIDRA_LOCAL_JAVA_OPTIONS\""),
            "run_ghidra.sh must preserve caller-provided headless Java options:\n{sh}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn symbol_map_creation_limits() {
        // A giant map is not a practical unit fixture, so pin the parser's
        // combined execution-plus-creation accounting at its source boundary.
        let creations = PAL_TASKS_SUPPORT_JAVA
            .split_once("name(reader, \"creations\");")
            .expect("PalTasksSupport must parse creations")
            .1
            .split_once("endArray(reader, \"creations\");")
            .expect("PalTasksSupport must finish the creations array")
            .0;
        let parser = creations.split_whitespace().collect::<Vec<_>>().join(" ");
        let unique_position = |needle: &str| {
            let positions = parser
                .match_indices(needle)
                .map(|(offset, _)| offset)
                .collect::<Vec<_>>();
            assert_eq!(
                positions.len(),
                1,
                "creations parser must contain exactly one {needle:?}"
            );
            positions[0]
        };

        let loops = parser
            .match_indices("while (arrayHasNext(reader)) {")
            .map(|(offset, _)| offset)
            .collect::<Vec<_>>();
        assert_eq!(
            loops.len(),
            2,
            "creations parser must contain exactly its outer creation loop and inner range loop"
        );
        let outer_loop = loops[0];
        let inner_loop = loops[1];
        let inner_loop_end = unique_position("} endArray(reader, \"decode_ranges\");");
        let range_total = unique_position("long creationRangeTotal = totalRanges;");
        let charged_total = unique_position("long creationChargedTotal = chargedBytes;");
        let range_guard =
            unique_position("if (creationRangeTotal >= MAX_EXECUTION_RANGES_TOTAL) {");
        let per_creation_add = unique_position(
            "creationCharged = checkedAdd(creationCharged, end - start, \"charged range bytes\");",
        );
        let per_creation_guard =
            unique_position("if (creationCharged > MAX_CHARGED_RANGE_BYTES) {");
        let combined_add = unique_position(
            "creationChargedTotal = checkedAdd(creationChargedTotal, end - start, \"aggregate creation charged range bytes\");",
        );
        let combined_guard =
            unique_position("if (creationChargedTotal > MAX_CHARGED_RANGE_BYTES) {");
        let range_increment = unique_position("creationRangeTotal++;");
        let accept =
            unique_position("ranges.add(new ExecutionRangeWire(isa, start, end, blake3));");

        assert!(
            range_total < outer_loop && charged_total < outer_loop,
            "aggregate creation totals must be initialized before the outer creation loop"
        );
        assert!(
            outer_loop < inner_loop,
            "the outer creation loop must precede the inner range loop"
        );
        for (relationship, position) in [
            ("aggregate range guard", range_guard),
            ("per-creation charged-byte addition", per_creation_add),
            ("per-creation charged-byte guard", per_creation_guard),
            ("aggregate charged-byte addition", combined_add),
            ("aggregate charged-byte guard", combined_guard),
            ("aggregate range increment", range_increment),
            ("range acceptance", accept),
        ] {
            assert!(
                inner_loop < position && position < inner_loop_end,
                "{relationship} must remain inside the inner range loop"
            );
        }
        assert!(range_guard < range_increment && range_increment < accept);
        assert!(per_creation_add < per_creation_guard && per_creation_guard < accept);
        assert!(combined_add < combined_guard && combined_guard < accept);
    }

    #[test]
    fn generated_kit_stages_pal_support() {
        // The Rust-side Ghidra leaf limit and the Java-side runtime
        // assertion must pin the same 2000-character ceiling.
        assert_eq!(crate::pal_tasks::MAX_SYMBOL_LEAF_BYTES, 2000);

        let buf = craft_modem_bin(&[("MAIN", 0x4001_0000, 3, &[0u8; 8])]);
        let dir = std::env::temp_dir().join(format!("pme_pal_support_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let modem = dir.join("modem.bin");
        std::fs::write(&modem, &buf).unwrap();
        let out = dir.join("out");
        let opts = Opts {
            run: false,
            image: None,
            ghidra_home: None,
            processor: "ARM:LE:32:v7".into(),
            no_thumb_decompile: false,
            rizin_fallback: false,
            tighten_wall_clock_budget_override: None,
            no_skip_opaque: false,
        };
        run(&modem, &opts, &out).unwrap();

        let staged_path = out.join("scripts").join("PalTasksSupport.java");
        let staged = std::fs::read(&staged_path).unwrap_or_default();
        assert_eq!(
            staged,
            PAL_TASKS_SUPPORT_JAVA.as_bytes(),
            "generated kits must stage the exact PalTasksSupport source"
        );
        let shared_staged =
            std::fs::read(out.join("scripts/PmeScriptSupport.java")).unwrap_or_default();
        assert_eq!(
            shared_staged,
            PME_SCRIPT_SUPPORT_JAVA.as_bytes(),
            "generated kits must stage the exact shared script support source"
        );

        // Source contract: PalTasksSupport owns the one copy of every PAL
        // parser/digest/registry constant; generic symbol policy is shared.
        // No other staged script may redefine the PAL constants below.
        let source = PAL_TASKS_SUPPORT_JAVA;
        for owned in [
            "pixel-modem-extractor-pal-tasks-v1",
            "pixel-modem-extractor-symbol-map-v4",
            "PixelModemExtractor_PalTasks_v1",
            "PixelModemExtractor.PalTasks.v1.Ownership",
            "PixelModemExtractor.ThumbNames.v1.Ownership",
            "PixelModemExtractor.PalTasks\"",
            "PixelModemExtractor.SymbolPass2",
            "pixel-modem-extractor-execution-v1",
            "pixel-modem-extractor-pal-labels-v1",
            "pixel-modem-extractor-pal-primary-v1",
            "pixel-modem-extractor-pal-comment-v1",
        ] {
            assert!(
                source.contains(owned),
                "PalTasksSupport.java must own the constant {owned:?}"
            );
        }

        let mut staged_scripts = std::fs::read_dir(out.join("scripts"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "java")
            })
            .collect::<Vec<_>>();
        staged_scripts.sort();
        assert_eq!(
            staged_scripts
                .iter()
                .map(|path| path.to_string_lossy())
                .collect::<Vec<_>>(),
            vec![
                out.join("scripts/ApplyExceptionRoots.java")
                    .to_string_lossy(),
                out.join("scripts/ApplyGlobalTypes.java").to_string_lossy(),
                out.join("scripts/ApplyGlobals.java").to_string_lossy(),
                out.join("scripts/ApplyPalTasks.java").to_string_lossy(),
                out.join("scripts/ApplyScatterLoad.java").to_string_lossy(),
                out.join("scripts/ApplySymbols.java").to_string_lossy(),
                out.join("scripts/ApplyThumbNames.java").to_string_lossy(),
                out.join("scripts/ExceptionRootsSupport.java")
                    .to_string_lossy(),
                out.join("scripts/ExportDecomp.java").to_string_lossy(),
                out.join("scripts/PalTasksSupport.java").to_string_lossy(),
                out.join("scripts/PmeScriptSupport.java").to_string_lossy(),
                out.join("scripts/TameAnalysis.java").to_string_lossy(),
            ]
        );
        for path in &staged_scripts {
            if path
                .file_name()
                .is_some_and(|name| name == "PalTasksSupport.java")
            {
                continue;
            }
            let other = std::fs::read_to_string(path).unwrap();
            for owned in [
                "PixelModemExtractor_PalTasks_v1",
                "PixelModemExtractor.PalTasks.v1.Ownership",
                "pixel-modem-extractor-pal-labels-v1",
                "pixel-modem-extractor-pal-primary-v1",
                "pixel-modem-extractor-pal-comment-v1",
            ] {
                assert!(
                    !other.contains(owned),
                    "{} redefines the PAL constant {owned:?} owned by PalTasksSupport",
                    path.display()
                );
            }
            let normalized = other.split_whitespace().collect::<Vec<_>>().join(" ");
            assert!(
                !normalized.contains("static final String THUMB_CREATION_OWNERSHIP_MAP"),
                "{} redeclares THUMB_CREATION_OWNERSHIP_MAP owned by PalTasksSupport",
                path.display()
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn locate_tools_respects_precedence() {
        let base = std::env::temp_dir().join(format!("pme_ghidra_locate_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let home = base.join("home");
        std::fs::create_dir_all(home.join("support")).unwrap();
        std::fs::write(home.join("support").join("analyzeHeadless"), b"#!/bin/sh\n").unwrap();
        let want = home.join("support").join("analyzeHeadless");

        // --ghidra-home wins
        assert_eq!(
            locate_tools(Some(&home), None, &[], None)
                .map(|g| g.headless)
                .as_ref(),
            Some(&want)
        );
        // $GHIDRA_INSTALL_DIR used when --ghidra-home is None
        assert_eq!(
            locate_tools(None, Some(&home), &[], None)
                .map(|g| g.headless)
                .as_ref(),
            Some(&want)
        );
        // PATH dir used as last resort (analyzeHeadless directly in the dir)
        let pdir = base.join("pbin");
        std::fs::create_dir_all(&pdir).unwrap();
        std::fs::write(pdir.join("analyzeHeadless"), b"#!/bin/sh\n").unwrap();
        assert_eq!(
            locate_tools(None, None, std::slice::from_ref(&pdir), None).map(|g| g.headless),
            Some(pdir.join("analyzeHeadless"))
        );
        // nothing found -> None
        assert!(locate_tools(None, None, &[], None).is_none());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn locate_tools_falls_back_to_default_root() {
        // The conventional /opt/ghidra install is probed only after --ghidra-home,
        // $GHIDRA_INSTALL_DIR, and PATH all miss. A temp dir is injected as the
        // default root so the test never touches the real /opt/ghidra.
        let base = std::env::temp_dir().join(format!("pme_ghidra_default_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let default_root = base.join("opt").join("ghidra");
        std::fs::create_dir_all(default_root.join("support")).unwrap();
        std::fs::write(
            default_root.join("support").join("analyzeHeadless"),
            b"#!/bin/sh\n",
        )
        .unwrap();
        let want = default_root.join("support").join("analyzeHeadless");

        // Nothing from --ghidra-home / env / PATH -> the default root is used.
        assert_eq!(
            locate_tools(None, None, &[], Some(&default_root)).map(|g| g.headless),
            Some(want)
        );

        // An explicit source still wins over the default: a PATH dir with a bare
        // analyzeHeadless takes precedence over the /opt/ghidra fallback.
        let pdir = base.join("pbin");
        std::fs::create_dir_all(&pdir).unwrap();
        std::fs::write(pdir.join("analyzeHeadless"), b"#!/bin/sh\n").unwrap();
        assert_eq!(
            locate_tools(None, None, std::slice::from_ref(&pdir), Some(&default_root))
                .map(|g| g.headless),
            Some(pdir.join("analyzeHeadless"))
        );

        // No default provided and nothing else -> None (fallback is opt-in).
        assert!(locate_tools(None, None, &[], None).is_none());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn headless_in_root_finds_upstream_and_homebrew_layouts() {
        let base = std::env::temp_dir().join(format!("pme_hir_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);

        // upstream: <root>/support/analyzeHeadless
        let up = base.join("upstream");
        std::fs::create_dir_all(up.join("support")).unwrap();
        std::fs::write(up.join("support").join("analyzeHeadless"), b"#!/bin/sh\n").unwrap();
        assert_eq!(
            headless_in_root(&up),
            Some(up.join("support").join("analyzeHeadless"))
        );

        // homebrew: <root>/libexec/support/analyzeHeadless
        let brew = base.join("brew");
        std::fs::create_dir_all(brew.join("libexec").join("support")).unwrap();
        std::fs::write(
            brew.join("libexec").join("support").join("analyzeHeadless"),
            b"#!/bin/sh\n",
        )
        .unwrap();
        assert_eq!(
            headless_in_root(&brew),
            Some(brew.join("libexec").join("support").join("analyzeHeadless"))
        );

        // neither -> None
        assert!(headless_in_root(&base.join("empty")).is_none());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn ghidra_home_accepts_homebrew_layout() {
        // A Homebrew-style prefix: analyzeHeadless under libexec/support, wrapper under bin/.
        let base = std::env::temp_dir().join(format!("pme_hbhome_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("opt").join("ghidra");
        std::fs::create_dir_all(root.join("libexec").join("support")).unwrap();
        std::fs::write(
            root.join("libexec").join("support").join("analyzeHeadless"),
            b"#!/bin/sh\n",
        )
        .unwrap();
        std::fs::create_dir_all(root.join("bin")).unwrap();
        std::fs::write(root.join("bin").join("ghidraRun"), b"#!/bin/bash\n").unwrap();

        let got = locate_tools(Some(&root), None, &[], None).unwrap();
        assert_eq!(
            got.headless,
            root.join("libexec").join("support").join("analyzeHeadless")
        );
        assert_eq!(got.ghidra_run, Some(root.join("bin").join("ghidraRun")));

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn roots_from_ghidra_run_yields_dir_then_parent() {
        let run = PathBuf::from("/opt/homebrew/Cellar/ghidra/12.1.2/bin/ghidraRun");
        assert_eq!(
            roots_from_ghidra_run(&run),
            vec![
                PathBuf::from("/opt/homebrew/Cellar/ghidra/12.1.2/bin"),
                PathBuf::from("/opt/homebrew/Cellar/ghidra/12.1.2"),
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn path_ghidra_run_symlink_resolves_to_homebrew_headless() {
        // Mimic Homebrew: PATH holds a `ghidraRun` symlink into a Cellar-like tree whose
        // analyzeHeadless lives under libexec/support. Discovery must canonicalize the
        // symlink, derive the root, and find the launcher there.
        let base = std::env::temp_dir().join(format!("pme_pathrun_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let cellar = base.join("Cellar").join("ghidra").join("12.1.2");
        std::fs::create_dir_all(cellar.join("libexec").join("support")).unwrap();
        std::fs::write(
            cellar
                .join("libexec")
                .join("support")
                .join("analyzeHeadless"),
            b"#!/bin/sh\n",
        )
        .unwrap();
        std::fs::create_dir_all(cellar.join("bin")).unwrap();
        std::fs::write(cellar.join("bin").join("ghidraRun"), b"#!/bin/bash\n").unwrap();

        let pbin = base.join("bin");
        std::fs::create_dir_all(&pbin).unwrap();
        std::os::unix::fs::symlink(cellar.join("bin").join("ghidraRun"), pbin.join("ghidraRun"))
            .unwrap();

        let got = locate_tools(None, None, std::slice::from_ref(&pbin), None).unwrap();
        assert_eq!(
            got.headless,
            std::fs::canonicalize(
                cellar
                    .join("libexec")
                    .join("support")
                    .join("analyzeHeadless")
            )
            .unwrap()
        );
        assert!(got.ghidra_run.is_some());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn build_load_spec_maps_toc_addresses() {
        let buf = craft_modem_bin(&[
            ("BOOT", 0x0, 1, &[0xaa, 0xbb, 0xcc, 0xdd]),
            ("MAIN", 0x4001_0000, 3, &[0u8; 8]),
        ]);
        let toc = Toc::parse(&buf).unwrap();
        let spec = build_load_spec(&toc, &buf, "modem.bin", "ARM:LE:32:v7").unwrap();
        assert_eq!(spec.processor, "ARM:LE:32:v7");
        assert_eq!(spec.source.path, "modem.bin");
        assert_eq!(spec.source.blake3.len(), 64);
        assert_eq!(spec.images.len(), 2);
        assert_eq!(spec.images[0].name, "00_BOOT");
        assert_eq!(spec.images[0].file, "images/00_BOOT");
        assert_eq!(spec.images[0].base_addr, "0x00000000");
        assert_eq!(spec.images[0].entry_point, "0x00000000");
        assert_eq!(spec.images[0].size, 4);
        assert_eq!(spec.images[0].blake3.len(), 64);
        assert_eq!(spec.images[1].name, "02_MAIN");
        assert_eq!(spec.images[1].file, "images/02_MAIN");
        assert_eq!(spec.images[1].base_addr, "0x40010000");
        assert_eq!(spec.images[1].entry_point, "0x40010000");
        assert_eq!(spec.images[1].size, 8);
        assert_eq!(spec.images[1].blake3.len(), 64);
    }

    #[test]
    fn build_load_spec_errors_on_out_of_range_image() {
        // valid TOC, then corrupt entry 0's size field (@0x34) to exceed the buffer.
        let mut buf = craft_modem_bin(&[("BOOT", 0x0, 1, &[0u8; 4])]);
        buf[0x34..0x38].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
        let toc = Toc::parse(&buf).unwrap();
        assert!(build_load_spec(&toc, &buf, "modem.bin", "ARM:LE:32:v7").is_err());
    }

    #[test]
    fn image_matches_label_or_bare_name_or_all() {
        assert!(image_matches(None, "02_MAIN", "MAIN")); // no filter → all
        assert!(image_matches(Some("02_MAIN"), "02_MAIN", "MAIN")); // canonical label
        assert!(image_matches(Some("MAIN"), "02_MAIN", "MAIN")); // bare name
        assert!(!image_matches(Some("BOOT"), "02_MAIN", "MAIN")); // no match
    }

    #[test]
    fn count_functions_reads_array_len() {
        let dir = std::env::temp_dir().join(format!("pme_count_fns_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // populated array → element count
        std::fs::write(
            dir.join("functions.json"),
            br#"[{"name":"a","entry":"0x0","size":4},{"name":"b","entry":"0x4","size":8}]"#,
        )
        .unwrap();
        assert_eq!(count_functions(&dir), 2);
        // empty array (an encrypted/compressed partition: no disassembly) → 0
        std::fs::write(dir.join("functions.json"), b"[\n]\n").unwrap();
        assert_eq!(count_functions(&dir), 0);
        // missing file → 0 (no panic)
        std::fs::remove_file(dir.join("functions.json")).unwrap();
        assert_eq!(count_functions(&dir), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ghidra_export_run_invalidates_and_validates_only_a_complete_current_set() {
        let root = tempfile::tempdir().unwrap();
        let run = GhidraExportRun::new(root.path(), "02_MAIN");
        assert_eq!(run.directory, root.path().join("export/02_MAIN"));
        assert_eq!(run.completion, root.path().join("export/02_MAIN.complete"));
        std::fs::create_dir_all(&run.directory).unwrap();
        for name in GHIDRA_EXPORT_FILES {
            std::fs::write(run.directory.join(name), format!("stale {name}\n")).unwrap();
        }
        std::fs::write(
            &run.completion,
            export_completion_marker("none", "none", "none"),
        )
        .unwrap();

        run.invalidate().unwrap();

        assert!(!run.completion.exists());
        for name in GHIDRA_EXPORT_FILES {
            assert!(!run.directory.join(name).exists());
        }
        assert!(run.validate_current("none", "none", "none").is_err());

        for name in GHIDRA_EXPORT_FILES {
            std::fs::write(run.directory.join(name), b"current\n").unwrap();
        }
        std::fs::write(&run.completion, b"wrong generation\n").unwrap();
        assert!(run.validate_current("none", "none", "none").is_err());
        // A complete old v3 marker is stale, not normalized.
        std::fs::write(
            &run.completion,
            b"pixel-modem-extractor-ghidra-export-v3\npal_tasks=none\nsymbol_map=none\n",
        )
        .unwrap();
        assert!(run.validate_current("none", "none", "none").is_err());
        std::fs::write(
            &run.completion,
            export_completion_marker("none", "none", "none"),
        )
        .unwrap();
        run.validate_current("none", "none", "none").unwrap();
        // Stale identity or map binding values are rejected exactly.
        let bound = export_completion_marker(
            "v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:2:0",
            "none",
            "none",
        );
        std::fs::write(&run.completion, &bound).unwrap();
        assert!(run.validate_current("none", "none", "none").is_err());
        assert!(
            run.validate_current(
                "v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:2:0",
                "none",
                "none"
            )
            .is_ok()
        );
    }

    #[test]
    fn export_invalidation_scrubs_other_owned_files_after_a_structural_failure() {
        let root = tempfile::tempdir().unwrap();
        let run = GhidraExportRun::new(root.path(), "02_MAIN");
        std::fs::create_dir_all(run.directory.join("functions.json")).unwrap();
        std::fs::write(run.directory.join("disasm.lst"), b"stale\n").unwrap();
        std::fs::write(run.directory.join("decompiled.c"), b"stale\n").unwrap();
        std::fs::write(
            &run.completion,
            export_completion_marker("none", "none", "none"),
        )
        .unwrap();

        run.invalidate().unwrap_err();

        assert!(!run.completion.exists());
        assert!(run.directory.join("functions.json").is_dir());
        assert!(!run.directory.join("disasm.lst").exists());
        assert!(!run.directory.join("decompiled.c").exists());
    }

    #[test]
    fn exporter_publishes_completion_atomically_in_the_marker_directory() {
        assert!(
            EXPORT_DECOMP_JAVA.contains(
                "File.createTempFile(outDir.getName() + \".complete.\", \".tmp\", parent)"
            )
        );
        assert!(EXPORT_DECOMP_JAVA.contains("StandardCopyOption.ATOMIC_MOVE"));
        assert!(EXPORT_DECOMP_JAVA.contains("StandardCopyOption.REPLACE_EXISTING"));
    }

    #[test]
    fn export_fallback_is_limited_to_map_absent_runs() {
        assert!(
            EXPORT_DECOMP_JAVA.contains("if (map == null && fm.getFunctionCount() == 0)"),
            "the entry fallback must never mutate map-authenticated pass-2 state"
        );
    }

    #[test]
    fn run_script_probes_both_ghidra_layouts() {
        let base = std::env::temp_dir().join(format!("pme_runscript_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let buf = craft_modem_bin(&[("BOOT", 0x0, 1, &[0xaa, 0xbb, 0xcc, 0xdd])]);
        let toc = Toc::parse(&buf).unwrap();
        write_run_script(
            &base,
            &toc,
            "ARM:LE:32:v7",
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap();
        let sh = std::fs::read_to_string(base.join("run_ghidra.sh")).unwrap();
        assert!(
            sh.contains("$GHIDRA_INSTALL_DIR/support/analyzeHeadless"),
            "sh:\n{sh}"
        );
        assert!(
            sh.contains("$GHIDRA_INSTALL_DIR/libexec/support/analyzeHeadless"),
            "sh:\n{sh}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn shell_quote_escapes_metacharacters() {
        // Plain alphanumeric / path chars stay readable (no quoting noise).
        assert_eq!(shell_quote("ARM:LE:32:v7"), "'ARM:LE:32:v7'");
        assert_eq!(shell_quote("40010000"), "'40010000'");
        // Empty string is the empty-quoted form.
        assert_eq!(shell_quote(""), "''");
        // A single embedded quote splits the literal — `'\''` — and the rest reopens.
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn run_script_quotes_processor_arg_against_injection() {
        // `--processor` flows in unfiltered from the user; an injection attempt
        // like `a';rm -rf $HOME;echo'` must round-trip as a single-quoted literal
        // and never break out of the quoted argv token.
        let base = std::env::temp_dir().join(format!("pme_runscript_inj_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let buf = craft_modem_bin(&[("BOOT", 0x0, 1, &[0xaa, 0xbb])]);
        let toc = Toc::parse(&buf).unwrap();
        let evil = "a';rm -rf $HOME;echo'";
        write_run_script(
            &base,
            &toc,
            evil,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap();
        let sh = std::fs::read_to_string(base.join("run_ghidra.sh")).unwrap();
        // The processor appears only inside the single-quoted, escaped form — never
        // raw. The dangerous chars (`;`, `$`, ` `, `'`) are inert inside the quotes.
        assert!(
            sh.contains(&shell_quote(evil)),
            "expected processor to be shell-quoted in:\n{sh}"
        );
        // The raw payload (with its `;` command separators) must NOT appear
        // unquoted anywhere in the script — that would be a command injection.
        assert!(
            !sh.contains(evil),
            "raw injection payload leaked unquoted in:\n{sh}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("pme_{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_consumer_v3_fixture(path: &Path) {
        std::fs::write(
            path,
            crate::thumb_analysis::ParsedThumbArtifact::consumer_v3_fixture(),
        )
        .unwrap();
    }

    #[test]
    fn thumb_enrich_preserves_v3_provenance() {
        let root = temp_dir("thumb_enrich_v3_provenance");
        let c_path = root.join("decompiled.c");
        std::fs::write(
            &c_path,
            "// FUN_4000 @ 00004000\nvoid FUN_4000(void)\n{\n  return;\n}\n",
        )
        .unwrap();
        let thumb_path = root.join("thumb_functions.json");
        let original = crate::thumb_analysis::ParsedThumbArtifact::consumer_v3_fixture();
        std::fs::write(&thumb_path, original).unwrap();
        let before: serde_json::Value = serde_json::from_slice(original).unwrap();

        assert_eq!(
            thumb_enrich(&c_path, &thumb_path, &test_runtime()).unwrap(),
            1
        );
        let rewritten_bytes = std::fs::read(&thumb_path).unwrap();
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
        let mut before_function = before["functions"][0].clone();
        let mut after_function = after["functions"][0].clone();
        before_function.as_object_mut().unwrap().remove("body_c");
        let body_c = after_function
            .as_object_mut()
            .unwrap()
            .remove("body_c")
            .unwrap();
        assert!(body_c.as_str().unwrap().contains("FUN_4000"));
        assert_eq!(after_function, before_function);
        assert_eq!(after["functions"][1], before["functions"][1]);
    }

    #[test]
    fn thumb_enrich_v3_noop_is_byte_identical() {
        let root = temp_dir("thumb_enrich_v3_noop");
        let body = "// FUN_4000 @ 00004000\nvoid FUN_4000(void)\n{\n}\n";
        let c_path = root.join("decompiled.c");
        std::fs::write(&c_path, body).unwrap();
        let thumb_path = root.join("thumb_functions.json");
        std::fs::write(
            &thumb_path,
            crate::thumb_analysis::ParsedThumbArtifact::consumer_v3_fixture(),
        )
        .unwrap();
        let mut artifact =
            crate::thumb_analysis::read_thumb_artifact(&thumb_path, &test_runtime()).unwrap();
        artifact.function_values_mut()[0]["body_c"] = serde_json::json!(body);
        artifact.write_atomic(&thumb_path).unwrap();
        let before = std::fs::read(&thumb_path).unwrap();

        assert_eq!(
            thumb_enrich(&c_path, &thumb_path, &test_runtime()).unwrap(),
            1
        );
        assert_eq!(std::fs::read(&thumb_path).unwrap(), before);
    }

    #[test]
    fn thumb_enrich_populates_body_c_for_matching_entry() {
        let root = temp_dir("thumb_enrich_match");
        let c_path = root.join("decompiled.c");
        // ExportDecomp.java emits "// <name> @ <addr>\n<C>\n\n" per function.
        // Ghidra's pre-pass-2 names are `FUN_<addr>`; the entry address is what
        // thumb_enrich matches by.
        std::fs::write(
            &c_path,
            "// FUN_4000 @ 00004000\nvoid FUN_4000(int a)\n{\n  return;\n}\n\n",
        )
        .unwrap();
        let thumb_path = root.join("thumb_functions.json");
        write_consumer_v3_fixture(&thumb_path);

        let n = thumb_enrich(&c_path, &thumb_path, &test_runtime()).unwrap();
        assert_eq!(n, 1, "exactly one function matched by address");

        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&thumb_path).unwrap()).unwrap();
        assert_eq!(v["format"], "pixel-modem-extractor-thumb-functions-v3");
        assert!(v["functions"][0]["body_c"].is_string());
        assert!(
            v["functions"][0]["body_c"]
                .as_str()
                .unwrap()
                .contains("FUN_4000"),
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
            "// FUN_4000 @ 00004000\n\nvoid FUN_4000(int a)\n\n{\n  return;\n}\n\n",
        )
        .unwrap();
        let thumb_path = root.join("thumb_functions.json");
        write_consumer_v3_fixture(&thumb_path);

        let n = thumb_enrich(&c_path, &thumb_path, &test_runtime()).unwrap();
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
            "// FUN_4000 @ 00004000\n\nvoid FUN_4000(\n    int a,\n    int b)\n\n{\n  return;\n}\n\n",
        )
        .unwrap();
        let thumb_path = root.join("thumb_functions.json");
        write_consumer_v3_fixture(&thumb_path);

        let n = thumb_enrich(&c_path, &thumb_path, &test_runtime()).unwrap();
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
            "// FUN_4000 @ 00004001\nvoid FUN_4000(void)\n{\n  return;\n}\n\n",
        )
        .unwrap();
        let thumb_path = root.join("thumb_functions.json");
        write_consumer_v3_fixture(&thumb_path);

        let n = thumb_enrich(&c_path, &thumb_path, &test_runtime()).unwrap();
        assert_eq!(
            n, 1,
            "T-bit normalization: 4001 (Ghidra) matches 4000 (analyzer)"
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
        let original = crate::thumb_analysis::ParsedThumbArtifact::consumer_v3_fixture();
        std::fs::write(&thumb_path, original).unwrap();

        let n = thumb_enrich(&c_path, &thumb_path, &test_runtime()).unwrap();
        assert_eq!(n, 0);
        assert_eq!(std::fs::read(&thumb_path).unwrap(), original);
    }

    #[test]
    fn thumb_enrich_is_idempotent() {
        let root = temp_dir("thumb_enrich_idem");
        let c_path = root.join("decompiled.c");
        std::fs::write(
            &c_path,
            "// FUN_4000 @ 00004000\nvoid FUN_4000(void)\n{\n  return;\n}\n\n",
        )
        .unwrap();
        let thumb_path = root.join("thumb_functions.json");
        write_consumer_v3_fixture(&thumb_path);

        let _ = thumb_enrich(&c_path, &thumb_path, &test_runtime()).unwrap();
        let after_first = std::fs::read_to_string(&thumb_path).unwrap();
        let _ = thumb_enrich(&c_path, &thumb_path, &test_runtime()).unwrap();
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
        let original = crate::thumb_analysis::ParsedThumbArtifact::consumer_v3_fixture();
        std::fs::write(&thumb_path, original).unwrap();

        let err = thumb_enrich(&c_path, &thumb_path, &test_runtime()).unwrap_err();
        // The on-disk JSON is unchanged.
        assert_eq!(std::fs::read(&thumb_path).unwrap(), original);
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
        let c = "// FUN_4000 @ 00004000\n\
                 void FUN_4000(void)\n\
                 {\n\
                 \x20 const char *s = \"expected } close\";\n\
                 \x20 /* block comment with } brace */\n\
                 \x20 // line comment with } brace\n\
                 \x20 helper_call();\n\
                 \x20 return;\n\
                 }\n\n";
        std::fs::write(&c_path, c).unwrap();
        let thumb_path = root.join("thumb_functions.json");
        write_consumer_v3_fixture(&thumb_path);

        let n = thumb_enrich(&c_path, &thumb_path, &test_runtime()).unwrap();
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

    #[test]
    fn streaming_decompiled_c_body_collection_matches_whole_oracle() {
        let fixtures = [
            "\n\n// FUN_100 @ 0x100\nvoid FUN_100(void)\n{\n  return;\n}\n\n",
            "\n\n// FUN_200 @ 0x200\nvoid FUN_200(\n    int a)\n{\n  a;\n}\n",
            "// f @ 40e1201\nvoid f(void)\n{\n  x;\n}\n",
            "// f @ 0x00040e1200\nint f(void)\n{\n  return \"}{\"[0];\n}\n",
            "// g @ 0x300\nvoid g(void);\n\n\n\n\n\n\n\n\n{\n}\n",
            "// a @ 0x10\nvoid a(void)\n{\n}\n// b @ 0x20\nvoid b(void)\n{\n}\n",
            "// h @ 0x40\nvoid h(\n   int a,\n   int b,\n   int c,\n   int d,\n   int e)\n{\n}\n",
            "",
        ];
        let dir = tempfile::tempdir().unwrap();
        for (index, text) in fixtures.iter().enumerate() {
            let path = dir.path().join(format!("fixture-{index}.c"));
            std::fs::write(&path, text).unwrap();
            assert_eq!(
                collect_decompiled_c_bodies(&path).unwrap(),
                parse_decompiled_c_function_bodies_by_addr(text),
                "fixture {index}"
            );
        }
    }

    #[test]
    fn streaming_thumb_enrich_matches_whole_oracle_for_v3() {
        let c = "// FUN_4000 @ 00004000\nvoid FUN_4000(void)\n{\n  return;\n}\n";
        let input = crate::thumb_analysis::ParsedThumbArtifact::consumer_v3_fixture();
        let dir = tempfile::tempdir().unwrap();
        let c_path = dir.path().join("decompiled.c");
        let streaming = dir.path().join("streaming.json");
        let oracle = dir.path().join("oracle.json");
        std::fs::write(&c_path, c).unwrap();
        std::fs::write(&streaming, input).unwrap();
        std::fs::write(&oracle, input).unwrap();

        let streaming_count = thumb_enrich(&c_path, &streaming, &test_runtime()).unwrap();
        let oracle_count = thumb_enrich_whole(&c_path, &oracle).unwrap();

        assert_eq!(streaming_count, oracle_count);
        assert_eq!(
            std::fs::read(&streaming).unwrap(),
            std::fs::read(&oracle).unwrap(),
        );
    }

    /// Production-scale differential replay. The retained tree is read-only;
    /// both enrichers operate on disposable copies outside the tree.
    #[test]
    fn streaming_enrich_ab_matches_oracle_on_production_inputs() {
        let Ok(root) = std::env::var("PME_GOLDEN_DIR") else {
            return;
        };
        let images = Path::new(&root).join("images");
        let Some(main_dir) = std::fs::read_dir(&images)
            .ok()
            .into_iter()
            .flatten()
            .flatten()
            .map(|entry| entry.path().join("decompiled"))
            .find(|dir| {
                dir.parent()
                    .and_then(Path::file_name)
                    .is_some_and(|name| name.to_string_lossy().ends_with("_MAIN"))
                    && dir.join("decompiled.c").is_file()
                    && dir.join("thumb_functions.json").is_file()
            })
        else {
            return;
        };
        let c_path = main_dir.join("decompiled.c");
        let source = main_dir.join("thumb_functions.json");
        let work = tempfile::tempdir().unwrap();
        let streaming = work.path().join("streaming.json");
        let oracle = work.path().join("oracle.json");
        std::fs::copy(&source, &streaming).unwrap();
        std::fs::copy(&source, &oracle).unwrap();

        let streaming_count = thumb_enrich(&c_path, &streaming, &test_runtime()).unwrap();
        let oracle_count = thumb_enrich_whole(&c_path, &oracle).unwrap();

        assert_eq!(streaming_count, oracle_count);
        assert!(streaming_count > 0, "production replay enriched no records");
        assert_eq!(
            std::fs::metadata(&streaming).unwrap().len(),
            std::fs::metadata(&oracle).unwrap().len()
        );
        assert_eq!(
            crate::manifest::blake3_file(&streaming).unwrap(),
            crate::manifest::blake3_file(&oracle).unwrap()
        );
    }
}
