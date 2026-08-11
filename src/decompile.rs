//! Decompile the modem TOC code images with Ghidra. Pure-Rust generation always
//! emits a self-contained Ghidra import kit (per-image slices, a machine-readable
//! `ghidra_load.json` load spec, a turnkey `run_ghidra.sh`, and an embedded Java
//! exporter); the opt-in `--run` drives `analyzeHeadless` headless to export
//! decompiled C, a disassembly listing, a function inventory, and a saved project,
//! with radare2 covering dense Thumb regions that Ghidra cannot converge on.

use crate::{
    error::{Error, Result},
    toc::Toc,
};
use serde::Serialize;
use std::{
    collections::HashMap,
    ffi::{OsStr, OsString},
    num::NonZeroUsize,
    path::{Path, PathBuf},
};

const EXPORT_DECOMP_JAVA: &str = include_str!("ghidra/ExportDecomp.java");
const TAME_ANALYSIS_JAVA: &str = include_str!("ghidra/TameAnalysis.java");
const APPLY_SYMBOLS_JAVA: &str = include_str!("ghidra/ApplySymbols.java");
const APPLY_GLOBALS_JAVA: &str = include_str!("ghidra/ApplyGlobals.java");
const GLOBALS_APPLY_ERROR_MAX_CHARS: usize = 2_048;

/// Ghidra project name passed to `analyzeHeadless` (the directory is
/// `<root>/ghidra_project`). Shared by pass 1 (`-import`) and pass 2
/// (`-process`) so the two argument vectors never drift on a rename.
const GHIDRA_PROJECT_NAME: &str = "pixel-modem";

#[derive(Debug, Clone)]
pub struct Opts {
    pub run: bool,
    pub image: Option<String>,
    pub ghidra_home: Option<PathBuf>,
    pub processor: String,
    /// Phase 2 escape hatch: when true, `TameAnalysis` runs in `datamark` mode
    /// (today's Phase-1 behavior — dense Thumb regions marked as data, radare2
    /// handles them, no `thumb_enrich` runs, `thumb_functions.json` stays at v2
    /// asm-only). Default false (tighten mode).
    pub no_thumb_decompile: bool,
    /// Phase 2 / Surface B: test-only override that bypasses
    /// `baseline * wall_clock_multiplier` and supplies an absolute wall-clock
    /// budget for the tighten-watch kill decision. Wired to the hidden
    /// `--tighten-wall-clock-budget-sec` flag (Section 7 verification).
    /// Production callers leave this `None`.
    pub tighten_wall_clock_budget_override: Option<std::time::Duration>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SourceRef {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct ImageSpec {
    pub name: String,
    pub file: String,
    pub size: u32,
    pub base_addr: String,
    pub entry_point: String,
    pub sha256: String,
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
                sha256: crate::manifest::sha256_bytes(&data[start..end]),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(LoadSpec {
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        source: SourceRef {
            path: source_name.to_string(),
            sha256: crate::manifest::sha256_bytes(data),
        },
        processor: processor.to_string(),
        images,
    })
}

/// The `analyzeHeadless` argument vector for one image — the single source of
/// truth used both to serialize `run_ghidra.sh` and to spawn under `--run`.
/// `root` is the path prefix (an absolute out dir for `--run`, or `$HERE` in the
/// shell script). NOTE: `-loader-baseAddr` is hex WITHOUT a `0x` prefix.
///
/// `mode` is "tighten" (Phase 2+ default — attempt Thumb) or "datamark" (Phase-1
/// fallback — mark regions as data). When "tighten", the `thumb_regions` arg is
/// ignored (no data-marks passed to the script).
fn headless_args(
    root: &str,
    label: &str,
    processor: &str,
    base_addr: u32,
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
        // Pre-script (runs before auto-analysis): TameAnalysis takes `mode` as
        // its arg[0]. In `datamark` mode it also disables the Aggressive
        // Instruction Finder and marks the dense high-entropy regions passed
        // below (each as "addrHex:lenHex") as data — Thumb-2 protocol-stack
        // code Ghidra can't converge on, so radare2 analyzes it separately. In
        // `tighten` mode no regions are passed (Phase 2+: let Ghidra try).
        "-preScript".to_string(),
        "TameAnalysis.java".to_string(),
        mode.to_string(),
    ];
    if mode == "datamark" {
        for (addr, len) in thumb_regions {
            args.push(format!("{addr:08x}:{len:x}"));
        }
    }
    args.extend([
        "-postScript".to_string(),
        "ExportDecomp.java".to_string(),
        format!("{root}/export/{label}"),
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

fn ghidra_config_home(root: &Path) -> PathBuf {
    root.join("ghidra_config")
}

fn ghidra_cache_home(root: &Path) -> PathBuf {
    root.join("ghidra_cache")
}

fn ghidra_temp_home(root: &Path) -> PathBuf {
    root.join("ghidra_tmp")
}

fn ghidra_java_options(root: &Path, existing: Option<&OsStr>) -> OsString {
    let local = format!(
        "-Dapplication.settingsdir={} -Dapplication.cachedir={} -Dapplication.tempdir={} -Djava.io.tmpdir={}",
        ghidra_config_home(root).display(),
        ghidra_cache_home(root).display(),
        ghidra_temp_home(root).display(),
        ghidra_temp_home(root).display()
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
    root: &Path,
    java_home: Option<&Path>,
) -> std::process::Command {
    let mut command = std::process::Command::new(headless);
    command.args(args);
    command.env("XDG_CONFIG_HOME", ghidra_config_home(root));
    command.env("XDG_CACHE_HOME", ghidra_cache_home(root));
    command.env(
        "GHIDRA_HEADLESS_JAVA_OPTIONS",
        ghidra_java_options(
            root,
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

/// True if this image should be analyzed under `--run`: no `--image` filter, or
/// the filter matches the canonical label (e.g. "02_MAIN") or the bare TOC name (e.g. "MAIN").
fn image_matches(want: Option<&str>, label: &str, name: &str) -> bool {
    want.is_none() || want == Some(label) || want == Some(name)
}

/// One image's `--run` result: either analyzed (with the function count ExportDecomp
/// recorded) or `analyzeHeadless` exited non-zero. Recorded per image so a full run
/// reports every partition instead of aborting on the first failure.
#[derive(Debug)]
pub enum ImageOutcome {
    Analyzed(usize),
    Failed(i32),
}

/// One image's structured `--run` outcome, surfaced for callers that orchestrate
/// (e.g. `decompose`) rather than just print.
#[derive(Debug)]
pub struct ImageResult {
    pub label: String,
    pub outcome: ImageOutcome,
    pub thumb_functions: Option<usize>,
    /// Reason-only Thumb/radare2 failure text; `label` already identifies the image.
    pub thumb_error: Option<String>,
    /// Pass-2 (symbolication) outcome: count of names `ApplySymbols.java`
    /// reported applying. `None` when pass 2 did not run for this image.
    pub pass2_applied: Option<usize>,
    /// Reason-only pass-2 failure text (e.g. analyzeHeadless exited non-zero).
    pub pass2_error: Option<String>,
    /// Phase 2: count of Thumb functions whose `body_c` was populated by
    /// `thumb_enrich` from the regenerated `decompiled.c`. `None` when Phase 2
    /// did not run for this image (no Thumb regions, or `--no-thumb-decompile`).
    pub thumb_decompiled: Option<usize>,
    /// Phase 2 / Surface B: reason-only text set when the runtime wall-clock
    /// or log-spam watch killed the tightened run and fell back to `datamark`.
    pub thumb_tighten_error: Option<String>,
    /// Phase 2 / Surface C: reason-only text set when `thumb_enrich` could not
    /// parse `decompiled.c` (malformed output). The v1 `thumb_functions.json`
    /// is left intact; downstream stages keep working against v1.
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
    /// Phase 3.0.1: total tier:"provisional" globals generated for this image
    /// (before any suppression). None when Phase 3.0.1 didn't run for this image.
    pub globals_provisional: Option<usize>,
    /// Phase 3.0.1: subset dropped because a Recovered (addr, name') exists at
    /// the same address (tier-conflict suppression — the gate-relevant metric).
    /// None when Phase 3.0.1 didn't run; Some(0) is a valid value.
    pub globals_provisional_suppressed: Option<usize>,
}

/// A decompile run's per-image outcomes plus the `ghidra_load.json` path.
#[derive(Debug)]
pub struct DecompileReport {
    pub images: Vec<ImageResult>,
    pub spec_path: PathBuf,
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

fn generation_only_hint(out: &Path) -> String {
    format!(
        "(generation only; pass --run to drive Ghidra plus radare2 for dense Thumb regions, or run {}/run_ghidra.sh for Ghidra-only import/export)",
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
/// entropy marks the Thumb regions. Ghidra cannot converge on them (it spins forever
/// in a `ClearFlowAndRepairCmd` overlapping-function loop — ~10M+ repair messages on
/// MAIN), so the pre-script marks them as data for Ghidra and the host analyzes them
/// with radare2 instead.
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
/// spaces, and any other shell metacharacter — used by the generated
/// `run_ghidra.sh` for every arg, since `--processor`, `--ghidra-home`, and the
/// project root flow in from user-controlled inputs. Empty string → `''`.
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

/// Write a turnkey `run_ghidra.sh` (one `analyzeHeadless` invocation per image),
/// built from `headless_args` against a relocatable `$HERE` root.
fn write_run_script(out: &Path, toc: &Toc, processor: &str) -> Result<()> {
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
    s.push_str("HERE=\"$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)\"\n");
    s.push_str("export XDG_CONFIG_HOME=\"$HERE/ghidra_config\"\n");
    s.push_str("export XDG_CACHE_HOME=\"$HERE/ghidra_cache\"\n");
    // NOTE: `$HERE` is interpolated into these `-D…` tokens and the resulting
    // env var is later word-split unquoted by `analyzeHeadless` itself, so a
    // `$HERE` containing spaces breaks the launch. We don't escape here because
    // no shell-quoting survives the unquoted re-split downstream; if you need a
    // `$HERE` with spaces, invoke the binary directly (the in-process `Command`
    // path is unaffected).
    s.push_str("GHIDRA_LOCAL_JAVA_OPTIONS=\"-Dapplication.settingsdir=$HERE/ghidra_config -Dapplication.cachedir=$HERE/ghidra_cache -Dapplication.tempdir=$HERE/ghidra_tmp -Djava.io.tmpdir=$HERE/ghidra_tmp\"\n");
    s.push_str("if [ \"${GHIDRA_HEADLESS_JAVA_OPTIONS+x}\" ]; then\n");
    s.push_str("  export GHIDRA_HEADLESS_JAVA_OPTIONS=\"$GHIDRA_HEADLESS_JAVA_OPTIONS $GHIDRA_LOCAL_JAVA_OPTIONS\"\n");
    s.push_str("else\n");
    s.push_str("  export GHIDRA_HEADLESS_JAVA_OPTIONS=\"$GHIDRA_LOCAL_JAVA_OPTIONS\"\n");
    s.push_str("fi\n");
    s.push_str("mkdir -p \"$HERE/ghidra_project\" \"$HERE/export\" \"$XDG_CONFIG_HOME\" \"$XDG_CACHE_HOME\" \"$HERE/ghidra_tmp\"\n");
    for e in toc.embedded() {
        // `run_ghidra.sh` runs in tighten mode (production default), which does
        // not data-mark regions — `headless_args` ignores the slice. Pass an
        // empty slice and skip the entropy scan; the regions are computed in
        // `run_report` under `--run` only when `mode=datamark` actually needs them.
        let mode = "tighten";
        let args = headless_args("$HERE", &e.label(), processor, e.load_addr, &[], mode);
        s.push_str("\"$HEADLESS\"");
        for a in &args {
            // Shell-quote every arg: `--processor` and `--ghidra-home` flow in from
            // the user and could otherwise inject into the generated script. Labels
            // are already whitelisted by `toc::TocEntry::label` but quoting is the
            // robust boundary. POSIX single-quote form: closes the quote on an
            // embedded `'`, emits `'\''`, reopens.
            s.push(' ');
            s.push_str(&shell_quote(a));
        }
        s.push('\n');
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

/// Build the Ghidra import kit (always) and, with `--run`, drive `analyzeHeadless` per
/// image — returning the structured per-image outcomes plus the `ghidra_load.json` path.
/// Unlike [`run`], this never errors on a per-image analysis failure: every partition is
/// attempted and recorded, so an orchestrator (e.g. `decompose`) decides what a failure means.
pub fn run_report(modem_bin: &Path, opts: &Opts, out: &Path) -> Result<DecompileReport> {
    let data = std::fs::read(modem_bin)?;
    let toc = Toc::parse(&data)?;
    std::fs::create_dir_all(out)?;

    // 1. per-image slices -> out/images/NN_NAME (validates ranges; CRC advisory only)
    toc.split_to_dir(&data, &out.join("images"), false)?;

    // 2. embedded Java scripts -> out/scripts/{TameAnalysis,ExportDecomp,ApplySymbols,ApplyGlobals}.java
    //    (TameAnalysis pre-script tames Ghidra's auto-analysis; ExportDecomp post-script
    //    writes the decompiled C / disasm listing / function inventory; ApplySymbols
    //    and ApplyGlobals are staged for pass-2 application.)
    let scripts = out.join("scripts");
    std::fs::create_dir_all(&scripts)?;
    std::fs::write(scripts.join("TameAnalysis.java"), TAME_ANALYSIS_JAVA)?;
    std::fs::write(scripts.join("ExportDecomp.java"), EXPORT_DECOMP_JAVA)?;
    std::fs::write(scripts.join("ApplySymbols.java"), APPLY_SYMBOLS_JAVA)?;
    std::fs::write(scripts.join("ApplyGlobals.java"), APPLY_GLOBALS_JAVA)?;

    // 3. machine-readable load spec -> out/ghidra_load.json
    let source_name = modem_bin
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("modem.bin");
    let spec = build_load_spec(&toc, &data, source_name, &opts.processor)?;
    let spec_path = out.join("ghidra_load.json");
    std::fs::write(
        &spec_path,
        serde_json::to_string_pretty(&spec).map_err(|e| Error::Serialize(e.to_string()))?,
    )?;

    // 4. turnkey shell script -> out/run_ghidra.sh
    write_run_script(out, &toc, &opts.processor)?;

    // 5. optional: drive Ghidra headless per selected image, plus radare2 for dense Thumb regions
    let mut image_results: Vec<ImageResult> = Vec::new();
    if opts.run {
        let install = find_ghidra(opts)?;
        let java_home =
            resolve_java_home(std::env::var_os("JAVA_HOME"), install.ghidra_run.as_deref());
        // analyzeHeadless needs the project dir to exist; use an absolute (canonical) root so
        // the spawned invocation is cwd-independent (the generated run_ghidra.sh uses $HERE).
        let root = std::fs::canonicalize(out)?;
        std::fs::create_dir_all(root.join("ghidra_project"))?;
        std::fs::create_dir_all(ghidra_config_home(&root))?;
        std::fs::create_dir_all(ghidra_cache_home(&root))?;
        std::fs::create_dir_all(ghidra_temp_home(&root))?;
        let root_str = root.to_string_lossy().into_owned();
        let want = opts.image.as_deref();
        let r2_bin = find_radare2();
        // Analyze every selected image, recording each outcome rather than aborting on the
        // first failure — so a heavy or unanalyzable partition (the ~87 MB MAIN, or an
        // encrypted one) can't sink the rest of a full run.
        struct RunResult {
            label: String,
            outcome: ImageOutcome,
            thumb_functions: Option<usize>,
            thumb_error: Option<String>,
            tighten_error: Option<String>,
            // When the tighten-watch kills the run, we re-spawn as datamark
            // and there is no `thumb_enrich` to run later; mark the count
            // definitively zero so downstream stages don't enqueue
            // work against an empty decompiled.c.
            thumb_decompiled: Option<usize>,
        }
        let mut results: Vec<RunResult> = Vec::new();
        for e in toc.embedded() {
            let label = e.label();
            if !image_matches(want, &label, &e.name) {
                continue;
            }
            let start = (e.offset as usize).min(data.len());
            let end = (e.offset as usize + e.size as usize).min(data.len());
            let img = &data[start..end];
            let regions = thumb_regions(img, e.load_addr);
            let mode = mode_from_opts(opts);
            tracing::info!(
                "ghidra: analyzing {label} (base 0x{:08x}, mode={mode})",
                e.load_addr
            );
            // Phase-1 datamark framing only — in tighten mode the regions are NOT
            // data-marked (Ghidra is allowed to try), so the "marked as data"
            // message would be misleading.
            if mode == "datamark" && !regions.is_empty() {
                tracing::info!(
                    "ghidra: {label} has {} dense Thumb-2 region(s) — marked as data (radare2 handles them)",
                    regions.len()
                );
            }
            let args = headless_args(
                &root_str,
                &label,
                &opts.processor,
                e.load_addr,
                &regions,
                mode,
            );
            // Surface B: in tighten mode, spawn with piped stdout so we can
            // count `ClearFlowAndRepairCmd` log lines and kill the runaway
            // overlap-repair loop before it sinks the whole run. On kill we
            // fall back to `datamark` (Phase-1 behavior). In datamark mode
            // there is no watch — the spawn blocks until completion as before.
            let mut tighten_error: Option<String> = None;
            // When the tighten-watch kills the run, we re-spawn as datamark
            // and there is no `thumb_enrich` to run later; mark the count
            // definitively zero so downstream stages don't enqueue
            // work against an empty decompiled.c.
            let mut thumb_decompiled_override: Option<usize> = None;
            let status = if mode == "tighten" {
                let mut cmd =
                    headless_command(&install.headless, &args, &root, java_home.as_deref());
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
                            &regions,
                            "datamark",
                        );
                        let retry_status = headless_command(
                            &install.headless,
                            &datamark_args,
                            &root,
                            java_home.as_deref(),
                        )
                        .status()?;
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
                        retry_status
                    }
                    None => child.wait()?,
                }
            } else {
                headless_command(&install.headless, &args, &root, java_home.as_deref()).status()?
            };
            let outcome = if status.success() {
                let n = count_functions(&root.join("export").join(&label));
                if n == 0 {
                    tracing::warn!(
                        "ghidra: {label} yielded 0 functions — no decompilable code (e.g. a compressed/encrypted partition)"
                    );
                }
                ImageOutcome::Analyzed(n)
            } else {
                let code = status.code().unwrap_or(-1);
                tracing::warn!("ghidra: {label} failed (analyzeHeadless exit {code})");
                ImageOutcome::Failed(code)
            };
            // Ghidra can't converge on the dense Thumb-2 regions (overlap-repair loop) and
            // marked them as data — hand them to radare2 for the protocol stack.
            let (thumb_functions, thumb_error) = if regions.is_empty() {
                (None, None)
            } else if let Some(r2) = &r2_bin {
                match run_radare2_thumb(
                    r2,
                    img,
                    e.load_addr,
                    &regions,
                    &root.join("export").join(&label),
                ) {
                    Ok(n) => {
                        tracing::info!("radare2: {label} Thumb stack -> {n} function(s)");
                        (Some(n), None)
                    }
                    Err(err) => {
                        tracing::warn!("radare2: {label} failed: {err}");
                        (None, Some(err.to_string()))
                    }
                }
            } else {
                let err = format!(
                    "{} Thumb region(s) left unanalyzed — radare2 (r2) not on PATH; Ghidra can't analyze them",
                    regions.len()
                );
                tracing::warn!("{label}: {err}");
                (None, Some(err))
            };
            results.push(RunResult {
                label,
                outcome,
                thumb_functions,
                thumb_error,
                tighten_error,
                thumb_decompiled: thumb_decompiled_override,
            });
        }
        if results.is_empty() {
            return Err(Error::NotFound(match &opts.image {
                Some(img) => format!("no image matched --image {img}"),
                None => "no embedded images found in TOC".to_string(),
            }));
        }
        println!(
            "ghidra: analyzed {} image(s) -> {}",
            results.len(),
            out.join("export").display()
        );
        for r in &results {
            let t = if let Some(n) = r.thumb_functions {
                format!("  + {n} Thumb fn(s) [radare2]")
            } else if let Some(err) = &r.thumb_error {
                format!("  + Thumb FAILED [radare2: {err}]")
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
            }
        }
        image_results = results
            .into_iter()
            .map(|r| ImageResult {
                label: r.label,
                outcome: r.outcome,
                thumb_functions: r.thumb_functions,
                thumb_error: r.thumb_error,
                pass2_applied: None,
                pass2_error: None,
                thumb_decompiled: r.thumb_decompiled,
                thumb_tighten_error: r.tighten_error,
                thumb_enrich_error: None,
                globals_error: None,
                globals_recovered: None,
                globals_applied: None,
                globals_apply_skipped: None,
                globals_apply_error: None,
                globals_provisional: None,
                globals_provisional_suppressed: None,
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
    })
}

/// Convert structured per-image outcomes into the standalone `decompile` failure,
/// after every selected image has had a chance to run.
fn report_failure(report: &DecompileReport) -> Option<Error> {
    if let Some(code) = report.images.iter().find_map(|r| match r.outcome {
        ImageOutcome::Failed(c) => Some(c),
        ImageOutcome::Analyzed(_) => None,
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
    let thumb_failed: Vec<String> = report
        .images
        .iter()
        .filter_map(|r| {
            r.thumb_error
                .as_ref()
                .map(|err| format!("{}: {err}", r.label))
        })
        .collect();
    if !thumb_failed.is_empty() {
        return Some(Error::DecomposeIncomplete(format!(
            "radare2 failed on {}",
            thumb_failed.join(", ")
        )));
    }
    None
}

/// The `analyzeHeadless` argument vector for pass 2 of `run_two_pass`. Runs in
/// `-process` mode on the existing project so there is no re-import and no
/// re-analysis: the requested `ApplySymbols.java` and `ApplyGlobals.java`
/// scripts run in that order, then `ExportDecomp.java` regenerates the export
/// with applied function and global names baked in.
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
    pub function_map: Option<PreparedPass2Map>,
    pub global_map: Option<PreparedPass2Map>,
}

fn headless_process_args(
    root: &str,
    label: &str,
    input: &Pass2Input,
) -> Result<Option<Vec<String>>> {
    let function_map = input.function_map.as_ref();
    let global_map = input.global_map.as_ref();
    if function_map.is_none() && global_map.is_none() {
        return Ok(None);
    }

    if let Some(map) = function_map {
        map.validate_for_spawn()?;
    }
    if let Some(map) = global_map {
        map.validate_for_spawn()?;
    }

    let mut args = vec![
        format!("{root}/ghidra_project"),
        GHIDRA_PROJECT_NAME.to_string(),
        "-process".to_string(),
        label.to_string(),
        "-noanalysis".to_string(),
        "-scriptPath".to_string(),
        format!("{root}/scripts"),
    ];
    if let Some(map) = function_map {
        args.extend([
            "-postScript".to_string(),
            "ApplySymbols.java".to_string(),
            map.path().to_string_lossy().into_owned(),
        ]);
    }
    if let Some(map) = global_map {
        args.extend([
            "-postScript".to_string(),
            "ApplyGlobals.java".to_string(),
            map.path().to_string_lossy().into_owned(),
        ]);
    }
    args.extend([
        "-postScript".to_string(),
        "ExportDecomp.java".to_string(),
        format!("{root}/export/{label}"),
    ]);
    Ok(Some(args))
}

/// Extract the `N` from the summary line
/// `ApplySymbols: image=<image> applied N names, M plate comments, skipped K`.
/// `None` when the line is missing or the count is not an integer — the caller
/// treats `None` as "no information from pass 2".
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

/// Pass 2 of two-pass decompile. Accepts the pass-1 `report` (callers run pass 1
/// via `run_report` separately and pass its result here — running pass 1 again
/// would triple Ghidra time on `02_MAIN`). Pass 2 runs only for images whose
/// `inputs.get(&label)` contains a prepared non-zero function or global count
/// with its corresponding map path. Per-image pass-2 failures (non-zero exit,
/// spawn failure) are recorded into `ImageResult.pass2_error`, not propagated —
/// pass 1 already produced a valid `decompiled.c`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pass2ProcessOutcome {
    ProcessSucceeded,
    Failed(String),
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

    for (label, input) in inputs {
        if (input.function_map.is_some() || input.global_map.is_some())
            && !report.images.iter().any(|image| image.label == *label)
        {
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
        ir.pass2_error = None;
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
        if applies_functions {
            ir.pass2_applied = None;
        }
        if applies_globals {
            ir.globals_applied = None;
            ir.globals_apply_skipped = None;
            ir.globals_apply_error = None;
        }

        tracing::info!("ghidra: pass 2 application for {}", ir.label);
        // Spawn failure (e.g. executable bit lost, Ghidra uninstalled mid-run)
        // lands in `pass2_error` per image instead of propagating — pass 1
        // already produced a valid `decompiled.c` for every image.
        let output = match headless_command(&install.headless, &args, &root, java_home.as_deref())
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
            let stdout = String::from_utf8_lossy(&output.stdout);
            if applies_functions {
                ir.pass2_applied = parse_pass2_summary(&stdout);
            }
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

/// Generate the kit and (with `--run`) drive Ghidra plus radare2 for dense Thumb
/// regions; non-zero if any selected image failed either analysis path.
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
    None
}

/// Locate the Ghidra headless launcher: `--ghidra-home` → `$GHIDRA_INSTALL_DIR` → `PATH`
/// (a bare `analyzeHeadless`, or resolved from a `ghidraRun` wrapper). Each root is probed
/// for both the upstream (`support/`) and Homebrew (`libexec/support/`) layouts.
pub fn find_headless(ghidra_home: Option<&Path>) -> Result<GhidraInstall> {
    let env_dir = std::env::var_os("GHIDRA_INSTALL_DIR").map(PathBuf::from);
    let path_dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    locate_tools(ghidra_home, env_dir.as_deref(), &path_dirs).ok_or_else(|| {
        Error::GhidraNotFound(
            "tried --ghidra-home, $GHIDRA_INSTALL_DIR, and PATH; if Ghidra was installed via \
             Homebrew, pass --ghidra-home \"$(brew --prefix ghidra)\" or add its bin to PATH"
                .into(),
        )
    })
}

fn find_ghidra(opts: &Opts) -> Result<GhidraInstall> {
    find_headless(opts.ghidra_home.as_deref())
}

/// Locate the `radare2` binary (`r2`) on `PATH` — used to analyze the Thumb-2 regions
/// Ghidra cannot. `None` if not installed (those regions are then left unanalyzed).
pub fn find_radare2() -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|d| d.join("r2"))
        .find(|p| p.exists())
}

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
    function_count: usize,
    pdfj_count: usize,
    missing_pdfj_count: usize,
    pairs: Vec<(serde_json::Value, serde_json::Value)>,
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
            function_count: 0,
            pdfj_count: 0,
            missing_pdfj_count: 0,
            pairs: Vec::new(),
        };
    };
    let pdfjs = pdfj_values_from_radare2_output(&values);
    let mut used_pdfjs = vec![false; pdfjs.len()];
    let mut paired_pdfjs: Vec<Option<serde_json::Value>> = vec![None; fns.len()];

    for (idx, f) in fns.iter().enumerate() {
        let Some(entry) = radare2_function_entry(f) else {
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

    let pairs: Vec<_> = fns
        .iter()
        .cloned()
        .zip(paired_pdfjs)
        .filter_map(|(f, pdfj)| pdfj.map(|pdfj| (f, pdfj)))
        .collect();
    let missing_pdfj_count = fns.len().saturating_sub(pairs.len());

    Radare2ThumbOutput {
        json_value_count: values.len(),
        has_function_inventory: true,
        function_count: fns.len(),
        pdfj_count: pdfjs.len(),
        missing_pdfj_count,
        pairs,
    }
}

#[cfg(test)]
fn radare2_thumb_function_pdfjs(stdout: &[u8]) -> Vec<(serde_json::Value, serde_json::Value)> {
    parse_radare2_thumb_output(stdout).pairs
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
    if parsed.missing_pdfj_count > 0 {
        let pdfj_detail = if parsed.pdfj_count == 0 {
            "no parseable pdfj bodies".to_string()
        } else {
            format!(
                "missing {} pdfj {}",
                parsed.missing_pdfj_count,
                if parsed.missing_pdfj_count == 1 {
                    "body"
                } else {
                    "bodies"
                }
            )
        };
        return Err(Error::Serialize(format!(
            "radare2 reported {} functions but {pdfj_detail} for Thumb region 0x{addr:x}",
            parsed.function_count,
        )));
    }
    let empty_body_count = parsed
        .pairs
        .iter()
        .filter(|(_, pdfj)| pdfj_body(pdfj).is_empty())
        .count();
    if empty_body_count > 0 {
        return Err(Error::Serialize(format!(
            "radare2 reported {} functions but {} paired pdfj {} had an empty pdfj body for Thumb region 0x{addr:x}",
            parsed.function_count,
            empty_body_count,
            if empty_body_count == 1 {
                "body"
            } else {
                "bodies"
            }
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
    normalize_radare2_function_checked(raw, pdfj, 0)
}

fn normalize_radare2_function_checked(
    raw: &serde_json::Value,
    pdfj: &serde_json::Value,
    region_addr: u32,
) -> Result<serde_json::Value> {
    let entry = radare2_function_entry(raw).ok_or_else(|| {
        Error::Serialize(format!(
            "radare2 function lacks entry/addr for Thumb region 0x{region_addr:x}"
        ))
    })?;
    let size = raw.get("size").and_then(json_u64).unwrap_or(0);
    let name = raw
        .get("name")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| format!("thumb_{entry:x}"));
    let body = pdfj_body(pdfj);
    if body.is_empty() {
        return Err(Error::Serialize(format!(
            "radare2 function 0x{entry:x} has empty pdfj body for Thumb region 0x{region_addr:x}"
        )));
    }
    Ok(serde_json::json!({
        "name": name,
        "entry": json_hex(entry),
        "end": json_hex(entry.saturating_add(size)),
        "size": size,
        "body_kind": "thumb_disassembly",
        "body": body,
        "data_refs": data_refs_from_pdfj(pdfj),
    }))
}

/// Defensive upper bound on a single Thumb region's r2 stdout. Grounded in
/// production: 02_MAIN's largest dense-Thumb region (`410b0000`, ~20 MiB
/// carved .bin, ~71 k functions) emits ~1.82 GiB of `aflj;pdfj @@f` JSON
/// (~25 KiB/function). 4 GiB is ~2× that peak, with headroom for r2 version
/// differences and slightly larger images. Exceeding it indicates genuine
/// r2 pathology (infinite loop, corrupt input triggering verbose output) —
/// fail-closed rather than OOM the host.
pub(super) const R2_STDOUT_CAP_BYTES: usize = 4 * 1024 * 1024 * 1024;

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

/// Analyze an image's dense Thumb-2 regions with radare2. Each region is carved out,
/// analyzed as ARM/Thumb (`-a arm -b 16`) based at its load address, and its
/// `aflj`/`pdfj` function output merged into `out_dir/thumb_functions.json` (the carved
/// blobs are kept under `out_dir/thumb/` for follow-up). Returns the count of substantial
/// (>= 32-byte) functions recovered.
fn run_radare2_thumb(
    r2: &Path,
    image: &[u8],
    load_addr: u32,
    regions: &[(u32, u32)],
    out_dir: &Path,
) -> Result<usize> {
    let thumb_dir = out_dir.join("thumb");
    std::fs::create_dir_all(&thumb_dir)?;
    let mut all: Vec<serde_json::Value> = Vec::new();
    for &(addr, len) in regions {
        let off = addr.wrapping_sub(load_addr) as usize;
        if off >= image.len() {
            continue;
        }
        let end = off.saturating_add(len as usize).min(image.len());
        let bin = thumb_dir.join(format!("{addr:08x}.bin"));
        std::fs::write(&bin, &image[off..end])?;
        // Stream r2 stdout to a per-region temp file. The file is kept after
        // parse for debugging (disk is cheap; --prune drops it with the rest
        // of `thumb/`). Cap is `R2_STDOUT_CAP_BYTES` (4 GiB) — see the const's
        // doc comment for the production grounding.
        let mut child = std::process::Command::new(r2)
            .args(["-a", "arm", "-b", "16", "-m"])
            .arg(format!("0x{addr:x}"))
            .args(["-q", "-c", "aaa;aflj;pdfj @@f"])
            .arg(&bin)
            .stderr(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .spawn()?;
        let mut stdout = child.stdout.take().expect("piped stdout");
        let stdout_path = thumb_dir.join(format!("{addr:08x}.stdout"));
        let mut file = std::fs::File::create(&stdout_path)?;

        let cap_err = stream_to_cap(&mut stdout, &mut file, R2_STDOUT_CAP_BYTES);
        drop(file); // close + flush before any read-back or removal
        drop(stdout); // drop the pipe handle explicitly

        if let Err(e) = cap_err {
            // Cap exceeded OR genuine I/O error. Either way: kill, reap,
            // remove the partial file (no value in keeping truncated output),
            // return Err. The `ErrorKind::Other` discrimination is the
            // cap-exceed signal from `stream_to_cap`; a genuine I/O error
            // could in rare cases also surface as `Other`, but the cleanup
            // path is identical, so a misclassification only changes the
            // error message — acceptable per the task brief.
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

        // Read the streamed file back for parsing. Memory peak here is ~file
        // size (the parse path holds the bytes + builds JSON Value trees).
        // Acceptable on research machines; a future streaming-JSON-parser
        // follow-up would reduce this — see CONTRIBUTING's radare2 invariant.
        let stdout_bytes = std::fs::read(&stdout_path)?;
        let parsed = parse_checked_radare2_thumb_output(&stdout_bytes, addr)?;
        for (f, pdfj) in parsed.pairs {
            all.push(normalize_radare2_function_checked(&f, &pdfj, addr)?);
        }
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

/// Phase 2: enrich a v1 (or v2 asm-only) `thumb_functions.json` with per-function
/// `body_c` sourced from a `decompiled.c`. Bumps `format` to v2 iff at least one
/// `body_c` is populated; otherwise leaves the file byte-identical. Idempotent.
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
/// `FUN_<addr>`/recovered names. Returns the count of functions whose `body_c`
/// was populated.
///
/// Fail-closed: a malformed `decompiled.c` (read or parse failure) returns `Err`;
/// the on-disk `thumb_functions.json` is unchanged.
pub fn thumb_enrich(decompiled_c_path: &Path, thumb_functions_json_path: &Path) -> Result<usize> {
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
/// prior name-based parser.
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
        // State machine tracks string literals + line/block comments so a `}` inside
        // `"expected }"` or `// close }` doesn't truncate the body. Char literals
        // (`'}'`) are not tracked — rare in Ghidra decompiled C, and bounded impact
        // (only affected body_c, matching is by entry address). Mirrors the
        // string-aware pattern already used by `balanced_json_end`.
        let mut depth = 0i32;
        let mut saw_brace = false;
        let mut body = String::new();
        let mut in_string = false;
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
                match ch {
                    '"' => in_string = true,
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

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn headless_args_base_addr_is_hex_without_0x() {
        let args = headless_args(
            "/out",
            "02_MAIN",
            "ARM:LE:32:v7",
            0x4001_0000,
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
        // pre-script wires TameAnalysis.java, then mode, then the data-region args
        // (only in datamark mode), before the post-script
        let pre = args.iter().position(|a| a == "-preScript").unwrap();
        assert_eq!(args[pre + 1], "TameAnalysis.java");
        assert_eq!(args[pre + 2], "datamark");
        assert_eq!(args[pre + 3], "41090000:2880000"); // addrHex:lenHex
        assert!(pre < ps, "pre-script must precede post-script");
        assert!(args.iter().any(|a| a == "-overwrite"));
        // base 0 -> zero-padded "00000000"; no data regions -> -postScript directly
        // follows the mode arg
        let z = headless_args("/o", "00_BOOT", "ARM:LE:32:v7", 0, &[], "datamark");
        let zpre = z.iter().position(|a| a == "-preScript").unwrap();
        assert_eq!(z[zpre + 1], "TameAnalysis.java");
        assert_eq!(z[zpre + 2], "datamark");
        assert_eq!(z[zpre + 3], "-postScript");
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
            &[(0x40e12000, 0x100000)],
            "tighten",
        );
        let pre_idx = args.iter().position(|a| a == "TameAnalysis.java").unwrap();
        // The next arg after the script name is the mode.
        assert_eq!(args[pre_idx + 1], "tighten");
        // No addrHex:lenHex follows (tighten mode does not data-mark).
        assert!(
            !args[pre_idx + 2..].iter().any(|a| a.contains(':')),
            "tighten mode must not pass region args: {:?}",
            &args[pre_idx + 2..]
        );
    }

    #[test]
    fn headless_args_passes_datamark_mode_and_regions() {
        let args = headless_args(
            "$HERE",
            "02_MAIN",
            "ARM:LE:32:v7",
            0x40e00000,
            &[(0x40e12000, 0x100000)],
            "datamark",
        );
        let pre_idx = args.iter().position(|a| a == "TameAnalysis.java").unwrap();
        assert_eq!(args[pre_idx + 1], "datamark");
        assert!(args[pre_idx + 2..].iter().any(|a| a == "40e12000:100000"));
    }

    #[test]
    fn prepared_pass2_map_canonicalizes_relative_regular_file() {
        let relative_dir = PathBuf::from("target")
            .join(format!("pme_task8r_relative_maps_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&relative_dir);
        std::fs::create_dir_all(&relative_dir).unwrap();
        let function_path = relative_dir.join("functions.json");
        let global_path = relative_dir.join("globals.json");
        std::fs::write(&function_path, b"functions").unwrap();
        std::fs::write(&global_path, b"globals").unwrap();

        let input = Pass2Input {
            function_map: Some(
                PreparedPass2Map::new(&function_path, std::num::NonZeroUsize::new(1).unwrap())
                    .unwrap(),
            ),
            global_map: Some(
                PreparedPass2Map::new(&global_path, std::num::NonZeroUsize::new(2).unwrap())
                    .unwrap(),
            ),
        };
        let args = headless_process_args("/out", "02_MAIN", &input)
            .unwrap()
            .expect("typed maps schedule pass two");
        let function_argument = &args[args
            .iter()
            .position(|arg| arg == "ApplySymbols.java")
            .unwrap()
            + 1];
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
            Path::new(global_argument),
            std::fs::canonicalize(&global_path).unwrap()
        );
        assert!(Path::new(function_argument).is_absolute());
        assert!(Path::new(global_argument).is_absolute());
        assert!(Path::new(function_argument).is_file());
        assert!(Path::new(global_argument).is_file());

        let _ = std::fs::remove_dir_all(&relative_dir);
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
    fn validated_headless_process_args_rejects_late_disappearance() {
        let root =
            PathBuf::from("target").join(format!("pme_task8r_late_map_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("functions.json");
        std::fs::write(&path, b"functions").unwrap();
        let input = Pass2Input {
            function_map: Some(
                PreparedPass2Map::new(&path, NonZeroUsize::new(1).unwrap()).unwrap(),
            ),
            global_map: None,
        };
        std::fs::remove_file(&path).unwrap();

        let error = headless_process_args("/out", "02_MAIN", &input).unwrap_err();

        assert!(error.to_string().contains("no longer"));
        let _ = std::fs::remove_dir_all(&root);
    }

    fn pass2_test_map(name: &str, count: usize) -> Option<PreparedPass2Map> {
        let count = NonZeroUsize::new(count)?;
        let dir = PathBuf::from("target").join("pme_task8r_pass2_args");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, name).unwrap();
        Some(PreparedPass2Map::new(&path, count).unwrap())
    }

    fn pass2_input(function_count: usize, global_count: usize) -> Pass2Input {
        Pass2Input {
            function_map: pass2_test_map("functions.json", function_count),
            global_map: pass2_test_map("globals.json", global_count),
        }
    }

    #[test]
    fn headless_process_args_wires_functions_then_globals_then_export() {
        let input = pass2_input(1, 1);
        let args = headless_process_args("/out", "02_MAIN", &input)
            .unwrap()
            .expect("non-empty prepared input must invoke pass two");
        let function_path = input
            .function_map
            .as_ref()
            .unwrap()
            .path()
            .to_string_lossy();
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
                "ApplySymbols.java",
                function_path.as_ref(),
                "-postScript",
                "ApplyGlobals.java",
                global_path.as_ref(),
                "-postScript",
                "ExportDecomp.java",
                "/out/export/02_MAIN",
            ]
        );
    }

    #[test]
    fn headless_process_args_wires_functions_only_then_export() {
        let input = pass2_input(1, 0);
        let args = headless_process_args("/out", "02_MAIN", &input)
            .unwrap()
            .expect("prepared function input must invoke pass two");
        let function_path = input
            .function_map
            .as_ref()
            .unwrap()
            .path()
            .to_string_lossy();

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
                "ApplySymbols.java",
                function_path.as_ref(),
                "-postScript",
                "ExportDecomp.java",
                "/out/export/02_MAIN",
            ]
        );
        assert!(!args.iter().any(|argument| argument == "ApplyGlobals.java"));
    }

    #[test]
    fn headless_process_args_wires_globals_only_then_export() {
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
    fn parse_pass2_summary_reads_applied_count() {
        let stdout =
            "...\nApplySymbols: image=02_MAIN applied 42 names, 7 plate comments, skipped 3\n";
        assert_eq!(parse_pass2_summary(stdout), Some(42));
        // Missing / malformed summary -> None (caller treats as "no info").
        assert_eq!(parse_pass2_summary("nothing useful\n"), None);
        assert_eq!(parse_pass2_summary(""), None);
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
    fn headless_command_uses_output_local_ghidra_config() {
        let root = PathBuf::from("/tmp/pme-out");
        let args = vec!["/tmp/pme-out/ghidra_project".to_string()];
        let cmd = headless_command(
            Path::new("/opt/ghidra/support/analyzeHeadless"),
            &args,
            &root,
            None,
        );

        assert_eq!(
            cmd.get_envs()
                .find(|(key, _)| *key == std::ffi::OsStr::new("XDG_CONFIG_HOME")),
            Some((
                std::ffi::OsStr::new("XDG_CONFIG_HOME"),
                Some(ghidra_config_home(&root).as_os_str())
            ))
        );
        assert_eq!(
            cmd.get_envs()
                .find(|(key, _)| *key == std::ffi::OsStr::new("XDG_CACHE_HOME")),
            Some((
                std::ffi::OsStr::new("XDG_CACHE_HOME"),
                Some(ghidra_cache_home(&root).as_os_str())
            ))
        );
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
        let root = PathBuf::from("/tmp/pme-out");
        let args = vec!["/tmp/pme-out/ghidra_project".to_string()];
        let jh = PathBuf::from("/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home");
        let cmd = headless_command(
            Path::new("/opt/ghidra/support/analyzeHeadless"),
            &args,
            &root,
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
            &root,
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
    fn ghidra_java_options_preserve_existing_and_add_output_local_dirs() {
        let root = PathBuf::from("/tmp/pme-out");
        let options = ghidra_java_options(&root, Some(std::ffi::OsStr::new("-Dexisting.option=1")));
        let options = options.to_string_lossy();

        assert!(
            options.contains("-Dexisting.option=1"),
            "options: {options}"
        );
        assert!(
            options.contains("-Dapplication.settingsdir=/tmp/pme-out/ghidra_config"),
            "options: {options}"
        );
        assert!(
            options.contains("-Dapplication.cachedir=/tmp/pme-out/ghidra_cache"),
            "options: {options}"
        );
        assert!(
            options.contains("-Dapplication.tempdir=/tmp/pme-out/ghidra_tmp"),
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
    fn radare2_thumb_rejects_functions_without_parseable_pdfj_bodies() {
        let stdout = b"Warning: noisy prelude
[{\"name\":\"sym.thumb_func\",\"offset\":16384,\"size\":64}]
INFO: no pdfj body followed
";

        let err = parse_checked_radare2_thumb_output(stdout, 0x4000).unwrap_err();

        assert!(matches!(err, Error::Serialize(message) if message.contains("no parseable pdfj")));
    }

    #[test]
    fn radare2_thumb_rejects_paired_pdfj_with_empty_rendered_body() {
        let stdout = br#"Warning: noisy prelude
[{"name":"sym.thumb_func","offset":16384,"size":64}]
{"addr":16384,"ops":[]}
"#;

        let err = parse_checked_radare2_thumb_output(stdout, 0x4000).unwrap_err();

        assert!(matches!(err, Error::Serialize(message) if message.contains("empty pdfj body")));
    }

    #[test]
    fn radare2_thumb_rejects_partial_pdfj_recovery() {
        let stdout = br#"Warning: noisy prelude
[{"name":"sym.first","offset":16384,"size":64},{"name":"sym.second","offset":16448,"size":64}]
{"addr":16384,"ops":[{"offset":16384,"bytes":"b5f0","disasm":"push {r4, lr}"}]}
INFO: second pdfj body was noisy and not parseable
"#;

        let err = parse_checked_radare2_thumb_output(stdout, 0x4000).unwrap_err();

        assert!(matches!(err, Error::Serialize(message) if message.contains("missing 1 pdfj")));
    }

    #[test]
    fn radare2_thumb_does_not_reuse_entry_matched_pdfj_as_positional_fallback() {
        let stdout = br#"Warning: noisy prelude
[{"name":"sym.first","offset":16384,"size":64},{"name":"sym.second","offset":16448,"size":64}]
{"addr":16448,"ops":[{"offset":16448,"bytes":"4770","disasm":"bx lr"}]}
"#;

        let err = parse_checked_radare2_thumb_output(stdout, 0x4000).unwrap_err();

        assert!(matches!(err, Error::Serialize(message) if message.contains("missing 1 pdfj")));
    }

    #[test]
    fn radare2_thumb_rejects_positional_pdfj_with_different_parseable_entry() {
        let stdout = br#"Warning: noisy prelude
[{"name":"sym.first","offset":16384,"size":64},{"name":"sym.second","offset":16448,"size":64}]
{"addr":20480,"ops":[{"offset":20480,"bytes":"00bf","disasm":"nop"}]}
{"addr":16448,"ops":[{"offset":16448,"bytes":"4770","disasm":"bx lr"}]}
"#;

        let err = parse_checked_radare2_thumb_output(stdout, 0x4000).unwrap_err();

        assert!(matches!(err, Error::Serialize(message) if message.contains("missing 1 pdfj")));
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
    fn run_radare2_thumb_rejects_unnormalizable_raw_function() {
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
            match run_radare2_thumb(&r2, &[0u8; 16], 0x4000, &[(0x4000, 16)], &out) {
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
        let err = last.expect("expected an error from run_radare2_thumb");

        assert!(
            matches!(err, Error::Serialize(message) if message.contains("lacks entry/addr") && message.contains("0x4000"))
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
            tighten_wall_clock_budget_override: None,
        };

        let rep = run_report(&modem, &opts, &dir.join("out")).unwrap();

        assert!(rep.spec_path.ends_with("ghidra_load.json"));
        assert!(rep.spec_path.exists());
        assert!(rep.images.is_empty(), "no images analyzed without --run");
    }

    #[test]
    fn report_failure_returns_thumb_error_when_only_thumb_failed() {
        let report = DecompileReport {
            images: vec![ImageResult {
                label: "02_MAIN".into(),
                outcome: ImageOutcome::Analyzed(12),
                thumb_functions: None,
                thumb_error: Some("radare2 parser rejected empty stdout".into()),
                pass2_applied: None,
                pass2_error: None,
                thumb_decompiled: None,
                thumb_tighten_error: None,
                thumb_enrich_error: None,
                globals_error: None,
                globals_recovered: None,
                globals_applied: None,
                globals_apply_skipped: None,
                globals_apply_error: None,
                globals_provisional: None,
                globals_provisional_suppressed: None,
            }],
            spec_path: PathBuf::from("ghidra_load.json"),
        };

        let err = report_failure(&report).expect("thumb error should fail standalone run");
        assert_eq!(
            err.to_string(),
            "decompose incomplete: radare2 failed on 02_MAIN: radare2 parser rejected empty stdout"
        );
    }

    #[test]
    fn report_failure_does_not_duplicate_label_for_missing_radare2() {
        let report = DecompileReport {
            images: vec![ImageResult {
                label: "02_MAIN".into(),
                outcome: ImageOutcome::Analyzed(12),
                thumb_functions: None,
                thumb_error: Some(
                    "1 Thumb region(s) left unanalyzed — radare2 (r2) not on PATH; Ghidra can't analyze them"
                        .into(),
                ),
                pass2_applied: None,
                pass2_error: None,
                thumb_decompiled: None,
                thumb_tighten_error: None,
                thumb_enrich_error: None,
                globals_error: None,
                globals_recovered: None,
                globals_applied: None,
                globals_apply_skipped: None,
                globals_apply_error: None,
                globals_provisional: None,
                globals_provisional_suppressed: None,
            }],
            spec_path: PathBuf::from("ghidra_load.json"),
        };

        let err = report_failure(&report).expect("thumb error should fail standalone run");
        assert_eq!(
            err.to_string(),
            "decompose incomplete: radare2 failed on 02_MAIN: 1 Thumb region(s) left unanalyzed — radare2 (r2) not on PATH; Ghidra can't analyze them"
        );
    }

    #[test]
    fn image_result_carries_phase3_0_1_fields() {
        let r = ImageResult {
            label: "02_MAIN".into(),
            outcome: ImageOutcome::Analyzed(10),
            thumb_functions: None,
            thumb_error: None,
            pass2_applied: None,
            pass2_error: None,
            thumb_decompiled: None,
            thumb_tighten_error: None,
            thumb_enrich_error: None,
            globals_error: None,
            globals_recovered: Some(968),
            globals_applied: None,
            globals_apply_skipped: None,
            globals_apply_error: None,
            globals_provisional: Some(42),
            globals_provisional_suppressed: Some(7),
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
            tighten_wall_clock_budget_override: None,
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
            sh.contains("export XDG_CONFIG_HOME=\"$HERE/ghidra_config\""),
            "run_ghidra.sh must keep Ghidra config under the output dir:\n{sh}"
        );
        assert!(
            sh.contains("export XDG_CACHE_HOME=\"$HERE/ghidra_cache\""),
            "run_ghidra.sh must keep Ghidra cache under the output dir:\n{sh}"
        );
        assert!(
            sh.contains("-Dapplication.tempdir=$HERE/ghidra_tmp"),
            "run_ghidra.sh must keep Ghidra temp files under the output dir:\n{sh}"
        );
        assert!(
            sh.contains("GHIDRA_HEADLESS_JAVA_OPTIONS=\"$GHIDRA_HEADLESS_JAVA_OPTIONS $GHIDRA_LOCAL_JAVA_OPTIONS\""),
            "run_ghidra.sh must preserve caller-provided headless Java options:\n{sh}"
        );

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
            locate_tools(Some(&home), None, &[])
                .map(|g| g.headless)
                .as_ref(),
            Some(&want)
        );
        // $GHIDRA_INSTALL_DIR used when --ghidra-home is None
        assert_eq!(
            locate_tools(None, Some(&home), &[])
                .map(|g| g.headless)
                .as_ref(),
            Some(&want)
        );
        // PATH dir used as last resort (analyzeHeadless directly in the dir)
        let pdir = base.join("pbin");
        std::fs::create_dir_all(&pdir).unwrap();
        std::fs::write(pdir.join("analyzeHeadless"), b"#!/bin/sh\n").unwrap();
        assert_eq!(
            locate_tools(None, None, std::slice::from_ref(&pdir)).map(|g| g.headless),
            Some(pdir.join("analyzeHeadless"))
        );
        // nothing found -> None
        assert!(locate_tools(None, None, &[]).is_none());

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

        let got = locate_tools(Some(&root), None, &[]).unwrap();
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

        let got = locate_tools(None, None, std::slice::from_ref(&pbin)).unwrap();
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
        assert_eq!(spec.source.sha256.len(), 64);
        assert_eq!(spec.images.len(), 2);
        assert_eq!(spec.images[0].name, "00_BOOT");
        assert_eq!(spec.images[0].file, "images/00_BOOT");
        assert_eq!(spec.images[0].base_addr, "0x00000000");
        assert_eq!(spec.images[0].entry_point, "0x00000000");
        assert_eq!(spec.images[0].size, 4);
        assert_eq!(spec.images[0].sha256.len(), 64);
        assert_eq!(spec.images[1].name, "02_MAIN");
        assert_eq!(spec.images[1].file, "images/02_MAIN");
        assert_eq!(spec.images[1].base_addr, "0x40010000");
        assert_eq!(spec.images[1].entry_point, "0x40010000");
        assert_eq!(spec.images[1].size, 8);
        assert_eq!(spec.images[1].sha256.len(), 64);
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
    fn run_script_probes_both_ghidra_layouts() {
        let base = std::env::temp_dir().join(format!("pme_runscript_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let buf = craft_modem_bin(&[("BOOT", 0x0, 1, &[0xaa, 0xbb, 0xcc, 0xdd])]);
        let toc = Toc::parse(&buf).unwrap();
        write_run_script(&base, &toc, "ARM:LE:32:v7").unwrap();
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
        write_run_script(&base, &toc, evil).unwrap();
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
}
