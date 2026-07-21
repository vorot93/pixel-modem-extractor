# Phase 2 — Thumb decompilation coverage: tighten TameAnalysis, hybrid output

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace today's data-mark-everything `TameAnalysis.java` with a tightened variant that lets Ghidra attempt Thumb function discovery and decompilation in `02_MAIN`, producing per-function hybrid output (`thumb_functions.json` v2 with optional `body_c` per function) and falling back per-function to today's radare2 assembly where Ghidra doesn't converge.

**Architecture:** One bounded investigation (Task 1) picks the tightened Ghidra option set on a real Thumb sample and freezes the winning `mode=tighten` Java code. The investigation gates everything else — if it returns negative, the rest of the plan does not execute (per spec § Surface A). On success, the pipeline gains (a) a `thumb_enrich` pure-Rust step that parses `decompiled.c` and fills per-function `body_c` in `thumb_functions.json` v2; (b) a `mode=tighten|datamark` arg on `TameAnalysis.java`; (c) a runtime wall-clock + log-spam watch with kill + datamark-retry fallback (Surface B); (d) an escape-hatch `--no-thumb-decompile` flag that forces today's behavior. Phase 1's symbol pipeline lights up for Thumb automatically because Thumb functions now live in-program — `ApplySymbols.java` is unchanged.

**Tech stack:** Rust 2024 edition; `clap` 4; `serde`/`serde_json`; `thiserror`; Ghidra 12 headless (Java post-/pre-scripts); `radare2`.

## Global constraints

- Latest stable Rust, edition 2024.
- `cargo fmt --all --check` clean.
- `cargo clippy --all-targets --all-features -- -D warnings` clean (warnings are errors).
- `cargo test --all-targets` green.
- New code is Apache-2.0 compatible.
- **No proprietary data in the repo** — only magic numbers / offsets / structure. Investigation outputs (carved sample bytes, sample `decompiled.c`, measurements on real firmware) are derived artifacts and stay out of git; the findings doc records *measurements*, not firmware bytes.
- **Fidelity over readability when in conflict.** No lossy decompiler options; symbolicate fail-closed criteria unchanged; provenance preserved (`original_name` from the `Symbol` record, not from `functions.json`'s `name` field).
- Inline unit tests next to code; env-gated golden integration tests skip cleanly when env vars unset or inputs absent.
- Commit messages: short imperative subjects, capitalized, no trailing period.
- Phase 1 invariants (CONTRIBUTING.md § "Two-pass sequencing invariants") preserved:
  1. `run_two_pass` takes the pass-1 `DecompileReport` as a parameter; it does NOT re-run `run_report`.
  2. `refresh_decompiled` runs per-image after `run_two_pass` returns `Ok`.
  3. `decode_tokens` runs before the `symbol_map` stage.
- Phase 1's "Thumb entries in the symbol_map are inert" caveat is **retired** in Phase 2 — that is the point of Phase 2.

## Investigation gate

**Task 1 is the gate.** If Task 1's investigation returns negative (no candidate meets the spec's stop conditions), **Tasks 2–12 do not execute.** Commit the negative-result findings doc and stop; re-spec.

If Task 1 succeeds, the literal `mode=tighten` Java code committed in the findings doc is the source of truth for Task 5. Do not invent different Java in Task 5.

---

## Task 1: Investigation — sample-first, pick the tightened TameAnalysis config

**Special task.** Empirical, one-off, does not follow TDD. Produces two committed artifacts that downstream tasks consume: (a) a findings appendix under `docs/superpowers/specs/`; (b) the literal `mode=tighten` Java code, recorded inside the findings doc.

**Files:**
- Create: `docs/superpowers/specs/2026-07-21-thumb-decompilation-phase2-findings.md`

**Inputs (do not commit; lawfully obtained, supplied via env):**
- `PME_RADIO_IMG=/path/to/radio.img` — a real Pixel radio image.
- A local Ghidra install (`GHIDRA_INSTALL_DIR` or `/opt/ghidra`).
- A local radare2 (`r2` on `PATH`).

**Consumes:**
- `src/decompile.rs:thumb_regions(bytes, load_addr) -> Vec<(u32, u32)>` (entropy-based region detector).
- `src/decompile.rs:run_radare2_thumb(...)` (today's baseline Thumb analyzer).
- `src/ghidra/TameAnalysis.java` (today's data-marking pre-script).

**Produces (in the findings doc — these are the literal artifacts Tasks 5 and 11 reference):**
- Per-candidate measurements: `N_r2`, `N_ghidra`, wall-clock, repair-log count, 3 spot-check verdicts.
- The winning candidate's exact `mode=tighten` Java body — a snippet that Tasks 5 embeds in `TameAnalysis.java` verbatim.
- The exact Ghidra analysis option name(s) used (e.g. the `ClearFlowAndRepairCmd` toggle). Record the canonical Ghidra-12 name discovered by `javap`-ing the relevant framework jars.

- [ ] **Step 1: Carve the smallest dense-Thumb sample region**

Use the existing pipeline to detect dense-Thumb regions on a real `02_MAIN`:

```sh
# Extract the modem images from a real radio.img (lawfully obtained).
PME_RADIO_IMG=/path/to/radio.img cargo run --release -- extract "$PME_RADIO_IMG"
# This writes ./radio.extracted/modem.bin.split/02_MAIN (among others).
```

Then write a one-off Rust helper (do NOT commit it; it's scratch) to find the smallest detected dense-Thumb region in `02_MAIN`:

```sh
cat > /tmp/carve_sample.rs <<'EOF'
//! Scratch: find the smallest dense-Thumb region in 02_MAIN and carve it.
fn window_entropy(w: &[u8]) -> f64 {
    if w.is_empty() { return 0.0; }
    let mut counts = [0u32; 256];
    for &b in w { counts[b as usize] += 1; }
    let n = w.len() as f64;
    counts.iter().filter(|&&c| c > 0).map(|&c| { let p = c as f64 / n; -p * p.log2() }).sum()
}
fn thumb_regions(bytes: &[u8], load_addr: u32) -> Vec<(u32, u32)> {
    const WINDOW: usize = 64 * 1024;
    const ENTROPY_THRESHOLD: f64 = 6.5;
    const MIN_REGION: usize = 1024 * 1024;
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut open: Option<usize> = None;
    let mut off = 0;
    while off < bytes.len() {
        let end = (off + WINDOW).min(bytes.len());
        if window_entropy(&bytes[off..end]) > ENTROPY_THRESHOLD { open.get_or_insert(off); }
        else if let Some(start) = open.take() { spans.push((start, off)); }
        off = end;
    }
    if let Some(start) = open.take() { spans.push((start, bytes.len())); }
    spans.into_iter().filter(|(s,e)| e-s >= MIN_REGION).map(|(s,e)| (load_addr.wrapping_add(s as u32), (e-s) as u32)).collect()
}
fn main() {
    let bytes = std::fs::read(std::env::args().nth(1).expect("02_MAIN path")).unwrap();
    let regions = thumb_regions(&bytes, 0x40e00000); // 02_MAIN load addr; confirm from manifest.json
    let (smallest_addr, smallest_len) = regions.iter().min_by_key(|(_,l)| l).unwrap();
    let off = smallest_addr.wrapping_sub(0x40e00000) as usize;
    std::fs::write("/tmp/thumb_sample.bin", &bytes[off..off + *smallest_len as usize]).unwrap();
    println!("carved {} bytes at 0x{:08x} -> /tmp/thumb_sample.bin", smallest_len, smallest_addr);
}
EOF
rustc /tmp/carve_sample.rs -o /tmp/carve_sample && /tmp/carve_sample radio.extracted/modem.bin.split/02_MAIN
```

Confirm the carve by inspecting entropy: `python3 -c "import math,sys; b=open('/tmp/thumb_sample.bin','rb').read(); print(len(b), 'bytes')"`.

- [ ] **Step 2: Record the baseline `N_r2` (radare2 function count)**

Run today's radare2 path on the carved sample (load address from the carved region's first byte):

```sh
R2_LOAD_ADDR=0x40e12000  # replace with the actual smallest_addr from Step 1
r2 -a arm -b 16 -m "$R2_LOAD_ADDR" -q -c 'aaa;aflj' /tmp/thumb_sample.bin > /tmp/sample_aflj.json
python3 -c "import json; print('N_r2 =', len(json.load(open('/tmp/sample_aflj.json'))))"
```

Record `N_r2` in the findings doc.

- [ ] **Step 3: Try candidate 1 — status quo control (today's TameAnalysis)**

Set up a tiny Ghidra scratch project and import the carved sample with today's `TameAnalysis` data-marking the whole region. Expected: 0 functions discovered (because data-marked). This confirms experiment wiring.

Record the actual `N_ghidra`, wall-clock, repair-log count, and a one-line verdict ("wiring confirmed: 0 functions as expected" or observed anomaly).

- [ ] **Step 4: Try candidate 2 — no data-marks**

Disable Aggressive Instruction Finder only; leave the region as code. The candidate Java body for `mode=tighten` is:

```java
// Candidate 2: no data-marks. Aggressive Instruction Finder stays disabled.
Options opts = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
for (String name : DISABLE) {
    if (opts.contains(name)) { opts.setBoolean(name, false); println("TameAnalysis: disabled '" + name + "'"); }
}
```

Run Ghidra headless on the sample; record `N_ghidra`, wall-clock, repair-log count, and 3 spot-check verdicts (open `decompiled.c` for 3 random functions; non-empty + plausible C = pass; empty/spin/garbage = fail).

- [ ] **Step 5: Try candidate 3 — no data-marks + disable ClearFlowAndRepairCmd**

First, `javap` Ghidra 12 to find the exact analysis option name controlling overlapping-function repair. Look under `/opt/ghidra/Ghidra/Features/*/lib/*.jar` for analysis-option keys. The likely name pattern is `"Function Start Search"` sub-options or `"Clear Flow And Repair"` — confirm by inspection; record the exact name.

The candidate Java body for `mode=tighten` is then:

```java
// Candidate 3: no data-marks + disable ClearFlowAndRepairCmd (exact name TBD by javap).
Options opts = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
for (String name : DISABLE) {
    if (opts.contains(name)) { opts.setBoolean(name, false); println("TameAnalysis: disabled '" + name + "'"); }
}
String[] TIGHTEN_EXTRA = { "<EXACT_NAME_FROM_JAVAP>" }; // e.g. the ClearFlowAndRepairCmd toggle
for (String name : TIGHTEN_EXTRA) {
    if (opts.contains(name)) { opts.setBoolean(name, false); println("TameAnalysis: disabled '" + name + "'"); }
}
```

Run + measure + spot-check as in Step 4.

- [ ] **Step 6: Try candidate 4 — no data-marks + cap repair effort (only if candidate 3 over-merges)**

Skip this step if candidate 3 already passed the stop conditions. Only run if candidate 3 lost too many functions (`N_ghidra < 0.5 × N_r2`). Try a "cap repair" variant: keep repair on, but find the option that fails fast instead of spinning (likely a related sub-option of `Function Start Search` or `Clear Flow And Repair`; identify via `javap`). Measure.

- [ ] **Step 7: Apply stop conditions; decide success or negative**

Stop conditions (spec § Investigation protocol → Stop conditions):
- **Success:** `N_ghidra ≥ 0.5 × N_r2` AND wall-clock < 30 min on the sample AND < 1000 repair-related log lines AND all 3 spot-checks produce non-empty C.
- **Failure:** all tried candidates exhausted without meeting the bar.

Stop at the first success.

- [ ] **Step 8: Write the findings appendix**

Create `docs/superpowers/specs/2026-07-21-thumb-decompilation-phase2-findings.md`. Structure:

```markdown
# Phase 2 investigation findings — Thumb decompilation via tightened TameAnalysis

Status: <success | negative>  Date: <YYYY-MM-DD>

## Sample

- Source: real `02_MAIN`, lawfully obtained via `PME_RADIO_IMG` (not committed).
- Region: `0x<addr>`–`0x<addr+len>`, <len> bytes (smallest detected dense-Thumb region).
- `N_r2` (baseline radare2 function count): <N>.

## Per-candidate measurements

| # | Candidate | N_ghidra | Wall-clock | Repair-log lines | Spot-checks | Verdict |
|---|-----------|----------|------------|------------------|-------------|---------|
| 1 | Status quo control (data-mark) | 0 | … | … | n/a | wiring confirmed |
| 2 | No data-marks | … | … | … | … | … |
| 3 | No data-marks + disable <OPTION> | … | … | … | … | … |
| 4 | No data-marks + cap repair | … | … | … | … | … |

## Winning configuration (or negative result)

<If success: name the winning candidate. Embed the literal `mode=tighten` Java body
that Task 5 will paste into `TameAnalysis.java` verbatim. Record the exact Ghidra
analysis-option name(s) used.>

<If negative: state which stop-condition each candidate missed. Task 5 does not
apply; Tasks 2–12 do not execute; re-spec.>
```

- [ ] **Step 9: Commit the findings doc**

```sh
git add docs/superpowers/specs/2026-07-21-thumb-decompilation-phase2-findings.md
git commit -m "Add Phase-2 investigation findings"
```

- [ ] **Step 10: Gate decision**

If status is **success**: continue to Task 2.
If status is **negative**: stop. Open an issue / re-spec for Phase 2.1 picking Approach 2 (r2ghidra), Approach 3 (carve), or strategy B/C.

---

## Task 2: Add Phase-2 fields to `decompile::ImageResult` and `decompose::ImageReport`

Adds the three new `Option` fields the spec requires (§ Artifacts → `decompose::ImageResult`). Pure addition; no behavior change yet. Existing fields keep their exact names and order.

**Files:**
- Modify: `src/decompile.rs:215-226` (`ImageResult` struct)
- Modify: `src/decompose.rs:29-45` (`ImageReport` struct)
- Modify: `src/decompose.rs:47-75` (`ImageReport::from_result`)

**Interfaces:**
- Produces:
  - `decompile::ImageResult.thumb_decompiled: Option<usize>` — count of functions where `body_c` was populated (Task 4 sets it).
  - `decompile::ImageResult.thumb_tighten_error: Option<String>` — Surface B failure text (Task 7 sets it).
  - `decompile::ImageResult.thumb_enrich_error: Option<String>` — Surface C failure text (Task 8 sets it).
  - `decompose::ImageReport` mirrors all three with `#[serde(skip_serializing_if = "Option::is_none")]`.

- [ ] **Step 1: Write the failing tests**

Add to the `#[cfg(test)] mod tests` block in `src/decompose.rs` (extending the existing `ImageReport` test block). The test asserts the new fields exist, default to `None`, and round-trip through `from_result`:

```rust
#[test]
fn image_report_serializes_phase2_fields_as_none_when_absent() {
    let r = decompile::ImageResult {
        label: "02_MAIN".into(),
        outcome: decompile::ImageOutcome::Analyzed(10),
        thumb_functions: Some(5),
        thumb_error: None,
        pass2_applied: None,
        pass2_error: None,
        thumb_decompiled: None,
        thumb_tighten_error: None,
        thumb_enrich_error: None,
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
        thumb_functions: Some(5),
        thumb_error: None,
        pass2_applied: None,
        pass2_error: None,
        thumb_decompiled: Some(3),
        thumb_tighten_error: None,
        thumb_enrich_error: Some("malformed decompiled.c".into()),
    };
    let report = ImageReport::from_result(&r);
    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains("\"thumb_decompiled\":3"));
    assert!(!json.contains("thumb_tighten_error"));
    assert!(json.contains("\"thumb_enrich_error\":\"malformed decompiled.c\""));
}
```

- [ ] **Step 2: Run the tests; verify they fail to compile**

```sh
cargo test --lib decompose::tests::image_report_serializes_phase2
```
Expected: compile error — `thumb_decompiled`, `thumb_tighten_error`, `thumb_enrich_error` are not fields of `ImageResult` / `ImageReport`.

- [ ] **Step 3: Add the fields to `ImageResult`**

Edit `src/decompile.rs` at the `ImageResult` definition (around line 215). Replace the existing block:

```rust
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
}
```

with:

```rust
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
}
```

- [ ] **Step 4: Update every existing `ImageResult { ... }` construction to set the new fields to `None`**

Grep for `ImageResult {` and add the three fields initialized to `None` in each. Specifically in `src/decompile.rs` (around line 515, where today's construction lives) and any test fixtures. Example patch for the production construction:

```rust
image_results = results
    .into_iter()
    .map(
        |(label, outcome, thumb_functions, thumb_error)| ImageResult {
            label,
            outcome,
            thumb_functions,
            thumb_error,
            pass2_applied: None,
            pass2_error: None,
            thumb_decompiled: None,
            thumb_tighten_error: None,
            thumb_enrich_error: None,
        },
    )
    .collect();
```

`run_two_pass` already constructs `ImageResult` by mutating existing fields — confirm the three new fields are initialized to `None` at construction and only overwritten by Tasks 7 and 8 if their respective surfaces fire.

- [ ] **Step 5: Add the new fields to `decompose::ImageReport`**

Edit `src/decompose.rs` at the `ImageReport` definition (around line 30). Append after `pass2_error`:

```rust
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pass2_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumb_decompiled: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumb_tighten_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumb_enrich_error: Option<String>,
}
```

- [ ] **Step 6: Update `ImageReport::from_result` to thread the new fields**

In `src/decompose.rs:47-75`, both match arms need to copy the three new fields. Edit each arm:

```rust
ImageOutcome::Analyzed(n) => ImageReport {
    image: r.label.clone(),
    status: if r.thumb_error.is_some() { "failed" } else { "analyzed" },
    functions: Some(n),
    thumb_functions: r.thumb_functions,
    thumb_error: r.thumb_error.clone(),
    exit: None,
    pass2_applied: r.pass2_applied,
    pass2_error: r.pass2_error.clone(),
    thumb_decompiled: r.thumb_decompiled,
    thumb_tighten_error: r.thumb_tighten_error.clone(),
    thumb_enrich_error: r.thumb_enrich_error.clone(),
},
ImageOutcome::Failed(code) => ImageReport {
    image: r.label.clone(),
    status: "failed",
    functions: None,
    thumb_functions: r.thumb_functions,
    thumb_error: r.thumb_error.clone(),
    exit: Some(code),
    pass2_applied: r.pass2_applied,
    pass2_error: r.pass2_error.clone(),
    thumb_decompiled: r.thumb_decompiled,
    thumb_tighten_error: r.thumb_tighten_error.clone(),
    thumb_enrich_error: r.thumb_enrich_error.clone(),
},
```

- [ ] **Step 7: Run the new tests; verify they pass**

```sh
cargo test --lib decompose::tests::image_report_serializes_phase2
```
Expected: PASS.

- [ ] **Step 8: Run the full suite to catch any construction regressions**

```sh
cargo build && cargo test --all-targets
```
Expected: PASS (no behavior change; all new fields default to `None`).

- [ ] **Step 9: Commit**

```sh
git add src/decompile.rs src/decompose.rs
git commit -m "Add Phase-2 ImageResult and ImageReport fields"
```

---

## Task 3: Add `thumb_functions.json` v2 format constant

Bumps the format string from `pixel-modem-extractor-thumb-functions-v1` to `pixel-modem-extractor-thumb-functions-v2`. v1 readers ignore unknown keys (per spec § Artifacts → `thumb_functions.json`), so this is forward-compatible.

**Files:**
- Modify: `src/decompile.rs` (the `"format"` literal inside `run_radare2_thumb`'s `serde_json::json!` macro — around line 1333)
- Modify: `src/symbolicate.rs` (any literal referring to the format constant)
- Modify: `src/recover_source.rs` (the loader's expected format string — around line 388–393)

**Interfaces:**
- Produces: `thumb_functions.json` files emitted by `run_radare2_thumb` carry `"format": "pixel-modem-extractor-thumb-functions-v2"` (still asm-only at this stage; Task 4 adds `body_c`).

- [ ] **Step 1: Write the failing test**

Add to `src/decompile.rs`'s `#[cfg(test)] mod tests`. The test asserts the format bump:

```rust
#[test]
fn run_radare2_thumb_emits_v2_format_string() {
    // Reuse the existing craft_modem_bin + r2 skip pattern from run_radare2_thumb_* tests.
    // If r2 is not installed, this test skips cleanly (see existing pattern).
    let r2 = match crate::decompile::find_radare2() {
        Some(p) => p,
        None => { eprintln!("skipping (no r2)"); return; }
    };
    let out = temp_dir("thumb_v2_format");
    let _ = run_radare2_thumb(&r2, &[0u8; 0x180], 0x4000, &[(0x4120, 0x20)], &out).unwrap();
    let bytes = std::fs::read(out.join("thumb_functions.json")).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        v["format"],
        "pixel-modem-extractor-thumb-functions-v2",
        "Phase 2 bumps the format to v2 (body_c field arrives in Task 4)"
    );
}
```

- [ ] **Step 2: Run the test; verify it fails**

```sh
cargo test --lib decompile::tests::run_radare2_thumb_emits_v2_format_string
```
Expected: FAIL — today's format string is `pixel-modem-extractor-thumb-functions-v1`.

- [ ] **Step 3: Bump the format constant in `run_radare2_thumb`**

In `src/decompile.rs` (around line 1332, the `serde_json::json!` macro), change:

```rust
    let wrapped = serde_json::json!({
        "format": "pixel-modem-extractor-thumb-functions-v1",
        "functions": all,
    });
```

to:

```rust
    let wrapped = serde_json::json!({
        "format": "pixel-modem-extractor-thumb-functions-v2",
        "functions": all,
    });
```

- [ ] **Step 4: Update the loader in `recover_source.rs`**

In `src/recover_source.rs` around line 388–393 (`parses_optional_radare2_thumb_functions` test pattern), the loader must accept both v1 and v2 (forward-compat for golden trees written under v1). Look for the format-string check and make it accept either:

```rust
// Before (strict v1):
if thumb_file.format != "pixel-modem-extractor-thumb-functions-v1" { … }

// After (accept v1 or v2; v2 readers must populate body_c which v1 omits):
match thumb_file.format.as_str() {
    "pixel-modem-extractor-thumb-functions-v1" | "pixel-modem-extractor-thumb-functions-v2" => {}
    other => return Err(Error::BadMagic { … }),
}
```

Confirm the actual check by reading `recover_source.rs` before patching; if there's no strict check today (just an informational field), leave the loader untouched.

- [ ] **Step 5: Update the inline test fixture values**

`src/recover_source.rs:1058` and `src/symbolicate.rs` inline test fixtures that hard-code the v1 format string: update them to v2 where they're round-trip-testing new output, OR add parallel v2 fixtures if they're testing v1 input parsing. Read each before patching.

- [ ] **Step 6: Run all tests; verify pass**

```sh
cargo test --all-targets
```
Expected: PASS.

- [ ] **Step 7: Commit**

```sh
git add src/decompile.rs src/recover_source.rs src/symbolicate.rs
git commit -m "Bump thumb_functions.json format to v2"
```

---

## Task 4: Add `thumb_enrich` — pure-Rust step that fills `body_c` from `decompiled.c`

The biggest new code unit. Pure file I/O + parsing; no Ghidra round-trip. Idempotent.

**Files:**
- Modify: `src/decompile.rs` (add `thumb_enrich` function + inline tests)

**Interfaces:**
- Produces:
  ```rust
  /// Phase 2: enrich a v1 (or v2 asm-only) `thumb_functions.json` with per-function
  /// `body_c` sourced from a `decompiled.c`. Bumps `format` to v2 iff at least one
  /// `body_c` is populated; otherwise leaves the file unchanged. Idempotent.
  ///
  /// `decompiled_c_path` is the unified C listing (pass-1 or post-pass-2). The
  /// `thumb_functions_json_path` is read, updated in memory, and rewritten in place.
  ///
  /// Returns the count of functions whose `body_c` was populated. Fail-closed:
  /// a malformed `decompiled.c` returns `Err`; the on-disk `thumb_functions.json`
  /// is unchanged.
  pub fn thumb_enrich(
      decompiled_c_path: &Path,
      thumb_functions_json_path: &Path,
  ) -> Result<usize>
  ```

- [ ] **Step 1: Write the failing test — populates body_c for matching entry**

Add to `src/decompile.rs`'s `#[cfg(test)] mod tests`:

```rust
#[test]
fn thumb_enrich_populates_body_c_for_matching_entry() {
    let root = temp_dir("thumb_enrich_match");
    let c_path = root.join("decompiled.c");
    std::fs::write(
        &c_path,
        "/*\n * FUN_40e1200\n */\nvoid thumb_40e1200(int a)\n{\n  return;\n}\n\n"
    ).unwrap();
    let thumb_path = root.join("thumb_functions.json");
    std::fs::write(
        &thumb_path,
        r#"{
            "format": "pixel-modem-extractor-thumb-functions-v2",
            "functions": [
                {"entry": "0x40e1200", "name": "thumb_40e1200", "size": 8,
                 "body_kind": "thumb_disassembly", "body": "movs r0, 0", "data_refs": []},
                {"entry": "0x40efffc", "name": "thumb_40efffc", "size": 4,
                 "body_kind": "thumb_disassembly", "body": "bx lr", "data_refs": []}
            ]
        }"#
    ).unwrap();

    let n = thumb_enrich(&c_path, &thumb_path).unwrap();
    assert_eq!(n, 1, "exactly one function matched");

    let v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&thumb_path).unwrap()).unwrap();
    assert_eq!(v["format"], "pixel-modem-extractor-thumb-functions-v2");
    assert!(v["functions"][0]["body_c"].is_string());
    assert!(v["functions"][0]["body_c"].as_str().unwrap().contains("thumb_40e1200"));
    assert!(v["functions"][1].get("body_c").is_none(), "no match -> no body_c");
}
```

- [ ] **Step 2: Write the failing test — zero matches leaves file byte-identical**

```rust
#[test]
fn thumb_enrich_zero_matches_leaves_file_unchanged() {
    let root = temp_dir("thumb_enrich_no_match");
    let c_path = root.join("decompiled.c");
    std::fs::write(&c_path, "/* nothing relevant */\nvoid FUN_deadbeef(void){}\n").unwrap();
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
```

- [ ] **Step 3: Write the failing test — idempotent**

```rust
#[test]
fn thumb_enrich_is_idempotent() {
    let root = temp_dir("thumb_enrich_idem");
    let c_path = root.join("decompiled.c");
    std::fs::write(
        &c_path,
        "void thumb_40e1200(void){\n  return;\n}\n"
    ).unwrap();
    let thumb_path = root.join("thumb_functions.json");
    std::fs::write(
        &thumb_path,
        r#"{"format":"pixel-modem-extractor-thumb-functions-v1","functions":[
            {"entry":"0x40e1200","name":"thumb_40e1200","size":4,
             "body_kind":"thumb_disassembly","body":"bx lr","data_refs":[]}]}"#
    ).unwrap();

    let _ = thumb_enrich(&c_path, &thumb_path).unwrap();
    let after_first = std::fs::read_to_string(&thumb_path).unwrap();
    let _ = thumb_enrich(&c_path, &thumb_path).unwrap();
    let after_second = std::fs::read_to_string(&thumb_path).unwrap();
    assert_eq!(after_first, after_second, "second run is a no-op on the same inputs");
}
```

- [ ] **Step 4: Write the failing test — fail-closed on malformed decompiled.c**

```rust
#[test]
fn thumb_enrich_fail_closed_on_malformed_decompiled_c() {
    let root = temp_dir("thumb_enrich_bad_c");
    let c_path = root.join("decompiled.c");
    // Not valid UTF-8.
    std::fs::write(&c_path, &[0xff, 0xfe, 0xfd, 0xfc]).unwrap();
    let thumb_path = root.join("thumb_functions.json");
    let original = r#"{"format":"pixel-modem-extractor-thumb-functions-v1","functions":[]}"#;
    std::fs::write(&thumb_path, original).unwrap();

    let err = thumb_enrich(&c_path, &thumb_path).unwrap_err();
    // The on-disk JSON is unchanged.
    assert_eq!(std::fs::read_to_string(&thumb_path).unwrap(), original);
    // Surfaced as a typed error (any variant — just confirm it's not silent).
    let _ = format!("{err}");
}
```

- [ ] **Step 5: Run the tests; verify they fail to compile**

```sh
cargo test --lib decompile::tests::thumb_enrich
```
Expected: compile error — `thumb_enrich` is not defined.

- [ ] **Step 6: Implement `thumb_enrich`**

Add to `src/decompile.rs` (place near `run_radare2_thumb`, around line 1340):

```rust
/// Phase 2: enrich a v1 (or v2 asm-only) `thumb_functions.json` with per-function
/// `body_c` sourced from a `decompiled.c`. Bumps `format` to v2 iff at least one
/// `body_c` is populated; otherwise leaves the file byte-identical. Idempotent.
///
/// `decompiled.c` is parsed by scanning for top-level function headers of the form
///
/// ```text
/// <return-type> <name>(<params>)\n{\n ... \n}\n
/// ```
///
/// where `<name>` matches the radare2-emitted `thumb_<hex>` entry name (the entry's
/// pre-rename name; pass-2 regenerates `decompiled.c` with post-rename names, and
/// `thumb_enrich` re-runs against that to refresh `body_c` with the new names).
///
/// Matching is by name (not entry address) because `decompiled.c`'s function names
/// are exactly the names in `thumb_functions.json` at the time `decompiled.c` was
/// emitted. Returns the count of functions whose `body_c` was populated.
///
/// Fail-closed: a malformed `decompiled.c` (read or parse failure) returns `Err`;
/// the on-disk `thumb_functions.json` is unchanged.
pub fn thumb_enrich(decompiled_c_path: &Path, thumb_functions_json_path: &Path) -> Result<usize> {
    // std::io::Error auto-converts via Error::Io(#[from]) — `?` propagates directly.
    let c_text = std::fs::read_to_string(decompiled_c_path)?;

    // Parse decompiled.c into {function_name -> body_text}.
    let bodies = parse_decompiled_c_function_bodies(&c_text);

    // Read thumb_functions.json, augment in memory, decide whether to rewrite.
    let raw = std::fs::read(thumb_functions_json_path)?;
    let mut v: serde_json::Value = serde_json::from_slice(&raw)
        .map_err(|e| Error::Serialize(format!("parse {}: {e}", thumb_functions_json_path.display())))?;

    let mut populated = 0usize;
    if let Some(funcs) = v.get_mut("functions").and_then(|f| f.as_array_mut()) {
        for f in funcs {
            let Some(name) = f.get("name").and_then(|n| n.as_str()) else { continue };
            if let Some(body) = bodies.get(name) {
                f.as_object_mut().unwrap().insert("body_c".to_string(), serde_json::Value::String(body.clone()));
                populated += 1;
            }
        }
    }

    if populated == 0 {
        return Ok(0); // Leave file byte-identical (do not rewrite).
    }

    // Bump format to v2 on first population.
    if let Some(obj) = v.as_object_mut() {
        obj.insert("format".to_string(), serde_json::Value::String("pixel-modem-extractor-thumb-functions-v2".to_string()));
    }

    let out = serde_json::to_string_pretty(&v)
        .map_err(|e| Error::Serialize(format!("re-serialize thumb_functions.json: {e}")))?;
    std::fs::write(thumb_functions_json_path, out)?;
    Ok(populated)
}

/// Parse a `decompiled.c` text into a map of `{function_name -> body_text}`, where
/// `body_text` is the full function including signature and braces. The parser is
/// deliberately conservative: it scans for lines that look like function headers
/// (identifier-ish name followed by `(...)` and a trailing `{`), then captures
/// text up to the matching closing `}` at brace-depth 0. Comments and string
/// literals are not special-cased — ExportDecomp.java's output is regular enough
/// that brace-counting is sufficient; malformed input fails closed in the caller.
fn parse_decompiled_c_function_bodies(c_text: &str) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    let lines: Vec<&str> = c_text.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        // Match a line ending in `{` that also contains `(` and `)` and a name token.
        // Header shape exported by ExportDecomp.java: "<ret> <name>(<params>)\n{\n".
        if line.trim_end().ends_with('{') && line.contains('(') && line.contains(')') {
            // Extract the name: the identifier immediately before the first '('.
            let before_paren = line.split('(').next().unwrap_or("").trim();
            let name = before_paren.rsplit(|c: char| !c.is_ascii_alphanumeric() && c != '_').next().unwrap_or("");
            if name.is_empty() {
                i += 1;
                continue;
            }
            // Capture from this line through the matching closing brace at depth 0.
            let start = i;
            let mut depth = 0i32;
            let mut body = String::new();
            while i < lines.len() {
                let l = lines[i];
                for ch in l.chars() {
                    match ch {
                        '{' => depth += 1,
                        '}' => depth -= 1,
                        _ => {}
                    }
                }
                body.push_str(l);
                body.push('\n');
                if depth <= 0 && i > start {
                    break;
                }
                i += 1;
            }
            out.insert(name.to_string(), body);
        }
        i += 1;
    }
    out
}
```

(`src/error.rs` defines `Error::Io(#[from] std::io::Error)` — io::Errors auto-convert via `?`. The implementation above uses `?` directly for filesystem operations and `Error::Serialize(String)` for serde failures. No new error variant is needed.)

- [ ] **Step 7: Run the tests; verify all four pass**

```sh
cargo test --lib decompile::tests::thumb_enrich
```
Expected: PASS for all four.

- [ ] **Step 8: Run clippy on the new code**

```sh
cargo clippy --all-targets --all-features -- -D warnings
```
Expected: clean.

- [ ] **Step 9: Commit**

```sh
git add src/decompile.rs
git commit -m "Add thumb_enrich step (pure Rust, populates body_c)"
```

---

## Task 5: Update `TameAnalysis.java` with a `mode` argument

Applies the winning configuration from Task 1's findings doc. The Java body for `mode=tighten` is **whatever Task 1 recorded in the findings doc** — copy it verbatim. Do not invent a different set of options.

**Files:**
- Modify: `src/ghidra/TameAnalysis.java`

**Interfaces:**
- Produces: `TameAnalysis.java` accepts script arg[0] = `tighten` or `datamark`. Default (no arg) is `tighten` (the new production behavior). When mode is `datamark`, the script reads remaining args as today's `addrHex:lenHex` data-mark regions.

- [ ] **Step 1: Re-read the Task 1 findings doc**

```sh
cat docs/superpowers/specs/2026-07-21-thumb-decompilation-phase2-findings.md
```

Identify the "Winning configuration" section and the literal Java body it embeds for `mode=tighten`. Copy that exact body — Tasks 5 does not invent Java.

If Task 1's status is negative: **stop the plan**. Do not proceed.

- [ ] **Step 2: Restructure `TameAnalysis.java` to take a mode arg**

Replace the entire `run()` body with a mode-dispatching version. The `DISABLE` list stays; the data-marking block moves under `mode=datamark`; the new tighten block (from Task 1) goes under `mode=tighten`. Template:

```java
// TameAnalysis.java — Ghidra headless PRE-script for pixel-modem-extractor.
// Runs before auto-analysis. Phase 2+: takes a mode argument.
//
//   arg[0] = "tighten" (new default; Phase 2+): disable the Aggressive Instruction
//     Finder plus the analysis options identified by the Phase-2 investigation
//     (see docs/superpowers/specs/2026-07-21-thumb-decompilation-phase2-findings.md).
//     Does NOT data-mark regions; Ghidra attempts Thumb function discovery and
//     decompilation. Per-function convergence failures fall through to radare2 in
//     the Rust host (see decompile::thumb_enrich).
//
//   arg[0] = "datamark" (today's Phase-1 behavior; also used by --no-thumb-decompile):
//     additionally mark each remaining arg "addrHex:lenHex" as DATA so Ghidra's
//     analysis of surrounding A32 code converges cleanly on images whose dense
//     Thumb regions we don't want Ghidra to attempt.
//
// When no arg is supplied, defaults to "tighten" (Phase 2+ production behavior).
//@category PixelModem
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

public class TameAnalysis extends GhidraScript {
    private static final String[] DISABLE = {
        "ARM Aggressive Instruction Finder",
        "Aggressive Instruction Finder",
    };

    // Phase-2 winning options (from the investigation findings doc).
    private static final String[] TIGHTEN_EXTRA = {
        // <EXACT_OPTIONS_FROM_TASK_1_FINDINGS_DOC>
    };

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String mode = args.length == 0 ? "tighten" : args[0];

        Options opts = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
        for (String name : DISABLE) {
            if (opts.contains(name)) {
                opts.setBoolean(name, false);
                println("TameAnalysis: disabled '" + name + "'");
            }
        }

        if (mode.equals("tighten")) {
            for (String name : TIGHTEN_EXTRA) {
                if (opts.contains(name)) {
                    opts.setBoolean(name, false);
                    println("TameAnalysis: disabled '" + name + "'");
                }
            }
            println("TameAnalysis: mode=tighten (Phase 2+)");
            return;
        }

        if (mode.equals("datamark")) {
            Listing listing = currentProgram.getListing();
            for (int i = 1; i < args.length; i++) {
                String arg = args[i];
                int colon = arg.indexOf(':');
                if (colon < 0) continue;
                long addr = Long.parseLong(arg.substring(0, colon), 16);
                long len = Long.parseLong(arg.substring(colon + 1), 16);
                Address start = toAddr(addr);
                Address end = start.add(len - 1);
                try {
                    listing.clearCodeUnits(start, end, false);
                    listing.createData(start, new ArrayDataType(Undefined1DataType.dataType, (int) len, 1));
                    println("TameAnalysis: marked data region (radare2 handles it) " + start + ".." + end);
                } catch (Exception e) {
                    println("TameAnalysis: could not mark " + start + ": " + e.getMessage());
                }
            }
            println("TameAnalysis: mode=datamark (Phase-1 fallback)");
            return;
        }

        println("TameAnalysis: unknown mode '" + mode + "' (expected 'tighten' or 'datamark')");
    }
}
```

Replace the `<EXACT_OPTIONS_FROM_TASK_1_FINDINGS_DOC>` placeholder with the literal winning option(s) from Task 1's findings doc. Remove this comment when done.

- [ ] **Step 3: Run any existing unit tests that include `TameAnalysis.java`**

`TameAnalysis.java` is embedded into `decompile.rs` via `include_str!` and written to the kit. Compile-check:

```sh
cargo build
```
Expected: PASS (the include_str! just reads the file; no Java compile happens at Rust build time).

- [ ] **Step 4: Defer full e2e validation to Task 11**

This task's behavioral correctness (does `mode=tighten` actually emit Thumb functions in `decompiled.c`?) is validated by `tests/decompile_golden.rs::tightened_tame_analysis_emits_thumb_function` in Task 11. Do not assert that here.

- [ ] **Step 5: Commit**

```sh
git add src/ghidra/TameAnalysis.java
git commit -m "Add TameAnalysis mode arg (tighten default, datamark fallback)"
```

---

## Task 6: Wire `mode` + `--no-thumb-decompile` through `decompile::Opts` and `headless_args`

Adds the escape hatch plumbing. `Opts` gains `no_thumb_decompile: bool`; `headless_args` passes `tighten` or `datamark` to `TameAnalysis.java`.

**Files:**
- Modify: `src/decompile.rs:23-29` (`Opts` struct)
- Modify: `src/decompile.rs:104-141` (`headless_args` function)

**Interfaces:**
- Produces:
  - `decompile::Opts.no_thumb_decompile: bool` — when true, all Ghidra invocations pass `TameAnalysis mode=datamark` with the carved regions (today's Phase-1 behavior); when false (default), they pass `mode=tighten` (no data-marks).
  - `headless_args` returns a vec that begins the pre-script args with `[mode_str]`, followed by the `addrHex:lenHex` regions only when mode is `datamark`.

- [ ] **Step 1: Write the failing test — tighten mode arg**

Add to `src/decompile.rs`'s `#[cfg(test)] mod tests`:

```rust
#[test]
fn headless_args_passes_tighten_mode() {
    let args = headless_args("$HERE", "02_MAIN", "ARM:LE:32:v7", 0x40e00000, &[(0x40e12000, 0x100000)], "tighten");
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
```

- [ ] **Step 2: Write the failing test — datamark mode arg**

```rust
#[test]
fn headless_args_passes_datamark_mode_and_regions() {
    let args = headless_args("$HERE", "02_MAIN", "ARM:LE:32:v7", 0x40e00000, &[(0x40e12000, 0x100000)], "datamark");
    let pre_idx = args.iter().position(|a| a == "TameAnalysis.java").unwrap();
    assert_eq!(args[pre_idx + 1], "datamark");
    assert!(args[pre_idx + 2..].iter().any(|a| a == "40e12000:100000"));
}
```

- [ ] **Step 3: Run the tests; verify they fail to compile**

```sh
cargo test --lib decompile::tests::headless_args_passes
```
Expected: compile error — today's `headless_args` is 5-arg, no `mode` parameter.

- [ ] **Step 4: Add `no_thumb_decompile` to `Opts`**

Edit `src/decompile.rs:23-29`:

```rust
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
}
```

Update every existing `Opts { ... }` construction to set `no_thumb_decompile: false` by default (search for `Opts {`).

- [ ] **Step 5: Change `headless_args` signature to take `mode`**

Replace `src/decompile.rs:104-141`. The function takes an explicit `mode: &str` and threads it as `TameAnalysis.java`'s arg[0]; when mode is `datamark`, the carved regions follow as today; when mode is `tighten`, no region args are passed:

```rust
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
        "pixel-modem".to_string(),
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
    if opts.no_thumb_decompile { "datamark" } else { "tighten" }
}
```

- [ ] **Step 6: Update all production callers of `headless_args` to pass the mode**

Two production call sites: `write_run_script` (line ~342) and the `--run` loop (line ~441). Update each:

For `write_run_script` (the kit generator), pass `"tighten"` (Phase 2+ production default) — kit callers without Opts get tighten:

```rust
let mode = "tighten"; // Phase 2+: kit callers without Opts get tighten (production default).
let args = headless_args("$HERE", &e.label(), processor, e.load_addr, &regions, mode);
```

For the `--run` loop, derive from `opts`:

```rust
let mode = mode_from_opts(opts);
let args = headless_args(&root_str, &label, &opts.processor, e.load_addr, &regions, mode);
```

Task 7 will replace this single spawn call with the watch-and-retry control flow.

- [ ] **Step 7: Update the existing `headless_args` test**

The existing `headless_args_base_addr_is_hex_without_0x` test (around line 1378) calls `headless_args` with today's 5-arg signature. Update it to pass `mode = "datamark"` so the assertions about region args still hold (today's test asserted regions appear in the output; that's only true in datamark mode now).

- [ ] **Step 8: Run all tests; verify pass**

```sh
cargo test --all-targets
```
Expected: PASS.

- [ ] **Step 9: Commit**

```sh
git add src/decompile.rs
git commit -m "Wire TameAnalysis mode (tighten|datamark) through decompile::Opts"
```

---

## Task 7: Runtime watch — kill tightened Ghidra on spin, fall back to `datamark` (Surface B)

Implements the spec's Surface B protection. The watch kills `analyzeHeadless` when wall-clock or log-spam thresholds are exceeded, then re-spawns pass 1 with `mode=datamark`.

**Files:**
- Modify: `src/decompile.rs` (refactor the `--run` spawn loop; add `should_kill_tighten` helper + tests)

**Interfaces:**
- Produces:
  - `decompile::TightenBudget { wall_clock_multiplier: u32, log_spam_max: usize }` — configurable thresholds (the `--tighten-wall-clock-budget-sec` test-only flag overrides `wall_clock_multiplier` for Section 7 verification).
  - `decompile::should_kill_tighten(elapsed: Duration, repair_log_lines: usize, budget: &TightenBudget) -> Option<KillReason>` — pure decision function.
  - `decompile::KillReason::WallClock | KillReason::LogSpam` — surfaced as the reason string in `thumb_tighten_error`.

- [ ] **Step 1: Write the failing test — decision function**

Add to `src/decompile.rs`'s `#[cfg(test)] mod tests`:

```rust
#[test]
fn should_kill_tighten_returns_none_under_budget() {
    let budget = TightenBudget { wall_clock_multiplier: 4, log_spam_max: 100_000 };
    assert_eq!(
        should_kill_tighten(std::time::Duration::from_secs(60), 1000, &budget),
        None
    );
}

#[test]
fn should_kill_tighten_returns_wall_clock_over_budget() {
    let budget = TightenBudget { wall_clock_multiplier: 4, log_spam_max: 100_000 };
    // 600s elapsed vs. 100s baseline * 4 = 400s budget -> over.
    assert!(matches!(
        should_kill_tighten(std::time::Duration::from_secs(600), 1000, &budget, /*baseline=*/std::time::Duration::from_secs(100)),
        Some(KillReason::WallClock)
    ));
}

#[test]
fn should_kill_tighten_returns_log_spam_over_threshold() {
    let budget = TightenBudget { wall_clock_multiplier: 4, log_spam_max: 100_000 };
    assert!(matches!(
        should_kill_tighten(std::time::Duration::from_secs(10), 200_000, &budget, /*baseline=*/std::time::Duration::from_secs(5)),
        Some(KillReason::LogSpam)
    ));
}
```

(Adjust the function signature in Step 5 below to take a `baseline: Duration` parameter if the test signature above is the better shape — make test and impl match. Tests are the source of truth here.)

- [ ] **Step 2: Run the tests; verify they fail to compile**

```sh
cargo test --lib decompile::tests::should_kill_tighten
```
Expected: compile error — `TightenBudget`, `KillReason`, `should_kill_tighten` undefined.

- [ ] **Step 3: Add the types and decision function**

In `src/decompile.rs`, near `thumb_regions`:

```rust
use std::time::Duration;

/// Phase 2 / Surface B: thresholds for killing a tightened Ghidra run that is
/// spinning on overlapping-function repair. Defaults are conservative; the
/// `--tighten-wall-clock-budget-sec` test-only flag overrides the wall-clock
/// budget for verification.
#[derive(Debug, Clone)]
pub struct TightenBudget {
    /// Multiplied by the pass-1 baseline wall-clock to get the per-image budget.
    pub wall_clock_multiplier: u32,
    /// Hard cap on `ClearFlowAndRepairCmd`-related log lines.
    pub log_spam_max: usize,
}

impl Default for TightenBudget {
    fn default() -> Self {
        Self { wall_clock_multiplier: 4, log_spam_max: 100_000 }
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
/// `baseline` is the pass-1 wall-clock recorded for this image; the budget is
/// `baseline * budget.wall_clock_multiplier`.
pub fn should_kill_tighten(
    elapsed: Duration,
    repair_log_lines: usize,
    budget: &TightenBudget,
    baseline: Duration,
) -> Option<KillReason> {
    let wall_budget = baseline.checked_mul(budget.wall_clock_multiplier)?;
    if elapsed > wall_budget {
        return Some(KillReason::WallClock);
    }
    if repair_log_lines > budget.log_spam_max {
        return Some(KillReason::LogSpam);
    }
    None
}
```

- [ ] **Step 4: Run the unit tests; verify pass**

```sh
cargo test --lib decompile::tests::should_kill_tighten
```
Expected: PASS.

- [ ] **Step 5: Wire the watch into the `--run` spawn loop**

Today's spawn loop in `src/decompile.rs` around line 441–486 uses `headless_command(...).status()` — that blocks until completion. Replace it with a spawn-and-watch pattern. Sketch:

```rust
let mode = mode_from_opts(opts);
let mut tighten_error: Option<String> = None;

if mode == "tighten" {
    // Spawn with piped stdout so we can count ClearFlowAndRepairCmd lines.
    let mut cmd = headless_command(&install.headless, &args, &root, java_home.as_deref());
    cmd.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    let started = Instant::now();
    let mut child = cmd.spawn()?;
    let budget = TightenBudget::default();
    let baseline = Duration::from_secs(60); // placeholder; replace with measured pass-1 wall-clock per image
    let outcome = watch_tighten_child(&mut child, started, baseline, &budget)?;
    match outcome {
        WatchOutcome::Completed => { /* fall through to existing pass-1 result handling */ }
        WatchOutcome::Killed(reason) => {
            tighten_error = Some(format!("tighten killed: {reason}; retrying as datamark"));
            // Re-spawn with mode=datamark.
            let args2 = headless_args(&root_str, &label, &opts.processor, e.load_addr, &regions, "datamark");
            let status2 = headless_command(&install.headless, &args2, &root, java_home.as_deref())
                .status()?;
            // Use status2 as the pass-1 outcome; thumb_enrich will find no Thumb functions in decompiled.c.
            // … (fall through with status2) …
        }
    }
} else {
    // mode == "datamark": today's path, unchanged.
    let status = headless_command(&install.headless, &args, &root, java_home.as_deref()).status()?;
    // … (existing handling) …
}
```

`watch_tighten_child` is a small helper that drains the child's stdout line-by-line, counts lines matching `ClearFlowAndRepairCmd`, polls `should_kill_tighten`, and calls `child.kill()` when it returns `Some`. Returns `WatchOutcome::Completed` when the child exits normally or `WatchOutcome::Killed(reason)` when the watch killed it.

Because this is the riskiest control flow in Phase 2, prefer a minimal, well-commented implementation; full coverage comes from the structural tests + the manual verification step in Task 12.

If implementing the watch inline proves too invasive in this task, split it: this task lands the pure `should_kill_tighten` + `TightenBudget` + `KillReason` types (Steps 3–4), and a follow-up step lands the spawn-loop refactor. Commit each separately.

- [ ] **Step 6: Set `thumb_tighten_error` on the image result**

In the same edit, when the watch killed the run, set `thumb_tighten_error` on the `ImageResult` being built. Use the same fail-closed framing as `thumb_error` / `pass2_error` — `Some(reason_string)` recorded, image not marked `failed`.

- [ ] **Step 7: Add the test-only `--tighten-wall-clock-budget-sec` override**

In `src/cli.rs`'s `Decompile` and `Decompose` variants (Task 10 adds the public flag), add a hidden `--tighten-wall-clock-budget-sec <N>` arg that, when set, overrides `TightenBudget::wall_clock_multiplier` indirectly: it sets an absolute seconds budget that `should_kill_tighten` compares against `elapsed` (instead of `baseline * multiplier`). Implement by adding `pub tighten_wall_clock_budget_override: Option<Duration>` to `Opts` and threading it through.

This arg is **not** documented in `--help` (use `clap`'s `hide = true`). It exists only for Section 7 verification.

- [ ] **Step 8: Run all tests; verify pass**

```sh
cargo test --all-targets
```
Expected: PASS. The watch behavior itself is not unit-tested (non-deterministic); only the pure decision function is.

- [ ] **Step 9: Commit**

```sh
git add src/decompile.rs src/cli.rs
git commit -m "Add tightened-Ghidra runtime watch with datamark retry (Surface B)"
```

---

## Task 8: Wire `thumb_enrich` into the `decompose` pipeline

Plugs the pure `thumb_enrich` (Task 4) into both pass-1 and pass-2 halves of `decompose::run`. Skips on `--no-thumb-decompile`.

**Files:**
- Modify: `src/decompose.rs:run` (around the existing `decompile` / `decompile_pass2` stage boundaries — see lines 367–630)

**Interfaces:**
- Consumes:
  - `decompile::thumb_enrich(decompiled_c_path, thumb_functions_json_path) -> Result<usize>` (Task 4).
  - `decompile::ImageResult.thumb_decompiled` and `thumb_enrich_error` (Task 2).

- [ ] **Step 1: Re-read the pipeline structure**

```sh
sed -n '365,640p' src/decompose.rs
```

Identify the existing stage boundaries: `decompile` (pass 1), `symbol_map`, `decompile_pass2`, `symbolicate`. Today the radare2 path runs **inside** `decompile::run_report` per image. Phase 2 inserts `thumb_enrich` *after* `run_report` returns (pass 1) and again *after* `run_two_pass` returns (pass 2).

- [ ] **Step 2: Add a `thumb_enrich` stage after pass 1**

After the `decompile` stage in `decompose::run` (today's pass-1 block), iterate per image and call `thumb_enrich`. For each image:

```rust
let mut thumb_enrich_errors: Vec<(String, String)> = Vec::new();
let mut thumb_decompiled_counts: Vec<(String, usize)> = Vec::new();
for image_result in &mut decompile_report.images {
    let label = &image_result.label;
    let decompiled_c = out.join(format!("images/{label}/decompiled/decompiled.c"));
    let thumb_json = out.join(format!("images/{label}/decompiled/thumb_functions.json"));
    if !thumb_json.exists() {
        continue; // No Thumb regions on this image.
    }
    match decompile::thumb_enrich(&decompiled_c, &thumb_json) {
        Ok(n) => {
            image_result.thumb_decompiled = Some(n);
            thumb_decompiled_counts.push((label.clone(), n));
        }
        Err(e) => {
            let msg = format!("{e:#}");
            image_result.thumb_enrich_error = Some(msg.clone());
            thumb_enrich_errors.push((label.clone(), msg));
        }
    }
}
let enrich_ms = enrich_started.elapsed().as_millis();
stages.push(StageReport {
    stage: "thumb_enrich",
    status: if thumb_enrich_errors.is_empty() { "ok" } else { "failed" },
    output: Some(format!("{} image(s) enriched", thumb_decompiled_counts.len())),
    reason: None,
    error: thumb_enrich_errors.first().map(|(_, e)| e.clone()),
    images: Vec::new(),
    duration_ms: enrich_ms,
});
```

- [ ] **Step 3: Skip the stage on `--no-thumb-decompile`**

Wrap the Step 2 block:

```rust
if opts.no_thumb_decompile {
    stages.push(StageReport::skipped("thumb_enrich", "--no-thumb-decompile"));
} else {
    // … Step 2 block …
}
```

- [ ] **Step 4: Add a second `thumb_enrich` re-run after pass 2**

After `run_two_pass` returns Ok and `refresh_decompiled` has run per-image (Phase 1 invariant #2), re-run `thumb_enrich` against each image's *regenerated* `decompiled.c`. This refreshes `body_c` with the recovered names. Same shape as Step 2; record into the existing `ImageResult.thumb_decompiled` (overwriting the pass-1 count).

Stage name: `"thumb_enrich_post_pass2"`. Same skip rule on `--no-thumb-decompile`.

- [ ] **Step 5: Skip the second re-run when `--no-symbol-pass`**

```rust
if opts.no_symbol_pass {
    stages.push(StageReport::skipped("thumb_enrich_post_pass2", "--no-symbol-pass"));
} else if !opts.no_thumb_decompile {
    // … Step 4 block …
}
```

- [ ] **Step 6: Add an integration test that mocks `thumb_enrich`'s inputs**

Add to `tests/decompose_golden.rs` (it's env-gated, but the structural assertion runs whenever a real `decompose` output is available). Assert the new stage names appear:

```rust
let stages: Vec<String> = report["stages"].as_array().unwrap().iter()
    .map(|s| s["stage"].as_str().unwrap().to_string())
    .collect();
assert!(stages.iter().any(|s| s == "thumb_enrich"), "stage list: {stages:?}");
```

This test runs only when `PME_RADIO_IMG` + `PME_GOLDEN_DIR` are set (existing pattern in the file).

- [ ] **Step 7: Run the test suite; verify pass**

```sh
cargo test --all-targets
```
Expected: PASS. (The env-gated golden test skips cleanly.)

- [ ] **Step 8: Commit**

```sh
git add src/decompose.rs tests/decompose_golden.rs
git commit -m "Wire thumb_enrich into decompose (pass-1 + post-pass-2)"
```

---

## Task 9: Handle `body_c` in `symbolicate::finalize_image`

Phase-1 invariant preserved: `finalize_image` with `rewrite_decompiled_c=false` (decompose path under pass 2) leaves `body_c` byte-identical (names already correct post-pass-2). With `rewrite_decompiled_c=true` (standalone `symbolicate` subcommand against a pre-Phase-2 tree), renames in `body_c` follow the same text-substitution rule as `body`.

**Files:**
- Modify: `src/symbolicate.rs:690-810` (the `rewrite_text_*` family)

**Interfaces:**
- Consumes: the existing `Symbol.original_name -> name` rename map.
- Produces: `body_c` (when present) is rewritten by the same text substitution that today applies to `body` and `decompiled.c`.

- [ ] **Step 1: Write the failing test — body_c preserved when rewrite_decompiled_c=false**

Add to `src/symbolicate.rs`'s `#[cfg(test)] mod tests`:

```rust
#[test]
fn finalize_image_preserves_body_c_when_rewrite_decompiled_c_false() {
    let root = tmp("pme_sym_body_c_preserve");
    let dec = root.join("images/02_MAIN/decompiled");
    std::fs::create_dir_all(&dec).unwrap();
    // thumb_functions.json v2 with one body_c already populated.
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
    // … minimal functions.json, symbols.json, etc. per existing finalize_image test setup …

    let symbols = vec![Symbol {
        address: "0x40e1200".into(),
        arch: "thumb",
        original_name: "thumb_40e1200".into(),
        name: Some("RealName".into()),
        tier: Tier::Recovered,
        evidence: vec![],
        annotations: vec![],
    }];
    finalize_image(&root.join("images/02_MAIN"), "02_MAIN", &symbols,
        &FinalizeOpts { rewrite_decompiled_c: false }).unwrap();

    let after = std::fs::read_to_string(dec.join("thumb_functions.json")).unwrap();
    assert!(
        after.contains("thumb_40e1200(void)"),
        "body_c must be byte-identical when rewrite_decompiled_c=false: {after}"
    );
}
```

- [ ] **Step 2: Write the failing test — body_c renamed when rewrite_decompiled_c=true**

```rust
#[test]
fn finalize_image_renames_body_c_when_rewrite_decompiled_c_true() {
    // Same setup as above, but call finalize_image with rewrite_decompiled_c: true.
    // Assert the body_c text now contains "RealName" (recovered) instead of "thumb_40e1200".
}
```

- [ ] **Step 3: Run the tests; verify they fail**

```sh
cargo test --lib symbolicate::tests::finalize_image_.*body_c
```
Expected: FAIL — `body_c` is not currently touched by `rewrite_text_*`.

- [ ] **Step 4: Update `rewrite_text_files` (or equivalent) to handle `body_c`**

In `src/symbolicate.rs` (around the `rewrite_text_*` functions, ~line 690–810), the rewrite walks `thumb_functions.json` and substitutes `original_name -> name` in the `body` field. Extend it to also substitute in the `body_c` field when present.

The substitution is the same `original_name -> name` text replacement already applied to `body` — reuse the existing longest-first rename map. Sketch:

```rust
// Inside the thumb_functions.json rewrite, after handling body:
if let Some(body_c) = func.get("body_c").and_then(|v| v.as_str()) {
    let renamed = apply_rename_map(body_c, &rename_map);
    func["body_c"] = serde_json::Value::String(renamed);
}
```

(Use the same rename-map helper already used for `body`.)

- [ ] **Step 5: Ensure the `rewrite_decompiled_c=false` path still skips `body_c`**

The `rewrite_decompiled_c=false` branch already skips the `decompiled.c` rewrite and the `body` rewrite. Verify it also skips `body_c` — the cleanest implementation is to gate the entire text-substitution block (body, body_c, decompiled.c) on `rewrite_decompiled_c`. If today's code already gates `body` substitution under `rewrite_decompiled_c`, then extending it to `body_c` automatically preserves the no-rewrite path.

Read `src/symbolicate.rs:876-905` (`run` and its `rewrite_decompiled_c` check) before patching to confirm the gating structure.

- [ ] **Step 6: Run the tests; verify pass**

```sh
cargo test --lib symbolicate::tests::finalize_image_.*body_c
cargo test --all-targets
```
Expected: PASS.

- [ ] **Step 7: Commit**

```sh
git add src/symbolicate.rs
git commit -m "Handle body_c in symbolicate::finalize_image"
```

---

## Task 10: Add `--no-thumb-decompile` flag to `decompose` and `decompile`

Public CLI escape hatch. Threads `Opts.no_thumb_decompile` end-to-end.

**Files:**
- Modify: `src/cli.rs` (both `Decompile` and `Decompose` variants + their dispatch)
- Modify: `src/decompose.rs:Opts` (add `no_thumb_decompile: bool`)
- Modify: `src/decompile.rs:Opts` (already added in Task 6 Step 4)

**Interfaces:**
- Produces: clap field `no_thumb_decompile: bool` on both subcommands; default `false`. Help text documented.

- [ ] **Step 1: Write the failing CLI parse tests**

Add to `src/cli.rs`'s `#[cfg(test)] mod tests`:

```rust
#[test]
fn decompose_help_lists_no_thumb_decompile_flag() {
    let app = crate::cli::build_app();
    let help = app.render_help(crate::cli::Commands::Decompose { /* … */ });
    // Or however the existing decompose_help test renders help.
    assert!(help.contains("--no-thumb-decompile"), "help:\n{help}");
}

#[test]
fn decompile_help_lists_no_thumb_decompile_flag() {
    // Mirror of the existing decompose_help_mentions_radare2_thumb_regions test.
    let help = render_decompile_help();
    assert!(help.contains("--no-thumb-decompile"), "help:\n{help}");
}

#[test]
fn decompose_no_thumb_decompile_flag_defaults_false() {
    // Parse `decompose radio.img` with no flag; assert opts.no_thumb_decompile == false.
}

#[test]
fn decompose_no_thumb_decompile_flag_parses_true() {
    // Parse `decompose --no-thumb-decompile radio.img`; assert opts.no_thumb_decompile == true.
}
```

Mirror the existing `--no-symbol-pass` test patterns (search `cli.rs` for `no_symbol_pass`).

- [ ] **Step 2: Run the tests; verify they fail to compile**

```sh
cargo test --lib cli::tests::.*no_thumb_decompile
```
Expected: compile error — flag does not exist yet.

- [ ] **Step 3: Add the flag to the `Decompile` clap variant**

In `src/cli.rs`, in the `Decompile { ... }` variant of `Commands`, add (mirroring `no_symbol_pass` in `Decompose`):

```rust
Decompile {
    // … existing fields …
    /// Skip Phase-2 Thumb decompilation: dense Thumb regions stay marked as data
    /// (today's Phase-1 behavior). `thumb_functions.json` is emitted at v2
    /// asm-only (no `body_c`). Use when the tightened TameAnalysis regresses on
    /// your firmware version.
    #[arg(long)]
    no_thumb_decompile: bool,
}
```

- [ ] **Step 4: Add the flag to the `Decompose` clap variant**

Same shape:

```rust
Decompose {
    // … existing fields including no_symbol_pass …
    /// Skip Phase-2 Thumb decompilation: dense Thumb regions stay marked as data
    /// (today's Phase-1 behavior). `thumb_functions.json` is emitted at v2
    /// asm-only (no `body_c`).
    #[arg(long)]
    no_thumb_decompile: bool,
}
```

- [ ] **Step 5: Add `no_thumb_decompile` to `decompose::Opts`**

In `src/decompose.rs:17-27`:

```rust
#[derive(Debug, Clone)]
pub struct Opts {
    pub no_verify: bool,
    pub prune: bool,
    pub ghidra_home: Option<PathBuf>,
    pub processor: String,
    pub no_symbol_pass: bool,
    /// Phase 2 escape hatch: when true, `TameAnalysis` runs in `datamark` mode
    /// and `thumb_enrich` does not run. Default false.
    pub no_thumb_decompile: bool,
}
```

- [ ] **Step 6: Thread the flag through dispatch**

In `src/cli.rs`'s `Commands::Decompile` and `Commands::Decompose` match arms, populate `Opts.no_thumb_decompile` from the parsed clap field. Update every test fixture that constructs `Opts { ... }` to set the new field.

- [ ] **Step 7: Run all tests; verify pass**

```sh
cargo test --all-targets
```
Expected: PASS.

- [ ] **Step 8: Commit**

```sh
git add src/cli.rs src/decompose.rs
git commit -m "Add --no-thumb-decompile flag to decompose and decompile"
```

---

## Task 11: New Ghidra e2e tests in `tests/decompile_golden.rs`

Three new tests that exercise the Phase-2 behavior end-to-end against real Ghidra (skips cleanly when Ghidra is absent — follow the existing pattern in `tests/decompile_golden.rs`).

**Files:**
- Modify: `tests/decompile_golden.rs`

**Inputs:** A real Ghidra (`GHIDRA_INSTALL_DIR` or `/opt/ghidra`); tests skip cleanly otherwise.

- [ ] **Step 1: Reuse the existing TOC-fixture helper**

`tests/decompile_golden.rs` already has a `craft_modem_bin(images: &[(&str, u32, u32, &[u8])]) -> Vec<u8>` helper (mirrored from the inline test). Reuse it.

- [ ] **Step 2: Write `tightened_tame_analysis_emits_thumb_function`**

Craft a TOC fixture with one small hand-assembled valid Thumb-2 function. The minimal payload is a function epilogue/prologue pair in Thumb-2:

```rust
fn thumb_function_bytes() -> Vec<u8> {
    // push {r7, lr}   -> 0xb580 (little-endian: 80 b5)
    // movs r0, #0     -> 0x2000 (little-endian: 00 20)
    // pop {r7, pc}    -> 0xbd80 (little-endian: 80 bd)
    vec![0x80, 0xb5, 0x00, 0x20, 0x80, 0xbd]
}
```

Run `decompile::run_report` with `Opts { no_thumb_decompile: false, ... }` against a TOC fixture embedding that payload at a known load address. Assert `out/export/<label>/decompiled.c` contains a function at the Thumb entry address (Ghidra will name it `FUN_<addr>` or similar).

The test shape:

```rust
#[test]
fn tightened_tame_analysis_emits_thumb_function() {
    let (headless, _ghidra_home) = match locate_ghidra() {
        Some(x) => x,
        None => { eprintln!("skipping (no Ghidra)"); return; }
    };
    let tmp = tempdir().unwrap();
    let modem_bin = tmp.path().join("modem.bin");
    let payload = thumb_function_bytes();
    std::fs::write(&modem_bin, craft_modem_bin(&[("02_MAIN", 0x40e00000, 1, &payload)])).unwrap();

    let opts = decompile::Opts {
        run: true,
        image: None,
        ghidra_home: None,
        processor: "ARM:LE:32:v7".into(),
        no_thumb_decompile: false,
    };
    let report = decompile::run_report(&modem_bin, &opts, tmp.path()).unwrap();
    let decompiled_c = std::fs::read_to_string(
        tmp.path().join("export/02_MAIN/decompiled.c")
    ).unwrap();
    assert!(
        decompiled_c.contains("0x40e00000") || decompiled_c.contains("_40e00000"),
        "tightened TameAnalysis should let Ghidra discover the Thumb function; got:\n{decompiled_c}"
    );
}
```

- [ ] **Step 3: Write `thumb_enrich_populates_body_c`**

```rust
#[test]
fn thumb_enrich_populates_body_c() {
    let tmp = tempdir().unwrap();
    let c_path = tmp.path().join("decompiled.c");
    std::fs::write(&c_path, "void thumb_40e00000(void)\n{\n  return;\n}\n").unwrap();
    let thumb_path = tmp.path().join("thumb_functions.json");
    std::fs::write(&thumb_path, r#"{"format":"pixel-modem-extractor-thumb-functions-v1","functions":[
        {"entry":"0x40e00000","name":"thumb_40e00000","size":6,
         "body_kind":"thumb_disassembly","body":"bx lr","data_refs":[]}]}"#).unwrap();

    let n = decompile::thumb_enrich(&c_path, &thumb_path).unwrap();
    assert_eq!(n, 1);
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&thumb_path).unwrap()).unwrap();
    assert_eq!(v["format"], "pixel-modem-extractor-thumb-functions-v2");
    assert!(v["functions"][0]["body_c"].is_string());
}
```

(This doesn't need Ghidra; it tests the pure Rust step. Group it with the Ghidra tests anyway because it's regression coverage for the Phase-2 contract.)

- [ ] **Step 4: Write `no_thumb_decompile_flag_falls_back_to_datamark`**

Same fixture as Step 2, but `Opts { no_thumb_decompile: true, ... }`. Assert `decompiled.c` does **not** contain the Thumb function (it was data-marked) and `thumb_functions.json` (if any) stays at v2 asm-only.

```rust
#[test]
fn no_thumb_decompile_flag_falls_back_to_datamark() {
    let (headless, _) = match locate_ghidra() {
        Some(x) => x,
        None => { eprintln!("skipping (no Ghidra)"); return; }
    };
    let tmp = tempdir().unwrap();
    let modem_bin = tmp.path().join("modem.bin");
    let payload = thumb_function_bytes();
    std::fs::write(&modem_bin, craft_modem_bin(&[("02_MAIN", 0x40e00000, 1, &payload)])).unwrap();

    let opts = decompile::Opts {
        run: true,
        image: None,
        ghidra_home: None,
        processor: "ARM:LE:32:v7".into(),
        no_thumb_decompile: true,
    };
    let _report = decompile::run_report(&modem_bin, &opts, tmp.path()).unwrap();
    let decompiled_c = std::fs::read_to_string(
        tmp.path().join("export/02_MAIN/decompiled.c")
    ).unwrap();
    assert!(
        !decompiled_c.contains("_40e00000"),
        "--no-thumb-decompile should leave the region data-marked; got:\n{decompiled_c}"
    );
}
```

- [ ] **Step 5: Run the e2e tests against a real Ghidra**

```sh
GHIDRA_INSTALL_DIR=/opt/ghidra cargo test --test decompile_golden -- --nocapture
```
Expected: PASS (or skip cleanly if no Ghidra).

- [ ] **Step 6: Commit**

```sh
git add tests/decompile_golden.rs
git commit -m "Add Phase-2 Ghidra e2e tests (tighten, enrich, escape hatch)"
```

---

## Task 12: `decompose_golden.rs` field assertions + docs sync + final verification

The final integration step. Asserts the new fields land in `report.json`, updates the docs, runs the full gate, and executes the manual verification checklist from spec § Verification.

**Files:**
- Modify: `tests/decompose_golden.rs`
- Modify: `README.md`
- Modify: `CONTRIBUTING.md`

- [ ] **Step 1: Add Phase-2 field assertions to `decompose_golden.rs`**

```rust
#[test]
fn report_json_includes_phase2_fields() {
    let Some(_root) = decompose_root_from_env() else { eprintln!("skipping"); return; };
    let report: serde_json::Value = read_report_json();

    // The fields exist on per-image entries (at least on 02_MAIN).
    let main = report["stages"].as_array().unwrap().iter()
        .flat_map(|s| s["images"].as_array().into_iter().flatten())
        .find(|i| i["image"] == "02_MAIN")
        .expect("02_MAIN entry missing");
    assert!(
        main.get("thumb_decompiled").is_some() || main.get("thumb_tighten_error").is_some(),
        "Phase-2 fields absent on 02_MAIN: {main}"
    );
}
```

(Adjust to match the existing env-gating helper pattern in `decompose_golden.rs`.)

- [ ] **Step 2: Update `README.md` — Commands table**

Add `--no-thumb-decompile` to the `decompose` and `decompile` rows. In the `decompose` row, replace Phase 1's "Phase 1:" sentence with a Phase-2 update:

```markdown
| `decompose <radio.img>` | **Everything, one shot.** … **Phase 1:** decompile runs twice per image (pass 1 analyzes + exports; pass 2 applies recovered names + plate comments). **Phase 2:** dense Thumb regions in `02_MAIN` are decompiled by Ghidra (tightened `TameAnalysis`); functions Ghidra can't converge on fall through to today's radare2 disassembly. `thumb_functions.json` is v2 (optional per-function `body_c`). `--no-thumb-decompile` skips Phase 2 (Phase-1 datamark behavior). |
```

(Refine the wording; the key facts: hybrid Thumb output, v2 schema, `--no-thumb-decompile`.)

- [ ] **Step 3: Update `README.md` — Output layout**

In the Output layout section, update the `decompiled/` description to note `body_c` and the v2 format. Add `--no-thumb-decompile` to the `decompose` example block.

- [ ] **Step 4: Update `CONTRIBUTING.md` — Domain map and invariants**

(a) In the Domain map section, replace the "Phase 1+" / two-pass decompile note's mention of "Thumb entries in the map are inert in Phase 1" with a Phase-2 update:

```markdown
- **Phase 2: Thumb decompilation.** Dense Thumb regions in `02_MAIN` are no
  longer data-marked for Ghidra; the tightened `TameAnalysis` (mode=tighten)
  lets Ghidra attempt function discovery and decompilation. Per-function hybrid
  output: `thumb_functions.json` v2 with optional per-function `body_c`; the
  asm `body` is always populated (radare2 unchanged). `--no-thumb-decompile`
  reverts to Phase-1 datamark behavior. A runtime wall-clock + log-spam watch
  kills Ghidra on overlapping-function-repair spin and falls back to datamark
  per image (recorded as `thumb_tighten_error`, image not marked `failed`).
  `thumb_enrich` parses `decompiled.c` and fills `body_c`; it is pure Rust,
  idempotent, runs after pass 1 and again after pass 2.
```

(b) Add the new invariants:

```markdown
- **Phase 2 invariants.**
  (1) **`thumb_enrich` runs after pass 1 AND after `run_two_pass` returns `Ok`.**
  Skipping the second run leaves `body_c` with placeholder names — same
  contract as pass-2 skipping on `--no-symbol-pass`.
  (2) **`--no-thumb-decompile` skips both `thumb_enrich` runs** and forces
  `TameAnalysis mode=datamark` end-to-end. The output is byte-equivalent to
  today's Phase-1 behavior (modulo the v2 format bump on `thumb_functions.json`).
  (3) **The runtime watch (Surface B) is non-deterministic.** Its data fields
  (`thumb_tighten_error`) are structurally tested; the kill behavior itself is
  verified manually via `--tighten-wall-clock-budget-sec 1`.
```

(c) Record the winning TameAnalysis option(s) from Task 1's findings doc, with a one-line rationale per losing candidate. Reference the findings doc by path.

- [ ] **Step 5: Run the standard Rust gate**

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
```
Expected: PASS on all three.

- [ ] **Step 6: Run the Ghidra e2e suite against a real Ghidra**

```sh
GHIDRA_INSTALL_DIR=/opt/ghidra cargo test --test decompile_golden -- --nocapture
```
Expected: PASS (all three new tests, plus existing Phase-1 regression tests).

- [ ] **Step 7: Manual verification on a real radio image**

On a disposable copy of a real `02_MAIN` (lawfully obtained via `PME_RADIO_IMG`):

```sh
cargo run --release -- decompose "$PME_RADIO_IMG" --out /tmp/p2-verify
```

Confirm:
- (a) `/tmp/p2-verify/report.json` shows `thumb_decompiled > 0` for `02_MAIN`.
- (b) `/tmp/p2-verify/images/02_MAIN/decompiled/thumb_functions.json` has `"format": "pixel-modem-extractor-thumb-functions-v2"` and at least one entry with `body_c`.
- (c) The unified `/tmp/p2-verify/images/02_MAIN/decompiled/decompiled.c` contains Thumb function bodies (sample a few with `grep -c '^void \|^int ' decompiled.c`).
- (d) At least one Thumb function in `decompiled.c` shows a recovered name + `// logs:` / `// file:` plate comment (Phase-1 symbol pipeline lit up for Thumb).

- [ ] **Step 8: Manual verification — Surface B (kill + datamark retry)**

```sh
cargo run --release -- decompose "$PME_RADIO_IMG" --out /tmp/p2-surfaceB \
    --tighten-wall-clock-budget-sec 1
```
Expected: `02_MAIN`'s `thumb_tighten_error` is set in `report.json`; `thumb_decompiled` is 0 or absent; image is **not** marked `failed`; ARM `decompiled.c` is still valid.

- [ ] **Step 9: Manual verification — escape hatch**

```sh
cargo run --release -- decompose "$PME_RADIO_IMG" --out /tmp/p2-no-thumb --no-thumb-decompile
```
Expected: `thumb_functions.json` is asm-only (no `body_c`); `decompiled.c` does not contain Thumb functions (data-marked); StageReport `thumb_enrich` is `skipped`.

- [ ] **Step 10: Manual verification — Phase 1 non-regression**

```sh
cargo run --release -- decompose "$PME_RADIO_IMG" --out /tmp/p2-no-sym --no-symbol-pass
```
Expected: valid Phase-1-shaped tree (only the symbol-pass delta is off; thumb_enrich still runs once after pass 1, populating `body_c` with placeholder names).

- [ ] **Step 11: Commit**

```sh
git add tests/decompose_golden.rs README.md CONTRIBUTING.md
git commit -m "Document Phase-2 Thumb decompilation and assert new report fields"
```

---

## Done criteria (mirrors spec § Done criteria)

Phase 2 is done when:

1. Task 1's investigation finding is committed (success or negative).
2. If success: all Rust gates pass (Task 12 Step 5); the Ghidra e2e suite passes against a real Ghidra (Task 12 Step 6); the manual verification above passes on a real image (Task 12 Steps 7–10); the docs are updated.
3. If negative: the negative-result appendix is committed and a re-spec path is agreed. Tasks 2–12 are not executed.

A negative investigation result is a valid Phase-2 outcome — it closes the question with evidence.
