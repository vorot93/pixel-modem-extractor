# Phase 2 investigation findings — Thumb decompilation via tightened TameAnalysis

Status: **success**  Date: 2026-07-21
Winner: **Candidate 2** (no data-marks; Aggressive Instruction Finder stays disabled)
Gate decision: **continue to Task 2** (Tasks 2–12 execute).

## Sample

- Source: real `02_MAIN` (Pixel 6 Pro "mustang" radio image), lawfully obtained via
  `PME_RADIO_IMG` (not committed; only its structure was inspected).
- 02_MAIN load address: `0x40000000` (from `manifest.json`; `e.load_addr`).
- The detector (`thumb_regions`, entropy ≥ 6.5, ≥ 1 MiB) found **5** dense-Thumb regions
  in this 02_MAIN, totaling ~42 MiB. The five ranges (absolute load addresses):

  | # | Range (abs) | Size (MiB) |
  |---|-------------|------------|
  | 1 | `0x40e10000`–`0x41020000` | 2.06 |
  | 2 | `0x410a0000`–`0x423c0000` | 19.12 |
  | 3 | `0x423d0000`–`0x427e0000` | 4.06 |
  | 4 | `0x42860000`–`0x43020000` | 7.75 |
  | 5 | `0x43030000`–`0x43920000` | 8.94 |

- **Sample carved: region #1** — `0x40e10000`–`0x41020000`, **2,162,688 bytes** (2.06 MiB,
  the smallest detected region), at byte offset `0xe10000` in `02_MAIN`. Imported as a
  standalone binary at base address `0x40e10000`.
- `N_r2` (baseline radare2 function count): **11,023** — radare2 6.1.4,
  `r2 -a arm -b 16 -m 0x40e10000 -q -c 'aaa;aflj'`, 8.7 s wall-clock.

## Per-candidate measurements

| # | Candidate | N_ghidra | Wall-clock | Repair-log lines | Spot-checks | Verdict |
|---|-----------|---------:|-----------:|-----------------:|:-----------:|---------|
| 1 | Status quo control (data-mark whole region) | 0 | 6 s | 0 | n/a | wiring confirmed — 0 functions as expected (region marked as data) |
| 2 | No data-marks (TameAnalysis disables AIF only) | **7,728** | **80 s** | **0** | **3/3 PASS** | **SUCCESS — all stop conditions met** |
| 3 | No data-marks + disable `ClearFlowAndRepairCmd` | — | — | — | — | not run — candidate 2 already passed |
| 4 | No data-marks + cap repair | — | — | — | — | not run — candidate 2 already passed |

Coverage: `N_ghidra / N_r2 = 7,728 / 11,023 = 0.70` (threshold: ≥ 0.50).

### Stop-condition check (Candidate 2)

- `N_ghidra ≥ 0.5 × N_r2`: `7,728 ≥ 5,512` ✓ (ratio 0.70).
- Wall-clock < 30 min on the sample: `80 s` ✓.
- < 1000 repair-related log lines: `0` ✓ — a broad grep for
  `repair|overlap|clear.*flow` across stdout and stderr returns 0 hits.
- All 3 spot-checks produce non-empty C: `3/3` ✓ — every function header
  (`// FUN_<addr> @ <addr>`) in `decompiled.c` is followed by a real C body;
  `0` `<decompilation failed>` markers across all 7,728 bodies.

### Spot-check detail (3/3 PASS; shapes paraphrased — no firmware bytes committed)

Three deterministic-random functions (seed `0xC0DEFE5`) chosen from the
candidate-2 `functions.json`. The classifier required a parenthesized parameter
list, opening `{`, closing `}`, and ≥ 1 semicolon-terminated statement.

1. `FUN_40feb32a` @ `0x40feb32a` — `void` return, 2 params; 5 non-comment C lines,
   2 statements.
2. `FUN_40f94580` @ `0x40f94580` — `void` return, pointer + int params;
   11 non-comment lines, 8 statements.
3. `FUN_40fa58d6` @ `0x40fa58d6` — `int` (4-byte) return, 1 pointer param;
   6 non-comment lines, 3 statements.

## Winning configuration: Candidate 2 (no data-marks)

The investigation did **not** need to disable `ClearFlowAndRepairCmd` or any other
analysis option beyond the Aggressive Instruction Finder already disabled by
today's `TameAnalysis.java`. On the smallest dense-Thumb region of a real
`02_MAIN`, disabling AIF alone was sufficient for Ghidra 12.1.2 to converge in
80 s with 0 repair-log lines and 70 % coverage of radare2's function count.

### Exact Ghidra-12 analysis option names disabled by the winning config

Both already live in `src/ghidra/TameAnalysis.java`'s `DISABLE` array; both
confirmed present in this Ghidra 12.1.2 install — the script's `println` for
each fired on every candidate run:

- `"ARM Aggressive Instruction Finder"`
- `"Aggressive Instruction Finder"`

No other analysis option is touched by `mode=tighten`. The Phase-2
investigation did **not** need to resolve the `ClearFlowAndRepairCmd` option
name (Candidate 3 was never reached). Task 5 sets `TIGHTEN_EXTRA = {}` (empty).

### Literal `mode=tighten` Java body (paste verbatim into `TameAnalysis.java`)

This is the body Task 5 puts under the `if (mode.equals("tighten")) { … }` branch
of the mode-dispatching `run()`. `TIGHTEN_EXTRA` is the empty array — included
here for shape symmetry with Task 5's template, but its content is empty:

```java
// Phase 2 `mode=tighten` body — sourced verbatim from the Phase-2 investigation
// (docs/superpowers/specs/2026-07-21-thumb-decompilation-phase2-findings.md).
// On the smallest dense-Thumb region of a real 02_MAIN (2.06 MiB sample,
// N_r2 = 11023), disabling the Aggressive Instruction Finder alone caused
// Ghidra 12.1.2 to converge in 80 s with 0 ClearFlowAndRepairCmd log lines
// and 70 % coverage (N_ghidra = 7728). No additional analysis options needed
// to be disabled; the dense-Thumb region is NOT data-marked in this mode.
private static final String[] TIGHTEN_EXTRA = {
    // empty — investigation found no extra option needed disabling.
};

// Inside run(), after the shared DISABLE loop:
Options opts = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
for (String name : TIGHTEN_EXTRA) {
    if (opts.contains(name)) {
        opts.setBoolean(name, false);
        println("TameAnalysis: disabled '" + name + "'");
    }
}
```

The shared `DISABLE` loop (already in today's `TameAnalysis.java`) runs
unconditionally for both modes:

```java
Options opts = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
for (String name : DISABLE) {
    if (opts.contains(name)) {
        opts.setBoolean(name, false);
        println("TameAnalysis: disabled '" + name + "'");
    }
}
```

## Notes for production (Task 11 / Surface B verification)

- **Sample-size caveat.** The sample is the *smallest* of 5 detected dense-Thumb
  regions in this 02_MAIN (2.06 MiB out of ~42 MiB). The other four regions
  (4–19 MiB each) are larger and may contain more varied Thumb patterns.
  0 repair-log lines and 80 s wall-clock on this sample is a strong positive
  signal but is not, by itself, a guarantee that the full ~87 MB `02_MAIN`
  converges as cleanly. Task 11 (production verification) and the spec's
  Surface B both address this.
- **Spec mitigation already in place.** Surface B (spec § Error handling →
  Surface B) implements a per-image wall-clock + log-spam watch with kill +
  `mode=datamark` retry fallback. If the full `02_MAIN` spins at runtime where
  the sample did not, the watch fires, the image is re-spawned with today's
  Phase-1 behavior, and `thumb_tighten_error` lands in `report.json` without
  marking the image `failed`. The investigation does not need to solve that
  case — only to find a config that converges on a real sample, which it did.
- **Decompiler p-code warnings** on the carved sample are sample-boundary
  artifacts (12 instances in candidate 2's log): functions whose disassembly
  flow references addresses outside the 2 MiB carve (e.g. `4101ffe0` references
  `41020000`, one byte past the carve's end). These do not affect the
  spot-checks (the sampled functions decompiled cleanly) and would not arise
  on full `02_MAIN` — they are a property of carving a region out, not of the
  candidate config.
- **radare2 vs Ghidra count delta.** radare2 reports 11,023 functions vs Ghidra's
  7,728. radare2's `aaa` is more aggressive at splitting at every prologue
  without overlap repair; some of the delta is over-splitting by r2 rather than
  under-discovery by Ghidra. The 50 % threshold in the stop conditions is
  intentionally lenient for this reason; the 70 % observed is comfortably
  above it.

## Artifacts not committed (scratch)

Per the project's ground rules, none of these were committed: the carved
`/tmp/thumb_sample.bin`, the scratch carve helper (`/tmp/carve_sample.rs`), the
per-candidate Ghidra project trees under `/tmp/pme-task1/cand{1..4}/`, the
scratch `decompiled.c` / `functions.json` outputs, the candidate run script
(`/tmp/pme-task1/run_candidate.sh`), and the spot-check script
(`/tmp/pme-task1/spotcheck.py`). Only this findings doc is committed.
