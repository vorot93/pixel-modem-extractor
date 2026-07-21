# Phase 2.1 — Per-region Thumb tightening (design stub)

Status: **stub — pending brainstorming session**
Parent spec: `docs/superpowers/specs/2026-07-21-thumb-decompilation-phase2-design.md`

## Problem

Phase 2 ships with `thumb_decompiled > 0` unreachable on production `02_MAIN`.
Body-c dormancy has **two independent causes**, both of which Phase 2.1 must
address:

1. **`thumb_enrich` matching bug (gate).** `thumb_enrich` matches by function
   name, but `thumb_functions.json`'s radare2-style names (`thumb_<addr>` /
   `sym.thumb_<addr>`) never align with `decompiled.c`'s Ghidra names
   (`FUN_<addr>` or post-pass-2 recovered names). `body_c` stays empty on any
   image regardless of which mode Ghidra ran in. The Phase 2 spec
   (`docs/superpowers/specs/2026-07-21-thumb-decompilation-phase2-design.md`,
   § Acceptance → thumb_enrich contract) specified **address-based** matching;
   the plan deviated to name-based. This is a prerequisite for any body-c
   population and must land first.

2. **Surface B datamark fallback (production `02_MAIN` only).** The single
   per-image `mode=tighten` invocation triggers Ghidra's overlap-repair spin on
   the larger dense-Thumb regions; Surface B's watch correctly fires after
   ~28 min and falls back to `mode=datamark`, but that data-marks every dense
   region, leaving `thumb_enrich` with no Thumb C bodies in `decompiled.c` to
   populate. Addressed by per-region tightening (the original Phase 2.1
   direction below).

A real Ghidra e2e fixture that triggers Thumb discovery under `ARM:LE:32:v7` is
also required — the current 6-byte fixture doesn't, so today's
`tightened_tame_analysis_dispatchs_tighten_mode` test asserts only mode dispatch
(was renamed from `…_emits_thumb_function` to reflect this). Phase 2.1 must add
a fixture with a mode-switch instruction so the end-to-end Thumb→C path is
actually exercised.

Task 1's investigation (`docs/superpowers/specs/2026-07-21-thumb-decompilation-phase2-findings.md`)
validated the tightened config on the *smallest* of 5 detected dense-Thumb regions
(2 MiB; 0 repair-log lines; 70% coverage). The smallest region does not predict the
behavior of the larger four (4–19 MiB each).

## Direction (to be refined in brainstorming)

**Required, in order:**

- **Lead with the `thumb_enrich` matching fix.** Switch from name-based to
  address-based matching (per the Phase 2 spec). Without this, no amount of
  tightening will deliver `body_c` — the matching gate fires first. Pure Rust,
  well-bounded by the existing `thumb_enrich_populates_body_c` test (which
  today uses a hand-aligned name and will need its assertion flipped to
  address-based).
- **Add a real Ghidra Thumb e2e fixture.** Construct a fixture with a mode-switch
  instruction so Ghidra auto-discovers a Thumb function under `ARM:LE:32:v7`;
  use it to extend the e2e suite beyond mode-dispatch assertions.
- **Then per-region tightening** (the original direction below) to address
  Surface B on production `02_MAIN`.

Per-region tightening remains a candidate (and is required for production
body_c), but it is the third step, not the first — it cannot succeed without
the matching fix above it. Each detected dense-Thumb region gets its own Ghidra
tighten invocation (either as a carved standalone program, or via multiple
`analyzeHeadless` passes over the same project but with per-region
`TightenBudget`s). Regions that converge produce Thumb C in `decompiled.c`;
regions that spin fall back to datamark individually. The smallest region
(Task 1's sample) is known to converge — it alone would deliver non-zero
`body_c` on production, validating the Phase 2 architecture end-to-end.

Alternative directions to consider in brainstorming:

- **Carve each region into a standalone Ghidra program.** Each carve is small enough
  that Ghidra converges cleanly (matches Task 1's sample behavior). Reuses Phase 1's
  ApplySymbols+ExportDecomp toolchain per carve. Highest implementation cost; cleanest
  separation.
- **Bump the log-spam threshold** (100k → 1M+). Quick to try; risk of masking actual
  runaway spin. May or may not help if Ghidra eventually converges on full `02_MAIN`.
- **Disable ClearFlowAndRepairCmd in tighten mode.** Task 1's investigation deferred
  this (Candidate 3, never run). If the spin is concentrated in the repair command
  itself, disabling it (and accepting any over-merge artifacts) might let the larger
  regions converge. Requires empirical investigation.

## Out of scope for the stub

- Concrete approach choice (defer to brainstorming).
- Implementation plan (defer to writing-plans after brainstorming).
- Per-image vs per-region fallback semantics (defer to brainstorming).

## Reference

- Phase 2 spec: `docs/superpowers/specs/2026-07-21-thumb-decompilation-phase2-design.md`
- Phase 2 investigation findings: `docs/superpowers/specs/2026-07-21-thumb-decompilation-phase2-findings.md`
- Phase 2 implementation plan: `docs/superpowers/plans/2026-07-21-thumb-decompilation-phase2.md`
- Production verification report: `.superpowers/sdd/task-12-report.md` (worktree-local)
