# Phase 1 — Readable decompiled code: close the symbol loop

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the symbol loop in `decompose` so the recovered function names and inline evidence land in Ghidra's decompiled C during a second analyzeHeadless pass (instead of being text-substituted afterward).

**Architecture:** Two Ghidra passes per image on `decompose`. Pass 1 = today's analyze + export inventory. Between passes, Rust builds a `symbol_map.json` from pass-1 outputs using today's symbolicate logic refactored into a pure builder. Pass 2 = `analyzeHeadless -process` on the same project, runs a new `ApplySymbols.java` post-script (renames functions, sets plate comments), then re-runs `ExportDecomp.java` to regenerate `decompiled.c` with names + comments baked in. Fidelity-first: no lossy decompiler options; symbolicate criteria unchanged.

**Tech stack:** Rust 2024 edition; `clap` 4; `serde`/`serde_json`; `thiserror`; Ghidra headless (Java post-scripts); `radare2`.

## Global constraints

- Latest stable Rust, edition 2024.
- `cargo fmt --all --check` clean.
- `cargo clippy --all-targets --all-features -- -D warnings` clean (warnings are errors).
- `cargo test --all-targets` green.
- New code is Apache-2.0 compatible.
- **No proprietary data in the repo** — only magic numbers / offsets / structure. Extraction output, decompiled C, and golden trees are derived artifacts and stay out of git.
- **Fidelity over readability when in conflict.** No lossy decompiler options; symbolicate fail-closed criteria unchanged (only `__func__` yields a rename; token matches stay `guess_…`; everything else is comments).
- Inline unit tests next to code; env-gated golden integration tests skip cleanly when env vars unset or inputs absent.
- Commit messages: short imperative subjects, capitalized, no trailing period.

---

## Task 1: Refactor `symbolicate_image` into `build_map` + `finalize_image`

**Files:**
- Modify: `src/symbolicate.rs:725-814` (split `symbolicate_image`)

**Interfaces:**
- Produces:
  - `fn build_map(image_dir: &Path, image_label: &str, tokens: &HashMap<u32, String>, manifest: &Path) -> Result<Vec<Symbol>>` (private) — pure; no file writes; today's recovery logic.
  - `fn finalize_image(image_dir: &Path, image_label: &str, symbols: &[Symbol], opts: &FinalizeOpts) -> Result<PathBuf>` (private) — does today's `rewrite_functions_json` + `rewrite_text_files` + `write_symbols_json`. `FinalizeOpts` is a small struct with a single field `rewrite_decompiled_c: bool` for now (more fields arrive in later tasks).
  - `fn symbolicate_image(...)` stays as a thin wrapper that calls both, preserving today's external behavior.

- [ ] **Step 1: Write the failing tests**

Add to the existing `#[cfg(test)] mod tests` block in `src/symbolicate.rs`:

```rust
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

    let symbols = build_map(
        &root.join("images/02_MAIN"),
        "02_MAIN",
        &tokmap,
        &manifest,
    )
    .unwrap();

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
    let opts = FinalizeOpts { rewrite_decompiled_c: true };
    let path = finalize_image(&root.join("images/02_MAIN"), "02_MAIN", &symbols, &opts).unwrap();
    assert!(path.ends_with("symbols.json"));
    assert!(dec.join("symbols.json").exists());
    // functions.json was rewritten with original_name.
    let v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dec.join("functions.json")).unwrap()).unwrap();
    assert_eq!(v[0]["name"], "real");
    assert_eq!(v[0]["original_name"], "FUN_10");
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib symbolicate::tests::build_map_returns_symbols_without_writing_files symbolicate::tests::finalize_image_writes_symbols_json_when_given_symbols`
Expected: FAIL — `cannot find function 'build_map'` and `cannot find function 'finalize_image'` / `cannot find type 'FinalizeOpts'`.

- [ ] **Step 3: Implement `build_map`, `finalize_image`, and `FinalizeOpts`**

In `src/symbolicate.rs`, replace the body of `symbolicate_image` (currently at `src/symbolicate.rs:725-814`) with three items. The exact replacement:

```rust
/// Tunable parameters for `finalize_image`. Today a single flag controls whether
/// `decompiled.c` / `disasm.lst` are text-rewritten; on the `decompose` two-pass
/// path (Phase 1+), pass 2 regenerates `decompiled.c` and the rewrite is skipped.
pub struct FinalizeOpts {
    pub rewrite_decompiled_c: bool,
}

/// Pure: build the per-image `Symbol` set from pass-1 outputs. No file writes.
fn build_map(
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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib symbolicate::`
Expected: PASS — all symbolicate tests including the two new ones.

- [ ] **Step 5: Run the full lint + format gate**

Run: `cargo fmt --all --check && cargo clippy --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add src/symbolicate.rs
git commit -m "Split symbolicate_image into build_map and finalize_image"
```

---

## Task 2: Provenance fix — source `original_name` from the `Symbol` record

**Files:**
- Modify: `src/symbolicate.rs` — `rewrite_functions_json` (currently `src/symbolicate.rs:634-705`).

**Why:** After Phase 1's pass 2 regenerates `functions.json` with recovered names baked in, today's `rewrite_functions_json` would record the *recovered* name as `original_name` (corrupting provenance). Source `original_name` from the `Symbol` record instead — the Symbol preserves it.

**Interfaces:** None new.

- [ ] **Step 1: Write the failing test**

Add to `src/symbolicate.rs` `#[cfg(test)] mod tests`:

```rust
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --lib symbolicate::tests::rewrite_functions_json_keeps_symbol_original_name_when_name_already_renamed`
Expected: FAIL — `assert_eq! failed: "FUN_10" != "real"` (the current code reads `obj["name"]` into `original_name`).

- [ ] **Step 3: Fix `rewrite_functions_json`**

In `src/symbolicate.rs`, locate the closure body inside `rewrite_functions_json` (currently `src/symbolicate.rs:641-675`). Replace these two lines inside the `let Some(sym) = by_addr.get(&addr) else { continue; };` block:

Current:
```rust
            let orig = obj.get("name").cloned().unwrap_or(serde_json::Value::Null);
            obj.insert("original_name".into(), orig);
```

Replacement:
```rust
            // Source original_name from the Symbol record, not from obj["name"]:
            // on the Phase-1 two-pass path, obj["name"] already holds the
            // recovered name (pass 2 renamed in-program before regenerating
            // functions.json). The Symbol preserves the true original.
            obj.insert(
                "original_name".into(),
                serde_json::Value::String(sym.original_name.clone()),
            );
```

- [ ] **Step 4: Run the full symbolicate test suite**

Run: `cargo test --lib symbolicate::`
Expected: PASS — the new test passes; `rewrite_functions_json_sets_name_and_annotations` still passes (its fixture has matching name/original_name so the behavior is unchanged for it).

- [ ] **Step 5: Run the full lint + format gate**

Run: `cargo fmt --all --check && cargo clippy --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add src/symbolicate.rs
git commit -m "Source functions.json original_name from Symbol record"
```

---

## Task 3: Add `symbolicate::write_symbol_map` and thread `Opts.rewrite_decompiled_c` through the standalone subcommand

**Files:**
- Modify: `src/symbolicate.rs` — add `write_symbol_map`; add field to `Opts`.
- Modify: `src/cli.rs:228-232` — initialize the new `Opts` field.

**Interfaces:**
- Produces:
  - `pub fn write_symbol_map(out_path: &Path, image_label: &str, symbols: &[Symbol], source_sha256: &str, functions_sha256: &str) -> Result<PathBuf>` — serializes the schema in `docs/superpowers/specs/2026-07-21-readable-decompiled-code-phase1-design.md` ("New: `<out>/ghidra/symbol_maps/<label>.json`").
  - `pub struct Opts { pub token_db: Option<PathBuf>, pub rewrite_decompiled_c: bool }` — the public Opts gains a new required field. The standalone `symbolicate` subcommand always sets it to `true`; the `decompose` path (later task) sets it to `false`.

- [ ] **Step 1: Write the failing tests**

Add to `src/symbolicate.rs` `#[cfg(test)] mod tests`:

```rust
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
    let path = write_symbol_map(&dir.join("m.json"), "02_MAIN", &symbols, "abc", "def").unwrap();

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
    assert_eq!(syms[0]["annotations"][0], "logs: \"RRC Reestab (%d)\" [LTE_RRC_METRICS]");
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib symbolicate::tests::write_symbol_map_round_trips symbolicate::tests::finalize_image_with_rewrite_false_leaves_decompiled_c_untouched`
Expected: FAIL — `cannot find function 'write_symbol_map'`.

- [ ] **Step 3: Implement `write_symbol_map`**

In `src/symbolicate.rs`, add immediately after the `write_symbols_json` function (currently ends at `src/symbolicate.rs:598`):

```rust
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
```

- [ ] **Step 4: Add `rewrite_decompiled_c` to `symbolicate::Opts`**

In `src/symbolicate.rs`, change the existing `pub struct Opts` (currently `src/symbolicate.rs:15-17`):

Current:
```rust
pub struct Opts {
    pub token_db: Option<PathBuf>,
}
```

Replacement:
```rust
pub struct Opts {
    pub token_db: Option<PathBuf>,
    /// Whether `decompiled.c` / `disasm.lst` are text-rewritten in place. The
    /// standalone `symbolicate` subcommand sets `true`; the `decompose` two-pass
    /// path (which regenerates `decompiled.c` from Ghidra in pass 2) sets `false`.
    pub rewrite_decompiled_c: bool,
}
```

- [ ] **Step 5: Thread `rewrite_decompiled_c` through `symbolicate::run`**

In `src/symbolicate.rs`, change the body of `run` (currently `src/symbolicate.rs:819-846`) so it passes the opt into `symbolicate_image`. Concretely, replace the line:

Current:
```rust
        let out = symbolicate_image(&dir, &label, &tokens, &manifest)?;
```

Replacement:
```rust
        let symbols = build_map(&dir, &label, &tokens, &manifest)?;
        let out = finalize_image(
            &dir,
            &label,
            &symbols,
            &FinalizeOpts {
                rewrite_decompiled_c: opts.rewrite_decompiled_c,
            },
        )?;
```

- [ ] **Step 6: Update `src/cli.rs` for the new required `Opts` field**

In `src/cli.rs:228-232`, change the `Symbolicate` match arm.

Current:
```rust
        Commands::Symbolicate { path, token_db } => {
            let opts = crate::symbolicate::Opts { token_db };
            let root = crate::symbolicate::run(&path, &opts)?;
            println!("symbolicated -> {}", root.display());
        }
```

Replacement:
```rust
        Commands::Symbolicate { path, token_db } => {
            let opts = crate::symbolicate::Opts {
                token_db,
                rewrite_decompiled_c: true,
            };
            let root = crate::symbolicate::run(&path, &opts)?;
            println!("symbolicated -> {}", root.display());
        }
```

- [ ] **Step 7: Update `tests/symbolicate_golden.rs` for the new `Opts` field**

In `tests/symbolicate_golden.rs:19-23`:

Current:
```rust
    pixel_modem_extractor::symbolicate::run(
        &root,
        &pixel_modem_extractor::symbolicate::Opts { token_db },
    )
    .unwrap();
```

Replacement:
```rust
    pixel_modem_extractor::symbolicate::run(
        &root,
        &pixel_modem_extractor::symbolicate::Opts {
            token_db,
            rewrite_decompiled_c: true,
        },
    )
    .unwrap();
```

Also in `src/decompose.rs:752-772` (the `symbolicate_stage_runs_over_a_crafted_tree` test), the existing `crate::symbolicate::Opts { token_db: None }` must become:

```rust
        crate::symbolicate::Opts {
            token_db: None,
            rewrite_decompiled_c: true,
        }
```

- [ ] **Step 8: Run all symbolicate tests + the touched call sites**

Run: `cargo test --lib symbolicate:: && cargo test --test symbolicate_golden && cargo test --lib decompose::tests::symbolicate_stage_runs_over_a_crafted_tree`
Expected: PASS — all green (symbolicate_golden skips without env vars but still compiles).

- [ ] **Step 9: Run the full lint + format + test gate**

Run: `cargo fmt --all --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test --all-targets`
Expected: clean / green.

- [ ] **Step 10: Commit**

```bash
git add src/symbolicate.rs src/cli.rs tests/symbolicate_golden.rs src/decompose.rs
git commit -m "Add symbolicate::write_symbol_map and rewrite_decompiled_c opt"
```

---

## Task 4: Add `pass2_applied` / `pass2_error` to `decompile::ImageResult` and `decompose::ImageReport`

**Files:**
- Modify: `src/decompile.rs:212-219` (`ImageResult` struct).
- Modify: `src/decompose.rs:24-36` (`ImageReport` struct).
- Modify: `src/decompose.rs:39-62` (`ImageReport::from_result`).
- Modify: `src/decompose.rs:485-505` (the existing test fixture in `report_serializes_and_ok_reflects_failure`).

**Interfaces:**
- Produces: two new optional fields on both structs, both `#[serde(skip_serializing_if = "Option::is_none")]`. `from_result` copies them through.

- [ ] **Step 1: Add the fields to `decompile::ImageResult`**

In `src/decompile.rs:212-219`, replace the `ImageResult` struct definition.

Current:
```rust
#[derive(Debug)]
pub struct ImageResult {
    pub label: String,
    pub outcome: ImageOutcome,
    pub thumb_functions: Option<usize>,
    /// Reason-only Thumb/radare2 failure text; `label` already identifies the image.
    pub thumb_error: Option<String>,
}
```

Replacement:
```rust
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
}
```

This temporarily breaks every existing construction of `ImageResult`. Locate the construction in `decompile.rs` (currently `src/decompile.rs:503-513`) and add the two fields set to `None`:

Current:
```rust
        image_results = results
            .into_iter()
            .map(
                |(label, outcome, thumb_functions, thumb_error)| ImageResult {
                    label,
                    outcome,
                    thumb_functions,
                    thumb_error,
                },
            )
            .collect();
```

Replacement:
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
                },
            )
            .collect();
```

- [ ] **Step 2: Add the fields to `decompose::ImageReport` and thread through `from_result`**

In `src/decompose.rs:24-36`, add the two new fields to `ImageReport`:

Current:
```rust
#[derive(Debug, Serialize)]
pub struct ImageReport {
    pub image: String,
    pub status: &'static str, // "analyzed" | "failed"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub functions: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumb_functions: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumb_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit: Option<i32>,
}
```

Replacement:
```rust
#[derive(Debug, Serialize)]
pub struct ImageReport {
    pub image: String,
    pub status: &'static str, // "analyzed" | "failed"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub functions: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumb_functions: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumb_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pass2_applied: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pass2_error: Option<String>,
}
```

Update `from_result` in `src/decompose.rs:39-62`. Each match arm gains two field initializers.

Current (first arm):
```rust
        ImageOutcome::Analyzed(n) => ImageReport {
            image: r.label.clone(),
            status: if r.thumb_error.is_some() {
                "failed"
            } else {
                "analyzed"
            },
            functions: Some(n),
            thumb_functions: r.thumb_functions,
            thumb_error: r.thumb_error.clone(),
            exit: None,
        },
```

Replacement:
```rust
        ImageOutcome::Analyzed(n) => ImageReport {
            image: r.label.clone(),
            status: if r.thumb_error.is_some() {
                "failed"
            } else {
                "analyzed"
            },
            functions: Some(n),
            thumb_functions: r.thumb_functions,
            thumb_error: r.thumb_error.clone(),
            exit: None,
            pass2_applied: r.pass2_applied,
            pass2_error: r.pass2_error.clone(),
        },
```

Current (second arm):
```rust
        ImageOutcome::Failed(code) => ImageReport {
            image: r.label.clone(),
            status: "failed",
            functions: None,
            thumb_functions: r.thumb_functions,
            thumb_error: r.thumb_error.clone(),
            exit: Some(code),
        },
```

Replacement:
```rust
        ImageOutcome::Failed(code) => ImageReport {
            image: r.label.clone(),
            status: "failed",
            functions: None,
            thumb_functions: r.thumb_functions,
            thumb_error: r.thumb_error.clone(),
            exit: Some(code),
            pass2_applied: r.pass2_applied,
            pass2_error: r.pass2_error.clone(),
        },
```

- [ ] **Step 3: Update the existing `decompose::tests` fixture that constructs `ImageReport`**

In `src/decompose.rs:485-505` (inside `report_serializes_and_ok_reflects_failure`), each `ImageReport { ... }` literal gains `pass2_applied: None, pass2_error: None`. There are two such literals (the `02_MAIN` and `04_VSS` cases). Add the two fields to each.

- [ ] **Step 4: Run the full test suite**

Run: `cargo test --all-targets`
Expected: PASS — all green; the new fields are skipped on serialization when `None`, so the existing `assert!` statements on the JSON shape still hold.

- [ ] **Step 5: Run the full lint + format gate**

Run: `cargo fmt --all --check && cargo clippy --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add src/decompile.rs src/decompose.rs
git commit -m "Add pass2_applied and pass2_error to image reports"
```

---

## Task 5: Create `src/ghidra/ApplySymbols.java`

**Files:**
- Create: `src/ghidra/ApplySymbols.java`
- Modify: `src/decompile.rs:18-19` — add `include_str!` constant for the new script.
- Modify: `src/decompile.rs:375-378` (the script-copy block in `run_report`) — also write the new script.

**Why:** Pass 2 of `run_two_pass` invokes this script. No Rust test runs it alone — it's exercised end-to-end via `tests/decompile_golden.rs` in Task 7.

**Interfaces:** The script's stdout summary line is parsed by `parse_pass2_summary` (added in Task 6). Format: `ApplySymbols: image=<image> applied N names, M plate comments, skipped K`.

- [ ] **Step 1: Create the Java file**

Create `src/ghidra/ApplySymbols.java` with this exact content:

```java
// ApplySymbols.java — Ghidra headless post-script for pixel-modem-extractor.
// Arg[0] = absolute path to a symbol_map.json produced by symbolicate::write_symbol_map.
// Renames functions and sets plate comments from the recovered evidence, so the
// subsequent ExportDecomp.java pass emits decompiled C with names + inline
// evidence baked in. Fail-closed per symbol: a missing function, an invalid
// name, or a name collision is logged via println and skipped. The script
// always returns normally so ExportDecomp still runs and decompiled.c is
// complete.
//@category PixelModem
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonArray;
import com.google.gson.JsonParser;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.SourceType;

import java.io.File;
import java.io.FileReader;

public class ApplySymbols extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("ApplySymbols: missing symbol_map.json argument");
            summarize("?", 0, 0, 0);
            return;
        }
        File mapFile = new File(args[0]);
        if (!mapFile.exists()) {
            println("ApplySymbols: symbol map not found: " + mapFile.getAbsolutePath());
            summarize("?", 0, 0, 0);
            return;
        }

        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();

        JsonObject root;
        try (FileReader r = new FileReader(mapFile)) {
            root = JsonParser.parseReader(r).getAsJsonObject();
        }
        String image = root.has("image") ? root.get("image").getAsString() : "?";
        JsonArray symbols = root.has("symbols") ? root.getAsJsonArray("symbols") : new JsonArray();

        int applied = 0;
        int comments = 0;
        int skipped = 0;
        for (JsonElement el : symbols) {
            if (!el.isJsonObject()) { skipped++; continue; }
            JsonObject sym = el.getAsJsonObject();
            if (!sym.has("entry") || !sym.get("entry").isJsonPrimitive()) {
                skipped++;
                continue;
            }
            long entryAddr;
            try {
                entryAddr = parseAddr(sym.get("entry").getAsString());
            } catch (Exception e) {
                println("ApplySymbols: bad entry " + sym.get("entry") + ": " + e.getMessage());
                skipped++;
                continue;
            }
            Address a;
            try {
                a = toAddr(entryAddr);
            } catch (Exception e) {
                println("ApplySymbols: cannot resolve " + sym.get("entry") + ": " + e.getMessage());
                skipped++;
                continue;
            }

            // Plate comment is independent of whether a function exists at the
            // address — it still anchors the evidence for the decompiler.
            if (sym.has("annotations") && sym.get("annotations").isJsonArray()) {
                JsonArray anns = sym.getAsJsonArray("annotations");
                StringBuilder b = new StringBuilder();
                for (JsonElement an : anns) {
                    if (!an.isJsonPrimitive()) continue;
                    if (b.length() > 0) b.append("\n// ");
                    b.append(an.getAsString());
                }
                if (b.length() > 0) {
                    try {
                        listing.setPlateComment(a, b.toString());
                        comments++;
                    } catch (Exception e) {
                        println("ApplySymbols: could not set plate comment at " + a + ": " + e.getMessage());
                    }
                }
            }

            Function fn = fm.getFunctionAt(a);
            if (fn == null) {
                println("ApplySymbols: no function at " + a + " (entry may have moved)");
                skipped++;
                continue;
            }
            if (!sym.has("name") || sym.get("name").isJsonNull()) {
                continue; // no rename — Tier::None
            }
            String name = sym.get("name").getAsString();
            SourceType source = SourceType.ANALYSIS;
            if (sym.has("tier") && sym.get("tier").isJsonPrimitive()
                    && "recovered".equals(sym.get("tier").getAsString())) {
                source = SourceType.USER;
            }
            try {
                fn.setName(name, source);
                applied++;
            } catch (Exception e) {
                println("ApplySymbols: could not rename " + a + " to " + name + ": " + e.getMessage());
                skipped++;
            }
        }
        summarize(image, applied, comments, skipped);
    }

    private void summarize(String image, int applied, int comments, int skipped) {
        println("ApplySymbols: image=" + image + " applied " + applied
                + " names, " + comments + " plate comments, skipped " + skipped);
    }

    private static long parseAddr(String s) throws NumberFormatException {
        String t = s.trim();
        if (t.startsWith("0x") || t.startsWith("0X")) t = t.substring(2);
        return Long.parseUnsignedLong(t, 16);
    }
}
```

- [ ] **Step 2: Add `include_str!` for the new script in `src/decompile.rs`**

In `src/decompile.rs:18-19`, alongside the existing `EXPORT_DECOMP_JAVA` / `TAME_ANALYSIS_JAVA` constants.

Current:
```rust
const EXPORT_DECOMP_JAVA: &str = include_str!("ghidra/ExportDecomp.java");
const TAME_ANALYSIS_JAVA: &str = include_str!("ghidra/TameAnalysis.java");
```

Replacement:
```rust
const EXPORT_DECOMP_JAVA: &str = include_str!("ghidra/ExportDecomp.java");
const TAME_ANALYSIS_JAVA: &str = include_str!("ghidra/TameAnalysis.java");
const APPLY_SYMBOLS_JAVA: &str = include_str!("ghidra/ApplySymbols.java");
```

- [ ] **Step 3: Write the new script to the kit's `scripts/` dir in `run_report`**

In `src/decompile.rs:375-378`, add a line that also writes `ApplySymbols.java`.

Current:
```rust
    std::fs::write(scripts.join("TameAnalysis.java"), TAME_ANALYSIS_JAVA)?;
    std::fs::write(scripts.join("ExportDecomp.java"), EXPORT_DECOMP_JAVA)?;
```

Replacement:
```rust
    std::fs::write(scripts.join("TameAnalysis.java"), TAME_ANALYSIS_JAVA)?;
    std::fs::write(scripts.join("ExportDecomp.java"), EXPORT_DECOMP_JAVA)?;
    std::fs::write(scripts.join("ApplySymbols.java"), APPLY_SYMBOLS_JAVA)?;
```

- [ ] **Step 4: Verify build + format**

Run: `cargo build && cargo fmt --all --check && cargo clippy --all-targets --all-features -- -D warnings`
Expected: clean. (No behavior change yet — just ships a new script in the kit.)

- [ ] **Step 5: Commit**

```bash
git add src/ghidra/ApplySymbols.java src/decompile.rs
git commit -m "Add ApplySymbols.java post-script to the Ghidra kit"
```

---

## Task 6: Add `decompile::run_two_pass`

**Files:**
- Modify: `src/decompile.rs` — add `run_two_pass`, `headless_process_args`, `parse_pass2_summary`.

**Interfaces:**
- Produces:
  - `pub fn run_two_pass(modem_bin: &Path, opts: &Opts, out: &Path, symbol_maps: &HashMap<String, PathBuf>) -> Result<DecompileReport>` — runs today's `run_report` (pass 1), then for every image whose `symbol_maps.get(&label)` exists and has at least one non-null `name`, runs a second `analyzeHeadless -process` invocation with `ApplySymbols.java` + `ExportDecomp.java` post-scripts. Per-image pass-2 failures are recorded into `ImageResult.pass2_error`, not propagated.
  - `fn headless_process_args(root: &str, label: &str, map_path: &Path) -> Vec<String>` (private) — argument vector for the `-process` invocation.
  - `fn parse_pass2_summary(stdout: &str) -> Option<usize>` (private) — extracts `N` from `ApplySymbols: image=... applied N names, ...`.

- [ ] **Step 1: Write failing unit tests**

Add to `src/decompile.rs` `#[cfg(test)] mod tests`:

```rust
#[test]
fn headless_process_args_wires_process_mode_and_post_scripts() {
    let args = headless_process_args(
        "/out",
        "02_MAIN",
        std::path::Path::new("/out/ghidra/symbol_maps/02_MAIN.json"),
    );
    // <projectDir> <projectName> -process <label> -noanalysis -scriptPath <root>/scripts
    assert_eq!(args[0], "/out/ghidra_project");
    assert_eq!(args[1], "pixel-modem");
    let proc = args.iter().position(|a| a == "-process").unwrap();
    assert_eq!(args[proc + 1], "02_MAIN");
    let na = args.iter().position(|a| a == "-noanalysis").unwrap();
    assert!(na > proc);
    let sp = args.iter().position(|a| a == "-scriptPath").unwrap();
    assert_eq!(args[sp + 1], "/out/scripts");
    // ApplySymbols.java comes before ExportDecomp.java, with map path between.
    let ps1 = args.iter().position(|a| a == "-postScript").unwrap();
    assert_eq!(args[ps1 + 1], "ApplySymbols.java");
    assert_eq!(args[ps1 + 2], "/out/ghidra/symbol_maps/02_MAIN.json");
    // Second -postScript is ExportDecomp.java with the per-image export dir.
    let ps2 = args.iter().rposition(|a| a == "-postScript").unwrap();
    assert!(ps2 > ps1);
    assert_eq!(args[ps2 + 1], "ExportDecomp.java");
    assert_eq!(args[ps2 + 2], "/out/export/02_MAIN");
}

#[test]
fn parse_pass2_summary_reads_applied_count() {
    let stdout = "...\nApplySymbols: image=02_MAIN applied 42 names, 7 plate comments, skipped 3\n";
    assert_eq!(parse_pass2_summary(stdout), Some(42));
    // Missing / malformed summary -> None (caller treats as "no info").
    assert_eq!(parse_pass2_summary("nothing useful\n"), None);
    assert_eq!(parse_pass2_summary(""), None);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib decompile::tests::headless_process_args_wires_process_mode_and_post_scripts decompile::tests::parse_pass2_summary_reads_applied_count`
Expected: FAIL — `cannot find function 'headless_process_args'`.

- [ ] **Step 3: Implement the three functions**

Add to `src/decompile.rs`, immediately before the existing `pub fn run` (currently at `src/decompile.rs:571`):

```rust
use std::collections::HashMap;

/// The `analyzeHeadless` argument vector for pass 2 of `run_two_pass`. Runs in
/// `-process` mode on the existing project so there is no re-import and no
/// re-analysis: `ApplySymbols.java` renames functions and sets plate comments,
/// then `ExportDecomp.java` regenerates `decompiled.c` with the new names and
/// comments baked in.
fn headless_process_args(root: &str, label: &str, map_path: &Path) -> Vec<String> {
    vec![
        format!("{root}/ghidra_project"),
        "pixel-modem".to_string(),
        "-process".to_string(),
        label.to_string(),
        "-noanalysis".to_string(),
        "-scriptPath".to_string(),
        format!("{root}/scripts"),
        "-postScript".to_string(),
        "ApplySymbols.java".to_string(),
        map_path.to_string_lossy().into_owned(),
        "-postScript".to_string(),
        "ExportDecomp.java".to_string(),
        format!("{root}/export/{label}"),
    ]
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

/// Two-pass decompile. Pass 1 is exactly today's `run_report`. Pass 2 runs only
/// for images whose `symbol_maps.get(&label)` exists, points at a readable file,
/// and contains at least one non-null `name`. Per-image pass-2 failures are
/// recorded into `ImageResult.pass2_error`, not propagated — pass 1 already
/// produced a valid `decompiled.c`.
pub fn run_two_pass(
    modem_bin: &Path,
    opts: &Opts,
    out: &Path,
    symbol_maps: &HashMap<String, PathBuf>,
) -> Result<DecompileReport> {
    let mut report = run_report(modem_bin, opts, out)?;
    if !opts.run {
        return Ok(report);
    }
    let install = find_ghidra(opts)?;
    let java_home =
        resolve_java_home(std::env::var_os("JAVA_HOME"), install.ghidra_run.as_deref());
    let root = std::fs::canonicalize(out)?;
    let root_str = root.to_string_lossy().into_owned();

    for ir in &mut report.images {
        let Some(map_path) = symbol_maps.get(&ir.label) else {
            continue;
        };
        if !map_path.exists() {
            continue;
        }
        // Skip pass 2 when the map has no non-null names — pass 1's decompiled.c
        // is already fine for that image.
        let map_str = std::fs::read_to_string(map_path).unwrap_or_default();
        let map_json: serde_json::Value =
            serde_json::from_str(&map_str).unwrap_or(serde_json::Value::Null);
        let has_names = map_json["symbols"]
            .as_array()
            .map(|arr| arr.iter().any(|s| !s["name"].is_null()))
            .unwrap_or(false);
        if !has_names {
            continue;
        }

        tracing::info!("ghidra: pass 2 symbolication for {}", ir.label);
        let args = headless_process_args(&root_str, &ir.label, map_path);
        let output = headless_command(&install.headless, &args, &root, java_home.as_deref())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()?;
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            ir.pass2_applied = parse_pass2_summary(&stdout);
        } else {
            let code = output.status.code().unwrap_or(-1);
            tracing::warn!("ghidra: pass 2 for {} failed (exit {code})", ir.label);
            ir.pass2_error = Some(format!("analyzeHeadless exit {code}"));
        }
    }
    Ok(report)
}
```

(Add the `use std::collections::HashMap;` import only if it is not already in scope at the top of the file. Check first — the file may already import it.)

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib decompile::tests::headless_process_args_wires_process_mode_and_post_scripts decompile::tests::parse_pass2_summary_reads_applied_count`
Expected: PASS.

- [ ] **Step 5: Run the full lint + format + test gate**

Run: `cargo fmt --all --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test --all-targets`
Expected: clean / green.

- [ ] **Step 6: Commit**

```bash
git add src/decompile.rs
git commit -m "Add decompile::run_two_pass for symbolicated pass-2"
```

---

## Task 7: Wire `run_two_pass` into `decompose` and reorder the pipeline

**Files:**
- Modify: `src/decompose.rs:284-477` (the body of `run`).

**Interfaces:** No public signature changes. `decompose::run` now produces two extra stages (`symbol_map` and `symbolicate_finalize`) in `report.json` in addition to today's `symbolicate` stage (which becomes `symbolicate_finalize`); the decompile stage uses `run_two_pass`.

- [ ] **Step 1: Update `tests/decompose_golden.rs` to assert the new pipeline shape**

In `tests/decompose_golden.rs`, after the existing `assert!(recovered_index.exists(), ...)` (line 76) and before the `index:` parse (line 79), insert a check that the symbol_map stage ran. Then change the symbolicate-related assertions to look for the renamed `symbolicate_finalize` stage. Concretely, find the line `let report: serde_json::Value =` (currently line 56) and after the existing `source_attribution` assertions, add:

```rust
    // Phase 1: symbol_map stage ran between source_attribution and decompile pass 2.
    let symbol_map_stage = report["stages"]
        .as_array()
        .and_then(|stages| stages.iter().find(|stage| stage["stage"] == "symbol_map"))
        .expect("report.json must contain symbol_map stage");
    assert_eq!(symbol_map_stage["status"], "ok");

    // Phase 1: pass 2 ran on at least one image (02_MAIN on real firmware has
    // token-derived names). pass2_applied is recorded into the decompile stage's
    // per-image report.
    let decompile_stage = report["stages"]
        .as_array()
        .and_then(|stages| stages.iter().find(|stage| stage["stage"] == "decompile"))
        .expect("report.json must contain decompile stage");
    let any_pass2 = decompile_stage["images"]
        .as_array()
        .map(|imgs| {
            imgs.iter()
                .any(|i| i.get("pass2_applied").is_some())
        })
        .unwrap_or(false);
    assert!(any_pass2, "expected at least one image with pass2_applied set");

    // decompiled.c on 02_MAIN contains a plate comment from inline evidence.
    let main_c = std::fs::read_to_string(
        out.join("images")
            .join("02_MAIN")
            .join("decompiled")
            .join("decompiled.c"),
    )
    .unwrap_or_default();
    assert!(
        main_c.contains("// logs:") || main_c.contains("// file:"),
        "expected inline-evidence plate comments in 02_MAIN decompiled.c"
    );
```

Also extend the existing 02_MAIN assertion (currently line 40-46) to also assert `02_MAIN/decompiled/symbols.json` exists:

```rust
    assert!(
        out.join("images")
            .join("02_MAIN")
            .join("decompiled")
            .join("symbols.json")
            .exists(),
        "02_MAIN symbols.json"
    );
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `PME_RADIO_IMG=/path/to/radio.img cargo test --test decompose_golden -- --nocapture` (with `GHIDRA_INSTALL_DIR` set so Ghidra is found)
Expected: FAIL — `report.json must contain symbol_map stage` (the stage does not exist yet).

If no real radio image is available, mark this step as "skipped locally; CI runs it nightly". The structural changes still get exercised by the next steps.

- [ ] **Step 3: Reorder `decompose::run` and call `run_two_pass`**

In `src/decompose.rs`, replace the body of `run` from the comment `// 3. Decompile all images into out/ghidra, then marshal into per-image folders.` (currently around line 323) all the way through the existing `// 5b. Symbolicate` block (currently lines 452-468).

The replacement reorders the pipeline per the spec: extract → decompile pass 1 → source_tree → recover_source → decode_tokens → build symbol_map per image → decompile pass 2 → finalize per image → remaining decoders.

Concretely, replace that span with:

```rust
    // 3. Decompile pass 1 (analyze + inventory + initial decompiled.c) into
    // out/ghidra, then marshal into per-image folders.
    let t = Instant::now();
    let ghidra_dir = out.join("ghidra");
    let dopts = decompile::Opts {
        run: true,
        image: None,
        ghidra_home: opts.ghidra_home.clone(),
        processor: opts.processor.clone(),
    };
    let pass1_report = match decompile::run_report(&modem_bin, &dopts, &ghidra_dir) {
        Ok(rep) => {
            let mut image_reports = Vec::new();
            let mut marshal_err = None;
            for ir in &rep.images {
                if let Err(e) = marshal_image(&ghidra_dir, &images_dir, &ir.label) {
                    marshal_err = Some(e.to_string());
                    break;
                }
                image_reports.push(ImageReport::from_result(ir));
            }
            match marshal_err {
                None => stages.push(StageReport::decompile(image_reports, t.elapsed().as_millis())),
                Some(err) => stages.push(StageReport::failed(
                    "decompile",
                    format!("marshal: {err}"),
                    t.elapsed().as_millis(),
                )),
            }
            Some(rep)
        }
        Err(e) => {
            stages.push(StageReport::failed(
                "decompile",
                e.to_string(),
                t.elapsed().as_millis(),
            ));
            None
        }
    };

    // 4. Source tree — 02_MAIN only.
    let main_bin = images_dir.join("02_MAIN").join("02_MAIN.bin");
    if main_bin.exists() {
        let st_out = images_dir.join("02_MAIN").join("source_tree");
        let st_opts = source_tree::Opts {
            no_attribution: false,
            gap: 4,
            shared_pct: 0.05,
            min_run: 3,
        };
        run_stage(
            &mut stages,
            "source_tree",
            "images/02_MAIN/source_tree",
            || source_tree::run(&main_bin, &st_out, &st_opts),
        );
    } else {
        stages.push(StageReport::skipped("source_tree", "no 02_MAIN image"));
    }

    let source_tree_dir = images_dir.join("02_MAIN").join("source_tree");
    let decompiled_dir = images_dir.join("02_MAIN").join("decompiled");
    if source_tree_dir.join("manifest.json").exists()
        && source_tree_dir.join("tree").is_dir()
        && decompiled_dir.join("functions.json").exists()
        && decompiled_dir.join("decompiled.c").exists()
    {
        run_stage(
            &mut stages,
            "source_attribution",
            "images/02_MAIN/source_tree/recovered_index.json",
            || {
                recover_source::run(
                    &source_tree_dir,
                    &decompiled_dir,
                    &source_tree_dir.join("recovered_index.json"),
                    &recover_source::Opts::default(),
                )
            },
        );
    } else {
        stages.push(StageReport::skipped(
            "source_attribution",
            "no 02_MAIN source tree or decompiler artifacts",
        ));
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
    let symbol_maps = build_and_write_symbol_maps(
        out,
        &images_dir,
        &token_db,
        &out.join("manifest.json"),
    );
    {
        let total: usize = symbol_maps.values().map(|(_, n)| *n).sum();
        let stage = if total == 0 {
            StageReport::skipped("symbol_map", "no symbols recovered")
        } else {
            StageReport::ok(
                "symbol_map",
                "ghidra/symbol_maps/",
                0, // timed inside build_and_write_symbol_maps; small enough to skip
            )
        };
        // overwrite the duration with a real measurement by re-deriving inside
        // build_and_write_symbol_maps is overkill; the ok variant is fine here.
        stages.push(stage);
    }

    // 7. Decompile pass 2 — ApplySymbols + ExportDecomp on each image with a
    //    non-empty map. Updates the pass1_report's per-image outcomes in place.
    if let Some(mut rep) = pass1_report {
        let t = Instant::now();
        let map_paths: HashMap<String, PathBuf> = symbol_maps
            .into_iter()
            .map(|(label, (path, _))| (label, path))
            .collect();
        match decompile::run_two_pass(&modem_bin, &dopts, &ghidra_dir, &map_paths) {
            Ok(rep2) => {
                // Refresh the decompile stage's per-image reports with pass-2 fields.
                rep.images = rep2.images;
                let image_reports: Vec<ImageReport> = rep.images.iter().map(ImageReport::from_result).collect();
                // Replace the last decompile stage entry.
                if let Some(pos) = stages.iter().rposition(|s| s.stage == "decompile") {
                    stages[pos] = StageReport::decompile(image_reports, t.elapsed().as_millis());
                }
            }
            Err(e) => stages.push(StageReport::failed(
                "decompile_pass2",
                e.to_string(),
                t.elapsed().as_millis(),
            )),
        }
    }

    // 8. Finalize symbolication per image: rewrite thumb_functions.json (still
    //    asm in Phase 1) and write symbols.json. decompiled.c is left alone on
    //    this path — pass 2 regenerated it with names baked in.
    run_stage(
        &mut stages,
        "symbolicate_finalize",
        "images/*/decompiled/symbols.json",
        || {
            symbolicate::run(
                out,
                &symbolicate::Opts {
                    token_db: token_db.exists().then(|| token_db.clone()),
                    rewrite_decompiled_c: false,
                },
            )
        },
    );

    // 9. Remaining decoders (independent of symbolication).
    let rf_dir = out.join("rf_cfg_decompressed");
    let hwcfg_path = rootfs.join("hardware_config.json");
    let rf_present = std::fs::read_dir(&rf_dir)
        .map(|mut it| it.next().is_some())
        .unwrap_or(false);

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

    if hwcfg_path.exists() {
        let rf_arg = rf_present.then(|| rf_dir.clone());
        run_stage(&mut stages, "hardware_config", "rf/hwcfg_summary", || {
            hwcfg::run(
                &hwcfg_path,
                rf_arg.as_deref(),
                &out.join("rf").join("hwcfg_summary"),
            )
        });
    } else {
        stages.push(StageReport::skipped(
            "hardware_config",
            "no hardware_config.json",
        ));
    }
```

- [ ] **Step 4: Add the `build_and_write_symbol_maps` helper**

In `src/decompose.rs`, immediately above `pub fn run` (currently line 282), add:

```rust
use crate::symbolicate;
use std::collections::HashMap;

/// Build the per-image symbol map from pass-1 outputs and write each to
/// `<out>/ghidra/symbol_maps/<label>.json`. Returns `(label, (path, count))`
/// per image where `count` is the number of symbols with non-null names.
fn build_and_write_symbol_maps(
    out: &Path,
    images_dir: &Path,
    token_db: &Path,
    manifest: &Path,
) -> Vec<(String, (PathBuf, usize))> {
    let tokens = if token_db.exists() {
        match std::fs::read(token_db)
            .map_err(crate::tokens::parse)
            .and_then(|db| Ok(db))
        {
            Ok(db) => symbolicate::token_map(&db),
            Err(_) => HashMap::new(),
        }
    } else {
        HashMap::new()
    };
    let maps_dir = out.join("ghidra").join("symbol_maps");
    let _ = std::fs::create_dir_all(&maps_dir);
    let mut out_vec = Vec::new();
    if let Ok(entries) = std::fs::read_dir(images_dir) {
        for entry in entries.flatten() {
            let dir = entry.path();
            let Some(label) = dir.file_name().and_then(|n| n.to_str()).map(str::to_string) else {
                continue;
            };
            if !dir.join("decompiled").join("functions.json").exists() {
                continue;
            }
            let funcs_sha = std::fs::read(dir.join("decompiled").join("functions.json"))
                .ok()
                .map(|b| crate::manifest::sha256_bytes(&b))
                .unwrap_or_default();
            let image_sha = std::fs::read(dir.join(format!("{label}.bin")))
                .ok()
                .map(|b| crate::manifest::sha256_bytes(&b))
                .unwrap_or_default();
            let symbols = match symbolicate::build_map(&dir, &label, &tokens, manifest) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let with_names = symbols
                .iter()
                .filter(|s| s.name.is_some())
                .count();
            let map_path = maps_dir.join(format!("{label}.json"));
            if symbolicate::write_symbol_map(&map_path, &label, &symbols, &image_sha, &funcs_sha)
                .is_ok()
            {
                out_vec.push((label, (map_path, with_names)));
            }
        }
    }
    out_vec
}
```

Note: `symbolicate::build_map` is currently private to the `symbolicate` module. Promote it to `pub(crate) fn build_map` in `src/symbolicate.rs` so `decompose` can call it. The signature stays the same. (This is the next step.)

- [ ] **Step 5: Promote `symbolicate::build_map` to `pub(crate)`**

In `src/symbolicate.rs`, change the visibility:

Current:
```rust
fn build_map(
```

Replacement:
```rust
pub(crate) fn build_map(
```

- [ ] **Step 6: Confirm the imports at the top of `src/decompose.rs` are complete**

The existing imports at `src/decompose.rs:1-13` are:

```rust
use crate::decompile::{self, ImageOutcome};
use crate::error::{Error, Result};
use crate::{
    decode_rf, hwcfg, manifest, pipeline, recover_source, source_tree, symbolicate, tokens,
};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::Instant;
```

Add `std::collections::HashMap` if the new helper compiles without it (the helper uses `HashMap` in the inline `token_map`'s return type). Adjust if the compiler complains.

- [ ] **Step 7: Run the full test suite**

Run: `cargo test --all-targets`
Expected: PASS — unit tests pass; `decompose_golden` skips without `PME_RADIO_IMG`.

- [ ] **Step 8: Run the full lint + format gate**

Run: `cargo fmt --all --check && cargo clippy --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 9: (If a real radio image is available) run the integration test**

Run: `PME_RADIO_IMG=/path/to/radio.img GHIDRA_INSTALL_DIR=/path/to/ghidra cargo test --test decompose_golden -- --nocapture`
Expected: PASS — including the new symbol_map / pass2_applied / plate-comment assertions.

If no real radio image is available, note this in the commit message and rely on CI.

- [ ] **Step 10: Commit**

```bash
git add src/decompose.rs src/symbolicate.rs tests/decompose_golden.rs
git commit -m "Reorder decompose to two-pass decompile with symbol maps"
```

---

## Task 8: Add `--no-symbol-pass` flag to `decompose`

**Files:**
- Modify: `src/cli.rs:88-100` (the `Decompose` variant).
- Modify: `src/cli.rs:203-227` (the `Decompose` match arm).
- Modify: `src/cli.rs:367-400` (the `parses_decompose` test).
- Modify: `src/decompose.rs:16-22` (`Opts` struct).
- Modify: `src/decompose.rs:284` (top of `run`) — branch on the new opt.

**Interfaces:**
- Produces: `Opts { no_symbol_pass: bool }` on `decompose::Opts`. When `true`, `decompose::run` calls `decompile::run_report` (today's path) instead of `run_two_pass`, and skips the `symbol_map` and `symbolicate_finalize` stages' pass-2 work.

- [ ] **Step 1: Add the flag to `decompose::Opts` and the clap variant**

In `src/decompose.rs:16-22`:

Current:
```rust
#[derive(Debug, Clone)]
pub struct Opts {
    pub no_verify: bool,
    pub prune: bool,
    pub ghidra_home: Option<PathBuf>,
    pub processor: String,
}
```

Replacement:
```rust
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
}
```

In `src/cli.rs:88-100` (the `Decompose` clap variant), add a new field:

```rust
    /// Skip the symbolication pass 2 (Phase 1). Today's single-pass decompile behavior.
    #[arg(long)]
    no_symbol_pass: bool,
```

Place it after `prune` and before `ghidra_home`.

In `src/cli.rs:203-227` (the `Decompose` match arm), update the destructuring and `Opts` construction:

Current:
```rust
        Commands::Decompose {
            img,
            out,
            no_verify,
            prune,
            ghidra_home,
            processor,
        } => {
            ...
            let opts = crate::decompose::Opts {
                no_verify,
                prune,
                ghidra_home,
                processor,
            };
            ...
        }
```

Replacement:
```rust
        Commands::Decompose {
            img,
            out,
            no_verify,
            prune,
            no_symbol_pass,
            ghidra_home,
            processor,
        } => {
            ...
            let opts = crate::decompose::Opts {
                no_verify,
                prune,
                ghidra_home,
                processor,
                no_symbol_pass,
            };
            ...
        }
```

- [ ] **Step 2: Branch in `decompose::run`**

In `src/decompose.rs`, the decompile pass 1 / pass 2 split added in Task 7 needs to be gated on `!opts.no_symbol_pass`. Concretely, the `if let Some(mut rep) = pass1_report` block (the pass-2 invocation in Task 7 step 3) gains a guard:

Current (from Task 7):
```rust
    if let Some(mut rep) = pass1_report {
        let t = Instant::now();
        ...
        match decompile::run_two_pass(&modem_bin, &dopts, &ghidra_dir, &map_paths) {
            ...
        }
    }
```

Replacement:
```rust
    if !opts.no_symbol_pass {
        if let Some(mut rep) = pass1_report {
            let t = Instant::now();
            let map_paths: HashMap<String, PathBuf> = symbol_maps
                .into_iter()
                .map(|(label, (path, _))| (label, path))
                .collect();
            match decompile::run_two_pass(&modem_bin, &dopts, &ghidra_dir, &map_paths) {
                Ok(rep2) => {
                    rep.images = rep2.images;
                    let image_reports: Vec<ImageReport> =
                        rep.images.iter().map(ImageReport::from_result).collect();
                    if let Some(pos) = stages.iter().rposition(|s| s.stage == "decompile") {
                        stages[pos] =
                            StageReport::decompile(image_reports, t.elapsed().as_millis());
                    }
                }
                Err(e) => stages.push(StageReport::failed(
                    "decompile_pass2",
                    e.to_string(),
                    t.elapsed().as_millis(),
                )),
            }
        }
    } else {
        stages.push(StageReport::skipped(
            "decompile_pass2",
            "--no-symbol-pass",
        ));
    }
```

Also gate the `symbol_map` stage on the same flag — when `no_symbol_pass`, skip building maps. Concretely, the `build_and_write_symbol_maps` call (Task 7 step 3, "// 6. Build the per-image symbol map") becomes:

```rust
    let symbol_maps = if opts.no_symbol_pass {
        Vec::new()
    } else {
        build_and_write_symbol_maps(out, &images_dir, &token_db, &out.join("manifest.json"))
    };
```

And the stage push becomes:

```rust
    if opts.no_symbol_pass {
        stages.push(StageReport::skipped("symbol_map", "--no-symbol-pass"));
    } else {
        let total: usize = symbol_maps.values().map(|(_, n)| *n).sum();
        let stage = if total == 0 {
            StageReport::skipped("symbol_map", "no symbols recovered")
        } else {
            StageReport::ok("symbol_map", "ghidra/symbol_maps/", 0)
        };
        stages.push(stage);
    }
```

- [ ] **Step 3: Update the `parses_decompose` test**

In `src/cli.rs:367-400`, add `--no-symbol-pass` to the args and assert the new field:

Current:
```rust
    #[test]
    fn parses_decompose() {
        let cli = Cli::try_parse_from([
            "pme",
            "decompose",
            "/tmp/radio.img",
            "--out",
            "/tmp/o",
            "--prune",
            "--no-verify",
            "--ghidra-home",
            "/opt/ghidra",
            "--processor",
            "ARM:LE:32:v8",
        ])
        .unwrap();
        match cli.command {
            Commands::Decompose {
                img,
                out,
                no_verify,
                prune,
                ghidra_home,
                processor,
            } => {
                assert_eq!(img, PathBuf::from("/tmp/radio.img"));
                assert_eq!(out, Some(PathBuf::from("/tmp/o")));
                assert!(no_verify);
                assert!(prune);
                assert_eq!(ghidra_home, Some(PathBuf::from("/opt/ghidra")));
                assert_eq!(processor, "ARM:LE:32:v8");
            }
            _ => panic!("wrong subcommand"),
        }
    }
```

Replacement:
```rust
    #[test]
    fn parses_decompose() {
        let cli = Cli::try_parse_from([
            "pme",
            "decompose",
            "/tmp/radio.img",
            "--out",
            "/tmp/o",
            "--prune",
            "--no-verify",
            "--no-symbol-pass",
            "--ghidra-home",
            "/opt/ghidra",
            "--processor",
            "ARM:LE:32:v8",
        ])
        .unwrap();
        match cli.command {
            Commands::Decompose {
                img,
                out,
                no_verify,
                prune,
                no_symbol_pass,
                ghidra_home,
                processor,
            } => {
                assert_eq!(img, PathBuf::from("/tmp/radio.img"));
                assert_eq!(out, Some(PathBuf::from("/tmp/o")));
                assert!(no_verify);
                assert!(prune);
                assert!(no_symbol_pass);
                assert_eq!(ghidra_home, Some(PathBuf::from("/opt/ghidra")));
                assert_eq!(processor, "ARM:LE:32:v8");
            }
            _ => panic!("wrong subcommand"),
        }
    }
```

Also update `tests/decompose_golden.rs` to construct `decompose::Opts` with the new field. In `tests/decompose_golden.rs:25-30`:

Current:
```rust
    let opts = decompose::Opts {
        no_verify: false,
        prune: false,
        ghidra_home: None,
        processor: "ARM:LE:32:v7".to_string(),
    };
```

Replacement:
```rust
    let opts = decompose::Opts {
        no_verify: false,
        prune: false,
        ghidra_home: None,
        processor: "ARM:LE:32:v7".to_string(),
        no_symbol_pass: false,
    };
```

- [ ] **Step 4: Run all tests + lint + format**

Run: `cargo fmt --all --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test --all-targets`
Expected: clean / green.

- [ ] **Step 5: Commit**

```bash
git add src/cli.rs src/decompose.rs tests/decompose_golden.rs
git commit -m "Add decompose --no-symbol-pass escape hatch"
```

---

## Task 9: Add fidelity-first doc comment to `ExportDecomp.java`

**Files:**
- Modify: `src/ghidra/ExportDecomp.java:1-3` (header comment).

**Why:** Record the analysis from the Phase-1 spec (Fidelity posture section) at the top of the script so future tuning starts from the right baseline.

- [ ] **Step 1: Replace the header comment**

In `src/ghidra/ExportDecomp.java`, replace lines 1-3.

Current:
```java
// ExportDecomp.java — Ghidra headless post-script for pixel-modem-extractor.
// Arg[0] = output directory. Writes decompiled.c, disasm.lst, functions.json.
//@category PixelModem
```

Replacement:
```java
// ExportDecomp.java — Ghidra headless post-script for pixel-modem-extractor.
// Arg[0] = output directory. Writes decompiled.c, disasm.lst, functions.json.
//
// FIDELITY POSTURE (Phase 1+): this script intentionally does NOT call
// DecompInterface.setOptions(...). Ghidra's decompiler defaults are already a
// fiducial baseline, and setOptions *replaces* the program's "Decompiler"
// property sheet rather than merging with it, which would clobber user /
// environment defaults for zero benefit.
//
// The candidate readability knobs were reviewed and kept at Ghidra defaults:
//   - EliminateUnreachable: OFF. Can drop real firmware code reached via
//     jump tables, computed branches, or tail-call dispatch.
//   - Simplify: OFF. Extended simplification can elide semantically relevant
//     intermediate state.
//   - NoCasts: OFF (default). The alternative hides real type conversions.
//   - DisableDecompilerParameterNames: OFF (default). The alternative strips
//     parameter names.
//   - UseHexadecimal: TRUE (default). Display-only; matches disasm.lst.
//
// Pass 2 of `decompose` re-runs this script unchanged after ApplySymbols.java
// has renamed functions in the program — getC() then emits the regenerated C
// with names + plate comments baked in.
//@category PixelModem
```

- [ ] **Step 2: Verify build (no functional change)**

Run: `cargo build && cargo fmt --all --check && cargo clippy --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add src/ghidra/ExportDecomp.java
git commit -m "Document fidelity posture in ExportDecomp.java"
```

---

## Task 10: Update `README.md` and `CONTRIBUTING.md`

**Files:**
- Modify: `README.md:51` (the `decompose` row in the Commands table).
- Modify: `CONTRIBUTING.md:89-123` (the Domain map section).

- [ ] **Step 1: Update the `decompose` row in `README.md`**

In `README.md:51`, append a sentence about the two-pass behavior and the new flag.

Current:
```markdown
| `decompose <radio.img>` | **Everything, one shot.** Runs `extract`, decompiles all six images (Ghidra), enriches `02_MAIN/source_tree` with recovered-code evidence when attribution is possible, and runs every decoder into one per-image tree (`images/NN_NAME/{decompiled,…}`, `rf/`, `tokens/`) with a `report.json`. **Requires a local Ghidra and radare2** (`r2`), probed up front. `--prune` keeps only the terminal artifacts; `--out`, `--ghidra-home`, `--processor`, `--no-verify` as elsewhere. Default out `./<img>.decomposed/`. Also symbolicates each image (names + annotations + symbols.json). |
```

Replacement:
```markdown
| `decompose <radio.img>` | **Everything, one shot.** Runs `extract`, decompiles all six images (Ghidra), enriches `02_MAIN/source_tree` with recovered-code evidence when attribution is possible, and runs every decoder into one per-image tree (`images/NN_NAME/{decompiled,…}`, `rf/`, `tokens/`) with a `report.json`. **Requires a local Ghidra and radare2** (`r2`), probed up front. `--prune` keeps only the terminal artifacts; `--out`, `--ghidra-home`, `--processor`, `--no-verify` as elsewhere. Default out `./<img>.decomposed/`. **Phase 1:** `decompose` runs decompile **twice** per image — pass 1 analyzes and exports an initial inventory; pass 2 (`ApplySymbols.java` + `ExportDecomp.java`) applies the recovered function names and inline-evidence plate comments so the regenerated `decompiled.c` is born with names baked in (instead of text-substituted afterward). `--no-symbol-pass` skips pass 2 (today's single-pass behavior). |
```

- [ ] **Step 2: Add a `symbol_map.json` row to the Output-layout section**

In `README.md`, after the `manifest.json` row in the `decompose` output layout block (around line 87), insert one new line for `ghidra/symbol_maps/`:

Current:
```markdown
    ├── rf/                           # decoded/  +  hwcfg_summary/
    ├── tokens/                       # pw_token_db.csv + summary.json
    ├── manifest.json
    └── report.json
```

Replacement:
```markdown
    ├── rf/                           # decoded/  +  hwcfg_summary/
    ├── tokens/                       # pw_token_db.csv + summary.json
    ├── manifest.json
    ├── ghidra/symbol_maps/           # per-image symbol_map.json (input to pass 2; Phase 1+)
    └── report.json
```

- [ ] **Step 3: Update the Domain map section of `CONTRIBUTING.md`**

In `CONTRIBUTING.md:89-123` (the Domain map & code conventions section), add a Phase-1 note. Insert after the existing "**Symbolication is fail-closed.**" paragraph (currently ending around line 123). Add:

```markdown
- **Two-pass decompile (Phase 1+).** `decompose` runs decompile twice per
  image: pass 1 (`decompile::run_report`) analyzes and exports an initial
  inventory + `decompiled.c`. Between passes, `decompose::build_and_write_symbol_maps`
  builds a `symbol_map.json` per image from pass-1 outputs (using
  `symbolicate::build_map`, the pure builder split out of `symbolicate_image`).
  Pass 2 (`decompile::run_two_pass`) drives `analyzeHeadless -process` on the
  same project, running `ApplySymbols.java` (renames + plate comments) followed
  by `ExportDecomp.java` (regenerates `decompiled.c` with names + comments baked
  in). `--no-symbol-pass` skips pass 2 entirely. `decompile --run` (the
  standalone subcommand) is single-pass and unchanged. The standalone
  `symbolicate` subcommand still does today's in-place text substitution
  (controlled by `Opts.rewrite_decompiled_c`, which is `true` for the
  standalone path and `false` for the decompose path).
- **Provenance invariant for `functions.json`.** Pass 2 regenerates
  `functions.json` with recovered names in the `name` field (because
  `ApplySymbols.java` renamed in-program first). `rewrite_functions_json`
  sources `original_name` from the `Symbol` record, not from `functions.json`'s
  `name` field, so the original name is preserved across (a) re-running
  decompose and (b) running the standalone `symbolicate` against a Phase-1
  decompose tree.
- **Fidelity over readability.** No lossy `DecompInterface.setOptions(...)` call
  in `ExportDecomp.java` — see the script's header comment for the analysis.
  `Tier::Recovered`'s strict single-identifier-plus-`__FILE__` rule and
  `Tier::Provisional`'s `guess_…` marker convention are preserved as-is; Phase
  1 only changes *where* names are applied, not *which* are considered safe.
```

- [ ] **Step 4: Verify the docs-only change builds clean**

Run: `cargo build && cargo fmt --all --check`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add README.md CONTRIBUTING.md
git commit -m "Document Phase-1 two-pass decompile in README and CONTRIBUTING"
```

---

## Self-review

**Spec coverage:** walk the spec section by section:

- *Two-pass decompile on `decompose`; one-pass unchanged on `decompile --run`* → Tasks 6, 7, 8. ✓
- *Approach 1 (chosen)* → Tasks 5 (ApplySymbols.java), 6 (run_two_pass), 7 (decompose reorder). ✓
- *New artifact `symbol_map.json`* → Task 3 (write_symbol_map). ✓
- *New `ApplySymbols.java`* → Task 5. ✓
- *Modified `ExportDecomp.java` (no functional change; doc comment)* → Task 9. ✓
- *Refactor `symbolicate.rs` (build_map / write_symbol_map / finalize_image)* → Tasks 1, 3. ✓
- *New `decompile::run_two_pass`* → Task 6. ✓
- *`decompose.rs` reordering and stage reporting* → Task 7. ✓
- *Per-image fail-closed policy on pass 2 (`pass2_applied` / `pass2_error`)* → Tasks 4, 6. ✓
- *Escape hatch `--no-symbol-pass`* → Task 8. ✓
- *Provenance invariant for `functions.json`* → Task 2. ✓
- *Empty map → pass 2 skipped* → Task 6 (`has_names` check). ✓
- *`01_PSP` (encrypted) → 0 functions → empty map → no pass 2* → covered by Task 6's `has_names` check. ✓
- *Idempotency preserved on standalone path* → Tasks 1, 3 (finalize_image respects opts). ✓
- *Fidelity posture (no lossy options; no criteria relaxation; plate comments additive; provenance preserved)* → Tasks 2, 9. ✓
- *Testing — Rust unit tests, `decompile_golden.rs` roundtrip, `symbolicate_golden.rs` unchanged, `decompose_golden.rs` new assertions* → covered inline in each task. ✓
- *Verification (fmt + clippy + test, real-image decompose spot-check, `--no-symbol-pass` reproduces today)* → each task ends with the gate; the real-image spot-check is Task 7 step 9. ✓
- *Docs kept in sync (README, CONTRIBUTING)* → Task 10. ✓
- *Future phases (context only)* → no code; documented in the spec. ✓

**Placeholder scan:** no TBD, TODO, "implement later", "add appropriate error handling", "similar to Task N", or steps without code/commands. All code blocks are complete.

**Type consistency:** `pass2_applied: Option<usize>` and `pass2_error: Option<String>` appear in `decompile::ImageResult` (Task 4) and `decompose::ImageReport` (Task 4) with identical types and identical serde `skip_serializing_if`. `from_result` (Task 4) copies both. The pass-2 setter in `run_two_pass` (Task 6) uses `ir.pass2_applied = parse_pass2_summary(&stdout)` (returns `Option<usize>`) and `ir.pass2_error = Some(format!(...))` (returns `Option<String>`). ✓

`build_map`, `finalize_image`, `FinalizeOpts`, `write_symbol_map` — names and signatures consistent across Tasks 1, 2, 3, 7. ✓

`headless_process_args`, `parse_pass2_summary`, `run_two_pass` — names and signatures consistent across Tasks 5, 6, 7. ✓

`no_symbol_pass: bool` — consistent across `decompose::Opts`, `Commands::Decompose` clap variant, `parses_decompose` test, `decompose_golden.rs` fixture (Tasks 8). ✓

`rewrite_decompiled_c: bool` — consistent across `symbolicate::Opts`, `symbolicate::run`, `finalize_image`, `cli.rs` Symbolicate arm, `symbolicate_golden.rs`, `decompose.rs` symbolicate-stage test (Tasks 1, 3, 7). ✓
