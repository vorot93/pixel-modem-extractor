//! End-to-end `decompose` test. Requires a real radio image (`PME_RADIO_IMG`) plus a
//! local Ghidra and radare2; self-skips cleanly when any is absent — matching the
//! other golden tests.

use pixel_modem_extractor::{decompile, decompose};
use std::io::ErrorKind;
use std::path::PathBuf;

#[test]
fn decompose_produces_unified_tree() {
    let Some(img) = std::env::var_os("PME_RADIO_IMG").map(PathBuf::from) else {
        eprintln!("skip: set PME_RADIO_IMG");
        return;
    };
    if !img.exists() {
        eprintln!("skip: PME_RADIO_IMG not found");
        return;
    }
    if decompile::find_headless(None).is_err() || decompile::find_radare2().is_none() {
        eprintln!("skip: Ghidra and/or radare2 not available on this host");
        return;
    }

    let out = std::env::temp_dir().join(format!("pme_decompose_golden_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out);
    let opts = decompose::Opts {
        no_verify: false,
        prune: false,
        ghidra_home: None,
        processor: "ARM:LE:32:v7".to_string(),
        no_symbol_pass: false,
        no_thumb_decompile: false,
        rizin_fallback: false,
        tighten_wall_clock_budget_override: None,
        globals_provisional: false,
        globals_k_arm: None,
        globals_k_thumb: None,
        no_apply_global_types: false,
        no_skip_opaque: false,
    };

    // Best-effort: some partitions may fail Ghidra analysis, which makes `run` return
    // Err — but `report.json` and every successful leaf are still written. Assert the
    // tree, not the exit status.
    let _ = decompose::run(&img, &opts, &out);

    let report_path = out.join("report.json");
    assert!(report_path.exists(), "report.json written");
    assert!(out.join("manifest.json").exists(), "manifest.json present");
    assert!(
        out.join("images")
            .join("02_MAIN")
            .join("decompiled")
            .exists(),
        "02_MAIN decompiled"
    );
    assert!(
        out.join("images")
            .join("02_MAIN")
            .join("decompiled")
            .join("symbols.json")
            .exists(),
        "02_MAIN symbols.json"
    );
    assert!(
        out.join("images")
            .join("02_MAIN")
            .join("source_tree")
            .exists(),
        "02_MAIN source tree"
    );
    let source_tree = out.join("images").join("02_MAIN").join("source_tree");
    let recovered_index = source_tree.join("recovered_index.json");
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report_path).unwrap()).unwrap();
    let source_attribution = report["stages"]
        .as_array()
        .and_then(|stages| {
            stages
                .iter()
                .find(|stage| stage["stage"] == "source_attribution")
        })
        .expect("report.json must contain source_attribution stage");
    assert_eq!(
        source_attribution["status"], "ok",
        "source_attribution stage must complete"
    );
    assert_eq!(
        source_attribution["output"], "images/02_MAIN/source_tree/recovered_index.json",
        "source_attribution output must be recovered_index.json"
    );
    assert!(
        recovered_index.exists(),
        "source_attribution reported ok but recovered_index.json was not produced"
    );

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
        .map(|imgs| imgs.iter().any(|i| i.get("pass2_applied").is_some()))
        .unwrap_or(false);
    assert!(
        any_pass2,
        "expected at least one image with pass2_applied set"
    );
    for image in decompile_stage["images"].as_array().unwrap() {
        let Some(functions) = image.get("functions").and_then(serde_json::Value::as_u64) else {
            continue;
        };
        let ghidra_accepted = image["ghidra_execution_accepted"]
            .as_u64()
            .expect("analyzed image must report current Ghidra accepted count");
        let ghidra_quarantined = image["ghidra_execution_quarantined"]
            .as_u64()
            .expect("analyzed image must report current Ghidra quarantine count");
        assert_eq!(
            functions,
            ghidra_accepted + ghidra_quarantined,
            "Ghidra raw records must be conserved: {image}"
        );
        match image.get("thumb_functions") {
            Some(_) => {
                let accepted = image["thumb_execution_accepted"]
                    .as_u64()
                    .expect("retained Thumb inventory must report accepted count");
                let quarantined = image["thumb_execution_quarantined"]
                    .as_u64()
                    .expect("retained Thumb inventory must report quarantine count");
                assert!(accepted + quarantined > 0, "{image}");
            }
            None => {
                assert!(image.get("thumb_execution_accepted").is_none(), "{image}");
                assert!(
                    image.get("thumb_execution_quarantined").is_none(),
                    "{image}"
                );
            }
        }
        if current_global_shapes_inputs_succeeded(image) {
            for key in NINE_GLOBAL_SHAPES_FIELDS {
                assert!(
                    image.get(key).and_then(serde_json::Value::as_u64).is_some(),
                    "successful global-shapes image must report {key}, including explicit zeros: {image}"
                );
            }
            assert!(
                image.get("global_shapes_error").is_none(),
                "successful global-shapes image must omit global_shapes_error: {image}"
            );
        }
    }

    // Phase 2: thumb_enrich (pass 1) and thumb_enrich_post_pass2 stages are
    // both present in the report. Defaults run both; skip rules covered in
    // Task 10/12.
    let stage_names: Vec<String> = report["stages"]
        .as_array()
        .map(|stages| {
            stages
                .iter()
                .map(|s| s["stage"].as_str().unwrap_or("").to_string())
                .collect()
        })
        .unwrap_or_default();
    assert!(
        stage_names.iter().any(|s| s == "thumb_enrich"),
        "expected thumb_enrich stage in report: {stage_names:?}"
    );
    assert!(
        stage_names.iter().any(|s| s == "thumb_enrich_post_pass2"),
        "expected thumb_enrich_post_pass2 stage in report: {stage_names:?}"
    );
    let shapes_positions: Vec<usize> = stage_names
        .iter()
        .enumerate()
        .filter(|(_, name)| *name == "global_shapes")
        .map(|(index, _)| index)
        .collect();
    assert_eq!(
        shapes_positions.len(),
        1,
        "expected exactly one global_shapes stage: {stage_names:?}"
    );
    // This test always runs the normal route. The single entry is pushed by
    // the route's FIRST sweep (after `globals`, before `decompile_pass2`) and
    // the final re-commit sweep — which runs after pass 2 /
    // thumb_enrich_post_pass2 rewrite the sidecar's hashed inputs — replaces
    // that entry in place, so the position pins to the first sweep's slot.
    let shapes = shapes_positions[0];
    let globals = stage_names
        .iter()
        .position(|name| name == "globals")
        .expect("globals stage");
    assert!(
        globals < shapes,
        "global_shapes must follow globals: {stage_names:?}"
    );
    let pass2 = stage_names
        .iter()
        .position(|name| name == "decompile_pass2")
        .expect("decompile_pass2 stage");
    assert!(
        shapes < pass2,
        "global_shapes must precede decompile_pass2: {stage_names:?}"
    );
    let thumb_post = stage_names
        .iter()
        .position(|name| name == "thumb_enrich_post_pass2")
        .unwrap();
    assert!(
        pass2 < thumb_post,
        "thumb_enrich_post_pass2 must follow decompile_pass2: {stage_names:?}"
    );
    for decoder in ["decode_rf", "hardware_config"] {
        if let Some(pos) = stage_names.iter().position(|name| name == decoder) {
            assert!(
                shapes < pos,
                "global_shapes must precede {decoder}: {stage_names:?}"
            );
        }
    }

    let shapes_stage = report["stages"]
        .as_array()
        .and_then(|stages| {
            stages
                .iter()
                .find(|stage| stage["stage"] == "global_shapes")
        })
        .expect("report.json must contain global_shapes stage");
    let images = decompile_stage["images"]
        .as_array()
        .expect("decompile images");
    let any_shape_error = images
        .iter()
        .any(|image| image.get("global_shapes_error").is_some());
    assert_eq!(
        shapes_stage["status"],
        if any_shape_error { "failed" } else { "ok" },
        "global_shapes stage status must agree with per-image errors: {shapes_stage}"
    );
    let output = shapes_stage["output"]
        .as_str()
        .expect("global_shapes stage output");
    assert!(
        output.contains("images/*/decompiled/global_shapes.json"),
        "stage output must name the sidecar glob: {output}"
    );
    let mut totals = [0u64; 9];
    for image in images {
        if image.get("global_shapes_error").is_some() {
            continue;
        }
        for (index, key) in NINE_GLOBAL_SHAPES_FIELDS.into_iter().enumerate() {
            totals[index] += image
                .get(key)
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
        }
    }
    for (key, expected) in [
        ("inferred=", totals[0]),
        ("no_evidence=", totals[1]),
        ("conflicting=", totals[2]),
        ("observations=", totals[3]),
        ("ghidra_quarantined=", totals[4]),
        ("thumb_quarantined=", totals[5]),
        ("quarantine_errors=", totals[6]),
        ("decode_failures=", totals[7]),
        ("state_barriers=", totals[8]),
    ] {
        let start = output
            .find(key)
            .unwrap_or_else(|| panic!("stage output missing {key}: {output}"));
        let rest = &output[start + key.len()..];
        let end = rest
            .find([',', ')'])
            .unwrap_or_else(|| panic!("unterminated {key} in {output}"));
        let actual: u64 = rest[..end]
            .parse()
            .unwrap_or_else(|_| panic!("invalid {key} in {output}"));
        assert_eq!(actual, expected, "stage output {key} mismatch in {output}");
    }
    let main = images
        .iter()
        .find(|image| image["image"] == "02_MAIN")
        .expect("02_MAIN entry missing from decompile stage");
    if current_global_shapes_inputs_succeeded(main) {
        assert!(
            out.join("images")
                .join("02_MAIN")
                .join("decompiled")
                .join("global_shapes.json")
                .exists(),
            "02_MAIN current inputs succeeded but global_shapes.json is missing"
        );
        if main.get("global_shapes_error").is_none() {
            assert_eq!(
                main["global_shapes_inferred"]
                    .as_u64()
                    .expect("02_MAIN inferred")
                    + main["global_shapes_no_evidence"]
                        .as_u64()
                        .expect("02_MAIN no_evidence")
                    + main["global_shapes_conflicting"]
                        .as_u64()
                        .expect("02_MAIN conflicting"),
                main["globals_recovered"]
                    .as_u64()
                    .expect("02_MAIN globals_recovered"),
                "status counts must conserve Recovered globals: {main}"
            );
        }
    }

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

    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&recovered_index).unwrap()).unwrap();
    assert_eq!(index["attribution"], "moderate");
    let sources = index["sources"]
        .as_object()
        .expect("recovered_index.json sources must be an object");
    let attributed_leaves: Vec<_> = sources
        .values()
        .filter_map(|source| {
            let functions = source["functions"].as_array()?;
            if functions.is_empty() {
                None
            } else {
                source["leaf"].as_str()
            }
        })
        .collect();
    assert!(
        !attributed_leaves.is_empty(),
        "recovered_index.json contained no sources with attributed functions"
    );

    let mut saw_recovered = false;
    for leaf in attributed_leaves {
        let path = source_tree.join(leaf);
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        if text.contains("// --- recovered function") {
            saw_recovered = true;
            assert!(
                text.starts_with("// Reconstructed node"),
                "source-tree metadata must remain first in {}",
                path.display()
            );
            break;
        }
    }
    assert!(
        saw_recovered,
        "no attributed source-tree leaf contained recovered function evidence"
    );
    // intermediates present without --prune
    assert!(out.join("modem.ext4").exists(), "ext4 kept without --prune");
}

/// Phase 2: on a real `02_MAIN` the per-image entry in `report.json` carries at
/// least one of the Phase-2 Thumb fields — either `thumb_decompiled` (the
/// happy path: tightened Ghidra converged and `thumb_enrich` populated `body_c`)
/// or `thumb_tighten_error` (Surface B fired: the runtime watch killed the
/// tightened run and fell back to datamark). Either is a valid Phase-2 outcome;
/// their absence means the Phase-2 wiring is silently inert.
#[test]
fn report_json_includes_phase2_fields() {
    let Some(img) = std::env::var_os("PME_RADIO_IMG").map(PathBuf::from) else {
        eprintln!("skip: set PME_RADIO_IMG");
        return;
    };
    if !img.exists() {
        eprintln!("skip: PME_RADIO_IMG not found");
        return;
    }
    if decompile::find_headless(None).is_err() || decompile::find_radare2().is_none() {
        eprintln!("skip: Ghidra and/or radare2 not available on this host");
        return;
    }

    let out = std::env::temp_dir().join(format!(
        "pme_decompose_golden_phase2_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&out);
    let opts = decompose::Opts {
        no_verify: false,
        prune: false,
        ghidra_home: None,
        processor: "ARM:LE:32:v7".to_string(),
        no_symbol_pass: false,
        no_thumb_decompile: false,
        rizin_fallback: false,
        tighten_wall_clock_budget_override: None,
        globals_provisional: false,
        globals_k_arm: None,
        globals_k_thumb: None,
        no_apply_global_types: false,
        no_skip_opaque: false,
    };
    let _ = decompose::run(&img, &opts, &out);

    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("report.json")).unwrap()).unwrap();
    let main = report["stages"]
        .as_array()
        .and_then(|stages| stages.iter().find(|s| s["stage"] == "decompile"))
        .and_then(|s| s["images"].as_array())
        .and_then(|imgs| imgs.iter().find(|i| i["image"] == "02_MAIN"))
        .expect("02_MAIN entry missing from decompile stage");
    assert!(
        main.get("thumb_decompiled").is_some() || main.get("thumb_tighten_error").is_some(),
        "Phase-2 fields absent on 02_MAIN: {main}"
    );
}

/// Phase 3.0: on a real `02_MAIN`, the per-image entry in the `decompile`
/// stage's `images[]` carries either `globals_recovered` (happy path) or
/// `globals_error` (per-image failure). Their absence means the
/// `refresh_decompile_stage_images` call is missing after the globals sweep
/// — the same wiring gap that bit Phase 2.1 on the pass-1 path.
#[test]
fn report_json_includes_globals_field() {
    let Some(img) = std::env::var_os("PME_RADIO_IMG").map(PathBuf::from) else {
        eprintln!("skip: set PME_RADIO_IMG");
        return;
    };
    if !img.exists() {
        eprintln!("skip: PME_RADIO_IMG not found");
        return;
    }
    if decompile::find_headless(None).is_err() || decompile::find_radare2().is_none() {
        eprintln!("skip: Ghidra and/or radare2 not available");
        return;
    }
    let out = std::env::temp_dir().join(format!(
        "pme_decompose_golden_phase3_{}",
        std::process::id()
    ));
    match std::fs::remove_dir_all(&out) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => panic!("failed to remove stale output {}: {e}", out.display()),
    }
    let opts = decompose::Opts {
        no_verify: false,
        prune: false,
        ghidra_home: None,
        processor: "ARM:LE:32:v7".to_string(),
        no_symbol_pass: true,
        no_thumb_decompile: false,
        rizin_fallback: false,
        tighten_wall_clock_budget_override: None,
        globals_provisional: false,
        globals_k_arm: None,
        globals_k_thumb: None,
        no_apply_global_types: false,
        no_skip_opaque: false,
    };
    let _ = decompose::run(&img, &opts, &out);

    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("report.json")).unwrap()).unwrap();
    let main = report["stages"]
        .as_array()
        .and_then(|stages| stages.iter().find(|s| s["stage"] == "decompile"))
        .and_then(|s| s["images"].as_array())
        .and_then(|imgs| imgs.iter().find(|i| i["image"] == "02_MAIN"))
        .expect("02_MAIN entry missing from decompile stage");
    assert!(
        main.get("globals_recovered").is_some() || main.get("globals_error").is_some(),
        "Phase 3.0 fields absent on 02_MAIN: {main}"
    );
    let functions = main["functions"]
        .as_u64()
        .expect("no-symbol-pass must retain current Ghidra raw count");
    assert_eq!(
        functions,
        main["ghidra_execution_accepted"].as_u64().unwrap()
            + main["ghidra_execution_quarantined"].as_u64().unwrap(),
        "no-symbol-pass must use the same terminal validation contract: {main}"
    );
}

/// Phase 3.0.1: on a real `02_MAIN`, the per-image entry in the `decompile`
/// stage's `images[]` carries `globals_provisional` and
/// `globals_provisional_suppressed` (Some, possibly 0). Their absence means
/// the `refresh_decompile_stage_images` call is missing after the Phase 3.0.1
/// globals sweep — the same wiring gap that bit Phase 2.1 on the pass-1 path
/// (and Phase 3.0 on its initial wiring). Reads `$PME_GOLDEN_DIR/report.json`
/// (pre-existing decompose output; never auto-runs decompose — production
/// verification supplies the env); skips cleanly when the env is unset or the
/// file is absent.
#[test]
fn report_json_includes_phase3_0_1_fields() {
    let Some(dir) = std::env::var_os("PME_GOLDEN_DIR").map(PathBuf::from) else {
        eprintln!("skip: set PME_GOLDEN_DIR");
        return;
    };
    let report_path = dir.join("report.json");
    if !report_path.exists() {
        eprintln!("skip: PME_GOLDEN_DIR/report.json not found");
        return;
    }
    let v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report_path).expect("report.json readable"))
            .expect("report.json valid JSON");
    let main = v["stages"]
        .as_array()
        .and_then(|stages| stages.iter().find(|s| s["stage"] == "decompile"))
        .and_then(|s| s["images"].as_array())
        .and_then(|imgs| imgs.iter().find(|i| i["image"] == "02_MAIN"))
        .expect("02_MAIN entry missing from decompile stage");
    assert!(
        main.get("globals_provisional").is_some(),
        "globals_provisional missing — refresh_decompile_stage_images not called after Phase 3.0.1 sweep: {main}"
    );
    assert!(
        main.get("globals_provisional_suppressed").is_some(),
        "globals_provisional_suppressed missing — refresh_decompile_stage_images not called after Phase 3.0.1 sweep: {main}"
    );
}

const NINE_GLOBAL_SHAPES_FIELDS: [&str; 9] = [
    "global_shapes_inferred",
    "global_shapes_no_evidence",
    "global_shapes_conflicting",
    "global_shape_observations",
    "global_shapes_ghidra_quarantined",
    "global_shapes_thumb_quarantined",
    "global_shapes_quarantine_errors",
    "global_shapes_decode_failures",
    "global_shapes_state_barriers",
];

fn current_global_shapes_inputs_succeeded(image: &serde_json::Value) -> bool {
    if image
        .get("functions")
        .and_then(serde_json::Value::as_u64)
        .is_none()
    {
        return false;
    }
    let (Some(accepted), Some(quarantined)) = (
        image
            .get("ghidra_execution_accepted")
            .and_then(serde_json::Value::as_u64),
        image
            .get("ghidra_execution_quarantined")
            .and_then(serde_json::Value::as_u64),
    ) else {
        return false;
    };
    if accepted + quarantined != image["functions"].as_u64().unwrap() {
        return false;
    }
    if image.get("thumb_error").is_some() || image.get("globals_error").is_some() {
        return false;
    }
    let thumb_fields = (
        image.get("thumb_functions").is_some(),
        image.get("thumb_execution_accepted").is_some(),
        image.get("thumb_execution_quarantined").is_some(),
    );
    if !matches!(thumb_fields, (false, false, false) | (true, true, true)) {
        return false;
    }
    image
        .get("globals_recovered")
        .and_then(serde_json::Value::as_u64)
        .is_some()
}

/// Phase 3.2: retained `report.json` carries the `global_shapes` stage and
/// the nine per-image analysis numbers on a successful current-input image.
/// Reads `$PME_GOLDEN_DIR/report.json` only and never launches decompose.
/// Pre-stage corpora (no stage and no per-image fields) skip cleanly.
#[test]
fn report_json_includes_global_shapes_fields() {
    let Some(dir) = std::env::var_os("PME_GOLDEN_DIR").map(PathBuf::from) else {
        eprintln!("skip: set PME_GOLDEN_DIR");
        return;
    };
    let report_path = dir.join("report.json");
    if !report_path.exists() {
        eprintln!("skip: PME_GOLDEN_DIR/report.json not found");
        return;
    }
    let v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report_path).expect("report.json readable"))
            .expect("report.json valid JSON");
    let stages = v["stages"]
        .as_array()
        .expect("report.json stages must be an array");
    let has_stage = stages.iter().any(|stage| stage["stage"] == "global_shapes");
    let main = stages
        .iter()
        .find(|stage| stage["stage"] == "decompile")
        .and_then(|stage| stage["images"].as_array())
        .and_then(|images| images.iter().find(|image| image["image"] == "02_MAIN"))
        .expect("02_MAIN entry missing from decompile stage");
    let has_fields = NINE_GLOBAL_SHAPES_FIELDS
        .iter()
        .any(|key| main.get(*key).is_some())
        || main.get("global_shapes_error").is_some();
    if !has_stage && !has_fields {
        eprintln!(
            "skip: retained tree predates the global_shapes stage ({})",
            dir.display()
        );
        return;
    }
    if has_stage {
        let names: Vec<&str> = stages
            .iter()
            .filter_map(|stage| stage["stage"].as_str())
            .collect();
        assert_eq!(
            names
                .iter()
                .filter(|name| **name == "global_shapes")
                .count(),
            1,
            "exactly one global_shapes stage: {names:?}"
        );
        let shapes = names
            .iter()
            .position(|name| *name == "global_shapes")
            .unwrap();
        let thumb = names
            .iter()
            .position(|name| *name == "thumb_enrich_post_pass2")
            .expect("thumb_enrich_post_pass2 must precede or follow global_shapes");
        // Route-dependent order: on `--no-symbol-pass`, `global_shapes` still
        // runs last (after its own, always-"skipped" `thumb_enrich_post_pass2`
        // stub) exactly as before Task 5's reorder. On the normal route,
        // Task 5's input-safe reorder moved `global_shapes` to run *before*
        // `DispatchPass2` (which pushes the real `thumb_enrich_post_pass2`) so
        // a later pass-2 post-script can apply the recovered shapes as types —
        // see CONTRIBUTING.md's "Phase 3.2: global storage-shape recovery".
        // `decompile_pass2`'s stage `reason` is the only route signal already
        // present in report.json: it is exactly "--no-symbol-pass" on that
        // route and never on the normal route (previously this assertion only
        // checked the pre-reorder `--no-symbol-pass` direction unconditionally,
        // which is wrong for a normal-route tree since the Task 5 reorder —
        // that gap is exactly how the global_shapes_* report-field regression
        // below went uncaught).
        let is_no_symbol_pass_route = stages
            .iter()
            .find(|stage| stage["stage"] == "decompile_pass2")
            .and_then(|stage| stage["reason"].as_str())
            == Some("--no-symbol-pass");
        if is_no_symbol_pass_route {
            assert!(
                thumb < shapes,
                "on --no-symbol-pass, global_shapes must follow thumb_enrich_post_pass2: {names:?}"
            );
        } else {
            assert!(
                shapes < thumb,
                "on the normal route, global_shapes must precede thumb_enrich_post_pass2 \
                 (Task 5's input-safe reorder): {names:?}"
            );
        }
        // Unconditional on both routes: `orchestrate_post_symbol_route`
        // (decode_rf, hardware_config) always runs strictly after the whole
        // `orchestrate_symbol_route` closure returns, for both routes, so
        // global_shapes — wherever it lands within that closure — always
        // precedes both decoders.
        for decoder in ["decode_rf", "hardware_config"] {
            if let Some(pos) = names.iter().position(|name| *name == decoder) {
                assert!(
                    shapes < pos,
                    "global_shapes must precede {decoder}: {names:?}"
                );
            }
        }
    }
    // Route-agnostic on purpose (covers the normal route, where Task 5's
    // reorder made `RunGlobalShapes` run before `DispatchPass2`'s
    // `refresh_decompile_stage_images`, which would otherwise silently null
    // these nine fields — see `reapply_global_shapes_outcomes` in
    // decompose.rs and the plain-unit-test regression sentinel
    // `global_shapes_outcomes_survive_refresh_decompile_stage_images`, which
    // pins this without needing PME_GOLDEN_DIR — and the `--no-symbol-pass`
    // route, which was never affected).
    if current_global_shapes_inputs_succeeded(main) && main.get("global_shapes_error").is_none() {
        for key in NINE_GLOBAL_SHAPES_FIELDS {
            assert!(
                main.get(key).and_then(serde_json::Value::as_u64).is_some(),
                "{key} missing on successful 02_MAIN: {main}"
            );
        }
    }
}

/// Phase 3.2 type application: on a real `02_MAIN`, the per-image entry in
/// the `decompile` stage's `images[]` carries all four `global_types_*`
/// counting fields (`global_types_applied`, `global_types_candidates`,
/// `global_types_ineligible`, `global_types_skipped`), conserves
/// `candidates == applied + skipped`, and has actually applied at least one
/// recovered scalar shape. Their absence means either
/// `global_types_apply_stage`'s post-`DispatchPass2` patch never ran (the
/// same wiring-gap class `report_json_includes_phase3_0_1_fields` and
/// `report_json_includes_global_shapes_fields` guard against for their own
/// fields) or the retained tree predates this stage and must be regenerated
/// with a current `decompose` binary. Reads `$PME_GOLDEN_DIR/report.json`
/// (pre-existing decompose output; never auto-runs decompose — production
/// verification supplies the env); skips cleanly when the env is unset or
/// the file is absent.
///
/// Idempotency (re-running `decompose` over an already-typed tree and
/// getting an identical result) is intentionally NOT covered here: a static
/// `report.json` golden cannot observe a second run. That guarantee comes
/// from `ApplyGlobalTypes.java` widening only already-undefined bytes
/// (`CLEAR_ALL_UNDEFINED_CONFLICT_DATA`) plus the DEFAULT-only Ghidra
/// re-apply and unit-test coverage described in CONTRIBUTING.md's Phase 3.2
/// type-application notes.
#[test]
fn global_types_applied_on_retained_tree() {
    let Some(dir) = std::env::var_os("PME_GOLDEN_DIR").map(PathBuf::from) else {
        eprintln!("skip: set PME_GOLDEN_DIR");
        return;
    };
    let report_path = dir.join("report.json");
    if !report_path.exists() {
        eprintln!("skip: PME_GOLDEN_DIR/report.json not found");
        return;
    }
    let v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report_path).expect("report.json readable"))
            .expect("report.json valid JSON");
    let main = v["stages"]
        .as_array()
        .and_then(|stages| stages.iter().find(|s| s["stage"] == "decompile"))
        .and_then(|s| s["images"].as_array())
        .and_then(|imgs| imgs.iter().find(|i| i["image"] == "02_MAIN"))
        .expect("02_MAIN entry missing from decompile stage");

    for key in [
        "global_types_applied",
        "global_types_candidates",
        "global_types_ineligible",
        "global_types_skipped",
    ] {
        assert!(
            main.get(key).is_some(),
            "{key} missing on 02_MAIN — global_types_apply_stage's report patch \
             is missing, or this tree predates Phase 3.2 type application: {main}"
        );
    }

    let applied = main["global_types_applied"]
        .as_u64()
        .expect("global_types_applied is a u64");
    let candidates = main["global_types_candidates"]
        .as_u64()
        .expect("global_types_candidates is a u64");
    let skipped = main["global_types_skipped"]
        .as_u64()
        .expect("global_types_skipped is a u64");

    assert_eq!(
        candidates,
        applied + skipped,
        "global_types_candidates must conserve applied + skipped on 02_MAIN: {main}"
    );
    assert!(
        applied <= candidates,
        "global_types_applied must not exceed global_types_candidates on 02_MAIN: {main}"
    );
    // The 270-of-274-inferred-globals-are-scalar-candidates split (1 array,
    // 3 unknown; task-9-brief.md, Fidelity/scope decisions) was measured on
    // the retained CHEETAH `01_MAIN` tree, not this test's MUSTANG `02_MAIN`
    // target — `02_MAIN` has a different, smaller inferred count (125 per
    // the Phase 3.2 production baseline in CONTRIBUTING.md) and no
    // independently measured scalar/array/unknown split of its own, so a
    // healthy run here applies some unmeasured number up to that ~125
    // ceiling, not the cheetah figure. Pin only the non-zero floor; a
    // tighter band would both babysit Ghidra's analysis nondeterminism and
    // require a `02_MAIN`-specific measurement this test doesn't have.
    assert!(
        applied >= 1,
        "expected at least one recovered global type applied on 02_MAIN, got {applied} \
         (candidates={candidates}, skipped={skipped}): {main}"
    );
    eprintln!("02_MAIN global_types: applied={applied} candidates={candidates} skipped={skipped}");
}

/// pme-paq-v1 equality of every pinned deterministic surface against a
/// reference (re-baselined) decomposed tree (`PME_DECOMPOSED_GOLDEN_DIR`).
/// Pinned surfaces are the **measured-deterministic** set (two fresh mustang
/// runs, 2026-08-18): `manifest.json` (pinned by blake3 content — pme-paq-v1
/// only hashes directories), `tokens/`, `rf/`, and
/// `ghidra/global_types_maps/`. Unpinned, with the measured reason:
/// `report.json` (wall-clock durations), `ghidra/` project residue,
/// `ghidra/symbol_maps/` (embeds the pass-1 `functions.json` digest, whose
/// content carries Ghidra run-to-run jitter — the symbol arrays themselves
/// reproduced byte-identically), `images/*/source_tree/` (recovered-code
/// enrichment derives from the same jittery Ghidra evidence), and everything
/// under `images/*/decompiled/`. See CONTRIBUTING "Hashing and golden
/// identity".
#[test]
fn decompose_pinned_surfaces_match_reference() {
    let Some(img) = std::env::var_os("PME_RADIO_IMG").map(PathBuf::from) else {
        eprintln!("skip: set PME_RADIO_IMG");
        return;
    };
    if !img.exists() {
        eprintln!("skip: PME_RADIO_IMG not found");
        return;
    }
    let Some(gold) = std::env::var_os("PME_DECOMPOSED_GOLDEN_DIR").map(PathBuf::from) else {
        eprintln!("skip: set PME_DECOMPOSED_GOLDEN_DIR");
        return;
    };
    if !gold.is_dir() {
        eprintln!("skip: PME_DECOMPOSED_GOLDEN_DIR not found");
        return;
    }
    if decompile::find_headless(None).is_err() || decompile::find_radare2().is_none() {
        eprintln!("skip: Ghidra and/or radare2 not available on this host");
        return;
    }
    let out = std::env::temp_dir().join(format!("pme_paq_golden_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out);
    let opts = decompose::Opts {
        no_verify: false,
        prune: false,
        ghidra_home: None,
        processor: "ARM:LE:32:v7".to_string(),
        no_symbol_pass: false,
        no_thumb_decompile: false,
        rizin_fallback: false,
        tighten_wall_clock_budget_override: None,
        globals_provisional: false,
        globals_k_arm: None,
        globals_k_thumb: None,
        no_apply_global_types: false,
        no_skip_opaque: false,
    };
    decompose::run(&img, &opts, &out).expect("decompose");
    let surfaces = ["manifest.json", "tokens", "rf", "ghidra/global_types_maps"];
    for rel in surfaces {
        let ours = out.join(rel);
        let theirs = gold.join(rel);
        if !theirs.exists() {
            continue; // model-dependent (e.g. rf/ absent on cheetah)
        }
        if ours.is_dir() {
            assert!(
                pixel_modem_extractor::tree_hash::pme_paq_v1(&ours).unwrap()
                    == pixel_modem_extractor::tree_hash::pme_paq_v1(&theirs).unwrap(),
                "pinned surface {rel} must reproduce the reference pme-paq-v1"
            );
        } else {
            assert_eq!(
                pixel_modem_extractor::manifest::blake3_bytes(&std::fs::read(&ours).unwrap()),
                pixel_modem_extractor::manifest::blake3_bytes(&std::fs::read(&theirs).unwrap()),
                "pinned surface {rel} must reproduce the reference bytes"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&out);
}
