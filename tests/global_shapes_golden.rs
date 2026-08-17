//! Read-only env-gated validation of retained or fresh `global_shapes.json`.
//!
//! Reads `$PME_GOLDEN_DIR` and never launches decompose. Skips cleanly when
//! the env is unset, the directory is absent, or the tree has no shape
//! sidecars (a pre-`global_shapes` corpus). The validator does not hardcode
//! a yield percentage.

use pixel_modem_extractor::global_shapes::{FORMAT_V3, validate_artifact};
use pixel_modem_extractor::manifest::sha256_bytes;
use serde_json::Value;
use std::path::{Path, PathBuf};

const STALE_V2_FORMAT: &str = "pixel-modem-extractor-global-shapes-v2";

fn golden_dir() -> Option<PathBuf> {
    let Some(dir) = std::env::var_os("PME_GOLDEN_DIR").map(PathBuf::from) else {
        eprintln!("skip: set PME_GOLDEN_DIR");
        return None;
    };
    if !dir.exists() {
        eprintln!("skip: PME_GOLDEN_DIR not found on disk: {}", dir.display());
        return None;
    }
    Some(dir)
}

fn load_report(dir: &Path) -> Option<Value> {
    let path = dir.join("report.json");
    if !path.exists() {
        eprintln!("skip: PME_GOLDEN_DIR/report.json not found");
        return None;
    }
    Some(
        serde_json::from_slice(&std::fs::read(&path).expect("report.json readable"))
            .expect("report.json valid JSON"),
    )
}

fn stages(report: &Value) -> &[Value] {
    report["stages"]
        .as_array()
        .expect("report.json stages must be an array")
}

fn stage_names(report: &Value) -> Vec<&str> {
    stages(report)
        .iter()
        .filter_map(|stage| stage["stage"].as_str())
        .collect()
}

fn decompile_images(report: &Value) -> &[Value] {
    stages(report)
        .iter()
        .find(|stage| stage["stage"] == "decompile")
        .and_then(|stage| stage["images"].as_array())
        .expect("decompile stage images must be an array")
}

fn sidecar_path(dir: &Path, label: &str) -> PathBuf {
    dir.join("images")
        .join(label)
        .join("decompiled")
        .join("global_shapes.json")
}

fn present_sidecars(dir: &Path, report: &Value) -> Vec<(String, PathBuf)> {
    decompile_images(report)
        .iter()
        .filter_map(|image| {
            let label = image["image"].as_str()?.to_owned();
            let path = sidecar_path(dir, &label);
            path.is_file().then_some((label, path))
        })
        .collect()
}

struct ShapesTree {
    dir: PathBuf,
    report: Value,
    sidecars: Vec<(String, PathBuf)>,
}

fn shapes_tree() -> Option<ShapesTree> {
    let dir = golden_dir()?;
    let report = load_report(&dir)?;
    let sidecars = present_sidecars(&dir, &report);
    if sidecars.is_empty() {
        eprintln!(
            "skip: no global_shapes.json sidecars under {}",
            dir.display()
        );
        return None;
    }
    Some(ShapesTree {
        dir,
        report,
        sidecars,
    })
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn report_image<'a>(report: &'a Value, label: &str) -> &'a Value {
    decompile_images(report)
        .iter()
        .find(|image| image["image"] == label)
        .unwrap_or_else(|| panic!("{label} missing from decompile stage"))
}

fn assert_stage_order(report: &Value) {
    let names = stage_names(report);
    if !names.contains(&"global_shapes") {
        return;
    }
    let shapes = names
        .iter()
        .position(|name| *name == "global_shapes")
        .unwrap();
    assert_eq!(
        names
            .iter()
            .filter(|name| **name == "global_shapes")
            .count(),
        1,
        "exactly one global_shapes stage: {names:?}"
    );
    // The entry is pushed by the route's FIRST sweep (right after `globals`,
    // before pass 2 on the normal route) and the final re-commit sweep —
    // which runs after pass 2 / thumb_enrich_post_pass2 rewrite the sidecar's
    // hashed inputs — replaces that entry in place, so the position always
    // pins to the first sweep's slot.
    let globals = names
        .iter()
        .position(|name| *name == "globals")
        .expect("globals must precede global_shapes");
    assert!(
        globals < shapes,
        "global_shapes must follow globals: {names:?}"
    );
    if let Some(thumb_pass1) = names.iter().position(|name| *name == "thumb_enrich") {
        assert!(
            thumb_pass1 < shapes,
            "global_shapes must follow the pass-1 thumb_enrich: {names:?}"
        );
    }
    // `decompile_pass2` is real only on the normal route; on
    // `--no-symbol-pass` it is an always-skipped stub pushed BEFORE
    // global_shapes (that route runs the stage last, once), so only the
    // normal route pins shapes before it. The stub is identifiable by its
    // `reason`, exactly as in tests/decompose_golden.rs.
    let no_symbol_route = stages(report)
        .iter()
        .find(|stage| stage["stage"] == "decompile_pass2")
        .and_then(|stage| stage["reason"].as_str())
        == Some("--no-symbol-pass");
    if !no_symbol_route {
        let pass2 = names
            .iter()
            .position(|name| *name == "decompile_pass2")
            .expect("normal route must run decompile_pass2");
        assert!(
            shapes < pass2,
            "global_shapes must precede decompile_pass2: {names:?}"
        );
    }
    for decoder in ["decode_rf", "hardware_config"] {
        if let Some(pos) = names.iter().position(|name| *name == decoder) {
            assert!(
                shapes < pos,
                "global_shapes must precede {decoder}: {names:?}"
            );
        }
    }
}

fn parse_stage_totals(output: &str) -> [u64; 9] {
    let mut totals = [0u64; 9];
    for (index, key) in [
        "inferred=",
        "no_evidence=",
        "conflicting=",
        "observations=",
        "ghidra_quarantined=",
        "thumb_quarantined=",
        "quarantine_errors=",
        "decode_failures=",
        "state_barriers=",
    ]
    .into_iter()
    .enumerate()
    {
        let start = output
            .find(key)
            .unwrap_or_else(|| panic!("stage output missing {key}: {output}"));
        let rest = &output[start + key.len()..];
        let end = rest
            .find([',', ')'])
            .unwrap_or_else(|| panic!("unterminated {key} in {output}"));
        totals[index] = rest[..end]
            .parse()
            .unwrap_or_else(|_| panic!("invalid {key} in {output}"));
    }
    totals
}

#[test]
fn artifacts_satisfy_v3_invariants() {
    let Some(tree) = shapes_tree() else {
        return;
    };
    for (label, path) in &tree.sidecars {
        let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert!(
            !bytes.ends_with(b"\n"),
            "{} must not have a trailing newline",
            path.display()
        );
        let artifact: Value =
            serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        if artifact["format"] == STALE_V2_FORMAT {
            eprintln!("stale v2 vintage sidecar skipped: {}", path.display());
            continue;
        }
        validate_artifact(&tree.dir, report_image(&tree.report, label), &artifact);
        assert!(is_sha256_hex(&sha256_bytes(&bytes)));
        assert_eq!(artifact["format"], FORMAT_V3);
    }
}

#[test]
fn report_stage_order_and_aggregate_totals() {
    let Some(tree) = shapes_tree() else {
        return;
    };
    assert_stage_order(&tree.report);
    let Some(stage) = stages(&tree.report)
        .iter()
        .find(|stage| stage["stage"] == "global_shapes")
    else {
        return;
    };
    let mut inferred = 0u64;
    let mut no_evidence = 0u64;
    let mut conflicting = 0u64;
    let mut observations = 0u64;
    let mut ghidra_quarantined = 0u64;
    let mut thumb_quarantined = 0u64;
    let mut quarantine_errors = 0u64;
    let mut decode_failures = 0u64;
    let mut state_barriers = 0u64;
    for image in decompile_images(&tree.report) {
        if image.get("global_shapes_error").is_some() {
            continue;
        }
        let Some(value) = image.get("global_shapes_inferred").and_then(Value::as_u64) else {
            continue;
        };
        inferred += value;
        no_evidence += image["global_shapes_no_evidence"].as_u64().unwrap();
        conflicting += image["global_shapes_conflicting"].as_u64().unwrap();
        observations += image["global_shape_observations"].as_u64().unwrap();
        ghidra_quarantined += image["global_shapes_ghidra_quarantined"].as_u64().unwrap();
        thumb_quarantined += image["global_shapes_thumb_quarantined"].as_u64().unwrap();
        quarantine_errors += image["global_shapes_quarantine_errors"].as_u64().unwrap();
        decode_failures += image["global_shapes_decode_failures"].as_u64().unwrap();
        state_barriers += image["global_shapes_state_barriers"].as_u64().unwrap();
    }
    if let Some(output) = stage["output"].as_str() {
        assert_eq!(
            parse_stage_totals(output),
            [
                inferred,
                no_evidence,
                conflicting,
                observations,
                ghidra_quarantined,
                thumb_quarantined,
                quarantine_errors,
                decode_failures,
                state_barriers,
            ]
        );
    }
    assert!(!tree.sidecars.is_empty());
}

#[test]
fn accepted_corpus_has_arm_and_thumb_observations() {
    let Some(tree) = shapes_tree() else {
        return;
    };
    let has_arm_inventory = decompile_images(&tree.report).iter().any(|image| {
        image
            .get("functions")
            .and_then(Value::as_u64)
            .is_some_and(|count| count > 0)
    });
    let has_thumb_inventory = decompile_images(&tree.report)
        .iter()
        .any(|image| image.get("thumb_functions").is_some());
    let has_recovered = decompile_images(&tree.report).iter().any(|image| {
        image
            .get("globals_recovered")
            .and_then(Value::as_u64)
            .is_some_and(|count| count > 0)
    });
    if !(has_arm_inventory && has_thumb_inventory && has_recovered) {
        eprintln!("skip: tree does not look like the accepted Mustang corpus");
        return;
    }
    let mut saw_arm = false;
    let mut saw_thumb = false;
    for (_label, path) in &tree.sidecars {
        let artifact: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        for global in artifact["globals"].as_array().expect("globals array") {
            for observation in global["observations"]
                .as_array()
                .expect("observations array")
            {
                match observation["arch"].as_str() {
                    Some("arm") => saw_arm = true,
                    Some("thumb") => saw_thumb = true,
                    _ => {}
                }
            }
        }
    }
    assert!(
        saw_arm && saw_thumb,
        "accepted Mustang corpus must have at least one ARM and one Thumb observation under {}",
        tree.dir.display()
    );
}
