//! Golden: symbolicate a real decompose tree supplied from outside the repo.
//! Set PME_DECOMPOSED_DIR to a `decompose` output root (with images/02_MAIN,
//! manifest.json) and PME_TOKEN_DB to the raw pw_token_db. Skips otherwise.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn assert_manifest_evidence(image_dir: &Path, relative: &str, kind: &str) -> bool {
    let manifest = image_dir.join(relative);
    if !manifest.is_file() {
        return false;
    }
    let manifest_blake3 = blake3::hash(&std::fs::read(&manifest).unwrap()).to_string();
    let symbols: serde_json::Value =
        serde_json::from_slice(&std::fs::read(image_dir.join("decompiled/symbols.json")).unwrap())
            .unwrap();
    let matched = symbols["symbols"].as_array().unwrap().iter().any(|symbol| {
        symbol["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .any(|evidence| {
                if evidence["kind"] != kind {
                    return false;
                }
                if kind == "pal_task" {
                    evidence["task"]["manifest_blake3"].as_str() == Some(&manifest_blake3)
                } else {
                    evidence["manifest_blake3"].as_str() == Some(&manifest_blake3)
                }
            })
    });
    assert!(
        matched,
        "{kind} evidence bound to {} is absent from final symbols.json",
        manifest.display()
    );
    true
}

#[test]
fn symbolicate_recovers_names_and_annotations() {
    let Some(root) = std::env::var_os("PME_DECOMPOSED_DIR").map(PathBuf::from) else {
        eprintln!("skip: set PME_DECOMPOSED_DIR");
        return;
    };
    let token_db = std::env::var_os("PME_TOKEN_DB").map(PathBuf::from);
    let dec = root.join("images/02_MAIN/decompiled");
    if !dec.join("functions.json").exists() {
        eprintln!("skip: no 02_MAIN decompiled artifacts");
        return;
    }

    let opts = pixel_modem_extractor::symbolicate::Opts {
        token_db,
        rewrite_decompiled_c: true,
    };
    pixel_modem_extractor::symbolicate::run(&root, &opts).unwrap();

    let v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dec.join("symbols.json")).unwrap()).unwrap();
    // At least some provisional (token) names on the real firmware.
    assert!(
        v["counts"]["named_provisional"].as_u64().unwrap_or(0) > 0,
        "expected token-derived provisional names"
    );
    // Every provisional name is marked.
    for s in v["symbols"].as_array().unwrap() {
        if s["tier"] == "provisional" {
            assert!(
                s["name"].as_str().unwrap().starts_with("guess_"),
                "unmarked provisional name: {s}"
            );
        }
    }

    let mut role_manifests = 0usize;
    let mut first_artifacts = BTreeMap::new();
    for entry in std::fs::read_dir(root.join("images")).unwrap() {
        let image_dir = entry.unwrap().path();
        if !image_dir.join("decompiled/functions.json").is_file() {
            continue;
        }
        role_manifests += usize::from(assert_manifest_evidence(
            &image_dir,
            "exception_roots/roots.json",
            "exception_root",
        ));
        role_manifests += usize::from(assert_manifest_evidence(
            &image_dir,
            "pal_tasks/tasks.json",
            "pal_task",
        ));
        let decompiled = image_dir.join("decompiled");
        for name in [
            "functions.json",
            "thumb_functions.json",
            "decompiled.c",
            "disasm.lst",
            "symbols.json",
        ] {
            let path = decompiled.join(name);
            if path.is_file() {
                first_artifacts.insert(path.clone(), std::fs::read(path).unwrap());
            }
        }
    }
    if role_manifests == 0 {
        eprintln!("note: retained tree has no role manifests");
    }

    pixel_modem_extractor::symbolicate::run(&root, &opts).unwrap();
    for (path, first) in first_artifacts {
        assert_eq!(
            std::fs::read(&path).unwrap(),
            first,
            "second standalone run changed {}",
            path.display()
        );
    }
}
