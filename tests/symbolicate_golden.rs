//! Golden: symbolicate a real decompose tree supplied from outside the repo.
//! Set PME_DECOMPOSED_DIR to a `decompose` output root (with images/02_MAIN,
//! manifest.json) and PME_TOKEN_DB to the raw pw_token_db. Skips otherwise.
use std::path::PathBuf;

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

    pixel_modem_extractor::symbolicate::run(
        &root,
        &pixel_modem_extractor::symbolicate::Opts {
            token_db,
            rewrite_decompiled_c: true,
        },
    )
    .unwrap();

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
}
