//! Private-corpus ss specialized-name goldens for retained S5400 and S5300 MAIN images.
//!
//! Path: production scatter + `ss::discover` at load `0x40010000`. Inventory-free pins
//! are helper entry/ISA and callsite count. Inventory-gated pins (`PME_DECOMPOSED_GOLDEN_DIR`)
//! are recovered/conflicts. Empty sentinels until a lawful run prints `PIN OBSERVED`.
//! Only an unset variable skips; a set missing/non-regular/symlink path fails.
//! Never infer a corpus pass from a clean env-gated skip. No firmware names.

use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;

const IMAGE_BASE: u32 = 0x4001_0000;

struct CorpusPin {
    env_var: &'static str,
    label: &'static str,
    helper_entry: &'static str,
    helper_isa: &'static str,
    callsites: &'static str,
    recovered: &'static str,
    conflicts: &'static str,
}

const S5400: CorpusPin = CorpusPin {
    env_var: "PME_S5400_MAIN",
    label: "02_MAIN",
    helper_entry: "",
    helper_isa: "",
    callsites: "",
    recovered: "",
    conflicts: "",
};

const S5300: CorpusPin = CorpusPin {
    env_var: "PME_S5300_MAIN",
    label: "01_MAIN",
    helper_entry: "",
    helper_isa: "",
    callsites: "",
    recovered: "",
    conflicts: "",
};

#[test]
fn s5400_ss_names_pins_are_structural() {
    assert_corpus(&S5400);
}

#[test]
fn s5300_ss_names_pins_are_structural() {
    assert_corpus(&S5300);
}

fn assert_corpus(pins: &CorpusPin) {
    let Some(path) = corpus_path_value(pins.env_var, std::env::var_os(pins.env_var))
        .unwrap_or_else(|error| panic!("{error}"))
    else {
        return;
    };
    let image = fs::read(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    let inventories = inventories_dir(pins.label).unwrap_or_else(|error| panic!("{error}"));
    let report = pixel_modem_extractor::symbolicate::generate_ss_names_corpus(
        &image,
        IMAGE_BASE,
        inventories.as_deref(),
    )
    .unwrap_or_else(|error| panic!("{} generation failed: {error}", pins.env_var));

    if let Some(error) = &report.error {
        panic!("{} generation failed: {error}", pins.env_var);
    }

    if report.helper_entry.is_none() {
        eprintln!("PIN OBSERVED: {} status=absent", pins.env_var);
        assert!(
            pins.helper_entry.is_empty() && pins.helper_isa.is_empty() && pins.callsites.is_empty(),
            "{} generation was clean absence but a Present pin is populated",
            pins.env_var
        );
        return;
    }

    let observed_entry = report.helper_entry.as_deref().unwrap_or_default();
    let observed_isa = report.helper_isa.as_deref().unwrap_or_default();
    let observed_callsites = report
        .callsites
        .map(|value| value.to_string())
        .unwrap_or_default();
    let observed_recovered = report
        .recovered
        .map(|value| value.to_string())
        .unwrap_or_default();
    let observed_conflicts = report
        .conflicts
        .map(|value| value.to_string())
        .unwrap_or_default();
    eprintln!(
        "PIN OBSERVED: {} helper_entry={} helper_isa={} callsites={} recovered={} conflicts={}",
        pins.env_var,
        observed_entry,
        observed_isa,
        observed_callsites,
        observed_recovered,
        observed_conflicts
    );
    pin_or_observe("helper_entry", pins.helper_entry, observed_entry);
    pin_or_observe("helper_isa", pins.helper_isa, observed_isa);
    pin_or_observe("callsites", pins.callsites, &observed_callsites);
    if inventories.is_some() {
        pin_or_observe("recovered", pins.recovered, &observed_recovered);
        pin_or_observe("conflicts", pins.conflicts, &observed_conflicts);
    }
}

fn pin_or_observe(name: &str, expected: &str, observed: &str) {
    if expected.is_empty() {
        return;
    }
    assert_eq!(observed, expected, "pin mismatch: {name}");
}

fn corpus_path_value(env_var: &str, value: Option<OsString>) -> Result<Option<PathBuf>, String> {
    let Some(value) = value else {
        eprintln!("UNRUN: {env_var} is unset");
        return Ok(None);
    };
    let path = PathBuf::from(
        value
            .into_string()
            .map_err(|_| format!("{env_var} input path is not valid Unicode"))?,
    );
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(format!(
            "{env_var} input is a symlink, expected a regular file: {}",
            path.display()
        )),
        Ok(metadata) if metadata.is_file() => Ok(Some(path)),
        Ok(_) => Err(format!(
            "{env_var} input is not a regular file: {}",
            path.display()
        )),
        Err(error) => Err(format!(
            "failed to inspect configured {env_var} input {}: {error}",
            path.display()
        )),
    }
}

fn inventories_dir(label: &str) -> Result<Option<PathBuf>, String> {
    let Some(root) = inventory_root_value(std::env::var_os("PME_DECOMPOSED_GOLDEN_DIR"))? else {
        return Ok(None);
    };
    for dir in [
        root.join("images").join(label).join("decompiled"),
        root.join("decompiled"),
    ] {
        match std::fs::symlink_metadata(&dir) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!(
                    "PME_DECOMPOSED_GOLDEN_DIR inventory is a symlink, expected a regular directory: {}",
                    dir.display()
                ));
            }
            Ok(metadata) if metadata.is_dir() => {
                let functions = dir.join("functions.json");
                match std::fs::symlink_metadata(&functions) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        return Err(format!(
                            "PME_DECOMPOSED_GOLDEN_DIR functions.json is a symlink, expected a regular file: {}",
                            functions.display()
                        ));
                    }
                    Ok(metadata) if metadata.is_file() => return Ok(Some(dir)),
                    Ok(_) => {
                        return Err(format!(
                            "PME_DECOMPOSED_GOLDEN_DIR functions.json is not a regular file: {}",
                            functions.display()
                        ));
                    }
                    Err(_) => {}
                }
            }
            Ok(_) => {
                return Err(format!(
                    "PME_DECOMPOSED_GOLDEN_DIR inventory is not a directory: {}",
                    dir.display()
                ));
            }
            Err(_) => {}
        }
    }
    eprintln!("UNRUN: no function inventories under PME_DECOMPOSED_GOLDEN_DIR for {label}");
    Ok(None)
}

fn inventory_root_value(value: Option<OsString>) -> Result<Option<PathBuf>, String> {
    let Some(value) = value else {
        eprintln!("UNRUN: PME_DECOMPOSED_GOLDEN_DIR is unset");
        return Ok(None);
    };
    let path =
        PathBuf::from(value.into_string().map_err(|_| {
            "PME_DECOMPOSED_GOLDEN_DIR input path is not valid Unicode".to_string()
        })?);
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(format!(
            "PME_DECOMPOSED_GOLDEN_DIR input is a symlink, expected a directory: {}",
            path.display()
        )),
        Ok(metadata) if metadata.is_dir() => Ok(Some(path)),
        Ok(_) => Err(format!(
            "PME_DECOMPOSED_GOLDEN_DIR input is not a directory: {}",
            path.display()
        )),
        Err(error) => Err(format!(
            "failed to inspect configured PME_DECOMPOSED_GOLDEN_DIR input {}: {error}",
            path.display()
        )),
    }
}

#[test]
fn no_corpus_environment_skips_independently() {
    assert_eq!(corpus_path_value("PME_S5400_MAIN", None).unwrap(), None);
    assert_eq!(corpus_path_value("PME_S5300_MAIN", None).unwrap(), None);
    assert_eq!(inventory_root_value(None).unwrap(), None);

    let root = tempfile::tempdir().unwrap();
    let s5400 = root.path().join("s5400.bin");
    fs::write(&s5400, b"image").unwrap();

    assert_eq!(
        corpus_path_value("PME_S5400_MAIN", Some(s5400.clone().into_os_string())).unwrap(),
        Some(s5400),
        "a configured regular S5400 input must run"
    );
    assert_eq!(
        corpus_path_value("PME_S5300_MAIN", None).unwrap(),
        None,
        "the unavailable S5300 leg must still skip independently"
    );
    assert_eq!(
        inventory_root_value(None).unwrap(),
        None,
        "unset inventories must skip independently of a configured MAIN"
    );

    let missing = root.path().join("missing.bin");
    let error = corpus_path_value("PME_S5300_MAIN", Some(missing.into_os_string())).unwrap_err();
    assert!(
        error.contains("failed to inspect configured PME_S5300_MAIN input"),
        "unexpected configured-missing error: {error}"
    );

    let error = corpus_path_value(
        "PME_S5300_MAIN",
        Some(root.path().as_os_str().to_os_string()),
    )
    .unwrap_err();
    assert!(error.contains("not a regular file"), "{error}");

    let error =
        inventory_root_value(Some(root.path().join("missing-dir").into_os_string())).unwrap_err();
    assert!(
        error.contains("failed to inspect configured PME_DECOMPOSED_GOLDEN_DIR input"),
        "unexpected configured-missing inventory error: {error}"
    );

    let error =
        inventory_root_value(Some(root.path().join("s5400.bin").into_os_string())).unwrap_err();
    assert!(
        error.contains("not a directory"),
        "unexpected configured-file inventory error: {error}"
    );
}

#[cfg(unix)]
#[test]
fn configured_corpus_symlink_to_regular_file_is_rejected() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let regular = root.path().join("main.bin");
    let link = root.path().join("main-link.bin");
    fs::write(&regular, b"image").unwrap();
    symlink(&regular, &link).unwrap();

    let error = corpus_path_value("PME_S5400_MAIN", Some(link.into_os_string())).unwrap_err();
    assert!(
        error.contains("is a symlink, expected a regular file"),
        "unexpected configured-symlink error: {error}"
    );

    let dir_link = root.path().join("dir-link");
    symlink(root.path(), &dir_link).unwrap();
    let error = inventory_root_value(Some(dir_link.into_os_string())).unwrap_err();
    assert!(
        error.contains("is a symlink, expected a directory"),
        "unexpected configured-symlink inventory error: {error}"
    );
}
