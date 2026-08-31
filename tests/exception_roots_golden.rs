//! Private-corpus exception-root goldens for retained S5400 and S5300 MAIN images.

use serde_json::Value;
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;

const IMAGE_BASE: u32 = 0x4001_0000;

struct CorpusPin {
    env_var: &'static str,
    label: &'static str,
    toc_index: u32,
    manifest_blake3: &'static str,
}

const S5400: CorpusPin = CorpusPin {
    env_var: "PME_S5400_MAIN",
    label: "02_MAIN",
    toc_index: 3,
    manifest_blake3: "dfb5b19229432824e86394798a1545ce28cbceebe103aef02922b0cad391f402",
};

const S5300: CorpusPin = CorpusPin {
    env_var: "PME_S5300_MAIN",
    label: "01_MAIN",
    toc_index: 2,
    manifest_blake3: "2597eab66f60c7be950c9671e4f14d443eca4b7c826446f5e2bd65ae4c12516f",
};

#[test]
fn s5400_main_has_canonical_exception_roots() {
    assert_corpus(&S5400);
}

#[test]
fn s5300_main_has_canonical_exception_roots() {
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
    let image_size = u32::try_from(image.len()).expect("MAIN image size fits u32");

    let root = tempfile::tempdir().expect("temporary exception-root corpus root");
    let modem_path = root.path().join("modem.bin");
    fs::write(&modem_path, wrap_corpus_main(&image, pins.toc_index)).unwrap();
    let out = root.path().join("out");
    let report = pixel_modem_extractor::decompile::run_report(
        &modem_path,
        &pixel_modem_extractor::decompile::Opts {
            run: false,
            image: None,
            ghidra_home: None,
            processor: "ARM:LE:32:v7".to_string(),
            no_thumb_decompile: false,
            rizin_fallback: false,
            tighten_wall_clock_budget_override: None,
            no_skip_opaque: true,
        },
        &out,
    )
    .unwrap_or_else(|error| panic!("{} generation failed: {error}", pins.env_var));

    let expected_relative = format!("exception_roots/{}/roots.json", pins.label);
    let spec: Value = serde_json::from_slice(&fs::read(report.spec_path).unwrap()).unwrap();
    assert_eq!(spec["images"].as_array().unwrap().len(), 1);
    assert_eq!(
        spec["images"][0]["exception_root_map"], expected_relative,
        "the production kit must consume this run's manifest"
    );

    let manifest_path = out.join(&expected_relative);
    let manifest_bytes = fs::read(&manifest_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", manifest_path.display()));
    let manifest: Value = serde_json::from_slice(&manifest_bytes)
        .unwrap_or_else(|error| panic!("invalid {}: {error}", manifest_path.display()));
    assert_manifest_structure(&manifest, pins, image_size, &image);

    let observed = blake3::hash(&manifest_bytes).to_hex().to_string();
    assert_manifest_digest(pins, &observed);
}

fn wrap_corpus_main(image: &[u8], index: u32) -> Vec<u8> {
    let entry_offset = 0x20usize;
    let payload_offset = entry_offset + 0x20;
    let mut modem = vec![0; payload_offset + image.len()];
    modem[0..4].copy_from_slice(b"TOC\0");
    modem[0x1c..0x20].copy_from_slice(&1u32.to_le_bytes());
    modem[entry_offset..entry_offset + 4].copy_from_slice(b"MAIN");
    modem[entry_offset + 12..entry_offset + 16]
        .copy_from_slice(&(payload_offset as u32).to_le_bytes());
    modem[entry_offset + 16..entry_offset + 20].copy_from_slice(&IMAGE_BASE.to_le_bytes());
    modem[entry_offset + 20..entry_offset + 24]
        .copy_from_slice(&(image.len() as u32).to_le_bytes());
    modem[entry_offset + 28..entry_offset + 32].copy_from_slice(&index.to_le_bytes());
    modem[payload_offset..].copy_from_slice(image);
    modem
}

fn assert_manifest_structure(manifest: &Value, pins: &CorpusPin, image_size: u32, image: &[u8]) {
    const ROLES: [&str; 8] = [
        "reset",
        "undefined_instruction",
        "supervisor_call",
        "prefetch_abort",
        "data_abort",
        "reserved",
        "irq",
        "fiq",
    ];

    assert_eq!(
        manifest["format"],
        "pixel-modem-extractor-exception-roots-v1"
    );
    assert_eq!(manifest["image"]["label"], pins.label);
    assert_eq!(manifest["image"]["toc_name"], "MAIN");
    assert_eq!(manifest["image"]["base_addr"], "0x40010000");
    assert_eq!(manifest["image"]["size"], image_size);
    assert_eq!(
        manifest["image"]["blake3"],
        blake3::hash(image).to_hex().to_string(),
        "the manifest must authenticate the complete configured MAIN input"
    );

    let initial = &manifest["initial_table"];
    assert_eq!(initial["kind"], "initial");
    assert_eq!(initial["address"], "0x40010000");
    let tables = manifest["tables"].as_array().expect("tables array");
    assert_eq!(
        tables.len(),
        1,
        "the measured corpus has one complete table"
    );
    assert_eq!(
        &tables[0], initial,
        "the complete table is the initial table"
    );

    let slots = initial["slots"].as_array().expect("initial slots array");
    assert_eq!(slots.len(), ROLES.len());
    for (index, (slot, role)) in slots.iter().zip(ROLES).enumerate() {
        assert_eq!(slot["index"], index);
        assert_eq!(slot["role"], role);
        assert_eq!(slot["form"], "literal_load");
        assert!(slot["literal"].is_object());
        assert_eq!(
            parse_address(&slot["address"], "slot address"),
            IMAGE_BASE + u32::try_from(index).unwrap() * 4
        );
    }

    let relocation = &manifest["relocation"];
    assert_eq!(
        relocation["status"], "confirmed_initial",
        "unexpected relocation proof: {relocation}"
    );
    assert_eq!(relocation["table_address"], Value::Null);
    let selected = relocation["selected"]
        .as_object()
        .expect("selected VBAR proof");
    assert_eq!(selected["exact_value"], "0x40010000");
    assert_eq!(selected["conditional"], false);
    assert_eq!(selected["dominates_handoffs"], true);
    assert!(
        !relocation["observations"].as_array().unwrap().is_empty(),
        "confirmed-initial VBAR requires an observation"
    );

    let roots = manifest["roots"].as_array().expect("roots array");
    assert_eq!(roots.len(), ROLES.len(), "the measured roots are distinct");
    let root_keys = roots
        .iter()
        .map(|root| {
            (
                parse_address(&root["entry"], "root entry"),
                root["isa"].as_str().expect("root ISA").to_string(),
            )
        })
        .collect::<Vec<_>>();
    let mut sorted_root_keys = root_keys.clone();
    sorted_root_keys.sort();
    assert_eq!(root_keys, sorted_root_keys, "roots must be canonical");
    assert_eq!(
        root_keys.iter().cloned().collect::<BTreeSet<_>>().len(),
        ROLES.len(),
        "all measured roots are distinct by entry and ISA"
    );

    let claimed_roles = roots
        .iter()
        .flat_map(|root| root["claims"].as_array().expect("root claims"))
        .map(|claim| claim["role"].as_str().expect("claim role"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        roots
            .iter()
            .map(|root| root["claims"].as_array().unwrap().len())
            .sum::<usize>(),
        ROLES.len(),
        "root claims must conserve the eight table slots"
    );
    assert_eq!(claimed_roles, ROLES.into_iter().collect());

    let applications = manifest["applications"]
        .as_array()
        .expect("applications array");
    assert_eq!(applications.len(), roots.len());
    let application_keys = applications
        .iter()
        .map(|application| {
            (
                parse_address(&application["entry"], "application entry"),
                application["isa"]
                    .as_str()
                    .expect("application ISA")
                    .to_string(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        application_keys, root_keys,
        "applications must follow root order"
    );
    assert_eq!(
        applications
            .iter()
            .map(|application| application["claims"].as_array().unwrap().len())
            .sum::<usize>(),
        ROLES.len(),
        "applications must conserve every table role"
    );
    assert!(applications.iter().all(|application| {
        application["desired_primary"].is_string()
            && application["role_labels"]
                .as_array()
                .is_some_and(|labels| labels.len() == 1)
    }));
}

fn parse_address(value: &Value, what: &str) -> u32 {
    u32::from_str_radix(
        value
            .as_str()
            .unwrap_or_else(|| panic!("{what} must be a string"))
            .strip_prefix("0x")
            .unwrap_or_else(|| panic!("{what} must start with 0x")),
        16,
    )
    .unwrap_or_else(|error| panic!("{what} is invalid: {error}"))
}

fn assert_manifest_digest(pins: &CorpusPin, observed: &str) {
    if pins.manifest_blake3.is_empty() {
        eprintln!(
            "PIN UNPOPULATED: {} exception-root manifest BLAKE3 = {observed}",
            pins.env_var
        );
        panic!(
            "{} corpus ran but its exception-root manifest digest sentinel is empty",
            pins.env_var
        );
    }
    assert_eq!(
        observed, pins.manifest_blake3,
        "{} canonical exception-root manifest BLAKE3",
        pins.env_var
    );
}

fn corpus_path_value(env_var: &str, value: Option<OsString>) -> Result<Option<PathBuf>, String> {
    let Some(path) = value.map(PathBuf::from) else {
        eprintln!("UNRUN: {env_var} is unset");
        return Ok(None);
    };
    match std::fs::metadata(&path) {
        Ok(metadata) if metadata.is_file() => Ok(Some(path)),
        Ok(_) => Err(format!(
            "{env_var} input is not a regular file: {}",
            path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("UNRUN: {env_var} input does not exist: {}", path.display());
            Ok(None)
        }
        Err(error) => Err(format!(
            "failed to inspect {env_var} input {}: {error}",
            path.display()
        )),
    }
}

#[test]
fn no_corpus_environment_skips_independently_and_rejects_nonregular_inputs() {
    assert_eq!(corpus_path_value("PME_S5400_MAIN", None).unwrap(), None);
    assert_eq!(corpus_path_value("PME_S5300_MAIN", None).unwrap(), None);

    let root = tempfile::tempdir().unwrap();
    let s5400 = root.path().join("s5400.bin");
    std::fs::write(&s5400, b"image").unwrap();

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

    let missing = root.path().join("missing.bin");
    assert_eq!(
        corpus_path_value("PME_S5300_MAIN", Some(missing.into_os_string())).unwrap(),
        None,
        "a configured missing input remains an explicit skip"
    );

    let error = corpus_path_value(
        "PME_S5300_MAIN",
        Some(root.path().as_os_str().to_os_string()),
    )
    .unwrap_err();
    assert!(error.contains("not a regular file"), "{error}");
}
