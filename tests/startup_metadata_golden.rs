//! Private-corpus startup-metadata goldens for retained S5400 and S5300 MAIN images.

use pixel_modem_extractor::toc::Toc;
use serde_json::Value;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;

const IMAGE_BASE: u32 = 0x4001_0000;

struct CorpusPin {
    env_var: &'static str,
    label: &'static str,
    toc_index: u32,
    warm_boot_seed: bool,
    stack_guard_seed: bool,
    rvct_seed: bool,
    shannon_os_seed: bool,
    hardware_init: &'static str,
    stack_guard: &'static str,
    compiler: &'static str,
    privileged_ops: Option<usize>,
    named_roots: Option<usize>,
    no_return_roots: Option<usize>,
    manifest_blake3: &'static str,
}

const S5400: CorpusPin = CorpusPin {
    env_var: "PME_S5400_MAIN",
    label: "02_MAIN",
    toc_index: 3,
    warm_boot_seed: true,
    stack_guard_seed: true,
    rvct_seed: true,
    shannon_os_seed: false,
    hardware_init: "",
    stack_guard: "",
    compiler: "",
    privileged_ops: None,
    named_roots: None,
    no_return_roots: None,
    manifest_blake3: "",
};

const S5300: CorpusPin = CorpusPin {
    env_var: "PME_S5300_MAIN",
    label: "01_MAIN",
    toc_index: 2,
    warm_boot_seed: true,
    stack_guard_seed: true,
    rvct_seed: true,
    shannon_os_seed: false,
    hardware_init: "",
    stack_guard: "",
    compiler: "",
    privileged_ops: None,
    named_roots: None,
    no_return_roots: None,
    manifest_blake3: "",
};

#[test]
fn s5400_startup_metadata_pins_are_structural() {
    assert_corpus(&S5400);
}

#[test]
fn s5300_startup_metadata_pins_are_structural() {
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

    let wrapped = wrap_corpus_main(&image, pins.toc_index);
    let toc = Toc::parse(&wrapped).expect("TOC-wrapped MAIN must parse");
    assert_eq!(toc.entries.len(), 1);
    assert_eq!(toc.entries[0].name, "MAIN");
    assert_eq!(toc.entries[0].label(), pins.label);
    assert_eq!(toc.entries[0].load_addr, IMAGE_BASE);
    let payload_offset = toc.entries[0].offset as usize;
    let payload_end = payload_offset + image.len();
    assert_eq!(&wrapped[payload_offset..payload_end], image.as_slice());

    let inventories = inventories_dir(pins.label).unwrap_or_else(|error| panic!("{error}"));
    let root = tempfile::tempdir().expect("temporary startup-metadata corpus root");
    let report = pixel_modem_extractor::generate_startup_metadata(
        &image,
        IMAGE_BASE,
        pins.label,
        "MAIN",
        inventories.as_deref(),
        root.path(),
    )
    .unwrap_or_else(|error| panic!("{} generation failed: {error}", pins.env_var));

    assert_eq!(report.seeds.warm_boot, pins.warm_boot_seed);
    assert_eq!(report.seeds.stack_guard, pins.stack_guard_seed);
    assert_eq!(report.seeds.rvct, pins.rvct_seed);
    assert_eq!(report.seeds.shannon_os, pins.shannon_os_seed);

    if inventories.is_none() {
        assert_eq!(
            report.privileged_ops, 0,
            "{} privileged ops on raw without inventories must be empty",
            pins.env_var
        );
        return;
    }

    let artifact = report.artifact.as_ref().unwrap_or_else(|| {
        panic!(
            "{} inventories were present but no startup artifact was published",
            pins.env_var
        )
    });

    let manifest_path = root.path().join(&artifact.relative_path);
    let manifest_bytes = fs::read(&manifest_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", manifest_path.display()));
    let manifest: Value = serde_json::from_slice(&manifest_bytes)
        .unwrap_or_else(|error| panic!("invalid {}: {error}", manifest_path.display()));
    let observed = blake3::hash(&manifest_bytes).to_hex().to_string();
    eprintln!(
        "PIN OBSERVED: {} hardware_init={} stack_guard={} compiler={} privileged_ops={} named_roots={} no_return_roots={} identity={} manifest_blake3={}",
        pins.env_var,
        artifact.hardware_init_status,
        artifact.stack_guard_status,
        artifact.compiler_status,
        artifact.privileged_ops,
        artifact.named_roots,
        artifact.no_return_roots,
        artifact.identity,
        observed
    );
    assert_eq!(artifact.manifest_blake3, observed);
    assert_eq!(
        artifact.identity,
        format!(
            "v1:{observed}:{}:{}:{}",
            artifact.named_roots, artifact.no_return_roots, artifact.privileged_ops
        )
    );
    assert_eq!(report.privileged_ops, artifact.privileged_ops);
    assert_eq!(
        manifest["format"],
        "pixel-modem-extractor-startup-metadata-v1"
    );
    assert_eq!(manifest["image"]["label"], pins.label);
    assert_eq!(manifest["image"]["toc_name"], "MAIN");
    assert_eq!(manifest["image"]["base_addr"], "0x40010000");
    assert_eq!(
        manifest["hardware_init"]["status"].as_str(),
        Some(artifact.hardware_init_status)
    );
    assert_eq!(
        manifest["stack_guard"]["status"].as_str(),
        Some(artifact.stack_guard_status)
    );
    assert_eq!(
        manifest["compiler"]["status"].as_str(),
        Some(artifact.compiler_status)
    );
    assert_eq!(
        manifest["privileged_ops"]
            .as_array()
            .expect("privileged_ops array")
            .len(),
        artifact.privileged_ops
    );
    assert_eq!(
        manifest["applications"]
            .as_array()
            .expect("applications array")
            .len(),
        artifact.named_roots
    );
    assert_inventory_pins(pins, artifact, &observed);
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

fn assert_inventory_pins(
    pins: &CorpusPin,
    artifact: &pixel_modem_extractor::StartupCorpusArtifact,
    observed: &str,
) {
    let unpopulated = pins.hardware_init.is_empty()
        || pins.stack_guard.is_empty()
        || pins.compiler.is_empty()
        || pins.privileged_ops.is_none()
        || pins.named_roots.is_none()
        || pins.no_return_roots.is_none()
        || pins.manifest_blake3.is_empty();
    if unpopulated {
        panic!(
            "{} corpus ran with unpopulated inventory pins; copy the PIN OBSERVED line",
            pins.env_var
        );
    }
    assert_eq!(
        artifact.hardware_init_status, pins.hardware_init,
        "{} hardware_init status",
        pins.env_var
    );
    assert_eq!(
        artifact.stack_guard_status, pins.stack_guard,
        "{} stack_guard status",
        pins.env_var
    );
    assert_eq!(
        artifact.compiler_status, pins.compiler,
        "{} compiler status",
        pins.env_var
    );
    assert_eq!(
        Some(artifact.privileged_ops),
        pins.privileged_ops,
        "{} privileged_ops",
        pins.env_var
    );
    assert_eq!(
        Some(artifact.named_roots),
        pins.named_roots,
        "{} named_roots",
        pins.env_var
    );
    assert_eq!(
        Some(artifact.no_return_roots),
        pins.no_return_roots,
        "{} no_return_roots",
        pins.env_var
    );
    assert_eq!(
        observed, pins.manifest_blake3,
        "{} canonical startup-metadata manifest BLAKE3",
        pins.env_var
    );
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

    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        use std::os::unix::fs::symlink;

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

        let error =
            corpus_path_value("PME_S5300_MAIN", Some(OsString::from_vec(vec![0xff]))).unwrap_err();
        assert!(
            error.contains("PME_S5300_MAIN input path is not valid Unicode"),
            "unexpected configured-non-UTF-8 error: {error}"
        );
    }
}
