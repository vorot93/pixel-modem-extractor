//! Opt-in exact corpus pins for retained S5400 and S5300 MAIN images.

use pixel_modem_extractor::scatter::{self, HandlerMap, LoadPlan, Operation};
use serde_json::{Value, json};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use tempfile::tempdir;

#[derive(Clone, Copy)]
struct AddressPin {
    value: u32,
    json: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExpectedOperation {
    Null,
    Copy,
    Decompress1,
    Zero,
}

impl ExpectedOperation {
    fn json(self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Copy => "copy",
            Self::Decompress1 => "decompress1",
            Self::Zero => "zero",
        }
    }

    fn production(self) -> Operation {
        match self {
            Self::Null => Operation::Null,
            Self::Copy => Operation::Copy,
            Self::Decompress1 => Operation::Decompress1,
            Self::Zero => Operation::Zero,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExpectedDescriptor {
    source: u32,
    destination: u32,
    size: u32,
    handler: u32,
    operation: ExpectedOperation,
}

struct CorpusPins {
    env_var: &'static str,
    label: &'static str,
    manifest_path: &'static str,
    source_blake3: &'static str,
    image_base: AddressPin,
    loader: AddressPin,
    literal_pair: AddressPin,
    table_start: AddressPin,
    table_end: AddressPin,
    null_handler: AddressPin,
    copy_handler: AddressPin,
    decompress1_handler: AddressPin,
    zero_handler: AddressPin,
    entry_count: usize,
    self_copy_entries: &'static [usize],
    none_entries: &'static [usize],
    file_entries: &'static [usize],
    zero_fill_entries: &'static [usize],
    copy_total: u64,
    decompress1_total: u64,
    compressed_total: u64,
    zero_total: u64,
    logical_total: u64,
    output_hashes: &'static [(usize, &'static str)],
}

#[derive(Debug, PartialEq, Eq)]
struct Totals {
    copy: u64,
    decompress1: u64,
    zero: u64,
    logical: u64,
}

const IMAGE_BASE: AddressPin = AddressPin {
    value: 0x4001_0000,
    json: "0x40010000",
};

const S5400_OUTPUT_HASHES: &[(usize, &str)] = &[
    (
        2,
        "73919af90e1fee9f2c6585e4534a6fa9e04931c0090b9c7ab9e631b16d8c8da0",
    ),
    (
        3,
        "043b854068acbd1114139798af58e6a874e56542616fb70b1c83868d9d066613",
    ),
    (
        4,
        "54759e25c1cefbc865e0ea679f31261920c13142ab1a4ec8869e8eda428f4423",
    ),
    (
        5,
        "272dce0559ee49e861556e3b50f832c08248c996680b1c5b636c0425efe5ca75",
    ),
    (
        6,
        "55a60b524884928742ea974ef100d848eb8a67b97e8097ddeac80d3a69c83340",
    ),
    (
        7,
        "5200bd41849466ac13ed61842dff70e21c73ccb893b134d2f28e9be9d5dc10d4",
    ),
    (
        8,
        "9d3aa443c914cd13ea3683de12e1974b5a21d1e6d6cb1e0649708f6f8421a236",
    ),
    (
        9,
        "dbf4296abe8651f4511d705c886e838b99182d161471accdadd6eabc4122f4b6",
    ),
    (
        10,
        "b0fdccd1399a65bef7ea3f711091fd38f00a3d927d058c7b61da9aa716974fc4",
    ),
    (
        11,
        "2f57df7a7fa265617f418bce70b3244f4cf442ee0cbc518ddc87c73ec59f0592",
    ),
    (
        12,
        "09433175ce27892a2a33341352bb2c67e59d21f2520c104c3a4373b275987c4a",
    ),
    (
        13,
        "11f7c7085e85f8f54a816086351810cb5415bc59fee815f6bef9f11b9794e731",
    ),
    (
        14,
        "25fb0650f0a0bdcf248e9912d5b65d518798b3993d9bca21fddaad4e6740f60c",
    ),
    (
        15,
        "d96610738764229fcc61b344b194f7a9af583927f65d0b15ba9c569adad4d46e",
    ),
    (
        16,
        "fa220900d0e5c248b805669e2484b0383d8ea3bf61a61541985047026ccc1626",
    ),
    (
        17,
        "fbe81ba7278c2fab08c7fb02643ec855ec3a4a2a8e34b9bc497993ca683b6835",
    ),
    (
        18,
        "f1d50871826786b03f9c3791b2ce929beee2b69791eed2f252e3572f895fc412",
    ),
    (
        19,
        "b4e1c811f7cee4c4f6a4959648ce14919591efbc779066f8a0ecc64b649813de",
    ),
    (
        20,
        "b4bb8848c239cd5d40d66704a2bf5557a57da7697d55823c34ef703807ebab8c",
    ),
    (
        21,
        "6c2a43cfae17ed0a27beda0e6eb753bfbbc109091e5684c9e9701934e91454c1",
    ),
    (
        22,
        "e65e0f6da2dc3519ddf56e30b6ddeece41f2085c96aed4cbb67d20e19ddbe478",
    ),
];

const S5300_OUTPUT_HASHES: &[(usize, &str)] = &[
    (
        2,
        "73919af90e1fee9f2c6585e4534a6fa9e04931c0090b9c7ab9e631b16d8c8da0",
    ),
    (
        3,
        "6987f087bcebc950cc9c06e9741bd043da36fe31dd71dcc949c6a2cbec8976d9",
    ),
    (
        4,
        "73919af90e1fee9f2c6585e4534a6fa9e04931c0090b9c7ab9e631b16d8c8da0",
    ),
    (
        5,
        "decd5c342d9ac276472869206e9d1da2983c5f2b6cdff09cc6d5e5a39912847b",
    ),
    (
        6,
        "7d5c223384d8fc02a0f8306413a1dde4d28660101248fbcca89c090650b932dc",
    ),
    (
        7,
        "75e674ae3dd00cf6d8ac6273a2c784304cda304ac0c7af595a007dc9500bde6d",
    ),
    (
        8,
        "4896eca995fffb4e15ae26324a1b37091c522a3df8c6fc5e4b801c183a17607b",
    ),
    (
        9,
        "6ac17381d7323906a907e0234f85e0e2dfe76cdd581e6464af80cb06eb180018",
    ),
    (
        10,
        "65e6759038cbcf9cf5af60a317a4cf9ab7eda54468410306319b05839d2dbfa2",
    ),
    (
        11,
        "a5399ef119852c7847831dd933026e9b4de108453e402d8020f2469bbcc4a6ad",
    ),
    (
        12,
        "800a1c75a4417729882ac8a6b5d9c03e25fc610e354c5e9be4e66e424a7c5f69",
    ),
    (
        13,
        "d96610738764229fcc61b344b194f7a9af583927f65d0b15ba9c569adad4d46e",
    ),
    (
        14,
        "fa220900d0e5c248b805669e2484b0383d8ea3bf61a61541985047026ccc1626",
    ),
    (
        15,
        "fbe81ba7278c2fab08c7fb02643ec855ec3a4a2a8e34b9bc497993ca683b6835",
    ),
    (
        16,
        "f1d50871826786b03f9c3791b2ce929beee2b69791eed2f252e3572f895fc412",
    ),
    (
        17,
        "b4e1c811f7cee4c4f6a4959648ce14919591efbc779066f8a0ecc64b649813de",
    ),
    (
        18,
        "bd174bc7ae07e743668553e970363f140707ee3c295e607e94a024c97e9d7a35",
    ),
    (
        19,
        "a5a660f21ad0cb8759b082233650c1d43c05500e1c31e8701173ddba4ef2c427",
    ),
    (
        20,
        "07e273dfe9b1a556ff9a3e29144597664ef39c686296a8fe7b2f9952b8b736c1",
    ),
    (
        21,
        "2a9ef94cb5832b2642d1c2285bd2d0ca83eb09a3a94e01c2238cf26e9c517067",
    ),
];

const S5400: CorpusPins = CorpusPins {
    env_var: "PME_S5400_MAIN",
    label: "02_MAIN",
    manifest_path: "scatter/02_MAIN/load_map.json",
    source_blake3: "efdf5ce38548d393b5e473597e0efe61f13e09db8d6e805c927eb76303687dd0",
    image_base: IMAGE_BASE,
    loader: AddressPin {
        value: 0x4393_1eb0,
        json: "0x43931eb0",
    },
    literal_pair: AddressPin {
        value: 0x4393_1f14,
        json: "0x43931f14",
    },
    table_start: AddressPin {
        value: 0x40e1_8948,
        json: "0x40e18948",
    },
    table_end: AddressPin {
        value: 0x40e1_8ab8,
        json: "0x40e18ab8",
    },
    null_handler: AddressPin {
        value: 0x4393_1fb8,
        json: "0x43931fb8",
    },
    copy_handler: AddressPin {
        value: 0x4393_1f90,
        json: "0x43931f90",
    },
    decompress1_handler: AddressPin {
        value: 0x4393_1f1c,
        json: "0x43931f1c",
    },
    zero_handler: AddressPin {
        value: 0x4393_1fbc,
        json: "0x43931fbc",
    },
    entry_count: 23,
    self_copy_entries: &[2, 3],
    none_entries: &[0, 1, 2, 3],
    file_entries: &[4, 5, 10, 11],
    zero_fill_entries: &[6, 7, 8, 9, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22],
    copy_total: 0x003f_efe8,
    decompress1_total: 0x0537_c678,
    compressed_total: 0x000b_18f0,
    zero_total: 0x03ae_ee3c,
    logical_total: 0x0926_a49c,
    output_hashes: S5400_OUTPUT_HASHES,
};

const S5300: CorpusPins = CorpusPins {
    env_var: "PME_S5300_MAIN",
    label: "01_MAIN",
    manifest_path: "scatter/01_MAIN/load_map.json",
    source_blake3: "5b4bc06c800553445ae60471f84afd95b0d2b365a03d481394d8b6e54a0e4d11",
    image_base: IMAGE_BASE,
    loader: AddressPin {
        value: 0x4397_a958,
        json: "0x4397a958",
    },
    literal_pair: AddressPin {
        value: 0x4397_a98c,
        json: "0x4397a98c",
    },
    table_start: AddressPin {
        value: 0x4110_5828,
        json: "0x41105828",
    },
    table_end: AddressPin {
        value: 0x4110_5988,
        json: "0x41105988",
    },
    null_handler: AddressPin {
        value: 0x4397_a96c,
        json: "0x4397a96c",
    },
    copy_handler: AddressPin {
        value: 0x4397_aa08,
        json: "0x4397aa08",
    },
    decompress1_handler: AddressPin {
        value: 0x4397_a994,
        json: "0x4397a994",
    },
    zero_handler: AddressPin {
        value: 0x4397_aa30,
        json: "0x4397aa30",
    },
    entry_count: 22,
    self_copy_entries: &[2, 3],
    none_entries: &[0, 1, 2, 3],
    file_entries: &[4, 5, 6, 10, 11],
    zero_fill_entries: &[7, 8, 9, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21],
    copy_total: 0x0070_4018,
    decompress1_total: 0x0879_997c,
    compressed_total: 0x0038_5231,
    zero_total: 0x03aa_72dc,
    logical_total: 0x0c94_4c70,
    output_hashes: S5300_OUTPUT_HASHES,
};

#[test]
fn s5400_main_matches_exact_scatter_corpus() {
    assert_corpus(&S5400);
}

#[test]
fn s5300_main_matches_exact_scatter_corpus() {
    assert_corpus(&S5300);
}

fn assert_corpus(pins: &CorpusPins) {
    let Some(path) = corpus_path(pins.env_var) else {
        return;
    };
    let image = fs::read(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));

    // Identity must be established before any corpus-specific address is used.
    let source_blake3 = blake3::hash(&image).to_hex().to_string();
    assert_eq!(
        source_blake3, pins.source_blake3,
        "{} source identity mismatch",
        pins.env_var
    );

    let image_size = u32::try_from(image.len()).expect("MAIN image size fits u32");
    let descriptors = parse_descriptors(&image, pins);
    assert_descriptor_totals(&descriptors, pins);
    let plan = scatter::discover(&image, pins.image_base.value)
        .unwrap_or_else(|error| panic!("{} discovery failed: {error}", pins.env_var))
        .unwrap_or_else(|| panic!("{} produced no scatter plan", pins.env_var));
    assert_plan(&plan, &descriptors, image_size, pins);

    let root = tempdir().expect("temporary scatter artifact root");
    let artifact = scatter::materialize(&plan, &image, pins.label, root.path())
        .unwrap_or_else(|error| panic!("{} materialization failed: {error}", pins.env_var));
    assert_eq!(artifact.relative_path, pins.manifest_path);

    let manifest_path = root.path().join(&artifact.relative_path);
    let manifest: Value = serde_json::from_slice(
        &fs::read(&manifest_path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", manifest_path.display())),
    )
    .unwrap_or_else(|error| panic!("invalid {}: {error}", manifest_path.display()));
    assert_manifest(&manifest, &descriptors, image_size, pins, root.path());
}

fn corpus_path(env_var: &str) -> Option<PathBuf> {
    corpus_path_value(env_var, std::env::var_os(env_var)).unwrap_or_else(|error| panic!("{error}"))
}

fn corpus_path_value(
    env_var: &str,
    value: Option<std::ffi::OsString>,
) -> Result<Option<PathBuf>, String> {
    let Some(path) = value.map(PathBuf::from) else {
        eprintln!("skip: set {env_var}");
        return Ok(None);
    };
    match fs::metadata(&path) {
        Ok(metadata) if metadata.is_file() => Ok(Some(path)),
        Ok(_) => Err(format!(
            "{env_var} input is not a regular file: {}",
            path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skip: {env_var} input not found");
            Ok(None)
        }
        Err(error) => Err(format!(
            "failed to inspect {env_var} input {}: {error}",
            path.display()
        )),
    }
}

#[test]
fn corpus_path_gate_skips_only_unset_or_missing_inputs() {
    assert_eq!(corpus_path_value("PME_TEST_MAIN", None).unwrap(), None);

    let root = tempdir().unwrap();
    let missing = root.path().join("missing.bin");
    assert_eq!(
        corpus_path_value("PME_TEST_MAIN", Some(missing.into_os_string())).unwrap(),
        None
    );

    let error = corpus_path_value(
        "PME_TEST_MAIN",
        Some(root.path().as_os_str().to_os_string()),
    )
    .unwrap_err();
    assert!(error.contains("not a regular file"), "{error}");
}

#[cfg(unix)]
#[test]
fn corpus_path_gate_rejects_metadata_errors() {
    use std::os::unix::fs::symlink;

    let root = tempdir().unwrap();
    let looping = root.path().join("loop");
    symlink("loop", &looping).unwrap();

    let error = corpus_path_value("PME_TEST_MAIN", Some(looping.into_os_string())).unwrap_err();
    assert!(error.contains("failed to inspect"), "{error}");
}

fn parse_descriptors(image: &[u8], pins: &CorpusPins) -> Vec<ExpectedDescriptor> {
    let table_start = pins
        .table_start
        .value
        .checked_sub(pins.image_base.value)
        .and_then(|offset| usize::try_from(offset).ok())
        .expect("pinned table start is inside the authenticated image");
    let table_end = pins
        .table_end
        .value
        .checked_sub(pins.image_base.value)
        .and_then(|offset| usize::try_from(offset).ok())
        .expect("pinned table end is inside the authenticated image");
    let table = image
        .get(table_start..table_end)
        .expect("pinned table range is inside the authenticated image");
    assert_eq!(
        table.len(),
        pins.entry_count
            .checked_mul(16)
            .expect("pinned table length fits usize")
    );

    table
        .as_chunks::<16>()
        .0
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let handler = read_u32(entry, 12);
            ExpectedDescriptor {
                source: read_u32(entry, 0),
                destination: read_u32(entry, 4),
                size: read_u32(entry, 8),
                handler,
                operation: operation_for_handler(handler, index, pins),
            }
        })
        .collect()
}

fn operation_for_handler(handler: u32, index: usize, pins: &CorpusPins) -> ExpectedOperation {
    if handler == pins.null_handler.value {
        ExpectedOperation::Null
    } else if handler == pins.copy_handler.value {
        ExpectedOperation::Copy
    } else if handler == pins.decompress1_handler.value {
        ExpectedOperation::Decompress1
    } else if handler == pins.zero_handler.value {
        ExpectedOperation::Zero
    } else {
        panic!("entry {index} has unpinned raw handler {handler:#010x}");
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let end = offset.checked_add(4).expect("descriptor offset fits usize");
    u32::from_le_bytes(
        bytes
            .get(offset..end)
            .expect("complete 16-byte descriptor field")
            .try_into()
            .expect("descriptor field is four bytes"),
    )
}

fn assert_descriptor_totals(descriptors: &[ExpectedDescriptor], pins: &CorpusPins) {
    let mut totals = Totals {
        copy: 0,
        decompress1: 0,
        zero: 0,
        logical: 0,
    };
    for descriptor in descriptors {
        let size = u64::from(descriptor.size);
        match descriptor.operation {
            ExpectedOperation::Null => assert_eq!(size, 0),
            ExpectedOperation::Copy => {
                totals.copy += size;
                totals.logical += size;
            }
            ExpectedOperation::Decompress1 => {
                totals.decompress1 += size;
                totals.logical += size;
            }
            ExpectedOperation::Zero => {
                totals.zero += size;
                totals.logical += size;
            }
        }
    }
    assert_eq!(totals, expected_totals(pins));
}

fn assert_plan(
    plan: &LoadPlan,
    descriptors: &[ExpectedDescriptor],
    image_size: u32,
    pins: &CorpusPins,
) {
    assert_eq!(plan.image_base, pins.image_base.value);
    assert_eq!(plan.image_size, image_size);
    assert_eq!(plan.loader_address, pins.loader.value);
    assert_eq!(plan.literal_pair_address, pins.literal_pair.value);
    assert_eq!(plan.table_start, pins.table_start.value);
    assert_eq!(plan.table_end, pins.table_end.value);
    assert_eq!(
        plan.handlers,
        HandlerMap {
            null: pins.null_handler.value,
            copy: pins.copy_handler.value,
            decompress1: pins.decompress1_handler.value,
            zero: pins.zero_handler.value,
        }
    );
    assert_eq!(plan.entries.len(), pins.entry_count);
    assert_eq!(plan.entries.len(), descriptors.len());
    assert_eq!(plan.logical_output_size, pins.logical_total);

    let mut compressed_total = 0u64;
    for (index, (entry, expected)) in plan.entries.iter().zip(descriptors).enumerate() {
        assert_eq!(entry.index, index);
        assert_eq!(entry.descriptor.source, expected.source);
        assert_eq!(entry.descriptor.destination, expected.destination);
        assert_eq!(entry.descriptor.size, expected.size);
        assert_eq!(entry.descriptor.handler, expected.handler);
        assert_eq!(entry.operation, expected.operation.production());
        match expected.operation {
            ExpectedOperation::Decompress1 => {
                compressed_total += u64::from(
                    entry
                        .compressed_size
                        .expect("decompress1 entry has compressed size"),
                );
            }
            ExpectedOperation::Null | ExpectedOperation::Copy | ExpectedOperation::Zero => {
                assert_eq!(entry.compressed_size, None);
            }
        }
    }
    assert_eq!(compressed_total, pins.compressed_total);
}

fn assert_manifest(
    manifest: &Value,
    descriptors: &[ExpectedDescriptor],
    image_size: u32,
    pins: &CorpusPins,
    root: &Path,
) {
    assert_exact_keys(
        manifest,
        &[
            "format",
            "schema_version",
            "tool_version",
            "image",
            "loader",
            "table",
            "entries",
        ],
        "load map",
    );
    assert_eq!(manifest["format"], "pixel-modem-extractor-scatter-load-v1");
    assert_eq!(manifest["schema_version"], 1);
    assert_eq!(manifest["tool_version"], "2.0.0");
    assert_eq!(
        manifest["image"],
        json!({
            "label": pins.label,
            "base_addr": pins.image_base.json,
            "size": image_size,
            "blake3": pins.source_blake3,
        })
    );
    assert_eq!(
        manifest["loader"],
        json!({
            "address": pins.loader.json,
            "literal_pair": pins.literal_pair.json,
        })
    );
    assert_eq!(
        manifest["table"],
        json!({
            "start": pins.table_start.json,
            "end": pins.table_end.json,
            "entry_count": pins.entry_count,
            "handlers": {
                "null": pins.null_handler.json,
                "copy": pins.copy_handler.json,
                "decompress1": pins.decompress1_handler.json,
                "zero": pins.zero_handler.json,
            },
        })
    );

    let entries = manifest["entries"]
        .as_array()
        .expect("load-map entries are an array");
    assert_eq!(entries.len(), pins.entry_count);
    assert_eq!(entries.len(), descriptors.len());
    assert_entry_metadata(entries, descriptors);
    assert_entry_totals(entries, pins);
    assert_output_hashes(entries, pins);
    assert_materializations(entries, descriptors, pins, root);
}

fn assert_entry_metadata(entries: &[Value], descriptors: &[ExpectedDescriptor]) {
    for (index, (entry, expected)) in entries.iter().zip(descriptors).enumerate() {
        assert_eq!(entry_index(entry), index);
        let expected_keys: &[&str] = match expected.operation {
            ExpectedOperation::Null => &[
                "index",
                "source",
                "destination",
                "size",
                "handler",
                "operation",
                "materialization",
            ],
            ExpectedOperation::Copy => &[
                "index",
                "source",
                "destination",
                "size",
                "handler",
                "operation",
                "output_blake3",
                "materialization",
            ],
            ExpectedOperation::Decompress1 => &[
                "index",
                "source",
                "destination",
                "size",
                "handler",
                "operation",
                "compressed_size",
                "output_blake3",
                "materialization",
            ],
            ExpectedOperation::Zero => &[
                "index",
                "source",
                "destination",
                "size",
                "handler",
                "operation",
                "output_blake3",
                "materialization",
            ],
        };
        assert_exact_keys(entry, expected_keys, "entry");
        assert_eq!(
            entry["source"].as_str(),
            Some(address(expected.source).as_str())
        );
        assert_eq!(
            entry["destination"].as_str(),
            Some(address(expected.destination).as_str())
        );
        assert_eq!(
            entry["handler"].as_str(),
            Some(address(expected.handler).as_str())
        );
        assert_eq!(entry["size"].as_u64(), Some(u64::from(expected.size)));
        assert_eq!(entry["operation"].as_str(), Some(expected.operation.json()));
        if expected.operation == ExpectedOperation::Decompress1 {
            u32::try_from(
                entry["compressed_size"]
                    .as_u64()
                    .expect("decompress1 compressed size is an integer"),
            )
            .expect("decompress1 compressed size fits u32");
        }
        assert_canonical_address(&entry["source"]);
        assert_canonical_address(&entry["destination"]);
        assert_canonical_address(&entry["handler"]);
    }
}

fn assert_entry_totals(entries: &[Value], pins: &CorpusPins) {
    let mut totals = Totals {
        copy: 0,
        decompress1: 0,
        zero: 0,
        logical: 0,
    };
    let mut compressed_total = 0u64;
    for entry in entries {
        let size = entry["size"].as_u64().expect("entry size is an integer");
        match entry["operation"].as_str().expect("entry operation") {
            "null" => assert_eq!(size, 0),
            "copy" => {
                totals.copy += size;
                totals.logical += size;
            }
            "decompress1" => {
                totals.decompress1 += size;
                totals.logical += size;
                compressed_total += entry["compressed_size"]
                    .as_u64()
                    .expect("decompress1 compressed size is an integer");
            }
            "zero" => {
                totals.zero += size;
                totals.logical += size;
            }
            other => panic!("unexpected operation {other:?}"),
        }
    }
    assert_eq!(totals, expected_totals(pins));
    assert_eq!(compressed_total, pins.compressed_total);
}

fn assert_output_hashes(entries: &[Value], pins: &CorpusPins) {
    let hashes = entries
        .iter()
        .filter_map(|entry| {
            entry["output_blake3"]
                .as_str()
                .map(|hash| (entry_index(entry), hash))
        })
        .collect::<Vec<_>>();
    assert_eq!(hashes.as_slice(), pins.output_hashes);
}

fn assert_materializations(
    entries: &[Value],
    descriptors: &[ExpectedDescriptor],
    pins: &CorpusPins,
    root: &Path,
) {
    let none = json_indices_for_materialization(entries, "none");
    let files = json_indices_for_materialization(entries, "file");
    let zero_fill = json_indices_for_materialization(entries, "zero_fill");
    assert_eq!(none.as_slice(), pins.none_entries);
    assert_eq!(files.as_slice(), pins.file_entries);
    assert_eq!(zero_fill.as_slice(), pins.zero_fill_entries);
    assert_eq!(none.len() + files.len() + zero_fill.len(), pins.entry_count);

    let self_copies = descriptors
        .iter()
        .enumerate()
        .filter(|(_, descriptor)| {
            descriptor.operation == ExpectedOperation::Copy
                && descriptor.source == descriptor.destination
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    assert_eq!(self_copies.as_slice(), pins.self_copy_entries);
    for &index in pins.none_entries {
        assert_eq!(entries[index]["materialization"], json!({"kind": "none"}));
    }
    for &index in pins.zero_fill_entries {
        assert_eq!(
            entries[index]["materialization"],
            json!({"kind": "zero_fill"})
        );
    }

    let map_dir = root.join("scatter").join(pins.label);
    let mut expected_block_files = Vec::with_capacity(pins.file_entries.len());
    for &index in pins.file_entries {
        let descriptor = descriptors
            .get(index)
            .expect("file-backed index has a raw descriptor");
        let file_name = format!("{index:02}-{}.bin", descriptor.operation.json());
        let relative_path = format!("blocks/{file_name}");
        let size = u64::from(descriptor.size);
        assert_eq!(
            entries[index]["materialization"],
            json!({
                "kind": "file",
                "path": &relative_path,
                "size": size,
            })
        );
        let payload = map_dir.join(&relative_path);
        assert_eq!(
            fs::metadata(&payload)
                .unwrap_or_else(|error| panic!("failed to stat {}: {error}", payload.display()))
                .len(),
            size
        );
        let expected_hash = pins
            .output_hashes
            .iter()
            .find_map(|&(expected_index, hash)| (expected_index == index).then_some(hash))
            .expect("file-backed entry has a pinned output hash");
        assert_eq!(blake3_file(&payload), expected_hash);
        expected_block_files.push(file_name);
    }

    assert_eq!(
        directory_names(&map_dir)
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["blocks", "load_map.json"]
    );
    assert_eq!(
        directory_names(&map_dir.join("blocks")).as_slice(),
        expected_block_files
    );
}

fn expected_totals(pins: &CorpusPins) -> Totals {
    Totals {
        copy: pins.copy_total,
        decompress1: pins.decompress1_total,
        zero: pins.zero_total,
        logical: pins.logical_total,
    }
}

fn address(value: u32) -> String {
    format!("{value:#010x}")
}

fn json_indices_for_materialization(entries: &[Value], kind: &str) -> Vec<usize> {
    entries
        .iter()
        .filter(|entry| entry["materialization"]["kind"].as_str() == Some(kind))
        .map(entry_index)
        .collect()
}

fn entry_index(entry: &Value) -> usize {
    usize::try_from(entry["index"].as_u64().expect("entry index is an integer"))
        .expect("entry index fits usize")
}

fn assert_exact_keys(value: &Value, expected: &[&str], context: &str) {
    let object = value
        .as_object()
        .unwrap_or_else(|| panic!("{context} is an object"));
    assert_eq!(object.len(), expected.len(), "unexpected {context} fields");
    for key in expected {
        assert!(object.contains_key(*key), "{context} field {key:?} missing");
    }
}

fn assert_canonical_address(value: &Value) {
    let address = value.as_str().expect("address is a string");
    let bytes = address.as_bytes();
    assert_eq!(bytes.len(), 10, "non-canonical address {address:?}");
    assert_eq!(&bytes[..2], b"0x", "non-canonical address {address:?}");
    assert!(
        bytes[2..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)),
        "non-canonical address {address:?}"
    );
}

fn directory_names(path: &Path) -> Vec<String> {
    let mut names = fs::read_dir(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
        .map(|entry| {
            entry
                .expect("directory entry is readable")
                .file_name()
                .into_string()
                .expect("artifact file name is UTF-8")
        })
        .collect::<Vec<_>>();
    names.sort();
    names
}

fn blake3_file(path: &Path) -> String {
    let mut file = fs::File::open(path)
        .unwrap_or_else(|error| panic!("failed to open {}: {error}", path.display()));
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    hasher.finalize().to_hex().to_string()
}
