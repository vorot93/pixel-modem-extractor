use super::{LoadPlan, Operation, PlannedEntry, PlannedOutput};
use crate::error::{Error, Result};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

pub const LOAD_MAP_FORMAT: &str = "pixel-modem-extractor-scatter-load-v1";

const SCHEMA_VERSION: u32 = 1;
static ZERO_CHUNK: [u8; 64 * 1024] = [0; 64 * 1024];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedLoadMap {
    pub relative_path: String,
}

#[derive(Serialize)]
struct LoadMap<'a> {
    format: &'static str,
    schema_version: u32,
    tool_version: &'static str,
    image: Image<'a>,
    loader: Loader,
    table: Table,
    entries: Vec<Entry>,
}

#[derive(Serialize)]
struct Image<'a> {
    label: &'a str,
    base_addr: String,
    size: u32,
    blake3: String,
}

#[derive(Serialize)]
struct Loader {
    address: String,
    literal_pair: String,
}

#[derive(Serialize)]
struct Table {
    start: String,
    end: String,
    entry_count: usize,
    handlers: Handlers,
}

#[derive(Serialize)]
struct Handlers {
    null: String,
    copy: String,
    decompress1: String,
    zero: String,
}

#[derive(Serialize)]
struct Entry {
    index: usize,
    source: String,
    destination: String,
    size: u32,
    handler: String,
    operation: Operation,
    #[serde(skip_serializing_if = "Option::is_none")]
    compressed_size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output_blake3: Option<String>,
    materialization: Materialization,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Materialization {
    None,
    ZeroFill,
    File { path: String, size: u32 },
}

pub fn clear_materialized(root: &Path, label: &str) -> Result<()> {
    validate_label(label)?;
    let Some(scatter_root) = scatter_directory(root, false)? else {
        return Ok(());
    };
    remove_owned_path(&scatter_root.join(label))
}

pub fn materialize(
    plan: &LoadPlan,
    image: &[u8],
    label: &str,
    root: &Path,
) -> Result<MaterializedLoadMap> {
    validate_label(label)?;

    let Some(scatter_root) = scatter_directory(root, true)? else {
        return Err(bad("failed to create the artifact scatter directory"));
    };
    let final_dir = scatter_root.join(label);
    remove_owned_path(&final_dir)?;

    let staging_dir = scatter_root.join(format!("{label}.staging+{}", std::process::id()));
    remove_owned_path(&staging_dir)?;
    let result = stage_and_publish(plan, image, label, &staging_dir, &final_dir);
    if let Err(error) = result {
        let _ = remove_owned_path(&staging_dir);
        return Err(error);
    }

    Ok(MaterializedLoadMap {
        relative_path: format!("scatter/{label}/load_map.json"),
    })
}

fn stage_and_publish(
    plan: &LoadPlan,
    image: &[u8],
    label: &str,
    staging_dir: &Path,
    final_dir: &Path,
) -> Result<()> {
    let blocks_dir = staging_dir.join("blocks");
    fs::create_dir_all(&blocks_dir)?;

    let image_size = u32::try_from(image.len())
        .map_err(|_| bad("source image size does not fit the load-map schema"))?;
    if image_size != plan.image_size {
        return Err(bad(format!(
            "source image size {image_size} does not match planned size {}",
            plan.image_size
        )));
    }

    let mut entries = Vec::with_capacity(plan.entries.len());
    for entry in &plan.entries {
        entries.push(stage_entry(plan, image, entry, &blocks_dir)?);
    }
    let map = LoadMap {
        format: LOAD_MAP_FORMAT,
        schema_version: SCHEMA_VERSION,
        tool_version: env!("CARGO_PKG_VERSION"),
        image: Image {
            label,
            base_addr: address(plan.image_base),
            size: plan.image_size,
            blake3: crate::manifest::blake3_bytes(image),
        },
        loader: Loader {
            address: address(plan.loader_address),
            literal_pair: address(plan.literal_pair_address),
        },
        table: Table {
            start: address(plan.table_start),
            end: address(plan.table_end),
            entry_count: plan.entries.len(),
            handlers: Handlers {
                null: address(plan.handlers.null),
                copy: address(plan.handlers.copy),
                decompress1: address(plan.handlers.decompress1),
                zero: address(plan.handlers.zero),
            },
        },
        entries,
    };
    let mut manifest =
        serde_json::to_vec_pretty(&map).map_err(|error| Error::Serialize(error.to_string()))?;
    manifest.push(b'\n');
    fs::write(staging_dir.join("load_map.json"), manifest)?;
    fs::rename(staging_dir, final_dir)?;
    Ok(())
}

fn stage_entry(
    plan: &LoadPlan,
    image: &[u8],
    entry: &PlannedEntry,
    blocks_dir: &Path,
) -> Result<Entry> {
    validate_operation_metadata(plan, entry)?;
    let (output_blake3, materialization) = match (&entry.operation, &entry.output) {
        (Operation::Null, PlannedOutput::None) => (None, Materialization::None),
        (Operation::Copy, PlannedOutput::SelfCopy) => {
            if entry.descriptor.source != entry.descriptor.destination {
                return Err(entry_error(
                    entry,
                    "self-copy source and destination differ",
                ));
            }
            let bytes = source_slice(plan, image, entry)?;
            (
                Some(crate::manifest::blake3_bytes(bytes)),
                Materialization::None,
            )
        }
        (Operation::Copy, PlannedOutput::Bytes(bytes))
        | (Operation::Decompress1, PlannedOutput::Bytes(bytes)) => {
            validate_output_size(entry, bytes)?;
            let hash = crate::manifest::blake3_bytes(bytes);
            if entry.operation == Operation::Decompress1 && bytes.iter().all(|&byte| byte == 0) {
                (Some(hash), Materialization::ZeroFill)
            } else {
                let operation = operation_name(entry.operation);
                let file_name = format!("{:02}-{operation}.bin", entry.index);
                fs::write(blocks_dir.join(&file_name), bytes)?;
                (
                    Some(hash),
                    Materialization::File {
                        path: format!("blocks/{file_name}"),
                        size: entry.descriptor.size,
                    },
                )
            }
        }
        (Operation::Zero, PlannedOutput::ZeroFill) => (
            Some(blake3_zeros(entry.descriptor.size)),
            Materialization::ZeroFill,
        ),
        _ => {
            return Err(entry_error(
                entry,
                "planned output does not match the classified operation",
            ));
        }
    };

    Ok(Entry {
        index: entry.index,
        source: address(entry.descriptor.source),
        destination: address(entry.descriptor.destination),
        size: entry.descriptor.size,
        handler: address(entry.descriptor.handler),
        operation: entry.operation,
        compressed_size: entry.compressed_size,
        output_blake3,
        materialization,
    })
}

fn validate_operation_metadata(plan: &LoadPlan, entry: &PlannedEntry) -> Result<()> {
    let expected_handler = match entry.operation {
        Operation::Null => plan.handlers.null,
        Operation::Copy => plan.handlers.copy,
        Operation::Decompress1 => plan.handlers.decompress1,
        Operation::Zero => plan.handlers.zero,
    };
    if entry.descriptor.handler != expected_handler {
        return Err(entry_error(
            entry,
            "handler does not match the classified operation",
        ));
    }
    if (entry.operation == Operation::Decompress1) != entry.compressed_size.is_some() {
        return Err(entry_error(
            entry,
            "compressed size presence does not match the classified operation",
        ));
    }
    Ok(())
}

fn validate_output_size(entry: &PlannedEntry, bytes: &[u8]) -> Result<()> {
    let size = usize::try_from(entry.descriptor.size)
        .map_err(|_| entry_error(entry, "output size does not fit the host"))?;
    if bytes.len() != size {
        return Err(entry_error(
            entry,
            format!(
                "output byte length {} does not match declared size {}",
                bytes.len(),
                entry.descriptor.size
            ),
        ));
    }
    Ok(())
}

fn source_slice<'a>(plan: &LoadPlan, image: &'a [u8], entry: &PlannedEntry) -> Result<&'a [u8]> {
    let start = entry
        .descriptor
        .source
        .checked_sub(plan.image_base)
        .ok_or_else(|| entry_error(entry, "self-copy source begins below the source image"))?;
    let end = start
        .checked_add(entry.descriptor.size)
        .filter(|&end| end <= plan.image_size)
        .ok_or_else(|| entry_error(entry, "self-copy source range escapes the source image"))?;
    let start = usize::try_from(start)
        .map_err(|_| entry_error(entry, "self-copy source offset does not fit the host"))?;
    let end = usize::try_from(end)
        .map_err(|_| entry_error(entry, "self-copy source end does not fit the host"))?;
    image
        .get(start..end)
        .ok_or_else(|| entry_error(entry, "self-copy source range escapes the source image"))
}

fn blake3_zeros(size: u32) -> String {
    let mut hasher = blake3::Hasher::new();
    let mut remaining = u64::from(size);
    while remaining > 0 {
        let length = remaining.min(ZERO_CHUNK.len() as u64) as usize;
        hasher.update(&ZERO_CHUNK[..length]);
        remaining -= length as u64;
    }
    hasher.finalize().to_hex().to_string()
}

fn validate_label(label: &str) -> Result<()> {
    let valid = !label.is_empty()
        && label != "."
        && label != ".."
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(bad(format!("invalid artifact label {label:?}")))
    }
}

fn scatter_directory(root: &Path, create: bool) -> Result<Option<PathBuf>> {
    let path = root.join("scatter");
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !create => return Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(root)?;
            match fs::create_dir(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
            fs::symlink_metadata(&path)?
        }
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(bad("artifact scatter path is not an owned real directory"));
    }
    Ok(Some(path))
}

fn remove_owned_path(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if metadata.is_dir() {
        fs::remove_dir_all(path)?;
    } else {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn operation_name(operation: Operation) -> &'static str {
    match operation {
        Operation::Null => "null",
        Operation::Copy => "copy",
        Operation::Decompress1 => "decompress1",
        Operation::Zero => "zero",
    }
}

fn address(value: u32) -> String {
    format!("{value:#010x}")
}

fn entry_error(entry: &PlannedEntry, reason: impl Into<String>) -> Error {
    bad(format!("entry {}: {}", entry.index, reason.into()))
}

fn bad(reason: impl Into<String>) -> Error {
    Error::BadScatter(reason.into())
}

#[cfg(test)]
mod tests {
    use super::{LOAD_MAP_FORMAT, clear_materialized, materialize};
    use crate::error::Error;
    use crate::scatter::{
        Descriptor, HandlerMap, LoadPlan, Operation, PlannedEntry, PlannedOutput,
    };
    use serde_json::json;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    use tempfile::tempdir;

    const BASE: u32 = 0x1000_0000;
    const IMAGE_LEN: usize = 0x1000;
    const NULL_HANDLER: u32 = BASE + 0x600;
    const COPY_HANDLER: u32 = BASE + 0x601;
    const DECOMPRESS1_HANDLER: u32 = BASE + 0x604;
    const ZERO_HANDLER: u32 = BASE + 0x609;
    const SENTINEL_SOURCE: u32 = BASE + 0x680;
    const SELF_COPY_SOURCE: u32 = BASE + 0x700;
    const COPY_SOURCE: u32 = BASE + 0x710;
    const DECOMPRESS1_SOURCE: u32 = BASE + 0x720;
    const ZERO_SOURCE: u32 = BASE + 0x730;

    struct Fixture {
        image: Vec<u8>,
        plan: LoadPlan,
    }

    fn fixture() -> Fixture {
        let mut image = vec![0; IMAGE_LEN];
        image[0x700..0x704].copy_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        image[0x710..0x714].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        image[0x720..0x722].copy_from_slice(&[0x22, 0xaa]);

        let entries = vec![
            planned_entry(
                0,
                SENTINEL_SOURCE,
                0,
                0,
                NULL_HANDLER,
                Operation::Null,
                None,
                PlannedOutput::None,
            ),
            planned_entry(
                1,
                0,
                SENTINEL_SOURCE,
                0,
                NULL_HANDLER,
                Operation::Null,
                None,
                PlannedOutput::None,
            ),
            planned_entry(
                2,
                SELF_COPY_SOURCE,
                SELF_COPY_SOURCE,
                4,
                COPY_HANDLER,
                Operation::Copy,
                None,
                PlannedOutput::SelfCopy,
            ),
            planned_entry(
                3,
                COPY_SOURCE,
                0x2000_0100,
                4,
                COPY_HANDLER,
                Operation::Copy,
                None,
                PlannedOutput::Bytes(vec![0x11, 0x22, 0x33, 0x44]),
            ),
            planned_entry(
                4,
                DECOMPRESS1_SOURCE,
                0x2000_0200,
                3,
                DECOMPRESS1_HANDLER,
                Operation::Decompress1,
                Some(2),
                PlannedOutput::Bytes(vec![0xaa, 0, 0]),
            ),
            planned_entry(
                5,
                ZERO_SOURCE,
                0x2000_0300,
                5,
                ZERO_HANDLER,
                Operation::Zero,
                None,
                PlannedOutput::ZeroFill,
            ),
        ];
        let plan = LoadPlan {
            image_base: BASE,
            image_size: IMAGE_LEN as u32,
            loader_address: BASE + 0x40,
            literal_pair_address: BASE + 0x80,
            table_start: BASE + 0x200,
            table_end: BASE + 0x260,
            handlers: HandlerMap {
                null: NULL_HANDLER,
                copy: COPY_HANDLER,
                decompress1: DECOMPRESS1_HANDLER,
                zero: ZERO_HANDLER,
            },
            entries,
            logical_output_size: 16,
        };
        Fixture { image, plan }
    }

    #[allow(clippy::too_many_arguments)]
    fn planned_entry(
        index: usize,
        source: u32,
        destination: u32,
        size: u32,
        handler: u32,
        operation: Operation,
        compressed_size: Option<u32>,
        output: PlannedOutput,
    ) -> PlannedEntry {
        PlannedEntry {
            index,
            descriptor: Descriptor {
                source,
                destination,
                size,
                handler,
            },
            operation,
            compressed_size,
            output,
        }
    }

    #[test]
    fn materializes_exact_pretty_schema_hashes_and_payloads() {
        let fixture = fixture();
        let root = tempdir().unwrap();

        let artifact = materialize(&fixture.plan, &fixture.image, "02_MAIN", root.path()).unwrap();
        assert_eq!(LOAD_MAP_FORMAT, "pixel-modem-extractor-scatter-load-v1");
        assert_eq!(artifact.relative_path, "scatter/02_MAIN/load_map.json");

        let manifest_path = root.path().join(&artifact.relative_path);
        let bytes = fs::read(&manifest_path).unwrap();
        let expected = r#"{
  "format": "pixel-modem-extractor-scatter-load-v1",
  "schema_version": 1,
  "tool_version": "2.0.0",
  "image": {
    "label": "02_MAIN",
    "base_addr": "0x10000000",
    "size": 4096,
    "blake3": "e6e58cd8b4cdf2a04a31d39aea29579eecda4d8f58147c10a9e478c279092e8a"
  },
  "loader": {
    "address": "0x10000040",
    "literal_pair": "0x10000080"
  },
  "table": {
    "start": "0x10000200",
    "end": "0x10000260",
    "entry_count": 6,
    "handlers": {
      "null": "0x10000600",
      "copy": "0x10000601",
      "decompress1": "0x10000604",
      "zero": "0x10000609"
    }
  },
  "entries": [
    {
      "index": 0,
      "source": "0x10000680",
      "destination": "0x00000000",
      "size": 0,
      "handler": "0x10000600",
      "operation": "null",
      "materialization": {
        "kind": "none"
      }
    },
    {
      "index": 1,
      "source": "0x00000000",
      "destination": "0x10000680",
      "size": 0,
      "handler": "0x10000600",
      "operation": "null",
      "materialization": {
        "kind": "none"
      }
    },
    {
      "index": 2,
      "source": "0x10000700",
      "destination": "0x10000700",
      "size": 4,
      "handler": "0x10000601",
      "operation": "copy",
      "output_blake3": "650e93bacca01942a5a787f2f3ec4ce560998eb7c250733601a880d7f0c11178",
      "materialization": {
        "kind": "none"
      }
    },
    {
      "index": 3,
      "source": "0x10000710",
      "destination": "0x20000100",
      "size": 4,
      "handler": "0x10000601",
      "operation": "copy",
      "output_blake3": "a7c8ca54b7a30c966b22e012bdef6cbda17a47047f323f482d62c2b999e9e275",
      "materialization": {
        "kind": "file",
        "path": "blocks/03-copy.bin",
        "size": 4
      }
    },
    {
      "index": 4,
      "source": "0x10000720",
      "destination": "0x20000200",
      "size": 3,
      "handler": "0x10000604",
      "operation": "decompress1",
      "compressed_size": 2,
      "output_blake3": "f15560edad7f63b7ff8df07a8222f6246941621ad8db903b047972ccc5a4ab9b",
      "materialization": {
        "kind": "file",
        "path": "blocks/04-decompress1.bin",
        "size": 3
      }
    },
    {
      "index": 5,
      "source": "0x10000730",
      "destination": "0x20000300",
      "size": 5,
      "handler": "0x10000609",
      "operation": "zero",
      "output_blake3": "cdc96eca844d7912acdbb3dca677757d0db5747a1df61166339cfc7156d4880f",
      "materialization": {
        "kind": "zero_fill"
      }
    }
  ]
}
"#;
        assert_eq!(bytes, expected.as_bytes());
        assert_eq!(
            fs::read(root.path().join("scatter/02_MAIN/blocks/03-copy.bin")).unwrap(),
            [0x11, 0x22, 0x33, 0x44]
        );
        assert_eq!(
            fs::read(
                root.path()
                    .join("scatter/02_MAIN/blocks/04-decompress1.bin")
            )
            .unwrap(),
            [0xaa, 0, 0]
        );
        let mut names = fs::read_dir(root.path().join("scatter/02_MAIN/blocks"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect::<Vec<_>>();
        names.sort();
        assert_eq!(names, ["03-copy.bin", "04-decompress1.bin"]);
    }

    #[test]
    fn all_zero_decompression_uses_zero_fill_without_a_payload_file() {
        let mut fixture = fixture();
        fixture.plan.entries[4].output = PlannedOutput::Bytes(vec![0; 3]);
        let root = tempdir().unwrap();

        let artifact = materialize(&fixture.plan, &fixture.image, "02_MAIN", root.path()).unwrap();
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(root.path().join(artifact.relative_path)).unwrap())
                .unwrap();

        assert_eq!(
            manifest["entries"][4]["output_blake3"],
            "91525ff00a3755a8df93c626b59f6e36cf021d85ebccecdedc38f3f1890a15fc"
        );
        assert_eq!(
            manifest["entries"][4]["materialization"],
            json!({"kind": "zero_fill"})
        );
        assert!(
            !root
                .path()
                .join("scatter/02_MAIN/blocks/04-decompress1.bin")
                .exists()
        );
    }

    #[test]
    fn all_zero_copy_remains_file_backed() {
        let mut fixture = fixture();
        fixture.image[0x710..0x714].fill(0);
        fixture.plan.entries[3].output = PlannedOutput::Bytes(vec![0; 4]);
        let root = tempdir().unwrap();

        let artifact = materialize(&fixture.plan, &fixture.image, "02_MAIN", root.path()).unwrap();
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(root.path().join(artifact.relative_path)).unwrap())
                .unwrap();

        assert_eq!(
            manifest["entries"][3]["output_blake3"],
            "ec2bd03bf86b935fa34d71ad7ebb049f1f10f87d343e521511d8f9e6625620cd"
        );
        assert_eq!(
            manifest["entries"][3]["materialization"],
            json!({"kind": "file", "path": "blocks/03-copy.bin", "size": 4})
        );
        assert_eq!(
            fs::read(root.path().join("scatter/02_MAIN/blocks/03-copy.bin")).unwrap(),
            [0, 0, 0, 0]
        );
    }

    #[test]
    fn zero_fill_hash_crosses_the_chunk_boundary() {
        let size = 64 * 1024 + 1;
        let expected = blake3::hash(&vec![0; size as usize]).to_hex().to_string();

        assert_eq!(super::blake3_zeros(size), expected);
    }

    #[test]
    fn rerun_is_byte_identical_and_replaces_stale_owned_output() {
        let fixture = fixture();
        let root = tempdir().unwrap();
        let artifact = materialize(&fixture.plan, &fixture.image, "02_MAIN", root.path()).unwrap();
        let manifest_path = root.path().join(&artifact.relative_path);
        let first = fs::read(&manifest_path).unwrap();
        let final_dir = root.path().join("scatter/02_MAIN");
        fs::write(final_dir.join("stale.bin"), b"stale").unwrap();
        fs::write(&manifest_path, b"stale manifest").unwrap();
        let staging = root
            .path()
            .join(format!("scatter/02_MAIN.staging+{}", std::process::id()));
        fs::create_dir_all(&staging).unwrap();
        fs::write(staging.join("stale.bin"), b"stale staging").unwrap();

        let rerun = materialize(&fixture.plan, &fixture.image, "02_MAIN", root.path()).unwrap();

        assert_eq!(rerun, artifact);
        assert_eq!(fs::read(&manifest_path).unwrap(), first);
        assert!(!final_dir.join("stale.bin").exists());
        assert!(!staging.exists());
    }

    #[test]
    fn failed_staging_exposes_no_manifest_and_cleans_staging() {
        let mut fixture = fixture();
        let root = tempdir().unwrap();
        materialize(&fixture.plan, &fixture.image, "02_MAIN", root.path()).unwrap();
        fixture.plan.entries[2].descriptor.source = BASE + IMAGE_LEN as u32 - 2;
        fixture.plan.entries[2].descriptor.destination = BASE + IMAGE_LEN as u32 - 2;
        let final_dir = root.path().join("scatter/02_MAIN");
        let staging = root
            .path()
            .join(format!("scatter/02_MAIN.staging+{}", std::process::id()));

        let error = materialize(&fixture.plan, &fixture.image, "02_MAIN", root.path()).unwrap_err();

        assert!(
            matches!(error, Error::BadScatter(reason) if reason.contains("entry 2") && reason.contains("source"))
        );
        assert!(!final_dir.join("load_map.json").exists());
        assert!(!final_dir.exists());
        assert!(!staging.exists());
    }

    #[cfg(unix)]
    #[test]
    fn clear_rejects_intermediate_scatter_symlink_without_touching_target() {
        let root = tempdir().unwrap();
        let external = tempdir().unwrap();
        let external_label = external.path().join("02_MAIN");
        fs::create_dir(&external_label).unwrap();
        let sentinel = external_label.join("keep.bin");
        fs::write(&sentinel, b"external").unwrap();
        symlink(external.path(), root.path().join("scatter")).unwrap();

        let result = clear_materialized(root.path(), "02_MAIN");
        let sentinel_after = fs::read(&sentinel);

        assert!(matches!(result, Err(Error::BadScatter(_))));
        assert_eq!(sentinel_after.unwrap(), b"external");
        assert!(
            fs::symlink_metadata(root.path().join("scatter"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn materialize_rejects_intermediate_scatter_symlink_without_touching_target() {
        let fixture = fixture();
        let root = tempdir().unwrap();
        let external = tempdir().unwrap();
        let external_label = external.path().join("02_MAIN");
        fs::create_dir(&external_label).unwrap();
        let sentinel = external_label.join("keep.bin");
        fs::write(&sentinel, b"external").unwrap();
        symlink(external.path(), root.path().join("scatter")).unwrap();

        let result = materialize(&fixture.plan, &fixture.image, "02_MAIN", root.path());
        let sentinel_after = fs::read(&sentinel);
        let external_manifest = external_label.join("load_map.json").exists();

        assert!(matches!(result, Err(Error::BadScatter(_))));
        assert_eq!(sentinel_after.unwrap(), b"external");
        assert!(!external_manifest);
        assert!(
            fs::symlink_metadata(root.path().join("scatter"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn materializing_short_label_preserves_valid_legacy_staging_name_label() {
        let fixture = fixture();
        let root = tempdir().unwrap();
        let colliding_label = format!("A.staging-{}", std::process::id());
        let colliding =
            materialize(&fixture.plan, &fixture.image, &colliding_label, root.path()).unwrap();
        let colliding_dir = root.path().join("scatter").join(&colliding_label);
        let manifest_before = fs::read(root.path().join(colliding.relative_path)).unwrap();
        fs::write(colliding_dir.join("keep.bin"), b"owned by colliding label").unwrap();

        materialize(&fixture.plan, &fixture.image, "A", root.path()).unwrap();

        assert_eq!(
            fs::read(colliding_dir.join("load_map.json")).unwrap(),
            manifest_before
        );
        assert_eq!(
            fs::read(colliding_dir.join("keep.bin")).unwrap(),
            b"owned by colliding label"
        );
        assert!(root.path().join("scatter/A/load_map.json").exists());
    }

    #[test]
    fn clear_removes_only_the_owned_label_directory_and_absence_succeeds() {
        let root = tempdir().unwrap();
        let owned = root.path().join("scatter/02_MAIN");
        let sibling = root.path().join("scatter/03_DSP");
        let similarly_named = root.path().join("scatter/02_MAIN.staging-foreign");
        let unrelated = root.path().join("outside");
        for path in [&owned, &sibling, &similarly_named, &unrelated] {
            fs::create_dir_all(path).unwrap();
            fs::write(path.join("keep.bin"), b"keep").unwrap();
        }

        clear_materialized(root.path(), "02_MAIN").unwrap();

        assert!(!owned.exists());
        assert!(sibling.join("keep.bin").exists());
        assert!(similarly_named.join("keep.bin").exists());
        assert!(unrelated.join("keep.bin").exists());
        clear_materialized(root.path(), "02_MAIN").unwrap();
        assert!(sibling.join("keep.bin").exists());
    }

    #[test]
    fn labels_accept_only_safe_ascii_components() {
        let fixture = fixture();
        let root = tempdir().unwrap();
        for label in ["A", "02_MAIN", "a.b-c_9", "a..b", "-", "_"] {
            let artifact = materialize(&fixture.plan, &fixture.image, label, root.path()).unwrap();
            assert_eq!(
                artifact.relative_path,
                format!("scatter/{label}/load_map.json")
            );
            clear_materialized(root.path(), label).unwrap();
        }

        let invalid_root = tempdir().unwrap();
        for label in [
            "", ".", "..", "a/b", "a\\b", "a b", "a\tb", "a\nb", "a;b", "$(id)", "`id`", "a&b",
            "a|b", "a*b", "a?b", "a>b", "a<b", "a'b", "a\"b", "[ab]", "{a,b}", "!a", "é",
        ] {
            let clear_error = clear_materialized(invalid_root.path(), label).unwrap_err();
            assert!(
                matches!(clear_error, Error::BadScatter(_)),
                "clear accepted {label:?}"
            );
            let write_error =
                materialize(&fixture.plan, &fixture.image, label, invalid_root.path()).unwrap_err();
            assert!(
                matches!(write_error, Error::BadScatter(_)),
                "materialize accepted {label:?}"
            );
        }
        assert!(!invalid_root.path().join("scatter").exists());
    }
}
