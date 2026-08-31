#[cfg(test)]
mod tests {
    use super::{ExceptionArtifactContext, materialize, read, read_bytes};
    use crate::exception_roots::discover;
    use crate::runtime_image::RuntimeImage;
    use crate::scatter::{
        Descriptor, HandlerMap, LoadPlan, Operation, PlannedEntry, PlannedOutput,
    };

    const BASE: u32 = 0x4001_0000;
    const IMAGE_SIZE: usize = 0x800;
    const RESET_ENTRY: u32 = BASE + 0x400;
    const SCATTER_ROOT: u32 = 0x5000_0000;
    const ARM_NOP: u32 = 0xe1a0_0000;

    fn write_u32(raw: &mut [u8], address: u32, value: u32) {
        let start = usize::try_from(address - BASE).unwrap();
        raw[start..start + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn literal_address(slot: usize) -> u32 {
        if slot == 7 {
            BASE + 0x20
        } else {
            BASE + 0x40 + u32::try_from(slot).unwrap() * 4
        }
    }

    fn a32_ldr_pc(slot: u32, literal: u32) -> u32 {
        let displacement = i64::from(literal) - (i64::from(slot) + 8);
        let base = if displacement >= 0 {
            0xe59f_f000
        } else {
            0xe51f_f000
        };
        base | u32::try_from(displacement.unsigned_abs()).unwrap()
    }

    fn a32_branch(slot: u32, target: u32) -> u32 {
        let displacement = i64::from(target) - (i64::from(slot) + 8);
        assert_eq!(displacement % 4, 0);
        let words = displacement / 4;
        assert!((-0x80_0000..=0x7f_ffff).contains(&words));
        0xea00_0000 | u32::try_from(words & 0x00ff_ffff).unwrap()
    }

    fn a32_mov_half(register: u8, immediate: u16, high: bool) -> u32 {
        let opcode = if high { 0xe340_0000 } else { 0xe300_0000 };
        opcode
            | ((u32::from(immediate) & 0xf000) << 4)
            | (u32::from(register) << 12)
            | (u32::from(immediate) & 0x0fff)
    }

    fn canonical_raw_fixture() -> Vec<u8> {
        let mut raw = vec![0; IMAGE_SIZE];
        let targets = [
            RESET_ENTRY,
            RESET_ENTRY,
            BASE + 0x500,
            BASE + 0x504,
            BASE + 0x508,
            BASE + 0x50c,
            BASE + 0x510,
            BASE + 0x514,
        ];
        for (index, target) in targets.into_iter().enumerate() {
            let slot = BASE + u32::try_from(index).unwrap() * 4;
            let literal = literal_address(index);
            write_u32(&mut raw, slot, a32_ldr_pc(slot, literal));
            write_u32(&mut raw, literal, target);
            write_u32(&mut raw, target, ARM_NOP);
        }

        write_u32(&mut raw, RESET_ENTRY, a32_mov_half(0, BASE as u16, false));
        write_u32(
            &mut raw,
            RESET_ENTRY + 4,
            a32_mov_half(0, (BASE >> 16) as u16, true),
        );
        write_u32(&mut raw, RESET_ENTRY + 8, 0xee0c_0f10);
        write_u32(&mut raw, RESET_ENTRY + 12, 0xe12f_ff1e);
        raw
    }

    fn ghidra_raw_fixture() -> Vec<u8> {
        const IMAGE_SIZE: usize = 0x1000;
        const TARGETS: [u32; 8] = [
            BASE + 0x200,
            BASE + 0x220,
            BASE + 0x240,
            BASE + 0x260,
            BASE + 0x280,
            BASE + 0x280,
            BASE + 0x2a0,
            BASE + 0x2c0,
        ];
        const THUMB: [bool; 8] = [false, true, false, true, false, false, false, true];

        let mut raw = vec![0; IMAGE_SIZE];
        for (index, target) in TARGETS.into_iter().enumerate() {
            let instruction: &[u8] = if target == BASE + 0x220 {
                &[0x41, 0xf2, 0x34, 0x20]
            } else if THUMB[index] {
                &[0x70, 0x47]
            } else {
                &[0x1e, 0xff, 0x2f, 0xe1]
            };
            let offset = usize::try_from(target - BASE).unwrap();
            raw[offset..offset + instruction.len()].copy_from_slice(instruction);

            let slot = BASE + u32::try_from(index).unwrap() * 4;
            if index == 0 {
                write_u32(&mut raw, slot, a32_branch(slot, target));
            } else {
                let literal = BASE + 0x40 + u32::try_from(index).unwrap() * 4;
                write_u32(&mut raw, slot, a32_ldr_pc(slot, literal));
                write_u32(
                    &mut raw,
                    literal,
                    if THUMB[index] { target | 1 } else { target },
                );
            }
        }
        raw
    }

    fn ghidra_nonlexical_shared_fixture() -> Vec<u8> {
        let mut raw = ghidra_raw_fixture();
        write_u32(&mut raw, BASE + 0x4c, BASE + 0x240);
        raw
    }

    fn ghidra_relocated_same_targets_fixture() -> Vec<u8> {
        let mut raw = ghidra_raw_fixture();
        let relocated = BASE + 0x100;
        let literals = BASE + 0x140;
        write_u32(
            &mut raw,
            BASE + 0x200,
            a32_mov_half(0, relocated as u16, false),
        );
        write_u32(
            &mut raw,
            BASE + 0x204,
            a32_mov_half(0, (relocated >> 16) as u16, true),
        );
        write_u32(&mut raw, BASE + 0x208, 0xee0c_0f10);
        write_u32(&mut raw, BASE + 0x20c, 0xe12f_ff1e);
        let targets = [
            (BASE + 0x200, false),
            (BASE + 0x220, true),
            (BASE + 0x240, false),
            (BASE + 0x260, true),
            (BASE + 0x280, false),
            (BASE + 0x280, false),
            (BASE + 0x2a0, false),
            (BASE + 0x2c0, true),
        ];
        for (index, (target, thumb)) in targets.into_iter().enumerate() {
            let slot = relocated + u32::try_from(index).unwrap() * 4;
            let literal = literals + u32::try_from(index).unwrap() * 4;
            write_u32(&mut raw, slot, a32_ldr_pc(slot, literal));
            write_u32(&mut raw, literal, if thumb { target | 1 } else { target });
        }
        raw
    }

    fn write_scatter_descriptor(
        raw: &mut [u8],
        index: u32,
        source: u32,
        destination: u32,
        size: u32,
        handler: u32,
    ) {
        let address = BASE + 0x400 + index * 16;
        for (offset, value) in [source, destination, size, handler].into_iter().enumerate() {
            write_u32(raw, address + u32::try_from(offset).unwrap() * 4, value);
        }
    }

    fn ghidra_scatter_fixture() -> Vec<u8> {
        const COPY_DESTINATION: u32 = BASE + 0x1000;
        const DECOMPRESS_DESTINATION: u32 = COPY_DESTINATION + 0x10;
        const ZERO_DESTINATION: u32 = COPY_DESTINATION + 0x20;
        const NULL_HANDLER: u32 = BASE + 0x600;
        const COPY_HANDLER: u32 = BASE + 0x601;
        const DECOMPRESS_HANDLER: u32 = BASE + 0x604;
        const ZERO_HANDLER: u32 = BASE + 0x609;
        const SENTINEL_SOURCE: u32 = BASE + 0x680;
        const SELF_COPY_SOURCE: u32 = BASE + 0x700;
        const DECOMPRESS_SOURCE: u32 = BASE + 0x720;
        const ZERO_SOURCE: u32 = BASE + 0x730;

        let mut raw = ghidra_raw_fixture();
        for (offset, instruction) in [0xe28f_0078, 0xe890_0c00, 0xe08a_a000, 0xe08b_b000]
            .into_iter()
            .enumerate()
        {
            write_u32(
                &mut raw,
                BASE + 0x300 + u32::try_from(offset).unwrap() * 4,
                instruction,
            );
        }
        let literal_pair = BASE + 0x380;
        let table = BASE + 0x400;
        write_u32(&mut raw, literal_pair, table.wrapping_sub(literal_pair));
        write_u32(
            &mut raw,
            literal_pair + 4,
            (table + 7 * 16).wrapping_sub(literal_pair),
        );
        raw[0x700..0x704].copy_from_slice(&[0xff; 4]);
        raw[0x720..0x722].copy_from_slice(&[0x22, 0xaa]);
        for (index, source, destination, size, handler) in [
            (0, SENTINEL_SOURCE, 0, 0, NULL_HANDLER),
            (1, 0, SENTINEL_SOURCE, 0, NULL_HANDLER),
            (2, SELF_COPY_SOURCE, SELF_COPY_SOURCE, 4, COPY_HANDLER),
            (3, BASE + 0x2c0, COPY_DESTINATION, 2, COPY_HANDLER),
            (4, BASE + 0x200, COPY_DESTINATION + 8, 4, COPY_HANDLER),
            (
                5,
                DECOMPRESS_SOURCE,
                DECOMPRESS_DESTINATION,
                3,
                DECOMPRESS_HANDLER,
            ),
            (6, ZERO_SOURCE, ZERO_DESTINATION, 5, ZERO_HANDLER),
        ] {
            write_scatter_descriptor(
                raw.as_mut_slice(),
                index,
                source,
                destination,
                size,
                handler,
            );
        }
        write_u32(&mut raw, BASE + 0x5c, COPY_DESTINATION | 1);
        write_u32(&mut raw, BASE, a32_branch(BASE, COPY_DESTINATION + 8));
        raw
    }

    fn scatter_fixture() -> (Vec<u8>, LoadPlan) {
        let mut raw = canonical_raw_fixture();
        let source = BASE + 0x600;
        let copy_handler = BASE + 0x700;
        write_u32(&mut raw, literal_address(7), SCATTER_ROOT);
        write_u32(&mut raw, source, ARM_NOP);
        let plan = LoadPlan {
            image_base: BASE,
            image_size: u32::try_from(raw.len()).unwrap(),
            loader_address: BASE + 0x680,
            literal_pair_address: BASE + 0x690,
            table_start: BASE + 0x6a0,
            table_end: BASE + 0x6b0,
            handlers: HandlerMap {
                null: BASE + 0x6c0,
                copy: copy_handler,
                decompress1: BASE + 0x704,
                zero: BASE + 0x708,
            },
            entries: vec![PlannedEntry {
                index: 0,
                descriptor: Descriptor {
                    source,
                    destination: SCATTER_ROOT,
                    size: 4,
                    handler: copy_handler,
                },
                operation: Operation::Copy,
                compressed_size: None,
                output: PlannedOutput::Bytes(ARM_NOP.to_le_bytes().to_vec()),
            }],
            logical_output_size: 4,
        };
        (raw, plan)
    }

    fn relocated_raw_fixture() -> Vec<u8> {
        const RELOCATED: u32 = BASE + 0x1000;
        let mut raw = vec![0; 0x2000];
        let initial_targets: [u32; 8] =
            std::array::from_fn(|index| RESET_ENTRY + u32::try_from(index).unwrap() * 0x40);
        let relocated_targets: [u32; 8] =
            std::array::from_fn(|index| BASE + 0x1800 + u32::try_from(index).unwrap() * 4);
        for (table, literals, targets) in [
            (BASE, BASE + 0x40, initial_targets),
            (RELOCATED, RELOCATED + 0x40, relocated_targets),
        ] {
            for (index, target) in targets.into_iter().enumerate() {
                let slot = table + u32::try_from(index).unwrap() * 4;
                let literal = literals + u32::try_from(index).unwrap() * 4;
                write_u32(&mut raw, slot, a32_ldr_pc(slot, literal));
                write_u32(&mut raw, literal, target);
                write_u32(&mut raw, target, ARM_NOP);
            }
        }
        write_u32(
            &mut raw,
            RESET_ENTRY,
            a32_mov_half(0, RELOCATED as u16, false),
        );
        write_u32(
            &mut raw,
            RESET_ENTRY + 4,
            a32_mov_half(0, (RELOCATED >> 16) as u16, true),
        );
        write_u32(&mut raw, RESET_ENTRY + 8, 0xee0c_0f10);
        write_u32(&mut raw, RESET_ENTRY + 12, 0xe12f_ff1e);
        raw
    }

    fn replace_once(bytes: &[u8], from: &str, to: &str) -> Vec<u8> {
        let text = std::str::from_utf8(bytes).unwrap();
        assert_eq!(text.matches(from).count(), 1, "mutation target {from:?}");
        text.replacen(from, to, 1).into_bytes()
    }

    fn replace_all(bytes: &[u8], from: &str, to: &str) -> Vec<u8> {
        let text = std::str::from_utf8(bytes).unwrap();
        assert!(text.contains(from), "mutation target {from:?}");
        text.replace(from, to).into_bytes()
    }

    fn write_manifest(root: &tempfile::TempDir, bytes: &[u8]) -> std::path::PathBuf {
        let path = root.path().join("exception_roots/01_MAIN/roots.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn materializes_canonical_v1_and_revalidates_it() {
        let raw = canonical_raw_fixture();
        let runtime = RuntimeImage::from_plan(&raw, BASE, None).unwrap();
        let plan = discover(&runtime, "01_MAIN", "MAIN").unwrap().unwrap();
        let context = ExceptionArtifactContext {
            label: "01_MAIN",
            toc_name: "MAIN",
            image_blake3: *blake3::hash(&raw).as_bytes(),
            scatter_load_map_blake3: None,
        };
        let root = tempfile::tempdir().unwrap();

        let map = materialize(&plan, context, root.path()).unwrap();

        assert_eq!(map.relative_path, "exception_roots/01_MAIN/roots.json");
        let bytes = std::fs::read(root.path().join(&map.relative_path)).unwrap();
        assert_eq!(bytes.len(), 27_244);
        assert_eq!(
            map.blake3,
            "799292b0fcbe955c61f22f0efbfc10fc4c610cabf675246318b378602f9ac39e"
        );
        assert_eq!(
            map.identity,
            "v1:799292b0fcbe955c61f22f0efbfc10fc4c610cabf675246318b378602f9ac39e:1:7"
        );
        let text = std::str::from_utf8(&bytes).unwrap();
        let top_level_keys: Vec<&str> = text
            .lines()
            .filter_map(|line| {
                line.strip_prefix("  \"")
                    .filter(|_| !line.starts_with("    "))
                    .and_then(|rest| rest.split_once('\"').map(|(key, _)| key))
            })
            .collect();
        assert_eq!(
            top_level_keys,
            [
                "format",
                "schema_version",
                "tool_version",
                "image",
                "runtime",
                "decoder",
                "initial_table",
                "relocation",
                "tables",
                "roots",
                "applications",
            ]
        );
        assert!(!bytes.ends_with(b"\n"));
        let validated = read(&root.path().join(&map.relative_path), &runtime, context).unwrap();
        assert_eq!(validated.identity, map.identity);
        assert_eq!(validated.plan, plan);
    }

    #[test]
    fn committed_ghidra_fixture_matches_production_discovery_and_serialization() {
        let fixture_dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/exception_roots");
        let update = std::env::var_os("PME_UPDATE_EXCEPTION_ROOT_FIXTURE").is_some();
        let mut canonical = None;
        for (name, expected_raw) in [
            (None, ghidra_raw_fixture()),
            (
                Some("nonlexical_shared"),
                ghidra_nonlexical_shared_fixture(),
            ),
            (
                Some("relocated_same_targets"),
                ghidra_relocated_same_targets_fixture(),
            ),
        ] {
            let case_dir = name.map_or_else(|| fixture_dir.clone(), |name| fixture_dir.join(name));
            let runtime = RuntimeImage::from_plan(&expected_raw, BASE, None).unwrap();
            let plan = discover(&runtime, "00_BOOT", "BOOT").unwrap().unwrap();
            let context = ExceptionArtifactContext {
                label: "00_BOOT",
                toc_name: "BOOT",
                image_blake3: *blake3::hash(&expected_raw).as_bytes(),
                scatter_load_map_blake3: None,
            };
            let serialized = super::serialize(&plan, &context).unwrap();
            if update {
                std::fs::create_dir_all(&case_dir).unwrap();
                std::fs::write(case_dir.join("synthetic.bin"), &expected_raw).unwrap();
                std::fs::write(case_dir.join("roots.json"), &serialized).unwrap();
            }
            assert_eq!(
                std::fs::read(case_dir.join("synthetic.bin"))
                    .expect("committed synthetic exception-root raw fixture"),
                expected_raw
            );
            assert_eq!(
                std::fs::read(case_dir.join("roots.json"))
                    .expect("committed canonical exception-root manifest fixture"),
                serialized
            );
            if name.is_none() {
                canonical = Some((serialized, plan.tables.len(), plan.roots.len()));
            }
        }

        let scatter_raw = ghidra_scatter_fixture();
        let scatter_plan = crate::scatter::discover(&scatter_raw, BASE)
            .unwrap()
            .expect("synthetic scatter fixture");
        let scatter_root = tempfile::tempdir().unwrap();
        let scatter_map = crate::scatter::materialize(
            &scatter_plan,
            &scatter_raw,
            "00_BOOT",
            scatter_root.path(),
        )
        .unwrap();
        let scatter_bytes =
            std::fs::read(scatter_root.path().join(&scatter_map.relative_path)).unwrap();
        let scatter_blake3 = *blake3::hash(&scatter_bytes).as_bytes();
        assert_eq!(
            scatter_map.blake3,
            blake3::hash(&scatter_bytes).to_hex().to_string()
        );
        let runtime = RuntimeImage::from_plan(&scatter_raw, BASE, Some(&scatter_plan)).unwrap();
        let scatter_exception_plan = discover(&runtime, "00_BOOT", "BOOT").unwrap().unwrap();
        let scatter_context = ExceptionArtifactContext {
            label: "00_BOOT",
            toc_name: "BOOT",
            image_blake3: *blake3::hash(&scatter_raw).as_bytes(),
            scatter_load_map_blake3: Some(scatter_blake3),
        };
        let scatter_serialized =
            super::serialize(&scatter_exception_plan, &scatter_context).unwrap();
        let scatter_fixture_dir = fixture_dir.join("scatter");
        if update {
            std::fs::create_dir_all(&scatter_fixture_dir).unwrap();
            std::fs::write(scatter_fixture_dir.join("synthetic.bin"), &scatter_raw).unwrap();
            std::fs::write(scatter_fixture_dir.join("roots.json"), &scatter_serialized).unwrap();
        }
        assert_eq!(
            std::fs::read(scatter_fixture_dir.join("synthetic.bin"))
                .expect("committed synthetic scatter exception-root raw fixture"),
            scatter_raw
        );
        assert_eq!(
            std::fs::read(scatter_fixture_dir.join("roots.json"))
                .expect("committed canonical scatter exception-root manifest fixture"),
            scatter_serialized
        );

        let (committed, tables, roots) = canonical.unwrap();
        assert_eq!(
            blake3::hash(&committed).to_hex().as_str(),
            "078cc132cc0c351f6bbf7dba7ce29e53cbd94c730962800b467753395ba3b203"
        );
        assert_eq!(
            super::identity(*blake3::hash(&committed).as_bytes(), tables, roots),
            "v1:078cc132cc0c351f6bbf7dba7ce29e53cbd94c730962800b467753395ba3b203:1:7"
        );
    }

    #[cfg(unix)]
    #[test]
    fn materialize_rejects_a_symlinked_output_root_without_writing_through_it() {
        let raw = canonical_raw_fixture();
        let runtime = RuntimeImage::from_plan(&raw, BASE, None).unwrap();
        let plan = discover(&runtime, "01_MAIN", "MAIN").unwrap().unwrap();
        let context = ExceptionArtifactContext {
            label: "01_MAIN",
            toc_name: "MAIN",
            image_blake3: *blake3::hash(&raw).as_bytes(),
            scatter_load_map_blake3: None,
        };
        let parent = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let linked_root = parent.path().join("linked-root");
        std::os::unix::fs::symlink(external.path(), &linked_root).unwrap();

        let result = materialize(&plan, context, &linked_root);

        assert!(matches!(
            result,
            Err(crate::exception_roots::ExceptionRootError::Artifact(_))
        ));
        assert!(!external.path().join("exception_roots").exists());
    }

    #[test]
    fn pre_commit_failure_preserves_the_old_complete_manifest() {
        let raw = canonical_raw_fixture();
        let runtime = RuntimeImage::from_plan(&raw, BASE, None).unwrap();
        let plan = discover(&runtime, "01_MAIN", "MAIN").unwrap().unwrap();
        let context = ExceptionArtifactContext {
            label: "01_MAIN",
            toc_name: "MAIN",
            image_blake3: *blake3::hash(&raw).as_bytes(),
            scatter_load_map_blake3: None,
        };
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("exception_roots/01_MAIN/roots.json");
        materialize(&plan, context, root.path()).unwrap();
        let old_bytes = std::fs::read(&path).unwrap();
        super::set_before_commit_failure("injected pre-commit failure");

        let result = materialize(
            &plan,
            ExceptionArtifactContext {
                image_blake3: [7; 32],
                ..context
            },
            root.path(),
        );

        assert!(matches!(
            result,
            Err(crate::exception_roots::ExceptionRootError::Artifact(_))
        ));
        assert_eq!(std::fs::read(path).unwrap(), old_bytes);
    }

    #[cfg(unix)]
    #[test]
    fn replacement_preserves_existing_manifest_mode() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let raw = canonical_raw_fixture();
        let runtime = RuntimeImage::from_plan(&raw, BASE, None).unwrap();
        let plan = discover(&runtime, "01_MAIN", "MAIN").unwrap().unwrap();
        let context = ExceptionArtifactContext {
            label: "01_MAIN",
            toc_name: "MAIN",
            image_blake3: *blake3::hash(&raw).as_bytes(),
            scatter_load_map_blake3: None,
        };
        let root = tempfile::tempdir().unwrap();
        let materialized = materialize(&plan, context, root.path()).unwrap();
        let path = root.path().join(materialized.relative_path);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let expected_mode = std::fs::metadata(&path).unwrap().mode() & 0o7777;

        materialize(
            &plan,
            ExceptionArtifactContext {
                image_blake3: [7; 32],
                ..context
            },
            root.path(),
        )
        .unwrap();

        assert_eq!(
            std::fs::metadata(path).unwrap().mode() & 0o7777,
            expected_mode
        );
    }

    #[test]
    fn oversized_serialized_manifest_is_rejected_before_opening_the_destination() {
        let raw = canonical_raw_fixture();
        let runtime = RuntimeImage::from_plan(&raw, BASE, None).unwrap();
        let plan = discover(&runtime, "01_MAIN", "MAIN").unwrap().unwrap();
        let context = ExceptionArtifactContext {
            label: "01_MAIN",
            toc_name: "MAIN",
            image_blake3: *blake3::hash(&raw).as_bytes(),
            scatter_load_map_blake3: None,
        };
        let root = tempfile::tempdir().unwrap();
        let label_dir = root.path().join("exception_roots/01_MAIN");
        let path = label_dir.join("roots.json");
        materialize(&plan, context, root.path()).unwrap();
        let old_bytes = std::fs::read(&path).unwrap();
        super::set_serialized_manifest_override(vec![b' '; 1024 * 1024 + 1]);

        let error = materialize(&plan, context, root.path()).unwrap_err();

        assert!(error.to_string().contains("1048576-byte ceiling"));
        assert_eq!(std::fs::read(path).unwrap(), old_bytes);
        assert_eq!(std::fs::read_dir(label_dir).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn reader_rejects_a_manifest_reached_through_a_symlinked_label_parent() {
        let raw = canonical_raw_fixture();
        let runtime = RuntimeImage::from_plan(&raw, BASE, None).unwrap();
        let plan = discover(&runtime, "01_MAIN", "MAIN").unwrap().unwrap();
        let context = ExceptionArtifactContext {
            label: "01_MAIN",
            toc_name: "MAIN",
            image_blake3: *blake3::hash(&raw).as_bytes(),
            scatter_load_map_blake3: None,
        };
        let external = tempfile::tempdir().unwrap();
        materialize(&plan, context, external.path()).unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("exception_roots")).unwrap();
        std::os::unix::fs::symlink(
            external.path().join("exception_roots/01_MAIN"),
            root.path().join("exception_roots/01_MAIN"),
        )
        .unwrap();
        let path = root.path().join("exception_roots/01_MAIN/roots.json");

        let result = read(&path, &runtime, context);

        assert!(matches!(
            result,
            Err(crate::exception_roots::ExceptionRootError::Artifact(_))
        ));
    }

    #[test]
    fn pinned_reader_rejects_a_stale_external_identity() {
        let raw = canonical_raw_fixture();
        let runtime = RuntimeImage::from_plan(&raw, BASE, None).unwrap();
        let plan = discover(&runtime, "01_MAIN", "MAIN").unwrap().unwrap();
        let context = ExceptionArtifactContext {
            label: "01_MAIN",
            toc_name: "MAIN",
            image_blake3: *blake3::hash(&raw).as_bytes(),
            scatter_load_map_blake3: None,
        };
        let root = tempfile::tempdir().unwrap();
        let materialized = materialize(&plan, context, root.path()).unwrap();
        let path = root.path().join(materialized.relative_path);
        let stale = format!(
            "v1:{}:{}:{}",
            "0".repeat(64),
            plan.tables.len(),
            plan.roots.len()
        );

        let stale_result = super::read_with_identity(&path, &runtime, context, &stale);
        let current =
            super::read_with_identity(&path, &runtime, context, &materialized.identity).unwrap();

        assert!(matches!(
            stale_result,
            Err(crate::exception_roots::ExceptionRootError::Artifact(_))
        ));
        assert_eq!(current.identity, materialized.identity);
    }

    #[test]
    fn exact_bytes_reader_matches_the_retained_path_reader() {
        let raw = canonical_raw_fixture();
        let runtime = RuntimeImage::from_plan(&raw, BASE, None).unwrap();
        let plan = discover(&runtime, "01_MAIN", "MAIN").unwrap().unwrap();
        let context = ExceptionArtifactContext {
            label: "01_MAIN",
            toc_name: "MAIN",
            image_blake3: *blake3::hash(&raw).as_bytes(),
            scatter_load_map_blake3: None,
        };
        let root = tempfile::tempdir().unwrap();
        let materialized = materialize(&plan, context, root.path()).unwrap();
        let path = root.path().join(materialized.relative_path);
        let bytes = std::fs::read(&path).unwrap();

        assert_eq!(
            read_bytes(&bytes, &runtime, context).unwrap(),
            read(&path, &runtime, context).unwrap()
        );
    }

    #[test]
    fn scatter_backed_manifest_binds_map_root_bytes_and_storage_entry() {
        let (raw, scatter) = scatter_fixture();
        let runtime = RuntimeImage::from_plan(&raw, BASE, Some(&scatter)).unwrap();
        let plan = discover(&runtime, "01_MAIN", "MAIN").unwrap().unwrap();
        let context = ExceptionArtifactContext {
            label: "01_MAIN",
            toc_name: "MAIN",
            image_blake3: *blake3::hash(&raw).as_bytes(),
            scatter_load_map_blake3: Some([0x5a; 32]),
        };
        let root = tempfile::tempdir().unwrap();
        let materialized = materialize(&plan, context, root.path()).unwrap();
        let path = root.path().join(materialized.relative_path);
        let bytes = std::fs::read(&path).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.contains(
            "\"scatter_load_map_blake3\": \"5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a\""
        ));
        assert!(text.contains("\"scatter_entries_used\": [\n      0\n    ]"));
        assert_eq!(read(&path, &runtime, context).unwrap().plan, plan);

        let wrong_context = ExceptionArtifactContext {
            scatter_load_map_blake3: Some([0x6a; 32]),
            ..context
        };
        assert!(read(&path, &runtime, wrong_context).is_err());

        let mut changed_bytes = scatter.clone();
        changed_bytes.entries[0].output =
            PlannedOutput::Bytes(0xe12f_ff1eu32.to_le_bytes().to_vec());
        let changed_runtime = RuntimeImage::from_plan(&raw, BASE, Some(&changed_bytes)).unwrap();
        assert!(read(&path, &changed_runtime, context).is_err());

        let mut changed_storage = scatter;
        changed_storage.entries[0].index = 1;
        let changed_runtime = RuntimeImage::from_plan(&raw, BASE, Some(&changed_storage)).unwrap();
        assert!(read(&path, &changed_runtime, context).is_err());
    }

    #[test]
    fn strict_reader_rejects_schema_drift_and_noncanonical_bytes() {
        let raw = canonical_raw_fixture();
        let runtime = RuntimeImage::from_plan(&raw, BASE, None).unwrap();
        let plan = discover(&runtime, "01_MAIN", "MAIN").unwrap().unwrap();
        let context = ExceptionArtifactContext {
            label: "01_MAIN",
            toc_name: "MAIN",
            image_blake3: *blake3::hash(&raw).as_bytes(),
            scatter_load_map_blake3: None,
        };
        let canonical = {
            let root = tempfile::tempdir().unwrap();
            let map = materialize(&plan, context, root.path()).unwrap();
            std::fs::read(root.path().join(map.relative_path)).unwrap()
        };
        let format_line = concat!(
            "  \"format\": \"pixel-modem-extractor-exception-roots-v1\",\n",
            "  \"schema_version\": 1,"
        );
        let mutations = [
            (
                "unknown field",
                replace_once(
                    &canonical,
                    format_line,
                    concat!(
                        "  \"format\": \"pixel-modem-extractor-exception-roots-v1\",\n",
                        "  \"unknown\": 0,\n",
                        "  \"schema_version\": 1,"
                    ),
                ),
            ),
            (
                "missing field",
                replace_once(&canonical, "  \"schema_version\": 1,\n", ""),
            ),
            (
                "duplicate field",
                replace_once(
                    &canonical,
                    "  \"schema_version\": 1,",
                    "  \"schema_version\": 1,\n  \"schema_version\": 1,",
                ),
            ),
            (
                "top-level order",
                replace_once(
                    &canonical,
                    format_line,
                    concat!(
                        "  \"schema_version\": 1,\n",
                        "  \"format\": \"pixel-modem-extractor-exception-roots-v1\","
                    ),
                ),
            ),
            (
                "noncanonical address",
                replace_once(
                    &canonical,
                    "\"base_addr\": \"0x40010000\"",
                    "\"base_addr\": \"0X40010000\"",
                ),
            ),
            (
                "legacy format",
                replace_once(
                    &canonical,
                    "pixel-modem-extractor-exception-roots-v1",
                    "pixel-modem-extractor-exception-roots-v0",
                ),
            ),
            (
                "slot count/index drift",
                replace_all(&canonical, "\"index\": 0,", "\"index\": 8,"),
            ),
            {
                let mut bytes = canonical.clone();
                bytes.push(b'\n');
                ("trailing newline", bytes)
            },
        ];

        for (name, bytes) in mutations {
            let root = tempfile::tempdir().unwrap();
            let path = write_manifest(&root, &bytes);
            assert!(read(&path, &runtime, context).is_err(), "accepted {name}");
        }
    }

    #[test]
    fn strict_reader_recomputes_every_semantic_plan_surface() {
        let raw = canonical_raw_fixture();
        let runtime = RuntimeImage::from_plan(&raw, BASE, None).unwrap();
        let plan = discover(&runtime, "01_MAIN", "MAIN").unwrap().unwrap();
        let context = ExceptionArtifactContext {
            label: "01_MAIN",
            toc_name: "MAIN",
            image_blake3: *blake3::hash(&raw).as_bytes(),
            scatter_load_map_blake3: None,
        };
        let canonical = {
            let root = tempfile::tempdir().unwrap();
            let map = materialize(&plan, context, root.path()).unwrap();
            std::fs::read(root.path().join(map.relative_path)).unwrap()
        };
        let zeros = "0".repeat(64);
        let table_hash = blake3::Hash::from(plan.initial_table.blake3)
            .to_hex()
            .to_string();
        let slot_hash = blake3::Hash::from(plan.initial_table.slots[0].slot_blake3)
            .to_hex()
            .to_string();
        let literal_hash = blake3::Hash::from(plan.initial_table.slots[0].literal_blake3.unwrap())
            .to_hex()
            .to_string();
        let root_hash = blake3::Hash::from(plan.roots[0].instruction_blake3)
            .to_hex()
            .to_string();
        let mutations = [
            (
                "decoder identity",
                replace_once(
                    &canonical,
                    "\"version\": \"1.0.0\"",
                    "\"version\": \"1.0.1\"",
                ),
            ),
            ("table bytes", replace_all(&canonical, &table_hash, &zeros)),
            ("slot bytes", replace_all(&canonical, &slot_hash, &zeros)),
            (
                "literal bytes",
                replace_all(&canonical, &literal_hash, &zeros),
            ),
            ("root bytes", replace_all(&canonical, &root_hash, &zeros)),
            (
                "storage provenance",
                replace_once(
                    &canonical,
                    "\"kind\": \"raw\",\n        \"address\": \"0x40010000\",\n        \"size\": 32,\n        \"scatter_entry\": null",
                    "\"kind\": \"scatter_bytes\",\n        \"address\": \"0x40010000\",\n        \"size\": 32,\n        \"scatter_entry\": 0",
                ),
            ),
            (
                "VBAR selected evidence",
                replace_all(
                    &canonical,
                    "\"exact_value\": \"0x40010000\"",
                    "\"exact_value\": \"0x40011000\"",
                ),
            ),
            (
                "application primary",
                replace_once(
                    &canonical,
                    "\"desired_primary\": \"SupervisorCall\"",
                    "\"desired_primary\": \"WrongPrimary\"",
                ),
            ),
            (
                "application role order",
                replace_once(
                    &canonical,
                    concat!(
                        "\"role_labels\": [\n",
                        "        \"exception_reset_40010000\",\n",
                        "        \"exception_undefined_instruction_40010000\"\n",
                        "      ]"
                    ),
                    concat!(
                        "\"role_labels\": [\n",
                        "        \"exception_undefined_instruction_40010000\",\n",
                        "        \"exception_reset_40010000\"\n",
                        "      ]"
                    ),
                ),
            ),
        ];

        for (name, bytes) in mutations {
            let root = tempfile::tempdir().unwrap();
            let path = write_manifest(&root, &bytes);
            assert!(read(&path, &runtime, context).is_err(), "accepted {name}");
        }

        let mut changed_image = raw.clone();
        changed_image[0x700] ^= 1;
        let changed_runtime = RuntimeImage::from_plan(&changed_image, BASE, None).unwrap();
        let root = tempfile::tempdir().unwrap();
        let path = write_manifest(&root, &canonical);
        assert!(read(&path, &changed_runtime, context).is_err());
    }

    #[test]
    fn strict_reader_rejects_dependency_byte_drift_after_rebinding_the_image_hash() {
        let raw = canonical_raw_fixture();
        let runtime = RuntimeImage::from_plan(&raw, BASE, None).unwrap();
        let plan = discover(&runtime, "01_MAIN", "MAIN").unwrap().unwrap();
        let context = ExceptionArtifactContext {
            label: "01_MAIN",
            toc_name: "MAIN",
            image_blake3: *blake3::hash(&raw).as_bytes(),
            scatter_load_map_blake3: None,
        };
        let canonical = {
            let root = tempfile::tempdir().unwrap();
            let map = materialize(&plan, context, root.path()).unwrap();
            std::fs::read(root.path().join(map.relative_path)).unwrap()
        };
        let old_image_hash = blake3::hash(&raw).to_hex().to_string();
        let mut table_slot = raw.clone();
        let slot = BASE + 2 * 4;
        write_u32(&mut table_slot, slot, a32_ldr_pc(slot, literal_address(3)));
        let mut literal = raw.clone();
        write_u32(&mut literal, literal_address(2), BASE + 0x504);
        let mut root_bytes = raw.clone();
        write_u32(&mut root_bytes, BASE + 0x500, 0xe12f_ff1e);
        let mut vbar_proof = raw.clone();
        write_u32(
            &mut vbar_proof,
            RESET_ENTRY,
            a32_mov_half(1, BASE as u16, false),
        );
        write_u32(
            &mut vbar_proof,
            RESET_ENTRY + 4,
            a32_mov_half(1, (BASE >> 16) as u16, true),
        );
        write_u32(&mut vbar_proof, RESET_ENTRY + 8, 0xee0c_1f10);

        for (name, changed) in [
            ("table and slot bytes", table_slot),
            ("literal bytes", literal),
            ("root bytes", root_bytes),
            ("VBAR proof bytes", vbar_proof),
        ] {
            let changed_hash = *blake3::hash(&changed).as_bytes();
            let manifest = replace_once(
                &canonical,
                &old_image_hash,
                blake3::Hash::from(changed_hash).to_hex().as_ref(),
            );
            let changed_runtime = RuntimeImage::from_plan(&changed, BASE, None).unwrap();
            let root = tempfile::tempdir().unwrap();
            let path = write_manifest(&root, &manifest);
            let changed_context = ExceptionArtifactContext {
                image_blake3: changed_hash,
                ..context
            };
            assert!(
                read(&path, &changed_runtime, changed_context).is_err(),
                "accepted {name}"
            );
        }
    }

    #[test]
    fn present_replaces_only_the_owned_manifest_and_absence_preserves_foreign_siblings() {
        let raw = canonical_raw_fixture();
        let runtime = RuntimeImage::from_plan(&raw, BASE, None).unwrap();
        let plan = discover(&runtime, "01_MAIN", "MAIN").unwrap().unwrap();
        let context = ExceptionArtifactContext {
            label: "01_MAIN",
            toc_name: "MAIN",
            image_blake3: *blake3::hash(&raw).as_bytes(),
            scatter_load_map_blake3: None,
        };
        let root = tempfile::tempdir().unwrap();
        let first = materialize(&plan, context, root.path()).unwrap();
        let path = root.path().join(&first.relative_path);
        let first_bytes = std::fs::read(&path).unwrap();
        std::fs::write(root.path().join("foreign.bin"), b"outside").unwrap();
        std::fs::create_dir_all(root.path().join("exception_roots/02_VSS")).unwrap();
        std::fs::write(
            root.path().join("exception_roots/02_VSS/foreign.bin"),
            b"other-label",
        )
        .unwrap();
        std::fs::write(path.parent().unwrap().join("foreign.bin"), b"same-label").unwrap();

        let second = materialize(
            &plan,
            ExceptionArtifactContext {
                image_blake3: [9; 32],
                ..context
            },
            root.path(),
        )
        .unwrap();

        assert_ne!(std::fs::read(&path).unwrap(), first_bytes);
        assert_ne!(second.identity, first.identity);
        assert_eq!(
            std::fs::read(path.parent().unwrap().join("foreign.bin")).unwrap(),
            b"same-label"
        );
        super::clear_materialized(root.path(), "02_APM").unwrap();
        assert!(path.exists(), "unmanaged label was inferred from existence");
        super::clear_materialized(root.path(), "01_MAIN").unwrap();
        assert!(!path.exists());
        assert_eq!(
            std::fs::read(root.path().join("foreign.bin")).unwrap(),
            b"outside"
        );
        assert_eq!(
            std::fs::read(root.path().join("exception_roots/02_VSS/foreign.bin")).unwrap(),
            b"other-label"
        );
        assert_eq!(
            std::fs::read(root.path().join("exception_roots/01_MAIN/foreign.bin")).unwrap(),
            b"same-label"
        );
        std::fs::remove_file(root.path().join("exception_roots/01_MAIN/foreign.bin")).unwrap();
        super::clear_materialized(root.path(), "01_MAIN").unwrap();
        assert!(root.path().join("exception_roots/01_MAIN").is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn materialize_parent_swap_never_updates_the_replacement_tree() {
        use std::os::unix::fs::symlink;

        let raw = canonical_raw_fixture();
        let runtime = RuntimeImage::from_plan(&raw, BASE, None).unwrap();
        let plan = discover(&runtime, "01_MAIN", "MAIN").unwrap().unwrap();
        let context = ExceptionArtifactContext {
            label: "01_MAIN",
            toc_name: "MAIN",
            image_blake3: *blake3::hash(&raw).as_bytes(),
            scatter_load_map_blake3: None,
        };
        let root = tempfile::tempdir().unwrap();
        materialize(&plan, context, root.path()).unwrap();
        let old_path = root.path().join("exception_roots/01_MAIN/roots.json");
        let old_bytes = std::fs::read(&old_path).unwrap();
        let outside = tempfile::tempdir().unwrap();
        let retained = outside.path().join("retained-label");
        let replacement = outside.path().join("replacement-label");
        std::fs::create_dir(&replacement).unwrap();
        let replacement_manifest = replacement.join("roots.json");
        std::fs::write(&replacement_manifest, b"replacement must survive").unwrap();
        let label = old_path.parent().unwrap().to_path_buf();
        let retained_for_hook = retained.clone();
        let replacement_for_hook = replacement.clone();
        super::set_before_materialize_publication(move || {
            std::fs::rename(&label, &retained_for_hook).unwrap();
            symlink(&replacement_for_hook, &label).unwrap();
        });

        materialize(
            &plan,
            ExceptionArtifactContext {
                image_blake3: [7; 32],
                ..context
            },
            root.path(),
        )
        .unwrap();

        assert_eq!(
            std::fs::read(&replacement_manifest).unwrap(),
            b"replacement must survive"
        );
        assert_ne!(
            std::fs::read(retained.join("roots.json")).unwrap(),
            old_bytes
        );
    }

    #[cfg(unix)]
    #[test]
    fn clear_parent_swap_after_manifest_unlink_preserves_both_directories() {
        use std::os::unix::fs::symlink;

        let raw = canonical_raw_fixture();
        let runtime = RuntimeImage::from_plan(&raw, BASE, None).unwrap();
        let plan = discover(&runtime, "01_MAIN", "MAIN").unwrap().unwrap();
        let context = ExceptionArtifactContext {
            label: "01_MAIN",
            toc_name: "MAIN",
            image_blake3: *blake3::hash(&raw).as_bytes(),
            scatter_load_map_blake3: None,
        };
        let root = tempfile::tempdir().unwrap();
        materialize(&plan, context, root.path()).unwrap();
        let label = root.path().join("exception_roots/01_MAIN");
        let outside = tempfile::tempdir().unwrap();
        let retained = outside.path().join("retained-label");
        let replacement = outside.path().join("replacement-label");
        std::fs::create_dir(&replacement).unwrap();
        let replacement_manifest = replacement.join("roots.json");
        std::fs::write(&replacement_manifest, b"replacement must survive").unwrap();
        let label_for_hook = label.clone();
        let retained_for_hook = retained.clone();
        let replacement_for_hook = replacement.clone();
        super::set_after_clear_manifest_unlink(move || {
            std::fs::rename(&label_for_hook, &retained_for_hook).unwrap();
            symlink(&replacement_for_hook, &label_for_hook).unwrap();
        });

        super::clear_materialized(root.path(), "01_MAIN").unwrap();

        assert_eq!(
            std::fs::read(&replacement_manifest).unwrap(),
            b"replacement must survive"
        );
        assert!(retained.is_dir());
        assert!(!retained.join("roots.json").exists());
    }

    #[cfg(unix)]
    #[test]
    fn reader_setup_swap_cannot_select_the_replacement_manifest() {
        use std::os::unix::fs::symlink;

        let raw = canonical_raw_fixture();
        let runtime = RuntimeImage::from_plan(&raw, BASE, None).unwrap();
        let plan = discover(&runtime, "01_MAIN", "MAIN").unwrap().unwrap();
        let context = ExceptionArtifactContext {
            label: "01_MAIN",
            toc_name: "MAIN",
            image_blake3: *blake3::hash(&raw).as_bytes(),
            scatter_load_map_blake3: None,
        };
        let root = tempfile::tempdir().unwrap();
        let materialized = materialize(&plan, context, root.path()).unwrap();
        let manifest = root.path().join(&materialized.relative_path);
        std::fs::write(&manifest, b"invalid retained manifest").unwrap();
        let outside = tempfile::tempdir().unwrap();
        let external = materialize(&plan, context, outside.path()).unwrap();
        let replacement = outside
            .path()
            .join(external.relative_path)
            .parent()
            .unwrap()
            .to_path_buf();
        let replacement_bytes = std::fs::read(replacement.join("roots.json")).unwrap();
        let retained = outside.path().join("retained-invalid-label");
        let label = manifest.parent().unwrap().to_path_buf();
        let label_for_hook = label.clone();
        let retained_for_hook = retained.clone();
        let replacement_for_hook = replacement.clone();
        super::set_before_reader_setup(move || {
            std::fs::rename(&label_for_hook, &retained_for_hook).unwrap();
            symlink(&replacement_for_hook, &label_for_hook).unwrap();
        });

        let result = read(&manifest, &runtime, context);

        assert!(result.is_err(), "reader selected the replacement manifest");
        assert_eq!(
            std::fs::read(replacement.join("roots.json")).unwrap(),
            replacement_bytes
        );
    }

    #[test]
    fn clear_leaves_empty_label_directory_as_allowed_residue() {
        let raw = canonical_raw_fixture();
        let runtime = RuntimeImage::from_plan(&raw, BASE, None).unwrap();
        let plan = discover(&runtime, "01_MAIN", "MAIN").unwrap().unwrap();
        let context = ExceptionArtifactContext {
            label: "01_MAIN",
            toc_name: "MAIN",
            image_blake3: *blake3::hash(&raw).as_bytes(),
            scatter_load_map_blake3: None,
        };
        let root = tempfile::tempdir().unwrap();
        let materialized = materialize(&plan, context, root.path()).unwrap();
        let manifest = root.path().join(materialized.relative_path);
        super::clear_materialized(root.path(), "01_MAIN").unwrap();

        assert!(!manifest.exists());
        assert!(manifest.parent().unwrap().is_dir());
    }

    #[test]
    fn all_relocation_variants_round_trip_with_exact_variant_fields() {
        let mut not_observed = canonical_raw_fixture();
        write_u32(&mut not_observed, RESET_ENTRY, 0xe12f_ff1e);
        let mut unresolved = canonical_raw_fixture();
        write_u32(&mut unresolved, RESET_ENTRY + 8, 0x1e0c_0f10);
        let mut incomplete = canonical_raw_fixture();
        write_u32(&mut incomplete, RESET_ENTRY, 0xe12f_ff10);
        let fixtures = [
            ("confirmed_initial", canonical_raw_fixture(), 1usize),
            ("relocated", relocated_raw_fixture(), 2usize),
            ("unresolved", unresolved, 1usize),
            ("not_observed", not_observed, 1usize),
            ("analysis_incomplete", incomplete, 1usize),
        ];

        for (status, raw, expected_tables) in fixtures {
            let runtime = RuntimeImage::from_plan(&raw, BASE, None).unwrap();
            let plan = discover(&runtime, "01_MAIN", "MAIN").unwrap().unwrap();
            let context = ExceptionArtifactContext {
                label: "01_MAIN",
                toc_name: "MAIN",
                image_blake3: *blake3::hash(&raw).as_bytes(),
                scatter_load_map_blake3: None,
            };
            let root = tempfile::tempdir().unwrap();
            let materialized = materialize(&plan, context, root.path()).unwrap();
            let path = root.path().join(materialized.relative_path);
            let bytes = std::fs::read(&path).unwrap();

            assert_eq!(materialized.tables, expected_tables, "{status}");
            assert!(
                std::str::from_utf8(&bytes)
                    .unwrap()
                    .contains(&format!("\"status\": \"{status}\"")),
                "{status}"
            );
            assert_eq!(
                read(&path, &runtime, context).unwrap().plan,
                plan,
                "{status}"
            );
        }
    }

    #[test]
    fn materialize_rejects_path_bearing_relocation_evidence() {
        let raw = canonical_raw_fixture();
        let runtime = RuntimeImage::from_plan(&raw, BASE, None).unwrap();
        let mut plan = discover(&runtime, "01_MAIN", "MAIN").unwrap().unwrap();
        plan.relocation = crate::exception_roots::RelocationEvidence::AnalysisIncomplete {
            observations: Vec::new(),
            handoffs: Vec::new(),
            reason: Some("decoder opened /private/corpus/main.bin".to_owned()),
        };
        let context = ExceptionArtifactContext {
            label: "01_MAIN",
            toc_name: "MAIN",
            image_blake3: *blake3::hash(&raw).as_bytes(),
            scatter_load_map_blake3: None,
        };
        let root = tempfile::tempdir().unwrap();

        let result = materialize(&plan, context, root.path());

        assert!(matches!(
            result,
            Err(crate::exception_roots::ExceptionRootError::Artifact(_))
        ));
        assert!(!root.path().join("exception_roots").exists());
    }

    #[test]
    fn publication_and_clear_reject_non_directory_owned_parents_and_leaf() {
        let raw = canonical_raw_fixture();
        let runtime = RuntimeImage::from_plan(&raw, BASE, None).unwrap();
        let plan = discover(&runtime, "01_MAIN", "MAIN").unwrap().unwrap();
        let context = ExceptionArtifactContext {
            label: "01_MAIN",
            toc_name: "MAIN",
            image_blake3: *blake3::hash(&raw).as_bytes(),
            scatter_load_map_blake3: None,
        };

        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("exception_roots"), b"parent-file").unwrap();
        assert!(materialize(&plan, context, root.path()).is_err());
        assert!(super::clear_materialized(root.path(), "01_MAIN").is_err());
        assert_eq!(
            std::fs::read(root.path().join("exception_roots")).unwrap(),
            b"parent-file"
        );

        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("exception_roots")).unwrap();
        std::fs::write(root.path().join("exception_roots/01_MAIN"), b"label-file").unwrap();
        assert!(materialize(&plan, context, root.path()).is_err());
        assert!(super::clear_materialized(root.path(), "01_MAIN").is_err());

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("exception_roots/01_MAIN/roots.json");
        std::fs::create_dir_all(&path).unwrap();
        assert!(materialize(&plan, context, root.path()).is_err());
        assert!(super::clear_materialized(root.path(), "01_MAIN").is_err());
        assert!(read(&path, &runtime, context).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn publication_clear_and_read_reject_a_symlinked_manifest_leaf() {
        let raw = canonical_raw_fixture();
        let runtime = RuntimeImage::from_plan(&raw, BASE, None).unwrap();
        let plan = discover(&runtime, "01_MAIN", "MAIN").unwrap().unwrap();
        let context = ExceptionArtifactContext {
            label: "01_MAIN",
            toc_name: "MAIN",
            image_blake3: *blake3::hash(&raw).as_bytes(),
            scatter_load_map_blake3: None,
        };
        let external = tempfile::tempdir().unwrap();
        let external_map = materialize(&plan, context, external.path()).unwrap();
        let external_path = external.path().join(external_map.relative_path);
        let external_bytes = std::fs::read(&external_path).unwrap();
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("exception_roots/01_MAIN/roots.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&external_path, &path).unwrap();

        assert!(materialize(&plan, context, root.path()).is_err());
        assert!(super::clear_materialized(root.path(), "01_MAIN").is_err());
        assert!(read(&path, &runtime, context).is_err());
        assert_eq!(std::fs::read(external_path).unwrap(), external_bytes);
    }

    #[test]
    fn reader_rejects_oversized_input_before_parsing() {
        let raw = canonical_raw_fixture();
        let runtime = RuntimeImage::from_plan(&raw, BASE, None).unwrap();
        let context = ExceptionArtifactContext {
            label: "01_MAIN",
            toc_name: "MAIN",
            image_blake3: *blake3::hash(&raw).as_bytes(),
            scatter_load_map_blake3: None,
        };
        let root = tempfile::tempdir().unwrap();
        let oversized = vec![b' '; 1024 * 1024 + 1];
        let path = write_manifest(&root, &oversized);

        let error = read(&path, &runtime, context).unwrap_err();

        assert!(error.to_string().contains("1 MiB"));
    }

    #[test]
    fn materialize_rejects_label_path_escape_before_creating_owned_parents() {
        let raw = canonical_raw_fixture();
        let runtime = RuntimeImage::from_plan(&raw, BASE, None).unwrap();
        let mut plan = discover(&runtime, "01_MAIN", "MAIN").unwrap().unwrap();
        plan.image_label = "../escape".to_owned();
        let context = ExceptionArtifactContext {
            label: "../escape",
            toc_name: "MAIN",
            image_blake3: *blake3::hash(&raw).as_bytes(),
            scatter_load_map_blake3: None,
        };
        let root = tempfile::tempdir().unwrap();

        assert!(materialize(&plan, context, root.path()).is_err());
        assert!(!root.path().join("exception_roots").exists());
        assert!(!root.path().parent().unwrap().join("escape").exists());
    }

    #[test]
    fn portable_labels_are_rejected_before_filesystem_effects() {
        let raw = canonical_raw_fixture();
        let runtime = RuntimeImage::from_plan(&raw, BASE, None).unwrap();
        let canonical = discover(&runtime, "01_MAIN", "MAIN").unwrap().unwrap();
        let invalid = [
            String::new(),
            ".".to_owned(),
            "..".to_owned(),
            "a".repeat(256),
            "01_MAIN.".to_owned(),
            "01_MAIN ".to_owned(),
            "CON".to_owned(),
            "prn.txt".to_owned(),
            "AuX.log".to_owned(),
            "nul.bin".to_owned(),
            "com1".to_owned(),
            "COM9.ext".to_owned(),
            "lpt1".to_owned(),
            "LpT9.cfg".to_owned(),
            "bad:name".to_owned(),
            "bad*name".to_owned(),
            "bad/name".to_owned(),
            "bad\\name".to_owned(),
            "bad\0name".to_owned(),
        ];

        for label in invalid {
            let mut plan = canonical.clone();
            plan.image_label = label.clone();
            let context = ExceptionArtifactContext {
                label: &label,
                toc_name: "MAIN",
                image_blake3: *blake3::hash(&raw).as_bytes(),
                scatter_load_map_blake3: None,
            };
            let root = tempfile::tempdir().unwrap();

            let error = materialize(&plan, context, root.path()).unwrap_err();

            assert!(
                error.to_string().contains("invalid artifact label"),
                "unexpected rejection for {label:?}: {error}"
            );
            assert!(
                !root.path().join("exception_roots").exists(),
                "invalid label {label:?} caused a filesystem effect"
            );
        }
    }

    #[test]
    fn materialize_rejects_allocator_drift_before_output_root_access() {
        let raw = canonical_raw_fixture();
        let runtime = RuntimeImage::from_plan(&raw, BASE, None).unwrap();
        let mut plan = discover(&runtime, "01_MAIN", "MAIN").unwrap().unwrap();
        let application = plan
            .applications
            .iter_mut()
            .find(|application| application.desired_primary.is_some())
            .unwrap();
        application.desired_primary = Some("ValidButWrong".to_owned());
        let context = ExceptionArtifactContext {
            label: "01_MAIN",
            toc_name: "MAIN",
            image_blake3: *blake3::hash(&raw).as_bytes(),
            scatter_load_map_blake3: None,
        };
        let holder = tempfile::tempdir().unwrap();
        let absent_root = holder.path().join("must-not-be-opened");

        let error = materialize(&plan, context, &absent_root).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("canonical root/application allocation"),
            "unexpected rejection: {error}"
        );
        assert!(!absent_root.exists());
    }

    #[test]
    fn materialize_rejects_out_of_limit_scatter_provenance() {
        let (raw, mut scatter) = scatter_fixture();
        scatter.entries[0].index = 256;
        let runtime = RuntimeImage::from_plan(&raw, BASE, Some(&scatter)).unwrap();
        let plan = discover(&runtime, "01_MAIN", "MAIN").unwrap().unwrap();
        let context = ExceptionArtifactContext {
            label: "01_MAIN",
            toc_name: "MAIN",
            image_blake3: *blake3::hash(&raw).as_bytes(),
            scatter_load_map_blake3: Some([0x5a; 32]),
        };
        let root = tempfile::tempdir().unwrap();

        let result = materialize(&plan, context, root.path());

        assert!(matches!(
            result,
            Err(crate::exception_roots::ExceptionRootError::Artifact(_))
        ));
        assert!(!root.path().join("exception_roots").exists());
    }
}
use super::discover::build_roots_and_applications;
use super::{
    ExceptionApplication, ExceptionClaim, ExceptionRole, ExceptionRoot, ExceptionRootError,
    ExceptionRootPlan, MAX_ROOTS, MAX_TABLES, MAX_VBAR_WRITES, RelocationEvidence, RootIsa,
    SlotForm, VECTOR_SLOTS, VbarWriteEvidence, VectorSlot, VectorTable, VectorTableKind, discover,
};
use crate::arm32::{InstructionDecoder, PureRustDecoder};
use crate::runtime_image::{RuntimeImage, StorageKind, StorageSpan};
use crate::semantic_cfg::{BoundaryKind, Handoff};
use crate::trusted_fs::TrustedDirectory;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::path::Path;

pub(crate) const FORMAT: &str = "pixel-modem-extractor-exception-roots-v1";

const SCHEMA_VERSION: u32 = 1;
const SEMANTIC_ADAPTER: &str = "pixel-modem-extractor-arm32-v1";
const ARTIFACT_FILE_NAME: &str = "roots.json";
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_REASON_BYTES: usize = 2048;
const MAX_SYMBOL_LEAF_BYTES: usize = 2000;
const MAX_PATH_COMPONENT_BYTES: usize = 255;
const TABLE_BYTES: u32 = VECTOR_SLOTS as u32 * 4;
const WINDOWS_RESERVED_DEVICE_NAMES: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

type Result<T> = std::result::Result<T, ExceptionRootError>;

#[derive(Debug, Clone, Copy)]
pub(crate) struct ExceptionArtifactContext<'a> {
    pub label: &'a str,
    pub toc_name: &'a str,
    pub image_blake3: [u8; 32],
    pub scatter_load_map_blake3: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MaterializedExceptionRoots {
    pub relative_path: String,
    pub blake3: String,
    pub identity: String,
    pub tables: usize,
    pub roots: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValidatedExceptionRoots {
    pub plan: ExceptionRootPlan,
    pub manifest_blake3: [u8; 32],
    pub identity: String,
    pub image_label: String,
    pub toc_name: String,
    pub image_blake3: [u8; 32],
    pub scatter_load_map_blake3: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireManifest {
    format: String,
    schema_version: u32,
    tool_version: String,
    image: WireImage,
    runtime: WireRuntime,
    decoder: WireDecoder,
    initial_table: WireTable,
    relocation: WireRelocation,
    tables: Vec<WireTable>,
    roots: Vec<WireRoot>,
    applications: Vec<WireApplication>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireImage {
    label: String,
    toc_name: String,
    base_addr: String,
    size: u32,
    blake3: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRuntime {
    scatter_load_map_blake3: Option<String>,
    scatter_entries_used: Vec<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireDecoder {
    semantic_adapter: String,
    #[serde(rename = "crate")]
    crate_name: String,
    version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSpan {
    kind: String,
    address: String,
    size: u32,
    scatter_entry: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireTable {
    kind: String,
    address: String,
    blake3: String,
    storage: Vec<WireSpan>,
    slots: Vec<WireSlot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSlot {
    index: usize,
    role: String,
    address: String,
    form: String,
    slot_blake3: String,
    slot_storage: Vec<WireSpan>,
    literal: Option<WireLiteral>,
    entry: String,
    isa: String,
    instruction_size: u8,
    instruction_blake3: String,
    instruction_storage: Vec<WireSpan>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireLiteral {
    address: String,
    blake3: String,
    storage: Vec<WireSpan>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRelocation {
    status: String,
    selected: Option<WireVbarEvidence>,
    table_address: Option<String>,
    observations: Vec<WireVbarEvidence>,
    handoffs: Vec<WireHandoff>,
    reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireVbarEvidence {
    pc: String,
    isa: String,
    source_register: u8,
    conditional: bool,
    exact_value: Option<String>,
    definitions: Vec<String>,
    dominates_handoffs: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireHandoff {
    pc: String,
    kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRoot {
    entry: String,
    isa: String,
    instruction_size: u8,
    instruction_blake3: String,
    storage: Vec<WireSpan>,
    claims: Vec<WireClaim>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireClaim {
    table_kind: String,
    table_address: String,
    slot_address: String,
    role: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireApplication {
    entry: String,
    isa: String,
    desired_primary: Option<String>,
    claims: Vec<WireClaim>,
    role_labels: Vec<String>,
}

pub(crate) fn materialize(
    plan: &ExceptionRootPlan,
    context: ExceptionArtifactContext<'_>,
    root: &Path,
) -> Result<MaterializedExceptionRoots> {
    let bytes = serialized_for_materialize(plan, &context)?;
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(invalid(format!(
            "serialized manifest is {} bytes, above the {MAX_MANIFEST_BYTES}-byte ceiling",
            bytes.len()
        )));
    }

    let trusted_root =
        TrustedDirectory::new(root, "artifact root").map_err(|error| invalid(error.to_string()))?;
    let exception_dir = trusted_root
        .open_or_create_directory_child("exception_roots", "artifact exception_roots directory")
        .map_err(|error| invalid(error.to_string()))?;
    let label_dir = exception_dir
        .open_or_create_directory_child(context.label, "artifact label directory")
        .map_err(|error| invalid(error.to_string()))?;

    let manifest_blake3 = *blake3::hash(&bytes).as_bytes();
    run_before_materialize_publication();
    let mut file = label_dir
        .atomic_write_file(ARTIFACT_FILE_NAME, "manifest destination")
        .map_err(|error| invalid(format!("atomic manifest publication failed: {error}")))?;
    file.write_all(&bytes)
        .map_err(|error| invalid(format!("atomic manifest write failed: {error}")))?;
    run_before_commit()?;
    file.commit()
        .map_err(|error| invalid(format!("atomic manifest commit failed: {error}")))?;

    let tables = plan.tables.len();
    let roots = plan.roots.len();
    Ok(MaterializedExceptionRoots {
        relative_path: format!("exception_roots/{}/roots.json", context.label),
        blake3: blake3_hex(manifest_blake3),
        identity: identity(manifest_blake3, tables, roots),
        tables,
        roots,
    })
}

pub(crate) fn clear_materialized(root: &Path, label: &str) -> Result<()> {
    validate_label(label, "artifact label")?;
    let Some(trusted_root) = TrustedDirectory::open_existing(root, "artifact root")
        .map_err(|error| invalid(error.to_string()))?
    else {
        return Ok(());
    };
    let Some(exception_dir) = trusted_root
        .open_directory_child("exception_roots", "artifact exception_roots directory")
        .map_err(|error| invalid(error.to_string()))?
    else {
        return Ok(());
    };
    let Some(label_dir) = exception_dir
        .open_directory_child(label, "owned label directory")
        .map_err(|error| invalid(error.to_string()))?
    else {
        return Ok(());
    };

    // Manifest unlink or confirmed absence is the complete clear operation. The label directory
    // intentionally remains because post-unlink name cleanup cannot be object-bound on POSIX.
    label_dir
        .unlink_regular_file_if_exists(ARTIFACT_FILE_NAME, "owned manifest")
        .map_err(|error| invalid(error.to_string()))?;
    run_after_clear_manifest_unlink();

    Ok(())
}

pub(crate) fn read(
    path: &Path,
    runtime: &RuntimeImage<'_>,
    expected: ExceptionArtifactContext<'_>,
) -> Result<ValidatedExceptionRoots> {
    validate_label(expected.label, "artifact label")?;
    validate_label(expected.toc_name, "artifact TOC name")?;
    let mut file = open_manifest_file(path, expected.label)?;
    let bytes = read_manifest_bytes(&mut file)?;
    read_bytes(&bytes, runtime, expected)
}

fn read_manifest_bytes(file: &mut File) -> Result<Vec<u8>> {
    let length = file
        .metadata()
        .map_err(|error| invalid(format!("manifest metadata is unavailable: {error}")))?
        .len();
    if length > MAX_MANIFEST_BYTES as u64 {
        return Err(invalid(
            "manifest exceeds the 1 MiB ceiling and is rejected before parsing",
        ));
    }
    let length =
        usize::try_from(length).map_err(|_| invalid("manifest size does not fit the host"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| invalid("manifest allocation failed"))?;
    bytes.resize(length, 0);
    file.read_exact(&mut bytes)
        .map_err(|error| invalid(format!("manifest read failed: {error}")))?;
    let mut trailing = [0u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|error| invalid(format!("manifest trailing read failed: {error}")))?
        != 0
    {
        return Err(invalid("manifest grew while it was being authenticated"));
    }

    Ok(bytes)
}

pub(crate) fn read_bytes(
    bytes: &[u8],
    runtime: &RuntimeImage<'_>,
    expected: ExceptionArtifactContext<'_>,
) -> Result<ValidatedExceptionRoots> {
    validate_label(expected.label, "artifact label")?;
    validate_label(expected.toc_name, "artifact TOC name")?;
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(invalid(
            "manifest exceeds the 1 MiB ceiling and is rejected before parsing",
        ));
    }

    let wire: WireManifest = serde_json::from_slice(bytes)
        .map_err(|error| invalid(format!("manifest schema is invalid: {error}")))?;
    let canonical = serde_json::to_vec_pretty(&wire)
        .map_err(|error| invalid(format!("manifest canonicalization failed: {error}")))?;
    if canonical != bytes {
        return Err(invalid(
            "manifest bytes are not in the canonical field order or JSON spelling",
        ));
    }
    let manifest_blake3 = *blake3::hash(bytes).as_bytes();
    revalidate(wire, runtime, &expected, manifest_blake3)
}

pub(crate) fn read_with_identity(
    path: &Path,
    runtime: &RuntimeImage<'_>,
    expected: ExceptionArtifactContext<'_>,
    expected_identity: &str,
) -> Result<ValidatedExceptionRoots> {
    let validated = read(path, runtime, expected)?;
    if validated.identity != expected_identity {
        return Err(invalid(
            "exception-root identity does not match the current manifest bytes and counts",
        ));
    }
    Ok(validated)
}

pub(crate) fn read_bytes_with_identity(
    bytes: &[u8],
    runtime: &RuntimeImage<'_>,
    expected: ExceptionArtifactContext<'_>,
    expected_identity: &str,
) -> Result<ValidatedExceptionRoots> {
    let validated = read_bytes(bytes, runtime, expected)?;
    if validated.identity != expected_identity {
        return Err(invalid(
            "exception-root identity does not match the current manifest bytes and counts",
        ));
    }
    Ok(validated)
}

fn serialize(plan: &ExceptionRootPlan, context: &ExceptionArtifactContext<'_>) -> Result<Vec<u8>> {
    let wire = WireManifest::from_plan(plan, context)?;
    serde_json::to_vec_pretty(&wire)
        .map_err(|error| invalid(format!("manifest serialization failed: {error}")))
}

#[cfg(test)]
thread_local! {
    static SERIALIZED_MANIFEST_OVERRIDE: std::cell::RefCell<Option<Vec<u8>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn set_serialized_manifest_override(bytes: Vec<u8>) {
    SERIALIZED_MANIFEST_OVERRIDE.with(|slot| {
        assert!(
            slot.borrow_mut().replace(bytes).is_none(),
            "a serialized-manifest override is already installed"
        );
    });
}

fn serialized_for_materialize(
    plan: &ExceptionRootPlan,
    context: &ExceptionArtifactContext<'_>,
) -> Result<Vec<u8>> {
    let bytes = serialize(plan, context)?;
    #[cfg(test)]
    if let Some(override_bytes) = SERIALIZED_MANIFEST_OVERRIDE.with(|slot| slot.borrow_mut().take())
    {
        return Ok(override_bytes);
    }
    Ok(bytes)
}

fn revalidate(
    wire: WireManifest,
    runtime: &RuntimeImage<'_>,
    expected: &ExceptionArtifactContext<'_>,
    manifest_blake3: [u8; 32],
) -> Result<ValidatedExceptionRoots> {
    if wire.format != FORMAT {
        return Err(invalid("unexpected exception-root manifest format"));
    }
    if wire.schema_version != SCHEMA_VERSION {
        return Err(invalid(
            "unsupported exception-root manifest schema_version",
        ));
    }
    if wire.tool_version != env!("CARGO_PKG_VERSION") {
        return Err(invalid(
            "manifest tool_version does not match the compiled crate",
        ));
    }
    validate_label(&wire.image.label, "image label")?;
    validate_label(&wire.image.toc_name, "image TOC name")?;
    if wire.image.label != expected.label || wire.image.toc_name != expected.toc_name {
        return Err(invalid(
            "manifest image identity does not match the expected artifact context",
        ));
    }
    let image_base = parse_address(&wire.image.base_addr, "image base_addr")?;
    let image_blake3 = parse_blake3(&wire.image.blake3, "image blake3")?;
    if image_blake3 != expected.image_blake3 {
        return Err(invalid(
            "image BLAKE3 does not match the expected artifact context",
        ));
    }
    if runtime.image_bounds() != (image_base, wire.image.size) {
        return Err(invalid(
            "image base or size does not match the runtime image",
        ));
    }
    let actual_image_blake3 = runtime
        .hash_range(image_base, wire.image.size)
        .map_err(|error| invalid(format!("whole-image hash failed: {error}")))?;
    if actual_image_blake3 != image_blake3 {
        return Err(invalid("image BLAKE3 does not match the runtime bytes"));
    }
    let scatter_load_map_blake3 = wire
        .runtime
        .scatter_load_map_blake3
        .as_deref()
        .map(|digest| parse_blake3(digest, "scatter load-map blake3"))
        .transpose()?;
    if scatter_load_map_blake3 != expected.scatter_load_map_blake3 {
        return Err(invalid(
            "scatter load-map dependency does not match the expected artifact context",
        ));
    }
    validate_decoder(&wire.decoder)?;

    let stored_entries = wire.runtime.scatter_entries_used.clone();
    let plan = wire.into_plan()?;
    validate_plan(&plan, expected)?;
    let used_entries = scatter_entries_used(&plan);
    if stored_entries != used_entries.iter().copied().collect::<Vec<_>>() {
        return Err(invalid(
            "scatter_entries_used does not match the complete storage provenance",
        ));
    }
    if !used_entries.is_empty() && scatter_load_map_blake3.is_none() {
        return Err(invalid(
            "scatter-backed evidence has no complete load-map dependency",
        ));
    }

    let recomputed = discover(runtime, expected.label, expected.toc_name)?
        .ok_or_else(|| invalid("current runtime image has no exception-root plan"))?;
    if recomputed != plan {
        return Err(invalid(
            "manifest semantic plan does not match current runtime discovery",
        ));
    }

    let tables = plan.tables.len();
    let roots = plan.roots.len();
    Ok(ValidatedExceptionRoots {
        image_label: plan.image_label.clone(),
        toc_name: plan.toc_name.clone(),
        plan,
        manifest_blake3,
        identity: identity(manifest_blake3, tables, roots),
        image_blake3,
        scatter_load_map_blake3,
    })
}

fn validate_decoder(decoder: &WireDecoder) -> Result<()> {
    let identity = PureRustDecoder.identity();
    if decoder.semantic_adapter != SEMANTIC_ADAPTER
        || decoder.crate_name != identity.crate_name
        || decoder.version != identity.version
    {
        return Err(invalid(
            "decoder identity does not match the compiled semantic adapter",
        ));
    }
    Ok(())
}

fn invalid(reason: impl Into<String>) -> ExceptionRootError {
    ExceptionRootError::Artifact(reason.into())
}

fn address(value: u32) -> String {
    format!("{value:#010x}")
}

fn parse_address(value: &str, what: &str) -> Result<u32> {
    if value.len() != 10
        || !value.starts_with("0x")
        || !value[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(format!("{what} is not a canonical address")));
    }
    let parsed = u32::from_str_radix(&value[2..], 16)
        .map_err(|_| invalid(format!("{what} does not fit u32")))?;
    if address(parsed) != value {
        return Err(invalid(format!("{what} is not a canonical address")));
    }
    Ok(parsed)
}

fn blake3_hex(digest: [u8; 32]) -> String {
    blake3::Hash::from(digest).to_hex().to_string()
}

fn parse_blake3(value: &str, what: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(format!("{what} is not lowercase 64-hex")));
    }
    let mut digest = [0u8; 32];
    for (index, output) in digest.iter_mut().enumerate() {
        let high = hex_nibble(value.as_bytes()[index * 2]);
        let low = hex_nibble(value.as_bytes()[index * 2 + 1]);
        *output = high << 4 | low;
    }
    Ok(digest)
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("parse_blake3 checked lowercase hexadecimal"),
    }
}

fn identity(manifest_blake3: [u8; 32], tables: usize, roots: usize) -> String {
    format!("v1:{}:{tables}:{roots}", blake3_hex(manifest_blake3))
}

fn validate_label(value: &str, what: &str) -> Result<()> {
    let safe = !value.is_empty()
        && value.len() <= MAX_PATH_COMPONENT_BYTES
        && value != "."
        && value != ".."
        && !value.ends_with(['.', ' '])
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
        && !WINDOWS_RESERVED_DEVICE_NAMES.iter().any(|reserved| {
            value
                .split_once('.')
                .map_or(value, |(stem, _)| stem)
                .eq_ignore_ascii_case(reserved)
        });
    if safe {
        Ok(())
    } else {
        Err(invalid(format!("invalid {what} {value:?}")))
    }
}

fn validate_symbol(value: &str, what: &str) -> Result<()> {
    if !value.is_empty()
        && value.len() <= MAX_SYMBOL_LEAF_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        Ok(())
    } else {
        Err(invalid(format!("{what} is not a bounded symbol leaf")))
    }
}

#[cfg(test)]
thread_local! {
    static BEFORE_COMMIT_FAILURE: std::cell::RefCell<Option<String>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn set_before_commit_failure(reason: &str) {
    BEFORE_COMMIT_FAILURE.with(|slot| {
        assert!(
            slot.borrow_mut().replace(reason.to_owned()).is_none(),
            "a pre-commit failure is already installed"
        );
    });
}

fn run_before_commit() -> Result<()> {
    #[cfg(test)]
    if let Some(reason) = BEFORE_COMMIT_FAILURE.with(|slot| slot.borrow_mut().take()) {
        return Err(invalid(reason));
    }
    Ok(())
}

#[cfg(all(test, unix))]
thread_local! {
    static BEFORE_MATERIALIZE_PUBLICATION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
    static AFTER_CLEAR_MANIFEST_UNLINK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
    static BEFORE_READER_SETUP: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

#[cfg(all(test, unix))]
fn set_before_materialize_publication(hook: impl FnOnce() + 'static) {
    BEFORE_MATERIALIZE_PUBLICATION.with(|slot| {
        assert!(slot.borrow_mut().replace(Box::new(hook)).is_none());
    });
}

#[cfg(all(test, unix))]
fn set_after_clear_manifest_unlink(hook: impl FnOnce() + 'static) {
    AFTER_CLEAR_MANIFEST_UNLINK.with(|slot| {
        assert!(slot.borrow_mut().replace(Box::new(hook)).is_none());
    });
}

#[cfg(all(test, unix))]
fn set_before_reader_setup(hook: impl FnOnce() + 'static) {
    BEFORE_READER_SETUP.with(|slot| {
        assert!(slot.borrow_mut().replace(Box::new(hook)).is_none());
    });
}

fn run_before_materialize_publication() {
    #[cfg(all(test, unix))]
    BEFORE_MATERIALIZE_PUBLICATION.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

fn run_after_clear_manifest_unlink() {
    #[cfg(all(test, unix))]
    AFTER_CLEAR_MANIFEST_UNLINK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

fn run_before_reader_setup() {
    #[cfg(all(test, unix))]
    BEFORE_READER_SETUP.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

fn open_manifest_file(path: &Path, expected_label: &str) -> Result<File> {
    if !path.is_absolute() {
        return Err(invalid("manifest path is not absolute"));
    }
    if path.file_name().and_then(|name| name.to_str()) != Some(ARTIFACT_FILE_NAME) {
        return Err(invalid("manifest file name is not roots.json"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| invalid("manifest path has no parent directory"))?;
    if parent.file_name().and_then(|name| name.to_str()) != Some(expected_label) {
        return Err(invalid(
            "manifest label directory does not match the expected image label",
        ));
    }
    let exception_dir = parent
        .parent()
        .ok_or_else(|| invalid("manifest path has no exception_roots directory"))?;
    if exception_dir.file_name().and_then(|name| name.to_str()) != Some("exception_roots") {
        return Err(invalid("manifest path escapes exception_roots/<label>"));
    }
    let output_root = exception_dir
        .parent()
        .ok_or_else(|| invalid("manifest path has no output root"))?;
    let trusted_root =
        TrustedDirectory::new(output_root, "manifest output root").map_err(|error| {
            invalid(format!(
                "manifest output root cannot be opened securely: {error}"
            ))
        })?;
    let trusted_exception = trusted_root
        .open_directory_child("exception_roots", "manifest exception_roots directory")
        .map_err(|error| invalid(error.to_string()))?
        .ok_or_else(|| invalid("manifest exception_roots directory does not exist"))?;
    let trusted_label = trusted_exception
        .open_directory_child(expected_label, "manifest label directory")
        .map_err(|error| invalid(error.to_string()))?
        .ok_or_else(|| invalid("manifest label directory does not exist"))?;
    run_before_reader_setup();
    trusted_label
        .open_regular_file_with_parent(Path::new(ARTIFACT_FILE_NAME), "exception-root manifest")
        .map(|(file, _)| file)
        .map_err(|error| invalid(error.to_string()))
}

impl WireManifest {
    fn from_plan(plan: &ExceptionRootPlan, context: &ExceptionArtifactContext<'_>) -> Result<Self> {
        validate_plan(plan, context)?;
        let used = scatter_entries_used(plan);
        if !used.is_empty() && context.scatter_load_map_blake3.is_none() {
            return Err(invalid(
                "scatter-backed evidence has no complete load-map dependency",
            ));
        }
        let decoder = PureRustDecoder.identity();
        Ok(Self {
            format: FORMAT.to_owned(),
            schema_version: SCHEMA_VERSION,
            tool_version: env!("CARGO_PKG_VERSION").to_owned(),
            image: WireImage {
                label: context.label.to_owned(),
                toc_name: context.toc_name.to_owned(),
                base_addr: address(plan.image_base),
                size: plan.image_size,
                blake3: blake3_hex(context.image_blake3),
            },
            runtime: WireRuntime {
                scatter_load_map_blake3: context.scatter_load_map_blake3.map(blake3_hex),
                scatter_entries_used: used.into_iter().collect(),
            },
            decoder: WireDecoder {
                semantic_adapter: SEMANTIC_ADAPTER.to_owned(),
                crate_name: decoder.crate_name.to_owned(),
                version: decoder.version.to_owned(),
            },
            initial_table: wire_table(&plan.initial_table)?,
            relocation: wire_relocation(&plan.relocation),
            tables: plan.tables.iter().map(wire_table).collect::<Result<_>>()?,
            roots: plan.roots.iter().map(wire_root).collect(),
            applications: plan.applications.iter().map(wire_application).collect(),
        })
    }

    fn into_plan(self) -> Result<ExceptionRootPlan> {
        let image_base = parse_address(&self.image.base_addr, "image base_addr")?;
        let initial_table = parse_table(self.initial_table, "initial_table")?;
        let relocation = parse_relocation(self.relocation)?;
        let tables = self
            .tables
            .into_iter()
            .enumerate()
            .map(|(index, table)| parse_table(table, &format!("tables[{index}]")))
            .collect::<Result<Vec<_>>>()?;
        let roots = self
            .roots
            .into_iter()
            .enumerate()
            .map(|(index, root)| parse_root(root, &format!("roots[{index}]")))
            .collect::<Result<Vec<_>>>()?;
        let applications = self
            .applications
            .into_iter()
            .enumerate()
            .map(|(index, application)| {
                parse_application(application, &format!("applications[{index}]"))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(ExceptionRootPlan {
            image_label: self.image.label,
            toc_name: self.image.toc_name,
            image_base,
            image_size: self.image.size,
            initial_table,
            relocation,
            tables,
            roots,
            applications,
        })
    }
}

fn wire_table(table: &VectorTable) -> Result<WireTable> {
    let slots = table
        .slots
        .iter()
        .enumerate()
        .map(|(index, slot)| {
            let slot_storage = storage_subrange(
                &table.storage,
                slot.address,
                4,
                &format!("table slot {index}"),
            )?;
            Ok(WireSlot {
                index,
                role: slot.role.as_wire().to_owned(),
                address: address(slot.address),
                form: slot.form.as_wire().to_owned(),
                slot_blake3: blake3_hex(slot.slot_blake3),
                slot_storage: slot_storage.iter().map(wire_span).collect(),
                literal: match slot.form {
                    SlotForm::DirectBranch => None,
                    SlotForm::LiteralLoad { literal_address } => Some(WireLiteral {
                        address: address(literal_address),
                        blake3: blake3_hex(slot.literal_blake3.ok_or_else(|| {
                            invalid(format!("table slot {index} has no literal digest"))
                        })?),
                        storage: slot.literal_storage.iter().map(wire_span).collect(),
                    }),
                },
                entry: address(slot.entry),
                isa: slot.isa.as_wire().to_owned(),
                instruction_size: slot.instruction_size,
                instruction_blake3: blake3_hex(slot.instruction_blake3),
                instruction_storage: slot.instruction_storage.iter().map(wire_span).collect(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(WireTable {
        kind: table_kind_name(table.kind).to_owned(),
        address: address(table.address),
        blake3: blake3_hex(table.blake3),
        storage: table.storage.iter().map(wire_span).collect(),
        slots,
    })
}

fn wire_span(span: &StorageSpan) -> WireSpan {
    WireSpan {
        kind: storage_kind_name(span.kind).to_owned(),
        address: address(span.address),
        size: span.size,
        scatter_entry: span.scatter_entry,
    }
}

fn wire_relocation(relocation: &RelocationEvidence) -> WireRelocation {
    let (status, selected, table_address, observations, handoffs, reason) = match relocation {
        RelocationEvidence::ConfirmedInitial {
            selected,
            observations,
        } => (
            "confirmed_initial",
            Some(wire_vbar(selected)),
            None,
            observations.iter().map(wire_vbar).collect(),
            Vec::new(),
            None,
        ),
        RelocationEvidence::Relocated {
            selected,
            table_address,
            observations,
        } => (
            "relocated",
            Some(wire_vbar(selected)),
            Some(address(*table_address)),
            observations.iter().map(wire_vbar).collect(),
            Vec::new(),
            None,
        ),
        RelocationEvidence::Unresolved { observations } => (
            "unresolved",
            None,
            None,
            observations.iter().map(wire_vbar).collect(),
            Vec::new(),
            None,
        ),
        RelocationEvidence::NotObserved => {
            ("not_observed", None, None, Vec::new(), Vec::new(), None)
        }
        RelocationEvidence::AnalysisIncomplete {
            observations,
            handoffs,
            reason,
        } => (
            "analysis_incomplete",
            None,
            None,
            observations.iter().map(wire_vbar).collect(),
            handoffs.iter().map(wire_handoff).collect(),
            reason.clone(),
        ),
    };
    WireRelocation {
        status: status.to_owned(),
        selected,
        table_address,
        observations,
        handoffs,
        reason,
    }
}

fn wire_vbar(evidence: &VbarWriteEvidence) -> WireVbarEvidence {
    WireVbarEvidence {
        pc: address(evidence.pc),
        isa: evidence.isa.as_wire().to_owned(),
        source_register: evidence.source_register,
        conditional: evidence.conditional,
        exact_value: evidence.exact_value.map(address),
        definitions: evidence.definitions.iter().copied().map(address).collect(),
        dominates_handoffs: evidence.dominates_handoffs,
    }
}

fn wire_handoff(handoff: &Handoff) -> WireHandoff {
    WireHandoff {
        pc: address(handoff.pc),
        kind: boundary_kind_name(handoff.kind).to_owned(),
    }
}

fn wire_root(root: &ExceptionRoot) -> WireRoot {
    WireRoot {
        entry: address(root.entry),
        isa: root.isa.as_wire().to_owned(),
        instruction_size: root.instruction_size,
        instruction_blake3: blake3_hex(root.instruction_blake3),
        storage: root.storage.iter().map(wire_span).collect(),
        claims: root.claims.iter().map(wire_claim).collect(),
    }
}

fn wire_claim(claim: &ExceptionClaim) -> WireClaim {
    WireClaim {
        table_kind: table_kind_name(claim.table_kind).to_owned(),
        table_address: address(claim.table_address),
        slot_address: address(claim.slot_address),
        role: claim.role.as_wire().to_owned(),
    }
}

fn wire_application(application: &ExceptionApplication) -> WireApplication {
    WireApplication {
        entry: address(application.entry),
        isa: application.isa.as_wire().to_owned(),
        desired_primary: application.desired_primary.clone(),
        claims: application.claims.iter().map(wire_claim).collect(),
        role_labels: application.role_labels.clone(),
    }
}

fn parse_table(table: WireTable, what: &str) -> Result<VectorTable> {
    let kind = parse_table_kind(&table.kind, &format!("{what}.kind"))?;
    let table_address = parse_address(&table.address, &format!("{what}.address"))?;
    let storage = parse_spans(table.storage, &format!("{what}.storage"))?;
    validate_storage(
        &storage,
        table_address,
        TABLE_BYTES,
        &format!("{what}.storage"),
    )?;
    if table.slots.len() != VECTOR_SLOTS {
        return Err(invalid(format!(
            "{what}.slots does not contain exactly {VECTOR_SLOTS} entries"
        )));
    }
    let mut slots = Vec::with_capacity(VECTOR_SLOTS);
    for (position, slot) in table.slots.into_iter().enumerate() {
        if slot.index != position {
            return Err(invalid(format!(
                "{what}.slots[{position}].index does not match its array position"
            )));
        }
        let role = parse_role(&slot.role, &format!("{what}.slots[{position}].role"))?;
        if role != ExceptionRole::ALL[position] {
            return Err(invalid(format!(
                "{what}.slots[{position}].role is not in architectural order"
            )));
        }
        let expected_address = table_address
            .checked_add(u32::try_from(position).unwrap() * 4)
            .ok_or_else(|| invalid(format!("{what} slot address overflows")))?;
        let slot_address =
            parse_address(&slot.address, &format!("{what}.slots[{position}].address"))?;
        if slot_address != expected_address {
            return Err(invalid(format!(
                "{what}.slots[{position}].address is not architectural"
            )));
        }
        let slot_storage = parse_spans(
            slot.slot_storage,
            &format!("{what}.slots[{position}].slot_storage"),
        )?;
        validate_storage(
            &slot_storage,
            slot_address,
            4,
            &format!("{what}.slots[{position}].slot_storage"),
        )?;
        let expected_slot_storage = storage_subrange(
            &storage,
            slot_address,
            4,
            &format!("{what}.slots[{position}].slot_storage"),
        )?;
        if slot_storage != expected_slot_storage {
            return Err(invalid(format!(
                "{what}.slots[{position}].slot_storage does not match table storage"
            )));
        }
        let (form, literal_blake3, literal_storage) = match (slot.form.as_str(), slot.literal) {
            ("direct_branch", None) => (SlotForm::DirectBranch, None, Vec::new()),
            ("literal_load", Some(literal)) => {
                let literal_address = parse_address(
                    &literal.address,
                    &format!("{what}.slots[{position}].literal.address"),
                )?;
                let literal_storage = parse_spans(
                    literal.storage,
                    &format!("{what}.slots[{position}].literal.storage"),
                )?;
                validate_storage(
                    &literal_storage,
                    literal_address,
                    4,
                    &format!("{what}.slots[{position}].literal.storage"),
                )?;
                (
                    SlotForm::LiteralLoad { literal_address },
                    Some(parse_blake3(
                        &literal.blake3,
                        &format!("{what}.slots[{position}].literal.blake3"),
                    )?),
                    literal_storage,
                )
            }
            ("direct_branch", Some(_)) => {
                return Err(invalid(format!(
                    "{what}.slots[{position}] direct branch carries a literal"
                )));
            }
            ("literal_load", None) => {
                return Err(invalid(format!(
                    "{what}.slots[{position}] literal load has no literal"
                )));
            }
            _ => {
                return Err(invalid(format!(
                    "{what}.slots[{position}].form is outside the closed domain"
                )));
            }
        };
        let entry = parse_address(&slot.entry, &format!("{what}.slots[{position}].entry"))?;
        let isa = parse_isa(&slot.isa, &format!("{what}.slots[{position}].isa"))?;
        let instruction_storage = parse_spans(
            slot.instruction_storage,
            &format!("{what}.slots[{position}].instruction_storage"),
        )?;
        validate_storage(
            &instruction_storage,
            entry,
            u32::from(slot.instruction_size),
            &format!("{what}.slots[{position}].instruction_storage"),
        )?;
        slots.push(VectorSlot {
            role,
            address: slot_address,
            form,
            slot_blake3: parse_blake3(
                &slot.slot_blake3,
                &format!("{what}.slots[{position}].slot_blake3"),
            )?,
            literal_blake3,
            literal_storage,
            entry,
            isa,
            instruction_size: slot.instruction_size,
            instruction_blake3: parse_blake3(
                &slot.instruction_blake3,
                &format!("{what}.slots[{position}].instruction_blake3"),
            )?,
            instruction_storage,
        });
    }
    Ok(VectorTable {
        kind,
        address: table_address,
        blake3: parse_blake3(&table.blake3, &format!("{what}.blake3"))?,
        storage,
        slots,
    })
}

fn parse_relocation(relocation: WireRelocation) -> Result<RelocationEvidence> {
    if relocation.observations.len() > MAX_VBAR_WRITES {
        return Err(invalid(
            "relocation observations exceed the supported limit",
        ));
    }
    let observations = relocation
        .observations
        .into_iter()
        .enumerate()
        .map(|(index, evidence)| parse_vbar(evidence, &format!("relocation.observations[{index}]")))
        .collect::<Result<Vec<_>>>()?;
    validate_observations(&observations)?;
    let selected = relocation
        .selected
        .map(|evidence| parse_vbar(evidence, "relocation.selected"))
        .transpose()?;
    let table_address = relocation
        .table_address
        .as_deref()
        .map(|value| parse_address(value, "relocation.table_address"))
        .transpose()?;
    let handoffs = relocation
        .handoffs
        .into_iter()
        .enumerate()
        .map(|(index, handoff)| parse_handoff(handoff, &format!("relocation.handoffs[{index}]")))
        .collect::<Result<Vec<_>>>()?;
    if handoffs.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(invalid(
            "relocation handoffs are not strictly ordered and unique",
        ));
    }
    if let Some(reason) = relocation.reason.as_deref() {
        validate_reason(reason)?;
    }

    match relocation.status.as_str() {
        "confirmed_initial"
            if selected.is_some()
                && table_address.is_none()
                && handoffs.is_empty()
                && relocation.reason.is_none() =>
        {
            let selected = selected.unwrap();
            require_selected_observation(&selected, &observations)?;
            Ok(RelocationEvidence::ConfirmedInitial {
                selected,
                observations,
            })
        }
        "relocated"
            if selected.is_some()
                && table_address.is_some()
                && handoffs.is_empty()
                && relocation.reason.is_none() =>
        {
            let selected = selected.unwrap();
            require_selected_observation(&selected, &observations)?;
            Ok(RelocationEvidence::Relocated {
                selected,
                table_address: table_address.unwrap(),
                observations,
            })
        }
        "unresolved"
            if selected.is_none()
                && table_address.is_none()
                && handoffs.is_empty()
                && relocation.reason.is_none() =>
        {
            Ok(RelocationEvidence::Unresolved { observations })
        }
        "not_observed"
            if selected.is_none()
                && table_address.is_none()
                && observations.is_empty()
                && handoffs.is_empty()
                && relocation.reason.is_none() =>
        {
            Ok(RelocationEvidence::NotObserved)
        }
        "analysis_incomplete" if selected.is_none() && table_address.is_none() => {
            Ok(RelocationEvidence::AnalysisIncomplete {
                observations,
                handoffs,
                reason: relocation.reason,
            })
        }
        _ => Err(invalid(
            "relocation status and variant fields are inconsistent",
        )),
    }
}

fn parse_vbar(evidence: WireVbarEvidence, what: &str) -> Result<VbarWriteEvidence> {
    if evidence.source_register >= 16 {
        return Err(invalid(format!("{what}.source_register is outside r0-r15")));
    }
    let definitions = evidence
        .definitions
        .iter()
        .enumerate()
        .map(|(index, definition)| {
            parse_address(definition, &format!("{what}.definitions[{index}]"))
        })
        .collect::<Result<Vec<_>>>()?;
    if definitions.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(invalid(format!(
            "{what}.definitions are not strictly ordered and unique"
        )));
    }
    Ok(VbarWriteEvidence {
        pc: parse_address(&evidence.pc, &format!("{what}.pc"))?,
        isa: parse_isa(&evidence.isa, &format!("{what}.isa"))?,
        source_register: evidence.source_register,
        conditional: evidence.conditional,
        exact_value: evidence
            .exact_value
            .as_deref()
            .map(|value| parse_address(value, &format!("{what}.exact_value")))
            .transpose()?,
        definitions,
        dominates_handoffs: evidence.dominates_handoffs,
    })
}

fn parse_handoff(handoff: WireHandoff, what: &str) -> Result<Handoff> {
    Ok(Handoff {
        pc: parse_address(&handoff.pc, &format!("{what}.pc"))?,
        kind: parse_boundary_kind(&handoff.kind, &format!("{what}.kind"))?,
    })
}

fn parse_root(root: WireRoot, what: &str) -> Result<ExceptionRoot> {
    let entry = parse_address(&root.entry, &format!("{what}.entry"))?;
    let storage = parse_spans(root.storage, &format!("{what}.storage"))?;
    validate_storage(
        &storage,
        entry,
        u32::from(root.instruction_size),
        &format!("{what}.storage"),
    )?;
    let claims = root
        .claims
        .into_iter()
        .enumerate()
        .map(|(index, claim)| parse_claim(claim, &format!("{what}.claims[{index}]")))
        .collect::<Result<Vec<_>>>()?;
    validate_claims(&claims, what)?;
    Ok(ExceptionRoot {
        entry,
        isa: parse_isa(&root.isa, &format!("{what}.isa"))?,
        instruction_size: root.instruction_size,
        instruction_blake3: parse_blake3(
            &root.instruction_blake3,
            &format!("{what}.instruction_blake3"),
        )?,
        storage,
        claims,
    })
}

fn parse_claim(claim: WireClaim, what: &str) -> Result<ExceptionClaim> {
    Ok(ExceptionClaim {
        table_kind: parse_table_kind(&claim.table_kind, &format!("{what}.table_kind"))?,
        table_address: parse_address(&claim.table_address, &format!("{what}.table_address"))?,
        slot_address: parse_address(&claim.slot_address, &format!("{what}.slot_address"))?,
        role: parse_role(&claim.role, &format!("{what}.role"))?,
    })
}

fn parse_application(application: WireApplication, what: &str) -> Result<ExceptionApplication> {
    if let Some(primary) = application.desired_primary.as_deref() {
        validate_symbol(primary, &format!("{what}.desired_primary"))?;
    }
    for (index, label) in application.role_labels.iter().enumerate() {
        validate_symbol(label, &format!("{what}.role_labels[{index}]"))?;
    }
    let claims = application
        .claims
        .into_iter()
        .enumerate()
        .map(|(index, claim)| parse_claim(claim, &format!("{what}.claims[{index}]")))
        .collect::<Result<Vec<_>>>()?;
    validate_claims(&claims, what)?;
    Ok(ExceptionApplication {
        entry: parse_address(&application.entry, &format!("{what}.entry"))?,
        isa: parse_isa(&application.isa, &format!("{what}.isa"))?,
        desired_primary: application.desired_primary,
        claims,
        role_labels: application.role_labels,
    })
}

fn validate_plan(plan: &ExceptionRootPlan, context: &ExceptionArtifactContext<'_>) -> Result<()> {
    validate_label(context.label, "artifact label")?;
    validate_label(context.toc_name, "artifact TOC name")?;
    if plan.image_label != context.label || plan.toc_name != context.toc_name {
        return Err(invalid(
            "plan image identity does not match the artifact context",
        ));
    }
    if plan.image_size == 0
        || plan.image_base.checked_add(plan.image_size).is_none()
        || plan.tables.is_empty()
        || plan.tables.len() > MAX_TABLES
    {
        return Err(invalid("plan image or table count is outside its limits"));
    }
    if plan.tables[0] != plan.initial_table || plan.initial_table.kind != VectorTableKind::Initial {
        return Err(invalid(
            "initial_table is not the first validated initial table",
        ));
    }
    if plan.tables.iter().enumerate().any(|(index, table)| {
        table.kind
            != if index == 0 {
                VectorTableKind::Initial
            } else {
                VectorTableKind::Relocated
            }
    }) {
        return Err(invalid("validated tables are not in kind order"));
    }
    let mut table_addresses = BTreeSet::new();
    for (table_index, table) in plan.tables.iter().enumerate() {
        if !table_addresses.insert(table.address) {
            return Err(invalid("validated tables contain duplicate addresses"));
        }
        validate_table(table, &format!("tables[{table_index}]"))?;
    }
    validate_table(&plan.initial_table, "initial_table")?;

    let (canonical_roots, canonical_applications) = build_roots_and_applications(&plan.tables)
        .map_err(|error| {
            invalid(format!(
                "canonical root/application allocation failed: {error}"
            ))
        })?;
    if plan.roots != canonical_roots || plan.applications != canonical_applications {
        return Err(invalid(
            "plan does not match the canonical root/application allocation",
        ));
    }

    if plan.roots.is_empty()
        || plan.roots.len() > MAX_ROOTS
        || plan.applications.len() != plan.roots.len()
    {
        return Err(invalid(
            "root/application counts do not satisfy the bounded plan",
        ));
    }
    if plan
        .roots
        .windows(2)
        .any(|pair| (pair[0].entry, pair[0].isa) >= (pair[1].entry, pair[1].isa))
    {
        return Err(invalid("roots are not strictly ordered by entry and ISA"));
    }
    for (index, root) in plan.roots.iter().enumerate() {
        validate_instruction_size(root.isa, root.instruction_size, &format!("roots[{index}]"))?;
        validate_storage(
            &root.storage,
            root.entry,
            u32::from(root.instruction_size),
            &format!("roots[{index}].storage"),
        )?;
        validate_claims(&root.claims, &format!("roots[{index}]"))?;
    }
    if plan
        .applications
        .windows(2)
        .any(|pair| (pair[0].entry, pair[0].isa) >= (pair[1].entry, pair[1].isa))
    {
        return Err(invalid(
            "applications are not strictly ordered by entry and ISA",
        ));
    }
    for (index, application) in plan.applications.iter().enumerate() {
        validate_claims(&application.claims, &format!("applications[{index}]"))?;
        if let Some(primary) = application.desired_primary.as_deref() {
            validate_symbol(primary, &format!("applications[{index}].desired_primary"))?;
        }
        if application.role_labels.len() != application.claims.len() {
            return Err(invalid(format!(
                "applications[{index}] role-label count does not match its claims"
            )));
        }
        for (label_index, label) in application.role_labels.iter().enumerate() {
            validate_symbol(
                label,
                &format!("applications[{index}].role_labels[{label_index}]"),
            )?;
        }
    }
    validate_relocation(&plan.relocation)?;
    Ok(())
}

fn validate_table(table: &VectorTable, what: &str) -> Result<()> {
    validate_storage(
        &table.storage,
        table.address,
        TABLE_BYTES,
        &format!("{what}.storage"),
    )?;
    if table.slots.len() != VECTOR_SLOTS {
        return Err(invalid(format!(
            "{what} does not contain exactly {VECTOR_SLOTS} slots"
        )));
    }
    for (index, slot) in table.slots.iter().enumerate() {
        let expected_address = table
            .address
            .checked_add(u32::try_from(index).unwrap() * 4)
            .ok_or_else(|| invalid(format!("{what} slot address overflows")))?;
        if slot.role != ExceptionRole::ALL[index] || slot.address != expected_address {
            return Err(invalid(format!(
                "{what}.slots[{index}] is not in architectural order"
            )));
        }
        storage_subrange(
            &table.storage,
            slot.address,
            4,
            &format!("{what}.slots[{index}]"),
        )?;
        match slot.form {
            SlotForm::DirectBranch => {
                if slot.literal_blake3.is_some() || !slot.literal_storage.is_empty() {
                    return Err(invalid(format!(
                        "{what}.slots[{index}] direct branch carries literal evidence"
                    )));
                }
            }
            SlotForm::LiteralLoad { literal_address } => {
                if slot.literal_blake3.is_none() {
                    return Err(invalid(format!(
                        "{what}.slots[{index}] literal load has no literal digest"
                    )));
                }
                validate_storage(
                    &slot.literal_storage,
                    literal_address,
                    4,
                    &format!("{what}.slots[{index}].literal_storage"),
                )?;
            }
        }
        validate_instruction_size(
            slot.isa,
            slot.instruction_size,
            &format!("{what}.slots[{index}]"),
        )?;
        validate_storage(
            &slot.instruction_storage,
            slot.entry,
            u32::from(slot.instruction_size),
            &format!("{what}.slots[{index}].instruction_storage"),
        )?;
    }
    Ok(())
}

fn validate_relocation(relocation: &RelocationEvidence) -> Result<()> {
    let (selected, observations, handoffs, reason) = match relocation {
        RelocationEvidence::ConfirmedInitial {
            selected,
            observations,
        }
        | RelocationEvidence::Relocated {
            selected,
            observations,
            ..
        } => (Some(selected), observations.as_slice(), &[][..], None),
        RelocationEvidence::Unresolved { observations } => {
            (None, observations.as_slice(), &[][..], None)
        }
        RelocationEvidence::NotObserved => (None, &[][..], &[][..], None),
        RelocationEvidence::AnalysisIncomplete {
            observations,
            handoffs,
            reason,
        } => (
            None,
            observations.as_slice(),
            handoffs.as_slice(),
            reason.as_deref(),
        ),
    };
    if observations.len() > MAX_VBAR_WRITES {
        return Err(invalid(
            "relocation observations exceed the supported limit",
        ));
    }
    validate_observations(observations)?;
    if let Some(selected) = selected {
        require_selected_observation(selected, observations)?;
    }
    if handoffs.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(invalid(
            "relocation handoffs are not strictly ordered and unique",
        ));
    }
    if let Some(reason) = reason {
        validate_reason(reason)?;
    }
    Ok(())
}

fn validate_observations(observations: &[VbarWriteEvidence]) -> Result<()> {
    if observations.windows(2).any(|pair| pair[0].pc >= pair[1].pc) {
        return Err(invalid(
            "relocation observations are not strictly ordered by PC",
        ));
    }
    for (index, observation) in observations.iter().enumerate() {
        if observation.source_register >= 16
            || observation
                .definitions
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(invalid(format!(
                "relocation observation {index} is not canonical"
            )));
        }
    }
    Ok(())
}

fn require_selected_observation(
    selected: &VbarWriteEvidence,
    observations: &[VbarWriteEvidence],
) -> Result<()> {
    if observations
        .iter()
        .any(|observation| observation == selected)
    {
        Ok(())
    } else {
        Err(invalid(
            "selected VBAR evidence is absent from the ordered observations",
        ))
    }
}

fn validate_reason(reason: &str) -> Result<()> {
    if reason.is_empty()
        || reason.len() > MAX_REASON_BYTES
        || !reason
            .bytes()
            .all(|byte| byte == b'\t' || (b' '..=b'~').contains(&byte))
        || reason.bytes().any(|byte| matches!(byte, b'/' | b'\\'))
    {
        return Err(invalid(
            "relocation reason is empty, unbounded, non-ASCII, or path-bearing",
        ));
    }
    Ok(())
}

fn validate_instruction_size(isa: RootIsa, size: u8, what: &str) -> Result<()> {
    let valid = match isa {
        RootIsa::Arm => size == 4,
        RootIsa::Thumb => matches!(size, 2 | 4),
    };
    if valid {
        Ok(())
    } else {
        Err(invalid(format!(
            "{what}.instruction_size does not match its ISA"
        )))
    }
}

fn validate_claims(claims: &[ExceptionClaim], what: &str) -> Result<()> {
    if claims.is_empty() || claims.len() > MAX_TABLES * VECTOR_SLOTS {
        return Err(invalid(format!("{what}.claims count is outside its limit")));
    }
    if claims.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(invalid(format!(
            "{what}.claims are not strictly ordered and unique"
        )));
    }
    for claim in claims {
        let expected_slot = claim
            .table_address
            .checked_add(u32::try_from(claim.role.slot_index()).unwrap() * 4)
            .ok_or_else(|| invalid(format!("{what}.claim slot address overflows")))?;
        if claim.slot_address != expected_slot {
            return Err(invalid(format!(
                "{what}.claim slot does not match its architectural role"
            )));
        }
    }
    Ok(())
}

fn parse_spans(spans: Vec<WireSpan>, what: &str) -> Result<Vec<StorageSpan>> {
    spans
        .into_iter()
        .enumerate()
        .map(|(index, span)| {
            let kind = match span.kind.as_str() {
                "raw" => StorageKind::Raw,
                "scatter_bytes" => StorageKind::ScatterBytes,
                "scatter_zero" => StorageKind::ScatterZero,
                _ => {
                    return Err(invalid(format!(
                        "{what}[{index}].kind is outside the closed domain"
                    )));
                }
            };
            Ok(StorageSpan {
                kind,
                address: parse_address(&span.address, &format!("{what}[{index}].address"))?,
                size: span.size,
                scatter_entry: span.scatter_entry,
            })
        })
        .collect()
}

fn validate_storage(spans: &[StorageSpan], address: u32, size: u32, what: &str) -> Result<()> {
    if size == 0 || spans.is_empty() {
        return Err(invalid(format!("{what} is empty")));
    }
    let expected_end = address
        .checked_add(size)
        .ok_or_else(|| invalid(format!("{what} range overflows")))?;
    let mut cursor = address;
    for (index, span) in spans.iter().enumerate() {
        if span.size == 0 || span.address != cursor {
            return Err(invalid(format!(
                "{what}[{index}] is zero-sized, gapped, overlapping, or out of order"
            )));
        }
        match (span.kind, span.scatter_entry) {
            (StorageKind::Raw, None) => {}
            (StorageKind::ScatterBytes, Some(entry)) if entry < crate::scatter::MAX_ENTRIES => {}
            (StorageKind::ScatterBytes, Some(_)) => {
                return Err(invalid(format!(
                    "{what}[{index}] scatter entry exceeds the supported limit"
                )));
            }
            (StorageKind::ScatterZero, _) => {
                return Err(invalid(format!(
                    "{what}[{index}] uses zero-fill as byte evidence"
                )));
            }
            _ => {
                return Err(invalid(format!(
                    "{what}[{index}] storage kind and scatter entry disagree"
                )));
            }
        }
        cursor = cursor
            .checked_add(span.size)
            .ok_or_else(|| invalid(format!("{what}[{index}] endpoint overflows")))?;
        if cursor > expected_end {
            return Err(invalid(format!(
                "{what}[{index}] escapes its evidence range"
            )));
        }
    }
    if cursor != expected_end {
        return Err(invalid(format!(
            "{what} does not cover its exact evidence range"
        )));
    }
    Ok(())
}

fn storage_subrange(
    spans: &[StorageSpan],
    address: u32,
    size: u32,
    what: &str,
) -> Result<Vec<StorageSpan>> {
    let end = address
        .checked_add(size)
        .ok_or_else(|| invalid(format!("{what} range overflows")))?;
    let mut selected = Vec::new();
    for span in spans {
        let span_end = span
            .address
            .checked_add(span.size)
            .ok_or_else(|| invalid(format!("{what} backing span overflows")))?;
        let start = span.address.max(address);
        let selected_end = span_end.min(end);
        if start < selected_end {
            selected.push(StorageSpan {
                kind: span.kind,
                address: start,
                size: selected_end - start,
                scatter_entry: span.scatter_entry,
            });
        }
    }
    validate_storage(&selected, address, size, what)?;
    Ok(selected)
}

fn scatter_entries_used(plan: &ExceptionRootPlan) -> BTreeSet<usize> {
    let mut entries = BTreeSet::new();
    let mut collect = |spans: &[StorageSpan]| {
        entries.extend(spans.iter().filter_map(|span| span.scatter_entry));
    };
    collect(&plan.initial_table.storage);
    for slot in &plan.initial_table.slots {
        collect(&slot.literal_storage);
        collect(&slot.instruction_storage);
    }
    for table in &plan.tables {
        collect(&table.storage);
        for slot in &table.slots {
            collect(&slot.literal_storage);
            collect(&slot.instruction_storage);
        }
    }
    for root in &plan.roots {
        collect(&root.storage);
    }
    entries
}

fn storage_kind_name(kind: StorageKind) -> &'static str {
    match kind {
        StorageKind::Raw => "raw",
        StorageKind::ScatterBytes => "scatter_bytes",
        StorageKind::ScatterZero => "scatter_zero",
    }
}

fn table_kind_name(kind: VectorTableKind) -> &'static str {
    match kind {
        VectorTableKind::Initial => "initial",
        VectorTableKind::Relocated => "relocated",
    }
}

fn parse_table_kind(value: &str, what: &str) -> Result<VectorTableKind> {
    match value {
        "initial" => Ok(VectorTableKind::Initial),
        "relocated" => Ok(VectorTableKind::Relocated),
        _ => Err(invalid(format!("{what} is outside the closed domain"))),
    }
}

fn parse_role(value: &str, what: &str) -> Result<ExceptionRole> {
    ExceptionRole::ALL
        .into_iter()
        .find(|role| role.as_wire() == value)
        .ok_or_else(|| invalid(format!("{what} is outside the closed domain")))
}

fn parse_isa(value: &str, what: &str) -> Result<RootIsa> {
    match value {
        "arm" => Ok(RootIsa::Arm),
        "thumb" => Ok(RootIsa::Thumb),
        _ => Err(invalid(format!("{what} is outside the closed domain"))),
    }
}

fn boundary_kind_name(kind: BoundaryKind) -> &'static str {
    match kind {
        BoundaryKind::Call => "call",
        BoundaryKind::Return => "return",
        BoundaryKind::ExceptionCall => "exception_call",
        BoundaryKind::Indirect => "indirect",
        BoundaryKind::Unmapped => "unmapped",
        BoundaryKind::DecodeFailure => "decode_failure",
    }
}

fn parse_boundary_kind(value: &str, what: &str) -> Result<BoundaryKind> {
    match value {
        "call" => Ok(BoundaryKind::Call),
        "return" => Ok(BoundaryKind::Return),
        "exception_call" => Ok(BoundaryKind::ExceptionCall),
        "indirect" => Ok(BoundaryKind::Indirect),
        "unmapped" => Ok(BoundaryKind::Unmapped),
        "decode_failure" => Ok(BoundaryKind::DecodeFailure),
        _ => Err(invalid(format!("{what} is outside the closed domain"))),
    }
}
