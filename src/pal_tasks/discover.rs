// Bounded anchor materialization sweep, unique-prologue root selection,
// and candidate aggregation over the runtime image. One image-wide
// halfword-aligned Thumb sweep resolves every anchor reference for the
// complete anchor set; the image is never rescanned per anchor.

use crate::arm32::{
    AccessKind, AddressBase, AddressOffset, ControlFlow, DecodedInstruction, InstructionDecoder,
    PureRustDecoder, Register, ValueEffect, ValueExpr,
};
use crate::execution_ranges::DecodeIsa;
use crate::pal_tasks::cfg::{
    decode_entry_rooted_cfg, decode_thumb_at, visible_pc, wrapping_offset,
};
use crate::pal_tasks::{
    ANCHOR_PATTERN, AnchorCfgCandidate, AnchorReference, AnchorReferenceKind,
    MAX_ANCHOR_OCCURRENCES, MAX_ANCHOR_REFERENCE_DISTANCE, MAX_ANCHOR_REFERENCES,
    MAX_MOVW_MOVT_SPAN_INSTRUCTIONS, PROLOGUE_WINDOW_BYTES, PalTaskError,
};
use crate::runtime_image::{MAX_EXACT_READ, RuntimeImage, StorageSpan};

const THUMB: DecodeIsa = DecodeIsa::Thumb;
const SP: Register = Register(13);
const LR: Register = Register(14);

/// Discover every anchor-reference candidate: one entry per semantic
/// reference that survives unique-prologue root selection and bounded
/// CFG closure. Below-threshold misses are skipped; named resource
/// limits and runtime failures are typed errors.
pub(super) fn discover_anchor_cfg(
    image: &RuntimeImage<'_>,
    label: &str,
) -> std::result::Result<Vec<AnchorCfgCandidate>, PalTaskError> {
    let anchors = find_anchor_occurrences(image, label)?;
    if anchors.is_empty() {
        return Ok(Vec::new());
    }
    let references = find_anchor_references(image, label, &anchors)?;
    let mut candidates = Vec::new();
    for reference in references {
        let Some(initializer) = unique_prologue_root(image, reference.pc) else {
            continue;
        };
        let Some(cfg) = decode_entry_rooted_cfg(image, initializer) else {
            continue;
        };
        if !cfg.has_only_unconditional_external_exits() || !cfg.contains_node(reference.pc) {
            continue;
        }
        let anchor_storage = anchors
            .iter()
            .find(|anchor| anchor.address == reference.anchor)
            .map(|anchor| anchor.storage.clone())
            .unwrap_or_default();
        candidates.push(AnchorCfgCandidate {
            anchor: reference.anchor,
            anchor_storage,
            reference,
            initializer,
            cfg,
        });
    }
    Ok(candidates)
}

/// One exact `PALTskTm\0` occurrence with its nine-byte storage
/// provenance.
pub(super) struct AnchorOccurrence {
    pub address: u32,
    pub storage: Vec<StorageSpan>,
}

fn runtime_error(label: &str, address: u32, size: u32, error: crate::error::Error) -> PalTaskError {
    PalTaskError::Runtime {
        address,
        size,
        reason: format!("{label}: {error}"),
    }
}

/// Scan every byte-backed span once for exact anchor occurrences. A
/// match may cross contiguous provenance spans but never zero-fill or
/// unmapped storage.
pub(super) fn find_anchor_occurrences(
    image: &RuntimeImage<'_>,
    label: &str,
) -> std::result::Result<Vec<AnchorOccurrence>, PalTaskError> {
    let mut occurrences = Vec::new();
    for range in image.byte_backed_ranges() {
        let mut cursor = range.start;
        while cursor < range.end {
            let remaining = range.end - cursor;
            let body = remaining.min(MAX_EXACT_READ as u32 - 8);
            // The chunk tail overlap lets every position in [cursor,
            // cursor + body) complete its nine-byte window inside one
            // read; the final chunk reads exactly to the range end.
            let window = (body + 8).min(remaining);
            let bytes = image
                .read_exact(cursor, window as usize)
                .map_err(|error| runtime_error(label, cursor, window, error))?;
            let scan_limit = window;
            if let Some(last_start) = scan_limit.checked_sub(ANCHOR_PATTERN.len() as u32) {
                for offset in 0..=last_start {
                    let start = offset as usize;
                    let end = start + ANCHOR_PATTERN.len();
                    if bytes[start..end] == ANCHOR_PATTERN[..] {
                        let address = cursor + offset;
                        let storage = image
                            .storage_spans(address, ANCHOR_PATTERN.len() as u32)
                            .map_err(|error| {
                                runtime_error(label, address, ANCHOR_PATTERN.len() as u32, error)
                            })?;
                        occurrences.push(AnchorOccurrence { address, storage });
                        if occurrences.len() as u64 > MAX_ANCHOR_OCCURRENCES {
                            return Err(PalTaskError::ResourceLimit {
                                what: "anchor occurrences",
                                actual: occurrences.len() as u64,
                                limit: MAX_ANCHOR_OCCURRENCES,
                            });
                        }
                    }
                }
            }
            cursor += body;
        }
    }
    Ok(occurrences)
}

/// One image-wide halfword-aligned Thumb sweep over byte-backed storage
/// that resolves every semantic anchor reference for the complete anchor
/// set: `ADR` materializations, literal loads whose pool word equals the
/// anchor, and register-consistent `MOVW`/`MOVT` constructions.
pub(super) fn find_anchor_references(
    image: &RuntimeImage<'_>,
    label: &str,
    anchors: &[AnchorOccurrence],
) -> std::result::Result<Vec<AnchorReference>, PalTaskError> {
    let addresses: Vec<u32> = anchors.iter().map(|anchor| anchor.address).collect();
    let mut references = Vec::new();
    for range in image.byte_backed_ranges() {
        let mut cursor = range.start;
        while cursor < range.end {
            let remaining = range.end - cursor;
            let body = remaining.min(MAX_EXACT_READ as u32 - 4);
            let window = (body + 4).min(remaining);
            let bytes = image
                .read_exact(cursor, window as usize)
                .map_err(|error| runtime_error(label, cursor, window, error))?;
            // Positions in [cursor, cursor + body) belong to this chunk;
            // the last two bytes of the read back a narrow final
            // instruction, and wider decodes fail naturally when the run
            // ends first.
            let limit = (cursor + body).min(cursor + window.saturating_sub(2));
            let mut pc = cursor + (cursor & 1);
            while pc < limit {
                let offset = usize::try_from(pc - cursor).expect("pc stays inside the chunk");
                if let Some(reference) = classify_position(image, pc, &bytes[offset..], &addresses)?
                {
                    references.push(reference);
                    if references.len() as u64 > MAX_ANCHOR_REFERENCES {
                        return Err(PalTaskError::ResourceLimit {
                            what: "anchor references",
                            actual: references.len() as u64,
                            limit: MAX_ANCHOR_REFERENCES,
                        });
                    }
                }
                pc += 2;
            }
            cursor += body;
        }
    }
    Ok(references)
}

fn classify_position(
    image: &RuntimeImage<'_>,
    pc: u32,
    encoding: &[u8],
    anchor_addresses: &[u32],
) -> std::result::Result<Option<AnchorReference>, PalTaskError> {
    let decoder = PureRustDecoder;
    let mut state = decoder.begin_range(THUMB);
    let Ok(instruction) = decoder.decode_one(&mut state, THUMB, pc, encoding) else {
        return Ok(None);
    };
    match &instruction.effect {
        ValueEffect::RegisterWrite { dst, value } => match value {
            ValueExpr::ArchitecturalPc {
                addend,
                align_to_four: true,
            } => {
                let address = wrapping_offset(visible_pc(pc, true), *addend);
                Ok(anchor_reference(
                    anchor_addresses,
                    AnchorReferenceKind::Adr,
                    pc,
                    vec![pc],
                    *dst,
                    address,
                ))
            }
            ValueExpr::Immediate(low) => {
                movw_movt_reference(image, pc, *dst, *low, instruction.length, anchor_addresses)
            }
            _ => Ok(None),
        },
        ValueEffect::LiteralWordLoad { dst, address } => {
            let crate::arm32::AddressExpr {
                base:
                    AddressBase::ArchitecturalPc {
                        align_to_four: true,
                    },
                offset: AddressOffset::Immediate(offset),
            } = address
            else {
                return Ok(None);
            };
            let literal = wrapping_offset(visible_pc(pc, true), *offset);
            match image.read_u32(literal) {
                Ok(value) => Ok(anchor_reference(
                    anchor_addresses,
                    AnchorReferenceKind::Literal,
                    pc,
                    vec![pc],
                    *dst,
                    value,
                )),
                // A pool word outside byte-backed storage is not a
                // materialization of any anchor.
                Err(_) => Ok(None),
            }
        }
        _ => Ok(None),
    }
}

/// Resolve a `MOVW`-style low-half write through a register-consistent
/// `MOVT` in the same basic block, within the 32-instruction span and
/// with no intervening clobber of the destination.
fn movw_movt_reference(
    image: &RuntimeImage<'_>,
    movw_pc: u32,
    destination: Register,
    low: u32,
    movw_length: u8,
    anchor_addresses: &[u32],
) -> std::result::Result<Option<AnchorReference>, PalTaskError> {
    let Some(start) = movw_pc.checked_add(u32::from(movw_length)) else {
        return Ok(None);
    };
    let mut pc = start;
    let mut remaining = MAX_MOVW_MOVT_SPAN_INSTRUCTIONS - 1;
    while remaining > 0 {
        remaining -= 1;
        let Some(instruction) = decode_thumb_at(image, pc) else {
            return Ok(None);
        };
        if !matches!(instruction.flow, ControlFlow::Linear) {
            // Any non-linear transfer ends the basic block.
            return Ok(None);
        }
        if let ValueEffect::RegisterWrite {
            dst,
            value: ValueExpr::ReplaceHighHalf { source, high },
        } = &instruction.effect
            && *dst == destination
            && *source == destination
        {
            let value = (u32::from(*high) << 16) | (low & 0xffff);
            return Ok(anchor_reference(
                anchor_addresses,
                AnchorReferenceKind::MovwMovt,
                movw_pc,
                vec![movw_pc, pc],
                destination,
                value,
            ));
        }
        if instruction.writes.contains(&destination) {
            // Any other write to the destination breaks register
            // consistency.
            return Ok(None);
        }
        let Some(next) = pc.checked_add(u32::from(instruction.length)) else {
            return Ok(None);
        };
        pc = next;
    }
    Ok(None)
}

fn anchor_reference(
    anchor_addresses: &[u32],
    kind: AnchorReferenceKind,
    pc: u32,
    definitions: Vec<u32>,
    register: Register,
    value: u32,
) -> Option<AnchorReference> {
    let anchor = anchor_addresses
        .binary_search(&value)
        .ok()
        .map(|index| anchor_addresses[index])?;
    (pc.abs_diff(anchor) <= MAX_ANCHOR_REFERENCE_DISTANCE).then_some(AnchorReference {
        anchor,
        kind,
        pc,
        definitions,
        register,
    })
}

/// Enumerate every recognized Thumb prologue in the window before the
/// reference and keep the candidate only when exactly one decodes
/// linearly onto the reference. Selecting the nearest candidate or
/// filtering ambiguous roots by later topology is forbidden.
pub(super) fn unique_prologue_root(image: &RuntimeImage<'_>, reference: u32) -> Option<u32> {
    let window_start = reference.saturating_sub(PROLOGUE_WINDOW_BYTES) & !1;
    let mut candidates = Vec::new();
    let mut pc = window_start;
    while pc < reference {
        if let Some(instruction) = decode_thumb_at(image, pc)
            && is_recognized_prologue(&instruction)
            && linear_decode_reaches(image, pc, reference)
        {
            candidates.push(pc);
        }
        pc = pc.checked_add(2)?;
    }
    match candidates.as_slice() {
        [only] => Some(*only),
        _ => None,
    }
}

fn linear_decode_reaches(image: &RuntimeImage<'_>, start: u32, reference: u32) -> bool {
    let mut pc = start;
    while pc < reference {
        let Some(instruction) = decode_thumb_at(image, pc) else {
            return false;
        };
        let Some(next) = pc.checked_add(u32::from(instruction.length)) else {
            return false;
        };
        pc = next;
    }
    pc == reference
}

/// A recognized prologue stores LR through a decrementing SP writeback:
/// `push {..., lr}` or `stmdb sp!, {..., lr}`.
fn is_recognized_prologue(instruction: &DecodedInstruction) -> bool {
    if !matches!(instruction.flow, ControlFlow::Linear) {
        return false;
    }
    let ValueEffect::Memory(effect) = &instruction.effect else {
        return false;
    };
    let Some((base, writeback)) = &effect.writeback else {
        return false;
    };
    if *base != SP {
        return false;
    }
    let AddressOffset::Immediate(delta) = writeback.offset else {
        return false;
    };
    delta < 0
        && effect.transfers.iter().any(|transfer| {
            transfer.kind == AccessKind::Write
                && transfer.width == 4
                && transfer.value == Some(LR)
                && matches!(&transfer.address.base, AddressBase::Register(base) if *base == SP)
        })
}

#[cfg(test)]
mod tests {
    use super::{find_anchor_occurrences, find_anchor_references};
    use crate::arm32::Register;
    use crate::pal_tasks::discover_anchor_cfg;
    use crate::pal_tasks::{
        ANCHOR_PATTERN, AnchorReference, AnchorReferenceKind, MAX_ANCHOR_REFERENCE_DISTANCE,
        PalTaskError,
    };
    use crate::runtime_image::{RuntimeImage, StorageKind, StorageSpan};
    use crate::scatter::{
        Descriptor, HandlerMap, LoadPlan, Operation, PlannedEntry, PlannedOutput,
    };
    use scaleservers_arm32_assembly::{
        Arm32GeneralPurposeRegister as Gpr, Arm32LowGeneralPurposeRegister as Low,
        ArmT32Instruction as T32,
    };

    const BASE: u32 = 0x1000;

    fn raw_image(bytes: &[u8]) -> RuntimeImage<'_> {
        RuntimeImage::from_plan(bytes, BASE, None).expect("raw fixture image")
    }

    fn bytes_entry(index: usize, destination: u32, bytes: Vec<u8>) -> PlannedEntry {
        PlannedEntry {
            index,
            descriptor: Descriptor {
                source: destination,
                destination,
                size: u32::try_from(bytes.len()).expect("fixture size fits u32"),
                handler: BASE + 2,
            },
            operation: Operation::Copy,
            compressed_size: None,
            output: PlannedOutput::Bytes(bytes),
        }
    }

    fn zero_entry(index: usize, destination: u32, size: u32) -> PlannedEntry {
        PlannedEntry {
            index,
            descriptor: Descriptor {
                source: destination,
                destination,
                size,
                handler: BASE + 4,
            },
            operation: Operation::Zero,
            compressed_size: None,
            output: PlannedOutput::ZeroFill,
        }
    }

    fn scatter_plan(image_size: u32, entries: Vec<PlannedEntry>) -> LoadPlan {
        let logical = entries
            .iter()
            .map(|entry| u64::from(entry.descriptor.size))
            .sum();
        LoadPlan {
            image_base: BASE,
            image_size,
            loader_address: BASE,
            literal_pair_address: BASE,
            table_start: BASE,
            table_end: BASE + image_size,
            handlers: HandlerMap {
                null: BASE + 1,
                copy: BASE + 2,
                decompress1: BASE + 3,
                zero: BASE + 4,
            },
            entries,
            logical_output_size: logical,
        }
    }

    fn enc(instruction: &T32) -> Vec<u8> {
        instruction.encode().expect("fixture encodes")
    }

    fn put(bytes: &mut [u8], offset: usize, part: &[u8]) {
        bytes[offset..offset + part.len()].copy_from_slice(part);
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn gpr(number: u8) -> Gpr {
        Gpr::from_operand_bits(number)
    }

    fn low(number: u8) -> Low {
        Low::from_operand_bits(number)
    }

    fn addresses(occurrences: &[super::AnchorOccurrence]) -> Vec<u32> {
        occurrences.iter().map(|anchor| anchor.address).collect()
    }

    #[test]
    fn anchor_sweep_finds_raw_scatter_and_cross_span_materializations() {
        // Raw anchor at BASE+0x8, an anchor straddling the raw/scatter
        // boundary at BASE+0x3a, and a fully scatter-backed anchor at
        // 0x3000.
        let mut raw = vec![0u8; 0x40];
        put(&mut raw, 0x08, ANCHOR_PATTERN);
        put(&mut raw, 0x3a, b"PALTsk");
        let cross = b"Tm\0".to_vec();
        let scatter = ANCHOR_PATTERN.to_vec();
        let plan = scatter_plan(
            0x40,
            vec![
                bytes_entry(0, BASE + 0x40, cross),
                bytes_entry(1, 0x3000, scatter),
            ],
        );
        let image = RuntimeImage::from_plan(&raw, BASE, Some(&plan)).expect("fixture image");

        let occurrences = find_anchor_occurrences(&image, "fixture").unwrap();
        assert_eq!(addresses(&occurrences), [BASE + 0x08, BASE + 0x3a, 0x3000]);
        // The cross-span anchor retains the exact nine-byte provenance.
        assert_eq!(
            occurrences[1].storage,
            [
                StorageSpan {
                    kind: StorageKind::Raw,
                    address: BASE + 0x3a,
                    size: 6,
                    scatter_entry: None,
                },
                StorageSpan {
                    kind: StorageKind::ScatterBytes,
                    address: BASE + 0x40,
                    size: 3,
                    scatter_entry: Some(0),
                },
            ]
        );
    }

    #[test]
    fn anchor_references_cover_adr_literal_and_movw_movt_materializations() {
        // ADR: push, adr r1 -> anchor, bx lr.
        let mut bytes = vec![0u8; 0x19];
        put(&mut bytes, 0x00, &enc(&T32::Push_T1(vec![gpr(4), gpr(14)])));
        put(&mut bytes, 0x02, &enc(&T32::Adr_T1(low(1), 0x0c)));
        put(&mut bytes, 0x04, &enc(&T32::Bx_T1(gpr(14))));
        put(&mut bytes, 0x10, ANCHOR_PATTERN);
        let candidates = discover_anchor_cfg(&raw_image(&bytes), "fixture").unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].anchor, BASE + 0x10);
        assert_eq!(candidates[0].initializer, BASE);
        assert_eq!(
            candidates[0].reference,
            AnchorReference {
                anchor: BASE + 0x10,
                kind: AnchorReferenceKind::Adr,
                pc: BASE + 0x02,
                definitions: vec![BASE + 0x02],
                register: Register(1),
            }
        );
        assert!(candidates[0].cfg.contains_node(BASE + 0x02));

        // Literal load: push, ldr r0, [pc, #4] with a pool word equal to
        // the anchor.
        let mut bytes = vec![0u8; 0x19];
        put(&mut bytes, 0x00, &enc(&T32::Push_T1(vec![gpr(4), gpr(14)])));
        put(&mut bytes, 0x02, &enc(&T32::Ldr_Literal_T1(low(0), 4)));
        put(&mut bytes, 0x04, &enc(&T32::Bx_T1(gpr(14))));
        put_u32(&mut bytes, 0x08, BASE + 0x10);
        put(&mut bytes, 0x10, ANCHOR_PATTERN);
        let candidates = discover_anchor_cfg(&raw_image(&bytes), "fixture").unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].reference,
            AnchorReference {
                anchor: BASE + 0x10,
                kind: AnchorReferenceKind::Literal,
                pc: BASE + 0x02,
                definitions: vec![BASE + 0x02],
                register: Register(0),
            }
        );

        // MOVW/MOVT: push, movw r3, movt r3, bx lr, in one basic block.
        let mut bytes = vec![0u8; 0x19];
        put(&mut bytes, 0x00, &enc(&T32::Push_T1(vec![gpr(4), gpr(14)])));
        put(
            &mut bytes,
            0x02,
            &enc(&T32::Mov_Immediate_T3(gpr(3), 0x1010)),
        );
        put(&mut bytes, 0x06, &enc(&T32::Movt_T1(gpr(3), 0)));
        put(&mut bytes, 0x0a, &enc(&T32::Bx_T1(gpr(14))));
        put(&mut bytes, 0x10, ANCHOR_PATTERN);
        let candidates = discover_anchor_cfg(&raw_image(&bytes), "fixture").unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].reference,
            AnchorReference {
                anchor: BASE + 0x10,
                kind: AnchorReferenceKind::MovwMovt,
                pc: BASE + 0x02,
                definitions: vec![BASE + 0x02, BASE + 0x06],
                register: Register(3),
            }
        );
    }

    #[test]
    fn anchor_reference_beyond_four_kib_is_not_collected() {
        // Anchor at BASE+0x10; a literal load at +0x1000 (exactly the
        // distance limit, collected) and materializations far beyond it
        // (rejected even though they resolve the same anchor).
        let mut bytes = vec![0u8; 0x3020];
        put(&mut bytes, 0x10, ANCHOR_PATTERN);
        // Exactly MAX_ANCHOR_REFERENCE_DISTANCE away: collected.
        put(&mut bytes, 0x1010, &enc(&T32::Ldr_Literal_T2(gpr(4), 0)));
        put_u32(&mut bytes, 0x1014, BASE + 0x10);
        // 0x2000 away: not collected.
        put(&mut bytes, 0x2010, &enc(&T32::Ldr_Literal_T2(gpr(0), 0)));
        put_u32(&mut bytes, 0x2014, BASE + 0x10);
        // 0x3000 away: not collected.
        put(
            &mut bytes,
            0x3010,
            &enc(&T32::Mov_Immediate_T3(gpr(2), 0x1010)),
        );
        put(&mut bytes, 0x3014, &enc(&T32::Movt_T1(gpr(2), 0)));

        let anchors = find_anchor_occurrences(&raw_image(&bytes), "fixture").unwrap();
        assert_eq!(addresses(&anchors), [BASE + 0x10]);
        let references = find_anchor_references(&raw_image(&bytes), "fixture", &anchors).unwrap();
        assert_eq!(
            references,
            [AnchorReference {
                anchor: BASE + 0x10,
                kind: AnchorReferenceKind::Literal,
                pc: BASE + 0x1010,
                definitions: vec![BASE + 0x1010],
                register: Register(4),
            }]
        );
        assert_eq!(
            MAX_ANCHOR_REFERENCE_DISTANCE, 4096,
            "distance limit fixture depends on the exact bound"
        );
        assert!(
            discover_anchor_cfg(&raw_image(&bytes), "fixture")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn anchor_unrelated_materializations_yield_no_candidates() {
        // An ADR to a nearby non-anchor string is not a reference.
        let mut bytes = vec![0u8; 0x60];
        put(&mut bytes, 0x10, ANCHOR_PATTERN);
        put(&mut bytes, 0x40, b"OTHER\0\0\0");
        put(&mut bytes, 0x02, &enc(&T32::Adr_T1(low(1), 0x40)));
        let candidates = discover_anchor_cfg(&raw_image(&bytes), "fixture").unwrap();
        assert!(candidates.is_empty());

        // An image without the anchor materialization finds nothing.
        let mut bytes = vec![0u8; 0x20];
        put(&mut bytes, 0x02, &enc(&T32::Adr_T1(low(1), 0x08)));
        assert!(
            discover_anchor_cfg(&raw_image(&bytes), "fixture")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn anchor_occurrences_are_capped_at_4096() {
        let mut bytes = vec![0u8; 4097 * 16];
        for index in 0..4097 {
            put(&mut bytes, index * 16, ANCHOR_PATTERN);
        }
        assert!(matches!(
            discover_anchor_cfg(&raw_image(&bytes), "fixture"),
            Err(PalTaskError::ResourceLimit {
                what: "anchor occurrences",
                actual: 4097,
                limit: 4096,
            })
        ));
    }

    #[test]
    fn anchor_references_are_capped_at_16384() {
        // 33 anchors, each preceded by a cluster of 512 ADR references
        // inside the distance limit: 16896 references in total.
        const CLUSTERS: usize = 33;
        const STRIDE: u32 = 0x1100;
        let image_end = 0x400 + STRIDE * (CLUSTERS as u32 - 1) + 0x20;
        let mut bytes = vec![0u8; image_end as usize];
        for cluster in 0..CLUSTERS {
            let anchor_address = BASE + 0x400 + STRIDE * cluster as u32;
            put(
                &mut bytes,
                (0x400 + STRIDE * cluster as u32) as usize,
                ANCHOR_PATTERN,
            );
            let cluster_start = STRIDE * cluster as u32;
            let mut offset = cluster_start;
            while offset < cluster_start + 0x400 {
                let pc = BASE + offset;
                let visible = (pc + 4) & !3;
                let const10 =
                    u16::try_from(anchor_address - visible).expect("fixture const10 fits u16");
                put(
                    &mut bytes,
                    offset as usize,
                    &enc(&T32::Adr_T1(low(1), const10)),
                );
                offset += 2;
            }
        }
        assert!(matches!(
            discover_anchor_cfg(&raw_image(&bytes), "fixture"),
            Err(PalTaskError::ResourceLimit {
                what: "anchor references",
                actual: 16385,
                limit: 16384,
            })
        ));
    }

    #[test]
    fn anchor_movw_movt_pairs_share_one_block_within_32_instructions() {
        // Cluster A: movw + 30 nops + movt is a 32-instruction span.
        let mut bytes = vec![0u8; 0x4060];
        put(
            &mut bytes,
            0x00,
            &enc(&T32::Mov_Immediate_T3(gpr(0), 0x1048)),
        );
        for index in 0..30 {
            put(&mut bytes, 0x04 + index * 2, &enc(&T32::Nop_T1));
        }
        put(&mut bytes, 0x40, &enc(&T32::Movt_T1(gpr(0), 0)));
        put(&mut bytes, 0x48, ANCHOR_PATTERN);

        // Cluster B: one extra nop makes the span 33 instructions.
        put(
            &mut bytes,
            0x1000,
            &enc(&T32::Mov_Immediate_T3(gpr(0), 0x2048)),
        );
        for index in 0..31 {
            put(&mut bytes, 0x1004 + index * 2, &enc(&T32::Nop_T1));
        }
        put(&mut bytes, 0x1042, &enc(&T32::Movt_T1(gpr(0), 0)));
        put(&mut bytes, 0x1048, ANCHOR_PATTERN);

        // Cluster C: an intervening write to the destination register
        // breaks register consistency.
        put(
            &mut bytes,
            0x2000,
            &enc(&T32::Mov_Immediate_T3(gpr(2), 0x3010)),
        );
        put(
            &mut bytes,
            0x2004,
            &enc(&T32::Mov_Register_T1(gpr(2), gpr(3))),
        );
        put(&mut bytes, 0x2006, &enc(&T32::Movt_T1(gpr(2), 0)));
        put(&mut bytes, 0x2010, ANCHOR_PATTERN);

        // Cluster D: an unconditional branch ends the basic block before
        // the movt.
        put(
            &mut bytes,
            0x3000,
            &enc(&T32::Mov_Immediate_T3(gpr(0), 0x4010)),
        );
        put(&mut bytes, 0x3004, &enc(&T32::Nop_T1));
        put(&mut bytes, 0x3006, &enc(&T32::B_T2(0)));
        put(&mut bytes, 0x3008, &enc(&T32::Nop_T1));
        put(&mut bytes, 0x300a, &enc(&T32::Movt_T1(gpr(0), 0)));
        put(&mut bytes, 0x3010, ANCHOR_PATTERN);

        let anchors = find_anchor_occurrences(&raw_image(&bytes), "fixture").unwrap();
        assert_eq!(
            addresses(&anchors),
            [BASE + 0x48, BASE + 0x1048, BASE + 0x2010, BASE + 0x3010]
        );
        let references = find_anchor_references(&raw_image(&bytes), "fixture", &anchors).unwrap();
        assert_eq!(
            references,
            [AnchorReference {
                anchor: BASE + 0x48,
                kind: AnchorReferenceKind::MovwMovt,
                pc: BASE,
                definitions: vec![BASE, BASE + 0x40],
                register: Register(0),
            }]
        );
    }

    #[test]
    fn anchor_matches_never_cross_zero_or_gap_storage() {
        // Eight anchor bytes end the raw image and the ninth byte would
        // have to come from zero-fill storage: no match, even though the
        // zero-fill content is a NUL.
        let mut raw = vec![0u8; 0x10];
        put(&mut raw, 0x08, b"PALTskTm");
        let plan = scatter_plan(0x10, vec![zero_entry(0, BASE + 0x10, 8)]);
        let image = RuntimeImage::from_plan(&raw, BASE, Some(&plan)).expect("fixture image");
        assert!(
            find_anchor_occurrences(&image, "fixture")
                .unwrap()
                .is_empty()
        );

        // A pattern split across an unmapped gap never matches.
        let mut raw = vec![0u8; 0x10];
        put(&mut raw, 0x0a, b"PALTsk");
        let plan = scatter_plan(0x10, vec![bytes_entry(0, BASE + 0x18, b"Tm\0".to_vec())]);
        let image = RuntimeImage::from_plan(&raw, BASE, Some(&plan)).expect("fixture image");
        assert!(
            find_anchor_occurrences(&image, "fixture")
                .unwrap()
                .is_empty()
        );
    }
}
