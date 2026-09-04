use super::{
    MAX_CSTRING_BYTES, MAX_TABLE_CAPACITY, MAX_TABLE_STRIDE, MessagePlan, PalMessageError, SEED,
};
use crate::arm32::{
    AccessKind, AddressBase, AddressOffset, DecodedInstruction, ValueEffect, ValueExpr, visible_pc,
    wrapping_offset,
};
use crate::execution_ranges::DecodeIsa;
use crate::runtime_image::{ByteBackedRange, MAX_EXACT_READ, RuntimeImage};
use crate::semantic_cfg::{CallPolicy, CfgLimits, SemanticCfg};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SeedHit {
    pub address: u32,
    pub string_start: u32,
    pub string_len: u32,
}

#[derive(Clone, Copy)]
struct Occurrence {
    address: u32,
    range: ByteBackedRange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SemanticRef {
    pub entry: u32,
    pub isa: DecodeIsa,
    pub pc: u32,
    pub address: u32,
}

fn pal_message_cfg_limits() -> CfgLimits {
    CfgLimits {
        max_charged_bytes: 512,
        max_instructions: 256,
        max_blocks: 256,
    }
}

pub(crate) fn discover(
    runtime: &RuntimeImage<'_>,
    label: &str,
) -> Result<Option<MessagePlan>, PalMessageError> {
    let Some(seed) = find_unique_seed(runtime, SEED)? else {
        return Ok(None);
    };
    let refs = semantic_refs(runtime, seed.string_start)?;
    prove_plan(runtime, label, &refs)
}

pub(crate) fn semantic_refs(
    runtime: &RuntimeImage<'_>,
    string_start: u32,
) -> Result<Vec<SemanticRef>, PalMessageError> {
    let mut refs = Vec::new();
    let mut seen = BTreeSet::new();
    for range in runtime.byte_backed_ranges() {
        let mut pc = range.start & !3;
        if pc < range.start {
            pc = pc.saturating_add(4);
        }
        while pc.saturating_add(4) <= range.end {
            if let Ok(cfg) = SemanticCfg::decode_with_address_window(
                runtime,
                pc,
                DecodeIsa::Arm,
                pal_message_cfg_limits(),
                CallPolicy::Fallthrough,
                Some(512),
            ) {
                collect_refs_from_cfg(
                    &cfg,
                    runtime,
                    pc,
                    DecodeIsa::Arm,
                    string_start,
                    &mut seen,
                    &mut refs,
                );
            }
            pc = match pc.checked_add(4) {
                Some(next) => next,
                None => break,
            };
        }
    }
    Ok(refs)
}

fn collect_refs_from_cfg(
    cfg: &SemanticCfg,
    runtime: &RuntimeImage<'_>,
    entry: u32,
    isa: DecodeIsa,
    string_start: u32,
    seen: &mut BTreeSet<u32>,
    refs: &mut Vec<SemanticRef>,
) {
    for state in cfg.exact_register_states().values() {
        for (_, value) in state.iter() {
            if value.value != string_start {
                continue;
            }
            let Some(pc) = value.root() else {
                continue;
            };
            let Some(definition) = value.definition() else {
                continue;
            };
            let Some(instruction) = cfg.instructions().get(&definition) else {
                continue;
            };
            if !is_pal_materialization(instruction, string_start, runtime) {
                continue;
            }
            if !seen.insert(pc) {
                continue;
            }
            refs.push(SemanticRef {
                entry,
                isa,
                pc,
                address: string_start,
            });
        }
    }
}

fn prove_plan(
    runtime: &RuntimeImage<'_>,
    label: &str,
    refs: &[SemanticRef],
) -> Result<Option<MessagePlan>, PalMessageError> {
    let mut pcs = BTreeSet::new();
    for reference in refs {
        pcs.insert(reference.pc);
    }
    let setup_pc = match pcs.len() {
        0 => return Ok(None),
        1 => *pcs.iter().next().expect("one pc"),
        _ => {
            return Err(PalMessageError::Ambiguous {
                values: pcs.into_iter().collect(),
            });
        }
    };
    let isa = refs
        .iter()
        .find(|reference| reference.pc == setup_pc)
        .map(|reference| reference.isa)
        .ok_or_else(|| malformed("setup reference is missing an ISA"))?;
    let cfg = match SemanticCfg::decode_with_address_window(
        runtime,
        setup_pc,
        isa,
        pal_message_cfg_limits(),
        CallPolicy::Fallthrough,
        Some(512),
    ) {
        Ok(cfg) => cfg,
        Err(_) => return Ok(None),
    };
    let Some((capacity, table_base, stride)) = unique_geometry(&cfg) else {
        return Ok(None);
    };
    if runtime.hash_range(table_base, stride).is_err() {
        return Ok(None);
    }
    let mut charged = 0u64;
    let slots = crate::pal_messages::table::hash_slots(
        runtime,
        table_base,
        stride,
        capacity,
        &mut charged,
    )?;
    let (image_base, image_size) = runtime.image_bounds();
    let table_end = table_base
        .checked_add(
            capacity
                .checked_mul(stride)
                .ok_or_else(|| malformed("table size wrap"))?,
        )
        .ok_or_else(|| malformed("table end wraps the address space"))?;
    Ok(Some(MessagePlan {
        image_label: label.to_owned(),
        image_base,
        image_size,
        setup_entry: setup_pc,
        setup_isa: isa,
        table_base,
        table_end,
        stride,
        capacity,
        slots,
    }))
}

fn unique_geometry(cfg: &SemanticCfg) -> Option<(u32, u32, u32)> {
    let mut stored_capacity = BTreeSet::new();
    let mut table_bases = BTreeSet::new();
    let mut store_regs = BTreeSet::new();
    for (pc, instruction) in cfg.instructions() {
        let ValueEffect::Memory(memory) = &instruction.effect else {
            continue;
        };
        let Some(state) = cfg.exact_register_states().get(pc) else {
            continue;
        };
        for transfer in &memory.transfers {
            if transfer.kind != AccessKind::Write || transfer.width != 4 {
                continue;
            }
            let Some(value_reg) = transfer.value else {
                continue;
            };
            let AddressBase::Register(base_reg) = transfer.address.base else {
                continue;
            };
            let AddressOffset::Immediate(0) = transfer.address.offset else {
                continue;
            };
            let Some(capacity) = state
                .get(value_reg)
                .filter(|fact| (1..=MAX_TABLE_CAPACITY).contains(&fact.value))
            else {
                continue;
            };
            let Some(base) = state.get(base_reg) else {
                continue;
            };
            stored_capacity.insert(capacity.value);
            table_bases.insert(base.value);
            store_regs.insert(value_reg);
            store_regs.insert(base_reg);
        }
    }
    let capacity = unique_value(&stored_capacity)?;
    let table_base = unique_value(&table_bases)?;
    let mut stride_immediates = BTreeSet::new();
    for instruction in cfg.instructions().values() {
        let ValueEffect::RegisterWrite {
            dst,
            value: ValueExpr::Immediate(value),
        } = instruction.effect
        else {
            continue;
        };
        if store_regs.contains(&dst) {
            continue;
        }
        if (4..=MAX_TABLE_STRIDE).contains(&value) && value % 4 == 0 && value != capacity {
            stride_immediates.insert(value);
        }
    }
    let stride = unique_value(&stride_immediates)?;
    Some((capacity, table_base, stride))
}

fn unique_value(values: &BTreeSet<u32>) -> Option<u32> {
    let mut iter = values.iter().copied();
    let first = iter.next()?;
    if iter.next().is_some() {
        None
    } else {
        Some(first)
    }
}

fn is_pal_materialization(
    instruction: &DecodedInstruction,
    string_start: u32,
    runtime: &RuntimeImage<'_>,
) -> bool {
    match &instruction.effect {
        ValueEffect::RegisterWrite {
            value:
                ValueExpr::ArchitecturalPc {
                    addend,
                    align_to_four,
                },
            ..
        } => wrapping_offset(visible_pc(instruction.pc, *align_to_four), *addend) == string_start,
        ValueEffect::RegisterWrite {
            value: ValueExpr::Immediate(value),
            ..
        } => *value == string_start,
        ValueEffect::RegisterWrite {
            value: ValueExpr::ReplaceHighHalf { .. },
            ..
        } => true,
        ValueEffect::LiteralWordLoad { address, .. } => {
            let crate::arm32::AddressExpr {
                base: AddressBase::ArchitecturalPc { align_to_four },
                offset: AddressOffset::Immediate(offset),
            } = address
            else {
                return false;
            };
            let literal = wrapping_offset(visible_pc(instruction.pc, *align_to_four), *offset);
            runtime.read_u32(literal).ok() == Some(string_start)
        }
        _ => false,
    }
}

pub(crate) fn find_unique_seed(
    runtime: &RuntimeImage<'_>,
    needle: &[u8],
) -> Result<Option<SeedHit>, PalMessageError> {
    if needle.is_empty() {
        return Err(malformed("seed needle is empty"));
    }
    let mut hits = Vec::new();
    for range in runtime.byte_backed_ranges() {
        collect_hits(runtime, needle, range, &mut hits)?;
    }
    match hits.as_slice() {
        [] => Ok(None),
        [hit] => parse_cstring(runtime, *hit, needle.len()).map(Some),
        _ => Err(PalMessageError::Ambiguous {
            values: hits.iter().map(|hit| hit.address).collect(),
        }),
    }
}

fn malformed(context: impl Into<String>) -> PalMessageError {
    PalMessageError::Malformed {
        context: context.into(),
    }
}

fn runtime_error(address: u32, size: u32, error: crate::error::Error) -> PalMessageError {
    PalMessageError::Runtime {
        address,
        size,
        reason: error.to_string(),
    }
}

fn collect_hits(
    runtime: &RuntimeImage<'_>,
    needle: &[u8],
    range: ByteBackedRange,
    hits: &mut Vec<Occurrence>,
) -> Result<(), PalMessageError> {
    let needle_len = u32::try_from(needle.len())
        .map_err(|_| malformed("seed needle length does not fit u32"))?;
    let tail = needle_len - 1;
    let max_body = (MAX_EXACT_READ as u32)
        .checked_sub(tail)
        .ok_or_else(|| malformed("seed needle exceeds the exact-read ceiling"))?;
    if max_body == 0 {
        return Err(malformed("seed needle exceeds the exact-read ceiling"));
    }
    let mut cursor = range.start;
    while cursor < range.end {
        let remaining = range.end - cursor;
        let body = remaining.min(max_body);
        let window = (body + tail).min(remaining);
        let bytes = runtime
            .read_exact(cursor, window as usize)
            .map_err(|error| runtime_error(cursor, window, error))?;
        if let Some(last_start) = window.checked_sub(needle_len) {
            for offset in 0..=last_start {
                let start = offset as usize;
                if bytes[start..start + needle.len()] == needle[..] {
                    hits.push(Occurrence {
                        address: cursor + offset,
                        range,
                    });
                }
            }
        }
        cursor += body;
    }
    Ok(())
}

fn cstring_content_byte(byte: u8) -> bool {
    byte == b'\t' || byte == b'\n' || byte == b'\r' || (0x20..=0x7e).contains(&byte)
}

fn parse_cstring(
    runtime: &RuntimeImage<'_>,
    hit: Occurrence,
    needle_len: usize,
) -> Result<SeedHit, PalMessageError> {
    let mut string_start = hit.address;
    while string_start > hit.range.start {
        let prev = string_start - 1;
        let byte = runtime
            .read_u8(prev)
            .map_err(|error| runtime_error(prev, 1, error))?;
        if byte == 0 || !cstring_content_byte(byte) {
            break;
        }
        string_start = prev;
        if (hit.address - string_start) as usize >= MAX_CSTRING_BYTES {
            return Err(malformed("containing C-string exceeds the 128-byte bound"));
        }
    }
    let mut string_len = 0u32;
    loop {
        if string_len as usize >= MAX_CSTRING_BYTES {
            return Err(malformed("containing C-string exceeds the 128-byte bound"));
        }
        let cursor = string_start
            .checked_add(string_len)
            .ok_or_else(|| malformed("containing C-string wraps the address space"))?;
        if cursor >= hit.range.end {
            return Err(malformed("containing C-string is unterminated"));
        }
        let byte = runtime
            .read_u8(cursor)
            .map_err(|error| runtime_error(cursor, 1, error))?;
        string_len += 1;
        if byte == 0 {
            let needle_end = hit
                .address
                .checked_add(
                    u32::try_from(needle_len)
                        .map_err(|_| malformed("seed needle length does not fit u32"))?,
                )
                .ok_or_else(|| malformed("seed needle wraps the address space"))?;
            let string_end = string_start
                .checked_add(string_len)
                .ok_or_else(|| malformed("containing C-string wraps the address space"))?;
            if hit.address < string_start || needle_end >= string_end {
                return Err(malformed(
                    "seed needle is not inside the containing C-string",
                ));
            }
            return Ok(SeedHit {
                address: hit.address,
                string_start,
                string_len,
            });
        }
        if !cstring_content_byte(byte) {
            return Err(malformed("containing C-string has a non-printable byte"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{discover, find_unique_seed};
    use crate::pal_messages::{PalMessageError, SEED};
    use crate::runtime_image::RuntimeImage;

    const BASE: u32 = 0x4001_0000;

    fn runtime(raw: &[u8]) -> RuntimeImage<'_> {
        RuntimeImage::from_plan(raw, BASE, None).expect("raw fixture")
    }

    #[test]
    fn missing_seed_is_clean_absence() {
        let image = vec![0u8; 64];
        assert!(
            discover(&runtime(&image), "02_MAIN")
                .expect("no seed")
                .is_none()
        );
    }

    #[test]
    fn unique_seed_is_present_and_duplicate_is_ambiguous() {
        let mut unique = SEED.to_vec();
        unique.push(0);
        let hit = find_unique_seed(&runtime(&unique), SEED)
            .expect("unique seed")
            .expect("present");
        assert_eq!(hit.address, BASE);
        assert_eq!(hit.string_start, BASE);
        assert_eq!(hit.string_len, unique.len() as u32);

        let mut duplicate = unique.clone();
        duplicate.extend_from_slice(&unique);
        match find_unique_seed(&runtime(&duplicate), SEED) {
            Err(PalMessageError::Ambiguous { values }) => {
                assert_eq!(values, vec![BASE, BASE + unique.len() as u32]);
            }
            other => panic!("expected Ambiguous, got {other:?}"),
        }
    }

    #[test]
    fn unique_seed_after_thumb_padding_starts_at_the_needle() {
        let mut image = vec![0u8, 0xbf];
        image.extend_from_slice(SEED);
        image.push(0);
        let hit = find_unique_seed(&runtime(&image), SEED)
            .expect("unique seed")
            .expect("present");
        assert_eq!(hit.address, BASE + 2);
        assert_eq!(hit.string_start, BASE + 2);
    }

    #[test]
    fn unterminated_or_nonprintable_unique_hit_is_malformed() {
        match find_unique_seed(&runtime(SEED), SEED) {
            Err(PalMessageError::Malformed { context }) => {
                assert!(context.contains("unterminated"));
            }
            other => panic!("expected unterminated, got {other:?}"),
        }
        let mut image = SEED.to_vec();
        image.push(0x01);
        image.push(0);
        match find_unique_seed(&runtime(&image), SEED) {
            Err(PalMessageError::Malformed { context }) => {
                assert!(context.contains("non-printable"));
            }
            other => panic!("expected non-printable, got {other:?}"),
        }
    }

    const A32_ADD_R0_PC_8: [u8; 4] = [0x08, 0x00, 0x8f, 0xe2];
    const A32_BX_LR: [u8; 4] = [0x1e, 0xff, 0x2f, 0xe1];

    fn a32_movw(rd: u8, imm16: u16) -> [u8; 4] {
        let imm4 = u32::from(imm16) >> 12;
        let imm12 = u32::from(imm16) & 0xfff;
        (0xe300_0000 | (imm4 << 16) | (u32::from(rd) << 12) | imm12).to_le_bytes()
    }

    fn a32_movt(rd: u8, imm16: u16) -> [u8; 4] {
        let imm4 = u32::from(imm16) >> 12;
        let imm12 = u32::from(imm16) & 0xfff;
        (0xe340_0000 | (imm4 << 16) | (u32::from(rd) << 12) | imm12).to_le_bytes()
    }

    #[test]
    fn adr_materialization_is_a_ref() {
        let mut image = vec![0u8; 0x40];
        image[0..4].copy_from_slice(&A32_ADD_R0_PC_8);
        image[4..8].copy_from_slice(&A32_BX_LR);
        let string_off = 0x10;
        image[string_off..string_off + SEED.len()].copy_from_slice(SEED);
        image[string_off + SEED.len()] = 0;
        let runtime = runtime(&image);
        let seed = find_unique_seed(&runtime, SEED)
            .expect("unique")
            .expect("present");
        let refs = super::semantic_refs(&runtime, seed.string_start).expect("refs");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].pc, BASE);
        assert_eq!(refs[0].address, seed.string_start);
    }

    #[test]
    fn add_immediate_after_movw_movt_is_not_a_ref() {
        let mut image = vec![0u8; 0x40];
        let string_off = 0x20;
        image[string_off..string_off + SEED.len()].copy_from_slice(SEED);
        image[string_off + SEED.len()] = 0;
        let string_start = BASE + string_off as u32;
        let low = (string_start.wrapping_sub(4) & 0xffff) as u16;
        let high = (string_start.wrapping_sub(4) >> 16) as u16;
        image[0..4].copy_from_slice(&a32_movw(0, low));
        image[4..8].copy_from_slice(&a32_movt(0, high));
        image[8..12].copy_from_slice(&[0x04, 0x00, 0x80, 0xe2]);
        image[12..16].copy_from_slice(&A32_BX_LR);
        let runtime = runtime(&image);
        let seed = find_unique_seed(&runtime, SEED)
            .expect("unique")
            .expect("present");
        let refs = super::semantic_refs(&runtime, seed.string_start).expect("refs");
        assert!(
            refs.is_empty(),
            "ADD after MOVW/MOVT must not be a ref: {refs:?}"
        );
    }

    const A32_MOV_R1_4: [u8; 4] = [0x04, 0x10, 0xa0, 0xe3];
    const A32_MOV_R3_16: [u8; 4] = [0x10, 0x30, 0xa0, 0xe3];
    const A32_STR_R1_R2: [u8; 4] = [0x00, 0x10, 0x82, 0xe5];
    const A32_ADD_R0_PC_18: [u8; 4] = [0x18, 0x00, 0x8f, 0xe2];

    fn plant_setup(image: &mut [u8], table_base: u32) {
        image[0..4].copy_from_slice(&A32_ADD_R0_PC_18);
        image[4..8].copy_from_slice(&A32_MOV_R1_4);
        image[8..12].copy_from_slice(&A32_MOV_R3_16);
        image[12..16].copy_from_slice(&a32_movw(2, (table_base & 0xffff) as u16));
        image[16..20].copy_from_slice(&a32_movt(2, (table_base >> 16) as u16));
        image[20..24].copy_from_slice(&A32_STR_R1_R2);
        image[24..28].copy_from_slice(&A32_BX_LR);
        image[0x20..0x20 + SEED.len()].copy_from_slice(SEED);
        image[0x20 + SEED.len()] = 0;
    }

    #[test]
    fn discover_present_for_unique_setup_and_complete_table() {
        let mut image = vec![0u8; 0x100];
        let table_base = BASE + 0x80;
        plant_setup(&mut image, table_base);
        let plan = discover(&runtime(&image), "02_MAIN")
            .expect("discover")
            .expect("present");
        assert_eq!(plan.setup_entry, BASE);
        assert_eq!(plan.capacity, 4);
        assert_eq!(plan.stride, 16);
        assert_eq!(plan.table_base, table_base);
        assert_eq!(plan.slots.len(), 4);
        assert_eq!(plan.table_end, table_base + 64);
    }

    #[test]
    fn first_slot_unreadable_is_absence() {
        let mut image = vec![0u8; 0x40];
        plant_setup(&mut image, BASE + 0x1000);
        assert!(
            discover(&runtime(&image), "02_MAIN")
                .expect("discover")
                .is_none()
        );
    }

    #[test]
    fn readable_then_short_table_is_malformed() {
        let mut image = vec![0u8; 0x90];
        plant_setup(&mut image, BASE + 0x80);
        match discover(&runtime(&image), "02_MAIN") {
            Err(PalMessageError::Runtime { .. } | PalMessageError::Malformed { .. }) => {}
            other => panic!("expected malformed or runtime, got {other:?}"),
        }
    }

    #[test]
    fn two_complete_setups_are_ambiguous() {
        let mut image = vec![0u8; 0x80];
        image[0..4].copy_from_slice(&A32_ADD_R0_PC_18);
        image[4..8].copy_from_slice(&A32_BX_LR);
        image[8..12].copy_from_slice(&[0x10, 0x00, 0x8f, 0xe2]);
        image[12..16].copy_from_slice(&A32_BX_LR);
        let seed_off = 0x20;
        image[seed_off..seed_off + SEED.len()].copy_from_slice(SEED);
        image[seed_off + SEED.len()] = 0;
        match discover(&runtime(&image), "02_MAIN") {
            Err(PalMessageError::Ambiguous { values }) => {
                assert_eq!(values.len(), 2);
            }
            other => panic!("expected Ambiguous, got {other:?}"),
        }
    }
}
