use super::{MAX_CSTRING_BYTES, MessagePlan, PalMessageError, SEED};
use crate::arm32::{
    AddressBase, AddressOffset, DecodedInstruction, ValueEffect, ValueExpr, visible_pc,
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
    _label: &str,
) -> Result<Option<MessagePlan>, PalMessageError> {
    let _ = find_unique_seed(runtime, SEED)?;
    Ok(None)
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
                collect_refs_from_cfg(&cfg, runtime, pc, DecodeIsa::Arm, string_start, &mut seen, &mut refs);
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
        assert!(refs.is_empty(), "ADD after MOVW/MOVT must not be a ref: {refs:?}");
    }
}
