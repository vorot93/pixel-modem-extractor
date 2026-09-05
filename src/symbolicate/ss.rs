#![cfg_attr(not(test), allow(dead_code))]

use crate::arm32::{
    ControlFlow, DecodedInstruction, ItRangeState, Register, ValueEffect, decode_a32, decode_t32,
};
use crate::execution_ranges::DecodeIsa;
use crate::pal_messages::{PalMessageError, SemanticRef, find_unique_seed, semantic_refs};
use crate::runtime_image::RuntimeImage;
use crate::semantic_cfg::{CallPolicy, CfgLimits, SemanticCfg, SemanticCfgError};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt;

pub(crate) const SEED: &[u8] = b"ss_DecodeGmmFacilityMsg";
#[allow(dead_code)]
pub(crate) const MAX_CSTRING_BYTES: usize = 128;
pub(crate) const MAX_SS_CALLSITES: usize = 4096;
pub(crate) const MAX_IDENT_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SsNameError {
    Malformed {
        context: String,
    },
    Ambiguous {
        values: Vec<u32>,
    },
    Decode {
        pc: u32,
        isa: DecodeIsa,
        reason: String,
    },
    Runtime {
        address: u32,
        size: u32,
        reason: String,
    },
    ResourceLimit {
        what: &'static str,
        actual: u64,
        limit: u64,
    },
}

impl fmt::Display for SsNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed { context } => write!(f, "ss names malformed: {context}"),
            Self::Ambiguous { values } => write!(f, "ss names ambiguous: {values:?}"),
            Self::Decode { pc, isa, reason } => {
                write!(f, "ss names decode {isa:?} {pc:#010x}: {reason}")
            }
            Self::Runtime {
                address,
                size,
                reason,
            } => write!(f, "ss names runtime {address:#010x}+{size:#x}: {reason}"),
            Self::ResourceLimit {
                what,
                actual,
                limit,
            } => write!(f, "ss names {what} {actual} exceeds {limit}"),
        }
    }
}

pub(crate) fn map_pal_error(error: PalMessageError) -> SsNameError {
    match error {
        PalMessageError::Malformed { context } => SsNameError::Malformed { context },
        PalMessageError::Ambiguous { values } => SsNameError::Ambiguous { values },
        PalMessageError::Decode { pc, isa, reason } => SsNameError::Decode { pc, isa, reason },
        PalMessageError::Runtime {
            address,
            size,
            reason,
        } => SsNameError::Runtime {
            address,
            size,
            reason,
        },
        PalMessageError::ResourceLimit {
            what,
            actual,
            limit,
        } => SsNameError::ResourceLimit {
            what,
            actual,
            limit,
        },
        PalMessageError::Artifact(context) => SsNameError::Malformed { context },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SsContainer {
    pub entry: u32,
    pub isa: DecodeIsa,
    pub ranges: Vec<(u32, u32)>,
    pub ghidra: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SsPlan {
    pub helper_entry: u32,
    pub helper_isa: DecodeIsa,
    pub callsites: usize,
    pub names: BTreeMap<(u32, DecodeIsa), String>,
    pub conflicts: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SsOutcome {
    Absent,
    Present(SsPlan),
    Failed(SsNameError),
}

pub(crate) fn prove_helper(runtime: &RuntimeImage<'_>) -> SsOutcome {
    let seed = match find_unique_seed(runtime, SEED) {
        Ok(None) => return SsOutcome::Absent,
        Ok(Some(hit)) => hit,
        Err(error) => return SsOutcome::Failed(map_pal_error(error)),
    };
    let refs = match semantic_refs(runtime, seed.string_start) {
        Ok(refs) => refs,
        Err(error) => return SsOutcome::Failed(map_pal_error(error)),
    };
    let reference = match refs.as_slice() {
        [] => return SsOutcome::Absent,
        [reference] => *reference,
        _ => {
            return SsOutcome::Failed(SsNameError::Ambiguous {
                values: refs.iter().map(|reference| reference.pc).collect(),
            });
        }
    };
    let cfg = match SemanticCfg::decode_with_address_window(
        runtime,
        reference.pc,
        reference.isa,
        CfgLimits::ss_names(),
        CallPolicy::Fallthrough,
        Some(512),
    ) {
        Ok(cfg) => cfg,
        Err(SemanticCfgError::ResourceLimit {
            what,
            actual,
            limit,
        }) => {
            return SsOutcome::Failed(SsNameError::ResourceLimit {
                what,
                actual,
                limit,
            });
        }
        Err(_) => return SsOutcome::Absent,
    };
    match consuming_helpers(&cfg, reference, seed.string_start) {
        Ok(None) => SsOutcome::Absent,
        Ok(Some(target)) => match validate_helper(runtime, target, reference.isa) {
            Ok(helper_entry) => SsOutcome::Present(SsPlan {
                helper_entry,
                helper_isa: reference.isa,
                callsites: 0,
                names: BTreeMap::new(),
                conflicts: 0,
            }),
            Err(error) => SsOutcome::Failed(error),
        },
        Err(error) => SsOutcome::Failed(error),
    }
}

pub(crate) fn discover(
    runtime: &RuntimeImage<'_>,
    containers: &[SsContainer],
    globals: &HashSet<String>,
    fn_names: &HashSet<String>,
) -> SsOutcome {
    let mut plan = match prove_helper(runtime) {
        SsOutcome::Present(plan) => plan,
        other => return other,
    };
    let callsites = match collect_helper_callsites(runtime, plan.helper_entry, plan.helper_isa) {
        Ok(callsites) => callsites,
        Err(error) => return SsOutcome::Failed(error),
    };
    plan.callsites = callsites.len();
    let mut pairs = Vec::new();
    for pc in callsites {
        if let Some(pair) = name_at_callsite(runtime, pc, plan.helper_isa, containers) {
            pairs.push(pair);
        }
    }
    let (names, conflicts) = one_to_one(pairs, globals, fn_names);
    plan.names = names;
    plan.conflicts = conflicts;
    SsOutcome::Present(plan)
}

fn collect_helper_callsites(
    runtime: &RuntimeImage<'_>,
    helper_entry: u32,
    helper_isa: DecodeIsa,
) -> Result<Vec<u32>, SsNameError> {
    let step: u32 = match helper_isa {
        DecodeIsa::Arm => 4,
        DecodeIsa::Thumb => 2,
    };
    let mut callsites = Vec::new();
    for range in runtime.byte_backed_ranges() {
        let mask = step.wrapping_sub(1);
        let mut pc = range.start & !mask;
        if pc < range.start {
            pc = match pc.checked_add(step) {
                Some(next) => next,
                None => continue,
            };
        }
        while pc.saturating_add(step) <= range.end {
            if let Some(instruction) = decode_at(runtime, pc, helper_isa)
                && let ControlFlow::DirectCall { target } = instruction.flow
                && target == helper_entry
            {
                callsites.push(pc);
                if callsites.len() > MAX_SS_CALLSITES {
                    return Err(SsNameError::ResourceLimit {
                        what: "callsites",
                        actual: callsites.len() as u64,
                        limit: MAX_SS_CALLSITES as u64,
                    });
                }
            }
            pc = match pc.checked_add(step) {
                Some(next) => next,
                None => break,
            };
        }
    }
    Ok(callsites)
}

fn decode_at(runtime: &RuntimeImage<'_>, pc: u32, isa: DecodeIsa) -> Option<DecodedInstruction> {
    let bytes = runtime.read_exact(pc, 4).ok()?;
    match isa {
        DecodeIsa::Arm => decode_a32(pc, bytes.as_ref()).ok(),
        DecodeIsa::Thumb => {
            let mut it = ItRangeState::default();
            decode_t32(&mut it, pc, bytes.as_ref()).ok()
        }
    }
}

fn name_at_callsite(
    runtime: &RuntimeImage<'_>,
    pc: u32,
    helper_isa: DecodeIsa,
    containers: &[SsContainer],
) -> Option<(u32, DecodeIsa, String)> {
    let container = unique_container(containers, pc, helper_isa)?;
    let cfg = SemanticCfg::decode_with_address_window(
        runtime,
        container.entry,
        container.isa,
        CfgLimits::ss_names(),
        CallPolicy::Fallthrough,
        Some(512),
    )
    .ok()?;
    let address = cfg
        .exact_register_states()
        .get(&pc)
        .and_then(|state| state.get(Register(0)))
        .map(|value| value.value)?;
    let name = read_ss_ident(runtime, address)?;
    Some((container.entry, container.isa, name))
}

fn unique_container(
    containers: &[SsContainer],
    pc: u32,
    helper_isa: DecodeIsa,
) -> Option<&SsContainer> {
    let mut by_entry: BTreeMap<u32, &SsContainer> = BTreeMap::new();
    for container in containers {
        if container.isa != helper_isa {
            continue;
        }
        if !container
            .ranges
            .iter()
            .any(|&(start, end)| start <= pc && pc < end)
        {
            continue;
        }
        match by_entry.get(&container.entry) {
            Some(existing) if existing.ghidra || !container.ghidra => {}
            _ => {
                by_entry.insert(container.entry, container);
            }
        }
    }
    if by_entry.len() != 1 {
        return None;
    }
    by_entry.into_values().next()
}

fn read_ss_ident(runtime: &RuntimeImage<'_>, address: u32) -> Option<String> {
    let mut bytes = Vec::new();
    for offset in 0..=MAX_IDENT_BYTES {
        let offset = u32::try_from(offset).ok()?;
        let cursor = address.checked_add(offset)?;
        if !runtime.is_byte_backed(cursor, 1).ok()? {
            return None;
        }
        let byte = runtime.read_u8(cursor).ok()?;
        if byte == 0 {
            let name = String::from_utf8(bytes).ok()?;
            if name.starts_with("ss_") && super::name_guess::is_ident(&name) {
                return Some(name);
            }
            return None;
        }
        if !cstring_content_byte(byte) {
            return None;
        }
        if offset as usize == MAX_IDENT_BYTES {
            return None;
        }
        bytes.push(byte);
    }
    None
}

fn cstring_content_byte(byte: u8) -> bool {
    byte == b'\t' || byte == b'\n' || byte == b'\r' || (0x20..=0x7e).contains(&byte)
}

fn one_to_one(
    pairs: Vec<(u32, DecodeIsa, String)>,
    globals: &HashSet<String>,
    fn_names: &HashSet<String>,
) -> (BTreeMap<(u32, DecodeIsa), String>, usize) {
    let unique: BTreeSet<(u32, DecodeIsa, String)> = pairs.into_iter().collect();
    let total = unique.len();
    let mut names_for_id: BTreeMap<(u32, DecodeIsa), BTreeSet<String>> = BTreeMap::new();
    let mut ids_for_name: BTreeMap<String, BTreeSet<(u32, DecodeIsa)>> = BTreeMap::new();
    for (entry, isa, name) in &unique {
        names_for_id
            .entry((*entry, *isa))
            .or_default()
            .insert(name.clone());
        ids_for_name
            .entry(name.clone())
            .or_default()
            .insert((*entry, *isa));
    }
    let mut names = BTreeMap::new();
    for (identity, name_set) in names_for_id {
        if name_set.len() != 1 {
            continue;
        }
        let name = name_set.into_iter().next().expect("len == 1");
        if ids_for_name[&name].len() != 1 {
            continue;
        }
        if globals.contains(&name) || fn_names.contains(&name) {
            continue;
        }
        names.insert(identity, name);
    }
    let conflicts = total - names.len();
    (names, conflicts)
}

fn consuming_helpers(
    cfg: &SemanticCfg,
    reference: SemanticRef,
    seed: u32,
) -> Result<Option<u32>, SsNameError> {
    let Some(ref_instruction) = cfg.instructions().get(&reference.pc) else {
        return Ok(None);
    };
    if !writes_r0(ref_instruction) {
        return Ok(None);
    }
    let mut helpers = Vec::new();
    for (&pc, instruction) in cfg.instructions() {
        if pc < reference.pc {
            continue;
        }
        let ControlFlow::DirectCall { target } = instruction.flow else {
            continue;
        };
        if r0_holds_seed(cfg, pc, seed) {
            helpers.push((pc, target));
        }
    }
    match helpers.as_slice() {
        [] => Ok(None),
        [(_, target)] => Ok(Some(*target)),
        _ => Err(SsNameError::Ambiguous {
            values: helpers.iter().map(|(pc, _)| *pc).collect(),
        }),
    }
}

fn writes_r0(instruction: &DecodedInstruction) -> bool {
    match &instruction.effect {
        ValueEffect::RegisterWrite { dst, .. }
        | ValueEffect::LiteralWordLoad { dst, .. }
        | ValueEffect::Shift { dst, .. } => *dst == Register(0),
        _ => instruction.writes.contains(&Register(0)),
    }
}

fn r0_holds_seed(cfg: &SemanticCfg, pc: u32, seed: u32) -> bool {
    cfg.exact_register_states()
        .get(&pc)
        .and_then(|state| state.get(Register(0)))
        .is_some_and(|value| value.value == seed)
}

fn validate_helper(
    runtime: &RuntimeImage<'_>,
    target: u32,
    isa: DecodeIsa,
) -> Result<u32, SsNameError> {
    if target & 1 == 1 {
        if isa != DecodeIsa::Thumb {
            return Err(SsNameError::Malformed {
                context: "ARM/Thumb alias of one address".into(),
            });
        }
        let pc = target & !1;
        decode_helper_instruction(runtime, pc, isa)?;
        return Ok(pc);
    }
    decode_helper_instruction(runtime, target, isa)?;
    Ok(target)
}

fn decode_helper_instruction(
    runtime: &RuntimeImage<'_>,
    pc: u32,
    isa: DecodeIsa,
) -> Result<(), SsNameError> {
    let aligned = match isa {
        DecodeIsa::Arm => pc.is_multiple_of(4),
        DecodeIsa::Thumb => pc.is_multiple_of(2),
    };
    if !aligned {
        return Err(SsNameError::Malformed {
            context: format!("helper {pc:#010x} is not aligned for {isa:?}"),
        });
    }
    let bytes = match runtime.read_exact(pc, 4) {
        Ok(bytes) => bytes,
        Err(_) if isa == DecodeIsa::Thumb => {
            runtime
                .read_exact(pc, 2)
                .map_err(|error| SsNameError::Runtime {
                    address: pc,
                    size: 2,
                    reason: error.to_string(),
                })?
        }
        Err(error) => {
            return Err(SsNameError::Runtime {
                address: pc,
                size: 4,
                reason: error.to_string(),
            });
        }
    };
    let decoded = match isa {
        DecodeIsa::Arm => decode_a32(pc, bytes.as_ref()),
        DecodeIsa::Thumb => {
            let mut it = ItRangeState::default();
            decode_t32(&mut it, pc, bytes.as_ref())
        }
    };
    decoded.map(|_| ()).map_err(|error| SsNameError::Decode {
        pc,
        isa,
        reason: error.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::{SEED, SsContainer, SsNameError, SsOutcome, discover, prove_helper};
    use crate::execution_ranges::DecodeIsa;
    use crate::runtime_image::RuntimeImage;
    use std::collections::HashSet;

    const BASE: u32 = 0x4001_0000;
    const A32_ADD_R0_PC_24: [u8; 4] = [0x18, 0x00, 0x8f, 0xe2];
    const A32_BX_LR: [u8; 4] = [0x1e, 0xff, 0x2f, 0xe1];
    const A32_MOV_R0_1: [u8; 4] = [0x01, 0x00, 0xa0, 0xe3];
    const A32_SVC_1: [u8; 4] = [0x01, 0x00, 0x00, 0xef];

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

    fn plant_seed(image: &mut [u8], offset: usize) {
        image[offset..offset + SEED.len()].copy_from_slice(SEED);
        image[offset + SEED.len()] = 0;
    }

    fn adr_r0_bl_image() -> Vec<u8> {
        let mut image = vec![0u8; 0x80];
        image[0..4].copy_from_slice(&A32_ADD_R0_PC_24);
        image[4..8].copy_from_slice(&0xeb00000du32.to_le_bytes());
        image[8..12].copy_from_slice(&A32_BX_LR);
        plant_seed(&mut image, 32);
        image[0x40..0x44].copy_from_slice(&A32_BX_LR);
        image
    }

    #[test]
    fn unique_seed_adr_r0_bl_proves_helper() {
        let image = adr_r0_bl_image();
        let runtime = RuntimeImage::from_plan(&image, BASE, None).unwrap();
        match prove_helper(&runtime) {
            SsOutcome::Present(plan) => {
                assert_eq!(plan.helper_entry, BASE + 0x40);
                assert_eq!(plan.helper_isa, DecodeIsa::Arm);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn missing_seed_is_absent() {
        let image = vec![0u8; 0x80];
        let runtime = RuntimeImage::from_plan(&image, BASE, None).unwrap();
        assert_eq!(prove_helper(&runtime), SsOutcome::Absent);
    }

    #[test]
    fn duplicate_seed_is_ambiguous() {
        let mut image = vec![0u8; 0x80];
        plant_seed(&mut image, 32);
        plant_seed(&mut image, 64);
        let runtime = RuntimeImage::from_plan(&image, BASE, None).unwrap();
        match prove_helper(&runtime) {
            SsOutcome::Failed(SsNameError::Ambiguous { values }) => {
                assert_eq!(values, vec![BASE + 32, BASE + 64]);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn movw_movt_linear_pair_proves_helper() {
        let mut image = vec![0u8; 0x80];
        let string_start = BASE + 32;
        image[0..4].copy_from_slice(&a32_movw(0, (string_start & 0xffff) as u16));
        image[4..8].copy_from_slice(&a32_movt(0, (string_start >> 16) as u16));
        image[8..12].copy_from_slice(&0xeb00000cu32.to_le_bytes());
        image[12..16].copy_from_slice(&A32_BX_LR);
        plant_seed(&mut image, 32);
        image[0x40..0x44].copy_from_slice(&A32_BX_LR);
        let runtime = RuntimeImage::from_plan(&image, BASE, None).unwrap();
        match prove_helper(&runtime) {
            SsOutcome::Present(plan) => {
                assert_eq!(plan.helper_entry, BASE + 0x40);
                assert_eq!(plan.helper_isa, DecodeIsa::Arm);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn svc_between_movw_and_movt_is_not_a_ref() {
        let mut image = vec![0u8; 0x80];
        let string_start = BASE + 32;
        image[0..4].copy_from_slice(&a32_movw(0, (string_start & 0xffff) as u16));
        image[4..8].copy_from_slice(&A32_SVC_1);
        image[8..12].copy_from_slice(&a32_movt(0, (string_start >> 16) as u16));
        image[12..16].copy_from_slice(&A32_BX_LR);
        plant_seed(&mut image, 32);
        let runtime = RuntimeImage::from_plan(&image, BASE, None).unwrap();
        assert_eq!(prove_helper(&runtime), SsOutcome::Absent);
    }

    #[test]
    fn intervening_r0_write_before_bl_is_absent() {
        let mut image = vec![0u8; 0x80];
        image[0..4].copy_from_slice(&A32_ADD_R0_PC_24);
        image[4..8].copy_from_slice(&A32_MOV_R0_1);
        image[8..12].copy_from_slice(&0xeb00000cu32.to_le_bytes());
        image[12..16].copy_from_slice(&A32_BX_LR);
        plant_seed(&mut image, 32);
        image[0x40..0x44].copy_from_slice(&A32_BX_LR);
        let runtime = RuntimeImage::from_plan(&image, BASE, None).unwrap();
        assert_eq!(prove_helper(&runtime), SsOutcome::Absent);
    }

    #[test]
    fn two_consuming_bls_are_ambiguous() {
        let mut image = vec![0u8; 0x80];
        image[0..4].copy_from_slice(&A32_ADD_R0_PC_24);
        image[4..8].copy_from_slice(&0x0a000001u32.to_le_bytes());
        image[8..12].copy_from_slice(&0xeb00000cu32.to_le_bytes());
        image[12..16].copy_from_slice(&0xea000000u32.to_le_bytes());
        image[16..20].copy_from_slice(&0xeb000006u32.to_le_bytes());
        image[20..24].copy_from_slice(&A32_BX_LR);
        plant_seed(&mut image, 32);
        image[0x40..0x44].copy_from_slice(&A32_BX_LR);
        let runtime = RuntimeImage::from_plan(&image, BASE, None).unwrap();
        match prove_helper(&runtime) {
            SsOutcome::Failed(SsNameError::Ambiguous { values }) => {
                assert_eq!(values.len(), 2);
            }
            other => panic!("{other:?}"),
        }
    }

    fn a32_bl(pc: u32, target: u32) -> [u8; 4] {
        let imm24 = target.wrapping_sub(pc.wrapping_add(8)) / 4;
        (0xeb00_0000 | (imm24 & 0x00ff_ffff)).to_le_bytes()
    }

    fn plant_cstr(image: &mut [u8], offset: usize, bytes: &[u8]) {
        image[offset..offset + bytes.len()].copy_from_slice(bytes);
        image[offset + bytes.len()] = 0;
    }

    fn foo_callsite_image(name: &[u8]) -> Vec<u8> {
        let mut image = adr_r0_bl_image();
        image[0x50..0x54].copy_from_slice(&A32_ADD_R0_PC_24);
        image[0x54..0x58].copy_from_slice(&a32_bl(0x54, 0x40));
        image[0x58..0x5c].copy_from_slice(&A32_BX_LR);
        plant_cstr(&mut image, 0x70, name);
        image
    }

    fn seed_container() -> SsContainer {
        SsContainer {
            entry: BASE,
            isa: DecodeIsa::Arm,
            ranges: vec![(BASE, BASE + 0x10)],
            ghidra: true,
        }
    }

    fn foo_container() -> SsContainer {
        SsContainer {
            entry: BASE + 0x50,
            isa: DecodeIsa::Arm,
            ranges: vec![(BASE + 0x50, BASE + 0x60)],
            ghidra: true,
        }
    }

    fn discover_names(
        image: &[u8],
        containers: &[SsContainer],
        globals: &HashSet<String>,
        fn_names: &HashSet<String>,
    ) -> super::SsPlan {
        let runtime = RuntimeImage::from_plan(image, BASE, None).unwrap();
        match discover(&runtime, containers, globals, fn_names) {
            SsOutcome::Present(plan) => plan,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn callsite_names_containing_function() {
        let image = foo_callsite_image(b"ss_Foo");
        let containers = [seed_container(), foo_container()];
        let plan = discover_names(&image, &containers, &HashSet::new(), &HashSet::new());
        assert_eq!(plan.helper_entry, BASE + 0x40);
        assert_eq!(plan.helper_isa, DecodeIsa::Arm);
        assert_eq!(
            plan.names
                .get(&(BASE + 0x50, DecodeIsa::Arm))
                .map(String::as_str),
            Some("ss_Foo")
        );
    }

    #[test]
    fn duplicate_name_is_conflict_not_recovered() {
        let mut image = foo_callsite_image(b"ss_Foo");
        image.resize(0xc0, 0);
        image[0x80..0x84].copy_from_slice(&[0x08, 0x00, 0x8f, 0xe2]);
        image[0x84..0x88].copy_from_slice(&a32_bl(0x84, 0x40));
        image[0x88..0x8c].copy_from_slice(&A32_BX_LR);
        plant_cstr(&mut image, 0x90, b"ss_Foo");
        let second = SsContainer {
            entry: BASE + 0x80,
            isa: DecodeIsa::Arm,
            ranges: vec![(BASE + 0x80, BASE + 0x90)],
            ghidra: true,
        };
        let containers = [seed_container(), foo_container(), second];
        let plan = discover_names(&image, &containers, &HashSet::new(), &HashSet::new());
        assert!(!plan.names.values().any(|name| name == "ss_Foo"));
        assert!(plan.conflicts >= 2);
    }

    #[test]
    fn non_ss_prefix_is_dropped() {
        let image = foo_callsite_image(b"Foo");
        let containers = [seed_container(), foo_container()];
        let plan = discover_names(&image, &containers, &HashSet::new(), &HashSet::new());
        assert!(!plan.names.contains_key(&(BASE + 0x50, DecodeIsa::Arm)));
    }

    #[test]
    fn name_in_fn_names_is_dropped() {
        let image = foo_callsite_image(b"ss_Foo");
        let containers = [seed_container(), foo_container()];
        let fn_names = HashSet::from(["ss_Foo".to_string()]);
        let plan = discover_names(&image, &containers, &HashSet::new(), &fn_names);
        assert!(!plan.names.contains_key(&(BASE + 0x50, DecodeIsa::Arm)));
    }

    #[test]
    fn missing_container_skips_callsite() {
        let image = foo_callsite_image(b"ss_Foo");
        let containers = [seed_container()];
        let plan = discover_names(&image, &containers, &HashSet::new(), &HashSet::new());
        assert!(!plan.names.contains_key(&(BASE + 0x50, DecodeIsa::Arm)));
    }

    #[test]
    fn proven_helper_without_valid_callsite_names_is_present_empty() {
        let image = adr_r0_bl_image();
        let plan = discover_names(&image, &[], &HashSet::new(), &HashSet::new());
        assert_eq!(plan.helper_entry, BASE + 0x40);
        assert!(plan.names.is_empty());
    }

    #[test]
    fn ghidra_preferred_over_thumb_at_same_entry() {
        let image = foo_callsite_image(b"ss_Foo");
        let thumb = SsContainer {
            ghidra: false,
            ..foo_container()
        };
        let containers = [seed_container(), thumb, foo_container()];
        let plan = discover_names(&image, &containers, &HashSet::new(), &HashSet::new());
        assert_eq!(
            plan.names
                .get(&(BASE + 0x50, DecodeIsa::Arm))
                .map(String::as_str),
            Some("ss_Foo")
        );
    }
}
