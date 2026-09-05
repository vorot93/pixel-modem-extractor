#![cfg_attr(not(test), allow(dead_code))]

use crate::arm32::{
    ControlFlow, DecodedInstruction, ItRangeState, Register, ValueEffect, decode_a32, decode_t32,
};
use crate::execution_ranges::DecodeIsa;
use crate::pal_messages::{PalMessageError, SemanticRef, find_unique_seed, semantic_refs};
use crate::runtime_image::RuntimeImage;
use crate::semantic_cfg::{CallPolicy, CfgLimits, SemanticCfg, SemanticCfgError};
use std::collections::BTreeMap;
use std::fmt;

pub(crate) const SEED: &[u8] = b"ss_DecodeGmmFacilityMsg";
#[allow(dead_code)]
pub(crate) const MAX_CSTRING_BYTES: usize = 128;
#[allow(dead_code)]
pub(crate) const MAX_SS_CALLSITES: usize = 4096;
#[allow(dead_code)]
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

#[allow(dead_code)]
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
    use super::{SEED, SsNameError, SsOutcome, prove_helper};
    use crate::execution_ranges::DecodeIsa;
    use crate::runtime_image::RuntimeImage;

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
}
