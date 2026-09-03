// Shared project-owned A32/T32 one-instruction decoder semantics over
// `scaleservers-arm32-assembly` 1.0.0. This module owns the architecture
// model (registers, operands, memory transfers, value/flag effects, branch
// predicates, control flow) and the single-instruction decoder; range
// orchestration and reachability stay with consumers such as
// `global_shapes::decoder`.
#![allow(clippy::too_many_arguments)]

use crate::execution_ranges::DecodeIsa as Isa;
use scaleservers_arm32_assembly::{
    Arm32BlockAddressMode, Arm32Condition, Arm32GeneralPurposeRegister, Arm32IndexMode,
    Arm32LowGeneralPurposeRegister, Arm32MemoryOffset, Arm32MemoryOffset8, Arm32RegisterShift,
    ArmA32Instruction, ArmT32Instruction,
};
use std::collections::BTreeSet;
use std::fmt;

const DECODER_CRATE: &str = "scaleservers-arm32-assembly";
const DECODER_VERSION: &str = "1.0.0";
const PC: Register = Register(15);
const LR: Register = Register(14);
const SP: Register = Register(13);
const CORE_REGISTER_COUNT: u8 = 16;

/// The visible PC value a PC-relative expression resolves against: Thumb
/// ADR/LDR-literal forms align to four, while A32 PC-relative operands read
/// PC as instruction-plus-eight.
pub(crate) fn visible_pc(pc: u32, align_to_four: bool) -> u32 {
    if align_to_four {
        pc.wrapping_add(4) & !3
    } else {
        pc.wrapping_add(8)
    }
}

/// Wrapping add of an i64 offset onto a u32 address: exact modular
/// arithmetic through the low 32 bits for any offset magnitude.
pub(crate) fn wrapping_offset(address: u32, offset: i64) -> u32 {
    address.wrapping_add((offset & 0xFFFF_FFFF) as u32)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Register(pub(crate) u8);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SystemDirection {
    Read,
    Write,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CoprocessorTransfer {
    pub direction: SystemDirection,
    pub coprocessor: u8,
    pub opcode1: u8,
    pub rt: Register,
    pub crn: u8,
    pub crm: u8,
    pub opcode2: u8,
    pub unconditional_extension: bool,
}

impl CoprocessorTransfer {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn is_vbar_write(self) -> bool {
        self.direction == SystemDirection::Write
            && !self.unconditional_extension
            && self.coprocessor == 15
            && self.opcode1 == 0
            && self.crn == 12
            && self.crm == 0
            && self.opcode2 == 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SystemEffect {
    None,
    CoprocessorTransfer(CoprocessorTransfer),
    PsrTransfer {
        direction: SystemDirection,
        register: Option<Register>,
        mask: u8,
        immediate: Option<u32>,
    },
}

impl SystemEffect {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const fn transfer(self) -> Option<CoprocessorTransfer> {
        match self {
            Self::None | Self::PsrTransfer { .. } => None,
            Self::CoprocessorTransfer(transfer) => Some(transfer),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Shift {
    Lsl(u8),
    Lsr(u8),
    Asr(u8),
    Ror(u8),
    Rrx,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Operand {
    Immediate(u32),
    Register { register: Register, shift: Shift },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AddressBase {
    Register(Register),
    ArchitecturalPc { align_to_four: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AddressOffset {
    Immediate(i64),
    Register {
        register: Register,
        subtract: bool,
        shift: Shift,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AddressExpr {
    pub base: AddressBase,
    pub offset: AddressOffset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ValueExpr {
    Immediate(u32),
    Register(Register),
    ReplaceHighHalf { source: Register, high: u16 },
    Add { left: Register, right: Operand },
    Sub { left: Register, right: Operand },
    ArchitecturalPc { addend: i64, align_to_four: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum AccessKind {
    Read,
    Write,
    ReadWrite,
}

/// One modeled memory transfer. `value` is the explicit data register: the
/// destination a load fills, or the source a store sends across the bus
/// (for a swap it is the loaded destination; the stored source stays in
/// `reads`). Writeback-only effects have no transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MemoryTransfer {
    pub address: AddressExpr,
    pub kind: AccessKind,
    pub width: u8,
    pub value: Option<Register>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MemoryEffect {
    pub transfers: Vec<MemoryTransfer>,
    pub writeback: Option<(Register, AddressExpr)>,
}

/// The compare operation defining NZCV for `ValueEffect::Compare` /
/// `FlagEffect::Written(FlagWriter::Compare)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompareOp {
    Subtract,
    Add,
    And,
    ExclusiveOr,
}

/// Data effect of one decoded instruction. `Compare` reads its operands and
/// writes only NZCV (see `flags`); `Shift` is the logical-shift family with
/// destination, source, kind, and decoded amount preserved. `Unsupported`
/// means the architecture-level effect is not modeled; consumers treat it
/// as an explicit proof barrier for value questions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ValueEffect {
    None,
    RegisterWrite {
        dst: Register,
        value: ValueExpr,
    },
    Shift {
        dst: Register,
        source: Register,
        shift: Shift,
    },
    LiteralWordLoad {
        dst: Register,
        address: AddressExpr,
    },
    Memory(MemoryEffect),
    Compare {
        operation: CompareOp,
        left: Register,
        right: Operand,
    },
    Unsupported,
}

/// Which flag definition an NZCV write carries. `FlagWriter::Compare`
/// refers to this instruction's own `ValueEffect::Compare` operands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlagWriter {
    Compare,
}

/// Architectural NZCV effect of one decoded instruction. `Written` names a
/// modeled definition, `Preserved` leaves NZCV untouched, and `Clobbered`
/// covers flag writes without a modeled definition (S-form data processing
/// and every unsupported encoding, conservatively).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlagEffect {
    Preserved,
    Written(FlagWriter),
    Clobbered,
}

/// Why a direct branch transfers, preserving the architectural condition
/// code or the register-zero test with `CBZ`/`CBNZ` polarity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BranchPredicate {
    Always,
    Condition(Arm32Condition),
    RegisterZero { register: Register, nonzero: bool },
}

/// Total control classification of one decoded instruction, computed before
/// value mapping. `Barrier` covers every transfer that static decoding
/// cannot resolve: any R15 write outside the modeled branch/call forms,
/// indirect transfers (`bx rN`, `blx rN`, table and LOB branches), and
/// unsupported stops; `links_lr` on the instruction records the call forms
/// among them that still write the return address into LR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ControlFlow {
    Linear,
    DirectBranch {
        target: u32,
        fallthrough: Option<u32>,
        predicate: BranchPredicate,
    },
    DirectCall {
        target: u32,
    },
    ExceptionCall,
    Return,
    Barrier,
}

/// The AAPCS/ShannonOS call-boundary contract: R0-R3, R12, and LR become
/// unknown and NZCV becomes unknown, while R4-R11 (including the
/// ShannonOS platform register R9) and SP survive. Applied identically at
/// both call boundaries (caller and callee view).
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CallBoundary {
    pub volatile: BTreeSet<Register>,
    pub flags_unknown: bool,
}

impl ControlFlow {
    /// The call-boundary contract when this flow is a call: direct calls,
    /// returning exception calls, and linked barriers (indirect `blx`).
    /// Returns `None` for non-call flows.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn call_boundary(&self, links_lr: bool) -> Option<CallBoundary> {
        fn aapcs_boundary() -> CallBoundary {
            CallBoundary {
                volatile: BTreeSet::from([
                    Register(0),
                    Register(1),
                    Register(2),
                    Register(3),
                    Register(12),
                    LR,
                ]),
                flags_unknown: true,
            }
        }
        match self {
            ControlFlow::DirectCall { .. } | ControlFlow::ExceptionCall => Some(aapcs_boundary()),
            ControlFlow::Barrier if links_lr => Some(aapcs_boundary()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DecodedInstruction {
    pub isa: Isa,
    pub pc: u32,
    pub length: u8,
    pub conditional: bool,
    /// True when this instruction architecturally writes the return address
    /// into LR (`bl`, `blx` immediate/register, `blxns`).
    pub links_lr: bool,
    pub reads: BTreeSet<Register>,
    pub writes: BTreeSet<Register>,
    pub effect: ValueEffect,
    pub system: SystemEffect,
    pub flags: FlagEffect,
    pub flow: ControlFlow,
}

impl DecodedInstruction {
    fn with_flags(mut self, flags: FlagEffect) -> Self {
        self.flags = flags;
        self
    }

    /// Mark an S-bit (flag-setting) data-processing form: NZCV is written
    /// without a modeled definition. Compare forms set `Written` directly
    /// through their effect.
    fn with_flag_write(self, set_flags: bool) -> Self {
        if set_flags {
            self.with_flags(FlagEffect::Clobbered)
        } else {
            self
        }
    }

    fn with_link(mut self) -> Self {
        self.links_lr = true;
        self
    }

    fn with_system(mut self, system: SystemEffect) -> Self {
        self.system = system;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DecodeError {
    pub message: String,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DecodeError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DecoderIdentity {
    pub crate_name: &'static str,
    pub version: &'static str,
}

pub(crate) trait InstructionDecoder {
    type RangeState;

    fn identity(&self) -> DecoderIdentity;
    fn begin_range(&self, isa: Isa) -> Self::RangeState;
    fn decode_one(
        &self,
        state: &mut Self::RangeState,
        isa: Isa,
        pc: u32,
        bytes: &[u8],
    ) -> std::result::Result<DecodedInstruction, DecodeError>;
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ItRangeState {
    remaining: u8,
}

impl ItRangeState {
    /// Whether an IT block is currently open in this range state.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn is_open(&self) -> bool {
        self.remaining != 0
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct PureRustDecoder;

impl InstructionDecoder for PureRustDecoder {
    type RangeState = ItRangeState;

    fn identity(&self) -> DecoderIdentity {
        DecoderIdentity {
            crate_name: DECODER_CRATE,
            version: DECODER_VERSION,
        }
    }

    fn begin_range(&self, _isa: Isa) -> Self::RangeState {
        ItRangeState { remaining: 0 }
    }

    fn decode_one(
        &self,
        state: &mut Self::RangeState,
        isa: Isa,
        pc: u32,
        bytes: &[u8],
    ) -> std::result::Result<DecodedInstruction, DecodeError> {
        match isa {
            Isa::Arm => decode_a32(pc, bytes),
            Isa::Thumb => decode_t32(state, pc, bytes),
        }
    }
}

pub(crate) fn decode_a32(
    pc: u32,
    bytes: &[u8],
) -> std::result::Result<DecodedInstruction, DecodeError> {
    let mut offset = 0usize;
    let decoded = ArmA32Instruction::decode(&mut bytes.iter(), &mut offset);
    let inst = take_decoded(Isa::Arm, offset, bytes.len(), decoded)?;
    Ok(finish(map_a32(pc, offset as u8, &inst)))
}

pub(crate) fn decode_t32(
    state: &mut ItRangeState,
    pc: u32,
    bytes: &[u8],
) -> std::result::Result<DecodedInstruction, DecodeError> {
    let mut offset = 0usize;
    let decoded = ArmT32Instruction::decode(&mut bytes.iter(), &mut offset);
    let inst = take_decoded(Isa::Thumb, offset, bytes.len(), decoded)?;
    if let ArmT32Instruction::It_T1(cond, mask) = &inst {
        if state.remaining != 0 {
            return Err(decode_err("IT while previous IT block is still open"));
        }
        if !it_condition_is_safe(*cond) {
            return Err(decode_err("IT condition cannot be exposed safely"));
        }
        let remaining =
            it_remaining(*mask).ok_or_else(|| decode_err("IT mask cannot be exposed safely"))?;
        state.remaining = remaining;
        return Ok(finish(map_t32(pc, offset as u8, &inst)));
    }
    let mut instruction = finish(map_t32(pc, offset as u8, &inst));
    if state.remaining > 0 {
        instruction.conditional = true;
        state.remaining -= 1;
    }
    Ok(instruction)
}

fn take_decoded<T>(
    isa: Isa,
    offset: usize,
    available: usize,
    decoded: std::result::Result<Option<T>, scaleservers_arm32_assembly::DecodeError>,
) -> std::result::Result<T, DecodeError> {
    match decoded {
        Ok(Some(inst)) => {
            let length = u8::try_from(offset)
                .map_err(|_| decode_err("decoder consumed a length that does not fit u8"))?;
            if offset == 0 || offset > available || !valid_isa_length(isa, length) {
                return Err(decode_err("decoder consumed an invalid instruction length"));
            }
            Ok(inst)
        }
        Ok(None) => Err(decode_err("empty input")),
        Err(scaleservers_arm32_assembly::DecodeError::IncompleteInstruction) => {
            Err(decode_err("truncated encoding"))
        }
        Err(scaleservers_arm32_assembly::DecodeError::InvalidOpcode) => {
            Err(decode_err("unrecognized encoding"))
        }
    }
}

pub(crate) fn valid_isa_length(isa: Isa, length: u8) -> bool {
    match isa {
        Isa::Arm => length == 4,
        Isa::Thumb => length == 2 || length == 4,
    }
}

fn it_remaining(mask: u8) -> Option<u8> {
    if mask == 0 || mask > 0b1111 {
        return None;
    }
    Some(4 - u8::try_from(mask.trailing_zeros()).unwrap_or(4))
}

fn it_condition_is_safe(cond: Arm32Condition) -> bool {
    !matches!(
        cond,
        Arm32Condition::AlwaysUnconditional | Arm32Condition::Undefined(_)
    )
}

fn finish(mut instruction: DecodedInstruction) -> DecodedInstruction {
    // Total R15 classification, applied before value mapping: any otherwise
    // linear instruction that writes the program counter is a no-successor
    // barrier, even when its value or memory effect stays fully modeled.
    if instruction.writes.contains(&PC) && matches!(instruction.flow, ControlFlow::Linear) {
        instruction.flow = ControlFlow::Barrier;
    }
    if matches!(instruction.effect, ValueEffect::None) && !instruction.writes.is_empty() {
        instruction.effect = ValueEffect::Unsupported;
        if matches!(instruction.flags, FlagEffect::Preserved) {
            instruction.flags = FlagEffect::Clobbered;
        }
    }
    instruction
}

fn decode_err(message: &str) -> DecodeError {
    DecodeError {
        message: message.to_owned(),
    }
}

fn gpr(reg: Arm32GeneralPurposeRegister) -> Register {
    Register(reg.as_operand_bits())
}

fn system_transfer(
    direction: SystemDirection,
    coprocessor: u8,
    opcode1: u8,
    rt: Arm32GeneralPurposeRegister,
    crn: u8,
    crm: u8,
    opcode2: u8,
    unconditional_extension: bool,
) -> SystemEffect {
    SystemEffect::CoprocessorTransfer(CoprocessorTransfer {
        direction,
        coprocessor,
        opcode1,
        rt: gpr(rt),
        crn,
        crm,
        opcode2,
        unconditional_extension,
    })
}

fn low_reg(reg: Arm32LowGeneralPurposeRegister) -> Register {
    Register(reg.as_operand_bits())
}

fn low_to_gpr(reg: Arm32LowGeneralPurposeRegister) -> Arm32GeneralPurposeRegister {
    Arm32GeneralPurposeRegister::from_operand_bits(reg.as_operand_bits())
}

fn is_pc(reg: Arm32GeneralPurposeRegister) -> bool {
    reg == Arm32GeneralPurposeRegister::R15
}

fn pair_reg(rt: Register) -> Option<Register> {
    rt.0.checked_add(1)
        .filter(|number| *number < CORE_REGISTER_COUNT)
        .map(Register)
}

fn map_shift(shift: Arm32RegisterShift) -> Shift {
    match shift {
        Arm32RegisterShift::Lsl(amount) => Shift::Lsl(amount),
        Arm32RegisterShift::Lsr(amount) => Shift::Lsr(amount),
        Arm32RegisterShift::Asr(amount) => Shift::Asr(amount),
        Arm32RegisterShift::Ror(amount) => Shift::Ror(amount),
        Arm32RegisterShift::Rrx => Shift::Rrx,
    }
}

fn a32_conditional(cond: Arm32Condition) -> bool {
    !matches!(cond, Arm32Condition::AlwaysUnconditional)
}

fn branch_target(isa: Isa, pc: u32, offset: i32) -> u32 {
    let bias = match isa {
        Isa::Arm => 8,
        Isa::Thumb => 4,
    };
    pc.wrapping_add(bias).wrapping_add_signed(offset)
}

fn insn(
    isa: Isa,
    pc: u32,
    length: u8,
    conditional: bool,
    reads: BTreeSet<Register>,
    writes: BTreeSet<Register>,
    effect: ValueEffect,
    flow: ControlFlow,
) -> DecodedInstruction {
    let flags = match &effect {
        ValueEffect::Compare { .. } => FlagEffect::Written(FlagWriter::Compare),
        ValueEffect::Unsupported => FlagEffect::Clobbered,
        _ => FlagEffect::Preserved,
    };
    DecodedInstruction {
        isa,
        pc,
        length,
        conditional,
        links_lr: false,
        reads,
        writes,
        effect,
        system: SystemEffect::None,
        flags,
        flow,
    }
}

fn set<const N: usize>(regs: [Register; N]) -> BTreeSet<Register> {
    BTreeSet::from(regs)
}

fn all_core_registers() -> BTreeSet<Register> {
    (0..CORE_REGISTER_COUNT).map(Register).collect()
}

fn clrm_writes(list: u16) -> BTreeSet<Register> {
    (0u8..15)
        .filter(|bit| list & (1 << bit) != 0)
        .map(Register)
        .collect()
}

fn address(base: AddressBase, offset: AddressOffset) -> AddressExpr {
    AddressExpr { base, offset }
}

fn imm_addr(base: Register, offset: i64) -> AddressExpr {
    address(
        AddressBase::Register(base),
        AddressOffset::Immediate(offset),
    )
}

fn pc_addr(align_to_four: bool, offset: i64) -> AddressExpr {
    address(
        AddressBase::ArchitecturalPc { align_to_four },
        AddressOffset::Immediate(offset),
    )
}

fn memory(
    transfers: Vec<MemoryTransfer>,
    writeback: Option<(Register, AddressExpr)>,
) -> ValueEffect {
    ValueEffect::Memory(MemoryEffect {
        transfers,
        writeback,
    })
}

fn transfer(
    address: AddressExpr,
    kind: AccessKind,
    width: u8,
    value: Option<Register>,
) -> MemoryTransfer {
    MemoryTransfer {
        address,
        kind,
        width,
        value,
    }
}

fn operand_from_shift(register: Register, shift: Arm32RegisterShift) -> Operand {
    Operand::Register {
        register,
        shift: map_shift(shift),
    }
}

fn map_a32(pc: u32, length: u8, inst: &ArmA32Instruction) -> DecodedInstruction {
    match inst {
        ArmA32Instruction::Mov_Immediate_A1(cond, set_flags, rd, imm) => a32_reg_write(
            pc,
            length,
            *cond,
            gpr(*rd),
            ValueExpr::Immediate(*imm),
            BTreeSet::new(),
        )
        .with_flag_write(*set_flags),
        ArmA32Instruction::Movw_A2(cond, rd, imm) => a32_reg_write(
            pc,
            length,
            *cond,
            gpr(*rd),
            ValueExpr::Immediate(u32::from(*imm)),
            BTreeSet::new(),
        ),
        ArmA32Instruction::Movt_A1(cond, rd, imm) => a32_reg_write(
            pc,
            length,
            *cond,
            gpr(*rd),
            ValueExpr::ReplaceHighHalf {
                source: gpr(*rd),
                high: *imm,
            },
            set([gpr(*rd)]),
        ),
        ArmA32Instruction::Mov_Register_A1(cond, set_flags, rd, rm, shift) if shift.is_none() => {
            a32_reg_write(
                pc,
                length,
                *cond,
                gpr(*rd),
                ValueExpr::Register(gpr(*rm)),
                set([gpr(*rm)]),
            )
            .with_flag_write(*set_flags)
        }
        // Shifted register moves are the logical-shift family (LSL/LSR/ASR/
        // ROR/RRX by an immediate amount): destination, source, kind, and
        // decoded amount preserved.
        ArmA32Instruction::Mov_Register_A1(cond, set_flags, rd, rm, shift) => insn(
            Isa::Arm,
            pc,
            length,
            a32_conditional(*cond),
            set([gpr(*rm)]),
            set([gpr(*rd)]),
            ValueEffect::Shift {
                dst: gpr(*rd),
                source: gpr(*rm),
                shift: map_shift(*shift),
            },
            ControlFlow::Linear,
        )
        .with_flag_write(*set_flags),
        ArmA32Instruction::Add_Immediate_A1(cond, set_flags, rd, rn, imm) => {
            a32_add_sub_imm(pc, length, *cond, gpr(*rd), *rn, *imm, false)
                .with_flag_write(*set_flags)
        }
        ArmA32Instruction::Sub_Immediate_A1(cond, set_flags, rd, rn, imm) => {
            a32_add_sub_imm(pc, length, *cond, gpr(*rd), *rn, *imm, true)
                .with_flag_write(*set_flags)
        }
        ArmA32Instruction::Add_Register_A1(cond, set_flags, rd, rn, rm, shift) => {
            a32_add_sub_reg(pc, length, *cond, gpr(*rd), *rn, *rm, *shift, false)
                .with_flag_write(*set_flags)
        }
        ArmA32Instruction::Sub_Register_A1(cond, set_flags, rd, rn, rm, shift) => {
            a32_add_sub_reg(pc, length, *cond, gpr(*rd), *rn, *rm, *shift, true)
                .with_flag_write(*set_flags)
        }
        // Compare-family: NZCV written from the operation on left/right.
        // The register operands keep their decoded shift; register-shifted
        // register amounts stay unsupported (see a32_unsupported).
        ArmA32Instruction::Tst_Immediate_A1(cond, rn, imm) => a32_compare(
            pc,
            length,
            *cond,
            CompareOp::And,
            gpr(*rn),
            Operand::Immediate(*imm),
        ),
        ArmA32Instruction::Teq_Immediate_A1(cond, rn, imm) => a32_compare(
            pc,
            length,
            *cond,
            CompareOp::ExclusiveOr,
            gpr(*rn),
            Operand::Immediate(*imm),
        ),
        ArmA32Instruction::Cmp_Immediate_A1(cond, rn, imm) => a32_compare(
            pc,
            length,
            *cond,
            CompareOp::Subtract,
            gpr(*rn),
            Operand::Immediate(*imm),
        ),
        ArmA32Instruction::Cmn_Immediate_A1(cond, rn, imm) => a32_compare(
            pc,
            length,
            *cond,
            CompareOp::Add,
            gpr(*rn),
            Operand::Immediate(*imm),
        ),
        ArmA32Instruction::Tst_Register_A1(cond, rn, rm, shift) => a32_compare(
            pc,
            length,
            *cond,
            CompareOp::And,
            gpr(*rn),
            operand_from_shift(gpr(*rm), *shift),
        ),
        ArmA32Instruction::Teq_Register_A1(cond, rn, rm, shift) => a32_compare(
            pc,
            length,
            *cond,
            CompareOp::ExclusiveOr,
            gpr(*rn),
            operand_from_shift(gpr(*rm), *shift),
        ),
        ArmA32Instruction::Cmp_Register_A1(cond, rn, rm, shift) => a32_compare(
            pc,
            length,
            *cond,
            CompareOp::Subtract,
            gpr(*rn),
            operand_from_shift(gpr(*rm), *shift),
        ),
        ArmA32Instruction::Cmn_Register_A1(cond, rn, rm, shift) => a32_compare(
            pc,
            length,
            *cond,
            CompareOp::Add,
            gpr(*rn),
            operand_from_shift(gpr(*rm), *shift),
        ),
        ArmA32Instruction::Ldr_A1(cond, rt, rn, offset, index) => {
            a32_load_word(pc, length, *cond, gpr(*rt), *rn, offset, *index)
        }
        ArmA32Instruction::Str_A1(cond, rt, rn, offset, index) => a32_single_mem(
            pc,
            length,
            *cond,
            AccessKind::Write,
            4,
            Some(gpr(*rt)),
            *rn,
            a32_offset(offset),
            *index,
        ),
        ArmA32Instruction::Ldrb_A1(cond, rt, rn, offset, index) => a32_single_mem(
            pc,
            length,
            *cond,
            AccessKind::Read,
            1,
            Some(gpr(*rt)),
            *rn,
            a32_offset(offset),
            *index,
        ),
        ArmA32Instruction::Strb_A1(cond, rt, rn, offset, index) => a32_single_mem(
            pc,
            length,
            *cond,
            AccessKind::Write,
            1,
            Some(gpr(*rt)),
            *rn,
            a32_offset(offset),
            *index,
        ),
        ArmA32Instruction::Ldrh_A1(cond, rt, rn, offset, index) => a32_single_mem(
            pc,
            length,
            *cond,
            AccessKind::Read,
            2,
            Some(gpr(*rt)),
            *rn,
            a32_offset8(offset),
            *index,
        ),
        ArmA32Instruction::Strh_A1(cond, rt, rn, offset, index) => a32_single_mem(
            pc,
            length,
            *cond,
            AccessKind::Write,
            2,
            Some(gpr(*rt)),
            *rn,
            a32_offset8(offset),
            *index,
        ),
        ArmA32Instruction::Ldrsb_A1(cond, rt, rn, offset, index) => a32_single_mem(
            pc,
            length,
            *cond,
            AccessKind::Read,
            1,
            Some(gpr(*rt)),
            *rn,
            a32_offset8(offset),
            *index,
        ),
        ArmA32Instruction::Ldrsh_A1(cond, rt, rn, offset, index) => a32_single_mem(
            pc,
            length,
            *cond,
            AccessKind::Read,
            2,
            Some(gpr(*rt)),
            *rn,
            a32_offset8(offset),
            *index,
        ),
        ArmA32Instruction::Ldrd_A1(cond, rt, rn, offset, index) => a32_dual_mem(
            pc,
            length,
            *cond,
            AccessKind::Read,
            gpr(*rt),
            *rn,
            a32_offset8(offset),
            *index,
        ),
        ArmA32Instruction::Strd_A1(cond, rt, rn, offset, index) => a32_dual_mem(
            pc,
            length,
            *cond,
            AccessKind::Write,
            gpr(*rt),
            *rn,
            a32_offset8(offset),
            *index,
        ),
        ArmA32Instruction::Ldrex_A1(cond, rt, rn) => {
            a32_exclusive_load(pc, length, *cond, gpr(*rt), None, gpr(*rn), 4, 0)
        }
        ArmA32Instruction::Ldrexb_A1(cond, rt, rn) => {
            a32_exclusive_load(pc, length, *cond, gpr(*rt), None, gpr(*rn), 1, 0)
        }
        ArmA32Instruction::Ldrexh_A1(cond, rt, rn) => {
            a32_exclusive_load(pc, length, *cond, gpr(*rt), None, gpr(*rn), 2, 0)
        }
        ArmA32Instruction::Ldrexd_A1(cond, rt, rn) => a32_exclusive_load(
            pc,
            length,
            *cond,
            gpr(*rt),
            pair_reg(gpr(*rt)),
            gpr(*rn),
            8,
            0,
        ),
        ArmA32Instruction::Strex_A1(cond, rd, rt, rn) => {
            a32_exclusive_store(pc, length, *cond, gpr(*rd), gpr(*rt), None, gpr(*rn), 4, 0)
        }
        ArmA32Instruction::Strexb_A1(cond, rd, rt, rn) => {
            a32_exclusive_store(pc, length, *cond, gpr(*rd), gpr(*rt), None, gpr(*rn), 1, 0)
        }
        ArmA32Instruction::Strexh_A1(cond, rd, rt, rn) => {
            a32_exclusive_store(pc, length, *cond, gpr(*rd), gpr(*rt), None, gpr(*rn), 2, 0)
        }
        ArmA32Instruction::Strexd_A1(cond, rd, rt, rn) => a32_exclusive_store(
            pc,
            length,
            *cond,
            gpr(*rd),
            gpr(*rt),
            pair_reg(gpr(*rt)),
            gpr(*rn),
            8,
            0,
        ),
        ArmA32Instruction::Swp_A1(cond, rt, rt2, rn) => {
            a32_swap(pc, length, *cond, gpr(*rt), gpr(*rt2), gpr(*rn), 4)
        }
        ArmA32Instruction::Swpb_A1(cond, rt, rt2, rn) => {
            a32_swap(pc, length, *cond, gpr(*rt), gpr(*rt2), gpr(*rn), 1)
        }
        ArmA32Instruction::Ldm_A1(cond, mode, rn, writeback, user_mode, regs) => a32_block(
            pc,
            length,
            *cond,
            AccessKind::Read,
            *mode,
            gpr(*rn),
            *writeback,
            *user_mode,
            regs.iter().copied().map(gpr).collect(),
        ),
        ArmA32Instruction::Stm_A1(cond, mode, rn, writeback, user_mode, regs) => a32_block(
            pc,
            length,
            *cond,
            AccessKind::Write,
            *mode,
            gpr(*rn),
            *writeback,
            *user_mode,
            regs.iter().copied().map(gpr).collect(),
        ),
        ArmA32Instruction::B_A1(cond, offset) => a32_branch(pc, length, *cond, *offset),
        // Only direct same-ISA `bl` resolves to a target; the call-boundary
        // contract (`ControlFlow::call_boundary`) carries the volatility.
        ArmA32Instruction::Bl_A1(cond, offset) => insn(
            Isa::Arm,
            pc,
            length,
            a32_conditional(*cond),
            BTreeSet::new(),
            BTreeSet::new(),
            ValueEffect::None,
            ControlFlow::DirectCall {
                target: branch_target(Isa::Arm, pc, *offset),
            },
        )
        .with_link(),
        // blx-immediate is a same-encoding-family, cross-ISA (Arm -> Thumb)
        // call. Resolving it stays deferred (see plan handoff note), so the
        // unresolved transfer is a linked barrier.
        ArmA32Instruction::Blx_Immediate_A1(_) => insn(
            Isa::Arm,
            pc,
            length,
            false,
            BTreeSet::new(),
            BTreeSet::new(),
            ValueEffect::None,
            ControlFlow::Barrier,
        )
        .with_link(),
        // blx register: an indirect call — the transfer itself is an
        // unresolved barrier, but LR still receives the return address.
        ArmA32Instruction::Blx_Register_A1(cond, rm) => insn(
            Isa::Arm,
            pc,
            length,
            a32_conditional(*cond),
            set([gpr(*rm)]),
            BTreeSet::new(),
            ValueEffect::None,
            ControlFlow::Barrier,
        )
        .with_link(),
        // `bx lr` is the canonical return; any other register is an
        // unresolved transfer barrier.
        ArmA32Instruction::Bx_A1(cond, rm) => insn(
            Isa::Arm,
            pc,
            length,
            a32_conditional(*cond),
            set([gpr(*rm)]),
            BTreeSet::new(),
            ValueEffect::None,
            if *rm == Arm32GeneralPurposeRegister::R14 {
                ControlFlow::Return
            } else {
                ControlFlow::Barrier
            },
        ),
        ArmA32Instruction::Svc_A1(cond, _) => insn(
            Isa::Arm,
            pc,
            length,
            a32_conditional(*cond),
            BTreeSet::new(),
            BTreeSet::new(),
            ValueEffect::None,
            ControlFlow::ExceptionCall,
        ),
        other => a32_unsupported(pc, length, other),
    }
}

fn map_t32(pc: u32, length: u8, inst: &ArmT32Instruction) -> DecodedInstruction {
    match inst {
        // T1 is the narrow always-flag-setting `movs rd, #imm`.
        ArmT32Instruction::Mov_Immediate_T1(rd, imm) => t32_reg_write(
            pc,
            length,
            low_reg(*rd),
            ValueExpr::Immediate(u32::from(*imm)),
            BTreeSet::new(),
        )
        .with_flag_write(true),
        ArmT32Instruction::Mov_Immediate_T2(rd, imm, set_flags) => t32_reg_write(
            pc,
            length,
            gpr(*rd),
            ValueExpr::Immediate(*imm),
            BTreeSet::new(),
        )
        .with_flag_write(*set_flags),
        ArmT32Instruction::Mov_Immediate_T3(rd, imm) => t32_reg_write(
            pc,
            length,
            gpr(*rd),
            ValueExpr::Immediate(u32::from(*imm)),
            BTreeSet::new(),
        ),
        ArmT32Instruction::Movt_T1(rd, imm) => t32_reg_write(
            pc,
            length,
            gpr(*rd),
            ValueExpr::ReplaceHighHalf {
                source: gpr(*rd),
                high: *imm,
            },
            set([gpr(*rd)]),
        ),
        ArmT32Instruction::Mov_Register_T1(rd, rm) => t32_reg_write(
            pc,
            length,
            gpr(*rd),
            ValueExpr::Register(gpr(*rm)),
            set([gpr(*rm)]),
        ),
        // T2 is the narrow always-flag-setting `movs rd, rm`.
        ArmT32Instruction::Mov_Register_T2(rd, rm) => t32_reg_write(
            pc,
            length,
            low_reg(*rd),
            ValueExpr::Register(low_reg(*rm)),
            set([low_reg(*rm)]),
        )
        .with_flag_write(true),
        ArmT32Instruction::Mov_Register_T3(rd, rm, shift, set_flags) if shift.is_none() => {
            t32_reg_write(
                pc,
                length,
                gpr(*rd),
                ValueExpr::Register(gpr(*rm)),
                set([gpr(*rm)]),
            )
            .with_flag_write(*set_flags)
        }
        // The wide `.w` shift mnemonics (LSL/LSR/ASR/ROR by an immediate
        // amount) decode as MOV_T3 with a shift: destination, source, kind,
        // and decoded amount preserved.
        ArmT32Instruction::Mov_Register_T3(rd, rm, shift, set_flags) => insn(
            Isa::Thumb,
            pc,
            length,
            false,
            set([gpr(*rm)]),
            set([gpr(*rd)]),
            shift_effect(gpr(*rd), gpr(*rm), map_shift(*shift)),
            ControlFlow::Linear,
        )
        .with_flag_write(*set_flags),
        // The narrow shift forms are always flag-setting.
        ArmT32Instruction::Lsl_Immediate_T1(rd, rm, amount) => insn(
            Isa::Thumb,
            pc,
            length,
            false,
            set([low_reg(*rm)]),
            set([low_reg(*rd)]),
            shift_effect(low_reg(*rd), low_reg(*rm), Shift::Lsl(*amount)),
            ControlFlow::Linear,
        )
        .with_flag_write(true),
        ArmT32Instruction::Lsr_Immediate_T1(rd, rm, amount) => insn(
            Isa::Thumb,
            pc,
            length,
            false,
            set([low_reg(*rm)]),
            set([low_reg(*rd)]),
            shift_effect(low_reg(*rd), low_reg(*rm), Shift::Lsr(*amount)),
            ControlFlow::Linear,
        )
        .with_flag_write(true),
        ArmT32Instruction::Asr_Immediate_T1(rd, rm, amount) => insn(
            Isa::Thumb,
            pc,
            length,
            false,
            set([low_reg(*rm)]),
            set([low_reg(*rd)]),
            shift_effect(low_reg(*rd), low_reg(*rm), Shift::Asr(*amount)),
            ControlFlow::Linear,
        )
        .with_flag_write(true),
        // Narrow adds/subs always set flags.
        ArmT32Instruction::Add_Immediate_T1(rd, rn, imm) => t32_add_sub_imm(
            pc,
            length,
            low_reg(*rd),
            low_to_gpr(*rn),
            u32::from(*imm),
            false,
        )
        .with_flag_write(true),
        ArmT32Instruction::Add_Immediate_T2(rdn, imm) => t32_add_sub_imm(
            pc,
            length,
            low_reg(*rdn),
            low_to_gpr(*rdn),
            u32::from(*imm),
            false,
        )
        .with_flag_write(true),
        ArmT32Instruction::Add_Immediate_T3(rd, rn, imm, set_flags) => {
            t32_add_sub_imm(pc, length, gpr(*rd), *rn, *imm, false).with_flag_write(*set_flags)
        }
        ArmT32Instruction::Sub_Immediate_T1(rd, rn, imm) => t32_add_sub_imm(
            pc,
            length,
            low_reg(*rd),
            low_to_gpr(*rn),
            u32::from(*imm),
            true,
        )
        .with_flag_write(true),
        ArmT32Instruction::Sub_Immediate_T2(rdn, imm) => t32_add_sub_imm(
            pc,
            length,
            low_reg(*rdn),
            low_to_gpr(*rdn),
            u32::from(*imm),
            true,
        )
        .with_flag_write(true),
        ArmT32Instruction::Sub_Immediate_T3(rd, rn, imm, set_flags) => {
            t32_add_sub_imm(pc, length, gpr(*rd), *rn, *imm, true).with_flag_write(*set_flags)
        }
        ArmT32Instruction::Add_Register_T1(rd, rn, rm) => t32_add_sub_reg(
            pc,
            length,
            low_reg(*rd),
            low_to_gpr(*rn),
            low_to_gpr(*rm),
            Arm32RegisterShift::none(),
            false,
        )
        .with_flag_write(true),
        ArmT32Instruction::Add_Register_T2(rdn, rm) => t32_add_sub_reg(
            pc,
            length,
            gpr(*rdn),
            *rdn,
            *rm,
            Arm32RegisterShift::none(),
            false,
        ),
        ArmT32Instruction::Add_Register_T3(rd, rn, rm, shift, set_flags) => {
            t32_add_sub_reg(pc, length, gpr(*rd), *rn, *rm, *shift, false)
                .with_flag_write(*set_flags)
        }
        ArmT32Instruction::Sub_Register_T1(rd, rn, rm) => t32_add_sub_reg(
            pc,
            length,
            low_reg(*rd),
            low_to_gpr(*rn),
            low_to_gpr(*rm),
            Arm32RegisterShift::none(),
            true,
        )
        .with_flag_write(true),
        ArmT32Instruction::Sub_Register_T2(rd, rn, rm, shift, set_flags) => {
            t32_add_sub_reg(pc, length, gpr(*rd), *rn, *rm, *shift, true)
                .with_flag_write(*set_flags)
        }
        ArmT32Instruction::Add_SpPlusImmediate_T1(rd, imm) => t32_reg_write(
            pc,
            length,
            low_reg(*rd),
            ValueExpr::Add {
                left: SP,
                right: Operand::Immediate(u32::from(*imm)),
            },
            set([SP]),
        ),
        ArmT32Instruction::Add_SpPlusImmediate_T2(imm) => t32_reg_write(
            pc,
            length,
            SP,
            ValueExpr::Add {
                left: SP,
                right: Operand::Immediate(u32::from(*imm)),
            },
            set([SP]),
        ),
        ArmT32Instruction::Add_SpPlusRegister_T1(rdm) => t32_add_sub_reg(
            pc,
            length,
            gpr(*rdm),
            *rdm,
            Arm32GeneralPurposeRegister::R13,
            Arm32RegisterShift::none(),
            false,
        ),
        ArmT32Instruction::Add_SpPlusRegister_T2(rm) => t32_add_sub_reg(
            pc,
            length,
            SP,
            Arm32GeneralPurposeRegister::R13,
            *rm,
            Arm32RegisterShift::none(),
            false,
        ),
        ArmT32Instruction::Sub_SpMinusImmediate_T1(imm) => t32_reg_write(
            pc,
            length,
            SP,
            ValueExpr::Sub {
                left: SP,
                right: Operand::Immediate(u32::from(*imm)),
            },
            set([SP]),
        ),
        ArmT32Instruction::Adr_T1(rd, imm) => t32_reg_write(
            pc,
            length,
            low_reg(*rd),
            ValueExpr::ArchitecturalPc {
                addend: i64::from(*imm),
                align_to_four: true,
            },
            BTreeSet::new(),
        ),
        ArmT32Instruction::Ldr_Literal_T1(rt, imm) => {
            t32_literal(pc, length, low_reg(*rt), i64::from(*imm))
        }
        ArmT32Instruction::Ldr_Literal_T2(rt, imm) => {
            t32_literal(pc, length, gpr(*rt), i64::from(*imm))
        }
        ArmT32Instruction::Ldr_Immediate_T1(rt, rn, imm) => t32_imm_mem(
            pc,
            length,
            AccessKind::Read,
            4,
            Some(low_reg(*rt)),
            low_to_gpr(*rn),
            i64::from(*imm),
            Arm32IndexMode::Offset,
        ),
        ArmT32Instruction::Ldr_Immediate_T2(rt, imm) => t32_imm_mem(
            pc,
            length,
            AccessKind::Read,
            4,
            Some(low_reg(*rt)),
            Arm32GeneralPurposeRegister::R13,
            i64::from(*imm),
            Arm32IndexMode::Offset,
        ),
        ArmT32Instruction::Ldr_Immediate_T3(rt, rn, imm) => t32_imm_mem(
            pc,
            length,
            AccessKind::Read,
            4,
            Some(gpr(*rt)),
            *rn,
            i64::from(*imm),
            Arm32IndexMode::Offset,
        ),
        ArmT32Instruction::Ldr_Immediate_T4(rt, rn, offset, mode) => t32_imm_mem(
            pc,
            length,
            AccessKind::Read,
            4,
            Some(gpr(*rt)),
            *rn,
            i64::from(*offset),
            *mode,
        ),
        ArmT32Instruction::Str_Immediate_T1(rt, rn, imm) => t32_imm_mem(
            pc,
            length,
            AccessKind::Write,
            4,
            Some(low_reg(*rt)),
            low_to_gpr(*rn),
            i64::from(*imm),
            Arm32IndexMode::Offset,
        ),
        ArmT32Instruction::Str_Immediate_T2(rt, imm) => t32_imm_mem(
            pc,
            length,
            AccessKind::Write,
            4,
            Some(low_reg(*rt)),
            Arm32GeneralPurposeRegister::R13,
            i64::from(*imm),
            Arm32IndexMode::Offset,
        ),
        ArmT32Instruction::Str_Immediate_T3(rt, rn, imm) => t32_imm_mem(
            pc,
            length,
            AccessKind::Write,
            4,
            Some(gpr(*rt)),
            *rn,
            i64::from(*imm),
            Arm32IndexMode::Offset,
        ),
        ArmT32Instruction::Str_Immediate_T4(rt, rn, offset, mode) => t32_imm_mem(
            pc,
            length,
            AccessKind::Write,
            4,
            Some(gpr(*rt)),
            *rn,
            i64::from(*offset),
            *mode,
        ),
        ArmT32Instruction::Ldrb_Immediate_T1(rt, rn, imm) => t32_imm_mem(
            pc,
            length,
            AccessKind::Read,
            1,
            Some(low_reg(*rt)),
            low_to_gpr(*rn),
            i64::from(*imm),
            Arm32IndexMode::Offset,
        ),
        ArmT32Instruction::Ldrb_Immediate_T2(rt, rn, imm) => t32_imm_mem(
            pc,
            length,
            AccessKind::Read,
            1,
            Some(gpr(*rt)),
            *rn,
            i64::from(*imm),
            Arm32IndexMode::Offset,
        ),
        ArmT32Instruction::Ldrb_Immediate_T3(rt, rn, offset, mode) => t32_imm_mem(
            pc,
            length,
            AccessKind::Read,
            1,
            Some(gpr(*rt)),
            *rn,
            i64::from(*offset),
            *mode,
        ),
        ArmT32Instruction::Strb_Immediate_T1(rt, rn, imm) => t32_imm_mem(
            pc,
            length,
            AccessKind::Write,
            1,
            Some(low_reg(*rt)),
            low_to_gpr(*rn),
            i64::from(*imm),
            Arm32IndexMode::Offset,
        ),
        ArmT32Instruction::Strb_Immediate_T2(rt, rn, imm) => t32_imm_mem(
            pc,
            length,
            AccessKind::Write,
            1,
            Some(gpr(*rt)),
            *rn,
            i64::from(*imm),
            Arm32IndexMode::Offset,
        ),
        ArmT32Instruction::Strb_Immediate_T3(rt, rn, offset, mode) => t32_imm_mem(
            pc,
            length,
            AccessKind::Write,
            1,
            Some(gpr(*rt)),
            *rn,
            i64::from(*offset),
            *mode,
        ),
        ArmT32Instruction::Ldrh_Immediate_T1(rt, rn, imm) => t32_imm_mem(
            pc,
            length,
            AccessKind::Read,
            2,
            Some(low_reg(*rt)),
            low_to_gpr(*rn),
            i64::from(*imm),
            Arm32IndexMode::Offset,
        ),
        ArmT32Instruction::Ldrh_Immediate_T2(rt, rn, imm) => t32_imm_mem(
            pc,
            length,
            AccessKind::Read,
            2,
            Some(gpr(*rt)),
            *rn,
            i64::from(*imm),
            Arm32IndexMode::Offset,
        ),
        ArmT32Instruction::Ldrh_Immediate_T3(rt, rn, offset, mode) => t32_imm_mem(
            pc,
            length,
            AccessKind::Read,
            2,
            Some(gpr(*rt)),
            *rn,
            i64::from(*offset),
            *mode,
        ),
        ArmT32Instruction::Strh_Immediate_T1(rt, rn, imm) => t32_imm_mem(
            pc,
            length,
            AccessKind::Write,
            2,
            Some(low_reg(*rt)),
            low_to_gpr(*rn),
            i64::from(*imm),
            Arm32IndexMode::Offset,
        ),
        ArmT32Instruction::Strh_Immediate_T2(rt, rn, imm) => t32_imm_mem(
            pc,
            length,
            AccessKind::Write,
            2,
            Some(gpr(*rt)),
            *rn,
            i64::from(*imm),
            Arm32IndexMode::Offset,
        ),
        ArmT32Instruction::Strh_Immediate_T3(rt, rn, offset, mode) => t32_imm_mem(
            pc,
            length,
            AccessKind::Write,
            2,
            Some(gpr(*rt)),
            *rn,
            i64::from(*offset),
            *mode,
        ),
        ArmT32Instruction::Ldrsb_Immediate_T1(rt, rn, imm) => t32_imm_mem(
            pc,
            length,
            AccessKind::Read,
            1,
            Some(gpr(*rt)),
            *rn,
            i64::from(*imm),
            Arm32IndexMode::Offset,
        ),
        ArmT32Instruction::Ldrsb_Immediate_T2(rt, rn, offset, mode) => t32_imm_mem(
            pc,
            length,
            AccessKind::Read,
            1,
            Some(gpr(*rt)),
            *rn,
            i64::from(*offset),
            *mode,
        ),
        ArmT32Instruction::Ldrsh_Immediate_T1(rt, rn, imm) => t32_imm_mem(
            pc,
            length,
            AccessKind::Read,
            2,
            Some(gpr(*rt)),
            *rn,
            i64::from(*imm),
            Arm32IndexMode::Offset,
        ),
        ArmT32Instruction::Ldrsh_Immediate_T2(rt, rn, offset, mode) => t32_imm_mem(
            pc,
            length,
            AccessKind::Read,
            2,
            Some(gpr(*rt)),
            *rn,
            i64::from(*offset),
            *mode,
        ),
        ArmT32Instruction::Ldrb_Literal_T1(rt, imm) => t32_imm_mem(
            pc,
            length,
            AccessKind::Read,
            1,
            Some(gpr(*rt)),
            Arm32GeneralPurposeRegister::R15,
            i64::from(*imm),
            Arm32IndexMode::Offset,
        ),
        ArmT32Instruction::Ldrh_Literal_T1(rt, imm) => t32_imm_mem(
            pc,
            length,
            AccessKind::Read,
            2,
            Some(gpr(*rt)),
            Arm32GeneralPurposeRegister::R15,
            i64::from(*imm),
            Arm32IndexMode::Offset,
        ),
        ArmT32Instruction::Ldrsb_Literal_T1(rt, imm) => t32_imm_mem(
            pc,
            length,
            AccessKind::Read,
            1,
            Some(gpr(*rt)),
            Arm32GeneralPurposeRegister::R15,
            i64::from(*imm),
            Arm32IndexMode::Offset,
        ),
        ArmT32Instruction::Ldrsh_Literal_T1(rt, imm) => t32_imm_mem(
            pc,
            length,
            AccessKind::Read,
            2,
            Some(gpr(*rt)),
            Arm32GeneralPurposeRegister::R15,
            i64::from(*imm),
            Arm32IndexMode::Offset,
        ),
        ArmT32Instruction::Ldr_Register_T1(rt, rn, rm) => t32_reg_mem(
            pc,
            length,
            AccessKind::Read,
            4,
            Some(low_reg(*rt)),
            low_to_gpr(*rn),
            low_to_gpr(*rm),
            0,
        ),
        ArmT32Instruction::Ldr_Register_T2(rt, rn, rm, lsl) => t32_reg_mem(
            pc,
            length,
            AccessKind::Read,
            4,
            Some(gpr(*rt)),
            *rn,
            *rm,
            *lsl,
        ),
        ArmT32Instruction::Str_Register_T1(rt, rn, rm) => t32_reg_mem(
            pc,
            length,
            AccessKind::Write,
            4,
            Some(low_reg(*rt)),
            low_to_gpr(*rn),
            low_to_gpr(*rm),
            0,
        ),
        ArmT32Instruction::Str_Register_T2(rt, rn, rm, lsl) => t32_reg_mem(
            pc,
            length,
            AccessKind::Write,
            4,
            Some(gpr(*rt)),
            *rn,
            *rm,
            *lsl,
        ),
        ArmT32Instruction::Ldrb_Register_T1(rt, rn, rm) => t32_reg_mem(
            pc,
            length,
            AccessKind::Read,
            1,
            Some(low_reg(*rt)),
            low_to_gpr(*rn),
            low_to_gpr(*rm),
            0,
        ),
        ArmT32Instruction::Ldrb_Register_T2(rt, rn, rm, lsl) => t32_reg_mem(
            pc,
            length,
            AccessKind::Read,
            1,
            Some(gpr(*rt)),
            *rn,
            *rm,
            *lsl,
        ),
        ArmT32Instruction::Strb_Register_T1(rt, rn, rm) => t32_reg_mem(
            pc,
            length,
            AccessKind::Write,
            1,
            Some(low_reg(*rt)),
            low_to_gpr(*rn),
            low_to_gpr(*rm),
            0,
        ),
        ArmT32Instruction::Strb_Register_T2(rt, rn, rm, lsl) => t32_reg_mem(
            pc,
            length,
            AccessKind::Write,
            1,
            Some(gpr(*rt)),
            *rn,
            *rm,
            *lsl,
        ),
        ArmT32Instruction::Ldrh_Register_T1(rt, rn, rm) => t32_reg_mem(
            pc,
            length,
            AccessKind::Read,
            2,
            Some(low_reg(*rt)),
            low_to_gpr(*rn),
            low_to_gpr(*rm),
            0,
        ),
        ArmT32Instruction::Ldrh_Register_T2(rt, rn, rm, lsl) => t32_reg_mem(
            pc,
            length,
            AccessKind::Read,
            2,
            Some(gpr(*rt)),
            *rn,
            *rm,
            *lsl,
        ),
        ArmT32Instruction::Strh_Register_T1(rt, rn, rm) => t32_reg_mem(
            pc,
            length,
            AccessKind::Write,
            2,
            Some(low_reg(*rt)),
            low_to_gpr(*rn),
            low_to_gpr(*rm),
            0,
        ),
        ArmT32Instruction::Strh_Register_T2(rt, rn, rm, lsl) => t32_reg_mem(
            pc,
            length,
            AccessKind::Write,
            2,
            Some(gpr(*rt)),
            *rn,
            *rm,
            *lsl,
        ),
        ArmT32Instruction::Ldrsb_Register_T1(rt, rn, rm) => t32_reg_mem(
            pc,
            length,
            AccessKind::Read,
            1,
            Some(low_reg(*rt)),
            low_to_gpr(*rn),
            low_to_gpr(*rm),
            0,
        ),
        ArmT32Instruction::Ldrsb_Register_T2(rt, rn, rm, lsl) => t32_reg_mem(
            pc,
            length,
            AccessKind::Read,
            1,
            Some(gpr(*rt)),
            *rn,
            *rm,
            *lsl,
        ),
        ArmT32Instruction::Ldrsh_Register_T1(rt, rn, rm) => t32_reg_mem(
            pc,
            length,
            AccessKind::Read,
            2,
            Some(low_reg(*rt)),
            low_to_gpr(*rn),
            low_to_gpr(*rm),
            0,
        ),
        ArmT32Instruction::Ldrsh_Register_T2(rt, rn, rm, lsl) => t32_reg_mem(
            pc,
            length,
            AccessKind::Read,
            2,
            Some(gpr(*rt)),
            *rn,
            *rm,
            *lsl,
        ),
        ArmT32Instruction::Ldrd_Immediate_T1(rt, rt2, rn, offset, mode) => t32_dual_mem(
            pc,
            length,
            AccessKind::Read,
            gpr(*rt),
            gpr(*rt2),
            *rn,
            i64::from(*offset),
            *mode,
        ),
        ArmT32Instruction::Strd_Immediate_T1(rt, rt2, rn, offset, mode) => t32_dual_mem(
            pc,
            length,
            AccessKind::Write,
            gpr(*rt),
            gpr(*rt2),
            *rn,
            i64::from(*offset),
            *mode,
        ),
        ArmT32Instruction::Ldrex_T1(rt, rn, imm) => a32_exclusive_load(
            pc,
            length,
            Arm32Condition::AlwaysUnconditional,
            gpr(*rt),
            None,
            gpr(*rn),
            4,
            i64::from(*imm),
        )
        .with_isa(Isa::Thumb),
        ArmT32Instruction::Ldrexb_T1(rt, rn) => a32_exclusive_load(
            pc,
            length,
            Arm32Condition::AlwaysUnconditional,
            gpr(*rt),
            None,
            gpr(*rn),
            1,
            0,
        )
        .with_isa(Isa::Thumb),
        ArmT32Instruction::Ldrexh_T1(rt, rn) => a32_exclusive_load(
            pc,
            length,
            Arm32Condition::AlwaysUnconditional,
            gpr(*rt),
            None,
            gpr(*rn),
            2,
            0,
        )
        .with_isa(Isa::Thumb),
        ArmT32Instruction::Strex_T1(rd, rt, rn, imm) => a32_exclusive_store(
            pc,
            length,
            Arm32Condition::AlwaysUnconditional,
            gpr(*rd),
            gpr(*rt),
            None,
            gpr(*rn),
            4,
            i64::from(*imm),
        )
        .with_isa(Isa::Thumb),
        ArmT32Instruction::Strexb_T1(rd, rt, rn) => a32_exclusive_store(
            pc,
            length,
            Arm32Condition::AlwaysUnconditional,
            gpr(*rd),
            gpr(*rt),
            None,
            gpr(*rn),
            1,
            0,
        )
        .with_isa(Isa::Thumb),
        ArmT32Instruction::Strexh_T1(rd, rt, rn) => a32_exclusive_store(
            pc,
            length,
            Arm32Condition::AlwaysUnconditional,
            gpr(*rd),
            gpr(*rt),
            None,
            gpr(*rn),
            2,
            0,
        )
        .with_isa(Isa::Thumb),
        ArmT32Instruction::Ldm_T1(rn, regs) => {
            let base = low_reg(*rn);
            let list: Vec<Register> = regs.iter().copied().map(low_reg).collect();
            let writeback = !list.contains(&base);
            t32_block(
                pc,
                length,
                AccessKind::Read,
                Arm32BlockAddressMode::IncrementAfter,
                base,
                writeback,
                list,
            )
        }
        ArmT32Instruction::Stm_T1(rn, regs) => {
            let base = low_reg(*rn);
            let list: Vec<Register> = regs.iter().copied().map(low_reg).collect();
            let writeback = !list.contains(&base);
            t32_block(
                pc,
                length,
                AccessKind::Write,
                Arm32BlockAddressMode::IncrementAfter,
                base,
                writeback,
                list,
            )
        }
        ArmT32Instruction::Ldmia_T2(rn, writeback, regs) => t32_block(
            pc,
            length,
            AccessKind::Read,
            Arm32BlockAddressMode::IncrementAfter,
            gpr(*rn),
            *writeback,
            regs.iter().copied().map(gpr).collect(),
        ),
        ArmT32Instruction::Stmia_T2(rn, writeback, regs) => t32_block(
            pc,
            length,
            AccessKind::Write,
            Arm32BlockAddressMode::IncrementAfter,
            gpr(*rn),
            *writeback,
            regs.iter().copied().map(gpr).collect(),
        ),
        ArmT32Instruction::Ldmdb_T1(rn, writeback, regs) => t32_block(
            pc,
            length,
            AccessKind::Read,
            Arm32BlockAddressMode::DecrementBefore,
            gpr(*rn),
            *writeback,
            regs.iter().copied().map(gpr).collect(),
        ),
        ArmT32Instruction::Stmdb_T1(rn, writeback, regs) => t32_block(
            pc,
            length,
            AccessKind::Write,
            Arm32BlockAddressMode::DecrementBefore,
            gpr(*rn),
            *writeback,
            regs.iter().copied().map(gpr).collect(),
        ),
        ArmT32Instruction::Push_T1(regs) => t32_block(
            pc,
            length,
            AccessKind::Write,
            Arm32BlockAddressMode::DecrementBefore,
            SP,
            true,
            regs.iter().copied().map(gpr).collect(),
        ),
        ArmT32Instruction::Pop_T1(regs) => t32_block(
            pc,
            length,
            AccessKind::Read,
            Arm32BlockAddressMode::IncrementAfter,
            SP,
            true,
            regs.iter().copied().map(gpr).collect(),
        ),
        ArmT32Instruction::B_T1(cond, offset) => t32_branch(
            pc,
            length,
            branch_target(Isa::Thumb, pc, i32::from(*offset)),
            Some(*cond),
        ),
        ArmT32Instruction::B_T2(offset) => t32_branch(
            pc,
            length,
            branch_target(Isa::Thumb, pc, i32::from(*offset)),
            None,
        ),
        ArmT32Instruction::B_T3(cond, offset) => t32_branch(
            pc,
            length,
            branch_target(Isa::Thumb, pc, *offset),
            Some(*cond),
        ),
        ArmT32Instruction::B_T4(offset) => {
            t32_branch(pc, length, branch_target(Isa::Thumb, pc, *offset), None)
        }
        ArmT32Instruction::Cbz_T1(rn, offset) => {
            t32_compare_branch(pc, length, low_reg(*rn), *offset, false)
        }
        ArmT32Instruction::Cbnz_T1(rn, offset) => {
            t32_compare_branch(pc, length, low_reg(*rn), *offset, true)
        }
        ArmT32Instruction::Bl_T1(offset) => insn(
            Isa::Thumb,
            pc,
            length,
            false,
            BTreeSet::new(),
            BTreeSet::new(),
            ValueEffect::None,
            ControlFlow::DirectCall {
                target: branch_target(Isa::Thumb, pc, *offset),
            },
        )
        .with_link(),
        ArmT32Instruction::Blx_Register_T1(rm) => insn(
            Isa::Thumb,
            pc,
            length,
            false,
            set([gpr(*rm)]),
            BTreeSet::new(),
            ValueEffect::None,
            ControlFlow::Barrier,
        )
        .with_link(),
        ArmT32Instruction::Bx_T1(rm) => insn(
            Isa::Thumb,
            pc,
            length,
            false,
            set([gpr(*rm)]),
            BTreeSet::new(),
            ValueEffect::None,
            if *rm == Arm32GeneralPurposeRegister::R14 {
                ControlFlow::Return
            } else {
                ControlFlow::Barrier
            },
        ),
        ArmT32Instruction::Svc_T1(_) => insn(
            Isa::Thumb,
            pc,
            length,
            false,
            BTreeSet::new(),
            BTreeSet::new(),
            ValueEffect::None,
            ControlFlow::ExceptionCall,
        ),
        // Compare family: NZCV written from the operation on left/right.
        ArmT32Instruction::Cmp_Immediate_T1(rn, imm) => t32_compare(
            pc,
            length,
            CompareOp::Subtract,
            low_reg(*rn),
            Operand::Immediate(u32::from(*imm)),
        ),
        ArmT32Instruction::Cmp_Immediate_T2(rn, imm) => t32_compare(
            pc,
            length,
            CompareOp::Subtract,
            gpr(*rn),
            Operand::Immediate(*imm),
        ),
        ArmT32Instruction::Cmn_Immediate_T1(rn, imm) => t32_compare(
            pc,
            length,
            CompareOp::Add,
            gpr(*rn),
            Operand::Immediate(*imm),
        ),
        ArmT32Instruction::Tst_Immediate_T1(rn, imm) => t32_compare(
            pc,
            length,
            CompareOp::And,
            gpr(*rn),
            Operand::Immediate(*imm),
        ),
        ArmT32Instruction::Teq_Immediate_T1(rn, imm) => t32_compare(
            pc,
            length,
            CompareOp::ExclusiveOr,
            gpr(*rn),
            Operand::Immediate(*imm),
        ),
        ArmT32Instruction::Cmp_Register_T1(rn, rm) => t32_compare(
            pc,
            length,
            CompareOp::Subtract,
            low_reg(*rn),
            Operand::Register {
                register: low_reg(*rm),
                shift: Shift::Lsl(0),
            },
        ),
        ArmT32Instruction::Cmn_Register_T1(rn, rm) => t32_compare(
            pc,
            length,
            CompareOp::Add,
            low_reg(*rn),
            Operand::Register {
                register: low_reg(*rm),
                shift: Shift::Lsl(0),
            },
        ),
        ArmT32Instruction::Tst_Register_T1(rn, rm) => t32_compare(
            pc,
            length,
            CompareOp::And,
            low_reg(*rn),
            Operand::Register {
                register: low_reg(*rm),
                shift: Shift::Lsl(0),
            },
        ),
        ArmT32Instruction::Cmp_Register_T2(rn, rm) => t32_compare(
            pc,
            length,
            CompareOp::Subtract,
            gpr(*rn),
            Operand::Register {
                register: gpr(*rm),
                shift: Shift::Lsl(0),
            },
        ),
        ArmT32Instruction::Cmn_Register_T2(rn, rm, shift) => t32_compare(
            pc,
            length,
            CompareOp::Add,
            gpr(*rn),
            operand_from_shift(gpr(*rm), *shift),
        ),
        ArmT32Instruction::Tst_Register_T2(rn, rm, shift) => t32_compare(
            pc,
            length,
            CompareOp::And,
            gpr(*rn),
            operand_from_shift(gpr(*rm), *shift),
        ),
        ArmT32Instruction::Teq_Register_T1(rn, rm, shift) => t32_compare(
            pc,
            length,
            CompareOp::ExclusiveOr,
            gpr(*rn),
            operand_from_shift(gpr(*rm), *shift),
        ),
        ArmT32Instruction::Cmp_Register_T3(rn, rm, shift) => t32_compare(
            pc,
            length,
            CompareOp::Subtract,
            gpr(*rn),
            operand_from_shift(gpr(*rm), *shift),
        ),
        ArmT32Instruction::It_T1(cond, mask) => map_it(pc, length, *cond, *mask),
        other => t32_unsupported(pc, length, other),
    }
}

trait WithIsa {
    fn with_isa(self, isa: Isa) -> Self;
}

impl WithIsa for DecodedInstruction {
    fn with_isa(mut self, isa: Isa) -> Self {
        self.isa = isa;
        self
    }
}

fn compare_effect(operation: CompareOp, left: Register, right: Operand) -> ValueEffect {
    ValueEffect::Compare {
        operation,
        left,
        right,
    }
}

fn compare_reads(left: Register, right: Operand) -> BTreeSet<Register> {
    let mut reads = set([left]);
    if let Operand::Register { register, .. } = right {
        reads.insert(register);
    }
    reads
}

fn a32_compare(
    pc: u32,
    length: u8,
    cond: Arm32Condition,
    operation: CompareOp,
    left: Register,
    right: Operand,
) -> DecodedInstruction {
    insn(
        Isa::Arm,
        pc,
        length,
        a32_conditional(cond),
        compare_reads(left, right),
        BTreeSet::new(),
        compare_effect(operation, left, right),
        ControlFlow::Linear,
    )
}

fn t32_compare(
    pc: u32,
    length: u8,
    operation: CompareOp,
    left: Register,
    right: Operand,
) -> DecodedInstruction {
    insn(
        Isa::Thumb,
        pc,
        length,
        false,
        compare_reads(left, right),
        BTreeSet::new(),
        compare_effect(operation, left, right),
        ControlFlow::Linear,
    )
}

fn shift_effect(dst: Register, source: Register, shift: Shift) -> ValueEffect {
    ValueEffect::Shift { dst, source, shift }
}

fn a32_reg_write(
    pc: u32,
    length: u8,
    cond: Arm32Condition,
    dst: Register,
    value: ValueExpr,
    reads: BTreeSet<Register>,
) -> DecodedInstruction {
    insn(
        Isa::Arm,
        pc,
        length,
        a32_conditional(cond),
        reads,
        set([dst]),
        ValueEffect::RegisterWrite { dst, value },
        ControlFlow::Linear,
    )
}

fn t32_reg_write(
    pc: u32,
    length: u8,
    dst: Register,
    value: ValueExpr,
    reads: BTreeSet<Register>,
) -> DecodedInstruction {
    insn(
        Isa::Thumb,
        pc,
        length,
        false,
        reads,
        set([dst]),
        ValueEffect::RegisterWrite { dst, value },
        ControlFlow::Linear,
    )
}

fn a32_add_sub_imm(
    pc: u32,
    length: u8,
    cond: Arm32Condition,
    dst: Register,
    rn: Arm32GeneralPurposeRegister,
    imm: u32,
    subtract: bool,
) -> DecodedInstruction {
    if is_pc(rn) {
        let addend = if subtract {
            -i64::from(imm)
        } else {
            i64::from(imm)
        };
        return a32_reg_write(
            pc,
            length,
            cond,
            dst,
            ValueExpr::ArchitecturalPc {
                addend,
                align_to_four: false,
            },
            BTreeSet::new(),
        );
    }
    let value = if subtract {
        ValueExpr::Sub {
            left: gpr(rn),
            right: Operand::Immediate(imm),
        }
    } else {
        ValueExpr::Add {
            left: gpr(rn),
            right: Operand::Immediate(imm),
        }
    };
    a32_reg_write(pc, length, cond, dst, value, set([gpr(rn)]))
}

fn a32_add_sub_reg(
    pc: u32,
    length: u8,
    cond: Arm32Condition,
    dst: Register,
    rn: Arm32GeneralPurposeRegister,
    rm: Arm32GeneralPurposeRegister,
    shift: Arm32RegisterShift,
    subtract: bool,
) -> DecodedInstruction {
    if is_pc(rn) || is_pc(rm) {
        return unsupported(
            Isa::Arm,
            pc,
            length,
            a32_conditional(cond),
            set([gpr(rn), gpr(rm)]),
            set([dst]),
            ControlFlow::Linear,
        );
    }
    let right = operand_from_shift(gpr(rm), shift);
    let value = if subtract {
        ValueExpr::Sub {
            left: gpr(rn),
            right,
        }
    } else {
        ValueExpr::Add {
            left: gpr(rn),
            right,
        }
    };
    a32_reg_write(pc, length, cond, dst, value, set([gpr(rn), gpr(rm)]))
}

fn t32_add_sub_imm(
    pc: u32,
    length: u8,
    dst: Register,
    rn: Arm32GeneralPurposeRegister,
    imm: u32,
    subtract: bool,
) -> DecodedInstruction {
    if is_pc(rn) {
        let addend = if subtract {
            -i64::from(imm)
        } else {
            i64::from(imm)
        };
        return t32_reg_write(
            pc,
            length,
            dst,
            ValueExpr::ArchitecturalPc {
                addend,
                align_to_four: true,
            },
            BTreeSet::new(),
        );
    }
    let value = if subtract {
        ValueExpr::Sub {
            left: gpr(rn),
            right: Operand::Immediate(imm),
        }
    } else {
        ValueExpr::Add {
            left: gpr(rn),
            right: Operand::Immediate(imm),
        }
    };
    t32_reg_write(pc, length, dst, value, set([gpr(rn)]))
}

fn t32_add_sub_reg(
    pc: u32,
    length: u8,
    dst: Register,
    rn: Arm32GeneralPurposeRegister,
    rm: Arm32GeneralPurposeRegister,
    shift: Arm32RegisterShift,
    subtract: bool,
) -> DecodedInstruction {
    if is_pc(rn) || is_pc(rm) {
        return unsupported(
            Isa::Thumb,
            pc,
            length,
            false,
            set([gpr(rn), gpr(rm)]),
            set([dst]),
            ControlFlow::Linear,
        );
    }
    let right = operand_from_shift(gpr(rm), shift);
    let value = if subtract {
        ValueExpr::Sub {
            left: gpr(rn),
            right,
        }
    } else {
        ValueExpr::Add {
            left: gpr(rn),
            right,
        }
    };
    t32_reg_write(pc, length, dst, value, set([gpr(rn), gpr(rm)]))
}

fn a32_load_word(
    pc: u32,
    length: u8,
    cond: Arm32Condition,
    rt: Register,
    rn: Arm32GeneralPurposeRegister,
    offset: &Arm32MemoryOffset,
    index: Arm32IndexMode,
) -> DecodedInstruction {
    if is_pc(rn)
        && let Some(imm) = a32_imm_offset(offset)
    {
        return insn(
            Isa::Arm,
            pc,
            length,
            a32_conditional(cond),
            BTreeSet::new(),
            set([rt]),
            ValueEffect::LiteralWordLoad {
                dst: rt,
                address: pc_addr(false, imm),
            },
            ControlFlow::Linear,
        );
    }
    a32_single_mem(
        pc,
        length,
        cond,
        AccessKind::Read,
        4,
        Some(rt),
        rn,
        a32_offset(offset),
        index,
    )
}

fn t32_literal(pc: u32, length: u8, rt: Register, offset: i64) -> DecodedInstruction {
    insn(
        Isa::Thumb,
        pc,
        length,
        false,
        BTreeSet::new(),
        set([rt]),
        ValueEffect::LiteralWordLoad {
            dst: rt,
            address: pc_addr(true, offset),
        },
        ControlFlow::Linear,
    )
}

struct ResolvedOffset {
    offset: AddressOffset,
    extra_read: Option<Register>,
}

fn a32_offset(offset: &Arm32MemoryOffset) -> ResolvedOffset {
    match *offset {
        Arm32MemoryOffset::Immediate { add, imm12 } => ResolvedOffset {
            offset: AddressOffset::Immediate(signed_offset(add, i64::from(imm12))),
            extra_read: None,
        },
        Arm32MemoryOffset::Register { add, rm, shift } => ResolvedOffset {
            offset: AddressOffset::Register {
                register: gpr(rm),
                subtract: !add,
                shift: map_shift(shift),
            },
            extra_read: Some(gpr(rm)),
        },
    }
}

fn a32_offset8(offset: &Arm32MemoryOffset8) -> ResolvedOffset {
    match *offset {
        Arm32MemoryOffset8::Immediate { add, imm8 } => ResolvedOffset {
            offset: AddressOffset::Immediate(signed_offset(add, i64::from(imm8))),
            extra_read: None,
        },
        Arm32MemoryOffset8::Register { add, rm } => ResolvedOffset {
            offset: AddressOffset::Register {
                register: gpr(rm),
                subtract: !add,
                shift: Shift::Lsl(0),
            },
            extra_read: Some(gpr(rm)),
        },
    }
}

fn a32_imm_offset(offset: &Arm32MemoryOffset) -> Option<i64> {
    match *offset {
        Arm32MemoryOffset::Immediate { add, imm12 } => Some(signed_offset(add, i64::from(imm12))),
        Arm32MemoryOffset::Register { .. } => None,
    }
}

fn signed_offset(add: bool, magnitude: i64) -> i64 {
    if add { magnitude } else { -magnitude }
}

fn a32_single_mem(
    pc: u32,
    length: u8,
    cond: Arm32Condition,
    kind: AccessKind,
    width: u8,
    transferred: Option<Register>,
    rn: Arm32GeneralPurposeRegister,
    resolved: ResolvedOffset,
    index: Arm32IndexMode,
) -> DecodedInstruction {
    let (access, writeback) = index_addresses(rn, &resolved.offset, index);
    let mut reads = BTreeSet::new();
    let mut writes = BTreeSet::new();
    if !is_pc(rn) {
        reads.insert(gpr(rn));
    }
    if let Some(register) = resolved.extra_read {
        reads.insert(register);
    }
    if let Some(register) = transferred {
        match kind {
            AccessKind::Read | AccessKind::ReadWrite => {
                writes.insert(register);
            }
            AccessKind::Write => {
                reads.insert(register);
            }
        }
    }
    if let Some((register, _)) = writeback {
        writes.insert(register);
    }
    let base = if is_pc(rn) {
        AddressBase::ArchitecturalPc {
            align_to_four: false,
        }
    } else {
        AddressBase::Register(gpr(rn))
    };
    insn(
        Isa::Arm,
        pc,
        length,
        a32_conditional(cond),
        reads,
        writes,
        memory(
            vec![transfer(
                AddressExpr {
                    base,
                    offset: access,
                },
                kind,
                width,
                transferred,
            )],
            writeback,
        ),
        ControlFlow::Linear,
    )
}

fn a32_dual_mem(
    pc: u32,
    length: u8,
    cond: Arm32Condition,
    kind: AccessKind,
    rt: Register,
    rn: Arm32GeneralPurposeRegister,
    resolved: ResolvedOffset,
    index: Arm32IndexMode,
) -> DecodedInstruction {
    let Some(rt2) = pair_reg(rt) else {
        return unsupported(
            Isa::Arm,
            pc,
            length,
            a32_conditional(cond),
            set([rt, gpr(rn)]),
            set([rt]),
            ControlFlow::Linear,
        );
    };
    let mut mapped = a32_single_mem(pc, length, cond, kind, 8, Some(rt), rn, resolved, index);
    match kind {
        AccessKind::Read | AccessKind::ReadWrite => {
            mapped.writes.insert(rt2);
        }
        AccessKind::Write => {
            mapped.reads.insert(rt2);
        }
    }
    mapped
}

fn t32_imm_mem(
    pc: u32,
    length: u8,
    kind: AccessKind,
    width: u8,
    transferred: Option<Register>,
    rn: Arm32GeneralPurposeRegister,
    offset: i64,
    mode: Arm32IndexMode,
) -> DecodedInstruction {
    if kind == AccessKind::Read
        && width == 4
        && is_pc(rn)
        && mode == Arm32IndexMode::Offset
        && let Some(rt) = transferred
    {
        return t32_literal(pc, length, rt, offset);
    }
    let resolved = ResolvedOffset {
        offset: AddressOffset::Immediate(offset),
        extra_read: None,
    };
    a32_single_mem(
        pc,
        length,
        Arm32Condition::AlwaysUnconditional,
        kind,
        width,
        transferred,
        rn,
        resolved,
        mode,
    )
    .with_isa(Isa::Thumb)
    .with_pc_align(is_pc(rn))
}

fn t32_reg_mem(
    pc: u32,
    length: u8,
    kind: AccessKind,
    width: u8,
    transferred: Option<Register>,
    rn: Arm32GeneralPurposeRegister,
    rm: Arm32GeneralPurposeRegister,
    lsl: u8,
) -> DecodedInstruction {
    let resolved = ResolvedOffset {
        offset: AddressOffset::Register {
            register: gpr(rm),
            subtract: false,
            shift: Shift::Lsl(lsl),
        },
        extra_read: Some(gpr(rm)),
    };
    a32_single_mem(
        pc,
        length,
        Arm32Condition::AlwaysUnconditional,
        kind,
        width,
        transferred,
        rn,
        resolved,
        Arm32IndexMode::Offset,
    )
    .with_isa(Isa::Thumb)
}

fn t32_dual_mem(
    pc: u32,
    length: u8,
    kind: AccessKind,
    rt: Register,
    rt2: Register,
    rn: Arm32GeneralPurposeRegister,
    offset: i64,
    mode: Arm32IndexMode,
) -> DecodedInstruction {
    let mut mapped = t32_imm_mem(pc, length, kind, 8, Some(rt), rn, offset, mode);
    match kind {
        AccessKind::Read | AccessKind::ReadWrite => {
            mapped.writes.insert(rt2);
        }
        AccessKind::Write => {
            mapped.reads.insert(rt2);
        }
    }
    mapped
}

trait WithPcAlign {
    fn with_pc_align(self, align: bool) -> Self;
}

impl WithPcAlign for DecodedInstruction {
    fn with_pc_align(mut self, align: bool) -> Self {
        if let ValueEffect::Memory(effect) = &mut self.effect {
            for transfer in &mut effect.transfers {
                if let AddressBase::ArchitecturalPc { align_to_four } = &mut transfer.address.base {
                    *align_to_four = align;
                }
            }
            if let Some((_, address)) = &mut effect.writeback
                && let AddressBase::ArchitecturalPc { align_to_four } = &mut address.base
            {
                *align_to_four = align;
            }
        }
        if let ValueEffect::LiteralWordLoad { address, .. } = &mut self.effect
            && let AddressBase::ArchitecturalPc { align_to_four } = &mut address.base
        {
            *align_to_four = align;
        }
        self
    }
}

fn index_addresses(
    rn: Arm32GeneralPurposeRegister,
    offset: &AddressOffset,
    index: Arm32IndexMode,
) -> (AddressOffset, Option<(Register, AddressExpr)>) {
    let base = if is_pc(rn) {
        AddressBase::ArchitecturalPc {
            align_to_four: false,
        }
    } else {
        AddressBase::Register(gpr(rn))
    };
    match index {
        Arm32IndexMode::Offset => (*offset, None),
        Arm32IndexMode::PreIndex => (
            *offset,
            Some((
                gpr(rn),
                AddressExpr {
                    base,
                    offset: *offset,
                },
            )),
        ),
        Arm32IndexMode::PostIndex => (
            AddressOffset::Immediate(0),
            Some((
                gpr(rn),
                AddressExpr {
                    base,
                    offset: *offset,
                },
            )),
        ),
    }
}

fn a32_exclusive_load(
    pc: u32,
    length: u8,
    cond: Arm32Condition,
    rt: Register,
    rt2: Option<Register>,
    rn: Register,
    width: u8,
    offset: i64,
) -> DecodedInstruction {
    let mut writes = set([rt]);
    if let Some(second) = rt2 {
        writes.insert(second);
    }
    insn(
        Isa::Arm,
        pc,
        length,
        a32_conditional(cond),
        set([rn]),
        writes,
        memory(
            vec![transfer(
                imm_addr(rn, offset),
                AccessKind::Read,
                width,
                Some(rt),
            )],
            None,
        ),
        ControlFlow::Linear,
    )
}

fn a32_exclusive_store(
    pc: u32,
    length: u8,
    cond: Arm32Condition,
    rd: Register,
    rt: Register,
    rt2: Option<Register>,
    rn: Register,
    width: u8,
    offset: i64,
) -> DecodedInstruction {
    let mut reads = set([rt, rn]);
    if let Some(second) = rt2 {
        reads.insert(second);
    }
    insn(
        Isa::Arm,
        pc,
        length,
        a32_conditional(cond),
        reads,
        set([rd]),
        memory(
            vec![transfer(
                imm_addr(rn, offset),
                AccessKind::Write,
                width,
                Some(rt),
            )],
            None,
        ),
        ControlFlow::Linear,
    )
}

fn a32_swap(
    pc: u32,
    length: u8,
    cond: Arm32Condition,
    rt: Register,
    rt2: Register,
    rn: Register,
    width: u8,
) -> DecodedInstruction {
    insn(
        Isa::Arm,
        pc,
        length,
        a32_conditional(cond),
        set([rt2, rn]),
        set([rt]),
        memory(
            vec![transfer(
                imm_addr(rn, 0),
                AccessKind::ReadWrite,
                width,
                Some(rt),
            )],
            None,
        ),
        ControlFlow::Linear,
    )
}

fn a32_block(
    pc: u32,
    length: u8,
    cond: Arm32Condition,
    kind: AccessKind,
    mode: Arm32BlockAddressMode,
    rn: Register,
    writeback: bool,
    user_mode: bool,
    regs: Vec<Register>,
) -> DecodedInstruction {
    let mapped = expand_block(
        Isa::Arm,
        pc,
        length,
        a32_conditional(cond),
        kind,
        mode,
        rn,
        writeback,
        regs,
    );
    if user_mode {
        return unsupported(
            Isa::Arm,
            pc,
            length,
            mapped.conditional,
            mapped.reads,
            mapped.writes,
            mapped.flow,
        );
    }
    mapped
}

fn t32_block(
    pc: u32,
    length: u8,
    kind: AccessKind,
    mode: Arm32BlockAddressMode,
    rn: Register,
    writeback: bool,
    regs: Vec<Register>,
) -> DecodedInstruction {
    expand_block(
        Isa::Thumb,
        pc,
        length,
        false,
        kind,
        mode,
        rn,
        writeback,
        regs,
    )
}

fn expand_block(
    isa: Isa,
    pc: u32,
    length: u8,
    conditional: bool,
    kind: AccessKind,
    mode: Arm32BlockAddressMode,
    rn: Register,
    writeback: bool,
    mut regs: Vec<Register>,
) -> DecodedInstruction {
    regs.sort_by_key(|register| register.0);
    regs.dedup();
    let count = i64::from(u32::try_from(regs.len()).unwrap_or(u32::MAX));
    let first = match mode {
        Arm32BlockAddressMode::IncrementAfter => 0,
        Arm32BlockAddressMode::IncrementBefore => 4,
        Arm32BlockAddressMode::DecrementAfter => -4 * count + 4,
        Arm32BlockAddressMode::DecrementBefore => -4 * count,
    };
    let transfers = regs
        .iter()
        .enumerate()
        .map(|(index, register)| {
            transfer(
                imm_addr(rn, first + 4 * i64::try_from(index).unwrap_or(i64::MAX)),
                kind,
                4,
                Some(*register),
            )
        })
        .collect();
    let mut reads = set([rn]);
    let mut writes = BTreeSet::new();
    match kind {
        AccessKind::Read | AccessKind::ReadWrite => {
            writes.extend(regs.iter().copied());
        }
        AccessKind::Write => {
            reads.extend(regs.iter().copied());
        }
    }
    let writeback = if writeback && !regs.contains(&rn) {
        let delta = match mode {
            Arm32BlockAddressMode::IncrementAfter | Arm32BlockAddressMode::IncrementBefore => {
                4 * count
            }
            Arm32BlockAddressMode::DecrementAfter | Arm32BlockAddressMode::DecrementBefore => {
                -4 * count
            }
        };
        writes.insert(rn);
        Some((rn, imm_addr(rn, delta)))
    } else {
        None
    };
    let flow = if writes.contains(&PC) {
        ControlFlow::Barrier
    } else {
        ControlFlow::Linear
    };
    insn(
        isa,
        pc,
        length,
        conditional,
        reads,
        writes,
        memory(transfers, writeback),
        flow,
    )
}

fn a32_branch(pc: u32, length: u8, cond: Arm32Condition, offset: i32) -> DecodedInstruction {
    let predicate = branch_predicate(cond);
    insn(
        Isa::Arm,
        pc,
        length,
        a32_conditional(cond),
        BTreeSet::new(),
        BTreeSet::new(),
        ValueEffect::None,
        direct_branch(branch_target(Isa::Arm, pc, offset), pc, length, predicate),
    )
}

fn t32_branch(
    pc: u32,
    length: u8,
    target: u32,
    cond: Option<Arm32Condition>,
) -> DecodedInstruction {
    let predicate = match cond {
        Some(cond) => branch_predicate(cond),
        None => BranchPredicate::Always,
    };
    insn(
        Isa::Thumb,
        pc,
        length,
        cond.is_some_and(a32_conditional),
        BTreeSet::new(),
        BTreeSet::new(),
        ValueEffect::None,
        direct_branch(target, pc, length, predicate),
    )
}

fn t32_compare_branch(
    pc: u32,
    length: u8,
    rn: Register,
    offset: u8,
    nonzero: bool,
) -> DecodedInstruction {
    insn(
        Isa::Thumb,
        pc,
        length,
        true,
        set([rn]),
        BTreeSet::new(),
        ValueEffect::None,
        direct_branch(
            branch_target(Isa::Thumb, pc, i32::from(offset)),
            pc,
            length,
            BranchPredicate::RegisterZero {
                register: rn,
                nonzero,
            },
        ),
    )
}

/// Build a direct branch with its architectural fallthrough: conditional
/// branches keep the next instruction as fallthrough, unconditional ones do
/// not.
fn direct_branch(target: u32, pc: u32, length: u8, predicate: BranchPredicate) -> ControlFlow {
    let fallthrough =
        (!matches!(predicate, BranchPredicate::Always)).then(|| pc.wrapping_add(u32::from(length)));
    ControlFlow::DirectBranch {
        target,
        fallthrough,
        predicate,
    }
}

fn branch_predicate(cond: Arm32Condition) -> BranchPredicate {
    if a32_conditional(cond) {
        BranchPredicate::Condition(cond)
    } else {
        BranchPredicate::Always
    }
}

fn map_it(pc: u32, length: u8, _cond: Arm32Condition, _mask: u8) -> DecodedInstruction {
    insn(
        Isa::Thumb,
        pc,
        length,
        false,
        BTreeSet::new(),
        BTreeSet::new(),
        ValueEffect::None,
        ControlFlow::Linear,
    )
}

fn unsupported(
    isa: Isa,
    pc: u32,
    length: u8,
    conditional: bool,
    reads: BTreeSet<Register>,
    writes: BTreeSet<Register>,
    flow: ControlFlow,
) -> DecodedInstruction {
    insn(
        isa,
        pc,
        length,
        conditional,
        reads,
        writes,
        ValueEffect::Unsupported,
        flow,
    )
}

fn a32_linear(
    pc: u32,
    length: u8,
    cond: Arm32Condition,
    reads: BTreeSet<Register>,
    writes: BTreeSet<Register>,
) -> DecodedInstruction {
    unsupported(
        Isa::Arm,
        pc,
        length,
        a32_conditional(cond),
        reads,
        writes,
        ControlFlow::Linear,
    )
}

fn a32_barrier(
    pc: u32,
    length: u8,
    cond: Arm32Condition,
    reads: BTreeSet<Register>,
    writes: BTreeSet<Register>,
) -> DecodedInstruction {
    unsupported(
        Isa::Arm,
        pc,
        length,
        a32_conditional(cond),
        reads,
        writes,
        ControlFlow::Barrier,
    )
}

fn a32_unsupported(pc: u32, length: u8, inst: &ArmA32Instruction) -> DecodedInstruction {
    match inst {
        ArmA32Instruction::And_Immediate_A1(cond, _, rd, rn, _)
        | ArmA32Instruction::Eor_Immediate_A1(cond, _, rd, rn, _)
        | ArmA32Instruction::Orr_Immediate_A1(cond, _, rd, rn, _)
        | ArmA32Instruction::Bic_Immediate_A1(cond, _, rd, rn, _)
        | ArmA32Instruction::Adc_Immediate_A1(cond, _, rd, rn, _)
        | ArmA32Instruction::Sbc_Immediate_A1(cond, _, rd, rn, _)
        | ArmA32Instruction::Rsb_Immediate_A1(cond, _, rd, rn, _)
        | ArmA32Instruction::Rsc_Immediate_A1(cond, _, rd, rn, _) => {
            a32_linear(pc, length, *cond, set([gpr(*rn)]), set([gpr(*rd)]))
        }
        ArmA32Instruction::And_Register_A1(cond, _, rd, rn, rm, _)
        | ArmA32Instruction::Eor_Register_A1(cond, _, rd, rn, rm, _)
        | ArmA32Instruction::Orr_Register_A1(cond, _, rd, rn, rm, _)
        | ArmA32Instruction::Bic_Register_A1(cond, _, rd, rn, rm, _)
        | ArmA32Instruction::Adc_Register_A1(cond, _, rd, rn, rm, _)
        | ArmA32Instruction::Sbc_Register_A1(cond, _, rd, rn, rm, _)
        | ArmA32Instruction::Rsb_Register_A1(cond, _, rd, rn, rm, _)
        | ArmA32Instruction::Rsc_Register_A1(cond, _, rd, rn, rm, _) => a32_linear(
            pc,
            length,
            *cond,
            set([gpr(*rn), gpr(*rm)]),
            set([gpr(*rd)]),
        ),
        ArmA32Instruction::And_RegisterShiftedRegister_A1(cond, _, rd, rn, rm, _, rs)
        | ArmA32Instruction::Eor_RegisterShiftedRegister_A1(cond, _, rd, rn, rm, _, rs)
        | ArmA32Instruction::Sub_RegisterShiftedRegister_A1(cond, _, rd, rn, rm, _, rs)
        | ArmA32Instruction::Rsb_RegisterShiftedRegister_A1(cond, _, rd, rn, rm, _, rs)
        | ArmA32Instruction::Add_RegisterShiftedRegister_A1(cond, _, rd, rn, rm, _, rs)
        | ArmA32Instruction::Adc_RegisterShiftedRegister_A1(cond, _, rd, rn, rm, _, rs)
        | ArmA32Instruction::Sbc_RegisterShiftedRegister_A1(cond, _, rd, rn, rm, _, rs)
        | ArmA32Instruction::Rsc_RegisterShiftedRegister_A1(cond, _, rd, rn, rm, _, rs)
        | ArmA32Instruction::Orr_RegisterShiftedRegister_A1(cond, _, rd, rn, rm, _, rs)
        | ArmA32Instruction::Bic_RegisterShiftedRegister_A1(cond, _, rd, rn, rm, _, rs) => {
            a32_linear(
                pc,
                length,
                *cond,
                set([gpr(*rn), gpr(*rm), gpr(*rs)]),
                set([gpr(*rd)]),
            )
        }
        ArmA32Instruction::Mvn_Immediate_A1(cond, _, rd, _) => {
            a32_linear(pc, length, *cond, BTreeSet::new(), set([gpr(*rd)]))
        }
        ArmA32Instruction::Mvn_Register_A1(cond, _, rd, rm, _) => {
            a32_linear(pc, length, *cond, set([gpr(*rm)]), set([gpr(*rd)]))
        }
        ArmA32Instruction::Mov_RegisterShiftedRegister_A1(cond, _, rd, rm, _, rs)
        | ArmA32Instruction::Mvn_RegisterShiftedRegister_A1(cond, _, rd, rm, _, rs) => a32_linear(
            pc,
            length,
            *cond,
            set([gpr(*rm), gpr(*rs)]),
            set([gpr(*rd)]),
        ),
        // Register-shifted-register compares keep their S-bit flag write but
        // stay unsupported: the barrel-shift amount is not statically
        // modeled. (The immediate/register compare forms are modeled in
        // map_a32 above.)
        ArmA32Instruction::Tst_RegisterShiftedRegister_A1(cond, rn, rm, _, rs)
        | ArmA32Instruction::Teq_RegisterShiftedRegister_A1(cond, rn, rm, _, rs)
        | ArmA32Instruction::Cmp_RegisterShiftedRegister_A1(cond, rn, rm, _, rs)
        | ArmA32Instruction::Cmn_RegisterShiftedRegister_A1(cond, rn, rm, _, rs) => a32_linear(
            pc,
            length,
            *cond,
            set([gpr(*rn), gpr(*rm), gpr(*rs)]),
            BTreeSet::new(),
        ),
        ArmA32Instruction::Mul_A1(cond, _, rd, rn, rm)
        | ArmA32Instruction::Smulw_A1(cond, rd, rn, rm, _)
        | ArmA32Instruction::Smul_A1(cond, rd, rn, rm, _, _)
        | ArmA32Instruction::Smuad_A1(cond, rd, rn, rm, _)
        | ArmA32Instruction::Smusd_A1(cond, rd, rn, rm, _)
        | ArmA32Instruction::Smmul_A1(cond, rd, rn, rm, _)
        | ArmA32Instruction::Usad8_A1(cond, rd, rn, rm)
        | ArmA32Instruction::Qadd_A1(cond, rd, rm, rn)
        | ArmA32Instruction::Qsub_A1(cond, rd, rm, rn)
        | ArmA32Instruction::Qdadd_A1(cond, rd, rm, rn)
        | ArmA32Instruction::Qdsub_A1(cond, rd, rm, rn)
        | ArmA32Instruction::Sel_A1(cond, rd, rn, rm)
        | ArmA32Instruction::ParallelAddSub_A1(cond, _, _, rd, rn, rm)
        | ArmA32Instruction::Crc32b_A1(cond, rd, rn, rm)
        | ArmA32Instruction::Crc32h_A1(cond, rd, rn, rm)
        | ArmA32Instruction::Crc32w_A1(cond, rd, rn, rm)
        | ArmA32Instruction::Crc32cb_A1(cond, rd, rn, rm)
        | ArmA32Instruction::Crc32ch_A1(cond, rd, rn, rm)
        | ArmA32Instruction::Crc32cw_A1(cond, rd, rn, rm) => a32_linear(
            pc,
            length,
            *cond,
            set([gpr(*rn), gpr(*rm)]),
            set([gpr(*rd)]),
        ),
        ArmA32Instruction::Mla_A1(cond, _, rd, rn, rm, ra)
        | ArmA32Instruction::Mls_A1(cond, rd, rn, rm, ra)
        | ArmA32Instruction::Smla_A1(cond, rd, rn, rm, ra, _, _)
        | ArmA32Instruction::Smlaw_A1(cond, rd, rn, rm, ra, _)
        | ArmA32Instruction::Smlad_A1(cond, rd, rn, rm, ra, _)
        | ArmA32Instruction::Smlsd_A1(cond, rd, rn, rm, ra, _)
        | ArmA32Instruction::Smmla_A1(cond, rd, rn, rm, ra, _)
        | ArmA32Instruction::Smmls_A1(cond, rd, rn, rm, ra, _)
        | ArmA32Instruction::Usada8_A1(cond, rd, rn, rm, ra) => a32_linear(
            pc,
            length,
            *cond,
            set([gpr(*rn), gpr(*rm), gpr(*ra)]),
            set([gpr(*rd)]),
        ),
        ArmA32Instruction::Umull_A1(cond, _, rdlo, rdhi, rn, rm)
        | ArmA32Instruction::Umlal_A1(cond, _, rdlo, rdhi, rn, rm)
        | ArmA32Instruction::Smull_A1(cond, _, rdlo, rdhi, rn, rm)
        | ArmA32Instruction::Smlal_A1(cond, _, rdlo, rdhi, rn, rm)
        | ArmA32Instruction::Umaal_A1(cond, rdlo, rdhi, rn, rm)
        | ArmA32Instruction::Smlal_Halfword_A1(cond, rdlo, rdhi, rn, rm, _, _)
        | ArmA32Instruction::Smlald_A1(cond, rdlo, rdhi, rn, rm, _)
        | ArmA32Instruction::Smlsld_A1(cond, rdlo, rdhi, rn, rm, _) => a32_linear(
            pc,
            length,
            *cond,
            set([gpr(*rdlo), gpr(*rdhi), gpr(*rn), gpr(*rm)]),
            set([gpr(*rdlo), gpr(*rdhi)]),
        ),
        ArmA32Instruction::Extend_A1(cond, _, rd, rm, _)
        | ArmA32Instruction::Rev_A1(cond, rd, rm)
        | ArmA32Instruction::Rev16_A1(cond, rd, rm)
        | ArmA32Instruction::Revsh_A1(cond, rd, rm)
        | ArmA32Instruction::Rbit_A1(cond, rd, rm)
        | ArmA32Instruction::Clz_A1(cond, rd, rm)
        | ArmA32Instruction::Ssat_A1(cond, rd, _, rm, _)
        | ArmA32Instruction::Usat_A1(cond, rd, _, rm, _)
        | ArmA32Instruction::Ssat16_A1(cond, rd, _, rm)
        | ArmA32Instruction::Usat16_A1(cond, rd, _, rm) => {
            a32_linear(pc, length, *cond, set([gpr(*rm)]), set([gpr(*rd)]))
        }
        ArmA32Instruction::ExtendAndAdd_A1(cond, _, rd, rn, rm, _)
        | ArmA32Instruction::Pkhbt_A1(cond, rd, rn, rm, _)
        | ArmA32Instruction::Pkhtb_A1(cond, rd, rn, rm, _) => a32_linear(
            pc,
            length,
            *cond,
            set([gpr(*rn), gpr(*rm)]),
            set([gpr(*rd)]),
        ),
        ArmA32Instruction::Bfc_A1(cond, rd, _, _) => {
            a32_linear(pc, length, *cond, set([gpr(*rd)]), set([gpr(*rd)]))
        }
        ArmA32Instruction::Bfi_A1(cond, rd, rn, _, _)
        | ArmA32Instruction::Sbfx_A1(cond, rd, rn, _, _)
        | ArmA32Instruction::Ubfx_A1(cond, rd, rn, _, _) => a32_linear(
            pc,
            length,
            *cond,
            set([gpr(*rd), gpr(*rn)]),
            set([gpr(*rd)]),
        ),
        ArmA32Instruction::Ldrt_A1(cond, rt, rn, _)
        | ArmA32Instruction::Ldrbt_A1(cond, rt, rn, _)
        | ArmA32Instruction::Ldrht_A1(cond, rt, rn, _)
        | ArmA32Instruction::Ldrsbt_A1(cond, rt, rn, _)
        | ArmA32Instruction::Ldrsht_A1(cond, rt, rn, _)
        | ArmA32Instruction::Lda_A1(cond, rt, rn)
        | ArmA32Instruction::Ldab_A1(cond, rt, rn)
        | ArmA32Instruction::Ldah_A1(cond, rt, rn)
        | ArmA32Instruction::Ldaex_A1(cond, rt, rn)
        | ArmA32Instruction::Ldaexb_A1(cond, rt, rn)
        | ArmA32Instruction::Ldaexh_A1(cond, rt, rn) => {
            a32_linear(pc, length, *cond, set([gpr(*rn)]), set([gpr(*rt)]))
        }
        ArmA32Instruction::Ldaexd_A1(cond, rt, rn) => {
            let mut writes = set([gpr(*rt)]);
            if let Some(rt2) = pair_reg(gpr(*rt)) {
                writes.insert(rt2);
            }
            a32_linear(pc, length, *cond, set([gpr(*rn)]), writes)
        }
        ArmA32Instruction::Strt_A1(cond, rt, rn, _)
        | ArmA32Instruction::Strbt_A1(cond, rt, rn, _)
        | ArmA32Instruction::Strht_A1(cond, rt, rn, _)
        | ArmA32Instruction::Stl_A1(cond, rt, rn)
        | ArmA32Instruction::Stlb_A1(cond, rt, rn)
        | ArmA32Instruction::Stlh_A1(cond, rt, rn) => a32_linear(
            pc,
            length,
            *cond,
            set([gpr(*rt), gpr(*rn)]),
            BTreeSet::new(),
        ),
        ArmA32Instruction::Stlex_A1(cond, rd, rt, rn)
        | ArmA32Instruction::Stlexb_A1(cond, rd, rt, rn)
        | ArmA32Instruction::Stlexh_A1(cond, rd, rt, rn)
        | ArmA32Instruction::Stlexd_A1(cond, rd, rt, rn) => a32_linear(
            pc,
            length,
            *cond,
            set([gpr(*rt), gpr(*rn)]),
            set([gpr(*rd)]),
        ),
        ArmA32Instruction::Mrs_A1(cond, _, rd) => {
            a32_linear(pc, length, *cond, BTreeSet::new(), set([gpr(*rd)])).with_system(
                SystemEffect::PsrTransfer {
                    direction: SystemDirection::Read,
                    register: Some(gpr(*rd)),
                    mask: 0,
                    immediate: None,
                },
            )
        }
        ArmA32Instruction::MrsBanked_A1(cond, _, _, rd) => {
            a32_linear(pc, length, *cond, BTreeSet::new(), set([gpr(*rd)]))
        }
        ArmA32Instruction::Msr_Register_A1(cond, _, mask, rm) => {
            a32_linear(pc, length, *cond, set([gpr(*rm)]), BTreeSet::new()).with_system(
                SystemEffect::PsrTransfer {
                    direction: SystemDirection::Write,
                    register: Some(gpr(*rm)),
                    mask: *mask,
                    immediate: None,
                },
            )
        }
        ArmA32Instruction::MsrBanked_A1(cond, _, _, rm) => {
            a32_linear(pc, length, *cond, set([gpr(*rm)]), BTreeSet::new())
        }
        ArmA32Instruction::Msr_Immediate_A1(cond, _, mask, imm) => {
            a32_linear(pc, length, *cond, BTreeSet::new(), BTreeSet::new()).with_system(
                SystemEffect::PsrTransfer {
                    direction: SystemDirection::Write,
                    register: None,
                    mask: *mask,
                    immediate: Some(*imm),
                },
            )
        }
        ArmA32Instruction::Mrc_A1(cond, coprocessor, opcode1, rt, crn, crm, opcode2) => {
            a32_linear(pc, length, *cond, BTreeSet::new(), set([gpr(*rt)])).with_system(
                system_transfer(
                    SystemDirection::Read,
                    *coprocessor,
                    *opcode1,
                    *rt,
                    *crn,
                    *crm,
                    *opcode2,
                    false,
                ),
            )
        }
        ArmA32Instruction::Mrc2_A1(coprocessor, opcode1, rt, crn, crm, opcode2) => unsupported(
            Isa::Arm,
            pc,
            length,
            false,
            BTreeSet::new(),
            set([gpr(*rt)]),
            ControlFlow::Linear,
        )
        .with_system(system_transfer(
            SystemDirection::Read,
            *coprocessor,
            *opcode1,
            *rt,
            *crn,
            *crm,
            *opcode2,
            true,
        )),
        ArmA32Instruction::Mcr_A1(cond, coprocessor, opcode1, rt, crn, crm, opcode2) => {
            a32_linear(pc, length, *cond, set([gpr(*rt)]), BTreeSet::new()).with_system(
                system_transfer(
                    SystemDirection::Write,
                    *coprocessor,
                    *opcode1,
                    *rt,
                    *crn,
                    *crm,
                    *opcode2,
                    false,
                ),
            )
        }
        ArmA32Instruction::Mcr2_A1(coprocessor, opcode1, rt, crn, crm, opcode2) => unsupported(
            Isa::Arm,
            pc,
            length,
            false,
            set([gpr(*rt)]),
            BTreeSet::new(),
            ControlFlow::Linear,
        )
        .with_system(system_transfer(
            SystemDirection::Write,
            *coprocessor,
            *opcode1,
            *rt,
            *crn,
            *crm,
            *opcode2,
            true,
        )),
        ArmA32Instruction::Mrrc_A1(cond, _, _, rt, rt2, _) => a32_linear(
            pc,
            length,
            *cond,
            BTreeSet::new(),
            set([gpr(*rt), gpr(*rt2)]),
        ),
        ArmA32Instruction::Mrrc2_A1(_, _, rt, rt2, _) => unsupported(
            Isa::Arm,
            pc,
            length,
            false,
            BTreeSet::new(),
            set([gpr(*rt), gpr(*rt2)]),
            ControlFlow::Linear,
        ),
        ArmA32Instruction::Mcrr_A1(cond, _, _, rt, rt2, _) => a32_linear(
            pc,
            length,
            *cond,
            set([gpr(*rt), gpr(*rt2)]),
            BTreeSet::new(),
        ),
        ArmA32Instruction::Mcrr2_A1(_, _, rt, rt2, _) => unsupported(
            Isa::Arm,
            pc,
            length,
            false,
            set([gpr(*rt), gpr(*rt2)]),
            BTreeSet::new(),
            ControlFlow::Linear,
        ),
        ArmA32Instruction::Ldc_A1(cond, _, _, _, rn, _, _, _)
        | ArmA32Instruction::Stc_A1(cond, _, _, _, rn, _, _, _) => {
            a32_linear(pc, length, *cond, set([gpr(*rn)]), set([gpr(*rn)]))
        }
        ArmA32Instruction::Ldc2_A1(_, _, _, rn, _, _, _)
        | ArmA32Instruction::Stc2_A1(_, _, _, rn, _, _, _) => unsupported(
            Isa::Arm,
            pc,
            length,
            false,
            set([gpr(*rn)]),
            set([gpr(*rn)]),
            ControlFlow::Linear,
        ),
        ArmA32Instruction::Cdp_A1(cond, _, _, _, _, _, _) => {
            a32_linear(pc, length, *cond, BTreeSet::new(), BTreeSet::new())
        }
        ArmA32Instruction::Cdp2_A1(_, _, _, _, _, _) => unsupported(
            Isa::Arm,
            pc,
            length,
            false,
            BTreeSet::new(),
            BTreeSet::new(),
            ControlFlow::Linear,
        ),
        ArmA32Instruction::Nop_A1(cond)
        | ArmA32Instruction::Yield_A1(cond)
        | ArmA32Instruction::Wfe_A1(cond)
        | ArmA32Instruction::Wfi_A1(cond)
        | ArmA32Instruction::Sev_A1(cond)
        | ArmA32Instruction::Dbg_A1(cond, _)
        | ArmA32Instruction::Csdb_A1(cond)
        | ArmA32Instruction::Esb_A1(cond)
        | ArmA32Instruction::Sevl_A1(cond) => {
            a32_linear(pc, length, *cond, BTreeSet::new(), BTreeSet::new())
        }
        ArmA32Instruction::Dmb_A1(_)
        | ArmA32Instruction::Dsb_A1(_)
        | ArmA32Instruction::Isb_A1(_)
        | ArmA32Instruction::Clrex_A1
        | ArmA32Instruction::Setend_A1(_)
        | ArmA32Instruction::Setpan_A1(_)
        | ArmA32Instruction::Cps_A1(_, _, _, _, _)
        | ArmA32Instruction::Sb_A1 => unsupported(
            Isa::Arm,
            pc,
            length,
            false,
            BTreeSet::new(),
            BTreeSet::new(),
            ControlFlow::Linear,
        ),
        ArmA32Instruction::Pld_A1(rn, offset)
        | ArmA32Instruction::Pldw_A1(rn, offset)
        | ArmA32Instruction::Pli_A1(rn, offset) => {
            let resolved = a32_offset(offset);
            let mut reads = BTreeSet::new();
            if !is_pc(*rn) {
                reads.insert(gpr(*rn));
            }
            if let Some(register) = resolved.extra_read {
                reads.insert(register);
            }
            unsupported(
                Isa::Arm,
                pc,
                length,
                false,
                reads,
                BTreeSet::new(),
                ControlFlow::Linear,
            )
        }
        ArmA32Instruction::Rfe_A1(_, rn, writeback) => {
            let writes = if *writeback {
                set([gpr(*rn)])
            } else {
                BTreeSet::new()
            };
            unsupported(
                Isa::Arm,
                pc,
                length,
                false,
                set([gpr(*rn)]),
                writes,
                ControlFlow::Barrier,
            )
        }
        ArmA32Instruction::Srs_A1(_, writeback, _) => {
            let writes = if *writeback {
                set([SP])
            } else {
                BTreeSet::new()
            };
            unsupported(
                Isa::Arm,
                pc,
                length,
                false,
                set([SP]),
                writes,
                ControlFlow::Linear,
            )
        }
        ArmA32Instruction::Bxj_A1(cond, rm) => {
            a32_barrier(pc, length, *cond, set([gpr(*rm)]), BTreeSet::new())
        }
        ArmA32Instruction::Bkpt_A1(cond, _)
        | ArmA32Instruction::Hlt_A1(cond, _)
        | ArmA32Instruction::Hvc_A1(cond, _)
        | ArmA32Instruction::Smc_A1(cond, _)
        | ArmA32Instruction::Udf_A1(cond, _)
        | ArmA32Instruction::Eret_A1(cond) => {
            a32_barrier(pc, length, *cond, BTreeSet::new(), BTreeSet::new())
        }
        _ => unsupported(
            Isa::Arm,
            pc,
            length,
            false,
            BTreeSet::new(),
            all_core_registers(),
            ControlFlow::Barrier,
        ),
    }
}

fn t32_linear(
    pc: u32,
    length: u8,
    reads: BTreeSet<Register>,
    writes: BTreeSet<Register>,
) -> DecodedInstruction {
    unsupported(
        Isa::Thumb,
        pc,
        length,
        false,
        reads,
        writes,
        ControlFlow::Linear,
    )
}

fn t32_barrier(
    pc: u32,
    length: u8,
    reads: BTreeSet<Register>,
    writes: BTreeSet<Register>,
) -> DecodedInstruction {
    unsupported(
        Isa::Thumb,
        pc,
        length,
        false,
        reads,
        writes,
        ControlFlow::Barrier,
    )
}

fn t32_unsupported(pc: u32, length: u8, inst: &ArmT32Instruction) -> DecodedInstruction {
    match inst {
        ArmT32Instruction::And_Register_T1(rdn, rm)
        | ArmT32Instruction::Eor_Register_T1(rdn, rm)
        | ArmT32Instruction::Orr_Register_T1(rdn, rm)
        | ArmT32Instruction::Bic_Register_T1(rdn, rm)
        | ArmT32Instruction::Adc_Register_T1(rdn, rm)
        | ArmT32Instruction::Sbc_Register_T1(rdn, rm)
        | ArmT32Instruction::Lsl_Register_T1(rdn, rm)
        | ArmT32Instruction::Lsr_Register_T1(rdn, rm)
        | ArmT32Instruction::Asr_Register_T1(rdn, rm)
        | ArmT32Instruction::Ror_Register_T1(rdn, rm)
        | ArmT32Instruction::Mul_T1(rdn, rm) => t32_linear(
            pc,
            length,
            set([low_reg(*rdn), low_reg(*rm)]),
            set([low_reg(*rdn)]),
        ),
        // Register-amount shifts keep their S-bit flag write but stay
        // unsupported: the shift amount is not statically modeled. (The
        // immediate-amount forms are modeled in map_t32 above.)
        ArmT32Instruction::Mvn_Register_T1(rd, rm)
        | ArmT32Instruction::Rev_T1(rd, rm)
        | ArmT32Instruction::Rev16_T1(rd, rm)
        | ArmT32Instruction::Revsh_T1(rd, rm)
        | ArmT32Instruction::Sxtb_T1(rd, rm)
        | ArmT32Instruction::Sxth_T1(rd, rm)
        | ArmT32Instruction::Uxtb_T1(rd, rm)
        | ArmT32Instruction::Uxth_T1(rd, rm)
        | ArmT32Instruction::Rsb_Immediate_T1(rd, rm) => {
            t32_linear(pc, length, set([low_reg(*rm)]), set([low_reg(*rd)]))
        }
        ArmT32Instruction::And_Immediate_T1(rd, rn, _, _)
        | ArmT32Instruction::Eor_Immediate_T1(rd, rn, _, _)
        | ArmT32Instruction::Orr_Immediate_T1(rd, rn, _, _)
        | ArmT32Instruction::Bic_Immediate_T1(rd, rn, _, _)
        | ArmT32Instruction::Adc_Immediate_T1(rd, rn, _, _)
        | ArmT32Instruction::Sbc_Immediate_T1(rd, rn, _, _)
        | ArmT32Instruction::Rsb_Immediate_T2(rd, rn, _, _)
        | ArmT32Instruction::Orn_Immediate_T1(rd, rn, _, _)
        | ArmT32Instruction::Ssat_T1(rd, _, rn, _)
        | ArmT32Instruction::Usat_T1(rd, _, rn, _)
        | ArmT32Instruction::Ssat16_T1(rd, _, rn)
        | ArmT32Instruction::Usat16_T1(rd, _, rn) => {
            t32_linear(pc, length, set([gpr(*rn)]), set([gpr(*rd)]))
        }
        ArmT32Instruction::And_Register_T2(rd, rn, rm, _, _)
        | ArmT32Instruction::Orr_Register_T2(rd, rn, rm, _, _)
        | ArmT32Instruction::Eor_Register_T2(rd, rn, rm, _, _)
        | ArmT32Instruction::Bic_Register_T2(rd, rn, rm, _, _)
        | ArmT32Instruction::Adc_Register_T2(rd, rn, rm, _, _)
        | ArmT32Instruction::Sbc_Register_T2(rd, rn, rm, _, _)
        | ArmT32Instruction::Rsb_Register_T1(rd, rn, rm, _, _)
        | ArmT32Instruction::Orn_Register_T1(rd, rn, rm, _, _)
        | ArmT32Instruction::Mul_T2(rd, rn, rm)
        | ArmT32Instruction::Sdiv_T1(rd, rn, rm)
        | ArmT32Instruction::Udiv_T1(rd, rn, rm) => {
            t32_linear(pc, length, set([gpr(*rn), gpr(*rm)]), set([gpr(*rd)]))
        }
        ArmT32Instruction::Mvn_Immediate_T1(rd, _, _) => {
            t32_linear(pc, length, BTreeSet::new(), set([gpr(*rd)]))
        }
        ArmT32Instruction::Mrs_T1(rd, _) => {
            t32_linear(pc, length, BTreeSet::new(), set([gpr(*rd)])).with_system(
                SystemEffect::PsrTransfer {
                    direction: SystemDirection::Read,
                    register: Some(gpr(*rd)),
                    mask: 0,
                    immediate: None,
                },
            )
        }
        ArmT32Instruction::Mvn_Register_T2(rd, rm, _, _)
        | ArmT32Instruction::Clz_T1(rd, rm)
        | ArmT32Instruction::Rbit_T1(rd, rm)
        | ArmT32Instruction::Sxtb_T2(rd, rm, _)
        | ArmT32Instruction::Uxtb_T2(rd, rm, _)
        | ArmT32Instruction::Sxth_T2(rd, rm, _)
        | ArmT32Instruction::Uxth_T2(rd, rm, _)
        | ArmT32Instruction::Rev_T2(rd, rm)
        | ArmT32Instruction::Rev16_T2(rd, rm)
        | ArmT32Instruction::Revsh_T2(rd, rm)
        | ArmT32Instruction::Sxtb16_T1(rd, rm, _)
        | ArmT32Instruction::Uxtb16_T1(rd, rm, _) => {
            t32_linear(pc, length, set([gpr(*rm)]), set([gpr(*rd)]))
        }
        ArmT32Instruction::Bfc_T1(rd, _, _) => {
            t32_linear(pc, length, set([gpr(*rd)]), set([gpr(*rd)]))
        }
        ArmT32Instruction::Bfi_T1(rd, rn, _, _)
        | ArmT32Instruction::Sbfx_T1(rd, rn, _, _)
        | ArmT32Instruction::Ubfx_T1(rd, rn, _, _) => {
            t32_linear(pc, length, set([gpr(*rd), gpr(*rn)]), set([gpr(*rd)]))
        }
        ArmT32Instruction::Qadd_T1(rd, rm, rn)
        | ArmT32Instruction::Qsub_T1(rd, rm, rn)
        | ArmT32Instruction::Qdadd_T1(rd, rm, rn)
        | ArmT32Instruction::Qdsub_T1(rd, rm, rn)
        | ArmT32Instruction::Sxtab_T1(rd, rn, rm, _)
        | ArmT32Instruction::Uxtab_T1(rd, rn, rm, _)
        | ArmT32Instruction::Sxtah_T1(rd, rn, rm, _)
        | ArmT32Instruction::Uxtah_T1(rd, rn, rm, _)
        | ArmT32Instruction::Sxtab16_T1(rd, rn, rm, _)
        | ArmT32Instruction::Uxtab16_T1(rd, rn, rm, _)
        | ArmT32Instruction::Pkhbt_T1(rd, rn, rm, _)
        | ArmT32Instruction::Pkhtb_T1(rd, rn, rm, _)
        | ArmT32Instruction::Sel_T1(rd, rn, rm)
        | ArmT32Instruction::Usad8_T1(rd, rn, rm)
        | ArmT32Instruction::ParallelAddSub_T1(_, _, rd, rn, rm)
        | ArmT32Instruction::Smul_T1(rd, rn, rm, _, _)
        | ArmT32Instruction::Smulw_T1(rd, rn, rm, _)
        | ArmT32Instruction::Smuad_T1(rd, rn, rm, _)
        | ArmT32Instruction::Smusd_T1(rd, rn, rm, _)
        | ArmT32Instruction::Smmul_T1(rd, rn, rm, _) => {
            t32_linear(pc, length, set([gpr(*rn), gpr(*rm)]), set([gpr(*rd)]))
        }
        ArmT32Instruction::Mla_T1(rd, rn, rm, ra)
        | ArmT32Instruction::Mls_T1(rd, rn, rm, ra)
        | ArmT32Instruction::Usada8_T1(rd, rn, rm, ra)
        | ArmT32Instruction::Smla_T1(rd, rn, rm, ra, _, _)
        | ArmT32Instruction::Smlaw_T1(rd, rn, rm, ra, _)
        | ArmT32Instruction::Smlad_T1(rd, rn, rm, ra, _)
        | ArmT32Instruction::Smlsd_T1(rd, rn, rm, ra, _)
        | ArmT32Instruction::Smmla_T1(rd, rn, rm, ra, _)
        | ArmT32Instruction::Smmls_T1(rd, rn, rm, ra, _) => t32_linear(
            pc,
            length,
            set([gpr(*rn), gpr(*rm), gpr(*ra)]),
            set([gpr(*rd)]),
        ),
        ArmT32Instruction::Smull_T1(rdlo, rdhi, rn, rm)
        | ArmT32Instruction::Umull_T1(rdlo, rdhi, rn, rm)
        | ArmT32Instruction::Smlal_T1(rdlo, rdhi, rn, rm)
        | ArmT32Instruction::Umlal_T1(rdlo, rdhi, rn, rm)
        | ArmT32Instruction::Umaal_T1(rdlo, rdhi, rn, rm)
        | ArmT32Instruction::Smlal_Halfword_T1(rdlo, rdhi, rn, rm, _, _)
        | ArmT32Instruction::Smlald_T1(rdlo, rdhi, rn, rm, _)
        | ArmT32Instruction::Smlsld_T1(rdlo, rdhi, rn, rm, _) => t32_linear(
            pc,
            length,
            set([gpr(*rdlo), gpr(*rdhi), gpr(*rn), gpr(*rm)]),
            set([gpr(*rdlo), gpr(*rdhi)]),
        ),
        ArmT32Instruction::Msr_Register_T1(_, rn) => {
            t32_linear(pc, length, set([gpr(*rn)]), BTreeSet::new()).with_system(
                SystemEffect::PsrTransfer {
                    direction: SystemDirection::Write,
                    register: Some(gpr(*rn)),
                    mask: 0,
                    immediate: None,
                },
            )
        }
        ArmT32Instruction::LoadAcquire_T1(_, _, rt, rn)
        | ArmT32Instruction::UnprivLoadStore_T1(true, _, _, rt, rn, _) => {
            t32_linear(pc, length, set([gpr(*rn)]), set([gpr(*rt)]))
        }
        ArmT32Instruction::StoreRelease_T1(_, rt, rn)
        | ArmT32Instruction::UnprivLoadStore_T1(false, _, _, rt, rn, _) => {
            t32_linear(pc, length, set([gpr(*rt), gpr(*rn)]), BTreeSet::new())
        }
        ArmT32Instruction::StoreReleaseExclusive_T1(_, rd, rt, rn) => {
            t32_linear(pc, length, set([gpr(*rt), gpr(*rn)]), set([gpr(*rd)]))
        }
        ArmT32Instruction::Pld_Immediate_T1(rn, _) | ArmT32Instruction::Pli_Immediate_T1(rn, _) => {
            t32_linear(pc, length, set([gpr(*rn)]), BTreeSet::new())
        }
        ArmT32Instruction::Coproc_Mcr_T1(
            two,
            false,
            coprocessor,
            opcode1,
            rt,
            crn,
            crm,
            opcode2,
        ) => t32_linear(pc, length, set([gpr(*rt)]), BTreeSet::new()).with_system(system_transfer(
            SystemDirection::Write,
            *coprocessor,
            *opcode1,
            *rt,
            *crn,
            *crm,
            *opcode2,
            *two,
        )),
        ArmT32Instruction::Coproc_Mcr_T1(
            two,
            true,
            coprocessor,
            opcode1,
            rt,
            crn,
            crm,
            opcode2,
        ) => t32_linear(pc, length, BTreeSet::new(), set([gpr(*rt)])).with_system(system_transfer(
            SystemDirection::Read,
            *coprocessor,
            *opcode1,
            *rt,
            *crn,
            *crm,
            *opcode2,
            *two,
        )),
        ArmT32Instruction::Coproc_Mcrr_T1(_, false, _, _, rt, rt2, _) => {
            t32_linear(pc, length, set([gpr(*rt), gpr(*rt2)]), BTreeSet::new())
        }
        ArmT32Instruction::Coproc_Mcrr_T1(_, true, _, _, rt, rt2, _) => {
            t32_linear(pc, length, BTreeSet::new(), set([gpr(*rt), gpr(*rt2)]))
        }
        ArmT32Instruction::Coproc_Ldc_T1(_, _, _, _, _, rn, _) => {
            t32_linear(pc, length, set([gpr(*rn)]), BTreeSet::new())
        }
        ArmT32Instruction::Coproc_Cdp_T1(_, _, _, _, _, _, _) => {
            t32_linear(pc, length, BTreeSet::new(), BTreeSet::new())
        }
        ArmT32Instruction::PacbtiHint_T1(0) => {
            t32_linear(pc, length, BTreeSet::new(), BTreeSet::new())
        }
        ArmT32Instruction::PacbtiHint_T1(_) => {
            t32_linear(pc, length, set([SP, LR]), set([Register(12)]))
        }
        ArmT32Instruction::PacbtiData_T1(2, rd, rn, rm) => t32_barrier(
            pc,
            length,
            set([gpr(*rd), gpr(*rn), gpr(*rm)]),
            BTreeSet::new(),
        ),
        ArmT32Instruction::PacbtiData_T1(_, rd, rn, rm) => {
            t32_linear(pc, length, set([gpr(*rn), gpr(*rm)]), set([gpr(*rd)]))
        }
        ArmT32Instruction::Cde_Cx1_T1(_, dual, _, rd, _) => {
            let mut writes = set([gpr(*rd)]);
            if *dual && let Some(pair) = pair_reg(gpr(*rd)) {
                writes.insert(pair);
            }
            t32_linear(pc, length, BTreeSet::new(), writes)
        }
        ArmT32Instruction::Cde_Cx2_T1(_, dual, _, rd, rn, _) => {
            let mut writes = set([gpr(*rd)]);
            if *dual && let Some(pair) = pair_reg(gpr(*rd)) {
                writes.insert(pair);
            }
            t32_linear(pc, length, set([gpr(*rn)]), writes)
        }
        ArmT32Instruction::Cde_Cx3_T1(_, dual, _, rd, rn, rm, _) => {
            let mut writes = set([gpr(*rd)]);
            if *dual && let Some(pair) = pair_reg(gpr(*rd)) {
                writes.insert(pair);
            }
            t32_linear(pc, length, set([gpr(*rn), gpr(*rm)]), writes)
        }
        ArmT32Instruction::Bf_T1(_, _)
        | ArmT32Instruction::Bfl_T4(_, _)
        | ArmT32Instruction::Bfcsel_T2(_, _, _, _) => {
            t32_barrier(pc, length, BTreeSet::new(), BTreeSet::new())
        }
        ArmT32Instruction::Bfx_T3(_, rn) | ArmT32Instruction::Bflx_T5(_, rn) => {
            t32_barrier(pc, length, set([gpr(*rn)]), BTreeSet::new())
        }
        // Plain DLS/WLS/LE need only LOB, not MVE. LR is the implicit loop
        // register. DLS copies Rn→LR and continues; WLS does the same then
        // either falls into the body or skips it (Linear keeps the body and
        // other GPR facts; Call would wipe the fallthrough like BL). LE
        // decrements LR and either loops back or exits — Linear so the exit
        // path stays reachable. Tail-predicated DLSTP/WLSTP/LETP and LCTP
        // stay on `_` as MVE.
        ArmT32Instruction::LobStart(_, None, rn, _) => {
            t32_linear(pc, length, set([gpr(*rn)]), set([LR]))
        }
        ArmT32Instruction::LobEnd(false, _) => t32_linear(pc, length, set([LR]), set([LR])),
        ArmT32Instruction::Csel_T1(_, rd, rn, rm, _) => {
            t32_linear(pc, length, set([gpr(*rn), gpr(*rm)]), set([gpr(*rd)]))
        }
        ArmT32Instruction::Clrm_T1(list) => {
            t32_linear(pc, length, BTreeSet::new(), clrm_writes(*list))
        }
        ArmT32Instruction::LongShiftImm_T1(_, lo, hi, _)
        | ArmT32Instruction::SatShiftLongImm_T1(_, lo, hi, _) => t32_linear(
            pc,
            length,
            set([gpr(*lo), gpr(*hi)]),
            set([gpr(*lo), gpr(*hi)]),
        ),
        ArmT32Instruction::LongShiftReg_T1(_, lo, hi, rm)
        | ArmT32Instruction::SatShiftLongReg_T1(_, lo, hi, rm, _) => t32_linear(
            pc,
            length,
            set([gpr(*lo), gpr(*hi), gpr(*rm)]),
            set([gpr(*lo), gpr(*hi)]),
        ),
        ArmT32Instruction::SatShiftImm_T1(_, rda, _) => {
            t32_linear(pc, length, set([gpr(*rda)]), set([gpr(*rda)]))
        }
        ArmT32Instruction::SatShiftReg_T1(_, rda, rm) => {
            t32_linear(pc, length, set([gpr(*rda), gpr(*rm)]), set([gpr(*rda)]))
        }
        ArmT32Instruction::Tt_T1(rd, rn, _, _) => {
            t32_linear(pc, length, set([gpr(*rn)]), set([gpr(*rd)]))
        }
        ArmT32Instruction::Csdb_T1
        | ArmT32Instruction::Dbg_T1(_)
        | ArmT32Instruction::Esb_T1
        | ArmT32Instruction::Ssbb_T1
        | ArmT32Instruction::Pssbb_T1
        | ArmT32Instruction::Sb_T1
        | ArmT32Instruction::Sg_T1 => t32_linear(pc, length, BTreeSet::new(), BTreeSet::new()),
        ArmT32Instruction::Bxns_T1(rm) => t32_barrier(pc, length, set([gpr(*rm)]), BTreeSet::new()),
        ArmT32Instruction::Blxns_T1(rm) => insn(
            Isa::Thumb,
            pc,
            length,
            false,
            set([gpr(*rm)]),
            BTreeSet::new(),
            ValueEffect::None,
            ControlFlow::Barrier,
        )
        .with_link(),
        ArmT32Instruction::Nop_T1
        | ArmT32Instruction::Yield_T1
        | ArmT32Instruction::Wfe_T1
        | ArmT32Instruction::Wfi_T1
        | ArmT32Instruction::Sev_T1
        | ArmT32Instruction::Dmb_T1(_)
        | ArmT32Instruction::Dsb_T1(_)
        | ArmT32Instruction::Isb_T1(_)
        | ArmT32Instruction::Clrex_T1
        | ArmT32Instruction::Cps_T1(_)
        | ArmT32Instruction::Setpan_T1(_) => {
            t32_linear(pc, length, BTreeSet::new(), BTreeSet::new())
        }
        ArmT32Instruction::Tbb_T1(rn, rm) | ArmT32Instruction::Tbh_T1(rn, rm) => {
            t32_barrier(pc, length, set([gpr(*rn), gpr(*rm)]), BTreeSet::new())
        }
        ArmT32Instruction::Bkpt_T1(_)
        | ArmT32Instruction::Hlt_T1(_)
        | ArmT32Instruction::Udf_T1(_)
        | ArmT32Instruction::Udf_T2(_) => t32_barrier(pc, length, BTreeSet::new(), BTreeSet::new()),
        _ => unsupported(
            Isa::Thumb,
            pc,
            length,
            false,
            BTreeSet::new(),
            all_core_registers(),
            ControlFlow::Barrier,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::execution_ranges::DecodeIsa as Isa;
    use scaleservers_arm32_assembly::{
        Arm32Condition, Arm32GeneralPurposeRegister, Arm32LowGeneralPurposeRegister,
        Arm32RegisterShift, ArmA32Instruction, ArmT32Instruction, ArmT32SpecialRegister,
    };
    use std::collections::BTreeSet;

    const R0: Register = Register(0);
    const R1: Register = Register(1);
    const R2: Register = Register(2);
    const R3: Register = Register(3);
    const R9: Register = Register(9);
    const R12: Register = Register(12);
    const LR: Register = Register(14);
    const SP: Register = Register(13);
    const PC: Register = Register(15);

    fn decode(isa: Isa, pc: u32, bytes: &[u8]) -> DecodedInstruction {
        let decoder = PureRustDecoder;
        let mut state = decoder.begin_range(isa);
        decoder
            .decode_one(&mut state, isa, pc, bytes)
            .expect("fixture must decode")
    }

    fn decode_t32(pc: u32, inst: &ArmT32Instruction) -> DecodedInstruction {
        decode(Isa::Thumb, pc, &inst.encode().expect("fixture encodes"))
    }

    fn decode_a32(pc: u32, inst: &ArmA32Instruction) -> DecodedInstruction {
        decode(Isa::Arm, pc, &inst.encode().expect("fixture encodes"))
    }

    fn regs(values: &[Register]) -> BTreeSet<Register> {
        values.iter().copied().collect()
    }

    fn gpr(number: u8) -> Arm32GeneralPurposeRegister {
        Arm32GeneralPurposeRegister::from_operand_bits(number)
    }

    fn low(number: u8) -> Arm32LowGeneralPurposeRegister {
        Arm32LowGeneralPurposeRegister::from_operand_bits(number)
    }

    fn always() -> Arm32Condition {
        Arm32Condition::AlwaysUnconditional
    }

    fn transfer_of(effect: &ValueEffect) -> Option<&MemoryTransfer> {
        match effect {
            ValueEffect::Memory(effect) => effect.transfers.first(),
            _ => None,
        }
    }

    #[test]
    fn a32_vbar_write_preserves_every_system_operand() {
        // `mcr p15, #0, r0, c12, c0, #0` (0xee0c0f10).
        let insn = super::decode_a32(0x1000, &[0x10, 0x0f, 0x0c, 0xee]).unwrap();
        assert_eq!(
            insn.system,
            SystemEffect::CoprocessorTransfer(CoprocessorTransfer {
                direction: SystemDirection::Write,
                coprocessor: 15,
                opcode1: 0,
                rt: Register(0),
                crn: 12,
                crm: 0,
                opcode2: 0,
                unconditional_extension: false,
            })
        );
        assert!(insn.system.transfer().unwrap().is_vbar_write());
        assert_eq!(insn.effect, ValueEffect::Unsupported);
        assert_eq!(insn.reads, regs(&[R0]));
        assert!(insn.writes.is_empty());
        assert_eq!(insn.flags, FlagEffect::Clobbered);
        assert_eq!(insn.flow, ControlFlow::Linear);
    }

    #[test]
    fn a32_mrc_preserves_read_direction_and_every_system_operand() {
        // `mrcne p14, #0, r0, c1, c2, #3` (0x1e110e72).
        let insn = super::decode_a32(0x1000, &[0x72, 0x0e, 0x11, 0x1e]).unwrap();
        assert_eq!(
            insn.system,
            SystemEffect::CoprocessorTransfer(CoprocessorTransfer {
                direction: SystemDirection::Read,
                coprocessor: 14,
                opcode1: 0,
                rt: Register(0),
                crn: 1,
                crm: 2,
                opcode2: 3,
                unconditional_extension: false,
            })
        );
        assert!(!insn.system.transfer().unwrap().is_vbar_write());
        assert!(insn.reads.is_empty());
        assert_eq!(insn.writes, regs(&[R0]));
        assert_eq!(insn.effect, ValueEffect::Unsupported);
        assert_eq!(insn.flags, FlagEffect::Clobbered);
        assert!(insn.conditional);
        assert_eq!(insn.flow, ControlFlow::Linear);
    }

    #[test]
    fn a32_extension_transfers_preserve_direction_and_every_system_operand() {
        // `mcr2 p9, #3, r8, c4, c5, #2` (0xfe648955).
        let write = super::decode_a32(0x1000, &[0x55, 0x89, 0x64, 0xfe]).unwrap();
        assert_eq!(
            write.system,
            SystemEffect::CoprocessorTransfer(CoprocessorTransfer {
                direction: SystemDirection::Write,
                coprocessor: 9,
                opcode1: 3,
                rt: Register(8),
                crn: 4,
                crm: 5,
                opcode2: 2,
                unconditional_extension: true,
            })
        );
        assert_eq!(write.reads, regs(&[Register(8)]));
        assert!(write.writes.is_empty());
        assert_eq!(write.effect, ValueEffect::Unsupported);
        assert_eq!(write.flags, FlagEffect::Clobbered);
        assert_eq!(write.flow, ControlFlow::Linear);

        // `mrc2 p14, #7, r6, c1, c2, #5` (0xfef16eb2).
        let read = super::decode_a32(0x1004, &[0xb2, 0x6e, 0xf1, 0xfe]).unwrap();
        assert_eq!(
            read.system,
            SystemEffect::CoprocessorTransfer(CoprocessorTransfer {
                direction: SystemDirection::Read,
                coprocessor: 14,
                opcode1: 7,
                rt: Register(6),
                crn: 1,
                crm: 2,
                opcode2: 5,
                unconditional_extension: true,
            })
        );
        assert!(read.reads.is_empty());
        assert_eq!(read.writes, regs(&[Register(6)]));
        assert_eq!(read.effect, ValueEffect::Unsupported);
        assert_eq!(read.flags, FlagEffect::Clobbered);
        assert_eq!(read.flow, ControlFlow::Linear);
    }

    #[test]
    fn t32_mrc_direction_and_extension_are_not_collapsed() {
        // `mrc p15, #0, r1, c0, c0, #0`.
        let insn = super::decode_t32(
            &mut ItRangeState::default(),
            0x2000,
            &[0x10, 0xee, 0x10, 0x1f],
        )
        .unwrap();
        let transfer = insn.system.transfer().expect("coprocessor transfer");
        assert_eq!(transfer.direction, SystemDirection::Read);
        assert_eq!(transfer.coprocessor, 15);
        assert_eq!(transfer.rt, Register(1));
        assert_eq!(transfer.opcode1, 0);
        assert_eq!(transfer.crn, 0);
        assert_eq!(transfer.crm, 0);
        assert_eq!(transfer.opcode2, 0);
        assert!(!transfer.unconditional_extension);
        assert!(!transfer.is_vbar_write());
        assert!(insn.reads.is_empty());
        assert_eq!(insn.writes, regs(&[R1]));
        assert_eq!(insn.effect, ValueEffect::Unsupported);
        assert_eq!(insn.flags, FlagEffect::Clobbered);
        assert_eq!(insn.flow, ControlFlow::Linear);
    }

    #[test]
    fn t32_extension_transfers_preserve_direction_and_every_system_operand() {
        // `mcr2 p14, #1, r2, c3, c4, #2`.
        let write = super::decode_t32(
            &mut ItRangeState::default(),
            0x2000,
            &[0x23, 0xfe, 0x54, 0x2e],
        )
        .unwrap();
        assert_eq!(
            write.system,
            SystemEffect::CoprocessorTransfer(CoprocessorTransfer {
                direction: SystemDirection::Write,
                coprocessor: 14,
                opcode1: 1,
                rt: Register(2),
                crn: 3,
                crm: 4,
                opcode2: 2,
                unconditional_extension: true,
            })
        );
        assert_eq!(write.reads, regs(&[R2]));
        assert!(write.writes.is_empty());
        assert_eq!(write.effect, ValueEffect::Unsupported);
        assert_eq!(write.flags, FlagEffect::Clobbered);
        assert_eq!(write.flow, ControlFlow::Linear);

        // `mrc2 p14, #7, r6, c1, c2, #5`.
        let read = super::decode_t32(
            &mut ItRangeState::default(),
            0x2004,
            &[0xf1, 0xfe, 0xb2, 0x6e],
        )
        .unwrap();
        assert_eq!(
            read.system,
            SystemEffect::CoprocessorTransfer(CoprocessorTransfer {
                direction: SystemDirection::Read,
                coprocessor: 14,
                opcode1: 7,
                rt: Register(6),
                crn: 1,
                crm: 2,
                opcode2: 5,
                unconditional_extension: true,
            })
        );
        assert!(read.reads.is_empty());
        assert_eq!(read.writes, regs(&[Register(6)]));
        assert_eq!(read.effect, ValueEffect::Unsupported);
        assert_eq!(read.flags, FlagEffect::Clobbered);
        assert_eq!(read.flow, ControlFlow::Linear);
    }

    #[test]
    fn mrs_a1_is_psr_transfer_read() {
        let insn = decode_a32(0x1000, &ArmA32Instruction::Mrs_A1(always(), false, gpr(0)));
        assert_eq!(
            insn.system,
            SystemEffect::PsrTransfer {
                direction: SystemDirection::Read,
                register: Some(R0),
                mask: 0,
                immediate: None,
            }
        );
        assert_eq!(insn.writes, regs(&[R0]));
        assert!(insn.reads.is_empty());
    }

    #[test]
    fn msr_register_a1_is_psr_transfer_write() {
        let insn = decode_a32(
            0x1000,
            &ArmA32Instruction::Msr_Register_A1(always(), false, 0b1000, gpr(1)),
        );
        assert_eq!(
            insn.system,
            SystemEffect::PsrTransfer {
                direction: SystemDirection::Write,
                register: Some(R1),
                mask: 0b1000,
                immediate: None,
            }
        );
        assert_eq!(insn.reads, regs(&[R1]));
        assert!(insn.writes.is_empty());
    }

    #[test]
    fn msr_immediate_a1_is_psr_transfer_write() {
        let insn = decode_a32(
            0x1000,
            &ArmA32Instruction::Msr_Immediate_A1(always(), false, 0b1000, 0xF000_0000),
        );
        assert_eq!(
            insn.system,
            SystemEffect::PsrTransfer {
                direction: SystemDirection::Write,
                register: None,
                mask: 0b1000,
                immediate: Some(0xF000_0000),
            }
        );
        assert!(insn.reads.is_empty());
        assert!(insn.writes.is_empty());
    }

    #[test]
    fn mrs_t1_is_psr_transfer_read() {
        let insn = decode_t32(
            0x2000,
            &ArmT32Instruction::Mrs_T1(gpr(0), ArmT32SpecialRegister::Apsr),
        );
        assert_eq!(
            insn.system,
            SystemEffect::PsrTransfer {
                direction: SystemDirection::Read,
                register: Some(R0),
                mask: 0,
                immediate: None,
            }
        );
        assert_eq!(insn.writes, regs(&[R0]));
        assert!(insn.reads.is_empty());
    }

    #[test]
    fn msr_register_t1_is_psr_transfer_write() {
        let insn = decode_t32(
            0x2000,
            &ArmT32Instruction::Msr_Register_T1(ArmT32SpecialRegister::Apsr, gpr(1)),
        );
        assert_eq!(
            insn.system,
            SystemEffect::PsrTransfer {
                direction: SystemDirection::Write,
                register: Some(R1),
                mask: 0,
                immediate: None,
            }
        );
        assert_eq!(insn.reads, regs(&[R1]));
        assert!(insn.writes.is_empty());
    }

    #[test]
    fn compare_instructions_expose_operands_and_flag_writer() {
        // A32 `cmp r1, #0`: subtract-compare of r1 against 0, no register
        // result, NZCV written from the operands.
        let insn = decode(Isa::Arm, 0x1000, &[0x00, 0x00, 0x51, 0xe3]);
        assert_eq!(
            insn.effect,
            ValueEffect::Compare {
                operation: CompareOp::Subtract,
                left: R1,
                right: Operand::Immediate(0),
            }
        );
        assert_eq!(insn.reads, regs(&[R1]));
        assert!(insn.writes.is_empty());
        assert_eq!(insn.flags, FlagEffect::Written(FlagWriter::Compare));
        assert!(matches!(insn.flow, ControlFlow::Linear));

        // A32 `cmp r1, r2, lsl #2`: the register right operand keeps its
        // decoded shift.
        let insn = decode_a32(
            0x1000,
            &ArmA32Instruction::Cmp_Register_A1(
                always(),
                gpr(1),
                gpr(2),
                Arm32RegisterShift::Lsl(2),
            ),
        );
        assert_eq!(
            insn.effect,
            ValueEffect::Compare {
                operation: CompareOp::Subtract,
                left: R1,
                right: Operand::Register {
                    register: R2,
                    shift: Shift::Lsl(2),
                },
            }
        );
        assert_eq!(insn.reads, regs(&[R1, R2]));

        // T32 `cmp r1, #5` and `cmp r1, r2`.
        let insn = decode_t32(0x1000, &ArmT32Instruction::Cmp_Immediate_T1(low(1), 5));
        assert_eq!(
            insn.effect,
            ValueEffect::Compare {
                operation: CompareOp::Subtract,
                left: R1,
                right: Operand::Immediate(5),
            }
        );
        assert_eq!(insn.reads, regs(&[R1]));
        let insn = decode_t32(0x1000, &ArmT32Instruction::Cmp_Register_T1(low(1), low(2)));
        assert_eq!(
            insn.effect,
            ValueEffect::Compare {
                operation: CompareOp::Subtract,
                left: R1,
                right: Operand::Register {
                    register: R2,
                    shift: Shift::Lsl(0),
                },
            }
        );
        assert_eq!(insn.reads, regs(&[R1, R2]));

        // TST/CMN/TEQ preserve their operation on the same operand shape.
        let insn = decode_a32(
            0x1000,
            &ArmA32Instruction::Tst_Immediate_A1(always(), gpr(0), 1),
        );
        assert_eq!(
            insn.effect,
            ValueEffect::Compare {
                operation: CompareOp::And,
                left: R0,
                right: Operand::Immediate(1),
            }
        );
        let insn = decode_a32(
            0x1000,
            &ArmA32Instruction::Cmn_Immediate_A1(always(), gpr(1), 4),
        );
        assert_eq!(
            insn.effect,
            ValueEffect::Compare {
                operation: CompareOp::Add,
                left: R1,
                right: Operand::Immediate(4),
            }
        );
        let insn = decode_t32(0x1000, &ArmT32Instruction::Teq_Immediate_T1(gpr(1), 2));
        assert_eq!(
            insn.effect,
            ValueEffect::Compare {
                operation: CompareOp::ExclusiveOr,
                left: R1,
                right: Operand::Immediate(2),
            }
        );
        assert_eq!(insn.flags, FlagEffect::Written(FlagWriter::Compare));
    }

    #[test]
    fn shift_effects_preserve_destination_source_and_amount() {
        // T32 `lsrs r0, r1, #4` (flag-setting T1 form).
        let insn = decode_t32(
            0x1000,
            &ArmT32Instruction::Lsr_Immediate_T1(low(0), low(1), 4),
        );
        assert_eq!(
            insn.effect,
            ValueEffect::Shift {
                dst: R0,
                source: R1,
                shift: Shift::Lsr(4),
            }
        );
        assert_eq!(insn.reads, regs(&[R1]));
        assert_eq!(insn.writes, regs(&[R0]));
        assert_eq!(insn.flags, FlagEffect::Clobbered);

        // T32 `lsr.w r2, r3, #8` (non-flag-setting MOV_T3 shift form).
        let insn = decode_t32(
            0x1000,
            &ArmT32Instruction::Mov_Register_T3(gpr(2), gpr(3), Arm32RegisterShift::Lsr(8), false),
        );
        assert_eq!(
            insn.effect,
            ValueEffect::Shift {
                dst: R2,
                source: R3,
                shift: Shift::Lsr(8),
            }
        );
        assert_eq!(insn.flags, FlagEffect::Preserved);

        // A32 `mov r2, r3, lsl #2` / `movs r2, r3, asr #1`.
        let insn = decode_a32(
            0x1000,
            &ArmA32Instruction::Mov_Register_A1(
                always(),
                false,
                gpr(2),
                gpr(3),
                Arm32RegisterShift::Lsl(2),
            ),
        );
        assert_eq!(
            insn.effect,
            ValueEffect::Shift {
                dst: R2,
                source: R3,
                shift: Shift::Lsl(2),
            }
        );
        assert_eq!(insn.flags, FlagEffect::Preserved);
        let insn = decode_a32(
            0x1000,
            &ArmA32Instruction::Mov_Register_A1(
                always(),
                true,
                gpr(2),
                gpr(3),
                Arm32RegisterShift::Asr(1),
            ),
        );
        assert_eq!(
            insn.effect,
            ValueEffect::Shift {
                dst: R2,
                source: R3,
                shift: Shift::Asr(1),
            }
        );
        assert_eq!(insn.flags, FlagEffect::Clobbered);
    }

    #[test]
    fn memory_transfers_carry_explicit_value_registers() {
        // T32 `ldr r0, [r1, #4]`: load destination recorded on the transfer.
        let insn = decode(Isa::Thumb, 0x1000, &[0x48, 0x68]);
        let transfer = transfer_of(&insn.effect).expect("load has a transfer");
        assert_eq!(transfer.kind, AccessKind::Read);
        assert_eq!(transfer.width, 4);
        assert_eq!(transfer.value, Some(R0));
        assert_eq!(transfer.address.base, AddressBase::Register(R1));
        assert_eq!(transfer.address.offset, AddressOffset::Immediate(4));

        // T32 `str r0, [r1, #4]`: store source recorded on the transfer.
        let insn = decode(Isa::Thumb, 0x1000, &[0x48, 0x60]);
        let transfer = transfer_of(&insn.effect).expect("store has a transfer");
        assert_eq!(transfer.kind, AccessKind::Write);
        assert_eq!(transfer.value, Some(R0));
        assert_eq!(insn.writes, BTreeSet::new());

        // A32 `ldm r0, {r1, r2}`: one transfer per register, each carrying
        // its own destination.
        let insn = decode(Isa::Arm, 0x1000, &[0x06, 0x00, 0x90, 0xe8]);
        match &insn.effect {
            ValueEffect::Memory(effect) => {
                assert_eq!(effect.transfers.len(), 2);
                assert_eq!(effect.transfers[0].value, Some(R1));
                assert_eq!(effect.transfers[1].value, Some(R2));
            }
            other => panic!("expected memory effect, got {other:?}"),
        }

        // A32 `strex r2, r0, [r1]`: stored source r0, plus the separate
        // status destination r2.
        let insn = decode(Isa::Arm, 0x1000, &[0x90, 0x2f, 0x81, 0xe1]);
        let transfer = transfer_of(&insn.effect).expect("strex has a transfer");
        assert_eq!(transfer.kind, AccessKind::Write);
        assert_eq!(transfer.value, Some(R0));
        assert_eq!(insn.writes, regs(&[R2]));
    }

    #[test]
    fn cbz_and_cbnz_expose_register_zero_polarity() {
        // `cbz r1, +8` at 0x1000: branches to 0x100c when r1 is zero and
        // falls through to 0x1002 otherwise.
        let insn = decode_t32(0x1000, &ArmT32Instruction::Cbz_T1(low(1), 8));
        assert_eq!(
            insn.flow,
            ControlFlow::DirectBranch {
                target: 0x100c,
                fallthrough: Some(0x1002),
                predicate: BranchPredicate::RegisterZero {
                    register: R1,
                    nonzero: false,
                },
            }
        );
        assert_eq!(insn.reads, regs(&[R1]));

        // `cbnz r2, +4`: same shape, opposite polarity.
        let insn = decode_t32(0x1000, &ArmT32Instruction::Cbnz_T1(low(2), 4));
        assert_eq!(
            insn.flow,
            ControlFlow::DirectBranch {
                target: 0x1008,
                fallthrough: Some(0x1002),
                predicate: BranchPredicate::RegisterZero {
                    register: R2,
                    nonzero: true,
                },
            }
        );
    }

    #[test]
    fn conditional_branches_preserve_architectural_conditions() {
        // A32 `bhi +8`: unsigned-higher condition with an architectural
        // fallthrough.
        let insn = decode_a32(
            0x1000,
            &ArmA32Instruction::B_A1(Arm32Condition::UnsignedHigher, 8),
        );
        assert_eq!(
            insn.flow,
            ControlFlow::DirectBranch {
                target: 0x1010,
                fallthrough: Some(0x1004),
                predicate: BranchPredicate::Condition(Arm32Condition::UnsignedHigher),
            }
        );

        // A32 `b +0`: unconditional, so no fallthrough and no condition.
        let insn = decode_a32(0x1000, &ArmA32Instruction::B_A1(always(), 0));
        assert_eq!(
            insn.flow,
            ControlFlow::DirectBranch {
                target: 0x1008,
                fallthrough: None,
                predicate: BranchPredicate::Always,
            }
        );

        // T32 `beq +0` keeps its condition code and fallthrough.
        let insn = decode_t32(0x1000, &ArmT32Instruction::B_T1(Arm32Condition::Equal, 0));
        assert_eq!(
            insn.flow,
            ControlFlow::DirectBranch {
                target: 0x1004,
                fallthrough: Some(0x1002),
                predicate: BranchPredicate::Condition(Arm32Condition::Equal),
            }
        );
    }

    #[test]
    fn flag_effects_are_written_preserved_or_clobbered() {
        // Compare writes NZCV from its own operands.
        let insn = decode(Isa::Arm, 0x1000, &[0x00, 0x00, 0x51, 0xe3]);
        assert_eq!(insn.flags, FlagEffect::Written(FlagWriter::Compare));

        // Non-flag-setting modeled data ops preserve NZCV.
        for bytes in [
            &[0x34, 0x02, 0x01, 0xe3][..], // a32 movw
            &[0x04, 0x00, 0x81, 0xe2][..], // a32 add (no S)
            &[0x04, 0x00, 0x91, 0xe5][..], // a32 ldr
            &[0x04, 0x00, 0x81, 0xe5][..], // a32 str
        ] {
            let insn = decode(Isa::Arm, 0x1000, bytes);
            assert_eq!(insn.flags, FlagEffect::Preserved, "{bytes:02x?}");
        }

        // Flag-setting narrow Thumb forms and unsupported data processing
        // clobber NZCV.
        for (isa, bytes) in [
            (Isa::Thumb, &[0x01, 0x20][..]), // t32 movs
            (Isa::Thumb, &[0x88, 0x00][..]), // t32 lsls
        ] {
            let insn = decode(isa, 0x1000, bytes);
            assert_eq!(insn.flags, FlagEffect::Clobbered, "{bytes:02x?}");
        }
        let insn = decode(Isa::Arm, 0x1000, &[0x01, 0x00, 0x01, 0xe2]); // a32 and (unsupported)
        assert_eq!(insn.flags, FlagEffect::Clobbered);
    }

    #[test]
    fn r15_writes_classify_as_barriers_before_value_mapping() {
        // A32 `mov pc, r1`: the R15 write is a barrier, and the value
        // mapping is still recorded.
        let insn = decode(Isa::Arm, 0x1000, &[0x01, 0xf0, 0xa0, 0xe1]);
        assert!(matches!(insn.flow, ControlFlow::Barrier));
        assert_eq!(
            insn.effect,
            ValueEffect::RegisterWrite {
                dst: PC,
                value: ValueExpr::Register(R1),
            }
        );

        // A32 `ldr pc, [r1]`: barrier, with the memory transfer retained.
        let insn = decode(Isa::Arm, 0x1000, &[0x00, 0xf0, 0x91, 0xe5]);
        assert!(matches!(insn.flow, ControlFlow::Barrier));
        let transfer = transfer_of(&insn.effect).expect("pc load keeps its transfer");
        assert_eq!(transfer.kind, AccessKind::Read);
        assert_eq!(transfer.value, Some(PC));

        // T32 `pop {r0, pc}`: barrier, both transfers retained.
        let insn = decode(Isa::Thumb, 0x1000, &[0x01, 0xbd]);
        assert!(matches!(insn.flow, ControlFlow::Barrier));
        match &insn.effect {
            ValueEffect::Memory(effect) => assert_eq!(effect.transfers.len(), 2),
            other => panic!("expected memory effect, got {other:?}"),
        }
        assert_eq!(insn.writes, regs(&[SP, R0, PC]));

        // A32 `add pc, r1, r2`: barrier despite the modeled add value.
        let insn = decode_a32(
            0x1000,
            &ArmA32Instruction::Add_Register_A1(
                always(),
                false,
                gpr(15),
                gpr(1),
                gpr(2),
                Arm32RegisterShift::none(),
            ),
        );
        assert!(matches!(insn.flow, ControlFlow::Barrier));
        assert_eq!(
            insn.effect,
            ValueEffect::RegisterWrite {
                dst: PC,
                value: ValueExpr::Add {
                    left: R1,
                    right: Operand::Register {
                        register: R2,
                        shift: Shift::Lsl(0),
                    },
                },
            }
        );
    }

    #[test]
    fn it_block_governs_and_table_branches_stay_unresolved() {
        // `it eq` itself is linear; the governed `movs` (decoded through the
        // same range state) is conditional.
        let decoder = PureRustDecoder;
        let mut state = decoder.begin_range(Isa::Thumb);
        let it = decoder
            .decode_one(&mut state, Isa::Thumb, 0x1000, &[0x08, 0xbf])
            .expect("fixture must decode");
        assert!(matches!(it.flow, ControlFlow::Linear));
        assert_eq!(it.effect, ValueEffect::None);
        let movs = decoder
            .decode_one(&mut state, Isa::Thumb, 0x1002, &[0x01, 0x20])
            .expect("fixture must decode");
        assert!(movs.conditional);

        // Table branches are unresolved control transfers: barriers.
        let insn = decode_t32(0x1000, &ArmT32Instruction::Tbb_T1(gpr(1), gpr(2)));
        assert!(matches!(insn.flow, ControlFlow::Barrier));
        assert_eq!(insn.effect, ValueEffect::Unsupported);
        assert_eq!(insn.reads, regs(&[R1, R2]));
        let insn = decode_t32(0x1000, &ArmT32Instruction::Tbh_T1(gpr(1), gpr(2)));
        assert!(matches!(insn.flow, ControlFlow::Barrier));
    }

    #[test]
    fn direct_calls_retain_decoded_targets_and_link() {
        // A32 `bl +0x10` at 0x1000: entry 0x1018, LR receives the return
        // address.
        let insn = decode(Isa::Arm, 0x1000, &[0x04, 0x00, 0x00, 0xeb]);
        assert_eq!(insn.flow, ControlFlow::DirectCall { target: 0x1018 });
        assert!(insn.links_lr);

        // T32 `bl +0` at 0x1000: entry 0x1004.
        let insn = decode(Isa::Thumb, 0x1000, &[0x00, 0xf0, 0x00, 0xf8]);
        assert_eq!(insn.flow, ControlFlow::DirectCall { target: 0x1004 });
        assert!(insn.links_lr);
    }

    #[test]
    fn call_boundary_volatility_is_aapcs_with_shannonos_r9() {
        // At either call boundary R0-R3, R12, and LR become unknown and
        // NZCV becomes unknown; R4-R11 (including the ShannonOS platform
        // register R9) and SP survive.
        let boundary = ControlFlow::DirectCall { target: 0x2000 }
            .call_boundary(true)
            .expect("direct call has a boundary");
        assert_eq!(boundary.volatile, regs(&[R0, R1, R2, R3, R12, LR]));
        assert!(boundary.flags_unknown);
        for number in 4u8..=11 {
            assert!(!boundary.volatile.contains(&Register(number)), "r{number}");
        }
        assert!(!boundary.volatile.contains(&R9));
        assert!(!boundary.volatile.contains(&SP));

        // The exception-call boundary carries the same contract.
        let boundary = ControlFlow::ExceptionCall
            .call_boundary(false)
            .expect("exception call has a boundary");
        assert_eq!(boundary.volatile, regs(&[R0, R1, R2, R3, R12, LR]));
        assert!(boundary.flags_unknown);

        // A linked barrier (indirect call) is a call boundary too.
        let boundary = ControlFlow::Barrier
            .call_boundary(true)
            .expect("linked barrier is a call");
        assert!(boundary.flags_unknown);

        // Non-call flows never claim the boundary contract.
        assert!(ControlFlow::Linear.call_boundary(false).is_none());
        assert!(ControlFlow::Return.call_boundary(false).is_none());
        assert!(ControlFlow::Barrier.call_boundary(false).is_none());
        assert!(
            ControlFlow::DirectBranch {
                target: 0,
                fallthrough: Some(4),
                predicate: BranchPredicate::Always,
            }
            .call_boundary(false)
            .is_none()
        );
    }

    #[test]
    fn returns_and_indirect_transfers_are_distinct() {
        // `bx lr` is the canonical return in both ISAs.
        let insn = decode(Isa::Arm, 0x1000, &[0x1e, 0xff, 0x2f, 0xe1]);
        assert!(matches!(insn.flow, ControlFlow::Return));
        assert_eq!(insn.reads, regs(&[LR]));
        let insn = decode(Isa::Thumb, 0x1000, &[0x70, 0x47]);
        assert!(matches!(insn.flow, ControlFlow::Return));

        // `bx r3` is an unresolved register transfer: a barrier without a
        // link.
        let insn = decode_a32(0x1000, &ArmA32Instruction::Bx_A1(always(), gpr(3)));
        assert!(matches!(insn.flow, ControlFlow::Barrier));
        assert!(!insn.links_lr);

        // `blx r0` is an indirect call: a barrier that links LR.
        let insn = decode(Isa::Arm, 0x1000, &[0x30, 0xff, 0x2f, 0xe1]);
        assert!(matches!(insn.flow, ControlFlow::Barrier));
        assert!(insn.links_lr);

        // A32 `blx <imm>` switches ISA; its target stays unresolved, but it
        // still links.
        let insn = decode_a32(0x1000, &ArmA32Instruction::Blx_Immediate_A1(8));
        assert!(matches!(insn.flow, ControlFlow::Barrier));
        assert!(insn.links_lr);

        // `blxns r0` is also a linked indirect call.
        let insn = decode_t32(0x1000, &ArmT32Instruction::Blxns_T1(gpr(0)));
        assert!(matches!(insn.flow, ControlFlow::Barrier));
        assert!(insn.links_lr);
    }

    #[test]
    fn svc_is_a_returning_exception_call() {
        // SVC raises a call into the handler with an ordinary architectural
        // return site; no handler result is synthesized, so nothing is
        // read or written at the instruction itself.
        let insn = decode_a32(0x1000, &ArmA32Instruction::Svc_A1(always(), 0));
        assert!(matches!(insn.flow, ControlFlow::ExceptionCall));
        assert_eq!(insn.effect, ValueEffect::None);
        assert!(insn.reads.is_empty());
        assert!(insn.writes.is_empty());
        assert!(
            ControlFlow::ExceptionCall
                .call_boundary(insn.links_lr)
                .is_some()
        );

        let insn = decode_t32(0x1000, &ArmT32Instruction::Svc_T1(0));
        assert!(matches!(insn.flow, ControlFlow::ExceptionCall));
    }

    // Mirror of the production `insn()` flag-defaulting above, kept
    // deliberately independent so a bug introduced in `insn()` cannot
    // self-hide by making both sides agree; update both consciously.
    fn expected(
        isa: Isa,
        length: u8,
        conditional: bool,
        reads: &[Register],
        writes: &[Register],
        effect: ValueEffect,
        flow: ControlFlow,
    ) -> DecodedInstruction {
        let flags = match &effect {
            ValueEffect::Compare { .. } => FlagEffect::Written(FlagWriter::Compare),
            ValueEffect::Unsupported => FlagEffect::Clobbered,
            _ => FlagEffect::Preserved,
        };
        DecodedInstruction {
            isa,
            pc: 0x1000,
            length,
            conditional,
            links_lr: false,
            reads: regs(reads),
            writes: regs(writes),
            effect,
            flags,
            flow,
            system: SystemEffect::None,
        }
    }

    fn expected_transfer(
        mut instruction: DecodedInstruction,
        transfer: CoprocessorTransfer,
    ) -> DecodedInstruction {
        instruction.system = SystemEffect::CoprocessorTransfer(transfer);
        instruction
    }

    fn write(dst: Register, value: ValueExpr) -> ValueEffect {
        ValueEffect::RegisterWrite { dst, value }
    }

    fn mem(
        address: AddressExpr,
        kind: AccessKind,
        width: u8,
        value: Option<Register>,
        writeback: Option<(Register, AddressExpr)>,
    ) -> ValueEffect {
        memory(vec![transfer(address, kind, width, value)], writeback)
    }

    fn imm(base: Register, offset: i64) -> AddressExpr {
        imm_addr(base, offset)
    }

    fn reg_off(base: Register, index: Register) -> AddressExpr {
        address(
            AddressBase::Register(base),
            AddressOffset::Register {
                register: index,
                subtract: false,
                shift: Shift::Lsl(0),
            },
        )
    }

    fn linear() -> ControlFlow {
        ControlFlow::Linear
    }

    fn direct(target: u32) -> ControlFlow {
        ControlFlow::DirectBranch {
            target,
            fallthrough: None,
            predicate: BranchPredicate::Always,
        }
    }

    fn direct_cond(target: u32, fallthrough: u32, cond: Arm32Condition) -> ControlFlow {
        ControlFlow::DirectBranch {
            target,
            fallthrough: Some(fallthrough),
            predicate: BranchPredicate::Condition(cond),
        }
    }

    struct NamedFixture {
        name: &'static str,
        isa: Isa,
        bytes: &'static [u8],
        expected: DecodedInstruction,
    }

    fn fixtures() -> Vec<NamedFixture> {
        vec![
            NamedFixture {
                name: "a32_mov_imm",
                isa: Isa::Arm,
                bytes: &[0x01, 0x00, 0xa0, 0xe3],
                expected: expected(
                    Isa::Arm,
                    4,
                    false,
                    &[],
                    &[R0],
                    write(R0, ValueExpr::Immediate(1)),
                    linear(),
                ),
            },
            NamedFixture {
                name: "a32_movw",
                isa: Isa::Arm,
                bytes: &[0x34, 0x02, 0x01, 0xe3],
                expected: expected(
                    Isa::Arm,
                    4,
                    false,
                    &[],
                    &[R0],
                    write(R0, ValueExpr::Immediate(0x1234)),
                    linear(),
                ),
            },
            NamedFixture {
                name: "a32_movt",
                isa: Isa::Arm,
                bytes: &[0x34, 0x02, 0x41, 0xe3],
                expected: expected(
                    Isa::Arm,
                    4,
                    false,
                    &[R0],
                    &[R0],
                    write(
                        R0,
                        ValueExpr::ReplaceHighHalf {
                            source: R0,
                            high: 0x1234,
                        },
                    ),
                    linear(),
                ),
            },
            NamedFixture {
                name: "a32_mov_reg",
                isa: Isa::Arm,
                bytes: &[0x01, 0x00, 0xa0, 0xe1],
                expected: expected(
                    Isa::Arm,
                    4,
                    false,
                    &[R1],
                    &[R0],
                    write(R0, ValueExpr::Register(R1)),
                    linear(),
                ),
            },
            NamedFixture {
                name: "a32_add_imm",
                isa: Isa::Arm,
                bytes: &[0x04, 0x00, 0x81, 0xe2],
                expected: expected(
                    Isa::Arm,
                    4,
                    false,
                    &[R1],
                    &[R0],
                    write(
                        R0,
                        ValueExpr::Add {
                            left: R1,
                            right: Operand::Immediate(4),
                        },
                    ),
                    linear(),
                ),
            },
            NamedFixture {
                name: "a32_sub_imm",
                isa: Isa::Arm,
                bytes: &[0x04, 0x00, 0x41, 0xe2],
                expected: expected(
                    Isa::Arm,
                    4,
                    false,
                    &[R1],
                    &[R0],
                    write(
                        R0,
                        ValueExpr::Sub {
                            left: R1,
                            right: Operand::Immediate(4),
                        },
                    ),
                    linear(),
                ),
            },
            NamedFixture {
                name: "a32_pc_address",
                isa: Isa::Arm,
                bytes: &[0x08, 0x00, 0x8f, 0xe2],
                expected: expected(
                    Isa::Arm,
                    4,
                    false,
                    &[],
                    &[R0],
                    write(
                        R0,
                        ValueExpr::ArchitecturalPc {
                            addend: 8,
                            align_to_four: false,
                        },
                    ),
                    linear(),
                ),
            },
            NamedFixture {
                name: "a32_literal_load",
                isa: Isa::Arm,
                bytes: &[0x00, 0x00, 0x9f, 0xe5],
                expected: expected(
                    Isa::Arm,
                    4,
                    false,
                    &[],
                    &[R0],
                    ValueEffect::LiteralWordLoad {
                        dst: R0,
                        address: pc_addr(false, 0),
                    },
                    linear(),
                ),
            },
            NamedFixture {
                name: "a32_ldr_word",
                isa: Isa::Arm,
                bytes: &[0x04, 0x00, 0x91, 0xe5],
                expected: expected(
                    Isa::Arm,
                    4,
                    false,
                    &[R1],
                    &[R0],
                    mem(imm(R1, 4), AccessKind::Read, 4, Some(R0), None),
                    linear(),
                ),
            },
            NamedFixture {
                name: "a32_str_word",
                isa: Isa::Arm,
                bytes: &[0x04, 0x00, 0x81, 0xe5],
                expected: expected(
                    Isa::Arm,
                    4,
                    false,
                    &[R0, R1],
                    &[],
                    mem(imm(R1, 4), AccessKind::Write, 4, Some(R0), None),
                    linear(),
                ),
            },
            NamedFixture {
                name: "a32_ldrb",
                isa: Isa::Arm,
                bytes: &[0x04, 0x00, 0xd1, 0xe5],
                expected: expected(
                    Isa::Arm,
                    4,
                    false,
                    &[R1],
                    &[R0],
                    mem(imm(R1, 4), AccessKind::Read, 1, Some(R0), None),
                    linear(),
                ),
            },
            NamedFixture {
                name: "a32_strb",
                isa: Isa::Arm,
                bytes: &[0x04, 0x00, 0xc1, 0xe5],
                expected: expected(
                    Isa::Arm,
                    4,
                    false,
                    &[R0, R1],
                    &[],
                    mem(imm(R1, 4), AccessKind::Write, 1, Some(R0), None),
                    linear(),
                ),
            },
            NamedFixture {
                name: "a32_ldrh",
                isa: Isa::Arm,
                bytes: &[0xb4, 0x00, 0xd1, 0xe1],
                expected: expected(
                    Isa::Arm,
                    4,
                    false,
                    &[R1],
                    &[R0],
                    mem(imm(R1, 4), AccessKind::Read, 2, Some(R0), None),
                    linear(),
                ),
            },
            NamedFixture {
                name: "a32_strh",
                isa: Isa::Arm,
                bytes: &[0xb4, 0x00, 0xc1, 0xe1],
                expected: expected(
                    Isa::Arm,
                    4,
                    false,
                    &[R0, R1],
                    &[],
                    mem(imm(R1, 4), AccessKind::Write, 2, Some(R0), None),
                    linear(),
                ),
            },
            NamedFixture {
                name: "a32_ldrsb",
                isa: Isa::Arm,
                bytes: &[0xd4, 0x00, 0xd1, 0xe1],
                expected: expected(
                    Isa::Arm,
                    4,
                    false,
                    &[R1],
                    &[R0],
                    mem(imm(R1, 4), AccessKind::Read, 1, Some(R0), None),
                    linear(),
                ),
            },
            NamedFixture {
                name: "a32_ldrsh",
                isa: Isa::Arm,
                bytes: &[0xf4, 0x00, 0xd1, 0xe1],
                expected: expected(
                    Isa::Arm,
                    4,
                    false,
                    &[R1],
                    &[R0],
                    mem(imm(R1, 4), AccessKind::Read, 2, Some(R0), None),
                    linear(),
                ),
            },
            NamedFixture {
                name: "a32_ldrd",
                isa: Isa::Arm,
                bytes: &[0xd8, 0x00, 0xc1, 0xe1],
                expected: expected(
                    Isa::Arm,
                    4,
                    false,
                    &[R1],
                    &[R0, R1],
                    mem(imm(R1, 8), AccessKind::Read, 8, Some(R0), None),
                    linear(),
                ),
            },
            NamedFixture {
                name: "a32_strd",
                isa: Isa::Arm,
                bytes: &[0xf8, 0x00, 0xc1, 0xe1],
                expected: expected(
                    Isa::Arm,
                    4,
                    false,
                    &[R0, R1],
                    &[],
                    mem(imm(R1, 8), AccessKind::Write, 8, Some(R0), None),
                    linear(),
                ),
            },
            NamedFixture {
                name: "a32_ldr_reg_offset",
                isa: Isa::Arm,
                bytes: &[0x02, 0x00, 0x91, 0xe7],
                expected: expected(
                    Isa::Arm,
                    4,
                    false,
                    &[R1, R2],
                    &[R0],
                    mem(reg_off(R1, R2), AccessKind::Read, 4, Some(R0), None),
                    linear(),
                ),
            },
            NamedFixture {
                name: "a32_ldr_imm_sub",
                isa: Isa::Arm,
                bytes: &[0x04, 0x00, 0x11, 0xe5],
                expected: expected(
                    Isa::Arm,
                    4,
                    false,
                    &[R1],
                    &[R0],
                    mem(imm(R1, -4), AccessKind::Read, 4, Some(R0), None),
                    linear(),
                ),
            },
            NamedFixture {
                name: "a32_ldr_pre_index",
                isa: Isa::Arm,
                bytes: &[0x04, 0x00, 0xb1, 0xe5],
                expected: expected(
                    Isa::Arm,
                    4,
                    false,
                    &[R1],
                    &[R0, R1],
                    mem(
                        imm(R1, 4),
                        AccessKind::Read,
                        4,
                        Some(R0),
                        Some((R1, imm(R1, 4))),
                    ),
                    linear(),
                ),
            },
            NamedFixture {
                name: "a32_ldr_post_index",
                isa: Isa::Arm,
                bytes: &[0x04, 0x00, 0x91, 0xe4],
                expected: expected(
                    Isa::Arm,
                    4,
                    false,
                    &[R1],
                    &[R0, R1],
                    mem(
                        imm(R1, 0),
                        AccessKind::Read,
                        4,
                        Some(R0),
                        Some((R1, imm(R1, 4))),
                    ),
                    linear(),
                ),
            },
            NamedFixture {
                name: "a32_ldrex",
                isa: Isa::Arm,
                bytes: &[0x9f, 0x0f, 0x91, 0xe1],
                expected: expected(
                    Isa::Arm,
                    4,
                    false,
                    &[R1],
                    &[R0],
                    mem(imm(R1, 0), AccessKind::Read, 4, Some(R0), None),
                    linear(),
                ),
            },
            NamedFixture {
                name: "a32_strex",
                isa: Isa::Arm,
                bytes: &[0x90, 0x2f, 0x81, 0xe1],
                expected: expected(
                    Isa::Arm,
                    4,
                    false,
                    &[R0, R1],
                    &[R2],
                    mem(imm(R1, 0), AccessKind::Write, 4, Some(R0), None),
                    linear(),
                ),
            },
            NamedFixture {
                name: "a32_swp",
                isa: Isa::Arm,
                bytes: &[0x91, 0x00, 0x02, 0xe1],
                expected: expected(
                    Isa::Arm,
                    4,
                    false,
                    &[R1, R2],
                    &[R0],
                    mem(imm(R2, 0), AccessKind::ReadWrite, 4, Some(R0), None),
                    linear(),
                ),
            },
            NamedFixture {
                name: "a32_ldm",
                isa: Isa::Arm,
                bytes: &[0x06, 0x00, 0x90, 0xe8],
                expected: expected(
                    Isa::Arm,
                    4,
                    false,
                    &[R0],
                    &[R1, R2],
                    memory(
                        vec![
                            transfer(imm(R0, 0), AccessKind::Read, 4, Some(R1)),
                            transfer(imm(R0, 4), AccessKind::Read, 4, Some(R2)),
                        ],
                        None,
                    ),
                    linear(),
                ),
            },
            NamedFixture {
                name: "a32_stm_db",
                isa: Isa::Arm,
                bytes: &[0x06, 0x00, 0x20, 0xe9],
                expected: expected(
                    Isa::Arm,
                    4,
                    false,
                    &[R0, R1, R2],
                    &[R0],
                    memory(
                        vec![
                            transfer(imm(R0, -8), AccessKind::Write, 4, Some(R1)),
                            transfer(imm(R0, -4), AccessKind::Write, 4, Some(R2)),
                        ],
                        Some((R0, imm(R0, -8))),
                    ),
                    linear(),
                ),
            },
            NamedFixture {
                name: "a32_b",
                isa: Isa::Arm,
                bytes: &[0x00, 0x00, 0x00, 0xea],
                expected: expected(
                    Isa::Arm,
                    4,
                    false,
                    &[],
                    &[],
                    ValueEffect::None,
                    direct(0x1008),
                ),
            },
            NamedFixture {
                name: "a32_bl",
                isa: Isa::Arm,
                bytes: &[0x00, 0x00, 0x00, 0xeb],
                expected: expected(
                    Isa::Arm,
                    4,
                    false,
                    &[],
                    &[],
                    ValueEffect::None,
                    ControlFlow::DirectCall { target: 0x1008 },
                )
                .with_link(),
            },
            NamedFixture {
                name: "a32_bx_lr",
                isa: Isa::Arm,
                bytes: &[0x1e, 0xff, 0x2f, 0xe1],
                expected: expected(
                    Isa::Arm,
                    4,
                    false,
                    &[LR],
                    &[],
                    ValueEffect::None,
                    ControlFlow::Return,
                ),
            },
            NamedFixture {
                name: "a32_blx_reg",
                isa: Isa::Arm,
                bytes: &[0x30, 0xff, 0x2f, 0xe1],
                expected: expected(
                    Isa::Arm,
                    4,
                    false,
                    &[R0],
                    &[],
                    ValueEffect::None,
                    ControlFlow::Barrier,
                )
                .with_link(),
            },
            NamedFixture {
                name: "a32_beq",
                isa: Isa::Arm,
                bytes: &[0x00, 0x00, 0x00, 0x0a],
                expected: expected(
                    Isa::Arm,
                    4,
                    true,
                    &[],
                    &[],
                    ValueEffect::None,
                    direct_cond(0x1008, 0x1004, Arm32Condition::Equal),
                ),
            },
            NamedFixture {
                name: "a32_moveq",
                isa: Isa::Arm,
                bytes: &[0x01, 0x00, 0xa0, 0x03],
                expected: expected(
                    Isa::Arm,
                    4,
                    true,
                    &[],
                    &[R0],
                    write(R0, ValueExpr::Immediate(1)),
                    linear(),
                ),
            },
            NamedFixture {
                name: "a32_ldreq",
                isa: Isa::Arm,
                bytes: &[0x04, 0x00, 0x91, 0x05],
                expected: expected(
                    Isa::Arm,
                    4,
                    true,
                    &[R1],
                    &[R0],
                    mem(imm(R1, 4), AccessKind::Read, 4, Some(R0), None),
                    linear(),
                ),
            },
            NamedFixture {
                name: "t32_movs",
                isa: Isa::Thumb,
                bytes: &[0x01, 0x20],
                expected: expected(
                    Isa::Thumb,
                    2,
                    false,
                    &[],
                    &[R0],
                    write(R0, ValueExpr::Immediate(1)),
                    linear(),
                )
                .with_flags(FlagEffect::Clobbered),
            },
            NamedFixture {
                name: "t32_movw",
                isa: Isa::Thumb,
                bytes: &[0x41, 0xf2, 0x34, 0x20],
                expected: expected(
                    Isa::Thumb,
                    4,
                    false,
                    &[],
                    &[R0],
                    write(R0, ValueExpr::Immediate(0x1234)),
                    linear(),
                ),
            },
            NamedFixture {
                name: "t32_movt",
                isa: Isa::Thumb,
                bytes: &[0xc1, 0xf2, 0x34, 0x20],
                expected: expected(
                    Isa::Thumb,
                    4,
                    false,
                    &[R0],
                    &[R0],
                    write(
                        R0,
                        ValueExpr::ReplaceHighHalf {
                            source: R0,
                            high: 0x1234,
                        },
                    ),
                    linear(),
                ),
            },
            NamedFixture {
                name: "t32_mov_reg",
                isa: Isa::Thumb,
                bytes: &[0x08, 0x46],
                expected: expected(
                    Isa::Thumb,
                    2,
                    false,
                    &[R1],
                    &[R0],
                    write(R0, ValueExpr::Register(R1)),
                    linear(),
                ),
            },
            NamedFixture {
                name: "t32_add_imm",
                isa: Isa::Thumb,
                bytes: &[0x08, 0x1d],
                expected: expected(
                    Isa::Thumb,
                    2,
                    false,
                    &[R1],
                    &[R0],
                    write(
                        R0,
                        ValueExpr::Add {
                            left: R1,
                            right: Operand::Immediate(4),
                        },
                    ),
                    linear(),
                )
                .with_flags(FlagEffect::Clobbered),
            },
            NamedFixture {
                name: "t32_sub_imm",
                isa: Isa::Thumb,
                bytes: &[0x08, 0x1f],
                expected: expected(
                    Isa::Thumb,
                    2,
                    false,
                    &[R1],
                    &[R0],
                    write(
                        R0,
                        ValueExpr::Sub {
                            left: R1,
                            right: Operand::Immediate(4),
                        },
                    ),
                    linear(),
                )
                .with_flags(FlagEffect::Clobbered),
            },
            NamedFixture {
                name: "t32_adr",
                isa: Isa::Thumb,
                bytes: &[0x02, 0xa0],
                expected: expected(
                    Isa::Thumb,
                    2,
                    false,
                    &[],
                    &[R0],
                    write(
                        R0,
                        ValueExpr::ArchitecturalPc {
                            addend: 8,
                            align_to_four: true,
                        },
                    ),
                    linear(),
                ),
            },
            NamedFixture {
                name: "t32_literal_load",
                isa: Isa::Thumb,
                bytes: &[0x01, 0x48],
                expected: expected(
                    Isa::Thumb,
                    2,
                    false,
                    &[],
                    &[R0],
                    ValueEffect::LiteralWordLoad {
                        dst: R0,
                        address: pc_addr(true, 4),
                    },
                    linear(),
                ),
            },
            NamedFixture {
                name: "t32_ldr_word",
                isa: Isa::Thumb,
                bytes: &[0x48, 0x68],
                expected: expected(
                    Isa::Thumb,
                    2,
                    false,
                    &[R1],
                    &[R0],
                    mem(imm(R1, 4), AccessKind::Read, 4, Some(R0), None),
                    linear(),
                ),
            },
            NamedFixture {
                name: "t32_str_word",
                isa: Isa::Thumb,
                bytes: &[0x48, 0x60],
                expected: expected(
                    Isa::Thumb,
                    2,
                    false,
                    &[R0, R1],
                    &[],
                    mem(imm(R1, 4), AccessKind::Write, 4, Some(R0), None),
                    linear(),
                ),
            },
            NamedFixture {
                name: "t32_ldrb",
                isa: Isa::Thumb,
                bytes: &[0x08, 0x79],
                expected: expected(
                    Isa::Thumb,
                    2,
                    false,
                    &[R1],
                    &[R0],
                    mem(imm(R1, 4), AccessKind::Read, 1, Some(R0), None),
                    linear(),
                ),
            },
            NamedFixture {
                name: "t32_strb",
                isa: Isa::Thumb,
                bytes: &[0x08, 0x71],
                expected: expected(
                    Isa::Thumb,
                    2,
                    false,
                    &[R0, R1],
                    &[],
                    mem(imm(R1, 4), AccessKind::Write, 1, Some(R0), None),
                    linear(),
                ),
            },
            NamedFixture {
                name: "t32_ldrh",
                isa: Isa::Thumb,
                bytes: &[0x88, 0x88],
                expected: expected(
                    Isa::Thumb,
                    2,
                    false,
                    &[R1],
                    &[R0],
                    mem(imm(R1, 4), AccessKind::Read, 2, Some(R0), None),
                    linear(),
                ),
            },
            NamedFixture {
                name: "t32_strh",
                isa: Isa::Thumb,
                bytes: &[0x88, 0x80],
                expected: expected(
                    Isa::Thumb,
                    2,
                    false,
                    &[R0, R1],
                    &[],
                    mem(imm(R1, 4), AccessKind::Write, 2, Some(R0), None),
                    linear(),
                ),
            },
            NamedFixture {
                name: "t32_ldrsb_reg",
                isa: Isa::Thumb,
                bytes: &[0x88, 0x56],
                expected: expected(
                    Isa::Thumb,
                    2,
                    false,
                    &[R1, R2],
                    &[R0],
                    mem(reg_off(R1, R2), AccessKind::Read, 1, Some(R0), None),
                    linear(),
                ),
            },
            NamedFixture {
                name: "t32_ldrsh_reg",
                isa: Isa::Thumb,
                bytes: &[0x88, 0x5e],
                expected: expected(
                    Isa::Thumb,
                    2,
                    false,
                    &[R1, R2],
                    &[R0],
                    mem(reg_off(R1, R2), AccessKind::Read, 2, Some(R0), None),
                    linear(),
                ),
            },
            NamedFixture {
                name: "t32_ldr_reg",
                isa: Isa::Thumb,
                bytes: &[0x88, 0x58],
                expected: expected(
                    Isa::Thumb,
                    2,
                    false,
                    &[R1, R2],
                    &[R0],
                    mem(reg_off(R1, R2), AccessKind::Read, 4, Some(R0), None),
                    linear(),
                ),
            },
            NamedFixture {
                name: "t32_ldrb_pre",
                isa: Isa::Thumb,
                bytes: &[0x11, 0xf8, 0x04, 0x0f],
                expected: expected(
                    Isa::Thumb,
                    4,
                    false,
                    &[R1],
                    &[R0, R1],
                    mem(
                        imm(R1, 4),
                        AccessKind::Read,
                        1,
                        Some(R0),
                        Some((R1, imm(R1, 4))),
                    ),
                    linear(),
                ),
            },
            NamedFixture {
                name: "t32_ldrb_post",
                isa: Isa::Thumb,
                bytes: &[0x11, 0xf8, 0x04, 0x0b],
                expected: expected(
                    Isa::Thumb,
                    4,
                    false,
                    &[R1],
                    &[R0, R1],
                    mem(
                        imm(R1, 0),
                        AccessKind::Read,
                        1,
                        Some(R0),
                        Some((R1, imm(R1, 4))),
                    ),
                    linear(),
                ),
            },
            NamedFixture {
                name: "t32_ldrd",
                isa: Isa::Thumb,
                bytes: &[0xd2, 0xe9, 0x02, 0x01],
                expected: expected(
                    Isa::Thumb,
                    4,
                    false,
                    &[R2],
                    &[R0, R1],
                    mem(imm(R2, 8), AccessKind::Read, 8, Some(R0), None),
                    linear(),
                ),
            },
            NamedFixture {
                name: "t32_strd",
                isa: Isa::Thumb,
                bytes: &[0xc2, 0xe9, 0x02, 0x01],
                expected: expected(
                    Isa::Thumb,
                    4,
                    false,
                    &[R0, R1, R2],
                    &[],
                    mem(imm(R2, 8), AccessKind::Write, 8, Some(R0), None),
                    linear(),
                ),
            },
            NamedFixture {
                name: "t32_ldrex",
                isa: Isa::Thumb,
                bytes: &[0x51, 0xe8, 0x00, 0x0f],
                expected: expected(
                    Isa::Thumb,
                    4,
                    false,
                    &[R1],
                    &[R0],
                    mem(imm(R1, 0), AccessKind::Read, 4, Some(R0), None),
                    linear(),
                ),
            },
            NamedFixture {
                name: "t32_strex",
                isa: Isa::Thumb,
                bytes: &[0x41, 0xe8, 0x00, 0x02],
                expected: expected(
                    Isa::Thumb,
                    4,
                    false,
                    &[R0, R1],
                    &[R2],
                    mem(imm(R1, 0), AccessKind::Write, 4, Some(R0), None),
                    linear(),
                ),
            },
            NamedFixture {
                name: "t32_ldm",
                isa: Isa::Thumb,
                bytes: &[0x06, 0xc8],
                expected: expected(
                    Isa::Thumb,
                    2,
                    false,
                    &[R0],
                    &[R0, R1, R2],
                    memory(
                        vec![
                            transfer(imm(R0, 0), AccessKind::Read, 4, Some(R1)),
                            transfer(imm(R0, 4), AccessKind::Read, 4, Some(R2)),
                        ],
                        Some((R0, imm(R0, 8))),
                    ),
                    linear(),
                ),
            },
            NamedFixture {
                name: "t32_stm",
                isa: Isa::Thumb,
                bytes: &[0x06, 0xc0],
                expected: expected(
                    Isa::Thumb,
                    2,
                    false,
                    &[R0, R1, R2],
                    &[R0],
                    memory(
                        vec![
                            transfer(imm(R0, 0), AccessKind::Write, 4, Some(R1)),
                            transfer(imm(R0, 4), AccessKind::Write, 4, Some(R2)),
                        ],
                        Some((R0, imm(R0, 8))),
                    ),
                    linear(),
                ),
            },
            NamedFixture {
                name: "t32_push_lr",
                isa: Isa::Thumb,
                bytes: &[0x00, 0xb5],
                expected: expected(
                    Isa::Thumb,
                    2,
                    false,
                    &[SP, LR],
                    &[SP],
                    memory(
                        vec![transfer(imm(SP, -4), AccessKind::Write, 4, Some(LR))],
                        Some((SP, imm(SP, -4))),
                    ),
                    linear(),
                ),
            },
            NamedFixture {
                name: "t32_pop_pc",
                isa: Isa::Thumb,
                bytes: &[0x01, 0xbd],
                expected: expected(
                    Isa::Thumb,
                    2,
                    false,
                    &[SP],
                    &[SP, R0, PC],
                    memory(
                        vec![
                            transfer(imm(SP, 0), AccessKind::Read, 4, Some(R0)),
                            transfer(imm(SP, 4), AccessKind::Read, 4, Some(PC)),
                        ],
                        Some((SP, imm(SP, 8))),
                    ),
                    ControlFlow::Barrier,
                ),
            },
            NamedFixture {
                name: "t32_b",
                isa: Isa::Thumb,
                bytes: &[0x00, 0xe0],
                expected: expected(
                    Isa::Thumb,
                    2,
                    false,
                    &[],
                    &[],
                    ValueEffect::None,
                    direct(0x1004),
                ),
            },
            NamedFixture {
                name: "t32_bl",
                isa: Isa::Thumb,
                bytes: &[0x00, 0xf0, 0x00, 0xf8],
                expected: expected(
                    Isa::Thumb,
                    4,
                    false,
                    &[],
                    &[],
                    ValueEffect::None,
                    ControlFlow::DirectCall { target: 0x1004 },
                )
                .with_link(),
            },
            NamedFixture {
                name: "t32_bx_lr",
                isa: Isa::Thumb,
                bytes: &[0x70, 0x47],
                expected: expected(
                    Isa::Thumb,
                    2,
                    false,
                    &[LR],
                    &[],
                    ValueEffect::None,
                    ControlFlow::Return,
                ),
            },
            NamedFixture {
                name: "t32_blx_reg",
                isa: Isa::Thumb,
                bytes: &[0x80, 0x47],
                expected: expected(
                    Isa::Thumb,
                    2,
                    false,
                    &[R0],
                    &[],
                    ValueEffect::None,
                    ControlFlow::Barrier,
                )
                .with_link(),
            },
            NamedFixture {
                name: "t32_beq",
                isa: Isa::Thumb,
                bytes: &[0x00, 0xd0],
                expected: expected(
                    Isa::Thumb,
                    2,
                    true,
                    &[],
                    &[],
                    ValueEffect::None,
                    direct_cond(0x1004, 0x1002, Arm32Condition::Equal),
                ),
            },
            NamedFixture {
                name: "t32_it_eq",
                isa: Isa::Thumb,
                bytes: &[0x08, 0xbf],
                expected: expected(Isa::Thumb, 2, false, &[], &[], ValueEffect::None, linear()),
            },
            NamedFixture {
                name: "t32_it_contained_movs",
                isa: Isa::Thumb,
                bytes: &[0x01, 0x20],
                expected: expected(
                    Isa::Thumb,
                    2,
                    false,
                    &[],
                    &[R0],
                    write(R0, ValueExpr::Immediate(1)),
                    linear(),
                )
                .with_flags(FlagEffect::Clobbered),
            },
            NamedFixture {
                name: "a32_nop_unsupported",
                isa: Isa::Arm,
                bytes: &[0x00, 0xf0, 0x20, 0xe3],
                expected: expected(
                    Isa::Arm,
                    4,
                    false,
                    &[],
                    &[],
                    ValueEffect::Unsupported,
                    linear(),
                ),
            },
            NamedFixture {
                name: "t32_nop_unsupported",
                isa: Isa::Thumb,
                bytes: &[0x00, 0xbf],
                expected: expected(
                    Isa::Thumb,
                    2,
                    false,
                    &[],
                    &[],
                    ValueEffect::Unsupported,
                    linear(),
                ),
            },
            NamedFixture {
                name: "a32_and_unsupported",
                isa: Isa::Arm,
                bytes: &[0x01, 0x00, 0x01, 0xe2],
                expected: expected(
                    Isa::Arm,
                    4,
                    false,
                    &[R1],
                    &[R0],
                    ValueEffect::Unsupported,
                    linear(),
                ),
            },
            NamedFixture {
                name: "t32_ands_unsupported",
                isa: Isa::Thumb,
                bytes: &[0x08, 0x40],
                expected: expected(
                    Isa::Thumb,
                    2,
                    false,
                    &[R0, R1],
                    &[R0],
                    ValueEffect::Unsupported,
                    linear(),
                ),
            },
            NamedFixture {
                name: "t32_cmp_imm",
                isa: Isa::Thumb,
                bytes: &[0x00, 0x28],
                expected: expected(
                    Isa::Thumb,
                    2,
                    false,
                    &[R0],
                    &[],
                    ValueEffect::Compare {
                        operation: CompareOp::Subtract,
                        left: R0,
                        right: Operand::Immediate(0),
                    },
                    linear(),
                ),
            },
            NamedFixture {
                name: "a32_cmp_reg",
                isa: Isa::Arm,
                bytes: &[0x01, 0x00, 0x50, 0xe1],
                expected: expected(
                    Isa::Arm,
                    4,
                    false,
                    &[R0, R1],
                    &[],
                    ValueEffect::Compare {
                        operation: CompareOp::Subtract,
                        left: R0,
                        right: Operand::Register {
                            register: R1,
                            shift: Shift::Lsl(0),
                        },
                    },
                    linear(),
                ),
            },
            NamedFixture {
                name: "t32_lsls",
                isa: Isa::Thumb,
                bytes: &[0x88, 0x00],
                expected: expected(
                    Isa::Thumb,
                    2,
                    false,
                    &[R1],
                    &[R0],
                    ValueEffect::Shift {
                        dst: R0,
                        source: R1,
                        shift: Shift::Lsl(2),
                    },
                    linear(),
                )
                .with_flags(FlagEffect::Clobbered),
            },
            NamedFixture {
                name: "t32_lsl_w",
                isa: Isa::Thumb,
                bytes: &[0x4f, 0xea, 0xc1, 0x00],
                expected: expected(
                    Isa::Thumb,
                    4,
                    false,
                    &[R1],
                    &[R0],
                    ValueEffect::Shift {
                        dst: R0,
                        source: R1,
                        shift: Shift::Lsl(3),
                    },
                    linear(),
                ),
            },
            NamedFixture {
                name: "t32_mla",
                isa: Isa::Thumb,
                bytes: &[0x01, 0xfb, 0x02, 0x30],
                expected: expected(
                    Isa::Thumb,
                    4,
                    false,
                    &[R1, R2, R3],
                    &[R0],
                    ValueEffect::Unsupported,
                    linear(),
                ),
            },
            NamedFixture {
                name: "a32_pld",
                isa: Isa::Arm,
                bytes: &[0x08, 0xf0, 0xd0, 0xf5],
                expected: expected(
                    Isa::Arm,
                    4,
                    false,
                    &[R0],
                    &[],
                    ValueEffect::Unsupported,
                    linear(),
                ),
            },
            NamedFixture {
                name: "t32_mcr",
                isa: Isa::Thumb,
                bytes: &[0x00, 0xee, 0x10, 0x1f],
                expected: expected_transfer(
                    expected(
                        Isa::Thumb,
                        4,
                        false,
                        &[R1],
                        &[],
                        ValueEffect::Unsupported,
                        linear(),
                    ),
                    CoprocessorTransfer {
                        direction: SystemDirection::Write,
                        coprocessor: 15,
                        opcode1: 0,
                        rt: R1,
                        crn: 0,
                        crm: 0,
                        opcode2: 0,
                        unconditional_extension: false,
                    },
                ),
            },
            NamedFixture {
                name: "t32_csel",
                isa: Isa::Thumb,
                bytes: &[0x51, 0xea, 0x02, 0x80],
                expected: expected(
                    Isa::Thumb,
                    4,
                    false,
                    &[R1, R2],
                    &[R0],
                    ValueEffect::Unsupported,
                    linear(),
                ),
            },
            NamedFixture {
                name: "t32_clrm",
                isa: Isa::Thumb,
                bytes: &[0x9f, 0xe8, 0x07, 0x00],
                expected: expected(
                    Isa::Thumb,
                    4,
                    false,
                    &[],
                    &[R0, R1, R2],
                    ValueEffect::Unsupported,
                    linear(),
                ),
            },
            NamedFixture {
                name: "t32_asrl",
                isa: Isa::Thumb,
                bytes: &[0x50, 0xea, 0x6f, 0x11],
                expected: expected(
                    Isa::Thumb,
                    4,
                    false,
                    &[R0, R1],
                    &[R0, R1],
                    ValueEffect::Unsupported,
                    linear(),
                ),
            },
            NamedFixture {
                name: "t32_tt",
                isa: Isa::Thumb,
                bytes: &[0x41, 0xe8, 0x00, 0xf0],
                expected: expected(
                    Isa::Thumb,
                    4,
                    false,
                    &[R1],
                    &[R0],
                    ValueEffect::Unsupported,
                    linear(),
                ),
            },
            NamedFixture {
                name: "t32_bxns",
                isa: Isa::Thumb,
                bytes: &[0x1c, 0x47],
                expected: expected(
                    Isa::Thumb,
                    2,
                    false,
                    &[R3],
                    &[],
                    ValueEffect::Unsupported,
                    ControlFlow::Barrier,
                ),
            },
            NamedFixture {
                name: "t32_pac",
                isa: Isa::Thumb,
                bytes: &[0xaf, 0xf3, 0x1d, 0x80],
                expected: expected(
                    Isa::Thumb,
                    4,
                    false,
                    &[SP, LR],
                    &[R12],
                    ValueEffect::Unsupported,
                    linear(),
                ),
            },
            NamedFixture {
                name: "t32_dls",
                isa: Isa::Thumb,
                // crate: LobStart(false, None, R0, 0) — `dls lr, r0`
                bytes: &[0x40, 0xf0, 0x01, 0xe0],
                expected: expected(
                    Isa::Thumb,
                    4,
                    false,
                    &[R0],
                    &[LR],
                    ValueEffect::Unsupported,
                    linear(),
                ),
            },
            NamedFixture {
                name: "t32_wls",
                isa: Isa::Thumb,
                // crate: LobStart(true, None, R0, 12) — `wls lr, r0, .+16`
                bytes: &[0x40, 0xf0, 0x07, 0xc0],
                expected: expected(
                    Isa::Thumb,
                    4,
                    false,
                    &[R0],
                    &[LR],
                    ValueEffect::Unsupported,
                    linear(),
                ),
            },
            NamedFixture {
                name: "t32_le",
                isa: Isa::Thumb,
                // crate: LobEnd(false, -12) — `le lr, .-8`
                bytes: &[0x0f, 0xf0, 0x07, 0xc0],
                expected: expected(
                    Isa::Thumb,
                    4,
                    false,
                    &[LR],
                    &[LR],
                    ValueEffect::Unsupported,
                    linear(),
                ),
            },
        ]
    }

    #[test]
    fn selected_adapter_matches_normalized_fixtures() {
        let decoder = PureRustDecoder;
        let identity = decoder.identity();
        assert_eq!(identity.crate_name, "scaleservers-arm32-assembly");
        assert_eq!(identity.version, "1.0.0");

        for fixture in fixtures() {
            let got = decode(fixture.isa, 0x1000, fixture.bytes);
            assert_eq!(got, fixture.expected, "{}", fixture.name);
            assert!(got.length > 0 && usize::from(got.length) <= fixture.bytes.len());
        }

        for (name, isa, bytes) in [
            ("a32_truncated", Isa::Arm, &[0x01, 0x00, 0xa0][..]),
            ("t32_truncated", Isa::Thumb, &[0x01][..]),
            ("t32_wide_truncated", Isa::Thumb, &[0x41, 0xf2][..]),
            ("empty", Isa::Arm, &[][..]),
        ] {
            let mut state = decoder.begin_range(isa);
            let result = decoder.decode_one(&mut state, isa, 0x1000, bytes);
            assert!(result.is_err(), "{name} unexpectedly decoded {result:?}");
        }
    }

    #[test]
    fn a32_bl_carries_resolved_same_isa_target() {
        // BL +0x10 (A1): imm24 = 0x10 >> 2 = 4, encoded as `04 00 00 eb`.
        // target = pc(0x1000) + 8 + 0x10 = 0x1018.
        let insn = decode(Isa::Arm, 0x1000, &[0x04, 0x00, 0x00, 0xeb]);
        assert_eq!(insn.flow, ControlFlow::DirectCall { target: 0x1018 });
        assert!(insn.links_lr);
    }

    #[test]
    fn t32_bl_carries_resolved_thumb_target() {
        // BL +0 (T1), same bytes as the `t32_bl` fixture, decoded at a different pc
        // to confirm the target tracks the caller's pc, not a fixed offset.
        let insn = decode(Isa::Thumb, 0x2000, &[0x00, 0xf0, 0x00, 0xf8]);
        assert_eq!(insn.flow, ControlFlow::DirectCall { target: 0x2004 });
        assert!(insn.links_lr);
    }

    #[test]
    fn blx_and_bx_do_not_resolve_a_target() {
        // BLX r0 / BX lr (A32 register forms) must not fabricate a target:
        // the indirect call is a linked barrier, the return is `bx lr`.
        let blx = decode(Isa::Arm, 0x1000, &[0x30, 0xff, 0x2f, 0xe1]);
        assert!(matches!(blx.flow, ControlFlow::Barrier));
        assert!(blx.links_lr);
        let bx = decode(Isa::Arm, 0x1000, &[0x1e, 0xff, 0x2f, 0xe1]);
        assert!(matches!(bx.flow, ControlFlow::Return));
    }
}
