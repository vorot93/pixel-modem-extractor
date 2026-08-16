// Pure-Rust adapter over `scaleservers-arm32-assembly` 1.0.0.
#![allow(clippy::too_many_arguments)]

use super::FunctionExecution;
use crate::error::{Error, Result};
use crate::execution_ranges::{DecodeIsa as Isa, DecodeRange};
use scaleservers_arm32_assembly::{
    Arm32BlockAddressMode, Arm32Condition, Arm32GeneralPurposeRegister, Arm32IndexMode,
    Arm32LowGeneralPurposeRegister, Arm32MemoryOffset, Arm32MemoryOffset8, Arm32RegisterShift,
    ArmA32Instruction, ArmT32Instruction,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

const DECODER_CRATE: &str = "scaleservers-arm32-assembly";
const DECODER_VERSION: &str = "1.0.0";
const PC: Register = Register(15);
const LR: Register = Register(14);
const SP: Register = Register(13);
const CORE_REGISTER_COUNT: u8 = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Register(pub(crate) u8);

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MemoryTransfer {
    pub address: AddressExpr,
    pub kind: AccessKind,
    pub width: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MemoryEffect {
    pub transfers: Vec<MemoryTransfer>,
    pub writeback: Option<(Register, AddressExpr)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SemanticEffect {
    None,
    RegisterWrite { dst: Register, value: ValueExpr },
    LiteralWordLoad { dst: Register, address: AddressExpr },
    Memory(MemoryEffect),
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ControlFlow {
    Linear,
    DirectBranch { target: u32, has_fallthrough: bool },
    Call { target: Option<CallTarget> },
    Stop,
}

/// A direct `bl` call target resolved to a same-ISA entry PC.
///
/// Only direct `bl` (A32 `Bl_A1` / T32 `Bl_T1`) resolves to `Some`. The other
/// `ControlFlow::Call` sources — `blx`-immediate (cross-ISA resolution is
/// deferred), `blx`/`blxns` register forms — always carry `target: None`;
/// fabricating a target for those would misattribute interprocedural
/// evidence. `bx` (register branch, no link) is `ControlFlow::Stop`, not
/// `Call`, and has no target at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CallTarget {
    pub entry: u32,
    pub isa: Isa,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DecodedInstruction {
    pub isa: Isa,
    pub pc: u32,
    pub length: u8,
    pub conditional: bool,
    pub reads: BTreeSet<Register>,
    pub writes: BTreeSet<Register>,
    pub effect: SemanticEffect,
    pub flow: ControlFlow,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DecodeFailure {
    pub pc: u32,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DecodedRange {
    pub range: DecodeRange,
    pub instructions: BTreeMap<u32, DecodedInstruction>,
    pub decode_failure: Option<DecodeFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DecodedFunction {
    pub ranges: Vec<DecodedRange>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Block {
    pub isa: Isa,
    pub start: u32,
    pub end: u32,
    /// Direct successor block-start PCs of this block's last instruction —
    /// exactly the edges the reachability walk computes: branch target
    /// (decoded anywhere in the function) and/or same-range fallthrough.
    /// No edges across gaps, into undecoded suffixes, or invented for
    /// calls/returns/indirect transfers.
    pub successors: Vec<u32>,
}

pub(crate) fn decode_function(
    decoder: &impl InstructionDecoder,
    function: &FunctionExecution,
    bytes: &[u8],
    load_address: u32,
) -> Result<DecodedFunction> {
    if function.identity.decode_ranges.is_empty() {
        return Err(invalid("function has no decode ranges"));
    }
    let mut ranges = Vec::new();
    for range in &function.identity.decode_ranges {
        ranges.push(decode_range(decoder, *range, bytes, load_address)?);
    }
    Ok(DecodedFunction { ranges })
}

pub(crate) fn reachable_blocks(
    function: &FunctionExecution,
    decoded: &DecodedFunction,
) -> Result<Vec<Block>> {
    let decoded_pcs = decoded_pc_map(decoded);
    let entry = function.identity.entry;
    // Undecoded entry is recoverable evidence loss: no walk, no invented length.
    if !decoded_pcs.contains_key(&entry) {
        return Ok(Vec::new());
    }

    let mut boundaries = BTreeSet::from([entry]);
    for range in &decoded.ranges {
        for insn in range.instructions.values() {
            let fallthrough = insn.pc.wrapping_add(u32::from(insn.length));
            match insn.flow {
                ControlFlow::Linear => {}
                ControlFlow::DirectBranch { target, .. } => {
                    if decoded_pcs.contains_key(&target) {
                        boundaries.insert(target);
                    }
                    if range.instructions.contains_key(&fallthrough) {
                        boundaries.insert(fallthrough);
                    }
                }
                ControlFlow::Call { .. } | ControlFlow::Stop => {
                    if range.instructions.contains_key(&fallthrough) {
                        boundaries.insert(fallthrough);
                    }
                }
            }
        }
    }

    let mut reachable = BTreeSet::new();
    let mut work = vec![entry];
    while let Some(pc) = work.pop() {
        if !reachable.insert(pc) {
            continue;
        }
        let Some((insn, range)) = decoded_pcs.get(&pc) else {
            continue;
        };
        for successor in successors(insn, range, &decoded_pcs) {
            if !reachable.contains(&successor) {
                work.push(successor);
            }
        }
    }

    let mut blocks = Vec::new();
    for range in &decoded.ranges {
        let pcs: Vec<u32> = range.instructions.keys().copied().collect();
        let mut index = 0;
        while index < pcs.len() {
            let start = pcs[index];
            if !reachable.contains(&start) {
                index += 1;
                continue;
            }
            let mut end_index = index;
            loop {
                let insn = &range.instructions[&pcs[end_index]];
                if !matches!(insn.flow, ControlFlow::Linear) {
                    break;
                }
                let next_pc = insn.pc.wrapping_add(u32::from(insn.length));
                let Some(&following) = pcs.get(end_index + 1) else {
                    break;
                };
                if following != next_pc
                    || !reachable.contains(&following)
                    || boundaries.contains(&following)
                {
                    break;
                }
                end_index += 1;
            }
            let last = &range.instructions[&pcs[end_index]];
            let end = last
                .pc
                .checked_add(u32::from(last.length))
                .ok_or_else(|| invalid("block end overflows u32"))?;
            if end <= start {
                return Err(invalid("block span is empty"));
            }
            if !block_end_is_valid(range, end) {
                return Err(invalid(
                    "block boundary is not a decoded instruction PC or prefix end",
                ));
            }
            blocks.push(Block {
                isa: range.range.isa,
                start,
                end,
                successors: Vec::new(),
            });
            index = end_index + 1;
        }
    }

    blocks.sort_by_key(|block| block.start);
    for window in blocks.windows(2) {
        if window[0].end > window[1].start {
            return Err(invalid("reachable blocks overlap"));
        }
        if window[0].start >= window[0].end || window[1].start >= window[1].end {
            return Err(invalid("block span is empty"));
        }
    }
    let starts: BTreeMap<u32, usize> = blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.start, index))
        .collect();
    for block in &mut blocks {
        let Some((_, range)) = decoded_pcs.get(&block.start) else {
            return Err(invalid("block start is not a decoded instruction"));
        };
        let Some((_, last)) = range.instructions.range(..block.end).next_back() else {
            return Err(invalid("block has no decoded instructions"));
        };
        let mut edges = successors(last, range, &decoded_pcs);
        edges.dedup();
        for edge in &edges {
            if !starts.contains_key(edge) {
                return Err(invalid("successor is not a reachable block start"));
            }
        }
        block.successors = edges;
    }
    Ok(blocks)
}

fn decode_range(
    decoder: &impl InstructionDecoder,
    range: DecodeRange,
    bytes: &[u8],
    load_address: u32,
) -> Result<DecodedRange> {
    let slice = range_bytes(bytes, load_address, range)?;
    let mut state = decoder.begin_range(range.isa);
    let mut instructions = BTreeMap::new();
    let mut decode_failure = None;
    let mut pc = range.start;
    while pc < range.end {
        let offset = checked_pc_offset(pc, range.start)?;
        if offset >= slice.len() {
            return Err(invalid("decode cursor left the declared range slice"));
        }
        match decoder.decode_one(&mut state, range.isa, pc, &slice[offset..]) {
            Ok(instruction) => {
                check_adapter_invariants(&instruction, range, pc, &instructions, range.end)?;
                let length = u32::from(instruction.length);
                if instructions.insert(pc, instruction).is_some() {
                    return Err(invalid("duplicate decoded instruction PC"));
                }
                let next = pc
                    .checked_add(length)
                    .ok_or_else(|| invalid("instruction length overflows u32"))?;
                if next <= pc {
                    return Err(invalid("decoded PC regressed"));
                }
                pc = next;
            }
            Err(error) => {
                decode_failure = Some(DecodeFailure {
                    pc,
                    message: error.message,
                });
                break;
            }
        }
    }
    Ok(DecodedRange {
        range,
        instructions,
        decode_failure,
    })
}

fn check_adapter_invariants(
    instruction: &DecodedInstruction,
    range: DecodeRange,
    requested_pc: u32,
    seen: &BTreeMap<u32, DecodedInstruction>,
    range_end: u32,
) -> Result<()> {
    if instruction.isa != range.isa {
        return Err(invalid("decoder returned an ISA other than the range ISA"));
    }
    if instruction.length == 0 || !valid_isa_length(instruction.isa, instruction.length) {
        return Err(invalid("decoder returned an impossible instruction length"));
    }
    if seen.contains_key(&instruction.pc) {
        return Err(invalid("duplicate decoded instruction PC"));
    }
    if seen
        .keys()
        .next_back()
        .is_some_and(|last| instruction.pc < *last)
    {
        return Err(invalid("decoded PC regressed"));
    }
    if instruction.pc != requested_pc {
        return Err(invalid("decoder returned a PC other than the requested PC"));
    }
    let end = instruction
        .pc
        .checked_add(u32::from(instruction.length))
        .ok_or_else(|| invalid("instruction length overflows u32"))?;
    if end > range_end {
        return Err(invalid("decoded instruction overruns the declared range"));
    }
    Ok(())
}

fn valid_isa_length(isa: Isa, length: u8) -> bool {
    match isa {
        Isa::Arm => length == 4,
        Isa::Thumb => length == 2 || length == 4,
    }
}

fn range_bytes(bytes: &[u8], load_address: u32, range: DecodeRange) -> Result<&[u8]> {
    if range.end <= range.start {
        return Err(invalid("decode range is empty"));
    }
    let start = range
        .start
        .checked_sub(load_address)
        .ok_or_else(|| invalid("decode range starts before the load address"))?;
    let end = range
        .end
        .checked_sub(load_address)
        .ok_or_else(|| invalid("decode range ends before the load address"))?;
    let start = usize::try_from(start).map_err(|_| invalid("decode range start does not fit"))?;
    let end = usize::try_from(end).map_err(|_| invalid("decode range end does not fit"))?;
    if end > bytes.len() {
        return Err(invalid("decode range extends past the image"));
    }
    Ok(&bytes[start..end])
}

fn checked_pc_offset(pc: u32, start: u32) -> Result<usize> {
    let offset = pc
        .checked_sub(start)
        .ok_or_else(|| invalid("decode PC is before the range start"))?;
    usize::try_from(offset).map_err(|_| invalid("decode PC offset does not fit"))
}

fn decoded_pc_map(
    decoded: &DecodedFunction,
) -> BTreeMap<u32, (&DecodedInstruction, &DecodedRange)> {
    let mut map = BTreeMap::new();
    for range in &decoded.ranges {
        for (pc, insn) in &range.instructions {
            map.insert(*pc, (insn, range));
        }
    }
    map
}

fn successors(
    insn: &DecodedInstruction,
    range: &DecodedRange,
    decoded_pcs: &BTreeMap<u32, (&DecodedInstruction, &DecodedRange)>,
) -> Vec<u32> {
    let fallthrough = insn.pc.wrapping_add(u32::from(insn.length));
    let fallthrough_in_range = range.instructions.contains_key(&fallthrough);
    match insn.flow {
        ControlFlow::Linear => {
            if fallthrough_in_range {
                vec![fallthrough]
            } else {
                Vec::new()
            }
        }
        ControlFlow::DirectBranch {
            target,
            has_fallthrough,
        } => {
            let mut next = Vec::new();
            if decoded_pcs.contains_key(&target) {
                next.push(target);
            }
            if has_fallthrough && fallthrough_in_range {
                next.push(fallthrough);
            }
            next
        }
        ControlFlow::Call { .. } => {
            if fallthrough_in_range {
                vec![fallthrough]
            } else {
                Vec::new()
            }
        }
        ControlFlow::Stop => Vec::new(),
    }
}

fn block_end_is_valid(range: &DecodedRange, end: u32) -> bool {
    if range.instructions.contains_key(&end) {
        return true;
    }
    if let Some((pc, insn)) = range.instructions.iter().next_back()
        && pc.checked_add(u32::from(insn.length)) == Some(end)
    {
        return true;
    }
    false
}

fn decode_a32(pc: u32, bytes: &[u8]) -> std::result::Result<DecodedInstruction, DecodeError> {
    let mut offset = 0usize;
    let decoded = ArmA32Instruction::decode(&mut bytes.iter(), &mut offset);
    let inst = take_decoded(Isa::Arm, offset, bytes.len(), decoded)?;
    Ok(finish(map_a32(pc, offset as u8, &inst)))
}

fn decode_t32(
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
    if instruction.writes.contains(&PC) && matches!(instruction.flow, ControlFlow::Linear) {
        instruction.flow = ControlFlow::Stop;
    }
    if matches!(instruction.effect, SemanticEffect::None) && !instruction.writes.is_empty() {
        instruction.effect = SemanticEffect::Unsupported;
    }
    instruction
}

fn decode_err(message: &str) -> DecodeError {
    DecodeError {
        message: message.to_owned(),
    }
}

fn invalid(message: &str) -> Error {
    Error::Serialize(message.to_owned())
}

fn gpr(reg: Arm32GeneralPurposeRegister) -> Register {
    Register(reg.as_operand_bits())
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
    effect: SemanticEffect,
    flow: ControlFlow,
) -> DecodedInstruction {
    DecodedInstruction {
        isa,
        pc,
        length,
        conditional,
        reads,
        writes,
        effect,
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
) -> SemanticEffect {
    SemanticEffect::Memory(MemoryEffect {
        transfers,
        writeback,
    })
}

fn transfer(address: AddressExpr, kind: AccessKind, width: u8) -> MemoryTransfer {
    MemoryTransfer {
        address,
        kind,
        width,
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
        ArmA32Instruction::Mov_Immediate_A1(cond, _, rd, imm) => a32_reg_write(
            pc,
            length,
            *cond,
            gpr(*rd),
            ValueExpr::Immediate(*imm),
            BTreeSet::new(),
        ),
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
        ArmA32Instruction::Mov_Register_A1(cond, _, rd, rm, shift) if shift.is_none() => {
            a32_reg_write(
                pc,
                length,
                *cond,
                gpr(*rd),
                ValueExpr::Register(gpr(*rm)),
                set([gpr(*rm)]),
            )
        }
        ArmA32Instruction::Add_Immediate_A1(cond, _, rd, rn, imm) => {
            a32_add_sub_imm(pc, length, *cond, gpr(*rd), *rn, *imm, false)
        }
        ArmA32Instruction::Sub_Immediate_A1(cond, _, rd, rn, imm) => {
            a32_add_sub_imm(pc, length, *cond, gpr(*rd), *rn, *imm, true)
        }
        ArmA32Instruction::Add_Register_A1(cond, _, rd, rn, rm, shift) => {
            a32_add_sub_reg(pc, length, *cond, gpr(*rd), *rn, *rm, *shift, false)
        }
        ArmA32Instruction::Sub_Register_A1(cond, _, rd, rn, rm, shift) => {
            a32_add_sub_reg(pc, length, *cond, gpr(*rd), *rn, *rm, *shift, true)
        }
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
        ArmA32Instruction::Bl_A1(cond, offset) => insn(
            Isa::Arm,
            pc,
            length,
            a32_conditional(*cond),
            BTreeSet::new(),
            BTreeSet::new(),
            SemanticEffect::None,
            ControlFlow::Call {
                target: Some(CallTarget {
                    entry: branch_target(Isa::Arm, pc, *offset),
                    isa: Isa::Arm,
                }),
            },
        ),
        // blx-immediate is a same-encoding-family, cross-ISA (Arm -> Thumb) call.
        // Resolving it is deferred for v1 (see plan handoff note); target stays None.
        ArmA32Instruction::Blx_Immediate_A1(_) => insn(
            Isa::Arm,
            pc,
            length,
            false,
            BTreeSet::new(),
            BTreeSet::new(),
            SemanticEffect::None,
            ControlFlow::Call { target: None },
        ),
        ArmA32Instruction::Blx_Register_A1(cond, rm) => insn(
            Isa::Arm,
            pc,
            length,
            a32_conditional(*cond),
            set([gpr(*rm)]),
            BTreeSet::new(),
            SemanticEffect::None,
            ControlFlow::Call { target: None },
        ),
        ArmA32Instruction::Bx_A1(cond, rm) => insn(
            Isa::Arm,
            pc,
            length,
            a32_conditional(*cond),
            set([gpr(*rm)]),
            BTreeSet::new(),
            SemanticEffect::None,
            ControlFlow::Stop,
        ),
        other => a32_unsupported(pc, length, other),
    }
}

fn map_t32(pc: u32, length: u8, inst: &ArmT32Instruction) -> DecodedInstruction {
    match inst {
        ArmT32Instruction::Mov_Immediate_T1(rd, imm) => t32_reg_write(
            pc,
            length,
            low_reg(*rd),
            ValueExpr::Immediate(u32::from(*imm)),
            BTreeSet::new(),
        ),
        ArmT32Instruction::Mov_Immediate_T2(rd, imm, _) => t32_reg_write(
            pc,
            length,
            gpr(*rd),
            ValueExpr::Immediate(*imm),
            BTreeSet::new(),
        ),
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
        ArmT32Instruction::Mov_Register_T2(rd, rm) => t32_reg_write(
            pc,
            length,
            low_reg(*rd),
            ValueExpr::Register(low_reg(*rm)),
            set([low_reg(*rm)]),
        ),
        ArmT32Instruction::Mov_Register_T3(rd, rm, shift, _) if shift.is_none() => t32_reg_write(
            pc,
            length,
            gpr(*rd),
            ValueExpr::Register(gpr(*rm)),
            set([gpr(*rm)]),
        ),
        ArmT32Instruction::Add_Immediate_T1(rd, rn, imm) => t32_add_sub_imm(
            pc,
            length,
            low_reg(*rd),
            low_to_gpr(*rn),
            u32::from(*imm),
            false,
        ),
        ArmT32Instruction::Add_Immediate_T2(rdn, imm) => t32_add_sub_imm(
            pc,
            length,
            low_reg(*rdn),
            low_to_gpr(*rdn),
            u32::from(*imm),
            false,
        ),
        ArmT32Instruction::Add_Immediate_T3(rd, rn, imm, _) => {
            t32_add_sub_imm(pc, length, gpr(*rd), *rn, *imm, false)
        }
        ArmT32Instruction::Sub_Immediate_T1(rd, rn, imm) => t32_add_sub_imm(
            pc,
            length,
            low_reg(*rd),
            low_to_gpr(*rn),
            u32::from(*imm),
            true,
        ),
        ArmT32Instruction::Sub_Immediate_T2(rdn, imm) => t32_add_sub_imm(
            pc,
            length,
            low_reg(*rdn),
            low_to_gpr(*rdn),
            u32::from(*imm),
            true,
        ),
        ArmT32Instruction::Sub_Immediate_T3(rd, rn, imm, _) => {
            t32_add_sub_imm(pc, length, gpr(*rd), *rn, *imm, true)
        }
        ArmT32Instruction::Add_Register_T1(rd, rn, rm) => t32_add_sub_reg(
            pc,
            length,
            low_reg(*rd),
            low_to_gpr(*rn),
            low_to_gpr(*rm),
            Arm32RegisterShift::none(),
            false,
        ),
        ArmT32Instruction::Add_Register_T2(rdn, rm) => t32_add_sub_reg(
            pc,
            length,
            gpr(*rdn),
            *rdn,
            *rm,
            Arm32RegisterShift::none(),
            false,
        ),
        ArmT32Instruction::Add_Register_T3(rd, rn, rm, shift, _) => {
            t32_add_sub_reg(pc, length, gpr(*rd), *rn, *rm, *shift, false)
        }
        ArmT32Instruction::Sub_Register_T1(rd, rn, rm) => t32_add_sub_reg(
            pc,
            length,
            low_reg(*rd),
            low_to_gpr(*rn),
            low_to_gpr(*rm),
            Arm32RegisterShift::none(),
            true,
        ),
        ArmT32Instruction::Sub_Register_T2(rd, rn, rm, shift, _) => {
            t32_add_sub_reg(pc, length, gpr(*rd), *rn, *rm, *shift, true)
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
            a32_conditional(*cond),
        ),
        ArmT32Instruction::B_T2(offset) => t32_branch(
            pc,
            length,
            branch_target(Isa::Thumb, pc, i32::from(*offset)),
            false,
        ),
        ArmT32Instruction::B_T3(cond, offset) => t32_branch(
            pc,
            length,
            branch_target(Isa::Thumb, pc, *offset),
            a32_conditional(*cond),
        ),
        ArmT32Instruction::B_T4(offset) => {
            t32_branch(pc, length, branch_target(Isa::Thumb, pc, *offset), false)
        }
        ArmT32Instruction::Cbz_T1(rn, offset) => {
            t32_compare_branch(pc, length, low_reg(*rn), *offset)
        }
        ArmT32Instruction::Cbnz_T1(rn, offset) => {
            t32_compare_branch(pc, length, low_reg(*rn), *offset)
        }
        ArmT32Instruction::Bl_T1(offset) => insn(
            Isa::Thumb,
            pc,
            length,
            false,
            BTreeSet::new(),
            BTreeSet::new(),
            SemanticEffect::None,
            ControlFlow::Call {
                target: Some(CallTarget {
                    entry: branch_target(Isa::Thumb, pc, *offset),
                    isa: Isa::Thumb,
                }),
            },
        ),
        ArmT32Instruction::Blx_Register_T1(rm) => insn(
            Isa::Thumb,
            pc,
            length,
            false,
            set([gpr(*rm)]),
            BTreeSet::new(),
            SemanticEffect::None,
            ControlFlow::Call { target: None },
        ),
        ArmT32Instruction::Bx_T1(rm) => insn(
            Isa::Thumb,
            pc,
            length,
            false,
            set([gpr(*rm)]),
            BTreeSet::new(),
            SemanticEffect::None,
            ControlFlow::Stop,
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
        SemanticEffect::RegisterWrite { dst, value },
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
        SemanticEffect::RegisterWrite { dst, value },
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
            SemanticEffect::LiteralWordLoad {
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
        SemanticEffect::LiteralWordLoad {
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
        if let SemanticEffect::Memory(effect) = &mut self.effect {
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
        if let SemanticEffect::LiteralWordLoad { address, .. } = &mut self.effect
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
            vec![transfer(imm_addr(rn, offset), AccessKind::Read, width)],
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
            vec![transfer(imm_addr(rn, offset), AccessKind::Write, width)],
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
            vec![transfer(imm_addr(rn, 0), AccessKind::ReadWrite, width)],
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
        .map(|(index, _)| {
            transfer(
                imm_addr(rn, first + 4 * i64::try_from(index).unwrap_or(i64::MAX)),
                kind,
                4,
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
        ControlFlow::Stop
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
    let conditional = a32_conditional(cond);
    insn(
        Isa::Arm,
        pc,
        length,
        conditional,
        BTreeSet::new(),
        BTreeSet::new(),
        SemanticEffect::None,
        ControlFlow::DirectBranch {
            target: branch_target(Isa::Arm, pc, offset),
            has_fallthrough: conditional,
        },
    )
}

fn t32_branch(pc: u32, length: u8, target: u32, conditional: bool) -> DecodedInstruction {
    insn(
        Isa::Thumb,
        pc,
        length,
        conditional,
        BTreeSet::new(),
        BTreeSet::new(),
        SemanticEffect::None,
        ControlFlow::DirectBranch {
            target,
            has_fallthrough: conditional,
        },
    )
}

fn t32_compare_branch(pc: u32, length: u8, rn: Register, offset: u8) -> DecodedInstruction {
    insn(
        Isa::Thumb,
        pc,
        length,
        true,
        set([rn]),
        BTreeSet::new(),
        SemanticEffect::None,
        ControlFlow::DirectBranch {
            target: branch_target(Isa::Thumb, pc, i32::from(offset)),
            has_fallthrough: true,
        },
    )
}

fn map_it(pc: u32, length: u8, _cond: Arm32Condition, _mask: u8) -> DecodedInstruction {
    insn(
        Isa::Thumb,
        pc,
        length,
        false,
        BTreeSet::new(),
        BTreeSet::new(),
        SemanticEffect::None,
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
        SemanticEffect::Unsupported,
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

fn a32_stop(
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
        ControlFlow::Stop,
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
        ArmA32Instruction::Mvn_Register_A1(cond, _, rd, rm, _)
        | ArmA32Instruction::Mov_Register_A1(cond, _, rd, rm, _) => {
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
        ArmA32Instruction::Tst_Immediate_A1(cond, rn, _)
        | ArmA32Instruction::Teq_Immediate_A1(cond, rn, _)
        | ArmA32Instruction::Cmp_Immediate_A1(cond, rn, _)
        | ArmA32Instruction::Cmn_Immediate_A1(cond, rn, _) => {
            a32_linear(pc, length, *cond, set([gpr(*rn)]), BTreeSet::new())
        }
        ArmA32Instruction::Tst_Register_A1(cond, rn, rm, _)
        | ArmA32Instruction::Teq_Register_A1(cond, rn, rm, _)
        | ArmA32Instruction::Cmp_Register_A1(cond, rn, rm, _)
        | ArmA32Instruction::Cmn_Register_A1(cond, rn, rm, _) => a32_linear(
            pc,
            length,
            *cond,
            set([gpr(*rn), gpr(*rm)]),
            BTreeSet::new(),
        ),
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
        ArmA32Instruction::Mrs_A1(cond, _, rd)
        | ArmA32Instruction::MrsBanked_A1(cond, _, _, rd) => {
            a32_linear(pc, length, *cond, BTreeSet::new(), set([gpr(*rd)]))
        }
        ArmA32Instruction::Msr_Register_A1(cond, _, _, rm)
        | ArmA32Instruction::MsrBanked_A1(cond, _, _, rm) => {
            a32_linear(pc, length, *cond, set([gpr(*rm)]), BTreeSet::new())
        }
        ArmA32Instruction::Msr_Immediate_A1(cond, _, _, _) => {
            a32_linear(pc, length, *cond, BTreeSet::new(), BTreeSet::new())
        }
        ArmA32Instruction::Mrc_A1(cond, _, _, rt, _, _, _) => {
            a32_linear(pc, length, *cond, BTreeSet::new(), set([gpr(*rt)]))
        }
        ArmA32Instruction::Mrc2_A1(_, _, rt, _, _, _) => unsupported(
            Isa::Arm,
            pc,
            length,
            false,
            BTreeSet::new(),
            set([gpr(*rt)]),
            ControlFlow::Linear,
        ),
        ArmA32Instruction::Mcr_A1(cond, _, _, rt, _, _, _) => {
            a32_linear(pc, length, *cond, set([gpr(*rt)]), BTreeSet::new())
        }
        ArmA32Instruction::Mcr2_A1(_, _, rt, _, _, _) => unsupported(
            Isa::Arm,
            pc,
            length,
            false,
            set([gpr(*rt)]),
            BTreeSet::new(),
            ControlFlow::Linear,
        ),
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
                ControlFlow::Stop,
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
            a32_stop(pc, length, *cond, set([gpr(*rm)]), BTreeSet::new())
        }
        ArmA32Instruction::Svc_A1(cond, _)
        | ArmA32Instruction::Bkpt_A1(cond, _)
        | ArmA32Instruction::Hlt_A1(cond, _)
        | ArmA32Instruction::Hvc_A1(cond, _)
        | ArmA32Instruction::Smc_A1(cond, _)
        | ArmA32Instruction::Udf_A1(cond, _)
        | ArmA32Instruction::Eret_A1(cond) => {
            a32_stop(pc, length, *cond, BTreeSet::new(), BTreeSet::new())
        }
        _ => unsupported(
            Isa::Arm,
            pc,
            length,
            false,
            BTreeSet::new(),
            all_core_registers(),
            ControlFlow::Stop,
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

fn t32_stop(
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
        ControlFlow::Stop,
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
        ArmT32Instruction::Lsl_Immediate_T1(rd, rm, _)
        | ArmT32Instruction::Lsr_Immediate_T1(rd, rm, _)
        | ArmT32Instruction::Asr_Immediate_T1(rd, rm, _)
        | ArmT32Instruction::Mvn_Register_T1(rd, rm)
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
        ArmT32Instruction::Mvn_Immediate_T1(rd, _, _) | ArmT32Instruction::Mrs_T1(rd, _) => {
            t32_linear(pc, length, BTreeSet::new(), set([gpr(*rd)]))
        }
        ArmT32Instruction::Mov_Register_T3(rd, rm, _, _)
        | ArmT32Instruction::Mvn_Register_T2(rd, rm, _, _)
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
        ArmT32Instruction::Cmp_Immediate_T1(rn, _) => {
            t32_linear(pc, length, set([low_reg(*rn)]), BTreeSet::new())
        }
        ArmT32Instruction::Cmp_Immediate_T2(rn, _)
        | ArmT32Instruction::Tst_Immediate_T1(rn, _)
        | ArmT32Instruction::Teq_Immediate_T1(rn, _)
        | ArmT32Instruction::Cmn_Immediate_T1(rn, _) => {
            t32_linear(pc, length, set([gpr(*rn)]), BTreeSet::new())
        }
        ArmT32Instruction::Tst_Register_T1(rn, rm)
        | ArmT32Instruction::Cmp_Register_T1(rn, rm)
        | ArmT32Instruction::Cmn_Register_T1(rn, rm) => t32_linear(
            pc,
            length,
            set([low_reg(*rn), low_reg(*rm)]),
            BTreeSet::new(),
        ),
        ArmT32Instruction::Cmp_Register_T2(rn, rm)
        | ArmT32Instruction::Tst_Register_T2(rn, rm, _)
        | ArmT32Instruction::Teq_Register_T1(rn, rm, _)
        | ArmT32Instruction::Cmn_Register_T2(rn, rm, _)
        | ArmT32Instruction::Cmp_Register_T3(rn, rm, _) => {
            t32_linear(pc, length, set([gpr(*rn), gpr(*rm)]), BTreeSet::new())
        }
        ArmT32Instruction::Msr_Register_T1(_, rn) => {
            t32_linear(pc, length, set([gpr(*rn)]), BTreeSet::new())
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
        ArmT32Instruction::Coproc_Mcr_T1(_, false, _, _, rt, _, _, _) => {
            t32_linear(pc, length, set([gpr(*rt)]), BTreeSet::new())
        }
        ArmT32Instruction::Coproc_Mcr_T1(_, true, _, _, rt, _, _, _) => {
            t32_linear(pc, length, BTreeSet::new(), set([gpr(*rt)]))
        }
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
        ArmT32Instruction::PacbtiData_T1(2, rd, rn, rm) => t32_stop(
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
            t32_stop(pc, length, BTreeSet::new(), BTreeSet::new())
        }
        ArmT32Instruction::Bfx_T3(_, rn) | ArmT32Instruction::Bflx_T5(_, rn) => {
            t32_stop(pc, length, set([gpr(*rn)]), BTreeSet::new())
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
        ArmT32Instruction::Bxns_T1(rm) => t32_stop(pc, length, set([gpr(*rm)]), BTreeSet::new()),
        ArmT32Instruction::Blxns_T1(rm) => insn(
            Isa::Thumb,
            pc,
            length,
            false,
            set([gpr(*rm)]),
            BTreeSet::new(),
            SemanticEffect::None,
            ControlFlow::Call { target: None },
        ),
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
            t32_stop(pc, length, set([gpr(*rn), gpr(*rm)]), BTreeSet::new())
        }
        ArmT32Instruction::Svc_T1(_)
        | ArmT32Instruction::Bkpt_T1(_)
        | ArmT32Instruction::Hlt_T1(_)
        | ArmT32Instruction::Udf_T1(_)
        | ArmT32Instruction::Udf_T2(_) => t32_stop(pc, length, BTreeSet::new(), BTreeSet::new()),
        _ => unsupported(
            Isa::Thumb,
            pc,
            length,
            false,
            BTreeSet::new(),
            all_core_registers(),
            ControlFlow::Stop,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::execution_ranges::ExecutionIdentity;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    const R0: Register = Register(0);
    const R1: Register = Register(1);
    const R2: Register = Register(2);
    const R3: Register = Register(3);
    const R12: Register = Register(12);

    fn decode(isa: Isa, pc: u32, bytes: &[u8]) -> DecodedInstruction {
        let decoder = PureRustDecoder;
        let mut state = decoder.begin_range(isa);
        decoder
            .decode_one(&mut state, isa, pc, bytes)
            .expect("fixture must decode")
    }

    fn regs(values: &[Register]) -> BTreeSet<Register> {
        values.iter().copied().collect()
    }

    fn expected(
        isa: Isa,
        length: u8,
        conditional: bool,
        reads: &[Register],
        writes: &[Register],
        effect: SemanticEffect,
        flow: ControlFlow,
    ) -> DecodedInstruction {
        DecodedInstruction {
            isa,
            pc: 0x1000,
            length,
            conditional,
            reads: regs(reads),
            writes: regs(writes),
            effect,
            flow,
        }
    }

    fn write(dst: Register, value: ValueExpr) -> SemanticEffect {
        SemanticEffect::RegisterWrite { dst, value }
    }

    fn mem(
        address: AddressExpr,
        kind: AccessKind,
        width: u8,
        writeback: Option<(Register, AddressExpr)>,
    ) -> SemanticEffect {
        memory(vec![transfer(address, kind, width)], writeback)
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

    fn direct(target: u32, has_fallthrough: bool) -> ControlFlow {
        ControlFlow::DirectBranch {
            target,
            has_fallthrough,
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
                    SemanticEffect::LiteralWordLoad {
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
                    mem(imm(R1, 4), AccessKind::Read, 4, None),
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
                    mem(imm(R1, 4), AccessKind::Write, 4, None),
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
                    mem(imm(R1, 4), AccessKind::Read, 1, None),
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
                    mem(imm(R1, 4), AccessKind::Write, 1, None),
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
                    mem(imm(R1, 4), AccessKind::Read, 2, None),
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
                    mem(imm(R1, 4), AccessKind::Write, 2, None),
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
                    mem(imm(R1, 4), AccessKind::Read, 1, None),
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
                    mem(imm(R1, 4), AccessKind::Read, 2, None),
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
                    mem(imm(R1, 8), AccessKind::Read, 8, None),
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
                    mem(imm(R1, 8), AccessKind::Write, 8, None),
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
                    mem(reg_off(R1, R2), AccessKind::Read, 4, None),
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
                    mem(imm(R1, -4), AccessKind::Read, 4, None),
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
                    mem(imm(R1, 4), AccessKind::Read, 4, Some((R1, imm(R1, 4)))),
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
                    mem(imm(R1, 0), AccessKind::Read, 4, Some((R1, imm(R1, 4)))),
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
                    mem(imm(R1, 0), AccessKind::Read, 4, None),
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
                    mem(imm(R1, 0), AccessKind::Write, 4, None),
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
                    mem(imm(R2, 0), AccessKind::ReadWrite, 4, None),
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
                            transfer(imm(R0, 0), AccessKind::Read, 4),
                            transfer(imm(R0, 4), AccessKind::Read, 4),
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
                            transfer(imm(R0, -8), AccessKind::Write, 4),
                            transfer(imm(R0, -4), AccessKind::Write, 4),
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
                    SemanticEffect::None,
                    direct(0x1008, false),
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
                    SemanticEffect::None,
                    ControlFlow::Call {
                        target: Some(CallTarget {
                            entry: 0x1008,
                            isa: Isa::Arm,
                        }),
                    },
                ),
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
                    SemanticEffect::None,
                    ControlFlow::Stop,
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
                    SemanticEffect::None,
                    ControlFlow::Call { target: None },
                ),
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
                    SemanticEffect::None,
                    direct(0x1008, true),
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
                    mem(imm(R1, 4), AccessKind::Read, 4, None),
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
                ),
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
                ),
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
                ),
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
                    SemanticEffect::LiteralWordLoad {
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
                    mem(imm(R1, 4), AccessKind::Read, 4, None),
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
                    mem(imm(R1, 4), AccessKind::Write, 4, None),
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
                    mem(imm(R1, 4), AccessKind::Read, 1, None),
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
                    mem(imm(R1, 4), AccessKind::Write, 1, None),
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
                    mem(imm(R1, 4), AccessKind::Read, 2, None),
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
                    mem(imm(R1, 4), AccessKind::Write, 2, None),
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
                    mem(reg_off(R1, R2), AccessKind::Read, 1, None),
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
                    mem(reg_off(R1, R2), AccessKind::Read, 2, None),
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
                    mem(reg_off(R1, R2), AccessKind::Read, 4, None),
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
                    mem(imm(R1, 4), AccessKind::Read, 1, Some((R1, imm(R1, 4)))),
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
                    mem(imm(R1, 0), AccessKind::Read, 1, Some((R1, imm(R1, 4)))),
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
                    mem(imm(R2, 8), AccessKind::Read, 8, None),
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
                    mem(imm(R2, 8), AccessKind::Write, 8, None),
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
                    mem(imm(R1, 0), AccessKind::Read, 4, None),
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
                    mem(imm(R1, 0), AccessKind::Write, 4, None),
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
                            transfer(imm(R0, 0), AccessKind::Read, 4),
                            transfer(imm(R0, 4), AccessKind::Read, 4),
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
                            transfer(imm(R0, 0), AccessKind::Write, 4),
                            transfer(imm(R0, 4), AccessKind::Write, 4),
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
                        vec![transfer(imm(SP, -4), AccessKind::Write, 4)],
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
                            transfer(imm(SP, 0), AccessKind::Read, 4),
                            transfer(imm(SP, 4), AccessKind::Read, 4),
                        ],
                        Some((SP, imm(SP, 8))),
                    ),
                    ControlFlow::Stop,
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
                    SemanticEffect::None,
                    direct(0x1004, false),
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
                    SemanticEffect::None,
                    ControlFlow::Call {
                        target: Some(CallTarget {
                            entry: 0x1004,
                            isa: Isa::Thumb,
                        }),
                    },
                ),
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
                    SemanticEffect::None,
                    ControlFlow::Stop,
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
                    SemanticEffect::None,
                    ControlFlow::Call { target: None },
                ),
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
                    SemanticEffect::None,
                    direct(0x1004, true),
                ),
            },
            NamedFixture {
                name: "t32_it_eq",
                isa: Isa::Thumb,
                bytes: &[0x08, 0xbf],
                expected: expected(
                    Isa::Thumb,
                    2,
                    false,
                    &[],
                    &[],
                    SemanticEffect::None,
                    linear(),
                ),
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
                ),
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
                    SemanticEffect::Unsupported,
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
                    SemanticEffect::Unsupported,
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
                    SemanticEffect::Unsupported,
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
                    SemanticEffect::Unsupported,
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
                    SemanticEffect::Unsupported,
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
                    SemanticEffect::Unsupported,
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
                    SemanticEffect::Unsupported,
                    linear(),
                ),
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
                    SemanticEffect::Unsupported,
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
                    SemanticEffect::Unsupported,
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
                    SemanticEffect::Unsupported,
                    linear(),
                ),
            },
            NamedFixture {
                name: "t32_mcr",
                isa: Isa::Thumb,
                bytes: &[0x00, 0xee, 0x10, 0x1f],
                expected: expected(
                    Isa::Thumb,
                    4,
                    false,
                    &[R1],
                    &[],
                    SemanticEffect::Unsupported,
                    linear(),
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
                    SemanticEffect::Unsupported,
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
                    SemanticEffect::Unsupported,
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
                    SemanticEffect::Unsupported,
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
                    SemanticEffect::Unsupported,
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
                    SemanticEffect::Unsupported,
                    ControlFlow::Stop,
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
                    SemanticEffect::Unsupported,
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
                    SemanticEffect::Unsupported,
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
                    SemanticEffect::Unsupported,
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
                    SemanticEffect::Unsupported,
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
        let insn = decode_a32(0x1000, &[0x04, 0x00, 0x00, 0xeb]).expect("fixture must decode");
        assert_eq!(
            insn.flow,
            ControlFlow::Call {
                target: Some(CallTarget {
                    entry: 0x1018,
                    isa: Isa::Arm,
                }),
            }
        );
    }

    #[test]
    fn t32_bl_carries_resolved_thumb_target() {
        // BL +0 (T1), same bytes as the `t32_bl` fixture, decoded at a different pc
        // to confirm the target tracks the caller's pc, not a fixed offset.
        let mut state = ItRangeState::default();
        let insn =
            decode_t32(&mut state, 0x2000, &[0x00, 0xf0, 0x00, 0xf8]).expect("fixture must decode");
        match insn.flow {
            ControlFlow::Call { target: Some(t) } => {
                assert_eq!(
                    t,
                    CallTarget {
                        entry: 0x2004,
                        isa: Isa::Thumb
                    }
                );
            }
            other => panic!("expected resolved thumb call, got {other:?}"),
        }
    }

    #[test]
    fn blx_and_bx_do_not_resolve_a_target() {
        // BLX r0 / BX lr (A32 register forms) must not fabricate a target.
        let blx = decode_a32(0x1000, &[0x30, 0xff, 0x2f, 0xe1]).expect("fixture must decode");
        assert!(matches!(blx.flow, ControlFlow::Call { target: None }));
        let bx = decode_a32(0x1000, &[0x1e, 0xff, 0x2f, 0xe1]).expect("fixture must decode");
        assert!(matches!(bx.flow, ControlFlow::Stop));
    }

    fn function(entry: u32, ranges: Vec<DecodeRange>) -> FunctionExecution {
        FunctionExecution {
            identity: ExecutionIdentity {
                entry,
                decode_ranges: ranges,
            },
            contexts: BTreeSet::new(),
        }
    }

    fn arm_range(start: u32, end: u32) -> DecodeRange {
        DecodeRange {
            start,
            end,
            isa: Isa::Arm,
        }
    }

    fn thumb_range(start: u32, end: u32) -> DecodeRange {
        DecodeRange {
            start,
            end,
            isa: Isa::Thumb,
        }
    }

    #[derive(Debug, Clone)]
    enum Scripted {
        Insn(DecodedInstruction),
        Err(&'static str),
        Panic,
    }

    #[derive(Debug, Clone)]
    struct DecodeCall {
        isa: Isa,
        pc: u32,
        bytes: Vec<u8>,
    }

    struct ScriptedDecoder {
        begin_log: RefCell<Vec<Isa>>,
        decode_log: RefCell<Vec<DecodeCall>>,
        script: RefCell<VecDeque<Scripted>>,
    }

    impl ScriptedDecoder {
        fn new(script: Vec<Scripted>) -> Self {
            Self {
                begin_log: RefCell::new(Vec::new()),
                decode_log: RefCell::new(Vec::new()),
                script: RefCell::new(script.into()),
            }
        }
    }

    impl InstructionDecoder for ScriptedDecoder {
        type RangeState = ();

        fn identity(&self) -> DecoderIdentity {
            DecoderIdentity {
                crate_name: "scripted",
                version: "0",
            }
        }

        fn begin_range(&self, isa: Isa) -> Self::RangeState {
            self.begin_log.borrow_mut().push(isa);
        }

        fn decode_one(
            &self,
            _state: &mut Self::RangeState,
            isa: Isa,
            pc: u32,
            bytes: &[u8],
        ) -> std::result::Result<DecodedInstruction, DecodeError> {
            self.decode_log.borrow_mut().push(DecodeCall {
                isa,
                pc,
                bytes: bytes.to_vec(),
            });
            match self.script.borrow_mut().pop_front() {
                Some(Scripted::Insn(instruction)) => Ok(instruction),
                Some(Scripted::Err(message)) => Err(decode_err(message)),
                Some(Scripted::Panic) => panic!("deliberate decoder panic"),
                None => Ok(DecodedInstruction {
                    isa,
                    pc,
                    length: match isa {
                        Isa::Arm => 4,
                        Isa::Thumb => 2,
                    },
                    conditional: false,
                    reads: BTreeSet::new(),
                    writes: BTreeSet::new(),
                    effect: SemanticEffect::None,
                    flow: ControlFlow::Linear,
                }),
            }
        }
    }

    fn linear_at(isa: Isa, pc: u32, length: u8) -> DecodedInstruction {
        DecodedInstruction {
            isa,
            pc,
            length,
            conditional: false,
            reads: BTreeSet::new(),
            writes: BTreeSet::new(),
            effect: SemanticEffect::None,
            flow: ControlFlow::Linear,
        }
    }

    fn flow_at(isa: Isa, pc: u32, length: u8, flow: ControlFlow) -> DecodedInstruction {
        DecodedInstruction {
            isa,
            pc,
            length,
            conditional: false,
            reads: BTreeSet::new(),
            writes: BTreeSet::new(),
            effect: SemanticEffect::None,
            flow,
        }
    }

    fn err_message(result: Result<DecodedFunction>) -> String {
        match result {
            Err(Error::Serialize(message)) => message,
            other => panic!("expected serialize error, got {other:?}"),
        }
    }

    #[test]
    fn decode_function_passes_only_range_bytes_and_fresh_state() {
        let image = (0u8..=0x1f).collect::<Vec<_>>();
        let decoder = ScriptedDecoder::new(vec![
            Scripted::Insn(linear_at(Isa::Arm, 0x1000, 4)),
            Scripted::Insn(linear_at(Isa::Arm, 0x1004, 4)),
            Scripted::Insn(linear_at(Isa::Thumb, 0x1010, 2)),
        ]);
        let decoded = decode_function(
            &decoder,
            &function(
                0x1000,
                vec![arm_range(0x1000, 0x1008), thumb_range(0x1010, 0x1012)],
            ),
            &image,
            0x1000,
        )
        .expect("scripted decode");
        assert_eq!(
            decoder.begin_log.borrow().as_slice(),
            &[Isa::Arm, Isa::Thumb]
        );
        let calls = decoder.decode_log.borrow();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].isa, Isa::Arm);
        assert_eq!(calls[0].pc, 0x1000);
        assert_eq!(calls[0].bytes, image[0..8]);
        assert_eq!(calls[1].isa, Isa::Arm);
        assert_eq!(calls[1].pc, 0x1004);
        assert_eq!(calls[1].bytes, image[4..8]);
        assert_eq!(calls[2].isa, Isa::Thumb);
        assert_eq!(calls[2].pc, 0x1010);
        assert_eq!(calls[2].bytes, image[0x10..0x12]);
        assert_eq!(decoded.ranges.len(), 2);
        assert_eq!(decoded.ranges[0].instructions.len(), 2);
        assert_eq!(decoded.ranges[1].instructions.len(), 1);
        assert!(
            decoded
                .ranges
                .iter()
                .all(|range| range.decode_failure.is_none())
        );
    }

    #[test]
    fn decode_function_records_prefix_failure_and_continues() {
        let image = vec![0u8; 0x20];
        let decoder = ScriptedDecoder::new(vec![
            Scripted::Insn(linear_at(Isa::Arm, 0x1000, 4)),
            Scripted::Err("truncated encoding"),
            Scripted::Insn(linear_at(Isa::Thumb, 0x1010, 2)),
        ]);
        let decoded = decode_function(
            &decoder,
            &function(
                0x1000,
                vec![arm_range(0x1000, 0x1008), thumb_range(0x1010, 0x1012)],
            ),
            &image,
            0x1000,
        )
        .expect("prefix failure is recoverable");
        assert_eq!(decoded.ranges[0].instructions.len(), 1);
        assert_eq!(
            decoded.ranges[0].decode_failure,
            Some(DecodeFailure {
                pc: 0x1004,
                message: "truncated encoding".into(),
            })
        );
        assert_eq!(decoded.ranges[1].instructions.len(), 1);
        assert_eq!(decoded.ranges[1].decode_failure, None);
        assert_eq!(decoder.begin_log.borrow().len(), 2);
    }

    #[test]
    fn decode_function_rejects_adapter_invariants() {
        let image = vec![0u8; 16];
        let cases = [
            (
                "wrong pc",
                Scripted::Insn(linear_at(Isa::Arm, 0x2000, 4)),
                "requested PC",
            ),
            (
                "wrong isa",
                Scripted::Insn(linear_at(Isa::Thumb, 0x1000, 2)),
                "ISA",
            ),
            (
                "zero length",
                Scripted::Insn(linear_at(Isa::Arm, 0x1000, 0)),
                "impossible instruction length",
            ),
            (
                "impossible length",
                Scripted::Insn(linear_at(Isa::Arm, 0x1000, 3)),
                "impossible instruction length",
            ),
            (
                "overrun",
                Scripted::Insn(linear_at(Isa::Arm, 0x1000, 4)),
                "overruns",
            ),
        ];
        for (name, scripted, needle) in cases {
            let end = if name == "overrun" { 0x1002 } else { 0x1008 };
            let decoder = ScriptedDecoder::new(vec![scripted]);
            let result = decode_function(
                &decoder,
                &function(0x1000, vec![arm_range(0x1000, end)]),
                &image,
                0x1000,
            );
            let message = err_message(result);
            assert!(message.contains(needle), "{name}: {message}");
        }
    }

    #[test]
    fn decode_function_rejects_duplicate_pcs() {
        let decoder = ScriptedDecoder::new(vec![
            Scripted::Insn(linear_at(Isa::Arm, 0x1000, 4)),
            Scripted::Insn(linear_at(Isa::Arm, 0x1000, 4)),
        ]);
        let message = err_message(decode_function(
            &decoder,
            &function(0x1000, vec![arm_range(0x1000, 0x1008)]),
            &[0; 16],
            0x1000,
        ));
        assert!(message.contains("duplicate"), "duplicate PC: {message}");
    }

    #[test]
    fn decode_function_rejects_pc_regression() {
        let decoder = ScriptedDecoder::new(vec![
            Scripted::Insn(linear_at(Isa::Arm, 0x1000, 4)),
            Scripted::Insn(linear_at(Isa::Arm, 0x0ffc, 4)),
        ]);
        let message = err_message(decode_function(
            &decoder,
            &function(0x1000, vec![arm_range(0x1000, 0x1008)]),
            &[0; 16],
            0x1000,
        ));
        assert!(message.contains("regressed"), "PC regression: {message}");
    }

    #[test]
    fn decode_function_does_not_cross_range_gaps_or_isa() {
        let image = vec![0u8; 16];
        let decoder = ScriptedDecoder::new(Vec::new());
        let decoded = decode_function(
            &decoder,
            &function(
                0x1000,
                vec![arm_range(0x1000, 0x1004), thumb_range(0x1008, 0x100a)],
            ),
            &image,
            0x1000,
        )
        .expect("adjacent ISA ranges stay isolated");
        assert_eq!(
            decoded.ranges[0]
                .instructions
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            vec![0x1000]
        );
        assert_eq!(
            decoded.ranges[1]
                .instructions
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            vec![0x1008]
        );
        assert_eq!(decoder.decode_log.borrow()[0].bytes.len(), 4);
        assert_eq!(decoder.decode_log.borrow()[1].bytes.len(), 2);
    }

    #[test]
    fn decode_function_truncated_tails_do_not_guess() {
        let decoder = PureRustDecoder;
        let decoded = decode_function(
            &decoder,
            &function(0x1000, vec![arm_range(0x1000, 0x1005)]),
            &[0x01, 0x00, 0xa0, 0xe3, 0xff],
            0x1000,
        )
        .expect("truncated tail is a prefix failure");
        assert_eq!(decoded.ranges[0].instructions.len(), 1);
        assert_eq!(
            decoded.ranges[0]
                .decode_failure
                .as_ref()
                .map(|failure| failure.pc),
            Some(0x1004)
        );

        let thumb = decode_function(
            &decoder,
            &function(0x1000, vec![thumb_range(0x1000, 0x1001)]),
            &[0x01],
            0x1000,
        )
        .expect("one-byte thumb range fails closed");
        assert!(thumb.ranges[0].instructions.is_empty());
        assert!(thumb.ranges[0].decode_failure.is_some());
    }

    #[test]
    fn decode_function_arbitrary_buffers_do_not_panic_or_loop() {
        let decoder = PureRustDecoder;
        for length in 0..=256 {
            for fill in [0u8, 0xff] {
                let bytes = vec![fill; length];
                for isa in [Isa::Arm, Isa::Thumb] {
                    let end = 0x1000 + u32::try_from(length).expect("length fits");
                    let range = DecodeRange {
                        start: 0x1000,
                        end: end.max(0x1002),
                        isa,
                    };
                    let result = catch_unwind(AssertUnwindSafe(|| {
                        decode_function(&decoder, &function(0x1000, vec![range]), &bytes, 0x1000)
                    }));
                    assert!(
                        result.is_ok(),
                        "decoder panicked on {isa:?} fill={fill:#x} len={length}"
                    );
                }
            }
        }
    }

    #[test]
    fn decode_function_propagates_decoder_panic() {
        let decoder = ScriptedDecoder::new(vec![Scripted::Panic]);
        let result = catch_unwind(AssertUnwindSafe(|| {
            decode_function(
                &decoder,
                &function(0x1000, vec![arm_range(0x1000, 0x1004)]),
                &[0; 4],
                0x1000,
            )
        }));
        let payload = result.expect_err("panicking decoder must remain a panic here");
        let message = payload.downcast_ref::<&str>().copied().unwrap_or("");
        assert_eq!(message, "deliberate decoder panic");
    }

    #[test]
    fn decode_function_it_marks_governed_instructions_and_resets_at_range() {
        let decoder = PureRustDecoder;
        let decoded = decode_function(
            &decoder,
            &function(
                0x1000,
                vec![thumb_range(0x1000, 0x1004), thumb_range(0x1008, 0x100a)],
            ),
            &[0x08, 0xbf, 0x01, 0x20, 0, 0, 0, 0, 0x01, 0x20],
            0x1000,
        )
        .expect("IT range");
        assert!(!decoded.ranges[0].instructions[&0x1000].conditional);
        assert!(decoded.ranges[0].instructions[&0x1002].conditional);
        assert!(!decoded.ranges[1].instructions[&0x1008].conditional);
    }

    fn decoded_from(
        _function: &FunctionExecution,
        instructions: Vec<(DecodeRange, Vec<DecodedInstruction>)>,
    ) -> DecodedFunction {
        DecodedFunction {
            ranges: instructions
                .into_iter()
                .map(|(range, insns)| DecodedRange {
                    range,
                    instructions: insns.into_iter().map(|insn| (insn.pc, insn)).collect(),
                    decode_failure: None,
                })
                .collect(),
        }
    }

    #[test]
    fn reachable_blocks_start_only_at_entry() {
        let range = arm_range(0x1000, 0x1008);
        let function = function(0x1004, vec![range]);
        let decoded = decoded_from(
            &function,
            vec![(
                range,
                vec![
                    linear_at(Isa::Arm, 0x1000, 4),
                    linear_at(Isa::Arm, 0x1004, 4),
                ],
            )],
        );
        let blocks = reachable_blocks(&function, &decoded).expect("entry is decoded");
        assert_eq!(
            blocks,
            vec![Block {
                isa: Isa::Arm,
                start: 0x1004,
                end: 0x1008,
                successors: vec![]
            }]
        );
    }

    #[test]
    fn reachable_blocks_require_decoded_entry() {
        let range = arm_range(0x1000, 0x1004);
        let function = function(0x1000, vec![range]);
        let decoded = DecodedFunction {
            ranges: vec![DecodedRange {
                range,
                instructions: BTreeMap::new(),
                decode_failure: Some(DecodeFailure {
                    pc: 0x1000,
                    message: "truncated encoding".into(),
                }),
            }],
        };
        let blocks =
            reachable_blocks(&function, &decoded).expect("undecoded entry is recoverable loss");
        assert_eq!(blocks, Vec::new());
    }

    #[test]
    fn reachable_blocks_conditional_branch_reaches_target_and_fallthrough() {
        let range = arm_range(0x1000, 0x1010);
        let function = function(0x1000, vec![range]);
        let decoded = decoded_from(
            &function,
            vec![(
                range,
                vec![
                    flow_at(Isa::Arm, 0x1000, 4, direct(0x100c, true)),
                    linear_at(Isa::Arm, 0x1004, 4),
                    linear_at(Isa::Arm, 0x1008, 4),
                    linear_at(Isa::Arm, 0x100c, 4),
                ],
            )],
        );
        let blocks = reachable_blocks(&function, &decoded).expect("conditional branch");
        assert_eq!(
            blocks,
            vec![
                Block {
                    isa: Isa::Arm,
                    start: 0x1000,
                    end: 0x1004,
                    successors: vec![0x100c, 0x1004],
                },
                Block {
                    isa: Isa::Arm,
                    start: 0x1004,
                    end: 0x100c,
                    successors: vec![0x100c],
                },
                Block {
                    isa: Isa::Arm,
                    start: 0x100c,
                    end: 0x1010,
                    successors: vec![],
                },
            ]
        );
    }

    #[test]
    fn reachable_blocks_successors_dedup_when_target_equals_fallthrough() {
        let range = arm_range(0x1000, 0x100c);
        let function = function(0x1000, vec![range]);
        let decoded = decoded_from(
            &function,
            vec![(
                range,
                vec![
                    flow_at(Isa::Arm, 0x1000, 4, direct(0x1004, true)),
                    linear_at(Isa::Arm, 0x1004, 4),
                    linear_at(Isa::Arm, 0x1008, 4),
                ],
            )],
        );
        let blocks = reachable_blocks(&function, &decoded).expect("target equals fallthrough");
        assert_eq!(
            blocks[0].successors,
            vec![0x1004],
            "target == fallthrough must yield one edge, not two"
        );
    }

    #[test]
    fn reachable_blocks_unconditional_branch_reaches_only_target() {
        let range = arm_range(0x1000, 0x100c);
        let function = function(0x1000, vec![range]);
        let decoded = decoded_from(
            &function,
            vec![(
                range,
                vec![
                    flow_at(Isa::Arm, 0x1000, 4, direct(0x1008, false)),
                    linear_at(Isa::Arm, 0x1004, 4),
                    linear_at(Isa::Arm, 0x1008, 4),
                ],
            )],
        );
        let blocks = reachable_blocks(&function, &decoded).expect("unconditional branch");
        assert_eq!(
            blocks,
            vec![
                Block {
                    isa: Isa::Arm,
                    start: 0x1000,
                    end: 0x1004,
                    successors: vec![0x1008]
                },
                Block {
                    isa: Isa::Arm,
                    start: 0x1008,
                    end: 0x100c,
                    successors: vec![]
                },
            ]
        );
    }

    #[test]
    fn reachable_blocks_call_reaches_only_fallthrough() {
        let range = arm_range(0x1000, 0x100c);
        let function = function(0x1000, vec![range]);
        let decoded = decoded_from(
            &function,
            vec![(
                range,
                vec![
                    flow_at(Isa::Arm, 0x1000, 4, ControlFlow::Call { target: None }),
                    linear_at(Isa::Arm, 0x1004, 4),
                ],
            )],
        );
        let blocks = reachable_blocks(&function, &decoded).expect("call");
        assert_eq!(
            blocks,
            vec![
                Block {
                    isa: Isa::Arm,
                    start: 0x1000,
                    end: 0x1004,
                    successors: vec![0x1004]
                },
                Block {
                    isa: Isa::Arm,
                    start: 0x1004,
                    end: 0x1008,
                    successors: vec![]
                },
            ]
        );
    }

    #[test]
    fn reachable_blocks_stop_ends_path() {
        let range = arm_range(0x1000, 0x1008);
        let function = function(0x1000, vec![range]);
        let decoded = decoded_from(
            &function,
            vec![(
                range,
                vec![
                    flow_at(Isa::Arm, 0x1000, 4, ControlFlow::Stop),
                    linear_at(Isa::Arm, 0x1004, 4),
                ],
            )],
        );
        let blocks = reachable_blocks(&function, &decoded).expect("stop");
        assert_eq!(
            blocks,
            vec![Block {
                isa: Isa::Arm,
                start: 0x1000,
                end: 0x1004,
                successors: vec![]
            }]
        );
    }

    #[test]
    fn reachable_blocks_direct_target_may_enter_other_range() {
        let arm = arm_range(0x1000, 0x1004);
        let thumb = thumb_range(0x2000, 0x2002);
        let function = function(0x1000, vec![arm, thumb]);
        let decoded = decoded_from(
            &function,
            vec![
                (
                    arm,
                    vec![flow_at(Isa::Arm, 0x1000, 4, direct(0x2000, false))],
                ),
                (thumb, vec![linear_at(Isa::Thumb, 0x2000, 2)]),
            ],
        );
        let blocks = reachable_blocks(&function, &decoded).expect("cross-range target");
        assert_eq!(
            blocks,
            vec![
                Block {
                    isa: Isa::Arm,
                    start: 0x1000,
                    end: 0x1004,
                    successors: vec![0x2000]
                },
                Block {
                    isa: Isa::Thumb,
                    start: 0x2000,
                    end: 0x2002,
                    successors: vec![]
                },
            ]
        );
    }

    #[test]
    fn reachable_blocks_discard_targets_outside_ranges() {
        let range = arm_range(0x1000, 0x1008);
        let function = function(0x1000, vec![range]);
        let decoded = decoded_from(
            &function,
            vec![(
                range,
                vec![
                    flow_at(Isa::Arm, 0x1000, 4, direct(0x3000, true)),
                    linear_at(Isa::Arm, 0x1004, 4),
                ],
            )],
        );
        let blocks = reachable_blocks(&function, &decoded).expect("outside target discarded");
        assert_eq!(
            blocks,
            vec![
                Block {
                    isa: Isa::Arm,
                    start: 0x1000,
                    end: 0x1004,
                    successors: vec![0x1004]
                },
                Block {
                    isa: Isa::Arm,
                    start: 0x1004,
                    end: 0x1008,
                    successors: vec![]
                },
            ]
        );
    }

    #[test]
    fn reachable_blocks_no_invented_linear_across_gaps() {
        let first = arm_range(0x1000, 0x1004);
        let second = thumb_range(0x1004, 0x1006);
        let function = function(0x1000, vec![first, second]);
        let decoded = decoded_from(
            &function,
            vec![
                (first, vec![linear_at(Isa::Arm, 0x1000, 4)]),
                (second, vec![linear_at(Isa::Thumb, 0x1004, 2)]),
            ],
        );
        let blocks = reachable_blocks(&function, &decoded).expect("no invented ISA edge");
        assert_eq!(
            blocks,
            vec![Block {
                isa: Isa::Arm,
                start: 0x1000,
                end: 0x1004,
                successors: vec![]
            }]
        );
    }

    #[test]
    fn reachable_blocks_disconnected_range_not_reached() {
        let first = arm_range(0x1000, 0x1004);
        let second = arm_range(0x2000, 0x2004);
        let function = function(0x1000, vec![first, second]);
        let decoded = decoded_from(
            &function,
            vec![
                (first, vec![linear_at(Isa::Arm, 0x1000, 4)]),
                (second, vec![linear_at(Isa::Arm, 0x2000, 4)]),
            ],
        );
        let blocks = reachable_blocks(&function, &decoded).expect("disconnected");
        assert_eq!(
            blocks,
            vec![Block {
                isa: Isa::Arm,
                start: 0x1000,
                end: 0x1004,
                successors: vec![]
            }]
        );
    }

    #[test]
    fn reachable_blocks_sorted_non_overlapping() {
        let range = arm_range(0x1000, 0x1010);
        let function = function(0x1000, vec![range]);
        let decoded = decoded_from(
            &function,
            vec![(
                range,
                vec![
                    flow_at(Isa::Arm, 0x1000, 4, direct(0x100c, true)),
                    linear_at(Isa::Arm, 0x1004, 4),
                    flow_at(Isa::Arm, 0x1008, 4, ControlFlow::Stop),
                    linear_at(Isa::Arm, 0x100c, 4),
                ],
            )],
        );
        let blocks = reachable_blocks(&function, &decoded).expect("sorted");
        let starts: Vec<u32> = blocks.iter().map(|block| block.start).collect();
        let mut ordered = starts.clone();
        ordered.sort_unstable();
        assert_eq!(starts, ordered);
        for window in blocks.windows(2) {
            assert!(window[0].end <= window[1].start);
            assert!(window[0].start < window[0].end);
        }
        assert!(!blocks.is_empty());
    }

    #[test]
    fn reachable_blocks_decode_failed_tail_has_no_linear_edge() {
        let range = arm_range(0x1000, 0x100c);
        let function = function(0x1000, vec![range]);
        let decoded = DecodedFunction {
            ranges: vec![DecodedRange {
                range,
                instructions: BTreeMap::from([(0x1000, linear_at(Isa::Arm, 0x1000, 4))]),
                decode_failure: Some(DecodeFailure {
                    pc: 0x1004,
                    message: "truncated encoding".into(),
                }),
            }],
        };
        let blocks = reachable_blocks(&function, &decoded).expect("failed tail");
        assert_eq!(
            blocks,
            vec![Block {
                isa: Isa::Arm,
                start: 0x1000,
                end: 0x1004,
                successors: vec![]
            }]
        );
    }
}
