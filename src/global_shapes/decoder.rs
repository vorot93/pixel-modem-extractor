// Function-range decode orchestration over the shared `crate::arm32`
// semantics, plus the frozen projection of those semantics onto the
// tracker-observation vocabulary the v4 artifact verdicts were pinned to.

use super::FunctionExecution;
use crate::arm32::{self, InstructionDecoder, Register, ValueEffect, valid_isa_length};
use crate::error::{Error, Result};
use crate::execution_ranges::{AuthenticatedDecodeRange, DecodeIsa as Isa};
use std::collections::{BTreeMap, BTreeSet};

/// Frozen v4 tracker view of one decoded instruction: shared ARM32
/// semantics projected onto the effect and control vocabulary this
/// artifact's verdicts were pinned to. Flag effects, link information, and
/// transfer value registers do not exist in this view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DecodedInstruction {
    pub isa: Isa,
    pub pc: u32,
    pub length: u8,
    pub conditional: bool,
    pub reads: BTreeSet<Register>,
    pub writes: BTreeSet<Register>,
    pub effect: ValueEffect,
    pub flow: ControlFlow,
}

impl DecodedInstruction {
    /// Project shared ARM32 semantics onto the frozen tracker view. The
    /// mapping is total and behavior-preserving:
    ///
    /// - direct branches keep target + fallthrough presence;
    /// - a direct call keeps its target and stays same-ISA (`bl` only);
    /// - `SVC`/exception calls and returns are path ends here, although the
    ///   shared flow carries their architectural fallthrough;
    /// - linked barriers (the indirect `blx` family) keep the v4 indirect
    ///   call shape — fallthrough successor, never a fabricated target;
    /// - compare and shift effects are newer than the v4 vocabulary, so
    ///   they downgrade to `Unsupported` (their reads/writes are identical,
    ///   which is all the tracker consumes).
    pub(crate) fn from_shared(insn: arm32::DecodedInstruction) -> Self {
        let flow = match insn.flow {
            arm32::ControlFlow::Linear => ControlFlow::Linear,
            arm32::ControlFlow::DirectBranch {
                target,
                fallthrough,
                ..
            } => ControlFlow::DirectBranch {
                target,
                has_fallthrough: fallthrough.is_some(),
            },
            arm32::ControlFlow::DirectCall { target } => ControlFlow::Call {
                target: Some(CallTarget {
                    entry: target,
                    isa: insn.isa,
                }),
            },
            arm32::ControlFlow::ExceptionCall | arm32::ControlFlow::Return => ControlFlow::Stop,
            arm32::ControlFlow::Barrier => {
                if insn.links_lr {
                    ControlFlow::Call { target: None }
                } else {
                    ControlFlow::Stop
                }
            }
        };
        let effect = match insn.effect {
            ValueEffect::Compare { .. } | ValueEffect::Shift { .. } => ValueEffect::Unsupported,
            other => other,
        };
        Self {
            isa: insn.isa,
            pc: insn.pc,
            length: insn.length,
            conditional: insn.conditional,
            reads: insn.reads,
            writes: insn.writes,
            effect,
            flow,
        }
    }
}

/// Control classification consumed by reachability and the tracker. This is
/// the v4 verdict vocabulary; the total architectural classification lives
/// in `crate::arm32::ControlFlow`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ControlFlow {
    Linear,
    DirectBranch { target: u32, has_fallthrough: bool },
    Call { target: Option<CallTarget> },
    Stop,
}

/// A direct `bl` call target resolved to a same-ISA entry PC.
///
/// Only direct same-ISA `bl` resolves to `Some`. Indirect calls (`blx`
/// register, `blxns`) and cross-ISA `blx`-immediate (resolution deferred)
/// carry `target: None`; fabricating a target for those would misattribute
/// interprocedural evidence. `bx` (register branch, no link) is
/// `ControlFlow::Stop`, not `Call`, and has no target at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CallTarget {
    pub entry: u32,
    pub isa: Isa,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DecodeFailure {
    pub pc: u32,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DecodedRange {
    pub range: AuthenticatedDecodeRange,
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
    range: AuthenticatedDecodeRange,
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
            Ok(raw) => {
                let instruction = DecodedInstruction::from_shared(raw);
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
    range: AuthenticatedDecodeRange,
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

fn range_bytes(bytes: &[u8], load_address: u32, range: AuthenticatedDecodeRange) -> Result<&[u8]> {
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

fn invalid(message: &str) -> Error {
    Error::Serialize(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arm32::{
        DecodeError, DecoderIdentity, FlagEffect, Operand, PureRustDecoder, SystemEffect,
    };
    use crate::error::Error;
    use crate::execution_ranges::ExecutionIdentity;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    fn function(entry: u32, ranges: Vec<AuthenticatedDecodeRange>) -> FunctionExecution {
        FunctionExecution {
            owner: crate::execution_ranges::FunctionOwner::Ghidra,
            identity: ExecutionIdentity {
                entry,
                decode_ranges: ranges,
                execution_blake3: [0; 32],
            },
            contexts: BTreeSet::new(),
        }
    }

    fn arm_range(start: u32, end: u32) -> AuthenticatedDecodeRange {
        AuthenticatedDecodeRange {
            start,
            end,
            isa: Isa::Arm,
            blake3: [0; 32],
        }
    }

    fn thumb_range(start: u32, end: u32) -> AuthenticatedDecodeRange {
        AuthenticatedDecodeRange {
            start,
            end,
            isa: Isa::Thumb,
            blake3: [0; 32],
        }
    }

    #[derive(Debug, Clone)]
    enum Scripted {
        Insn(arm32::DecodedInstruction),
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
        ) -> std::result::Result<arm32::DecodedInstruction, DecodeError> {
            self.decode_log.borrow_mut().push(DecodeCall {
                isa,
                pc,
                bytes: bytes.to_vec(),
            });
            match self.script.borrow_mut().pop_front() {
                Some(Scripted::Insn(instruction)) => Ok(instruction),
                Some(Scripted::Err(message)) => Err(DecodeError {
                    message: message.to_owned(),
                }),
                Some(Scripted::Panic) => panic!("deliberate decoder panic"),
                None => Ok(arm32::DecodedInstruction {
                    isa,
                    pc,
                    length: match isa {
                        Isa::Arm => 4,
                        Isa::Thumb => 2,
                    },
                    conditional: false,
                    links_lr: false,
                    reads: BTreeSet::new(),
                    writes: BTreeSet::new(),
                    effect: ValueEffect::None,
                    system: SystemEffect::None,
                    flags: FlagEffect::Preserved,
                    flow: arm32::ControlFlow::Linear,
                }),
            }
        }
    }

    fn arm_linear(isa: Isa, pc: u32, length: u8) -> arm32::DecodedInstruction {
        arm32::DecodedInstruction {
            isa,
            pc,
            length,
            conditional: false,
            links_lr: false,
            reads: BTreeSet::new(),
            writes: BTreeSet::new(),
            effect: ValueEffect::None,
            system: SystemEffect::None,
            flags: FlagEffect::Preserved,
            flow: arm32::ControlFlow::Linear,
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
            effect: ValueEffect::None,
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
            effect: ValueEffect::None,
            flow,
        }
    }

    fn direct(target: u32, has_fallthrough: bool) -> ControlFlow {
        ControlFlow::DirectBranch {
            target,
            has_fallthrough,
        }
    }

    fn err_message(result: Result<DecodedFunction>) -> String {
        match result {
            Err(Error::Serialize(message)) => message,
            other => panic!("expected serialize error, got {other:?}"),
        }
    }

    #[test]
    fn from_shared_projects_the_frozen_v4_flow() {
        // Compare and shift effects downgrade to Unsupported with identical
        // reads/writes.
        let compare = arm32::DecodedInstruction {
            isa: Isa::Arm,
            pc: 0x1000,
            length: 4,
            conditional: false,
            links_lr: false,
            reads: BTreeSet::from([Register(1)]),
            writes: BTreeSet::new(),
            effect: arm32::ValueEffect::Compare {
                operation: arm32::CompareOp::Subtract,
                left: Register(1),
                right: Operand::Immediate(0),
            },
            system: SystemEffect::None,
            flags: FlagEffect::Written(arm32::FlagWriter::Compare),
            flow: arm32::ControlFlow::Linear,
        };
        let projected = DecodedInstruction::from_shared(compare);
        assert_eq!(projected.effect, ValueEffect::Unsupported);
        assert_eq!(projected.reads, BTreeSet::from([Register(1)]));
        assert!(projected.writes.is_empty());
        assert!(matches!(projected.flow, ControlFlow::Linear));

        // A linked barrier keeps the indirect-call shape; an unlinked one
        // stops; exception calls and returns stop; direct calls stay
        // same-ISA; branch fallthrough presence is preserved.
        let linked_barrier = arm32::DecodedInstruction {
            isa: Isa::Thumb,
            pc: 0x1000,
            length: 2,
            conditional: false,
            links_lr: true,
            reads: BTreeSet::from([Register(0)]),
            writes: BTreeSet::new(),
            effect: ValueEffect::None,
            system: SystemEffect::None,
            flags: FlagEffect::Preserved,
            flow: arm32::ControlFlow::Barrier,
        };
        assert!(matches!(
            DecodedInstruction::from_shared(linked_barrier.clone()).flow,
            ControlFlow::Call { target: None }
        ));

        let unlinked_barrier = arm32::DecodedInstruction {
            links_lr: false,
            ..linked_barrier.clone()
        };
        assert!(matches!(
            DecodedInstruction::from_shared(unlinked_barrier).flow,
            ControlFlow::Stop
        ));

        let exception = arm32::DecodedInstruction {
            flow: arm32::ControlFlow::ExceptionCall,
            ..linked_barrier.clone()
        };
        assert!(matches!(
            DecodedInstruction::from_shared(exception).flow,
            ControlFlow::Stop
        ));

        let ret = arm32::DecodedInstruction {
            flow: arm32::ControlFlow::Return,
            ..linked_barrier.clone()
        };
        assert!(matches!(
            DecodedInstruction::from_shared(ret).flow,
            ControlFlow::Stop
        ));

        let call = arm32::DecodedInstruction {
            flow: arm32::ControlFlow::DirectCall { target: 0x2000 },
            ..linked_barrier.clone()
        };
        assert_eq!(
            DecodedInstruction::from_shared(call).flow,
            ControlFlow::Call {
                target: Some(CallTarget {
                    entry: 0x2000,
                    isa: Isa::Thumb,
                }),
            }
        );

        let branch = arm32::DecodedInstruction {
            flow: arm32::ControlFlow::DirectBranch {
                target: 0x2004,
                fallthrough: Some(0x1002),
                predicate: arm32::BranchPredicate::Always,
            },
            ..linked_barrier
        };
        assert_eq!(
            DecodedInstruction::from_shared(branch).flow,
            ControlFlow::DirectBranch {
                target: 0x2004,
                has_fallthrough: true,
            }
        );
    }

    #[test]
    fn decode_function_passes_only_range_bytes_and_fresh_state() {
        let image = (0u8..=0x1f).collect::<Vec<_>>();
        let decoder = ScriptedDecoder::new(vec![
            Scripted::Insn(arm_linear(Isa::Arm, 0x1000, 4)),
            Scripted::Insn(arm_linear(Isa::Arm, 0x1004, 4)),
            Scripted::Insn(arm_linear(Isa::Thumb, 0x1010, 2)),
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
            Scripted::Insn(arm_linear(Isa::Arm, 0x1000, 4)),
            Scripted::Err("truncated encoding"),
            Scripted::Insn(arm_linear(Isa::Thumb, 0x1010, 2)),
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
                Scripted::Insn(arm_linear(Isa::Arm, 0x2000, 4)),
                "requested PC",
            ),
            (
                "wrong isa",
                Scripted::Insn(arm_linear(Isa::Thumb, 0x1000, 2)),
                "ISA",
            ),
            (
                "zero length",
                Scripted::Insn(arm_linear(Isa::Arm, 0x1000, 0)),
                "impossible instruction length",
            ),
            (
                "impossible length",
                Scripted::Insn(arm_linear(Isa::Arm, 0x1000, 3)),
                "impossible instruction length",
            ),
            (
                "overrun",
                Scripted::Insn(arm_linear(Isa::Arm, 0x1000, 4)),
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
            Scripted::Insn(arm_linear(Isa::Arm, 0x1000, 4)),
            Scripted::Insn(arm_linear(Isa::Arm, 0x1000, 4)),
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
            Scripted::Insn(arm_linear(Isa::Arm, 0x1000, 4)),
            Scripted::Insn(arm_linear(Isa::Arm, 0x0ffc, 4)),
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
                    let range = AuthenticatedDecodeRange {
                        start: 0x1000,
                        end: end.max(0x1002),
                        isa,
                        blake3: [0; 32],
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
        instructions: Vec<(AuthenticatedDecodeRange, Vec<DecodedInstruction>)>,
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
