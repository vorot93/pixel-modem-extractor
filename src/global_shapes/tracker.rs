// Conservative per-block fact tracking.

use super::decoder::{
    AccessKind, AddressBase, AddressExpr, AddressOffset, Block, CallTarget, ControlFlow,
    DecodedFunction, DecodedInstruction, Operand, Register, SemanticEffect, Shift, ValueExpr,
};
use super::{FunctionContext, FunctionExecution};
use crate::error::{Error, Result};
use crate::execution_ranges::DecodeIsa as Isa;
use std::collections::{BTreeMap, BTreeSet};

const PC: Register = Register(15);
const CORE_REGISTER_COUNT: u8 = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CandidateObservation {
    pub target_address: u32,
    pub isa: Isa,
    pub pc: u32,
    pub conditional: bool,
    pub kind: AccessKind,
    pub width: u8,
    pub offset: u32,
    pub functions: BTreeSet<FunctionContext>,
    pub provenance_path: Vec<u32>,
    /// Depth-1 call hops this evidence crossed. Always empty here: the
    /// tracker only ever sees one function at a time, so it cannot know
    /// whether a candidate came from a seeded entry block. The coordinator
    /// (a later stage) stamps this once it replays a `CallFact`'s seed into
    /// a callee and keeps the resulting evidence.
    pub via: Vec<CallHop>,
}

/// One depth-1 `bl` hop from a caller's entry block into a tracked callee.
/// Field names mirror `artifact::CallHopWire` (its wire counterpart, all
/// `String`); keep them identical so the later wire conversion stays a
/// straight field-by-field mapping.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CallHop {
    pub caller_entry: u32,
    pub caller_name: String,
    pub call_pc: u32,
    pub arg_register: u8,
}

#[derive(Debug, Default, PartialEq)]
pub(crate) struct TrackerReport {
    pub candidates: Vec<CandidateObservation>,
    pub call_facts: Vec<CallFact>,
    /// v3: instruction kill events plus cross-block join kills (each counted
    /// once). The v2 per-non-entry-block-start +1 is gone.
    pub state_barriers: usize,
    /// (block, register) join events where ≥1 in-edge held a fact.
    pub join_facts: usize,
    /// (block, register) join events where ≥1 in-edge held a fact but the
    /// join left the register Unknown.
    pub join_kills: usize,
    /// (block, register) facts in final in-states of non-entry blocks.
    pub entry_facts: usize,
    /// Observations whose provenance reaches outside the observing block.
    pub propagated_facts: usize,
    /// Whether any non-entry block holds a fact in its final in-state.
    pub join_survivor: bool,
}

/// A depth-1 call-site fact: at `call_pc` inside `caller_entry`, one or more
/// AAPCS argument registers (r0-r3) provably held a recovered global's base
/// address (displacement zero — the pointer itself, not `&global + k`). A
/// later stage seeds the callee's entry block from `seed` and re-tracks it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CallFact {
    pub caller_entry: u32,
    pub caller_contexts: BTreeSet<FunctionContext>,
    pub call_pc: u32,
    pub callee_target: u32,
    pub callee_isa: Isa,
    pub seed: BTreeMap<Register, u32>,
}

pub(crate) fn track_function(
    function: &FunctionExecution,
    decoded: &DecodedFunction,
    blocks: &[Block],
    image: &[u8],
    load_address: u32,
    recovered_addresses: &BTreeSet<u32>,
    seed: &BTreeMap<Register, u32>,
) -> Result<TrackerReport> {
    let instructions = instruction_map(decoded)?;
    let mut sorted: Vec<&Block> = blocks.iter().collect();
    sorted.sort_by_key(|block| block.start);
    let program: Vec<(Vec<&DecodedInstruction>, Vec<u32>)> = sorted
        .iter()
        .map(|block| {
            Ok((
                block_instructions(&instructions, block)?,
                block.successors.clone(),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let index: BTreeMap<u32, usize> = sorted
        .iter()
        .enumerate()
        .map(|(position, block)| (block.start, position))
        .collect();
    let entry_index = index.get(&function.identity.entry).copied();

    // Phase 1: worklist fixpoint. in-state None means "no edge has spoken
    // yet" (⊥); facts only die and provenance only grows, so deterministic
    // round-robin over address-sorted blocks converges.
    let mut in_states: Vec<Option<State>> = vec![None; sorted.len()];
    let mut out_states: Vec<State> = vec![State::default(); sorted.len()];
    let mut ever_held: Vec<BTreeSet<Register>> = vec![BTreeSet::new(); sorted.len()];
    let mut dirty = vec![true; sorted.len()];
    // The depth-1 seed joins like a virtual predecessor at the entry block:
    // a disagreeing real predecessor kills it; it never wins by fiat.
    if let Some(entry) = entry_index {
        in_states[entry] = Some(seed_state(seed));
    }

    loop {
        let mut changed = false;
        for position in 0..sorted.len() {
            if !dirty[position] {
                continue;
            }
            dirty[position] = false;
            let Some(mut state) = in_states[position].clone() else {
                continue;
            };
            for insn in &program[position].0 {
                apply_instruction(
                    &mut state,
                    insn,
                    image,
                    load_address,
                    recovered_addresses,
                    &function.contexts,
                );
            }
            out_states[position] = state;
            for successor in &program[position].1 {
                let Some(next) = index.get(successor) else {
                    return Err(invalid("successor is not a block start"));
                };
                if join_into(*next, &out_states[position], &mut in_states, &mut ever_held) {
                    dirty[*next] = true;
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }

    let join_facts: usize = ever_held.iter().map(|held| held.len()).sum();
    let join_kills: usize = ever_held
        .iter()
        .zip(&in_states)
        .filter(|(held, _)| !held.is_empty())
        .map(|(held, in_state)| {
            held.iter()
                .filter(|register| {
                    !in_state
                        .as_ref()
                        .is_some_and(|state| state.facts.contains_key(*register))
                })
                .count()
        })
        .sum();
    let is_non_entry = |position: usize| Some(position) != entry_index;
    let entry_facts: usize = in_states
        .iter()
        .enumerate()
        .filter(|(position, _)| is_non_entry(*position))
        .map(|(_, in_state)| {
            in_state
                .as_ref()
                .map(|state| state.facts.len())
                .unwrap_or(0)
        })
        .sum();
    let join_survivor = in_states
        .iter()
        .enumerate()
        .filter(|(position, _)| is_non_entry(*position))
        .any(|(_, in_state)| {
            in_state
                .as_ref()
                .is_some_and(|state| !state.facts.is_empty())
        });

    // Phase 2: harvest. One walk in block-address order replays each
    // instruction against its block's final in-state; apply_instruction is
    // deterministic, so each (ISA, PC) executes against exactly one state.
    let mut candidates = Vec::new();
    let mut call_facts = Vec::new();
    let mut instruction_barriers = 0usize;
    let mut propagated_facts = 0usize;
    for (position, block) in sorted.iter().enumerate() {
        let mut state = in_states[position].clone().unwrap_or_default();
        for insn in &program[position].0 {
            // Harvested before `apply_instruction` runs the call's effect.
            if let ControlFlow::Call {
                target: Some(target),
            } = insn.flow
                && let Some(call_fact) = harvest_call_fact(&state, function, insn.pc, target)
            {
                call_facts.push(call_fact);
            }
            let step = apply_instruction(
                &mut state,
                insn,
                image,
                load_address,
                recovered_addresses,
                &function.contexts,
            );
            for candidate in step.observations {
                if candidate
                    .provenance_path
                    .iter()
                    .any(|pc| *pc < block.start || *pc >= block.end)
                {
                    propagated_facts += 1;
                }
                candidates.push(candidate);
            }
            if step.barrier {
                instruction_barriers += 1;
            }
        }
    }
    sort_candidates(&mut candidates);
    Ok(TrackerReport {
        candidates,
        call_facts,
        state_barriers: instruction_barriers + join_kills,
        join_facts,
        join_kills,
        entry_facts,
        propagated_facts,
        join_survivor,
    })
}

fn seed_state(seed: &BTreeMap<Register, u32>) -> State {
    let mut state = State::new();
    for (register, address) in seed {
        state.insert(
            *register,
            Fact::Global {
                target_address: *address,
                displacement: 0,
                provenance: Vec::new(),
            },
        );
    }
    state
}

/// Must-facts join of one predecessor out-state into a block's in-state:
/// a register keeps its fact only while every in-edge so far agrees on the
/// payload; provenance unions (dedup, deterministic order). Returns whether
/// the in-state changed.
fn join_into(
    position: usize,
    out: &State,
    in_states: &mut [Option<State>],
    ever_held: &mut [BTreeSet<Register>],
) -> bool {
    for register in out.facts.keys() {
        ever_held[position].insert(*register);
    }
    let Some(in_state) = &mut in_states[position] else {
        in_states[position] = Some(out.clone());
        return true;
    };
    let mut changed = false;
    let registers: Vec<Register> = in_state.facts.keys().copied().collect();
    for register in registers {
        let Some(incoming) = out.facts.get(&register) else {
            in_state.facts.remove(&register);
            changed = true;
            continue;
        };
        let held = in_state.facts[&register].clone();
        if !held.same_payload(incoming) {
            in_state.facts.remove(&register);
            changed = true;
            continue;
        }
        let merged = merge_provenance(held.provenance(), incoming.provenance());
        if merged != held.provenance() {
            in_state
                .facts
                .insert(register, held.with_provenance(merged));
            changed = true;
        }
    }
    changed
}

fn merge_provenance(left: &[u32], right: &[u32]) -> Vec<u32> {
    let mut merged = left.to_vec();
    for pc in right {
        if !merged.contains(pc) {
            merged.push(*pc);
        }
    }
    merged
}

// Only the AAPCS integer argument registers (r0-r3) are in scope for depth-1
// seeding; only a bare recovered base (displacement 0) counts as passing the
// global itself rather than an interior pointer into it.
fn harvest_call_fact(
    state: &State,
    function: &FunctionExecution,
    call_pc: u32,
    target: CallTarget,
) -> Option<CallFact> {
    let mut seed = BTreeMap::new();
    for number in 0u8..=3 {
        if let Some(Fact::Global {
            target_address,
            displacement: 0,
            ..
        }) = state.get(Register(number))
        {
            seed.insert(Register(number), *target_address);
        }
    }
    if seed.is_empty() {
        return None;
    }
    Some(CallFact {
        caller_entry: function.identity.entry,
        caller_contexts: function.contexts.clone(),
        call_pc,
        callee_target: target.entry,
        callee_isa: target.isa,
        seed,
    })
}

// Exact values independently re-check the Recovered set. Once a fact is a
// Global, later copy/arithmetic keep that identity and never retarget just
// because the numeric result equals another Recovered base.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Fact {
    Exact {
        value: u32,
        provenance: Vec<u32>,
    },
    Global {
        target_address: u32,
        displacement: i64,
        provenance: Vec<u32>,
    },
}

impl Fact {
    fn provenance(&self) -> &[u32] {
        match self {
            Self::Exact { provenance, .. } | Self::Global { provenance, .. } => provenance,
        }
    }

    fn with_pc(mut self, pc: u32) -> Self {
        match &mut self {
            Self::Exact { provenance, .. } | Self::Global { provenance, .. } => {
                provenance.push(pc);
            }
        }
        self
    }

    fn with_provenance(mut self, provenance: Vec<u32>) -> Self {
        match &mut self {
            Self::Exact {
                provenance: slot, ..
            }
            | Self::Global {
                provenance: slot, ..
            } => {
                *slot = provenance;
            }
        }
        self
    }

    fn same_payload(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Exact { value: left, .. }, Self::Exact { value: right, .. }) => left == right,
            (
                Self::Global {
                    target_address: left_target,
                    displacement: left_disp,
                    ..
                },
                Self::Global {
                    target_address: right_target,
                    displacement: right_disp,
                    ..
                },
            ) => left_target == right_target && left_disp == right_disp,
            _ => false,
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
struct State {
    facts: BTreeMap<Register, Fact>,
}

impl State {
    fn new() -> Self {
        Self {
            facts: BTreeMap::new(),
        }
    }

    fn get(&self, register: Register) -> Option<&Fact> {
        if is_pc(register) {
            return None;
        }
        self.facts.get(&register)
    }

    fn insert(&mut self, register: Register, fact: Fact) {
        if !is_pc(register) {
            self.facts.insert(register, fact);
        }
    }

    fn kill(&mut self, register: Register) -> bool {
        self.facts.remove(&register).is_some()
    }

    fn clear(&mut self) -> bool {
        let known = !self.facts.is_empty();
        self.facts.clear();
        known
    }
}

struct Step {
    observations: Vec<CandidateObservation>,
    barrier: bool,
}

fn instruction_map(decoded: &DecodedFunction) -> Result<BTreeMap<u32, &DecodedInstruction>> {
    let mut map = BTreeMap::new();
    for range in &decoded.ranges {
        for (pc, insn) in &range.instructions {
            if map.insert(*pc, insn).is_some() {
                return Err(invalid("duplicate decoded instruction PC"));
            }
        }
    }
    Ok(map)
}

fn block_instructions<'a>(
    instructions: &BTreeMap<u32, &'a DecodedInstruction>,
    block: &Block,
) -> Result<Vec<&'a DecodedInstruction>> {
    if block.end <= block.start {
        return Err(invalid("block span is empty"));
    }
    let insns: Vec<&DecodedInstruction> = instructions
        .range(block.start..block.end)
        .map(|(_, insn)| *insn)
        .collect();
    let Some(first) = insns.first() else {
        return Err(invalid("block contains no decoded instructions"));
    };
    if first.pc != block.start {
        return Err(invalid("block does not start at a decoded instruction"));
    }
    for window in insns.windows(2) {
        let next = window[0]
            .pc
            .checked_add(u32::from(window[0].length))
            .ok_or_else(|| invalid("instruction length overflows u32"))?;
        if next != window[1].pc {
            return Err(invalid("block instructions are not contiguous"));
        }
    }
    let last = insns
        .last()
        .ok_or_else(|| invalid("block contains no decoded instructions"))?;
    let end = last
        .pc
        .checked_add(u32::from(last.length))
        .ok_or_else(|| invalid("instruction length overflows u32"))?;
    if end != block.end {
        return Err(invalid("block end does not match last instruction"));
    }
    Ok(insns)
}

// Observations are collected against the pre-write state. Register writes,
// writeback, and leftover explicit destinations are applied afterwards.
fn apply_instruction(
    state: &mut State,
    insn: &DecodedInstruction,
    image: &[u8],
    load_address: u32,
    recovered: &BTreeSet<u32>,
    functions: &BTreeSet<FunctionContext>,
) -> Step {
    let mut observations = Vec::new();
    let mut exactly_updated = BTreeSet::new();
    let mut killed_known = false;
    let mut unbounded = false;

    match &insn.effect {
        SemanticEffect::None => {}
        SemanticEffect::RegisterWrite { dst, value } => {
            let fact = eval_value(value, state, insn.isa, insn.pc, recovered);
            apply_write(
                state,
                *dst,
                fact,
                insn.conditional,
                insn.pc,
                &mut exactly_updated,
                &mut killed_known,
            );
        }
        SemanticEffect::LiteralWordLoad { dst, address } => {
            let addr_fact = eval_address(address, state, insn.isa, insn.pc, recovered);
            if let Some(fact) = &addr_fact
                && let Some(observation) =
                    observation_from(fact, insn, AccessKind::Read, 4, functions)
            {
                observations.push(observation);
            }
            let loaded = addr_fact
                .as_ref()
                .and_then(numeric)
                .and_then(|address| read_literal_word(image, load_address, address))
                .map(|value| {
                    anchor(
                        Fact::Exact {
                            value,
                            provenance: Vec::new(),
                        },
                        recovered,
                    )
                });
            apply_write(
                state,
                *dst,
                loaded,
                insn.conditional,
                insn.pc,
                &mut exactly_updated,
                &mut killed_known,
            );
        }
        SemanticEffect::Memory(effect) => {
            for transfer in &effect.transfers {
                if let Some(fact) =
                    eval_address(&transfer.address, state, insn.isa, insn.pc, recovered)
                    && let Some(observation) =
                        observation_from(&fact, insn, transfer.kind, transfer.width, functions)
                {
                    observations.push(observation);
                }
            }
            if let Some((wb_reg, wb_addr)) = &effect.writeback {
                let fact = eval_address(wb_addr, state, insn.isa, insn.pc, recovered);
                apply_write(
                    state,
                    *wb_reg,
                    fact,
                    insn.conditional,
                    insn.pc,
                    &mut exactly_updated,
                    &mut killed_known,
                );
            }
        }
        SemanticEffect::Unsupported => {
            if is_unbounded(&insn.writes) {
                unbounded = true;
                if state.clear() {
                    killed_known = true;
                }
                exactly_updated.extend(insn.writes.iter().copied());
            } else {
                for register in &insn.writes {
                    if state.kill(*register) {
                        killed_known = true;
                    }
                    exactly_updated.insert(*register);
                }
            }
        }
    }

    if !matches!(insn.effect, SemanticEffect::Unsupported) {
        for register in &insn.writes {
            if !exactly_updated.contains(register) && state.kill(*register) {
                killed_known = true;
            }
        }
    }

    Step {
        observations,
        barrier: killed_known || unbounded,
    }
}

fn apply_write(
    state: &mut State,
    dst: Register,
    computed: Option<Fact>,
    conditional: bool,
    pc: u32,
    exactly_updated: &mut BTreeSet<Register>,
    killed_known: &mut bool,
) {
    if is_pc(dst) {
        if state.kill(dst) {
            *killed_known = true;
        }
        return;
    }
    let computed = computed.map(|fact| fact.with_pc(pc));
    if conditional {
        match (state.get(dst), computed) {
            (Some(old), Some(new)) if old.same_payload(&new) => {
                exactly_updated.insert(dst);
            }
            (None, None) => {}
            _ => {
                if state.kill(dst) {
                    *killed_known = true;
                }
            }
        }
        return;
    }
    match computed {
        Some(fact) => {
            state.insert(dst, fact);
            exactly_updated.insert(dst);
        }
        None => {
            if state.kill(dst) {
                *killed_known = true;
            }
        }
    }
}

fn eval_value(
    expr: &ValueExpr,
    state: &State,
    isa: Isa,
    pc: u32,
    recovered: &BTreeSet<u32>,
) -> Option<Fact> {
    let fact = match expr {
        ValueExpr::Immediate(value) => Fact::Exact {
            value: *value,
            provenance: Vec::new(),
        },
        ValueExpr::Register(register) => state.get(*register)?.clone(),
        ValueExpr::ReplaceHighHalf { source, high } => {
            let source = state.get(*source)?;
            let value = numeric(source)?;
            Fact::Exact {
                value: (value & 0xffff) | (u32::from(*high) << 16),
                provenance: source.provenance().to_vec(),
            }
        }
        ValueExpr::Add { left, right } => combine(state, *left, right, false)?,
        ValueExpr::Sub { left, right } => combine(state, *left, right, true)?,
        ValueExpr::ArchitecturalPc {
            addend,
            align_to_four,
        } => Fact::Exact {
            value: architectural_pc(isa, pc, *addend, *align_to_four)?,
            provenance: Vec::new(),
        },
    };
    Some(anchor(fact, recovered))
}

fn eval_address(
    expr: &AddressExpr,
    state: &State,
    isa: Isa,
    pc: u32,
    recovered: &BTreeSet<u32>,
) -> Option<Fact> {
    let base = match expr.base {
        AddressBase::Register(register) => state.get(register)?.clone(),
        AddressBase::ArchitecturalPc { align_to_four } => Fact::Exact {
            value: architectural_pc(isa, pc, 0, align_to_four)?,
            provenance: Vec::new(),
        },
    };
    let (delta, extra_provenance) = match expr.offset {
        AddressOffset::Immediate(imm) => (imm, Vec::new()),
        AddressOffset::Register {
            register,
            subtract,
            shift,
        } => {
            let fact = state.get(register)?;
            let shifted = apply_shift(numeric(fact)?, shift)?;
            let delta = if subtract {
                -i64::from(shifted)
            } else {
                i64::from(shifted)
            };
            (delta, fact.provenance().to_vec())
        }
    };
    let mut provenance = base.provenance().to_vec();
    provenance.extend(extra_provenance);
    let fact = match base {
        Fact::Global {
            target_address,
            displacement,
            ..
        } => displace_global(target_address, displacement, delta, provenance)?,
        Fact::Exact { value, .. } => Fact::Exact {
            value: add_u32_i64(value, delta)?,
            provenance,
        },
    };
    Some(anchor(fact, recovered))
}

fn combine(state: &State, left: Register, right: &Operand, subtract: bool) -> Option<Fact> {
    let left_fact = state.get(left)?;
    let (rhs, rhs_provenance) = eval_operand(state, right)?;
    let delta = if subtract {
        -i64::from(rhs)
    } else {
        i64::from(rhs)
    };
    let mut provenance = left_fact.provenance().to_vec();
    provenance.extend(rhs_provenance);
    match left_fact {
        Fact::Global {
            target_address,
            displacement,
            ..
        } => displace_global(*target_address, *displacement, delta, provenance),
        Fact::Exact { value, .. } => Some(Fact::Exact {
            value: add_u32_i64(*value, delta)?,
            provenance,
        }),
    }
}

fn eval_operand(state: &State, operand: &Operand) -> Option<(u32, Vec<u32>)> {
    match *operand {
        Operand::Immediate(value) => Some((value, Vec::new())),
        Operand::Register { register, shift } => {
            let fact = state.get(register)?;
            Some((
                apply_shift(numeric(fact)?, shift)?,
                fact.provenance().to_vec(),
            ))
        }
    }
}

fn apply_shift(value: u32, shift: Shift) -> Option<u32> {
    match shift {
        Shift::Lsl(amount) => value.checked_shl(u32::from(amount)),
        Shift::Lsr(amount) => {
            if amount >= 32 {
                Some(0)
            } else {
                Some(value >> amount)
            }
        }
        Shift::Asr(amount) => {
            let amount = u32::from(amount.min(31));
            Some(((value as i32) >> amount) as u32)
        }
        Shift::Ror(amount) => Some(value.rotate_right(u32::from(amount))),
        Shift::Rrx => None,
    }
}

fn architectural_pc(isa: Isa, pc: u32, addend: i64, align_to_four: bool) -> Option<u32> {
    let bias = match isa {
        Isa::Arm => 8u32,
        Isa::Thumb => 4u32,
    };
    let mut base = pc.checked_add(bias)?;
    if align_to_four {
        base &= !3;
    }
    add_u32_i64(base, addend)
}

fn add_u32_i64(value: u32, delta: i64) -> Option<u32> {
    u32::try_from(i64::from(value).checked_add(delta)?).ok()
}

fn displace_global(
    target_address: u32,
    displacement: i64,
    delta: i64,
    provenance: Vec<u32>,
) -> Option<Fact> {
    let displacement = displacement.checked_add(delta)?;
    add_u32_i64(target_address, displacement)?;
    Some(Fact::Global {
        target_address,
        displacement,
        provenance,
    })
}

fn numeric(fact: &Fact) -> Option<u32> {
    match *fact {
        Fact::Exact { value, .. } => Some(value),
        Fact::Global {
            target_address,
            displacement,
            ..
        } => add_u32_i64(target_address, displacement),
    }
}

fn anchor(fact: Fact, recovered: &BTreeSet<u32>) -> Fact {
    match fact {
        Fact::Exact { value, provenance } if recovered.contains(&value) => Fact::Global {
            target_address: value,
            displacement: 0,
            provenance,
        },
        other => other,
    }
}

fn observation_from(
    fact: &Fact,
    insn: &DecodedInstruction,
    kind: AccessKind,
    width: u8,
    functions: &BTreeSet<FunctionContext>,
) -> Option<CandidateObservation> {
    let Fact::Global {
        target_address,
        displacement,
        provenance,
    } = fact
    else {
        return None;
    };
    if *displacement < 0 {
        return None;
    }
    let offset = u32::try_from(*displacement).ok()?;
    let start = target_address.checked_add(offset)?;
    start.checked_add(u32::from(width))?;
    Some(CandidateObservation {
        target_address: *target_address,
        isa: insn.isa,
        pc: insn.pc,
        conditional: insn.conditional,
        kind,
        width,
        offset,
        functions: functions.clone(),
        provenance_path: provenance.clone(),
        via: Vec::new(),
    })
}

fn read_literal_word(image: &[u8], load_address: u32, address: u32) -> Option<u32> {
    if address < load_address {
        return None;
    }
    let end = address.checked_add(4)?;
    let start = usize::try_from(address.checked_sub(load_address)?).ok()?;
    let end = usize::try_from(end.checked_sub(load_address)?).ok()?;
    image
        .get(start..end)?
        .try_into()
        .ok()
        .map(u32::from_le_bytes)
}

fn is_unbounded(writes: &BTreeSet<Register>) -> bool {
    writes.len() == usize::from(CORE_REGISTER_COUNT)
        && (0..CORE_REGISTER_COUNT).all(|number| writes.contains(&Register(number)))
}

fn is_pc(register: Register) -> bool {
    register == PC
}

fn sort_candidates(candidates: &mut [CandidateObservation]) {
    candidates.sort_by(|left, right| {
        left.isa
            .cmp(&right.isa)
            .then(left.pc.cmp(&right.pc))
            .then(left.target_address.cmp(&right.target_address))
            .then(left.kind.cmp(&right.kind))
            .then(left.width.cmp(&right.width))
            .then(left.offset.cmp(&right.offset))
            .then(left.provenance_path.cmp(&right.provenance_path))
    });
}

fn invalid(message: &str) -> Error {
    Error::Serialize(format!("global_shapes tracker: {message}"))
}

#[cfg(test)]
mod tests {
    use super::super::decoder::{
        CallTarget, ControlFlow, DecodeFailure, DecodedRange, MemoryEffect, MemoryTransfer,
        reachable_blocks,
    };
    use super::*;
    use crate::execution_ranges::{AuthenticatedDecodeRange, ExecutionIdentity, FunctionOwner};

    const R0: Register = Register(0);
    const R1: Register = Register(1);
    const R2: Register = Register(2);
    const R3: Register = Register(3);
    const GLOBAL: u32 = 0x2000;
    const OTHER: u32 = 0x3000;
    const BETWEEN: u32 = 0x2800;
    const ENTRY: u32 = 0x1000;

    fn contexts() -> BTreeSet<FunctionContext> {
        BTreeSet::from([FunctionContext {
            entry: ENTRY,
            name: "f".into(),
        }])
    }

    fn function_at(entry: u32, ranges: Vec<AuthenticatedDecodeRange>) -> FunctionExecution {
        FunctionExecution {
            owner: FunctionOwner::Ghidra,
            identity: ExecutionIdentity {
                entry,
                decode_ranges: ranges,
                execution_blake3: [0; 32],
            },
            contexts: BTreeSet::from([FunctionContext {
                entry,
                name: "f".into(),
            }]),
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

    fn insn(
        isa: Isa,
        pc: u32,
        length: u8,
        conditional: bool,
        writes: impl IntoIterator<Item = Register>,
        effect: SemanticEffect,
        flow: ControlFlow,
    ) -> DecodedInstruction {
        DecodedInstruction {
            isa,
            pc,
            length,
            conditional,
            reads: BTreeSet::new(),
            writes: writes.into_iter().collect(),
            effect,
            flow,
        }
    }

    fn arm(
        pc: u32,
        writes: impl IntoIterator<Item = Register>,
        effect: SemanticEffect,
    ) -> DecodedInstruction {
        insn(Isa::Arm, pc, 4, false, writes, effect, ControlFlow::Linear)
    }

    fn thumb(
        pc: u32,
        writes: impl IntoIterator<Item = Register>,
        effect: SemanticEffect,
    ) -> DecodedInstruction {
        insn(
            Isa::Thumb,
            pc,
            2,
            false,
            writes,
            effect,
            ControlFlow::Linear,
        )
    }

    fn write(dst: Register, value: ValueExpr) -> SemanticEffect {
        SemanticEffect::RegisterWrite { dst, value }
    }

    fn mov_imm(isa: Isa, pc: u32, dst: Register, value: u32) -> DecodedInstruction {
        let length = match isa {
            Isa::Arm => 4,
            Isa::Thumb => 2,
        };
        insn(
            isa,
            pc,
            length,
            false,
            [dst],
            write(dst, ValueExpr::Immediate(value)),
            ControlFlow::Linear,
        )
    }

    fn add_imm(pc: u32, dst: Register, src: Register, imm: u32) -> DecodedInstruction {
        arm(
            pc,
            [dst],
            write(
                dst,
                ValueExpr::Add {
                    left: src,
                    right: Operand::Immediate(imm),
                },
            ),
        )
    }

    fn sub_imm(pc: u32, dst: Register, src: Register, imm: u32) -> DecodedInstruction {
        arm(
            pc,
            [dst],
            write(
                dst,
                ValueExpr::Sub {
                    left: src,
                    right: Operand::Immediate(imm),
                },
            ),
        )
    }

    fn copy(pc: u32, dst: Register, src: Register) -> DecodedInstruction {
        arm(pc, [dst], write(dst, ValueExpr::Register(src)))
    }

    fn imm_addr(base: Register, offset: i64) -> AddressExpr {
        AddressExpr {
            base: AddressBase::Register(base),
            offset: AddressOffset::Immediate(offset),
        }
    }

    fn transfer(address: AddressExpr, kind: AccessKind, width: u8) -> MemoryTransfer {
        MemoryTransfer {
            address,
            kind,
            width,
        }
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

    fn mem(
        base: Register,
        offset: i64,
        kind: AccessKind,
        width: u8,
        dests: impl IntoIterator<Item = Register>,
    ) -> (SemanticEffect, BTreeSet<Register>) {
        (
            memory(vec![transfer(imm_addr(base, offset), kind, width)], None),
            dests.into_iter().collect(),
        )
    }

    fn load(pc: u32, dst: Register, base: Register, offset: i64, width: u8) -> DecodedInstruction {
        let (effect, writes) = mem(base, offset, AccessKind::Read, width, [dst]);
        arm(pc, writes, effect)
    }

    fn store(pc: u32, base: Register, offset: i64, width: u8) -> DecodedInstruction {
        let (effect, writes) = mem(base, offset, AccessKind::Write, width, []);
        arm(pc, writes, effect)
    }

    fn decoded_from(
        ranges: Vec<(
            AuthenticatedDecodeRange,
            Vec<DecodedInstruction>,
            Option<DecodeFailure>,
        )>,
    ) -> DecodedFunction {
        DecodedFunction {
            ranges: ranges
                .into_iter()
                .map(|(range, insns, decode_failure)| DecodedRange {
                    range,
                    instructions: insns.into_iter().map(|insn| (insn.pc, insn)).collect(),
                    decode_failure,
                })
                .collect(),
        }
    }

    fn linear_decoded(
        insns: Vec<DecodedInstruction>,
    ) -> (FunctionExecution, DecodedFunction, Vec<Block>) {
        let first = insns
            .first()
            .expect("linear fixture needs at least one instruction");
        let last = insns
            .last()
            .expect("linear fixture needs at least one instruction");
        let start = first.pc;
        let end = last
            .pc
            .checked_add(u32::from(last.length))
            .expect("fixture end");
        let isa = first.isa;
        let range = AuthenticatedDecodeRange {
            start,
            end,
            isa,
            blake3: [0; 32],
        };
        let function = function_at(start, vec![range]);
        let decoded = decoded_from(vec![(range, insns, None)]);
        let blocks = vec![Block {
            isa,
            start,
            end,
            successors: Vec::new(),
        }];
        (function, decoded, blocks)
    }

    fn track_linear(insns: Vec<DecodedInstruction>, recovered: &[u32]) -> TrackerReport {
        track_linear_on(&[], 0, insns, recovered)
    }

    fn track_linear_on(
        image: &[u8],
        load_address: u32,
        insns: Vec<DecodedInstruction>,
        recovered: &[u32],
    ) -> TrackerReport {
        let (function, decoded, blocks) = linear_decoded(insns);
        track_function(
            &function,
            &decoded,
            &blocks,
            image,
            load_address,
            &recovered.iter().copied().collect(),
            &BTreeMap::new(),
        )
        .expect("linear track")
    }

    fn track_reachable(
        function: FunctionExecution,
        decoded: DecodedFunction,
        recovered: &[u32],
    ) -> TrackerReport {
        let blocks = reachable_blocks(&function, &decoded).expect("reachable blocks");
        track_function(
            &function,
            &decoded,
            &blocks,
            &[],
            0,
            &recovered.iter().copied().collect(),
            &BTreeMap::new(),
        )
        .expect("reachable track")
    }

    fn obs(
        target: u32,
        pc: u32,
        kind: AccessKind,
        offset: u32,
        provenance: &[u32],
    ) -> CandidateObservation {
        CandidateObservation {
            target_address: target,
            isa: Isa::Arm,
            pc,
            conditional: false,
            kind,
            width: 4,
            offset,
            functions: contexts(),
            provenance_path: provenance.to_vec(),
            via: Vec::new(),
        }
    }

    fn all_core_writes() -> BTreeSet<Register> {
        (0..CORE_REGISTER_COUNT).map(Register).collect()
    }

    #[test]
    fn anchor_exact_value_only_when_equal_to_recovered() {
        let report = track_linear(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                load(0x1004, R1, R0, 0, 4),
            ],
            &[GLOBAL],
        );
        assert_eq!(
            report.candidates,
            vec![obs(GLOBAL, 0x1004, AccessKind::Read, 0, &[0x1000])]
        );

        let miss = track_linear(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, 0x1234),
                load(0x1004, R1, R0, 0, 4),
            ],
            &[GLOBAL],
        );
        assert!(miss.candidates.is_empty(), "{miss:?}");
    }

    #[test]
    fn anchor_value_between_globals_is_not_nearest_preceding() {
        let report = track_linear(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, BETWEEN),
                load(0x1004, R1, R0, 0, 4),
            ],
            &[GLOBAL, OTHER],
        );
        assert!(
            report.candidates.is_empty(),
            "between-globals value must not attach to {GLOBAL:#x}: {report:?}"
        );
    }

    #[test]
    fn anchor_identity_survives_copy_and_displacement() {
        let report = track_linear(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                copy(0x1004, R1, R0),
                add_imm(0x1008, R2, R1, 4),
                store(0x100c, R2, 0, 4),
            ],
            &[GLOBAL],
        );
        assert_eq!(
            report.candidates,
            vec![obs(
                GLOBAL,
                0x100c,
                AccessKind::Write,
                4,
                &[0x1000, 0x1004, 0x1008],
            )]
        );
    }

    #[test]
    fn anchor_fact_does_not_retarget_when_numeric_equals_another_global() {
        let report = track_linear(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                add_imm(0x1004, R0, R0, 8),
                load(0x1008, R1, R0, 0, 4),
            ],
            &[GLOBAL, GLOBAL + 8],
        );
        assert_eq!(
            report.candidates,
            vec![obs(GLOBAL, 0x1008, AccessKind::Read, 8, &[0x1000, 0x1004])]
        );
        assert!(
            report
                .candidates
                .iter()
                .all(|candidate| candidate.target_address != GLOBAL + 8)
        );
    }

    #[test]
    fn anchor_unanchored_effective_address_only_at_global_base() {
        let hit = track_linear(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL - 4),
                load(0x1004, R1, R0, 4, 4),
            ],
            &[GLOBAL],
        );
        assert_eq!(
            hit.candidates,
            vec![obs(GLOBAL, 0x1004, AccessKind::Read, 0, &[0x1000])]
        );

        let miss = track_linear(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL + 4),
                load(0x1004, R1, R0, 0, 4),
            ],
            &[GLOBAL],
        );
        assert!(
            miss.candidates.is_empty(),
            "unanchored interior address must not become offset 4 of the preceding global: {miss:?}"
        );
    }

    #[test]
    fn anchor_negative_displacement_produces_no_observation() {
        let report = track_linear(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                sub_imm(0x1004, R0, R0, 4),
                load(0x1008, R1, R0, 0, 4),
            ],
            &[GLOBAL],
        );
        assert!(report.candidates.is_empty(), "{report:?}");
    }

    #[test]
    fn anchor_wrap_overflow_kills_and_does_not_observe() {
        let wrap = track_linear(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, 0xffff_0000),
                add_imm(0x1004, R0, R0, 0x2_0000),
                sub_imm(0x1008, R0, R0, 0x2_0000),
                load(0x100c, R1, R0, 0, 4),
            ],
            &[0xffff_0000],
        );
        assert!(
            wrap.candidates.is_empty(),
            "u32 wrap must kill the Global rather than keep offset 0x20000: {wrap:?}"
        );

        let high_base = track_linear(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, 0xffff_fffc),
                load(0x1004, R1, R0, 4, 4),
            ],
            &[0xffff_fffc],
        );
        assert!(
            high_base.candidates.is_empty(),
            "high-base wrap must not observe at offset 4: {high_base:?}"
        );
    }

    #[test]
    fn anchor_offset_plus_width_overflow_produces_no_observation() {
        let report = track_linear(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                arm(
                    0x1004,
                    [R0],
                    write(
                        R0,
                        ValueExpr::Add {
                            left: R0,
                            right: Operand::Immediate(u32::MAX),
                        },
                    ),
                ),
                load(0x1008, R1, R0, 0, 4),
            ],
            &[GLOBAL],
        );
        assert!(
            report.candidates.is_empty(),
            "offset + width overflow must drop the observation: {report:?}"
        );
    }

    #[test]
    fn anchor_provenance_is_address_producers_not_access_pc() {
        let report = track_linear(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, 0x2000),
                arm(
                    0x1004,
                    [R0],
                    write(
                        R0,
                        ValueExpr::ReplaceHighHalf {
                            source: R0,
                            high: 0,
                        },
                    ),
                ),
                add_imm(0x1008, R0, R0, 8),
                load(0x100c, R1, R0, 0, 4),
            ],
            &[GLOBAL],
        );
        assert_eq!(report.candidates.len(), 1, "{report:?}");
        assert_eq!(report.candidates[0].pc, 0x100c);
        assert_eq!(
            report.candidates[0].provenance_path,
            vec![0x1000, 0x1004, 0x1008]
        );
        assert!(
            !report.candidates[0]
                .provenance_path
                .contains(&report.candidates[0].pc)
        );
    }

    #[test]
    fn value_movw_then_movt() {
        let report = track_linear(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, 0x5678),
                arm(
                    0x1004,
                    [R0],
                    write(
                        R0,
                        ValueExpr::ReplaceHighHalf {
                            source: R0,
                            high: 0x1234,
                        },
                    ),
                ),
                load(0x1008, R1, R0, 0, 4),
            ],
            &[0x1234_5678],
        );
        assert_eq!(
            report.candidates,
            vec![obs(
                0x1234_5678,
                0x1008,
                AccessKind::Read,
                0,
                &[0x1000, 0x1004],
            )]
        );
    }

    #[test]
    fn value_lone_movt_stays_unknown() {
        let report = track_linear(
            vec![
                arm(
                    0x1000,
                    [R0],
                    write(
                        R0,
                        ValueExpr::ReplaceHighHalf {
                            source: R0,
                            high: 0x1234,
                        },
                    ),
                ),
                load(0x1004, R1, R0, 0, 4),
            ],
            &[0x1234_0000],
        );
        assert!(report.candidates.is_empty(), "{report:?}");
    }

    #[test]
    fn value_register_copy() {
        let report = track_linear(
            vec![
                mov_imm(Isa::Arm, 0x1000, R1, GLOBAL),
                copy(0x1004, R0, R1),
                load(0x1008, R2, R0, 0, 4),
            ],
            &[GLOBAL],
        );
        assert_eq!(report.candidates[0].provenance_path, vec![0x1000, 0x1004]);
        assert_eq!(report.candidates[0].target_address, GLOBAL);
    }

    #[test]
    fn value_add_sub_immediate() {
        let add = track_linear(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                add_imm(0x1004, R0, R0, 12),
                load(0x1008, R1, R0, 0, 4),
            ],
            &[GLOBAL],
        );
        assert_eq!(add.candidates[0].offset, 12);

        let sub = track_linear(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                add_imm(0x1004, R0, R0, 12),
                sub_imm(0x1008, R0, R0, 4),
                load(0x100c, R1, R0, 0, 4),
            ],
            &[GLOBAL],
        );
        assert_eq!(sub.candidates[0].offset, 8);
    }

    #[test]
    fn value_exact_register_operand_accepted_shifts() {
        let cases = [
            (Shift::Lsl(2), 2, 8u32),
            (Shift::Lsr(1), 8, 4),
            (Shift::Asr(1), 10, 5),
            (Shift::Ror(4), 0x20, 0x0000_0002),
        ];
        for (shift, raw, expected_offset) in cases {
            let report = track_linear(
                vec![
                    mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                    mov_imm(Isa::Arm, 0x1004, R1, raw),
                    arm(
                        0x1008,
                        [R2],
                        write(
                            R2,
                            ValueExpr::Add {
                                left: R0,
                                right: Operand::Register {
                                    register: R1,
                                    shift,
                                },
                            },
                        ),
                    ),
                    load(0x100c, R3, R2, 0, 4),
                ],
                &[GLOBAL],
            );
            assert_eq!(
                report.candidates.len(),
                1,
                "shift {shift:?} produced {report:?}"
            );
            assert_eq!(
                report.candidates[0].offset, expected_offset,
                "shift {shift:?}"
            );
        }

        let rrx = track_linear(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                mov_imm(Isa::Arm, 0x1004, R1, 2),
                arm(
                    0x1008,
                    [R2],
                    write(
                        R2,
                        ValueExpr::Add {
                            left: R0,
                            right: Operand::Register {
                                register: R1,
                                shift: Shift::Rrx,
                            },
                        },
                    ),
                ),
                load(0x100c, R3, R2, 0, 4),
            ],
            &[GLOBAL],
        );
        assert!(
            rrx.candidates.is_empty(),
            "RRX must kill rather than invent a value: {rrx:?}"
        );
    }

    #[test]
    fn value_arm_pc_semantics() {
        let report = track_linear(
            vec![
                arm(
                    0x1000,
                    [R0],
                    write(
                        R0,
                        ValueExpr::ArchitecturalPc {
                            addend: 0,
                            align_to_four: false,
                        },
                    ),
                ),
                load(0x1004, R1, R0, 0, 4),
            ],
            &[0x1008],
        );
        assert_eq!(
            report.candidates,
            vec![obs(0x1008, 0x1004, AccessKind::Read, 0, &[0x1000])]
        );
    }

    #[test]
    fn value_thumb_pc_semantics() {
        let report = track_linear(
            vec![
                thumb(
                    0x1002,
                    [R0],
                    write(
                        R0,
                        ValueExpr::ArchitecturalPc {
                            addend: 0,
                            align_to_four: true,
                        },
                    ),
                ),
                insn(
                    Isa::Thumb,
                    0x1004,
                    2,
                    false,
                    [R1],
                    memory(vec![transfer(imm_addr(R0, 0), AccessKind::Read, 4)], None),
                    ControlFlow::Linear,
                ),
            ],
            &[0x1004],
        );
        assert_eq!(report.candidates.len(), 1, "{report:?}");
        assert_eq!(report.candidates[0].target_address, 0x1004);
        assert_eq!(report.candidates[0].isa, Isa::Thumb);
    }

    #[test]
    fn literal_word_load_in_image() {
        let mut image = vec![0u8; 16];
        image[8..12].copy_from_slice(&GLOBAL.to_le_bytes());
        let report = track_linear_on(
            &image,
            0x1000,
            vec![
                arm(
                    0x1000,
                    [R0],
                    SemanticEffect::LiteralWordLoad {
                        dst: R0,
                        address: AddressExpr {
                            base: AddressBase::ArchitecturalPc {
                                align_to_four: false,
                            },
                            offset: AddressOffset::Immediate(0),
                        },
                    },
                ),
                load(0x1004, R1, R0, 0, 4),
            ],
            &[GLOBAL],
        );
        assert_eq!(
            report.candidates,
            vec![obs(GLOBAL, 0x1004, AccessKind::Read, 0, &[0x1000])]
        );
    }

    #[test]
    fn literal_address_overflow_rejected() {
        let report = track_linear_on(
            &[0; 16],
            0x1000,
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, 0xffff_fffe),
                arm(
                    0x1004,
                    [R1],
                    SemanticEffect::LiteralWordLoad {
                        dst: R1,
                        address: imm_addr(R0, 0),
                    },
                ),
                load(0x1008, R2, R1, 0, 4),
            ],
            &[GLOBAL],
        );
        assert!(
            report.candidates.is_empty(),
            "overflowing literal word must not produce an observation: {report:?}"
        );
    }

    #[test]
    fn literal_below_load_address_rejected() {
        let mut image = vec![0u8; 16];
        image[0..4].copy_from_slice(&GLOBAL.to_le_bytes());
        let report = track_linear_on(
            &image,
            0x2000,
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, 0x1000),
                arm(
                    0x1004,
                    [R1],
                    SemanticEffect::LiteralWordLoad {
                        dst: R1,
                        address: imm_addr(R0, 0),
                    },
                ),
                load(0x1008, R2, R1, 0, 4),
            ],
            &[GLOBAL],
        );
        assert!(
            report.candidates.is_empty(),
            "literal below the load address must not be read: {report:?}"
        );
    }

    #[test]
    fn literal_truncated_pool_rejected() {
        let mut image = vec![0u8; 10];
        image[8..10].copy_from_slice(&0x2000u16.to_le_bytes());
        let report = track_linear_on(
            &image,
            0x1000,
            vec![
                arm(
                    0x1000,
                    [R0],
                    SemanticEffect::LiteralWordLoad {
                        dst: R0,
                        address: AddressExpr {
                            base: AddressBase::ArchitecturalPc {
                                align_to_four: false,
                            },
                            offset: AddressOffset::Immediate(0),
                        },
                    },
                ),
                load(0x1004, R1, R0, 0, 4),
            ],
            &[GLOBAL],
        );
        assert!(report.candidates.is_empty(), "{report:?}");
    }

    #[test]
    fn literal_loaded_word_anchors_when_equal_to_global() {
        let mut image = vec![0u8; 16];
        image[8..12].copy_from_slice(&GLOBAL.to_le_bytes());
        let report = track_linear_on(
            &image,
            0x1000,
            vec![
                arm(
                    0x1000,
                    [R0],
                    SemanticEffect::LiteralWordLoad {
                        dst: R0,
                        address: AddressExpr {
                            base: AddressBase::ArchitecturalPc {
                                align_to_four: false,
                            },
                            offset: AddressOffset::Immediate(0),
                        },
                    },
                ),
                load(0x1004, R1, R0, 4, 4),
            ],
            &[GLOBAL],
        );
        assert_eq!(report.candidates[0].target_address, GLOBAL);
        assert_eq!(report.candidates[0].offset, 4);
    }

    #[test]
    fn literal_records_read_if_address_attributable() {
        let mut image = vec![0u8; 16];
        image[8..12].copy_from_slice(&0x1111_1111u32.to_le_bytes());
        let report = track_linear_on(
            &image,
            0x1000,
            vec![arm(
                0x1000,
                [R0],
                SemanticEffect::LiteralWordLoad {
                    dst: R0,
                    address: AddressExpr {
                        base: AddressBase::ArchitecturalPc {
                            align_to_four: false,
                        },
                        offset: AddressOffset::Immediate(0),
                    },
                },
            )],
            &[0x1008],
        );
        assert_eq!(
            report.candidates,
            vec![obs(0x1008, 0x1000, AccessKind::Read, 0, &[])]
        );
    }

    #[test]
    fn memory_load_store_readwrite_widths() {
        let cases = [
            (AccessKind::Read, 1u8),
            (AccessKind::Read, 2),
            (AccessKind::Read, 4),
            (AccessKind::Read, 8),
            (AccessKind::Write, 1),
            (AccessKind::Write, 2),
            (AccessKind::Write, 4),
            (AccessKind::Write, 8),
            (AccessKind::ReadWrite, 1),
            (AccessKind::ReadWrite, 4),
        ];
        for (kind, width) in cases {
            let dests = match kind {
                AccessKind::Write => Vec::new(),
                _ => vec![R1],
            };
            let report = track_linear(
                vec![
                    mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                    arm(
                        0x1004,
                        dests,
                        memory(vec![transfer(imm_addr(R0, 0), kind, width)], None),
                    ),
                ],
                &[GLOBAL],
            );
            assert_eq!(report.candidates.len(), 1, "{kind:?} width {width}");
            assert_eq!(report.candidates[0].kind, kind);
            assert_eq!(report.candidates[0].width, width);
        }
    }

    #[test]
    fn memory_signed_load_storage_widths() {
        for width in [1u8, 2] {
            let report = track_linear(
                vec![
                    mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                    load(0x1004, R1, R0, 0, width),
                ],
                &[GLOBAL],
            );
            assert_eq!(report.candidates[0].width, width);
            assert_eq!(report.candidates[0].kind, AccessKind::Read);
        }
    }

    #[test]
    fn memory_immediate_register_offset_add_sub() {
        let add = track_linear(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                load(0x1004, R1, R0, 8, 4),
            ],
            &[GLOBAL],
        );
        assert_eq!(add.candidates[0].offset, 8);

        let sub = track_linear(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                add_imm(0x1004, R0, R0, 8),
                load(0x1008, R1, R0, -4, 4),
            ],
            &[GLOBAL],
        );
        assert_eq!(sub.candidates[0].offset, 4);

        let reg = track_linear(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                mov_imm(Isa::Arm, 0x1004, R1, 2),
                arm(
                    0x1008,
                    [R2],
                    memory(
                        vec![transfer(
                            AddressExpr {
                                base: AddressBase::Register(R0),
                                offset: AddressOffset::Register {
                                    register: R1,
                                    subtract: false,
                                    shift: Shift::Lsl(2),
                                },
                            },
                            AccessKind::Read,
                            4,
                        )],
                        None,
                    ),
                ),
            ],
            &[GLOBAL],
        );
        assert_eq!(reg.candidates[0].offset, 8);

        let reg_sub = track_linear(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                add_imm(0x1004, R0, R0, 8),
                mov_imm(Isa::Arm, 0x1008, R1, 4),
                arm(
                    0x100c,
                    [R2],
                    memory(
                        vec![transfer(
                            AddressExpr {
                                base: AddressBase::Register(R0),
                                offset: AddressOffset::Register {
                                    register: R1,
                                    subtract: true,
                                    shift: Shift::Lsl(0),
                                },
                            },
                            AccessKind::Read,
                            4,
                        )],
                        None,
                    ),
                ),
            ],
            &[GLOBAL],
        );
        assert_eq!(reg_sub.candidates[0].offset, 4);
    }

    #[test]
    fn memory_pre_index_observes_before_writeback() {
        let report = track_linear(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                arm(
                    0x1004,
                    [R1, R0],
                    memory(
                        vec![transfer(imm_addr(R0, 4), AccessKind::Read, 4)],
                        Some((R0, imm_addr(R0, 4))),
                    ),
                ),
                load(0x1008, R2, R0, 0, 4),
            ],
            &[GLOBAL],
        );
        assert_eq!(
            report
                .candidates
                .iter()
                .map(|candidate| (candidate.pc, candidate.offset))
                .collect::<Vec<_>>(),
            vec![(0x1004, 4), (0x1008, 4)]
        );
    }

    #[test]
    fn memory_post_index_observes_before_writeback() {
        let report = track_linear(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                arm(
                    0x1004,
                    [R1, R0],
                    memory(
                        vec![transfer(imm_addr(R0, 0), AccessKind::Read, 4)],
                        Some((R0, imm_addr(R0, 4))),
                    ),
                ),
                load(0x1008, R2, R0, 0, 4),
            ],
            &[GLOBAL],
        );
        assert_eq!(
            report
                .candidates
                .iter()
                .map(|candidate| (candidate.pc, candidate.offset))
                .collect::<Vec<_>>(),
            vec![(0x1004, 0), (0x1008, 4)]
        );
    }

    #[test]
    fn memory_exact_writeback_preserves_global_identity() {
        let report = track_linear(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                arm(
                    0x1004,
                    [R1, R0],
                    memory(
                        vec![transfer(imm_addr(R0, 8), AccessKind::Read, 4)],
                        Some((R0, imm_addr(R0, 8))),
                    ),
                ),
                add_imm(0x1008, R0, R0, 4),
                store(0x100c, R0, 0, 2),
            ],
            &[GLOBAL, GLOBAL + 8],
        );
        assert_eq!(report.candidates.len(), 2, "{report:?}");
        assert!(
            report
                .candidates
                .iter()
                .all(|candidate| candidate.target_address == GLOBAL)
        );
        assert_eq!(report.candidates[1].offset, 12);
    }

    #[test]
    fn memory_loaded_destination_killed_after_observation() {
        let report = track_linear(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                load(0x1004, R0, R0, 0, 4),
                load(0x1008, R1, R0, 0, 4),
            ],
            &[GLOBAL],
        );
        assert_eq!(report.candidates.len(), 1, "{report:?}");
        assert_eq!(report.candidates[0].pc, 0x1004);
    }

    #[test]
    fn memory_store_exclusive_status_register_write() {
        let report = track_linear(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                mov_imm(Isa::Arm, 0x1004, R2, 7),
                arm(
                    0x1008,
                    [R2],
                    memory(vec![transfer(imm_addr(R0, 0), AccessKind::Write, 4)], None),
                ),
                load(0x100c, R1, R2, 0, 4),
            ],
            &[GLOBAL],
        );
        assert_eq!(report.candidates.len(), 1, "{report:?}");
        assert_eq!(report.candidates[0].kind, AccessKind::Write);
        assert_eq!(report.candidates[0].pc, 0x1008);
    }

    #[test]
    fn memory_swap_read_write() {
        let report = track_linear(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                arm(
                    0x1004,
                    [R1],
                    memory(
                        vec![transfer(imm_addr(R0, 0), AccessKind::ReadWrite, 4)],
                        None,
                    ),
                ),
            ],
            &[GLOBAL],
        );
        assert_eq!(report.candidates[0].kind, AccessKind::ReadWrite);
    }

    #[test]
    fn memory_ldm_stm_ordering_and_offsets() {
        let report = track_linear(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                arm(
                    0x1004,
                    [R1, R2],
                    memory(
                        vec![
                            transfer(imm_addr(R0, 4), AccessKind::Read, 4),
                            transfer(imm_addr(R0, 0), AccessKind::Read, 4),
                        ],
                        None,
                    ),
                ),
                arm(
                    0x1008,
                    [],
                    memory(
                        vec![
                            transfer(imm_addr(R0, 8), AccessKind::Write, 4),
                            transfer(imm_addr(R0, 12), AccessKind::Write, 4),
                        ],
                        None,
                    ),
                ),
            ],
            &[GLOBAL],
        );
        let keys: Vec<_> = report
            .candidates
            .iter()
            .map(|candidate| (candidate.pc, candidate.kind, candidate.offset))
            .collect();
        assert_eq!(
            keys,
            vec![
                (0x1004, AccessKind::Read, 0),
                (0x1004, AccessKind::Read, 4),
                (0x1008, AccessKind::Write, 8),
                (0x1008, AccessKind::Write, 12),
            ]
        );
    }

    #[test]
    fn memory_conditional_access_recorded() {
        let report = track_linear(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                insn(
                    Isa::Arm,
                    0x1004,
                    4,
                    true,
                    [R1],
                    memory(vec![transfer(imm_addr(R0, 0), AccessKind::Read, 4)], None),
                    ControlFlow::Linear,
                ),
            ],
            &[GLOBAL],
        );
        assert_eq!(report.candidates.len(), 1);
        assert!(report.candidates[0].conditional);
    }

    #[test]
    fn memory_loaded_pointer_contents_not_followed() {
        let report = track_linear(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                load(0x1004, R1, R0, 0, 4),
                load(0x1008, R2, R1, 0, 4),
            ],
            &[GLOBAL],
        );
        assert_eq!(report.candidates.len(), 1, "{report:?}");
        assert_eq!(report.candidates[0].pc, 0x1004);
    }

    fn branch_function(
        insns: Vec<DecodedInstruction>,
        end: u32,
    ) -> (FunctionExecution, DecodedFunction) {
        let range = arm_range(ENTRY, end);
        let function = function_at(ENTRY, vec![range]);
        let decoded = decoded_from(vec![(range, insns, None)]);
        (function, decoded)
    }

    fn breq(pc: u32, target: u32) -> DecodedInstruction {
        insn(
            Isa::Arm,
            pc,
            4,
            true,
            [],
            SemanticEffect::None,
            ControlFlow::DirectBranch {
                target,
                has_fallthrough: true,
            },
        )
    }

    fn b(pc: u32, target: u32) -> DecodedInstruction {
        insn(
            Isa::Arm,
            pc,
            4,
            false,
            [],
            SemanticEffect::None,
            ControlFlow::DirectBranch {
                target,
                has_fallthrough: false,
            },
        )
    }

    #[test]
    fn facts_cross_conditional_edges_into_both_arms() {
        let (function, decoded) = branch_function(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                breq(0x1004, 0x100c),
                load(0x1008, R1, R0, 0, 4),
                load(0x100c, R2, R0, 0, 4),
            ],
            0x1010,
        );
        let report = track_reachable(function, decoded, &[GLOBAL]);
        let pcs: Vec<u32> = report.candidates.iter().map(|c| c.pc).collect();
        assert_eq!(pcs, vec![0x1008, 0x100c]);
        assert_eq!(report.propagated_facts, 2);
    }

    #[test]
    fn facts_cross_a_call_fallthrough() {
        let (function, decoded) = branch_function(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                insn(
                    Isa::Arm,
                    0x1004,
                    4,
                    false,
                    [],
                    SemanticEffect::None,
                    ControlFlow::Call { target: None },
                ),
                load(0x1008, R1, R0, 0, 4),
            ],
            0x100c,
        );
        let report = track_reachable(function, decoded, &[GLOBAL]);
        assert_eq!(
            report.candidates,
            vec![obs(GLOBAL, 0x1008, AccessKind::Read, 0, &[0x1000])]
        );
        assert_eq!(report.propagated_facts, 1);
    }

    #[test]
    fn join_agreement_carries_fact_across_a_diamond() {
        // entry: mov r0,GLOBAL ; breq → 0x100c (ft 0x1008)
        // left:  mov r0,GLOBAL            (0x1008..0x100c)
        // join:  load r1,[r0]             (0x100c)
        let (function, decoded) = branch_function(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                breq(0x1004, 0x100c),
                mov_imm(Isa::Arm, 0x1008, R0, GLOBAL),
                load(0x100c, R1, R0, 0, 4),
            ],
            0x1010,
        );
        let report = track_reachable(function, decoded, &[GLOBAL]);
        assert_eq!(
            report.candidates,
            vec![obs(GLOBAL, 0x100c, AccessKind::Read, 0, &[0x1000, 0x1008])]
        );
        assert!(report.join_survivor);
        assert_eq!(report.join_kills, 0);
        assert_eq!(report.join_facts, 2); // r0 arrives at 0x1008 and at 0x100c
        assert_eq!(report.entry_facts, 2); // r0 live at 0x1008 and 0x100c entries
        assert_eq!(report.propagated_facts, 1); // the 0x100c use
        assert_eq!(report.state_barriers, 0);
    }

    #[test]
    fn join_disagreement_kills_fact_and_counts_a_barrier() {
        let (function, decoded) = branch_function(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                breq(0x1004, 0x100c),
                mov_imm(Isa::Arm, 0x1008, R0, OTHER),
                load(0x100c, R1, R0, 0, 4),
            ],
            0x1010,
        );
        let report = track_reachable(function, decoded, &[GLOBAL, OTHER]);
        assert!(
            report.candidates.is_empty(),
            "disagreeing arms must not carry either fact: {report:?}"
        );
        assert_eq!(report.join_kills, 1);
        assert_eq!(report.state_barriers, 1); // the join kill, no instruction kill
        // r0 provably holds GLOBAL along the fallthrough arm's single
        // in-edge, so that block's entry state keeps the fact (must-join
        // only kills at the 0x100c join where the arms disagree).
        assert!(report.join_survivor);
        assert_eq!(report.entry_facts, 1);
    }

    #[test]
    fn fact_survives_a_loop_back_edge() {
        // 0x1000: mov r0,GLOBAL ; 0x1004: b → 0x1008
        // 0x1008: load r1,[r0] ; 0x100c: b → 0x1008
        let (function, decoded) = branch_function(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                b(0x1004, 0x1008),
                load(0x1008, R1, R0, 0, 4),
                b(0x100c, 0x1008),
            ],
            0x1010,
        );
        let report = track_reachable(function, decoded, &[GLOBAL]);
        assert_eq!(
            report.candidates,
            vec![obs(GLOBAL, 0x1008, AccessKind::Read, 0, &[0x1000])]
        );
        assert!(report.join_survivor);
        assert_eq!(report.join_kills, 0);
    }

    #[test]
    fn seed_killed_by_disagreeing_predecessor() {
        // Loop back into the seeded entry: the predecessor's out-state
        // disagrees with the seed, so the seed must not win by fiat.
        let (function, decoded) = branch_function(
            vec![
                insn(
                    Isa::Arm,
                    0x1000,
                    4,
                    false,
                    [R1],
                    write(R1, ValueExpr::Immediate(0x9999)),
                    ControlFlow::Linear,
                ),
                b(0x1004, 0x1008),
                load(0x1008, R2, R1, 0, 4),
                b(0x100c, 0x1000),
            ],
            0x1010,
        );
        let blocks = reachable_blocks(&function, &decoded).expect("reachable blocks");
        let report = track_function(
            &function,
            &decoded,
            &blocks,
            &[],
            0,
            &BTreeSet::from([GLOBAL]),
            &BTreeMap::from([(R1, GLOBAL)]),
        )
        .expect("seeded loop track");
        assert!(report.candidates.is_empty(), "{report:?}");
        assert_eq!(
            report.join_kills, 1,
            "the seed r1 must die at the entry join"
        );
    }

    #[test]
    fn seeded_fact_flows_beyond_the_entry_block() {
        // Entry contains only a branch; the seeded dereference sits in the
        // successor block (the callee-side cross-block case the v1 engine lost).
        let (function, decoded) =
            branch_function(vec![b(0x1000, 0x1004), load(0x1004, R1, R1, 4, 4)], 0x1008);
        let blocks = reachable_blocks(&function, &decoded).expect("reachable blocks");
        let report = track_function(
            &function,
            &decoded,
            &blocks,
            &[],
            0,
            &BTreeSet::from([GLOBAL]),
            &BTreeMap::from([(R1, GLOBAL)]),
        )
        .expect("seeded track");
        assert_eq!(
            report.candidates,
            vec![obs(GLOBAL, 0x1004, AccessKind::Read, 4, &[])]
        );
        assert!(report.join_survivor);
        assert_eq!(
            report.propagated_facts, 0,
            "empty-provenance seed is not a propagated fact"
        );
    }

    #[test]
    fn tracking_is_deterministic() {
        let (function, decoded) = branch_function(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                breq(0x1004, 0x100c),
                mov_imm(Isa::Arm, 0x1008, R0, GLOBAL),
                load(0x100c, R1, R0, 0, 4),
                b(0x1010, 0x1008),
            ],
            0x1014,
        );
        let (function2, decoded2) = branch_function(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                breq(0x1004, 0x100c),
                mov_imm(Isa::Arm, 0x1008, R0, GLOBAL),
                load(0x100c, R1, R0, 0, 4),
                b(0x1010, 0x1008),
            ],
            0x1014,
        );
        let first = track_reachable(function, decoded, &[GLOBAL]);
        let second = track_reachable(function2, decoded2, &[GLOBAL]);
        assert_eq!(first, second);
    }

    #[test]
    fn facts_cross_an_unconditional_edge() {
        let (function, decoded) = branch_function(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                b(0x1004, 0x100c),
                load(0x1008, R1, R0, 0, 4), // unreachable: no block, no observation
                load(0x100c, R2, R0, 0, 4),
            ],
            0x1010,
        );
        let report = track_reachable(function, decoded, &[GLOBAL]);
        assert_eq!(
            report.candidates,
            vec![obs(GLOBAL, 0x100c, AccessKind::Read, 0, &[0x1000])]
        );
    }

    #[test]
    fn join_disagreement_between_predecessors_kills_fact() {
        let (function, decoded) = branch_function(
            vec![
                insn(
                    Isa::Arm,
                    0x1000,
                    4,
                    true,
                    [],
                    SemanticEffect::None,
                    ControlFlow::DirectBranch {
                        target: 0x100c,
                        has_fallthrough: true,
                    },
                ),
                mov_imm(Isa::Arm, 0x1004, R0, GLOBAL),
                insn(
                    Isa::Arm,
                    0x1008,
                    4,
                    false,
                    [],
                    SemanticEffect::None,
                    ControlFlow::DirectBranch {
                        target: 0x100c,
                        has_fallthrough: false,
                    },
                ),
                load(0x100c, R1, R0, 0, 4),
            ],
            0x1010,
        );
        let report = track_reachable(function, decoded, &[GLOBAL]);
        assert!(report.candidates.is_empty(), "{report:?}");
        assert_eq!(report.join_kills, 1);
        assert_eq!(report.state_barriers, 1);
    }

    #[test]
    fn block_unreachable_instructions_produce_no_observation() {
        let (function, decoded) = branch_function(
            vec![
                insn(
                    Isa::Arm,
                    0x1000,
                    4,
                    false,
                    [],
                    SemanticEffect::None,
                    ControlFlow::DirectBranch {
                        target: 0x100c,
                        has_fallthrough: false,
                    },
                ),
                arm(
                    0x1004,
                    [R0],
                    SemanticEffect::LiteralWordLoad {
                        dst: R0,
                        address: AddressExpr {
                            base: AddressBase::ArchitecturalPc {
                                align_to_four: false,
                            },
                            offset: AddressOffset::Immediate(0),
                        },
                    },
                ),
                load(0x1008, R1, R0, 0, 4),
                arm(0x100c, [], SemanticEffect::None),
            ],
            0x1010,
        );
        let report = track_reachable(function, decoded, &[0x100c]);
        assert!(
            report.candidates.is_empty(),
            "unreachable literal access must stay silent: {report:?}"
        );
    }

    #[test]
    fn block_return_indirect_paths_end() {
        let (function, decoded) = branch_function(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                insn(
                    Isa::Arm,
                    0x1004,
                    4,
                    false,
                    [],
                    SemanticEffect::None,
                    ControlFlow::Stop,
                ),
                load(0x1008, R1, R0, 0, 4),
            ],
            0x100c,
        );
        let report = track_reachable(function, decoded, &[GLOBAL]);
        assert!(report.candidates.is_empty(), "{report:?}");
    }

    #[test]
    fn block_prefix_survives_later_decoder_failure() {
        let range = arm_range(0x1000, 0x100c);
        let function = function_at(0x1000, vec![range]);
        let decoded = decoded_from(vec![(
            range,
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                load(0x1004, R1, R0, 0, 4),
            ],
            Some(DecodeFailure {
                pc: 0x1008,
                message: "truncated encoding".into(),
            }),
        )]);
        let report = track_reachable(function, decoded, &[GLOBAL]);
        assert_eq!(report.candidates.len(), 1, "{report:?}");
        assert_eq!(report.candidates[0].pc, 0x1004);
    }

    #[test]
    fn block_candidate_order_is_deterministic() {
        let arm_range = arm_range(0x2000, 0x200c);
        let thumb_range = thumb_range(0x1000, 0x1006);
        let function = function_at(0x2000, vec![arm_range, thumb_range]);
        let decoded = decoded_from(vec![
            (
                arm_range,
                vec![
                    mov_imm(Isa::Arm, 0x2000, R0, OTHER),
                    insn(
                        Isa::Arm,
                        0x2004,
                        4,
                        false,
                        [R1, R2],
                        memory(
                            vec![
                                transfer(imm_addr(R0, 4), AccessKind::Write, 2),
                                transfer(imm_addr(R0, 0), AccessKind::Read, 4),
                            ],
                            None,
                        ),
                        ControlFlow::DirectBranch {
                            target: 0x1000,
                            has_fallthrough: false,
                        },
                    ),
                ],
                None,
            ),
            (
                thumb_range,
                vec![
                    mov_imm(Isa::Thumb, 0x1000, R0, GLOBAL),
                    insn(
                        Isa::Thumb,
                        0x1002,
                        2,
                        false,
                        [R1],
                        memory(vec![transfer(imm_addr(R0, 0), AccessKind::Read, 1)], None),
                        ControlFlow::Linear,
                    ),
                    insn(
                        Isa::Thumb,
                        0x1004,
                        2,
                        false,
                        [R1],
                        memory(vec![transfer(imm_addr(R0, 0), AccessKind::Read, 1)], None),
                        ControlFlow::Linear,
                    ),
                ],
                None,
            ),
        ]);
        let report = track_reachable(function, decoded, &[GLOBAL, OTHER]);
        let keys: Vec<_> = report
            .candidates
            .iter()
            .map(|candidate| {
                (
                    candidate.isa,
                    candidate.pc,
                    candidate.target_address,
                    candidate.kind,
                    candidate.width,
                    candidate.offset,
                )
            })
            .collect();
        assert_eq!(
            keys,
            vec![
                (Isa::Arm, 0x2004, OTHER, AccessKind::Read, 4, 0),
                (Isa::Arm, 0x2004, OTHER, AccessKind::Write, 2, 4),
                (Isa::Thumb, 0x1002, GLOBAL, AccessKind::Read, 1, 0),
                (Isa::Thumb, 0x1004, GLOBAL, AccessKind::Read, 1, 0),
            ]
        );
    }

    #[test]
    fn barrier_entry_initialization_is_not_a_barrier() {
        let report = track_linear(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                load(0x1004, R1, R0, 0, 4),
            ],
            &[GLOBAL],
        );
        assert_eq!(report.state_barriers, 0);
        assert_eq!(report.candidates.len(), 1);
    }

    #[test]
    fn barrier_v3_drops_per_block_start_count() {
        let (function, decoded) = branch_function(
            vec![
                insn(
                    Isa::Arm,
                    0x1000,
                    4,
                    false,
                    [],
                    SemanticEffect::None,
                    ControlFlow::DirectBranch {
                        target: 0x1008,
                        has_fallthrough: false,
                    },
                ),
                arm(0x1004, [], SemanticEffect::None),
                arm(0x1008, [], SemanticEffect::None),
            ],
            0x100c,
        );
        let report = track_reachable(function, decoded, &[]);
        assert_eq!(report.state_barriers, 0);
        assert_eq!(report.join_kills, 0);
    }

    #[test]
    fn barrier_instruction_kills_at_most_once() {
        let report = track_linear(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                mov_imm(Isa::Arm, 0x1004, R1, GLOBAL),
                arm(0x1008, [R0, R1], SemanticEffect::Unsupported),
            ],
            &[GLOBAL],
        );
        assert_eq!(report.state_barriers, 1);
    }

    #[test]
    fn barrier_bounded_unsupported_kills_only_destinations() {
        let report = track_linear(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                mov_imm(Isa::Arm, 0x1004, R1, OTHER),
                arm(0x1008, [R0], SemanticEffect::Unsupported),
                load(0x100c, R2, R1, 0, 4),
                load(0x1010, R3, R0, 0, 4),
            ],
            &[GLOBAL, OTHER],
        );
        assert_eq!(report.candidates.len(), 1, "{report:?}");
        assert_eq!(report.candidates[0].target_address, OTHER);
        assert_eq!(report.state_barriers, 1);
    }

    #[test]
    fn barrier_unbounded_unsupported_clears_all() {
        let report = track_linear(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                mov_imm(Isa::Arm, 0x1004, R1, OTHER),
                insn(
                    Isa::Arm,
                    0x1008,
                    4,
                    false,
                    all_core_writes(),
                    SemanticEffect::Unsupported,
                    ControlFlow::Linear,
                ),
                load(0x100c, R2, R0, 0, 4),
                load(0x1010, R3, R1, 0, 4),
            ],
            &[GLOBAL, OTHER],
        );
        assert!(report.candidates.is_empty(), "{report:?}");
        assert_eq!(report.state_barriers, 1);
    }

    #[test]
    fn barrier_conditional_write_retains_only_identical() {
        let keep = track_linear(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                insn(
                    Isa::Arm,
                    0x1004,
                    4,
                    true,
                    [R0],
                    write(R0, ValueExpr::Immediate(GLOBAL)),
                    ControlFlow::Linear,
                ),
                load(0x1008, R1, R0, 0, 4),
            ],
            &[GLOBAL],
        );
        assert_eq!(keep.candidates.len(), 1, "{keep:?}");
        assert_eq!(keep.candidates[0].provenance_path, vec![0x1000]);

        let kill = track_linear(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                insn(
                    Isa::Arm,
                    0x1004,
                    4,
                    true,
                    [R0],
                    write(R0, ValueExpr::Immediate(OTHER)),
                    ControlFlow::Linear,
                ),
                load(0x1008, R1, R0, 0, 4),
            ],
            &[GLOBAL, OTHER],
        );
        assert!(kill.candidates.is_empty(), "{kill:?}");

        let unknown = track_linear(
            vec![
                insn(
                    Isa::Arm,
                    0x1000,
                    4,
                    true,
                    [R0],
                    write(R0, ValueExpr::Immediate(GLOBAL)),
                    ControlFlow::Linear,
                ),
                load(0x1004, R1, R0, 0, 4),
            ],
            &[GLOBAL],
        );
        assert!(unknown.candidates.is_empty(), "{unknown:?}");
    }

    #[test]
    fn barrier_decode_failure_is_not_counted() {
        let range = arm_range(0x1000, 0x100c);
        let function = function_at(0x1000, vec![range]);
        let decoded = decoded_from(vec![(
            range,
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                load(0x1004, R1, R0, 0, 4),
            ],
            Some(DecodeFailure {
                pc: 0x1008,
                message: "truncated encoding".into(),
            }),
        )]);
        let report = track_reachable(function, decoded, &[GLOBAL]);
        assert_eq!(report.state_barriers, 0);
        assert_eq!(report.candidates.len(), 1);
    }

    #[test]
    fn barrier_unioned_function_names_do_not_multiply() {
        let range = arm_range(0x1000, 0x100c);
        let function = FunctionExecution {
            owner: FunctionOwner::Ghidra,
            identity: ExecutionIdentity {
                entry: 0x1000,
                decode_ranges: vec![range],
                execution_blake3: [0; 32],
            },
            contexts: BTreeSet::from([
                FunctionContext {
                    entry: 0x1000,
                    name: "a".into(),
                },
                FunctionContext {
                    entry: 0x1000,
                    name: "b".into(),
                },
            ]),
        };
        let decoded = decoded_from(vec![(
            range,
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                mov_imm(Isa::Arm, 0x1004, R1, OTHER),
                arm(0x1008, [R0], SemanticEffect::Unsupported),
            ],
            None,
        )]);
        let report = track_function(
            &function,
            &decoded,
            &[Block {
                isa: Isa::Arm,
                start: 0x1000,
                end: 0x100c,
                successors: Vec::new(),
            }],
            &[],
            0,
            &BTreeSet::from([GLOBAL, OTHER]),
            &BTreeMap::new(),
        )
        .expect("unioned contexts");
        assert_eq!(report.state_barriers, 1);
        assert!(report.candidates.is_empty());
    }

    #[test]
    fn harvest_emits_call_fact_when_arg_reg_holds_global() {
        // mov r0, GLOBAL ; bl <callee 0x1200 (arm)>
        let report = track_linear(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                insn(
                    Isa::Arm,
                    0x1004,
                    4,
                    false,
                    [],
                    SemanticEffect::None,
                    ControlFlow::Call {
                        target: Some(CallTarget {
                            entry: 0x1200,
                            isa: Isa::Arm,
                        }),
                    },
                ),
            ],
            &[GLOBAL],
        );
        assert_eq!(report.call_facts.len(), 1);
        let cf = &report.call_facts[0];
        assert_eq!(cf.callee_target, 0x1200);
        assert_eq!(cf.callee_isa, Isa::Arm);
        assert_eq!(cf.call_pc, 0x1004);
        assert_eq!(cf.seed.get(&R0), Some(&GLOBAL));
    }

    #[test]
    fn harvest_ignores_interior_pointer_and_indirect_call() {
        // &GLOBAL+8 in r0 must not seed; a target:None call must not harvest.
        let interior = track_linear(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                add_imm(0x1004, R0, R0, 8),
                insn(
                    Isa::Arm,
                    0x1008,
                    4,
                    false,
                    [],
                    SemanticEffect::None,
                    ControlFlow::Call {
                        target: Some(CallTarget {
                            entry: 0x1200,
                            isa: Isa::Arm,
                        }),
                    },
                ),
            ],
            &[GLOBAL],
        );
        assert!(interior.call_facts.is_empty(), "{interior:?}");
        let indirect = track_linear(
            vec![
                mov_imm(Isa::Arm, 0x1000, R0, GLOBAL),
                insn(
                    Isa::Arm,
                    0x1004,
                    4,
                    false,
                    [],
                    SemanticEffect::None,
                    ControlFlow::Call { target: None },
                ),
            ],
            &[GLOBAL],
        );
        assert!(indirect.call_facts.is_empty());
    }

    #[test]
    fn seeded_entry_block_observes_dereference_of_seeded_global() {
        // callee entry: str [r1, #4]  — with r1 seeded = &GLOBAL, expect write obs at offset 4.
        let (function, decoded, blocks) = linear_decoded(vec![store(0x1200, R1, 4, 4)]);
        let seed = BTreeMap::from([(R1, GLOBAL)]);
        let report = track_function(
            &function,
            &decoded,
            &blocks,
            &[],
            0,
            &BTreeSet::from([GLOBAL]),
            &seed,
        )
        .unwrap();
        assert_eq!(report.candidates.len(), 1);
        assert_eq!(report.candidates[0].target_address, GLOBAL);
        assert_eq!(report.candidates[0].offset, 4);
        assert_eq!(report.candidates[0].kind, AccessKind::Write);
    }
}
