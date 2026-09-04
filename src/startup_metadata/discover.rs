// Seed search over byte-backed runtime spans, containing C-string
// extraction, semantic materialization over accepted executions, and
// the single-plan allocator.

use super::{
    CompilerMeta, HardwareInit, MAX_APPLICATIONS, MAX_CALLGRAPH_DEPTH, MAX_CALLGRAPH_FUNCTIONS,
    MAX_CSTRING_BYTES, MAX_PRIVILEGED_OPS, MAX_SEED_REFS, PrivilegedClass, PrivilegedOp, SEED_RVCT,
    SEED_SHANNON_OS, SEED_STACK_GUARD, SEED_WARM_BOOT, Section, StackGuard, StartupApplication,
    StartupMetadataError, StartupPlan, StartupRole,
};
use crate::arm32::{
    AddressBase, AddressOffset, ControlFlow, CoprocessorTransfer, DecodedInstruction,
    InstructionDecoder, PureRustDecoder, Register, SystemDirection, SystemEffect, ValueEffect,
    ValueExpr, valid_isa_length, visible_pc, wrapping_offset,
};
use crate::execution_ranges::{
    AuthenticatedDecodeRange, DecodeIsa, ExecutionProjection, OwnedExecutionIdentity,
    TaggedExecutionRecord, execution_identity,
};
use crate::runtime_image::{ByteBackedRange, MAX_EXACT_READ, RuntimeImage};
use crate::semantic_cfg::{BoundaryKind, CallPolicy, CfgLimits, SemanticCfg, SemanticCfgError};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct SeedHit {
    pub address: u32,
    pub string_start: u32,
    pub string_len: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct SemanticRef {
    pub function: OwnedExecutionIdentity,
    pub pc: u32,
    pub address: u32,
}

#[derive(Clone, Copy)]
struct Occurrence {
    address: u32,
    range: ByteBackedRange,
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn find_unique_seed(
    runtime: &RuntimeImage<'_>,
    needle: &[u8],
) -> Result<Option<SeedHit>, StartupMetadataError> {
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
        _ => Err(StartupMetadataError::Ambiguous {
            values: hits.iter().map(|hit| hit.address).collect(),
        }),
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn semantic_refs(
    runtime: &RuntimeImage<'_>,
    inventories: &[TaggedExecutionRecord],
    string_start: u32,
) -> Result<Vec<SemanticRef>, StartupMetadataError> {
    let mut refs = Vec::new();
    for record in inventories {
        collect_semantic_refs(runtime, record, string_start, &mut refs)?;
    }
    Ok(refs)
}

fn collect_semantic_refs(
    runtime: &RuntimeImage<'_>,
    record: &TaggedExecutionRecord,
    string_start: u32,
    refs: &mut Vec<SemanticRef>,
) -> Result<(), StartupMetadataError> {
    let ExecutionProjection::Accepted(ranges) = &record.projection else {
        return Ok(());
    };
    let Some(first) = ranges.first() else {
        return Err(malformed("accepted execution has no decode range"));
    };
    let identity = execution_identity(record.entry, &record.projection)
        .map_err(|error| malformed(error.to_string()))?
        .ok_or_else(|| malformed("accepted execution identity is missing"))?;
    let window_end = ranges
        .iter()
        .map(|range| range.end)
        .max()
        .unwrap_or(first.end);
    let Some(span) = window_end.checked_sub(record.entry) else {
        return Ok(());
    };
    let cfg = match SemanticCfg::decode_with_address_window(
        runtime,
        record.entry,
        first.isa,
        CfgLimits::startup_metadata(),
        CallPolicy::Fallthrough,
        Some(span),
    ) {
        Ok(cfg) => cfg,
        Err(_) => return Ok(()),
    };
    let function = OwnedExecutionIdentity {
        owner: record.owner,
        identity,
    };
    let mut seen = BTreeSet::new();
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
            if !pc_in_ranges(pc, ranges) || !seen.insert(pc) {
                continue;
            }
            if refs.len() >= MAX_SEED_REFS {
                return Err(StartupMetadataError::ResourceLimit {
                    what: "seed refs",
                    actual: refs.len() as u64 + 1,
                    limit: MAX_SEED_REFS as u64,
                });
            }
            refs.push(SemanticRef {
                function: function.clone(),
                pc,
                address: string_start,
            });
        }
    }
    Ok(())
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

fn pc_in_ranges(pc: u32, ranges: &[AuthenticatedDecodeRange]) -> bool {
    ranges
        .iter()
        .any(|range| pc >= range.start && pc < range.end)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn prove_hardware_init(
    runtime: &RuntimeImage<'_>,
    inventories: &[TaggedExecutionRecord],
    reset: Option<(u32, DecodeIsa)>,
) -> Result<Section<HardwareInit>, StartupMetadataError> {
    let Some(seed) = find_unique_seed(runtime, SEED_WARM_BOOT)? else {
        return Ok(Section::Absent);
    };
    let Some(reset) = reset else {
        return Ok(Section::Absent);
    };
    let refs = semantic_refs(runtime, inventories, seed.string_start)?;
    if refs.is_empty() {
        return Ok(Section::Absent);
    }
    let containers: BTreeSet<(u32, DecodeIsa)> = refs
        .iter()
        .filter_map(|reference| {
            identity_isa(&reference.function).map(|isa| (reference.function.identity.entry, isa))
        })
        .collect();
    let visited = reachable_from_reset(runtime, inventories, reset, &containers)?;
    let mut survivors =
        unique_named_containers(refs.into_iter().map(|reference| reference.function).filter(
            |function| {
                identity_isa(function)
                    .is_some_and(|isa| visited.contains(&(function.identity.entry, isa)))
            },
        ));
    match survivors.len() {
        0 => Err(malformed("hardware_init is not reset-reachable")),
        1 => {
            let function = survivors.remove(0);
            let isa = identity_isa(&function)
                .ok_or_else(|| malformed("hardware_init identity has no decode range"))?;
            Ok(Section::Present(HardwareInit {
                entry: function.identity.entry,
                isa,
                owner: function.owner,
                execution_blake3: function.identity.execution_blake3,
            }))
        }
        _ => Err(StartupMetadataError::Ambiguous {
            values: survivors
                .iter()
                .map(|function| function.identity.entry)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        }),
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn prove_stack_guard(
    runtime: &RuntimeImage<'_>,
    inventories: &[TaggedExecutionRecord],
) -> Result<Section<StackGuard>, StartupMetadataError> {
    let Some(seed) = find_unique_seed(runtime, SEED_STACK_GUARD)? else {
        return Ok(Section::Absent);
    };
    let refs = semantic_refs(runtime, inventories, seed.string_start)?;
    if refs.is_empty() {
        return Ok(Section::Absent);
    }
    let mut containers =
        unique_named_containers(refs.into_iter().map(|reference| reference.function));
    match containers.len() {
        0 => Ok(Section::Absent),
        1 => {
            let function = containers.remove(0);
            let isa = identity_isa(&function)
                .ok_or_else(|| malformed("stack_guard identity has no decode range"))?;
            Ok(Section::Present(StackGuard {
                entry: function.identity.entry,
                isa,
                owner: function.owner,
                execution_blake3: function.identity.execution_blake3,
                non_return: stack_guard_non_return(runtime, &function),
            }))
        }
        _ => Err(StartupMetadataError::Ambiguous {
            values: containers
                .iter()
                .map(|function| function.identity.entry)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        }),
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn prove_compiler(
    runtime: &RuntimeImage<'_>,
    inventories: &[TaggedExecutionRecord],
) -> Result<Section<CompilerMeta>, StartupMetadataError> {
    let rvct = find_unique_seed(runtime, SEED_RVCT)?;
    find_unique_seed(runtime, SEED_SHANNON_OS)?;
    let Some(seed) = rvct else {
        return Ok(Section::Absent);
    };
    let mut sites = Vec::new();
    for record in inventories {
        collect_compiler_sites(runtime, record, seed.string_start, &mut sites)?;
    }
    sites.sort_by_key(|site| site.pc);
    let Some(first) = sites.first() else {
        return Ok(Section::Absent);
    };
    if sites.iter().any(|site| site.operands != first.operands) {
        return Err(StartupMetadataError::Ambiguous {
            values: sites.iter().map(|site| site.pc).collect(),
        });
    }
    if !first.operands.contains(&seed.string_start) {
        return Err(malformed("compiler callsite is missing the format pointer"));
    }
    let format_blake3 = runtime
        .hash_range(seed.string_start, seed.string_len)
        .map_err(|error| runtime_error(seed.string_start, seed.string_len, error))?;
    Ok(Section::Present(CompilerMeta {
        format_address: seed.string_start,
        format_len: seed.string_len,
        format_blake3,
        callsite_pc: first.pc,
        isa: first.isa,
        operands: first.operands.clone(),
    }))
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn sweep_privileged_ops(
    runtime: &RuntimeImage<'_>,
    inventories: &[TaggedExecutionRecord],
) -> Result<Vec<PrivilegedOp>, StartupMetadataError> {
    let mut ops = Vec::new();
    for record in inventories {
        collect_privileged_ops(runtime, record, &mut ops)?;
    }
    Ok(ops)
}

pub(crate) fn discover(
    runtime: &RuntimeImage<'_>,
    label: &str,
    toc_name: &str,
    inventories: &[TaggedExecutionRecord],
    reset: Option<(u32, DecodeIsa)>,
) -> Result<StartupPlan, StartupMetadataError> {
    let hardware_init = prove_hardware_init(runtime, inventories, reset)?;
    let stack_guard = prove_stack_guard(runtime, inventories)?;
    let compiler = prove_compiler(runtime, inventories)?;
    let privileged_ops = sweep_privileged_ops(runtime, inventories)?;
    let applications = allocate_applications(&hardware_init, &stack_guard)?;
    let (image_base, image_size) = runtime.image_bounds();
    Ok(StartupPlan {
        image_label: label.to_owned(),
        toc_name: toc_name.to_owned(),
        image_base,
        image_size,
        hardware_init,
        stack_guard,
        compiler,
        privileged_ops,
        applications,
    })
}

fn allocate_applications(
    hardware_init: &Section<HardwareInit>,
    stack_guard: &Section<StackGuard>,
) -> Result<Vec<StartupApplication>, StartupMetadataError> {
    let mut applications = Vec::with_capacity(MAX_APPLICATIONS);
    if let Section::Present(hw) = hardware_init {
        applications.push(StartupApplication {
            role: StartupRole::HardwareInit,
            entry: hw.entry,
            isa: hw.isa,
            desired_primary: StartupRole::HardwareInit.desired_primary(),
            role_label: StartupRole::HardwareInit.role_label(),
            set_no_return: false,
        });
    }
    if let Section::Present(guard) = stack_guard {
        if applications
            .iter()
            .any(|application| application.entry == guard.entry && application.isa == guard.isa)
        {
            return Err(malformed(format!(
                "hardware_init and stack_guard share entry {:#010x}",
                guard.entry
            )));
        }
        applications.push(StartupApplication {
            role: StartupRole::StackGuard,
            entry: guard.entry,
            isa: guard.isa,
            desired_primary: StartupRole::StackGuard.desired_primary(),
            role_label: StartupRole::StackGuard.role_label(),
            set_no_return: guard.non_return,
        });
    }
    Ok(applications)
}

fn collect_privileged_ops(
    runtime: &RuntimeImage<'_>,
    record: &TaggedExecutionRecord,
    ops: &mut Vec<PrivilegedOp>,
) -> Result<(), StartupMetadataError> {
    let ExecutionProjection::Accepted(ranges) = &record.projection else {
        return Ok(());
    };
    if ranges.is_empty() {
        return Err(malformed("accepted execution has no decode range"));
    }
    let identity = execution_identity(record.entry, &record.projection)
        .map_err(|error| malformed(error.to_string()))?
        .ok_or_else(|| malformed("accepted execution identity is missing"))?;
    for range in ranges {
        sweep_range(runtime, record, identity.execution_blake3, range, ops)?;
    }
    Ok(())
}

fn sweep_range(
    runtime: &RuntimeImage<'_>,
    record: &TaggedExecutionRecord,
    execution_blake3: [u8; 32],
    range: &AuthenticatedDecodeRange,
    ops: &mut Vec<PrivilegedOp>,
) -> Result<(), StartupMetadataError> {
    let decoder = PureRustDecoder;
    let mut state = decoder.begin_range(range.isa);
    let mut pc = range.start;
    while pc < range.end {
        let Some(fetch) = fetch_len(runtime, range, pc)? else {
            break;
        };
        let bytes = runtime
            .read_exact(pc, fetch as usize)
            .map_err(|error| runtime_error(pc, fetch, error))?;
        match decoder.decode_one(&mut state, range.isa, pc, &bytes) {
            Ok(instruction) => {
                check_adapter_invariants(range, pc, &instruction)?;
                let length = u32::from(instruction.length);
                let next = pc.checked_add(length).ok_or_else(|| {
                    decode_error(pc, range.isa, "instruction length overflows u32")
                })?;
                if next <= pc {
                    return Err(decode_error(pc, range.isa, "decoded PC regressed"));
                }
                if next > range.end {
                    return Err(decode_error(
                        pc,
                        range.isa,
                        "instruction extent leaves the decode range",
                    ));
                }
                push_privileged_op(ops, record, execution_blake3, &instruction)?;
                pc = next;
            }
            Err(_) => {
                let next = pc.checked_add(fetch).ok_or_else(|| {
                    decode_error(pc, range.isa, "unrecognized encoding skip overflows u32")
                })?;
                pc = next.min(range.end);
            }
        }
    }
    Ok(())
}

fn fetch_len(
    runtime: &RuntimeImage<'_>,
    range: &AuthenticatedDecodeRange,
    pc: u32,
) -> Result<Option<u32>, StartupMetadataError> {
    let remaining = range.end.saturating_sub(pc);
    match range.isa {
        DecodeIsa::Arm => {
            if remaining < 4 {
                return Ok(None);
            }
            Ok(Some(4))
        }
        DecodeIsa::Thumb => {
            if remaining < 2 {
                return Ok(None);
            }
            let halfword = runtime
                .read_u16(pc)
                .map_err(|error| runtime_error(pc, 2, error))?;
            let wide = matches!(halfword >> 11, 0b11101..=0b11111);
            if wide && remaining < 4 {
                return Ok(None);
            }
            Ok(Some(if wide { 4 } else { 2 }))
        }
    }
}

fn check_adapter_invariants(
    range: &AuthenticatedDecodeRange,
    pc: u32,
    instruction: &crate::arm32::DecodedInstruction,
) -> Result<(), StartupMetadataError> {
    if instruction.isa != range.isa {
        return Err(decode_error(
            pc,
            range.isa,
            "decoder returned an ISA other than the range ISA",
        ));
    }
    if instruction.pc != pc {
        return Err(decode_error(
            pc,
            range.isa,
            "decoder returned a different PC",
        ));
    }
    if instruction.length == 0 || !valid_isa_length(instruction.isa, instruction.length) {
        return Err(decode_error(
            pc,
            range.isa,
            "decoder returned an impossible instruction length",
        ));
    }
    Ok(())
}

fn push_privileged_op(
    ops: &mut Vec<PrivilegedOp>,
    record: &TaggedExecutionRecord,
    execution_blake3: [u8; 32],
    instruction: &crate::arm32::DecodedInstruction,
) -> Result<(), StartupMetadataError> {
    let op = match instruction.system {
        SystemEffect::CoprocessorTransfer(transfer) if transfer.coprocessor == 15 => PrivilegedOp {
            pc: instruction.pc,
            isa: instruction.isa,
            entry: record.entry,
            owner: record.owner,
            execution_blake3,
            direction: transfer.direction,
            class: classify_p15(transfer),
            coprocessor: Some(transfer.coprocessor),
            opcode1: Some(transfer.opcode1),
            crn: Some(transfer.crn),
            crm: Some(transfer.crm),
            opcode2: Some(transfer.opcode2),
            register: None,
            immediate: None,
        },
        SystemEffect::PsrTransfer {
            direction,
            register,
            mask,
            immediate,
        } => PrivilegedOp {
            pc: instruction.pc,
            isa: instruction.isa,
            entry: record.entry,
            owner: record.owner,
            execution_blake3,
            direction,
            class: PrivilegedClass::CpsrSpsr,
            coprocessor: None,
            opcode1: Some(mask),
            crn: None,
            crm: None,
            opcode2: None,
            register: register.map(|register| register.0),
            immediate,
        },
        SystemEffect::None | SystemEffect::CoprocessorTransfer(_) => return Ok(()),
    };
    if ops.len() >= MAX_PRIVILEGED_OPS {
        return Err(StartupMetadataError::ResourceLimit {
            what: "privileged ops",
            actual: ops.len() as u64 + 1,
            limit: MAX_PRIVILEGED_OPS as u64,
        });
    }
    ops.push(op);
    Ok(())
}

fn classify_p15(transfer: CoprocessorTransfer) -> PrivilegedClass {
    if transfer.is_vbar_write()
        || (transfer.direction == SystemDirection::Read
            && transfer.coprocessor == 15
            && transfer.opcode1 == 0
            && transfer.crn == 12
            && transfer.crm == 0
            && transfer.opcode2 == 0
            && !transfer.unconditional_extension)
    {
        return PrivilegedClass::Vbar;
    }
    if transfer.unconditional_extension {
        return PrivilegedClass::Unclassified;
    }
    match (
        transfer.opcode1,
        transfer.crn,
        transfer.crm,
        transfer.opcode2,
    ) {
        (0, 0, 0, 0) => PrivilegedClass::Midr,
        (_, 0, _, _) => PrivilegedClass::Features,
        (0, 1, 0, 0) | (4, 1, 0, 0) => PrivilegedClass::Sctlr,
        (0, 2, 0, 0) | (0, 2, 0, 1) => PrivilegedClass::Ttbr,
        (0, 2, 0, 2) => PrivilegedClass::Ttbcr,
        (0, 3, 0, 0) => PrivilegedClass::Dacr,
        (_, 5, _, _) | (_, 6, _, _) => PrivilegedClass::Fault,
        (_, 7, _, _) | (_, 8, _, _) => PrivilegedClass::CacheTlb,
        (_, 9, _, _) => PrivilegedClass::Pmu,
        (_, 13, _, _) => PrivilegedClass::ContextId,
        _ => PrivilegedClass::Unclassified,
    }
}

fn decode_error(pc: u32, isa: DecodeIsa, reason: &str) -> StartupMetadataError {
    StartupMetadataError::Decode {
        pc,
        isa,
        reason: reason.to_owned(),
    }
}

struct CompilerSite {
    pc: u32,
    isa: DecodeIsa,
    operands: Vec<u32>,
}

fn collect_compiler_sites(
    runtime: &RuntimeImage<'_>,
    record: &TaggedExecutionRecord,
    string_start: u32,
    sites: &mut Vec<CompilerSite>,
) -> Result<(), StartupMetadataError> {
    let ExecutionProjection::Accepted(_) = &record.projection else {
        return Ok(());
    };
    let Some(isa) = first_isa(record) else {
        return Err(malformed("accepted execution has no decode range"));
    };
    let window = identity_window(record)?;
    let cfg = match SemanticCfg::decode_with_address_window(
        runtime,
        record.entry,
        isa,
        CfgLimits::startup_metadata(),
        CallPolicy::Fallthrough,
        window,
    ) {
        Ok(cfg) => cfg,
        Err(_) => return Ok(()),
    };
    for pc in cfg.reachable() {
        let Some(instruction) = cfg.instructions().get(pc) else {
            continue;
        };
        if !matches!(instruction.flow, ControlFlow::DirectCall { .. }) {
            continue;
        }
        let Some(state) = cfg.exact_register_states().get(pc) else {
            continue;
        };
        let mut operands = Vec::new();
        for index in 0..4u8 {
            let Some(value) = state.get(Register(index)) else {
                continue;
            };
            operands.push(value.value);
        }
        if !operands.contains(&string_start) {
            continue;
        }
        if sites.len() >= MAX_SEED_REFS {
            return Err(StartupMetadataError::ResourceLimit {
                what: "seed refs",
                actual: sites.len() as u64 + 1,
                limit: MAX_SEED_REFS as u64,
            });
        }
        sites.push(CompilerSite {
            pc: *pc,
            isa,
            operands,
        });
    }
    Ok(())
}

fn stack_guard_non_return(runtime: &RuntimeImage<'_>, function: &OwnedExecutionIdentity) -> bool {
    let Some(isa) = identity_isa(function) else {
        return false;
    };
    let ranges = &function.identity.decode_ranges;
    let Some(first) = ranges.first() else {
        return false;
    };
    let window_end = ranges
        .iter()
        .map(|range| range.end)
        .max()
        .unwrap_or(first.end);
    let Some(span) = window_end.checked_sub(function.identity.entry) else {
        return false;
    };
    let Ok(cfg) = SemanticCfg::decode_with_address_window(
        runtime,
        function.identity.entry,
        isa,
        CfgLimits::startup_metadata(),
        CallPolicy::Fallthrough,
        Some(span),
    ) else {
        return false;
    };
    if cfg.handoffs().iter().any(|handoff| {
        matches!(
            handoff.kind,
            BoundaryKind::Indirect | BoundaryKind::DecodeFailure | BoundaryKind::Unmapped
        )
    }) {
        return false;
    }
    !cfg.instructions()
        .values()
        .any(|instruction| matches!(instruction.flow, ControlFlow::Return))
}

fn reachable_from_reset(
    runtime: &RuntimeImage<'_>,
    inventories: &[TaggedExecutionRecord],
    reset: (u32, DecodeIsa),
    containers: &BTreeSet<(u32, DecodeIsa)>,
) -> Result<BTreeSet<(u32, DecodeIsa)>, StartupMetadataError> {
    let mut visited = BTreeSet::new();
    let mut queue = VecDeque::new();
    enqueue_callgraph_node(&mut visited, &mut queue, reset.0, reset.1, 0)?;
    while let Some((entry, isa, depth)) = queue.pop_front() {
        if callgraph_decided(&visited, containers) {
            break;
        }
        let cfg = decode_callgraph_cfg(runtime, inventories, entry, isa)?;
        for target in callee_targets(&cfg) {
            if callgraph_decided(&visited, containers) {
                break;
            }
            let Some(callee) = resolve_accepted(inventories, target, isa) else {
                continue;
            };
            let Some(callee_isa) = first_isa(callee) else {
                continue;
            };
            enqueue_callgraph_node(
                &mut visited,
                &mut queue,
                callee.entry,
                callee_isa,
                depth + 1,
            )?;
        }
    }
    Ok(visited)
}

fn callgraph_decided(
    visited: &BTreeSet<(u32, DecodeIsa)>,
    containers: &BTreeSet<(u32, DecodeIsa)>,
) -> bool {
    let mut survivors = 0usize;
    for container in containers {
        if !visited.contains(container) {
            continue;
        }
        survivors += 1;
        if survivors >= 2 {
            return true;
        }
    }
    survivors == containers.len()
}

fn enqueue_callgraph_node(
    visited: &mut BTreeSet<(u32, DecodeIsa)>,
    queue: &mut VecDeque<(u32, DecodeIsa, usize)>,
    entry: u32,
    isa: DecodeIsa,
    depth: usize,
) -> Result<(), StartupMetadataError> {
    if depth > MAX_CALLGRAPH_DEPTH {
        return Err(StartupMetadataError::ResourceLimit {
            what: "callgraph depth",
            actual: depth as u64,
            limit: MAX_CALLGRAPH_DEPTH as u64,
        });
    }
    if visited.contains(&(entry, isa)) {
        return Ok(());
    }
    if visited.len() >= MAX_CALLGRAPH_FUNCTIONS {
        return Err(StartupMetadataError::ResourceLimit {
            what: "callgraph functions",
            actual: visited.len() as u64 + 1,
            limit: MAX_CALLGRAPH_FUNCTIONS as u64,
        });
    }
    visited.insert((entry, isa));
    queue.push_back((entry, isa, depth));
    Ok(())
}

fn decode_callgraph_cfg(
    runtime: &RuntimeImage<'_>,
    inventories: &[TaggedExecutionRecord],
    entry: u32,
    isa: DecodeIsa,
) -> Result<SemanticCfg, StartupMetadataError> {
    let window = match resolve_accepted(inventories, entry, isa) {
        Some(record) => identity_window(record)?,
        None => None,
    };
    SemanticCfg::decode_with_address_window(
        runtime,
        entry,
        isa,
        CfgLimits::startup_metadata(),
        CallPolicy::FallthroughAndHandoff,
        window,
    )
    .map_err(|error| cfg_error(error, isa))
}

fn identity_window(record: &TaggedExecutionRecord) -> Result<Option<u32>, StartupMetadataError> {
    let ExecutionProjection::Accepted(ranges) = &record.projection else {
        return Ok(None);
    };
    let Some(first) = ranges.first() else {
        return Err(malformed("accepted execution has no decode range"));
    };
    let window_end = ranges
        .iter()
        .map(|range| range.end)
        .max()
        .unwrap_or(first.end);
    window_end
        .checked_sub(record.entry)
        .ok_or_else(|| malformed("accepted execution window wraps the address space"))
        .map(Some)
}

fn callee_targets(cfg: &SemanticCfg) -> BTreeSet<u32> {
    let mut targets = BTreeSet::new();
    for pc in cfg.reachable() {
        let Some(instruction) = cfg.instructions().get(pc) else {
            continue;
        };
        if let ControlFlow::DirectCall { target } = instruction.flow {
            targets.insert(target);
        }
    }
    targets
}

fn resolve_accepted(
    inventories: &[TaggedExecutionRecord],
    target: u32,
    isa: DecodeIsa,
) -> Option<&TaggedExecutionRecord> {
    inventories
        .iter()
        .filter(|record| record.entry == target && first_isa(record) == Some(isa))
        .min_by_key(|record| record.owner)
}

fn first_isa(record: &TaggedExecutionRecord) -> Option<DecodeIsa> {
    match &record.projection {
        ExecutionProjection::Accepted(ranges) => ranges.first().map(|range| range.isa),
        ExecutionProjection::Quarantined(_) => None,
    }
}

fn identity_isa(function: &OwnedExecutionIdentity) -> Option<DecodeIsa> {
    function
        .identity
        .decode_ranges
        .first()
        .map(|range| range.isa)
}

fn unique_named_containers(
    functions: impl IntoIterator<Item = OwnedExecutionIdentity>,
) -> Vec<OwnedExecutionIdentity> {
    let mut by_key = BTreeMap::<(u32, DecodeIsa), OwnedExecutionIdentity>::new();
    for function in functions {
        let Some(isa) = identity_isa(&function) else {
            continue;
        };
        let key = (function.identity.entry, isa);
        match by_key.entry(key) {
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(function);
            }
            std::collections::btree_map::Entry::Occupied(mut slot) => {
                if function.owner < slot.get().owner {
                    slot.insert(function);
                }
            }
        }
    }
    by_key.into_values().collect()
}

fn cfg_error(error: SemanticCfgError, isa: DecodeIsa) -> StartupMetadataError {
    match error {
        SemanticCfgError::Decode { pc, reason } => StartupMetadataError::Decode { pc, isa, reason },
        SemanticCfgError::Runtime {
            address,
            size,
            reason,
        } => StartupMetadataError::Runtime {
            address,
            size,
            reason,
        },
        SemanticCfgError::InvalidFlow { pc, reason } => {
            malformed(format!("callgraph flow at {pc:#010x} is invalid: {reason}"))
        }
        SemanticCfgError::ResourceLimit {
            what,
            actual,
            limit,
        } => StartupMetadataError::ResourceLimit {
            what,
            actual,
            limit,
        },
    }
}

fn collect_hits(
    runtime: &RuntimeImage<'_>,
    needle: &[u8],
    range: ByteBackedRange,
    hits: &mut Vec<Occurrence>,
) -> Result<(), StartupMetadataError> {
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
) -> Result<SeedHit, StartupMetadataError> {
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

fn malformed(context: impl Into<String>) -> StartupMetadataError {
    StartupMetadataError::Malformed {
        context: context.into(),
    }
}

fn runtime_error(address: u32, size: u32, error: crate::error::Error) -> StartupMetadataError {
    StartupMetadataError::Runtime {
        address,
        size,
        reason: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SeedHit, SemanticRef, discover, find_unique_seed, prove_compiler, prove_hardware_init,
        prove_stack_guard, semantic_refs, sweep_privileged_ops,
    };
    use crate::analysis_tool::AnalysisTool;
    use crate::arm32::SystemDirection;
    use crate::execution_ranges::{
        AuthenticatedDecodeRange, DecodeIsa, DecodeRangeError, DecodeRangeErrorKind,
        ExecutionProjection, FunctionOwner, OwnedExecutionIdentity, TaggedExecutionRecord,
        execution_identity,
    };
    use crate::runtime_image::RuntimeImage;
    use crate::startup_metadata::{
        CompilerMeta, HardwareInit, MAX_CALLGRAPH_DEPTH, MAX_CSTRING_BYTES, MAX_PRIVILEGED_OPS,
        MAX_SEED_REFS, PrivilegedClass, PrivilegedOp, SEED_RVCT, SEED_SHANNON_OS, SEED_STACK_GUARD,
        SEED_WARM_BOOT, Section, StackGuard, StartupMetadataError,
    };

    const BASE: u32 = 0x4001_0000;

    fn runtime(raw: &[u8]) -> RuntimeImage<'_> {
        RuntimeImage::from_plan(raw, BASE, None).expect("raw fixture runtime")
    }

    #[test]
    fn unique_seed_is_present_and_duplicate_is_ambiguous() {
        let mut unique = SEED_WARM_BOOT.to_vec();
        unique.push(0);
        let hit = find_unique_seed(&runtime(&unique), SEED_WARM_BOOT)
            .expect("unique seed")
            .expect("present");
        assert_eq!(
            hit,
            SeedHit {
                address: BASE,
                string_start: BASE,
                string_len: 18,
            }
        );

        let mut prefixed = b"pre\t".to_vec();
        prefixed.extend_from_slice(SEED_WARM_BOOT);
        prefixed.push(0);
        let hit = find_unique_seed(&runtime(&prefixed), SEED_WARM_BOOT)
            .expect("unique prefixed seed")
            .expect("present");
        assert_eq!(
            hit,
            SeedHit {
                address: BASE + 4,
                string_start: BASE,
                string_len: 22,
            }
        );

        let mut after_nul = b"xx\0".to_vec();
        after_nul.extend_from_slice(SEED_WARM_BOOT);
        after_nul.push(0);
        let hit = find_unique_seed(&runtime(&after_nul), SEED_WARM_BOOT)
            .expect("unique seed after NUL")
            .expect("present");
        assert_eq!(
            hit,
            SeedHit {
                address: BASE + 3,
                string_start: BASE + 3,
                string_len: 18,
            }
        );

        let mut duplicate = unique.clone();
        duplicate.extend_from_slice(&unique);
        match find_unique_seed(&runtime(&duplicate), SEED_WARM_BOOT) {
            Err(StartupMetadataError::Ambiguous { values }) => {
                assert_eq!(values, vec![BASE, BASE + 18]);
            }
            other => panic!("expected Ambiguous, got {other:?}"),
        }

        let absent = [0u8; 64];
        assert_eq!(
            find_unique_seed(&runtime(&absent), SEED_WARM_BOOT).expect("zero occurrences"),
            None
        );
    }

    #[test]
    fn unterminated_or_nonprintable_unique_hit_is_malformed() {
        let mut unterminated = SEED_WARM_BOOT.to_vec();
        unterminated.resize(MAX_CSTRING_BYTES, b'A');
        assert!(matches!(
            find_unique_seed(&runtime(&unterminated), SEED_WARM_BOOT),
            Err(StartupMetadataError::Malformed { .. })
        ));

        let mut over_cap = SEED_WARM_BOOT.to_vec();
        over_cap.resize(MAX_CSTRING_BYTES, b'A');
        over_cap.push(0);
        assert!(matches!(
            find_unique_seed(&runtime(&over_cap), SEED_WARM_BOOT),
            Err(StartupMetadataError::Malformed { .. })
        ));

        let mut nonprintable = SEED_WARM_BOOT.to_vec();
        nonprintable.push(0x01);
        nonprintable.push(0);
        assert!(matches!(
            find_unique_seed(&runtime(&nonprintable), SEED_WARM_BOOT),
            Err(StartupMetadataError::Malformed { .. })
        ));
    }

    #[test]
    fn unique_seed_after_thumb_padding_starts_at_the_needle() {
        let mut image = vec![0u8, 0xbf];
        image.extend_from_slice(SEED_STACK_GUARD);
        image.extend_from_slice(b" (0x%08x)\0");
        let hit = find_unique_seed(&runtime(&image), SEED_STACK_GUARD)
            .expect("unique seed")
            .expect("present");
        assert_eq!(hit.address, BASE + 2);
        assert_eq!(hit.string_start, BASE + 2);
        assert_eq!(
            hit.string_len,
            (SEED_STACK_GUARD.len() + b" (0x%08x)\0".len()) as u32
        );
    }

    #[test]
    fn unique_seed_inside_newline_terminated_format_string_is_present() {
        let mut image = b"Version    : ".to_vec();
        image.extend_from_slice(SEED_RVCT);
        image.extend_from_slice(b" %d.%d [Build %d]\n\0");
        let hit = find_unique_seed(&runtime(&image), SEED_RVCT)
            .expect("unique seed")
            .expect("present");
        assert_eq!(hit.address, BASE + 13);
        assert_eq!(hit.string_start, BASE);
        assert_eq!(hit.string_len, image.len() as u32);
    }

    const A32_ADD_R0_PC_8: [u8; 4] = [0x08, 0x00, 0x8f, 0xe2];
    const A32_BX_LR: [u8; 4] = [0x1e, 0xff, 0x2f, 0xe1];

    fn plant_cstr(image: &mut [u8], offset: usize, needle: &[u8]) -> u32 {
        image[offset..offset + needle.len()].copy_from_slice(needle);
        image[offset + needle.len()] = 0;
        BASE + offset as u32
    }

    fn plant_seed(image: &mut [u8], offset: usize) -> u32 {
        plant_cstr(image, offset, SEED_WARM_BOOT)
    }

    fn accepted_arm(runtime: &RuntimeImage<'_>, entry: u32, end: u32) -> TaggedExecutionRecord {
        accepted_record(runtime, entry, end, DecodeIsa::Arm)
    }

    fn accepted_thumb(runtime: &RuntimeImage<'_>, entry: u32, end: u32) -> TaggedExecutionRecord {
        accepted_record(runtime, entry, end, DecodeIsa::Thumb)
    }

    fn accepted_record(
        runtime: &RuntimeImage<'_>,
        entry: u32,
        end: u32,
        isa: DecodeIsa,
    ) -> TaggedExecutionRecord {
        let size = end - entry;
        TaggedExecutionRecord {
            owner: FunctionOwner::Ghidra,
            entry,
            projection: ExecutionProjection::Accepted(vec![AuthenticatedDecodeRange {
                isa,
                start: entry,
                end,
                blake3: runtime.hash_range(entry, size).expect("range hash"),
            }]),
        }
    }

    fn with_owner(
        mut record: TaggedExecutionRecord,
        owner: FunctionOwner,
    ) -> TaggedExecutionRecord {
        record.owner = owner;
        record
    }

    fn radare2_run_owner() -> FunctionOwner {
        FunctionOwner::Run {
            producer: AnalysisTool::Radare2,
            region_index: 0,
            run_index: 0,
        }
    }

    fn quarantined_arm(entry: u32) -> TaggedExecutionRecord {
        TaggedExecutionRecord {
            owner: FunctionOwner::Ghidra,
            entry,
            projection: ExecutionProjection::Quarantined(vec![DecodeRangeError {
                kind: DecodeRangeErrorKind::EmptyProjection,
                address: entry,
                end: None,
            }]),
        }
    }

    fn owned_identity(record: &TaggedExecutionRecord) -> OwnedExecutionIdentity {
        OwnedExecutionIdentity {
            owner: record.owner,
            identity: execution_identity(record.entry, &record.projection)
                .expect("accepted identity")
                .expect("accepted projection"),
        }
    }

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

    fn a32_bl(pc: u32, target: u32) -> [u8; 4] {
        let offset = target.wrapping_sub(pc.wrapping_add(8));
        (0xeb00_0000 | ((offset >> 2) & 0x00ff_ffff)).to_le_bytes()
    }

    fn a32_b(pc: u32, target: u32) -> [u8; 4] {
        let offset = target.wrapping_sub(pc.wrapping_add(8));
        (0xea00_0000 | ((offset >> 2) & 0x00ff_ffff)).to_le_bytes()
    }

    fn plant_movw_movt_seed(image: &mut [u8], entry_off: usize, string_start: u32) {
        let low = (string_start & 0xffff) as u16;
        let high = (string_start >> 16) as u16;
        image[entry_off..entry_off + 4].copy_from_slice(&a32_movw(0, low));
        image[entry_off + 4..entry_off + 8].copy_from_slice(&a32_movt(0, high));
        image[entry_off + 8..entry_off + 12].copy_from_slice(&A32_BX_LR);
    }

    fn plant_dual_seed_loads(image: &mut [u8], entry_off: usize, warm: u32, stack: u32) {
        image[entry_off..entry_off + 4].copy_from_slice(&a32_movw(0, (warm & 0xffff) as u16));
        image[entry_off + 4..entry_off + 8].copy_from_slice(&a32_movt(0, (warm >> 16) as u16));
        image[entry_off + 8..entry_off + 12].copy_from_slice(&a32_movw(1, (stack & 0xffff) as u16));
        image[entry_off + 12..entry_off + 16].copy_from_slice(&a32_movt(1, (stack >> 16) as u16));
        image[entry_off + 16..entry_off + 20].copy_from_slice(&A32_BX_LR);
    }

    #[test]
    fn adr_materialization_inside_accepted_execution_is_a_ref() {
        let mut image = vec![0u8; 0x30];
        image[0..4].copy_from_slice(&A32_ADD_R0_PC_8);
        image[4..8].copy_from_slice(&A32_BX_LR);
        let string_start = plant_seed(&mut image, 0x10);
        let runtime = runtime(&image);
        let seed = find_unique_seed(&runtime, SEED_WARM_BOOT)
            .expect("unique seed")
            .expect("present");
        assert_eq!(seed.string_start, string_start);

        let accepted = accepted_arm(&runtime, BASE, BASE + 8);
        let expected = SemanticRef {
            function: owned_identity(&accepted),
            pc: BASE,
            address: string_start,
        };
        assert_eq!(
            semantic_refs(&runtime, &[quarantined_arm(BASE)], string_start)
                .expect("quarantined only"),
            []
        );
        let refs = semantic_refs(&runtime, &[quarantined_arm(BASE), accepted], string_start)
            .expect("accepted plus quarantined sibling");
        assert_eq!(refs, [expected]);
    }

    #[test]
    fn add_immediate_after_movw_movt_is_not_a_ref() {
        let mut image = vec![0u8; 0x40];
        let string_start = plant_seed(&mut image, 0x20);
        plant_movw_movt_seed(&mut image, 0, string_start.wrapping_sub(4));
        image[8..12].copy_from_slice(&0xe280_0004u32.to_le_bytes());
        image[12..16].copy_from_slice(&A32_BX_LR);
        let runtime = runtime(&image);
        let accepted = accepted_arm(&runtime, BASE, BASE + 16);
        assert_eq!(
            semantic_refs(&runtime, &[accepted], string_start)
                .expect("ADD is not a PAL materialization"),
            []
        );
    }

    #[test]
    fn more_than_max_seed_refs_is_resource_limit() {
        const FN_LEN: u32 = 12;
        const COUNT: usize = MAX_SEED_REFS + 1;
        let seed_off = 0x400usize;
        let mut image = vec![0u8; seed_off + 32];
        let string_start = plant_seed(&mut image, seed_off);
        let low = (string_start & 0xffff) as u16;
        let high = (string_start >> 16) as u16;
        for index in 0..COUNT {
            let offset = index * FN_LEN as usize;
            image[offset..offset + 4].copy_from_slice(&a32_movw(0, low));
            image[offset + 4..offset + 8].copy_from_slice(&a32_movt(0, high));
            image[offset + 8..offset + 12].copy_from_slice(&A32_BX_LR);
        }
        let runtime = runtime(&image);
        let seed = find_unique_seed(&runtime, SEED_WARM_BOOT)
            .expect("unique seed")
            .expect("present");
        assert_eq!(seed.string_start, string_start);

        let records: Vec<_> = (0..COUNT)
            .map(|index| {
                let entry = BASE + index as u32 * FN_LEN;
                accepted_arm(&runtime, entry, entry + FN_LEN)
            })
            .collect();
        let at_limit =
            semantic_refs(&runtime, &records[..MAX_SEED_REFS], string_start).expect("64 refs fit");
        assert_eq!(at_limit.len(), MAX_SEED_REFS);
        match semantic_refs(&runtime, &records, string_start) {
            Err(StartupMetadataError::ResourceLimit {
                what,
                actual,
                limit,
            }) => {
                assert_eq!(what, "seed refs");
                assert_eq!(actual, COUNT as u64);
                assert_eq!(limit, MAX_SEED_REFS as u64);
            }
            other => panic!("expected ResourceLimit, got {other:?}"),
        }
    }

    #[test]
    fn cfg_failure_of_one_identity_does_not_drop_other_refs() {
        let mut image = vec![0u8; 0x40];
        image[0..4].copy_from_slice(&A32_ADD_R0_PC_8);
        image[4..8].copy_from_slice(&A32_BX_LR);
        let string_start = plant_seed(&mut image, 0x10);
        image[0x30..0x32].copy_from_slice(&[0x08, 0xbf]);
        let runtime = runtime(&image);
        let accepted = accepted_arm(&runtime, BASE, BASE + 8);
        let expected = SemanticRef {
            function: owned_identity(&accepted),
            pc: BASE,
            address: string_start,
        };
        let it = accepted_thumb(&runtime, BASE + 0x30, BASE + 0x32);
        let refs = semantic_refs(&runtime, &[it, accepted], string_start)
            .expect("IT identity is skipped, not fatal");
        assert_eq!(refs, [expected]);
    }

    #[test]
    fn cfg_resource_limit_during_refs_skips_the_function() {
        const SPAN: usize = 64 * 1024 + 4;
        let mut image = vec![0u8; SPAN + 32];
        for chunk in image[..SPAN].as_chunks_mut::<4>().0 {
            chunk.copy_from_slice(&0xe1a0_0000u32.to_le_bytes());
        }
        let string_start = plant_seed(&mut image, SPAN);
        let runtime = runtime(&image);
        let record = accepted_arm(&runtime, BASE, BASE + SPAN as u32);
        assert_eq!(
            semantic_refs(&runtime, std::slice::from_ref(&record), string_start)
                .expect("oversized CFG is skipped"),
            []
        );
        assert_eq!(
            prove_hardware_init(
                &runtime,
                std::slice::from_ref(&record),
                Some((BASE, DecodeIsa::Arm))
            )
            .expect("only oversized ref is absence"),
            Section::Absent
        );
    }

    #[test]
    fn cfg_resource_limit_during_refs_does_not_drop_other_refs() {
        const SPAN: usize = 64 * 1024 + 4;
        let mut image = vec![0u8; SPAN + 0x40];
        for chunk in image[..SPAN].as_chunks_mut::<4>().0 {
            chunk.copy_from_slice(&0xe1a0_0000u32.to_le_bytes());
        }
        let hw_off = SPAN;
        image[hw_off..hw_off + 4].copy_from_slice(&A32_ADD_R0_PC_8);
        image[hw_off + 4..hw_off + 8].copy_from_slice(&A32_BX_LR);
        let string_start = plant_seed(&mut image, hw_off + 0x10);
        let runtime = runtime(&image);
        let huge = accepted_arm(&runtime, BASE, BASE + SPAN as u32);
        let hw = accepted_arm(&runtime, BASE + hw_off as u32, BASE + hw_off as u32 + 8);
        let refs = semantic_refs(&runtime, &[huge, hw], string_start)
            .expect("oversized sibling is skipped");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].function.identity.entry, BASE + hw_off as u32);
    }

    #[test]
    fn branch_out_of_authenticated_range_does_not_claim_foreign_adr() {
        let mut image = vec![0u8; 0x50];
        image[0..4].copy_from_slice(&0xea00_0006u32.to_le_bytes());
        image[0x20..0x24].copy_from_slice(&A32_ADD_R0_PC_8);
        image[0x24..0x28].copy_from_slice(&A32_BX_LR);
        let string_start = plant_seed(&mut image, 0x30);
        let runtime = runtime(&image);
        assert_eq!(
            semantic_refs(
                &runtime,
                &[accepted_arm(&runtime, BASE, BASE + 4)],
                string_start
            )
            .expect("brancher only"),
            []
        );
        let brancher = accepted_arm(&runtime, BASE, BASE + 4);
        let foreign = accepted_arm(&runtime, BASE + 0x20, BASE + 0x28);
        let expected = SemanticRef {
            function: owned_identity(&foreign),
            pc: BASE + 0x20,
            address: string_start,
        };
        let refs = semantic_refs(&runtime, &[brancher, foreign], string_start)
            .expect("foreign ADR stays on its identity");
        assert_eq!(refs, [expected]);
    }

    #[test]
    fn hw_init_absent_without_reset_root_even_with_unique_ref() {
        let mut image = vec![0u8; 0x30];
        image[0..4].copy_from_slice(&A32_ADD_R0_PC_8);
        image[4..8].copy_from_slice(&A32_BX_LR);
        let string_start = plant_seed(&mut image, 0x10);
        let runtime = runtime(&image);
        let seed = find_unique_seed(&runtime, SEED_WARM_BOOT)
            .expect("unique seed")
            .expect("present");
        assert_eq!(seed.string_start, string_start);
        let hw = accepted_arm(&runtime, BASE, BASE + 8);
        assert_eq!(
            semantic_refs(&runtime, std::slice::from_ref(&hw), string_start)
                .expect("unique ref")
                .len(),
            1
        );
        assert_eq!(
            prove_hardware_init(&runtime, &[hw], None).expect("no reset is absence"),
            Section::Absent
        );
    }

    #[test]
    fn hw_init_present_when_unique_ref_is_reset_reachable() {
        let mut image = vec![0u8; 0x40];
        image[0..4].copy_from_slice(&a32_bl(BASE, BASE + 0x10));
        image[4..8].copy_from_slice(&A32_BX_LR);
        image[0x10..0x14].copy_from_slice(&A32_ADD_R0_PC_8);
        image[0x14..0x18].copy_from_slice(&A32_BX_LR);
        let string_start = plant_seed(&mut image, 0x20);
        let runtime = runtime(&image);
        let seed = find_unique_seed(&runtime, SEED_WARM_BOOT)
            .expect("unique seed")
            .expect("present");
        assert_eq!(seed.string_start, string_start);
        let reset = accepted_arm(&runtime, BASE, BASE + 8);
        let hw = accepted_arm(&runtime, BASE + 0x10, BASE + 0x18);
        let expected = HardwareInit {
            entry: BASE + 0x10,
            isa: DecodeIsa::Arm,
            owner: FunctionOwner::Ghidra,
            execution_blake3: owned_identity(&hw).identity.execution_blake3,
        };
        assert_eq!(
            prove_hardware_init(&runtime, &[reset, hw], Some((BASE, DecodeIsa::Arm)))
                .expect("reset-reachable unique ref"),
            Section::Present(expected)
        );
    }

    #[test]
    fn hw_init_same_entry_ghidra_and_thumb_is_one_container() {
        let mut image = vec![0u8; 0x40];
        image[0..4].copy_from_slice(&a32_bl(BASE, BASE + 0x10));
        image[4..8].copy_from_slice(&A32_BX_LR);
        image[0x10..0x14].copy_from_slice(&A32_ADD_R0_PC_8);
        image[0x14..0x18].copy_from_slice(&A32_BX_LR);
        plant_seed(&mut image, 0x20);
        let runtime = runtime(&image);
        let reset = accepted_arm(&runtime, BASE, BASE + 8);
        let ghidra = accepted_arm(&runtime, BASE + 0x10, BASE + 0x18);
        let thumb = with_owner(
            accepted_arm(&runtime, BASE + 0x10, BASE + 0x18),
            radare2_run_owner(),
        );
        let expected = HardwareInit {
            entry: BASE + 0x10,
            isa: DecodeIsa::Arm,
            owner: FunctionOwner::Ghidra,
            execution_blake3: owned_identity(&ghidra).identity.execution_blake3,
        };
        assert_eq!(
            prove_hardware_init(
                &runtime,
                &[reset, thumb, ghidra],
                Some((BASE, DecodeIsa::Arm))
            )
            .expect("overlapping owners are one container"),
            Section::Present(expected)
        );
    }

    #[test]
    fn hw_init_reset_walk_resource_limit_still_fails() {
        const SPAN: usize = 64 * 1024 + 4;
        let mut image = vec![0u8; SPAN + 0x40];
        for chunk in image[..SPAN].as_chunks_mut::<4>().0 {
            chunk.copy_from_slice(&0xe1a0_0000u32.to_le_bytes());
        }
        let hw_off = SPAN;
        image[hw_off..hw_off + 4].copy_from_slice(&A32_ADD_R0_PC_8);
        image[hw_off + 4..hw_off + 8].copy_from_slice(&A32_BX_LR);
        plant_seed(&mut image, hw_off + 0x10);
        let runtime = runtime(&image);
        let reset = accepted_arm(&runtime, BASE, BASE + SPAN as u32);
        let hw = accepted_arm(&runtime, BASE + hw_off as u32, BASE + hw_off as u32 + 8);
        match prove_hardware_init(&runtime, &[reset, hw], Some((BASE, DecodeIsa::Arm))) {
            Err(StartupMetadataError::ResourceLimit { what, limit, .. }) => {
                assert_eq!(what, "charged bytes");
                assert_eq!(limit, 64 * 1024);
            }
            other => panic!("expected reset-walk ResourceLimit, got {other:?}"),
        }
    }

    #[test]
    fn hw_init_malformed_when_unique_ref_is_not_reachable() {
        let mut image = vec![0u8; 0x40];
        image[0..4].copy_from_slice(&A32_BX_LR);
        image[0x10..0x14].copy_from_slice(&A32_ADD_R0_PC_8);
        image[0x14..0x18].copy_from_slice(&A32_BX_LR);
        plant_seed(&mut image, 0x20);
        let runtime = runtime(&image);
        let reset = accepted_arm(&runtime, BASE, BASE + 4);
        let hw = accepted_arm(&runtime, BASE + 0x10, BASE + 0x18);
        match prove_hardware_init(&runtime, &[reset, hw], Some((BASE, DecodeIsa::Arm))) {
            Err(StartupMetadataError::Malformed { context }) => {
                assert_eq!(context, "hardware_init is not reset-reachable");
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn hw_init_ambiguous_when_two_reachable_containers_exist() {
        let mut image = vec![0u8; 0x60];
        image[0..4].copy_from_slice(&a32_bl(BASE, BASE + 0x20));
        image[4..8].copy_from_slice(&a32_bl(BASE + 4, BASE + 0x30));
        image[8..12].copy_from_slice(&A32_BX_LR);
        let string_start = plant_seed(&mut image, 0x40);
        plant_movw_movt_seed(&mut image, 0x20, string_start);
        plant_movw_movt_seed(&mut image, 0x30, string_start);
        let runtime = runtime(&image);
        let reset = accepted_arm(&runtime, BASE, BASE + 12);
        let first = accepted_arm(&runtime, BASE + 0x20, BASE + 0x2c);
        let second = accepted_arm(&runtime, BASE + 0x30, BASE + 0x3c);
        match prove_hardware_init(
            &runtime,
            &[reset, first, second],
            Some((BASE, DecodeIsa::Arm)),
        ) {
            Err(StartupMetadataError::Ambiguous { values }) => {
                assert_eq!(values, vec![BASE + 0x20, BASE + 0x30]);
            }
            other => panic!("expected Ambiguous, got {other:?}"),
        }
    }

    #[test]
    fn hw_init_malformed_when_unique_ref_is_only_tail_branch_reachable() {
        let mut image = vec![0u8; 0x40];
        image[0..4].copy_from_slice(&a32_b(BASE, BASE + 0x10));
        image[4..8].copy_from_slice(&A32_BX_LR);
        image[0x10..0x14].copy_from_slice(&A32_ADD_R0_PC_8);
        image[0x14..0x18].copy_from_slice(&A32_BX_LR);
        plant_seed(&mut image, 0x20);
        let runtime = runtime(&image);
        let reset = accepted_arm(&runtime, BASE, BASE + 8);
        let hw = accepted_arm(&runtime, BASE + 0x10, BASE + 0x18);
        match prove_hardware_init(&runtime, &[reset, hw], Some((BASE, DecodeIsa::Arm))) {
            Err(StartupMetadataError::Malformed { context }) => {
                assert_eq!(context, "hardware_init is not reset-reachable");
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn hw_init_present_stops_before_cousin_callgraph_limit() {
        const COUSINS: usize = MAX_CALLGRAPH_DEPTH;
        const COUSIN_OFF: u32 = 0x40;
        const COUSIN_LEN: u32 = 8;
        let mut image = vec![0u8; (COUSIN_OFF + COUSINS as u32 * COUSIN_LEN) as usize];
        image[0..4].copy_from_slice(&a32_bl(BASE, BASE + 0x10));
        image[4..8].copy_from_slice(&A32_BX_LR);
        image[0x20] = 0;
        let string_start = plant_seed(&mut image, 0x21);
        let low = (string_start & 0xffff) as u16;
        let high = (string_start >> 16) as u16;
        image[0x10..0x14].copy_from_slice(&a32_movw(0, low));
        image[0x14..0x18].copy_from_slice(&a32_movt(0, high));
        image[0x18..0x1c].copy_from_slice(&a32_bl(BASE + 0x18, BASE + COUSIN_OFF));
        image[0x1c..0x20].copy_from_slice(&A32_BX_LR);
        for index in 0..COUSINS {
            let offset = COUSIN_OFF as usize + index * COUSIN_LEN as usize;
            let pc = BASE + offset as u32;
            let next = pc + COUSIN_LEN;
            image[offset..offset + 4].copy_from_slice(&a32_bl(pc, next));
            image[offset + 4..offset + 8].copy_from_slice(&A32_BX_LR);
        }
        let runtime = runtime(&image);
        let reset = accepted_arm(&runtime, BASE, BASE + 8);
        let hw = accepted_arm(&runtime, BASE + 0x10, BASE + 0x20);
        let mut records = vec![reset, hw.clone()];
        for index in 0..COUSINS {
            let entry = BASE + COUSIN_OFF + index as u32 * COUSIN_LEN;
            records.push(accepted_arm(&runtime, entry, entry + COUSIN_LEN));
        }
        let expected = HardwareInit {
            entry: BASE + 0x10,
            isa: DecodeIsa::Arm,
            owner: FunctionOwner::Ghidra,
            execution_blake3: owned_identity(&hw).identity.execution_blake3,
        };
        assert_eq!(
            prove_hardware_init(&runtime, &records, Some((BASE, DecodeIsa::Arm)))
                .expect("unique survivor must not pay cousin depth"),
            Section::Present(expected)
        );
    }

    const A32_BX_R1: [u8; 4] = [0x11, 0xff, 0x2f, 0xe1];

    #[test]
    fn stack_guard_names_unique_container_without_reset() {
        let mut image = vec![0u8; 0x30];
        image[0..4].copy_from_slice(&A32_ADD_R0_PC_8);
        image[4..8].copy_from_slice(&A32_BX_LR);
        let string_start = plant_cstr(&mut image, 0x10, SEED_STACK_GUARD);
        let runtime = runtime(&image);
        let seed = find_unique_seed(&runtime, SEED_STACK_GUARD)
            .expect("unique seed")
            .expect("present");
        assert_eq!(seed.string_start, string_start);
        let handler = accepted_arm(&runtime, BASE, BASE + 8);
        assert_eq!(
            semantic_refs(&runtime, std::slice::from_ref(&handler), string_start)
                .expect("unique ref")
                .len(),
            1
        );
        let expected = StackGuard {
            entry: BASE,
            isa: DecodeIsa::Arm,
            owner: FunctionOwner::Ghidra,
            execution_blake3: owned_identity(&handler).identity.execution_blake3,
            non_return: false,
        };
        assert_eq!(
            prove_stack_guard(&runtime, &[handler])
                .expect("unique container is named without reset"),
            Section::Present(expected)
        );
    }

    #[test]
    fn stack_guard_non_return_false_when_cfg_contains_return_class() {
        let mut image = vec![0u8; 0x30];
        image[0..4].copy_from_slice(&A32_ADD_R0_PC_8);
        image[4..8].copy_from_slice(&A32_BX_LR);
        plant_cstr(&mut image, 0x10, SEED_STACK_GUARD);
        let runtime = runtime(&image);
        let handler = accepted_arm(&runtime, BASE, BASE + 8);
        match prove_stack_guard(&runtime, &[handler]) {
            Ok(Section::Present(guard)) => {
                assert_eq!(guard.entry, BASE);
                assert!(!guard.non_return);
            }
            other => panic!("expected Present with return-class, got {other:?}"),
        }
    }

    #[test]
    fn stack_guard_non_return_true_when_complete_cfg_has_no_return() {
        let mut image = vec![0u8; 0x30];
        image[0..4].copy_from_slice(&A32_ADD_R0_PC_8);
        image[4..8].copy_from_slice(&a32_b(BASE + 4, BASE + 4));
        plant_cstr(&mut image, 0x10, SEED_STACK_GUARD);
        let runtime = runtime(&image);
        let handler = accepted_arm(&runtime, BASE, BASE + 8);
        let expected = StackGuard {
            entry: BASE,
            isa: DecodeIsa::Arm,
            owner: FunctionOwner::Ghidra,
            execution_blake3: owned_identity(&handler).identity.execution_blake3,
            non_return: true,
        };
        assert_eq!(
            prove_stack_guard(&runtime, &[handler]).expect("complete non-returning CFG"),
            Section::Present(expected)
        );
    }

    #[test]
    fn stack_guard_non_return_false_when_cfg_is_incomplete() {
        let mut image = vec![0u8; 0x30];
        image[0..4].copy_from_slice(&A32_ADD_R0_PC_8);
        image[4..8].copy_from_slice(&A32_BX_R1);
        plant_cstr(&mut image, 0x10, SEED_STACK_GUARD);
        let runtime = runtime(&image);
        let handler = accepted_arm(&runtime, BASE, BASE + 8);
        let execution_blake3 = owned_identity(&handler).identity.execution_blake3;
        match prove_stack_guard(&runtime, &[handler]) {
            Ok(Section::Present(guard)) => {
                assert_eq!(guard.entry, BASE);
                assert_eq!(guard.isa, DecodeIsa::Arm);
                assert_eq!(guard.owner, FunctionOwner::Ghidra);
                assert_eq!(guard.execution_blake3, execution_blake3);
                assert!(!guard.non_return);
            }
            other => panic!("incomplete CFG must still Present the name, got {other:?}"),
        }
    }

    #[test]
    fn stack_guard_absent_without_refs() {
        let mut image = vec![0u8; 0x30];
        image[0..4].copy_from_slice(&A32_BX_LR);
        plant_cstr(&mut image, 0x10, SEED_STACK_GUARD);
        let runtime = runtime(&image);
        let dead = accepted_arm(&runtime, BASE, BASE + 4);
        assert_eq!(
            prove_stack_guard(&runtime, &[dead]).expect("zero refs is absence"),
            Section::Absent
        );
    }

    #[test]
    fn stack_guard_ambiguous_when_two_containers_exist() {
        let mut image = vec![0u8; 0x50];
        let string_start = plant_cstr(&mut image, 0x30, SEED_STACK_GUARD);
        plant_movw_movt_seed(&mut image, 0x00, string_start);
        plant_movw_movt_seed(&mut image, 0x10, string_start);
        let runtime = runtime(&image);
        let first = accepted_arm(&runtime, BASE, BASE + 0x0c);
        let second = accepted_arm(&runtime, BASE + 0x10, BASE + 0x1c);
        match prove_stack_guard(&runtime, &[first, second]) {
            Err(StartupMetadataError::Ambiguous { values }) => {
                assert_eq!(values, vec![BASE, BASE + 0x10]);
            }
            other => panic!("expected Ambiguous, got {other:?}"),
        }
    }

    #[test]
    fn stack_guard_same_entry_ghidra_and_thumb_is_one_container() {
        let mut image = vec![0u8; 0x30];
        image[0..4].copy_from_slice(&A32_ADD_R0_PC_8);
        image[4..8].copy_from_slice(&A32_BX_LR);
        plant_cstr(&mut image, 0x10, SEED_STACK_GUARD);
        let runtime = runtime(&image);
        let ghidra = accepted_arm(&runtime, BASE, BASE + 8);
        let thumb = with_owner(accepted_arm(&runtime, BASE, BASE + 8), radare2_run_owner());
        let expected = StackGuard {
            entry: BASE,
            isa: DecodeIsa::Arm,
            owner: FunctionOwner::Ghidra,
            execution_blake3: owned_identity(&ghidra).identity.execution_blake3,
            non_return: false,
        };
        assert_eq!(
            prove_stack_guard(&runtime, &[thumb, ghidra])
                .expect("overlapping owners are one container"),
            Section::Present(expected)
        );
    }

    const RVCT_CALL_LEN: u32 = 20;
    const RVCT_OPERAND: u16 = 0x1234;
    const RVCT_OPERAND_OTHER: u16 = 0x5678;

    fn plant_rvct_call(
        image: &mut [u8],
        entry_off: usize,
        string_start: u32,
        r1: u16,
        bl_target: u32,
    ) {
        let entry = BASE + entry_off as u32;
        let low = (string_start & 0xffff) as u16;
        let high = (string_start >> 16) as u16;
        image[entry_off..entry_off + 4].copy_from_slice(&a32_movw(0, low));
        image[entry_off + 4..entry_off + 8].copy_from_slice(&a32_movt(0, high));
        image[entry_off + 8..entry_off + 12].copy_from_slice(&a32_movw(1, r1));
        image[entry_off + 12..entry_off + 16].copy_from_slice(&a32_bl(entry + 12, bl_target));
        image[entry_off + 16..entry_off + 20].copy_from_slice(&A32_BX_LR);
    }

    #[test]
    fn rvct_absent_when_seed_missing() {
        let mut image = vec![0u8; 0x20];
        image[0..4].copy_from_slice(&A32_BX_LR);
        let runtime = runtime(&image);
        let dead = accepted_arm(&runtime, BASE, BASE + 4);
        assert_eq!(
            find_unique_seed(&runtime, SEED_RVCT).expect("zero RVCT occurrences"),
            None
        );
        assert_eq!(
            prove_compiler(&runtime, &[dead]).expect("missing RVCT seed is absence"),
            Section::Absent
        );
    }

    #[test]
    fn rvct_records_uninterpreted_exact_operands_at_callsite() {
        let mut image = vec![0u8; 0x40];
        let string_start = plant_cstr(&mut image, 0x20, SEED_RVCT);
        plant_rvct_call(&mut image, 0, string_start, RVCT_OPERAND, BASE + 0x30);
        let runtime = runtime(&image);
        let seed = find_unique_seed(&runtime, SEED_RVCT)
            .expect("unique RVCT seed")
            .expect("present");
        assert_eq!(seed.string_start, string_start);
        let caller = accepted_arm(&runtime, BASE, BASE + RVCT_CALL_LEN);
        let expected = CompilerMeta {
            format_address: string_start,
            format_len: seed.string_len,
            format_blake3: runtime
                .hash_range(string_start, seed.string_len)
                .expect("format hash"),
            callsite_pc: BASE + 12,
            isa: DecodeIsa::Arm,
            operands: vec![string_start, u32::from(RVCT_OPERAND)],
        };
        assert_eq!(
            prove_compiler(&runtime, &[caller]).expect("unique agreeing callsite"),
            Section::Present(expected)
        );
    }

    #[test]
    fn compiler_skips_oversized_cfg_and_keeps_a_later_callsite() {
        const SPAN: usize = 64 * 1024 + 4;
        let mut image = vec![0u8; SPAN + 0x40];
        for chunk in image[..SPAN].as_chunks_mut::<4>().0 {
            chunk.copy_from_slice(&0xe1a0_0000u32.to_le_bytes());
        }
        let call_off = SPAN;
        let string_start = plant_cstr(&mut image, call_off + 0x20, SEED_RVCT);
        plant_rvct_call(
            &mut image,
            call_off,
            string_start,
            RVCT_OPERAND,
            BASE + call_off as u32 + 0x30,
        );
        let runtime = runtime(&image);
        let huge = accepted_arm(&runtime, BASE, BASE + SPAN as u32);
        let caller = accepted_arm(
            &runtime,
            BASE + call_off as u32,
            BASE + call_off as u32 + RVCT_CALL_LEN,
        );
        match prove_compiler(&runtime, &[huge, caller]) {
            Ok(Section::Present(meta)) => {
                assert_eq!(meta.format_address, string_start);
                assert_eq!(meta.callsite_pc, BASE + call_off as u32 + 12);
            }
            other => panic!("expected Present after skipping oversized CFG, got {other:?}"),
        }
    }

    #[test]
    fn rvct_ambiguous_when_callsites_disagree() {
        let mut image = vec![0u8; 0x60];
        let string_start = plant_cstr(&mut image, 0x40, SEED_RVCT);
        plant_rvct_call(&mut image, 0, string_start, RVCT_OPERAND, BASE + 0x50);
        plant_rvct_call(
            &mut image,
            0x20,
            string_start,
            RVCT_OPERAND_OTHER,
            BASE + 0x50,
        );
        let runtime = runtime(&image);
        let first = accepted_arm(&runtime, BASE, BASE + RVCT_CALL_LEN);
        let second = accepted_arm(&runtime, BASE + 0x20, BASE + 0x20 + RVCT_CALL_LEN);
        match prove_compiler(&runtime, &[first, second]) {
            Err(StartupMetadataError::Ambiguous { values }) => {
                assert_eq!(values, vec![BASE + 12, BASE + 0x20 + 12]);
            }
            other => panic!("expected Ambiguous, got {other:?}"),
        }
    }

    #[test]
    fn shannon_os_absent_is_not_an_error() {
        let mut image = vec![0u8; 0x40];
        let string_start = plant_cstr(&mut image, 0x20, SEED_RVCT);
        plant_rvct_call(&mut image, 0, string_start, RVCT_OPERAND, BASE + 0x30);
        let runtime = runtime(&image);
        assert_eq!(
            find_unique_seed(&runtime, SEED_SHANNON_OS).expect("zero ShannonOS occurrences"),
            None
        );
        let caller = accepted_arm(&runtime, BASE, BASE + RVCT_CALL_LEN);
        match prove_compiler(&runtime, &[caller]) {
            Ok(Section::Present(meta)) => {
                assert_eq!(meta.format_address, string_start);
                assert_eq!(meta.operands, vec![string_start, u32::from(RVCT_OPERAND)]);
            }
            other => panic!("ShannonOS absence must not fail RVCT, got {other:?}"),
        }
    }

    const A32_MCR_VBAR: [u8; 4] = [0x10, 0x0f, 0x0c, 0xee];
    const A32_MCR_P15_C15: [u8; 4] = [0x10, 0x0f, 0x0f, 0xee];
    const A32_MRS_CPSR_R0: [u8; 4] = [0x00, 0x00, 0x0f, 0xe1];

    #[test]
    fn vbar_write_is_classified_and_does_not_relocate_exception_tables() {
        let mut image = vec![0u8; 0x10];
        image[0..4].copy_from_slice(&A32_MCR_VBAR);
        image[4..8].copy_from_slice(&A32_MRS_CPSR_R0);
        image[8..12].copy_from_slice(&A32_BX_LR);
        let runtime = runtime(&image);
        let accepted = accepted_arm(&runtime, BASE, BASE + 12);
        let identity = owned_identity(&accepted);
        let ops = sweep_privileged_ops(&runtime, &[accepted]).expect("vbar sweep");
        assert_eq!(
            ops,
            vec![
                PrivilegedOp {
                    pc: BASE,
                    isa: DecodeIsa::Arm,
                    entry: BASE,
                    owner: FunctionOwner::Ghidra,
                    execution_blake3: identity.identity.execution_blake3,
                    direction: SystemDirection::Write,
                    class: PrivilegedClass::Vbar,
                    coprocessor: Some(15),
                    opcode1: Some(0),
                    crn: Some(12),
                    crm: Some(0),
                    opcode2: Some(0),
                    register: None,
                    immediate: None,
                },
                PrivilegedOp {
                    pc: BASE + 4,
                    isa: DecodeIsa::Arm,
                    entry: BASE,
                    owner: FunctionOwner::Ghidra,
                    execution_blake3: identity.identity.execution_blake3,
                    direction: SystemDirection::Read,
                    class: PrivilegedClass::CpsrSpsr,
                    coprocessor: None,
                    opcode1: Some(0),
                    crn: None,
                    crm: None,
                    opcode2: None,
                    register: Some(0),
                    immediate: None,
                },
            ]
        );
        assert_eq!(PrivilegedClass::Vbar.as_wire(), "vbar");
        assert_eq!(PrivilegedClass::CpsrSpsr.as_wire(), "cpsr_spsr");
        assert!(
            crate::exception_roots::discover(&runtime, "MAIN", "MAIN")
                .expect("3A discovery is independent")
                .is_none()
        );
    }

    #[test]
    fn empty_privileged_ops_is_valid() {
        let mut image = vec![0u8; 0x10];
        image[0..4].copy_from_slice(&A32_BX_LR);
        let runtime = runtime(&image);
        let accepted = accepted_arm(&runtime, BASE, BASE + 4);
        let quarantined = quarantined_arm(BASE + 4);
        let ops = sweep_privileged_ops(&runtime, &[accepted, quarantined])
            .expect("empty sweep is success");
        assert_eq!(ops, Vec::new());
        assert_eq!(
            [
                PrivilegedClass::Midr.as_wire(),
                PrivilegedClass::Features.as_wire(),
                PrivilegedClass::Sctlr.as_wire(),
                PrivilegedClass::Ttbr.as_wire(),
                PrivilegedClass::Ttbcr.as_wire(),
                PrivilegedClass::Dacr.as_wire(),
                PrivilegedClass::Fault.as_wire(),
                PrivilegedClass::CacheTlb.as_wire(),
                PrivilegedClass::Pmu.as_wire(),
                PrivilegedClass::Vbar.as_wire(),
                PrivilegedClass::ContextId.as_wire(),
                PrivilegedClass::CpsrSpsr.as_wire(),
                PrivilegedClass::Unclassified.as_wire(),
            ],
            [
                "midr",
                "features",
                "sctlr",
                "ttbr",
                "ttbcr",
                "dacr",
                "fault",
                "cache_tlb",
                "pmu",
                "vbar",
                "context_id",
                "cpsr_spsr",
                "unclassified",
            ]
        );
    }

    #[test]
    fn unclassified_p15_still_counts_toward_the_cap() {
        let mut image = vec![0u8; 0x10];
        image[0..4].copy_from_slice(&A32_MCR_P15_C15);
        image[4..8].copy_from_slice(&A32_BX_LR);
        let runtime = runtime(&image);
        let accepted = accepted_arm(&runtime, BASE, BASE + 8);
        let ops = sweep_privileged_ops(&runtime, &[accepted]).expect("unclassified p15");
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].class, PrivilegedClass::Unclassified);
        assert_eq!(ops[0].pc, BASE);
        assert_eq!(ops[0].direction, SystemDirection::Write);
        assert_eq!(ops[0].coprocessor, Some(15));
        assert_eq!(ops[0].crn, Some(15));
        assert_eq!(ops[0].crm, Some(0));
        assert_eq!(PrivilegedClass::Unclassified.as_wire(), "unclassified");
    }

    #[test]
    fn privileged_op_cap_is_resource_limit() {
        let count = MAX_PRIVILEGED_OPS + 1;
        let mut image = vec![0u8; count * 4];
        for chunk in image.as_chunks_mut::<4>().0 {
            chunk.copy_from_slice(&A32_MCR_VBAR);
        }
        let runtime = runtime(&image);
        let accepted = accepted_arm(&runtime, BASE, BASE + (count as u32) * 4);
        match sweep_privileged_ops(&runtime, &[accepted]) {
            Err(StartupMetadataError::ResourceLimit {
                what,
                actual,
                limit,
            }) => {
                assert_eq!(what, "privileged ops");
                assert_eq!(actual, count as u64);
                assert_eq!(limit, MAX_PRIVILEGED_OPS as u64);
            }
            other => panic!("expected ResourceLimit, got {other:?}"),
        }
    }

    #[test]
    fn colliding_hw_init_and_stack_entries_are_malformed() {
        let mut image = vec![0u8; 0x80];
        image[0..4].copy_from_slice(&a32_bl(BASE, BASE + 0x10));
        image[4..8].copy_from_slice(&A32_BX_LR);
        let warm = plant_cstr(&mut image, 0x30, SEED_WARM_BOOT);
        let stack = plant_cstr(&mut image, 0x50, SEED_STACK_GUARD);
        plant_dual_seed_loads(&mut image, 0x10, warm, stack);
        let runtime = runtime(&image);
        let reset = accepted_arm(&runtime, BASE, BASE + 8);
        let shared = accepted_arm(&runtime, BASE + 0x10, BASE + 0x24);
        let inventories = [reset, shared];
        match prove_hardware_init(&runtime, &inventories, Some((BASE, DecodeIsa::Arm))) {
            Ok(Section::Present(hw)) => {
                assert_eq!(hw.entry, BASE + 0x10);
                assert_eq!(hw.isa, DecodeIsa::Arm);
            }
            other => panic!("expected unique reset-reachable hw_init, got {other:?}"),
        }
        match prove_stack_guard(&runtime, &inventories) {
            Ok(Section::Present(guard)) => {
                assert_eq!(guard.entry, BASE + 0x10);
                assert_eq!(guard.isa, DecodeIsa::Arm);
            }
            other => panic!("expected unique stack_guard container, got {other:?}"),
        }
        match discover(
            &runtime,
            "02_MAIN",
            "MAIN",
            &inventories,
            Some((BASE, DecodeIsa::Arm)),
        ) {
            Err(StartupMetadataError::Malformed { context }) => {
                assert_eq!(
                    context,
                    "hardware_init and stack_guard share entry 0x40010010"
                );
            }
            other => panic!("expected colliding Malformed, got {other:?}"),
        }
    }

    #[test]
    fn stack_ambiguous_fails_the_whole_plan_even_if_hw_init_was_provable() {
        let mut image = vec![0u8; 0x90];
        image[0..4].copy_from_slice(&a32_bl(BASE, BASE + 0x10));
        image[4..8].copy_from_slice(&A32_BX_LR);
        let warm = plant_cstr(&mut image, 0x50, SEED_WARM_BOOT);
        let stack = plant_cstr(&mut image, 0x70, SEED_STACK_GUARD);
        plant_movw_movt_seed(&mut image, 0x10, warm);
        plant_movw_movt_seed(&mut image, 0x20, stack);
        plant_movw_movt_seed(&mut image, 0x30, stack);
        let runtime = runtime(&image);
        let reset = accepted_arm(&runtime, BASE, BASE + 8);
        let hw = accepted_arm(&runtime, BASE + 0x10, BASE + 0x1c);
        let first = accepted_arm(&runtime, BASE + 0x20, BASE + 0x2c);
        let second = accepted_arm(&runtime, BASE + 0x30, BASE + 0x3c);
        let inventories = [reset, hw, first, second];
        match prove_hardware_init(&runtime, &inventories, Some((BASE, DecodeIsa::Arm))) {
            Ok(Section::Present(init)) => {
                assert_eq!(init.entry, BASE + 0x10);
                assert_eq!(init.isa, DecodeIsa::Arm);
            }
            other => panic!("hw_init must be independently Present, got {other:?}"),
        }
        match prove_stack_guard(&runtime, &inventories) {
            Err(StartupMetadataError::Ambiguous { values }) => {
                assert_eq!(values, vec![BASE + 0x20, BASE + 0x30]);
            }
            other => panic!("expected stack Ambiguous, got {other:?}"),
        }
        match discover(
            &runtime,
            "02_MAIN",
            "MAIN",
            &inventories,
            Some((BASE, DecodeIsa::Arm)),
        ) {
            Err(StartupMetadataError::Ambiguous { values }) => {
                assert_eq!(values, vec![BASE + 0x20, BASE + 0x30]);
            }
            other => panic!("expected whole-plan Ambiguous, got {other:?}"),
        }
    }

    #[test]
    fn all_string_sections_absent_still_returns_a_plan() {
        let mut image = vec![0u8; 0x10];
        image[0..4].copy_from_slice(&A32_BX_LR);
        let runtime = runtime(&image);
        let accepted = accepted_arm(&runtime, BASE, BASE + 4);
        let plan = discover(&runtime, "02_MAIN", "MAIN", &[accepted], None)
            .expect("absent string sections still publish a plan");
        assert_eq!(plan.image_label, "02_MAIN");
        assert_eq!(plan.toc_name, "MAIN");
        assert_eq!(plan.image_base, BASE);
        assert_eq!(plan.image_size, 0x10);
        assert_eq!(plan.hardware_init, Section::Absent);
        assert_eq!(plan.stack_guard, Section::Absent);
        assert_eq!(plan.compiler, Section::Absent);
        assert_eq!(plan.privileged_ops, Vec::new());
        assert_eq!(plan.applications, Vec::new());
    }
}
