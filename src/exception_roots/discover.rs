use super::{
    ExceptionApplication, ExceptionClaim, ExceptionRole, ExceptionRoot, ExceptionRootError,
    ExceptionRootPlan, MAX_ROOTS, MAX_TABLES, MAX_VBAR_WRITES, RelocationEvidence, RootIsa,
    SlotForm, VECTOR_SLOTS, VbarWriteEvidence, VectorSlot, VectorTable, VectorTableKind,
};
use crate::arm32::{
    AddressBase, AddressOffset, BranchPredicate, ControlFlow, InstructionDecoder, PureRustDecoder,
    Register, ValueEffect,
};
use crate::runtime_image::{RuntimeImage, StorageKind, StorageSpan};
use crate::semantic_cfg::{BoundaryKind, CallPolicy, CfgLimits, SemanticCfg, SemanticCfgError};
use std::collections::{BTreeMap, BTreeSet};

const SLOT_BYTES: u32 = 4;
const TABLE_BYTES: u32 = VECTOR_SLOTS as u32 * SLOT_BYTES;
const PC: Register = Register(15);

#[derive(Debug, Clone, Copy)]
enum ClassifiedTarget {
    DirectBranch { offset: i64 },
    LiteralLoad { offset: i64 },
}

#[derive(Debug, Clone, Copy)]
struct ClassifiedSlot {
    role: ExceptionRole,
    address: u32,
    target: ClassifiedTarget,
}

#[derive(Debug)]
struct ValidatedInstruction {
    size: u8,
    blake3: [u8; 32],
    storage: Vec<StorageSpan>,
}

pub(crate) fn discover(
    runtime: &RuntimeImage<'_>,
    label: &str,
    toc_name: &str,
) -> Result<Option<ExceptionRootPlan>, ExceptionRootError> {
    let table_address = runtime.image_bounds().0;
    let Some(initial_table) = validate_table(runtime, table_address, VectorTableKind::Initial)?
    else {
        return Ok(None);
    };
    let (relocation, relocated_table) = prove_reset_vbar(runtime, &initial_table)?;
    let mut tables = vec![initial_table.clone()];
    if let Some(relocated_table) = relocated_table {
        tables.push(relocated_table);
    }
    assemble_plan(
        runtime,
        label,
        toc_name,
        initial_table.clone(),
        tables,
        relocation,
    )
    .map(Some)
}

fn prove_reset_vbar(
    runtime: &RuntimeImage<'_>,
    initial_table: &VectorTable,
) -> Result<(RelocationEvidence, Option<VectorTable>), ExceptionRootError> {
    let reset = initial_table
        .slots
        .iter()
        .find(|slot| slot.role == ExceptionRole::Reset)
        .ok_or_else(|| malformed(initial_table.address, "validated table has no reset slot"))?;
    let cfg = match SemanticCfg::decode(
        runtime,
        reset.entry,
        reset.isa.decode_isa(),
        CfgLimits::exception_roots(),
        CallPolicy::FallthroughAndHandoff,
    ) {
        Ok(cfg) => cfg,
        Err(SemanticCfgError::ResourceLimit {
            what,
            actual,
            limit,
        }) => {
            return Err(ExceptionRootError::ResourceLimit {
                what,
                actual,
                limit,
            });
        }
        Err(error) => {
            return Ok((
                RelocationEvidence::AnalysisIncomplete {
                    observations: Vec::new(),
                    handoffs: Vec::new(),
                    reason: Some(error.to_string()),
                },
                None,
            ));
        }
    };
    let mut observations = Vec::new();
    for (pc, instruction) in cfg.instructions() {
        let Some(transfer) = instruction.system.transfer() else {
            continue;
        };
        if !transfer.is_vbar_write() {
            continue;
        }
        let actual =
            observations
                .len()
                .checked_add(1)
                .ok_or(ExceptionRootError::ResourceLimit {
                    what: "VBAR write observations",
                    actual: u64::MAX,
                    limit: MAX_VBAR_WRITES as u64,
                })?;
        if actual > MAX_VBAR_WRITES {
            return Err(ExceptionRootError::ResourceLimit {
                what: "VBAR write observations",
                actual: actual as u64,
                limit: MAX_VBAR_WRITES as u64,
            });
        }
        let dominates_handoffs = cfg
            .handoffs()
            .iter()
            .all(|handoff| cfg.dominates(*pc, handoff.pc));
        let value = cfg
            .exact_register_states()
            .get(pc)
            .and_then(|state| state.get(transfer.rt));
        observations.push(VbarWriteEvidence {
            pc: *pc,
            isa: RootIsa::from_decode_isa(instruction.isa),
            source_register: transfer.rt.0,
            conditional: instruction.conditional,
            exact_value: value.map(|value| value.value),
            definitions: value
                .map(|value| value.definitions().into_iter().collect())
                .unwrap_or_default(),
            dominates_handoffs,
        });
    }
    observations.sort_by_key(|observation| observation.pc);
    observations.dedup();
    if cfg
        .handoffs()
        .iter()
        .any(|handoff| is_incomplete_boundary(handoff.kind))
    {
        return Ok((
            RelocationEvidence::AnalysisIncomplete {
                observations,
                handoffs: cfg.handoffs().to_vec(),
                reason: None,
            },
            None,
        ));
    }
    let candidates = observations
        .iter()
        .filter(|observation| {
            !observation.conditional
                && observation.dominates_handoffs
                && observation.exact_value.is_some()
        })
        .cloned()
        .collect::<Vec<_>>();
    let values = candidates
        .iter()
        .filter_map(|candidate| candidate.exact_value)
        .collect::<BTreeSet<_>>();
    let Some(selected) = select_final_vbar(&cfg, &candidates) else {
        if !observations.is_empty() {
            if values.len() > 1 {
                return Err(ExceptionRootError::Ambiguous {
                    values: values.into_iter().collect(),
                });
            }
            return Ok((RelocationEvidence::Unresolved { observations }, None));
        }
        return Ok((RelocationEvidence::NotObserved, None));
    };
    if !selection_is_final(&cfg, &selected, &observations) {
        return Ok((RelocationEvidence::Unresolved { observations }, None));
    }
    let value = selected
        .exact_value
        .expect("selecting VBAR candidates carry exact values");
    if value == initial_table.address {
        return Ok((
            RelocationEvidence::ConfirmedInitial {
                selected,
                observations,
            },
            None,
        ));
    }
    if classify_slots(runtime, value).is_none() {
        return Ok((RelocationEvidence::Unresolved { observations }, None));
    }
    let relocated = match validate_table(runtime, value, VectorTableKind::Relocated) {
        Ok(Some(table)) => table,
        Ok(None) => {
            return Err(malformed(
                value,
                "relocated table fell below threshold during strict validation",
            ));
        }
        Err(error @ ExceptionRootError::ResourceLimit { .. }) => return Err(error),
        Err(error) => {
            return Err(malformed(
                value,
                format!("relocated table strict validation failed: {error}"),
            ));
        }
    };
    Ok((
        RelocationEvidence::Relocated {
            selected,
            table_address: value,
            observations,
        },
        Some(relocated),
    ))
}

fn selection_is_final(
    cfg: &SemanticCfg,
    selected: &VbarWriteEvidence,
    observations: &[VbarWriteEvidence],
) -> bool {
    observations.iter().all(|other| {
        other.pc == selected.pc
            || (other.exact_value.is_some() && other.exact_value == selected.exact_value)
            || cfg.dominates(other.pc, selected.pc)
    })
}

fn select_final_vbar(
    cfg: &SemanticCfg,
    candidates: &[VbarWriteEvidence],
) -> Option<VbarWriteEvidence> {
    let mut final_candidates = candidates.iter().filter(|candidate| {
        candidates
            .iter()
            .all(|other| other.pc == candidate.pc || cfg.dominates(other.pc, candidate.pc))
    });
    let selected = final_candidates.next().cloned();
    if final_candidates.next().is_none() {
        return selected;
    }
    None
}

fn is_incomplete_boundary(kind: BoundaryKind) -> bool {
    matches!(
        kind,
        BoundaryKind::ExceptionCall
            | BoundaryKind::Indirect
            | BoundaryKind::Unmapped
            | BoundaryKind::DecodeFailure
    )
}

/// Classify all eight A32 slots before resolving any literal or target. A
/// decode/read miss during classification is clean absence; after all eight
/// forms survive, every arithmetic, runtime, identity, and decode failure is
/// fail-closed.
fn validate_table(
    runtime: &RuntimeImage<'_>,
    table_address: u32,
    kind: VectorTableKind,
) -> Result<Option<VectorTable>, ExceptionRootError> {
    let Some(classified) = classify_slots(runtime, table_address) else {
        return Ok(None);
    };

    let storage = byte_backed_storage(runtime, table_address, TABLE_BYTES, "vector table")?;
    let blake3 = runtime
        .hash_range(table_address, TABLE_BYTES)
        .map_err(|error| runtime_error(table_address, TABLE_BYTES, "vector table hash", error))?;
    let mut slots = Vec::with_capacity(VECTOR_SLOTS);

    for classified_slot in classified {
        let slot_blake3 = runtime
            .hash_range(classified_slot.address, SLOT_BYTES)
            .map_err(|error| {
                runtime_error(
                    classified_slot.address,
                    SLOT_BYTES,
                    "vector slot hash",
                    error,
                )
            })?;
        let (form, entry, isa, literal_blake3, literal_storage) = match classified_slot.target {
            ClassifiedTarget::DirectBranch { offset } => {
                let entry = checked_pc_relative(
                    table_address,
                    classified_slot.address,
                    offset,
                    "direct branch target",
                )?;
                (
                    SlotForm::DirectBranch,
                    entry,
                    RootIsa::Arm,
                    None,
                    Vec::new(),
                )
            }
            ClassifiedTarget::LiteralLoad { offset } => {
                let literal_address = checked_pc_relative(
                    table_address,
                    classified_slot.address,
                    offset,
                    "literal address",
                )?;
                let literal_storage =
                    byte_backed_storage(runtime, literal_address, SLOT_BYTES, "vector literal")?;
                let pointer = runtime.read_u32(literal_address).map_err(|error| {
                    runtime_error(literal_address, SLOT_BYTES, "vector literal read", error)
                })?;
                let literal_blake3 =
                    runtime
                        .hash_range(literal_address, SLOT_BYTES)
                        .map_err(|error| {
                            runtime_error(literal_address, SLOT_BYTES, "vector literal hash", error)
                        })?;
                let (isa, entry) = if pointer & 1 == 1 {
                    (RootIsa::Thumb, pointer & !1)
                } else {
                    (RootIsa::Arm, pointer)
                };
                (
                    SlotForm::LiteralLoad { literal_address },
                    entry,
                    isa,
                    Some(literal_blake3),
                    literal_storage,
                )
            }
        };
        let instruction = validate_instruction(runtime, entry, isa)?;
        slots.push(VectorSlot {
            role: classified_slot.role,
            address: classified_slot.address,
            form,
            slot_blake3,
            literal_blake3,
            literal_storage,
            entry,
            isa,
            instruction_size: instruction.size,
            instruction_blake3: instruction.blake3,
            instruction_storage: instruction.storage,
        });
    }

    reject_cross_isa_aliases(&slots)?;
    Ok(Some(VectorTable {
        kind,
        address: table_address,
        blake3,
        storage,
        slots,
    }))
}

fn classify_slots(
    runtime: &RuntimeImage<'_>,
    table_address: u32,
) -> Option<[ClassifiedSlot; VECTOR_SLOTS]> {
    if !table_address.is_multiple_of(SLOT_BYTES) {
        return None;
    }
    let decoder = PureRustDecoder;
    let mut slots = Vec::with_capacity(VECTOR_SLOTS);
    for (index, role) in ExceptionRole::ALL.into_iter().enumerate() {
        let offset = u32::try_from(index).ok()?.checked_mul(SLOT_BYTES)?;
        let address = table_address.checked_add(offset)?;
        let bytes = runtime.read_exact(address, SLOT_BYTES as usize).ok()?;
        let word = u32::from_le_bytes(bytes.as_ref().try_into().ok()?);
        let mut state = decoder.begin_range(RootIsa::Arm.decode_isa());
        let instruction = decoder
            .decode_one(&mut state, RootIsa::Arm.decode_isa(), address, &bytes)
            .ok()?;
        let target = classify_slot(word, &instruction)?;
        slots.push(ClassifiedSlot {
            role,
            address,
            target,
        });
    }
    slots.try_into().ok()
}

fn classify_slot(
    word: u32,
    instruction: &crate::arm32::DecodedInstruction,
) -> Option<ClassifiedTarget> {
    if instruction.conditional || instruction.links_lr || instruction.length != SLOT_BYTES as u8 {
        return None;
    }
    if matches!(
        instruction.flow,
        ControlFlow::DirectBranch {
            predicate: BranchPredicate::Always,
            fallthrough: None,
            ..
        }
    ) {
        return Some(ClassifiedTarget::DirectBranch {
            offset: branch_offset(word),
        });
    }
    match instruction.effect {
        ValueEffect::LiteralWordLoad {
            dst: PC,
            address:
                crate::arm32::AddressExpr {
                    base:
                        AddressBase::ArchitecturalPc {
                            align_to_four: false,
                        },
                    offset: AddressOffset::Immediate(offset),
                },
        } if literal_uses_offset_addressing(word) => Some(ClassifiedTarget::LiteralLoad { offset }),
        _ => None,
    }
}

fn literal_uses_offset_addressing(word: u32) -> bool {
    word & (1 << 24) != 0 && word & (1 << 21) == 0
}

fn branch_offset(word: u32) -> i64 {
    let signed_words = (((word & 0x00ff_ffff) << 8) as i32) >> 8;
    i64::from(signed_words) * 4
}

fn checked_pc_relative(
    table: u32,
    pc: u32,
    offset: i64,
    context: &str,
) -> Result<u32, ExceptionRootError> {
    let visible_pc = pc.checked_add(8).ok_or_else(|| {
        malformed(
            table,
            format!("{context} architectural PC wraps at {pc:#010x}"),
        )
    })?;
    checked_offset(visible_pc, offset).ok_or_else(|| {
        malformed(
            table,
            format!("{context} wraps at slot {pc:#010x} with offset {offset}"),
        )
    })
}

fn checked_offset(address: u32, offset: i64) -> Option<u32> {
    if offset >= 0 {
        address.checked_add(u32::try_from(offset).ok()?)
    } else {
        address.checked_sub(u32::try_from(offset.unsigned_abs()).ok()?)
    }
}

fn validate_instruction(
    runtime: &RuntimeImage<'_>,
    entry: u32,
    isa: RootIsa,
) -> Result<ValidatedInstruction, ExceptionRootError> {
    let decode_error = |reason| ExceptionRootError::Decode {
        pc: entry,
        isa,
        reason,
    };
    if isa == RootIsa::Arm && !entry.is_multiple_of(4) {
        return Err(decode_error("ARM target is not word-aligned".to_string()));
    }

    let mut bytes = runtime.read_exact(entry, 4);
    if isa == RootIsa::Thumb && bytes.is_err() {
        bytes = runtime.read_exact(entry, 2);
    }
    let bytes = bytes.map_err(|error| runtime_error(entry, 4, "target instruction read", error))?;
    let decoder = PureRustDecoder;
    let mut state = decoder.begin_range(isa.decode_isa());
    let instruction = decoder
        .decode_one(&mut state, isa.decode_isa(), entry, &bytes)
        .map_err(|error| decode_error(error.to_string()))?;
    let size = u32::from(instruction.length);
    let storage = byte_backed_storage(runtime, entry, size, "target instruction")?;
    let blake3 = runtime
        .hash_range(entry, size)
        .map_err(|error| runtime_error(entry, size, "target instruction hash", error))?;
    Ok(ValidatedInstruction {
        size: instruction.length,
        blake3,
        storage,
    })
}

fn byte_backed_storage(
    runtime: &RuntimeImage<'_>,
    address: u32,
    size: u32,
    context: &str,
) -> Result<Vec<StorageSpan>, ExceptionRootError> {
    let storage = runtime
        .storage_spans(address, size)
        .map_err(|error| runtime_error(address, size, context, error))?;
    if storage
        .iter()
        .any(|span| span.kind == StorageKind::ScatterZero)
    {
        return Err(ExceptionRootError::Runtime {
            address,
            size,
            reason: format!("{context} crosses virtual zero-fill storage"),
        });
    }
    Ok(storage)
}

fn reject_cross_isa_aliases<'a>(
    slots: impl IntoIterator<Item = &'a VectorSlot>,
) -> Result<(), ExceptionRootError> {
    let mut identities: BTreeMap<u32, BTreeSet<RootIsa>> = BTreeMap::new();
    for slot in slots {
        identities.entry(slot.entry).or_default().insert(slot.isa);
    }
    let values = identities
        .into_iter()
        .filter_map(|(entry, isas)| (isas.len() > 1).then_some(entry))
        .collect::<Vec<_>>();
    if values.is_empty() {
        Ok(())
    } else {
        Err(ExceptionRootError::Ambiguous { values })
    }
}

fn build_roots_and_applications(
    tables: &[VectorTable],
) -> Result<(Vec<ExceptionRoot>, Vec<ExceptionApplication>), ExceptionRootError> {
    reject_cross_isa_aliases(tables.iter().flat_map(|table| table.slots.iter()))?;

    let mut roots: BTreeMap<(u32, RootIsa), ExceptionRoot> = BTreeMap::new();
    let mut ordered_tables = tables.iter().collect::<Vec<_>>();
    ordered_tables.sort_by_key(|table| (table.kind, table.address));
    for table in ordered_tables {
        let mut slots = table.slots.iter().collect::<Vec<_>>();
        slots.sort_by_key(|slot| (slot.address, slot.role));
        for slot in slots {
            let key = (slot.entry, slot.isa);
            if !roots.contains_key(&key) && roots.len() == MAX_ROOTS {
                return Err(ExceptionRootError::ResourceLimit {
                    what: "exception roots",
                    actual: (MAX_ROOTS + 1) as u64,
                    limit: MAX_ROOTS as u64,
                });
            }
            let root = roots.entry(key).or_insert_with(|| ExceptionRoot {
                entry: slot.entry,
                isa: slot.isa,
                instruction_size: slot.instruction_size,
                instruction_blake3: slot.instruction_blake3,
                storage: slot.instruction_storage.clone(),
                claims: Vec::new(),
            });
            if root.instruction_size != slot.instruction_size
                || root.instruction_blake3 != slot.instruction_blake3
                || root.storage != slot.instruction_storage
            {
                return Err(malformed(
                    table.address,
                    format!(
                        "root identity {:#010x} has inconsistent instruction evidence",
                        slot.entry
                    ),
                ));
            }
            root.claims.push(ExceptionClaim {
                table_kind: table.kind,
                table_address: table.address,
                slot_address: slot.address,
                role: slot.role,
            });
        }
    }

    let mut roots = roots.into_values().collect::<Vec<_>>();
    for root in &mut roots {
        root.claims.sort();
        root.claims.dedup();
    }

    let mut role_identities: BTreeMap<ExceptionRole, BTreeSet<(u32, RootIsa)>> = BTreeMap::new();
    for root in &roots {
        for claim in &root.claims {
            role_identities
                .entry(claim.role)
                .or_default()
                .insert((root.entry, root.isa));
        }
    }
    let applications = roots
        .iter()
        .map(|root| {
            let roles = root
                .claims
                .iter()
                .map(|claim| claim.role)
                .collect::<BTreeSet<_>>();
            let desired_primary = if roles.len() == 1 {
                let role = *roles.first().expect("one role after length check");
                (role_identities
                    .get(&role)
                    .is_some_and(|entries| entries.len() == 1))
                .then(|| role.preferred_primary().to_string())
            } else {
                None
            };
            let mut role_labels = Vec::new();
            for claim in &root.claims {
                let label = format!(
                    "exception_{}_{:08x}",
                    claim.role.as_wire(),
                    claim.table_address
                );
                if !role_labels.contains(&label) {
                    role_labels.push(label);
                }
            }
            ExceptionApplication {
                entry: root.entry,
                isa: root.isa,
                desired_primary,
                claims: root.claims.clone(),
                role_labels,
            }
        })
        .collect();
    Ok((roots, applications))
}

fn assemble_plan(
    runtime: &RuntimeImage<'_>,
    label: &str,
    toc_name: &str,
    initial_table: VectorTable,
    mut tables: Vec<VectorTable>,
    relocation: RelocationEvidence,
) -> Result<ExceptionRootPlan, ExceptionRootError> {
    if tables.len() > MAX_TABLES {
        return Err(ExceptionRootError::ResourceLimit {
            what: "vector tables",
            actual: tables.len() as u64,
            limit: MAX_TABLES as u64,
        });
    }
    let mut counts = BTreeMap::new();
    for table in &tables {
        *counts.entry(table.address).or_insert(0usize) += 1;
    }
    let duplicate_addresses = counts
        .into_iter()
        .filter_map(|(address, count)| (count > 1).then_some(address))
        .collect::<Vec<_>>();
    if !duplicate_addresses.is_empty() {
        return Err(ExceptionRootError::Ambiguous {
            values: duplicate_addresses,
        });
    }
    if !tables.iter().any(|table| table == &initial_table) {
        return Err(malformed(
            initial_table.address,
            "validated table set does not contain the initial table",
        ));
    }
    tables.sort_by_key(|table| (table.kind, table.address));
    let (roots, applications) = build_roots_and_applications(&tables)?;
    let (image_base, image_size) = runtime.image_bounds();
    Ok(ExceptionRootPlan {
        image_label: label.to_string(),
        toc_name: toc_name.to_string(),
        image_base,
        image_size,
        initial_table,
        relocation,
        tables,
        roots,
        applications,
    })
}

fn malformed(table: u32, context: impl Into<String>) -> ExceptionRootError {
    ExceptionRootError::Malformed {
        table,
        context: context.into(),
    }
}

fn runtime_error(
    address: u32,
    size: u32,
    context: &str,
    error: crate::error::Error,
) -> ExceptionRootError {
    ExceptionRootError::Runtime {
        address,
        size,
        reason: format!("{context}: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::{assemble_plan, build_roots_and_applications, discover, validate_table};
    use crate::arm32::{
        AddressBase, ControlFlow, InstructionDecoder, PureRustDecoder, Register, ValueEffect,
        ValueExpr,
    };
    use crate::exception_roots::{
        ExceptionRole, ExceptionRootError, MAX_ROOTS, MAX_TABLES, RelocationEvidence, RootIsa,
        SlotForm, VectorTableKind,
    };
    use crate::runtime_image::{RuntimeImage, StorageKind, StorageSpan};
    use crate::scatter::{
        Descriptor, HandlerMap, LoadPlan, Operation, PlannedEntry, PlannedOutput,
    };

    const BASE: u32 = 0x4001_0000;
    const IMAGE_SIZE: usize = 0x800;
    const TABLE_SIZE: u32 = 8 * 4;
    const ARM_NOP: u32 = 0xe1a0_0000;
    const THUMB_BX_LR: u16 = 0x4770;
    const ARM_TARGET_START: u32 = BASE + 0x100;
    const RESET_ENTRY: u32 = BASE + 0x400;
    const RELOCATED_TABLE: u32 = BASE + 0x1000;
    const RESET_IMAGE_SIZE: usize = 0x2000;
    const COPY_HANDLER: u32 = BASE + 0x280;
    const ZERO_HANDLER: u32 = BASE + 0x284;
    const EXPECTED_ROLES: [ExceptionRole; 8] = [
        ExceptionRole::Reset,
        ExceptionRole::UndefinedInstruction,
        ExceptionRole::SupervisorCall,
        ExceptionRole::PrefetchAbort,
        ExceptionRole::DataAbort,
        ExceptionRole::Reserved,
        ExceptionRole::Irq,
        ExceptionRole::Fiq,
    ];

    #[derive(Clone, Copy)]
    enum TargetLayout {
        DistinctArm,
        Shared(ExceptionRole, ExceptionRole),
    }

    #[derive(Clone, Copy)]
    enum VbarValue {
        Initial,
        SecondValidTable,
    }

    struct VectorFixture {
        base: u32,
        raw: Vec<u8>,
        plan: Option<LoadPlan>,
    }

    impl VectorFixture {
        fn runtime(&self) -> RuntimeImage<'_> {
            RuntimeImage::from_plan(&self.raw, self.base, self.plan.as_ref()).unwrap()
        }

        fn write_u16(&mut self, address: u32, value: u16) {
            write_bytes(&mut self.raw, self.base, address, &value.to_le_bytes());
        }

        fn write_u32(&mut self, address: u32, value: u32) {
            write_u32(&mut self.raw, self.base, address, value);
        }

        fn literal_address(&self, slot: usize) -> u32 {
            literal_address(self.base, slot)
        }

        fn set_pointer(&mut self, slot: usize, pointer: u32) {
            self.write_u32(self.literal_address(slot), pointer);
        }
    }

    fn role_index(role: ExceptionRole) -> usize {
        EXPECTED_ROLES
            .iter()
            .position(|candidate| *candidate == role)
            .unwrap()
    }

    fn write_bytes(raw: &mut [u8], base: u32, address: u32, bytes: &[u8]) {
        let start = usize::try_from(address.checked_sub(base).unwrap()).unwrap();
        let end = start.checked_add(bytes.len()).unwrap();
        raw[start..end].copy_from_slice(bytes);
    }

    fn write_u32(raw: &mut [u8], base: u32, address: u32, value: u32) {
        write_bytes(raw, base, address, &value.to_le_bytes());
    }

    fn literal_address(base: u32, slot: usize) -> u32 {
        if slot == 7 {
            base + 0x20
        } else {
            base + 0x40 + u32::try_from(slot).unwrap() * 4
        }
    }

    // A32 LDR (immediate), P=1/W=0/L=1, Rn=PC, Rd=PC. The fixture
    // encoder follows the architectural bit fields rather than calling
    // the production decoder or any production address helper.
    fn a32_ldr_pc(slot: u32, literal: u32) -> u32 {
        let visible_pc = i64::from(slot) + 8;
        let displacement = i64::from(literal) - visible_pc;
        assert!(displacement.unsigned_abs() <= 0xfff);
        let base = if displacement >= 0 {
            0xe59f_f000
        } else {
            0xe51f_f000
        };
        base | u32::try_from(displacement.unsigned_abs()).unwrap()
    }

    // A32 B/BL immediate: signed imm24 is the byte displacement divided
    // by four from architectural PC (slot + 8).
    fn a32_branch(slot: u32, target: u32, condition: u8, link: bool) -> u32 {
        let displacement = i64::from(target) - (i64::from(slot) + 8);
        assert_eq!(displacement % 4, 0);
        let words = displacement / 4;
        assert!((-(1 << 23)..(1 << 23)).contains(&words));
        (u32::from(condition) << 28)
            | (0b101 << 25)
            | (u32::from(link) << 24)
            | ((words as u32) & 0x00ff_ffff)
    }

    // A32 MOVW/MOVT encodings derived directly from the architectural
    // immediate split: imm4 occupies bits 19:16 and imm12 bits 11:0.
    fn a32_mov_half(register: u8, immediate: u16, high: bool) -> u32 {
        let opcode = if high { 0xe340_0000 } else { 0xe300_0000 };
        opcode
            | ((u32::from(immediate) & 0xf000) << 4)
            | (u32::from(register) << 12)
            | (u32::from(immediate) & 0x0fff)
    }

    // A32 MCR p15, 0, Rt, c12, c0, 0. This test encoder is independent of
    // the production classifier and varies only the architectural Rt field.
    fn a32_vbar_write_with_condition(register: u8, condition: u8) -> u32 {
        (u32::from(condition) << 28) | 0x0e0c_0f10 | (u32::from(register) << 12)
    }

    fn a32_vbar_write(register: u8) -> u32 {
        a32_vbar_write_with_condition(register, 0xe)
    }

    fn target_for_role(role: ExceptionRole) -> u32 {
        ARM_TARGET_START + u32::try_from(role_index(role)).unwrap() * 4
    }

    fn write_literal_table(
        raw: &mut [u8],
        base: u32,
        table: u32,
        literal_start: u32,
        targets: [u32; 8],
    ) {
        for (index, target) in targets.into_iter().enumerate() {
            let index = u32::try_from(index).unwrap();
            let slot = table + index * 4;
            let literal = literal_start + index * 4;
            write_u32(raw, base, slot, a32_ldr_pc(slot, literal));
            write_u32(raw, base, literal, target);
            let entry = target & !1;
            if target & 1 == 0 {
                write_u32(raw, base, entry, ARM_NOP);
            } else {
                write_bytes(raw, base, entry, &THUMB_BX_LR.to_le_bytes());
            }
        }
    }

    fn reset_tables_fixture() -> VectorFixture {
        let mut fixture = VectorFixture {
            base: BASE,
            raw: vec![0; RESET_IMAGE_SIZE],
            plan: None,
        };
        let initial_targets: [u32; 8] =
            std::array::from_fn(|index| RESET_ENTRY + u32::try_from(index).unwrap() * 0x40);
        write_literal_table(&mut fixture.raw, BASE, BASE, BASE + 0x40, initial_targets);
        let relocated_targets =
            std::array::from_fn(|index| BASE + 0x1800 + u32::try_from(index).unwrap() * 4);
        write_literal_table(
            &mut fixture.raw,
            BASE,
            RELOCATED_TABLE,
            RELOCATED_TABLE + 0x40,
            relocated_targets,
        );

        fixture
    }

    fn write_reset_program(fixture: &mut VectorFixture, instructions: &[u32]) {
        for (index, instruction) in instructions.iter().copied().enumerate() {
            fixture.write_u32(RESET_ENTRY + u32::try_from(index).unwrap() * 4, instruction);
        }
    }

    fn reset_fixture_with_program(instructions: &[u32]) -> VectorFixture {
        let mut fixture = reset_tables_fixture();
        write_reset_program(&mut fixture, instructions);
        fixture
    }

    fn materialize(register: u8, value: u32) -> [u32; 2] {
        [
            a32_mov_half(register, value as u16, false),
            a32_mov_half(register, (value >> 16) as u16, true),
        ]
    }

    fn t32_mov_half(register: u8, immediate: u16, high: bool) -> [u8; 4] {
        let immediate = u32::from(immediate);
        let mut first = if high { 0xf2c0 } else { 0xf240 };
        first |= (immediate >> 12) & 0xf;
        first |= ((immediate >> 11) & 1) << 10;
        let second = ((immediate >> 8) & 7) << 12 | (u32::from(register) << 8) | (immediate & 0xff);
        let first = (first as u16).to_le_bytes();
        let second = (second as u16).to_le_bytes();
        [first[0], first[1], second[0], second[1]]
    }

    fn t32_vbar_write(register: u8) -> [u8; 4] {
        let first = 0xee0cu16.to_le_bytes();
        let second = (0x0f10u16 | (u16::from(register) << 12)).to_le_bytes();
        [first[0], first[1], second[0], second[1]]
    }

    fn thumb_reset_fixture(value: u32, tail: &[u8]) -> VectorFixture {
        let mut fixture = reset_tables_fixture();
        fixture.set_pointer(0, RESET_ENTRY | 1);
        let mut program = Vec::new();
        program.extend_from_slice(&t32_mov_half(0, value as u16, false));
        program.extend_from_slice(&t32_mov_half(0, (value >> 16) as u16, true));
        program.extend_from_slice(&t32_vbar_write(0));
        program.extend_from_slice(tail);
        write_bytes(&mut fixture.raw, BASE, RESET_ENTRY, &program);
        fixture
    }

    fn reset_vbar_fixture(value: VbarValue) -> VectorFixture {
        let selected = match value {
            VbarValue::Initial => BASE,
            VbarValue::SecondValidTable => RELOCATED_TABLE,
        };
        let [movw, movt] = materialize(0, selected);
        reset_fixture_with_program(&[
            movw,
            movt,
            a32_vbar_write(0),
            0xe12f_ff1e, // bx lr
        ])
    }

    fn set_relocated_pointer(fixture: &mut VectorFixture, slot: usize, pointer: u32) {
        fixture.write_u32(
            RELOCATED_TABLE + 0x40 + u32::try_from(slot).unwrap() * 4,
            pointer,
        );
    }

    fn ordered_vbar_fixture(first: u32, second: u32) -> VectorFixture {
        let [first_movw, first_movt] = materialize(0, first);
        let [second_movw, second_movt] = materialize(1, second);
        reset_fixture_with_program(&[
            first_movw,
            first_movt,
            a32_vbar_write(0),
            second_movw,
            second_movt,
            a32_vbar_write(1),
            0xe12f_ff1e,
        ])
    }

    fn branching_vbar_fixture() -> VectorFixture {
        let right = RESET_ENTRY + 20;
        let [left_movw, left_movt] = materialize(0, BASE);
        let [right_movw, right_movt] = materialize(1, RELOCATED_TABLE);
        reset_fixture_with_program(&[
            a32_branch(RESET_ENTRY, right, 0x1, false),
            left_movw,
            left_movt,
            a32_vbar_write(0),
            a32_branch(RESET_ENTRY + 16, RESET_ENTRY + 16, 0xe, false),
            right_movw,
            right_movt,
            a32_vbar_write(1),
            a32_branch(RESET_ENTRY + 32, RESET_ENTRY + 32, 0xe, false),
        ])
    }

    fn full_literal_fixture(layout: TargetLayout) -> VectorFixture {
        let mut fixture = VectorFixture {
            base: BASE,
            raw: vec![0; IMAGE_SIZE],
            plan: None,
        };
        let mut targets = EXPECTED_ROLES.map(target_for_role);
        if let TargetLayout::Shared(first, second) = layout {
            targets[role_index(second)] = targets[role_index(first)];
        }
        for (index, target) in targets.into_iter().enumerate() {
            let slot = BASE + u32::try_from(index).unwrap() * 4;
            let literal = fixture.literal_address(index);
            fixture.write_u32(slot, a32_ldr_pc(slot, literal));
            fixture.write_u32(literal, target);
            fixture.write_u32(target, ARM_NOP);
        }
        fixture
    }

    fn vector_fixture(supported: usize, layout: TargetLayout) -> VectorFixture {
        if supported == 8 {
            return full_literal_fixture(layout);
        }
        let mut fixture = VectorFixture {
            base: BASE,
            raw: vec![0; supported * 4 + 1],
            plan: None,
        };
        for index in 0..supported {
            let slot = BASE + u32::try_from(index).unwrap() * 4;
            fixture.write_u32(slot, a32_ldr_pc(slot, BASE + 0x100));
        }
        fixture
    }

    fn copy_entry(index: usize, source: u32, destination: u32, bytes: &[u8]) -> PlannedEntry {
        PlannedEntry {
            index,
            descriptor: Descriptor {
                source,
                destination,
                size: u32::try_from(bytes.len()).unwrap(),
                handler: COPY_HANDLER,
            },
            operation: Operation::Copy,
            compressed_size: None,
            output: PlannedOutput::Bytes(bytes.to_vec()),
        }
    }

    fn zero_entry(index: usize, destination: u32, size: u32) -> PlannedEntry {
        PlannedEntry {
            index,
            descriptor: Descriptor {
                source: 0,
                destination,
                size,
                handler: ZERO_HANDLER,
            },
            operation: Operation::Zero,
            compressed_size: None,
            output: PlannedOutput::ZeroFill,
        }
    }

    fn attach_plan(fixture: &mut VectorFixture, entries: Vec<PlannedEntry>) {
        let logical_output_size = entries
            .iter()
            .map(|entry| u64::from(entry.descriptor.size))
            .sum();
        fixture.plan = Some(LoadPlan {
            image_base: fixture.base,
            image_size: u32::try_from(fixture.raw.len()).unwrap(),
            loader_address: fixture.base + 0x200,
            literal_pair_address: fixture.base + 0x210,
            table_start: fixture.base + 0x220,
            table_end: fixture.base + 0x220 + u32::try_from(entries.len()).unwrap() * 16,
            handlers: HandlerMap {
                null: fixture.base + 0x278,
                copy: COPY_HANDLER,
                decompress1: fixture.base + 0x288,
                zero: ZERO_HANDLER,
            },
            entries,
            logical_output_size,
        });
    }

    fn multi_table_fixture(count: usize, agree: bool) -> (VectorFixture, Vec<u32>) {
        let mut fixture = VectorFixture {
            base: BASE,
            raw: vec![0; 0x1200],
            plan: None,
        };
        let mut addresses = Vec::new();
        for table_index in 0..count {
            let table = BASE + u32::try_from(table_index).unwrap() * 0x200;
            let literals = table + 0x40;
            let target_base = if agree {
                BASE + 0xa00
            } else {
                BASE + 0xa00 + u32::try_from(table_index).unwrap() * 0x40
            };
            let targets =
                std::array::from_fn(|slot| target_base + u32::try_from(slot).unwrap() * 4);
            write_literal_table(&mut fixture.raw, BASE, table, literals, targets);
            addresses.push(table);
        }
        (fixture, addresses)
    }

    #[test]
    fn seven_vector_forms_are_clean_absence() {
        let fixture = vector_fixture(7, TargetLayout::DistinctArm);
        assert_eq!(
            discover(&fixture.runtime(), "00_BOOT", "BOOT").unwrap(),
            None
        );
    }

    #[test]
    fn every_partial_prefix_is_clean_absence_without_resolving_bad_literals() {
        for supported in 0..8 {
            let fixture = vector_fixture(supported, TargetLayout::DistinctArm);
            assert_eq!(
                discover(&fixture.runtime(), "00_BOOT", "BOOT").unwrap(),
                None,
                "prefix length {supported}"
            );
        }
    }

    #[test]
    fn dominating_exact_vbar_confirms_initial_table() {
        let fixture = reset_vbar_fixture(VbarValue::Initial);
        let plan = discover(&fixture.runtime(), "01_MAIN", "MAIN")
            .unwrap()
            .unwrap();

        let RelocationEvidence::ConfirmedInitial {
            selected,
            observations,
        } = plan.relocation
        else {
            panic!("expected confirmed-initial evidence");
        };
        assert_eq!(selected.pc, RESET_ENTRY + 8);
        assert_eq!(selected.isa, RootIsa::Arm);
        assert_eq!(selected.source_register, 0);
        assert_eq!(selected.exact_value, Some(BASE));
        assert_eq!(selected.definitions, [RESET_ENTRY, RESET_ENTRY + 4]);
        assert!(selected.dominates_handoffs);
        assert!(!selected.conditional);
        assert_eq!(observations, [selected]);
    }

    #[test]
    fn proven_relocated_table_contributes_roots() {
        let fixture = reset_vbar_fixture(VbarValue::SecondValidTable);
        let plan = discover(&fixture.runtime(), "01_MAIN", "MAIN")
            .unwrap()
            .unwrap();

        let RelocationEvidence::Relocated {
            selected,
            table_address,
            observations,
        } = plan.relocation
        else {
            panic!("expected relocated evidence");
        };
        assert_eq!(selected.exact_value, Some(RELOCATED_TABLE));
        assert_eq!(table_address, RELOCATED_TABLE);
        assert_eq!(observations, [selected]);
        assert_eq!(plan.tables.len(), 2);
        assert_eq!(plan.roots.len(), 16);
        assert_eq!(plan.applications.len(), 16);
        assert!(
            plan.applications
                .iter()
                .all(|application| application.desired_primary.is_none())
        );
    }

    #[test]
    fn relocated_role_agreement_recomputes_one_global_application_plan() {
        let mut fixture = reset_vbar_fixture(VbarValue::SecondValidTable);
        let initial_targets: [u32; 8] =
            std::array::from_fn(|index| RESET_ENTRY + u32::try_from(index).unwrap() * 0x40);
        for (index, target) in initial_targets.into_iter().enumerate() {
            set_relocated_pointer(&mut fixture, index, target);
        }

        let first = discover(&fixture.runtime(), "01_MAIN", "MAIN")
            .unwrap()
            .unwrap();
        let second = discover(&fixture.runtime(), "01_MAIN", "MAIN")
            .unwrap()
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.tables.len(), 2);
        assert_eq!(first.roots.len(), 8);
        assert_eq!(first.applications.len(), 8);
        let reset = first
            .applications
            .iter()
            .find(|application| application.entry == RESET_ENTRY)
            .unwrap();
        assert_eq!(reset.desired_primary.as_deref(), Some("Reset"));
        assert_eq!(reset.claims.len(), 2);
        assert_eq!(
            reset.role_labels,
            ["exception_reset_40010000", "exception_reset_40011000"]
        );
    }

    #[test]
    fn every_relocated_post_threshold_target_failure_is_malformed() {
        let bad_target = BASE + 0x3000;
        for slot in 0..8 {
            let mut fixture = reset_vbar_fixture(VbarValue::SecondValidTable);
            set_relocated_pointer(&mut fixture, slot, bad_target);
            let result = discover(&fixture.runtime(), "01_MAIN", "MAIN");
            assert!(
                matches!(
                    &result,
                    Err(ExceptionRootError::Malformed { table, context })
                        if *table == RELOCATED_TABLE
                            && context.contains("target instruction")
                ),
                "slot {slot}: {result:?}"
            );
        }
    }

    #[test]
    fn relocated_post_threshold_literal_isa_decode_and_identity_failures_are_malformed() {
        let mut bad_literal = reset_vbar_fixture(VbarValue::SecondValidTable);
        let literal = BASE + RESET_IMAGE_SIZE as u32;
        bad_literal.write_u32(RELOCATED_TABLE, a32_ldr_pc(RELOCATED_TABLE, literal));

        let mut zero_target = reset_vbar_fixture(VbarValue::SecondValidTable);
        let zero = BASE + 0x3000;
        set_relocated_pointer(&mut zero_target, 0, zero);
        attach_plan(&mut zero_target, vec![zero_entry(0, zero, 4)]);

        let mut misaligned = reset_vbar_fixture(VbarValue::SecondValidTable);
        set_relocated_pointer(&mut misaligned, 0, BASE + 0x1802);

        let mut undecodable = reset_vbar_fixture(VbarValue::SecondValidTable);
        let invalid_thumb = BASE + 0x1d00;
        undecodable.write_u16(invalid_thumb, 0xbfe8);
        set_relocated_pointer(&mut undecodable, 0, invalid_thumb | 1);

        let mut cross_isa = reset_vbar_fixture(VbarValue::SecondValidTable);
        set_relocated_pointer(&mut cross_isa, 0, BASE + 0x1800);
        set_relocated_pointer(&mut cross_isa, 1, BASE + 0x1801);

        for (name, fixture) in [
            ("literal", bad_literal),
            ("zero", zero_target),
            ("alignment", misaligned),
            ("decode", undecodable),
            ("identity", cross_isa),
        ] {
            let result = discover(&fixture.runtime(), "01_MAIN", "MAIN");
            assert!(
                matches!(
                    result,
                    Err(ExceptionRootError::Malformed {
                        table: RELOCATED_TABLE,
                        ..
                    })
                ),
                "{name} failure: {result:?}"
            );
        }
    }

    #[test]
    fn conditional_vbar_is_limited_evidence_and_never_selects() {
        let [movw, movt] = materialize(0, BASE);
        let fixture = reset_fixture_with_program(&[
            movw,
            movt,
            a32_vbar_write_with_condition(0, 0x1),
            0xe12f_ff1e,
        ]);
        let plan = discover(&fixture.runtime(), "01_MAIN", "MAIN")
            .unwrap()
            .unwrap();

        let RelocationEvidence::Unresolved { observations } = plan.relocation else {
            panic!("conditional VBAR must remain unresolved");
        };
        assert_eq!(observations.len(), 1);
        assert!(observations[0].conditional);
        assert_eq!(observations[0].exact_value, Some(BASE));
        assert_eq!(plan.tables.len(), 1);
    }

    #[test]
    fn later_conditional_or_unknown_write_blocks_an_earlier_exact_selection() {
        let [initial_movw, initial_movt] = materialize(0, BASE);
        let [relocated_movw, relocated_movt] = materialize(1, RELOCATED_TABLE);
        let conditional = reset_fixture_with_program(&[
            initial_movw,
            initial_movt,
            a32_vbar_write(0),
            relocated_movw,
            relocated_movt,
            a32_vbar_write_with_condition(1, 0x1),
            0xe12f_ff1e,
        ]);
        let unknown = reset_fixture_with_program(&[
            initial_movw,
            initial_movt,
            a32_vbar_write(0),
            a32_vbar_write(2),
            0xe12f_ff1e,
        ]);

        for fixture in [conditional, unknown] {
            let plan = discover(&fixture.runtime(), "01_MAIN", "MAIN")
                .unwrap()
                .unwrap();
            let RelocationEvidence::Unresolved { observations } = plan.relocation else {
                panic!("a potentially later write must block exact selection");
            };
            assert_eq!(observations.len(), 2);
            assert_eq!(plan.tables.len(), 1);
        }
    }

    #[test]
    fn final_exact_write_overwrites_earlier_limited_evidence() {
        let [movw, movt] = materialize(0, BASE);
        let fixture = reset_fixture_with_program(&[
            a32_vbar_write(2),
            movw,
            movt,
            a32_vbar_write(0),
            0xe12f_ff1e,
        ]);
        let plan = discover(&fixture.runtime(), "01_MAIN", "MAIN")
            .unwrap()
            .unwrap();

        let RelocationEvidence::ConfirmedInitial {
            selected,
            observations,
        } = plan.relocation
        else {
            panic!("final exact write must overwrite earlier unknown evidence");
        };
        assert_eq!(selected.pc, RESET_ENTRY + 12);
        assert_eq!(observations.len(), 2);
    }

    #[test]
    fn extension_and_operand_near_misses_are_not_vbar_observations() {
        let [movw, movt] = materialize(0, BASE);
        for transfer in [
            a32_vbar_write_with_condition(0, 0xf), // mcr2 extension form
            0xee0b_0f10,                           // mcr p15, 0, r0, c11, c0, 0
            0xee0c_0f11,                           // mcr p15, 0, r0, c12, c1, 0
        ] {
            let fixture = reset_fixture_with_program(&[movw, movt, transfer, 0xe12f_ff1e]);
            let plan = discover(&fixture.runtime(), "01_MAIN", "MAIN")
                .unwrap()
                .unwrap();
            assert_eq!(plan.relocation, RelocationEvidence::NotObserved);
        }
    }

    #[test]
    fn unknown_vbar_source_is_unresolved_limited_evidence() {
        let fixture = reset_fixture_with_program(&[a32_vbar_write(2), 0xe12f_ff1e]);
        let plan = discover(&fixture.runtime(), "01_MAIN", "MAIN")
            .unwrap()
            .unwrap();

        let RelocationEvidence::Unresolved { observations } = plan.relocation else {
            panic!("unknown VBAR source must remain unresolved");
        };
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].source_register, 2);
        assert_eq!(observations[0].exact_value, None);
        assert!(observations[0].dominates_handoffs);
    }

    #[test]
    fn direct_call_clobbers_vbar_source_on_the_only_retained_fallthrough() {
        let [movw, movt] = materialize(0, BASE);
        let call_pc = RESET_ENTRY + 8;
        let fixture = reset_fixture_with_program(&[
            movw,
            movt,
            a32_branch(call_pc, BASE + 0x1f00, 0xe, true),
            a32_vbar_write(0),
            0xe12f_ff1e,
        ]);
        let plan = discover(&fixture.runtime(), "01_MAIN", "MAIN")
            .unwrap()
            .unwrap();

        let RelocationEvidence::Unresolved { observations } = plan.relocation else {
            panic!("call-clobbered VBAR source must remain unresolved");
        };
        assert_eq!(observations[0].exact_value, None);
        assert!(!observations[0].dominates_handoffs);
    }

    #[test]
    fn exact_vbar_after_startup_call_does_not_dominate_the_handoff() {
        let [movw, movt] = materialize(4, BASE);
        let fixture = reset_fixture_with_program(&[
            a32_branch(RESET_ENTRY, BASE + 0x1f00, 0xe, true),
            movw,
            movt,
            a32_vbar_write(4),
            0xe12f_ff1e,
        ]);
        let plan = discover(&fixture.runtime(), "01_MAIN", "MAIN")
            .unwrap()
            .unwrap();

        let RelocationEvidence::Unresolved { observations } = plan.relocation else {
            panic!("post-handoff VBAR must remain unresolved");
        };
        assert_eq!(observations[0].exact_value, Some(BASE));
        assert!(!observations[0].dominates_handoffs);
    }

    #[test]
    fn outside_zero_fill_and_mapped_non_table_values_are_unresolved() {
        let cases = [0x5000_0000, BASE + 0x3000, BASE + 0x1c00];
        for (index, value) in cases.into_iter().enumerate() {
            let [movw, movt] = materialize(0, value);
            let mut fixture =
                reset_fixture_with_program(&[movw, movt, a32_vbar_write(0), 0xe12f_ff1e]);
            if index == 1 {
                attach_plan(&mut fixture, vec![zero_entry(0, value, TABLE_SIZE)]);
            }
            let plan = discover(&fixture.runtime(), "01_MAIN", "MAIN")
                .unwrap()
                .unwrap();
            let RelocationEvidence::Unresolved { observations } = plan.relocation else {
                panic!("value {value:#010x} must remain unresolved");
            };
            assert_eq!(observations[0].exact_value, Some(value));
            assert_eq!(plan.tables.len(), 1);
        }
    }

    #[test]
    fn completed_return_prefix_without_vbar_is_not_observed() {
        let fixture = reset_fixture_with_program(&[0xe12f_ff1e]);
        let plan = discover(&fixture.runtime(), "01_MAIN", "MAIN")
            .unwrap()
            .unwrap();

        assert_eq!(plan.relocation, RelocationEvidence::NotObserved);
    }

    #[test]
    fn thumb_reset_prefix_uses_the_table_selected_isa() {
        let fixture = thumb_reset_fixture(BASE, &THUMB_BX_LR.to_le_bytes());
        let plan = discover(&fixture.runtime(), "01_MAIN", "MAIN")
            .unwrap()
            .unwrap();

        let RelocationEvidence::ConfirmedInitial { selected, .. } = plan.relocation else {
            panic!("Thumb reset prefix must confirm the initial table");
        };
        assert_eq!(selected.pc, RESET_ENTRY + 8);
        assert_eq!(selected.isa, RootIsa::Thumb);
        assert_eq!(selected.exact_value, Some(BASE));
    }

    #[test]
    fn decode_unmapped_indirect_and_exception_boundaries_are_incomplete() {
        let [movw, movt] = materialize(0, BASE);
        let branch_pc = RESET_ENTRY + 12;
        let cases = [
            (
                vec![movw, movt, a32_vbar_write(0), 0xe12f_ff11],
                crate::semantic_cfg::BoundaryKind::Indirect,
            ),
            (
                vec![movw, movt, a32_vbar_write(0), 0xef00_0000],
                crate::semantic_cfg::BoundaryKind::ExceptionCall,
            ),
            (
                vec![
                    movw,
                    movt,
                    a32_vbar_write(0),
                    a32_branch(branch_pc, BASE + 0x3000, 0xe, false),
                ],
                crate::semantic_cfg::BoundaryKind::Unmapped,
            ),
        ];
        for (program, expected) in cases {
            let fixture = reset_fixture_with_program(&program);
            let plan = discover(&fixture.runtime(), "01_MAIN", "MAIN")
                .unwrap()
                .unwrap();
            let RelocationEvidence::AnalysisIncomplete {
                observations,
                handoffs,
                reason,
            } = plan.relocation
            else {
                panic!("{expected:?} boundary must make analysis incomplete");
            };
            assert_eq!(observations[0].exact_value, Some(BASE));
            assert!(handoffs.iter().any(|handoff| handoff.kind == expected));
            assert_eq!(reason, None);
            assert_eq!(plan.tables.len(), 1);
        }

        let fixture = thumb_reset_fixture(BASE, &0xbfe8u16.to_le_bytes());
        let plan = discover(&fixture.runtime(), "01_MAIN", "MAIN")
            .unwrap()
            .unwrap();
        let RelocationEvidence::AnalysisIncomplete { handoffs, .. } = plan.relocation else {
            panic!("decode barrier must make analysis incomplete");
        };
        assert!(
            handoffs.iter().any(|handoff| {
                handoff.kind == crate::semantic_cfg::BoundaryKind::DecodeFailure
            })
        );
    }

    #[test]
    fn reset_cfg_default_byte_budget_is_a_typed_resource_failure() {
        let mut fixture = reset_tables_fixture();
        let attempted = 64 * 1024 / 4 + 1;
        fixture
            .raw
            .resize((RESET_ENTRY - BASE) as usize + attempted * 4, 0);
        write_reset_program(&mut fixture, &vec![ARM_NOP; attempted]);

        assert!(matches!(
            discover(&fixture.runtime(), "01_MAIN", "MAIN"),
            Err(ExceptionRootError::ResourceLimit {
                what: "charged bytes",
                actual: 65_540,
                limit: 65_536,
            })
        ));
    }

    #[test]
    fn strict_dominance_order_selects_the_final_distinct_write() {
        let fixture = ordered_vbar_fixture(RELOCATED_TABLE, BASE);
        let plan = discover(&fixture.runtime(), "01_MAIN", "MAIN")
            .unwrap()
            .unwrap();
        let RelocationEvidence::ConfirmedInitial {
            selected,
            observations,
        } = plan.relocation
        else {
            panic!("final initial-table write must win strict order");
        };
        assert_eq!(selected.pc, RESET_ENTRY + 20);
        assert_eq!(selected.exact_value, Some(BASE));
        assert_eq!(observations.len(), 2);
        assert_eq!(plan.tables.len(), 1);

        let fixture = ordered_vbar_fixture(BASE, RELOCATED_TABLE);
        let plan = discover(&fixture.runtime(), "01_MAIN", "MAIN")
            .unwrap()
            .unwrap();
        let RelocationEvidence::Relocated {
            selected,
            table_address,
            ..
        } = plan.relocation
        else {
            panic!("final relocated-table write must win strict order");
        };
        assert_eq!(selected.pc, RESET_ENTRY + 20);
        assert_eq!(table_address, RELOCATED_TABLE);
        assert_eq!(plan.tables.len(), 2);
    }

    #[test]
    fn incomparable_distinct_selecting_values_are_ambiguous() {
        let error = discover(&branching_vbar_fixture().runtime(), "01_MAIN", "MAIN").unwrap_err();
        assert_eq!(
            error,
            ExceptionRootError::Ambiguous {
                values: vec![BASE, RELOCATED_TABLE]
            }
        );
    }

    #[test]
    fn vbar_observation_cap_accepts_sixty_four_and_rejects_sixty_five() {
        let [movw, movt] = materialize(0, BASE);
        let mut program = vec![movw, movt];
        program.extend(std::iter::repeat_n(a32_vbar_write(0), 64));
        program.push(0xe12f_ff1e);
        let fixture = reset_fixture_with_program(&program);
        let plan = discover(&fixture.runtime(), "01_MAIN", "MAIN")
            .unwrap()
            .unwrap();
        let RelocationEvidence::ConfirmedInitial {
            selected,
            observations,
        } = plan.relocation
        else {
            panic!("64 exact observations must remain valid");
        };
        assert_eq!(observations.len(), 64);
        assert_eq!(selected.pc, RESET_ENTRY + 8 + 63 * 4);

        program.insert(program.len() - 1, a32_vbar_write(0));
        let fixture = reset_fixture_with_program(&program);
        assert!(matches!(
            discover(&fixture.runtime(), "01_MAIN", "MAIN"),
            Err(ExceptionRootError::ResourceLimit {
                what: "VBAR write observations",
                actual: 65,
                limit: 64,
            })
        ));
    }

    #[test]
    fn two_mod_four_image_base_is_clean_absence_before_slot_decode() {
        let base = BASE + 2;
        let mut fixture = VectorFixture {
            base,
            raw: vec![0; IMAGE_SIZE],
            plan: None,
        };
        for index in 0..8 {
            let offset = u32::try_from(index).unwrap() * 4;
            let slot = base + offset;
            let literal = BASE + 0x40 + offset;
            let target = ARM_TARGET_START + offset;
            fixture.write_u32(slot, a32_ldr_pc(slot, literal));
            fixture.write_u32(literal, target);
            fixture.write_u32(target, ARM_NOP);
        }

        assert_eq!(
            discover(&fixture.runtime(), "01_MAIN", "MAIN").unwrap(),
            None
        );
    }

    #[test]
    fn complete_literal_table_yields_ordered_roots() {
        let fixture = vector_fixture(8, TargetLayout::DistinctArm);
        let runtime = fixture.runtime();
        let plan = discover(&runtime, "01_MAIN", "MAIN").unwrap().unwrap();

        assert_eq!(plan.image_label, "01_MAIN");
        assert_eq!(plan.toc_name, "MAIN");
        assert_eq!(plan.image_base, BASE);
        assert_eq!(plan.image_size, IMAGE_SIZE as u32);
        assert_eq!(plan.initial_table.address, runtime.image_bounds().0);
        assert_eq!(plan.initial_table.slots.len(), 8);
        assert_eq!(
            plan.initial_table
                .slots
                .iter()
                .map(|slot| slot.role)
                .collect::<Vec<_>>(),
            EXPECTED_ROLES
        );
        assert_eq!(plan.roots.len(), 8);
        assert_eq!(
            plan.roots.iter().map(|root| root.entry).collect::<Vec<_>>(),
            (0..8)
                .map(|index| ARM_TARGET_START + index * 4)
                .collect::<Vec<_>>()
        );
        assert!(matches!(
            plan.relocation,
            RelocationEvidence::AnalysisIncomplete { .. }
        ));
    }

    #[test]
    fn complete_table_authenticates_slots_roots_and_storage() {
        let fixture = full_literal_fixture(TargetLayout::DistinctArm);
        let plan = discover(&fixture.runtime(), "01_MAIN", "MAIN")
            .unwrap()
            .unwrap();
        let table_bytes = &fixture.raw[..TABLE_SIZE as usize];

        assert_eq!(
            plan.initial_table.blake3,
            *blake3::hash(table_bytes).as_bytes()
        );
        assert_eq!(
            plan.initial_table.storage,
            [StorageSpan {
                kind: StorageKind::Raw,
                address: BASE,
                size: TABLE_SIZE,
                scatter_entry: None,
            }]
        );
        assert_eq!(
            plan.initial_table.slots[0].slot_blake3,
            *blake3::hash(&fixture.raw[..4]).as_bytes()
        );
        assert_eq!(
            plan.roots[0].instruction_blake3,
            *blake3::hash(&ARM_NOP.to_le_bytes()).as_bytes()
        );
        assert_eq!(
            plan.roots[0].storage,
            [StorageSpan {
                kind: StorageKind::Raw,
                address: ARM_TARGET_START,
                size: 4,
                scatter_entry: None,
            }]
        );
    }

    #[test]
    fn shared_same_isa_handler_is_one_root_with_two_roles() {
        let fixture = vector_fixture(
            8,
            TargetLayout::Shared(ExceptionRole::Irq, ExceptionRole::Fiq),
        );
        let plan = discover(&fixture.runtime(), "01_MAIN", "MAIN")
            .unwrap()
            .unwrap();

        assert_eq!(plan.roots.len(), 7);
        let shared = plan.roots.last().unwrap();
        assert_eq!(shared.entry, target_for_role(ExceptionRole::Irq));
        assert_eq!(
            shared
                .claims
                .iter()
                .map(|claim| claim.role)
                .collect::<Vec<_>>(),
            [ExceptionRole::Irq, ExceptionRole::Fiq]
        );
        assert_eq!(plan.applications.last().unwrap().desired_primary, None);
    }

    #[test]
    fn conditional_linking_and_writeback_forms_never_cross_threshold() {
        let supported = full_literal_fixture(TargetLayout::DistinctArm);
        let slot = BASE;
        for invalid in [
            a32_branch(slot, ARM_TARGET_START, 0x1, false),
            a32_branch(slot, ARM_TARGET_START, 0xe, true),
            0x159f_f038, // ldrne pc, [pc, #0x38]
            0xe49f_f004, // ldr pc, [pc], #4 (post-indexed)
            0xe5bf_f038, // ldr pc, [pc, #0x38]! (writeback)
        ] {
            let mut fixture = VectorFixture {
                base: supported.base,
                raw: supported.raw.clone(),
                plan: None,
            };
            fixture.write_u32(slot, invalid);
            assert_eq!(
                discover(&fixture.runtime(), "01_MAIN", "MAIN").unwrap(),
                None,
                "encoding {invalid:#010x}"
            );
        }
    }

    #[test]
    fn register_indirect_pc_transfer_never_crosses_threshold() {
        let encoding = 0xe591_f000u32; // ldr pc, [r1]
        let decoder = PureRustDecoder;
        let mut state = decoder.begin_range(RootIsa::Arm.decode_isa());
        let instruction = decoder
            .decode_one(
                &mut state,
                RootIsa::Arm.decode_isa(),
                BASE,
                &encoding.to_le_bytes(),
            )
            .unwrap();
        assert!(matches!(instruction.flow, ControlFlow::Barrier));
        let ValueEffect::Memory(memory) = &instruction.effect else {
            panic!("register-indirect PC load lost its memory effect");
        };
        assert_eq!(memory.transfers.len(), 1);
        assert_eq!(
            memory.transfers[0].address.base,
            AddressBase::Register(Register(1))
        );
        assert_eq!(memory.transfers[0].value, Some(Register(15)));

        let mut fixture = full_literal_fixture(TargetLayout::DistinctArm);
        fixture.write_u32(BASE, encoding);
        assert_eq!(
            discover(&fixture.runtime(), "01_MAIN", "MAIN").unwrap(),
            None
        );
    }

    #[test]
    fn computed_pc_write_never_crosses_threshold() {
        let encoding = 0xe1a0_f001u32; // mov pc, r1
        let decoder = PureRustDecoder;
        let mut state = decoder.begin_range(RootIsa::Arm.decode_isa());
        let instruction = decoder
            .decode_one(
                &mut state,
                RootIsa::Arm.decode_isa(),
                BASE,
                &encoding.to_le_bytes(),
            )
            .unwrap();
        assert!(matches!(instruction.flow, ControlFlow::Barrier));
        assert_eq!(
            instruction.effect,
            ValueEffect::RegisterWrite {
                dst: Register(15),
                value: ValueExpr::Register(Register(1)),
            }
        );

        let mut fixture = full_literal_fixture(TargetLayout::DistinctArm);
        fixture.write_u32(BASE, encoding);
        assert_eq!(
            discover(&fixture.runtime(), "01_MAIN", "MAIN").unwrap(),
            None
        );
    }

    #[test]
    fn return_never_crosses_threshold() {
        let encoding = 0xe12f_ff1eu32; // bx lr
        let decoder = PureRustDecoder;
        let mut state = decoder.begin_range(RootIsa::Arm.decode_isa());
        let instruction = decoder
            .decode_one(
                &mut state,
                RootIsa::Arm.decode_isa(),
                BASE,
                &encoding.to_le_bytes(),
            )
            .unwrap();
        assert!(matches!(instruction.flow, ControlFlow::Return));
        assert_eq!(instruction.effect, ValueEffect::None);
        assert_eq!(instruction.reads, [Register(14)].into_iter().collect());

        let mut fixture = full_literal_fixture(TargetLayout::DistinctArm);
        fixture.write_u32(BASE, encoding);
        assert_eq!(
            discover(&fixture.runtime(), "01_MAIN", "MAIN").unwrap(),
            None
        );
    }

    #[test]
    fn exception_call_never_crosses_threshold() {
        let encoding = 0xef00_0000u32; // svc #0
        let decoder = PureRustDecoder;
        let mut state = decoder.begin_range(RootIsa::Arm.decode_isa());
        let instruction = decoder
            .decode_one(
                &mut state,
                RootIsa::Arm.decode_isa(),
                BASE,
                &encoding.to_le_bytes(),
            )
            .unwrap();
        assert!(matches!(instruction.flow, ControlFlow::ExceptionCall));
        assert_eq!(instruction.effect, ValueEffect::None);
        assert!(instruction.reads.is_empty());
        assert!(instruction.writes.is_empty());

        let mut fixture = full_literal_fixture(TargetLayout::DistinctArm);
        fixture.write_u32(BASE, encoding);
        assert_eq!(
            discover(&fixture.runtime(), "01_MAIN", "MAIN").unwrap(),
            None
        );
    }

    #[test]
    fn sole_initial_candidate_is_the_image_base() {
        let mut fixture = VectorFixture {
            base: BASE,
            raw: vec![0; 0x800],
            plan: None,
        };
        fixture.write_u32(BASE, ARM_NOP);
        let table = BASE + 0x200;
        let targets = std::array::from_fn(|index| BASE + 0x500 + index as u32 * 4);
        write_literal_table(&mut fixture.raw, BASE, table, table + 0x40, targets);

        assert_eq!(
            discover(&fixture.runtime(), "01_MAIN", "MAIN").unwrap(),
            None
        );
    }

    #[test]
    fn mixed_branch_and_literal_forms_resolve_without_isa_fallback() {
        let mut fixture = full_literal_fixture(TargetLayout::DistinctArm);
        let thumb_target = BASE + 0x182;
        fixture.write_u16(thumb_target, THUMB_BX_LR);
        fixture.set_pointer(1, thumb_target | 1);
        fixture.write_u32(
            BASE,
            a32_branch(BASE, target_for_role(ExceptionRole::Reset), 0xe, false),
        );
        fixture.write_u32(BASE + 7 * 4, a32_branch(BASE + 7 * 4, BASE, 0xe, false));

        let plan = discover(&fixture.runtime(), "01_MAIN", "MAIN")
            .unwrap()
            .unwrap();
        assert_eq!(plan.initial_table.slots[0].form, SlotForm::DirectBranch);
        assert_eq!(
            plan.initial_table.slots[1].form,
            SlotForm::LiteralLoad {
                literal_address: literal_address(BASE, 1),
            }
        );
        assert_eq!(plan.initial_table.slots[1].isa, RootIsa::Thumb);
        assert_eq!(plan.initial_table.slots[1].entry, thumb_target);
        assert_eq!(plan.initial_table.slots[7].form, SlotForm::DirectBranch);
        assert_eq!(plan.initial_table.slots[7].entry, BASE);
    }

    #[test]
    fn positive_and_negative_literal_offsets_preserve_exact_addresses() {
        let fixture = full_literal_fixture(TargetLayout::DistinctArm);
        let plan = discover(&fixture.runtime(), "01_MAIN", "MAIN")
            .unwrap()
            .unwrap();

        assert_eq!(
            plan.initial_table.slots[0].form,
            SlotForm::LiteralLoad {
                literal_address: BASE + 0x40,
            }
        );
        assert_eq!(
            plan.initial_table.slots[7].form,
            SlotForm::LiteralLoad {
                literal_address: BASE + 0x20,
            }
        );
    }

    #[test]
    fn every_post_threshold_literal_failure_is_typed_by_slot() {
        let bad_literal = BASE + IMAGE_SIZE as u32;
        for index in 0..8 {
            let mut fixture = full_literal_fixture(TargetLayout::DistinctArm);
            let slot = BASE + u32::try_from(index).unwrap() * 4;
            fixture.write_u32(slot, a32_ldr_pc(slot, bad_literal));
            assert!(
                matches!(
                    discover(&fixture.runtime(), "01_MAIN", "MAIN"),
                    Err(ExceptionRootError::Runtime {
                        address,
                        size: 4,
                        ..
                    }) if address == bad_literal
                ),
                "slot {index}"
            );
        }
    }

    #[test]
    fn every_post_threshold_target_failure_is_typed_by_slot() {
        let bad_target = BASE + IMAGE_SIZE as u32 + 0x100;
        for index in 0..8 {
            let mut fixture = full_literal_fixture(TargetLayout::DistinctArm);
            fixture.set_pointer(index, bad_target);
            assert!(
                matches!(
                    discover(&fixture.runtime(), "01_MAIN", "MAIN"),
                    Err(ExceptionRootError::Runtime {
                        address,
                        size: 4,
                        ..
                    }) if address == bad_target
                ),
                "slot {index}"
            );
        }
    }

    #[test]
    fn literal_address_wrap_after_threshold_is_malformed() {
        let base = (u32::MAX - TABLE_SIZE) & !3;
        let mut fixture = VectorFixture {
            base,
            raw: vec![0; TABLE_SIZE as usize],
            plan: None,
        };
        for index in 0..8 {
            fixture.write_u32(base + index * 4, 0xe59f_f100);
        }

        let result = discover(&fixture.runtime(), "00_BOOT", "BOOT");
        assert!(
            matches!(
                &result,
                Err(ExceptionRootError::Malformed { table, context })
                    if *table == base && context.contains("wrap")
            ),
            "{result:?}"
        );
    }

    #[test]
    fn branch_target_wrap_after_threshold_is_malformed() {
        let base = (u32::MAX - TABLE_SIZE) & !3;
        let mut fixture = VectorFixture {
            base,
            raw: vec![0; TABLE_SIZE as usize],
            plan: None,
        };
        for index in 0..8 {
            fixture.write_u32(base + index * 4, 0xeaff_fffe);
        }

        let result = discover(&fixture.runtime(), "00_BOOT", "BOOT");
        assert!(
            matches!(
                &result,
                Err(ExceptionRootError::Malformed { table, context })
                    if *table == base && context.contains("wrap")
            ),
            "{result:?}"
        );
    }

    #[test]
    fn zero_fill_literal_is_not_pointer_evidence() {
        let mut fixture = full_literal_fixture(TargetLayout::DistinctArm);
        let zero = BASE + IMAGE_SIZE as u32;
        fixture.write_u32(BASE, a32_ldr_pc(BASE, zero));
        attach_plan(&mut fixture, vec![zero_entry(0, zero, 4)]);

        assert!(matches!(
            discover(&fixture.runtime(), "01_MAIN", "MAIN"),
            Err(ExceptionRootError::Runtime {
                address,
                size: 4,
                ..
            }) if address == zero
        ));
    }

    #[test]
    fn zero_fill_target_is_not_executable_evidence() {
        let mut fixture = full_literal_fixture(TargetLayout::DistinctArm);
        let zero = BASE + IMAGE_SIZE as u32;
        fixture.set_pointer(0, zero);
        attach_plan(&mut fixture, vec![zero_entry(0, zero, 4)]);

        assert!(matches!(
            discover(&fixture.runtime(), "01_MAIN", "MAIN"),
            Err(ExceptionRootError::Runtime {
                address,
                size: 4,
                ..
            }) if address == zero
        ));
    }

    #[test]
    fn raw_and_scatter_targets_retain_exact_storage_provenance() {
        let mut fixture = full_literal_fixture(TargetLayout::DistinctArm);
        let source_arm = BASE + 0x2a0;
        let source_thumb = BASE + 0x2a4;
        let scatter_arm = BASE + 0x1000;
        let scatter_thumb = BASE + 0x1102;
        fixture.write_u32(source_arm, ARM_NOP);
        fixture.write_u16(source_thumb, THUMB_BX_LR);
        fixture.set_pointer(0, scatter_arm);
        fixture.set_pointer(1, scatter_thumb | 1);
        attach_plan(
            &mut fixture,
            vec![
                copy_entry(0, source_arm, scatter_arm, &ARM_NOP.to_le_bytes()),
                copy_entry(1, source_thumb, scatter_thumb, &THUMB_BX_LR.to_le_bytes()),
            ],
        );

        let plan = discover(&fixture.runtime(), "01_MAIN", "MAIN")
            .unwrap()
            .unwrap();
        let arm = plan
            .roots
            .iter()
            .find(|root| root.entry == scatter_arm)
            .unwrap();
        let thumb = plan
            .roots
            .iter()
            .find(|root| root.entry == scatter_thumb)
            .unwrap();
        assert_eq!(arm.isa, RootIsa::Arm);
        assert_eq!(arm.instruction_size, 4);
        assert_eq!(
            arm.storage,
            [StorageSpan {
                kind: StorageKind::ScatterBytes,
                address: scatter_arm,
                size: 4,
                scatter_entry: Some(0),
            }]
        );
        assert_eq!(thumb.isa, RootIsa::Thumb);
        assert_eq!(thumb.instruction_size, 2);
        assert_eq!(thumb.entry % 4, 2);
        assert_eq!(
            thumb.storage,
            [StorageSpan {
                kind: StorageKind::ScatterBytes,
                address: scatter_thumb,
                size: 2,
                scatter_entry: Some(1),
            }]
        );
    }

    #[test]
    fn arm_target_at_two_mod_four_is_rejected_without_thumb_fallback() {
        let mut fixture = full_literal_fixture(TargetLayout::DistinctArm);
        let misaligned = ARM_TARGET_START + 2;
        fixture.set_pointer(0, misaligned);

        assert!(matches!(
            discover(&fixture.runtime(), "01_MAIN", "MAIN"),
            Err(ExceptionRootError::Decode {
                pc,
                isa: RootIsa::Arm,
                ..
            }) if pc == misaligned
        ));
    }

    #[test]
    fn selected_isa_decode_failure_does_not_fall_back() {
        let mut fixture = full_literal_fixture(TargetLayout::DistinctArm);
        let target = BASE + 0x1c0;
        fixture.write_u16(target, 0xbfe8); // Architecturally invalid IT AL.
        fixture.set_pointer(0, target | 1);

        assert!(matches!(
            discover(&fixture.runtime(), "01_MAIN", "MAIN"),
            Err(ExceptionRootError::Decode {
                pc,
                isa: RootIsa::Thumb,
                ..
            }) if pc == target
        ));
    }

    #[test]
    fn arm_and_thumb_alias_at_one_normalized_address_is_ambiguous() {
        let mut fixture = full_literal_fixture(TargetLayout::DistinctArm);
        let target = ARM_TARGET_START;
        fixture.set_pointer(0, target);
        fixture.set_pointer(1, target | 1);

        assert_eq!(
            discover(&fixture.runtime(), "01_MAIN", "MAIN").unwrap_err(),
            ExceptionRootError::Ambiguous {
                values: vec![target]
            }
        );
    }

    #[test]
    fn exact_role_labels_and_conservative_primaries_are_allocated() {
        let fixture =
            full_literal_fixture(TargetLayout::Shared(ExceptionRole::Irq, ExceptionRole::Fiq));
        let plan = discover(&fixture.runtime(), "01_MAIN", "MAIN")
            .unwrap()
            .unwrap();
        let reset = plan
            .applications
            .iter()
            .find(|application| application.entry == ARM_TARGET_START)
            .unwrap();
        let shared = plan.applications.last().unwrap();

        assert_eq!(reset.desired_primary.as_deref(), Some("Reset"));
        assert_eq!(reset.role_labels, ["exception_reset_40010000"]);
        assert_eq!(shared.desired_primary, None);
        assert_eq!(
            shared.role_labels,
            ["exception_irq_40010000", "exception_fiq_40010000"]
        );
    }

    #[test]
    fn cross_table_role_disagreement_suppresses_both_primaries() {
        let (fixture, addresses) = multi_table_fixture(2, false);
        let runtime = fixture.runtime();
        let initial = validate_table(&runtime, addresses[0], VectorTableKind::Initial)
            .unwrap()
            .unwrap();
        let relocated = validate_table(&runtime, addresses[1], VectorTableKind::Relocated)
            .unwrap()
            .unwrap();
        let (_, applications) = build_roots_and_applications(&[initial, relocated]).unwrap();
        let reset_applications = applications
            .iter()
            .filter(|application| {
                application
                    .claims
                    .iter()
                    .any(|claim| claim.role == ExceptionRole::Reset)
            })
            .collect::<Vec<_>>();

        assert_eq!(reset_applications.len(), 2);
        assert!(
            reset_applications
                .iter()
                .all(|application| application.desired_primary.is_none())
        );
    }

    #[test]
    fn cross_table_role_agreement_keeps_one_primary_and_two_labels() {
        let (fixture, addresses) = multi_table_fixture(2, true);
        let runtime = fixture.runtime();
        let initial = validate_table(&runtime, addresses[0], VectorTableKind::Initial)
            .unwrap()
            .unwrap();
        let relocated = validate_table(&runtime, addresses[1], VectorTableKind::Relocated)
            .unwrap()
            .unwrap();
        let (_, applications) = build_roots_and_applications(&[initial, relocated]).unwrap();
        let reset = applications
            .iter()
            .find(|application| application.entry == BASE + 0xa00)
            .unwrap();

        assert_eq!(reset.desired_primary.as_deref(), Some("Reset"));
        assert_eq!(
            reset.role_labels,
            ["exception_reset_40010000", "exception_reset_40010200"]
        );
    }

    #[test]
    fn duplicate_table_addresses_are_ambiguous_before_label_allocation() {
        let fixture = full_literal_fixture(TargetLayout::DistinctArm);
        let runtime = fixture.runtime();
        let initial = validate_table(&runtime, BASE, VectorTableKind::Initial)
            .unwrap()
            .unwrap();
        let mut duplicate = initial.clone();
        duplicate.kind = VectorTableKind::Relocated;

        assert_eq!(
            assemble_plan(
                &runtime,
                "01_MAIN",
                "MAIN",
                initial.clone(),
                vec![initial, duplicate],
                RelocationEvidence::NotObserved,
            )
            .unwrap_err(),
            ExceptionRootError::Ambiguous { values: vec![BASE] }
        );
    }

    #[test]
    fn table_limit_rejects_a_third_complete_table() {
        let (fixture, addresses) = multi_table_fixture(MAX_TABLES + 1, false);
        let runtime = fixture.runtime();
        let mut tables = Vec::new();
        for (index, address) in addresses.into_iter().enumerate() {
            let kind = if index == 0 {
                VectorTableKind::Initial
            } else {
                VectorTableKind::Relocated
            };
            tables.push(validate_table(&runtime, address, kind).unwrap().unwrap());
        }

        assert!(matches!(
            assemble_plan(
                &runtime,
                "01_MAIN",
                "MAIN",
                tables[0].clone(),
                tables,
                RelocationEvidence::NotObserved,
            ),
            Err(ExceptionRootError::ResourceLimit {
                what: "vector tables",
                actual: 3,
                limit: 2,
            })
        ));
    }

    #[test]
    fn root_limit_rejects_the_seventeenth_distinct_identity() {
        let (fixture, addresses) = multi_table_fixture(3, false);
        let runtime = fixture.runtime();
        let tables = addresses
            .into_iter()
            .enumerate()
            .map(|(index, address)| {
                validate_table(
                    &runtime,
                    address,
                    if index == 0 {
                        VectorTableKind::Initial
                    } else {
                        VectorTableKind::Relocated
                    },
                )
                .unwrap()
                .unwrap()
            })
            .collect::<Vec<_>>();

        assert!(matches!(
            build_roots_and_applications(&tables),
            Err(ExceptionRootError::ResourceLimit {
                what: "exception roots",
                actual,
                limit,
            }) if actual == (MAX_ROOTS + 1) as u64 && limit == MAX_ROOTS as u64
        ));
    }

    #[test]
    fn roots_claims_and_applications_are_deterministic_and_address_sorted() {
        let mut fixture = full_literal_fixture(TargetLayout::DistinctArm);
        let descending = [
            BASE + 0x1e0,
            BASE + 0x1d0,
            BASE + 0x1c0,
            BASE + 0x1b0,
            BASE + 0x1a0,
            BASE + 0x190,
            BASE + 0x180,
            BASE + 0x170,
        ];
        for (index, target) in descending.into_iter().enumerate() {
            fixture.set_pointer(index, target);
            fixture.write_u32(target, ARM_NOP);
        }

        let first = discover(&fixture.runtime(), "01_MAIN", "MAIN")
            .unwrap()
            .unwrap();
        let second = discover(&fixture.runtime(), "01_MAIN", "MAIN")
            .unwrap()
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(
            first
                .roots
                .iter()
                .map(|root| root.entry)
                .collect::<Vec<_>>(),
            [
                BASE + 0x170,
                BASE + 0x180,
                BASE + 0x190,
                BASE + 0x1a0,
                BASE + 0x1b0,
                BASE + 0x1c0,
                BASE + 0x1d0,
                BASE + 0x1e0,
            ]
        );
        assert_eq!(
            first
                .applications
                .iter()
                .map(|application| application.entry)
                .collect::<Vec<_>>(),
            first
                .roots
                .iter()
                .map(|root| root.entry)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            first
                .roots
                .iter()
                .flat_map(|root| root.claims.iter().map(|claim| claim.role))
                .collect::<Vec<_>>(),
            EXPECTED_ROLES.into_iter().rev().collect::<Vec<_>>()
        );
    }
}
