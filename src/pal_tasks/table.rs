// Descriptor-v1 table validation over one initializer candidate: the
// first-slot plausibility probe, slot parsing with exact hashes and
// storage provenance, architectural entry validation, and the
// deterministic label/application allocator. `validate_candidate`
// returns the plan core; the discovery boundary in `discover`
// assembles the final `TaskPlan`.

use crate::arm32::{InstructionDecoder, PureRustDecoder, ValueEffect};
use crate::error::Error;
use crate::pal_tasks::{
    CandidateBudget, DESCRIPTOR_PROJECTION_OFFSET, InitializerCandidate,
    MAX_ENTRY_INSTRUCTION_BYTES, MAX_SYMBOL_LEAF_BYTES, MAX_TABLE_CAPACITY, MAX_TABLE_STRIDE,
    MAX_TASK_NAME_BYTES, PalTaskError, TASK_NAME_READ_BYTES, TaskApplication, TaskIsa,
    TaskLabelApplication, TaskRecord, TaskTable, TerminalRecord,
};
use crate::runtime_image::{RuntimeImage, StorageSpan};
use std::collections::{BTreeMap, BTreeSet};

/// The table plan core produced by one successful validation.
pub(super) struct ValidatedTable {
    pub table: TaskTable,
    pub tasks: Vec<TaskRecord>,
    pub applications: Vec<TaskApplication>,
    pub terminal: TerminalRecord,
}

/// The descriptor-v1 field offsets derived from the discovered name
/// field under checked arithmetic.
struct DescriptorOffsets {
    priority: u32,
    stack_size: u32,
    entry: u32,
    callback: u32,
    unknown_pointer: u32,
}

fn descriptor_offsets(name_offset: u32) -> Option<DescriptorOffsets> {
    Some(DescriptorOffsets {
        priority: name_offset.checked_add(4)?,
        stack_size: name_offset.checked_add(8)?,
        entry: name_offset.checked_add(12)?,
        callback: name_offset.checked_add(16)?,
        unknown_pointer: name_offset.checked_add(20)?,
    })
}

/// Map one `RuntimeImage` failure: a host or medium failure is the
/// typed runtime error; every mapping/extent failure below becomes the
/// caller's contextual rejection.
fn is_runtime_failure(error: &Error) -> bool {
    matches!(error, Error::Io(_))
}

fn runtime_failure(label: &str, address: u32, size: u32, error: &Error) -> PalTaskError {
    PalTaskError::Runtime {
        address,
        size,
        reason: format!("{label}: {error}"),
    }
}

/// Validate one initializer candidate's table. `Ok(None)` is the
/// pre-threshold miss (the first slot is not readable with nonzero
/// name and entry pointers); every failure after the threshold is a
/// typed contextual error. Slot bytes hashed, bounded name reads, and
/// entry instruction bytes are charged against the shared
/// non-refundable budget before the work runs.
pub(super) fn validate_candidate(
    image: &RuntimeImage<'_>,
    label: &str,
    candidate: &InitializerCandidate,
    budget: &mut CandidateBudget,
) -> std::result::Result<Option<ValidatedTable>, PalTaskError> {
    let geometry = candidate.geometry;
    let initializer = candidate.evidence.cfg_entry;
    let malformed = |context: String| PalTaskError::Malformed {
        initializer,
        context,
    };
    // Geometry that cannot even address the descriptor fields is the
    // same pre-threshold class as the projection gate.
    let Some(offsets) = descriptor_offsets(geometry.name_offset) else {
        return Ok(None);
    };
    let Some(name_field) = geometry.slot_base.checked_add(geometry.name_offset) else {
        return Ok(None);
    };
    let Some(entry_field) = geometry.slot_base.checked_add(offsets.entry) else {
        return Ok(None);
    };
    let Some(name_pointer) = probe_word(image, label, name_field)? else {
        return Ok(None);
    };
    let Some(entry_pointer) = probe_word(image, label, entry_field)? else {
        return Ok(None);
    };
    if name_pointer == 0 || entry_pointer == 0 {
        return Ok(None);
    }

    // The first-slot plausibility threshold is crossed: every failure
    // below is a typed contextual rejection.
    if geometry.capacity == 0 || geometry.capacity > MAX_TABLE_CAPACITY {
        return Err(malformed(format!(
            "capacity {} exceeds the descriptor-v1 table limit {MAX_TABLE_CAPACITY}",
            geometry.capacity
        )));
    }
    if geometry.stride == 0 || geometry.stride > MAX_TABLE_STRIDE {
        return Err(malformed(format!(
            "stride {:#010x} exceeds the descriptor-v1 table limit {MAX_TABLE_STRIDE:#x}",
            geometry.stride
        )));
    }
    let Some(descriptor_end) = geometry.name_offset.checked_add(24) else {
        return Err(malformed(format!(
            "name offset {:#010x} cannot address the descriptor fields",
            geometry.name_offset
        )));
    };
    let Some(index_end) = geometry.index_offset.checked_add(4) else {
        return Err(malformed(format!(
            "index offset {:#010x} cannot address its field",
            geometry.index_offset
        )));
    };
    if descriptor_end > geometry.stride || index_end > geometry.stride {
        return Err(malformed(format!(
            "known descriptor fields do not fit inside stride {:#010x}",
            geometry.stride
        )));
    }

    let mut tasks: Vec<TaskRecord> = Vec::new();
    let mut terminal: Option<TerminalRecord> = None;
    for index in 0..geometry.capacity {
        let Some(advanced) = index.checked_mul(geometry.stride) else {
            return Err(malformed(format!(
                "slot {index} address arithmetic wraps the address space"
            )));
        };
        let Some(slot) = geometry.slot_base.checked_add(advanced) else {
            return Err(malformed(format!(
                "slot {index} address arithmetic wraps the address space"
            )));
        };
        let slot_context = format!("slot {index} at {slot:#010x}");
        budget.charge(u64::from(geometry.stride), "candidate validation bytes")?;
        let slot_blake3 = image.hash_range(slot, geometry.stride).map_err(|error| {
            if is_runtime_failure(&error) {
                runtime_failure(label, slot, geometry.stride, &error)
            } else {
                malformed(format!("{slot_context} range is unreadable: {error}"))
            }
        })?;
        let slot_storage = image
            .storage_spans(slot, geometry.stride)
            .map_err(|error| {
                if is_runtime_failure(&error) {
                    runtime_failure(label, slot, geometry.stride, &error)
                } else {
                    malformed(format!("{slot_context} provenance is unreadable: {error}"))
                }
            })?;
        let name_pointer = read_table_word(
            image,
            label,
            initializer,
            slot,
            geometry.name_offset,
            &slot_context,
            "name pointer",
        )?;
        if name_pointer == 0 {
            terminal = Some(validate_terminal(
                image,
                label,
                initializer,
                slot,
                &slot_context,
                &offsets,
                (slot_blake3, slot_storage),
            )?);
            break;
        }
        let priority_word = read_table_word(
            image,
            label,
            initializer,
            slot,
            offsets.priority,
            &slot_context,
            "priority word",
        )?;
        let Some(priority) = u8::try_from(priority_word).ok() else {
            return Err(malformed(format!(
                "{slot_context} priority word {priority_word:#010x} has nonzero upper bits"
            )));
        };
        let stack_size = read_table_word(
            image,
            label,
            initializer,
            slot,
            offsets.stack_size,
            &slot_context,
            "stack size",
        )?;
        if stack_size == 0 || stack_size % 4 != 0 {
            return Err(malformed(format!(
                "{slot_context} stack size {stack_size:#010x} is zero or not four-byte aligned"
            )));
        }
        let stored_entry = read_table_word(
            image,
            label,
            initializer,
            slot,
            offsets.entry,
            &slot_context,
            "entry pointer",
        )?;
        let callback = read_table_word(
            image,
            label,
            initializer,
            slot,
            offsets.callback,
            &slot_context,
            "callback",
        )?;
        let unknown_pointer = read_table_word(
            image,
            label,
            initializer,
            slot,
            offsets.unknown_pointer,
            &slot_context,
            "unknown pointer",
        )?;
        budget.charge(TASK_NAME_READ_BYTES, "candidate validation bytes")?;
        let (name, name_storage) = image
            .read_ascii_nul(name_pointer, MAX_TASK_NAME_BYTES)
            .map_err(|error| {
                if is_runtime_failure(&error) {
                    runtime_failure(label, name_pointer, MAX_TASK_NAME_BYTES as u32, &error)
                } else {
                    malformed(format!(
                        "{slot_context} name at {name_pointer:#010x} is invalid: {error}"
                    ))
                }
            })?;
        if name.len() < 2 {
            return Err(malformed(format!(
                "{slot_context} name at {name_pointer:#010x} is shorter than two characters"
            )));
        }
        let entry = validate_entry(image, label, stored_entry, budget)
            .map_err(|error| contextualize_entry(error, &slot_context, stored_entry))?;
        tasks.push(TaskRecord {
            index,
            slot,
            slot_blake3,
            name_pointer,
            name,
            task_label: String::new(),
            priority,
            stack_size,
            entry_pointer: stored_entry,
            entry: entry.address,
            isa: entry.isa,
            instruction_size: entry.size,
            instruction_blake3: entry.blake3,
            callback,
            unknown_pointer,
            slot_storage,
            name_storage,
            entry_storage: entry.storage,
        });
    }
    let Some(terminal) = terminal else {
        return Err(malformed(format!(
            "no terminal slot before capacity {} at base {:#010x}",
            geometry.capacity, geometry.slot_base
        )));
    };
    let applications = allocate_applications(&mut tasks, initializer)?;
    Ok(Some(ValidatedTable {
        table: TaskTable {
            slot_base: geometry.slot_base,
            name_offset: geometry.name_offset,
            index_offset: geometry.index_offset,
            stride: geometry.stride,
            capacity: geometry.capacity,
            count: u32::try_from(tasks.len())
                .map_err(|_| malformed("task count does not fit the table record".to_string()))?,
            descriptor_projection_offset: geometry
                .name_offset
                .checked_sub(DESCRIPTOR_PROJECTION_OFFSET)
                .ok_or_else(|| {
                    malformed(format!(
                        "name offset {:#010x} cannot project the descriptor",
                        geometry.name_offset
                    ))
                })?,
            priority_offset: offsets.priority,
            stack_size_offset: offsets.stack_size,
            entry_offset: offsets.entry,
            callback_offset: offsets.callback,
            unknown_pointer_offset: offsets.unknown_pointer,
        },
        tasks,
        applications,
        terminal,
    }))
}

/// The pre-threshold probe of one first-slot word: a host or medium
/// failure is the typed runtime error; anything else is a miss.
fn probe_word(
    image: &RuntimeImage<'_>,
    label: &str,
    address: u32,
) -> std::result::Result<Option<u32>, PalTaskError> {
    match image.read_u32(address) {
        Ok(word) => Ok(Some(word)),
        Err(error) if is_runtime_failure(&error) => Err(runtime_failure(label, address, 4, &error)),
        Err(_) => Ok(None),
    }
}

fn read_table_word(
    image: &RuntimeImage<'_>,
    label: &str,
    initializer: u32,
    slot: u32,
    offset: u32,
    slot_context: &str,
    what: &str,
) -> std::result::Result<u32, PalTaskError> {
    let Some(address) = slot.checked_add(offset) else {
        return Err(PalTaskError::Malformed {
            initializer,
            context: format!("{slot_context} {what} at offset {offset:#010x} wraps"),
        });
    };
    image.read_u32(address).map_err(|error| {
        if is_runtime_failure(&error) {
            runtime_failure(label, address, 4, &error)
        } else {
            PalTaskError::Malformed {
                initializer,
                context: format!("{slot_context} {what} is unreadable: {error}"),
            }
        }
    })
}

/// The terminal slot: the complete slot was already hashed; its known
/// fields must all be zero while opaque bytes stay unrestricted.
fn validate_terminal(
    image: &RuntimeImage<'_>,
    label: &str,
    initializer: u32,
    slot: u32,
    slot_context: &str,
    offsets: &DescriptorOffsets,
    evidence: ([u8; 32], Vec<StorageSpan>),
) -> std::result::Result<TerminalRecord, PalTaskError> {
    let (slot_blake3, storage) = evidence;
    for (offset, name) in [
        (offsets.priority, "priority"),
        (offsets.stack_size, "stack"),
        (offsets.entry, "entry"),
        (offsets.callback, "callback"),
        (offsets.unknown_pointer, "unknown"),
    ] {
        let word = read_table_word(image, label, initializer, slot, offset, slot_context, name)?;
        if word != 0 {
            return Err(PalTaskError::Malformed {
                initializer,
                context: format!("{slot_context} terminal {name} word {word:#010x} is nonzero"),
            });
        }
    }
    Ok(TerminalRecord {
        slot,
        slot_blake3,
        storage,
    })
}

/// One architecturally validated task entry.
struct ValidEntry {
    address: u32,
    isa: TaskIsa,
    size: u8,
    blake3: [u8; 32],
    storage: Vec<StorageSpan>,
}

/// Normalize the stored pointer (odd selects Thumb with bit zero
/// cleared, which is always halfword aligned; even selects ARM and
/// must be word aligned), read one complete instruction from
/// byte-backed storage, decode exactly the selected ISA, and never
/// retry the other one.
fn validate_entry(
    image: &RuntimeImage<'_>,
    label: &str,
    stored: u32,
    budget: &mut CandidateBudget,
) -> std::result::Result<ValidEntry, PalTaskError> {
    let (isa, address) = if stored & 1 == 1 {
        (TaskIsa::Thumb, stored & !1)
    } else {
        (TaskIsa::Arm, stored)
    };
    let decode_error = |reason: String| PalTaskError::Decode {
        pc: address,
        isa,
        reason,
    };
    if isa == TaskIsa::Arm && !address.is_multiple_of(4) {
        return Err(decode_error(format!(
            "stored entry pointer {stored:#010x} is not word-aligned"
        )));
    }
    budget.charge(MAX_ENTRY_INSTRUCTION_BYTES, "candidate validation bytes")?;
    let mut bytes = image.read_exact(address, 4);
    if isa == TaskIsa::Thumb && bytes.is_err() {
        // A narrow final instruction may complete from two bytes; a
        // 32-bit encoding then fails the decode below.
        bytes = image.read_exact(address, 2);
    }
    let bytes = bytes.map_err(|error| {
        if is_runtime_failure(&error) {
            runtime_failure(label, address, 4, &error)
        } else {
            decode_error(format!("entry bytes are unreadable: {error}"))
        }
    })?;
    let decoder = PureRustDecoder;
    let mut state = decoder.begin_range(isa.decode_isa());
    let instruction = decoder
        .decode_one(&mut state, isa.decode_isa(), address, &bytes)
        .map_err(|error| decode_error(error.to_string()))?;
    let length = u32::from(instruction.length);
    let byte_backed = image.is_byte_backed(address, length).map_err(|error| {
        if is_runtime_failure(&error) {
            runtime_failure(label, address, length, &error)
        } else {
            decode_error(format!("entry storage is unverifiable: {error}"))
        }
    })?;
    if !byte_backed {
        return Err(decode_error(
            "entry instruction storage is not byte-backed".to_string(),
        ));
    }
    if matches!(instruction.effect, ValueEffect::Unsupported) {
        return Err(decode_error("unsupported entry instruction".to_string()));
    }
    let blake3 = image.hash_range(address, length).map_err(|error| {
        if is_runtime_failure(&error) {
            runtime_failure(label, address, length, &error)
        } else {
            decode_error(format!("entry bytes are unreadable: {error}"))
        }
    })?;
    let storage = image.storage_spans(address, length).map_err(|error| {
        if is_runtime_failure(&error) {
            runtime_failure(label, address, length, &error)
        } else {
            decode_error(format!("entry provenance is unreadable: {error}"))
        }
    })?;
    Ok(ValidEntry {
        address,
        isa,
        size: instruction.length,
        blake3,
        storage,
    })
}

/// Attach the slot context to a decode failure so the error names the
/// record whose entry failed.
fn contextualize_entry(error: PalTaskError, slot_context: &str, stored: u32) -> PalTaskError {
    match error {
        PalTaskError::Decode { pc, isa, reason } => PalTaskError::Decode {
            pc,
            isa,
            reason: format!("{slot_context} entry pointer {stored:#010x}: {reason}"),
        },
        other => other,
    }
}

/// Preserve ASCII alphanumerics and underscores, replace each maximal
/// run of other bytes with one underscore, prefix an underscore when
/// the result starts with a digit, and reject an empty result.
fn sanitize_task_name(name: &str) -> Option<String> {
    let mut out = String::new();
    let mut pending_underscore = false;
    for byte in name.bytes() {
        if byte.is_ascii_alphanumeric() || byte == b'_' {
            if pending_underscore {
                out.push('_');
                pending_underscore = false;
            }
            out.push(char::from(byte));
        } else {
            pending_underscore = true;
        }
    }
    if pending_underscore {
        out.push('_');
    }
    if out.is_empty() {
        return None;
    }
    if out.starts_with(|character: char| character.is_ascii_digit()) {
        out.insert(0, '_');
    }
    Some(out)
}

/// The collision domain of one leaf identity: the reserved task-label
/// namespace and the global primary namespace allocate separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum LabelNamespace {
    Reserved,
    Global,
}

/// Which leaf kind one identity requests; the identity key carries it
/// even inside a single-domain namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum LeafKind {
    Role,
    Primary,
}

/// The allocation identity: `(namespace, entry, isa, lowest task
/// index, kind)`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct LeafIdentityKey {
    namespace: LabelNamespace,
    entry: u32,
    isa: TaskIsa,
    lowest_index: u32,
    kind: LeafKind,
}

#[derive(Debug, Clone)]
struct LeafIdentity {
    key: LeafIdentityKey,
    preferred: String,
}

fn suffixed_leaf(
    preferred: &str,
    entry: u32,
    lowest_index: u32,
    nonce: u32,
) -> std::result::Result<String, PalTaskError> {
    let suffix = format!("_pme_{entry:08x}_{lowest_index:08x}_{nonce:08x}");
    let Some(keep) = MAX_SYMBOL_LEAF_BYTES.checked_sub(suffix.len()) else {
        return Err(PalTaskError::Artifact(
            "collision suffix cannot fit the symbol leaf limit".to_string(),
        ));
    };
    // Preferred bases are ASCII by construction, so the byte cut is a
    // character cut.
    let base = &preferred[..preferred.len().min(keep)];
    Ok(format!("{base}{suffix}"))
}

/// Allocate every leaf in both namespaces. The forbidden set is every
/// preferred leaf in the domain — unique and duplicate-group members
/// alike — plus every already assigned leaf. Unique preferreds keep
/// their exact strings; every duplicate-group member is
/// suffix-allocated in identity-key order, trying exactly nonces
/// `0..=2*N`: with N identities the forbidden set holds at most
/// `N + N = 2*N` members against `2*N + 1` candidates distinct by
/// nonce, so one allocation must exist.
fn allocate_leaves(
    identities: &[LeafIdentity],
) -> std::result::Result<BTreeMap<LeafIdentityKey, String>, PalTaskError> {
    let mut assigned: BTreeMap<LeafIdentityKey, String> = BTreeMap::new();
    for namespace in [LabelNamespace::Reserved, LabelNamespace::Global] {
        let mut domain: Vec<&LeafIdentity> = identities
            .iter()
            .filter(|identity| identity.key.namespace == namespace)
            .collect();
        domain.sort_by(|left, right| left.key.cmp(&right.key));
        let count = domain.len();
        let mut occurrences: BTreeMap<&str, usize> = BTreeMap::new();
        for identity in &domain {
            *occurrences.entry(identity.preferred.as_str()).or_insert(0) += 1;
        }
        // Seed the forbidden set with every preferred leaf in the
        // domain, not only the unique ones: a suffix candidate must
        // also avoid each duplicate group's (unassigned) preferred.
        let mut taken: BTreeSet<String> = domain
            .iter()
            .map(|identity| identity.preferred.clone())
            .collect();
        for identity in &domain {
            if occurrences[identity.preferred.as_str()] != 1 {
                continue;
            }
            if identity.preferred.len() > MAX_SYMBOL_LEAF_BYTES {
                return Err(PalTaskError::Artifact(format!(
                    "unique preferred leaf exceeds the {MAX_SYMBOL_LEAF_BYTES}-character limit"
                )));
            }
            assigned.insert(identity.key.clone(), identity.preferred.clone());
        }
        let Some(count32) = u32::try_from(count).ok() else {
            return Err(PalTaskError::Artifact(
                "leaf identity count overflows the nonce bound".to_string(),
            ));
        };
        let Some(max_nonce) = count32.checked_mul(2) else {
            return Err(PalTaskError::Artifact(
                "leaf identity count overflows the nonce bound".to_string(),
            ));
        };
        for identity in &domain {
            if occurrences[identity.preferred.as_str()] == 1 {
                continue;
            }
            let mut allocated = None;
            for nonce in 0..=max_nonce {
                let candidate = suffixed_leaf(
                    &identity.preferred,
                    identity.key.entry,
                    identity.key.lowest_index,
                    nonce,
                )?;
                if !taken.contains(&candidate) {
                    allocated = Some(candidate);
                    break;
                }
            }
            let Some(leaf) = allocated else {
                return Err(PalTaskError::Artifact(
                    "collision suffix allocation exhausted nonces 0..=2*N".to_string(),
                ));
            };
            taken.insert(leaf.clone());
            assigned.insert(identity.key.clone(), leaf);
        }
    }
    Ok(assigned)
}

/// Reject cross-ISA aliases, allocate every task label and application
/// primary, fill the per-record labels, and prove the exact
/// task-index/label partitions. Also the artifact reader's recomputation
/// path: it must reproduce the serialized allocation decision through
/// this one implementation.
pub(super) fn allocate_applications(
    tasks: &mut [TaskRecord],
    initializer: u32,
) -> std::result::Result<Vec<TaskApplication>, PalTaskError> {
    let malformed = |context: String| PalTaskError::Malformed {
        initializer,
        context,
    };
    // Cross-ISA aliases are rejected before any grouping.
    let mut entry_isas: BTreeMap<u32, BTreeSet<TaskIsa>> = BTreeMap::new();
    for task in tasks.iter() {
        entry_isas.entry(task.entry).or_default().insert(task.isa);
    }
    for (entry, isas) in &entry_isas {
        if isas.len() > 1 {
            return Err(malformed(format!(
                "cross-ISA alias at {entry:#010x}: one entry cannot carry both {isas:?}"
            )));
        }
    }

    // Task-label identities: one per distinct (name, entry, isa). The
    // member map owns its names so the per-record label fill can borrow
    // the records mutably.
    let mut label_members: BTreeMap<(String, u32, TaskIsa), Vec<u32>> = BTreeMap::new();
    for task in tasks.iter() {
        label_members
            .entry((task.name.clone(), task.entry, task.isa))
            .or_default()
            .push(task.index);
    }
    let mut identities: Vec<LeafIdentity> = Vec::new();
    for ((name, entry, isa), indices) in &label_members {
        let Some(sanitized) = sanitize_task_name(name) else {
            return Err(malformed(format!(
                "task name {name:?} sanitizes to an empty portion"
            )));
        };
        let Some(lowest_index) = indices.first().copied() else {
            return Err(PalTaskError::Artifact(
                "label identity without member indices".to_string(),
            ));
        };
        identities.push(LeafIdentity {
            key: LeafIdentityKey {
                namespace: LabelNamespace::Reserved,
                entry: *entry,
                isa: *isa,
                lowest_index,
                kind: LeafKind::Role,
            },
            preferred: format!("pal_TaskEntry_{sanitized}"),
        });
    }

    // Application identities: one per normalized (entry, isa) group.
    let mut groups: BTreeMap<(u32, TaskIsa), Vec<u32>> = BTreeMap::new();
    for task in tasks.iter() {
        groups
            .entry((task.entry, task.isa))
            .or_default()
            .push(task.index);
    }
    for ((entry, isa), indices) in &groups {
        let distinct = label_members
            .keys()
            .filter(|(_, label_entry, label_isa)| label_entry == entry && label_isa == isa)
            .count();
        let Some(lowest_index) = indices.first().copied() else {
            return Err(PalTaskError::Artifact(
                "application identity without member indices".to_string(),
            ));
        };
        let preferred = if distinct == 1 {
            let name = label_members
                .keys()
                .find(|(_, label_entry, label_isa)| label_entry == entry && label_isa == isa)
                .map(|(name, _, _)| name.as_str())
                .ok_or_else(|| {
                    PalTaskError::Artifact("application group lost its identity".to_string())
                })?;
            let Some(sanitized) = sanitize_task_name(name) else {
                return Err(malformed(format!(
                    "task name {name:?} sanitizes to an empty portion"
                )));
            };
            format!("pal_TaskEntry_{sanitized}")
        } else {
            format!("pal_TaskEntry_shared_{entry:08x}")
        };
        identities.push(LeafIdentity {
            key: LeafIdentityKey {
                namespace: LabelNamespace::Global,
                entry: *entry,
                isa: *isa,
                lowest_index,
                kind: LeafKind::Primary,
            },
            preferred,
        });
    }

    let leaves = allocate_leaves(&identities)?;
    // Pre-collect every member's allocated role label so the per-record
    // lookups below borrow their keys instead of allocating an owned
    // `(String, u32, TaskIsa)` per lookup; bounded by MAX_TABLE_CAPACITY
    // task names.
    let allocated_labels: BTreeMap<(&str, u32, TaskIsa), &str> = label_members
        .iter()
        .filter_map(|((name, entry, isa), indices)| {
            let lowest = *indices.first()?;
            let label = leaves.get(&LeafIdentityKey {
                namespace: LabelNamespace::Reserved,
                entry: *entry,
                isa: *isa,
                lowest_index: lowest,
                kind: LeafKind::Role,
            })?;
            Some(((name.as_str(), *entry, *isa), label.as_str()))
        })
        .collect();
    let label_of = |name: &str, entry: u32, isa: TaskIsa| -> Option<&str> {
        allocated_labels.get(&(name, entry, isa)).copied()
    };
    for task in tasks.iter_mut() {
        let Some(label) = label_of(&task.name, task.entry, task.isa) else {
            return Err(PalTaskError::Artifact(
                "task record lost its allocated label".to_string(),
            ));
        };
        task.task_label = label.to_string();
    }

    let mut applications = Vec::new();
    for ((entry, isa), indices) in &groups {
        let Some(lowest) = indices.first().copied() else {
            return Err(PalTaskError::Artifact(
                "application identity without member indices".to_string(),
            ));
        };
        let desired_primary = leaves
            .get(&LeafIdentityKey {
                namespace: LabelNamespace::Global,
                entry: *entry,
                isa: *isa,
                lowest_index: lowest,
                kind: LeafKind::Primary,
            })
            .ok_or_else(|| {
                PalTaskError::Artifact("application lost its allocated primary".to_string())
            })?
            .clone();
        let mut labels: Vec<TaskLabelApplication> = Vec::new();
        for ((name, label_entry, label_isa), member_indices) in label_members.iter() {
            if label_entry != entry || label_isa != isa {
                continue;
            }
            let Some(label) = label_of(name, *entry, *isa) else {
                return Err(PalTaskError::Artifact("label allocation gap".to_string()));
            };
            labels.push(TaskLabelApplication {
                label: label.to_string(),
                task_indices: member_indices.clone(),
            });
        }
        labels.sort_by(|left, right| left.task_indices.first().cmp(&right.task_indices.first()));
        applications.push(TaskApplication {
            entry: *entry,
            isa: *isa,
            desired_primary,
            task_indices: indices.clone(),
            labels,
        });
    }
    applications.sort_by_key(|application| (application.entry, application.isa));
    prove_partitions(tasks, &applications)?;
    Ok(applications)
}

/// The exact partition proof: applications partition every task index
/// once, labels partition each application, and every record's label
/// is the label of the application containing it.
fn prove_partitions(
    tasks: &[TaskRecord],
    applications: &[TaskApplication],
) -> std::result::Result<(), PalTaskError> {
    let artifact = |reason: &str| PalTaskError::Artifact(reason.to_string());
    let mut seen: BTreeSet<u32> = BTreeSet::new();
    for application in applications {
        let mut label_indices: BTreeSet<u32> = BTreeSet::new();
        for label in &application.labels {
            for index in &label.task_indices {
                if !label_indices.insert(*index) {
                    return Err(artifact("one task index appears in two labels"));
                }
            }
        }
        let application_indices: BTreeSet<u32> = application.task_indices.iter().copied().collect();
        if label_indices != application_indices {
            return Err(artifact("labels do not partition one application"));
        }
        for index in &application_indices {
            if !seen.insert(*index) {
                return Err(artifact("one task index appears in two applications"));
            }
        }
    }
    let task_count = u32::try_from(tasks.len()).map_err(|_| {
        PalTaskError::Artifact("task count does not fit the partition proof".to_string())
    })?;
    if seen != (0..task_count).collect::<BTreeSet<u32>>() {
        return Err(artifact("applications do not partition the task indices"));
    }
    for task in tasks {
        let labeled = applications
            .iter()
            .filter(|application| application.task_indices.contains(&task.index))
            .count();
        if labeled != 1 {
            return Err(artifact(
                "one task does not belong to exactly one application",
            ));
        }
        let carries = applications.iter().any(|application| {
            application.task_indices.contains(&task.index)
                && application.labels.iter().any(|label| {
                    label.task_indices.contains(&task.index) && label.label == task.task_label
                })
        });
        if !carries {
            return Err(artifact(
                "one task record does not carry its allocated label",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        LabelNamespace, LeafIdentity, LeafIdentityKey, LeafKind, ValidatedTable, allocate_leaves,
        sanitize_task_name, validate_candidate,
    };
    use crate::arm32::Register;
    use crate::pal_tasks::discover as discover_plan;
    use crate::pal_tasks::discover::test_support::{
        BASE, FixtureItem, adr_to, assemble, branch_to, branch32_to, bytes_entry, cbz_to, enc, gpr,
        insn, low, put_u32, raw_image, scatter_plan, word_at, zero_entry,
    };
    use crate::pal_tasks::{
        AnchorProofPath, AnchorReference, AnchorReferenceKind, CandidateBudget, CapacityGuard,
        InitializerCandidate, InitializerEvidence, MAX_CANDIDATE_VALIDATION_BYTES, PalTaskError,
        TaskIsa, TaskTableGeometry,
    };
    use crate::runtime_image::{RuntimeImage, StorageKind, StorageSpan};
    use scaleservers_arm32_assembly::{Arm32Condition, ArmT32Instruction as T32};
    use std::collections::BTreeSet;

    const NAME_OFFSET: u32 = 0x4c;
    const INDEX_OFFSET: u32 = 0x0c;
    const STRIDE: u32 = 0x1f8;
    const CFG_ENTRY: u32 = 0x1100;

    /// Growable image under construction: bytes above `BASE` grown on
    /// demand, written at absolute addresses.
    struct ImageBuilder {
        bytes: Vec<u8>,
    }

    impl ImageBuilder {
        fn new() -> Self {
            ImageBuilder { bytes: Vec::new() }
        }

        fn ensure(&mut self, end: u32) {
            let end = usize::try_from(end - BASE).expect("fixture extent fits the host");
            if self.bytes.len() < end {
                self.bytes.resize(end, 0);
            }
        }

        fn write(&mut self, address: u32, data: &[u8]) {
            self.ensure(
                address
                    .checked_add(u32::try_from(data.len()).unwrap())
                    .unwrap(),
            );
            let offset = usize::try_from(address - BASE).unwrap();
            self.bytes[offset..offset + data.len()].copy_from_slice(data);
        }

        fn write_u32(&mut self, address: u32, value: u32) {
            self.write(address, &value.to_le_bytes());
        }

        fn image(&self) -> RuntimeImage<'_> {
            raw_image(&self.bytes)
        }
    }

    /// One nonterminal slot's desired content. `None` pointers let the
    /// builder assign default addresses (a written name string and a
    /// distinct Thumb `push` entry).
    struct SlotSpec {
        name: String,
        name_pointer: Option<u32>,
        entry_pointer: Option<u32>,
        priority: u32,
        stack_size: u32,
        callback: u32,
        unknown_pointer: u32,
        opaque: u8,
    }

    fn slot(name: &str) -> SlotSpec {
        SlotSpec {
            name: name.to_string(),
            name_pointer: None,
            entry_pointer: None,
            priority: 0x64,
            stack_size: 0x200,
            callback: 0,
            unknown_pointer: 0,
            opaque: 0x5a,
        }
    }

    /// Write the descriptor-v1 slots and terminal described by
    /// `slots`, plus their name strings and default Thumb entries;
    /// returns the parallel name and entry addresses. `patches` are
    /// applied last for test-authored entry bytes.
    fn write_table(
        image: &mut ImageBuilder,
        slot_base: u32,
        stride: u32,
        slots: &[SlotSpec],
        terminal_opaque: u8,
        patches: &[(u32, Vec<u8>)],
    ) -> (Vec<u32>, Vec<u32>) {
        let slot_count = u32::try_from(slots.len()).expect("fixture slot count fits u32") + 1;
        let table_end = slot_base + slot_count * stride;
        image.ensure(table_end);
        let mut cursor = table_end + 0x40;
        let mut name_addresses = Vec::with_capacity(slots.len());
        for spec in slots {
            image.write(cursor, spec.name.as_bytes());
            image.write(cursor + u32::try_from(spec.name.len()).unwrap(), &[0]);
            name_addresses.push(cursor);
            cursor += u32::try_from(spec.name.len()).unwrap() + 1;
        }
        cursor = cursor.div_ceil(4) * 4;
        let entries_base = cursor;
        let mut entry_addresses = Vec::with_capacity(slots.len());
        let push = enc(&T32::Push_T1(vec![gpr(4), gpr(14)]));
        for index in 0..slots.len() {
            let address = entries_base + u32::try_from(index).unwrap() * 4;
            image.write(address, &push);
            entry_addresses.push(address);
        }
        image.ensure(entries_base + u32::try_from(slots.len()).unwrap() * 4 + 4);
        for (index, spec) in slots.iter().enumerate() {
            let index = u32::try_from(index).unwrap();
            let slot_address = slot_base + index * stride;
            for offset in 0..stride {
                let byte = spec.opaque.wrapping_add((offset as u8) ^ (index as u8));
                image.write(slot_address + offset, &[byte]);
            }
            image.write_u32(
                slot_address + NAME_OFFSET,
                spec.name_pointer
                    .unwrap_or(name_addresses[usize::try_from(index).unwrap()]),
            );
            image.write_u32(slot_address + NAME_OFFSET + 4, spec.priority);
            image.write_u32(slot_address + NAME_OFFSET + 8, spec.stack_size);
            image.write_u32(
                slot_address + NAME_OFFSET + 12,
                spec.entry_pointer
                    .unwrap_or(entry_addresses[usize::try_from(index).unwrap()] | 1),
            );
            image.write_u32(slot_address + NAME_OFFSET + 16, spec.callback);
            image.write_u32(slot_address + NAME_OFFSET + 20, spec.unknown_pointer);
        }
        let terminal = slot_base + slot_count.saturating_sub(1) * stride;
        for offset in 0..stride {
            let byte = terminal_opaque.wrapping_add(offset as u8);
            image.write(terminal + offset, &[byte]);
        }
        // The terminal's known descriptor fields are zero; only opaque
        // bytes outside the overlay stay nonzero.
        for field in [
            NAME_OFFSET,
            NAME_OFFSET + 4,
            NAME_OFFSET + 8,
            NAME_OFFSET + 12,
            NAME_OFFSET + 16,
            NAME_OFFSET + 20,
        ] {
            image.write_u32(terminal + field, 0);
        }
        for (address, data) in patches {
            image.write(*address, data);
        }
        (name_addresses, entry_addresses)
    }

    /// A synthetic initializer candidate carrying only the geometry
    /// table validation consumes.
    fn table_candidate(slot_base: u32, stride: u32, capacity: u32) -> InitializerCandidate {
        let geometry = TaskTableGeometry {
            slot_base,
            name_offset: NAME_OFFSET,
            index_offset: INDEX_OFFSET,
            stride,
            capacity,
        };
        InitializerCandidate {
            evidence: InitializerEvidence {
                cfg_entry: CFG_ENTRY,
                proof_paths: vec![AnchorProofPath {
                    anchor: 0x3000,
                    reference: AnchorReference {
                        anchor: 0x3000,
                        kind: AnchorReferenceKind::Adr,
                        pc: 0x1102,
                        definitions: vec![0x1102],
                        register: Register(1),
                    },
                    call: 0x1106,
                }],
                anchors: vec![],
                code_storage: vec![],
                loop_start: 0x1110,
                count_zero_definition: 0x1104,
                slot_definition: crate::pal_tasks::SlotDefinition {
                    root: 0x1108,
                    definitions: vec![0x1108],
                },
                normal_exit: 0x1120,
                capacity_exit: 0x111c,
                capacity_guard: CapacityGuard {
                    start: 0x1124,
                    compare: 0x1126,
                    branch: 0x1128,
                    fallthrough: 0x112a,
                    shift_amount: 3,
                    compare_value: 124,
                },
                suffix_loop: 0x112a,
                join: 0x1130,
                count_global: 0x5000,
                slot_base,
                name_offset: NAME_OFFSET,
                index_offset: INDEX_OFFSET,
                stride,
                capacity,
            },
            geometry,
        }
    }

    fn default_budget() -> CandidateBudget {
        CandidateBudget::default()
    }

    fn validate(
        image: &RuntimeImage<'_>,
        candidate: &InitializerCandidate,
    ) -> std::result::Result<Option<ValidatedTable>, PalTaskError> {
        validate_candidate(image, "fixture", candidate, &mut CandidateBudget::default())
    }

    fn slot_bytes(image_bytes: &[u8], slot: u32) -> Vec<u8> {
        let start = usize::try_from(slot - BASE).unwrap();
        image_bytes[start..start + STRIDE as usize].to_vec()
    }

    #[test]
    fn descriptor_slots_parse_with_provenance_and_exact_hashes() {
        // A raw-backed table of two slots with a terminal.
        let mut image = ImageBuilder::new();
        let (names, entries) = write_table(
            &mut image,
            0x4000,
            STRIDE,
            &[
                SlotSpec {
                    callback: 0x12,
                    unknown_pointer: 0x34,
                    ..slot("alpha")
                },
                SlotSpec {
                    priority: 0xff,
                    stack_size: 0x80e8,
                    ..slot("beta")
                },
            ],
            0xc7,
            &[],
        );
        let candidate = table_candidate(0x4000, STRIDE, 8);
        let validated = validate(&image.image(), &candidate)
            .unwrap()
            .expect("raw table validates");
        assert_eq!(
            validated.table,
            crate::pal_tasks::TaskTable {
                slot_base: 0x4000,
                name_offset: NAME_OFFSET,
                index_offset: INDEX_OFFSET,
                stride: STRIDE,
                capacity: 8,
                count: 2,
                descriptor_projection_offset: NAME_OFFSET - 0x24,
                priority_offset: NAME_OFFSET + 4,
                stack_size_offset: NAME_OFFSET + 8,
                entry_offset: NAME_OFFSET + 12,
                callback_offset: NAME_OFFSET + 16,
                unknown_pointer_offset: NAME_OFFSET + 20,
            }
        );
        assert_eq!(validated.tasks.len(), 2);
        let first = &validated.tasks[0];
        assert_eq!(first.index, 0);
        assert_eq!(first.slot, 0x4000);
        assert_eq!(first.name_pointer, names[0]);
        assert_eq!(first.name, "alpha");
        assert_eq!(first.priority, 0x64);
        assert_eq!(first.stack_size, 0x200);
        assert_eq!(first.callback, 0x12);
        assert_eq!(first.unknown_pointer, 0x34);
        assert_eq!(first.entry_pointer, entries[0] | 1);
        assert_eq!(first.entry, entries[0]);
        assert_eq!(first.isa, TaskIsa::Thumb);
        assert_eq!(
            first.slot_blake3,
            *blake3::hash(&slot_bytes(&image.bytes, 0x4000)).as_bytes()
        );
        assert_eq!(
            first.slot_storage,
            vec![StorageSpan {
                kind: StorageKind::Raw,
                address: 0x4000,
                size: STRIDE,
                scatter_entry: None,
            }]
        );
        assert_eq!(
            first.name_storage,
            vec![StorageSpan {
                kind: StorageKind::Raw,
                address: names[0],
                size: 6,
                scatter_entry: None,
            }]
        );
        let second = &validated.tasks[1];
        assert_eq!(second.priority, 0xff);
        assert_eq!(second.stack_size, 0x80e8);
        assert_eq!(second.slot, 0x4000 + STRIDE);
        assert_eq!(second.name, "beta");
        let terminal_address = 0x4000 + 2 * STRIDE;
        assert_eq!(
            validated.terminal.slot_blake3,
            *blake3::hash(&slot_bytes(&image.bytes, terminal_address)).as_bytes()
        );
        assert_eq!(
            validated.terminal.storage,
            vec![StorageSpan {
                kind: StorageKind::Raw,
                address: terminal_address,
                size: STRIDE,
                scatter_entry: None,
            }]
        );

        // The same table split across raw and scatter provenance: slot 1
        // crosses the boundary and keeps both spans; the hash matches
        // the flattened bytes.
        let mut raw = image.bytes.clone();
        raw.truncate(usize::try_from(0x4280 - BASE).unwrap());
        let scatter_start = 0x4280;
        let scatter_extent = BASE + u32::try_from(image.bytes.len()).unwrap();
        let slot_one_end = 0x4000 + 2 * STRIDE;
        let scatter: Vec<u8> = image.bytes[usize::try_from(scatter_start - BASE).unwrap()
            ..usize::try_from(scatter_extent - BASE).unwrap()]
            .to_vec();
        let plan = scatter_plan(
            u32::try_from(raw.len()).unwrap(),
            vec![bytes_entry(0, scatter_start, scatter)],
        );
        let mixed = RuntimeImage::from_plan(&raw, BASE, Some(&plan)).expect("fixture image");
        let validated = validate(&mixed, &candidate)
            .unwrap()
            .expect("mixed table validates");
        let second = &validated.tasks[1];
        assert_eq!(
            second.slot_storage,
            vec![
                StorageSpan {
                    kind: StorageKind::Raw,
                    address: 0x4000 + STRIDE,
                    size: scatter_start - (0x4000 + STRIDE),
                    scatter_entry: None,
                },
                StorageSpan {
                    kind: StorageKind::ScatterBytes,
                    address: scatter_start,
                    size: slot_one_end - scatter_start,
                    scatter_entry: Some(0),
                },
            ]
        );
        assert_eq!(
            second.slot_blake3,
            *blake3::hash(&slot_bytes(&image.bytes, second.slot)).as_bytes()
        );
    }

    #[test]
    fn entry_validation_covers_arm_thumb_16_and_32_bit_forms() {
        let mut image = ImageBuilder::new();
        let arm_word = 0xE3A0_0000u32.to_le_bytes();
        let movw = enc(&T32::Mov_Immediate_T3(gpr(0), 0x1234));
        write_table(
            &mut image,
            0x4000,
            STRIDE,
            &[
                SlotSpec {
                    entry_pointer: Some(0x3600),
                    ..slot("arm_task")
                },
                SlotSpec {
                    entry_pointer: Some(0x3701),
                    ..slot("thumb32_task")
                },
            ],
            0x11,
            &[(0x3600, arm_word.to_vec()), (0x3700, movw.clone())],
        );
        let validated = validate(&image.image(), &table_candidate(0x4000, STRIDE, 8))
            .unwrap()
            .expect("entries validate");
        let arm = &validated.tasks[0];
        assert_eq!(arm.isa, TaskIsa::Arm);
        assert_eq!(arm.entry, 0x3600);
        assert_eq!(arm.instruction_size, 4);
        assert_eq!(arm.instruction_blake3, *blake3::hash(&arm_word).as_bytes());
        assert_eq!(
            arm.entry_storage,
            vec![StorageSpan {
                kind: StorageKind::Raw,
                address: 0x3600,
                size: 4,
                scatter_entry: None,
            }]
        );
        let thumb32 = &validated.tasks[1];
        assert_eq!(thumb32.isa, TaskIsa::Thumb);
        assert_eq!(thumb32.entry, 0x3700);
        assert_eq!(thumb32.instruction_size, 4);
        assert_eq!(thumb32.instruction_blake3, *blake3::hash(&movw).as_bytes());
        // The default builder entry is a 16-bit Thumb push.
        let (_, entries) = write_table(
            &mut ImageBuilder::new(),
            0x4000,
            STRIDE,
            &[slot("thumb16_task")],
            0x11,
            &[],
        );
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn thumb_halfword_alignment_is_valid_and_arm_requires_word_alignment() {
        let mut image = ImageBuilder::new();
        let push = enc(&T32::Push_T1(vec![gpr(4), gpr(14)]));
        write_table(
            &mut image,
            0x4000,
            STRIDE,
            &[SlotSpec {
                entry_pointer: Some(0x3603),
                ..slot("thumb_half")
            }],
            0x22,
            &[(0x3602, push.clone())],
        );
        let validated = validate(&image.image(), &table_candidate(0x4000, STRIDE, 8))
            .unwrap()
            .expect("halfword Thumb entry validates");
        assert_eq!(validated.tasks[0].entry, 0x3602);
        assert_eq!(validated.tasks[0].instruction_size, 2);

        // The same halfword address through an even (ARM) pointer is
        // misaligned and rejected.
        let mut image = ImageBuilder::new();
        write_table(
            &mut image,
            0x4000,
            STRIDE,
            &[SlotSpec {
                entry_pointer: Some(0x3602),
                ..slot("arm_misaligned")
            }],
            0x22,
            &[(0x3600, push)],
        );
        assert!(matches!(
            validate(&image.image(), &table_candidate(0x4000, STRIDE, 8)),
            Err(PalTaskError::Decode {
                isa: TaskIsa::Arm,
                pc: 0x3602,
                ..
            })
        ));
    }

    #[test]
    fn truncated_thirty_two_bit_thumb_entry_is_rejected() {
        // A 32-bit Thumb prefix with only two byte-backed bytes at the
        // end of a scatter segment: the decode fails and never falls
        // back to another interpretation.
        let mut image = ImageBuilder::new();
        write_table(
            &mut image,
            0x4000,
            STRIDE,
            &[SlotSpec {
                entry_pointer: Some(0x5001),
                ..slot("trunc")
            }],
            0x33,
            &[],
        );
        let mut raw = image.bytes.clone();
        raw.truncate(usize::try_from(0x4800 - BASE).unwrap());
        let plan = scatter_plan(
            u32::try_from(raw.len()).unwrap(),
            vec![bytes_entry(0, 0x4800, vec![0x40, 0xF2])],
        );
        let scatter_image = RuntimeImage::from_plan(&raw, BASE, Some(&plan)).expect("fixture");
        assert!(matches!(
            validate(&scatter_image, &table_candidate(0x4000, STRIDE, 8)),
            Err(PalTaskError::Decode {
                isa: TaskIsa::Thumb,
                pc: 0x5000,
                ..
            })
        ));
    }

    #[test]
    fn entry_decode_never_retries_the_other_isa() {
        // 0xE7F00010 is not a decodable A32 instruction, though the
        // same bytes decode as 16-bit Thumb: the selected ISA failure
        // must stand.
        let mut image = ImageBuilder::new();
        write_table(
            &mut image,
            0x4000,
            STRIDE,
            &[SlotSpec {
                entry_pointer: Some(0x3600),
                ..slot("arm_undef")
            }],
            0x44,
            &[(0x3600, 0xE7F0_0010u32.to_le_bytes().to_vec())],
        );
        assert!(matches!(
            validate(&image.image(), &table_candidate(0x4000, STRIDE, 8)),
            Err(PalTaskError::Decode {
                isa: TaskIsa::Arm,
                pc: 0x3600,
                ..
            })
        ));

        // A supported-but-unmodeled A32 encoding (permanently undefined
        // space) is equally rejected.
        let mut image = ImageBuilder::new();
        write_table(
            &mut image,
            0x4000,
            STRIDE,
            &[SlotSpec {
                entry_pointer: Some(0x3600),
                ..slot("arm_udf")
            }],
            0x44,
            &[(0x3600, 0xE7F0_00F0u32.to_le_bytes().to_vec())],
        );
        assert!(matches!(
            validate(&image.image(), &table_candidate(0x4000, STRIDE, 8)),
            Err(PalTaskError::Decode {
                isa: TaskIsa::Arm,
                pc: 0x3600,
                ..
            })
        ));
    }

    #[test]
    fn zero_fill_and_unmapped_entries_are_rejected() {
        let mut image = ImageBuilder::new();
        write_table(
            &mut image,
            0x4000,
            STRIDE,
            &[
                SlotSpec {
                    entry_pointer: Some(0x6001),
                    ..slot("zero_fill_entry")
                },
                SlotSpec {
                    entry_pointer: Some(0x8001),
                    ..slot("unmapped_entry")
                },
            ],
            0x55,
            &[],
        );
        let mut raw = image.bytes.clone();
        raw.truncate(usize::try_from(0x5000 - BASE).unwrap());
        let plan = scatter_plan(
            u32::try_from(raw.len()).unwrap(),
            vec![zero_entry(0, 0x6000, 8)],
        );
        let zoned = RuntimeImage::from_plan(&raw, BASE, Some(&plan)).expect("fixture");
        assert!(matches!(
            validate(&zoned, &table_candidate(0x4000, STRIDE, 8)),
            Err(PalTaskError::Decode {
                isa: TaskIsa::Thumb,
                pc: 0x6000,
                ..
            })
        ));
        // 0x8000 lies in the unmapped gap past the raw image end.
        let mut raw = image.bytes.clone();
        raw.truncate(usize::try_from(0x7000 - BASE).unwrap());
        let plan = scatter_plan(
            u32::try_from(raw.len()).unwrap(),
            vec![bytes_entry(0, 0x6000, vec![0x82, 0xb4])],
        );
        let gapped = RuntimeImage::from_plan(&raw, BASE, Some(&plan)).expect("fixture");
        assert!(matches!(
            validate(&gapped, &table_candidate(0x4000, STRIDE, 8)),
            Err(PalTaskError::Decode {
                isa: TaskIsa::Thumb,
                pc: 0x8000,
                ..
            })
        ));
    }

    #[test]
    fn task_names_enforce_printable_two_to_128_bounds() {
        fn with_name(name: &str) -> std::result::Result<Option<ValidatedTable>, PalTaskError> {
            let mut image = ImageBuilder::new();
            write_table(&mut image, 0x4000, STRIDE, &[slot(name)], 0x66, &[]);
            validate(&image.image(), &table_candidate(0x4000, STRIDE, 8))
        }
        assert_eq!(
            with_name("ab").unwrap().unwrap().tasks[0].name,
            "ab",
            "two-character name is valid"
        );
        assert_eq!(
            with_name(&"x".repeat(128)).unwrap().unwrap().tasks[0]
                .name
                .len(),
            128,
            "128-character name is valid"
        );
        assert_eq!(
            with_name(&"x".repeat(128)).unwrap().unwrap().tasks[0].name_storage[0].size,
            129,
            "name storage includes the NUL"
        );
        assert!(matches!(
            with_name("x"),
            Err(PalTaskError::Malformed { initializer: CFG_ENTRY, context })
                if context.contains("slot 0")
        ));
        assert!(matches!(
            with_name(&"x".repeat(129)),
            Err(PalTaskError::Malformed { .. })
        ));
        // A non-printable byte inside the name storage.
        let mut image = ImageBuilder::new();
        write_table(
            &mut image,
            0x4000,
            STRIDE,
            &[SlotSpec {
                name_pointer: Some(0x3600),
                ..slot("bad")
            }],
            0x66,
            &[(0x3600, vec![b'a', 0x01, b'b', 0])],
        );
        assert!(matches!(
            validate(&image.image(), &table_candidate(0x4000, STRIDE, 8)),
            Err(PalTaskError::Malformed { .. })
        ));
        // A name pointer into zero-fill storage.
        let mut image = ImageBuilder::new();
        write_table(
            &mut image,
            0x4000,
            STRIDE,
            &[SlotSpec {
                name_pointer: Some(0x6000),
                ..slot("zeroed")
            }],
            0x66,
            &[],
        );
        let mut raw = image.bytes.clone();
        raw.truncate(usize::try_from(0x5000 - BASE).unwrap());
        let plan = scatter_plan(
            u32::try_from(raw.len()).unwrap(),
            vec![zero_entry(0, 0x6000, 8)],
        );
        let zoned = RuntimeImage::from_plan(&raw, BASE, Some(&plan)).expect("fixture");
        assert!(matches!(
            validate(&zoned, &table_candidate(0x4000, STRIDE, 8)),
            Err(PalTaskError::Malformed { .. })
        ));
    }

    #[test]
    fn priority_word_must_fit_u8_with_zero_upper_bits() {
        fn with_priority(word: u32) -> std::result::Result<Option<ValidatedTable>, PalTaskError> {
            let mut image = ImageBuilder::new();
            write_table(
                &mut image,
                0x4000,
                STRIDE,
                &[SlotSpec {
                    priority: word,
                    ..slot("prio")
                }],
                0x77,
                &[],
            );
            validate(&image.image(), &table_candidate(0x4000, STRIDE, 8))
        }
        assert_eq!(
            with_priority(0).unwrap().unwrap().tasks[0].priority,
            0,
            "priority zero is valid"
        );
        assert_eq!(
            with_priority(0xff).unwrap().unwrap().tasks[0].priority,
            0xff,
            "priority 0xff is valid"
        );
        assert!(matches!(
            with_priority(0x100),
            Err(PalTaskError::Malformed {
                initializer: CFG_ENTRY,
                ..
            })
        ));
        assert!(matches!(
            with_priority(0x0200_0000 | 0x33),
            Err(PalTaskError::Malformed { .. })
        ));
    }

    #[test]
    fn stack_size_must_be_nonzero_and_four_byte_aligned() {
        fn with_stack(size: u32) -> std::result::Result<Option<ValidatedTable>, PalTaskError> {
            let mut image = ImageBuilder::new();
            write_table(
                &mut image,
                0x4000,
                STRIDE,
                &[SlotSpec {
                    stack_size: size,
                    ..slot("stk")
                }],
                0x88,
                &[],
            );
            validate(&image.image(), &table_candidate(0x4000, STRIDE, 8))
        }
        assert!(matches!(
            with_stack(0),
            Err(PalTaskError::Malformed {
                initializer: CFG_ENTRY,
                ..
            })
        ));
        assert!(matches!(
            with_stack(0x80e7),
            Err(PalTaskError::Malformed { .. })
        ));
        // 0x80e8 is deliberately not a power of two: no power-of-two
        // scheduler policy exists here.
        let validated = with_stack(0x80e8).unwrap().unwrap();
        assert_eq!(validated.tasks[0].stack_size, 0x80e8);
    }

    #[test]
    fn callback_and_unknown_pointer_retain_raw_values() {
        let mut image = ImageBuilder::new();
        write_table(
            &mut image,
            0x4000,
            STRIDE,
            &[SlotSpec {
                callback: 0xDEAD_BEEF,
                unknown_pointer: 0xCAFE_BABE,
                ..slot("rawish")
            }],
            0x99,
            &[],
        );
        let validated = validate(&image.image(), &table_candidate(0x4000, STRIDE, 8))
            .unwrap()
            .unwrap();
        assert_eq!(validated.tasks[0].callback, 0xDEAD_BEEF);
        assert_eq!(validated.tasks[0].unknown_pointer, 0xCAFE_BABE);
    }

    #[test]
    fn opaque_slot_bytes_change_the_slot_hash() {
        let mut first = ImageBuilder::new();
        write_table(
            &mut first,
            0x4000,
            STRIDE,
            &[SlotSpec {
                opaque: 0x11,
                ..slot("opaque")
            }],
            0xaa,
            &[],
        );
        let mut second = ImageBuilder::new();
        write_table(
            &mut second,
            0x4000,
            STRIDE,
            &[SlotSpec {
                opaque: 0x22,
                ..slot("opaque")
            }],
            0xaa,
            &[],
        );
        let first_table = validate(&first.image(), &table_candidate(0x4000, STRIDE, 8))
            .unwrap()
            .unwrap();
        let second_table = validate(&second.image(), &table_candidate(0x4000, STRIDE, 8))
            .unwrap()
            .unwrap();
        assert_eq!(
            first_table.tasks[0].slot_blake3,
            *blake3::hash(&slot_bytes(&first.bytes, 0x4000)).as_bytes()
        );
        assert_ne!(
            first_table.tasks[0].slot_blake3,
            second_table.tasks[0].slot_blake3
        );
        assert_eq!(
            first_table.terminal.slot_blake3, second_table.terminal.slot_blake3,
            "identical terminal bytes hash identically"
        );
    }

    #[test]
    fn terminal_validation_rejects_nonzero_known_fields() {
        fn with_terminal_field(
            field: u32,
            value: u32,
        ) -> std::result::Result<Option<ValidatedTable>, PalTaskError> {
            let mut image = ImageBuilder::new();
            write_table(&mut image, 0x4000, STRIDE, &[slot("tt")], 0xbb, &[]);
            // The terminal slot directly follows the single task slot.
            let terminal = 0x4000 + STRIDE;
            image.write_u32(terminal + field, value);
            validate(&image.image(), &table_candidate(0x4000, STRIDE, 8))
        }
        // A valid terminal keeps opaque bytes nonzero: only the known
        // fields must be zero.
        let mut image = ImageBuilder::new();
        write_table(&mut image, 0x4000, STRIDE, &[slot("tt")], 0xbb, &[]);
        let validated = validate(&image.image(), &table_candidate(0x4000, STRIDE, 8))
            .unwrap()
            .unwrap();
        assert_eq!(validated.table.count, 1);
        assert_eq!(validated.terminal.slot, 0x4000 + STRIDE);
        for (field, name) in [
            (NAME_OFFSET + 4, "priority"),
            (NAME_OFFSET + 8, "stack"),
            (NAME_OFFSET + 12, "entry"),
            (NAME_OFFSET + 16, "callback"),
            (NAME_OFFSET + 20, "unknown"),
        ] {
            assert!(
                matches!(
                    with_terminal_field(field, 7),
                    Err(PalTaskError::Malformed { initializer: CFG_ENTRY, context })
                        if context.contains(name)
                ),
                "terminal {name} must be zero"
            );
        }
    }

    #[test]
    fn interior_zero_name_pointer_with_leftover_fields_is_malformed() {
        let mut image = ImageBuilder::new();
        write_table(
            &mut image,
            0x4000,
            STRIDE,
            &[slot("one"), slot("two")],
            0xcc,
            &[],
        );
        // Zero the second slot's name pointer but leave its entry.
        image.write_u32(0x4000 + STRIDE + NAME_OFFSET, 0);
        assert!(matches!(
            validate(&image.image(), &table_candidate(0x4000, STRIDE, 8)),
            Err(PalTaskError::Malformed { initializer: CFG_ENTRY, context })
                if context.contains("slot 1")
        ));
    }

    #[test]
    fn missing_terminal_before_capacity_is_malformed() {
        let mut image = ImageBuilder::new();
        write_table(
            &mut image,
            0x4000,
            STRIDE,
            &[slot("aa"), slot("bb"), slot("cc"), slot("dd")],
            0xdd,
            &[],
        );
        // Capacity 4 with four nonterminal slots: the table fills
        // without ever observing a zero name pointer.
        assert!(matches!(
            validate(&image.image(), &table_candidate(0x4000, STRIDE, 4)),
            Err(PalTaskError::Malformed { initializer: CFG_ENTRY, context })
                if context.contains("terminal")
        ));
    }

    #[test]
    fn capacity_and_stride_limits_are_enforced() {
        // Capacity exactly 4096 with a terminal at index 1 is valid.
        let mut image = ImageBuilder::new();
        write_table(&mut image, 0x4000, STRIDE, &[slot("cap")], 0xee, &[]);
        assert!(
            validate(&image.image(), &table_candidate(0x4000, STRIDE, 4096))
                .unwrap()
                .is_some()
        );
        let mut image = ImageBuilder::new();
        write_table(&mut image, 0x4000, STRIDE, &[slot("cap")], 0xee, &[]);
        assert!(matches!(
            validate(&image.image(), &table_candidate(0x4000, STRIDE, 4097)),
            Err(PalTaskError::Malformed { initializer: CFG_ENTRY, context })
                if context.contains("capacity")
        ));

        // Stride exactly 64 KiB is valid; one byte more is not.
        let mut image = ImageBuilder::new();
        write_table(&mut image, 0x4000, 64 * 1024, &[slot("wide")], 0xee, &[]);
        assert!(
            validate(&image.image(), &table_candidate(0x4000, 64 * 1024, 8))
                .unwrap()
                .is_some()
        );
        let mut image = ImageBuilder::new();
        write_table(
            &mut image,
            0x4000,
            64 * 1024 + 1,
            &[slot("wide")],
            0xee,
            &[],
        );
        assert!(matches!(
            validate(&image.image(), &table_candidate(0x4000, 64 * 1024 + 1, 8)),
            Err(PalTaskError::Malformed { initializer: CFG_ENTRY, context })
                if context.contains("stride")
        ));

        // A stride that cannot contain the known descriptor fields is
        // malformed even below the ceiling.
        let mut image = ImageBuilder::new();
        write_table(
            &mut image,
            0x4000,
            NAME_OFFSET + 4,
            &[slot("narrow")],
            0xee,
            &[],
        );
        assert!(matches!(
            validate(&image.image(), &table_candidate(0x4000, NAME_OFFSET + 4, 8)),
            Err(PalTaskError::Malformed { .. })
        ));
    }

    #[test]
    fn slot_address_arithmetic_wrap_is_a_typed_outcome() {
        // A slot base whose first name field would wrap never crosses
        // the plausibility threshold: a miss, not a panic.
        let mut image = ImageBuilder::new();
        write_table(&mut image, 0x4000, STRIDE, &[slot("w")], 0x1f, &[]);
        assert!(
            validate(&image.image(), &table_candidate(0xFFFF_FFC0, STRIDE, 8))
                .unwrap()
                .is_none()
        );

        // A readable slot 0 whose complete stride extends past the
        // 32-bit address space is malformed after the threshold.
        let top_base = 0xFFFF_8000;
        let mut raw = vec![0u8; 0x70];
        put_u32(&mut raw, NAME_OFFSET as usize, 0x2000);
        put_u32(&mut raw, (NAME_OFFSET + 12) as usize, 0x3001);
        let top_image = RuntimeImage::from_plan(&raw, top_base, None).expect("fixture image");
        assert!(matches!(
            validate(&top_image, &table_candidate(top_base, 0xC000, 8)),
            Err(PalTaskError::Malformed {
                initializer: CFG_ENTRY,
                ..
            })
        ));
    }

    #[test]
    fn plausibility_threshold_requires_readable_first_slot() {
        // Slot 0 unmapped: a pre-threshold miss.
        let mut image = ImageBuilder::new();
        image.ensure(0x4000);
        assert!(
            validate(&image.image(), &table_candidate(0x4000, STRIDE, 8))
                .unwrap()
                .is_none()
        );

        // Slot 0 with a zero name pointer: a miss.
        let mut image = ImageBuilder::new();
        image.ensure(0x4000 + 0x80);
        image.write_u32(0x4000 + NAME_OFFSET, 0);
        image.write_u32(0x4000 + NAME_OFFSET + 12, 0x3001);
        assert!(
            validate(&image.image(), &table_candidate(0x4000, STRIDE, 8))
                .unwrap()
                .is_none()
        );

        // Slot 0 with a zero entry pointer: a miss.
        let mut image = ImageBuilder::new();
        image.ensure(0x4000 + 0x80);
        image.write_u32(0x4000 + NAME_OFFSET, 0x2000);
        image.write_u32(0x4000 + NAME_OFFSET + 12, 0);
        assert!(
            validate(&image.image(), &table_candidate(0x4000, STRIDE, 8))
                .unwrap()
                .is_none()
        );

        // A valid slot 0 makes every later failure malformed: slot 1
        // here has a priority word above 0xff.
        let mut image = ImageBuilder::new();
        write_table(
            &mut image,
            0x4000,
            STRIDE,
            &[
                slot("good"),
                SlotSpec {
                    priority: 0x155,
                    ..slot("bad")
                },
            ],
            0x2a,
            &[],
        );
        assert!(matches!(
            validate(&image.image(), &table_candidate(0x4000, STRIDE, 8)),
            Err(PalTaskError::Malformed {
                initializer: CFG_ENTRY,
                ..
            })
        ));
    }

    #[test]
    fn table_validation_charges_the_shared_budget_before_work() {
        let mut image = ImageBuilder::new();
        write_table(&mut image, 0x4000, STRIDE, &[slot("b")], 0x3a, &[]);
        let candidate = table_candidate(0x4000, STRIDE, 8);
        let mut budget = default_budget();
        budget
            .charge(
                MAX_CANDIDATE_VALIDATION_BYTES - u64::from(STRIDE) + 1,
                "candidate validation bytes",
            )
            .unwrap();
        assert!(matches!(
            validate_candidate(&image.image(), "fixture", &candidate, &mut budget),
            Err(PalTaskError::ResourceLimit {
                what: "candidate validation bytes",
                ..
            })
        ));
        // The rejected charge is never refunded: a second attempt with
        // the same budget fails identically.
        assert!(matches!(
            validate_candidate(&image.image(), "fixture", &candidate, &mut budget),
            Err(PalTaskError::ResourceLimit { .. })
        ));
    }

    #[test]
    fn cheetah_slot_zero_regression_parses_162_slots() {
        // The retained corpus shape: a 162-slot table whose slot 0 is
        // the semantic induction base, an unrelated accessor returning
        // slot_base + 0x118, and the terminal at slot_base + 162*stride.
        const SLOT_BASE: u32 = 0x4000;
        const CAPACITY: u32 = 1000;
        let slots: Vec<SlotSpec> = (0..162)
            .map(|index| slot(&format!("cheetah_task_{index:03}")))
            .collect();
        let mut image = ImageBuilder::new();
        let code = initializer_items(SLOT_BASE, CAPACITY);
        let (code_bytes, _) = assemble(BASE, &code);
        image.write(BASE, &code_bytes);
        write_table(&mut image, SLOT_BASE, STRIDE, &slots, 0x7e, &[]);
        // An unrelated accessor returning slot_base + 0x118.
        let accessor = [
            enc(&T32::Mov_Immediate_T3(gpr(0), 0x4118)),
            enc(&T32::Movt_T1(gpr(0), 0)),
            enc(&T32::Bx_T1(gpr(14))),
        ]
        .concat();
        let accessor_address = 0x40000;
        image.write(accessor_address, &accessor);

        let plan = discover_plan(&image.image(), "fixture")
            .unwrap()
            .expect("the cheetah-shaped table yields one plan");
        assert_eq!(plan.table.slot_base, SLOT_BASE);
        assert_eq!(plan.table.count, 162);
        assert_eq!(plan.tasks.len(), 162);
        assert_eq!(plan.terminal.slot, SLOT_BASE + 162 * STRIDE);
        assert_eq!(plan.tasks[0].name, "cheetah_task_000");
        assert_eq!(plan.tasks[161].name, "cheetah_task_161");
        assert_eq!(plan.tasks[161].slot, SLOT_BASE + 161 * STRIDE);
    }

    fn ident(
        namespace: LabelNamespace,
        entry: u32,
        isa: TaskIsa,
        lowest_index: u32,
        kind: LeafKind,
        preferred: &str,
    ) -> LeafIdentity {
        LeafIdentity {
            key: LeafIdentityKey {
                namespace,
                entry,
                isa,
                lowest_index,
                kind,
            },
            preferred: preferred.to_string(),
        }
    }

    #[test]
    fn sanitization_rules_preserve_runs_and_reject_empties() {
        assert_eq!(sanitize_task_name("alpha_9"), Some("alpha_9".to_string()));
        assert_eq!(sanitize_task_name("a--b"), Some("a_b".to_string()));
        assert_eq!(sanitize_task_name("a.b c"), Some("a_b_c".to_string()));
        assert_eq!(sanitize_task_name("!lead"), Some("_lead".to_string()));
        assert_eq!(sanitize_task_name("trail!"), Some("trail_".to_string()));
        assert_eq!(sanitize_task_name("9lives"), Some("_9lives".to_string()));
        assert_eq!(sanitize_task_name("!!"), Some("_".to_string()));
        assert_eq!(sanitize_task_name(""), None);
    }

    #[test]
    fn allocator_protects_unique_leaves_and_suffixes_duplicates() {
        // Two identities sharing one preferred leaf in the reserved
        // namespace, in identity-key order.
        let leaves = allocate_leaves(&[
            ident(
                LabelNamespace::Reserved,
                0x2000,
                TaskIsa::Thumb,
                0,
                LeafKind::Role,
                "pal_TaskEntry_x",
            ),
            ident(
                LabelNamespace::Reserved,
                0x2100,
                TaskIsa::Thumb,
                1,
                LeafKind::Role,
                "pal_TaskEntry_x",
            ),
            ident(
                LabelNamespace::Reserved,
                0x2200,
                TaskIsa::Thumb,
                2,
                LeafKind::Role,
                "pal_TaskEntry_unique",
            ),
        ])
        .unwrap();
        assert_eq!(
            leaves[&LeafIdentityKey {
                namespace: LabelNamespace::Reserved,
                entry: 0x2000,
                isa: TaskIsa::Thumb,
                lowest_index: 0,
                kind: LeafKind::Role,
            }],
            "pal_TaskEntry_x_pme_00002000_00000000_00000000"
        );
        assert_eq!(
            leaves[&LeafIdentityKey {
                namespace: LabelNamespace::Reserved,
                entry: 0x2100,
                isa: TaskIsa::Thumb,
                lowest_index: 1,
                kind: LeafKind::Role,
            }],
            "pal_TaskEntry_x_pme_00002100_00000001_00000000"
        );
        // The unique leaf is protected exactly as preferred.
        assert_eq!(
            leaves[&LeafIdentityKey {
                namespace: LabelNamespace::Reserved,
                entry: 0x2200,
                isa: TaskIsa::Thumb,
                lowest_index: 2,
                kind: LeafKind::Role,
            }],
            "pal_TaskEntry_unique"
        );

        // The same preferred leaf in the global namespace allocates
        // independently: namespaces are separate collision domains.
        let leaves = allocate_leaves(&[
            ident(
                LabelNamespace::Global,
                0x2000,
                TaskIsa::Thumb,
                0,
                LeafKind::Primary,
                "pal_TaskEntry_x",
            ),
            ident(
                LabelNamespace::Global,
                0x2100,
                TaskIsa::Thumb,
                1,
                LeafKind::Primary,
                "pal_TaskEntry_x",
            ),
        ])
        .unwrap();
        let values: Vec<&String> = leaves.values().collect();
        assert_eq!(
            values,
            [
                &"pal_TaskEntry_x_pme_00002000_00000000_00000000".to_string(),
                &"pal_TaskEntry_x_pme_00002100_00000001_00000000".to_string(),
            ]
        );
    }

    #[test]
    fn allocator_tries_exactly_nonces_zero_through_two_n() {
        // Identity A's nonce-0..2 candidates are pre-collided by three
        // protected preferred leaves, so A must walk to nonce 3; the
        // group peer E takes its free nonce 0. Five identities bound
        // the walk at nonce <= 2*N = 10, and the pigeonhole guarantee
        // keeps allocation total.
        let identities = vec![
            ident(
                LabelNamespace::Reserved,
                0x2000,
                TaskIsa::Thumb,
                0,
                LeafKind::Role,
                "x",
            ),
            ident(
                LabelNamespace::Reserved,
                0x2100,
                TaskIsa::Thumb,
                1,
                LeafKind::Role,
                "x",
            ),
            ident(
                LabelNamespace::Reserved,
                0x3000,
                TaskIsa::Thumb,
                2,
                LeafKind::Role,
                "x_pme_00002000_00000000_00000000",
            ),
            ident(
                LabelNamespace::Reserved,
                0x3100,
                TaskIsa::Thumb,
                3,
                LeafKind::Role,
                "x_pme_00002000_00000000_00000001",
            ),
            ident(
                LabelNamespace::Reserved,
                0x3200,
                TaskIsa::Thumb,
                4,
                LeafKind::Role,
                "x_pme_00002000_00000000_00000002",
            ),
        ];
        let leaves = allocate_leaves(&identities).unwrap();
        let of = |entry: u32, lowest: u32| {
            leaves
                .get(&LeafIdentityKey {
                    namespace: LabelNamespace::Reserved,
                    entry,
                    isa: TaskIsa::Thumb,
                    lowest_index: lowest,
                    kind: LeafKind::Role,
                })
                .unwrap()
                .clone()
        };
        assert_eq!(
            of(0x2000, 0),
            "x_pme_00002000_00000000_00000003",
            "A walks past the three pre-collided nonces"
        );
        assert_eq!(of(0x2100, 1), "x_pme_00002100_00000001_00000000");
        assert_eq!(
            of(0x3000, 2),
            "x_pme_00002000_00000000_00000000",
            "protected preferred leaves keep their exact strings"
        );
        // Every final leaf is distinct.
        let mut seen = BTreeSet::new();
        for leaf in leaves.values() {
            assert!(seen.insert(leaf.clone()), "duplicate leaf {leaf}");
        }
    }

    #[test]
    fn allocator_forbids_suffix_collisions_with_duplicate_group_preferreds() {
        // C's nonce-0 candidate is exactly the preferred leaf of the
        // duplicate group D/E (an unprotected preferred under the
        // brief's letter): the design's forbidden set covers every
        // preferred in the domain, so C must skip that nonce and take
        // the next one.
        let leaves = allocate_leaves(&[
            ident(
                LabelNamespace::Reserved,
                0x2000,
                TaskIsa::Thumb,
                0,
                LeafKind::Role,
                "x",
            ),
            ident(
                LabelNamespace::Reserved,
                0x2100,
                TaskIsa::Thumb,
                1,
                LeafKind::Role,
                "x",
            ),
            ident(
                LabelNamespace::Reserved,
                0x2200,
                TaskIsa::Thumb,
                2,
                LeafKind::Role,
                "x",
            ),
            ident(
                LabelNamespace::Reserved,
                0x3000,
                TaskIsa::Thumb,
                3,
                LeafKind::Role,
                "x_pme_00002200_00000002_00000000",
            ),
            ident(
                LabelNamespace::Reserved,
                0x3100,
                TaskIsa::Thumb,
                4,
                LeafKind::Role,
                "x_pme_00002200_00000002_00000000",
            ),
        ])
        .unwrap();
        let of = |entry: u32, lowest: u32| {
            leaves
                .get(&LeafIdentityKey {
                    namespace: LabelNamespace::Reserved,
                    entry,
                    isa: TaskIsa::Thumb,
                    lowest_index: lowest,
                    kind: LeafKind::Role,
                })
                .unwrap()
                .clone()
        };
        assert_eq!(
            of(0x2200, 2),
            "x_pme_00002200_00000002_00000001",
            "C skips its nonce-0 collision with the D/E group's preferred"
        );
        assert_eq!(of(0x2000, 0), "x_pme_00002000_00000000_00000000");
        assert_eq!(of(0x2100, 1), "x_pme_00002100_00000001_00000000");
        // D/E suffix their own full preferred base.
        assert_eq!(
            of(0x3000, 3),
            "x_pme_00002200_00000002_00000000_pme_00003000_00000003_00000000"
        );
        assert_eq!(
            of(0x3100, 4),
            "x_pme_00002200_00000002_00000000_pme_00003100_00000004_00000000"
        );
        // Every final leaf stays distinct from every preferred and
        // from the other assignments.
        let mut seen = BTreeSet::new();
        for leaf in leaves.values() {
            assert!(seen.insert(leaf.clone()), "duplicate leaf {leaf}");
        }
        assert!(!seen.contains("x"));
        assert!(!seen.contains("x_pme_00002200_00000002_00000000"));
    }

    #[test]
    fn allocator_enforces_the_2000_character_boundary() {
        // A suffixed base is truncated so the complete leaf is exactly
        // 2000 characters.
        let base_1970 = "b".repeat(1970);
        let base_1969 = "c".repeat(1969);
        let leaves = allocate_leaves(&[
            ident(
                LabelNamespace::Reserved,
                0x2000,
                TaskIsa::Thumb,
                0,
                LeafKind::Role,
                &base_1970,
            ),
            ident(
                LabelNamespace::Reserved,
                0x2100,
                TaskIsa::Thumb,
                1,
                LeafKind::Role,
                &base_1970,
            ),
            ident(
                LabelNamespace::Reserved,
                0x2200,
                TaskIsa::Thumb,
                2,
                LeafKind::Role,
                &base_1969,
            ),
            ident(
                LabelNamespace::Reserved,
                0x2300,
                TaskIsa::Thumb,
                3,
                LeafKind::Role,
                &base_1969,
            ),
        ])
        .unwrap();
        for leaf in leaves.values() {
            assert!(leaf.is_ascii());
            assert!(
                leaf.chars().count() <= 2000,
                "leaf {} is too long",
                leaf.len()
            );
        }
        let of = |lowest: u32| {
            leaves
                .values()
                .find(|leaf| leaf.ends_with(&format!("_pme_00002100_0000000{lowest}_00000000")))
                .unwrap()
                .clone()
        };
        let long = of(1);
        assert_eq!(long.chars().count(), 2000);
        assert!(long.starts_with(&"b".repeat(1969)));
        assert!(long.ends_with("_pme_00002100_00000001_00000000"));

        // A unique preferred leaf that itself exceeds 2000 characters
        // cannot be represented: an artifact error, never a malformed
        // firmware verdict.
        let over = allocate_leaves(&[ident(
            LabelNamespace::Reserved,
            0x2000,
            TaskIsa::Thumb,
            0,
            LeafKind::Role,
            &"l".repeat(2001),
        )]);
        assert!(matches!(over, Err(PalTaskError::Artifact(_))));
    }

    #[test]
    fn duplicate_identical_records_share_one_label_and_application() {
        let mut image = ImageBuilder::new();
        let (names, entries) = write_table(
            &mut image,
            0x4000,
            STRIDE,
            &[slot("dup"), slot("dup")],
            0x4a,
            &[],
        );
        // Point both records at one name and one entry.
        let shared_entry = entries[0];
        image.write_u32(0x4000 + STRIDE + NAME_OFFSET, names[0]);
        image.write_u32(0x4000 + NAME_OFFSET + 12, shared_entry | 1);
        image.write_u32(0x4000 + STRIDE + NAME_OFFSET + 12, shared_entry | 1);
        let validated = validate(&image.image(), &table_candidate(0x4000, STRIDE, 8))
            .unwrap()
            .unwrap();
        assert_eq!(validated.tasks.len(), 2);
        assert_eq!(validated.tasks[0].name, "dup");
        assert_eq!(validated.tasks[1].name, "dup");
        assert_eq!(validated.tasks[0].task_label, validated.tasks[1].task_label);
        assert_eq!(validated.tasks[0].task_label, "pal_TaskEntry_dup");
        assert_eq!(validated.applications.len(), 1);
        let application = &validated.applications[0];
        assert_eq!(application.task_indices, [0, 1]);
        assert_eq!(application.desired_primary, "pal_TaskEntry_dup");
        assert_eq!(application.labels.len(), 1);
        assert_eq!(application.labels[0].label, "pal_TaskEntry_dup");
        assert_eq!(application.labels[0].task_indices, [0, 1]);
    }

    #[test]
    fn duplicate_names_at_distinct_entries_get_deterministic_suffixes() {
        let mut image = ImageBuilder::new();
        let (_, entries) = write_table(
            &mut image,
            0x4000,
            STRIDE,
            &[slot("twin"), slot("twin")],
            0x5a,
            &[],
        );
        let validated = validate(&image.image(), &table_candidate(0x4000, STRIDE, 8))
            .unwrap()
            .unwrap();
        let first_entry = entries[0];
        let second_entry = entries[1];
        assert_eq!(
            validated.tasks[0].task_label,
            format!("pal_TaskEntry_twin_pme_{first_entry:08x}_00000000_00000000")
        );
        assert_eq!(
            validated.tasks[1].task_label,
            format!("pal_TaskEntry_twin_pme_{second_entry:08x}_00000001_00000000")
        );
        assert_eq!(validated.applications.len(), 2);
        assert_eq!(
            validated.applications[0].desired_primary,
            format!("pal_TaskEntry_twin_pme_{first_entry:08x}_00000000_00000000")
        );
        assert_eq!(
            validated.applications[1].desired_primary,
            format!("pal_TaskEntry_twin_pme_{second_entry:08x}_00000001_00000000")
        );
    }

    #[test]
    fn shared_entries_use_shared_primary_with_per_name_labels() {
        let mut image = ImageBuilder::new();
        let (_, entries) = write_table(
            &mut image,
            0x4000,
            STRIDE,
            &[slot("alpha"), slot("beta")],
            0x6a,
            &[],
        );
        let shared = entries[0];
        image.write_u32(0x4000 + STRIDE + NAME_OFFSET + 12, shared | 1);
        let validated = validate(&image.image(), &table_candidate(0x4000, STRIDE, 8))
            .unwrap()
            .unwrap();
        assert_eq!(validated.applications.len(), 1);
        let application = &validated.applications[0];
        assert_eq!(application.entry, shared);
        assert_eq!(application.task_indices, [0, 1]);
        assert_eq!(
            application.desired_primary,
            format!("pal_TaskEntry_shared_{shared:08x}")
        );
        assert_eq!(application.labels.len(), 2);
        assert_eq!(application.labels[0].label, "pal_TaskEntry_alpha");
        assert_eq!(application.labels[0].task_indices, [0]);
        assert_eq!(application.labels[1].label, "pal_TaskEntry_beta");
        assert_eq!(application.labels[1].task_indices, [1]);
    }

    #[test]
    fn sanitized_collisions_allocate_deterministic_suffixes() {
        let mut image = ImageBuilder::new();
        write_table(
            &mut image,
            0x4000,
            STRIDE,
            &[slot("a-b"), slot("a.b")],
            0x7a,
            &[],
        );
        let validated = validate(&image.image(), &table_candidate(0x4000, STRIDE, 8))
            .unwrap()
            .unwrap();
        assert_eq!(validated.tasks[0].name, "a-b");
        assert_eq!(validated.tasks[1].name, "a.b");
        assert!(
            validated.tasks[0]
                .task_label
                .starts_with("pal_TaskEntry_a_b_pme_")
        );
        assert!(
            validated.tasks[1]
                .task_label
                .starts_with("pal_TaskEntry_a_b_pme_")
        );
        assert_ne!(validated.tasks[0].task_label, validated.tasks[1].task_label);

        // A pure-punctuation name sanitizes to a single replacement
        // underscore; only the empty string is rejected.
        let mut image = ImageBuilder::new();
        write_table(&mut image, 0x4000, STRIDE, &[slot("!!")], 0x7a, &[]);
        let validated = validate(&image.image(), &table_candidate(0x4000, STRIDE, 8))
            .unwrap()
            .unwrap();
        assert_eq!(validated.tasks[0].name, "!!");
        assert_eq!(validated.tasks[0].task_label, "pal_TaskEntry__");
    }

    #[test]
    fn arm_thumb_aliases_normalizing_to_one_address_are_malformed() {
        let mut image = ImageBuilder::new();
        let arm_word = 0xE3A0_0000u32.to_le_bytes();
        let push = enc(&T32::Push_T1(vec![gpr(4), gpr(14)]));
        write_table(
            &mut image,
            0x4000,
            STRIDE,
            &[
                SlotSpec {
                    entry_pointer: Some(0x3600),
                    ..slot("arm_side")
                },
                SlotSpec {
                    entry_pointer: Some(0x3601),
                    ..slot("thumb_side")
                },
            ],
            0x8a,
            &[(0x3600, arm_word.to_vec()), (0x3604, push)],
        );
        assert!(matches!(
            validate(&image.image(), &table_candidate(0x4000, STRIDE, 8)),
            Err(PalTaskError::Malformed { initializer: CFG_ENTRY, context })
                if context.contains("alias")
        ));
    }

    #[test]
    fn applications_partition_task_indices_and_labels_exactly() {
        // A rich table: one shared entry with two names, a duplicate
        // identical record, and two unique tasks.
        let mut image = ImageBuilder::new();
        let (_, entries) = write_table(
            &mut image,
            0x4000,
            STRIDE,
            &[
                slot("shared_a"),
                slot("shared_b"),
                slot("solo"),
                slot("solo"),
            ],
            0x9a,
            &[],
        );
        let shared = entries[0];
        image.write_u32(0x4000 + STRIDE + NAME_OFFSET + 12, shared | 1);
        // Records 2 and 3 are identical duplicates of "solo" at
        // entries[2].
        image.write_u32(0x4000 + 3 * STRIDE + NAME_OFFSET + 12, entries[2] | 1);
        let validated = validate(&image.image(), &table_candidate(0x4000, STRIDE, 16))
            .unwrap()
            .unwrap();
        let count = validated.tasks.len();
        assert_eq!(count, 4);
        let mut seen_indices = BTreeSet::new();
        for application in &validated.applications {
            let mut label_indices = BTreeSet::new();
            for label in &application.labels {
                for index in &label.task_indices {
                    assert!(
                        label_indices.insert(*index),
                        "index {index} appears in two labels of one application"
                    );
                }
            }
            let application_indices: BTreeSet<u32> =
                application.task_indices.iter().copied().collect();
            assert_eq!(
                label_indices, application_indices,
                "labels must partition the application indices"
            );
            for index in &application_indices {
                assert!(
                    seen_indices.insert(*index),
                    "index {index} appears in two applications"
                );
            }
        }
        assert_eq!(
            seen_indices,
            (0..count as u32).collect::<BTreeSet<u32>>(),
            "applications must partition every task index"
        );
        for task in &validated.tasks {
            let application = validated
                .applications
                .iter()
                .find(|application| application.task_indices.contains(&task.index))
                .expect("every task belongs to one application");
            let label = application
                .labels
                .iter()
                .find(|label| label.task_indices.contains(&task.index))
                .expect("every task belongs to one label");
            assert_eq!(label.label, task.task_label);
        }
        // The shared entry carries the shared primary and both names.
        let shared_application = validated
            .applications
            .iter()
            .find(|application| application.entry == shared)
            .unwrap();
        assert_eq!(
            shared_application.desired_primary,
            format!("pal_TaskEntry_shared_{shared:08x}")
        );
        // Applications are sorted by (entry, isa).
        let mut order = validated
            .applications
            .iter()
            .map(|application| (application.entry, application.isa))
            .collect::<Vec<_>>();
        let mut sorted = order.clone();
        sorted.sort_by_key(|(entry, isa)| (*entry, *isa == TaskIsa::Thumb));
        assert_eq!(order, sorted);
        order.dedup();
        assert_eq!(order.len(), validated.applications.len());
    }

    /// The canonical initializer shape with a parameterized slot base
    /// and capacity: slot r4, count r5, name r0, guard shift 3.
    fn initializer_items(slot_base: u32, capacity: u32) -> Vec<FixtureItem> {
        let guard_value = capacity / 8 - 1;
        vec![
            insn("init", |_, _| T32::Push_T1(vec![gpr(4), gpr(14)])),
            insn("ref", |pc, l| T32::Adr_T1(low(1), adr_to(l, "anchor", pc))),
            insn("zero", |_, _| T32::Mov_Immediate_T1(low(5), 0)),
            insn("slotlo", move |_, _| {
                T32::Mov_Immediate_T3(gpr(4), u16::try_from(slot_base & 0xffff).unwrap())
            }),
            insn("slothi", move |_, _| {
                T32::Movt_T1(gpr(4), u16::try_from(slot_base >> 16).unwrap())
            }),
            insn("call", |pc, l| T32::Bl_T1(branch32_to(l, "leaf", pc))),
            insn("load", |_, _| T32::Ldr_Immediate_T1(low(0), low(4), 0x4c)),
            insn("lcbz", |pc, l| T32::Cbz_T1(low(0), cbz_to(l, "term", pc))),
            insn("lstr", |_, _| T32::Str_Immediate_T1(low(5), low(4), 0x0c)),
            insn("ladd", |_, _| T32::Add_Immediate_T2(low(5), 1)),
            insn("lstride", |_, _| {
                T32::Add_Immediate_T3(gpr(4), gpr(4), 0x1f8, false)
            }),
            insn("lcmp", move |_, _| T32::Cmp_Immediate_T2(gpr(5), capacity)),
            insn("lbne", |pc, l| {
                T32::B_T1(Arm32Condition::NotEqual, branch_to(l, "load", pc))
            }),
            insn("cap", |_, l| {
                T32::Mov_Immediate_T3(
                    gpr(0),
                    u16::try_from(word_at(l, "globals") & 0xffff).unwrap(),
                )
            }),
            insn("", |_, l| {
                T32::Movt_T1(gpr(0), u16::try_from(word_at(l, "globals") >> 16).unwrap())
            }),
            insn("cval", move |_, _| {
                T32::Mov_Immediate_T3(gpr(1), u16::try_from(capacity).unwrap())
            }),
            insn("cstr", |_, _| T32::Str_Immediate_T1(low(1), low(0), 0)),
            insn("cjmp", |pc, l| T32::B_T2(branch_to(l, "join", pc))),
            insn("term", |pc, l| {
                T32::Adr_T1(low(0), adr_to(l, "globals", pc))
            }),
            insn("tstr", |_, _| T32::Str_Immediate_T1(low(5), low(0), 0)),
            insn("glsr", |_, _| T32::Lsr_Immediate_T1(low(0), low(5), 3)),
            insn("gcmp", move |_, _| {
                T32::Cmp_Immediate_T1(low(0), u8::try_from(guard_value).unwrap())
            }),
            insn("gbhi", |pc, l| {
                T32::B_T1(Arm32Condition::UnsignedHigher, branch_to(l, "join", pc))
            }),
            insn("sstr", |_, _| T32::Str_Immediate_T1(low(5), low(4), 0x0c)),
            insn("sadd", |_, _| T32::Add_Immediate_T2(low(5), 1)),
            insn("sslot", |_, _| {
                T32::Add_Immediate_T3(gpr(4), gpr(4), 0x1f8, false)
            }),
            insn("smov", |_, _| T32::Mov_Register_T1(gpr(6), gpr(0))),
            insn("snop", |_, _| T32::Nop_T1),
            insn("scmp", move |_, _| T32::Cmp_Immediate_T2(gpr(5), capacity)),
            insn("sbne", |pc, l| {
                T32::B_T1(Arm32Condition::NotEqual, branch_to(l, "sstr", pc))
            }),
            insn("join", |_, _| T32::Bx_T1(gpr(14))),
            FixtureItem::Align(4),
            FixtureItem::Anchor("anchor"),
            FixtureItem::Align(2),
            insn("leaf", |_, _| T32::Mov_Immediate_T3(gpr(0), 0x1234)),
            insn("leaf2", |_, _| T32::Movt_T1(gpr(0), 0)),
            insn("leafret", |_, _| T32::Bx_T1(gpr(14))),
            FixtureItem::Align(4),
            FixtureItem::Data("globals", 8),
        ]
    }

    fn end_to_end_plan(
        slot_base: u32,
        capacity: u32,
        slots: &[SlotSpec],
        terminal_opaque: u8,
    ) -> (ImageBuilder, Option<crate::pal_tasks::TaskPlan>) {
        let mut image = ImageBuilder::new();
        let (code_bytes, _) = assemble(BASE, &initializer_items(slot_base, capacity));
        image.write(BASE, &code_bytes);
        write_table(&mut image, slot_base, STRIDE, slots, terminal_opaque, &[]);
        let plan = discover_plan(&image.image(), "fixture").unwrap();
        (image, plan)
    }

    #[test]
    fn discover_end_to_end_yields_one_complete_plan() {
        const SLOT_BASE: u32 = 0x4000;
        let (image, plan) = end_to_end_plan(
            SLOT_BASE,
            8,
            &[
                SlotSpec {
                    callback: 0x10,
                    unknown_pointer: 0x20,
                    ..slot("first_task")
                },
                slot("second_task"),
            ],
            0x33,
        );
        let plan = plan.expect("one complete plan");
        assert_eq!(plan.image_base, BASE);
        assert_eq!(plan.image_size, u32::try_from(image.bytes.len()).unwrap());
        assert_eq!(plan.initializer.cfg_entry, BASE);
        assert_eq!(plan.table.slot_base, SLOT_BASE);
        assert_eq!(plan.table.count, 2);
        assert_eq!(plan.table.capacity, 8);
        assert_eq!(plan.table.descriptor_projection_offset, NAME_OFFSET - 0x24);
        assert_eq!(plan.table.priority_offset, NAME_OFFSET + 4);
        assert_eq!(plan.table.stack_size_offset, NAME_OFFSET + 8);
        assert_eq!(plan.table.entry_offset, NAME_OFFSET + 12);
        assert_eq!(plan.table.callback_offset, NAME_OFFSET + 16);
        assert_eq!(plan.table.unknown_pointer_offset, NAME_OFFSET + 20);
        assert_eq!(plan.tasks.len(), 2);
        assert_eq!(plan.tasks[0].name, "first_task");
        assert_eq!(plan.tasks[0].callback, 0x10);
        assert_eq!(plan.tasks[0].unknown_pointer, 0x20);
        assert_eq!(plan.tasks[0].task_label, "pal_TaskEntry_first_task");
        assert_eq!(plan.tasks[1].task_label, "pal_TaskEntry_second_task");
        assert_eq!(plan.terminal.slot, SLOT_BASE + 2 * STRIDE);
        assert_eq!(plan.applications.len(), 2);
        assert_eq!(
            plan.applications[0].desired_primary,
            "pal_TaskEntry_first_task"
        );
    }

    #[test]
    fn discover_returns_none_without_pal_evidence() {
        let image = raw_image(&[0u8; 0x100]);
        assert!(discover_plan(&image, "fixture").unwrap().is_none());
    }

    #[test]
    fn discover_returns_none_when_the_first_slot_is_unreadable() {
        // The initializer proof completes, but the table region is
        // unmapped: a pre-threshold miss yields no plan.
        let mut image = ImageBuilder::new();
        let (code_bytes, _) = assemble(BASE, &initializer_items(0x4000, 8));
        image.write(BASE, &code_bytes);
        assert!(discover_plan(&image.image(), "fixture").unwrap().is_none());
    }

    #[test]
    fn discover_reports_every_candidate_when_multiple_complete_survivors() {
        let mut image = ImageBuilder::new();
        let (first, _) = assemble(BASE, &initializer_items(0x4000, 8));
        let (second, _) = assemble(BASE + 0x200, &initializer_items(0x10000, 8));
        image.write(BASE, &first);
        image.write(BASE + 0x200, &second);
        write_table(&mut image, 0x4000, STRIDE, &[slot("aa")], 0x44, &[]);
        write_table(&mut image, 0x10000, STRIDE, &[slot("bb")], 0x55, &[]);
        assert!(matches!(
            discover_plan(&image.image(), "fixture"),
            Err(PalTaskError::Ambiguous { candidates })
                if candidates == vec![(BASE, 0x4000), (BASE + 0x200, 0x10000)]
        ));
    }

    #[test]
    fn discover_fails_malformed_even_with_a_valid_sibling() {
        let mut image = ImageBuilder::new();
        let (first, _) = assemble(BASE, &initializer_items(0x4000, 8));
        let (second, _) = assemble(BASE + 0x200, &initializer_items(0x10000, 8));
        image.write(BASE, &first);
        image.write(BASE + 0x200, &second);
        // The first table is malformed after the threshold (priority
        // word above 0xff in its only slot); the second is valid.
        write_table(
            &mut image,
            0x4000,
            STRIDE,
            &[SlotSpec {
                priority: 0x100,
                ..slot("bad")
            }],
            0x44,
            &[],
        );
        write_table(&mut image, 0x10000, STRIDE, &[slot("good")], 0x55, &[]);
        assert!(matches!(
            discover_plan(&image.image(), "fixture"),
            Err(PalTaskError::Malformed {
                initializer: BASE,
                ..
            })
        ));
    }
}
