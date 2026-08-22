// The canonical authenticated PAL task manifest: the exact wire
// projection of one validated `TaskPlan`, the strict fail-closed reader
// that revalidates every claim against the runtime image, and atomic
// present/absence publication under `pal_tasks/<label>/tasks.json`.
// The wire carries no output path, no analyzer membership, and no
// unchecked decision: applications are recomputed by the reader through
// the same deterministic allocator `table` used, and every hash and
// storage provenance claim is recomputed through `RuntimeImage`.

use crate::arm32::{ControlFlow, InstructionDecoder, PureRustDecoder, ValueEffect};
use crate::execution_ranges::parse_blake3;
use crate::pal_tasks::{
    ANCHOR_PATTERN, AnchorProofPath, AnchorProvenance, AnchorReference, AnchorReferenceKind,
    AnchorReferenceKind::{Adr, Literal, MovwMovt},
    CapacityGuard, DESCRIPTOR_PROJECTION_OFFSET, InitializerEvidence, MAX_TABLE_CAPACITY,
    MAX_TABLE_STRIDE, MAX_TASK_NAME_BYTES, PalTaskError, SlotDefinition, TaskApplication, TaskIsa,
    TaskPlan, TaskRecord, TaskTable, TerminalRecord,
};
use crate::runtime_image::{RuntimeImage, StorageKind, StorageSpan};
use atomic_write_file::AtomicWriteFile;
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

pub(crate) const FORMAT: &str = "pixel-modem-extractor-pal-tasks-v1";

const SCHEMA_VERSION: u32 = 1;
const SEMANTIC_ADAPTER: &str = "pixel-modem-extractor-arm32-v1";
const BACKEND_CRATE: &str = "scaleservers-arm32-assembly";
const CAPACITY_GUARD_RELATION: &str = "count_ge_capacity";
const ARTIFACT_FILE_NAME: &str = "tasks.json";
const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;

/// The result of one successful present publication: the current-run
/// state itself, never inferred from path existence.
pub(crate) struct MaterializedTaskMap {
    pub relative_path: String,
    pub blake3: String,
    pub identity: String,
    pub task_records: usize,
    pub distinct_entries: usize,
}

/// The identity a reader must pin: the image label, the raw image
/// digest, and the complete scatter dependency (the whole load map, not
/// only the entries selected evidence reached).
#[derive(Clone, Copy)]
pub(crate) struct TaskArtifactContext<'a> {
    pub label: &'a str,
    pub image_blake3: [u8; 32],
    pub scatter_load_map_blake3: Option<[u8; 32]>,
}

/// One strict-reader verdict: the revalidated plan plus the identities
/// the artifact was pinned against.
pub(crate) struct ValidatedTaskArtifact {
    pub plan: TaskPlan,
    pub image_label: String,
    pub image_blake3: [u8; 32],
    pub manifest_blake3: [u8; 32],
    pub identity: String,
    pub scatter_load_map_blake3: Option<[u8; 32]>,
}

type Result<T> = std::result::Result<T, PalTaskError>;

fn invalid(reason: impl Into<String>) -> PalTaskError {
    PalTaskError::Artifact(reason.into())
}

// ---------------------------------------------------------------------------
// Publication
// ---------------------------------------------------------------------------

pub(crate) fn materialize(
    plan: &TaskPlan,
    context: TaskArtifactContext<'_>,
    root: &Path,
) -> Result<MaterializedTaskMap> {
    validate_label(context.label)?;
    let pal_dir = owned_directory(&root.join("pal_tasks"), true)?
        .ok_or_else(|| invalid("the artifact pal_tasks directory cannot be created"))?;
    let label_dir = owned_directory(&pal_dir.join(context.label), true)?
        .ok_or_else(|| invalid("the artifact label directory cannot be created"))?;

    let bytes = serialize(plan, &context)?;
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(invalid(format!(
            "serialized manifest is {} bytes, above the {MAX_MANIFEST_BYTES}-byte ceiling",
            bytes.len()
        )));
    }

    let target = label_dir.join(ARTIFACT_FILE_NAME);
    match fs::symlink_metadata(&target) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(invalid("manifest destination is a symlink"));
            }
            if !metadata.is_file() {
                return Err(invalid("manifest destination is not a regular file"));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(invalid(format!(
                "manifest destination metadata is unavailable: {error}"
            )));
        }
    }

    let manifest_blake3 = *blake3::hash(&bytes).as_bytes();
    let mut file = AtomicWriteFile::open(&target)
        .map_err(|error| invalid(format!("atomic manifest publication failed: {error}")))?;
    file.write_all(&bytes)
        .map_err(|error| invalid(format!("atomic manifest write failed: {error}")))?;
    run_before_commit();
    file.commit()
        .map_err(|error| invalid(format!("atomic manifest commit failed: {error}")))?;

    let used = scatter_entries_used(plan);
    let task_records = plan.tasks.len();
    let distinct_entries = used.len();
    Ok(MaterializedTaskMap {
        relative_path: format!("pal_tasks/{}/{}", context.label, ARTIFACT_FILE_NAME),
        blake3: blake3_hex(manifest_blake3),
        identity: identity(manifest_blake3, task_records, distinct_entries),
        task_records,
        distinct_entries,
    })
}

pub(crate) fn clear_materialized(root: &Path, label: &str) -> Result<()> {
    validate_label(label)?;
    let Some(pal_dir) = owned_directory(&root.join("pal_tasks"), false)? else {
        return Ok(());
    };
    let label_dir = pal_dir.join(label);
    match fs::symlink_metadata(&label_dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(invalid(format!(
                "owned label directory metadata is unavailable: {error}"
            )));
        }
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(invalid(
                    "owned label directory is a symlink and never becomes absence",
                ));
            }
            if !metadata.is_dir() {
                return Err(invalid(
                    "owned label path is not a directory and never becomes absence",
                ));
            }
        }
    }

    let manifest = label_dir.join(ARTIFACT_FILE_NAME);
    match fs::symlink_metadata(&manifest) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(invalid(format!(
                "owned manifest metadata is unavailable: {error}"
            )));
        }
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(invalid(
                    "owned manifest path is a symlink and never becomes absence",
                ));
            }
            if !metadata.is_file() {
                return Err(invalid(
                    "owned manifest path is not a regular file and never becomes absence",
                ));
            }
            fs::remove_file(&manifest)
                .map_err(|error| invalid(format!("owned manifest cannot be removed: {error}")))?;
        }
    }

    match fs::remove_dir(&label_dir) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty => Ok(()),
        Err(error) => Err(invalid(format!(
            "owned label directory cannot be removed: {error}"
        ))),
    }
}

fn validate_label(label: &str) -> Result<()> {
    let safe = !label.is_empty()
        && label != "."
        && label != ".."
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'));
    if safe {
        Ok(())
    } else {
        Err(invalid(format!("invalid artifact label {label:?}")))
    }
}

/// One owned real directory: created when missing (if `create`),
/// rejected when it exists as a symlink or a non-directory.
fn owned_directory(path: &Path, create: bool) -> Result<Option<PathBuf>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !create => return Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|error| {
                    invalid(format!("artifact directory cannot be created: {error}"))
                })?;
            }
            match fs::create_dir(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(invalid(format!(
                        "artifact directory cannot be created: {error}"
                    )));
                }
            }
            fs::symlink_metadata(path).map_err(|error| {
                invalid(format!(
                    "artifact directory metadata is unavailable: {error}"
                ))
            })?
        }
        Err(error) => {
            return Err(invalid(format!(
                "artifact directory metadata is unavailable: {error}"
            )));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(invalid(format!(
            "artifact directory {} is not an owned real directory",
            path.display()
        )));
    }
    Ok(Some(path.to_path_buf()))
}

#[cfg(all(test, unix))]
type BeforeCommitHook = Box<dyn FnOnce()>;

#[cfg(all(test, unix))]
thread_local! {
    static BEFORE_COMMIT: std::cell::RefCell<Option<BeforeCommitHook>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(all(test, unix))]
fn set_before_commit(hook: impl FnOnce() + 'static) {
    BEFORE_COMMIT.with(|slot| {
        assert!(
            slot.borrow_mut().replace(Box::new(hook)).is_none(),
            "a before-commit hook is already installed"
        );
    });
}

fn run_before_commit() {
    #[cfg(all(test, unix))]
    BEFORE_COMMIT.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

// ---------------------------------------------------------------------------
// Canonical serialization
// ---------------------------------------------------------------------------

fn address(value: u32) -> String {
    format!("{value:#010x}")
}

fn blake3_hex(digest: [u8; 32]) -> String {
    blake3::Hash::from(digest).to_hex().to_string()
}

fn identity(manifest_blake3: [u8; 32], task_records: usize, distinct_entries: usize) -> String {
    format!(
        "v1:{}:{task_records}:{distinct_entries}",
        blake3_hex(manifest_blake3)
    )
}

fn storage_kind_name(kind: StorageKind) -> &'static str {
    match kind {
        StorageKind::Raw => "raw",
        StorageKind::ScatterBytes => "scatter_bytes",
        StorageKind::ScatterZero => "scatter_zero",
    }
}

fn anchor_kind_name(kind: AnchorReferenceKind) -> &'static str {
    match kind {
        Adr => "adr",
        Literal => "literal",
        MovwMovt => "movw_movt",
    }
}

fn anchor_kind_rank(kind: AnchorReferenceKind) -> u8 {
    match kind {
        Adr => 0,
        Literal => 1,
        MovwMovt => 2,
    }
}

fn scatter_entries_used(plan: &TaskPlan) -> BTreeSet<usize> {
    let mut used = BTreeSet::new();
    let mut collect = |spans: &[StorageSpan]| {
        for span in spans {
            if let Some(entry) = span.scatter_entry {
                used.insert(entry);
            }
        }
    };
    for anchor in &plan.initializer.anchors {
        collect(&anchor.storage);
    }
    collect(&plan.initializer.code_storage);
    for task in &plan.tasks {
        collect(&task.slot_storage);
        collect(&task.name_storage);
        collect(&task.entry_storage);
    }
    collect(&plan.terminal.storage);
    used
}

/// Sort by address, drop exact duplicates, and coalesce adjacent spans
/// with the same kind and scatter entry. Gaps are never invented.
fn canonical_spans(spans: &[StorageSpan]) -> Result<Vec<StorageSpan>> {
    let mut canonical: Vec<StorageSpan> = spans.to_vec();
    canonical.sort_by_key(|span| (span.address, span.size));
    canonical.dedup();
    let mut coalesced: Vec<StorageSpan> = Vec::with_capacity(canonical.len());
    for span in canonical {
        match coalesced.last_mut() {
            Some(last)
                if last.kind == span.kind
                    && last.scatter_entry == span.scatter_entry
                    && last.address.checked_add(last.size) == Some(span.address) =>
            {
                last.size = last
                    .size
                    .checked_add(span.size)
                    .ok_or_else(|| invalid("canonical storage span coalescing overflows"))?;
            }
            _ => coalesced.push(span),
        }
    }
    Ok(coalesced)
}

/// A minimal pretty-JSON emitter pinned to the canonical two-space
/// layout the exact-byte fixture freezes.
struct JsonWriter {
    bytes: Vec<u8>,
    depth: usize,
}

impl JsonWriter {
    fn new() -> Self {
        JsonWriter {
            bytes: Vec::new(),
            depth: 0,
        }
    }

    fn indent(&mut self) {
        for _ in 0..self.depth {
            self.bytes.extend_from_slice(b"  ");
        }
    }

    fn open_object(&mut self) {
        self.bytes.push(b'{');
        self.depth += 1;
    }

    fn close_object(&mut self) {
        self.depth -= 1;
        if self.bytes.last() == Some(&b'{') {
            self.bytes.push(b'}');
            return;
        }
        self.bytes.push(b'\n');
        self.indent();
        self.bytes.push(b'}');
    }

    fn open_array(&mut self) {
        self.bytes.push(b'[');
        self.depth += 1;
    }

    fn close_array(&mut self) {
        self.depth -= 1;
        if self.bytes.last() == Some(&b'[') {
            self.bytes.push(b']');
            return;
        }
        self.bytes.push(b'\n');
        self.indent();
        self.bytes.push(b']');
    }

    fn key(&mut self, first: bool, name: &str) {
        if !first {
            self.bytes.push(b',');
        }
        self.bytes.push(b'\n');
        self.indent();
        self.bytes.push(b'"');
        self.bytes.extend_from_slice(name.as_bytes());
        self.bytes.extend_from_slice(b"\": ");
    }

    fn element(&mut self, first: bool) {
        if !first {
            self.bytes.push(b',');
        }
        self.bytes.push(b'\n');
        self.indent();
    }

    fn string_value(&mut self, value: &str) {
        self.bytes.push(b'"');
        for byte in value.bytes() {
            match byte {
                b'"' => self.bytes.extend_from_slice(b"\\\""),
                b'\\' => self.bytes.extend_from_slice(b"\\\\"),
                _ => self.bytes.push(byte),
            }
        }
        self.bytes.push(b'"');
    }

    fn u32_value(&mut self, value: u32) {
        push_decimal(&mut self.bytes, u64::from(value));
    }

    fn usize_value(&mut self, value: usize) {
        push_decimal(&mut self.bytes, value as u64);
    }
}

fn push_decimal(bytes: &mut Vec<u8>, value: u64) {
    let mut buffer = [0u8; 20];
    let mut length = 0usize;
    let mut remaining = value;
    loop {
        buffer[length] = b'0' + (remaining % 10) as u8;
        length += 1;
        remaining /= 10;
        if remaining == 0 {
            break;
        }
    }
    bytes.extend(buffer[..length].iter().rev());
}

fn write_span(json: &mut JsonWriter, span: &StorageSpan) {
    json.open_object();
    json.key(true, "kind");
    json.string_value(storage_kind_name(span.kind));
    json.key(false, "address");
    json.string_value(&address(span.address));
    json.key(false, "size");
    json.u32_value(span.size);
    if let Some(entry) = span.scatter_entry {
        json.key(false, "scatter_entry");
        json.usize_value(entry);
    }
    json.close_object();
}

fn write_spans(json: &mut JsonWriter, spans: &[StorageSpan]) {
    json.open_array();
    for (index, span) in spans.iter().enumerate() {
        json.element(index == 0);
        write_span(json, span);
    }
    json.close_array();
}

fn serialize(plan: &TaskPlan, context: &TaskArtifactContext<'_>) -> Result<Vec<u8>> {
    let used = scatter_entries_used(plan);
    let anchors = canonical_anchors(&plan.initializer.anchors);
    let references = canonical_references(&plan.initializer.proof_paths);
    let code_storage = canonical_spans(&plan.initializer.code_storage)?;

    let mut json = JsonWriter::new();
    json.open_object();
    json.key(true, "format");
    json.string_value(FORMAT);
    json.key(false, "schema_version");
    json.u32_value(SCHEMA_VERSION);
    json.key(false, "tool_version");
    json.string_value(env!("CARGO_PKG_VERSION"));

    json.key(false, "image");
    json.open_object();
    json.key(true, "label");
    json.string_value(context.label);
    json.key(false, "base_addr");
    json.string_value(&address(plan.image_base));
    json.key(false, "size");
    json.u32_value(plan.image_size);
    json.key(false, "blake3");
    json.string_value(&blake3_hex(context.image_blake3));
    json.close_object();

    json.key(false, "runtime_view");
    json.open_object();
    json.key(true, "scatter_load_map_blake3");
    match context.scatter_load_map_blake3 {
        Some(digest) => json.string_value(&blake3_hex(digest)),
        None => json.bytes.extend_from_slice(b"null"),
    }
    json.key(false, "scatter_entries_used");
    json.open_array();
    for (index, entry) in used.iter().enumerate() {
        json.element(index == 0);
        json.usize_value(*entry);
    }
    json.close_array();
    json.close_object();

    json.key(false, "decoder");
    json.open_object();
    json.key(true, "semantic_adapter");
    json.string_value(SEMANTIC_ADAPTER);
    json.key(false, "backend_crate");
    json.string_value(BACKEND_CRATE);
    json.key(false, "backend_version");
    json.string_value(env!("CARGO_PKG_VERSION"));
    json.close_object();

    json.key(false, "initializer");
    json.open_object();
    json.key(true, "cfg_entry");
    json.string_value(&address(plan.initializer.cfg_entry));
    json.key(false, "anchors");
    json.open_array();
    for (index, anchor) in anchors.iter().enumerate() {
        json.element(index == 0);
        json.open_object();
        json.key(true, "address");
        json.string_value(&address(anchor.address));
        json.key(false, "storage");
        write_spans(&mut json, &anchor.storage);
        json.close_object();
    }
    json.close_array();
    json.key(false, "anchor_references");
    json.open_array();
    for (index, path) in references.iter().enumerate() {
        json.element(index == 0);
        json.open_object();
        json.key(true, "anchor");
        json.string_value(&address(path.anchor));
        json.key(false, "address");
        json.string_value(&address(path.reference.pc));
        json.key(false, "kind");
        json.string_value(anchor_kind_name(path.reference.kind));
        json.key(false, "definitions");
        json.open_array();
        for (definition_index, definition) in path.reference.definitions.iter().enumerate() {
            json.element(definition_index == 0);
            json.string_value(&address(*definition));
        }
        json.close_array();
        json.key(false, "call");
        json.string_value(&address(path.call));
        json.close_object();
    }
    json.close_array();
    json.key(false, "code_storage");
    write_spans(&mut json, &code_storage);
    json.key(false, "loop_start");
    json.string_value(&address(plan.initializer.loop_start));
    json.key(false, "count_zero_definition");
    json.string_value(&address(plan.initializer.count_zero_definition));
    json.key(false, "slot_definition");
    json.open_object();
    json.key(true, "root");
    json.string_value(&address(plan.initializer.slot_definition.root));
    json.key(false, "definitions");
    json.open_array();
    for (definition_index, definition) in plan
        .initializer
        .slot_definition
        .definitions
        .iter()
        .enumerate()
    {
        json.element(definition_index == 0);
        json.string_value(&address(*definition));
    }
    json.close_array();
    json.close_object();
    json.key(false, "normal_exit");
    json.string_value(&address(plan.initializer.normal_exit));
    json.key(false, "capacity_exit");
    json.string_value(&address(plan.initializer.capacity_exit));
    json.key(false, "capacity_guard");
    json.open_object();
    json.key(true, "start");
    json.string_value(&address(plan.initializer.capacity_guard.start));
    json.key(false, "branch");
    json.string_value(&address(plan.initializer.capacity_guard.branch));
    json.key(false, "fallthrough");
    json.string_value(&address(plan.initializer.capacity_guard.fallthrough));
    json.key(false, "relation");
    json.string_value(CAPACITY_GUARD_RELATION);
    json.close_object();
    json.key(false, "suffix_loop");
    json.string_value(&address(plan.initializer.suffix_loop));
    json.key(false, "join");
    json.string_value(&address(plan.initializer.join));
    json.key(false, "count_global");
    json.string_value(&address(plan.initializer.count_global));
    json.key(false, "slot_base");
    json.string_value(&address(plan.initializer.slot_base));
    json.key(false, "name_offset");
    json.u32_value(plan.initializer.name_offset);
    json.key(false, "index_offset");
    json.u32_value(plan.initializer.index_offset);
    json.key(false, "stride");
    json.u32_value(plan.initializer.stride);
    json.key(false, "capacity");
    json.u32_value(plan.initializer.capacity);
    json.close_object();

    json.key(false, "table");
    json.open_object();
    json.key(true, "count");
    json.u32_value(plan.table.count);
    json.key(false, "terminal_slot");
    json.string_value(&address(plan.terminal.slot));
    json.key(false, "terminal_blake3");
    json.string_value(&blake3_hex(plan.terminal.slot_blake3));
    json.key(false, "terminal_storage");
    write_spans(&mut json, &plan.terminal.storage);
    json.key(false, "descriptor_projection_offset");
    json.u32_value(plan.table.descriptor_projection_offset);
    json.key(false, "priority_offset");
    json.u32_value(plan.table.priority_offset);
    json.key(false, "stack_size_offset");
    json.u32_value(plan.table.stack_size_offset);
    json.key(false, "entry_offset");
    json.u32_value(plan.table.entry_offset);
    json.key(false, "callback_offset");
    json.u32_value(plan.table.callback_offset);
    json.key(false, "unknown_pointer_offset");
    json.u32_value(plan.table.unknown_pointer_offset);
    json.close_object();

    json.key(false, "tasks");
    json.open_array();
    for (index, task) in plan.tasks.iter().enumerate() {
        json.element(index == 0);
        json.open_object();
        json.key(true, "index");
        json.u32_value(task.index);
        json.key(false, "slot");
        json.string_value(&address(task.slot));
        json.key(false, "slot_blake3");
        json.string_value(&blake3_hex(task.slot_blake3));
        json.key(false, "name_pointer");
        json.string_value(&address(task.name_pointer));
        json.key(false, "name");
        json.string_value(&task.name);
        json.key(false, "task_label");
        json.string_value(&task.task_label);
        json.key(false, "priority");
        json.u32_value(u32::from(task.priority));
        json.key(false, "stack_size");
        json.u32_value(task.stack_size);
        json.key(false, "entry_pointer");
        json.string_value(&address(task.entry_pointer));
        json.key(false, "entry");
        json.string_value(&address(task.entry));
        json.key(false, "isa");
        json.string_value(match task.isa {
            TaskIsa::Arm => "arm",
            TaskIsa::Thumb => "thumb",
        });
        json.key(false, "instruction_size");
        json.u32_value(u32::from(task.instruction_size));
        json.key(false, "instruction_blake3");
        json.string_value(&blake3_hex(task.instruction_blake3));
        json.key(false, "callback");
        json.string_value(&address(task.callback));
        json.key(false, "unknown_pointer");
        json.string_value(&address(task.unknown_pointer));
        json.key(false, "slot_storage");
        write_spans(&mut json, &task.slot_storage);
        json.key(false, "name_storage");
        write_spans(&mut json, &task.name_storage);
        json.key(false, "entry_storage");
        write_spans(&mut json, &task.entry_storage);
        json.close_object();
    }
    json.close_array();

    json.key(false, "applications");
    json.open_array();
    for (index, application) in plan.applications.iter().enumerate() {
        json.element(index == 0);
        json.open_object();
        json.key(true, "entry");
        json.string_value(&address(application.entry));
        json.key(false, "isa");
        json.string_value(match application.isa {
            TaskIsa::Arm => "arm",
            TaskIsa::Thumb => "thumb",
        });
        json.key(false, "desired_primary");
        json.string_value(&application.desired_primary);
        json.key(false, "task_indices");
        json.open_array();
        for (member, task_index) in application.task_indices.iter().enumerate() {
            json.element(member == 0);
            json.u32_value(*task_index);
        }
        json.close_array();
        json.key(false, "labels");
        json.open_array();
        for (label_index, label) in application.labels.iter().enumerate() {
            json.element(label_index == 0);
            json.open_object();
            json.key(true, "label");
            json.string_value(&label.label);
            json.key(false, "task_indices");
            json.open_array();
            for (member, task_index) in label.task_indices.iter().enumerate() {
                json.element(member == 0);
                json.u32_value(*task_index);
            }
            json.close_array();
            json.close_object();
        }
        json.close_array();
        json.close_object();
    }
    json.close_array();

    json.close_object();
    json.bytes.push(b'\n');
    Ok(json.bytes)
}

fn canonical_anchors(anchors: &[AnchorProvenance]) -> Vec<AnchorProvenance> {
    let mut canonical: Vec<AnchorProvenance> = Vec::new();
    for anchor in anchors {
        if !canonical.iter().any(|kept| kept.address == anchor.address) {
            canonical.push(anchor.clone());
        }
    }
    canonical.sort_by_key(|anchor| anchor.address);
    canonical
}

fn canonical_references(paths: &[AnchorProofPath]) -> Vec<AnchorProofPath> {
    let key = |path: &AnchorProofPath| {
        (
            path.anchor,
            path.reference.pc,
            anchor_kind_rank(path.reference.kind),
            path.call,
        )
    };
    let mut canonical: Vec<AnchorProofPath> = Vec::new();
    for path in paths {
        let path_key = key(path);
        if !canonical.iter().any(|kept| key(kept) == path_key) {
            canonical.push(path.clone());
        }
    }
    canonical.sort_by_key(key);
    canonical
}

// ---------------------------------------------------------------------------
// Strict streaming reader
// ---------------------------------------------------------------------------

struct WireSpan {
    kind: StorageKind,
    address: u32,
    size: u32,
    scatter_entry: Option<usize>,
}

impl WireSpan {
    fn as_storage(&self) -> StorageSpan {
        StorageSpan {
            kind: self.kind,
            address: self.address,
            size: self.size,
            scatter_entry: self.scatter_entry,
        }
    }
}

struct WireAnchor {
    address: u32,
    storage: Vec<WireSpan>,
}

struct WireReference {
    anchor: u32,
    address: u32,
    kind: AnchorReferenceKind,
    definitions: Vec<u32>,
    call: u32,
}

struct WireInitializer {
    cfg_entry: u32,
    anchors: Vec<WireAnchor>,
    references: Vec<WireReference>,
    code_storage: Vec<WireSpan>,
    loop_start: u32,
    count_zero_definition: u32,
    slot_definition_root: u32,
    slot_definition_definitions: Vec<u32>,
    normal_exit: u32,
    capacity_exit: u32,
    guard_start: u32,
    guard_branch: u32,
    guard_fallthrough: u32,
    suffix_loop: u32,
    join: u32,
    count_global: u32,
    slot_base: u32,
    name_offset: u32,
    index_offset: u32,
    stride: u32,
    capacity: u32,
}

struct WireTable {
    count: u32,
    terminal_slot: u32,
    terminal_blake3: [u8; 32],
    terminal_storage: Vec<WireSpan>,
    descriptor_projection_offset: u32,
    priority_offset: u32,
    stack_size_offset: u32,
    entry_offset: u32,
    callback_offset: u32,
    unknown_pointer_offset: u32,
}

struct WireTask {
    index: u32,
    slot: u32,
    slot_blake3: [u8; 32],
    name_pointer: u32,
    name: String,
    task_label: String,
    priority: u8,
    stack_size: u32,
    entry_pointer: u32,
    entry: u32,
    isa: TaskIsa,
    instruction_size: u8,
    instruction_blake3: [u8; 32],
    callback: u32,
    unknown_pointer: u32,
    slot_storage: Vec<WireSpan>,
    name_storage: Vec<WireSpan>,
    entry_storage: Vec<WireSpan>,
}

struct WireLabel {
    label: String,
    task_indices: Vec<u32>,
}

struct WireApplication {
    entry: u32,
    isa: TaskIsa,
    desired_primary: String,
    task_indices: Vec<u32>,
    labels: Vec<WireLabel>,
}

struct WireManifest {
    format: String,
    schema_version: u32,
    tool_version: String,
    image_label: String,
    image_base: u32,
    image_size: u32,
    image_blake3: [u8; 32],
    scatter_load_map_blake3: Option<[u8; 32]>,
    scatter_entries_used: Vec<usize>,
    semantic_adapter: String,
    backend_crate: String,
    backend_version: String,
    initializer: WireInitializer,
    table: WireTable,
    tasks: Vec<WireTask>,
    applications: Vec<WireApplication>,
}

/// A fail-closed cursor over the manifest bytes. Keys must appear in the
/// exact canonical order, integers are canonical unsigned decimals,
/// strings are printable ASCII with only the two mandatory escapes, and
/// anything unexpected is a typed rejection.
struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Cursor { bytes, position: 0 }
    }

    fn skip_whitespace(&mut self) {
        while matches!(
            self.bytes.get(self.position),
            Some(b' ' | b'\t' | b'\n' | b'\r')
        ) {
            self.position += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }

    fn peek_after_ws(&mut self) -> Option<u8> {
        self.skip_whitespace();
        self.peek()
    }

    fn next_byte(&mut self) -> Result<u8> {
        let byte = self
            .bytes
            .get(self.position)
            .copied()
            .ok_or_else(|| invalid("manifest ended inside a value"))?;
        self.position += 1;
        Ok(byte)
    }

    fn expect_byte(&mut self, expected: u8, what: &str) -> Result<()> {
        let byte = self.next_byte()?;
        if byte != expected {
            return Err(invalid(format!(
                "expected {what} {expected:?} but found byte {byte:?}"
            )));
        }
        Ok(())
    }

    fn json_string(&mut self, what: &str) -> Result<String> {
        self.skip_whitespace();
        self.expect_byte(b'"', &format!("{what} opening quote"))?;
        let mut out = Vec::new();
        loop {
            let byte = self.next_byte()?;
            match byte {
                b'"' => break,
                b'\\' => match self.next_byte()? {
                    b'"' => out.push(b'"'),
                    b'\\' => out.push(b'\\'),
                    other => {
                        return Err(invalid(format!(
                            "{what} uses the non-canonical escape \\{other:?}"
                        )));
                    }
                },
                0x20..=0x7e => out.push(byte),
                other => {
                    return Err(invalid(format!(
                        "{what} contains the non-canonical byte {other:#04x}"
                    )));
                }
            }
        }
        String::from_utf8(out).map_err(|_| invalid(format!("{what} is not valid UTF-8")))
    }

    fn key(&mut self, first: bool, expected: &str) -> Result<()> {
        self.skip_whitespace();
        if !first {
            self.expect_byte(b',', "object field separator")?;
        }
        self.skip_whitespace();
        let name = self.json_string("object key")?;
        if name != expected {
            return Err(invalid(format!(
                "expected key {expected:?} but found {name:?}"
            )));
        }
        self.skip_whitespace();
        self.expect_byte(b':', "key/value separator")
    }

    /// The optional trailing key of one object: either the expected name
    /// or the end of the object; anything else is a rejection.
    fn optional_key(&mut self, expected: &str) -> Result<bool> {
        self.skip_whitespace();
        match self.peek() {
            Some(b'}') => Ok(false),
            Some(b',') => {
                self.position += 1;
                self.skip_whitespace();
                let name = self.json_string("object key")?;
                if name != expected {
                    return Err(invalid(format!(
                        "expected the last key {expected:?} but found {name:?}"
                    )));
                }
                self.skip_whitespace();
                self.expect_byte(b':', "key/value separator")?;
                Ok(true)
            }
            other => Err(invalid(format!(
                "unexpected byte {other:?} where an object continues"
            ))),
        }
    }

    fn enter_object(&mut self) -> Result<()> {
        self.skip_whitespace();
        self.expect_byte(b'{', "object opening brace")
    }

    fn exit_object(&mut self) -> Result<()> {
        self.skip_whitespace();
        self.expect_byte(b'}', "object closing brace")
    }

    fn enter_array(&mut self) -> Result<()> {
        self.skip_whitespace();
        self.expect_byte(b'[', "array opening bracket")
    }

    fn element(&mut self, first: bool) -> Result<()> {
        self.skip_whitespace();
        if !first {
            self.expect_byte(b',', "array element separator")?;
        }
        Ok(())
    }

    fn exit_array(&mut self) -> Result<()> {
        self.skip_whitespace();
        self.expect_byte(b']', "array closing bracket")
    }

    fn null(&mut self) -> Result<()> {
        self.skip_whitespace();
        for expected in b"null" {
            self.expect_byte(*expected, "null literal")?;
        }
        Ok(())
    }

    fn decimal(&mut self, what: &str) -> Result<u64> {
        self.skip_whitespace();
        let first = self.next_byte()?;
        if !first.is_ascii_digit() {
            return Err(invalid(format!(
                "{what} is not a canonical unsigned decimal"
            )));
        }
        if first == b'0' {
            if matches!(self.peek(), Some(byte) if byte.is_ascii_digit()) {
                return Err(invalid(format!(
                    "{what} has a leading zero outside canonical form"
                )));
            }
            return Ok(0);
        }
        let mut value = u64::from(first - b'0');
        while matches!(self.peek(), Some(byte) if byte.is_ascii_digit()) {
            let digit = u64::from(self.next_byte()? - b'0');
            value = value
                .checked_mul(10)
                .and_then(|scaled| scaled.checked_add(digit))
                .ok_or_else(|| invalid(format!("{what} overflows the integer domain")))?;
        }
        Ok(value)
    }

    fn u8_value(&mut self, what: &str) -> Result<u8> {
        u8::try_from(self.decimal(what)?)
            .map_err(|_| invalid(format!("{what} does not fit the u8 domain")))
    }

    fn u32_value(&mut self, what: &str) -> Result<u32> {
        u32::try_from(self.decimal(what)?)
            .map_err(|_| invalid(format!("{what} does not fit the u32 domain")))
    }

    fn usize_value(&mut self, what: &str) -> Result<usize> {
        usize::try_from(self.decimal(what)?)
            .map_err(|_| invalid(format!("{what} does not fit the usize domain")))
    }

    fn address(&mut self, what: &str) -> Result<u32> {
        let text = self.json_string(what)?;
        parse_address(&text, what)
    }

    fn blake3_value(&mut self, what: &str) -> Result<[u8; 32]> {
        let text = self.json_string(what)?;
        parse_blake3(&text).map_err(|_| invalid(format!("{what} is not 64 lowercase hex BLAKE3")))
    }

    fn finish(&mut self) -> Result<()> {
        self.skip_whitespace();
        if self.position != self.bytes.len() {
            return Err(invalid("manifest carries trailing content"));
        }
        Ok(())
    }
}

fn parse_address(text: &str, what: &str) -> Result<u32> {
    let bytes = text.as_bytes();
    if bytes.len() != 10
        || !text.starts_with("0x")
        || !bytes[2..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(invalid(format!("{what} is not a canonical address")));
    }
    u32::from_str_radix(&text[2..], 16)
        .map_err(|_| invalid(format!("{what} is outside the u32 address domain")))
}

fn parse_storage_kind(cursor: &mut Cursor<'_>) -> Result<StorageKind> {
    let text = cursor.json_string("storage kind")?;
    match text.as_str() {
        "raw" => Ok(StorageKind::Raw),
        "scatter_bytes" => Ok(StorageKind::ScatterBytes),
        "scatter_zero" => Ok(StorageKind::ScatterZero),
        other => Err(invalid(format!("unknown storage kind {other:?}"))),
    }
}

fn parse_task_isa(cursor: &mut Cursor<'_>) -> Result<TaskIsa> {
    let text = cursor.json_string("ISA")?;
    match text.as_str() {
        "arm" => Ok(TaskIsa::Arm),
        "thumb" => Ok(TaskIsa::Thumb),
        other => Err(invalid(format!("unknown ISA {other:?}"))),
    }
}

fn parse_anchor_kind(cursor: &mut Cursor<'_>) -> Result<AnchorReferenceKind> {
    let text = cursor.json_string("anchor reference kind")?;
    match text.as_str() {
        "adr" => Ok(Adr),
        "literal" => Ok(Literal),
        "movw_movt" => Ok(MovwMovt),
        other => Err(invalid(format!("unknown anchor reference kind {other:?}"))),
    }
}

fn parse_span(cursor: &mut Cursor<'_>) -> Result<WireSpan> {
    cursor.enter_object()?;
    cursor.key(true, "kind")?;
    let kind = parse_storage_kind(cursor)?;
    cursor.key(false, "address")?;
    let address = cursor.address("storage address")?;
    cursor.key(false, "size")?;
    let size = cursor.u32_value("storage size")?;
    let scatter_entry = if cursor.optional_key("scatter_entry")? {
        Some(cursor.usize_value("scatter entry")?)
    } else {
        None
    };
    cursor.exit_object()?;
    match (kind, scatter_entry) {
        (StorageKind::Raw, None) => Ok(WireSpan {
            kind,
            address,
            size,
            scatter_entry,
        }),
        (StorageKind::Raw, Some(_)) => Err(invalid(
            "raw storage span carries a scatter_entry it cannot have",
        )),
        (_, None) => Err(invalid(
            "scatter storage span lacks its required scatter_entry",
        )),
        (_, Some(_)) => Ok(WireSpan {
            kind,
            address,
            size,
            scatter_entry,
        }),
    }
}

fn parse_spans(cursor: &mut Cursor<'_>) -> Result<Vec<WireSpan>> {
    cursor.enter_array()?;
    let mut spans = Vec::new();
    let mut first = true;
    cursor.skip_whitespace();
    while cursor.peek() != Some(b']') {
        cursor.element(first)?;
        spans.push(parse_span(cursor)?);
        first = false;
        cursor.skip_whitespace();
    }
    cursor.exit_array()?;
    Ok(spans)
}

fn parse_manifest(bytes: &[u8]) -> Result<WireManifest> {
    let mut cursor = Cursor::new(bytes);
    cursor.enter_object()?;
    cursor.key(true, "format")?;
    let format = cursor.json_string("format")?;
    cursor.key(false, "schema_version")?;
    let schema_version = cursor.u32_value("schema_version")?;
    cursor.key(false, "tool_version")?;
    let tool_version = cursor.json_string("tool_version")?;

    cursor.key(false, "image")?;
    cursor.enter_object()?;
    cursor.key(true, "label")?;
    let image_label = cursor.json_string("image label")?;
    cursor.key(false, "base_addr")?;
    let image_base = cursor.address("image base_addr")?;
    cursor.key(false, "size")?;
    let image_size = cursor.u32_value("image size")?;
    cursor.key(false, "blake3")?;
    let image_blake3 = cursor.blake3_value("image blake3")?;
    cursor.exit_object()?;

    cursor.key(false, "runtime_view")?;
    cursor.enter_object()?;
    cursor.key(true, "scatter_load_map_blake3")?;
    let scatter_load_map_blake3 = if matches!(cursor.peek_after_ws(), Some(b'n')) {
        cursor.null()?;
        None
    } else {
        Some(cursor.blake3_value("scatter_load_map_blake3")?)
    };
    cursor.key(false, "scatter_entries_used")?;
    let mut scatter_entries_used = Vec::new();
    cursor.enter_array()?;
    cursor.skip_whitespace();
    let mut first = true;
    while cursor.peek() != Some(b']') {
        cursor.element(first)?;
        let entry = cursor.usize_value("scatter_entries_used element")?;
        if matches!(scatter_entries_used.last(), Some(last) if *last >= entry) {
            return Err(invalid(
                "scatter_entries_used is not sorted with unique elements",
            ));
        }
        scatter_entries_used.push(entry);
        first = false;
        cursor.skip_whitespace();
    }
    cursor.exit_array()?;
    cursor.exit_object()?;

    cursor.key(false, "decoder")?;
    cursor.enter_object()?;
    cursor.key(true, "semantic_adapter")?;
    let semantic_adapter = cursor.json_string("semantic_adapter")?;
    cursor.key(false, "backend_crate")?;
    let backend_crate = cursor.json_string("backend_crate")?;
    cursor.key(false, "backend_version")?;
    let backend_version = cursor.json_string("backend_version")?;
    cursor.exit_object()?;

    cursor.key(false, "initializer")?;
    cursor.enter_object()?;
    cursor.key(true, "cfg_entry")?;
    let cfg_entry = cursor.address("initializer cfg_entry")?;
    cursor.key(false, "anchors")?;
    let mut anchors = Vec::new();
    cursor.enter_array()?;
    cursor.skip_whitespace();
    let mut first = true;
    while cursor.peek() != Some(b']') {
        cursor.element(first)?;
        cursor.enter_object()?;
        cursor.key(true, "address")?;
        let address = cursor.address("anchor address")?;
        cursor.key(false, "storage")?;
        let storage = parse_spans(&mut cursor)?;
        cursor.exit_object()?;
        anchors.push(WireAnchor { address, storage });
        first = false;
        cursor.skip_whitespace();
    }
    cursor.exit_array()?;
    cursor.key(false, "anchor_references")?;
    let mut references = Vec::new();
    cursor.enter_array()?;
    cursor.skip_whitespace();
    let mut first = true;
    while cursor.peek() != Some(b']') {
        cursor.element(first)?;
        cursor.enter_object()?;
        cursor.key(true, "anchor")?;
        let anchor = cursor.address("anchor reference anchor")?;
        cursor.key(false, "address")?;
        let address = cursor.address("anchor reference address")?;
        cursor.key(false, "kind")?;
        let kind = parse_anchor_kind(&mut cursor)?;
        cursor.key(false, "definitions")?;
        let mut definitions = Vec::new();
        cursor.enter_array()?;
        cursor.skip_whitespace();
        let mut definition_first = true;
        while cursor.peek() != Some(b']') {
            cursor.element(definition_first)?;
            definitions.push(cursor.address("anchor definition")?);
            definition_first = false;
            cursor.skip_whitespace();
        }
        cursor.exit_array()?;
        cursor.key(false, "call")?;
        let call = cursor.address("anchor reference call")?;
        cursor.exit_object()?;
        references.push(WireReference {
            anchor,
            address,
            kind,
            definitions,
            call,
        });
        first = false;
        cursor.skip_whitespace();
    }
    cursor.exit_array()?;
    cursor.key(false, "code_storage")?;
    let code_storage = parse_spans(&mut cursor)?;
    cursor.key(false, "loop_start")?;
    let loop_start = cursor.address("initializer loop_start")?;
    cursor.key(false, "count_zero_definition")?;
    let count_zero_definition = cursor.address("initializer count_zero_definition")?;
    cursor.key(false, "slot_definition")?;
    cursor.enter_object()?;
    cursor.key(true, "root")?;
    let slot_definition_root = cursor.address("slot definition root")?;
    cursor.key(false, "definitions")?;
    let mut slot_definition_definitions = Vec::new();
    cursor.enter_array()?;
    cursor.skip_whitespace();
    let mut definition_first = true;
    while cursor.peek() != Some(b']') {
        cursor.element(definition_first)?;
        slot_definition_definitions.push(cursor.address("slot definition")?);
        definition_first = false;
        cursor.skip_whitespace();
    }
    cursor.exit_array()?;
    cursor.exit_object()?;
    cursor.key(false, "normal_exit")?;
    let normal_exit = cursor.address("initializer normal_exit")?;
    cursor.key(false, "capacity_exit")?;
    let capacity_exit = cursor.address("initializer capacity_exit")?;
    cursor.key(false, "capacity_guard")?;
    cursor.enter_object()?;
    cursor.key(true, "start")?;
    let guard_start = cursor.address("capacity guard start")?;
    cursor.key(false, "branch")?;
    let guard_branch = cursor.address("capacity guard branch")?;
    cursor.key(false, "fallthrough")?;
    let guard_fallthrough = cursor.address("capacity guard fallthrough")?;
    cursor.key(false, "relation")?;
    let relation = cursor.json_string("capacity guard relation")?;
    if relation != CAPACITY_GUARD_RELATION {
        return Err(invalid(format!(
            "unknown capacity guard relation {relation:?}"
        )));
    }
    cursor.exit_object()?;
    cursor.key(false, "suffix_loop")?;
    let suffix_loop = cursor.address("initializer suffix_loop")?;
    cursor.key(false, "join")?;
    let join = cursor.address("initializer join")?;
    cursor.key(false, "count_global")?;
    let count_global = cursor.address("initializer count_global")?;
    cursor.key(false, "slot_base")?;
    let slot_base = cursor.address("initializer slot_base")?;
    cursor.key(false, "name_offset")?;
    let name_offset = cursor.u32_value("initializer name_offset")?;
    cursor.key(false, "index_offset")?;
    let index_offset = cursor.u32_value("initializer index_offset")?;
    cursor.key(false, "stride")?;
    let stride = cursor.u32_value("initializer stride")?;
    cursor.key(false, "capacity")?;
    let capacity = cursor.u32_value("initializer capacity")?;
    cursor.exit_object()?;

    cursor.key(false, "table")?;
    cursor.enter_object()?;
    cursor.key(true, "count")?;
    let count = cursor.u32_value("table count")?;
    cursor.key(false, "terminal_slot")?;
    let terminal_slot = cursor.address("table terminal_slot")?;
    cursor.key(false, "terminal_blake3")?;
    let terminal_blake3 = cursor.blake3_value("table terminal_blake3")?;
    cursor.key(false, "terminal_storage")?;
    let terminal_storage = parse_spans(&mut cursor)?;
    cursor.key(false, "descriptor_projection_offset")?;
    let descriptor_projection_offset = cursor.u32_value("table descriptor_projection_offset")?;
    cursor.key(false, "priority_offset")?;
    let priority_offset = cursor.u32_value("table priority_offset")?;
    cursor.key(false, "stack_size_offset")?;
    let stack_size_offset = cursor.u32_value("table stack_size_offset")?;
    cursor.key(false, "entry_offset")?;
    let entry_offset = cursor.u32_value("table entry_offset")?;
    cursor.key(false, "callback_offset")?;
    let callback_offset = cursor.u32_value("table callback_offset")?;
    cursor.key(false, "unknown_pointer_offset")?;
    let unknown_pointer_offset = cursor.u32_value("table unknown_pointer_offset")?;
    cursor.exit_object()?;

    cursor.key(false, "tasks")?;
    let mut tasks = Vec::new();
    cursor.enter_array()?;
    cursor.skip_whitespace();
    let mut first = true;
    while cursor.peek() != Some(b']') {
        cursor.element(first)?;
        cursor.enter_object()?;
        cursor.key(true, "index")?;
        let index = cursor.u32_value("task index")?;
        cursor.key(false, "slot")?;
        let slot = cursor.address("task slot")?;
        cursor.key(false, "slot_blake3")?;
        let slot_blake3 = cursor.blake3_value("task slot_blake3")?;
        cursor.key(false, "name_pointer")?;
        let name_pointer = cursor.address("task name_pointer")?;
        cursor.key(false, "name")?;
        let name = cursor.json_string("task name")?;
        cursor.key(false, "task_label")?;
        let task_label = cursor.json_string("task task_label")?;
        cursor.key(false, "priority")?;
        let priority = cursor.u8_value("task priority")?;
        cursor.key(false, "stack_size")?;
        let stack_size = cursor.u32_value("task stack_size")?;
        cursor.key(false, "entry_pointer")?;
        let entry_pointer = cursor.address("task entry_pointer")?;
        cursor.key(false, "entry")?;
        let entry = cursor.address("task entry")?;
        cursor.key(false, "isa")?;
        let isa = parse_task_isa(&mut cursor)?;
        cursor.key(false, "instruction_size")?;
        let instruction_size = cursor.u8_value("task instruction_size")?;
        cursor.key(false, "instruction_blake3")?;
        let instruction_blake3 = cursor.blake3_value("task instruction_blake3")?;
        cursor.key(false, "callback")?;
        let callback = cursor.address("task callback")?;
        cursor.key(false, "unknown_pointer")?;
        let unknown_pointer = cursor.address("task unknown_pointer")?;
        cursor.key(false, "slot_storage")?;
        let slot_storage = parse_spans(&mut cursor)?;
        cursor.key(false, "name_storage")?;
        let name_storage = parse_spans(&mut cursor)?;
        cursor.key(false, "entry_storage")?;
        let entry_storage = parse_spans(&mut cursor)?;
        cursor.exit_object()?;
        tasks.push(WireTask {
            index,
            slot,
            slot_blake3,
            name_pointer,
            name,
            task_label,
            priority,
            stack_size,
            entry_pointer,
            entry,
            isa,
            instruction_size,
            instruction_blake3,
            callback,
            unknown_pointer,
            slot_storage,
            name_storage,
            entry_storage,
        });
        first = false;
        cursor.skip_whitespace();
    }
    cursor.exit_array()?;

    cursor.key(false, "applications")?;
    let mut applications = Vec::new();
    cursor.enter_array()?;
    cursor.skip_whitespace();
    let mut first = true;
    while cursor.peek() != Some(b']') {
        cursor.element(first)?;
        cursor.enter_object()?;
        cursor.key(true, "entry")?;
        let entry = cursor.address("application entry")?;
        cursor.key(false, "isa")?;
        let isa = parse_task_isa(&mut cursor)?;
        cursor.key(false, "desired_primary")?;
        let desired_primary = cursor.json_string("application desired_primary")?;
        cursor.key(false, "task_indices")?;
        let mut task_indices = Vec::new();
        cursor.enter_array()?;
        cursor.skip_whitespace();
        let mut member_first = true;
        while cursor.peek() != Some(b']') {
            cursor.element(member_first)?;
            let task_index = cursor.u32_value("application task index")?;
            if matches!(task_indices.last(), Some(last) if *last >= task_index) {
                return Err(invalid(
                    "application task_indices are not sorted with unique elements",
                ));
            }
            task_indices.push(task_index);
            member_first = false;
            cursor.skip_whitespace();
        }
        cursor.exit_array()?;
        cursor.key(false, "labels")?;
        let mut labels = Vec::new();
        cursor.enter_array()?;
        cursor.skip_whitespace();
        let mut label_first = true;
        while cursor.peek() != Some(b']') {
            cursor.element(label_first)?;
            cursor.enter_object()?;
            cursor.key(true, "label")?;
            let label = cursor.json_string("application label")?;
            cursor.key(false, "task_indices")?;
            let mut label_indices = Vec::new();
            cursor.enter_array()?;
            cursor.skip_whitespace();
            let mut index_first = true;
            while cursor.peek() != Some(b']') {
                cursor.element(index_first)?;
                let task_index = cursor.u32_value("label task index")?;
                if matches!(label_indices.last(), Some(last) if *last >= task_index) {
                    return Err(invalid(
                        "label task_indices are not sorted with unique elements",
                    ));
                }
                label_indices.push(task_index);
                index_first = false;
                cursor.skip_whitespace();
            }
            cursor.exit_array()?;
            cursor.exit_object()?;
            labels.push(WireLabel {
                label,
                task_indices: label_indices,
            });
            label_first = false;
            cursor.skip_whitespace();
        }
        cursor.exit_array()?;
        cursor.exit_object()?;
        applications.push(WireApplication {
            entry,
            isa,
            desired_primary,
            task_indices,
            labels,
        });
        first = false;
        cursor.skip_whitespace();
    }
    cursor.exit_array()?;

    cursor.exit_object()?;
    cursor.finish()?;

    Ok(WireManifest {
        format,
        schema_version,
        tool_version,
        image_label,
        image_base,
        image_size,
        image_blake3,
        scatter_load_map_blake3,
        scatter_entries_used,
        semantic_adapter,
        backend_crate,
        backend_version,
        initializer: WireInitializer {
            cfg_entry,
            anchors,
            references,
            code_storage,
            loop_start,
            count_zero_definition,
            slot_definition_root,
            slot_definition_definitions,
            normal_exit,
            capacity_exit,
            guard_start,
            guard_branch,
            guard_fallthrough,
            suffix_loop,
            join,
            count_global,
            slot_base,
            name_offset,
            index_offset,
            stride,
            capacity,
        },
        table: WireTable {
            count,
            terminal_slot,
            terminal_blake3,
            terminal_storage,
            descriptor_projection_offset,
            priority_offset,
            stack_size_offset,
            entry_offset,
            callback_offset,
            unknown_pointer_offset,
        },
        tasks,
        applications,
    })
}

// ---------------------------------------------------------------------------
// Fail-closed revalidation against the runtime image
// ---------------------------------------------------------------------------

pub(crate) fn read(
    path: &Path,
    runtime: &RuntimeImage<'_>,
    expected: TaskArtifactContext<'_>,
) -> Result<ValidatedTaskArtifact> {
    let mut file = open_manifest_file(path)?;
    let length = file
        .metadata()
        .map_err(|error| invalid(format!("manifest metadata is unavailable: {error}")))?
        .len();
    if length > MAX_MANIFEST_BYTES as u64 {
        return Err(invalid(
            "manifest exceeds the 4 MiB ceiling and is rejected before parsing",
        ));
    }
    let length =
        usize::try_from(length).map_err(|_| invalid("manifest size does not fit the host"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| invalid("manifest allocation failed"))?;
    bytes.resize(length, 0);
    file.read_exact(&mut bytes)
        .map_err(|error| invalid(format!("manifest read failed: {error}")))?;
    let mut trailing = [0u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|error| invalid(format!("manifest trailing read failed: {error}")))?
        != 0
    {
        return Err(invalid("manifest grew while it was being authenticated"));
    }

    let manifest_blake3 = *blake3::hash(&bytes).as_bytes();
    let wire = parse_manifest(&bytes)?;
    revalidate(wire, runtime, &expected, manifest_blake3)
}

fn require_mapped(runtime: &RuntimeImage<'_>, address: u32, what: &str) -> Result<()> {
    runtime
        .read_u8(address)
        .map(|_| ())
        .map_err(|error| invalid(format!("{what} {address:#010x} is not mapped: {error}")))
}

fn read_word(runtime: &RuntimeImage<'_>, address: u32, what: &str) -> Result<u32> {
    runtime
        .read_u32(address)
        .map_err(|error| invalid(format!("{what} at {address:#010x} is unreadable: {error}")))
}

fn expect_storage(storage: &[WireSpan], expected: &[StorageSpan], what: &str) -> Result<()> {
    let actual: Vec<StorageSpan> = storage.iter().map(WireSpan::as_storage).collect();
    if actual == expected {
        Ok(())
    } else {
        Err(invalid(format!(
            "{what} does not match the runtime provenance"
        )))
    }
}

fn storage_of(storage: &[WireSpan]) -> Vec<StorageSpan> {
    storage.iter().map(WireSpan::as_storage).collect()
}

fn revalidate(
    wire: WireManifest,
    runtime: &RuntimeImage<'_>,
    expected: &TaskArtifactContext<'_>,
    manifest_blake3: [u8; 32],
) -> Result<ValidatedTaskArtifact> {
    // Policy: format, schema, tool version, and the exact decoder triple.
    if wire.format != FORMAT {
        return Err(invalid("unexpected PAL task-manifest format"));
    }
    if wire.schema_version != SCHEMA_VERSION {
        return Err(invalid("unsupported PAL task-manifest schema_version"));
    }
    if wire.tool_version != env!("CARGO_PKG_VERSION") {
        return Err(invalid(format!(
            "tool_version {:?} does not match the compiled crate version",
            wire.tool_version
        )));
    }
    if wire.semantic_adapter != SEMANTIC_ADAPTER {
        return Err(invalid(
            "decoder semantic_adapter does not match the compiled semantic adapter",
        ));
    }
    if wire.backend_crate != BACKEND_CRATE {
        return Err(invalid(
            "decoder backend_crate does not match the compiled decoder crate",
        ));
    }
    if wire.backend_version != env!("CARGO_PKG_VERSION") {
        return Err(invalid(
            "decoder backend_version does not match the compiled crate version",
        ));
    }

    // Image identity: the label grammar, the supplied expectation, and a
    // fresh hash of the raw runtime segment.
    validate_label(&wire.image_label)?;
    if wire.image_label != expected.label {
        return Err(invalid(
            "image label does not match the expected artifact context",
        ));
    }
    let (image_base, image_size) = runtime.image_bounds();
    if wire.image_base != image_base || wire.image_size != image_size {
        return Err(invalid(
            "image base or size does not match the runtime image",
        ));
    }
    if wire.image_blake3 != expected.image_blake3 {
        return Err(invalid(
            "image BLAKE3 does not match the expected artifact context",
        ));
    }
    let recomputed_image_blake3 = runtime
        .hash_range(image_base, image_size)
        .map_err(|error| invalid(format!("raw image hash failed: {error}")))?;
    if recomputed_image_blake3 != wire.image_blake3 {
        return Err(invalid("image BLAKE3 does not match the raw runtime image"));
    }

    // The complete scatter dependency, not only the selected spans.
    if wire.scatter_load_map_blake3 != expected.scatter_load_map_blake3 {
        return Err(invalid(
            "scatter load map dependency does not match the expected artifact context",
        ));
    }

    revalidate_initializer(&wire, runtime)?;
    let tasks = revalidate_table_and_tasks(&wire, runtime)?;
    revalidate_used_entry_union(&wire)?;
    let applications = revalidate_applications(&wire, &tasks)?;

    let initializer = &wire.initializer;
    let used = wire.scatter_entries_used.clone();
    let task_records = wire.tasks.len();
    let distinct_entries = used.len();
    let plan = TaskPlan {
        image_base,
        image_size,
        initializer: InitializerEvidence {
            cfg_entry: initializer.cfg_entry,
            proof_paths: wire
                .initializer
                .references
                .iter()
                .map(|reference| AnchorProofPath {
                    anchor: reference.anchor,
                    reference: AnchorReference {
                        anchor: reference.anchor,
                        kind: reference.kind,
                        pc: reference.address,
                        definitions: reference.definitions.clone(),
                        register: crate::arm32::Register(0),
                    },
                    call: reference.call,
                })
                .collect(),
            anchors: wire
                .initializer
                .anchors
                .iter()
                .map(|anchor| AnchorProvenance {
                    address: anchor.address,
                    storage: storage_of(&anchor.storage),
                })
                .collect(),
            code_storage: storage_of(&initializer.code_storage),
            loop_start: initializer.loop_start,
            count_zero_definition: initializer.count_zero_definition,
            slot_definition: SlotDefinition {
                root: initializer.slot_definition_root,
                definitions: initializer.slot_definition_definitions.clone(),
            },
            normal_exit: initializer.normal_exit,
            capacity_exit: initializer.capacity_exit,
            // The wire carries the semantic guard result; the
            // reconstruction fills the encoding-specific fields with the
            // canonical minimal encoding of the same relation.
            capacity_guard: CapacityGuard {
                start: initializer.guard_start,
                compare: initializer.guard_branch,
                branch: initializer.guard_branch,
                fallthrough: initializer.guard_fallthrough,
                shift_amount: 0,
                compare_value: initializer
                    .capacity
                    .checked_sub(1)
                    .ok_or_else(|| invalid("capacity has no positive guard bound"))?,
            },
            suffix_loop: initializer.suffix_loop,
            join: initializer.join,
            count_global: initializer.count_global,
            slot_base: initializer.slot_base,
            name_offset: initializer.name_offset,
            index_offset: initializer.index_offset,
            stride: initializer.stride,
            capacity: initializer.capacity,
        },
        table: TaskTable {
            slot_base: initializer.slot_base,
            name_offset: initializer.name_offset,
            index_offset: initializer.index_offset,
            stride: initializer.stride,
            capacity: initializer.capacity,
            count: wire.table.count,
            descriptor_projection_offset: wire.table.descriptor_projection_offset,
            priority_offset: wire.table.priority_offset,
            stack_size_offset: wire.table.stack_size_offset,
            entry_offset: wire.table.entry_offset,
            callback_offset: wire.table.callback_offset,
            unknown_pointer_offset: wire.table.unknown_pointer_offset,
        },
        tasks,
        applications,
        terminal: TerminalRecord {
            slot: wire.table.terminal_slot,
            slot_blake3: wire.table.terminal_blake3,
            storage: storage_of(&wire.table.terminal_storage),
        },
    };
    Ok(ValidatedTaskArtifact {
        plan,
        image_label: wire.image_label,
        image_blake3: wire.image_blake3,
        manifest_blake3,
        identity: identity(manifest_blake3, task_records, distinct_entries),
        scatter_load_map_blake3: wire.scatter_load_map_blake3,
    })
}

fn revalidate_initializer(wire: &WireManifest, runtime: &RuntimeImage<'_>) -> Result<()> {
    let initializer = &wire.initializer;

    // Geometry limits mirrored from table validation.
    if initializer.capacity == 0 || initializer.capacity > MAX_TABLE_CAPACITY {
        return Err(invalid("capacity exceeds the descriptor-v1 table limit"));
    }
    if initializer.stride == 0 || initializer.stride > MAX_TABLE_STRIDE {
        return Err(invalid("stride exceeds the descriptor-v1 table limit"));
    }
    let descriptor_end = initializer
        .name_offset
        .checked_add(24)
        .ok_or_else(|| invalid("name offset cannot address the descriptor fields"))?;
    let index_end = initializer
        .index_offset
        .checked_add(4)
        .ok_or_else(|| invalid("index offset cannot address its field"))?;
    if descriptor_end > initializer.stride || index_end > initializer.stride {
        return Err(invalid(
            "known descriptor fields do not fit inside the stride",
        ));
    }
    let field_offset = |delta: u32| {
        initializer
            .name_offset
            .checked_add(delta)
            .ok_or_else(|| invalid("table field offset wraps the address space"))
    };
    let expected_offsets = [
        field_offset(4)?,
        field_offset(8)?,
        field_offset(12)?,
        field_offset(16)?,
        field_offset(20)?,
    ];
    let offsets = [
        wire.table.priority_offset,
        wire.table.stack_size_offset,
        wire.table.entry_offset,
        wire.table.callback_offset,
        wire.table.unknown_pointer_offset,
    ];
    if offsets != expected_offsets {
        return Err(invalid(
            "table field offsets do not follow the discovered name offset",
        ));
    }
    if wire.table.descriptor_projection_offset
        != initializer
            .name_offset
            .checked_sub(DESCRIPTOR_PROJECTION_OFFSET)
            .ok_or_else(|| invalid("name offset cannot project the descriptor"))?
    {
        return Err(invalid(
            "descriptor projection offset is not the projection",
        ));
    }

    // Control addresses stay mapped, distinct where the proof needs them,
    // and the guard branch resolves to the declared join.
    for (address, what) in [
        (initializer.cfg_entry, "initializer cfg_entry"),
        (initializer.loop_start, "initializer loop_start"),
        (
            initializer.count_zero_definition,
            "initializer count_zero_definition",
        ),
        (initializer.normal_exit, "initializer normal_exit"),
        (initializer.capacity_exit, "initializer capacity_exit"),
        (initializer.guard_start, "capacity guard start"),
        (initializer.guard_fallthrough, "capacity guard fallthrough"),
        (initializer.suffix_loop, "initializer suffix_loop"),
        (initializer.join, "initializer join"),
        (initializer.count_global, "initializer count_global"),
    ] {
        require_mapped(runtime, address, what)?;
    }
    if initializer.normal_exit == initializer.capacity_exit {
        return Err(invalid("dual exits share one address"));
    }
    let Some(instruction) = super::cfg::decode_thumb_at(runtime, initializer.guard_branch) else {
        return Err(invalid(
            "capacity guard branch does not decode as Thumb code",
        ));
    };
    match instruction.flow {
        ControlFlow::DirectBranch {
            target,
            fallthrough: Some(fallthrough),
            ..
        } if target == initializer.join && fallthrough == initializer.guard_fallthrough => {}
        _ => {
            return Err(invalid(
                "capacity guard branch does not target the common join with the declared fallthrough",
            ));
        }
    }

    // Anchors: sorted unique occurrences with exact nine-byte evidence.
    if initializer.anchors.is_empty() {
        return Err(invalid("the anchors array is empty"));
    }
    let mut anchor_addresses = BTreeSet::new();
    for anchor in &initializer.anchors {
        if !anchor_addresses.insert(anchor.address) {
            return Err(invalid("anchors are not sorted by unique address"));
        }
        if anchor_addresses.last() != Some(&anchor.address) {
            return Err(invalid("anchors are not sorted by unique address"));
        }
        if anchor.storage.is_empty() {
            return Err(invalid("anchor storage is empty"));
        }
        if storage_of(&anchor.storage)
            .iter()
            .any(|span| span.kind == StorageKind::ScatterZero)
        {
            return Err(invalid("anchor storage contains virtual zero fill"));
        }
        let bytes = runtime.read_exact(anchor.address, 9).map_err(|error| {
            invalid(format!(
                "anchor at {:#010x} is unreadable: {error}",
                anchor.address
            ))
        })?;
        if bytes.as_ref() != &ANCHOR_PATTERN[..] {
            return Err(invalid("anchor bytes are not the PAL task marker"));
        }
        let spans = runtime
            .storage_spans(anchor.address, 9)
            .map_err(|error| invalid(format!("anchor provenance is unreadable: {error}")))?;
        expect_storage(&anchor.storage, &spans, "anchor storage")?;
    }

    // Proof paths: deduplicated, sorted, every anchor known, every
    // definition chain nonempty and mapped.
    if initializer.references.is_empty() {
        return Err(invalid("the anchor_references array is empty"));
    }
    let mut reference_keys: Vec<(u32, u32, u8, u32)> = Vec::new();
    for reference in &initializer.references {
        let key = (
            reference.anchor,
            reference.address,
            anchor_kind_rank(reference.kind),
            reference.call,
        );
        if matches!(reference_keys.last(), Some(last) if *last >= key) {
            return Err(invalid(
                "anchor_references are not sorted by (anchor,address,kind,call)",
            ));
        }
        reference_keys.push(key);
        if !anchor_addresses.contains(&reference.anchor) {
            return Err(invalid("an anchor reference names an unknown anchor"));
        }
        if reference.definitions.is_empty() {
            return Err(invalid("an anchor reference has an empty definition chain"));
        }
        require_mapped(runtime, reference.address, "anchor reference address")?;
        require_mapped(runtime, reference.call, "anchor reference call")?;
        for definition in &reference.definitions {
            require_mapped(runtime, *definition, "anchor definition")?;
        }
    }

    // Code storage: the canonical sorted byte-backed union.
    if initializer.code_storage.is_empty() {
        return Err(invalid("the code_storage array is empty"));
    }
    revalidate_span_union(&initializer.code_storage, runtime, "code_storage")?;

    // The slot definition chain begins at its root.
    if initializer.slot_definition_definitions.first() != Some(&initializer.slot_definition_root) {
        return Err(invalid("slot definition chain does not begin at its root"));
    }
    require_mapped(
        runtime,
        initializer.slot_definition_root,
        "slot definition root",
    )?;
    for definition in &initializer.slot_definition_definitions {
        require_mapped(runtime, *definition, "slot definition")?;
    }
    Ok(())
}

/// A canonical span union: sorted, positive, non-overlapping, byte-backed,
/// and every span resolves to exactly itself in the runtime image.
fn revalidate_span_union(spans: &[WireSpan], runtime: &RuntimeImage<'_>, what: &str) -> Result<()> {
    let mut previous_end: Option<u32> = None;
    for span in spans {
        if span.size == 0 {
            return Err(invalid(format!("{what} contains a zero-size span")));
        }
        let end = span
            .address
            .checked_add(span.size)
            .ok_or_else(|| invalid(format!("{what} span wraps the address space")))?;
        if matches!(previous_end, Some(previous) if span.address < previous) {
            return Err(invalid(format!("{what} spans are not sorted or overlap")));
        }
        previous_end = Some(end);
        if span.kind == StorageKind::ScatterZero {
            return Err(invalid(format!("{what} contains virtual zero fill")));
        }
        let resolved = runtime
            .storage_spans(span.address, span.size)
            .map_err(|error| invalid(format!("{what} span is unreadable: {error}")))?;
        if resolved.len() != 1 || resolved[0] != span.as_storage() {
            return Err(invalid(format!(
                "{what} span does not resolve to exactly itself"
            )));
        }
    }
    Ok(())
}

fn revalidate_table_and_tasks(
    wire: &WireManifest,
    runtime: &RuntimeImage<'_>,
) -> Result<Vec<TaskRecord>> {
    let initializer = &wire.initializer;
    let task_count = wire.tasks.len();
    let count = u32::try_from(task_count)
        .map_err(|_| invalid("task count does not fit the table record"))?;
    if wire.table.count != count {
        return Err(invalid(format!(
            "table task count {} does not match the {task_count} serialized task records",
            wire.table.count
        )));
    }
    if count == 0 || count >= initializer.capacity {
        return Err(invalid("task count is outside 1..capacity"));
    }
    let terminal_advanced = count
        .checked_mul(initializer.stride)
        .ok_or_else(|| invalid("terminal slot arithmetic wraps"))?;
    let terminal_slot = initializer
        .slot_base
        .checked_add(terminal_advanced)
        .ok_or_else(|| invalid("terminal slot arithmetic wraps"))?;
    if wire.table.terminal_slot != terminal_slot {
        return Err(invalid(
            "terminal slot is not the slot after the final task",
        ));
    }
    let field_address = |slot: u32, offset: u32| {
        slot.checked_add(offset)
            .ok_or_else(|| invalid("table field address wraps the address space"))
    };

    // Terminal evidence: known words zero, hash and storage exact.
    for (offset, what) in [
        (initializer.name_offset, "terminal name"),
        (wire.table.priority_offset, "terminal priority"),
        (wire.table.stack_size_offset, "terminal stack"),
        (wire.table.entry_offset, "terminal entry"),
        (wire.table.callback_offset, "terminal callback"),
        (
            wire.table.unknown_pointer_offset,
            "terminal unknown pointer",
        ),
    ] {
        let address = field_address(terminal_slot, offset)?;
        let word = read_word(runtime, address, what)?;
        if word != 0 {
            return Err(invalid(format!("{what} word is nonzero")));
        }
    }
    if wire.table.terminal_storage.is_empty() {
        return Err(invalid("terminal storage is empty"));
    }
    let terminal_hash = runtime
        .hash_range(terminal_slot, initializer.stride)
        .map_err(|error| invalid(format!("terminal slot is unreadable: {error}")))?;
    if terminal_hash != wire.table.terminal_blake3 {
        return Err(invalid("terminal BLAKE3 does not match the runtime bytes"));
    }
    let terminal_spans = runtime
        .storage_spans(terminal_slot, initializer.stride)
        .map_err(|error| invalid(format!("terminal provenance is unreadable: {error}")))?;
    expect_storage(
        &wire.table.terminal_storage,
        &terminal_spans,
        "terminal storage",
    )?;

    let mut records = Vec::with_capacity(task_count);
    for task in &wire.tasks {
        let advanced = task
            .index
            .checked_mul(initializer.stride)
            .ok_or_else(|| invalid("task slot arithmetic wraps"))?;
        let slot = initializer
            .slot_base
            .checked_add(advanced)
            .ok_or_else(|| invalid("task slot arithmetic wraps"))?;
        let position = u32::try_from(records.len())
            .map_err(|_| invalid("task count does not fit the table record"))?;
        if task.index != position {
            return Err(invalid("task indices are not the contiguous table order"));
        }
        if task.slot != slot {
            return Err(invalid(format!(
                "task {} slot is not the slot_base geometry",
                task.index
            )));
        }

        // Every interpreted word is re-read and compared.
        let name_pointer = read_word(
            runtime,
            field_address(slot, initializer.name_offset)?,
            &format!("task {} name pointer", task.index),
        )?;
        if name_pointer != task.name_pointer {
            return Err(invalid("task name pointer does not match the slot bytes"));
        }
        let priority_word = read_word(
            runtime,
            field_address(slot, wire.table.priority_offset)?,
            &format!("task {} priority", task.index),
        )?;
        if priority_word != u32::from(task.priority) {
            return Err(invalid("task priority does not match the slot bytes"));
        }
        let stack_word = read_word(
            runtime,
            field_address(slot, wire.table.stack_size_offset)?,
            &format!("task {} stack size", task.index),
        )?;
        if stack_word != task.stack_size {
            return Err(invalid("task stack size does not match the slot bytes"));
        }
        if task.stack_size == 0 || task.stack_size % 4 != 0 {
            return Err(invalid("task stack size is zero or not four-byte aligned"));
        }
        let entry_pointer = read_word(
            runtime,
            field_address(slot, wire.table.entry_offset)?,
            &format!("task {} entry pointer", task.index),
        )?;
        if entry_pointer != task.entry_pointer {
            return Err(invalid("task entry pointer does not match the slot bytes"));
        }
        let callback = read_word(
            runtime,
            field_address(slot, wire.table.callback_offset)?,
            &format!("task {} callback", task.index),
        )?;
        if callback != task.callback {
            return Err(invalid("task callback does not match the slot bytes"));
        }
        let unknown_pointer = read_word(
            runtime,
            field_address(slot, wire.table.unknown_pointer_offset)?,
            &format!("task {} unknown pointer", task.index),
        )?;
        if unknown_pointer != task.unknown_pointer {
            return Err(invalid(
                "task unknown pointer does not match the slot bytes",
            ));
        }

        // The exact NUL-terminated name bytes and provenance.
        let (name, name_storage) = runtime
            .read_ascii_nul(task.name_pointer, MAX_TASK_NAME_BYTES)
            .map_err(|error| {
                invalid(format!(
                    "task {} name at {:#010x} is invalid: {error}",
                    task.index, task.name_pointer
                ))
            })?;
        if name != task.name {
            return Err(invalid("task name does not match the runtime bytes"));
        }
        if task.name.len() < 2 {
            return Err(invalid("task name is shorter than two characters"));
        }
        if task.name_storage.is_empty() {
            return Err(invalid("task name storage is empty"));
        }
        expect_storage(&task.name_storage, &name_storage, "task name storage")?;

        // Slot hash and provenance.
        let slot_hash = runtime
            .hash_range(slot, initializer.stride)
            .map_err(|error| invalid(format!("task {} slot is unreadable: {error}", task.index)))?;
        if slot_hash != task.slot_blake3 {
            return Err(invalid(format!(
                "task {} slot BLAKE3 does not match the runtime bytes",
                task.index
            )));
        }
        let slot_spans = runtime
            .storage_spans(slot, initializer.stride)
            .map_err(|error| {
                invalid(format!(
                    "task {} provenance is unreadable: {error}",
                    task.index
                ))
            })?;
        if task.slot_storage.is_empty() {
            return Err(invalid("task slot storage is empty"));
        }
        expect_storage(&task.slot_storage, &slot_spans, "task slot storage")?;

        revalidate_entry(task, runtime)?;

        records.push(TaskRecord {
            index: task.index,
            slot: task.slot,
            slot_blake3: task.slot_blake3,
            name_pointer: task.name_pointer,
            name: task.name.clone(),
            task_label: task.task_label.clone(),
            priority: task.priority,
            stack_size: task.stack_size,
            entry_pointer: task.entry_pointer,
            entry: task.entry,
            isa: task.isa,
            instruction_size: task.instruction_size,
            instruction_blake3: task.instruction_blake3,
            callback: task.callback,
            unknown_pointer: task.unknown_pointer,
            slot_storage: storage_of(&task.slot_storage),
            name_storage: storage_of(&task.name_storage),
            entry_storage: storage_of(&task.entry_storage),
        });
    }
    Ok(records)
}

/// Normalize the stored pointer, decode exactly the selected ISA, and
/// recompute the instruction hash and storage — mirroring the original
/// table validation with no cross-ISA fallback.
fn revalidate_entry(task: &WireTask, runtime: &RuntimeImage<'_>) -> Result<()> {
    let (isa, address) = if task.entry_pointer & 1 == 1 {
        (TaskIsa::Thumb, task.entry_pointer & !1)
    } else {
        (TaskIsa::Arm, task.entry_pointer)
    };
    if isa != task.isa || address != task.entry {
        return Err(invalid("task entry does not match the normalized pointer"));
    }
    if isa == TaskIsa::Arm && !address.is_multiple_of(4) {
        return Err(invalid("ARM entry pointer is not word aligned"));
    }
    let mut bytes = runtime.read_exact(address, 4);
    if isa == TaskIsa::Thumb && bytes.is_err() {
        bytes = runtime.read_exact(address, 2);
    }
    let bytes =
        bytes.map_err(|error| invalid(format!("task entry bytes are unreadable: {error}")))?;
    let decoder = PureRustDecoder;
    let mut state = decoder.begin_range(isa.decode_isa());
    let instruction = decoder
        .decode_one(&mut state, isa.decode_isa(), address, &bytes)
        .map_err(|error| invalid(format!("task entry instruction does not decode: {error}")))?;
    let length = u32::from(instruction.length);
    if length != u32::from(task.instruction_size) {
        return Err(invalid(
            "task instruction size does not match the decoded length",
        ));
    }
    if matches!(instruction.effect, ValueEffect::Unsupported) {
        return Err(invalid("task entry instruction is unsupported"));
    }
    if !runtime
        .is_byte_backed(address, length)
        .map_err(|error| invalid(format!("task entry storage is unverifiable: {error}")))?
    {
        return Err(invalid("task entry storage is not byte-backed"));
    }
    let hash = runtime
        .hash_range(address, length)
        .map_err(|error| invalid(format!("task entry bytes are unreadable: {error}")))?;
    if hash != task.instruction_blake3 {
        return Err(invalid(
            "task instruction BLAKE3 does not match the runtime bytes",
        ));
    }
    let spans = runtime
        .storage_spans(address, length)
        .map_err(|error| invalid(format!("task entry provenance is unreadable: {error}")))?;
    if task.entry_storage.is_empty() {
        return Err(invalid("task entry storage is empty"));
    }
    expect_storage(&task.entry_storage, &spans, "task entry storage")
}

fn revalidate_used_entry_union(wire: &WireManifest) -> Result<()> {
    let mut used = BTreeSet::new();
    let mut collect = |spans: &[WireSpan]| {
        for span in spans {
            if let Some(entry) = span.scatter_entry {
                used.insert(entry);
            }
        }
    };
    for anchor in &wire.initializer.anchors {
        collect(&anchor.storage);
    }
    collect(&wire.initializer.code_storage);
    for task in &wire.tasks {
        collect(&task.slot_storage);
        collect(&task.name_storage);
        collect(&task.entry_storage);
    }
    collect(&wire.table.terminal_storage);
    let recomputed: Vec<usize> = used.into_iter().collect();
    if wire.scatter_entries_used != recomputed {
        return Err(invalid(
            "scatter_entries_used is not the exact runtime union",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Deterministic application recomputation through `table`'s allocator
// ---------------------------------------------------------------------------

/// Recompute the complete deterministic application decision from the
/// revalidated task records through the same allocator `table` used —
/// groups, preferred leaves, collision suffixes, label partitions, and
/// ordering — and require the serialized decision to equal it.
fn revalidate_applications(
    wire: &WireManifest,
    records: &[TaskRecord],
) -> Result<Vec<TaskApplication>> {
    // Recompute the allocation through the one deterministic allocator
    // `table` owns: it fills every record's `task_label` and returns the
    // applications; any allocator-level rejection is a wire violation.
    let mut recomputed = records.to_vec();
    let applications =
        super::table::allocate_applications(&mut recomputed, wire.initializer.cfg_entry)
            .map_err(|error| invalid(error.to_string()))?;

    // The serialized per-record labels must equal the recomputation.
    for (task, record) in wire.tasks.iter().zip(&recomputed) {
        if task.task_label != record.task_label {
            return Err(invalid(format!(
                "task {} label does not match the deterministic allocation",
                task.index
            )));
        }
    }

    // The serialized application decision must equal the recomputation
    // exactly.
    if wire.applications.len() != applications.len() {
        return Err(invalid(
            "applications do not cover exactly the distinct entry groups",
        ));
    }
    for (wire_application, application) in wire.applications.iter().zip(&applications) {
        if wire_application.entry != application.entry
            || wire_application.isa != application.isa
            || wire_application.desired_primary != application.desired_primary
        {
            return Err(invalid(
                "desired primary does not match the deterministic allocation",
            ));
        }
        if wire_application.task_indices != application.task_indices {
            return Err(invalid(
                "application task indices do not match the entry group",
            ));
        }
        if wire_application.labels.len() != application.labels.len() {
            return Err(invalid(
                "application labels do not partition the entry group",
            ));
        }
        for (wire_label, label) in wire_application.labels.iter().zip(&application.labels) {
            if wire_label.label != label.label || wire_label.task_indices != label.task_indices {
                return Err(invalid(
                    "application label does not match the deterministic allocation",
                ));
            }
        }
    }
    Ok(applications)
}

// ---------------------------------------------------------------------------
// Secure manifest open
// ---------------------------------------------------------------------------

/// Open the manifest through scatter's handle-anchored
/// `TrustedDirectory`: the parent directory is opened without following
/// links and the leaf is opened relative to that retained capability,
/// with a regular-file check — the same proven containment the scatter
/// artifact reader uses, on every supported platform.
fn open_manifest_file(path: &Path) -> Result<File> {
    if !path.is_absolute() {
        return Err(invalid("manifest path is not absolute"));
    }
    if path.file_name().and_then(|name| name.to_str()) != Some(ARTIFACT_FILE_NAME) {
        return Err(invalid("manifest file name is not tasks.json"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| invalid("manifest path has no parent directory"))?;
    let trusted = crate::scatter::TrustedDirectory::new(parent, "pal task manifest parent")
        .map_err(|error| {
            invalid(format!(
                "manifest parent cannot be opened securely: {error}"
            ))
        })?;
    let (file, _) = trusted
        .open_regular_file_with_parent(Path::new(ARTIFACT_FILE_NAME), "pal task manifest")
        .map_err(|error| invalid(error.to_string()))?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use crate::arm32::Register;
    use crate::pal_tasks::discover::test_support::{
        BASE, bytes_entry, enc, gpr, raw_image, scatter_plan, zero_entry,
    };
    use crate::pal_tasks::{
        ANCHOR_PATTERN, AnchorProofPath, AnchorProvenance, AnchorReference, AnchorReferenceKind,
        CapacityGuard, InitializerEvidence, PalTaskError, SlotDefinition, TaskApplication, TaskIsa,
        TaskLabelApplication, TaskPlan, TaskRecord, TaskTable, TerminalRecord,
    };
    use crate::pal_tasks::{
        FORMAT, MaterializedTaskMap, TaskArtifactContext, ValidatedTaskArtifact,
        clear_materialized, materialize, read,
    };
    use crate::runtime_image::{RuntimeImage, StorageKind, StorageSpan};
    use scaleservers_arm32_assembly::{Arm32Condition, ArmT32Instruction as T32};
    use std::fs;
    use std::path::{Path, PathBuf};
    use tempfile::{TempDir, tempdir};

    const CODE_BASE: u32 = BASE;
    const CODE_LEN: u32 = 0x100;
    const LOOP_START: u32 = BASE + 0x4;
    const COUNT_ZERO_DEFINITION: u32 = BASE + 0x8;
    const SLOT_DEFINITION_ROOT: u32 = BASE + 0xc;
    const NORMAL_EXIT: u32 = BASE + 0x10;
    const CAPACITY_EXIT: u32 = BASE + 0x14;
    const GUARD_START: u32 = BASE + 0x18;
    const GUARD_BRANCH: u32 = BASE + 0x1c;
    const GUARD_FALLTHROUGH: u32 = BASE + 0x1e;
    const SUFFIX_LOOP: u32 = BASE + 0x20;
    const JOIN: u32 = BASE + 0x24;
    const REF_A_ADDRESS: u32 = BASE + 0x28;
    const REF_A_CALL: u32 = BASE + 0x2c;
    const REF_B_ADDRESS: u32 = BASE + 0x30;
    const REF_B_CALL: u32 = BASE + 0x34;
    const COUNT_GLOBAL: u32 = BASE + 0xf0;
    const ANCHOR_A: u32 = BASE + 0x100;
    const ANCHOR_B: u32 = BASE + 0x200;
    const NAME_ALPHA: u32 = BASE + 0x500;
    const NAME_BETA: u32 = BASE + 0x508;
    const ENTRY_A: u32 = BASE + 0x600;
    const ENTRY_B: u32 = BASE + 0x604;
    const SLOT_BASE: u32 = 0x2000;
    const STRIDE: u32 = 0x1f8;
    const NAME_OFFSET: u32 = 0x4c;
    const INDEX_OFFSET: u32 = 0x0c;
    const CAPACITY: u32 = 8;
    const SLOT_ALPHA: u32 = SLOT_BASE;
    const SLOT_BETA: u32 = SLOT_BASE + STRIDE;
    const TERMINAL_SLOT: u32 = SLOT_BASE + 2 * STRIDE;
    const IMAGE_END: u32 = 0x2600;
    const SCATTER_MAP_BLAKE3: [u8; 32] = *b"fixture-load-map-blake3-identity";

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
            let end = address
                .checked_add(u32::try_from(data.len()).unwrap())
                .unwrap();
            self.ensure(end);
            let offset = usize::try_from(address - BASE).unwrap();
            self.bytes[offset..offset + data.len()].copy_from_slice(data);
        }

        fn write_u8(&mut self, address: u32, value: u8) {
            self.write(address, &[value]);
        }

        fn write_u32(&mut self, address: u32, value: u32) {
            self.write(address, &value.to_le_bytes());
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn write_slot(
        image: &mut ImageBuilder,
        slot: u32,
        opaque_seed: u8,
        name_pointer: u32,
        priority: u32,
        stack_size: u32,
        entry_pointer: u32,
        callback: u32,
        unknown_pointer: u32,
    ) {
        for offset in 0..STRIDE {
            image.write_u8(slot + offset, opaque_seed.wrapping_add(offset as u8));
        }
        image.write_u32(slot + NAME_OFFSET, name_pointer);
        image.write_u32(slot + NAME_OFFSET + 4, priority);
        image.write_u32(slot + NAME_OFFSET + 8, stack_size);
        image.write_u32(slot + NAME_OFFSET + 12, entry_pointer);
        image.write_u32(slot + NAME_OFFSET + 16, callback);
        image.write_u32(slot + NAME_OFFSET + 20, unknown_pointer);
    }

    fn write_terminal(image: &mut ImageBuilder, slot: u32, opaque_seed: u8) {
        for offset in 0..STRIDE {
            image.write_u8(slot + offset, opaque_seed.wrapping_add(offset as u8));
        }
        for field in [
            NAME_OFFSET,
            NAME_OFFSET + 4,
            NAME_OFFSET + 8,
            NAME_OFFSET + 12,
            NAME_OFFSET + 16,
            NAME_OFFSET + 20,
        ] {
            image.write_u32(slot + field, 0);
        }
    }

    fn build_flat() -> Vec<u8> {
        let mut image = ImageBuilder::new();
        for offset in 0..CODE_LEN {
            image.write_u8(CODE_BASE + offset, 0xa5);
        }
        // The capacity-guard branch: conditional Thumb branch to JOIN with
        // fallthrough GUARD_FALLTHROUGH (the assembler immediate is the
        // target - pc - 4 byte offset).
        image.write(GUARD_BRANCH, &enc(&T32::B_T1(Arm32Condition::NotEqual, 4)));
        image.write(ANCHOR_A, ANCHOR_PATTERN);
        image.write(ANCHOR_B, ANCHOR_PATTERN);
        image.write(NAME_ALPHA, b"alpha\0");
        image.write(NAME_BETA, b"beta\0");
        image.write(ENTRY_A, &enc(&T32::Push_T1(vec![gpr(4), gpr(14)])));
        image.write(ENTRY_B, &enc(&T32::Mov_Immediate_T3(gpr(0), 0x1234)));
        write_slot(
            &mut image,
            SLOT_ALPHA,
            0x5a,
            NAME_ALPHA,
            100,
            0x200,
            ENTRY_A | 1,
            0,
            0,
        );
        write_slot(
            &mut image,
            SLOT_BETA,
            0xc7,
            NAME_BETA,
            0xff,
            0x80e8,
            ENTRY_B | 1,
            0x6789_abcd,
            0x1234,
        );
        write_terminal(&mut image, TERMINAL_SLOT, 0x33);
        image.ensure(IMAGE_END);
        image.bytes
    }

    fn proof_paths() -> Vec<AnchorProofPath> {
        vec![
            AnchorProofPath {
                anchor: ANCHOR_A,
                reference: AnchorReference {
                    anchor: ANCHOR_A,
                    kind: AnchorReferenceKind::Adr,
                    pc: REF_A_ADDRESS,
                    definitions: vec![REF_A_ADDRESS],
                    register: Register(0),
                },
                call: REF_A_CALL,
            },
            AnchorProofPath {
                anchor: ANCHOR_B,
                reference: AnchorReference {
                    anchor: ANCHOR_B,
                    kind: AnchorReferenceKind::MovwMovt,
                    pc: REF_B_ADDRESS,
                    definitions: vec![REF_B_ADDRESS, REF_B_ADDRESS + 2],
                    register: Register(0),
                },
                call: REF_B_CALL,
            },
        ]
    }

    /// The plan frame shared by every synthetic fixture: the fixed
    /// initializer/table/terminal geometry over the fixture image.
    fn synthetic_frame(
        image: &RuntimeImage<'_>,
        tasks: Vec<TaskRecord>,
        applications: Vec<TaskApplication>,
    ) -> TaskPlan {
        let anchors = [ANCHOR_A, ANCHOR_B]
            .into_iter()
            .map(|address| AnchorProvenance {
                address,
                storage: image.storage_spans(address, 9).unwrap(),
            })
            .collect();
        let initializer = InitializerEvidence {
            cfg_entry: CODE_BASE,
            proof_paths: proof_paths(),
            anchors,
            code_storage: image.storage_spans(CODE_BASE, CODE_LEN).unwrap(),
            loop_start: LOOP_START,
            count_zero_definition: COUNT_ZERO_DEFINITION,
            // The fixture image carries no real MOVW/MOVT pair, so the
            // chain is the bare immediate root; the leaf-call and copy
            // chains are pinned by the discovery-side fixtures.
            slot_definition: SlotDefinition {
                root: SLOT_DEFINITION_ROOT,
                definitions: vec![SLOT_DEFINITION_ROOT],
            },
            normal_exit: NORMAL_EXIT,
            capacity_exit: CAPACITY_EXIT,
            // The wire carries the semantic guard {start,branch,fallthrough};
            // the reader reconstructs compare = branch, shift 0, and
            // compare_value = capacity - 1, so the fixture aligns with it.
            capacity_guard: CapacityGuard {
                start: GUARD_START,
                compare: GUARD_BRANCH,
                branch: GUARD_BRANCH,
                fallthrough: GUARD_FALLTHROUGH,
                shift_amount: 0,
                compare_value: CAPACITY - 1,
            },
            suffix_loop: SUFFIX_LOOP,
            join: JOIN,
            count_global: COUNT_GLOBAL,
            slot_base: SLOT_BASE,
            name_offset: NAME_OFFSET,
            index_offset: INDEX_OFFSET,
            stride: STRIDE,
            capacity: CAPACITY,
        };
        let (image_base, image_size) = image.image_bounds();
        TaskPlan {
            image_base,
            image_size,
            initializer,
            table: TaskTable {
                slot_base: SLOT_BASE,
                name_offset: NAME_OFFSET,
                index_offset: INDEX_OFFSET,
                stride: STRIDE,
                capacity: CAPACITY,
                count: 2,
                descriptor_projection_offset: NAME_OFFSET - 0x24,
                priority_offset: NAME_OFFSET + 4,
                stack_size_offset: NAME_OFFSET + 8,
                entry_offset: NAME_OFFSET + 12,
                callback_offset: NAME_OFFSET + 16,
                unknown_pointer_offset: NAME_OFFSET + 20,
            },
            tasks,
            applications,
            terminal: TerminalRecord {
                slot: TERMINAL_SLOT,
                slot_blake3: image.hash_range(TERMINAL_SLOT, STRIDE).unwrap(),
                storage: image.storage_spans(TERMINAL_SLOT, STRIDE).unwrap(),
            },
        }
    }

    fn synthetic_plan(image: &RuntimeImage<'_>) -> TaskPlan {
        let tasks = vec![
            TaskRecord {
                index: 0,
                slot: SLOT_ALPHA,
                slot_blake3: image.hash_range(SLOT_ALPHA, STRIDE).unwrap(),
                name_pointer: NAME_ALPHA,
                name: "alpha".to_string(),
                task_label: "pal_TaskEntry_alpha".to_string(),
                priority: 100,
                stack_size: 0x200,
                entry_pointer: ENTRY_A | 1,
                entry: ENTRY_A,
                isa: TaskIsa::Thumb,
                instruction_size: 2,
                instruction_blake3: image.hash_range(ENTRY_A, 2).unwrap(),
                callback: 0,
                unknown_pointer: 0,
                slot_storage: image.storage_spans(SLOT_ALPHA, STRIDE).unwrap(),
                name_storage: image.storage_spans(NAME_ALPHA, 6).unwrap(),
                entry_storage: image.storage_spans(ENTRY_A, 2).unwrap(),
            },
            TaskRecord {
                index: 1,
                slot: SLOT_BETA,
                slot_blake3: image.hash_range(SLOT_BETA, STRIDE).unwrap(),
                name_pointer: NAME_BETA,
                name: "beta".to_string(),
                task_label: "pal_TaskEntry_beta".to_string(),
                priority: 0xff,
                stack_size: 0x80e8,
                entry_pointer: ENTRY_B | 1,
                entry: ENTRY_B,
                isa: TaskIsa::Thumb,
                instruction_size: 4,
                instruction_blake3: image.hash_range(ENTRY_B, 4).unwrap(),
                callback: 0x6789_abcd,
                unknown_pointer: 0x1234,
                slot_storage: image.storage_spans(SLOT_BETA, STRIDE).unwrap(),
                name_storage: image.storage_spans(NAME_BETA, 5).unwrap(),
                entry_storage: image.storage_spans(ENTRY_B, 4).unwrap(),
            },
        ];
        let applications = vec![
            TaskApplication {
                entry: ENTRY_A,
                isa: TaskIsa::Thumb,
                desired_primary: "pal_TaskEntry_alpha".to_string(),
                task_indices: vec![0],
                labels: vec![TaskLabelApplication {
                    label: "pal_TaskEntry_alpha".to_string(),
                    task_indices: vec![0],
                }],
            },
            TaskApplication {
                entry: ENTRY_B,
                isa: TaskIsa::Thumb,
                desired_primary: "pal_TaskEntry_beta".to_string(),
                task_indices: vec![1],
                labels: vec![TaskLabelApplication {
                    label: "pal_TaskEntry_beta".to_string(),
                    task_indices: vec![1],
                }],
            },
        ];
        synthetic_frame(image, tasks, applications)
    }

    fn raw_fixture() -> (Vec<u8>, RuntimeImage<'static>) {
        // The image borrows the leaked flat bytes so tests can hold both.
        let flat = Box::leak(build_flat().into_boxed_slice());
        (flat.to_vec(), raw_image(flat))
    }

    fn raw_context(image_blake3: [u8; 32]) -> TaskArtifactContext<'static> {
        TaskArtifactContext {
            label: "02_MAIN",
            image_blake3,
            scatter_load_map_blake3: None,
        }
    }

    fn scatter_fixture() -> (Vec<u8>, RuntimeImage<'static>, [u8; 32]) {
        let flat = Box::leak(build_flat().into_boxed_slice());
        let raw: &'static [u8] =
            Box::leak(flat[..(0x2000 - BASE) as usize].to_vec().into_boxed_slice());
        let zero_region: u32 = 0x38;
        let entries = vec![
            bytes_entry(0, 0x2000, flat[0x1000..0x1008].to_vec()),
            zero_entry(1, 0x2008, zero_region),
            bytes_entry(2, 0x2040, flat[0x1040..0x1600].to_vec()),
        ];
        let plan: &'static crate::scatter::LoadPlan =
            Box::leak(scatter_plan(0x1000, entries).into());
        let runtime = RuntimeImage::from_plan(raw, BASE, Some(plan)).unwrap();
        let image_blake3 = *blake3::hash(raw).as_bytes();
        (raw.to_vec(), runtime, image_blake3)
    }

    fn scatter_context(image_blake3: [u8; 32]) -> TaskArtifactContext<'static> {
        TaskArtifactContext {
            label: "02_MAIN",
            image_blake3,
            scatter_load_map_blake3: Some(SCATTER_MAP_BLAKE3),
        }
    }

    fn manifest_path(root: &Path) -> PathBuf {
        root.join("pal_tasks/02_MAIN/tasks.json")
    }

    fn materialized_raw(root: &Path) -> Vec<u8> {
        let (_raw, runtime) = raw_fixture();
        let plan = synthetic_plan(&runtime);
        let context = raw_context(*blake3::hash(&_raw).as_bytes());
        materialize(&plan, context, root).unwrap();
        fs::read(manifest_path(root)).unwrap()
    }

    fn write_manifest(root: &TempDir, bytes: &[u8]) -> PathBuf {
        fs::create_dir_all(manifest_path(root.path()).parent().unwrap()).unwrap();
        fs::write(manifest_path(root.path()), bytes).unwrap();
        manifest_path(root.path())
    }

    fn replace_once(bytes: &[u8], from: &str, to: &str) -> Vec<u8> {
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        let count = text.matches(from).count();
        assert_eq!(count, 1, "mutation source {from:?} matched {count} times");
        text.replacen(from, to, 1).into_bytes()
    }

    fn assert_rejected(
        path: &Path,
        runtime: &RuntimeImage<'_>,
        context: &TaskArtifactContext<'_>,
        reason: &str,
    ) {
        match read(path, runtime, *context) {
            Err(PalTaskError::Artifact(message)) => assert!(
                message.contains(reason),
                "expected {reason:?} in reader failure, got {message:?}"
            ),
            Err(other) => panic!("expected artifact reader failure, got {other:?}"),
            Ok(_) => panic!("strict reader accepted invalid manifest ({reason})"),
        }
    }

    fn hex(digest: [u8; 32]) -> String {
        digest.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    // The pinned canonical manifest bytes for the raw fixture; filled with
    // the serialized output of the implementation under test.
    const PINNED_RAW_MANIFEST: &str = r#"{
  "format": "pixel-modem-extractor-pal-tasks-v1",
  "schema_version": 1,
  "tool_version": "2.0.0",
  "image": {
    "label": "02_MAIN",
    "base_addr": "0x00001000",
    "size": 5632,
    "blake3": "6ed3cacc7fa4c9b37fda021cf1b08023c826a131430cee4c478306253b6e6f7f"
  },
  "runtime_view": {
    "scatter_load_map_blake3": null,
    "scatter_entries_used": []
  },
  "decoder": {
    "semantic_adapter": "pixel-modem-extractor-arm32-v1",
    "backend_crate": "scaleservers-arm32-assembly",
    "backend_version": "2.0.0"
  },
  "initializer": {
    "cfg_entry": "0x00001000",
    "anchors": [
      {
        "address": "0x00001100",
        "storage": [
          {
            "kind": "raw",
            "address": "0x00001100",
            "size": 9
          }
        ]
      },
      {
        "address": "0x00001200",
        "storage": [
          {
            "kind": "raw",
            "address": "0x00001200",
            "size": 9
          }
        ]
      }
    ],
    "anchor_references": [
      {
        "anchor": "0x00001100",
        "address": "0x00001028",
        "kind": "adr",
        "definitions": [
          "0x00001028"
        ],
        "call": "0x0000102c"
      },
      {
        "anchor": "0x00001200",
        "address": "0x00001030",
        "kind": "movw_movt",
        "definitions": [
          "0x00001030",
          "0x00001032"
        ],
        "call": "0x00001034"
      }
    ],
    "code_storage": [
      {
        "kind": "raw",
        "address": "0x00001000",
        "size": 256
      }
    ],
    "loop_start": "0x00001004",
    "count_zero_definition": "0x00001008",
    "slot_definition": {
      "root": "0x0000100c",
      "definitions": [
        "0x0000100c"
      ]
    },
    "normal_exit": "0x00001010",
    "capacity_exit": "0x00001014",
    "capacity_guard": {
      "start": "0x00001018",
      "branch": "0x0000101c",
      "fallthrough": "0x0000101e",
      "relation": "count_ge_capacity"
    },
    "suffix_loop": "0x00001020",
    "join": "0x00001024",
    "count_global": "0x000010f0",
    "slot_base": "0x00002000",
    "name_offset": 76,
    "index_offset": 12,
    "stride": 504,
    "capacity": 8
  },
  "table": {
    "count": 2,
    "terminal_slot": "0x000023f0",
    "terminal_blake3": "496c91b6997aec817fbbec3de1a5f7db2b6aca8104dec9010de099eae994d8a2",
    "terminal_storage": [
      {
        "kind": "raw",
        "address": "0x000023f0",
        "size": 504
      }
    ],
    "descriptor_projection_offset": 40,
    "priority_offset": 80,
    "stack_size_offset": 84,
    "entry_offset": 88,
    "callback_offset": 92,
    "unknown_pointer_offset": 96
  },
  "tasks": [
    {
      "index": 0,
      "slot": "0x00002000",
      "slot_blake3": "6c4754e66af6e7f6362aeabd687d8d2d256e545ecaccabe8aaf7292b310024cf",
      "name_pointer": "0x00001500",
      "name": "alpha",
      "task_label": "pal_TaskEntry_alpha",
      "priority": 100,
      "stack_size": 512,
      "entry_pointer": "0x00001601",
      "entry": "0x00001600",
      "isa": "thumb",
      "instruction_size": 2,
      "instruction_blake3": "d75e9748a3564878378526a612aecb0ec337915c18366493d5a0b710b273cda2",
      "callback": "0x00000000",
      "unknown_pointer": "0x00000000",
      "slot_storage": [
        {
          "kind": "raw",
          "address": "0x00002000",
          "size": 504
        }
      ],
      "name_storage": [
        {
          "kind": "raw",
          "address": "0x00001500",
          "size": 6
        }
      ],
      "entry_storage": [
        {
          "kind": "raw",
          "address": "0x00001600",
          "size": 2
        }
      ]
    },
    {
      "index": 1,
      "slot": "0x000021f8",
      "slot_blake3": "90daf0b62eda112c52314e735ac25a59a64eaadbd730f026d0199c776594aa99",
      "name_pointer": "0x00001508",
      "name": "beta",
      "task_label": "pal_TaskEntry_beta",
      "priority": 255,
      "stack_size": 33000,
      "entry_pointer": "0x00001605",
      "entry": "0x00001604",
      "isa": "thumb",
      "instruction_size": 4,
      "instruction_blake3": "1cfbcf27261950280385ff2e7043a518683f55a02909f46977a084b568b5097f",
      "callback": "0x6789abcd",
      "unknown_pointer": "0x00001234",
      "slot_storage": [
        {
          "kind": "raw",
          "address": "0x000021f8",
          "size": 504
        }
      ],
      "name_storage": [
        {
          "kind": "raw",
          "address": "0x00001508",
          "size": 5
        }
      ],
      "entry_storage": [
        {
          "kind": "raw",
          "address": "0x00001604",
          "size": 4
        }
      ]
    }
  ],
  "applications": [
    {
      "entry": "0x00001600",
      "isa": "thumb",
      "desired_primary": "pal_TaskEntry_alpha",
      "task_indices": [
        0
      ],
      "labels": [
        {
          "label": "pal_TaskEntry_alpha",
          "task_indices": [
            0
          ]
        }
      ]
    },
    {
      "entry": "0x00001604",
      "isa": "thumb",
      "desired_primary": "pal_TaskEntry_beta",
      "task_indices": [
        1
      ],
      "labels": [
        {
          "label": "pal_TaskEntry_beta",
          "task_indices": [
            1
          ]
        }
      ]
    }
  ]
}
"#;

    #[test]
    fn materializes_exact_canonical_bytes_with_pinned_blake3_and_identity() {
        assert_eq!(FORMAT, "pixel-modem-extractor-pal-tasks-v1");
        let (raw, runtime) = raw_fixture();
        let plan = synthetic_plan(&runtime);
        let image_blake3 = *blake3::hash(&raw).as_bytes();
        let root = tempdir().unwrap();
        let context = raw_context(image_blake3);

        let map: MaterializedTaskMap = materialize(&plan, context, root.path()).unwrap();

        assert_eq!(map.relative_path, "pal_tasks/02_MAIN/tasks.json");
        let bytes = fs::read(manifest_path(root.path())).unwrap();
        assert_eq!(bytes, PINNED_RAW_MANIFEST.as_bytes());
        assert_eq!(bytes.last(), Some(&b'\n'));
        assert_eq!(map.blake3, hex(*blake3::hash(&bytes).as_bytes()));
        assert_eq!(map.task_records, 2);
        assert_eq!(map.distinct_entries, 0);
        assert_eq!(map.identity, format!("v1:{}:2:0", map.blake3));
        // Package version and lowercase canonical addresses are pinned.
        let text = PINNED_RAW_MANIFEST;
        assert!(text.contains("\"tool_version\": \"2.0.0\""));
        assert!(text.contains("\"backend_version\": \"2.0.0\""));
        assert!(text.contains("\"cfg_entry\": \"0x00001000\""));
    }

    #[test]
    fn reruns_are_byte_identical_and_canonicalize_proof_arrays() {
        let (_raw, runtime) = raw_fixture();
        let mut plan = synthetic_plan(&runtime);
        // Insertion-order variation: reversed, duplicated, and unsorted
        // provenance arrays must canonicalize to identical wire bytes.
        let mut paths = proof_paths();
        let reversed: Vec<AnchorProofPath> = paths.clone().into_iter().rev().collect();
        paths.push(reversed[0].clone());
        plan.initializer.proof_paths = paths;
        plan.initializer.anchors.reverse();
        let doubled = plan.initializer.code_storage.clone();
        plan.initializer.code_storage.extend(doubled);
        let root = tempdir().unwrap();

        materialize(
            &plan,
            raw_context(*blake3::hash(&_raw).as_bytes()),
            root.path(),
        )
        .unwrap();

        assert_eq!(
            fs::read(manifest_path(root.path())).unwrap(),
            PINNED_RAW_MANIFEST.as_bytes()
        );
    }

    #[test]
    fn reader_round_trips_and_revalidates_the_canonical_manifest() {
        let (raw, runtime) = raw_fixture();
        let plan = synthetic_plan(&runtime);
        let context = raw_context(*blake3::hash(&raw).as_bytes());
        let root = tempdir().unwrap();
        let map = materialize(&plan, context, root.path()).unwrap();

        let artifact: ValidatedTaskArtifact =
            read(&manifest_path(root.path()), &runtime, context).unwrap();

        assert_eq!(artifact.image_label, "02_MAIN");
        assert_eq!(artifact.image_blake3, context.image_blake3);
        assert_eq!(artifact.scatter_load_map_blake3, None);
        assert_eq!(hex(artifact.manifest_blake3), map.blake3);
        assert_eq!(artifact.identity, map.identity);
        assert_eq!(artifact.plan, plan);
    }

    #[test]
    fn reader_recomputes_collision_suffixed_allocations_through_one_allocator() {
        // Two distinct exact names ("al.pha" and "al--pha") that sanitize
        // to one preferred leaf `pal_TaskEntry_al_pha` at two entries:
        // both namespaces hit the duplicate-group path, so every label
        // and primary is nonce-suffixed. The hand-pinned strings below
        // are the allocator's identity-key-ordered nonce-0 decisions;
        // read() recomputes them through the same `table` allocator.
        const NAME_DOT: u32 = BASE + 0x510;
        const NAME_DASHES: u32 = BASE + 0x518;
        let label_a = format!("pal_TaskEntry_al_pha_pme_{ENTRY_A:08x}_00000000_00000000");
        let label_b = format!("pal_TaskEntry_al_pha_pme_{ENTRY_B:08x}_00000001_00000000");

        let mut image = ImageBuilder::new();
        for offset in 0..CODE_LEN {
            image.write_u8(CODE_BASE + offset, 0xa5);
        }
        image.write(GUARD_BRANCH, &enc(&T32::B_T1(Arm32Condition::NotEqual, 4)));
        image.write(ANCHOR_A, ANCHOR_PATTERN);
        image.write(ANCHOR_B, ANCHOR_PATTERN);
        image.write(NAME_ALPHA, b"alpha\0");
        image.write(NAME_DOT, b"al.pha\0");
        image.write(NAME_DASHES, b"al--pha\0");
        image.write(ENTRY_A, &enc(&T32::Push_T1(vec![gpr(4), gpr(14)])));
        image.write(ENTRY_B, &enc(&T32::Mov_Immediate_T3(gpr(0), 0x1234)));
        write_slot(
            &mut image,
            SLOT_ALPHA,
            0x5a,
            NAME_DOT,
            100,
            0x200,
            ENTRY_A | 1,
            0,
            0,
        );
        write_slot(
            &mut image,
            SLOT_BETA,
            0xc7,
            NAME_DASHES,
            0xff,
            0x80e8,
            ENTRY_B | 1,
            0,
            0,
        );
        write_terminal(&mut image, TERMINAL_SLOT, 0x33);
        image.ensure(IMAGE_END);
        let raw = image.bytes;
        let runtime = raw_image(&raw);

        let task = |index: u32,
                    slot: u32,
                    name_pointer: u32,
                    name: &str,
                    label: &str,
                    entry: u32,
                    size: u8,
                    priority: u8,
                    stack_size: u32| TaskRecord {
            index,
            slot,
            slot_blake3: runtime.hash_range(slot, STRIDE).unwrap(),
            name_pointer,
            name: name.to_string(),
            task_label: label.to_string(),
            priority,
            stack_size,
            entry_pointer: entry | 1,
            entry,
            isa: TaskIsa::Thumb,
            instruction_size: size,
            instruction_blake3: runtime.hash_range(entry, u32::from(size)).unwrap(),
            callback: 0,
            unknown_pointer: 0,
            slot_storage: runtime.storage_spans(slot, STRIDE).unwrap(),
            name_storage: runtime
                .storage_spans(name_pointer, u32::try_from(name.len()).unwrap() + 1)
                .unwrap(),
            entry_storage: runtime.storage_spans(entry, u32::from(size)).unwrap(),
        };
        let tasks = vec![
            task(
                0, SLOT_ALPHA, NAME_DOT, "al.pha", &label_a, ENTRY_A, 2, 100, 0x200,
            ),
            task(
                1,
                SLOT_BETA,
                NAME_DASHES,
                "al--pha",
                &label_b,
                ENTRY_B,
                4,
                0xff,
                0x80e8,
            ),
        ];
        let application = |entry: u32, label: &str, index: u32| TaskApplication {
            entry,
            isa: TaskIsa::Thumb,
            desired_primary: label.to_string(),
            task_indices: vec![index],
            labels: vec![TaskLabelApplication {
                label: label.to_string(),
                task_indices: vec![index],
            }],
        };
        let applications = vec![
            application(ENTRY_A, &label_a, 0),
            application(ENTRY_B, &label_b, 1),
        ];
        let plan = synthetic_frame(&runtime, tasks, applications);

        let context = raw_context(*blake3::hash(&raw).as_bytes());
        let root = tempdir().unwrap();
        materialize(&plan, context, root.path()).unwrap();

        let artifact: ValidatedTaskArtifact =
            read(&manifest_path(root.path()), &runtime, context).unwrap();

        assert_eq!(artifact.plan.tasks[0].task_label, label_a);
        assert_eq!(artifact.plan.tasks[1].task_label, label_b);
        assert_eq!(artifact.plan.applications[0].desired_primary, label_a);
        assert_eq!(artifact.plan.applications[1].desired_primary, label_b);
        assert_eq!(artifact.plan, plan);
    }

    #[test]
    fn reader_revalidates_scatter_provenance_and_used_entry_union() {
        let (_raw, runtime, image_blake3) = scatter_fixture();
        let plan = synthetic_plan(&runtime);
        let context = scatter_context(image_blake3);
        let root = tempdir().unwrap();

        let map = materialize(&plan, context, root.path()).unwrap();
        assert_eq!(map.task_records, 2);
        assert_eq!(map.distinct_entries, 3);
        assert_eq!(map.identity, format!("v1:{}:2:3", map.blake3));

        let artifact = read(&manifest_path(root.path()), &runtime, context).unwrap();
        assert_eq!(artifact.identity, map.identity);
        assert_eq!(artifact.scatter_load_map_blake3, Some(SCATTER_MAP_BLAKE3));
        assert_eq!(artifact.plan, plan);
        // The slot-0 record keeps all three provenance spans across the
        // byte/zero/byte scatter boundary.
        assert_eq!(
            artifact.plan.tasks[0].slot_storage,
            vec![
                StorageSpan {
                    kind: StorageKind::ScatterBytes,
                    address: SLOT_BASE,
                    size: 8,
                    scatter_entry: Some(0),
                },
                StorageSpan {
                    kind: StorageKind::ScatterZero,
                    address: SLOT_BASE + 8,
                    size: 0x38,
                    scatter_entry: Some(1),
                },
                StorageSpan {
                    kind: StorageKind::ScatterBytes,
                    address: SLOT_BASE + 0x40,
                    size: STRIDE - 0x40,
                    scatter_entry: Some(2),
                },
            ]
        );

        // Nullability is part of the dependency identity: neither side may
        // drift between Some and None.
        assert_rejected(
            &manifest_path(root.path()),
            &runtime,
            &TaskArtifactContext {
                label: "02_MAIN",
                image_blake3,
                scatter_load_map_blake3: None,
            },
            "scatter",
        );
        let (raw_only, raw_runtime) = raw_fixture();
        let raw_root = tempdir().unwrap();
        materialized_raw(raw_root.path());
        assert_rejected(
            &manifest_path(raw_root.path()),
            &raw_runtime,
            &TaskArtifactContext {
                label: "02_MAIN",
                image_blake3: *blake3::hash(&raw_only).as_bytes(),
                scatter_load_map_blake3: Some(SCATTER_MAP_BLAKE3),
            },
            "scatter",
        );
    }

    #[test]
    fn strict_reader_rejects_structural_policy_and_metadata_tampering() {
        let (raw, runtime) = raw_fixture();
        let context = raw_context(*blake3::hash(&raw).as_bytes());
        let canonical = {
            let root = tempdir().unwrap();
            materialized_raw(root.path())
        };
        let zeros64 = "0".repeat(64);
        let mutations: Vec<(&str, Vec<u8>, &str)> = vec![
            (
                "unknown top-level field",
                replace_once(
                    &canonical,
                    "\"format\": \"pixel-modem-extractor-pal-tasks-v1\",",
                    "\"format\": \"pixel-modem-extractor-pal-tasks-v1\",\n  \"unexpected\": true,",
                ),
                "unexpected",
            ),
            (
                "missing tool_version",
                replace_once(
                    &canonical,
                    "\"pixel-modem-extractor-pal-tasks-v1\",\n  \"schema_version\": 1,\n  \"tool_version\": \"2.0.0\",",
                    "\"pixel-modem-extractor-pal-tasks-v1\",\n  \"schema_version\": 1,",
                ),
                "tool_version",
            ),
            (
                "duplicate tool_version",
                replace_once(
                    &canonical,
                    "\"tool_version\": \"2.0.0\",",
                    "\"tool_version\": \"2.0.0\",\n  \"tool_version\": \"2.0.0\",",
                ),
                "tool_version",
            ),
            (
                "out-of-order image fields",
                replace_once(
                    &canonical,
                    "\"label\": \"02_MAIN\",\n    \"base_addr\": \"0x00001000\",",
                    "\"base_addr\": \"0x00001000\",\n    \"label\": \"02_MAIN\",",
                ),
                "label",
            ),
            (
                "wrong format name",
                replace_once(
                    &canonical,
                    "pixel-modem-extractor-pal-tasks-v1",
                    "pixel-modem-extractor-pal-tasks-v2",
                ),
                "format",
            ),
            (
                "wrong schema version",
                replace_once(&canonical, "\"schema_version\": 1", "\"schema_version\": 2"),
                "schema_version",
            ),
            (
                "wrong decoder backend version",
                replace_once(
                    &canonical,
                    "\"backend_version\": \"2.0.0\"",
                    "\"backend_version\": \"9.9.9\"",
                ),
                "backend_version",
            ),
            (
                "wrong image blake3",
                replace_once(&canonical, &hex(*blake3::hash(&raw).as_bytes()), &zeros64),
                "image BLAKE3",
            ),
            (
                "wrong slot blake3",
                replace_once(
                    &canonical,
                    &hex(runtime.hash_range(SLOT_ALPHA, STRIDE).unwrap()),
                    &zeros64,
                ),
                "slot BLAKE3",
            ),
            (
                "wrong terminal blake3",
                replace_once(
                    &canonical,
                    &hex(runtime.hash_range(TERMINAL_SLOT, STRIDE).unwrap()),
                    &zeros64,
                ),
                "terminal BLAKE3",
            ),
            (
                "wrong slot storage address",
                replace_once(
                    &canonical,
                    "\"slot_storage\": [\n        {\n          \"kind\": \"raw\",\n          \"address\": \"0x00002000\",",
                    "\"slot_storage\": [\n        {\n          \"kind\": \"raw\",\n          \"address\": \"0x00002001\",",
                ),
                "slot storage",
            ),
            (
                "wrong scatter used-entry union",
                replace_once(
                    &canonical,
                    "\"scatter_entries_used\": []",
                    "\"scatter_entries_used\": [0]",
                ),
                "scatter_entries_used",
            ),
            (
                "unsafe image label",
                replace_once(&canonical, "\"label\": \"02_MAIN\"", "\"label\": \"a/b\""),
                "label",
            ),
            (
                "wrong task count",
                replace_once(&canonical, "\"count\": 2", "\"count\": 3"),
                "task count",
            ),
            (
                "unmapped initializer cfg_entry",
                replace_once(
                    &canonical,
                    "\"cfg_entry\": \"0x00001000\"",
                    "\"cfg_entry\": \"0x90000000\"",
                ),
                "cfg_entry",
            ),
            (
                "wrong capacity guard branch target",
                replace_once(
                    &canonical,
                    "\"branch\": \"0x0000101c\"",
                    "\"branch\": \"0x00001024\"",
                ),
                "capacity guard",
            ),
            (
                "tampered desired primary",
                replace_once(
                    &canonical,
                    "\"desired_primary\": \"pal_TaskEntry_alpha\"",
                    "\"desired_primary\": \"pal_TaskEntry_beta\"",
                ),
                "primary",
            ),
            (
                "dropped application label",
                replace_once(
                    &canonical,
                    "\"labels\": [\n        {\n          \"label\": \"pal_TaskEntry_alpha\",\n          \"task_indices\": [\n            0\n          ]\n        }\n      ]",
                    "\"labels\": []",
                ),
                "label",
            ),
        ];
        for (name, bytes, reason) in mutations {
            let root = tempdir().unwrap();
            let path = write_manifest(&root, &bytes);
            eprintln!("reader rejection case: {name}");
            assert_rejected(&path, &runtime, &context, reason);
        }

        // Wrong supplied metadata is rejected even against canonical bytes.
        let root = tempdir().unwrap();
        let path = write_manifest(&root, &canonical);
        assert_rejected(
            &path,
            &runtime,
            &TaskArtifactContext {
                label: "03_DSP",
                image_blake3: context.image_blake3,
                scatter_load_map_blake3: None,
            },
            "label",
        );
        assert_rejected(
            &path,
            &runtime,
            &TaskArtifactContext {
                label: "02_MAIN",
                image_blake3: [9; 32],
                scatter_load_map_blake3: None,
            },
            "image BLAKE3",
        );
    }

    #[cfg(unix)]
    #[test]
    fn reader_rejects_oversized_symlinked_and_non_regular_files() {
        let (raw, runtime) = raw_fixture();
        let context = raw_context(*blake3::hash(&raw).as_bytes());
        let canonical = {
            let root = tempdir().unwrap();
            materialized_raw(root.path())
        };

        let oversized = {
            let mut bytes = canonical.clone();
            bytes.extend(std::iter::repeat_n(b' ', 4 * 1024 * 1024 + 1));
            bytes
        };
        let root = tempdir().unwrap();
        let path = write_manifest(&root, &oversized);
        assert_rejected(&path, &runtime, &context, "4 MiB");

        let root = tempdir().unwrap();
        fs::create_dir_all(manifest_path(root.path()).parent().unwrap()).unwrap();
        let external = tempdir().unwrap();
        fs::write(external.path().join("tasks.json"), &canonical).unwrap();
        std::os::unix::fs::symlink(
            external.path().join("tasks.json"),
            manifest_path(root.path()),
        )
        .unwrap();
        assert_rejected(&manifest_path(root.path()), &runtime, &context, "symlink");

        let root = tempdir().unwrap();
        fs::create_dir_all(manifest_path(root.path())).unwrap();
        assert_rejected(&manifest_path(root.path()), &runtime, &context, "regular");
    }

    #[cfg(unix)]
    #[test]
    fn publication_failure_before_commit_preserves_old_complete_bytes() {
        use std::os::unix::fs::PermissionsExt;

        let (raw, runtime) = raw_fixture();
        let plan = synthetic_plan(&runtime);
        let image_blake3 = *blake3::hash(&raw).as_bytes();
        let root = tempdir().unwrap();
        materialize(&plan, raw_context(image_blake3), root.path()).unwrap();
        let old_bytes = fs::read(manifest_path(root.path())).unwrap();
        let label_dir = manifest_path(root.path()).parent().unwrap().to_path_buf();
        let hook_dir = label_dir.clone();
        super::set_before_commit(move || {
            // Before commit the destination still carries the complete old
            // bytes, and a failed rename leaves them intact.
            assert_eq!(fs::read(hook_dir.join("tasks.json")).unwrap(), old_bytes);
            fs::set_permissions(&hook_dir, fs::Permissions::from_mode(0o500)).unwrap();
        });

        let altered = raw_context([7; 32]);
        let failed = materialize(&plan, altered, root.path());
        fs::set_permissions(&label_dir, fs::Permissions::from_mode(0o700)).unwrap();

        assert!(matches!(failed, Err(PalTaskError::Artifact(_))));
        assert_eq!(fs::read(manifest_path(root.path())).unwrap(), {
            let root = tempdir().unwrap();
            materialized_raw(root.path())
        });
    }

    #[cfg(unix)]
    #[test]
    fn new_bytes_appear_only_after_commit() {
        let (raw, runtime) = raw_fixture();
        let plan = synthetic_plan(&runtime);
        let context = raw_context(*blake3::hash(&raw).as_bytes());
        let root = tempdir().unwrap();
        let target = manifest_path(root.path());
        super::set_before_commit(move || {
            assert!(!target.exists(), "destination visible before commit");
        });

        let map = materialize(&plan, context, root.path()).unwrap();

        let bytes = fs::read(manifest_path(root.path())).unwrap();
        assert_eq!(bytes, PINNED_RAW_MANIFEST.as_bytes());
        assert_eq!(hex(*blake3::hash(&bytes).as_bytes()), map.blake3);
    }

    #[cfg(unix)]
    #[test]
    fn materialize_rejects_symlinked_directories_and_destinations() {
        let (raw, runtime) = raw_fixture();
        let plan = synthetic_plan(&runtime);
        let context = raw_context(*blake3::hash(&raw).as_bytes());

        let root = tempdir().unwrap();
        let external = tempdir().unwrap();
        fs::create_dir_all(external.path().join("02_MAIN")).unwrap();
        fs::write(external.path().join("02_MAIN/keep.bin"), b"external").unwrap();
        std::os::unix::fs::symlink(external.path(), root.path().join("pal_tasks")).unwrap();
        assert!(matches!(
            materialize(&plan, context, root.path()),
            Err(PalTaskError::Artifact(_))
        ));
        assert!(external.path().join("02_MAIN/keep.bin").exists());

        let root = tempdir().unwrap();
        fs::create_dir_all(root.path().join("pal_tasks")).unwrap();
        std::os::unix::fs::symlink(
            external.path().join("02_MAIN"),
            root.path().join("pal_tasks/02_MAIN"),
        )
        .unwrap();
        assert!(matches!(
            materialize(&plan, context, root.path()),
            Err(PalTaskError::Artifact(_))
        ));

        let root = tempdir().unwrap();
        fs::create_dir_all(root.path().join("pal_tasks")).unwrap();
        fs::write(root.path().join("pal_tasks/02_MAIN"), b"not a directory").unwrap();
        assert!(matches!(
            materialize(&plan, context, root.path()),
            Err(PalTaskError::Artifact(_))
        ));

        let root = tempdir().unwrap();
        fs::create_dir_all(root.path().join("pal_tasks/02_MAIN")).unwrap();
        let manifest = manifest_path(root.path());
        let outside = tempdir().unwrap();
        fs::write(outside.path().join("victim"), b"victim").unwrap();
        std::os::unix::fs::symlink(outside.path().join("victim"), &manifest).unwrap();
        assert!(matches!(
            materialize(&plan, context, root.path()),
            Err(PalTaskError::Artifact(_))
        ));
        assert_eq!(fs::read(outside.path().join("victim")).unwrap(), b"victim");
    }

    #[test]
    fn clear_removes_only_the_owned_file_and_empty_directory() {
        let root = tempdir().unwrap();
        let (_raw, runtime) = raw_fixture();
        let plan = synthetic_plan(&runtime);
        materialize(
            &plan,
            raw_context(*blake3::hash(&_raw).as_bytes()),
            root.path(),
        )
        .unwrap();
        let sibling = root.path().join("pal_tasks/03_DSP");
        fs::create_dir_all(&sibling).unwrap();
        fs::write(sibling.join("keep.bin"), b"keep").unwrap();

        clear_materialized(root.path(), "02_MAIN").unwrap();

        assert!(!manifest_path(root.path()).exists());
        assert!(!root.path().join("pal_tasks/02_MAIN").exists());
        assert!(sibling.join("keep.bin").exists());
        // Absence is idempotent and succeeds with no directory at all.
        clear_materialized(root.path(), "02_MAIN").unwrap();
        let empty = tempdir().unwrap();
        clear_materialized(empty.path(), "02_MAIN").unwrap();

        // A label directory with foreign content loses only the owned file.
        let root = tempdir().unwrap();
        materialize(
            &plan,
            raw_context(*blake3::hash(&_raw).as_bytes()),
            root.path(),
        )
        .unwrap();
        fs::write(
            root.path().join("pal_tasks/02_MAIN/foreign.bin"),
            b"foreign",
        )
        .unwrap();
        clear_materialized(root.path(), "02_MAIN").unwrap();
        assert!(!manifest_path(root.path()).exists());
        assert!(root.path().join("pal_tasks/02_MAIN/foreign.bin").exists());
    }

    #[test]
    fn clear_rejects_unsafe_labels() {
        let root = tempdir().unwrap();
        for label in ["", ".", "..", "a/b", "a\\b", "a b", "$(id)", "\u{e9}"] {
            assert!(
                matches!(
                    clear_materialized(root.path(), label),
                    Err(PalTaskError::Artifact(_))
                ),
                "clear accepted {label:?}"
            );
        }
        assert!(!root.path().join("pal_tasks").exists());
    }

    #[cfg(unix)]
    #[test]
    fn clear_never_turns_wrong_or_symlink_metadata_into_absence() {
        let root = tempdir().unwrap();
        let label_dir = root.path().join("pal_tasks/02_MAIN");
        fs::create_dir_all(&label_dir).unwrap();
        let outside = tempdir().unwrap();
        fs::write(outside.path().join("victim"), b"victim").unwrap();
        std::os::unix::fs::symlink(outside.path().join("victim"), label_dir.join("tasks.json"))
            .unwrap();

        assert!(matches!(
            clear_materialized(root.path(), "02_MAIN"),
            Err(PalTaskError::Artifact(_))
        ));
        assert_eq!(fs::read(outside.path().join("victim")).unwrap(), b"victim");
        assert!(
            fs::symlink_metadata(label_dir.join("tasks.json"))
                .unwrap()
                .file_type()
                .is_symlink()
        );

        let root = tempdir().unwrap();
        fs::create_dir_all(root.path().join("pal_tasks/02_MAIN/tasks.json")).unwrap();
        assert!(matches!(
            clear_materialized(root.path(), "02_MAIN"),
            Err(PalTaskError::Artifact(_))
        ));

        let root = tempdir().unwrap();
        let external = tempdir().unwrap();
        fs::create_dir_all(external.path().join("02_MAIN")).unwrap();
        fs::write(external.path().join("02_MAIN/keep.bin"), b"external").unwrap();
        fs::create_dir_all(root.path().join("pal_tasks")).unwrap();
        std::os::unix::fs::symlink(
            external.path().join("02_MAIN"),
            root.path().join("pal_tasks/02_MAIN"),
        )
        .unwrap();
        assert!(matches!(
            clear_materialized(root.path(), "02_MAIN"),
            Err(PalTaskError::Artifact(_))
        ));
        assert!(external.path().join("02_MAIN/keep.bin").exists());
    }

    /// The execution grammar shared with Task 2 and the Java support:
    /// BLAKE3 over ASCII `pixel-modem-extractor-execution-v1\0`,
    /// little-endian u32 entry, little-endian u32 range count, then each
    /// canonical range as ISA byte 0=ARM/1=Thumb, little-endian u32
    /// start/end, and the 32 decoded range-digest bytes. The sample frames
    /// entry 0x40010400 with one Thumb range [0x40010400,0x40010404) whose
    /// four bytes [1,2,3,4] hash to the pinned range digest.
    #[test]
    fn execution_digest_vector_is_pinned() {
        let mut framed = Vec::new();
        framed.extend_from_slice(b"pixel-modem-extractor-execution-v1\0");
        framed.extend_from_slice(&0x4001_0400u32.to_le_bytes());
        framed.extend_from_slice(&1u32.to_le_bytes());
        let range_digest = *blake3::hash(&[1u8, 2, 3, 4]).as_bytes();
        framed.push(1);
        framed.extend_from_slice(&0x4001_0400u32.to_le_bytes());
        framed.extend_from_slice(&0x4001_0404u32.to_le_bytes());
        framed.extend_from_slice(&range_digest);

        assert_eq!(
            hex(range_digest),
            "63781d171425a36312fa058d8712d5d05135a991ec20351ce9d65cdb19a05432"
        );
        assert_eq!(
            hex(*blake3::hash(&framed).as_bytes()),
            "1383ca88fa4bb8d58aedbac50f7e298be9dd15ad8553eb565ac14848cfd771dd"
        );
    }

    /// The label-set grammar: BLAKE3 over ASCII
    /// `pixel-modem-extractor-pal-labels-v1\0`, little-endian u32 label
    /// count, then each label sorted by (leaf, symbol-id) as little-endian
    /// u64 symbol ID, little-endian u32 UTF-8 byte length, and the exact
    /// ASCII leaf bytes. The sample frames `pal_TaskEntry_alpha` under
    /// symbol ID 7 and `pal_TaskEntry_beta` under symbol ID 3.
    #[test]
    fn label_set_digest_vector_is_pinned() {
        let mut framed = Vec::new();
        framed.extend_from_slice(b"pixel-modem-extractor-pal-labels-v1\0");
        framed.extend_from_slice(&2u32.to_le_bytes());
        framed.extend_from_slice(&7u64.to_le_bytes());
        framed.extend_from_slice(&19u32.to_le_bytes());
        framed.extend_from_slice(b"pal_TaskEntry_alpha");
        framed.extend_from_slice(&3u64.to_le_bytes());
        framed.extend_from_slice(&18u32.to_le_bytes());
        framed.extend_from_slice(b"pal_TaskEntry_beta");

        assert_eq!(
            hex(*blake3::hash(&framed).as_bytes()),
            "77747c233b288a5f01b755c5307f19f190fc342952891c39f5bd813923a27052"
        );
    }

    /// The primary-name grammar: BLAKE3 over ASCII
    /// `pixel-modem-extractor-pal-primary-v1\0`, little-endian u32 UTF-8
    /// byte length, and the exact primary-name bytes. The sample frames
    /// the 19-byte name `pal_TaskEntry_alpha`.
    #[test]
    fn primary_name_digest_vector_is_pinned() {
        let mut framed = Vec::new();
        framed.extend_from_slice(b"pixel-modem-extractor-pal-primary-v1\0");
        framed.extend_from_slice(&19u32.to_le_bytes());
        framed.extend_from_slice(b"pal_TaskEntry_alpha");

        assert_eq!(
            hex(*blake3::hash(&framed).as_bytes()),
            "8538942936387e769666d449ac837a35a0c7bbeac557c8e2467bc7b75bf0edba"
        );
    }

    /// The owned-comment grammar: BLAKE3 over ASCII
    /// `pixel-modem-extractor-pal-comment-v1\0`, little-endian u32
    /// section-byte length, and the exact section bytes from the first
    /// `[` of the opening marker through the last `]` of the closing
    /// marker. The section uses literal LF between canonical lines and no
    /// terminal newline. The sample frames one task record attached to a
    /// manifest with the all-hex placeholder digest.
    #[test]
    fn owned_comment_digest_vector_is_pinned() {
        let manifest = "0123456789abcdef".repeat(4);
        let section = format!(
            "[[pixel-modem-extractor:pal-tasks:v1]]\nmanifest={manifest} tasks=1\n\
             task index=0 name=\"alpha\" slot=0x40010800 priority=30 stack=4096\n\
             [[/pixel-modem-extractor:pal-tasks:v1]]"
        );
        let mut framed = Vec::new();
        framed.extend_from_slice(b"pixel-modem-extractor-pal-comment-v1\0");
        framed.extend_from_slice(&u32::try_from(section.len()).unwrap().to_le_bytes());
        framed.extend_from_slice(section.as_bytes());

        assert_eq!(section.as_bytes().last(), Some(&b']'));
        assert!(!section.ends_with('\n'));
        assert_eq!(
            hex(*blake3::hash(&framed).as_bytes()),
            "dcf724f43e1550d495b847e96e2ce17d00eb4674fb988a908f2e956142550c2b"
        );
    }
}
