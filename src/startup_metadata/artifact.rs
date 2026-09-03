use super::{
    CompilerMeta, FORMAT, HardwareInit, MAX_APPLICATIONS, MAX_MANIFEST_BYTES, MAX_PRIVILEGED_OPS,
    MAX_SYMBOL_LEAF_BYTES, PrivilegedClass, PrivilegedOp, Section, StackGuard, StartupApplication,
    StartupMetadataError, StartupPlan, StartupRole,
};
use crate::analysis_tool::AnalysisTool;
use crate::arm32::{InstructionDecoder, PureRustDecoder, SystemDirection};
use crate::execution_ranges::{DecodeIsa, FunctionOwner};
use crate::runtime_image::RuntimeImage;
use crate::trusted_fs::{TrustedDirectory, validate_relative_path};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::path::Path;

const SCHEMA_VERSION: u32 = 1;
const ARTIFACT_DIR_NAME: &str = "startup_metadata";
const ARTIFACT_FILE_NAME: &str = "startup.json";
const MAX_PATH_COMPONENT_BYTES: usize = 255;
const WINDOWS_RESERVED_DEVICE_NAMES: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

type Result<T> = std::result::Result<T, StartupMetadataError>;

#[derive(Debug, Clone, Copy)]
pub(crate) struct StartupArtifactContext<'a> {
    pub label: &'a str,
    pub toc_name: &'a str,
    pub image_base: u32,
    pub image_size: u32,
    pub image_blake3: [u8; 32],
    pub scatter_blake3: Option<[u8; 32]>,
    pub scatter_entries: &'a [u32],
    pub functions_blake3: [u8; 32],
    pub thumb_functions_blake3: Option<[u8; 32]>,
    pub exception_identity: Option<&'a str>,
    pub tool_version: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MaterializedStartup {
    pub relative_path: String,
    pub blake3: String,
    pub identity: String,
    pub named_roots: usize,
    pub no_return_roots: usize,
    pub privileged_ops: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValidatedStartup {
    pub plan: StartupPlan,
    pub manifest_blake3: [u8; 32],
    pub identity: String,
    pub image_label: String,
    pub toc_name: String,
    pub image_blake3: [u8; 32],
    pub scatter_blake3: Option<[u8; 32]>,
    pub functions_blake3: [u8; 32],
    pub thumb_functions_blake3: Option<[u8; 32]>,
    pub exception_identity: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireManifest {
    format: String,
    schema_version: u32,
    tool_version: String,
    image: WireImage,
    runtime: WireRuntime,
    inventories: WireInventories,
    decoder: WireDecoder,
    exception_roots: Option<String>,
    hardware_init: WireHardwareInit,
    stack_guard: WireStackGuard,
    compiler: WireCompiler,
    privileged_ops: Vec<WirePrivilegedOp>,
    applications: Vec<WireApplication>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireImage {
    label: String,
    toc_name: String,
    base_addr: String,
    size: u32,
    blake3: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRuntime {
    scatter_load_map_blake3: Option<String>,
    scatter_entries_used: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireInventories {
    functions_blake3: String,
    thumb_functions_blake3: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireDecoder {
    #[serde(rename = "crate")]
    crate_name: String,
    version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status")]
enum WireHardwareInit {
    #[serde(rename = "absent")]
    Absent,
    #[serde(rename = "present")]
    Present {
        entry: String,
        isa: String,
        owner: WireOwner,
        execution_blake3: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status")]
enum WireStackGuard {
    #[serde(rename = "absent")]
    Absent,
    #[serde(rename = "present")]
    Present {
        entry: String,
        isa: String,
        owner: WireOwner,
        execution_blake3: String,
        non_return: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status")]
enum WireCompiler {
    #[serde(rename = "absent")]
    Absent,
    #[serde(rename = "present")]
    Present {
        format_address: String,
        format_len: u32,
        format_blake3: String,
        callsite_pc: String,
        isa: String,
        operands: Vec<u32>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePrivilegedOp {
    pc: String,
    isa: String,
    entry: String,
    owner: WireOwner,
    execution_blake3: String,
    direction: String,
    class: String,
    coprocessor: Option<u8>,
    opcode1: Option<u8>,
    crn: Option<u8>,
    crm: Option<u8>,
    opcode2: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
enum WireOwner {
    #[serde(rename = "ghidra")]
    Ghidra,
    #[serde(rename = "legacy")]
    Legacy { producer: AnalysisTool },
    #[serde(rename = "run")]
    Run {
        producer: AnalysisTool,
        region_index: usize,
        run_index: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireApplication {
    role: String,
    entry: String,
    isa: String,
    desired_primary: String,
    role_label: String,
    set_no_return: bool,
}

pub(crate) fn materialize(
    plan: &StartupPlan,
    context: StartupArtifactContext<'_>,
    root: &Path,
) -> Result<MaterializedStartup> {
    let bytes = serialize(plan, &context)?;
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(invalid(format!(
            "serialized manifest is {} bytes, above the {MAX_MANIFEST_BYTES}-byte ceiling",
            bytes.len()
        )));
    }

    let trusted_root =
        TrustedDirectory::new(root, "artifact root").map_err(|error| invalid(error.to_string()))?;
    let startup_dir = trusted_root
        .open_or_create_directory_child(ARTIFACT_DIR_NAME, "artifact startup_metadata directory")
        .map_err(|error| invalid(error.to_string()))?;
    let label_dir = startup_dir
        .open_or_create_directory_child(context.label, "artifact label directory")
        .map_err(|error| invalid(error.to_string()))?;

    let manifest_blake3 = *blake3::hash(&bytes).as_bytes();
    let mut file = label_dir
        .atomic_write_file(ARTIFACT_FILE_NAME, "manifest destination")
        .map_err(|error| invalid(format!("atomic manifest publication failed: {error}")))?;
    file.write_all(&bytes)
        .map_err(|error| invalid(format!("atomic manifest write failed: {error}")))?;
    run_before_commit()?;
    file.commit()
        .map_err(|error| invalid(format!("atomic manifest commit failed: {error}")))?;

    let (named_roots, no_return_roots, privileged_ops) = identity_counts(plan)?;
    Ok(MaterializedStartup {
        relative_path: format!("{ARTIFACT_DIR_NAME}/{}/{ARTIFACT_FILE_NAME}", context.label),
        blake3: blake3_hex(manifest_blake3),
        identity: identity(
            manifest_blake3,
            named_roots,
            no_return_roots,
            privileged_ops,
        ),
        named_roots,
        no_return_roots,
        privileged_ops,
    })
}

pub(crate) fn materialize_image(
    plan: &StartupPlan,
    context: StartupArtifactContext<'_>,
    image_dir: &Path,
) -> Result<MaterializedStartup> {
    let bytes = serialize(plan, &context)?;
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(invalid(format!(
            "serialized manifest is {} bytes, above the {MAX_MANIFEST_BYTES}-byte ceiling",
            bytes.len()
        )));
    }

    let trusted_image = TrustedDirectory::new(image_dir, "artifact image directory")
        .map_err(|error| invalid(error.to_string()))?;
    let startup_dir = trusted_image
        .open_or_create_directory_child(ARTIFACT_DIR_NAME, "artifact startup_metadata directory")
        .map_err(|error| invalid(error.to_string()))?;

    let manifest_blake3 = *blake3::hash(&bytes).as_bytes();
    let mut file = startup_dir
        .atomic_write_file(ARTIFACT_FILE_NAME, "manifest destination")
        .map_err(|error| invalid(format!("atomic manifest publication failed: {error}")))?;
    file.write_all(&bytes)
        .map_err(|error| invalid(format!("atomic manifest write failed: {error}")))?;
    run_before_commit()?;
    file.commit()
        .map_err(|error| invalid(format!("atomic manifest commit failed: {error}")))?;

    let (named_roots, no_return_roots, privileged_ops) = identity_counts(plan)?;
    Ok(MaterializedStartup {
        relative_path: format!("{ARTIFACT_DIR_NAME}/{ARTIFACT_FILE_NAME}"),
        blake3: blake3_hex(manifest_blake3),
        identity: identity(
            manifest_blake3,
            named_roots,
            no_return_roots,
            privileged_ops,
        ),
        named_roots,
        no_return_roots,
        privileged_ops,
    })
}

pub(crate) fn clear_materialized(root: &Path, label: &str) -> Result<()> {
    validate_label(label, "artifact label")?;
    let Some(trusted_root) = TrustedDirectory::open_existing(root, "artifact root")
        .map_err(|error| invalid(error.to_string()))?
    else {
        return Ok(());
    };
    let Some(startup_dir) = trusted_root
        .open_directory_child(ARTIFACT_DIR_NAME, "artifact startup_metadata directory")
        .map_err(|error| invalid(error.to_string()))?
    else {
        return Ok(());
    };
    let Some(label_dir) = startup_dir
        .open_directory_child(label, "owned label directory")
        .map_err(|error| invalid(error.to_string()))?
    else {
        return Ok(());
    };
    label_dir
        .unlink_regular_file_if_exists(ARTIFACT_FILE_NAME, "owned manifest")
        .map_err(|error| invalid(error.to_string()))?;
    Ok(())
}

pub(crate) fn clear_image(image_dir: &Path) -> Result<()> {
    let Some(trusted_image) =
        TrustedDirectory::open_existing(image_dir, "artifact image directory")
            .map_err(|error| invalid(error.to_string()))?
    else {
        return Ok(());
    };
    let Some(startup_dir) = trusted_image
        .open_directory_child(ARTIFACT_DIR_NAME, "artifact startup_metadata directory")
        .map_err(|error| invalid(error.to_string()))?
    else {
        return Ok(());
    };
    startup_dir
        .unlink_regular_file_if_exists(ARTIFACT_FILE_NAME, "owned manifest")
        .map_err(|error| invalid(error.to_string()))?;
    Ok(())
}

pub(crate) fn read(
    path: &Path,
    runtime: &RuntimeImage<'_>,
    expected: StartupArtifactContext<'_>,
) -> Result<ValidatedStartup> {
    validate_label(expected.label, "artifact label")?;
    validate_label(expected.toc_name, "artifact TOC name")?;
    let mut file = open_manifest_file(path, expected.label)?;
    let bytes = read_manifest_bytes(&mut file)?;
    read_bytes(&bytes, runtime, expected)
}

pub(crate) fn read_from_trusted(
    root: &TrustedDirectory,
    manifest_relative: &Path,
    runtime: &RuntimeImage<'_>,
    expected: StartupArtifactContext<'_>,
) -> Result<ValidatedStartup> {
    validate_label(expected.label, "artifact label")?;
    validate_label(expected.toc_name, "artifact TOC name")?;
    validate_relative_path(manifest_relative, "startup metadata manifest")
        .map_err(|error| invalid(error.to_string()))?;
    if manifest_relative.file_name().and_then(|name| name.to_str()) != Some(ARTIFACT_FILE_NAME) {
        return Err(invalid("manifest file name is not startup.json"));
    }
    let parent = manifest_relative
        .parent()
        .ok_or_else(|| invalid("manifest path has no parent directory"))?;
    if parent.file_name().and_then(|name| name.to_str()) != Some(expected.label) {
        return Err(invalid(
            "manifest label directory does not match the expected image label",
        ));
    }
    let startup_dir = parent
        .parent()
        .ok_or_else(|| invalid("manifest path has no startup_metadata directory"))?;
    if startup_dir.file_name().and_then(|name| name.to_str()) != Some(ARTIFACT_DIR_NAME) {
        return Err(invalid("manifest path escapes startup_metadata/<label>"));
    }
    let (mut file, _parent) = root
        .open_regular_file_with_parent(manifest_relative, "startup metadata manifest")
        .map_err(|error| invalid(error.to_string()))?;
    let bytes = read_manifest_bytes(&mut file)?;
    read_bytes(&bytes, runtime, expected)
}

pub(crate) fn read_bytes(
    bytes: &[u8],
    runtime: &RuntimeImage<'_>,
    expected: StartupArtifactContext<'_>,
) -> Result<ValidatedStartup> {
    validate_label(expected.label, "artifact label")?;
    validate_label(expected.toc_name, "artifact TOC name")?;
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(invalid(
            "manifest exceeds the 1 MiB ceiling and is rejected before parsing",
        ));
    }
    let wire: WireManifest = serde_json::from_slice(bytes)
        .map_err(|error| invalid(format!("manifest schema is invalid: {error}")))?;
    let canonical = canonical_bytes(&wire)?;
    if canonical.as_slice() != bytes {
        return Err(invalid(
            "manifest bytes are not in the canonical field order or JSON spelling",
        ));
    }
    let manifest_blake3 = *blake3::hash(bytes).as_bytes();
    revalidate(wire, runtime, &expected, manifest_blake3)
}

fn serialize(plan: &StartupPlan, context: &StartupArtifactContext<'_>) -> Result<Vec<u8>> {
    let wire = WireManifest::from_plan(plan, context)?;
    canonical_bytes(&wire)
}

fn canonical_bytes(wire: &WireManifest) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(wire)
        .map_err(|error| invalid(format!("manifest serialization failed: {error}")))?;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    Ok(bytes)
}

fn read_manifest_bytes(file: &mut File) -> Result<Vec<u8>> {
    let length = file
        .metadata()
        .map_err(|error| invalid(format!("manifest metadata is unavailable: {error}")))?
        .len();
    if length > MAX_MANIFEST_BYTES as u64 {
        return Err(invalid(
            "manifest exceeds the 1 MiB ceiling and is rejected before parsing",
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
    Ok(bytes)
}

fn revalidate(
    wire: WireManifest,
    runtime: &RuntimeImage<'_>,
    expected: &StartupArtifactContext<'_>,
    manifest_blake3: [u8; 32],
) -> Result<ValidatedStartup> {
    if wire.format != FORMAT {
        return Err(invalid("unexpected startup-metadata manifest format"));
    }
    if wire.schema_version != SCHEMA_VERSION {
        return Err(invalid(
            "unsupported startup-metadata manifest schema_version",
        ));
    }
    if wire.tool_version != env!("CARGO_PKG_VERSION") || wire.tool_version != expected.tool_version
    {
        return Err(invalid(
            "manifest tool_version does not match the compiled crate",
        ));
    }
    validate_label(&wire.image.label, "image label")?;
    validate_label(&wire.image.toc_name, "image TOC name")?;
    if wire.image.label != expected.label || wire.image.toc_name != expected.toc_name {
        return Err(invalid(
            "manifest image identity does not match the expected artifact context",
        ));
    }
    let image_base = parse_address(&wire.image.base_addr, "image base_addr")?;
    if image_base != expected.image_base || wire.image.size != expected.image_size {
        return Err(invalid(
            "image base or size does not match the expected artifact context",
        ));
    }
    if runtime.image_bounds() != (image_base, wire.image.size) {
        return Err(invalid(
            "image base or size does not match the runtime image",
        ));
    }
    let image_blake3 = parse_blake3(&wire.image.blake3, "image blake3")?;
    if image_blake3 != expected.image_blake3 {
        return Err(invalid(
            "image BLAKE3 does not match the expected artifact context",
        ));
    }
    let actual_image_blake3 = runtime
        .hash_range(image_base, wire.image.size)
        .map_err(|error| invalid(format!("whole-image hash failed: {error}")))?;
    if actual_image_blake3 != image_blake3 {
        return Err(invalid("image BLAKE3 does not match the runtime bytes"));
    }
    let scatter_blake3 = wire
        .runtime
        .scatter_load_map_blake3
        .as_deref()
        .map(|digest| parse_blake3(digest, "scatter load-map blake3"))
        .transpose()?;
    if scatter_blake3 != expected.scatter_blake3 {
        return Err(invalid(
            "scatter load-map dependency does not match the expected artifact context",
        ));
    }
    if wire.runtime.scatter_entries_used != expected.scatter_entries {
        return Err(invalid(
            "scatter_entries_used does not match the expected artifact context",
        ));
    }
    if !expected.scatter_entries.is_empty() && scatter_blake3.is_none() {
        return Err(invalid(
            "scatter-backed evidence has no complete load-map dependency",
        ));
    }
    let functions_blake3 = parse_blake3(&wire.inventories.functions_blake3, "functions blake3")?;
    if functions_blake3 != expected.functions_blake3 {
        return Err(invalid(
            "functions BLAKE3 does not match the expected artifact context",
        ));
    }
    let thumb_functions_blake3 = wire
        .inventories
        .thumb_functions_blake3
        .as_deref()
        .map(|digest| parse_blake3(digest, "thumb functions blake3"))
        .transpose()?;
    if thumb_functions_blake3 != expected.thumb_functions_blake3 {
        return Err(invalid(
            "thumb functions BLAKE3 does not match the expected artifact context",
        ));
    }
    validate_decoder(&wire.decoder)?;
    if wire.exception_roots.as_deref() != expected.exception_identity {
        return Err(invalid(
            "exception-root identity does not match the expected artifact context",
        ));
    }

    let plan = wire.into_plan()?;
    validate_plan(&plan, expected)?;
    let (named_roots, no_return_roots, privileged_ops) = identity_counts(&plan)?;
    if named_roots != plan.applications.len() || privileged_ops != plan.privileged_ops.len() {
        return Err(invalid(
            "identity counts do not match the reconstructed plan",
        ));
    }
    Ok(ValidatedStartup {
        image_label: plan.image_label.clone(),
        toc_name: plan.toc_name.clone(),
        identity: identity(
            manifest_blake3,
            named_roots,
            no_return_roots,
            privileged_ops,
        ),
        plan,
        manifest_blake3,
        image_blake3,
        scatter_blake3,
        functions_blake3,
        thumb_functions_blake3,
        exception_identity: expected.exception_identity.map(str::to_owned),
    })
}

fn validate_decoder(decoder: &WireDecoder) -> Result<()> {
    let identity = PureRustDecoder.identity();
    if decoder.crate_name != identity.crate_name || decoder.version != identity.version {
        return Err(invalid(
            "decoder identity does not match the compiled semantic adapter",
        ));
    }
    Ok(())
}

fn identity_counts(plan: &StartupPlan) -> Result<(usize, usize, usize)> {
    let named_roots = plan.applications.len();
    if named_roots > MAX_APPLICATIONS {
        return Err(invalid("applications exceed the named-roots bound"));
    }
    let no_return_roots = plan
        .applications
        .iter()
        .filter(|row| row.set_no_return)
        .count();
    if no_return_roots > 1 {
        return Err(invalid("no-return-roots exceeds 1"));
    }
    let privileged_ops = plan.privileged_ops.len();
    if privileged_ops > MAX_PRIVILEGED_OPS {
        return Err(invalid("privileged_ops exceed the inventory bound"));
    }
    Ok((named_roots, no_return_roots, privileged_ops))
}

fn validate_plan(plan: &StartupPlan, context: &StartupArtifactContext<'_>) -> Result<()> {
    validate_label(context.label, "artifact label")?;
    validate_label(context.toc_name, "artifact TOC name")?;
    if plan.image_label != context.label || plan.toc_name != context.toc_name {
        return Err(invalid(
            "plan image identity does not match the expected artifact context",
        ));
    }
    if plan.image_base != context.image_base || plan.image_size != context.image_size {
        return Err(invalid(
            "plan image bounds do not match the expected artifact context",
        ));
    }
    identity_counts(plan)?;
    if !context
        .scatter_entries
        .windows(2)
        .all(|pair| pair[0] < pair[1])
    {
        return Err(invalid(
            "scatter_entries_used is not sorted with unique elements",
        ));
    }
    if !context.scatter_entries.is_empty() && context.scatter_blake3.is_none() {
        return Err(invalid(
            "scatter-backed evidence has no complete load-map dependency",
        ));
    }

    let mut saw_hardware = false;
    let mut saw_stack = false;
    for application in &plan.applications {
        validate_symbol(application.desired_primary, "desired_primary")?;
        validate_symbol(application.role_label, "role_label")?;
        if application.desired_primary != application.role.desired_primary()
            || application.role_label != application.role.role_label()
        {
            return Err(invalid("application names do not match the closed role"));
        }
        match application.role {
            StartupRole::HardwareInit => {
                if saw_hardware || saw_stack {
                    return Err(invalid("applications are not in role order"));
                }
                saw_hardware = true;
                if application.set_no_return {
                    return Err(invalid("hardware_init cannot set no-return"));
                }
                match &plan.hardware_init {
                    Section::Present(init)
                        if init.entry == application.entry && init.isa == application.isa => {}
                    _ => {
                        return Err(invalid(
                            "hardware_init application does not match the present section",
                        ));
                    }
                }
            }
            StartupRole::StackGuard => {
                if saw_stack {
                    return Err(invalid("duplicate stack_guard application"));
                }
                saw_stack = true;
                match &plan.stack_guard {
                    Section::Present(guard)
                        if guard.entry == application.entry && guard.isa == application.isa =>
                    {
                        if application.set_no_return != guard.non_return {
                            return Err(invalid(
                                "set_no_return does not match stack_guard.non_return",
                            ));
                        }
                    }
                    _ => {
                        return Err(invalid(
                            "stack_guard application does not match the present section",
                        ));
                    }
                }
            }
        }
    }
    if matches!(plan.hardware_init, Section::Present(_)) && !saw_hardware {
        return Err(invalid("present hardware_init has no application"));
    }
    if matches!(plan.stack_guard, Section::Present(_)) && !saw_stack {
        return Err(invalid("present stack_guard has no application"));
    }
    for (index, application) in plan.applications.iter().enumerate() {
        if plan.applications[..index]
            .iter()
            .any(|prior| prior.entry == application.entry && prior.isa == application.isa)
        {
            return Err(malformed(format!(
                "hardware_init and stack_guard share entry {:#010x}",
                application.entry
            )));
        }
    }
    Ok(())
}

impl WireManifest {
    fn from_plan(plan: &StartupPlan, context: &StartupArtifactContext<'_>) -> Result<Self> {
        validate_plan(plan, context)?;
        let decoder = PureRustDecoder.identity();
        Ok(Self {
            format: FORMAT.to_owned(),
            schema_version: SCHEMA_VERSION,
            tool_version: env!("CARGO_PKG_VERSION").to_owned(),
            image: WireImage {
                label: context.label.to_owned(),
                toc_name: context.toc_name.to_owned(),
                base_addr: address(plan.image_base),
                size: plan.image_size,
                blake3: blake3_hex(context.image_blake3),
            },
            runtime: WireRuntime {
                scatter_load_map_blake3: context.scatter_blake3.map(blake3_hex),
                scatter_entries_used: context.scatter_entries.to_vec(),
            },
            inventories: WireInventories {
                functions_blake3: blake3_hex(context.functions_blake3),
                thumb_functions_blake3: context.thumb_functions_blake3.map(blake3_hex),
            },
            decoder: WireDecoder {
                crate_name: decoder.crate_name.to_owned(),
                version: decoder.version.to_owned(),
            },
            exception_roots: context.exception_identity.map(str::to_owned),
            hardware_init: wire_hardware_init(&plan.hardware_init)?,
            stack_guard: wire_stack_guard(&plan.stack_guard)?,
            compiler: wire_compiler(&plan.compiler)?,
            privileged_ops: plan
                .privileged_ops
                .iter()
                .map(wire_privileged_op)
                .collect::<Result<_>>()?,
            applications: plan
                .applications
                .iter()
                .map(wire_application)
                .collect::<Result<_>>()?,
        })
    }

    fn into_plan(self) -> Result<StartupPlan> {
        let image_base = parse_address(&self.image.base_addr, "image base_addr")?;
        Ok(StartupPlan {
            image_label: self.image.label,
            toc_name: self.image.toc_name,
            image_base,
            image_size: self.image.size,
            hardware_init: parse_hardware_init(self.hardware_init)?,
            stack_guard: parse_stack_guard(self.stack_guard)?,
            compiler: parse_compiler(self.compiler)?,
            privileged_ops: self
                .privileged_ops
                .into_iter()
                .map(parse_privileged_op)
                .collect::<Result<_>>()?,
            applications: self
                .applications
                .into_iter()
                .map(parse_application)
                .collect::<Result<_>>()?,
        })
    }
}

fn wire_hardware_init(section: &Section<HardwareInit>) -> Result<WireHardwareInit> {
    match section {
        Section::Absent => Ok(WireHardwareInit::Absent),
        Section::Present(init) => Ok(WireHardwareInit::Present {
            entry: address(init.entry),
            isa: isa_wire(init.isa).to_owned(),
            owner: owner_wire(init.owner),
            execution_blake3: blake3_hex(init.execution_blake3),
        }),
    }
}

fn parse_hardware_init(section: WireHardwareInit) -> Result<Section<HardwareInit>> {
    match section {
        WireHardwareInit::Absent => Ok(Section::Absent),
        WireHardwareInit::Present {
            entry,
            isa,
            owner,
            execution_blake3,
        } => Ok(Section::Present(HardwareInit {
            entry: parse_address(&entry, "hardware_init entry")?,
            isa: parse_isa(&isa)?,
            owner: parse_owner(owner),
            execution_blake3: parse_blake3(&execution_blake3, "hardware_init execution_blake3")?,
        })),
    }
}

fn wire_stack_guard(section: &Section<StackGuard>) -> Result<WireStackGuard> {
    match section {
        Section::Absent => Ok(WireStackGuard::Absent),
        Section::Present(guard) => Ok(WireStackGuard::Present {
            entry: address(guard.entry),
            isa: isa_wire(guard.isa).to_owned(),
            owner: owner_wire(guard.owner),
            execution_blake3: blake3_hex(guard.execution_blake3),
            non_return: guard.non_return,
        }),
    }
}

fn parse_stack_guard(section: WireStackGuard) -> Result<Section<StackGuard>> {
    match section {
        WireStackGuard::Absent => Ok(Section::Absent),
        WireStackGuard::Present {
            entry,
            isa,
            owner,
            execution_blake3,
            non_return,
        } => Ok(Section::Present(StackGuard {
            entry: parse_address(&entry, "stack_guard entry")?,
            isa: parse_isa(&isa)?,
            owner: parse_owner(owner),
            execution_blake3: parse_blake3(&execution_blake3, "stack_guard execution_blake3")?,
            non_return,
        })),
    }
}

fn wire_compiler(section: &Section<CompilerMeta>) -> Result<WireCompiler> {
    match section {
        Section::Absent => Ok(WireCompiler::Absent),
        Section::Present(meta) => Ok(WireCompiler::Present {
            format_address: address(meta.format_address),
            format_len: meta.format_len,
            format_blake3: blake3_hex(meta.format_blake3),
            callsite_pc: address(meta.callsite_pc),
            isa: isa_wire(meta.isa).to_owned(),
            operands: meta.operands.clone(),
        }),
    }
}

fn parse_compiler(section: WireCompiler) -> Result<Section<CompilerMeta>> {
    match section {
        WireCompiler::Absent => Ok(Section::Absent),
        WireCompiler::Present {
            format_address,
            format_len,
            format_blake3,
            callsite_pc,
            isa,
            operands,
        } => Ok(Section::Present(CompilerMeta {
            format_address: parse_address(&format_address, "compiler format_address")?,
            format_len,
            format_blake3: parse_blake3(&format_blake3, "compiler format_blake3")?,
            callsite_pc: parse_address(&callsite_pc, "compiler callsite_pc")?,
            isa: parse_isa(&isa)?,
            operands,
        })),
    }
}

fn wire_privileged_op(op: &PrivilegedOp) -> Result<WirePrivilegedOp> {
    Ok(WirePrivilegedOp {
        pc: address(op.pc),
        isa: isa_wire(op.isa).to_owned(),
        entry: address(op.entry),
        owner: owner_wire(op.owner),
        execution_blake3: blake3_hex(op.execution_blake3),
        direction: direction_wire(op.direction).to_owned(),
        class: op.class.as_wire().to_owned(),
        coprocessor: op.coprocessor,
        opcode1: op.opcode1,
        crn: op.crn,
        crm: op.crm,
        opcode2: op.opcode2,
    })
}

fn parse_privileged_op(op: WirePrivilegedOp) -> Result<PrivilegedOp> {
    Ok(PrivilegedOp {
        pc: parse_address(&op.pc, "privileged_ops pc")?,
        isa: parse_isa(&op.isa)?,
        entry: parse_address(&op.entry, "privileged_ops entry")?,
        owner: parse_owner(op.owner),
        execution_blake3: parse_blake3(&op.execution_blake3, "privileged_ops execution_blake3")?,
        direction: parse_direction(&op.direction)?,
        class: parse_class(&op.class)?,
        coprocessor: op.coprocessor,
        opcode1: op.opcode1,
        crn: op.crn,
        crm: op.crm,
        opcode2: op.opcode2,
    })
}

fn wire_application(application: &StartupApplication) -> Result<WireApplication> {
    Ok(WireApplication {
        role: application.role.as_wire().to_owned(),
        entry: address(application.entry),
        isa: isa_wire(application.isa).to_owned(),
        desired_primary: application.desired_primary.to_owned(),
        role_label: application.role_label.to_owned(),
        set_no_return: application.set_no_return,
    })
}

fn parse_application(application: WireApplication) -> Result<StartupApplication> {
    let role = parse_role(&application.role)?;
    let desired_primary = intern_role_name(role.desired_primary(), &application.desired_primary)?;
    let role_label = intern_role_name(role.role_label(), &application.role_label)?;
    Ok(StartupApplication {
        role,
        entry: parse_address(&application.entry, "application entry")?,
        isa: parse_isa(&application.isa)?,
        desired_primary,
        role_label,
        set_no_return: application.set_no_return,
    })
}

fn intern_role_name(canonical: &'static str, value: &str) -> Result<&'static str> {
    if value == canonical {
        Ok(canonical)
    } else {
        Err(invalid("application names do not match the closed role"))
    }
}

fn open_manifest_file(path: &Path, expected_label: &str) -> Result<File> {
    if !path.is_absolute() {
        return Err(invalid("manifest path is not absolute"));
    }
    if path.file_name().and_then(|name| name.to_str()) != Some(ARTIFACT_FILE_NAME) {
        return Err(invalid("manifest file name is not startup.json"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| invalid("manifest path has no parent directory"))?;
    if parent.file_name().and_then(|name| name.to_str()) != Some(expected_label) {
        return Err(invalid(
            "manifest label directory does not match the expected image label",
        ));
    }
    let startup_dir = parent
        .parent()
        .ok_or_else(|| invalid("manifest path has no startup_metadata directory"))?;
    if startup_dir.file_name().and_then(|name| name.to_str()) != Some(ARTIFACT_DIR_NAME) {
        return Err(invalid("manifest path escapes startup_metadata/<label>"));
    }
    let output_root = startup_dir
        .parent()
        .ok_or_else(|| invalid("manifest path has no output root"))?;
    let trusted_root =
        TrustedDirectory::new(output_root, "manifest output root").map_err(|error| {
            invalid(format!(
                "manifest output root cannot be opened securely: {error}"
            ))
        })?;
    let trusted_startup = trusted_root
        .open_directory_child(ARTIFACT_DIR_NAME, "manifest startup_metadata directory")
        .map_err(|error| invalid(error.to_string()))?
        .ok_or_else(|| invalid("manifest startup_metadata directory does not exist"))?;
    let trusted_label = trusted_startup
        .open_directory_child(expected_label, "manifest label directory")
        .map_err(|error| invalid(error.to_string()))?
        .ok_or_else(|| invalid("manifest label directory does not exist"))?;
    trusted_label
        .open_regular_file_with_parent(Path::new(ARTIFACT_FILE_NAME), "startup metadata manifest")
        .map(|(file, _)| file)
        .map_err(|error| invalid(error.to_string()))
}

fn invalid(reason: impl Into<String>) -> StartupMetadataError {
    StartupMetadataError::Artifact(reason.into())
}

fn malformed(context: impl Into<String>) -> StartupMetadataError {
    StartupMetadataError::Malformed {
        context: context.into(),
    }
}

fn address(value: u32) -> String {
    format!("{value:#010x}")
}

fn parse_address(value: &str, what: &str) -> Result<u32> {
    if value.len() != 10
        || !value.starts_with("0x")
        || !value[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(format!("{what} is not a canonical address")));
    }
    let parsed = u32::from_str_radix(&value[2..], 16)
        .map_err(|_| invalid(format!("{what} does not fit u32")))?;
    if address(parsed) != value {
        return Err(invalid(format!("{what} is not a canonical address")));
    }
    Ok(parsed)
}

fn blake3_hex(digest: [u8; 32]) -> String {
    blake3::Hash::from(digest).to_hex().to_string()
}

fn parse_blake3(value: &str, what: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(format!("{what} is not lowercase 64-hex")));
    }
    let mut digest = [0u8; 32];
    for (index, output) in digest.iter_mut().enumerate() {
        let high = hex_nibble(value.as_bytes()[index * 2]);
        let low = hex_nibble(value.as_bytes()[index * 2 + 1]);
        *output = high << 4 | low;
    }
    Ok(digest)
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("parse_blake3 checked lowercase hexadecimal"),
    }
}

fn identity(
    manifest_blake3: [u8; 32],
    named_roots: usize,
    no_return_roots: usize,
    privileged_ops: usize,
) -> String {
    format!(
        "v1:{}:{named_roots}:{no_return_roots}:{privileged_ops}",
        blake3_hex(manifest_blake3)
    )
}

fn isa_wire(isa: DecodeIsa) -> &'static str {
    match isa {
        DecodeIsa::Arm => "arm",
        DecodeIsa::Thumb => "thumb",
    }
}

fn parse_isa(value: &str) -> Result<DecodeIsa> {
    match value {
        "arm" => Ok(DecodeIsa::Arm),
        "thumb" => Ok(DecodeIsa::Thumb),
        _ => Err(invalid("isa is not a closed decode ISA")),
    }
}

fn owner_wire(owner: FunctionOwner) -> WireOwner {
    match owner {
        FunctionOwner::Ghidra => WireOwner::Ghidra,
        FunctionOwner::Legacy { producer } => WireOwner::Legacy { producer },
        FunctionOwner::Run {
            producer,
            region_index,
            run_index,
        } => WireOwner::Run {
            producer,
            region_index,
            run_index,
        },
    }
}

fn parse_owner(owner: WireOwner) -> FunctionOwner {
    match owner {
        WireOwner::Ghidra => FunctionOwner::Ghidra,
        WireOwner::Legacy { producer } => FunctionOwner::Legacy { producer },
        WireOwner::Run {
            producer,
            region_index,
            run_index,
        } => FunctionOwner::Run {
            producer,
            region_index,
            run_index,
        },
    }
}

fn direction_wire(direction: SystemDirection) -> &'static str {
    match direction {
        SystemDirection::Read => "read",
        SystemDirection::Write => "write",
    }
}

fn parse_direction(value: &str) -> Result<SystemDirection> {
    match value {
        "read" => Ok(SystemDirection::Read),
        "write" => Ok(SystemDirection::Write),
        _ => Err(invalid("direction is not a closed system direction")),
    }
}

fn parse_class(value: &str) -> Result<PrivilegedClass> {
    const CLASSES: [PrivilegedClass; 13] = [
        PrivilegedClass::Midr,
        PrivilegedClass::Features,
        PrivilegedClass::Sctlr,
        PrivilegedClass::Ttbr,
        PrivilegedClass::Ttbcr,
        PrivilegedClass::Dacr,
        PrivilegedClass::Fault,
        PrivilegedClass::CacheTlb,
        PrivilegedClass::Pmu,
        PrivilegedClass::Vbar,
        PrivilegedClass::ContextId,
        PrivilegedClass::CpsrSpsr,
        PrivilegedClass::Unclassified,
    ];
    CLASSES
        .into_iter()
        .find(|class| class.as_wire() == value)
        .ok_or_else(|| invalid("class is not a closed privileged class"))
}

fn parse_role(value: &str) -> Result<StartupRole> {
    match value {
        "hardware_init" => Ok(StartupRole::HardwareInit),
        "stack_protection_failure" => Ok(StartupRole::StackGuard),
        _ => Err(invalid("role is not a closed startup role")),
    }
}

fn validate_label(value: &str, what: &str) -> Result<()> {
    let safe = !value.is_empty()
        && value.len() <= MAX_PATH_COMPONENT_BYTES
        && value != "."
        && value != ".."
        && !value.ends_with(['.', ' '])
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
        && !WINDOWS_RESERVED_DEVICE_NAMES.iter().any(|reserved| {
            value
                .split_once('.')
                .map_or(value, |(stem, _)| stem)
                .eq_ignore_ascii_case(reserved)
        });
    if safe {
        Ok(())
    } else {
        Err(invalid(format!("invalid {what} {value:?}")))
    }
}

fn validate_symbol(value: &str, what: &str) -> Result<()> {
    if !value.is_empty()
        && value.len() <= MAX_SYMBOL_LEAF_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        Ok(())
    } else {
        Err(invalid(format!("{what} is not a bounded symbol leaf")))
    }
}

#[cfg(test)]
thread_local! {
    static BEFORE_COMMIT_FAILURE: std::cell::RefCell<Option<String>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn set_before_commit_failure(reason: &str) {
    BEFORE_COMMIT_FAILURE.with(|slot| {
        assert!(
            slot.borrow_mut().replace(reason.to_owned()).is_none(),
            "a pre-commit failure is already installed"
        );
    });
}

fn run_before_commit() -> Result<()> {
    #[cfg(test)]
    if let Some(reason) = BEFORE_COMMIT_FAILURE.with(|slot| slot.borrow_mut().take()) {
        return Err(invalid(reason));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        StartupArtifactContext, clear_materialized, materialize, read, read_bytes,
        read_from_trusted, set_before_commit_failure,
    };
    use crate::analysis_tool::AnalysisTool;
    use crate::arm32::SystemDirection;
    use crate::execution_ranges::{DecodeIsa, FunctionOwner};
    use crate::runtime_image::RuntimeImage;
    use crate::startup_metadata::{
        CompilerMeta, HardwareInit, PrivilegedClass, PrivilegedOp, Section, StackGuard,
        StartupApplication, StartupMetadataError, StartupPlan, StartupRole,
    };
    use crate::trusted_fs::TrustedDirectory;
    use std::path::Path;

    const BASE: u32 = 0x4001_0000;
    const LABEL: &str = "02_MAIN";
    const TOC: &str = "MAIN";

    fn digest(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn fixture() -> (Vec<u8>, StartupPlan, [u8; 32]) {
        let raw = vec![0x11u8; 0x40];
        let image_blake3 = *blake3::hash(&raw).as_bytes();
        let plan = StartupPlan {
            image_label: LABEL.to_owned(),
            toc_name: TOC.to_owned(),
            image_base: BASE,
            image_size: 0x40,
            hardware_init: Section::Present(HardwareInit {
                entry: BASE + 0x10,
                isa: DecodeIsa::Arm,
                owner: FunctionOwner::Ghidra,
                execution_blake3: digest(0x21),
            }),
            stack_guard: Section::Present(StackGuard {
                entry: BASE + 0x20,
                isa: DecodeIsa::Arm,
                owner: FunctionOwner::Ghidra,
                execution_blake3: digest(0x22),
                non_return: true,
            }),
            compiler: Section::Present(CompilerMeta {
                format_address: BASE + 0x30,
                format_len: 9,
                format_blake3: digest(0x23),
                callsite_pc: BASE + 0x08,
                isa: DecodeIsa::Arm,
                operands: vec![1, 2, BASE],
            }),
            privileged_ops: vec![PrivilegedOp {
                pc: BASE,
                isa: DecodeIsa::Arm,
                entry: BASE,
                owner: FunctionOwner::Ghidra,
                execution_blake3: digest(0x24),
                direction: SystemDirection::Write,
                class: PrivilegedClass::Vbar,
                coprocessor: Some(15),
                opcode1: Some(0),
                crn: Some(12),
                crm: Some(0),
                opcode2: Some(0),
            }],
            applications: vec![
                StartupApplication {
                    role: StartupRole::HardwareInit,
                    entry: BASE + 0x10,
                    isa: DecodeIsa::Arm,
                    desired_primary: StartupRole::HardwareInit.desired_primary(),
                    role_label: StartupRole::HardwareInit.role_label(),
                    set_no_return: false,
                },
                StartupApplication {
                    role: StartupRole::StackGuard,
                    entry: BASE + 0x20,
                    isa: DecodeIsa::Arm,
                    desired_primary: StartupRole::StackGuard.desired_primary(),
                    role_label: StartupRole::StackGuard.role_label(),
                    set_no_return: true,
                },
            ],
        };
        (raw, plan, image_blake3)
    }

    fn context<'a>(
        image_blake3: [u8; 32],
        functions_blake3: [u8; 32],
        exception_identity: Option<&'a str>,
    ) -> StartupArtifactContext<'a> {
        StartupArtifactContext {
            label: LABEL,
            toc_name: TOC,
            image_base: BASE,
            image_size: 0x40,
            image_blake3,
            scatter_blake3: None,
            scatter_entries: &[],
            functions_blake3,
            thumb_functions_blake3: None,
            exception_identity,
            tool_version: env!("CARGO_PKG_VERSION"),
        }
    }

    fn identity_from_bytes(bytes: &[u8]) -> String {
        let value: serde_json::Value = serde_json::from_slice(bytes).expect("json");
        let object = value.as_object().expect("object");
        assert!(
            !object.contains_key("identity"),
            "identity must not be a JSON oracle"
        );
        let applications = object["applications"].as_array().expect("applications");
        let named = applications.len();
        let no_return = applications
            .iter()
            .filter(|row| row["set_no_return"].as_bool() == Some(true))
            .count();
        let ops = object["privileged_ops"]
            .as_array()
            .expect("privileged_ops")
            .len();
        format!(
            "v1:{}:{named}:{no_return}:{ops}",
            blake3::hash(bytes).to_hex()
        )
    }

    #[test]
    fn canonical_bytes_have_no_trailing_newline_and_identity_rederives() {
        let (raw, plan, image_blake3) = fixture();
        let runtime = RuntimeImage::from_plan(&raw, BASE, None).expect("runtime");
        let ctx = context(image_blake3, digest(0x31), Some("v1:aa:1:8"));
        let root = tempfile::tempdir().unwrap();
        let materialized = materialize(&plan, ctx, root.path()).expect("materialize");
        let bytes = std::fs::read(root.path().join(&materialized.relative_path)).expect("bytes");

        assert!(
            !bytes.ends_with(b"\n"),
            "canonical startup.json must not end with a newline"
        );
        let text = std::str::from_utf8(&bytes).expect("utf8");
        let keys: Vec<&str> = text
            .lines()
            .filter_map(|line| {
                let rest = line.strip_prefix("  \"")?;
                if rest.starts_with('"') {
                    return None;
                }
                rest.split_once('"').map(|(key, _)| key)
            })
            .collect();
        assert_eq!(
            keys,
            [
                "format",
                "schema_version",
                "tool_version",
                "image",
                "runtime",
                "inventories",
                "decoder",
                "exception_roots",
                "hardware_init",
                "stack_guard",
                "compiler",
                "privileged_ops",
                "applications",
            ]
        );
        let expected = identity_from_bytes(&bytes);
        assert_eq!(materialized.identity, expected);
        assert_eq!(expected, "v1:".to_owned() + &expected[3..]);
        assert!(expected.ends_with(":2:1:1"), "{expected}");

        let validated = read(
            &root.path().join(&materialized.relative_path),
            &runtime,
            ctx,
        )
        .expect("read");
        assert_eq!(validated.identity, expected);
        assert_eq!(validated.plan.applications.len(), 2);
        assert_eq!(
            validated
                .plan
                .applications
                .iter()
                .filter(|row| row.set_no_return)
                .count(),
            1
        );
        assert_eq!(validated.plan.privileged_ops.len(), 1);
    }

    #[test]
    fn materialize_then_read_round_trips_and_revalidates_runtime() {
        let (raw, plan, image_blake3) = fixture();
        let runtime = RuntimeImage::from_plan(&raw, BASE, None).expect("runtime");
        let ctx = context(image_blake3, digest(0x31), Some("v1:aa:1:8"));
        let root = tempfile::tempdir().unwrap();
        let materialized = materialize(&plan, ctx, root.path()).expect("materialize");
        let path = root.path().join(&materialized.relative_path);
        let bytes = std::fs::read(&path).expect("bytes");

        let from_path = read(&path, &runtime, ctx).expect("read");
        assert_eq!(from_path.plan, plan);
        assert_eq!(from_path.identity, materialized.identity);
        assert_eq!(from_path.manifest_blake3, *blake3::hash(&bytes).as_bytes());

        let from_bytes = read_bytes(&bytes, &runtime, ctx).expect("read_bytes");
        assert_eq!(from_bytes, from_path);

        let trusted = TrustedDirectory::new(root.path(), "artifact root").expect("trusted");
        let from_trusted = read_from_trusted(
            &trusted,
            Path::new(&materialized.relative_path),
            &runtime,
            ctx,
        )
        .expect("read_from_trusted");
        assert_eq!(from_trusted, from_path);

        let mut other = raw.clone();
        other[0] ^= 0xff;
        let other_runtime = RuntimeImage::from_plan(&other, BASE, None).expect("other runtime");
        assert!(
            read(&path, &other_runtime, ctx).is_err(),
            "runtime byte drift must fail"
        );

        let bad_image = StartupArtifactContext {
            image_blake3: digest(0x00),
            ..ctx
        };
        assert!(
            read(&path, &runtime, bad_image).is_err(),
            "image digest mismatch must fail"
        );

        let bad_functions = StartupArtifactContext {
            functions_blake3: digest(0x00),
            ..ctx
        };
        assert!(
            read(&path, &runtime, bad_functions).is_err(),
            "inventory digest mismatch must fail"
        );
    }

    #[test]
    fn publication_failure_preserves_previous_complete_artifact() {
        let (_raw, plan, image_blake3) = fixture();
        let ctx = context(image_blake3, digest(0x31), Some("v1:aa:1:8"));
        let root = tempfile::tempdir().unwrap();
        let materialized = materialize(&plan, ctx, root.path()).expect("first materialize");
        let path = root.path().join(&materialized.relative_path);
        let old_bytes = std::fs::read(&path).expect("old bytes");
        set_before_commit_failure("injected pre-commit failure");

        let result = materialize(
            &plan,
            StartupArtifactContext {
                functions_blake3: digest(0x99),
                ..ctx
            },
            root.path(),
        );

        assert!(result.is_err(), "injected publication failure must surface");
        assert_eq!(std::fs::read(path).expect("preserved"), old_bytes);
    }

    #[test]
    fn clear_removes_owned_leaf_only() {
        let (_raw, plan, image_blake3) = fixture();
        let ctx = context(image_blake3, digest(0x31), None);
        let root = tempfile::tempdir().unwrap();
        let materialized = materialize(&plan, ctx, root.path()).expect("materialize");
        let manifest = root.path().join(&materialized.relative_path);
        let label_dir = manifest.parent().expect("label dir");
        let sibling = label_dir.join("foreign.txt");
        std::fs::write(&sibling, b"keep").expect("sibling");

        clear_materialized(root.path(), LABEL).expect("clear");

        assert!(!manifest.exists());
        assert!(sibling.is_file());
        assert!(label_dir.is_dir());
        assert!(root.path().join("startup_metadata").is_dir());
        clear_materialized(root.path(), LABEL).expect("clear is idempotent");
        assert!(sibling.is_file());
    }

    #[test]
    fn run_owner_round_trips_through_materialize_and_read() {
        let (raw, mut plan, image_blake3) = fixture();
        let owner = FunctionOwner::Run {
            producer: AnalysisTool::Radare2,
            region_index: 3,
            run_index: 1,
        };
        plan.privileged_ops[0].owner = owner;
        let runtime = RuntimeImage::from_plan(&raw, BASE, None).expect("runtime");
        let ctx = context(image_blake3, digest(0x31), None);
        let root = tempfile::tempdir().unwrap();
        let materialized = materialize(&plan, ctx, root.path()).expect("materialize");
        let path = root.path().join(&materialized.relative_path);
        let bytes = std::fs::read(&path).expect("bytes");

        let validated = read(&path, &runtime, ctx).expect("read");
        assert_eq!(validated.plan.privileged_ops[0].owner, owner);
        assert_eq!(validated.plan, plan);
        let from_bytes = read_bytes(&bytes, &runtime, ctx).expect("read_bytes");
        assert_eq!(from_bytes.plan.privileged_ops[0].owner, owner);
    }

    #[test]
    fn colliding_entry_isa_applications_are_malformed() {
        let (_raw, mut plan, image_blake3) = fixture();
        let shared = BASE + 0x10;
        match &mut plan.stack_guard {
            Section::Present(guard) => {
                guard.entry = shared;
                guard.isa = DecodeIsa::Arm;
            }
            Section::Absent => panic!("fixture stack_guard"),
        }
        plan.applications[1].entry = shared;
        plan.applications[1].isa = DecodeIsa::Arm;
        let ctx = context(image_blake3, digest(0x31), None);
        let root = tempfile::tempdir().unwrap();
        match materialize(&plan, ctx, root.path()) {
            Err(StartupMetadataError::Malformed { context }) => {
                assert_eq!(
                    context,
                    format!("hardware_init and stack_guard share entry {shared:#010x}")
                );
            }
            other => panic!("expected colliding Malformed, got {other:?}"),
        }

        let (raw, plan, image_blake3) = fixture();
        let runtime = RuntimeImage::from_plan(&raw, BASE, None).expect("runtime");
        let ctx = context(image_blake3, digest(0x31), None);
        let root = tempfile::tempdir().unwrap();
        let materialized = materialize(&plan, ctx, root.path()).expect("valid materialize");
        let bytes = std::fs::read(root.path().join(&materialized.relative_path)).expect("bytes");
        let text = std::str::from_utf8(&bytes).expect("utf8");
        let mutated = text.replace("0x40010020", "0x40010010");
        assert_ne!(mutated.as_bytes(), bytes.as_slice());
        match read_bytes(mutated.as_bytes(), &runtime, ctx) {
            Err(StartupMetadataError::Malformed { context }) => {
                assert_eq!(
                    context,
                    "hardware_init and stack_guard share entry 0x40010010"
                );
            }
            other => panic!("expected colliding Malformed on read, got {other:?}"),
        }
    }
}
