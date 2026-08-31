use crate::decompile::{
    AppliedExceptionRoots, AppliedPalTasks, ExceptionPass2Context, ExceptionPass2ContextExactInput,
    RuntimeExceptionState, RuntimeScatterState, RuntimeTaskState,
    read_exception_pass2_context_exact,
};
use crate::error::{Error, Result};
use crate::runtime_image::RuntimeImage;
use crate::trusted_fs::{ExpectedFileIdentity, TrustedDirectory, validate_relative_path};
use crate::{pal_tasks, scatter, symbolicate};
use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const EXCEPTION_MANIFEST_LIMIT: usize = 1024 * 1024;
const PAL_MANIFEST_LIMIT: usize = 4 * 1024 * 1024;

pub(crate) struct SnapshotBuildRequest<'a> {
    pub image_dir: &'a Path,
    pub kit_root: &'a Path,
    pub image_label: &'a str,
    pub toc_name: &'a str,
    pub image_base: u32,
    pub scatter: RuntimeScatterState,
    pub exception: &'a RuntimeExceptionState,
    pub exception_applied: Option<&'a AppliedExceptionRoots>,
    pub pal: &'a RuntimeTaskState,
    pub pal_applied: Option<&'a AppliedPalTasks>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TerminalPass2Binding {
    pub image_label: String,
    pub image_blake3: String,
    pub scatter_blake3: Option<String>,
    pub exception_identity: String,
    pub exception_manifest_blake3: Option<String>,
    pub pal_identity: String,
    pub pal_manifest_blake3: Option<String>,
}

#[derive(Debug)]
struct SnapshotException {
    identity: String,
    manifest_bytes: Arc<[u8]>,
    context: ExceptionPass2Context,
    applied: AppliedExceptionRoots,
}

#[derive(Debug)]
struct SnapshotPal {
    identity: String,
    manifest_bytes: Arc<[u8]>,
    context: symbolicate::PalPass2Context,
    applied: AppliedPalTasks,
}

#[derive(Debug)]
pub(crate) struct TerminalPass2Snapshot {
    kit_root_path: PathBuf,
    kit_root: TrustedDirectory,
    image_label: String,
    toc_name: String,
    image_base: u32,
    raw: Arc<[u8]>,
    raw_identity: ExpectedFileIdentity,
    scatter_state: RuntimeScatterState,
    scatter_blake3: Option<[u8; 32]>,
    exception_managed: bool,
    exception: Option<SnapshotException>,
    pal_managed: bool,
    pal: Option<SnapshotPal>,
}

impl TerminalPass2Snapshot {
    pub(crate) fn build(request: SnapshotBuildRequest<'_>) -> Result<Self> {
        validate_relative_path(Path::new(request.image_label), "snapshot image label")?;
        validate_relative_path(Path::new(request.toc_name), "snapshot TOC name")?;
        let kit_root_path = std::fs::canonicalize(request.kit_root)?;
        let kit_root = TrustedDirectory::new(&kit_root_path, "terminal pass-2 kit root")?;
        let source = TrustedDirectory::new(request.image_dir, "terminal pass-2 image directory")?;

        let raw_relative = Path::new(&format!("{}.bin", request.image_label)).to_path_buf();
        let raw = read_relative(
            &source,
            &raw_relative,
            u32::MAX as usize,
            None,
            "terminal raw image",
        )?;
        if raw.is_empty() || raw.len() > u32::MAX as usize {
            return Err(Error::DecomposeIncomplete(
                "terminal pass-2 raw image is empty or exceeds u32".into(),
            ));
        }
        let raw_identity = ExpectedFileIdentity::from_bytes(&raw);
        let kit_images =
            kit_root.open_or_create_directory_child("images", "kit image directory")?;
        kit_images.copy_verified_atomic(
            request.image_label,
            &mut std::io::Cursor::new(raw.as_slice()),
            raw_identity,
            "kit raw image",
        )?;

        let scatter_blake3 = match request.scatter {
            RuntimeScatterState::Present => {
                let artifact = scatter::read_materialized_from_trusted(
                    &source,
                    Path::new("scatter/load_map.json"),
                    &raw,
                    request.image_base,
                )?;
                let digest = artifact.manifest_blake3();
                scatter::restage_retained_to(&artifact, request.image_label, &kit_root)?;
                Some(digest)
            }
            RuntimeScatterState::Absent => {
                clear_staged_leaf(
                    &kit_root,
                    "scatter",
                    request.image_label,
                    "load_map.json",
                    "absent snapshot scatter map",
                )?;
                None
            }
            RuntimeScatterState::Unmanaged => None,
        };

        let staged_scatter = scatter_blake3
            .map(|expected| {
                let artifact = scatter::read_materialized_from_trusted(
                    &kit_root,
                    &scatter_relative(request.image_label),
                    &raw,
                    request.image_base,
                )?;
                if artifact.manifest_blake3() != expected {
                    return Err(Error::BadScatter(
                        "staged snapshot scatter identity changed".into(),
                    ));
                }
                Ok(artifact)
            })
            .transpose()?;
        let runtime = match staged_scatter {
            Some(artifact) => RuntimeImage::from_materialized(&raw, request.image_base, artifact)?,
            None => RuntimeImage::from_plan(&raw, request.image_base, None)?,
        };

        let exception_managed = !matches!(request.exception, RuntimeExceptionState::Unmanaged);
        let exception = match request.exception {
            RuntimeExceptionState::Present(map) => {
                let applied = request.exception_applied.ok_or_else(|| {
                    Error::BadExceptionRoots(format!(
                        "{} current exception application summary is missing",
                        request.image_label
                    ))
                })?;
                let bytes = read_relative(
                    &source,
                    Path::new("exception_roots/roots.json"),
                    EXCEPTION_MANIFEST_LIMIT,
                    Some(&map.blake3),
                    "terminal exception manifest",
                )
                .map_err(|error| Error::BadExceptionRoots(error.to_string()))?;
                let context = read_exception_pass2_context_exact(ExceptionPass2ContextExactInput {
                    manifest_bytes: &bytes,
                    runtime: &runtime,
                    image_label: request.image_label,
                    toc_name: request.toc_name,
                    expected_identity: &map.identity,
                    expected_scatter_load_map_blake3: scatter_blake3,
                    applied,
                })
                .map_err(|error| Error::BadExceptionRoots(error.to_string()))?;
                stage_manifest(
                    &kit_root,
                    "exception_roots",
                    request.image_label,
                    "roots.json",
                    &bytes,
                    "snapshot exception manifest",
                )
                .map_err(|error| Error::BadExceptionRoots(error.to_string()))?;
                Some(SnapshotException {
                    identity: map.identity.clone(),
                    manifest_bytes: bytes.into(),
                    context,
                    applied: applied.clone(),
                })
            }
            RuntimeExceptionState::Absent => {
                clear_staged_leaf(
                    &kit_root,
                    "exception_roots",
                    request.image_label,
                    "roots.json",
                    "absent snapshot exception manifest",
                )?;
                None
            }
            RuntimeExceptionState::Unmanaged => None,
        };

        let pal_managed = !matches!(request.pal, RuntimeTaskState::Unmanaged);
        let pal = match request.pal {
            RuntimeTaskState::Present(map) => {
                let applied = request.pal_applied.ok_or_else(|| {
                    Error::BadPalTasks(format!(
                        "{} current PAL application summary is missing",
                        request.image_label
                    ))
                })?;
                let bytes = read_relative(
                    &source,
                    Path::new("pal_tasks/tasks.json"),
                    PAL_MANIFEST_LIMIT,
                    Some(&map.blake3),
                    "terminal PAL manifest",
                )
                .map_err(|error| Error::BadPalTasks(error.to_string()))?;
                let artifact = pal_tasks::read_bytes(
                    &bytes,
                    &runtime,
                    pal_tasks::TaskArtifactContext {
                        label: request.image_label,
                        image_blake3: *blake3::hash(&raw).as_bytes(),
                        scatter_load_map_blake3: scatter_blake3,
                    },
                )
                .map_err(|error| Error::BadPalTasks(error.to_string()))?;
                if artifact.identity != map.identity
                    || artifact.plan.tasks.len() != applied.tasks
                    || artifact.plan.applications.len() != applied.entries
                {
                    return Err(Error::BadPalTasks(format!(
                        "{} PAL snapshot does not match current generation/application state",
                        request.image_label
                    )));
                }
                stage_manifest(
                    &kit_root,
                    "pal_tasks",
                    request.image_label,
                    "tasks.json",
                    &bytes,
                    "snapshot PAL manifest",
                )
                .map_err(|error| Error::BadPalTasks(error.to_string()))?;
                Some(SnapshotPal {
                    identity: map.identity.clone(),
                    manifest_bytes: bytes.into(),
                    context: pal_pass2_context(&artifact),
                    applied: applied.clone(),
                })
            }
            RuntimeTaskState::Absent => {
                clear_staged_leaf(
                    &kit_root,
                    "pal_tasks",
                    request.image_label,
                    "tasks.json",
                    "absent snapshot PAL manifest",
                )
                .map_err(|error| Error::BadPalTasks(error.to_string()))?;
                None
            }
            RuntimeTaskState::Unmanaged => None,
        };

        let snapshot = Self {
            kit_root_path,
            kit_root,
            image_label: request.image_label.to_string(),
            toc_name: request.toc_name.to_string(),
            image_base: request.image_base,
            raw: raw.into(),
            raw_identity,
            scatter_state: request.scatter,
            scatter_blake3,
            exception_managed,
            exception,
            pal_managed,
            pal,
        };
        snapshot.validate_for_spawn()?;
        Ok(snapshot)
    }

    pub(crate) fn build_raw_only_from_kit(
        kit_root: &Path,
        image_label: &str,
        toc_name: &str,
        image_base: u32,
    ) -> Result<Self> {
        validate_relative_path(Path::new(image_label), "snapshot image label")?;
        validate_relative_path(Path::new(toc_name), "snapshot TOC name")?;
        let kit_root_path = std::fs::canonicalize(kit_root)?;
        let kit_root = TrustedDirectory::new(&kit_root_path, "terminal pass-2 kit root")?;
        let raw = read_relative(
            &kit_root,
            &Path::new("images").join(image_label),
            u32::MAX as usize,
            None,
            "terminal raw image",
        )?;
        if raw.is_empty() || raw.len() > u32::MAX as usize {
            return Err(Error::DecomposeIncomplete(
                "terminal pass-2 raw image is empty or exceeds u32".into(),
            ));
        }
        clear_staged_leaf(
            &kit_root,
            "scatter",
            image_label,
            "load_map.json",
            "raw-only snapshot scatter map",
        )?;
        clear_staged_leaf(
            &kit_root,
            "exception_roots",
            image_label,
            "roots.json",
            "raw-only snapshot exception manifest",
        )?;
        clear_staged_leaf(
            &kit_root,
            "pal_tasks",
            image_label,
            "tasks.json",
            "raw-only snapshot PAL manifest",
        )?;
        let snapshot = Self {
            kit_root_path,
            kit_root,
            image_label: image_label.to_string(),
            toc_name: toc_name.to_string(),
            image_base,
            raw_identity: ExpectedFileIdentity::from_bytes(&raw),
            raw: raw.into(),
            scatter_state: RuntimeScatterState::Absent,
            scatter_blake3: None,
            exception_managed: true,
            exception: None,
            pal_managed: true,
            pal: None,
        };
        snapshot.validate_for_spawn()?;
        Ok(snapshot)
    }

    pub(crate) fn image_label(&self) -> &str {
        &self.image_label
    }

    pub(crate) fn image_base(&self) -> u32 {
        self.image_base
    }

    pub(crate) fn kit_root_path(&self) -> &Path {
        &self.kit_root_path
    }

    pub(crate) fn image_blake3(&self) -> String {
        crate::manifest::blake3_fixed(self.raw_identity.blake3())
    }

    pub(crate) fn raw_path(&self) -> PathBuf {
        self.kit_root_path.join("images").join(&self.image_label)
    }

    pub(crate) fn scatter_manifest(&self) -> Option<PathBuf> {
        self.scatter_blake3
            .map(|_| self.kit_root_path.join(scatter_relative(&self.image_label)))
    }

    pub(crate) fn exception_manifest(&self) -> Option<PathBuf> {
        self.exception.as_ref().map(|_| {
            self.kit_root_path
                .join(exception_relative(&self.image_label))
        })
    }

    pub(crate) fn pal_manifest(&self) -> Option<PathBuf> {
        self.pal
            .as_ref()
            .map(|_| self.kit_root_path.join(pal_relative(&self.image_label)))
    }

    pub(crate) fn exception_identity(&self) -> &str {
        self.exception
            .as_ref()
            .map(|state| state.identity.as_str())
            .unwrap_or("none")
    }

    pub(crate) fn pal_identity(&self) -> &str {
        self.pal
            .as_ref()
            .map(|state| state.identity.as_str())
            .unwrap_or("none")
    }

    pub(crate) fn exception_context(&self) -> Option<&ExceptionPass2Context> {
        self.exception.as_ref().map(|state| &state.context)
    }

    pub(crate) fn pal_context(&self) -> Option<&symbolicate::PalPass2Context> {
        self.pal.as_ref().map(|state| &state.context)
    }

    pub(crate) fn binding(&self) -> TerminalPass2Binding {
        TerminalPass2Binding {
            image_label: self.image_label.clone(),
            image_blake3: self.image_blake3(),
            scatter_blake3: self.scatter_blake3.map(crate::manifest::blake3_fixed),
            exception_identity: self.exception_identity().to_string(),
            exception_manifest_blake3: self
                .exception
                .as_ref()
                .map(|state| crate::manifest::blake3_bytes(&state.manifest_bytes)),
            pal_identity: self.pal_identity().to_string(),
            pal_manifest_blake3: self
                .pal
                .as_ref()
                .map(|state| crate::manifest::blake3_bytes(&state.manifest_bytes)),
        }
    }

    pub(crate) fn with_runtime<T>(
        &self,
        use_runtime: impl FnOnce(&[u8], &RuntimeImage<'_>) -> Result<T>,
    ) -> Result<T> {
        self.validate_with_runtime(use_runtime)
    }

    pub(crate) fn validate_for_spawn(&self) -> Result<()> {
        self.validate_with_runtime(|_, runtime| {
            if let Some(exception) = &self.exception {
                let context = read_exception_pass2_context_exact(ExceptionPass2ContextExactInput {
                    manifest_bytes: &exception.manifest_bytes,
                    runtime,
                    image_label: &self.image_label,
                    toc_name: &self.toc_name,
                    expected_identity: &exception.identity,
                    expected_scatter_load_map_blake3: self.scatter_blake3,
                    applied: &exception.applied,
                })
                .map_err(|error| Error::BadExceptionRoots(error.to_string()))?;
                if context != exception.context {
                    return Err(Error::BadExceptionRoots(
                        "snapshot exception application context changed".into(),
                    ));
                }
            }
            if let Some(pal) = &self.pal {
                let artifact = pal_tasks::read_bytes(
                    &pal.manifest_bytes,
                    runtime,
                    pal_tasks::TaskArtifactContext {
                        label: &self.image_label,
                        image_blake3: self.raw_identity.blake3(),
                        scatter_load_map_blake3: self.scatter_blake3,
                    },
                )
                .map_err(|error| Error::BadPalTasks(error.to_string()))?;
                if artifact.identity != pal.identity
                    || artifact.plan.tasks.len() != pal.applied.tasks
                    || artifact.plan.applications.len() != pal.applied.entries
                    || pal_pass2_context(&artifact) != pal.context
                {
                    return Err(Error::BadPalTasks(
                        "snapshot PAL application context changed".into(),
                    ));
                }
            }
            Ok(())
        })
    }

    fn validate_with_runtime<T>(
        &self,
        use_runtime: impl FnOnce(&[u8], &RuntimeImage<'_>) -> Result<T>,
    ) -> Result<T> {
        self.kit_root
            .verify_path_binding(&self.kit_root_path, "terminal pass-2 kit root")?;
        let raw = read_relative(
            &self.kit_root,
            &Path::new("images").join(&self.image_label),
            self.raw_identity.length() as usize,
            Some(&self.image_blake3()),
            "snapshot raw image",
        )?;
        if raw.as_slice() != self.raw.as_ref() {
            return Err(Error::DecomposeIncomplete(
                "snapshot raw image changed after construction".into(),
            ));
        }
        let scatter = match self.scatter_blake3 {
            Some(expected) => {
                let artifact = scatter::read_materialized_from_trusted(
                    &self.kit_root,
                    &scatter_relative(&self.image_label),
                    &raw,
                    self.image_base,
                )?;
                if artifact.manifest_blake3() != expected {
                    return Err(Error::BadScatter(
                        "snapshot scatter manifest changed after construction".into(),
                    ));
                }
                Some(artifact)
            }
            None => {
                if self.scatter_state == RuntimeScatterState::Absent {
                    require_staged_leaf_absent(
                        &self.kit_root,
                        "scatter",
                        &self.image_label,
                        "load_map.json",
                        "snapshot scatter manifest",
                    )?;
                }
                None
            }
        };
        validate_manifest_leaf(
            &self.kit_root,
            self.exception_managed,
            self.exception
                .as_ref()
                .map(|state| state.manifest_bytes.as_ref()),
            "exception_roots",
            &self.image_label,
            "roots.json",
            EXCEPTION_MANIFEST_LIMIT,
            "snapshot exception manifest",
        )
        .map_err(|error| Error::BadExceptionRoots(error.to_string()))?;
        validate_manifest_leaf(
            &self.kit_root,
            self.pal_managed,
            self.pal.as_ref().map(|state| state.manifest_bytes.as_ref()),
            "pal_tasks",
            &self.image_label,
            "tasks.json",
            PAL_MANIFEST_LIMIT,
            "snapshot PAL manifest",
        )
        .map_err(|error| Error::BadPalTasks(error.to_string()))?;
        let runtime = match scatter {
            Some(artifact) => RuntimeImage::from_materialized(&raw, self.image_base, artifact)?,
            None => RuntimeImage::from_plan(&raw, self.image_base, None)?,
        };
        use_runtime(&raw, &runtime)
    }
}

fn read_relative(
    root: &TrustedDirectory,
    relative: &Path,
    limit: usize,
    expected_blake3: Option<&str>,
    context: &str,
) -> Result<Vec<u8>> {
    let mut file = root.open_regular_file(relative, context)?;
    read_file(&mut file, limit, expected_blake3, context)
}

fn read_file(
    file: &mut File,
    limit: usize,
    expected_blake3: Option<&str>,
    context: &str,
) -> Result<Vec<u8>> {
    let length = file.metadata()?.len();
    if length > limit as u64 {
        return Err(Error::DecomposeIncomplete(format!(
            "{context} exceeds its {limit}-byte limit"
        )));
    }
    let length = usize::try_from(length)
        .map_err(|_| Error::DecomposeIncomplete(format!("{context} size does not fit the host")))?;
    let mut bytes = vec![0; length];
    file.read_exact(&mut bytes)?;
    let mut trailing = [0u8; 1];
    if file.read(&mut trailing)? != 0 {
        return Err(Error::DecomposeIncomplete(format!(
            "{context} grew while it was being authenticated"
        )));
    }
    if expected_blake3.is_some_and(|expected| crate::manifest::blake3_bytes(&bytes) != expected) {
        return Err(Error::DecomposeIncomplete(format!(
            "{context} changed after construction"
        )));
    }
    Ok(bytes)
}

fn stage_manifest(
    kit: &TrustedDirectory,
    component: &str,
    label: &str,
    leaf: &str,
    bytes: &[u8],
    context: &str,
) -> Result<()> {
    let destination = kit
        .open_or_create_directory_child(component, context)?
        .open_or_create_directory_child(label, context)?;
    destination.copy_verified_atomic(
        leaf,
        &mut std::io::Cursor::new(bytes),
        ExpectedFileIdentity::from_bytes(bytes),
        context,
    )
}

fn clear_staged_leaf(
    kit: &TrustedDirectory,
    component: &str,
    label: &str,
    leaf: &str,
    context: &str,
) -> Result<()> {
    let Some(component) = kit.open_directory_child(component, context)? else {
        return Ok(());
    };
    let Some(label) = component.open_directory_child(label, context)? else {
        return Ok(());
    };
    label.unlink_regular_file_if_exists(leaf, context)?;
    Ok(())
}

fn require_staged_leaf_absent(
    kit: &TrustedDirectory,
    component: &str,
    label: &str,
    leaf: &str,
    context: &str,
) -> Result<()> {
    let Some(component) = kit.open_directory_child(component, context)? else {
        return Ok(());
    };
    let Some(label) = component.open_directory_child(label, context)? else {
        return Ok(());
    };
    if label.regular_file_exists(leaf, context)? {
        return Err(Error::DecomposeIncomplete(format!(
            "{context} is present for explicit absence"
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_manifest_leaf(
    kit: &TrustedDirectory,
    managed: bool,
    expected: Option<&[u8]>,
    component: &str,
    label: &str,
    leaf: &str,
    limit: usize,
    context: &str,
) -> Result<()> {
    match expected {
        Some(expected) => {
            let relative = Path::new(component).join(label).join(leaf);
            let bytes = read_relative(
                kit,
                &relative,
                limit,
                Some(&crate::manifest::blake3_bytes(expected)),
                context,
            )?;
            if bytes != expected {
                return Err(Error::DecomposeIncomplete(format!(
                    "{context} changed after construction"
                )));
            }
        }
        None if managed => {
            require_staged_leaf_absent(kit, component, label, leaf, context)?;
        }
        None => {}
    }
    Ok(())
}

fn scatter_relative(label: &str) -> PathBuf {
    Path::new("scatter").join(label).join("load_map.json")
}

fn exception_relative(label: &str) -> PathBuf {
    Path::new("exception_roots").join(label).join("roots.json")
}

fn pal_relative(label: &str) -> PathBuf {
    Path::new("pal_tasks").join(label).join("tasks.json")
}

fn pal_pass2_context(artifact: &pal_tasks::ValidatedTaskArtifact) -> symbolicate::PalPass2Context {
    let manifest_blake3 = crate::manifest::blake3_fixed(artifact.manifest_blake3);
    let scatter_load_map_blake3 = artifact
        .scatter_load_map_blake3
        .map(crate::manifest::blake3_fixed);
    let tasks_by_index = |index: u32| {
        artifact
            .plan
            .tasks
            .iter()
            .find(|task| task.index == index)
            .expect("validated applications reference parsed task indices")
    };
    let mut applications = std::collections::BTreeMap::new();
    for application in &artifact.plan.applications {
        let tasks = application
            .task_indices
            .iter()
            .map(|index| {
                let task = tasks_by_index(*index);
                symbolicate::PalTaskRef {
                    manifest_blake3: manifest_blake3.clone(),
                    task_index: task.index,
                    name: task.name.clone(),
                    slot: task.slot,
                    priority: task.priority,
                    stack_size: task.stack_size,
                }
            })
            .collect();
        applications.insert(
            application.entry,
            symbolicate::PalApplicationRef {
                isa: match application.isa {
                    pal_tasks::TaskIsa::Arm => "arm",
                    pal_tasks::TaskIsa::Thumb => "thumb",
                },
                desired_primary: application.desired_primary.clone(),
                applied: true,
                tasks,
            },
        );
    }
    symbolicate::PalPass2Context {
        identity: artifact.identity.clone(),
        manifest_blake3,
        scatter_load_map_blake3,
        applications,
    }
}

#[cfg(test)]
mod tests {
    use super::{SnapshotBuildRequest, TerminalPass2Snapshot};
    use crate::decompile::{
        AppliedPalTasks, RuntimeExceptionState, RuntimeScatterState, RuntimeTaskState,
    };
    use crate::pal_tasks::test_support::BASE;

    struct CombinedFixture {
        _root: tempfile::TempDir,
        image: std::path::PathBuf,
        kit: std::path::PathBuf,
        snapshot: TerminalPass2Snapshot,
        exception_bytes: Vec<u8>,
        pal_bytes: Vec<u8>,
    }

    fn write_u32(raw: &mut [u8], address: u32, value: u32) {
        let offset = usize::try_from(address - BASE).unwrap();
        raw[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn a32_branch(slot: u32, target: u32) -> u32 {
        let displacement = i64::from(target) - (i64::from(slot) + 8);
        assert_eq!(displacement % 4, 0);
        let words = displacement / 4;
        0xea00_0000 | u32::try_from(words & 0x00ff_ffff).unwrap()
    }

    fn combined_raw() -> Vec<u8> {
        let mut raw = crate::pal_tasks::test_support::craft_scatter_pal_main_image();
        for index in 0..8u32 {
            let slot = BASE + index * 4;
            let target = BASE + 0x3000 + index * 8;
            write_u32(&mut raw, slot, a32_branch(slot, target));
            write_u32(&mut raw, target, 0xe1a0_0000);
            write_u32(&mut raw, target + 4, 0xe12f_ff1e);
        }
        raw
    }

    fn applied_exception_roots(
        plan: &crate::exception_roots::ExceptionRootPlan,
        identity: &str,
    ) -> crate::decompile::AppliedExceptionRoots {
        let mut applications = plan.applications.clone();
        applications.sort_by_key(|application| application.entry);
        let rows = applications
            .iter()
            .enumerate()
            .map(|(index, application)| {
                let name = application
                    .desired_primary
                    .as_ref()
                    .expect("distinct vector targets each request a primary");
                serde_json::json!({
                    "entry": format!("{:#010x}", application.entry),
                    "isa": "arm",
                    "function_result": "created",
                    "name_result": "applied",
                    "shared": false,
                    "primary_disposition": "exception_owned",
                    "current_primary": {
                        "symbol_id": 100 + index,
                        "source": "analysis",
                        "name": name,
                        "name_blake3": crate::manifest::blake3_bytes(name.as_bytes()),
                    },
                    "transition": null,
                })
            })
            .collect::<Vec<_>>();
        let count = rows.len();
        let summary = format!(
            "ApplyExceptionRoots: {}",
            serde_json::json!({
                "image": "02_MAIN",
                "status": "ok",
                "identity": identity,
                "symbol_pass2": null,
                "tables": plan.tables.len(),
                "roles": 8,
                "entries": count,
                "functions_created": count,
                "functions_reapplied": 0,
                "functions_existing": 0,
                "names_applied": count,
                "names_reapplied": 0,
                "names_preserved": 0,
                "names_not_requested": 0,
                "shared_entries": 0,
                "applications": rows,
            })
        );
        crate::decompile::test_applied_exception_roots_from_summary(&summary, "02_MAIN", identity)
    }

    fn combined_fixture() -> CombinedFixture {
        let root = tempfile::tempdir().unwrap();
        let image = root.path().join("images/02_MAIN");
        let generation = root.path().join("generation");
        let kit = root.path().join("ghidra");
        std::fs::create_dir_all(&image).unwrap();
        std::fs::create_dir(&generation).unwrap();
        std::fs::create_dir(&kit).unwrap();

        let raw = combined_raw();
        std::fs::write(image.join("02_MAIN.bin"), &raw).unwrap();
        let scatter_plan = crate::scatter::discover(&raw, BASE)
            .unwrap()
            .expect("combined fixture retains its scatter loader");
        let scatter_map =
            crate::scatter::materialize(&scatter_plan, &raw, "02_MAIN", &generation).unwrap();
        std::fs::rename(generation.join("scatter/02_MAIN"), image.join("scatter")).unwrap();
        let scatter_blake3 = crate::execution_ranges::parse_blake3(&scatter_map.blake3).unwrap();

        let (exception_plan, exception_map, pal_map, pal_tasks, pal_applications) = {
            let scatter = crate::scatter::read_materialized(
                &image,
                &image.join("scatter/load_map.json"),
                &raw,
                BASE,
            )
            .unwrap();
            let runtime =
                crate::runtime_image::RuntimeImage::from_materialized(&raw, BASE, scatter).unwrap();
            let exception_plan = crate::exception_roots::discover(&runtime, "02_MAIN", "MAIN")
                .unwrap()
                .expect("combined fixture has an exception vector table");
            let exception_map = crate::exception_roots::materialize(
                &exception_plan,
                crate::exception_roots::ExceptionArtifactContext {
                    label: "02_MAIN",
                    toc_name: "MAIN",
                    image_blake3: *blake3::hash(&raw).as_bytes(),
                    scatter_load_map_blake3: Some(scatter_blake3),
                },
                &generation,
            )
            .unwrap();
            let pal_plan = crate::pal_tasks::discover(&runtime, "02_MAIN")
                .unwrap()
                .expect("combined fixture retains its PAL initializer");
            let pal_map = crate::pal_tasks::materialize(
                &pal_plan,
                crate::pal_tasks::TaskArtifactContext {
                    label: "02_MAIN",
                    image_blake3: *blake3::hash(&raw).as_bytes(),
                    scatter_load_map_blake3: Some(scatter_blake3),
                },
                &generation,
            )
            .unwrap();
            (
                exception_plan,
                exception_map,
                pal_map,
                pal_plan.tasks.len(),
                pal_plan.applications.len(),
            )
        };

        let exception_bytes = std::fs::read(generation.join(&exception_map.relative_path)).unwrap();
        let pal_bytes = std::fs::read(generation.join(&pal_map.relative_path)).unwrap();
        std::fs::create_dir(image.join("exception_roots")).unwrap();
        std::fs::create_dir(image.join("pal_tasks")).unwrap();
        std::fs::write(image.join("exception_roots/roots.json"), &exception_bytes).unwrap();
        std::fs::write(image.join("pal_tasks/tasks.json"), &pal_bytes).unwrap();

        let exception_applied = applied_exception_roots(&exception_plan, &exception_map.identity);
        let pal_applied = AppliedPalTasks {
            tasks: pal_tasks,
            entries: pal_applications,
            functions_created: pal_applications,
            functions_existing: 0,
            names_applied: pal_applications,
            names_preserved: 0,
            shared_entries: 0,
        };
        let exception_state = RuntimeExceptionState::Present(exception_map);
        let pal_state = RuntimeTaskState::Present(pal_map);
        let snapshot = TerminalPass2Snapshot::build(SnapshotBuildRequest {
            image_dir: &image,
            kit_root: &kit,
            image_label: "02_MAIN",
            toc_name: "MAIN",
            image_base: BASE,
            scatter: RuntimeScatterState::Present,
            exception: &exception_state,
            exception_applied: Some(&exception_applied),
            pal: &pal_state,
            pal_applied: Some(&pal_applied),
        })
        .unwrap();

        CombinedFixture {
            _root: root,
            image,
            kit,
            snapshot,
            exception_bytes,
            pal_bytes,
        }
    }

    fn raw_only_fixture() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let image = root.path().join("images/00_BOOT");
        let kit = root.path().join("ghidra");
        std::fs::create_dir_all(&image).unwrap();
        std::fs::create_dir(&kit).unwrap();
        std::fs::write(image.join("00_BOOT.bin"), [0x11; 64]).unwrap();
        (root, image, kit)
    }

    fn build_raw_only<'a>(
        image: &'a std::path::Path,
        kit: &'a std::path::Path,
    ) -> TerminalPass2Snapshot {
        TerminalPass2Snapshot::build(SnapshotBuildRequest {
            image_dir: image,
            kit_root: kit,
            image_label: "00_BOOT",
            toc_name: "BOOT",
            image_base: 0x4001_0000,
            scatter: RuntimeScatterState::Absent,
            exception: &RuntimeExceptionState::Absent,
            exception_applied: None,
            pal: &RuntimeTaskState::Absent,
            pal_applied: None,
        })
        .unwrap()
    }

    #[test]
    fn terminal_pass2_snapshot_builds_one_canonical_raw_copy() {
        let (_root, image, kit) = raw_only_fixture();
        for path in [
            kit.join("scatter/00_BOOT/load_map.json"),
            kit.join("exception_roots/00_BOOT/roots.json"),
            kit.join("pal_tasks/00_BOOT/tasks.json"),
        ] {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, b"stale").unwrap();
        }

        let snapshot = build_raw_only(&image, &kit);

        assert_eq!(snapshot.image_label(), "00_BOOT");
        assert_eq!(
            snapshot.image_blake3(),
            crate::manifest::blake3_bytes(&[0x11; 64])
        );
        assert_eq!(std::fs::read(snapshot.raw_path()).unwrap(), [0x11; 64]);
        assert!(snapshot.scatter_manifest().is_none());
        assert_eq!(snapshot.exception_identity(), "none");
        assert_eq!(snapshot.pal_identity(), "none");
        assert!(!kit.join("scatter/00_BOOT/load_map.json").exists());
        assert!(!kit.join("exception_roots/00_BOOT/roots.json").exists());
        assert!(!kit.join("pal_tasks/00_BOOT/tasks.json").exists());
        snapshot.validate_for_spawn().unwrap();
    }

    #[test]
    fn terminal_pass2_snapshot_rejects_post_context_drift() {
        let (_root, image, kit) = raw_only_fixture();
        let snapshot = build_raw_only(&image, &kit);
        std::fs::write(snapshot.raw_path(), [0x22; 64]).unwrap();

        let error = snapshot.validate_for_spawn().unwrap_err();

        assert!(error.to_string().contains("raw image"));
        assert!(error.to_string().contains("changed"));
    }

    #[test]
    fn terminal_snapshot_derives_both_contexts_from_one_runtime_and_never_reopens_source() {
        let fixture = combined_fixture();
        let binding = fixture.snapshot.binding();
        assert!(fixture.snapshot.exception_context().is_some());
        assert!(fixture.snapshot.pal_context().is_some());
        assert_eq!(
            binding.scatter_blake3,
            fixture.snapshot.binding().scatter_blake3
        );
        assert_eq!(
            std::fs::read(fixture.snapshot.exception_manifest().unwrap()).unwrap(),
            fixture.exception_bytes
        );
        assert_eq!(
            std::fs::read(fixture.snapshot.pal_manifest().unwrap()).unwrap(),
            fixture.pal_bytes
        );
        fixture
            .snapshot
            .with_runtime(|_, runtime| {
                assert_eq!(runtime.image_bounds().0, BASE);
                assert!(runtime.read_exact(BASE + 0x5000, 4).is_ok());
                Ok(())
            })
            .unwrap();

        let moved = fixture.image.with_extension("authenticated-source");
        std::fs::rename(&fixture.image, moved).unwrap();
        fixture.snapshot.validate_for_spawn().unwrap();
    }

    #[test]
    fn terminal_snapshot_rejects_each_staged_context_drift() {
        let exception = combined_fixture();
        std::fs::write(
            exception.snapshot.exception_manifest().unwrap(),
            b"changed exception manifest",
        )
        .unwrap();
        assert!(
            exception
                .snapshot
                .validate_for_spawn()
                .unwrap_err()
                .to_string()
                .contains("exception")
        );

        let pal = combined_fixture();
        std::fs::write(
            pal.snapshot.pal_manifest().unwrap(),
            b"changed PAL manifest",
        )
        .unwrap();
        assert!(
            pal.snapshot
                .validate_for_spawn()
                .unwrap_err()
                .to_string()
                .contains("PAL")
        );

        let scatter = combined_fixture();
        std::fs::write(
            scatter.kit.join("scatter/02_MAIN/blocks/03-copy.bin"),
            b"evil",
        )
        .unwrap();
        assert!(
            scatter
                .snapshot
                .validate_for_spawn()
                .unwrap_err()
                .to_string()
                .to_lowercase()
                .contains("scatter")
        );
    }

    #[test]
    fn failed_snapshot_build_returns_no_object_and_preserves_old_manifest() {
        const BASE: u32 = 0x4001_0000;
        let root = tempfile::tempdir().unwrap();
        let image = root.path().join("images/00_BOOT");
        let generation = root.path().join("generation");
        let kit = root.path().join("ghidra");
        std::fs::create_dir_all(&image).unwrap();
        std::fs::create_dir(&generation).unwrap();
        std::fs::create_dir_all(kit.join("exception_roots/00_BOOT")).unwrap();
        std::fs::write(
            kit.join("exception_roots/00_BOOT/roots.json"),
            b"old complete manifest",
        )
        .unwrap();
        let fixture =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/exception_roots");
        let raw = std::fs::read(fixture.join("synthetic.bin")).unwrap();
        std::fs::write(image.join("00_BOOT.bin"), &raw).unwrap();
        let runtime = crate::runtime_image::RuntimeImage::from_plan(&raw, BASE, None).unwrap();
        let plan = crate::exception_roots::discover(&runtime, "00_BOOT", "BOOT")
            .unwrap()
            .unwrap();
        let map = crate::exception_roots::materialize(
            &plan,
            crate::exception_roots::ExceptionArtifactContext {
                label: "00_BOOT",
                toc_name: "BOOT",
                image_blake3: *blake3::hash(&raw).as_bytes(),
                scatter_load_map_blake3: None,
            },
            &generation,
        )
        .unwrap();
        std::fs::create_dir(image.join("exception_roots")).unwrap();
        std::fs::copy(
            generation.join(&map.relative_path),
            image.join("exception_roots/roots.json"),
        )
        .unwrap();
        let applied = crate::decompile::test_applied_exception_roots(
            "00_BOOT",
            &format!("v1:{}:1:7", "f".repeat(64)),
        );
        let exception = RuntimeExceptionState::Present(map);

        let result = TerminalPass2Snapshot::build(SnapshotBuildRequest {
            image_dir: &image,
            kit_root: &kit,
            image_label: "00_BOOT",
            toc_name: "BOOT",
            image_base: BASE,
            scatter: RuntimeScatterState::Absent,
            exception: &exception,
            exception_applied: Some(&applied),
            pal: &RuntimeTaskState::Absent,
            pal_applied: None,
        });

        assert!(
            result.is_err(),
            "a digest mismatch produced a current snapshot"
        );
        assert_eq!(
            std::fs::read(kit.join("exception_roots/00_BOOT/roots.json")).unwrap(),
            b"old complete manifest"
        );
    }
}
