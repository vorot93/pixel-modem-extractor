use crate::decompile::{
    AppliedExceptionRoots, AppliedPalTasks, ExceptionPass2Context, ExceptionPass2ContextExactInput,
    RuntimeExceptionState, RuntimeScatterState, RuntimeTaskState,
    read_exception_pass2_context_exact, read_exception_pass2_context_exact_with_validated,
};
use crate::error::{Error, Result};
use crate::runtime_image::RuntimeImage;
use crate::trusted_fs::{ExpectedFileIdentity, TrustedDirectory, validate_relative_path};
use crate::{pal_tasks, scatter, startup_metadata, symbolicate};
use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const EXCEPTION_MANIFEST_LIMIT: usize = 1024 * 1024;
const PAL_MANIFEST_LIMIT: usize = 4 * 1024 * 1024;
const STARTUP_MANIFEST_LIMIT: usize = startup_metadata::MAX_MANIFEST_BYTES;

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
    pub symbolication: Arc<symbolicate::role_evidence::CurrentSymbolicationContext>,
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
    pub startup_identity: String,
    pub startup_manifest_blake3: Option<String>,
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
struct SnapshotStartup {
    identity: String,
    manifest_bytes: Arc<[u8]>,
    functions_path: PathBuf,
    functions_blake3: String,
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
    startup_managed: bool,
    startup: Option<SnapshotStartup>,
    symbolication: Arc<symbolicate::role_evidence::CurrentSymbolicationContext>,
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

        let startup_state = request.symbolication.roles().startup();
        let startup_managed = !matches!(
            startup_state,
            symbolicate::role_evidence::ArtifactState::Unmanaged
        );
        let startup = match startup_state {
            symbolicate::role_evidence::ArtifactState::Present(expected) => {
                let digest = crate::manifest::blake3_fixed(expected.manifest_blake3());
                let bytes = read_relative(
                    &source,
                    Path::new("startup_metadata/startup.json"),
                    STARTUP_MANIFEST_LIMIT,
                    Some(&digest),
                    "terminal startup manifest",
                )
                .map_err(|error| Error::BadStartupMetadata(error.to_string()))?;
                let exception_identity = exception.as_ref().map(|state| state.identity.as_str());
                let validated = authenticate_startup(
                    &bytes,
                    &runtime,
                    request.image_label,
                    request.toc_name,
                    raw_identity.blake3(),
                    scatter_blake3,
                    exception_identity,
                )?;
                if validated.identity != expected.identity()
                    || validated.manifest_blake3 != expected.manifest_blake3()
                {
                    return Err(Error::BadStartupMetadata(format!(
                        "{} startup snapshot does not match current publication identity",
                        request.image_label
                    )));
                }
                stage_manifest(
                    &kit_root,
                    "startup_metadata",
                    request.image_label,
                    "startup.json",
                    &bytes,
                    "snapshot startup manifest",
                )
                .map_err(|error| Error::BadStartupMetadata(error.to_string()))?;
                let functions_path = request.image_dir.join("decompiled").join("functions.json");
                Some(SnapshotStartup {
                    identity: expected.identity().to_string(),
                    manifest_bytes: bytes.into(),
                    functions_path,
                    functions_blake3: crate::manifest::blake3_fixed(validated.functions_blake3),
                })
            }
            symbolicate::role_evidence::ArtifactState::Absent => {
                clear_staged_leaf(
                    &kit_root,
                    "startup_metadata",
                    request.image_label,
                    "startup.json",
                    "absent snapshot startup manifest",
                )
                .map_err(|error| Error::BadStartupMetadata(error.to_string()))?;
                None
            }
            symbolicate::role_evidence::ArtifactState::Unmanaged => None,
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
            startup_managed,
            startup,
            symbolication: request.symbolication,
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
        clear_staged_leaf(
            &kit_root,
            "startup_metadata",
            image_label,
            "startup.json",
            "raw-only snapshot startup manifest",
        )?;
        let symbolication = Arc::new(
            symbolicate::role_evidence::CurrentSymbolicationContext::new(
                symbolicate::role_evidence::RuntimeBinding::new(
                    image_label,
                    toc_name,
                    image_base,
                    *blake3::hash(&raw).as_bytes(),
                    symbolicate::role_evidence::ArtifactState::Absent,
                ),
                symbolicate::role_evidence::ArtifactState::Absent,
                symbolicate::role_evidence::ArtifactState::Absent,
                symbolicate::role_evidence::ArtifactState::Absent,
            )?,
        );
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
            startup_managed: true,
            startup: None,
            symbolication,
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

    pub(crate) fn startup_manifest(&self) -> Option<PathBuf> {
        self.startup.as_ref().map(|_| {
            self.kit_root_path
                .join("startup_metadata")
                .join(&self.image_label)
                .join("startup.json")
        })
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

    pub(crate) fn startup_identity(&self) -> &str {
        self.startup
            .as_ref()
            .map(|state| state.identity.as_str())
            .unwrap_or("none")
    }

    pub(crate) fn startup_functions_path(&self) -> Option<&Path> {
        self.startup
            .as_ref()
            .map(|state| state.functions_path.as_path())
    }

    pub(crate) fn startup_functions_blake3(&self) -> Option<&str> {
        self.startup
            .as_ref()
            .map(|state| state.functions_blake3.as_str())
    }

    pub(crate) fn exception_context(&self) -> Option<&ExceptionPass2Context> {
        self.exception.as_ref().map(|state| &state.context)
    }

    pub(crate) fn pal_context(&self) -> Option<&symbolicate::PalPass2Context> {
        self.pal.as_ref().map(|state| &state.context)
    }

    pub(crate) fn symbolication_context(
        &self,
    ) -> &symbolicate::role_evidence::CurrentSymbolicationContext {
        &self.symbolication
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
            startup_identity: self.startup_identity().to_string(),
            startup_manifest_blake3: self
                .startup
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
            let exception = if let Some(exception) = &self.exception {
                let (context, validated) = read_exception_pass2_context_exact_with_validated(
                    ExceptionPass2ContextExactInput {
                        manifest_bytes: &exception.manifest_bytes,
                        runtime,
                        image_label: &self.image_label,
                        toc_name: &self.toc_name,
                        expected_identity: &exception.identity,
                        expected_scatter_load_map_blake3: self.scatter_blake3,
                        applied: &exception.applied,
                    },
                )
                .map_err(|error| Error::BadExceptionRoots(error.to_string()))?;
                if context != exception.context {
                    return Err(Error::BadExceptionRoots(
                        "snapshot exception application context changed".into(),
                    ));
                }
                symbolicate::role_evidence::ArtifactState::Present(validated)
            } else if self.exception_managed {
                symbolicate::role_evidence::ArtifactState::Absent
            } else {
                symbolicate::role_evidence::ArtifactState::Unmanaged
            };
            let pal = if let Some(pal) = &self.pal {
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
                symbolicate::role_evidence::ArtifactState::Present(artifact)
            } else if self.pal_managed {
                symbolicate::role_evidence::ArtifactState::Absent
            } else {
                symbolicate::role_evidence::ArtifactState::Unmanaged
            };
            let scatter = match self.scatter_state {
                RuntimeScatterState::Present => symbolicate::role_evidence::ArtifactState::Present(
                    self.scatter_blake3.ok_or_else(|| {
                        Error::DecomposeIncomplete(
                            "snapshot present scatter state has no manifest digest".into(),
                        )
                    })?,
                ),
                RuntimeScatterState::Absent => symbolicate::role_evidence::ArtifactState::Absent,
                RuntimeScatterState::Unmanaged => {
                    symbolicate::role_evidence::ArtifactState::Unmanaged
                }
            };
            let exception_identity = self.exception.as_ref().map(|state| state.identity.as_str());
            let startup = if let Some(startup) = &self.startup {
                let validated = authenticate_startup(
                    &startup.manifest_bytes,
                    runtime,
                    &self.image_label,
                    &self.toc_name,
                    self.raw_identity.blake3(),
                    self.scatter_blake3,
                    exception_identity,
                )?;
                if validated.identity != startup.identity {
                    return Err(Error::BadStartupMetadata(
                        "snapshot startup identity changed".into(),
                    ));
                }
                symbolicate::role_evidence::ArtifactState::Present(validated)
            } else if self.startup_managed {
                symbolicate::role_evidence::ArtifactState::Absent
            } else {
                symbolicate::role_evidence::ArtifactState::Unmanaged
            };
            let projected = symbolicate::role_evidence::CurrentSymbolicationContext::new(
                symbolicate::role_evidence::RuntimeBinding::new(
                    &self.image_label,
                    &self.toc_name,
                    self.image_base,
                    self.raw_identity.blake3(),
                    scatter,
                ),
                exception,
                pal,
                startup,
            )?;
            if projected.runtime() != self.symbolication.runtime() {
                return Err(Error::DecomposeIncomplete(
                    "snapshot symbolication runtime binding changed".into(),
                ));
            }
            if projected.roles().exception() != self.symbolication.roles().exception() {
                return Err(Error::BadExceptionRoots(
                    "snapshot exception role evidence changed".into(),
                ));
            }
            if projected.roles().pal() != self.symbolication.roles().pal() {
                return Err(Error::BadPalTasks(
                    "snapshot PAL role evidence changed".into(),
                ));
            }
            if projected.roles().startup() != self.symbolication.roles().startup() {
                return Err(Error::BadStartupMetadata(
                    "snapshot startup role evidence changed".into(),
                ));
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
        validate_manifest_leaf(
            &self.kit_root,
            self.startup_managed,
            self.startup
                .as_ref()
                .map(|state| state.manifest_bytes.as_ref()),
            "startup_metadata",
            &self.image_label,
            "startup.json",
            STARTUP_MANIFEST_LIMIT,
            "snapshot startup manifest",
        )
        .map_err(|error| Error::BadStartupMetadata(error.to_string()))?;
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

fn authenticate_startup(
    bytes: &[u8],
    runtime: &RuntimeImage<'_>,
    label: &str,
    toc_name: &str,
    image_blake3: [u8; 32],
    scatter_blake3: Option<[u8; 32]>,
    exception_identity: Option<&str>,
) -> Result<startup_metadata::ValidatedStartup> {
    let inventories = peek_startup_inventories(bytes)?;
    let (image_base, image_size) = runtime.image_bounds();
    startup_metadata::read_bytes(
        bytes,
        runtime,
        startup_metadata::StartupArtifactContext {
            label,
            toc_name,
            image_base,
            image_size,
            image_blake3,
            scatter_blake3,
            scatter_entries: &inventories.scatter_entries,
            functions_blake3: inventories.functions_blake3,
            thumb_functions_blake3: inventories.thumb_functions_blake3,
            exception_identity,
            tool_version: env!("CARGO_PKG_VERSION"),
        },
    )
    .map_err(|error| Error::BadStartupMetadata(error.to_string()))
}

struct StartupInventoryBinding {
    scatter_entries: Vec<u32>,
    functions_blake3: [u8; 32],
    thumb_functions_blake3: Option<[u8; 32]>,
}

fn peek_startup_inventories(bytes: &[u8]) -> Result<StartupInventoryBinding> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|error| {
        Error::BadStartupMetadata(format!("startup metadata schema is invalid: {error}"))
    })?;
    let inventories = value.get("inventories").ok_or_else(|| {
        Error::BadStartupMetadata("startup metadata is missing inventories".into())
    })?;
    let functions = inventories
        .get("functions_blake3")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            Error::BadStartupMetadata("startup metadata is missing functions_blake3".into())
        })?;
    let functions_blake3 = crate::execution_ranges::parse_blake3(functions)
        .map_err(|error| Error::BadStartupMetadata(error.to_string()))?;
    let thumb_functions_blake3 = match inventories.get("thumb_functions_blake3") {
        None | Some(serde_json::Value::Null) => None,
        Some(value) => Some(
            crate::execution_ranges::parse_blake3(value.as_str().ok_or_else(|| {
                Error::BadStartupMetadata(
                    "startup metadata thumb_functions_blake3 is not a string".into(),
                )
            })?)
            .map_err(|error| Error::BadStartupMetadata(error.to_string()))?,
        ),
    };
    let entries = value
        .get("runtime")
        .and_then(|runtime| runtime.get("scatter_entries_used"))
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            Error::BadStartupMetadata("startup metadata is missing scatter_entries_used".into())
        })?;
    let mut scatter_entries = Vec::new();
    scatter_entries
        .try_reserve_exact(entries.len())
        .map_err(|_| {
            Error::BadStartupMetadata("startup scatter-entry projection allocation failed".into())
        })?;
    for entry in entries {
        let Some(value) = entry.as_u64() else {
            return Err(Error::BadStartupMetadata(
                "startup scatter entry is not an integer".into(),
            ));
        };
        let value = u32::try_from(value)
            .map_err(|_| Error::BadStartupMetadata("startup scatter entry exceeds u32".into()))?;
        scatter_entries.push(value);
    }
    Ok(StartupInventoryBinding {
        scatter_entries,
        functions_blake3,
        thumb_functions_blake3,
    })
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
    use crate::arm32::SystemDirection;
    use crate::decompile::{
        AppliedPalTasks, RuntimeExceptionState, RuntimeScatterState, RuntimeTaskState,
    };
    use crate::execution_ranges::{DecodeIsa, FunctionOwner};
    use crate::pal_tasks::test_support::BASE;
    use crate::startup_metadata::{
        HardwareInit, PrivilegedClass, PrivilegedOp, Section, StackGuard, StartupApplication,
        StartupArtifactContext, StartupPlan, StartupRole, materialize_image, read_bytes,
    };
    use crate::symbolicate::role_evidence::{
        ArtifactState, CurrentSymbolicationContext, RuntimeBinding,
    };

    struct CombinedFixture {
        _root: tempfile::TempDir,
        image: std::path::PathBuf,
        kit: std::path::PathBuf,
        snapshot: TerminalPass2Snapshot,
        symbolication:
            std::sync::Arc<crate::symbolicate::role_evidence::CurrentSymbolicationContext>,
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
        let symbolication = std::sync::Arc::new(
            crate::symbolicate::role_evidence::CurrentSymbolicationContext::from_retained(
                &image, "02_MAIN", "MAIN", BASE,
            )
            .unwrap(),
        );
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
            symbolication: std::sync::Arc::clone(&symbolication),
        })
        .unwrap();

        CombinedFixture {
            _root: root,
            image,
            kit,
            snapshot,
            symbolication,
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

    fn raw_only_symbolication(
        image: &std::path::Path,
    ) -> std::sync::Arc<crate::symbolicate::role_evidence::CurrentSymbolicationContext> {
        let raw = std::fs::read(image.join("00_BOOT.bin")).unwrap();
        std::sync::Arc::new(
            crate::symbolicate::role_evidence::CurrentSymbolicationContext::new(
                crate::symbolicate::role_evidence::RuntimeBinding::new(
                    "00_BOOT",
                    "BOOT",
                    0x4001_0000,
                    *blake3::hash(&raw).as_bytes(),
                    crate::symbolicate::role_evidence::ArtifactState::Absent,
                ),
                crate::symbolicate::role_evidence::ArtifactState::Absent,
                crate::symbolicate::role_evidence::ArtifactState::Absent,
                crate::symbolicate::role_evidence::ArtifactState::Absent,
            )
            .unwrap(),
        )
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
            symbolication: raw_only_symbolication(image),
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
    fn terminal_snapshot_shares_and_revalidates_symbolication_context() {
        let raw = combined_fixture();
        assert!(std::ptr::eq(
            std::sync::Arc::as_ptr(&raw.symbolication),
            raw.snapshot.symbolication_context(),
        ));
        std::fs::write(raw.snapshot.raw_path(), [0x22; 0x4700]).unwrap();
        assert!(raw.snapshot.validate_for_spawn().is_err());
        assert!(std::ptr::eq(
            std::sync::Arc::as_ptr(&raw.symbolication),
            raw.snapshot.symbolication_context(),
        ));

        let scatter = combined_fixture();
        std::fs::write(
            scatter.kit.join("scatter/02_MAIN/blocks/03-copy.bin"),
            b"changed scatter payload",
        )
        .unwrap();
        assert!(scatter.snapshot.validate_for_spawn().is_err());
        assert!(std::ptr::eq(
            std::sync::Arc::as_ptr(&scatter.symbolication),
            scatter.snapshot.symbolication_context(),
        ));

        let exception = combined_fixture();
        std::fs::write(
            exception.snapshot.exception_manifest().unwrap(),
            b"changed exception manifest",
        )
        .unwrap();
        assert!(exception.snapshot.validate_for_spawn().is_err());
        assert!(std::ptr::eq(
            std::sync::Arc::as_ptr(&exception.symbolication),
            exception.snapshot.symbolication_context(),
        ));

        let pal = combined_fixture();
        std::fs::write(
            pal.snapshot.pal_manifest().unwrap(),
            b"changed PAL manifest",
        )
        .unwrap();
        assert!(pal.snapshot.validate_for_spawn().is_err());
        assert!(std::ptr::eq(
            std::sync::Arc::as_ptr(&pal.symbolication),
            pal.snapshot.symbolication_context(),
        ));
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
            symbolication: raw_only_symbolication(&image),
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

    fn startup_digest(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn published_startup(
        image: &std::path::Path,
        label: &str,
        toc_name: &str,
        raw: &[u8],
    ) -> (Vec<u8>, String, crate::startup_metadata::ValidatedStartup) {
        let image_blake3 = *blake3::hash(raw).as_bytes();
        let image_size = u32::try_from(raw.len()).unwrap();
        let plan = StartupPlan {
            image_label: label.to_owned(),
            toc_name: toc_name.to_owned(),
            image_base: 0x4001_0000,
            image_size,
            hardware_init: Section::Present(HardwareInit {
                entry: 0x4001_0010,
                isa: DecodeIsa::Arm,
                owner: FunctionOwner::Ghidra,
                execution_blake3: startup_digest(0x21),
            }),
            stack_guard: Section::Present(StackGuard {
                entry: 0x4001_0020,
                isa: DecodeIsa::Arm,
                owner: FunctionOwner::Ghidra,
                execution_blake3: startup_digest(0x22),
                non_return: true,
            }),
            compiler: Section::Absent,
            privileged_ops: vec![PrivilegedOp {
                pc: 0x4001_0000,
                isa: DecodeIsa::Arm,
                entry: 0x4001_0000,
                owner: FunctionOwner::Ghidra,
                execution_blake3: startup_digest(0x24),
                direction: SystemDirection::Write,
                class: PrivilegedClass::Vbar,
                coprocessor: Some(15),
                opcode1: Some(0),
                crn: Some(12),
                crm: Some(0),
                opcode2: Some(0),
                register: None,
                immediate: None,
            }],
            applications: vec![
                StartupApplication {
                    role: StartupRole::HardwareInit,
                    entry: 0x4001_0010,
                    isa: DecodeIsa::Arm,
                    desired_primary: StartupRole::HardwareInit.desired_primary(),
                    role_label: StartupRole::HardwareInit.role_label(),
                    set_no_return: false,
                },
                StartupApplication {
                    role: StartupRole::StackGuard,
                    entry: 0x4001_0020,
                    isa: DecodeIsa::Arm,
                    desired_primary: StartupRole::StackGuard.desired_primary(),
                    role_label: StartupRole::StackGuard.role_label(),
                    set_no_return: true,
                },
            ],
        };
        let context = StartupArtifactContext {
            label,
            toc_name,
            image_base: 0x4001_0000,
            image_size,
            image_blake3,
            scatter_blake3: None,
            scatter_entries: &[],
            functions_blake3: startup_digest(0x31),
            thumb_functions_blake3: None,
            exception_identity: None,
            tool_version: env!("CARGO_PKG_VERSION"),
        };
        let materialized = materialize_image(&plan, context, image).unwrap();
        let bytes = std::fs::read(image.join(&materialized.relative_path)).unwrap();
        let runtime =
            crate::runtime_image::RuntimeImage::from_plan(raw, 0x4001_0000, None).unwrap();
        let validated = read_bytes(&bytes, &runtime, context).unwrap();
        (bytes, materialized.identity, validated)
    }

    fn snapshot_with_startup(
        image: &std::path::Path,
        kit: &std::path::Path,
        startup: ArtifactState<crate::startup_metadata::ValidatedStartup>,
    ) -> TerminalPass2Snapshot {
        let raw = std::fs::read(image.join("00_BOOT.bin")).unwrap();
        let symbolication = std::sync::Arc::new(
            CurrentSymbolicationContext::new(
                RuntimeBinding::new(
                    "00_BOOT",
                    "BOOT",
                    0x4001_0000,
                    *blake3::hash(&raw).as_bytes(),
                    ArtifactState::Absent,
                ),
                ArtifactState::Absent,
                ArtifactState::Absent,
                startup,
            )
            .unwrap(),
        );
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
            symbolication,
        })
        .unwrap()
    }

    #[test]
    fn snapshot_stages_startup_bytes_only_when_present() {
        let (_present_root, present_image, present_kit) = raw_only_fixture();
        let raw = std::fs::read(present_image.join("00_BOOT.bin")).unwrap();
        let (bytes, identity, validated) =
            published_startup(&present_image, "00_BOOT", "BOOT", &raw);
        let present = snapshot_with_startup(
            &present_image,
            &present_kit,
            ArtifactState::Present(validated),
        );
        let staged = present_kit.join("startup_metadata/00_BOOT/startup.json");
        assert_eq!(present.startup_identity(), identity.as_str());
        assert_ne!(present.startup_identity(), "none");
        assert_eq!(present.startup_manifest(), Some(staged.clone()));
        assert_eq!(std::fs::read(&staged).unwrap(), bytes);

        let (_absent_root, absent_image, absent_kit) = raw_only_fixture();
        std::fs::create_dir_all(absent_kit.join("startup_metadata/00_BOOT")).unwrap();
        std::fs::write(
            absent_kit.join("startup_metadata/00_BOOT/startup.json"),
            b"stale startup",
        )
        .unwrap();
        let absent = snapshot_with_startup(&absent_image, &absent_kit, ArtifactState::Absent);
        assert_eq!(absent.startup_identity(), "none");
        assert_eq!(
            absent
                .startup_manifest()
                .map(|path| path.to_string_lossy().into_owned())
                .unwrap_or_else(|| "-".to_string()),
            "-"
        );
        assert!(
            !absent_kit
                .join("startup_metadata/00_BOOT/startup.json")
                .exists()
        );
    }

    #[test]
    fn snapshot_rejects_startup_drift_at_pre_spawn_gate() {
        let (_root, image, kit) = raw_only_fixture();
        let raw = std::fs::read(image.join("00_BOOT.bin")).unwrap();
        let (_bytes, _identity, validated) = published_startup(&image, "00_BOOT", "BOOT", &raw);
        let snapshot = snapshot_with_startup(&image, &kit, ArtifactState::Present(validated));
        std::fs::write(
            snapshot.startup_manifest().unwrap(),
            b"changed startup manifest",
        )
        .unwrap();
        let error = snapshot.validate_for_spawn().unwrap_err();
        assert!(
            error.to_string().to_lowercase().contains("startup"),
            "{error}"
        );
    }

    #[test]
    fn leftover_startup_json_without_publication_is_unmanaged_not_current() {
        let (_root, image, kit) = raw_only_fixture();
        std::fs::create_dir_all(image.join("startup_metadata")).unwrap();
        std::fs::write(
            image.join("startup_metadata/startup.json"),
            b"leftover image",
        )
        .unwrap();
        std::fs::create_dir_all(kit.join("startup_metadata/00_BOOT")).unwrap();
        std::fs::write(
            kit.join("startup_metadata/00_BOOT/startup.json"),
            b"leftover kit",
        )
        .unwrap();
        let snapshot = snapshot_with_startup(&image, &kit, ArtifactState::Unmanaged);
        assert_eq!(snapshot.startup_identity(), "none");
        assert_eq!(
            snapshot
                .startup_manifest()
                .map(|path| path.to_string_lossy().into_owned())
                .unwrap_or_else(|| "-".to_string()),
            "-"
        );
        assert_eq!(
            std::fs::read(kit.join("startup_metadata/00_BOOT/startup.json")).unwrap(),
            b"leftover kit"
        );
        snapshot.validate_for_spawn().unwrap();
    }
}
