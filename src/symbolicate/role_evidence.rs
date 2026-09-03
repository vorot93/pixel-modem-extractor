use crate::error::{Error, Result};
use crate::exception_roots::{self, ValidatedExceptionRoots};
use crate::execution_ranges::DecodeIsa;
use crate::pal_tasks::{self, ValidatedTaskArtifact};
use crate::runtime_image::RuntimeImage;
use crate::startup_metadata::{self, ValidatedStartup};
use crate::trusted_fs::TrustedDirectory;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read as _;
use std::path::Path;

const EXCEPTION_MANIFEST_MAX_BYTES: u64 = 1024 * 1024;
const RAW_IMAGE_MAX_BYTES: u64 = u32::MAX as u64;
const WINDOWS_RESERVED_COMPONENTS: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ArtifactState<T> {
    Unmanaged,
    Absent,
    Present(T),
}

impl<T> ArtifactState<T> {
    pub(crate) const fn present(&self) -> Option<&T> {
        match self {
            Self::Present(value) => Some(value),
            Self::Unmanaged | Self::Absent => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuntimeBinding {
    image_label: String,
    toc_name: String,
    image_base: u32,
    image_blake3: [u8; 32],
    scatter: ArtifactState<[u8; 32]>,
}

impl RuntimeBinding {
    pub(crate) fn new(
        image_label: impl Into<String>,
        toc_name: impl Into<String>,
        image_base: u32,
        image_blake3: [u8; 32],
        scatter: ArtifactState<[u8; 32]>,
    ) -> Self {
        Self {
            image_label: image_label.into(),
            toc_name: toc_name.into(),
            image_base,
            image_blake3,
            scatter,
        }
    }

    pub(crate) const fn image_base(&self) -> u32 {
        self.image_base
    }

    pub(crate) const fn scatter(&self) -> &ArtifactState<[u8; 32]> {
        &self.scatter
    }

    fn role_scatter_blake3(&self) -> Option<[u8; 32]> {
        match self.scatter {
            ArtifactState::Present(digest) => Some(digest),
            ArtifactState::Absent | ArtifactState::Unmanaged => None,
        }
    }

    fn validate(&self) -> Result<()> {
        validate_component(&self.image_label, "symbolication image label")?;
        validate_component(&self.toc_name, "symbolication TOC name")?;
        if crate::manifest::toc_name(&self.image_label) != self.toc_name {
            return Err(model_error(
                "symbolication TOC name does not match the image label",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExceptionRoleClaim {
    table_kind: &'static str,
    table_address: u32,
    slot_address: u32,
    role: &'static str,
}

impl ExceptionRoleClaim {
    pub(crate) const fn table_kind(&self) -> &'static str {
        self.table_kind
    }

    pub(crate) const fn table_address(&self) -> u32 {
        self.table_address
    }

    pub(crate) const fn slot_address(&self) -> u32 {
        self.slot_address
    }

    pub(crate) const fn role(&self) -> &'static str {
        self.role
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExceptionRoleApplication {
    entry: u32,
    isa: DecodeIsa,
    desired_primary: Option<String>,
    claims: Vec<ExceptionRoleClaim>,
}

impl ExceptionRoleApplication {
    #[cfg(test)]
    pub(crate) const fn entry(&self) -> u32 {
        self.entry
    }

    #[cfg(test)]
    pub(crate) const fn isa(&self) -> DecodeIsa {
        self.isa
    }

    pub(crate) fn desired_primary(&self) -> Option<&str> {
        self.desired_primary.as_deref()
    }

    pub(crate) fn claims(&self) -> &[ExceptionRoleClaim] {
        &self.claims
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExceptionRoleSet {
    identity: String,
    manifest_blake3: [u8; 32],
    image_label: String,
    toc_name: String,
    image_base: u32,
    image_blake3: [u8; 32],
    scatter_load_map_blake3: Option<[u8; 32]>,
    applications: Vec<ExceptionRoleApplication>,
    application_index: BTreeMap<(u32, DecodeIsa), usize>,
}

impl ExceptionRoleSet {
    fn from_validated(validated: &ValidatedExceptionRoots) -> Result<Self> {
        let application_count = validated.plan.applications.len();
        if application_count > exception_roots::MAX_ROOTS {
            return Err(model_error(format!(
                "exception application limit exceeded: {application_count} > {}",
                exception_roots::MAX_ROOTS
            )));
        }
        if validated.plan.tables.is_empty()
            || validated.plan.tables.len() > exception_roots::MAX_TABLES
            || validated.plan.roots.is_empty()
            || validated.plan.roots.len() > exception_roots::MAX_ROOTS
        {
            return Err(model_error(
                "exception projection has invalid table or root counts",
            ));
        }
        if validated.image_label != validated.plan.image_label
            || validated.toc_name != validated.plan.toc_name
        {
            return Err(model_error(
                "exception projection image identity differs from its plan",
            ));
        }
        let expected_identity = format!(
            "v1:{}:{}:{}",
            crate::manifest::blake3_fixed(validated.manifest_blake3),
            validated.plan.tables.len(),
            validated.plan.roots.len()
        );
        if validated.identity != expected_identity {
            return Err(model_error(
                "exception projection identity differs from its manifest and counts",
            ));
        }

        let mut applications = Vec::new();
        applications
            .try_reserve_exact(application_count)
            .map_err(|_| model_error("exception application projection allocation failed"))?;
        let mut application_index = BTreeMap::new();
        let mut claim_count = 0usize;
        for application in &validated.plan.applications {
            validate_primary(application.desired_primary.as_deref(), "exception primary")?;
            claim_count = claim_count
                .checked_add(application.claims.len())
                .ok_or_else(|| model_error("exception claim count overflows the host"))?;
            let claim_limit = exception_roots::MAX_TABLES
                .checked_mul(exception_roots::VECTOR_SLOTS)
                .ok_or_else(|| model_error("exception claim limit overflows the host"))?;
            if claim_count > claim_limit {
                return Err(model_error(format!(
                    "exception claim limit exceeded: {claim_count} > {claim_limit}"
                )));
            }
            if application.claims.is_empty() {
                return Err(model_error("exception application has no role claims"));
            }
            let key = (application.entry, application.isa.decode_isa());
            if application_index.insert(key, applications.len()).is_some() {
                return Err(model_error(format!(
                    "duplicate exception application at {:#010x} ({:?})",
                    key.0, key.1
                )));
            }
            let claims = application
                .claims
                .iter()
                .map(|claim| ExceptionRoleClaim {
                    table_kind: match claim.table_kind {
                        exception_roots::VectorTableKind::Initial => "initial",
                        exception_roots::VectorTableKind::Relocated => "relocated",
                    },
                    table_address: claim.table_address,
                    slot_address: claim.slot_address,
                    role: claim.role.as_wire(),
                })
                .collect();
            applications.push(ExceptionRoleApplication {
                entry: application.entry,
                isa: application.isa.decode_isa(),
                desired_primary: application.desired_primary.clone(),
                claims,
            });
        }

        Ok(Self {
            identity: validated.identity.clone(),
            manifest_blake3: validated.manifest_blake3,
            image_label: validated.image_label.clone(),
            toc_name: validated.toc_name.clone(),
            image_base: validated.plan.image_base,
            image_blake3: validated.image_blake3,
            scatter_load_map_blake3: validated.scatter_load_map_blake3,
            applications,
            application_index,
        })
    }

    pub(crate) fn identity(&self) -> &str {
        &self.identity
    }

    pub(crate) fn reset_root(&self) -> Option<(u32, DecodeIsa)> {
        self.applications.iter().find_map(|application| {
            application
                .claims
                .iter()
                .any(|claim| claim.role() == "reset" && claim.table_kind() == "initial")
                .then_some((application.entry, application.isa))
        })
    }

    pub(crate) const fn manifest_blake3(&self) -> [u8; 32] {
        self.manifest_blake3
    }

    #[cfg(test)]
    pub(crate) fn applications(&self) -> &[ExceptionRoleApplication] {
        &self.applications
    }

    pub(crate) fn application(
        &self,
        entry: u32,
        isa: DecodeIsa,
    ) -> Option<&ExceptionRoleApplication> {
        self.application_index
            .get(&(entry, isa))
            .and_then(|index| self.applications.get(*index))
    }

    fn validate_runtime_binding(&self, runtime: &RuntimeBinding) -> Result<()> {
        if self.image_label != runtime.image_label
            || self.toc_name != runtime.toc_name
            || self.image_base != runtime.image_base
            || self.image_blake3 != runtime.image_blake3
        {
            return Err(model_error(
                "exception role evidence does not match the runtime raw-image binding",
            ));
        }
        if self.scatter_load_map_blake3 != runtime.role_scatter_blake3() {
            return Err(model_error(
                "exception role evidence does not match the runtime scatter binding",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PalRoleTask {
    task_index: u32,
    name: String,
    slot: u32,
    priority: u8,
    stack_size: u32,
}

impl PalRoleTask {
    pub(crate) const fn task_index(&self) -> u32 {
        self.task_index
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) const fn slot(&self) -> u32 {
        self.slot
    }

    pub(crate) const fn priority(&self) -> u8 {
        self.priority
    }

    pub(crate) const fn stack_size(&self) -> u32 {
        self.stack_size
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PalRoleApplication {
    entry: u32,
    isa: DecodeIsa,
    desired_primary: String,
    tasks: Vec<PalRoleTask>,
}

impl PalRoleApplication {
    #[cfg(test)]
    pub(crate) const fn entry(&self) -> u32 {
        self.entry
    }

    #[cfg(test)]
    pub(crate) const fn isa(&self) -> DecodeIsa {
        self.isa
    }

    pub(crate) fn desired_primary(&self) -> &str {
        &self.desired_primary
    }

    pub(crate) fn tasks(&self) -> &[PalRoleTask] {
        &self.tasks
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PalRoleSet {
    identity: String,
    manifest_blake3: [u8; 32],
    image_label: String,
    image_base: u32,
    image_blake3: [u8; 32],
    scatter_load_map_blake3: Option<[u8; 32]>,
    applications: Vec<PalRoleApplication>,
    application_index: BTreeMap<(u32, DecodeIsa), usize>,
}

impl PalRoleSet {
    fn from_validated(validated: &ValidatedTaskArtifact) -> Result<Self> {
        let task_count = validated.plan.tasks.len();
        if task_count > pal_tasks::MAX_TABLE_CAPACITY as usize {
            return Err(model_error(format!(
                "PAL task-record limit exceeded: {task_count} > {}",
                pal_tasks::MAX_TABLE_CAPACITY
            )));
        }
        let application_count = validated.plan.applications.len();
        if application_count > pal_tasks::MAX_TABLE_CAPACITY as usize {
            return Err(model_error(format!(
                "PAL application limit exceeded: {application_count} > {}",
                pal_tasks::MAX_TABLE_CAPACITY
            )));
        }
        if validated.plan.table.count as usize != task_count {
            return Err(model_error(
                "PAL projection task count differs from its table count",
            ));
        }
        let expected_identity = format!(
            "v1:{}:{task_count}:{application_count}",
            crate::manifest::blake3_fixed(validated.manifest_blake3)
        );
        if validated.identity != expected_identity {
            return Err(model_error(
                "PAL projection identity differs from its manifest and counts",
            ));
        }

        let mut tasks_by_index = BTreeMap::new();
        for task in &validated.plan.tasks {
            if task.name.len() > pal_tasks::MAX_TASK_NAME_BYTES || !task.name.is_ascii() {
                return Err(model_error(
                    "PAL task name exceeds its strict projection bound",
                ));
            }
            if tasks_by_index.insert(task.index, task).is_some() {
                return Err(model_error(format!(
                    "duplicate PAL task index {}",
                    task.index
                )));
            }
        }

        let mut applications = Vec::new();
        applications
            .try_reserve_exact(application_count)
            .map_err(|_| model_error("PAL application projection allocation failed"))?;
        let mut application_index = BTreeMap::new();
        let mut referenced_tasks = BTreeSet::new();
        for application in &validated.plan.applications {
            validate_primary(Some(&application.desired_primary), "PAL primary")?;
            let key = (application.entry, application.isa.decode_isa());
            if application_index.insert(key, applications.len()).is_some() {
                return Err(model_error(format!(
                    "duplicate PAL application at {:#010x} ({:?})",
                    key.0, key.1
                )));
            }
            if application.task_indices.is_empty() {
                return Err(model_error("PAL application has no task records"));
            }
            let mut tasks = Vec::new();
            tasks
                .try_reserve_exact(application.task_indices.len())
                .map_err(|_| model_error("PAL task projection allocation failed"))?;
            for task_index in &application.task_indices {
                if !referenced_tasks.insert(*task_index) {
                    return Err(model_error(format!(
                        "PAL task index {task_index} appears in more than one application"
                    )));
                }
                let task = tasks_by_index.get(task_index).ok_or_else(|| {
                    model_error(format!(
                        "PAL application references missing task index {task_index}"
                    ))
                })?;
                if task.entry != application.entry || task.isa != application.isa {
                    return Err(model_error(format!(
                        "PAL task index {task_index} does not match its exact entry and ISA"
                    )));
                }
                tasks.push(PalRoleTask {
                    task_index: task.index,
                    name: task.name.clone(),
                    slot: task.slot,
                    priority: task.priority,
                    stack_size: task.stack_size,
                });
            }
            applications.push(PalRoleApplication {
                entry: application.entry,
                isa: application.isa.decode_isa(),
                desired_primary: application.desired_primary.clone(),
                tasks,
            });
        }
        if referenced_tasks.len() != tasks_by_index.len() {
            return Err(model_error(
                "PAL applications do not cover every task record exactly once",
            ));
        }

        Ok(Self {
            identity: validated.identity.clone(),
            manifest_blake3: validated.manifest_blake3,
            image_label: validated.image_label.clone(),
            image_base: validated.plan.image_base,
            image_blake3: validated.image_blake3,
            scatter_load_map_blake3: validated.scatter_load_map_blake3,
            applications,
            application_index,
        })
    }

    pub(crate) fn identity(&self) -> &str {
        &self.identity
    }

    pub(crate) const fn manifest_blake3(&self) -> [u8; 32] {
        self.manifest_blake3
    }

    pub(crate) const fn scatter_load_map_blake3(&self) -> Option<[u8; 32]> {
        self.scatter_load_map_blake3
    }

    #[cfg(test)]
    pub(crate) fn applications(&self) -> &[PalRoleApplication] {
        &self.applications
    }

    pub(crate) fn application(&self, entry: u32, isa: DecodeIsa) -> Option<&PalRoleApplication> {
        self.application_index
            .get(&(entry, isa))
            .and_then(|index| self.applications.get(*index))
    }

    fn validate_runtime_binding(&self, runtime: &RuntimeBinding) -> Result<()> {
        if self.image_label != runtime.image_label
            || self.image_base != runtime.image_base
            || self.image_blake3 != runtime.image_blake3
        {
            return Err(model_error(
                "PAL role evidence does not match the runtime raw-image binding",
            ));
        }
        if matches!(runtime.scatter, ArtifactState::Unmanaged) {
            return Err(model_error(
                "PAL role evidence cannot bind an unmanaged scatter state",
            ));
        }
        if self.scatter_load_map_blake3 != runtime.role_scatter_blake3() {
            return Err(model_error(
                "PAL role evidence does not match the runtime scatter binding",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StartupRoleApplication {
    entry: u32,
    isa: DecodeIsa,
    desired_primary: String,
    role: &'static str,
    set_no_return: bool,
}

impl StartupRoleApplication {
    #[cfg(test)]
    pub(crate) const fn entry(&self) -> u32 {
        self.entry
    }

    #[cfg(test)]
    pub(crate) const fn isa(&self) -> DecodeIsa {
        self.isa
    }

    pub(crate) fn desired_primary(&self) -> &str {
        &self.desired_primary
    }

    pub(crate) const fn role(&self) -> &'static str {
        self.role
    }

    pub(crate) const fn set_no_return(&self) -> bool {
        self.set_no_return
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StartupRoleSet {
    identity: String,
    manifest_blake3: [u8; 32],
    image_label: String,
    toc_name: String,
    image_base: u32,
    image_blake3: [u8; 32],
    scatter_load_map_blake3: Option<[u8; 32]>,
    applications: Vec<StartupRoleApplication>,
    application_index: BTreeMap<(u32, DecodeIsa), usize>,
}

impl StartupRoleSet {
    fn from_validated(validated: &ValidatedStartup) -> Result<Self> {
        let application_count = validated.plan.applications.len();
        if application_count > startup_metadata::MAX_APPLICATIONS {
            return Err(model_error(format!(
                "startup application limit exceeded: {application_count} > {}",
                startup_metadata::MAX_APPLICATIONS
            )));
        }
        let no_return_roots = validated
            .plan
            .applications
            .iter()
            .filter(|application| application.set_no_return)
            .count();
        let expected_identity = format!(
            "v1:{}:{application_count}:{no_return_roots}:{}",
            crate::manifest::blake3_fixed(validated.manifest_blake3),
            validated.plan.privileged_ops.len()
        );
        if validated.identity != expected_identity {
            return Err(model_error(
                "startup projection identity differs from its manifest and counts",
            ));
        }
        if validated.image_label != validated.plan.image_label
            || validated.toc_name != validated.plan.toc_name
        {
            return Err(model_error(
                "startup projection image identity differs from its plan",
            ));
        }

        let mut applications = Vec::new();
        applications
            .try_reserve_exact(application_count)
            .map_err(|_| model_error("startup application projection allocation failed"))?;
        let mut application_index = BTreeMap::new();
        for application in &validated.plan.applications {
            validate_primary(Some(application.desired_primary), "startup primary")?;
            let key = (application.entry, application.isa);
            if application_index.insert(key, applications.len()).is_some() {
                return Err(model_error(format!(
                    "duplicate startup application at {:#010x} ({:?})",
                    key.0, key.1
                )));
            }
            applications.push(StartupRoleApplication {
                entry: application.entry,
                isa: application.isa,
                desired_primary: application.desired_primary.to_string(),
                role: application.role.as_wire(),
                set_no_return: application.set_no_return,
            });
        }

        Ok(Self {
            identity: validated.identity.clone(),
            manifest_blake3: validated.manifest_blake3,
            image_label: validated.image_label.clone(),
            toc_name: validated.toc_name.clone(),
            image_base: validated.plan.image_base,
            image_blake3: validated.image_blake3,
            scatter_load_map_blake3: validated.scatter_blake3,
            applications,
            application_index,
        })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn identity(&self) -> &str {
        &self.identity
    }

    pub(crate) const fn manifest_blake3(&self) -> [u8; 32] {
        self.manifest_blake3
    }

    #[cfg(test)]
    pub(crate) fn applications(&self) -> &[StartupRoleApplication] {
        &self.applications
    }

    pub(crate) fn application(
        &self,
        entry: u32,
        isa: DecodeIsa,
    ) -> Option<&StartupRoleApplication> {
        self.application_index
            .get(&(entry, isa))
            .and_then(|index| self.applications.get(*index))
    }

    fn validate_runtime_binding(&self, runtime: &RuntimeBinding) -> Result<()> {
        if self.image_label != runtime.image_label
            || self.toc_name != runtime.toc_name
            || self.image_base != runtime.image_base
            || self.image_blake3 != runtime.image_blake3
        {
            return Err(model_error(
                "startup role evidence does not match the runtime raw-image binding",
            ));
        }
        if self.scatter_load_map_blake3 != runtime.role_scatter_blake3() {
            return Err(model_error(
                "startup role evidence does not match the runtime scatter binding",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthenticatedRoleEvidence {
    exception: ArtifactState<ExceptionRoleSet>,
    pal: ArtifactState<PalRoleSet>,
    startup: ArtifactState<StartupRoleSet>,
}

impl AuthenticatedRoleEvidence {
    fn from_validated(
        exception: ArtifactState<ValidatedExceptionRoots>,
        pal: ArtifactState<ValidatedTaskArtifact>,
        startup: ArtifactState<ValidatedStartup>,
    ) -> Result<Self> {
        let exception = match exception {
            ArtifactState::Unmanaged => ArtifactState::Unmanaged,
            ArtifactState::Absent => ArtifactState::Absent,
            ArtifactState::Present(validated) => {
                ArtifactState::Present(ExceptionRoleSet::from_validated(&validated)?)
            }
        };
        let pal = match pal {
            ArtifactState::Unmanaged => ArtifactState::Unmanaged,
            ArtifactState::Absent => ArtifactState::Absent,
            ArtifactState::Present(validated) => {
                ArtifactState::Present(PalRoleSet::from_validated(&validated)?)
            }
        };
        let startup = match startup {
            ArtifactState::Unmanaged => ArtifactState::Unmanaged,
            ArtifactState::Absent => ArtifactState::Absent,
            ArtifactState::Present(validated) => {
                ArtifactState::Present(StartupRoleSet::from_validated(&validated)?)
            }
        };
        Ok(Self {
            exception,
            pal,
            startup,
        })
    }

    pub(crate) const fn exception(&self) -> &ArtifactState<ExceptionRoleSet> {
        &self.exception
    }

    pub(crate) const fn pal(&self) -> &ArtifactState<PalRoleSet> {
        &self.pal
    }

    pub(crate) const fn startup(&self) -> &ArtifactState<StartupRoleSet> {
        &self.startup
    }

    fn validate_runtime_binding(&self, runtime: &RuntimeBinding) -> Result<()> {
        if let ArtifactState::Present(exception) = &self.exception {
            exception.validate_runtime_binding(runtime)?;
        }
        if let ArtifactState::Present(pal) = &self.pal {
            pal.validate_runtime_binding(runtime)?;
        }
        if let ArtifactState::Present(startup) = &self.startup {
            startup.validate_runtime_binding(runtime)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CurrentSymbolicationContext {
    runtime: RuntimeBinding,
    roles: AuthenticatedRoleEvidence,
}

impl CurrentSymbolicationContext {
    pub(crate) fn new(
        runtime: RuntimeBinding,
        exception: ArtifactState<ValidatedExceptionRoots>,
        pal: ArtifactState<ValidatedTaskArtifact>,
        startup: ArtifactState<ValidatedStartup>,
    ) -> Result<Self> {
        runtime.validate()?;
        let roles = AuthenticatedRoleEvidence::from_validated(exception, pal, startup)?;
        roles.validate_runtime_binding(&runtime)?;
        Ok(Self { runtime, roles })
    }

    pub(crate) fn from_retained(
        image_dir: &Path,
        image_label: &str,
        toc_name: &str,
        image_base: u32,
    ) -> Result<Self> {
        validate_image_dir(image_dir, image_label)?;
        let image = TrustedDirectory::new(image_dir, "retained symbolication image directory")?;
        let raw = read_raw_image(&image, image_label)?;
        let image_blake3 = *blake3::hash(&raw).as_bytes();
        let (scatter, runtime) = retained_runtime(
            &image,
            &raw,
            image_label,
            toc_name,
            image_base,
            image_blake3,
        )?;
        let role_scatter_blake3 = match scatter {
            ArtifactState::Present(digest) => Some(digest),
            ArtifactState::Absent | ArtifactState::Unmanaged => None,
        };

        let exception = if owned_leaf_present(
            &image,
            "exception_roots",
            "roots.json",
            "retained exception-root manifest",
        )? {
            let bytes = read_nested_leaf(
                &image,
                "exception_roots",
                "roots.json",
                EXCEPTION_MANIFEST_MAX_BYTES,
                "retained exception-root manifest",
            )?;
            ArtifactState::Present(exception_roots::read_bytes(
                &bytes,
                &runtime,
                exception_roots::ExceptionArtifactContext {
                    label: image_label,
                    toc_name,
                    image_blake3,
                    scatter_load_map_blake3: role_scatter_blake3,
                },
            )?)
        } else {
            ArtifactState::Absent
        };

        let pal = if toc_name == "MAIN" {
            if owned_leaf_present(
                &image,
                "pal_tasks",
                "tasks.json",
                "retained PAL task manifest",
            )? {
                ArtifactState::Present(pal_tasks::read_from_trusted(
                    &image,
                    Path::new("pal_tasks/tasks.json"),
                    &runtime,
                    pal_tasks::TaskArtifactContext {
                        label: image_label,
                        image_blake3,
                        scatter_load_map_blake3: role_scatter_blake3,
                    },
                )?)
            } else {
                ArtifactState::Absent
            }
        } else {
            ArtifactState::Unmanaged
        };

        let exception_identity = match &exception {
            ArtifactState::Present(validated) => Some(validated.identity.as_str()),
            ArtifactState::Absent | ArtifactState::Unmanaged => None,
        };
        let startup = if owned_leaf_present(
            &image,
            "startup_metadata",
            "startup.json",
            "retained startup metadata manifest",
        )? {
            let bytes = read_nested_leaf(
                &image,
                "startup_metadata",
                "startup.json",
                startup_metadata::MAX_MANIFEST_BYTES as u64,
                "retained startup metadata manifest",
            )?;
            let image_size = u32::try_from(raw.len()).map_err(|_| {
                current_error("raw image size exceeds the startup metadata u32 domain")
            })?;
            let binding = retained_startup_binding(&bytes)?;
            ArtifactState::Present(startup_metadata::read_bytes(
                &bytes,
                &runtime,
                startup_metadata::StartupArtifactContext {
                    label: image_label,
                    toc_name,
                    image_base,
                    image_size,
                    image_blake3,
                    scatter_blake3: role_scatter_blake3,
                    scatter_entries: &binding.scatter_entries,
                    functions_blake3: binding.functions_blake3,
                    thumb_functions_blake3: binding.thumb_functions_blake3,
                    exception_identity,
                    tool_version: env!("CARGO_PKG_VERSION"),
                },
            )?)
        } else {
            ArtifactState::Absent
        };

        Self::new(
            RuntimeBinding::new(image_label, toc_name, image_base, image_blake3, scatter),
            exception,
            pal,
            startup,
        )
    }

    pub(crate) fn validate<T>(
        &self,
        image_dir: &Path,
        use_runtime: impl FnOnce(
            &TrustedDirectory,
            &[u8],
            &RuntimeImage<'_>,
            &AuthenticatedRoleEvidence,
        ) -> Result<T>,
    ) -> Result<T> {
        validate_image_dir(image_dir, &self.runtime.image_label)?;
        let image = TrustedDirectory::new(image_dir, "current symbolication image directory")?;
        let raw = read_raw_image(&image, &self.runtime.image_label)?;
        if *blake3::hash(&raw).as_bytes() != self.runtime.image_blake3 {
            return Err(current_error(
                "raw image BLAKE3 changed after context construction",
            ));
        }
        let runtime = runtime_from_binding(&image, &raw, &self.runtime)?;
        validate_exception_state(&image, &runtime, &self.runtime, &self.roles.exception)?;
        validate_pal_state(&image, &runtime, &self.runtime, &self.roles.pal)?;
        validate_startup_state(&image, &runtime, &self.runtime, &self.roles)?;
        image.verify_path_binding(image_dir, "current symbolication image directory")?;
        let result = use_runtime(&image, &raw, &runtime, &self.roles);
        image.verify_path_binding(image_dir, "current symbolication image directory")?;
        result
    }

    pub(crate) const fn runtime(&self) -> &RuntimeBinding {
        &self.runtime
    }

    pub(crate) const fn roles(&self) -> &AuthenticatedRoleEvidence {
        &self.roles
    }

    pub(crate) fn with_startup(&self, startup: ArtifactState<ValidatedStartup>) -> Result<Self> {
        let startup = match startup {
            ArtifactState::Unmanaged => ArtifactState::Unmanaged,
            ArtifactState::Absent => ArtifactState::Absent,
            ArtifactState::Present(validated) => {
                ArtifactState::Present(StartupRoleSet::from_validated(&validated)?)
            }
        };
        let roles = AuthenticatedRoleEvidence {
            exception: self.roles.exception.clone(),
            pal: self.roles.pal.clone(),
            startup,
        };
        roles.validate_runtime_binding(&self.runtime)?;
        Ok(Self {
            runtime: self.runtime.clone(),
            roles,
        })
    }
}

fn retained_runtime<'a>(
    image: &TrustedDirectory,
    raw: &'a [u8],
    image_label: &str,
    toc_name: &str,
    image_base: u32,
    image_blake3: [u8; 32],
) -> Result<(ArtifactState<[u8; 32]>, RuntimeImage<'a>)> {
    if toc_name != "MAIN" {
        return Ok((
            ArtifactState::Unmanaged,
            RuntimeImage::from_plan(raw, image_base, None)?,
        ));
    }
    if !owned_leaf_present(
        image,
        "scatter",
        "load_map.json",
        "retained scatter load map",
    )? {
        return Ok((
            ArtifactState::Absent,
            RuntimeImage::from_plan(raw, image_base, None)?,
        ));
    }
    let artifact = crate::scatter::read_materialized_from_trusted(
        image,
        Path::new("scatter/load_map.json"),
        raw,
        image_base,
    )?;
    validate_scatter_artifact(&artifact, image_label, image_base, image_blake3)?;
    let digest = artifact.manifest_blake3;
    let runtime = RuntimeImage::from_materialized(raw, image_base, artifact)?;
    Ok((ArtifactState::Present(digest), runtime))
}

fn runtime_from_binding<'a>(
    image: &TrustedDirectory,
    raw: &'a [u8],
    binding: &RuntimeBinding,
) -> Result<RuntimeImage<'a>> {
    match binding.scatter {
        ArtifactState::Unmanaged => RuntimeImage::from_plan(raw, binding.image_base, None),
        ArtifactState::Absent => {
            if owned_leaf_present(
                image,
                "scatter",
                "load_map.json",
                "current scatter load map",
            )? {
                return Err(current_error(
                    "scatter load map is present for explicit absence",
                ));
            }
            RuntimeImage::from_plan(raw, binding.image_base, None)
        }
        ArtifactState::Present(expected_digest) => {
            if !owned_leaf_present(
                image,
                "scatter",
                "load_map.json",
                "current scatter load map",
            )? {
                return Err(current_error(
                    "current scatter load map is missing for explicit presence",
                ));
            }
            let artifact = crate::scatter::read_materialized_from_trusted(
                image,
                Path::new("scatter/load_map.json"),
                raw,
                binding.image_base,
            )?;
            validate_scatter_artifact(
                &artifact,
                &binding.image_label,
                binding.image_base,
                binding.image_blake3,
            )?;
            if artifact.manifest_blake3 != expected_digest {
                return Err(current_error(
                    "scatter load-map BLAKE3 changed after context construction",
                ));
            }
            RuntimeImage::from_materialized(raw, binding.image_base, artifact)
        }
    }
}

fn validate_scatter_artifact(
    artifact: &crate::scatter::MaterializedScatter,
    image_label: &str,
    image_base: u32,
    image_blake3: [u8; 32],
) -> Result<()> {
    if artifact.image_label != image_label
        || artifact.image_base != image_base
        || artifact.image_blake3 != image_blake3
    {
        return Err(current_error(
            "scatter artifact does not match the current runtime binding",
        ));
    }
    Ok(())
}

fn validate_exception_state(
    image: &TrustedDirectory,
    runtime: &RuntimeImage<'_>,
    binding: &RuntimeBinding,
    state: &ArtifactState<ExceptionRoleSet>,
) -> Result<()> {
    match state {
        ArtifactState::Unmanaged => Ok(()),
        ArtifactState::Absent => {
            if owned_leaf_present(
                image,
                "exception_roots",
                "roots.json",
                "current exception-root manifest",
            )? {
                return Err(current_error(
                    "exception-root manifest is present for explicit absence",
                ));
            }
            Ok(())
        }
        ArtifactState::Present(expected) => {
            if !owned_leaf_present(
                image,
                "exception_roots",
                "roots.json",
                "current exception-root manifest",
            )? {
                return Err(current_error(
                    "current exception-root manifest is missing for explicit presence",
                ));
            }
            let bytes = read_nested_leaf(
                image,
                "exception_roots",
                "roots.json",
                EXCEPTION_MANIFEST_MAX_BYTES,
                "current exception-root manifest",
            )?;
            let validated = exception_roots::read_bytes_with_identity(
                &bytes,
                runtime,
                exception_roots::ExceptionArtifactContext {
                    label: &binding.image_label,
                    toc_name: &binding.toc_name,
                    image_blake3: binding.image_blake3,
                    scatter_load_map_blake3: binding.role_scatter_blake3(),
                },
                expected.identity(),
            )?;
            let actual = ExceptionRoleSet::from_validated(&validated)?;
            if actual != *expected {
                return Err(current_error(
                    "exception role projection changed after context construction",
                ));
            }
            Ok(())
        }
    }
}

fn validate_pal_state(
    image: &TrustedDirectory,
    runtime: &RuntimeImage<'_>,
    binding: &RuntimeBinding,
    state: &ArtifactState<PalRoleSet>,
) -> Result<()> {
    match state {
        ArtifactState::Unmanaged => Ok(()),
        ArtifactState::Absent => {
            if owned_leaf_present(
                image,
                "pal_tasks",
                "tasks.json",
                "current PAL task manifest",
            )? {
                return Err(current_error(
                    "PAL task manifest is present for explicit absence",
                ));
            }
            Ok(())
        }
        ArtifactState::Present(expected) => {
            if !owned_leaf_present(
                image,
                "pal_tasks",
                "tasks.json",
                "current PAL task manifest",
            )? {
                return Err(current_error(
                    "current PAL task manifest is missing for explicit presence",
                ));
            }
            let validated = pal_tasks::read_from_trusted(
                image,
                Path::new("pal_tasks/tasks.json"),
                runtime,
                pal_tasks::TaskArtifactContext {
                    label: &binding.image_label,
                    image_blake3: binding.image_blake3,
                    scatter_load_map_blake3: binding.role_scatter_blake3(),
                },
            )?;
            let actual = PalRoleSet::from_validated(&validated)?;
            if actual != *expected {
                return Err(current_error(
                    "PAL role projection changed after context construction",
                ));
            }
            Ok(())
        }
    }
}

fn validate_startup_state(
    image: &TrustedDirectory,
    runtime: &RuntimeImage<'_>,
    binding: &RuntimeBinding,
    roles: &AuthenticatedRoleEvidence,
) -> Result<()> {
    match &roles.startup {
        ArtifactState::Unmanaged => Ok(()),
        ArtifactState::Absent => {
            if owned_leaf_present(
                image,
                "startup_metadata",
                "startup.json",
                "current startup metadata manifest",
            )? {
                return Err(current_error(
                    "startup metadata manifest is present for explicit absence",
                ));
            }
            Ok(())
        }
        ArtifactState::Present(expected) => {
            if !owned_leaf_present(
                image,
                "startup_metadata",
                "startup.json",
                "current startup metadata manifest",
            )? {
                return Err(current_error(
                    "current startup metadata manifest is missing for explicit presence",
                ));
            }
            let bytes = read_nested_leaf(
                image,
                "startup_metadata",
                "startup.json",
                startup_metadata::MAX_MANIFEST_BYTES as u64,
                "current startup metadata manifest",
            )?;
            let (_image_base, image_size) = runtime.image_bounds();
            let startup_binding = retained_startup_binding(&bytes)?;
            let exception_identity = roles.exception.present().map(ExceptionRoleSet::identity);
            let validated = startup_metadata::read_bytes(
                &bytes,
                runtime,
                startup_metadata::StartupArtifactContext {
                    label: &binding.image_label,
                    toc_name: &binding.toc_name,
                    image_base: binding.image_base,
                    image_size,
                    image_blake3: binding.image_blake3,
                    scatter_blake3: binding.role_scatter_blake3(),
                    scatter_entries: &startup_binding.scatter_entries,
                    functions_blake3: startup_binding.functions_blake3,
                    thumb_functions_blake3: startup_binding.thumb_functions_blake3,
                    exception_identity,
                    tool_version: env!("CARGO_PKG_VERSION"),
                },
            )?;
            let actual = StartupRoleSet::from_validated(&validated)?;
            if actual != *expected {
                return Err(current_error(
                    "startup role projection changed after context construction",
                ));
            }
            Ok(())
        }
    }
}

struct RetainedStartupBinding {
    scatter_entries: Vec<u32>,
    functions_blake3: [u8; 32],
    thumb_functions_blake3: Option<[u8; 32]>,
}

fn retained_startup_binding(bytes: &[u8]) -> Result<RetainedStartupBinding> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| current_error(format!("startup metadata schema is invalid: {error}")))?;
    let inventories = value
        .get("inventories")
        .ok_or_else(|| current_error("startup metadata is missing inventories"))?;
    let functions = inventories
        .get("functions_blake3")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| current_error("startup metadata is missing functions_blake3"))?;
    let functions_blake3 = crate::execution_ranges::parse_blake3(functions)
        .map_err(|error| current_error(error.to_string()))?;
    let thumb_functions_blake3 = match inventories.get("thumb_functions_blake3") {
        None | Some(serde_json::Value::Null) => None,
        Some(value) => Some(
            crate::execution_ranges::parse_blake3(value.as_str().ok_or_else(|| {
                current_error("startup metadata thumb_functions_blake3 is not a string")
            })?)
            .map_err(|error| current_error(error.to_string()))?,
        ),
    };
    let entries = value
        .get("runtime")
        .and_then(|runtime| runtime.get("scatter_entries_used"))
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| current_error("startup metadata is missing scatter_entries_used"))?;
    let mut scatter_entries = Vec::new();
    scatter_entries
        .try_reserve_exact(entries.len())
        .map_err(|_| current_error("startup scatter-entry projection allocation failed"))?;
    for entry in entries {
        let Some(value) = entry.as_u64() else {
            return Err(current_error("startup scatter entry is not an integer"));
        };
        let value =
            u32::try_from(value).map_err(|_| current_error("startup scatter entry exceeds u32"))?;
        scatter_entries.push(value);
    }
    Ok(RetainedStartupBinding {
        scatter_entries,
        functions_blake3,
        thumb_functions_blake3,
    })
}

fn read_raw_image(image: &TrustedDirectory, image_label: &str) -> Result<Vec<u8>> {
    let leaf = format!("{image_label}.bin");
    let file = image.open_regular_file(Path::new(&leaf), "symbolication raw image")?;
    read_bounded_file(file, RAW_IMAGE_MAX_BYTES, "symbolication raw image")
}

fn read_nested_leaf(
    image: &TrustedDirectory,
    directory: &str,
    leaf: &str,
    limit: u64,
    context: &str,
) -> Result<Vec<u8>> {
    let directory = image
        .open_directory_child(directory, context)?
        .ok_or_else(|| current_error(format!("{context} directory is missing")))?;
    let file = directory.open_regular_file(Path::new(leaf), context)?;
    read_bounded_file(file, limit, context)
}

fn read_bounded_file(mut file: File, limit: u64, context: &str) -> Result<Vec<u8>> {
    let length = file.metadata()?.len();
    if length > limit {
        return Err(current_error(format!(
            "{context} exceeds its {limit}-byte limit"
        )));
    }
    let length = usize::try_from(length)
        .map_err(|_| current_error(format!("{context} size does not fit the host")))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| current_error(format!("{context} allocation failed")))?;
    bytes.resize(length, 0);
    file.read_exact(&mut bytes)?;
    let mut trailing = [0u8; 1];
    if file.read(&mut trailing)? != 0 {
        return Err(current_error(format!(
            "{context} grew while it was being authenticated"
        )));
    }
    Ok(bytes)
}

fn owned_leaf_present(
    image: &TrustedDirectory,
    directory: &str,
    leaf: &str,
    context: &str,
) -> Result<bool> {
    let Some(directory) = image.open_directory_child(directory, context)? else {
        return Ok(false);
    };
    directory.regular_file_exists(leaf, context)
}

fn validate_image_dir(image_dir: &Path, image_label: &str) -> Result<()> {
    if !image_dir.is_absolute() {
        return Err(current_error(
            "symbolication image directory is not absolute",
        ));
    }
    validate_component(image_label, "symbolication image label")?;
    if image_dir.file_name().and_then(|name| name.to_str()) != Some(image_label) {
        return Err(current_error(
            "symbolication image directory does not match its image label",
        ));
    }
    Ok(())
}

fn validate_component(value: &str, context: &str) -> Result<()> {
    let valid = !value.is_empty()
        && value != "."
        && value != ".."
        && value.len() <= 255
        && !value.ends_with(['.', ' '])
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
        && !WINDOWS_RESERVED_COMPONENTS.iter().any(|reserved| {
            value
                .split_once('.')
                .map_or(value, |(stem, _)| stem)
                .eq_ignore_ascii_case(reserved)
        });
    if valid {
        Ok(())
    } else {
        Err(model_error(format!(
            "{context} is not a safe path component"
        )))
    }
}

fn validate_primary(primary: Option<&str>, context: &str) -> Result<()> {
    if let Some(primary) = primary
        && (primary.is_empty()
            || !primary.is_ascii()
            || primary.contains('\0')
            || primary.len() > super::MAX_PRIMARY_CHARS)
    {
        return Err(model_error(format!(
            "{context} exceeds its strict symbol-leaf bound"
        )));
    }
    Ok(())
}

fn model_error(reason: impl Into<String>) -> Error {
    Error::Serialize(format!(
        "authenticated role-evidence model: {}",
        reason.into()
    ))
}

fn current_error(reason: impl Into<String>) -> Error {
    Error::DecomposeIncomplete(format!("current symbolication context: {}", reason.into()))
}

#[cfg(test)]
pub(crate) fn retained_pal_fixture_tree(
    with_scatter: bool,
) -> (tempfile::TempDir, std::path::PathBuf) {
    const BASE: u32 = crate::pal_tasks::test_support::BASE;
    const LABEL: &str = "02_MAIN";

    let root = tempfile::tempdir().unwrap();
    let image_dir = root.path().join("images").join(LABEL);
    let generation = root.path().join("generation");
    std::fs::create_dir_all(&image_dir).unwrap();
    std::fs::create_dir(&generation).unwrap();

    let raw = if with_scatter {
        crate::pal_tasks::test_support::craft_scatter_pal_main_image()
    } else {
        crate::pal_tasks::test_support::craft_discoverable_pal_main_image()
    };
    std::fs::write(image_dir.join(format!("{LABEL}.bin")), &raw).unwrap();

    let (runtime, scatter_blake3) = if with_scatter {
        let plan = crate::scatter::discover(&raw, BASE)
            .unwrap()
            .expect("fixture has scatter");
        let map = crate::scatter::materialize(&plan, &raw, LABEL, &generation).unwrap();
        std::fs::rename(
            generation.join("scatter").join(LABEL),
            image_dir.join("scatter"),
        )
        .unwrap();
        let artifact = crate::scatter::read_materialized(
            &image_dir,
            &image_dir.join("scatter/load_map.json"),
            &raw,
            BASE,
        )
        .unwrap();
        let digest = crate::execution_ranges::parse_blake3(&map.blake3).unwrap();
        (
            RuntimeImage::from_materialized(&raw, BASE, artifact).unwrap(),
            Some(digest),
        )
    } else {
        (RuntimeImage::from_plan(&raw, BASE, None).unwrap(), None)
    };
    let plan = crate::pal_tasks::discover(&runtime, LABEL)
        .unwrap()
        .expect("fixture has PAL tasks");
    crate::pal_tasks::materialize(
        &plan,
        crate::pal_tasks::TaskArtifactContext {
            label: LABEL,
            image_blake3: *blake3::hash(&raw).as_bytes(),
            scatter_load_map_blake3: scatter_blake3,
        },
        &generation,
    )
    .unwrap();
    std::fs::create_dir(image_dir.join("pal_tasks")).unwrap();
    std::fs::copy(
        generation.join("pal_tasks").join(LABEL).join("tasks.json"),
        image_dir.join("pal_tasks/tasks.json"),
    )
    .unwrap();
    (root, image_dir)
}

#[cfg(test)]
pub(crate) fn context_from_test_pal_pass2(
    mut runtime: RuntimeBinding,
    pal: &super::PalPass2Context,
) -> Result<CurrentSymbolicationContext> {
    let manifest_blake3 = crate::execution_ranges::parse_blake3(&pal.manifest_blake3)?;
    let scatter_load_map_blake3 = pal
        .scatter_load_map_blake3
        .as_deref()
        .map(crate::execution_ranges::parse_blake3)
        .transpose()?;
    runtime.scatter = scatter_load_map_blake3
        .map(ArtifactState::Present)
        .unwrap_or(ArtifactState::Absent);
    let mut applications = Vec::with_capacity(pal.applications.len());
    let mut application_index = BTreeMap::new();
    for (entry, application) in &pal.applications {
        let isa = match application.isa {
            "arm" => DecodeIsa::Arm,
            "thumb" => DecodeIsa::Thumb,
            other => {
                return Err(model_error(format!(
                    "test PAL application has invalid ISA {other:?}"
                )));
            }
        };
        application_index.insert((*entry, isa), applications.len());
        applications.push(PalRoleApplication {
            entry: *entry,
            isa,
            desired_primary: application.desired_primary.clone(),
            tasks: application
                .tasks
                .iter()
                .map(|task| PalRoleTask {
                    task_index: task.task_index,
                    name: task.name.clone(),
                    slot: task.slot,
                    priority: task.priority,
                    stack_size: task.stack_size,
                })
                .collect(),
        });
    }
    let pal = PalRoleSet {
        identity: pal.identity.clone(),
        manifest_blake3,
        image_label: runtime.image_label.clone(),
        image_base: runtime.image_base,
        image_blake3: runtime.image_blake3,
        scatter_load_map_blake3,
        applications,
        application_index,
    };
    let roles = AuthenticatedRoleEvidence {
        exception: ArtifactState::Unmanaged,
        pal: ArtifactState::Present(pal),
        startup: ArtifactState::Unmanaged,
    };
    roles.validate_runtime_binding(&runtime)?;
    Ok(CurrentSymbolicationContext { runtime, roles })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exception_roots::{ExceptionArtifactContext, ValidatedExceptionRoots};
    use crate::execution_ranges::DecodeIsa;
    use crate::pal_tasks::{TaskArtifactContext, ValidatedTaskArtifact};
    use crate::runtime_image::RuntimeImage;
    use std::cell::Cell;
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    const EXCEPTION_BASE: u32 = 0x4001_0000;
    const EXCEPTION_LABEL: &str = "00_BOOT";
    const PAL_BASE: u32 = crate::pal_tasks::test_support::BASE;
    const PAL_LABEL: &str = "02_MAIN";

    fn retained_exception_tree() -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let image_dir = root.path().join("images").join(EXCEPTION_LABEL);
        std::fs::create_dir_all(image_dir.join("exception_roots")).unwrap();
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/exception_roots");
        std::fs::copy(
            fixture.join("synthetic.bin"),
            image_dir.join(format!("{EXCEPTION_LABEL}.bin")),
        )
        .unwrap();
        std::fs::copy(
            fixture.join("roots.json"),
            image_dir.join("exception_roots/roots.json"),
        )
        .unwrap();
        (root, image_dir)
    }

    fn validated_exception(image_dir: &Path) -> ValidatedExceptionRoots {
        let raw = std::fs::read(image_dir.join(format!("{EXCEPTION_LABEL}.bin"))).unwrap();
        let runtime = RuntimeImage::from_plan(&raw, EXCEPTION_BASE, None).unwrap();
        let bytes = std::fs::read(image_dir.join("exception_roots/roots.json")).unwrap();
        crate::exception_roots::read_bytes(
            &bytes,
            &runtime,
            ExceptionArtifactContext {
                label: EXCEPTION_LABEL,
                toc_name: "BOOT",
                image_blake3: *blake3::hash(&raw).as_bytes(),
                scatter_load_map_blake3: None,
            },
        )
        .unwrap()
    }

    fn validated_pal(image_dir: &Path, with_scatter: bool) -> ValidatedTaskArtifact {
        let raw = std::fs::read(image_dir.join(format!("{PAL_LABEL}.bin"))).unwrap();
        let (runtime, scatter_blake3) = if with_scatter {
            let bytes = std::fs::read(image_dir.join("scatter/load_map.json")).unwrap();
            (
                RuntimeImage::for_image_dir(&raw, PAL_BASE, image_dir).unwrap(),
                Some(*blake3::hash(&bytes).as_bytes()),
            )
        } else {
            (RuntimeImage::from_plan(&raw, PAL_BASE, None).unwrap(), None)
        };
        let image = TrustedDirectory::new(image_dir, "test PAL image directory").unwrap();
        crate::pal_tasks::read_from_trusted(
            &image,
            Path::new("pal_tasks/tasks.json"),
            &runtime,
            TaskArtifactContext {
                label: PAL_LABEL,
                image_blake3: *blake3::hash(&raw).as_bytes(),
                scatter_load_map_blake3: scatter_blake3,
            },
        )
        .unwrap()
    }

    fn runtime_binding(
        image_dir: &Path,
        label: &str,
        toc_name: &str,
        base: u32,
        scatter: ArtifactState<[u8; 32]>,
    ) -> RuntimeBinding {
        let raw = std::fs::read(image_dir.join(format!("{label}.bin"))).unwrap();
        RuntimeBinding::new(
            label,
            toc_name,
            base,
            *blake3::hash(&raw).as_bytes(),
            scatter,
        )
    }

    fn snapshot_tree(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        fn collect(root: &Path, current: &Path, snapshot: &mut BTreeMap<PathBuf, Vec<u8>>) {
            let mut entries = std::fs::read_dir(current)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect::<Vec<_>>();
            entries.sort();
            for path in entries {
                let metadata = std::fs::symlink_metadata(&path).unwrap();
                if metadata.is_dir() {
                    collect(root, &path, snapshot);
                } else if metadata.is_file() {
                    snapshot.insert(
                        path.strip_prefix(root).unwrap().to_path_buf(),
                        std::fs::read(path).unwrap(),
                    );
                }
            }
        }

        let mut snapshot = BTreeMap::new();
        collect(root, root, &mut snapshot);
        snapshot
    }

    #[test]
    fn projections_are_exact_entry_isa_ordered_and_bounded() {
        let (_exception_root, exception_dir) = retained_exception_tree();
        let exception_context = CurrentSymbolicationContext::from_retained(
            &exception_dir,
            EXCEPTION_LABEL,
            "BOOT",
            EXCEPTION_BASE,
        )
        .unwrap();
        let exception = exception_context
            .roles()
            .exception()
            .present()
            .expect("retained exception evidence");

        assert_eq!(
            exception
                .applications()
                .iter()
                .map(|application| (application.entry(), application.isa()))
                .collect::<Vec<_>>(),
            [
                (0x4001_0200, DecodeIsa::Arm),
                (0x4001_0220, DecodeIsa::Thumb),
                (0x4001_0240, DecodeIsa::Arm),
                (0x4001_0260, DecodeIsa::Thumb),
                (0x4001_0280, DecodeIsa::Arm),
                (0x4001_02a0, DecodeIsa::Arm),
                (0x4001_02c0, DecodeIsa::Thumb),
            ]
        );
        assert!(exception.application(0x4001_0220, DecodeIsa::Arm).is_none());
        let undefined = exception
            .application(0x4001_0220, DecodeIsa::Thumb)
            .expect("exact exception application");
        assert_eq!(undefined.desired_primary(), Some("UndefinedInstruction"));
        assert_eq!(undefined.claims().len(), 1);
        assert_eq!(undefined.claims()[0].table_kind(), "initial");
        assert_eq!(undefined.claims()[0].table_address(), EXCEPTION_BASE);
        assert_eq!(undefined.claims()[0].slot_address(), EXCEPTION_BASE + 4);
        assert_eq!(undefined.claims()[0].role(), "undefined_instruction");

        let (_pal_root, pal_dir) = retained_pal_fixture_tree(false);
        let pal_context =
            CurrentSymbolicationContext::from_retained(&pal_dir, PAL_LABEL, "MAIN", PAL_BASE)
                .unwrap();
        let pal = pal_context
            .roles()
            .pal()
            .present()
            .expect("retained PAL evidence");
        assert_eq!(
            pal.applications()
                .iter()
                .map(|application| (application.entry(), application.isa()))
                .collect::<Vec<_>>(),
            [
                (0x0000_5640, DecodeIsa::Thumb),
                (0x0000_5648, DecodeIsa::Thumb),
            ]
        );
        assert!(pal.application(0x5640, DecodeIsa::Arm).is_none());
        let first = pal
            .application(0x5640, DecodeIsa::Thumb)
            .expect("exact PAL application");
        assert_eq!(first.desired_primary(), "pal_TaskEntry_first_task");
        assert_eq!(first.tasks().len(), 1);
        assert_eq!(first.tasks()[0].task_index(), 0);
        assert_eq!(first.tasks()[0].name(), "first_task");
        assert_eq!(first.tasks()[0].slot(), 0x5000);
        assert_eq!(first.tasks()[0].priority(), 100);
        assert_eq!(first.tasks()[0].stack_size(), 0x200);
    }

    #[test]
    fn projections_reject_oversized_or_ambiguous_validated_inputs() {
        let (_exception_root, exception_dir) = retained_exception_tree();
        let mut exception = validated_exception(&exception_dir);
        let application = exception.plan.applications[0].clone();
        exception
            .plan
            .applications
            .resize(crate::exception_roots::MAX_ROOTS + 1, application);
        let error = CurrentSymbolicationContext::new(
            runtime_binding(
                &exception_dir,
                EXCEPTION_LABEL,
                "BOOT",
                EXCEPTION_BASE,
                ArtifactState::Unmanaged,
            ),
            ArtifactState::Present(exception),
            ArtifactState::Unmanaged,
            ArtifactState::Unmanaged,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("application limit"), "{error}");

        let (_pal_root, pal_dir) = retained_pal_fixture_tree(false);
        let mut pal = validated_pal(&pal_dir, false);
        let task = pal.plan.tasks[0].clone();
        pal.plan
            .tasks
            .resize(crate::pal_tasks::MAX_TABLE_CAPACITY as usize + 1, task);
        let error = CurrentSymbolicationContext::new(
            runtime_binding(&pal_dir, PAL_LABEL, "MAIN", PAL_BASE, ArtifactState::Absent),
            ArtifactState::Absent,
            ArtifactState::Present(pal),
            ArtifactState::Unmanaged,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("task-record limit"), "{error}");

        let mut exception = validated_exception(&exception_dir);
        exception.plan.applications[1].entry = exception.plan.applications[0].entry;
        exception.plan.applications[1].isa = exception.plan.applications[0].isa;
        let error = CurrentSymbolicationContext::new(
            runtime_binding(
                &exception_dir,
                EXCEPTION_LABEL,
                "BOOT",
                EXCEPTION_BASE,
                ArtifactState::Unmanaged,
            ),
            ArtifactState::Present(exception),
            ArtifactState::Unmanaged,
            ArtifactState::Unmanaged,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("duplicate exception application"), "{error}");
    }

    #[test]
    fn explicit_present_requires_the_owned_exception_and_pal_leaves() {
        let (_exception_root, exception_dir) = retained_exception_tree();
        let exception_context = CurrentSymbolicationContext::from_retained(
            &exception_dir,
            EXCEPTION_LABEL,
            "BOOT",
            EXCEPTION_BASE,
        )
        .unwrap();
        std::fs::remove_file(exception_dir.join("exception_roots/roots.json")).unwrap();
        let called = Cell::new(false);
        let error = exception_context
            .validate(&exception_dir, |_, _, _, _| {
                called.set(true);
                Ok(())
            })
            .unwrap_err()
            .to_string();
        assert!(!called.get());
        assert!(
            error.contains("exception") && error.contains("missing"),
            "{error}"
        );

        let (_pal_root, pal_dir) = retained_pal_fixture_tree(false);
        let pal_context =
            CurrentSymbolicationContext::from_retained(&pal_dir, PAL_LABEL, "MAIN", PAL_BASE)
                .unwrap();
        std::fs::remove_file(pal_dir.join("pal_tasks/tasks.json")).unwrap();
        let called = Cell::new(false);
        let error = pal_context
            .validate(&pal_dir, |_, _, _, _| {
                called.set(true);
                Ok(())
            })
            .unwrap_err()
            .to_string();
        assert!(!called.get());
        assert!(
            error.contains("PAL") && error.contains("missing"),
            "{error}"
        );
    }

    #[test]
    fn explicit_absence_rejects_stale_owned_leaves() {
        let (_exception_root, exception_dir) = retained_exception_tree();
        let absent_exception = CurrentSymbolicationContext::new(
            runtime_binding(
                &exception_dir,
                EXCEPTION_LABEL,
                "BOOT",
                EXCEPTION_BASE,
                ArtifactState::Unmanaged,
            ),
            ArtifactState::Absent,
            ArtifactState::Unmanaged,
            ArtifactState::Unmanaged,
        )
        .unwrap();
        let error = absent_exception
            .validate(&exception_dir, |_, _, _, _| Ok(()))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("exception") && error.contains("explicit absence"),
            "{error}"
        );

        let (_pal_root, pal_dir) = retained_pal_fixture_tree(false);
        let absent_pal = CurrentSymbolicationContext::new(
            runtime_binding(&pal_dir, PAL_LABEL, "MAIN", PAL_BASE, ArtifactState::Absent),
            ArtifactState::Absent,
            ArtifactState::Absent,
            ArtifactState::Unmanaged,
        )
        .unwrap();
        let error = absent_pal
            .validate(&pal_dir, |_, _, _, _| Ok(()))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("PAL") && error.contains("explicit absence"),
            "{error}"
        );
    }

    #[test]
    fn unmanaged_foreign_role_and_scatter_leaves_are_not_authority() {
        let root = tempfile::tempdir().unwrap();
        let image_dir = root.path().join("images/00_BOOT");
        std::fs::create_dir_all(image_dir.join("scatter")).unwrap();
        std::fs::create_dir_all(image_dir.join("exception_roots")).unwrap();
        std::fs::create_dir_all(image_dir.join("pal_tasks")).unwrap();
        std::fs::write(image_dir.join("00_BOOT.bin"), [0u8; 16]).unwrap();
        std::fs::write(image_dir.join("scatter/load_map.json"), b"foreign scatter").unwrap();
        std::fs::write(
            image_dir.join("exception_roots/roots.json"),
            b"foreign exception",
        )
        .unwrap();
        std::fs::write(image_dir.join("pal_tasks/tasks.json"), b"foreign PAL").unwrap();
        let context = CurrentSymbolicationContext::new(
            runtime_binding(
                &image_dir,
                "00_BOOT",
                "BOOT",
                0x1000,
                ArtifactState::Unmanaged,
            ),
            ArtifactState::Unmanaged,
            ArtifactState::Unmanaged,
            ArtifactState::Unmanaged,
        )
        .unwrap();

        context
            .validate(&image_dir, |_, raw, runtime, roles| {
                assert_eq!(raw, [0u8; 16]);
                assert_eq!(runtime.image_bounds(), (0x1000, 16));
                assert!(matches!(roles.exception(), ArtifactState::Unmanaged));
                assert!(matches!(roles.pal(), ArtifactState::Unmanaged));
                assert!(matches!(roles.startup(), ArtifactState::Unmanaged));
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn construction_rejects_runtime_and_scatter_binding_mismatches() {
        let (_exception_root, exception_dir) = retained_exception_tree();
        let exception = validated_exception(&exception_dir);
        let mut wrong_image = runtime_binding(
            &exception_dir,
            EXCEPTION_LABEL,
            "BOOT",
            EXCEPTION_BASE,
            ArtifactState::Unmanaged,
        );
        wrong_image.image_blake3 = [0x5a; 32];
        let error = CurrentSymbolicationContext::new(
            wrong_image,
            ArtifactState::Present(exception),
            ArtifactState::Unmanaged,
            ArtifactState::Unmanaged,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("raw-image binding"), "{error}");

        let (_pal_root, pal_dir) = retained_pal_fixture_tree(true);
        let pal = validated_pal(&pal_dir, true);
        let error = CurrentSymbolicationContext::new(
            runtime_binding(
                &pal_dir,
                PAL_LABEL,
                "MAIN",
                PAL_BASE,
                ArtifactState::Present([0x33; 32]),
            ),
            ArtifactState::Absent,
            ArtifactState::Present(pal),
            ArtifactState::Unmanaged,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("scatter binding"), "{error}");
    }

    #[test]
    fn runtime_binding_rejects_toc_mismatch_and_nonportable_components() {
        let error = CurrentSymbolicationContext::new(
            RuntimeBinding::new(
                "02_MAIN",
                "BOOT",
                PAL_BASE,
                [0x11; 32],
                ArtifactState::Unmanaged,
            ),
            ArtifactState::Unmanaged,
            ArtifactState::Unmanaged,
            ArtifactState::Unmanaged,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("TOC name does not match"), "{error}");

        let error = CurrentSymbolicationContext::new(
            RuntimeBinding::new("CON", "CON", PAL_BASE, [0x22; 32], ArtifactState::Unmanaged),
            ArtifactState::Unmanaged,
            ArtifactState::Unmanaged,
            ArtifactState::Unmanaged,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("safe path component"), "{error}");
    }

    #[test]
    fn validate_rejects_raw_scatter_and_role_manifest_drift_before_use() {
        let (_raw_root, raw_dir) = retained_exception_tree();
        let raw_context = CurrentSymbolicationContext::from_retained(
            &raw_dir,
            EXCEPTION_LABEL,
            "BOOT",
            EXCEPTION_BASE,
        )
        .unwrap();
        let raw_path = raw_dir.join(format!("{EXCEPTION_LABEL}.bin"));
        let mut raw = std::fs::read(&raw_path).unwrap();
        raw[0] ^= 1;
        std::fs::write(&raw_path, raw).unwrap();
        let before = snapshot_tree(&raw_dir);
        let called = Cell::new(false);
        let error = raw_context
            .validate(&raw_dir, |_, _, _, _| {
                called.set(true);
                Ok(())
            })
            .unwrap_err()
            .to_string();
        assert!(!called.get());
        assert!(error.contains("raw image BLAKE3"), "{error}");
        assert_eq!(snapshot_tree(&raw_dir), before);

        let (_scatter_root, scatter_dir) = retained_pal_fixture_tree(true);
        let scatter_context =
            CurrentSymbolicationContext::from_retained(&scatter_dir, PAL_LABEL, "MAIN", PAL_BASE)
                .unwrap();
        let scatter_path = scatter_dir.join("scatter/load_map.json");
        let mut scatter = std::fs::read(&scatter_path).unwrap();
        scatter.push(b' ');
        std::fs::write(&scatter_path, scatter).unwrap();
        let before = snapshot_tree(&scatter_dir);
        let called = Cell::new(false);
        let error = scatter_context
            .validate(&scatter_dir, |_, _, _, _| {
                called.set(true);
                Ok(())
            })
            .unwrap_err()
            .to_string();
        assert!(!called.get());
        assert!(error.contains("scatter"), "{error}");
        assert_eq!(snapshot_tree(&scatter_dir), before);

        let (_exception_root, exception_dir) = retained_exception_tree();
        let exception_context = CurrentSymbolicationContext::from_retained(
            &exception_dir,
            EXCEPTION_LABEL,
            "BOOT",
            EXCEPTION_BASE,
        )
        .unwrap();
        std::fs::write(
            exception_dir.join("exception_roots/roots.json"),
            b"stale exception manifest",
        )
        .unwrap();
        let before = snapshot_tree(&exception_dir);
        let called = Cell::new(false);
        let error = exception_context
            .validate(&exception_dir, |_, _, _, _| {
                called.set(true);
                Ok(())
            })
            .unwrap_err()
            .to_string();
        assert!(!called.get());
        assert!(error.contains("exception"), "{error}");
        assert_eq!(snapshot_tree(&exception_dir), before);

        let (_pal_root, pal_dir) = retained_pal_fixture_tree(false);
        let pal_context =
            CurrentSymbolicationContext::from_retained(&pal_dir, PAL_LABEL, "MAIN", PAL_BASE)
                .unwrap();
        std::fs::write(pal_dir.join("pal_tasks/tasks.json"), b"stale PAL manifest").unwrap();
        let before = snapshot_tree(&pal_dir);
        let called = Cell::new(false);
        let error = pal_context
            .validate(&pal_dir, |_, _, _, _| {
                called.set(true);
                Ok(())
            })
            .unwrap_err()
            .to_string();
        assert!(!called.get());
        assert!(error.contains("PAL"), "{error}");
        assert_eq!(snapshot_tree(&pal_dir), before);
    }

    #[cfg(unix)]
    #[test]
    fn validation_rejects_image_namespace_swap_before_use() {
        let (root, image_dir) = retained_pal_fixture_tree(false);
        let context =
            CurrentSymbolicationContext::from_retained(&image_dir, PAL_LABEL, "MAIN", PAL_BASE)
                .unwrap();
        let detached = root.path().join("detached-image");
        let replacement_manifest = b"replacement PAL manifest".to_vec();
        let hook_image = image_dir.clone();
        let hook_detached = detached.clone();
        let hook_manifest = replacement_manifest.clone();
        crate::trusted_fs::set_before_contained_open("PAL task manifest", move || {
            std::fs::rename(&hook_image, &hook_detached).unwrap();
            std::fs::create_dir_all(hook_image.join("pal_tasks")).unwrap();
            std::fs::copy(
                hook_detached.join(format!("{PAL_LABEL}.bin")),
                hook_image.join(format!("{PAL_LABEL}.bin")),
            )
            .unwrap();
            std::fs::write(hook_image.join("pal_tasks/tasks.json"), hook_manifest).unwrap();
        });

        let called = Cell::new(false);
        let error = context
            .validate(&image_dir, |_, _, _, _| {
                called.set(true);
                Ok(())
            })
            .unwrap_err()
            .to_string();

        assert!(!called.get());
        assert!(error.contains("path binding changed"), "{error}");
        assert_eq!(
            std::fs::read(image_dir.join("pal_tasks/tasks.json")).unwrap(),
            replacement_manifest
        );
        assert!(detached.join("pal_tasks/tasks.json").is_file());
    }

    #[test]
    fn successful_validation_has_no_filesystem_side_effects() {
        let (_root, image_dir) = retained_pal_fixture_tree(true);
        let context =
            CurrentSymbolicationContext::from_retained(&image_dir, PAL_LABEL, "MAIN", PAL_BASE)
                .unwrap();
        let before = snapshot_tree(&image_dir);

        context
            .validate(&image_dir, |_, raw, runtime, roles| {
                assert_eq!(*blake3::hash(raw).as_bytes(), context.runtime.image_blake3);
                assert_eq!(runtime.image_bounds().0, PAL_BASE);
                assert!(roles.pal().present().is_some());
                Ok(())
            })
            .unwrap();

        assert_eq!(snapshot_tree(&image_dir), before);
    }

    const STARTUP_BASE: u32 = 0x4001_0000;
    const STARTUP_LABEL: &str = "02_MAIN";

    fn retained_startup_tree() -> (tempfile::TempDir, PathBuf, ValidatedStartup) {
        use crate::startup_metadata::{
            HardwareInit, Section, StackGuard, StartupApplication, StartupArtifactContext,
            StartupPlan, StartupRole,
        };

        let root = tempfile::tempdir().unwrap();
        let image_dir = root.path().join("images").join(STARTUP_LABEL);
        std::fs::create_dir_all(image_dir.join("startup_metadata")).unwrap();
        let raw = vec![0x11u8; 0x40];
        std::fs::write(image_dir.join(format!("{STARTUP_LABEL}.bin")), &raw).unwrap();
        let image_blake3 = *blake3::hash(&raw).as_bytes();
        let plan = StartupPlan {
            image_label: STARTUP_LABEL.to_owned(),
            toc_name: "MAIN".to_owned(),
            image_base: STARTUP_BASE,
            image_size: 0x40,
            hardware_init: Section::Present(HardwareInit {
                entry: STARTUP_BASE + 0x10,
                isa: DecodeIsa::Arm,
                owner: crate::execution_ranges::FunctionOwner::Ghidra,
                execution_blake3: [0x21; 32],
            }),
            stack_guard: Section::Present(StackGuard {
                entry: STARTUP_BASE + 0x20,
                isa: DecodeIsa::Arm,
                owner: crate::execution_ranges::FunctionOwner::Ghidra,
                execution_blake3: [0x22; 32],
                non_return: true,
            }),
            compiler: Section::Absent,
            privileged_ops: Vec::new(),
            applications: vec![
                StartupApplication {
                    role: StartupRole::HardwareInit,
                    entry: STARTUP_BASE + 0x10,
                    isa: DecodeIsa::Arm,
                    desired_primary: StartupRole::HardwareInit.desired_primary(),
                    role_label: StartupRole::HardwareInit.role_label(),
                    set_no_return: false,
                },
                StartupApplication {
                    role: StartupRole::StackGuard,
                    entry: STARTUP_BASE + 0x20,
                    isa: DecodeIsa::Arm,
                    desired_primary: StartupRole::StackGuard.desired_primary(),
                    role_label: StartupRole::StackGuard.role_label(),
                    set_no_return: true,
                },
            ],
        };
        let generation = root.path().join("generation");
        std::fs::create_dir(&generation).unwrap();
        let context = StartupArtifactContext {
            label: STARTUP_LABEL,
            toc_name: "MAIN",
            image_base: STARTUP_BASE,
            image_size: 0x40,
            image_blake3,
            scatter_blake3: None,
            scatter_entries: &[],
            functions_blake3: [0x31; 32],
            thumb_functions_blake3: None,
            exception_identity: None,
            tool_version: env!("CARGO_PKG_VERSION"),
        };
        let materialized =
            crate::startup_metadata::materialize(&plan, context, &generation).unwrap();
        std::fs::copy(
            generation.join(&materialized.relative_path),
            image_dir.join("startup_metadata/startup.json"),
        )
        .unwrap();
        let runtime = RuntimeImage::from_plan(&raw, STARTUP_BASE, None).unwrap();
        let bytes = std::fs::read(image_dir.join("startup_metadata/startup.json")).unwrap();
        let validated = crate::startup_metadata::read_bytes(&bytes, &runtime, context).unwrap();
        (root, image_dir, validated)
    }

    #[test]
    fn from_retained_loads_startup_by_exact_entry_and_isa() {
        let (_root, image_dir, _) = retained_startup_tree();
        let context = CurrentSymbolicationContext::from_retained(
            &image_dir,
            STARTUP_LABEL,
            "MAIN",
            STARTUP_BASE,
        )
        .unwrap();
        let startup = context
            .roles()
            .startup()
            .present()
            .expect("retained startup evidence");
        assert!(startup.identity().starts_with("v1:"));
        assert_eq!(
            startup
                .applications()
                .iter()
                .map(|application| (application.entry(), application.isa()))
                .collect::<Vec<_>>(),
            [
                (STARTUP_BASE + 0x10, DecodeIsa::Arm),
                (STARTUP_BASE + 0x20, DecodeIsa::Arm),
            ]
        );
        assert!(
            startup
                .application(STARTUP_BASE + 0x10, DecodeIsa::Thumb)
                .is_none()
        );
        let hw = startup
            .application(STARTUP_BASE + 0x10, DecodeIsa::Arm)
            .expect("hardware_init application");
        assert_eq!(hw.desired_primary(), "hw_Init");
        assert_eq!(hw.role(), "hardware_init");
        assert!(!hw.set_no_return());
        let guard = startup
            .application(STARTUP_BASE + 0x20, DecodeIsa::Arm)
            .expect("stack_guard application");
        assert_eq!(guard.desired_primary(), "StackProtectionFailure");
        assert_eq!(guard.role(), "stack_protection_failure");
        assert!(guard.set_no_return());
        assert!(matches!(context.roles().exception(), ArtifactState::Absent));
        assert!(matches!(context.roles().pal(), ArtifactState::Absent));
    }

    #[test]
    fn startup_projection_rejects_more_than_max_applications() {
        let (_root, image_dir, mut validated) = retained_startup_tree();
        let extra = validated.plan.applications[0].clone();
        validated
            .plan
            .applications
            .resize(crate::startup_metadata::MAX_APPLICATIONS + 1, extra);
        let error = CurrentSymbolicationContext::new(
            runtime_binding(
                &image_dir,
                STARTUP_LABEL,
                "MAIN",
                STARTUP_BASE,
                ArtifactState::Absent,
            ),
            ArtifactState::Absent,
            ArtifactState::Absent,
            ArtifactState::Present(validated),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("application limit"), "{error}");
    }
}
