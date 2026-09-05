//! Sealed current-run exception-root state for symbol pass 2.
//!
//! This module alone parses the `ApplyExceptionRoots` process interface and
//! combines that opaque token with the authenticated runtime artifact. Other
//! modules receive immutable views; none can manufacture semantic state.

use crate::error::{Error, Result};
use crate::exception_roots::{self, ExceptionArtifactContext};
use crate::execution_ranges::DecodeIsa;
use crate::runtime_image::RuntimeImage;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const SUMMARY_MAX_BYTES: usize = 256 * 1024;
const PRIMARY_MAX_UTF8_BYTES: usize = 2000;
const SYMBOL_PASS2_MAX_BYTES: usize = 192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FunctionResult {
    Created,
    Reapplied,
    Existing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NameResult {
    Applied,
    Reapplied,
    Preserved,
    NotRequested,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrimarySource {
    Default,
    Analysis,
    Ai,
    Imported,
    UserDefined,
}

impl PrimarySource {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Analysis => "analysis",
            Self::Ai => "ai",
            Self::Imported => "imported",
            Self::UserDefined => "user_defined",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransitionAuthority {
    Func,
    Registration,
}

impl TransitionAuthority {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Func => "func",
            Self::Registration => "registration",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PrimaryIdentity {
    symbol_id: u64,
    source: PrimarySource,
    name: String,
    name_blake3: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PrimaryDisposition {
    ExceptionOwned {
        current: PrimaryIdentity,
    },
    Preserved {
        current: PrimaryIdentity,
    },
    NotRequested {
        current: PrimaryIdentity,
    },
    Pass2Owned {
        authority: TransitionAuthority,
        original: PrimaryIdentity,
        final_primary: PrimaryIdentity,
    },
}

impl PrimaryDisposition {
    fn current(&self) -> &PrimaryIdentity {
        match self {
            Self::ExceptionOwned { current }
            | Self::Preserved { current }
            | Self::NotRequested { current } => current,
            Self::Pass2Owned { final_primary, .. } => final_primary,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AppliedApplication {
    function_result: FunctionResult,
    name_result: NameResult,
    shared: bool,
    disposition: PrimaryDisposition,
}

/// Strict current-run `ApplyExceptionRoots` result. No public parser or
/// semantic fields exist; production obtains it only from decompile's process
/// coordination.
///
/// ```compile_fail
/// use pixel_modem_extractor::decompile::AppliedExceptionRoots;
/// let _ = AppliedExceptionRoots::parse_current("", "00_BOOT", "v1:stale");
/// ```
///
/// ```compile_fail
/// use pixel_modem_extractor::decompile::AppliedExceptionRoots;
/// let _ = AppliedExceptionRoots::default();
/// ```
///
/// ```compile_fail
/// use pixel_modem_extractor::decompile::AppliedExceptionRoots;
/// let _ = AppliedExceptionRoots {
///     image: String::new(),
/// };
/// ```
///
/// ```compile_fail
/// use pixel_modem_extractor::decompile::AppliedExceptionRoots;
/// let _: AppliedExceptionRoots = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedExceptionRoots {
    image: String,
    identity: String,
    tables: usize,
    roles: usize,
    entries: usize,
    functions_created: usize,
    functions_reapplied: usize,
    functions_existing: usize,
    names_applied: usize,
    names_reapplied: usize,
    names_preserved: usize,
    names_not_requested: usize,
    shared_entries: usize,
    symbol_pass2: Option<String>,
    applications: BTreeMap<(u32, DecodeIsa), AppliedApplication>,
}

impl AppliedExceptionRoots {
    pub fn image(&self) -> &str {
        &self.image
    }

    pub fn identity(&self) -> &str {
        &self.identity
    }

    pub fn tables(&self) -> usize {
        self.tables
    }

    pub fn roles(&self) -> usize {
        self.roles
    }

    pub fn entries(&self) -> usize {
        self.entries
    }

    pub fn functions_created(&self) -> usize {
        self.functions_created
    }

    pub fn functions_reapplied(&self) -> usize {
        self.functions_reapplied
    }

    pub fn functions_existing(&self) -> usize {
        self.functions_existing
    }

    pub fn names_applied(&self) -> usize {
        self.names_applied
    }

    pub fn names_reapplied(&self) -> usize {
        self.names_reapplied
    }

    pub fn names_preserved(&self) -> usize {
        self.names_preserved
    }

    pub fn names_not_requested(&self) -> usize {
        self.names_not_requested
    }

    pub fn shared_entries(&self) -> usize {
        self.shared_entries
    }

    pub fn symbol_pass2(&self) -> Option<&str> {
        self.symbol_pass2.as_deref()
    }
}

/// Explicit inputs for constructing authenticated exception state. The
/// current-run token is opaque and can only come from production coordination.
pub struct ExceptionPass2ContextInput<'a> {
    pub manifest_path: &'a Path,
    pub image_dir: &'a Path,
    pub image_label: &'a str,
    pub toc_name: &'a str,
    pub image_base: u32,
    pub expected_identity: &'a str,
    pub expected_scatter_load_map_blake3: Option<[u8; 32]>,
    pub applied: &'a AppliedExceptionRoots,
}

pub(crate) struct ExceptionPass2ContextExactInput<'a, 'runtime> {
    pub manifest_bytes: &'a [u8],
    pub runtime: &'a RuntimeImage<'runtime>,
    pub image_label: &'a str,
    pub toc_name: &'a str,
    pub expected_identity: &'a str,
    pub expected_scatter_load_map_blake3: Option<[u8; 32]>,
    pub applied: &'a AppliedExceptionRoots,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RoleRef {
    table_kind: &'static str,
    table_address: u32,
    slot_address: u32,
    role: &'static str,
}

impl RoleRef {
    pub(crate) fn table_kind(&self) -> &'static str {
        self.table_kind
    }

    pub(crate) fn table_address(&self) -> u32 {
        self.table_address
    }

    pub(crate) fn slot_address(&self) -> u32 {
        self.slot_address
    }

    pub(crate) fn role(&self) -> &'static str {
        self.role
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExceptionApplicationRef {
    desired_primary: Option<String>,
    disposition: PrimaryDisposition,
    roles: Vec<RoleRef>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExceptionDispositionKind {
    ExceptionOwned,
    Preserved,
    NotRequested,
    Pass2Owned,
}

#[derive(Clone, Copy)]
pub(crate) struct ExceptionPrimaryRef<'a> {
    primary: &'a PrimaryIdentity,
}

impl<'a> ExceptionPrimaryRef<'a> {
    pub(crate) fn symbol_id(self) -> u64 {
        self.primary.symbol_id
    }

    pub(crate) fn source(self) -> &'static str {
        self.primary.source.as_str()
    }

    pub(crate) fn name(self) -> &'a str {
        &self.primary.name
    }

    pub(crate) fn name_blake3(self) -> &'a str {
        &self.primary.name_blake3
    }
}

impl ExceptionApplicationRef {
    pub(crate) fn desired_primary(&self) -> Option<&str> {
        self.desired_primary.as_deref()
    }

    pub(crate) fn roles(&self) -> &[RoleRef] {
        &self.roles
    }

    pub(crate) fn proposes_exception_primary(&self) -> bool {
        matches!(self.disposition, PrimaryDisposition::ExceptionOwned { .. })
    }

    pub(crate) fn owns_current_primary(&self) -> bool {
        matches!(
            self.disposition,
            PrimaryDisposition::ExceptionOwned { .. } | PrimaryDisposition::Pass2Owned { .. }
        )
    }

    pub(crate) fn current_primary(&self) -> ExceptionPrimaryRef<'_> {
        ExceptionPrimaryRef {
            primary: self.disposition.current(),
        }
    }

    pub(crate) fn disposition_kind(&self) -> ExceptionDispositionKind {
        match &self.disposition {
            PrimaryDisposition::ExceptionOwned { .. } => ExceptionDispositionKind::ExceptionOwned,
            PrimaryDisposition::Preserved { .. } => ExceptionDispositionKind::Preserved,
            PrimaryDisposition::NotRequested { .. } => ExceptionDispositionKind::NotRequested,
            PrimaryDisposition::Pass2Owned { .. } => ExceptionDispositionKind::Pass2Owned,
        }
    }

    pub(crate) fn transition_authority(&self) -> Option<&'static str> {
        match &self.disposition {
            PrimaryDisposition::Pass2Owned { authority, .. } => Some(authority.as_str()),
            _ => None,
        }
    }

    pub(crate) fn transition_original(&self) -> Option<ExceptionPrimaryRef<'_>> {
        match &self.disposition {
            PrimaryDisposition::Pass2Owned { original, .. } => {
                Some(ExceptionPrimaryRef { primary: original })
            }
            _ => None,
        }
    }

    pub(crate) fn transition_final(&self) -> Option<ExceptionPrimaryRef<'_>> {
        match &self.disposition {
            PrimaryDisposition::Pass2Owned { final_primary, .. } => Some(ExceptionPrimaryRef {
                primary: final_primary,
            }),
            _ => None,
        }
    }
}

/// Authenticated exception state consumed by symbolication and pass 2.
///
/// ```compile_fail
/// use pixel_modem_extractor::symbolicate::ExceptionPass2Context;
/// let _ = ExceptionPass2Context {
///     identity: String::new(),
/// };
/// ```
///
/// ```compile_fail
/// use pixel_modem_extractor::symbolicate::ExceptionPass2Context;
/// let _ = ExceptionPass2Context::default();
/// ```
///
/// ```compile_fail
/// use pixel_modem_extractor::symbolicate::ExceptionPass2Context;
/// let _: ExceptionPass2Context = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExceptionPass2Context {
    identity: String,
    manifest_blake3: String,
    predecessor_symbol_pass2: Option<String>,
    applications: BTreeMap<(u32, DecodeIsa), ExceptionApplicationRef>,
}

impl ExceptionPass2Context {
    pub fn identity(&self) -> &str {
        &self.identity
    }

    pub(crate) fn manifest_blake3(&self) -> &str {
        &self.manifest_blake3
    }

    pub(crate) fn predecessor_symbol_pass2(&self) -> Option<&str> {
        self.predecessor_symbol_pass2.as_deref()
    }

    pub(crate) fn application(&self, key: &(u32, DecodeIsa)) -> Option<&ExceptionApplicationRef> {
        self.applications.get(key)
    }
}

/// Authenticate the runtime image and exception manifest, then bind the
/// strict opaque current-run token into an opaque pass-2 context. The expected
/// scatter digest is explicit currentness: `None` builds a raw-only runtime
/// without probing stale paths, while `Some` requires those exact map bytes.
pub fn read_exception_pass2_context(
    input: ExceptionPass2ContextInput<'_>,
) -> Result<ExceptionPass2Context> {
    let raw = std::fs::read(input.image_dir.join(format!("{}.bin", input.image_label)))?;
    let runtime = if let Some(expected) = input.expected_scatter_load_map_blake3 {
        let scatter = input.image_dir.join("scatter/load_map.json");
        let bytes = std::fs::read(&scatter)?;
        if *blake3::hash(&bytes).as_bytes() != expected {
            return Err(Error::BadExceptionRoots(
                "exception pass-2 context scatter manifest digest mismatch".into(),
            ));
        }
        RuntimeImage::from_artifact(&raw, input.image_base, input.image_dir, Some(&scatter))?
    } else {
        // `None` is explicit raw-only state. Never let a stale scatter path
        // expand the runtime view after currentness has already been decided.
        RuntimeImage::from_plan(&raw, input.image_base, None)?
    };
    let manifest_bytes = std::fs::read(input.manifest_path)?;
    read_exception_pass2_context_exact(ExceptionPass2ContextExactInput {
        manifest_bytes: &manifest_bytes,
        runtime: &runtime,
        image_label: input.image_label,
        toc_name: input.toc_name,
        expected_identity: input.expected_identity,
        expected_scatter_load_map_blake3: input.expected_scatter_load_map_blake3,
        applied: input.applied,
    })
}

pub(crate) fn read_exception_pass2_context_exact(
    input: ExceptionPass2ContextExactInput<'_, '_>,
) -> Result<ExceptionPass2Context> {
    read_exception_pass2_context_exact_with_validated(input).map(|(context, _)| context)
}

pub(crate) fn read_exception_pass2_context_exact_with_validated(
    input: ExceptionPass2ContextExactInput<'_, '_>,
) -> Result<(
    ExceptionPass2Context,
    exception_roots::ValidatedExceptionRoots,
)> {
    let (image_base, image_size) = input.runtime.image_bounds();
    let image_blake3 = input.runtime.hash_range(image_base, image_size)?;
    let validated = exception_roots::read_bytes_with_identity(
        input.manifest_bytes,
        input.runtime,
        ExceptionArtifactContext {
            label: input.image_label,
            toc_name: input.toc_name,
            image_blake3,
            scatter_load_map_blake3: input.expected_scatter_load_map_blake3,
        },
        input.expected_identity,
    )?;
    let context = context_from_validated(&validated, input.applied)?;
    Ok((context, validated))
}

fn context_from_validated(
    validated: &exception_roots::ValidatedExceptionRoots,
    applied: &AppliedExceptionRoots,
) -> Result<ExceptionPass2Context> {
    if applied.image != validated.image_label {
        return Err(Error::Serialize(
            "exception pass-2 context summary image does not match its manifest".into(),
        ));
    }
    if applied.identity != validated.identity {
        return Err(Error::Serialize(
            "exception pass-2 context summary identity does not match its manifest".into(),
        ));
    }
    let expected_roles = validated
        .plan
        .applications
        .iter()
        .map(|application| application.claims.len())
        .sum::<usize>();
    let expected_shared = validated
        .plan
        .applications
        .iter()
        .filter(|application| application_is_shared(application))
        .count();
    if applied.tables != validated.plan.tables.len()
        || applied.roles != expected_roles
        || applied.entries != validated.plan.applications.len()
        || applied.shared_entries != expected_shared
    {
        return Err(Error::Serialize(
            "exception pass-2 context aggregate counts do not match its manifest".into(),
        ));
    }
    let expected = validated
        .plan
        .applications
        .iter()
        .map(|application| (application.entry, application.isa.decode_isa()))
        .collect::<BTreeSet<_>>();
    let supplied = applied
        .applications
        .keys()
        .copied()
        .collect::<BTreeSet<_>>();
    if supplied != expected {
        return Err(Error::Serialize(
            "exception pass-2 context does not carry the exact application state".into(),
        ));
    }

    let mut applications = BTreeMap::new();
    for application in &validated.plan.applications {
        let key = (application.entry, application.isa.decode_isa());
        let current = &applied.applications[&key];
        validate_application_state(application, current)?;
        let roles = application
            .claims
            .iter()
            .map(|claim| RoleRef {
                table_kind: match claim.table_kind {
                    exception_roots::VectorTableKind::Initial => "initial",
                    exception_roots::VectorTableKind::Relocated => "relocated",
                },
                table_address: claim.table_address,
                slot_address: claim.slot_address,
                role: claim.role.as_wire(),
            })
            .collect();
        applications.insert(
            key,
            ExceptionApplicationRef {
                desired_primary: application.desired_primary.clone(),
                disposition: current.disposition.clone(),
                roles,
            },
        );
    }

    Ok(ExceptionPass2Context {
        identity: validated.identity.clone(),
        manifest_blake3: crate::manifest::blake3_fixed(validated.manifest_blake3),
        predecessor_symbol_pass2: applied.symbol_pass2.clone(),
        applications,
    })
}

fn validate_application_state(
    application: &exception_roots::ExceptionApplication,
    current: &AppliedApplication,
) -> Result<()> {
    let shared = application_is_shared(application);
    if current.shared != shared {
        return Err(Error::Serialize(format!(
            "exception application at 0x{:08x} has inconsistent shared state",
            application.entry
        )));
    }
    let desired = application.desired_primary.as_deref();
    let state_error = || {
        Error::Serialize(format!(
            "exception application at 0x{:08x} state does not match its manifest",
            application.entry
        ))
    };
    match &current.disposition {
        PrimaryDisposition::ExceptionOwned { current } => {
            if desired != Some(current.name.as_str()) || current.source != PrimarySource::Analysis {
                return Err(state_error());
            }
        }
        PrimaryDisposition::Preserved { current } => {
            if desired.is_none() || current.source == PrimarySource::Default {
                return Err(state_error());
            }
        }
        PrimaryDisposition::NotRequested { .. } => {
            if desired.is_some() {
                return Err(state_error());
            }
        }
        PrimaryDisposition::Pass2Owned {
            original,
            final_primary,
            ..
        } => {
            if desired != Some(original.name.as_str())
                || original.source != PrimarySource::Analysis
                || final_primary.source != PrimarySource::UserDefined
                || original.symbol_id != final_primary.symbol_id
                || original.name == final_primary.name
            {
                return Err(state_error());
            }
        }
    }
    Ok(())
}

fn application_is_shared(application: &exception_roots::ExceptionApplication) -> bool {
    application.desired_primary.is_none() && application.claims.len() > 1
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SummaryWire {
    image: String,
    status: String,
    identity: String,
    symbol_pass2: NullableStringWire,
    tables: usize,
    roles: usize,
    entries: usize,
    functions_created: usize,
    functions_reapplied: usize,
    functions_existing: usize,
    names_applied: usize,
    names_reapplied: usize,
    names_preserved: usize,
    names_not_requested: usize,
    shared_entries: usize,
    applications: Vec<ApplicationWire>,
}

#[derive(Deserialize)]
#[serde(transparent)]
struct NullableStringWire(Option<String>);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplicationWire {
    entry: String,
    isa: String,
    function_result: String,
    name_result: String,
    shared: bool,
    primary_disposition: String,
    current_primary: PrimaryIdentityWire,
    transition: NullableTransitionWire,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrimaryIdentityWire {
    symbol_id: u64,
    source: String,
    name: String,
    name_blake3: String,
}

#[derive(Deserialize)]
#[serde(transparent)]
struct NullableTransitionWire(Option<TransitionWire>);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TransitionWire {
    authority: String,
    original_primary: PrimaryIdentityWire,
}

/// The sole production summary coordination entry. The parser itself remains
/// private to this module and the returned token has no constructible fields.
pub(super) fn parse_for_decompile(
    stdout: &str,
    expected_image: &str,
    expected_identity: &str,
) -> std::result::Result<AppliedExceptionRoots, String> {
    parse_summary(stdout, expected_image, expected_identity)
}

fn parse_summary(
    stdout: &str,
    expected_image: &str,
    expected_identity: &str,
) -> std::result::Result<AppliedExceptionRoots, String> {
    let mut payloads = stdout
        .lines()
        .filter_map(|line| line.strip_prefix("ApplyExceptionRoots: "));
    let payload = payloads
        .next()
        .ok_or_else(|| "missing ApplyExceptionRoots summary".to_string())?;
    if payloads.next().is_some() {
        return Err("duplicate ApplyExceptionRoots summaries".to_string());
    }
    if payload.len() > SUMMARY_MAX_BYTES {
        return Err(format!(
            "ApplyExceptionRoots summary exceeds the {SUMMARY_MAX_BYTES}-byte limit"
        ));
    }
    let wire: SummaryWire = serde_json::from_str(payload)
        .map_err(|error| format!("malformed ApplyExceptionRoots summary: {error}"))?;
    if wire.image != expected_image {
        return Err(
            "ApplyExceptionRoots summary image does not match the expected image".to_string(),
        );
    }
    if wire.status != "ok" {
        return Err("ApplyExceptionRoots summary status is not \"ok\"".to_string());
    }
    if wire.identity != expected_identity {
        return Err(
            "ApplyExceptionRoots summary identity does not match this run's root map".to_string(),
        );
    }
    if !(1..=exception_roots::MAX_TABLES).contains(&wire.tables) {
        return Err(format!(
            "ApplyExceptionRoots summary table count is outside 1..={}",
            exception_roots::MAX_TABLES
        ));
    }
    let expected_roles = wire
        .tables
        .checked_mul(exception_roots::VECTOR_SLOTS)
        .ok_or_else(|| "ApplyExceptionRoots summary role count overflows".to_string())?;
    if wire.roles != expected_roles {
        return Err(format!(
            "ApplyExceptionRoots summary roles {} do not match {} tables",
            wire.roles, wire.tables
        ));
    }
    let symbol_pass2 = wire.symbol_pass2.0.map(validate_symbol_pass2).transpose()?;
    if wire.applications.is_empty() || wire.applications.len() > exception_roots::MAX_ROOTS {
        return Err(format!(
            "ApplyExceptionRoots summary carries {} applications outside 1..={}",
            wire.applications.len(),
            exception_roots::MAX_ROOTS
        ));
    }

    let mut applications = BTreeMap::new();
    let mut functions_created = 0usize;
    let mut functions_reapplied = 0usize;
    let mut functions_existing = 0usize;
    let mut names_applied = 0usize;
    let mut names_reapplied = 0usize;
    let mut names_preserved = 0usize;
    let mut names_not_requested = 0usize;
    let mut shared_entries = 0usize;
    let mut previous_key = None;
    let mut pass2_owned = 0usize;
    for application in wire.applications {
        let entry = parse_address(&application.entry)?;
        let isa = parse_isa(&application.isa)?;
        let key = (entry, isa);
        if previous_key.is_some_and(|previous| previous >= key) {
            return Err(
                "ApplyExceptionRoots applications are not strictly sorted by (entry, ISA)"
                    .to_string(),
            );
        }
        previous_key = Some(key);
        let function_result = match application.function_result.as_str() {
            "created" => {
                functions_created += 1;
                FunctionResult::Created
            }
            "reapplied" => {
                functions_reapplied += 1;
                FunctionResult::Reapplied
            }
            "existing" => {
                functions_existing += 1;
                FunctionResult::Existing
            }
            _ => {
                return Err(format!(
                    "ApplyExceptionRoots application at 0x{entry:08x} carries an unknown function_result"
                ));
            }
        };
        let name_result = match application.name_result.as_str() {
            "applied" => {
                names_applied += 1;
                NameResult::Applied
            }
            "reapplied" => {
                names_reapplied += 1;
                NameResult::Reapplied
            }
            "preserved" => {
                names_preserved += 1;
                NameResult::Preserved
            }
            "not_requested" => {
                names_not_requested += 1;
                NameResult::NotRequested
            }
            _ => {
                return Err(format!(
                    "ApplyExceptionRoots application at 0x{entry:08x} carries an unknown name_result"
                ));
            }
        };
        if matches!(
            (function_result, name_result),
            (FunctionResult::Reapplied, NameResult::Applied)
                | (FunctionResult::Created, NameResult::Reapplied)
        ) {
            return Err(format!(
                "ApplyExceptionRoots application at 0x{entry:08x} carries inconsistent function_result and name_result replay state"
            ));
        }
        if application.shared {
            shared_entries += 1;
        }
        let current = parse_primary(application.current_primary, entry, "current")?;
        let disposition = match application.primary_disposition.as_str() {
            "exception_owned" => {
                if application.transition.0.is_some()
                    || current.source != PrimarySource::Analysis
                    || !matches!(name_result, NameResult::Applied | NameResult::Reapplied)
                {
                    return Err(format!(
                        "exception_owned application at 0x{entry:08x} has inconsistent state"
                    ));
                }
                PrimaryDisposition::ExceptionOwned { current }
            }
            "preserved" => {
                if application.transition.0.is_some()
                    || current.source == PrimarySource::Default
                    || name_result != NameResult::Preserved
                {
                    return Err(format!(
                        "preserved application at 0x{entry:08x} has inconsistent state"
                    ));
                }
                PrimaryDisposition::Preserved { current }
            }
            "not_requested" => {
                if application.transition.0.is_some()
                    || name_result != NameResult::NotRequested
                    || !application.shared
                {
                    return Err(format!(
                        "not_requested application at 0x{entry:08x} is not a shared entry or has inconsistent state"
                    ));
                }
                PrimaryDisposition::NotRequested { current }
            }
            "pass2_owned" => {
                let transition = application.transition.0.ok_or_else(|| {
                    format!("pass2_owned application at 0x{entry:08x} lacks its transition")
                })?;
                let authority = match transition.authority.as_str() {
                    "func" => TransitionAuthority::Func,
                    "registration" => TransitionAuthority::Registration,
                    _ => {
                        return Err(format!(
                            "pass2_owned application at 0x{entry:08x} has an unknown transition authority"
                        ));
                    }
                };
                let original = parse_primary(transition.original_primary, entry, "original")?;
                if name_result != NameResult::Reapplied
                    || original.source != PrimarySource::Analysis
                    || current.source != PrimarySource::UserDefined
                    || original.symbol_id != current.symbol_id
                    || original.name == current.name
                {
                    return Err(format!(
                        "pass2_owned application at 0x{entry:08x} has inconsistent transition state"
                    ));
                }
                pass2_owned += 1;
                PrimaryDisposition::Pass2Owned {
                    authority,
                    original,
                    final_primary: current,
                }
            }
            _ => {
                return Err(format!(
                    "ApplyExceptionRoots application at 0x{entry:08x} carries an unknown primary_disposition"
                ));
            }
        };
        if application.shared && name_result != NameResult::NotRequested {
            return Err(format!(
                "shared exception application at 0x{entry:08x} is not name_result not_requested"
            ));
        }
        if applications
            .insert(
                key,
                AppliedApplication {
                    function_result,
                    name_result,
                    shared: application.shared,
                    disposition,
                },
            )
            .is_some()
        {
            return Err(format!(
                "ApplyExceptionRoots summary duplicates application 0x{entry:08x}/{}",
                application.isa
            ));
        }
    }
    if pass2_owned != 0 && symbol_pass2.is_none() {
        return Err(
            "ApplyExceptionRoots pass2_owned state lacks the SymbolPass2 property".to_string(),
        );
    }
    if wire.entries != applications.len()
        || wire.functions_created != functions_created
        || wire.functions_reapplied != functions_reapplied
        || wire.functions_existing != functions_existing
        || wire.names_applied != names_applied
        || wire.names_reapplied != names_reapplied
        || wire.names_preserved != names_preserved
        || wire.names_not_requested != names_not_requested
        || wire.shared_entries != shared_entries
    {
        return Err(
            "non-conserving ApplyExceptionRoots summary: aggregate counters do not match application rows"
                .to_string(),
        );
    }
    Ok(AppliedExceptionRoots {
        image: wire.image,
        identity: wire.identity,
        tables: wire.tables,
        roles: wire.roles,
        entries: wire.entries,
        functions_created: wire.functions_created,
        functions_reapplied: wire.functions_reapplied,
        functions_existing: wire.functions_existing,
        names_applied: wire.names_applied,
        names_reapplied: wire.names_reapplied,
        names_preserved: wire.names_preserved,
        names_not_requested: wire.names_not_requested,
        shared_entries: wire.shared_entries,
        symbol_pass2,
        applications,
    })
}

fn parse_address(value: &str) -> std::result::Result<u32, String> {
    if value.len() != 10
        || !value.starts_with("0x")
        || !value[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "ApplyExceptionRoots application address {value:?} is not canonical"
        ));
    }
    u32::from_str_radix(&value[2..], 16)
        .map_err(|_| format!("ApplyExceptionRoots application address {value:?} is invalid"))
}

fn parse_isa(value: &str) -> std::result::Result<DecodeIsa, String> {
    match value {
        "arm" => Ok(DecodeIsa::Arm),
        "thumb" => Ok(DecodeIsa::Thumb),
        _ => Err(format!(
            "ApplyExceptionRoots application ISA {value:?} is not arm or thumb"
        )),
    }
}

fn parse_primary(
    wire: PrimaryIdentityWire,
    entry: u32,
    kind: &str,
) -> std::result::Result<PrimaryIdentity, String> {
    if wire.symbol_id > i64::MAX as u64 {
        return Err(format!(
            "exception {kind} primary symbol ID exceeds Long.MAX_VALUE at 0x{entry:08x}"
        ));
    }
    let source = match wire.source.as_str() {
        "default" => PrimarySource::Default,
        "analysis" => PrimarySource::Analysis,
        "ai" => PrimarySource::Ai,
        "imported" => PrimarySource::Imported,
        "user_defined" => PrimarySource::UserDefined,
        _ => {
            return Err(format!(
                "exception {kind} primary source is unknown at 0x{entry:08x}"
            ));
        }
    };
    if wire.name.len() > PRIMARY_MAX_UTF8_BYTES
        || wire.name.contains('\0')
        || wire.name.contains('\u{fffd}')
    {
        return Err(format!(
            "exception {kind} primary name is invalid at 0x{entry:08x}"
        ));
    }
    validate_lower_blake3(&wire.name_blake3, "exception primary name")?;
    if crate::manifest::blake3_bytes(wire.name.as_bytes()) != wire.name_blake3 {
        return Err(format!(
            "exception {kind} primary name digest does not match at 0x{entry:08x}"
        ));
    }
    Ok(PrimaryIdentity {
        symbol_id: wire.symbol_id,
        source,
        name: wire.name,
        name_blake3: wire.name_blake3,
    })
}

fn validate_lower_blake3(value: &str, what: &str) -> std::result::Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{what} is not 64 lowercase hexadecimal characters"));
    }
    Ok(())
}

fn validate_symbol_pass2(value: String) -> std::result::Result<String, String> {
    if value.len() > SYMBOL_PASS2_MAX_BYTES || !value.is_ascii() {
        return Err(format!(
            "SymbolPass2 property exceeds the {SYMBOL_PASS2_MAX_BYTES}-byte ASCII limit"
        ));
    }
    let parts = value.split(':').collect::<Vec<_>>();
    if parts.len() != 4 || parts[0] != "v3" {
        return Err("SymbolPass2 property is not the strict v3 grammar".to_string());
    }
    validate_lower_blake3(parts[1], "SymbolPass2 map BLAKE3")?;
    validate_lower_blake3(parts[2], "SymbolPass2 functions BLAKE3")?;
    let execution_count = parts[3]
        .parse::<usize>()
        .map_err(|_| "SymbolPass2 execution count is not canonical unsigned decimal".to_string())?;
    if parts[3].starts_with('0') && parts[3] != "0" {
        return Err("SymbolPass2 execution count is not canonical unsigned decimal".to_string());
    }
    if execution_count > crate::execution_ranges::MAX_EXECUTION_FUNCTIONS {
        return Err(format!(
            "SymbolPass2 execution count exceeds the {}-execution limit",
            crate::execution_ranges::MAX_EXECUTION_FUNCTIONS
        ));
    }
    Ok(value)
}

#[cfg(test)]
fn test_primary(symbol_id: u64, source: &str, name: &str) -> serde_json::Value {
    serde_json::json!({
        "symbol_id": symbol_id,
        "source": source,
        "name": name,
        "name_blake3": crate::manifest::blake3_bytes(name.as_bytes()),
    })
}

#[cfg(test)]
pub(super) fn test_summary_for(image: &str, identity: &str) -> String {
    let applications = vec![
        serde_json::json!({
            "entry": "0x40010200", "isa": "arm", "function_result": "created",
            "name_result": "applied", "shared": false,
            "primary_disposition": "exception_owned",
            "current_primary": test_primary(10, "analysis", "Reset"),
            "transition": null,
        }),
        serde_json::json!({
            "entry": "0x40010220", "isa": "arm", "function_result": "created",
            "name_result": "applied", "shared": false,
            "primary_disposition": "exception_owned",
            "current_primary": test_primary(11, "analysis", "UndefinedInstruction"),
            "transition": null,
        }),
        serde_json::json!({
            "entry": "0x40010240", "isa": "arm", "function_result": "created",
            "name_result": "applied", "shared": false,
            "primary_disposition": "exception_owned",
            "current_primary": test_primary(12, "analysis", "SupervisorCall"),
            "transition": null,
        }),
        serde_json::json!({
            "entry": "0x40010260", "isa": "arm", "function_result": "created",
            "name_result": "applied", "shared": false,
            "primary_disposition": "exception_owned",
            "current_primary": test_primary(13, "analysis", "PrefetchAbort"),
            "transition": null,
        }),
        serde_json::json!({
            "entry": "0x40010280", "isa": "arm", "function_result": "created",
            "name_result": "applied", "shared": false,
            "primary_disposition": "exception_owned",
            "current_primary": test_primary(14, "analysis", "DataAbort"),
            "transition": null,
        }),
        serde_json::json!({
            "entry": "0x400102a0", "isa": "arm", "function_result": "existing",
            "name_result": "preserved", "shared": false,
            "primary_disposition": "preserved",
            "current_primary": test_primary(15, "imported", "ExistingIrq"),
            "transition": null,
        }),
        serde_json::json!({
            "entry": "0x400102c0", "isa": "arm", "function_result": "existing",
            "name_result": "not_requested", "shared": true,
            "primary_disposition": "not_requested",
            "current_primary": test_primary(16, "default", "FUN_400102c0"),
            "transition": null,
        }),
    ];
    format!(
        "ApplyExceptionRoots: {}",
        serde_json::json!({
            "image": image,
            "status": "ok",
            "identity": identity,
            "symbol_pass2": null,
            "tables": 1,
            "roles": 8,
            "entries": 7,
            "functions_created": 5,
            "functions_reapplied": 0,
            "functions_existing": 2,
            "names_applied": 5,
            "names_reapplied": 0,
            "names_preserved": 1,
            "names_not_requested": 1,
            "shared_entries": 1,
            "applications": applications,
        })
    )
}

#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub(crate) enum TestExceptionContextState {
    Fresh,
    PreservedReset,
    Pass2OwnedReset,
}

#[cfg(test)]
pub(crate) fn test_context_from_fixture(state: TestExceptionContextState) -> ExceptionPass2Context {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/exception_roots");
    let raw = std::fs::read(fixture.join("synthetic.bin")).unwrap();
    let retained = tempfile::tempdir().unwrap();
    let image_dir = retained.path().join("images/00_BOOT");
    std::fs::create_dir_all(&image_dir).unwrap();
    std::fs::write(image_dir.join("00_BOOT.bin"), raw).unwrap();
    let manifest = retained.path().join("exception_roots/00_BOOT/roots.json");
    std::fs::create_dir_all(manifest.parent().unwrap()).unwrap();
    std::fs::copy(fixture.join("roots.json"), &manifest).unwrap();
    let manifest_blake3 = crate::manifest::blake3_file(&manifest).unwrap();
    let identity = format!("v1:{manifest_blake3}:1:7");
    let applied = parse_summary(
        &test_fixture_summary(&identity, state),
        "00_BOOT",
        &identity,
    )
    .unwrap();
    read_exception_pass2_context(ExceptionPass2ContextInput {
        manifest_path: &manifest,
        image_dir: &image_dir,
        image_label: "00_BOOT",
        toc_name: "BOOT",
        image_base: 0x4001_0000,
        expected_identity: &identity,
        expected_scatter_load_map_blake3: None,
        applied: &applied,
    })
    .unwrap()
}

#[cfg(test)]
fn test_fixture_summary(identity: &str, state: TestExceptionContextState) -> String {
    let rows = [
        ("0x40010200", "arm", Some("Reset"), false),
        ("0x40010220", "thumb", Some("UndefinedInstruction"), false),
        ("0x40010240", "arm", Some("SupervisorCall"), false),
        ("0x40010260", "thumb", Some("PrefetchAbort"), false),
        ("0x40010280", "arm", None, true),
        ("0x400102a0", "arm", Some("IRQ"), false),
        ("0x400102c0", "thumb", Some("FIQ"), false),
    ];
    let mut applications = rows
        .into_iter()
        .enumerate()
        .map(|(index, (entry, isa, desired, shared))| {
            let (name_result, disposition, source, name) = match desired {
                Some(name) => ("applied", "exception_owned", "analysis", name),
                None => ("not_requested", "not_requested", "default", "FUN_40010280"),
            };
            serde_json::json!({
                "entry": entry,
                "isa": isa,
                "function_result": "created",
                "name_result": name_result,
                "shared": shared,
                "primary_disposition": disposition,
                "current_primary": test_primary(100 + index as u64, source, name),
                "transition": null,
            })
        })
        .collect::<Vec<_>>();
    let mut functions_created = 7;
    let mut functions_reapplied = 0;
    let mut names_applied = 6;
    let mut names_reapplied = 0;
    let mut names_preserved = 0;
    let mut symbol_pass2 = serde_json::Value::Null;
    match state {
        TestExceptionContextState::Fresh => {}
        TestExceptionContextState::PreservedReset => {
            applications[0]["name_result"] = serde_json::json!("preserved");
            applications[0]["primary_disposition"] = serde_json::json!("preserved");
            applications[0]["current_primary"] = test_primary(100, "imported", "foreign_primary");
            names_applied = 5;
            names_preserved = 1;
        }
        TestExceptionContextState::Pass2OwnedReset => {
            let predecessor = format!("v3:{}:{}:7", "a".repeat(64), "b".repeat(64));
            applications[0]["function_result"] = serde_json::json!("reapplied");
            applications[0]["name_result"] = serde_json::json!("reapplied");
            applications[0]["primary_disposition"] = serde_json::json!("pass2_owned");
            applications[0]["current_primary"] =
                test_primary(100, "user_defined", "registered_reset");
            applications[0]["transition"] = serde_json::json!({
                "authority": "registration",
                "original_primary": test_primary(100, "analysis", "Reset"),
            });
            functions_created = 6;
            functions_reapplied = 1;
            names_applied = 5;
            names_reapplied = 1;
            symbol_pass2 = serde_json::json!(predecessor);
        }
    }
    format!(
        "ApplyExceptionRoots: {}",
        serde_json::json!({
            "image": "00_BOOT",
            "status": "ok",
            "identity": identity,
            "symbol_pass2": symbol_pass2,
            "tables": 1,
            "roles": 8,
            "entries": 7,
            "functions_created": functions_created,
            "functions_reapplied": functions_reapplied,
            "functions_existing": 0,
            "names_applied": names_applied,
            "names_reapplied": names_reapplied,
            "names_preserved": names_preserved,
            "names_not_requested": 1,
            "shared_entries": 1,
            "applications": applications,
        })
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symbolicate::{
        ExceptionRoleRefSet, PalApplicationRef, PalRoleRefSet, PalTaskRef, RawEvidence,
        TaggedEvidence, Tier, decide,
    };

    const IDENTITY: &str =
        "v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:1:7";

    fn summary() -> String {
        test_summary_for("00_BOOT", IDENTITY)
    }

    fn raw_exception(manifest_blake3: &str, application: ExceptionApplicationRef) -> RawEvidence {
        let exception_proposed_primary = application
            .proposes_exception_primary()
            .then(|| application.desired_primary().map(str::to_owned))
            .flatten();
        RawEvidence {
            func_name: None,
            tokens: Vec::new(),
            file: None,
            file_strings: Vec::new(),
            dbt_sources: Vec::new(),
            ident_guess: None,
            registration: None,
            ss: None,
            exception_manifest_blake3: Some(manifest_blake3.to_string()),
            exception: Some(ExceptionRoleRefSet::from_pass2(&application)),
            exception_proposed_primary,
            pal: None,
            pal_proposed_primary: None,
            startup_manifest_blake3: None,
            startup: None,
            startup_proposed_primary: None,
        }
    }

    #[test]
    fn consumer_views_preserve_exception_authority_and_role_evidence() {
        let context = test_context_from_fixture(TestExceptionContextState::Fresh);
        let application = context
            .application(&(0x4001_0200, DecodeIsa::Arm))
            .unwrap()
            .clone();
        let raw = raw_exception(context.manifest_blake3(), application.clone());

        let (name, tier, evidence, _, conflicts) = decide("40010200", &raw);

        assert_eq!(name.as_deref(), Some("Reset"));
        assert_eq!(tier, Tier::Recovered);
        assert!(conflicts.is_empty());
        assert!(matches!(
            evidence.as_slice(),
            [TaggedEvidence::ExceptionRoot { role: "reset", .. }]
        ));

        let mut with_func = raw_exception(context.manifest_blake3(), application.clone());
        with_func.func_name = Some("func_winner".into());
        assert_eq!(
            decide("40010200", &with_func).0.as_deref(),
            Some("func_winner")
        );

        let mut with_registration = raw_exception(context.manifest_blake3(), application.clone());
        with_registration.registration = Some("registration_winner".into());
        assert_eq!(
            decide("40010200", &with_registration).0.as_deref(),
            Some("registration_winner")
        );

        let mut with_pal = raw_exception(context.manifest_blake3(), application.clone());
        let pal = PalApplicationRef {
            isa: "arm",
            desired_primary: "pal_TaskEntry_reset".into(),
            tasks: vec![PalTaskRef {
                manifest_blake3: "b".repeat(64),
                task_index: 0,
                name: "reset".into(),
                slot: 0x4001_1000,
                priority: 1,
                stack_size: 1024,
            }],
        };
        with_pal.pal = Some(PalRoleRefSet::from_pass2(&pal));
        with_pal.pal_proposed_primary = Some(pal.desired_primary);
        assert_eq!(decide("40010200", &with_pal).0.as_deref(), Some("Reset"));

        let mut with_token = raw_exception(context.manifest_blake3(), application);
        with_token.tokens.push((
            0x3c2a,
            "\u{25a0}format\u{2666}token_name\u{25a0}domain\u{2666}D".into(),
        ));
        assert_eq!(decide("40010200", &with_token).0.as_deref(), Some("Reset"));
    }

    #[test]
    fn consumer_views_keep_shared_and_preserved_applications_evidence_only() {
        for (state, key) in [
            (
                TestExceptionContextState::Fresh,
                (0x4001_0280, DecodeIsa::Arm),
            ),
            (
                TestExceptionContextState::PreservedReset,
                (0x4001_0200, DecodeIsa::Arm),
            ),
        ] {
            let context = test_context_from_fixture(state);
            let application = context.application(&key).unwrap().clone();
            let mut raw = raw_exception(context.manifest_blake3(), application);
            raw.tokens.push((0x3c2a, "weaker token".into()));
            let (name, tier, evidence, _, conflicts) = decide("40010280", &raw);
            assert_eq!(name, None);
            assert_eq!(tier, Tier::None);
            assert!(conflicts.is_empty());
            let roles = evidence
                .iter()
                .filter_map(|item| match item {
                    TaggedEvidence::ExceptionRoot { role, .. } => Some(*role),
                    _ => None,
                })
                .collect::<Vec<_>>();
            assert!(!roles.is_empty());
            if key.0 == 0x4001_0280 {
                assert_eq!(roles, ["data_abort", "reserved"]);
            }
        }
    }

    #[test]
    fn parser_requires_rows_and_accepts_exact_conservation() {
        let aggregate_only = format!(
            "ApplyExceptionRoots: {{\"image\":\"00_BOOT\",\"status\":\"ok\",\"identity\":\"{IDENTITY}\",\"tables\":1,\"roles\":8,\"entries\":7,\"functions_created\":5,\"functions_reapplied\":0,\"functions_existing\":2,\"names_applied\":5,\"names_reapplied\":0,\"names_preserved\":1,\"names_not_requested\":1,\"shared_entries\":1}}"
        );
        assert!(parse_summary(&aggregate_only, "00_BOOT", IDENTITY).is_err());

        let parsed = parse_summary(&summary(), "00_BOOT", IDENTITY).unwrap();
        assert_eq!(parsed.image, "00_BOOT");
        assert_eq!(parsed.identity, IDENTITY);
        assert_eq!(parsed.tables, 1);
        assert_eq!(parsed.roles, 8);
        assert_eq!(parsed.entries, 7);
        assert_eq!(parsed.functions_created, 5);
        assert_eq!(parsed.functions_existing, 2);
        assert_eq!(parsed.names_applied, 5);
        assert_eq!(parsed.names_preserved, 1);
        assert_eq!(parsed.names_not_requested, 1);
        assert_eq!(parsed.shared_entries, 1);
        assert_eq!(parsed.applications.len(), 7);
    }

    #[test]
    fn parser_requires_one_matching_interface_line() {
        let valid = summary();
        for stdout in ["ordinary output".to_string(), format!("{valid}\n{valid}")] {
            assert!(parse_summary(&stdout, "00_BOOT", IDENTITY).is_err());
        }
        assert!(parse_summary(&valid, "01_PSP", IDENTITY).is_err());
        assert!(parse_summary(&valid, "00_BOOT", "v1:stale").is_err());
    }

    #[test]
    fn parser_does_not_reflect_near_limit_wrong_image_or_status() {
        for (field, expected) in [
            (
                "image",
                "ApplyExceptionRoots summary image does not match the expected image",
            ),
            ("status", "ApplyExceptionRoots summary status is not \"ok\""),
        ] {
            let mut value: serde_json::Value = serde_json::from_str(
                summary()
                    .strip_prefix("ApplyExceptionRoots: ")
                    .expect("summary prefix"),
            )
            .unwrap();
            value[field] = serde_json::json!("x".repeat(SUMMARY_MAX_BYTES - 16 * 1024));
            let payload = serde_json::to_string(&value).unwrap();
            assert!(payload.len() <= SUMMARY_MAX_BYTES);
            assert!(payload.len() > SUMMARY_MAX_BYTES - 32 * 1024);

            let error = parse_summary(
                &format!("ApplyExceptionRoots: {payload}"),
                "00_BOOT",
                IDENTITY,
            )
            .unwrap_err();

            assert_eq!(error, expected);
            assert!(error.chars().count() <= crate::error::REPORT_REASON_MAX_CHARS);
        }
    }

    #[test]
    fn parser_rejects_malformed_bounded_and_nonconserving_values() {
        for stdout in [
            "ApplyExceptionRoots: {".to_string(),
            summary().replacen("\"tables\":1", "\"tables\":\"1\"", 1),
            summary().replacen("\"tables\":1", "\"tables\":3", 1),
            summary().replacen("\"roles\":8", "\"roles\":17", 1),
            summary().replacen("\"status\":\"ok\"", "\"status\":\"error\"", 1),
            summary().replacen("\"functions_created\":5", "\"functions_created\":4", 1),
            summary().replacen("\"names_applied\":5", "\"names_applied\":4", 1),
            summary().replacen("\"shared_entries\":1", "\"shared_entries\":2", 1),
        ] {
            assert!(
                parse_summary(&stdout, "00_BOOT", IDENTITY).is_err(),
                "accepted malformed summary: {stdout}"
            );
        }

        let oversized = format!("{}{}", summary(), " ".repeat(SUMMARY_MAX_BYTES));
        assert!(
            parse_summary(&oversized, "00_BOOT", IDENTITY)
                .unwrap_err()
                .contains("byte limit")
        );
    }

    #[test]
    fn parser_enforces_replay_and_shared_result_pairs() {
        let impossible = summary()
            .replacen(
                "\"function_result\":\"created\"",
                "\"function_result\":\"reapplied\"",
                1,
            )
            .replacen("\"functions_created\":5", "\"functions_created\":4", 1)
            .replacen("\"functions_reapplied\":0", "\"functions_reapplied\":1", 1);
        let error = parse_summary(&impossible, "00_BOOT", IDENTITY).unwrap_err();
        assert!(error.contains("function_result") && error.contains("name_result"));

        let mut value: serde_json::Value = serde_json::from_str(
            summary()
                .strip_prefix("ApplyExceptionRoots: ")
                .expect("summary prefix"),
        )
        .unwrap();
        value["applications"][6]["shared"] = serde_json::json!(false);
        value["shared_entries"] = serde_json::json!(0);
        let error = parse_summary(
            &format!("ApplyExceptionRoots: {value}"),
            "00_BOOT",
            IDENTITY,
        )
        .unwrap_err();
        assert!(error.contains("not_requested") && error.contains("shared"));
    }

    #[test]
    fn parser_accepts_owned_primary_on_existing_function_replay() {
        let mut value: serde_json::Value = serde_json::from_str(
            summary()
                .strip_prefix("ApplyExceptionRoots: ")
                .expect("summary prefix"),
        )
        .unwrap();
        value["applications"][5]["name_result"] = serde_json::json!("reapplied");
        value["applications"][5]["primary_disposition"] = serde_json::json!("exception_owned");
        value["applications"][5]["current_primary"] = test_primary(15, "analysis", "IRQ");
        value["names_reapplied"] = serde_json::json!(1);
        value["names_preserved"] = serde_json::json!(0);

        let parsed = parse_summary(
            &format!("ApplyExceptionRoots: {value}"),
            "00_BOOT",
            IDENTITY,
        )
        .unwrap();
        let application = &parsed.applications[&(0x4001_02a0, DecodeIsa::Arm)];
        assert_eq!(application.function_result, FunctionResult::Existing);
        assert_eq!(application.name_result, NameResult::Reapplied);
    }

    #[test]
    fn context_authenticates_artifact_and_rejects_private_state_drift() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/exception_roots");
        let raw = std::fs::read(fixture.join("synthetic.bin")).unwrap();
        let retained = tempfile::tempdir().unwrap();
        let image_dir = retained.path().join("images/00_BOOT");
        std::fs::create_dir_all(&image_dir).unwrap();
        std::fs::write(image_dir.join("00_BOOT.bin"), raw).unwrap();
        let manifest = retained.path().join("exception_roots/00_BOOT/roots.json");
        std::fs::create_dir_all(manifest.parent().unwrap()).unwrap();
        std::fs::copy(fixture.join("roots.json"), &manifest).unwrap();
        let manifest_blake3 = crate::manifest::blake3_file(&manifest).unwrap();
        let identity = format!("v1:{manifest_blake3}:1:7");

        let fixture_summary = test_fixture_summary(&identity, TestExceptionContextState::Fresh);
        let applied = parse_summary(&fixture_summary, "00_BOOT", &identity).unwrap();
        let input = |applied| ExceptionPass2ContextInput {
            manifest_path: &manifest,
            image_dir: &image_dir,
            image_label: "00_BOOT",
            toc_name: "BOOT",
            image_base: 0x4001_0000,
            expected_identity: &identity,
            expected_scatter_load_map_blake3: None,
            applied,
        };
        let context = read_exception_pass2_context(input(&applied)).unwrap();
        assert_eq!(context.identity(), identity);

        let mut drifted = applied.clone();
        drifted.tables += 1;
        assert!(read_exception_pass2_context(input(&drifted)).is_err());

        let mut drifted = applied.clone();
        let first = *drifted.applications.keys().next().unwrap();
        let state = drifted.applications.remove(&first).unwrap();
        drifted.applications.insert((first.0 + 4, first.1), state);
        assert!(read_exception_pass2_context(input(&drifted)).is_err());
    }
}
