// Staged internal API: later tasks introduce the tracker and aggregate
// callers. Until then unused pub(crate) items exist for those stages.
#![allow(dead_code)]

mod artifact;
mod decoder;

#[allow(unused_imports)]
use crate::execution_ranges::{DecodeIsa as Isa, ExecutionIdentity};
use std::collections::BTreeSet;
use std::path::Path;

pub const FORMAT_V1: &str = "pixel-modem-extractor-global-shapes-v1";

#[derive(Debug)]
pub(crate) struct RunRequest<'a> {
    pub image_dir: &'a Path,
    pub image_label: &'a str,
    pub manifest_path: &'a Path,
    pub expected_ghidra_records: usize,
    pub expected_ghidra_accepted: usize,
    pub expected_ghidra_quarantined: usize,
    pub expected_thumb_substantial: Option<usize>,
    pub expected_thumb_accepted: Option<usize>,
    pub expected_thumb_quarantined: Option<usize>,
    pub expected_recovered_globals: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GlobalShapesReport {
    pub inferred: usize,
    pub no_evidence: usize,
    pub conflicting: usize,
    pub observations: usize,
    pub ghidra_quarantined: usize,
    pub thumb_quarantined: usize,
    pub quarantine_errors: usize,
    pub decode_failures: usize,
    pub state_barriers: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct FunctionContext {
    pub entry: u32,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FunctionExecution {
    pub identity: ExecutionIdentity,
    pub contexts: BTreeSet<FunctionContext>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceProjectionCounts {
    pub ghidra_accepted: usize,
    pub ghidra_quarantined: usize,
    pub thumb_accepted: usize,
    pub thumb_quarantined: usize,
    pub quarantine_errors: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecoveredGlobal {
    pub source_index: usize,
    pub address: u32,
    pub name: String,
    pub arch: String,
}
