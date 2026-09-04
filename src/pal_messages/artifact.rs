#![allow(dead_code)]

use super::{MessagePlan, PalMessageError};
use crate::runtime_image::RuntimeImage;
use std::path::Path;

#[derive(Clone, Copy)]
pub(crate) struct MessageArtifactContext<'a> {
    pub label: &'a str,
    pub image_blake3: [u8; 32],
    pub scatter_load_map_blake3: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MaterializedMessages {
    pub relative_path: String,
    pub blake3: String,
    pub identity: String,
}

pub(crate) fn materialize(
    _plan: &MessagePlan,
    _context: MessageArtifactContext<'_>,
    _out: &Path,
) -> Result<MaterializedMessages, PalMessageError> {
    Err(PalMessageError::Artifact("not implemented".into()))
}

pub(crate) fn read_bytes(
    _bytes: &[u8],
    _runtime: &RuntimeImage<'_>,
    _context: MessageArtifactContext<'_>,
) -> Result<MessagePlan, PalMessageError> {
    Err(PalMessageError::Artifact("not implemented".into()))
}

pub(crate) fn clear_materialized(_out: &Path, _label: &str) -> Result<(), PalMessageError> {
    Ok(())
}
