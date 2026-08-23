use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("bad or missing FBPK magic")]
    BadMagic,
    #[error("unsupported FBPK version {0}")]
    UnsupportedVersion(u32),
    #[error("partition or directory not found: {0}")]
    NotFound(String),
    #[error("unexpected payload (not the expected container)")]
    UnexpectedPayload,
    #[error("bad TOC: {0}")]
    BadToc(String),
    #[error("tree-hash target invalid: {0}")]
    BadTree(String),
    #[error("bad scatter load map: {0}")]
    BadScatter(String),
    #[error("bad token database: {0}")]
    BadTokenDb(String),
    #[error("bad PAL task evidence: {0}")]
    BadPalTasks(String),
    #[error("size mismatch for {name}: expected {expected}, got {actual}")]
    SizeMismatch {
        name: String,
        expected: u64,
        actual: u64,
    },
    #[error("ext4 error: {0}")]
    Ext4(String),
    #[error("serialize: {0}")]
    Serialize(String),
    #[error("ghidra not found: {0}")]
    GhidraNotFound(String),
    #[error("ghidra failed on {image}: exit code {code}")]
    GhidraFailed { image: String, code: i32 },
    #[error("ghidra state home unusable: {0}")]
    GhidraStateHome(String),
    #[error("required tool not found: {0}")]
    ToolNotFound(String),
    #[error("decompose incomplete: {0}")]
    DecomposeIncomplete(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
