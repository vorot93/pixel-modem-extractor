use super::identity::discover;
use super::{ProducerIdentity, ThumbProducer};
use crate::error::Result;
use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
pub(super) struct FunctionRecord {
    pub entry: Option<u64>,
    pub end: Option<u64>,
    pub real_size: Option<u64>,
    pub bounding_size: Option<u64>,
    pub name: Option<String>,
}

fn json_u64(value: &Value) -> Option<u64> {
    if let Some(number) = value.as_u64() {
        return Some(number);
    }
    if let Some(number) = value.as_i64() {
        return (number >= 0).then_some(number as u64);
    }
    let value = value.as_str()?;
    value
        .strip_prefix("0x")
        .and_then(|hex| u64::from_str_radix(hex, 16).ok())
        .or_else(|| value.parse::<u64>().ok())
}

pub(super) fn function_record(raw: &Value) -> FunctionRecord {
    FunctionRecord {
        entry: raw
            .get("addr")
            .or_else(|| raw.get("offset"))
            .and_then(json_u64),
        end: raw.get("maxaddr").and_then(json_u64),
        real_size: raw.get("realsz").and_then(json_u64),
        bounding_size: raw.get("size").and_then(json_u64),
        name: raw.get("name").and_then(Value::as_str).map(str::to_owned),
    }
}

pub fn discover_radare2() -> Result<ProducerIdentity> {
    discover("r2", ThumbProducer::Radare2)
}
