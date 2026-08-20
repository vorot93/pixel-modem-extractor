use super::{ProducerIdentity, ThumbProducer, discover};
use crate::error::Result;

pub fn discover_radare2() -> Result<ProducerIdentity> {
    discover("r2", ThumbProducer::Radare2)
}
