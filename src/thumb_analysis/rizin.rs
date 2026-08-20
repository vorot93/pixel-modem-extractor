use super::{ProducerIdentity, ThumbProducer, discover};
use crate::error::Result;

pub fn discover_rizin() -> Result<ProducerIdentity> {
    discover("rizin", ThumbProducer::Rizin)
}
