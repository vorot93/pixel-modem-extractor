use super::{
    MAX_CANDIDATE_VALIDATION_BYTES, MAX_TABLE_CAPACITY, MAX_TABLE_STRIDE, PalMessageError, RawSlot,
};
use crate::runtime_image::RuntimeImage;

pub(crate) fn hash_slots(
    runtime: &RuntimeImage<'_>,
    base: u32,
    stride: u32,
    capacity: u32,
    charged: &mut u64,
) -> Result<Vec<RawSlot>, PalMessageError> {
    if capacity == 0 || capacity > MAX_TABLE_CAPACITY {
        return Err(malformed("table capacity is out of range"));
    }
    if stride < 4 || stride > MAX_TABLE_STRIDE || stride % 4 != 0 {
        return Err(malformed("table stride is out of range"));
    }
    let total = (capacity as u64)
        .checked_mul(stride as u64)
        .ok_or_else(|| malformed("table size overflows"))?;
    let end = base
        .checked_add(u32::try_from(total).map_err(|_| malformed("table size overflows u32"))?)
        .ok_or_else(|| malformed("table end wraps the address space"))?;
    let _ = end;
    let mut slots = Vec::with_capacity(capacity as usize);
    for index in 0..capacity {
        let address = base
            .checked_add(
                index
                    .checked_mul(stride)
                    .ok_or_else(|| malformed("slot address wrap"))?,
            )
            .ok_or_else(|| malformed("slot address wrap"))?;
        let charge = u64::from(stride);
        let next = charged
            .checked_add(charge)
            .ok_or_else(|| PalMessageError::ResourceLimit {
                what: "validation bytes",
                actual: u64::MAX,
                limit: MAX_CANDIDATE_VALIDATION_BYTES,
            })?;
        if next > MAX_CANDIDATE_VALIDATION_BYTES {
            return Err(PalMessageError::ResourceLimit {
                what: "validation bytes",
                actual: next,
                limit: MAX_CANDIDATE_VALIDATION_BYTES,
            });
        }
        *charged = next;
        let blake3 =
            runtime
                .hash_range(address, stride)
                .map_err(|error| PalMessageError::Runtime {
                    address,
                    size: stride,
                    reason: error.to_string(),
                })?;
        slots.push(RawSlot {
            index,
            address,
            size: stride,
            blake3,
        });
    }
    Ok(slots)
}

fn malformed(context: impl Into<String>) -> PalMessageError {
    PalMessageError::Malformed {
        context: context.into(),
    }
}
