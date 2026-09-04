use super::{MessagePlan, PalMessageError};
use crate::runtime_image::RuntimeImage;

pub(crate) fn discover(
    runtime: &RuntimeImage<'_>,
    _label: &str,
) -> Result<Option<MessagePlan>, PalMessageError> {
    let _ = runtime;
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::discover;
    use crate::runtime_image::RuntimeImage;

    const BASE: u32 = 0x4001_0000;

    fn runtime(raw: &[u8]) -> RuntimeImage<'_> {
        RuntimeImage::from_plan(raw, BASE, None).expect("raw fixture")
    }

    #[test]
    fn missing_seed_is_clean_absence() {
        let image = vec![0u8; 64];
        assert!(
            discover(&runtime(&image), "02_MAIN")
                .expect("no seed")
                .is_none()
        );
    }
}
