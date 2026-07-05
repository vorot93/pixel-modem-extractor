use crate::error::Result;
use std::io::Read;

pub fn gunzip(src: &[u8]) -> Result<Vec<u8>> {
    let mut d = flate2::read::GzDecoder::new(src);
    let mut out = Vec::new();
    d.read_to_end(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn roundtrip() {
        let original = b"RF_CFG calibration bytes \x00\x01\x02";
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(original).unwrap();
        let gz = enc.finish().unwrap();
        assert_eq!(gunzip(&gz).unwrap(), original);
    }
}
