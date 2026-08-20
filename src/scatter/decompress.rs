use crate::scatter::ScatterError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Decoded {
    pub bytes: Vec<u8>,
    pub consumed: usize,
}

#[derive(Debug)]
pub(crate) struct DecodeBudget {
    produced: u64,
    limit: u64,
}

impl DecodeBudget {
    pub(crate) fn new(limit: u64) -> Self {
        Self { produced: 0, limit }
    }

    fn charge(&mut self, amount: usize) -> Result<(), ScatterError> {
        self.produced =
            self.produced
                .checked_add(amount as u64)
                .ok_or(ScatterError::ResourceLimit {
                    what: "decoded output",
                    limit: self.limit,
                })?;
        if self.produced > self.limit {
            return Err(ScatterError::ResourceLimit {
                what: "decoded output",
                limit: self.limit,
            });
        }
        Ok(())
    }
}

struct ByteReader<'a> {
    input: &'a [u8],
    consumed: usize,
}

impl<'a> ByteReader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, consumed: 0 }
    }

    fn read(&mut self) -> Result<u8, ScatterError> {
        let byte = self
            .input
            .get(self.consumed)
            .copied()
            .ok_or_else(|| malformed("truncated input"))?;
        self.consumed += 1;
        Ok(byte)
    }
}

pub(crate) fn decompress1(
    input: &[u8],
    expected: usize,
    budget: &mut DecodeBudget,
) -> Result<Decoded, ScatterError> {
    budget.charge(expected)?;

    let mut reader = ByteReader::new(input);
    let mut output = Vec::with_capacity(expected);

    while output.len() < expected {
        let before = output.len();
        let token = reader.read()?;

        let mut literal_code = usize::from(token & 7);
        if literal_code == 0 {
            literal_code = usize::from(reader.read()?);
            if literal_code == 0 {
                return Err(malformed("extended literal code is zero"));
            }
        }
        let literal_count = literal_code - 1;

        let mut run = usize::from(token >> 4);
        if run == 0 {
            run = usize::from(reader.read()?);
        }

        let literal_end = output
            .len()
            .checked_add(literal_count)
            .filter(|&end| end <= expected)
            .ok_or_else(|| malformed("literal count exceeds expected output"))?;
        while output.len() < literal_end {
            output.push(reader.read()?);
        }

        if token & 8 == 0 {
            let run_end = output
                .len()
                .checked_add(run)
                .filter(|&end| end <= expected)
                .ok_or_else(|| malformed("zero run exceeds expected output"))?;
            output.resize(run_end, 0);
        } else {
            let distance = usize::from(reader.read()?);
            if distance == 0 {
                return Err(malformed("back-reference distance is zero"));
            }
            if distance > output.len() {
                return Err(malformed("back-reference distance exceeds output"));
            }

            let run_end = output
                .len()
                .checked_add(run + 2)
                .filter(|&end| end <= expected)
                .ok_or_else(|| malformed("back-reference exceeds expected output"))?;
            while output.len() < run_end {
                let byte = output[output.len() - distance];
                output.push(byte);
            }
        }

        if output.len() == before {
            return Err(malformed("token made no output progress"));
        }
    }

    Ok(Decoded {
        bytes: output,
        consumed: reader.consumed,
    })
}

fn malformed(reason: &str) -> ScatterError {
    ScatterError::Malformed {
        loader: 0,
        entry: None,
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_and_zero_run_decode_exactly() {
        let mut budget = DecodeBudget::new(16);
        let got = decompress1(&[0x22, 0xaa], 3, &mut budget).unwrap();
        assert_eq!(got.bytes, [0xaa, 0x00, 0x00]);
        assert_eq!(got.consumed, 2);
    }

    #[test]
    fn overlapping_back_reference_uses_newly_written_bytes() {
        let mut budget = DecodeBudget::new(16);
        let got = decompress1(&[0x03, 0x00, b'A', b'B', 0x29, 0x02], 6, &mut budget).unwrap();
        assert_eq!(got.bytes, b"ABABAB");
        assert_eq!(got.consumed, 6);
    }

    #[test]
    fn extended_literal_count_decodes_exactly() {
        let mut budget = DecodeBudget::new(16);
        let got = decompress1(&[0x10, 0x02, 0xbb], 2, &mut budget).unwrap();
        assert_eq!(got.bytes, [0xbb, 0x00]);
        assert_eq!(got.consumed, 3);
    }

    #[test]
    fn truncated_input_is_rejected() {
        let mut budget = DecodeBudget::new(16);
        let error = decompress1(&[0x10], 2, &mut budget).unwrap_err();
        assert_eq!(
            error,
            ScatterError::Malformed {
                loader: 0,
                entry: None,
                reason: "truncated input".into(),
            }
        );
    }

    #[test]
    fn extended_literal_code_zero_is_rejected() {
        let mut budget = DecodeBudget::new(16);
        let error = decompress1(&[0x10, 0x00], 1, &mut budget).unwrap_err();
        assert_eq!(
            error,
            ScatterError::Malformed {
                loader: 0,
                entry: None,
                reason: "extended literal code is zero".into(),
            }
        );
    }

    #[test]
    fn token_making_no_output_progress_is_rejected() {
        let mut budget = DecodeBudget::new(16);
        let error = decompress1(&[0x01, 0x00], 1, &mut budget).unwrap_err();
        assert_eq!(
            error,
            ScatterError::Malformed {
                loader: 0,
                entry: None,
                reason: "token made no output progress".into(),
            }
        );
    }

    #[test]
    fn distance_zero_is_rejected() {
        let mut budget = DecodeBudget::new(16);
        let error = decompress1(&[0x1a, b'A', 0x00], 4, &mut budget).unwrap_err();
        assert_eq!(
            error,
            ScatterError::Malformed {
                loader: 0,
                entry: None,
                reason: "back-reference distance is zero".into(),
            }
        );
    }

    #[test]
    fn distance_beyond_output_is_rejected() {
        let mut budget = DecodeBudget::new(16);
        let error = decompress1(&[0x1a, b'A', 0x02], 4, &mut budget).unwrap_err();
        assert_eq!(
            error,
            ScatterError::Malformed {
                loader: 0,
                entry: None,
                reason: "back-reference distance exceeds output".into(),
            }
        );
    }

    #[test]
    fn literal_overflow_is_rejected() {
        let mut budget = DecodeBudget::new(16);
        let error = decompress1(&[0x13, b'A', b'B'], 1, &mut budget).unwrap_err();
        assert_eq!(
            error,
            ScatterError::Malformed {
                loader: 0,
                entry: None,
                reason: "literal count exceeds expected output".into(),
            }
        );
    }

    #[test]
    fn zero_run_overflow_is_rejected() {
        let mut budget = DecodeBudget::new(16);
        let error = decompress1(&[0x22, 0xaa], 2, &mut budget).unwrap_err();
        assert_eq!(
            error,
            ScatterError::Malformed {
                loader: 0,
                entry: None,
                reason: "zero run exceeds expected output".into(),
            }
        );
    }

    #[test]
    fn back_reference_overflow_is_rejected() {
        let mut budget = DecodeBudget::new(16);
        let error = decompress1(&[0x2a, b'A', 0x01], 4, &mut budget).unwrap_err();
        assert_eq!(
            error,
            ScatterError::Malformed {
                loader: 0,
                entry: None,
                reason: "back-reference exceeds expected output".into(),
            }
        );
    }

    #[test]
    fn decode_work_limit_one_byte_below_requested_output_is_rejected() {
        let mut budget = DecodeBudget::new(1);
        let error = decompress1(&[0x12, b'A'], 2, &mut budget).unwrap_err();
        assert_eq!(
            error,
            ScatterError::ResourceLimit {
                what: "decoded output",
                limit: 1,
            }
        );
    }

    #[test]
    fn shared_decode_budget_counts_multiple_streams() {
        let mut budget = DecodeBudget::new(5);
        decompress1(&[0x22, 0xaa], 3, &mut budget).unwrap();
        let error = decompress1(&[0x12, 0xbb], 3, &mut budget).unwrap_err();
        assert_eq!(
            error,
            ScatterError::ResourceLimit {
                what: "decoded output",
                limit: 5,
            }
        );
    }
}
