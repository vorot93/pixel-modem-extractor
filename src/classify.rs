//! Opaque-image classification: a 5-test statistical battery over a firmware image.
//!
//! Uniform high entropy with no byte-frequency, correlation, or windowed structure
//! marks an image as `opaque` (consistent with encryption, e.g. mustang `01_PSP`),
//! letting downstream Ghidra runs skip it: nothing is recoverable from such bytes.
//!
//! The battery:
//! - `entropy_bits` — whole-image Shannon entropy over the 256-bucket byte histogram.
//! - `chi2_per_df` — χ² uniformity of that histogram (Σ(obs−exp)²/exp with exp = n/256,
//!   reported ÷ 255 df).
//! - `serial_correlation` — serial-correlation coefficient over consecutive bytes.
//! - `window_min`/`window_mean`/`window_max`/`frac_windows_high` — Shannon entropy per
//!   64-KiB window (trailing window counted iff ≥ 4 KiB); catches partial encryption
//!   that a whole-image average can hide.
//!
//! Verdict is **unanimous and fail-closed**: `opaque` iff H ≥ 7.5 ∧ χ²/df ≤ 64.0 ∧
//! |SCC| ≤ 0.10 ∧ window_min ≥ 7.7 ∧ frac_windows_high ≥ 0.99. Any single refusal —
//! including `window_count == 0`, where the window stats stay 0.0 and thus refuse —
//! yields `not_opaque`, and the image goes to Ghidra exactly as today: a
//! partially-encrypted image is never skipped.
//!
//! Calibration corpus (both reference models; mustang `01_PSP` is the only opaque
//! image on both): ~/.superpowers/pixel-modem-extractor/2026-08-19-opaque-image-classification-design.md

use serde::Serialize;

/// Stride of the per-window entropy tests.
pub const WINDOW_SIZE: usize = 64 * 1024;

/// Per-window entropy strictly above this counts the window in `frac_windows_high`.
pub const HIGH_ENTROPY_WINDOW: f64 = 7.5;

/// A trailing partial window shorter than this is not counted.
const TRAILING_WINDOW_MIN: usize = 4096;

const ENTROPY_MIN: f64 = 7.5;
const CHI2_PER_DF_MAX: f64 = 64.0;
const SERIAL_CORRELATION_MAX: f64 = 0.10;
const WINDOW_ENTROPY_MIN: f64 = 7.7;
const FRAC_WINDOWS_HIGH_MIN: f64 = 0.99;

/// Opaque-image battery over one firmware image. All floats full-precision; rounding
/// happens at the serialization boundary.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct BatteryStats {
    pub opaque: bool,
    pub entropy_bits: f64,
    pub chi2_per_df: f64,
    pub serial_correlation: f64,
    pub window_min: f64,
    pub window_mean: f64,
    pub window_max: f64,
    pub frac_windows_high: f64,
    pub window_count: usize,
}

fn histogram(bytes: &[u8]) -> [u64; 256] {
    let mut hist = [0u64; 256];
    for &b in bytes {
        hist[b as usize] += 1;
    }
    hist
}

fn shannon_entropy(hist: &[u64; 256], n: usize) -> f64 {
    if n == 0 {
        return 0.0;
    }
    let n = n as f64;
    hist.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

fn chi2_per_df(hist: &[u64; 256], n: usize) -> f64 {
    if n == 0 {
        return 0.0;
    }
    let exp = n as f64 / 256.0;
    let chi2: f64 = hist
        .iter()
        .map(|&c| {
            let d = c as f64 - exp;
            d * d / exp
        })
        .sum();
    chi2 / 255.0
}

fn serial_correlation(bytes: &[u8]) -> f64 {
    let n = bytes.len();
    if n < 2 {
        return 0.0;
    }
    let (mut sum, mut sum_sq, mut sum_prod) = (0.0f64, 0.0f64, 0.0f64);
    for i in 0..n {
        let x = bytes[i] as f64;
        let y = bytes[(i + 1) % n] as f64;
        sum += x;
        sum_sq += x * x;
        sum_prod += x * y;
    }
    let n = n as f64;
    let num = n * sum_prod - sum * sum;
    let den = n * sum_sq - sum * sum;
    if den == 0.0 { 0.0 } else { num / den }
}

/// Run the opaque-image battery. Single-threaded and deterministic; an empty or
/// windowless input refuses (all window stats 0.0, `opaque == false`).
pub fn classify(bytes: &[u8]) -> BatteryStats {
    let n = bytes.len();
    let hist = histogram(bytes);
    let entropy_bits = shannon_entropy(&hist, n);
    let chi2_per_df = chi2_per_df(&hist, n);
    let serial_correlation = serial_correlation(bytes);

    let window_entropies: Vec<f64> = bytes
        .chunks(WINDOW_SIZE)
        .filter(|w| w.len() == WINDOW_SIZE || w.len() >= TRAILING_WINDOW_MIN)
        .map(|w| shannon_entropy(&histogram(w), w.len()))
        .collect();
    let window_count = window_entropies.len();
    let (window_min, window_mean, window_max, frac_windows_high) = if window_count == 0 {
        (0.0, 0.0, 0.0, 0.0)
    } else {
        let min = window_entropies
            .iter()
            .copied()
            .fold(f64::INFINITY, f64::min);
        let max = window_entropies
            .iter()
            .copied()
            .fold(f64::NEG_INFINITY, f64::max);
        let mean = window_entropies.iter().sum::<f64>() / window_count as f64;
        let high = window_entropies
            .iter()
            .filter(|&&h| h > HIGH_ENTROPY_WINDOW)
            .count();
        (min, mean, max, high as f64 / window_count as f64)
    };

    let opaque = entropy_bits >= ENTROPY_MIN
        && chi2_per_df <= CHI2_PER_DF_MAX
        && serial_correlation.abs() <= SERIAL_CORRELATION_MAX
        && window_min >= WINDOW_ENTROPY_MIN
        && frac_windows_high >= FRAC_WINDOWS_HIGH_MIN;

    BatteryStats {
        opaque,
        entropy_bits,
        chi2_per_df,
        serial_correlation,
        window_min,
        window_mean,
        window_max,
        frac_windows_high,
        window_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// xorshift64* (Vigna) emitting the top byte of each 64-bit output — the
    /// well-mixed end of the word.
    struct Xorshift64Star(u64);

    impl Xorshift64Star {
        fn seeded() -> Self {
            Self(0x9E3779B97F4A7C15)
        }

        fn byte(&mut self) -> u8 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            (x.wrapping_mul(0x2545F4914F6CDD1D) >> 56) as u8
        }
    }

    fn uniform_blob(len: usize) -> Vec<u8> {
        let mut rng = Xorshift64Star::seeded();
        (0..len).map(|_| rng.byte()).collect()
    }

    const PATTERN: [u8; 16] = [
        0x00, 0xBF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
        0xEE,
    ];

    fn pattern_blob(len: usize) -> Vec<u8> {
        (0..len).map(|i| PATTERN[i % 16]).collect()
    }

    #[test]
    fn uniform_blob_is_opaque() {
        let stats = classify(&uniform_blob(256 * 1024));
        assert!(stats.opaque);
        assert!(stats.entropy_bits >= ENTROPY_MIN);
        assert!(stats.chi2_per_df <= CHI2_PER_DF_MAX);
        assert!(stats.serial_correlation.abs() <= SERIAL_CORRELATION_MAX);
        assert!(stats.window_min >= WINDOW_ENTROPY_MIN);
        assert_eq!(stats.frac_windows_high, 1.0);
        assert_eq!(stats.window_count, 4);
    }

    #[test]
    fn low_entropy_arm_ish_blob_is_not_opaque() {
        let stats = classify(&pattern_blob(64 * 1024));
        assert!(!stats.opaque);
        assert!(stats.entropy_bits < ENTROPY_MIN);
        assert_eq!(stats.window_count, 1);
    }

    #[test]
    fn half_encrypted_blob_is_not_opaque() {
        let mut blob = uniform_blob(128 * 1024);
        blob.extend(pattern_blob(128 * 1024));
        let stats = classify(&blob);
        assert!(!stats.opaque);
        assert!(stats.window_min < WINDOW_ENTROPY_MIN);
        assert!(stats.frac_windows_high < FRAC_WINDOWS_HIGH_MIN);
        assert_eq!(stats.window_count, 4);
    }

    #[test]
    fn tiny_blob_has_no_windows() {
        let stats = classify(&uniform_blob(4095));
        assert_eq!(stats.window_count, 0);
        assert!(!stats.opaque);
    }
}
