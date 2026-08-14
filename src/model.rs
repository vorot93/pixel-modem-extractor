//! Model-agnostic derivation of a Pixel modem's identity from its FBPK /
//! firmware-directory name (e.g. "g5400i-260317-…", "g5300q-260317-…").
//!
//! The extractor is otherwise structural (TOC-driven); these helpers exist only
//! to recognize the firmware-directory token and to derive a *truthful* Shannon
//! modem-generation label ("S5400", "S5300") for human-facing output — without a
//! hardcoded model table.

/// The leading firmware token `g<digits><letter>` of an FBPK / firmware-dir name.
/// `"g5400i-260317-…"` → `Some("g5400i")`, `"g5300q-…"` → `Some("g5300q")`.
/// `None` when the name does not begin with that shape.
pub fn firmware_prefix(name: &str) -> Option<&str> {
    let rest = name.strip_prefix('g')?;
    let ndigits = rest.chars().take_while(|c| c.is_ascii_digit()).count();
    if ndigits == 0 {
        return None;
    }
    match rest.as_bytes().get(ndigits) {
        Some(b) if b.is_ascii_lowercase() => Some(&name[..1 + ndigits + 1]),
        _ => None,
    }
}

/// The Shannon modem generation derived from the firmware digits.
/// `"g5400i…"` → `Some("S5400")`, `"g5300q…"` → `Some("S5300")`.
/// Needs only `g` + a digit run (trailing letter optional). `None` otherwise.
pub fn modem_generation(name: &str) -> Option<String> {
    let rest = name.strip_prefix('g')?;
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        None
    } else {
        Some(format!("S{digits}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_from_g5400i() {
        let n = "g5400i-260317-260429-M-15308590";
        assert_eq!(firmware_prefix(n), Some("g5400i"));
        assert_eq!(modem_generation(n).as_deref(), Some("S5400"));
    }

    #[test]
    fn derives_from_g5300q() {
        let n = "g5300q-260317-260505-M-15346003";
        assert_eq!(firmware_prefix(n), Some("g5300q"));
        assert_eq!(modem_generation(n).as_deref(), Some("S5300"));
    }

    #[test]
    fn rejects_non_firmware_names() {
        for n in ["modem", "", "g-abc", "5400i", "gq"] {
            assert_eq!(firmware_prefix(n), None, "prefix {n}");
            assert_eq!(modem_generation(n), None, "gen {n}");
        }
        // firmware_prefix requires the trailing letter; modem_generation does not.
        assert_eq!(firmware_prefix("g5400"), None);
        assert_eq!(modem_generation("g5400").as_deref(), Some("S5400"));
    }
}
