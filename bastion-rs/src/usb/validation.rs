//! Input sanitisation for untrusted USB descriptor strings and rule keys.

const MAX_SERIAL_LEN: usize = 128;
const MAX_NAME_LEN: usize = 256;
const MAX_KEY_LEN: usize = 256;

/// Keep only hex digits, lowercase, truncate to 4 and left-pad with zeros.
pub fn sanitize_hex_id(input: &str) -> String {
    let clean: String = input
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_ascii_lowercase())
        .take(4)
        .collect();
    format!("{:0>4}", clean)
}

fn is_serial_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-'
}

/// Keep `[A-Za-z0-9._-]`, at most 128 chars; empty result becomes `no-serial`.
pub fn sanitize_serial(input: &str) -> String {
    let clean: String = input.chars().filter(|c| is_serial_char(*c)).take(MAX_SERIAL_LEN).collect();
    if clean.is_empty() {
        "no-serial".to_string()
    } else {
        clean
    }
}

/// Strip control characters and truncate a vendor/product name.
pub fn sanitize_name(input: &str) -> String {
    input.chars().filter(|c| !c.is_control()).take(MAX_NAME_LEN).collect()
}

fn is_hex4(s: &str) -> bool {
    s.len() == 4 && s.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

/// Valid rule keys: `vvvv:pppp:serial`, `vvvv:pppp:*` or `vvvv:*:*`.
pub fn validate_key(key: &str) -> bool {
    if key.len() > MAX_KEY_LEN {
        return false;
    }
    let parts: Vec<&str> = key.split(':').collect();
    let [vendor, product, serial] = parts.as_slice() else {
        return false;
    };
    if !is_hex4(vendor) {
        return false;
    }
    match (*product, *serial) {
        ("*", "*") => true,
        ("*", _) => false,
        (p, "*") => is_hex4(p),
        (p, s) => is_hex4(p) && !s.is_empty() && s.len() <= MAX_SERIAL_LEN && s.chars().all(is_serial_char),
    }
}

/// Bus ids look like `1-2.3`; digits, `-` and `.` only, starting with a digit.
pub fn validate_bus_id(bus_id: &str) -> bool {
    !bus_id.is_empty()
        && bus_id.len() <= 32
        && bus_id.starts_with(|c: char| c.is_ascii_digit())
        && bus_id.chars().all(|c| c.is_ascii_digit() || c == '-' || c == '.')
        && !bus_id.contains("..")
        && !bus_id.ends_with('.')
        && !bus_id.ends_with('-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_ids() {
        assert_eq!(sanitize_hex_id("046D"), "046d");
        assert_eq!(sanitize_hex_id("6d"), "006d");
        assert_eq!(sanitize_hex_id("zz12345"), "1234");
        assert_eq!(sanitize_hex_id(""), "0000");
    }

    #[test]
    fn serials() {
        assert_eq!(sanitize_serial("AB:C/12 3"), "ABC123");
        assert_eq!(sanitize_serial("../"), "..");
        assert_eq!(sanitize_serial("///"), "no-serial");
        assert_eq!(sanitize_serial(&"a".repeat(500)).len(), 128);
    }

    #[test]
    fn names_drop_control_chars() {
        assert_eq!(sanitize_name("Log\x1b[31mi\ntech"), "Log[31mitech");
    }

    #[test]
    fn keys() {
        assert!(validate_key("046d:c52b:ABC123"));
        assert!(validate_key("046d:c52b:*"));
        assert!(validate_key("046d:*:*"));
        assert!(!validate_key("046d:*:ABC"));
        assert!(!validate_key("046D:c52b:*"));
        assert!(!validate_key("046d:c52b"));
        assert!(!validate_key("046d:c52b:a:b"));
        assert!(!validate_key("046d:c52b:a b"));
        assert!(!validate_key("046d:c52b:"));
        assert!(!validate_key(&format!("046d:c52b:{}", "a".repeat(300))));
    }

    #[test]
    fn bus_ids() {
        assert!(validate_bus_id("1-2.3"));
        assert!(validate_bus_id("3-4"));
        assert!(!validate_bus_id(""));
        assert!(!validate_bus_id("usb1"));
        assert!(!validate_bus_id("1-2/../3"));
        assert!(!validate_bus_id("1..2"));
        assert!(!validate_bus_id("1-2."));
    }
}
