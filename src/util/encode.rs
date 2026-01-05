fn is_unreserved(byte: u8) -> bool {
    matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~')
}

pub(crate) fn aws_percent_encode(input: &str) -> String {
    aws_percent_encode_impl(input, false)
}

pub(crate) fn aws_percent_encode_path(input: &str) -> String {
    aws_percent_encode_impl(input, true)
}

fn aws_percent_encode_impl(input: &str, preserve_slash: bool) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        if is_unreserved(b) || (preserve_slash && b == b'/') {
            out.push(b as char);
            continue;
        }

        out.push('%');
        out.push(hex_upper(b >> 4));
        out.push(hex_upper(b & 0x0F));
    }
    out
}

fn hex_upper(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'A' + (nibble - 10)) as char,
        _ => '0',
    }
}

pub(crate) fn canonical_query_string(params: &[(String, String)]) -> String {
    let mut items = params
        .iter()
        .map(|(k, v)| (aws_percent_encode(k), aws_percent_encode(v)))
        .collect::<Vec<_>>();

    items.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    let mut out = String::new();
    for (idx, (k, v)) in items.into_iter().enumerate() {
        if idx > 0 {
            out.push('&');
        }
        out.push_str(&k);
        out.push('=');
        out.push_str(&v);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_encoding_for_query_uses_rfc3986() {
        assert_eq!(aws_percent_encode("a+b c"), "a%2Bb%20c");
        assert_eq!(aws_percent_encode("~"), "~");
        assert_eq!(aws_percent_encode("/"), "%2F");
    }

    #[test]
    fn percent_encoding_for_path_preserves_slash() {
        assert_eq!(aws_percent_encode_path("a/b+c"), "a/b%2Bc");
        assert_eq!(aws_percent_encode_path("/a b"), "/a%20b");
    }

    #[test]
    fn canonical_query_string_sorts_and_encodes() {
        let params = vec![
            ("b".to_string(), "2".to_string()),
            ("a".to_string(), "1".to_string()),
            ("a".to_string(), "0".to_string()),
            ("space".to_string(), "a b".to_string()),
        ];
        assert_eq!(canonical_query_string(&params), "a=0&a=1&b=2&space=a%20b");
    }
}
