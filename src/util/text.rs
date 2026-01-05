pub(crate) fn truncate_snippet(body: &str, max_len: usize) -> String {
    if body.len() <= max_len {
        return body.to_string();
    }

    let cut = if body.is_char_boundary(max_len) {
        max_len
    } else {
        body.char_indices()
            .take_while(|(idx, _)| *idx < max_len)
            .last()
            .map(|(idx, _)| idx)
            .unwrap_or(0)
    };

    let mut out = body[..cut].to_string();
    out.push_str("...");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncates_ascii_without_panic() {
        let body = "a".repeat(10);
        assert_eq!(truncate_snippet(&body, 10), body);
        assert_eq!(truncate_snippet(&body, 5), "aaaaa...");
    }

    #[test]
    fn truncates_utf8_safely() {
        let body = "你好，世界".repeat(10);
        let out = truncate_snippet(&body, 5);
        assert!(out.ends_with("..."));
        assert!(out.len() > 3);
        assert!(out.len() <= 5 + 3);
    }
}
