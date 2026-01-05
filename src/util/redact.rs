use http::header::HeaderName;

use crate::error::Error;

pub(crate) fn redact_value(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        return "<redacted>".to_string();
    }

    let head = value.chars().take(4).collect::<String>();
    let tail = value
        .chars()
        .rev()
        .take(4)
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();

    if head.len() + tail.len() >= value.len() {
        return "<redacted>".to_string();
    }

    format!("{head}...{tail}")
}

pub(crate) fn metadata_header_name(value: &str) -> Result<HeaderName, Error> {
    let value = value.trim();
    if value.is_empty() {
        return Err(Error::invalid_config("metadata key must not be empty"));
    }

    let mut name = String::with_capacity("x-amz-meta-".len() + value.len());
    name.push_str("x-amz-meta-");
    name.push_str(&value.to_ascii_lowercase());

    HeaderName::from_bytes(name.as_bytes())
        .map_err(|_| Error::invalid_config("invalid metadata key for x-amz-meta-* header"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_values_consistently() {
        assert_eq!(redact_value(""), "<redacted>");
        assert_eq!(redact_value("   "), "<redacted>");
        assert_eq!(redact_value("12345678"), "<redacted>");
        assert_eq!(redact_value("123456789"), "1234...6789");
    }

    #[test]
    fn builds_metadata_header_name() {
        let name = metadata_header_name(" Foo ").unwrap();
        assert_eq!(name.as_str(), "x-amz-meta-foo");

        assert!(metadata_header_name("").is_err());
        assert!(metadata_header_name("a b").is_err());
    }
}
