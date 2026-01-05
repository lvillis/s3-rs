use std::net::IpAddr;

use url::Url;

use crate::{auth::AddressingStyle, error::Error};

pub(crate) struct ResolvedUrl {
    pub(crate) url: Url,
    pub(crate) canonical_uri: String,
    pub(crate) canonical_query_string: String,
}

pub(crate) fn resolve_url(
    base_url: &Url,
    bucket: Option<&str>,
    key: Option<&str>,
    query_params: &[(String, String)],
    addressing: AddressingStyle,
) -> Result<ResolvedUrl, Error> {
    let mut url = base_url.clone();

    let canonical_query_string = crate::util::encode::canonical_query_string(query_params);

    if canonical_query_string.is_empty() {
        url.set_query(None);
    } else {
        url.set_query(Some(&canonical_query_string));
    }

    let Some(bucket) = bucket else {
        url.set_path("/");
        return Ok(ResolvedUrl {
            url,
            canonical_uri: "/".to_string(),
            canonical_query_string,
        });
    };

    let host = base_url
        .host_str()
        .ok_or_else(|| Error::invalid_config("endpoint must include host"))?;

    let resolved_style = resolve_addressing_style(base_url, host, bucket, addressing);

    let (final_host, raw_path) = match resolved_style {
        AddressingStyle::Path => {
            let raw_path = match key {
                Some(key) => format!("/{bucket}/{key}"),
                None => format!("/{bucket}"),
            };
            (host.to_string(), raw_path)
        }
        AddressingStyle::VirtualHosted => {
            if !is_dns_compatible_bucket(bucket) {
                return Err(Error::invalid_config(
                    "bucket is not DNS compatible for virtual-hosted-style",
                ));
            }
            let raw_path = match key {
                Some(key) if !key.is_empty() => format!("/{key}"),
                _ => "/".to_string(),
            };
            (format!("{bucket}.{host}"), raw_path)
        }
        AddressingStyle::Auto => {
            return Err(Error::invalid_config(
                "internal error: auto addressing style must be resolved",
            ));
        }
    };

    let canonical_uri = crate::util::encode::aws_percent_encode_path(&raw_path);

    url.set_path(&canonical_uri);
    url.set_host(Some(&final_host))
        .map_err(|_| Error::invalid_config("invalid endpoint host"))?;

    Ok(ResolvedUrl {
        url,
        canonical_uri,
        canonical_query_string,
    })
}

fn resolve_addressing_style(
    base_url: &Url,
    host: &str,
    bucket: &str,
    addressing: AddressingStyle,
) -> AddressingStyle {
    match addressing {
        AddressingStyle::Path | AddressingStyle::VirtualHosted => addressing,
        AddressingStyle::Auto => {
            if host == "localhost" || host.parse::<IpAddr>().is_ok() {
                return AddressingStyle::Path;
            }

            if base_url.scheme() == "https" && bucket.contains('.') {
                return AddressingStyle::Path;
            }

            if !is_dns_compatible_bucket(bucket) {
                return AddressingStyle::Path;
            }

            AddressingStyle::VirtualHosted
        }
    }
}

fn is_dns_compatible_bucket(bucket: &str) -> bool {
    let bytes = bucket.as_bytes();
    if bytes.len() < 3 || bytes.len() > 63 {
        return false;
    }

    if bytes.iter().any(|b| b.is_ascii_uppercase()) {
        return false;
    }

    let is_allowed = |b: u8| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.');
    if !bytes.iter().all(|&b| is_allowed(b)) {
        return false;
    }

    let starts_ok = matches!(bytes[0], b'a'..=b'z' | b'0'..=b'9');
    let ends_ok = matches!(bytes[bytes.len() - 1], b'a'..=b'z' | b'0'..=b'9');
    if !starts_ok || !ends_ok {
        return false;
    }

    if bucket.contains("..") {
        return false;
    }

    if bucket.parse::<IpAddr>().is_ok() {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AddressingStyle;

    #[test]
    fn resolves_path_style_url_and_does_not_double_encode() {
        let base = Url::parse("https://example.com").unwrap();
        let resolved = resolve_url(
            &base,
            Some("my-bucket"),
            Some("a+b"),
            &[],
            AddressingStyle::Path,
        )
        .unwrap();

        assert_eq!(resolved.canonical_uri, "/my-bucket/a%2Bb");
        assert_eq!(resolved.url.as_str(), "https://example.com/my-bucket/a%2Bb");
    }

    #[test]
    fn resolves_virtual_hosted_style_url() {
        let base = Url::parse("https://s3.example.com").unwrap();
        let resolved = resolve_url(
            &base,
            Some("mybucket"),
            Some("a+b"),
            &[],
            AddressingStyle::VirtualHosted,
        )
        .unwrap();

        assert_eq!(resolved.url.host_str().unwrap(), "mybucket.s3.example.com");
        assert_eq!(resolved.canonical_uri, "/a%2Bb");
    }

    #[test]
    fn auto_falls_back_to_path_style_for_dot_bucket_on_https() {
        let base = Url::parse("https://s3.example.com").unwrap();
        let resolved = resolve_url(
            &base,
            Some("bucket.with.dots"),
            Some("key"),
            &[],
            AddressingStyle::Auto,
        )
        .unwrap();

        assert_eq!(resolved.url.host_str().unwrap(), "s3.example.com");
        assert_eq!(resolved.canonical_uri, "/bucket.with.dots/key");
    }

    #[test]
    fn path_encoding_preserves_slash_in_key() {
        let base = Url::parse("https://example.com").unwrap();
        let resolved = resolve_url(
            &base,
            Some("my-bucket"),
            Some("a/b"),
            &[],
            AddressingStyle::Path,
        )
        .unwrap();

        assert_eq!(resolved.canonical_uri, "/my-bucket/a/b");
    }

    #[test]
    fn query_params_are_canonicalized_and_applied_to_url() {
        let base = Url::parse("https://example.com").unwrap();
        let resolved = resolve_url(
            &base,
            Some("my-bucket"),
            Some("key"),
            &[
                ("b".to_string(), "2".to_string()),
                ("a".to_string(), "".to_string()),
            ],
            AddressingStyle::Path,
        )
        .unwrap();

        assert_eq!(resolved.canonical_query_string, "a=&b=2");
        assert_eq!(resolved.url.query().unwrap_or(""), "a=&b=2");
    }
}
