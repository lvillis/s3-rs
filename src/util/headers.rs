use http::{HeaderMap, header::AsHeaderName};

pub(crate) fn header_string<N>(headers: &HeaderMap, name: N) -> Option<String>
where
    N: AsHeaderName,
{
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string())
}

pub(crate) fn header_u64<N>(headers: &HeaderMap, name: N) -> Option<u64>
where
    N: AsHeaderName,
{
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
}

pub(crate) fn copy_source_header_value(
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
) -> String {
    let bucket_enc = crate::util::encode::aws_percent_encode(bucket);
    let key_enc = crate::util::encode::aws_percent_encode_path(key);

    match version_id {
        Some(v) => {
            let version_enc = crate::util::encode::aws_percent_encode(v);
            format!("/{bucket_enc}/{key_enc}?versionId={version_enc}")
        }
        None => format!("/{bucket_enc}/{key_enc}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_string_and_u64_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("etag", "\"abc\"".parse().unwrap());
        headers.insert("content-length", "42".parse().unwrap());

        assert_eq!(header_string(&headers, "etag").as_deref(), Some("\"abc\""));
        assert_eq!(header_u64(&headers, "content-length"), Some(42));
    }

    #[test]
    fn copy_source_header_value_encodes_bucket_key_and_version() {
        assert_eq!(
            copy_source_header_value("bucket name", "dir/file name.txt", Some("v 1")),
            "/bucket%20name/dir/file%20name.txt?versionId=v%201"
        );
    }
}
