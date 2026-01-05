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
