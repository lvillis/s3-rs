use bytes::Bytes;
use hmac::{Hmac, Mac as _};
use http::{HeaderMap, HeaderValue, Method};
use sha2::Digest as _;
use sha2::Sha256;
use time::OffsetDateTime;

use crate::{
    auth::{Credentials, Region},
    error::Error,
    types::PresignedRequest,
    util::url::ResolvedUrl,
};

type HmacSha256 = Hmac<Sha256>;

pub(crate) const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";
const DEFAULT_SERVICE: &str = "s3";

#[derive(Clone, Copy)]
pub(crate) struct SigV4Params<'a> {
    region: &'a Region,
    service: &'a str,
    credentials: &'a Credentials,
    now: OffsetDateTime,
}

impl<'a> SigV4Params<'a> {
    pub(crate) fn new(
        region: &'a Region,
        service: &'a str,
        credentials: &'a Credentials,
        now: OffsetDateTime,
    ) -> Self {
        Self {
            region,
            service,
            credentials,
            now,
        }
    }

    pub(crate) fn for_s3(
        region: &'a Region,
        credentials: &'a Credentials,
        now: OffsetDateTime,
    ) -> Self {
        Self::new(region, DEFAULT_SERVICE, credentials, now)
    }
}

pub(crate) fn payload_hash_bytes(body: &Bytes) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    let digest = hasher.finalize();
    hex::encode(digest)
}

pub(crate) fn payload_hash_empty() -> String {
    payload_hash_bytes(&Bytes::new())
}

pub(crate) fn sign_headers(
    method: &Method,
    resolved: &ResolvedUrl,
    headers: &mut HeaderMap,
    payload_hash: &str,
    region: &Region,
    credentials: &Credentials,
    now: OffsetDateTime,
) -> Result<(), Error> {
    sign_headers_with_service(
        method,
        resolved,
        headers,
        payload_hash,
        SigV4Params::for_s3(region, credentials, now),
    )
}

pub(crate) fn sign_headers_with_service(
    method: &Method,
    resolved: &ResolvedUrl,
    headers: &mut HeaderMap,
    payload_hash: &str,
    params: SigV4Params<'_>,
) -> Result<(), Error> {
    set_amz_headers(headers, payload_hash, params.credentials, params.now)?;

    let host_header_value = host_header_value(&resolved.url)?;
    headers.insert(http::header::HOST, host_header_value);

    let (canonical_headers, signed_headers) = canonicalize_headers(headers);

    let canonical_request = canonical_request(
        method,
        &resolved.canonical_uri,
        &resolved.canonical_query_string,
        &canonical_headers,
        &signed_headers,
        payload_hash,
    );

    let string_to_sign = string_to_sign(
        params.region,
        params.service,
        params.now,
        &canonical_request,
    );
    let signature = signature(
        params.credentials,
        params.region,
        params.service,
        params.now,
        &string_to_sign,
    )?;

    let credential_scope = credential_scope(params.region, params.service, params.now);
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        params.credentials.access_key_id, credential_scope, signed_headers, signature
    );

    let value = HeaderValue::from_str(&authorization)
        .map_err(|_| Error::signing("invalid authorization header value"))?;
    headers.insert(http::header::AUTHORIZATION, value);

    Ok(())
}

pub(crate) fn presign(
    method: Method,
    resolved: ResolvedUrl,
    params: SigV4Params<'_>,
    expires_in: std::time::Duration,
    existing_query_params: &[(String, String)],
    headers: &HeaderMap,
) -> Result<PresignedRequest, Error> {
    let mut resolved = resolved;
    let expires = expires_in.as_secs();
    if expires == 0 {
        return Err(Error::invalid_config("presign expires_in must be > 0"));
    }
    if expires > 604_800 {
        return Err(Error::invalid_config(
            "presign expires_in must be <= 7 days",
        ));
    }

    let mut signing_headers = headers.clone();
    signing_headers.insert(http::header::HOST, host_header_value(&resolved.url)?);
    let (canonical_headers, signed_headers) = canonicalize_headers(&signing_headers);

    let amz_date = amz_datetime(params.now);
    let credential_scope = credential_scope(params.region, params.service, params.now);
    let credential = format!("{}/{}", params.credentials.access_key_id, credential_scope);

    let mut query_params = existing_query_params.to_vec();
    query_params.push((
        "X-Amz-Algorithm".to_string(),
        "AWS4-HMAC-SHA256".to_string(),
    ));
    query_params.push(("X-Amz-Credential".to_string(), credential));
    query_params.push(("X-Amz-Date".to_string(), amz_date));
    query_params.push(("X-Amz-Expires".to_string(), expires.to_string()));

    query_params.push(("X-Amz-SignedHeaders".to_string(), signed_headers.clone()));

    if let Some(token) = &params.credentials.session_token {
        query_params.push(("X-Amz-Security-Token".to_string(), token.clone()));
    }

    resolved.canonical_query_string = crate::util::encode::canonical_query_string(&query_params);
    resolved
        .url
        .set_query(Some(&resolved.canonical_query_string));

    let canonical_request = canonical_request(
        &method,
        &resolved.canonical_uri,
        &resolved.canonical_query_string,
        &canonical_headers,
        &signed_headers,
        UNSIGNED_PAYLOAD,
    );

    let string_to_sign = string_to_sign(
        params.region,
        params.service,
        params.now,
        &canonical_request,
    );
    let sig = signature(
        params.credentials,
        params.region,
        params.service,
        params.now,
        &string_to_sign,
    )?;

    query_params.push(("X-Amz-Signature".to_string(), sig));
    let final_query = crate::util::encode::canonical_query_string(&query_params);
    resolved.url.set_query(Some(&final_query));

    Ok(PresignedRequest {
        method,
        url: resolved.url,
        headers: headers.clone(),
    })
}

fn set_amz_headers(
    headers: &mut HeaderMap,
    payload_hash: &str,
    credentials: &Credentials,
    now: OffsetDateTime,
) -> Result<(), Error> {
    let amz_date = amz_datetime(now);
    let amz_date = HeaderValue::from_str(&amz_date)
        .map_err(|_| Error::signing("invalid x-amz-date header value"))?;
    headers.insert("x-amz-date", amz_date);

    let payload_hash = HeaderValue::from_str(payload_hash)
        .map_err(|_| Error::signing("invalid x-amz-content-sha256 header value"))?;
    headers.insert("x-amz-content-sha256", payload_hash);

    if let Some(token) = &credentials.session_token {
        let token = HeaderValue::from_str(token)
            .map_err(|_| Error::signing("invalid x-amz-security-token header value"))?;
        headers.insert("x-amz-security-token", token);
    }

    Ok(())
}

fn host_header_value(url: &url::Url) -> Result<HeaderValue, Error> {
    let host = url
        .host_str()
        .ok_or_else(|| Error::invalid_config("endpoint must include host"))?;
    let default_port = match url.scheme() {
        "http" => Some(80),
        "https" => Some(443),
        _ => None,
    };
    let host = match (url.port(), default_port) {
        (Some(port), Some(default)) if port != default => format!("{host}:{port}"),
        (Some(port), None) => format!("{host}:{port}"),
        _ => host.to_string(),
    };

    HeaderValue::from_str(&host).map_err(|_| Error::signing("invalid host header value"))
}

fn canonicalize_headers(headers: &HeaderMap) -> (String, String) {
    let mut pairs = headers
        .iter()
        .filter_map(|(name, value)| {
            let name_str = name.as_str();
            if !should_sign_header(name_str) {
                return None;
            }
            let value_str = value.to_str().ok()?;
            Some((
                name_str.to_ascii_lowercase(),
                normalize_header_value(value_str),
            ))
        })
        .collect::<Vec<_>>();

    pairs.sort_by(|a, b| a.0.cmp(&b.0));

    let mut canonical_headers = String::new();
    let mut signed_headers = String::new();
    for (idx, (name, value)) in pairs.into_iter().enumerate() {
        canonical_headers.push_str(&name);
        canonical_headers.push(':');
        canonical_headers.push_str(&value);
        canonical_headers.push('\n');

        if idx > 0 {
            signed_headers.push(';');
        }
        signed_headers.push_str(&name);
    }

    (canonical_headers, signed_headers)
}

fn should_sign_header(name: &str) -> bool {
    match name {
        "host"
        | "content-type"
        | "content-md5"
        | "range"
        | "if-match"
        | "if-none-match"
        | "if-modified-since"
        | "if-unmodified-since" => true,
        _ => name.starts_with("x-amz-"),
    }
}

fn normalize_header_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut in_ws = false;
    for c in value.trim().chars() {
        if c.is_whitespace() {
            in_ws = true;
            continue;
        }
        if in_ws && !out.is_empty() {
            out.push(' ');
        }
        in_ws = false;
        out.push(c);
    }
    out
}

fn canonical_request(
    method: &Method,
    canonical_uri: &str,
    canonical_query_string: &str,
    canonical_headers: &str,
    signed_headers: &str,
    payload_hash: &str,
) -> String {
    format!(
        "{method}\n{canonical_uri}\n{canonical_query_string}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    )
}

fn string_to_sign(
    region: &Region,
    service: &str,
    now: OffsetDateTime,
    canonical_request: &str,
) -> String {
    let amz_date = amz_datetime(now);
    let scope = credential_scope(region, service, now);
    let hashed = sha256_hex(canonical_request.as_bytes());
    format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{hashed}")
}

fn signature(
    credentials: &Credentials,
    region: &Region,
    service: &str,
    now: OffsetDateTime,
    string_to_sign: &str,
) -> Result<String, Error> {
    let k_date = hmac_sha256(
        format!("AWS4{}", credentials.secret_access_key).as_bytes(),
        date_stamp(now).as_bytes(),
    )?;
    let k_region = hmac_sha256(&k_date, region.as_str().as_bytes())?;
    let k_service = hmac_sha256(&k_region, service.as_bytes())?;
    let k_signing = hmac_sha256(&k_service, b"aws4_request")?;
    let sig = hmac_sha256(&k_signing, string_to_sign.as_bytes())?;
    Ok(hex::encode(sig))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|_| Error::signing("invalid HMAC key"))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn date_stamp(now: OffsetDateTime) -> String {
    let year = now.year();
    let month = now.month() as u8;
    let day = now.day();
    format!("{year:04}{month:02}{day:02}")
}

fn amz_datetime(now: OffsetDateTime) -> String {
    let year = now.year();
    let month = now.month() as u8;
    let day = now.day();
    let hour = now.hour();
    let minute = now.minute();
    let second = now.second();
    format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z")
}

fn credential_scope(region: &Region, service: &str, now: OffsetDateTime) -> String {
    format!(
        "{}/{}/{service}/aws4_request",
        date_stamp(now),
        region.as_str()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{auth::AddressingStyle, util::url as s3_url};
    use std::time::Duration;

    #[test]
    fn signs_headers_and_sets_expected_fields() {
        let endpoint = url::Url::parse("https://example.com").unwrap();
        let region = Region::new("us-east-1").unwrap();
        let creds =
            Credentials::new("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY").unwrap();
        let now = OffsetDateTime::from_unix_timestamp(1_369_353_600).unwrap();

        let resolved = s3_url::resolve_url(
            &endpoint,
            Some("my-bucket"),
            Some("a+b"),
            &[],
            AddressingStyle::Path,
        )
        .unwrap();

        let mut headers = HeaderMap::new();
        sign_headers(
            &Method::GET,
            &resolved,
            &mut headers,
            &payload_hash_empty(),
            &region,
            &creds,
            now,
        )
        .unwrap();

        assert_eq!(
            headers.get("x-amz-date").unwrap().to_str().unwrap(),
            "20130524T000000Z"
        );

        let auth = headers
            .get(http::header::AUTHORIZATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(auth.starts_with(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20130524/us-east-1/s3/aws4_request,"
        ));
        assert!(auth.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date,"));
        assert!(auth.contains("Signature="));
        let sig = auth.split("Signature=").nth(1).unwrap();
        assert_eq!(sig.len(), 64);
        assert!(
            sig.chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
        );
    }

    #[test]
    fn presign_includes_expected_query_params() {
        let endpoint = url::Url::parse("https://example.com").unwrap();
        let region = Region::new("us-east-1").unwrap();
        let creds =
            Credentials::new("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY").unwrap();
        let now = OffsetDateTime::from_unix_timestamp(1_369_353_600).unwrap();

        let resolved = s3_url::resolve_url(
            &endpoint,
            Some("my-bucket"),
            Some("a+b"),
            &[],
            AddressingStyle::Path,
        )
        .unwrap();

        let presigned = presign(
            Method::GET,
            resolved,
            SigV4Params::for_s3(&region, &creds, now),
            Duration::from_secs(60),
            &[],
            &HeaderMap::new(),
        )
        .unwrap();

        let s = presigned.url.as_str();
        assert!(s.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"));
        assert!(
            s.contains("X-Amz-Credential=AKIDEXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request")
        );
        assert!(s.contains("X-Amz-Date=20130524T000000Z"));
        assert!(s.contains("X-Amz-Expires=60"));
        assert!(s.contains("X-Amz-SignedHeaders=host"));
        assert!(s.contains("X-Amz-Signature="));
    }

    #[test]
    fn presign_can_sign_additional_headers() {
        let endpoint = url::Url::parse("https://example.com").unwrap();
        let region = Region::new("us-east-1").unwrap();
        let creds =
            Credentials::new("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY").unwrap();
        let now = OffsetDateTime::from_unix_timestamp(1_369_353_600).unwrap();

        let resolved = s3_url::resolve_url(
            &endpoint,
            Some("my-bucket"),
            Some("a+b"),
            &[],
            AddressingStyle::Path,
        )
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain"),
        );

        let presigned = presign(
            Method::PUT,
            resolved,
            SigV4Params::for_s3(&region, &creds, now),
            Duration::from_secs(60),
            &[],
            &headers,
        )
        .unwrap();

        let s = presigned.url.as_str();
        assert!(s.contains("X-Amz-SignedHeaders=content-type%3Bhost"));
        assert_eq!(
            presigned
                .headers
                .get(http::header::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap(),
            "text/plain"
        );
    }
}
