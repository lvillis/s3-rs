use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
#[cfg(any(feature = "async", feature = "blocking"))]
use reqx::{
    advanced::TlsRootStore,
    prelude::{RedirectPolicy, RetryPolicy, StatusPolicy},
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    auth::{AddressingStyle, Credentials, CredentialsSnapshot, Region},
    error::Error,
};

const SERVICE: &str = "sts";
const STS_GLOBAL_ENDPOINT: &str = "https://sts.amazonaws.com";

#[cfg(feature = "async")]
pub(crate) async fn assume_role_async(
    region: Region,
    role_arn: String,
    role_session_name: String,
    source_credentials: Credentials,
    tls_root_store: TlsRootStore,
) -> Result<CredentialsSnapshot, Error> {
    use std::time::Duration;

    let endpoint = sts_regional_endpoint(&region)?;
    let body = form_body(&[
        ("Action", "AssumeRole"),
        ("Version", "2011-06-15"),
        ("RoleArn", &role_arn),
        ("RoleSessionName", &role_session_name),
    ]);

    let body_bytes = Bytes::from(body);
    let payload_hash = crate::util::signing::payload_hash_bytes(&body_bytes);

    let resolved =
        crate::util::url::resolve_url(&endpoint, None, None, &[], AddressingStyle::Path)?;

    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );

    let now = time::OffsetDateTime::now_utc();
    crate::util::signing::sign_headers_with_service(
        &Method::POST,
        &resolved,
        &mut headers,
        &payload_hash,
        crate::util::signing::SigV4Params::new(&region, SERVICE, &source_credentials, now),
    )?;

    let client = sts_async_client(Duration::from_secs(10), tls_root_store)?;
    let (status, headers, text) =
        send_form_async(&client, resolved.url.as_str(), headers, body_bytes).await?;

    if !status.is_success() {
        return Err(sts_api_error(status, &headers, &text));
    }

    parse_assume_role_response(&text)
}

#[cfg(feature = "blocking")]
pub(crate) fn assume_role_blocking(
    region: Region,
    role_arn: String,
    role_session_name: String,
    source_credentials: Credentials,
    tls_root_store: TlsRootStore,
) -> Result<CredentialsSnapshot, Error> {
    use std::time::Duration;

    let endpoint = sts_regional_endpoint(&region)?;
    let body = form_body(&[
        ("Action", "AssumeRole"),
        ("Version", "2011-06-15"),
        ("RoleArn", &role_arn),
        ("RoleSessionName", &role_session_name),
    ]);

    let body_bytes = Bytes::from(body);
    let payload_hash = crate::util::signing::payload_hash_bytes(&body_bytes);

    let resolved =
        crate::util::url::resolve_url(&endpoint, None, None, &[], AddressingStyle::Path)?;

    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );

    let now = time::OffsetDateTime::now_utc();
    crate::util::signing::sign_headers_with_service(
        &Method::POST,
        &resolved,
        &mut headers,
        &payload_hash,
        crate::util::signing::SigV4Params::new(&region, SERVICE, &source_credentials, now),
    )?;

    let client = sts_blocking_client(Duration::from_secs(10), tls_root_store)?;
    let (status, headers, text) =
        send_form_blocking(&client, resolved.url.as_str(), headers, body_bytes)?;

    if !status.is_success() {
        return Err(sts_api_error(status, &headers, &text));
    }

    parse_assume_role_response(&text)
}

#[cfg(feature = "async")]
pub(crate) async fn assume_role_with_web_identity_env_async(
    tls_root_store: TlsRootStore,
) -> Result<CredentialsSnapshot, Error> {
    use std::time::Duration;

    let (role_arn, session_name, token) = web_identity_env()?;
    let endpoint = web_identity_sts_endpoint(&role_arn)?;

    let body = form_body(&[
        ("Action", "AssumeRoleWithWebIdentity"),
        ("Version", "2011-06-15"),
        ("RoleArn", &role_arn),
        ("RoleSessionName", &session_name),
        ("WebIdentityToken", &token),
    ]);
    let body_bytes = Bytes::from(body);

    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );

    let client = sts_async_client(Duration::from_secs(10), tls_root_store)?;
    let (status, headers, text) =
        send_form_async(&client, endpoint.as_str(), headers, body_bytes).await?;

    if !status.is_success() {
        return Err(sts_api_error(status, &headers, &text));
    }

    parse_assume_role_with_web_identity_response(&text)
}

#[cfg(feature = "blocking")]
pub(crate) fn assume_role_with_web_identity_env_blocking(
    tls_root_store: TlsRootStore,
) -> Result<CredentialsSnapshot, Error> {
    use std::time::Duration;

    let (role_arn, session_name, token) = web_identity_env()?;
    let endpoint = web_identity_sts_endpoint(&role_arn)?;

    let body = form_body(&[
        ("Action", "AssumeRoleWithWebIdentity"),
        ("Version", "2011-06-15"),
        ("RoleArn", &role_arn),
        ("RoleSessionName", &session_name),
        ("WebIdentityToken", &token),
    ]);

    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );

    let client = sts_blocking_client(Duration::from_secs(10), tls_root_store)?;
    let (status, headers, text) =
        send_form_blocking(&client, endpoint.as_str(), headers, Bytes::from(body))?;

    if !status.is_success() {
        return Err(sts_api_error(status, &headers, &text));
    }

    parse_assume_role_with_web_identity_response(&text)
}

#[cfg(feature = "async")]
async fn send_form_async(
    client: &reqx::Client,
    url: &str,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, HeaderMap, String), Error> {
    let mut req = client
        .request(Method::POST, url.to_string())
        .body(body)
        .redirect_policy(RedirectPolicy::none())
        .retry_policy(RetryPolicy::disabled());
    for (name, value) in headers {
        if let Some(name) = name {
            req = req.header(name, value);
        }
    }

    let resp = req
        .status_policy(StatusPolicy::Response)
        .send()
        .await
        .map_err(|e| crate::transport::map_reqx_error("request failed", e))?;
    Ok((
        resp.status(),
        resp.headers().clone(),
        String::from_utf8_lossy(resp.body()).to_string(),
    ))
}

#[cfg(feature = "blocking")]
fn send_form_blocking(
    client: &reqx::blocking::Client,
    url: &str,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, HeaderMap, String), Error> {
    let mut req = client
        .request(Method::POST, url.to_string())
        .body(body)
        .redirect_policy(RedirectPolicy::none())
        .retry_policy(RetryPolicy::disabled());
    for (name, value) in headers {
        if let Some(name) = name {
            req = req.header(name, value);
        }
    }

    let resp = req
        .status_policy(StatusPolicy::Response)
        .send()
        .map_err(|e| crate::transport::map_reqx_error("request failed", e))?;
    Ok((
        resp.status(),
        resp.headers().clone(),
        String::from_utf8_lossy(resp.body()).to_string(),
    ))
}

fn sts_regional_endpoint(region: &Region) -> Result<url::Url, Error> {
    sts_regional_endpoint_for_partition(region, None)
}

fn sts_regional_endpoint_for_partition(
    region: &Region,
    partition: Option<&str>,
) -> Result<url::Url, Error> {
    let suffix = if matches!(partition, Some("aws-cn")) || region.as_str().starts_with("cn-") {
        "amazonaws.com.cn"
    } else {
        "amazonaws.com"
    };
    let url = format!("https://sts.{}.{suffix}", region.as_str());
    url::Url::parse(&url).map_err(|_| Error::invalid_config("invalid STS endpoint URL"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StsRegionalEndpointsMode {
    Legacy,
    Regional,
}

impl StsRegionalEndpointsMode {
    fn parse(value: &str) -> Result<Self, Error> {
        match value.trim().to_ascii_lowercase().as_str() {
            "legacy" => Ok(Self::Legacy),
            "regional" => Ok(Self::Regional),
            _ => Err(Error::invalid_config(
                "AWS_STS_REGIONAL_ENDPOINTS must be one of: legacy, regional",
            )),
        }
    }
}

fn sts_regional_endpoints_mode_from_env() -> Result<Option<StsRegionalEndpointsMode>, Error> {
    let value = match std::env::var("AWS_STS_REGIONAL_ENDPOINTS") {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    if value.trim().is_empty() {
        return Ok(None);
    }
    StsRegionalEndpointsMode::parse(&value).map(Some)
}

fn web_identity_region_from_env() -> Option<String> {
    std::env::var("AWS_REGION")
        .ok()
        .or_else(|| std::env::var("AWS_DEFAULT_REGION").ok())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn partition_from_role_arn(role_arn: &str) -> Option<&str> {
    let mut parts = role_arn.splitn(6, ':');
    match (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) {
        (Some("arn"), Some(partition), Some(_service), Some(_region), Some(_account))
            if !partition.is_empty() =>
        {
            Some(partition)
        }
        _ => None,
    }
}

fn web_identity_sts_endpoint(role_arn: &str) -> Result<url::Url, Error> {
    let partition = partition_from_role_arn(role_arn);
    let region = web_identity_region_from_env();
    let mode = sts_regional_endpoints_mode_from_env()?;
    resolve_web_identity_sts_endpoint(partition, region.as_deref(), mode)
}

fn resolve_web_identity_sts_endpoint(
    partition: Option<&str>,
    region: Option<&str>,
    mode: Option<StsRegionalEndpointsMode>,
) -> Result<url::Url, Error> {
    let requires_regional = matches!(partition, Some("aws-cn" | "aws-us-gov"));
    let use_regional = requires_regional
        || matches!(
            mode.unwrap_or(StsRegionalEndpointsMode::Legacy),
            StsRegionalEndpointsMode::Regional
        );

    if use_regional {
        let region = region.ok_or_else(|| {
            Error::invalid_config(
                "AWS_REGION or AWS_DEFAULT_REGION is required for regional STS endpoint",
            )
        })?;
        let region = Region::new(region.to_string())?;
        return sts_regional_endpoint_for_partition(&region, partition);
    }

    url::Url::parse(STS_GLOBAL_ENDPOINT)
        .map_err(|_| Error::invalid_config("invalid STS endpoint URL"))
}

fn web_identity_env() -> Result<(String, String, String), Error> {
    let role_arn =
        std::env::var("AWS_ROLE_ARN").map_err(|_| Error::invalid_config("missing AWS_ROLE_ARN"))?;
    let token_file = std::env::var("AWS_WEB_IDENTITY_TOKEN_FILE")
        .map_err(|_| Error::invalid_config("missing AWS_WEB_IDENTITY_TOKEN_FILE"))?;
    let session_name =
        std::env::var("AWS_ROLE_SESSION_NAME").unwrap_or_else(|_| "s3-session".to_string());

    let token = std::fs::read_to_string(token_file)
        .map_err(|e| Error::invalid_config(format!("failed to read web identity token: {e}")))?;
    let token = token.trim().to_string();
    if token.is_empty() {
        return Err(Error::invalid_config("web identity token is empty"));
    }

    Ok((role_arn, session_name, token))
}

fn form_body(params: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (idx, (k, v)) in params.iter().enumerate() {
        if idx > 0 {
            out.push('&');
        }
        out.push_str(&crate::util::encode::aws_percent_encode(k));
        out.push('=');
        out.push_str(&crate::util::encode::aws_percent_encode(v));
    }
    out
}

fn sts_api_error(status: StatusCode, headers: &HeaderMap, body: &str) -> Error {
    crate::transport::response_error_from_status(status, headers, body)
}

fn parse_expiration(value: &str) -> Result<OffsetDateTime, Error> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|e| {
        Error::decode(
            "failed to parse credentials expiration timestamp",
            Some(Box::new(e)),
        )
    })
}

fn parse_assume_role_response(body: &str) -> Result<CredentialsSnapshot, Error> {
    #[derive(serde::Deserialize)]
    struct XmlAssumeRoleResponse {
        #[serde(rename = "AssumeRoleResult")]
        result: XmlAssumeRoleResult,
    }

    #[derive(serde::Deserialize)]
    struct XmlAssumeRoleResult {
        #[serde(rename = "Credentials")]
        credentials: XmlStsCredentials,
    }

    #[derive(serde::Deserialize)]
    struct XmlStsCredentials {
        #[serde(rename = "AccessKeyId")]
        access_key_id: String,
        #[serde(rename = "Expiration")]
        expiration: String,
        #[serde(rename = "SecretAccessKey")]
        secret_access_key: String,
        #[serde(rename = "SessionToken")]
        session_token: String,
    }

    let parsed = quick_xml::de::from_str::<XmlAssumeRoleResponse>(body)
        .map_err(|e| Error::decode("failed to parse AssumeRole XML response", Some(Box::new(e))))?;

    let mut creds = Credentials::new(
        parsed.result.credentials.access_key_id,
        parsed.result.credentials.secret_access_key,
    )?;
    creds = creds.with_session_token(parsed.result.credentials.session_token)?;
    let expires_at = parse_expiration(parsed.result.credentials.expiration.trim())?;
    Ok(CredentialsSnapshot::new(creds).with_expires_at(expires_at))
}

fn parse_assume_role_with_web_identity_response(body: &str) -> Result<CredentialsSnapshot, Error> {
    #[derive(serde::Deserialize)]
    struct XmlResponse {
        #[serde(rename = "AssumeRoleWithWebIdentityResult")]
        result: XmlResult,
    }

    #[derive(serde::Deserialize)]
    struct XmlResult {
        #[serde(rename = "Credentials")]
        credentials: XmlStsCredentials,
    }

    #[derive(serde::Deserialize)]
    struct XmlStsCredentials {
        #[serde(rename = "AccessKeyId")]
        access_key_id: String,
        #[serde(rename = "Expiration")]
        expiration: String,
        #[serde(rename = "SecretAccessKey")]
        secret_access_key: String,
        #[serde(rename = "SessionToken")]
        session_token: String,
    }

    let parsed = quick_xml::de::from_str::<XmlResponse>(body).map_err(|e| {
        Error::decode(
            "failed to parse AssumeRoleWithWebIdentity XML response",
            Some(Box::new(e)),
        )
    })?;

    let mut creds = Credentials::new(
        parsed.result.credentials.access_key_id,
        parsed.result.credentials.secret_access_key,
    )?;
    creds = creds.with_session_token(parsed.result.credentials.session_token)?;
    let expires_at = parse_expiration(parsed.result.credentials.expiration.trim())?;
    Ok(CredentialsSnapshot::new(creds).with_expires_at(expires_at))
}

#[cfg(feature = "async")]
fn sts_async_client(
    timeout: std::time::Duration,
    tls_root_store: TlsRootStore,
) -> Result<reqx::Client, Error> {
    reqx::Client::builder("http://localhost")
        .request_timeout(timeout)
        .retry_policy(RetryPolicy::disabled())
        .redirect_policy(RedirectPolicy::none())
        .default_status_policy(StatusPolicy::Response)
        .max_response_body_bytes(4 * 1024 * 1024)
        .tls_backend(crate::transport::default_tls_backend())
        .tls_root_store(tls_root_store)
        .client_name("s3-sts")
        .build()
        .map_err(|e| Error::transport("failed to build HTTP client", Some(Box::new(e))))
}

#[cfg(feature = "blocking")]
fn sts_blocking_client(
    timeout: std::time::Duration,
    tls_root_store: TlsRootStore,
) -> Result<reqx::blocking::Client, Error> {
    reqx::blocking::Client::builder("http://localhost")
        .request_timeout(timeout)
        .retry_policy(RetryPolicy::disabled())
        .redirect_policy(RedirectPolicy::none())
        .default_status_policy(StatusPolicy::Response)
        .max_response_body_bytes(4 * 1024 * 1024)
        .tls_backend(crate::transport::default_tls_backend())
        .tls_root_store(tls_root_store)
        .client_name("s3-sts")
        .build()
        .map_err(|e| Error::transport("failed to build HTTP client", Some(Box::new(e))))
}

#[cfg(test)]
mod tests {
    use std::io::{ErrorKind, Read, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::thread::JoinHandle;
    use std::time::Duration;
    use std::time::Instant;

    use super::*;

    fn spawn_test_server(
        response: Vec<u8>,
    ) -> std::result::Result<(SocketAddr, JoinHandle<()>), Error> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .map_err(|e| Error::transport("failed to bind test server", Some(Box::new(e))))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| Error::transport("failed to configure test server", Some(Box::new(e))))?;
        let addr = listener.local_addr().map_err(|e| {
            Error::transport("failed to read test server address", Some(Box::new(e)))
        })?;

        let handle = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
                        let mut request = Vec::new();
                        let mut buf = [0u8; 1024];
                        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                            match stream.read(&mut buf) {
                                Ok(0) => break,
                                Ok(n) => {
                                    request.extend_from_slice(&buf[..n]);
                                    if request.len() > 64 * 1024 {
                                        break;
                                    }
                                }
                                Err(err)
                                    if matches!(
                                        err.kind(),
                                        ErrorKind::WouldBlock | ErrorKind::TimedOut
                                    ) =>
                                {
                                    break;
                                }
                                Err(_) => break,
                            }
                        }
                        let _ = stream.write_all(&response);
                        let _ = stream.flush();
                        break;
                    }
                    Err(err) if err.kind() == ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => return,
                }
            }
        });

        Ok((addr, handle))
    }

    #[cfg(all(feature = "async", feature = "native-tls", not(feature = "rustls")))]
    fn assert_native_tls_webpki_error(err: Error) {
        match err {
            Error::Transport {
                source: Some(source),
                ..
            } => {
                assert!(
                    source.to_string().contains("TlsRootStore::WebPki"),
                    "unexpected source error: {source}"
                );
            }
            other => panic!("expected transport error, got {other:?}"),
        }
    }

    #[test]
    fn builds_regional_endpoint() {
        let region = Region::new("us-east-1").unwrap();
        let url = sts_regional_endpoint(&region).unwrap();
        assert_eq!(url.as_str(), "https://sts.us-east-1.amazonaws.com/");
    }

    #[test]
    fn builds_regional_endpoint_for_cn_region() {
        let region = Region::new("cn-north-1").unwrap();
        let url = sts_regional_endpoint(&region).unwrap();
        assert_eq!(url.as_str(), "https://sts.cn-north-1.amazonaws.com.cn/");
    }

    #[test]
    fn resolve_web_identity_sts_endpoint_defaults_to_global() {
        let url = resolve_web_identity_sts_endpoint(None, None, None).unwrap();
        assert_eq!(url.as_str(), "https://sts.amazonaws.com/");
    }

    #[test]
    fn resolve_web_identity_sts_endpoint_uses_regional_when_requested() {
        let url = resolve_web_identity_sts_endpoint(
            Some("aws"),
            Some("eu-west-1"),
            Some(StsRegionalEndpointsMode::Regional),
        )
        .unwrap();
        assert_eq!(url.as_str(), "https://sts.eu-west-1.amazonaws.com/");
    }

    #[test]
    fn resolve_web_identity_sts_endpoint_requires_region_for_cn_partition() {
        let err = resolve_web_identity_sts_endpoint(Some("aws-cn"), None, None)
            .expect_err("aws-cn should require a regional endpoint");
        match err {
            Error::InvalidConfig { message } => {
                assert!(message.contains("AWS_REGION or AWS_DEFAULT_REGION"));
            }
            other => panic!("expected invalid config, got {other:?}"),
        }
    }

    #[test]
    fn resolve_web_identity_sts_endpoint_uses_cn_regional_suffix() {
        let url = resolve_web_identity_sts_endpoint(
            Some("aws-cn"),
            Some("cn-northwest-1"),
            Some(StsRegionalEndpointsMode::Legacy),
        )
        .unwrap();
        assert_eq!(url.as_str(), "https://sts.cn-northwest-1.amazonaws.com.cn/");
    }

    #[test]
    fn form_body_percent_encodes() {
        let body = form_body(&[("a+b", "c d"), ("x", "~")]);
        assert_eq!(body, "a%2Bb=c%20d&x=~");
    }

    #[test]
    fn parses_assume_role_response() {
        let xml = r#"
 <AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
   <AssumeRoleResult>
     <Credentials>
       <AccessKeyId>AKIA_TEST</AccessKeyId>
       <Expiration>2020-01-01T00:00:00Z</Expiration>
       <SecretAccessKey>SECRET_TEST</SecretAccessKey>
       <SessionToken>TOKEN_TEST</SessionToken>
     </Credentials>
   </AssumeRoleResult>
 </AssumeRoleResponse>
 "#;

        let snapshot = parse_assume_role_response(xml).unwrap();
        let creds = snapshot.credentials();
        assert_eq!(creds.access_key_id, "AKIA_TEST");
        assert_eq!(creds.secret_access_key, "SECRET_TEST");
        assert_eq!(creds.session_token.as_deref(), Some("TOKEN_TEST"));
        assert_eq!(
            snapshot.expires_at(),
            Some(parse_expiration("2020-01-01T00:00:00Z").unwrap())
        );
    }

    #[test]
    fn parses_assume_role_with_web_identity_response() {
        let xml = r#"
 <AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
   <AssumeRoleWithWebIdentityResult>
     <Credentials>
       <AccessKeyId>AKIA_TEST</AccessKeyId>
       <Expiration>2020-01-01T00:00:00Z</Expiration>
       <SecretAccessKey>SECRET_TEST</SecretAccessKey>
       <SessionToken>TOKEN_TEST</SessionToken>
     </Credentials>
   </AssumeRoleWithWebIdentityResult>
 </AssumeRoleWithWebIdentityResponse>
 "#;

        let snapshot = parse_assume_role_with_web_identity_response(xml).unwrap();
        let creds = snapshot.credentials();
        assert_eq!(creds.access_key_id, "AKIA_TEST");
        assert_eq!(creds.secret_access_key, "SECRET_TEST");
        assert_eq!(creds.session_token.as_deref(), Some("TOKEN_TEST"));
        assert_eq!(
            snapshot.expires_at(),
            Some(parse_expiration("2020-01-01T00:00:00Z").unwrap())
        );
    }

    #[test]
    fn sts_api_error_parses_xml_error() {
        let err_xml = r#"
<Error>
  <Code>AccessDenied</Code>
  <Message>Access Denied</Message>
  <RequestId>req-123</RequestId>
  <HostId>host-456</HostId>
</Error>
"#;
        let headers = HeaderMap::new();
        let err = sts_api_error(StatusCode::FORBIDDEN, &headers, err_xml);
        match err {
            Error::Api {
                status,
                code,
                message,
                request_id,
                host_id,
                body_snippet,
            } => {
                assert_eq!(status, StatusCode::FORBIDDEN);
                assert_eq!(code.as_deref(), Some("AccessDenied"));
                assert_eq!(message.as_deref(), Some("Access Denied"));
                assert_eq!(request_id.as_deref(), Some("req-123"));
                assert_eq!(host_id.as_deref(), Some("host-456"));
                assert!(body_snippet.unwrap_or_default().contains("AccessDenied"));
            }
            other => panic!("expected api error, got {other:?}"),
        }
    }

    #[test]
    fn sts_api_error_maps_rate_limited() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::RETRY_AFTER, HeaderValue::from_static("2"));
        headers.insert("x-amz-request-id", HeaderValue::from_static("req-1"));

        let err = sts_api_error(StatusCode::TOO_MANY_REQUESTS, &headers, "slow down");
        match err {
            Error::RateLimited {
                retry_after,
                request_id,
                ..
            } => {
                assert_eq!(retry_after, Some(Duration::from_secs(2)));
                assert_eq!(request_id.as_deref(), Some("req-1"));
            }
            other => panic!("expected rate-limited error, got {other:?}"),
        }
    }

    #[cfg(feature = "async")]
    #[test]
    fn sts_async_client_accepts_backend_default() {
        let client = sts_async_client(Duration::from_secs(1), TlsRootStore::BackendDefault);
        let client = client.expect("async STS client should build");
        assert_eq!(client.default_status_policy(), StatusPolicy::Response);
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn send_form_async_non_success_returns_status_response() -> std::result::Result<(), Error>
    {
        let (addr, handle) = spawn_test_server(
            b"HTTP/1.1 403 Forbidden\r\nx-amz-request-id: req-1\r\nContent-Length: 13\r\nConnection: close\r\n\r\nAccess Denied!".to_vec(),
        )?;
        let client = sts_async_client(Duration::from_secs(2), TlsRootStore::BackendDefault)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );

        let url = format!("http://{addr}/");
        let (status, _, body) =
            send_form_async(&client, &url, headers, Bytes::from("Action=AssumeRole")).await?;
        handle
            .join()
            .map_err(|_| Error::transport("test server thread panicked", None))?;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(body.contains("Access Denied"));
        Ok(())
    }

    #[cfg(all(feature = "async", feature = "rustls"))]
    #[test]
    fn sts_async_client_accepts_webpki_on_rustls() {
        let client = sts_async_client(Duration::from_secs(1), TlsRootStore::WebPki);
        assert!(client.is_ok(), "rustls should accept WebPki root store");
    }

    #[cfg(all(feature = "async", feature = "native-tls", not(feature = "rustls")))]
    #[test]
    fn sts_async_client_rejects_webpki_on_native_tls() {
        let err = match sts_async_client(Duration::from_secs(1), TlsRootStore::WebPki) {
            Ok(_) => panic!("native-tls should reject WebPki root store"),
            Err(err) => err,
        };
        assert_native_tls_webpki_error(err);
    }

    #[cfg(feature = "blocking")]
    #[test]
    fn sts_blocking_client_accepts_backend_default() {
        let client = sts_blocking_client(Duration::from_secs(1), TlsRootStore::BackendDefault);
        let client = client.expect("blocking STS client should build");
        assert_eq!(client.default_status_policy(), StatusPolicy::Response);
    }

    #[cfg(feature = "blocking")]
    #[test]
    fn send_form_blocking_non_success_returns_status_response() -> std::result::Result<(), Error> {
        let (addr, handle) = spawn_test_server(
            b"HTTP/1.1 403 Forbidden\r\nx-amz-request-id: req-1\r\nContent-Length: 13\r\nConnection: close\r\n\r\nAccess Denied!".to_vec(),
        )?;
        let client = sts_blocking_client(Duration::from_secs(2), TlsRootStore::BackendDefault)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );

        let url = format!("http://{addr}/");
        let (status, _, body) =
            send_form_blocking(&client, &url, headers, Bytes::from("Action=AssumeRole"))?;
        handle
            .join()
            .map_err(|_| Error::transport("test server thread panicked", None))?;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(body.contains("Access Denied"));
        Ok(())
    }

    #[cfg(all(feature = "blocking", feature = "rustls"))]
    #[test]
    fn sts_blocking_client_accepts_webpki_on_rustls() {
        let client = sts_blocking_client(Duration::from_secs(1), TlsRootStore::WebPki);
        assert!(client.is_ok(), "rustls should accept WebPki root store");
    }

    #[cfg(all(feature = "blocking", feature = "native-tls", not(feature = "rustls")))]
    #[test]
    fn sts_blocking_client_accepts_webpki_on_native_tls() {
        // reqx blocking transport (ureq backend) accepts WebPki roots on native-tls.
        let client = sts_blocking_client(Duration::from_secs(1), TlsRootStore::WebPki);
        assert!(
            client.is_ok(),
            "native-tls should build with WebPki root store"
        );
    }
}
