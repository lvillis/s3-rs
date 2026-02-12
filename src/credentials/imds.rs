use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    auth::{Credentials, CredentialsSnapshot},
    error::Error,
};

#[derive(serde::Deserialize)]
struct MetadataCredentials {
    #[serde(rename = "AccessKeyId")]
    access_key_id: String,
    #[serde(rename = "SecretAccessKey")]
    secret_access_key: String,
    #[serde(rename = "Expiration")]
    expiration: Option<String>,
    #[serde(rename = "Token")]
    token: Option<String>,
}

impl MetadataCredentials {
    fn into_snapshot(self) -> Result<CredentialsSnapshot, Error> {
        let mut creds = Credentials::new(self.access_key_id, self.secret_access_key)?;
        if let Some(token) = self.token {
            creds = creds.with_session_token(token)?;
        }

        let expiration = self
            .expiration
            .ok_or_else(|| Error::decode("missing credentials expiration", None))?;
        let expiration = expiration.trim();
        if expiration.is_empty() {
            return Err(Error::decode("missing credentials expiration", None));
        }
        let expires_at = parse_expiration(expiration)?;
        Ok(CredentialsSnapshot::new(creds).with_expires_at(expires_at))
    }
}

fn parse_expiration(value: &str) -> Result<OffsetDateTime, Error> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|e| {
        Error::decode(
            "failed to parse credentials expiration timestamp",
            Some(Box::new(e)),
        )
    })
}

#[cfg(feature = "async")]
pub(crate) async fn load_async(
    tls_root_store: reqx::TlsRootStore,
) -> Result<CredentialsSnapshot, Error> {
    use std::time::Duration;

    let client = metadata_async_client(Duration::from_secs(2), tls_root_store)?;

    if let Some(full) = std::env::var("AWS_CONTAINER_CREDENTIALS_FULL_URI")
        .ok()
        .filter(|v| !v.is_empty())
    {
        let headers = container_auth_headers()?;
        let body = http_get_text(&client, &full, headers).await?;
        let parsed: MetadataCredentials = serde_json::from_str(&body).map_err(|e| {
            Error::decode(
                "failed to parse container credentials JSON",
                Some(Box::new(e)),
            )
        })?;
        return parsed.into_snapshot();
    }

    if let Some(rel) = std::env::var("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
        .ok()
        .filter(|v| !v.is_empty())
    {
        let url = format!("http://169.254.170.2{rel}");
        let headers = container_auth_headers()?;
        let body = http_get_text(&client, &url, headers).await?;
        let parsed: MetadataCredentials = serde_json::from_str(&body).map_err(|e| {
            Error::decode(
                "failed to parse container credentials JSON",
                Some(Box::new(e)),
            )
        })?;
        return parsed.into_snapshot();
    }

    let token = fetch_imds_v2_token(&client).await.ok();
    let mut headers = http::HeaderMap::new();
    if let Some(token) = token.as_deref().filter(|v| !v.is_empty()) {
        let value = http::HeaderValue::from_str(token)
            .map_err(|_| Error::invalid_config("invalid IMDS token"))?;
        headers.insert("X-aws-ec2-metadata-token", value);
    }

    let role = http_get_text(
        &client,
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        headers.clone(),
    )
    .await?;
    let role = role.lines().next().unwrap_or("").trim();
    if role.is_empty() {
        return Err(Error::invalid_config("missing IMDS role name"));
    }

    let url = format!("http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}");
    let body = http_get_text(&client, &url, headers).await?;
    let parsed: MetadataCredentials = serde_json::from_str(&body)
        .map_err(|e| Error::decode("failed to parse IMDS credentials JSON", Some(Box::new(e))))?;
    parsed.into_snapshot()
}

#[cfg(feature = "async")]
async fn http_get_text(
    client: &reqx::Client,
    url: &str,
    headers: http::HeaderMap,
) -> Result<String, Error> {
    let mut req = client
        .request(http::Method::GET, url.to_string())
        .redirect_policy(reqx::RedirectPolicy::none());
    for (name, value) in headers {
        if let Some(name) = name {
            req = req.header(name, value);
        }
    }

    let resp = req
        .status_policy(reqx::StatusPolicy::Response)
        .send()
        .await
        .map_err(|e| crate::transport::map_reqx_error("request failed", e))?;
    let status = resp.status();
    let body = String::from_utf8_lossy(resp.body()).to_string();
    if status.is_success() {
        return Ok(body);
    }
    Err(crate::transport::response_error_from_status(
        status,
        resp.headers(),
        &body,
    ))
}

#[cfg(feature = "async")]
async fn fetch_imds_v2_token(client: &reqx::Client) -> Result<String, Error> {
    let resp = client
        .request(
            http::Method::PUT,
            "http://169.254.169.254/latest/api/token".to_string(),
        )
        .redirect_policy(reqx::RedirectPolicy::none())
        .header(
            http::header::HeaderName::from_static("x-aws-ec2-metadata-token-ttl-seconds"),
            http::HeaderValue::from_static("21600"),
        )
        .status_policy(reqx::StatusPolicy::Response)
        .send()
        .await
        .map_err(|e| crate::transport::map_reqx_error("request failed", e))?;
    let status = resp.status();
    let body = String::from_utf8_lossy(resp.body()).to_string();
    if status.is_success() {
        return Ok(body.trim().to_string());
    }
    Err(crate::transport::response_error_from_status(
        status,
        resp.headers(),
        &body,
    ))
}

#[cfg(feature = "async")]
fn container_auth_headers() -> Result<http::HeaderMap, Error> {
    let mut headers = http::HeaderMap::new();
    if let Ok(token) = std::env::var("AWS_CONTAINER_AUTHORIZATION_TOKEN") {
        if !token.trim().is_empty() {
            let value = http::HeaderValue::from_str(token.trim())
                .map_err(|_| Error::invalid_config("invalid container authorization token"))?;
            headers.insert(http::header::AUTHORIZATION, value);
        }
    } else if let Ok(path) = std::env::var("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE") {
        let token = std::fs::read_to_string(path)
            .map_err(|e| Error::invalid_config(format!("failed to read token file: {e}")))?;
        if !token.trim().is_empty() {
            let value = http::HeaderValue::from_str(token.trim())
                .map_err(|_| Error::invalid_config("invalid container authorization token"))?;
            headers.insert(http::header::AUTHORIZATION, value);
        }
    }
    Ok(headers)
}

#[cfg(feature = "blocking")]
pub(crate) fn load_blocking(
    tls_root_store: reqx::TlsRootStore,
) -> Result<CredentialsSnapshot, Error> {
    use std::time::Duration;

    let client = metadata_blocking_client(Duration::from_secs(2), tls_root_store)?;

    if let Some(full) = std::env::var("AWS_CONTAINER_CREDENTIALS_FULL_URI")
        .ok()
        .filter(|v| !v.is_empty())
    {
        let headers = container_auth_headers_blocking()?;
        let body = http_get_text_blocking(&client, &full, &headers)?;
        let parsed: MetadataCredentials = serde_json::from_str(&body).map_err(|e| {
            Error::decode(
                "failed to parse container credentials JSON",
                Some(Box::new(e)),
            )
        })?;
        return parsed.into_snapshot();
    }

    if let Some(rel) = std::env::var("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
        .ok()
        .filter(|v| !v.is_empty())
    {
        let url = format!("http://169.254.170.2{rel}");
        let headers = container_auth_headers_blocking()?;
        let body = http_get_text_blocking(&client, &url, &headers)?;
        let parsed: MetadataCredentials = serde_json::from_str(&body).map_err(|e| {
            Error::decode(
                "failed to parse container credentials JSON",
                Some(Box::new(e)),
            )
        })?;
        return parsed.into_snapshot();
    }

    let token = fetch_imds_v2_token_blocking(&client).ok();
    let mut headers = http::HeaderMap::new();
    if let Some(token) = token.as_deref().filter(|v| !v.is_empty()) {
        let value = http::HeaderValue::from_str(token)
            .map_err(|_| Error::invalid_config("invalid IMDS token"))?;
        headers.insert("X-aws-ec2-metadata-token", value);
    }

    let role = http_get_text_blocking(
        &client,
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        &headers,
    )?;
    let role = role.lines().next().unwrap_or("").trim();
    if role.is_empty() {
        return Err(Error::invalid_config("missing IMDS role name"));
    }

    let url = format!("http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}");
    let body = http_get_text_blocking(&client, &url, &headers)?;
    let parsed: MetadataCredentials = serde_json::from_str(&body)
        .map_err(|e| Error::decode("failed to parse IMDS credentials JSON", Some(Box::new(e))))?;
    parsed.into_snapshot()
}

#[cfg(feature = "blocking")]
fn http_get_text_blocking(
    client: &reqx::blocking::Client,
    url: &str,
    headers: &http::HeaderMap,
) -> Result<String, Error> {
    let mut req = client
        .request(http::Method::GET, url.to_string())
        .redirect_policy(reqx::RedirectPolicy::none());
    for (name, value) in headers {
        req = req.header(name.clone(), value.clone());
    }

    let resp = req
        .status_policy(reqx::StatusPolicy::Response)
        .send()
        .map_err(|e| crate::transport::map_reqx_error("request failed", e))?;
    let status = resp.status();
    let out = String::from_utf8_lossy(resp.body()).to_string();

    if status.is_success() {
        return Ok(out);
    }

    Err(crate::transport::response_error_from_status(
        status,
        resp.headers(),
        &out,
    ))
}

#[cfg(feature = "blocking")]
fn fetch_imds_v2_token_blocking(client: &reqx::blocking::Client) -> Result<String, Error> {
    let resp = client
        .request(
            http::Method::PUT,
            "http://169.254.169.254/latest/api/token".to_string(),
        )
        .redirect_policy(reqx::RedirectPolicy::none())
        .header(
            http::header::HeaderName::from_static("x-aws-ec2-metadata-token-ttl-seconds"),
            http::HeaderValue::from_static("21600"),
        )
        .status_policy(reqx::StatusPolicy::Response)
        .send()
        .map_err(|e| crate::transport::map_reqx_error("request failed", e))?;

    let status = resp.status();
    let out = String::from_utf8_lossy(resp.body()).to_string();

    if status.is_success() {
        return Ok(out.trim().to_string());
    }

    Err(crate::transport::response_error_from_status(
        status,
        resp.headers(),
        &out,
    ))
}

#[cfg(feature = "blocking")]
fn container_auth_headers_blocking() -> Result<http::HeaderMap, Error> {
    let mut headers = http::HeaderMap::new();
    if let Ok(token) = std::env::var("AWS_CONTAINER_AUTHORIZATION_TOKEN") {
        if !token.trim().is_empty() {
            let value = http::HeaderValue::from_str(token.trim())
                .map_err(|_| Error::invalid_config("invalid container authorization token"))?;
            headers.insert(http::header::AUTHORIZATION, value);
        }
    } else if let Ok(path) = std::env::var("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE") {
        let token = std::fs::read_to_string(path)
            .map_err(|e| Error::invalid_config(format!("failed to read token file: {e}")))?;
        if !token.trim().is_empty() {
            let value = http::HeaderValue::from_str(token.trim())
                .map_err(|_| Error::invalid_config("invalid container authorization token"))?;
            headers.insert(http::header::AUTHORIZATION, value);
        }
    }
    Ok(headers)
}

#[cfg(feature = "async")]
fn metadata_async_client(
    timeout: std::time::Duration,
    tls_root_store: reqx::TlsRootStore,
) -> Result<reqx::Client, Error> {
    reqx::Client::builder("http://localhost")
        .request_timeout(timeout)
        .retry_policy(reqx::RetryPolicy::disabled())
        .redirect_policy(reqx::RedirectPolicy::none())
        .default_status_policy(reqx::StatusPolicy::Response)
        .max_response_body_bytes(1024 * 1024)
        .tls_backend(default_tls_backend())
        .tls_root_store(tls_root_store)
        .client_name("s3-imds")
        .build()
        .map_err(|e| Error::transport("failed to build HTTP client", Some(Box::new(e))))
}

#[cfg(feature = "blocking")]
fn metadata_blocking_client(
    timeout: std::time::Duration,
    tls_root_store: reqx::TlsRootStore,
) -> Result<reqx::blocking::Client, Error> {
    reqx::blocking::Client::builder("http://localhost")
        .request_timeout(timeout)
        .retry_policy(reqx::RetryPolicy::disabled())
        .redirect_policy(reqx::RedirectPolicy::none())
        .default_status_policy(reqx::StatusPolicy::Response)
        .max_response_body_bytes(1024 * 1024)
        .tls_backend(default_tls_backend())
        .tls_root_store(tls_root_store)
        .client_name("s3-imds")
        .build()
        .map_err(|e| Error::transport("failed to build HTTP client", Some(Box::new(e))))
}

fn default_tls_backend() -> reqx::TlsBackend {
    #[cfg(feature = "rustls")]
    {
        return reqx::TlsBackend::RustlsRing;
    }
    #[cfg(all(not(feature = "rustls"), feature = "native-tls"))]
    {
        return reqx::TlsBackend::NativeTls;
    }
    #[allow(unreachable_code)]
    reqx::TlsBackend::RustlsRing
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
    fn deserializes_and_converts_metadata_credentials() {
        let json = r#"
{
  "AccessKeyId": "AKIA_TEST",
  "Expiration": "2020-01-01T00:00:00Z",
  "SecretAccessKey": "SECRET_TEST",
  "Token": "TOKEN_TEST"
}
"#;
        let parsed: MetadataCredentials = serde_json::from_str(json).unwrap();
        let snapshot = parsed.into_snapshot().unwrap();
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
    fn missing_token_is_ok() {
        let json = r#"
{
  "AccessKeyId": "AKIA_TEST",
  "Expiration": "2020-01-01T00:00:00Z",
  "SecretAccessKey": "SECRET_TEST"
}
"#;
        let parsed: MetadataCredentials = serde_json::from_str(json).unwrap();
        let snapshot = parsed.into_snapshot().unwrap();
        let creds = snapshot.credentials();
        assert!(creds.session_token.is_none());
        assert_eq!(
            snapshot.expires_at(),
            Some(parse_expiration("2020-01-01T00:00:00Z").unwrap())
        );
    }

    #[cfg(feature = "async")]
    #[test]
    fn metadata_async_client_accepts_backend_default() {
        let client =
            metadata_async_client(Duration::from_secs(1), reqx::TlsRootStore::BackendDefault);
        let client = client.expect("async metadata client should build");
        assert_eq!(client.default_status_policy(), reqx::StatusPolicy::Response);
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn http_get_text_maps_429_to_rate_limited_async() -> std::result::Result<(), Error> {
        let (addr, handle) = spawn_test_server(
            b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 3\r\nx-amz-request-id: req-1\r\nContent-Length: 4\r\nConnection: close\r\n\r\nslow".to_vec(),
        )?;
        let client =
            metadata_async_client(Duration::from_secs(2), reqx::TlsRootStore::BackendDefault)?;
        let url = format!("http://{addr}/");

        let err = http_get_text(&client, &url, http::HeaderMap::new())
            .await
            .expect_err("expected non-success IMDS response to be mapped");
        handle
            .join()
            .map_err(|_| Error::transport("test server thread panicked", None))?;

        match err {
            Error::RateLimited {
                retry_after,
                request_id,
            } => {
                assert_eq!(retry_after, Some(Duration::from_secs(3)));
                assert_eq!(request_id.as_deref(), Some("req-1"));
            }
            other => panic!("expected rate-limited error, got {other:?}"),
        }

        Ok(())
    }

    #[cfg(all(feature = "async", feature = "rustls"))]
    #[test]
    fn metadata_async_client_accepts_webpki_on_rustls() {
        let client = metadata_async_client(Duration::from_secs(1), reqx::TlsRootStore::WebPki);
        assert!(client.is_ok(), "rustls should accept WebPki root store");
    }

    #[cfg(all(feature = "async", feature = "native-tls", not(feature = "rustls")))]
    #[test]
    fn metadata_async_client_rejects_webpki_on_native_tls() {
        let err = match metadata_async_client(Duration::from_secs(1), reqx::TlsRootStore::WebPki) {
            Ok(_) => panic!("native-tls should reject WebPki root store"),
            Err(err) => err,
        };
        assert_native_tls_webpki_error(err);
    }

    #[cfg(feature = "blocking")]
    #[test]
    fn metadata_blocking_client_accepts_backend_default() {
        let client =
            metadata_blocking_client(Duration::from_secs(1), reqx::TlsRootStore::BackendDefault);
        let client = client.expect("blocking metadata client should build");
        assert_eq!(client.default_status_policy(), reqx::StatusPolicy::Response);
    }

    #[cfg(feature = "blocking")]
    #[test]
    fn http_get_text_blocking_maps_429_to_rate_limited() -> std::result::Result<(), Error> {
        let (addr, handle) = spawn_test_server(
            b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 3\r\nx-amz-request-id: req-1\r\nContent-Length: 4\r\nConnection: close\r\n\r\nslow".to_vec(),
        )?;
        let client =
            metadata_blocking_client(Duration::from_secs(2), reqx::TlsRootStore::BackendDefault)?;
        let url = format!("http://{addr}/");

        let err = http_get_text_blocking(&client, &url, &http::HeaderMap::new())
            .expect_err("expected non-success IMDS response to be mapped");
        handle
            .join()
            .map_err(|_| Error::transport("test server thread panicked", None))?;

        match err {
            Error::RateLimited {
                retry_after,
                request_id,
            } => {
                assert_eq!(retry_after, Some(Duration::from_secs(3)));
                assert_eq!(request_id.as_deref(), Some("req-1"));
            }
            other => panic!("expected rate-limited error, got {other:?}"),
        }

        Ok(())
    }

    #[cfg(all(feature = "blocking", feature = "rustls"))]
    #[test]
    fn metadata_blocking_client_accepts_webpki_on_rustls() {
        let client = metadata_blocking_client(Duration::from_secs(1), reqx::TlsRootStore::WebPki);
        assert!(client.is_ok(), "rustls should accept WebPki root store");
    }

    #[cfg(all(feature = "blocking", feature = "native-tls", not(feature = "rustls")))]
    #[test]
    fn metadata_blocking_client_accepts_webpki_on_native_tls() {
        // reqx blocking transport (ureq backend) accepts WebPki roots on native-tls.
        let client = metadata_blocking_client(Duration::from_secs(1), reqx::TlsRootStore::WebPki);
        assert!(
            client.is_ok(),
            "native-tls should build with WebPki root store"
        );
    }
}
