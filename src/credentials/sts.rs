use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode};

use crate::{
    auth::{AddressingStyle, Credentials, Region},
    error::Error,
};

const SERVICE: &str = "sts";

#[cfg(feature = "async")]
pub(crate) async fn assume_role_async(
    region: Region,
    role_arn: String,
    role_session_name: String,
    source_credentials: Credentials,
) -> Result<Credentials, Error> {
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

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| Error::transport("failed to build HTTP client", Some(Box::new(e))))?;

    let resp = client
        .post(resolved.url)
        .headers(headers)
        .body(body_bytes)
        .send()
        .await
        .map_err(|e| Error::transport("request failed", Some(Box::new(e))))?;

    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| Error::transport("failed to read response body", Some(Box::new(e))))?;

    if !status.is_success() {
        return Err(sts_api_error(status, &text));
    }

    parse_assume_role_response(&text)
}

#[cfg(feature = "blocking")]
pub(crate) fn assume_role_blocking(
    region: Region,
    role_arn: String,
    role_session_name: String,
    source_credentials: Credentials,
) -> Result<Credentials, Error> {
    use std::io::Read as _;

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

    let mut req = ureq::agent().post(resolved.url.as_str());
    for (name, value) in headers.iter() {
        let Ok(value) = value.to_str() else {
            continue;
        };
        req = req.header(name.as_str(), value);
    }

    let resp = req
        .send(body_bytes.as_ref())
        .map_err(|e| Error::transport("request failed", Some(Box::new(e))))?;

    let status = resp.status();

    let mut text = String::new();
    resp.into_body()
        .into_reader()
        .read_to_string(&mut text)
        .map_err(|e| Error::transport("failed to read response body", Some(Box::new(e))))?;

    if !status.is_success() {
        return Err(sts_api_error(status, &text));
    }

    parse_assume_role_response(&text)
}

#[cfg(feature = "async")]
pub(crate) async fn assume_role_with_web_identity_env_async() -> Result<Credentials, Error> {
    use std::time::Duration;

    let (role_arn, session_name, token) = web_identity_env()?;

    let endpoint = url::Url::parse("https://sts.amazonaws.com")
        .map_err(|_| Error::invalid_config("invalid STS endpoint URL"))?;

    let body = form_body(&[
        ("Action", "AssumeRoleWithWebIdentity"),
        ("Version", "2011-06-15"),
        ("RoleArn", &role_arn),
        ("RoleSessionName", &session_name),
        ("WebIdentityToken", &token),
    ]);
    let body_bytes = Bytes::from(body);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| Error::transport("failed to build HTTP client", Some(Box::new(e))))?;

    let resp = client
        .post(endpoint)
        .header(
            http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(body_bytes)
        .send()
        .await
        .map_err(|e| Error::transport("request failed", Some(Box::new(e))))?;

    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| Error::transport("failed to read response body", Some(Box::new(e))))?;

    if !status.is_success() {
        return Err(sts_api_error(status, &text));
    }

    parse_assume_role_with_web_identity_response(&text)
}

#[cfg(feature = "blocking")]
pub(crate) fn assume_role_with_web_identity_env_blocking() -> Result<Credentials, Error> {
    use std::io::Read as _;

    let (role_arn, session_name, token) = web_identity_env()?;

    let body = form_body(&[
        ("Action", "AssumeRoleWithWebIdentity"),
        ("Version", "2011-06-15"),
        ("RoleArn", &role_arn),
        ("RoleSessionName", &session_name),
        ("WebIdentityToken", &token),
    ]);

    let resp = ureq::agent()
        .post("https://sts.amazonaws.com/")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send(body.as_bytes())
        .map_err(|e| Error::transport("request failed", Some(Box::new(e))))?;

    let status = resp.status();

    let mut text = String::new();
    resp.into_body()
        .into_reader()
        .read_to_string(&mut text)
        .map_err(|e| Error::transport("failed to read response body", Some(Box::new(e))))?;

    if !status.is_success() {
        return Err(sts_api_error(status, &text));
    }

    parse_assume_role_with_web_identity_response(&text)
}

fn sts_regional_endpoint(region: &Region) -> Result<url::Url, Error> {
    let url = format!("https://sts.{}.amazonaws.com", region.as_str());
    url::Url::parse(&url).map_err(|_| Error::invalid_config("invalid STS endpoint URL"))
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

fn sts_api_error(status: StatusCode, body: &str) -> Error {
    let snippet = truncate_snippet(body, 4096);
    if let Some(parsed) = crate::util::xml::parse_error_xml(body) {
        return Error::Api {
            status,
            code: parsed.code,
            message: parsed.message,
            request_id: parsed.request_id,
            host_id: parsed.host_id,
            body_snippet: Some(snippet),
        };
    }

    Error::Api {
        status,
        code: None,
        message: None,
        request_id: None,
        host_id: None,
        body_snippet: Some(snippet),
    }
}

fn truncate_snippet(body: &str, max_len: usize) -> String {
    if body.len() <= max_len {
        return body.to_string();
    }
    let mut out = body[..max_len].to_string();
    out.push_str("...");
    out
}

fn parse_assume_role_response(body: &str) -> Result<Credentials, Error> {
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
    Ok(creds)
}

fn parse_assume_role_with_web_identity_response(body: &str) -> Result<Credentials, Error> {
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
    Ok(creds)
}
