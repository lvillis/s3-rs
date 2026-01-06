use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    auth::{AddressingStyle, Credentials, CredentialsSnapshot, Region},
    error::Error,
};

const SERVICE: &str = "sts";

#[cfg(feature = "async")]
pub(crate) async fn assume_role_async(
    region: Region,
    role_arn: String,
    role_session_name: String,
    source_credentials: Credentials,
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
) -> Result<CredentialsSnapshot, Error> {
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
pub(crate) async fn assume_role_with_web_identity_env_async() -> Result<CredentialsSnapshot, Error>
{
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
pub(crate) fn assume_role_with_web_identity_env_blocking() -> Result<CredentialsSnapshot, Error> {
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
    let snippet = crate::util::text::truncate_snippet(body, 4096);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_regional_endpoint() {
        let region = Region::new("us-east-1").unwrap();
        let url = sts_regional_endpoint(&region).unwrap();
        assert_eq!(url.as_str(), "https://sts.us-east-1.amazonaws.com/");
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

        let err = sts_api_error(StatusCode::FORBIDDEN, err_xml);
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
}
