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
pub(crate) async fn load_async() -> Result<CredentialsSnapshot, Error> {
    use std::time::Duration;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|e| Error::transport("failed to build HTTP client", Some(Box::new(e))))?;

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
    client: &reqwest::Client,
    url: &str,
    headers: http::HeaderMap,
) -> Result<String, Error> {
    let resp = client
        .get(url)
        .headers(headers)
        .send()
        .await
        .map_err(|e| Error::transport("request failed", Some(Box::new(e))))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| Error::transport("failed to read response body", Some(Box::new(e))))?;
    if status.is_success() {
        return Ok(body);
    }
    Err(Error::Api {
        status,
        code: None,
        message: None,
        request_id: None,
        host_id: None,
        body_snippet: Some(body),
    })
}

#[cfg(feature = "async")]
async fn fetch_imds_v2_token(client: &reqwest::Client) -> Result<String, Error> {
    let resp = client
        .put("http://169.254.169.254/latest/api/token")
        .header("X-aws-ec2-metadata-token-ttl-seconds", "21600")
        .send()
        .await
        .map_err(|e| Error::transport("request failed", Some(Box::new(e))))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| Error::transport("failed to read response body", Some(Box::new(e))))?;
    if status.is_success() {
        return Ok(body.trim().to_string());
    }
    Err(Error::Api {
        status,
        code: None,
        message: None,
        request_id: None,
        host_id: None,
        body_snippet: Some(body),
    })
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
pub(crate) fn load_blocking() -> Result<CredentialsSnapshot, Error> {
    if let Some(full) = std::env::var("AWS_CONTAINER_CREDENTIALS_FULL_URI")
        .ok()
        .filter(|v| !v.is_empty())
    {
        let headers = container_auth_headers_blocking()?;
        let body = http_get_text_blocking(&full, &headers)?;
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
        let body = http_get_text_blocking(&url, &headers)?;
        let parsed: MetadataCredentials = serde_json::from_str(&body).map_err(|e| {
            Error::decode(
                "failed to parse container credentials JSON",
                Some(Box::new(e)),
            )
        })?;
        return parsed.into_snapshot();
    }

    let token = fetch_imds_v2_token_blocking().ok();
    let mut headers = http::HeaderMap::new();
    if let Some(token) = token.as_deref().filter(|v| !v.is_empty()) {
        let value = http::HeaderValue::from_str(token)
            .map_err(|_| Error::invalid_config("invalid IMDS token"))?;
        headers.insert("X-aws-ec2-metadata-token", value);
    }

    let role = http_get_text_blocking(
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        &headers,
    )?;
    let role = role.lines().next().unwrap_or("").trim();
    if role.is_empty() {
        return Err(Error::invalid_config("missing IMDS role name"));
    }

    let url = format!("http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}");
    let body = http_get_text_blocking(&url, &headers)?;
    let parsed: MetadataCredentials = serde_json::from_str(&body)
        .map_err(|e| Error::decode("failed to parse IMDS credentials JSON", Some(Box::new(e))))?;
    parsed.into_snapshot()
}

#[cfg(feature = "blocking")]
fn http_get_text_blocking(url: &str, headers: &http::HeaderMap) -> Result<String, Error> {
    use std::io::Read as _;

    let mut req = ureq::agent().get(url);
    for (name, value) in headers.iter() {
        let Ok(value) = value.to_str() else {
            continue;
        };
        req = req.header(name.as_str(), value);
    }

    let resp = req
        .call()
        .map_err(|e| Error::transport("request failed", Some(Box::new(e))))?;
    let status = resp.status();

    let mut out = String::new();
    resp.into_body()
        .into_reader()
        .read_to_string(&mut out)
        .map_err(|e| Error::transport("failed to read response body", Some(Box::new(e))))?;

    if status.is_success() {
        return Ok(out);
    }

    Err(Error::Api {
        status,
        code: None,
        message: None,
        request_id: None,
        host_id: None,
        body_snippet: Some(out),
    })
}

#[cfg(feature = "blocking")]
fn fetch_imds_v2_token_blocking() -> Result<String, Error> {
    use std::io::Read as _;

    let resp = ureq::agent()
        .put("http://169.254.169.254/latest/api/token")
        .header("X-aws-ec2-metadata-token-ttl-seconds", "21600")
        .send_empty()
        .map_err(|e| Error::transport("request failed", Some(Box::new(e))))?;

    let status = resp.status();

    let mut out = String::new();
    resp.into_body()
        .into_reader()
        .read_to_string(&mut out)
        .map_err(|e| Error::transport("failed to read response body", Some(Box::new(e))))?;

    if status.is_success() {
        return Ok(out.trim().to_string());
    }

    Err(Error::Api {
        status,
        code: None,
        message: None,
        request_id: None,
        host_id: None,
        body_snippet: Some(out),
    })
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
