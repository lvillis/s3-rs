use std::time::Duration;

use http::{HeaderMap, Method};
use time::OffsetDateTime;
use url::Url;

use crate::{
    auth::{CredentialsSnapshot, Region},
    error::{Error, Result},
    util,
};

pub(crate) fn sign_with_snapshot(
    method: &Method,
    resolved: &crate::util::url::ResolvedUrl,
    headers: &mut HeaderMap,
    payload_hash: &str,
    region: &Region,
    snapshot: &CredentialsSnapshot,
    now: OffsetDateTime,
) -> Result<()> {
    util::signing::sign_headers(
        method,
        resolved,
        headers,
        payload_hash,
        region,
        snapshot.credentials(),
        now,
    )
}

pub(crate) fn parse_endpoint(endpoint: &str) -> Result<Url> {
    let endpoint = Url::parse(endpoint)
        .map_err(|_| Error::invalid_config("endpoint must be a valid absolute URL"))?;

    if endpoint.scheme() != "http" && endpoint.scheme() != "https" {
        return Err(Error::invalid_config(
            "endpoint scheme must be http or https",
        ));
    }
    if endpoint.host_str().is_none() {
        return Err(Error::invalid_config("endpoint must include host"));
    }
    if !endpoint.username().is_empty() || endpoint.password().is_some() {
        return Err(Error::invalid_config("endpoint must not include user info"));
    }
    if endpoint.query().is_some() || endpoint.fragment().is_some() {
        return Err(Error::invalid_config(
            "endpoint must not include query or fragment",
        ));
    }
    if endpoint.path() != "/" && !endpoint.path().is_empty() {
        return Err(Error::invalid_config("endpoint must not include a path"));
    }

    Ok(endpoint)
}

pub(crate) fn validate_presign_credentials_lifetime(
    snapshot: &CredentialsSnapshot,
    expires_in: Duration,
    now: OffsetDateTime,
) -> Result<()> {
    if let Some(expires_at) = snapshot.expires_at() {
        if expires_at <= now {
            return Err(Error::invalid_config("credentials are expired"));
        }
        let remaining: std::time::Duration = (expires_at - now).try_into().map_err(|_| {
            Error::invalid_config("failed to calculate credentials expiration window")
        })?;
        if remaining < expires_in {
            return Err(Error::invalid_config(
                "presign expires_in exceeds credentials lifetime",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::auth::Credentials;

    #[test]
    fn validate_presign_credentials_lifetime_accepts_non_expiring_snapshot() {
        let snapshot = CredentialsSnapshot::new(
            Credentials::new("AKIA_TEST", "SECRET_TEST").expect("valid credentials"),
        );
        assert!(
            validate_presign_credentials_lifetime(
                &snapshot,
                Duration::from_secs(300),
                OffsetDateTime::now_utc(),
            )
            .is_ok()
        );
    }

    #[test]
    fn validate_presign_credentials_lifetime_rejects_expired_snapshot() {
        let now = OffsetDateTime::now_utc();
        let snapshot = CredentialsSnapshot::new(
            Credentials::new("AKIA_TEST", "SECRET_TEST").expect("valid credentials"),
        )
        .with_expires_at(now - time::Duration::seconds(1));
        let err = validate_presign_credentials_lifetime(&snapshot, Duration::from_secs(1), now)
            .expect_err("expired snapshot should be rejected");
        match err {
            Error::InvalidConfig { message } => assert!(message.contains("expired")),
            other => panic!("expected invalid config, got {other:?}"),
        }
    }

    #[test]
    fn validate_presign_credentials_lifetime_rejects_excessive_expiry() {
        let now = OffsetDateTime::now_utc();
        let snapshot = CredentialsSnapshot::new(
            Credentials::new("AKIA_TEST", "SECRET_TEST").expect("valid credentials"),
        )
        .with_expires_at(now + time::Duration::seconds(30));
        let err = validate_presign_credentials_lifetime(&snapshot, Duration::from_secs(60), now)
            .expect_err("expires_in beyond credentials lifetime should be rejected");
        match err {
            Error::InvalidConfig { message } => {
                assert!(message.contains("exceeds credentials lifetime"))
            }
            other => panic!("expected invalid config, got {other:?}"),
        }
    }

    #[test]
    fn parse_endpoint_accepts_clean_absolute_urls() {
        let endpoint = parse_endpoint("https://s3.example.com").expect("endpoint should parse");
        assert_eq!(endpoint.as_str(), "https://s3.example.com/");
    }

    #[test]
    fn parse_endpoint_rejects_paths_and_query_strings() {
        let err = parse_endpoint("https://s3.example.com/path?x=1")
            .expect_err("endpoint with path and query must be rejected");
        match err {
            Error::InvalidConfig { message } => {
                assert!(
                    message.contains("path") || message.contains("query or fragment"),
                    "unexpected message: {message}"
                );
            }
            other => panic!("expected invalid config, got {other:?}"),
        }
    }
}
