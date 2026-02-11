#[cfg(all(feature = "async", feature = "credentials-imds"))]
use std::env;

#[cfg(all(feature = "async", feature = "credentials-imds"))]
use s3::{AsyncTlsRootStore, Auth, Client, CredentialsTlsRootStore};

#[cfg(all(feature = "async", feature = "credentials-imds"))]
fn request_tls_root_store_from_env() -> AsyncTlsRootStore {
    match env::var("S3_TLS_ROOT_STORE")
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "webpki" => AsyncTlsRootStore::WebPki,
        "system" => AsyncTlsRootStore::System,
        _ => AsyncTlsRootStore::BackendDefault,
    }
}

#[cfg(all(feature = "async", feature = "credentials-imds"))]
fn credentials_tls_root_store_from_env() -> CredentialsTlsRootStore {
    match env::var("S3_CREDENTIALS_TLS_ROOT_STORE")
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "webpki" => CredentialsTlsRootStore::WebPki,
        "system" => CredentialsTlsRootStore::System,
        _ => CredentialsTlsRootStore::BackendDefault,
    }
}

#[cfg(all(feature = "async", feature = "credentials-imds"))]
#[allow(clippy::result_large_err)]
#[tokio::main]
async fn main() -> Result<(), s3::Error> {
    let endpoint = match env::var("S3_TEST_ENDPOINT") {
        Ok(v) => v,
        Err(_) => {
            eprintln!("Set S3_TEST_ENDPOINT to run this example (e.g. http://127.0.0.1:9000).");
            return Ok(());
        }
    };
    let region = env::var("S3_TEST_REGION").unwrap_or_else(|_| "us-east-1".to_string());

    let credentials_tls_root_store = credentials_tls_root_store_from_env();
    let auth = match Auth::from_imds_with_tls_root_store(credentials_tls_root_store).await {
        Ok(v) => v,
        Err(err) => {
            eprintln!("IMDS is not available: {err}");
            return Ok(());
        }
    };

    let request_tls_root_store = request_tls_root_store_from_env();
    eprintln!(
        "Using request TLS root store: {request_tls_root_store:?}; credentials TLS root store: {credentials_tls_root_store:?}"
    );
    eprintln!(
        "Set S3_TLS_ROOT_STORE and S3_CREDENTIALS_TLS_ROOT_STORE to system|webpki|backend-default."
    );

    let client = Client::builder(&endpoint)?
        .region(region)
        .auth(auth)
        .tls_root_store(request_tls_root_store)
        .build()?;

    let buckets = client.buckets().list().send().await?;
    for bucket in buckets.buckets {
        println!("{}", bucket.name);
    }

    Ok(())
}

#[cfg(not(all(feature = "async", feature = "credentials-imds")))]
fn main() {
    eprintln!("This example requires `async` + `credentials-imds`.");
    eprintln!("Try: cargo run --example async_auth_imds --features credentials-imds");
}
