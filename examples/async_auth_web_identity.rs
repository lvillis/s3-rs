#[cfg(all(feature = "async", feature = "credentials-sts"))]
use std::env;

#[cfg(all(feature = "async", feature = "credentials-sts"))]
use s3::{Auth, Client};

#[cfg(all(feature = "async", feature = "credentials-sts"))]
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

    let auth = match Auth::from_web_identity_env().await {
        Ok(v) => v,
        Err(err) => {
            eprintln!("Web identity credentials are not available: {err}");
            return Ok(());
        }
    };

    let client = Client::builder(&endpoint)?
        .region(region)
        .auth(auth)
        .build()?;

    let buckets = client.buckets().list().send().await?;
    for bucket in buckets.buckets {
        println!("{}", bucket.name);
    }

    Ok(())
}

#[cfg(not(all(feature = "async", feature = "credentials-sts")))]
fn main() {
    eprintln!("This example requires `async` + `credentials-sts`.");
    eprintln!("Try: cargo run --example async_auth_web_identity --features credentials-sts");
}
