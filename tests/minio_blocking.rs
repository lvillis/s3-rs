#![cfg(feature = "blocking")]
#![allow(clippy::result_large_err)]

use std::{
    env,
    sync::atomic::{AtomicUsize, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use http::StatusCode;

use s3::{AddressingStyle, Auth, BlockingClient, Error, Region};

static BUCKET_COUNTER: AtomicUsize = AtomicUsize::new(0);

struct TestConfig {
    endpoint: String,
    region: Region,
    auth: Auth,
}

fn load_config() -> Result<Option<TestConfig>, Error> {
    let Ok(endpoint) = env::var("S3_TEST_ENDPOINT") else {
        return Ok(None);
    };

    let region = env::var("S3_TEST_REGION").unwrap_or_else(|_| "us-east-1".to_string());
    let region = Region::new(region)?;

    let Ok(auth) = Auth::from_env() else {
        return Ok(None);
    };

    Ok(Some(TestConfig {
        endpoint,
        region,
        auth,
    }))
}

fn unique_bucket(prefix: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let n = BUCKET_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}{now}-{n}")
}

fn build_client(cfg: &TestConfig) -> Result<BlockingClient, Error> {
    BlockingClient::builder(&cfg.endpoint)?
        .region(cfg.region.as_str())
        .auth(cfg.auth.clone())
        .addressing_style(AddressingStyle::Auto)
        .build()
}

#[test]
fn minio_blocking_put_get_delete_roundtrip() -> Result<(), Error> {
    let Some(cfg) = load_config()? else {
        return Ok(());
    };

    let client = build_client(&cfg)?;
    let bucket = unique_bucket("s3-it-blocking-");

    client.buckets().create(&bucket).send()?;

    let key = "hello.txt";
    let body = Bytes::from_static(b"hello");
    client
        .objects()
        .put(&bucket, key)
        .body_bytes(body.clone())
        .send()?;

    let head = client.objects().head(&bucket, key).send()?;
    assert_eq!(head.content_length, Some(5));

    let range = client
        .objects()
        .get(&bucket, key)
        .range_bytes(0, 3)
        .send()?
        .bytes()?;
    assert_eq!(range, Bytes::from_static(b"hell"));

    let got = client.objects().get(&bucket, key).send()?.bytes()?;
    assert_eq!(got, body);

    let copied = "copied.txt";
    client
        .objects()
        .copy(&bucket, key, &bucket, copied)
        .send()?;
    let got = client.objects().get(&bucket, copied).send()?.bytes()?;
    assert_eq!(got, body);

    for k in ["a/1.txt", "a/2.txt", "a/3.txt", "b/1.txt", "root.txt"] {
        client
            .objects()
            .put(&bucket, k)
            .body_bytes(Bytes::from_static(b"x"))
            .send()?;
    }

    let mut keys = Vec::new();
    let pager = client
        .objects()
        .list_v2(&bucket)
        .prefix("a/")
        .max_keys(2)
        .pager();
    for page in pager {
        let page = page?;
        keys.extend(page.contents.into_iter().map(|o| o.key));
    }
    keys.sort();
    assert_eq!(keys, vec!["a/1.txt", "a/2.txt", "a/3.txt"]);

    let out = client.objects().list_v2(&bucket).delimiter("/").send()?;
    assert!(out.common_prefixes.iter().any(|p| p == "a/"));
    assert!(out.common_prefixes.iter().any(|p| p == "b/"));
    assert!(out.contents.iter().any(|o| o.key == "root.txt"));

    match client.objects().get(&bucket, "does-not-exist").send() {
        Ok(_) => panic!("expected not found error"),
        Err(Error::Api { status, .. }) => assert_eq!(status, StatusCode::NOT_FOUND),
        Err(other) => panic!("expected api error, got {other:?}"),
    }

    let presigned = client.objects().presign_get(&bucket, key).build()?;
    let mut req = ureq::agent().get(presigned.url.as_str());
    for (name, value) in presigned.headers.iter() {
        let Ok(value_str) = value.to_str() else {
            continue;
        };
        req = req.header(name.as_str(), value_str);
    }
    let resp = req
        .call()
        .map_err(|e| Error::transport("presigned request failed", Some(Box::new(e))))?;
    assert!(resp.status().is_success());

    client
        .objects()
        .delete_objects(&bucket)
        .objects([
            key, copied, "a/1.txt", "a/2.txt", "a/3.txt", "b/1.txt", "root.txt",
        ])
        .send()?;
    client.buckets().delete(&bucket).send()?;
    Ok(())
}
