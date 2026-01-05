#![cfg(feature = "async")]
#![allow(clippy::result_large_err)]

use std::{
    env,
    sync::atomic::{AtomicUsize, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use http::StatusCode;

use s3::{AddressingStyle, Auth, Client, Error, Region};

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

fn build_client(cfg: &TestConfig) -> Result<Client, Error> {
    Client::builder(&cfg.endpoint)?
        .region(cfg.region.as_str())
        .auth(cfg.auth.clone())
        .addressing_style(AddressingStyle::Auto)
        .build()
}

#[tokio::test]
async fn minio_put_get_list_delete_roundtrip() -> Result<(), Error> {
    let Some(cfg) = load_config()? else {
        return Ok(());
    };

    let client = build_client(&cfg)?;
    let bucket = unique_bucket("s3-it-");

    client.buckets().create(&bucket).send().await?;

    let key = "a+b.txt";
    let body = Bytes::from_static(b"hello");
    client
        .objects()
        .put(&bucket, key)
        .body_bytes(body.clone())
        .send()
        .await?;

    let got = client
        .objects()
        .get(&bucket, key)
        .send()
        .await?
        .bytes()
        .await?;
    assert_eq!(got, body);

    let head = client.objects().head(&bucket, key).send().await?;
    assert_eq!(head.content_length, Some(5));

    let list = client.objects().list_v2(&bucket).send().await?;
    assert!(list.contents.iter().any(|o| o.key == key));

    let presigned = client.objects().presign_get(&bucket, key).build()?;
    let resp = reqwest::Client::new()
        .request(presigned.method.clone(), presigned.url.clone())
        .headers(presigned.headers.clone())
        .send()
        .await
        .map_err(|e| Error::transport("presigned request failed", Some(Box::new(e))))?;
    assert!(resp.status().is_success());
    let presigned_body = resp
        .bytes()
        .await
        .map_err(|e| Error::transport("failed to read presigned body", Some(Box::new(e))))?;
    assert_eq!(presigned_body, Bytes::from_static(b"hello"));

    match client.objects().get(&bucket, "does-not-exist").send().await {
        Ok(_) => panic!("expected not found error"),
        Err(Error::Api { status, .. }) => assert_eq!(status, StatusCode::NOT_FOUND),
        Err(other) => panic!("expected api error, got {other:?}"),
    }

    client.objects().delete(&bucket, key).send().await?;
    client.buckets().delete(&bucket).send().await?;
    Ok(())
}

#[tokio::test]
async fn minio_delete_objects_batch() -> Result<(), Error> {
    let Some(cfg) = load_config()? else {
        return Ok(());
    };

    let client = build_client(&cfg)?;
    let bucket = unique_bucket("s3-it-batch-");
    client.buckets().create(&bucket).send().await?;

    client
        .objects()
        .put(&bucket, "k1")
        .body_bytes(Bytes::from_static(b"1"))
        .send()
        .await?;
    client
        .objects()
        .put(&bucket, "k2")
        .body_bytes(Bytes::from_static(b"2"))
        .send()
        .await?;

    let out = client
        .objects()
        .delete_objects(&bucket)
        .object("k1")
        .object("k2")
        .send()
        .await?;
    assert!(out.errors.is_empty());
    assert!(out.deleted.len() >= 2);

    client.buckets().delete(&bucket).send().await?;
    Ok(())
}

#[cfg(feature = "multipart")]
#[tokio::test]
async fn minio_multipart_put_get_roundtrip() -> Result<(), Error> {
    let Some(cfg) = load_config()? else {
        return Ok(());
    };

    let client = build_client(&cfg)?;
    let bucket = unique_bucket("s3-it-mpu-");
    client.buckets().create(&bucket).send().await?;

    let key = "mpu.txt";
    let create = client
        .objects()
        .create_multipart_upload(&bucket, key)
        .send()
        .await?;
    let upload_id = create.upload_id;

    let p1 = client
        .objects()
        .upload_part(&bucket, key, &upload_id, 1)
        .body_bytes(Bytes::from_static(b"hello"))
        .send()
        .await?;
    let p2 = client
        .objects()
        .upload_part(&bucket, key, &upload_id, 2)
        .body_bytes(Bytes::from_static(b"world"))
        .send()
        .await?;

    let etag1 = p1
        .etag
        .ok_or_else(|| Error::decode("missing upload part etag", None))?;
    let etag2 = p2
        .etag
        .ok_or_else(|| Error::decode("missing upload part etag", None))?;

    client
        .objects()
        .complete_multipart_upload(&bucket, key, &upload_id)
        .part(1, etag1)
        .part(2, etag2)
        .send()
        .await?;

    let got = client
        .objects()
        .get(&bucket, key)
        .send()
        .await?
        .bytes()
        .await?;
    assert_eq!(got, Bytes::from_static(b"helloworld"));

    client.objects().delete(&bucket, key).send().await?;
    client.buckets().delete(&bucket).send().await?;
    Ok(())
}
