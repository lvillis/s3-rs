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
async fn minio_get_range_and_conditions() -> Result<(), Error> {
    let Some(cfg) = load_config()? else {
        return Ok(());
    };

    let client = build_client(&cfg)?;
    let bucket = unique_bucket("s3-it-range-");
    client.buckets().create(&bucket).send().await?;

    let key = "range.txt";
    let body = Bytes::from_static(b"hello world");
    let put = client
        .objects()
        .put(&bucket, key)
        .content_type("text/plain")
        .body_bytes(body.clone())
        .send()
        .await?;

    let etag = put
        .etag
        .ok_or_else(|| Error::decode("missing etag", None))?;

    let got = client
        .objects()
        .get(&bucket, key)
        .range_bytes(0, 4)
        .send()
        .await?
        .bytes()
        .await?;
    assert_eq!(got, Bytes::from_static(b"hello"));

    let ok = client
        .objects()
        .get(&bucket, key)
        .if_match(etag.clone())
        .send()
        .await?
        .bytes()
        .await?;
    assert_eq!(ok, body);

    match client
        .objects()
        .get(&bucket, key)
        .if_match("not-a-real-etag")
        .send()
        .await
    {
        Ok(_) => panic!("expected precondition failed"),
        Err(Error::Api { status, .. }) => assert_eq!(status, StatusCode::PRECONDITION_FAILED),
        Err(other) => panic!("expected api error, got {other:?}"),
    }

    match client
        .objects()
        .get(&bucket, key)
        .if_none_match(etag)
        .send()
        .await
    {
        Ok(_) => panic!("expected not modified"),
        Err(Error::Api { status, .. }) => assert_eq!(status, StatusCode::NOT_MODIFIED),
        Err(other) => panic!("expected api error, got {other:?}"),
    }

    client.objects().delete(&bucket, key).send().await?;
    client.buckets().delete(&bucket).send().await?;
    Ok(())
}

#[tokio::test]
async fn minio_list_v2_pager_and_common_prefixes() -> Result<(), Error> {
    let Some(cfg) = load_config()? else {
        return Ok(());
    };

    let client = build_client(&cfg)?;
    let bucket = unique_bucket("s3-it-list-");
    client.buckets().create(&bucket).send().await?;

    for key in ["a/1.txt", "a/2.txt", "a/3.txt", "b/1.txt", "root.txt"] {
        client
            .objects()
            .put(&bucket, key)
            .body_bytes(Bytes::from_static(b"x"))
            .send()
            .await?;
    }

    let mut pager = client
        .objects()
        .list_v2(&bucket)
        .prefix("a/")
        .max_keys(2)
        .pager();
    let mut keys = Vec::new();
    while let Some(page) = pager.next_page().await? {
        keys.extend(page.contents.into_iter().map(|o| o.key));
    }
    keys.sort();
    assert_eq!(keys, vec!["a/1.txt", "a/2.txt", "a/3.txt"]);

    let out = client
        .objects()
        .list_v2(&bucket)
        .delimiter("/")
        .send()
        .await?;
    assert!(out.common_prefixes.iter().any(|p| p == "a/"));
    assert!(out.common_prefixes.iter().any(|p| p == "b/"));
    assert!(out.contents.iter().any(|o| o.key == "root.txt"));

    client.objects().delete(&bucket, "a/1.txt").send().await?;
    client.objects().delete(&bucket, "a/2.txt").send().await?;
    client.objects().delete(&bucket, "a/3.txt").send().await?;
    client.objects().delete(&bucket, "b/1.txt").send().await?;
    client.objects().delete(&bucket, "root.txt").send().await?;
    client.buckets().delete(&bucket).send().await?;
    Ok(())
}

#[tokio::test]
async fn minio_copy_object_roundtrip() -> Result<(), Error> {
    let Some(cfg) = load_config()? else {
        return Ok(());
    };

    let client = build_client(&cfg)?;
    let bucket = unique_bucket("s3-it-copy-");
    client.buckets().create(&bucket).send().await?;

    let src = "src/a+b.txt";
    let dst = "dst/copied.txt";
    let body = Bytes::from_static(b"copy-me");
    client
        .objects()
        .put(&bucket, src)
        .body_bytes(body.clone())
        .send()
        .await?;

    client
        .objects()
        .copy(&bucket, src, &bucket, dst)
        .send()
        .await?;

    let got = client
        .objects()
        .get(&bucket, dst)
        .send()
        .await?
        .bytes()
        .await?;
    assert_eq!(got, body);

    client.objects().delete(&bucket, src).send().await?;
    client.objects().delete(&bucket, dst).send().await?;
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

    let part1 = Bytes::from(vec![b'a'; 5 * 1024 * 1024]);
    let part2 = Bytes::from_static(b"world");

    let p1 = client
        .objects()
        .upload_part(&bucket, key, &upload_id, 1)
        .body_bytes(part1.clone())
        .send()
        .await?;
    let p2 = client
        .objects()
        .upload_part(&bucket, key, &upload_id, 2)
        .body_bytes(part2.clone())
        .send()
        .await?;

    let etag1 = p1
        .etag
        .ok_or_else(|| Error::decode("missing upload part etag", None))?;
    let etag2 = p2
        .etag
        .ok_or_else(|| Error::decode("missing upload part etag", None))?;

    let parts = client
        .objects()
        .list_parts(&bucket, key, &upload_id)
        .send()
        .await?;
    assert!(parts.parts.len() >= 2);

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
    assert_eq!(got.len(), part1.len() + part2.len());
    let got = got.as_ref();
    assert!(got[..part1.len()].iter().all(|&b| b == b'a'));
    assert_eq!(&got[part1.len()..], part2.as_ref());

    client.objects().delete(&bucket, key).send().await?;
    client.buckets().delete(&bucket).send().await?;
    Ok(())
}
