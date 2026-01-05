use bytes::Bytes;

use crate::{error::Error, types};

const S3_XMLNS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

pub(crate) fn parse_error_xml(body: &str) -> Option<types::XmlError> {
    if body.trim().is_empty() {
        return None;
    }

    quick_xml::de::from_str::<types::XmlError>(body).ok()
}

pub(crate) fn parse_list_objects_v2(body: &str) -> Result<types::ListObjectsV2Output, Error> {
    let parsed = quick_xml::de::from_str::<types::XmlListBucketResult>(body).map_err(|e| {
        Error::decode(
            "failed to parse ListObjectsV2 XML response",
            Some(Box::new(e)),
        )
    })?;
    types::ListObjectsV2Output::try_from(parsed)
}

pub(crate) fn parse_list_buckets(body: &str) -> Result<types::ListBucketsOutput, Error> {
    let parsed =
        quick_xml::de::from_str::<types::XmlListAllMyBucketsResult>(body).map_err(|e| {
            Error::decode(
                "failed to parse ListBuckets XML response",
                Some(Box::new(e)),
            )
        })?;
    Ok(types::ListBucketsOutput::from(parsed))
}

pub(crate) fn parse_bucket_versioning(
    body: &str,
) -> Result<types::BucketVersioningConfiguration, Error> {
    let parsed =
        quick_xml::de::from_str::<types::XmlVersioningConfiguration>(body).map_err(|e| {
            Error::decode(
                "failed to parse GetBucketVersioning XML response",
                Some(Box::new(e)),
            )
        })?;

    Ok(types::BucketVersioningConfiguration {
        status: parsed.status.as_deref().and_then(parse_versioning_status),
        mfa_delete: parsed.mfa_delete.as_deref().and_then(parse_mfa_delete),
    })
}

pub(crate) fn parse_bucket_lifecycle(
    body: &str,
) -> Result<types::BucketLifecycleConfiguration, Error> {
    let parsed =
        quick_xml::de::from_str::<types::XmlLifecycleConfiguration>(body).map_err(|e| {
            Error::decode(
                "failed to parse GetBucketLifecycle XML response",
                Some(Box::new(e)),
            )
        })?;

    Ok(types::BucketLifecycleConfiguration {
        rules: parsed
            .rules
            .into_iter()
            .filter_map(|r| {
                let status = match r.status.as_str() {
                    "Enabled" => types::BucketLifecycleStatus::Enabled,
                    "Disabled" => types::BucketLifecycleStatus::Disabled,
                    _ => return None,
                };

                let prefix = r
                    .filter
                    .and_then(|f| f.prefix)
                    .or(r.prefix)
                    .filter(|v| !v.is_empty());
                let (expiration_days, expiration_date) = match r.expiration {
                    Some(exp) => (exp.days, exp.date),
                    None => (None, None),
                };

                Some(types::BucketLifecycleRule {
                    id: r.id,
                    status,
                    prefix,
                    expiration_days,
                    expiration_date,
                })
            })
            .collect(),
    })
}

pub(crate) fn parse_bucket_cors(body: &str) -> Result<types::BucketCorsConfiguration, Error> {
    let parsed = quick_xml::de::from_str::<types::XmlCorsConfiguration>(body).map_err(|e| {
        Error::decode(
            "failed to parse GetBucketCors XML response",
            Some(Box::new(e)),
        )
    })?;

    Ok(types::BucketCorsConfiguration {
        rules: parsed
            .rules
            .into_iter()
            .map(|r| types::BucketCorsRule {
                id: r.id,
                allowed_origins: r.allowed_origins,
                allowed_methods: r
                    .allowed_methods
                    .into_iter()
                    .map(parse_cors_method)
                    .collect(),
                allowed_headers: r.allowed_headers,
                expose_headers: r.expose_headers,
                max_age_seconds: r.max_age_seconds,
            })
            .collect(),
    })
}

pub(crate) fn parse_bucket_tagging(body: &str) -> Result<types::BucketTagging, Error> {
    let parsed = quick_xml::de::from_str::<types::XmlTagging>(body).map_err(|e| {
        Error::decode(
            "failed to parse GetBucketTagging XML response",
            Some(Box::new(e)),
        )
    })?;

    let tags = parsed
        .tag_set
        .map(|ts| {
            ts.tags
                .into_iter()
                .map(|t| types::Tag {
                    key: t.key,
                    value: t.value,
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(types::BucketTagging { tags })
}

pub(crate) fn parse_bucket_encryption(
    body: &str,
) -> Result<types::BucketEncryptionConfiguration, Error> {
    let parsed = quick_xml::de::from_str::<types::XmlServerSideEncryptionConfiguration>(body)
        .map_err(|e| {
            Error::decode(
                "failed to parse GetBucketEncryption XML response",
                Some(Box::new(e)),
            )
        })?;

    let rules = parsed
        .rules
        .into_iter()
        .filter_map(|r| {
            let apply = r.apply?;
            Some(types::BucketEncryptionRule {
                apply: types::ApplyServerSideEncryptionByDefault {
                    sse_algorithm: parse_sse_algorithm(&apply.sse_algorithm),
                    kms_master_key_id: apply.kms_master_key_id,
                },
                bucket_key_enabled: r.bucket_key_enabled,
            })
        })
        .collect();

    Ok(types::BucketEncryptionConfiguration { rules })
}

pub(crate) fn parse_bucket_public_access_block(
    body: &str,
) -> Result<types::BucketPublicAccessBlockConfiguration, Error> {
    let parsed = quick_xml::de::from_str::<types::XmlPublicAccessBlockConfiguration>(body)
        .map_err(|e| {
            Error::decode(
                "failed to parse GetPublicAccessBlock XML response",
                Some(Box::new(e)),
            )
        })?;

    Ok(types::BucketPublicAccessBlockConfiguration {
        block_public_acls: parsed.block_public_acls.unwrap_or(false),
        ignore_public_acls: parsed.ignore_public_acls.unwrap_or(false),
        block_public_policy: parsed.block_public_policy.unwrap_or(false),
        restrict_public_buckets: parsed.restrict_public_buckets.unwrap_or(false),
    })
}

pub(crate) fn parse_delete_objects(body: &str) -> Result<types::DeleteObjectsOutput, Error> {
    let parsed = quick_xml::de::from_str::<types::XmlDeleteResult>(body).map_err(|e| {
        Error::decode(
            "failed to parse DeleteObjects XML response",
            Some(Box::new(e)),
        )
    })?;
    Ok(types::DeleteObjectsOutput::from(parsed))
}

pub(crate) fn parse_copy_object(body: &str) -> Result<types::CopyObjectOutput, Error> {
    let parsed = quick_xml::de::from_str::<types::XmlCopyObjectResult>(body)
        .map_err(|e| Error::decode("failed to parse CopyObject XML response", Some(Box::new(e))))?;
    Ok(types::CopyObjectOutput::from(parsed))
}

#[cfg(feature = "multipart")]
pub(crate) fn parse_create_multipart_upload(
    body: &str,
) -> Result<types::CreateMultipartUploadOutput, Error> {
    let parsed =
        quick_xml::de::from_str::<types::XmlInitiateMultipartUploadResult>(body).map_err(|e| {
            Error::decode(
                "failed to parse CreateMultipartUpload XML response",
                Some(Box::new(e)),
            )
        })?;
    Ok(types::CreateMultipartUploadOutput::from(parsed))
}

#[cfg(feature = "multipart")]
pub(crate) fn parse_complete_multipart_upload(
    body: &str,
) -> Result<types::CompleteMultipartUploadOutput, Error> {
    let parsed =
        quick_xml::de::from_str::<types::XmlCompleteMultipartUploadResult>(body).map_err(|e| {
            Error::decode(
                "failed to parse CompleteMultipartUpload XML response",
                Some(Box::new(e)),
            )
        })?;
    Ok(types::CompleteMultipartUploadOutput::from(parsed))
}

#[cfg(feature = "multipart")]
pub(crate) fn parse_list_parts(body: &str) -> Result<types::ListPartsOutput, Error> {
    let parsed = quick_xml::de::from_str::<types::XmlListPartsResult>(body)
        .map_err(|e| Error::decode("failed to parse ListParts XML response", Some(Box::new(e))))?;
    Ok(types::ListPartsOutput::from(parsed))
}

#[cfg(feature = "multipart")]
pub(crate) fn parse_upload_part_copy(body: &str) -> Result<types::UploadPartCopyOutput, Error> {
    let parsed = quick_xml::de::from_str::<types::XmlCopyPartResult>(body).map_err(|e| {
        Error::decode(
            "failed to parse UploadPartCopy XML response",
            Some(Box::new(e)),
        )
    })?;
    Ok(types::UploadPartCopyOutput::from(parsed))
}

pub(crate) fn encode_create_bucket_configuration(region: &str) -> Result<Bytes, Error> {
    if region.trim().is_empty() {
        return Err(Error::invalid_config(
            "create bucket location constraint must not be empty",
        ));
    }

    #[derive(serde::Serialize)]
    #[serde(rename = "CreateBucketConfiguration")]
    struct XmlCreateBucketConfiguration<'a> {
        #[serde(rename = "@xmlns")]
        xmlns: &'static str,
        #[serde(rename = "LocationConstraint")]
        location_constraint: &'a str,
    }

    let xml = quick_xml::se::to_string(&XmlCreateBucketConfiguration {
        xmlns: S3_XMLNS,
        location_constraint: region,
    })
    .map_err(|e| {
        Error::decode(
            "failed to encode CreateBucketConfiguration XML",
            Some(Box::new(e)),
        )
    })?;
    Ok(Bytes::from(xml))
}

#[cfg(feature = "multipart")]
pub(crate) fn encode_complete_multipart_upload(
    parts: &[types::CompletedPart],
) -> Result<Bytes, Error> {
    if parts.is_empty() {
        return Err(Error::invalid_config(
            "complete multipart upload requires at least one part",
        ));
    }

    #[derive(serde::Serialize)]
    #[serde(rename = "CompleteMultipartUpload")]
    struct XmlOut<'a> {
        #[serde(rename = "@xmlns")]
        xmlns: &'static str,
        #[serde(rename = "Part")]
        parts: Vec<XmlPart<'a>>,
    }

    #[derive(serde::Serialize)]
    struct XmlPart<'a> {
        #[serde(rename = "PartNumber")]
        part_number: u32,
        #[serde(rename = "ETag")]
        etag: &'a str,
    }

    let xml = quick_xml::se::to_string(&XmlOut {
        xmlns: S3_XMLNS,
        parts: parts
            .iter()
            .map(|p| XmlPart {
                part_number: p.part_number,
                etag: &p.etag,
            })
            .collect(),
    })
    .map_err(|e| {
        Error::decode(
            "failed to encode CompleteMultipartUpload XML",
            Some(Box::new(e)),
        )
    })?;

    Ok(Bytes::from(xml))
}

pub(crate) fn encode_delete_objects(
    objects: &[types::DeleteObjectIdentifier],
    quiet: bool,
) -> Result<Bytes, Error> {
    if objects.is_empty() {
        return Err(Error::invalid_config(
            "delete_objects requires at least one object",
        ));
    }

    #[derive(serde::Serialize)]
    #[serde(rename = "Delete")]
    struct XmlOut<'a> {
        #[serde(rename = "@xmlns")]
        xmlns: &'static str,
        #[serde(rename = "Object")]
        objects: Vec<XmlObject<'a>>,
        #[serde(rename = "Quiet")]
        quiet: bool,
    }

    #[derive(serde::Serialize)]
    struct XmlObject<'a> {
        #[serde(rename = "Key")]
        key: &'a str,
        #[serde(rename = "VersionId", skip_serializing_if = "Option::is_none")]
        version_id: Option<&'a str>,
    }

    let xml = quick_xml::se::to_string(&XmlOut {
        xmlns: S3_XMLNS,
        objects: objects
            .iter()
            .map(|o| XmlObject {
                key: &o.key,
                version_id: o.version_id.as_deref(),
            })
            .collect(),
        quiet,
    })
    .map_err(|e| Error::decode("failed to encode DeleteObjects XML", Some(Box::new(e))))?;

    Ok(Bytes::from(xml))
}

pub(crate) fn encode_bucket_versioning(
    configuration: &types::BucketVersioningConfiguration,
) -> Result<Bytes, Error> {
    if configuration.status.is_none() {
        return Err(Error::invalid_config(
            "bucket versioning configuration must include status",
        ));
    }

    #[derive(serde::Serialize)]
    #[serde(rename = "VersioningConfiguration")]
    struct XmlOut {
        #[serde(rename = "@xmlns")]
        xmlns: &'static str,
        #[serde(rename = "Status", skip_serializing_if = "Option::is_none")]
        status: Option<&'static str>,
        #[serde(rename = "MfaDelete", skip_serializing_if = "Option::is_none")]
        mfa_delete: Option<&'static str>,
    }

    let xml = quick_xml::se::to_string(&XmlOut {
        xmlns: S3_XMLNS,
        status: configuration.status.map(versioning_status_str),
        mfa_delete: configuration.mfa_delete.map(mfa_delete_str),
    })
    .map_err(|e| {
        Error::decode(
            "failed to encode VersioningConfiguration XML",
            Some(Box::new(e)),
        )
    })?;
    Ok(Bytes::from(xml))
}

pub(crate) fn encode_bucket_lifecycle(
    configuration: &types::BucketLifecycleConfiguration,
) -> Result<Bytes, Error> {
    if configuration.rules.is_empty() {
        return Err(Error::invalid_config(
            "bucket lifecycle configuration must include at least one rule",
        ));
    }

    #[derive(serde::Serialize)]
    #[serde(rename = "LifecycleConfiguration")]
    struct XmlOut {
        #[serde(rename = "@xmlns")]
        xmlns: &'static str,
        #[serde(rename = "Rule")]
        rules: Vec<XmlRuleOut>,
    }

    #[derive(serde::Serialize)]
    struct XmlRuleOut {
        #[serde(rename = "ID", skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        #[serde(rename = "Status")]
        status: &'static str,
        #[serde(rename = "Filter", skip_serializing_if = "Option::is_none")]
        filter: Option<XmlFilterOut>,
        #[serde(rename = "Expiration", skip_serializing_if = "Option::is_none")]
        expiration: Option<XmlExpirationOut>,
    }

    #[derive(serde::Serialize)]
    struct XmlFilterOut {
        #[serde(rename = "Prefix", skip_serializing_if = "Option::is_none")]
        prefix: Option<String>,
    }

    #[derive(serde::Serialize)]
    struct XmlExpirationOut {
        #[serde(rename = "Days", skip_serializing_if = "Option::is_none")]
        days: Option<u32>,
        #[serde(rename = "Date", skip_serializing_if = "Option::is_none")]
        date: Option<String>,
    }

    let rules = configuration
        .rules
        .iter()
        .map(|r| XmlRuleOut {
            id: r.id.clone(),
            status: lifecycle_status_str(r.status),
            filter: if r.prefix.is_some() {
                Some(XmlFilterOut {
                    prefix: r.prefix.clone(),
                })
            } else {
                None
            },
            expiration: if r.expiration_days.is_some() || r.expiration_date.is_some() {
                Some(XmlExpirationOut {
                    days: r.expiration_days,
                    date: r.expiration_date.clone(),
                })
            } else {
                None
            },
        })
        .collect::<Vec<_>>();

    let xml = quick_xml::se::to_string(&XmlOut {
        xmlns: S3_XMLNS,
        rules,
    })
    .map_err(|e| {
        Error::decode(
            "failed to encode LifecycleConfiguration XML",
            Some(Box::new(e)),
        )
    })?;
    Ok(Bytes::from(xml))
}

pub(crate) fn encode_bucket_cors(
    configuration: &types::BucketCorsConfiguration,
) -> Result<Bytes, Error> {
    if configuration.rules.is_empty() {
        return Err(Error::invalid_config(
            "bucket cors configuration must include at least one rule",
        ));
    }

    #[derive(serde::Serialize)]
    #[serde(rename = "CORSConfiguration")]
    struct XmlOut {
        #[serde(rename = "@xmlns")]
        xmlns: &'static str,
        #[serde(rename = "CORSRule")]
        rules: Vec<XmlRuleOut>,
    }

    #[derive(serde::Serialize)]
    struct XmlRuleOut {
        #[serde(rename = "ID", skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        #[serde(rename = "AllowedOrigin")]
        allowed_origins: Vec<String>,
        #[serde(rename = "AllowedMethod")]
        allowed_methods: Vec<String>,
        #[serde(rename = "AllowedHeader", skip_serializing_if = "Vec::is_empty")]
        allowed_headers: Vec<String>,
        #[serde(rename = "ExposeHeader", skip_serializing_if = "Vec::is_empty")]
        expose_headers: Vec<String>,
        #[serde(rename = "MaxAgeSeconds", skip_serializing_if = "Option::is_none")]
        max_age_seconds: Option<u32>,
    }

    let xml = quick_xml::se::to_string(&XmlOut {
        xmlns: S3_XMLNS,
        rules: configuration
            .rules
            .iter()
            .map(|r| XmlRuleOut {
                id: r.id.clone(),
                allowed_origins: r.allowed_origins.clone(),
                allowed_methods: r
                    .allowed_methods
                    .iter()
                    .map(|m| m.as_str().to_string())
                    .collect(),
                allowed_headers: r.allowed_headers.clone(),
                expose_headers: r.expose_headers.clone(),
                max_age_seconds: r.max_age_seconds,
            })
            .collect(),
    })
    .map_err(|e| Error::decode("failed to encode CORSConfiguration XML", Some(Box::new(e))))?;
    Ok(Bytes::from(xml))
}

pub(crate) fn encode_bucket_tagging(tagging: &types::BucketTagging) -> Result<Bytes, Error> {
    #[derive(serde::Serialize)]
    #[serde(rename = "Tagging")]
    struct XmlOut {
        #[serde(rename = "@xmlns")]
        xmlns: &'static str,
        #[serde(rename = "TagSet")]
        tag_set: XmlTagSet,
    }

    #[derive(serde::Serialize)]
    struct XmlTagSet {
        #[serde(rename = "Tag")]
        tags: Vec<XmlTag>,
    }

    #[derive(serde::Serialize)]
    struct XmlTag {
        #[serde(rename = "Key")]
        key: String,
        #[serde(rename = "Value")]
        value: String,
    }

    let xml = quick_xml::se::to_string(&XmlOut {
        xmlns: S3_XMLNS,
        tag_set: XmlTagSet {
            tags: tagging
                .tags
                .iter()
                .map(|t| XmlTag {
                    key: t.key.clone(),
                    value: t.value.clone(),
                })
                .collect(),
        },
    })
    .map_err(|e| Error::decode("failed to encode Tagging XML", Some(Box::new(e))))?;
    Ok(Bytes::from(xml))
}

pub(crate) fn encode_bucket_encryption(
    configuration: &types::BucketEncryptionConfiguration,
) -> Result<Bytes, Error> {
    if configuration.rules.is_empty() {
        return Err(Error::invalid_config(
            "bucket encryption configuration must include at least one rule",
        ));
    }

    #[derive(serde::Serialize)]
    #[serde(rename = "ServerSideEncryptionConfiguration")]
    struct XmlOut {
        #[serde(rename = "@xmlns")]
        xmlns: &'static str,
        #[serde(rename = "Rule")]
        rules: Vec<XmlRuleOut>,
    }

    #[derive(serde::Serialize)]
    struct XmlRuleOut {
        #[serde(rename = "ApplyServerSideEncryptionByDefault")]
        apply: XmlApplyOut,
        #[serde(rename = "BucketKeyEnabled", skip_serializing_if = "Option::is_none")]
        bucket_key_enabled: Option<bool>,
    }

    #[derive(serde::Serialize)]
    struct XmlApplyOut {
        #[serde(rename = "SSEAlgorithm")]
        sse_algorithm: String,
        #[serde(rename = "KMSMasterKeyID", skip_serializing_if = "Option::is_none")]
        kms_master_key_id: Option<String>,
    }

    let rules = configuration
        .rules
        .iter()
        .map(|r| XmlRuleOut {
            apply: XmlApplyOut {
                sse_algorithm: r.apply.sse_algorithm.as_str().to_string(),
                kms_master_key_id: r.apply.kms_master_key_id.clone(),
            },
            bucket_key_enabled: r.bucket_key_enabled,
        })
        .collect();

    let xml = quick_xml::se::to_string(&XmlOut {
        xmlns: S3_XMLNS,
        rules,
    })
    .map_err(|e| {
        Error::decode(
            "failed to encode ServerSideEncryptionConfiguration XML",
            Some(Box::new(e)),
        )
    })?;
    Ok(Bytes::from(xml))
}

pub(crate) fn encode_bucket_public_access_block(
    configuration: &types::BucketPublicAccessBlockConfiguration,
) -> Result<Bytes, Error> {
    #[derive(serde::Serialize)]
    #[serde(rename = "PublicAccessBlockConfiguration")]
    struct XmlOut {
        #[serde(rename = "@xmlns")]
        xmlns: &'static str,
        #[serde(rename = "BlockPublicAcls")]
        block_public_acls: bool,
        #[serde(rename = "IgnorePublicAcls")]
        ignore_public_acls: bool,
        #[serde(rename = "BlockPublicPolicy")]
        block_public_policy: bool,
        #[serde(rename = "RestrictPublicBuckets")]
        restrict_public_buckets: bool,
    }

    let xml = quick_xml::se::to_string(&XmlOut {
        xmlns: S3_XMLNS,
        block_public_acls: configuration.block_public_acls,
        ignore_public_acls: configuration.ignore_public_acls,
        block_public_policy: configuration.block_public_policy,
        restrict_public_buckets: configuration.restrict_public_buckets,
    })
    .map_err(|e| {
        Error::decode(
            "failed to encode PublicAccessBlockConfiguration XML",
            Some(Box::new(e)),
        )
    })?;
    Ok(Bytes::from(xml))
}

fn parse_versioning_status(value: &str) -> Option<types::BucketVersioningStatus> {
    match value {
        "Enabled" => Some(types::BucketVersioningStatus::Enabled),
        "Suspended" => Some(types::BucketVersioningStatus::Suspended),
        _ => None,
    }
}

fn versioning_status_str(value: types::BucketVersioningStatus) -> &'static str {
    match value {
        types::BucketVersioningStatus::Enabled => "Enabled",
        types::BucketVersioningStatus::Suspended => "Suspended",
    }
}

fn parse_mfa_delete(value: &str) -> Option<types::BucketMfaDeleteStatus> {
    match value {
        "Enabled" => Some(types::BucketMfaDeleteStatus::Enabled),
        "Disabled" => Some(types::BucketMfaDeleteStatus::Disabled),
        _ => None,
    }
}

fn mfa_delete_str(value: types::BucketMfaDeleteStatus) -> &'static str {
    match value {
        types::BucketMfaDeleteStatus::Enabled => "Enabled",
        types::BucketMfaDeleteStatus::Disabled => "Disabled",
    }
}

fn lifecycle_status_str(value: types::BucketLifecycleStatus) -> &'static str {
    match value {
        types::BucketLifecycleStatus::Enabled => "Enabled",
        types::BucketLifecycleStatus::Disabled => "Disabled",
    }
}

fn parse_cors_method(value: String) -> types::CorsMethod {
    match value.as_str() {
        "GET" => types::CorsMethod::Get,
        "PUT" => types::CorsMethod::Put,
        "POST" => types::CorsMethod::Post,
        "DELETE" => types::CorsMethod::Delete,
        "HEAD" => types::CorsMethod::Head,
        other => types::CorsMethod::Other(other.to_string()),
    }
}

fn parse_sse_algorithm(value: &str) -> types::SseAlgorithm {
    match value {
        "AES256" => types::SseAlgorithm::Aes256,
        "aws:kms" => types::SseAlgorithm::AwsKms,
        "aws:kms:dsse" => types::SseAlgorithm::AwsKmsDsse,
        other => types::SseAlgorithm::Other(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::DeleteObjectIdentifier;

    #[test]
    fn parses_list_buckets() {
        let xml = r#"
<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Owner>
    <ID>owner-id</ID>
    <DisplayName>owner</DisplayName>
  </Owner>
  <Buckets>
    <Bucket>
      <Name>bucket-a</Name>
      <CreationDate>2020-01-01T00:00:00.000Z</CreationDate>
    </Bucket>
  </Buckets>
</ListAllMyBucketsResult>
"#;

        let out = parse_list_buckets(xml).unwrap();
        assert_eq!(out.owner.unwrap().id.as_deref(), Some("owner-id"));
        assert_eq!(out.buckets.len(), 1);
        assert_eq!(out.buckets[0].name, "bucket-a");
    }

    #[test]
    fn encodes_delete_objects_request() {
        let objects = vec![
            DeleteObjectIdentifier::new("a.txt"),
            DeleteObjectIdentifier::new("b.txt").with_version_id("v1"),
        ];
        let xml = encode_delete_objects(&objects, true).unwrap();
        let xml = String::from_utf8_lossy(&xml).to_string();

        assert!(xml.contains("<Delete"));
        assert!(xml.contains("<Quiet>true</Quiet>"));
        assert!(xml.contains("<Key>a.txt</Key>"));
        assert!(xml.contains("<Key>b.txt</Key>"));
        assert!(xml.contains("<VersionId>v1</VersionId>"));
    }

    #[test]
    fn encodes_bucket_versioning() {
        let cfg = types::BucketVersioningConfiguration {
            status: Some(types::BucketVersioningStatus::Enabled),
            mfa_delete: Some(types::BucketMfaDeleteStatus::Disabled),
        };
        let xml = encode_bucket_versioning(&cfg).unwrap();
        let xml = String::from_utf8_lossy(&xml).to_string();
        assert!(xml.contains("<VersioningConfiguration"));
        assert!(xml.contains("xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\""));
        assert!(xml.contains("<Status>Enabled</Status>"));
        assert!(xml.contains("<MfaDelete>Disabled</MfaDelete>"));
    }

    #[cfg(feature = "multipart")]
    #[test]
    fn encodes_complete_multipart_upload() {
        let parts = vec![
            types::CompletedPart {
                part_number: 1,
                etag: "\"etag1\"".to_string(),
            },
            types::CompletedPart {
                part_number: 2,
                etag: "\"etag2\"".to_string(),
            },
        ];
        let xml = encode_complete_multipart_upload(&parts).unwrap();
        let xml = String::from_utf8_lossy(&xml).to_string();
        assert!(xml.contains("<CompleteMultipartUpload"));
        assert!(xml.contains("<PartNumber>1</PartNumber>"));
        assert!(xml.contains("<ETag>\"etag1\"</ETag>"));
    }
}
