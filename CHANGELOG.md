## [0.1.7] - 2026-01-12

### 🚀 Features

- *(providers)* Add typed R2 endpoints with jurisdiction support
## [0.1.6] - 2026-01-08

### ⚙️ Miscellaneous Tasks

- *(docs)* Expand rustdoc coverage and stabilize all-features tests
- Release s3 version 0.1.6
## [0.1.5] - 2026-01-06

### 🧪 Testing

- *(store)* Rename and stabilize s3_compat integration tests
- *(store)* Make s3_compat tests strictness configurable

### ⚙️ Miscellaneous Tasks

- Add rustfs integration tests
- Release s3 version 0.1.5
## [0.1.4] - 2026-01-06

### 🧪 Testing

- Fix MinIO virtual-hosted integration by creating buckets via path-style

### ⚙️ Miscellaneous Tasks

- *(ci)* Update ci.yaml
- *(ci)* Set MINIO_DOMAIN for vhost tests
- Release s3 version 0.1.4
## [0.1.3] - 2026-01-06

### 🚀 Features

- *(providers)* Add rule-based presets and AwsRegion helpers
- *(auth)* Add credential providers with cached auto-refresh

### 🧪 Testing

- Expand coverage for cached credentials, transport, and MinIO vhost

### ⚙️ Miscellaneous Tasks

- *(examples)* Add practical async/blocking usage examples
- *(ci)* Update
- *(examples)* Add more runnable usage guides
- Release s3 version 0.1.3
## [0.1.2] - 2026-01-06

### 🐛 Bug Fixes

- *(ci)* Make async streaming PUT sized and skip unsupported bucket config ops
- Add Content-MD5 for bucket config PUT requests

### 🧪 Testing

- Harden MinIO integration suite
- *(ci)* Skip unsupported bucket config ops in MinIO integration

### ⚙️ Miscellaneous Tasks

- *(bench)* Add criterion microbench suite
- Release s3 version 0.1.2
## [0.1.1] - 2026-01-05

### 🐛 Bug Fixes

- Ci
- *(ci)* Add Content-MD5 for DeleteObjects and make multipart test S3-compliant
- *(blocking)* Treat non-2xx responses as API errors

### 🚜 Refactor

- Harden blocking retries, add native-tls CI, and dedupe api helpers

### ⚙️ Miscellaneous Tasks

- Init commit
- Update Cargo.toml
- Release s3 version 0.1.1
