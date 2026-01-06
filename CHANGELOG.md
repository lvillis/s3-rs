## [0.1.2] - 2026-01-06

### 🐛 Bug Fixes

- *(ci)* Make async streaming PUT sized and skip unsupported bucket config ops
- Add Content-MD5 for bucket config PUT requests

### 🧪 Testing

- Harden MinIO integration suite
- *(ci)* Skip unsupported bucket config ops in MinIO integration

### ⚙️ Miscellaneous Tasks

- *(bench)* Add criterion microbench suite
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
