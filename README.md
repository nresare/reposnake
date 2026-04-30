# reposnake

`reposnake` is a small Axum service that stores Python distribution files and exposes a minimal PyPI-compatible package index.

It serves the Simple Repository API from the service root, stores uploaded artifacts on the filesystem, and accepts uploads through a Twine-compatible `/legacy/` endpoint. Uploads are authorized with JWTs.

## Configuration

```toml
bind_address = "0.0.0.0:8080"
storage_directory = "/var/lib/reposnake"
max_upload_bytes = 104857600

[authentication]
audience = "reposnake"
issuer = "https://issuer.example"
algorithm = "RS256"
validation_key = """
-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----
"""

[[publisher]]
name = "ci"
projects = ["example-package", "other_package"]

[publisher.required_claims]
sub = "system:serviceaccount:build:publisher"
repository = "example-package"
```

Project names in `projects` are normalized using the Python packaging rules, so `other_package` and `other-package` refer to the same project. Use `projects = ["*"]` for a publisher policy that can upload any project.

## Installing

Point pip at the Simple API:

```sh
pip install --extra-index-url http://localhost:8080 example-package
```

The root project list is available at `/` and project pages at `/{normalized-project}/`.
Project pages publish package file links as relative basenames, for example `example_package-0.1.0-py3-none-any.whl#sha256=...`.
Those links resolve under the project page URL, while `/simple/...` and `/packages/{normalized-project}/{filename}` remain available as compatibility aliases.

## Uploading

Twine can upload to the legacy endpoint with the JWT as the password:

```sh
twine upload \
  --repository-url http://localhost:8080/legacy/ \
  --username __token__ \
  --password "$UPLOAD_JWT" \
  dist/*
```

Direct clients may also send the JWT as a bearer token:

```sh
curl -X POST \
  -H "Authorization: Bearer $UPLOAD_JWT" \
  -F ':action=file_upload' \
  -F 'protocol_version=1' \
  -F 'filetype=sdist' \
  -F 'pyversion=source' \
  -F 'metadata_version=2.4' \
  -F 'name=example-package' \
  -F 'version=0.1.0' \
  -F "sha256_digest=$(shasum -a 256 dist/example-package-0.1.0.tar.gz | awk '{print $1}')" \
  -F 'content=@dist/example-package-0.1.0.tar.gz' \
  http://localhost:8080/legacy/
```

For local testing, authentication and publisher policy checks can be bypassed:

```sh
cargo run -- --config-file reposnake.toml.example --disable-auth
```

Use `--debug` to log detailed upload and authorization flow steps.

## License

MIT
