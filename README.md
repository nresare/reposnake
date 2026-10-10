# reposnake

`reposnake` is a small Axum service that stores Python distribution files and OCI container images.

It serves the Python Simple Repository API from the service root, stores uploaded artifacts on the filesystem, and accepts Python uploads through a Twine-compatible POST to `/`. It also exposes an OCI Distribution-compatible registry under `/v2/`. Uploads and OCI pushes are authorized with JWTs; Python downloads and OCI pulls are public.

## Configuration

```toml
bind-address = "0.0.0.0:8080"
origin = "http://localhost:8080"
max-upload-bytes = 104857600

[object-store]
directory = "/data"

# Optional. For S3, credentials come from the ambient AWS provider chain,
# such as AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, AWS_WEB_IDENTITY_TOKEN_FILE,
# ECS/EC2 metadata, or IRSA. Set AWS_REGION in the environment.
# backend = "s3"
# bucket = "reposnake-packages"
# directory = "/data" # Optional migration source for existing filesystem objects.

# Optional. Caches small objects read from S3.
# [cache]
# enabled = true
# directory = "/var/lib/reposnake-cache"
# max-file-size = "200KiB"
# max-total-size = "1GiB"

[metadata-store]
uri = "mem://"

# Optional. Store package metadata as JSON files instead of using SurrealDB.
# backend = "filesystem"
# directory = "/data/metadata"

# For a SurrealDB server:
# uri = "ws://localhost:8000/"
# username = "reposnake"
# password-file = "/run/secrets/surrealdb-password"
#
# Or authenticate to SurrealDB through idmouse:
# [metadata-store.idmouse]
# url = "http://idmouse.example/token"
# token-path = "/run/secrets/idmouse-bearer-token"

[[role]]
name = "kubernetes"
audience = "reposnake"
issuer = "https://issuer.example"

# Optional. If omitted, reposnake fetches
# <issuer>/.well-known/openid-configuration and uses the returned jwks_uri.
validation-key = """
-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----
"""

[role.claims]
sub = "system:serviceaccount:build:publisher"
repository = "example-package"

[[publisher]]
name = "ci"
projects = ["example-package", "other_package"]
role = "kubernetes"
```

An IPv4-any or IPv4-loopback `bind-address`, such as `0.0.0.0:8080` or `127.0.0.1:8080`, listens on both IPv4 and IPv6 when IPv6 is available.

Project names in `projects` are normalized using the Python packaging rules for Python uploads, so `other_package` and `other-package` refer to the same project. The same list may also contain OCI repository names such as `team/image`. Use `projects = ["*"]` for a publisher policy that can upload any Python project or push any OCI repository.

To serve HTTPS, configure both PEM paths. Relative paths resolve from the configuration
file's directory. TLS advertises HTTP/2 and HTTP/1.1 through ALPN:

```toml
tls-cert-path = "tls/cert.pem"
tls-key-path = "tls/key.pem"
```

The default bind address is `0.0.0.0:8443` with TLS and `0.0.0.0:8080` otherwise.
An explicit `bind-address` overrides either default. Invalid, incomplete, or mismatched
certificate/key settings cause startup to fail before connecting to storage.

## Cluster deployment

Commits to `main` use `.buildkite/pipelinegen.toml` to test, publish a container image,
and notify relcoord. Relcoord reads `.deploy` from that same commit, generates
manifests using the website plugin from system, and pushes them to the configured
manifest repository for Argo CD to reconcile. The image comes from the build;
`.deploy` deliberately does not pin an image tag.

The cluster configuration retains two replicas, the existing S3 bucket and endpoint,
SurrealDB/idmouse settings, and projected token audiences. The website plugin creates
a cluster-local certificate mounted at `/tls`, HTTPS probes, a Service on port 443
forwarding to port 8443, and a BackendTLSPolicy that verifies the certificate against
the `cluster-local-ca` ConfigMap. The namespace's `trust: cluster-local` label makes
trust-manager install that CA bundle.

For the handoff from system:

1. Keep the existing `reposnake/` manifests in the fruktsallad output repository
   throughout the switchover. Removing `reposnake` from `owners/system.toml` is
   preparation; it does not confirm that Argo CD has adopted the new deployment.
2. Merge the reposnake changes and let its main-branch Buildkite deployment complete.
   Confirm `owners/reposnake.toml` contains `owned = "reposnake"`, the generated
   image is the one from this build, and Argo CD has synced the workload and reports
   it healthy. Verify HTTPS traffic to `https://repo.noa.re` succeeds.
3. Only then merge the system cleanup that removes its `repo.noa.re` website block
   and `reposnake/reposnake.toml`. Future reposnake commits deploy through the same
   Buildkite/relcoord pipeline.

Avoid system deployments during the handoff. Before reposnake claims the namespace,
system's old website block can reclaim it; afterwards, that block conflicts with
reposnake ownership and generation fails without pushing manifests. The cleanup
removes that conflict. Infrastructure such as the website plugin, CA, and idmouse
token policy remains in system.

## Installing

Point pip at the Simple API:

```sh
pip install --extra-index-url http://localhost:8080 example-package
```

The root project list is available at `/` and project pages at `/{normalized-project}/`.
Project pages publish package file links as relative basenames, for example `example_package-0.1.0-py3-none-any.whl#sha256=...`.
Those links resolve under the project page URL.

## Uploading

Twine can upload to the top-level endpoint with the JWT as the password:

```sh
twine upload \
  --repository-url http://localhost:8080/ \
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
  http://localhost:8080/
```

## OCI Containers

The OCI registry API is available at `/v2/`. Pulls are public:

```sh
docker pull localhost:8080/team/image:latest
```

Pushes use the same JWT mechanism as Python uploads. Docker-compatible clients can pass the JWT as the registry password:

```sh
echo "$UPLOAD_JWT" | docker login localhost:8080 --username __token__ --password-stdin
docker tag team/image:latest localhost:8080/team/image:latest
docker push localhost:8080/team/image:latest
```

Direct clients may also use bearer authentication when creating blob uploads and writing manifests under `/v2/{repository}/...`.
When a Docker-compatible client starts a push without credentials, reposnake returns a Bearer
challenge pointing at `/v2/token`. The token endpoint validates the JWT supplied through Basic
or Bearer authentication and returns that same JWT as the registry bearer token.

For local testing, authentication and publisher role checks can be bypassed:

```sh
cargo run -- --config-file reposnake.toml.example --disable-auth
```

Use `--debug` to log detailed upload and authorization flow steps.

## Build Features

The `s3` and `surrealdb` Cargo features are enabled by default. Disable default
features for a lean filesystem-only build:

```sh
cargo build --no-default-features
```

In that build, omit S3 configuration and use filesystem metadata:

```toml
[metadata-store]
backend = "filesystem"
directory = "/data/metadata"
```

## License

MIT
