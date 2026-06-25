# TLS — Examples 23–24

`hearth.yaml` snippets for TLS termination and mutual TLS (mTLS).
Return to the [example index](./index.md) for a full list of all examples.

Hearth can terminate TLS itself using a PEM certificate and key. When `tls_cert_path` is set,
Hearth automatically starts an HTTP→HTTPS redirect listener on `port - 1` (or port 80 when
`port: 443`). Send `SIGHUP` to hot-reload the certificate without restarting the process.

For deployments that already terminate TLS at a load balancer or ingress, leave these fields
absent and configure `server.trusted_proxies` + `server.trust_forwarded_proto` instead.

---

## Example 23 — HTTPS / TLS termination

**Audience:** operators running Hearth directly on the internet without a separate TLS-terminating
reverse proxy.

```yaml
server:
  bind_address: "0.0.0.0"
  port: 443
  tls_cert_path: "/etc/hearth/tls/server.crt"
  tls_key_path:  "/etc/hearth/tls/server.key"

storage:
  data_dir: "/var/lib/hearth/data"
  fsync: true

oidc:
  issuer: "https://auth.example.com"
```

- Both `tls_cert_path` and `tls_key_path` must be set together; specifying only one is a config
  error.
- With `port: 443`, the redirect listener binds to port 80 automatically.
- `SIGHUP` triggers a hot-reload: Hearth re-reads the certificate and key files without
  dropping existing connections. Use this with ACME/certbot hooks to rotate certificates.
- Use PEM format (the concatenated certificate chain, not just the leaf certificate).

---

## Example 24 — Mutual TLS (mTLS)

**Audience:** operators building machine-to-machine (M2M) APIs or zero-trust service meshes where
clients must present a certificate signed by a known CA.

```yaml
server:
  bind_address: "0.0.0.0"
  port: 8420
  tls_cert_path:            "/etc/hearth/tls/server.crt"
  tls_key_path:             "/etc/hearth/tls/server.key"
  tls_client_ca_path:       "/etc/hearth/tls/client-ca.crt"
  tls_require_client_cert:  true

storage:
  data_dir: "/var/lib/hearth/data"
  fsync: true

oidc:
  issuer: "https://auth.example.com"
```

- `tls_client_ca_path` sets the CA that signs client certificates. Hearth verifies the client
  certificate against this CA on every TLS handshake.
- `tls_require_client_cert: true` makes a missing or invalid client certificate a hard TLS
  rejection (no 401 response — the connection is dropped at the transport layer).
- `tls_require_client_cert: false` (default) with `tls_client_ca_path` set puts Hearth in
  *optional client cert* mode — the certificate is verified if presented but not required.
- The client CA file may contain multiple PEM-encoded certificates for CA rotation.

---
