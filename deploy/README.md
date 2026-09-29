# Hearth — Deployment Guide

This directory contains ready-to-use deployment artifacts for three environments:

| Method | Directory | Best for |
|---|---|---|
| Docker Compose | `docker-compose.yml` | Single-host / staging |
| systemd | `systemd/hearth.service` | VM / bare-metal |
| Helm | `helm/hearth/` | Kubernetes |

---

## Prerequisites

All methods share the same binary. Download from [GitHub Releases](https://github.com/hearth-auth/hearth/releases) or use the Docker image:

```
ghcr.io/hearth-auth/hearth:latest
```

> **Known gap — the container image is not anonymously pullable today.** Re-checked 2026-09-21:
> an unauthenticated manifest fetch for `ghcr.io/hearth-auth/hearth` (any tag) and for the Helm
> chart package `ghcr.io/hearth-auth/charts/hearth` returns **401**. The GitHub repository and
> its Releases are public; the two GHCR packages are not. Until they are flipped to public, every
> `docker pull`, `docker compose up` and `helm install` in this guide fails at the first command
> for an anonymous user.
>
> **What to do instead:** `docker login ghcr.io` with a personal access token carrying
> `read:packages`, or download the release binary from GitHub Releases and use the systemd path
> below. Tracked as remediation task 3.4; release validation now gates on an anonymous fetch, so
> versions published after that gate landed will be public.

---

## Docker Compose (single-host / staging)

The container runs `hearth serve` in **production mode**. `--dev` cannot be used here: dev mode
refuses to listen on anything but loopback, and a published container port needs the server on
`0.0.0.0` (the compose file passes `--bind 0.0.0.0` for that). For local development without
Docker, use `make dev`.

### Setup

```bash
# 1. Copy and edit the example config. Production start-up requires:
#    - an HTTPS posture: server.tls_cert_path + tls_key_path, OR
#      server.trust_forwarded_proto: true with server.trusted_proxies listing
#      your reverse proxy's IP(s) or CIDR range(s);
#    - oidc.issuer set to the public https:// URL;
#    - a real email.transport (smtp, sendgrid, …), or
#      email.allow_log_transport_in_production: true to evaluate with every
#      email dropped to the log.
cp hearth.example.yaml hearth.yaml

# 2. Create the environment file with the two required keys
cp deploy/hearth.env.example deploy/hearth.env
chmod 600 deploy/hearth.env
#    then set HEARTH_MASTER_KEY and HEARTH_KEK (openssl rand -hex 32 each)

# 3. Check the config the way start-up will
docker compose -f deploy/docker-compose.yml run --rm hearth config validate /etc/hearth/hearth.yaml

# 4. Start the stack
docker compose -f deploy/docker-compose.yml up -d

# 5. Check readiness (https:// and -k with direct TLS)
curl http://localhost:8420/readyz
# → {"status":"ready","storage":"ok"}
```

Back up `HEARTH_MASTER_KEY` and `HEARTH_KEK` outside the host. Without the master key the data
in the `hearth_data` volume cannot be read.

The image healthcheck probes `HEARTH_HEALTHCHECK_URL` (default
`http://127.0.0.1:8420/readyz`). With direct TLS, set
`HEARTH_HEALTHCHECK_URL=https://127.0.0.1:8420/readyz` in `deploy/hearth.env`; the probe skips
certificate verification because it targets loopback.

**Mailpit is not started by default.** It sits behind a compose profile, so it only starts when
you ask for it:

```bash
docker compose -f deploy/docker-compose.yml --profile mail up -d
```

That adds **Mailpit** (SMTP capture UI) at `http://localhost:8025`. Its SMTP port is reachable
only from inside the compose network, as `mailpit:1025` — point `email.smtp.host` / `port` at it
to capture Hearth's mail there.

### Configuration

Edit `hearth.yaml` in the project root and restart:

```bash
docker compose -f deploy/docker-compose.yml restart hearth
```

### Persistent data

All data is stored in a Docker named volume (`hearth_data`). To wipe and start fresh:

```bash
docker compose -f deploy/docker-compose.yml down -v
```

### Environment variables

`deploy/hearth.env` is **required** — `docker compose up` fails without it, because production
mode cannot start without `HEARTH_MASTER_KEY` and `HEARTH_KEK`:

```bash
cp deploy/hearth.env.example deploy/hearth.env   # then edit
```

```bash
# deploy/hearth.env
HEARTH_MASTER_KEY=<64 hex chars>
HEARTH_KEK=<64 hex chars>
HEARTH_SMTP_PASSWORD=s3cr3t
```

There is **no generic "environment overrides `hearth.yaml`" mechanism.** A variable reaches Hearth
in one of two ways only:

1. It is one of the few variables the server reads directly: `HEARTH_MASTER_KEY`, `HEARTH_KEK`,
   `HEARTH_PREVIOUS_MASTER_KEY`, `HEARTH_SMS_OTP_HMAC_KEY`, `HEARTH_TURNSTILE_SECRET_KEY`,
   `HEARTH_MAILCATCHER_PASSWORD`, `RUST_LOG` (plus the dev-only `HEARTH_DEV_DATA_DIR`).
2. `hearth.yaml` references it with `${VAR}` substitution. In production an unset or empty
   `${VAR}` is a hard start-up error.

```yaml
email:
  smtp:
    password: "${HEARTH_SMTP_PASSWORD}"
```

Everything else is ignored. The bind address and port belong in `hearth.yaml` or on the command
line (`--bind`, `--port`); the compose file passes `--bind 0.0.0.0`. An earlier revision set
`HEARTH_BIND_ADDRESS`, which the server never read.

> **Not the repository-root `.env`.** The compose file used to read `../.env`, and that was
> removed (audit 2026-08-28 §4.8#17). Compose injects **every** key of an `env_file` into the
> container, where `docker inspect` can read it, and Hearth reads the variables listed above plus
> any `${VAR}` that `hearth.yaml` names — so an unrelated key in a developer's root `.env` was
> both leaked into the server process and able to change what the server ran.
> `deploy/hearth.env` is gitignored, scoped to this one service, and enforced by
> `scripts/check-compose-env-scope.sh`. The compose file's own `environment:` block wins over it
> for the same key.

---

## systemd (VM / bare-metal)

### Installation

```bash
# 1. Install the binary
sudo install -m 755 hearth /usr/local/bin/hearth

# 2. Create the hearth user
sudo useradd --system --no-create-home --shell /usr/sbin/nologin hearth

# 3. Create directories
sudo mkdir -p /var/lib/hearth /etc/hearth
sudo chown -R hearth:hearth /var/lib/hearth /etc/hearth

# 4. Install the config, then edit it: production start-up needs an HTTPS
#    posture (see TLS below, or trust_forwarded_proto + trusted_proxies behind
#    a proxy), oidc.issuer, and a real email.transport.
sudo cp hearth.example.yaml /etc/hearth/hearth.yaml
sudo chown hearth:hearth /etc/hearth/hearth.yaml
sudo chmod 640 /etc/hearth/hearth.yaml

# 5. Create the environment file the unit reads (EnvironmentFile=). Root-owned
#    0400: systemd reads it before dropping to the hearth user. Back both keys
#    up off the host — without the master key the data cannot be read.
sudo install -m 0400 -o root -g root /dev/null /etc/hearth/hearth.env
printf 'HEARTH_MASTER_KEY=%s\nHEARTH_KEK=%s\n' \
  "$(openssl rand -hex 32)" "$(openssl rand -hex 32)" | sudo tee /etc/hearth/hearth.env >/dev/null
#    Add any ${VAR} hearth.yaml references (e.g. HEARTH_SMTP_PASSWORD=...) here too.

# 6. Validate the config the way start-up will
sudo sh -c 'set -a; . /etc/hearth/hearth.env; exec hearth config validate /etc/hearth/hearth.yaml'

# 7. Install the unit file
sudo cp deploy/systemd/hearth.service /etc/systemd/system/
sudo systemctl daemon-reload

# 8. Enable and start
sudo systemctl enable --now hearth

# 9. Check status
sudo systemctl status hearth
curl http://localhost:8420/readyz        # https:// and -k with direct TLS
```

### Logs

```bash
sudo journalctl -u hearth -f
```

### TLS

Enable TLS in `/etc/hearth/hearth.yaml`:

```yaml
server:
  tls_cert_path: /etc/hearth/tls/server.crt
  tls_key_path:  /etc/hearth/tls/server.key
```

With TLS on, Hearth also opens a plaintext HTTP→HTTPS redirect listener on `port - 1` (8419 for
the default 8420), or on port 80 when `port: 443`. The unit grants `CAP_NET_BIND_SERVICE` so the
443 + 80 pair can bind as the unprivileged `hearth` user.

Turning TLS on or off needs a restart (`sudo systemctl restart hearth`). Renewed certificate
files are picked up without downtime (Hearth handles `SIGHUP`):

```bash
sudo systemctl kill --signal=SIGHUP hearth
```

### Security hardening

The unit file ships with these restrictions enabled by default:

- `NoNewPrivileges` — prevents privilege escalation via setuid
- `ProtectSystem=strict` — mounts `/usr`, `/boot`, `/etc` read-only
- `ProtectHome=true` — hides `/home` and `/root`
- `PrivateTmp=true` — isolated `/tmp`
- `PrivateDevices=true` — no raw device access
- `MemoryDenyWriteExecute=true` — enforces W^X
- `SystemCallFilter=@system-service` — restricts available syscalls
- `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` — every capability dropped except binding ports
  below 1024 (needed for `port: 443` and its port-80 redirect; empty it if you never use one)
- `LimitNPROC=4096` — the limit counts threads, and Tokio's blocking pool alone may use 512

---

## Helm (Kubernetes)

### Prerequisites

- Kubernetes ≥ 1.24
- Helm ≥ 3.10
- A default `StorageClass` (for the PVC)
- `cert-manager` (optional, recommended for TLS via Let's Encrypt)
- `nginx-ingress-controller` (optional, recommended for Ingress)

### End-to-end production install

The chart ships a ready-to-use production profile at
`deploy/helm/hearth/values-prod.yaml`. Follow these steps to go from zero to a
running identity server with TLS.

The chart always runs `hearth serve` in production mode. The default `values.yaml` alone does
**not** start: it picks no HTTPS posture and sets no `oidc.issuer`, so the server refuses to run
until you choose them. `values-prod.yaml` is the complete, working profile.

**Step 1 — Create the namespace and the Secrets**

```bash
kubectl create namespace hearth

# Encryption keys (required). The chart reads them from this Secret and never
# generates them — a regenerated master key makes the PVC's data unreadable.
# Back both values up outside the cluster.
kubectl -n hearth create secret generic hearth-keys \
  --from-literal=HEARTH_MASTER_KEY="$(openssl rand -hex 32)" \
  --from-literal=HEARTH_KEK="$(openssl rand -hex 32)"

# SMTP password, referenced as ${SMTP_PASSWORD} by values-prod.yaml.
kubectl -n hearth create secret generic hearth-smtp \
  --from-literal=password='<smtp password>'
```

Until `hearth-keys` exists the pod waits in `CreateContainerConfigError`.

**Step 2 — Edit the production values**

```bash
cp deploy/helm/hearth/values-prod.yaml my-values.yaml
```

Open `my-values.yaml` and replace the placeholders:

| Field | Example | Notes |
|---|---|---|
| `ingress.hosts[0].host` | `auth.company.com` | Your public domain |
| `ingress.tls[0].hosts[0]` | `auth.company.com` | Must match the host |
| `config.oidc.issuer` | `https://auth.company.com` | Returned in OIDC discovery |
| `config.server.trusted_proxies` | `["10.42.3.0/24"]` | **Required.** The IP(s) or CIDR range(s) your Ingress controller connects to the pod from. Use the narrowest range that holds the controller pods — every host in it is trusted to set `X-Forwarded-For`. Host bits in a range (`10.42.3.7/24`), ranges broader than `/8` (IPv4) or `/16` (IPv6), and catch-alls are refused. The shipped placeholder makes the server refuse to start. |
| `config.email.smtp.*` | `smtp.company.com` | Mail server settings |
| `extraEnv` | `hearth-smtp` / `password` | Secret holding the SMTP password |

> **Keep `trusted_proxies` current.** Ingress-controller pod IPs change when the pods are
> rescheduled. With a stale list Hearth ignores `X-Forwarded-For`, every client appears to come
> from the controller, and per-IP rate limits (login lockout included) hit all users at once.
> List a CIDR range covering the addresses the controller pods can be given (for example a
> dedicated ingress node pool's pod CIDR), or give the controller stable addresses
> (`hostNetwork`, or static pod IPs from your CNI).
>
> **Direct TLS instead:** set `tls.enabled: true` and `tls.existingSecret` (a `kubernetes.io/tls`
> Secret), drop `trust_forwarded_proto`, and add the ingress annotation
> `nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"`. The chart then points
> `server.tls_cert_path` / `tls_key_path` at the mounted certificate and switches the liveness
> and readiness probes to HTTPS.

> **Security note:** Do not commit plaintext secret values. Use the
> [External Secrets Operator](https://external-secrets.io/) or
> [sealed-secrets](https://github.com/bitnami-labs/sealed-secrets) to maintain the Secrets above
> from your secrets manager.

**Step 3 — Install**

```bash
helm install hearth deploy/helm/hearth \
  -f my-values.yaml \
  --namespace hearth
```

**Step 4 — Create the first admin** *(first install only)*

`/admin/bootstrap` is a dev-only endpoint and is not compiled into the published image. On a
fresh data directory Hearth instead writes a one-time setup token to `<data_dir>/.setup_token`
and logs the setup URL (without the token):

```bash
# Wait for the pod to be ready
kubectl wait --for=condition=ready pod \
  -l app.kubernetes.io/name=hearth \
  -n hearth --timeout=120s

# Read the one-time setup token
kubectl -n hearth exec deploy/hearth -- cat /var/lib/hearth/.setup_token
```

Open `https://auth.company.com/ui/setup?token=<token>` and create the first administrator.

**Step 5 — Verify**

```bash
# OIDC discovery document (requires ingress to be live)
curl https://auth.company.com/.well-known/openid-configuration | jq .issuer
```

### Upgrade

```bash
helm upgrade hearth deploy/helm/hearth -f my-values.yaml --namespace hearth
```

Upgrades are **not** zero-downtime. The Deployment uses `strategy: Recreate`, because a second
pod cannot open the locked data directory: the old pod stops before the new one starts. Because
Hearth's ConfigMap and chart-managed Secret are checksummed in the pod annotations, any change to
them triggers a new rollout (with the same short outage). Secrets you manage yourself
(`hearth-keys`, `hearth-smtp`) are not checksummed — restart the pod after changing them.

The `podDisruptionBudget` defaults to `maxUnavailable: 1`, so `kubectl drain` can evict the single
pod. The chart refuses to render a `minAvailable` at or above `replicaCount`, which would block
every drain forever.

### Values reference

| Key | Default | Description |
|---|---|---|
| `image.repository` | `ghcr.io/hearth-auth/hearth` | Image repository |
| `image.tag` | Chart `appVersion` | Image tag |
| `replicaCount` | `1` | Pod count (see note on stateful scaling) |
| `persistence.enabled` | `true` | Enable PVC for data |
| `persistence.size` | `10Gi` | PVC size |
| `persistence.storageClassName` | `""` (cluster default) | StorageClass name |
| `ingress.enabled` | `false` | Create Ingress |
| `ingress.className` | `""` | IngressClass name |
| `config.*` | see `values.yaml` | Hearth YAML config |
| `encryptionKeys.enabled` | `true` | Inject `HEARTH_MASTER_KEY` / `HEARTH_KEK` from a Secret |
| `encryptionKeys.existingSecret` | `""` (→ `<fullname>-keys`) | Secret holding both keys |
| `encryptionKeys.masterKeySecretKey` / `kekSecretKey` | `HEARTH_MASTER_KEY` / `HEARTH_KEK` | Key names inside that Secret |
| `tls.enabled` | `false` | Terminate TLS in the pod; probes switch to HTTPS |
| `tls.existingSecret` | `""` | `kubernetes.io/tls` Secret to mount at `/etc/hearth/tls/` |
| `secret.tlsCert` | `""` | Inline PEM TLS certificate (pod-level TLS; prefer `tls.existingSecret`) |
| `secret.tlsKey` | `""` | Inline PEM TLS private key |
| `secret.env` | `{}` | Chart-managed Secret, injected as env vars |
| `extraEnv` | `[]` | Extra `EnvVar` objects, e.g. `valueFrom.secretKeyRef` to your own Secrets |
| `env` | `RUST_LOG: info` | Plain env vars |
| `resources.requests.cpu` | `100m` | CPU request |
| `resources.requests.memory` | `128Mi` | Memory request |
| `podDisruptionBudget.enabled` | `false` | Enable PDB |
| `podDisruptionBudget.maxUnavailable` | `1` | Never blocks a drain; `minAvailable` ≥ `replicaCount` is refused |

Full reference: [`helm/hearth/values.yaml`](helm/hearth/values.yaml).  
Production profile: [`helm/hearth/values-prod.yaml`](helm/hearth/values-prod.yaml).

### Exposing with cert-manager

The production profile already includes the cert-manager annotations. If you
are configuring from scratch:

```yaml
# my-values.yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: auth.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: hearth-tls
      hosts:
        - auth.example.com

config:
  server:
    bind_address: "0.0.0.0"
    port: 8420
    trust_forwarded_proto: true
    trusted_proxies:
      - "10.42.3.0/24"     # your Ingress controller's IP(s) or CIDR range(s)
  oidc:
    issuer: "https://auth.example.com"
  email:
    transport: smtp        # plus from/smtp settings — see values-prod.yaml
```

```bash
# Create the hearth-keys Secret first (Step 1 above), then:
helm install hearth deploy/helm/hearth -f my-values.yaml -n hearth
```

### Providing secrets

Reference Secrets you manage with `extraEnv`, then use the variable from `config` with `${VAR}`
substitution (an unset or empty `${VAR}` is a hard start-up error in production):

```yaml
# my-values.yaml
extraEnv:
  - name: SMTP_PASSWORD
    valueFrom:
      secretKeyRef:
        name: hearth-smtp
        key: password

config:
  email:
    transport: smtp
    smtp:
      password: "${SMTP_PASSWORD}"
```

`secret.env` still works — the chart creates a Secret from the literal values — but the values
then live in your values file and in Helm's release history, so prefer `extraEnv` for anything
real.

### Scaling note

Hearth uses an embedded storage engine (WAL + SSTs on a PVC). Multiple replicas
sharing a `ReadWriteOnce` volume is not supported. For high availability, use
`ReadWriteMany` storage or a remote backend (roadmap item).

> **There is no `autoscaling` value and no HorizontalPodAutoscaler template.** An earlier
> revision of this guide documented `autoscaling.enabled`; the key does not appear anywhere in
> `deploy/helm/hearth/`, so setting it has no effect and produces no error. Horizontal
> autoscaling would be wrong for this chart in any case — the storage engine is a single-writer
> WAL on one PVC, so scaling replicas is not a supported operation, automatic or manual.

> **Note on StatefulSet vs Deployment:** The chart currently uses `Deployment +
> PVC`. Because the WAL is single-writer and `fsync`-bound, switching to
> `StatefulSet` would be more correct for HA (one pod ↔ one WAL volume). This
> is tracked as a future opt-in via a `controller.kind` value — see the
> discussion on the parent epic.

### Linting and snapshot tests

Two Makefile targets validate the chart locally:

```bash
# Lint the chart (runs helm lint)
make helm-lint

# Diff rendered templates against committed snapshots
make helm-template

# Update snapshots after intentional chart changes
make helm-template UPDATE=1
```

Snapshots live at `deploy/helm/hearth/tests/` and are CI-gated by
`.github/workflows/helm.yml`.

### Uninstall

```bash
helm uninstall hearth -n hearth
# The PVC is NOT deleted by default — delete it manually if you want to wipe data:
kubectl delete pvc -n hearth -l app.kubernetes.io/name=hearth
```

---

## Configuration reference

All three deployment methods consume the same `hearth.yaml` format. See [`hearth.example.yaml`](../hearth.example.yaml) for the full annotated reference, or run:

```bash
hearth config --help
```
