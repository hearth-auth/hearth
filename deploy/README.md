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

### Setup

```bash
# 1. Copy and edit the example config
cp hearth.example.yaml hearth.yaml

# 2. Start the stack
docker compose -f deploy/docker-compose.yml up -d

# 3. Check readiness
curl http://localhost:8420/readyz
# → {"status":"ready","storage":"ok"}
```

Services started by the command above:
- **Hearth** at `http://localhost:8420`. Outbound email is captured by the in-process
  mailcatcher transport and rendered at `http://localhost:8420/dev/mail` — no second container
  is needed for local mail.

**Mailpit is not started by default.** It sits behind a compose profile, so it only starts when
you ask for it:

```bash
docker compose -f deploy/docker-compose.yml --profile mail up -d
```

That adds **Mailpit** (SMTP capture UI) at `http://localhost:8025`. Its SMTP port is reachable
only from inside the compose network, as `mailpit:1025`.

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

Create `deploy/hearth.env`. The compose file loads it automatically when present and starts
without it when absent:

```bash
cp deploy/hearth.env.example deploy/hearth.env   # then edit
```

```bash
# deploy/hearth.env
SMTP_PASSWORD=s3cr3t
```

> **Not the repository-root `.env`.** The compose file used to read `../.env`, and that was
> removed (audit 2026-08-28 §4.8#17). Compose injects **every** key of an `env_file` into the
> container, where `docker inspect` can read it, and Hearth additionally reads `HEARTH_*`
> variables as configuration — so an unrelated key in a developer's root `.env` was both leaked
> into the server process and able to silently override the `hearth.yaml` bind-mounted above.
> `deploy/hearth.env` is gitignored, scoped to this one service, and enforced by
> `scripts/check-compose-env-scope.sh`. Values in it override `hearth.yaml`; the compose file's
> own `environment:` block overrides both.

Reference variables in `hearth.yaml`:

```yaml
email:
  smtp:
    password: "${SMTP_PASSWORD}"
```

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

# 4. Install the config
sudo cp hearth.example.yaml /etc/hearth/hearth.yaml
sudo chown hearth:hearth /etc/hearth/hearth.yaml
sudo chmod 640 /etc/hearth/hearth.yaml

# 5. Install the unit file
sudo cp deploy/systemd/hearth.service /etc/systemd/system/
sudo systemctl daemon-reload

# 6. Enable and start
sudo systemctl enable --now hearth

# 7. Check status
sudo systemctl status hearth
curl http://localhost:8420/readyz
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

Then reload without downtime (Hearth handles `SIGHUP`):

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
- `CapabilityBoundingSet=` — drops all capabilities (port 8420 doesn't need `CAP_NET_BIND_SERVICE`)

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

**Step 1 — Create the namespace**

```bash
kubectl create namespace hearth
```

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
| `config.email.smtp.*` | `smtp.company.com` | Mail server settings |
| `secret.env.SMTP_PASSWORD` | `""` | Inject via ESO or sealed-secrets |

> **Security note:** Do not commit plaintext secret values. Use the
> [External Secrets Operator](https://external-secrets.io/) or
> [sealed-secrets](https://github.com/bitnami-labs/sealed-secrets) to source
> `secret.env` values from your secrets manager.

**Step 3 — Install**

```bash
helm install hearth deploy/helm/hearth \
  -f my-values.yaml \
  --namespace hearth
```

**Step 4 — Bootstrap the first realm and admin token** *(first install only)*

```bash
# Wait for the pod to be ready
kubectl wait --for=condition=ready pod \
  -l app.kubernetes.io/name=hearth \
  -n hearth --timeout=120s

# Forward the admin port temporarily
kubectl port-forward -n hearth svc/hearth 8420:8420 &

# Bootstrap (creates the default realm, admin user, and a bootstrap token)
curl -s -X POST http://127.0.0.1:8420/admin/bootstrap | jq .

# Kill the port-forward when done
kill %1
```

**Step 5 — Verify**

```bash
# OIDC discovery document (requires ingress to be live)
curl https://auth.company.com/.well-known/openid-configuration | jq .issuer
```

### Upgrade

```bash
helm upgrade hearth deploy/helm/hearth -f my-values.yaml --namespace hearth
```

Helm upgrades are rolling (zero-downtime) by default. Because Hearth's
ConfigMap and Secret are checksummed in the pod annotations, any config change
automatically triggers a new rollout.

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
| `secret.tlsCert` | `""` | PEM TLS certificate (pod-level TLS) |
| `secret.tlsKey` | `""` | PEM TLS private key (pod-level TLS) |
| `secret.env` | `{}` | Injected as env vars (e.g. `SMTP_PASSWORD`) |
| `resources.requests.cpu` | `100m` | CPU request |
| `resources.requests.memory` | `128Mi` | Memory request |
| `podDisruptionBudget.enabled` | `false` | Enable PDB |

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
  oidc:
    issuer: "https://auth.example.com"
```

```bash
helm install hearth deploy/helm/hearth -f my-values.yaml -n hearth --create-namespace
```

### Providing secrets

Use `secret.env` to inject credentials referenced from `hearth.yaml`:

```yaml
# my-values.yaml
secret:
  env:
    SMTP_PASSWORD: "s3cr3t"
    SENDGRID_API_KEY: "SG.xxx"

config:
  email:
    transport: smtp
    smtp:
      password: "${SMTP_PASSWORD}"
```

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
