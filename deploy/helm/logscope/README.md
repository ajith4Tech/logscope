# Logscope Helm chart

You configure one file (`values.yaml`) and run standard Helm commands. There
are no deployment scripts.

## Architecture and data flow

```
 k3s node(s)                                                 outside k3s
┌──────────────────────────────────────────────────┐
│ container logs (/var/log/pods)                   │
│        │                                         │
│        ▼                                         │
│ Vector DaemonSet ── classify (VRL) ──────────────┼──► AWS S3 bucket
│  ▲  severity buckets, infra vs namespace,        │    <keyPrefix>/<bucket>/YYYY/MM/DD/…gz
│  │  Falco JSON → scope "security"                │    (+ security/<bucket>/… for Falco)
│  │                                               │         │
│ Falco DaemonSet ── JSON alerts on stdout         │         │ poll every 30s (read-only)
│  (kernel events → rules)                         │         ▼
│                                                  │
│ Logscope web app (Deployment, 1 pod) ◄───────────┼──── List/GetObject
│  SQLite cache + anomaly state on PVC             │
│  UI/API :8000 ── ClusterIP Service               │──► AI provider (optional, HTTPS):
│        ▲                                         │    Anthropic · Gemini · OpenAI · OpenRouter
│ kubectl port-forward / optional Ingress          │
└──────────────────────────────────────────────────┘
```

| Component | Responsibility | Where it runs | Managed by this chart |
|---|---|---|---|
| **Falco** | Detects runtime security events and prints them as JSON to stdout | k3s (privileged DaemonSet) | Optional: `falco.enabled` (official chart 9.1.0, vendored). Default: use the existing install |
| **Vector** | Tails all pod logs, classifies severity and scope, writes gzip objects to S3. Falco events are recognised by namespace and written twice: to their severity prefix and to `security/` | k3s (DaemonSet) | Optional: `vector.enabled`. Default: use the existing install (`scripts/render.py` + `vector/vector`) |
| **S3** | Durable log store. Its lifecycle rule is the retention policy | External (AWS) | No. Bucket, IAM and lifecycle rule are prerequisites |
| **Logscope web app** | Polls S3, caches in SQLite, serves the UI/API, detects anomalies, requests AI summaries | k3s (Deployment + PVC) | Always |
| **AI provider** | Summarises anomalies and explains logs on request. It receives log samples | External API | No. Configured via `ai.*` |

Logscope needs no database, Redis, or other in-cluster services.

## Prerequisites (manual)

1. **S3 bucket** in your region.
   - Apply the retention lifecycle rule once:
     `python3 scripts/apply_s3_lifecycle.py` (uses `config.yaml`). Helm
     doesn't manage bucket properties.
   - Create two IAM identities: **write** for Vector (`s3:PutObject`,
     `s3:AbortMultipartUpload` on `<bucket>/<prefix>/*`) and **read-only** for
     the web app:
     ```json
     {"Version": "2012-10-17", "Statement": [
       {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::<BUCKET>",
        "Condition": {"StringLike": {"s3:prefix": ["k3s-logs/*"]}}},
       {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::<BUCKET>/k3s-logs/*"}]}
     ```
2. **Namespaces.**
   - The release namespace (Vector's existing install uses `logging`) should
     carry `vector.dev/exclude=true` (`kubectl apply -f deploy/namespace.yaml`).
   - For chart-managed Falco, create the Falco namespace first
     (`kubectl create namespace falco`). It must **not** carry that label.
3. **Outbound HTTPS (443) and DNS** from the cluster to
   `s3.<region>.amazonaws.com`, and to the AI provider if used.
4. **A default StorageClass**, or set `persistence.storageClass`.
5. **The web app image**: see [Image](#image).

## Existing vs Helm-managed Falco/Vector

| Situation | Values | Notes |
|---|---|---|
| **Existing Vector + Falco (current cluster)** | `vector.enabled: false`, `falco.enabled: false` (defaults) | Installs only the web app. Keep `logscope.*` and `s3.*` identical to the `config.yaml` your Vector was rendered from |
| Chart-managed Vector | `vector.enabled: true` + `s3.credentials.vector` | First run `helm -n logging uninstall vector`, otherwise the install refuses because it detects DaemonSet `vector`. `vector.dataDir` keeps `/var/lib/vector`, so read checkpoints continue and nothing is re-shipped. Logs are not collected between the uninstall and the new DaemonSet starting (old checkpoints are reused) |
| Chart-managed Falco | `falco.enabled: true` | First run `helm -n falco uninstall falco`, otherwise the install refuses because it detects DaemonSet `falco`. Every key under `falco:` goes to the official chart (driver, rules, resources) |
| Existing Falco, no Vector integration | `logscope.falco.enabled: false` | Falco pod logs are then classified like any other namespace |

The file-sink mode (node-local log files plus the backup CronJob) remains
available through `scripts/render.py`. The chart supports the S3 pipeline only.

## Configuration

Copy only what you change into `values.local.yaml`, which is gitignored:

```bash
install -m 600 /dev/null deploy/helm/logscope/values.local.yaml
$EDITOR deploy/helm/logscope/values.local.yaml
```

Minimal, with the existing Vector and Falco installs:

```yaml
image:
  tag: "<git sha>"
s3:
  bucket: "<bucket>"
  region: "<region>"
  credentials:
    webapp:
      existingSecret: logscope-webapp-s3      # or accessKeyId / secretAccessKey inline
```

AI, by provider. `model` is always explicit (there is no default model):

```yaml
ai:
  provider: anthropic        # sends output_config.effort; refusal fallback on current models
  model: claude-opus-5-5
  apiKey: "<key>"            # or existingSecret / existingSecretKey
# provider: gemini      model: <gemini model id>
# provider: openai      model: <openai model id>     (Chat Completions, JSON mode)
# provider: openrouter  model: <vendor/model>
# baseUrl: https://llm-gateway.internal/...          # optional endpoint override
```

Notes on the AI providers:
- **Anthropic** uses the official `anthropic` SDK. On `claude-fable-5-1`,
  `claude-opus-5-5`, `claude-opus-5` and `claude-sonnet-5-5` at the default
  endpoint, the chart enables server-side refusal fallback
  (`fallbacks: "default"`).
- `reasoningEffort` is sent to Anthropic and to OpenRouter models that support
  it. Set it to `""` for older Claude models that reject effort.
- Gemini and OpenAI requests carry no effort or sampling parameters.

Chart-managed Vector, adding to the minimal example:

```yaml
vector:
  enabled: true
s3:
  credentials:
    vector:
      existingSecret: logscope-s3-creds       # existing write Secret (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY)
```

Every key is documented inline in `values.yaml`. Rendering fails with a clear
message in any of these cases:
- a required value is missing;
- the image tag is `latest`;
- credentials are incomplete;
- the AI provider is unknown or has no key;
- a Falco priority maps to an unknown bucket;
- replicas are greater than 1;
- the Ingress is enabled without auth;
- chart-managed Vector or Falco would collide with an existing install.

### Secrets

| Credential | Inline values (chart creates the Secret) | Existing Secret (recommended) |
|---|---|---|
| Web app S3 (read) | `s3.credentials.webapp.accessKeyId/secretAccessKey` | `s3.credentials.webapp.existingSecret` (keys `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`) |
| Vector S3 (write) | `s3.credentials.vector.*` | `s3.credentials.vector.existingSecret` (same keys) |
| AI API key | `ai.apiKey` | `ai.existingSecret` + `ai.existingSecretKey` |

- Credentials reach pods only through `secretKeyRef` environment variables.
  They never go into ConfigMaps, command lines, NOTES output or app logs; the
  app redacts keys from provider error messages.
- **Inline values are a trade-off.** They make installs a single file, but:
  - the populated values file is a plaintext secret: never commit it, and
    keep it `chmod 600`;
  - Helm also stores supplied values in the release record (Secret
    `sh.helm.release.v1.<release>.v<N>` in the release namespace), so anyone
    who can read Secrets there can read them, and old revisions keep old keys
    until the release history is pruned;
  - `helm get values` prints them.
- Prefer existing Secrets created out of band:
  ```bash
  umask 077; F=$(mktemp); printf 'AWS_ACCESS_KEY_ID=\nAWS_SECRET_ACCESS_KEY=\n' > "$F"; $EDITOR "$F"
  kubectl -n logging create secret generic logscope-webapp-s3 --from-env-file="$F"; shred -u "$F"
  ```
- Changing credential values in `values.yaml` rolls the affected workload
  automatically: the web app for `s3.credentials.webapp`/`ai.*`, the Vector
  DaemonSet for `s3.credentials.vector`. The pod annotations hold only a
  one-way hash. Helm can't see changes made inside an existing Secret, so
  after rotating one run
  `kubectl -n logging rollout restart deploy/logscope-webapp` (or
  `ds/logscope-vector`).

## Image

```bash
git status --porcelain                        # empty: the tag must identify the code
TAG=$(git rev-parse --short=12 HEAD)
docker build -f webapp/Dockerfile -t logscope-webapp:$TAG .
```

- **Single node, no registry:** `docker save logscope-webapp:$TAG | sudo k3s ctr images import -`,
  and keep `image.repository: logscope-webapp`.
- **Multi-node:** an imported image exists on one node only, and pods placed
  elsewhere fail with `ErrImagePull`. Push to a registry every node can reach,
  set `image.repository: <registry>/<project>/logscope-webapp`, and add
  `image.pullSecrets` if the registry is private.

Vector (`docker.io/timberio/vector`) and Falco pull from public registries,
as they do today.

## Install / upgrade / rollback

```bash
V=deploy/helm/logscope/values.local.yaml
helm lint deploy/helm/logscope -f $V
helm upgrade --install logscope deploy/helm/logscope -n logging -f $V --set image.tag=$TAG \
  --dry-run=server                                  # renders and checks against the cluster; creates nothing
helm upgrade --install logscope deploy/helm/logscope -n logging -f $V --set image.tag=$TAG --wait --timeout 10m

helm history logscope -n logging
helm rollback logscope <REVISION> -n logging --wait
```

- The web app uses `Recreate` (single SQLite writer), so each upgrade has a few
  seconds of UI downtime.
- Vector rolls one node at a time and resumes from its checkpoints.
- `helm uninstall` keeps the web app PVC (`helm.sh/resource-policy: keep`).
- The Falco chart is vendored in `charts/` and pinned in `Chart.yaml`, so
  there's deliberately no `Chart.lock`. Don't run `helm dependency
  update/build`; `Chart.yaml` explains how to upgrade it.
- Database schema changes are additive, so a rollback can open a newer database.

## Exposing Logscope on a hostname

The default access path is ClusterIP plus `kubectl port-forward`. Expose a
hostname only when people need the UI without kubectl. Logscope has no login
of its own, so the chart refuses to render an Ingress that isn't protected.

### What this k3s cluster already has (observed read-only, 2026-10-14)

| Item | Observed | Meaning |
|---|---|---|
| IngressClass | `traefik` (cluster default) | `ingress.className: ""` picks it; `ingress.controller: traefik` (default) |
| Traefik entrypoints | `web` → Service port 80, `websecure` → Service port 443 (TLS on) | The chart routes Logscope on `websecure` only. `web` just redirects to HTTPS |
| Traefik Service | `LoadBalancer` via k3s ServiceLB; EXTERNAL-IP `10.42.254.1` | ServiceLB binds ports 80/443 on each node. `10.42.254.1` is the node's **InternalIP**; no public IP is configured |
| Certificates | no cert-manager, no Traefik TLSStore | Without `ingress.tls.secretName`, Traefik serves its self-signed default certificate |
| NetworkPolicy | chart default admits only Traefik pods in `kube-system` | Matches the cluster's existing `user-*` policies |
| Other Ingresses | 12 host-less pgAdmin routes `/pgadmin/<user>` on `web` | Unaffected on other hosts or IPs. Logscope's host-specific rules win only for requests to the Logscope hostname, so don't share that hostname with pgAdmin |

### Values

```yaml
ingress:
  enabled: true
  host: logscope.example.com          # your FQDN (placeholder)
  className: ""                       # cluster default (traefik)
  controller: traefik
  tls:
    enabled: true
    secretName: logscope-tls          # kubernetes.io/tls Secret for the host
  basicAuth:
    secretName: logscope-basic-auth   # htpasswd Secret, key "users"
  httpsRedirect: true                 # http:// → https:// (nothing served over HTTP)
```

What renders with `controller: traefik`:
- an Ingress on `websecure` for `host` → Service `logscope-webapp`, port
  `http` (8000), with basic auth attached;
- a redirect-only Ingress on `web`;
- two Traefik Middlewares (auth, redirect).

With any other controller, use `controller: other` and set the controller's
own TLS and auth annotations in `ingress.annotations`. Also set
`externalAuth: true` and adjust `networkPolicy.ingressFrom` to that
controller's pods.

### 1. Authentication Secret

```bash
htpasswd -nB <username> > users        # prompts for the password (bcrypt); apache2-utils / httpd-tools
kubectl -n logging create secret generic logscope-basic-auth --from-file=users=users
shred -u users
```

Repeat the `htpasswd` line, appending with `>>`, to add users. Basic auth
only protects the UI: there are no roles, and every user sees all logs.
Use SSO in front (`externalAuth: true`) if you need per-user identity or
revocation.

### 2. TLS certificate

Pick one. The chart only references the Secret.

- **Existing certificate** (corporate CA or purchased):
  `kubectl -n logging create secret tls logscope-tls --cert=fullchain.pem --key=privkey.pem`.
  Renew before expiry by replacing the Secret; Traefik reloads it
  automatically.
- **cert-manager** (not installed on this cluster): install it, create an
  Issuer or ClusterIssuer, and add
  `ingress.annotations: {cert-manager.io/cluster-issuer: <issuer>}` with
  `tls.secretName` set. Let's Encrypt HTTP-01 needs port 80 on the public
  address reachable from the internet. DNS-01 works for private hosts.
- **No Secret:** Traefik's self-signed default certificate. Use it for
  testing only; browsers warn.

### 3. DNS record (configured at your DNS provider, outside Kubernetes)

Point the hostname at the address clients use to reach Traefik:

| Your setup | Record |
|---|---|
| Node or LB with a static IPv4 | `A logscope.example.com → <IPv4>` |
| IPv6 reachable | add `AAAA logscope.example.com → <IPv6>` |
| Cloud/external load balancer with its own DNS name | `CNAME logscope.example.com → <lb-hostname>` (not at a zone apex) |
| Internal-only access | the same record in internal DNS (split-horizon) pointing at a node IP reachable on your network, e.g. the observed `10.42.254.1` if clients can route to it |

Find the candidate address with
`kubectl -n kube-system get svc traefik -o wide` (EXTERNAL-IP) and
`kubectl get nodes -o wide`. On this cluster both show the node's internal
address. **Internet access needs a public address you supply**: a public IP on
a node, a NAT or port-forward from a public IP to a node's 80/443, or an
external load balancer in front of the nodes. Use a low TTL (e.g. 300) while
setting up.

### 4. Network path and firewall (outside Kubernetes)

- Allow inbound **TCP 443** (HTTPS) and **TCP 80** (redirect, and ACME HTTP-01
  if used) from your clients to the public IP or LB, and onward to the k3s
  nodes. Check the host firewall too (e.g. `ufw`/`firewalld` on the node) and
  any cloud security groups.
- ServiceLB publishes 80/443 on every node that runs a `svclb-traefik` pod.
  The DNS record (or the LB pool) must point at those nodes.
- Nothing else needs to be exposed. Port 8000 and the Service stay internal.
  Don't publish the Traefik dashboard or Logscope's ClusterIP.
- If a load balancer in front terminates TLS, set `allowPlainHttp: true` only
  when the LB → node hop stays on a trusted network.

### Request protections in the web app

These apply however the UI is reached:

- **CSRF.** `POST`/`PATCH` from a browser must carry an `Origin` equal to the
  host the request was sent to; anything else gets `403`.
  - Requests without `Origin` are rejected only when `Sec-Fetch-Site` marks
    them cross-site, so `curl` and scripts keep working.
  - `X-Forwarded-*` headers are not trusted. If a proxy in front rewrites
    `Host`, list the public origin in `webapp.allowedOrigins`.
- **JSON bodies** must be sent as `application/json`; anything else gets `415`.
- **AI rate limit.** `ai.rateLimitPerMinute` (default 10) operator-triggered AI
  calls per minute, shared by all users. Cached answers don't count; excess
  requests get `429` with `Retry-After`. The limit is in memory and per pod,
  so it resets on restart; with N replicas the effective limit would be N
  times higher (the chart runs one).
- **Security headers** on every response: `X-Content-Type-Options`,
  `X-Frame-Options: DENY`, `Referrer-Policy`, and a same-origin
  `Content-Security-Policy`. Styles allow `'unsafe-inline'` for the
  dashboard's inline bar widths.
- **Access log.** The app logs method, path (without the query string, which
  can contain search terms), status and peer address to stderr. Writes and
  errors are logged at INFO; successful reads only at DEBUG. Behind Traefik,
  the peer address is Traefik's.
  - Traefik's own access log is off in k3s by default. If you enable it (a
    cluster-level Traefik setting), it records full request URIs including
    query strings and the basic-auth username. Keep its header logging at the
    default (dropped).

### 5. Install and verify

```bash
helm upgrade --install logscope deploy/helm/logscope -n logging -f $V --set image.tag=$TAG --wait
kubectl -n logging get ingress,middleware.traefik.io
dig +short logscope.example.com                                   # resolves to the address above
curl -sI http://logscope.example.com/ | head -3                    # 301/308 → https://
curl -s -o /dev/null -w '%{http_code}\n' https://logscope.example.com/        # 401 without credentials
curl -s -u <username> https://logscope.example.com/healthz                      # {"status":"ok"}
# Before DNS exists, test through a node address:
curl -sk --resolve logscope.example.com:443:<node-ip> -u <username> https://logscope.example.com/healthz
```

Expected results: HTTP redirects, HTTPS returns 401 without credentials and
200 with them, and the certificate matches the hostname (add `-k` only for
the self-signed case).

To withdraw access, set `ingress.enabled: false` and upgrade, then delete the
DNS record. The basic-auth and TLS Secrets are yours to remove.

## Health checks and logs

```bash
kubectl -n logging get pods -l app.kubernetes.io/instance=logscope
kubectl -n logging port-forward svc/logscope-webapp 8000:8000     # UI: http://127.0.0.1:8000
curl -s localhost:8000/healthz     # liveness: process up, ingest loop running
curl -s localhost:8000/readyz      # readiness: SQLite cache queryable
curl -s localhost:8000/api/status  # last_error, last_successful_ingest_at, total_objects, ai_configured
kubectl -n logging logs deploy/logscope-webapp --tail=100 -f
kubectl -n logging logs ds/logscope-vector --tail=50 | grep -i -E "error|s3"   # chart-managed Vector
kubectl -n logging port-forward ds/logscope-vector 8686:8686   # Vector metrics: component_errors_total, component_discarded_events_total
kubectl -n falco logs ds/logscope-falco --tail=20              # chart-managed Falco
```

S3 and AI outages don't make the web app unready; they appear in
`/api/status` and the logs. Vector excludes its own namespace, so read the
app's and Vector's logs with `kubectl logs`.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Helm render error | Read the message. It names the value to fix |
| "another Vector/Falco install exists" | Keep `vector.enabled` / `falco.enabled` false, or uninstall the old release first |
| `CreateContainerConfigError` | The Secret name or key doesn't exist |
| `ErrImagePull` | Image not imported on that node, or wrong registry or pull secret |
| Web app `Pending` | PVC not bound: check the StorageClass |
| `last_error: Unable to locate credentials` / `AccessDenied` | Web app S3 Secret empty, or IAM/bucket/prefix mismatch |
| `last_error: Could not connect to the endpoint URL` | DNS or outbound 443 blocked |
| UI empty, no error | Nothing in S3 yet (Vector batches flush after up to 10 min), or `s3.keyPrefix`/`logscope.*` differ from what the existing Vector writes |
| No security events | Falco namespace labeled `vector.dev/exclude`, `logscope.falco.namespace` wrong, or Falco not emitting JSON on stdout |
| AI "not configured" | `ai.model` or key missing; check `/api/status` `ai_configured` |
| AI HTTP 4xx in logs | Wrong model ID or key for that provider; the key is redacted in messages |
| `https://<host>` returns Traefik `404 page not found` | DNS points at Traefik, but the host doesn't match `ingress.host`, or the Ingress isn't admitted: `kubectl -n logging describe ingress logscope-webapp` |
| `https://<host>` times out | DNS, public IP/NAT, or firewall (443) isn't in place. Test inside the network with `curl --resolve` |
| `502 Bad Gateway` / `504` | Web app pod not Ready, or `networkPolicy.ingressFrom` doesn't match the controller's pods |
| `401` with the right password | Secret key isn't `users`, or the entry isn't htpasswd format. Recreate the Secret |
| Browser certificate warning | No `ingress.tls.secretName` (self-signed default), or the certificate doesn't cover the host |
| OOMKilled | Raise `resources.limits.memory` (Insights loads 7 days of rows) or `vector.resources` |

## Limitations

- **No built-in authentication or authorization.** Anyone who reaches the
  Service can read all collected logs and trigger paid AI calls. The default
  is ClusterIP plus port-forward. An Ingress requires basic auth
  (`ingress.basicAuth`, Traefik only) or `ingress.externalAuth: true` when SSO
  is enforced in front, and HTTPS unless `allowPlainHttp` is set. See
  [Exposing Logscope on a hostname](#exposing-logscope-on-a-hostname).
- **Rate limiting covers AI calls only.** Other API endpoints aren't
  throttled, and the AI limit is in memory and per pod (see
  [Request protections](#request-protections-in-the-web-app)).
- **Single web app replica** (SQLite); no high availability.
- **S3 only, AWS endpoints.** There is no custom S3 endpoint (MinIO/Ceph), no
  IRSA wiring in the chart, and no file-sink mode in the chart.
- **Vector runs as root with host log mounts**; Falco is privileged (upstream
  chart defaults). This is inherent to node agents.
- **AI.** Log content leaves the cluster unredacted: messages, namespace, pod
  and container names, timestamps, and up to 50 lines per explanation. That
  can include tokens, emails or other personal data that applications logged.
  The provider's retention terms apply.
  - Only the four providers above are supported (Azure OpenAI and Bedrock
    aren't). `baseUrl` only works with endpoints that speak the selected
    provider's own API.
  - OpenAI requests use Chat Completions JSON mode with a 4,096-token output
    budget. Reasoning models that spend it all on reasoning return an
    explicit error.
  - A single AI call is bounded at about 2 minutes for Gemini, OpenAI and
    OpenRouter (4 × 30 s) and about 3 minutes for Anthropic (2 × 90 s). Any
    proxy timeout in front of the app must allow that.
  - An anomaly whose summary fails 3 times in a row is marked "AI error" and
    not retried.
- **Backups.** Only anomaly triage state on the PVC can't be rebuilt from S3.
