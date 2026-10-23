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
│  │  Falco JSON → scope "security"                │    (Falco: security/<bucket>/… only)
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
| **Vector** | Tails all pod logs, classifies severity and scope, writes gzip objects to S3. Falco events are recognised by namespace and container (`logscope.falco.containers`) and written once, under `security/<severity>/` | k3s (DaemonSet) | Optional: `vector.enabled`. Default: use the existing install (`scripts/render.py` + `vector/vector`) |
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
      existingSecret: vector-s3-creds         # existing write Secret (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY): sinks.s3.secret_name of the existing install
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
| Settings admin token | — (generated once into `/state/admin.token`) | `settings.adminToken.existingSecret` + `existingSecretKey` |
| Settings master key | — (generated once into `/state/secret.key`) | `settings.secretKey.existingSecret` + `existingSecretKey` (+ optional `previousKeysKey`) |

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

### AI settings from the UI (Settings tab)

The Settings tab changes the AI provider, model, deep model (used for anomaly
summaries), base URL and API key, the feature flags, daily budgets and the
price table at runtime, without a restart. It shows today's and the last 7
days' AI usage per feature (calls, tokens, estimated cost, cache-hit %,
blocked calls).

- **Admin token.** The tab and `/api/settings/ai*` need
  `Authorization: Bearer <token>` on top of the Origin check. The token is
  `LOGSCOPE_ADMIN_TOKEN` (from `settings.adminToken.existingSecret`) or,
  without it, a random token generated once into `/state/admin.token`
  (mode 0600). Only the file's path is logged. The image is distroless (no
  shell or `cat`), so reading the generated file needs access to the volume;
  for a token you can hand out, create a Secret and point the chart at it:
  ```bash
  kubectl -n logging create secret generic logscope-admin \
    --from-literal=LOGSCOPE_ADMIN_TOKEN="$(openssl rand -base64 32)"
  # values: settings.adminToken.existingSecret: logscope-admin
  ```
  A wrong token gets `401`; after 10 failures in a minute an address gets
  `429` (even with the right token) until the minute has passed. The UI keeps
  the token in `sessionStorage` only.
- **Precedence.** An environment variable (set directly or from a Secret)
  wins and is read-only in the tab; otherwise the value saved in the tab;
  otherwise `config.yaml` (these chart values). For the key: the chart's
  `ai.apiKey`/`ai.existingSecret` (`LOGSCOPE_AI_API_KEY`) > the key stored
  from the tab > none. `LOGSCOPE_AI_PROVIDER`, `LOGSCOPE_AI_MODEL`,
  `LOGSCOPE_AI_DEEP_MODEL` and `LOGSCOPE_AI_BASE_URL` (via
  `webapp.extraEnv`) pin the other fields.
- **Stored key.** Encrypted (Fernet) with the master key and kept in the
  state database with its last 4 characters; no endpoint returns it or its
  ciphertext, and it is never logged.
- **Base URL allowlist.** The official OpenRouter, Gemini, OpenAI and
  Anthropic API hosts, `localhost`/`127.0.0.1`/`[::1]`, and the hosts in
  `ai.allowedHosts` (`LOGSCOPE_AI_ALLOWED_HOSTS`). https is required except
  for local hosts; anything else gets `422`.
- **Feature flags.** `explain_line`, `explain_filtered`,
  `anomaly_auto_summary` (default **off**: anomalies are summarized only on
  request), `anomaly_manual_summary`, `nl_filters` (the Ask box: proposes
  filters from a plain-language request via `POST /api/ai/filters`, fast
  model, never applied without a click; no log content is sent). A disabled
  feature answers `403 {"error": "ai_feature_disabled"}` and its buttons are
  hidden.
- **Budgets** (UTC days): `daily_tokens`, `daily_cost_usd`, and per-feature
  `daily_calls`. Checked before each call; over budget the call is skipped
  and the answer is `{"degraded": true, "reason": "budget"}`. At 80%
  `/api/status` `ai_warnings` says so, and with Mattermost enabled one notice
  per budget per day is sent.
- **Metering.** Every AI request is a row in the state database's
  `ai_usage` table (outcome `ok`, `error`, `cache_hit` or `budget_blocked`).
  Token counts come from the provider's usage fields, else chars/4. Cost uses
  `ai.prices` (or the tab's price table; USD per million input, output and
  cached input tokens); a model without a price is counted with an unknown
  cost.

#### Rotating the master key

Without `settings.secretKey.existingSecret` the master key is
`/state/secret.key`, created on first start. To rotate (or to move to a
Secret):

1. Create the new key: `python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'`
   (any random string of 32+ characters also works).
2. Put it in the Secret as `LOGSCOPE_SECRET_KEY` and the old key as
   `LOGSCOPE_SECRET_KEY_PREVIOUS` (comma-separated for several), and set
   `settings.secretKey.existingSecret`. Moving off the generated file, the old
   key is the content of `/state/secret.key`.
3. Restart (`kubectl -n logging rollout restart deploy/logscope-webapp`). On
   start the stored API key is re-encrypted with the new key ("Re-encrypted
   the stored AI key" in the log).
4. Remove `LOGSCOPE_SECRET_KEY_PREVIOUS` from the Secret and restart again.

If the master key changes without the previous one (e.g. the Secret was
replaced or `secret.key` lost), the app keeps running: the stored key reads
as not set (`key_set: false`), the tab and `/api/status` show a warning, and
the key has to be entered again. A key from `ai.apiKey`/`ai.existingSecret`
is not affected. Rotating the admin token is a Secret update (or deleting
`/state/admin.token`) followed by a restart.

### Alerts on saved views (Alerts tab)

A rule counts what a saved view matches (`count`, `error_count` or
`distinct_pods`) over a window of 5 min to 24 h, every 1 to 60 min, and
compares it with a threshold (`>`, `>=`, `<`, `<=`), optionally per namespace
or pod (at most 20 groups; the rest is reported as overflow). At most 100
rules. Creating, changing or deleting rules and channels needs the Settings
admin token; muting (1 h, 4 h, 24 h or custom) does not, so on-call can
silence a rule from the UI (rate limited per address). The rule form shows a
backtest ("would have fired N times in 7 days") computed from the histogram
buckets.

- **Watermark.** Every window ends at the ingest watermark, never at "now":
  per S3 prefix, the start of its latest complete listing minus Vector's
  batch timeout (600 s), held back to the key time of any object that is
  still failing; the oldest prefix wins, minus `alerts.watermarkMarginSecs`.
  `/api/status` → `watermark` shows it. When it is more than 3 × the batch
  timeout (30 min) behind, the pipeline is stale: `<`/`<=` rules report
  *unknown* instead of firing on missing data, and one `pipeline_stale` alert
  goes to the default (environment Mattermost) channel.
- **States.** ok → pending (until the required consecutive breaches) →
  firing → resolved → ok. Notifications on firing, again every
  `renotify` interval while firing (default 6 h), and on resolved if enabled.
  A muted rule still records its events. Every transition is kept in the
  state database for 30 days, and the evaluator rebuilds its state from it at
  start, so a restart neither forgets nor re-sends a firing alert.
- **Channels.** Mattermost or Slack incoming webhooks, or a generic JSON
  webhook (optionally signed: `X-Logscope-Signature: sha256=<HMAC-SHA256 of the
  body>`). URLs and signing secrets are encrypted with the settings master key
  and are write-only (the UI shows the last six characters). 10 s timeout, 5
  attempts with backoff, no redirects; failures are stored with the event.
  Channel URLs must be https and must not resolve to link-local, cloud
  metadata, loopback or private addresses; list internal hosts (e.g. an
  in-cluster Mattermost) in `alerts.allowedHosts` to allow http and private
  addresses for them (link-local and metadata stay refused). The Mattermost
  webhook from `mattermost.*` is offered as a read-only default channel; its
  URL never leaves the environment variable.
- **Content.** Rule, value vs threshold, the window in `alerts.displayTz`,
  the three most frequent message templates with counts (redacted, no raw log
  lines), the matching known-pattern title, and a link to the Logs tab with
  the view's filters and that window when `alerts.publicUrl` (or
  `mattermost.linkBaseUrl`) is set. A rule can opt in to an AI summary (fast
  model, metered and budgeted as `alert_summary`; skipped, not blocking, when
  over budget).
- **One replica.** The evaluator and its in-memory state live in the web app
  pod; two replicas would evaluate and notify twice. The chart allows only
  `replicaCount` 0 or 1 and uses the `Recreate` strategy, so this holds.

### NetworkPolicy and egress

The chart's NetworkPolicy restricts **ingress** only. Outbound traffic is
whatever the namespace allows. If your cluster applies a default-deny egress
policy, the web app pod needs egress to:

- S3 (`s3.<region>.amazonaws.com`, TCP 443) for ingestion;
- the AI provider API (TCP 443) when AI is enabled;
- every alert channel's host (TCP 443, or the port in an allowed http URL),
  and the Mattermost server for anomaly notifications;
- DNS (kube-dns, UDP/TCP 53), since channel hosts are resolved and checked
  before each delivery.

## Image

The web app image is built from the repository's `Dockerfile`: the `logscope`
binary on distroless (no shell, UID 10001). The container runs the image's
own command (`logscope serve --host 0.0.0.0 --port 8000 --config
/etc/logscope/config.yaml`). `image.tag` defaults to the chart's
`appVersion`; release tags `vX.Y.Z` publish image tag `X.Y.Z`.

```bash
git status --porcelain                        # empty: the tag must identify the code
make image IMAGE=ghcr.io/<owner>/logscope     # tag = git describe, without a leading "v"
TAG=$(make -s version | sed 's/^v//')
```

- **Single node, no registry:** `make k3s-import` prints
  `docker save ghcr.io/<owner>/logscope:$TAG | sudo k3s ctr images import -`;
  run it on the node and install with `--set image.pullPolicy=Never`.
- **Multi-node:** an imported image exists on one node only, and pods placed
  elsewhere fail with `ErrImagePull`. Push to a registry every node can reach
  (`make image-multi PUSH=1`, or the release workflow pushes `v*` tags to
  GHCR), set `image.repository` (optionally `image.digest` to pin it), and add
  `image.pullSecrets` if the registry is private.
- **kubectl actions** (off by default) need an image built with
  `INCLUDE_KUBECTL=true`, `kubectl.enabled: true` and an explicit Role
  (`rbac.readOnly.create` / `rbac.rollout.create`, namespaced, listed in
  `rbac.namespaces`). The HTTP API has no authentication, so whoever reaches
  the web app can run what those Roles allow.

Vector (`docker.io/timberio/vector`) and Falco keep pulling their upstream
images from public registries, as they do today.

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

- **Trusted hosts (DNS-rebinding guard).** Requests whose `Host` header is not
  trusted get `421`. Trusted: IP addresses, `localhost` (port-forward), this
  release's Service names and `ingress.host`; add other names users reach the
  app by in `webapp.trustedHosts` (exact names or `*.example.com`). `/healthz`
  and `/readyz` are exempt.
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
curl -s localhost:8000/api/status  # ingest.state, last_error, failing_objects, insights.last_error, ai_configured
kubectl -n logging logs deploy/logscope-webapp --tail=100 -f
kubectl -n logging logs ds/logscope-vector --tail=50 | grep -i -E "error|s3"   # chart-managed Vector
kubectl -n logging port-forward ds/logscope-vector 8686:8686   # Vector metrics: component_errors_total, component_discarded_events_total
kubectl -n falco logs ds/logscope-falco --tail=20              # chart-managed Falco
```

S3 and AI outages don't make the web app unready; they appear in
`/api/status` and the logs. Vector excludes its own namespace, so read the
app's and Vector's logs with `kubectl logs`.

`/api/status` → `ingest.state` is the signal to alert on:

| State | Meaning |
|---|---|
| `ok` | Polls succeed |
| `degraded` | Polls run, but a prefix or some objects fail (`failing_objects`, `latest_failure`); failed objects are retried with backoff (next poll, then 1 min doubling to 1 h) without blocking others |
| `stale` | No successful poll for `stale_after_secs` (5 poll intervals, at least 5 min) — usually S3 credentials, network or bucket problems (`last_error`) |
| `stalled` | The poll loop itself has not completed a poll in that time |

Anomaly detection compares the previous complete hour (re-checked on every
run of the following hour, so late uploads count) and the current hour once
15 minutes of it have passed, each against the same duration of baseline. The
baseline uses the history actually stored, up to `baseline_window_days`; until
there are `min_baseline_hours` (24) of history, detection is **learning** and
raises nothing (`insights.learning: true`), so a new install is quiet for its
first day. Both settings go under `webapp.insights`.

`insights` reports the detection job: `last_run_at`, `last_duration_ms`,
`last_counts` (created / updated / recurred / summarized) and `last_error`;
failures are also logged with a traceback.

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
| AI "not configured" | `ai.model` or key missing (chart values or the Settings tab); check `/api/status` `ai_configured` and `ai_warnings` |
| Settings tab: "stored API key is not usable" | The master key changed; enter the key again, or rotate with `LOGSCOPE_SECRET_KEY_PREVIOUS` (see "Rotating the master key") |
| `403 ai_feature_disabled` | The feature is switched off in the Settings tab |
| `{"degraded": true, "reason": "budget"}` | A daily AI budget is used up; it resets at 00:00 UTC, or raise it in the Settings tab |
| AI HTTP 4xx in logs | Wrong model ID or key for that provider; the key is redacted in messages |
| `https://<host>` returns Traefik `404 page not found` | DNS points at Traefik, but the host doesn't match `ingress.host`, or the Ingress isn't admitted: `kubectl -n logging describe ingress logscope-webapp` |
| `https://<host>` times out | DNS, public IP/NAT, or firewall (443) isn't in place. Test inside the network with `curl --resolve` |
| `502 Bad Gateway` / `504` | Web app pod not Ready, or `networkPolicy.ingressFrom` doesn't match the controller's pods |
| `401` with the right password | Secret key isn't `users`, or the entry isn't htpasswd format. Recreate the Secret |
| Browser certificate warning | No `ingress.tls.secretName` (self-signed default), or the certificate doesn't cover the host |
| `421 Untrusted Host header` | The app is reached by a host name it doesn't know: add it to `webapp.trustedHosts` |
| OOMKilled | Raise `resources.limits.memory` or `vector.resources` |

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
- **Single web app replica** (SQLite); no high availability. Alerts rely on
  it too: a second replica would evaluate and notify every rule twice.
- **S3 only, AWS endpoints.** There is no custom S3 endpoint (MinIO/Ceph), no
  IRSA wiring in the chart, and no file-sink mode in the chart.
- **Vector runs as root with host log mounts**; Falco is privileged (upstream
  chart defaults). This is inherent to node agents.
- **AI.** Log content leaves the cluster: messages, namespace, pod and
  container names, timestamps, and up to 50 lines per explanation. Before
  anything is sent (on every provider path, including anomaly summaries) the
  app redacts: private-key blocks, JWTs, `Bearer`/`Basic` credentials, whole
  `Authorization` and `Cookie`/`Set-Cookie` header values, AWS key IDs,
  common vendor tokens (OpenAI/Anthropic/OpenRouter, GitHub, GitLab, Slack,
  Google API and OAuth, Stripe, npm, Hugging Face), Slack/Discord/`/hooks/`
  webhook URLs, passwords and tokens in URLs, values of keys such as
  `password`, `*_pass`, `secret`, `token`, `api_key`, `access_key`,
  `client_secret`, `session_id`, `credentials`, `signature` (also quoted,
  JSON-escaped or multi-word), and email addresses. Provider error messages
  are redacted the same way before they are logged, returned or stored.
  Redaction is pattern-based and cannot be complete: a secret with no
  recognisable prefix or key name (e.g. a bare random string, a password in
  free text), other personal data (names, phone numbers, card numbers) and
  IP addresses are sent as logged. The provider's retention terms apply.
  - Log text is sent as data and the model is told never to follow
    instructions inside it. That reduces prompt injection but cannot rule it
    out: a crafted log line can still bias or falsify a summary. The model
    cannot run anything or lower a risk rating — every suggested command is
    re-parsed and risk-rated by the server, and only an exact match to a
    registered kubectl action can run: shell syntax, unknown flags, flags that
    change the target cluster or identity (`--context`, `--as`, ...), extra
    arguments, and state-changing commands carrying any flag the server would
    have to drop (`--dry-run`, `--to-revision`, ...) are refused. A
    state-changing action additionally needs a single-use confirmation token
    that the server issues for that exact command when it is shown to the
    person (the chart keeps actions disabled regardless).
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
- **Mattermost notifications** (`mattermost.*`, off by default). The webhook
  URL is a credential: it is passed as a Secret-backed environment variable
  and never logged or shown in the API/UI. One message per anomaly occurrence
  (anomaly + detection hour) at or above `minUrgency`; refreshed counts of the
  same occurrence send nothing, and a recurrence of the same anomaly within
  `renotifyAfterHours` is recorded as suppressed. Occurrences older than
  `maxAgeHours` are never sent, so enabling it does not replay history.
  Messages carry identifiers and counts only (no sample log lines or AI
  text); set `linkBaseUrl` to include links back to the UI. Delivery runs on
  its own thread (10 s timeout, up to 5 attempts with backoff) and its state
  is shown in `/api/status` → `notifications` and on the Pipeline tab. The
  pod needs egress to the Mattermost server.
- **Backups.** Only anomaly triage state and saved views on the PVC can't be
  rebuilt from S3. Nothing backs them up automatically; see
  [Backup and restore](#backup-and-restore-of-the-web-app-database).

## Backup and restore of the web app database

The web app's SQLite file (`/data/logscope.sqlite` on the PVC) holds the log
cache, ingest bookkeeping and the anomaly triage state. It is separate from
Vector's file-sink backup CronJob. Cached records can be re-read from S3 while
they are within the bucket's retention; anomaly status and AI summaries exist
only here.

Backup (online — the app keeps running; uses SQLite's backup API, so the copy
is consistent). It needs free space on the PVC about the size of the live data
(the command checks first and refuses an existing destination file):

The web app image has no shell and no `tar`, so `kubectl cp` and `rm` cannot
run in its container. Files go in and out of the PVC through a short-lived
busybox pod that mounts the same claim (`logscope-webapp-data`), and
`logscope db` runs either in the web app container (`kubectl exec`, app
running) or in a one-off pod from the same image (app stopped). Define these
two shell helpers first:

```bash
# Copy pod: busybox on the PVC as UID 10001 (the state database is mode 0600).
# NODE pins it to the volume's node (needed for ReadWriteOnce network storage);
# leave it empty when the web app is scaled to 0.
copy_pod() {
  kubectl -n logging apply -f - <<YAML
apiVersion: v1
kind: Pod
metadata: {name: logscope-copy}
spec:
  ${NODE:+nodeName: $NODE}
  restartPolicy: Never
  securityContext: {runAsUser: 10001, runAsGroup: 10001, runAsNonRoot: true}
  containers:
    - name: copy
      image: busybox:1.36
      command: [sleep, "1800"]
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}}
      volumeMounts: [{name: data, mountPath: /data}]
  volumes:
    - {name: data, persistentVolumeClaim: {claimName: logscope-webapp-data}}
YAML
  kubectl -n logging wait --for=condition=Ready pod/logscope-copy --timeout=180s
}

# One-off `logscope db ARGS...` in a pod from the web app's image (app stopped).
db_pod() {
  local img args
  img=$(kubectl -n logging get deploy logscope-webapp -o jsonpath='{.spec.template.spec.containers[0].image}')
  args=$(printf '"%s", ' db "$@"); args=${args%, }
  kubectl -n logging apply -f - <<YAML
apiVersion: v1
kind: Pod
metadata: {name: logscope-db}
spec:
  restartPolicy: Never
  securityContext: {runAsUser: 10001, runAsGroup: 10001, runAsNonRoot: true}
  containers:
    - name: db
      image: $img
      args: [$args]
      securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
      volumeMounts: [{name: data, mountPath: /data}, {name: tmp, mountPath: /tmp}]
  volumes:
    - {name: data, persistentVolumeClaim: {claimName: logscope-webapp-data}}
    - {name: tmp, emptyDir: {}}
YAML
  kubectl -n logging wait --for=jsonpath='{.status.phase}'=Succeeded pod/logscope-db --timeout=30m
  kubectl -n logging logs pod/logscope-db
  kubectl -n logging delete pod logscope-db
}
```

Backup:

```bash
POD=$(kubectl -n logging get pod -l app.kubernetes.io/instance=logscope,app.kubernetes.io/component=webapp -o name | head -1)
NODE=$(kubectl -n logging get $POD -o jsonpath='{.spec.nodeName}')
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
kubectl -n logging exec $POD -- logscope db backup /data/backup-$STAMP.sqlite
copy_pod
kubectl -n logging cp logscope-copy:/data/backup-$STAMP.sqlite ./logscope-$STAMP.sqlite
kubectl -n logging exec logscope-copy -- rm /data/backup-$STAMP.sqlite
kubectl -n logging delete pod logscope-copy
logscope db verify ./logscope-$STAMP.sqlite      # integrity check + row counts (or python -m webapp.api.dbtool)
```

Restore (the app must be stopped; nothing is deleted or overwritten). The
backup is first copied and integrity-checked beside the database
(`logscope.sqlite.restore-partial`, needs free space about the backup's size);
only then is the current database kept as
`/data/logscope.sqlite.pre-restore-<timestamp>[-N]` and the copy swapped in
atomically. If anything fails before the swap (e.g. a full disk), the current
database is left as it was. After a restore, ingest resumes from the backup's
S3 cursors and re-reads newer objects still in the bucket; anomaly triage
changes made after the backup are lost:

```bash
kubectl -n logging scale deploy/logscope-webapp --replicas=0
NODE= copy_pod
kubectl -n logging cp ./logscope-<stamp>.sqlite logscope-copy:/data/logscope-<stamp>.sqlite
kubectl -n logging delete pod logscope-copy
db_pod --db /data/logscope.sqlite restore /data/logscope-<stamp>.sqlite --app-stopped
kubectl -n logging scale deploy/logscope-webapp --replicas=1
```

### Saved views (state database)

Saved views live in a separate SQLite file, `/state/state.sqlite`: the same
PVC mounted a second time under its own subPath (`state/`), set through
`LOGSCOPE_WEBAPP_STATE_DB_PATH`. Wiping or restoring the log cache never
touches it. The file is created with mode 0600 and its schema is versioned
(`schema_version` table; upgrades only ever add migrations). Outside the
chart it defaults to `$XDG_DATA_HOME/logscope/state.sqlite`
(`~/.local/share/logscope/state.sqlite`), never `/tmp`; set
`webapp.backend.state_db_path` in `config.yaml` to change it.

`backup`, `verify` and `restore` take `--state` to work on this file instead
(same safety rules as above; copies are created with mode 0600, and `--db`
defaults to `$LOGSCOPE_WEBAPP_STATE_DB_PATH`):

```bash
kubectl -n logging exec $POD -- logscope db backup --state /state/backup-$STAMP.sqlite
copy_pod                         # mounts the whole PVC: /state is /data/state here
kubectl -n logging cp logscope-copy:/data/state/backup-$STAMP.sqlite ./logscope-state-$STAMP.sqlite
kubectl -n logging exec logscope-copy -- rm /data/state/backup-$STAMP.sqlite
kubectl -n logging delete pod logscope-copy
logscope db verify --state ./logscope-state-$STAMP.sqlite   # integrity + saved view count
# restore: app stopped; both helper pods mount the whole PVC at /data, so the
# state file is /data/state/state.sqlite.
kubectl -n logging scale deploy/logscope-webapp --replicas=0
NODE= copy_pod
kubectl -n logging cp ./logscope-state-<stamp>.sqlite logscope-copy:/data/state/logscope-state-<stamp>.sqlite
kubectl -n logging delete pod logscope-copy
db_pod --db /data/state/state.sqlite restore --state /data/state/logscope-state-<stamp>.sqlite --app-stopped
kubectl -n logging scale deploy/logscope-webapp --replicas=1
```

### Compaction

`db_pod --db /data/logscope.sqlite compact --app-stopped`, with the web app
scaled to 0 (app stopped; free space ≈ twice the live data, because VACUUM writes a copy
and, in WAL mode, the WAL as well — the command checks first) rewrites a database created by an
older version so that pruning returns space to the filesystem; new databases
do this automatically.

**Upgrading from an earlier version.** On first start the app moves the
full-text search index to a layout that no longer stores a second copy of
every log line. This runs in the background in small batches (search keeps
working, progress survives restarts); `/api/status` → `storage.fts_layout`
reads `migrating` until it finishes and `external` afterwards. While both
indexes exist the file grows by roughly 15% (measured on synthetic logs);
afterwards about 35–40% of it is free space that new data reuses. The file
does not shrink by itself; run `compact` (above) to return that space to the
volume. Take a backup first. If a step fails (e.g. the disk fills), search
keeps using the old index and the migration retries with backoff (1 to 30
minutes); `storage.fts_migration` in `/api/status` shows the rows remaining
and the last error.

**Disk space.** `/api/status` → `storage` reports the database size, WAL size,
reusable free pages and free space on the volume; `disk_low` (less than
256 MiB or 5% free) turns the ingest state to `degraded`. When the volume
fills, writes fail and are rolled back: ingest stops advancing its S3 cursors
(nothing is skipped, it resumes when space is freed) and the failure shows in
`last_error`. SQLite's temporary files go to the PVC (`SQLITE_TMPDIR=/data`)
rather than the size-limited `/tmp` emptyDir, so size the PVC for the
database plus headroom for one copy of it (backup, compaction) — the 2Gi
default suits small clusters only; check `db_bytes` after the first days of
retention.
