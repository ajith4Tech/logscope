# Vector Agent — cluster → S3 (flat text)

Ships classified logs **incrementally** in the same default line format as the
local file sink:

```
<date> - <namespace> - <pod>/<container> - <message>
```

S3 key layout (from config `sinks.s3.key_prefix`; shown with the default
`k3s-logs/logs/{{ log_type }}/%Y/%m/%d/%H_%M_%S_`):

```
s3://$BUCKET/k3s-logs/logs/{error|warning|info|debug|metrics}/%Y/%m/%d/%H_%M_%S_<batch>.log.gz
s3://$BUCKET/k3s-logs/logs/security/<severity>/%Y/%m/%d/%H_%M_%S_<batch>.log.gz   # Falco events, when enabled
```

Keys are partitioned by severity only, not by scope (infra vs namespace): the
line carries the namespace and the web app derives the scope from it. Falco
events are written once, under `security/` only; the main sink leaves them out.

Helm values and Vector config are rendered from the repo-root `config.yaml`
(`sinks.s3.*`). Do not put real bucket/region/ARNs in git; `config.example.yaml`
only has empty examples.

## Config vs this kit

| This kit (Helm `deploy/values-agent.yaml`) | Local file kit |
|---|---|
| Extra hostPath for checkpoints (`paths.checkpoint`, DirectoryOrCreate) | Chart default `/var/lib/vector` mount — do not duplicate |
| S3 sink when `sinks.s3.enabled` | File sink when `sinks.file.enabled` |
| Bucket and region written literally into the sink (Vector 0.57+ does not interpolate `${ENV}` by default; the `AWS_REGION` / `S3_BUCKET` env vars are set but not read by the config). Keys from the Secret `sinks.s3.secret_name` as env, or IRSA annotation | No AWS env |

**Not previously tested against live S3 in this repo.** Batch size (50MB),
timeout (600s), gzip, disk buffer (2.5 GiB per S3 sink, so 5 GiB with Falco
enabled, which adds the `falco_security_s3` sink), and `when_full: block` are copied
from the old `values-agent.yaml` / `vector.toml` and are **not** YAML-config
(operational pins). Confirm region, bucket, IAM, and a first object before
trusting the pipeline.

**Inferred (not copied from a running S3 deploy):**

- `sinks.s3.irsa_role_arn` — if set, annotates the Vector ServiceAccount with
  `eks.amazonaws.com/role-arn` and **omits** static access keys. Otherwise the
  keys come from the Secret named by `sinks.s3.secret_name` (default
  `vector-s3-creds`). IRSA was not wired in Vector values before; verify
  assume-role and that you do not also inject keys.
- Multiline `reduce` is **on by default** (`multiline.enabled: true`), grouped
  by `pod_name` + `container_name` + `pod_namespace`. The old S3 kit never
  used it; set `multiline.enabled: false` to ship physical lines.
- Classify VRL always sets `scope` (infra vs `namespaces/<ns>`). The default
  S3 `key_prefix` does not use `scope`, and the web app assumes it does not
  (it lists `<root>/<severity>/` prefixes).
- Namespace lookup prefers `kubernetes.pod_namespace`, then
  `namespace_name` (local Vector behavior). Old `vector.toml` only read
  `namespace_name`.

## Incremental semantics

- Read positions live under `paths.checkpoint` (hostPath). Restarts resume.
- First boot: `ignore_older_secs` 3600 (not in config).
- Wiping the checkpoint dir re-reads recent files.

## Deploy

```bash
cp ../config.example.yaml ../config.yaml
# Set sinks.s3.enabled: true, region, bucket; typically sinks.file.enabled: false
python3 ../scripts/render.py

NS=$(python3 -c "import yaml; print(yaml.safe_load(open('../config.yaml'))['cluster']['namespace'])")
# or: NS=logging

kubectl apply -f ../deploy/namespace.yaml
kubectl label ns "$NS" vector.dev/exclude=true --overwrite

# Static keys (skip if irsa_role_arn is set in config). The name must equal
# sinks.s3.secret_name (default vector-s3-creds):
SECRET=$(python3 -c "import yaml; print(yaml.safe_load(open('../config.yaml'))['sinks']['s3'].get('secret_name') or 'vector-s3-creds')")
kubectl -n "$NS" create secret generic "$SECRET" \
  --from-literal=AWS_ACCESS_KEY_ID=... \
  --from-literal=AWS_SECRET_ACCESS_KEY=...

helm repo add vector https://helm.vector.dev && helm repo update
helm upgrade --install vector vector/vector -n "$NS" \
  -f ../deploy/values-agent.yaml --version 0.57.0

kubectl -n "$NS" rollout status ds/vector
kubectl -n "$NS" logs ds/vector --tail=20 | grep -i s3
```

Secret name defaults to `vector-s3-creds` (`sinks.s3.secret_name`).

**EC2 instance profile:** attach `s3:PutObject` / `s3:AbortMultipartUpload` on
`arn:aws:s3:::BUCKET/<key_prefix root>/*` (default `k3s-logs/*`), set `irsa_role_arn` empty, and do not
create the Secret — then edit `deploy/values-agent.yaml` to drop the `env` key refs, or
leave keys unset so the SDK uses IMDS. **Flag:** render still emits
`secretKeyRef` when IRSA is empty. For IMDS-only, set a dummy secret or we
need a config flag (not added). Prefer IRSA/keys as documented above.

**S3-compatible (MinIO/Ceph):** add `endpoint:` under `sinks.s3_logs` in
`deploy/values-agent.yaml` after render (not in config.yaml yet).

## Operations

| Concern | Detail |
|---|---|
| Metrics | `:8686/metrics` |
| Alert | `component_discarded_events_total` increasing = loss |
| Offline check | `vector validate --no-environment deploy/vector.yaml` (needs Vector; kubernetes_logs may warn without a cluster) |

Classification changes: edit `config.yaml` `severity` / `format`, re-render, helm upgrade.
