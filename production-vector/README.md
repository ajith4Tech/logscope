# Vector Agent — cluster → S3 (flat text)

Ships classified logs **incrementally** in the same default line format as the
local file sink:

```
<date> - <namespace> - <pod>/<container> - <message>
```

S3 key layout (from config `sinks.s3.key_prefix`):

```
s3://$BUCKET/cluster-logs/logs/{error|warning|info|debug|metrics}/%Y/%m/%d/<batch>.log.gz
```

Helm values and Vector config are rendered from the repo-root `config.yaml`
(`sinks.s3.*`). Do not put real bucket/region/ARNs in git; `config.example.yaml`
only has empty examples.

## Config vs this kit

| This kit (Helm `deploy/values-agent.yaml`) | Local file kit |
|---|---|
| Extra hostPath for checkpoints (`paths.checkpoint`, DirectoryOrCreate) | Chart default `/var/lib/vector` mount — do not duplicate |
| S3 sink when `sinks.s3.enabled` | File sink when `sinks.file.enabled` |
| Env `AWS_REGION` / `S3_BUCKET` + Secret keys, or IRSA annotation | No AWS env |

**Not previously tested against live S3 in this repo.** Batch size (50MB),
timeout (600s), gzip, disk buffer (~2.5GB), and `when_full: block` are copied
from the old `values-agent.yaml` / `vector.toml` and are **not** YAML-config
(operational pins). Confirm region, bucket, IAM, and a first object before
trusting the pipeline.

**Inferred (not copied from a running S3 deploy):**

- `sinks.s3.irsa_role_arn` — if set, annotates the Vector ServiceAccount with
  `eks.amazonaws.com/role-arn` and **omits** static access keys. The old kit
  always used Secret `vector-s3-creds`. IRSA was not wired in Vector values
  before; verify assume-role and that you do not also inject keys.
- Multiline `reduce` `group_by` uses `pod_name` + `container_name` +
  `pod_namespace` when `multiline.enabled` is true. Never used on the old S3
  kit (`multiline.enabled: false` by default).
- Classify VRL always sets `scope` (infra vs `namespaces/<ns>`). S3
  `key_prefix` does not use `scope` unless you add it. Extra field is unused
  for S3; harmless.
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

# Static keys (skip if irsa_role_arn is set in config):
kubectl -n "$NS" create secret generic vector-s3-creds \
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
`arn:aws:s3:::BUCKET/cluster-logs/*`, set `irsa_role_arn` empty, and do not
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
