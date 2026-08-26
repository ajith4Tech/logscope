# Logscope

Centralized Kubernetes (k3s) log collection. **Vector** runs as a DaemonSet, tails
every container log, classifies severity, and writes **infra** vs **per-namespace**
files — or ships the same classified lines to S3.

Clone the repo, copy `config.example.yaml` → `config.yaml`, set your node path and
namespaces, render, deploy. No code changes.

## How configuration works

Identity and classification live in **one YAML file**. `scripts/render.py` writes
cluster install files into `deploy/` (Helm values, namespace, backup CronJob,
raw `vector.yaml`).

**Why a Python pre-processor (not Vector env templating)?** Vector can substitute
`${ENV}` into a few sink fields, but it cannot build VRL from a namespace glob
list, a line-format template, or a keyword table. Helm already `tpl`s
`customConfig`, which is why file-sink paths use `{{`{{ scope }}`}}`. A small
render step keeps one source of truth. Cost: Python 3 + PyYAML before `helm
upgrade`. Alternative would be a hand-maintained Vector config per cluster.

Environment variables override YAML after load (`LOGSCOPE_CLUSTER_NAMESPACE`,
`LOGSCOPE_PATHS_HOST_PATH`, `LOGSCOPE_S3_BUCKET`, … — full list in
`scripts/render.py` `ENV_MAP`). `LOGSCOPE_CONFIG` selects the file.

## Line format (default = current behavior)

```
<timestamp> - <namespace> - <pod>/<container> - <message>
```

Same wrapping for Prometheus `# HELP` / `# TYPE` / samples. Change
`format.line` / `format.metrics` in config for a tagged layout later — that is a
config edit, not a Vector rewrite.

## Layout (file sink)

```
<host_path>/
├── logs/infra/{error,warning,info,debug,metrics}.log
├── logs/namespaces/<ns>/{error,warning,info,debug,metrics}.log
└── backups/current/          # incremental mirror (CronJob)
```

Infra namespaces default to `default`, `kube-public`, `kube-node-lease`,
`kube-system` (globs allowed, e.g. `kube-*`).

## Deploy (node-local files)

```bash
pip install -r requirements.txt
cp config.example.yaml config.yaml   # then edit paths.host_path, routing, etc.

# Directory must already exist on the node (hostPath type: Directory).
sudo mkdir -p /var/lib/logscope

python3 scripts/render.py

kubectl apply -f deploy/namespace.yaml
helm repo add vector https://helm.vector.dev && helm repo update
helm upgrade --install vector vector/vector -n logging \
  -f deploy/values-local.yaml --version 0.57.0
kubectl -n logging rollout status ds/vector

kubectl apply -f deploy/backup-cronjob.yaml
kubectl apply -f local-vector/test-job.yaml   # -> logs/namespaces/vector-demo/
```

If GitHub chart downloads time out:

```bash
helm upgrade --install vector ~/.cache/helm/repository/vector-0.57.0.tgz \
  -n logging -f deploy/values-local.yaml
```

Do not remove the `vector.dev/exclude=true` label on the install namespace
(the rendered `deploy/namespace.yaml` sets it) or Vector will scrape itself.

Internal metrics: `kubectl -n logging port-forward ds/vector 8686:8686`

## Production (S3)

Same `config.yaml`. Set `sinks.s3.enabled: true`, `sinks.s3.region`,
`sinks.s3.bucket` (examples only in `config.example.yaml` — never real account
values). Optionally `sinks.file.enabled: false` if you do not want node files.
Re-render, then follow [`production-vector/README.md`](./production-vector/README.md).

## Classification

Priority (unchanged): structured level → embedded JSON/logfmt → klog `E####` /
`W####` / `I####` → Prometheus shape → keywords → `info`. Rules are
`severity.buckets` in config.

## Backup

Byte-append, not rsync: skip a source whose last byte is not newline; if the
backup is larger than the source, recopy; else append new bytes. Cadence is
`backup.schedule` (default `*/30 * * * *`).

```bash
kubectl -n logging create job --from=cronjob/vector-log-backup backup-manual
```

## Notes

- Image pin: chart **0.57.0** → `timberio/vector:0.57.0-debian` (not in YAML config).
- Checkpoints: `/var/lib/vector` (config `paths.checkpoint`). First boot skips
  files older than 3600s (`ignore_older_secs`, not in YAML).
- Fluent Bit manifests: [`archive/fluent-bit/`](./archive/fluent-bit/) (reference only).
- Multiline stack traces: `multiline.enabled` (default `false`). CRI split-line
  merge stays on via Vector `auto_partial_merge`.
