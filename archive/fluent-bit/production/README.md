# Production: HA log scraping → S3

This folder turns the laptop prototype (`../k8s/`) into a production-ready,
highly-available pipeline that ships classified logs from every node to S3.

> **Non-EKS / manually-built cluster?** Prefer Vector at the repo root:
> [`../../../production-vector/`](../../../production-vector/).
> Its S3 sink writes the **exact flat text format** (Fluent Bit's S3 output can
> only write JSON-wrapped records), needs no IRSA, and was validated against
> Vector v0.57.0. This Fluent Bit kit remains the right choice on EKS/IRSA or if
> JSON-lines objects are acceptable.

## Architecture

```
┌─────────────── node A ───────────────┐   ┌─────────────── node B ───────────────┐
│ containerd /var/log/containers/*.log │   │ containerd /var/log/containers/*.log │
│        │                             │   │        │                             │
│  Fluent Bit DaemonSet pod            │   │  Fluent Bit DaemonSet pod            │
│   tail → enrich → classify (lua)     │   │   (identical, independent)           │
│   → route logs.{error,warning,...}   │   │                                      │
│   → fs buffer /var/lib/fluent-bit ───┼───┼──► (survives agent/net/S3 outage)    │
└────────────┬─────────────────────────┘   └────────────┬─────────────────────────┘
             │  gzip, multipart upload                  │
             ▼                                          ▼
        ┌──────────────── S3 bucket (versioned, encrypted) ─────────────────┐
        │ cluster-logs/logs/error/2026/08/25/HO_MI_S_<uuid>.gz              │
        │ cluster-logs/logs/warning/…   cluster-logs/logs/info/…            │
        │ cluster-logs/logs/debug/…     cluster-logs/logs/metrics/…         │
        └────────────────────────────────────────────────────────────────────┘
                     │ lifecycle: IA 30d → Glacier Instant 90d → expire 1y
                     ▼
             Athena / Glue / OpenSearch (optional)
```

## Why this is highly available

| Failure | Effect | Recovery |
|---|---|---|
| Fluent Bit pod crash | Only that node pauses; offsets live on the node's disk | New pod resumes from last offset — no loss |
| One node dies | Its logs stop; every other node unaffected | Node returns → buffered tail continues |
| S3 / network outage | Chunks queue on node disk (`storage.type filesystem`) | Auto-retries; drains when S3 returns |
| Rolling upgrade | `maxUnavailable: 1` → one node uncollected at a time | None needed |

Deliberate choices:
- **No extra "aggregator" replicas needed.** Two collectors reading the same
  files would duplicate logs. A DaemonSet is already HA: the failure domain is
  one node's agent, and its disk buffer covers that case.
- **At-least-once delivery.** Crash between upload and offset flush can resend
  a chunk → rare duplicates keyed by `$UUID` object names; consumers dedupe if
  exactly-once matters.
- **Ordering:** `preserve_data_ordering On` keeps per-file order within an S3 key.

## Deploy (EKS)

```bash
# 0. One-time: classifier script consumed by the chart (see prereq in helm-values.yaml)
kubectl -n kube-system create configmap fluent-bit-lua \
  --from-file=classify.lua --dry-run=client -o yaml | kubectl apply -f -

# 1. Bucket + least-privilege IAM role (IRSA)
export CLUSTER_NAME=my-prod-cluster AWS_REGION=ap-south-1 S3_BUCKET=myco-k8s-logs
./irsa-setup.sh

# 2. Install the chart with production values (pin the chart version!)
helm repo add fluent https://fluent.github.io/helm-charts
helm repo update
helm upgrade --install fluent-bit fluent/fluent-bit \
  --namespace kube-system -f helm-values.yaml

# 3. Verify
kubectl -n kube-system rollout status ds/fluent-bit
kubectl -n kube-system logs ds/fluent-bit --tail=20 | grep -i s3
kubectl -n kube-system port-forward ds/fluent-bit 2020:2020 &
curl -s localhost:2020/api/v1/metrics/prometheus | grep fluentbit_output_proc_records
aws s3 ls s3://$S3_BUCKET/cluster-logs/logs/error/ --recursive | tail
```

### Non-EKS clusters (self-managed k3s/RKE on EC2, on-prem)

No IRSA? Pick one, in order of preference:
1. **Node instance profile** (EC2): give the node IAM role the same
   `PutObject/AbortMultipartUpload` policy — plugin picks up IMDS creds. Zero config.
2. **Static keys** (last resort): create a Secret, pass via chart `env`, and in the
   output use `access_key_id ${AWS_ACCESS_KEY_ID}` / `secret_access_key ${AWS_SECRET_ACCESS_KEY}`.
3. **Non-AWS S3-compatible** (MinIO/Ceph): add `endpoint http://minio:9000` to the output block.

## What lands in S3

Each object is **gzip JSON-lines** — the full enriched record per log line
(`date, log_type, namespace, pod, container, host, labels, stream, message`),
not the flat text used locally. That makes it queryable with Athena:

```sql
SELECT namespace, pod, count(*) FROM logs
WHERE log_type='error' AND date BETWEEN '2026-08-25' AND '2026-08-26'
GROUP BY 1,2 ORDER BY 3 DESC;
```

`helm-values.yaml` drops the redundant `line` field before shipping to save
bytes; remove that modify filter if you want identical payloads everywhere.

## Cost & retention levers

- `compression gzip` (~80–90% smaller than raw)
- `storage_class INTELLIGENT_TIERING` + lifecycle: IA @30d → Glacier Instant @90d → expire @365d
- S3 **VPC gateway endpoint** → no NAT data-processing charges
- Bucket hardening: versioning + SSE-KMS + Block Public Access ON

## Monitoring (alert on these)

Scrape `:2020/api/v1/metrics/prometheus`:

| Metric | Alert when |
|---|---|
| `fluentbit_output_dropped_records_total` rate > 0 | logs being lost — buffer full / fatal S3 errors |
| `fluentbit_output_retries_failed_records_total` grows | credentials/bucket problem |
| `fluentbit_input_bytes_total` plateaus while pods run | tail stuck (rotation issue) |
| node disk where `/var/lib/fluent-bit` lives | >75% — prolonged outage filling buffer |

## Sizing starting point (tune per workload)

Per node: requests `100m CPU / 192Mi`, limits `500m / 512Mi`; reserve ≥2 GB disk
for the buffer. At ~2k lines/sec/node raise `Mem_Buf_Limit` and consider `Flush 2`.

## When you outgrow direct-to-S3

Agents → **Kafka/Redpanda** → consumer fleet → S3 buys replayability,
backpressure shielding, multi-consumer fan-out (search + archive + alerting),
and cross-AZ aggregation. Don't add it until sustained >50k lines/sec
cluster-wide, or a second downstream consumer appears.

## Runbook

| Symptom | Cause | Fix |
|---|---|---|
| `AccessDenied` in logs | IRSA role/policy mismatch, wrong region | re-run `irsa-setup.sh`; check SA annotation |
| No `logs.error` prefix objects yet | nothing classified as error yet | emit test lines (`../k8s/04-test-job.yaml`) |
| Duplicate lines after crash | expected at-least-once semantics | dedupe on `(date,pod,message)` or accept |
| Uploads lag hours behind | small chunks waiting on timeout | lower `upload_timeout` |
| Clock-skewed timestamps | node NTP broken | fix chrony; CRI header supplies timestamps |

