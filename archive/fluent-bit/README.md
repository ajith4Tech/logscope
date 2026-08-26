# Archived: Fluent Bit pipeline

This tree is the **retired** Fluent Bit scraper (local DaemonSet manifests and the EKS/IRSA S3 kit). Vector replaced it as the active collector.

- `k8s/` — in-cluster Fluent Bit manifests (namespace, RBAC, ConfigMap + Lua classifier, DaemonSet, test/reset jobs)
- `production/` — Fluent Bit Helm values, `classify.lua`, and `irsa-setup.sh` for EKS → S3 (JSON-lines objects, not the Vector flat-text format)

**Not config-extracted.** Hardcoded namespaces, paths, and keyword lists stay as they were on the last working Fluent Bit revision. Do not deploy this alongside Vector (double-scraping).

The maintained pipeline is Vector: edit `config.example.yaml` / `config.yaml` at the repo root, then `python3 scripts/render.py`. For S3 in the original flat text format, use `production-vector/` (Helm values under `deploy/`).
