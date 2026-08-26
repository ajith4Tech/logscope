# Local Vector (file sink)

Active path for a node-local scrape: Helm values are **generated**.

```bash
python3 scripts/render.py
helm upgrade --install vector vector/vector -n logging \
  -f ../deploy/values-local.yaml --version 0.57.0
kubectl apply -f ../deploy/backup-cronjob.yaml
kubectl apply -f test-job.yaml
```

`test-job.yaml` emits one line per severity bucket in namespace `vector-demo`
(not infra), so files land under `logs/namespaces/vector-demo/`.
