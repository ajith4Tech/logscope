Cluster install files rendered by `python3 scripts/render.py`. Do not edit by
hand; change `config.yaml` / `config.example.yaml` instead.

- `values-local.yaml` — Helm Agent + file sink (no extra checkpoint volume)
- `values-agent.yaml` — Helm Agent + S3 sink layout (extra checkpoint hostPath)
- `vector.yaml` — raw Vector config (both sinks that are enabled in config)
- `namespace.yaml` — install namespace + `vector.dev/exclude=true`
- `backup-cronjob.yaml` — incremental byte-append backup
