Cluster install files rendered by `python3 scripts/render.py`. Do not edit by
hand; change `config.yaml` / `config.example.yaml` instead.

- `values-local.yaml` — Helm Agent + file sink (no extra checkpoint volume)
- `values-agent.yaml` — Helm Agent + S3 sink layout (extra checkpoint hostPath)
- `vector.yaml` — raw Vector config (both sinks that are enabled in config)
- `namespace.yaml` — install namespace + `vector.dev/exclude=true`
- `backup-cronjob.yaml` — incremental byte-append backup of the file sink
  (rendered only when `sinks.file.enabled` and `backup.enabled` are both true)

These files are rendered from your `config.yaml`, so they contain environment
identifiers such as the S3 bucket name and region (not credentials). Review
them before committing, or keep cluster-specific renders out of Git.

`helm/logscope/` is the exception: the hand-maintained Helm chart for the
Logscope web app (not rendered). See [`helm/logscope/README.md`](./helm/logscope/README.md).
