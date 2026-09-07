#!/usr/bin/env python3
"""Render Vector Helm values, raw vector.yaml, and the backup CronJob from config."""

from __future__ import annotations

import argparse
import os
import re
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    sys.stderr.write("PyYAML is required: pip install -r requirements.txt\n")
    sys.exit(1)

ROOT = Path(__file__).resolve().parents[1]

# Operational pins — not in config.yaml (see README).
CHART_VERSION = "0.57.0"
VECTOR_IMAGE_REPO = "docker.io/timberio/vector"
VECTOR_IMAGE_BASE = "debian"
METRICS_ADDR = "0.0.0.0:8686"
IGNORE_OLDER_SECS = 3600
MAX_LINE_BYTES = 10485760
INTERNAL_METRICS_SECS = 15
S3_BATCH_MAX_SIZE = 50_000_000
S3_BATCH_TIMEOUT_SECS = 600
S3_BUFFER_MAX_SIZE = 2_684_354_560

FORMAT_VARS = {
    "timestamp": "ts",
    "namespace": "ns",
    "pod": "pod",
    "container": "contnr",
    "message": "flat",
    "log_type": "bkt",
    "severity": "bkt",
    "scope": "scope",
    "scope_label": "scope_label",
}

ENV_MAP = {
    "LOGSCOPE_CLUSTER_NAMESPACE": ("cluster.namespace", "str"),
    "LOGSCOPE_PATHS_HOST_PATH": ("paths.host_path", "str"),
    "LOGSCOPE_PATHS_CHECKPOINT": ("paths.checkpoint", "str"),
    "LOGSCOPE_ROUTING_INFRA_NAMESPACES": ("routing.infra_namespaces", "list"),
    "LOGSCOPE_ROUTING_INFRA_SCOPE": ("routing.infra_scope", "str"),
    "LOGSCOPE_ROUTING_NAMESPACE_SCOPE_PREFIX": ("routing.namespace_scope_prefix", "str"),
    "LOGSCOPE_FORMAT_TIMESTAMP": ("format.timestamp", "str"),
    "LOGSCOPE_FORMAT_LINE": ("format.line", "str"),
    "LOGSCOPE_FORMAT_METRICS": ("format.metrics", "str"),
    "LOGSCOPE_MULTILINE_ENABLED": ("multiline.enabled", "bool"),
    "LOGSCOPE_MULTILINE_STARTS_WHEN": ("multiline.starts_when", "str"),
    "LOGSCOPE_MULTILINE_TIMEOUT_MS": ("multiline.timeout_ms", "int"),
    "LOGSCOPE_SINKS_FILE_ENABLED": ("sinks.file.enabled", "bool"),
    "LOGSCOPE_SINKS_FILE_PATH": ("sinks.file.path", "str"),
    "LOGSCOPE_SINKS_PROMETHEUS_ENABLED": ("sinks.prometheus.enabled", "bool"),
    "LOGSCOPE_SINKS_S3_ENABLED": ("sinks.s3.enabled", "bool"),
    "LOGSCOPE_S3_REGION": ("sinks.s3.region", "str"),
    "LOGSCOPE_S3_BUCKET": ("sinks.s3.bucket", "str"),
    "LOGSCOPE_S3_SECRET_NAME": ("sinks.s3.secret_name", "str"),
    "LOGSCOPE_S3_KEY_PREFIX": ("sinks.s3.key_prefix", "str"),
    "LOGSCOPE_S3_RETENTION_DAYS": ("sinks.s3.retention_days", "int"),
    "LOGSCOPE_S3_IRSA_ROLE_ARN": ("sinks.s3.irsa_role_arn", "str"),
    "LOGSCOPE_BACKUP_ENABLED": ("backup.enabled", "bool"),
    "LOGSCOPE_BACKUP_SCHEDULE": ("backup.schedule", "str"),
    "LOGSCOPE_BACKUP_SRC": ("backup.src", "str"),
    "LOGSCOPE_BACKUP_DST": ("backup.dst", "str"),
    "LOGSCOPE_BACKUP_LOG": ("backup.log", "str"),
    "LOGSCOPE_FALCO_ENABLED": ("falco.enabled", "bool"),
    "LOGSCOPE_FALCO_NAMESPACE": ("falco.namespace", "str"),
}

# Official Falco priority names (JSON `priority` field), lowercased as config keys.
FALCO_PRIORITIES = (
    "emergency",
    "alert",
    "critical",
    "error",
    "warning",
    "notice",
    "informational",
    "debug",
)


def deep_get(d: dict, dotted: str) -> Any:
    cur: Any = d
    for part in dotted.split("."):
        cur = cur[part]
    return cur


def deep_set(d: dict, dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    cur = d
    for p in parts[:-1]:
        cur = cur.setdefault(p, {})
    cur[parts[-1]] = value


def parse_bool(raw: str) -> bool:
    v = raw.strip().lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off"):
        return False
    raise SystemExit(f"invalid boolean env value: {raw!r}")


def apply_env(cfg: dict) -> dict:
    out = deepcopy(cfg)
    for env_name, (path, kind) in ENV_MAP.items():
        if env_name not in os.environ:
            continue
        raw = os.environ[env_name]
        if kind == "str":
            val: Any = raw
        elif kind == "bool":
            val = parse_bool(raw)
        elif kind == "int":
            val = int(raw)
        elif kind == "list":
            val = [x.strip() for x in raw.split(",") if x.strip()]
        else:
            raise AssertionError(kind)
        deep_set(out, path, val)
    return out


def glob_to_regex(pattern: str) -> str:
    """Convert a glob (* ?) to a full-match regex. No ** (would be two *)."""
    out: list[str] = ["^"]
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            out.append(".*")
        elif c == "?":
            out.append(".")
        elif c == "[":
            j = pattern.find("]", i + 1)
            if j == -1:
                out.append("\\[")
            else:
                out.append(pattern[i : j + 1])
                i = j
        else:
            if c in r".^$+{}()|\\":
                out.append("\\" + c)
            else:
                out.append(c)
        i += 1
    out.append("$")
    return "".join(out)


def vrl_escape_regex(pattern: str) -> str:
    # VRL raw strings r'...' keep backslashes; only quotes need escaping.
    return pattern.replace("'", "\\'")


def vrl_string(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def format_to_vrl(template: str) -> str:
    parts: list[str] = []
    pos = 0
    for m in re.finditer(r"\{([a-z_]+)\}", template):
        lit = template[pos : m.start()]
        if lit:
            parts.append(vrl_string(lit))
        key = m.group(1)
        if key not in FORMAT_VARS:
            known = ", ".join(sorted(FORMAT_VARS))
            raise SystemExit(f"unknown format placeholder {{{key}}}; expected one of: {known}")
        parts.append(FORMAT_VARS[key])
        pos = m.end()
    lit = template[pos:]
    if lit:
        parts.append(vrl_string(lit))
    return " + ".join(parts) if parts else '""'


def helm_escape_vector_tpl(s: str) -> str:
    """Make Vector {{ field }} survive Helm templating of customConfig."""
    return re.sub(r"\{\{\s*([^}]+?)\s*\}\}", r"{{`{{ \1 }}`}}", s)


def indent_block(text: str, n: int) -> str:
    pad = " " * n
    return "\n".join(pad + line if line else "" for line in text.splitlines())


def yaml_str(s: str) -> str:
    return yaml.dump(s, default_style='"').strip()


def falco_enabled(cfg: dict) -> bool:
    f = cfg.get("falco")
    return bool(isinstance(f, dict) and f.get("enabled"))


def falco_priority_map(cfg: dict) -> dict[str, str]:
    raw = cfg["falco"].get("priority_map") or {}
    if not isinstance(raw, dict):
        raise SystemExit("falco.priority_map must be a mapping of Falco priority → bucket")
    return {str(k).lower(): str(v) for k, v in raw.items()}


def falco_security_file_path(cfg: dict) -> str:
    """Sibling of the scoped severity files: …/logs/{{ scope }}.log → security.log."""
    p = cfg["sinks"]["file"]["path"]
    marker = "{{ scope }}"
    if marker in p:
        return p.split(marker, 1)[0].rstrip("/") + "/" + "{{ scope }}.log"
    return "/data/logs/{{ scope }}.log"


def falco_security_s3_prefix(cfg: dict) -> str:
    """Falco copy under logs/{{ scope }}/{{ log_type }}/ → security/<bucket>/."""
    p = cfg["sinks"]["s3"]["key_prefix"]
    marker = "{{ log_type }}"
    if marker in p:
        return p.replace(marker, "{{ scope }}/{{ log_type }}", 1)
    return "k3s-logs/logs/{{ scope }}/{{ log_type }}/%Y/%m/%d/%H_%M_%S_"


def _aws_s3_sink(cfg: dict, *, inputs: list[str], key_prefix: str) -> dict:
    s3 = cfg["sinks"]["s3"]
    return {
        "type": "aws_s3",
        "inputs": inputs,
        "bucket": s3["bucket"],
        "region": s3["region"],
        "key_prefix": key_prefix,
        "compression": "gzip",
        "encoding": {"codec": "text"},
        "framing": {"method": "newline_delimited"},
        "batch": {
            "max_size": S3_BATCH_MAX_SIZE,
            "timeout_secs": S3_BATCH_TIMEOUT_SECS,
        },
        "buffer": {
            "type": "disk",
            "max_size": S3_BUFFER_MAX_SIZE,
            "when_full": "block",
        },
    }


def build_vrl(cfg: dict) -> str:
    sev = cfg["severity"]
    routing = cfg["routing"]
    fmt = cfg["format"]
    buckets: list[dict] = sev["buckets"]

    text_fields = ", ".join(vrl_string(x) for x in sev["text_fields"])
    fields = sev["structured_fields"]
    if not fields:
        raise SystemExit("severity.structured_fields must not be empty")
    lvl_chain = " || ".join(f"obj.{f}" for f in fields)

    json_keys = sev.get("json_level_keys") or ["level", "lvl", "severity"]
    json_alt = "|".join(re.escape(k) for k in json_keys)

    lines: list[str] = [
        "raw = string!(.message)",
        "obj = parse_json(raw) ?? {}",
        "if !is_object(obj) { obj = {} }",
        "",
        "# ---- text body (first present field wins) ----",
        "text = \"\"",
        f"for_each([{text_fields}]) -> |_i, fname| {{",
        "  v, verr = get(obj, [fname])",
        "  if text == \"\" && verr == null && v != null {",
        "    sv, serr = to_string(v)",
        "    if serr == null && sv != \"\" { text = sv }",
        "  }",
        "}",
        "if text == \"\" { text = raw }",
        "low = downcase(text)",
        "",
        "# ---- candidate level: structured fields, then embedded JSON/logfmt ----",
        "lv = \"\"",
        f"lvl_any = {lvl_chain}",
        "if lvl_any != null {",
        "  lvs, lerr = to_string(lvl_any)",
        "  if lerr == null { lv = downcase(lvs) }",
        "}",
        "if lv == \"\" {",
        f"  m = parse_regex(raw, r'\"(?:{json_alt})\"\\s*:\\s*\"(?P<l>[^\"]+)\"') ?? {{}}",
        "  if exists(m.l) { lv = downcase(string!(m.l)) }",
        "}",
    ]
    if sev.get("logfmt_level", True):
        lines += [
            "if lv == \"\" {",
            "  m2 = parse_regex(raw, r'level=(?P<l>[a-zA-Z]+)') ?? {}",
            "  if exists(m2.l) { lv = downcase(string!(m2.l)) }",
            "}",
        ]

    lines += ["", "bkt = \"\"", "if lv != \"\" {"]
    first_if = True
    for b in buckets:
        name = b["name"]
        equals = [x.lower() for x in (b.get("level_equals") or [])]
        contains = [x.lower() for x in (b.get("level_contains") or [])]
        conds: list[str] = [f"lv == {vrl_string(e)}" for e in equals]
        conds += [f"contains(lv, {vrl_string(c)})" for c in contains]
        if not conds:
            continue
        joiner = " || ".join(conds)
        kw = "if" if first_if else "else if"
        first_if = False
        lines.append(f"  {kw} {joiner} {{ bkt = {vrl_string(name)} }}")
    lines.append("}")

    klog_buckets = [(b["name"], b["klog"]) for b in buckets if b.get("klog")]
    if klog_buckets:
        lines += ["", "# ---- klog prefixes ----", 'if bkt == "" {']
        for i, (name, pfx) in enumerate(klog_buckets):
            rx = vrl_escape_regex(rf"^{re.escape(str(pfx))}\d{{4}}\s")
            kw = "if" if i == 0 else "else if"
            lines.append(f"  {kw} match(text, r'{rx}') {{ bkt = {vrl_string(name)} }}")
        lines.append("}")

    prom = next((b for b in buckets if b.get("prometheus")), None)
    if prom:
        pname = vrl_string(prom["name"])
        lines += [
            "",
            "# ---- Prometheus exposition shapes ----",
            'if bkt == "" {',
            r"  is_metric = match(text, r'^#\s+(HELP|TYPE)\s+') ||",
            r"    match(low, r'^[a-z_:][a-z0-9_:]*\{[^}]*\}\s+[+-]?[0-9]+(\.[0-9]+)?([e][+-]?[0-9]+)?$') ||",
            r"    match(low, r'^[a-z_:][a-z0-9_:]*\s+[+-]?[0-9]+(\.[0-9]+)?([e][+-]?[0-9]+)?$')",
            f"  if is_metric {{ bkt = {pname} }}",
            "}",
        ]

    extra = sev.get("extra_patterns") or []
    if extra:
        lines += ["", "# ---- extra regex patterns ----"]
        for spec in extra:
            pat = vrl_escape_regex(spec["pattern"])
            bn = vrl_string(spec["bucket"])
            lines.append(f'if bkt == "" && match(text, r\'{pat}\') {{ bkt = {bn} }}')

    lines += ["", "# ---- keyword heuristics ----"]
    for b in buckets:
        kws = b.get("keywords") or []
        if not kws:
            continue
        conds = [f"contains(low, {vrl_string(w.lower())})" for w in kws]
        lines.append(f'if bkt == "" && ({" || ".join(conds)}) {{ bkt = {vrl_string(b["name"])} }}')
    lines.append(f'if bkt == "" {{ bkt = {vrl_string(sev["default"])} }}')

    ts_fmt = vrl_string(fmt["timestamp"])
    line_expr = format_to_vrl(fmt["line"])
    metrics_expr = format_to_vrl(fmt["metrics"])
    if line_expr == metrics_expr:
        out_assign = f"out = {line_expr}"
    else:
        out_assign = (
            f"out = if bkt == {vrl_string('metrics')} {{\n"
            f"  {metrics_expr}\n"
            f"}} else {{\n"
            f"  {line_expr}\n"
            f"}}"
        )

    infra_scope = routing.get("infra_scope", "infra")
    ns_prefix = routing.get("namespace_scope_prefix", "namespaces/")
    patterns = routing.get("infra_namespaces") or []
    match_lines = ['is_infra = false']
    for p in patterns:
        rx = vrl_escape_regex(glob_to_regex(str(p)))
        match_lines.append(f"if match(ns, r'{rx}') {{ is_infra = true }}")

    lines += [
        "",
        "# ---- flatten + timestamp + k8s metadata ----",
        'flat = replace(text, r\'[\\r\\n\\t]+\', " ")',
        "",
        "ts = if is_timestamp(.timestamp) {",
        f"  format_timestamp!(.timestamp, {ts_fmt})",
        "} else {",
        "  ts_s, ts_err = to_string(.timestamp)",
        '  if ts_err == null { ts_s } else { "" }',
        "}",
        "",
        'kmeta  = get(., ["kubernetes"]) ?? {}',
        'ns_raw, ns_err = get(kmeta, ["pod_namespace"])',
        "if ns_err != null || ns_raw == null {",
        '  ns_raw, ns_err = get(kmeta, ["namespace_name"])',
        "}",
        'if ns_err != null || ns_raw == null { ns_raw = "-" }',
        'ns = to_string(ns_raw) ?? "-"',
        'if ns == "" { ns = "-" }',
        'pod    = to_string(get(kmeta, ["pod_name"]) ?? "-") ?? "-"',
        'contnr = to_string(get(kmeta, ["container_name"]) ?? "-") ?? "-"',
        "",
        "# ---- routing scope ----",
        *match_lines,
        'scope_label = if is_infra { "infra" } else { "namespace" }',
        "scope = if is_infra {",
        f"  {vrl_string(infra_scope)}",
        "} else {",
        f"  {vrl_string(ns_prefix)} + ns",
        "}",
        "",
    ]
    if falco_enabled(cfg):
        lines += _falco_vrl(cfg)
        emit = '. = { "message": out, "log_type": bkt, "scope": scope, "falco": falco_hit }'
        lines += [
            out_assign,
            # Text sinks only emit .message — tag Falco lines so scope is visible in S3.
            'if falco_hit { out = out + " scope=" + scope }',
            emit,
        ]
    else:
        emit = '. = { "message": out, "log_type": bkt, "scope": scope }'
        lines += [
            out_assign,
            emit,
        ]
    return "\n".join(lines) + "\n"


def _falco_vrl(cfg: dict) -> list[str]:
    """Override scope/severity/message for pods in falco.namespace (from config)."""
    ns = vrl_string(cfg["falco"]["namespace"])
    pmap = falco_priority_map(cfg)
    lines = [
        "# ---- falco (detect via config namespace; parallel sink uses .falco) ----",
        "falco_hit = false",
        f"if ns == {ns} {{",
        "  falco_hit = true",
        '  scope = "security"',
        '  fout, foerr = get(obj, ["output"])',
        "  if foerr == null && fout != null {",
        "    fout_s, ferr = to_string(fout)",
        '    if ferr == null && fout_s != "" {',
        "      text = fout_s",
        '      frule, frerr = get(obj, ["rule"])',
        "      if frerr == null && frule != null {",
        "        rs, rerr = to_string(frule)",
        '        if rerr == null && rs != "" && !contains(text, rs) {',
        '          text = rs + ": " + text',
        "        }",
        "      }",
        '      flat = replace(text, r\'[\\r\\n\\t]+\', " ")',
        "    }",
        "  }",
        '  fp, fperr = get(obj, ["priority"])',
        "  if fperr == null && fp != null {",
        "    fps, perr = to_string(fp)",
        "    if perr == null {",
        "      fpl = downcase(fps)",
    ]
    first = True
    for key in FALCO_PRIORITIES:
        bucket = pmap[key]
        kw = "if" if first else "else if"
        first = False
        lines.append(f"        {kw} fpl == {vrl_string(key)} {{ bkt = {vrl_string(bucket)} }}")
    lines += [
        "    }",
        "  }",
        "}",
        "",
    ]
    return lines


def validate_cfg(cfg: dict) -> None:
    ns = cfg["cluster"]["namespace"]
    if not ns:
        raise SystemExit("cluster.namespace is required")
    host = cfg["paths"]["host_path"]
    if not host:
        raise SystemExit("paths.host_path is required")
    s3 = cfg["sinks"]["s3"]
    if s3.get("enabled"):
        if not (s3.get("region") or "").strip():
            raise SystemExit("sinks.s3.region is required when sinks.s3.enabled is true")
        if not (s3.get("bucket") or "").strip():
            raise SystemExit("sinks.s3.bucket is required when sinks.s3.enabled is true")
    # sinks.s3.retention_days: positive int (default 30). Used by apply_s3_lifecycle.py;
    # not a Vector/Helm setting. Omit or null → treated as unset (script defaults).
    if "retention_days" in s3 and s3["retention_days"] is not None:
        days = s3["retention_days"]
        if not isinstance(days, int) or isinstance(days, bool) or days < 1:
            raise SystemExit("sinks.s3.retention_days must be a positive integer")
    file_on = cfg["sinks"]["file"].get("enabled")
    prom_on = cfg["sinks"]["prometheus"].get("enabled")
    if not file_on and not s3.get("enabled") and not prom_on:
        raise SystemExit("at least one sink must be enabled")
    format_to_vrl(cfg["format"]["line"])
    format_to_vrl(cfg["format"]["metrics"])
    _validate_falco(cfg)


def _validate_falco(cfg: dict) -> None:
    f = cfg.get("falco")
    if not f:
        return
    if not isinstance(f, dict):
        raise SystemExit("falco must be a mapping")
    if not f.get("enabled"):
        return
    ns = f.get("namespace")
    if not isinstance(ns, str) or not ns.strip():
        raise SystemExit("falco.namespace is required when falco.enabled is true")
    pmap = falco_priority_map(cfg)
    missing = [p for p in FALCO_PRIORITIES if p not in pmap]
    if missing:
        need = ", ".join(FALCO_PRIORITIES)
        raise SystemExit(
            "falco.priority_map is missing required Falco priorit"
            + ("y" if len(missing) == 1 else "ies")
            + f": {', '.join(missing)} (need all 8: {need})"
        )
    buckets = {b["name"] for b in cfg["severity"]["buckets"]}
    for prio, dest in pmap.items():
        if prio in FALCO_PRIORITIES and dest not in buckets:
            raise SystemExit(
                f"falco.priority_map[{prio!r}] maps to {dest!r}, "
                f"which is not a severity.buckets name"
            )


def classify_inputs(cfg: dict) -> list[str]:
    if cfg["multiline"].get("enabled"):
        return ["multiline"]
    return ["kube_logs"]


def vector_config_dict(
    cfg: dict,
    *,
    include_file: bool | None = None,
    include_s3: bool | None = None,
) -> dict:
    """Plain Vector YAML (no Helm). Used for `vector validate` and as the logical pipeline."""
    if include_file is None:
        include_file = bool(cfg["sinks"]["file"].get("enabled"))
    if include_s3 is None:
        include_s3 = bool(cfg["sinks"]["s3"].get("enabled"))
    vrl = build_vrl(cfg)
    sources: dict[str, Any] = {
        "kube_logs": {
            "type": "kubernetes_logs",
            "auto_partial_merge": True,
            "ignore_older_secs": IGNORE_OLDER_SECS,
            "max_line_bytes": MAX_LINE_BYTES,
        }
    }
    transforms: dict[str, Any] = {}
    ml = cfg["multiline"]
    if ml.get("enabled"):
        rx = vrl_escape_regex(ml["starts_when"])
        transforms["multiline"] = {
            "type": "reduce",
            "inputs": ["kube_logs"],
            "group_by": [
                "kubernetes.pod_name",
                "kubernetes.container_name",
                "kubernetes.pod_namespace",
            ],
            "merge_strategies": {"message": "concat_newline"},
            "starts_when": f"match(string!(.message), r'{rx}')",
            "expire_after_ms": int(ml["timeout_ms"]),
        }
    transforms["classify_and_scope"] = {
        "type": "remap",
        "inputs": classify_inputs(cfg),
        "drop_on_error": True,
        "reroute_dropped": False,
        "source": vrl,
    }
    sinks: dict[str, Any] = {}
    # Dual-write Falco: main sink still gets every event; filter fans out a second copy.
    # Vector `route` is first-match exclusive — do not use it here.
    if falco_enabled(cfg) and (include_file or include_s3):
        transforms["falco_security"] = {
            "type": "filter",
            "inputs": ["classify_and_scope"],
            "condition": ".falco == true",
        }
    if include_file:
        sinks["log_files"] = {
            "type": "file",
            "inputs": ["classify_and_scope"],
            "path": cfg["sinks"]["file"]["path"],
            "encoding": {"codec": "text"},
        }
        if falco_enabled(cfg):
            sinks["falco_security_log"] = {
                "type": "file",
                "inputs": ["falco_security"],
                "path": falco_security_file_path(cfg),
                "encoding": {"codec": "text"},
            }
    if include_s3:
        # Embed bucket/region (Vector 0.57+ disables ${ENV} interpolation by default).
        # AWS_* keys still come from the Secret via env / IRSA — not from config.
        sinks["s3_logs"] = _aws_s3_sink(
            cfg, inputs=["classify_and_scope"], key_prefix=cfg["sinks"]["s3"]["key_prefix"]
        )
        if falco_enabled(cfg):
            sinks["falco_security_s3"] = _aws_s3_sink(
                cfg, inputs=["falco_security"], key_prefix=falco_security_s3_prefix(cfg)
            )
    if cfg["sinks"]["prometheus"].get("enabled"):
        sources["internal_metrics"] = {
            "type": "internal_metrics",
            "scrape_interval_secs": INTERNAL_METRICS_SECS,
        }
        sinks["prometheus"] = {
            "type": "prometheus_exporter",
            "inputs": ["internal_metrics"],
            "address": METRICS_ADDR,
        }
    return {
        "data_dir": cfg["paths"]["checkpoint"],
        "timezone": "UTC",
        "api": {"enabled": False},
        "sources": sources,
        "transforms": transforms,
        "sinks": sinks,
    }


def dump_vector_yaml(doc: dict) -> str:
    """Dump Vector config keeping remap source as a literal block."""
    doc = deepcopy(doc)
    vrl = doc["transforms"]["classify_and_scope"].pop("source")
    dumped = yaml.dump(doc, default_flow_style=False, sort_keys=False, width=1000)
    src = "    source: |\n" + indent_block(vrl.rstrip("\n"), 6) + "\n"
    needle = "    reroute_dropped: false\n"
    if needle not in dumped:
        raise SystemExit("internal error: could not inject VRL source into vector.yaml")
    return dumped.replace(needle, needle + src, 1)


def build_custom_config_for_helm(cfg: dict, *, include_file: bool, include_s3: bool) -> str:
    """YAML fragment for Helm values customConfig: (already indented 2 spaces at top)."""
    doc = vector_config_dict(cfg, include_file=include_file, include_s3=include_s3)
    vrl = doc["transforms"]["classify_and_scope"].pop("source")
    if include_file:
        doc["sinks"]["log_files"]["path"] = "__FILE_PATH__"
        if falco_enabled(cfg) and "falco_security_log" in doc.get("sinks", {}):
            doc["sinks"]["falco_security_log"]["path"] = "__FALCO_SECURITY_PATH__"
    if include_s3:
        doc["sinks"]["s3_logs"]["key_prefix"] = "__S3_PREFIX__"
        if falco_enabled(cfg) and "falco_security_s3" in doc.get("sinks", {}):
            doc["sinks"]["falco_security_s3"]["key_prefix"] = "__FALCO_S3_PREFIX__"

    dumped = yaml.dump(doc, default_flow_style=False, sort_keys=False, width=1000)
    dumped = dumped.replace("    reroute_dropped: false\n", "    reroute_dropped: false\nPLACEHOLDER_SOURCE\n", 1)
    src_block = "    source: |\n" + indent_block(vrl.rstrip("\n"), 6) + "\n"
    dumped = dumped.replace("PLACEHOLDER_SOURCE\n", src_block, 1)
    if include_file:
        dumped = dumped.replace(
            "path: __FILE_PATH__",
            'path: "' + helm_escape_vector_tpl(cfg["sinks"]["file"]["path"]) + '"',
        )
        if falco_enabled(cfg):
            dumped = dumped.replace(
                "path: __FALCO_SECURITY_PATH__",
                'path: "' + helm_escape_vector_tpl(falco_security_file_path(cfg)) + '"',
            )
    if include_s3:
        dumped = dumped.replace(
            "key_prefix: __S3_PREFIX__",
            'key_prefix: "' + helm_escape_vector_tpl(cfg["sinks"]["s3"]["key_prefix"]) + '"',
        )
        if falco_enabled(cfg):
            dumped = dumped.replace(
                "key_prefix: __FALCO_S3_PREFIX__",
                'key_prefix: "' + helm_escape_vector_tpl(falco_security_s3_prefix(cfg)) + '"',
            )
    return dumped


AGENT_HEADER = """\
## Generated by scripts/render.py — do not edit by hand.
## Chart: https://helm.vector.dev (vector/vector) {chart}
##   python3 scripts/render.py
##   helm upgrade --install vector vector/vector -n {ns} -f {values_file} --version {chart}
"""


def helm_values(cfg: dict, *, mode: str) -> str:
    """mode: local (file hostPath, no extra checkpoint vol) | agent (S3 checkpoint vol)."""
    ns = cfg["cluster"]["namespace"]
    values_file = "deploy/values-local.yaml" if mode == "local" else "deploy/values-agent.yaml"
    sa_block = [
        "serviceAccount:",
        "  create: true",
    ]
    s3 = cfg["sinks"]["s3"]
    irsa = (s3.get("irsa_role_arn") or "").strip()
    if mode == "agent" and s3.get("enabled") and irsa:
        sa_block += [
            "  annotations:",
            f"    eks.amazonaws.com/role-arn: {irsa}",
        ]

    env_block = ""
    if mode == "agent" and s3.get("enabled"):
        env_lines = [
            "env:",
            f"  - name: AWS_REGION",
            f"    value: {yaml_str(s3['region'])}",
            f"  - name: S3_BUCKET",
            f"    value: {yaml_str(s3['bucket'])}",
        ]
        if not irsa:
            secret = s3.get("secret_name") or "vector-s3-creds"
            env_lines += [
                "  - name: AWS_ACCESS_KEY_ID",
                "    valueFrom:",
                f"      secretKeyRef: {{ name: {secret}, key: AWS_ACCESS_KEY_ID }}",
                "  - name: AWS_SECRET_ACCESS_KEY",
                "    valueFrom:",
                f"      secretKeyRef: {{ name: {secret}, key: AWS_SECRET_ACCESS_KEY }}",
            ]
        env_block = "\n".join(env_lines) + "\n"

    volumes: list[str] = []
    mounts: list[str] = []
    include_file = mode == "local" and bool(cfg["sinks"]["file"].get("enabled"))
    include_s3 = mode == "agent" and bool(s3.get("enabled"))
    if include_file:
        volumes += [
            "  - name: project-logs",
            "    hostPath:",
            f"      path: {cfg['paths']['host_path']}",
            "      type: Directory",
        ]
        mounts += [
            "  - name: project-logs",
            "    mountPath: /data",
        ]
    if mode == "agent":
        volumes += [
            "  - name: vector-data",
            "    hostPath:",
            f"      path: {cfg['paths']['checkpoint']}",
            "      type: DirectoryOrCreate",
        ]
        mounts += [
            "  - name: vector-data",
            f"    mountPath: {cfg['paths']['checkpoint']}",
        ]

    vol_yaml = "extraVolumes:\n" + "\n".join(volumes) + "\n" if volumes else "extraVolumes: []\n"
    mnt_yaml = "extraVolumeMounts:\n" + "\n".join(mounts) + "\n" if mounts else "extraVolumeMounts: []\n"

    custom = indent_block(
        build_custom_config_for_helm(cfg, include_file=include_file, include_s3=include_s3).rstrip("\n"),
        2,
    )

    header = AGENT_HEADER.format(chart=CHART_VERSION, ns=ns, values_file=values_file)
    return f"""{header}
role: "Agent"

image:
  repository: {VECTOR_IMAGE_REPO}
  base: "{VECTOR_IMAGE_BASE}"
  pullPolicy: IfNotPresent

rbac:
  create: true

{chr(10).join(sa_block)}

podPriorityClassName: system-node-critical

updateStrategy:
  type: "RollingUpdate"
  rollingUpdate:
    maxUnavailable: 1

tolerations:
  - key: node-role.kubernetes.io/control-plane
    operator: Exists
    effect: NoSchedule
  - key: node-role.kubernetes.io/master
    operator: Exists
    effect: NoSchedule

resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 512Mi

podAnnotations:
  prometheus.io/scrape: "true"
  prometheus.io/port: "8686"

{env_block}{vol_yaml}{mnt_yaml}
customConfig:
{custom}
"""


def namespace_yaml(cfg: dict) -> str:
    ns = cfg["cluster"]["namespace"]
    return f"""apiVersion: v1
kind: Namespace
metadata:
  name: {ns}
  labels:
    app.kubernetes.io/name: logscope
    vector.dev/exclude: "true"
"""


def backup_cronjob(cfg: dict) -> str:
    b = cfg["backup"]
    ns = cfg["cluster"]["namespace"]
    host = cfg["paths"]["host_path"]
    src, dst, logf = b["src"], b["dst"], b["log"]
    # Algorithm is the existing byte-append job; only identity/paths are filled in.
    script = f"""set -u
SRC={src}
DST={dst}
LOGF={logf}
CNT=/tmp/backup.changed          # subshell-safe change counter
mkdir -p "$DST"
: > "$CNT"

find "$SRC" -type f -name '*.log' 2>/dev/null | sort |
while read -r src; do
  rel=${{src#"$SRC"/}}
  dst="$DST/$rel"
  mkdir -p "${{dst%/*}}"

  # Skip sources still being written (last byte != newline)
  last=$(tail -c 1 "$src" | od -An -tu1 | tr -d '[:space:]')
  [ "$last" = "10" ] || continue

  s=$(wc -c < "$src")
  if [ -f "$dst" ]; then d=$(wc -c < "$dst"); else d=0; : > "$dst"; fi

  if [ "$d" -gt "$s" ]; then
    cat "$src" > "$dst"                    # source shrank: full resync
    echo x >> "$CNT"
  elif [ "$d" -lt "$s" ]; then
    tail -c +"$((d + 1))" "$src" >> "$dst"  # INCREMENTAL: append new bytes only
    echo x >> "$CNT"
  fi
done

changed=$(wc -l < "$CNT")
total=$(find "$DST" -type f -name '*.log' | wc -l)
echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') sync ok: $changed file(s) updated, $total file(s) in backup" >> "$LOGF"
"""
    # YAML literal for args
    script_indented = indent_block(script.rstrip("\n"), 18)
    return f"""# Generated by scripts/render.py — do not edit by hand.
# Incremental byte-append backup (shrink → full recopy; else tail-append).
apiVersion: batch/v1
kind: CronJob
metadata:
  name: vector-log-backup
  namespace: {ns}
  labels:
    app.kubernetes.io/name: vector-log-backup
spec:
  schedule: {yaml_str(b['schedule'])}
  concurrencyPolicy: Forbid
  successfulJobsHistoryLimit: 1
  failedJobsHistoryLimit: 3
  jobTemplate:
    spec:
      backoffLimit: 2
      activeDeadlineSeconds: 240
      template:
        metadata:
          labels:
            app.kubernetes.io/name: vector-log-backup
        spec:
          restartPolicy: OnFailure
          nodeSelector:
            kubernetes.io/os: linux
          tolerations:
            - key: node-role.kubernetes.io/control-plane
              operator: Exists
              effect: NoSchedule
            - key: node-role.kubernetes.io/master
              operator: Exists
              effect: NoSchedule
          containers:
            - name: backup
              image: busybox:1.36
              imagePullPolicy: IfNotPresent
              command: ["sh", "-c"]
              args:
                - |
{script_indented}
              volumeMounts:
                - name: project
                  mountPath: /data
          volumes:
            - name: project
              hostPath:
                path: {host}
                type: Directory
"""


def load_config(path: Path) -> dict:
    with path.open() as f:
        cfg = yaml.safe_load(f)
    if not isinstance(cfg, dict):
        raise SystemExit(f"{path} did not parse as a mapping")
    return apply_env(cfg)


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content if content.endswith("\n") else content + "\n")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "-c",
        "--config",
        default=os.environ.get("LOGSCOPE_CONFIG", ""),
        help="config YAML (default: ./config.yaml if present, else config.example.yaml)",
    )
    p.add_argument("-o", "--out", default=str(ROOT / "deploy"), help="output directory")
    args = p.parse_args()

    if args.config:
        cfg_path = Path(args.config)
    else:
        cfg_path = ROOT / "config.yaml"
        if not cfg_path.is_file():
            cfg_path = ROOT / "config.example.yaml"
    if not cfg_path.is_file():
        raise SystemExit(f"config not found: {cfg_path}")

    cfg = load_config(cfg_path)
    validate_cfg(cfg)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    write(out / "vector.yaml", dump_vector_yaml(vector_config_dict(cfg)))
    write(out / "values-local.yaml", helm_values(cfg, mode="local"))
    write(out / "values-agent.yaml", helm_values(cfg, mode="agent"))
    write(out / "namespace.yaml", namespace_yaml(cfg))
    if cfg["backup"].get("enabled"):
        write(out / "backup-cronjob.yaml", backup_cronjob(cfg))
    else:
        stale = out / "backup-cronjob.yaml"
        if stale.exists():
            stale.unlink()

    print(f"Rendered from {cfg_path} → {out}/")
    print(f"  namespace: {cfg['cluster']['namespace']}")
    print(f"  host_path: {cfg['paths']['host_path']}")
    print(f"  file sink: {cfg['sinks']['file'].get('enabled')}  s3 sink: {cfg['sinks']['s3'].get('enabled')}")
    print(f"  helm local:  helm upgrade --install vector vector/vector -n {cfg['cluster']['namespace']} \\")
    print(f"                 -f {out}/values-local.yaml --version {CHART_VERSION}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyError, TypeError) as e:
        raise SystemExit(f"config error: {e}") from e
