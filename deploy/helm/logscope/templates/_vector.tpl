{{/*
Vector pipeline for chart-managed Vector. A port of scripts/render.py
(build_vrl / vector_config_dict with the S3 sink, no file sink) so the agent
classifies exactly like an install rendered from config.yaml. Parity is
pinned by test/test_helm_chart.py — change both together.
Fixed (not configurable, the web app depends on them): line format,
timestamp format, infra scope "infra", namespace scope prefix "namespaces/".
*/}}

{{- define "logscope.vrl.str" -}}
"{{ . | replace "\\" "\\\\" | replace "\"" "\\\"" }}"
{{- end -}}

{{- define "logscope.vrl.rx" -}}
{{ . | replace "'" "\\'" }}
{{- end -}}

{{- define "logscope.vrl.glob" -}}
^{{ regexQuoteMeta (toString .) | replace "\\*" ".*" | replace "\\?" "." | replace "\\[" "[" | replace "\\]" "]" }}$
{{- end -}}

{{- define "logscope.vector.vrl" -}}
{{- $sev := .Values.logscope.severity -}}
{{- $buckets := $sev.buckets -}}
{{- $l := list -}}
{{- $textFields := list -}}
{{- range $sev.text_fields }}{{ $textFields = append $textFields (include "logscope.vrl.str" .) }}{{ end -}}
{{- $lvl := list -}}
{{- range $sev.structured_fields }}{{ $lvl = append $lvl (printf "obj.%s" .) }}{{ end -}}
{{- $jsonKeys := list -}}
{{- range ($sev.json_level_keys | default (list "level" "lvl" "severity")) }}{{ $jsonKeys = append $jsonKeys (regexQuoteMeta .) }}{{ end -}}
{{- $l = append $l "raw = string!(.message)" -}}
{{- $l = append $l "obj = parse_json(raw) ?? {}" -}}
{{- $l = append $l "if !is_object(obj) { obj = {} }" -}}
{{- $l = append $l "" -}}
{{- $l = append $l "# ---- text body (first present field wins) ----" -}}
{{- $l = append $l `text = ""` -}}
{{- $l = append $l (printf "for_each([%s]) -> |_i, fname| {" (join ", " $textFields)) -}}
{{- $l = append $l "  v, verr = get(obj, [fname])" -}}
{{- $l = append $l `  if text == "" && verr == null && v != null {` -}}
{{- $l = append $l "    sv, serr = to_string(v)" -}}
{{- $l = append $l `    if serr == null && sv != "" { text = sv }` -}}
{{- $l = append $l "  }" -}}
{{- $l = append $l "}" -}}
{{- $l = append $l `if text == "" { text = raw }` -}}
{{- $l = append $l "low = downcase(text)" -}}
{{- $l = append $l "" -}}
{{- $l = append $l "# ---- candidate level: structured fields, then embedded JSON/logfmt ----" -}}
{{- $l = append $l `lv = ""` -}}
{{- $l = append $l (printf "lvl_any = %s" (join " || " $lvl)) -}}
{{- $l = append $l "if lvl_any != null {" -}}
{{- $l = append $l "  lvs, lerr = to_string(lvl_any)" -}}
{{- $l = append $l "  if lerr == null { lv = downcase(lvs) }" -}}
{{- $l = append $l "}" -}}
{{- $l = append $l `if lv == "" {` -}}
{{- $l = append $l (printf `  m = parse_regex(raw, r'"(?:%s)"\s*:\s*"(?P<l>[^"]+)"') ?? {}` (join "|" $jsonKeys)) -}}
{{- $l = append $l "  if exists(m.l) { lv = downcase(string!(m.l)) }" -}}
{{- $l = append $l "}" -}}
{{- if ne (toString $sev.logfmt_level) "false" -}}
{{- $l = append $l `if lv == "" {` -}}
{{- $l = append $l `  m2 = parse_regex(raw, r'level=(?P<l>[a-zA-Z]+)') ?? {}` -}}
{{- $l = append $l "  if exists(m2.l) { lv = downcase(string!(m2.l)) }" -}}
{{- $l = append $l "}" -}}
{{- end -}}
{{- $l = append $l "" -}}
{{- $l = append $l `bkt = ""` -}}
{{- $l = append $l `if lv != "" {` -}}
{{- $first := true -}}
{{- range $buckets -}}
{{- $conds := list -}}
{{- range (.level_equals | default list) }}{{ $conds = append $conds (printf "lv == %s" (include "logscope.vrl.str" (lower .))) }}{{ end -}}
{{- range (.level_contains | default list) }}{{ $conds = append $conds (printf "contains(lv, %s)" (include "logscope.vrl.str" (lower .))) }}{{ end -}}
{{- if $conds -}}
{{- $l = append $l (printf "  %s %s { bkt = %s }" (ternary "if" "else if" $first) (join " || " $conds) (include "logscope.vrl.str" .name)) -}}
{{- $first = false -}}
{{- end -}}
{{- end -}}
{{- $l = append $l "}" -}}
{{- $klog := list -}}
{{- range $buckets }}{{ if .klog }}{{ $klog = append $klog . }}{{ end }}{{ end -}}
{{- if $klog -}}
{{- $l = append $l "" -}}
{{- $l = append $l "# ---- klog prefixes ----" -}}
{{- $l = append $l `if bkt == "" {` -}}
{{- range $i, $b := $klog -}}
{{- $rx := include "logscope.vrl.rx" (printf `^%s\d{4}\s` (regexQuoteMeta (toString $b.klog))) -}}
{{- $l = append $l (printf "  %s match(text, r'%s') { bkt = %s }" (ternary "if" "else if" (eq $i 0)) $rx (include "logscope.vrl.str" $b.name)) -}}
{{- end -}}
{{- $l = append $l "}" -}}
{{- end -}}
{{- $prom := "" -}}
{{- range $buckets }}{{ if and .prometheus (not $prom) }}{{ $prom = .name }}{{ end }}{{ end -}}
{{- if $prom -}}
{{- $l = append $l "" -}}
{{- $l = append $l "# ---- Prometheus exposition shapes ----" -}}
{{- $l = append $l `if bkt == "" {` -}}
{{- $l = append $l `  is_metric = match(text, r'^#\s+(HELP|TYPE)\s+') ||` -}}
{{- $l = append $l `    match(low, r'^[a-z_:][a-z0-9_:]*\{[^}]*\}\s+[+-]?[0-9]+(\.[0-9]+)?([e][+-]?[0-9]+)?$') ||` -}}
{{- $l = append $l `    match(low, r'^[a-z_:][a-z0-9_:]*\s+[+-]?[0-9]+(\.[0-9]+)?([e][+-]?[0-9]+)?$')` -}}
{{- $l = append $l (printf "  if is_metric { bkt = %s }" (include "logscope.vrl.str" $prom)) -}}
{{- $l = append $l "}" -}}
{{- end -}}
{{- if $sev.extra_patterns -}}
{{- $l = append $l "" -}}
{{- $l = append $l "# ---- extra regex patterns ----" -}}
{{- range $sev.extra_patterns -}}
{{- $l = append $l (printf `if bkt == "" && match(text, r'%s') { bkt = %s }` (include "logscope.vrl.rx" .pattern) (include "logscope.vrl.str" .bucket)) -}}
{{- end -}}
{{- end -}}
{{- $l = append $l "" -}}
{{- $l = append $l "# ---- keyword heuristics ----" -}}
{{- range $buckets -}}
{{- if .keywords -}}
{{- $conds := list -}}
{{- range .keywords }}{{ $conds = append $conds (printf "contains(low, %s)" (include "logscope.vrl.str" (lower (toString .)))) }}{{ end -}}
{{- $l = append $l (printf `if bkt == "" && (%s) { bkt = %s }` (join " || " $conds) (include "logscope.vrl.str" .name)) -}}
{{- end -}}
{{- end -}}
{{- $l = append $l (printf `if bkt == "" { bkt = %s }` (include "logscope.vrl.str" $sev.default)) -}}
{{- $l = append $l "" -}}
{{- $l = append $l "# ---- flatten + timestamp + k8s metadata ----" -}}
{{- $l = append $l `flat = replace(text, r'[\r\n\t]+', " ")` -}}
{{- $l = append $l "" -}}
{{- $l = append $l "ts = if is_timestamp(.timestamp) {" -}}
{{- $l = append $l `  format_timestamp!(.timestamp, "%Y-%m-%dT%H:%M:%SZ")` -}}
{{- $l = append $l "} else {" -}}
{{- $l = append $l "  ts_s, ts_err = to_string(.timestamp)" -}}
{{- $l = append $l `  if ts_err == null { ts_s } else { "" }` -}}
{{- $l = append $l "}" -}}
{{- $l = append $l "" -}}
{{- $l = append $l `kmeta  = get(., ["kubernetes"]) ?? {}` -}}
{{- $l = append $l `ns_raw, ns_err = get(kmeta, ["pod_namespace"])` -}}
{{- $l = append $l "if ns_err != null || ns_raw == null {" -}}
{{- $l = append $l `  ns_raw, ns_err = get(kmeta, ["namespace_name"])` -}}
{{- $l = append $l "}" -}}
{{- $l = append $l `if ns_err != null || ns_raw == null { ns_raw = "-" }` -}}
{{- $l = append $l `ns = to_string(ns_raw) ?? "-"` -}}
{{- $l = append $l `if ns == "" { ns = "-" }` -}}
{{- $l = append $l `pod    = to_string(get(kmeta, ["pod_name"]) ?? "-") ?? "-"` -}}
{{- $l = append $l `contnr = to_string(get(kmeta, ["container_name"]) ?? "-") ?? "-"` -}}
{{- $l = append $l "" -}}
{{- $l = append $l "# ---- routing scope ----" -}}
{{- $l = append $l "is_infra = false" -}}
{{- range .Values.logscope.routing.infra_namespaces -}}
{{- $l = append $l (printf "if match(ns, r'%s') { is_infra = true }" (include "logscope.vrl.rx" (include "logscope.vrl.glob" .))) -}}
{{- end -}}
{{- $l = append $l `scope_label = if is_infra { "infra" } else { "namespace" }` -}}
{{- $l = append $l "scope = if is_infra {" -}}
{{- $l = append $l `  "infra"` -}}
{{- $l = append $l "} else {" -}}
{{- $l = append $l `  "namespaces/" + ns` -}}
{{- $l = append $l "}" -}}
{{- $l = append $l "" -}}
{{- $out := `out = ts + " - " + ns + " - " + pod + "/" + contnr + " - " + flat` -}}
{{- if .Values.logscope.falco.enabled -}}
{{- $pm := .Values.logscope.falco.priority_map -}}
{{- $l = append $l "# ---- falco (detect via config namespace; parallel sink uses .falco) ----" -}}
{{- $l = append $l "falco_hit = false" -}}
{{- $l = append $l (printf "if ns == %s {" (include "logscope.vrl.str" .Values.logscope.falco.namespace)) -}}
{{- $l = append $l "  falco_hit = true" -}}
{{- $l = append $l `  scope = "security"` -}}
{{- $l = append $l `  fout, foerr = get(obj, ["output"])` -}}
{{- $l = append $l "  if foerr == null && fout != null {" -}}
{{- $l = append $l "    fout_s, ferr = to_string(fout)" -}}
{{- $l = append $l `    if ferr == null && fout_s != "" {` -}}
{{- $l = append $l "      text = fout_s" -}}
{{- $l = append $l `      frule, frerr = get(obj, ["rule"])` -}}
{{- $l = append $l "      if frerr == null && frule != null {" -}}
{{- $l = append $l "        rs, rerr = to_string(frule)" -}}
{{- $l = append $l `        if rerr == null && rs != "" && !contains(text, rs) {` -}}
{{- $l = append $l `          text = rs + ": " + text` -}}
{{- $l = append $l "        }" -}}
{{- $l = append $l "      }" -}}
{{- $l = append $l `      flat = replace(text, r'[\r\n\t]+', " ")` -}}
{{- $l = append $l "    }" -}}
{{- $l = append $l "  }" -}}
{{- $l = append $l `  fp, fperr = get(obj, ["priority"])` -}}
{{- $l = append $l "  if fperr == null && fp != null {" -}}
{{- $l = append $l "    fps, perr = to_string(fp)" -}}
{{- $l = append $l "    if perr == null {" -}}
{{- $l = append $l "      fpl = downcase(fps)" -}}
{{- range $i, $p := (list "emergency" "alert" "critical" "error" "warning" "notice" "informational" "debug") -}}
{{- $l = append $l (printf "        %s fpl == %s { bkt = %s }" (ternary "if" "else if" (eq $i 0)) (include "logscope.vrl.str" $p) (include "logscope.vrl.str" (get $pm $p))) -}}
{{- end -}}
{{- $l = append $l "    }" -}}
{{- $l = append $l "  }" -}}
{{- $l = append $l "}" -}}
{{- $l = append $l "" -}}
{{- $l = append $l $out -}}
{{- $l = append $l `if falco_hit { out = out + " scope=" + scope }` -}}
{{- $l = append $l `. = { "message": out, "log_type": bkt, "scope": scope, "falco": falco_hit }` -}}
{{- else -}}
{{- $l = append $l $out -}}
{{- $l = append $l `. = { "message": out, "log_type": bkt, "scope": scope }` -}}
{{- end -}}
{{- printf "%s\n" (join "\n" $l) -}}
{{- end -}}

{{- define "logscope.vector.s3sink" -}}
{{- $ := index . 0 -}}
{{- dict
  "type" "aws_s3"
  "inputs" (list (index . 1))
  "bucket" $.Values.s3.bucket
  "region" $.Values.s3.region
  "key_prefix" (index . 2)
  "compression" "gzip"
  "encoding" (dict "codec" "text")
  "framing" (dict "method" "newline_delimited")
  "batch" (dict "max_size" 50000000 "timeout_secs" 600)
  "buffer" (dict "type" "disk" "max_size" 2684354560 "when_full" "block")
  | toJson -}}
{{- end -}}

{{- define "logscope.vector.config" -}}
{{- $sources := dict "kube_logs" (dict "type" "kubernetes_logs" "auto_partial_merge" true "ignore_older_secs" 3600 "max_line_bytes" 10485760) -}}
{{- $transforms := dict -}}
{{- $classifyInput := "kube_logs" -}}
{{- $ml := .Values.logscope.multiline -}}
{{- if $ml.enabled -}}
{{- $_ := set $transforms "multiline" (dict
  "type" "reduce"
  "inputs" (list "kube_logs")
  "group_by" (list "kubernetes.pod_name" "kubernetes.container_name" "kubernetes.pod_namespace")
  "merge_strategies" (dict "message" "concat_newline")
  "starts_when" (printf "match(string!(.message), r'%s')" (include "logscope.vrl.rx" $ml.starts_when))
  "expire_after_ms" (int $ml.timeout_ms)) -}}
{{- $classifyInput = "multiline" -}}
{{- end -}}
{{- $_ := set $transforms "classify_and_scope" (dict "type" "remap" "inputs" (list $classifyInput) "drop_on_error" true "reroute_dropped" false "source" (include "logscope.vector.vrl" .)) -}}
{{- $sinks := dict "s3_logs" (include "logscope.vector.s3sink" (list . "classify_and_scope" .Values.s3.keyPrefix) | fromJson) -}}
{{- if .Values.logscope.falco.enabled -}}
{{- $_ := set $transforms "falco_security" (dict "type" "filter" "inputs" (list "classify_and_scope") "condition" ".falco == true") -}}
{{- $falcoPrefix := "k3s-logs/logs/{{ scope }}/{{ log_type }}/%Y/%m/%d/%H_%M_%S_" -}}
{{- if contains "{{ log_type }}" .Values.s3.keyPrefix -}}
{{- $falcoPrefix = replace "{{ log_type }}" "{{ scope }}/{{ log_type }}" .Values.s3.keyPrefix -}}
{{- end -}}
{{- $_ := set $sinks "falco_security_s3" (include "logscope.vector.s3sink" (list . "falco_security" $falcoPrefix) | fromJson) -}}
{{- end -}}
{{- if .Values.vector.metrics.enabled -}}
{{- $_ := set $sources "internal_metrics" (dict "type" "internal_metrics" "scrape_interval_secs" 15) -}}
{{- $_ := set $sinks "prometheus" (dict "type" "prometheus_exporter" "inputs" (list "internal_metrics") "address" "0.0.0.0:8686") -}}
{{- end -}}
{{- dict "data_dir" .Values.vector.dataDir "timezone" "UTC" "api" (dict "enabled" false) "sources" $sources "transforms" $transforms "sinks" $sinks | toYaml -}}
{{- end -}}
