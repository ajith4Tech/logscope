{{- define "logscope.fullname" -}}
{{- printf "%s-webapp" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "logscope.vector.fullname" -}}
{{- printf "%s-vector" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Cluster-scoped objects (ClusterRole/Binding) include the namespace so two
     releases with the same name in different namespaces cannot collide. */}}
{{- define "logscope.vector.clusterName" -}}
{{- printf "%s-%s-vector" (include "logscope.namespace" .) .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Rollout triggers for credential changes: one-way hashes of the
     credential settings, never the values themselves. Rotating a key inside
     an existingSecret is not visible to Helm; restart the workload instead. */}}
{{- define "logscope.webapp.credentialsChecksum" -}}
{{- $c := .Values.s3.credentials.webapp -}}
{{- list $c.existingSecret $c.accessKeyId $c.secretAccessKey .Values.ai.provider .Values.ai.existingSecret .Values.ai.existingSecretKey .Values.ai.apiKey .Values.mattermost.enabled .Values.mattermost.existingSecret .Values.mattermost.existingSecretKey .Values.mattermost.webhookUrl | toJson | sha256sum -}}
{{- end -}}

{{- define "logscope.vector.credentialsChecksum" -}}
{{- $c := .Values.s3.credentials.vector -}}
{{- list $c.existingSecret $c.accessKeyId $c.secretAccessKey | toJson | sha256sum -}}
{{- end -}}

{{/* Web app image: repository:tag[@digest]; tag defaults to the chart's appVersion. */}}
{{- define "logscope.imageTag" -}}
{{- .Values.image.tag | default .Chart.AppVersion | toString -}}
{{- end -}}

{{- define "logscope.image" -}}
{{- $ref := printf "%s:%s" .Values.image.repository (include "logscope.imageTag" .) -}}
{{- with .Values.image.digest }}{{ $ref = printf "%s@%s" $ref . }}{{ end -}}
{{- $ref -}}
{{- end -}}

{{/* "true" when the pod needs a ServiceAccount token and runs kubectl actions. */}}
{{- define "logscope.kubectlEnabled" -}}
{{- if .Values.kubectl.enabled }}true{{ end -}}
{{- end -}}

{{- define "logscope.namespace" -}}
{{- default .Release.Namespace .Values.namespace -}}
{{- end -}}

{{- define "logscope.selectorLabels" -}}
app.kubernetes.io/name: logscope
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: webapp
{{- end -}}

{{- define "logscope.vector.selectorLabels" -}}
app.kubernetes.io/name: logscope
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: vector
{{- end -}}

{{- define "logscope.commonLabels" -}}
app.kubernetes.io/part-of: logscope
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "logscope.labels" -}}
{{ include "logscope.selectorLabels" . }}
{{ include "logscope.commonLabels" . }}
{{- end -}}

{{- define "logscope.vector.labels" -}}
{{ include "logscope.vector.selectorLabels" . }}
{{ include "logscope.commonLabels" . }}
{{- end -}}

{{/* Secret names: an existing Secret wins; otherwise the chart-created one. */}}
{{- define "logscope.webapp.s3Secret" -}}
{{- .Values.s3.credentials.webapp.existingSecret | default (printf "%s-credentials" (include "logscope.fullname" .)) -}}
{{- end -}}

{{- define "logscope.aiSecret" -}}
{{- .Values.ai.existingSecret | default (printf "%s-credentials" (include "logscope.fullname" .)) -}}
{{- end -}}

{{- define "logscope.aiSecretKey" -}}
{{- if .Values.ai.existingSecret }}{{ .Values.ai.existingSecretKey }}{{ else }}AI_API_KEY{{ end -}}
{{- end -}}

{{- define "logscope.vector.s3Secret" -}}
{{- .Values.s3.credentials.vector.existingSecret | default (printf "%s-credentials" (include "logscope.vector.fullname" .)) -}}
{{- end -}}

{{- define "logscope.aiEnabled" -}}
{{- if ne (lower (toString .Values.ai.provider)) "none" }}true{{ end -}}
{{- end -}}

{{/* Fails rendering with an actionable message. Never echoes secret values. */}}
{{/*
Comma-separated LOGSCOPE_TRUSTED_HOSTS: the in-cluster Service names, the
Ingress host when enabled, and webapp.trustedHosts.
*/}}
{{- define "logscope.trustedHosts" -}}
{{- $svc := include "logscope.fullname" . -}}
{{- $ns := include "logscope.namespace" . -}}
{{- $hosts := list $svc (printf "%s.%s" $svc $ns) (printf "%s.%s.svc" $svc $ns) (printf "%s.%s.svc.cluster.local" $svc $ns) -}}
{{- if and .Values.ingress.enabled .Values.ingress.host -}}
{{- $hosts = append $hosts .Values.ingress.host -}}
{{- end -}}
{{- range .Values.webapp.trustedHosts -}}
{{- $hosts = append $hosts . -}}
{{- end -}}
{{- join "," $hosts -}}
{{- end -}}

{{/* Variables the chart sets itself; webapp.extraEnv must not override them. */}}
{{- define "logscope.reservedEnv" -}}
LOGSCOPE_WEBAPP_DB_PATH LOGSCOPE_WEBAPP_STATE_DB_PATH SQLITE_TMPDIR LOGSCOPE_ACTIONS_ENABLED LOGSCOPE_LOG_LEVEL LOGSCOPE_AI_RATE_LIMIT_PER_MINUTE LOGSCOPE_ALLOWED_ORIGINS LOGSCOPE_TRUSTED_HOSTS LOGSCOPE_AI_API_KEY LOGSCOPE_MATTERMOST_WEBHOOK_URL AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
{{- end -}}

{{- define "logscope.validate" -}}
{{- $reserved := splitList " " (include "logscope.reservedEnv" .) -}}
{{- range .Values.webapp.extraEnv -}}
{{- if has (toString .name) $reserved -}}
{{- fail (printf "webapp.extraEnv must not set %s: the chart sets it, and a duplicate entry would silently override the chart's value (LOGSCOPE_ACTIONS_ENABLED is always false; use webapp.trustedHosts / webapp.allowedOrigins / webapp.logLevel instead)" .name) -}}
{{- end -}}
{{- end -}}
{{- if gt (int .Values.replicaCount) 1 -}}
{{- fail "replicaCount must be 0 or 1: the web app uses a single-writer SQLite database on a ReadWriteOnce volume" -}}
{{- end -}}
{{- $_ := required "image.repository is required" .Values.image.repository -}}
{{- $_ := required "image.tag is required (or set the chart's appVersion; use an immutable tag such as a release version or git SHA)" (include "logscope.imageTag" .) -}}
{{- if eq (include "logscope.imageTag" .) "latest" -}}
{{- fail "image.tag must be immutable; \"latest\" is not allowed" -}}
{{- end -}}
{{- with .Values.image.digest -}}
{{- if not (regexMatch "^sha256:[a-f0-9]{64}$" (toString .)) -}}
{{- fail "image.digest must look like sha256:<64 hex characters>" -}}
{{- end -}}
{{- end -}}
{{- if and .Values.kubectl.enabled (not (or .Values.rbac.readOnly.create .Values.rbac.rollout.create)) -}}
{{- fail "kubectl.enabled=true needs an explicit RBAC Role: set rbac.readOnly.create and/or rbac.rollout.create (and an image built with INCLUDE_KUBECTL=true). The API has no authentication; see values.yaml" -}}
{{- end -}}
{{- $_ := required "s3.bucket is required" .Values.s3.bucket -}}
{{- $_ := required "s3.region is required" .Values.s3.region -}}
{{- $_ := required "s3.keyPrefix is required" .Values.s3.keyPrefix -}}
{{- include "logscope.validateCreds" (list "s3.credentials.webapp" .Values.s3.credentials.webapp) -}}
{{- $providers := list "none" "anthropic" "gemini" "openai" "openrouter" -}}
{{- if not (has (lower (toString .Values.ai.provider)) $providers) -}}
{{- fail (printf "ai.provider must be one of %s" (join ", " $providers)) -}}
{{- end -}}
{{- if include "logscope.aiEnabled" . -}}
{{- $_ := required "ai.model is required when ai.provider is not none" .Values.ai.model -}}
{{- if not (or .Values.ai.apiKey .Values.ai.existingSecret) -}}
{{- fail "ai.apiKey or ai.existingSecret is required when ai.provider is not none" -}}
{{- end -}}
{{- end -}}
{{- if .Values.mattermost.enabled -}}
{{- if not (or .Values.mattermost.webhookUrl .Values.mattermost.existingSecret) -}}
{{- fail "mattermost.webhookUrl or mattermost.existingSecret is required when mattermost.enabled is true" -}}
{{- end -}}
{{- $urgencies := list "low" "medium" "high" "urgent" -}}
{{- if not (has (lower (toString .Values.mattermost.minUrgency)) $urgencies) -}}
{{- fail "mattermost.minUrgency must be one of low, medium, high, urgent" -}}
{{- end -}}
{{- end -}}
{{- $buckets := list -}}
{{- range .Values.logscope.severity.buckets }}{{ $buckets = append $buckets .name }}{{ end -}}
{{- if not $buckets }}{{ fail "logscope.severity.buckets must define at least one bucket" }}{{ end -}}
{{- if .Values.logscope.falco.enabled -}}
{{- $_ := required "logscope.falco.namespace is required when logscope.falco.enabled" .Values.logscope.falco.namespace -}}
{{- range (list "emergency" "alert" "critical" "error" "warning" "notice" "informational" "debug") -}}
{{- $dest := get $.Values.logscope.falco.priority_map . -}}
{{- if not $dest }}{{ fail (printf "logscope.falco.priority_map is missing Falco priority %q (all 8 are required)" .) }}{{ end -}}
{{- if not (has $dest $buckets) }}{{ fail (printf "logscope.falco.priority_map.%s maps to %q, which is not a logscope.severity.buckets name" . $dest) }}{{ end -}}
{{- end -}}
{{- end -}}
{{- if .Values.vector.enabled -}}
{{- include "logscope.validateCreds" (list "s3.credentials.vector" .Values.s3.credentials.vector) -}}
{{- with .Values.vector.conflictCheck.daemonSetName -}}
{{- $existing := lookup "apps/v1" "DaemonSet" (include "logscope.namespace" $) . -}}
{{- if and $existing (ne (dig "metadata" "annotations" "meta.helm.sh/release-name" "" $existing) $.Release.Name) -}}
{{- fail (printf "vector.enabled=true but DaemonSet %q (another Vector install) exists in this namespace. Uninstall it first (see README) or keep vector.enabled=false." .) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if .Values.falco.enabled -}}
{{- if not .Values.logscope.falco.enabled -}}
{{- fail "falco.enabled=true requires logscope.falco.enabled=true so Vector routes Falco events" -}}
{{- end -}}
{{- $falcoNs := .Values.falco.namespaceOverride | default .Release.Namespace -}}
{{- if ne $falcoNs .Values.logscope.falco.namespace -}}
{{- fail (printf "falco.namespaceOverride (%s) must equal logscope.falco.namespace (%s)" $falcoNs .Values.logscope.falco.namespace) -}}
{{- end -}}
{{- with (dig "conflictCheck" "daemonSetName" "" .Values.falco) -}}
{{- $existing := lookup "apps/v1" "DaemonSet" $falcoNs . -}}
{{- if and $existing (ne (dig "metadata" "annotations" "meta.helm.sh/release-name" "" $existing) $.Release.Name) -}}
{{- fail (printf "falco.enabled=true but DaemonSet %q (another Falco install) exists in namespace %s. Keep falco.enabled=false to use it, or uninstall it first (see README)." . $falcoNs) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "logscope.validateCreds" -}}
{{- $path := index . 0 -}}
{{- $c := index . 1 -}}
{{- if not $c.existingSecret -}}
{{- if not (and $c.accessKeyId $c.secretAccessKey) -}}
{{- fail (printf "%s: set existingSecret, or both accessKeyId and secretAccessKey" $path) -}}
{{- end -}}
{{- end -}}
{{- end -}}
