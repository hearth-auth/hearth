{{/*
Expand the name of the chart.
*/}}
{{- define "hearth.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
Truncated to 63 chars due to DNS naming spec.
*/}}
{{- define "hearth.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart label.
*/}}
{{- define "hearth.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "hearth.labels" -}}
helm.sh/chart: {{ include "hearth.chart" . }}
{{ include "hearth.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "hearth.selectorLabels" -}}
app.kubernetes.io/name: {{ include "hearth.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
ServiceAccount name.
*/}}
{{- define "hearth.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "hearth.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Image tag — falls back to v<appVersion>.

The registry only holds v-prefixed semver tags (the Docker workflow publishes
`type=semver,pattern=v{{version}}`), so a bare appVersion cannot be pulled
(audit 2026-08-28 §4.8#4). Guarded by scripts/check-chart-image-tag.sh.
*/}}
{{- define "hearth.imageTag" -}}
{{- .Values.image.tag | default (printf "v%s" .Chart.AppVersion) }}
{{- end }}

{{/*
True when any Secret value is non-empty.
*/}}
{{- define "hearth.hasSecret" -}}
{{- if or .Values.secret.tlsCert .Values.secret.tlsKey .Values.secret.env }}
{{- true }}
{{- end }}
{{- end }}
