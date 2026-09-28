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

{{/*
Name of the Secret the TLS certificate and key are mounted from, or "" when
the chart mounts no certificate. `tls.existingSecret` (a kubernetes.io/tls
Secret, e.g. one cert-manager maintains) wins over the inline
`secret.tlsCert` / `secret.tlsKey` pair, which lands in the chart's own Secret.
*/}}
{{- define "hearth.tlsSecretName" -}}
{{- if and .Values.tls.enabled .Values.tls.existingSecret }}
{{- .Values.tls.existingSecret }}
{{- else if and .Values.secret.tlsCert .Values.secret.tlsKey }}
{{- include "hearth.fullname" . }}
{{- end }}
{{- end }}

{{/*
True when the Hearth listener speaks TLS: the chart mounts a certificate, or
the operator set config.server.tls_cert_path by hand. The liveness and
readiness probes follow this, so they never speak plaintext to a TLS port.
*/}}
{{- define "hearth.tlsEnabled" -}}
{{- $server := .Values.config.server | default dict }}
{{- if or (include "hearth.tlsSecretName" .) $server.tls_cert_path }}
{{- true }}
{{- end }}
{{- end }}

{{/*
The Hearth config rendered into the ConfigMap. When the chart mounts a
certificate it also points server.tls_cert_path / tls_key_path at it, unless
the operator already set those paths explicitly.
*/}}
{{- define "hearth.config" -}}
{{- $config := deepCopy .Values.config }}
{{- if include "hearth.tlsSecretName" . }}
{{- $server := $config.server | default dict }}
{{- if not $server.tls_cert_path }}
{{- $_ := set $server "tls_cert_path" "/etc/hearth/tls/tls.crt" }}
{{- end }}
{{- if not $server.tls_key_path }}
{{- $_ := set $server "tls_key_path" "/etc/hearth/tls/tls.key" }}
{{- end }}
{{- $_ := set $config "server" $server }}
{{- end }}
{{- toYaml $config }}
{{- end }}

{{/*
A probe with its httpGet.scheme following the TLS setting. An explicit
`scheme` in the values wins. Kubernetes does not verify the certificate of an
HTTPS httpGet probe, so a self-signed or internal-CA certificate works.
Call with (dict "probe" .Values.livenessProbe "root" $).
*/}}
{{- define "hearth.probe" -}}
{{- $probe := deepCopy .probe }}
{{- if and $probe.httpGet (not $probe.httpGet.scheme) }}
{{- $_ := set $probe.httpGet "scheme" (ternary "HTTPS" "HTTP" (eq (include "hearth.tlsEnabled" .root) "true")) }}
{{- end }}
{{- toYaml $probe }}
{{- end }}

{{/*
Names of every environment variable the operator already supplies through
`env`, `secret.env` or `extraEnv`, as a dict. The encryption-key injection
skips a name that is already present, so an install that passes
HEARTH_MASTER_KEY through `secret.env` keeps working unchanged.
*/}}
{{- define "hearth.operatorEnvNames" -}}
{{- $names := dict }}
{{- range $k, $_ := .Values.env }}{{ $_ := set $names $k true }}{{ end }}
{{- range $k, $_ := .Values.secret.env }}{{ $_ := set $names $k true }}{{ end }}
{{- range .Values.extraEnv }}{{ $_ := set $names .name true }}{{ end }}
{{- toJson $names }}
{{- end }}
