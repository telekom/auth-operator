{{/*
Expand the name of the chart.
*/}}
{{- define "auth-operator.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "auth-operator.fullname" -}}
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
Create chart name and version as used by the chart label.
*/}}
{{- define "auth-operator.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "auth-operator.labels" -}}
helm.sh/chart: {{ include "auth-operator.chart" . }}
{{ include "auth-operator.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "auth-operator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "auth-operator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Image - supports both tag and digest references
If digest is provided, use digest (immutable reference)
Otherwise, use tag (or default to Chart.AppVersion)
*/}}
{{- define "auth-operator.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}
{{- end }}

{{/*
Image pull policy
*/}}
{{- define "auth-operator.imagePullPolicy" -}}
{{ .Values.image.pullPolicy | default "IfNotPresent" }}
{{- end }}

{{/*
Standard egress rules for operator pods (DNS + kube-apiserver).
Both the controller-manager and the webhook-server need DNS resolution
and kube-apiserver access, so this helper avoids duplicating the block.

NOTE: When the kube-apiserver runs outside the cluster (e.g. managed Kubernetes
with an external control plane), the egress rules rely on
networkPolicy.egress.apiServerCIDR being set explicitly.  Without it, the
apiserver egress rule has no `to:` selector and defaults to "allow to all
destinations on ports 443/6443", which is broader than ideal but still
limits the allowed ports.
*/}}
{{- define "auth-operator.egressRules" -}}
# DNS — allow CoreDNS resolution (UDP + TCP 53)
- ports:
    - port: 53
      protocol: UDP
    - port: 53
      protocol: TCP
  to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: {{ .Values.networkPolicy.egress.dnsNamespace | default "kube-system" | quote }}
# Kubernetes API server (TCP 443 and 6443)
- ports:
    - port: 443
      protocol: TCP
    - port: 6443
      protocol: TCP
  {{- if .Values.networkPolicy.egress.apiServerCIDR }}
  to:
    - ipBlock:
        cidr: {{ .Values.networkPolicy.egress.apiServerCIDR | quote }}
  {{- end }}
{{- if .Values.networkPolicy.egress.additionalRules }}
{{- toYaml .Values.networkPolicy.egress.additionalRules | nindent 0 }}
{{- end }}
{{- end }}


