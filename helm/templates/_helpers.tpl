{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "t-caas-rbac-generator.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "t-caas-rbac-generator.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "t-caas-rbac-generator.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Define standard labels for frequently used metadata.
*/}}
{{- define "t-caas-rbac-generator.labels.standard" -}}
app: {{ template "t-caas-rbac-generator.name" . }}
chart: "{{ .Chart.Name }}-{{ .Chart.Version }}"
release: "{{ .Release.Name }}"
heritage: "{{ .Release.Service }}"
{{- end -}}

{{/*
Create the name of the service account to use
*/}}
{{- define "t-caas-rbac-generator.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
    {{ default (include "t-caas-rbac-generator.fullname" .) .Values.serviceAccount.name }}
{{- else -}}
    {{ default "default" .Values.serviceAccount.name }}
{{- end -}}
{{- end -}}

{{/*
Template image tag.
*/}}
{{- define "caas-image-template" }}
{{- if .repository -}}
{{- printf "%s/%s/%s:%s" (required (printf "missing %s.%s" . .registry) (trimSuffix "/" .registry)) (trimAll "/" .repository) (required (printf "missing %s.%s" . .name) (trimAll "/" .name)) (required (printf "missing %s.%s" . .tag) .tag) }}
{{- else -}}
{{- printf "%s/%s:%s" (required (printf "missing %s.%s" . .registry) (trimSuffix "/" .registry)) (required (printf "missing %s.%s" . .name) (trimAll "/" .name)) (required (printf "missing %s.%s" . .tag) .tag) }}
{{- end }}
{{- end }}
