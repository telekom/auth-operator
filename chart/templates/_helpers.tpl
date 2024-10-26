{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "authn-authz-operator.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "authn-authz-operator.fullname" -}}
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
{{- define "authn-authz-operator.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Define binder labels for frequently used metadata.
*/}}
{{- define "authn-authz-operator.labels.binder" -}}
app: binder-{{ template "authn-authz-operator.name" . }}
chart: "{{ .Chart.Name }}-{{ .Chart.Version }}"
release: "{{ .Release.Name }}"
heritage: "{{ .Release.Service }}"
{{- end -}}

{{/*
Define generator labels for frequently used metadata.
*/}}
{{- define "authn-authz-operator.labels.generator" -}}
app: generator-{{ template "authn-authz-operator.name" . }}
chart: "{{ .Chart.Name }}-{{ .Chart.Version }}"
release: "{{ .Release.Name }}"
heritage: "{{ .Release.Service }}"
{{- end -}}

{{/*
Define idp labels for frequently used metadata.
*/}}
{{- define "authn-authz-operator.labels.idp" -}}
app: idp-{{ template "authn-authz-operator.name" . }}
chart: "{{ .Chart.Name }}-{{ .Chart.Version }}"
release: "{{ .Release.Name }}"
heritage: "{{ .Release.Service }}"
{{- end -}}

{{/*
Create the name of the service account to use
*/}}
{{- define "authn-authz-operator.serviceAccountName" -}}
{{- if .Values.global.serviceAccount.create -}}
    {{ default (include "authn-authz-operator.fullname" .) .Values.global.serviceAccount.name }}
{{- else -}}
    {{ default "default" .Values.global.serviceAccount.name }}
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
