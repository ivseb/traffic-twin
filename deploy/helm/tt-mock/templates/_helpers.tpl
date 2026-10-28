{{- define "tt-mock.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "tt-mock.fullname" -}}
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

{{- define "tt-mock.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "tt-mock.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: traffic-twin
{{- end -}}

{{- define "tt-mock.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tt-mock.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "tt-mock.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "tt-mock.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "tt-mock.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%v" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{/* URL the tests use, shown on the Mock page of the console. */}}
{{- define "tt-mock.publicURL" -}}
{{- if .Values.console.publicURL -}}
{{- .Values.console.publicURL -}}
{{- else if and .Values.route.enabled .Values.route.host -}}
{{- printf "https://%s" .Values.route.host -}}
{{- else -}}
{{- printf "http://%s.%s.svc.cluster.local:%v" (include "tt-mock.fullname" .) .Release.Namespace .Values.service.port -}}
{{- end -}}
{{- end -}}

{{/* Port of the console URL (443 by default). */}}
{{- define "tt-mock.consolePort" -}}
{{- $u := urlParse .Values.console.url -}}
{{- if contains ":" $u.host -}}{{ splitList ":" $u.host | last }}{{- else if eq $u.scheme "http" -}}80{{- else -}}443{{- end -}}
{{- end -}}

{{- define "tt-mock.packImage" -}}
{{- $i := .Values.pack.image -}}
{{- if $i.digest -}}
{{- printf "%s@%s" $i.repository $i.digest -}}
{{- else -}}
{{- printf "%s:%v" $i.repository $i.tag -}}
{{- end -}}
{{- end -}}

{{/* Which pack source is active: console, pvc, configmap, image or none. */}}
{{- define "tt-mock.packSource" -}}
{{- if .Values.console.url -}}console
{{- else if .Values.pack.persistentVolumeClaim -}}pvc
{{- else if .Values.pack.configMap -}}configmap
{{- else if .Values.pack.image.repository -}}image
{{- else -}}none
{{- end -}}
{{- end -}}
