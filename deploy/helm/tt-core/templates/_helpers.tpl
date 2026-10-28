{{- define "tt-core.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "tt-core.fullname" -}}
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

{{- define "tt-core.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "tt-core.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: traffic-twin
{{- end -}}

{{- define "tt-core.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tt-core.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "tt-core.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "tt-core.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "tt-core.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%v" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{/* Name of the Secret holding tls.crt, tls.key of the admin and intake listeners.
     Default <fullname>-tls: created by cert-manager, or by you (the pod waits for it). */}}
{{- define "tt-core.tlsSecretName" -}}
{{- if and (not .Values.tls.certManager.enabled) .Values.tls.existingSecret -}}
{{- .Values.tls.existingSecret -}}
{{- else -}}
{{- printf "%s-tls" (include "tt-core.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* Port numbers are read from the listen addresses so that values and config cannot drift. */}}
{{- define "tt-core.adminPort" -}}
{{- (splitList ":" .Values.config.admin.addr | last) | int -}}
{{- end -}}

{{- define "tt-core.intakePort" -}}
{{- (splitList ":" .Values.config.intake.addr | last) | int -}}
{{- end -}}
