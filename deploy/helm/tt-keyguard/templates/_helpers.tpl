{{- define "tt-keyguard.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "tt-keyguard.fullname" -}}
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

{{- define "tt-keyguard.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "tt-keyguard.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: traffic-twin
{{- end -}}

{{- define "tt-keyguard.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tt-keyguard.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "tt-keyguard.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "tt-keyguard.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "tt-keyguard.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%v" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{- define "tt-keyguard.installerImage" -}}
{{- $i := .Values.keys.installer.image -}}
{{- if $i.digest -}}
{{- printf "%s@%s" $i.repository $i.digest -}}
{{- else -}}
{{- printf "%s:%v" $i.repository $i.tag -}}
{{- end -}}
{{- end -}}

{{- define "tt-keyguard.tlsSecret" -}}
{{- default (printf "%s-tls" (include "tt-keyguard.fullname" .)) .Values.tls.existingSecret -}}
{{- end -}}

{{- define "tt-keyguard.keysSecret" -}}
{{- default (printf "%s-keys" (include "tt-keyguard.fullname" .)) .Values.keys.existingSecret -}}
{{- end -}}

{{- define "tt-keyguard.port" -}}
{{- (splitList ":" .Values.listen | last) | int -}}
{{- end -}}

{{/* Directory the keyguard process reads key material from. */}}
{{- define "tt-keyguard.keyDir" -}}/keys{{- end -}}
