{{- define "tt-egress.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "tt-egress.fullname" -}}
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

{{- define "tt-egress.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "tt-egress.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: traffic-twin
{{- end -}}

{{- define "tt-egress.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tt-egress.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "tt-egress.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "tt-egress.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "tt-egress.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%v" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{- define "tt-egress.serviceName" -}}
{{- default (include "tt-egress.fullname" .) .Values.enroll.serviceName -}}
{{- end -}}

{{/* The tt-egress YAML configuration. Argument: dict "ctx" . "listen" "<addr>". */}}
{{- define "tt-egress.config" -}}
{{- $cfg := dict "listen" .listen -}}
{{- $ups := list -}}
{{- range .ctx.Values.upstreams -}}
{{- $u := dict "alias" .alias "url" .url -}}
{{- if .captureOrigin }}{{- $_ := set $u "capture_origin" .captureOrigin -}}{{- end -}}
{{- if .caFile }}{{- $_ := set $u "ca_file" .caFile -}}{{- end -}}
{{- $ups = append $ups $u -}}
{{- end -}}
{{- if $ups }}{{- $_ := set $cfg "upstreams" $ups -}}{{- end -}}
{{- toYaml (mergeOverwrite $cfg (deepCopy .ctx.Values.extraConfig)) -}}
{{- end -}}

{{/* The tt-egress container, shared by the Deployment and the sidecar snippet.
     Argument: dict "ctx" . "port" <int>. Mounts expected: tt-egress-config, tt-egress-state, tt-egress-hmac. */}}
{{- define "tt-egress.container" -}}
{{- $v := .ctx.Values -}}
name: tt-egress
image: {{ include "tt-egress.image" .ctx | quote }}
imagePullPolicy: {{ $v.image.pullPolicy }}
args: ["egress"]
env:
  - name: TT_EGRESS_CONFIG
    value: /etc/tt/egress/egress.yaml
  - name: TT_STATE_DIR
    value: /var/lib/tt/state
  - name: TT_SERVICE_NAME
    value: {{ include "tt-egress.serviceName" .ctx | quote }}
  {{- if $v.enroll.url }}
  - name: TT_ENROLL_URL
    value: {{ $v.enroll.url | quote }}
  {{- end }}
  {{- if $v.enroll.tokenSecret.name }}
  - name: TT_ENROLL_TOKEN
    valueFrom:
      secretKeyRef:
        name: {{ $v.enroll.tokenSecret.name }}
        key: {{ $v.enroll.tokenSecret.key }}
  {{- end }}
  {{- if $v.hmacKey.existingSecret }}
  - name: TT_HMAC_KEY_FILE
    value: /etc/tt/hmac/{{ $v.hmacKey.key }}
  {{- end }}
ports:
  - name: proxy
    containerPort: {{ .port }}
    protocol: TCP
securityContext:
  {{- toYaml $v.securityContext | nindent 2 }}
resources:
  {{- toYaml $v.resources | nindent 2 }}
volumeMounts:
  - name: tt-egress-config
    mountPath: /etc/tt/egress
    readOnly: true
  - name: tt-egress-state
    mountPath: /var/lib/tt/state
  {{- if $v.hmacKey.existingSecret }}
  - name: tt-egress-hmac
    mountPath: /etc/tt/hmac
    readOnly: true
  {{- end }}
  {{- with $v.extraVolumeMounts }}
  {{- toYaml . | nindent 2 }}
  {{- end }}
{{- end -}}

{{/* The volumes the container above mounts. Argument: dict "ctx" . "configMap" "<name>". */}}
{{- define "tt-egress.volumes" -}}
{{- $v := .ctx.Values -}}
- name: tt-egress-config
  configMap:
    name: {{ .configMap }}
    defaultMode: 0444
- name: tt-egress-state
  emptyDir:
    sizeLimit: 16Mi
{{- if $v.hmacKey.existingSecret }}
- name: tt-egress-hmac
  secret:
    secretName: {{ $v.hmacKey.existingSecret }}
    defaultMode: 0440
    items:
      - key: {{ $v.hmacKey.key }}
        path: {{ $v.hmacKey.key }}
{{- end }}
{{- with $v.extraVolumes }}
{{ toYaml . }}
{{- end }}
{{- end -}}
