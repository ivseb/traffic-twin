{{/* Port of the keyguard URL (default 7443). */}}
{{- define "tt-core.keyguardPort" -}}
{{- $host := (urlParse .Values.keyguard.url).host | default "" -}}
{{- if contains ":" $host -}}{{ splitList ":" $host | last }}{{- else -}}7443{{- end -}}
{{- end -}}

{{/* "host" or "host:port" as drift.webhook_allow wants it (443 is the default port). */}}
{{- define "tt-core.webhookEntry" -}}
{{- if and .port (ne (int .port) 443) -}}{{ printf "%s:%d" .host (int .port) }}{{- else -}}{{ .host }}{{- end -}}
{{- end -}}

{{/* The complete core.yaml: values.config plus what the chart derives from the other values. */}}
{{- define "tt-core.config" -}}
{{- $cfg := deepCopy .Values.config -}}
{{- $full := include "tt-core.fullname" . -}}
{{- $ns := .Release.Namespace -}}
{{- $intake := printf "%s-intake" $full -}}
{{- $fleet := default dict $cfg.fleet -}}
{{- if not $fleet.public_url -}}
{{- $_ := set $fleet "public_url" (printf "https://%s.%s.svc.cluster.local:%s" $intake $ns (include "tt-core.intakePort" .)) -}}
{{- end -}}
{{- if not $fleet.server_names -}}
{{- $_ := set $fleet "server_names" (list $intake (printf "%s.%s" $intake $ns) (printf "%s.%s.svc" $intake $ns) (printf "%s.%s.svc.cluster.local" $intake $ns)) -}}
{{- end -}}
{{- $_ := set $cfg "fleet" $fleet -}}
{{- $kg := dict "url" .Values.keyguard.url "timeout" .Values.keyguard.timeout -}}
{{- $_ := set $kg "client_cert_file" "/etc/tt/keyguard-client/tls.crt" -}}
{{- $_ := set $kg "client_key_file" "/etc/tt/keyguard-client/tls.key" -}}
{{- if .Values.keyguard.caFromSecret -}}{{- $_ := set $kg "ca_file" "/etc/tt/keyguard-client/ca.crt" -}}{{- end -}}
{{- if .Values.keyguard.serverPin -}}{{- $_ := set $kg "server_pin" .Values.keyguard.serverPin -}}{{- end -}}
{{- $_ := set $cfg "keyguard" $kg -}}
{{- $drift := default dict $cfg.drift -}}
{{- $allow := list -}}
{{- range .Values.webhooks -}}{{- $allow = append $allow (include "tt-core.webhookEntry" .) -}}{{- end -}}
{{- $_ := set $drift "webhook_allow" $allow -}}
{{- $_ := set $cfg "drift" $drift -}}
{{- $mm := .Values.mockManager -}}
{{- if $mm.enabled -}}
{{- $mock := default dict $cfg.mock -}}
{{- if not $mock.console_url -}}
{{- $_ := set $mock "console_url" (default (printf "https://%s.%s.svc.cluster.local:%d" $full $ns (include "tt-core.adminPort" . | int)) $mm.consoleURL) -}}
{{- end -}}
{{- if $mm.consoleCAFromTLSSecret -}}{{- $_ := set $mock "console_ca_file" "/etc/tt/tls/ca.crt" -}}{{- end -}}
{{- $_ := set $mock "image" (default (include "tt-core.image" .) $mm.image) -}}
{{- $k := dict "enabled" true "namespace" (default $ns $mm.namespace) "route" $mm.route -}}
{{- with $mm.serviceAccount -}}{{- $_ := set $k "service_account" . -}}{{- end -}}
{{- with $mm.resources.cpuRequest -}}{{- $_ := set $k "cpu_request" . -}}{{- end -}}
{{- with $mm.resources.memoryRequest -}}{{- $_ := set $k "memory_request" . -}}{{- end -}}
{{- with $mm.resources.cpuLimit -}}{{- $_ := set $k "cpu_limit" . -}}{{- end -}}
{{- with $mm.resources.memoryLimit -}}{{- $_ := set $k "memory_limit" . -}}{{- end -}}
{{- $_ := set $mock "kubernetes" $k -}}
{{- $_ := set $cfg "mock" $mock -}}
{{- end -}}
{{- toYaml $cfg -}}
{{- end -}}
