#!/usr/bin/env bash
# Admin API helpers for test/e2e/lab-e2e.sh (source this file).
# Sessions use the cookie + CSRF header scheme of tt-core; one cookie jar per user.

CORE_HOST="${CORE_HOST:-${LAB_HOST_CORE:-core.lab.example}}"
DEMO_HOST="${DEMO_HOST:-${LAB_HOST_DEMO:-demo.lab.example}}"
CORE_URL="${CORE_URL:-https://$CORE_HOST:7443}"
MOCK_URL="${MOCK_URL:-http://$DEMO_HOST:8480}"

PASS=0; FAIL=0; FAILED=()
log()  { printf '\033[1m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
warn() { printf '\033[33m[%s] WARN\033[0m %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
die()  { printf '\033[31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# check <description> <command...>: records a pass/fail without stopping.
check() {
  local what="$1"; shift
  if "$@" >/dev/null 2>&1; then PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m %s\n' "$what" >&2
  else FAIL=$((FAIL+1)); FAILED+=("$what"); printf '  \033[31mFAIL\033[0m %s\n' "$what" >&2; fi
}
# gap <description> <command...>: a product gap found by the lab (ground truth of the demo not reproduced).
# It is reported and counted but does not fail the run; the lab report lists them.
GAPS=()
gap() {
  local what="$1"; shift
  if "$@" >/dev/null 2>&1; then printf '  \033[32mPASS\033[0m %s\n' "$what" >&2
  else GAPS+=("$what"); printf '  \033[33mGAP \033[0m %s\n' "$what" >&2; fi
}
# eq <description> <got> <want>
eq() { check "$1 (got '$2', want '$3')" test "$2" = "$3"; }
# ge <description> <got> <min>
ge() { check "$1 (got $2, want >= $3)" test "${2:-0}" -ge "$3"; }

# req <user> <METHOD> <path> [json body | @file]: sets CODE and BODY.
# 429 (login rate limit) is retried after Retry-After.
req() {
  local user="$1" method="$2" path="$3" data="${4:-}" out hdr tries=0
  local jar="$WORK/jar.$user" csrf="" args=()
  [[ -f "$WORK/csrf.$user" ]] && csrf="$(<"$WORK/csrf.$user")"
  args=(-sS -m 120 --cacert "$CA_CERT" -b "$jar" -c "$jar" -X "$method" -w $'\n%{http_code}')
  [[ -n "$csrf" && "$method" != GET ]] && args+=(-H "X-CSRF-Token: $csrf")
  if [[ -n "$data" ]]; then
    case "$data" in
      @*) args+=(-H 'Content-Type: application/json' --data-binary "$data") ;;
      *) args+=(-H 'Content-Type: application/json' --data-binary "$data") ;;
    esac
  fi
  while :; do
    out="$(curl "${args[@]}" "$CORE_URL$path")" || { CODE=000; BODY=""; return 0; }
    CODE="${out##*$'\n'}"; BODY="${out%$'\n'*}"
    if [[ "$CODE" == 429 && $tries -lt 8 ]]; then tries=$((tries+1)); sleep $((tries * 7)); continue; fi
    return 0
  done
}

# login <user> <password>: opens a session, stores the CSRF token.
login() {
  local user="$1" pass="$2"
  rm -f "$WORK/jar.$user" "$WORK/csrf.$user"
  req "$user" POST /api/v1/auth/login "$(jq -nc --arg u "$user" --arg p "$pass" '{username:$u,password:$p}')"
  [[ "$CODE" == 200 ]] || { warn "login $user: HTTP $CODE"; return 1; }
  jq -r '.csrf_token' <<<"$BODY" >"$WORK/csrf.$user"
}

# jqb <filter>: jq over the last BODY.
jqb() { jq -r "$@" <<<"$BODY"; }
# expect <what> <codes...>: the last call must have returned one of the codes.
expect() {
  local what="$1"; shift
  local c
  for c in "$@"; do [[ "$CODE" == "$c" ]] && return 0; done
  die "$what: HTTP $CODE (want $*): ${BODY:0:400}"
}

# follow_job <user>: a long operation answers 202 with its job, finished or
# still running when it takes longer than the server wait (admin API "Jobs");
# a running job is polled at GET /api/v1/jobs/{id} until it ends, and BODY
# becomes the final job. Gives up after JOB_TIMEOUT seconds (default 900).
follow_job() {
  local user="$1" id deadline
  [[ "$CODE" == 202 && "$(jqb '.status' 2>/dev/null)" == running ]] || return 0
  id="$(jqb '.id // .job_id')"
  deadline=$(( $(date +%s) + ${JOB_TIMEOUT:-900} ))
  log "job $id still running, following it"
  while [[ "$(jqb '.status' 2>/dev/null)" == running ]]; do
    [[ $(date +%s) -lt $deadline ]] || die "timeout following job $id"
    sleep 5
    req "$user" GET "/api/v1/jobs/$id"; expect "job $id" 200
  done
  CODE=202
}

# mockc <METHOD> <path> [json] [session]: data/control calls on tt-mock.
mockc() {
  local method="$1" path="$2" data="${3:-}" sess="${4:-}" out args
  args=(-sS -m 60 -X "$method" -w $'\n%{http_code}' -H "Authorization: Bearer ${MOCK_TOKEN:-}")
  if [[ "$path" == /__svc/* ]]; then
    # data plane: the contracts inferred from real traffic list as required every header the callers
    # sent (also transport ones: accept-encoding, user-agent, sec-fetch-mode, ...), so a client must send them
    args=(-sS -m 60 -X "$method" -w $'\n%{http_code}' -H 'Authorization: Bearer synthetic-lab-token' \
      -H 'traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01' \
      -H 'Accept: */*' -H 'Accept-Language: *' -H 'Sec-Fetch-Mode: cors' -H 'Accept-Encoding: gzip' \
      -H "Idempotency-Key: $(openssl rand -hex 8)" -A 'tt-lab-e2e')
  fi
  [[ -n "$sess" ]] && args+=(-H "X-TT-Session: $sess")
  [[ -n "$data" ]] && args+=(-H 'Content-Type: application/json' --data-binary "$data")
  out="$(curl "${args[@]}" "$MOCK_URL$path")" || { CODE=000; BODY=""; return 0; }
  CODE="${out##*$'\n'}"; BODY="${out%$'\n'*}"
}
