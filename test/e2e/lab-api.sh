#!/usr/bin/env bash
# Ad-hoc admin API call on the lab core, as one of the lab users.
#   test/e2e/lab-api.sh [-u e2e_operator] GET /api/v1/fleet/sources
# Prints the HTTP code on stderr and the body on stdout. Passwords are read
# from the core host and never printed.
set -euo pipefail
E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$E2E_DIR/../.." && pwd)"
source "$REPO_DIR/test/lab/lib.sh"
source "$E2E_DIR/lab-lib.sh"
WORK="$STATE_DIR/e2e"; mkdir -p "$WORK"; CA_CERT="$STATE_DIR/pki/lab-ca.crt"
user=e2e_operator
if [[ "${1:-}" == -u ]]; then user="$2"; shift 2; fi
method="${1:?METHOD}"; path="${2:?path}"; data="${3:-}"
pw="$(ct "$CORE" "grep '^PW_$user=' /etc/tt-lab/credentials.env | cut -d= -f2-")"
[[ -f "$WORK/csrf.$user" ]] && { req "$user" GET /api/v1/auth/me; [[ "$CODE" == 200 ]] || login "$user" "$pw"; } || login "$user" "$pw"
req "$user" "$method" "$path" "$data"
echo "HTTP $CODE" >&2
printf '%s\n' "$BODY"
