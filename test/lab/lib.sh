#!/usr/bin/env bash
# Shared helpers of the traffic-twin multi-host lab scripts (source this file).
#
# Three Linux hosts (VMs, containers or bare metal) reachable over SSH, each
# one with a role (see test/lab/README.md):
#   demo      LAB_HOST_DEMO      demo stack (Docker), tt-mock, WireMock
#   keyguard  LAB_HOST_KEYGUARD  tt keyguard (mTLS :7443)
#   core      LAB_HOST_CORE      tt core (admin :7443, intake :4318)
# A host is a DNS name or an IP address; the defaults are documentation
# placeholders and must be overridden.
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$LAB_DIR/../.." && pwd)"
STATE_DIR="${LAB_STATE:-$LAB_DIR/.state}"

DEMO=demo; KG=keyguard; CORE=core
DEMO_HOST="${LAB_HOST_DEMO:-demo.lab.example}"
KG_HOST="${LAB_HOST_KEYGUARD:-keyguard.lab.example}"
CORE_HOST="${LAB_HOST_CORE:-core.lab.example}"
# The keyguard unit only lets tt-core in (IPAddressAllow=): an IP address or prefix.
CORE_ALLOW_IP="${LAB_CORE_ALLOW_IP:-192.0.2.12}"
# The scripts install packages, users and systemd units: the SSH user needs root rights.
LAB_SSH_USER="${LAB_SSH_USER:-root}"
SSH_OPTS=(-o BatchMode=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="${LAB_KNOWN_HOSTS:-$HOME/.ssh/known_hosts_tt_lab}" -o LogLevel=ERROR)
# Optional jump host (ssh -J), e.g. LAB_SSH_JUMP=user@bastion.lab.example
if [[ -n "${LAB_SSH_JUMP:-}" ]]; then SSH_OPTS+=(-J "$LAB_SSH_JUMP"); fi

log() { printf '\033[1m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
die() { printf '\033[31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# host_of <role>: the address of a lab host.
host_of() {
  case "$1" in
    "$DEMO") echo "$DEMO_HOST" ;;
    "$KG") echo "$KG_HOST" ;;
    "$CORE") echo "$CORE_HOST" ;;
    *) die "unknown lab role $1 (demo, keyguard, core)" ;;
  esac
}

# san_of <host>: subjectAltName entry of a host (IP: for an address, DNS: for a name).
san_of() {
  if [[ "$1" =~ ^[0-9.]+$ || "$1" == *:* ]]; then echo "IP:$1"; else echo "DNS:$1"; fi
}

# ct <role> <command...>: run a command on a lab host as LAB_SSH_USER.
ct() { local h; h="$(host_of "$1")"; shift; ssh "${SSH_OPTS[@]}" "$LAB_SSH_USER@$h" "$@"; }

# put <role> <local> <remote> [mode]: copy a file to a lab host.
put() {
  local id="$1" src="$2" dst="$3" mode="${4:-}"
  scp -q "${SSH_OPTS[@]}" "$src" "$LAB_SSH_USER@$(host_of "$id"):$dst"
  if [[ -n "$mode" ]]; then ct "$id" "chmod $mode '$dst'"; fi
}

# get <role> <remote> <local>
get() { scp -q "${SSH_OPTS[@]}" "$LAB_SSH_USER@$(host_of "$1"):$2" "$3"; }

mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"
