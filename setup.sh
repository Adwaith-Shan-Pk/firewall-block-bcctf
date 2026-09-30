#!/usr/bin/env bash
# CTF firewall setup (Linux / nftables)
#   - Resolves every domain in the blocklist and rejects outbound traffic to those IPs on the listed ports
#   - Resolves the CTF whitelist hosts and always allows them (on the whitelisted TCP ports) BEFORE the block rules
#   - Everything lives in one nft table ("inet ctf_fw"), so remove.sh cleans it up completely
#
# Usage: sudo ./setup.sh [whitelist_file] [blocklist_file]
# Re-run any time to refresh DNS results (it is idempotent).

# Re-launch under bash if started with sh/dash (they don't support pipefail)
[ -n "${BASH_VERSION:-}" ] || exec bash "$0" "$@"

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WHITELIST="${1:-$SCRIPT_DIR/ctf_whitelist.txt}"
BLOCKLIST="${2:-$SCRIPT_DIR/ai_blocklist.txt}"
TABLE="ctf_fw"
JOBS=16

die() { echo "ERROR: $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root (sudo $0)"
for c in nft getent awk sed xargs; do command -v "$c" >/dev/null || die "'$c' is required"; done
[[ -r $WHITELIST ]] || die "cannot read whitelist: $WHITELIST"
[[ -r $BLOCKLIST ]] || die "cannot read blocklist: $BLOCKLIST"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Strip CRs, comments, blank lines, surrounding whitespace
clean() {
  tr -d '\r' < "$1" \
    | sed -e 's/[[:space:]]*#.*$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' \
    | awk 'NF'
}

# Prints "host ip" lines for each address the host resolves to
resolve_one() {
  getent ahosts "$1" 2>/dev/null | awk -v h="$1" '{print h, $1}' | sort -u || true
  return 0
}
export -f resolve_one
resolve_hosts() { xargs -P "$JOBS" -I{} bash -c 'resolve_one "$1"' _ {} | sort -u; }

# Loopback / unspecified / private / link-local / v4-mapped: never block these (sinkholed DNS, LAN, etc.)
UNSAFE4='^(0\.|127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.)'
UNSAFE6='^(::1?|::ffff:|fe80:|f[cd][0-9a-f]{2}:)'

# ---------------------------------------------------------------- whitelist
clean "$WHITELIST" | { grep -Eiv '^(tcp|udp):' || true; } \
  | sed -E 's#^[A-Za-z]+://##; s#^\*\.##; s#[/:].*$##' \
  | tr 'A-Z' 'a-z' | sort -u > "$WORK/ctf_hosts"

TCP_PORTS="$(clean "$WHITELIST" | { grep -Ei '^tcp:' || true; } \
  | sed -E 's/^[Tt][Cc][Pp]:[[:space:]]*//' | tr ',' '\n' | tr -d ' \t' | awk 'NF' | paste -sd, -)"

[[ -n $TCP_PORTS ]] || die "no 'TCP:' port lines found in $WHITELIST"
[[ $TCP_PORTS =~ ^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$ ]] || die "could not parse TCP ports: $TCP_PORTS"
if clean "$WHITELIST" | grep -Eiq '^udp:'; then echo "WARN: UDP whitelist lines are ignored by this script."; fi

echo "[*] Resolving $(wc -l < "$WORK/ctf_hosts") CTF host(s)..."
resolve_hosts < "$WORK/ctf_hosts" > "$WORK/ctf_resolved"
CTF4="$(awk '$2 !~ /:/ {print $2}' "$WORK/ctf_resolved" | sort -u | paste -sd, - || true)"
CTF6="$(awk '$2 ~  /:/ {print $2}' "$WORK/ctf_resolved" | sort -u | paste -sd, - || true)"
[[ -n $CTF4$CTF6 ]] || echo "WARN: no CTF hosts resolved - whitelist will be empty."

# ---------------------------------------------------------------- blocklist
# host:port -> "host port"
clean "$BLOCKLIST" | { grep -E '^[^:]+:[0-9]+$' || true; } | tr 'A-Z' 'a-z' | sort -u | tr ':' ' ' > "$WORK/ai_hp"
awk '{print $1}' "$WORK/ai_hp" | sort -u > "$WORK/ai_hosts"

echo "[*] Resolving $(wc -l < "$WORK/ai_hosts") blocklisted host(s) (this can take a minute)..."
resolve_hosts < "$WORK/ai_hosts" > "$WORK/ai_resolved"

# Join resolved IPs with each host's ports -> "ip port"
awk 'NR==FNR { p[$1] = p[$1] " " $2; next }
     { n = split(p[$1], a, " "); for (i = 1; i <= n; i++) print $2, a[i] }' \
  "$WORK/ai_hp" "$WORK/ai_resolved" | sort -u > "$WORK/ai_ip_port"

AI4="$(awk '$1 !~ /:/' "$WORK/ai_ip_port" | { grep -Ev "$UNSAFE4" || true; } | awk '{printf "%s%s . %s", (NR>1?", ":""), $1, $2}')"
AI6="$(awk '$1 ~  /:/' "$WORK/ai_ip_port" | { grep -Eiv "$UNSAFE6" || true; } | awk '{printf "%s%s . %s", (NR>1?", ":""), $1, $2}')"

UNRESOLVED="$(comm -23 "$WORK/ai_hosts" <(awk '{print $1}' "$WORK/ai_resolved" | sort -u) | wc -l)"

# ---------------------------------------------------------------- ruleset
{
  echo "table inet $TABLE"
  echo "delete table inet $TABLE"
  echo "table inet $TABLE {"
  echo "  set ctf_v4 { type ipv4_addr; }"
  echo "  set ctf_v6 { type ipv6_addr; }"
  echo "  set ai_v4  { type ipv4_addr . inet_service; }"
  echo "  set ai_v6  { type ipv6_addr . inet_service; }"
  # 'output' covers this machine; 'forward' covers routed traffic (containers, VMs, NAT gateway)
  for hook in output forward; do
    cat <<EOF
  chain $hook {
    type filter hook $hook priority 0; policy accept;
    ip  daddr @ctf_v4 tcp dport { $TCP_PORTS } counter accept
    ip6 daddr @ctf_v6 tcp dport { $TCP_PORTS } counter accept
    ip  daddr . tcp dport @ai_v4 counter reject with tcp reset
    ip  daddr . udp dport @ai_v4 counter reject
    ip6 daddr . tcp dport @ai_v6 counter reject with tcp reset
    ip6 daddr . udp dport @ai_v6 counter reject
  }
EOF
  done
  echo "}"
  [[ -z $CTF4 ]] || echo "add element inet $TABLE ctf_v4 { $CTF4 }"
  [[ -z $CTF6 ]] || echo "add element inet $TABLE ctf_v6 { $CTF6 }"
  [[ -z $AI4  ]] || echo "add element inet $TABLE ai_v4 { $AI4 }"
  [[ -z $AI6  ]] || echo "add element inet $TABLE ai_v6 { $AI6 }"
} > "$WORK/rules.nft"

nft -c -f "$WORK/rules.nft" || die "generated ruleset failed validation"
nft -f "$WORK/rules.nft"

echo "[+] Applied nft table 'inet $TABLE'"
echo "    CTF whitelist : $(wc -l < "$WORK/ctf_hosts") hosts -> $(awk '{print $2}' "$WORK/ctf_resolved" | sort -u | wc -l) IPs, TCP ports $TCP_PORTS"
echo "    AI blocklist  : $(wc -l < "$WORK/ai_hosts") hosts -> $(wc -l < "$WORK/ai_ip_port") ip:port entries ($UNRESOLVED host(s) did not resolve)"
echo "    Inspect hits  : sudo nft list table inet $TABLE"
echo "    Remove        : sudo ./remove.sh"
