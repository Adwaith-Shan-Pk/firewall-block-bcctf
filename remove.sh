#!/usr/bin/env bash
# Removes everything created by setup.sh (Linux / nftables)
set -euo pipefail

TABLE="ctf_fw"

[[ $EUID -eq 0 ]] || { echo "ERROR: run as root (sudo $0)" >&2; exit 1; }
command -v nft >/dev/null || { echo "ERROR: 'nft' is required" >&2; exit 1; }

if nft list table inet "$TABLE" >/dev/null 2>&1; then
  nft delete table inet "$TABLE"
  echo "[+] Removed nft table 'inet $TABLE'. Firewall restrictions lifted."
else
  echo "[*] Nothing to remove (table 'inet $TABLE' not found)."
fi
