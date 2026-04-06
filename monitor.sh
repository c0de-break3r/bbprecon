#!/usr/bin/bash
# New-asset monitoring (from workflow video): subfinder + haktrails -> anew -> notify.
# Schedule with cron or: while :; do ./monitor.sh; sleep 3600; done
#
# Required: subfinder, anew, notify (ProjectDiscovery notify)
# Optional: haktrails + SecurityTrails API config
#
# export NOTIFY_WEBHOOK_URL or configure notify provider YAML.

set -euo pipefail

domain="${DOMAIN:-target.com}"
file_name="${SUBDOMAIN_DB:-$HOME/recon/${domain}/all_subdomains_history.txt}"
mkdir -p "$(dirname "$file_name")"

if command -v subfinder >/dev/null 2>&1; then
  subfinder -d "$domain" -silent -nc -all | tr '[:upper:]' '[:lower:]' | anew "$file_name" | notify || true
else
  echo "[-] subfinder not found" >&2
fi

if command -v haktrails >/dev/null 2>&1; then
  echo "$domain" | haktrails subdomains | tr '[:upper:]' '[:lower:]' | anew "$file_name" | notify || true
else
  echo "[-] haktrails not found (optional)" >&2
fi
