# Recon

Python-driven recon pipeline that runs common CLI tools in sequence, stores dated artifacts under a per-domain directory, optionally pings a Discord webhook on interesting findings, and emits a simple HTML report.

## What it runs

| Stage | Tool | Notes |
|--------|------|--------|
| Subdomains | `subfinder`, `assetfinder`, `amass` | Amass uses passive enum only (no root required). |
| Live hosts + tech | ProjectDiscovery `httpx` | Must be the PD binary, not the Python HTTPX CLI. |
| Templates | `nuclei` | Severities: critical, high, medium. |
| Ports | `nmap` | Top 1000 ports per host; optional skip flag. |
| Screenshots | `eyewitness` | Skipped if not installed. |

A separate shell script, `monitor.sh`, is meant for scheduled **new-subdomain** checks using `subfinder`, `anew`, `notify`, and optionally `haktrails`.

## Requirements

- Python 3.10+ (uses `Path | None` style hints).
- External tools on `PATH` as needed: `subfinder`, `assetfinder`, `amass`, ProjectDiscovery `httpx`, `nuclei`, `nmap`, `eyewitness`.
- For monitoring: ProjectDiscovery `notify`, `anew`; optional `haktrails` with its config.

## Output layout

Default base directory: `~/recon` or `$RECON_BASE`.

```
<base>/<domain>/
  scans/
    all_subdomains_YYYYMMDD.txt
    alive_hosts_YYYYMMDD.txt
    nuclei_YYYYMMDD.txt
    httpx_YYYYMMDD.jsonl
    nmap_<host>_YYYYMMDD.txt
    eyewitness/
  results/
    report_YYYYMMDD.html
```

## Usage

```bash
chmod +x recon.py monitor.sh   # once

./recon.py example.com
./recon.py example.com --base-dir /path/to/output
./recon.py example.com --skip-nmap
```

Monitoring (example):

```bash
export DOMAIN=example.com
export SUBDOMAIN_DB="$HOME/recon/example.com/all_subdomains_history.txt"
./monitor.sh
```

Run periodically with `cron` or a loop, for example:

```bash
while :; do ./monitor.sh; sleep 3600; done
```

## Environment variables

| Variable | Purpose |
|----------|---------|
| `RECON_BASE` | Default parent directory for all targets (instead of `~/recon`). |
| `RECON_HTTPX` | Full path to ProjectDiscovery `httpx` if another `httpx` appears first on `PATH`. |
| `DISCORD_WEBHOOK_URL` or `NOTIFY_WEBHOOK_URL` | JSON webhook used by `recon.py` for nuclei hits and “interesting” nmap ports. |
| `DOMAIN` | Target domain for `monitor.sh` (default `target.com` placeholder). |
| `SUBDOMAIN_DB` | Path to the historical subdomain file for `anew` in `monitor.sh`. |

Configure `notify` (and `haktrails` if used) per upstream docs; `monitor.sh` expects `notify` on `PATH`.

## Local helper

`error_lookup.html` is a static page you can open in a browser: search filters common CLI error strings by category. It does not run the pipeline.

## Legal use

Use only against systems you are authorized to test. Scope and program rules always override this tooling.
