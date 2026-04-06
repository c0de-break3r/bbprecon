#!/usr/bin/env python3
"""
Bug bounty recon automation — chains subfinder, assetfinder, amass, httpx,
nuclei, nmap, eyewitness; writes dated artifacts and optional HTML report.
Webhook: set DISCORD_WEBHOOK_URL (or NOTIFY_WEBHOOK_URL).
"""

from __future__ import annotations

import argparse
import html
import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path


class ReconAutomator:
    def __init__(self, target: str, base_dir: Path | None = None) -> None:
        self.target = target.strip().lower()
        self.date = datetime.now().strftime("%Y%m%d")
        root = base_dir or Path(os.environ.get("RECON_BASE", Path.home() / "recon"))
        self.root = root / self.target
        self.scans_dir = self.root / "scans"
        self.results_dir = self.root / "results"
        self.screenshot_dir = self.scans_dir / "eyewitness"

    def setup_dirs(self) -> None:
        self.scans_dir.mkdir(parents=True, exist_ok=True)
        self.results_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def check_tool_installed(name: str) -> bool:
        return shutil.which(name) is not None

    @staticmethod
    def projectdiscovery_httpx_bin() -> str | None:
        override = os.environ.get("RECON_HTTPX")
        if override and Path(override).is_file():
            return override
        for cand in ("httpx",):
            path = shutil.which(cand)
            if not path:
                continue
            try:
                r = subprocess.run(
                    [cand, "--help"],
                    capture_output=True,
                    text=True,
                    timeout=8,
                )
                help_text = (r.stdout or "") + (r.stderr or "")
                if "projectdiscovery" in help_text.lower():
                    return cand
                if "-l" in help_text and "-list" in help_text.lower():
                    return cand
            except (OSError, subprocess.TimeoutExpired):
                continue
        return None

    @staticmethod
    def run_command(cmd: str, *, shell: bool = True) -> int:
        return subprocess.call(cmd, shell=shell)

    def send_notification(self, title: str, message: str) -> None:
        url = os.environ.get("DISCORD_WEBHOOK_URL") or os.environ.get("NOTIFY_WEBHOOK_URL")
        if not url:
            return
        payload = json.dumps(
            {"embeds": [{"title": title, "description": message[:1900]}]}
        ).encode()
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=15)
        except urllib.error.URLError:
            print("[-] Webhook notification failed")

    def print_banner(self) -> None:
        box = (
            "┌─────────────────────────────────────────────┐\n"
            "│  BUG BOUNTY RECON AUTOMATION SUITE          │\n"
            "│  Automating subdomain discovery & scanning  │\n"
            "└─────────────────────────────────────────────┘"
        )
        print(box)

    def subdomain_file(self) -> Path:
        return self.scans_dir / f"all_subdomains_{self.date}.txt"

    def alive_file(self) -> Path:
        return self.scans_dir / f"alive_hosts_{self.date}.txt"

    def nuclei_file(self) -> Path:
        return self.scans_dir / f"nuclei_{self.date}.txt"

    def report_file(self) -> Path:
        return self.results_dir / f"report_{self.date}.html"

    def enumerate_subdomains(self) -> Path:
        out = self.subdomain_file()
        subs: set[str] = set()

        print("[*] Starting subdomain enumeration")

        if self.check_tool_installed("subfinder"):
            print("[+] Running Subfinder")
            p = subprocess.run(
                ["subfinder", "-d", self.target, "-silent", "-nc", "-all"],
                capture_output=True,
                text=True,
            )
            for line in (p.stdout or "").splitlines():
                h = line.strip().lower()
                if h:
                    subs.add(h)
                    print(h)
        else:
            print("[-] subfinder not in PATH. Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")

        if self.check_tool_installed("assetfinder"):
            print("[+] Running Assetfinder")
            p = subprocess.run(
                ["assetfinder", "--subs-only", self.target],
                capture_output=True,
                text=True,
            )
            for line in (p.stdout or "").splitlines():
                h = line.strip().lower()
                if h and self.target in h:
                    subs.add(h)
        else:
            print("[-] assetfinder not in PATH")

        if self.check_tool_installed("amass"):
            print("[+] Running Amass (passive)")
            p = subprocess.run(
                ["amass", "enum", "-passive", "-d", self.target],
                capture_output=True,
                text=True,
            )
            for line in (p.stdout or "").splitlines():
                h = line.strip().lower().split()[0] if line.strip() else ""
                if h and "." in h:
                    subs.add(h)
        else:
            print("[-] amass not in PATH")

        if not subs:
            subs.add(self.target)

        out.write_text("\n".join(sorted(subs)) + "\n", encoding="utf-8")
        print(f"[+] Wrote {len(subs)} subdomains -> {out}")
        return out

    def probe_alive(self, subs_file: Path) -> Path:
        alive = self.alive_file()
        jsonl = self.scans_dir / f"httpx_{self.date}.jsonl"
        hx = self.projectdiscovery_httpx_bin()
        if not hx:
            print(
                "[-] ProjectDiscovery httpx not found (need CLI with -l host list). "
                "Install: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest "
                "and ensure it is before any other 'httpx' on PATH, or set RECON_HTTPX."
            )
            shutil.copy(subs_file, alive)
            return alive

        print("[*] Probing live hosts (httpx)")
        p = subprocess.run(
            [
                hx,
                "-l",
                str(subs_file),
                "-silent",
                "-nc",
                "-tech-detect",
                "-json",
            ],
            capture_output=True,
            text=True,
        )
        urls: list[str] = []
        jsonl.write_text("", encoding="utf-8")
        with jsonl.open("a", encoding="utf-8") as jf:
            for line in (p.stdout or "").splitlines():
                line = line.strip()
                if not line:
                    continue
                jf.write(line + "\n")
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                u = obj.get("url") or obj.get("final_url")
                if u:
                    urls.append(u)
        alive.write_text("\n".join(urls) + ("\n" if urls else ""), encoding="utf-8")
        if not urls:
            print("[-] No alive hosts file found (httpx produced empty output)")
        else:
            print(f"[+] Alive hosts -> {alive}")
        return alive

    def run_nuclei(self) -> None:
        alive_file = self.alive_file()
        nuclei_file = self.nuclei_file()

        if not self.check_tool_installed("nuclei"):
            print("[-] nuclei not installed. Install:")
            print("    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
            return

        if not alive_file.exists():
            print("[-] No alive hosts file found")
            return

        print("[*] Running Nuclei vulnerability scan")
        cmd = (
            f"nuclei -l {alive_file} -severity critical,high,medium "
            f"-o {nuclei_file} -silent"
        )
        self.run_command(cmd, shell=True)

        if nuclei_file.exists() and nuclei_file.stat().st_size > 0:
            vulns = nuclei_file.read_text(encoding="utf-8", errors="replace").splitlines()
            vulns = [v for v in vulns if v.strip()]
            print(f"[!] Found {len(vulns)} potential vulnerabilities!")
            self.send_notification(
                "🚨 Vulnerabilities Found",
                f"{len(vulns)} vulnerabilities detected on {self.target}",
            )
        else:
            print("[+] No vulnerabilities found")

    def host_from_url(self, line: str) -> str | None:
        line = line.strip()
        if not line:
            return None
        if "://" not in line:
            return line.split("/")[0].split(":")[0]
        p = urllib.parse.urlparse(line)
        return p.hostname

    def run_nmap_interesting(self) -> None:
        alive_file = self.alive_file()
        if not alive_file.exists():
            print("[-] No alive hosts file found")
            return
        if not self.check_tool_installed("nmap"):
            print("[-] nmap not in PATH")
            return

        hosts: set[str] = set()
        for line in alive_file.read_text(encoding="utf-8", errors="replace").splitlines():
            h = self.host_from_url(line)
            if h:
                hosts.add(h)

        interesting_ports = ["8080", "8443", "8888", "3000", "8000", "9000", "8081"]
        for hostname in sorted(hosts):
            output_file = self.scans_dir / f"nmap_{hostname}_{self.date}.txt"
            cmd = f"nmap -T4 --top-ports 1000 -oN {output_file} {hostname}"
            self.run_command(cmd, shell=True)
            if output_file.exists():
                content = output_file.read_text(encoding="utf-8", errors="replace")
                if any(port in content for port in interesting_ports):
                    print(f"[!] Interesting ports found on {hostname} - consider full scan")
                    self.send_notification(
                        "🔍 Interesting Ports",
                        f"Found interesting ports on {hostname}",
                    )

    def run_eyewitness(self) -> None:
        alive_file = self.alive_file()
        if not self.check_tool_installed("eyewitness"):
            print("[-] EyeWitness not installed. Skipping screenshots...")
            return
        if not alive_file.exists():
            print("[-] No alive hosts file found")
            return

        screenshot_dir = self.screenshot_dir
        screenshot_dir.mkdir(parents=True, exist_ok=True)
        cmd = f"eyewitness --web -f {alive_file} -d {screenshot_dir} --no-prompt"
        print("[*] Taking screenshots")
        self.run_command(cmd, shell=True)
        print(f"[+] Screenshots saved to {screenshot_dir}")

    def tech_summary(self) -> list[dict]:
        jsonl = self.scans_dir / f"httpx_{self.date}.jsonl"
        rows: list[dict] = []
        if not jsonl.exists():
            return rows
        for line in jsonl.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = obj.get("url") or obj.get("input", "")
            tech = obj.get("tech", []) or obj.get("technologies", [])
            rows.append({"url": url, "tech": tech})
        return rows

    def generate_report(self) -> None:
        print("[*] Generating report")
        tech_rows = self.tech_summary()
        nuclei_path = self.nuclei_file()
        vuln_lines: list[str] = []
        if nuclei_path.exists():
            vuln_lines = [v for v in nuclei_path.read_text(encoding="utf-8", errors="replace").splitlines() if v.strip()]

        parts = [
            "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Recon Report</title>",
            "<style>body{font-family:system-ui,sans-serif;margin:24px;background:#111;color:#eee}",
            "table{border-collapse:collapse;width:100%;margin:16px 0}",
            "th,td{border:1px solid #444;padding:8px;text-align:left}",
            "th{background:#222} pre{white-space:pre-wrap;background:#1a1a1a;padding:12px}",
            "</style></head><body>",
            f"<h1>Report — {html.escape(self.target)}</h1>",
            f"<p>Date: {html.escape(self.date)}</p>",
            "<h2>Technology stacks (httpx)</h2>",
        ]
        if tech_rows:
            parts.append("<table><tr><th>URL</th><th>Tech</th></tr>")
            for r in tech_rows:
                t = r.get("tech")
                if isinstance(t, list):
                    td = ", ".join(html.escape(str(x)) for x in t)
                else:
                    td = html.escape(str(t))
                parts.append(
                    f"<tr><td>{html.escape(str(r.get('url','')))}</td><td>{td}</td></tr>"
                )
            parts.append("</table>")
        else:
            parts.append("<p>No httpx JSON export (install httpx with -tech-detect).</p>")

        parts.append("<h2>Nuclei (critical / high / medium)</h2>")
        if vuln_lines:
            parts.append("<pre>" + html.escape("\n".join(vuln_lines)) + "</pre>")
        else:
            parts.append("<p>No findings in nuclei output.</p>")

        parts.append(
            f"<p>Artifacts: <code>{html.escape(str(self.scans_dir))}</code></p>"
            "</body></html>"
        )
        self.report_file().write_text("".join(parts), encoding="utf-8")
        print(f"[+] Report generated: {self.report_file()}")

    def run(self, *, skip_nmap: bool = False) -> None:
        self.print_banner()
        print(f"[+] Target: {self.target}")
        print("[+] Setting up directories")
        self.setup_dirs()

        subs = self.enumerate_subdomains()
        self.probe_alive(subs)
        self.run_nuclei()
        if not skip_nmap:
            self.run_nmap_interesting()
        self.run_eyewitness()
        self.generate_report()


def main() -> None:
    parser = argparse.ArgumentParser(description="Bug bounty recon automation suite")
    parser.add_argument("domain", help="Target domain, e.g. example.com")
    parser.add_argument(
        "--base-dir",
        type=Path,
        default=None,
        help="Override output base (default: ~/recon or $RECON_BASE)",
    )
    parser.add_argument("--skip-nmap", action="store_true", help="Skip per-host nmap")
    args = parser.parse_args()

    r = ReconAutomator(args.domain, base_dir=args.base_dir)
    r.run(skip_nmap=args.skip_nmap)


if __name__ == "__main__":
    main()
