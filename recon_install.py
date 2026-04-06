"""
Install recon toolchain: Go-based tools, system packages (nmap, eyewitness), PATH prep.
Supports Debian/Ubuntu/Parrot/Kali (apt), Fedora/RHEL (dnf/yum), Arch (pacman), macOS (brew).
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path

GO_VERSION = "1.22.8"
GO_LINUX_ARCH = "linux-amd64"  # override via RECON_GO_ARCH if needed

GO_INSTALLS: list[tuple[str, str]] = [
    ("subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    ("httpx", "github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    ("nuclei", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    ("notify", "github.com/projectdiscovery/notify/cmd/notify@latest"),
    ("assetfinder", "github.com/tomnomnom/assetfinder@latest"),
    ("anew", "github.com/tomnomnom/anew@latest"),
    ("haktrails", "github.com/hakluke/haktrails@latest"),
    ("amass", "github.com/owasp-amass/amass/v4/cmd/amass@latest"),
]


def _run(
    cmd: list[str] | str,
    *,
    shell: bool = False,
    env: dict[str, str] | None = None,
) -> bool:
    if isinstance(cmd, str):
        r = subprocess.run(cmd, shell=True, env=env)
        return r.returncode == 0
    r = subprocess.run(cmd, env=env)
    return r.returncode == 0


def _which(name: str) -> str | None:
    return shutil.which(name)


def _prepend_path(dir_path: Path) -> None:
    p = str(dir_path.resolve())
    current = os.environ.get("PATH", "")
    if p not in current.split(os.pathsep):
        os.environ["PATH"] = p + os.pathsep + current


def detect_os() -> str:
    s = platform.system().lower()
    if s == "darwin":
        return "darwin"
    if s == "linux":
        return "linux"
    return "unknown"


def has_sudo_nopasswd() -> bool:
    try:
        r = subprocess.run(
            ["sudo", "-n", "true"],
            capture_output=True,
            timeout=5,
        )
        return r.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def apt_install(packages: list[str]) -> bool:
    if not packages:
        return True
    if has_sudo_nopasswd():
        return _run(
            ["sudo", "apt-get", "install", "-y", *packages],
        )
    print("[*] Trying apt without sudo (may fail); otherwise run:")
    print(f"    sudo apt-get update && sudo apt-get install -y {' '.join(packages)}")
    return _run(["apt-get", "install", "-y", *packages])


def dnf_install(packages: list[str]) -> bool:
    for exe in ("dnf", "yum"):
        if _which(exe):
            if has_sudo_nopasswd():
                return _run(["sudo", exe, "install", "-y", *packages])
            print(f"[*] Run: sudo {exe} install -y {' '.join(packages)}")
            return False
    return False


def pacman_install(packages: list[str]) -> bool:
    if not _which("pacman"):
        return False
    if has_sudo_nopasswd():
        return _run(["sudo", "pacman", "-Sy", "--noconfirm", *packages])
    print(f"[*] Run: sudo pacman -Sy {' '.join(packages)}")
    return False


def brew_install(packages: list[str]) -> bool:
    if not _which("brew"):
        return False
    return _run(["brew", "install", *packages])


def install_system_packages() -> None:
    pkgs_nmap = ["nmap", "git", "ca-certificates", "curl"]
    eyewitness_pkgs = ["eyewitness"]  # Kali/Parrot often have it; may fail on minimal Ubuntu

    os_type = detect_os()
    if os_type == "darwin":
        brew_install(pkgs_nmap)
        brew_install(["eyewitness"]) if False else None  # often not in brew; try anyway
        return

    if os_type != "linux":
        return

    if _which("apt-get"):
        _run(["sudo", "apt-get", "update"]) if has_sudo_nopasswd() else None
        if has_sudo_nopasswd():
            _run(["sudo", "apt-get", "install", "-y", *pkgs_nmap])
            r = subprocess.run(
                ["sudo", "apt-get", "install", "-y", *eyewitness_pkgs],
                capture=True,
            )
            if r.returncode != 0:
                print("[-] Package 'eyewitness' not available via apt; install manually if needed.")
        else:
            print("[!] Passwordless sudo not configured; install with:")
            print(f"    sudo apt-get update && sudo apt-get install -y {' '.join(pkgs_nmap)}")
        return

    if _which("dnf") or _which("yum"):
        dnf_install(pkgs_nmap)
        return

    if _which("pacman"):
        pacman_install(pkgs_nmap)


def local_go_root() -> Path:
    return Path.home() / ".local" / "go"


def ensure_go() -> Path | None:
    """Return path to go binary directory (containing `go`), or None."""
    if _which("go"):
        try:
            r = subprocess.run(
                ["go", "version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if r.returncode == 0:
                gopath_bin = Path(subprocess.check_output(["go", "env", "GOPATH"], text=True).strip()) / "bin"
                _prepend_path(gopath_bin)
                return Path(_which("go")).parent
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass

    goroot = local_go_root()
    go_bin = goroot / "bin" / "go"
    if go_bin.is_file():
        _prepend_path(go_bin.parent)
        gopath_bin = Path.home() / "go" / "bin"
        gopath_bin.mkdir(parents=True, exist_ok=True)
        _prepend_path(gopath_bin)
        return go_bin.parent

    if detect_os() != "linux":
        print("[-] Install Go from https://go.dev/dl/ then re-run --install-deps")
        return None

    arch = os.environ.get("RECON_GO_ARCH", GO_LINUX_ARCH)
    url = f"https://go.dev/dl/go{GO_VERSION}.{arch}.tar.gz"
    dest = Path.home() / ".local"
    dest.mkdir(parents=True, exist_ok=True)
    tgz = dest / f"go{GO_VERSION}.tar.gz"
    print(f"[*] Downloading Go {GO_VERSION} ({arch})…")
    try:
        urllib.request.urlretrieve(url, tgz)
    except urllib.error.URLError as e:
        print(f"[-] Failed to download Go: {e}")
        return None

    if goroot.exists():
        shutil.rmtree(goroot)
    with tarfile.open(tgz, "r:gz") as tf:
        tf.extractall(dest)
    (dest / f"go").rename(goroot)
    tgz.unlink(missing_ok=True)

    _prepend_path(goroot / "bin")
    gopath_bin = Path.home() / "go" / "bin"
    gopath_bin.mkdir(parents=True, exist_ok=True)
    _prepend_path(gopath_bin)
    os.environ.setdefault("GOPATH", str(Path.home() / "go"))
    print(f"[+] Go installed at {goroot}")
    return goroot / "bin"


def go_install_all() -> bool:
    go_parent = ensure_go()
    if not go_parent or not _which("go"):
        print("[-] go executable not available")
        return False

    gopath_bin = Path(subprocess.check_output(["go", "env", "GOPATH"], text=True).strip()) / "bin"
    gopath_bin.mkdir(parents=True, exist_ok=True)
    _prepend_path(gopath_bin)

    env = os.environ.copy()
    env["CGO_ENABLED"] = "0"

    ok = True
    for bin_name, module in GO_INSTALLS:
        if _which(bin_name) and bin_name != "httpx":
            print(f"[+] {bin_name} already on PATH")
            continue
        if bin_name == "httpx" and _which("httpx"):
            r = subprocess.run(
                ["httpx", "--help"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            helptext = (r.stdout or "") + (r.stderr or "")
            if "projectdiscovery" in helptext.lower():
                print("[+] httpx (ProjectDiscovery) already on PATH")
                continue

        print(f"[*] go install {bin_name} …")
        r = subprocess.run(
            ["go", "install", "-v", module],
            env=env,
        )
        if r.returncode != 0:
            print(f"[-] go install failed for {bin_name}")
            ok = False

    # Install PD httpx as httpx-pd if plain `httpx` is already the Python client
    hx = gopath_bin / "httpx"
    if hx.is_file():
        wrong = False
        try:
            r = subprocess.run(
                [str(hx), "--help"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            ht = (r.stdout or "") + (r.stderr or "")
            wrong = "projectdiscovery" not in ht.lower()
        except (OSError, subprocess.TimeoutExpired):
            wrong = True
        py_httpx = _which("httpx")
        if wrong or (py_httpx and str(hx) not in py_httpx):
            pd_name = gopath_bin / "httpx-pd"
            if not pd_name.exists():
                hx.rename(pd_name)
            print("[+] ProjectDiscovery httpx installed as httpx-pd (Python httpx also present)")
            os.environ["RECON_HTTPX"] = str(pd_name)

    _prepend_path(gopath_bin)
    return ok


def nuclei_update_templates() -> None:
    nu = _which("nuclei")
    if not nu:
        return
    print("[*] nuclei -update-templates")
    subprocess.run([nu, "-update-templates"], capture_output=True)


def install_pd_httpx_env_file(gopath_bin: Path) -> None:
    """Write RECON_HTTPX to ~/.profile snippet if httpx-pd exists."""
    pd = gopath_bin / "httpx-pd"
    if not pd.is_file():
        pd = gopath_bin / "httpx"
    if not pd.is_file():
        return
    try:
        r = subprocess.run(
            [str(pd), "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if "projectdiscovery" not in ((r.stdout or "") + (r.stderr or "")).lower():
            return
    except (OSError, subprocess.TimeoutExpired):
        return

    marker = "# recon: RECON_HTTPX"
    profile = Path.home() / ".profile"
    line = f'export RECON_HTTPX="{pd.resolve()}" {marker}\n'
    try:
        text = profile.read_text(encoding="utf-8") if profile.exists() else ""
        if marker not in text:
            with profile.open("a", encoding="utf-8") as f:
                f.write("\n" + line)
            print(f"[+] Appended RECON_HTTPX to {profile}")
    except OSError:
        pass


def install_dependencies() -> bool:
    print("[*] Installing recon dependencies…")
    install_system_packages()
    gopath_bin = Path.home() / "go" / "bin"
    gopath_bin.mkdir(parents=True, exist_ok=True)
    _prepend_path(gopath_bin)

    if not go_install_all():
        print("[-] Some Go tools failed to install")
        return False

    gopath_bin = Path(subprocess.check_output(["go", "env", "GOPATH"], text=True).strip()) / "bin"
    _prepend_path(gopath_bin)

    if _which("httpx") and "RECON_HTTPX" not in os.environ:
        try:
            r = subprocess.run(
                ["httpx", "--help"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            ht = (r.stdout or "") + (r.stderr or "")
            if "projectdiscovery" not in ht.lower():
                pd = gopath_bin / "httpx-pd"
                if pd.is_file():
                    os.environ["RECON_HTTPX"] = str(pd.resolve())
        except (OSError, subprocess.TimeoutExpired):
            pass

    install_pd_httpx_env_file(gopath_bin)
    nuclei_update_templates()

    print("[+] Dependency install finished. Ensure ~/go/bin is on your PATH:")
    print(f"    export PATH=\"{gopath_bin}:$PATH\"")
    return True


def ensure_dependencies_for_run() -> bool:
    """Light check: if critical tools missing, run full install."""
    need = ["subfinder", "nuclei", "nmap"]
    missing = [n for n in need if not _which(n)]
    httpx_ok = False
    try:
        from recon import ReconAutomator  # type: ignore

        httpx_ok = ReconAutomator.projectdiscovery_httpx_bin() is not None
    except Exception:
        if _which("httpx-pd"):
            os.environ["RECON_HTTPX"] = str(Path(_which("httpx-pd")).resolve())
            httpx_ok = True
        elif _which("httpx"):
            r = subprocess.run(
                ["httpx", "--help"],
                capture_output=True,
                text=True,
                timeout=8,
            )
            ht = (r.stdout or "") + (r.stderr or "")
            httpx_ok = "projectdiscovery" in ht.lower()

    if missing or not httpx_ok:
        return install_dependencies()
    return True
