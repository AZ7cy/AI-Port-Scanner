#!/usr/bin/env python3

# ── Standard library imports ────────────────────────────────────────────────
import concurrent.futures
import csv
import errno
import ftplib
import html
import io
import json
import logging
import math
import os
import re
import shutil
import smtplib
import socket
import subprocess
import sys
import textwrap
import threading
import time
from datetime import datetime
from typing import Callable, Dict, List, Optional, Tuple

# ── Third-party imports ──────────────────────────────────────────────────────
import nmap
import requests

# Suppress the expected urllib3 warning because HTTPS banner probing intentionally
# allows self-signed/invalid certificates with verify=False.
requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)
from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

from PyQt6.QtCore import QThread, QPointF, QRectF, Qt, pyqtSignal
from PyQt6.QtGui import (
    QColor, QFont, QIcon, QLinearGradient, QPainter, QPainterPath,
    QPen, QPixmap, QRadialGradient,
)
from PyQt6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDialog, QDoubleSpinBox, QFileDialog,
    QFormLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QMainWindow,
    QMessageBox, QProgressBar, QPushButton, QSpinBox, QTabWidget,
    QTextEdit, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)


################################################################################
# SECTION: scanner  (from scanner.py)
################################################################################

"""
Nmap scanning wrapper module.
Handles all port scanning operations using python-nmap and direct subprocess
streaming for real-time per-port output.
"""



# Shared target validation for every scanner entry point.
_SAFE_TARGET = re.compile(r"^[a-zA-Z0-9.\-_:/\[\]]+$")

def _validate_target(target: str) -> str:
    """Validate and return a target safe to place in an Nmap argv list."""
    if not isinstance(target, str) or not target.strip():
        raise ValueError("Target must be a non-empty hostname or IP address.")
    target = target.strip()
    if target.startswith("-") or not _SAFE_TARGET.fullmatch(target):
        raise ValueError(
            f"Invalid target {target!r}: only hostname/IP characters are allowed, "
            "and the target must not start with '-'. Strip any Nmap flags from the target field."
        )
    return target


class ScanProfile:
    """Predefined scan profiles with nmap arguments."""

    QUICK = {
        "name": "Quick Scan (Top 100 Ports)",
        "ports": "",                       # Nmap --top-ports controls the Nmap list
        # Socket Full Detail cannot ask Nmap for its internal top-port list.
        # Use a deterministic explicit range instead of silently falling back
        # to 1-1024 while still displaying a misleading "Top 100" command.
        "socket_ports": "1-1024",
        "arguments": "-T4 --top-ports 100",
        "description": "Fast scan of the most common 100 ports",
    }

    COMMON = {
        "name": "Common Ports (1-1024)",
        "ports": "1-1024",
        "arguments": "-T4",
        "description": "Scan all well-known service ports",
    }

    SERVICE_VERSION = {
        "name": "Service / Version Detection",
        "ports": "1-1024",
        "arguments": "-sV -T4",
        "description": "Detect service versions on common ports",
    }

    FULL_TCP = {
        "name": "Full TCP Scan (All Ports)",
        "ports": "1-65535",
        "arguments": "-sT -T4",
        "description": "Complete TCP connect scan of all 65 535 ports",
    }

    INTENSE = {
        "name": "Intense Scan",
        "ports": "1-65535",
        "arguments": "-sV -sC -T4",
        "description": "Version detection + default NSE scripts on all ports",
    }

    @classmethod
    def get_all_profiles(cls) -> List[Dict]:
        return [cls.QUICK, cls.COMMON, cls.SERVICE_VERSION, cls.FULL_TCP, cls.INTENSE]

    @classmethod
    def get_profile_names(cls) -> List[str]:
        return [p["name"] for p in cls.get_all_profiles()]

    @classmethod
    def get_profile_by_name(cls, name: str) -> Optional[Dict]:
        for profile in cls.get_all_profiles():
            if profile["name"] == name:
                return profile
        return None


# ── Regex patterns for parsing nmap -vv live output ──────────────────────────

# "Discovered open port 443/tcp on 192.168.1.1"
_RE_OPEN = re.compile(
    r"Discovered open port\s+(\d+)/(\w+)\s+on\s+([\w.:\-]+)", re.IGNORECASE
)

# Final table line:  "80/tcp   open   http   ..."  or  "80/tcp   closed http   ..."
_RE_PORT_LINE = re.compile(
    r"^(\d+)/(\w+)\s+(open|closed|filtered|unfiltered|open\|filtered|closed\|filtered)\s*(\S*)\s*(.*)",
    re.IGNORECASE,
)

# "Stats: 0:00:03 elapsed; ... About 45.00% done; ETC: ..."
_RE_STATS = re.compile(r"About\s+([\d.]+)%\s+done", re.IGNORECASE)

# "Scanning hostname (ip) [N ports]"
_RE_SCANNING = re.compile(r"Scanning\s+.*?\[(\d+)\s+ports?\]", re.IGNORECASE)

# Latency line:  "Host is up (0.0012s latency)."
_RE_LATENCY = re.compile(r"Host is up.*?\(([\d.]+)s\s+latency\)", re.IGNORECASE)

# "Nmap done: N IP address(es) (N host up) scanned in X seconds"
_RE_DONE = re.compile(r"Nmap done.*?scanned in\s+([\d.]+)\s+seconds", re.IGNORECASE)


class PortScanner:
    """Wrapper around nmap for port scanning with live streaming support."""

    WINDOWS_DEFAULT_PATHS = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
    ]

    def __init__(self, nmap_path: Optional[str] = None):
        self.nmap_path = nmap_path
        self.scanner = None
        self._process: Optional[subprocess.Popen] = None
        self._resolve_and_init()

    # ── Path resolution ───────────────────────────────────────────────────────

    def _resolve_and_init(self) -> None:
        exe_path: Optional[str] = None

        if self.nmap_path:
            p = os.path.normpath(self.nmap_path)
            if os.path.isfile(p):
                exe_path = p
            elif os.path.isdir(p):
                candidate = os.path.join(p, "nmap.exe")
                if os.path.isfile(candidate):
                    exe_path = candidate
            if exe_path is None:
                raise FileNotFoundError(
                    f"nmap not found at: {self.nmap_path}\n"
                    "Please check the path in Settings."
                )
        else:
            found = shutil.which("nmap")
            if found:
                exe_path = found
            else:
                for candidate in self.WINDOWS_DEFAULT_PATHS:
                    if os.path.isfile(candidate):
                        exe_path = candidate
                        break

        if exe_path is None:
            raise FileNotFoundError(
                "nmap was not found.\n\n"
                "Install from https://nmap.org/download.html\n"
                "Default path: C:\\Program Files (x86)\\Nmap\\nmap.exe\n\n"
                "After installing restart the app or set the path in Settings."
            )

        self.nmap_path = exe_path
        try:
            self.scanner = nmap.PortScanner(nmap_search_path=(exe_path,))
        except Exception as e:
            raise FileNotFoundError(f"Failed to init nmap: {e}")

    # ── Live streaming scan ───────────────────────────────────────────────────

    def run_scan_live(
        self,
        target: str,
        ports: str = "",
        arguments: str = "-T4",
        on_line: Optional[Callable[[str], None]] = None,
        on_port: Optional[Callable[[Dict], None]] = None,
        on_progress: Optional[Callable[[float, str], None]] = None,
        stop_flag: Optional[Callable[[], bool]] = None,
    ) -> Dict:
        """
        Run nmap with -vv and stream output line-by-line.

        Callbacks (all optional, called from the scan thread):
            on_line(raw_line)               — every output line
            on_port(port_dict)              — fired when a port result is parsed
            on_progress(pct, message)       — fired on Stats/% lines
            stop_flag() -> bool             — return True to abort the scan

        port_dict keys:
            port, proto, state, service, reason, latency, host

        Returns the same results dict structure as run_scan().
        """
        # Build nmap command
        cmd = [self.nmap_path]

        # Validate target to prevent accidental Nmap-option injection.
        target = _validate_target(target)

        # -vv gives per-port discovery lines; --stats-every gives % updates
        # We inject these ourselves — strip any existing -v/-vv from arguments
        clean_args = re.sub(r"\s-vv?\b", "", arguments).strip()
        cmd += ["-vv", "--stats-every", "1s"]

        if ports:
            cmd += ["-p", ports]

        cmd += clean_args.split() + [target]

        # Bookkeeping
        results: Dict = {
            "command": " ".join(f'"{c}"' if " " in c else c for c in cmd),
            "scan_info": {},
            "hosts": {},
        }
        current_host: Optional[str] = None
        total_ports_expected = 0
        in_port_table = False          # True once we see the PORT/STATE header
        host_latency: Dict[str, str] = {}

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
            )

            for raw in self._process.stdout:
                if stop_flag and stop_flag():
                    self._process.terminate()
                    break

                line = raw.rstrip()
                if not line:
                    in_port_table = False
                    continue

                # Fire raw-line callback
                if on_line:
                    on_line(line)

                # ── Host detection ────────────────────────────────────────
                m_host = re.search(
                    r"Nmap scan report for\s+(?:\S+\s+\()?([\d:.]+)\)?", line
                )
                if m_host:
                    current_host = m_host.group(1)
                    if current_host not in results["hosts"]:
                        results["hosts"][current_host] = {
                            "state": "up",
                            "hostnames": [],
                            "protocols": {},
                        }
                    # Try to grab hostname
                    m_hn = re.match(r"Nmap scan report for\s+(\S+)\s+\(", line)
                    if m_hn:
                        hn = m_hn.group(1)
                        if hn not in results["hosts"][current_host]["hostnames"]:
                            results["hosts"][current_host]["hostnames"].append(hn)
                    in_port_table = False
                    continue

                # ── Expected port count ───────────────────────────────────
                m_scan = _RE_SCANNING.search(line)
                if m_scan:
                    total_ports_expected = int(m_scan.group(1))
                    if on_progress:
                        on_progress(0.0, f"Scanning {total_ports_expected} ports on {target}…")
                    continue

                # ── Latency ───────────────────────────────────────────────
                m_lat = _RE_LATENCY.search(line)
                if m_lat and current_host:
                    host_latency[current_host] = m_lat.group(1) + "s"
                    continue

                # ── Live "Discovered open port" lines ─────────────────────
                m_open = _RE_OPEN.match(line)
                if m_open:
                    port_num = int(m_open.group(1))
                    proto    = m_open.group(2).lower()
                    host     = m_open.group(3)
                    if host not in results["hosts"]:
                        results["hosts"][host] = {
                            "state": "up", "hostnames": [], "protocols": {}
                        }
                    pd = {"state": "open", "name": "", "product": "",
                          "version": "", "extrainfo": "", "reason": "syn-ack", "cpe": ""}
                    results["hosts"][host].setdefault(
                        "protocols", {}
                    ).setdefault(proto, {})[port_num] = pd

                    if on_port:
                        on_port({
                            "host": host, "port": port_num, "proto": proto,
                            "state": "open", "service": "", "reason": "syn-ack",
                            "latency": host_latency.get(host, ""),
                        })
                    continue

                # ── Progress stats line ───────────────────────────────────
                m_stats = _RE_STATS.search(line)
                if m_stats:
                    pct = float(m_stats.group(1))
                    if on_progress:
                        on_progress(pct, f"Scanning… {pct:.1f}% complete")
                    continue

                # ── PORT/STATE header line — start of final table ─────────
                if re.match(r"^PORT\s+STATE\s+SERVICE", line, re.IGNORECASE):
                    in_port_table = True
                    continue

                # ── Final port table rows ─────────────────────────────────
                if in_port_table and current_host:
                    m_pl = _RE_PORT_LINE.match(line)
                    if m_pl:
                        port_num = int(m_pl.group(1))
                        proto    = m_pl.group(2).lower()
                        state    = m_pl.group(3).lower()
                        service  = m_pl.group(4)
                        rest     = m_pl.group(5).strip()

                        # Parse reason from rest (last token that matches word/word pattern)
                        reason = ""
                        m_reason = re.search(r"(\S+)\s+ttl\s+\d+", rest)
                        if m_reason:
                            reason = m_reason.group(1)
                            rest = rest[:m_reason.start()].strip()

                        # Update or create entry
                        proto_dict = results["hosts"][current_host][
                            "protocols"
                        ].setdefault(proto, {})
                        existing = proto_dict.get(port_num, {})
                        existing.update({
                            "state":     state,
                            "name":      service or existing.get("name", ""),
                            "product":   existing.get("product", ""),
                            "version":   existing.get("version", ""),
                            "extrainfo": rest or existing.get("extrainfo", ""),
                            "reason":    reason or existing.get("reason", ""),
                            "cpe":       existing.get("cpe", ""),
                        })
                        proto_dict[port_num] = existing

                        if on_port:
                            on_port({
                                "host":    current_host,
                                "port":    port_num,
                                "proto":   proto,
                                "state":   state,
                                "service": service,
                                "reason":  reason,
                                "latency": host_latency.get(current_host, ""),
                            })
                        continue

                # ── Scan-info line (method) ───────────────────────────────
                m_method = re.search(
                    r"Initiating\s+(\w[\w ]+Scan)\s+at", line, re.IGNORECASE
                )
                if m_method:
                    method = m_method.group(1)
                    results["scan_info"].setdefault("tcp", {})["method"] = method
                    continue

                # ── Done line ─────────────────────────────────────────────
                m_done = _RE_DONE.search(line)
                if m_done:
                    elapsed = float(m_done.group(1))
                    results["scan_info"]["elapsed"] = f"{elapsed:.2f}s"
                    if on_progress:
                        on_progress(100.0, f"Scan finished in {elapsed:.2f}s")

            self._process.wait()

        except Exception as e:
            raise Exception(f"Live scan error: {e}") from e
        finally:
            self._process = None

        # Store total ports scanned count
        results["scan_info"]["total_ports_expected"] = total_ports_expected
        return results

    def stop_live_scan(self):
        """Terminate a running live scan process."""
        if self._process and self._process.poll() is None:
            self._process.terminate()

    # ── Legacy blocking scan (kept for compatibility) ─────────────────────────

    def run_scan(self, target: str, ports: str = "1-1024",
                 arguments: str = "-sV") -> Dict:
        """Blocking scan via python-nmap (no live output)."""
        if not self.scanner:
            raise RuntimeError("Scanner not initialised.")
        target = _validate_target(target)
        try:
            if ports:
                self.scanner.scan(target, ports, arguments=arguments)
            else:
                self.scanner.scan(target, arguments=arguments)

            results = {
                "command": self.scanner.command_line(),
                "scan_info": self.scanner.scaninfo(),
                "hosts": {},
            }
            for host in self.scanner.all_hosts():
                host_info = {
                    "state": self.scanner[host].state(),
                    "hostnames": [
                        h["name"] for h in self.scanner[host].get("hostnames", [])
                    ],
                    "protocols": {},
                }
                for proto in self.scanner[host].all_protocols():
                    ports_info = {}
                    for port in self.scanner[host][proto].keys():
                        d = self.scanner[host][proto][port]
                        ports_info[port] = {
                            "state":     d.get("state", "unknown"),
                            "name":      d.get("name", ""),
                            "product":   d.get("product", ""),
                            "version":   d.get("version", ""),
                            "extrainfo": d.get("extrainfo", ""),
                            "reason":    d.get("reason", ""),
                            "cpe":       d.get("cpe", ""),
                        }
                    host_info["protocols"][proto] = ports_info
                results["hosts"][host] = host_info
            return results
        except nmap.PortScannerError as e:
            raise Exception(f"Nmap scan error: {e}")
        except Exception as e:
            raise Exception(f"Scan error: {e}")

    def scan_with_profile(self, target: str, profile_name: str) -> Dict:
        """Blocking scan using a named profile (no live output)."""
        profile = ScanProfile.get_profile_by_name(profile_name)
        if not profile:
            raise ValueError(f"Unknown profile: {profile_name}")
        return self.run_scan(
            target=target,
            ports=profile["ports"],
            arguments=profile["arguments"],
        )


################################################################################
# SECTION: socket_scanner  (from socket_scanner.py)
################################################################################

"""
socket_scanner.py
-----------------
Direct TCP socket scanner that classifies every port in a range as:

    open     – connect_ex() returned 0
    closed   – connect_ex() returned ECONNREFUSED (errno 111 / 10061)
    filtered – connection timed out or any other OS-level error

This matches Nmap's own state definitions and is the only reliable way to
get per-port results for large ranges because Nmap collapses runs of
closed/filtered ports into summary lines that can't be parsed back out.

The scanner:
  • Uses a thread pool (default 256 workers) for speed
  • Fires on_port() callbacks in real time as results arrive
  • Reports progress via on_progress() every ~0.5 s
  • Can be stopped cleanly via a stop_flag callable
  • Returns the same results-dict schema as PortScanner.run_scan_live()

After the socket pass the caller can optionally run Nmap's -sV on only the
open ports to get structured version info without touching closed/filtered
ports at all.

Diagnostic helpers
------------------
Call run_diagnostics(target) before a scan to surface the real failure layer:
    • DNS resolution (gaierror hidden as 'filtered' without this check)
    • Target string sanity (http://, trailing slash, hidden whitespace)
    • Single-port sanity test on port 80
    • Per-exception-type logging for the first few ports
    • Guidance on network-level blocking (proxy/VPN/AV)
"""



# Module-level logger — handlers are added by run_diagnostics() if needed.
_diag_log = logging.getLogger("socket_scanner.diag")

# Windows ECONNREFUSED is 10061; POSIX is 111
_ECONNREFUSED = {errno.ECONNREFUSED}
try:
    _ECONNREFUSED.add(10061)          # Windows
except AttributeError:
    pass

# How many per-port exceptions to log before going silent (avoids log spam).
_DIAG_LOG_LIMIT = 20
_diag_exception_count = 0
_diag_exception_lock  = threading.Lock()


def _classify_port(host: str, port: int, timeout: float) -> str:
    """
    Attempt a TCP connect to host:port and return the port state.

    Returns one of: 'open', 'closed', 'filtered'
    Never raises.

    When diagnostic logging is active (run_diagnostics() was called or
    _diag_log has handlers), the first _DIAG_LOG_LIMIT failures are logged
    with the exact exception type and errno so callers can see the real
    failure mode instead of a flat 'filtered' label.
    """
    global _diag_exception_count

    def _log_exc(exc: Exception, note: str = ""):
        """Log the exception if we haven't hit the cap yet."""
        global _diag_exception_count
        if not _diag_log.handlers:
            return
        with _diag_exception_lock:
            if _diag_exception_count >= _DIAG_LOG_LIMIT:
                return
            _diag_exception_count += 1
            count = _diag_exception_count

        exc_type  = type(exc).__name__
        exc_errno = getattr(exc, "errno", None)
        errno_sym = errno.errorcode.get(exc_errno, str(exc_errno)) if exc_errno else "n/a"
        _diag_log.debug(
            "[port %d] %s  exception=%s  errno=%s(%s)%s",
            port, note, exc_type, exc_errno, errno_sym,
            f"  detail={exc}" if str(exc) else "",
        )
        if count == _DIAG_LOG_LIMIT:
            _diag_log.debug(
                "[port %d] ... further per-port exceptions suppressed "
                "(limit %d reached)",
                port, _DIAG_LOG_LIMIT,
            )

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()
        if result == 0:
            return "open"
        if result in _ECONNREFUSED:
            return "closed"
        # Any other OS error (ENETUNREACH, EHOSTUNREACH, etc.) → filtered
        # Log the raw errno so diagnostics can distinguish ETIMEDOUT from
        # ENETUNREACH, EHOSTUNREACH, etc.
        if _diag_log.handlers:
            errno_sym = errno.errorcode.get(result, str(result))
            with _diag_exception_lock:
                if _diag_exception_count < _DIAG_LOG_LIMIT:
                    _diag_exception_count += 1
                    _diag_log.debug(
                        "[port %d] connect_ex returned %d (%s) → filtered",
                        port, result, errno_sym,
                    )
        return "filtered"
    except socket.timeout:
        _log_exc(socket.timeout(), "socket.timeout (connect timed out)")
        return "filtered"
    except OSError as e:
        if e.errno in _ECONNREFUSED:
            return "closed"
        _log_exc(e, "OSError → filtered")
        return "filtered"
    except Exception as e:
        _log_exc(e, "unexpected exception → filtered")
        return "filtered"


# ---------------------------------------------------------------------------
# Diagnostic helpers
# ---------------------------------------------------------------------------

def _sanitize_target(raw: str) -> Tuple[str, List[str]]:
    """
    Strip common accidental prefixes/suffixes and return the clean hostname
    plus a list of warning strings describing what was stripped.
    """
    warnings: List[str] = []
    host = raw

    for scheme in ("https://", "http://"):
        if host.lower().startswith(scheme):
            host = host[len(scheme):]
            warnings.append(f"Stripped '{scheme}' prefix — connect_ex does not speak HTTP")

    if host.endswith("/"):
        host = host.rstrip("/")
        warnings.append("Stripped trailing '/' — socket API needs a bare hostname")

    stripped = host.strip()
    if stripped != host:
        warnings.append(
            f"Stripped hidden whitespace: repr={repr(raw)}"
        )
        host = stripped

    return host, warnings


def run_diagnostics(
    target: str,
    probe_port: int = 80,
    probe_timeout: float = 5.0,
    alt_targets: Optional[List[str]] = None,
    log_to_console: bool = True,
) -> Dict:
    """
    Run a layered pre-scan diagnostic and return a results dict.

    Checks (in order):
        1. Target string sanity  (http://, trailing /, hidden whitespace)
        2. DNS resolution        (surfaces gaierror before it gets hidden)
        3. Single-port TCP probe (port 80 by default)
        4. Alternative targets   (scanme.nmap.org by default) when the
                                  primary target's probe fails
        5. Network-level blocking hints

    Parameters
    ----------
    target         : The raw target string the user typed.
    probe_port     : Port used for the single-connection sanity test (80).
    probe_timeout  : Timeout for the single-port probe (5 s is generous).
    alt_targets    : Alternative hosts to test when the primary probe fails.
                     Defaults to ['scanme.nmap.org'].
    log_to_console : When True a StreamHandler is attached so diagnostic
                     output appears on stdout even if the caller hasn't
                     configured logging.

    Returns
    -------
    Dict with keys:
        clean_target     str   – sanitised hostname to use for scanning
        resolved_ip      str | None
        dns_ok           bool
        probe_ok         bool
        alt_probe_ok     bool | None  (None if not attempted)
        warnings         list[str]
        errors           list[str]
        suggestions      list[str]
        safe_to_scan     bool  – True only when DNS + probe both succeeded
    """
    global _diag_exception_count
    _diag_exception_count = 0   # reset counter for a fresh diagnostic run

    if alt_targets is None:
        alt_targets = ["scanme.nmap.org"]

    # ── Attach a console handler so output is always visible ─────────────────
    if log_to_console and not _diag_log.handlers:
        _h = logging.StreamHandler()
        _h.setFormatter(logging.Formatter("%(message)s"))
        _diag_log.addHandler(_h)
    _diag_log.setLevel(logging.DEBUG)

    out: Dict = {
        "clean_target": target,
        "resolved_ip":  None,
        "dns_ok":        False,
        "probe_ok":      False,
        "alt_probe_ok":  None,
        "warnings":      [],
        "errors":        [],
        "suggestions":   [],
        "safe_to_scan":  False,
    }

    sep = "=" * 60
    _diag_log.info(sep)
    _diag_log.info("SOCKET SCANNER — PRE-SCAN DIAGNOSTICS")
    _diag_log.info(sep)

    # ── Layer 1: Target string sanity ─────────────────────────────────────────
    _diag_log.info("\n[1] Target string check")
    _diag_log.info("    Raw value  : %r", target)

    clean, san_warns = _sanitize_target(target)
    out["clean_target"] = clean

    if san_warns:
        for w in san_warns:
            _diag_log.warning("    WARNING: %s", w)
            out["warnings"].append(w)
        _diag_log.info("    Clean value: %r  ← this will be passed to the scanner", clean)
    else:
        _diag_log.info("    ✓ No prefix/suffix issues detected")

    # ── Layer 2: DNS resolution ───────────────────────────────────────────────
    _diag_log.info("\n[2] DNS resolution  →  socket.gethostbyname(%r)", clean)
    try:
        resolved_ip = socket.gethostbyname(clean)
        out["resolved_ip"] = resolved_ip
        out["dns_ok"]       = True
        _diag_log.info("    ✓ Resolved to: %s", resolved_ip)
    except socket.gaierror as e:
        err_msg = (
            f"DNS resolution FAILED for {clean!r}: "
            f"{type(e).__name__}  errno={e.errno}  detail={e}"
        )
        _diag_log.error("    ✗ %s", err_msg)
        out["errors"].append(err_msg)
        out["suggestions"].append(
            "DNS failure is the most likely reason every port shows 'filtered'. "
            "connect_ex() raises socket.gaierror (a subclass of OSError) when DNS "
            "fails, and the current scanner catches it silently as 'filtered'. "
            "Fix: check your internet connection, try 'ping testphp.vulnweb.com' "
            "in a terminal, or verify the hostname spelling."
        )
        _diag_log.info(sep)
        _diag_log.info("Diagnostics complete — DNS failed, aborting further checks.")
        _diag_log.info(sep)
        return out   # nothing else is meaningful without DNS

    # ── Layer 3: Single-port sanity test ──────────────────────────────────────
    _diag_log.info(
        "\n[3] Single-port TCP probe  →  "
        "socket.create_connection((%r, %d), timeout=%s)",
        clean, probe_port, probe_timeout,
    )
    try:
        conn = socket.create_connection((clean, probe_port), timeout=probe_timeout)
        conn.close()
        out["probe_ok"] = True
        _diag_log.info(
            "    ✓ Connected to %s:%d successfully — basic TCP connectivity is fine",
            clean, probe_port,
        )
    except socket.timeout:
        _diag_log.error(
            "    ✗ Connection to %s:%d TIMED OUT after %.1fs",
            clean, probe_port, probe_timeout,
        )
        out["errors"].append(
            f"TCP probe to {clean}:{probe_port} timed out — "
            "no SYN-ACK or RST received within the timeout window."
        )
        _diag_log.warning(
            "    This strongly suggests a network-level block (see Layer 4)."
        )
    except OSError as e:
        exc_type  = type(e).__name__
        exc_errno = e.errno
        errno_sym = errno.errorcode.get(exc_errno, str(exc_errno)) if exc_errno else "n/a"
        _diag_log.error(
            "    ✗ Connection to %s:%d FAILED: %s  errno=%s(%s)  detail=%s",
            clean, probe_port, exc_type, exc_errno, errno_sym, e,
        )
        out["errors"].append(
            f"TCP probe to {clean}:{probe_port} failed: "
            f"{exc_type}  errno={exc_errno}({errno_sym})"
        )

    # ── Layer 4: Network-blocking hints (printed regardless of probe result) ──
    _diag_log.info("\n[4] Network-level blocking hints")
    if not out["probe_ok"]:
        hints = [
            "  • Corporate firewall / VPN: raw socket.connect() calls do NOT go through",
            "    HTTP proxies. If your network requires a proxy for outbound TCP, every",
            "    direct socket attempt silently times out. Check HTTP_PROXY / HTTPS_PROXY",
            "    env vars and your network policy.",
            "  • Antivirus / endpoint security: some AV products intercept or block",
            "    outbound connections from Python (or unsigned processes) specifically.",
            "    Temporarily disable real-time protection and retry.",
            "  • Windows Firewall: ensure outbound TCP is allowed for python.exe.",
            "  • ISP-level blocking: some ISPs block outbound port 80 from residential",
            "    connections. Try a different port (e.g. 443) or a different network.",
        ]
        for h in hints:
            _diag_log.warning(h)
        for h in hints:
            out["suggestions"].append(h.strip())
    else:
        _diag_log.info(
            "    ✓ Probe succeeded — no network-level blocking detected for this target"
        )

    # ── Layer 5: Alternative target check (only if primary probe failed) ───────
    if not out["probe_ok"] and alt_targets:
        _diag_log.info(
            "\n[5] Alternative target probe  (primary failed — checking %s to rule out",
            alt_targets,
        )
        _diag_log.info("     target-side rate-limiting vs. local environment blocking)")
        for alt in alt_targets:
            _diag_log.info("    Testing %s:%d …", alt, probe_port)
            try:
                alt_ip = socket.gethostbyname(alt)
                conn   = socket.create_connection((alt_ip, probe_port), timeout=probe_timeout)
                conn.close()
                out["alt_probe_ok"] = True
                _diag_log.info(
                    "    ✓ Connected to %s (%s):%d — your machine CAN reach the internet.",
                    alt, alt_ip, probe_port,
                )
                _diag_log.warning(
                    "    This means the issue is specific to %r, not your network.",
                    clean,
                )
                _diag_log.warning(
                    "    Likely cause: target-side rate-limiting / WAF / IDS (Layer 5)."
                )
                _diag_log.warning(
                    "    Suggestions: wait a few minutes and retry, or scan from a",
                )
                _diag_log.warning(
                    "    different IP. Earlier aggressive scans against sibling hosts",
                )
                _diag_log.warning(
                    "    on the same subnet may have triggered a block on your IP.",
                )
                out["suggestions"].append(
                    f"Alternative probe to {alt}:{probe_port} succeeded, so your "
                    f"internet connection is fine. The block is specific to {clean} — "
                    "likely Acunetix WAF/IDS rate-limiting. Wait a few minutes, or "
                    "switch to a different source IP (different network / VPN exit)."
                )
                break
            except Exception as e2:
                out["alt_probe_ok"] = False
                _diag_log.error(
                    "    ✗ Alternative probe to %s:%d also failed: %s — "
                    "problem is likely on your end (firewall/proxy/AV).",
                    alt, probe_port, e2,
                )
                out["suggestions"].append(
                    f"Alternative probe to {alt}:{probe_port} also failed ({e2}). "
                    "This points to a local environment issue: "
                    "VPN/proxy blocking direct TCP, AV intercepting connections, "
                    "or Windows Firewall. Not a scanner bug."
                )
    elif out["probe_ok"]:
        _diag_log.info("\n[5] Alternative target probe — skipped (primary probe passed)")

    # ── Summary ───────────────────────────────────────────────────────────────
    out["safe_to_scan"] = out["dns_ok"] and out["probe_ok"]

    _diag_log.info("\n%s", sep)
    _diag_log.info("DIAGNOSTIC SUMMARY")
    _diag_log.info(sep)
    _diag_log.info("  Clean target  : %r", out["clean_target"])
    _diag_log.info("  Resolved IP   : %s", out["resolved_ip"] or "FAILED")
    _diag_log.info("  DNS ok        : %s", out["dns_ok"])
    _diag_log.info("  Port-%d probe ok: %s", probe_port, out["probe_ok"])
    if out["alt_probe_ok"] is not None:
        _diag_log.info("  Alt probe ok  : %s", out["alt_probe_ok"])
    if out["errors"]:
        _diag_log.error("  Errors:")
        for e in out["errors"]:
            _diag_log.error("    - %s", e)
    if out["suggestions"]:
        _diag_log.warning("  Suggestions:")
        for s in out["suggestions"]:
            _diag_log.warning("    → %s", s)
    _diag_log.info(
        "  Safe to scan  : %s", out["safe_to_scan"]
    )
    if not out["safe_to_scan"]:
        _diag_log.warning(
            "\n  ⚠  Do NOT run the full scan yet — the diagnostics above explain why "
            "every port would show 'filtered'. Fix the underlying issue first."
        )
    _diag_log.info(sep)

    return out


def _service_name(port: int, proto: str = "tcp") -> str:
    """
    Return the IANA well-known service name for a port, or '' if unknown.
    Uses the OS service database — works without any network access.
    """
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return ""


def _parse_port_spec(port_spec: str) -> List[int]:
    """
    Parse a port specification string into a sorted list of port numbers.

    Accepts:
        ""         → [1..1024]  (default)
        "80"       → [80]
        "22,80,443"→ [22, 80, 443]
        "1-1024"   → [1, 2, …, 1024]
        "1-65535"  → all ports
        "22,80-90" → mixed
    """
    if not port_spec or port_spec.strip() == "":
        return list(range(1, 1025))

    ports: List[int] = []
    for token in port_spec.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            try:
                lo, hi = token.split("-", 1)
                lo_i, hi_i = int(lo.strip()), int(hi.strip())
                if lo_i > hi_i:
                    lo_i, hi_i = hi_i, lo_i
                ports.extend(range(lo_i, hi_i + 1))
            except ValueError:
                pass
        else:
            try:
                ports.append(int(token))
            except ValueError:
                pass

    # Deduplicate and sort
    return sorted(set(p for p in ports if 1 <= p <= 65535))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class SocketScanner:
    """
    Full-fidelity TCP port scanner based on direct socket connections.

    Every port in the requested range gets a row in the results dict with
    an accurate open / closed / filtered state.  Version info (product,
    version, extrainfo) is left empty here — the caller should run
    banner_grabber.enrich_scan_results() on the returned dict to fill those
    in for open ports.
    """

    def __init__(self, max_workers: int = 256, timeout: float = 1.0):
        """
        Args:
            max_workers: Thread-pool size. 256 is a good balance between
                         speed and not exhausting ephemeral ports. Raise to
                         512 for faster full-range scans on local networks.
            timeout:     Per-port connect timeout in seconds.
                         0.5 s is fine for LAN; use 1.0–2.0 s for WAN.
        """
        self.max_workers = max_workers
        self.timeout     = timeout
        self._stop_event = threading.Event()

    def stop(self):
        """Signal the running scan to stop as soon as possible."""
        self._stop_event.set()

    def run_scan_live(
        self,
        target: str,
        ports: str = "",
        arguments: str = "",          # accepted but ignored (compat shim)
        on_line: Optional[Callable[[str], None]] = None,
        on_port: Optional[Callable[[Dict], None]] = None,
        on_progress: Optional[Callable[[float, str], None]] = None,
        stop_flag: Optional[Callable[[], bool]] = None,
    ) -> Dict:
        """
        Scan every port in ``ports`` against ``target`` using TCP connect.

        Parameters mirror PortScanner.run_scan_live() so this class is a
        drop-in replacement for the worker.

        Returns:
            A results dict in the same schema as PortScanner.run_scan_live():
            {
                "command":   str,
                "scan_info": { "tcp": {"method": "Socket Connect"},
                               "elapsed": "X.XXs",
                               "total_ports_expected": N },
                "hosts": {
                    "<ip>": {
                        "state":     "up",
                        "hostnames": [...],
                        "protocols": {
                            "tcp": {
                                <port_int>: {
                                    "state":     "open"|"closed"|"filtered",
                                    "name":      "<service_name>",
                                    "product":   "",
                                    "version":   "",
                                    "extrainfo": "",
                                    "reason":    "",
                                    "cpe":       "",
                                }
                            }
                        }
                    }
                }
            }
        """
        target = _validate_target(target)

        self._stop_event.clear()
        port_list = _parse_port_spec(ports)
        total     = len(port_list)

        # ── Diagnostic: print exact target string BEFORE any resolution ───────
        # A leading http://, trailing slash, or invisible whitespace will cause
        # every port to silently resolve as 'filtered' without this check.
        clean_target, san_warns = _sanitize_target(target)
        if san_warns or clean_target != target:
            msg = (
                f"[socket-scan] WARNING — target string was sanitised:\n"
                f"  raw  : {target!r}\n"
                f"  clean: {clean_target!r}\n"
                + "\n".join(f"  • {w}" for w in san_warns)
            )
            if on_line:
                on_line(msg)
            _diag_log.warning(msg)
            target = clean_target   # use the sanitised string going forward
        else:
            if on_line:
                on_line(f"[socket-scan] Target string: {target!r}  (no sanitisation needed)")

        # ── DNS resolution — surface gaierror as a distinct failure ───────────
        # Without this explicit check, socket.gaierror (a subclass of OSError)
        # is silently caught inside _classify_port() and returns 'filtered' for
        # every single port, making a DNS failure look like a scan result.
        try:
            resolved_ip = socket.gethostbyname(target)
            if on_line:
                on_line(f"[socket-scan] DNS resolved {target!r}  →  {resolved_ip}")
        except socket.gaierror as e:
            err = (
                f"[socket-scan] DNS RESOLUTION FAILED for {target!r}: "
                f"{type(e).__name__}  errno={e.errno}  detail={e}\n"
                f"  This would have caused every port to show 'filtered' — "
                f"NOT a real scan result.\n"
                f"  Fix: verify the hostname spelling, check your internet "
                f"connection, or run 'ping {target}' in a terminal."
            )
            if on_line:
                on_line(err)
            _diag_log.error(err)
            # Re-raise so the worker can surface this as scan_error rather than
            # emitting a fake results dict full of 'filtered' ports.
            raise RuntimeError(err) from e

        # Try to get a reverse hostname
        try:
            hostname = socket.gethostbyaddr(resolved_ip)[0]
        except Exception:
            hostname = ""

        results: Dict = {
            "command": f"socket-scan {target} -p {ports or '1-1024'} -T {self.timeout}s",
            "scan_info": {
                "tcp": {"method": "Socket Connect"},
                "total_ports_expected": total,
                "stopped": False,
            },
            "hosts": {
                resolved_ip: {
                    "state":     "up",
                    "hostnames": [hostname] if hostname and hostname != resolved_ip else [],
                    "protocols": {"tcp": {}},
                }
            },
        }

        tcp_ports: Dict[int, Dict] = results["hosts"][resolved_ip]["protocols"]["tcp"]

        # Activate per-port exception logging so the first _DIAG_LOG_LIMIT
        # failures include exact exception type + errno instead of a flat
        # 'filtered' label.  Attach a handler only if none exists yet.
        global _diag_exception_count
        _diag_exception_count = 0
        if not _diag_log.handlers:
            _h = logging.StreamHandler()
            _h.setFormatter(logging.Formatter("%(message)s"))
            _diag_log.addHandler(_h)
        _diag_log.setLevel(logging.DEBUG)

        if on_line:
            on_line(f"[socket-scan] Starting scan of {total} ports on {resolved_ip}…")

        scan_start   = time.time()
        completed    = 0
        lock         = threading.Lock()
        last_progress_time = [time.time()]

        def _scan_one(port: int):
            nonlocal completed

            if stop_flag and stop_flag():
                return
            if self._stop_event.is_set():
                return

            state   = _classify_port(resolved_ip, port, self.timeout)

            # A stop request may arrive while connect_ex() is waiting. Do not
            # add a late result or emit progress after the user has stopped.
            if (stop_flag and stop_flag()) or self._stop_event.is_set():
                return

            svc     = _service_name(port, "tcp")

            port_dict = {
                "state":     state,
                "name":      svc,
                "product":   "",
                "version":   "",
                "extrainfo": "",
                "reason":    ("syn-ack" if state == "open"
                              else "reset" if state == "closed"
                              else "no-response"),
                "cpe":       "",
            }

            with lock:
                tcp_ports[port] = port_dict
                completed += 1
                now = time.time()
                pct = completed / total * 100.0

                # Fire on_port for every port (not just open ones)
                if on_port:
                    on_port({
                        "host":    resolved_ip,
                        "port":    port,
                        "proto":   "tcp",
                        "state":   state,
                        "service": svc,
                        "reason":  port_dict["reason"],
                        "latency": "",
                    })

                # Throttle progress callbacks to avoid flooding the UI
                if on_progress and (now - last_progress_time[0] >= 0.5 or completed == total):
                    elapsed = now - scan_start
                    on_progress(
                        pct,
                        f"Socket scan… {pct:.1f}%  "
                        f"({completed}/{total} ports, {elapsed:.1f}s elapsed)"
                    )
                    last_progress_time[0] = now

                # Emit a line to the live console for every port so the
                # console stays active.  Format mimics nmap's final table so
                # existing colour-coding in the UI handler fires correctly.
                if on_line:
                    if state == "open":
                        # Green "Discovered" line — matches nmap's live output
                        on_line(
                            f"Discovered open port {port}/tcp on {resolved_ip}"
                        )
                    else:
                        # Mimic nmap final-table row:  "80/tcp   closed   http"
                        svc_col = svc if svc else ""
                        on_line(
                            f"{port}/tcp   {state:<10} {svc_col}"
                        )

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.max_workers
        ) as executor:
            futures = {executor.submit(_scan_one, p): p for p in port_list}
            for future in concurrent.futures.as_completed(futures):
                if (stop_flag and stop_flag()) or self._stop_event.is_set():
                    # Cancel remaining futures gracefully
                    for f in futures:
                        f.cancel()
                    break
                try:
                    future.result()
                except Exception:
                    pass

        elapsed = time.time() - scan_start
        was_stopped = bool(
            (stop_flag and stop_flag()) or self._stop_event.is_set()
        )
        results["scan_info"]["elapsed"] = f"{elapsed:.2f}s"
        results["scan_info"]["stopped"] = was_stopped
        results["scan_info"]["ports_scanned"] = completed

        # Never report 100% for an intentionally interrupted scan.
        if on_progress:
            if was_stopped:
                pct = (completed / total * 100.0) if total else 100.0
                on_progress(
                    pct,
                    f"Socket scan stopped at {pct:.1f}% "
                    f"({completed}/{total} ports, {elapsed:.1f}s elapsed)"
                )
            else:
                on_progress(100.0, f"Socket scan complete in {elapsed:.2f}s")
        if on_line:
            status = "stopped" if was_stopped else "done"
            on_line(
                f"[socket-scan] {status.capitalize()} — "
                f"{completed}/{total} ports scanned in {elapsed:.2f}s"
            )

        return results

    def stop_live_scan(self):
        """Alias used by ScanWorker.stop() for interface compatibility."""
        self.stop()


################################################################################
# SECTION: advanced_scanner  (from advanced_scanner.py)
################################################################################

"""
Advanced scanning capabilities with multiple techniques.
Includes stealth, OS detection, vulnerability mapping, and evasion.

NOTE ON REMOVED PROFILES (Decoy Scan, MAC Spoofing Scan, Source Port Evasion,
Full Evasion Combo): these were removed because they only function correctly
when nmap is run with root/Administrator privileges (raw-socket access).
Without elevation, nmap silently drops -D / --spoof-mac / --source-port and
falls back to a plain unprivileged connect scan — so the scan still "runs"
but produces no actual decoy, spoofing, or evasion behaviour, which is
misleading. MAC spoofing is additionally only meaningful against hosts on
the same physical Ethernet segment and has no effect on remote/Internet
targets, which is the typical use case for this tool. Service Scripts Scan
and Vulnerability Scan are kept because they work correctly without
elevated privileges.
"""



class AdvancedScanProfile(ScanProfile):
    """Extended scan profiles with advanced techniques."""
    
    # Service & Version Fingerprinting
    AGGRESSIVE_VERSION = {
        "name": "🔍 Aggressive Version Detection",
        "ports": "1-65535",
        "arguments": "-sV --version-intensity 9 -T4",
        "description": "Maximum version detection intensity across all ports"
    }
    
    SERVICE_SCRIPTS = {
        "name": "📜 Service Scripts Scan",
        "ports": "1-1024",
        "arguments": "-sV -sC -T4",
        "description": "Version detection + default NSE scripts. Works without root/Administrator privileges."
    }
    
    # Vulnerability Mapping
    VULN_SCAN = {
        "name": "🛡️ Vulnerability Scan",
        "ports": "1-1024",
        "arguments": "-sV --script vuln -T4",
        "description": "Check for known vulnerabilities using NSE scripts. Works without root/Administrator privileges; may take longer to run."
    }
    
    # Comprehensive
    FULL_COMPREHENSIVE = {
        "name": "🎯 Full Comprehensive",
        "ports": "1-65535",
        "arguments": "-sV -sC --traceroute -T4",
        "description": "Full scan: version detection, scripts, and traceroute"
    }

    # Stealth / Firewall & IDS Evasion
    # NOTE: -sS (SYN scan) and -f (fragmentation) require raw-socket
    # access, i.e. root/Administrator privileges. Running unprivileged silently
    # falls back to a -sT connect scan in nmap, which defeats the evasion intent.
    STEALTH_SYN = {
        "name": "🥷 Stealth SYN Scan",
        "ports": "1-1024",
        "arguments": "-sS -T2",
        "description": "Half-open SYN scan — quieter than a full TCP connect (requires root/admin)"
    }

    FRAGMENTED_SCAN = {
        "name": "🧩 Fragmented Packet Scan",
        "ports": "1-1024",
        "arguments": "-sS -f -T2",
        "description": "Splits probes into 8-byte IP fragments to slip past simple packet filters (requires root/admin)"
    }

    @classmethod
    def get_all_profiles(cls) -> List[Dict]:
        """Return all available scan profiles including advanced ones."""
        basic_profiles = super().get_all_profiles()
        advanced_profiles = [
            cls.AGGRESSIVE_VERSION,
            cls.SERVICE_SCRIPTS,
            cls.VULN_SCAN,
            cls.FULL_COMPREHENSIVE,
            cls.STEALTH_SYN,
            cls.FRAGMENTED_SCAN,
        ]
        return basic_profiles + advanced_profiles


class AdvancedScanner(PortScanner):
    """Enhanced scanner with advanced capabilities."""
    
    def __init__(self, nmap_path: Optional[str] = None):
        """Initialize advanced scanner."""
        super().__init__(nmap_path)
    
    def detect_os(self, target: str, aggressive: bool = True) -> Dict:
        """
        Perform OS detection on target.
        
        Args:
            target: Target IP or hostname
            aggressive: Use aggressive OS detection
        
        Returns:
            Dictionary with OS detection results
        """
        # Nmap OS fingerprinting always requires -O.  The non-aggressive
        # mode therefore uses -O without --osscan-guess rather than -sV,
        # which is service/version detection and cannot populate osmatch.
        args = "-O --osscan-guess" if aggressive else "-O"
        
        target = _validate_target(target)

        try:
            self.scanner.scan(target, arguments=args)
            
            results = {"os_matches": []}
            
            for host in self.scanner.all_hosts():
                if "osmatch" in self.scanner[host]:
                    for os_match in self.scanner[host]["osmatch"]:
                        results["os_matches"].append({
                            "name": os_match.get("name", "Unknown"),
                            "accuracy": os_match.get("accuracy", "0"),
                            "type": "Active" if aggressive else "Passive"
                        })
            
            return results
        except Exception as e:
            raise Exception(f"OS detection failed: {str(e)}")
    
    def vulnerability_scan(self, target: str, ports: str = "1-1024") -> Dict:
        """
        Scan for vulnerabilities using NSE scripts.
        
        Args:
            target: Target IP or hostname
            ports: Port range to scan
        
        Returns:
            Dictionary with vulnerability information
        """
        target = _validate_target(target)

        try:
            self.scanner.scan(
                target,
                ports,
                arguments="-sV --script vuln,exploit,vulners -T4"
            )
            
            results = {"vulnerabilities": []}
            
            for host in self.scanner.all_hosts():
                for proto in self.scanner[host].all_protocols():
                    for port in self.scanner[host][proto].keys():
                        port_info = self.scanner[host][proto][port]
                        
                        if "script" in port_info:
                            for script_name, script_output in port_info["script"].items():
                                results["vulnerabilities"].append({
                                    "host": host,
                                    "port": port,
                                    "protocol": proto,
                                    "script": script_name,
                                    "output": script_output
                                })
            
            return results
        except Exception as e:
            raise Exception(f"Vulnerability scan failed: {str(e)}")
    
    def detect_honeypot(self, target: str, port_range: str = "1-100") -> Dict:
        """
        Attempt to detect if target is a honeypot.
        
        Args:
            target: Target IP or hostname
            port_range: Nmap port specification to scan (defaults to 1-100)
        
        Returns:
            Dictionary with honeypot indicators
        """
        indicators = {
            "suspicious_behaviors": [],
            "confidence": "low"
        }
        
        target = _validate_target(target)

        try:
            # Quick scan to check response patterns
            self.scanner.scan(target, port_range, arguments="-sV -T2")
            total_ports_scanned = len(_parse_port_spec(port_range))
            
            if not self.scanner.all_hosts():
                return indicators
            
            host = self.scanner.all_hosts()[0]
            
            # Check for suspicious patterns
            open_ports = 0
            for proto in self.scanner[host].all_protocols():
                open_ports += len([p for p, info in self.scanner[host][proto].items() 
                                  if info.get("state") == "open"])
            
            # Too many open ports is suspicious
            if open_ports > 50:
                indicators["suspicious_behaviors"].append(
                    f"Unusually high number of open ports ({open_ports})"
                )
                indicators["confidence"] = "medium"
            
            # Compare against the number of ports actually requested from Nmap,
            # not len(self.scanner[host][proto]). Nmap may omit closed/filtered
            # ports from the results dict and summarize them as "Not shown: N ports".
            if total_ports_scanned > 0 and open_ports == total_ports_scanned:
                indicators["suspicious_behaviors"].append(
                    f"All {total_ports_scanned} scanned ports are open — classic honeypot behavior"
                )
                indicators["confidence"] = "high"
            
            return indicators
        
        except Exception as e:
            indicators["error"] = str(e)
            return indicators
    
    def firewall_detect(self, target: str, port_range: str = "1-100") -> Dict:
        """
        Detect firewall presence and type.
        
        Args:
            target: Target IP or hostname
            port_range: Nmap port specification to scan (defaults to 1-100)
        
        Returns:
            Dictionary with firewall detection results
        """
        target = _validate_target(target)

        try:
            # Use various techniques to detect firewall
            self.scanner.scan(
                target,
                port_range,
                arguments="-sA --script firewall-bypass -T4"
            )
            
            results = {
                "firewall_detected": False,
                "filtered_ports": 0,
                "unfiltered_ports": 0,
                "indicators": []
            }
            
            if not self.scanner.all_hosts():
                return results
            
            host = self.scanner.all_hosts()[0]
            
            for proto in self.scanner[host].all_protocols():
                for port, info in self.scanner[host][proto].items():
                    state = info.get("state", "unknown")
                    
                    if state == "filtered":
                        results["filtered_ports"] += 1
                    elif state == "unfiltered":
                        # -sA (ACK scan) cannot distinguish open from closed.
                        # Nmap reports unfiltered when ACK probes receive a
                        # response, so expose that state instead of pretending
                        # these are confirmed open ports.
                        results["unfiltered_ports"] += 1
            
            # High ratio of filtered ports suggests firewall
            if results["filtered_ports"] > 20:
                results["firewall_detected"] = True
                results["indicators"].append(
                    f"High number of filtered ports ({results['filtered_ports']})"
                )
            
            return results
        
        except Exception as e:
            raise Exception(f"Firewall detection failed: {str(e)}")
    
    def traceroute(self, target: str) -> List[Dict]:
        """
        Perform traceroute to target.
        
        Args:
            target: Target IP or hostname
        
        Returns:
            List of hops with timing information
        """
        target = _validate_target(target)

        try:
            # Give --traceroute a real TCP probe to attach to. -Pn skips host discovery
            # (so ICMP blocking does not prevent the scan), while -p 80,443 probes
            # common web ports and lets traceroute ride on the TCP probe packets.
            self.scanner.scan(target, arguments="-Pn -p 80,443 --traceroute")

            hops = []

            if self.scanner.all_hosts():
                host = self.scanner.all_hosts()[0]
                trace = self.scanner[host].get("trace", {})
                for hop in trace.get("hops", []):
                    if not isinstance(hop, dict):
                        continue
                    hops.append({
                        "hop": hop.get("ttl", "?"),
                        "ip": hop.get("ipaddr", "Unknown"),
                        "hostname": hop.get("host", "Unknown"),
                        "rtt": hop.get("rtt", "N/A"),
                    })

            return sorted(
                hops,
                key=lambda x: int(x["hop"]) if str(x["hop"]).isdigit() else 0
            )
        
        except Exception as e:
            raise Exception(f"Traceroute failed: {str(e)}")


################################################################################
# SECTION: banner_grabber  (from banner_grabber.py)
################################################################################

"""
banner_grabber.py
-----------------
Service banner / version grabbing for open ports.
Uses direct socket connections (HTTP, FTP, SSH, Telnet, SMTP, DNS) to
retrieve richer version info than a plain nmap scan provides.

All functions are safe to call from a background thread and never raise —
they return None on any failure so the caller can continue gracefully.
"""


# Optional heavy deps — imported lazily so the app starts even without them.
_requests  = None
_dns       = None


def _get_requests():
    global _requests
    if _requests is None:
        try:
            import requests as req
            _requests = req
        except ImportError:
            pass
    return _requests


def _get_dns():
    global _dns
    if _dns is None:
        try:
            import dns.resolver
            _dns = dns.resolver
        except ImportError:
            pass
    return _dns


# ---------------------------------------------------------------------------
# Per-protocol grabbers
# ---------------------------------------------------------------------------

def _grab_http(target: str, port: int, timeout: float) -> Optional[str]:
    """Return the Server: header from an HTTP response, or None."""
    req = _get_requests()
    if req is None:
        return None
    try:
        scheme = "https" if port in (443, 8443) else "http"
        r = req.get(
            f"{scheme}://{target}:{port}",
            timeout=timeout,
            # verify=False is intentional: this scanner probes arbitrary hosts,
            # many of which use self-signed certificates. Enforcing verification
            # would cause the majority of HTTPS banner grabs to fail with
            # SSLError. This connection is read-only (GET, no credentials sent).
            verify=False,
            allow_redirects=False,
        )
        return r.headers.get("Server") or r.headers.get("X-Powered-By")
    except Exception:
        return None


def _grab_ftp(target: str, port: int, timeout: float) -> Optional[str]:
    """Return FTP server welcome banner."""
    try:
        ftp = ftplib.FTP()
        ftp.connect(target, port, timeout=timeout)
        banner = ftp.getwelcome()
        ftp.quit()
        return banner.strip() if banner else None
    except Exception:
        return None


def _grab_ssh(target: str, port: int, timeout: float) -> Optional[str]:
    """Return the SSH server's identification string, e.g. 'SSH-2.0-OpenSSH_9.6'.

    SSH servers send this line as soon as the TCP connection opens (RFC 4253,
    section 4.2), so it can be read without starting a login. Servers may send
    other lines first, so return the first line that starts with 'SSH-'.
    """
    data = b""
    try:
        with socket.create_connection((target, port), timeout=timeout) as s:
            while len(data) < 4096 and not re.search(rb"^SSH-.*\n", data, re.M):
                chunk = s.recv(1024)
                if not chunk:
                    break
                data += chunk
    except Exception:
        pass  # keep whatever arrived before the timeout or disconnect
    match = re.search(rb"^SSH-[^\r\n]*", data, re.M)
    return match.group().decode(errors="replace") if match else None


def _grab_telnet(target: str, port: int, timeout: float) -> Optional[str]:
    """Return first line of Telnet banner via raw socket."""
    try:
        with socket.create_connection((target, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = s.recv(512)
            # Strip telnet IAC negotiation bytes (0xFF prefix sequences)
            import re
            text = re.sub(rb"\xff[\xfb-\xfe].", b"", data)
            return text.decode(errors="replace").strip()[:120] or None
    except Exception:
        return None


def _grab_smtp(target: str, port: int, timeout: float) -> Optional[str]:
    """Return SMTP server greeting."""
    try:
        smtp = smtplib.SMTP(timeout=timeout)
        code, msg = smtp.connect(target, port)
        smtp.quit()
        return msg.decode(errors="replace").strip() if isinstance(msg, bytes) else str(msg).strip()
    except Exception:
        return None


def _grab_dns(target: str, timeout: float) -> Optional[str]:
    """Return DNS server version via CHAOS TXT query."""
    resolver = _get_dns()
    if resolver is None:
        return None
    try:
        r = resolver.Resolver()
        r.nameservers = [target]
        r.timeout = timeout
        r.lifetime = timeout
        answer = r.resolve("version.bind.", "TXT", rdclass="CHAOS")
        for rdata in answer:
            for s in rdata.strings:
                return s.decode(errors="replace")
    except Exception:
        return None
    return None


def _grab_generic(target: str, port: int, timeout: float) -> Optional[str]:
    """Raw socket read — grab whatever the server sends on connect."""
    try:
        with socket.create_connection((target, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = s.recv(256)
            return data.decode(errors="replace").strip()[:120] if data else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

# Map port number → grabber function
_PORT_GRABBERS = {
    21:   lambda t, p, to: _grab_ftp(t, p, to),
    22:   lambda t, p, to: _grab_ssh(t, p, to),
    23:   lambda t, p, to: _grab_telnet(t, p, to),
    25:   lambda t, p, to: _grab_smtp(t, p, to),
    53:   lambda t, p, to: _grab_dns(t, to),
    80:   lambda t, p, to: _grab_http(t, p, to),
    110:  lambda t, p, to: _grab_generic(t, p, to),   # POP3
    143:  lambda t, p, to: _grab_generic(t, p, to),   # IMAP
    443:  lambda t, p, to: _grab_http(t, p, to),
    587:  lambda t, p, to: _grab_smtp(t, p, to),
    8080: lambda t, p, to: _grab_http(t, p, to),
    8443: lambda t, p, to: _grab_http(t, p, to),
    8888: lambda t, p, to: _grab_http(t, p, to),
}


def grab_banner(target: str, port: int, timeout: float = 3.0) -> Optional[str]:
    """
    Attempt to grab a service banner / version string for the given port.

    Returns a short descriptive string, or None if nothing could be retrieved.
    Never raises.
    """
    try:
        grabber = _PORT_GRABBERS.get(port, lambda t, p, to: _grab_generic(t, p, to))
        result = grabber(target, port, timeout)
        if result:
            # Sanitise: strip control chars, cap length
            import re
            result = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", result)
            return result[:120].strip() or None
        return None
    except Exception:
        return None


def enrich_scan_results(results: dict, timeout: float = 3.0,
                        stop_flag=None) -> dict:
    """
    Walk every OPEN port in `results` and attempt to grab a banner.
    Updates the port's 'product' or 'extrainfo' field in-place if empty.

    Args:
        results:   The results dict from PortScanner.run_scan_live()
        timeout:   Per-connection timeout in seconds
        stop_flag: Optional callable() -> bool; if True, stop early

    Returns the same results dict (mutated in-place).
    """
    import concurrent.futures

    tasks = []
    for host, host_info in results.get("hosts", {}).items():
        for proto, ports in host_info.get("protocols", {}).items():
            for port, d in ports.items():
                if d.get("state") == "open":
                    tasks.append((host, proto, port, d))

    if not tasks:
        return results

    def _grab(args):
        host, proto, port, d = args
        if stop_flag and stop_flag():
            return
        banner = grab_banner(host, port, timeout)
        if banner:
            # Fill product if empty, otherwise append to extrainfo
            if not d.get("product"):
                d["product"] = banner
            elif not d.get("extrainfo"):
                d["extrainfo"] = banner

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(_grab, t): t for t in tasks}
        for f in concurrent.futures.as_completed(futures):
            if stop_flag and stop_flag():
                break
            try:
                f.result()
            except Exception:
                pass

    return results


################################################################################
# SECTION: ai_analysis  (from ai_analysis.py)
################################################################################

"""
AI analysis module using Ollama for LLM-based scan result analysis.
"""



class OllamaClient:
    """Client for interacting with local Ollama LLM API."""
    
    def __init__(self, host: str = "localhost", port: int = 11434):
        self.base_url = f"http://{host}:{port}"
        self.api_url  = f"{self.base_url}/api"
    
    def is_available(self) -> bool:
        try:
            response = requests.get(f"{self.base_url}/", timeout=2)
            return response.status_code == 200
        except requests.exceptions.RequestException:
            return False
    
    def list_models(self) -> List[str]:
        try:
            response = requests.get(f"{self.api_url}/tags", timeout=5)
            response.raise_for_status()
            data = response.json()
            return [model["name"] for model in data.get("models", [])]
        except requests.exceptions.RequestException as e:
            raise ConnectionError(
                f"Failed to connect to Ollama at {self.base_url}\n"
                "Make sure Ollama is running (ollama serve)\n"
                f"Error: {str(e)}"
            )
    
    def generate(self, model: str, prompt: str, stream: bool = False) -> str:
        """
        Generate text using the specified Ollama model.

        When stream=False (legacy / blocking) the full response is returned
        as a string.  When stream=True the response is streamed — use
        generate_stream() for that path instead.
        """
        try:
            response = requests.post(
                f"{self.api_url}/generate",
                json={"model": model, "prompt": prompt, "stream": False},
                timeout=90,
            )
            response.raise_for_status()
            data = response.json()
            return data.get("response", "")
        except requests.exceptions.Timeout:
            raise ConnectionError(
                "Ollama request timed out. Try a smaller/faster model."
            )
        except requests.exceptions.RequestException as e:
            if "404" in str(e):
                raise ValueError(
                    f"Model '{model}' not found in Ollama.\n"
                    f"Pull it with: ollama pull {model}"
                )
            raise ConnectionError(
                f"Failed to generate response from Ollama: {str(e)}"
            )

    def generate_stream(
        self,
        model: str,
        prompt: str,
        on_token: Callable[[str], None],
        stop_flag: Optional[Callable[[], bool]] = None,
    ) -> str:
        """
        Stream a generation from Ollama, calling on_token() for each token.

        Returns the complete concatenated response string.
        Raises ConnectionError / ValueError on failure.
        """
        try:
            with requests.post(
                f"{self.api_url}/generate",
                json={"model": model, "prompt": prompt, "stream": True},
                stream=True,
                timeout=90,
            ) as response:
                response.raise_for_status()
                full = []
                for raw_line in response.iter_lines():
                    if stop_flag and stop_flag():
                        break
                    if not raw_line:
                        continue
                    try:
                        chunk = json.loads(raw_line)
                    except json.JSONDecodeError:
                        continue
                    token = chunk.get("response", "")
                    if token:
                        full.append(token)
                        on_token(token)
                    if chunk.get("done"):
                        break
                return "".join(full)
        except requests.exceptions.Timeout:
            raise ConnectionError(
                "Ollama streaming timed out. Try a smaller/faster model."
            )
        except requests.exceptions.RequestException as e:
            if "404" in str(e):
                raise ValueError(
                    f"Model '{model}' not found in Ollama.\n"
                    f"Pull it with: ollama pull {model}"
                )
            raise ConnectionError(
                f"Failed to stream response from Ollama: {str(e)}"
            )


class ScanAnalyzer:
    """Analyzes port scan results using an Ollama LLM."""
    
    def __init__(self, ollama_client: OllamaClient, model: str = "llama3"):
        self.client = ollama_client
        self.model  = model
    
    def analyze_scan_results(
        self,
        scan_results: Dict,
        on_token: Optional[Callable[[str], None]] = None,
        stop_flag: Optional[Callable[[], bool]] = None,
    ) -> str:
        """
        Analyze scan results using the LLM.

        Args:
            scan_results: Results dict from PortScanner / SocketScanner.
            on_token:     Optional callback fired for each streamed token.
                          When provided the response streams in real time.
            stop_flag:    Optional callable; return True to abort early.

        Returns:
            Complete AI analysis string.
        """
        # Build a concise summary — open ports only so the prompt stays small
        summary = self._build_scan_summary(scan_results)
        
        prompt = (
            "You are a security analyst reviewing a network port scan. "
            "Analyze the following scan results and provide:\n\n"
            "1. **Attack Surface Summary**: Brief overview of what's exposed\n"
            "2. **Security Risks**: Flag risky services "
            "(Telnet, FTP, unencrypted protocols, outdated versions)\n"
            "3. **Next Steps**: 2–3 concrete follow-up actions\n\n"
            "Be concise. Scan Results:\n"
            f"{summary}\n\n"
            "Provide your analysis in a clear, structured format."
        )

        try:
            if on_token is not None:
                return self.client.generate_stream(
                    self.model, prompt,
                    on_token=on_token,
                    stop_flag=stop_flag,
                )
            else:
                return self.client.generate(self.model, prompt, stream=False)
        except Exception as e:
            raise Exception(f"Failed to analyze scan results: {e}") from e
    
    def _build_scan_summary(self, scan_results: Dict) -> str:
        """
        Build a concise summary for the LLM — open ports only.

        Sending thousands of closed/filtered port rows to an LLM wastes
        tokens and slows the response without adding useful signal.
        """
        lines = []

        if "command" in scan_results:
            lines.append(f"Command: {scan_results['command']}")
            lines.append("")

        hosts = scan_results.get("hosts", {})
        if not hosts:
            return "No hosts discovered in scan."

        lines.append(f"Discovered {len(hosts)} host(s):")
        lines.append("")

        for host, host_info in hosts.items():
            lines.append(f"Host: {host} [{host_info.get('state', 'unknown')}]")
            hostnames = [h for h in host_info.get("hostnames", []) if h]
            if hostnames:
                lines.append(f"  Hostnames: {', '.join(hostnames)}")

            total_ports = 0
            open_ports  = 0
            for proto, ports in host_info.get("protocols", {}).items():
                total_ports += len(ports)
                open_entries = [
                    (p, d) for p, d in ports.items() if d.get("state") == "open"
                ]
                open_ports += len(open_entries)

                if open_entries:
                    lines.append(f"  Open {proto.upper()} ports:")
                    for port, d in sorted(open_entries):
                        svc     = d.get("name",    "unknown")
                        product = d.get("product", "")
                        version = d.get("version", "")
                        extra   = d.get("extrainfo","")
                        detail  = " ".join(filter(None, [product, version, extra]))
                        line    = f"    {port}/{proto} - {svc}"
                        if detail:
                            line += f" ({detail})"
                        lines.append(line)

            lines.append(
                f"  Summary: {open_ports} open, "
                f"{total_ports - open_ports} closed/filtered out of {total_ports} probed"
            )
            lines.append("")

        return "\n".join(lines)


################################################################################
# SECTION: anomaly_detector  (from anomaly_detector.py)
################################################################################

"""
Anomaly detection engine for identifying suspicious network behavior.
"""



class AnomalyDetector:
    """Detect anomalous behavior in scan results."""
    
    # Known suspicious port patterns
    SUSPICIOUS_PORTS = {
        31337: "Back Orifice trojan",
        12345: "NetBus trojan",
        54321: "Back Orifice 2000",
        1243: "SubSeven trojan",
        6667: "IRC (often used by botnets)",
        6668: "IRC (often used by botnets)",
        6669: "IRC (often used by botnets)",
    }
    
    # Honeypot indicators
    HONEYPOT_PORTS = [23, 135, 139, 445, 1433, 3306, 3389, 5900]
    
    @staticmethod
    def analyze_scan_results(scan_results: Dict) -> Dict:
        """
        Analyze scan results for anomalies and suspicious patterns.
        
        Args:
            scan_results: Scan results from PortScanner
        
        Returns:
            Dictionary with anomaly detection results
        """
        anomalies = {
            "alerts": [],
            "warnings": [],
            "info": [],
            "risk_score": 0,
            "honeypot_indicators": [],
            "suspicious_services": [],
            "port_distribution": {}
        }
        
        hosts = scan_results.get("hosts", {})
        
        if not hosts:
            return anomalies
        
        for host, host_info in hosts.items():
            protocols = host_info.get("protocols", {})
            
            for proto, ports in protocols.items():
                open_ports = [p for p, info in ports.items() if info.get("state") == "open"]
                
                # Check 1: Suspicious port detection
                for port in open_ports:
                    if port in AnomalyDetector.SUSPICIOUS_PORTS:
                        anomalies["alerts"].append({
                            "type": "Suspicious Port",
                            "host": host,
                            "port": port,
                            "description": AnomalyDetector.SUSPICIOUS_PORTS[port],
                            "severity": "HIGH"
                        })
                        anomalies["risk_score"] += 20
                
                # Check 2: Too many open ports (possible honeypot)
                if len(open_ports) > 50:
                    anomalies["honeypot_indicators"].append({
                        "host": host,
                        "indicator": f"Unusually high number of open ports ({len(open_ports)})",
                        "confidence": "medium" if len(open_ports) < 100 else "high"
                    })
                    anomalies["risk_score"] += 15
                
                # Check 3: All ports open (strong honeypot indicator)
                if len(open_ports) == len(ports):
                    anomalies["alerts"].append({
                        "type": "Honeypot Detection",
                        "host": host,
                        "description": "All scanned ports are open - possible honeypot",
                        "severity": "CRITICAL"
                    })
                    anomalies["risk_score"] += 50
                
                # Check 4: Common honeypot port pattern
                honeypot_open = [p for p in AnomalyDetector.HONEYPOT_PORTS if p in open_ports]
                if len(honeypot_open) >= 5:
                    anomalies["honeypot_indicators"].append({
                        "host": host,
                        "indicator": f"Multiple common honeypot ports open: {honeypot_open}",
                        "confidence": "high"
                    })
                    anomalies["risk_score"] += 25
                
                # Check 5: Vulnerable or outdated services
                for port, port_info in ports.items():
                    service = port_info.get("name", "").lower()
                    version = port_info.get("version", "").lower()
                    product = port_info.get("product", "").lower()
                    
                    # Check for cleartext protocols
                    if service in ["telnet", "ftp", "http"]:
                        anomalies["warnings"].append({
                            "type": "Cleartext Protocol",
                            "host": host,
                            "port": port,
                            "service": service,
                            "description": f"{service.upper()} transmits data in cleartext",
                            "severity": "MEDIUM"
                        })
                        anomalies["risk_score"] += 5
                    
                    # Check for anonymous FTP
                    if service == "ftp" and "anonymous" in product:
                        anomalies["alerts"].append({
                            "type": "Anonymous Access",
                            "host": host,
                            "port": port,
                            "description": "FTP allows anonymous login",
                            "severity": "HIGH"
                        })
                        anomalies["risk_score"] += 15
                    
                    # Check for old SSH versions
                    if service == "ssh" and version:
                        try:
                            version_num = float(version.split()[0])
                            if version_num < 2.0:
                                anomalies["alerts"].append({
                                    "type": "Outdated Service",
                                    "host": host,
                                    "port": port,
                                    "description": f"SSH version {version} is outdated and vulnerable",
                                    "severity": "HIGH"
                                })
                                anomalies["risk_score"] += 20
                        except Exception:
                            pass
                    
                    # Check for SMB (often targeted)
                    if service in ["microsoft-ds", "netbios-ssn"] or port in [139, 445]:
                        anomalies["info"].append({
                            "type": "High-Value Target",
                            "host": host,
                            "port": port,
                            "description": "SMB service detected - commonly targeted by attacks",
                            "severity": "INFO"
                        })
                        anomalies["risk_score"] += 3
                    
                    # Check for RDP
                    if service == "ms-wbt-server" or port == 3389:
                        anomalies["warnings"].append({
                            "type": "Remote Access",
                            "host": host,
                            "port": port,
                            "description": "RDP (Remote Desktop) is exposed - ensure strong authentication",
                            "severity": "MEDIUM"
                        })
                        anomalies["risk_score"] += 10
                
                # Check 6: Port distribution analysis
                if len(open_ports) > 0:
                    # Analyze port number distribution
                    low_ports = len([p for p in open_ports if p < 1024])
                    high_ports = len([p for p in open_ports if p >= 1024])
                    
                    anomalies["port_distribution"][host] = {
                        "total_open": len(open_ports),
                        "low_ports": low_ports,
                        "high_ports": high_ports,
                        "ratio": round(low_ports / len(open_ports), 2) if len(open_ports) > 0 else 0
                    }
                    
                    # Unusual distribution can indicate scanning/honeypot
                    if high_ports > low_ports * 3:
                        anomalies["warnings"].append({
                            "type": "Unusual Port Distribution",
                            "host": host,
                            "description": f"Many high-numbered ports open ({high_ports} high vs {low_ports} low)",
                            "severity": "MEDIUM"
                        })
                        anomalies["risk_score"] += 8
        
        # Normalize risk score (0-100)
        anomalies["risk_score"] = min(100, anomalies["risk_score"])
        
        # Determine overall risk level
        if anomalies["risk_score"] >= 70:
            anomalies["risk_level"] = "CRITICAL"
        elif anomalies["risk_score"] >= 40:
            anomalies["risk_level"] = "HIGH"
        elif anomalies["risk_score"] >= 20:
            anomalies["risk_level"] = "MEDIUM"
        else:
            anomalies["risk_level"] = "LOW"
        
        return anomalies
    
    @staticmethod
    def format_anomaly_report(anomalies: Dict) -> str:
        """
        Format anomaly detection results into readable report.
        
        Args:
            anomalies: Anomaly detection results
        
        Returns:
            Formatted text report
        """
        lines = []
        
        lines.append("=" * 80)
        lines.append("ANOMALY DETECTION REPORT")
        lines.append("=" * 80)
        lines.append("")
        
        # Risk Score
        risk_score = anomalies.get("risk_score", 0)
        risk_level = anomalies.get("risk_level", "UNKNOWN")
        
        lines.append(f"Overall Risk Score: {risk_score}/100 [{risk_level}]")
        lines.append("")
        
        # Alerts (Critical issues)
        alerts = anomalies.get("alerts", [])
        if alerts:
            lines.append("🚨 CRITICAL ALERTS:")
            lines.append("-" * 80)
            for alert in alerts:
                lines.append(f"  [{alert['severity']}] {alert['type']}")
                lines.append(f"  Host: {alert.get('host', 'N/A')}")
                if 'port' in alert:
                    lines.append(f"  Port: {alert['port']}")
                lines.append(f"  Description: {alert['description']}")
                lines.append("")
        
        # Warnings
        warnings = anomalies.get("warnings", [])
        if warnings:
            lines.append("⚠️  WARNINGS:")
            lines.append("-" * 80)
            for warning in warnings:
                lines.append(f"  [{warning['severity']}] {warning['type']}")
                lines.append(f"  Host: {warning.get('host', 'N/A')}")
                if 'port' in warning:
                    lines.append(f"  Port: {warning['port']}")
                if 'service' in warning:
                    lines.append(f"  Service: {warning['service']}")
                lines.append(f"  Description: {warning['description']}")
                lines.append("")
        
        # Honeypot Indicators
        honeypot_indicators = anomalies.get("honeypot_indicators", [])
        if honeypot_indicators:
            lines.append("🍯 HONEYPOT INDICATORS:")
            lines.append("-" * 80)
            for indicator in honeypot_indicators:
                lines.append(f"  Host: {indicator['host']}")
                lines.append(f"  Indicator: {indicator['indicator']}")
                lines.append(f"  Confidence: {indicator['confidence'].upper()}")
                lines.append("")
        
        # Info Messages
        info_messages = anomalies.get("info", [])
        if info_messages:
            lines.append("ℹ️  INFORMATION:")
            lines.append("-" * 80)
            for info in info_messages:
                lines.append(f"  {info['type']}: {info['description']}")
                lines.append(f"  Host: {info.get('host', 'N/A')} | Port: {info.get('port', 'N/A')}")
                lines.append("")
        
        # Port Distribution
        port_dist = anomalies.get("port_distribution", {})
        if port_dist:
            lines.append("📊 PORT DISTRIBUTION ANALYSIS:")
            lines.append("-" * 80)
            for host, dist in port_dist.items():
                lines.append(f"  Host: {host}")
                lines.append(f"  Total Open: {dist['total_open']}")
                lines.append(f"  Low Ports (<1024): {dist['low_ports']}")
                lines.append(f"  High Ports (≥1024): {dist['high_ports']}")
                lines.append(f"  Ratio: {dist['ratio']}")
                lines.append("")
        
        if not alerts and not warnings and not honeypot_indicators:
            lines.append("✅ No significant anomalies detected.")
            lines.append("")
        
        lines.append("=" * 80)
        
        return "\n".join(lines)


################################################################################
# SECTION: report_generator  (from report_generator.py)
################################################################################

"""
report_generator.py
-------------------
Professional report generation for AI Port Scanner results.

Supported output formats
------------------------
    TXT   – clean plain-text (no box-drawing chars)
    CSV   – ports table + separate anomaly-warnings CSV
    JSON  – fully structured machine-readable object
    HTML  – responsive single-page with dashboard, sortable/filterable table,
            severity badges
    PDF   – print-ready via reportlab
    DOCX  – Word document with heading styles and executive summary

Every human-readable format highlights:
    • Open port 80 / HTTP exposure
    • Cleartext-protocol warnings (HTTP, FTP, Telnet)
    • Overall risk score with LOW/MEDIUM/HIGH/CRITICAL label
"""

# ── stdlib ────────────────────────────────────────────────────────────────────

# ── reportlab ─────────────────────────────────────────────────────────────────

# ── python-docx ───────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# Shared colour constants
# ─────────────────────────────────────────────────────────────────────────────
_C_BRAND      = colors.HexColor("#4A6CF7")
_C_BRAND_DARK = colors.HexColor("#2D3A8C")
_C_OPEN       = colors.HexColor("#16A34A")
_C_CLOSED     = colors.HexColor("#DC2626")
_C_FILTERED   = colors.HexColor("#D97706")
_C_CRITICAL   = colors.HexColor("#991B1B")
_C_HIGH       = colors.HexColor("#DC2626")
_C_MEDIUM     = colors.HexColor("#D97706")
_C_LOW        = colors.HexColor("#16A34A")
_C_INFO       = colors.HexColor("#2563EB")
_C_LIGHT_GREY = colors.HexColor("#F3F4F6")
_C_MID_GREY   = colors.HexColor("#E5E7EB")
_C_TEXT       = colors.HexColor("#374151")

_CLEARTEXT_SERVICES = {"http", "ftp", "telnet", "smtp", "pop3", "imap"}


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _risk_label(score) -> str:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "UNKNOWN"
    if s >= 75: return "CRITICAL"
    if s >= 50: return "HIGH"
    if s >= 25: return "MEDIUM"
    return "LOW"


def _sev_hex(sev: str) -> str:
    return {"CRITICAL":"#991B1B","HIGH":"#DC2626","MEDIUM":"#D97706",
            "LOW":"#16A34A","INFO":"#2563EB"}.get(sev.upper(), "#6B7280")


def _rl_color(score):
    return {"CRITICAL":_C_CRITICAL,"HIGH":_C_HIGH,
            "MEDIUM":_C_MEDIUM,"LOW":_C_LOW}.get(_risk_label(score), colors.grey)


def _collect_stats(scan_results: Dict) -> Dict:
    hosts = scan_results.get("hosts", {})
    total = open_ = closed = filtered = 0
    for hi in hosts.values():
        for pp in hi.get("protocols", {}).values():
            for pi in pp.values():
                total += 1
                s = pi.get("state", "")
                if s == "open":           open_    += 1
                elif s == "closed":       closed   += 1
                elif "filtered" in s:     filtered += 1
    si = scan_results.get("scan_info", {})
    expected = si.get("total_ports_expected", total)
    scanned = si.get("ports_scanned")
    stopped = bool(si.get("stopped", False))
    # ``ports_scanned`` is meaningful for the socket scanner.  For Nmap,
    # retain the reported/expected count when that field is absent.
    if scanned is None:
        scanned = total
    return {
        "hosts_count":    len(hosts),
        "ports_probed":   scanned if stopped else expected,
        "ports_expected": expected,
        "ports_scanned":  scanned,
        "ports_reported": total,
        "open":           open_,
        "closed":         closed,
        "filtered":       filtered,
        "elapsed":        si.get("elapsed", ""),
        "method":         si.get("tcp", {}).get("method", ""),
        "stopped":        stopped,
    }


def _collect_ports(scan_results: Dict) -> List[Dict]:
    rows = []
    for host, hi in sorted(scan_results.get("hosts", {}).items()):
        for proto, pp in hi.get("protocols", {}).items():
            for port, pi in sorted(pp.items(), key=lambda x: int(x[0])):
                rows.append({
                    "host":      host,
                    "port":      int(port),
                    "proto":     proto.upper(),
                    "state":     pi.get("state",     ""),
                    "service":   pi.get("name",      ""),
                    "product":   pi.get("product",   ""),
                    "version":   pi.get("version",   ""),
                    "extrainfo": pi.get("extrainfo", ""),
                    "reason":    pi.get("reason",    ""),
                    "cpe":       pi.get("cpe",       ""),
                })
    return rows


def _parse_ai(ai_text: str) -> Dict:
    if not ai_text:
        return {"attack_surface": "", "risks": [], "next_steps": [], "raw": ""}
    secs: Dict[str, List[str]] = {"attack_surface": [], "risks": [], "next_steps": []}
    cur = None
    for line in ai_text.splitlines():
        low = line.lower()
        if "attack surface" in low:             cur = "attack_surface"
        elif "risk" in low or "vulnerab" in low: cur = "risks"
        elif "next step" in low or "recommend" in low or "remediat" in low:
                                                 cur = "next_steps"
        elif cur and line.strip():
            secs[cur].append(line.strip())
    return {
        "attack_surface": " ".join(secs["attack_surface"]),
        "risks":          secs["risks"],
        "next_steps":     secs["next_steps"],
        "raw":            ai_text,
    }


def _parse_anomalies(anomaly_data) -> Dict:
    if anomaly_data is None:
        return {"risk_score": None, "risk_label": "UNKNOWN",
                "warnings": [], "port_distribution": ""}
    if isinstance(anomaly_data, str):
        m     = re.search(r"risk[^:]*:\s*([\d.]+)", anomaly_data, re.IGNORECASE)
        score = float(m.group(1)) if m else None
        return {"risk_score": score, "risk_label": _risk_label(score),
                "warnings": [], "port_distribution": anomaly_data}
    if isinstance(anomaly_data, dict):
        score = anomaly_data.get("risk_score")
        norm  = []
        # Preserve the highest-severity findings as well as MEDIUM warnings.
        # AnomalyDetector stores CRITICAL/HIGH findings in ``alerts`` and
        # honeypot evidence separately, so ignoring those would make reports
        # materially under-report the scan risk.
        entries = []
        for w in anomaly_data.get("alerts", []):
            entries.append(w)
        for w in anomaly_data.get("warnings", []):
            entries.append(w)
        for w in anomaly_data.get("honeypot_indicators", []):
            if isinstance(w, dict):
                item = dict(w)
                # Honeypot confidence is the detector's strength signal; map it
                # to report severity instead of treating every indicator as HIGH.
                confidence = str(item.get("confidence", "")).strip().lower()
                confidence_to_severity = {"medium": "MEDIUM", "high": "HIGH"}
                item.setdefault("severity", confidence_to_severity.get(confidence, "HIGH"))
                # Honeypot records use ``indicator`` for their human-readable
                # finding.  Do not fall back to the raw dict representation.
                item.setdefault("description", item.get("indicator", item.get("message", item.get("type", str(item)))))
                entries.append(item)
            else:
                entries.append({"severity": "HIGH", "description": str(w)})
        for w in entries:
            if isinstance(w, dict):
                norm.append({"severity":    w.get("severity",    "INFO"),
                             "host":        w.get("host",        ""),
                             "port":        w.get("port",        ""),
                             "service":     w.get("service",     ""),
                             "description": w.get("description", w.get("message", str(w)))})
            else:
                norm.append({"severity":"INFO","host":"","port":"",
                             "service":"","description":str(w)})
        return {"risk_score": score, "risk_label": _risk_label(score),
                "warnings": norm,
                "port_distribution": anomaly_data.get("port_distribution", "")}
    return {"risk_score": None, "risk_label": "UNKNOWN",
            "warnings": [], "port_distribution": ""}


def _is_cleartext_open(p: Dict) -> bool:
    return p["state"] == "open" and p["service"].lower() in _CLEARTEXT_SERVICES


# Characters that spreadsheet programs (Excel, LibreOffice, Google Sheets) may
# treat as the start of a formula. A hostile service can return a banner that
# begins with one of these, so CSV export prefixes any such cell with a single
# quote to force the spreadsheet to keep it as plain text.
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value):
    """Neutralise CSV formula injection in one exported cell.

    Non-strings (ints, None) are returned unchanged so numbers stay numeric.
    A string whose first character could start a formula is prefixed with a
    single quote; every other value is returned unchanged. A leading space
    already stops a spreadsheet from evaluating a cell, so those are left as-is.
    """
    if isinstance(value, str) and value.startswith(_CSV_FORMULA_PREFIXES):
        return "'" + value
    return value


# ─────────────────────────────────────────────────────────────────────────────
# ReportGenerator
# ─────────────────────────────────────────────────────────────────────────────

class ReportGenerator:
    """
    Generate polished, professional security reports from scan results.

    All public methods accept:
        scan_results  – dict from PortScanner / SocketScanner
        ai_analysis   – raw AI analysis string (optional)
        anomaly_data  – dict or string from AnomalyDetector (optional)
        target        – hostname / IP shown in headers
        profile       – scan profile name shown in headers

    Text-returning : generate_text_report, generate_csv_report,
                     generate_anomaly_csv, generate_json_report,
                     generate_html_report
    Bytes-returning: generate_pdf_report
    File-writing   : generate_docx_report(output_path, ...)
    """

    # ──────────────────────────────────────────────────────────────────────────
    # TXT
    # ──────────────────────────────────────────────────────────────────────────
    @staticmethod
    def generate_text_report(
        scan_results: Dict,
        ai_analysis:  Optional[str] = None,
        anomaly_data                = None,
        target:       str           = "",
        profile:      str           = "",
    ) -> str:
        stats = _collect_stats(scan_results)
        ports = _collect_ports(scan_results)
        anom  = _parse_anomalies(anomaly_data)
        ai    = _parse_ai(ai_analysis)
        now   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        W     = 80
        dline = "=" * W

        def hdr(t: str) -> str:
            pad = W - len(t) - 4
            return f"== {t} {'=' * max(pad, 0)}"

        L = [
            dline,
            "  AI PORT SCANNER - SECURITY ASSESSMENT REPORT".center(W),
            dline, "",
            hdr("SCAN METADATA"),
            f"  Generated : {now}",
            f"  Target    : {target or 'N/A'}",
            f"  Profile   : {profile or 'N/A'}",
            f"  Command   : {scan_results.get('command', 'N/A')}",
            f"  Method    : {stats['method']}",
            f"  Elapsed   : {stats['elapsed']}", "",
            hdr("SCAN STATISTICS"),
            f"  Hosts Discovered  : {stats['hosts_count']}",
            f"  Ports Probed      : {stats['ports_probed']}",
            f"  Ports Expected    : {stats['ports_expected']}",
            f"  Ports Reported    : {stats['ports_reported']}",
            f"  Scan Status       : {'STOPPED EARLY' if stats['stopped'] else 'COMPLETED'}",
            f"  Open              : {stats['open']}",
            f"  Closed            : {stats['closed']}",
            f"  Filtered          : {stats['filtered']}",
        ]

        rs     = anom["risk_score"]
        rlabel = anom["risk_label"]
        if rs is not None:
            L += ["", hdr("OVERALL RISK ASSESSMENT"),
                  f"  Risk Score : {rs}/100  [{rlabel}]"]

        # Key findings callout
        kf = []
        if rs is not None:
            kf.append(f"  *** RISK SCORE: {rs}/100 [{rlabel}] ***")
        for p in ports:
            if _is_cleartext_open(p):
                kf.append(
                    f"  *** CLEARTEXT: port {p['port']}/TCP ({p['service'].upper()}) "
                    f"- data transmitted without encryption ***"
                )
        if kf:
            L += ["", hdr("KEY RISK FINDINGS"), "-" * W] + kf + ["-" * W]

        # Port table
        L += ["", hdr("PORT SCAN RESULTS")]
        col = "{:<10}  {:<10}  {:<12}  {:<25}  {:<12}  {}"
        L.append("  " + col.format("PORT", "STATE", "SERVICE", "PRODUCT", "VERSION", "REASON"))
        L.append("  " + "-" * (W - 2))
        for p in ports:
            L.append("  " + col.format(
                f"{p['port']}/{p['proto'].lower()}",
                p["state"].upper(),
                (p["service"] or "")[:12],
                (p["product"] or "-")[:25],
                (p["version"] or "-")[:12],
                p["reason"],
            ))

        # Anomaly warnings
        if anom["warnings"]:
            L += ["", hdr("ANOMALY DETECTION WARNINGS")]
            for w in anom["warnings"]:
                sev = w["severity"].upper()
                loc = f"{w['host']}:{w['port']}" if w["port"] else w["host"]
                svc = f" ({w['service']})" if w["service"] else ""
                L.append(f"  [{sev}] {loc}{svc}")
                for chunk in textwrap.wrap(w["description"], W - 6):
                    L.append(f"      {chunk}")
        if anom["port_distribution"]:
            L += ["", "  Port Distribution Analysis:", f"  {anom['port_distribution']}"]

        # AI analysis
        if ai["raw"]:
            L += ["", hdr("AI ANALYSIS")]
            for sec, heading in [
                ("attack_surface", "Attack Surface Summary"),
                ("risks",          "Security Risks"),
                ("next_steps",     "Next Steps / Recommendations"),
            ]:
                val = ai[sec]
                items = [val] if isinstance(val, str) and val else val
                if items:
                    L += [f"\n  {heading}:", "  " + "-" * 40]
                    for item in items:
                        for chunk in textwrap.wrap(item, W - 4):
                            L.append(f"    {chunk}")
            if not (ai["attack_surface"] or ai["risks"] or ai["next_steps"]):
                for line in ai["raw"].splitlines():
                    L.append(f"  {line}")

        # Always close the report, even when AI analysis is unavailable.
        L += ["", dline,
          "  Generated by AI Port Scanner  |  For authorized use only".center(W),
          dline]
        return "\n".join(L)

    # ──────────────────────────────────────────────────────────────────────────
    # CSV — ports
    # ──────────────────────────────────────────────────────────────────────────
    @staticmethod
    def generate_csv_report(
        scan_results: Dict,
        ai_analysis:  Optional[str] = None,
        anomaly_data                = None,
        target:       str           = "",
        profile:      str           = "",
    ) -> str:
        ports = _collect_ports(scan_results)
        buf   = io.StringIO()
        w     = csv.writer(buf)

        def wr(row):
            """Write a data row, guarding each cell against CSV formula injection."""
            w.writerow([_csv_safe(c) for c in row])

        w.writerow(["# AI Port Scanner — Port Report"])
        w.writerow([f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"])
        w.writerow([f"# Target: {target}", f"# Profile: {profile}"])
        w.writerow([f"# Command: {scan_results.get('command','N/A')}"])
        w.writerow([])
        w.writerow(["host","port","proto","state","service",
                    "product","version","extrainfo","reason"])
        for p in ports:
            wr([p["host"],p["port"],p["proto"],p["state"],
                p["service"],p["product"],p["version"],
                p["extrainfo"],p["reason"]])

        # Keep CSV useful as a single exported report: include scan statistics,
        # anomaly findings, and AI analysis after the port table. Each section
        # has its own header so spreadsheet programs can still open the file.
        stats = _collect_stats(scan_results)
        anom  = _parse_anomalies(anomaly_data)
        ai    = _parse_ai(ai_analysis)
        w.writerow([])
        w.writerow(["# Scan Statistics"])
        w.writerow(["metric", "value"])
        for label, value in [
            ("hosts_discovered", stats["hosts_count"]),
            ("ports_probed", stats["ports_probed"]),
            ("ports_expected", stats["ports_expected"]),
            ("ports_reported", stats["ports_reported"]),
            ("open", stats["open"]),
            ("closed", stats["closed"]),
            ("filtered", stats["filtered"]),
            ("scan_status", "STOPPED EARLY" if stats["stopped"] else "COMPLETED"),
            ("elapsed", stats["elapsed"]),
            ("method", stats["method"]),
        ]:
            wr([label, value])

        w.writerow([])
        w.writerow(["# Anomaly Analysis"])
        wr(["risk_score", anom["risk_score"]])
        wr(["risk_label", anom["risk_label"]])
        w.writerow([])
        w.writerow(["severity", "host", "port", "service", "description"])
        for warn in anom["warnings"]:
            wr([warn["severity"], warn["host"], warn["port"],
                warn["service"], warn["description"]])
        if anom["port_distribution"]:
            w.writerow([])
            wr(["port_distribution", anom["port_distribution"]])

        w.writerow([])
        w.writerow(["# AI Security Analysis"])
        wr(["attack_surface", ai["attack_surface"]])
        wr(["risks", "\n".join(ai["risks"]) if isinstance(ai["risks"], list) else ai["risks"]])
        wr(["next_steps", "\n".join(ai["next_steps"]) if isinstance(ai["next_steps"], list) else ai["next_steps"]])
        wr(["raw", ai["raw"]])
        return buf.getvalue()

    # ──────────────────────────────────────────────────────────────────────────
    # CSV — anomaly warnings
    # ──────────────────────────────────────────────────────────────────────────
    @staticmethod
    def generate_anomaly_csv(anomaly_data) -> str:
        anom = _parse_anomalies(anomaly_data)
        buf  = io.StringIO()
        w    = csv.writer(buf)

        def wr(row):
            """Write a data row, guarding each cell against CSV formula injection."""
            w.writerow([_csv_safe(c) for c in row])

        w.writerow(["# AI Port Scanner — Anomaly Warnings"])
        w.writerow([f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"])
        if anom["risk_score"] is not None:
            w.writerow([f"# Risk Score: {anom['risk_score']}/100  [{anom['risk_label']}]"])
        w.writerow([])
        w.writerow(["severity","host","port","service","description"])
        for warn in anom["warnings"]:
            wr([warn["severity"],warn["host"],warn["port"],
                warn["service"],warn["description"]])
        return buf.getvalue()

    # ──────────────────────────────────────────────────────────────────────────
    # JSON
    # ──────────────────────────────────────────────────────────────────────────
    @staticmethod
    def generate_json_report(
        scan_results: Dict,
        ai_analysis:  Optional[str] = None,
        anomaly_data                = None,
        target:       str           = "",
        profile:      str           = "",
    ) -> str:
        stats = _collect_stats(scan_results)
        ports = _collect_ports(scan_results)
        anom  = _parse_anomalies(anomaly_data)
        ai    = _parse_ai(ai_analysis)
        report = {
            "metadata": {
                "generated": datetime.now().isoformat(),
                "target": target, "profile": profile,
                "command": scan_results.get("command",""),
                "tool": "AI Port Scanner",
            },
            "statistics": {
                "hosts_discovered":  stats["hosts_count"],
                "ports_probed":      stats["ports_probed"],
                "ports_expected":    stats["ports_expected"],
                "ports_reported":    stats["ports_reported"],
                "stopped":           stats["stopped"],
                "open":              stats["open"],
                "closed":            stats["closed"],
                "filtered":          stats["filtered"],
                "elapsed":           stats["elapsed"],
                "method":            stats["method"],
            },
            "ports": ports,
            "analysis": {
                "attack_surface": ai["attack_surface"],
                "risks":          ai["risks"],
                "next_steps":     ai["next_steps"],
                "raw":            ai["raw"],
            },
            "anomalies": {
                "risk_score":        anom["risk_score"],
                "risk_label":        anom["risk_label"],
                "warnings":          anom["warnings"],
                "port_distribution": anom["port_distribution"],
            },
        }
        return json.dumps(report, indent=2)

    # ──────────────────────────────────────────────────────────────────────────
    # HTML
    # ──────────────────────────────────────────────────────────────────────────
    @staticmethod
    def generate_html_report(
        scan_results: Dict,
        ai_analysis:  Optional[str] = None,
        anomaly_data                = None,
        target:       str           = "",
        profile:      str           = "",
    ) -> str:
        stats  = _collect_stats(scan_results)
        ports  = _collect_ports(scan_results)
        anom   = _parse_anomalies(anomaly_data)
        ai     = _parse_ai(ai_analysis)
        now    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        rs     = anom["risk_score"]
        rlabel = anom["risk_label"]
        rcss   = {"CRITICAL":"#991B1B","HIGH":"#DC2626","MEDIUM":"#D97706",
                  "LOW":"#16A34A"}.get(rlabel, "#6B7280")

        def esc(s): return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

        # port rows
        port_rows_html = ""
        for p in ports:
            s    = p["state"]
            cls  = {"open":"open","closed":"closed"}.get(s,"filtered")
            hi   = ' class="row-hl"' if _is_cleartext_open(p) else ""
            port_rows_html += (
                f'<tr data-state="{s}"{hi}>'
                f'<td><strong>{p["port"]}/{p["proto"].lower()}</strong></td>'
                f'<td><span class="dot dot-{cls}"></span>'
                f'<span class="badge badge-{cls}">{s.upper()}</span></td>'
                f'<td>{esc(p["service"])}</td>'
                f'<td>{esc(p["product"] or "—")}</td>'
                f'<td>{esc(p["version"] or "—")}</td>'
                f'<td>{esc(p["reason"])}</td>'
                f'</tr>\n'
            )

        # warning cards
        warn_html = ""
        for w in anom["warnings"]:
            sev  = w["severity"].upper()
            sc   = _sev_hex(sev)
            loc  = f'{esc(w["host"])}:{esc(str(w["port"]))}' if w["port"] else esc(w["host"])
            svc  = f'&nbsp;<em>{esc(w["service"])}</em>' if w["service"] else ""
            warn_html += (
                f'<div class="warn-card">'
                f'<span class="sev-badge" style="background:{sc}">{sev}</span>'
                f'<span class="warn-loc">{loc}{svc}</span>'
                f'<p class="warn-desc">{esc(w["description"])}</p>'
                f'</div>\n'
            )
        if not warn_html:
            warn_html = "<p>No anomaly warnings detected.</p>"

        # key findings
        kf_items = []
        if rs is not None:
            kf_items.append(
                f'Risk score: <strong style="color:{rcss}">{rs}/100 [{rlabel}]</strong>'
            )
        for p in ports:
            if _is_cleartext_open(p):
                kf_items.append(
                    f'Port <strong>{p["port"]}/TCP ({p["service"].upper()})</strong> open — '
                    f'cleartext protocol, no encryption.'
                )
        kf_html = ""
        if kf_items:
            li = "".join(f"<li>{i}</li>" for i in kf_items)
            kf_html = (
                f'<div class="key-findings">'
                f'<h3>&#9888;&#xFE0F; Key Risk Findings</h3>'
                f'<ul>{li}</ul></div>'
            )

        # risk KPI card
        risk_kpi = ""
        if rs is not None:
            risk_kpi = (
                f'<div class="kpi">'
                f'<div class="kpi-num" style="color:{rcss}">{rs}/100</div>'
                f'<div class="kpi-label">Risk Score ({rlabel})</div>'
                f'</div>'
            )

        # ai section
        ai_section = ""
        if ai["raw"]:
            ai_section = (
                f'<div class="section">'
                f'<div class="section-title">AI Security Analysis</div>'
                f'<pre class="ai-raw">{esc(ai["raw"])}</pre>'
                f'</div>'
            )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Port Scanner Report — {esc(target)}</title>
<style>
:root{{--brand:#4A6CF7;--brand-dk:#2D3A8C;--open:#16A34A;--closed:#DC2626;
      --filtered:#D97706;--bg:#F9FAFB;--card:#fff;--border:#E5E7EB;
      --text:#111827;--muted:#6B7280}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);
      color:var(--text);font-size:14px}}
.page-header{{background:linear-gradient(135deg,var(--brand),var(--brand-dk));
              color:#fff;padding:36px 48px}}
.page-header h1{{font-size:1.85rem}}
.page-header .sub{{opacity:.85;margin-top:6px;font-size:.92rem}}
.meta-strip{{background:#fff;border-bottom:1px solid var(--border);
             padding:14px 48px;display:flex;flex-wrap:wrap;gap:22px;font-size:.82rem}}
.meta-strip strong{{color:var(--brand)}}
.dashboard{{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));
            gap:14px;padding:24px 48px}}
.kpi{{background:var(--card);border:1px solid var(--border);border-radius:10px;
      padding:18px;text-align:center;box-shadow:0 1px 4px rgba(0,0,0,.06)}}
.kpi-num{{font-size:2rem;font-weight:700;line-height:1}}
.kpi-label{{margin-top:5px;font-size:.72rem;color:var(--muted);
            text-transform:uppercase;letter-spacing:.5px}}
.section{{padding:24px 48px}}
.section-title{{font-size:1.1rem;font-weight:700;color:var(--brand);
                border-bottom:2px solid var(--brand);padding-bottom:7px;margin-bottom:16px}}
.key-findings{{background:#FFF7ED;border:1px solid #FED7AA;border-radius:8px;
               padding:16px 20px;margin-bottom:20px}}
.key-findings h3{{color:#92400E;margin-bottom:8px;font-size:.88rem;
                  text-transform:uppercase;letter-spacing:.5px}}
.key-findings ul{{padding-left:18px}}
.key-findings li{{color:#92400E;margin-bottom:4px;font-size:.86rem}}
.table-controls{{display:flex;gap:10px;margin-bottom:12px;flex-wrap:wrap;align-items:center}}
.search-input{{flex:1;min-width:180px;padding:7px 11px;border:1px solid var(--border);
               border-radius:6px;font-size:.83rem}}
.filter-btn{{padding:5px 13px;border:1px solid var(--border);border-radius:6px;
             background:#fff;font-size:.8rem;cursor:pointer;transition:.15s}}
.filter-btn.active,.filter-btn:hover{{background:var(--brand);color:#fff;
                                       border-color:var(--brand)}}
table{{width:100%;border-collapse:collapse;font-size:.83rem}}
thead th{{background:#F3F4F6;padding:9px 11px;text-align:left;font-weight:600;
           color:#374151;border-bottom:2px solid var(--border);
           white-space:nowrap;cursor:pointer;user-select:none}}
thead th:hover{{background:#E5E7EB}}
thead th::after{{content:' ↕';font-size:.68rem;color:var(--muted)}}
tbody td{{padding:8px 11px;border-bottom:1px solid var(--border)}}
tbody tr:hover{{background:#F9FAFB}}
tr.row-hl td:first-child{{border-left:3px solid #F59E0B}}
.badge{{display:inline-block;padding:2px 8px;border-radius:11px;
        font-size:.73rem;font-weight:600}}
.badge-open{{background:#DCFCE7;color:#15803D}}
.badge-closed{{background:#FEE2E2;color:#B91C1C}}
.badge-filtered{{background:#FEF3C7;color:#92400E}}
.dot{{display:inline-block;width:7px;height:7px;border-radius:50%;
      margin-right:5px;vertical-align:middle}}
.dot-open{{background:var(--open)}}.dot-closed{{background:var(--closed)}}
.dot-filtered{{background:var(--filtered)}}
.sev-badge{{display:inline-block;padding:2px 8px;border-radius:11px;
            font-size:.71rem;font-weight:700;color:#fff;margin-right:7px}}
.warn-card{{background:#fff;border:1px solid var(--border);border-radius:8px;
            padding:12px 16px;margin-bottom:9px;display:flex;
            flex-wrap:wrap;align-items:flex-start;gap:6px}}
.warn-loc{{font-weight:600;font-size:.86rem}}
.warn-desc{{width:100%;color:#374151;font-size:.83rem;margin-top:5px;line-height:1.5}}
.ai-raw{{background:#F3F4F6;border:1px solid var(--border);border-radius:6px;
         padding:14px;font-size:.8rem;white-space:pre-wrap;line-height:1.6;
         max-height:400px;overflow:auto}}
footer{{background:#1F2937;color:#9CA3AF;text-align:center;
        padding:16px;font-size:.78rem}}
</style>
</head>
<body>
<div class="page-header">
  <h1>&#x1F50D; Port Scanner Security Report</h1>
  <p class="sub">Professional Network Security Assessment &mdash; {now}</p>
</div>
<div class="meta-strip">
  <span><strong>Target:</strong> {esc(target) or 'N/A'}</span>
  <span><strong>Profile:</strong> {esc(profile) or 'N/A'}</span>
  <span><strong>Elapsed:</strong> {esc(stats['elapsed'])}</span>
  <span style="font-family:monospace"><strong>Command:</strong> {esc(scan_results.get('command','N/A'))}</span>
</div>
<div class="dashboard">
  <div class="kpi"><div class="kpi-num">{stats['hosts_count']}</div><div class="kpi-label">Hosts</div></div>
  <div class="kpi"><div class="kpi-num">{stats['ports_probed']}</div><div class="kpi-label">Ports Probed</div></div>
  <div class="kpi"><div class="kpi-num" style="color:var(--open)">{stats['open']}</div><div class="kpi-label">Open</div></div>
  <div class="kpi"><div class="kpi-num" style="color:var(--closed)">{stats['closed']}</div><div class="kpi-label">Closed</div></div>
  <div class="kpi"><div class="kpi-num" style="color:var(--filtered)">{stats['filtered']}</div><div class="kpi-label">Filtered</div></div>
  {risk_kpi}
</div>
<div class="section">
  {kf_html}
</div>
<div class="section">
  <div class="section-title">Port Scan Results</div>
  <div class="table-controls">
    <input class="search-input" id="si" placeholder="Search ports, services, products…" oninput="ft()">
    <button class="filter-btn active" onclick="sf('all',this)">All</button>
    <button class="filter-btn" onclick="sf('open',this)">Open</button>
    <button class="filter-btn" onclick="sf('closed',this)">Closed</button>
    <button class="filter-btn" onclick="sf('filtered',this)">Filtered</button>
  </div>
  <table id="pt">
    <thead><tr>
      <th onclick="st(0)">Port</th><th onclick="st(1)">State</th>
      <th onclick="st(2)">Service</th><th onclick="st(3)">Product</th>
      <th onclick="st(4)">Version</th><th onclick="st(5)">Reason</th>
    </tr></thead>
    <tbody id="pb">{port_rows_html}</tbody>
  </table>
</div>
<div class="section">
  <div class="section-title">Anomaly Detection Warnings</div>
  {warn_html}
</div>
{ai_section}
<footer>Generated by AI Port Scanner &nbsp;|&nbsp; For authorized use only &nbsp;|&nbsp; {now}</footer>
<script>
let _f='all';
function sf(f,b){{_f=f;document.querySelectorAll('.filter-btn').forEach(x=>x.classList.remove('active'));b.classList.add('active');ft();}}
function ft(){{const q=document.getElementById('si').value.toLowerCase();document.querySelectorAll('#pb tr').forEach(r=>{{const ok=(_f==='all'||r.dataset.state===_f)&&(!q||r.textContent.toLowerCase().includes(q));r.style.display=ok?'':'none';}});}}
function st(c){{const tb=document.getElementById('pb');const rows=[...tb.querySelectorAll('tr')];const dir=tb.dataset['s'+c]==='a'?-1:1;tb.dataset['s'+c]=dir===1?'a':'d';rows.sort((a,b)=>{{const av=a.cells[c]?.textContent.trim()||'',bv=b.cells[c]?.textContent.trim()||'';const an=parseFloat(av),bn=parseFloat(bv);return(!isNaN(an)&&!isNaN(bn))?(an-bn)*dir:av.localeCompare(bv)*dir;}});rows.forEach(r=>tb.appendChild(r));}}
</script>
</body></html>"""

    # ──────────────────────────────────────────────────────────────────────────
    # PDF
    # ──────────────────────────────────────────────────────────────────────────
    @staticmethod
    def generate_pdf_report(
        scan_results: Dict,
        ai_analysis:  Optional[str] = None,
        anomaly_data                = None,
        target:       str           = "",
        profile:      str           = "",
    ) -> bytes:
        """Return PDF bytes — write to file or serve directly."""
        buf   = io.BytesIO()
        stats = _collect_stats(scan_results)
        ports = _collect_ports(scan_results)
        anom  = _parse_anomalies(anomaly_data)
        ai    = _parse_ai(ai_analysis)
        now   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        W     = A4[0] - 4*cm

        doc = SimpleDocTemplate(
            buf, pagesize=A4,
            leftMargin=2*cm, rightMargin=2*cm,
            topMargin=2*cm,  bottomMargin=2*cm,
            title=f"Port Scanner Report — {target}",
            author="AI Port Scanner",
        )

        def ps(name, **kw):
            return ParagraphStyle(name, **kw)

        def pescape(value):
            """Escape user/scan text before feeding it to ReportLab Paragraph."""
            return html.escape(str(value if value is not None else ""), quote=False)

        s_h1   = ps("H1",  fontSize=20, textColor=_C_BRAND_DARK, spaceAfter=6,
                            fontName="Helvetica-Bold", leading=24)
        s_h2   = ps("H2",  fontSize=13, textColor=_C_BRAND, spaceAfter=4,
                            fontName="Helvetica-Bold", leading=16, spaceBefore=14)
        s_h3   = ps("H3",  fontSize=10, textColor=_C_BRAND, spaceAfter=3,
                            fontName="Helvetica-Bold", leading=13, spaceBefore=8)
        s_body = ps("Body",fontSize=8.5, textColor=_C_TEXT,
                            fontName="Helvetica", leading=12, spaceAfter=3)
        s_c    = ps("C",   fontSize=8.5, fontName="Helvetica",
                            leading=12, alignment=TA_CENTER)

        story = []

        # Title
        story.append(Paragraph("PORT SCANNER SECURITY REPORT", s_h1))
        story.append(HRFlowable(width=W, thickness=3, color=_C_BRAND, spaceAfter=8))

        # Meta table
        meta_rows = [
            ["Generated", now], ["Target", target or "N/A"],
            ["Profile",   profile or "N/A"], ["Method", stats["method"]],
            ["Elapsed",   stats["elapsed"]],
        ]
        mt = Table(meta_rows, colWidths=[3*cm, W-3*cm])
        mt.setStyle(TableStyle([
            ("FONTNAME",  (0,0),(-1,-1), "Helvetica"),
            ("FONTNAME",  (0,0),(0,-1),  "Helvetica-Bold"),
            ("FONTSIZE",  (0,0),(-1,-1), 8.5),
            ("TEXTCOLOR", (0,0),(0,-1),  _C_BRAND),
            ("TEXTCOLOR", (1,0),(1,-1),  _C_TEXT),
            ("ROWBACKGROUNDS",(0,0),(-1,-1), [colors.white, _C_LIGHT_GREY]),
            ("TOPPADDING",   (0,0),(-1,-1), 4),
            ("BOTTOMPADDING",(0,0),(-1,-1), 4),
        ]))
        story.append(mt)
        story.append(Spacer(1, 12))

        # KPI row
        story.append(Paragraph("Scan Statistics", s_h2))
        rs     = anom["risk_score"]
        rlabel = anom["risk_label"]
        rc     = _rl_color(rs)

        def kpi(label, val, col=_C_BRAND):
            return Paragraph(
                f'<font color="{col.hexval()}" size="17"><b>{val}</b></font>'
                f'<br/><font size="7" color="grey">{label}</font>', s_c)

        kpi_row = [
            kpi("Hosts",           stats["hosts_count"]),
            kpi("Ports Probed",    stats["ports_probed"]),
            kpi("Open",            stats["open"],     _C_OPEN),
            kpi("Closed",          stats["closed"],   _C_CLOSED),
            kpi("Filtered",        stats["filtered"], _C_FILTERED),
            kpi(f"Risk ({rlabel})",
                f"{rs}/100" if rs is not None else "N/A", rc),
        ]
        kt = Table([kpi_row], colWidths=[W/6]*6, rowHeights=[1.35*cm])
        kt.setStyle(TableStyle([
            ("BOX",      (0,0),(-1,-1), 0.5, _C_MID_GREY),
            ("INNERGRID",(0,0),(-1,-1), 0.5, _C_MID_GREY),
            ("BACKGROUND",(0,0),(-1,-1), _C_LIGHT_GREY),
            ("VALIGN",   (0,0),(-1,-1), "MIDDLE"),
            ("ALIGN",    (0,0),(-1,-1), "CENTRE"),
        ]))
        story.append(kt)
        story.append(Spacer(1, 10))

        # Key findings
        kf = []
        if rs is not None:
            kf.append(
                f'Risk score: <b><font color="{rc.hexval()}">'
                f'{rs}/100 [{rlabel}]</font></b>'
            )
        for p in ports:
            if _is_cleartext_open(p):
                kf.append(
                    f'Port <b>{p["port"]}/TCP ({pescape(p["service"].upper())})</b> — '
                    f'cleartext protocol, no encryption.'
                )
        if kf:
            story.append(Paragraph("Key Risk Findings", s_h2))
            fd = [[Paragraph(f"&#x26A0; {item}", s_body)] for item in kf]
            ft_ = Table(fd, colWidths=[W])
            ft_.setStyle(TableStyle([
                ("BACKGROUND",   (0,0),(-1,-1), colors.HexColor("#FFF7ED")),
                ("BOX",          (0,0),(-1,-1), 1.0, colors.HexColor("#FED7AA")),
                ("LEFTPADDING",  (0,0),(-1,-1), 10),
                ("TOPPADDING",   (0,0),(-1,-1), 5),
                ("BOTTOMPADDING",(0,0),(-1,-1), 5),
            ]))
            story.append(ft_)
            story.append(Spacer(1, 8))

        # Port table
        story.append(Paragraph("Port Scan Results", s_h2))
        col_w = [1.6*cm, 2.1*cm, 2.3*cm, 4.6*cm, 2.5*cm, 3.0*cm]

        def th(t):
            return Paragraph(t, ps("TH", fontSize=8, fontName="Helvetica-Bold",
                                   textColor=colors.white, alignment=TA_CENTER))
        def sp(state):
            c = {"open":_C_OPEN,"closed":_C_CLOSED}.get(state, _C_FILTERED)
            return Paragraph(
                f'<b><font color="{c.hexval()}">{state.upper()}</font></b>',
                ps(f"SP{state}", fontSize=7.5, fontName="Helvetica-Bold",
                   alignment=TA_CENTER))

        tbl_data  = [[th("Port"),th("State"),th("Service"),
                      th("Product"),th("Version"),th("Reason")]]
        tbl_style = [
            ("BACKGROUND",    (0,0),(-1,0),   _C_BRAND),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),  [colors.white, _C_LIGHT_GREY]),
            ("FONTSIZE",      (0,1),(-1,-1),  7.5),
            ("FONTNAME",      (0,1),(-1,-1),  "Helvetica"),
            ("TOPPADDING",    (0,0),(-1,-1),  4),
            ("BOTTOMPADDING", (0,0),(-1,-1),  4),
            ("GRID",          (0,0),(-1,-1),  0.4, _C_MID_GREY),
        ]
        hl_rows = []
        for i, p in enumerate(ports, 1):
            tbl_data.append([
                Paragraph(pescape(f'{p["port"]}/{p["proto"].lower()}'),
                          ps("PP", fontSize=7.5, fontName="Helvetica-Bold")),
                sp(p["state"]),
                Paragraph(pescape((p["service"] or "")[:22]), s_body),
                Paragraph(pescape((p["product"] or "—")[:36]), s_body),
                Paragraph(pescape((p["version"] or "—")[:20]), s_body),
                Paragraph(pescape((p["reason"]  or "")[:22]), s_body),
            ])
            if _is_cleartext_open(p):
                hl_rows.append(i)
        for r in hl_rows:
            tbl_style.append(("BACKGROUND",(0,r),(-1,r), colors.HexColor("#FFF7ED")))

        ptbl = Table(tbl_data, colWidths=col_w, repeatRows=1)
        ptbl.setStyle(TableStyle(tbl_style))
        story.append(ptbl)
        story.append(Spacer(1, 10))

        # Anomaly warnings
        if anom["warnings"]:
            story.append(Paragraph("Anomaly Detection Warnings", s_h2))
            wd = [[th("Severity"), th("Location"), th("Description")]]
            ws = [
                ("BACKGROUND",    (0,0),(-1,0),  _C_BRAND),
                ("ROWBACKGROUNDS",(0,1),(-1,-1), [colors.white, _C_LIGHT_GREY]),
                ("FONTSIZE",      (0,1),(-1,-1), 7.5),
                ("FONTNAME",      (0,1),(-1,-1), "Helvetica"),
                ("TOPPADDING",    (0,0),(-1,-1), 4),
                ("BOTTOMPADDING", (0,0),(-1,-1), 4),
                ("GRID",          (0,0),(-1,-1), 0.4, _C_MID_GREY),
                ("VALIGN",        (0,0),(-1,-1), "TOP"),
            ]
            SC = {"CRITICAL":_C_CRITICAL,"HIGH":_C_HIGH,
                  "MEDIUM":_C_MEDIUM,"LOW":_C_LOW,"INFO":_C_INFO}
            for w in anom["warnings"]:
                sev = w["severity"].upper()
                sc  = SC.get(sev, colors.grey)
                loc = f'{w["host"]}:{w["port"]}' if w["port"] else w["host"]
                wd.append([
                    Paragraph(f'<font color="{sc.hexval()}"><b>{sev}</b></font>',
                              ps("WS", fontSize=7.5, fontName="Helvetica-Bold")),
                    Paragraph(pescape(loc + (f'\n({w["service"]})' if w["service"] else "")),
                              ps("WL", fontSize=7.5, fontName="Helvetica")),
                    Paragraph(pescape(w["description"]),
                              ps("WD", fontSize=7.5, fontName="Helvetica")),
                ])
            wtbl = Table(wd, colWidths=[2.2*cm, 3.4*cm, W-5.6*cm], repeatRows=1)
            wtbl.setStyle(TableStyle(ws))
            story.append(wtbl)
            story.append(Spacer(1, 10))

        # AI analysis
        if ai["raw"]:
            story.append(PageBreak())
            story.append(Paragraph("AI Security Analysis", s_h2))
            story.append(HRFlowable(width=W, thickness=1, color=_C_BRAND, spaceAfter=6))
            for sec_key, heading in [
                ("attack_surface","Attack Surface Summary"),
                ("risks",         "Security Risks"),
                ("next_steps",    "Next Steps / Recommendations"),
            ]:
                val   = ai[sec_key]
                items = [val] if isinstance(val, str) and val else val
                if items:
                    story.append(Paragraph(heading, s_h3))
                    for item in items:
                        story.append(Paragraph(pescape(f"• {item}"), s_body))
            if not (ai["attack_surface"] or ai["risks"] or ai["next_steps"]):
                for line in ai["raw"].splitlines():
                    story.append(Paragraph(pescape(line or " "), s_body))

        def _footer(canvas, doc_):
            canvas.saveState()
            canvas.setFont("Helvetica", 7)
            canvas.setFillColor(colors.grey)
            canvas.drawString(2*cm, 1.2*cm,
                              f"AI Port Scanner Report — {target} — {now}")
            canvas.drawRightString(A4[0]-2*cm, 1.2*cm, f"Page {doc_.page}")
            canvas.restoreState()

        doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
        return buf.getvalue()

    # ──────────────────────────────────────────────────────────────────────────
    # DOCX
    # ──────────────────────────────────────────────────────────────────────────
    @staticmethod
    def generate_docx_report(
        output_path:  str,
        scan_results: Dict,
        ai_analysis:  Optional[str] = None,
        anomaly_data                = None,
        target:       str           = "",
        profile:      str           = "",
    ) -> None:
        """Write a .docx file to output_path."""
        stats  = _collect_stats(scan_results)
        ports  = _collect_ports(scan_results)
        anom   = _parse_anomalies(anomaly_data)
        ai     = _parse_ai(ai_analysis)
        now    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        rs     = anom["risk_score"]
        rlabel = anom["risk_label"]

        doc = Document()
        for sec in doc.sections:
            sec.top_margin    = Inches(1.0)
            sec.bottom_margin = Inches(1.0)
            sec.left_margin   = Inches(1.15)
            sec.right_margin  = Inches(1.15)

        def _cell_bg(cell, hex_str: str):
            tc   = cell._tc
            tcPr = tc.get_or_add_tcPr()
            shd  = OxmlElement("w:shd")
            shd.set(qn("w:val"),   "clear")
            shd.set(qn("w:color"), "auto")
            shd.set(qn("w:fill"),  hex_str.lstrip("#"))
            tcPr.append(shd)

        def _run_color(run, hex_str: str):
            run.font.color.rgb = RGBColor.from_string(hex_str.lstrip("#"))

        # Cover title
        tp = doc.add_paragraph()
        tp.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r  = tp.add_run("Port Scanner Security Report")
        r.bold = True; r.font.size = Pt(24)
        _run_color(r, "4A6CF7")

        sp2 = doc.add_paragraph()
        sp2.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r2  = sp2.add_run("Professional Network Security Assessment")
        r2.font.size = Pt(11)
        _run_color(r2, "6B7280")
        doc.add_paragraph()

        # Executive summary
        doc.add_heading("Executive Summary", level=1)
        et = doc.add_table(rows=1, cols=2)
        et.style = "Table Grid"
        hc = et.rows[0].cells
        hc[0].text = "Field"; hc[1].text = "Value"
        for c in hc:
            _cell_bg(c, "4A6CF7")
            for p in c.paragraphs:
                if p.runs: p.runs[0].bold = True; _run_color(p.runs[0], "FFFFFF")

        RISK_COLORS = {"CRITICAL":"991B1B","HIGH":"DC2626",
                       "MEDIUM":"D97706","LOW":"16A34A"}
        summary = [
            ("Generated",      now),
            ("Target",         target or "N/A"),
            ("Profile",        profile or "N/A"),
            ("Method",         stats["method"]),
            ("Elapsed",        stats["elapsed"]),
            ("Hosts Found",    str(stats["hosts_count"])),
            ("Ports Probed",   str(stats["ports_probed"])),
            ("Open Ports",     str(stats["open"])),
            ("Closed Ports",   str(stats["closed"])),
            ("Filtered Ports", str(stats["filtered"])),
        ]
        if rs is not None:
            summary.append(("Risk Score", f"{rs}/100  [{rlabel}]"))

        for lbl, val in summary:
            rc_ = et.add_row().cells
            rc_[0].text = lbl; rc_[1].text = val
            if rc_[1].paragraphs and rc_[1].paragraphs[0].runs:
                run_ = rc_[1].paragraphs[0].runs[0]
                if lbl == "Open Ports":     _run_color(run_, "16A34A")
                elif lbl == "Risk Score":   _run_color(run_, RISK_COLORS.get(rlabel,"374151"))

        # Key findings
        kf = []
        if rs is not None:
            kf.append(f"Overall risk score: {rs}/100 [{rlabel}]")
        for p in ports:
            if _is_cleartext_open(p):
                kf.append(
                    f"Port {p['port']}/TCP ({p['service'].upper()}) is open — "
                    f"cleartext protocol, data transmitted without encryption."
                )
        if kf:
            doc.add_paragraph()
            doc.add_heading("Key Risk Findings", level=2)
            for item in kf:
                bp  = doc.add_paragraph(style="List Bullet")
                run_ = bp.add_run(item)
                run_.font.size = Pt(10)
                if "risk score" in item.lower():
                    _run_color(run_, RISK_COLORS.get(rlabel, "374151"))
                    run_.bold = True
                else:
                    _run_color(run_, "92400E")

        # Port table
        doc.add_page_break()
        doc.add_heading("Port Scan Results", level=1)
        pt = doc.add_table(rows=1, cols=6)
        pt.style = "Table Grid"
        ph = pt.rows[0].cells
        for ci, cn in enumerate(["Port","State","Service","Product","Version","Reason"]):
            ph[ci].text = cn
            _cell_bg(ph[ci], "4A6CF7")
            for p_ in ph[ci].paragraphs:
                if p_.runs: p_.runs[0].bold = True; _run_color(p_.runs[0], "FFFFFF")

        STATE_CLR = {"open":"16A34A","closed":"DC2626","filtered":"D97706"}
        for p in ports:
            rc_ = pt.add_row().cells
            rc_[0].text = f"{p['port']}/{p['proto'].lower()}"
            rc_[1].text = p["state"].upper()
            rc_[2].text = p["service"]
            rc_[3].text = p["product"] or "—"
            rc_[4].text = p["version"] or "—"
            rc_[5].text = p["reason"]
            if rc_[1].paragraphs and rc_[1].paragraphs[0].runs:
                r_ = rc_[1].paragraphs[0].runs[0]
                r_.bold = True
                _run_color(r_, STATE_CLR.get(p["state"], "374151"))
            if _is_cleartext_open(p):
                for ci in range(6):
                    _cell_bg(rc_[ci], "FFF7ED")

        # Anomaly warnings
        if anom["warnings"]:
            doc.add_page_break()
            doc.add_heading("Anomaly Detection Warnings", level=1)
            if rs is not None:
                rp  = doc.add_paragraph()
                rr  = rp.add_run(f"Risk Score: {rs}/100  [{rlabel}]")
                rr.bold = True; rr.font.size = Pt(11)
                _run_color(rr, RISK_COLORS.get(rlabel, "374151"))

            wt = doc.add_table(rows=1, cols=4)
            wt.style = "Table Grid"
            wh = wt.rows[0].cells
            for ci, cn in enumerate(["Severity","Host:Port","Service","Description"]):
                wh[ci].text = cn
                _cell_bg(wh[ci], "4A6CF7")
                for p_ in wh[ci].paragraphs:
                    if p_.runs: p_.runs[0].bold = True; _run_color(p_.runs[0], "FFFFFF")

            SEV_CLR = {"CRITICAL":"991B1B","HIGH":"DC2626","MEDIUM":"D97706",
                       "LOW":"16A34A","INFO":"2563EB"}
            for w in anom["warnings"]:
                wr  = wt.add_row().cells
                sev = w["severity"].upper()
                loc = f'{w["host"]}:{w["port"]}' if w["port"] else w["host"]
                wr[0].text = sev; wr[1].text = loc
                wr[2].text = w["service"]; wr[3].text = w["description"]
                if wr[0].paragraphs and wr[0].paragraphs[0].runs:
                    r_ = wr[0].paragraphs[0].runs[0]
                    r_.bold = True
                    _run_color(r_, SEV_CLR.get(sev, "374151"))

        # AI analysis
        if ai["raw"]:
            doc.add_page_break()
            doc.add_heading("AI Security Analysis", level=1)
            for sec_key, heading in [
                ("attack_surface","Attack Surface Summary"),
                ("risks",         "Security Risks"),
                ("next_steps",    "Next Steps / Recommendations"),
            ]:
                val   = ai[sec_key]
                items = [val] if isinstance(val, str) and val else val
                if items:
                    doc.add_heading(heading, level=2)
                    for item in items:
                        bp = doc.add_paragraph(style="List Bullet")
                        bp.add_run(item).font.size = Pt(10)
            if not (ai["attack_surface"] or ai["risks"] or ai["next_steps"]):
                # FIX: previously this set `.style.font.size`, which mutates the
                # shared "Normal" paragraph style object (every paragraph using
                # that style, document-wide) instead of sizing just this run.
                # Setting the size on the run itself (as done everywhere else
                # in this method) keeps the change local to each line.
                for line in ai["raw"].splitlines():
                    p_line = doc.add_paragraph(line)
                    if p_line.runs:
                        p_line.runs[0].font.size = Pt(9)

        # Footer
        doc.add_paragraph()
        fp = doc.add_paragraph()
        fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
        fr = fp.add_run(
            f"Generated by AI Port Scanner  |  For authorized use only  |  {now}"
        )
        fr.font.size = Pt(8)
        _run_color(fr, "9CA3AF")

        doc.save(output_path)


################################################################################
# SECTION: logo  (from logo.py)
################################################################################

"""
Cypher-themed logo for AI Port Scanner.
Inspired by Valorant's Cypher agent — surveillance, mystery, encrypted data.
"""



class LogoGenerator:
    """Generate Valorant Cypher-inspired logo."""

    # Cypher colour palette
    CYPHER_GOLD   = QColor(0xFF, 0xC4, 0x00)   # #FFC400 — Valorant yellow
    CYPHER_DARK   = QColor(0x0D, 0x0D, 0x0D)   # near-black hood shadow
    CYPHER_GREY   = QColor(0x2A, 0x2A, 0x2A)   # cloak mid-tone
    CYPHER_LIGHT  = QColor(0xAA, 0x90, 0x50)   # warm dim gold
    CYPHER_GLOW   = QColor(0xFF, 0xC4, 0x00, 120)
    CYPHER_BG1    = QColor(0x0A, 0x0C, 0x10)   # deep dark background
    CYPHER_BG2    = QColor(0x16, 0x14, 0x0A)   # slight warm tint
    CYPHER_EYE    = QColor(0xFF, 0xE0, 0x60)   # glowing eye

    @staticmethod
    def create_logo(size: int = 256) -> QPixmap:
        """
        Create the Cypher-themed logo pixmap.

        Args:
            size: Width and height in pixels.

        Returns:
            QPixmap containing the logo.
        """
        pixmap = QPixmap(size, size)
        pixmap.fill(Qt.GlobalColor.transparent)

        p = QPainter(pixmap)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        cx, cy = size / 2, size / 2
        r = size / 2

        # ── 1. Circular background ────────────────────────────────────────────
        bg = QRadialGradient(cx, cy * 0.9, r)
        bg.setColorAt(0.0, QColor(0x20, 0x1A, 0x08))
        bg.setColorAt(0.6, QColor(0x10, 0x0E, 0x04))
        bg.setColorAt(1.0, QColor(0x04, 0x04, 0x04))
        p.setBrush(bg)
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(QRectF(0, 0, size, size))

        # ── 2. Outer gold ring ────────────────────────────────────────────────
        pen_w = max(2, size // 50)
        p.setPen(QPen(LogoGenerator.CYPHER_GOLD, pen_w))
        p.setBrush(Qt.BrushStyle.NoBrush)
        margin = pen_w
        p.drawEllipse(QRectF(margin, margin, size - margin * 2, size - margin * 2))

        # ── 3. Cipher / surveillance wheel ───────────────────────────────────
        #    Concentric dashed arcs + tick marks = Cypher's camera wheel motif
        wheel_r  = r * 0.82
        spoke_r  = r * 0.68
        tick_len = r * 0.06

        # Dashed arc
        p.setPen(QPen(LogoGenerator.CYPHER_GOLD, max(1, size // 80),
                      Qt.PenStyle.DashLine))
        p.drawEllipse(QRectF(cx - wheel_r, cy - wheel_r,
                             wheel_r * 2, wheel_r * 2))

        # Tick marks every 30°
        p.setPen(QPen(LogoGenerator.CYPHER_GOLD, max(1, size // 70)))
        for deg in range(0, 360, 30):
            rad = math.radians(deg)
            x1 = cx + spoke_r * math.cos(rad)
            y1 = cy + spoke_r * math.sin(rad)
            x2 = cx + (spoke_r + tick_len) * math.cos(rad)
            y2 = cy + (spoke_r + tick_len) * math.sin(rad)
            p.drawLine(QPointF(x1, y1), QPointF(x2, y2))

        # Inner thin ring
        inner_r = r * 0.52
        p.setPen(QPen(LogoGenerator.CYPHER_LIGHT, max(1, size // 100)))
        p.drawEllipse(QRectF(cx - inner_r, cy - inner_r,
                             inner_r * 2, inner_r * 2))

        # ── 4. Hooded silhouette ──────────────────────────────────────────────
        #    Head circle + flowing cloak shape built from bezier curves
        head_r   = r * 0.22
        head_cy  = cy * 0.72          # slightly above centre
        cloak_w  = r * 0.78
        cloak_h  = r * 0.70

        # Hood / head dark sphere with subtle gradient
        hood_grad = QRadialGradient(cx - head_r * 0.15, head_cy - head_r * 0.2,
                                    head_r * 1.1)
        hood_grad.setColorAt(0.0, QColor(0x44, 0x3A, 0x1A))
        hood_grad.setColorAt(0.5, QColor(0x1E, 0x18, 0x08))
        hood_grad.setColorAt(1.0, QColor(0x06, 0x05, 0x02))
        p.setBrush(hood_grad)
        p.setPen(QPen(LogoGenerator.CYPHER_GOLD, max(1, size // 90)))
        p.drawEllipse(QRectF(cx - head_r, head_cy - head_r,
                             head_r * 2, head_r * 2))

        # Glowing eye slit (narrow horizontal ellipse)
        eye_w  = head_r * 0.80
        eye_h  = head_r * 0.18
        eye_cy = head_cy + head_r * 0.08
        eye_grad = QLinearGradient(cx - eye_w, eye_cy, cx + eye_w, eye_cy)
        eye_grad.setColorAt(0.0,  QColor(0xFF, 0xC4, 0x00, 0))
        eye_grad.setColorAt(0.35, LogoGenerator.CYPHER_EYE)
        eye_grad.setColorAt(0.5,  QColor(0xFF, 0xFF, 0xCC))
        eye_grad.setColorAt(0.65, LogoGenerator.CYPHER_EYE)
        eye_grad.setColorAt(1.0,  QColor(0xFF, 0xC4, 0x00, 0))
        p.setBrush(eye_grad)
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(QRectF(cx - eye_w, eye_cy - eye_h,
                             eye_w * 2, eye_h * 2))

        # Eye glow halo
        halo = QRadialGradient(cx, eye_cy, eye_w * 1.2)
        halo.setColorAt(0.0, QColor(0xFF, 0xC4, 0x00, 80))
        halo.setColorAt(1.0, QColor(0xFF, 0xC4, 0x00, 0))
        p.setBrush(halo)
        p.drawEllipse(QRectF(cx - eye_w * 1.2, eye_cy - eye_w * 0.6,
                             eye_w * 2.4, eye_w * 1.2))

        # Cloak body — flowing bezier cape
        cloak_top  = head_cy + head_r * 0.75
        cloak_bot  = cy + cloak_h
        cloak_l    = cx - cloak_w
        cloak_r    = cx + cloak_w

        cloak = QPainterPath()
        cloak.moveTo(cx - head_r * 0.8, cloak_top)
        # Left side of cloak
        cloak.cubicTo(
            cx - head_r * 1.6, cloak_top + (cloak_bot - cloak_top) * 0.2,
            cloak_l + r * 0.05, cloak_bot - r * 0.25,
            cloak_l + r * 0.10, cloak_bot
        )
        # Bottom hem — slight arc
        cloak.cubicTo(
            cx - r * 0.20, cloak_bot + r * 0.04,
            cx + r * 0.20, cloak_bot + r * 0.04,
            cloak_r - r * 0.10, cloak_bot
        )
        # Right side of cloak
        cloak.cubicTo(
            cloak_r - r * 0.05, cloak_bot - r * 0.25,
            cx + head_r * 1.6, cloak_top + (cloak_bot - cloak_top) * 0.2,
            cx + head_r * 0.8, cloak_top
        )
        cloak.closeSubpath()

        cloak_grad = QLinearGradient(cx, cloak_top, cx, cloak_bot)
        cloak_grad.setColorAt(0.0, QColor(0x33, 0x2B, 0x10))
        cloak_grad.setColorAt(0.4, QColor(0x1A, 0x16, 0x08))
        cloak_grad.setColorAt(1.0, QColor(0x08, 0x07, 0x02))
        p.setBrush(cloak_grad)
        p.setPen(QPen(QColor(0xFF, 0xC4, 0x00, 160), max(1, size // 110)))
        p.drawPath(cloak)

        # ── 5. Encrypted data lines — Cypher's signature wire frames ─────────
        data_y_start = cy + r * 0.15
        line_gap     = r * 0.072
        segments     = [0.18, 0.38, 0.26, 0.44, 0.32]   # relative widths

        p.setPen(QPen(QColor(0xFF, 0xC4, 0x00, 140), max(1, size // 110)))
        for i, seg in enumerate(segments):
            lw    = size * seg
            lx    = cx - lw / 2
            ly    = data_y_start + i * line_gap
            if ly > cy + r * 0.88:
                break
            p.drawLine(QPointF(lx, ly), QPointF(lx + lw, ly))

        # Small square data nodes on alternate lines
        node_sz = max(2, size // 55)
        p.setBrush(LogoGenerator.CYPHER_GOLD)
        p.setPen(Qt.PenStyle.NoPen)
        for i, seg in enumerate(segments):
            if i % 2 == 0:
                lw = size * seg
                lx = cx - lw / 2
                ly = data_y_start + i * line_gap
                if ly > cy + r * 0.88:
                    break
                p.drawRect(QRectF(lx - node_sz / 2, ly - node_sz / 2,
                                  node_sz, node_sz))
                p.drawRect(QRectF(lx + lw - node_sz / 2, ly - node_sz / 2,
                                  node_sz, node_sz))

        # ── 6. Corner targeting brackets ─────────────────────────────────────
        br_len = r * 0.18
        br_w   = max(2, size // 55)
        p.setPen(QPen(LogoGenerator.CYPHER_GOLD, br_w))
        offset = r * 0.10
        for sx, sy in [(-1, -1), (1, -1), (-1, 1), (1, 1)]:
            bx = cx + sx * (r - offset)
            by = cy + sy * (r - offset)
            dx = sx * br_len
            dy = sy * br_len
            p.drawLine(QPointF(bx, by), QPointF(bx - dx, by))
            p.drawLine(QPointF(bx, by), QPointF(bx, by - dy))

        # ── 7. Central crosshair ─────────────────────────────────────────────
        ch_r = r * 0.07
        p.setPen(QPen(LogoGenerator.CYPHER_GOLD, max(1, size // 80)))
        p.drawLine(QPointF(cx - ch_r, cy), QPointF(cx + ch_r, cy))
        p.drawLine(QPointF(cx, cy - ch_r), QPointF(cx, cy + ch_r))
        p.setBrush(QColor(0xFF, 0xC4, 0x00, 60))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(QRectF(cx - ch_r * 0.5, cy - ch_r * 0.5,
                             ch_r, ch_r))

        # ── 8. Outer vignette / atmospheric glow ─────────────────────────────
        vignette = QRadialGradient(cx, cy, r)
        vignette.setColorAt(0.55, QColor(0xFF, 0xC4, 0x00, 0))
        vignette.setColorAt(0.82, QColor(0xFF, 0xC4, 0x00, 25))
        vignette.setColorAt(1.00, QColor(0xFF, 0xC4, 0x00, 70))
        p.setBrush(vignette)
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(QRectF(0, 0, size, size))

        p.end()
        return pixmap

    @staticmethod
    def create_icon_sizes() -> dict:
        """Create logo in multiple sizes."""
        return {s: LogoGenerator.create_logo(s)
                for s in [16, 32, 48, 64, 128, 256, 512]}

    @staticmethod
    def save_logo(filepath: str, size: int = 512) -> None:
        """Save logo to a PNG file."""
        LogoGenerator.create_logo(size).save(filepath, "PNG")
        print(f"Logo saved -> {filepath}")




################################################################################
# SECTION: settings_dialog  (from settings_dialog.py)
################################################################################

"""
Settings dialog for configuring application preferences.
"""



class SettingsDialog(QDialog):
    """Dialog for configuring application settings."""

    SETTINGS_FILE = "scanner_settings.json"

    DEFAULT_SETTINGS = {
        "nmap_path": "",
        "ollama_host": "localhost",
        "ollama_port": 11434,
        "default_model": "llama3",
        "default_profile": "Quick Scan (Top 100 Ports)",
        "socket_max_workers": 256,
        "socket_timeout": 1.0,
    }

    def __init__(self, parent=None):
        """Initialize settings dialog."""
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setModal(True)
        self.setMinimumWidth(500)

        self.settings = self.load_settings()
        self._init_ui()

    def _init_ui(self):
        """Initialize the UI components."""
        # Apply dark theme to settings dialog
        self.setStyleSheet("""
            /* Dialog - Dark Background */
            QDialog {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0f1419, stop:1 #1a1f2e);
            }
            
            /* Labels - Cyan text */
            QLabel {
                color: #b0c4de;
                font-size: 10pt;
            }
            
            /* Input Fields - Dark with cyan accent */
            QLineEdit {
                padding: 10px;
                border: 2px solid #3a3f4e;
                border-radius: 6px;
                background-color: #1e2330;
                color: #e0e6f0;
                font-size: 10pt;
                selection-background-color: #667eea;
            }
            QLineEdit:focus {
                border: 2px solid #00d4ff;
                background-color: #252b3d;
            }
            QLineEdit::placeholder {
                color: #6a7080;
            }
            
            /* Spin Boxes - Dark style */
            QSpinBox, QDoubleSpinBox {
                padding: 10px;
                border: 2px solid #3a3f4e;
                border-radius: 6px;
                background-color: #1e2330;
                color: #e0e6f0;
                font-size: 10pt;
            }
            QSpinBox:focus, QDoubleSpinBox:focus {
                border: 2px solid #00d4ff;
                background-color: #252b3d;
            }
            QSpinBox::up-button, QSpinBox::down-button,
            QDoubleSpinBox::up-button, QDoubleSpinBox::down-button {
                background-color: #667eea;
                border-radius: 3px;
            }
            QSpinBox::up-button:hover, QSpinBox::down-button:hover,
            QDoubleSpinBox::up-button:hover, QDoubleSpinBox::down-button:hover {
                background-color: #5568d3;
            }
            
            /* Combo Boxes - Dark dropdown */
            QComboBox {
                padding: 10px;
                border: 2px solid #3a3f4e;
                border-radius: 6px;
                background-color: #1e2330;
                color: #e0e6f0;
                font-size: 10pt;
            }
            QComboBox:hover {
                border: 2px solid #667eea;
                background-color: #252b3d;
            }
            QComboBox:focus {
                border: 2px solid #00d4ff;
            }
            QComboBox::drop-down {
                border: none;
                width: 30px;
            }
            QComboBox::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 6px solid #00d4ff;
                margin-right: 8px;
            }
            QComboBox QAbstractItemView {
                background-color: #1e2330;
                color: #e0e6f0;
                selection-background-color: #667eea;
                selection-color: white;
                border: 2px solid #00d4ff;
                border-radius: 4px;
            }
            
            /* Buttons - Cyberpunk style */
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #667eea, stop:1 #764ba2);
                color: #ffffff;
                border: 1px solid #00d4ff;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 10pt;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #5568d3, stop:1 #6a3f9a);
                border: 2px solid #00d4ff;
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #4c5fc6, stop:1 #5a3586);
                border: 1px solid #0099cc;
            }
        """)

        layout = QVBoxLayout()

        # Form layout for settings
        form_layout = QFormLayout()

        # Nmap path setting
        nmap_layout = QHBoxLayout()
        self.nmap_path_input = QLineEdit(self.settings.get("nmap_path", ""))
        self.nmap_path_input.setPlaceholderText("Leave empty to use system PATH")
        nmap_browse_btn = QPushButton("Browse...")
        nmap_browse_btn.clicked.connect(self._browse_nmap_path)
        nmap_layout.addWidget(self.nmap_path_input)
        nmap_layout.addWidget(nmap_browse_btn)
        form_layout.addRow("Nmap Binary Path:", nmap_layout)

        # Ollama host setting
        self.ollama_host_input = QLineEdit(self.settings.get("ollama_host", "localhost"))
        form_layout.addRow("Ollama Host:", self.ollama_host_input)

        # Ollama port setting
        self.ollama_port_input = QSpinBox()
        self.ollama_port_input.setRange(1, 65535)
        self.ollama_port_input.setValue(self.settings.get("ollama_port", 11434))
        form_layout.addRow("Ollama Port:", self.ollama_port_input)

        # Default model setting
        self.default_model_input = QLineEdit(self.settings.get("default_model", "llama3"))
        self.default_model_input.setPlaceholderText("e.g., llama3, mistral, codellama")
        form_layout.addRow("Default Model:", self.default_model_input)

        # Default profile setting — pulled dynamically from AdvancedScanProfile so
        # this list can never drift out of sync with the profiles actually offered
        # in the main scan dropdown.
        self.default_profile_combo = QComboBox()
        profiles = AdvancedScanProfile.get_profile_names()
        self.default_profile_combo.addItems(profiles)
        default_profile = self.settings.get("default_profile", "Quick Scan (Top 100 Ports)")
        index = self.default_profile_combo.findText(default_profile)
        if index >= 0:
            self.default_profile_combo.setCurrentIndex(index)
        form_layout.addRow("Default Profile:", self.default_profile_combo)

        # Socket-scan thread count — used by the Full Detail (socket) scanner.
        # Higher = faster full-range scans but more ephemeral-port pressure.
        self.socket_workers_input = QSpinBox()
        self.socket_workers_input.setRange(16, 1024)
        self.socket_workers_input.setSingleStep(16)
        self.socket_workers_input.setValue(int(self.settings.get("socket_max_workers", 256)))
        self.socket_workers_input.setToolTip(
            "Thread-pool size for Full Detail (socket) scans.\n"
            "256 is a good balance for most networks; raise to 512 for fast LANs."
        )
        form_layout.addRow("Socket Scan Threads:", self.socket_workers_input)

        # Socket-scan per-port connect timeout
        self.socket_timeout_input = QDoubleSpinBox()
        self.socket_timeout_input.setRange(0.1, 10.0)
        self.socket_timeout_input.setSingleStep(0.1)
        self.socket_timeout_input.setDecimals(1)
        self.socket_timeout_input.setValue(float(self.settings.get("socket_timeout", 1.0)))
        self.socket_timeout_input.setToolTip(
            "Per-port connect timeout (seconds) for Full Detail (socket) scans.\n"
            "0.5s is fine for LAN targets; use 1.0–2.0s for WAN/internet targets."
        )
        form_layout.addRow("Socket Timeout (s):", self.socket_timeout_input)

        layout.addLayout(form_layout)

        # Info label
        info_label = QLabel(
            "Note: Changes take effect immediately.\n"
            "Nmap and Ollama must be properly installed and configured."
        )
        info_label.setStyleSheet("color: #666; font-size: 9pt;")
        info_label.setWordWrap(True)
        layout.addWidget(info_label)

        # Buttons
        button_layout = QHBoxLayout()
        save_btn = QPushButton("Save")
        save_btn.clicked.connect(self._save_settings)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addStretch()
        button_layout.addWidget(save_btn)
        button_layout.addWidget(cancel_btn)

        layout.addLayout(button_layout)
        self.setLayout(layout)

    def _browse_nmap_path(self):
        """Open file browser to select nmap binary."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Nmap Binary",
            "",
            "Executable Files (*)"
        )
        if file_path:
            self.nmap_path_input.setText(file_path)

    def _save_settings(self):
        """Save settings to file and close dialog."""
        # Merge edited fields into the existing settings so keys persisted by
        # other controls (e.g. full_detail_mode) are never silently discarded.
        self.settings.update({
            "nmap_path": self.nmap_path_input.text().strip(),
            "ollama_host": self.ollama_host_input.text().strip(),
            "ollama_port": self.ollama_port_input.value(),
            "default_model": self.default_model_input.text().strip(),
            "default_profile": self.default_profile_combo.currentText(),
            "socket_max_workers": self.socket_workers_input.value(),
            "socket_timeout": self.socket_timeout_input.value(),
        })

        try:
            self.save_settings_to_file(self.settings)
            QMessageBox.information(self, "Success", "Settings saved successfully!")
            self.accept()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save settings: {str(e)}")

    @classmethod
    def load_settings(cls) -> dict:
        """
        Load settings from file or return defaults.

        Returns:
            Dictionary of settings
        """
        if os.path.exists(cls.SETTINGS_FILE):
            try:
                with open(cls.SETTINGS_FILE, 'r') as f:
                    loaded = json.load(f)
                merged = cls.DEFAULT_SETTINGS.copy()
                merged.update(loaded)
                return merged
            except Exception:
                pass
        return cls.DEFAULT_SETTINGS.copy()

    @classmethod
    def save_settings_to_file(cls, settings: dict):
        """
        Save settings to file.

        Args:
            settings: Dictionary of settings to save
        """
        with open(cls.SETTINGS_FILE, 'w') as f:
            json.dump(settings, f, indent=2)

    def get_settings(self) -> dict:
        """
        Get current settings.

        Returns:
            Dictionary of settings
        """
        return self.settings


################################################################################
# SECTION: worker  (from worker.py)
################################################################################

"""
Worker thread for running port scans in the background.

Two scan modes:
    full_detail=False  (default / legacy)
        Runs Nmap live with -vv, streams per-port output, captures only the
        ports Nmap reports (open ports + whatever makes it into the final
        table).  Fast and gives rich version data for open ports, but large
        ranges show only open/reported ports — same behaviour as before.

    full_detail=True
        Replaces (or supplements) the Nmap text-output pass with a direct
        TCP socket scan that classifies *every* port in the range as
        open / closed / filtered.  After the socket pass, banner grabbing
        enriches the open ports exactly as before.  Nmap is not invoked for
        the socket pass, so this mode works without Nmap installed.

        NOTE: the socket backend only understands a bare host/IP and only
        ever does a plain TCP-connect probe — it has no concept of Nmap's
        -sS/-sV/-sC/--script/-f/--traceroute flags. So if the selected
        profile relies on any of those (Vulnerability Scan, Stealth SYN,
        Service Scripts, etc.), Full Detail mode silently drops that
        technique and just does a connect-scan of the profile's port range.
        run() now warns about this before scanning, and _run_socket_scan()
        rejects CIDR/wildcard targets up front with a clear error instead
        of failing deep inside socket.gethostbyname().
"""



# Flags that mean "this profile does more than a plain TCP connect scan."
# Full Detail (socket) mode can't perform any of these — it only classifies
# open/closed/filtered via connect_ex(). Used to warn the user before the
# scan starts so a chosen technique doesn't get silently dropped.
_TECHNIQUE_FLAGS = ("-sS", "-sV", "-sC", "-O", "--script", "-f", "--traceroute")


def _profile_drops_technique_in_full_detail(arguments: str) -> bool:
    """True if Full Detail mode would silently ignore part of this profile."""
    return any(flag in arguments for flag in _TECHNIQUE_FLAGS)


def _profile_requires_raw_socket(arguments: str) -> bool:
    """Return True for Nmap techniques that normally need raw-socket privileges."""
    raw_flags = ("-sS", "-O", "-f", "--send-ip", "--spoof-mac", "-D ", "--source-port")
    return any(flag in arguments for flag in raw_flags)


class ScanWorker(QThread):
    """Background worker — streams scan output via signals."""

    # ── Signals ───────────────────────────────────────────────────────────────
    scan_started       = pyqtSignal()
    scan_progress      = pyqtSignal(str)          # status-bar text
    scan_progress_pct  = pyqtSignal(float, str)   # (percent 0-100, message)
    scan_line          = pyqtSignal(str)           # raw output line
    port_found         = pyqtSignal(dict)          # per-port dict as found live
    scan_completed     = pyqtSignal(dict)          # full results dict
    scan_error         = pyqtSignal(str)
    analysis_started   = pyqtSignal()
    analysis_token     = pyqtSignal(str)           # streamed AI token
    analysis_completed = pyqtSignal(str)           # full AI text (when done)
    analysis_error     = pyqtSignal(str)

    def __init__(self, scanner: AdvancedScanner, analyzer,
                 target: str, profile_name: str,
                 custom_ports: str = "",
                 full_detail: bool = False):
        """
        Args:
            scanner:      AdvancedScanner (Nmap wrapper). May be None if Nmap
                          is unavailable — full_detail mode works without it.
            analyzer:     OllamaClient/ScanAnalyzer for AI analysis (optional).
            target:       Hostname or IP to scan.
            profile_name: Name of the scan profile to look up.
            custom_ports: Overrides the profile's port range when non-empty.
            full_detail:  When True, use the socket-based scanner so every
                          port gets an accurate state row in the results.
        """
        super().__init__()
        self.scanner      = scanner
        self.analyzer     = analyzer
        self.target       = target
        self.profile_name = profile_name
        self.custom_ports = custom_ports.strip()
        self.full_detail  = full_detail
        self._is_running  = True

    # ── Thread entry point ────────────────────────────────────────────────────

    def run(self):
        try:
            self.scan_started.emit()
            port_info = f"  ports: {self.custom_ports}" if self.custom_ports else ""
            mode_tag  = "  [full-detail socket scan]" if self.full_detail else ""
            self.scan_progress.emit(
                f"Starting {self.profile_name} on {self.target}{port_info}{mode_tag}…"
            )

            # ── Resolve ports + arguments from profile ────────────────────

            profile = (ScanProfile.get_profile_by_name(self.profile_name)
                       or AdvancedScanProfile.get_profile_by_name(self.profile_name))
            if not profile:
                self.scan_error.emit(f"Unknown scan profile: {self.profile_name}")
                return

            ports     = self.custom_ports if self.custom_ports else profile["ports"]
            arguments = profile["arguments"]

            # Full Detail uses the socket backend, so Nmap-only implicit port
            # selectors such as --top-ports cannot be reproduced directly.
            # Profiles may provide an explicit socket_ports fallback.
            socket_ports = (
                self.custom_ports
                if self.custom_ports
                else profile.get("socket_ports", ports)
            )

            # ── Choose scan backend ───────────────────────────────────────
            if self.full_detail:
                if self.profile_name == ScanProfile.QUICK["name"] and not self.custom_ports:
                    self.scan_progress.emit(
                        "Note: Full Detail uses ports 1-1024 for Quick Scan because "
                        "the built-in socket scanner cannot reproduce Nmap's "
                        "--top-ports 100 database selection. "
                        "Set custom ports if you want a different range."
                    )
                if _profile_drops_technique_in_full_detail(arguments):
                    self.scan_progress.emit(
                        f"Note: Full Detail mode uses a plain TCP-connect probe — "
                        f"the '{self.profile_name}' profile's extra techniques "
                        f"(version/script/stealth/traceroute) will NOT run. "
                        f"Uncheck Full Detail to use them."
                    )
                try:
                    results = self._run_socket_scan(socket_ports)
                except RuntimeError as e:
                    # Raised by _run_socket_scan for CIDR/wildcard targets or
                    # DNS failures — surface it as a clean scan error instead
                    # of an unhandled exception.
                    self.scan_error.emit(str(e))
                    return
            else:
                # Raw-socket Nmap techniques (notably SYN/fragmented scans)
                # require elevated privileges.  Do not let an unprivileged
                # run silently appear to have used the selected technique.
                if _profile_requires_raw_socket(arguments):
                    self._on_line(
                        "[warning] This profile uses an Nmap raw-socket technique "
                        "(for example SYN/OS/fragmentation). Run the application "
                        "with Administrator/root privileges to preserve that technique; "
                        "otherwise Nmap may fall back or fail."
                    )
                    self.scan_progress.emit(
                        "Warning: selected Nmap technique may require Administrator/root privileges"
                    )
                if not self.scanner:
                    self.scan_error.emit(
                        "Scanner not initialised. "
                        "Make sure Nmap is installed and configured in Settings.\n\n"
                        "Alternatively, enable Full Detail mode to use the built-in "
                        "socket scanner (no Nmap required)."
                    )
                    return
                results = self.scanner.run_scan_live(
                    target=self.target,
                    ports=ports,
                    arguments=arguments,
                    on_line=self._on_line,
                    on_port=self._on_port,
                    on_progress=self._on_progress,
                    stop_flag=lambda: not self._is_running,
                )

            if not self._is_running:
                return

            self.scan_progress.emit("Scan complete — grabbing service banners…")

            # ── Banner enrichment (open ports only) ───────────────────────
            try:
                enrich_scan_results(
                    results,
                    timeout=3.0,
                    stop_flag=lambda: not self._is_running,
                )
            except Exception:
                pass  # banner grabbing is best-effort

            self.scan_progress.emit("Scan complete — processing results…")
            self.scan_completed.emit(results)

            if not self._is_running:
                return

            # ── Optional AI analysis ──────────────────────────────────────
            if self.analyzer:
                self.analysis_started.emit()
                self.scan_progress.emit("Running AI analysis…")
                try:
                    def _on_token(token: str):
                        if self._is_running:
                            self.analysis_token.emit(token)

                    analysis = self.analyzer.analyze_scan_results(
                        results,
                        on_token=_on_token,
                        stop_flag=lambda: not self._is_running,
                    )
                    if self._is_running:
                        self.analysis_completed.emit(analysis)
                        self.scan_progress.emit("Analysis complete.")
                except Exception as e:
                    self.analysis_error.emit(str(e))
            else:
                self.analysis_error.emit(
                    "Ollama is not available. Run 'ollama serve' to enable AI analysis."
                )

        except Exception as e:
            self.scan_error.emit(str(e))

    # ── Socket scan (full-detail mode) ────────────────────────────────────────

    def _run_socket_scan(self, ports: str) -> dict:
        """
        Run the socket-based scanner.  Fires the same callbacks as the Nmap
        path so the UI updates identically.

        Raises RuntimeError up front (before any port classification starts)
        if the target isn't a single host/IP the socket API can resolve —
        e.g. a CIDR range or a wildcard — since socket.gethostbyname() can't
        handle those and would otherwise fail deep inside run_scan_live()
        with a confusing DNS-resolution message.
        """
        if "/" in self.target or "*" in self.target:
            raise RuntimeError(
                f"Full Detail (socket scan) mode only supports a single host "
                f"or IP, not a range like {self.target!r}. "
                f"Uncheck Full Detail to scan CIDR ranges with Nmap instead."
            )

        settings        = SettingsDialog.load_settings()
        max_workers     = int(settings.get("socket_max_workers", 256))
        connect_timeout = float(settings.get("socket_timeout", 1.0))

        sock_scanner = SocketScanner(
            max_workers=max_workers,
            timeout=connect_timeout,
        )
        # Keep a reference so stop() can reach it
        self._socket_scanner = sock_scanner

        results = sock_scanner.run_scan_live(
            target=self.target,
            ports=ports,
            on_line=self._on_line,
            on_port=self._on_port,
            on_progress=self._on_progress,
            stop_flag=lambda: not self._is_running,
        )
        return results

    # ── Callbacks from scanner (called on worker thread) ─────────────────────

    def _on_line(self, line: str):
        if self._is_running:
            self.scan_line.emit(line)

    def _on_port(self, port_dict: dict):
        if self._is_running:
            self.port_found.emit(port_dict)

    def _on_progress(self, pct: float, msg: str):
        if self._is_running:
            self.scan_progress.emit(msg)
            self.scan_progress_pct.emit(pct, msg)

    # ── Stop ──────────────────────────────────────────────────────────────────

    def stop(self):
        self._is_running = False
        # Stop whichever backend is running
        if self.scanner:
            self.scanner.stop_live_scan()
        sock = getattr(self, "_socket_scanner", None)
        if sock:
            sock.stop()
        self.quit()
        self.wait()


class AdvancedToolWorker(QThread):
    """
    Generic background worker for the one-shot advanced scanner tools
    (OS detection, honeypot detection, firewall detection, traceroute).

    These AdvancedScanner methods block and return a single dict/list, so
    rather than give each tool its own QThread subclass, this worker just
    wraps whichever callable + target it's given.
    """

    result_ready = pyqtSignal(str, object)   # (tool_name, result)
    tool_error   = pyqtSignal(str, str)       # (tool_name, error message)

    def __init__(self, tool_name: str, func: Callable, target: str, **kwargs):
        super().__init__()
        self.tool_name = tool_name
        self.func      = func
        self.target    = target
        self.kwargs    = kwargs

    def run(self):
        try:
            result = self.func(self.target, **self.kwargs)
            self.result_ready.emit(self.tool_name, result)
        except Exception as e:
            self.tool_error.emit(self.tool_name, str(e))

################################################################################
# SECTION: main_window  (from main_window.py)
################################################################################

"""
Main GUI window for the AI Port Scanner application.
"""




def _fmt_ports(ports: list, max_show: int = 10) -> str:
    """Format a port list as a compact string, truncating if too long."""
    if not ports:
        return ""
    shown = [str(p) for p in ports[:max_show]]
    tail  = f"  ...+{len(ports) - max_show} more" if len(ports) > max_show else ""
    return "[" + ", ".join(shown) + "]" + tail


class MainWindow(QMainWindow):
    """Main application window."""
    
    def __init__(self):
        """Initialize the main window."""
        super().__init__()
        self.setWindowTitle("Cypher — AI Network Intelligence Scanner")
        self.setGeometry(100, 100, 1400, 900)
        
        # Set application icon
        try:
            logo = LogoGenerator.create_logo(64)
            self.setWindowIcon(QIcon(logo))
        except Exception:
            pass  # If logo generation fails, continue without it
        
        # State variables
        self.current_scan_results = None
        self.current_ai_analysis = None
        self.current_anomaly_report = None
        self.scan_worker = None
        self._live_port_count = 0
        
        # Load settings
        self.settings = SettingsDialog.load_settings()
        
        # Initialize components (will be done after UI)
        self.scanner = None
        self.ollama_client = None
        self.analyzer = None
        
        # Initialize UI
        self._init_ui()
        
        # Initialize scanner and AI components
        self._init_components()
    
    def _init_ui(self):
        """Initialize the user interface."""
        # Set dark theme inspired by Cypher
        self.setStyleSheet("""
            /* Main Window - Dark Background */
            QMainWindow {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0f1419, stop:1 #1a1f2e);
            }
            
            /* Group Boxes - Dark with cyan glow */
            QGroupBox {
                font-weight: bold;
                font-size: 11pt;
                border: 2px solid #667eea;
                border-radius: 10px;
                margin-top: 16px;
                padding-top: 16px;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 rgba(26, 31, 46, 200), stop:1 rgba(15, 20, 25, 220));
                color: #00d4ff;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 8px;
                color: #00d4ff;
                background-color: #1a1f2e;
            }
            
            /* Buttons - Cyberpunk style */
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #667eea, stop:1 #764ba2);
                color: #ffffff;
                border: 1px solid #00d4ff;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 10pt;
                text-transform: uppercase;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #5568d3, stop:1 #6a3f9a);
                border: 2px solid #00d4ff;
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #4c5fc6, stop:1 #5a3586);
                border: 1px solid #0099cc;
            }
            QPushButton:disabled {
                background-color: #2a2f3e;
                color: #5a6070;
                border: 1px solid #3a3f4e;
            }
            
            /* Input Fields - Dark with cyan accent */
            QLineEdit {
                padding: 10px;
                border: 2px solid #3a3f4e;
                border-radius: 6px;
                background-color: #1e2330;
                color: #e0e6f0;
                font-size: 10pt;
                selection-background-color: #667eea;
            }
            QLineEdit:focus {
                border: 2px solid #00d4ff;
                background-color: #252b3d;
            }
            QLineEdit::placeholder {
                color: #6a7080;
            }
            
            /* Combo Boxes - Dark dropdown */
            QComboBox {
                padding: 10px;
                border: 2px solid #3a3f4e;
                border-radius: 6px;
                background-color: #1e2330;
                color: #e0e6f0;
                font-size: 10pt;
            }
            QComboBox:hover {
                border: 2px solid #667eea;
                background-color: #252b3d;
            }
            QComboBox:focus {
                border: 2px solid #00d4ff;
            }
            QComboBox::drop-down {
                border: none;
                width: 30px;
            }
            QComboBox::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 6px solid #00d4ff;
                margin-right: 8px;
            }
            QComboBox QAbstractItemView {
                background-color: #1e2330;
                color: #e0e6f0;
                selection-background-color: #667eea;
                selection-color: white;
                border: 2px solid #00d4ff;
                border-radius: 4px;
            }
            
            /* Labels - Cyan text */
            QLabel {
                color: #b0c4de;
                font-size: 10pt;
            }
            
            /* Checkboxes - Custom styled */
            QCheckBox {
                color: #e0e6f0;
                font-size: 10pt;
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 20px;
                height: 20px;
                border: 2px solid #3a3f4e;
                border-radius: 4px;
                background-color: #1e2330;
            }
            QCheckBox::indicator:hover {
                border: 2px solid #667eea;
            }
            QCheckBox::indicator:checked {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #667eea, stop:1 #764ba2);
                border: 2px solid #00d4ff;
            }
            QCheckBox::indicator:checked:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #5568d3, stop:1 #6a3f9a);
            }
            
            /* Tables - Dark grid */
            QTableWidget {
                background-color: #1a1f2e;
                alternate-background-color: #1e2330;
                gridline-color: #2a2f3e;
                border: 2px solid #3a3f4e;
                border-radius: 8px;
                color: #e0e6f0;
                font-size: 9pt;
            }
            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid #2a2f3e;
            }
            QTableWidget::item:selected {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #667eea, stop:1 #764ba2);
                color: white;
            }
            QTableWidget::item:hover {
                background-color: #252b3d;
            }
            
            /* Table Headers - Gradient header */
            QHeaderView::section {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #667eea, stop:1 #764ba2);
                color: white;
                padding: 10px;
                border: none;
                border-right: 1px solid #5568d3;
                font-weight: bold;
                font-size: 9pt;
                text-transform: uppercase;
            }
            QHeaderView::section:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #5568d3, stop:1 #6a3f9a);
            }
            
            /* Text Edit - Dark editor */
            QTextEdit {
                background-color: #1a1f2e;
                border: 2px solid #3a3f4e;
                border-radius: 8px;
                padding: 12px;
                color: #e0e6f0;
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 9pt;
                selection-background-color: #667eea;
            }
            
            /* Progress Bar - Cyberpunk glow */
            QProgressBar {
                border: 2px solid #00d4ff;
                border-radius: 6px;
                text-align: center;
                background-color: #1a1f2e;
                color: #00d4ff;
                font-weight: bold;
                font-size: 10pt;
                height: 25px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #667eea, stop:1 #00d4ff);
                border-radius: 4px;
            }
            
            /* Tabs - Dark tabs */
            QTabWidget::pane {
                border: 2px solid #3a3f4e;
                background: #1a1f2e;
                border-radius: 8px;
                top: -2px;
            }
            QTabBar::tab {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #252b3d, stop:1 #1e2330);
                color: #b0c4de;
                padding: 12px 24px;
                margin-right: 2px;
                border: 2px solid #3a3f4e;
                border-bottom: none;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                font-weight: bold;
                font-size: 10pt;
            }
            QTabBar::tab:selected {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #667eea, stop:1 #764ba2);
                color: white;
                border: 2px solid #00d4ff;
                border-bottom: none;
            }
            QTabBar::tab:hover:!selected {
                background: #2a2f3e;
                border: 2px solid #667eea;
            }
            
            /* Scrollbars - Sleek dark scrollbars */
            QScrollBar:vertical {
                background: #1a1f2e;
                width: 12px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical {
                background: #667eea;
                border-radius: 6px;
                min-height: 20px;
            }
            QScrollBar::handle:vertical:hover {
                background: #5568d3;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
            QScrollBar:horizontal {
                background: #1a1f2e;
                height: 12px;
                border-radius: 6px;
            }
            QScrollBar::handle:horizontal {
                background: #667eea;
                border-radius: 6px;
                min-width: 20px;
            }
            QScrollBar::handle:horizontal:hover {
                background: #5568d3;
            }
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
                width: 0px;
            }
            
            /* Tool Tips - Dark tooltips */
            QToolTip {
                background-color: #1e2330;
                color: #00d4ff;
                border: 2px solid #667eea;
                border-radius: 4px;
                padding: 5px;
                font-size: 9pt;
            }
        """)
        
        # Central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(10, 10, 10, 10)
        
        # === Top Section: Controls ===
        controls_group = QGroupBox("🔍 SCAN CONFIGURATION")
        controls_group.setStyleSheet("""
            QGroupBox {
                font-size: 12pt;
                font-weight: bold;
                text-transform: uppercase;
                letter-spacing: 1px;
            }
        """)
        controls_layout = QVBoxLayout()
        controls_layout.setSpacing(12)

        # ── Row 1: Domain / IP  +  Target IP ─────────────────────────────────
        row1 = QHBoxLayout()
        row1.setSpacing(10)

        domain_label = QLabel("🌐 Domain / IP:")
        domain_label.setMinimumWidth(100)
        row1.addWidget(domain_label)
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("e.g. example.com or 192.168.1.0/24")
        self.domain_input.setToolTip(
            "Enter a domain name (e.g. example.com) or a CIDR range.\n"
            "Leave blank to use only the Target IP field."
        )
        row1.addWidget(self.domain_input, 2)

        row1.addSpacing(16)

        target_label = QLabel("🎯 Target IP:")
        target_label.setMinimumWidth(80)
        row1.addWidget(target_label)
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("e.g. 192.168.1.1")
        self.target_input.setToolTip(
            "Enter a single IP address or hostname.\n"
            "If both Domain and Target IP are filled, Target IP takes priority."
        )
        row1.addWidget(self.target_input, 2)

        controls_layout.addLayout(row1)

        # ── Row 2: Start Port  +  End Port ───────────────────────────────────
        row2 = QHBoxLayout()
        row2.setSpacing(10)

        sp_label = QLabel("🔢 Start Port:")
        sp_label.setMinimumWidth(100)
        row2.addWidget(sp_label)
        self.start_port_input = QLineEdit()
        self.start_port_input.setPlaceholderText("1  (leave blank = profile default)")
        self.start_port_input.setMaximumWidth(160)
        self.start_port_input.setToolTip(
            "First port in the range to scan.\n"
            "Leave blank to use the selected profile's default range."
        )
        row2.addWidget(self.start_port_input)

        ep_label = QLabel("🔢 End Port:")
        ep_label.setMinimumWidth(80)
        row2.addWidget(ep_label)
        self.end_port_input = QLineEdit()
        self.end_port_input.setPlaceholderText("1024  (leave blank = profile default)")
        self.end_port_input.setMaximumWidth(160)
        self.end_port_input.setToolTip(
            "Last port in the range to scan.\n"
            "Leave blank to use the selected profile's default range."
        )
        row2.addWidget(self.end_port_input)

        row2.addStretch()

        controls_layout.addLayout(row2)

        # ── Row 3: Scan Profile + AI Model ───────────────────────────────────
        row3 = QHBoxLayout()
        row3.setSpacing(10)

        row3.addWidget(QLabel("Scan Profile:"))
        self.profile_combo = QComboBox()
        self.profile_combo.setMinimumWidth(280)

        for profile in AdvancedScanProfile.get_all_profiles():
            self.profile_combo.addItem(profile["name"])
            self.profile_combo.setItemData(
                self.profile_combo.count() - 1,
                profile["description"],
                Qt.ItemDataRole.ToolTipRole
            )

        row3.addWidget(self.profile_combo)
        row3.addSpacing(16)

        row3.addWidget(QLabel("AI Model:"))
        self.model_combo = QComboBox()
        self.model_combo.addItem(self.settings.get("default_model", "llama3"))
        row3.addWidget(self.model_combo)

        refresh_models_btn = QPushButton("⟳ Refresh")
        refresh_models_btn.setToolTip("Reload available Ollama models")
        refresh_models_btn.clicked.connect(self._refresh_models)
        row3.addWidget(refresh_models_btn)

        row3.addStretch()
        controls_layout.addLayout(row3)

        # ── Row 4: Auth checkbox + Full Detail toggle + action buttons ──────────
        row4 = QHBoxLayout()
        self.auth_checkbox = QCheckBox(
            "I have authorization to scan this target (required)"
        )
        self.auth_checkbox.stateChanged.connect(self._update_scan_button_state)
        row4.addWidget(self.auth_checkbox)

        row4.addSpacing(20)

        self.full_detail_checkbox = QCheckBox("Full Detail (socket scan — all ports)")
        self.full_detail_checkbox.setToolTip(
            "When checked, every port in the range is classified as\n"
            "open / closed / filtered using direct TCP socket connections.\n\n"
            "This guarantees a row for every port scanned and accurate\n"
            "state counts — no more 'Not shown: N closed ports' data loss.\n\n"
            "For large ranges (e.g. 1–65535) the table will be large;\n"
            "use with a narrower custom port range if you only need detail\n"
            "on a specific segment.\n\n"
            "Does NOT require Nmap — uses the built-in socket scanner.\n\n"
            "Thread count and per-port timeout are configurable in Settings."
        )
        # Load saved preference
        self.full_detail_checkbox.setChecked(
            bool(self.settings.get("full_detail_mode", False))
        )
        self.full_detail_checkbox.stateChanged.connect(self._on_full_detail_changed)
        row4.addWidget(self.full_detail_checkbox)

        row4.addStretch()

        self.scan_btn = QPushButton("▶ Start Scan")
        self.scan_btn.setEnabled(False)
        self.scan_btn.clicked.connect(self._start_scan)
        row4.addWidget(self.scan_btn)

        self.stop_btn = QPushButton("⏹ Stop Scan")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop_scan)
        row4.addWidget(self.stop_btn)

        settings_btn = QPushButton("⚙ Settings")
        settings_btn.clicked.connect(self._open_settings)
        row4.addWidget(settings_btn)

        controls_layout.addLayout(row4)
        controls_group.setLayout(controls_layout)
        main_layout.addWidget(controls_group)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setVisible(False)
        main_layout.addWidget(self.progress_bar)
        
        # Status label with dark theme
        self.status_label = QLabel("⚡ Ready to scan")
        self.status_label.setStyleSheet(
            "color: #00d4ff; padding: 8px; "
            "background-color: rgba(102, 126, 234, 0.1); "
            "border-left: 4px solid #00d4ff; "
            "border-radius: 4px; "
            "font-weight: bold; font-size: 10pt;"
        )
        main_layout.addWidget(self.status_label)
        
        # === Middle Section: Results (Tabbed Interface) ===
        results_tabs = QTabWidget()
        self.results_tabs_ref = results_tabs  # keep reference for tab switching
        results_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 2px solid #3a3f4e;
                background: #1a1f2e;
                border-radius: 10px;
                top: -2px;
            }
            QTabBar::tab {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #252b3d, stop:1 #1e2330);
                color: #b0c4de;
                padding: 14px 28px;
                margin-right: 2px;
                border: 2px solid #3a3f4e;
                border-bottom: none;
                border-top-left-radius: 10px;
                border-top-right-radius: 10px;
                font-weight: bold;
                font-size: 11pt;
            }
            QTabBar::tab:selected {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #667eea, stop:1 #764ba2);
                color: white;
                border: 2px solid #00d4ff;
                border-bottom: none;
            }
            QTabBar::tab:hover:!selected {
                background: #2a2f3e;
                border: 2px solid #667eea;
                color: #00d4ff;
            }
        """)
        
        # ── Tab 0: Live Console ───────────────────────────────────────────────
        live_widget = QWidget()
        live_layout = QVBoxLayout(live_widget)

        live_header = QHBoxLayout()
        live_label = QLabel("⚡ LIVE SCAN CONSOLE")
        live_label.setFont(QFont("Consolas", 11, QFont.Weight.Bold))
        live_label.setStyleSheet("color: #00d4ff; letter-spacing: 1px;")
        live_header.addWidget(live_label)
        live_header.addStretch()

        self.current_port_label = QLabel("Currently scanning: —")
        self.current_port_label.setStyleSheet(
            "color: #ffc400; font-weight: bold; font-size: 10pt; padding: 4px 10px;"
            "background: rgba(255,196,0,0.08); border: 1px solid #ffc400; border-radius: 4px;"
        )
        live_header.addWidget(self.current_port_label)

        self.live_port_counter = QLabel("Ports found: 0")
        self.live_port_counter.setStyleSheet(
            "color: #2ed573; font-weight: bold; font-size: 10pt; padding: 4px 10px;"
            "background: rgba(46,213,115,0.1); border: 1px solid #2ed573; border-radius: 4px;"
        )
        live_header.addWidget(self.live_port_counter)

        clear_live_btn = QPushButton("Clear")
        clear_live_btn.setMaximumWidth(70)
        clear_live_btn.clicked.connect(lambda: self.live_console.clear())
        live_header.addWidget(clear_live_btn)
        live_layout.addLayout(live_header)

        self.live_console = QTextEdit()
        self.live_console.setReadOnly(True)
        self.live_console.setFont(QFont("Consolas", 9))
        self.live_console.setStyleSheet(
            "QTextEdit { background-color: #0a0c10; color: #c8d0e0; "
            "border: 2px solid #00d4ff; border-radius: 6px; padding: 8px; }"
        )
        self.live_console.setPlaceholderText(
            "Live nmap output will stream here as each port is probed...\n\n"
            "  Discovered open port 443/tcp on 192.168.1.1\n"
            "  80/tcp   closed  http    reset ttl 128\n"
            "  Scanning... 45.0% complete\n"
        )
        live_layout.addWidget(self.live_console)
        results_tabs.addTab(live_widget, "⚡ Live Console")

        # ── Tab 1: Scan Results ───────────────────────────────────────────────
        scan_results_widget = QWidget()
        scan_results_layout = QVBoxLayout(scan_results_widget)

        results_header = QHBoxLayout()
        results_header_label = QLabel("📊 SCAN RESULTS  —  all scanned ports")
        results_header_label.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        results_header_label.setStyleSheet("color: #00d4ff; letter-spacing: 1px;")
        results_header.addWidget(results_header_label)
        results_header.addStretch()

        export_csv_btn = QPushButton("📋 Export CSV")
        export_csv_btn.setToolTip("Export all scanned ports as CSV")
        export_csv_btn.clicked.connect(self._export_csv)
        results_header.addWidget(export_csv_btn)

        export_json_btn = QPushButton("💾 Export JSON")
        export_json_btn.setToolTip("Export scan results as JSON")
        export_json_btn.clicked.connect(self._export_json)
        results_header.addWidget(export_json_btn)

        export_txt_btn = QPushButton("📄 Export TXT")
        export_txt_btn.setToolTip("Export as formatted text report")
        export_txt_btn.clicked.connect(self._export_report)
        results_header.addWidget(export_txt_btn)

        export_html_btn = QPushButton("🌐 Export HTML")
        export_html_btn.setToolTip("Export as HTML report")
        export_html_btn.clicked.connect(self._export_html)
        results_header.addWidget(export_html_btn)

        export_pdf_btn = QPushButton("📕 Export PDF")
        export_pdf_btn.setToolTip("Export as PDF report")
        export_pdf_btn.clicked.connect(self._export_pdf)
        results_header.addWidget(export_pdf_btn)

        export_docx_btn = QPushButton("📝 Export DOCX")
        export_docx_btn.setToolTip("Export as Word document")
        export_docx_btn.clicked.connect(self._export_docx)
        results_header.addWidget(export_docx_btn)

        scan_results_layout.addLayout(results_header)

        self.results_table = QTableWidget()
        self.results_table.setColumnCount(8)
        self.results_table.setHorizontalHeaderLabels([
            "Host", "Port", "Protocol", "State", "Service", "Product", "Version", "Extra Info"
        ])
        self.results_table.setAlternatingRowColors(True)
        self.results_table.horizontalHeader().setStretchLastSection(True)
        self.results_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.results_table.setSortingEnabled(True)
        scan_results_layout.addWidget(self.results_table)
        results_tabs.addTab(scan_results_widget, "📊 Scan Results")

        # ── Tab 2: AI Analysis ────────────────────────────────────────────────
        ai_widget = QWidget()
        ai_layout = QVBoxLayout(ai_widget)
        ai_label = QLabel("🤖 AI SECURITY ANALYSIS")
        ai_label.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        ai_label.setStyleSheet("color: #00d4ff; letter-spacing: 1px;")
        ai_layout.addWidget(ai_label)
        self.ai_output = QTextEdit()
        self.ai_output.setReadOnly(True)
        self.ai_output.setPlaceholderText("AI analysis will appear here after scan completes...")
        ai_layout.addWidget(self.ai_output)
        results_tabs.addTab(ai_widget, "🤖 AI Analysis")

        # ── Tab 3: Anomaly Detection ──────────────────────────────────────────
        anomaly_widget = QWidget()
        anomaly_layout = QVBoxLayout(anomaly_widget)
        anomaly_label = QLabel("🚨 ANOMALY & HONEYPOT DETECTION")
        anomaly_label.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        anomaly_label.setStyleSheet("color: #00d4ff; letter-spacing: 1px;")
        anomaly_layout.addWidget(anomaly_label)
        self.anomaly_output = QTextEdit()
        self.anomaly_output.setReadOnly(True)
        self.anomaly_output.setPlaceholderText(
            "Anomaly detection analysis will appear here...\n\n"
            "Detects:\n"
            "  Suspicious ports and services\n"
            "  Honeypot indicators\n"
            "  Cleartext protocols\n"
            "  Outdated/vulnerable services\n"
            "  High-value targets (RDP, SMB, etc.)"
        )
        anomaly_layout.addWidget(self.anomaly_output)
        results_tabs.addTab(anomaly_widget, "🚨 Anomaly Detection")

        # ── Tab 4: Advanced Tools (OS detect / honeypot / firewall / traceroute) ─
        advanced_widget = QWidget()
        advanced_layout = QVBoxLayout(advanced_widget)

        advanced_label = QLabel("🔬 ADVANCED RECON TOOLS")
        advanced_label.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        advanced_label.setStyleSheet("color: #00d4ff; letter-spacing: 1px;")
        advanced_layout.addWidget(advanced_label)

        advanced_note = QLabel(
            "These run a fresh, separate Nmap probe against the target above "
            "(independent of the main scan) and may require root/admin privileges."
        )
        advanced_note.setWordWrap(True)
        advanced_note.setStyleSheet("color: #8899aa; font-size: 9pt;")
        advanced_layout.addWidget(advanced_note)

        advanced_btn_row = QHBoxLayout()

        self.os_detect_btn = QPushButton("🖥️ OS Detection")
        self.os_detect_btn.setToolTip("Fingerprint the target's OS (nmap -O); administrator/root privileges are typically required")
        self.os_detect_btn.clicked.connect(self._run_os_detection)
        advanced_btn_row.addWidget(self.os_detect_btn)

        self.honeypot_btn = QPushButton("🍯 Honeypot Check")
        self.honeypot_btn.setToolTip(
            "Probe the port range set above (defaults to 1-100) for classic honeypot behavior"
        )
        self.honeypot_btn.clicked.connect(self._run_honeypot_detection)
        advanced_btn_row.addWidget(self.honeypot_btn)

        self.firewall_btn = QPushButton("🛡️ Firewall Detection")
        self.firewall_btn.setToolTip(
            "Use ACK (-sA) on the port range set above (defaults to 1-100) to detect filtering; "
            "administrator/root privileges are typically required"
        )
        self.firewall_btn.clicked.connect(self._run_firewall_detection)
        advanced_btn_row.addWidget(self.firewall_btn)

        self.traceroute_btn = QPushButton("📡 Traceroute")
        self.traceroute_btn.setToolTip("Map network hops; administrator/root privileges may be required depending on platform")
        self.traceroute_btn.clicked.connect(self._run_traceroute)
        advanced_btn_row.addWidget(self.traceroute_btn)

        advanced_btn_row.addStretch()
        advanced_layout.addLayout(advanced_btn_row)

        self.advanced_output = QTextEdit()
        self.advanced_output.setReadOnly(True)
        self.advanced_output.setFont(QFont("Consolas", 9))
        self.advanced_output.setPlaceholderText(
            "Results from OS detection, honeypot checks, firewall detection, "
            "and traceroute will appear here…"
        )
        advanced_layout.addWidget(self.advanced_output)

        results_tabs.addTab(advanced_widget, "🔬 Advanced Tools")

        # ── Tab 5: Scan Details ───────────────────────────────────────────────
        details_widget = QWidget()
        details_layout = QVBoxLayout(details_widget)
        details_label = QLabel("ℹ️ SCAN DETAILS & STATISTICS")
        details_label.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        details_label.setStyleSheet("color: #00d4ff; letter-spacing: 1px;")
        details_layout.addWidget(details_label)
        self.details_output = QTextEdit()
        self.details_output.setReadOnly(True)
        self.details_output.setFont(QFont("Consolas", 9))
        self.details_output.setPlaceholderText("Detailed scan information will appear here...")
        details_layout.addWidget(self.details_output)
        results_tabs.addTab(details_widget, "ℹ️ Details")

        main_layout.addWidget(results_tabs, stretch=1)
        
        # Set default profile from settings
        default_profile = self.settings.get("default_profile", "Quick Scan (Top 100 Ports)")
        # Try to find exact match or partial match
        for i in range(self.profile_combo.count()):
            if default_profile in self.profile_combo.itemText(i):
                self.profile_combo.setCurrentIndex(i)
                break
    
    def _init_components(self):
        """Initialize scanner and AI components."""
        try:
            # Initialize advanced scanner
            nmap_path = self.settings.get("nmap_path") or None
            self.scanner = AdvancedScanner(nmap_path=nmap_path)
            
        except (FileNotFoundError, Exception) as e:
            error_msg = str(e)
            QMessageBox.critical(
                self, 
                "Nmap Not Found", 
                error_msg,
                QMessageBox.StandardButton.Ok
            )
            self.scan_btn.setEnabled(False)
            self.status_label.setText("⚠️ Nmap not found - scanning disabled")
            self.status_label.setStyleSheet(
                "color: #ff4757; padding: 8px; "
                "background-color: rgba(255, 71, 87, 0.15); "
                "border-left: 4px solid #ff4757; "
                "border-radius: 4px; font-weight: bold; font-size: 10pt;"
            )
            # Continue to initialize Ollama even if nmap fails
            self.scanner = None
        
        try:
            # Initialize Ollama client
            ollama_host = self.settings.get("ollama_host", "localhost")
            ollama_port = self.settings.get("ollama_port", 11434)
            self.ollama_client = OllamaClient(host=ollama_host, port=ollama_port)
            
            # Check if Ollama is available
            if self.ollama_client.is_available():
                self._refresh_models()
                
                # Initialize analyzer
                default_model = self.settings.get("default_model", "llama3")
                self.analyzer = ScanAnalyzer(self.ollama_client, model=default_model)
            else:
                self.status_label.setText(
                    "⚠️ Ollama is not running. AI analysis will be unavailable. "
                    "Start Ollama with: ollama serve"
                )
                self.status_label.setStyleSheet("color: #d63031; padding: 5px;")
        
        except Exception as e:
            QMessageBox.warning(
                self,
                "Ollama Connection Issue",
                f"Could not connect to Ollama:\n{str(e)}\n\n"
                "Scans will work but AI analysis will be unavailable."
            )
    
    def _update_scan_button_state(self):
        """Enable/disable scan button based on authorization checkbox."""
        self.scan_btn.setEnabled(self.auth_checkbox.isChecked())

    def _on_full_detail_changed(self, state):
        """Persist the Full Detail checkbox choice to settings."""
        self.settings["full_detail_mode"] = bool(state)
        SettingsDialog.save_settings_to_file(self.settings)
    
    def _refresh_models(self):
        """Refresh the list of available Ollama models."""
        if not self.ollama_client:
            return
        
        try:
            models = self.ollama_client.list_models()
            current_text = self.model_combo.currentText()
            
            self.model_combo.clear()
            if models:
                self.model_combo.addItems(models)
                
                # Try to restore previous selection
                index = self.model_combo.findText(current_text)
                if index >= 0:
                    self.model_combo.setCurrentIndex(index)
                else:
                    # Try to set default
                    default_model = self.settings.get("default_model", "llama3")
                    index = self.model_combo.findText(default_model, Qt.MatchFlag.MatchContains)
                    if index >= 0:
                        self.model_combo.setCurrentIndex(index)
            else:
                self.model_combo.addItem("No models found")
                QMessageBox.information(
                    self,
                    "No Models",
                    "No Ollama models found.\n\n"
                    "Pull a model with: ollama pull llama3"
                )
        
        except ConnectionError as e:
            QMessageBox.warning(self, "Connection Error", str(e))
    
    def _start_scan(self):
        """Start a port scan in background thread."""
        # ── Resolve target ────────────────────────────────────────────────────
        target_ip     = self.target_input.text().strip()
        domain_input  = self.domain_input.text().strip()

        # Target IP takes priority; fall back to domain/CIDR field
        target = target_ip or domain_input
        if not target:
            QMessageBox.warning(
                self, "No Target",
                "Please enter a Target IP or Domain / CIDR range."
            )
            return

        # ── Resolve custom port range ─────────────────────────────────────────
        sp_text = self.start_port_input.text().strip()
        ep_text = self.end_port_input.text().strip()
        custom_ports = ""

        if sp_text or ep_text:
            # Validate
            try:
                sp = int(sp_text) if sp_text else 1
                ep = int(ep_text) if ep_text else 65535
                if not (1 <= sp <= 65535) or not (1 <= ep <= 65535):
                    raise ValueError
                if sp > ep:
                    sp, ep = ep, sp   # swap silently
                custom_ports = f"{sp}-{ep}"
            except ValueError:
                QMessageBox.warning(
                    self, "Invalid Port Range",
                    "Start and End ports must be integers between 1 and 65535."
                )
                return

        if not self.auth_checkbox.isChecked():
            QMessageBox.warning(
                self,
                "Authorization Required",
                "You must confirm you have authorization to scan this target."
            )
            return

        # Clear previous results
        self.current_scan_results  = None
        self.current_ai_analysis   = None
        self.current_anomaly_report = None
        self.results_table.setRowCount(0)
        self.ai_output.clear()
        self.anomaly_output.clear()
        self.details_output.clear()
        self.live_console.clear()
        self.current_port_label.setText("Currently scanning: —")
        self._live_port_count = 0

        # Update UI state
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # indeterminate

        # Get selected profile and model
        profile_name = self.profile_combo.currentText()
        model_name   = self.model_combo.currentText()

        if self.analyzer:
            self.analyzer.model = model_name

        # Create and start worker thread
        self.scan_worker = ScanWorker(
            scanner=self.scanner,
            analyzer=self.analyzer,
            target=target,
            profile_name=profile_name,
            custom_ports=custom_ports,
            full_detail=self.full_detail_checkbox.isChecked(),
        )

        # Reset live console state
        self.live_console.clear()
        self.current_port_label.setText("Currently scanning: —")
        self._live_port_count = 0
        self.live_port_counter.setText("Ports found: 0")
        self.results_tabs_ref.setCurrentIndex(0)   # switch to Live Console

        # Connect signals
        self.scan_worker.scan_started.connect(self._on_scan_started)
        self.scan_worker.scan_progress.connect(self._on_scan_progress)
        self.scan_worker.scan_progress_pct.connect(self._on_scan_progress_pct)
        self.scan_worker.scan_line.connect(self._on_scan_line)
        self.scan_worker.port_found.connect(self._on_port_found_live)
        self.scan_worker.scan_completed.connect(self._on_scan_completed)
        self.scan_worker.scan_error.connect(self._on_scan_error)
        self.scan_worker.analysis_started.connect(self._on_analysis_started)
        self.scan_worker.analysis_token.connect(self._on_analysis_token)
        self.scan_worker.analysis_completed.connect(self._on_analysis_completed)
        self.scan_worker.analysis_error.connect(self._on_analysis_error)
        self.scan_worker.finished.connect(self._on_worker_finished)

        # Start the scan
        self.scan_worker.start()
    
    def _stop_scan(self):
        """Stop the current scan."""
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.stop()
            self.status_label.setText("Stopping scan...")

    # ── Advanced recon tools (OS detect / honeypot / firewall / traceroute) ──

    def _get_advanced_tool_target(self) -> Optional[str]:
        """Shared target + authorization validation for the advanced tool buttons."""
        target = self.target_input.text().strip() or self.domain_input.text().strip()
        if not target:
            QMessageBox.warning(
                self, "No Target",
                "Please enter a Target IP or Domain / CIDR range."
            )
            return None
        if not self.auth_checkbox.isChecked():
            QMessageBox.warning(
                self, "Authorization Required",
                "You must confirm you have authorization to scan this target."
            )
            return None
        if not self.scanner:
            QMessageBox.warning(
                self, "Nmap Unavailable",
                "These tools require Nmap. Configure the Nmap path in Settings."
            )
            return None
        return target

    def _get_advanced_tool_port_range(self) -> str:
        """Read the shared Start/End Port fields for advanced port-based tools."""
        sp_text = self.start_port_input.text().strip()
        ep_text = self.end_port_input.text().strip()

        # Preserve the advanced-tool default when both fields are blank.
        if not sp_text and not ep_text:
            return "1-100"

        try:
            sp = int(sp_text) if sp_text else 1
            ep = int(ep_text) if ep_text else 65535
            if not (1 <= sp <= 65535) or not (1 <= ep <= 65535):
                raise ValueError
            if sp > ep:
                sp, ep = ep, sp
            return f"{sp}-{ep}"
        except ValueError:
            QMessageBox.warning(
                self, "Invalid Port Range",
                "Start and End ports must be integers between 1 and 65535."
            )
            return ""

    def _set_advanced_buttons_enabled(self, enabled: bool):
        self.os_detect_btn.setEnabled(enabled)
        self.honeypot_btn.setEnabled(enabled)
        self.firewall_btn.setEnabled(enabled)
        self.traceroute_btn.setEnabled(enabled)

    def _launch_advanced_tool(self, tool_name: str, func: Callable, target: str, **kwargs):
        self._set_advanced_buttons_enabled(False)
        self.advanced_output.append(f"\n[{tool_name}] Running against {target}…")
        privilege_notes = {
            "OS Detection": "⚠ OS detection (-O) commonly requires administrator/root privileges; results may be unavailable or degraded without them.",
            "Firewall Detection": "⚠ ACK scanning (-sA) commonly requires administrator/root privileges; results may be unavailable or degraded without them.",
            "Traceroute": "⚠ Traceroute may require administrator/root privileges depending on the Nmap probe method and platform.",
        }
        note = privilege_notes.get(tool_name)
        if note:
            self.advanced_output.append(note)
        self.results_tabs_ref.setCurrentIndex(4)   # switch to Advanced Tools tab

        self._advanced_worker = AdvancedToolWorker(tool_name, func, target, **kwargs)
        self._advanced_worker.result_ready.connect(self._on_advanced_result)
        self._advanced_worker.tool_error.connect(self._on_advanced_error)
        self._advanced_worker.finished.connect(lambda: self._set_advanced_buttons_enabled(True))
        self._advanced_worker.start()

    def _run_os_detection(self):
        target = self._get_advanced_tool_target()
        if target:
            self._launch_advanced_tool("OS Detection", self.scanner.detect_os, target, aggressive=True)

    def _run_honeypot_detection(self):
        target = self._get_advanced_tool_target()
        if target:
            port_range = self._get_advanced_tool_port_range()
            if port_range:
                self._launch_advanced_tool(
                    "Honeypot Check", self.scanner.detect_honeypot, target, port_range=port_range
                )

    def _run_firewall_detection(self):
        target = self._get_advanced_tool_target()
        if target:
            port_range = self._get_advanced_tool_port_range()
            if port_range:
                self._launch_advanced_tool(
                    "Firewall Detection", self.scanner.firewall_detect, target, port_range=port_range
                )

    def _run_traceroute(self):
        target = self._get_advanced_tool_target()
        if target:
            self._launch_advanced_tool("Traceroute", self.scanner.traceroute, target)

    def _on_advanced_result(self, tool_name: str, result):
        """Format and display the result of an advanced tool run."""
        lines = [f"\n[{tool_name}] Complete."]

        if tool_name == "OS Detection":
            matches = result.get("os_matches", []) if isinstance(result, dict) else []
            if matches:
                for m in matches:
                    lines.append(f"  {m['name']}  (accuracy: {m['accuracy']}%, {m['type']})")
            else:
                lines.append("  No confident OS match — target may be filtering probes.")

        elif tool_name == "Honeypot Check":
            lines.append(f"  Confidence: {result.get('confidence', 'unknown').upper()}")
            for b in result.get("suspicious_behaviors", []):
                lines.append(f"  ⚠ {b}")
            if not result.get("suspicious_behaviors"):
                lines.append("  No honeypot indicators detected in the selected port range.")
            if "error" in result:
                lines.append(f"  Error: {result['error']}")

        elif tool_name == "Firewall Detection":
            lines.append(f"  Firewall detected : {result.get('firewall_detected', False)}")
            lines.append(f"  Unfiltered ports  : {result.get('unfiltered_ports', 0)}")
            lines.append(f"  Filtered ports    : {result.get('filtered_ports', 0)}")
            lines.append("  Note: ACK (-sA) scanning cannot confirm ports are open; unfiltered means the probes were not filtered.")
            for ind in result.get("indicators", []):
                lines.append(f"  ⚠ {ind}")

        elif tool_name == "Traceroute":
            hops = result if isinstance(result, list) else []
            if hops:
                for hop in hops:
                    lines.append(
                        f"  Hop {hop['hop']:>2}: {hop['ip']}  "
                        f"({hop['hostname']})  rtt={hop['rtt']}"
                    )
            else:
                lines.append("  No hops recorded — traceroute may need root/admin privileges.")

        self.advanced_output.append("\n".join(lines))
        sb = self.advanced_output.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _on_advanced_error(self, tool_name: str, error_message: str):
        self.advanced_output.append(f"\n[{tool_name}] ✗ Failed: {error_message}")
        sb = self.advanced_output.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _on_scan_started(self):
        """Handle scan started signal."""
        self.status_label.setText("Scan in progress...")

    def _on_scan_progress(self, message: str):
        """Handle scan progress updates."""
        self.status_label.setText(message)

    def _on_scan_progress_pct(self, pct: float, message: str):
        """Handle percentage progress updates."""
        if pct > 0:
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(int(pct))
        else:
            self.progress_bar.setRange(0, 0)  # indeterminate

    def _on_scan_line(self, line: str):
        """Stream scan output line to live console with colour coding."""
        # Throttle: cap the console at 4 000 lines so a full 65 535-port
        # socket scan doesn't lock the UI.  The progress bar and status label
        # still update normally — only the visible text is trimmed.
        if self.live_console.document().blockCount() > 4000:
            # Drop this line silently; progress updates still come via
            # scan_progress signal so the user sees percent/count moving.
            return

        if "Discovered open port" in line:
            line_html = (f'<span style="color:#2ed573;font-weight:bold;">{line}</span>')
        elif "/tcp" in line or "/udp" in line:
            if " open " in line or line.strip().startswith("Discovered"):
                line_html = f'<span style="color:#2ed573;">{line}</span>'
            elif "filtered" in line:
                line_html = f'<span style="color:#ffa502;">{line}</span>'
            elif "closed" in line:
                line_html = f'<span style="color:#ff4757;">{line}</span>'
            else:
                line_html = f'<span style="color:#747d8c;">{line}</span>'
        elif "%" in line or "Socket scan" in line or "socket-scan" in line:
            line_html = f'<span style="color:#00d4ff;">{line}</span>'
        elif "Starting Nmap" in line or "Nmap done" in line:
            line_html = f'<span style="color:#a29bfe;font-weight:bold;">{line}</span>'
        elif "ERROR" in line.upper() or "FAILED" in line.upper():
            line_html = f'<span style="color:#ff4757;">{line}</span>'
        else:
            line_html = f'<span style="color:#8899aa;">{line}</span>'

        self.live_console.append(line_html)
        # Auto-scroll to bottom
        sb = self.live_console.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _on_port_found_live(self, port_dict: dict):
        """Handle a port result discovered during live scan."""
        self._live_port_count += 1
        port  = port_dict.get("port", "")
        proto = port_dict.get("proto", "tcp").upper()
        state = port_dict.get("state", "")
        svc   = port_dict.get("service", "")

        # Update "currently scanning" label (show all states)
        svc_str = f"  ({svc})" if svc else ""
        self.current_port_label.setText(
            f"Last probed: {port}/{proto}{svc_str}  [{state.upper()}]"
        )
        self.live_port_counter.setText(f"Ports probed: {self._live_port_count}")
    
    def _on_scan_completed(self, results: dict):
        """Handle scan completion."""
        self.current_scan_results = results
        self._populate_results_table(results)
        self._populate_details_panel(results)
        self._run_anomaly_detection(results)

        # Build a meaningful status summary
        hosts        = results.get("hosts", {})
        total_open   = 0
        total_closed = 0
        total_filt   = 0
        total_ports  = 0
        for h_info in hosts.values():
            for p_dict in h_info.get("protocols", {}).values():
                total_ports  += len(p_dict)
                total_open   += sum(1 for d in p_dict.values() if d.get("state") == "open")
                total_closed += sum(1 for d in p_dict.values() if d.get("state") == "closed")
                total_filt   += sum(1 for d in p_dict.values() if d.get("state") == "filtered")

        host_list = ", ".join(hosts.keys()) if hosts else "no hosts"
        profile   = self.profile_combo.currentText()
        scan_info = results.get("scan_info", {})
        stopped = bool(scan_info.get("stopped", False))
        scanned = scan_info.get("ports_scanned")
        expected = scan_info.get("total_ports_expected")
        progress_text = (
            f"  |  STOPPED EARLY ({scanned}/{expected} ports)"
            if stopped and scanned is not None and expected is not None
            else "  |  COMPLETED"
        )
        self.status_label.setText(
            f"Scan done  |  Profile: {profile}  |  Host(s): {host_list}  |  "
            f"Open: {total_open}  Closed: {total_closed}  Filtered: {total_filt}  "
            f"Total: {total_ports}{progress_text}"
        )
        self.status_label.setStyleSheet(
            "color: #2ed573; padding: 8px; "
            "background-color: rgba(46, 213, 115, 0.1); "
            "border-left: 4px solid #2ed573; "
            "border-radius: 4px; font-weight: bold; font-size: 10pt;"
        )
    
    def _on_scan_error(self, error_message: str):
        """Handle scan error."""
        self.progress_bar.setVisible(False)
        self.status_label.setText("Scan failed")
        QMessageBox.critical(self, "Scan Error", f"Scan failed:\n\n{error_message}")
    
    def _on_analysis_started(self):
        """Handle analysis started signal — clear output and switch to AI tab."""
        self.ai_output.clear()
        self.ai_output.setPlaceholderText("⏳ Streaming AI analysis — tokens appear here as they arrive…")
        # Switch to AI tab so the user can watch it stream in real time
        self.results_tabs_ref.setCurrentIndex(2)
        self._ai_streaming_started = False   # first token will clear placeholder

    def _on_analysis_token(self, token: str):
        """Append a single streamed token to the AI output in real time."""
        from PyQt6.QtGui import QTextCursor
        cursor = self.ai_output.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.ai_output.setTextCursor(cursor)
        self.ai_output.insertPlainText(token)
        # Keep scrolled to bottom
        sb = self.ai_output.verticalScrollBar()
        sb.setValue(sb.maximum())
    
    def _on_analysis_completed(self, analysis: str):
        """Handle analysis completion."""
        self.current_ai_analysis = analysis
        self.ai_output.setPlainText(analysis)
        self.status_label.setText("Scan and analysis completed successfully")
    
    def _on_analysis_error(self, error_message: str):
        """Handle analysis error."""
        self.ai_output.setPlainText(
            f"⚠️ AI Analysis Failed\n\n{error_message}\n\n"
            "Scan results are still available above."
        )
        self.status_label.setText("Scan completed (AI analysis failed)")
    
    def _on_worker_finished(self):
        """Handle worker thread completion."""
        self.progress_bar.setVisible(False)
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.current_port_label.setText("Scan complete")
    
    def _run_anomaly_detection(self, scan_results: dict):
        """Run anomaly detection on scan results."""
        try:
            anomalies = AnomalyDetector.analyze_scan_results(scan_results)
            self.current_anomaly_report = anomalies
            
            # Format and display report
            report = AnomalyDetector.format_anomaly_report(anomalies)
            self.anomaly_output.setPlainText(report)
            
            # Set color based on risk level with dark theme
            risk_level = anomalies.get("risk_level", "LOW")
            if risk_level == "CRITICAL":
                self.anomaly_output.setStyleSheet(
                    "QTextEdit { "
                    "border-left: 4px solid #ff4757; "
                    "background-color: rgba(255, 71, 87, 0.1); "
                    "}"
                )
            elif risk_level == "HIGH":
                self.anomaly_output.setStyleSheet(
                    "QTextEdit { "
                    "border-left: 4px solid #ffa502; "
                    "background-color: rgba(255, 165, 2, 0.1); "
                    "}"
                )
            elif risk_level == "MEDIUM":
                self.anomaly_output.setStyleSheet(
                    "QTextEdit { "
                    "border-left: 4px solid #ffdd59; "
                    "background-color: rgba(255, 221, 89, 0.1); "
                    "}"
                )
            else:
                self.anomaly_output.setStyleSheet(
                    "QTextEdit { "
                    "border-left: 4px solid #2ed573; "
                    "background-color: rgba(46, 213, 115, 0.1); "
                    "}"
                )
        
        except Exception as e:
            self.anomaly_output.setPlainText(f"⚠️ Anomaly detection error:\n\n{str(e)}")
    
    def _populate_details_panel(self, results: dict):
        """Populate the details panel with scan information."""
        lines = []

        lines.append("=" * 80)
        lines.append("  SCAN DETAILS & STATISTICS")
        lines.append("=" * 80)
        lines.append("")

        # ── Command ──────────────────────────────────────────────────────────
        lines.append(f"Command  : {results.get('command', 'N/A')}")
        lines.append("")

        # ── Scan method info ─────────────────────────────────────────────────
        # NOTE: scan_info also carries top-level scalar keys such as
        # "elapsed" and "total_ports_expected" alongside per-protocol dicts
        # like "tcp": {"method": ...}. Those scalars are handled separately
        # below and must be skipped in this loop, or they'd be printed as
        # if they were bogus protocols (e.g. "Protocol: ELAPSED").
        scan_info = results.get("scan_info", {})
        if scan_info:
            lines.append("Scan Method:")
            method_shown = False
            for proto, info in scan_info.items():
                if not isinstance(info, dict):
                    continue
                method = info.get("method", "unknown")
                lines.append(f"  Protocol : {proto.upper()}")
                lines.append(f"  Method   : {method}")
                method_shown = True
            if scan_info.get("elapsed"):
                lines.append(f"  Elapsed  : {scan_info['elapsed']}")
            if scan_info.get("total_ports_expected"):
                expected = scan_info["total_ports_expected"]
                scanned = scan_info.get("ports_scanned")
                if scan_info.get("stopped") and scanned is not None:
                    lines.append(f"  Ports    : {scanned}/{expected} ports scanned (STOPPED EARLY)")
                else:
                    lines.append(f"  Ports    : {expected} ports probed")
            if scan_info.get("stopped"):
                lines.append("  Status   : STOPPED EARLY — scan did not complete")
            if not method_shown:
                lines.append("  (scan method unavailable)")
            lines.append("")

        # ── Per-host breakdown ────────────────────────────────────────────────
        hosts = results.get("hosts", {})
        all_open     = []
        all_closed   = []
        all_filtered = []
        services_set = set()

        for host, host_info in hosts.items():
            hostnames = [h for h in host_info.get("hostnames", []) if h]
            host_label = host
            if hostnames:
                host_label += f"  ({', '.join(hostnames)})"

            lines.append(f"Host : {host_label}")
            lines.append(f"  State : {host_info.get('state', 'unknown').upper()}")
            lines.append("")

            for proto, ports in host_info.get("protocols", {}).items():
                open_p     = sorted([p for p, d in ports.items() if d.get("state") == "open"])
                closed_p   = sorted([p for p, d in ports.items() if d.get("state") == "closed"])
                filtered_p = sorted([p for p, d in ports.items() if d.get("state") == "filtered"])

                all_open     += open_p
                all_closed   += closed_p
                all_filtered += filtered_p

                lines.append(f"  Protocol : {proto.upper()}")
                lines.append(f"  Open     : {len(open_p)} port(s)  {_fmt_ports(open_p)}")
                lines.append(f"  Closed   : {len(closed_p)} port(s)  {_fmt_ports(closed_p)}")
                lines.append(f"  Filtered : {len(filtered_p)} port(s)  {_fmt_ports(filtered_p)}")
                lines.append("")

                # Open port detail
                if open_p:
                    lines.append(f"  Open Port Details ({proto.upper()}):")
                    lines.append(f"  {'PORT':<8}{'SERVICE':<20}{'PRODUCT':<22}{'VERSION':<15}EXTRA")
                    lines.append(f"  {'-'*8}{'-'*20}{'-'*22}{'-'*15}{'-'*20}")
                    for port in open_p:
                        d = ports[port]
                        svc     = d.get("name",     "")[:18]
                        product = d.get("product",  "")[:20]
                        ver     = d.get("version",  "")[:13]
                        extra   = d.get("extrainfo","")[:20]
                        lines.append(f"  {str(port):<8}{svc:<20}{product:<22}{ver:<15}{extra}")
                    lines.append("")

                for port, d in ports.items():
                    svc = d.get("name", "")
                    if svc:
                        services_set.add(svc)

        # ── Summary ───────────────────────────────────────────────────────────
        lines.append("=" * 80)
        lines.append("  SUMMARY")
        lines.append("=" * 80)
        lines.append(f"  Total hosts   : {len(hosts)}")
        lines.append(f"  Open ports    : {len(all_open)}")
        lines.append(f"  Closed ports  : {len(all_closed)}")
        lines.append(f"  Filtered ports: {len(all_filtered)}")
        lines.append(f"  Services found: {len(services_set)}")
        if services_set:
            lines.append("")
            lines.append("  Discovered services:")
            for svc in sorted(services_set):
                lines.append(f"    - {svc}")
        lines.append("")
        lines.append("=" * 80)

        self.details_output.setPlainText("\n".join(lines))
    
    def _populate_results_table(self, results: dict):
        """Populate the results table with scan data."""
        self.results_table.setRowCount(0)

        hosts = results.get("hosts", {})
        if not hosts:
            self.status_label.setText("Scan completed - no hosts discovered")
            return

        row         = 0
        open_count  = 0
        closed_count    = 0
        filtered_count  = 0

        for host, host_info in hosts.items():
            protocols = host_info.get("protocols", {})

            for proto, ports in protocols.items():
                for port, port_info in sorted(ports.items()):
                    state = port_info.get("state", "unknown")

                    self.results_table.insertRow(row)

                    # Host
                    host_item = QTableWidgetItem(host)
                    host_item.setFont(QFont("Arial", 9, QFont.Weight.Bold))
                    host_item.setForeground(QColor("#00d4ff"))
                    self.results_table.setItem(row, 0, host_item)

                    # Port — numeric sort key stored as UserRole int
                    port_item = QTableWidgetItem(str(port))
                    port_item.setData(Qt.ItemDataRole.UserRole, int(port))
                    port_item.setFont(QFont("Courier New", 9, QFont.Weight.Bold))
                    port_item.setForeground(QColor("#ffffff"))
                    self.results_table.setItem(row, 1, port_item)

                    # Protocol
                    self.results_table.setItem(row, 2, QTableWidgetItem(proto.upper()))

                    # State with visual indicator
                    if state == "open":
                        state_symbol = "●"
                        state_color  = QColor("#2ed573")   # green
                        open_count  += 1
                    elif state == "closed":
                        state_symbol = "○"
                        state_color  = QColor("#ff4757")   # red
                        closed_count += 1
                    elif state == "filtered":
                        state_symbol = "◑"
                        state_color  = QColor("#ffa502")   # orange
                        filtered_count += 1
                    else:
                        state_symbol = "?"
                        state_color  = QColor("#747d8c")   # grey

                    state_item = QTableWidgetItem(f"{state_symbol} {state.upper()}")
                    state_item.setFont(QFont("Arial", 9, QFont.Weight.Bold))
                    state_item.setForeground(state_color)
                    self.results_table.setItem(row, 3, state_item)

                    # Service name — always populated from OS well-known-ports
                    # lookup or nmap; shows for all states
                    svc = port_info.get("name", "")
                    service_item = QTableWidgetItem(svc)
                    if svc:
                        service_item.setForeground(QColor("#00d4ff"))
                    self.results_table.setItem(row, 4, service_item)

                    # Product / Version / Extra — only meaningful for open ports
                    if state == "open":
                        product  = port_info.get("product",   "")
                        version  = port_info.get("version",   "")
                        extra    = port_info.get("extrainfo", "")
                    else:
                        product  = "—"
                        version  = "—"
                        extra    = ""

                    product_item = QTableWidgetItem(product)
                    if product and product != "—":
                        product_item.setForeground(QColor("#70a1ff"))
                    else:
                        product_item.setForeground(QColor("#444c5e"))
                    self.results_table.setItem(row, 5, product_item)

                    version_item = QTableWidgetItem(version)
                    if version and version != "—":
                        version_item.setForeground(QColor("#a29bfe"))
                    else:
                        version_item.setForeground(QColor("#444c5e"))
                    self.results_table.setItem(row, 6, version_item)

                    self.results_table.setItem(row, 7, QTableWidgetItem(extra))

                    row += 1

        # Resize columns to content
        self.results_table.resizeColumnsToContents()

        total_ports = row
        self.status_label.setText(
            f"✅ Scan completed — {total_ports} ports  "
            f"({open_count} open  |  {closed_count} closed  |  {filtered_count} filtered)  "
            f"on {len(hosts)} host(s)"
        )
        self.status_label.setStyleSheet(
            "color: #2ed573; padding: 8px; "
            "background-color: rgba(46, 213, 115, 0.15); "
            "border-left: 4px solid #2ed573; "
            "border-radius: 4px; font-weight: bold; font-size: 10pt;"
        )
    
    def _export_csv(self):
        """Export scan results, statistics, anomalies, and AI analysis as CSV."""
        if not self.current_scan_results:
            QMessageBox.information(self, "No Results", "No scan results to export.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export CSV",
            f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            "CSV Files (*.csv)"
        )
        if not file_path:
            return

        try:
            report = ReportGenerator.generate_csv_report(
                scan_results=self.current_scan_results,
                ai_analysis=self.current_ai_analysis,
                anomaly_data=self.current_anomaly_report,
                target=self.target_input.text(),
                profile=self.profile_combo.currentText()
            )
            with open(file_path, "w", newline="", encoding="utf-8") as f:
                f.write(report)
            QMessageBox.information(self, "Exported", f"CSV saved to:\n{file_path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export CSV:\n{e}")

    def _export_json(self):
        """Export scan results to JSON file."""
        if not self.current_scan_results:
            QMessageBox.information(self, "No Results", "No scan results to export.")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Scan Results",
            f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            "JSON Files (*.json)"
        )
        
        if file_path:
            try:
                report = ReportGenerator.generate_json_report(
                    scan_results=self.current_scan_results,
                    ai_analysis=self.current_ai_analysis,
                    anomaly_data=self.current_anomaly_report,
                    target=self.target_input.text(),
                    profile=self.profile_combo.currentText()
                )
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(report)
                QMessageBox.information(self, "Success", f"Results exported to:\n{file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export results:\n{str(e)}")
    
    def _export_report(self):
        """Export scan results and AI analysis to a formatted text report."""
        if not self.current_scan_results:
            QMessageBox.information(self, "No Results", "No scan results to export.")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Text Report",
            f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "Text Files (*.txt);;All Files (*)"
        )
        
        if file_path:
            try:
                report = ReportGenerator.generate_text_report(
                    scan_results=self.current_scan_results,
                    ai_analysis=self.current_ai_analysis,
                    target=self.target_input.text(),
                    profile=self.profile_combo.currentText()
                )
                
                # Append anomaly report
                if self.current_anomaly_report:
                    report += "\n\n"
                    report += AnomalyDetector.format_anomaly_report(self.current_anomaly_report)
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(report)
                
                QMessageBox.information(self, "Success", f"Text report exported to:\n{file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export report:\n{str(e)}")
    
    def _export_html(self):
        """Export scan results and AI analysis to an HTML report."""
        if not self.current_scan_results:
            QMessageBox.information(self, "No Results", "No scan results to export.")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export HTML Report",
            f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
            "HTML Files (*.html);;All Files (*)"
        )
        
        if file_path:
            try:
                report = ReportGenerator.generate_html_report(
                    scan_results=self.current_scan_results,
                    ai_analysis=self.current_ai_analysis,
                    target=self.target_input.text(),
                    profile=self.profile_combo.currentText(),
                    anomaly_data=self.current_anomaly_report
                )
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(report)
                
                QMessageBox.information(
                    self, 
                    "Success", 
                    f"HTML report exported to:\n{file_path}\n\nOpen in your browser to view."
                )
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export HTML report:\n{str(e)}")
    
    def _export_pdf(self):
        """Export the current scan as a PDF report."""
        if not self.current_scan_results:
            QMessageBox.information(self, "No Results", "No scan results to export.")
            return
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export PDF Report",
            f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            "PDF Files (*.pdf);;All Files (*)")
        if file_path:
            try:
                data = ReportGenerator.generate_pdf_report(
                    scan_results=self.current_scan_results,
                    ai_analysis=self.current_ai_analysis,
                    anomaly_data=self.current_anomaly_report,
                    target=self.target_input.text(),
                    profile=self.profile_combo.currentText())
                with open(file_path, "wb") as f:
                    f.write(data)
                QMessageBox.information(self, "Success", f"PDF report exported to:\n{file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export PDF report:\n{str(e)}")

    def _export_docx(self):
        """Export the current scan as a DOCX report."""
        if not self.current_scan_results:
            QMessageBox.information(self, "No Results", "No scan results to export.")
            return
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export DOCX Report",
            f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.docx",
            "Word Documents (*.docx);;All Files (*)")
        if file_path:
            try:
                ReportGenerator.generate_docx_report(
                    output_path=file_path,
                    scan_results=self.current_scan_results,
                    ai_analysis=self.current_ai_analysis,
                    anomaly_data=self.current_anomaly_report,
                    target=self.target_input.text(),
                    profile=self.profile_combo.currentText())
                QMessageBox.information(self, "Success", f"DOCX report exported to:\n{file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export DOCX report:\n{str(e)}")

    def _open_settings(self):
        """Open the settings dialog."""
        dialog = SettingsDialog(self)
        if dialog.exec():
            # Settings were saved, reload them
            self.settings = SettingsDialog.load_settings()
            
            # Reinitialize components with new settings
            self._init_components()
            
            QMessageBox.information(
                self,
                "Settings Applied",
                "Settings have been applied. Some changes may require restarting the application."
            )


################################################################################
# SECTION: main  (from main.py)
################################################################################

#!/usr/bin/env python3
"""
AI Port Scanner - Main entry point
A desktop GUI application combining nmap scanning with local LLM analysis.
"""



def main():
    """Application entry point."""
    app = QApplication(sys.argv)
    app.setApplicationName("AI Port Scanner")
    app.setOrganizationName("Security Tools")
    
    # Set application style
    app.setStyle("Fusion")
    
    # Create and show main window
    window = MainWindow()
    window.show()
    
    # Start event loop
    sys.exit(app.exec())


if __name__ == "__main__":
    main()