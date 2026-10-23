"""OSINT data-source tools used by the AI agent.

Every tool returns a JSON-serialisable dict with a ``tool`` key and either
``success: True`` plus data, ``success: False`` plus ``info`` (nothing found),
or ``error`` (the lookup failed). Tools never raise.

API keys are passed in explicitly via :class:`ApiKeys` so that concurrent
users of a shared deployment never see or use each other's keys.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import logging
import os
import re
import socket
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from itertools import zip_longest
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

import requests
import shodan

logger = logging.getLogger(__name__)

HTTP_TIMEOUT = 20
USER_AGENT = "AI-OSINT-Security-Analyzer/2.0 (+https://github.com/MRFrazer25/AI-OSINT-Security-Analyzer)"
MAX_TARGET_LENGTH = 253

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
INTERNETDB_URL = "https://internetdb.shodan.io"
CVEDB_URL = "https://cvedb.shodan.io/cve"
GREYNOISE_COMMUNITY_URL = "https://api.greynoise.io/v3/community"
SPAMHAUS_DROP_URLS = {4: "https://www.spamhaus.org/drop/drop_v4.json", 6: "https://www.spamhaus.org/drop/drop_v6.json"}
CRTSH_URL = "https://crt.sh/"
SANS_ISC_URL = "https://isc.sans.edu/api/ip"
EXPLOITDB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"
# IANA's official lists of which regional internet registry serves each address block over RDAP.
RDAP_BOOTSTRAP_URLS = {4: "https://data.iana.org/rdap/ipv4.json", 6: "https://data.iana.org/rdap/ipv6.json"}
VT_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Where users get each API key (single source of truth for the UI, docs and error messages).
KEY_SIGNUP_URLS = {
    "cohere": "https://dashboard.cohere.com/api-keys",
    "shodan": "https://account.shodan.io/",
    "virustotal": "https://www.virustotal.com/gui/join-us",
    "abuseipdb": "https://www.abuseipdb.com/register",
    "nvd": "https://nvd.nist.gov/developers/request-an-api-key",
    "greynoise": "https://viz.greynoise.io/signup",
}

@dataclass(frozen=True)
class ApiKeys:
    """API keys for a single analysis run. Never stored in module globals."""

    cohere: str = ""
    shodan: str = ""
    virustotal: str = ""
    abuseipdb: str = ""
    nvd: str = ""
    greynoise: str = ""

    @classmethod
    def from_env(cls) -> "ApiKeys":
        return cls(
            cohere=os.getenv("COHERE_API_KEY", ""),
            shodan=os.getenv("SHODAN_API_KEY", ""),
            virustotal=os.getenv("VIRUSTOTAL_API_KEY", "") or os.getenv("VT_API_KEY", ""),
            abuseipdb=os.getenv("ABUSEIPDB_API_KEY", ""),
            nvd=os.getenv("NVD_API_KEY", ""),
            greynoise=os.getenv("GREYNOISE_API_KEY", ""),
        )

    def with_overrides(self, **overrides: str) -> "ApiKeys":
        """Return a copy where any non-empty override replaces the current value."""
        values = {k: (overrides.get(k) or "").strip() or getattr(self, k) for k in self.__dataclass_fields__}
        return ApiKeys(**values)

    def secrets(self) -> List[str]:
        return [v for v in (self.cohere, self.shodan, self.virustotal, self.abuseipdb, self.nvd, self.greynoise) if v]


def redact(text: str, keys: Optional[ApiKeys]) -> str:
    """Remove any API key values that might appear in an error message."""
    if keys:
        for secret in keys.secrets():
            text = text.replace(secret, "[REDACTED]")
    return text


# ---------------------------------------------------------------------------
# Small caching / rate-limiting helpers (shared, public data only)
# ---------------------------------------------------------------------------

class _TTLCache:
    """Expiring cache bounded by entry count and, optionally, by the total ``size`` given to ``set``."""

    def __init__(self, ttl_seconds: float, maxsize: int = 1024, max_bytes: float = float("inf")):
        self._ttl = ttl_seconds
        self._maxsize = maxsize
        self._max_bytes = max_bytes
        self._bytes = 0
        self._data: Dict[Any, Tuple[float, Any, int]] = {}  # insertion order is age order
        self._lock = threading.Lock()

    def get(self, key: Any) -> Any:
        with self._lock:
            item = self._data.get(key)
            if item and time.monotonic() - item[0] < self._ttl:
                return item[1]
            self._discard(key)
            return None

    def set(self, key: Any, value: Any, size: int = 0) -> None:
        with self._lock:
            self._discard(key)
            if size > self._max_bytes:
                return
            while self._data and (len(self._data) >= self._maxsize or self._bytes + size > self._max_bytes):
                self._discard(next(iter(self._data)))
            self._data[key] = (time.monotonic(), value, size)
            self._bytes += size

    def _discard(self, key: Any) -> None:
        item = self._data.pop(key, None)
        if item:
            self._bytes -= item[2]


class _RateLimiter:
    """Rolling-window limiter: at most ``max_calls`` calls per ``period`` seconds."""

    def __init__(self, max_calls: int, period: float):
        self._max_calls = max_calls
        self._period = period
        self._calls: deque = deque()
        self._lock = threading.Lock()

    def wait(self) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                while self._calls and now - self._calls[0] >= self._period:
                    self._calls.popleft()
                if len(self._calls) < self._max_calls:
                    self._calls.append(now)
                    return
                delay = self._period - (now - self._calls[0])
            # Sleep without the lock so other callers aren't blocked; the window is re-checked afterwards.
            time.sleep(delay + 0.1)


# Responses are summarised before caching; the byte budget bounds memory shared by every session.
_nvd_cache = _TTLCache(ttl_seconds=3600, maxsize=512, max_bytes=32 * 1024 * 1024)
_epss_cache = _TTLCache(ttl_seconds=12 * 3600, maxsize=5000)
_kev_cache = _TTLCache(ttl_seconds=6 * 3600, maxsize=1)
_rdap_bootstrap_cache = _TTLCache(ttl_seconds=24 * 3600, maxsize=2)
# Exploit-DB's index of published exploits is a 10 MB CSV; once a day is plenty.
_exploitdb_cache = _TTLCache(ttl_seconds=24 * 3600, maxsize=1)
# Spamhaus asks for automated downloads of DROP no more than once a day.
_drop_cache = _TTLCache(ttl_seconds=24 * 3600, maxsize=2)
# One distro package's OSV records are about 1 MB raw; they're summarised first, then bounded here.
_osv_cache = _TTLCache(ttl_seconds=6 * 3600, maxsize=64, max_bytes=16 * 1024 * 1024)
# NVD allows 5 requests per 30 s without a key (per IP) and 50 with one.
_nvd_keyless_limiter = _RateLimiter(max_calls=5, period=30.0)
_nvd_keyed_limiter = _RateLimiter(max_calls=50, period=30.0)
# Analyses that consume the operator's keys, shared by every Streamlit session in this process.
SERVER_KEY_WINDOW_SECONDS = 3600


class ServerKeyQuota:
    """Sliding-window count of analyses that use the server's keys."""

    def __init__(self) -> None:
        self._runs: deque = deque()  # (start time, client)
        self._lock = threading.Lock()

    def reset(self) -> None:
        with self._lock:
            self._runs.clear()

    def acquire(self, client: str, total_limit: int, client_limit: int) -> float:
        """Record a run and return 0, or return the seconds until one is allowed.

        A limit of 0 means shared-key analyses are switched off, and returns infinity rather than a
        wait that would never end.
        """
        if total_limit <= 0 or client_limit <= 0:
            return float("inf")
        with self._lock:
            now = time.monotonic()
            while self._runs and now - self._runs[0][0] >= SERVER_KEY_WINDOW_SECONDS:
                self._runs.popleft()
            mine = [started for started, who in self._runs if who == client]
            if len(self._runs) >= total_limit:
                oldest = self._runs[0][0] if self._runs else now
            elif len(mine) >= client_limit:
                oldest = mine[0] if mine else now
            else:
                self._runs.append((now, client))
                return 0.0
            return max(1.0, SERVER_KEY_WINDOW_SECONDS - (now - oldest))

    def release(self, client: str) -> None:
        """Give back this client's most recent run (for analyses that failed before using any shared key)."""
        with self._lock:
            for i in range(len(self._runs) - 1, -1, -1):
                if self._runs[i][1] == client:
                    del self._runs[i]
                    return


_server_key_quota = ServerKeyQuota()


def server_key_quota() -> ServerKeyQuota:
    """Process-wide bucket. Lives on this imported module so Streamlit reruns and AppTest sessions share it."""
    return _server_key_quota


class SourceError(Exception):
    """A data source could not be reached or returned an unusable response."""


def _http_get(url: str, *, params: Optional[dict] = None, headers: Optional[dict] = None,
              timeout: float = HTTP_TIMEOUT, retries: int = 2, json_body: Optional[dict] = None) -> requests.Response:
    """GET (or POST, when ``json_body`` is given) with retries on network errors and 429/5xx."""
    merged_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    merged_headers.update(headers or {})
    last_error = ""
    for attempt in range(retries + 1):
        try:
            if json_body is not None:
                resp = requests.post(url, json=json_body, headers=merged_headers, timeout=timeout)
            else:
                resp = requests.get(url, params=params, headers=merged_headers, timeout=timeout)
        except requests.RequestException as exc:
            last_error = type(exc).__name__
            time.sleep(1.5 * (attempt + 1))
            continue
        if resp.status_code in (429, 502, 503, 504) and attempt < retries:
            retry_after = resp.headers.get("Retry-After", "")
            time.sleep(min(float(retry_after), 10.0) if retry_after.isdigit() else 2.0 * (attempt + 1))
            continue
        return resp
    raise SourceError(f"network error contacting {urlsplit(url).netloc}: {last_error}")


# ---------------------------------------------------------------------------
# Target classification and validation
# ---------------------------------------------------------------------------

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
DOMAIN_RE = re.compile(
    r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$",
    re.IGNORECASE,
)
# Simple, unambiguous patterns (no overlapping quantifiers), so matching time stays linear in input length.
SOFTWARE_NAME_RE = re.compile(r"[a-z][a-z0-9 ._+-]{1,60}", re.IGNORECASE)
_SOFTWARE_NAME_PART_RE = re.compile(r"[a-z][a-z0-9 ._+-]*", re.IGNORECASE)
_SOFTWARE_VERSION_PART_RE = re.compile(r"v?(\d[a-z0-9.+-]*)", re.IGNORECASE)
_NAME_VERSION_SEPARATORS = " \t/_-"


def split_software_version(value: str) -> Optional[Tuple[str, str]]:
    """Split "nginx 1.20.1" / "nginx/1.18.0" / "OpenSSH_8.9p1" into (name, version).

    Done with a plain scan instead of one big regex: the regex version backtracked polynomially
    on crafted input (CodeQL py/polynomial-redos).
    """
    seps = _NAME_VERSION_SEPARATORS
    for i, ch in enumerate(value):
        # Try the end of each run of separators, leftmost first (shortest name wins).
        if ch not in seps or (i + 1 < len(value) and value[i + 1] in seps):
            continue
        version = _SOFTWARE_VERSION_PART_RE.fullmatch(value[i + 1:])
        name = value[:i].rstrip(seps)
        if version and name and _SOFTWARE_NAME_PART_RE.fullmatch(name):
            return name.strip(" ._-"), version.group(1)
    return None


@dataclass(frozen=True)
class Target:
    value: str
    type: str  # ip | domain | cve | software | invalid
    error: Optional[str] = None
    software_name: Optional[str] = None
    software_version: Optional[str] = None


def validate_public_ip(ip_str: str) -> Tuple[bool, Optional[str]]:
    """Accept only globally routable addresses (rejects private, loopback, link-local, CGNAT, etc.)."""
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False, f"Invalid IP address format: {ip_str}"
    if not ip_obj.is_global or ip_obj.is_multicast:
        return False, f"IP {ip_obj} is not a public, globally routable address and is not suitable for OSINT analysis"
    return True, None


def is_valid_domain(domain: str) -> bool:
    return bool(DOMAIN_RE.match(domain))


def is_valid_cve(cve_id: str) -> bool:
    return bool(CVE_RE.match(cve_id.strip()))


_LOCAL_SUFFIXES = (".local", ".localhost", ".internal", ".lan", ".home.arpa", ".localdomain")
MAX_SOFTWARE_WORDS = 5  # longer text is a sentence, not a product name


def classify_target(raw: str) -> Target:
    """Normalise user input and classify it as ip, domain, cve or software."""
    if not raw or not isinstance(raw, str):
        return Target("", "invalid", "Please enter a target.")
    value = " ".join(raw.strip().split())
    if len(value) > MAX_TARGET_LENGTH:
        return Target(value[:MAX_TARGET_LENGTH], "invalid", f"Target is too long (max {MAX_TARGET_LENGTH} characters).")
    if any(ord(c) < 32 for c in value):
        return Target("", "invalid", "Target contains control characters.")

    # Accept pasted URLs by extracting the host.
    if "://" in value:
        host = urlsplit(value).hostname or ""
        if not host:
            return Target(value, "invalid", "Could not extract a host from that URL.")
        value = host

    if is_valid_cve(value):
        return Target(value.upper(), "cve")

    lowered = value.lower().rstrip(".")
    if lowered == "localhost" or lowered.endswith(_LOCAL_SUFFIXES):
        return Target(value, "invalid", f"{value} is a local name, not a public target.")
    if any(ord(c) > 127 for c in value) and " " not in value:
        try:
            value = value.encode("idna").decode("ascii")  # "münchen.de" -> "xn--mnchen-3ya.de"
        except UnicodeError:
            return Target(value, "invalid", "That isn't a valid international domain name.")

    candidate_ip = value[1:-1] if value.startswith("[") and value.endswith("]") else value
    try:
        ipaddress.ip_address(candidate_ip)
        ok, err = validate_public_ip(candidate_ip)
        return Target(str(ipaddress.ip_address(candidate_ip)), "ip" if ok else "invalid", err)
    except ValueError:
        pass

    domain = value.lower().rstrip(".")
    if is_valid_domain(domain):
        return Target(domain, "domain")

    split = split_software_version(value)
    if split:
        return Target(value, "software", software_name=split[0], software_version=split[1])
    if (SOFTWARE_NAME_RE.fullmatch(value) and not re.fullmatch(r"[\d.]+", value)
            and len(value.split()) <= MAX_SOFTWARE_WORDS):
        return Target(value, "software", software_name=value)

    return Target(value, "invalid",
                  "Could not identify the target. Enter a public IP, domain, CVE ID, or software name + version.")


# ---------------------------------------------------------------------------
# Software name / version helpers
# ---------------------------------------------------------------------------

# Common product names (as reported by Shodan banners or typed by users) -> NVD CPE (vendor, product).
# "*" as vendor means "any vendor" (e.g. nginx moved from nginx:nginx to f5:nginx).
SOFTWARE_CPE_ALIASES: Dict[str, Tuple[str, str]] = {
    "apache": ("apache", "http_server"),
    "apache httpd": ("apache", "http_server"),
    "apache http server": ("apache", "http_server"),
    "httpd": ("apache", "http_server"),
    "apache tomcat": ("apache", "tomcat"),
    "tomcat": ("apache", "tomcat"),
    "apache coyote": ("apache", "tomcat"),
    "nginx": ("*", "nginx"),
    "openssh": ("openbsd", "openssh"),
    "openssl": ("openssl", "openssl"),
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "postgres": ("postgresql", "postgresql"),
    "php": ("php", "php"),
    "iis": ("microsoft", "internet_information_services"),
    "microsoft iis": ("microsoft", "internet_information_services"),
    "microsoft-iis": ("microsoft", "internet_information_services"),
    "wordpress": ("wordpress", "wordpress"),
    "drupal": ("drupal", "drupal"),
    "jenkins": ("jenkins", "jenkins"),
    "elasticsearch": ("elastic", "elasticsearch"),
    "mongodb": ("mongodb", "mongodb"),
    "redis": ("redis", "redis"),
    "exim": ("exim", "exim"),
    "postfix": ("postfix", "postfix"),
    "proftpd": ("proftpd", "proftpd"),
    "vsftpd": ("*", "vsftpd"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "bind": ("isc", "bind"),
    "isc bind": ("isc", "bind"),
    "dovecot": ("dovecot", "dovecot"),
    "node.js": ("nodejs", "node.js"),
    "nodejs": ("nodejs", "node.js"),
    "grafana": ("grafana", "grafana"),
    "gitlab": ("gitlab", "gitlab"),
    "openresty": ("openresty", "openresty"),
    "squid": ("squid-cache", "squid"),
    "haproxy": ("haproxy", "haproxy"),
    "samba": ("samba", "samba"),
    "next.js": ("*", "next.js"),
    "nextjs": ("*", "next.js"),
    "vercel next.js": ("*", "next.js"),
    "react": ("facebook", "react"),
    "express": ("openjsf", "express"),
    "express.js": ("openjsf", "express"),
    "expressjs": ("openjsf", "express"),
    "netscaler": ("citrix", "netscaler_application_delivery_controller"),
    "netscaler adc": ("citrix", "netscaler_application_delivery_controller"),
    "citrix netscaler": ("citrix", "netscaler_application_delivery_controller"),
    "citrix netscaler adc": ("citrix", "netscaler_application_delivery_controller"),
    "netscaler gateway": ("citrix", "netscaler_gateway"),
    "citrix netscaler gateway": ("citrix", "netscaler_gateway"),
    "pan-os": ("paloaltonetworks", "pan-os"),
    "fortios": ("fortinet", "fortios"),
    "ivanti connect secure": ("ivanti", "connect_secure"),
    "rails": ("rubyonrails", "rails"),
    "ruby on rails": ("rubyonrails", "rails"),
    "spring": ("*", "spring_framework"),
    "spring framework": ("*", "spring_framework"),
    "ats": ("apache", "traffic_server"),
    "apache traffic server": ("apache", "traffic_server"),
    "traffic server": ("apache", "traffic_server"),
    "exchange server": ("microsoft", "exchange_server"),
    "microsoft exchange": ("microsoft", "exchange_server"),
    "microsoft exchange server": ("microsoft", "exchange_server"),
}

# Placeholder words a model may pass instead of a real product name.
_GENERIC_SOFTWARE_NAMES = {"all", "any", "none", "unknown", "n/a", "software", "server", "service", "services",
                           "web", "http", "https", "device", "devices", "firmware", "application", "app"}
_DAEMON_SUFFIXES = re.compile(r"\s+(?:httpd|smtpd|imapd|pop3d|sshd|ftpd|server|daemon)$")
_PRERELEASE_WORDS = {"alpha", "beta", "rc", "pre", "dev", "snapshot"}


def normalize_software_name(name: str) -> str:
    return " ".join(name.lower().replace("_", " ").split())


def resolve_cpe_alias(name: str) -> Optional[Tuple[str, str]]:
    normalized = normalize_software_name(name)
    if normalized in SOFTWARE_CPE_ALIASES:
        return SOFTWARE_CPE_ALIASES[normalized]
    stripped = _DAEMON_SUFFIXES.sub("", normalized)
    if stripped in SOFTWARE_CPE_ALIASES:
        return SOFTWARE_CPE_ALIASES[stripped]
    # "vendor product" as CPEs name it, e.g. "openbsd openssh" -> openbsd:openssh
    vendor, _, product = stripped.partition(" ")
    alias = SOFTWARE_CPE_ALIASES.get(product)
    return alias if alias and alias[0] in (vendor, "*") else None


def extract_version(text: Optional[str]) -> Optional[str]:
    """Pull the first version-looking token out of a string ("OpenSSH_8.9p1 Ubuntu" -> "8.9p1")."""
    if not text:
        return None
    # Hyphenated parts are kept only when they're builds, hotfixes or pre-releases (NetScaler "14.1-66.68",
    # PAN-OS "10.2.7-h1", "1.0.0-rc1"), never distro revisions such as "1.18.0-1ubuntu1".
    match = re.search(r"(\d+(?:\.\d+)*(?:-(?:\d+\.\d+|h\d+|(?:rc|alpha|beta|pre)\d*)(?![a-z0-9+~]))?[a-z0-9]*)",
                      str(text), re.IGNORECASE)
    return match.group(1) if match else None


def _version_tokens(version: str) -> List[Tuple[int, Any]]:
    tokens: List[Tuple[int, Any]] = []
    for tok in re.findall(r"\d+|[a-z]+", version.lower()):
        if tok.isdigit():
            tokens.append((2, int(tok)))
        elif tok in _PRERELEASE_WORDS:
            tokens.append((0, tok))
        else:
            tokens.append((1, tok))  # e.g. OpenSSL "1.1.1w", OpenSSH "8.9p1"
    return tokens


def compare_versions(a: str, b: str) -> int:
    """Compare two version strings. Returns -1, 0 or 1.

    Handles dotted numerics plus vendor suffixes that PEP 440 cannot parse,
    e.g. 1.1.1 < 1.1.1w, 8.9 < 8.9p1, 2.4.9 < 2.4.62, 1.0.0rc1 < 1.0.0, 2.4 == 2.4.0.
    """
    for x, y in zip_longest(_version_tokens(a), _version_tokens(b)):
        # A missing part counts as 0 against a number and as an empty suffix otherwise.
        x = x or ((2, 0) if y[0] == 2 else (1, ""))
        y = y or ((2, 0) if x[0] == 2 else (1, ""))
        if x == y:
            continue
        if x[0] != y[0]:
            return -1 if x[0] < y[0] else 1
        return -1 if x[1] < y[1] else 1
    return 0


def _parse_cpe(criteria: str) -> Dict[str, str]:
    # cpe:2.3:part:vendor:product:version:update:...  (escaped colons are rare enough to ignore)
    parts = criteria.split(":")
    keys = ["cpe", "spec", "part", "vendor", "product", "version", "update"]
    return {k: (parts[i] if i < len(parts) else "*") for i, k in enumerate(keys)}


def cpe_match_covers_version(match: Dict[str, Any], version: str) -> bool:
    """Does an NVD cpeMatch entry include ``version``?"""
    cpe = _parse_cpe(match.get("criteria", ""))
    start_inc = match.get("versionStartIncluding")
    start_exc = match.get("versionStartExcluding")
    end_inc = match.get("versionEndIncluding")
    end_exc = match.get("versionEndExcluding")

    if any((start_inc, start_exc, end_inc, end_exc)):
        if start_inc and compare_versions(version, start_inc) < 0:
            return False
        if start_exc and compare_versions(version, start_exc) <= 0:
            return False
        if end_inc and compare_versions(version, end_inc) > 0:
            return False
        if end_exc and compare_versions(version, end_exc) >= 0:
            return False
        return True

    cpe_version = cpe["version"]
    if cpe_version in ("*", "-", ""):
        # "*" with no range means every version; "-" means "not applicable".
        return cpe_version == "*"
    update = cpe["update"]
    exact = cpe_version + (update if update not in ("*", "-", "") else "")
    if compare_versions(version, exact) == 0:
        return True
    # "8.9" with update "*" should cover "8.9p1", but "1.20" must not cover "1.20.1".
    if update == "*":
        detected, base = _version_tokens(version), _version_tokens(cpe_version)
        return detected[: len(base)] == base and all(kind != 2 for kind, _ in detected[len(base):])
    return False


def _cpe_product_matches(criteria: str, vendor: str, product: str) -> bool:
    cpe = _parse_cpe(criteria)
    if cpe["product"].lower() != product.lower():
        return False
    return vendor == "*" or cpe["vendor"].lower() == vendor.lower()


def assess_cve_for_version(cve: Dict[str, Any], vendor: str, product: str, version: str) -> Dict[str, Any]:
    """Decide whether an NVD CVE record affects ``vendor:product`` at ``version``.

    Uses NVD's structured CPE configuration data rather than guessing from the
    description text. Returns status AFFECTED, NOT_AFFECTED or UNANALYZED.
    """
    relevant_matches = []
    requires_platform = False
    for config in cve.get("configurations", []) or []:
        for node in config.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                if match.get("vulnerable") and _cpe_product_matches(match.get("criteria", ""), vendor, product):
                    relevant_matches.append(match)
                    if (config.get("operator") or "").upper() == "AND":
                        requires_platform = True

    if not relevant_matches:
        return {"status": "UNANALYZED", "reason": "NVD has no CPE configuration for this product yet"}

    for match in relevant_matches:
        if cpe_match_covers_version(match, version):
            verdict = {
                "status": "AFFECTED",
                "matched_range": _describe_range(match),
                "requires_specific_platform": requires_platform,
            }
            if match.get("versionEndExcluding"):
                verdict["fixed_in"] = match["versionEndExcluding"]
            elif match.get("versionEndIncluding"):
                verdict["fixed_after"] = match["versionEndIncluding"]
            verdict["patch_status"] = patch_status(verdict)
            return verdict
    def nearness(match: Dict[str, Any]) -> int:
        """How many leading version parts a range's bounds share with ``version``."""
        wanted = _version_tokens(version)
        best = 0
        for key in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding"):
            bound = _version_tokens(match.get(key) or "")
            shared = next((i for i, (a, b) in enumerate(zip(wanted, bound)) if a != b), min(len(wanted), len(bound)))
            best = max(best, shared)
        return best

    nearest = sorted(relevant_matches, key=nearness, reverse=True)
    return {"status": "NOT_AFFECTED", "reason": "Version is outside every affected range listed by NVD",
            "affected_ranges": [_describe_range(m) for m in nearest[:3]]}


def patch_status(verdict: Dict[str, Any]) -> str:
    """What NVD lists as the fix for an affected CVE.

    Worded as NVD's listing on purpose: vendors often ship a fix before NVD records one, so a missing fixed
    version must not read as "no patch exists".
    """
    if verdict.get("fixed_in"):
        return f"fixed in {verdict['fixed_in']} or later (per NVD)"
    if verdict.get("fixed_after"):
        return f"fixed in versions later than {verdict['fixed_after']} (per NVD)"
    return "NVD lists no fixed version; check the vendor advisory"


def minimum_safe_version(affected: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The lowest version that is outside every affected range, from NVD's range ends.

    Computed in code because models were observed recommending versions that only fixed some of the CVEs.
    """
    best: Optional[Tuple[str, bool]] = None  # (version, must be strictly later)
    missing = 0
    for v in affected:
        if v.get("fixed_in"):
            candidate = (v["fixed_in"], False)
        elif v.get("fixed_after"):
            candidate = (v["fixed_after"], True)
        else:
            missing += 1
            continue
        if best is None:
            best = candidate
            continue
        cmp = compare_versions(candidate[0], best[0])
        if cmp > 0 or (cmp == 0 and candidate[1]):
            best = candidate
    if best is None:
        return None
    result = {"version": best[0], "text": f"later than {best[0]}" if best[1] else f"{best[0]} or later"}
    if missing:
        result["note"] = (f"{missing} affected CVE(s) list no fixed version in NVD; check the vendor advisory "
                          "for those.")
    return result


def _describe_range(match: Dict[str, Any]) -> str:
    # Ranges are written in words: models were observed dropping "<" from their output ("< 1.21.0" -> "1.21.0"),
    # which silently inverts the meaning.
    cpe = _parse_cpe(match.get("criteria", ""))
    bounds = []
    if match.get("versionStartIncluding"):
        bounds.append(f"from {match['versionStartIncluding']}")
    if match.get("versionStartExcluding"):
        bounds.append(f"after {match['versionStartExcluding']}")
    if match.get("versionEndIncluding"):
        bounds.append(f"through {match['versionEndIncluding']}")
    if match.get("versionEndExcluding"):
        bounds.append(f"before {match['versionEndExcluding']}")
    if not bounds:
        bounds.append("all versions" if cpe["version"] == "*" else f"version {cpe['version']}"
                      + (cpe["update"] if cpe["update"] not in ("*", "-") else ""))
    return f"{cpe['vendor']}:{cpe['product']} " + " ".join(bounds)


# ---------------------------------------------------------------------------
# NVD helpers
# ---------------------------------------------------------------------------

_NVD_MATCH_FIELDS = ("vulnerable", "criteria", "versionStartIncluding", "versionStartExcluding",
                     "versionEndIncluding", "versionEndExcluding")
_NVD_KEV_FIELDS = ("cisaExploitAdd", "cisaActionDue", "cisaRequiredAction", "cisaVulnerabilityName")
NVD_MAX_REFERENCES = 20
NVD_MAX_DESCRIPTION = 2000


def _summarize_nvd_record(cve: Dict[str, Any]) -> Dict[str, Any]:
    """The fields of an NVD CVE record that the tools read, in NVD's own shape (raw records can be very large)."""
    record = {k: cve[k] for k in ("id", "vulnStatus", "published", "lastModified", "weaknesses", *_NVD_KEV_FIELDS)
              if k in cve}
    record["descriptions"] = [{"lang": "en", "value": _english_description(cve)[:NVD_MAX_DESCRIPTION]}]
    record["references"] = [{"url": r.get("url"), "tags": r.get("tags", [])}
                            for r in (cve.get("references") or [])[:NVD_MAX_REFERENCES]]
    metrics = cve.get("metrics", {}) or {}
    for key in _CVSS_METRIC_KEYS:
        if metrics.get(key):
            record["metrics"] = {key: [_primary_metric(metrics[key])]}
            break
    record["configurations"] = [
        {"operator": config.get("operator"), "nodes": [
            {"cpeMatch": [{k: m[k] for k in _NVD_MATCH_FIELDS if k in m}
                          for m in node.get("cpeMatch", []) or [] if m.get("vulnerable")]}
            for node in config.get("nodes", []) or []]}
        for config in cve.get("configurations", []) or []
    ]
    return record


def _summarize_nvd_response(data: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "totalResults": data.get("totalResults", 0),
        "vulnerabilities": [{"cve": _summarize_nvd_record(v.get("cve", {}) or {})}
                            for v in data.get("vulnerabilities", []) or []],
        "products": [{"cpe": {"cpeName": (p.get("cpe") or {}).get("cpeName", "")}}
                     for p in data.get("products", []) or []],
    }


def _nvd_get(url: str, params: Dict[str, Any], keys: Optional[ApiKeys]) -> Dict[str, Any]:
    cache_key = (url, tuple(sorted(params.items())))
    cached = _nvd_cache.get(cache_key)
    if cached is not None:
        return cached
    nvd_key = keys.nvd if keys else ""
    headers = {"apiKey": nvd_key} if nvd_key else {}
    limiter = _nvd_keyed_limiter if nvd_key else _nvd_keyless_limiter
    for attempt in range(2):
        limiter.wait()
        resp = _http_get(url, params=params, headers=headers, timeout=30)
        # NVD signals rate limiting with 403 (not 429). On shared hosting other apps on the same IP count too.
        if resp.status_code not in (403, 429) or attempt:
            break
        time.sleep(6)
    if resp.status_code == 404:
        data: Dict[str, Any] = {"vulnerabilities": [], "products": [], "totalResults": 0}
    elif resp.status_code in (403, 429):
        raise SourceError("NVD rate limit reached. Wait about 30 seconds and retry"
                          + ("" if nvd_key else f", or add a free NVD API key ({KEY_SIGNUP_URLS['nvd']})"))
    elif resp.status_code != 200:
        message = resp.headers.get("message", "")
        raise SourceError(f"NVD returned HTTP {resp.status_code}" + (f": {message}" if message else ""))
    else:
        try:
            data = _summarize_nvd_response(resp.json())
        except (ValueError, AttributeError) as exc:
            raise SourceError("NVD returned invalid JSON") from exc
    _nvd_cache.set(cache_key, data, size=len(json.dumps(data, default=str)))
    return data


def mentions_whole_words(text: str, term: str) -> bool:
    """True if every word of ``term`` appears in ``text`` as a whole word (case-insensitive).

    Words that contain a digit may be followed by more digits ("log4j" matches "Log4j2"), but plain words may not
    ("ADT" does not match "ADT7470" or "AdTribes").
    """
    text = text.lower()
    for word in re.findall(r"[a-z0-9.+]+", term.lower()):
        # "_" counts as part of a word so code identifiers like "ajax_adt_clear" don't match "ADT".
        tail = r"(?![a-z_])" if any(ch.isdigit() for ch in word) else r"(?![a-z0-9_])"
        if not re.search(r"(?<![a-z0-9_])" + re.escape(word) + tail, text):
            return False
    return True


def _english_description(cve: Dict[str, Any]) -> str:
    descriptions = cve.get("descriptions", []) or []
    for desc in descriptions:
        if desc.get("lang") == "en":
            return desc.get("value", "")
    return descriptions[0].get("value", "") if descriptions else ""


def severity_from_score(score: Optional[float]) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


_CVSS_METRIC_KEYS = {"cvssMetricV40": "4.0", "cvssMetricV31": "3.1", "cvssMetricV30": "3.0", "cvssMetricV2": "2.0"}


def _primary_metric(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    return next((e for e in entries if e.get("type") == "Primary"), entries[0])


def extract_cvss(cve: Dict[str, Any]) -> Dict[str, Any]:
    """Pick the best available CVSS metric: newest version first, NVD 'Primary' score preferred."""
    metrics = cve.get("metrics", {}) or {}
    for key, label in _CVSS_METRIC_KEYS.items():
        entries = metrics.get(key) or []
        if not entries:
            continue
        entry = _primary_metric(entries)
        data = entry.get("cvssData", {})
        score = data.get("baseScore")
        severity = data.get("baseSeverity") or entry.get("baseSeverity") or severity_from_score(score)
        return {"cvss_score": score, "cvss_version": label, "cvss_vector": data.get("vectorString"),
                "severity": str(severity).upper(), "cvss_source": entry.get("source")}
    return {"cvss_score": None, "cvss_version": None, "cvss_vector": None, "severity": "UNKNOWN", "cvss_source": None}


def summarize_nvd_cve(cve: Dict[str, Any], description_limit: int = 600, reference_limit: int = 5) -> Dict[str, Any]:
    weaknesses = sorted({d.get("value") for w in cve.get("weaknesses", []) or []
                         for d in w.get("description", []) or [] if d.get("value", "").startswith("CWE-")})
    summary = {
        "cve_id": cve.get("id"),
        "status": cve.get("vulnStatus"),
        "published": (cve.get("published") or "")[:10],
        "last_modified": (cve.get("lastModified") or "")[:10],
        "description": _english_description(cve)[:description_limit],
        "cwe": weaknesses,
        **extract_cvss(cve),
        "references": [
            {"url": r.get("url"), "tags": r.get("tags", [])}
            for r in (cve.get("references") or [])[:reference_limit]
        ],
    }
    if cve.get("cisaExploitAdd"):
        summary["cisa_kev"] = {
            "date_added": cve.get("cisaExploitAdd"),
            "action_due": cve.get("cisaActionDue"),
            "required_action": cve.get("cisaRequiredAction"),
            "vulnerability_name": cve.get("cisaVulnerabilityName"),
            **kev_age(cve.get("cisaExploitAdd")),
        }
    return summary


def _nvd_most_recent(params: Dict[str, Any], keys: Optional[ApiKeys], limit: int) -> Tuple[int, List[Dict[str, Any]]]:
    """NVD returns oldest CVEs first; fetch the last page so results are the most recent ones."""
    first = _nvd_get(NVD_CVE_URL, {**params, "resultsPerPage": 1, "startIndex": 0}, keys)
    total = int(first.get("totalResults", 0))
    if total == 0:
        return 0, []
    start = max(0, total - limit)
    page = _nvd_get(NVD_CVE_URL, {**params, "resultsPerPage": limit, "startIndex": start}, keys)
    cves = [v.get("cve", {}) for v in page.get("vulnerabilities", [])]
    cves.sort(key=lambda c: c.get("published", ""), reverse=True)
    return total, cves


# ---------------------------------------------------------------------------
# CISA KEV and EPSS enrichment
# ---------------------------------------------------------------------------

def _load_kev_catalog() -> Dict[str, Any]:
    cached = _kev_cache.get("catalog")
    if cached is not None:
        return cached
    resp = _http_get(CISA_KEV_URL, timeout=30)
    if resp.status_code != 200:
        raise SourceError(f"CISA KEV feed returned HTTP {resp.status_code}")
    try:
        data = resp.json()
    except ValueError as exc:
        raise SourceError("CISA KEV feed returned invalid JSON") from exc
    catalog = {
        "date_released": data.get("dateReleased"),
        "vulnerabilities": data.get("vulnerabilities", []),
        "by_cve": {v.get("cveID", "").upper(): v for v in data.get("vulnerabilities", [])},
    }
    _kev_cache.set("catalog", catalog)
    return catalog


KEV_RECENT_DAYS = 30


def kev_age(date_added: Any) -> Dict[str, Any]:
    """Days since CISA added a CVE to KEV, and whether that is recent enough to call it newly exploited."""
    try:
        added = datetime.strptime(str(date_added or "")[:10], "%Y-%m-%d").date()
    except ValueError:
        return {}
    days = (datetime.now(timezone.utc).date() - added).days
    return {"days_in_kev": days, "recently_added_to_kev": 0 <= days <= KEV_RECENT_DAYS}


def _kev_entry_summary(vuln: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "cve_id": vuln.get("cveID"),
        "vendor_project": vuln.get("vendorProject"),
        "product": vuln.get("product"),
        "vulnerability_name": vuln.get("vulnerabilityName"),
        "date_added": vuln.get("dateAdded"),
        **kev_age(vuln.get("dateAdded")),
        "short_description": vuln.get("shortDescription"),
        "required_action": vuln.get("requiredAction"),
        "due_date": vuln.get("dueDate"),
        "known_ransomware_use": vuln.get("knownRansomwareCampaignUse", "Unknown"),
    }


def _kev_search_terms(software: str) -> List[set]:
    """Word sets that must all appear in a KEV entry's 'vendor product' text."""
    alias = resolve_cpe_alias(software)
    if alias:
        # Use the precise product only: "apache httpd" must not match Struts, Tomcat, etc.
        vendor, product = alias
        words = set(re.findall(r"[a-z0-9.+]+", product.replace("_", " ")))
        if vendor != "*":
            words.add(vendor)
        return [words]
    words = set(re.findall(r"[a-z0-9.+]+", _DAEMON_SUFFIXES.sub("", normalize_software_name(software))))
    return [words] if words else []


# CISA's product names where they differ from NVD's CPE product.
_KEV_PRODUCT_NAMES = {"netscaler_application_delivery_controller": "netscaler", "netscaler_gateway": "netscaler gateway",
                      "internet_information_services": "iis", "connect_secure": "connect secure"}


def kev_matches_software(vuln: Dict[str, Any], software: str) -> bool:
    # Whole-word matching, so "log4j" matches CISA's "Log4j2" but "apache httpd" doesn't match "Apache Struts".
    vendor_field, product_field = str(vuln.get("vendorProject", "")), str(vuln.get("product", ""))
    alias = resolve_cpe_alias(software)
    if alias:
        vendor, product = alias
        product_words = _KEV_PRODUCT_NAMES.get(product, product.replace("_", " "))
        # The product must be named in the product field, and the vendor anywhere in the entry.
        if mentions_whole_words(product_field, product_words) and (
                vendor == "*" or mentions_whole_words(f"{vendor_field} {product_field}", vendor)):
            return True
    else:
        text = f"{vendor_field} {product_field}"
        if any(mentions_whole_words(text, " ".join(sorted(term))) for term in _kev_search_terms(software)):
            return True
    # Some KEV entries name only the vendor as the product (CVE-2021-40438 is "Apache" / "Apache"). For known
    # products, accept the vulnerability name instead, but only when the vendor also matches.
    alias = resolve_cpe_alias(software)
    if not alias or alias[0] == "*":
        return False
    vendor, product = alias
    return (mentions_whole_words(str(vuln.get("vendorProject", "")), vendor)
            and mentions_whole_words(str(vuln.get("vulnerabilityName", "")),
                                     f"{vendor} {product.replace('_', ' ')}"))


def kev_lookup_many(cve_ids: Iterable[str]) -> Dict[str, Dict[str, Any]]:
    """Return KEV entries for any of ``cve_ids`` (empty dict if the feed is unavailable)."""
    try:
        by_cve = _load_kev_catalog()["by_cve"]
    except SourceError as exc:
        logger.warning("KEV enrichment skipped: %s", exc)
        return {}
    return {c.upper(): _kev_entry_summary(by_cve[c.upper()]) for c in cve_ids if c and c.upper() in by_cve}


def epss_percent(epss: float) -> str:
    """EPSS as a display percentage. 0.99999 would round to "100.00%", which overstates a probability, so the
    display is capped just below 100. Results carry this string so the model quotes the same value as the key facts."""
    return f"{min(epss * 100, 99.99) if epss < 1 else 100:.2f}%"


def epss_lookup_many(cve_ids: Iterable[str]) -> Dict[str, Dict[str, Any]]:
    """FIRST EPSS exploitation-probability scores (best effort; missing on failure)."""
    ids = sorted({c.upper() for c in cve_ids if c and is_valid_cve(c)})
    result: Dict[str, Dict[str, Any]] = {}
    missing = []
    for cve_id in ids:
        cached = _epss_cache.get(cve_id)
        if cached is not None:
            if cached:
                result[cve_id] = cached
        else:
            missing.append(cve_id)
    for i in range(0, len(missing), 50):
        batch = missing[i:i + 50]
        try:
            resp = _http_get(EPSS_URL, params={"cve": ",".join(batch)}, retries=1)
            rows = resp.json().get("data", []) if resp.status_code == 200 else None
            found = {r["cve"].upper(): {"epss": round(float(r["epss"]), 5),
                                        "percent": epss_percent(float(r["epss"])),
                                        "percentile": round(float(r["percentile"]), 4)}
                     for r in rows or [] if r.get("cve")}
        except (SourceError, ValueError, KeyError, TypeError, AttributeError):
            rows = None
        if rows is None:
            continue
        for cve_id in batch:
            _epss_cache.set(cve_id, found.get(cve_id, {}))
            if cve_id in found:
                result[cve_id] = found[cve_id]
    return result


def _exploitdb_index() -> Dict[str, List[Tuple[str, bool]]]:
    """CVE -> [(Exploit-DB id, verified)] from Exploit-DB's published index."""
    cached = _exploitdb_cache.get("index")
    if cached is not None:
        return cached
    resp = _http_get(EXPLOITDB_CSV_URL, headers={"Accept": "text/csv, text/plain"}, timeout=60, retries=1)
    if resp.status_code != 200:
        raise SourceError(f"Exploit-DB index returned HTTP {resp.status_code}")
    index: Dict[str, List[Tuple[str, bool]]] = {}
    for row in csv.DictReader(io.StringIO(resp.text)):
        for code in (row.get("codes") or "").split(";"):
            code = code.strip().upper()
            if CVE_RE.match(code):
                index.setdefault(code, []).append((str(row.get("id") or ""), row.get("verified") == "1"))
    if not index:
        raise SourceError("Exploit-DB index had no CVE references")
    _exploitdb_cache.set("index", index)
    return index


def exploit_lookup_many(cve_ids: Iterable[str]) -> Dict[str, Dict[str, Any]]:
    """Published exploit code on Exploit-DB for any of ``cve_ids`` (empty dict if the index is unavailable)."""
    try:
        index = _exploitdb_index()
    except (SourceError, csv.Error) as exc:
        logger.warning("Exploit-DB enrichment skipped: %s", exc)
        return {}
    found = {}
    for cve in {c.upper() for c in cve_ids if c}:
        if cve in index:
            entries = index[cve]
            found[cve] = {"exploit_db_ids": [i for i, _ in entries][:5], "count": len(entries),
                          "verified": any(v for _, v in entries)}
    return found


def _enrich_with_exploit_intel(vulns: List[Dict[str, Any]]) -> None:
    ids = [v["cve_id"] for v in vulns if v.get("cve_id")]
    kev = kev_lookup_many(ids)
    epss = epss_lookup_many(ids)
    exploits = exploit_lookup_many(ids)
    for v in vulns:
        cve_id = (v.get("cve_id") or "").upper()
        if cve_id in kev:
            v["in_cisa_kev"] = True
            v["kev_known_ransomware_use"] = kev[cve_id]["known_ransomware_use"]
            v["kev_date_added"] = kev[cve_id]["date_added"]
        else:
            v.setdefault("in_cisa_kev", bool(v.get("cisa_kev")))
            if v.get("cisa_kev"):
                v["kev_date_added"] = v["cisa_kev"].get("date_added")
        if v.get("kev_date_added"):
            v.update(kev_age(v["kev_date_added"]))
        if cve_id in epss:
            v["epss"] = epss[cve_id]
        if cve_id in exploits:
            v["public_exploit"] = exploits[cve_id]


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

def resolve_domain(domain: str) -> Dict[str, Any]:
    """Resolve a domain to its public A/AAAA records (non-public addresses are reported, not used)."""
    try:
        infos = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError) as exc:
        return {"success": False, "domain": domain, "error": f"DNS resolution failed: {exc}",
                "ipv4": [], "ipv6": [], "primary_ip": None}
    ipv4, ipv6, non_public = [], [], []
    for info in infos:
        ip = info[4][0]
        ok, _ = validate_public_ip(ip)
        if not ok:
            if ip not in non_public:
                non_public.append(ip)
            continue
        bucket = ipv6 if ":" in ip else ipv4
        if ip not in bucket:
            bucket.append(ip)
    result = {
        "success": bool(ipv4 or ipv6),
        "domain": domain,
        "ipv4": ipv4,
        "ipv6": ipv6,
        "primary_ip": (ipv4 or ipv6 or [None])[0],
    }
    if non_public:
        result["non_public_addresses_ignored"] = non_public
    return result


# ---------------------------------------------------------------------------
# Distro packages (backported fixes), from the distros' own data via OSV.dev
# ---------------------------------------------------------------------------

# Releases to try, newest first. Each lists its OSV ecosystems. Ubuntu moves releases to "Pro" when standard
# support ends and keeps the older fixes under the standard name, so both are read and merged.
DISTRO_RELEASES: Dict[str, List[Tuple[str, List[str]]]] = {
    "ubuntu": [("26.04", ["Ubuntu:26.04:LTS"]), ("25.10", ["Ubuntu:25.10"]), ("24.04", ["Ubuntu:24.04:LTS"]),
               ("22.04", ["Ubuntu:22.04:LTS"]), ("20.04", ["Ubuntu:20.04:LTS", "Ubuntu:Pro:20.04:LTS"]),
               ("18.04", ["Ubuntu:18.04:LTS", "Ubuntu:Pro:18.04:LTS"]),
               ("16.04", ["Ubuntu:16.04:LTS", "Ubuntu:Pro:16.04:LTS"]),
               ("14.04", ["Ubuntu:14.04:LTS", "Ubuntu:Pro:14.04:LTS"])],
    "debian": [("14", ["Debian:14"]), ("13", ["Debian:13"]), ("12", ["Debian:12"]), ("11", ["Debian:11"]),
               ("10", ["Debian:10"])],
}
_DISTRO_NAMES = {"ubuntu": "Ubuntu", "debian": "Debian"}
_PACKAGE_RE = re.compile(r"[a-z0-9][a-z0-9.+-]{0,60}")
_DPKG_VERSION_RE = re.compile(r"(?:\d{1,5}:)?[0-9][0-9A-Za-z.+~-]{0,80}")
_DEBIAN_SECURITY_RE = re.compile(r"\+deb(\d{1,2})u\d")
# Banners that carry the distro package revision, e.g. "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6".
# Character classes don't overlap, so matching stays linear on hostile banners.
_DISTRO_BANNERS = [("openssh", re.compile(r"OpenSSH_([0-9][0-9A-Za-z.]{0,30}) (Ubuntu|Debian)-([0-9][0-9A-Za-z.+~]{0,40})"))]


def distro_package_from_banner(banner: Optional[str]) -> Optional[Dict[str, str]]:
    """The distro package a service banner names, when the banner includes the package revision."""
    for package, pattern in _DISTRO_BANNERS:
        match = pattern.search(banner or "")
        if match:
            upstream, distro, revision = match.groups()
            return {"distro": distro, "package": package, "package_version": f"{upstream}-{revision}"}
    return None


def _dpkg_order(c: str) -> int:
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return -1 if c == "~" else ord(c) + 256


def _dpkg_part_cmp(a: str, b: str) -> int:
    """dpkg's ordering for an upstream version or revision ("~" sorts before everything, even the end)."""
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _dpkg_order(a[i]) if i < len(a) else 0
            bc = _dpkg_order(b[j]) if j < len(b) else 0
            if ac != bc:
                return -1 if ac < bc else 1
            i, j = i + 1, j + 1
        ni = i
        while ni < len(a) and a[ni].isdigit():
            ni += 1
        nj = j
        while nj < len(b) and b[nj].isdigit():
            nj += 1
        na, nb = int(a[i:ni] or 0), int(b[j:nj] or 0)
        if na != nb:
            return -1 if na < nb else 1
        i, j = ni, nj
    return 0


def _dpkg_split(version: str) -> Tuple[int, str, str]:
    epoch, sep, rest = version.partition(":")
    if not sep:
        epoch, rest = "0", version
    upstream, sep, revision = rest.rpartition("-")
    if not sep:
        upstream, revision = rest, ""
    return (int(epoch) if epoch.isdigit() else 0), upstream, revision


def compare_dpkg_versions(a: str, b: str) -> int:
    """Compare two Debian/Ubuntu package versions (epoch:upstream-revision) the way dpkg does. Returns -1, 0 or 1."""
    (ea, ua, ra), (eb, ub, rb) = _dpkg_split(a), _dpkg_split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _dpkg_part_cmp(ua, ub) or _dpkg_part_cmp(ra, rb)


def _strip_epoch(version: str) -> str:
    return version.split(":", 1)[1] if ":" in version else version


def _osv_package(ecosystem: str, package: str) -> Dict[str, Any]:
    """The distro's records for one source package in one release: known versions and each CVE's ranges."""
    cache_key = (ecosystem, package)
    cached = _osv_cache.get(cache_key)
    if cached is not None:
        return cached
    versions: set = set()
    records: List[Dict[str, Any]] = []
    body: Dict[str, Any] = {"package": {"name": package, "ecosystem": ecosystem}}
    for _ in range(5):  # OSV pages large answers
        resp = _http_get(OSV_QUERY_URL, json_body=body, timeout=30)
        if resp.status_code != 200:
            raise SourceError(f"OSV.dev returned HTTP {resp.status_code}")
        try:
            data = resp.json()
        except ValueError as exc:
            raise SourceError("OSV.dev returned invalid JSON") from exc
        for vuln in data.get("vulns", []) or []:
            cves = [c for c in (vuln.get("upstream") or vuln.get("aliases") or []) if is_valid_cve(c)]
            for affected in vuln.get("affected", []) or []:
                pkg = affected.get("package") or {}
                if pkg.get("name") != package or pkg.get("ecosystem") != ecosystem:
                    continue  # one record can cover several packages
                versions.update(_strip_epoch(v) for v in affected.get("versions", []) or [])
                ranges = [r.get("events", []) for r in affected.get("ranges", []) or [] if r.get("type") == "ECOSYSTEM"]
                specific = affected.get("ecosystem_specific") or {}
                for cve in cves:
                    records.append({"cve_id": cve.upper(), "ranges": ranges,
                                    "versions": [_strip_epoch(v) for v in affected.get("versions", []) or []],
                                    "availability": specific.get("availability")})
        token = data.get("next_page_token")
        if not token:
            break
        body = {**body, "page_token": token}
    summary = {"versions": sorted(versions), "records": records}
    _osv_cache.set(cache_key, summary, size=len(json.dumps(summary)))
    return summary


def _release_data(ecosystems: List[str], package: str) -> Dict[str, Any]:
    """One release's records for a package, merged across its OSV ecosystems (standard and Pro)."""
    parts = [_osv_package(e, package) for e in ecosystems]
    return {"versions": sorted({v for p in parts for v in p["versions"]}),
            "records": [r for p in parts for r in p["records"]]}


def _match_package_version(version: str, versions: List[str]) -> Optional[str]:
    """The distro's own spelling of ``version``: exact, or the one with the same revision and major.minor.

    OpenSSH's banner says "6.6.1p1 Ubuntu-2ubuntu2.13" while Ubuntu's package is "6.6p1-2ubuntu2.13".
    """
    plain = _strip_epoch(version)
    if plain in versions:
        return plain
    upstream, sep, revision = plain.rpartition("-")
    major_minor = re.match(r"\d+\.\d+", upstream)
    if not sep or not major_minor:
        return None
    matches = [v for v in versions if v.rpartition("-")[2] == revision
               and re.match(re.escape(major_minor.group()) + r"(?!\d)", v.rpartition("-")[0])]
    return matches[0] if len(matches) == 1 else None


def _with_epoch(version: str, reference: str) -> str:
    """Banners drop the epoch ("1:" in "1:8.9p1-3ubuntu0.6"); borrow it from the version being compared."""
    if ":" in version or ":" not in reference:
        return version
    return reference.split(":", 1)[0] + ":" + version


def _package_status(version: str, record: Dict[str, Any]) -> Dict[str, Any]:
    """Whether ``version`` of the package is affected by one distro record, and the fixing version if any."""
    if not record["ranges"]:
        return {"affected": _strip_epoch(version) in record["versions"], "fixed_in": None}
    affected, fixed_in = False, None
    for events in record["ranges"]:
        inside, fix = False, None
        for event in events:
            if "introduced" in event:
                intro = event["introduced"]
                if intro == "0" or compare_dpkg_versions(_with_epoch(version, intro), intro) >= 0:
                    inside = True
            elif "fixed" in event:
                fix = event["fixed"]
                if inside and compare_dpkg_versions(_with_epoch(version, fix), fix) >= 0:
                    inside = False
                elif inside:
                    break
            elif "last_affected" in event:
                if inside and compare_dpkg_versions(_with_epoch(version, event["last_affected"]),
                                                    event["last_affected"]) > 0:
                    inside = False
                elif inside:
                    break
        if inside:
            return {"affected": True, "fixed_in": fix if fix and compare_dpkg_versions(
                _with_epoch(version, fix), fix) < 0 else None}
        fixed_in = fixed_in or fix
    return {"affected": affected, "fixed_in": fixed_in}


def _find_release(distro: str, package: str, version: str) -> Tuple[Optional[str], Optional[str], List[str]]:
    """(release, ecosystem, ambiguous candidates) for a package version, from the distro's own version lists."""
    match = _DEBIAN_SECURITY_RE.search(version) if distro == "debian" else None
    if match:  # Debian security updates name their release, e.g. "+deb12u3"
        for release, ecosystems in DISTRO_RELEASES["debian"]:
            if release == match.group(1):
                return release, ecosystems[0], []
    found: List[Tuple[str, str]] = []
    for release, ecosystems in DISTRO_RELEASES[distro]:
        for ecosystem in ecosystems:
            if _match_package_version(version, _osv_package(ecosystem, package)["versions"]):
                found.append((release, ecosystem))
                break
    if len(found) == 1:
        return found[0][0], found[0][1], []
    return None, None, [release for release, _ in found]


def osint_distro_patch_check(package: str, package_version: str, distro: str, release: Optional[str] = None,
                             cve_ids: Optional[Sequence[str]] = None, result_limit: int = 15) -> Dict[str, Any]:
    """Check a Debian/Ubuntu package version against the distro's own fix data, so backported fixes count."""
    distro_key = (distro or "").strip().lower()
    if distro_key not in DISTRO_RELEASES:
        return {"tool": "distro_patch_check", "error": "distro must be 'Ubuntu' or 'Debian'"}
    package = (package or "").strip().lower()
    version = (package_version or "").strip()
    if not _PACKAGE_RE.fullmatch(package):
        return {"tool": "distro_patch_check", "error": f"Invalid package name: {package[:60]!r}"}
    if not _DPKG_VERSION_RE.fullmatch(version):
        return {"tool": "distro_patch_check", "error": f"Invalid package version: {version[:80]!r}"}
    ids = list(dict.fromkeys(c.strip().upper() for c in (cve_ids or []) if c and is_valid_cve(c)))[:50]
    name = _DISTRO_NAMES[distro_key]
    try:
        if release:
            release = str(release).strip().split(" ")[0]
            ecosystems = dict(DISTRO_RELEASES[distro_key]).get(release)
            if not ecosystems:
                known = ", ".join(r for r, _ in DISTRO_RELEASES[distro_key])
                return {"tool": "distro_patch_check", "error": f"Unknown {name} release {release!r} (known: {known})"}
            ecosystem = next((e for e in ecosystems
                              if _match_package_version(version, _osv_package(e, package)["versions"])), None)
            if ecosystem is None:
                found, _, candidates = _find_release(distro_key, package, version)
                where = (f"It matches {name} {found}." if found else
                         f"It matches {name} {', '.join(candidates)}." if candidates else
                         f"It isn't in {name}'s records for any supported release.")
                return {"tool": "distro_patch_check", "success": False, "distro": name, "package": package,
                        "package_version": version,
                        "info": f"{package} {version} isn't a package version in {name} {release}. {where} "
                                "Check the release, or omit it to detect it."}
        else:
            release, ecosystem, candidates = _find_release(distro_key, package, version)
            if not release:
                why = (f"matches several {name} releases ({', '.join(candidates)})" if candidates
                       else f"isn't in {name}'s records for any supported release")
                return {"tool": "distro_patch_check", "success": False, "distro": name, "package": package,
                        "package_version": version,
                        "info": f"Can't tell which {name} release this is: {package} {version} {why}. "
                                "Pass release if you know it."}
        data = _release_data(dict(DISTRO_RELEASES[distro_key])[release], package)
        ecosystem = ", ".join(e for e in dict(DISTRO_RELEASES[distro_key])[release]
                              if _osv_package(e, package)["records"]) or ecosystem
    except SourceError as exc:
        return {"tool": "distro_patch_check", "error": str(exc)}
    given = version
    version = _match_package_version(version, data["versions"]) or version

    open_cves: Dict[str, Dict[str, Any]] = {}
    open_fix: Dict[str, Optional[str]] = {}  # CVE -> package version that fixes it, for CVEs still open
    fixed: Dict[str, Optional[str]] = {}
    for record in data["records"]:
        status = _package_status(version, record)
        cve = record["cve_id"]
        if status["affected"]:
            entry = {"cve_id": cve, "package_fix": (f"fixed in package {status['fixed_in']}" if status["fixed_in"]
                                                   else f"{name} has not released a fix yet")}
            if status["fixed_in"] and record.get("availability"):
                entry["availability"] = record["availability"]
            open_cves[cve] = entry
            open_fix[cve] = status["fixed_in"]
            fixed.pop(cve, None)
        elif cve not in open_cves:
            fixed[cve] = status["fixed_in"]

    result: Dict[str, Any] = {
        "tool": "distro_patch_check",
        "success": True,
        "distro": name,
        "release": release,
        "osv_ecosystem": ecosystem,
        "package": package,
        "package_version": version,
        **({"package_version_note": f"{given} (from the banner) is {name}'s package {version}"}
           if version != _strip_epoch(given) else {}),
    }
    if ids:
        checked = {}
        for cve in ids:
            if cve in open_cves:
                checked[cve] = {"status": "STILL_AFFECTS_PACKAGE", **open_cves[cve]}
            elif cve in fixed:
                checked[cve] = {"status": "FIXED_IN_PACKAGE",
                                "detail": f"fixed by {name} in {fixed[cve]}" if fixed[cve] else f"{name} marks it not affecting this version"}
            else:
                checked[cve] = {"status": "NOT_LISTED",
                                "detail": f"{name}'s data for {package} doesn't list this CVE; can't tell"}
        result["checked_cves"] = checked
        result["fixed_by_backport"] = [c for c, v in checked.items() if v["status"] == "FIXED_IN_PACKAGE"]
        result["still_affects_package"] = [c for c, v in checked.items() if v["status"] == "STILL_AFFECTS_PACKAGE"]
        result["not_listed"] = [c for c, v in checked.items() if v["status"] == "NOT_LISTED"]
    vulns = sorted(open_cves.values(), key=lambda v: v["cve_id"], reverse=True)
    _enrich_with_exploit_intel(vulns)
    vulns.sort(key=lambda v: (bool(v.get("in_cisa_kev")), (v.get("epss") or {}).get("epss") or 0.0), reverse=True)
    fixes = [f for f in (open_fix.get(v["cve_id"]) for v in vulns) if f]
    if fixes:
        target = fixes[0]
        for fix in fixes[1:]:
            if compare_dpkg_versions(fix, target) > 0:
                target = fix
        covered = sum(1 for v in vulns if open_fix.get(v["cve_id"]))
        result["update_package_to_at_least"] = {
            "version": target,
            "text": f"{package} {target} or later",
            "fixes": f"{covered} of {len(vulns)} CVEs still open in this package",
        }
        # Ubuntu marks each fix "No subscription required" or, for ESM fixes, something like "Available with Ubuntu Pro".
        if any(v.get("availability") and "no subscription" not in str(v["availability"]).lower() for v in vulns):
            result["update_package_to_at_least"]["note"] = "Some of these fixes need an Ubuntu Pro subscription."
    result["no_fix_released_yet"] = [v["cve_id"] for v in vulns if not open_fix.get(v["cve_id"])]
    result["open_in_package_count"] = len(vulns)
    result["open_in_package"] = vulns[:result_limit]
    if len(vulns) > result_limit:
        result["open_in_package_shown"] = f"showing {result_limit} of {len(vulns)}, most exploited first"
    result["note"] = (f"From {name}'s own security data via OSV.dev, which accounts for fixes {name} backports "
                      "without changing the upstream version. FIXED_IN_PACKAGE overrides an NVD version match. "
                      "NOT_LISTED means the distro's data doesn't cover that CVE for this package.")
    return result


# ---------------------------------------------------------------------------
# Tools exposed to the agent
# ---------------------------------------------------------------------------

_CDN_NAMES = ("cloudflare", "akamai", "fastly", "cloudfront", "edgecast", "stackpath", "bunny", "sucuri",
              "incapsula", "imperva")
# Akamai bought Linode, so Linode servers report as "Akamai Connected Cloud". Those are ordinary cloud
# servers whose ports the customer controls, not CDN edges.
_CLOUD_HOSTING_NAMES = ("akamai connected cloud", "linode")


def _banner_server_header(banner: str) -> Optional[str]:
    match = re.search(r"^Server:[ \t]*([^\r\n]{1,80})", banner or "", re.IGNORECASE | re.MULTILINE)
    return _clean_banner(match.group(1).strip(), 80) if match else None


def kev_matches_for_software(names: Iterable[str], limit: int = 10) -> Dict[str, Dict[str, Any]]:
    """Product-level (or, failing that, vendor-level) CISA KEV matches for software names."""
    try:
        vulns = _load_kev_catalog()["vulnerabilities"]
    except SourceError as exc:
        logger.warning("KEV product matching skipped: %s", exc)
        return {}
    matches: Dict[str, Dict[str, Any]] = {}
    for name in dict.fromkeys(n for n in names if n):
        hits = [v for v in vulns if kev_matches_software(v, name)]
        level = "product"
        if not hits and not resolve_cpe_alias(name):
            vendor = normalize_software_name(name).split(" ")[0]
            if len(vendor) >= 3:
                hits = [v for v in vulns if vendor in re.findall(r"[a-z0-9.+]+", v.get("vendorProject", "").lower())]
                level = "vendor (different products possible)"
        if hits:
            hits.sort(key=lambda v: v.get("dateAdded") or "", reverse=True)
            matches[name] = {
                "match_level": level,
                "count": len(hits),
                "entries": [{"cve_id": v.get("cveID"), "product": f"{v.get('vendorProject')} {v.get('product')}",
                             "name": v.get("vulnerabilityName"), "date_added": v.get("dateAdded"),
                             **kev_age(v.get("dateAdded")),
                             "known_ransomware_use": v.get("knownRansomwareCampaignUse")}
                            for v in hits[:limit]],
                **({"entries_shown": f"showing {limit} of {len(hits)}, most recent first"} if len(hits) > limit else {}),
            }
    _add_epss([e for m in matches.values() for e in m["entries"]])
    return matches


def _add_epss(entries: List[Dict[str, Any]]) -> None:
    """Attach FIRST EPSS scores in place (best effort)."""
    epss = epss_lookup_many(e.get("cve_id") or "" for e in entries)
    for entry in entries:
        score = epss.get((entry.get("cve_id") or "").upper())
        if score:
            entry["epss"] = score


def _api_error_detail(resp: requests.Response, keys: ApiKeys) -> str:
    """The provider's own error message (VirusTotal and AbuseIPDB both return JSON errors), for diagnosis."""
    try:
        body = resp.json()
    except ValueError:
        return ""
    detail = ""
    if isinstance(body, dict):
        if isinstance(body.get("error"), dict):  # VirusTotal
            detail = body["error"].get("message") or body["error"].get("code") or ""
        elif isinstance(body.get("errors"), list) and body["errors"]:  # AbuseIPDB
            detail = str(body["errors"][0].get("detail", ""))
    detail = _clean_banner(redact(str(detail), keys), 200)
    return f": {detail}" if detail else ""


def _clean_banner(text: str, limit: int) -> str:
    text = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", text or "")
    return text[:limit]


def osint_resolve_domain(domain: str) -> Dict[str, Any]:
    domain = (domain or "").strip().lower().rstrip(".")
    if not is_valid_domain(domain):
        return {"tool": "dns", "error": f"Invalid domain: {domain!r}"}
    return {"tool": "dns", **resolve_domain(domain)}


def _cdn_note(org: str, tags: Sequence[str]) -> Optional[str]:
    org = org.lower()
    cdn_by_name = any(c in org for c in _CDN_NAMES) and not any(c in org for c in _CLOUD_HOSTING_NAMES)
    if "cdn" in (tags or []) or cdn_by_name:
        return ("This IP belongs to a CDN/edge network shared by many customers. Its open ports and services are "
                "the CDN's, not the origin server's; the site owner can't close them and they are not findings "
                "about the target.")
    return None


# Distributions that backport security fixes without changing the upstream version (names as CPEs spell them).
_BACKPORTING_DISTROS = ("ubuntu", "debian", "red hat", "redhat", "centos", "rocky", "almalinux", "suse", "oracle linux")


def _internetdb_host(ip_address: str) -> Dict[str, Any]:
    """Shodan's free InternetDB: ports, software (CPEs), hostnames, tags and CVEs for an IP. No key, no banners."""
    try:
        resp = _http_get(f"{INTERNETDB_URL}/{ip_address}", retries=1)
    except SourceError as exc:
        return {"tool": "shodan", "error": str(exc)}
    if resp.status_code == 404:
        return {"tool": "shodan", "success": False, "ip": ip_address, "data_source": "Shodan InternetDB",
                "info": f"Shodan InternetDB has no data for {ip_address}"}
    if resp.status_code != 200:
        return {"tool": "shodan", "error": f"Shodan InternetDB returned HTTP {resp.status_code}"}
    try:
        data = resp.json()
        ports = sorted(int(p) for p in data.get("ports") or [])
    except (ValueError, AttributeError, TypeError):
        return {"tool": "shodan", "error": "Shodan InternetDB returned an unexpected response"}

    software: List[Dict[str, Any]] = []
    systems: List[str] = []
    for cpe in data.get("cpes") or []:
        parts = str(cpe).split(":")  # cpe:/a:vendor:product[:version]; "/o" entries are operating systems
        if len(parts) >= 4 and parts[1] == "/o":
            systems.append(_clean_banner(f"{parts[2]} {parts[3]}".replace("_", " "), 80))
            continue
        if len(parts) < 4 or parts[1] not in ("/a", "/h"):
            continue
        vendor, product = parts[2].replace("_", " "), parts[3].replace("_", " ")
        # Keep the vendor unless the product already names it: "http server" alone matches Oracle's and
        # Microsoft's HTTP servers in KEV, "apache http server" only Apache's.
        name = product if vendor in product else f"{vendor} {product}"
        entry = {"name": _clean_banner(name, 80),
                 "version": _clean_banner(parts[4], 40) if len(parts) > 4 and parts[4] else None,
                 "source": "internetdb_cpe"}
        if entry not in software:
            software.append(entry)
    tags = [str(tag) for tag in data.get("tags") or []]
    result: Dict[str, Any] = {
        "tool": "shodan",
        "success": True,
        "ip": ip_address,
        "data_source": "Shodan InternetDB (no API key)",
        "open_ports": ports,
        "services": [{"port": p} for p in ports],
        "hostnames": [_clean_banner(str(h), 253) for h in data.get("hostnames") or []],
        "tags": tags,
        "discovered_software": software,
        "note": ("Free InternetDB data: open ports, software and operating system (from CPEs) and Shodan's inferred "
                 "CVEs only. There are no banners or organisation details, so services and distro packages can't be "
                 "checked further. Add SHODAN_API_KEY for full results."),
    }
    if systems:
        result["operating_system"] = ", ".join(dict.fromkeys(systems))
        if software and any(d in result["operating_system"] for d in _BACKPORTING_DISTROS):
            result["backport_note"] = (f"The OS is {result['operating_system']}, which backports security fixes "
                                       "without changing version numbers, so NVD matches on these software "
                                       "versions may already be fixed. A Shodan key shows the package versions "
                                       "needed for osint_distro_patch_check.")
    cdn = _cdn_note("", tags)
    if cdn:
        result["cdn_note"] = cdn
    kev = kev_matches_for_software([s["name"] for s in software])
    if kev:
        result["cisa_kev_product_matches"] = kev
        result["cisa_kev_note"] = ("Products seen on this host have CVEs in CISA's Known Exploited Vulnerabilities "
                                   "catalog. This shows real-world exploitation of the product family; it does not "
                                   "confirm this host's version is affected.")
    vulns = [str(v) for v in data.get("vulns") or [] if is_valid_cve(str(v))]
    if vulns:
        result["shodan_inferred_cves"] = sorted(vulns)[:50]
        result["shodan_inferred_cves_note"] = "Shodan infers these from software versions; they are unverified."
    return result


def osint_shodan_search(target: str, keys: ApiKeys, banner_limit: int = 200) -> Dict[str, Any]:
    """Look up a public IP (or a domain's primary IP) in Shodan's host database. Without a key, falls back to
    Shodan's free InternetDB (ports, software, OS and CVEs, but no banners)."""
    target = (target or "").strip()
    domain_info = None
    ok, err = validate_public_ip(target)
    if ok:
        ip_address = str(ipaddress.ip_address(target))
    elif is_valid_domain(target.lower()):
        domain_info = resolve_domain(target.lower())
        if not domain_info["success"]:
            return {"tool": "shodan", "error": f"Could not resolve {target} to a public IP", "dns": domain_info}
        ip_address = domain_info["primary_ip"]
    else:
        return {"tool": "shodan", "error": err or f"Invalid target: {target!r}"}

    if not keys.shodan:
        result = _internetdb_host(ip_address)
        if domain_info:
            result["dns"] = domain_info
        result["key_hint"] = f"Full Shodan results (banners, organisation, OS) need a key: {KEY_SIGNUP_URLS['shodan']}"
        return result

    try:
        host = shodan.Shodan(keys.shodan).host(ip_address)
    except shodan.APIError as exc:
        message = redact(str(exc), keys)
        if "no information available" in message.lower():
            return {"tool": "shodan", "success": False, "ip": ip_address,
                    "info": f"Shodan has no scan data for {ip_address}"}
        return {"tool": "shodan", "error": f"Shodan API error: {message}"}
    except Exception as exc:  # the shodan library can raise plain exceptions on network errors
        return {"tool": "shodan", "error": f"Shodan query failed: {redact(str(exc), keys)}"}

    services, software, distro_packages = [], [], []
    for item in host.get("data", []) or []:
        if not item.get("port"):
            continue
        # Shodan's version strings can end in a line break, sometimes written out literally as "\r\n".
        product, version = (" ".join(_clean_banner(str(item[k]).replace("\\r", " ").replace("\\n", " "), 80).split())
                            if item.get(k) else None for k in ("product", "version"))
        server_header = _banner_server_header(item.get("data", ""))
        distro_package = distro_package_from_banner(item.get("data", ""))
        if distro_package:
            distro_packages.append({**distro_package, "port": item.get("port")})
        services.append({
            "port": item.get("port"),
            "transport": item.get("transport", "tcp"),
            "product": product,
            "version": version,
            "server_header": server_header,
            "cpe": item.get("cpe23") or item.get("cpe"),
            "module": (item.get("_shodan") or {}).get("module"),
            "seen": (item.get("timestamp") or "")[:10],
            "banner": _clean_banner(item.get("data", ""), banner_limit),
        })
        # Shodan often leaves "product" empty when the banner still names it (e.g. "Server: Dahua Rtsp Server").
        if product:
            name, source = product, "shodan_product"
        elif server_header:
            # "nginx/1.18.0 (Ubuntu)" -> name "nginx", version "1.18.0"
            name = re.split(r"[/\s]v?\d", server_header, maxsplit=1)[0].strip() or server_header
            version, source = version or extract_version(server_header[len(name):]), "server_header"
        else:
            name = None
        if name:
            entry = {"name": name, "version": version, "port": item.get("port"), "source": source}
            if all(e["name"] != entry["name"] or e["version"] != entry["version"] for e in software):
                software.append(entry)

    result: Dict[str, Any] = {
        "tool": "shodan",
        "success": True,
        "ip": ip_address,
        "organization": host.get("org"),
        "isp": host.get("isp"),
        "asn": host.get("asn"),
        "country": host.get("country_name"),
        "city": host.get("city"),
        "os": host.get("os"),
        "hostnames": host.get("hostnames", []),
        "domains": host.get("domains", []),
        "tags": host.get("tags", []),
        "last_update": (host.get("last_update") or "")[:10],
        "open_ports": sorted(host.get("ports", []) or []),
        "services": services,
        "discovered_software": software,
        "note": ("Versions come from service banners. Linux distributions often backport security fixes "
                 "without changing the version string, so banner-based findings need verification."),
    }
    cdn = _cdn_note(f"{host.get('org') or ''} {host.get('isp') or ''}", host.get("tags") or [])
    if cdn:
        result["cdn_note"] = cdn
    kev = kev_matches_for_software([s["name"] for s in software])
    if kev:
        result["cisa_kev_product_matches"] = kev
        result["cisa_kev_note"] = ("Products/vendors seen on this host have CVEs in CISA's Known Exploited "
                                   "Vulnerabilities catalog. This shows real-world exploitation of the product "
                                   "family; it does not confirm this device's firmware is affected.")
    if distro_packages:
        result["distro_packages"] = distro_packages
        result["distro_packages_note"] = ("These banners name the distro package. After the version check, run "
                                          "osint_distro_patch_check with its affected CVE IDs: distros backport "
                                          "fixes without changing the upstream version.")
    vulns = host.get("vulns")
    if vulns:
        vuln_ids = sorted(vulns if isinstance(vulns, list) else vulns.keys())
        result["shodan_inferred_cves"] = vuln_ids[:50]
        result["shodan_inferred_cves_note"] = "Shodan infers these from banner versions; they are unverified."
    if domain_info:
        result["dns"] = domain_info
        result["note_shared_hosting"] = ("Hostnames/domains above belong to the IP and may include unrelated "
                                         "sites on shared or CDN infrastructure.")
    return result


def _rdap_base_url(ip_obj: Any) -> Optional[str]:
    """The registry RDAP service for an address, from IANA's bootstrap file."""
    services = _rdap_bootstrap_cache.get(ip_obj.version)
    if services is None:
        resp = _http_get(RDAP_BOOTSTRAP_URLS[ip_obj.version], timeout=30)
        if resp.status_code != 200:
            raise SourceError(f"IANA RDAP bootstrap returned HTTP {resp.status_code}")
        try:
            services = [(list(s[0]), list(s[1])) for s in resp.json().get("services", [])]
        except (ValueError, AttributeError, TypeError, IndexError) as exc:
            raise SourceError("IANA RDAP bootstrap returned an unexpected response") from exc
        _rdap_bootstrap_cache.set(ip_obj.version, services)
    best = None
    for prefixes, urls in services:
        for prefix in prefixes:
            try:
                network = ipaddress.ip_network(prefix, strict=False)
            except ValueError:
                continue
            if ip_obj in network and (best is None or network.prefixlen > best[0]):
                url = next((u for u in urls if u.startswith("https://")), None)
                if url:
                    best = (network.prefixlen, url)
    return best[1] if best else None


def _rdap_entities(entities: Any) -> Iterable[Dict[str, Any]]:
    for entity in entities or []:
        if isinstance(entity, dict):
            yield entity
            yield from _rdap_entities(entity.get("entities"))


def _vcard(entity: Dict[str, Any], field_name: str) -> Optional[str]:
    try:
        for item in entity.get("vcardArray", [None, []])[1]:
            if item[0] == field_name and isinstance(item[3], str):
                return item[3]
    except (IndexError, TypeError, AttributeError):
        pass
    return None


def osint_ip_owner(ip_address: str) -> Dict[str, Any]:
    """Who an IP's network is registered to, from the regional internet registry (RDAP). No key needed."""
    ok, err = validate_public_ip(ip_address or "")
    if not ok:
        return {"tool": "rdap", "error": err}
    ip_obj = ipaddress.ip_address(ip_address.strip())
    try:
        base = _rdap_base_url(ip_obj)
        if not base:
            return {"tool": "rdap", "success": False, "ip": str(ip_obj),
                    "info": "No registry lists this address block in IANA's RDAP bootstrap"}
        resp = _http_get(f"{base.rstrip('/')}/ip/{ip_obj}", headers={"Accept": "application/rdap+json"})
    except SourceError as exc:
        return {"tool": "rdap", "error": str(exc)}
    if resp.status_code == 404:
        return {"tool": "rdap", "success": False, "ip": str(ip_obj), "info": "The registry has no record for this IP"}
    if resp.status_code != 200:
        return {"tool": "rdap", "error": f"RDAP registry returned HTTP {resp.status_code}"}
    try:
        data = resp.json()
        entities = list(_rdap_entities(data.get("entities")))
    except (ValueError, AttributeError):
        return {"tool": "rdap", "error": "RDAP registry returned an unexpected response"}

    def first(role: str, field_name: str) -> Optional[str]:
        for entity in entities:
            if role in (entity.get("roles") or []):
                value = _vcard(entity, field_name)
                if value:
                    return _clean_banner(value, 120)
        return None

    cidrs = [f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}"
             for c in data.get("cidr0_cidrs") or [] if isinstance(c, dict) and c.get("length") is not None]
    return {
        "tool": "rdap",
        "success": True,
        "ip": str(ip_obj),
        "organization": first("registrant", "fn") or first("administrative", "fn"),
        "network_name": _clean_banner(str(data.get("name") or ""), 80) or None,
        "network_range": (f"{data.get('startAddress')} - {data.get('endAddress')}"
                          if data.get("startAddress") else None),
        "cidr": cidrs[:3],
        "country": _clean_banner(str(data.get("country") or ""), 8) or None,
        "abuse_contact": first("abuse", "email"),
        "registry": urlsplit(base).netloc,
        "note": ("From the regional internet registry. The registered owner can differ from whoever runs the "
                 "service, e.g. a cloud or hosting customer."),
    }


def _spamhaus_drop(version: int) -> Dict[str, Any]:
    """Spamhaus DROP: networks hijacked or run by criminals, downloaded at most once a day."""
    cached = _drop_cache.get(version)
    if cached is not None:
        return cached
    resp = _http_get(SPAMHAUS_DROP_URLS[version], headers={"Accept": "application/json"}, timeout=30, retries=1)
    if resp.status_code != 200:
        raise SourceError(f"Spamhaus DROP returned HTTP {resp.status_code}")
    networks, meta = [], {}
    for line in resp.text.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if row.get("type") == "metadata":
            meta = row
        elif row.get("cidr"):
            try:
                networks.append((ipaddress.ip_network(row["cidr"], strict=False), str(row.get("sblid") or "")))
            except ValueError:
                continue
    if not networks:
        raise SourceError("Spamhaus DROP returned no networks")
    updated = (datetime.fromtimestamp(meta["timestamp"], tz=timezone.utc).date().isoformat()
               if isinstance(meta.get("timestamp"), (int, float)) else None)
    data = {"networks": networks, "updated": updated, "copyright": meta.get("copyright") or "The Spamhaus Project"}
    _drop_cache.set(version, data)
    return data


def _greynoise(ip: str, keys: ApiKeys) -> Dict[str, Any]:
    headers = {"key": keys.greynoise} if keys.greynoise else {}
    resp = _http_get(f"{GREYNOISE_COMMUNITY_URL}/{ip}", headers=headers, retries=1)
    if resp.status_code == 429:
        raise SourceError("GreyNoise limit reached (10 lookups a day without a key)")
    if resp.status_code in (401, 403):
        raise SourceError(f"GreyNoise rejected the API key (HTTP {resp.status_code})")
    if resp.status_code not in (200, 404):
        raise SourceError(f"GreyNoise returned HTTP {resp.status_code}")
    try:
        data = resp.json()
    except ValueError as exc:
        raise SourceError("GreyNoise returned an unexpected response") from exc
    noise, riot = bool(data.get("noise")), bool(data.get("riot"))
    if riot:
        meaning = "a known business or service IP (GreyNoise RIOT), e.g. a public DNS, CDN or SaaS address"
    elif noise:
        meaning = f"seen scanning the internet; GreyNoise classifies it as {data.get('classification') or 'unknown'}"
    else:
        meaning = "not seen scanning the internet (GreyNoise community data)"
    return {"noise": noise, "riot": riot, "classification": data.get("classification"),
            "name": _clean_banner(str(data.get("name") or ""), 80) or None,
            "last_seen": data.get("last_seen"), "meaning": meaning}


def _sans_isc(ip: str) -> Dict[str, Any]:
    """SANS Internet Storm Center (DShield): attack reports from its sensors. Free and keyless, but the data is
    CC BY-NC-SA 4.0 (non-commercial), and SANS asks clients to pause 5 minutes after a 429."""
    resp = _http_get(f"{SANS_ISC_URL}/{ip}?json", retries=0)
    if resp.status_code == 429:
        raise SourceError("SANS ISC is busy and asks clients to wait 5 minutes")
    if resp.status_code != 200:
        raise SourceError(f"SANS ISC returned HTTP {resp.status_code}")
    try:
        data = resp.json().get("ip") or {}
    except (ValueError, AttributeError) as exc:
        raise SourceError("SANS ISC returned an unexpected response") from exc
    reports, attacks = data.get("count") or 0, data.get("attacks") or 0
    feeds = sorted(str(k) for k in (data.get("threatfeeds") or {}))
    if reports or attacks:
        # Sensors log every packet they see, so busy legitimate services (public DNS, CDNs) build up reports too.
        meaning = (f"seen by DShield sensors: {reports} reports and {attacks} attacks, last seen "
                   f"{data.get('maxdate') or 'unknown'} (sensors also log legitimate services such as public DNS)")
    else:
        meaning = "no attack reports from DShield sensors"
    return {"reports": reports, "attacks": attacks, "first_seen": data.get("mindate"),
            "last_seen": data.get("maxdate"), "threat_feeds": feeds[:10],
            "comment": _clean_banner(str(data.get("comment") or ""), 120) or None,
            "meaning": meaning + (f"; listed in threat feeds: {', '.join(feeds[:5])}" if feeds else ""),
            "credit": "SANS Internet Storm Center (DShield), CC BY-NC-SA 4.0"}


def osint_threat_lists_check(ip_address: str, keys: Optional[ApiKeys] = None) -> Dict[str, Any]:
    """Keyless reputation: Spamhaus DROP (criminal or hijacked networks) and GreyNoise (internet scanners)."""
    ok, err = validate_public_ip(ip_address or "")
    if not ok:
        return {"tool": "threat_lists", "error": err}
    ip_obj = ipaddress.ip_address(ip_address.strip())
    keys = keys or ApiKeys()
    result: Dict[str, Any] = {"tool": "threat_lists", "success": True, "ip": str(ip_obj)}
    try:
        drop = _spamhaus_drop(ip_obj.version)
        hit = next(((net, sbl) for net, sbl in drop["networks"] if ip_obj in net), None)
        result["spamhaus_drop"] = {
            "listed": bool(hit),
            "network": str(hit[0]) if hit else None,
            "sbl_id": hit[1] if hit else None,
            "meaning": ("listed: the whole network is hijacked or run by criminals; treat traffic from it as hostile"
                        if hit else "not listed. DROP only covers the worst networks, so this is weak evidence "
                                    "that the IP is clean"),
            "list_date": drop["updated"],
            "credit": f"Spamhaus DROP, {drop['copyright']}",
        }
    except SourceError as exc:
        result["spamhaus_drop"] = {"error": str(exc)}
    if ip_obj.version == 6:
        result["greynoise"] = {"error": "not checked: GreyNoise's community API covers IPv4 addresses only"}
    else:
        try:
            result["greynoise"] = _greynoise(str(ip_obj), keys)
        except SourceError as exc:
            result["greynoise"] = {"error": redact(str(exc), keys)}
    if "error" in result["greynoise"]:  # daily limit, IPv6 or an outage: ask SANS ISC instead
        try:
            result["sans_isc"] = _sans_isc(str(ip_obj))
        except SourceError as exc:
            result["sans_isc"] = {"error": str(exc)}
    sources = [k for k in ("spamhaus_drop", "greynoise", "sans_isc") if k in result]
    if all("error" in result[k] for k in sources):
        return {"tool": "threat_lists", "error": "; ".join(f"{k}: {result[k]['error']}" for k in sources)}
    return result


def osint_subdomains(domain: str, limit: int = 100) -> Dict[str, Any]:
    """Hostnames under a domain that have had TLS certificates, from public certificate transparency logs."""
    domain = (domain or "").strip().lower().rstrip(".")
    if not is_valid_domain(domain):
        return {"tool": "subdomains", "error": f"Invalid domain: {domain!r}"}
    names: set = set()
    source = None
    try:
        resp = _http_get(CRTSH_URL, params={"q": domain, "output": "json", "exclude": "expired",
                                            "deduplicate": "Y"}, timeout=45, retries=1)
        if resp.status_code == 200 and len(resp.content) < 32 * 1024 * 1024:
            for row in resp.json():
                names.update(str(row.get("name_value") or "").split("\n"))
            source = "crt.sh"
    except (SourceError, ValueError, AttributeError, TypeError):
        pass
    if source is None:  # crt.sh is often overloaded; Cert Spotter allows a few keyless lookups an hour
        try:
            resp = _http_get(CERTSPOTTER_URL, params={"domain": domain, "include_subdomains": "true",
                                                      "expand": "dns_names"}, timeout=30, retries=0)
            if resp.status_code == 200:
                for row in resp.json():
                    names.update(str(n) for n in row.get("dns_names") or [])
                source = "Cert Spotter"
            elif resp.status_code == 429:
                return {"tool": "subdomains", "error": "crt.sh is unavailable and Cert Spotter's hourly limit is "
                                                      "reached; try again later"}
        except (SourceError, ValueError, AttributeError, TypeError):
            pass
    if source is None:
        return {"tool": "subdomains", "error": "Certificate transparency search is unavailable (crt.sh and Cert Spotter)"}
    hosts, wildcards = set(), set()
    for name in names:
        name = name.strip().lower().rstrip(".")
        wildcard = name.startswith("*.")
        name = name[2:] if wildcard else name
        if (name == domain or name.endswith("." + domain)) and is_valid_domain(name):
            (wildcards if wildcard else hosts).add(name)
    found = sorted(hosts)
    return {
        "tool": "subdomains",
        "success": bool(found or wildcards),
        "domain": domain,
        "source": source,
        "count": len(found),
        "subdomains": found[:limit],
        **({"subdomains_shown": f"showing {limit} of {len(found)}"} if len(found) > limit else {}),
        "wildcard_certificates": sorted(wildcards)[:20],
        "note": ("From public certificate transparency logs: names that have had TLS certificates. They may no "
                 "longer exist or resolve. Shodan lookups are quota-limited, so check only hosts that matter."),
        **({} if found or wildcards else {"info": f"No certificates found for {domain}"}),
    }


def _cvedb_lookup(cve_id: str, reference_limit: int = 5) -> Optional[Dict[str, Any]]:
    """Shodan's free CVEDB record for one CVE, used only when NVD can't answer."""
    try:
        resp = _http_get(f"{CVEDB_URL}/{cve_id}", retries=1)
        if resp.status_code != 200:
            return None
        data = resp.json()
    except (SourceError, ValueError):
        return None
    if not isinstance(data, dict) or str(data.get("cve_id") or "").upper() != cve_id:
        return None
    for field_name, label in (("cvss_v4", "4.0"), ("cvss_v3", "3.x"), ("cvss_v2", "2.0")):
        if isinstance(data.get(field_name), (int, float)):
            score, version = float(data[field_name]), label
            break
    else:
        score, version = None, None
    result = {
        "tool": "nvd", "success": True, "cve_id": cve_id,
        "data_source": "Shodan CVEDB (NVD unavailable)",
        "published": (data.get("published_time") or "")[:10],
        "description": _clean_banner(str(data.get("summary") or ""), 2000),
        "cvss_score": score, "cvss_version": version, "severity": severity_from_score(score),
        "references": [{"url": u} for u in (data.get("references") or [])[:reference_limit]],
        "affected_products": [str(c) for c in (data.get("cpes") or [])[:15]],
        "note": "NVD couldn't be reached, so these details come from Shodan's CVEDB, a copy of NVD data.",
    }
    if isinstance(data.get("epss"), (int, float)):
        result["epss"] = {"epss": round(float(data["epss"]), 5), "percent": epss_percent(float(data["epss"])),
                          "percentile": data.get("ranking_epss")}
    return result


def osint_virustotal_check(target: str, target_type: str, keys: ApiKeys) -> Dict[str, Any]:
    """VirusTotal reputation for a public IP or domain."""
    if not keys.virustotal:
        return {"tool": "virustotal", "error": f"VirusTotal API key not configured (get one at {KEY_SIGNUP_URLS['virustotal']})"}
    target = (target or "").strip().lower().rstrip(".")
    if target_type == "ip":
        ok, err = validate_public_ip(target)
        if not ok:
            return {"tool": "virustotal", "error": err}
        target = str(ipaddress.ip_address(target))
        path = f"ip_addresses/{target}"
    elif target_type == "domain":
        if not is_valid_domain(target):
            return {"tool": "virustotal", "error": f"Invalid domain: {target!r}"}
        path = f"domains/{target}"
    else:
        return {"tool": "virustotal", "error": "target_type must be 'ip' or 'domain'"}

    try:
        resp = _http_get(f"{VT_URL}/{path}", headers={"x-apikey": keys.virustotal})
    except SourceError as exc:
        return {"tool": "virustotal", "error": str(exc)}
    if resp.status_code == 404:
        return {"tool": "virustotal", "success": False, "info": f"{target} not found in VirusTotal"}
    if resp.status_code in (401, 403):
        return {"tool": "virustotal",
                "error": f"VirusTotal rejected the API key (HTTP {resp.status_code}){_api_error_detail(resp, keys)}"}
    if resp.status_code == 429:
        return {"tool": "virustotal", "error": "VirusTotal quota exceeded (free tier: 4 lookups/minute)"}
    if resp.status_code != 200:
        return {"tool": "virustotal", "error": f"VirusTotal returned HTTP {resp.status_code}"}

    try:
        attrs = (resp.json().get("data") or {}).get("attributes", {}) or {}
    except (ValueError, AttributeError):
        return {"tool": "virustotal", "error": "VirusTotal returned an unexpected response"}
    stats = attrs.get("last_analysis_stats", {}) or {}
    malicious, suspicious = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
    harmless, undetected = int(stats.get("harmless", 0)), int(stats.get("undetected", 0))
    total = sum(int(v) for v in stats.values() if isinstance(v, (int, float)))
    flagged_by = sorted(
        name for name, res in (attrs.get("last_analysis_results") or {}).items()
        if res.get("category") in ("malicious", "suspicious")
    )

    if malicious >= 5:
        level = "HIGH"
    elif malicious >= 2 or (malicious >= 1 and suspicious >= 2):
        level = "MEDIUM"
    elif malicious or suspicious:
        level = "LOW"
    else:
        level = "NONE"

    def as_date(ts: Any) -> Optional[str]:
        return datetime.fromtimestamp(ts, tz=timezone.utc).date().isoformat() if isinstance(ts, (int, float)) else None

    result = {
        "tool": "virustotal",
        "success": True,
        "target": target,
        "target_type": target_type,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "total_engines": total,
        "flagged_by": flagged_by[:20],
        "community_reputation": attrs.get("reputation"),
        "community_votes": attrs.get("total_votes"),
        "last_analysis_date": as_date(attrs.get("last_analysis_date")),
        "threat_level": level,
        "threat_level_basis": ("HIGH >= 5 malicious engines; MEDIUM >= 2; LOW = 1 malicious or any suspicious "
                               "(single-engine hits are often false positives); NONE = no detections"),
        "tags": attrs.get("tags", []),
    }
    if target_type == "ip":
        result.update({"as_owner": attrs.get("as_owner"), "asn": attrs.get("asn"),
                       "country": attrs.get("country"), "network": attrs.get("network")})
    else:
        result.update({"registrar": attrs.get("registrar"), "categories": attrs.get("categories", {}),
                       "creation_date": as_date(attrs.get("creation_date"))})
    return result


def osint_abuseipdb_check(ip_address: str, keys: ApiKeys, max_age_days: int = 90) -> Dict[str, Any]:
    """AbuseIPDB abuse reports for a public IP (direct v2 API)."""
    if not keys.abuseipdb:
        return {"tool": "abuseipdb", "error": f"AbuseIPDB API key not configured (get one at {KEY_SIGNUP_URLS['abuseipdb']})"}
    ok, err = validate_public_ip(ip_address or "")
    if not ok:
        return {"tool": "abuseipdb", "error": err}
    ip_address = str(ipaddress.ip_address(ip_address.strip()))
    try:
        resp = _http_get(ABUSEIPDB_URL, params={"ipAddress": ip_address, "maxAgeInDays": max_age_days},
                         headers={"Key": keys.abuseipdb})
    except SourceError as exc:
        return {"tool": "abuseipdb", "error": str(exc)}
    if resp.status_code in (401, 403):
        return {"tool": "abuseipdb",
                "error": f"AbuseIPDB rejected the API key (HTTP {resp.status_code}){_api_error_detail(resp, keys)}"}
    if resp.status_code == 429:
        return {"tool": "abuseipdb", "error": "AbuseIPDB daily quota exceeded"}
    if resp.status_code != 200:
        return {"tool": "abuseipdb", "error": f"AbuseIPDB returned HTTP {resp.status_code}"}

    try:
        data = resp.json().get("data", {}) or {}
        score = int(data.get("abuseConfidenceScore", 0) or 0)
    except (ValueError, AttributeError, TypeError):
        return {"tool": "abuseipdb", "error": "AbuseIPDB returned an unexpected response"}
    level = "HIGH" if score >= 75 else "MEDIUM" if score >= 25 else "LOW" if score > 0 else "NONE"
    return {
        "tool": "abuseipdb",
        "success": True,
        "ip": ip_address,
        "abuse_confidence_percent": score,  # 0-100; the name keeps the model from reading 9 as 9/10
        "threat_level": level,
        "total_reports": data.get("totalReports", 0),
        "distinct_reporters": data.get("numDistinctUsers", 0),
        "last_reported": data.get("lastReportedAt"),
        "report_window_days": max_age_days,
        "is_whitelisted": data.get("isWhitelisted"),
        "is_tor": data.get("isTor"),
        "usage_type": data.get("usageType"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "hostnames": data.get("hostnames", []),
        "country": data.get("countryCode"),
    }


def osint_nvd_lookup(cve_id: str, keys: Optional[ApiKeys] = None, reference_limit: int = 5,
                     config_limit: int = 5) -> Dict[str, Any]:
    """Full NVD record for one CVE, enriched with CISA KEV status and EPSS."""
    cve_id = (cve_id or "").strip().upper()
    if not is_valid_cve(cve_id):
        return {"tool": "nvd", "error": f"Invalid CVE ID: {cve_id!r} (expected CVE-YYYY-NNNN)"}
    try:
        data = _nvd_get(NVD_CVE_URL, {"cveId": cve_id}, keys)
    except SourceError as exc:
        fallback = _cvedb_lookup(cve_id, reference_limit)
        if not fallback:
            return {"tool": "nvd", "error": str(exc)}
        kev = kev_lookup_many([cve_id]).get(cve_id)  # KEV status from CISA itself, not the copy
        if kev:
            fallback["cisa_kev"] = kev
        fallback["in_cisa_kev"] = bool(kev)
        fallback["nvd_error"] = str(exc)
        return fallback
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return {"tool": "nvd", "success": False, "info": f"{cve_id} not found in NVD"}
    cve = vulns[0].get("cve", {})
    summary = summarize_nvd_cve(cve, description_limit=2000, reference_limit=reference_limit)

    affected = []
    for config in cve.get("configurations", []) or []:
        for node in config.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                if match.get("vulnerable"):
                    affected.append(_describe_range(match))
    summary["affected_products"] = list(dict.fromkeys(affected))[: config_limit * 3]
    if summary.get("status") == "Rejected":
        summary["warning"] = "This CVE has been REJECTED and should not be treated as a real vulnerability."

    kev = kev_lookup_many([cve_id]).get(cve_id)
    if kev:
        summary["cisa_kev"] = kev
    summary["in_cisa_kev"] = bool(kev or summary.get("cisa_kev"))
    epss = epss_lookup_many([cve_id]).get(cve_id)
    if epss:
        summary["epss"] = epss
    exploit = exploit_lookup_many([cve_id]).get(cve_id)
    if exploit:
        summary["public_exploit"] = exploit
    return {"tool": "nvd", "success": True, **summary}


def osint_cve_search(search_term: str, keys: Optional[ApiKeys] = None, result_limit: int = 10) -> Dict[str, Any]:
    """Keyword search of NVD; returns the most recently published matching CVEs."""
    term = " ".join((search_term or "").split())[:100]
    if not term:
        return {"tool": "cve_search", "error": "search_term is required"}
    if is_valid_cve(term):
        return osint_nvd_lookup(term, keys)
    try:
        # Fetch extra: NVD's keyword search also matches inside words ("ADT" hits "adt7470", "AdTribes").
        total, fetched = _nvd_most_recent({"keywordSearch": term}, keys, max(result_limit * 4, 40))
    except SourceError as exc:
        return {"tool": "cve_search", "error": str(exc)}
    if not fetched:
        return {"tool": "cve_search", "success": False, "info": f"No CVEs in NVD match {term!r}"}
    cves = [c for c in fetched if mentions_whole_words(_english_description(c), term)]
    if not cves:
        return {"tool": "cve_search", "success": False, "search_term": term,
                "info": (f"NVD matched {term!r} only inside other words (e.g. other product names), so none of "
                         f"the {len(fetched)} most recent results are about {term!r}. Treat as no CVEs found.")}
    whole_word_count = len(cves)
    cves = cves[:result_limit]
    vulns = [summarize_nvd_cve(c, description_limit=300, reference_limit=0) for c in cves]
    for v in vulns:
        v.pop("references", None)
    _enrich_with_exploit_intel(vulns)
    return {
        "tool": "cve_search",
        "success": True,
        "search_term": term,
        "total_matches": total,
        "whole_word_matches_in_sample": f"{whole_word_count} of the {len(fetched)} most recent",
        "returned": len(vulns),
        "vulnerabilities": vulns,
        "note": ("Keyword matches on CVE descriptions are NOT version-checked. Use "
                 "osint_version_specific_vulnerability_check when a version is known."),
    }


def osint_cisa_kev_check(cve_ids: Optional[Sequence[str]] = None,
                         software_list: Optional[Sequence[str]] = None, kev_limit: int = 10,
                         cve_id: Optional[str] = None) -> Dict[str, Any]:
    """Check CVE IDs and/or product names against CISA's Known Exploited Vulnerabilities catalog."""
    def as_list(value: Any) -> List[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [part for part in re.split(r"[,\n]", value)]
        return [str(v) for v in value]

    ids = [c.strip().upper() for c in as_list(cve_ids) + as_list(cve_id) if c and c.strip()]
    ids = list(dict.fromkeys(ids))[:50]
    invalid = [c for c in ids if not is_valid_cve(c)]
    ids = [c for c in ids if is_valid_cve(c)]
    software = [s.strip() for s in as_list(software_list) if s and s.strip()][:20]
    if not ids and not software:
        return {"tool": "cisa_kev", "error": "Provide cve_ids and/or software_list"}
    try:
        catalog = _load_kev_catalog()
    except SourceError as exc:
        return {"tool": "cisa_kev", "error": str(exc)}

    cve_results = {c: (_kev_entry_summary(catalog["by_cve"][c]) if c in catalog["by_cve"] else None) for c in ids}
    software_matches: Dict[str, List[Dict[str, Any]]] = {}
    software_totals: Dict[str, int] = {}
    for name in software:
        hits = [_kev_entry_summary(v) for v in catalog["vulnerabilities"] if kev_matches_software(v, name)]
        hits.sort(key=lambda m: m.get("date_added") or "", reverse=True)
        software_totals[name] = len(hits)
        software_matches[name] = hits[:kev_limit]
    _add_epss([v for v in cve_results.values() if v] + [e for hits in software_matches.values() for e in hits])

    result: Dict[str, Any] = {
        "tool": "cisa_kev",
        "success": True,
        "catalog_date": catalog["date_released"],
        "catalog_size": len(catalog["vulnerabilities"]),
    }
    if ids:
        result["cve_results"] = {c: (v or "NOT IN KEV") for c, v in cve_results.items()}
        result["cves_in_kev"] = [c for c, v in cve_results.items() if v]
    if invalid:
        result["invalid_cve_ids"] = invalid
    if software:
        result["software_matches"] = {
            name: {"total_kev_entries": software_totals[name], "most_recent": hits,
                   **({"shown": f"showing {len(hits)} of {software_totals[name]}"}
                      if software_totals[name] > len(hits) else {})}
            for name, hits in software_matches.items()
        }
        result["software_note"] = ("Product-level KEV matches show that this product has had exploited flaws; "
                                   "they do NOT mean the target's version is affected.")
    return result


def osint_version_specific_vulnerability_check(software_name: str, keys: Optional[ApiKeys] = None,
                                               version: Optional[str] = None, result_limit: int = 10,
                                               not_affected_limit: int = 5) -> Dict[str, Any]:
    """Find CVEs whose NVD CPE configuration actually includes this exact product version."""
    name = " ".join(str(software_name or "").split())[:80]
    if not name:
        return {"tool": "version_check", "error": "software_name is required"}
    version = str(version).strip() if version is not None else ""
    version = extract_version(version) if version.lower() not in ("unknown", "none", "n/a", "") else None

    try:
        products = _resolve_products(name, keys)
    except SourceError as exc:
        return {"tool": "version_check", "error": str(exc)}
    if not products:
        return {"tool": "version_check", "success": False, "software": name,
                "info": f"Could not map {name!r} to an NVD product (CPE). Try osint_cve_search instead."}

    if not version:
        try:
            vendor, product = products[0]
            total, cves = _nvd_most_recent({"virtualMatchString": f"cpe:2.3:*:{vendor}:{product}"}, keys, result_limit)
        except SourceError as exc:
            return {"tool": "version_check", "error": str(exc)}
        vulns = [summarize_nvd_cve(c, description_limit=250, reference_limit=0) for c in cves]
        _enrich_with_exploit_intel(vulns)
        return {
            "tool": "version_check",
            "success": True,
            "software": name,
            "cpe_products": [f"{v}:{p}" for v, p in products],
            "version": None,
            "security_status": "UNKNOWN_VERSION",
            "total_cves_for_product": total,
            "most_recent_cves": vulns,
            "note": "No version supplied: these are the product's most recent CVEs, not confirmed to affect it.",
        }

    affected, not_affected, unanalyzed = [], [], []
    seen: set = set()
    candidates_total, truncated = 0, False
    # NVD serves 100-record pages in seconds but often drops 500-record ones after minutes (seen with PHP 4.3.8).
    page_size, max_pages = 100, 10
    try:
        for vendor, product in products:
            for page in range(max_pages):
                data = _nvd_get(NVD_CVE_URL, {
                    "virtualMatchString": f"cpe:2.3:*:{vendor}:{product}",
                    "versionStart": version, "versionStartType": "including",
                    "versionEnd": version, "versionEndType": "including",
                    "resultsPerPage": page_size, "startIndex": page * page_size,
                }, keys)
                total = int(data.get("totalResults", 0))
                for wrapper in data.get("vulnerabilities", []):
                    cve = wrapper.get("cve", {})
                    if cve.get("vulnStatus") == "Rejected" or cve.get("id") in seen:
                        continue
                    seen.add(cve.get("id"))
                    verdict = assess_cve_for_version(cve, vendor, product, version)
                    entry = {**summarize_nvd_cve(cve, description_limit=250, reference_limit=0), **verdict}
                    entry.pop("references", None)
                    buckets = {"AFFECTED": affected, "NOT_AFFECTED": not_affected}
                    buckets.get(verdict["status"], unanalyzed).append(entry)
                if (page + 1) * page_size >= total:
                    break
            else:
                truncated = True
            candidates_total += total
    except SourceError as exc:
        return {"tool": "version_check", "error": str(exc)}

    # Package advisories first: they confirm CVEs NVD hasn't analysed and add ones it doesn't have at all.
    package_ref, advisories_added, package_error, package_ids = None, 0, None, set()
    try:
        package_ref, advisories, package_ids = _package_advisories(products, version)
    except (SourceError, ValueError, AttributeError) as exc:
        advisories, package_error = [], str(exc)
    for adv in advisories:
        known = {v["cve_id"] for v in affected} | {v["cve_id"] for v in not_affected}
        if adv["cve_id"] in known:
            continue  # NVD already judged it for this version
        unanalyzed[:] = [v for v in unanalyzed if v["cve_id"] != adv["cve_id"]]
        affected.append(adv)
        seen.add(adv["cve_id"])
        advisories_added += 1

    recent_checked = True
    try:
        for cve in _recent_unanalyzed_cves(name, products, keys, seen):
            seen.add(cve.get("id"))
            entry = {**summarize_nvd_cve(cve, description_limit=400, reference_limit=0), "status": "UNANALYZED",
                     "reason": ("Published recently and not analysed by NVD yet, so its affected versions aren't "
                                "checked. Read the description to see whether this version is covered.")}
            if _description_covers(_english_description(cve), version):
                entry["description_covers_this_version"] = True
            entry.pop("references", None)
            unanalyzed.append(entry)
        if not candidates_total:
            for cve in _keyword_fallback_cves(name, products, keys, seen):
                seen.add(cve.get("id"))
                entry = {**summarize_nvd_cve(cve, description_limit=400, reference_limit=0), "status": "UNANALYZED",
                         "reason": ("Found by keyword: NVD files this CVE under a different product name, so this "
                                    "version wasn't checked against it. Read the description to see whether it applies.")}
                if _description_covers(_english_description(cve), version):
                    entry["description_covers_this_version"] = True
                entry.pop("references", None)
                unanalyzed.append(entry)
    except SourceError:
        recent_checked = False

    # A needs-review CVE the package's advisories cover, but not at this version, is ruled out by them.
    affecting = {a["cve_id"] for a in advisories}
    for v in list(unanalyzed):
        if v["cve_id"] in package_ids and v["cve_id"] not in affecting:
            unanalyzed.remove(v)
            not_affected.append({**v, "status": "NOT_AFFECTED",
                                 "reason": f"The {package_ref} advisory doesn't list this version as affected",
                                 "affected_ranges": [f"see the {package_ref} advisory"]})

    def score(v: Dict[str, Any]) -> float:
        # Advisory-only entries have a severity but no computed CVSS score; rank them by severity.
        return v.get("cvss_score") or {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.0}.get(v.get("severity"), 0.0)

    def sort_key(v: Dict[str, Any]) -> Tuple[float, str]:
        return (score(v), v.get("published") or "")

    affected.sort(key=sort_key, reverse=True)
    unanalyzed.sort(key=sort_key, reverse=True)
    _enrich_with_exploit_intel(affected + unanalyzed)
    # Exploited in the wild first, then most likely to be exploited (EPSS), then by CVSS.
    affected.sort(key=lambda v: (bool(v.get("in_cisa_kev")), (v.get("epss") or {}).get("epss") or 0.0,
                                 score(v)), reverse=True)
    no_fix = [v["cve_id"] for v in affected if not (v.get("fixed_in") or v.get("fixed_after"))]

    no_match_note, version_mismatch = (_no_candidates_note(products, version, keys) if not candidates_total
                                       else (None, False))
    if affected:
        status = "VULNERABLE"
    elif unanalyzed:
        status = "REVIEW_NEEDED"
    elif version_mismatch:
        status = "VERSION_NOT_MATCHED"  # NVD has CVEs for the product but numbers its versions another way
    else:
        status = "NO_KNOWN_VULNERABILITIES"

    severity_counts: Dict[str, int] = {}
    for v in affected:
        severity_counts[v["severity"]] = severity_counts.get(v["severity"], 0) + 1

    return {
        "tool": "version_check",
        "success": True,
        "software": name,
        "version": version,
        "cpe_products": [f"{v}:{p}" for v, p in products],
        "security_status": status,
        "affected_count": len(affected),
        "affected_by_severity": severity_counts,
        "affected_in_cisa_kev": [v["cve_id"] for v in affected if v.get("in_cisa_kev")],
        "upgrade_to_at_least": _upgrade_with_review_note(minimum_safe_version(affected), unanalyzed),
        **({} if recent_checked else {"recent_cves_note": "The search for recent CVEs NVD hasn't analysed yet "
                                                          "failed, so very new advisories may be missing."}),
        "patch_status_summary": {"fix_listed": len(affected) - len(no_fix), "no_fix_listed": len(no_fix)},
        "no_fix_listed_cves": no_fix,
        "affected_cve_ids": [v["cve_id"] for v in affected],  # every one, for osint_distro_patch_check
        "affected_cves": affected[:result_limit],
        "needs_review_count": len(unanalyzed),
        "needs_review_cves": unanalyzed[: max(3, result_limit // 2)],
        **({"package_advisories": {"package": package_ref, "added": advisories_added,
                                   "source": "GitHub Advisory Database via OSV.dev"}} if package_ref else {}),
        **({"package_advisories_note": f"The package advisory check failed ({package_error})."}
           if package_error else {}),
        "lists_shortened": {k: v for k, v in (
            ("affected_cves", f"showing {min(len(affected), result_limit)} of {len(affected)}"
             if len(affected) > result_limit else None),
            ("needs_review_cves", f"showing {max(3, result_limit // 2)} of {len(unanalyzed)}"
             if len(unanalyzed) > max(3, result_limit // 2) else None),
            ("ruled_out_examples", f"showing {not_affected_limit} of {len(not_affected)}"
             if len(not_affected) > not_affected_limit else None)) if v},
        "nvd_candidates_checked": len(seen),
        "nvd_candidates_total": candidates_total,
        **({"no_candidates_note": no_match_note} if no_match_note else {}),
        "results_truncated": truncated,
        "ruled_out_count": len(not_affected),
        "ruled_out_examples": [{"cve_id": v["cve_id"], "affected_ranges": v.get("affected_ranges")}
                               for v in not_affected[:not_affected_limit]],
        "method": ("Matched against NVD CPE configurations: a CVE counts as AFFECTED only when this exact version "
                   "falls inside an NVD-listed vulnerable range for the product."),
        "caveats": [
            "NO_KNOWN_VULNERABILITIES means no matching NVD records, not that the software is secure.",
            "Distribution packages (Debian/Ubuntu/RHEL) often backport fixes without changing the version string.",
            "Some CVEs only apply with specific modules, configurations, or platforms.",
        ],
    }


# NVD products that are also packages, mapped to their OSV ecosystem and package name. GitHub's advisory
# database (served through OSV) usually has new advisories for these hours or days before NVD analyses them.
_PACKAGE_ECOSYSTEMS = {
    "next.js": ("npm", "next"), "react": ("npm", "react"), "express": ("npm", "express"),
    "lodash": ("npm", "lodash"), "axios": ("npm", "axios"), "jquery": ("npm", "jquery"),
    "django": ("PyPI", "django"), "flask": ("PyPI", "flask"), "requests": ("PyPI", "requests"),
    "log4j": ("Maven", "org.apache.logging.log4j:log4j-core"),
    "spring_framework": ("Maven", "org.springframework:spring-core"), "rails": ("RubyGems", "rails"),
}
_ADVISORY_SEVERITY = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MODERATE": "MEDIUM", "MEDIUM": "MEDIUM", "LOW": "LOW"}


def _package_known_ids(ecosystem: str, package: str) -> set:
    """Every CVE and advisory ID OSV has for a package, at any version."""
    ids: set = set()
    body: Dict[str, Any] = {"package": {"name": package, "ecosystem": ecosystem}}
    for _ in range(5):
        resp = _http_get(OSV_QUERY_URL, json_body=body, timeout=30)
        if resp.status_code != 200:
            raise SourceError(f"OSV.dev returned HTTP {resp.status_code}")
        data = resp.json()
        for vuln in data.get("vulns", []) or []:
            ids.add(str(vuln.get("id")).upper())
            ids.update(str(a).upper() for a in vuln.get("aliases") or [])
        if not data.get("next_page_token"):
            break
        body = {**body, "page_token": data["next_page_token"]}
    return ids


def _package_advisories(products: List[Tuple[str, str]], version: str) -> Tuple[Optional[str], List[Dict[str, Any]], set]:
    """("ecosystem:package", advisories OSV says affect this exact version, every ID OSV has for the package),
    for products that are packages."""
    for _, product in products:
        if product not in _PACKAGE_ECOSYSTEMS:
            continue
        ecosystem, package = _PACKAGE_ECOSYSTEMS[product]
        resp = _http_get(OSV_QUERY_URL, json_body={"package": {"name": package, "ecosystem": ecosystem},
                                                   "version": version}, timeout=30)
        if resp.status_code != 200:
            raise SourceError(f"OSV.dev returned HTTP {resp.status_code}")
        try:
            vulns = resp.json().get("vulns", []) or []
        except (ValueError, AttributeError) as exc:
            raise SourceError("OSV.dev returned invalid JSON") from exc
        advisories = []
        for vuln in vulns:
            cve = next((a.upper() for a in vuln.get("aliases") or [] if is_valid_cve(a)), None)
            fixes = [e["fixed"] for a in vuln.get("affected", []) or []
                     if (a.get("package") or {}).get("name") == package
                     for r in a.get("ranges", []) or [] for e in r.get("events", []) or [] if e.get("fixed")]
            later = sorted((f for f in fixes if compare_versions(f, version) > 0), key=_version_tokens)
            severity = _ADVISORY_SEVERITY.get(str((vuln.get("database_specific") or {}).get("severity", "")).upper(),
                                              "UNKNOWN")
            entry = {
                "cve_id": cve or vuln.get("id"), "advisory_id": vuln.get("id"), "status": "AFFECTED",
                "source": "GitHub Advisory via OSV.dev", "severity": severity, "cvss_score": None,
                "cvss_vector": next((x.get("score") for x in vuln.get("severity", []) or []), None),
                "published": (vuln.get("published") or "")[:10],
                "description": _clean_banner(str(vuln.get("summary") or vuln.get("details") or ""), 300),
                "matched_range": f"{ecosystem} {package} " + (f"before {later[0]}" if later else "(no fix listed)"),
            }
            if later:
                entry["fixed_in"] = later[0]
            entry["patch_status"] = patch_status(entry).replace("per NVD", "per the advisory")
            advisories.append(entry)
        return f"{ecosystem}:{package}", advisories, _package_known_ids(ecosystem, package)
    return None, [], set()


_UNANALYZED_STATUSES = {"Received", "Awaiting Analysis", "Undergoing Analysis"}
RECENT_CVE_DAYS = 90


def _search_term(name: str, products: List[Tuple[str, str]]) -> str:
    """Words CVE descriptions use for the product: "next.js", "apache http server", or the user's own words."""
    vendor, product = products[0]
    words = product.replace("_", " ")
    typed = _DAEMON_SUFFIXES.sub("", normalize_software_name(name))
    if " " not in words:
        return words  # "next.js", "gitlab", "php"
    if words in typed:
        return typed  # the user named the product as descriptions do ("solarview compact", "apache http server")
    if vendor != "*" and len(words.split()) <= 2 and vendor not in words:
        return f"{vendor} {words}"  # "apache http server"
    return _DAEMON_SUFFIXES.sub("", normalize_software_name(name))  # long CPE names: use the user's words


def _recent_unanalyzed_cves(name: str, products: List[Tuple[str, str]], keys: Optional[ApiKeys],
                            seen: set) -> List[Dict[str, Any]]:
    """Recent CVEs that mention the product but that NVD hasn't analysed (so they have no CPE data yet).

    One request: NVD filters by publication date itself, which matters without a key (5 requests per 30 s).
    """
    term = _search_term(name, products)
    end = datetime.now(timezone.utc)
    start = end.fromordinal(end.toordinal() - RECENT_CVE_DAYS)
    data = _nvd_get(NVD_CVE_URL, {"keywordSearch": term, "resultsPerPage": 200,
                                  "pubStartDate": start.strftime("%Y-%m-%dT00:00:00.000"),
                                  "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000")}, keys)
    return [cve for cve in (v.get("cve", {}) for v in data.get("vulnerabilities", []))
            if cve.get("vulnStatus") in _UNANALYZED_STATUSES and cve.get("id") not in seen
            and _description_is_about(_english_description(cve), term)]


def _no_candidates_note(products: List[Tuple[str, str]], version: str, keys: Optional[ApiKeys]) -> Tuple[str, bool]:
    """Why a version matched nothing, and whether NVD has CVEs for the product but writes its versions differently."""
    names = ", ".join(f"{v}:{p}" for v, p in products)
    examples: List[str] = []
    try:
        vendor, product = products[0]
        _, recent = _nvd_most_recent({"virtualMatchString": f"cpe:2.3:*:{vendor}:{product}"}, keys, 20)
        for cve in recent:
            for config in cve.get("configurations", []) or []:
                for node in config.get("nodes", []) or []:
                    for match in node.get("cpeMatch", []) or []:
                        cpe = _parse_cpe(match.get("criteria", ""))
                        if cpe["product"] == product and cpe["version"] not in ("*", "-", ""):
                            label = cpe["version"] + (f" {cpe['update']}" if cpe["update"] not in ("*", "-", "") else "")
                            if label not in examples:
                                examples.append(label)
    except SourceError:
        pass
    if examples:
        return (f"NVD has CVEs for {names}, but none at version {version}. NVD writes this product's versions like: "
                f"{', '.join(examples[:5])}. Retry with a version in that form, or check the vendor's advisories. "
                "Don't treat this version as safe."), True
    return (f"NVD has no CVEs recorded for {names} {version}. Very recent advisories can take days to reach NVD, so "
            "check the vendor's security advisories. If you expected older CVEs, the name may map to a different "
            "product: retry with the vendor and product name, or use osint_cve_search."), False


def _keyword_fallback_cves(name: str, products: List[Tuple[str, str]], keys: Optional[ApiKeys],
                           seen: set) -> List[Dict[str, Any]]:
    """When NVD has no CVEs for the product's CPE at all, the CVEs may be filed under another product name
    (SolarView Compact's are under the firmware's model code). Find them by keyword instead."""
    term = _search_term(name, products)
    vendor = products[0][0]
    _, cves = _nvd_most_recent({"keywordSearch": term}, keys, 50)

    def judged_for_product(cve: Dict[str, Any]) -> bool:
        # NVD already matched this CVE against the product's CPE and found this version unaffected.
        return any(_cpe_product_matches(m.get("criteria", ""), v, p) for v, p in products
                   for c in cve.get("configurations", []) or [] for n in c.get("nodes", []) or []
                   for m in n.get("cpeMatch", []) or [])

    return [cve for cve in cves if cve.get("id") not in seen and cve.get("vulnStatus") != "Rejected"
            and not judged_for_product(cve) and _description_is_about(_english_description(cve), term, vendor)]


# How CVE descriptions usually open before naming the affected product.
_DESCRIPTION_LEADS = re.compile(r"^(?:an? (?:issue|vulnerability|flaw|security issue) (?:has been |was )?"
                                r"(?:discovered|found|identified|reported)? ?in |in |the )", re.IGNORECASE)


def _description_is_about(description: str, term: str, vendor: str = "*") -> bool:
    """Is the CVE about ``term`` itself? Its description opens with the product name ("GitLab has...",
    "In PHP versions..."), not with another product that only mentions it ("PhpSpreadsheet is a pure PHP
    library", "NextAuth.js provides authentication for Next.js")."""
    text = _DESCRIPTION_LEADS.sub("", description.strip(), count=1)
    if vendor != "*" and text.lower().startswith(vendor.lower() + " ") and not term.lower().startswith(vendor.lower()):
        text = text[len(vendor) + 1:]  # "CONTEC SolarView Compact ..." is about "solarview compact"
    return mentions_whole_words(text[:len(term) + 1], term) and text.lower().startswith(term.split()[0].lower())


_DESCRIPTION_RANGE = re.compile(r"(?:from |versions? )?(\d+(?:\.\d+)+)\s+(?:before|until|up to|prior to)\s+"
                                r"(\d+(?:\.\d+)+)", re.IGNORECASE)


def _description_covers(description: str, version: str) -> bool:
    """True when a "from X before Y" style range in the description includes ``version`` (a hint, not a verdict)."""
    return any(compare_versions(version, low) >= 0 and compare_versions(version, high) < 0
               for low, high in _DESCRIPTION_RANGE.findall(description))


def _upgrade_with_review_note(upgrade: Optional[Dict[str, Any]], unanalyzed: List[Dict[str, Any]]):
    """The minimum safe version only covers CVEs NVD has analysed; say so when others need review."""
    if upgrade and unanalyzed:
        upgrade = {**upgrade, "review_note": (f"Doesn't account for {len(unanalyzed)} CVE(s) NVD hasn't analysed "
                                              "yet (see needs_review_cves); they may need a later version.")}
    return upgrade


def _resolve_products(name: str, keys: Optional[ApiKeys]) -> List[Tuple[str, str]]:
    """Map a free-form software name to NVD CPE (vendor, product) pairs."""
    alias = resolve_cpe_alias(name)
    if alias:
        return [alias]
    normalized = _DAEMON_SUFFIXES.sub("", normalize_software_name(name))
    if normalized in _GENERIC_SOFTWARE_NAMES or len(normalized) < 2:
        return []
    guess = normalized.replace(" ", "_")
    wanted = set(re.findall(r"[a-z0-9.+]+", normalized))
    data = _nvd_get(NVD_CPE_URL, {"keywordSearch": normalized, "resultsPerPage": 100}, keys)
    counts: Dict[Tuple[str, str], int] = {}
    for item in data.get("products", []):
        cpe = _parse_cpe(item.get("cpe", {}).get("cpeName", ""))
        pair = (cpe["vendor"], cpe["product"])
        counts[pair] = counts.get(pair, 0) + 1
    # Devices often have a hardware CPE and a firmware CPE, and the CVEs are usually filed under the firmware
    # (SolarView Compact's are under solarview_compact_firmware), so include it.
    exact = [p for p in counts if p[1] in (guess, guess + "_firmware")]
    if exact:
        firmware = [p for p in exact if p[1].endswith("_firmware")]
        return (firmware + sorted((p for p in exact if p not in firmware), key=lambda p: -counts[p]))[:2]
    if len(wanted) < 2:
        # A single word ("all", "server", "dahua") is too ambiguous to match partially; it must be the exact product.
        return []
    # Only accept a product whose vendor/product names contain every word the user gave
    # ("apache struts" -> apache:struts). Guessing an unrelated product would produce false findings.
    covering = [p for p in counts
                if wanted <= set(re.findall(r"[a-z0-9.+]+", f"{p[0]} {p[1]}".replace("_", " ").lower()))]
    return sorted(covering, key=lambda p: -counts[p])[:2]


# Tool registry used by the agent: tool name -> function.
TOOL_FUNCTIONS = {
    "osint_resolve_domain": osint_resolve_domain,
    "osint_shodan_search": osint_shodan_search,
    "osint_virustotal_check": osint_virustotal_check,
    "osint_abuseipdb_check": osint_abuseipdb_check,
    "osint_cve_search": osint_cve_search,
    "osint_cisa_kev_check": osint_cisa_kev_check,
    "osint_nvd_lookup": osint_nvd_lookup,
    "osint_version_specific_vulnerability_check": osint_version_specific_vulnerability_check,
    "osint_distro_patch_check": osint_distro_patch_check,
    "osint_ip_owner": osint_ip_owner,
    "osint_threat_lists_check": osint_threat_lists_check,
    "osint_subdomains": osint_subdomains,
}
