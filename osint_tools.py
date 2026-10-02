"""OSINT data-source tools used by the AI agent.

Every tool returns a JSON-serialisable dict with a ``tool`` key and either
``success: True`` plus data, ``success: False`` plus ``info`` (nothing found),
or ``error`` (the lookup failed). Tools never raise.

API keys are passed in explicitly via :class:`ApiKeys` so that concurrent
users of a shared deployment never see or use each other's keys.
"""

from __future__ import annotations

import ipaddress
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
}

@dataclass(frozen=True)
class ApiKeys:
    """API keys for a single analysis run. Never stored in module globals."""

    cohere: str = ""
    shodan: str = ""
    virustotal: str = ""
    abuseipdb: str = ""
    nvd: str = ""

    @classmethod
    def from_env(cls) -> "ApiKeys":
        return cls(
            cohere=os.getenv("COHERE_API_KEY", ""),
            shodan=os.getenv("SHODAN_API_KEY", ""),
            virustotal=os.getenv("VIRUSTOTAL_API_KEY", "") or os.getenv("VT_API_KEY", ""),
            abuseipdb=os.getenv("ABUSEIPDB_API_KEY", ""),
            nvd=os.getenv("NVD_API_KEY", ""),
        )

    def with_overrides(self, **overrides: str) -> "ApiKeys":
        """Return a copy where any non-empty override replaces the current value."""
        values = {k: (overrides.get(k) or "").strip() or getattr(self, k) for k in self.__dataclass_fields__}
        return ApiKeys(**values)

    def secrets(self) -> List[str]:
        return [v for v in (self.cohere, self.shodan, self.virustotal, self.abuseipdb, self.nvd) if v]


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
    def __init__(self, ttl_seconds: float, maxsize: int = 1024):
        self._ttl = ttl_seconds
        self._maxsize = maxsize
        self._data: Dict[Any, Tuple[float, Any]] = {}
        self._lock = threading.Lock()

    def get(self, key: Any) -> Any:
        with self._lock:
            item = self._data.get(key)
            if item and time.monotonic() - item[0] < self._ttl:
                return item[1]
            self._data.pop(key, None)
            return None

    def set(self, key: Any, value: Any) -> None:
        with self._lock:
            if len(self._data) >= self._maxsize:
                oldest = min(self._data, key=lambda k: self._data[k][0])
                self._data.pop(oldest, None)
            self._data[key] = (time.monotonic(), value)


class _RateLimiter:
    """Rolling-window limiter (NVD allows 5 req/30s without a key, 50 with one)."""

    def __init__(self, period: float):
        self._period = period
        self._calls: deque = deque()
        self._lock = threading.Lock()

    def wait(self, max_calls: int) -> None:
        with self._lock:
            now = time.monotonic()
            while self._calls and now - self._calls[0] >= self._period:
                self._calls.popleft()
            if len(self._calls) >= max_calls:
                time.sleep(max(0.0, self._period - (now - self._calls[0])) + 0.1)
                now = time.monotonic()
                while self._calls and now - self._calls[0] >= self._period:
                    self._calls.popleft()
            self._calls.append(time.monotonic())


_nvd_cache = _TTLCache(ttl_seconds=3600)
_epss_cache = _TTLCache(ttl_seconds=12 * 3600, maxsize=5000)
_kev_cache = _TTLCache(ttl_seconds=6 * 3600, maxsize=1)
_nvd_limiter = _RateLimiter(period=30.0)


class SourceError(Exception):
    """A data source could not be reached or returned an unusable response."""


def _http_get(url: str, *, params: Optional[dict] = None, headers: Optional[dict] = None,
              timeout: float = HTTP_TIMEOUT, retries: int = 2) -> requests.Response:
    merged_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    merged_headers.update(headers or {})
    last_error = ""
    for attempt in range(retries + 1):
        try:
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
    if SOFTWARE_NAME_RE.fullmatch(value) and not re.fullmatch(r"[\d.]+", value):
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
    return SOFTWARE_CPE_ALIASES.get(stripped)


def extract_version(text: Optional[str]) -> Optional[str]:
    """Pull the first version-looking token out of a string ("OpenSSH_8.9p1 Ubuntu" -> "8.9p1")."""
    if not text:
        return None
    match = re.search(r"(\d+(?:\.\d+)*[a-z0-9]*)", str(text), re.IGNORECASE)
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
    e.g. 1.1.1 < 1.1.1w, 8.9 < 8.9p1, 2.4.9 < 2.4.62, 1.0.0rc1 < 1.0.0.
    """
    for x, y in zip_longest(_version_tokens(a), _version_tokens(b), fillvalue=(1, "")):
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
            return verdict
    return {"status": "NOT_AFFECTED", "reason": "Version is outside every affected range listed by NVD",
            "affected_ranges": [_describe_range(m) for m in relevant_matches[:3]]}


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

def _nvd_get(url: str, params: Dict[str, Any], keys: Optional[ApiKeys]) -> Dict[str, Any]:
    cache_key = (url, tuple(sorted(params.items())))
    cached = _nvd_cache.get(cache_key)
    if cached is not None:
        return cached
    nvd_key = keys.nvd if keys else ""
    headers = {"apiKey": nvd_key} if nvd_key else {}
    for attempt in range(2):
        _nvd_limiter.wait(50 if nvd_key else 5)
        resp = _http_get(url, params=params, headers=headers, timeout=30)
        # NVD signals rate limiting with 403 (not 429). On shared hosting other apps on the same IP count too.
        if resp.status_code != 403 or attempt:
            break
        time.sleep(6)
    if resp.status_code == 404:
        data: Dict[str, Any] = {"vulnerabilities": [], "products": [], "totalResults": 0}
    elif resp.status_code == 403:
        raise SourceError("NVD rate limit reached. Wait about 30 seconds and retry"
                          + ("" if nvd_key else f", or add a free NVD API key ({KEY_SIGNUP_URLS['nvd']})"))
    elif resp.status_code != 200:
        message = resp.headers.get("message", "")
        raise SourceError(f"NVD returned HTTP {resp.status_code}" + (f": {message}" if message else ""))
    else:
        try:
            data = resp.json()
        except ValueError as exc:
            raise SourceError("NVD returned invalid JSON") from exc
    _nvd_cache.set(cache_key, data)
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


def extract_cvss(cve: Dict[str, Any]) -> Dict[str, Any]:
    """Pick the best available CVSS metric: newest version first, NVD 'Primary' score preferred."""
    metrics = cve.get("metrics", {}) or {}
    for key, label in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"),
                       ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        entries = metrics.get(key) or []
        if not entries:
            continue
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
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


def _kev_entry_summary(vuln: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "cve_id": vuln.get("cveID"),
        "vendor_project": vuln.get("vendorProject"),
        "product": vuln.get("product"),
        "vulnerability_name": vuln.get("vulnerabilityName"),
        "date_added": vuln.get("dateAdded"),
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


def kev_matches_software(vuln: Dict[str, Any], software: str) -> bool:
    # Whole-word matching, so "log4j" matches CISA's "Log4j2" but "apache httpd" doesn't match "Apache Struts".
    text = f"{vuln.get('vendorProject', '')} {vuln.get('product', '')}"
    return any(mentions_whole_words(text, " ".join(sorted(term))) for term in _kev_search_terms(software))


def kev_lookup_many(cve_ids: Iterable[str]) -> Dict[str, Dict[str, Any]]:
    """Return KEV entries for any of ``cve_ids`` (empty dict if the feed is unavailable)."""
    try:
        by_cve = _load_kev_catalog()["by_cve"]
    except SourceError as exc:
        logger.warning("KEV enrichment skipped: %s", exc)
        return {}
    return {c.upper(): _kev_entry_summary(by_cve[c.upper()]) for c in cve_ids if c and c.upper() in by_cve}


def epss_lookup_many(cve_ids: Iterable[str]) -> Dict[str, Dict[str, float]]:
    """FIRST EPSS exploitation-probability scores (best effort; missing on failure)."""
    ids = sorted({c.upper() for c in cve_ids if c and is_valid_cve(c)})
    result: Dict[str, Dict[str, float]] = {}
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


def _enrich_with_exploit_intel(vulns: List[Dict[str, Any]]) -> None:
    ids = [v["cve_id"] for v in vulns if v.get("cve_id")]
    kev = kev_lookup_many(ids)
    epss = epss_lookup_many(ids)
    for v in vulns:
        cve_id = (v.get("cve_id") or "").upper()
        if cve_id in kev:
            v["in_cisa_kev"] = True
            v["kev_known_ransomware_use"] = kev[cve_id]["known_ransomware_use"]
        else:
            v.setdefault("in_cisa_kev", bool(v.get("cisa_kev")))
        if cve_id in epss:
            v["epss"] = epss[cve_id]


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
# Tools exposed to the agent
# ---------------------------------------------------------------------------

_CDN_NAMES = ("cloudflare", "akamai", "fastly", "cloudfront", "edgecast", "stackpath", "bunny", "sucuri",
              "incapsula", "imperva")


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
                             "known_ransomware_use": v.get("knownRansomwareCampaignUse")}
                            for v in hits[:limit]],
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


def osint_shodan_search(target: str, keys: ApiKeys, banner_limit: int = 200) -> Dict[str, Any]:
    """Look up a public IP (or a domain's primary IP) in Shodan's host database."""
    if not keys.shodan:
        return {"tool": "shodan", "error": f"Shodan API key not configured (get one at {KEY_SIGNUP_URLS['shodan']})"}
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

    services, software = [], []
    for item in host.get("data", []) or []:
        if not item.get("port"):
            continue
        product, version = item.get("product"), item.get("version")
        server_header = _banner_server_header(item.get("data", ""))
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
    org = f"{host.get('org') or ''} {host.get('isp') or ''}".lower()
    if "cdn" in (host.get("tags") or []) or any(c in org for c in _CDN_NAMES):
        result["cdn_note"] = ("This IP belongs to a CDN/edge network shared by many customers. Its open ports and "
                              "services are the CDN's, not the origin server's; the site owner can't close them "
                              "and they are not findings about the target.")
    kev = kev_matches_for_software([s["name"] for s in software])
    if kev:
        result["cisa_kev_product_matches"] = kev
        result["cisa_kev_note"] = ("Products/vendors seen on this host have CVEs in CISA's Known Exploited "
                                   "Vulnerabilities catalog. This shows real-world exploitation of the product "
                                   "family; it does not confirm this device's firmware is affected.")
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
        "abuse_confidence_score": score,
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
        return {"tool": "nvd", "error": str(exc)}
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


def osint_cisa_kev_check(keys: Optional[ApiKeys] = None, cve_ids: Optional[Sequence[str]] = None,
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
            name: {"total_kev_entries": software_totals[name], "most_recent": hits}
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
    page_size, max_pages = 500, 3
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

    def sort_key(v: Dict[str, Any]) -> Tuple[float, str]:
        return (v.get("cvss_score") or 0.0, v.get("published") or "")

    affected.sort(key=sort_key, reverse=True)
    unanalyzed.sort(key=sort_key, reverse=True)
    _enrich_with_exploit_intel(affected + unanalyzed)
    # Exploited-in-the-wild first, then by CVSS.
    affected.sort(key=lambda v: (bool(v.get("in_cisa_kev")), v.get("cvss_score") or 0.0), reverse=True)

    if affected:
        status = "VULNERABLE"
    elif unanalyzed:
        status = "REVIEW_NEEDED"
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
        "upgrade_to_at_least": minimum_safe_version(affected),
        "affected_cves": affected[:result_limit],
        "needs_review_count": len(unanalyzed),
        "needs_review_cves": unanalyzed[: max(3, result_limit // 2)],
        "nvd_candidates_checked": len(seen),
        "nvd_candidates_total": candidates_total,
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
    exact = [p for p in counts if p[1] == guess]
    if exact:
        return sorted(exact, key=lambda p: -counts[p])[:2]
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
}
