import pytest

import osint_tools as t


@pytest.mark.parametrize("raw, expected_type, expected_value", [
    ("8.8.8.8", "ip", "8.8.8.8"),
    (" 1.1.1.1 ", "ip", "1.1.1.1"),
    ("2606:4700:4700::1111", "ip", "2606:4700:4700::1111"),
    ("10.0.0.5", "invalid", "10.0.0.5"),
    ("127.0.0.1", "invalid", "127.0.0.1"),
    ("169.254.169.254", "invalid", "169.254.169.254"),  # cloud metadata / link-local
    ("100.64.1.1", "invalid", "100.64.1.1"),  # CGNAT
    ("Example.COM", "domain", "example.com"),
    ("https://sub.example.co.uk/path?q=1", "domain", "sub.example.co.uk"),
    ("example.technology", "domain", "example.technology"),
    ("cve-2021-44228", "cve", "CVE-2021-44228"),
    ("nginx 1.20.1", "software", "nginx 1.20.1"),
    ("jenkins", "software", "jenkins"),
    ("<script>alert(1)</script>", "invalid", None),
    ("x" * 300, "invalid", None),
    ("", "invalid", None),
])
def test_classify_target(raw, expected_type, expected_value):
    target = t.classify_target(raw)
    assert target.type == expected_type
    if expected_value is not None:
        assert target.value == expected_value


def test_classify_software_splits_name_and_version():
    target = t.classify_target("OpenSSH 8.9p1")
    assert (target.software_name, target.software_version) == ("OpenSSH", "8.9p1")


@pytest.mark.parametrize("a, b, expected", [
    ("2.4.9", "2.4.62", -1),
    ("2.4.62", "2.4.62", 0),
    ("1.1.1", "1.1.1w", -1),
    ("1.1.1w", "1.1.1a", 1),
    ("8.9", "8.9p1", -1),
    ("1.0.0rc1", "1.0.0", -1),
    ("10.0", "9.9", 1),
    ("2.4", "2.4.0", 0),
    ("2.4.0", "2.4", 0),
    ("1.20", "1.20.1", -1),
    ("2.0", "2.0.0.0", 0),
    ("1.0", "1.0.0rc1", 1),
])
def test_compare_versions(a, b, expected):
    assert t.compare_versions(a, b) == expected


def test_extract_version():
    assert t.extract_version("OpenSSH_8.9p1 Ubuntu-3ubuntu0.6") == "8.9p1"
    assert t.extract_version("1.20.1") == "1.20.1"
    assert t.extract_version("no version") is None


def _cve(*matches, operator=None):
    return {"id": "CVE-2000-0001", "configurations": [{"operator": operator, "nodes": [{"cpeMatch": list(matches)}]}]}


NGINX = "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"


def test_version_range_excluding_end_is_not_affected():
    # Real case: CVE-2021-23017 affects nginx 0.6.18 up to (excluding) 1.20.1.
    cve = _cve({"vulnerable": True, "criteria": NGINX, "versionStartIncluding": "0.6.18",
                "versionEndExcluding": "1.20.1"})
    assert t.assess_cve_for_version(cve, "*", "nginx", "1.20.1")["status"] == "NOT_AFFECTED"
    assert t.assess_cve_for_version(cve, "*", "nginx", "1.20.0")["status"] == "AFFECTED"


def test_exact_version_cpe_and_update_field():
    cve = _cve({"vulnerable": True, "criteria": "cpe:2.3:a:openbsd:openssh:8.9:p1:*:*:*:*:*:*"})
    assert t.assess_cve_for_version(cve, "openbsd", "openssh", "8.9p1")["status"] == "AFFECTED"
    assert t.assess_cve_for_version(cve, "openbsd", "openssh", "8.9p2")["status"] == "NOT_AFFECTED"


def test_exact_minor_does_not_cover_patch_release():
    cve = _cve({"vulnerable": True, "criteria": "cpe:2.3:a:f5:nginx:1.20:*:*:*:*:*:*:*"})
    assert t.assess_cve_for_version(cve, "*", "nginx", "1.20.1")["status"] == "NOT_AFFECTED"


def test_trailing_zeros_do_not_change_range_verdicts():
    start = _cve({"vulnerable": True, "criteria": NGINX, "versionStartIncluding": "2.4.0", "versionEndExcluding": "2.5"})
    assert t.assess_cve_for_version(start, "*", "nginx", "2.4")["status"] == "AFFECTED"
    end = _cve({"vulnerable": True, "criteria": NGINX, "versionEndExcluding": "2.0.0"})
    assert t.assess_cve_for_version(end, "*", "nginx", "2.0")["status"] == "NOT_AFFECTED"
    exact = _cve({"vulnerable": True, "criteria": "cpe:2.3:a:f5:nginx:2.4.0:*:*:*:*:*:*:*"})
    assert t.assess_cve_for_version(exact, "*", "nginx", "2.4")["status"] == "AFFECTED"


def test_other_products_and_non_vulnerable_entries_are_ignored():
    cve = _cve({"vulnerable": True, "criteria": "cpe:2.3:a:other:thing:*:*:*:*:*:*:*:*"},
               {"vulnerable": False, "criteria": NGINX})
    assert t.assess_cve_for_version(cve, "*", "nginx", "1.0")["status"] == "UNANALYZED"


def test_and_configuration_flags_platform_requirement():
    cve = _cve({"vulnerable": True, "criteria": NGINX, "versionEndIncluding": "2.0"}, operator="AND")
    verdict = t.assess_cve_for_version(cve, "*", "nginx", "1.0")
    assert verdict["status"] == "AFFECTED" and verdict["requires_specific_platform"]


def test_cpe_alias_resolution():
    assert t.resolve_cpe_alias("Apache httpd") == ("apache", "http_server")
    assert t.resolve_cpe_alias("Microsoft IIS httpd") == ("microsoft", "internet_information_services")
    assert t.resolve_cpe_alias("Exim smtpd") == ("exim", "exim")
    assert t.resolve_cpe_alias("totally-unknown") is None


def test_kev_software_matching_is_product_specific():
    httpd = {"vendorProject": "Apache", "product": "HTTP Server"}
    struts = {"vendorProject": "Apache", "product": "Struts"}
    assert t.kev_matches_software(httpd, "Apache httpd")
    assert not t.kev_matches_software(struts, "Apache httpd")
    assert t.kev_matches_software({"vendorProject": "Grafana Labs", "product": "Grafana"}, "grafana")


def test_extract_cvss_prefers_newest_primary_metric():
    cve = {"metrics": {
        "cvssMetricV31": [
            {"type": "Secondary", "source": "vendor", "cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM"}},
            {"type": "Primary", "source": "nvd", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}},
        ],
        "cvssMetricV2": [{"type": "Primary", "cvssData": {"baseScore": 7.5}, "baseSeverity": "HIGH"}],
    }}
    cvss = t.extract_cvss(cve)
    assert (cvss["cvss_score"], cvss["cvss_version"], cvss["severity"]) == (9.8, "3.1", "CRITICAL")
    assert t.extract_cvss({})["severity"] == "UNKNOWN"


def test_api_keys_overrides_and_redaction():
    keys = t.ApiKeys(cohere="server-c", shodan="server-s").with_overrides(shodan="user-s", virustotal="  ")
    assert (keys.cohere, keys.shodan, keys.virustotal) == ("server-c", "user-s", "")
    assert t.redact("bad key user-s in url", keys) == "bad key [REDACTED] in url"


def test_tools_reject_invalid_input_without_network():
    keys = t.ApiKeys(shodan="k", virustotal="k", abuseipdb="k")
    assert "error" in t.osint_abuseipdb_check("192.168.1.1", keys)
    assert "error" in t.osint_virustotal_check("../../etc", "domain", keys)
    assert "error" in t.osint_shodan_search("127.0.0.1", keys)
    assert "error" in t.osint_nvd_lookup("CVE-2021-44228?foo=bar")
    assert "error" in t.osint_cisa_kev_check()
    assert "error" in t.osint_shodan_search("8.8.8.8", t.ApiKeys())  # missing key


def test_extract_version_accepts_single_number():
    assert t.extract_version("7") == "7"


def test_kev_check_accepts_string_instead_of_list(monkeypatch):
    catalog = {"date_released": "x", "vulnerabilities": [{"cveID": "CVE-2021-41773", "vendorProject": "Apache",
                                                           "product": "HTTP Server"}]}
    catalog["by_cve"] = {"CVE-2021-41773": catalog["vulnerabilities"][0]}
    monkeypatch.setattr(t, "_load_kev_catalog", lambda: catalog)
    result = t.osint_cisa_kev_check(cve_ids="CVE-2021-41773", software_list="Apache httpd")
    assert result["cves_in_kev"] == ["CVE-2021-41773"]
    assert result["software_matches"]["Apache httpd"]["total_kev_entries"] == 1


def test_unknown_product_is_not_mapped_to_unrelated_cpe(monkeypatch):
    fake = {"products": [{"cpe": {"cpeName": "cpe:2.3:a:acme:rocket_launcher:1.0:*:*:*:*:*:*:*"}}]}
    monkeypatch.setattr(t, "_nvd_get", lambda url, params, keys: fake)
    assert t._resolve_products("zebra", None) == []
    assert t._resolve_products("acme rocket launcher", None) == [("acme", "rocket_launcher")]


def test_shodan_uses_server_header_and_flags_kev_vendor(monkeypatch):
    # Based on a real host: product field empty, vendor only visible in the RTSP "Server:" header.
    host = {"org": "ISP", "ports": [80, 554], "data": [
        {"port": 80, "product": "ADT DVR", "data": "HTTP/1.1 200 OK\n\nADT DVR:\n  Web Version: 3.1.0.5"},
        {"port": 554, "data": "RTSP/1.0 401 Unauthorized\nServer: Dahua Rtsp Server\nCSeq: 1\n"},
        {"port": 8080, "data": "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\n"},
    ]}

    class FakeShodan:
        def __init__(self, key):
            pass

        def host(self, ip):
            return host

    catalog = {"date_released": "x", "vulnerabilities": [
        {"cveID": "CVE-2021-33044", "vendorProject": "Dahua", "product": "IP Camera Firmware"}]}
    catalog["by_cve"] = {}
    monkeypatch.setattr(t.shodan, "Shodan", FakeShodan)
    monkeypatch.setattr(t, "_load_kev_catalog", lambda: catalog)

    result = t.osint_shodan_search("8.8.8.8", t.ApiKeys(shodan="k"))
    software = {s["name"]: s for s in result["discovered_software"]}
    assert software["Dahua Rtsp Server"]["source"] == "server_header"
    assert (software["nginx"]["version"], software["nginx"]["source"]) == ("1.18.0", "server_header")
    kev = result["cisa_kev_product_matches"]["Dahua Rtsp Server"]
    assert kev["match_level"].startswith("vendor") and kev["entries"][0]["cve_id"] == "CVE-2021-33044"
    assert "ADT DVR" not in result["cisa_kev_product_matches"]


def test_placeholder_and_single_word_names_never_map_to_unrelated_products(monkeypatch):
    # Real failure: a model passed "all", which partially matched "crunchify:all-in-on-webmaster".
    fake = {"products": [{"cpe": {"cpeName": "cpe:2.3:a:crunchify:all-in-on-webmaster:1.0:*:*:*:*:*:*:*"}},
                         {"cpe": {"cpeName": "cpe:2.3:h:hp:psc_1210_all-in-one:-:*:*:*:*:*:*:*"}}]}
    monkeypatch.setattr(t, "_nvd_get", lambda url, params, keys: fake)
    assert t._resolve_products("all", None) == []
    assert t._resolve_products("webmaster", None) == []


def test_kev_product_matches_include_epss(monkeypatch):
    catalog = {"date_released": "x", "by_cve": {}, "vulnerabilities": [
        {"cveID": "CVE-2021-33044", "vendorProject": "Dahua", "product": "IP Camera Firmware"}]}
    monkeypatch.setattr(t, "_load_kev_catalog", lambda: catalog)
    monkeypatch.setattr(t, "epss_lookup_many", lambda ids: {"CVE-2021-33044": {"epss": 0.99, "percentile": 0.99}})
    entry = t.kev_matches_for_software(["Dahua Rtsp Server"])["Dahua Rtsp Server"]["entries"][0]
    assert entry["epss"]["epss"] == 0.99


@pytest.mark.parametrize("text, term, expected", [
    ("hwmon: (adt7470) Fix busy-loop", "ADT", False),       # real false hits from an "ADT" search
    ("Product Feed PRO by AdTribes", "ADT", False),
    ("calls ajax_adt_clear_custom_attributes", "ADT", False),
    ("ADT LifeShield DIY HD Video Doorbell", "ADT", True),
    ("Digitek ADT1100 path traversal", "ADT", False),
    ("ADT DVR web interface flaw", "ADT", True),
    ("Apache Log4j2 2.0-beta9 JNDI", "log4j", True),        # digits in the term allow a numeric suffix
    ("some Dahua products could allow", "Dahua", True),
    ("cloudflare/cors-proxy-worker.js", "cloudflare", True),
])
def test_mentions_whole_words(text, term, expected):
    assert t.mentions_whole_words(text, term) is expected


def test_cve_search_drops_substring_only_matches(monkeypatch):
    cves = [{"id": "CVE-1", "published": "2026", "descriptions": [{"lang": "en", "value": "hwmon: adt7470 bug"}]},
            {"id": "CVE-2", "published": "2025", "descriptions": [{"lang": "en", "value": "AdTribes plugin"}]}]
    monkeypatch.setattr(t, "_nvd_most_recent", lambda params, keys, limit: (82, cves))
    result = t.osint_cve_search("ADT")
    assert result["success"] is False and "only inside other words" in result["info"]


def test_shodan_flags_cdn_ips(monkeypatch):
    class FakeShodan:
        def __init__(self, key):
            pass

        def host(self, ip):
            return {"org": "Cloudflare, Inc.", "tags": ["cdn"], "data": []}

    monkeypatch.setattr(t.shodan, "Shodan", FakeShodan)
    monkeypatch.setattr(t, "kev_matches_for_software", lambda names: {})
    assert "cdn_note" in t.osint_shodan_search("8.8.8.8", t.ApiKeys(shodan="k"))


def test_kev_matching_handles_numbered_product_names():
    # Real miss: CISA lists Log4Shell under product "Log4j2", so "log4j" found nothing.
    assert t.kev_matches_software({"vendorProject": "Apache", "product": "Log4j2"}, "log4j")
    assert not t.kev_matches_software({"vendorProject": "Apache", "product": "Struts"}, "Apache httpd")


def test_version_ranges_are_described_in_words():
    # Models dropped "<" from "< 1.21.0", inverting the meaning; words survive.
    match = {"criteria": NGINX, "versionStartIncluding": "0.6.18", "versionEndExcluding": "1.20.1"}
    assert t._describe_range(match) == "f5:nginx from 0.6.18 before 1.20.1"
    assert "<" not in t._describe_range({"criteria": NGINX, "versionEndIncluding": "2.0"})


def test_minimum_safe_version_covers_every_affected_cve():
    # Real mistake: a report said "upgrade to 1.22.1" for nginx 1.20.1, but CVE-2025-23419 is fixed in 1.26.3.
    affected = [{"fixed_in": "1.21.0"}, {"fixed_after": "1.25.2"}, {"fixed_after": "1.22.0"}, {"fixed_in": "1.26.3"}]
    assert t.minimum_safe_version(affected)["text"] == "1.26.3 or later"
    assert t.minimum_safe_version([{"fixed_after": "2.4.55"}])["text"] == "later than 2.4.55"
    assert "note" in t.minimum_safe_version([{"fixed_in": "2.0"}, {}])
    assert t.minimum_safe_version([{}]) is None


def test_affected_verdict_records_fix_version():
    cve = _cve({"vulnerable": True, "criteria": NGINX, "versionStartIncluding": "1.11.4",
                "versionEndExcluding": "1.26.3"})
    assert t.assess_cve_for_version(cve, "*", "nginx", "1.20.1")["fixed_in"] == "1.26.3"


def test_api_error_detail_is_extracted_and_redacted():
    class Resp:
        def __init__(self, body):
            self._body = body

        def json(self):
            return self._body

    keys = t.ApiKeys(abuseipdb="secret123")
    abuse = Resp({"errors": [{"detail": "Authentication failed. Your API key secret123 is either missing or invalid."}]})
    detail = t._api_error_detail(abuse, keys)
    assert "Authentication failed" in detail and "secret123" not in detail
    assert t._api_error_detail(Resp({"error": {"code": "WrongCredentialsError", "message": "Wrong API key"}}), keys) \
        == ": Wrong API key"


def test_nvd_rate_limit_403_is_retried_then_explained(monkeypatch):
    class Resp:
        status_code, headers = 403, {}

    calls = []
    monkeypatch.setattr(t, "_http_get", lambda *a, **k: calls.append(1) or Resp())
    monkeypatch.setattr(t.time, "sleep", lambda s: None)
    monkeypatch.setattr(t._RateLimiter, "wait", lambda self: None)
    with pytest.raises(t.SourceError, match="rate limit.*NVD API key"):
        t._nvd_get(t.NVD_CVE_URL, {"cveId": "CVE-2000-9999"}, None)
    assert len(calls) == 2  # one retry


def test_rate_limiter_sleeps_without_the_lock_and_rechecks(monkeypatch):
    limiter = t._RateLimiter(max_calls=2, period=30.0)
    clock = [1000.0]
    sleeps = []

    def fake_sleep(seconds):
        assert not limiter._lock.locked()
        sleeps.append(seconds)
        clock[0] += seconds

    monkeypatch.setattr(t.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(t.time, "sleep", fake_sleep)
    limiter.wait()
    limiter.wait()
    assert sleeps == []
    limiter.wait()
    assert len(sleeps) == 1 and sleeps[0] > 29
    assert len(limiter._calls) == 1  # both earlier calls aged out before this one was recorded


def test_nvd_keyed_and_keyless_requests_use_separate_limits(monkeypatch):
    class Resp:
        status_code, headers = 200, {}

        @staticmethod
        def json():
            return {"totalResults": 0, "vulnerabilities": []}

    used = []
    monkeypatch.setattr(t, "_http_get", lambda *a, **k: Resp())
    monkeypatch.setattr(t._nvd_keyed_limiter, "wait", lambda: used.append("keyed"))
    monkeypatch.setattr(t._nvd_keyless_limiter, "wait", lambda: used.append("keyless"))
    t._nvd_get(t.NVD_CVE_URL, {"cveId": "CVE-2000-0001", "test": "limiter"}, t.ApiKeys(nvd="k"))
    t._nvd_get(t.NVD_CVE_URL, {"cveId": "CVE-2000-0002", "test": "limiter"}, None)
    assert used == ["keyed", "keyless"]
    assert (t._nvd_keyed_limiter._max_calls, t._nvd_keyless_limiter._max_calls) == (50, 5)


def test_nvd_responses_are_summarised_before_caching(monkeypatch):
    raw_cve = {
        "id": "CVE-2000-0003", "vulnStatus": "Analyzed", "published": "2000-01-01T00:00", "sourceIdentifier": "x",
        "descriptions": [{"lang": "es", "value": "otro"}, {"lang": "en", "value": "nginx bug " + "a" * 5000}],
        "references": [{"url": f"https://example.com/{i}", "source": "s", "tags": ["Patch"]} for i in range(100)],
        "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
                    "cvssMetricV2": [{"type": "Primary", "cvssData": {"baseScore": 7.5}}]},
        "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [
            {"vulnerable": True, "criteria": NGINX, "versionEndExcluding": "1.20.1", "matchCriteriaId": "id"},
            {"vulnerable": False, "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"}]}]}],
    }

    class Resp:
        status_code, headers = 200, {}

        @staticmethod
        def json():
            return {"totalResults": 1, "format": "NVD_CVE", "vulnerabilities": [{"cve": raw_cve}]}

    monkeypatch.setattr(t, "_http_get", lambda *a, **k: Resp())
    monkeypatch.setattr(t._RateLimiter, "wait", lambda self: None)
    data = t._nvd_get(t.NVD_CVE_URL, {"cveId": "CVE-2000-0003", "test": "summary"}, None)
    cve = data["vulnerabilities"][0]["cve"]
    assert set(data) == {"totalResults", "vulnerabilities", "products"}
    assert len(cve["references"]) == t.NVD_MAX_REFERENCES and "source" not in cve["references"][0]
    assert len(cve["descriptions"][0]["value"]) == t.NVD_MAX_DESCRIPTION
    assert list(cve["metrics"]) == ["cvssMetricV31"] and "sourceIdentifier" not in cve
    assert cve["configurations"][0]["nodes"][0]["cpeMatch"] == [
        {"vulnerable": True, "criteria": NGINX, "versionEndExcluding": "1.20.1"}]
    # The tools reach the same conclusions from the summary as from the raw record.
    assert t.summarize_nvd_cve(cve) == t.summarize_nvd_cve(raw_cve)
    assert t.assess_cve_for_version(cve, "*", "nginx", "1.20.0") == t.assess_cve_for_version(raw_cve, "*", "nginx", "1.20.0")


def test_ttl_cache_enforces_byte_budget():
    cache = t._TTLCache(ttl_seconds=60, maxsize=10, max_bytes=100)
    cache.set("a", 1, size=40)
    cache.set("b", 2, size=40)
    cache.set("c", 3, size=40)  # evicts the oldest entry to stay within 100 bytes
    assert (cache.get("a"), cache.get("b"), cache.get("c")) == (None, 2, 3)
    cache.set("huge", 4, size=101)
    assert cache.get("huge") is None and cache.get("c") == 3
    cache.set("b", 5, size=10)  # replacing an entry releases its old size
    assert cache._bytes == 50


def test_server_key_quota_enforces_total_and_per_client_caps():
    quota = t.ServerKeyQuota()
    assert quota.acquire("a", total_limit=2, client_limit=1) == 0
    assert quota.acquire("a", total_limit=2, client_limit=1) >= 1  # same visitor
    assert quota.acquire("b", total_limit=2, client_limit=1) == 0
    assert quota.acquire("c", total_limit=2, client_limit=1) >= 1  # process-wide cap
    quota.reset()
    assert quota.acquire("c", total_limit=2, client_limit=1) == 0


@pytest.mark.parametrize("value, expected", [
    ("nginx 1.20.1", ("nginx", "1.20.1")),
    ("Apache httpd 2.4.62", ("Apache httpd", "2.4.62")),
    ("nginx/1.18.0", ("nginx", "1.18.0")),
    ("OpenSSH_8.9p1", ("OpenSSH", "8.9p1")),
    ("redis v7", ("redis", "7")),
    ("jenkins", None),
    ("123 4.5", None),
])
def test_split_software_version(value, expected):
    assert t.split_software_version(value) == expected


def test_software_parsing_is_fast_on_hostile_input():
    # CodeQL py/polynomial-redos patterns ("a" + many spaces, "a\t9" + many ".0"); the old regex took ~8s on 20k chars.
    import time
    start = time.perf_counter()
    t.split_software_version("a" + " " * 20000 + "!")
    t.split_software_version("a\t9" + ".0" * 10000 + "!")
    assert time.perf_counter() - start < 1.0
