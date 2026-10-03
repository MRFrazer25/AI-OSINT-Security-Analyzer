# AI OSINT Security Analyzer

An AI agent that investigates IP addresses, domains, CVEs and software versions across several threat-intelligence sources. It then writes an evidence-based security assessment. Cohere's Command A+ model decides which tools to run, and every finding in the report is tied back to the source that produced it.

**Live demo:** [osint-ai.streamlit.app](https://osint-ai.streamlit.app)

## Features

* **Agentic investigation:** the model plans and chains tool calls based on what it finds, within a per-run budget.
* **Version-accurate vulnerability matching:** CVEs are checked against NVD's structured CPE affected-version ranges, so `nginx 1.20.1` is not reported as vulnerable to a bug fixed in 1.20.1. Each CVE is labelled *affected*, *needs review* (NVD hasn't analysed it yet) or *ruled out*.
* **Exploit-aware prioritisation:** findings are enriched with [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (exploited in the wild), CVSS (v4.0 → v2 fallback) and [FIRST EPSS](https://www.first.org/epss/) exploit probability.
* **Exposure and reputation:** Shodan services and banners, VirusTotal engine detections (with the names of flagging vendors) and AbuseIPDB abuse reports.
* **Analysis depth levels:** Quick Scan, Standard, Comprehensive and Expert. Each level sets how many tool calls the agent may make, protecting free-tier quotas.
* **Key facts box:** open ports, reputation scores, version-check results, the minimum safe version to upgrade to, and confirmed vs related CISA KEV entries (with EPSS) are computed directly from the data sources and shown above the AI's write-up. They're identical on every run and use no AI credits.
* **Model choice:** pick a Cohere model per analysis, with automatic fallback if your key can't use it.
* **Exports:** a Markdown report, and full JSON evidence including every tool call.

## Supported targets

| Type | Examples |
|---|---|
| IP address (IPv4/IPv6, public only) | `8.8.8.8`, `2606:4700:4700::1111` |
| Domain or URL | `example.com`, `https://example.com/page` |
| CVE ID | `CVE-2021-44228` |
| Software + version | `nginx 1.20.1`, `Apache httpd 2.4.62`, `OpenSSH 8.9p1` |

Private, loopback, link-local, CGNAT and other non-public addresses are rejected.

## Data sources

| Source | Used for | API key | Get a key |
|---|---|---|---|
| [Cohere](https://cohere.com/) | AI agent | **Required** | [dashboard.cohere.com/api-keys](https://dashboard.cohere.com/api-keys) |
| [Shodan](https://www.shodan.io/) | Open ports, services, versions | Optional | [account.shodan.io](https://account.shodan.io/) |
| [VirusTotal](https://www.virustotal.com/) | Reputation / malicious detections | Optional | [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) |
| [AbuseIPDB](https://www.abuseipdb.com/) | Abuse reports for IPs | Optional | [abuseipdb.com/register](https://www.abuseipdb.com/register) |
| [NVD](https://nvd.nist.gov/) | CVE details and affected versions | Optional (raises rate limit) | [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key) |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [FIRST EPSS](https://www.first.org/epss/) | Exploitation status / probability | Not needed | n/a |

All of these offer free tiers. Check each provider for its current limits.

## Running locally

Requires Python 3.10+.

```bash
git clone https://github.com/MRFrazer25/AI-OSINT-Security-Analyzer.git
cd AI-OSINT-Security-Analyzer
python setup_check.py
```

`setup_check.py` installs or upgrades the requirements, verifies the imports, creates `.env` from `.env.example`, and prints where to get each key. Get a [Cohere key](https://dashboard.cohere.com/api-keys) (required) plus any optional keys from the table above. Add them to `.env`, or enter them in the web UI. Then start the app:

```bash
python -m streamlit run app.py
```

Open http://localhost:8501.

### Choosing a Cohere model

Pick the model in the app, next to "Analysis depth". Only models that support tool use are offered:

| Model | Best for |
|---|---|
| `command-a-plus-05-2026` (default) | Most capable; recommended |
| `command-a-03-2025` | Proven and stable |
| `command-a-reasoning-08-2025` | Harder analyses; slower because it reasons first |

If your key can't use the chosen model, the analysis falls back to `command-a-03-2025` automatically and tells you. The model that actually ran is shown with every report. To change the default, set `COHERE_MODEL` in `.env`.

### Tests

```bash
pip install pytest
python -m pytest
```

The tests run offline. They cover target validation, version comparison (including trailing zeros such as `2.4` vs `2.4.0`), NVD range matching, minimum safe versions, KEV and keyword matching, Markdown sanitising and export escaping, NVD cache/rate-limit behaviour, shared-key quotas, and the agent loop (using a fake Cohere client). Many are regression tests built from real analysis runs.

### Sharing server keys on a deployment

Keys in `.env` or Streamlit secrets are available to every visitor of that process. On a public app, either require visitors to bring their own keys or keep the hourly caps:

| Setting | Default | Meaning |
|---|---|---|
| `SHARE_SERVER_KEYS` | `false` | Set `true` to let visitors use the server's keys, up to the hourly caps below. |
| `SERVER_KEY_RUNS_PER_HOUR` | `20` | Process-wide analyses that may consume the server's keys. |
| `SERVER_KEY_RUNS_PER_CLIENT_PER_HOUR` | `5` | Per-visitor cap (best-effort client address; the process-wide cap is the real guard). |

These apply only when an analysis uses a server-provided key. A visitor who enters their own keys is not counted. There is still a 15-second per-session cooldown between runs. The same names can be set in `.streamlit/secrets.toml`.

## How it works

1. **Classify** the input as an IP, domain, CVE or software, rejecting anything invalid or non-public.
2. **Baseline lookups (in code):** for IPs and domains, DNS, Shodan, VirusTotal and AbuseIPDB always run before the AI starts, so core coverage never depends on the model. Shodan results are automatically checked against CISA KEV, including products named only in service banners.
3. **Investigate:** the agent chooses further tools (NVD version check, NVD lookup, CISA KEV, keyword search). Duplicate calls are served from cache, and quota-limited services are capped per run. Keyword searches keep only CVEs that mention the term as a whole word.
4. **Verify versions:** for each product and version, CVEs come from NVD's CPE match API and are then re-checked locally against each affected range. The minimum safe version is computed from the range ends.
5. **Report:** code builds the Key facts. The model writes an executive summary, a key-findings table, details (Confirmed / Related / Needs Review / Ruled Out), prioritised recommendations and limitations, citing a source for every claim.

## Security and privacy

* **Per-session API keys:** keys entered in the UI live only in that user's Streamlit session. They are never written to environment variables or disk, and never shared between users of a deployment. Keys configured on the server are never sent to the browser, and are not used unless `SHARE_SERVER_KEYS=true`. When sharing is on, hourly caps stop one visitor from draining the operator's quota.
* **Safe rendering:** the report includes third-party text (banners, descriptions), so it is rendered as Markdown only. Raw HTML is not rendered. Remaining `[`, `]` and `<` in the model's write-up are escaped so reference images, hidden links and HTML cannot survive, and third-party software names in the Markdown export are escaped the same way as on screen.
* **Prompt-injection hardening:** tool output is treated as untrusted data and kept inside escaped data blocks. Results are size-capped before they reach the model, and the model can't override server-side limits through tool arguments.
* **Input validation:** CVE IDs, domains and IPs are validated before any API call, and query parameters are URL-encoded.
* **Key redaction:** error messages are scrubbed of API key values.
* **No telemetry:** Streamlit usage stats are disabled, stack traces are hidden from visitors, and analysed targets are not written to server logs.

**What leaves your machine:** the target and the gathered evidence are sent to Cohere to produce the report. The target is also looked up at whichever sources apply (Shodan, VirusTotal, AbuseIPDB, NVD, CISA, FIRST). Each lookup is subject to that provider's privacy policy, so don't submit targets you need to keep confidential.

Exported reports can contain sensitive findings. Handle them accordingly.

## Accuracy notes

* Banner versions can mislead. Linux distributions often backport security fixes without changing the version string, so verify findings against your distribution's security tracker.
* "No known vulnerabilities" means no matching NVD records, not that a system is secure.
* A product-level CISA KEV match shows that the product has been exploited before, not that the target's version is affected.
* Testing so far has focused on common software and devices, so results for less common products may be less reliable. If a result looks wrong, please [open an issue](https://github.com/MRFrazer25/AI-OSINT-Security-Analyzer/issues) with the target you used.

## License

MIT. See [LICENSE](LICENSE).

## Disclaimer

For legitimate security research, defensive security and education only. Only investigate systems you own or are authorized to assess, and follow each data provider's terms of service.
