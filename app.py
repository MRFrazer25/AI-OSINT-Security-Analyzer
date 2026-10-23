"""Streamlit front end for the AI Vulnerability Exposure Analyzer."""

import json
import logging
import re
import time
from datetime import datetime

import altair as alt
import streamlit as st

try:  # before importing ai, so COHERE_MODEL in .env sets the default model (API keys are never read from it)
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

from ai import (AVAILABLE_MODELS, COMPLEXITY_PROFILES, DEFAULT_MODEL, build_cve_table, build_markdown_export,
                build_report_data, escape_markdown, run_agent, sanitize_report_markdown)
from lookups import KEY_SIGNUP_URLS, ApiKeys, classify_target

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

RUN_COOLDOWN_SECONDS = 15
# name -> (service, purpose, required)
KEY_FIELDS = {
    "cohere": ("Cohere", "runs the AI agent", True),
    "shodan": ("Shodan", "exposed services and versions", False),
    "virustotal": ("VirusTotal", "malicious/suspicious detections", False),
    "abuseipdb": ("AbuseIPDB", "IP abuse reports", False),
    "nvd": ("NVD", "faster CVE lookups", False),
    "greynoise": ("GreyNoise", "more scanner lookups than the 10 a day allowed without one (work-email "
                  "accounts only)", False),
}
# Which key a tool depends on, so missing-key errors can link to the sign-up page.
TOOL_KEYS = {"shodan_search": "shodan", "virustotal_check": "virustotal",
             "abuseipdb_check": "abuseipdb", "threat_lists_check": "greynoise"}
TOOL_LABELS = {
    "resolve_domain": "DNS resolution",
    "shodan_search": "Shodan host lookup",
    "virustotal_check": "VirusTotal reputation",
    "abuseipdb_check": "AbuseIPDB reputation",
    "version_specific_vulnerability_check": "Version-specific CVE check (NVD)",
    "nvd_lookup": "NVD CVE lookup",
    "cisa_kev_check": "CISA KEV check",
    "cve_search": "NVD keyword search",
    "distro_patch_check": "Distro patch check (Ubuntu/Debian via OSV)",
    "ip_owner": "Network owner (internet registry)",
    "threat_lists_check": "Spamhaus DROP and GreyNoise",
    "subdomains": "Subdomains (certificate logs)",
}


def effective_keys() -> ApiKeys:
    """Only the keys this visitor typed into their own session. Keys in .env, the environment or Streamlit
    secrets are never used, so one person's keys can't run another person's analysis."""
    return ApiKeys().with_overrides(**st.session_state.user_keys)

# Severity colours for the chart; they read on both the light and dark themes.
SEVERITY_COLORS = {"Critical": "#c62828", "High": "#ef6c00", "Medium": "#f9a825", "Low": "#1e88e5"}


def severity_chart(counts: dict) -> alt.Chart:
    """Horizontal bars, one per severity, so the labels stay readable on a narrow phone screen."""
    rows = [{"Severity": s.title(), "CVEs": n} for s, n in counts.items()]
    order = [s for s in SEVERITY_COLORS if s.upper() in counts]
    base = alt.Chart(alt.Data(values=rows)).encode(
        y=alt.Y("Severity:N", sort=order, title=None),
        x=alt.X("CVEs:Q", title="Confirmed CVEs", axis=alt.Axis(tickMinStep=1)),
        tooltip=["Severity:N", "CVEs:Q"])
    bars = base.mark_bar().encode(color=alt.Color("Severity:N", legend=None, scale=alt.Scale(
        domain=order, range=[SEVERITY_COLORS[s] for s in order])))
    labels = base.mark_text(align="left", dx=4).encode(text="CVEs:Q")
    return (bars + labels).properties(height=34 * len(order) + 40)


def key_link(name: str) -> str:
    return f"[{KEY_FIELDS[name][0]}]({KEY_SIGNUP_URLS[name]})"


def key_hint(tool: str, error) -> str:
    """Append a sign-up link when a tool failed because its key is missing or rejected."""
    name = TOOL_KEYS.get(tool)
    if name and re.search(r"key not configured|rejected the api key", str(error or ""), re.IGNORECASE):
        return f" ({key_link(name)})"
    return ""


def safe_filename(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("_")[:60] or "target"


def describe_args(arguments) -> str:
    try:
        args = json.loads(arguments) if isinstance(arguments, str) else arguments
        text = ", ".join(str(v) for v in args.values() if v) if isinstance(args, dict) else ""
        return escape_markdown(text[:200])
    except ValueError:
        return ""


st.set_page_config(page_title="AI Vulnerability Exposure Analyzer", page_icon="🔍", layout="wide")

st.session_state.setdefault("user_keys", {})
st.session_state.setdefault("report_data", None)
st.session_state.setdefault("last_run", 0.0)

st.title("AI Vulnerability Exposure Analyzer")
st.markdown("AI-driven checks of IPs, domains, CVEs and software versions for confirmed vulnerabilities and "
            "exposure, powered by Cohere Command models.")

with st.sidebar:
    st.markdown("## How to use")
    st.markdown(
        """
**Supported targets**
- **IP address**: `8.8.8.8`, `2606:4700:4700::1111`
- **Domain or URL**: `example.com`
- **CVE ID**: `CVE-2021-44228`
- **Software + version**: `nginx 1.20.1`, `OpenSSH 8.9p1`

Include a version for software. Without one, results are generic.

**How it works**
1. The agent plans which tools apply to your target.
2. It gathers evidence from the sources below.
3. Vulnerabilities are matched to exact versions using NVD's affected-version data, then ranked by CISA KEV (exploited in the wild), EPSS and CVSS. Each one shows the fix NVD lists.
4. For Ubuntu and Debian packages named in banners (e.g. OpenSSH), the distro's own data shows which CVEs are already fixed by a backport.
5. It writes a report that cites each source, and the key facts list which sources weren't checked.
"""
    )
    st.markdown("## Data sources")
    st.markdown(
        """
- [Shodan](https://www.shodan.io/): exposed services
- [VirusTotal](https://www.virustotal.com/): reputation
- [AbuseIPDB](https://www.abuseipdb.com/): abuse reports
- [NVD](https://nvd.nist.gov/): CVE details and affected versions
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog): exploited vulnerabilities
- [FIRST EPSS](https://www.first.org/epss/): exploit probability
- [OSV.dev](https://osv.dev/): Ubuntu and Debian fixes for installed packages
- Internet registries (RDAP): who owns an IP's network
- [Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) and [GreyNoise](https://www.greynoise.io/): hijacked networks and internet scanners
- [crt.sh](https://crt.sh/) and [Cert Spotter](https://sslmate.com/ct_search_api/): subdomains from certificate logs
- [SANS ISC](https://isc.sans.edu/): attack reports when GreyNoise can't answer
- [Exploit-DB](https://www.exploit-db.com/): published exploit code
- [GitHub Advisory Database](https://github.com/advisories): package advisories before NVD has them

Without a Shodan key, Shodan's free [InternetDB](https://internetdb.shodan.io/) is used (ports and software, no banners).
"""
    )
    st.caption("This product uses data from the NVD API but is not endorsed or certified by the NVD. "
               "Not affiliated with or endorsed by Cohere, Shodan, VirusTotal (Google), AbuseIPDB, NIST, CISA, FIRST, "
               "MITRE, Spamhaus, GreyNoise, SANS, OffSec (Exploit-DB), GitHub, Google (OSV.dev), Sectigo (crt.sh), "
               "SSLMate (Cert Spotter) or the internet registries. Spamhaus DROP data (c) The Spamhaus Project. "
               "SANS ISC data is CC BY-NC-SA 4.0. CVE® is a registered trademark of The MITRE Corporation.")

# --- API keys ---------------------------------------------------------------
with st.expander("API Keys Configuration", expanded=not effective_keys().cohere):
    st.markdown("**Get your keys (all have free tiers):**  \n" + "  \n".join(
        f"- {key_link(n)}: {'required' if req else 'optional'}, {purpose}"
        for n, (_, purpose, req) in KEY_FIELDS.items()
    ))
    st.caption(
        "Keys you enter are kept only in this browser session's server-side memory. They are never written "
        "to disk or shared with other users, and they are cleared when the session ends."
    )
    with st.form("api_keys_form", clear_on_submit=True):
        cols = st.columns(2)
        entered = {}
        for i, (name, (service, purpose, required)) in enumerate(KEY_FIELDS.items()):
            if st.session_state.user_keys.get(name):
                placeholder = "Saved for this session (leave blank to keep)"
            else:
                placeholder = "Required" if required else "Optional"
            entered[name] = cols[i % 2].text_input(
                f"{service} API Key" + ("" if required else " (optional)"), type="password",
                placeholder=placeholder, autocomplete="off",
                help=f"Used for {purpose}. Get a key: [{KEY_SIGNUP_URLS[name]}]({KEY_SIGNUP_URLS[name]})",
            )
        save_col, clear_col = st.columns([1, 1])
        saved = save_col.form_submit_button("Save keys", type="primary")
        cleared = clear_col.form_submit_button("Clear my keys")
    # Always reserve the message slot, so the status row below keeps its position between reruns.
    # Otherwise Streamlit leaves a faded copy of the old row on screen while an analysis runs.
    key_message = st.empty()
    if saved:
        for name, value in entered.items():
            if value.strip():
                st.session_state.user_keys[name] = value.strip()
        key_message.success("Keys saved for this session.")
    if cleared:
        st.session_state.user_keys = {}
        key_message.info("Session keys cleared.")

    keys_now = effective_keys()
    names = list(KEY_FIELDS)
    for start in range(0, len(names), 3):  # rows of three, so service names don't wrap mid-word
        for col, name in zip(st.columns(3), names[start:start + 3]):
            status = ("Configured" if getattr(keys_now, name)
                      else "Missing (required)" if KEY_FIELDS[name][2] else "Not set (optional)")
            col.markdown(f"**{key_link(name)}**  \n{status}")

# --- Target input -------------------------------------------------------------
st.subheader("Target Analysis")
complexity_help = {
    "Quick Scan": "Fast overview, fewest API calls.",
    "Standard Analysis": "Balanced depth and API usage.",
    "Comprehensive Investigation": "More tool calls and more detail per finding.",
    "Expert Deep Dive": "Maximum depth. Uses the most API quota and takes the longest.",
}
with st.form("analysis_form"):
    target_input = st.text_input(
        "Target",
        max_chars=253,
        placeholder="IP address, domain, CVE ID, or software + version (e.g. 'Apache httpd 2.4.62')",
    )
    depth_col, model_col = st.columns(2)
    complexity_level = depth_col.selectbox(
        "Analysis depth", list(COMPLEXITY_PROFILES), index=1,
        help="Controls how many tool calls the agent may make and how much detail is kept.")
    # An operator-set COHERE_MODEL that isn't in the list is offered too, as the default.
    model_options = list(dict.fromkeys([DEFAULT_MODEL, *AVAILABLE_MODELS]))
    model_choice = model_col.selectbox(
        "Cohere model", model_options, index=0,
        format_func=lambda m: f"{AVAILABLE_MODELS[m][0]} · {m}" if m in AVAILABLE_MODELS else m,
        help="All listed models support tool use. If your key can't use the chosen model, the analysis "
             f"automatically falls back to {AVAILABLE_MODELS['command-a-03-2025'][0].split(' (')[0]}.")
    st.caption(" | ".join(f"**{k}**: {v}" for k, v in complexity_help.items()))
    run_clicked = st.form_submit_button("Run Analysis", type="primary")

if run_clicked:
    target = classify_target(target_input)
    keys = effective_keys()
    wait = RUN_COOLDOWN_SECONDS - (time.time() - st.session_state.last_run)
    if target.type == "invalid":
        st.error(target.error)
    elif not keys.cohere:
        st.error(f"A Cohere API key is required. Get one free at {key_link('cohere')}, "
                 "then add it under API Keys Configuration.")
    elif wait > 0:
        st.warning(f"Please wait {int(wait) + 1}s before starting another analysis.")
    else:
        st.session_state.last_run = time.time()
        missing = [key_link(n) for n in ("virustotal", "abuseipdb") if not getattr(keys, n)]
        if target.type in ("ip", "domain") and (missing or not keys.shodan):
            notes = []
            if not keys.shodan:
                notes.append(f"No {key_link('shodan')} key, so Shodan's free InternetDB is used (no banners).")
            if missing:
                notes.append(f"Missing keys: {', '.join(missing)}. Those sources will be skipped.")
            st.info(" ".join(notes) + " Click a name to get a free key.")

        with st.status(f"Analyzing {escape_markdown(target.value)} ({target.type})...", expanded=True) as status:
            def on_event(kind, payload):
                if kind == "tool_start":
                    label = TOOL_LABELS.get(payload["tool"], payload["tool"])
                    status.write(f"Running **{label}** {describe_args(payload['arguments'])}")
                elif kind == "tool_end":
                    record = payload["record"]
                    if record.status == "error":
                        status.write(f"↳ {escape_markdown(record.result.get('error'))}"
                                     + key_hint(payload["tool"], record.result.get("error")))
                elif kind == "model_fallback":
                    status.write(f"Model `{payload['from']}` isn't available for this key; using `{payload['to']}`.")
                elif kind == "finalizing":
                    status.write("Writing the final report...")

            result = run_agent(target.value, keys, complexity_level, on_event=on_event, model=model_choice)
            if result.error:
                status.update(label=f"Analysis finished with an error: {escape_markdown(result.error)}",
                              state="error")
            else:
                status.update(label=f"Analysis complete ({result.duration_seconds}s, "
                                    f"{len(result.tool_calls)} tool calls, {result.model})",
                              state="complete", expanded=False)
        st.session_state.report_data = build_report_data(result)

# --- Results ----------------------------------------------------------------------
data = st.session_state.report_data
if data:
    meta, execution, summary = data["metadata"], data["execution"], data["summary"]
    st.divider()
    st.header(f"Security Report: {escape_markdown(meta['target'])}")
    st.caption(f"Model: {meta['model']} · Depth: {meta['complexity']} · Generated: {meta['generated_at']}")

    confirmed_kev = summary.get("cisa_kev_confirmed", [])
    related_kev = summary.get("cisa_kev_related", [])
    cve_table = build_cve_table(data)
    cols = st.columns(5)
    cols[0].metric("Tool calls", execution["total_tool_calls"])
    cols[1].metric("Successful", execution["successful_tool_calls"])
    if cve_table["total"]:  # the detailed lists are shortened, so count from the version checks' totals
        cols[2].metric("Confirmed CVEs", cve_table["total"],
                       help="CVEs that NVD's version ranges or a package advisory confirm for this exact version")
    else:
        cols[2].metric("CVEs referenced", len(summary["cves_referenced"]))
    cols[3].metric("KEV confirmed", len(confirmed_kev),
                   help="Exploited-in-the-wild CVEs (CISA KEV) confirmed to affect this target's exact version: "
                        + (", ".join(confirmed_kev) or "none"))
    cols[4].metric("KEV related", len(related_kev),
                   help="Exploited-in-the-wild CVEs for the same product family or vendor. Not confirmed "
                        "to affect this target: " + (", ".join(related_kev) or "none"))

    facts = data.get("key_facts") or []
    if facts:
        with st.container(border=True):
            st.markdown("**Key facts** · computed directly from the data sources, identical on every run")
            # Values include third-party text (banners, product names), so escape them.
            st.markdown("\n".join(f"- **{escape_markdown(f['label'])}:** {escape_markdown(f['value'])}"
                                  for f in facts))

    if cve_table["rows"]:
        st.markdown("**Confirmed vulnerabilities**")
        if cve_table["by_severity"]:
            st.altair_chart(severity_chart(cve_table["by_severity"]), width="stretch")
        # Streamlit's table scrolls sideways on narrow screens instead of squashing the columns.
        # Most important columns first, so a phone shows them without scrolling; Software only when it varies.
        columns = ["CVE", "Severity", "In CISA KEV", "EPSS %", "Fixed in", "CVSS", "Exploit published"]
        if len({row["Software"] for row in cve_table["rows"]}) > 1:
            columns.insert(1, "Software")
        st.dataframe(cve_table["rows"], hide_index=True, width="stretch", column_order=columns, column_config={
            "CVSS": st.column_config.NumberColumn(format="%.1f"),
            "EPSS %": st.column_config.NumberColumn(format="%.2f%%", help="Chance of exploitation in the next 30 days"),
            "In CISA KEV": st.column_config.CheckboxColumn(help="Known to be exploited in the wild"),
            "Exploit published": st.column_config.CheckboxColumn(help="Exploit code is on Exploit-DB"),
        })
        st.caption(f"Showing {len(cve_table['rows'])} of {cve_table['total']} confirmed CVEs, most urgent first "
                   "(in CISA KEV, then EPSS, then CVSS). Click a column heading to sort; on a phone, swipe the "
                   "table sideways for more columns.")

    st.markdown("**AI assessment**")
    # The report can echo untrusted third-party text: render Markdown only (no HTML), with remote images removed.
    st.markdown(sanitize_report_markdown(data["report_markdown"]))

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"vulnerability_report_{safe_filename(meta['target'])}_{stamp}"
    d1, d2 = st.columns(2)
    d1.download_button("Download report (Markdown)", build_markdown_export(data), f"{base}.md", "text/markdown",
                       on_click="ignore", width="stretch")
    d2.download_button("Download full data (JSON)", json.dumps(data, indent=2, default=str), f"{base}.json",
                       "application/json", on_click="ignore", width="stretch")

    st.subheader("Evidence: tool calls")
    for i, call in enumerate(data["tool_calls"], start=1):
        label = TOOL_LABELS.get(call["tool"], call["tool"])
        icon = {"success": "✅", "error": "❌"}.get(call["status"], "ℹ️")
        args = escape_markdown(", ".join(str(v) for v in call["arguments"].values() if v)[:120])
        with st.expander(f"{icon} {i}. {label}: {args} ({call['duration_ms']} ms)"):
            if call["status"] == "error":
                st.error(escape_markdown(call["result"].get("error"))
                         + key_hint(call["tool"], call["result"].get("error")))
            st.json(call["result"], expanded=False)

st.divider()
st.caption(
    "For legitimate security research, defensive security and education only. Only investigate systems you "
    "own or are authorized to assess, and follow each data provider's terms of service. Automated findings "
    "can be wrong. Verify before acting.  \n"
    "Testing so far has focused on common software and devices, so results for less common products may be "
    "less reliable. If a result looks wrong, please "
    "[open an issue](https://github.com/MRFrazer25/ai-vulnerability-exposure-analyzer/issues) with the target "
    "you used."
)
