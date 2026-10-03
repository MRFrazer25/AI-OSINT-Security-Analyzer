"""Streamlit front end for the AI OSINT Security Analyzer."""

import json
import logging
import os
import re
import time
from datetime import datetime

import streamlit as st

from ai import (AVAILABLE_MODELS, COMPLEXITY_PROFILES, DEFAULT_MODEL, build_markdown_export, build_report_data,
                escape_markdown, run_osint_agent, sanitize_report_markdown)
from osint_tools import KEY_SIGNUP_URLS, ApiKeys, classify_target, server_key_quota, validate_public_ip

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

RUN_COOLDOWN_SECONDS = 15
# name -> (service, env var, purpose, required)
KEY_FIELDS = {
    "cohere": ("Cohere", "COHERE_API_KEY", "runs the AI agent", True),
    "shodan": ("Shodan", "SHODAN_API_KEY", "exposed services and versions", False),
    "virustotal": ("VirusTotal", "VIRUSTOTAL_API_KEY", "malicious/suspicious detections", False),
    "abuseipdb": ("AbuseIPDB", "ABUSEIPDB_API_KEY", "IP abuse reports", False),
    "nvd": ("NVD", "NVD_API_KEY", "faster CVE lookups", False),
}
# Which key a tool depends on, so missing-key errors can link to the sign-up page.
TOOL_KEYS = {"osint_shodan_search": "shodan", "osint_virustotal_check": "virustotal",
             "osint_abuseipdb_check": "abuseipdb"}
TOOL_LABELS = {
    "osint_resolve_domain": "DNS resolution",
    "osint_shodan_search": "Shodan host lookup",
    "osint_virustotal_check": "VirusTotal reputation",
    "osint_abuseipdb_check": "AbuseIPDB reputation",
    "osint_version_specific_vulnerability_check": "Version-specific CVE check (NVD)",
    "osint_nvd_lookup": "NVD CVE lookup",
    "osint_cisa_kev_check": "CISA KEV check",
    "osint_cve_search": "NVD keyword search",
}


def setting(name: str, default: str = "") -> str:
    """Operator setting from Streamlit secrets, falling back to the environment / .env."""
    try:
        value = str(st.secrets.get(name, ""))
    except Exception:  # no secrets.toml
        value = ""
    return value or os.getenv(name, default)


def int_setting(name: str, default: int) -> int:
    try:
        return max(0, int(setting(name, str(default))))
    except ValueError:
        return default


def server_key_limits() -> tuple[int, int]:
    """(analyses per hour for all visitors, per visitor) that may use the server's keys."""
    return int_setting("SERVER_KEY_RUNS_PER_HOUR", 20), int_setting("SERVER_KEY_RUNS_PER_CLIENT_PER_HOUR", 5)


def server_keys() -> ApiKeys:
    """Keys configured by whoever runs the app (.env, environment, or Streamlit secrets).

    With SHARE_SERVER_KEYS=false they are never used, so every visitor must bring their own keys.
    """
    if setting("SHARE_SERVER_KEYS", "true").strip().lower() in ("false", "0", "no", "off"):
        return ApiKeys()
    return ApiKeys.from_env().with_overrides(**{name: setting(env) for name, (_, env, _, _) in KEY_FIELDS.items()})


def client_id() -> str:
    """Best-effort visitor address for the per-client limit (the process-wide limit is the real guard)."""
    address = st.context.ip_address or ""
    if not validate_public_ip(address)[0]:
        # Behind a reverse proxy the peer is the proxy; use the address it appended last.
        forwarded = (st.context.headers.get("X-Forwarded-For") or "").split(",")[-1].strip()
        address = forwarded or address
    return address or "local"


def effective_keys() -> ApiKeys:
    """Session keys typed by this user take precedence over server keys. Nothing is written to os.environ."""
    return server_keys().with_overrides(**st.session_state.user_keys)


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


st.set_page_config(page_title="AI OSINT Security Analyzer", page_icon="🔍", layout="wide")

st.session_state.setdefault("user_keys", {})
st.session_state.setdefault("report_data", None)
st.session_state.setdefault("last_run", 0.0)

st.title("AI OSINT Security Analyzer")
st.markdown("AI-driven security analysis of IPs, domains, CVEs and software versions, powered by Cohere Command models.")

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
3. Vulnerabilities are matched to exact versions using NVD's affected-version data, then ranked by CISA KEV (exploited in the wild), CVSS and EPSS.
4. It writes a report that cites each source.
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
"""
    )

# --- API keys ---------------------------------------------------------------
server = server_keys()
with st.expander("API Keys Configuration", expanded=not effective_keys().cohere):
    st.markdown("**Get your keys (all have free tiers):**  \n" + "  \n".join(
        f"- {key_link(n)}: {'required' if req else 'optional'}, {purpose}"
        for n, (_, _, purpose, req) in KEY_FIELDS.items()
    ))
    st.caption(
        "Keys you enter are kept only in this browser session's server-side memory. They are never written "
        "to disk or shared with other users, and they are cleared when the session ends."
    )
    if any(getattr(server, n) for n in KEY_FIELDS):
        total_limit, client_limit = server_key_limits()
        st.caption(f"Keys provided by this deployment are shared by all visitors and limited to {total_limit} "
                   f"analyses per hour ({client_limit} per visitor). Add your own keys to avoid the limit.")
    with st.form("api_keys_form", clear_on_submit=True):
        cols = st.columns(2)
        entered = {}
        for i, (name, (service, _, purpose, required)) in enumerate(KEY_FIELDS.items()):
            if st.session_state.user_keys.get(name):
                placeholder = "Saved for this session (leave blank to keep)"
            elif getattr(server, name):
                placeholder = "Provided by server config (leave blank to use it)"
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
    if saved:
        for name, value in entered.items():
            if value.strip():
                st.session_state.user_keys[name] = value.strip()
        st.success("Keys saved for this session.")
    if cleared:
        st.session_state.user_keys = {}
        st.info("Session keys cleared.")

    keys_now = effective_keys()
    status_cols = st.columns(len(KEY_FIELDS))
    for col, name in zip(status_cols, KEY_FIELDS, strict=True):
        col.markdown(f"**{key_link(name)}**  \n{'Configured' if getattr(keys_now, name) else 'Missing'}")

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
    uses_server_keys = any(getattr(server, n) and not st.session_state.user_keys.get(n) for n in KEY_FIELDS)
    if target.type == "invalid":
        st.error(target.error)
    elif not keys.cohere:
        st.error(f"A Cohere API key is required. Get one free at {key_link('cohere')}, "
                 "then add it under API Keys Configuration.")
    elif wait > 0:
        st.warning(f"Please wait {int(wait) + 1}s before starting another analysis.")
    elif uses_server_keys and (quota_wait := server_key_quota().acquire(client_id(), *server_key_limits())):
        st.warning(f"This deployment's shared API keys have reached their hourly limit. Try again in about "
                   f"{int(quota_wait // 60) + 1} min, or add your own keys under API Keys Configuration.")
    else:
        st.session_state.last_run = time.time()
        missing = [key_link(n) for n in ("shodan", "virustotal", "abuseipdb") if not getattr(keys, n)]
        if missing and target.type in ("ip", "domain"):
            st.info(f"Missing keys: {', '.join(missing)}. Those sources will be skipped. "
                    "Click a name to get a free key.")

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

            result = run_osint_agent(target.value, keys, complexity_level, on_event=on_event, model=model_choice)
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
    cols = st.columns(5)
    cols[0].metric("Tool calls", execution["total_tool_calls"])
    cols[1].metric("Successful", execution["successful_tool_calls"])
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

    st.markdown("**AI assessment**")
    # The report can echo untrusted third-party text: render Markdown only (no HTML), with remote images removed.
    st.markdown(sanitize_report_markdown(data["report_markdown"]))

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"osint_report_{safe_filename(meta['target'])}_{stamp}"
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
    "[open an issue](https://github.com/MRFrazer25/AI-OSINT-Security-Analyzer/issues) with the target you used."
)
