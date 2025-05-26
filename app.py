import streamlit as st
import os
import json
import re
from datetime import datetime
from ai import get_security_report, identify_target_type, generate_report_metadata, refresh_api_clients

def sanitize_ai_report(content):
    """
    Sanitize AI-generated report content for safe HTML rendering.
    Allows basic formatting while removing potentially dangerous elements.
    """
    if not isinstance(content, str):
        return str(content)
    
    # Remove script tags and their content completely
    content = re.sub(r'<script[^>]*>.*?</script>', '', content, flags=re.DOTALL | re.IGNORECASE)
    
    # Remove any onclick, onload, onerror and other event handlers
    content = re.sub(r'\s*on\w+\s*=\s*["\'][^"\']*["\']', '', content, flags=re.IGNORECASE)
    
    # Remove javascript: links
    content = re.sub(r'javascript:[^"\']*', '', content, flags=re.IGNORECASE)
    
    # Remove potentially dangerous attributes (keeping basic formatting)
    content = re.sub(r'\s*(?:style|class)\s*=\s*["\'][^"\']*["\']', '', content, flags=re.IGNORECASE)
    
    return content

# Load environment variables if .env file exists, but don't fail if it doesn't
try:
    from dotenv import load_dotenv
    load_dotenv()  # Load .env file if it exists, but don't fail if it doesn't
except ImportError:
    pass  # dotenv not installed, continue without it
except Exception:
    pass  # .env file doesn't exist or couldn't be loaded, continue without it

# Page Configuration
st.set_page_config(
    page_title="AI OSINT Agent", 
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if 'analysis_results' not in st.session_state:
    st.session_state.analysis_results = None
if 'analysis_metadata' not in st.session_state:
    st.session_state.analysis_metadata = None

# Initialize API keys from environment if they exist
if 'api_keys' not in st.session_state:
    st.session_state.api_keys = {
        'SHODAN_API_KEY': os.getenv('SHODAN_API_KEY', ''),
        'VIRUSTOTAL_API_KEY': os.getenv('VIRUSTOTAL_API_KEY', '') or os.getenv('VT_API_KEY', ''),
        'ABUSEIPDB_API_KEY': os.getenv('ABUSEIPDB_API_KEY', ''),
        'COHERE_API_KEY': os.getenv('COHERE_API_KEY', '')
    }

# Custom CSS for styling
st.html("""
<style>
    .main-header {
        text-align: center;
        padding: 1rem 0;
        margin-bottom: 1rem;
    }
    .block-container {
        padding-top: 2rem;
    }
</style>
""")

# Main Header
st.title("AI OSINT Security Analyzer")
st.markdown("**AI-Powered Security Analysis using Cohere's Command A Model**")
st.markdown("*Advanced multi-step intelligence gathering with smart tool selection*")

# Sidebar with Instructions and Information
with st.sidebar:
    st.markdown("## Instructions")
    st.markdown("""
    **Supported Input Types:**
    - **IP Addresses**: e.g., `8.8.8.8`
    - **Domain Names**: e.g., `example.com`
    - **CVE IDs**: e.g., `CVE-2021-44228`
    - **Software + Version**: e.g., `apache httpd 2.4.62`, `nginx 1.20.1` **Version Required for Accurate Analysis**
    
    **Agent Analysis Process:**
    1. **Target Identification**: AI agent analyzes input type
    2. **Smart Planning**: Agent creates investigation strategy
    3. **Tool Selection**: Agent chooses appropriate OSINT tools
    4. **Multi-step Execution**: Agent follows logical sequence
    5. **Data Correlation**: Agent connects findings across sources
    6. **Security Assessment**: Comprehensive risk evaluation
    
    **Agent Features:**
    - **Smart Decision Making**: No manual tool selection needed
    - **Adaptive Workflows**: Investigation path adjusts based on findings
    - **Multi-step Tool Use**: Agent chains tools intelligently
    - **Source References**: All findings linked back to sources
    """)
    
    st.markdown("## OSINT Tool Collection")
    st.markdown("""
    The agent has access to these specialized tools:
    - **[Shodan](https://www.shodan.io/)** - Network reconnaissance
    - **[VirusTotal](https://www.virustotal.com/)** - Threat intelligence
    - **[AbuseIPDB](https://www.abuseipdb.com/)** - IP reputation analysis
    - **[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)** - Active exploits
    - **[NVD](https://nvd.nist.gov/)** - Vulnerability database
    - **[CVE-Search](https://cve.circl.lu/)** - Exploit intelligence
    
    *Powered by [Cohere's Command A](https://cohere.com/blog/command-a) AI model*
    """)

# Main Content Area
st.markdown("---")

# API Keys Management Section
with st.expander("API Keys Configuration", expanded=False):
    st.warning("**Security Notice:** API keys entered here are stored temporarily in your browser session only and are not saved permanently or shared.")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**Required APIs:**")
        
        shodan_key = st.text_input(
            "Shodan API Key",
            value=st.session_state.api_keys.get('SHODAN_API_KEY', ''),
            type="password",
            help="Get your free API key from https://account.shodan.io/"
        )
        
        virustotal_key = st.text_input(
            "VirusTotal API Key",
            value=st.session_state.api_keys.get('VIRUSTOTAL_API_KEY', ''),
            type="password",
            help="Get your free API key from https://www.virustotal.com/gui/join-us"
        )
        
        abuseipdb_key = st.text_input(
            "AbuseIPDB API Key",
            value=st.session_state.api_keys.get('ABUSEIPDB_API_KEY', ''),
            type="password",
            help="Get your free API key from https://www.abuseipdb.com/api"
        )
    
    with col2:
        cohere_key = st.text_input(
            "Cohere API Key",
            value=st.session_state.api_keys.get('COHERE_API_KEY', ''),
            type="password",
            help="Get your API key from https://dashboard.cohere.ai/api-keys"
        )
        
        st.markdown("**API Key Status:**")
        
        # Check which APIs are configured
        keys_status = []
        if shodan_key: keys_status.append("Shodan: Configured")
        else: keys_status.append("Shodan: Missing")
        
        if virustotal_key: keys_status.append("VirusTotal: Configured")
        else: keys_status.append("VirusTotal: Missing")
        
        if abuseipdb_key: keys_status.append("AbuseIPDB: Configured")
        else: keys_status.append("AbuseIPDB: Missing")
        
        if cohere_key: keys_status.append("Cohere: Configured")
        else: keys_status.append("Cohere: Missing")
        
        for status in keys_status:
            st.markdown(status)
    
    # Save API keys button
    if st.button("Save API Keys", type="primary"):
        # Store in session state (temporary, secure)
        st.session_state.api_keys = {
            'SHODAN_API_KEY': shodan_key,
            'VIRUSTOTAL_API_KEY': virustotal_key,
            'ABUSEIPDB_API_KEY': abuseipdb_key,
            'COHERE_API_KEY': cohere_key
        }
        
        # Temporarily set environment variables for this session
        if shodan_key:
            os.environ['SHODAN_API_KEY'] = shodan_key
        if virustotal_key:
            os.environ['VIRUSTOTAL_API_KEY'] = virustotal_key
        if abuseipdb_key:
            os.environ['ABUSEIPDB_API_KEY'] = abuseipdb_key
        if cohere_key:
            os.environ['COHERE_API_KEY'] = cohere_key
        
        # Refresh API clients with new keys
        refresh_api_clients()
            
        st.success("API keys saved for this session!")
        st.info("Note: Keys are only stored temporarily and will be cleared when you close your browser.")

# Input Section with improved styling
st.subheader("Target Analysis")

# Analysis complexity selection
complexity_level = st.selectbox(
    "Analysis Complexity Level:",
    ("Quick Scan", "Standard Analysis", "Comprehensive Investigation", "Expert Deep Dive"),
    index=1,  # Default to "Standard Analysis"
    help="Choose the depth of detail in the report. All tools are used regardless of level, but higher levels show more detailed results and examples."
)

# Show complexity info
complexity_info = {
    "Quick Scan": "Fast overview with key findings (~3-5 results per category)",
    "Standard Analysis": "Balanced detail with good context (~5-10 results per category)", 
    "Comprehensive Investigation": "Detailed analysis with extensive data (~10-20 results per category)",
    "Expert Deep Dive": "Maximum forensic detail (~20-50 results per category)"
}
st.info(complexity_info[complexity_level])

col1, col2 = st.columns([4, 1])

with col1:
    target_input = st.text_input(
        "Enter target for analysis:",
        placeholder="IP address, domain, CVE ID, or software+version (e.g., 'apache httpd 2.4.62')",
        help="Enter the target you want to analyze. For software analysis, include specific version numbers for accurate vulnerability assessment (e.g., 'apache httpd 2.4.62' instead of just 'apache').",
        key="target_input"
    )

with col2:
    st.write("")
    analyze_button = st.button("Run Analysis", type="primary", use_container_width=True)

# Analysis Results
if analyze_button:
    if not target_input:
        st.error("Please enter a target to analyze.")
    else:
        target_type = identify_target_type(target_input)
        
        if target_type == "unknown":
            st.warning("Could not identify target type. Please ensure you've entered a valid IP address, domain name, CVE ID, or software name.")
        else:
            with st.spinner(f"AI Agent analyzing '{target_input}' (detected as: {target_type}) with {complexity_level}..."):
                try:
                    report, raw_data_collection = get_security_report(target_input, complexity_level)

                    # Store results in session state
                    st.session_state.analysis_results = {
                        'report': report,
                        'raw_data_collection': raw_data_collection,
                        'target_input': target_input,
                        'target_type': target_type
                    }
                    
                    # Generate metadata for downloads
                    st.session_state.analysis_metadata = generate_report_metadata(target_input, target_type)
                    
                    st.success("Agent analysis completed successfully!")
                    
                except Exception as e:
                    st.error(f"Agent execution failed: {e}")
                    st.exception(e)

# Display results if they exist in session state
if st.session_state.analysis_results is not None:
    results = st.session_state.analysis_results
    metadata = st.session_state.analysis_metadata
    
    # Main Report Section
    st.markdown("---")
    st.header("Security Intelligence Report")
    
    # Download Section
    st.subheader("Export Report")
    col1, col2, col3 = st.columns(3)
    
    # Prepare download data
    full_report_data = {
        "metadata": metadata,
        "intelligence_report": results['report'],
        "raw_intelligence": results['raw_data_collection']
    }
    
    report_json = json.dumps(full_report_data, indent=2, default=str)
    
    with col1:
        st.download_button(
            label="Download Full Report (JSON)",
            data=report_json,
            file_name=f"ai_osint_report_{results['target_input'].replace('.', '_').replace(':', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            help="Download complete report with all raw data",
            on_click=lambda: None  # Prevent rerun
        )
    
    with col2:
        # Create summary report
        summary_data = {
            "metadata": metadata,
            "intelligence_report": results['report'],
            "summary_statistics": {
                "discovered_software": len(results['raw_data_collection'].get("discovered_software", [])),
                "discovered_cves": len(results['raw_data_collection'].get("discovered_cves", [])),
                "cisa_kev_matches": len(results['raw_data_collection'].get("cisa_kev_matches", [])),
                "cve_search_results": len(results['raw_data_collection'].get("cve_search_exploits", [])),
                "nvd_entries": len(results['raw_data_collection'].get("nvd_cve_details", []))
            }
        }
        summary_json = json.dumps(summary_data, indent=2, default=str)
        
        st.download_button(
            label="Download Summary (JSON)",
            data=summary_json,
            file_name=f"ai_osint_summary_{results['target_input'].replace('.', '_').replace(':', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            help="Download summary report without raw API responses",
            on_click=lambda: None  # Prevent rerun
        )
    
    with col3:
        # Create text report
        text_report = f"""AI OSINT Security Report
Generated: {metadata['report_timestamp']}
Target: {metadata['target']} ({metadata['target_type']})
Generated by: {metadata['generated_by']}

{results['report']}

--- Statistics ---
Discovered Software: {len(results['raw_data_collection'].get("discovered_software", []))}
Discovered CVEs: {len(results['raw_data_collection'].get("discovered_cves", []))}
CISA KEV Matches: {len(results['raw_data_collection'].get("cisa_kev_matches", []))}
CVE-Search Results: {len(results['raw_data_collection'].get("cve_search_exploits", []))}
NVD Entries: {len(results['raw_data_collection'].get("nvd_cve_details", []))}
"""
        
        st.download_button(
            label="Download Text Report",
            data=text_report,
            file_name=f"ai_osint_report_{results['target_input'].replace('.', '_').replace(':', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain",
            help="Download human-readable text report",
            on_click=lambda: None  # Prevent rerun
        )

    # AI Intelligence Report
    st.subheader("AI Agent Intelligence Assessment")
    # Sanitize AI report content before rendering
    sanitized_report = sanitize_ai_report(results['report'])
    st.markdown(sanitized_report, unsafe_allow_html=True)

    # Detailed Intelligence Section
    st.markdown("---")
    st.header("Agent Tool Execution Details")
    
    # Show agent execution summary
    if results['raw_data_collection'].get("execution_summary"):
        summary = results['raw_data_collection']['execution_summary']
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Tools Called", summary.get('total_tools_called', 0))
        with col2:
            st.metric("Successful Calls", summary.get('successful_tools', 0))
        with col3:
            st.metric("Unique Tools", len(summary.get('tools_used', [])))

    # Target Information
    if results['raw_data_collection'].get("target_info"):
        with st.expander("Target Analysis", expanded=True):
            st.json(results['raw_data_collection']["target_info"])

    # Agent Tool Calls
    if results['raw_data_collection'].get("agent_tool_calls"):
        st.subheader("Agent Tool Call History")
        st.markdown("**Agent's autonomous tool execution sequence:**")
        tool_calls = results['raw_data_collection']['agent_tool_calls']
        for tool_call, result in tool_calls.items():
            tool_name = tool_call.split('_')[1] + '_' + tool_call.split('_')[2] if '_' in tool_call else tool_call
            if isinstance(result, dict) and result.get("success"):
                st.success(f"{tool_name}: Successful")
            elif isinstance(result, dict) and result.get("error"):
                st.error(f"{tool_name}: {result['error']}")
            else:
                st.info(f"{tool_name}: Info returned")
            if st.button(f"View {tool_name} details", key=f"details_{tool_call}"):
                st.json(result)

# Footer
st.markdown("---")
st.html("""
<div style="text-align: center; font-size: small; color: #666;">
    <p><strong>AI OSINT Security Analyzer</strong> | Built with Cohere Command A and OSINT APIs</p>
    <p>For educational, research, and defensive cybersecurity purposes only. Use responsibly and in compliance with applicable laws.</p>
    <p><strong>Security Notice:</strong> This tool is designed for legitimate security research and defensive cybersecurity purposes only. Users are responsible for ensuring compliance with applicable laws and regulations. Unauthorized use against systems you do not own or have explicit permission to test is prohibited.</p>
</div>
""") 