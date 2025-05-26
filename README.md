# AI OSINT Security Analyzer

An intelligent cybersecurity platform that uses AI agents to conduct autonomous OSINT investigations across multiple intelligence sources. Powered by Cohere's Command A model, it automatically selects tools, correlates findings, and provides comprehensive security assessments.

## Features

* **AI-Powered Analysis:** Autonomous tool selection and multi-step reasoning for comprehensive investigations.
* **Complexity-Based Reports:** Choose from Quick Scan, Standard Analysis, Comprehensive Investigation, or Expert Deep Dive.
* **Multi-Source Intelligence:** Integrates Shodan, VirusTotal, AbuseIPDB, CVE databases, CISA KEV, and NVD.
* **Version-Aware Vulnerability Assessment:** Accurate analysis for specific software versions with intelligent filtering.
* **Infrastructure Mapping:** Complete domain-to-IP analysis with hosting and service discovery.
* **Real-Time Threat Intelligence:** Identifies actively exploited vulnerabilities and threat indicators.
* **Secure & Private:** No data collection, session-only API key storage, advanced input sanitization.

## Target Types (With Examples)

* **IP Addresses:** `8.8.8.8` - Network services, reputation, hosting analysis
* **Domain Names:** `example.com` - DNS infrastructure, subdomain mapping
* **CVE IDs:** `CVE-2021-44228` - Vulnerability details and exploitation status
* **Software + Version:** `apache httpd 2.4.62` - Version-specific vulnerability assessment

## Requirements

* Python 3.8+
* Internet connection for OSINT API access
* API keys (see Setup for free tier options)

## Setup and Installation

### Option 1: Streamlit Website

**[Streamlit Link](https://osint-ai.streamlit.app)**

## Running the Application

### Option 2: Local Installation

1. **Clone Repository:**
   ```bash
   git clone https://github.com/MRFrazer25/AI-OSINT-Security-Analyzer.git
   cd AI-OSINT-Security-Analyzer
   ```

2. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Setup Configuration:**
   ```bash
   python setup.py
   ```
   This creates a `.env.example` template. Copy it to `.env` and add your API keys:
   ```bash
   cp .env.example .env
   # Edit .env with your API keys
   ```

4. **Get API Keys (Free Tiers Available):**
   * **[Cohere API](https://dashboard.cohere.ai/api-keys)** - Required for AI agent (1,000 calls/month free)
   * **[Shodan](https://account.shodan.io/)** - Network reconnaissance (100 queries/month free)
   * **[VirusTotal](https://www.virustotal.com/gui/join-us)** - Threat intelligence (500 queries/day free)
   * **[AbuseIPDB](https://www.abuseipdb.com/api)** - IP reputation (1,000 queries/day free)
   
   *CVE-Search, CISA KEV, and NVD require no API keys*

```bash
python -m streamlit run app.py
```

Open your browser to `http://localhost:8501`, configure your API keys in the web interface, and start analyzing targets.

## How It Works

The AI agent automatically:
1. **Analyzes** your target type (IP, domain, CVE, software)
2. **Selects** optimal OSINT tools for investigation
3. **Executes** tools in intelligent sequence based on discoveries
4. **Correlates** findings across all intelligence sources
5. **Synthesizes** comprehensive security assessment with risk prioritization

Choose your complexity level for report detail - all levels use the same comprehensive tool suite.

## Security

* **No Persistent Storage:** All analysis data processed in-memory only
* **Session-Only API Keys:** Never permanently stored or committed to files
* **Input Sanitization:** Advanced protection against injection attacks
* **Zero Telemetry:** No user tracking, analytics, or data collection
* **Local Processing:** Analysis runs entirely on your chosen environment

## Troubleshooting

* **Import Errors:** Ensure all dependencies installed: `pip install -r requirements.txt`
* **API Key Issues:** Verify keys are correctly added in web interface or `.env` file
* **Streamlit Not Found:** Install streamlit: `pip install streamlit`
* **Tool Failures:** Check internet connectivity and API key validity

## License

MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is designed for legitimate security research, defensive cybersecurity, and educational purposes only. Users are responsible for ensuring compliance with applicable laws and regulations. Unauthorized use against systems you do not own or have explicit permission to test is prohibited.