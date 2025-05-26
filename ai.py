import os
import re
import json
import requests
import ipaddress
import socket
from datetime import datetime
from typing import List

# Import OSINT libraries
import shodan
import vt
from abuseipdb_wrapper import AbuseIPDB
import cohere

# Load environment variables if .env file exists, but don't fail if it doesn't
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass
except Exception:
    pass

# Initialize Cohere Client
COHERE_API_KEY = os.getenv("COHERE_API_KEY")
if not COHERE_API_KEY:
    co = None
else:
    try:
        co = cohere.ClientV2(COHERE_API_KEY)
    except Exception:
        co = None

# API Keys for OSINT Tools
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY") or os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

# Initialize API clients
try:
    shodan_api = shodan.Shodan(SHODAN_API_KEY) if SHODAN_API_KEY else None
except Exception:
    shodan_api = None

vt_api_key = VT_API_KEY

try:
    abuseipdb_api = AbuseIPDB(api_key=ABUSEIPDB_API_KEY) if ABUSEIPDB_API_KEY else None
except Exception:
    abuseipdb_api = None


def refresh_api_clients():
    """Refresh API clients with current environment variables."""
    global co, shodan_api, vt_api_key, abuseipdb_api, COHERE_API_KEY, SHODAN_API_KEY, VT_API_KEY, ABUSEIPDB_API_KEY
    
    COHERE_API_KEY = os.getenv("COHERE_API_KEY")
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
    VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY") or os.getenv("VT_API_KEY")
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
    
    try:
        co = cohere.ClientV2(COHERE_API_KEY) if COHERE_API_KEY else None
    except Exception:
        co = None
    
    try:
        shodan_api = shodan.Shodan(SHODAN_API_KEY) if SHODAN_API_KEY else None
    except Exception:
        shodan_api = None
    
    vt_api_key = VT_API_KEY
    
    try:
        abuseipdb_api = AbuseIPDB(api_key=ABUSEIPDB_API_KEY) if ABUSEIPDB_API_KEY else None
    except Exception:
        abuseipdb_api = None


def validate_ip_address(ip_str):
    """Validate IP address format and ensure it's not private/reserved."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
            return False, f"IP {ip_str} is private/reserved and not suitable for OSINT analysis"
        return True, None
    except ValueError:
        return False, f"Invalid IP address format: {ip_str}"


def sanitize_input(user_input):
    """Sanitize user input to prevent injection attacks."""
    if not user_input or not isinstance(user_input, str):
        return ""
    # Use proper input validation
    user_input = user_input.strip()
    
    # Block dangerous URL schemes that can execute code
    dangerous_schemes = ['javascript:', 'vbscript:']
    for scheme in dangerous_schemes:
        if user_input.lower().startswith(scheme.lower()):
            return ""  # Reject entirely if dangerous scheme detected
    
    # Allow only alphanumeric, common punctuation, and safe characters for OSINT targets
    # This covers IP addresses, domains, CVE IDs, and software names
    import string
    allowed_chars = string.ascii_letters + string.digits + '.-_:/\\'
    sanitized = ''.join(char for char in user_input if char in allowed_chars)
    
    return sanitized[:100]


def resolve_domain_to_ips(domain_name: str):
    """Resolve domain name to IP addresses using multiple methods."""
    try:
        ips = []
        
        # Method 1: Basic socket resolution
        try:
            ip = socket.gethostbyname(domain_name)
            if ip and ip not in ips:
                ips.append(ip)
        except socket.gaierror:
            pass
        
        # Method 2: Get all IP addresses for the domain
        try:
            result = socket.getaddrinfo(domain_name, None)
            for item in result:
                ip = item[4][0]
                if ip and ip not in ips and not ip.startswith('::'): 
                    ips.append(ip)
        except socket.gaierror:
            pass
        
        # Method 3: Try common subdomains
        common_prefixes = ['www.', '']
        for prefix in common_prefixes:
            try:
                full_domain = f"{prefix}{domain_name}" if prefix else domain_name
                if full_domain != domain_name or not ips:  # Avoid duplicate if already attempted
                    ip = socket.gethostbyname(full_domain)
                    if ip and ip not in ips:
                        ips.append(ip)
            except socket.gaierror:
                continue
        
        return {
            "success": True if ips else False,
            "domain": domain_name,
            "resolved_ips": ips,
            "ip_count": len(ips),
            "primary_ip": ips[0] if ips else None
        }
    
    except Exception as e:
        return {
            "success": False,
            "domain": domain_name,
            "error": f"Domain resolution failed: {str(e)}",
            "resolved_ips": [],
            "ip_count": 0,
            "primary_ip": None
        }


def identify_target_type(target_input):
    """Identify target type with improved validation."""
    if not target_input:
        return "unknown"
    
    target_input = sanitize_input(target_input)
    target_input_upper = target_input.upper()
    
    if target_input_upper.startswith("CVE-") and re.match(r"^CVE-\d{4}-\d{4,}$", target_input_upper):
        return "cve"
    
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target_input):
        is_valid, error_msg = validate_ip_address(target_input)
        if is_valid:
            return "ip"
    
    if re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$", target_input):
        return "domain"
    
    software_keywords = ['apache', 'nginx', 'mysql', 'wordpress', 'drupal', 'joomla', 'tomcat', 
                        'jenkins', 'elasticsearch', 'mongodb', 'redis', 'openssh', 'openssl']
    if any(keyword.lower() in target_input.lower() for keyword in software_keywords):
        return "software"
    
    return "unknown"

# OSINT TOOLS - Converted to Cohere Agent Tools
def osint_shodan_search(target: str, banner_limit: int = 200):
    """Search Shodan for internet-connected device information. Accepts IP addresses or domain names."""
    if not shodan_api:
        return {"error": "Shodan API key not configured", "tool": "shodan"}
    
    # Check if input is an IP address or domain
    is_valid_ip, _ = validate_ip_address(target)
    
    if is_valid_ip:
        # Direct IP search
        ip_address = target
        domain_info = None
    else:
        # Domain resolution
        domain_resolution = resolve_domain_to_ips(target)
        if not domain_resolution.get("success") or not domain_resolution.get("resolved_ips"):
            return {
                "error": f"Could not resolve domain '{target}' to IP addresses",
                "tool": "shodan",
                "domain_resolution": domain_resolution
            }
        
        # Use the primary IP for Shodan search
        ip_address = domain_resolution["primary_ip"]
        domain_info = domain_resolution
    
    try:
        result = shodan_api.host(ip_address)
        if result and isinstance(result, dict):
            # Extract key information for the agent
            summary = {
                "ip": ip_address,
                "organization": result.get("org", "Unknown"),
                "country": result.get("country_name", "Unknown"),
                "city": result.get("city", "Unknown"),
                "ports": result.get("ports", []),
                "hostnames": result.get("hostnames", []),
                "services": [],
                "vulns": result.get("vulns", [])
            }
            
            # Extract service information with more details
            for item in result.get("data", []):
                service_info = {
                    "port": item.get("port"),
                    "protocol": item.get("transport", "tcp"),
                    "service": item.get("product", "Unknown"),
                    "version": item.get("version", "Unknown"),
                    "banner": item.get("data", "")[:banner_limit]  # Limit banner size based on complexity
                }
                if service_info["port"]:
                    summary["services"].append(service_info)
            
            # Extract software from services for vulnerability correlation
            discovered_software = []
            for service in summary["services"]:
                if service.get("service") and service["service"] != "Unknown":
                    software_name = service["service"].lower()
                    if software_name not in discovered_software:
                        discovered_software.append(software_name)
            
            response_data = {
                "success": True, 
                "tool": "shodan",
                "data": summary, 
                "discovered_software": discovered_software,
                "raw_data": result
            }
            
            # Add domain resolution info if this was a domain search
            if domain_info:
                response_data["domain_resolution"] = domain_info
                response_data["search_type"] = "domain_to_ip"
                response_data["original_target"] = target
            else:
                response_data["search_type"] = "direct_ip"
                response_data["original_target"] = target
            
            return response_data
        else:
            return {"success": False, "info": f"Limited data returned for IP {ip_address}", "tool": "shodan"}
            
    except shodan.APIError as e:
        return {"error": f"Shodan API error: {str(e)}", "tool": "shodan"}
    except Exception as e:
        return {"error": f"Shodan query error: {str(e)}", "tool": "shodan"}


def osint_virustotal_check(target: str, target_type: str):
    """Check VirusTotal for threat intelligence on IPs or domains."""
    if not vt_api_key: 
        return {"error": "VirusTotal API key not configured", "tool": "virustotal"}
    
    if target_type == "ip":
        is_valid, error_msg = validate_ip_address(target)
        if not is_valid:
            return {"error": error_msg, "tool": "virustotal"}
    elif target_type == "domain":
        if not re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$", target):
            return {"error": "Invalid domain format", "tool": "virustotal"}
    
    try:
        with vt.Client(vt_api_key) as client:
            if target_type == "ip":
                obj = client.get_object(f"/ip_addresses/{target}")
            elif target_type == "domain":
                obj = client.get_object(f"/domains/{target}")
            else:
                return {"error": f"Unsupported target type '{target_type}'", "tool": "virustotal"}
            
            attributes = obj.to_dict()
            reputation = attributes.get('last_analysis_stats', {})
            
            # Enhanced threat assessment
            malicious_count = reputation.get("malicious", 0)
            suspicious_count = reputation.get("suspicious", 0)
            clean_count = reputation.get("harmless", 0)
            undetected_count = reputation.get("undetected", 0)
            
            total_engines = malicious_count + suspicious_count + clean_count + undetected_count
            
            return {
                "success": True,
                "tool": "virustotal",
                "target": target,
                "target_type": target_type,
                "reputation_stats": reputation,
                "malicious_count": malicious_count,
                "suspicious_count": suspicious_count,
                "clean_count": clean_count,
                "undetected_count": undetected_count,
                "total_engines": total_engines,
                "threat_level": "HIGH" if malicious_count > 5 else "MEDIUM" if malicious_count > 0 or suspicious_count > 3 else "LOW",
                "threat_percentage": round((malicious_count / max(total_engines, 1)) * 100, 2) if total_engines > 0 else 0,
                "raw_data": attributes
            }
            
    except vt.APIError as e:
        if "NotFoundError" in str(e):
            return {"success": False, "info": f"{target_type.capitalize()} '{target}' not found in VirusTotal", "tool": "virustotal"}
        else:
            return {"error": f"VirusTotal API error: {str(e)}", "tool": "virustotal"}
    except Exception as e:
        return {"error": f"VirusTotal query error: {str(e)}", "tool": "virustotal"}


def osint_abuseipdb_check(ip_address: str):
    """Check AbuseIPDB for IP reputation and abuse reports."""
    if not abuseipdb_api: 
        return {"error": "AbuseIPDB API key not configured", "tool": "abuseipdb"}
    
    is_valid, error_msg = validate_ip_address(ip_address)
    if not is_valid:
        return {"error": error_msg, "tool": "abuseipdb"}
    
    try:
        # The abuseipdb_wrapper library requires adding IP and then checking
        abuseipdb_api.add_ip_list([ip_address])
        abuseipdb_api.check()  # This actually performs the API calls
        results = abuseipdb_api.get_db(matched_only=False)
        
        if results and ip_address in results:
            data = results[ip_address]
            abuse_confidence = data.get("abuseConfidenceScore", 0)
            
            return {
                "success": True,
                "tool": "abuseipdb",
                "ip": ip_address,
                "abuse_confidence": abuse_confidence,
                "country": data.get("countryCode", "Unknown"),
                "usage_type": data.get("usageType", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "domain": data.get("domain", "Unknown"),
                "total_reports": data.get("totalReports", 0),
                "num_distinct_users": data.get("numDistinctUsers", 0),
                "last_reported": data.get("lastReportedAt", "Never"),
                "threat_level": "HIGH" if abuse_confidence > 75 else "MEDIUM" if abuse_confidence > 25 else "LOW",
                "is_public": data.get("isPublic", True),
                "is_whitelisted": data.get("isWhitelisted", False),
                "raw_data": data
            }
        else:
            # Fall back to direct API call if wrapper doesn't work
            try:
                import requests
                url = "https://api.abuseipdb.com/api/v2/check"
                headers = {
                    'Accept': 'application/json',
                    'Key': ABUSEIPDB_API_KEY
                }
                params = {
                    'ipAddress': ip_address,
                    'maxAgeInDays': 90,
                    'verbose': ''
                }
                
                response = requests.get(url, headers=headers, params=params, timeout=10)
                if response.status_code == 200:
                    result = response.json()
                    data = result.get("data", {})
                    abuse_confidence = data.get("abuseConfidencePercentage", 0)
                    
                    return {
                        "success": True,
                        "tool": "abuseipdb",
                        "ip": ip_address,
                        "abuse_confidence": abuse_confidence,
                        "country": data.get("countryCode", "Unknown"),
                        "usage_type": data.get("usageType", "Unknown"),
                        "isp": data.get("isp", "Unknown"),
                        "domain": data.get("domain", "Unknown"),
                        "total_reports": data.get("totalReports", 0),
                        "num_distinct_users": data.get("numDistinctUsers", 0),
                        "last_reported": data.get("lastReportedAt", "Never"),
                        "threat_level": "HIGH" if abuse_confidence > 75 else "MEDIUM" if abuse_confidence > 25 else "LOW",
                        "is_public": data.get("isPublic", True),
                        "is_whitelisted": data.get("isWhitelisted", False),
                        "raw_data": data
                    }
                else:
                    return {"error": f"AbuseIPDB API returned status {response.status_code}", "tool": "abuseipdb"}
            except Exception as api_error:
                return {"error": f"AbuseIPDB direct API error: {str(api_error)}", "tool": "abuseipdb"}
            
    except Exception as e:
        return {"error": f"AbuseIPDB query error: {str(e)}", "tool": "abuseipdb"}


def osint_cve_search(search_term: str, result_limit: int = 10, reference_limit: int = 5):
    """Search CVE-Search API for vulnerability intelligence."""
    try:
        # Try multiple CVE search endpoints
        endpoints_to_try = []
        
        if search_term.upper().startswith("CVE-"):
            # Direct CVE lookup - try multiple endpoints
            endpoints_to_try = [
                f"https://cve.circl.lu/api/cve/{search_term}",
                f"https://opencve.io/cve/{search_term}",
                f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={search_term}"
            ]
        else:
            # Software search - try multiple endpoints
            endpoints_to_try = [
                f"https://cve.circl.lu/api/search/{search_term}",
                f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={search_term}&resultsPerPage=10"
            ]
        
        for url in endpoints_to_try:
            try:
                headers = {'User-Agent': 'AI-OSINT-Security-Analyzer'}
                response = requests.get(url, headers=headers, timeout=15)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Handle different API response formats - properly validate domain
                    from urllib.parse import urlparse
                    parsed_url = urlparse(url)
                    if parsed_url.netloc == "services.nvd.nist.gov":
                        # NVD API format
                        vulnerabilities = data.get("vulnerabilities", [])
                        if vulnerabilities:
                            vulns = []
                            for vuln_wrapper in vulnerabilities[:result_limit]:
                                cve_data = vuln_wrapper.get("cve", {})
                                vuln = {
                                    "cve_id": cve_data.get("id", "Unknown"),
                                    "summary": cve_data.get("descriptions", [{}])[0].get("value", "No description available")[:500],
                                    "published": cve_data.get("published", "Unknown"),
                                    "severity": "Unknown"
                                }
                                vulns.append(vuln)
                            
                            return {
                                "success": True,
                                "tool": "cve_search",
                                "search_term": search_term,
                                "search_type": "nvd_api",
                                "cve_count": len(vulns),
                                "vulnerabilities": vulns,
                                "discovered_cves": [v["cve_id"] for v in vulns],
                                "raw_data": vulnerabilities[:result_limit]
                            }
                    elif isinstance(data, dict) and "id" in data:
                        # CVE-Search single result format
                        vulnerability = {
                            "cve_id": data.get("id"),
                            "summary": data.get("summary", "No description available"),
                            "cvss": data.get("cvss", 0),
                            "published": data.get("Published", "Unknown"),
                            "modified": data.get("Modified", "Unknown"),
                            "access": data.get("access", {}),
                            "impact": data.get("impact", {}),
                            "references": data.get("references", [])[:reference_limit]
                        }
                        
                        return {
                            "success": True,
                            "tool": "cve_search", 
                            "search_term": search_term,
                            "search_type": "cve_direct",
                            "cve_count": 1,
                            "vulnerabilities": [vulnerability],
                            "raw_data": data
                        }
                    elif isinstance(data, list) and data:
                        # CVE-Search multiple results format
                        vulns = []
                        for item in data[:10]:
                            vuln = {
                                "cve_id": item.get("id"),
                                "summary": item.get("summary", "No description available"),
                                "cvss": item.get("cvss", 0),
                                "published": item.get("Published", "Unknown"),
                                "severity": "CRITICAL" if item.get("cvss", 0) >= 9.0 else "HIGH" if item.get("cvss", 0) >= 7.0 else "MEDIUM" if item.get("cvss", 0) >= 4.0 else "LOW"
                            }
                            vulns.append(vuln)
                        
                        return {
                            "success": True,
                            "tool": "cve_search",
                            "search_term": search_term,
                            "search_type": "software_search",
                            "cve_count": len(vulns),
                            "vulnerabilities": vulns,
                            "discovered_cves": [v["cve_id"] for v in vulns],
                            "raw_data": data[:10]
                        }
            except Exception as endpoint_error:
                # Continue to next endpoint
                continue
        
        # If all endpoints failed
        return {"success": False, "info": f"No vulnerability data found for '{search_term}' - all CVE sources unavailable", "tool": "cve_search"}
            
    except Exception as e: 
        return {"error": f"CVE-Search query error: {str(e)}", "tool": "cve_search"}


def osint_cisa_kev_check(cve_id: str = None, software_list: List[str] = None, kev_limit: int = 10):
    """Check CISA's Known Exploited Vulnerabilities catalog."""
    try:
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        response = requests.get(url, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            kev_list = data.get("vulnerabilities", [])
            
            matches = []
            
            if cve_id:
                # Direct CVE lookup
                for vuln in kev_list:
                    if vuln.get("cveID", "").upper() == cve_id.upper():
                        matches.append({
                            "cve_id": vuln.get("cveID"),
                            "vendor_project": vuln.get("vendorProject"),
                            "product": vuln.get("product"),
                            "vulnerability_name": vuln.get("vulnerabilityName"),
                            "date_added": vuln.get("dateAdded"),
                            "short_description": vuln.get("shortDescription"),
                            "required_action": vuln.get("requiredAction"),
                            "due_date": vuln.get("dueDate"),
                            "known_ransomware": vuln.get("knownRansomwareCampaignUse", "Unknown"),
                            "notes": vuln.get("notes", "")
                        })
            
            if software_list:
                # Software-based search
                for software in software_list:
                    for vuln in kev_list:
                        product = vuln.get("product", "").lower()
                        vendor = vuln.get("vendorProject", "").lower()
                        vuln_name = vuln.get("vulnerabilityName", "").lower()
                        
                        if (software.lower() in product or 
                            software.lower() in vendor or 
                            software.lower() in vuln_name):
                            
                            match = {
                                "cve_id": vuln.get("cveID"),
                                "vendor_project": vuln.get("vendorProject"),
                                "product": vuln.get("product"),
                                "vulnerability_name": vuln.get("vulnerabilityName"),
                                "date_added": vuln.get("dateAdded"),
                                "short_description": vuln.get("shortDescription"),
                                "required_action": vuln.get("requiredAction"),
                                "due_date": vuln.get("dueDate"),
                                "known_ransomware": vuln.get("knownRansomwareCampaignUse", "Unknown"),
                                "notes": vuln.get("notes", ""),
                                "matched_software": software
                            }
                            
                            # Avoid duplicates
                            if not any(m["cve_id"] == match["cve_id"] for m in matches):
                                matches.append(match)
            
            # Sort by date added (most recent first)
            matches.sort(key=lambda x: x.get("date_added", ""), reverse=True)
            
            return {
                "success": True,
                "tool": "cisa_kev",
                "total_kev_vulnerabilities": len(kev_list),
                "catalog_last_updated": data.get("dateReleased", "Unknown"),
                "search_criteria": {"cve_id": cve_id, "software_list": software_list},
                "matches_found": len(matches),
                "exploited_vulnerabilities": matches[:kev_limit],  # Limit results based on complexity
                "high_priority_count": len([m for m in matches if m.get("known_ransomware") == "Known"]),
                "raw_data": matches[:kev_limit]
            }
        else:
            return {"error": f"CISA KEV API returned status {response.status_code}", "tool": "cisa_kev"}
            
    except Exception as e:
        return {"error": f"CISA KEV query error: {str(e)}", "tool": "cisa_kev"}


def osint_nvd_lookup(cve_id: str, reference_limit: int = 5, config_limit: int = 3, cpe_limit: int = 2):
    """Look up CVE details from the National Vulnerability Database."""
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        headers = {
            "User-Agent": "AI-OSINT-Security-Analyzer"
        }
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            if vulnerabilities:
                cve_data = vulnerabilities[0].get("cve", {})
                metrics = cve_data.get("metrics", {})
                
                # Extract CVSS score with version preference
                cvss_score = 0
                cvss_vector = "Not available"
                cvss_version = "Unknown"
                
                if "cvssMetricV31" in metrics:
                    cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                    cvss_score = cvss_data.get("baseScore", 0)
                    cvss_vector = cvss_data.get("vectorString", "Not available")
                    cvss_version = "3.1"
                elif "cvssMetricV30" in metrics:
                    cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
                    cvss_score = cvss_data.get("baseScore", 0)
                    cvss_vector = cvss_data.get("vectorString", "Not available")
                    cvss_version = "3.0"
                elif "cvssMetricV2" in metrics:
                    cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
                    cvss_score = cvss_data.get("baseScore", 0)
                    cvss_vector = cvss_data.get("vectorString", "Not available")
                    cvss_version = "2.0"
                
                # Extract references
                references = []
                for ref in cve_data.get("references", [])[:reference_limit]:  # Limit references based on complexity
                    references.append({
                        "url": ref.get("url", ""),
                        "source": ref.get("source", ""),
                        "tags": ref.get("tags", [])
                    })
                
                # Extract affected configurations
                configurations = []
                for config in cve_data.get("configurations", [])[:config_limit]:  # Limit configs based on complexity
                    for node in config.get("nodes", []):
                        for cpe_match in node.get("cpeMatch", [])[:cpe_limit]:  # Limit CPE matches based on complexity
                            if cpe_match.get("vulnerable", False):
                                configurations.append({
                                    "criteria": cpe_match.get("criteria", ""),
                                    "version_start": cpe_match.get("versionStartIncluding", ""),
                                    "version_end": cpe_match.get("versionEndExcluding", "")
                                })
                
                return {
                    "success": True,
                    "tool": "nvd",
                    "cve_id": cve_id,
                    "description": cve_data.get("descriptions", [{}])[0].get("value", "No description available"),
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                    "cvss_version": cvss_version,
                    "severity": "CRITICAL" if cvss_score >= 9.0 else "HIGH" if cvss_score >= 7.0 else "MEDIUM" if cvss_score >= 4.0 else "LOW",
                    "published_date": cve_data.get("published", "Unknown"),
                    "last_modified": cve_data.get("lastModified", "Unknown"),
                    "source_identifier": cve_data.get("sourceIdentifier", "Unknown"),
                    "references": references,
                    "affected_configurations": configurations,
                    "raw_data": cve_data
                }
            else:
                return {"success": False, "info": f"CVE {cve_id} not found in NVD", "tool": "nvd"}
        else:
            return {"error": f"NVD API returned status {response.status_code}", "tool": "nvd"}
            
    except Exception as e:
        return {"error": f"NVD query error: {str(e)}", "tool": "nvd"}


def osint_version_specific_vulnerability_check(software_name: str, version: str = None, not_applicable_limit: int = 5, needs_review_limit: int = 3):
    """
    Enhanced version-specific vulnerability checking with proper version comparison,
    patch status tracking, and vulnerability applicability assessment.
    """
    try:
        import re
        from packaging import version as pkg_version
        from datetime import datetime, timedelta
        
        def parse_version(version_str):
            """Parse version string to comparable format"""
            if not version_str:
                return None
            # Extract numeric version (e.g., "2.4.62" from "apache httpd 2.4.62")
            match = re.search(r'(\d+\.[\d\.]+)', str(version_str))
            if match:
                try:
                    return pkg_version.parse(match.group(1))
                except:
                    return None
            return None
        
        def is_version_in_major_series(detected_ver, vuln_ver):
            """Check if versions are in the same major series (e.g., 2.4.x vs 1.3.x)"""
            if not detected_ver or not vuln_ver:
                return False
            detected_parts = str(detected_ver).split('.')
            vuln_parts = str(vuln_ver).split('.')
            
            # Compare major version (and minor if available)
            if len(detected_parts) >= 2 and len(vuln_parts) >= 2:
                return detected_parts[0] == vuln_parts[0] and detected_parts[1] == vuln_parts[1]
            elif len(detected_parts) >= 1 and len(vuln_parts) >= 1:
                return detected_parts[0] == vuln_parts[0]
            return False
        
        def get_vulnerability_age_years(published_date):
            """Calculate how old a vulnerability is in years"""
            if not published_date:
                return None
            try:
                # Handle different date formats
                for date_format in ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"]:
                    try:
                        vuln_date = datetime.strptime(published_date.split('T')[0], "%Y-%m-%d")
                        age = datetime.now() - vuln_date
                        return age.days / 365.25
                    except:
                        continue
            except:
                pass
            return None
        
        def check_vulnerability_applicability(vuln, detected_version):
            """Check if a vulnerability applies to the detected version with improved logic"""
            if not detected_version:
                return "UNKNOWN"
            
            vuln_summary = vuln.get("summary", "").lower()
            cve_id = vuln.get("cve_id", "")
            published_date = vuln.get("published", "")
            
            # Parse the detected version
            detected_ver = parse_version(detected_version)
            if not detected_ver:
                return "UNKNOWN"
            
            # Calculate vulnerability age
            vuln_age_years = get_vulnerability_age_years(published_date)
            
            # First, check for explicit version ranges in vulnerability description
            found_applicable = False
            found_not_applicable = False
            
            # Enhanced version patterns with better coverage
            version_patterns = [
                # "before" patterns
                (r'(?:versions?\s+)?before\s+(\d+\.[\d\.]+)', 'before'),
                (r'(?:versions?\s+)?prior\s+to\s+(\d+\.[\d\.]+)', 'before'),
                # Range patterns  
                (r'(?:versions?\s+)?(\d+\.[\d\.]+)\s+(?:through|to)\s+(\d+\.[\d\.]+)', 'range'),
                (r'(?:versions?\s+)?from\s+(\d+\.[\d\.]+)\s+(?:through|to)\s+(\d+\.[\d\.]+)', 'range'),
                # Specific version patterns
                (r'(?:versions?\s+)?(\d+\.[\d\.]+)\s+and\s+earlier', 'before_inclusive'),
                (r'(?:versions?\s+)?(\d+\.[\d\.]+)\s+and\s+below', 'before_inclusive'),
                # Inequality patterns
                (r'<\s*(\d+\.[\d\.]+)', 'before'),
                (r'<=\s*(\d+\.[\d\.]+)', 'before_inclusive'),
                # Specific version mentions
                (r'(?:versions?\s+)?(\d+\.[\d\.]+)(?:\s+only)?(?:\s+and\s+(?:earlier|below))?', 'specific')
            ]
            
            for pattern, pattern_type in version_patterns:
                matches = re.findall(pattern, vuln_summary)
                if matches:
                    try:
                        for match in matches:
                            if pattern_type == 'range' and isinstance(match, tuple) and len(match) == 2:
                                # Range pattern (e.g., "2.4.1 through 2.4.49")
                                start_ver = parse_version(match[0])
                                end_ver = parse_version(match[1])
                                if start_ver and end_ver:
                                    if start_ver <= detected_ver <= end_ver:
                                        return "VULNERABLE"
                                    elif is_version_in_major_series(detected_ver, start_ver):
                                        found_not_applicable = True
                                        
                            elif pattern_type in ['before', 'before_inclusive']:
                                # Before pattern (e.g., "before 2.4.50")
                                vuln_ver = parse_version(match if isinstance(match, str) else match[0])
                                if vuln_ver:
                                    comparison_op = '<=' if pattern_type == 'before_inclusive' else '<'
                                    if (comparison_op == '<=' and detected_ver <= vuln_ver) or \
                                       (comparison_op == '<' and detected_ver < vuln_ver):
                                        # Check if they're in the same major series
                                        if is_version_in_major_series(detected_ver, vuln_ver):
                                            return "VULNERABLE"
                                    elif is_version_in_major_series(detected_ver, vuln_ver):
                                        found_not_applicable = True
                                        
                            elif pattern_type == 'specific':
                                # Specific version mention
                                vuln_ver = parse_version(match if isinstance(match, str) else match[0])
                                if vuln_ver:
                                    if detected_ver == vuln_ver:
                                        return "VULNERABLE"
                                    elif is_version_in_major_series(detected_ver, vuln_ver):
                                        found_applicable = True
                    except Exception as e:
                        continue
            
            # Enhanced heuristic checks based on version series and age
            detected_major = str(detected_ver).split('.')[0] if detected_ver else "0"
            
            # Check if vulnerability is very old compared to detected version
            if vuln_age_years and vuln_age_years > 10:  # Vulnerability older than 10 years
                # Look for version indicators in the summary - generic patterns for any software
                old_version_indicators = [
                    r'(?:version\s+)?1\.\d+',  # Generic 1.x series
                    r'(?:version\s+)?0\.\d+',  # Generic 0.x series (very old)
                    r'(?:versions?\s+)?(?:before\s+)?2\.0\.',  # Before 2.0.x
                    r'(?:versions?\s+)?(?:prior\s+to\s+)?2\.0\.',  # Prior to 2.0.x
                    r'(?:versions?\s+)?1\.x',  # Explicit 1.x notation
                    r'(?:versions?\s+)?0\.x',  # Explicit 0.x notation
                ]
                
                for pattern in old_version_indicators:
                    if re.search(pattern, vuln_summary, re.IGNORECASE):
                        detected_major_int = int(detected_major) if detected_major.isdigit() else 0
                        
                        # If detected version is significantly newer than vulnerability mentions
                        if detected_major_int >= 2 and re.search(r'[01]\.\d+', vuln_summary):
                            return "NOT_APPLICABLE"
                        elif detected_major_int >= 3 and re.search(r'[012]\.\d+', vuln_summary):
                            return "NOT_APPLICABLE"
                        elif detected_major_int >= 4 and re.search(r'[0123]\.\d+', vuln_summary):
                            return "NOT_APPLICABLE"
            
            # If version-specific information found but no match, likely not applicable
            if found_not_applicable and not found_applicable:
                return "NOT_APPLICABLE"
            
            # For recent vulnerabilities (within last 5 years), be more cautious
            if vuln_age_years and vuln_age_years <= 5:
                return "NEEDS_VERIFICATION"
            
            # For older vulnerabilities without clear version info, likely not applicable
            if vuln_age_years and vuln_age_years > 8:
                return "NOT_APPLICABLE"
            
            return "NEEDS_VERIFICATION"
        
        # Search for vulnerabilities
        search_terms = []
        if version and version.lower() != "unknown":
            search_terms.extend([
                f"{software_name} {version}",
                f"{software_name.replace('_', ' ')} {version}",
                software_name
            ])
        else:
            search_terms.append(software_name)
        
        all_results = []
        for search_term in search_terms:
            try:
                cve_result = osint_cve_search(search_term)
                if cve_result.get("success") and cve_result.get("vulnerabilities"):
                    all_results.extend(cve_result["vulnerabilities"])
            except:
                continue
        
        # Remove duplicates and assess applicability
        seen_cves = set()
        unique_vulns = []
        vulnerable_to_current = []
        not_applicable = []
        needs_verification = []
        patched_not_vulnerable = []
        
        for vuln in all_results:
            cve_id = vuln.get("cve_id")
            if cve_id and cve_id not in seen_cves:
                seen_cves.add(cve_id)
                
                # Assess if this vulnerability applies to the detected version
                applicability = check_vulnerability_applicability(vuln, version)
                vuln["applicability_status"] = applicability
                vuln["reason"] = f"Applicability: {applicability}"
                
                unique_vulns.append(vuln)
                
                if applicability == "VULNERABLE":
                    vulnerable_to_current.append(vuln)
                elif applicability == "NOT_APPLICABLE":
                    not_applicable.append(vuln)
                elif applicability == "PATCHED_NOT_VULNERABLE":
                    patched_not_vulnerable.append(vuln)
                elif applicability in ["NEEDS_VERIFICATION", "POTENTIALLY_VULNERABLE"]:
                    needs_verification.append(vuln)
        
        # Generate assessment notes
        assessment_notes = []
        security_status = "SECURE"
        
        if version and version.lower() != "unknown":
            if vulnerable_to_current:
                assessment_notes.append(f"CRITICAL: Found {len(vulnerable_to_current)} vulnerabilities that specifically affect version {version}")
                security_status = "VULNERABLE"
            elif needs_verification:
                assessment_notes.append(f"REVIEW NEEDED: {len(needs_verification)} vulnerabilities require manual verification for version {version}")
                security_status = "REVIEW_NEEDED"
            else:
                assessment_notes.append(f"SECURE: No applicable vulnerabilities found for version {version}")
                security_status = "SECURE"
            
            if patched_not_vulnerable:
                assessment_notes.append(f"PATCHED: {len(patched_not_vulnerable)} vulnerabilities were fixed in this version")
            
            if not_applicable:
                assessment_notes.append(f"FILTERED OUT: {len(not_applicable)} outdated vulnerabilities that don't affect version {version}")
            
            # Add version context
            detected_ver = parse_version(version)
            if detected_ver:
                major_minor = '.'.join(str(detected_ver).split('.')[:2])
                assessment_notes.append(f"VERSION CONTEXT: Analyzing {software_name} {major_minor}.x series (detected: {version})")
        else:
            assessment_notes.append("Version not detected - performing generic vulnerability search without version filtering")
            security_status = "UNKNOWN"
        
        # Sort vulnerabilities by relevance and date - prioritize actually applicable ones
        relevant_vulns = []
        
        # First priority: vulnerabilities that definitely apply
        if vulnerable_to_current:
            relevant_vulns.extend(sorted(vulnerable_to_current, 
                                       key=lambda x: x.get("published", "1900-01-01"), 
                                       reverse=True)[:5])
        
        # Second priority: those needing verification (recent ones first)
        if needs_verification and len(relevant_vulns) < 10:
            remaining_slots = 10 - len(relevant_vulns)
            recent_verification = sorted(needs_verification, 
                                       key=lambda x: x.get("published", "1900-01-01"), 
                                       reverse=True)[:remaining_slots]
            relevant_vulns.extend(recent_verification)
        
        # Generate recommendations based on findings
        recommendations = []
        if vulnerable_to_current:
            recommendations.extend([
                f"IMMEDIATE ACTION: Update {software_name} to address {len(vulnerable_to_current)} confirmed vulnerabilities",
                "Review vendor security advisories for patch availability",
                "Consider implementing mitigating controls if patches are not available"
            ])
        elif needs_verification:
            recommendations.extend([
                f"VERIFICATION NEEDED: Manually review {len(needs_verification)} vulnerabilities for version {version}",
                "Check vendor security bulletins for version-specific guidance"
            ])
        else:
            recommendations.append(f"MAINTENANCE: Keep {software_name} {version} updated with latest security patches")
        
        return {
            "success": True,
            "tool": "version_specific_vulnerability_check",
            "software": software_name,
            "version": version,
            "security_status": security_status,
            "total_vulnerabilities_found": len(unique_vulns),
            "applicable_vulnerabilities": len(vulnerable_to_current),
            "not_applicable_vulnerabilities": len(not_applicable),
            "patched_vulnerabilities": len(patched_not_vulnerable),
            "needs_verification": len(needs_verification),
            "relevant_vulnerabilities": relevant_vulns,
            "vulnerable_to_current_version": vulnerable_to_current,
            "not_applicable_list": not_applicable[:not_applicable_limit],  # limits based on complexity
            "needs_verification_list": needs_verification[:needs_review_limit],  # limits based on complexity
            "assessment_notes": assessment_notes,
            "recommendations": recommendations,
            "version_analysis": {
                "version_detected": bool(version and version.lower() != "unknown"),
                "version_parsed_successfully": parse_version(version) is not None if version else False,
                "security_assessment": security_status,
                "major_series": '.'.join(str(parse_version(version)).split('.')[:2]) + '.x' if parse_version(version) else "Unknown",
                "filtering_applied": len(not_applicable) > 0,
                "total_filtered": len(not_applicable)
            }
        }
        
    except Exception as e:
        return {"error": f"Enhanced vulnerability check error: {str(e)}", "tool": "version_specific_vulnerability_check"}


def get_software_version_context(software_name: str, version: str):
    """
    Get version release context and security status for major software packages.
    This provides additional context for vulnerability assessment.
    """
    try:
        from packaging import version as pkg_version
        import re
        
        def parse_version(version_str):
            if not version_str:
                return None
            match = re.search(r'(\d+\.[\d\.]+)', str(version_str))
            if match:
                try:
                    return pkg_version.parse(match.group(1))
                except:
                    return None
            return None
        
        detected_ver = parse_version(version)
        if not detected_ver:
            return {"error": "Could not parse version", "software": software_name, "version": version}
        
        context = {
            "software": software_name,
            "version": version,
            "parsed_version": str(detected_ver),
            "version_status": "UNKNOWN",
            "release_context": "",
            "security_notes": [],
                        "patch_status": "UNKNOWN"
        }
        
        # Generic version status assessment
        context.update({
            "version_status": "DETECTED",
            "release_context": f"Version {version} detected - general security assessment available",
            "security_notes": [
                "Version detected and parsed successfully",
                "Use version-specific vulnerability check for detailed security assessment",
                "General vulnerability patterns applied"
            ],
            "patch_status": "ASSESSMENT_AVAILABLE"
        })
        
        # Add general recommendations
        recommendations = []
        if context["patch_status"] == "ASSESSMENT_AVAILABLE":
            recommendations.append("Use version-specific vulnerability assessment for detailed security analysis")
            recommendations.append("Compare detected version against known vulnerability databases")
            recommendations.append("Consider updating to latest stable version following security best practices")
        
        context["recommendations"] = recommendations
        
        return {
            "success": True,
            "tool": "version_context",
            **context
        }
        
    except Exception as e:
        return {"error": f"Version context lookup error: {str(e)}", "tool": "version_context"}


# Define tools for Cohere Command A
OSINT_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "osint_shodan_search",
            "description": "Search Shodan for internet-connected device information. Use this for IP addresses OR domain names to discover open ports, services, running software, and device details. For domains, it will automatically resolve to IP addresses first. Essential for network reconnaissance and discovering software that may have vulnerabilities.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "The IP address or domain name to search for (e.g., '8.8.8.8' or 'example.com'). For domains, will automatically resolve to IP addresses."
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "osint_virustotal_check",
            "description": "Check VirusTotal for threat intelligence and reputation data on IPs or domains. Use this to assess if a target is flagged as malicious by security vendors and get threat statistics.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "The IP address or domain to check (e.g., '8.8.8.8' or 'example.com')"
                    },
                    "target_type": {
                        "type": "string",
                        "description": "Type of target being checked",
                        "enum": ["ip", "domain"]
                    }
                },
                "required": ["target", "target_type"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "osint_abuseipdb_check",
            "description": "Check AbuseIPDB for IP reputation and abuse reports. Use this to determine if an IP has been reported for malicious activity, get abuse confidence scores, and ISP information.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ip_address": {
                        "type": "string",
                        "description": "The IP address to check for abuse reports (e.g., '8.8.8.8')"
                    }
                },
                "required": ["ip_address"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "osint_cve_search",
            "description": "Search for vulnerability information using CVE-Search. Use this to find CVEs related to specific software or to get details about a specific CVE ID. Particularly useful after discovering software from Shodan results.",
            "parameters": {
                "type": "object",
                "properties": {
                    "search_term": {
                        "type": "string",
                        "description": "CVE ID (e.g., 'CVE-2021-44228') or software name (e.g., 'apache', 'nginx') to search for vulnerabilities"
                    }
                },
                "required": ["search_term"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "osint_cisa_kev_check",
            "description": "Check CISA's Known Exploited Vulnerabilities catalog for actively exploited CVEs. Use this to determine if vulnerabilities are being exploited in the wild. Essential for risk prioritization.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cve_id": {
                        "type": "string",
                        "description": "Specific CVE ID to check (e.g., 'CVE-2021-44228'). Optional if checking by software."
                    },
                    "software_list": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of software names to check for known exploited vulnerabilities. Optional if checking specific CVE."
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "osint_nvd_lookup",
            "description": "Look up detailed CVE information from the National Vulnerability Database including CVSS scores, descriptions, references, and affected configurations. Use for comprehensive CVE analysis.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cve_id": {
                        "type": "string",
                        "description": "The CVE ID to look up (e.g., 'CVE-2021-44228')"
                    }
                },
                "required": ["cve_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "osint_version_specific_vulnerability_check",
            "description": "Check for vulnerabilities specific to a software version. CRITICAL: This function requires specific version numbers for accurate assessment (e.g., 'apache httpd 2.4.62', 'nginx 1.20.1'). Without version info, results will be generic and may include irrelevant ancient CVEs. This helps the AI agent make accurate assessments about whether detected software versions are actually vulnerable.",
            "parameters": {
                "type": "object",
                "properties": {
                    "software_name": {
                        "type": "string",
                        "description": "The name of the software to check for vulnerabilities (e.g., 'apache httpd', 'nginx', 'MySQL')"
                    },
                    "version": {
                        "type": "string",
                        "description": "REQUIRED for accurate assessment: The specific version of the software (e.g., '2.4.62', '1.20.1', '8.0.33'). If unknown, results will be generic and less accurate."
                    }
                },
                "required": ["software_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_software_version_context",
            "description": "Get version release context and security status for major software packages. IMPORTANT: Both software name AND version are required for meaningful analysis (e.g., 'apache httpd' and '2.4.62'). This provides additional context for vulnerability assessment.",
            "parameters": {
                "type": "object",
                "properties": {
                    "software_name": {
                        "type": "string",
                        "description": "The name of the software (e.g., 'apache httpd', 'nginx', 'MySQL')"
                    },
                    "version": {
                        "type": "string",
                        "description": "REQUIRED: The specific version of the software (e.g., '2.4.62', '1.20.1', '8.0.33'). Function will fail without version info."
                    }
                },
                "required": ["software_name", "version"]
            }
        }
    }
]

# Complexity-based result limits
COMPLEXITY_LIMITS = {
    "Quick Scan": {
        "cve_results": 3,
        "references": 2, 
        "kev_matches": 3,
        "not_applicable": 2,
        "needs_review": 1,
        "configurations": 2,
        "cpe_matches": 1,
        "banner_length": 100
    },
    "Standard Analysis": {
        "cve_results": 10,
        "references": 5,
        "kev_matches": 10, 
        "not_applicable": 5,
        "needs_review": 3,
        "configurations": 3,
        "cpe_matches": 2,
        "banner_length": 200
    },
    "Comprehensive Investigation": {
        "cve_results": 20,
        "references": 8,
        "kev_matches": 15,
        "not_applicable": 8, 
        "needs_review": 5,
        "configurations": 5,
        "cpe_matches": 3,
        "banner_length": 300
    },
    "Expert Deep Dive": {
        "cve_results": 50,
        "references": 15,
        "kev_matches": 25,
        "not_applicable": 15,
        "needs_review": 10,
        "configurations": 8,
        "cpe_matches": 5,
        "banner_length": 500
    }
}

# Functions map for tool execution
OSINT_FUNCTIONS_MAP = {
    "osint_shodan_search": osint_shodan_search,
    "osint_virustotal_check": osint_virustotal_check,
    "osint_abuseipdb_check": osint_abuseipdb_check,
    "osint_cve_search": osint_cve_search,
    "osint_cisa_kev_check": osint_cisa_kev_check,
    "osint_nvd_lookup": osint_nvd_lookup,
    "osint_version_specific_vulnerability_check": osint_version_specific_vulnerability_check,
    "get_software_version_context": get_software_version_context
}

# MAIN AGENT CODE

def run_osint_agent(target_input: str, complexity_level: str = "Standard Analysis", user_query: str = None):
    """Run the AI OSINT Security Analyzer using Cohere's Tool Use framework."""
    
    if not co:
        return "Error: Cohere API key not configured. Please configure your Cohere API key in the application settings.", {}

    # Get complexity limits
    limits = COMPLEXITY_LIMITS.get(complexity_level, COMPLEXITY_LIMITS["Standard Analysis"])

    # Identify target type for context
    target_type = identify_target_type(target_input)
    
    # Construct the agent prompt based on target type
    if not user_query:
        if target_type == "ip":
            user_query = f"Perform a COMPREHENSIVE security analysis of IP address {target_input}. You MUST use ALL available tools in this sequence: 1) osint_shodan_search to discover network services and software, 2) osint_virustotal_check and osint_abuseipdb_check for threat intelligence, 3) osint_cve_search for EACH discovered software, 4) osint_cisa_kev_check for EACH discovered software, 5) osint_nvd_lookup for any critical CVEs found, 6) osint_version_specific_vulnerability_check for EACH versioned software discovered, 7) get_software_version_context for major software packages. Do NOT stop early - use ALL tools for complete coverage."
        elif target_type == "domain":
            user_query = f"Perform COMPREHENSIVE security analysis of domain {target_input}. You MUST use ALL available tools in this sequence: 1) osint_shodan_search to discover all associated IP addresses, infrastructure, and services, 2) osint_virustotal_check for comprehensive threat intelligence and reputation analysis, 3) osint_abuseipdb_check for ALL discovered IP addresses to check abuse reports, 4) osint_cve_search for ANY software/technologies discovered from Shodan or VirusTotal, 5) osint_cisa_kev_check for each software package found, 6) osint_nvd_lookup for any critical CVEs discovered, 7) osint_version_specific_vulnerability_check for any versioned software found. Provide detailed domain infrastructure analysis, security posture assessment, and comprehensive threat intelligence. Do NOT stop early - use ALL tools."
        elif target_type == "cve":
            user_query = f"Provide COMPREHENSIVE analysis of {target_input}. You MUST use ALL available tools: 1) osint_nvd_lookup for detailed CVE information, 2) osint_cisa_kev_check to check exploitation status, 3) osint_cve_search for additional context and related vulnerabilities. Use ALL tools for complete CVE analysis."
        elif target_type == "software":
            user_query = f"Perform COMPREHENSIVE vulnerability analysis of {target_input}. CRITICAL: For accurate vulnerability assessment, software analysis requires specific version information (e.g., 'apache httpd 2.4.62', 'nginx 1.20.1', 'MySQL 8.0.33'). If no version is provided, request clarification. You MUST use ALL available tools: 1) osint_cve_search to find related CVEs, 2) osint_cisa_kev_check to determine active exploitation, 3) osint_nvd_lookup for detailed CVE information, 4) osint_version_specific_vulnerability_check with version info, 5) get_software_version_context for version analysis. Use ALL tools for complete software security assessment."
        else:
            user_query = f"Perform COMPREHENSIVE analysis of {target_input}. Determine the target type and use ALL available OSINT tools systematically to gather complete security intelligence. Do NOT stop early - use ALL tools for maximum coverage."
    
    # Initialize conversation with improved system prompt
    messages = [
        {
            "role": "system",
            "content": """You are an expert AI OSINT Security Analyzer specialized in cybersecurity intelligence gathering. Your mission is to autonomously investigate targets using multiple intelligence sources and provide comprehensive security assessments.

Available OSINT Tools:
- osint_shodan_search: Network reconnaissance for IP addresses (discovers services, software, ports)
- osint_virustotal_check: Threat intelligence and reputation checking for IPs/domains  
- osint_abuseipdb_check: IP abuse and reputation analysis
- osint_cve_search: Vulnerability research for CVEs and software
- osint_cisa_kev_check: Known Exploited Vulnerabilities (actively exploited threats)
- osint_nvd_lookup: Detailed CVE information from official database
- osint_version_specific_vulnerability_check: Version-aware vulnerability assessment for accurate analysis

Investigation Methodology - COMPREHENSIVE ANALYSIS REQUIRED:
1. **Target Classification**: Determine target type and appropriate investigation approach
2. **MANDATORY Tool Execution**: You MUST use ALL available tools for complete coverage:
   - For IP targets: Shodan > VirusTotal > AbuseIPDB > CVE-Search > CISA KEV > NVD > Version-Specific Analysis
   - For Domain/Website targets: Shodan > VirusTotal > AbuseIPDB > CVE-Search > CISA KEV > NVD > Version-Specific Analysis
   - For CVE targets: NVD > CISA KEV > CVE-Search for context
   - For Software targets: CVE-Search > CISA KEV > NVD > Version-Specific Analysis
3. **Tool Sequencing**: Follow logical order but ensure ALL tools are used, even if initial results seem sufficient
4. **Cross-Correlation**: Connect findings across ALL intelligence sources
5. **Risk Assessment**: Evaluate threat levels using data from ALL tools
6. **Comprehensive Reporting**: Synthesize ALL findings with actionable security recommendations

Key Principles:
- **USE ALL TOOLS**: Never stop early - execute all relevant tools for comprehensive analysis
- Always cite your sources and tool outputs from ALL tools used
- Explain the security implications of findings from EVERY tool
- Prioritize actively exploited vulnerabilities from CISA KEV analysis
- Correlate software discoveries with vulnerability research from ALL sources
- Provide clear threat level assessments based on ALL intelligence sources
- Use logical tool sequencing but ensure COMPLETE coverage

MANDATORY TOOL USAGE FOR IP ANALYSIS:
1. osint_shodan_search (discover services/software)
2. osint_virustotal_check (threat intelligence)
3. osint_abuseipdb_check (reputation analysis)
4. osint_cve_search (for each discovered software)
5. osint_cisa_kev_check (for each discovered software)
6. osint_nvd_lookup (for any high-severity CVEs found)
7. osint_version_specific_vulnerability_check (for each versioned software)
8. get_software_version_context (for major software packages)

MANDATORY TOOL USAGE FOR DOMAIN/WEBSITE ANALYSIS:
1. osint_shodan_search (discover all IPs, infrastructure, services)
2. osint_virustotal_check (comprehensive domain threat intelligence)
3. osint_abuseipdb_check (for ALL discovered IP addresses)
4. osint_cve_search (for any discovered software/services)
5. osint_cisa_kev_check (for each discovered software)
6. osint_nvd_lookup (for any critical CVEs found)
7. osint_version_specific_vulnerability_check (for versioned software)
8. get_software_version_context (for major software packages)

MANDATORY TOOL USAGE FOR DOMAIN ANALYSIS:
1. osint_shodan_search (discover all IPs, subdomains, infrastructure)
2. osint_virustotal_check (comprehensive threat intelligence)
3. osint_abuseipdb_check (for ALL discovered IPs)
4. osint_cve_search (for any discovered software/services)
5. osint_cisa_kev_check (for each discovered software)
6. osint_nvd_lookup (for any critical CVEs found)
7. osint_version_specific_vulnerability_check (for versioned software)

DOMAIN ANALYSIS BEST PRACTICES:
- Use Shodan to discover complete domain infrastructure before other tools
- Analyze ALL IP addresses associated with the domain
- Look for subdomains, services, and hosting infrastructure
- When reporting hostnames found via Shodan IP lookups, clearly state that these are hostnames associated with the IP address(es) and may include other domains if on shared infrastructure. Distinguish these from hostnames directly resolvable from the target domain.
- Cross-reference threat intelligence across all discovered assets
- Provide infrastructure mapping and security posture assessment
- Include hosting provider analysis and potential attack vectors

CRITICAL VULNERABILITY ASSESSMENT GUIDELINES:
- **VERSION INFORMATION IS MANDATORY**: For software analysis, ALWAYS require specific version numbers
- Examples of CORRECT software targets: "apache httpd 2.4.62", "nginx 1.20.1", "MySQL 8.0.33", "OpenSSL 1.1.1w"
- Examples of INCORRECT software targets: "apache", "nginx", "mysql" (missing version = inaccurate assessment)
- ALWAYS use osint_version_specific_vulnerability_check for software with version information from Shodan
- The system intelligently filters vulnerabilities based on version applicability to avoid ancient/irrelevant CVEs
- Only report vulnerabilities with security_status "VULNERABLE" as actual threats to the detected version
- Acknowledge filtered vulnerabilities: mention how many old/irrelevant CVEs were filtered out
- Use the security_status field to determine overall vulnerability state:
  * SECURE = No applicable vulnerabilities found for this version
  * VULNERABLE = Confirmed vulnerabilities that affect this specific version  
  * REVIEW_NEEDED = Some vulnerabilities need manual verification for this version
  * UNKNOWN = Cannot determine due to missing version info (REQUEST VERSION INFO)
- Focus on the "applicable_vulnerabilities" count for actual threats
- Reference the "total_filtered" count to show the system's intelligence
- Use version_analysis.major_series to show you understand the software series (e.g., "apache 2.4.x series")
- If software is analyzed WITHOUT version info, explicitly state this limitation and request version details

EXAMPLE CORRECT ASSESSMENT:
GOOD: "apache httpd 2.4.62 (2.4.x series) - SECURE: No vulnerabilities found that affect this version. System filtered out 15 ancient CVEs (1999-2006) that only affected 1.x and early 2.0.x series."

GOOD: "apache httpd 2.4.45 - VULNERABLE: 3 vulnerabilities confirmed to affect this version. System filtered out 12 irrelevant old CVEs."

AVOID: "apache has 18 vulnerabilities including CVE-1999-0236..." (mixing old irrelevant CVEs with current threats)

When you discover software from Shodan, always use version-specific vulnerability checking to make accurate assessments."""
        },
        {
            "role": "user", 
            "content": user_query
        }
    ]
    
    # Track all tool results for final report
    all_tool_results = {}
    max_iterations = 25  # Increased for comprehensive tool usage
    iteration = 0
    
    print(f"Starting AI OSINT Security Analyzer analysis for: {target_input}")
    
    while iteration < max_iterations:
        iteration += 1
        
        # Get response from Cohere with tools
        try:
            response = co.chat(
                model="command-a-03-2025",
                messages=messages,
                tools=OSINT_TOOLS,
                temperature=0.1,
                max_tokens=4000
            )
        except Exception as e:
            return f"Error communicating with Cohere: {str(e)}", all_tool_results
        
        # Check if the agent wants to use tools
        if response.message.tool_calls:
            print(f"Agent iteration {iteration}: Planning {len(response.message.tool_calls)} tool call(s)")
            
            # First, add the assistant message with tool calls to maintain conversation flow
            assistant_message = {
                "role": "assistant",
                "tool_calls": response.message.tool_calls
            }
            
            # Add content if present
            if response.message.content:
                assistant_content = response.message.content[0].text if isinstance(response.message.content, list) else response.message.content
                assistant_message["content"] = assistant_content
            
            # Add tool_plan if present  
            if hasattr(response.message, 'tool_plan') and response.message.tool_plan:
                assistant_message["tool_plan"] = response.message.tool_plan
            
            messages.append(assistant_message)
            
            # Execute each tool call
            for tool_call in response.message.tool_calls:
                tool_name = tool_call.function.name
                
                try:
                    tool_params = json.loads(tool_call.function.arguments)
                except json.JSONDecodeError as e:
                    print(f"JSON decode error for {tool_name}: {e}")
                    continue
                
                print(f"Executing: {tool_name}")
                
                # Execute the tool
                if tool_name in OSINT_FUNCTIONS_MAP:
                    try:
                        # Add complexity-based limits to tool parameters
                        if tool_name == "osint_shodan_search":
                            tool_params["banner_limit"] = limits["banner_length"]
                        elif tool_name == "osint_cve_search":
                            tool_params["result_limit"] = limits["cve_results"]
                            tool_params["reference_limit"] = limits["references"]
                        elif tool_name == "osint_cisa_kev_check":
                            tool_params["kev_limit"] = limits["kev_matches"]
                        elif tool_name == "osint_nvd_lookup":
                            tool_params["reference_limit"] = limits["references"]
                            tool_params["config_limit"] = limits["configurations"]
                            tool_params["cpe_limit"] = limits["cpe_matches"]
                        elif tool_name == "osint_version_specific_vulnerability_check":
                            tool_params["not_applicable_limit"] = limits["not_applicable"]
                            tool_params["needs_review_limit"] = limits["needs_review"]
                        
                        tool_result = OSINT_FUNCTIONS_MAP[tool_name](**tool_params)
                        tool_key = f"{tool_name}_{iteration}"
                        all_tool_results[tool_key] = tool_result
                        
                        # Add execution info
                        tool_result["_execution_info"] = {
                            "iteration": iteration,
                            "timestamp": datetime.now().isoformat(),
                            "parameters": tool_params
                        }
                        
                        # Add tool result to conversation in proper format for Command A
                        tool_content = []
                        if isinstance(tool_result, dict):
                            tool_content.append({
                                "type": "document", 
                                "document": {"data": json.dumps(tool_result, default=str)}
                            })
                        else:
                            tool_content.append({
                                "type": "document",
                                "document": {"data": str(tool_result)}
                            })
                        
                        messages.append({
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "content": tool_content
                        })
                        
                        # Print execution status
                        if tool_result.get("success"):
                            print(f"{tool_name}: Success")
                        elif tool_result.get("error"):
                            print(f"{tool_name}: {tool_result['error']}")
                        else:
                            print(f"{tool_name}: Info returned")
                    
                    except Exception as e:
                        error_result = {
                            "error": f"Tool execution failed: {str(e)}", 
                            "tool": tool_name,
                            "_execution_info": {
                                "iteration": iteration,
                                "timestamp": datetime.now().isoformat(),
                                "parameters": tool_params
                            }
                        }
                        all_tool_results[f"{tool_name}_{iteration}"] = error_result
                        
                        error_content = [{
                            "type": "document",
                            "document": {"data": json.dumps(error_result, default=str)}
                        }]
                        
                        messages.append({
                            "role": "tool", 
                            "tool_call_id": tool_call.id,
                            "content": error_content
                        })
                        print(f"{tool_name}: Execution failed - {str(e)}")
                else:
                    error_result = {
                        "error": f"Unknown tool: {tool_name}",
                        "_execution_info": {
                            "iteration": iteration,
                            "timestamp": datetime.now().isoformat()
                        }
                    }
                    all_tool_results[f"{tool_name}_{iteration}"] = error_result
                    
                    error_content = [{
                        "type": "document",
                        "document": {"data": json.dumps(error_result, default=str)}
                    }]
                    
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id, 
                        "content": error_content
                    })
                    print(f"Unknown tool: {tool_name}")
            
            # Continue conversation to get agent's analysis of tool results
            continue
        else:
            # No more tool calls, add final assistant message
            assistant_content = ""
            if response.message.content:
                assistant_content = response.message.content[0].text if isinstance(response.message.content, list) else response.message.content
            
            messages.append({
                "role": "assistant",
                "content": assistant_content
            })
            
            # Agent has completed analysis
            print(f"Agent analysis completed after {iteration} iterations")
            break
    
    # Get final response
    final_response = messages[-1]["content"] if messages and messages[-1]["role"] == "assistant" else "Analysis incomplete - no final response generated"
    
    return final_response, all_tool_results


def generate_report_metadata(target_input, target_type):
    """Generate metadata for the security report."""
    return {
        "report_timestamp": datetime.now().isoformat(),
        "target": target_input,
        "target_type": target_type,
        "generated_by": "AI OSINT Security Analyzer (AI Agent Framework)",
        "agent_framework": "Cohere Tool Use",
        "cohere_model": "command-a-03-2025"
    }


def get_security_report(target_input, complexity_level: str = "Standard Analysis"):
    """Main function for generating security reports using the AI agent."""
    try:
        # Run the AI agent
        print(f"Initializing AI OSINT Security Analyzer for target: {target_input}")
        agent_report, tool_results = run_osint_agent(target_input, complexity_level)
        
        discovered_software = []
        discovered_cves = []
        cisa_kev_matches = []
        
        # Process tool results to extract structured data
        for tool_key, result in tool_results.items():
            if isinstance(result, dict):
                # Extract software from Shodan results
                if "shodan_search" in tool_key and result.get("success"):
                    discovered_software.extend(result.get("discovered_software", []))
                
                # Extract CVEs from CVE-Search results  
                if "cve_search" in tool_key and result.get("success"):
                    discovered_cves.extend(result.get("discovered_cves", []))
                
                # Extract CISA KEV matches
                if "cisa_kev" in tool_key and result.get("success"):
                    cisa_kev_matches.extend(result.get("exploited_vulnerabilities", []))
        
        raw_data_collection = {
            "target_info": {
                "target": target_input,
                "target_type": identify_target_type(target_input),
                "analysis_timestamp": datetime.now().isoformat()
            },
            "agent_tool_calls": tool_results,
            "agent_reasoning": agent_report,
            
            "discovered_software": list(set(discovered_software)),
            "discovered_cves": list(set(discovered_cves)),
            "cisa_kev_matches": cisa_kev_matches,
            "cve_search_exploits": discovered_cves,
            "nvd_cve_details": [],
            
            # Enhanced agent statistics
            "execution_summary": {
                "total_tools_called": len(tool_results),
                "successful_tools": len([r for r in tool_results.values() if isinstance(r, dict) and r.get("success")]),
                "failed_tools": len([r for r in tool_results.values() if isinstance(r, dict) and r.get("error")]),
                "tools_used": list(set([tool.split('_')[1] + '_' + tool.split('_')[2] 
                                      for tool in tool_results.keys() if '_' in tool])),
                "total_iterations": max([r.get("_execution_info", {}).get("iteration", 0) 
                                       for r in tool_results.values() if isinstance(r, dict)], default=0),
                "analysis_duration": "Dynamic based on agent decisions"
            }
        }
        
        nvd_details = []
        for tool_key, result in tool_results.items():
            if "nvd_lookup" in tool_key and isinstance(result, dict) and result.get("success"):
                nvd_details.append(result)
        raw_data_collection["nvd_cve_details"] = nvd_details
        
        print("Security report generation completed successfully")
        return agent_report, raw_data_collection
        
    except Exception as e:
        print(f"Agent execution failed: {str(e)}")
        error_report = f"AI OSINT Security Analyzer execution failed: {str(e)}\n\nThis error occurred during the AI agent's autonomous analysis. Please check your API keys and network connectivity."
        error_collection = {
            "target_info": {
                "target": target_input,
                "target_type": identify_target_type(target_input),
                "analysis_timestamp": datetime.now().isoformat()
            },
            "errors": {"agent_execution": str(e)},
            "agent_tool_calls": {},
            "discovered_software": [],
            "discovered_cves": [],
            "cisa_kev_matches": [],
            "cve_search_exploits": [],
            "nvd_cve_details": []
        }
        return error_report, error_collection 