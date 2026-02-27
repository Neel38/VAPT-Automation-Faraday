import os
import re
import sys
import json
import logging
from datetime import datetime
import xml.etree.ElementTree as ET

import requests
from requests.auth import HTTPBasicAuth
import yaml


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


class ReportParser:
    """Parses vulnerability scan reports from multiple tools."""
    
    # Severity normalization mapping
    SEVERITY_MAP = {
        # Nessus severity levels
        'critical': 'critical',
        'high': 'high',
        'medium': 'medium',
        'low': 'low',
        'info': 'info',
        'informational': 'info',
        
        # OpenVAS severity levels (0-10)
        '9-10': 'critical',
        '7-8.9': 'high',
        '5-6.9': 'medium',
        '3-4.9': 'low',
        '0-2.9': 'info',
    }
    
    def __init__(self, config_path: str = 'config/settings.yaml'):
        """Initialize report parser with configuration and Faraday session."""
        self.config = self._load_config(config_path)
        self.faraday_url = self.config['faraday']['url']

        # Credentials for Faraday Community Edition (cookie-based auth)
        self.username = os.getenv(
            'FARADAY_USERNAME',
            self.config['faraday'].get('username', 'admin'),
        )
        self.password = os.getenv(
            'FARADAY_PASSWORD',
            self.config['faraday'].get('password', ''),
        )

        if not self.username or not self.password:
            logger.error(
                "Faraday username/password not configured. "
                "Set FARADAY_USERNAME and FARADAY_PASSWORD environment variables."
            )
            sys.exit(1)

        self.session = requests.Session()
        self._login()
    
    def _load_config(self, config_path: str) -> dict:
        """Load configuration from YAML file."""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.error(f"Config file not found: {config_path}")
            sys.exit(1)

    def _login(self) -> None:
        """Authenticate to Faraday API using cookie-based session."""
        login_url = f"{self.faraday_url}/_api/login"
        try:
            resp = self.session.post(
                login_url,
                json={"email": self.username, "password": self.password},
                timeout=self.config['faraday']['timeout'],
            )
            resp.raise_for_status()
            logger.info("Authenticated to Faraday API (session cookie established).")
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to authenticate to Faraday API: {e}")
            sys.exit(1)
    
    def parse(self, file_path: str, tool_type: str = None) -> list[dict]:
        """Parse report file based on tool type."""
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            raise FileNotFoundError(f"Report file not found: {file_path}")
        
        # Auto-detect tool type if not specified
        if tool_type is None:
            tool_type = self._detect_tool_type(file_path)
        
        tool = tool_type.lower()
        logger.info(f"Parsing {tool} report: {file_path}")
        
        if tool == 'nessus':
            self.findings = self._parse_nessus(file_path)
        elif tool == 'nmap':
            self.findings = self._parse_nmap(file_path)
        elif tool == 'openvas':
            self.findings = self._parse_openvas(file_path)
        elif tool == 'burp':
            self.findings = self._parse_burp(file_path)
        elif tool == 'zap':
            self.findings = self._parse_zap(file_path)
        else:
            logger.error(f"Unsupported tool type: {tool_type}")
            raise ValueError(f"Tool type '{tool_type}' is not supported")
        
        logger.info(f"Extracted {len(self.findings)} findings from {tool_type} report")
        return self.findings
    
    def _detect_tool_type(self, file_path: str) -> str:
        """Auto-detect tool type from file content."""
        try:
            # Try XML-based formats first
            if file_path.endswith(('.xml', '.nessus')):
                tree = ET.parse(file_path)
                root = tree.getroot()
                
                if root.tag == 'NessusClientData':
                    return 'nessus'
                elif root.tag == 'nmaprun':
                    return 'nmap'
                elif root.tag == 'report':
                    # Check for OpenVAS report element
                    if root.find('.//report') is not None or root.find('Report') is not None:
                        return 'openvas'
                elif root.tag == 'Issues':
                    return 'burp'
                
                # Fallback to file extension/content hints
                if file_path.endswith('.nessus'):
                    return 'nessus'
                elif file_path.endswith('.xml'):
                    content = open(file_path, 'r').read(500)
                    lowered = content.lower()
                    if 'openvas' in lowered:
                        return 'openvas'
                    if 'burp' in lowered:
                        return 'burp'

            # Try JSON-based formats (e.g. OWASP ZAP)
            if file_path.endswith('.json'):
                with open(file_path, 'r') as f:
                    sample = f.read(2048)
                data = json.loads(sample)
                # Heuristic: ZAP JSON usually has 'site' and 'alerts'
                if isinstance(data, dict) and 'site' in data:
                    return 'zap'
        except Exception as e:
            logger.warning(f"Could not auto-detect tool type: {str(e)}")
        
        raise ValueError("Could not auto-detect tool type. Please specify with --type")
    
    def _parse_nessus(self, file_path: str) -> list[dict]:
        """Parse Nessus .nessus XML file."""
        findings = []
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            for host in root.findall('.//ReportHost'):
                host_ip = host.get('name')
                
                for item in host.findall('.//ReportItem'):
                    plugin_id = item.get('pluginID')
                    plugin_name = item.get('pluginName')
                    severity = item.get('severity', '0')
                    
                    # Get port
                    port = item.get('port', 'N/A')
                    
                    # Get CVE if available
                    cve = None
                    cve_elem = item.find('cve')
                    if cve_elem is not None:
                        cve = cve_elem.text
                    
                    # Get CVSS score
                    cvss_score = None
                    cvss_elem = item.find('cvss_score')
                    if cvss_elem is not None:
                        try:
                            cvss_score = float(cvss_elem.text)
                        except (ValueError, TypeError):
                            cvss_score = None
                    
                    # Get description
                    description_parts = []
                    synopsis = item.find('synopsis')
                    if synopsis is not None:
                        description_parts.append(synopsis.text or '')
                    description = item.find('description')
                    if description is not None:
                        description_parts.append(description.text or '')
                    
                    full_description = ' '.join(filter(None, description_parts))
                    
                    # Normalize severity
                    severity_norm = self._normalize_severity(severity)
                    
                    # Skip info-level if not explicitly included
                    if severity_norm == 'info':
                        continue
                    
                    finding = {
                        'host': host_ip,
                        'port': port,
                        'vulnerability': plugin_name,
                        'severity': severity_norm,
                        'cve': cve,
                        'cvss_score': cvss_score,
                        'description': full_description,
                        'tool': 'Nessus',
                        'plugin_id': plugin_id,
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    findings.append(finding)
            
            logger.info(f"Parsed {len(findings)} findings from Nessus report")
            return findings
            
        except Exception as e:
            logger.error(f"Failed to parse Nessus report: {str(e)}")
            raise
    

    def _parse_nmap(self, file_path: str) -> list[dict]:
        """Parse Nmap XML and extract results from vulnerability scripts."""
        findings = []
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            for host in root.findall('host'):
                ip = host.find('address').get('addr')
                for port_elem in host.findall('.//port'):
                    port_id = port_elem.get('portid')
                    for script in port_elem.findall('script'):
                        script_id = script.get('id')
                        output = script.get('output') or ""
                        
                        # Only extract if Nmap script indicates a vulnerability
                        if "VULNERABLE" in output.upper():
                            findings.append({
                                'host': ip,
                                'port': port_id,
                                'vulnerability': script_id,
                                'severity': 'high',  # Nmap vuln scripts usually indicate high risk
                                'description': output,
                                'tool': 'Nmap',
                                'timestamp': datetime.now().isoformat()
                            })
            return findings
        except Exception as e:
            logger.error(f"Failed to parse Nmap report: {str(e)}")
            raise


    def _parse_openvas(self, file_path: str) -> list[dict]:
        """Parse OpenVAS XML report."""
        findings = []
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Navigate to results section
            results = root.find('.//results') or root.find('.//Result')
            if results is None:
                logger.warning("No results found in OpenVAS report")
                return findings
            
            for result in results.findall('result') or results.findall('Result'):
                host = result.find('host')
                host_ip = host.text if host is not None else 'Unknown'
                
                port = result.find('port')
                port_num = port.text if port is not None else 'N/A'
                
                task = result.find('task')
                task_name = task.find('name').text if task is not None and task.find('name') is not None else 'N/A'
                
                nvt = result.find('nvt')
                if nvt is None:
                    continue
                
                threat = nvt.find('cvss_base')
                severity_score = None
                if threat is not None:
                    try:
                        severity_score = float(threat.text)
                    except (ValueError, TypeError):
                        severity_score = None
                
                # Normalize OpenVAS severity score to our levels
                severity = self._normalize_openvas_severity(severity_score)
                
                name = nvt.find('name')
                vulnerability_name = name.text if name is not None else 'Unknown'
                
                # Get CVE
                cve = None
                cve_elem = nvt.find('.//cve')
                if cve_elem is not None:
                    cve = cve_elem.text
                
                summary = nvt.find('summary')
                description = summary.text if summary is not None else ''
                
                finding = {
                    'host': host_ip,
                    'port': port_num,
                    'vulnerability': vulnerability_name,
                    'severity': severity,
                    'cve': cve,
                    'cvss_score': severity_score,
                    'description': description,
                    'tool': 'OpenVAS',
                    'task': task_name,
                    'timestamp': datetime.now().isoformat()
                }
                
                findings.append(finding)
            
            logger.info(f"Parsed {len(findings)} findings from OpenVAS report")
            return findings
            
        except Exception as e:
            logger.error(f"Failed to parse OpenVAS report: {str(e)}")
            raise
    
    def _parse_burp(self, file_path: str) -> list[dict]:
        """Parse Burp Suite XML report."""
        findings = []
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            for issue in root.findall('.//Issue'):
                host = issue.find('Host')
                host_ip = host.text if host is not None else 'Unknown'
                
                port = issue.find('Port')
                port_num = port.text if port is not None else 'N/A'
                
                name = issue.find('Name')
                vulnerability_name = name.text if name is not None else 'Unknown'
                
                severity = issue.find('Severity')
                severity_level = severity.text if severity is not None else 'info'
                severity_norm = self._normalize_severity(severity_level.lower())
                
                issuedetail = issue.find('IssueDetail')
                description = issuedetail.text if issuedetail is not None else ''
                
                # Try to extract CVE from description (Burp may not have structured CVE)
                cve = None
                if 'CVE-' in (description or ''):
                    match = re.search(r'(CVE-\d+-\d+)', description)
                    if match:
                        cve = match.group(1)
                
                remediation = issue.find('RemediationDetail')
                remediation_text = remediation.text if remediation is not None else ''
                
                finding = {
                    'host': host_ip,
                    'port': port_num,
                    'vulnerability': vulnerability_name,
                    'severity': severity_norm,
                    'cve': cve,
                    'cvss_score': None,  # Burp Suite XML doesn't always include CVSS
                    'description': description,
                    'remediation': remediation_text,
                    'tool': 'Burp Suite',
                    'timestamp': datetime.now().isoformat()
                }
                
                findings.append(finding)
            
            logger.info(f"Parsed {len(findings)} findings from Burp Suite report")
            return findings
            
        except Exception as e:
            logger.error(f"Failed to parse Burp Suite report: {str(e)}")
            raise
    
    def _parse_zap(self, file_path: str) -> list[dict]:
        """Parse OWASP ZAP JSON report."""
        findings: list[dict] = []
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)

            sites = data.get('site', [])
            if isinstance(sites, dict):
                sites = [sites]

            for site in sites:
                host = site.get('@host') or site.get('host') or 'Unknown'
                alerts = site.get('alerts', [])
                for alert in alerts:
                    name = alert.get('alert') or alert.get('name') or 'Unknown'
                    risk = alert.get('risk') or alert.get('riskdesc') or 'info'
                    desc = alert.get('desc') or ''
                    solution = alert.get('solution') or ''
                    cwe = alert.get('cweid')
                    cve = None
                    if isinstance(alert.get('reference'), str) and 'CVE-' in alert['reference']:
                        m = re.search(r'(CVE-\d+-\d+)', alert['reference'])
                        if m:
                            cve = m.group(1)

                    # ZAP often embeds URL/port in 'instances'
                    port = 'N/A'
                    instances = alert.get('instances') or alert.get('instance') or []
                    if isinstance(instances, dict):
                        instances = [instances]
                    if instances:
                        uri = instances[0].get('uri') or instances[0].get('url')
                        if isinstance(uri, str) and '://' in uri:
                            try:
                                from urllib.parse import urlparse
                                parsed = urlparse(uri)
                                port = parsed.port or ('443' if parsed.scheme == 'https' else '80')
                            except Exception:
                                port = 'N/A'

                    severity_norm = self._normalize_severity(str(risk))

                    finding = {
                        'host': host,
                        'port': str(port),
                        'vulnerability': name,
                        'severity': severity_norm,
                        'cve': cve,
                        'cvss_score': None,
                        'description': f"{desc}\n\nRemediation: {solution}" if solution else desc,
                        'tool': 'OWASP ZAP',
                        'timestamp': datetime.now().isoformat()
                    }
                    findings.append(finding)

            logger.info(f"Parsed {len(findings)} findings from OWASP ZAP report")
            return findings
        except Exception as e:
            logger.error(f"Failed to parse OWASP ZAP report: {str(e)}")
            raise
    
    def _normalize_severity(self, severity: str) -> str:
        """Normalize severity values to standard format."""
        severity_lower = str(severity).lower().strip()
        
        # Direct mapping
        if severity_lower in self.SEVERITY_MAP:
            return self.SEVERITY_MAP[severity_lower]
        
        # Nessus XML uses 0-4: 0=Info, 1=Low, 2=Medium, 3=High, 4=Critical
        nessus_map = {'0': 'info', '1': 'low', '2': 'medium', '3': 'high', '4': 'critical'}
        if severity_lower in nessus_map:
            return nessus_map[severity_lower]
        
        # Try to handle numeric values (0-10 scale, e.g. CVSS)
        try:
            score = float(severity_lower)
            if score >= 9:
                return 'critical'
            elif score >= 7:
                return 'high'
            elif score >= 5:
                return 'medium'
            elif score >= 3:
                return 'low'
            else:
                return 'info'
        except ValueError:
            pass
        
        # Default
        return 'info'
    
    def _normalize_openvas_severity(self, score: float) -> str:
        """Normalize OpenVAS CVSS score to severity level."""
        if score is None:
            return 'info'
        
        if score >= 9.0:
            return 'critical'
        elif score >= 7.0:
            return 'high'
        elif score >= 5.0:
            return 'medium'
        elif score >= 3.0:
            return 'low'
        else:
            return 'info'


    def _get_or_create_host(self, workspace: str, ip: str) -> str:
        """Fetch existing host ID or create a new host in Faraday."""
        try:
            # Check if host exists
            search_url = f"{self.faraday_url}/_api/v3/ws/{workspace}/hosts?ip={ip}"
            res = self.session.get(search_url, timeout=self.config['faraday']['timeout'])
            if res.status_code == 200 and res.json().get('rows'):
                return res.json()['rows'][0]['id']
            
            # Create host if it doesn't exist
            create_url = f"{self.faraday_url}/_api/v3/ws/{workspace}/hosts"
            payload = {"ip": ip, "os": "unknown", "description": "Auto-created by report parser"}
            res = self.session.post(create_url, json=payload, timeout=self.config['faraday']['timeout'])
            if res.status_code in [200, 201]:
                return res.json()['id']
                
            raise Exception(f"Failed to create host {ip}: {res.text}")
        except Exception as e:
            logger.error(f"Error handling host {ip}: {str(e)}")
            return None

    def push_to_faraday(self, workspace: str) -> dict:
        """Push findings to Faraday, skipping duplicates to avoid 409/500 errors."""
        if not self.findings:
            return {'status': 'no_findings'}
        
        try:
            # 1. Fetch existing vulns to prevent duplicates
            existing_url = f"{self.faraday_url}/_api/v3/ws/{workspace}/vulns"
            resp = self.session.get(existing_url)
            existing_names = []
            if resp.status_code == 200:
                data = resp.json()
                rows = data.get('rows') or data.get('data') or []
                existing_names = [v.get('name') for v in rows]

            pushed_count = 0
            skipped_count = 0
            
            for finding in self.findings:
                if finding['vulnerability'] in existing_names:
                    skipped_count += 1
                    continue

                parent_id = self._get_or_create_host(workspace, finding.get('host', 'Unknown'))
                if not parent_id: continue

                vuln_data = {
                    'name': finding['vulnerability'],
                    'description': finding['description'][:5000], # Prevent DB overflow
                    'severity': finding['severity'],
                    'parent': parent_id,
                    'parent_type': 'Host',
                    'type': 'Vulnerability'
                }

                try:
                    res = self.session.post(f"{self.faraday_url}/_api/v3/ws/{workspace}/vulns", json=vuln_data)
                    # Treat 201, 200, and even 500 (if it actually saved) as successes for reporting
                    if res.status_code in [200, 201]:
                        pushed_count += 1
                    elif res.status_code == 409:
                        skipped_count += 1
                except:
                    pass
            
            logger.info(f"Final Sync: {pushed_count} new, {skipped_count} skipped/existing.")
            return {'pushed': pushed_count, 'skipped': skipped_count}
        except Exception as e:
            logger.error(f"Push failed: {str(e)}")
            raise
    

def main() -> None:
    """
    CLI entrypoint for multi-tool report parsing.

    Examples:
      python report_parser.py --file scan_results.nessus --workspace forenzy_lab
      python report_parser.py --file openvas_report.xml --type openvas --workspace forenzy_lab
      python report_parser.py --file burp_export.xml --type burp --workspace forenzy_lab
    """
    import argparse

    parser = argparse.ArgumentParser(
        description="Multi-tool report parser for Nessus, OpenVAS, and Burp Suite "
                    "with Faraday integration."
    )
    parser.add_argument(
        "--file",
        required=True,
        help="Path to Nessus/OpenVAS/Burp report file",
    )
    parser.add_argument(
        "--workspace",
        required=True,
        help="Faraday workspace name",
    )
    parser.add_argument(
        "--type",
        dest="tool_type",
        choices=["nmap","nessus", "openvas", "burp", "zap"],
        help="Tool type (auto-detected if omitted for common formats)",
    )
    parser.add_argument(
        "--config",
        default="config/settings.yaml",
        help="Path to configuration file (default: config/settings.yaml)",
    )
    parser.add_argument(
        "--export-json",
        dest="export_json",
        help="Optional path to export parsed findings as JSON",
    )

    args = parser.parse_args()

    rp = ReportParser(config_path=args.config)
    rp.parse(args.file, tool_type=args.tool_type)
    rp.push_to_faraday(args.workspace)

    if args.export_json:
        rp.export_json(args.export_json)


if __name__ == "__main__":
    main()

