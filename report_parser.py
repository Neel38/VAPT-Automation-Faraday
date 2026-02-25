import os
import requests
from requests.auth import HTTPBasicAuth

# Retrieve credentials from environment variables
username = os.getenv('FARADAY_USERNAME')
password = os.getenv('FARADAY_PASSWORD')

# Example function demonstrating HTTP Basic Authentication


def make_request(url):
    response = requests.get(url, auth=HTTPBasicAuth(username, password))
    return response

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
    
    def _load_config(self, config_path: str) -> Dict:
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
    
    def parse(self, file_path: str, tool_type: str = None) -> List[Dict]:
        """Parse report file based on tool type."""
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            raise FileNotFoundError(f"Report file not found: {file_path}")
        
        # Auto-detect tool type if not specified
        if tool_type is None:
            tool_type = self._detect_tool_type(file_path)
        
        logger.info(f"Parsing {tool_type} report: {file_path}")
        
        if tool_type.lower() == 'nessus':
            self.findings = self._parse_nessus(file_path)
        elif tool_type.lower() == 'openvas':
            self.findings = self._parse_openvas(file_path)
        elif tool_type.lower() == 'burp':
            self.findings = self._parse_burp(file_path)
        else:
            logger.error(f"Unsupported tool type: {tool_type}")
            raise ValueError(f"Tool type '{tool_type}' is not supported")
        
        logger.info(f"Extracted {len(self.findings)} findings from {tool_type} report")
        return self.findings
    
    def _detect_tool_type(self, file_path: str) -> str:
        """Auto-detect tool type from file content."""
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            if root.tag == 'NessusClientData':
                return 'nessus'
            elif root.tag == 'report':
                # Check for OpenVAS report element
                if root.find('.//report') is not None or root.find('Report') is not None:
                    return 'openvas'
            elif root.tag == 'Issues':
                return 'burp'
            
            # Fallback to file extension
            if file_path.endswith('.nessus'):
                return 'nessus'
            elif file_path.endswith('.xml'):
                # Check file size and common elements
                content = open(file_path, 'r').read(500)
                if 'openvas' in content.lower():
                    return 'openvas'
                elif 'burp' in content.lower():
                    return 'burp'
        except Exception as e:
            logger.warning(f"Could not auto-detect tool type: {str(e)}")
        
        raise ValueError("Could not auto-detect tool type. Please specify with --type")
    
    def _parse_nessus(self, file_path: str) -> List[Dict]:
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
    
    def _parse_openvas(self, file_path: str) -> List[Dict]:
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
    
    def _parse_burp(self, file_path: str) -> List[Dict]:
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
                    import re
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
    
    def _normalize_severity(self, severity: str) -> str:
        """Normalize severity values to standard format."""
        severity_lower = str(severity).lower().strip()
        
        # Direct mapping
        if severity_lower in self.SEVERITY_MAP:
            return self.SEVERITY_MAP[severity_lower]
        
        # Try to handle numeric values (0-10 scale)
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
    
    def push_to_faraday(self, workspace: str) -> Dict:
        """Push parsed findings to Faraday via REST API."""
        if not self.findings:
            logger.warning("No findings to push to Faraday")
            return {'status': 'no_findings'}
        
        try:
            # Faraday Community edition uses the /_api prefix and workspace-scoped vulns endpoint
            endpoint = f"{self.faraday_url}/_api/v3/ws/{workspace}/vulns/"

            pushed_count = 0
            failed_count = 0
            
            for finding in self.findings:
                # Prepare vulnerability payload for Faraday API
                # NOTE: Community API expects Faraday's internal schema (parent host/service, etc.).
                # Here we send a simplified payload; Faraday may enrich it internally depending
                # on version. For a production deployment you would create hosts/services first
                # and reference them via the 'parent' field.
                vuln_data = {
                    'name': finding['vulnerability'],
                    'description': finding['description'],
                    'severity': finding['severity'],
                    'type': 'Vulnerability',
                    'status': 'opened',
                    'ws': workspace,
                }
                
                # Add optional fields
                if finding.get('cve'):
                    vuln_data['cve'] = finding['cve']
                if finding.get('cvss_score'):
                    vuln_data['cvss_score'] = finding['cvss_score']
                
                try:
                    response = self.session.post(
                        endpoint,
                        json=vuln_data,
                        timeout=self.config['faraday']['timeout'],
                    )
                    
                    if response.status_code in [200, 201]:
                        pushed_count += 1
                        logger.debug(f"Successfully pushed finding: {finding['vulnerability']}")
                    else:
                        failed_count += 1
                        logger.warning(f"Failed to push finding (code {response.status_code}): {response.text}")
                
                except requests.exceptions.RequestException as e:
                    failed_count += 1
                    logger.error(f"Error pushing finding: {str(e)}")
            
            result = {
                'status': 'completed',
                'workspace': workspace,
                'total_findings': len(self.findings),
                'pushed': pushed_count,
                'failed': failed_count
            }
            
            logger.info(f"Faraday push completed: {pushed_count} pushed, {failed_count} failed")
            return result
            
        except Exception as e:
            logger.error(f"Failed to push findings to Faraday: {str(e)}")
            raise
    
    def export_json(self, output_file: str) -> None:
        """Export parsed findings to JSON file."""
        try:
            with open(output_file, 'w') as f:
                json.dump(self.findings, f, indent=2)
            
            logger.info(f"Exported {len(self.findings)} findings to {output_file}")
        except Exception as e:
            logger.error(f"Failed to export findings to JSON: {str(e)}")
            raise


# Use the make_request function within your application
