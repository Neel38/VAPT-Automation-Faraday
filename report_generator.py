#!/usr/bin/env python3
"""
Automated Compliance Report Generator for VAPT Pipeline
Generates professional HTML reports with compliance mapping.
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional
import requests
import yaml
from jinja2 import Environment, FileSystemLoader, select_autoescape

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('report_generator.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates professional compliance reports from Faraday findings."""
    
    # OWASP Top 10 (2021) Mapping
    OWASP_MAP = {
        'sql injection': 'A03: Injection',
        'cross-site scripting': 'A07: Cross-Site Scripting (XSS)',
        'xss': 'A07: Cross-Site Scripting (XSS)',
        'authentication': 'A07: Identification and Authentication Failures',
        'authentication failure': 'A07: Identification and Authentication Failures',
        'access control': 'A01: Broken Access Control',
        'broken access control': 'A01: Broken Access Control',
        'cryptography': 'A02: Cryptographic Failures',
        'encryption': 'A02: Cryptographic Failures',
        'xml external entity': 'A05: XML External Entity (XXE)',
        'xxe': 'A05: XML External Entity (XXE)',
        'broken authentication': 'A07: Identification and Authentication Failures',
        'sensitive data exposure': 'A02: Cryptographic Failures',
        'xxe': 'A05: XML External Entity (XXE)',
        'broken access': 'A01: Broken Access Control',
        'security misconfiguration': 'A05: Security Misconfiguration',
        'misconfiguration': 'A05: Security Misconfiguration',
        'insecure serialization': 'A08: Software and Data Integrity Failures',
        'deserialization': 'A08: Software and Data Integrity Failures',
        'insuffcient logging': 'A09: Security Logging and Monitoring Failures',
        'logging': 'A09: Security Logging and Monitoring Failures',
        'monitoring': 'A09: Security Logging and Monitoring Failures',
        'ssrf': 'A10: Server-Side Request Forgery (SSRF)',
        'server-side request forgery': 'A10: Server-Side Request Forgery (SSRF)',
    }
    
    # CIS Controls Mapping (simplified)
    CIS_MAP = {
        'asset management': 'CIS 1: Inventory and Control of Enterprise Assets',
        'access control': 'CIS 6: Access Control Management',
        'authentication': 'CIS 6: Access Control Management',
        'encryption': 'CIS 3: Data Protection',
        'vulnerability management': 'CIS 7: Continuous Vulnerability Management',
        'patch management': 'CIS 7: Continuous Vulnerability Management',
        'configuration': 'CIS 4: Secure Configuration Management',
        'logging': 'CIS 8: Security Awareness and Skills Training',
        'incident response': 'CIS 9: Security Incident Management',
    }
    
    def __init__(self, config_path: str = 'config/settings.yaml'):
        """Initialize report generator."""
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
        
        # Setup Jinja2 environment
        template_dir = self.config.get('directories', {}).get('templates', './templates')
        self.jinja_env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(['html', 'xml'])
        )
        
        self.findings = []
    
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
    
    def fetch_findings(self, workspace: str) -> List[Dict]:
        """Fetch all findings from Faraday workspace."""
        try:
            # Community edition uses /_api and workspace-scoped vulns endpoint
            # NOTE: On this server the URL is defined without a trailing slash.
            endpoint = f"{self.faraday_url}/_api/v3/ws/{workspace}/vulns"

            response = self.session.get(
                endpoint,
                timeout=self.config['faraday']['timeout'],
            )
            response.raise_for_status()

            data = response.json()
            if isinstance(data, dict) and 'data' in data:
                self.findings = data.get('data', [])
            elif isinstance(data, list):
                self.findings = data
            else:
                self.findings = []

            logger.info(f"Fetched {len(self.findings)} findings from Faraday")
            return self.findings
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch findings from Faraday: {str(e)}")
            return []
    
    def load_findings_from_file(self, file_path: str) -> List[Dict]:
        """Load findings from local JSON file."""
        try:
            with open(file_path, 'r') as f:
                self.findings = json.load(f)
            logger.info(f"Loaded {len(self.findings)} findings from {file_path}")
            return self.findings
        except Exception as e:
            logger.error(f"Failed to load findings file: {str(e)}")
            return []
    
    def map_to_compliance_control(self, vulnerability_name: str, framework: str = 'owasp') -> str:
        """Map vulnerability to compliance control."""
        vuln_lower = vulnerability_name.lower()
        
        if framework.lower() == 'cis':
            mapping = self.CIS_MAP
        else:  # Default to OWASP
            mapping = self.OWASP_MAP
        
        # Try exact match first
        if vuln_lower in mapping:
            return mapping[vuln_lower]
        
        # Try partial match
        for keyword, control in mapping.items():
            if keyword in vuln_lower:
                return control
        
        return 'Uncategorized Finding'
    
    def categorize_findings(self) -> Dict[str, List[Dict]]:
        """Categorize findings by severity."""
        categories = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }
        
        for finding in self.findings:
            severity = finding.get('severity', 'info').lower()
            if severity not in categories:
                severity = 'info'
            categories[severity].append(finding)
        
        return categories
    
    def build_compliance_map(self, framework: str = 'owasp') -> Dict[str, List[Dict]]:
        """Build mapping of findings to compliance controls."""
        compliance_map = {}
        
        for finding in self.findings:
            control = self.map_to_compliance_control(
                finding.get('name', 'Unknown'),
                framework
            )
            
            if control not in compliance_map:
                compliance_map[control] = []
            
            compliance_map[control].append(finding)
        
        # Sort by control name
        return dict(sorted(compliance_map.items()))
    
    def sort_by_cvss(self, findings: List[Dict]) -> List[Dict]:
        """Sort findings by CVSS score (highest first)."""
        def get_cvss(finding):
            try:
                score = finding.get('cvss_score')
                if score is None:
                    # Estimate based on severity
                    severity_scores = {'critical': 9.0, 'high': 7.0, 'medium': 5.0, 'low': 3.0}
                    score = severity_scores.get(finding.get('severity', 'info').lower(), 0)
                return float(score)
            except (ValueError, TypeError):
                return 0
        
        return sorted(findings, key=get_cvss, reverse=True)
    
    def generate_report(self, workspace: str, compliance_framework: str = 'owasp',
                       output_file: Optional[str] = None) -> str:
        """Generate HTML compliance report."""
        
        # Categorize findings
        categories = self.categorize_findings()
        
        # Build compliance map
        compliance_map = self.build_compliance_map(compliance_framework)
        
        # Get key findings (top 3 by severity then CVSS)
        key_findings = []
        for severity_list in [categories['critical'], categories['high'], categories['medium']]:
            key_findings.extend(self.sort_by_cvss(severity_list)[:1])
        
        # Prepare template data
        now = datetime.now()
        report_data = {
            'workspace': workspace,
            'report_date': now.strftime('%Y-%m-%d %H:%M:%S'),
            'scan_start': (now - timedelta(days=7)).strftime('%Y-%m-%d'),
            'scan_end': now.strftime('%Y-%m-%d'),
            'total_findings': len(self.findings),
            'critical_count': len(categories['critical']),
            'high_count': len(categories['high']),
            'medium_count': len(categories['medium']),
            'low_count': len(categories['low']),
            'info_count': len(categories['info']),
            'critical_findings': self.sort_by_cvss(categories['critical']),
            'high_findings': self.sort_by_cvss(categories['high']),
            'medium_findings': self.sort_by_cvss(categories['medium']),
            'low_findings': self.sort_by_cvss(categories['low']),
            'info_findings': self.sort_by_cvss(categories['info']),
            'key_findings': key_findings,
            'compliance_framework': compliance_framework,
            'compliance_map': compliance_map,
            'remediation_priority': self.sort_by_cvss(self.findings)[:20]  # Top 20 by CVSS
        }
        
        # Render template
        try:
            template = self.jinja_env.get_template('report_template.html')
            html_content = template.render(**report_data)
        except Exception as e:
            logger.error(f"Failed to render template: {str(e)}")
            raise
        
        # Generate output filename if not provided
        if output_file is None:
            output_file = f"report_{workspace}_{now.strftime('%Y%m%d_%H%M%S')}.html"
        
        # Ensure .html extension
        if not output_file.endswith('.html'):
            output_file += '.html'
        
        # Write report to file
        try:
            with open(output_file, 'w') as f:
                f.write(html_content)
            
            logger.info(f"Report generated: {output_file}")
            return output_file
            
        except Exception as e:
            logger.error(f"Failed to write report file: {str(e)}")
            raise
    
    def generate_json_report(self, output_file: Optional[str] = None) -> str:
        """Export findings as JSON for integration tools."""
        
        categories = self.categorize_findings()
        
        report_data = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'total_findings': len(self.findings),
                'severity_distribution': {
                    'critical': len(categories['critical']),
                    'high': len(categories['high']),
                    'medium': len(categories['medium']),
                    'low': len(categories['low']),
                    'info': len(categories['info']),
                }
            },
            'findings': self.findings
        }
        
        if output_file is None:
            output_file = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            with open(output_file, 'w') as f:
                json.dump(report_data, f, indent=2)
            
            logger.info(f"JSON report exported: {output_file}")
            return output_file
            
        except Exception as e:
            logger.error(f"Failed to export JSON report: {str(e)}")
            raise


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Automated Compliance Report Generator for VAPT Pipeline'
    )
    parser.add_argument(
        '--workspace',
        required=True,
        help='Faraday workspace to generate report for'
    )
    parser.add_argument(
        '--format',
        choices=['html', 'json', 'both'],
        default='html',
        help='Report output format (default: html)'
    )
    parser.add_argument(
        '--framework',
        choices=['owasp', 'cis'],
        default='owasp',
        help='Compliance framework for mapping (default: owasp)'
    )
    parser.add_argument(
        '--output',
        default=None,
        help='Output file path (auto-generated if not specified)'
    )
    parser.add_argument(
        '--input-file',
        default=None,
        help='Load findings from JSON file instead of Faraday API'
    )
    parser.add_argument(
        '--config',
        default='config/settings.yaml',
        help='Path to configuration file'
    )
    
    args = parser.parse_args()
    
    generator = ReportGenerator(args.config)
    
    # Load findings
    if args.input_file:
        generator.load_findings_from_file(args.input_file)
    else:
        generator.fetch_findings(args.workspace)
    
    if not generator.findings:
        logger.warning("No findings to report on")
        print("No findings found. Exiting.")
        return
    
    # Generate reports
    try:
        if args.format in ['html', 'both']:
            html_file = generator.generate_report(args.workspace, args.framework, args.output)
            print(f"✓ HTML report generated: {html_file}")
        
        if args.format in ['json', 'both']:
            json_output = args.output.replace('.html', '.json') if args.output else None
            json_file = generator.generate_json_report(json_output)
            print(f"✓ JSON report generated: {json_file}")
        
    except Exception as e:
        logger.error(f"Report generation failed: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()
