#!/usr/bin/env python3
"""
Automated Scan Scheduler for VAPT Pipeline
Handles Nmap scanning with auto-import to Faraday and deduplication tracking.
"""

import argparse
import subprocess
import os
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
import hashlib
import requests
import yaml
from typing import Dict, List, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scan.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class ScanScheduler:
    """Handles scheduling and execution of vulnerability scans."""
    
    def __init__(self, config_path: str = 'config/settings.yaml'):
        """Initialize scan scheduler with configuration."""
        self.config = self._load_config(config_path)
        self.faraday_url = self.config['faraday']['url']
        self.faraday_api_key = os.getenv('FARADAY_API_KEY', self.config['faraday']['api_key'])
        self.session = requests.Session()
        self.session.headers.update({'Authorization': f'Bearer {self.faraday_api_key}'})
        self.existing_findings = {}
        
    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from YAML file."""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.error(f"Config file not found: {config_path}")
            sys.exit(1)
    
    def run_nmap_scan(self, target: str, profile: str) -> Tuple[str, str]:
        """Execute Nmap scan and return result file path."""
        if profile not in self.config['scan_profiles']:
            logger.error(f"Unknown profile: {profile}")
            raise ValueError(f"Profile '{profile}' not found in configuration")
        
        profile_config = self.config['scan_profiles'][profile]
        timestamp = datetime.now().strftime('%Y-%m-%d')
        
        # Create timestamped directory
        report_dir = Path(self.config['directories']['reports']) / 'nmap' / timestamp
        report_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate output filename with timestamp and hash
        time_suffix = datetime.now().strftime('%H%M%S')
        target_hash = hashlib.md5(target.encode()).hexdigest()[:8]
        output_file = report_dir / f"scan_{time_suffix}_{profile}_{target_hash}"
        
        # Build Nmap command
        nmap_cmd = f"nmap {profile_config['flags']} -oX {output_file}.xml {target}"
        
        logger.info(f"Starting {profile} scan on target: {target}")
        logger.info(f"Nmap command: {nmap_cmd}")
        
        try:
            result = subprocess.run(
                nmap_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=profile_config['timeout']
            )
            
            if result.returncode != 0:
                logger.error(f"Nmap scan failed: {result.stderr}")
                raise RuntimeError(f"Nmap returned non-zero exit code: {result.returncode}")
            
            logger.info(f"Scan completed successfully: {output_file}.xml")
            return str(output_file), output_file.with_suffix('.xml')
            
        except subprocess.TimeoutExpired:
            logger.error(f"Nmap scan timed out (>{profile_config['timeout']}s)")
            raise
        except Exception as e:
            logger.error(f"Scan execution failed: {str(e)}")
            raise
    
    def load_existing_findings(self, workspace: str) -> None:
        """Load existing findings from Faraday to enable deduplication."""
        try:
            endpoint = f"{self.faraday_url}/api/v3/workspaces/{workspace}/vulns"
            response = self.session.get(endpoint, timeout=self.config['faraday']['timeout'])
            response.raise_for_status()
            
            data = response.json()
            findings = data.get('data', [])
            
            # Create a hash of (cve + host + port) for quick lookup
            for finding in findings:
                host = finding.get('target_distribution', {}).get('host')
                port = finding.get('target_distribution', {}).get('port')
                cve = finding.get('cve', '')
                
                if host and port and cve:
                    key = self._create_finding_hash(host, port, cve)
                    self.existing_findings[key] = finding.get('id')
            
            logger.info(f"Loaded {len(self.existing_findings)} existing findings from Faraday")
            
        except requests.exceptions.RequestException as e:
            logger.warning(f"Could not load existing findings: {str(e)}")
    
    def _create_finding_hash(self, host: str, port: str, cve: str) -> str:
        """Create a unique hash for a finding."""
        combined = f"{host}:{port}:{cve}"
        return hashlib.sha256(combined.encode()).hexdigest()
    
    def import_to_faraday(self, xml_file: str, workspace: str) -> Dict:
        """Import scan results to Faraday using REST API."""
        try:
            with open(xml_file, 'r') as f:
                xml_content = f.read()
            
            # Import via Faraday REST API
            endpoint = f"{self.faraday_url}/api/v3/workspaces/{workspace}/import_scan"
            
            files = {'file': (os.path.basename(xml_file), xml_content, 'application/xml')}
            data = {
                'tool': 'Nmap',
                'json_data': json.dumps({'ignore_info': False})
            }
            
            response = self.session.post(
                endpoint,
                files=files,
                data=data,
                timeout=self.config['faraday_timeout']
            )
            response.raise_for_status()
            
            result = response.json()
            logger.info(f"Successfully imported scan to Faraday workspace: {workspace}")
            return result
            
        except FileNotFoundError:
            logger.error(f"XML file not found: {xml_file}")
            raise
        except requests.exceptions.RequestException as e:
            logger.error(f"Faraday import failed: {str(e)}")
            raise
    
    def parse_nmap_xml(self, xml_file: str) -> Tuple[int, List[Dict]]:
        """Parse Nmap XML output to extract findings."""
        try:
            import xml.etree.ElementTree as ET
            
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            findings = []
            
            for host_elem in root.findall('host'):
                host_ip = host_elem.find('address').get('addr')
                
                for port_elem in host_elem.findall('.//port'):
                    port_num = port_elem.get('portid')
                    port_state = port_elem.find('state').get('state')
                    
                    if port_state != 'open':
                        continue
                    
                    service_elem = port_elem.find('service')
                    service_name = service_elem.get('name') if service_elem else 'unknown'
                    service_version = service_elem.get('version') if service_elem else 'unknown'
                    
                    finding = {
                        'host': host_ip,
                        'port': port_num,
                        'service': service_name,
                        'version': service_version,
                        'state': port_state
                    }
                    findings.append(finding)
            
            logger.info(f"Parsed {len(findings)} findings from Nmap XML")
            return len(findings), findings
            
        except Exception as e:
            logger.error(f"Failed to parse Nmap XML: {str(e)}")
            raise
    
    def check_deduplication(self, host: str, port: str, service: str = None) -> bool:
        """Check if a finding already exists to avoid duplicates."""
        # For simplicity, using host:port as key (enhance with CVE when available)
        key = hashlib.sha256(f"{host}:{port}".encode()).hexdigest()
        return key in self.existing_findings
    
    def generate_summary(self, new_count: int, duplicate_count: int, workspace: str) -> None:
        """Print structured summary to console."""
        summary = {
            'timestamp': datetime.now().isoformat(),
            'new_findings': new_count,
            'duplicate_findings': duplicate_count,
            'total_findings': new_count + duplicate_count,
            'workspace': workspace,
            'status': 'completed'
        }
        
        print("\n" + "="*50)
        print("[+] Scan Summary")
        print("="*50)
        print(f"[+] Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        print(f"[+] New findings imported: {new_count}")
        print(f"[~] Duplicate findings skipped: {duplicate_count}")
        print(f"[+] Total findings: {summary['total_findings']}")
        print(f"[+] Workspace: {workspace}")
        print("="*50 + "\n")
        
        # Log summary as JSON
        logger.info(f"Scan summary: {json.dumps(summary)}")
    
    def run(self, target: str, workspace: str, profile: str = 'quick') -> None:
        """Execute complete scan pipeline."""
        try:
            logger.info(f"Starting VAPT scan pipeline for target: {target}")
            
            # Run Nmap scan
            base_file, xml_file = self.run_nmap_scan(target, profile)
            
            # Parse local XML to count findings
            total_findings, parsed_findings = self.parse_nmap_xml(str(xml_file))
            
            # Load existing findings for deduplication
            self.load_existing_findings(workspace)
            
            # Perform deduplication check
            new_count = 0
            duplicate_count = 0
            
            for finding in parsed_findings:
                if not self.check_deduplication(finding['host'], finding['port'], finding['service']):
                    new_count += 1
                else:
                    duplicate_count += 1
            
            # Import to Faraday
            import_result = self.import_to_faraday(str(xml_file), workspace)
            
            # Generate summary
            self.generate_summary(new_count, duplicate_count, workspace)
            
            logger.info("VAPT scan pipeline completed successfully")
            
        except Exception as e:
            logger.error(f"Pipeline failed: {str(e)}")
            sys.exit(1)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Automated VAPT Scan Scheduler with Faraday Integration'
    )
    parser.add_argument(
        '--target',
        required=True,
        help='Target IP address or CIDR range (e.g., 192.168.1.0/24)'
    )
    parser.add_argument(
        '--profile',
        default='quick',
        choices=['quick', 'full', 'vuln'],
        help='Scan profile to use (default: quick)'
    )
    parser.add_argument(
        '--workspace',
        default='default_lab',
        help='Faraday workspace name (default: default_lab)'
    )
    parser.add_argument(
        '--config',
        default='config/settings.yaml',
        help='Path to configuration file'
    )
    
    args = parser.parse_args()
    
    scheduler = ScanScheduler(args.config)
    scheduler.run(args.target, args.workspace, args.profile)


if __name__ == '__main__':
    main()
