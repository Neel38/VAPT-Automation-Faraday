#!/usr/bin/env python3
"""
Integrated VAPT Pipeline Orchestrator
Merged with Phase 3 (DAST) and Phase 4 (Reporting) Requirements.
"""

import argparse
import logging
import os
import sys
import time
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List

import requests
import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('pipeline.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class VAPTPipeline:
    """Master orchestrator for VAPT automation pipeline."""
    
    def __init__(self, config_path: str = 'config/settings.yaml'):
        """Initialize pipeline and authenticate session."""
        self.config = self._load_config(config_path)
        self.faraday_url = self.config['faraday']['url'].rstrip('/')
        
        # 1. Initialize authenticated session (Required for Phase 3 CI/CD) 
        self.session = requests.Session()
        self._login()
        
        self.start_time = None
        self.end_time = None
        self.results = {
            'scans': [],
            'alerts': 0,
            'tickets': 0,
            'report_file': None
        }
    
    def _load_config(self, config_path: str) -> Dict:
        """Load configuration."""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.error(f"Config file not found: {config_path}")
            sys.exit(1)

    def _login(self) -> None:
        """Authenticate to Faraday using credentials (Requirement 3.1). """
        # Pull from GitHub Secrets (env vars) or fallback to config 
        username = os.getenv('FARADAY_USERNAME', self.config['faraday'].get('username'))
        password = os.getenv('FARADAY_PASSWORD', self.config['faraday'].get('password'))

        if not username or not password:
            logger.error("Auth Failed: FARADAY_USERNAME/PASSWORD not found in environment. ")
            sys.exit(1)

        login_url = f"{self.faraday_url}/_api/login"
        try:
            resp = self.session.post(
                login_url,
                json={"email": username, "password": password},
                timeout=self.config['faraday']['timeout']
            )
            resp.raise_for_status()
            logger.info(f"✓ Pipeline authenticated to Faraday as: {username} ")
        except Exception as e:
            logger.error(f"Pipeline Login Failed: {str(e)} ")
            sys.exit(1)
    
    def run_command(self, cmd: str, description: str) -> bool:
        """Execute shell command and log output."""
        logger.info(f"▶️  Starting: {description}")
        try:
            # Ensure sub-scripts can access the same environment secrets 
            env = os.environ.copy()
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, env=env)
            
            if result.returncode != 0:
                logger.error(f"✗ Failed: {description}")
                logger.error(f"  Error output: {result.stderr}")
                return False
            
            logger.info(f"✓ Completed: {description}")
            return True
        except Exception as e:
            logger.error(f"✗ Error: {description} - {str(e)}")
            return False
    
    def execute_phase_1(self, target: str, workspace: str, profile: str) -> bool:
        """Execute Phase 1: Scan Automation & Auto-Import."""
        logger.info("\n" + "="*60 + "\nPHASE 1: Scan Automation & Auto-Import\n" + "="*60)

        scan_cmd = f"python scan_scheduler.py --target {target} --profile {profile} --workspace {workspace}"
        if not self.run_command(scan_cmd, f"Nmap {profile} scan on {target}"):
            return False

        self.results['scans'].append({
            'tool': 'Nmap',
            'profile': profile,
            'target': target,
            'timestamp': datetime.now().isoformat()
        })

        reports_root = Path(self.config['directories']['reports'])

        def _process_latest_report(subdir: str, tool_type: str) -> None:
            tool_dir = reports_root / subdir
            if not tool_dir.exists(): return
            xml_candidates = sorted([p for p in tool_dir.rglob("*.xml") if p.is_file()], key=lambda p: p.stat().st_mtime)
            if not xml_candidates: return
            latest = xml_candidates[-1]
            parser_cmd = f"python report_parser.py --file \"{latest}\" --type {tool_type} --workspace {workspace}"
            self.run_command(parser_cmd, f"{tool_type.capitalize()} report parsing ({latest.name})")

        _process_latest_report("nmap", "nmap")        
        _process_latest_report("nessus", "nessus")
        _process_latest_report("openvas", "openvas")
        _process_latest_report("burp", "burp")
        return True
    
    def execute_phase_2(self, workspace: str) -> bool:
        """Execute Phase 2: Severity-Based Alerting & Ticketing."""
        logger.info("\n" + "="*60 + "\nPHASE 2: Severity-Based Alerting & Ticketing\n" + "="*60)
        
        self.run_command(f"python alert_engine.py --workspace {workspace}", "Alert engine processing")
        self.run_command(f"python ticket_manager.py sync --workspace {workspace}", "Ticketing system sync")
        self.run_command("python ticket_manager.py stats", "Ticket statistics")
        return True
    
    def execute_phase_3(self, target_url: str, workspace: str) -> bool:
        """Execute Phase 3: Live DAST Scanning using ZAP API."""
        logger.info("\n" + "="*60 + f"\nPHASE 3: DAST Scanning (ZAP API) into {workspace}\n" + "="*60)
        
        dast_config = self.config.get('dast', {})
        if not dast_config.get('enabled', False):
            logger.info("⊘ DAST scanning disabled in config.")
            return True

        zap_base = dast_config.get('zap', {}).get('url', 'http://localhost:8080').rstrip('/')
        
        try:
            # 1. Start Spider
            logger.info(f"🕸️  Starting ZAP Spider for: {target_url}")
            # Explicitly pass the url parameter in the query string
            spider_resp = requests.get(f"{zap_base}/JSON/spider/action/scan/", params={'url': target_url})
            spider_data = spider_resp.json()
            spider_id = spider_data.get('scan')
            
            if spider_id is None:
                logger.error(f"Failed to start Spider. ZAP Response: {spider_data}")
                return False
            
            # Wait for Spider completion
            while True:
                time.sleep(5)
                status_resp = requests.get(f"{zap_base}/JSON/spider/view/status/", params={'scanId': spider_id})
                status = status_resp.json().get('status')
                if status is None: continue
                logger.info(f"Spider Progress: {status}%")
                if int(status) >= 100: break

            # 2. Start Active Scan
            logger.info(f"🔥 Starting ZAP Active Scan for: {target_url}")
            ascan_resp = requests.get(f"{zap_base}/JSON/ascan/action/scan/", params={'url': target_url})
            ascan_data = ascan_resp.json()
            ascan_id = ascan_data.get('scan')
            
            if ascan_id:
                while True:
                    time.sleep(10)
                    status = requests.get(f"{zap_base}/JSON/ascan/view/status/", params={'scanId': ascan_id}).json().get('status')
                    logger.info(f"Active Scan Progress: {status}%")
                    if status is None or int(status) >= 100: break

            # 3. Save JSON Report
            zap_report_path = Path("reports/zap/latest_zap_report.json")
            zap_report_path.parent.mkdir(parents=True, exist_ok=True)
            report_resp = requests.get(f"{zap_base}/OTHER/core/other/jsonreport/")
            with open(zap_report_path, "w") as f:
                f.write(report_resp.text)
            
            # 4. Import findings to Faraday into the requested workspace
            parser_cmd = f"python report_parser.py --file \"{zap_report_path}\" --type zap --workspace {workspace}"
            return self.run_command(parser_cmd, f"ZAP Import into {workspace}")

        except Exception as e:
            logger.error(f"DAST Phase Failed: {str(e)}")
            return False
    
    def execute_phase_4(self, workspace: str, framework: str = 'owasp') -> bool:
        """Execute Phase 4: Compliance Reporting."""
        logger.info("\n" + "="*60 + "\nPHASE 4: Compliance Reporting\n" + "="*60)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = f"reports/compliance_report_{workspace}_{timestamp}.html"
        report_cmd = f"python report_generator.py --workspace {workspace} --framework {framework} --format html --output {output_file}"
        
        if self.run_command(report_cmd, "Compliance report generation"):
            if Path(output_file).exists():
                self.results['report_file'] = output_file
        return True
    
    def display_summary(self) -> None:
        """Display pipeline execution summary."""
        duration = (self.end_time - self.start_time).total_seconds()
        print("\n" + "="*70 + "\nVAPT PIPELINE EXECUTION SUMMARY\n" + "="*70)
        print(f"📊 Execution Time: {int(duration)} seconds")
        print(f"📋 Scans: {len(self.results['scans'])}")
        print(f"🚨 Report: {self.results.get('report_file', 'N/A')}\n✅ Pipeline complete!\n" + "="*70)

    def validate_environment(self) -> bool:
        """Validate credentials and tools for CI/CD. """
        if not os.getenv('FARADAY_USERNAME') or not os.getenv('FARADAY_PASSWORD'):
            logger.error("Missing Faraday Credentials (Env Vars). ")
            return False
        
        for tool in ['nmap', 'python3']:
            if subprocess.run(f"which {tool}", shell=True, capture_output=True).returncode != 0:
                logger.error(f"Required tool not found: {tool} ")
                return False
        return True
    
    def run(self, target: str, workspace: str, profile: str = 'quick', framework: str = 'owasp', phases: List[str] = None) -> None:
        """Execute complete pipeline flow."""
        self.start_time = datetime.now()
        if not self.validate_environment(): sys.exit(1)
        
        phases = phases or ['1', '2', '3', '4']
        try:
            if '1' in phases: self.execute_phase_1(target, workspace, profile)
            if '2' in phases: self.execute_phase_2(workspace)
            if '3' in phases: self.execute_phase_3(target, workspace)
            if '4' in phases: self.execute_phase_4(workspace, framework)
            self.end_time = datetime.now()
            self.display_summary()
        except Exception as e:
            logger.error(f"Pipeline failed: {str(e)}")
            sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Automated VAPT Pipeline')
    parser.add_argument('--target', required=True)
    parser.add_argument('--workspace', default='lab_scan')
    parser.add_argument('--profile', choices=['quick', 'full', 'vuln'], default='quick')
    parser.add_argument('--framework', default='owasp')
    parser.add_argument('--phases', default='1,2,3,4')
    args = parser.parse_args()
    
    pipeline = VAPTPipeline()
    pipeline.run(target=args.target, workspace=args.workspace, profile=args.profile, framework=args.framework, phases=args.phases.split(','))

if __name__ == '__main__':
    main()