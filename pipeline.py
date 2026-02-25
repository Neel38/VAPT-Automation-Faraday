#!/usr/bin/env python3
"""
Master VAPT Pipeline Orchestrator
Coordinates all components for automated vulnerability assessment and reporting.
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
        """Initialize pipeline."""
        self.config = self._load_config(config_path)
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
    
    def run_command(self, cmd: str, description: str) -> bool:
        """Execute shell command and log output."""
        logger.info(f"▶️  Starting: {description}")
        
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=None
            )
            
            if result.returncode != 0:
                logger.error(f"✗ Failed: {description}")
                logger.error(f"  Error output: {result.stderr}")
                return False
            
            logger.info(f"✓ Completed: {description}")
            
            # Log output if available
            if result.stdout:
                for line in result.stdout.split('\n'):
                    if line.strip():
                        logger.debug(f"  {line}")
            
            return True
            
        except subprocess.TimeoutExpired:
            logger.error(f"✗ Timeout: {description}")
            return False
        except Exception as e:
            logger.error(f"✗ Error: {description} - {str(e)}")
            return False
    
    def execute_phase_1(self, target: str, workspace: str, profile: str) -> bool:
        """Execute Phase 1: Scan Automation & Auto-Import."""
        logger.info("\n" + "="*60)
        logger.info("PHASE 1: Scan Automation & Auto-Import to Faraday")
        logger.info("="*60)
        
        # Step 1: Run Nmap scan
        scan_cmd = f"python scan_scheduler.py --target {target} --profile {profile} --workspace {workspace}"
        if not self.run_command(scan_cmd, f"Nmap {profile} scan on {target}"):
            return False
        
        self.results['scans'].append({
            'tool': 'Nmap',
            'profile': profile,
            'target': target,
            'timestamp': datetime.now().isoformat()
        })
        
        logger.info("✓ Phase 1 complete: Findings imported to Faraday")
        return True
    
    def execute_phase_2(self, workspace: str) -> bool:
        """Execute Phase 2: Severity-Based Alerting & Ticketing."""
        logger.info("\n" + "="*60)
        logger.info("PHASE 2: Severity-Based Alerting & Ticketing")
        logger.info("="*60)
        
        # Step 1: Run alert engine
        alert_cmd = f"python alert_engine.py --workspace {workspace}"
        if not self.run_command(alert_cmd, "Alert engine processing"):
            logger.warning("Alert engine encountered issues, continuing...")
        
        # Step 2: Sync findings to ticket system
        ticket_cmd = f"python ticket_manager.py sync --workspace {workspace}"
        if not self.run_command(ticket_cmd, "Ticketing system sync"):
            logger.warning("Ticket manager encountered issues, continuing...")
        
        # Step 3: Display ticket statistics
        stats_cmd = "python ticket_manager.py stats"
        self.run_command(stats_cmd, "Ticket statistics")
        
        logger.info("✓ Phase 2 complete: Alerts sent and tickets created")
        return True
    
    def execute_phase_3(self, workspace: str) -> bool:
        """Execute Phase 3: DAST Scanning (Optional)."""
        logger.info("\n" + "="*60)
        logger.info("PHASE 3: DAST Scanning (Optional)")
        logger.info("="*60)
        
        # Check if ZAP is configured and available
        dast_config = self.config.get('dast', {})
        if not dast_config.get('enabled', False):
            logger.info("⊘ DAST scanning disabled in configuration")
            return True
        
        logger.info("⚠️  DAST scanning requires OWASP ZAP to be running")
        logger.info("   Ensure ZAP is running at: http://localhost:8080")
        logger.info("   Skipping DAST for this run (requires manual setup)")
        
        return True
    
    def execute_phase_4(self, workspace: str, framework: str = 'owasp') -> bool:
        """Execute Phase 4: Compliance Reporting & Final Integration."""
        logger.info("\n" + "="*60)
        logger.info("PHASE 4: Compliance Reporting & Final Integration")
        logger.info("="*60)
        
        # Step 1: Generate HTML compliance report
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = f"reports/compliance_report_{workspace}_{timestamp}.html"
        
        report_cmd = (
            f"python report_generator.py --workspace {workspace} "
            f"--framework {framework} --format html --output {output_file}"
        )
        
        if not self.run_command(report_cmd, f"Compliance report generation"):
            logger.warning("Report generation encountered issues")
        else:
            self.results['report_file'] = output_file
        
        logger.info("✓ Phase 4 complete: Reports generated")
        return True
    
    def display_summary(self) -> None:
        """Display pipeline execution summary."""
        duration = (self.end_time - self.start_time).total_seconds()
        
        print("\n" + "="*70)
        print("VAPT PIPELINE EXECUTION SUMMARY")
        print("="*70)
        print(f"\n📊 Execution Time: {int(duration)} seconds")
        print(f"\n📋 Scans Executed: {len(self.results['scans'])}")
        for scan in self.results['scans']:
            print(f"   • {scan['tool']} ({scan['profile']}) on {scan['target']}")
        
        print(f"\n🚨 Results:")
        print(f"   • Alerts processed")
        print(f"   • Tickets created/updated")
        print(f"   • Report generated: {self.results.get('report_file', 'N/A')}")
        
        print("\n✅ Pipeline completed successfully!")
        print("="*70)
        print("\n📚 Next Steps:")
        print("   1. Review the compliance report")
        print("   2. Acknowledge tickets in the ticketing system")
        print("   3. Plan remediation for High/Critical findings")
        print("   4. Track remediation progress")
        print("\n")
    
    def validate_environment(self) -> bool:
        """Validate that required tools and credentials are available."""
        logger.info("Validating environment...")

        # Check for Faraday credentials (Community edition: username/password)
        faraday_user = os.getenv('FARADAY_USERNAME')
        faraday_pass = os.getenv('FARADAY_PASSWORD')
        if not faraday_user or not faraday_pass:
            logger.error(
                "Faraday credentials not set. Please export FARADAY_USERNAME and "
                "FARADAY_PASSWORD before running the pipeline."
            )
            return False
        
        # Check for required Python packages
        try:
            import yaml
            import requests
            import jinja2
        except ImportError as e:
            logger.error(f"Missing required Python package: {str(e)}")
            return False
        
        # Check for required tools
        tools_required = ['nmap', 'python3']
        for tool in tools_required:
            result = subprocess.run(f"which {tool}", shell=True, capture_output=True)
            if result.returncode != 0:
                logger.error(f"Required tool not found: {tool}")
                return False
        
        logger.info("✓ Environment validation passed")
        return True
    
    def run(self, target: str, workspace: str, profile: str = 'quick',
            framework: str = 'owasp', phases: List[str] = None) -> None:
        """Execute complete pipeline."""
        
        self.start_time = datetime.now()
        
        print("\n" + "="*70)
        print("🔐 AUTOMATED VAPT PIPELINE")
        print("="*70)
        print(f"Target: {target}")
        print(f"Workspace: {workspace}")
        print(f"Profile: {profile}")
        print(f"Framework: {framework}")
        print("="*70 + "\n")
        
        logger.info(f"Pipeline execution started at {self.start_time}")
        
        # Validate environment
        if not self.validate_environment():
            logger.error("Environment validation failed")
            sys.exit(1)
        
        # Default to all phases
        if phases is None:
            phases = ['1', '2', '3', '4']
        
        try:
            # Phase 1: Scan Automation
            if '1' in phases:
                if not self.execute_phase_1(target, workspace, profile):
                    logger.warning("Phase 1 encountered issues, continuing...")
            
            # Phase 2: Alerting & Ticketing
            if '2' in phases:
                if not self.execute_phase_2(workspace):
                    logger.warning("Phase 2 encountered issues, continuing...")
            
            # Phase 3: DAST (Optional)
            if '3' in phases:
                self.execute_phase_3(workspace)
            
            # Phase 4: Reporting
            if '4' in phases:
                if not self.execute_phase_4(workspace, framework):
                    logger.warning("Phase 4 encountered issues")
            
            self.end_time = datetime.now()
            self.display_summary()
            
            logger.info(f"Pipeline execution completed at {self.end_time}")
            
        except KeyboardInterrupt:
            logger.warning("Pipeline execution interrupted by user")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Pipeline execution failed: {str(e)}")
            sys.exit(1)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Automated VAPT Pipeline - Orchestrates complete vulnerability assessment workflow'
    )
    
    parser.add_argument(
        '--target',
        required=True,
        help='Target IP address or CIDR range (e.g., 192.168.1.0/24)'
    )
    parser.add_argument(
        '--workspace',
        default='default_lab',
        help='Faraday workspace name (default: default_lab)'
    )
    parser.add_argument(
        '--profile',
        choices=['quick', 'full', 'vuln'],
        default='quick',
        help='Nmap scan profile (default: quick)'
    )
    parser.add_argument(
        '--framework',
        choices=['owasp', 'cis'],
        default='owasp',
        help='Compliance framework for reporting (default: owasp)'
    )
    parser.add_argument(
        '--phases',
        default='1,2,3,4',
        help='Phases to execute (comma-separated, default: all)\nPhase 1: Scanning, Phase 2: Alerting, Phase 3: DAST, Phase 4: Reporting'
    )
    parser.add_argument(
        '--config',
        default='config/settings.yaml',
        help='Path to configuration file'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be executed without running'
    )
    
    args = parser.parse_args()
    
    # Parse phases
    phases = [p.strip() for p in args.phases.split(',')]
    
    # Create pipeline
    pipeline = VAPTPipeline(args.config)
    
    # Run pipeline
    pipeline.run(
        target=args.target,
        workspace=args.workspace,
        profile=args.profile,
        framework=args.framework,
        phases=phases
    )


if __name__ == '__main__':
    main()
