#!/usr/bin/env python3
"""
Severity-Based Alert Engine for VAPT Pipeline
Monitors Faraday for new findings and sends formatted alerts.
"""

import argparse
import json
import logging
import os
import sys
import time
import requests
import smtplib
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from typing import Dict, List
import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('alert_engine.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class AlertEngine:
    """Monitors Faraday findings and sends alerts based on severity."""
    
    SEVERITY_ICONS = {
        'critical': '🚨',
        'high': '⚠️',
        'medium': '⚠️',
        'low': 'ℹ️',
        'info': 'ℹ️'
    }
    
    SEVERITY_PRIORITY = {
        'critical': 0,
        'high': 1,
        'medium': 2,
        'low': 3,
        'info': 4
    }
    
    def __init__(self, config_path: str = 'config/settings.yaml'):
        """Initialize alert engine with configuration and Faraday session."""
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
        self.alert_config = self.config.get('alerts', {})
        self.severity_threshold = self.alert_config.get('severity_threshold', 'high')
        self.processed_findings = set()
        self._load_processed_findings()
    
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
    
    def _load_processed_findings(self) -> None:
        """Load previously processed findings to avoid duplicate alerts."""
        processed_file = Path('processed_findings.json')
        if processed_file.exists():
            try:
                with open(processed_file, 'r') as f:
                    data = json.load(f)
                    self.processed_findings = set(data.get('findings', []))
                logger.info(f"Loaded {len(self.processed_findings)} previously processed findings")
            except Exception as e:
                logger.warning(f"Could not load processed findings: {str(e)}")
    
    def _save_processed_findings(self) -> None:
        """Save processed findings to avoid duplicate alerts."""
        try:
            with open('processed_findings.json', 'w') as f:
                json.dump({'findings': list(self.processed_findings)}, f)
        except Exception as e:
            logger.warning(f"Could not save processed findings: {str(e)}")
    
    def _meets_severity_threshold(self, severity: str) -> bool:
        """Check if finding severity meets alert threshold."""
        threshold_priority = self.SEVERITY_PRIORITY.get(self.severity_threshold, 1)
        finding_priority = self.SEVERITY_PRIORITY.get(severity, 4)
        return finding_priority <= threshold_priority
    
    def fetch_new_findings(self, workspace: str) -> list[dict]:
        """Fetch findings and extract the nested 'value' dictionary."""
        try:
            url = f"{self.faraday_url}/_api/v3/ws/{workspace}/vulns"
            response = self.session.get(url, timeout=self.config['faraday']['timeout'])
            response.raise_for_status()
            
            data = response.json()
            raw_findings = data.get('vulnerabilities') or []

            new_findings = []
            for item in raw_findings:
                # The actual data is inside the 'value' key
                finding_data = item.get('value', {})
                severity = str(finding_data.get('severity', '')).lower()
                
                if severity in self.severity_threshold:
                    vuln_id = str(finding_data.get('id'))
                    if vuln_id not in self.processed_findings:
                        # Store the inner 'value' dict for easier processing
                        new_findings.append(finding_data)
            
            logger.info(f"Found {len(new_findings)} new findings meeting severity threshold")
            return new_findings
        except Exception as e:
            logger.error(f"Failed to fetch findings: {str(e)}")
            return []

    def format_alert_message(self, finding: Dict, workspace: str) -> str:
        """Format finding into a readable alert message using 'target' and 'name'."""
        severity_raw = finding.get('severity', 'unknown')
        severity = str(severity_raw).upper()
        icon = self.SEVERITY_ICONS.get(severity_raw.lower(), '❓')
        
        # verified keys from your JSON
        host = finding.get('target', 'Unknown') 
        vuln_name = finding.get('name', 'Unknown')
        
        cve_list = finding.get('cve', [])
        cve = cve_list[0] if isinstance(cve_list, list) and cve_list else 'N/A'
        
        cvss_score = finding.get('cvss3', {}).get('base_score') or \
                     finding.get('cvss2', {}).get('base_score') or 'N/A'
        
        message = f"""{icon} {severity} Finding Detected
─────────────────────────────
Host:          {host}
Vulnerability: {vuln_name}
CVE:           {cve}
Severity:      {severity}
CVSS Score:    {cvss_score}
Workspace:     {workspace}
Detected at:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"""
        
        return message
    
    def send_slack_alert(self, finding: Dict) -> bool:
        """Send alert to Slack webhook."""
        try:
            webhook_url = os.getenv('SLACK_WEBHOOK_URL', 
                                   self.alert_config.get('channels', {}).get('slack', {}).get('webhook_url'))
            
            if not webhook_url:
                logger.warning("Slack webhook URL not configured")
                return False
            
            severity = finding.get('severity', 'unknown').lower()
            color_map = {
                'critical': '#FF0000',
                'high': '#FFA500',
                'medium': '#FFD700',
                'low': '#90EE90',
                'info': '#87CEEB'
            }
            color = color_map.get(severity, '#808080')
            
            host = finding.get('target', 'Unknown')
            cve_list = finding.get('cve', [])
            cve = cve_list[0] if isinstance(cve_list, list) and cve_list else 'N/A'
            cvss_score = finding.get('cvss3', {}).get('base_score') or \
                         finding.get('cvss2', {}).get('base_score') or 'N/A'
            
            payload = {
                'attachments': [
                    {
                        'color': color,
                        'title': f"🚨 {severity.upper()} Vulnerability Found",
                        'fields': [
                            {'title': 'Host', 'value': host, 'short': True},
                            {'title': 'Port', 'value': port, 'short': True},
                            {'title': 'Vulnerability', 'value': finding.get('name', 'Unknown'), 'short': False},
                            {'title': 'CVE', 'value': cve, 'short': True},
                            {'title': 'CVSS Score', 'value': str(cvss_score), 'short': True},
                            {'title': 'Description', 'value': finding.get('description', 'N/A')[:500], 'short': False},
                        ],
                        'footer': 'VAPT Pipeline',
                        'ts': int(datetime.now().timestamp())
                    }
                ]
            }
            
            response = requests.post(webhook_url, json=payload, timeout=10)
            
            if response.status_code == 200:
                logger.info(f"Slack alert sent for finding: {finding.get('name')}")
                return True
            else:
                logger.error(f"Slack alert failed (code {response.status_code}): {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to send Slack alert: {str(e)}")
            return False
    
    def send_email_alert(self, finding: Dict) -> bool:
        """Send alert via SMTP email."""
        try:
            email_config = self.alert_config.get('channels', {}).get('email', {})
            
            smtp_server = os.getenv('EMAIL_SMTP_SERVER', email_config.get('smtp_server'))
            smtp_port = int(os.getenv('EMAIL_SMTP_PORT', email_config.get('smtp_port', 587)))
            from_addr = os.getenv('EMAIL_FROM', email_config.get('from_address'))
            to_addr = os.getenv('EMAIL_TO', email_config.get('to_address'))
            
            if not all([smtp_server, from_addr, to_addr]):
                logger.warning("Email configuration incomplete")
                return False
            
            # Create email message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[{finding.get('severity', 'UNKNOWN').upper()}] Vulnerability Alert: {finding.get('name')}"
            msg['From'] = from_addr
            msg['To'] = to_addr
            
            severity = finding.get('severity', 'unknown').upper()
            host = finding.get('target_distribution', {}).get('host', 'Unknown')
            port = finding.get('target_distribution', {}).get('port', 'N/A')
            cve = finding.get('cve', 'N/A')
            cvss_score = finding.get('cvss_score', 'N/A')
            
            text = f"""
VAPT Pipeline Alert

Severity:      {severity}
Host:          {host}
Port:          {port}
Vulnerability: {finding.get('name', 'Unknown')}
CVE:           {cve}
CVSS Score:    {cvss_score}
Detected at:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Description:
{finding.get('description', 'No description available')}

---
VAPT Pipeline - Automated Vulnerability Alerting
"""
            
            html = f"""
<html>
  <body style="font-family: Arial, sans-serif;">
    <div style="border-left: 4px solid #FF4444; padding: 15px; background: #FFF5F5;">
      <h2 style="color: #FF4444; margin: 0;">🚨 {severity} Vulnerability Alert</h2>
      <p style="margin: 10px 0;"><strong>Vulnerability:</strong> {finding.get('name', 'Unknown')}</p>
      <p style="margin: 10px 0;"><strong>Host:</strong> {host}</p>
      <p style="margin: 10px 0;"><strong>Port:</strong> {port}</p>
      <p style="margin: 10px 0;"><strong>CVE:</strong> {cve}</p>
      <p style="margin: 10px 0;"><strong>CVSS Score:</strong> {cvss_score}</p>
      <p style="margin: 10px 0;"><strong>Detected:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
      <hr>
      <p><strong>Description:</strong></p>
      <p>{finding.get('description', 'No description available')}</p>
    </div>
  </body>
</html>
"""
            
            msg.attach(MIMEText(text, 'plain'))
            msg.attach(MIMEText(html, 'html'))
            
            # Send email
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(from_addr, os.getenv('EMAIL_PASSWORD', ''))
                server.send_message(msg)
            
            logger.info(f"Email alert sent to {to_addr}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email alert: {str(e)}")
            return False
    
    def send_webhook_alert(self, finding: Dict, webhook_url: str) -> bool:
        """Send alert to generic webhook endpoint."""
        try:
            payload = {
                'alert_type': 'vulnerability',
                'severity': finding.get('severity', 'unknown'),
                'host': finding.get('target_distribution', {}).get('host', 'Unknown'),
                'port': finding.get('target_distribution', {}).get('port', 'N/A'),
                'vulnerability': finding.get('name', 'Unknown'),
                'cve': finding.get('cve', 'N/A'),
                'cvss_score': finding.get('cvss_score'),
                'description': finding.get('description', ''),
                'timestamp': datetime.now().isoformat()
            }
            
            response = requests.post(webhook_url, json=payload, timeout=10)
            
            if response.status_code in [200, 201, 202]:
                logger.info(f"Webhook alert sent to {webhook_url}")
                return True
            else:
                logger.warning(f"Webhook returned status {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to send webhook alert: {str(e)}")
            return False
    
    def run(self, workspace: str, dry_run: bool = False) -> None:
        """Run alert engine."""
        logger.info(f"Starting alert engine for workspace: {workspace}")
        
        try:
            # Fetch new findings
            findings = self.fetch_new_findings(workspace)
            
            if not findings:
                logger.info("No new findings to alert on")
                return
            
            logger.info(f"Processing {len(findings)} findings for alerts")
            
            # Process each finding
            for finding in findings:
                # Add the ID to the processed set IMMEDIATELY so it's tracked
                vuln_id = str(finding.get('id'))
                self.processed_findings.add(vuln_id)

                if dry_run:
                    message = self.format_alert_message(finding, workspace)
                    print(message)
                    print("\n" + "="*50 + "\n")
                    continue
                
                # Send alerts via configured channels
                channels = self.alert_config.get('channels', {})
                
                if channels.get('slack', {}).get('enabled', False) or os.getenv('SLACK_WEBHOOK_URL'):
                    self.send_slack_alert(finding)
                
                if channels.get('email', {}).get('enabled', False):
                    self.send_email_alert(finding)
            
            # Save processed findings
            self._save_processed_findings()
            
            logger.info("Alert engine completed")
            
        except Exception as e:
            logger.error(f"Alert engine failed: {str(e)}")
    
    def continuous_monitoring(self, workspace: str, interval: int = None) -> None:
        """Continuously monitor Faraday for new findings."""
        if interval is None:
            interval = self.alert_config.get('polling_interval', 60)
        
        logger.info(f"Starting continuous monitoring (interval: {interval}s)")
        
        try:
            while True:
                self.run(workspace, dry_run=False)
                time.sleep(interval)
        except KeyboardInterrupt:
            logger.info("Continuous monitoring stopped")
        except Exception as e:
            logger.error(f"Continuous monitoring failed: {str(e)}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Severity-Based Alert Engine for VAPT Pipeline'
    )
    parser.add_argument(
        '--workspace',
        required=True,
        help='Faraday workspace to monitor'
    )
    parser.add_argument(
        '--config',
        default='config/settings.yaml',
        help='Path to configuration file'
    )
    parser.add_argument(
        '--continuous',
        action='store_true',
        help='Run continuous monitoring'
    )
    parser.add_argument(
        '--interval',
        type=int,
        default=None,
        help='Polling interval in seconds (for continuous mode)'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Dry run - print alerts without sending'
    )
    
    args = parser.parse_args()
    
    engine = AlertEngine(args.config)
    
    if args.continuous:
        engine.continuous_monitoring(args.workspace, args.interval)
    else:
        engine.run(args.workspace, args.dry_run)


if __name__ == '__main__':
    main()
