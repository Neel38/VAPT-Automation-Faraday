#!/usr/bin/env python3
"""
Mock Ticketing System for VAPT Pipeline
Manages ticket lifecycle for High and Critical vulnerabilities.
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import requests
import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ticket_manager.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class TicketManager:
    """Manages ticket lifecycle for vulnerability tracking."""
    
    PRIORITY_MAP = {
        'critical': 'P0',
        'high': 'P1',
        'medium': 'P2',
        'low': 'P3',
        'info': 'P4'
    }
    
    def __init__(self, config_path: str = 'config/settings.yaml'):
        """Initialize ticket manager."""
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
        self.tickets_dir = Path(self.config.get('directories', {}).get('tickets', './tickets'))
        self.tickets_dir.mkdir(parents=True, exist_ok=True)
        self.ticket_counter = self._get_next_ticket_number()
    
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
    
    def _get_next_ticket_number(self) -> int:
        """Get next ticket number based on existing tickets."""
        existing_tickets = list(self.tickets_dir.glob('TICKET-*.json'))
        if not existing_tickets:
            return 1
        
        numbers = []
        for ticket_file in existing_tickets:
            try:
                num = int(ticket_file.stem.split('-')[1])
                numbers.append(num)
            except (ValueError, IndexError):
                continue
        
        return max(numbers) + 1 if numbers else 1
    
    def create_ticket_from_finding(self, finding: Dict) -> str:
        """Create a ticket from a vulnerability finding using Faraday API keys."""
        severity = str(finding.get('severity', 'low')).lower()
        
        # Check threshold
        severity_threshold = self.config.get('tickets', {}).get('severity_threshold', 'high')
        if self._is_severity_below_threshold(severity, severity_threshold):
            return None
        
        ticket_id = f"TICKET-{self.ticket_counter:03d}"
        self.ticket_counter += 1
        
        # Extract CVSS safely from Faraday structure
        cvss_score = finding.get('cvss3', {}).get('base_score') or \
                     finding.get('cvss2', {}).get('base_score')
        
        priority = self.PRIORITY_MAP.get(severity, 'P3')
        if cvss_score and float(cvss_score) >= 9.0:
            priority = 'P0'

        # Create ticket object with verified keys from the Faraday API
        ticket = {
            'ticket_id': ticket_id,
            'vuln_name': finding.get('name', 'Unknown'), # Verified key: 'name'
            'cve': finding.get('cve', []),
            'host': finding.get('target', 'Unknown'),    # Verified key: 'target'
            'port': finding.get('port', 'N/A'),
            'severity': severity,
            'cvss': cvss_score,
            'priority': priority,
            'status': 'open',
            'description': finding.get('description', ''),
            'created_at': datetime.now().isoformat(),
            'faraday_finding_id': finding.get('id')
        }
        
        # Save to file
        ticket_file = self.tickets_dir / f"{ticket_id}.json"
        with open(ticket_file, 'w') as f:
            json.dump(ticket, f, indent=2)
        
        logger.info(f"Created ticket {ticket_id} for: {ticket['vuln_name']}")
        return ticket_id
    
    def _is_severity_below_threshold(self, severity: str, threshold: str) -> bool:
        """Check if finding severity is below threshold."""
        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        
        try:
            severity_idx = severity_order.index(severity.lower())
            threshold_idx = severity_order.index(threshold.lower())
            return severity_idx > threshold_idx
        except ValueError:
            return False
    
    def load_ticket(self, ticket_id: str) -> Optional[Dict]:
        """Load ticket from file."""
        ticket_file = self.tickets_dir / f"{ticket_id}.json"
        
        if not ticket_file.exists():
            logger.error(f"Ticket not found: {ticket_id}")
            return None
        
        try:
            with open(ticket_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load ticket {ticket_id}: {str(e)}")
            return None
    
    def save_ticket(self, ticket: Dict) -> bool:
        """Save ticket to file."""
        try:
            ticket_file = self.tickets_dir / f"{ticket['ticket_id']}.json"
            with open(ticket_file, 'w') as f:
                json.dump(ticket, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Failed to save ticket {ticket.get('ticket_id')}: {str(e)}")
            return False
    
    def acknowledge_ticket(self, ticket_id: str, acknowledging_user: str = None) -> bool:
        """Mark ticket as acknowledged."""
        ticket = self.load_ticket(ticket_id)
        if not ticket:
            return False
        
        ticket['status'] = 'acknowledged'
        ticket['acknowledged_at'] = datetime.now().isoformat()
        ticket['assigned_to'] = acknowledging_user or 'Unknown'
        
        success = self.save_ticket(ticket)
        if success:
            logger.info(f"Acknowledged ticket {ticket_id}")
        return success
    
    def resolve_ticket(self, ticket_id: str, resolution_notes: str = None) -> bool:
        """Mark ticket as resolved."""
        ticket = self.load_ticket(ticket_id)
        if not ticket:
            return False
        
        ticket['status'] = 'resolved'
        ticket['resolved_at'] = datetime.now().isoformat()
        ticket['resolution_notes'] = resolution_notes or 'Resolved'
        
        success = self.save_ticket(ticket)
        if success:
            logger.info(f"Resolved ticket {ticket_id}")
        return success
    
    def list_tickets(self, status: Optional[str] = None, severity: Optional[str] = None) -> List[Dict]:
        """List tickets with optional filtering."""
        tickets = []
        
        for ticket_file in self.tickets_dir.glob('TICKET-*.json'):
            try:
                with open(ticket_file, 'r') as f:
                    ticket = json.load(f)
                
                # Apply filters
                if status and ticket.get('status') != status:
                    continue
                if severity and ticket.get('severity') != severity.lower():
                    continue
                
                tickets.append(ticket)
            except Exception as e:
                logger.warning(f"Failed to load ticket {ticket_file}: {str(e)}")
        
        # Sort by priority (P0 first) then by creation date (newest first)
        priority_order = ['P0', 'P1', 'P2', 'P3', 'P4']
        priority_rank = {p: i for i, p in enumerate(priority_order)}
        tickets.sort(
            key=lambda x: (
                priority_rank.get(x.get('priority', 'P4'), len(priority_order)),
                -datetime.fromisoformat(
                    x.get('created_at', datetime.now().isoformat())
                ).timestamp(),
            )
        )
        
        return tickets
    
    def get_ticket_statistics(self) -> Dict:
        """Get statistics about tickets."""
        all_tickets = self.list_tickets()
        
        stats = {
            'total': len(all_tickets),
            'by_status': {},
            'by_severity': {},
            'by_priority': {}
        }
        
        for ticket in all_tickets:
            status = ticket.get('status', 'unknown')
            severity = ticket.get('severity', 'unknown')
            priority = ticket.get('priority', 'unknown')
            
            stats['by_status'][status] = stats['by_status'].get(status, 0) + 1
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
            stats['by_priority'][priority] = stats['by_priority'].get(priority, 0) + 1
        
        return stats
    
    def sync_with_faraday(self, workspace: str) -> None:
        """Create tickets by extracting data from the nested 'value' key."""
        try:
            endpoint = f"{self.faraday_url}/_api/v3/ws/{workspace}/vulns"
            response = self.session.get(endpoint, timeout=self.config['faraday']['timeout'])
            response.raise_for_status()

            data = response.json()
            raw_findings = data.get('vulnerabilities') or []
            
            created_count = 0
            for item in raw_findings:
                # Dive into the 'value' dictionary where the real data lives
                finding = item.get('value', {})
                severity = str(finding.get('severity', '')).lower()
                
                if severity not in ['high', 'critical']:
                    continue

                faraday_id = finding.get('id')
                if faraday_id is None:
                    continue

                # Deduplication logic remains the same
                existing = False
                for ticket_file in self.tickets_dir.glob('TICKET-*.json'):
                    try:
                        with open(ticket_file, 'r') as f:
                            ticket = json.load(f)
                            if str(ticket.get('faraday_finding_id')) == str(faraday_id):
                                existing = True
                                break
                    except:
                        continue
                
                if not existing:
                    ticket_id = self.create_ticket_from_finding(finding)
                    if ticket_id:
                        created_count += 1
            
            logger.info(f"Synced with Faraday: created {created_count} new tickets")
        except Exception as e:
            logger.error(f"Failed to sync: {str(e)}")
    
    def print_ticket(self, ticket: Dict) -> None:
        """Pretty print a ticket."""
        status_symbol = {
            'open': '🔴',
            'acknowledged': '🟡',
            'resolved': '🟢'
        }
        
        symbol = status_symbol.get(ticket.get('status', 'open'), '⚪')
        
        print(f"\n{symbol} {ticket['ticket_id']} [{ticket['priority']}] {ticket['severity'].upper()}")
        print(f"   Vulnerability: {ticket['vuln_name']}")
        print(f"   Host: {ticket['host']}:{ticket['port']}")
        print(f"   CVE: {ticket['cve'] or 'N/A'}")
        print(f"   Status: {ticket['status'].upper()}")
        print(f"   Created: {ticket['created_at']}")
        if ticket['acknowledged_at']:
            print(f"   Acknowledged: {ticket['acknowledged_at']}")
        if ticket['resolved_at']:
            print(f"   Resolved: {ticket['resolved_at']}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Mock Ticketing System for VAPT Pipeline'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List tickets')
    list_parser.add_argument('--status', choices=['open', 'acknowledged', 'resolved'],
                            help='Filter by status')
    list_parser.add_argument('--severity', choices=['critical', 'high', 'medium', 'low', 'info'],
                            help='Filter by severity')
    
    # Acknowledge command
    ack_parser = subparsers.add_parser('acknowledge', help='Acknowledge a ticket')
    ack_parser.add_argument('ticket_id', help='Ticket ID to acknowledge')
    ack_parser.add_argument('--user', default=None, help='User acknowledging the ticket')
    
    # Resolve command
    res_parser = subparsers.add_parser('resolve', help='Resolve a ticket')
    res_parser.add_argument('ticket_id', help='Ticket ID to resolve')
    res_parser.add_argument('--notes', default=None, help='Resolution notes')
    
    # Show command
    show_parser = subparsers.add_parser('show', help='Show ticket details')
    show_parser.add_argument('ticket_id', help='Ticket ID to show')
    
    # Stats command
    stats_parser = subparsers.add_parser('stats', help='Show ticket statistics')
    
    # Sync command
    sync_parser = subparsers.add_parser('sync', help='Sync findings from Faraday')
    sync_parser.add_argument('--workspace', required=True, help='Faraday workspace')
    
    # Common arguments
    parser.add_argument('--config', default='config/settings.yaml',
                       help='Path to configuration file')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    manager = TicketManager(args.config)
    
    if args.command == 'list':
        tickets = manager.list_tickets(args.status, args.severity)
        if not tickets:
            print("No tickets found")
            return
        
        print(f"\n{'ID':<12} {'Priority':<8} {'Severity':<10} {'Status':<12} {'Host':<15} {'Vulnerability':<40}")
        print("-" * 100)
        
        for ticket in tickets:
            print(f"{ticket['ticket_id']:<12} {ticket['priority']:<8} {ticket['severity']:<10} "
                  f"{ticket['status']:<12} {ticket['host']:<15} {ticket['vuln_name'][:40]:<40}")
    
    elif args.command == 'acknowledge':
        if manager.acknowledge_ticket(args.ticket_id, args.user):
            print(f"✓ Ticket {args.ticket_id} acknowledged")
        else:
            print(f"✗ Failed to acknowledge ticket {args.ticket_id}")
    
    elif args.command == 'resolve':
        if manager.resolve_ticket(args.ticket_id, args.notes):
            print(f"✓ Ticket {args.ticket_id} resolved")
        else:
            print(f"✗ Failed to resolve ticket {args.ticket_id}")
    
    elif args.command == 'show':
        ticket = manager.load_ticket(args.ticket_id)
        if ticket:
            manager.print_ticket(ticket)
        else:
            print(f"Ticket {args.ticket_id} not found")
    
    elif args.command == 'stats':
        stats = manager.get_ticket_statistics()
        print(f"\nTicket Statistics")
        print(f"================")
        print(f"Total Tickets: {stats['total']}")
        print(f"\nBy Status:")
        for status, count in stats['by_status'].items():
            print(f"  {status}: {count}")
        print(f"\nBy Severity:")
        for severity, count in stats['by_severity'].items():
            print(f"  {severity}: {count}")
        print(f"\nBy Priority:")
        for priority, count in stats['by_priority'].items():
            print(f"  {priority}: {count}")
    
    elif args.command == 'sync':
        manager.sync_with_faraday(args.workspace)


if __name__ == '__main__':
    main()
