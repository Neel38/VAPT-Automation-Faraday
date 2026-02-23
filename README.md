# 🔐 VAPT Automation Pipeline Using Faraday

**Automated Vulnerability Assessment and Penetration Testing (VAPT) Pipeline**

This project implements a complete end-to-end automated VAPT pipeline that scans a local lab environment, centralizes findings into Faraday, triggers intelligent alerts, integrates into CI/CD, and generates professional compliance reports.

## Overview

This pipeline automates the complete vulnerability assessment workflow:

- **Automated Scanning**: Nmap with multiple profiles (quick, full, vuln)
- **Centralized Management**: Auto-import to Faraday with deduplication
- **Smart Alerting**: Multi-channel notifications (Slack, Email, Webhooks)
- **Ticket Management**: Automatic ticket creation for High/Critical findings
- **Compliance Reporting**: Professional HTML reports with OWASP/CIS mapping
- **CI/CD Integration**: GitHub Actions workflow for scheduled and on-demand runs

## Prerequisites

- Python 3.8+
- Docker & Docker Compose
- Nmap 7.70+
- Ubuntu 20.04+ or Debian 10+

## Installation

```bash
# 1. Clone repository
git clone https://github.com/yourusername/vapt-automation-faraday.git
cd vapt-automation-faraday

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Install system dependencies
sudo apt-get install -y nmap

# 5. Setup Faraday (Docker)
docker-compose up -d

# 6. Configure credentials
export FARADAY_API_KEY="your_api_key_here"
```

## Usage

### Run Quick Scan

```bash
python scan_scheduler.py --target 192.168.1.0/24 --profile quick --workspace lab_scan
```

### Run Alert Engine

```bash
python alert_engine.py --workspace lab_scan --continuous
```

### Manage Tickets

```bash
python ticket_manager.py list --status open
python ticket_manager.py acknowledge TICKET-001
```

### Generate Report

```bash
python report_generator.py --workspace lab_scan --format html
```

### Full Pipeline

```bash
python pipeline.py --target 192.168.1.0/24 --workspace lab_scan
```

## Components

| Script | Purpose |
|--------|---------|
| `scan_scheduler.py` | Nmap automation with Faraday import |
| `report_parser.py` | Parse Nessus/OpenVAS/Burp reports |
| `alert_engine.py` | Multi-channel alerting |
| `ticket_manager.py` | Ticket lifecycle management |
| `report_generator.py` | HTML compliance reports |
| `pipeline.py` | Master orchestrator |

## CI/CD Integration

### GitHub Actions Setup

1. Add secrets to your repository:
   - `FARADAY_API_KEY`: Your Faraday API key
   - `SLACK_WEBHOOK_URL` (optional): For Slack alerts

2. Workflow file: `.github/workflows/vapt_pipeline.yml`

3. Triggers:
   - Scheduled: Daily at 2 AM UTC
   - Manual: Via GitHub Actions UI with custom parameters

## Quick Examples

### Example 1: Lab Scan

```bash
source venv/bin/activate
export FARADAY_API_KEY="your_key"
python pipeline.py \
  --target 192.168.1.0/24 \
  --workspace lab_scan \
  --profile quick
```

### Example 2: Import Nessus Report

```bash
python report_parser.py \
  --file nessus_export.nessus \
  --workspace client_scan

python report_generator.py \
  --workspace client_scan
```

## Troubleshooting

### Test Faraday Connection

```bash
curl http://localhost:5985
```

### Install Nmap

```bash
sudo apt-get install nmap
```

### Check Dependencies

```bash
pip install -r requirements.txt --force-reinstall
```

## Legal Notice

⚠️ **Only scan systems you own or have written permission to test.**

Unauthorized scanning is illegal.

## License

MIT License

## Support

- [Faraday Documentation](https://docs.faradaysec.com)
- GitHub Issues
- README troubleshooting section

---

🔐 Automated Vulnerability Assessment & Penetration Testing Pipeline
