# Quick Start Guide

## 5-Minute Setup

### Step 1: Clone and Setup (2 minutes)

```bash
# Clone repository
git clone https://github.com/yourusername/vapt-automation-faraday.git
cd vapt-automation-faraday

# Create Python environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Install Nmap
sudo apt-get update && sudo apt-get install -y nmap
```

### Step 2: Setup Faraday (2 minutes)

```bash
# Start Faraday with Docker
docker-compose up -d

# Wait for startup
sleep 180

# Access at http://localhost:5985 (default: admin/admin)
```

### Step 3: Configure Credentials (1 minute)

```bash
# Get API key from Faraday WebUI (Settings > API Tokens)
export FARADAY_API_KEY="your_api_key_here"

# Optional: For Slack alerts
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
```

## Running Your First Scan

### Option A: Quick Scan

```bash
python pipeline.py \
  --target 192.168.1.0/24 \
  --workspace lab_scan \
  --profile quick
```

Expected output:
```
[+] Scan completed: 2025-02-18 10:30
[+] New findings imported: 14
[~] Duplicate findings skipped: 3
[+] Workspace: lab_scan
```

### Option B: Parse Existing Report

```bash
# If you have a Nessus or OpenVAS report
python report_parser.py \
  --file scan_results.nessus \
  --workspace lab_scan
```

### Option C: Just Generate Report

```bash
python report_generator.py \
  --workspace lab_scan \
  --output my_report.html

# Open report
open my_report.html
```

## Check Results

```bash
# View open tickets
python ticket_manager.py list --status open

# View ticket stats
python ticket_manager.py stats

# Show specific ticket
python ticket_manager.py show TICKET-001

# Acknowledge a ticket
python ticket_manager.py acknowledge TICKET-001

# Resolve a ticket
python ticket_manager.py resolve TICKET-001 --notes "Applied patch v1.2"
```

## Continuous Monitoring

```bash
# Run alerts continuously
python alert_engine.py --workspace lab_scan --continuous

# In another terminal, run periodic scans
while true; do
  python pipeline.py --target 192.168.1.0/24 --workspace lab_scan
  sleep 86400  # Run daily
done
```

## Setup GitHub Actions (Optional)

For automated scanning on schedule:

1. **Create GitHub Secrets** (Settings > Secrets)
   - `FARADAY_API_KEY`: Your Faraday API key
   - `SLACK_WEBHOOK_URL`: (optional) Your Slack webhook

2. **Workflow is ready**: `.github/workflows/vapt_pipeline.yml`

3. **Triggers automatically**:
   - Daily at 2 AM UTC
   - Manual via GitHub UI

## Troubleshooting

### Faraday Connection Failed

```bash
# Check Faraday is running
curl http://localhost:5985
# Expected: 200 response or redirect to login

# Check API key
curl -H "Authorization: Bearer $FARADAY_API_KEY" \
  http://localhost:5985/api/v3/users/me
```

### Nmap Permission Denied

```bash
# Nmap needs root for certain scans
sudo nmap -T4 192.168.1.100

# Or allow user to run nmap
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+ep /usr/bin/nmap
```

### Missing Python Packages

```bash
# Reinstall all requirements
pip install --force-reinstall -r requirements.txt
```

## Project Structure

```
vapt-automation-faraday/
├── scan_scheduler.py          # Phase 1: Run Nmap scans
├── report_parser.py           # Phase 1: Parse scan reports
├── alert_engine.py            # Phase 2: Severity-based alerting
├── ticket_manager.py          # Phase 2: Ticket lifecycle
├── report_generator.py        # Phase 4: Generate HTML reports
├── pipeline.py                # Master orchestrator
├── config/
│   └── settings.yaml          # Configuration file
├── templates/
│   └── report_template.html   # HTML report template
├── tickets/                   # Generated tickets (JSON)
│   ├── TICKET-001.json
│   ├── TICKET-002.json
│   └── ...
├── reports/                   # Generated scans and reports
│   ├── nmap/
│   ├── openvas/
│   └── burp/
├── .github/workflows/
│   └── vapt_pipeline.yml      # GitHub Actions workflow
├── requirements.txt           # Python dependencies
├── README.md                  # Full documentation
└── QUICKSTART.md             # This file
```

## Next Steps

1. **Customize Configuration**
   - Edit `config/settings.yaml`
   - Add your Slackwebhook
   - Change scan profiles

2. **Run Your First Pipeline**
   ```bash
   python pipeline.py --target YOUR_TARGET --workspace YOUR_WORKSPACE
   ```

3. **Setup Continuous Scanning**
   - Configure GitHub Actions
   - Or use cron for local scheduling

4. **Integrate with IR Workflow**
   - Connect ticketing to Jira
   - Send alerts to your SOC
   - Generate client reports

## Support

- **Documentation**: See README.md
- **Issues**: Create GitHub issue
- **Faraday Help**: https://docs.faradaysec.com
- **Questions**: Check troubleshooting section

---

🔐 You're all set! Happy scanning!
