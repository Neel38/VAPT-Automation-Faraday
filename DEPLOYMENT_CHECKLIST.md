# DEPLOYMENT CHECKLIST

## Pre-Deployment Verification

### Code Quality
- [x] All Python scripts linted and formatted
- [x] Error handling implemented throughout
- [x] Logging configured for all modules
- [x] Type hints added where appropriate
- [x] Docstrings on all classes and methods
- [x] Configuration externalized (no hardcoded values)
- [x] Secrets managed via environment variables

### Testing & Documentation
- [x] Component functions documented
- [x] Sample configuration provided
- [x] Sample tickets provided
- [x] Sample logs provided
- [x] README with comprehensive examples
- [x] QUICKSTART guide for fast setup
- [x] ARCHITECTURE document for technical details
- [x] GitHub Actions workflow configured

### Security Review
- [x] No API keys in code
- [x] No hardcoded credentials
- [x] YAML config uses ${ENV_VAR} format
- [x] HTTPS support in configuration
- [x] SSL verification options available
- [x] Error messages don't leak sensitive info
- [x] Input validation on CLI arguments
- [x] Safe file handling (pathlib used)
- [x] No arbitrary code execution risks

## Pre-Deployment Checklist

### System Preparation
- [ ] Ubuntu 20.04+ or Debian 10+ installed
- [ ] 4GB+ RAM available
- [ ] 20GB+ disk space available
- [ ] Internet connectivity to scan targets confirmed
- [ ] SSH/RDP access to deployment server verified

### Software Installation
- [ ] Python 3.8+ installed
- [ ] Docker installed
- [ ] Docker Compose installed
- [ ] Nmap installed
- [ ] Git installed
- [ ] curl/wget installed

### Repository Setup
- [ ] Repository cloned to deployment server
- [ ] Git permissions configured
- [ ] .gitignore includes sensitive files
- [ ] SSH keys configured for GitHub (if needed)

### Faraday Deployment
- [ ] Docker Compose configuration reviewed
- [ ] Faraday Docker image pulled
- [ ] PostgreSQL database setup confirmed
- [ ] Persistent volumes created
- [ ] Faraday accessible on http://localhost:5985
- [ ] Default credentials changed!

### Credentials & Secrets
- [ ] Faraday API key generated and saved
- [ ] Faraday API key added to FARADAY_API_KEY env var
- [ ] Slack webhook URL obtained (if using Slack alerts)
- [ ] Slack webhook added to SLACK_WEBHOOK_URL env var
- [ ] Email credentials configured (if using email alerts)
- [ ] GitHub Secrets created (for CI/CD)

### Configuration Customization
- [ ] Read `config/settings.yaml` completely
- [ ] Updated Faraday URL (if not localhost)
- [ ] Selected appropriate scan profiles
- [ ] Configured alert channels (Slack/Email/Webhooks)
- [ ] Set alert severity threshold
- [ ] Selected compliance framework (OWASP/CIS)
- [ ] Updated directory paths if needed

### Python Environment
- [ ] Python virtual environment created
- [ ] Virtual environment activated
- [ ] All requirements installed: `pip install -r requirements.txt`
- [ ] Dependencies verified: `python -c "import yaml, requests, jinja2"`
- [ ] Script permissions verified (executable)

### Testing
- [ ] Faraday connectivity test passed
  ```bash
  curl http://localhost:5985
  ```
- [ ] API key test passed
  ```bash
  curl -H "Authorization: Bearer $FARADAY_API_KEY" \
    http://localhost:5985/api/v3/users/me
  ```
- [ ] Nmap test passed
  ```bash
  nmap --version
  ```
- [ ] Python scripts execute without errors
  ```bash
  python scan_scheduler.py --help
  python report_parser.py --help
  python alert_engine.py --help
  python ticket_manager.py --help
  python report_generator.py --help
  python pipeline.py --help
  ```

### Network Configuration
- [ ] Firewall allows access to Faraday (5985)
- [ ] Network routes to scan targets confirmed
- [ ] Proxy settings configured (if applicable)
- [ ] DNS resolution working for Faraday hostname
- [ ] Webhook URLs are accessible (if using external webhooks)

### Logging & Monitoring
- [ ] Log directory created: `mkdir -p logs`
- [ ] Log rotation consideration documented
- [ ] Monitoring solution identified (if enterprise)
- [ ] Alert recipients confirmed (once alerts enabled)

## Deployment Steps

### 1. Initial Setup (First Time Only)

```bash
# Navigate to project directory
cd /path/to/vapt-automation-faraday

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create necessary directories
mkdir -p logs reports/nmap reports/openvas reports/burp tickets
```

### 2. Faraday Setup (First Time Only)

```bash
# Start Faraday
docker-compose up -d

# Wait for startup (2-3 minutes)
sleep 180

# Verify Faraday is running
curl http://localhost:5985
```

### 3. Credentials Configuration

```bash
# Export API key (add to ~/.bashrc for persistence)
export FARADAY_API_KEY="your_faraday_api_key"

# Optional: Export Slack webhook
export SLACK_WEBHOOK_URL="your_slack_webhook_url"
```

### 4. Initial Scan Test

```bash
# Run quick scan on small network
python pipeline.py \
  --target 192.168.1.100 \
  --workspace test_workspace \
  --profile quick
```

### 5. Verify Results

```bash
# Check tokens were created
python ticket_manager.py list

# View scan logs
tail -f scan.log

# Check Faraday for imported findings
# (via WebUI at localhost:5985)
```

### 6. Setup GitHub Actions (Optional)

```bash
# 1. Push to GitHub
git add .
git commit -m "Initial VAPT pipeline setup"
git push origin main

# 2. Go to GitHub repository Settings > Secrets

# 3. Add secrets:
#    - FARADAY_API_KEY
#    - SLACK_WEBHOOK_URL (optional)

# 4. Workflow is ready (triggered daily at 2 AM UTC)
```

### 7. Production Hardening

```bash
# Change Faraday default password!
# (Access WebUI at localhost:5985)

# Setup SSL/TLS for Faraday (recommended)
# - Update docker-compose.yml with cert paths
# - Update settings.yaml with https:// URL

# Setup persistent backups
# - Mount PostgreSQL data volume properly
# - Configure backup cron job
```

## Post-Deployment Verification

- [ ] First scan completed successfully
- [ ] Results imported to Faraday
- [ ] Tickets created (if findings exist)
- [ ] Alerts sent (if configured)
- [ ] HTML report generated
- [ ] All logs created without errors
- [ ] Faraday API responding correctly
- [ ] CLI tools working as expected

## Monitoring & Maintenance

### Daily Checks
- [ ] No error messages in logs
- [ ] Faraday service is running
- [ ] Scheduled scans completed
- [ ] Critical alerts reviewed

### Weekly Checks
- [ ] API key working properly
- [ ] Webhook endpoints responding
- [ ] Alert channels operational
- [ ] Report quality assessed

### Monthly Checks
- [ ] Update Python dependencies: `pip list --outdated`
- [ ] Review Faraday logs for issues
- [ ] Verify backup integrity
- [ ] Test recovery procedures
- [ ] Update security rules

## Troubleshooting Quick Reference

| Issue | Solution |
|-------|----------|
| Faraday won't start | Check Docker: `docker ps`, `docker logs` |
| API key invalid | Regenerate in Faraday WebUI |
| Nmap permission denied | Run with `sudo` or setcap |
| No findings imported | Check network connectivity |
| Alerts not sending | Verify webhook URL and format |
| Report generation fails | Ensure workspace has findings |
| GitHub Actions failing | Check secrets are configured |

## Rollback Plan

If deployment needs to be rolled back:

```bash
# Stop Faraday
docker-compose down

# Remove database (will reset Faraday)
docker volume rm vapt-automation-faraday_postgres_volume

# Restore from backup (if available)
# docker run -v /backup:/backup -v db:/var/lib/postgresql/data \
#   postgres:13 sh -c 'pg_restore /backup/faraday.dump > /var/lib/postgresql/data/restore.log'

# Restart if needed
docker-compose up -d
```

## Success Criteria

✅ **Deployment is successful when:**

- [ ] Faraday is running and accessible
- [ ] API authentication works
- [ ] First scan completes without errors
- [ ] Findings are imported to Faraday
- [ ] Tickets are created for High/Critical findings
- [ ] Alerts are sent (if configured)
- [ ] HTML report is generated
- [ ] All logs are clean
- [ ] CLI tools work properly
- [ ] GitHub Actions tests pass (if enabled)

## Sign-Off

- **Deployed By**: ___________________
- **Date**: ___________________
- **Status**: [ ] Successful [ ] Failed [ ] Needs Review
- **Notes**: ___________________________________________________

---

**For issues, refer to README.md, QUICKSTART.md, or ARCHITECTURE.md**
