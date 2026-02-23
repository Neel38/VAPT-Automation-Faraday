# Technical Architecture & Design Document

## Project Overview

The VAPT Automation Pipeline is a modular, extensible system for automated vulnerability assessment and penetration testing. It integrates with Faraday for centralized vulnerability management and provides multi-channel alerting, ticket management, and professional compliance reporting.

## System Architecture

### High-Level Data Flow

```
Scan Tools Input
    ↓
[Phase 1] Scan Automation & Auto-Import
    ├─ scan_scheduler.py    (Nmap execution)
    ├─ report_parser.py     (Multi-tool parsing)
    └─ Faraday API         (Auto-import)
    ↓
[Phase 2] Severity-Based Alerting & Ticketing
    ├─ alert_engine.py      (Multi-channel alerts)
    ├─ ticket_manager.py    (Ticket lifecycle)
    └─ Faraday API         (Finding polling)
    ↓
[Phase 3] DAST Scanning (Optional)
    └─ OWASP ZAP Integration (Coming soon)
    ↓
[Phase 4] Compliance Reporting
    ├─ report_generator.py  (HTML generation)
    ├─ Jinja2 Templates    (Professional formatting)
    └─ Compliance Mapping  (OWASP/CIS)
    ↓
Professional Reports & Intelligence
```

## Component Details

### Phase 1: Scan Automation & Auto-Import

#### `scan_scheduler.py`

**Purpose**: Execute Nmap scans and auto-import to Faraday

**Key Features**:
- Multiple scan profiles (quick, full, vuln)
- Timestamp-based result organization
- SHA256 deduplication hashing
- Structured logging
- Faraday API integration

**Workflow**:
```
Target Input
    ↓
Validate Profile
    ↓
Execute Nmap
    ↓
Save XML (timestamped)
    ↓
Parse XML locally
    ↓
Load existing findings from Faraday
    ↓
Deduplication check (CVE + Host + Port)
    ↓
Import to Faraday REST API
    ↓
Generate summary report
```

**Deduplication Logic**:
```python
hash_key = SHA256(f"{host}:{port}:{cve}")
if hash_key not in existing_findings:
    # New finding - import
else:
    # Duplicate - skip
```

#### `report_parser.py`

**Purpose**: Parse multi-tool scan reports

**Supported Formats**:
- Nessus (.nessus XML)
- OpenVAS (XML)
- Burp Suite (XML)

**Workflow**:
```
Report File
    ↓
Auto-detect tool type
    ↓
Parse tool-specific XML structure
    ↓
Normalize severity (0-10 → critical/high/medium/low/info)
    ↓
Extract: host, port, CVE, CVSS, description
    ↓
Push to Faraday API (/api/v3/workspaces/{ws}/vulns)
    ↓
Return: pushed/failed counts
```

**Severity Normalization**:
- CVSS 9.0-10.0 → Critical
- CVSS 7.0-8.9 → High
- CVSS 5.0-6.9 → Medium
- CVSS 3.0-4.9 → Low
- CVSS 0-2.9 → Info

### Phase 2: Severity-Based Alerting & Ticketing

#### `alert_engine.py`

**Purpose**: Monitor Faraday and send intelligent alerts

**Alert Channels**:
- **Slack**: Rich formatted messages with color coding
- **Email**: SMTP with HTML formatting
- **Webhooks**: Generic HTTP POST for external integrations

**Workflow**:
```
Poll Faraday API (configurable interval)
    ↓
Get all findings since last check
    ↓
Filter by severity threshold (configurable)
    ↓
Check if finding already processed (memory + JSON file)
    ↓
For each new finding:
    ├─ Format alert message
    └─ Send to enabled channels
    ↓
Save processed finding IDs
```

**Severity Filtering**:
```
Threshold: "high"
→ Alert on: Critical, High
→ Ignore: Medium, Low, Info

Threshold: "medium"
→ Alert on: Critical, High, Medium
→ Ignore: Low, Info
```

#### `ticket_manager.py`

**Purpose**: Manage ticket lifecycle for findings

**Ticket Status Flow**:
```
FINDING (from Faraday)
    ↓
CREATE TICKET (severity ≥ High)
    ├─ Status: "open"
    ├─ Priority: Based on CVSS
    └─ Created_at: timestamp
    ↓
ACKNOWLEDGE (when triaged)
    ├─ Status: "acknowledged"
    ├─ Assigned_to: team member
    └─ Acknowledged_at: timestamp
    ↓
RESOLVE (when fixed)
    ├─ Status: "resolved"
    ├─ Resolution_notes: What was done
    └─ Resolved_at: timestamp
```

**Priority Calculation**:
```python
if cvss_score >= 9.0:
    priority = "P0"  # Critical
elif cvss_score >= 7.0:
    priority = "P1"  # High
elif cvss_score >= 5.0:
    priority = "P2"  # Medium
else:
    priority = "P3"  # Low
```

**Ticket JSON Structure**:
```json
{
  "ticket_id": "TICKET-001",
  "vuln_name": "Vulnerability Name",
  "cve": "CVE-XXXX-XXXXX",
  "host": "192.168.1.100",
  "port": "443",
  "severity": "critical",
  "cvss": 9.8,
  "priority": "P0",
  "status": "open|acknowledged|resolved",
  "description": "...",
  "created_at": "2025-02-18T10:30:00",
  "acknowledged_at": null,
  "resolved_at": null,
  "resolution_notes": null,
  "assigned_to": null
}
```

### Phase 3: DAST Scanning

**Status**: Framework in place, integration pending

**Planned Features**:
- OWASP ZAP baseline scanning
- Auto-parse ZAP XML output
- Import web findings to separate workspace
- Differentiate DAST from network findings

### Phase 4: Compliance Reporting

#### `report_generator.py`

**Purpose**: Generate professional HTML compliance reports

**Workflow**:
```
Query Faraday API
    ↓
Fetch all findings for workspace
    ↓
Categorize by severity
    ↓
Build compliance mapping:
    - Map findings to OWASP Top 10
    - Map findings to CIS Controls
    ↓
Sort by CVSS score (for remediation priority)
    ↓
Render Jinja2 template with data
    ↓
Generate HTML report
```

**Report Sections**:
1. **Cover Page**: Title, workspace, date
2. **Executive Summary**: 
   - Finding counts by severity
   - Key findings highlighted
3. **Detailed Findings**: 
   - Critical/High: Detailed write-ups
   - Medium/Low: Table format
4. **Compliance Mapping**: 
   - Control-to-finding cross-reference
5. **Remediation Priority**: 
   - Top 20 by CVSS score
   - Action items
6. **Footer**: Generated timestamp

**Compliance Mapping Examples**:
```
Finding: "SQL Injection"
  → OWASP: A03: Injection
  → CIS: CIS 7: Vulnerability Management

Finding: "Weak Authentication"
  → OWASP: A07: Identification and Authentication Failures
  → CIS: CIS 6: Access Control Management
```

#### `templates/report_template.html`

**Features**:
- Professional CSS styling
- Color-coded severity levels
- Responsive design (mobile-friendly)
- Print-friendly formatting
- Jinja2 template variables
- Executive summary dashboard

### Master Orchestrator: `pipeline.py`

**Purpose**: Coordinate all phases

**Execution Flow**:
```
Parse CLI arguments
    ↓
Validate environment (tools, credentials)
    ↓
Phase 1: Execute scan_scheduler.py
    ↓
Phase 2: Execute alert_engine.py + ticket_manager.py
    ↓
Phase 3: Execute DAST (if enabled)
    ↓
Phase 4: Execute report_generator.py
    ↓
Generate execution summary
    ↓
Display results and next steps
```

**Available Phases**:
- `--phases 1,2,4` (skip DAST)
- `--phases 1` (scan only)
- `--phases 2,4` (alerts and reporting)

## API Integrations

### Faraday REST API

**Endpoints Used**:

1. **Import Scan Results**
```
POST /api/v3/workspaces/{workspace}/import_scan
Content-Type: multipart/form-data

file: XML scan file
tool: "Nmap|Nessus|OpenVAS"
```

2. **Query Findings**
```
GET /api/v3/workspaces/{workspace}/vulns
Authorization: Bearer {API_KEY}

Returns: List of vulnerability objects
```

3. **Create/Update Findings**
```
POST /api/v3/workspaces/{workspace}/vulns
Authorization: Bearer {API_KEY}
Content-Type: application/json

{
  "name": "Vulnerability Name",
  "severity": "critical",
  "description": "...",
  "host": "192.168.1.100",
  "port": "443"
}
```

### External Integrations

**Slack Webhook**:
```
POST {webhook_url}
Content-Type: application/json

{
  "attachments": [{
    "color": "#FF0000",
    "title": "🚨 Critical Vulnerability",
    "fields": [...]
  }]
}
```

**Email (SMTP)**:
```
Server: smtp.gmail.com:587
Auth: TLS
From: security@example.com
To: team@example.com
```

**Generic Webhooks**:
```
POST {webhook_url}
Content-Type: application/json

{
  "alert_type": "vulnerability",
  "severity": "critical",
  "host": "192.168.1.100",
  "vulnerability": "...",
  "timestamp": "2025-02-18T10:30:00Z"
}
```

## Configuration Management

### YAML Configuration (`config/settings.yaml`)

```yaml
faraday:
  url: "http://localhost:5985"
  api_key: "${FARADAY_API_KEY}"    # Via environment
  timeout: 30

scan_profiles:
  quick:    # -T4 -F (100 ports)
  full:     # -T4 -A -p- (all ports)
  vuln:     # --script vuln

alerts:
  channels:
    slack:
      enabled: true/false
      webhook_url: "${SLACK_WEBHOOK_URL}"
  severity_threshold: "high"

tickets:
  enabled: true
  severity_threshold: "high"
  priority_mapping:
    critical: "P0"
    high: "P1"
    # ...

reporting:
  compliance_framework: "owasp"    # or "cis"
```

### Environment Variables

```bash
FARADAY_API_KEY           # Required
SLACK_WEBHOOK_URL         # Optional
EMAIL_SMTP_SERVER         # Optional
EMAIL_FROM               # Optional
EMAIL_PASSWORD           # Optional
```

## Security Considerations

### Secrets Management

✅ **DO**:
- Use environment variables for secrets
- Store GitHub Secrets securely
- Rotate API keys regularly
- Use HTTPS for external APIs

❌ **DON'T**:
- Commit API keys to repository
- Hardcode credentials in config files
- Share webhook URLs publicly
- Log sensitive data

### Scanner Ethics

⚠️ **CRITICAL**:
- Only scan systems you own or have written permission
- Never scan production systems without approval
- Document all scanning activities
- Respect network impact (use appropriate timeouts)

## Performance Optimization

### Large Network Scans

**Strategy**: Split into multiple ranges
```bash
python scan_scheduler.py --target 10.0.0.0/16 --profile quick
python scan_scheduler.py --target 10.1.0.0/16 --profile quick
# ... etc
```

### Parallel Execution

```bash
python scan_scheduler.py --target 192.168.1.0/24 --profile quick &
python scan_scheduler.py --target 10.0.0.0/24 --profile quick &
wait
```

### Database Optimization (Future)

- Implement finding cache with SQLite
- Index by CVE + Host + Port
- Historical trend tracking
- False positive ML classifier

## Extensibility

### Adding New Tools

1. **Create parser method**: `_parse_newtool()`
2. **Add to ReportParser class**
3. **Register in auto-detect logic**
4. **Update requirements.txt**

### Adding New Alert Channels

1. **Create `send_channel_alert()` method**
2. **Add configuration in settings.yaml**
3. **Update AlertEngine class**

### Adding Compliance Frameworks

1. **Extend mapping dictionaries**
2. **Add framework parameter**
3. **Create template variants**

## Future Enhancements

- [ ] CVSS v3 auto-enrichment from NVD API
- [ ] Trend dashboard with Flask
- [ ] ML-based false positive detection
- [ ] Jira/ServiceNow integration
- [ ] Multi-workspace aggregation
- [ ] Kubernetes deployment
- [ ] Container image scanning

## Troubleshooting Reference

| Issue | Root Cause | Solution |
|-------|-----------|----------|
| Faraday connection failed | API key invalid | Regenerate API key |
| Nmap permission denied | No sudo access | Setcap or run with sudo |
| Report not generated | No findings | Check workspace has findings |
| Slack alert not sent | Webhook invalid | Verify webhook URL |
| High memory usage | Large workspace | Process findings in batches |

---

**Version**: 1.0.0
**Last Updated**: 2025-02-18
**Maintainers**: Security Team
