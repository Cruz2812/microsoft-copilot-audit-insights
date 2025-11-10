
---

## 🟧 `microsoft-copilot-audit-insights/README.md`

```markdown
# Microsoft Copilot Audit Insights

Python-based analysis of Microsoft 365 audit logs to detect and visualize Copilot “web-grounded” activity, blocked domains, and XPIA (eXternal Plugin Intelligent Access) patterns.

## Overview
This script processes large Copilot audit logs, identifies web-grounded or XPIA activity, compares it against a blocklist, and outputs analytics to Excel and charts.  
It is designed for security and compliance teams to monitor Copilot usage across their tenant.

## Script
- **copilot_webgrounded_audit_analysis.py**

## What It Does
1. Reads audit logs (CSV) and blocklist files.  
2. Parses Copilot event JSON embedded in each audit entry.  
3. Extracts domains, user activity, and detected XPIA resources.  
4. Compares accessed domains to a blocklist.  
5. Creates:
   - Excel summaries for blocked domain matches and XPIA detections
   - Bar chart of top 10 blocked domains

## Example Directory Structure
