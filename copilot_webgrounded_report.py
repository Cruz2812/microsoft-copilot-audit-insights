"""Process Copilot audit logs to find blocked domains and XPIA hits."""
import os
import json
from urllib.parse import urlparse
from collections import Counter
from datetime import datetime

import pandas as pd
from openpyxl import load_workbook

OUTPUT_DIR = r"<output_path>"
os.makedirs(OUTPUT_DIR, exist_ok=True)

blocklist_path = os.path.join(OUTPUT_DIR, "BlockList.csv")
auditlog_path = os.path.join(OUTPUT_DIR, "auditlogs.csv")
excluded_domains = {
    "outlook.office365.com",
    "outlook.office.com",
    "teams.microsoft.com",
    "www.office.com",
}

timestamp_suffix = "_" + datetime.now().strftime("%m%Y")

blocklist_df = pd.read_csv(blocklist_path)
blocked_domains = set(blocklist_df.iloc[:, 0].dropna().str.lower())

webgrounded_blocked_rows = []
webgrounded_blocked_counter = Counter()
xpia_rows_data = []

for chunk in pd.read_csv(auditlog_path, chunksize=5000):
    audit_data_column = chunk.iloc[:, 5].dropna()
    for index, audit_json_str in audit_data_column.items():
        try:
            audit_json = json.loads(audit_json_str)
        except Exception:
            continue
        creation_time = audit_json.get("CreationTime")
        resources = audit_json.get("CopilotEventData", {}).get("AccessedResources", [])
        for resource in resources:
            site_url = resource.get("SiteUrl")
            xpia_detected = resource.get("XPIADetected", False)
            action = resource.get("Action")
            resource_type = resource.get("Type")
            if site_url:
                domain = urlparse(site_url).netloc.lower()
                row_data = chunk.loc[index].to_dict()
                row_data["MatchedDomain"] = domain
                row_data["CreationTime"] = creation_time
                row_data["Site URL"] = site_url

                if domain not in excluded_domains and domain in blocked_domains:
                    webgrounded_blocked_rows.append(row_data)
                    webgrounded_blocked_counter[domain] += 1

                if xpia_detected:
                    row_data["XPIADetected"] = True
                    row_data["Action"] = action
                    row_data["Type"] = resource_type
                    xpia_rows_data.append(row_data)

webgrounded_df = pd.DataFrame(webgrounded_blocked_rows)[
    ["MatchedDomain", "CreationTime", "UserId", "RecordId", "AuditData", "Site URL"]
]
webgrounded_blocked_df = (
    pd.DataFrame(webgrounded_blocked_counter.items(), columns=["Domain", "Count"])
    .sort_values(by="Count", ascending=False)
)

xpia_df = pd.DataFrame(xpia_rows_data)[
    ["MatchedDomain", "XPIADetected", "Action", "Type", "CreationTime", "UserId", "RecordId", "AuditData", "Site URL"]
]

webgrounded_excel = os.path.join(OUTPUT_DIR, f"Copilot_WebGrounded_Summary{timestamp_suffix}.xlsx")
with pd.ExcelWriter(webgrounded_excel, engine="openpyxl") as writer:
    webgrounded_blocked_df.to_excel(writer, sheet_name="Identified Blocked Domains", index=False)
    webgrounded_df.to_excel(writer, sheet_name="Matched Data", index=False)

wb = load_workbook(webgrounded_excel)
ws_blocked = wb["Identified Blocked Domains"]
ws_blocked.column_dimensions["A"].width = 25

ws_matched = wb["Matched Data"]
for col, width in zip("ABCDEF", [25, 25, 42, 40, 25, 80]):
    ws_matched.column_dimensions[col].width = width

wb.save(webgrounded_excel)

xpia_excel = os.path.join(OUTPUT_DIR, f"Copilot_XPIA_Summary{timestamp_suffix}.xlsx")
with pd.ExcelWriter(xpia_excel, engine="openpyxl") as writer:
    xpia_df.to_excel(writer, sheet_name="Matched Data", index=False)
