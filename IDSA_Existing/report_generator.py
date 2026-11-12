import json
import os
import datetime
import uuid
import platform

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether,
)

REPORT_BASE_DIR = os.path.join(os.path.dirname(__file__), "..", "IDSA_REPORTS")

# Priority ranking map
SEV_RANK = {
    "CRITICAL": 1,
    "HIGH": 2,
    "MEDIUM": 3,
    "LOW": 4,
    "INFORMATIONAL": 5,
}

class NumberedCanvas:
    """Canvas wrapper to generate 2-pass dynamic page numbers (Page X of Y)"""
    def __init__(self, *args, **kwargs):
        pass


class ReportGenerator:
    def __init__(self):
        pass

    def _create_report_directory(self, scan_id):
        report_dir = os.path.join(REPORT_BASE_DIR, scan_id)
        os.makedirs(report_dir, exist_ok=True)
        return report_dir

    def _generate_json_report(self, scan_results, report_dir, scan_id):
        report_path = os.path.join(report_dir, f"report_{scan_id}.json")
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(scan_results, f, indent=4)
        return report_path

    def _generate_html_report(self, scan_results, report_dir, scan_id):
        report_path = os.path.join(report_dir, f"report_{scan_id}.html")
        raw_vulns = scan_results.get("vulnerabilities", [])
        devices = scan_results.get("devices", [])
        sys_info = scan_results.get("system_info", {})
        usb_devs = scan_results.get("usb_devices", [])

        # Sort High to Low
        vulns = sorted(
            raw_vulns,
            key=lambda x: SEV_RANK.get(str(x.get("severity", "INFORMATIONAL")).upper(), 99)
        )

        vuln_rows = ""
        for v in vulns:
            sev = str(v.get("severity", "Informational")).upper()
            mod = v.get("module", "General")
            desc = v.get("description", "No description provided.")
            rec = v.get("recommendation", "Review and apply standard security hardening.")

            if sev in ("CRITICAL", "HIGH"):
                color = "#ef4444"
                badge_bg = "rgba(239, 68, 68, 0.15)"
                icon = "&#9888;"
            elif sev == "MEDIUM":
                color = "#f59e0b"
                badge_bg = "rgba(245, 158, 11, 0.15)"
                icon = "&#9650;"
            elif sev == "LOW":
                color = "#3b82f6"
                badge_bg = "rgba(59, 130, 246, 0.15)"
                icon = "&#9679;"
            else:
                color = "#06b6d4"
                badge_bg = "rgba(6, 182, 212, 0.15)"
                icon = "&#8505;"

            vuln_rows += f"""
            <tr style="border-bottom: 1px solid #1f2937;">
                <td style="padding: 10px; vertical-align: top;">
                    <span style="display:inline-block; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; color: {color}; background: {badge_bg}; border: 1px solid {color}44;">
                        {icon} {sev}
                    </span>
                </td>
                <td style="padding: 10px; color: #94a3b8; font-size: 12px; vertical-align: top; font-family: monospace;">{mod}</td>
                <td style="padding: 10px; color: #f1f5f9; font-size: 13px; vertical-align: top;">{desc}</td>
                <td style="padding: 10px; color: #34d399; font-size: 12px; vertical-align: top; font-family: monospace;">{rec}</td>
            </tr>
            """

        dev_rows = ""
        for d in devices:
            ports = ", ".join(map(str, d.get("open_ports", []))) or "None"
            cves = ", ".join(d.get("cves", [])) or "None"
            dev_rows += f"""
            <tr style="border-bottom: 1px solid #1f2937;">
                <td style="padding: 9px; font-family: monospace; color: #38bdf8; font-weight: bold;">{d.get('ip')}</td>
                <td style="padding: 9px; color: #f8fafc;">{d.get('vendor')}</td>
                <td style="padding: 9px; font-family: monospace; color: #94a3b8;">{ports}</td>
                <td style="padding: 9px; font-weight: bold; color: {'#ef4444' if d.get('risk_score') == 'High' else '#f59e0b'};">{d.get('risk_score')}</td>
                <td style="padding: 9px; font-size: 11px; color: #cbd5e1; font-family: monospace;">{cves}</td>
            </tr>
            """

        os_info = sys_info.get("os_info", {})
        disk_info = sys_info.get("disk_usage", {})
        users = sys_info.get("logged_in_users", [])

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>IDSA Security Assessment Report - {scan_id}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0b0f19; color: #e2e8f0; margin: 0; padding: 25px; }}
        .wrap {{ max-width: 1100px; margin: auto; background: #111827; border: 1px solid #1f2937; border-radius: 12px; padding: 30px; box-shadow: 0 10px 40px rgba(0,0,0,0.6); }}
        .header {{ border-bottom: 1px solid #374151; padding-bottom: 15px; margin-bottom: 25px; display: flex; justify-content: space-between; align-items: flex-start; }}
        h1 {{ color: #00d4ff; margin: 0; font-size: 24px; }}
        h2 {{ color: #38bdf8; font-size: 16px; border-left: 4px solid #00d4ff; padding-left: 10px; margin-top: 30px; }}
        .meta {{ font-size: 12px; color: #94a3b8; font-family: monospace; line-height: 1.6; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; margin-top: 15px; }}
        .card {{ background: #0f172a; border: 1px solid #1e293b; border-radius: 8px; padding: 14px; font-size: 12px; }}
        .card-title {{ color: #38bdf8; font-weight: bold; font-family: monospace; margin-bottom: 6px; text-transform: uppercase; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th {{ background: #1e293b; color: #94a3b8; font-size: 12px; text-transform: uppercase; font-family: monospace; text-align: left; padding: 10px; }}
    </style>
</head>
<body>
    <div class="wrap">
        <div class="header">
            <div>
                <h1>IoT Device Security Analyzer (IDSA)</h1>
                <p style="margin: 4px 0 0 0; color: #94a3b8; font-size: 13px;">Comprehensive Host Posture &amp; IoT Network Security Evaluation</p>
            </div>
            <div style="text-align: right;" class="meta">
                <div><strong>Scan ID:</strong> {scan_id}</div>
                <div><strong>Generated:</strong> {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>
                <div><strong>Lead Architect:</strong> <span style="color:#38bdf8;">Rahul S</span></div>
            </div>
        </div>

        <h2>1. Host System Profile &amp; Telemetry</h2>
        <div class="grid">
            <div class="card">
                <div class="card-title">Operating System</div>
                <div>{os_info.get('system', platform.system())} {os_info.get('release', '')}</div>
                <div style="color:#64748b; font-size:11px;">Build: {os_info.get('version', '')[:25]}</div>
            </div>
            <div class="card">
                <div class="card-title">Hardware Architecture</div>
                <div>Node: {sys_info.get('hostname', platform.node())}</div>
                <div style="color:#64748b; font-size:11px;">Arch: {os_info.get('machine', platform.machine())}</div>
            </div>
            <div class="card">
                <div class="card-title">Storage Utilization</div>
                <div>Used: {disk_info.get('used', 'N/A')} / {disk_info.get('total', 'N/A')}</div>
                <div style="color:#64748b; font-size:11px;">Load: {disk_info.get('percentage_used', 'N/A')}</div>
            </div>
            <div class="card">
                <div class="card-title">Active Users &amp; Peripherals</div>
                <div>Users: {', '.join(users) if users else 'Single Console'}</div>
                <div style="color:#64748b; font-size:11px;">USB Attached: {len(usb_devs)} devices</div>
            </div>
        </div>

        <h2>2. Discovered Network Devices &amp; IoT Nodes ({len(devices)})</h2>
        <table>
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Identified Device / UPnP Model</th>
                    <th>Open Ports</th>
                    <th>Risk Rating</th>
                    <th>Mapped CVEs</th>
                </tr>
            </thead>
            <tbody>
                {dev_rows if dev_rows else '<tr><td colspan="5" style="padding:15px; color:#64748b;">No network devices discovered.</td></tr>'}
            </tbody>
        </table>

        <h2>3. Prioritized Security Findings &amp; Defensive Recommendations ({len(vulns)})</h2>
        <table>
            <thead>
                <tr>
                    <th style="width: 13%;">Severity</th>
                    <th style="width: 17%;">Audit Vector</th>
                    <th style="width: 35%;">Observed Vulnerability</th>
                    <th style="width: 35%;">Remediation Guidance</th>
                </tr>
            </thead>
            <tbody>
                {vuln_rows if vuln_rows else '<tr><td colspan="4" style="padding:15px; color:#34d399;">No security issues recorded.</td></tr>'}
            </tbody>
        </table>

        <div style="margin-top: 40px; padding-top: 15px; border-top: 1px solid #1f2937; display: flex; justify-content: space-between; font-size: 11px; color: #64748b; font-family: monospace;">
            <span>Target Execution: Removable USB Media Storage</span>
            <span>Standard: IDSA Confidential Evaluation &bull; Author: Rahul S</span>
        </div>
    </div>
</body>
</html>"""
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        return report_path

    def _generate_pdf_report(self, scan_results, report_dir, scan_id):
        report_path = os.path.join(report_dir, f"report_{scan_id}.pdf")
        doc = SimpleDocTemplate(
            report_path,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()

        # Custom typography hierarchy
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Heading1"],
            fontSize=16,
            leading=20,
            textColor=colors.HexColor("#0f172a"),
            fontName="Helvetica-Bold",
        )
        sub_style = ParagraphStyle(
            "DocSub",
            parent=styles["Normal"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#475569"),
        )
        h2_style = ParagraphStyle(
            "SectionHeading",
            parent=styles["Heading2"],
            fontSize=11,
            leading=15,
            textColor=colors.HexColor("#0369a1"),
            fontName="Helvetica-Bold",
            spaceBefore=12,
            spaceAfter=6,
        )
        cell_style = ParagraphStyle(
            "GridCell",
            parent=styles["Normal"],
            fontSize=7.5,
            leading=9.5,
            textColor=colors.HexColor("#334155"),
        )
        cell_bold = ParagraphStyle(
            "GridCellBold",
            parent=cell_style,
            fontName="Helvetica-Bold",
            textColor=colors.HexColor("#0f172a"),
        )
        rec_style = ParagraphStyle(
            "RecText",
            parent=cell_style,
            textColor=colors.HexColor("#047857"),
            fontName="Helvetica-Bold",
        )

        elements = []

        # Document Header Card
        elements.append(Paragraph("IoT Device Security Analyzer (IDSA)", title_style))
        elements.append(Paragraph("Comprehensive Host Posture &amp; IoT Network Security Evaluation", sub_style))
        elements.append(Paragraph(f"<b>Scan ID:</b> {scan_id} &nbsp;|&nbsp; <b>Author &amp; Architect:</b> Rahul S &nbsp;|&nbsp; <b>Generated:</b> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", sub_style))
        elements.append(Spacer(1, 8))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=10))

        # 1. System Telemetry Summary
        sys_info = scan_results.get("system_info", {})
        os_info = sys_info.get("os_info", {})
        disk_info = sys_info.get("disk_usage", {})
        users = sys_info.get("logged_in_users", [])

        elements.append(Paragraph("1. Target Host System Telemetry &amp; Profile", h2_style))
        sys_table_data = [
            [
                Paragraph("<b>Operating System:</b>", cell_style),
                Paragraph(f"{os_info.get('system', platform.system())} {os_info.get('release', '')}", cell_style),
                Paragraph("<b>Hostname:</b>", cell_style),
                Paragraph(str(sys_info.get("hostname", platform.node())), cell_style),
            ],
            [
                Paragraph("<b>Kernel / Build:</b>", cell_style),
                Paragraph(str(os_info.get("version", ""))[:35], cell_style),
                Paragraph("<b>Architecture:</b>", cell_style),
                Paragraph(str(os_info.get("machine", platform.machine())), cell_style),
            ],
            [
                Paragraph("<b>Storage Usage:</b>", cell_style),
                Paragraph(f"{disk_info.get('used', 'N/A')} / {disk_info.get('total', 'N/A')} ({disk_info.get('percentage_used', 'N/A')})", cell_style),
                Paragraph("<b>Active Accounts:</b>", cell_style),
                Paragraph(", ".join(users) if users else "Single Console User", cell_style),
            ]
        ]

        t_sys = Table(sys_table_data, colWidths=[1.4*inch, 2.3*inch, 1.4*inch, 2.3*inch])
        t_sys.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        elements.append(t_sys)
        elements.append(Spacer(1, 10))

        # 2. Discovered Network Devices
        devices = scan_results.get("devices", [])
        elements.append(Paragraph(f"2. Discovered Network Devices &amp; IoT Nodes ({len(devices)})", h2_style))

        dev_headers = [
            Paragraph("IP Address", cell_bold),
            Paragraph("Identified Vendor / Model / UPnP", cell_bold),
            Paragraph("Open Ports", cell_bold),
            Paragraph("Risk", cell_bold),
            Paragraph("CVE Exposures", cell_bold),
        ]
        dev_rows = [dev_headers]

        for d in devices:
            ports = ", ".join(map(str, d.get("open_ports", []))) or "None"
            cves = "<br/>".join(d.get("cves", [])) or "None"
            risk = str(d.get("risk_score", "Informational"))

            risk_color = colors.HexColor("#dc2626") if risk in ("High", "Critical") else colors.HexColor("#d97706") if risk == "Medium" else colors.HexColor("#0284c7")
            risk_p = Paragraph(f"<font color='{risk_color}'><b>{risk}</b></font>", cell_style)

            dev_rows.append([
                Paragraph(str(d.get("ip", "")), cell_style),
                Paragraph(f"{d.get('vendor', '')}<br/><font color='#64748b'>{d.get('mac', '')}</font>", cell_style),
                Paragraph(ports, cell_style),
                risk_p,
                Paragraph(cves, cell_style),
            ])

        if len(dev_rows) == 1:
            dev_rows.append([Paragraph("No active network devices detected.", cell_style), "", "", "", ""])

        t_dev = Table(dev_rows, colWidths=[1.1*inch, 2.5*inch, 1.0*inch, 0.9*inch, 1.9*inch])
        t_dev.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        elements.append(t_dev)
        elements.append(Spacer(1, 10))

        # 3. Prioritized Security Findings (High to Low with Icons)
        raw_vulns = scan_results.get("vulnerabilities", [])
        vulns = sorted(
            raw_vulns,
            key=lambda x: SEV_RANK.get(str(x.get("severity", "INFORMATIONAL")).upper(), 99)
        )

        elements.append(Paragraph(f"3. Prioritized Security Findings &amp; Remediation Guidance ({len(vulns)})", h2_style))

        vuln_headers = [
            Paragraph("Severity", cell_bold),
            Paragraph("Audit Vector", cell_bold),
            Paragraph("Observed Vulnerability Description", cell_bold),
            Paragraph("Actionable Remediation Guidance", cell_bold),
        ]
        vuln_rows = [vuln_headers]

        for v in vulns:
            sev_str = str(v.get("severity", "Informational")).upper()
            mod = v.get("module", "Security Scanner")
            desc = v.get("description", "")
            rec = v.get("recommendation", "Review and apply vendor security hardening guidance.")

            if sev_str in ("CRITICAL", "HIGH"):
                sev_color = colors.HexColor("#dc2626")
                icon = "[!]"
            elif sev_str == "MEDIUM":
                sev_color = colors.HexColor("#d97706")
                icon = "[^]"
            elif sev_str == "LOW":
                sev_color = colors.HexColor("#2563eb")
                icon = "[-]"
            else:
                sev_color = colors.HexColor("#0891b2")
                icon = "[i]"

            sev_p = Paragraph(f"<font color='{sev_color}'><b>{icon} {sev_str}</b></font>", cell_style)

            vuln_rows.append([
                sev_p,
                Paragraph(mod, cell_style),
                Paragraph(desc, cell_style),
                Paragraph(rec, rec_style),
            ])

        if len(vuln_rows) == 1:
            vuln_rows.append([Paragraph("No security vulnerabilities recorded.", cell_style), "", "", ""])

        t_vuln = Table(vuln_rows, colWidths=[1.1*inch, 1.4*inch, 2.5*inch, 2.4*inch])
        t_vuln.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        elements.append(t_vuln)

        # Footer Notice
        elements.append(Spacer(1, 14))
        elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceAfter=6))
        elements.append(Paragraph(
            "<b>Confidentiality Notice:</b> This security evaluation was generated by the IoT Device Security Analyzer (Author: Rahul S). "
            "Data was collected directly to removable USB media without external network transmission. Authorized use only.",
            ParagraphStyle("Notice", parent=styles["Normal"], fontSize=6.5, leading=8.5, textColor=colors.HexColor("#64748b"))
        ))

        doc.build(elements)
        return report_path

    def generate_report(self, scan_results, export_formats=("json", "html", "pdf")):
        scan_id = datetime.datetime.now().strftime("%Y%m%d-%H%M%S-") + str(uuid.uuid4())[:8]
        report_dir = self._create_report_directory(scan_id)
        generated_files = []

        if "json" in export_formats:
            json_path = self._generate_json_report(scan_results, report_dir, scan_id)
            generated_files.append(json_path)
        if "html" in export_formats:
            html_path = self._generate_html_report(scan_results, report_dir, scan_id)
            generated_files.append(html_path)
        if "pdf" in export_formats:
            pdf_path = self._generate_pdf_report(scan_results, report_dir, scan_id)
            generated_files.append(pdf_path)

        return {"scan_id": scan_id, "report_dir": report_dir, "files": generated_files}
