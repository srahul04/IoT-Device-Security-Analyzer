import json
import os
import datetime
import uuid
import platform

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable

REPORT_BASE_DIR = os.path.join(os.path.dirname(__file__), "..", "IDSA_REPORTS")

class ReportGenerator:
    def __init__(self):
        pass

    def _create_report_directory(self, scan_id):
        report_dir = os.path.join(REPORT_BASE_DIR, scan_id)
        os.makedirs(report_dir, exist_ok=True)
        return report_dir

    def _generate_json_report(self, scan_results, report_dir, scan_id):
        report_path = os.path.join(report_dir, f"report_{scan_id}.json")
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(scan_results, f, indent=4)
        return report_path

    def _generate_html_report(self, scan_results, report_dir, scan_id):
        report_path = os.path.join(report_dir, f"report_{scan_id}.html")
        vulns = scan_results.get("vulnerabilities", [])
        devices = scan_results.get("devices", [])
        
        vuln_rows = ""
        for v in vulns:
            sev = v.get("severity", "Informational")
            mod = v.get("module", "General")
            desc = v.get("description", "No description")
            rec = v.get("recommendation", "Review and remediate according to security best practices.")
            color = "#ef4444" if sev in ("High", "Critical") else "#f59e0b" if sev == "Medium" else "#00d4ff"
            vuln_rows += f"""
            <tr style="border-bottom: 1px solid #222;">
                <td style="padding: 10px; color: {color}; font-weight: bold;">{sev}</td>
                <td style="padding: 10px; color: #aaa;">{mod}</td>
                <td style="padding: 10px; color: #fff;">{desc}</td>
                <td style="padding: 10px; color: #10b981; font-size: 13px;">{rec}</td>
            </tr>
            """

        device_rows = ""
        for d in devices:
            device_rows += f"""
            <tr style="border-bottom: 1px solid #222;">
                <td style="padding: 8px; color: #00d4ff; font-family: monospace;">{d.get('ip')}</td>
                <td style="padding: 8px; color: #aaa;">{d.get('vendor')}</td>
                <td style="padding: 8px; color: #fff;">{', '.join(map(str, d.get('open_ports', [])))}</td>
                <td style="padding: 8px; color: #f59e0b;">{d.get('risk_score')}</td>
                <td style="padding: 8px; color: #ef4444; font-size: 12px;">{', '.join(d.get('cves', []))}</td>
            </tr>
            """

        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>IDSA Security Audit Report - {scan_id}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0b0f19; color: #e2e8f0; margin: 0; padding: 30px; }}
        .container {{ max-width: 1000px; margin: auto; background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 30px; }}
        h1, h2, h3 {{ color: #00d4ff; }}
        .header {{ border-bottom: 1px solid #374151; padding-bottom: 15px; margin-bottom: 25px; }}
        .meta {{ font-size: 13px; color: #9ca3af; font-family: monospace; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 14px; }}
        th {{ background: #1f2937; color: #93c5fd; text-align: left; padding: 10px; }}
        .badge {{ display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>IoT Device Security Analyzer (IDSA)</h1>
            <p style="margin: 0; color: #38bdf8; font-weight: 600;">System & Network Security Audit Report</p>
            <p class="meta">Scan ID: {scan_id} | Date: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | Author: Rahul S</p>
        </div>

        <h2>Discovered Network Devices ({len(devices)})</h2>
        <table>
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Vendor</th>
                    <th>Open Ports</th>
                    <th>Risk</th>
                    <th>Associated CVEs</th>
                </tr>
            </thead>
            <tbody>
                {device_rows if device_rows else '<tr><td colspan="5" style="padding:10px;">No devices detected</td></tr>'}
            </tbody>
        </table>

        <h2 style="margin-top: 40px;">Identified Vulnerabilities & Recommendations ({len(vulns)})</h2>
        <table>
            <thead>
                <tr>
                    <th style="width: 12%;">Severity</th>
                    <th style="width: 18%;">Module</th>
                    <th style="width: 35%;">Finding</th>
                    <th style="width: 35%;">Security Recommendation</th>
                </tr>
            </thead>
            <tbody>
                {vuln_rows if vuln_rows else '<tr><td colspan="4" style="padding:10px;">No critical vulnerabilities detected</td></tr>'}
            </tbody>
        </table>

        <div style="margin-top: 40px; font-size: 12px; color: #6b7280; border-top: 1px solid #1f2937; padding-top: 15px;">
            Confidential Security Assessment Document &bull; Generated by IDSA Portable Security Suite (Author: Rahul S)
        </div>
    </div>
</body>
</html>"""
        with open(report_path, 'w', encoding='utf-8') as f:
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
        title_style = ParagraphStyle(
            'TitleStyle',
            parent=styles['Heading1'],
            fontSize=18,
            leading=22,
            textColor=colors.HexColor('#0f172a')
        )
        subtitle_style = ParagraphStyle(
            'SubtitleStyle',
            parent=styles['Normal'],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor('#475569')
        )
        h2_style = ParagraphStyle(
            'H2Style',
            parent=styles['Heading2'],
            fontSize=13,
            leading=16,
            textColor=colors.HexColor('#1e293b'),
            spaceBefore=12,
            spaceAfter=6
        )
        cell_style = ParagraphStyle(
            'CellStyle',
            parent=styles['Normal'],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor('#334155')
        )
        cell_bold = ParagraphStyle(
            'CellBold',
            parent=cell_style,
            fontName='Helvetica-Bold'
        )
        rec_style = ParagraphStyle(
            'RecStyle',
            parent=cell_style,
            textColor=colors.HexColor('#047857')
        )

        elements = []
        
        # Header
        elements.append(Paragraph("IoT Device Security Analyzer (IDSA)", title_style))
        elements.append(Paragraph(f"Comprehensive Security Assessment Report &bull; Author: Rahul S", subtitle_style))
        elements.append(Paragraph(f"Scan ID: {scan_id} &bull; Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", subtitle_style))
        elements.append(Spacer(1, 10))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=12))

        # Discovered Devices Table
        devices = scan_results.get("devices", [])
        elements.append(Paragraph(f"1. Discovered Devices ({len(devices)})", h2_style))
        
        dev_data = [[
            Paragraph("IP Address", cell_bold),
            Paragraph("Vendor / MAC", cell_bold),
            Paragraph("Ports", cell_bold),
            Paragraph("Risk", cell_bold),
            Paragraph("CVEs", cell_bold)
        ]]
        
        for d in devices:
            dev_data.append([
                Paragraph(str(d.get("ip", "")), cell_style),
                Paragraph(f"{d.get('vendor', '')}<br/>{d.get('mac', '')}", cell_style),
                Paragraph(", ".join(map(str, d.get("open_ports", []))), cell_style),
                Paragraph(str(d.get("risk_score", "")), cell_bold),
                Paragraph("<br/>".join(d.get("cves", [])) or "None", cell_style)
            ])
            
        if len(dev_data) == 1:
            dev_data.append([Paragraph("No active devices found", cell_style), "", "", "", ""])

        t_dev = Table(dev_data, colWidths=[1.1*inch, 1.8*inch, 1.0*inch, 0.9*inch, 2.2*inch])
        t_dev.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f5f9')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]))
        elements.append(t_dev)
        elements.append(Spacer(1, 14))

        # Vulnerabilities and Recommendations
        vulns = scan_results.get("vulnerabilities", [])
        elements.append(Paragraph(f"2. Security Findings & Remediation Recommendations ({len(vulns)})", h2_style))
        
        vuln_data = [[
            Paragraph("Sev", cell_bold),
            Paragraph("Module", cell_bold),
            Paragraph("Finding Description", cell_bold),
            Paragraph("Remediation / Recommendation", cell_bold)
        ]]

        for v in vulns:
            sev = v.get("severity", "Informational")
            mod = v.get("module", "Security Scanner")
            desc = v.get("description", "")
            rec = v.get("recommendation", "Apply latest security patches and disable unnecessary services.")
            
            sev_color = colors.HexColor('#dc2626') if sev in ("High", "Critical") else colors.HexColor('#d97706') if sev == "Medium" else colors.HexColor('#2563eb')
            sev_p = Paragraph(f"<font color='{sev_color}'><b>{sev}</b></font>", cell_style)

            vuln_data.append([
                sev_p,
                Paragraph(mod, cell_style),
                Paragraph(desc, cell_style),
                Paragraph(rec, rec_style)
            ])

        if len(vuln_data) == 1:
            vuln_data.append([Paragraph("No vulnerabilities recorded", cell_style), "", "", ""])

        t_vuln = Table(vuln_data, colWidths=[0.8*inch, 1.3*inch, 2.5*inch, 2.4*inch])
        t_vuln.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f5f9')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]))
        elements.append(t_vuln)

        # Build genuine binary PDF document
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
