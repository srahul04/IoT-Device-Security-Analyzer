import json
import os
import datetime
import uuid
import platform

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
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>IDSA Scan Report - {scan_id}</title>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 20px; }}
                h1 {{ color: #333; }}
                h2 {{ color: #555; border-bottom: 1px solid #ccc; padding-bottom: 5px; margin-top: 20px; }}
                pre {{ background: #f4f4f4; padding: 10px; border: 1px solid #ddd; overflow-x: auto; }}
                .severity-High {{ color: red; font-weight: bold; }}
                .severity-Medium {{ color: orange; font-weight: bold; }}
                .severity-Low {{ color: green; }}
            </style>
        </head>
        <body>
            <h1>IDSA Scan Report - {scan_id}</h1>
            <p><strong>Scan Date:</strong> {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            <h2>Overall Vulnerabilities</h2>
            <ul>
        """
        if "vulnerabilities" in scan_results:
            for vuln in scan_results["vulnerabilities"]:
                html_content += f"<li class=\"severity-{vuln.get('severity', 'Unknown')}\">[{vuln.get('severity', 'Unknown')}] {vuln.get('module', 'N/A')}: {vuln.get('description', 'N/A')}</li>\n"
        else:
            html_content += "<li>No vulnerabilities detected.</li>\n"
        html_content += f"""
            </ul>
            <h2>Full Scan Data</h2>
            <pre>{json.dumps(scan_results, indent=2)}</pre>
        </body>
        </html>
        """
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        return report_path

    def _generate_pdf_report(self, scan_results, report_dir, scan_id):
        # Generating PDF directly in Python without external libraries can be complex.
        # For simplicity, this will save the raw JSON content as a .txt file
        # and instruct the user that a proper PDF requires external tools/libraries
        # or conversion from the HTML report.
        report_path = os.path.join(report_dir, f"report_{scan_id}.pdf") # Still save as .pdf for consistency

        # A real PDF generation would use a library like ReportLab or FPDF
        # For now, we'll create a text file that can be easily converted to PDF
        # or print a message if user expects a real PDF.
        temp_txt_path = os.path.join(report_dir, f"report_{scan_id}_raw.txt")
        with open(temp_txt_path, 'w', encoding='utf-8') as f:
            f.write(f"IDSA Scan Report - {scan_id}\n")
            f.write(f"Scan Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write("--- Overall Vulnerabilities ---\n")
            if "vulnerabilities" in scan_results:
                for vuln in scan_results["vulnerabilities"]:
                    f.write(f"[{vuln.get('severity', 'Unknown')}] {vuln.get('module', 'N/A')}: {vuln.get('description', 'N/A')}\n")
            else:
                f.write("No vulnerabilities detected.\n")
            f.write("\n--- Full Scan Data (JSON) ---\n")
            f.write(json.dumps(scan_results, indent=2))

        # Informative message for PDF generation
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("""
This PDF file contains a placeholder message.

For a full-featured PDF report, you would typically need to install additional Python libraries
like 'ReportLab' or 'fpdf'.

Alternatively, you can open the generated HTML report (report_{scan_id}.html) in a web browser
and use its 'Print to PDF' functionality to create a visually rich PDF.

A raw text version of the report is also available: report_{scan_id}_raw.txt
""")

        return report_path

    def generate_report(self, scan_results, export_formats=("json", "html", "pdf")):
        """Generates and saves scan reports in specified formats."""
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

# Example Usage:
if __name__ == "__main__":
    # Dummy scan results for demonstration
    dummy_scan_results = {
        "timestamp": datetime.datetime.now().isoformat(),
        "system_info": {"os": "Linux", "hostname": "test-host"},
        "usb_devices": [{"Description": "USB Disk", "DeviceID": "1234"}],
        "network_scan": {"local_ip": "192.168.1.100", "active_hosts": ["192.168.1.1", "192.168.1.5"]},
        "cve_lookup": [{"cve_id": "CVE-2023-1234", "severity": "High", "description": "Web Server X vuln"}],
        "config_issues": [{"severity": "Medium", "description": "Weak password detected"}],
        "vulnerabilities": [
            {"severity": "High", "module": "System Info", "description": "Outdated kernel"},
            {"severity": "Medium", "module": "Network Scan", "description": "Open SMB port"}
        ]
    }

    reporter = ReportGenerator()
    report_info = reporter.generate_report(dummy_scan_results, export_formats=("json", "html", "pdf"))
    print(f"Report generated for Scan ID: {report_info['scan_id']}")
    print(f"Report directory: {report_info['report_dir']}")
    for f in report_info['files']:
        print(f"  - {f}")

    # To test loading reports from the directory
    print("\n--- Listing generated reports ---")
    if os.path.exists(REPORT_BASE_DIR):
        for scan_folder in os.listdir(REPORT_BASE_DIR):
            print(f"Found report folder: {scan_folder}")
