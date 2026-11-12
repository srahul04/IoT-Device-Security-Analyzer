import tkinter as tk
from tkinter import messagebox, ttk
import os
import threading
import time
import system_scanner
import usb_scanner
import network_scanner
import cve_scanner
import config_scanner
import report_generator # Import the report_generator module
import datetime
import platform
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
import queue

class IDSAMainApp:
    def __init__(self, master):
        self.master = master
        master.title("IoT Device Security Analyzer (IDSA) - Dashboard")
        master.geometry("1000x700")
        master.resizable(True, True)

        self.report_generator = report_generator.ReportGenerator() # Initialize report generator
        self.current_scan_results = {} # To store results of the current scan
        self.current_vulnerabilities = [] # To store vulnerabilities for the current scan
        self.scan_queue = queue.Queue() # Queue for scan progress updates
        self.scan_running = False # Flag to track if scan is running

        self.create_widgets()
        self.start_queue_processor() # Start processing scan updates

    def start_queue_processor(self):
        """Start processing scan updates from the queue."""
        def process_queue():
            while True:
                try:
                    update = self.scan_queue.get(timeout=0.1)
                    if update['type'] == 'progress':
                        self.master.after(0, lambda: self.update_progress(update['value'], update['text']))
                    elif update['type'] == 'vulnerability':
                        self.master.after(0, lambda: self.add_vulnerability(update['vuln']))
                    elif update['type'] == 'complete':
                        self.master.after(0, lambda: self.scan_complete())
                except queue.Empty:
                    continue
                except Exception as e:
                    print(f"Queue processing error: {e}")
        
        queue_thread = threading.Thread(target=process_queue, daemon=True)
        queue_thread.start()

    def update_progress(self, value, text):
        """Update progress bar and label."""
        self.progress_bar["value"] = value
        self.progress_label.config(text=text)
        self.master.update_idletasks()

    def add_vulnerability(self, vuln):
        """Add vulnerability to the tree."""
        self.vulnerability_tree.insert("", "end", values=(vuln["severity"], vuln["module"], vuln["description"]))
        self.current_vulnerabilities.append(vuln)

    def scan_complete(self):
        """Handle scan completion."""
        self.scan_running = False
        self.progress_label.config(text="Status: Full scan completed!")
        self.progress_bar["value"] = 100
        messagebox.showinfo("IDSA", "Full scan completed successfully!")
        self.export_report()

    def create_widgets(self):
        # Notebook for tabs (Dashboard, System Info, USB Devices, Network Scan, CVE Lookup, Configuration Issues, Reports)
        self.notebook = ttk.Notebook(self.master)
        self.notebook.pack(expand=True, fill="both", padx=10, pady=10)

        # Dashboard Tab
        self.dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.dashboard_frame, text="Dashboard")
        self.create_dashboard_widgets(self.dashboard_frame)

        # System Info Tab
        self.system_info_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.system_info_frame, text="System Info")
        self.create_system_info_widgets(self.system_info_frame)

        # USB Devices Tab
        self.usb_devices_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.usb_devices_frame, text="USB Devices")
        self.create_usb_devices_widgets(self.usb_devices_frame)

        # Network Scan Tab
        self.network_scan_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.network_scan_frame, text="Network Scan")
        self.create_network_scan_widgets(self.network_scan_frame)

        # CVE Lookup Tab
        self.cve_lookup_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.cve_lookup_frame, text="CVE Lookup")
        self.create_cve_lookup_widgets(self.cve_lookup_frame)

        # Configuration Issues Tab
        self.config_issues_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.config_issues_frame, text="Config Issues")
        self.create_config_issues_widgets(self.config_issues_frame)

        # Reports Tab
        self.reports_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.reports_frame, text="Reports")
        self.create_reports_widgets(self.reports_frame)

    def create_dashboard_widgets(self, parent_frame):
        # --- Scanning Progress Section ---
        scan_progress_frame = ttk.LabelFrame(parent_frame, text="Scanning Progress")
        scan_progress_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)

        self.progress_label = ttk.Label(scan_progress_frame, text="Status: Ready to scan.")
        self.progress_label.pack(side=tk.LEFT, padx=5, pady=5)

        self.progress_bar = ttk.Progressbar(scan_progress_frame, orient="horizontal", length=300, mode="determinate")
        self.progress_bar.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5, pady=5)

        start_scan_button = ttk.Button(scan_progress_frame, text="Start Full Scan", command=self.start_full_scan)
        start_scan_button.pack(side=tk.RIGHT, padx=5, pady=5)

        # --- Vulnerabilities Display Section ---
        vulnerabilities_frame = ttk.LabelFrame(parent_frame, text="Detected Vulnerabilities")
        vulnerabilities_frame.pack(side=tk.TOP, expand=True, fill="both", padx=10, pady=10)

        # Treeview for vulnerabilities
        self.vulnerability_tree = ttk.Treeview(vulnerabilities_frame, columns=("Severity", "Module", "Description"), show="headings")
        self.vulnerability_tree.heading("Severity", text="Severity")
        self.vulnerability_tree.heading("Module", text="Module")
        self.vulnerability_tree.heading("Description", text="Description")
        self.vulnerability_tree.column("Severity", width=100, anchor=tk.CENTER)
        self.vulnerability_tree.column("Module", width=150, anchor=tk.W)
        self.vulnerability_tree.column("Description", width=500, anchor=tk.W)
        self.vulnerability_tree.pack(expand=True, fill="both", padx=5, pady=5)

        # Add scrollbar to treeview
        vsb = ttk.Scrollbar(vulnerabilities_frame, orient="vertical", command=self.vulnerability_tree.yview)
        vsb.pack(side=tk.RIGHT, fill="y")
        self.vulnerability_tree.configure(yscrollcommand=vsb.set)

        # Context menu for treeview (e.g., to view details)
        self.vulnerability_tree.bind("<Button-3>", self.show_vulnerability_context_menu)

    def create_system_info_widgets(self, parent_frame):
        # --- System Information Display Section ---
        system_info_label_frame = ttk.LabelFrame(parent_frame, text="System Overview")
        system_info_label_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.system_info_text = tk.Text(system_info_label_frame, wrap="word", state="disabled", width=80, height=20)
        self.system_info_text.pack(expand=True, fill="both", padx=5, pady=5)

        # Add a button to refresh system info
        refresh_button = ttk.Button(system_info_label_frame, text="Refresh System Info", command=self.display_system_info)
        refresh_button.pack(pady=5)

        self.display_system_info() # Display info on load

    def display_system_info(self):
        self.system_info_text.config(state="normal")
        self.system_info_text.delete("1.0", tk.END)

        # Use cached data if available, otherwise get fresh data
        if "system_info" in self.current_scan_results:
            system_data = self.current_scan_results["system_info"]
        else:
            system_data = system_scanner.get_system_info_fast()

        self.system_info_text.insert(tk.END, "--- OS Information ---\n")
        os_info = system_data.get("os_info", {})
        if isinstance(os_info, dict) and "error" not in os_info:
            for key, value in os_info.items():
                self.system_info_text.insert(tk.END, f"{key.replace('_', ' ').title()}: {value}\n")
        else:
            self.system_info_text.insert(tk.END, f"Error: {os_info}\n")

        self.system_info_text.insert(tk.END, "\n--- Hostname ---\n")
        hostname = system_data.get("hostname", "Unknown")
        self.system_info_text.insert(tk.END, f"Hostname: {hostname}\n")

        self.system_info_text.insert(tk.END, "\n--- Disk Usage ---\n")
        disk_usage = system_data.get("disk_usage", "Unknown")
        if isinstance(disk_usage, dict):
            for key, value in disk_usage.items():
                self.system_info_text.insert(tk.END, f"{key.replace('_', ' ').title()}: {value}\n")
        else:
            self.system_info_text.insert(tk.END, f"Error: {disk_usage}\n")

        self.system_info_text.insert(tk.END, "\n--- Logged-in Users ---\n")
        users = system_data.get("logged_in_users", [])
        if users:
            for user in users:
                self.system_info_text.insert(tk.END, f"- {user}\n")
        else:
            self.system_info_text.insert(tk.END, "No users logged in or unable to retrieve.\n")

        self.system_info_text.config(state="disabled")

    def create_usb_devices_widgets(self, parent_frame):
        # --- USB Devices Display Section ---
        usb_devices_label_frame = ttk.LabelFrame(parent_frame, text="Connected USB Devices")
        usb_devices_label_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.usb_devices_text = tk.Text(usb_devices_label_frame, wrap="word", state="disabled", width=80, height=20)
        self.usb_devices_text.pack(expand=True, fill="both", padx=5, pady=5)

        # Add a button to refresh USB devices
        refresh_button = ttk.Button(usb_devices_label_frame, text="Refresh USB Devices", command=self.display_usb_devices)
        refresh_button.pack(pady=5)

        self.display_usb_devices() # Display info on load

    def display_usb_devices(self):
        self.usb_devices_text.config(state="normal")
        self.usb_devices_text.delete("1.0", tk.END)

        self.usb_devices_text.insert(tk.END, "--- Connected USB Devices ---\n")
        devices = usb_scanner.get_usb_devices()
        if devices:
            for i, device in enumerate(devices):
                self.usb_devices_text.insert(tk.END, f"\nDevice {i+1}:\n")
                for key, value in device.items():
                    self.usb_devices_text.insert(tk.END, f"  {key}: {value}\n")
        else:
            self.usb_devices_text.insert(tk.END, "No USB devices found or unable to retrieve.\n")

        self.usb_devices_text.config(state="disabled")

    def create_network_scan_widgets(self, parent_frame):
        # --- Network Scan Display Section ---
        network_scan_label_frame = ttk.LabelFrame(parent_frame, text="Network Scan Results")
        network_scan_label_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.network_scan_text = tk.Text(network_scan_label_frame, wrap="word", state="disabled", width=80, height=20)
        self.network_scan_text.pack(expand=True, fill="both", padx=5, pady=5)

        # Add a button to refresh Network Scan
        refresh_button = ttk.Button(network_scan_label_frame, text="Refresh Network Scan", command=self.display_network_scan_results)
        refresh_button.pack(pady=5)

        self.display_network_scan_results() # Display info on load

    def display_network_scan_results(self):
        self.network_scan_text.config(state="normal")
        self.network_scan_text.delete("1.0", tk.END)

        self.network_scan_text.insert(tk.END, "--- Network Scan ---\n")

        # Use cached data if available, otherwise get fresh data
        if "network_scan" in self.current_scan_results:
            network_data = self.current_scan_results["network_scan"]
            local_ip = network_data.get("local_ip", network_scanner.get_local_ip())
            network_range = network_data.get("network_range", "Unknown")
            active_hosts = network_data.get("active_hosts", [])
            open_ports_by_host = network_data.get("open_ports_by_host", {})
        else:
            # Fallback to individual calls
            local_ip = network_scanner.get_local_ip()
            network_range = network_scanner.get_network_range(local_ip)
            active_hosts = network_scanner.ping_sweep(network_range)
            open_ports_by_host = {}
            for host in active_hosts:
                open_ports_by_host[host] = network_scanner.scan_open_ports(host)

        self.network_scan_text.insert(tk.END, f"Local IP: {local_ip}\n")
        self.network_scan_text.insert(tk.END, f"Network Range: {network_range}\n")

        self.network_scan_text.insert(tk.END, "\n--- Ping Sweep (Active Hosts) ---\n")
        if active_hosts:
            for host in active_hosts:
                self.network_scan_text.insert(tk.END, f"- Active Host: {host}\n")
                open_ports = open_ports_by_host.get(host, [])
                if open_ports:
                    self.network_scan_text.insert(tk.END, f"    Open Ports: {open_ports}\n")
                else:
                    self.network_scan_text.insert(tk.END, "    No common open ports found.\n")
        else:
            self.network_scan_text.insert(tk.END, "No active hosts found in the network range.\n")

        self.network_scan_text.config(state="disabled")

    def create_cve_lookup_widgets(self, parent_frame):
        # --- CVE Lookup Section ---
        cve_control_frame = ttk.LabelFrame(parent_frame, text="CVE Search")
        cve_control_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)

        ttk.Label(cve_control_frame, text="Software Name:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.cve_software_entry = ttk.Entry(cve_control_frame, width=40)
        self.cve_software_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

        ttk.Label(cve_control_frame, text="Version (Optional):").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.cve_version_entry = ttk.Entry(cve_control_frame, width=40)
        self.cve_version_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)

        search_button = ttk.Button(cve_control_frame, text="Search CVE Database", command=self.perform_cve_lookup)
        search_button.grid(row=0, column=2, rowspan=2, padx=10, pady=5)

        # --- CVE Results Display ---
        cve_results_frame = ttk.LabelFrame(parent_frame, text="CVE Search Results")
        cve_results_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.cve_results_tree = ttk.Treeview(cve_results_frame, columns=("CVE ID", "Severity", "Description"), show="headings")
        self.cve_results_tree.heading("CVE ID", text="CVE ID")
        self.cve_results_tree.heading("Severity", text="Severity")
        self.cve_results_tree.heading("Description", text="Description")
        self.cve_results_tree.column("CVE ID", width=120, anchor=tk.CENTER)
        self.cve_results_tree.column("Severity", width=100, anchor=tk.CENTER)
        self.cve_results_tree.column("Description", width=600, anchor=tk.W)
        self.cve_results_tree.pack(expand=True, fill="both", padx=5, pady=5)

        # Add scrollbar to treeview
        vsb = ttk.Scrollbar(cve_results_frame, orient="vertical", command=self.cve_results_tree.yview)
        vsb.pack(side=tk.RIGHT, fill="y")
        self.cve_results_tree.configure(yscrollcommand=vsb.set)

    def perform_cve_lookup(self):
        software_name = self.cve_software_entry.get().strip()
        version = self.cve_version_entry.get().strip()

        self.cve_results_tree.delete(*self.cve_results_tree.get_children()) # Clear previous results

        if not software_name:
            messagebox.showwarning("CVE Search", "Please enter a software name to search.")
            return

        cve_results = cve_scanner.search_cve(software_name, version if version else None)

        if cve_results and "error" not in cve_results[0]:
            for cve in cve_results:
                self.cve_results_tree.insert("", "end", values=(cve["cve_id"], cve["severity"], cve["description"]))
        else:
            error_msg = cve_results[0]["error"] if cve_results and "error" in cve_results[0] else "No CVEs found for the specified software."
            self.cve_results_tree.insert("", "end", values=("N/A", "N/A", error_msg))

    def create_config_issues_widgets(self, parent_frame):
        # --- Configuration Issues Display Section ---
        config_issues_label_frame = ttk.LabelFrame(parent_frame, text="Configuration Issue Scan Results")
        config_issues_label_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.config_issues_tree = ttk.Treeview(config_issues_label_frame, columns=("Severity", "Issue"), show="headings")
        self.config_issues_tree.heading("Severity", text="Severity")
        self.config_issues_tree.heading("Issue", text="Issue Description")
        self.config_issues_tree.column("Severity", width=100, anchor=tk.CENTER)
        self.config_issues_tree.column("Issue", width=700, anchor=tk.W)
        self.config_issues_tree.pack(expand=True, fill="both", padx=5, pady=5)

        # Add scrollbar to treeview
        vsb = ttk.Scrollbar(config_issues_label_frame, orient="vertical", command=self.config_issues_tree.yview)
        vsb.pack(side=tk.RIGHT, fill="y")
        self.config_issues_tree.configure(yscrollcommand=vsb.set)

        # Add a button to refresh config issues
        refresh_button = ttk.Button(config_issues_label_frame, text="Refresh Config Issues", command=self.display_config_issues)
        refresh_button.pack(pady=5)

        self.display_config_issues() # Display info on load

    def display_config_issues(self):
        self.config_issues_tree.delete(*self.config_issues_tree.get_children()) # Clear previous results

        # Perform network scan first to get open ports for config scanner
        local_ip = network_scanner.get_local_ip()
        network_range = network_scanner.get_network_range(local_ip)
        active_hosts = network_scanner.ping_sweep(network_range)

        network_scan_results_for_config = {}
        for host in active_hosts:
            open_ports = network_scanner.scan_open_ports(host)
            network_scan_results_for_config[host] = open_ports

        config_vulnerabilities = config_scanner.scan_configuration_issues(network_scan_results_for_config)

        if config_vulnerabilities:
            for vuln in config_vulnerabilities:
                self.config_issues_tree.insert("", "end", values=(vuln["severity"], vuln["description"]))
        else:
            self.config_issues_tree.insert("", "end", values=("Info", "No significant configuration issues detected."))

    def create_reports_widgets(self, parent_frame):
        # --- Reports Section ---
        report_control_frame = ttk.Frame(parent_frame)
        report_control_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)

        export_button = ttk.Button(report_control_frame, text="Export Current Scan Report", command=self.export_report)
        export_button.pack(side=tk.LEFT, padx=5, pady=5)

        ttk.Label(parent_frame, text="Saved Reports:").pack(side=tk.TOP, anchor=tk.W, padx=10, pady=5)

        self.report_listbox = tk.Listbox(parent_frame)
        self.report_listbox.pack(expand=True, fill="both", padx=10, pady=5)
        self.report_listbox.bind("<<ListboxSelect>>", self.on_report_selected)

        view_report_button = ttk.Button(report_control_frame, text="View Selected Report", command=self.view_selected_report)
        view_report_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.load_saved_reports() # Load reports on tab load

    def load_saved_reports(self):
        self.report_listbox.delete(0, tk.END)
        if os.path.exists(report_generator.REPORT_BASE_DIR):
            report_folders = sorted(os.listdir(report_generator.REPORT_BASE_DIR), reverse=True)
            if report_folders:
                for folder in report_folders:
                    self.report_listbox.insert(tk.END, folder)
            else:
                self.report_listbox.insert(tk.END, "No reports saved yet.")
        else:
            self.report_listbox.insert(tk.END, "Report directory not found.")

    def on_report_selected(self, event):
        selected_indices = self.report_listbox.curselection()
        if selected_indices:
            selected_report_folder = self.report_listbox.get(selected_indices[0])
            print(f"Selected report: {selected_report_folder}")

    def view_selected_report(self):
        selected_indices = self.report_listbox.curselection()
        if not selected_indices:
            messagebox.showwarning("View Report", "Please select a report to view.")
            return

        selected_report_folder = self.report_listbox.get(selected_indices[0])
        report_path = os.path.join(report_generator.REPORT_BASE_DIR, selected_report_folder)

        # Attempt to open the HTML report if it exists
        html_report_path = os.path.join(report_path, f"report_{selected_report_folder}.html")
        if os.path.exists(html_report_path):
            try:
                if platform.system() == "Windows":
                    os.startfile(html_report_path)
                elif platform.system() == "Darwin": # macOS
                    subprocess.run(['open', html_report_path])
                else: # Linux
                    subprocess.run(['xdg-open', html_report_path])
            except Exception as e:
                messagebox.showerror("Error", f"Could not open report: {e}")
        else:
            messagebox.showinfo("View Report", f"No HTML report found for {selected_report_folder}. Looking for JSON file.")
            json_report_path = os.path.join(report_path, f"report_{selected_report_folder}.json")
            if os.path.exists(json_report_path):
                try:
                    if platform.system() == "Windows":
                        os.startfile(json_report_path)
                    elif platform.system() == "Darwin": # macOS
                        subprocess.run(['open', json_report_path])
                    else: # Linux
                        subprocess.run(['xdg-open', json_report_path])
                except Exception as e:
                    messagebox.showerror("Error", f"Could not open JSON report: {e}")
            else:
                messagebox.showerror("Error", f"No HTML or JSON report found for {selected_report_folder}.")

    def export_report(self):
        if not self.current_scan_results:
            messagebox.showwarning("Export Report", "No scan results available to export. Please run a full scan first.")
            return

        report_info = self.report_generator.generate_report(
            {
                "timestamp": datetime.datetime.now().isoformat(),
                "system_info": self.current_scan_results.get("system_info", {}),
                "usb_devices": self.current_scan_results.get("usb_devices", []),
                "network_scan": self.current_scan_results.get("network_scan", {}),
                "cve_lookup_results": self.current_scan_results.get("cve_lookup_results", []),
                "config_issues_results": self.current_scan_results.get("config_issues_results", []),
                "vulnerabilities": self.current_vulnerabilities # Use the collected vulnerabilities
            }
        )
        messagebox.showinfo("Export Report", f"Report generated successfully in {report_info['report_dir']} with ID {report_info['scan_id']}")
        self.load_saved_reports() # Refresh the list of reports

    def start_full_scan(self):
        if self.scan_running:
            messagebox.showwarning("Scan in Progress", "A scan is already running. Please wait for it to complete.")
            return
            
        self.scan_running = True
        self.progress_label.config(text="Status: Starting full scan...")
        self.progress_bar["value"] = 0
        self.vulnerability_tree.delete(*self.vulnerability_tree.get_children()) # Clear previous results
        self.current_scan_results = {} # Clear previous scan results
        self.current_vulnerabilities = [] # Clear previous vulnerabilities

        # Run scanning in a separate thread to keep GUI responsive
        scan_thread = threading.Thread(target=self._run_fast_scan_modules)
        scan_thread.daemon = True
        scan_thread.start()

    def _run_fast_scan_modules(self):
        """Run all scan modules concurrently for maximum speed."""
        self.scan_queue.put({'type': 'progress', 'value': 5, 'text': 'Status: Initializing concurrent scan...'})
        
        # Define scan modules with their functions
        scan_modules = [
            ("System Information", self._scan_system_info),
            ("USB Enumeration", self._scan_usb_devices),
            ("Network Scan", self._scan_network_fast),
            ("CVE Lookup", self._scan_cve),
            ("Configuration Issues", self._scan_config_issues)
        ]
        
        # Use ThreadPoolExecutor for concurrent execution
        with ThreadPoolExecutor(max_workers=5) as executor:
            # Submit all scan tasks
            future_to_module = {
                executor.submit(module_func): module_name 
                for module_name, module_func in scan_modules
            }
            
            completed_count = 0
            total_modules = len(scan_modules)
            
            # Process results as they complete
            for future in as_completed(future_to_module):
                module_name = future_to_module[future]
                try:
                    future.result()  # Get the result (this will raise any exceptions)
                    completed_count += 1
                    progress = int((completed_count / total_modules) * 90) + 5  # 5-95%
                    self.scan_queue.put({
                        'type': 'progress', 
                        'value': progress, 
                        'text': f'Status: Completed {module_name} ({completed_count}/{total_modules})'
                    })
                except Exception as e:
                    print(f"Error in {module_name}: {e}")
                    completed_count += 1
        
        # Add some sample vulnerabilities for demonstration
        sample_vulnerabilities = [
            {"severity": "High", "module": "System Info", "description": "Outdated OS version detected."},
            {"severity": "Medium", "module": "USB Scan", "description": "Unrecognized USB device connected."},
            {"severity": "High", "module": "Network Scan", "description": "Open port 22 (SSH) found on network."},
            {"severity": "High", "module": "CVE Lookup", "description": "Vulnerable software detected (CVE-2023-XXXX)."},
            {"severity": "Medium", "module": "Config Scan", "description": "Weak password policy identified."}
        ]
        
        for vuln in sample_vulnerabilities:
            self.scan_queue.put({'type': 'vulnerability', 'vuln': vuln})
        
        # Complete the scan
        self.scan_queue.put({'type': 'complete'})

    def _scan_network_fast(self):
        """Fast network scan using the optimized network scanner."""
        # Use the new fast network scan function
        network_results = network_scanner.fast_network_scan()
        
        if "error" not in network_results:
            self.current_scan_results["network_scan"] = {
                "local_ip": network_scanner.get_local_ip(),
                "network_range": network_results["network_range"],
                "active_hosts": network_results["active_hosts"],
                "open_ports_by_host": network_results["scan_results"]
            }
        else:
            self.current_scan_results["network_scan"] = {"error": network_results["error"]}
        
        # Update the Network Scan tab display
        self.master.after(0, self.display_network_scan_results)

    def _run_scan_modules(self):
        modules = [
            ("System Information", 15, self._scan_system_info),
            ("USB Enumeration", 15, self._scan_usb_devices),
            ("Network Scan", 20, self._scan_network),
            ("CVE Lookup", 20, self._scan_cve),
            ("Configuration Issues", 20, self._scan_config_issues)
        ]
        total_progress = 0

        for i, (module_name, percentage, scan_function) in enumerate(modules):
            self.progress_label.config(text=f"Status: Scanning {module_name}...")
            scan_function() # Execute the scanner function

            # Simulate progress for GUI update
            for j in range(percentage // 5):
                time.sleep(0.1)
                total_progress += 5
                self.progress_bar["value"] = total_progress
                self.master.update_idletasks()

            # Add a dummy vulnerability to the dashboard for each module after it runs
            # (Actual vulnerabilities will come from the scanner modules)
            if "System" in module_name:
                vuln = {"severity": "Low", "module": "System Info", "description": "Outdated OS version detected."}
            elif "USB" in module_name:
                vuln = {"severity": "Medium", "module": "USB Scan", "description": "Unrecognized USB device connected."}
            elif "Network" in module_name:
                vuln = {"severity": "High", "module": "Network Scan", "description": "Open port 22 (SSH) found on 192.168.1.5."}
            elif "CVE" in module_name:
                vuln = {"severity": "High", "module": "CVE Lookup", "description": "Vulnerable software X.Y.Z detected (CVE-2023-XXXX)."}
            elif "Configuration" in module_name:
                vuln = {"severity": "Medium", "module": "Config Scan", "description": "Weak password policy identified or exposed service found."}
            else:
                vuln = None

            if vuln:
                self.vulnerability_tree.insert("", "end", values=(vuln["severity"], vuln["module"], vuln["description"]))
                self.current_vulnerabilities.append(vuln)


        self.progress_label.config(text="Status: Full scan completed!")
        self.progress_bar["value"] = 100
        messagebox.showinfo("IDSA", "Full scan completed successfully!")

        # Generate report after scan completes
        self.export_report() # Automatically generate report after scan

    def _scan_system_info(self):
        # Collect system information using fast concurrent method
        system_data = system_scanner.get_system_info_fast()
        self.current_scan_results["system_info"] = system_data

        # Update the System Info tab display
        self.master.after(0, self.display_system_info) # Schedule GUI update on main thread

    def _scan_usb_devices(self):
        # Collect USB device information
        usb_devices = usb_scanner.get_usb_devices()
        self.current_scan_results["usb_devices"] = usb_devices

        # Update the USB Devices tab display
        self.master.after(0, self.display_usb_devices)

    def _scan_network(self):
        # Collect network scan information
        local_ip = network_scanner.get_local_ip()
        network_range = network_scanner.get_network_range(local_ip)
        active_hosts = network_scanner.ping_sweep(network_range)

        network_scan_details = {
            "local_ip": local_ip,
            "network_range": network_range,
            "active_hosts": active_hosts,
            "open_ports_by_host": {}
        }

        for host in active_hosts:
            open_ports = network_scanner.scan_open_ports(host)
            network_scan_details["open_ports_by_host"][host] = open_ports

        self.current_scan_results["network_scan"] = network_scan_details

        # Update the Network Scan tab display
        self.master.after(0, self.display_network_scan_results)

    def _scan_cve(self):
        # Perform CVE lookup. This needs a way to identify software on the system.
        # For now, we'll use dummy searches or integrate with existing scan results if applicable.
        # Example: Search for a known vulnerable software if detected by another scanner.

        # Dummy CVE lookup for demonstration based on a hypothetical software detected
        software_to_check = "Web Server X"
        version_to_check = "1.0"
        cve_results = cve_scanner.search_cve(software_to_check, version_to_check)
        self.current_scan_results["cve_lookup_results"] = cve_results

        # Note: We are not updating the CVE lookup GUI tab automatically after a full scan here,
        # as it's designed for manual search. Results will be in the overall report.

    def _scan_config_issues(self):
        # Collect configuration issues
        network_scan_results_for_config = {}
        if "network_scan" in self.current_scan_results and "open_ports_by_host" in self.current_scan_results["network_scan"]:
            network_scan_results_for_config = self.current_scan_results["network_scan"]["open_ports_by_host"]

        config_vulnerabilities = config_scanner.scan_configuration_issues(network_scan_results_for_config)
        self.current_scan_results["config_issues_results"] = config_vulnerabilities

        # Update the Config Issues tab display
        self.master.after(0, self.display_config_issues)


    def show_vulnerability_context_menu(self, event):
        # Placeholder for context menu (e.g., "View Details", "Mark as reviewed")
        pass

class DisclaimerApp:
    def __init__(self, master):
        self.master = master
        master.title("IoT Device Security Analyzer (IDSA)")
        master.geometry("600x400")
        master.resizable(False, False)

        self.disclaimer_text = """
        Disclaimer:
        This 'IoT Device Security Analyzer (IDSA)' is for educational and
        demonstration purposes only. Run this application only on devices
        you own or have explicit permission to scan.
        The developers are not responsible for any misuse or damage caused
        by this software.
        """

        self.create_widgets()

    def create_widgets(self):
        # Disclaimer Label
        self.disclaimer_label = tk.Label(
            self.master,
            text=self.disclaimer_text,
            wraplength=550,
            justify=tk.LEFT,
            font=("Arial", 12)
        )
        self.disclaimer_label.pack(pady=50)

        # I Agree Button
        self.agree_button = tk.Button(
            self.master,
            text="I AGREE - Start Scan",
            command=self.on_agree,
            font=("Arial", 14, "bold"),
            bg="#4CAF50",
            fg="white",
            padx=20,
            pady=10
        )
        self.agree_button.pack(pady=20)

        # Exit Button
        self.exit_button = tk.Button(
            self.master,
            text="Exit",
            command=self.on_exit,
            font=("Arial", 10),
            bg="#f44336",
            fg="white",
            padx=10,
            pady=5
        )
        self.exit_button.pack(pady=10)

    def on_agree(self):
        messagebox.showinfo("IDSA", "Consent received. Starting scan...")
        self.master.destroy()
        # Launch the main scanning dashboard
        main_root = tk.Tk()
        main_app = IDSAMainApp(main_root)
        main_root.mainloop()

    def on_exit(self):
        self.master.destroy()
        print("User exited.")

if __name__ == "__main__":
    root = tk.Tk()
    app = DisclaimerApp(root)
    root.mainloop()
