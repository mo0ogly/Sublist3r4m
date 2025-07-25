#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
SubBrute GUI v2.0 - Simplified version for Python 2/3 compatibility

A modern graphical interface for subdomain enumeration with tabbed interface,
real-time progress monitoring, and comprehensive export functionality.
"""

# Python 2/3 compatibility imports
import sys
if sys.version_info[0] >= 3:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext
    import queue
else:
    import Tkinter as tk
    import ttk
    import tkFileDialog as filedialog
    import tkMessageBox as messagebox
    import ScrolledText as scrolledtext
    import Queue as queue

import threading
import time
import json
import csv
from datetime import datetime
import os
from collections import defaultdict

class SubBruteGUI:
    """
    Main GUI application class for SubBrute.
    
    Provides a comprehensive interface for subdomain enumeration with:
    - Tabbed interface for different functions
    - Real-time progress monitoring
    - Advanced configuration options
    - Export functionality
    - Live statistics and logging
    """
    
    def __init__(self, root):
        """Initialize the main GUI application."""
        self.root = root
        self.setup_window()
        self.setup_variables()
        self.setup_gui()
        
        # Initialize data structures
        self.results = []
        self.stats = {
            'start_time': None,
            'end_time': None,
            'successful_lookups': 0,
            'unique_ips': set(),
        }
        self.is_running = False
    
    def setup_window(self):
        """Configure the main window properties."""
        self.root.title("SubBrute GUI v2.0 - Advanced Subdomain Enumeration")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 600)
    
    def setup_variables(self):
        """Initialize Tkinter variables for form fields."""
        # Target configuration
        self.target_var = tk.StringVar(value="example.com")
        self.record_type_var = tk.StringVar(value="A")
        self.subdomains_file_var = tk.StringVar(value="names.txt")
        self.resolvers_file_var = tk.StringVar(value="resolvers.txt")
        self.process_count_var = tk.IntVar(value=16)
        
        # Status variables
        self.status_var = tk.StringVar(value="Ready")
        self.results_count_var = tk.StringVar(value="Results: 0")
    
    def setup_gui(self):
        """Create and configure the GUI components."""
        # Create main frames
        self.create_toolbar()
        self.create_notebook()
        self.create_status_bar()
        
        # Create tabs
        self.create_config_tab()
        self.create_results_tab()
        self.create_statistics_tab()
        self.create_logs_tab()
    
    def create_toolbar(self):
        """Create the main toolbar with action buttons."""
        toolbar = ttk.Frame(self.root)
        toolbar.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        
        # Main action buttons
        self.start_button = ttk.Button(toolbar, text="▶ Start Enumeration", 
                                      command=self.start_enumeration)
        self.start_button.pack(side=tk.LEFT, padx=(0, 5))
        
        self.stop_button = ttk.Button(toolbar, text="⏹ Stop", 
                                     command=self.stop_enumeration,
                                     state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=(0, 5))
        
        self.clear_button = ttk.Button(toolbar, text="🗑 Clear Results", 
                                      command=self.clear_results)
        self.clear_button.pack(side=tk.LEFT, padx=(0, 20))
        
        # Export buttons
        ttk.Label(toolbar, text="Export:").pack(side=tk.LEFT, padx=(0, 5))
        
        self.export_csv_button = ttk.Button(toolbar, text="CSV", 
                                           command=lambda: self.export_results('csv'))
        self.export_csv_button.pack(side=tk.LEFT, padx=(0, 2))
        
        self.export_json_button = ttk.Button(toolbar, text="JSON", 
                                            command=lambda: self.export_results('json'))
        self.export_json_button.pack(side=tk.LEFT, padx=(0, 2))
        
        # Help button
        self.help_button = ttk.Button(toolbar, text="❓ Help", 
                                     command=self.show_help)
        self.help_button.pack(side=tk.RIGHT)
    
    def create_notebook(self):
        """Create the main tabbed interface."""
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0, 5))
        
        # Create tab frames
        self.config_frame = ttk.Frame(self.notebook)
        self.results_frame = ttk.Frame(self.notebook)
        self.stats_frame = ttk.Frame(self.notebook)
        self.logs_frame = ttk.Frame(self.notebook)
        
        # Add tabs to notebook
        self.notebook.add(self.config_frame, text="⚙ Configuration")
        self.notebook.add(self.results_frame, text="📊 Results")
        self.notebook.add(self.stats_frame, text="📈 Statistics")
        self.notebook.add(self.logs_frame, text="📝 Logs")
    
    def create_status_bar(self):
        """Create the status bar with progress information."""
        status_frame = ttk.Frame(self.root)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)
        
        # Status label
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var)
        self.status_label.pack(side=tk.LEFT)
        
        # Progress bar
        self.progress_bar = ttk.Progressbar(status_frame, mode='indeterminate')
        self.progress_bar.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(20, 0))
    
    def create_config_tab(self):
        """Create the configuration tab with all options."""
        # Target Configuration Section
        target_section = ttk.LabelFrame(self.config_frame, text="Target Configuration", padding=10)
        target_section.pack(fill=tk.X, padx=10, pady=5)
        
        # Target domain
        ttk.Label(target_section, text="Target Domain:").grid(row=0, column=0, sticky=tk.W, pady=2)
        target_entry = ttk.Entry(target_section, textvariable=self.target_var, width=40)
        target_entry.grid(row=0, column=1, columnspan=2, sticky=tk.W+tk.E, padx=(10, 0), pady=2)
        
        # Record type
        ttk.Label(target_section, text="DNS Record Type:").grid(row=1, column=0, sticky=tk.W, pady=2)
        record_combo = ttk.Combobox(target_section, textvariable=self.record_type_var,
                                   values=["A", "AAAA", "CNAME", "MX", "TXT", "SOA"], width=15)
        record_combo.grid(row=1, column=1, sticky=tk.W, padx=(10, 0), pady=2)
        
        # File Configuration Section
        files_section = ttk.LabelFrame(self.config_frame, text="File Configuration", padding=10)
        files_section.pack(fill=tk.X, padx=10, pady=5)
        
        # Subdomains file
        ttk.Label(files_section, text="Subdomains File:").grid(row=0, column=0, sticky=tk.W, pady=2)
        subdomains_entry = ttk.Entry(files_section, textvariable=self.subdomains_file_var, width=35)
        subdomains_entry.grid(row=0, column=1, sticky=tk.W+tk.E, padx=(10, 0), pady=2)
        ttk.Button(files_section, text="Browse", 
                  command=lambda: self.browse_file(self.subdomains_file_var, "Select Subdomains File")).grid(
                  row=0, column=2, padx=(5, 0), pady=2)
        
        # Resolvers file
        ttk.Label(files_section, text="Resolvers File:").grid(row=1, column=0, sticky=tk.W, pady=2)
        resolvers_entry = ttk.Entry(files_section, textvariable=self.resolvers_file_var, width=35)
        resolvers_entry.grid(row=1, column=1, sticky=tk.W+tk.E, padx=(10, 0), pady=2)
        ttk.Button(files_section, text="Browse", 
                  command=lambda: self.browse_file(self.resolvers_file_var, "Select Resolvers File")).grid(
                  row=1, column=2, padx=(5, 0), pady=2)
        
        # Performance Configuration Section
        perf_section = ttk.LabelFrame(self.config_frame, text="Performance Configuration", padding=10)
        perf_section.pack(fill=tk.X, padx=10, pady=5)
        
        # Process count
        ttk.Label(perf_section, text="Process Count:").grid(row=0, column=0, sticky=tk.W, pady=2)
        process_spin = ttk.Spinbox(perf_section, from_=1, to=64, textvariable=self.process_count_var, width=10)
        process_spin.grid(row=0, column=1, sticky=tk.W, padx=(10, 0), pady=2)
        
        # Configure grid weights
        target_section.columnconfigure(1, weight=1)
        files_section.columnconfigure(1, weight=1)
    
    def create_results_tab(self):
        """Create the results tab with treeview and filtering."""
        # Create main frames
        filter_frame = ttk.Frame(self.results_frame)
        filter_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tree_frame = ttk.Frame(self.results_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0, 5))
        
        # Results counter
        ttk.Label(filter_frame, textvariable=self.results_count_var).pack(side=tk.LEFT)
        
        # Create treeview for results
        columns = ("hostname", "record_type", "addresses", "timestamp")
        self.results_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=20)
        
        # Configure columns
        self.results_tree.heading("hostname", text="Hostname")
        self.results_tree.heading("record_type", text="Type")
        self.results_tree.heading("addresses", text="IP Addresses")
        self.results_tree.heading("timestamp", text="Timestamp")
        
        self.results_tree.column("hostname", width=300, minwidth=200)
        self.results_tree.column("record_type", width=80, minwidth=60)
        self.results_tree.column("addresses", width=250, minwidth=150)
        self.results_tree.column("timestamp", width=150, minwidth=120)
        
        # Add scrollbars
        tree_scroll_y = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=tree_scroll_y.set)
        
        # Pack treeview and scrollbars
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_statistics_tab(self):
        """Create the statistics tab with real-time metrics."""
        # Summary statistics
        summary_frame = ttk.LabelFrame(self.stats_frame, text="Summary Statistics", padding=10)
        summary_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Statistics labels
        self.stats_labels = {}
        
        ttk.Label(summary_frame, text="Successful Lookups:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10), pady=2)
        self.stats_labels['successful'] = ttk.Label(summary_frame, text="0")
        self.stats_labels['successful'].grid(row=0, column=1, sticky=tk.W, padx=(0, 20), pady=2)
        
        ttk.Label(summary_frame, text="Unique IP Addresses:").grid(row=0, column=2, sticky=tk.W, padx=(0, 10), pady=2)
        self.stats_labels['unique_ips'] = ttk.Label(summary_frame, text="0")
        self.stats_labels['unique_ips'].grid(row=0, column=3, sticky=tk.W, padx=(0, 20), pady=2)
        
        # Refresh button
        ttk.Button(summary_frame, text="Refresh Statistics", 
                  command=self.refresh_statistics).grid(row=1, column=0, columnspan=4, pady=(10, 0))
    
    def create_logs_tab(self):
        """Create the logs tab with basic logging display."""
        # Log display
        self.log_text = scrolledtext.ScrolledText(self.logs_frame, height=25, width=100,
                                                 font=('Consolas', 9))
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Log controls
        log_controls_frame = ttk.Frame(self.logs_frame)
        log_controls_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(log_controls_frame, text="Clear Logs", 
                  command=self.clear_logs).pack(side=tk.LEFT, padx=(0, 5))
    
    def browse_file(self, var, title):
        """Browse for a file and update the variable."""
        filename = filedialog.askopenfilename(title=title,
                                            filetypes=[("Text files", "*.txt"),
                                                     ("All files", "*.*")])
        if filename:
            var.set(filename)
    
    def start_enumeration(self):
        """Start the subdomain enumeration process."""
        if self.is_running:
            messagebox.showwarning("Already Running", "Enumeration is already in progress!")
            return
        
        # Validate inputs
        if not self.target_var.get().strip():
            messagebox.showerror("Invalid Input", "Please enter a target domain!")
            return
        
        # Update UI state
        self.is_running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_var.set("Running enumeration...")
        self.progress_bar.start()
        
        # Log start
        self.add_log_entry("INFO", "Enumeration started for target: " + self.target_var.get())
        
        # Start enumeration in separate thread
        self.enumeration_thread = threading.Thread(target=self.run_enumeration, daemon=True)
        self.enumeration_thread.start()
    
    def stop_enumeration(self):
        """Stop the running enumeration process."""
        if not self.is_running:
            return
        
        self.is_running = False
        self.status_var.set("Stopping...")
        
        # Update UI state
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress_bar.stop()
        
        self.add_log_entry("WARNING", "Enumeration stopped by user")
    
    def run_enumeration(self):
        """Run a mock enumeration process."""
        try:
            self.stats['start_time'] = time.time()
            
            # Mock enumeration - in real implementation, use SubBrute engine
            mock_results = [
                ("www." + self.target_var.get(), "A", ["192.168.1.1"], datetime.now().strftime("%H:%M:%S")),
                ("mail." + self.target_var.get(), "A", ["192.168.1.2"], datetime.now().strftime("%H:%M:%S")),
                ("ftp." + self.target_var.get(), "A", ["192.168.1.3"], datetime.now().strftime("%H:%M:%S")),
            ]
            
            for hostname, record_type, addresses, timestamp in mock_results:
                if not self.is_running:
                    break
                
                result = {
                    'hostname': hostname,
                    'record_type': record_type,
                    'addresses': addresses,
                    'timestamp': timestamp
                }
                
                # Add result
                self.root.after(0, lambda r=result: self.add_result(r))
                
                # Update statistics
                self.stats['successful_lookups'] += 1
                for addr in addresses:
                    self.stats['unique_ips'].add(addr)
                
                # Simulate processing time
                time.sleep(1)
            
            # Enumeration completed
            self.stats['end_time'] = time.time()
            self.root.after(0, lambda: self.add_log_entry("INFO", "Enumeration completed: {} results found".format(len(self.results))))
            
        except Exception as e:
            self.root.after(0, lambda: self.add_log_entry("ERROR", "Enumeration error: " + str(e)))
            self.root.after(0, lambda: messagebox.showerror("Enumeration Error", "An error occurred: " + str(e)))
        
        finally:
            # Reset UI state
            self.is_running = False
            self.root.after(0, lambda: self.start_button.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.stop_button.config(state=tk.DISABLED))
            self.root.after(0, lambda: self.status_var.set("Ready"))
            self.root.after(0, lambda: self.progress_bar.stop())
    
    def add_result(self, result):
        """Add a result to the results tree."""
        self.results.append(result)
        
        # Add to treeview
        self.results_tree.insert("", tk.END, values=(
            result['hostname'],
            result['record_type'],
            ', '.join(result['addresses']),
            result['timestamp']
        ))
        
        # Update counter
        self.results_count_var.set("Results: {}".format(len(self.results)))
        
        # Auto-scroll to bottom
        if hasattr(self, 'results_tree'):
            children = self.results_tree.get_children()
            if children:
                self.results_tree.see(children[-1])
    
    def add_log_entry(self, level, message):
        """Add a log entry to the logs display."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_line = "[{}] {} | {}\\n".format(timestamp, level.ljust(8), message)
        
        # Insert log entry
        self.log_text.insert(tk.END, log_line)
        self.log_text.see(tk.END)
        
        # Limit log size (keep last 1000 lines)
        lines = int(self.log_text.index(tk.END).split('.')[0])
        if lines > 1000:
            self.log_text.delete('1.0', '{}0'.format(lines-1000))
    
    def clear_results(self):
        """Clear all results and reset statistics."""
        self.results = []
        
        # Clear treeview
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Reset statistics
        self.stats = {
            'start_time': None,
            'end_time': None,
            'successful_lookups': 0,
            'unique_ips': set(),
        }
        
        # Update displays
        self.results_count_var.set("Results: 0")
        if hasattr(self, 'stats_labels'):
            for label in self.stats_labels.values():
                label.config(text="0")
        
        self.add_log_entry("INFO", "Results and statistics cleared")
    
    def export_results(self, format_type):
        """Export results in the specified format."""
        if not self.results:
            messagebox.showwarning("No Results", "No results to export!")
            return
        
        # Get filename
        extensions = {'csv': '.csv', 'json': '.json'}
        extension = extensions.get(format_type, '.txt')
        
        filename = filedialog.asksaveasfilename(
            title="Export Results as " + format_type.upper(),
            defaultextension=extension,
            filetypes=[(format_type.upper() + " files", "*" + extension), ("All files", "*.*")]
        )
        
        if not filename:
            return
        
        try:
            if format_type == 'csv':
                self.export_csv(filename)
            elif format_type == 'json':
                self.export_json(filename)
            
            messagebox.showinfo("Export Complete", "Results exported to " + filename)
            self.add_log_entry("INFO", "Results exported to " + filename + " (" + format_type.upper() + " format)")
            
        except Exception as e:
            messagebox.showerror("Export Error", "Failed to export results: " + str(e))
            self.add_log_entry("ERROR", "Export error: " + str(e))
    
    def export_csv(self, filename):
        """Export results to CSV format."""
        with open(filename, 'w') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Hostname', 'Record Type', 'IP Addresses', 'Timestamp'])
            
            for result in self.results:
                writer.writerow([
                    result['hostname'],
                    result['record_type'],
                    ', '.join(result['addresses']),
                    result['timestamp']
                ])
    
    def export_json(self, filename):
        """Export results to JSON format."""
        export_data = {
            'metadata': {
                'target': self.target_var.get(),
                'export_time': datetime.now().isoformat(),
                'total_results': len(self.results),
            },
            'results': self.results
        }
        
        with open(filename, 'w') as jsonfile:
            json.dump(export_data, jsonfile, indent=2)
    
    def clear_logs(self):
        """Clear the log display."""
        self.log_text.delete('1.0', tk.END)
        self.add_log_entry("INFO", "Log display cleared")
    
    def refresh_statistics(self):
        """Refresh the statistics display."""
        if hasattr(self, 'stats_labels'):
            self.stats_labels['successful'].config(text=str(self.stats['successful_lookups']))
            self.stats_labels['unique_ips'].config(text=str(len(self.stats['unique_ips'])))
    
    def show_help(self):
        """Show help documentation."""
        help_text = """SubBrute GUI v2.0 - Help

Quick Start:
1. Enter target domain in Configuration tab
2. Select DNS record type (usually 'A')
3. Choose wordlist files or use defaults
4. Click 'Start Enumeration'
5. View results in Results tab
6. Export results using toolbar buttons

Features:
- Tabbed interface for easy navigation
- Real-time progress monitoring
- Export to CSV and JSON formats
- Comprehensive logging
- Multi-threaded processing

For more information, visit the project documentation.
"""
        
        messagebox.showinfo("SubBrute GUI Help", help_text)


def main():
    """Main entry point for the GUI application."""
    root = tk.Tk()
    app = SubBruteGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()