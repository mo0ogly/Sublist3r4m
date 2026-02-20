#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
SubBrute GUI v2.0 - Modern Tkinter Interface for Subdomain Enumeration

This module provides a comprehensive graphical user interface for the SubBrute
subdomain enumeration tool. Features include:
- Tabbed interface with configuration, results, statistics, and logs
- Real-time progress monitoring and statistics
- Advanced export functionality (CSV, JSON, XML, HTML)
- Modern UI with tooltips and help system
- Comprehensive logging and filtering options

Author: Enhanced SubBrute Team
License: MIT
"""

import csv
import json
import queue
import threading
import time
import tkinter as tk
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime
from tkinter import filedialog, messagebox, scrolledtext, ttk

# Import the SubBrute engine
try:
    from subbrute import ColoredLogger, SubBrute
except ImportError:
    # Fallback for development
    import subbrute
    SubBrute = subbrute.SubBrute
    ColoredLogger = subbrute.ColoredLogger


class ModernTooltip:
    """
    Modern tooltip class with styling and delay.

    Provides enhanced tooltips with customizable appearance and behavior
    for better user experience.
    """

    def __init__(self, widget, text, delay=500):
        """
        Initialize tooltip for a widget.

        Args:
            widget: Tkinter widget to attach tooltip to
            text (str): Tooltip text content
            delay (int): Delay in milliseconds before showing tooltip
        """
        self.widget = widget
        self.text = text
        self.delay = delay
        self.tooltip_window = None
        self.id = None

        # Bind events
        self.widget.bind('<Enter>', self.on_enter)
        self.widget.bind('<Leave>', self.on_leave)
        self.widget.bind('<Motion>', self.on_motion)

    def on_enter(self, event=None):
        """Handle mouse enter event."""
        self.schedule_tooltip()

    def on_leave(self, event=None):
        """Handle mouse leave event."""
        self.cancel_tooltip()
        self.hide_tooltip()

    def on_motion(self, event=None):
        """Handle mouse motion event."""
        self.cancel_tooltip()
        self.schedule_tooltip()

    def schedule_tooltip(self):
        """Schedule tooltip to appear after delay."""
        self.cancel_tooltip()
        self.id = self.widget.after(self.delay, self.show_tooltip)

    def cancel_tooltip(self):
        """Cancel scheduled tooltip."""
        if self.id:
            self.widget.after_cancel(self.id)
            self.id = None

    def show_tooltip(self):
        """Display the tooltip."""
        if self.tooltip_window or not self.text:
            return

        x, y, _, _ = self.widget.bbox("insert") if hasattr(self.widget, 'bbox') else (0, 0, 0, 0)
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25

        # Create tooltip window
        self.tooltip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry("+%d+%d" % (x, y))

        # Style the tooltip
        label = tk.Label(tw, text=self.text, justify='left',
                        background='#ffffe0', relief='solid', borderwidth=1,
                        font=('Arial', 9), padx=5, pady=3)
        label.pack()

    def hide_tooltip(self):
        """Hide the tooltip."""
        if self.tooltip_window:
            self.tooltip_window.destroy()
            self.tooltip_window = None


class GUILogger:
    """
    Custom logger for GUI integration.

    Captures log messages and forwards them to the GUI for display
    in the logs tab with real-time updates.
    """

    def __init__(self, log_queue):
        """
        Initialize GUI logger.

        Args:
            log_queue (Queue): Thread-safe queue for log messages
        """
        self.log_queue = log_queue
        self.start_time = time.time()

    def log(self, level, message):
        """
        Log a message with timestamp and level.

        Args:
            level (str): Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            message (str): Log message content
        """
        timestamp = datetime.now().strftime("%H:%M:%S.%")[:-3]
        elapsed = time.time() - self.start_time

        log_entry = {
            'timestamp': timestamp,
            'elapsed': elapsed,
            'level': level,
            'message': str(message)
        }

        try:
            self.log_queue.put_nowait(log_entry)
        except queue.Full:
            pass  # Drop message if queue is full

    def debug(self, *args):
        """Log debug message."""
        self.log('DEBUG', ' '.join(str(arg) for arg in args))

    def info(self, *args):
        """Log info message."""
        self.log('INFO', ' '.join(str(arg) for arg in args))

    def warning(self, *args):
        """Log warning message."""
        self.log('WARNING', ' '.join(str(arg) for arg in args))

    def error(self, *args):
        """Log error message."""
        self.log('ERROR', ' '.join(str(arg) for arg in args))

    def critical(self, *args):
        """Log critical message."""
        self.log('CRITICAL', ' '.join(str(arg) for arg in args))


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
        """
        Initialize the main GUI application.

        Args:
            root: Tkinter root window
        """
        self.root = root
        self.setup_window()
        self.setup_variables()
        self.setup_queues()
        self.setup_gui()
        self.setup_bindings()
        self.start_update_loop()

        # Initialize statistics
        self.stats = {
            'start_time': None,
            'end_time': None,
            'total_subdomains': 0,
            'successful_lookups': 0,
            'failed_lookups': 0,
            'wildcard_filtered': 0,
            'nameservers_used': 0,
            'rate_per_second': 0.0,
            'unique_ips': set(),
            'record_types': defaultdict(int)
        }

        self.results = []
        self.enumeration_thread = None
        self.is_running = False

    def setup_window(self):
        """Configure the main window properties."""
        self.root.title("SubBrute GUI v2.0 - Advanced Subdomain Enumeration")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 600)

        # Configure style
        style = ttk.Style()
        style.theme_use('clam')

        # Custom colors
        style.configure('Accent.TButton', background='#0078d4', foreground='white')
        style.configure('Success.TLabel', foreground='#107c10')
        style.configure('Error.TLabel', foreground='#d13438')
        style.configure('Warning.TLabel', foreground='#ff8c00')

    def setup_variables(self):
        """Initialize Tkinter variables for form fields."""
        # Target configuration
        self.target_var = tk.StringVar(value="example.com")
        self.record_type_var = tk.StringVar(value="A")
        self.subdomains_file_var = tk.StringVar(value="names.txt")
        self.resolvers_file_var = tk.StringVar(value="resolvers.txt")
        self.process_count_var = tk.IntVar(value=16)

        # Advanced options
        self.timeout_var = tk.DoubleVar(value=2.0)
        self.retries_var = tk.IntVar(value=3)
        self.verbose_var = tk.BooleanVar(value=True)
        self.save_logs_var = tk.BooleanVar(value=True)
        self.filter_wildcards_var = tk.BooleanVar(value=True)

        # Output options
        self.output_format_var = tk.StringVar(value="Text")
        self.output_file_var = tk.StringVar()
        self.real_time_export_var = tk.BooleanVar(value=False)

        # Status variables
        self.status_var = tk.StringVar(value="Ready")
        self.progress_var = tk.DoubleVar(value=0.0)
        self.current_task_var = tk.StringVar(value="Idle")

        # Statistics variables
        self.stats_labels = {}

    def setup_queues(self):
        """Initialize thread-safe queues for communication."""
        self.result_queue = queue.Queue()
        self.log_queue = queue.Queue()
        self.stats_queue = queue.Queue()
        self.gui_logger = GUILogger(self.log_queue)

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
                                      command=self.start_enumeration,
                                      style='Accent.TButton')
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

        self.export_xml_button = ttk.Button(toolbar, text="XML",
                                           command=lambda: self.export_results('xml'))
        self.export_xml_button.pack(side=tk.LEFT, padx=(0, 2))

        self.export_html_button = ttk.Button(toolbar, text="HTML",
                                            command=lambda: self.export_results('html'))
        self.export_html_button.pack(side=tk.LEFT, padx=(0, 20))

        # Help button
        self.help_button = ttk.Button(toolbar, text="❓ Help",
                                     command=self.show_help)
        self.help_button.pack(side=tk.RIGHT)

        # Add tooltips
        ModernTooltip(self.start_button, "Start subdomain enumeration with current configuration")
        ModernTooltip(self.stop_button, "Stop the running enumeration process")
        ModernTooltip(self.clear_button, "Clear all results and reset statistics")
        ModernTooltip(self.export_csv_button, "Export results to CSV format")
        ModernTooltip(self.export_json_button, "Export results to JSON format")
        ModernTooltip(self.export_xml_button, "Export results to XML format")
        ModernTooltip(self.export_html_button, "Export results to HTML report")

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
        self.progress_bar = ttk.Progressbar(status_frame, mode='determinate')
        self.progress_bar.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(20, 0))

        # Current task label
        self.task_label = ttk.Label(status_frame, textvariable=self.current_task_var)
        self.task_label.pack(side=tk.RIGHT, padx=(0, 10))

    def create_config_tab(self):
        """Create the configuration tab with all options."""
        # Create scrollable frame
        canvas = tk.Canvas(self.config_frame)
        scrollbar = ttk.Scrollbar(self.config_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        # Pack canvas and scrollbar
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Target Configuration Section
        target_section = ttk.LabelFrame(scrollable_frame, text="Target Configuration", padding=10)
        target_section.pack(fill=tk.X, padx=10, pady=5)

        # Target domain
        ttk.Label(target_section, text="Target Domain:").grid(row=0, column=0, sticky=tk.W, pady=2)
        target_entry = ttk.Entry(target_section, textvariable=self.target_var, width=40)
        target_entry.grid(row=0, column=1, columnspan=2, sticky=tk.W+tk.E, padx=(10, 0), pady=2)
        ModernTooltip(target_entry, "Enter the target domain (e.g., example.com)")

        # Record type
        ttk.Label(target_section, text="DNS Record Type:").grid(row=1, column=0, sticky=tk.W, pady=2)
        record_combo = ttk.Combobox(target_section, textvariable=self.record_type_var,
                                   values=["A", "AAAA", "CNAME", "MX", "TXT", "SOA"], width=15)
        record_combo.grid(row=1, column=1, sticky=tk.W, padx=(10, 0), pady=2)
        ModernTooltip(record_combo, "Select DNS record type to query")

        # File Configuration Section
        files_section = ttk.LabelFrame(scrollable_frame, text="File Configuration", padding=10)
        files_section.pack(fill=tk.X, padx=10, pady=5)

        # Subdomains file
        ttk.Label(files_section, text="Subdomains File:").grid(row=0, column=0, sticky=tk.W, pady=2)
        subdomains_entry = ttk.Entry(files_section, textvariable=self.subdomains_file_var, width=35)
        subdomains_entry.grid(row=0, column=1, sticky=tk.W+tk.E, padx=(10, 0), pady=2)
        ttk.Button(files_section, text="Browse",
                  command=lambda: self.browse_file(self.subdomains_file_var, "Select Subdomains File")).grid(
                  row=0, column=2, padx=(5, 0), pady=2)
        ModernTooltip(subdomains_entry, "Path to subdomains wordlist file")

        # Resolvers file
        ttk.Label(files_section, text="Resolvers File:").grid(row=1, column=0, sticky=tk.W, pady=2)
        resolvers_entry = ttk.Entry(files_section, textvariable=self.resolvers_file_var, width=35)
        resolvers_entry.grid(row=1, column=1, sticky=tk.W+tk.E, padx=(10, 0), pady=2)
        ttk.Button(files_section, text="Browse",
                  command=lambda: self.browse_file(self.resolvers_file_var, "Select Resolvers File")).grid(
                  row=1, column=2, padx=(5, 0), pady=2)
        ModernTooltip(resolvers_entry, "Path to DNS resolvers list file")

        # Performance Configuration Section
        perf_section = ttk.LabelFrame(scrollable_frame, text="Performance Configuration", padding=10)
        perf_section.pack(fill=tk.X, padx=10, pady=5)

        # Process count
        ttk.Label(perf_section, text="Process Count:").grid(row=0, column=0, sticky=tk.W, pady=2)
        process_spin = ttk.Spinbox(perf_section, from_=1, to=64, textvariable=self.process_count_var, width=10)
        process_spin.grid(row=0, column=1, sticky=tk.W, padx=(10, 0), pady=2)
        ModernTooltip(process_spin, "Number of parallel DNS lookup processes (1-64)")

        # Timeout
        ttk.Label(perf_section, text="Timeout (seconds):").grid(row=0, column=2, sticky=tk.W, padx=(20, 0), pady=2)
        timeout_spin = ttk.Spinbox(perf_section, from_=0.5, to=10.0, increment=0.5,
                                  textvariable=self.timeout_var, width=10)
        timeout_spin.grid(row=0, column=3, sticky=tk.W, padx=(10, 0), pady=2)
        ModernTooltip(timeout_spin, "DNS query timeout in seconds")

        # Retries
        ttk.Label(perf_section, text="Retries:").grid(row=1, column=0, sticky=tk.W, pady=2)
        retries_spin = ttk.Spinbox(perf_section, from_=0, to=10, textvariable=self.retries_var, width=10)
        retries_spin.grid(row=1, column=1, sticky=tk.W, padx=(10, 0), pady=2)
        ModernTooltip(retries_spin, "Number of retry attempts for failed queries")

        # Options Section
        options_section = ttk.LabelFrame(scrollable_frame, text="Options", padding=10)
        options_section.pack(fill=tk.X, padx=10, pady=5)

        # Checkboxes for various options
        ttk.Checkbutton(options_section, text="Verbose Logging",
                       variable=self.verbose_var).grid(row=0, column=0, sticky=tk.W, pady=2)
        ttk.Checkbutton(options_section, text="Save Logs to File",
                       variable=self.save_logs_var).grid(row=0, column=1, sticky=tk.W, padx=(20, 0), pady=2)
        ttk.Checkbutton(options_section, text="Filter Wildcard Responses",
                       variable=self.filter_wildcards_var).grid(row=1, column=0, sticky=tk.W, pady=2)
        ttk.Checkbutton(options_section, text="Real-time Export",
                       variable=self.real_time_export_var).grid(row=1, column=1, sticky=tk.W, padx=(20, 0), pady=2)

        # Output Configuration Section
        output_section = ttk.LabelFrame(scrollable_frame, text="Output Configuration", padding=10)
        output_section.pack(fill=tk.X, padx=10, pady=5)

        # Output format
        ttk.Label(output_section, text="Default Export Format:").grid(row=0, column=0, sticky=tk.W, pady=2)
        format_combo = ttk.Combobox(output_section, textvariable=self.output_format_var,
                                   values=["Text", "CSV", "JSON", "XML", "HTML"], width=15)
        format_combo.grid(row=0, column=1, sticky=tk.W, padx=(10, 0), pady=2)

        # Output file
        ttk.Label(output_section, text="Output File (optional):").grid(row=1, column=0, sticky=tk.W, pady=2)
        output_entry = ttk.Entry(output_section, textvariable=self.output_file_var, width=35)
        output_entry.grid(row=1, column=1, sticky=tk.W+tk.E, padx=(10, 0), pady=2)
        ttk.Button(output_section, text="Browse",
                  command=lambda: self.browse_save_file()).grid(row=1, column=2, padx=(5, 0), pady=2)

        # Configure grid weights
        scrollable_frame.columnconfigure(0, weight=1)
        target_section.columnconfigure(1, weight=1)
        files_section.columnconfigure(1, weight=1)
        output_section.columnconfigure(1, weight=1)

    def create_results_tab(self):
        """Create the results tab with treeview and filtering."""
        # Create main frames
        filter_frame = ttk.Frame(self.results_frame)
        filter_frame.pack(fill=tk.X, padx=5, pady=5)

        tree_frame = ttk.Frame(self.results_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0, 5))

        # Filter controls
        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT, padx=(0, 5))
        self.filter_var = tk.StringVar()
        self.filter_var.trace('w', self.filter_results)
        filter_entry = ttk.Entry(filter_frame, textvariable=self.filter_var, width=30)
        filter_entry.pack(side=tk.LEFT, padx=(0, 10))
        ModernTooltip(filter_entry, "Filter results by hostname or IP address")

        # Filter options
        self.filter_type_var = tk.StringVar(value="hostname")
        ttk.Radiobutton(filter_frame, text="Hostname", variable=self.filter_type_var,
                       value="hostname").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Radiobutton(filter_frame, text="IP Address", variable=self.filter_type_var,
                       value="ip").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Radiobutton(filter_frame, text="Both", variable=self.filter_type_var,
                       value="both").pack(side=tk.LEFT, padx=(0, 20))

        # Results counter
        self.results_count_var = tk.StringVar(value="Results: 0")
        ttk.Label(filter_frame, textvariable=self.results_count_var).pack(side=tk.RIGHT)

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
        tree_scroll_x = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=tree_scroll_y.set, xscrollcommand=tree_scroll_x.set)

        # Pack treeview and scrollbars
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        tree_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)

        # Bind double-click event
        self.results_tree.bind("<Double-1>", self.on_result_double_click)

    def create_statistics_tab(self):
        """Create the statistics tab with real-time charts and metrics."""
        # Create main frames
        summary_frame = ttk.LabelFrame(self.stats_frame, text="Summary Statistics", padding=10)
        summary_frame.pack(fill=tk.X, padx=10, pady=5)

        performance_frame = ttk.LabelFrame(self.stats_frame, text="Performance Metrics", padding=10)
        performance_frame.pack(fill=tk.X, padx=10, pady=5)

        details_frame = ttk.LabelFrame(self.stats_frame, text="Detailed Statistics", padding=10)
        details_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Summary statistics
        stats_grid = [
            ("Total Subdomains Processed", "total_subdomains"),
            ("Successful Lookups", "successful_lookups"),
            ("Failed Lookups", "failed_lookups"),
            ("Wildcard Filtered", "wildcard_filtered"),
            ("Unique IP Addresses", "unique_ips"),
            ("Nameservers Used", "nameservers_used")
        ]

        for i, (label, key) in enumerate(stats_grid):
            row, col = i // 3, (i % 3) * 2
            ttk.Label(summary_frame, text="{label}:").grid(row=row, column=col, sticky=tk.W, padx=(0, 10), pady=2)
            self.stats_labels[key] = ttk.Label(summary_frame, text="0", style='Success.TLabel')
            self.stats_labels[key].grid(row=row, column=col+1, sticky=tk.W, padx=(0, 20), pady=2)

        # Performance metrics
        perf_metrics = [
            ("Queries per Second", "rate_per_second"),
            ("Elapsed Time", "elapsed_time"),
            ("Estimated Completion", "eta")
        ]

        for i, (label, key) in enumerate(perf_metrics):
            ttk.Label(performance_frame, text="{label}:").grid(row=0, column=i*2, sticky=tk.W, padx=(0, 10), pady=2)
            self.stats_labels[key] = ttk.Label(performance_frame, text="0", style='Success.TLabel')
            self.stats_labels[key].grid(row=0, column=i*2+1, sticky=tk.W, padx=(0, 20), pady=2)

        # Detailed statistics (scrollable text)
        details_text_frame = ttk.Frame(details_frame)
        details_text_frame.pack(fill=tk.BOTH, expand=True)

        self.details_text = scrolledtext.ScrolledText(details_text_frame, height=10, width=80)
        self.details_text.pack(fill=tk.BOTH, expand=True)

        # Refresh button
        ttk.Button(details_frame, text="Refresh Statistics",
                  command=self.refresh_statistics).pack(pady=(5, 0))

    def create_logs_tab(self):
        """Create the logs tab with filtering and search capabilities."""
        # Create main frames
        log_controls_frame = ttk.Frame(self.logs_frame)
        log_controls_frame.pack(fill=tk.X, padx=5, pady=5)

        log_display_frame = ttk.Frame(self.logs_frame)
        log_display_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0, 5))

        # Log controls
        ttk.Label(log_controls_frame, text="Log Level:").pack(side=tk.LEFT, padx=(0, 5))
        self.log_level_var = tk.StringVar(value="ALL")
        log_level_combo = ttk.Combobox(log_controls_frame, textvariable=self.log_level_var,
                                      values=["ALL", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                                      width=10)
        log_level_combo.pack(side=tk.LEFT, padx=(0, 10))
        log_level_combo.bind("<<ComboboxSelected>>", self.filter_logs)

        ttk.Label(log_controls_frame, text="Search:").pack(side=tk.LEFT, padx=(0, 5))
        self.log_search_var = tk.StringVar()
        self.log_search_var.trace('w', self.search_logs)
        search_entry = ttk.Entry(log_controls_frame, textvariable=self.log_search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=(0, 10))
        ModernTooltip(search_entry, "Search log messages")

        # Log controls buttons
        ttk.Button(log_controls_frame, text="Clear Logs",
                  command=self.clear_logs).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(log_controls_frame, text="Save Logs",
                  command=self.save_logs).pack(side=tk.LEFT, padx=(0, 5))

        # Auto-scroll checkbox
        self.auto_scroll_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(log_controls_frame, text="Auto-scroll",
                       variable=self.auto_scroll_var).pack(side=tk.RIGHT)

        # Log display
        self.log_text = scrolledtext.ScrolledText(log_display_frame, height=25, width=100,
                                                 font=('Consolas', 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # Configure text tags for different log levels
        self.log_text.tag_configure("DEBUG", foreground="#808080")
        self.log_text.tag_configure("INFO", foreground="#000000")
        self.log_text.tag_configure("WARNING", foreground="#ff8c00")
        self.log_text.tag_configure("ERROR", foreground="#d13438")
        self.log_text.tag_configure("CRITICAL", foreground="#d13438", font=('Consolas', 9, 'bold'))

    def setup_bindings(self):
        """Setup keyboard shortcuts and event bindings."""
        self.root.bind('<Control-s>', lambda e: self.start_enumeration())
        self.root.bind('<Control-q>', lambda e: self.root.quit())
        self.root.bind('<F1>', lambda e: self.show_help())
        self.root.bind('<F5>', lambda e: self.refresh_statistics())

        # Handle window closing
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def start_update_loop(self):
        """Start the GUI update loop for real-time updates."""
        self.update_gui()
        self.root.after(100, self.start_update_loop)  # Update every 100ms

    def update_gui(self):
        """Update GUI with data from queues."""
        # Update results
        try:
            while True:
                result = self.result_queue.get_nowait()
                self.add_result(result)
        except queue.Empty:
            pass

        # Update logs
        try:
            while True:
                log_entry = self.log_queue.get_nowait()
                self.add_log_entry(log_entry)
        except queue.Empty:
            pass

        # Update statistics
        try:
            while True:
                stats_update = self.stats_queue.get_nowait()
                self.update_statistics(stats_update)
        except queue.Empty:
            pass

    def browse_file(self, var, title):
        """Browse for a file and update the variable."""
        filename = filedialog.askopenfilename(title=title,
                                            filetypes=[("Text files", "*.txt"),
                                                     ("All files", "*.*")])
        if filename:
            var.set(filename)

    def browse_save_file(self):
        """Browse for save location."""
        filename = filedialog.asksaveasfilename(title="Save Output File",
                                              defaultextension=".txt",
                                              filetypes=[("Text files", "*.txt"),
                                                       ("CSV files", "*.csv"),
                                                       ("JSON files", "*.json"),
                                                       ("XML files", "*.xml"),
                                                       ("HTML files", "*.html"),
                                                       ("All files", "*.*")])
        if filename:
            self.output_file_var.set(filename)

    def start_enumeration(self):
        """Start the subdomain enumeration process."""
        if self.is_running:
            messagebox.showwarning("Already Running", "Enumeration is already in progress!")
            return

        # Validate inputs
        if not self.target_var.get().strip():
            messagebox.showerror("Invalid Input", "Please enter a target domain!")
            return

        # Clear previous results if needed
        if messagebox.askyesno("Clear Results", "Clear previous results before starting?"):
            self.clear_results()

        # Update UI state
        self.is_running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_var.set("Starting enumeration...")
        self.current_task_var.set("Initializing...")

        # Reset statistics
        self.stats['start_time'] = time.time()
        self.stats['end_time'] = None

        # Start enumeration in separate thread
        self.enumeration_thread = threading.Thread(target=self.run_enumeration, daemon=True)
        self.enumeration_thread.start()

        self.gui_logger.info("Enumeration started for target:", self.target_var.get())

    def stop_enumeration(self):
        """Stop the running enumeration process."""
        if not self.is_running:
            return

        self.is_running = False
        self.status_var.set("Stopping...")
        self.current_task_var.set("Cleaning up...")

        # Update UI state
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

        self.gui_logger.warning("Enumeration stopped by user")

    def run_enumeration(self):
        """Run the actual enumeration process."""
        try:
            # Create SubBrute instance
            subbrute = SubBrute(
                target=self.target_var.get().strip(),
                record_type=self.record_type_var.get(),
                subdomains_file=self.subdomains_file_var.get(),
                resolvers_file=self.resolvers_file_var.get(),
                process_count=self.process_count_var.get(),
                debug=self.verbose_var.get()
            )

            # Run enumeration and process results
            result_count = 0
            for hostname, record_type, addresses in subbrute.run_enumeration():
                if not self.is_running:
                    break

                result_count += 1
                result = {
                    'hostname': hostname,
                    'record_type': record_type,
                    'addresses': addresses,
                    'timestamp': datetime.now().strftime("%H:%M:%S")
                }

                # Add to queue for GUI update
                self.result_queue.put(result)

                # Update statistics
                self.stats['successful_lookups'] += 1
                for addr in addresses:
                    self.stats['unique_ips'].add(addr)
                    self.stats['record_types'][record_type] += 1

                # Update progress
                if result_count % 10 == 0:
                    elapsed = time.time() - self.stats['start_time']
                    self.stats['rate_per_second'] = result_count / elapsed if elapsed > 0 else 0

                    stats_update = {
                        'successful_lookups': self.stats['successful_lookups'],
                        'unique_ips': len(self.stats['unique_ips']),
                        'rate_per_second': self.stats['rate_per_second'],
                        'elapsed_time': elapsed
                    }
                    self.stats_queue.put(stats_update)

            # Enumeration completed
            self.stats['end_time'] = time.time()
            self.gui_logger.info("Enumeration completed: {result_count} results found")

        except Exception:
            self.gui_logger.error("Enumeration error: {e}")
            messagebox.showerror("Enumeration Error", "An error occurred: {str(e)}")

        finally:
            # Reset UI state
            self.is_running = False
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.status_var.set("Ready")
            self.current_task_var.set("Idle")

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
        self.results_count_var.set("Results: {len(self.results)}")

        # Auto-scroll to bottom
        if hasattr(self, 'results_tree'):
            self.results_tree.see(self.results_tree.get_children()[-1])

    def add_log_entry(self, log_entry):
        """Add a log entry to the logs display."""
        _timestamp = log_entry['timestamp']
        level = log_entry['level']
        _message = log_entry['message']

        # Format log line
        log_line = "[{timestamp}] {level:8} | {message}\n"

        # Insert with appropriate tag
        self.log_text.insert(tk.END, log_line, level)

        # Auto-scroll if enabled
        if self.auto_scroll_var.get():
            self.log_text.see(tk.END)

        # Limit log size (keep last 1000 lines)
        lines = int(self.log_text.index(tk.END).split('.')[0])
        if lines > 1000:
            self.log_text.delete('1.0', '{lines-1000}.0')

    def update_statistics(self, stats_update):
        """Update the statistics display."""
        for key, value in stats_update.items():
            if key in self.stats_labels:
                if key == 'rate_per_second':
                    self.stats_labels[key].config(text="{value:.2f}")
                elif key == 'elapsed_time':
                    self.stats_labels[key].config(text="{int(value//60):02d}:{int(value%60):02d}")
                else:
                    self.stats_labels[key].config(text=str(value))

    def filter_results(self, *args):
        """Filter the results based on search criteria."""
        filter_text = self.filter_var.get().lower()
        filter_type = self.filter_type_var.get()

        # Clear current display
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)

        # Filter and re-add results
        filtered_count = 0
        for result in self.results:
            show_result = False

            if not filter_text:
                show_result = True
            elif filter_type == "hostname" and filter_text in result['hostname'].lower():
                show_result = True
            elif filter_type == "ip" and any(filter_text in addr.lower() for addr in result['addresses']):
                show_result = True
            elif filter_type == "both" and (filter_text in result['hostname'].lower() or
                                           any(filter_text in addr.lower() for addr in result['addresses'])):
                show_result = True

            if show_result:
                self.results_tree.insert("", tk.END, values=(
                    result['hostname'],
                    result['record_type'],
                    ', '.join(result['addresses']),
                    result['timestamp']
                ))
                filtered_count += 1

        # Update counter
        self.results_count_var.set("Results: {filtered_count}/{len(self.results)}")

    def clear_results(self):
        """Clear all results and reset statistics."""
        self.results.clear()

        # Clear treeview
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)

        # Reset statistics
        self.stats = {
            'start_time': None,
            'end_time': None,
            'total_subdomains': 0,
            'successful_lookups': 0,
            'failed_lookups': 0,
            'wildcard_filtered': 0,
            'nameservers_used': 0,
            'rate_per_second': 0.0,
            'unique_ips': set(),
            'record_types': defaultdict(int)
        }

        # Update displays
        self.results_count_var.set("Results: 0")
        for label in self.stats_labels.values():
            label.config(text="0")

        self.gui_logger.info("Results and statistics cleared")

    def export_results(self, format_type):
        """Export results in the specified format."""
        if not self.results:
            messagebox.showwarning("No Results", "No results to export!")
            return

        # Get filename
        extensions = {
            'csv': '.csv',
            'json': '.json',
            'xml': '.xml',
            'html': '.html'
        }

        filename = filedialog.asksaveasfilename(
            title="Export Results as {format_type.upper()}",
            defaultextension=extensions.get(format_type, '.txt'),
            filetypes=[("{format_type.upper()} files", "*{extensions.get(format_type, '.txt')}"),
                      ("All files", "*.*")]
        )

        if not filename:
            return

        try:
            if format_type == 'csv':
                self.export_csv(filename)
            elif format_type == 'json':
                self.export_json(filename)
            elif format_type == 'xml':
                self.export_xml(filename)
            elif format_type == 'html':
                self.export_html(filename)

            messagebox.showinfo("Export Complete", "Results exported to {filename}")
            self.gui_logger.info("Results exported to {filename} ({format_type.upper()} format)")

        except Exception:
            messagebox.showerror("Export Error", "Failed to export results: {str(e)}")
            self.gui_logger.error("Export error: {e}")

    def export_csv(self, filename):
        """Export results to CSV format."""
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
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
                'statistics': {
                    'successful_lookups': self.stats['successful_lookups'],
                    'unique_ips': len(self.stats['unique_ips']),
                    'record_types': dict(self.stats['record_types'])
                }
            },
            'results': self.results
        }

        with open(filename, 'w', encoding='utf-8') as jsonfile:
            json.dump(export_data, jsonfile, indent=2, ensure_ascii=False)

    def export_xml(self, filename):
        """Export results to XML format."""
        root = ET.Element("subbrute_results")

        # Metadata
        metadata = ET.SubElement(root, "metadata")
        ET.SubElement(metadata, "target").text = self.target_var.get()
        ET.SubElement(metadata, "export_time").text = datetime.now().isoformat()
        ET.SubElement(metadata, "total_results").text = str(len(self.results))

        # Results
        results_elem = ET.SubElement(root, "results")
        for result in self.results:
            result_elem = ET.SubElement(results_elem, "result")
            ET.SubElement(result_elem, "hostname").text = result['hostname']
            ET.SubElement(result_elem, "record_type").text = result['record_type']
            ET.SubElement(result_elem, "timestamp").text = result['timestamp']

            addresses_elem = ET.SubElement(result_elem, "addresses")
            for addr in result['addresses']:
                ET.SubElement(addresses_elem, "address").text = addr

        # Write to file
        tree = ET.ElementTree(root)
        tree.write(filename, encoding='utf-8', xml_declaration=True)

    def export_html(self, filename):
        """Export results to HTML format."""
        html_content = """
<!DOCTYPE html>
<html>
<head>
    <title>SubBrute Results - {self.target_var.get()}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .stats {{ display: flex; justify-content: space-around; margin: 20px 0; }}
        .stat {{ text-align: center; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        .timestamp {{ font-size: 0.8em; color: #666; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>SubBrute Enumeration Results</h1>
        <p><strong>Target:</strong> {self.target_var.get()}</p>
        <p><strong>Export Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>

    <div class="stats">
        <div class="stat">
            <h3>{len(self.results)}</h3>
            <p>Total Results</p>
        </div>
        <div class="stat">
            <h3>{len(self.stats['unique_ips'])}</h3>
            <p>Unique IPs</p>
        </div>
        <div class="stat">
            <h3>{len(set(r['record_type'] for r in self.results))}</h3>
            <p>Record Types</p>
        </div>
    </div>

    <table>
        <thead>
            <tr>
                <th>Hostname</th>
                <th>Record Type</th>
                <th>IP Addresses</th>
                <th>Timestamp</th>
            </tr>
        </thead>
        <tbody>
"""

        for result in self.results:
            html_content += """
            <tr>
                <td>{result['hostname']}</td>
                <td>{result['record_type']}</td>
                <td>{', '.join(result['addresses'])}</td>
                <td class="timestamp">{result['timestamp']}</td>
            </tr>
"""

        html_content += """
        </tbody>
    </table>
</body>
</html>
"""

        with open(filename, 'w', encoding='utf-8') as htmlfile:
            htmlfile.write(html_content)

    def on_result_double_click(self, event):
        """Handle double-click on result item."""
        selection = self.results_tree.selection()
        if selection:
            item = self.results_tree.item(selection[0])
            hostname = item['values'][0]

            # Show detailed information
            self.show_result_details(hostname)

    def show_result_details(self, hostname):
        """Show detailed information about a result."""
        # Find the result
        result = next((r for r in self.results if r['hostname'] == hostname), None)
        if not result:
            return

        # Create details window
        details_window = tk.Toplevel(self.root)
        details_window.title("Details - {hostname}")
        details_window.geometry("500x400")
        details_window.transient(self.root)
        details_window.grab_set()

        # Create content
        frame = ttk.Frame(details_window, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            frame, text="Hostname: {result['hostname']}",
            font=('Arial', 12, 'bold')).pack(anchor=tk.W, pady=(0, 10))
        ttk.Label(frame, text="Record Type: {result['record_type']}").pack(anchor=tk.W, pady=2)
        ttk.Label(frame, text="Timestamp: {result['timestamp']}").pack(anchor=tk.W, pady=2)

        ttk.Label(frame, text="IP Addresses:", font=('Arial', 10, 'bold')).pack(anchor=tk.W, pady=(10, 5))
        for addr in result['addresses']:
            ttk.Label(frame, text="  • {addr}").pack(anchor=tk.W, pady=1)

        # Buttons
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, pady=(20, 0))

        ttk.Button(button_frame, text="Copy Hostname",
                  command=lambda: self.copy_to_clipboard(hostname)).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(
            button_frame, text="Copy All IPs",
            command=lambda: self.copy_to_clipboard(
                ', '.join(result['addresses']))).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Close",
                  command=details_window.destroy).pack(side=tk.RIGHT)

    def copy_to_clipboard(self, text):
        """Copy text to clipboard."""
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("Copied", "Copied to clipboard: {text}")

    def filter_logs(self, event=None):
        """Filter logs by level."""
        # This would filter the log display - implementation depends on log storage
        pass

    def search_logs(self, *args):
        """Search logs for specific text."""
        # This would search through logs - implementation depends on log storage
        pass

    def clear_logs(self):
        """Clear the log display."""
        self.log_text.delete('1.0', tk.END)
        self.gui_logger.info("Log display cleared")

    def save_logs(self):
        """Save logs to file."""
        filename = filedialog.asksaveasfilename(
            title="Save Logs",
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
        )

        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as logfile:
                    logfile.write(self.log_text.get('1.0', tk.END))
                messagebox.showinfo("Logs Saved", "Logs saved to {filename}")
            except Exception:
                messagebox.showerror("Save Error", "Failed to save logs: {str(e)}")

    def refresh_statistics(self):
        """Refresh the statistics display."""
        if self.stats['start_time']:
            current_time = self.stats['end_time'] or time.time()
            elapsed = current_time - self.stats['start_time']

            # Update all statistics
            stats_update = {
                'total_subdomains': self.stats['total_subdomains'],
                'successful_lookups': self.stats['successful_lookups'],
                'failed_lookups': self.stats['failed_lookups'],
                'wildcard_filtered': self.stats['wildcard_filtered'],
                'unique_ips': len(self.stats['unique_ips']),
                'nameservers_used': self.stats['nameservers_used'],
                'rate_per_second': self.stats['successful_lookups'] / elapsed if elapsed > 0 else 0,
                'elapsed_time': elapsed
            }

            self.update_statistics(stats_update)

            # Update detailed statistics
            end_time_str = (
                datetime.fromtimestamp(self.stats['end_time']).strftime('%Y-%m-%d %H:%M:%S')
                if self.stats['end_time'] else 'Running...'
            )
            details = (
                "Detailed Statistics:\n\n"
                "Target Domain: {}\n".format(self.target_var.get()) +
                "Record Type: {}\n".format(self.record_type_var.get()) +
                "Process Count: {}\n\n".format(self.process_count_var.get()) +
                "Timing:\n" +
                "- Start Time: {}\n".format(
                    datetime.fromtimestamp(self.stats['start_time']).strftime('%Y-%m-%d %H:%M:%S')
                ) +
                "- End Time: {}\n".format(end_time_str) +
                "- Duration: {:02d}:{:02d}:{:02d}\n\n".format(
                    int(elapsed // 3600), int((elapsed % 3600) // 60), int(elapsed % 60)
                ) +
                "Record Type Distribution:\n"
            )

            for record_type, count in self.stats['record_types'].items():
                details += "- {record_type}: {count}\n"

            self.details_text.delete('1.0', tk.END)
            self.details_text.insert('1.0', details)

    def show_help(self):
        """Show help documentation."""
        help_window = tk.Toplevel(self.root)
        help_window.title("SubBrute GUI Help")
        help_window.geometry("800x600")
        help_window.transient(self.root)

        # Create notebook for help sections
        help_notebook = ttk.Notebook(help_window)
        help_notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Quick Start tab
        quickstart_frame = ttk.Frame(help_notebook)
        help_notebook.add(quickstart_frame, text="Quick Start")

        quickstart_text = scrolledtext.ScrolledText(quickstart_frame, wrap=tk.WORD)
        quickstart_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        quickstart_text.insert('1.0', """
Quick Start Guide:

1. Configuration Tab:
   - Enter your target domain (e.g., example.com)
   - Select DNS record type (usually 'A' for IPv4 addresses)
   - Choose subdomains wordlist file (names.txt)
   - Select DNS resolvers file (resolvers.txt)
   - Adjust process count based on your system (16 is default)

2. Starting Enumeration:
   - Click "▶ Start Enumeration" or press Ctrl+S
   - Monitor progress in the status bar
   - View real-time results in the Results tab

3. Viewing Results:
   - Switch to Results tab to see discovered subdomains
   - Use filter to search through results
   - Double-click any result for detailed information

4. Monitoring Progress:
   - Check Statistics tab for real-time metrics
   - View logs in the Logs tab for detailed information
   - Use the progress bar to monitor completion

5. Exporting Results:
   - Use toolbar buttons to export in various formats
   - Choose from CSV, JSON, XML, or HTML
   - Results include timestamps and metadata
""")

        # Keyboard Shortcuts tab
        shortcuts_frame = ttk.Frame(help_notebook)
        help_notebook.add(shortcuts_frame, text="Shortcuts")

        shortcuts_text = scrolledtext.ScrolledText(shortcuts_frame, wrap=tk.WORD)
        shortcuts_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        shortcuts_text.insert('1.0', """
Keyboard Shortcuts:

Ctrl+S       - Start enumeration
Ctrl+Q       - Quit application
F1           - Show this help
F5           - Refresh statistics

Mouse Actions:
Double-click result  - Show detailed information
Right-click         - Context menu (where available)
""")

        # About tab
        about_frame = ttk.Frame(help_notebook)
        help_notebook.add(about_frame, text="About")

        about_text = scrolledtext.ScrolledText(about_frame, wrap=tk.WORD)
        about_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        about_text.insert('1.0', """
SubBrute GUI v2.0

A modern graphical interface for the SubBrute subdomain enumeration tool.

Features:
- Tabbed interface with configuration, results, statistics, and logs
- Real-time progress monitoring and statistics
- Advanced export functionality (CSV, JSON, XML, HTML)
- Modern UI with tooltips and help system
- Comprehensive logging and filtering options
- Multi-threaded DNS resolution
- Wildcard detection and filtering

This tool is designed for security researchers, penetration testers, and
system administrators who need to discover subdomains of target domains.

License: MIT
Author: Enhanced SubBrute Team

For more information and updates, visit:
https://github.com/example/subbrute-gui
""")

        # Close button
        ttk.Button(help_window, text="Close", command=help_window.destroy).pack(pady=10)

    def on_closing(self):
        """Handle application closing."""
        if self.is_running:
            if messagebox.askokcancel("Quit", "Enumeration is running. Stop and quit?"):
                self.stop_enumeration()
                self.root.after(1000, self.root.destroy)  # Give time for cleanup
        else:
            self.root.destroy()


def main():
    """Main entry point for the GUI application."""
    root = tk.Tk()
    SubBruteGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
