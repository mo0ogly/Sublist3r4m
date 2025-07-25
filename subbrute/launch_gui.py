#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
SubBrute GUI Launcher

This script handles Python 2/3 compatibility and launches the GUI
with proper error handling and dependency checking.
"""

import sys
import os

def check_dependencies():
    """Check if all required dependencies are available."""
    missing_deps = []
    
    # Check Tkinter
    try:
        if sys.version_info[0] >= 3:
            import tkinter
            import tkinter.ttk
            import tkinter.filedialog
            import tkinter.messagebox
            import tkinter.scrolledtext
        else:
            import Tkinter as tkinter
            import ttk
            import tkFileDialog as filedialog
            import tkMessageBox as messagebox
            import ScrolledText as scrolledtext
    except ImportError as e:
        missing_deps.append("Tkinter/tkinter - " + str(e))
    
    # Check other dependencies
    try:
        import threading
        import queue if sys.version_info[0] >= 3 else Queue
        import json
        import csv
        import xml.etree.ElementTree
        from datetime import datetime
        from collections import defaultdict
    except ImportError as e:
        missing_deps.append("Standard library module - " + str(e))
    
    return missing_deps

def show_error_message(message):
    """Show error message using available methods."""
    print("ERROR: " + message)
    print("=" * 50)
    
    # Try to show GUI error if possible
    try:
        if sys.version_info[0] >= 3:
            import tkinter
            import tkinter.messagebox
            root = tkinter.Tk()
            root.withdraw()
            tkinter.messagebox.showerror("SubBrute GUI Error", message)
        else:
            import Tkinter
            import tkMessageBox
            root = Tkinter.Tk()
            root.withdraw()
            tkMessageBox.showerror("SubBrute GUI Error", message)
    except:
        pass

def main():
    """Main launcher function."""
    print("SubBrute GUI v2.0 - Starting...")
    print("Python version:", sys.version)
    
    # Check dependencies
    missing = check_dependencies()
    if missing:
        error_msg = "Missing dependencies:\n\n" + "\n".join(missing)
        error_msg += "\n\nPlease install the required packages:\n"
        error_msg += "- For Ubuntu/Debian: sudo apt-get install python-tk python3-tk\n"
        error_msg += "- For CentOS/RHEL: sudo yum install tkinter\n"
        error_msg += "- For Windows: Tkinter should be included with Python"
        
        show_error_message(error_msg)
        return 1
    
    # Check if SubBrute engine is available
    try:
        # Add current directory to path
        current_dir = os.path.dirname(os.path.abspath(__file__))
        if current_dir not in sys.path:
            sys.path.insert(0, current_dir)
        
        # Try to import SubBrute components
        import subbrute
        print("SubBrute engine found")
        
    except ImportError as e:
        error_msg = f"Cannot import SubBrute engine: {e}\n\n"
        error_msg += "Please ensure subbrute.py is in the same directory as this script."
        show_error_message(error_msg)
        return 1
    
    # Launch GUI
    try:
        print("Launching GUI...")
        
        # Import and run the GUI
        from subbrute_gui import main as gui_main
        gui_main()
        
        print("GUI closed normally")
        return 0
        
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        return 0
        
    except Exception as e:
        error_msg = f"Error launching GUI: {e}\n\n"
        error_msg += "This might be due to missing system dependencies or display issues."
        show_error_message(error_msg)
        return 1

if __name__ == "__main__":
    sys.exit(main())