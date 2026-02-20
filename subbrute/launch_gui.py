#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
SubBrute GUI Launcher

This script handles dependency checking and launches the GUI
with proper error handling.
"""

import os
import sys


def check_dependencies():
    """Check if all required dependencies are available."""
    missing_deps = []

    # Check Tkinter
    try:
        import tkinter  # noqa: F401
        import tkinter.filedialog  # noqa: F401
        import tkinter.messagebox  # noqa: F401
        import tkinter.scrolledtext  # noqa: F401
        import tkinter.ttk  # noqa: F401
    except ImportError as e:
        missing_deps.append("tkinter - " + str(e))

    # Check other dependencies
    try:
        import csv  # noqa: F401
        import json  # noqa: F401
        import queue  # noqa: F401
        import threading  # noqa: F401
        import xml.etree.ElementTree  # noqa: F401
        from collections import defaultdict  # noqa: F401
        from datetime import datetime  # noqa: F401
    except ImportError as e:
        missing_deps.append("Standard library module - " + str(e))

    return missing_deps


def show_error_message(message):
    """Show error message using available methods."""
    print("ERROR: " + message)
    print("=" * 50)

    # Try to show GUI error if possible
    try:
        import tkinter
        import tkinter.messagebox
        root = tkinter.Tk()
        root.withdraw()
        tkinter.messagebox.showerror("SubBrute GUI Error", message)
    except Exception:
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
        import subbrute  # noqa: F401
        print("SubBrute engine found")

    except ImportError as e:
        error_msg = "Cannot import SubBrute engine: {}\n\n".format(e)
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
        error_msg = "Error launching GUI: {}\n\n".format(e)
        error_msg += "This might be due to missing system dependencies or display issues."
        show_error_message(error_msg)
        return 1


if __name__ == "__main__":
    sys.exit(main())
