#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Backward-compatible entry point. Use the subbrute.gui_app module directly."""
import sys

from subbrute.gui_app import ResultWindow, main, main_advanced  # noqa: F401
from subbrute.gui_logger import AdvancedLogger  # noqa: F401
from subbrute.gui_widgets import AdvancedTooltip, SecurityValidator  # noqa: F401

if __name__ == "__main__":
    # Permettre le choix entre interface de test et avancee
    if len(sys.argv) > 1 and sys.argv[1] == "--advanced":
        sys.exit(main_advanced())
    else:
        main()
