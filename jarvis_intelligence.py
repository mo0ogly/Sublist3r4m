#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Backward-compatible entry point. Use the jarvis package directly."""
from jarvis import *  # noqa: F401,F403

if __name__ == "__main__":
    from jarvis.main import interactive_enhanced
    interactive_enhanced()
