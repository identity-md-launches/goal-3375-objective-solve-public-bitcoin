#!/usr/bin/env python3
"""Offline entry point. Use python3 -I -B private-search/run.py."""
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from kangaroo.cli import guarded_main

if __name__ == "__main__":
    raise SystemExit(guarded_main())
