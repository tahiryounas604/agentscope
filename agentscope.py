#!/usr/bin/env python3
"""Top-level entry point shim: python3 agentscope.py scan <path> ..."""
from agentscope.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
