#!/usr/bin/env python3
"""Asynx6 Web Scanner V2 — entry point.

Thin wrapper that delegates to the package CLI.
"""

from __future__ import annotations

import sys

from asynx6.cli import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))