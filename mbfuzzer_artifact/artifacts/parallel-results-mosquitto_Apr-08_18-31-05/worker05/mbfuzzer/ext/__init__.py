"""
OCP Extension Bootstrap for MBFuzzer.

This package applies all runtime extensions to MBFuzzer's original source code
**without modifying any original file**.  Import this package once (e.g. from
``fuzz_gcov.py``) before ``fuzz.main()`` is called.

Extensions applied:
  1. ``globals_ext``   – environment-variable overrides for globals.py
  2. ``client_patch``  – longer connect() timeout for Docker networking
  3. ``report_ext``    – paper-aligned summary appended to fuzzing report
"""

from ext.globals_ext import apply as _apply_globals
from ext.client_patch import apply as _apply_client
from ext.report_ext import apply as _apply_report


def apply_all():
    """Apply every extension in the correct order."""
    _apply_globals()
    _apply_client()
    _apply_report()
