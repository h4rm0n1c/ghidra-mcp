#!/usr/bin/env python3
"""Safely import a target into the isolated ghidra-mcp-2 project.

The import root is opt-in.  This administrative command refuses to run while
the instance server owns the project, and it never accepts a path outside the
configured root.
"""

import argparse
import os
from pathlib import Path
import subprocess
import sys
from urllib.error import URLError
from urllib.request import urlopen

from instance_config import IMPORT_ROOT, PROJECT_DIR, PROJECT_NAME


def main() -> int:
    parser = argparse.ArgumentParser(description="Import a target into ghidra-mcp-2")
    parser.add_argument("source", help="Target path below GHIDRA_MCP_IMPORT_ROOT")
    parser.add_argument("--analyze", action="store_true", help="Run initial Ghidra analysis after import")
    args = parser.parse_args()

    if not IMPORT_ROOT:
        parser.error("GHIDRA_MCP_IMPORT_ROOT must be configured before importing a target")
    root = Path(IMPORT_ROOT).resolve(strict=True)
    source = Path(args.source).resolve(strict=True)
    if not source.is_file() or not source.is_relative_to(root):
        parser.error("source must be a regular file beneath GHIDRA_MCP_IMPORT_ROOT")
    try:
        urlopen("http://127.0.0.1:8082/methods", timeout=1)
    except URLError:
        pass
    else:
        parser.error("stop ghidra-mcp-2 before importing; its server owns the project")

    ghidra_dir = Path(os.environ.get("GHIDRA_INSTALL_DIR", "/opt/ghidra_12.1_PUBLIC"))
    analyze_headless = ghidra_dir / "support" / "analyzeHeadless"
    if not analyze_headless.is_file():
        parser.error(f"analyzeHeadless not found: {analyze_headless}")
    command = [str(analyze_headless), PROJECT_DIR, PROJECT_NAME, "-import", str(source)]
    if not args.analyze:
        command.append("-noanalysis")
    subprocess.run(command, check=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
