"""Configuration defaults for the isolated ghidra-mcp-2 instance.

Every value can be overridden by the ghidra-mcp-2 init unit.  Nothing in this
module refers to the original Voxtalk project or its runtime paths.
"""

import os

INSTANCE_NAME = os.environ.get("GHIDRA_MCP_INSTANCE_NAME", "ghidra-mcp-2")
PROJECT_DIR = os.environ.get("GHIDRA_MCP_PROJECT_DIR", "/home/harri/ghidra_projects_2")
PROJECT_NAME = os.environ.get("GHIDRA_MCP_PROJECT_NAME", "GhidraMCP2")
DEFAULT_PROGRAM_PATH = os.environ.get("GHIDRA_MCP_DEFAULT_PROGRAM", "")
DEFAULT_CATEGORY = os.environ.get("GHIDRA_MCP_DEFAULT_CATEGORY", "Types")
IMPORT_ROOT = os.environ.get("GHIDRA_MCP_IMPORT_ROOT", "")
PROJECTS_FILE = os.environ.get(
    "GHIDRA_MCP_PROJECTS_FILE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "projects.json"))
