#!/usr/bin/env python3
"""Static MCP/HTTP surface audit for ghidra-mcp-2.

This deliberately parses source only: it never opens an MCP connection,
starts Ghidra, or accesses a project.  Run it after every surface change to
keep the bridge and headless API contracts reviewable.
"""

from __future__ import annotations

import argparse
import ast
import json
from collections import Counter
from pathlib import Path
from capability_catalog import effect_for


ROOT = Path(__file__).resolve().parent
BRIDGE = ROOT / "bridge_mcp_ghidra.py"
SERVER = ROOT / "ghidra_headless_server.py"
READ_PREFIXES = ("get_", "list_", "find_", "search_", "read_", "scan_", "trace_", "classify_", "map_", "resolve_", "analyze_", "disassemble_", "decompile_", "propose_")
WRITE_PREFIXES = ("set_", "rename_", "create_", "delete_", "edit_", "manage_", "promote_", "switch_", "batch_set_")


def literal(value: ast.AST) -> str | None:
    return value.value if isinstance(value, ast.Constant) and isinstance(value.value, str) else None


def is_tool(node: ast.FunctionDef) -> bool:
    return any(
        isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
        and isinstance(d.func.value, ast.Name) and d.func.value.id == "mcp" and d.func.attr == "tool"
        for d in node.decorator_list
    )


def called_endpoints(node: ast.FunctionDef) -> list[dict[str, str]]:
    calls = []
    for call in ast.walk(node):
        if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name):
            continue
        transport = call.func.id
        if transport not in {"safe_get", "safe_get_json", "safe_post", "safe_post_json", "safe_post_json_result"}:
            continue
        endpoint = literal(call.args[0]) if call.args else None
        calls.append({"endpoint": endpoint or "<dynamic>", "transport": transport})
    return calls


def dictionary_keys(source: str, method: str) -> set[str]:
    """Return literal keys from the handlers dictionary in one HTTP method."""
    tree = ast.parse(source)
    method_node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == method)
    keys: set[str] = set()
    for assignment in ast.walk(method_node):
        if isinstance(assignment, ast.Assign) and isinstance(assignment.value, ast.Dict):
            for key in assignment.value.keys:
                item = literal(key) if key else None
                if item is not None:
                    keys.add(item)
    return keys


def classification(name: str) -> str:
    """Read the closed v2 manifest instead of guessing from a tool prefix."""
    return effect_for(name) or "unclassified"


def audit() -> dict:
    bridge_tree = ast.parse(BRIDGE.read_text())
    server_source = SERVER.read_text()
    server_get = dictionary_keys(server_source, "do_GET")
    server_post = dictionary_keys(server_source, "do_POST")
    tools = []
    for node in bridge_tree.body:
        if isinstance(node, ast.FunctionDef) and is_tool(node):
            calls = called_endpoints(node)
            tools.append({"tool": node.name, "classification": classification(node.name), "calls": calls})
    mapped = {c["endpoint"] for tool in tools for c in tool["calls"] if c["endpoint"] != "<dynamic>"}
    unclassified = sorted(t["tool"] for t in tools if t["classification"] == "unclassified")
    return {
        "bridge_tools": len(tools),
        "bridge_by_classification": dict(sorted(Counter(t["classification"] for t in tools).items())),
        "server_get_endpoints": len(server_get),
        "server_post_endpoints": len(server_post),
        "mapped_endpoints": len(mapped),
        "bridge_endpoints_missing_from_server": sorted(mapped - server_get - server_post),
        "server_endpoints_not_exposed_by_bridge": sorted((server_get | server_post) - mapped - {"", "methods", "guidance"}),
        "tools_missing_capability_metadata": unclassified,
        "tools": tools,
    }


def markdown(report: dict) -> str:
    lines = [
        "# ghidra-mcp-2 static surface audit",
        "",
        "This report is source-only; no MCP endpoint or Ghidra project was contacted.",
        "",
        "## Inventory",
        "",
        f"- MCP tools: {report['bridge_tools']}",
        f"- MCP classification: {', '.join(f'{k}={v}' for k, v in report['bridge_by_classification'].items())}",
        f"- Headless GET endpoints: {report['server_get_endpoints']}",
        f"- Headless POST endpoints: {report['server_post_endpoints']}",
        f"- Bridge-mapped endpoints: {report['mapped_endpoints']}",
        "",
        "## Contract gaps",
        "",
        "- Bridge endpoints missing from server: " + (", ".join(report["bridge_endpoints_missing_from_server"]) or "none"),
        "- Server endpoints not exposed by bridge: " + (", ".join(report["server_endpoints_not_exposed_by_bridge"]) or "none"),
        "- Tools missing capability metadata: " + (", ".join(report["tools_missing_capability_metadata"]) or "none"),
        "",
        "## Refactor backlog",
        "",
        "1. Preserve the specialised tracing and evidence tools; they encode valuable RE workflows and should not be collapsed into generic CRUD endpoints.",
        "2. Add explicit capability metadata (domain, read/write effect, confidence/evidence tier, pagination) rather than relying on tool-name prefixes.",
        "3. Split the broad catalogue into discoverable namespaces/resources while retaining a compatibility catalog during the v2 transition.",
        "4. Normalize duplicate or alias operations only after target-based contract tests confirm equivalent semantics and response shapes.",
        "5. Add static contract checking to CI: every bridge call must resolve to a declared handler and every mutation must be labelled as such.",
        "",
        "## Tool map",
        "",
        "| Tool | Effect | Endpoint calls |",
        "| --- | --- | --- |",
    ]
    for tool in report["tools"]:
        calls = ", ".join(f"{c['transport']}:{c['endpoint']}" for c in tool["calls"]) or "none"
        lines.append(f"| `{tool['tool']}` | {tool['classification']} | {calls} |")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Static ghidra-mcp-2 surface audit")
    parser.add_argument("--format", choices=("json", "markdown"), default="markdown")
    args = parser.parse_args()
    report = audit()
    if report["tools_missing_capability_metadata"]:
        raise SystemExit("Capability metadata is required for every MCP tool")
    print(json.dumps(report, indent=2) if args.format == "json" else markdown(report), end="")


if __name__ == "__main__":
    main()
