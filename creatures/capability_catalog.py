"""Explicit v2 capability metadata for the MCP bridge.

This is intentionally a closed manifest: adding a tool without classifying
it makes the static audit fail.  It is an agent-facing safety/discovery layer,
not an authorization mechanism; Ghidra remains the authority for mutations.
"""

from __future__ import annotations

import ast
from pathlib import Path


READ_TOOLS = frozenset((
    "list_methods", "list_classes", "list_class_methods", "propose_struct_fields", "decompile_function", "list_segments", "list_imports", "list_exports", "list_namespaces", "list_data_items", "search_functions_by_name", "get_function_by_address", "get_current_address", "get_current_function", "list_functions", "decompile_function_by_address", "disassemble_function", "get_xrefs_to", "get_xrefs_from", "find_next_symbol", "find_address_references", "get_function_xrefs", "list_callees", "get_function_callers", "get_function_call_graph", "get_struct_layout", "get_instruction_facts", "get_function_exact_facts", "get_address_exact_facts", "get_type_exact_facts", "get_exact_neighborhood", "get_function_hash", "analyze_dataflow", "get_basic_blocks", "get_function_body_bytes", "search_bytes", "get_stack_variables", "get_stack_depth", "get_abi_summary", "get_referenced_strings", "scan_unnamed_labels", "find_class_ownership_strings", "classify_function_inventory", "get_allocation_site_info", "resolve_call_site_context", "get_seh_frame_info", "map_function_by_debug_strings", "find_thunk_candidates", "classify_pointer_provenance", "find_hook_point", "list_strings", "list_programs", "list_projects", "list_scripts", "list_committed_variables", "find_vtable_candidates", "trace_vtable_assignments", "resolve_vtable", "get_comments", "get_bytes", "read_float", "read_double", "read_int", "read_pointer_array", "read_float_matrix", "resolve_switch_dispatch", "read_int_array", "read_float_array", "read_double_array", "trace_fpu_stack", "get_guidance",
))
REVIEW_TOOLS = frozenset((
    "class_structure_diagnostic", "retype_variable_at", "batch_decompile", "save", "analyze", "run_script",
))
WRITE_TOOLS = frozenset((
    "promote_class_structure_fields", "rename_function", "rename_data", "rename_variable", "set_decompiler_comment", "set_disassembly_comment", "rename_function_by_address", "set_function_prototype", "set_local_variable_type", "set_this_type", "materialize_ecx_thiscall_callback", "manage_namespace", "set_parameter", "set_return_type", "edit_structure_field", "create_enum", "create_typedef", "create_function_pointer_type", "batch_set_comments", "switch_program", "switch_project", "import_program", "apply_map_symbols", "rename_variable_by_address", "uncommit_variable", "set_full_prototype", "materialize_ecx_thiscall_receiver", "create_function", "delete_function", "create_vtable_type", "create_label", "set_data_type", "create_structure", "create_structure_from_offsets",
))


def effect_for(tool: str) -> str | None:
    if tool in READ_TOOLS:
        return "read"
    if tool in REVIEW_TOOLS:
        return "review"
    if tool in WRITE_TOOLS:
        return "write"
    return None


def domain_for(tool: str) -> str:
    if any(token in tool for token in ("type", "struct", "enum", "typedef", "class_", "namespace", "vtable")):
        return "type-recovery"
    if any(token in tool for token in ("xref", "call", "dataflow", "pointer_provenance", "allocation", "seh", "hook", "fpu", "stack", "abi")):
        return "control-flow-and-tracing"
    if any(token in tool for token in ("decompile", "disassemble", "instruction", "basic_block", "function_body", "function_hash")):
        return "code-inspection"
    if any(token in tool for token in ("bytes", "read_", "strings", "segments", "imports", "exports", "data_items")):
        return "binary-data"
    if any(token in tool for token in ("rename", "comment", "label", "set_", "create_", "delete_", "save", "switch_program", "switch_project", "import_program", "apply_map_symbols")):
        return "program-mutation"
    return "program-discovery"


def evidence_tier(effect: str) -> str:
    if effect == "read":
        return "mechanical-or-derived"
    if effect == "review":
        return "operator-review-required"
    return "mutation"


def tool_names_from_bridge(bridge_path: Path) -> list[tuple[str, set[str]]]:
    """Return every MCP tool and its argument names without importing the bridge."""
    tree = ast.parse(bridge_path.read_text(encoding="utf-8"))
    result = []
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef):
            continue
        is_tool = any(
            isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
            and isinstance(d.func.value, ast.Name) and d.func.value.id == "mcp" and d.func.attr == "tool"
            for d in node.decorator_list
        )
        if is_tool:
            result.append((node.name, {arg.arg for arg in node.args.args}))
    return result


def catalog(bridge_path: Path) -> dict:
    tools = []
    for name, args in tool_names_from_bridge(bridge_path):
        effect = effect_for(name)
        if effect is None:
            raise ValueError(f"Tool lacks capability metadata: {name}")
        tools.append({
            "name": name,
            "domain": domain_for(name),
            "effect": effect,
            "evidence_tier": evidence_tier(effect),
            "confirmation_required": effect == "write",
            "pagination": "offset-limit" if {"offset", "limit"} <= args else "bounded" if "limit" in args else "none",
        })
    return {"schema_version": "2.0", "tools": sorted(tools, key=lambda item: item["name"])}
