# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import sys
import json
import requests
import argparse
import logging
from urllib.parse import urljoin

from mcp.server.fastmcp import FastMCP
from instance_config import DEFAULT_CATEGORY, INSTANCE_NAME
from capability_catalog import catalog

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8084/"

logger = logging.getLogger(__name__)

mcp = FastMCP(INSTANCE_NAME)

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER

def safe_get(endpoint: str, params: dict = None) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = urljoin(ghidra_server_url, endpoint)

    try:
        response = requests.get(url, params=params, timeout=30)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

def safe_post(endpoint: str, data: dict | str, timeout: int = 30) -> str:
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=timeout)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=timeout)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

def safe_post_json(endpoint: str, data: dict) -> str:
    """POST with JSON body instead of form-encoded."""
    try:
        url = urljoin(ghidra_server_url, endpoint)
        response = requests.post(url, json=data, timeout=30)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"


def safe_post_json_result(endpoint: str, data: dict) -> dict:
    """POST JSON and preserve the server's structured response when possible."""
    raw = safe_post_json(endpoint, data)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"error": raw}


def safe_get_json(endpoint: str, params: dict = None) -> dict | list:
    """GET and return parsed JSON.  Returns {"error": ...} on failure."""
    if params is None:
        params = {}
    url = urljoin(ghidra_server_url, endpoint)
    try:
        response = requests.get(url, params=params, timeout=30)
        response.encoding = "utf-8"
        if response.ok:
            return response.json()
        return {"error": f"HTTP {response.status_code}: {response.text.strip()[:200]}"}
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# MCP resources (loaded into agent context automatically on connect)
# ---------------------------------------------------------------------------

@mcp.resource("oldmac-re://program")
def program_resource() -> str:
    """Current Ghidra program context — loaded automatically.

    Shows which binary is currently loaded, its base address, function count,
    and what other programs are available in the project.  This is essential
    context because all addresses, functions, and segments are relative to
    the currently active program.
    """
    import json

    current = safe_get_json("get_current_address")
    programs = safe_get_json("list_programs")

    program_info = {"active": current, "available": programs} if not isinstance(current, dict) or "error" not in current else {"error": str(current)}
    if isinstance(programs, dict) and "error" not in programs:
        program_info["available"] = programs

    return json.dumps(program_info, indent=2, default=str)


@mcp.resource("oldmac-re://guidance")
def guidance_resource() -> str:
    """Read classic Macintosh RE workflow and known limitations."""
    from pathlib import Path
    return (Path(__file__).resolve().parents[1] / "GUIDANCE.md").read_text()


@mcp.resource("oldmac-re://capabilities")
def capabilities_resource() -> str:
    """Explicit v2 tool metadata: domain, effect, evidence tier and pagination.

    Use this before selecting tools.  `write` operations mutate the active program; `review` operations may be computationally expensive or
    produce interpretation-dependent results.
    """
    result = catalog(__import__("pathlib").Path(__file__))
    result["tools"] += [{"name":"find_function_pointer_tables","effect":"read","domain":"indirect-calls"}, {"name":"resolve_function_pointer_table","effect":"write","domain":"indirect-calls"}, {"name":"prepare_mac_resources","effect":"write","domain":"resource-extraction"}, {"name":"import_raw_68k","effect":"write","domain":"program-import"}]
    result["target"] = "Classic Macintosh 68k; see oldmac-re://guidance for limitations"
    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# MCP tools
# ---------------------------------------------------------------------------

@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> dict:
    """
    List all function names in the current Ghidra program with pagination.
    """
    return safe_get_json("list_functions", {"offset": offset, "limit": limit})

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> dict:
    """
    List all namespace/class names in the program with pagination.
    """
    return safe_get_json("classes", {"offset": offset, "limit": limit})

@mcp.tool()
def list_class_methods(class_name: str, offset: int = 0, limit: int = 500) -> dict:
    """
    Complete method list (name + address) for ONE class/namespace, no caps.

    list_classes truncates every class to its first 10 method NAMES (no
    addresses at all) plus 3 sample addresses total for the whole class --
    for any class bigger than that (StrBuffer had 19 methods, CSpeaker had
    67), the only way to get a specific method's address was a separate
    search_functions_by_name round-trip per method, repeatedly. This
    resolves the real Ghidra namespace and returns every direct-child
    Function symbol's name + address in one call.
    """
    return safe_get_json("list_class_methods",
                          {"class_name": class_name, "offset": offset, "limit": limit})

# Mac port: x86-dependent tool not registered.
def propose_struct_fields(address: str, this_param_index: int = 0) -> dict:
    """
    Propose a struct field layout by tracing a function's PCODE, not decompile text.

    Mechanizes the single most-repeated manual task in struct-building RE
    work: reading a constructor/method's decompile and converting every
    `this`-relative pointer-arithmetic expression into a byte offset by
    hand. Walks every LOAD/STORE pcode op AND every CALL's arguments in
    the function, traces each address/argument operand backward through
    COPY/CAST/INT_ADD/PTRADD/PTRSUB chains, and if it resolves to
    this_param_index's own HighVariable plus a constant offset, records
    that offset. Validated live against CSpeakerPage::construct: the
    direct LOAD/STORE signal alone found only 7 of the ~12 real fields --
    the rest, the sub-object boundaries, only show up as `this+N` passed
    into a sub-constructor call (e.g. `construct_field_0x30_body(this +
    0xc)`), which is how most real fields in this project were actually
    found by hand. Returns an offset-sorted proposal: for each offset,
    sizes_seen, size_ambiguous (true if two DIRECT accesses at the same
    offset disagreed on width -- inspect manually, don't just take the
    larger one), reads/writes counts, passed_to_calls (callee name + arg
    index, when a this+N pointer was handed to another function), and up
    to a few sample instruction addresses. Also reports
    untraced_this_relative_accesses (LOAD/STORE ops that couldn't be
    resolved to a constant offset -- not necessarily a problem, just
    informational).

    This is a STARTING POINT for create_structure/
    create_structure_from_offsets, not a finished field list -- field
    NAMES, semantic roles, and sub-object SIZES still require reading the
    surrounding code (a passed_to_calls hit tells you a sub-object starts
    at that offset, not how big it is).

    Args:
        address: hex address of (or inside) the target function
        this_param_index: 0-based parameter index to trace from (default 0,
            the usual 'this' slot)
    """
    return safe_get_json("propose_struct_fields",
                          {"address": address, "this_param_index": this_param_index})

# Mac port: x86-dependent tool not registered.
def class_structure_diagnostic(function_address: str) -> str:
    """Verify parent namespace runtime class and associated class structure.

    Reports the exact equivalents of Namespace.getClass(), instanceof
    GhidraClass, and VariableUtilities.findOrCreateClassStruct(function).
    Read-only; use before changing a class datatype.
    """
    return safe_post_json("class_structure_diagnostic", {"function_address": function_address})

# Mac port: x86-dependent tool not registered.
def promote_class_structure_fields(class_name: str, source_name: str,
                                   confirm: bool = False,
                                   target_size: int | None = None) -> str:
    """Copy a populated *Fields structure into its real class-associated struct.

    Guarded by default: an empty auto-created class placeholder is safe to
    populate; pass confirm=True only when intentionally replacing a non-empty
    destination. The source datatype is preserved.
    """
    return safe_post_json("promote_class_structure_fields", {
        "class_name": class_name, "source_name": source_name,
        "confirm": confirm, "target_size": target_size})

@mcp.tool()
def decompile_function(name: str, offset: int = 0, limit: int = 0) -> str:
    """
    Decompile a function by its exact name and return the decompiled C code.
    Uses exact-name matching (not substring) so it never silently decompiles
    the wrong function -- use search_functions_by_name first if you're not
    sure of the exact name.

    Paginate large functions with offset/limit (line-based; limit=0 means
    "no limit", matching disassemble_function's convention). Response also
    includes "total_lines" and "resolved_constants" -- an auto-resolved
    preview (string or short hex dump, one level of pointer dereference for
    PTR_DAT_ symbols) for every DAT_xxxxxxxx/PTR_DAT_xxxxxxxx constant
    referenced in the returned text, so a constant's contents usually don't
    need a separate get_bytes call.
    """
    # Server's POST /searchFunctions does an exact-name lookup (find_function),
    # unlike GET /searchFunctions which is a substring search.
    raw = safe_post_json("searchFunctions", {"name": name})
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return f"Error: unexpected response looking up '{name}': {raw}"
    addr = data.get("address")
    if not addr:
        return (f"Function '{name}' not found (exact match). "
                 "Use search_functions_by_name for a substring search, "
                 "or decompile_function_by_address with a hex address.")
    return "\n".join(safe_get("decompile_function",
                               {"address": addr, "offset": offset, "limit": limit}))

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})

@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at the specified address.
    """
    return safe_post("renameData", {"address": address, "newName": new_name})

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> dict:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get_json("segments", {"offset": offset, "limit": limit})

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> dict:
    """
    List imported symbols in the program with pagination.
    """
    return safe_get_json("imports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> dict:
    """
    List exported functions/symbols with pagination.
    """
    return safe_get_json("exports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> dict:
    """
    List all non-global namespaces in the program with pagination.
    """
    return safe_get_json("namespaces", {"offset": offset, "limit": limit})

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100) -> dict:
    """
    List defined data labels and their values with pagination.
    """
    return safe_get_json("data", {"offset": offset, "limit": limit})

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> dict:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return {"error": "query string is required"}
    return safe_get_json("searchFunctions", {"query": query, "offset": offset, "limit": limit})

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    """
    Rename a local variable within a function.

    NOTE: looks the function up by bare name. If more than one function shares that
    name (overloads, or same-named methods on different classes), this may silently
    target the wrong one. When ambiguity is possible, prefer rename_variable_by_address
    with the specific function's entry-point address instead.
    """
    return safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    })

@mcp.tool()
def rename_variable_by_address(function_address: str, old_name: str, new_name: str) -> str:
    """
    Rename a local variable within the function containing function_address.

    Use this instead of rename_variable whenever the function name is ambiguous
    (multiple functions share the same name -- overloads, or same-named methods on
    different classes) -- pass the specific function's entry-point address (e.g. from
    search_functions_by_name or decompile_function_by_address) to target exactly the
    right one.
    """
    return safe_post("rename_variable_by_address", {
        "function_address": function_address,
        "old_name": old_name,
        "new_name": new_name
    })

@mcp.tool()
def uncommit_variable(function_address: str, variable_name: str) -> str:
    """
    Repair tool for the decompiler-fragility regression class first confirmed on
    RecomputeBodyPartLayout and CInstinct::RunDreamStep this project: a
    rename_variable_by_address (or set_local_variable_type) call on a
    register-allocated/decompiler-only local doesn't just relabel it -- via
    HighFunctionDBUtil.updateDBVariable it PERMANENTLY COMMITS that HighSymbol as a
    real database-backed Variable with fixed storage. If the compiler had reused that
    storage for multiple logically distinct purposes across the function (the
    "genuinely multi-purpose, don't rename" pattern this project avoids by
    convention), the commit can split the decompiler's automatic Varnode-merge and
    permanently degrade an unrelated part of the same function into raw untyped
    pcode -- confirmed NOT fixable by renaming the symbol back to its old name, since
    the damage is the storage commit itself, not the label.

    This removes that committed Variable via Function.removeVariable(), restoring
    the storage to fully dynamic/automatic decompiler analysis. Redecompile
    afterward to confirm the original clean output returns. If variable_name isn't
    currently a committed Variable (nothing to remove), returns an error --
    check list_committed_variables or a fresh decompile for its current name first.
    """
    return safe_post("uncommit_variable", {
        "function_address": function_address,
        "variable_name": variable_name
    })

@mcp.tool()
def list_committed_variables(function_address: str) -> str:
    """
    Diagnostic companion to uncommit_variable: lists every database-committed
    Variable (stack- or register-backed) for a function -- name, type, and storage.
    This is the exact set uncommit_variable and rename_variable_by_address's
    low-level fallback both search. Use it to confirm whether a decompiler-only
    local has actually been committed (and is therefore fixable via
    uncommit_variable) versus still being fully dynamic (nothing to uncommit).
    """
    return safe_post("list_committed_variables", {
        "function_address": function_address
    })

@mcp.tool()
def get_function_by_address(address: str) -> str:
    """
    Get a function by its address.
    """
    return "\n".join(safe_get("get_function_by_address", {"address": address}))

@mcp.tool()
def get_current_address() -> str:
    """
    Get the address currently selected by the user.
    """
    return "\n".join(safe_get("get_current_address"))

@mcp.tool()
def get_current_function() -> str:
    """
    Get the function currently selected by the user.
    """
    return "\n".join(safe_get("get_current_function"))

@mcp.tool()
def list_functions() -> dict:
    """
    List all functions in the database.
    """
    return safe_get_json("list_functions")

@mcp.tool()
def decompile_function_by_address(address: str, offset: int = 0, limit: int = 0) -> str:
    """
    Decompile a function at the given address.

    Paginate large functions with offset/limit (line-based; limit=0 means
    "no limit"). Response also includes "total_lines" and
    "resolved_constants" -- an auto-resolved preview (string or short hex
    dump, one level of pointer dereference for PTR_DAT_ symbols) for every
    DAT_xxxxxxxx/PTR_DAT_xxxxxxxx constant referenced in the returned text,
    so a constant's contents usually don't need a separate get_bytes call.
    """
    return "\n".join(safe_get("decompile_function",
                               {"address": address, "offset": offset, "limit": limit}))

@mcp.tool()
def disassemble_function(address: str, offset: int = 0, limit: int = 50,
                         start_address: str = None) -> dict:
    """
    Get assembly code (address: bytes; mnemonic operands) for a function.
    Paginate with offset/limit (default 50 lines).
    Use start_address (hex, e.g. "0x10205642") to jump directly to an
    instruction within the function without guessing offset index values.
    start_address snaps to the nearest instruction at or before the given
    address, so it no longer needs to land exactly on an instruction
    boundary -- check the response's "resolved_start_address" field to see
    what it snapped to.
    """
    params = {"address": address, "offset": offset, "limit": limit}
    if start_address is not None:
        params["start_address"] = start_address
    return safe_get_json("disassemble_function", params)

@mcp.tool()
def set_decompiler_comment(address: str, comment: str, comment_type: str = "eol") -> str:
    """
    Set a comment for a given address in the function pseudocode.

    FIXED (2026-08-20): comment_type previously did not exist on this tool
    at all -- every call silently wrote the EOL comment regardless of any
    comment_type value a caller might have (incorrectly) passed, since
    extra/unrecognized parameters were tolerated rather than rejected by
    the schema layer. REAL INCIDENT (this project): an earlier part of
    this same session made several calls with comment_type="plate",
    genuinely believing it was writing a distinct plate comment separate
    from eol -- every one of those calls actually overwrote EOL instead,
    leaving the OLD plate text sitting untouched. One concrete, confirmed
    consequence: a stale plate comment describing an "unknown calling
    convention" problem kept tripping this project's own text-based
    ABI-review-signal scanner even after the real fix was applied via
    set_full_prototype, because the scanner reads the plate comment and
    the fix never reached it. If you have any set_decompiler_comment
    calls with comment_type from before this date, re-verify with
    get_comments and re-apply with the real comment_type now that it
    actually works -- don't assume they landed where intended.

    Args:
        address: hex address of (or inside) the target location
        comment: the comment text to set
        comment_type: "eol" (default), "plate", "pre", or "post" --
            matches Ghidra's CodeUnit.{EOL,PLATE,PRE,POST}_COMMENT.
    """
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment,
                                                 "comment_type": comment_type})

@mcp.tool()
def set_disassembly_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function disassembly.
    """
    return safe_post("set_disassembly_comment", {"address": address, "comment": comment})

@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str) -> str:
    """
    Rename a function by its address.
    """
    return safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str) -> str:
    """
    Set a function's prototype.

    WARNING (2026-08-20): this tool has two real, confirmed bugs. It
    parses `prototype` with Ghidra's FunctionSignatureParser, which (1)
    has no grammar for a calling-convention keyword in the string at all
    -- "int __thiscall Foo(...)" fails with "Can't resolve return type:
    int __thiscall" because the parser has no rule to split '__thiscall'
    off and just tries to resolve the whole run as one type name -- there
    is no working way to set calling convention through this tool; and
    (2) has weaker type resolution than set_this_type/set_full_prototype
    (their shared _resolve_type_by_name), and can fail to resolve a valid
    custom project struct-pointer type that resolves fine via those other
    tools on the same program. It was also independently confirmed
    (2026-07-13, see set_this_type's docstring) to be COSMETIC-ONLY for
    retyping 'this' on an already-namespaced function: it reports success
    and even shows the requested type in a plate comment, but the real
    applied signature silently keeps the old type.

    Prefer set_full_prototype for anything beyond a same-namespace
    return-type tweak that doesn't touch parameters or calling
    convention -- it uses the same real, verified-effective
    Function.updateFunction() mechanism set_this_type/set_parameter
    already use successfully, with none of the three limitations above.
    """
    return safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype})

@mcp.tool()
def set_full_prototype(function_address: str, calling_convention: str, return_type: str,
                        parameters: str) -> str:
    """
    Set a function's COMPLETE prototype (calling convention, return type,
    and full parameter list) in one call, via Function.updateFunction() on
    the listing-level Function object -- the same real, verified-effective
    mechanism set_this_type/set_parameter already use, not
    set_function_prototype's broken ApplyFunctionSignatureCmd/
    FunctionSignatureParser path (see that tool's docstring for the two
    confirmed bugs this one exists to avoid).

    ADDED (2026-08-20) to close a real gap found live on this project
    (Creatures 1 Science Kit RE, CScienceSheet::HandleControlCommand):
    after delete_function + create_function resets a function to a
    signature-not-yet-locked state, Ghidra's decompiler can still SHOW
    inferred parameters in its output even though
    Function.getParameterCount() reports 0 -- those are decompiler-only
    inferences, not real Parameter objects, until something calls
    updateFunction(). In that state, neither set_this_type nor
    set_parameter can help (both require at least one EXISTING parameter
    to retype -- they modify, they don't create), and
    set_function_prototype fails on its own bugs. This tool builds the
    parameter list and calling convention from scratch in one
    updateFunction() call, exactly like set_this_type does for the
    single-parameter case, generalized to any number of parameters.

    Args:
        function_address: hex address of (or inside) the target function
        calling_convention: e.g. "__thiscall", "__cdecl", "__stdcall",
            "__fastcall", or "unknown". Must be a convention name the
            program's compiler spec actually declares.
        return_type: e.g. "BOOL", "void", "int", "MyStruct *" -- resolved
            the same reliable way set_this_type resolves 'this' types, so
            custom project types work here unlike set_function_prototype.
        parameters: a JSON array string of {"name": ..., "type": ...}
            objects, in parameter order, e.g.
            '[{"name": "this", "type": "CScienceSheet *"},
              {"name": "control_command", "type": "CScienceControlCommand *"},
              {"name": "unused_padding", "type": "undefined4"}]'
            For a __thiscall function, include 'this' explicitly as the
            first entry -- storage is recomputed from calling_convention
            via DYNAMIC_STORAGE_ALL_PARAMS, so it still lands in ECX.

    Self-verifies like set_this_type: re-decompiles afterward and reports
    decompile_shows_field_access (checked, not assumed) for the first
    parameter with a checkable struct/pointer-to-struct type, scoped to
    that parameter's own name via '{name}->field' matching -- don't trust
    a bare "status: ok" alone, read that field.
    """
    return safe_post("set_full_prototype", {"function_address": function_address,
                                             "calling_convention": calling_convention,
                                             "return_type": return_type,
                                             "parameters": parameters})

@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    """
    Set a local variable's type by NAME. Fragile against renumbering: any
    retype call in a function can silently rename OTHER local variables in
    that SAME function on the next decompile (confirmed repeatedly across
    real RE sessions -- e.g. iVar4 becoming iVar5 becoming iVar6 across
    successive calls), turning one intended retype into a
    decompile/spot-the-new-name/retry loop. Also cannot touch an
    auto-generated 'this' parameter (raises InvalidInputException:
    Cannot modify auto-parameter: this -- a real Ghidra API restriction).

    For those two specific cases, use the more targeted tools instead:
      - set_this_type: the real fix for a thiscall function's 'this' type.
      - retype_variable_at: retype by instruction ADDRESS instead of by
        (renumbering-prone) variable name.

    SELF-VERIFIES (2026-07-13): like set_this_type, re-decompiles afterward
    and returns decompile_shows_field_access (true/false/null) plus
    sample_line -- don't trust a bare "status: ok" for a struct/pointer
    new_type. Added after a real incident on this project
    (CTextAnalyzer::champ_amplitude_rules_loader): the raw-listing stack
    variable name that ECX is literally spilled into in the prologue and
    the decompiler's own HighSymbol name for the value actually threaded
    through the function body can DIFFER for the same conceptual slot --
    a plausible variable_name (e.g. from get_stack_variables or
    set_this_type's detected_ecx_local) can still be the wrong one. If
    decompile_shows_field_access comes back false, try an adjacent local
    from get_stack_variables rather than assuming the retype is correct.
    """
    return safe_post("set_local_variable_type", {"function_address": function_address, "variable_name": variable_name, "new_type": new_type})

# Mac port: x86-dependent tool not registered.
def set_this_type(function_address: str, new_type: str, force: bool = False,
                   override_detected_local: bool = False,
                   insert_as_new_parameter: bool = False) -> str:
    """
    Set the REAL type of a thiscall function's 'this' parameter.

    set_function_prototype (via ApplyFunctionSignatureCmd, a data-type-level
    API) was confirmed COSMETIC-ONLY for any function Ghidra has already
    namespaced to a real class: it accepts the request and even shows the
    requested type in a plate comment, but the function's REAL applied
    signature silently keeps the class's own pre-existing 'this' type no
    matter what was requested -- confirmed via re-decompiling multiple
    already-namespaced functions (e.g. CVoice::free_frm,
    CWave::OutputFrame) after "successfully" retyping their 'this' that
    way and finding the old type still there.

    This tool instead calls Function.updateFunction() directly on the
    listing-level Function object (not through the decompiler's
    HighFunction/signature-string layer), rebuilding the parameter list
    with an explicit USER_DEFINED 'this' Parameter and committing with
    DYNAMIC_STORAGE_ALL_PARAMS (storage is recomputed from the existing
    calling convention -- for thiscall this keeps 'this' in ECX regardless
    of the new type, as it should).

    By default this OVERWRITES parameter 0 with the new 'this' parameter
    (correct only when parameter 0 was really just an untyped/mistyped
    stand-in for 'this', with nothing else lost). Pass
    insert_as_new_parameter=True to instead PREPEND 'this' and keep every
    existing parameter (0..N-1) exactly as it was -- the correct choice
    whenever 'this' is a genuinely separate value from every
    already-modeled parameter. See the WIDENED/FIXED notes below for why
    this flag exists and when the guard below will insist on it.

    It then RE-DECOMPILES the function and checks whether the target
    struct's own real field names actually show up as literal '->field'
    access in the output -- returned as decompile_shows_field_access
    (true/false/null) plus sample_line when true. This is checked, not
    assumed: a successful API call alone was already shown (via the OTHER
    code path above) to not guarantee a visible result, so don't trust a
    bare "status: ok" here either -- read decompile_shows_field_access.
    IMPORTANT: even decompile_shows_field_access=True is not airtight when
    insert_as_new_parameter=False and real evidence of a separate 'this'
    existed -- see the 2026-08-20 incident below, where the check reported
    a false positive because the WRONG variable happened to alias a
    same-shaped field at the same memory offset.

    GUARDED (2026-07-13): refuses by default when Ghidra's own
    calling-convention analysis says the function is __cdecl or __stdcall
    (100% stack-only conventions, never ECX-based) AND parameter 0 isn't
    already an auto-parameter -- i.e. nothing suggests parameter 0 is
    actually the object pointer. This closes two real incidents from one
    RE session (docs/RE_CSPEAKERPAGE_STRUCT_2026-07-13.md,
    CSpeakerPage::show_modal and SMException::raise): both returned
    status:ok and looked successful, but had silently retyped a genuine,
    unrelated, already-correct declared parameter (an HINSTANCE, an int)
    instead of the function's real object pointer, because the real
    'this' in both cases was an orphaned decompiler local.

    WIDENED (2026-08-20): the guard now ALSO refuses for 'unknown'
    calling convention when the function has MORE THAN ONE parameter
    already modeled. REAL INCIDENT (Creatures 1 Science Kit RE project):
    the previous version explicitly did not refuse on 'unknown'
    convention at all, reasoning it "isn't a confident negative signal" --
    true only for the single-parameter "mislabeled this" shape this tool
    was built for. It broke on CScienceSheet::HandleControlCommand and
    ::HandleDdeEvent, both 'unknown' convention with TWO real stack
    parameters already modeled plus a genuinely separate 'this' the
    decompiler named 'in_ECX' -- never spilled to a stack slot, so the
    prologue scan below couldn't see it either. The call proceeded,
    silently overwrote parameter 0 (an unrelated, already-correctly-typed
    argument), and decompile_shows_field_access came back a FALSE
    POSITIVE: the switch/dereference that used to read the real parameter
    0 got relabeled 'this->field' purely because 'this' is now the type
    occupying that slot, while the function's actual logic kept running
    unfixed through the untouched 'in_ECX' local for the rest of the
    body. 'unknown' with exactly one parameter is unaffected (still
    proceeds without refusing) -- that remains the dominant, safe
    "mislabeled this" shape; a second real argument is what turns
    'unknown' from a non-signal into one worth checking.

    STRENGTHENED (2026-07-13, extended 2026-08-20): the refusal now scans
    for evidence of a genuinely separate 'this' TWO ways, not just one:
      (1) a raw-disassembly scan of the prologue for a genuine
          'MOV [EBP+/-N], ECX' -- direct proof ECX is spilled to an
          orphaned stack local, not parameter 0 (reported as
          detected_ecx_local / detected_ecx_stack_offset);
      (2) (added 2026-08-20) the decompiled C text using an unspilled
          'in_ECX'/'unaff_ECX' register value directly -- the
          HandleControlCommand/HandleDdeEvent shape above, where there is
          no stack spill for (1) to find at all (reported as
          detected_in_ecx_register).
    When either fires, force=True ALONE still refuses. This exact
    scenario -- reading the refusal, correctly concluding it was an
    orphaned-this case, then using force=True on parameter 0 anyway
    because that was the only override offered -- reproduced the
    CSpeakerPage incident a THIRD time in a later session (docs/
    TRUTH_LEDGER.md, champ_amplitude_rules_loader, 2026-07-13).

    FIXED (2026-08-20): pass insert_as_new_parameter=True together with
    force=True (add override_detected_local=True too if you want, though
    it isn't required alongside insert_as_new_parameter) for the actual
    correct fix once you've confirmed 'this' is a genuinely separate
    value from every already-modeled parameter: this PREPENDS a new
    'this' and keeps ALL existing parameters exactly as they were,
    instead of overwriting parameter 0. This is the real fix for both
    incident shapes above -- set_local_variable_type cannot reach an
    unspilled 'in_ECX' register value at all (it only retypes named
    stack/HighSymbol locals), so before this flag existed there was no
    safe path to fix that shape short of hand-editing outside this tool.

    Args:
        function_address: hex address of (or inside) the target function
        new_type: e.g. "MyStructFields *" -- use a pointer type for a
            normal thiscall 'this' (the object itself, by reference)
        force: bypass the calling-convention guard above -- only pass this
            if you've independently confirmed the function's 'this' isn't
            ECX-sourced in a way the guard can't see (e.g. via
            get_abi_summary first). Does NOT bypass a detected_ecx_local /
            detected_in_ecx_register finding on its own -- see
            override_detected_local and insert_as_new_parameter.
        override_detected_local: pass True (together with force=True) only
            if you've independently confirmed parameter 0 itself really
            should become 'this' (overwriting it) despite a detected_*
            finding (e.g. a second, unrelated ECX spill earlier in the
            same prologue). Prefer insert_as_new_parameter instead when
            'this' is actually a separate value from parameter 0.
        insert_as_new_parameter: pass True (together with force=True when
            a guard refusal was hit) to PREPEND 'this' and keep every
            existing parameter (0..N-1) unchanged, instead of overwriting
            parameter 0. This is the correct choice whenever evidence
            (detected_ecx_local or detected_in_ecx_register) shows 'this'
            is genuinely separate from all currently-modeled parameters.
    """
    return safe_post("set_this_type", {"function_address": function_address,
                                        "new_type": new_type, "force": force,
                                        "override_detected_local": override_detected_local,
                                        "insert_as_new_parameter": insert_as_new_parameter})

# Mac port: x86-dependent tool not registered.
def materialize_ecx_thiscall_callback(function_address: str, this_type: str,
                                      evidence_instruction_address: str,
                                      stack_argument_type: str = "void *",
                                      stack_argument_name: str = "callback_argument",
                                      replace_existing: bool = False) -> str:
    """Repair a specific, proven parameterless x86 ECX-this callback shape.

    This is not a generic prototype parser. It requires a concrete raw
    instruction in the function that accesses ``[ECX+offset]`` and requires
    every return to be ``ret 4``. Only then it creates the real listing-level
    ``__thiscall(this, callback_argument)`` signature. It refuses to replace
    an existing signature unless replace_existing=True and rolls back unless
    Ghidra visibly allocates ``this`` in ECX.

    Args:
        function_address: target callback's entry (or an address inside it)
        this_type: pointer datatype for its ECX receiver, e.g. "CMacroHolder *"
        evidence_instruction_address: required address of the direct
            [ECX+offset] access proving the receiver's ABI role
        stack_argument_type: datatype for the sole explicit stack argument
        stack_argument_name: name for that argument
        replace_existing: only for repairing a previously bad signature;
            otherwise an existing signature is left untouched
    """
    return safe_post("materialize_ecx_thiscall_callback", {
        "function_address": function_address, "this_type": this_type,
        "evidence_instruction_address": evidence_instruction_address,
        "stack_argument_type": stack_argument_type,
        "stack_argument_name": stack_argument_name,
        "replace_existing": replace_existing,
    })

# Mac port: x86-dependent tool not registered.
def materialize_ecx_thiscall_receiver(function_address: str, this_type: str,
                                      evidence_instruction_address: str) -> str:
    """Repair a proven parameterless x86 ECX-receiver method.

    Requires a nominated memory access based on ECX or on a simple ``MOV
    reg, ECX`` alias, and proves every return is ``ret``/``ret 0``.  It then
    creates exactly the listing-level ``__thiscall(this)`` signature.  It
    refuses existing signatures and rolls back unless Ghidra assigns this to
    ECX.

    Args:
        function_address: target method's entry (or an address inside it)
        this_type: pointer datatype for its ECX receiver
        evidence_instruction_address: required receiver-derived memory access
    """
    return safe_post("materialize_ecx_thiscall_receiver", {
        "function_address": function_address, "this_type": this_type,
        "evidence_instruction_address": evidence_instruction_address,
    })

@mcp.tool()
def retype_variable_at(function_address: str, instruction_address: str, new_type: str,
                        side: str = "output", input_index: int = 0) -> str:
    """
    Retype the HighVariable touched by the pcode op AT a specific
    instruction address, instead of by its current (renumbering-prone)
    variable name.

    Use this when set_local_variable_type's name-based lookup keeps
    hitting the "variable was renamed by an earlier retype in this same
    function" problem -- an instruction ADDRESS is stable across that
    churn in a way an auto-generated decompiler variable name is not.

    Args:
        function_address: hex address of (or inside) the containing function
        instruction_address: hex address of the specific instruction whose
            pcode op touches the variable to retype
        new_type: the type to apply, e.g. "MyStruct *"
        side: "output" (default) retypes the variable ASSIGNED at that
            instruction -- the common case, e.g. "X = alloc_something(...)".
            "input" retypes an argument being READ/PASSED there instead.
        input_index: which input varnode (0-based) when side="input"
    """
    return safe_post("retype_variable_at", {
        "function_address": function_address, "instruction_address": instruction_address,
        "new_type": new_type, "side": side, "input_index": input_index})

@mcp.tool()
def manage_namespace(operation: str, path: str, new_name: str = "",
                      new_parent_path: str = "") -> str:
    """
    Explicit namespace create/rename/move.

    Previously the only way to create a real Ghidra namespace in this
    project was as a side effect of
    rename_function_by_address("Class::method", ...) -- this exposes the
    operation directly, and adds rename/move, which nothing did before.

    Args:
        operation: "create", "rename", or "move"
        path: "/"-separated namespace path, e.g. "CFoo" or "CFoo/Inner"
        new_name: required for operation="rename" -- the new leaf name
            (same parent, just the name changes)
        new_parent_path: required for operation="move" -- the namespace
            path to move `path` under (creating it if it doesn't exist yet)
    """
    return safe_post("manage_namespace", {
        "operation": operation, "path": path,
        "new_name": new_name, "new_parent_path": new_parent_path})

@mcp.tool()
def set_parameter(function_address: str, index: int, new_name: str = "",
                   new_type: str = "") -> str:
    """
    Rename and/or retype a function parameter BY INDEX (0-based), via the
    same Function.updateFunction() listing-level approach as
    set_this_type -- the real, verified-effective mechanism, not the
    cosmetic-only set_function_prototype/ApplyFunctionSignatureCmd path.

    index=0 on a thiscall function behaves identically to set_this_type
    (same underlying mechanism) -- prefer set_this_type there for its
    'this'-focused documentation and verification framing. Use this tool
    for any OTHER parameter index, or when you want to rename a parameter
    without necessarily retyping it.

    At least one of new_name/new_type must be given; the other keeps its
    current value. Re-decompiles afterward and reports
    decompile_shows_field_access the same honest way set_this_type does,
    when new_type is a Structure or pointer-to-Structure -- don't trust a
    bare "status: ok" for whether the type change is visibly resolved,
    read that field.

    Args:
        function_address: hex address of (or inside) the target function
        index: 0-based parameter index to change
        new_name: optional new parameter name
        new_type: optional new parameter type, e.g. "MyStruct *"
    """
    return safe_post("set_parameter", {
        "function_address": function_address, "index": index,
        "new_name": new_name, "new_type": new_type})

@mcp.tool()
def set_return_type(function_address: str, new_type: str) -> str:
    """Set a function return type through Ghidra's listing-level Function API.

    This avoids the C-signature parser used by ``set_function_prototype`` and
    supports custom root-category types such as ``Object *``.
    """
    return safe_post("set_return_type", {
        "function_address": function_address, "new_type": new_type})

@mcp.tool()
def edit_structure_field(struct_name: str, category: str, operation: str, offset: int,
                          field_name: str = "", field_type: str = "", field_size: int = 0,
                          expected_size: int = 0, allow_resize: bool = False,
                          dry_run: bool = False) -> str:
    """
    Add, rename, retype, or clear ONE field of an EXISTING structure at a
    specific byte offset, without rebuilding the whole struct.

    Complements create_structure/create_structure_from_offsets, which
    always replace the WHOLE field list. By default, add/retype are
    fixed-size-only: they refuse to move later fields or resize the struct.
    Use dry_run first for any boundary change, then explicitly opt in with
    allow_resize=True or rebuild the known layout atomically.

    Args:
        struct_name: name of the existing structure
        category: Ghidra category path (e.g. "Voxtalk")
        operation:
            "add" -- insert a new field at `offset` (must not already be
                covered by an existing named field); field_type required,
                field_size optional (defaults to the type's own length).
                Fixed-size mode only replaces an exact-size Undefined gap.
            "rename" -- change only the field name at `offset` (must
                exactly match an existing component's start offset),
                keeping its type/size. field_name required.
            "retype" -- change the field type (and optionally name) at
                `offset`; a new field_size different from the old one
                It must have the same byte length unless allow_resize=True.
                field_type required.
            "clear" -- revert the field at `offset` back to opaque
                Undefined bytes (Structure.clearComponent). Does NOT
                shrink the struct -- the safe default for "delete" in an
                RE context, where total struct size is usually a
                hard-won confirmed fact that should never accidentally
                shrink as a side effect of removing one field's name.
        offset: byte offset of the field to add/rename/retype/clear
        field_name: new field name (rename/retype/add)
        field_type: new field type string (add/retype)
        field_size: optional explicit size override (add/retype)
        expected_size: reject stale edits unless the full struct has this size
        allow_resize: explicit escape hatch for a changing layout (default false)
        dry_run: return the validated plan without changing Ghidra
    """
    return safe_post("edit_structure_field", {
        "struct_name": struct_name, "category": category, "operation": operation,
        "offset": offset, "field_name": field_name, "field_type": field_type,
        "field_size": field_size, "expected_size": expected_size,
        "allow_resize": allow_resize, "dry_run": dry_run})

@mcp.tool()
def create_enum(name: str, category: str, values: str, size: int = 4,
                replace: bool = False) -> str:
    """
    Create an enum data type, or explicitly update an existing enum in place.

    Previously entirely unsupported -- no existing tool could build an
    enum, typedef, or function-pointer type. Directly useful for this
    project's many already-confirmed packed type-code fields
    (DyRuleElement.type_code, VqDescriptor.type, etc) that have so far
    only ever been documented as magic-number comments in markdown, never
    as a real, queryable Ghidra type applied to the field itself.

    Args:
        name: enum type name
        category: Ghidra category path (e.g. "Voxtalk")
        values: JSON object string, e.g.
            '{"TYPE_NULL": 1, "TYPE_ANY": 2, "TYPE_OLD": 3}'
        size: byte width of the underlying storage (1/2/4/8, default 4)
        replace: default false. When an enum already exists, the safe default
            returns its exact stored members without changing it. Set true
            only after reviewing that result to intentionally replace it;
            references to the old enum are preserved by Ghidra.
    """
    return safe_post("create_enum", {"name": name, "category": category,
                                      "values": values, "size": size,
                                      "replace": replace})

@mcp.tool()
def create_typedef(name: str, category: str, base_type: str) -> str:
    """
    Create a typedef aliasing an existing type under a new name.

    Args:
        name: new typedef name
        category: Ghidra category path (e.g. "Voxtalk")
        base_type: existing type to alias, e.g. "CVoiceFields *"
    """
    return safe_post("create_typedef", {"name": name, "category": category,
                                         "base_type": base_type})

@mcp.tool()
def create_function_pointer_type(name: str, category: str, return_type: str,
                                  param_types: str, calling_convention: str = "") -> str:
    """
    Create a named function-pointer typedef.

    Directly useful for this project's recurring raw vtable-slot/callback
    call pattern seen throughout RE work
    ('(**(code**)*param_1)(0x2000008,0x15b,...)'-style calls) that
    currently has no queryable type at all, only a plate comment or
    nothing.

    Args:
        name: new function-pointer typedef name
        category: Ghidra category path (e.g. "Voxtalk")
        return_type: e.g. "void", "int", "CVoiceFields *"
        param_types: JSON list of type-name strings, e.g.
            '["int", "char *", "CUtilityFields *"]' (order = parameter
            order; parameter names are auto-generated param1/param2/...)
        calling_convention: optional, e.g. "__thiscall"/"__stdcall" --
            left as Ghidra's default if omitted
    """
    return safe_post("create_function_pointer_type", {
        "name": name, "category": category, "return_type": return_type,
        "param_types": param_types, "calling_convention": calling_convention})

@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100, size: int = 1,
                 grouped: bool = False) -> dict:
    """
    Get all references to the specified address (xref to).

    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        size: Scan [address, address+size) and union the results (default 1,
            i.e. the address alone). Pass the symbol's full declared width
            (e.g. 4 for a dword) to also catch byte-sub-address accesses --
            a packed-flag dword accessed as `test byte ptr [addr+2], 0x10`
            has its OWN separate xref list at addr+2 that a size=1 query at
            the base address will silently miss entirely. Each returned
            entry's "to_address" shows which specific byte was targeted.
        grouped: When True, return a "groups" structure keyed by
            byte_offset from base_address instead of a flat xrefs list,
            making base-vs-interior access patterns visible at a glance.

    Returns:
        By default, a flat list of references with pagination. When
        grouped=True, a groups dict with base_address, scanned_size,
        total, and groups: [{byte_offset, byte_address, refs}].
    """
    return safe_get_json("xrefs_to", {
        "address": address, "offset": offset, "limit": limit,
        "size": size, "grouped": str(grouped).lower(),
    })

@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100, size: int = 1) -> dict:
    """
    Get all references from the specified address (xref from).

    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        size: Scan [address, address+size) and union the results (default 1).
            Same sub-byte-blind-spot rationale as get_xrefs_to's size param.

    Returns:
        List of references from the specified address range. Each entry
        includes "from_address", "to_address", "ref_type",
        "access_size_bytes" (int or null), and the containing function's
        "function" (name) / "function_address" (entry point), if any.
    """
    return safe_get_json("xrefs_from", {"address": address, "offset": offset, "limit": limit, "size": size})

@mcp.tool()
def find_next_symbol(address: str, direction: str = "forward",
                     element_size: int = None) -> dict:
    """
    Find the nearest defined symbol (function/label/data) strictly after
    (direction="forward", default) or before (direction="backward") the
    given address, with "distance_bytes" to it.

    Use this to discover an unlabeled table's real extent -- "what's the
    next known symbol after this array's base?" -- instead of guessing a
    bound from memory/docs and manually subtracting addresses in Bash.

    When element_size is provided (e.g. 4 for uint32[], 12 for a struct),
    also computes "elements_to_next" and "remainder_bytes" for table-
    geometry work.
    """
    params = {"address": address, "direction": direction}
    if element_size is not None:
        params["element_size"] = str(element_size)
    return safe_get_json("find_next_symbol", params)

@mcp.tool()
def find_address_references(address: str, limit: int = 200) -> dict:
    """
    Find literal absolute-address references to `address` anywhere in
    memory (68k 32-bit big-endian encoding), without having
    to hand-build the wildcarded byte pattern yourself.

    Thin convenience wrapper around search_bytes -- use when get_xrefs_to
    comes back empty but you suspect the address is reached via a
    SIB-scaled computed offset (e.g. `lea reg, [idx*N + address]`) that
    Ghidra's static xref analysis didn't associate with this exact address.
    """
    try:
        addr_int = int(address, 16)
    except ValueError:
        return {"error": f"Invalid address: {address}"}
    pattern = " ".join(f"{b:02x}" for b in addr_int.to_bytes(4, "big"))
    return search_bytes(pattern, limit)

@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100) -> dict:
    """
    Get all references to the specified function by name.

    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)

    Returns:
        List of references to the specified function
    """
    return safe_get_json("function_xrefs", {"name": name, "offset": offset, "limit": limit})

@mcp.tool()
def list_callees(address: str, offset: int = 0, limit: int = 100) -> dict:
    """
    List all functions called (CALL instructions) from the function at the given address.
    Paginate with offset/limit.
    """
    return safe_get_json("list_callees", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_function_callers(address: str, offset: int = 0, limit: int = 100) -> dict:
    """List direct callers of the function containing `address`."""
    return safe_get_json("function_callers", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_function_call_graph(address: str, depth: int = 2, direction: str = "both") -> dict:
    """Build a bounded direct-call graph (depth 0-5) around a function."""
    return safe_get_json("function_call_graph", {
        "address": address, "depth": depth, "direction": direction,
    })

@mcp.tool()
def get_struct_layout(name: str) -> dict:
    """Return a structure's size, alignment, and defined fields with offsets."""
    return safe_get_json("get_struct_layout", {"name": name})

@mcp.tool()
def get_instruction_facts(address: str) -> dict:
    """Return the instruction that starts exactly at `address` and its stored operand references.

    Use only with an instruction-start address.  Output is limited to the
    listing decode and explicit Ghidra references; it contains no decompiler,
    P-code, analyzer conclusion, or inferred control/data-flow relationship.
    """
    return safe_get_json("get_instruction_facts", {"address": address})

@mcp.tool()
def get_function_exact_facts(address: str, limit: int = 200, offset: int = 0) -> dict:
    """Return stored metadata and references for the function containing `address`.

    A direct call is emitted only when Ghidra has both a call reference and a
    Function exactly at the target address.  Other references remain ordinary
    `REFERENCE` records; indirect/recovered targets are never guessed. Each
    list is paginated independently by `offset`/`limit` -- check the
    `total_*` counts and `*_truncated` flags and re-page with a larger
    `offset` rather than assuming `limit` covers everything.
    """
    return safe_get_json("get_function_exact_facts", {"address": address, "limit": limit, "offset": offset})

@mcp.tool()
def get_address_exact_facts(address: str, limit: int = 100, offset: int = 0) -> dict:
    """Return stored facts at one exact address, plus references to and from it.

    Includes decoded code/data beginning there, symbols, listing comments and
    memory block. References are only those stored at that exact address (not
    a range scan); no inferred relationships are added. Paginated by
    `offset`/`limit`; check `total_*_references` and `*_truncated` flags.
    """
    return safe_get_json("get_address_exact_facts", {"address": address, "limit": limit, "offset": offset})

@mcp.tool()
def get_type_exact_facts(name: str, limit: int = 100, offset: int = 0) -> dict:
    """Return an exactly named datatype's declared layout and typed instances.

    Fields come from Ghidra's declared datatype; instances are defined data
    whose datatype path exactly matches it. No recovered object instances,
    pointer targets, or guessed field uses are included. Paginated by
    `offset`/`limit`; check `total_typed_data_instances`/`instances_truncated`.
    """
    return safe_get_json("get_type_exact_facts", {"name": name, "limit": limit, "offset": offset})

@mcp.tool()
def get_exact_neighborhood(address: str, depth: int = 1, limit: int = 200,
                           include_incoming: bool = True,
                           include_outgoing: bool = True) -> dict:
    """Build a bounded exact-only graph around an address.

    Nodes are direct listing/symbol/data/memory facts. Edges are only stored
    Ghidra references, each with its original type and operand index; this is
    not a decompiler/CFG/data-flow graph. `depth` is capped at 3 and `limit`
    caps nodes; always check `truncated` before treating the result as complete.
    """
    return safe_get_json("get_exact_neighborhood", {
        "address": address, "depth": depth, "limit": limit,
        "include_incoming": str(include_incoming).lower(),
        "include_outgoing": str(include_outgoing).lower(),
    })

@mcp.tool()
def get_function_hash(address: str) -> dict:
    """Hash normalized instruction shape to compare functions across FlexTalk DLLs."""
    return safe_get_json("get_function_hash", {"address": address})

@mcp.tool()
def analyze_dataflow(address: str, variable: str = "", direction: str = "backward",
                     max_steps: int = 20) -> dict:
    """Trace one P-code value backward to definitions or forward to consumers.

    `variable` may be a decompiler variable or register name; omit it to trace
    the first P-code output at `address`.  Traces stop at calls and are capped.
    """
    return safe_get_json("analyze_dataflow", {
        "address": address, "variable": variable, "direction": direction,
        "max_steps": max_steps,
    })

@mcp.tool()
def batch_decompile(addresses: list[str]) -> dict:
    """Decompile up to 20 functions in one Ghidra decompiler session."""
    return safe_post_json_result("batch_decompile", {"addresses": addresses})

@mcp.tool()
def batch_set_comments(comments: list[dict]) -> dict:
    """Atomically set up to 100 listing comments.

    Each item is `{address, comment, type}`, where type is `eol` (default),
    `pre`, `post`, or `plate`.  All inputs are validated before any write.
    """
    return safe_post_json_result("batch_set_comments", {"comments": comments})

@mcp.tool()
def get_basic_blocks(address: str) -> str:
    """
    List basic blocks for the function containing `address`: each block's
    start/end address, plus its successor and predecessor edges (with flow
    type, e.g. CONDITIONAL_JUMP/UNCONDITIONAL_JUMP/FALL_THROUGH/CALL/TERMINATOR,
    and whether the edge target/source is inside the same function). Useful
    for tracing branch/dispatch structure without resorting to objdump.
    """
    return "\n".join(safe_get("get_basic_blocks", {"address": address}))

@mcp.tool()
def get_function_body_bytes(address: str) -> str:
    """
    Return the raw bytes of a function body as a hex string.
    """
    return "\n".join(safe_get("get_function_body_bytes", {"address": address}))

@mcp.tool()
def search_bytes(pattern: str, limit: int = 200) -> dict:
    """
    Search all executable memory for a hex byte pattern. Use ?? for wildcard bytes.
    Example: pattern='68 ?? 00 00 00' finds 'push dword 0x0000XXXX' instructions.
    Stops after `limit` matches (default 200).

    Returns "matches": a list of objects, each with "address" and the
    containing function's "function" (name) / "function_address" (entry
    point), or null for both if the match falls outside any function.
    Also returns "count" and the effective "limit".
    """
    return safe_get_json("search_bytes", {"pattern": pattern, "limit": limit})

@mcp.tool()
def get_stack_variables(address: str) -> str:
    """
    List local stack variables (name, offset, size, type) for a function.
    """
    return "\n".join(safe_get("get_stack_variables", {"address": address}))

# Mac port: x86-dependent tool not registered.
def get_stack_depth(address: str) -> dict:
    """
    Resolve a stack-relative operand (e.g. "[ESP+0x10]") at a specific
    instruction to its frame offset, so you can match it against
    get_stack_variables output (e.g. local_8 at offset -8).

    Prefer the returned "resolved_stack_offset" field when it's non-null --
    that comes directly from Ghidra's own stack analysis (authoritative).
    "stack_depth_at_target" is a hand-simulated ESP walk kept only as a
    fallback for instructions Ghidra's own analysis didn't resolve; treat it
    as best-effort, not ground truth.
    """
    return safe_get_json("stack_depth", {"address": address})

# Mac port: x86-dependent tool not registered.
def get_abi_summary(address: str) -> dict:
    """
    Mechanical calling-convention summary for a function: scans every RET
    in the function body for its stack-purge immediate, and checks the
    opening instructions for ECX (or a direct register alias) used as a
    memory base or spilled to a stack slot (the classic MSVC thiscall
    pattern).  Tracks register aliases of ECX (MOV EBX, ECX) and
    detects their use as memory bases too.

    Returns ret_purge_bytes_seen (all distinct RET immediates found --
    more than one means multiple exit paths disagree, worth a manual look),
    stack_args_guess (purge_bytes/4), convention_guess (a one-line summary
    string), and thiscall_evidence (the specific instructions that suggest
    ECX=this, if any).

    Best-effort, NOT authoritative -- this project's convention (see
    AGENTS.md Rule 12) is to count stack args from the RET instruction
    directly and verify against disassembly before writing a confirmed
    calling-convention comment; treat this as a fast first pass that still
    needs that verification, especially when ret_purge_bytes_seen has more
    than one value or thiscall_evidence is empty.
    """
    return safe_get_json("abi_summary", {"address": address})

@mcp.tool()
def get_referenced_strings(address: str) -> dict:
    """
    Given a code address (typically within a function), find all defined
    string data items referenced by instructions in the same function
    body.  Returns each string with its value, address, the code address
    that references it, and the Ghidra reference type.

    Best-effort: only finds references Ghidra's auto-analysis stored.
    Useful for finding debug/error messages used by a specific function
    without manually scanning decompiler output for DAT_/s_ references.
    """
    return safe_get_json("get_referenced_strings", {"address": address})

# Mac port: x86-dependent tool not registered.
def scan_unnamed_labels(name_prefix: str = "FUN_", max_functions: int = 500,
                         max_string_len: int = 80, limit: int = 200,
                         offset: int = 0) -> dict:
    """
    Bulk self-labeling-string scanner across every still-unnamed function
    (name starting with name_prefix, default "FUN_").

    For each matching function, walks its instructions' data references and
    reads the RAW BYTES at each referenced address directly -- this
    deliberately bypasses Ghidra's string auto-analysis catalog
    (list_strings), which has been observed to miss real embedded strings
    entirely (e.g. two confirmed cases in FlexTalk.dll where a function's
    own error string was only found this way). Tests each decoded string
    against these self-labeling shapes seen repeatedly in these binaries:
      - "ClassName::method_name" (e.g. "CTextAnalyzer::do_escapes")
      - "module.DLL: name" / "module.DLL:  name()" (e.g.
        "FT_UTIL.DLL:  new_word():  Ran out of frend words.")
      - "sourcefile.cpp: function_name: ..." (e.g.
        "falloc.cpp: save_lookahead: could not allocate ...") -- names the
        real vendor source function; the "@(#) $Id: FILE.CPP 4.1" SCCS
        version tags are deliberately NOT matched
      - bare "identifier()" debug-trace labels (e.g. "NXT_ccl_f()")

    Returns candidates: [{function_address, current_name, string_address,
    matched_string, pattern, implied_symbol}], total, functions_scanned.
    implied_symbol is the self-labeled name pulled out of the string (the
    Class::method, the function after ".cpp:", or the bare name), so a hit
    is directly actionable.

    This replaces the manual cycle used repeatedly this project (grep the
    string table -> find its address -> get_xrefs_to -> check if the caller
    is still unnamed) with a single bulk pass over a whole program.

    Best-effort, NOT authoritative: a match is strong evidence of the
    function's real name (especially Class::method and module.DLL: shapes)
    but confirm by reading the surrounding decompile before renaming, per
    project Rule 6 -- a matched string could belong to a nearby/related but
    distinct function if reference attribution is off.
    """
    return safe_get_json("scan_unnamed_labels", {
        "name_prefix": name_prefix,
        "max_functions": max_functions,
        "max_string_len": max_string_len,
        "limit": limit,
        "offset": offset,
    })

# Mac port: x86-dependent tool not registered.
def find_class_ownership_strings(max_functions: int = 5000, max_string_len: int = 80,
                                  limit: int = 200, offset: int = 0,
                                  only_mismatches: bool = False) -> dict:
    """
    Whole-DLL debug/self-labeled-string class-ownership inventory.

    Generalizes scan_unnamed_labels's string-classification core (which
    only looks at already-unnamed functions, to find rename candidates) to
    EVERY function regardless of current name. Shares its full pattern set,
    including the "MODULE_DLL!Class::method" raw-"!"-separator shape (e.g.
    "FT_WAVE_DLL!CWave::input_synch...") and the "sourcefile.cpp:
    function_name:" shape (e.g. "translat.cpp: CTranslator: ...").

    For every hit, compares the string's own implied class name against
    the CALLING function's current Ghidra namespace and reports
    namespace_mismatch=true when they disagree. For "file.cpp:" strings the
    implied class is only set when the captured token follows the C<Upper>
    class convention (so "CTranslator" can drive a mismatch while a plain
    function name like "save_lookahead" stays informational); either way
    the captured token is returned as implied_symbol.

    This mechanizes the single highest-leverage manual RE technique from
    real sessions on this kind of binary: object-identity corrections
    between similarly-shaped classes (e.g. two different objects that
    happen to share field offsets, or a function namespaced to the wrong
    class after an earlier refactor) have repeatedly been found by
    eyeballing exactly this kind of embedded debug string by hand -- this
    makes that a single bulk query instead of a lucky spot.

    Returns results: [{function_address, current_name, current_namespace,
    string_address, matched_string, pattern, implied_class, implied_symbol,
    namespace_mismatch}], total, functions_scanned.

    Pass only_mismatches=True to skip everything where the string's class
    agrees with (or doesn't distinguish from) the function's current
    namespace, surfacing just the disagreements worth investigating.

    Best-effort, NOT authoritative -- confirm via a fresh decompile before
    renaming/re-namespacing, per project Rule 6.
    """
    return safe_get_json("find_class_ownership_strings", {
        "max_functions": max_functions,
        "max_string_len": max_string_len,
        "limit": limit,
        "offset": offset,
        "only_mismatches": only_mismatches,
    })

# Mac port: x86-dependent tool not registered.
def classify_function_inventory(name_prefix: str = "FUN_", max_functions: int = 8000,
                                limit: int = 500, offset: int = 0) -> dict:
    """
    Triage the still-unnamed (name_prefix, default "FUN_") function
    inventory into likely-REAL functions vs. likely COMPILER ARTIFACTS, so a
    raw "N unnamed functions" backlog can be re-scoped before budgeting
    effort against the raw number.

    Motivated by a concrete FlexTalk.dll finding: of 511 "FUN_*", ~35% were
    not real functions but MSVC exception-handling cleanup funclets and
    orphaned function-boundary fragments (Ghidra ending a function early at a
    NOP it mistook for padding, then starting a spurious FUN_* at the
    fall-through). 11 non-16-byte-aligned entries were sampled by hand; all
    11 were artifacts, and every aligned one examined was real.

    Signals used:
      - real MSVC function entries are 16-BYTE ALIGNED; funclets/fragments
        sit right after their parent's code and are NOT aligned;
      - EH cleanup funclets are reached ONLY by call refs from a SINGLE
        parent function (they run in the parent's frame);
      - orphaned body fragments have ZERO references of any kind.

    Per matching function: address, name, aligned16, body_size,
    num_call_refs, distinct_owner_funcs, total_refs, classification
    (likely_real | likely_funclet | likely_orphan_fragment | uncertain),
    reason. Plus a summary count per class. Results are ordered artifacts
    first (most actionable). READ-ONLY.

    NOT authoritative: alignment is an excellent discriminator but a real
    aligned leaf can be tiny and a non-aligned entry can occasionally be
    real. Confirm with get_function_callers / decompile before deleting.
    Natural follow-up is delete_function on confirmed artifacts, or the
    delete-both-then-create_function merge for a split function.
    """
    return safe_get_json("classify_function_inventory", {
        "name_prefix": name_prefix,
        "max_functions": max_functions,
        "limit": limit,
        "offset": offset,
    })

# Mac port: x86-dependent tool not registered.
def get_allocation_site_info(address: str, lookback: int = 15, lookahead: int = 15) -> dict:
    """
    Given the address of a CALL instruction (typically to
    operator_new/malloc or a thunk to one), walks backward within the same
    basic block for the most recent PUSH <immediate> before the call (the
    presumed allocation SIZE argument -- __cdecl operator new(size_t)
    pushes size right before the call) and walks forward from the call for
    a use of the returned pointer (EAX) followed by another CALL, which is
    the routine "if (ptr) ClassName::ClassName(ptr)" idiom immediately
    after an allocation -- reported as the LIKELY CONSTRUCTOR.

    Mechanizes a walk done manually, repeatedly, when confirming a C++
    object's real size and constructor from its allocation site: read the
    disassembly, eyeball the PUSH immediately before the CALL for the size,
    then look at what happens to the returned pointer next.

    Args:
        address: hex address of the allocator CALL instruction itself
            (not the function containing it -- the specific CALL)
        lookback: max instructions to scan backward for the size PUSH
        lookahead: max instructions to scan forward for the constructor CALL

    Returns: {call_address, call_target, size_argument, size_argument_hex,
    size_pushed_at, likely_constructor_call_address,
    likely_constructor_target, likely_constructor_name}.

    Mechanical heuristic, NOT authoritative -- confirm the size PUSH is
    really this call's size argument (not left over from an outer
    expression) and that the "likely constructor" CALL genuinely takes the
    allocated pointer as its this/ECX, by reading the actual decompile
    before relying on this.
    """
    return safe_get_json("get_allocation_site_info", {
        "address": address, "lookback": lookback, "lookahead": lookahead})

# Mac port: x86-dependent tool not registered.
def resolve_call_site_context(address: str, max_args: int = 8, lookback: int = 40, lookahead: int = 15) -> dict:
    """
    General version of get_allocation_site_info for ANY call site with
    ANY number of arguments -- resolves both what's being passed IN to a
    specific CALL and what happens to its return value.

    Built to replace the repeated manual cycle of "disassemble a large
    function, eyeball which PUSH feeds which of many calls to the same
    callee, eyeball what happens to EAX after each one" -- exactly the
    kind of tracing needed to map a classification cascade (many calls to
    the same helper, each with a different literal argument, each
    feeding a different downstream decision) without re-reading
    surrounding disassembly by hand at every one of dozens of call
    sites.

    Workflow: call get_xrefs_to(callee_address) first to get every call
    site address within a caller, then call this once per site instead
    of pulling large disassemble_function windows and tracking registers
    by eye.

    Arguments resolution: walks backward from the CALL for the
    contiguous PUSH run immediately before it (standard __cdecl/stdcall
    right-to-left push order, returned here in real logical argument
    order via arg_index). Each argument reports its resolved kind:
    "immediate" (a literal pushed directly, with a best-effort raw-bytes
    NUL-terminated ASCII string_preview -- works even on literals Ghidra
    hasn't auto-typed as a String), "immediate_via_register" (the
    register was set by an immediately preceding MOV reg,imm or LEA
    reg,[imm] -- one level of backtracking only), or
    "unresolved_register" (the register's value doesn't trace back to a
    simple nearby constant load).

    Result-sink resolution: walks forward from the CALL for the first of
    -- EAX/AL compared then conditionally branched (compare_and_branch),
    EAX/AL stored to a fixed address/variable (store_to_address_or_variable),
    or EAX pushed as an argument to a subsequent CALL
    (used_as_argument_to_call).

    Args:
        address: hex address of the CALL instruction itself (not the
            containing function -- the specific call site)
        max_args: stop collecting pushed arguments after this many
        lookback: max instructions to scan backward for the push run
        lookahead: max instructions to scan forward for the result sink

    Returns: {call_address, call_target, callee_name, arguments: [...],
    result_sink: {...}}.

    Mechanical heuristic, NOT authoritative -- same disclaimer as
    get_allocation_site_info. Confirm a resolved argument or result sink
    against the real decompile before treating it as fact, especially
    for calling conventions that don't fit the simple contiguous-PUSH-run
    assumption (varargs, register-passed args, or an argument computed
    through a longer expression than one MOV/LEA back).
    """
    return safe_get_json("resolve_call_site_context", {
        "address": address, "max_args": max_args,
        "lookback": lookback, "lookahead": lookahead})

# Mac port: x86-dependent tool not registered.
def get_seh_frame_info(address: str) -> dict:
    """
    Detects the standard MSVC _except_handler3/_except_handler4 SEH
    prologue idiom at a function's entry (push -1; push <handler>;
    push fs:[0]; mov fs:[0],esp) -- the source of the
    unaff_FS_OFFSET/local_10/puStack_c-style clutter that shows up in
    nearly every decompiled function in a typical /EHsc-or-SEH-built 90s
    MSVC binary -- and reports whether it's present plus the handler
    function's address/name.

    Read-only/informational -- does not modify the function or its stack
    frame layout, does not retype anything. Useful as a quick "is this
    noise expected/compiler-inserted, or is it actually meaningful" check
    before spending time trying to make sense of those slots.

    Args:
        address: hex address of (or inside) the target function

    Returns: {function, address, seh_frame_present, handler_address,
    handler_name}.
    """
    return safe_get_json("get_seh_frame_info", {"address": address})

@mcp.tool()
def map_function_by_debug_strings(filter_str: str = None, string_addresses: str = None,
                                   min_hits: int = 1) -> dict:
    """
    Mechanizes the "find the real vendor function behind its self-labeled
    debug/diagnostic strings" technique this project has used repeatedly
    (e.g. locating sdict_suffix_ending_analysis as the real QEND.CPP function
    from its 18 distinct "QEND: ..." error strings, or ENDNG.CPP/SCNSTIT.CPP
    the same way): runs list_strings(filter_str) -- or takes an explicit
    comma-separated address list instead -- resolves get_xrefs_to on every
    matching string, groups the results by containing function, and returns
    each function's hits sorted by from_address. Reading the strings in that
    order gives an approximate branch-by-branch roadmap of the function
    straight from its own diagnostic messages, with zero decompile calls.

    Also useful for catching a likely-wrong existing name: if a function's
    hit set belongs to a different vendor module than its current name
    implies (as happened this session with a function named
    "sdict_literal_hash_probe" that turned out to contain all of BREAK.CPP's
    error strings), that's a signal to re-verify the name via a real
    decompile before trusting it (project Hard Rule: never trust an old
    name/comment at face value).

    Args:
        filter_str: substring to search all defined strings for (e.g. "QEND"
            or ":" to catch every self-labeled debug tag). Mutually exclusive
            with string_addresses.
        string_addresses: comma-separated hex addresses to use instead of a
            filter, when you already know the specific strings of interest.
        min_hits: only report functions with at least this many matching
            strings (default 1; raise it to filter out incidental single-hit
            matches when using a broad filter like ":").

    Returns: {functions: [{function_address, function_name, hit_count,
    roadmap: [{from_address, string_address, string_value}, ...]}, ...],
    total_strings_scanned}. Roadmap entries are sorted by from_address
    (approximate code order) within each function.

    Read-only, string-xref-derived -- a navigation aid, not a substitute for
    a real decompile of the function body.
    """
    params = {"min_hits": min_hits}
    if filter_str is not None:
        params["filter_str"] = filter_str
    if string_addresses is not None:
        params["string_addresses"] = string_addresses
    return safe_get_json("map_function_by_debug_strings", params)

# Mac port: x86-dependent tool not registered.
def find_thunk_candidates(min_gap_bytes: int = 4, max_gap_bytes: int = 128,
                           max_tail_bytes: int = 6, limit: int = 200) -> dict:
    """
    Mechanical scan for undefined vtable-forwarding thunks: gaps between
    defined functions (in executable memory blocks) that analyzeAll() left
    as raw, un-disassembled bytes but which contain the classic COM-wrapper
    thunk shape -- an indirect CALL through a register+offset (`FF /2`,
    i.e. "CALL [reg+disp]" or "CALL [reg]") followed shortly by a RET.

    This is the exact pattern found by hand repeatedly in this project's
    satellite DLLs (outer-wrapper interface objects whose methods are only
    reached through a vtable, never a direct CALL, so Ghidra's
    control-flow-driven auto-analysis never turns the bytes into a
    Function at all -- e.g. ft_sdict.dll's 0x1050bf0a/0x1050bf5c and 5 of
    ft_hgrap.dll's 6 vtable-forwarding stubs, all found this same way by
    hand before this tool existed).

    Does NOT use Ghidra's own disassembler (which would commit Instruction
    definitions for every candidate, including false positives) -- instead
    does a lightweight manual ModRM decode to find candidate indirect-CALL
    sites, then checks for a C3/C2 RET shortly after. A gap only qualifies
    if it contains EXACTLY ONE such indirect call (real thunks are
    single-call forwarders; more than one suggests unrelated code/data).

    Returns candidates: [{address, length_bytes, preceding_function,
    following_function}] -- the neighboring function names are useful
    context: a candidate sitting between two "Foo_wrapper_thunkN"
    functions is much more likely a real thunk than an isolated one.

    Best-effort, NOT authoritative: confirm each candidate with
    create_function + decompile_function_by_address before renaming or
    relying on it -- the byte pattern alone cannot rule out a coincidental
    match inside padding or unrelated data bytes.
    """
    return safe_get_json("find_thunk_candidates", {
        "min_gap_bytes": min_gap_bytes,
        "max_gap_bytes": max_gap_bytes,
        "max_tail_bytes": max_tail_bytes,
        "limit": limit,
    })

# Mac port: x86-dependent tool not registered.
def classify_pointer_provenance(address: str = None, function_address: str = None,
                                 offset: str = None, max_backtrack: int = 15) -> dict:
    """
    Answers the first question worth asking before trying to trace which
    concrete object/DLL a vtable-dispatched call actually reaches: is the
    pointer feeding that call a compile-time constant (further static
    tracing -- e.g. resolve_vtable -- is worthwhile), or is it populated at
    runtime via GetProcAddress/LoadLibraryA-family calls (further static
    tracing of this binary ALONE cannot resolve it -- stop and go to the
    real registry/config data or an oracle capture instead)?

    This project lost real time to exactly this ambiguity twice
    (TRUTH_LEDGER rows 533-537: `CTA+0x3b390`'s "Letter-To-Sound
    dictionary" object was guessed at twice, both wrong, before someone
    read the actual Wine registry Dictionaries key). This mechanizes the
    check that would have caught it immediately.

    Two modes (pick one):
    - address: a plain global/absolute address (e.g. a vtable pointer slot
      in .data). Uses xref infrastructure to find every write site.
    - function_address + offset: a struct-relative field (e.g.
      "CTextAnalyzer this+0x3b390") that isn't a fixed global address at
      all -- scans that function's own instructions for stores whose
      operand contains "+ offset" against any base register, since
      Ghidra's reference manager can't track "writes to object+N across
      all instances" the way it tracks writes to a real address.

    For each write site, classifies the source of the stored value by
    walking backward (up to max_backtrack instructions) for either an
    immediate constant load ("static_constant") or the most recent CALL
    to a known dynamic-loading import: GetProcAddress, LoadLibraryA/W,
    LoadLibraryExA/W ("runtime_dynamic"). Anything else is "unknown"
    (inconclusive -- not a green light to keep guessing statically either;
    often means the value flows through one more register hop than
    max_backtrack covers).

    Returns {write_sites: [{address, instruction, classification,
    evidence}], note}.

    Best-effort: a heuristic backward-scan, not full data-flow analysis.
    """
    params = {"max_backtrack": max_backtrack}
    if address:
        params["address"] = address
    if function_address:
        params["function_address"] = function_address
    if offset:
        params["offset"] = offset
    return safe_get_json("classify_pointer_provenance", params)

# Mac port: x86-dependent tool not registered.
def find_hook_point(address: str, min_bytes: int = 5) -> str:
    """
    Find the smallest instruction-aligned block starting at address
    that meets min_bytes (default 5).  Returns individual instruction
    boundaries, total byte count, and safety flags for common hook
    sizes (5-byte jmp+offset, 6-byte jmp+offset+prefix).

    Use this to verify you won't cut a multi-byte instruction when
    installing hooks — the disassembler knows instruction boundaries
    so you don't have to hand-count bytes.
    """
    return "\n".join(safe_get("hook_point", {
        "address": address,
        "min_bytes": str(min_bytes),
    }))

@mcp.tool()
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None) -> dict:
    """
    List all defined strings in the program with their addresses.

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 2000)
        filter: Optional filter to match within string content

    Returns:
        List of strings with their addresses
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get_json("strings", params)

@mcp.tool()
def switch_program(program_path: str) -> str:
    """
    Switch the active program to another one in the ACTIVE project
    (list_programs shows them). To change project, use switch_project.
    """
    return safe_post("switch_program", {"program": program_path})

# Operations that can take minutes: importing, analysing, whole-map naming,
# and scripts.
LONG_TIMEOUT = 3600

@mcp.tool()
def list_projects() -> str:
    """
    List the Ghidra projects this server can open (from projects.json): each
    one's key, location, whether it is open, which is active, its current or
    default program, and its script collection if it has one.
    """
    return json.dumps(safe_get_json("list_projects"))

@mcp.tool()
def switch_project(project: str, program: str = "") -> str:
    """
    Make another Ghidra project active (e.g. "c1", "mapeditor", "netbabel"),
    opening it if needed, and open `program` in it -- or the program last used
    there, or its default program. The outgoing program is saved first. Every
    other tool then works on this project's active program.
    """
    return safe_post("switch_project", {"project": project, "program": program})

@mcp.tool()
def import_program(path: str, folder: str = "/", analyze: bool = False) -> str:
    """
    Import a binary file into the ACTIVE project and make it the active
    program. analyze=True also runs Ghidra's auto-analysis. Projects with
    import_roots only accept files below those directories.
    """
    return safe_post("import_program", {"path": path, "folder": folder,
                                        "analyze": str(analyze).lower()},
                     timeout=LONG_TIMEOUT)

@mcp.tool()
def apply_map_symbols(map_path: str, demangle: bool = True,
                      create_functions: bool = True) -> str:
    """
    Name the active program from an MSVC linker .map file: every symbol under
    "Publics by Value" and "Static symbols" is labelled at its Rva+Base
    address, a function is created where the map marks one (f), and mangled
    C++ names are demangled into namespaces and signatures. Returns counts
    and the first failures.
    """
    return safe_post("apply_map_symbols", {"map_path": map_path,
                                           "demangle": str(demangle).lower(),
                                           "create_functions": str(create_functions).lower()},
                     timeout=LONG_TIMEOUT)

@mcp.tool()
def list_scripts() -> str:
    """
    List the active project's GhidraScript collection (projects.json
    "scripts"): one entry per script, in numbered stage-folder order, which is
    the order a staged recovery chain is meant to run in.
    """
    return json.dumps(safe_get_json("list_scripts"))

@mcp.tool()
def run_script(script: str, args: str = "") -> str:
    """
    Compile and run one GhidraScript (Java or Python) from the active
    project's collection against the active program, inside one transaction,
    and return what it printed. `script` is the file name (with or without
    .java), the stage folder name (e.g. "01-mfc-recovery") or a path relative
    to the collection. `args` are space-separated script arguments.
    """
    return safe_post("run_script", {"script": script, "args": args},
                     timeout=LONG_TIMEOUT)

@mcp.tool()
def list_programs() -> str:
    """
    List all available programs in this instance's Ghidra project.
    """
    return "\n".join(safe_get("list_programs"))

@mcp.tool()
def create_function(address: str, name: str = "") -> str:
    """
    Create a function at the given address (disassembles first if needed).
    Optionally name it immediately.
    """
    return safe_post("create_function", {"address": address, "name": name})

@mcp.tool()
def delete_function(address: str) -> str:
    """
    Remove the Function whose ENTRY POINT is exactly `address`, leaving its
    instructions/bytes intact (FunctionManager.removeFunction). Previously
    the mutation surface had create_function but no delete.

    Primary uses (both from classify_function_inventory's taxonomy):
      - retire a confirmed compiler artifact (MSVC EH cleanup funclet) from
        the FUN_* backlog;
      - REPAIR a Ghidra function-boundary split (a real function truncated
        into an entry + an orphaned fall-through tail): delete_function BOTH
        pieces, then create_function at the real (earlier, aligned) entry --
        CreateFunctionCmd recomputes the body from flow and re-absorbs the
        tail into one merged function.

    Refuses to act unless a function starts EXACTLY at `address`; it will not
    delete a function that merely CONTAINS the address (it returns that
    function's real entry instead). Bytes are never modified, so a mistaken
    delete is reversible: create_function at the same entry restores it.
    """
    return safe_post("delete_function", {"address": address})

# Mac port: x86-dependent tool not registered.
def find_vtable_candidates(start: str, end: str, min_slots: int = 3) -> dict:
    """Find vtable-shaped pointer runs in an address range without modifying Ghidra.

    Each candidate is a 4-byte-aligned run of at least ``min_slots`` values that
    point exactly to existing function entry points.  ``rtti_seeds`` separately
    reports MSVC RTTI/vftable artifacts already known to Ghidra; RTTI-free tables
    are still returned as ordinary candidates.
    """
    return safe_get_json("find_vtable_candidates", {
        "start": start, "end": end, "min_slots": min_slots,
    })

# Mac port: x86-dependent tool not registered.
def trace_vtable_assignments(function_address: str) -> dict:
    """List static vtable writes to ``this+0`` in a function's instruction order.

    Tracks ECX-derived ``this`` aliases and direct or one-hop register-loaded
    addresses.  The final reported write is the lexical last assignment, not a
    path-sensitive runtime guarantee.
    """
    return safe_get_json("trace_vtable_assignments", {"address": function_address})

# Mac port: x86-dependent tool not registered.
def resolve_vtable(address: str, count: int) -> str:
    """
    Resolve a C++ vtable's function pointers into real Ghidra Function objects.
    Reads `count` consecutive 4-byte little-endian pointers starting at `address`
    (32-bit x86 target) and, for each non-null target that doesn't already have
    a Function, create_function's it there. Needed because analyzeAll() only
    creates Functions at addresses reached by a direct CALL instruction --
    vtable-only-referenced virtual methods never get one otherwise.
    Does not decompile the resolved functions -- call decompile_function_by_address
    per-address afterward if you want that.
    Persists a managed plate-comment block at the table while preserving any
    analyst-authored comment text, and returns an ``ndjson_record`` ready for
    an external evidence/export pipeline. Null-pointer padding slots are kept.
    """
    return safe_post("resolve_vtable", {"address": address, "count": str(count)})

# Mac port: x86-dependent tool not registered.
def create_vtable_type(name: str, vtable_address: str, slots: list[dict],
                       category: str = "Vtables", replace: bool = False) -> str:
    """Create typed vtable and object-vptr structures, then apply the table type.

    ``slots`` is ``[{"index": int, "function_address": "0x..."}, ...]``.
    Function signatures come from the referenced Ghidra Functions.  The result
    includes a minimal object type whose offset-zero ``vptr`` points to the
    vtable; apply that object type to callers' object pointers to propagate
    virtual-call names and signatures in decompilation.
    """
    # slots is structured data, so use JSON rather than form encoding.
    return safe_post_json("create_vtable_type", {
        "name": name, "vtable_address": vtable_address, "slots": slots,
        "category": category, "replace": replace,
    })

@mcp.tool()
def create_label(address: str, name: str) -> str:
    """
    Create a label/symbol at the given address.
    """
    return safe_post("create_label", {"address": address, "name": name})

@mcp.tool()
def set_data_type(address: str, type_name: str) -> str:
    """
    Set the data type at a given address.

    Accepts Ghidra's native type names (byte, word, dword, qword, char,
    short, int, long, float, double, bool, void, undefined) AND common
    C/C99-stdint aliases (uint8_t, int8_t, uint16_t, int16_t, uint32_t,
    int32_t, uint64_t, int64_t, u8/i8/u16/i16/u32/i32/u64/i64, uint, ulong,
    unsigned int, unsigned short, unsigned long, unsigned long long, etc.)
    -- both work bare (e.g. "uint32_t") and as an array (e.g.
    "uint32_t[2605]", "dword[256]", "byte[49]"). Any other Ghidra type
    name known to the program (including custom structures/enums created
    via create_structure/create_enum) is also accepted by name.

    If a type name can't be resolved, the error response includes a
    "hint" field listing every recognized alias -- read it rather than
    guessing a second spelling.

    Args:
        address: hex address (e.g. "0x10539228")
        type_name: e.g. "uint32_t[2605]", "byte[49]", "float", "MyStruct"
    """
    return safe_post("set_data_type", {"address": address, "type_name": type_name})

@mcp.tool()
def get_comments(address: str) -> str:
    """
    Get all comments (plate/pre/eol/post) at a given address.
    """
    return safe_post("get_comments", {"address": address})

@mcp.tool()
def save() -> str:
    """
    Save the current Ghidra program to disk. All renames, comments, and
    data type changes are persisted.
    """
    return safe_post("save", {})

@mcp.tool()
def create_structure(name: str, category: str = DEFAULT_CATEGORY, fields: str = "[]",
                      replace: bool = False) -> str:
    """
    Create a structure data type in Ghidra's data type manager.
    fields is a JSON string: [{"name": str, "type": str, "size": int}, ...]
    Example: '[{"name":"next","type":"undefined","size":4},{"name":"prev","type":"undefined","size":4}]'

    replace=True updates an existing structure of the same name IN PLACE
    instead of creating a "Name.conflict" duplicate -- use this when
    re-deriving a structure's layout after newly-confirmed RE (e.g. fields
    that were previously lumped together as an opaque byte blob and have
    since been individually confirmed and named).

    replace=False (the default) now REFUSES with an error -- including the
    existing struct's own field list, so you can decide without a separate
    lookup -- if a type with this name+category already exists. Confirmed
    across real RE sessions that repeated create_structure calls for the
    same name could silently update an existing struct in place even
    without replace=True, with no reliable warning beyond an easy-to-miss
    response flag; this caused real near-miss overwrites of
    already-confirmed structs. ALWAYS check the error's "existing" field
    before passing replace=true -- it may already be the canonical struct
    from a prior/ported pass, not something to casually overwrite.

    Structs built here are unpacked/byte-precise (alignment 1) by
    construction -- the right default for RE-reconstructed raw-memory
    layouts, since it lets raw pointer/array arithmetic against these
    structs resolve to real field names instead of nonsensical
    stride-scaled offsets.

    WORKFLOW TIP: retyping a struct FIELD (a pointer field's target type,
    via a replace=True call here) can retroactively resolve consumer-side
    local variables ACROSS OTHER FUNCTIONS with no further action --
    confirmed in real use: giving one struct's existing generic pointer
    field a specific pointee struct type caused several previously-raw
    local variables in a different, already-decompiled consumer function
    to immediately show real "->field" access on the very next decompile,
    with zero calls to set_local_variable_type/retype_variable_at. This is
    a genuinely cheaper lever than chasing every individual local by hand
    -- when a struct has an opaque/generic pointer field whose real
    pointee type you've since confirmed, try refining THAT field first via
    create_structure(..., replace=True) before manually retyping locals in
    every function that reads through it.
    """
    return safe_post("create_structure", {"name": name, "category": category,
                                           "fields": fields, "replace": replace})

@mcp.tool()
def create_structure_from_offsets(name: str, category: str, fields: str,
                                   total_size: int, replace: bool = False) -> str:
    """
    Like create_structure, but fields is a SPARSE list -- give only the
    CONFIRMED fields at their real offsets, and gap fields between/after
    them are computed and inserted automatically, server-side.

    fields is a JSON string: [{"offset": int, "name": str,
    "type": str (optional), "size": int (optional)}, ...]. If "size" is
    omitted, it's taken from "type" if resolvable, else inferred from the
    gap to the next field's offset (or total_size for the last field).

    This replaces hand-computing every gap field with an external script --
    real prior workflow for large structs (a 344-byte CVoiceFields, a
    1.1MB CUtilityFields) that is exactly the kind of arithmetic step
    where a mistake is easy to make and expensive to catch late. Errors
    (does not silently truncate or overlap) if any field's computed extent
    would overlap the next one, or if fields extend past total_size.

    Example: '[{"offset": 0, "name": "vtable_ptr", "type": "undefined4"},
    {"offset": 12, "name": "counter", "type": "int"}]' with total_size=20
    produces vtable_ptr@0(4B), an auto gap@4-11(8B), counter@12(4B), and an
    auto gap@16-19(4B).
    """
    return safe_post("create_structure_from_offsets", {
        "name": name, "category": category, "fields": fields,
        "total_size": total_size, "replace": replace})

@mcp.tool()
def get_bytes(address: str, size: int = 1) -> str:
    """
    Return raw bytes at an address as a hex string.
    Args:
        address: Hex address (e.g. "0x102594ac")
        size: Number of bytes to read
    """
    return "\n".join(safe_get("get_bytes", {"address": address, "size": str(size)}))

@mcp.tool()
def read_float(address: str) -> str:
    """
    Read a 32-bit float from memory at the given address.
    Returns the float value directly — no struct.unpack needed.
    """
    return "\n".join(safe_get("read_float", {"address": address}))

@mcp.tool()
def read_double(address: str) -> str:
    """
    Read a 64-bit double from memory at the given address.
    """
    return "\n".join(safe_get("read_double", {"address": address}))

@mcp.tool()
def read_int(address: str, size: int = 4, signed: bool = True) -> str:
    """
    Read an integer from memory at the given address.
    Returns both "value" (decimal) and "hex" (zero-padded unsigned bit
    pattern, e.g. "0xffffffff" for -1 at size=4) -- no need to convert to
    hex yourself to cross-check against a decompiler `& 0x...` mask.
    Args:
        address: Hex address (e.g. "0x102594ac")
        size: 1, 2, 4, or 8 bytes (default 4)
        signed: Whether to interpret as signed (default True)
    """
    return "\n".join(safe_get("read_int", {
        "address": address,
        "size": str(size),
        "signed": str(signed).lower(),
    }))

@mcp.tool()
def read_pointer_array(address: str, count: int = 1) -> dict:
    """
    Read `count` consecutive 32-bit pointers from memory starting at the
    given address, resolving each pointer value to a named symbol in the
    current program (function name, data label, etc.) when one exists.

    Eliminates the manual read_int_array-then-lookup-each-address cycle
    that vtable, offset-table, and pointer-array RE otherwise needs.

    Args:
        address: Hex address (e.g. "0x102594ac")
        count: Number of pointers to read (required)

    Returns:
        {"address", "count", "pointers": [{index, address, pointer_hex,
         is_null, symbol, is_function, data_type}]}
    """
    return safe_get_json("read_pointer_array", {
        "address": address,
        "count": str(count),
    })

@mcp.tool()
def read_float_matrix(address: str, row_stride_bytes: int, num_rows: int, row_length: int) -> dict:
    """
    Read `num_rows` rows of `row_length` consecutive 32-bit floats each,
    where consecutive rows are `row_stride_bytes` apart -- which may
    differ from row_length*4 (e.g. a per-feature table padded to a wider
    struct stride, one row per feature/category/index).

    Replaces the manual "compute base+i*stride by hand, call
    read_float/read_float_array once per row" cycle for any strided table
    -- a real source of hex-arithmetic slips (e.g. 5*0x154 != 0x6a8,
    an off-by-4 error that silently reads one row over and produces a
    plausible-looking but wrong value). Use this whenever a table's
    per-entry stride isn't the tight row_length*4 packing
    read_float_array/read_int_array assume.

    Args:
        address: Hex address of row 0 (e.g. "0x10254e68")
        row_stride_bytes: Byte distance between the start of consecutive rows
        num_rows: Number of rows to read
        row_length: Number of floats per row

    Returns:
        {"rows": [[...], ...], "row_lengths": [...]} -- a row_lengths
        entry shorter than row_length means that row ran past mapped
        memory.
    """
    return safe_get_json("read_float_matrix", {
        "address": address,
        "row_stride_bytes": str(row_stride_bytes),
        "num_rows": str(num_rows),
        "row_length": str(row_length),
    })

# Mac port: x86-dependent tool not registered.
def resolve_switch_dispatch(byte_table_addr: str, entry_count: int, jump_table_addr: str,
                             case_value_start: int = 0) -> dict:
    """
    Resolve an MSVC-style switch dispatched via a per-case byte index
    table feeding a pointer jump table (the
    `MOV AL,[EDX+byte_table]; JMP [EAX*4+jump_table]` pattern for a dense
    switch with non-trivial fallthrough grouping).

    Reports groups_by_handler_address: case values that share the SAME
    actual resolved code address -- this is the grouping decompiler output
    shows as one merged `case A: case B: ...` list, since two DIFFERENT
    byte-table group indices can point at an IDENTICAL deduplicated
    handler when the compiler found their bodies identical. Also reports
    standalone_case_values: case values whose handler address is unique
    (shared with no other case) -- a strong signal that case needs its
    own independent verification rather than an assumption it behaves
    like its numeric neighbors (this is exactly the shape of a real bug
    found via this technique: a case silently sat in the decompiler's
    merged listing for unrelated cases, using their fallback/table
    instead of its own).

    Replaces the manual get_bytes(byte_table) + read_pointer_array(jump_table)
    + cross-reference-by-hand cycle.

    Args:
        byte_table_addr: Hex address of the per-case group-index byte table
        entry_count: Number of case values (bytes to read from byte_table_addr)
        jump_table_addr: Hex address of the pointer jump table
        case_value_start: First case value's number (default 0, e.g. if the
            switch's cases start at 0)

    Returns:
        {"entries": [{case_value, group_index, handler_address}, ...],
         "groups_by_handler_address": {addr: {case_values, symbol}},
         "standalone_case_values": [...]}
    """
    return safe_get_json("resolve_switch_dispatch", {
        "byte_table_addr": byte_table_addr,
        "entry_count": str(entry_count),
        "jump_table_addr": jump_table_addr,
        "case_value_start": str(case_value_start),
    })

@mcp.tool()
def read_int_array(address: str, count: int = 1, size: int = 4, signed: bool = False) -> str:
    """
    Read `count` consecutive integers (1/2/4/8 bytes each) from memory
    starting at the given address. Returns a JSON object with "values"
    (decimal) and "hex_values" (zero-padded unsigned hex per element).

    Replaces the get_bytes-then-struct.unpack-in-a-subprocess pattern for
    dumping fixed-width tables (category ids, feature/flag dwords, offset
    tables, etc.) -- the exact thing table-geometry and bitfield-catalog
    RE work otherwise needs constantly.

    Args:
        address: Hex address (e.g. "0x102594ac")
        count: Number of integer values to read (required)
        size: 1, 2, 4, or 8 bytes per element (default 4)
        signed: Whether to interpret as signed (default False)
    """
    return "\n".join(safe_get("read_int_array", {
        "address": address,
        "count": str(count),
        "size": str(size),
        "signed": str(signed).lower(),
    }))

@mcp.tool()
def read_float_array(address: str, count: int = 1) -> str:
    """
    Read `count` consecutive 32-bit floats from memory starting at the given address.
    Returns a JSON object with "values" — an array of decoded floats.
    Eliminates the need to call get_bytes and run IEEE 754 by hand for tables
    of polynomial coefficients, rate tables, etc.

    Args:
        address: Hex address (e.g. "0x102594ac")
        count: Number of float values to read (default 1)
    """
    return "\n".join(safe_get("read_float_array", {
        "address": address,
        "count": str(count),
    }))

@mcp.tool()
def read_double_array(address: str, count: int = 1) -> str:
    """
    Read `count` consecutive 64-bit doubles from memory starting at the given address.
    Returns a JSON object with "values" — an array of decoded doubles.

    Args:
        address: Hex address (e.g. "0x102594ac")
        count: Number of double values to read (default 1)
    """
    return "\n".join(safe_get("read_double_array", {
        "address": address,
        "count": str(count),
    }))

# Mac port: x86-dependent tool not registered.
def trace_fpu_stack(address: str, start_offset: int = 0, count: int = 20,
                    start_address: str = None, fpu_only: bool = False) -> str:
    """
    Walk a straight-line sequence of x87 FPU instructions from the function
    containing `address` and return the FPU register stack state at each step.

    Tracks pushes (FLD), pops (FSTP, FCOMP, FCOMPP, etc.), exchanges (FXCH),
    arithmetic (FADD/FADDP, FSUB/FSUBP, FMUL/FMULP, FDIV/FDIVP), and unary
    operations (FCHS, FABS, FSQRT, etc.).  Stack elements are represented as
    short string expressions e.g. "1.0 − b", "accum", "(a * b)" rather than
    concrete numbers, since most operands are register- or memory-relative
    at analysis time.

    Even the simplified depth-trace alone (tracking push/pop depth through
    CALL pow_shim boundaries) cuts analysis time for multi-level pow blends
    like pow(A,1−b)×pow(B,b).

    Use *either* start_offset (instruction index) or start_address (hex address
    from disassembly output) to pick where to begin.  If both are given,
    start_address wins.

    When fpu_only=True, non-FPU instructions are still processed for stack
    tracking but excluded from the returned trace — the output shows only
    the FLD/FST/FMUL/CALL etc. rows that actually change or matter for the
    FPU stack.

    Args:
        address: Hex address of any instruction in the target function
                 (e.g. "0x102594ac")
        start_offset: Offset into the function's instruction list to begin
                      tracing (default 0)
        count: Number of instructions to trace (default 20)
        start_address: Hex address to start tracing from (optional, e.g.
                       "0x10223291").  Takes precedence over start_offset.
        fpu_only: If True, suppress non-FPU instructions from the output
                  (default False)
    """
    params = {
        "address": address,
        "start_offset": str(start_offset),
        "count": str(count),
        "fpu_only": str(fpu_only).lower(),
    }
    if start_address is not None:
        params["start_address"] = start_address
    return "\n".join(safe_get("trace_fpu_stack", params))

@mcp.tool()
def analyze() -> str:
    """
    Run Ghidra's full auto-analysis pipeline on the current program:
    disassembly, function identification, stack analysis, data references,
    and calling-convention detection. Use after switch_program or after
    manual byte-pattern edits to get real analysis instead of raw bytes.
    """
    return safe_post("analyze", {}, timeout=LONG_TIMEOUT)

@mcp.tool()
def get_guidance() -> str:
    """Read classic Macintosh RE workflow and known limitations."""
    from pathlib import Path
    return (Path(__file__).resolve().parents[1] / "GUIDANCE.md").read_text()

def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse), default: 8083")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    args = parser.parse_args()
    
    # Use the global variable to ensure it's properly updated
    global ghidra_server_url
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server
    
    if args.transport == "sse":
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8083

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()
        
@mcp.tool()
def debug_compare_struct_lookup(name: str, category: str = "", offset: int = -1) -> dict:
    """DIAGNOSTIC, read-only: compares the name-only getAllDataTypes() scan
    (what get_struct_layout/get_type_exact_facts use) against the
    category-path getDataType(cat_path, name) lookup (what
    edit_structure_field uses) for the same struct name -- chases a bug
    where edit_structure_field reports success for a root-category struct
    but the change never surfaces via the read tools. If offset>=0, also
    reports each lookup's component type AT that offset directly, plus
    DataTypeManager identity for both paths."""
    return safe_get_json("debug_compare_struct_lookup", {"name": name, "category": category, "offset": offset})

@mcp.tool()
def delete_data_type(name: str, category: str = "", force: bool = False) -> str:
    """
    Permanently remove a data type (structure/typedef/enum/etc.) from the
    program's DataTypeManager. Added 2026-07-29 for cleaning up confirmed-
    stale DUPLICATE structs (e.g. CWaveFields vs the live CWave) -- this
    project's mutation surface previously had create_structure/
    create_structure_from_offsets/edit_structure_field but no way to
    remove a struct at all.

    Lookup: if category is given, resolves via the exact CategoryPath+name
    lookup (same path edit_structure_field uses). If category is omitted,
    does a name-only scan across ALL categories (same path
    get_struct_layout/get_type_exact_facts use) and refuses if more than
    one type shares that name anywhere in the program -- pass category
    explicitly to disambiguate.

    Safety check (without force=True): refuses if the program has any
    DEFINED DATA instances actually typed as this data type -- i.e. it's
    applied somewhere as a concrete memory label, not just an unused
    candidate struct definition. This does NOT check whether any
    function's parameter/return/local-variable type or another struct's
    FIELD type still references it -- confirm via decompile (which
    struct's field names actually surface on the real consumer functions)
    BEFORE calling this with force=True that the type being deleted is
    genuinely the unused duplicate, not the live one.

    No undo tool exists for this -- back up the Ghidra project's .rep
    directory before any bulk struct-cleanup pass.
    """
    return safe_post("delete_data_type", {"name": name, "category": category, "force": force})

@mcp.tool()
def disassemble_range(address: str, count: int = 20) -> dict:
    """Decode a bounded run of consecutive instructions from any code address.

    This is not limited to a function body and is intended for quick local
    inspection from a mid-function instruction, a tail fragment, or code
    Ghidra has not assigned to a function. A non-boundary address resolves to
    the containing instruction when possible, otherwise the next instruction.

    Args:
        address: Hex start address, including an arbitrary mid-instruction address.
        count: Maximum number of real instructions to return (1-1000).

    Returns:
        Decoded instruction records plus the resolved start and next address,
        which can be supplied to a later call to continue the walk.
    """
    return safe_get_json("disassemble_range", {"address": address, "count": count})

@mcp.tool()
def list_call_fixups() -> str:
    """
    List every call-fixup name known to the current program's compiler
    spec (e.g. "__chkstk"). A call fixup tells the decompiler what a
    callee actually does to registers/stack instead of assuming the
    calling-convention worst case (clobbers all volatile registers).

    Found 2026-08-01: a CRT stack-probe helper with a nonstandard local
    name (_chkstk_probe in FlexTalk.dll) was not auto-recognized as the
    classic MSVC __chkstk pattern, so every caller with a >4KB stack frame
    decompiled with unaff_ESI/extraout_ECX garbage after the call --
    including call-argument expressions deep in the function body, not
    just the immediate post-call block. Use this to find the exact
    registered fixup name, then set_call_fixup to apply it.
    """
    return safe_post("list_call_fixups", {})

@mcp.tool()
def search_function_disassembly(address: str, mnemonic: str | None = None,
                                operand_pattern: str | None = None,
                                operand_match_mode: str = "substring",
                                max_results: int = 200) -> dict:
    """Search one function's decoded instructions without dumping all of it.

    Args:
        address: Hex address at or inside the function to scan.
        mnemonic: Optional case-insensitive mnemonic prefix, e.g. ``CALL``.
        operand_pattern: Optional text or regex to match the rendered operands.
        operand_match_mode: ``substring`` (literal, default) or ``regex``.
        max_results: Maximum matched instruction records returned (1-1000).

    Returns:
        Function metadata, matching instruction records, scan/match totals,
        and a truncation flag. Operand text exactly matches
        ``disassemble_function`` output.
    """
    return safe_get_json("search_function_disassembly", {
        "address": address, "mnemonic": mnemonic,
        "operand_pattern": operand_pattern,
        "operand_match_mode": operand_match_mode,
        "max_results": max_results,
    })

@mcp.tool()
def set_call_fixup(function_address: str, fixup_name: str) -> str:
    """
    Assign a known call-fixup (from list_call_fixups) to the function at
    function_address. Pass fixup_name="" to clear an existing fixup.

    Rejects unknown fixup_name values and returns valid_call_fixups so you
    don't need a separate list_call_fixups round-trip on a typo.
    """
    return safe_post("set_call_fixup", {"function_address": function_address, "fixup_name": fixup_name})

@mcp.tool()
def set_calling_convention(function_address: str, convention_name: str) -> str:
    """
    Set a function's calling convention directly (e.g. "__thiscall",
    "__stdcall", "__cdecl"). Rejects unknown names and returns
    valid_calling_conventions so you don't need a separate round-trip.

    Use this when get_abi_summary's convention_guess says thiscall/stdcall
    but ghidra_calling_convention says "unknown" -- this happens after a
    delete_function+create_function repair, and set_this_type will silently
    REPLACE the sole existing parameter (instead of adding "this" alongside
    it) if the convention is still "unknown" when you call it. Fix the
    convention first, then set_this_type / set_parameter.
    """
    return safe_post("set_calling_convention", {"function_address": function_address, "convention_name": convention_name})

# Mac port: x86-dependent tool not registered.
def solve_struct_index(register_name: str, scale: int, displacement: int,
                       known_offsets: list[int], stride: int = 4) -> dict:
    """Solve a scaled-index struct access against known field-base offsets.

    Args:
        register_name: Index register as rendered in the disassembly, e.g. ``EAX``.
        scale: Register scale in the raw effective address.
        displacement: Raw effective-address displacement.
        known_offsets: Candidate field base offsets inside the structure.
        stride: Per-index byte stride for those fields (default 4).

    Returns:
        Every arithmetically consistent field-base/index formula. These are
        arithmetic candidates only; callers must still verify field semantics.
    """
    return safe_get_json("solve_struct_index", {
        "register_name": register_name, "scale": scale,
        "displacement": displacement, "known_offsets": json.dumps(known_offsets),
        "stride": stride,
    })

@mcp.tool()
def translate_subfield_mask(byte_offset: int, bit_mask: int,
                            element_size: int = 4) -> dict:
    """Translate a byte-local bit mask to an element-wide bit mask.

    Args:
        byte_offset: Byte position within the array element (zero-based).
        bit_mask: Bit mask at that byte position, e.g. ``0x80``.
        element_size: Containing element width in bytes (default 4).

    Returns:
        The shifted numeric full mask and a zero-padded hexadecimal form.
    """
    return safe_get_json("translate_subfield_mask", {
        "byte_offset": byte_offset, "bit_mask": bit_mask,
        "element_size": element_size,
    })

# Mac port: x86-dependent tool not registered.
def verify_decompile_constants(address: str) -> dict:
    """Detect suspicious decompiler constants using raw disassembly evidence.

    Walks the function's C-markup tokens and cross-checks large address-
    arithmetic constants and scalar-cast function symbols against values in
    their originating machine instruction. This is read-only and bounded by
    the function size. Detector confidence describes validation history, not
    certainty about an individual finding: the arithmetic detector has a
    confirmed true positive; the function-symbol detector currently has none.

    Args:
        address: Hex address at or inside the function to verify.

    Returns:
        Function/warning metadata, detector validation status, and mismatch
        records carrying ``detector_confidence``. ``clean=true`` with an empty
        ``flagged`` list means no suspicious artifact was detected. Findings
        remain signals for manual verification, not confirmed bugs.
    """
    return safe_get_json("verify_decompile_constants", {"address": address})

if __name__ == "__main__":
    main()
