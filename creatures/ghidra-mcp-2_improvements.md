# ghidra-mcp-2: Priority Tool Improvements for C1 Creatures.exe RE

## Source Context

This doc was written during an OpenCode session (Jul 21, 2026) working on
Creatures.exe (C1 Community Edition) via ghidra-mcp-2.

**Codex conversation (prior RE work, 10.5K lines):**
`019f6f45-ad16-7fc1-85b7-17098548ff3a`

**Current state of the Ghidra DB:**
- 1,881 functions total
- ~823 real unnamed `FUN_*` functions remaining
- 34 MSVC EH funclets identified (can be deleted)
- 183 classes/namespaces identified (mostly MFC framework + ~30 game classes)
- Custom structs: `CGenome` (28B, fully laid out), `Creature` (11,484B, partially),
  others in progress
- C1 is an MFC app — rich in CRuntimeClass structures, message maps, vtables

## Priority 1 (Highest Impact): CRuntimeClass Extractor

**Rationale:** MFC embeds `CRuntimeClass` structs containing the class name,
vtable pointer, and `CreateObject` factory. Ghidra can walk these. This would
auto-name 30-40 game classes, their vtables, and their factory methods in one
pass instead of manual one-at-a-time work.

**Proposed endpoint:** `POST /extract_runtime_classes`

**Logic:**
1. Walk the binary's `.rdata` section for `CRuntimeClass` signatures
   (known MFC pattern: linked list of `CRuntimeClass` structs).
2. For each instance, read:
   - `m_lpszClassName` → `char *` (e.g. `"CGenome"`, `"CBrain"`)
   - `m_pfnCreateObject` → `CObject* (*)()` (factory function address)
   - `m_pBaseClass` → `CRuntimeClass *` (parent class, for hierarchy recovery)
   - `m_wSchema` → `UINT` (serialization schema number)
   - `m_nObjectSize` → `UINT` (object size in bytes)
3. For each class:
   - Create Ghidra namespace (e.g. `CGenome`)
   - Rename factory function to `CGenome::CreateObject`
   - Find the class's vtable (typically the `CreateObject` thunk references it)
   - Resolve and name vtable slots as `CGenome::vfunc_00`, etc.
   - Optionally: apply object size as a struct hint for field recovery
4. Report: class name, address, parent class, object size, vtable address,
   factory function, number of vtable slots resolved.

**Verification:** Already present as the manual technique in the prior session:
finding `CreateObject` thunks was how classes were identified. This just
mechanizes it.

**Ref:** Ghidra's `RTTIUtilities`, `RttiManager`, or direct
`CRuntimeClass` scanning from known hash/signature patterns.

---

## Priority 2: Bulk Vtable Pipeline

**Rationale:** `find_vtable_candidates` (read-only exists) + `resolve_vtable`
(manual address+count exists) exist but are disconnected. A bulk endpoint
would resolve 200+ vtable methods in one pass.

**Proposed endpoint:** `POST /resolve_all_vtables`

**Parameters:**
```json
{
    "start_address": "0x00400000",
    "end_address": "0x00470000",
    "min_slots": 3
}
```

**Logic:**
1. Call `find_vtable_candidates` internally over the address range.
2. For each candidate run of function pointers:
   - Read the 4-byte aligned run as pointers
   - Verify each target is already a Function (or create one)
   - Create the vtable type in the datatype manager
   - Apply it at the vtable address
   - Name functions by slot index (or better: if the class was identified by
     Priority 1, use class namespace).
3. Report every resolved vtable with address, slot count, function names.

---

## Priority 3: Function Clustering by Shared Data Access

**Rationale:** Many unnamed `FUN_*` functions can be grouped by which globals
they read/write. Functions that all touch the genome data pointer are probably
`CGenome` methods. This turns a per-function guessing problem into a
cluster-naming problem.

**Proposed endpoint:** `POST /cluster_functions_by_data`

**Parameters:**
```json
{
    "min_cluster_size": 3,
    "data_section_start": "0x00460000",
    "data_section_end": "0x00480000",
    "max_functions": 800
}
```

**Logic:**
1. For every `FUN_*` function (or function in a given list), enumerate all
   data references from its instructions.
2. Group by data address: for each global, collect which functions reference it.
3. For each cluster of 3+ functions sharing the same global:
   - Report the global's name/label
   - Report the functions, sorted by body size
   - Optionally: include a decompile preview or key instructions
4. Additional mode: group by **import** (e.g. "these 12 functions all call
   `SetWindowTextA`") — can identify UI-related clusters.

---

## Priority 4: MFC Message Map Extractor

**Rationale:** MFC dispatches Windows messages through declared message-map
tables (`BEGIN_MESSAGE_MAP` / `END_MESSAGE_MAP`). These are detectable. Every
named message handler moves a `FUN_*` from "unknown" to "handles WM_SIZE"
before decompilation.

**Proposed endpoint:** `GET /mfc_message_maps`

**Parameters:**
```json
{
    "limit": 100,
    "offset": 0
}
```

**Logic:**
1. Search the binary for MFC message-map table patterns.
   Known pattern: array of `AFX_MSGMAP_ENTRY` structs terminated by a
   zero-entry. Each entry is:
   - `nMessage` (UINT) — Windows message ID
   - `nCode` (UINT) — control notification code
   - `nID` (UINT) — control/resource ID
   - `nLastID` (UINT) — last ID in range
   - `nSig` (UINT) — signature of the handler function
   - `pfn` (function pointer) — the handler address
2. Resolve each handler address to its function.
3. Group by declaring class (the preceding runtime class struct).
4. Return: class name, total messages, per-message (message_id, message_name,
   handler_address, handler_name_or_FUN_).

---

## Priority 5: Type Propagation Trigger

**Rationale:** When you retype a function's parameter or return type via
`set_this_type`/`set_parameter`, Ghidra's internal type propagation can push
types to callers. The MCP doesn't expose a "finish propagating" step, so
some benefits of signature changes (auto-retyped locals in callers) are lost.

**Proposed endpoint:** `POST /propagate_function_type`

**Parameters:**
```json
{
    "function_address": "0x00418400",
    "max_callers": 50
}
```

**Logic:**
1. After the caller applies type changes via existing tools, call this to
   trigger Ghidra's `FunctionPropagator` / `TypePropagator` on the changed
   function and its callers.
2. Report: functions affected, local variables retyped, any propagation
   failures (e.g. conflicting types at a call site).
3. Optionally: `propagate_all_changes` to apply to every function that was
   modified in this session.

---

## Implementation Notes

**File to modify:** `bridge_mcp_ghidra.py` (add new tool functions with
`@mcp.tool()` decorator), plus corresponding HTTP handler in
`ghidra_headless_server.py` if needed.

**Python venv:** `/home/harri/.ghidra_mcp_venv_2/` — use
`/home/harri/.ghidra_mcp_venv_2/bin/python`.

**Ghidra:** 12.1 PUBLIC at `/opt/ghidra_12.1_PUBLIC`.

**Service:** The ghidra-mcp-2 instance runs on ports 8082 (headless) and
8083 (MCP SSE bridge). Restart after changes with:
```sh
sudo /etc/init.d/ghidra-mcp-2 restart
```

**Full tool surface for reference:** Run `audit_surface.py` in the venv:
```sh
./bin/python audit_surface.py --format markdown
```

**Existing 98 tools include:**
- `propose_struct_fields` — P-code-based field offset discovery (UNDERUSED)
- `classify_function_inventory` — real vs funclet classification (UNDERUSED)
- `get_allocation_site_info` / `resolve_call_site_context` — constructor
  and call-site tracing
- `scan_unnamed_labels` — debug string scanning (C1 has very few, but
  C3/DS may have more via linker map)
- `find_class_ownership_strings` — class ownership from debug strings
- `create_enum` / `create_typedef` / `create_function_pointer_type` —
  type construction
- `create_vtable_type` — typed vtable from function signatures
- `batch_set_comments` / `batch_decompile` — bulk annotation
