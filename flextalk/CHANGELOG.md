# ghidra-mcp changelog

## 2026-07-12 — `classify_function_inventory` (read-only) + `delete_function` (mutation)

Two tools closing gaps found during the same FlexTalk.dll sweep.

**`classify_function_inventory`** (GET, read-only). Triages the still-unnamed
(`FUN_*`) backlog into `likely_real` / `likely_funclet` /
`likely_orphan_fragment` / `uncertain`, because a raw "N unnamed functions"
count is misleading: on FlexTalk.dll ~35% of 511 `FUN_*` were not functions but
MSVC exception-handling cleanup funclets and orphaned function-boundary
fragments. Signals: 16-byte alignment (real MSVC entries are aligned; funclets
and fragments sit right after their parent and are not), single owning parent
across all reference types (funclet), and zero references (orphan). Returns per
function `address/name/aligned16/body_size/num_call_refs/distinct_owner_funcs/
total_refs/classification/reason` plus a summary, artifacts sorted first. The
decision tree was validated against 9 hand-classified FlexTalk.dll cases before
commit.

**`delete_function`** (POST, mutation). `FunctionManager.removeFunction` on an
exact entry point, leaving instructions/bytes intact. Previously the surface had
`create_function` but no delete. Two uses: retire a confirmed artifact funclet,
or **repair a Ghidra function-boundary split** — delete both the truncated entry
and its orphaned tail, then `create_function` at the real (earlier, aligned)
entry so `CreateFunctionCmd` recomputes one merged body from flow. Refuses to act
unless a function starts exactly at the address (won't delete a merely-containing
function); reversible via `create_function` at the same entry since bytes are
never touched.

Both registered in the server (API method, HTTP route, `methods` list, guidance)
and the MCP bridge. Both files pass `py_compile`. **A full Ghidra project backup
was taken first** at
`~/ghidra_projects_backups/VoxtalkRE-2026-07-12-pre-delete-function-tool.tar.gz`
(15 MB, integrity-verified) since `delete_function` mutates the shared live DB.
**Requires a manual server restart to take effect.** Post-restart validation
plan: run `classify_function_inventory` on FlexTalk.dll, then exercise
`delete_function` by merging the real split defect at `StrBuffer::append_cstr`
(`0x10214700` + orphan `0x1021470a`).

## 2026-07-12 — `sourcefile.cpp: function:` self-labeling pattern (scanner blind spot)

`scan_unnamed_labels` and `find_class_ownership_strings` classified embedded
self-labeling strings against `Class::method`, `module.DLL: name`,
`MODULE_DLL!Class::method`, and bare `name()` — but **not** the
`sourcefile.cpp: function_name: message` shape these AT&T/FlexTalk binaries use
heavily (e.g. `falloc.cpp: save_lookahead: could not allocate ...`). A whole-DLL
`scan_unnamed_labels` over FlexTalk.dll therefore returned **zero** candidates,
reading as "no self-labeling strings left" when in fact a one-line
`list_strings(filter=".cpp:")` surfaced 16 strings naming real vendor functions
(recovered `ftinit`, `frend_init`, `save_lookahead`, `CVoice::LogPrintf`, all
previously guessed or unnamed).

Added a 5th pattern to both tools' shared classification core:
`^FILE.cpp:\s+NAME`. Notes:

- The `^` anchor plus the required `:` after `.cpp` deliberately exclude the
  `@(#) $Id: FILE.CPP 4.1 ...` SCCS version tags (they start with `@` and have
  no colon after the extension) — verified against real tags, no false
  positives.
- Both tools now also return `implied_symbol`: the self-labeled name pulled
  straight out of the string (the `Class::method`, the function after `.cpp:`,
  or the bare `name`), so a hit is directly actionable without re-reading it.
- In `find_class_ownership_strings`, a `file.cpp:` token drives
  `namespace_mismatch` only when it follows the `C<Upper>` class convention
  (e.g. `translat.cpp: CTranslator:` → class `CTranslator`); a plain function
  name (`save_lookahead`) stays informational and never produces a false
  mismatch.

Regex + full ordered-classify logic validated in isolation against the real
FlexTalk.dll strings before editing; both files pass `py_compile`. A dated
backup was left at
`ghidra_headless_server.py.bak-2026-07-12-pre-cpp-pattern`. **Requires a manual
server restart to take effect** (`/etc/init.d/ghidra-mcp restart`). Full RE
context: `voxtalk/docs/RE_FUNCTION_INVENTORY_TAXONOMY_2026-07-12.md`.

## 2026-07-10 — Exact-only graph facts

Added five read-only graph tools that intentionally use only decoded listing
objects and records stored in Ghidra's function, reference, symbol, datatype,
memory, and comment databases:

- `get_instruction_facts`
- `get_function_exact_facts`
- `get_address_exact_facts`
- `get_type_exact_facts`
- `get_exact_neighborhood`

Every response labels itself `certainty: "exact"`. The graph assembler emits
only raw `REFERENCE` edges and a deliberately strict `DIRECT_CALL` edge: a
stored call reference must target an actual Ghidra Function at its entry point.
It never uses decompiler/P-code output, recovered variables or types, indirect
call resolution, function similarity, or table/vtable heuristics.

## 2026-07-10 — Portable call-graph, comparison, and P-code tools

Code-level comparison with `bethington/ghidra-mcp` identified a small set of
tools that map directly onto the existing PyGhidra architecture and Ghidra
12.1 APIs. Added them to both the HTTP server and MCP bridge:

- `get_function_callers` and bounded `get_function_call_graph` for direct-call
  navigation in both directions;
- `batch_decompile` (maximum 20 functions, one decompiler session);
- `get_struct_layout` for field offsets, sizes, types, and comments;
- `get_function_hash`, a SHA-256 over normalized instruction shape for
  comparing likely homologous functions across FlexTalk DLLs;
- bounded `analyze_dataflow`, tracing a P-code value backward or forward and
  stopping at call boundaries; and
- atomic `batch_set_comments` (maximum 100 comments), which validates the
  whole batch before its single Ghidra transaction.

The service was restarted using `/etc/init.d/ghidra-mcp` and its log confirms
the Ghidra 12.1 server and SSE bridge loaded cleanly. Python syntax compilation
also passes. The sandbox cannot access the host service's loopback namespace,
so endpoint responses themselves must be checked from the host process.

## 2026-07-08 (later) — Added `resolve_vtable`

This project's binaries are all C++ built around vtables. `analyzeAll()` only
creates `Function` objects at addresses reached by a direct `CALL` instruction,
so vtable-only-referenced virtual methods never get one and
`decompile_function_by_address` fails on them with "No function at 0x...".
Previously this was worked around fully manually, twice: `get_bytes` at the
vtable address, hand-decode each 4-byte little-endian pointer, `create_function`
at each one, then `decompile_function_by_address` each one individually.

Added `resolve_vtable(address, count)` (server method + POST endpoint +
bridge MCP tool) which collapses the read/decode/create_function steps into
one call: reads `count` consecutive 4-byte pointers (32-bit x86 target),
`create_function`'s each non-null target that doesn't already have one, and
returns `{address, name, was_new}` per slot. Null/padding slots come back as
`{"address": null, "name": null, "was_new": false}`. Deliberately does not
auto-decompile — that stays a separate per-address follow-up call.

Verified live against `ft_l2s.dll`'s vtable at `0x1090d000` (count 10): the 6
entries from an earlier manual pass (`0x10903890`, `0x109038a0`, `0x109038b0`,
`0x10903a50`, `0x10903a60`, `0x10903830`) correctly came back `was_new: false`;
the repeated-pointer tail (`0x109050b0` × 4, real code, not padding — same
target function referenced from 4 vtable slots) correctly created the function
once (`was_new: true`) and deduplicated on the following 3 repeats
(`was_new: false`). Saved after.

## 2026-07-08 — Audit and fixes: analyze(), prototypes, imports/exports, process supervisors

### Context

This server (`ghidra_headless_server.py` + `bridge_mcp_ghidra.py`) is a from-scratch
PyGhidra reimplementation of [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP)'s
REST surface, built so the Voxtalk/FlexTalk RE project could run headless (no Ghidra GUI)
via `/etc/init.d/ghidra-mcp`. Because it's a reimplementation rather than the real plugin,
it had drifted from upstream's actual Ghidra API usage in several places, plus some bugs
specific to this codebase. This audit was triggered by an opencode session hitting a real
crash trying to bulk-analyze `ft_l2s.dll`, and was cross-checked by directly diffing
against upstream's `GhidraMCPPlugin.java` source and live-testing every fix against the
running server.

**If you're picking this codebase up cold:** diff any endpoint you're about to touch
against `github.com/LaurieWired/GhidraMCP/blob/main/src/main/java/com/lauriewired/GhidraMCPPlugin.java`
first — most of the bugs below were "we reinvented this instead of copying upstream's
proven Ghidra API calls."

### Fixed and verified

1. **`analyze()` was completely broken, and its old logic was wrong anyway.**
   - Was: crashed on `jpype.JClass('ghidra.program.model.lang.Disassembler')` (no
     fallback). Even without the crash, it brute-force-disassembled everything then ran
     `CreateFunctionCmd` at *every instruction address* — hundreds of junk stub
     functions, none of Ghidra's real analysis (no stack vars, no types, no data refs,
     no calling conventions).
   - Now: `self._flat.analyzeAll(self._program)` — Ghidra's real one-call full
     auto-analysis pipeline (`FlatProgramAPI.analyzeAll`).
   - Verified: `ft_l2s.dll` went from 1 function → 328, with real Function-ID-matched
     MSVC CRT symbols (`__CRT_INIT@12`, `___CxxFrameHandler`, `_CallSETranslator`,
     `entry`, etc.) instead of anonymous `FUN_*` stubs.
   - Added the missing `analyze` MCP tool to `bridge_mcp_ghidra.py` — it didn't exist
     before, so this endpoint wasn't reachable from any MCP client at all.

2. **`set_function_prototype` never touched the real function signature.**
   - Was: wrote the prototype string as a `PLATE_COMMENT` and stopped. The decompiler
     never saw it.
   - Now: still writes the same comment (matches upstream, so no data migration
     needed), then parses and applies it via `FunctionSignatureParser` +
     `ApplyFunctionSignatureCmd`, exactly like upstream `GhidraMCPPlugin.java`.
   - Verified: setting a prototype on FlexTalk.dll's `entry` (DllMain, `0x10241310`)
     changed parameter names/types (`hinstDLL`/`fdwReason`/`lpvReserved`, `void*`/`uint`)
     throughout the entire decompiled function body.

3. **`set_local_variable_type` bypassed the decompiler's variable model.**
   - Was: `Variable.setDataType(dt)` directly on a raw `Variable` from
     `fn.getAllVariables()`.
   - Now: decompiles the function, finds the matching `HighSymbol` in the
     `HighFunction`'s local symbol map, and applies the type via
     `HighFunctionDBUtil.updateDBVariable(...)` — necessary because a decompiled
     variable can be split/merged across multiple low-level storage locations, and only
     this path keeps the raw `Variable` and the decompiler's SSA view consistent.

4. **`create_structure` silently dropped every field's requested type.**
   - Was: read `size` but never read/parsed `type` — every field became `Undefined`
     regardless of what was requested.
   - Now: resolves `type` via `DataTypeParser` (same pattern as `set_data_type`),
     falling back to `Undefined` only if the type string doesn't resolve.

5. **`get_stack_depth` mis-handled calls into imported Win32 DLL functions.**
   - Was: tried to detect stdcall cleanup by scanning the callee's body for a
     `RET <imm16>` — but external/imported thunks have no such body, so cleanup
     silently defaulted to 0, meaning *every* Win32 API call (virtually all
     `__stdcall`) was treated as `__cdecl`.
   - Now: reads `Function.getStackPurgeSize()` first (Ghidra's own computed value);
     for externals where that's unknown (a documented Ghidra gap itself —
     NSA/ghidra#6737), approximates via `parameterCount * 4`; only falls back to the
     original RET-scan for internal functions with unknown purge size.
   - **Not done**: the whole method is still a hand-rolled ESP-delta simulator for
     everything else. See "Follow-up" below.

6. **`decompile_function` (bridge tool) was silently broken, not just "picks the wrong
   match on ambiguous names" as first suspected.**
   - Was: called the substring-matching `GET /searchFunctions` and did
     `data.get("address")` on the response — but that endpoint returns
     `{"functions": [...], "total": N}`, which has no top-level `"address"` key. So
     `addr` was always empty, and the tool likely *always* fell through to "function not
     found," regardless of whether the function existed.
   - Now: calls the server's exact-match `POST /searchFunctions` (`find_function()`)
     and correctly reads its `{"name", "address"}` response shape. Errors clearly on no
     exact match instead of guessing.

7. **`list_imports`/`list_exports` used string heuristics instead of Ghidra's real API.**
   - Was: `"EXTERNAL"` address-string prefix for imports, `"Ordinal_"` name-prefix
     pairing for exports.
   - Now: `SymbolTable.getExternalSymbols()` for imports, `Symbol.isExternalEntryPoint()`
     for exports — matches upstream `GhidraMCPPlugin.java` exactly.
   - Verified: FlexTalk.dll's real exports are `DllGetClassObject`, `DllCanUnloadNow`,
     `entry` (5 entries total including ordinals).

8. **`list_classes`/`list_namespaces` regex-mined debug strings instead of walking
   Ghidra's real namespace hierarchy.**
   - Was: `list_classes` regex-matched `ClassName::Method` patterns in defined strings;
     `list_namespaces` filtered by loose `SymbolType`-string containment.
   - Now: both walk `Symbol.getParentNamespace()` across all symbols, matching upstream.
   - **Behavior change to note**: "classes" are now Ghidra's real namespaces — e.g.
     external-library namespaces like `ADVAPI32.DLL` grouping its imported functions —
     rather than C++ `Class::Method` patterns mined from strings. Different character of
     data, but it's the real Ghidra symbol/namespace hierarchy.

9. **`_find_function_by_name`** was an O(n) linear scan over every function in the
   program, called by 5 other endpoints. Now a `SymbolTable.getSymbols(name)` lookup
   filtered to `SymbolType.FUNCTION`.

10. **Dead SSE-instruction detection** (`MOVSS`/`MOVSD` handling in `_get_access_size`)
    removed — SSE (1999, Pentium III) postdates this binary's target hardware entirely.

11. **Bridge tools declared `-> list` actually returned a 1-element list containing one
    raw JSON string**, because `safe_get()` does `response.text.splitlines()` on
    single-line JSON. ~15 tools (`list_methods`, `list_classes`,
    `list_imports`/`exports`/`namespaces`/`data`, `list_functions`,
    `disassemble_function`, `get_xrefs_to`/`from`, `get_function_xrefs`, `list_callees`,
    `search_bytes`, `list_strings`, `search_functions_by_name`) now use the pre-existing
    `safe_get_json()` helper and return real parsed dicts. Verified live via MCP tool
    calls.

12. **JArray boilerplate duplicated 6x** across `get_bytes`/`read_float`/`read_double`/
    `read_int`/`read_float_array`/`read_double_array` — factored into a shared
    `_read_raw_bytes(addr, size)` helper.

13. **36 raw `jpype.JClass('fully.qualified.Name')` string lookups, zero fallback on
    any of them** — the same failure class that broke `analyze()`. The 6 most-repeated
    (`SourceType`, `CodeUnit`, `DataTypeParser`, `DataTypeParser$AllowedDataTypes`,
    `SymbolType`, `Function`, `java.lang.Object`) are now resolved once via
    `_init_java_classes()`, called right after `pyghidra.start()` in `main()` (not at
    Python import time — the JVM isn't up yet then). A missing/renamed class now fails
    loudly at server startup instead of silently mid-request. ~15 single-use-per-method
    lookups (built-in `*DataType` classes, `CategoryPath`, etc.) were left as local
    per-call lookups — lower risk/value to consolidate.

14. **Bonus bug, caught live, in neither audit**: `DataTypeParser`'s fully-qualified
    class name was wrong everywhere (`ghidra.program.model.data.DataTypeParser` doesn't
    exist; real class is `ghidra.util.data.DataTypeParser`), *and* its constructor call
    passed a `ConsoleTaskMonitor` as the 4th argument when the real signature is
    `(sourceDTM, destDTM, DataTypeQueryService, AllowedDataTypes)`. This silently broke
    `set_data_type`, `set_local_variable_type`, and `create_structure` — never caught
    before because nothing had exercised those paths in a session where the result was
    actually checked. Fixed: correct package path +
    `DataTypeParser(dtm, dtm, None, DataTypeParserAllowedTypes.ALL)`. Verified via a
    live `create_structure` call (previously `Class ... is not found`, now succeeds).

### Operational

Four different scripts were independently starting/stopping the server with different
pidfile locations, and only `/etc/init.d/ghidra-mcp` started both the server *and* the
SSE bridge. This desync let an orphaned server process from 2026-07-04 survive
undetected for days, silently serving stale code while every subsequent "restart"
spawned a new process that failed to bind the already-held port and died immediately —
so restarts *looked* successful (pidfile updated, "ready" logged) while doing nothing.

- Retired `~/.ghidra_mcp_venv/ghidra-mcp` (old init.d script), `ghidrad.sh`, and
  `~/.config/systemd/user/ghidra-mcp.service` to `~/.ghidra_mcp_venv/attic/`.
- **`/etc/init.d/ghidra-mcp` (i.e. `sudo service ghidra-mcp restart`) is now the only
  supported way to manage this service.**
- Found and killed the orphaned server process (PID 15294, running since Jul 4) — this
  one really was dead weight, confirmed by finding a *second*, newer process that had
  failed to bind the already-held port and died silently.
- **CORRECTION (same session, later): the ~12 other "bridge" processes are NOT
  orphaned.** Checked each one's parent process before touching any of them — every
  single one has a live parent: other currently-running Claude Code/opencode sessions
  elsewhere on this machine (including at least one from an unrelated project). This
  `ghidra-mcp` server is evidently a shared, machine-wide MCP endpoint, not scoped to
  this project alone. **Do not kill these** — doing so would disrupt someone else's
  active session. Resolved as "not actually a problem," not "deferred cleanup."

15. **`get_stack_depth` now also surfaces Ghidra's own resolved `StackReference`
    directly**, instead of only ever returning the hand-simulated ESP-walk.
    - Discovered via `get_xrefs_from` on a real ESP-relative operand
      (`LEA ECX, [ESP + 0xc]` at `0x10205818` in FlexTalk.dll `FUN_10205780`): Ghidra had
      already resolved it to `Stack[-0x20]`, exactly matching `local_20`'s declared
      offset (-32) from `get_stack_variables`. The old hand-simulated
      `stack_depth_at_target` for the same instruction came out **-48, wrong by 16
      bytes** — empirical proof the ESP simulator is measurably broken for real code
      (it walks instructions in straight address order with no awareness of conditional
      branches, so it double-counts PUSH/CALL effects from sibling branches that don't
      actually co-occur on any single path to the target).
    - Added a `resolved_stack_offset` field that reads the real `StackReference` when
      present (authoritative); `stack_depth_at_target` is kept only as a fallback for
      instructions Ghidra's own stack analysis didn't resolve. Updated the bridge tool
      docstring and the `/guidance` "stack-coordinates" workflow to prefer it.

16. **`trace_fpu_stack` had real, confirmed bugs**, found by testing it against a
    genuine x87 `pow()`-like function in FlexTalk.dll (`0x10248510` — unreached by
    static analysis, likely called only through a function pointer; the classic
    `FXCH; FYL2X; ...; FSCALE; FCHS` sequence is textbook `pow(x,y) = 2^(y*log2(x))`):
    - `_opnd_str()` didn't know that `Instruction.getDefaultOperandRepresentation()`
      returns the literal string `"<UNSUPPORTED>"` for out-of-range operand indices
      (rather than throwing or returning null) — every bare zero-operand FPU instruction
      (`FXCH`, `FYL2X`, `FLD1`, etc.) got corrupted display text
      (`"FXCH <UNSUPPORTED>, <UNSUPPORTED>"`) and fed garbage into the constant/
      register-index parsing logic downstream. Fixed by normalizing the sentinel to
      `None`.
    - The "Constants" branch (`FLDZ`→"0.0", `FLD1`→"1.0", `FLDPI`→"pi", etc.) was dead
      code — the generic `FLD`/`FILD` push branch matched those same mnemonics earlier
      in the if/elif chain, so constants never got their clean labels. Fixed by
      reordering.
    - `FYL2X`/`FYL2XP1`/`FPATAN` were miscategorized as simple unary "modify ST(0)"
      ops, but they're genuinely binary combine-then-pop operations (confirmed against
      felixcloutier.com/x86 — `FYL2X` computes `ST(1) := ST(1) * log2(ST(0))` then
      pops, the exact operation this tool's own docstring cites as its reason for
      existing). Fixed with proper combine-and-pop handling.
    - `FPTAN`/`FSINCOS` were in the same miscategorized bucket, but both push an extra
      result onto the stack (also confirmed against felixcloutier.com). Fixed with
      proper modify-then-push handling.
    - Verified live: re-traced the same function post-fix — `FLD1` now shows clean
      `"instruction": "FLD1"` and pushes `"st0": "1.0"` instead of `"<UNSUPPORTED>"`.

### FIXED (was CRITICAL) — changes weren't persisting across restarts: two compounding bugs

Discovered while re-verifying fixes above: an `analyzeAll()` run on `ft_l2s.dll` (1→328
functions) and a `set_function_prototype` call on FlexTalk.dll's `entry` were **both
silently lost** after later, unrelated server restarts. Two independent bugs compounded:

1. **No auto-save existed.** Ghidra's headless session holds all edits in memory against
   the project's checked-out `DomainObject`; only an explicit `save()` call persists to
   disk. Fixed: `_with_transaction` (the chokepoint every write endpoint already funnels
   through) now auto-saves every `_AUTO_SAVE_INTERVAL = 10` successful writes (hardcoded,
   not configurable — batched to avoid thrashing disk on every single edit).
   `switch_program` also now saves the outgoing program before releasing it.
2. **The save-on-shutdown safety net added alongside fix #1 didn't run either, because of
   a separate, pre-existing deadlock**: the SIGTERM handler called `server.shutdown()`
   from inside itself. `HTTPServer.shutdown()` blocks waiting for `serve_forever()`'s own
   loop (on the *same* thread, suspended inside the very `select()` call the SIGTERM just
   interrupted) to notice and exit — a documented Python deadlock. The process would hang
   until the init script's 5-second timeout sent `SIGKILL` (uncatchable), so nothing after
   that point — including any save — ever ran. Confirmed via the log: no "Saved on
   shutdown" line ever appeared across 4 pre-fix restart cycles; a rename test reverted
   every time. Fixed: the SIGTERM handler now saves synchronously and calls `os._exit(0)`
   directly, never touching `server.shutdown()`.

Verified live: a rename test (`FUN_10205200` → `autosave_persistence_test_fn2`) survived
a full restart post-fix, confirmed via `get_function_by_address`, then renamed back.

Real RE work is now safe across restarts (crashes, code updates, host reboots) without
depending on anyone remembering to call `save()`.

### Follow-up

- **`ft_l2s.dll`'s real analysis (328 functions from `analyzeAll()`) needs to be re-run**
  — was lost to the persistence bugs above (now fixed, so it'll stick next time). User
  deferred this for later. **DONE** — re-run in a later voxtalk session on 2026-07-08
  (see that project's `docs/TRUTH_LEDGER.md`), and it stuck.
- ~~12 orphaned bridge processes~~ — **not actually orphaned**, see the corrected
  Operational section above. Nothing to clean up.
- Two leftover test data types (`TestStruct_verify`, `TestStruct_verify2`, category
  "Voxtalk") were created against the live `FlexTalk.dll` program during
  `create_structure` testing and never removed (no delete-datatype endpoint exists yet).
  Harmless but not real project structures — worth deleting by hand in the Ghidra GUI,
  or add a `delete_data_type` endpoint if this comes up again.
