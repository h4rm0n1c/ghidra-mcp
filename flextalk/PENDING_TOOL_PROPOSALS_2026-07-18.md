# ghidra-mcp: 3 pending tool proposals + 1 carried-over item — 2026-07-18

**STATUS UPDATE 2026-07-18, later same day: all 3 proposals below (
`search_function_disassembly`, `translate_subfield_mask`,
`solve_struct_index`) were implemented, deployed, and validated live**
against the exact test cases specified in this file — all passed (see
each proposal's "Concrete validation case" for the confirmed results).
This file is kept as-is below (mostly unedited) as the design record;
the still-open item is Proposal 2's STRETCH version (auto-annotation in
disassembly output), which was NOT built this pass — only the minimal
`translate_subfield_mask` calculator was. The carried-over
`disassemble_range` idea also remains unbuilt (see "Relationship to
disassemble_range" under Proposal 1).

Filed against `~/.ghidra_mcp_venv/ghidra_headless_server.py` (REST API,
methods on a class exposed via `do_GET`/`do_POST` dispatch dicts) and
`~/.ghidra_mcp_venv/bridge_mcp_ghidra.py` (the `@mcp.tool()`-decorated
MCP-facing wrappers, one per server endpoint) — together these ARE the
`mcp__ghidra-mcp__*` tool set used by the voxtalk project's RE sessions.
This is our own server, not a vendored dependency: past sessions have
added tools directly to it whenever a manual RE technique recurred or
was error-prone by hand (see `docs/GHIDRA_MCP_TOOLING_EXTENSIONS_2026-07-12.md`
in the voxtalk repo for the fullest prior writeup, and the auto-memory
entry `reference_ghidra_mcp_custom_tools.md` for the established
6-step add-a-tool procedure, reproduced below for convenience).

This file is a **spec for an agent to implement**, not yet acted on.
Written after a user prompt ("we're getting bogged down in mechanical
work... think a little harder") during a long mechanical-porting session
on `sdict_candidate_retry_dispatcher` (ft_sdict.dll, VA `0x1050cc4a`) —
every example below is a real, specific incident from that session, not
a hypothetical.

## Established pattern for adding a tool (do this for each item below)

1. Add a method to the API class in `ghidra_headless_server.py` (near
   similar existing methods — e.g. `read_float_array`/`read_pointer_array`
   for array-reading tools, `resolve_call_site_context` for
   instruction-scanning tools) — takes plain args, returns
   `json.dumps({...})` or `json.dumps({"error": ...})`.
2. Register the method name in the big endpoint-name list (~line 6474
   area in the current file) and add a `{"path": ..., "params": ...,
   "description": ...}` entry to the `/guidance` endpoint's doc list, so
   `get_guidance` reflects it.
3. Add the actual dispatch entry in `do_GET`'s `handlers = {...}` dict
   (read-only tools — all 3 proposals below are read-only) — a lambda
   calling `self.api.<method>(...)` with params pulled via
   `p("name", "default")`.
4. Add a matching `@mcp.tool()` function in `bridge_mcp_ghidra.py` with a
   proper docstring (Args/Returns) — this is what actually surfaces as an
   `mcp__ghidra-mcp__*` tool.
5. Restart: `sudo /etc/init.d/ghidra-mcp restart` — needs the user to run
   it directly (or `! sudo ...` in a Claude Code session — Claude cannot
   supply the sudo password itself).
6. **Critical extra step, easy to miss**: restarting the backend alone
   does NOT push new tool schemas to an already-connected MCP client —
   the client caches the tool list at connect time. The user must run
   `/mcp reconnect ghidra-mcp` (that exact server name; `/mcp reconnect
   ghidra` fails with "server not found"). After reconnect, new tools
   appear as deferred tools, findable via `ToolSearch`.

**Watch out for the form-encoded-boolean bug class** documented in
`docs/GHIDRA_MCP_TOOLING_EXTENSIONS_2026-07-12.md`: `bridge_mcp_ghidra.py`
posts as `application/x-www-form-urlencoded`, so any boolean parameter
arrives server-side as a literal string (`"False"` is truthy in Python).
None of the 3 tools below take boolean params in their minimal form, but
if you add one (e.g. an optional `case_sensitive` flag), use the
already-existing `_form_bool()` helper, not `bool(data.get(...))`.

---

## Proposal 1 (highest priority): `search_function_disassembly`

**The incident that motivated this.** Twice in one session (porting
`sdict_candidate_retry_dispatcher`), the task was "find every instruction
in THIS ONE FUNCTION that reads or writes stack slot `EBP + -0x1c`" (and
separately `EBP + -0x18`). There is no tool for this. The only path
available was calling `disassemble_function` with a huge `limit` to get
the whole function, which for this specific function (2916 instructions)
produced 383,742 characters / 17,505 lines — over the tool-result token
limit, so the harness silently fell back to saving it as a file and
telling the agent to read it back in ~1111-line chunks or grep it
directly with Bash. That worked (see
`docs/RE_SDICT_CANDIDATE_RETRY_DISPATCHER_2026-07-17.md` entry #27 for
the result: it resolved a genuine, previously-mysterious stack local's
provenance), but it's a large, wasteful round trip for what should be a
single targeted query — and the SAME need has already come up twice.

**Proposed signature**:
```
search_function_disassembly(function_address, mnemonic=None, operand_pattern=None, max_results=200)
```
- `function_address`: entry address of the function to scan (same
  semantics as `disassemble_function`'s required address — scans the
  function's full body via whatever body-range resolution
  `disassemble_function` already uses internally, so it correctly
  handles multi-block bodies).
- `mnemonic`: optional exact or prefix match against the instruction's
  mnemonic string (e.g. `"CALL"`, `"TEST"`).
- `operand_pattern`: optional substring or regex tested against the
  SAME rendered operand string `disassemble_function` already produces
  in its `"operands"` field (e.g. `"EBP + -0x1c"`, or a regex like
  `r"0x105\w+"` to find every reference into a specific data region).
- `max_results`: cap, to keep the response small even on a broad query.
- Both filters optional; if neither given, behaves like a size-limited
  `disassemble_function` (this alone could retire the still-open
  `disassemble_range` proposal below, see "Relationship to
  disassemble_range").

**Return shape**: same per-instruction object shape as
`disassemble_function`'s `"instructions"` list (`address`, `bytes`,
`mnemonic`, `operands`), plus a `total_scanned` count (how many
instructions were in the function body) and `total_matched` (how many
satisfied the filter, which may exceed `max_results` — surface that
distinction so the caller knows if results were truncated).

**Concrete validation case** (already used to test the implementation,
2026-07-18 — tool built and confirmed working):
`search_function_disassembly(0x1050cc4a, operand_pattern="EBP + -0x1c")`
against `sdict_candidate_retry_dispatcher` in `ft_sdict.dll` returns 7
hits total across the whole function (not just the 2 this port had
reached so far at write time — a write at `0x1050cc6d`, the prologue
zero-init, and a read at `0x1050e58a`, both relevant to the port at the
time; the other 5, at `0x1050d7fe`/`0x1050e66c`/`0x1050f212`/
`0x1050f21e`/`0x1050f3e2`, belong to code not yet reached by the port).
Confirmed byte-for-byte identical to the manual `grep` over the full
disassembly dump that originally motivated this tool. A second
known-good case:
`search_function_disassembly(0x1050cc4a, mnemonic="CALL")` should return
every CALL instruction in that one function (dozens), letting an agent
audit a whole function's callee list without a full disassembly dump —
complementary to `get_xrefs_to(callee)`, which answers the reverse
question ("who calls this specific function") but not "what does this
specific function call, and where."

**Implementation notes**: this can likely reuse whatever internal
instruction-iteration `disassemble_function` already does (walk the
function's `AddressSetView` body via Ghidra's `Listing.getInstructions`),
just adding a filter predicate before appending to the results list
instead of appending unconditionally. Should be a small diff relative to
the existing `disassemble_function` method, not a from-scratch
implementation.

### Relationship to the already-pending `disassemble_range` proposal

A prior session (2026-07-17, tracing `sdict_morphology_postprocess`,
recorded in the auto-memory entry
`reference_ghidra_mcp_tool_gaps_2026-07-17.md`) flagged a related but
distinct gap: `disassemble_range(address, count)` — walk forward N real
instructions from an ARBITRARY address (not necessarily a function
entry), replacing the manual `get_instruction_facts` → read `length` →
compute next address → repeat loop (8+ round trips in that session's
verification pass). That need is about **starting position**
flexibility; this proposal is about **filtering**. They're complementary,
not duplicates — but if only one gets built, `search_function_disassembly`
with no filters and a `start_address` parameter added (walk forward from
an arbitrary mid-function address, not just the function entry) would
cover both use cases in one tool. Implementer's call whether to merge
them or keep both; if merging, add an optional `start_address` param
(default: the function entry) alongside `function_address` (needed so
the tool still knows the function's total body bounds for a sane
default stopping point).

---

## Proposal 2: byte-offset-to-full-width-mask helper

**The incident class this targets.** Reading a sub-field of a
multi-byte array element via a byte-granularity `TEST`/`AND` — e.g.
`TEST byte ptr [EAX*4 + 0x1053922a], 0x80` where `0x1053922a` is
`kEndingCategoryFeatures_2605entries`'s base (`0x10539228`) **plus 2**,
i.e. testing bit 7 of byte-offset 2 within each 4-byte array element —
requires manually computing "byte offset 2, bit 7 → overall bit
`(2*8+7)=23` → mask `0x800000`" every single time this idiom appears.
This project's own codebase already documents a REAL bug that this
exact manual step caused: a comment in `src/sdict_qend_helpers.cpp`
(~line 3994-4002) records that an earlier session transcribed this
family of accesses as `0x400`/`0x800` (the raw byte-level bits) instead
of the correct `0x40000`/`0x80000` (the full-32-bit-field equivalent) —
a bug that shipped and was later caught and fixed. This session
independently re-did the same class of arithmetic multiple times for
`0x1053922a`'s `0x80` case (→ `0x800000`) while porting
`sdict_candidate_retry_dispatcher`'s `0x1050eb13` condition tree and its
`label_0x1050ec51`/`label_0x1050ec85` shared tails.

**Minimal version (build this first, cheap, immediately useful)**: a
pure calculator, no Ghidra state needed —
```
translate_subfield_mask(byte_offset, bit_mask, element_size=4)
```
Returns `bit_mask << (byte_offset * 8)` (with a bounds check that
`byte_offset < element_size`), e.g.
`translate_subfield_mask(2, 0x80)` → `0x800000`. Trivial arithmetic, but
making it an explicit, checkable tool call (vs. mental math done inline
while writing a C++ line) removes exactly the transcription-slip failure
mode that already caused a real bug once.

**Stretch version (more valuable, more work — implementer's call whether
to attempt this pass or leave it for later)**: auto-annotate this pattern
directly in `disassemble_function`'s (or the new
`search_function_disassembly`'s) output. When an instruction's operand
resolves to a byte-granularity access into an address that Ghidra
already has typed as a wider array (e.g. `kEndingCategoryFeatures_2605entries`
typed as `dword[2605]`, per the existing project convention of applying
real Ghidra types once a shape is confirmed — see
`reference_ghidra_mcp_custom_tools.md`'s "Don't just comment — create
real types too" section), compute:
1. Which element of the array is being addressed (from the register/
   scale part of the effective address).
2. Which byte within that element (from the displacement's offset past
   the array's own base, mod the element size).
3. The full-width equivalent mask, per the minimal version above.
...and attach this as an extra `"subfield_annotation"` field on that one
instruction's JSON object, only when the pattern is detected (don't
force it onto every instruction — most don't need it). This would have
directly caught the pre-existing `0x400`/`0x800` bug at read time, not
after it shipped.

---

## Proposal 3: struct-offset / index-algebra solver

**The incident class this targets.** `SdictCandidateRecord` (a 316-byte
struct in `src/sdict_qend_helpers.hpp`, `g_sdict_candidate_pool[7]`) has
~20 known per-index accessor fields at fixed byte bases (0, 4, 8, 12, 16,
44, 72, 76, 104, 108, 136, 140, 168, 172, 203, 204, 211, 212, 216, 220,
252 — see the struct definition for the full, named list). Reverse
engineering which accessor a raw compiled access like
`[pool_ptr + EAX*4 + 0x24]` refers to means solving, by hand each time,
"does `base + pos*4 == EAX*4 + 0x24` hold for some integer `pos` at one
of the 20 known bases, and if so what's `pos` in terms of `EAX`?" This
session did this derivation 4 times in a row for one single function
(`sdict_candidate_retry_dispatcher`'s `label_0x1050ec51`, for
K=4,8,0x24,0x28 respectively resolving to `segment_start_offset_w`,
`segment_end_offset`, `segment_p_value`, and a genuinely new field added
this session, `segment_field_48`) — each one a small but real
opportunity for an arithmetic slip, same failure class as Proposal 2.

**Proposed signature**:
```
solve_struct_index(raw_expr, known_offsets, stride=4)
```
- `raw_expr`: the linear expression as seen in the disassembly, e.g.
  `"EAX*4+0x24"` or just the two numbers `(scale=4, disp=0x24)` — pick
  whichever is easier to parse robustly; a structured `(scale, disp)`
  pair is probably more robust than parsing a free-form expression
  string.
- `known_offsets`: a list of the struct's own known field base offsets
  (the caller supplies these — e.g. paste in the `SdictCandidateRecord`
  list above — since the tool has no way to know a project's own accessor
  conventions).
- `stride`: the per-index step size shared by scale and every candidate
  field's own indexing (4 in every case seen this session, since these
  are all `int32_t` fields — expose as a parameter rather than hardcoding
  4, since a project could have byte-stride fields like
  `SdictCandidateRecord::segment_scratch_203`/`segment_merge_flag_m`,
  which use `stride=1` in the SAME struct).
- Returns every `(known_offset, pos_formula)` pair where
  `known_offset + pos*stride == scale*reg + disp` has an integer
  solution for `pos` as a function of the register value — i.e. for each
  candidate base `B`, checks `(disp - B) % stride == 0` (when `scale ==
  stride`) and reports `pos = reg + (disp - B) / stride` when it holds,
  or reports "no match" if none of the known offsets fit, honestly
  signaling "this may be an unconfirmed field" rather than silently
  guessing.

**Known limitation to flag to the caller, not hide**: this only proves
ARITHMETIC consistency (the offsets and strides line up), not SEMANTIC
correctness (that the resulting field is actually the right one to read
in context) — the tool should say so explicitly in its docstring/return
payload, so a future session doesn't over-trust a match the way a raw
number might get over-trusted. This is honestly the most
project-specific and lowest-leverage of the 3 proposals (it only helps
when working with an already-cataloged multi-field struct with a known
accessor table) — build it last if time is limited, and consider
whether it's worth a dedicated server-side tool at all vs. just a
snippet the agent runs locally in a scratch Python one-liner. The user
selected it when asked, so it's included here at full detail, but flag
this tradeoff back to whoever picks up the implementation in case they'd
rather spend the time on Proposals 1-2 only.

---

## Suggested order

1. `search_function_disassembly` — highest leverage, most general,
   directly retires 2 already-hit pain points from this session and
   subsumes the older pending `disassemble_range` idea if scoped to
   include it.
2. Proposal 2's minimal version (`translate_subfield_mask`) — cheap,
   directly targets a failure mode with a proven real-bug track record.
3. Proposal 3 (`solve_struct_index`) — most speculative value; do last,
   or reconsider scope per the note above.
4. Proposal 2's stretch version (auto-annotation) — highest total value
   of anything here, but also the most implementation work (requires
   correctly detecting "this address is a sub-byte access into an
   already-typed wider array," which touches Ghidra's type system more
   deeply than the other 3) — good candidate for a follow-up session
   once 1-3 are proven out.
