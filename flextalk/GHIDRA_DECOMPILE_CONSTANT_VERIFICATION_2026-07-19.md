# ghidra-mcp: deterministic decompile-artifact detector — spec for an agent to implement

**This file is a spec for an agent to implement, not yet acted on.**
Written 2026-07-19 during the voxtalk RE/port session, after the parent
session hit the SAME class of decompiler bug twice in one sitting on
`ft_sdict.dll`'s `sdict_candidate_retry_dispatcher`/
`sdict_candidate_stack_push` cluster (VA `0x1050cc4a`/`0x1050f6ce`) and
burned a non-trivial number of tokens manually chasing each one down by
hand (`get_xrefs_to` → `disassemble_range` → reasoning, repeated per
suspicious constant). The user's framing: if there's a mechanical,
deterministic-time detection process, build it — don't keep paying the
token cost of manual verification every time a decompile looks
suspicious.

Filed against the same 2 files every prior tool addition in this server
touches: `~/.ghidra_mcp_venv/ghidra_headless_server.py` (REST API,
methods on a class exposed via `do_GET`/`do_POST` dispatch dicts) and
`~/.ghidra_mcp_venv/bridge_mcp_ghidra.py` (the `@mcp.tool()`-decorated
MCP-facing wrappers). See `PENDING_TOOL_PROPOSALS_2026-07-18.md` in this
same directory for the established 6-step "how to add a tool" procedure
(add API method → register in the endpoint list + `/guidance` doc →
`do_GET` dispatch entry → matching `@mcp.tool()` wrapper → restart via
`sudo /etc/init.d/ghidra-mcp restart` → **critical, easy to miss**:
`/mcp reconnect ghidra-mcp` in the Claude session, since restarting the
backend alone does not push new tool schemas to an already-connected
client). Reuse that procedure exactly for whatever gets built here.

## The problem, with one real incident and one corrected false alarm

Ghidra's decompiler performs constant propagation/folding across P-code
SSA values. When two memory regions have overlapping or conflicting
symbol/type definitions in Ghidra's own database — which happens
constantly on this project's target binaries, since `ft_sdict.dll` etc.
are 1990s C code that genuinely reuses the same memory for different
purposes at different points in execution, and this project's own
iterative RE work has defined many structures/renames over many
sessions, some of which turned out to overlap — the decompiler can
silently fold together values that shouldn't be combined, producing
syntactically valid but semantically wrong C-like text. This is a
documented, longstanding, *unfixed* Ghidra limitation (confirmed via a
live web search against Ghidra's own GitHub issue tracker just before
this file was written — see NationalSecurityAgency/ghidra#3934, #1380,
#4533; the exact warning banner this project sees constantly, `/*
WARNING: Globals starting with '_' overlap smaller symbols at the same
address */`, has been present since at least Ghidra 10.3, and this
project runs 12.1 — there is no version upgrade that removes it).

**Incident 1** (`sdict_findwd_trie_search`, VA `0x1050ad82`, found
2026-07-19 earlier the same day as this file): the decompiler rendered
a `sdict_valid_stem_boundary_scan` call argument as
`_DAT_10562b98 + 0x4158b26` — `0x4158b26` is *impossible* as a literal
here (it would require a function parameter, a runtime register value,
to fold to a fixed compile-time constant). The real instruction at that
point is `LEA EBX, [EAX + 0x10562c98]` — `0x10562c98` is a real global
base address (a scratch buffer this project had already named), and the
decompiler's rendering bore no resemblable relationship to it at all.
Root-caused via `get_xrefs_to` (to find the 2 call sites of the callee)
then `disassemble_range` at the call site.

**Corrected false alarm 2** (`sdict_candidate_stack_push`, VA
`0x1050f7ab`): the decompiler rendered a byte-store as
`*(undefined1 *)(...+ 0x12) = (undefined1)sdict_candidate_score_accumulator;`
The real instruction is `MOV AL, [0x10563490]`. Follow-up verification
showed that `sdict_candidate_score_accumulator` is not a function:
Ghidra has no function at that address, and the project header already
declares it as the confirmed `int32_t` global at `0x10563490`. Reading
its low byte is therefore correct. Any detector must require an actual
`SymbolType.FUNCTION`; a bare or function-looking name is insufficient.

The real incident was caught because the rendered expression looked
implausible on inspection. The false alarm demonstrates the opposite
risk: unusual but correct scalar casts must not be flagged based on
names alone. The manual follow-up needed to distinguish them is the
token cost this spec exists to reduce.

## What "mechanical" and "deterministic-time" mean here, concretely

The right primitive already exists inside Ghidra's own decompiler API
and is *already partially used* in this server — `decompile_function`
(around line 252-291 of `ghidra_headless_server.py`) calls
`decomp.decompileFunction(func, 0, ConsoleTaskMonitor())` and takes
`res.getDecompiledFunction().getC()` for the plain text. The **same**
`res` (a `ghidra.app.decompiler.DecompileResults`) also exposes
`res.getCCodeMarkup()`, returning the root `ClangTokenGroup` of the
pretty-printed output — a tree of `ClangToken` objects, where tokens
that render as numeric literals or symbol references (`ClangVariableToken`,
or a plain `ClangToken` wrapping a `Varnode` with a constant address
space) carry their own `getMinAddress()`/`getMaxAddress()`, i.e. the
*exact instruction address* that token's value was derived from. This
is a **deterministic, bounded-time walk** (linear in token count, no
heuristic text-matching needed) — the exact API this project's own
`_resolve_dat_constants` helper (line ~230) already approximates via
regex-on-rendered-text; this proposal replaces that fragile-by-necessity
regex approach with the real token-to-address mapping for the specific
subset of tokens that are numeric constants.

**Detection algorithm** (bounded time: O(tokens in the function) token
walk, plus O(1) disassembly lookups per flagged token):

1. Decompile the target function via `DecompInterface`, same as the
   existing `decompile_function` method.
2. Walk `res.getCCodeMarkup()`'s token tree (recursively; a
   `ClangTokenGroup` contains child tokens/groups). For each leaf token:
   - If it's a numeric literal token (an integer constant rendered in
     the C text) AND its value doesn't look like a small, plausible
     immediate (heuristic pre-filter: magnitude > some threshold, e.g.
     `0x10000`, OR the literal appears inside an `INT_ADD`/`INT_SUB`
     expression alongside another operand that is itself a symbol/global
     reference — the confirmed incident above was exactly
     "plausible-looking symbol arithmetic producing an implausible
     combined constant") —
     mark it a candidate.
   - If it's a token whose underlying Varnode/HighVariable resolves to a
     **function symbol** being used in a context that expects a plain
     scalar (e.g. cast to `undefined1`/`char`/`int` rather than called or
     having its address taken with `&`) — mark it a candidate, but only
     when Ghidra reports `SymbolType.FUNCTION`.
3. For each candidate token, get its `getMinAddress()` (the originating
   instruction address within the function). Disassemble that single
   instruction (reuse the existing `disassemble_range(address, count=1)`
   logic, or call the underlying Ghidra API directly for one
   instruction) and extract its actual immediate operand(s) / referenced
   address(es) from the raw instruction, not from any further
   decompiler interpretation.
4. Compare: does the decompile-rendered value (the literal, or the
   resolved symbol) correspond to ANY immediate/address actually encoded
   in that instruction? If yes → not a bug, discard. If no → flag it,
   returning: the decompile line/expression text, the claimed value, the
   real instruction (address + mnemonic + operands), and a short
   "mismatch" verdict.
5. Return the full list of flagged candidates for the function (empty
   list = clean). This is naturally bounded — one pass over the
   function's own token tree, one extra disassembly call per flagged
   candidate (typically 0-3 per function in practice).

**Trigger/priority heuristic** (cheap, no token walk needed): any
function whose decompile text already contains a `WARNING:` comment
banner (`Globals starting with '_' overlap smaller symbols at the same
address`, `Could not reconcile some variable overlaps`, or similar —
grep the existing warning banners Ghidra emits) should be treated as
HIGH PRIOR RISK and checked by this tool before trusting any of its
unusual constants — the confirmed incident had that exact banner.
A cheap pre-check (does the decompile text start
with `/* WARNING:`?) can gate whether to bother running the full token
walk at all, if the fuller implementation proves expensive to write
first.

## Proposed new tool: `verify_decompile_constants`

- **New API method** (`ghidra_headless_server.py`, near
  `decompile_function`/`decompile_function_by_address`):
  `verify_decompile_constants(self, address_str)` → walks the token tree
  as described above, returns
  `json.dumps({"address": ..., "function": ..., "has_overlap_warning": bool,
  "flagged": [{"decompile_text": ..., "claimed_value": ...,
  "token_address": ..., "real_instruction": {"address":..., "mnemonic":...,
  "operands":...}, "verdict": "mismatch"}], "clean": bool})`.
- **MCP tool** (`bridge_mcp_ghidra.py`): `verify_decompile_constants(address: str)`,
  docstring explaining it cross-checks a function's decompile output
  against raw disassembly for constant-folding/symbol-resolution
  artifacts, returning any mismatches found (empty list = nothing
  suspicious detected).
- Read-only tool (like the 3 proposals in the 2026-07-18 file) — no
  boolean params to worry about for the form-encoding bug class.

## Concrete validation cases (use these to confirm the implementation works)

1. `verify_decompile_constants("0x1050a4e1")` (`sdict_findwd_trie_search`)
   should flag the token at `0x1050ad82` (`LEA EBX, [EAX + 0x10562c98]`)
   — decompile claims `+ 0x4158b26`, real instruction encodes
   `0x10562c98`. Mismatch.
2. `verify_decompile_constants("0x1050f6ce")` (`sdict_candidate_stack_push`)
   should return clean. At `0x1050f7ab`, `MOV AL, [0x10563490]` correctly
   reads the low byte of the confirmed `int32_t` global
   `sdict_candidate_score_accumulator`; it is not a function symbol.
3. Sanity check on a function with NO known artifacts (e.g. the already
   fully-verified `sdict_dict_bucket_locate`, VA `0x10516918`) should
   return `"clean": true, "flagged": []` — confirms the tool doesn't
   over-fire on ordinary, correct decompiles.

## Fallback if the ClangToken approach proves impractical

If walking `getCCodeMarkup()`'s token tree turns out to be awkward from
Jython/PyGhidra (API friction, not algorithmic difficulty), a
lower-fidelity but still deterministic fallback: regex-scan the
rendered decompile text (reusing `_resolve_dat_constants`'s existing
regex infrastructure) for (a) hex literals above a size threshold
appearing in arithmetic expressions, and (b) known function-symbol
names appearing in a scalar-cast/assignment context rather than a call
or `&`-address-of context — then, for each hit, use
`get_referenced_strings`/`get_xrefs_to`-style address resolution plus
`disassemble_range` to find the real instruction. This loses the exact
token→address precision of the ClangToken walk (may need to search a
small window of addresses within the function rather than one exact
address) but is implementable with tools this server already has, and
was literally the manual process the original investigations used —
just automated instead of hand-driven.

## CORRECTION 2026-07-19 (later, after initial implementation + validation): Incident 2 was never a real bug

While resuming port work, re-examined "Incident 2"
(`sdict_candidate_stack_push`, `sdict_candidate_score_accumulator`)
properly before using its value, and found it was a FALSE POSITIVE —
both in the original manual investigation AND in the tool's own
detection:

- `sdict_candidate_score_accumulator` is ALREADY a real, correctly-typed
  `extern int32_t` global in this project's own
  `src/sdict_qend_helpers.hpp` (confirmed by a PRIOR session, 2026-07-17,
  via `sdict_accum_add`'s own disassembly at `0x10508d71` — a genuine
  Hard-Rule-15 catch that CORRECTED an earlier mis-citation of this same
  variable at a different address). It's a data global with a
  function-sounding name, not a function.
- `get_function_by_address("0x10563490")` confirms Ghidra has **no
  function** at that address.
- The decompile line `(undefined1)sdict_candidate_score_accumulator` was
  therefore CORRECT the whole time: a normal byte-truncating cast of an
  `int32_t` global, rendered with its own (confusingly function-sounding,
  but not actually a function) name.

**Root cause of the false positive**: the `function_symbol_used_as_scalar`
detector heuristic apparently flags any bare (non-`DAT_`/non-`g_`-prefixed)
identifier used in a scalar-cast context as suspicious, without checking
whether that identifier is ACTUALLY a Ghidra `SymbolType.FUNCTION` symbol
vs. a renamed data label. **Fix needed**: before flagging a
`function_symbol_used_as_scalar` candidate, look up the symbol via
Ghidra's symbol table and only flag it if `getSymbolType() ==
SymbolType.FUNCTION` (or equivalently, if `getFunctionAt(symbolAddress)`
returns non-null). A renamed global data label should never trigger this
detector regardless of what its name looks like.

**Updated validation case 2**: `verify_decompile_constants("0x1050f6ce")`
should return `clean: true` once this fix lands (the previously-flagged
token at `0x1050f7ab` is not a real mismatch). Validation case 1
(`0x1050a4e1`, the genuine `0x4158b26` address-arithmetic bug) is
unaffected and should still flag exactly as before.

**Process lesson for whoever uses this tool**: a `flagged` result is a
strong signal to go verify, not a confirmed bug on its own — as this
incident shows, always cross-check whether the "suspicious" symbol is
already a known, deliberately-named global in the project's own headers
before concluding the decompiler is wrong. The tool narrows where to
look; it doesn't replace checking.

## Further improvement suggestion 2026-07-19 (after the false-positive fix landed and was re-validated)

The fix above (gate on `SymbolType.FUNCTION`/`getFunctionAt() != null`)
was implemented and re-validated: `verify_decompile_constants("0x1050f6ce")`
now correctly returns `clean: true`, and `0x1050a4e1`'s genuine catch is
unaffected. Good. But this surfaces a real gap worth fixing before
trusting this detector category as much as the other one:

**The `function_symbol_used_as_scalar` detector no longer has ANY
confirmed true positive.** Its only real-world test case
(`sdict_candidate_score_accumulator`) turned out, on proper
investigation, to not be a bug at all — a legitimately-named data
global, not a symbol-resolution failure. The `large_arithmetic_constant`
detector has a confirmed real catch (`0x1050ad82`'s `0x4158b26`); this
one currently has zero. That's a meaningfully different confidence
level, and the tool's output doesn't currently distinguish them — a
`flagged` entry from either detector looks equally authoritative in the
JSON, even though one category is unproven.

**Concrete suggestions, in order of value:**

1. **Add a `detector_confidence` field to each flagged entry** (e.g.
   `"confirmed"` for `large_arithmetic_constant`, since it has a real
   validated catch, vs. `"unconfirmed"` for
   `function_symbol_used_as_scalar`, since its only test case was a
   false positive) — cheap, purely a labeling change, and immediately
   tells a future caller "double-check this one extra carefully" without
   having to know this file's history.
2. **Actively hunt for a genuine true positive for the scalar-symbol
   detector**, or explicitly deprioritize/soften it until one is found.
   A quick way to look: grep this project's own decompiled functions
   (or scan a batch of `ft_sdict.dll`/`FlexTalk.dll` functions with
   `verify_decompile_constants`) for any OTHER case where a bare
   identifier appears in a scalar-cast context — for each hit, apply the
   same discipline this session used (check the project's own headers
   first, then `get_function_by_address`) before concluding it's real.
   Don't ship confidence in this detector on zero confirmed catches.
3. **Do not add a name-pattern exception** (e.g. "skip flagging if the
   name doesn't look like a function name") as a shortcut fix — the
   whole point of the `SymbolType.FUNCTION` gate is that it's a real
   Ghidra fact, not a heuristic guess about naming style. This project's
   own binaries already have data globals with confusing,
   function-sounding names (exactly what caused this false positive) —
   any name-based heuristic will immediately reintroduce the same class
   of mistake in the opposite direction (under-flagging a real function
   misresolution because its name looks plausible as data).
4. **Batch-run `verify_decompile_constants` across every function this
   project has already ported** (roughly 500 functions per DLL, per
   `list_programs`/`list_functions`) as a one-time sweep once the fix is
   stable, specifically filtering for `has_overlap_warning: true`
   functions first (the cheap pre-filter the original spec already
   proposed) — this project has been doing exactly this kind of
   RE/port work for weeks and almost certainly has more undiscovered
   instances of both bug classes sitting in already-"confirmed" code,
   given the confirmed incident was found by accident, not by systematic
   search.

### Implemented follow-up and sweep result

The confidence distinction is now part of the endpoint contract. Every
response includes category-level `detector_status`; every flagged record
includes `detector_confidence` and `detector_validation_status`. These fields
describe the validation history of the detector category, not the probability
that a particular finding is a real decompiler error. The response also
includes `candidates_checked_by_kind`, so an empty finding set can be
distinguished from a category that did not encounter any candidates.

The MCP wrapper and `/guidance` carry the same warning. The scalar-symbol
detector remains gated exclusively on Ghidra's `SymbolType.FUNCTION`; no
name-pattern fallback or exception was added.

Read-only validation against a disposable copy of the `VoxtalkRE` project on
2026-07-19 produced:

- 417 listed `ft_sdict.dll` functions swept; 0 verifier errors.
- 68 functions contained the decompiler overlap warning.
- `large_arithmetic_constant`: 68 candidates checked, 37 review signals.
- `function_symbol_used_as_scalar`: 0 candidates checked, 0 review signals.
- The known arithmetic incident remains an exact catch; the corrected
  `sdict_candidate_stack_push` case and `sdict_dict_bucket_locate` control both
  remain clean.

The 37 arithmetic signals are a triage set, **not 37 confirmed bugs**. Manual
inspection of the sweep samples found ordinary decompiler transformations
(including signed `SUB` presentation and pointer-bias propagation) among them.
The scalar-symbol category therefore still has no empirical true positive and
is intentionally reported as `unconfirmed` / `no_confirmed_true_positive`.
