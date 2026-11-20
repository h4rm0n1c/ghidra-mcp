# Analysis safeguards and adaptation priorities

## Separate the representations

For each analysis establish the input container, CPU/language, byte order, pointer storage width, runtime addressing mode, ABI and code-segment mapping. Confirm the active program rather than relying on a previous import. Decode memory using program endianness and file fields using their specified format; host byte order must never decide. Preserve original bytes alongside interpreted values. Verify signedness, field width, structure alignment and partial reads. IEEE floats, SANE extended data and integer bit patterns need distinct readers.

A 32-bit stored Mac pointer is not evidence that every bit participates in address translation. Preserve it before any justified address normalization; handles require an additional, potentially movable master-pointer indirection. Never globally strip the top byte. Synthetic CODE addresses require an explicit segment/resource/offset mapping before comparison with runtime observations.

Byte order and bit numbering are independent. Toolbox BitTst starts at the high-order bit of a byte and proceeds through memory. Its numbering differs from MC680x0 instruction bit numbering. The existing translate_subfield_mask tool accepts a numeric mask within a byte and accounts for byte position; it does not accept Toolbox bit indices.

Apple PT 14 documents Pascal stack result space, parameter order and callee cleanup, contrasts C order/cleanup/results, and discusses register-based calls. Infer conventions per routine and compiler, including glue, rather than setting one guessed ABI across a program. A6 frames and A5-relative accesses provide evidence but do not establish complete semantics.

## Corpus anchors actually read

- corpus 26387: Apple Technote PT 14, *Glue Code: It Gets You Out of Sticky Situations*, May 1993; parameter passing and assembly glue examples.
- corpus 19092: *Inside Macintosh: Operating System Utilities*, BitTst reference; explicit opposite numbering to MC680x0.
- corpus 41702: Universal Interfaces Endian.h, interfaces-libs-3.6; explicit source/native/destination endian conversions and mac68k structure alignment. This header is dated 1997–2001: supporting interface evidence, not proof that its APIs were present in System 7.
- corpus 20996: *Imaging With QuickDraw*, Offscreen Graphics Worlds summary; separate Pascal/C declarations and trap-selector table illustrate why prototypes alone do not explain dispatch.

## Preserve ideas, replace assumptions

| Existing idea | Useful Mac adaptation | Evidence required before exposing |
| --- | --- | --- |
| Decompiler constant verification | Match generated constants to encoded operands and p-code, including sign extension and truncation | 68k variable-length instructions, literal pools/data, endian fixtures; reject ambiguous matches |
| Structure/index solver | Accumulate field-offset, stride and access-width constraints | A-register addressing, signed displacements, packed records, handles and A5 globals; hypotheses must remain distinct from applied types |
| ECX/thiscall receiver recovery | Recover implicit register parameters and hidden environment dependencies | Per-compiler A/D register use and glue; no universal replacement of ECX with A0 |
| ABI/stack diagnostics | Explain stack delta, result slots, argument order and saved registers | Pascal/C/register-based fixtures and documented trap interfaces |
| Vtable and switch recovery | Discover function-pointer tables, callbacks, dispatch selectors and CODE jump tables | Big-endian target reads, executable-range checks and relocation-aware addresses; table shape alone is insufficient |
| x87 dataflow tracing | Trace 68881/68882 operations or SANE call effects | Actual instruction/call semantics, precision and exception behavior; no x87 stack model substitution |
| SEH/hook analysis | Track actual exception vectors, trap patches and callback chains when encountered | Mac-specific mechanisms and observed instructions; Windows SEH assumptions do not transfer |

The pointer-table implementations have now been adapted and exposed as `find_function_pointer_tables` and `resolve_function_pointer_table`. Both use the active program's byte order and pointer size. Scanning is read-only, bounded to 1 MiB, includes word-aligned 68k tables, retains repeated callbacks, and reports raw slot bytes plus exact executable function-entry evidence. It makes no C++ ABI/RTTI inference and does not discard presumed MSVC padding. Resolution is an explicit mutation, limited to 4096 slots; incomplete reads fail before changes. Non-executable, unmapped, odd 68k and existing-function-interior targets are rejected. Zero slots mean null; address-zero functions, encoded/relative tables and relocations need a different explicit representation. Other x86-specific implementations remain design references and are not enabled. See VALIDATION.md for actual Ghidra integration checks.

Prioritize byte/provenance reporting and ABI diagnostics, then trap/selector and indirect-call evidence, then richer inference driven by an actual target. Build diagnostic, bounded, nonmutating tools first; keep proposed types and flow edges reviewable before applying them. No new heuristics have been enabled by these notes.
