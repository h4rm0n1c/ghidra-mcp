# Classic Macintosh RE

This service owns OldMacRE, HTTP 127.0.0.1:8084, separately from FlexTalk (8080) and Creatures (8082). Use only this project's programs. Read `oldmac-re://program` to see the active program.

For Mac applications use `prepare_mac_resources(path)` for MacBinary, AppleDouble/AppleSingle, or raw resource forks. It writes a hashed copy under MacRE/imports and inventories types, signed IDs, names, sizes and attributes. Then `import_program(resource_fork, analyze=true)`. Never feed a MacBinary wrapper to the raw loader. Use `switch_program` for an existing import. For ROM dumps or individual extracted code use `import_raw_68k(path, base_address, analyze=false)` with the correct mapped ROM address; analyze after identifying executable regions and entry points.

The private ClassicMacLoader extension handles ordinary near-model CODE resources and CODE0 jump-table entry points. CODE blocks are packed at synthetic addresses, not live emulator addresses. Far-model and compressed CODE resources fail import explicitly. Relocation, A5 globals, cross-segment jump-table resolution and Pascal/Toolbox calling conventions are not fully modeled. A successful import does not establish these semantics. Preserve resource IDs and file offsets when reporting findings. Trap p-code and float support from GhidraApple are not installed. A-line traps may stop correct decompilation; inspect disassembly and consult the corpus for trap signatures and stack behavior. Default 68000 compiler convention is not proof of a Macintosh ABI.

Use bounded disassemble_range/search_function_disassembly, decompile_function_by_address, raw get_bytes, xrefs, exact facts, call graphs and types together. Check generated C against instructions, particularly traps and A5-relative accesses. Memory scalar/array readers use the active program's endianness. Pointer arrays are 32-bit, appropriate for this 68k target. IEEE float readers do not decode SANE 80-bit extended values.

Creatures provides project isolation, imports, scripts, full prototypes, namespaces, type edits and autosaving. FlexTalk contributes disassembly range/search, type lookup diagnostics/deletion, and calling convention/call-fixup controls. The MCP surface excludes x86-only ABI/SEH/ECX/x87/switch and vtable heuristics. Internal inherited HTTP endpoints are not the supported Mac API. `get_guidance` returns this document, not the inherited x86 workflow catalog.

For source maps use apply_map_symbols after confirming its addresses agree with the synthetic layout. Ghidra scripts are restricted to tools/mac-re/scripts by the project registry. Save before ending work. Existing application sources and disk images are never modified by import. MCP connection lifetime does not own the service lifetime.

## Interpretation and future tooling

For sustained investigations, retain evidence with specimen hashes, resource
ranges, synthetic mappings, observed/derived/hypothesized status, coverage and
unresolved edges. Reuse saved observations through bounded views rather than
repeating expensive producers or treating truncated output as complete. Verify
decoder/tool changes against independent bytes or fixtures and the actual MCP
workflow. The PortInTalk-specific procedure and reviewed upstream references
are in `MacRE/PortInTalk/ANALYSIS_WORKFLOW.md`; it adapts REA evidence/tool-design
practices and Superpowers debugging/verification to this workspace. It does
not require another RE service or supersede Mac-specific rules.

Endianness does not determine bit numbering or ABI. Read [adaptation notes](ADAPTATION.md) before extending inherited tools. In particular, Toolbox BitTst numbers bits from the high-order end, unlike MC680x0 bit instructions (corpus 19092). A byte-offset/mask translator is not a BitTst index translator. Preserve 32-bit stored pointers and establish the runtime addressing mode separately. Keep file offsets, synthetic Ghidra addresses and live addresses distinct.

The excluded x86 implementations preserve useful ideas: indirect-call discovery, structure constraints, ABI diagnostics, floating-point dataflow and checks of decompiled constants. Their absence from the MCP surface is a compatibility boundary, not a decision to abandon those capabilities. Reintroduce each with target-specific evidence and meaningful fixtures.

Use `find_function_pointer_tables(start, end, min_slots)` for bounded read-only discovery of pointer runs to existing executable functions. This includes word-aligned 68k tables and repeated callbacks; matching runs are evidence, not a vtable classification. `resolve_function_pointer_table(address, count)` explicitly creates functions at valid executable targets and annotates the table. Both honor program byte order and pointer size, preserve full pointer values, and treat zero as null. Resolution rejects incomplete tables and invalid/odd/interior targets. Relative pointers, encoded pointers and segment relocation are not handled automatically.
