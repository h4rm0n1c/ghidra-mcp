# ghidra-mcp-2 surface audit

Run the full source-only inventory with:

```sh
./bin/python audit_surface.py --format markdown
```

The baseline inventory is 98 MCP tools, backed by 69 GET and 36 POST
headless handlers.  It currently finds no bridge endpoint that lacks a
server handler.  Three server handlers are deliberately not exposed by the
bridge (`decompile`, `functions`, and `rename_variable_by_address`); the
first two are aliases and the third needs target-based semantic validation
before it is made public in v2.

The audit classifies 68 tools as read-only, 25 as mutations, and 5 as
requiring review.  This is a heuristic from tool names, not an authorization
boundary.  The next v2 API increment should make those properties explicit
in capability metadata, including domain, evidence/confidence tier and
pagination/limit behaviour.

The specialised tracing, evidence, type-recovery and bulk-analysis tools are
the valuable part of this surface.  Keep them as first-class workflows;
consolidate only aliases after controlled-target contract tests establish
that their request and response semantics are equivalent.
