# ghidra-mcp

Three MCP server implementations for headless Ghidra. Each one has two parts:

- `ghidra_headless_server.py` starts Ghidra's JVM through PyGhidra, opens a
  Ghidra project and serves a REST API.
- `bridge_mcp_ghidra.py` is a FastMCP server. It exposes the REST API as MCP
  tools (stdio or SSE).

No Ghidra GUI or Java plugin is necessary. The REST API is compatible with the
GhidraMCP plugin API, and the server adds many more endpoints.

| Folder | Instance | Default port | Description |
| --- | --- | --- | --- |
| `flextalk/` | `ghidra-mcp` | 8080 | First implementation, made for the FlexTalk TTS reverse-engineering project. Single project. |
| `creatures/` | `ghidra-mcp-2` | 8082 | Isolated second instance, made for the Creatures reverse-engineering work. Multi-project (`projects.json`), program import, map-file symbols, GhidraScript runs, capability catalog, x86/MSVC tools (vtables, ECX/thiscall receivers, SEH, x87 stack, switch dispatch). |
| `classic-mac/` | `oldmac-re` | 8084 | Classic Macintosh 68k variant. Merged from the two other servers (see `merge-manifest.json`), with x86-only tools removed and Mac resource-fork tools added. Includes the `ClassicMacLoader` Ghidra extension. |

## Requirements

- Ghidra 12.1 (set `GHIDRA_INSTALL_DIR`)
- Python 3.10 or later, in a venv with `pyghidra`, `mcp>=1.2.0,<2` and `requests`

## Run

```sh
export GHIDRA_INSTALL_DIR=/opt/ghidra_12.1_PUBLIC
python ghidra_headless_server.py --port 8082
python bridge_mcp_ghidra.py --ghidra-server http://127.0.0.1:8082/
```

The `*.init` files are the SysV init scripts used to run the servers as
services. They contain local paths. Change them before you use them.

### creatures/

`instance_config.py` reads its settings from `GHIDRA_MCP_*` environment
variables. The server reads the project registry from `projects.json` next to
the script. Copy `projects.example.json` to `projects.json` and set your
project paths.

### classic-mac/

`mcp_server.py` is the MCP entry point. It loads `vendor/bridge_mcp_ghidra.py`
and adds the Mac tools. `service_manager.py` starts the REST server. It expects
the original workspace layout (`MacRE/projects`), so you must change it for a
different layout. Read `GUIDANCE.md` and `ADAPTATION.md` before you extend the
tools. `fixtures/` has small 68k test binaries.

## Attribution

- `bridge_mcp_ghidra.py` and the REST API come from
  [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP)
  (Apache-2.0). They have been extended.
- `classic-mac/ClassicMacLoader/` is a modified copy of the Classic Mac
  resource-fork loader from
  [hippietrail/RetroGhidra](https://github.com/hippietrail/RetroGhidra).
