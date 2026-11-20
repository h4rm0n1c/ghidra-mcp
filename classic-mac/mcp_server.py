import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from service_manager import ensure_service
ensure_service('re')
sys.path.insert(0,str(Path(__file__).parent/'vendor'))
import bridge_mcp_ghidra as bridge
bridge.ghidra_server_url='http://127.0.0.1:8084/'
sys.path.insert(0,str(Path(__file__).parent))
from mac_resources import prepare
@bridge.mcp.tool()
def prepare_mac_resources(path: str, container: str = 'auto') -> dict:
    """Extract MacBinary/AppleDouble to an immutable hashed resource fork; list resource types and IDs. Does not import or modify source."""
    return prepare(path,container)
@bridge.mcp.tool()
def import_raw_68k(path: str, base_address: str = '0', analyze: bool = False) -> dict:
    """Import raw ROM/code as big-endian 68000 with explicit base address. Use prepare_mac_resources + import_program for Mac applications."""
    return bridge.safe_post_json_result('import_raw_68k', {'path':path,'base_address':base_address,'analyze':analyze})
@bridge.mcp.tool()
def find_function_pointer_tables(start: str, end: str, min_slots: int = 3) -> dict:
    """Read-only bounded scan of target-endian pointers to existing executable function entries. Includes word-aligned 68k tables and repeated callbacks. Does not infer vtables or relocate/mask pointers."""
    return bridge.safe_get_json('find_vtable_candidates', {'start':start,'end':end,'min_slots':min_slots})
@bridge.mcp.tool()
def resolve_function_pointer_table(address: str, count: int) -> dict:
    """Explicitly create functions at executable targets in a pointer table and annotate the table. Uses target byte order/width; rejects odd 68k/interior/unmapped targets and incomplete tables. Zero means null. Mutates the active program."""
    return bridge.safe_post_json_result('resolve_vtable', {'address':address,'count':count})
bridge.mcp.run()
