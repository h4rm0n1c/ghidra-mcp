#!/usr/bin/env python3
"""Reproduce the two instruction-confirmed relative component dispatch maps.

This is specific to the preserved PortInTalk specimens, not a generic code
scanner. Resource offsets are fork-relative; synthetic addresses are not live.
"""
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROJECT = ROOT / "MacRE/PortInTalk"


def map_table(payload, table, pc_base, selectors, synthetic):
    rows = []
    for index, selector in enumerate(selectors):
        displacement = struct.unpack_from(">h", payload, table + index * 2)[0]
        target = pc_base + displacement
        if target % 2 or not 0 <= target < len(payload):
            raise ValueError("Invalid relative dispatch target")
        rows.append({"selector": selector, "payload_offset": target,
                     "synthetic_address": f"{synthetic + target:08x}"})
    return rows


def main():
    specimens = [
        ("MacinTalk3", "binaries/MacinTalk3-ttvi-10.bin", "inventory.json",
         "ttvi", 10, 0x100000, [(0x36, 0x34, range(-1, -7, -1)),
                                (0xea, 0xe8, range(10))]),
        ("MacinTalkPro", "binaries/reseditor/MacinTalkPro-gtse-1.bin",
         "reseditor-inventory.json", "gtse", 1, 0x200000,
         [(0xbc, 0xba, range(10))]),
    ]
    results = []
    for name, filename, inventory, kind, rid, base, tables in specimens:
        payload = (PROJECT / filename).read_bytes()
        entries = json.loads((PROJECT / inventory).read_text())
        matches = [(e, r) for e in entries for r in e["resources"]
                   if r["type"] == kind and r["id"] == rid
                   and r["size"] == len(payload)]
        if len(matches) != 1:
            raise ValueError("Ambiguous resource provenance")
        entry, resource = matches[0]
        fork = Path(entry["resource_fork"]).read_bytes()
        if hashlib.sha256(fork).hexdigest() != entry["sha256"]:
            raise ValueError("Resource fork hash mismatch")
        offset = resource["offset"]
        if fork[offset:offset + resource["size"]] != payload:
            raise ValueError("Payload differs from preserved resource")
        rows = [row for table, pc, selectors in tables
                for row in map_table(payload, table, pc, selectors, base)]
        for row in rows:
            row["resource_fork_offset"] = offset + row["payload_offset"]
        results.append({"specimen": name, "payload": filename,
                        "sha256": hashlib.sha256(payload).hexdigest(),
                        "resource_type": kind, "resource_id": rid,
                        "resource_payload_offset": offset,
                        "synthetic_base": f"{base:08x}", "dispatch": rows})
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
