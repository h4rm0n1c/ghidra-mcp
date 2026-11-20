#!/usr/bin/env python3
"""
Headless Ghidra HTTP server — provides GhidraMCP-compatible API endpoints
for use with bridge_mcp_ghidra.py.  Uses PyGhidra to embed Ghidra's JVM.

Start:
    export GHIDRA_INSTALL_DIR=/opt/ghidra_12.1_PUBLIC
    python3 ghidra_headless_server.py [--port 8082]

The server opens an instance-configured project and serves decompiled functions,
cross-references, strings, etc. via the same REST API bridge_mcp_ghidra.py expects.
"""

import argparse
import hashlib
import json
import logging
import os
import re
import signal
import sys
import traceback
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import jpype
from instance_config import DEFAULT_CATEGORY, DEFAULT_PROGRAM_PATH, PROJECT_DIR, PROJECT_NAME, PROJECTS_FILE

HAS_GHIDRA = False
try:
    import pyghidra
    HAS_GHIDRA = True
except ImportError:
    pass

logger = logging.getLogger("ghidra-headless-server")

# ── Frequently-used Ghidra/Java classes ────────────────────────────
# Resolved once via _init_java_classes(), called right after pyghidra.start()
# in main() — NOT at Python import time, since the JVM isn't up yet then.
# A missing/renamed class now fails loudly at server startup instead of
# silently deep inside a random write endpoint (the same failure class that
# broke analyze()'s Disassembler lookup).
JObjectClass = None
SourceType = None
CodeUnit = None
DataTypeParser = None
DataTypeParserAllowedTypes = None
SymbolType = None
Function = None


def _init_java_classes():
    global JObjectClass, SourceType, CodeUnit, DataTypeParser, DataTypeParserAllowedTypes, SymbolType, Function
    JObjectClass = jpype.JClass('java.lang.Object')
    SourceType = jpype.JClass('ghidra.program.model.symbol.SourceType')
    CodeUnit = jpype.JClass('ghidra.program.model.listing.CodeUnit')
    DataTypeParser = jpype.JClass('ghidra.util.data.DataTypeParser')
    DataTypeParserAllowedTypes = jpype.JClass('ghidra.util.data.DataTypeParser$AllowedDataTypes')
    SymbolType = jpype.JClass('ghidra.program.model.symbol.SymbolType')
    Function = jpype.JClass('ghidra.program.model.listing.Function')

class GhidraAPI:
    _DECOMPILE_CONSTANT_DETECTORS = {
        "large_arithmetic_constant": {
            "confidence": "confirmed",
            "validation_status": "confirmed_true_positive",
            "validation_case": "ft_sdict.dll:0x1050ad82",
        },
        "function_symbol_used_as_scalar": {
            "confidence": "unconfirmed",
            "validation_status": "no_confirmed_true_positive",
            "validation_case": None,
        },
    }
    """Bridges PyGhidra calls to GhidraMCP's JSON HTTP response format."""

    # Hardcoded, not configurable: auto-save every this-many successful
    # write transactions, so RE work (renames, comments, prototypes,
    # analysis, etc.) survives a restart without depending on the model
    # remembering to call save() itself. Batched rather than per-write to
    # avoid thrashing disk on every single edit. See _with_transaction and
    # main()'s shutdown path (which always saves once more regardless of
    # this counter, so a clean stop/restart never loses the last batch).
    _AUTO_SAVE_INTERVAL = 10

    def __init__(self):
        self._project = None
        self._program = None
        self._flat = None
        self._function_manager = None
        self._ref_manager = None
        self._listing = None
        self._current_program_path = None
        self._write_count = 0
        self._program_consumer = None
        self._projects = {}
        self._project_key = None
        self._last_program = {}
        self._registry = {"projects": {}}

    @property
    def program(self):
        if self._program is None:
            raise RuntimeError("No program loaded")
        return self._program

    @property
    def flat(self):
        if self._flat is None:
            raise RuntimeError("No flat API")
        return self._flat

    def set_project(self, project):
        self._project = project

    def switch_program(self, program_path):
        """Close current program and open a new one from the active project."""
        from ghidra.util.task import ConsoleTaskMonitor
        # Release the current program -- saved first, or any edits made since
        # the last auto-save would be discarded -- with the same consumer it
        # was opened with.  (Releasing with a fresh Object, as this used to,
        # is refused by Ghidra, so every switch left the old program open.)
        self._release_program()

        df = self._project.getProjectData().getFile(program_path)
        if df is None:
            raise RuntimeError(f"Program not found in project: {program_path}")

        consumer = JObjectClass()
        program = df.getDomainObject(consumer, True, False, ConsoleTaskMonitor())
        self._program = program
        self._program_consumer = consumer
        self._current_program_path = program_path

        # Set up flat API
        flat_cls = jpype.JClass("ghidra.program.flatapi.FlatProgramAPI")
        self._flat = flat_cls(program)
        self._function_manager = program.getFunctionManager()
        self._ref_manager = program.getReferenceManager()
        self._listing = program.getListing()
        logger.info("Switched to program: %s (%d functions)",
                     program.getName(), self._function_manager.getFunctionCount())

    def set_program(self, program, flat_api=None):
        self._program = program
        if flat_api:
            self._flat = flat_api
        else:
            flat_cls = jpype.JClass("ghidra.program.flatapi.FlatProgramAPI")
            self._flat = flat_cls(program)
        self._function_manager = program.getFunctionManager()
        self._ref_manager = program.getReferenceManager()
        self._listing = program.getListing()

    def list_programs(self):
        """List all programs available in the project."""
        progs = []
        root = self._project.getProjectData().getRootFolder()

        def collect(folder, prefix=""):
            for df in folder.getFiles():
                path = f"{prefix}/{df.getName()}"
                progs.append({
                    "path": path,
                    "name": df.getName(),
                    "active": path == self._current_program_path,
                })
            for child in folder.getFolders():
                collect(child, f"{prefix}/{child.getName()}")

        collect(root)
        return json.dumps({"programs": progs, "total": len(progs)})

    # ── Projects ───────────────────────────────────────────────────
    # One server, several Ghidra projects (projects.json).  Every project
    # opened stays open and holds its own lock; one project and one program
    # are active at a time, and every existing endpoint works on those.

    def set_registry(self, registry):
        self._registry = registry or {"projects": {}}

    def reload_registry(self):
        """Re-read projects.json, so projects and script collections can be
        added without a restart.  Projects already open stay open, and one
        opened from the command line but missing from the file is kept."""
        if not os.path.exists(PROJECTS_FILE):
            return
        with open(PROJECTS_FILE, encoding="utf-8") as handle:
            fresh = json.load(handle)
        for key, entry in self._registry.get("projects", {}).items():
            fresh.setdefault("projects", {}).setdefault(key, entry)
        self._registry = fresh

    def _project_entry(self, key):
        entry = self._registry.get("projects", {}).get(key)
        if entry is None:
            raise RuntimeError(
                f"Unknown project '{key}'; known: "
                + ", ".join(sorted(self._registry.get("projects", {}))))
        return entry

    def _active_entry(self):
        if self._project_key is None:
            return {}
        return self._registry.get("projects", {}).get(self._project_key, {})

    def _open_project(self, key):
        if key in self._projects:
            return self._projects[key]
        entry = self._project_entry(key)
        if entry.get("create"):
            os.makedirs(entry["dir"], exist_ok=True)
        project = pyghidra.open_project(entry["dir"], entry["name"],
                                        create=bool(entry.get("create")))
        self._projects[key] = project
        logger.info("Project opened: %s (%s)", key, project.getName())
        return project

    def _release_program(self):
        """Save and release the active program, if any."""
        if self._program is None:
            return
        try:
            self._do_save()
        except Exception:
            logger.exception("Save before releasing program failed")
        try:
            self._program.release(self._program_consumer or JObjectClass())
        except Exception:
            pass
        self._program = None
        self._program_consumer = None
        self._flat = None
        self._function_manager = None
        self._ref_manager = None
        self._listing = None
        self._current_program_path = None

    def switch_project(self, key, program_path=""):
        """Make another project active, then open program_path, the program
        last used in that project, or its default_program."""
        self.reload_registry()
        entry = self._project_entry(key)
        project = self._open_project(key)
        if self._project_key is not None and self._current_program_path:
            self._last_program[self._project_key] = self._current_program_path
        self._release_program()
        self._project = project
        self._project_key = key
        wanted = (program_path or self._last_program.get(key)
                  or entry.get("default_program") or "")
        if wanted and project.getProjectData().getFile(wanted) is not None:
            self.switch_program(wanted)
        return json.dumps({
            "status": "ok",
            "project": key,
            "program": self._current_program_path,
            "programs": json.loads(self.list_programs())["programs"],
        })

    def list_projects(self):
        self.reload_registry()
        projects = []
        for key, entry in sorted(self._registry.get("projects", {}).items()):
            gpr = os.path.join(entry["dir"], entry["name"] + ".gpr")
            projects.append({
                "project": key,
                "description": entry.get("description", ""),
                "location": gpr,
                "exists": os.path.exists(gpr),
                "open": key in self._projects,
                "active": key == self._project_key,
                "program": (self._current_program_path if key == self._project_key
                            else self._last_program.get(key)
                            or entry.get("default_program")),
                "scripts": entry.get("scripts"),
            })
        return json.dumps({"projects": projects, "active": self._project_key})

    def close_projects(self):
        """Save and release everything; used on shutdown."""
        self._release_program()
        for key, project in list(self._projects.items()):
            try:
                project.close()
            except Exception:
                logger.exception("Closing project %s failed", key)
        self._projects.clear()

    # ── Import ─────────────────────────────────────────────────────

    def import_program(self, path, folder="/", analyze=False, raw_base=None):
        """Import a binary into the active project and make it the active
        program.  With import_roots set for the project, only files below
        those directories may be imported."""
        if self._project is None:
            return json.dumps({"error": "No active project"})
        source = os.path.realpath(path)
        if not os.path.isfile(source):
            return json.dumps({"error": f"Not a file: {path}"})
        roots = [os.path.realpath(r) for r in self._active_entry().get("import_roots", [])]
        if roots and not any(source.startswith(r + os.sep) for r in roots):
            return json.dumps({"error": f"{path} is not below this project's import_roots: {roots}"})
        name = os.path.basename(source)
        target = (folder.rstrip("/") + "/" + name) if folder != "/" else "/" + name
        if self._project.getProjectData().getFile(target) is not None:
            return json.dumps({"error": f"{target} is already in the project; switch_program to it"})

        File = jpype.JClass("java.io.File")
        MessageLog = jpype.JClass("ghidra.app.util.importer.MessageLog")
        ProgramLoader = jpype.JClass("ghidra.app.util.importer.ProgramLoader")
        TaskMonitor = jpype.JClass("ghidra.util.task.TaskMonitor")
        log = MessageLog()
        builder = (ProgramLoader.builder().source(File(source)).project(self._project)
                   .projectFolderPath(folder).log(log).monitor(TaskMonitor.DUMMY))
        if raw_base is not None:
            builder = (builder.loaders("BinaryLoader").language("68000:BE:32:default")
                       .compiler("default").addLoaderArg("-loader-baseAddr", raw_base))
        results = builder.load()
        consumer = JObjectClass()
        try:
            results.save(TaskMonitor.DUMMY)
            loaded = results.getPrimary()
            program_path = loaded.getProjectFolderPath().rstrip("/") + "/" + loaded.getName()
        finally:
            results.close()
        self.switch_program(program_path)
        response = {
            "status": "ok",
            "program": program_path,
            "functions": self._function_manager.getFunctionCount(),
            "import_log": str(log.toString())[:4000],
        }
        if analyze:
            response["analysis"] = json.loads(self.analyze())
        return json.dumps(response)

    # ── MSVC linker maps ───────────────────────────────────────────

    _MAP_SYMBOL = re.compile(
        r"^\s*([0-9a-fA-F]{4}):([0-9a-fA-F]{8})\s+(\S+)\s+([0-9a-fA-F]{8})\s+"
        r"(f\s+)?(i\s+)?(\S+)?\s*$")

    def apply_map_symbols(self, map_path, demangle=True, create_functions=True):
        """Name the active program from an MSVC linker .map: every public and
        static symbol at its Rva+Base address, a function where the map
        flags one (f), a label otherwise, demangled into namespaces and
        signatures where the name is a mangled C++ name."""
        with open(map_path, encoding="latin-1") as handle:
            lines = handle.read().splitlines()
        symbols = []
        in_symbols = False
        for line in lines:
            if "Publics by Value" in line or "Static symbols" in line:
                in_symbols = True
                continue
            if not in_symbols:
                continue
            match = self._MAP_SYMBOL.match(line)
            if match and int(match.group(1), 16) != 0:
                symbols.append((match.group(3), int(match.group(4), 16),
                                bool(match.group(5)), match.group(7) or ""))

        def work():
            DemanglerCmd = jpype.JClass("ghidra.app.cmd.label.DemanglerCmd")
            TaskMonitor = jpype.JClass("ghidra.util.task.TaskMonitor")
            factory = self._program.getAddressFactory()
            memory = self._program.getMemory()
            symbol_table = self._program.getSymbolTable()
            counts = {"symbols": len(symbols), "functions_created": 0, "labels": 0,
                      "demangled": 0, "outside_memory": 0, "failed": 0}
            failures = []
            for name, va, is_function, obj in symbols:
                try:
                    addr = factory.getDefaultAddressSpace().getAddress(va)
                    if not memory.contains(addr):
                        counts["outside_memory"] += 1
                        continue
                    if is_function and create_functions and \
                            self._function_manager.getFunctionAt(addr) is None:
                        if self._flat.createFunction(addr, None) is not None:
                            counts["functions_created"] += 1
                    label = symbol_table.createLabel(addr, name, SourceType.IMPORTED)
                    label.setPrimary()
                    counts["labels"] += 1
                    if demangle and name.startswith("?"):
                        if DemanglerCmd(addr, name).applyTo(self._program, TaskMonitor.DUMMY):
                            counts["demangled"] += 1
                except Exception as error:
                    counts["failed"] += 1
                    if len(failures) < 20:
                        failures.append({"name": name, "address": hex(va), "error": str(error)})
            counts["failures"] = failures
            counts["status"] = "ok"
            return json.dumps(counts)

        return self._with_transaction("apply_map_symbols", work)

    # ── Ghidra scripts ─────────────────────────────────────────────

    def _script_dir(self):
        self.reload_registry()
        scripts = self._active_entry().get("scripts")
        if not scripts:
            raise RuntimeError(f"Project '{self._project_key}' has no script collection")
        return os.path.realpath(scripts)

    def list_scripts(self):
        """The active project's scripts: files at the top of its collection,
        then one entry per numbered stage folder, in order."""
        root = self._script_dir()
        scripts = []
        for entry in sorted(os.listdir(root)):
            full = os.path.join(root, entry)
            if os.path.isfile(full) and entry.endswith((".java", ".py")):
                scripts.append({"stage": "", "script": entry, "path": full})
            elif os.path.isdir(full):
                files = sorted(f for f in os.listdir(full) if f.endswith((".java", ".py")))
                for f in files:
                    scripts.append({"stage": entry, "script": f,
                                    "path": os.path.join(full, f)})
                if not files:
                    scripts.append({"stage": entry, "script": None, "path": None,
                                    "note": "empty stage folder"})
        return json.dumps({"project": self._project_key, "root": root,
                           "scripts": scripts})

    def run_script(self, script, args=""):
        """Compile and run one GhidraScript from the active project's
        collection against the active program, inside one transaction, and
        return what it printed.  script is a file name, a stage folder name
        or a path below the collection."""
        root = self._script_dir()
        listed = [s for s in json.loads(self.list_scripts())["scripts"] if s["path"]]
        matches = [s for s in listed
                   if script in (s["script"], s["stage"], s["path"],
                                 os.path.relpath(s["path"], root))
                   or s["script"] == script + ".java"]
        if len(matches) != 1:
            return json.dumps({"error": f"'{script}' matches {len(matches)} scripts",
                               "candidates": [m["path"] for m in matches][:10]})
        path = matches[0]["path"]

        def work():
            File = jpype.JClass("java.io.File")
            ResourceFile = jpype.JClass("generic.jar.ResourceFile")
            StringWriter = jpype.JClass("java.io.StringWriter")
            PrintWriter = jpype.JClass("java.io.PrintWriter")
            GhidraScriptUtil = jpype.JClass("ghidra.app.script.GhidraScriptUtil")
            GhidraState = jpype.JClass("ghidra.app.script.GhidraState")
            ScriptControls = jpype.JClass("ghidra.app.script.ScriptControls")
            ProgramLocation = jpype.JClass("ghidra.program.util.ProgramLocation")
            TaskMonitor = jpype.JClass("ghidra.util.task.TaskMonitor")
            output = StringWriter()
            writer = PrintWriter(output, True)
            bundle_host = GhidraScriptUtil.acquireBundleHostReference()
            try:
                source = ResourceFile(File(path))
                directory = source.getParentFile()
                if bundle_host.getExistingGhidraBundle(directory) is None:
                    bundle_host.add(directory, True, False)
                provider = GhidraScriptUtil.getProvider(source)
                if provider is None:
                    return json.dumps({"error": f"No script provider for {path}"})
                instance = provider.getScriptInstance(source, writer)
                if args:
                    instance.setScriptArgs(jpype.JArray(jpype.JString)(args.split()))
                location = ProgramLocation(self._program, self._program.getMinAddress())
                state = GhidraState(None, self._project, self._program, location, None, None)
                instance.execute(state, ScriptControls(writer, writer, TaskMonitor.DUMMY))
            except Exception as error:
                writer.flush()
                return json.dumps({"error": f"{type(error).__name__}: {error}",
                                   "script": path, "output": str(output.toString())[-20000:]})
            finally:
                GhidraScriptUtil.releaseBundleHostReference()
            writer.flush()
            return json.dumps({"status": "ok", "script": path,
                               "output": str(output.toString())[-20000:]})

        return self._with_transaction("run_script " + os.path.basename(path), work)

    def get_all_functions(self, offset=0, limit=100):
        funcs = []
        if self._function_manager:
            it = self._function_manager.getFunctions(True)
            while it.hasNext():
                fn = it.next()
                funcs.append({
                    "name": self._qname(fn),
                    "address": str(fn.getEntryPoint()),
                    "body": str(fn.getBody()),
                })
        total = len(funcs)
        funcs = funcs[offset:offset + limit]
        return json.dumps({"functions": funcs, "total": total})

    def _preview_bytes_at(self, addr_str, max_len=40):
        """Best-effort short preview of the data at addr_str: a quoted string
        if printable and NUL-terminated within max_len, else a short hex
        dump of the first few bytes. Used to auto-resolve DAT_/PTR_DAT_
        decompiler symbols instead of requiring a separate get_bytes call
        per constant."""
        try:
            addr = self.program.getAddressFactory().getAddress(addr_str)
            if addr is None:
                return None
            raw, actual = self._read_raw_bytes(addr, max_len)
            if not raw:
                return None
            nul = raw.find(b'\x00')
            candidate = raw[:nul] if nul >= 0 else raw
            if candidate and 0 < len(candidate) <= max_len and \
                    all(32 <= b < 127 for b in candidate):
                return {"type": "string", "value": candidate.decode('latin1')}
            preview_len = min(8, actual)
            return {"type": "bytes",
                    "value": " ".join(f"{b:02x}" for b in raw[:preview_len])}
        except Exception:
            return None

    def _resolve_dat_constants(self, decompiled_text):
        """Best-effort inline preview for DAT_xxxxxxxx / PTR_DAT_xxxxxxxx
        symbols referenced in decompiler output. Resolves the single most
        common manual round trip in RE work against this server: "what does
        this constant actually contain" -- previously a separate get_bytes
        call per symbol. One level of pointer dereference for PTR_DAT_
        (reads the pointer, then previews what it points to)."""
        import re
        resolved = {}
        for m in re.finditer(r'\b(PTR_)?DAT_([0-9a-fA-F]{6,8})\b', decompiled_text):
            is_ptr, hexaddr = m.group(1), m.group(2)
            symbol = m.group(0)
            if symbol in resolved:
                continue
            addr_str = "0x" + hexaddr
            if is_ptr:
                try:
                    addr = self.program.getAddressFactory().getAddress(addr_str)
                    raw, n = self._read_raw_bytes(addr, 4)
                    if n == 4:
                        ptr_val = int.from_bytes(raw, 'big' if self.program.getLanguage().isBigEndian() else 'little')
                        target_preview = self._preview_bytes_at(f"0x{ptr_val:x}")
                        if target_preview:
                            resolved[symbol] = {"points_to": f"0x{ptr_val:x}",
                                                 **target_preview}
                            continue
                except Exception:
                    pass
            preview = self._preview_bytes_at(addr_str)
            if preview is not None:
                resolved[symbol] = preview
        return resolved

    def decompile_function(self, address_str, offset=0, limit=0):
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})
        func = self._function_manager.getFunctionContaining(addr)
        if func is None:
            return json.dumps({"error": f"No function at {address_str}"})
        decomp = DecompInterface()
        decomp.openProgram(self.program)
        try:
            res = decomp.decompileFunction(func, 0, ConsoleTaskMonitor())
            if res and res.getDecompiledFunction():
                code = res.getDecompiledFunction().getC()
                lines = code.split('\n')
                total_lines = len(lines)
                if limit > 0:
                    sliced = lines[offset:offset + limit]
                elif offset > 0:
                    sliced = lines[offset:]
                else:
                    sliced = lines
                result = {
                    "address": address_str,
                    "name": func.getName(),
                    "decompiled": "\n".join(sliced),
                    "total_lines": total_lines,
                }
                if offset > 0 or (limit > 0 and offset + limit < total_lines):
                    result["truncated"] = True
                try:
                    consts = self._resolve_dat_constants(result["decompiled"])
                    if consts:
                        result["resolved_constants"] = consts
                except Exception:
                    pass
                return json.dumps(result)
            return json.dumps({"error": "Decompilation failed"})
        finally:
            decomp.dispose()

    def _find_function_by_name(self, name):
        """Symbol-table lookup by name, filtered to Function symbols — avoids
        both the getFunction(str,None) overload crash in JPype and the O(n)
        cost of scanning every function in the program per call.

        ``Function.getName()`` is the leaf symbol (for example ``LoadGenome``),
        while RE clients commonly use a Ghidra-qualified spelling
        (``Skeleton::LoadGenome``) to disambiguate methods.  The old lookup
        passed that whole spelling to ``SymbolTable.getSymbols`` and found
        nothing; callers then either failed or retried with a bare name that
        could select an unrelated same-named function.  Match the leaf in the
        symbol table, then verify the namespace-qualified spelling when one
        was supplied.
        """
        if not self._function_manager or self._program is None:
            return None
        requested = (name or "").strip()
        if not requested:
            return None
        leaf_name = requested.rsplit("::", 1)[-1]
        wants_qualified_name = "::" in requested
        sym_table = self._program.getSymbolTable()
        for sym in sym_table.getSymbols(leaf_name):
            if sym.getSymbolType() == SymbolType.FUNCTION:
                fn = self._function_manager.getFunctionAt(sym.getAddress())
                if fn is not None:
                    if wants_qualified_name:
                        namespace_name = str(fn.getParentNamespace().getName(True))
                        qualified_name = namespace_name + "::" + str(fn.getName())
                        if qualified_name != requested:
                            continue
                    return fn
        return None

    def decompile_by_name(self, name):
        if self._function_manager:
            fn = self._find_function_by_name(name)
            if not fn:
                return json.dumps({"error": f"Function '{name}' not found"})
            return self.decompile_function(str(fn.getEntryPoint()))
        return json.dumps({"error": "No function manager"})

    def get_referenced_strings(self, address_str):
        """Given a code address (typically within a function), find all
        defined string data items referenced by instructions in the same
        function body.  Each returned string entry includes the string
        value, its address, and the reference type.  Best-effort: only
        finds references Ghidra's auto-analysis stored."""
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})
        fn = self._function_manager.getFunctionContaining(addr)
        if fn is None:
            return json.dumps({"error": f"No function containing {address_str}"})
        from ghidra.program.model.data import StringDataType, UnicodeDataType
        strings = []
        seen = set()
        instr_iter = self._listing.getInstructions(fn.getBody(), True)
        while instr_iter.hasNext():
            instr = instr_iter.next()
            for ref in self._ref_manager.getReferencesFrom(instr.getAddress()):
                target = ref.getToAddress()
                target_str = str(target)
                if target_str in seen:
                    continue
                data_at = self._listing.getDefinedDataAt(target)
                if data_at:
                    dt = data_at.getDataType()
                    if isinstance(dt, StringDataType) or isinstance(dt, UnicodeDataType):
                        seen.add(target_str)
                        strings.append({
                            "code_address": str(instr.getAddress()),
                            "string_address": target_str,
                            "value": str(data_at.getValue()),
                            "reference_type": str(ref.getReferenceType()),
                        })
        return json.dumps({
            "address": address_str,
            "function": fn.getName(),
            "strings": strings,
            "total": len(strings),
        })

    def list_strings(self, offset=0, limit=2000, filter_str=None):
        strings = []
        if self._listing:
            from ghidra.program.model.data import StringDataType, UnicodeDataType
            data_it = self._listing.getDefinedData(True)
            while data_it.hasNext():
                dd = data_it.next()
                dt = dd.getDataType()
                if not (isinstance(dt, StringDataType) or isinstance(dt, UnicodeDataType)):
                    continue
                val = str(dd.getValue())
                if filter_str and filter_str.lower() not in val.lower():
                    continue
                strings.append({
                    "address": str(dd.getAddress()),
                    "value": val,
                })
        total = len(strings)
        strings = strings[offset:offset + limit]
        return json.dumps({"strings": strings, "total": total})

    def find_function(self, name):
        if self._function_manager:
            fn = self._find_function_by_name(name)
            if fn:
                return json.dumps({
                    "name": fn.getName(),
                    "address": str(fn.getEntryPoint()),
                })
        return json.dumps({"error": f"Function '{name}' not found"})

    def search_functions(self, name_filter, offset=0, limit=100):
        funcs = []
        if self._function_manager:
            it = self._function_manager.getFunctions(True)
            while it.hasNext():
                fn = it.next()
                if name_filter.lower() in fn.getName().lower():
                    funcs.append({
                        "name": fn.getName(),
                        "address": str(fn.getEntryPoint()),
                    })
        total = len(funcs)
        funcs = funcs[offset:offset + limit]
        return json.dumps({"functions": funcs, "total": total})

    def get_function_by_address(self, address_str):
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})
        fn = self._function_manager.getFunctionContaining(addr)
        if fn:
            return json.dumps({
                "name": fn.getName(),
                "address": str(fn.getEntryPoint()),
                "body": str(fn.getBody()),
            })
        return json.dumps({"error": f"No function at {address_str}"})

    def _get_access_size(self, ref):
        """Try to determine the access size in bytes for a reference.
        Checks three strategies:
          1. Defined data type at the target address.
          2. Operand string size prefix (byte/dword/qword ptr).
          3. For DATA refs on x86, check the mnemonic's known access pattern.
        Returns None when size cannot be determined."""
        from_addr = ref.getFromAddress()
        instr = self._listing.getInstructionAt(from_addr)
        if instr is None:
            return None
        op_idx = ref.getOperandIndex()
        if op_idx < 0:
            return None

        # Strategy 1: target address has defined data
        to_addr = ref.getToAddress()
        if to_addr:
            try:
                data_at = self._listing.getDefinedDataAt(to_addr)
                if data_at:
                    return data_at.getLength()
            except Exception:
                pass

        # Strategy 2: parse operand string for size qualifier
        try:
            op_str = instr.getDefaultOperandRepresentation(op_idx)
            if op_str:
                import re
                m = re.search(
                    r'\b(byte|word|dword|qword|tbyte|oword|xmmword|ymmword)\s+ptr\b',
                    op_str, re.IGNORECASE,
                )
                if m:
                    size_map = {
                        'byte': 1, 'word': 2, 'dword': 4,
                        'qword': 8, 'tbyte': 10, 'oword': 16,
                        'xmmword': 16, 'ymmword': 32,
                    }
                    return size_map.get(m.group(1).lower())
        except Exception:
            pass

        # Strategy 3: known x87/fp access sizes by mnemonic
        try:
            mnem = instr.getMnemonicString().upper()
            # x87 loads
            if mnem == 'FLD':
                op_str = instr.getDefaultOperandRepresentation(0)
                if op_str and 'qword' in op_str.lower():
                    return 8
                elif op_str and 'tbyte' in op_str.lower():
                    return 10
                return 4  # default fld is dword
            if mnem in ('FILD', 'FISTP', 'FIST'):
                op_str = instr.getDefaultOperandRepresentation(0)
                if op_str and 'qword' in op_str.lower():
                    return 8
                elif op_str and 'word' in op_str.lower():
                    return 2
                return 4
            if mnem in ('FSTP', 'FST'):
                op_str = instr.getDefaultOperandRepresentation(0)
                if op_str and 'qword' in op_str.lower():
                    return 8
                elif op_str and 'tbyte' in op_str.lower():
                    return 10
                return 4
            if mnem in ('FCOMP', 'FCOM', 'FCOMPP'):
                return 8  # x87 default compare is qword
        except Exception:
            pass

        return None

    def get_xrefs_to(self, address_str, offset=0, limit=100, size=1, grouped=False):
        """Get references TO address, unioned across [address, address+size).
        size defaults to 1 (old exact-address-only behavior). Pass the
        symbol's full declared width (e.g. size=4 for a dword) to also catch
        byte-sub-address accesses (e.g. `test byte ptr [addr+2], 0x10`)
        that a size=1 query at the base address alone will silently miss --
        Ghidra's reference manager indexes refs by their exact target
        address, not by which symbol's declared range contains them.
        Each entry's "to_address" shows which specific byte address the
        reference actually targets, so byte-offset accesses are visible.
        When grouped=True, returns a "groups" structure instead of a flat
        xrefs list: groups are keyed by byte_offset from base_address, each
        containing the refs for that offset, making base-vs-interior access
        patterns visible at a glance."""
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})
        base_offset = addr.getOffset()
        size = max(1, int(size))
        grouped = str(grouped).lower() == "true"
        # Collect grouped: byte_offset → list of ref entries (no to_address)
        groups = {} if grouped else None
        # Collect flat for non-grouped mode
        seen = set()
        result = [] if not grouped else None
        cur = addr
        for _ in range(size):
            for r in self._ref_manager.getReferencesTo(cur):
                from_addr = r.getFromAddress()
                byte_off = cur.getOffset() - base_offset
                if grouped:
                    key = (str(from_addr), str(r.getReferenceType()), byte_off)
                else:
                    key = (str(from_addr), str(r.getReferenceType()), str(cur))
                if key in seen:
                    continue
                seen.add(key)
                fn = self._function_manager.getFunctionContaining(from_addr)
                entry = {
                    "from_address": str(from_addr),
                    "ref_type": str(r.getReferenceType()),
                    "function": self._qname(fn) if fn else None,
                    "function_address": str(fn.getEntryPoint()) if fn else None,
                }
                access_size = self._get_access_size(r)
                if access_size is not None:
                    entry["access_size_bytes"] = access_size
                if grouped:
                    entry["to_address"] = str(cur)
                    groups.setdefault(byte_off, []).append(entry)
                else:
                    entry["to_address"] = str(cur)
                    result.append(entry)
            cur = cur.add(1)
        if grouped:
            group_list = [{"byte_offset": off, "byte_address": str(addr.add(off)),
                           "refs": refs} for off, refs in sorted(groups.items())]
            return json.dumps({
                "base_address": address_str,
                "total": sum(len(g["refs"]) for g in group_list),
                "scanned_size": size,
                "groups": group_list,
            })
        total = len(result)
        result = result[offset:offset + limit]
        return json.dumps({"xrefs": result, "total": total, "scanned_size": size})

    def get_xrefs_from(self, address_str, offset=0, limit=100, size=1):
        """Get references FROM address, unioned across [address, address+size).
        See get_xrefs_to's size param docs -- same sub-byte-blind-spot fix.
        "function"/"function_address" report the containing function of the
        SOURCE side (cur), symmetric with get_xrefs_to; it used to look this
        up on to_addr instead, misreporting the callee as if it were the
        caller for mid-function callsites."""
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})
        size = max(1, int(size))
        seen = set()
        result = []
        cur = addr
        for _ in range(size):
            for r in self._ref_manager.getReferencesFrom(cur):
                to_addr = r.getToAddress()
                key = (str(cur), str(to_addr), str(r.getReferenceType()))
                if key in seen:
                    continue
                seen.add(key)
                fn = self._function_manager.getFunctionContaining(cur)
                entry = {
                    "from_address": str(cur),
                    "to_address": str(to_addr),
                    "ref_type": str(r.getReferenceType()),
                    "function": self._qname(fn) if fn else None,
                    "function_address": str(fn.getEntryPoint()) if fn else None,
                }
                access_size = self._get_access_size(r)
                if access_size is not None:
                    entry["access_size_bytes"] = access_size
                result.append(entry)
            cur = cur.add(1)
        total = len(result)
        result = result[offset:offset + limit]
        return json.dumps({"xrefs": result, "total": total, "scanned_size": size})

    def find_next_symbol(self, address_str, direction="forward", element_size=None):
        """Find the nearest defined symbol (function/label/data) strictly
        after (direction='forward', default) or before (direction='backward')
        the given address. Use this to discover an unlabeled table's real
        extent -- e.g. "what's the next known symbol after this array's
        base?" -- instead of guessing a bound from memory/docs and manually
        subtracting addresses. Returns distance_bytes so you can immediately
        see the gap size.  When element_size is provided (e.g. 4 for uint32[],
        12 for a struct WorkingNode), also computes elements_to_next and
        remainder_bytes for table-geometry work."""
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})
        if element_size is not None:
            element_size = int(element_size)
        forward = direction != "backward"
        sym_table = self._program.getSymbolTable()
        try:
            it = sym_table.getSymbolIterator(addr, forward)
            my_offset = addr.getOffset()
            while it.hasNext():
                sym = it.next()
                sym_addr = sym.getAddress()
                sym_offset = sym_addr.getOffset()
                if sym_offset == my_offset:
                    continue
                fn = self._function_manager.getFunctionContaining(sym_addr)
                data_at = self._listing.getDefinedDataAt(sym_addr)
                distance = (sym_offset - my_offset) if forward else (my_offset - sym_offset)
                result = {
                    "address": str(sym_addr),
                    "name": sym.getName(),
                    "symbol_type": str(sym.getSymbolType()),
                    "distance_bytes": int(distance),
                    "in_function": fn.getName() if fn else None,
                    "data_type": str(data_at.getDataType().getName()) if data_at else None,
                }
                if element_size and element_size > 0:
                    result["element_size"] = element_size
                    result["elements_to_next"] = distance // element_size
                    result["remainder_bytes"] = distance % element_size
                return json.dumps(result)
            return json.dumps({"error": f"No symbol found {direction} of {address_str}"})
        except Exception as e:
            return json.dumps({"error": f"Failed: {str(e)}"})

    def disassemble_function(self, address_str, offset=0, limit=0, start_address=None):
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})
        fn = self._function_manager.getFunctionContaining(addr)
        if fn is None:
            return json.dumps({"error": f"No function at {address_str}"})

        entry = str(fn.getEntryPoint())
        addr_set = fn.getBody()

        # Resolve start_address to an instruction index if provided.
        # Snaps to the last instruction whose start <= start_address, rather
        # than requiring an exact instruction-boundary match -- callers often
        # pick an address from a decompiler comment or a data xref that
        # lands mid-instruction, and erroring there just forces a retry.
        resolved_start_address = None
        if start_address is not None:
            start_addr_obj = self.program.getAddressFactory().getAddress(start_address)
            if start_addr_obj is None:
                return json.dumps({"error": f"Invalid start_address: {start_address}"})
            resolved_offset = None
            target_off = start_addr_obj.getOffset()
            temp_iter = self._listing.getInstructions(addr_set, True)
            idx = 0
            while temp_iter.hasNext():
                instr = temp_iter.next()
                instr_off = instr.getMinAddress().getOffset()
                if instr_off <= target_off:
                    resolved_offset = idx
                    resolved_start_address = str(instr.getMinAddress())
                if instr_off >= target_off:
                    break
                idx += 1
            if resolved_offset is None:
                return json.dumps({
                    "error": f"start_address {start_address} is before the first "
                             f"instruction of function {fn.getName()}",
                })
            offset = resolved_offset

        # Read entire function body as one chunk
        body_start = addr_set.getMinAddress()
        body_end = addr_set.getMaxAddress()
        body_size = int(body_end.getOffset() - body_start.getOffset()) + 1
        if body_size <= 0:
            return json.dumps({"error": "Empty function body"})
        from jpype import JArray as jp_JArray
        body_bytes = jp_JArray(jpype.JByte, 1)(body_size)
        self._program.getMemory().getBytes(body_start, body_bytes)

        # Collect all instructions
        all_instructions = []
        instr_iter = self._listing.getInstructions(addr_set, True)
        while instr_iter.hasNext():
            instr = instr_iter.next()
            ia = instr.getMinAddress()
            mnemonic = instr.getMnemonicString()
            op_str = ""
            try:
                op_count = instr.getNumOperands()
                ops = []
                for i in range(op_count):
                    rep = instr.getDefaultOperandRepresentation(i)
                    if rep:
                        ops.append(rep)
                op_str = ", ".join(ops)
            except Exception:
                pass
            # Extract bytes from pre-read chunk
            try:
                length = instr.getLength()
                if length > 0:
                    start_off = int(ia.getOffset() - body_start.getOffset())
                    instr_raw = body_bytes[start_off:start_off + length]
                    bytes_str = " ".join(f"{b & 0xFF:02x}" for b in instr_raw)
                else:
                    bytes_str = ""
            except Exception:
                bytes_str = ""
            all_instructions.append({
                "address": str(ia),
                "bytes": bytes_str,
                "mnemonic": mnemonic,
                "operands": op_str,
            })

        total = len(all_instructions)
        if limit > 0:
            all_instructions = all_instructions[offset:offset + limit]
        elif offset > 0:
            all_instructions = all_instructions[offset:]

        result = {
            "function": fn.getName(),
            "entry": entry,
            "body": str(fn.getBody()),
            "total_instructions": total,
            "instructions": all_instructions,
        }
        if resolved_start_address is not None:
            result["resolved_start_address"] = resolved_start_address
        return json.dumps(result)

    def list_classes(self, offset=0, limit=100):
        """List classes/namespaces via Symbol.getParentNamespace() — the real
        Ghidra namespace hierarchy (matches upstream GhidraMCPPlugin.java's
        getAllClassNames) — and the function symbols that belong to each,
        instead of regex-mining ClassName::Method patterns out of debug
        strings. Real namespaces reflect the actual Ghidra symbol database
        (including anything created via the GUI), which string-mining never
        saw."""
        classes = {}
        try:
            sym_table = self._program.getSymbolTable()
            it = sym_table.getAllSymbols(True)
            while it.hasNext():
                sym = it.next()
                ns = sym.getParentNamespace()
                if ns is None or ns.isGlobal():
                    continue
                cls_name = ns.getName()
                info = classes.setdefault(
                    cls_name, {"count": 0, "methods": set(), "addresses": set()})
                info["count"] += 1
                if str(sym.getSymbolType()) == "Function":
                    info["methods"].add(sym.getName())
                info["addresses"].add(str(sym.getAddress()))
        except Exception:
            pass

        classes_list = []
        for name, info in sorted(classes.items()):
            classes_list.append({
                "name": name,
                "method_references": info["count"],
                "methods": sorted(info["methods"])[:10],
                "string_locations": sorted(info["addresses"])[:3],
            })
        total = len(classes_list)
        classes_list = classes_list[offset:offset + limit]
        return json.dumps({"classes": classes_list, "total": total})

    def list_namespaces(self, offset=0, limit=100):
        """List non-global namespace names via Symbol.getParentNamespace(),
        matching upstream GhidraMCPPlugin.java's listNamespaces."""
        result = []
        try:
            sym_table = self._program.getSymbolTable()
            seen = set()
            it = sym_table.getAllSymbols(True)
            while it.hasNext():
                sym = it.next()
                ns = sym.getParentNamespace()
                if ns is None or ns.isGlobal():
                    continue
                name = ns.getName()
                if name in seen:
                    continue
                seen.add(name)
                result.append({"name": name, "address": str(ns.getSymbol().getAddress())})
        except Exception:
            return json.dumps({"namespaces": [], "total": 0})
        result.sort(key=lambda r: r["name"])
        total = len(result)
        result = result[offset:offset + limit]
        return json.dumps({"namespaces": result, "total": total})

    def list_class_methods(self, class_name, offset=0, limit=500):
        """Complete method list (name + address) for ONE class/namespace,
        no caps. list_classes truncates every class to its first 10
        method NAMES (no addresses) plus 3 sample addresses total across
        the whole class -- for any class bigger than that (StrBuffer had
        19 methods, CSpeaker had 67 this session), the only way to get a
        specific method's address was a separate search_functions_by_name
        round-trip per method, repeatedly. This resolves the real Ghidra
        namespace (same _resolve_namespace_path used by manage_namespace/
        promote_class_structure_fields, not string-mining) and lists every
        direct-child Function symbol's name + address in one call."""
        ns = self._resolve_namespace_path(class_name, create=False)
        if ns is None:
            return json.dumps({"error": f"No namespace/class named {class_name}"})
        methods = []
        try:
            sym_table = self._program.getSymbolTable()
            it = sym_table.getSymbols(ns)
            while it.hasNext():
                sym = it.next()
                if str(sym.getSymbolType()) == "Function":
                    methods.append({"name": str(sym.getName()), "address": str(sym.getAddress())})
        except Exception as e:
            return json.dumps({"error": f"Failed to enumerate symbols for {class_name}: {e}"})
        methods.sort(key=lambda m: m["name"])
        total = len(methods)
        return json.dumps({
            "class_name": class_name,
            "methods": methods[offset:offset + limit],
            "total": total,
        })

    def class_structure_diagnostic(self, function_address):
        """Inspect the exact Ghidra namespace/class and class datatype linkage.

        This deliberately mirrors the Java-side checks used when diagnosing
        C++ methods: parent namespace runtime class, GhidraClass identity, and
        VariableUtilities.findOrCreateClassStruct(function).  It is read-only.
        """
        addr = self.program.getAddressFactory().getAddress(function_address)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {function_address}"})
        fn = self._function_manager.getFunctionContaining(addr)
        if fn is None:
            return json.dumps({"error": f"No function at {function_address}"})
        ns = fn.getParentNamespace()
        associated = None
        association_error = None
        association_method = None
        try:
            VariableUtilities = jpype.JClass("ghidra.app.util.VariableUtilities")
            associated = VariableUtilities.findOrCreateClassStruct(fn)
            association_method = "VariableUtilities.findOrCreateClassStruct"
        except Exception as e:
            # Ghidra 12.1's headless classpath omits VariableUtilities. The
            # class-bound datatype is nevertheless stored at the root class
            # path; use that exact datatype as a transparent fallback.
            try:
                CategoryPath = jpype.JClass("ghidra.program.model.data.CategoryPath")
                Structure = jpype.JClass("ghidra.program.model.data.Structure")
                associated = self._program.getDataTypeManager().getDataType(
                    CategoryPath("/"), str(ns.getName())) if ns is not None else None
                if associated is not None and isinstance(associated, Structure):
                    association_method = "root_class_datatype_fallback"
                elif associated is not None:
                    association_error = ("Root datatype for %s is not a Structure: %s" %
                                         (str(ns.getName()), associated.getPathName()))
                    associated = None
                else:
                    association_error = str(e)
            except Exception as fallback_error:
                association_error = f"{association_error}; fallback: {fallback_error}"
        result = {
            "function": fn.getName(True),
            "address": str(fn.getEntryPoint()),
            "namespace": str(ns.getName()) if ns is not None else None,
            "namespace_class": ns.getClass().getName() if ns is not None else None,
            # Ghidra 12.1 does not expose a loadable GhidraClass class through
            # this PyGhidra classpath; Namespace.isClass() is the API-level
            # equivalent of `ns instanceof GhidraClass`.
            "namespace_is_ghidra_class": bool(ns is not None and
                str(ns.getClass().getName()).endswith("GhidraClassDB")),
            "association_method": association_method,
            "associated_structure": None if associated is None else {
                "name": str(associated.getName()),
                "path": str(associated.getPathName()),
                "length": int(associated.getLength()),
                "field_count": len(associated.getComponents()),
            },
        }
        if association_error:
            result["association_error"] = association_error
        return json.dumps(result)

    def promote_class_structure_fields(self, class_name, source_name, confirm=False,
                                        target_size=None):
        """Copy a populated *Fields structure into its class-associated struct.

        The operation is intentionally guarded: it only proceeds when the
        destination is the class struct returned by the same Ghidra API and is
        empty (the normal auto-created 1-byte placeholder), unless ``confirm``
        is explicitly true for a non-empty destination. Existing source and
        destination datatypes are never deleted or renamed.
        """
        return self._with_transaction("promote_class_structure_fields",
            lambda: self._do_promote_class_structure_fields(class_name, source_name,
                                                             confirm, target_size))

    def _do_promote_class_structure_fields(self, class_name, source_name, confirm=False,
                                           target_size=None):
        dtm = self._program.getDataTypeManager()
        source = self._resolve_type_by_name(dtm, source_name)
        if source is None or not isinstance(source, jpype.JClass("ghidra.program.model.data.Structure")):
            return json.dumps({"error": f"Source is not a resolvable Structure: {source_name}"})
        # Resolve the real class namespace, never a same-named datatype.
        ns = self._resolve_namespace_path(class_name, create=False)
        if ns is None:
            return json.dumps({"error": f"No namespace/class named {class_name}"})
        if not str(ns.getClass().getName()).endswith("GhidraClassDB"):
            return json.dumps({"error": f"Namespace {class_name} is not a GhidraClass"})
        CategoryPath = jpype.JClass("ghidra.program.model.data.CategoryPath")
        Structure = jpype.JClass("ghidra.program.model.data.Structure")
        target = dtm.getDataType(CategoryPath("/"), class_name)
        created_associated_structure = False
        if target is None:
            # In this Ghidra 12.1 headless classpath VariableUtilities is not
            # loadable.  Existing classes retain their root class structure,
            # but a newly-created GhidraClass has none until we create the
            # same root StructureDataType explicitly.  This is the exact
            # fallback used by the diagnostic above; it is deliberately here
            # (not in that read-only diagnostic) so inspection never mutates
            # a program.
            StructureDataType = jpype.JClass(
                "ghidra.program.model.data.StructureDataType")
            DataTypeConflictHandler = jpype.JClass(
                "ghidra.program.model.data.DataTypeConflictHandler")
            target = dtm.addDataType(
                StructureDataType(CategoryPath("/"), class_name, 0),
                DataTypeConflictHandler.DEFAULT_HANDLER)
            created_associated_structure = True
        if target is None:
            return json.dumps({"error": f"Failed to create associated class struct for {class_name}"})
        if not isinstance(target, Structure):
            return json.dumps({"error": f"Associated datatype is not a Structure: {target.getPathName()}"})
        if target.getName() != class_name:
            return json.dumps({"error": f"Associated struct is {target.getPathName()}, not {class_name}"})
        if target.getLength() > 1 or len(target.getComponents()) > 0:
            if not confirm:
                return json.dumps({"error": "Destination is non-empty; pass confirm=true to replace its fields",
                                   "destination": str(target.getPathName()),
                                   "length": int(target.getLength()),
                                   "field_count": len(target.getComponents())})
        # Copy the source's already byte-precise component sequence.  This
        # preserves offsets, gaps, names, comments, and component datatypes.
        # StructureDB exposes deleteAll() (not clear()) in this Ghidra build.
        target.deleteAll()
        for comp in source.getComponents():
            target.add(comp.getDataType(), comp.getLength(),
                       comp.getFieldName(), comp.getComment())
        if target_size is not None:
            target_size = int(target_size)
            if target_size < int(target.getLength()):
                return json.dumps({"error": "target_size is smaller than source layout",
                                   "source_length": int(target.getLength()),
                                   "target_size": target_size})
            if target_size > int(target.getLength()):
                # Grow with opaque bytes: the tail is an explicit unknown
                # region, never silently omitted or invented.
                undef1 = dtm.getDataType(
                    jpype.JClass("ghidra.program.model.data.CategoryPath")("/"),
                    "undefined1")
                target.add(undef1, target_size - int(target.getLength()),
                           "gap_%08x_%08x" % (int(target.getLength()), target_size - 1),
                           "Unmapped tail; extent supplied by confirmed allocation size.")
        return json.dumps({"status": "ok", "class": class_name,
                           "source": str(source.getPathName()),
                           "destination": str(target.getPathName()),
                           "length": int(target.getLength()),
                           "field_count": len(target.getComponents()),
                           "target_size": target_size,
                           "created_associated_structure": created_associated_structure})

    def list_segments(self, offset=0, limit=100):
        """List all memory segments/blocks in the program."""
        blocks = list(self._program.getMemory().getBlocks())
        result = []
        for b in blocks:
            result.append({
                "name": b.getName(),
                "start": str(b.getStart()),
                "end": str(b.getEnd()),
                "size": b.getSize(),
                "permissions": "".join([
                    "r" if b.isRead() else "",
                    "w" if b.isWrite() else "",
                    "x" if b.isExecute() else "",
                ]),
            })
        total = len(result)
        result = result[offset:offset + limit]
        return json.dumps({"segments": result, "total": total})

    def list_imports(self, offset=0, limit=100):
        """List imported symbols — external references to functions in other DLLs.
        Uses SymbolTable.getExternalSymbols(), the real Ghidra API for this
        (matches upstream GhidraMCPPlugin.java's listImports), instead of
        string-matching on address representation."""
        result = []
        try:
            sym_table = self._program.getSymbolTable()
            for sym in sym_table.getExternalSymbols():
                result.append({
                    "name": sym.getName(),
                    "address": str(sym.getAddress()),
                    "type": str(sym.getSymbolType()),
                })
        except Exception as e:
            return json.dumps({"imports": [], "total": 0, "error": str(e)})
        total = len(result)
        result = result[offset:offset + limit]
        return json.dumps({"imports": result, "total": total})

    def list_exports(self, offset=0, limit=100):
        """List PE export symbols via Symbol.isExternalEntryPoint() — the real
        Ghidra API for "this address is an entry point external code can call
        into" (matches upstream GhidraMCPPlugin.java's listExports), instead of
        pattern-matching on "Ordinal_"-prefixed names."""
        result = []
        try:
            sym_table = self._program.getSymbolTable()
            it = sym_table.getAllSymbols(True)
            while it.hasNext():
                sym = it.next()
                if sym.isExternalEntryPoint():
                    result.append({
                        "name": sym.getName(),
                        "address": str(sym.getAddress()),
                        "type": str(sym.getSymbolType()),
                    })
        except Exception as e:
            return json.dumps({"exports": [], "total": 0, "error": str(e)})
        total = len(result)
        result = result[offset:offset + limit]
        return json.dumps({"exports": result, "total": total})

    def list_data(self, offset=0, limit=100):
        """List defined data items (addresses with typed data)."""
        result = []
        if self._listing:
            data_it = self._listing.getDefinedData(True)
            while data_it.hasNext():
                dd = data_it.next()
                result.append({
                    "address": str(dd.getAddress()),
                    "type": str(dd.getDataType().getName()),
                    "value": str(dd.getValue())[:80],
                })
        total = len(result)
        result = result[offset:offset + limit]
        return json.dumps({"data": result, "total": total})

    # ── New query operations ──────────────────────────────────────

    def list_callees(self, address_str, offset=0, limit=100):
        """List all functions called (call instructions) from a given function."""
        result = []
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})
        fn = self._function_manager.getFunctionContaining(addr)
        if fn is None:
            return json.dumps({"error": f"No function at {address_str}"})

        addr_set = fn.getBody()
        instr_iter = self._listing.getInstructions(addr_set, True)
        seen = set()
        while instr_iter.hasNext():
            instr = instr_iter.next()
            mnem = instr.getMnemonicString()
            if mnem not in ("call", "CALL"):
                continue
            # Get call target from operand
            prim_ref = instr.getPrimaryReference(0)
            if prim_ref:
                target = prim_ref.getToAddress()
                target_str = str(target)
                if target_str not in seen:
                    seen.add(target_str)
                    # Try to resolve to a function name
                    callee = self._function_manager.getFunctionAt(target)
                    callee_name = callee.getName() if callee else ""
                    result.append({
                        "address": target_str,
                        "name": callee_name,
                        "from": str(instr.getMinAddress()),
                    })
        total = len(result)
        result = result[offset:offset + limit]
        return json.dumps({"callees": result, "total": total, "function": fn.getName()})

    def _function_for_address(self, address_str):
        """Resolve an address to its containing function, or raise ValueError."""
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            raise ValueError(f"Invalid address: {address_str}")
        fn = self._function_manager.getFunctionContaining(addr)
        if fn is None:
            raise ValueError(f"No function at {address_str}")
        return fn

    @staticmethod
    def _iter_java(java_iterator):
        """Yield a Java Iterator without relying on JPype collection coercion."""
        while java_iterator is not None and java_iterator.hasNext():
            yield java_iterator.next()

    @staticmethod
    def _qname(fn):
        """Fully-qualified display name for a Function ("Class::method" when
        it has a real non-global namespace, else the bare name). fn.getName()
        alone only ever returns the bare name -- since the namespace-creating
        rename_function_by_address fix (docs/GHIDRA_MCP_NAMESPACE_RENAME_GAP_2026-07-11.md),
        "SMException::raise" is stored as method name "raise" attached to a
        real Namespace/GhidraClass named "SMException", not as literal
        colon-containing text. Use this wherever a Function's name is put
        into a JSON display field so callers keep seeing the class-qualified
        form they got before that fix. NOT used for anything that must match
        the raw stored symbol name exactly (e.g. rename input parsing)."""
        if fn is None:
            return None
        try:
            return str(fn.getSymbol().getName(True))
        except Exception:
            return fn.getName()

    def _direct_callees(self, fn):
        """Return only call-reference-backed direct call targets."""
        callees = {}
        for edge in self._function_direct_call_edges(fn):
            callees[edge["to_address"]] = edge["callee"]
        return list(callees.values())

    def _reference_record(self, ref):
        """Serialize a stored Ghidra reference without interpreting its meaning."""
        ref_type = ref.getReferenceType()
        target = ref.getToAddress()
        record = {
            "from_address": str(ref.getFromAddress()),
            "to_address": str(target),
            "reference_type": ref_type.getName(),
            "operand_index": ref.getOperandIndex(),
        }
        # DIRECT_CALL is intentionally stricter than "a call-like instruction":
        # it needs both a stored call reference and a Function exactly at target.
        if ref_type.isCall():
            callee = self._function_manager.getFunctionAt(target)
            if callee is not None:
                record["kind"] = "DIRECT_CALL"
                record["target_function"] = {
                    "address": str(callee.getEntryPoint()), "name": self._qname(callee),
                }
                # Include callsite snippet for context
                try:
                    instr = self._listing.getInstructionAt(ref.getFromAddress())
                    if instr:
                        n_ops = instr.getNumOperands()
                        ops = [instr.getDefaultOperandRepresentation(i) for i in range(n_ops)]
                        record["callsite"] = f"{instr.getMnemonicString()} {', '.join(ops)}"
                except Exception:
                    pass
            else:
                record["kind"] = "REFERENCE"
        else:
            record["kind"] = "REFERENCE"
        return record

    def _function_direct_call_edges(self, fn):
        """Return per-call-site edges supported by instruction operand references."""
        result = []
        instr_iter = self._listing.getInstructions(fn.getBody(), True)
        while instr_iter.hasNext():
            instr = instr_iter.next()
            for index in range(instr.getNumOperands()):
                for ref in instr.getOperandReferences(index):
                    try:
                        if not ref.getReferenceType().isCall():
                            continue
                    except Exception:
                        continue
                    callee = self._function_manager.getFunctionAt(ref.getToAddress())
                    if callee is not None:
                        result.append({"from_address": str(instr.getAddress()),
                                       "to_address": str(callee.getEntryPoint()),
                                       "callee": callee,
                                       "reference_type": ref.getReferenceType().getName(),
                                       "operand_index": ref.getOperandIndex()})
        return result

    def _direct_callers(self, fn):
        """Return callers from references, rather than depending on UI state."""
        callers = {}
        refs = self._ref_manager.getReferencesTo(fn.getEntryPoint())
        while refs.hasNext():
            ref = refs.next()
            try:
                if not ref.getReferenceType().isCall():
                    continue
            except Exception:
                continue
            caller = self._function_manager.getFunctionContaining(ref.getFromAddress())
            if caller is not None:
                callers[str(caller.getEntryPoint())] = caller
        return list(callers.values())

    def get_function_callers(self, address_str, offset=0, limit=100):
        """List direct callers using Ghidra's reference database."""
        try:
            fn = self._function_for_address(address_str)
        except ValueError as exc:
            return json.dumps({"error": str(exc)})
        callers = sorted(self._direct_callers(fn), key=lambda f: str(f.getEntryPoint()))
        total = len(callers)
        return json.dumps({
            "function": fn.getName(), "address": str(fn.getEntryPoint()),
            "callers": [{"name": f.getName(), "address": str(f.getEntryPoint())}
                        for f in callers[offset:offset + limit]],
            "total": total,
        })

    def get_function_call_graph(self, address_str, depth=2, direction="both"):
        """Build a deliberately bounded direct-call graph around a function."""
        try:
            fn = self._function_for_address(address_str)
        except ValueError as exc:
            return json.dumps({"error": str(exc)})
        if direction not in ("callers", "callees", "both"):
            return json.dumps({"error": "direction must be callers, callees, or both"})
        depth = max(0, min(int(depth), 5))
        nodes, edges = {}, set()
        queue = [(fn, 0)]
        while queue and len(nodes) < 500:
            current, level = queue.pop(0)
            current_addr = str(current.getEntryPoint())
            if current_addr in nodes:
                continue
            nodes[current_addr] = {"address": current_addr, "name": current.getName(), "depth": level}
            if level >= depth:
                continue
            neighbours = []
            if direction in ("callees", "both"):
                neighbours.extend((child, "call") for child in self._direct_callees(current))
            if direction in ("callers", "both"):
                neighbours.extend((parent, "caller") for parent in self._direct_callers(current))
            for other, kind in neighbours:
                other_addr = str(other.getEntryPoint())
                if kind == "call":
                    edge = (current_addr, other_addr)
                else:
                    edge = (other_addr, current_addr)
                edges.add(edge)
                if other_addr not in nodes:
                    queue.append((other, level + 1))
        return json.dumps({"root": str(fn.getEntryPoint()), "depth": depth,
                           "direction": direction, "truncated": bool(queue),
                           "nodes": list(nodes.values()),
                           "edges": [{"from": source, "to": target, "kind": "call"}
                                     for source, target in sorted(edges)]})

    def batch_decompile(self, addresses):
        """Decompile up to 20 functions with one decompiler session."""
        if not isinstance(addresses, list) or not addresses:
            return json.dumps({"error": "addresses must be a non-empty JSON list"})
        if len(addresses) > 20:
            return json.dumps({"error": "batch_decompile accepts at most 20 addresses"})
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor
        decomp = DecompInterface()
        decomp.openProgram(self.program)
        results = []
        try:
            for address_str in addresses:
                try:
                    fn = self._function_for_address(address_str)
                    res = decomp.decompileFunction(fn, 0, ConsoleTaskMonitor())
                    dec = res.getDecompiledFunction() if res else None
                    if dec is None:
                        results.append({"address": address_str, "error": "Decompilation failed"})
                    else:
                        results.append({"address": str(fn.getEntryPoint()), "name": fn.getName(),
                                        "decompiled": dec.getC()})
                except Exception as exc:
                    results.append({"address": str(address_str), "error": str(exc)})
        finally:
            decomp.dispose()
        return json.dumps({"functions": results, "total": len(results)})

    def get_struct_layout(self, name):
        """Return field offsets for an exact-named Structure data type."""
        if not name:
            return json.dumps({"error": "Structure name is required"})
        iterator = self.program.getDataTypeManager().getAllDataTypes()
        found = None
        while iterator.hasNext():
            candidate = iterator.next()
            if candidate.getName() != name:
                continue
            try:
                candidate.getDefinedComponents()
                found = candidate
                break
            except Exception:
                pass
        if found is None:
            return json.dumps({"error": f"No structure named {name}"})
        fields = []
        for component in found.getDefinedComponents():
            fields.append({"offset": component.getOffset(), "length": component.getLength(),
                           "name": component.getFieldName() or "",
                           "type": component.getDataType().getName(),
                           "comment": component.getComment() or ""})
        return json.dumps({"name": found.getName(), "path": str(found.getDataTypePath()),
                           "size": found.getLength(), "alignment": found.getAlignment(),
                           "fields": fields})

    # ── Exact graph facts ─────────────────────────────────────────
    # These methods deliberately use only decoded listing objects and records
    # stored in Ghidra's function/reference/symbol/data-type databases.  They
    # never use decompiler output, P-code, analysis guesses, or heuristics.

    def _address_node(self, addr):
        """Return direct, stored metadata for one address."""
        node = {"id": f"address:{addr}", "kind": "address", "address": str(addr)}
        block = self.program.getMemory().getBlock(addr)
        if block is not None:
            node["memory_block"] = block.getName()
        instruction = self._listing.getInstructionAt(addr)
        if instruction is not None:
            node["instruction"] = str(instruction)
        data = self._listing.getDataAt(addr)
        if data is not None:
            node["data_type"] = data.getDataType().getName()
            node["data_length"] = data.getLength()
        symbols = []
        # In Ghidra 12.1 this overload returns Symbol[], unlike the iterator
        # returned by several other symbol-table queries.
        for symbol in self.program.getSymbolTable().getSymbols(addr):
            symbols.append({"name": symbol.getName(), "type": symbol.getSymbolType().toString(),
                            "source": symbol.getSource().toString()})
        if symbols:
            node["symbols"] = symbols
        return node

    def get_instruction_facts(self, address_str):
        """Return a decoded instruction and every explicit operand reference."""
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})
        instruction = self._listing.getInstructionAt(addr)
        if instruction is None:
            return json.dumps({"error": f"No instruction starts at {address_str}"})
        operands = []
        references = []
        for index in range(instruction.getNumOperands()):
            operands.append({"index": index,
                             "text": instruction.getDefaultOperandRepresentation(index)})
        for ref in self._ref_manager.getReferencesFrom(instruction.getAddress()):
            references.append(self._reference_record(ref))
        return json.dumps({"instruction": {"address": str(addr),
                                             "mnemonic": instruction.getMnemonicString(),
                                             "text": str(instruction),
                                             "length": instruction.getLength(),
                                             "operands": operands},
                           "references": references,
                           "certainty": "exact"})

    def get_function_exact_facts(self, address_str, limit=200, offset=0):
        """Return exact function metadata, stored references, and direct call
        sites. references/incoming_references are collected in full, then
        offset/limit is applied like get_xrefs_to/from, so a caller can page
        through a function with more than `limit` references instead of
        silently losing everything past the cap."""
        try:
            fn = self._function_for_address(address_str)
        except ValueError as exc:
            return json.dumps({"error": str(exc)})
        limit = max(1, min(int(limit), 1000))
        offset = max(0, int(offset))
        references, calls = [], []
        instr_iter = self._listing.getInstructions(fn.getBody(), True)
        while instr_iter.hasNext():
            instruction = instr_iter.next()
            # Operand-reference enumeration misses Ghidra's instruction-level
            # references (notably COMPUTED_CALL records at operand -1).  The
            # reference manager is the authoritative, complete view here.
            for ref in self._ref_manager.getReferencesFrom(instruction.getAddress()):
                record = self._reference_record(ref)
                references.append(record)
                if record["kind"] == "DIRECT_CALL":
                    calls.append(record)
        incoming = [self._reference_record(ref)
                    for ref in self._ref_manager.getReferencesTo(fn.getEntryPoint())]
        total_references, total_incoming, total_calls = len(references), len(incoming), len(calls)
        references = references[offset:offset + limit]
        calls = calls[offset:offset + limit]
        incoming = incoming[offset:offset + limit]
        return json.dumps({"function": {"id": f"function:{fn.getEntryPoint()}",
                                         "address": str(fn.getEntryPoint()),
                                         "name": self._qname(fn), "body": str(fn.getBody())},
                           "incoming_references": incoming, "references": references,
                           "direct_calls": calls,
                           "total_incoming_references": total_incoming,
                           "total_references": total_references,
                           "total_direct_calls": total_calls,
                           "incoming_truncated": offset + len(incoming) < total_incoming,
                           "references_truncated": offset + len(references) < total_references,
                           "certainty": "exact"})

    def get_address_exact_facts(self, address_str, limit=100, offset=0):
        """Return stored facts and raw inbound/outbound references for an
        address, paginated like get_xrefs_to/from (full collection, then
        offset/limit slice) instead of silently dropping past `limit`."""
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})
        limit = max(1, min(int(limit), 1000))
        offset = max(0, int(offset))
        incoming = [self._reference_record(ref) for ref in self._ref_manager.getReferencesTo(addr)]
        outgoing = [self._reference_record(ref) for ref in self._ref_manager.getReferencesFrom(addr)]
        total_incoming, total_outgoing = len(incoming), len(outgoing)
        incoming = incoming[offset:offset + limit]
        outgoing = outgoing[offset:offset + limit]
        code_unit = self._listing.getCodeUnitAt(addr)
        comments = {}
        if code_unit is not None:
            for comment_type, label in ((CodeUnit.PLATE_COMMENT, "plate"),
                                        (CodeUnit.PRE_COMMENT, "pre"),
                                        (CodeUnit.EOL_COMMENT, "eol"),
                                        (CodeUnit.POST_COMMENT, "post")):
                value = code_unit.getComment(comment_type)
                if value:
                    comments[label] = value
        return json.dumps({"node": self._address_node(addr), "comments": comments,
                           "incoming_references": incoming, "outgoing_references": outgoing,
                           "total_incoming_references": total_incoming,
                           "total_outgoing_references": total_outgoing,
                           "incoming_truncated": offset + len(incoming) < total_incoming,
                           "outgoing_truncated": offset + len(outgoing) < total_outgoing,
                           "certainty": "exact"})

    def get_type_exact_facts(self, name, limit=100, offset=0):
        """Return declared data-type metadata and explicitly typed data
        instances, paginated like get_xrefs_to/from."""
        if not name:
            return json.dumps({"error": "Data type name is required"})
        found = None
        iterator = self.program.getDataTypeManager().getAllDataTypes()
        while iterator.hasNext():
            candidate = iterator.next()
            if candidate.getName() == name:
                found = candidate
                break
        if found is None:
            return json.dumps({"error": f"No data type named {name}"})
        fields = []
        try:
            for component in found.getDefinedComponents():
                fields.append({"offset": component.getOffset(), "length": component.getLength(),
                               "name": component.getFieldName() or "",
                               "type": component.getDataType().getName()})
        except Exception:
            pass
        limit = max(1, min(int(limit), 1000))
        offset = max(0, int(offset))
        instances = []
        data_iter = self._listing.getDefinedData(True)
        target_path = str(found.getDataTypePath())
        while data_iter.hasNext():
            data = data_iter.next()
            if str(data.getDataType().getDataTypePath()) == target_path:
                instances.append({"address": str(data.getAddress()), "length": data.getLength()})
        total_instances = len(instances)
        instances = instances[offset:offset + limit]
        return json.dumps({"type": {"id": f"datatype:{target_path}", "name": found.getName(),
                                    "path": target_path, "length": found.getLength(),
                                    "alignment": found.getAlignment()},
                           "fields": fields, "typed_data_instances": instances,
                           "total_typed_data_instances": total_instances,
                           "instances_truncated": offset + len(instances) < total_instances,
                           "certainty": "exact"})

    def get_exact_neighborhood(self, address_str, depth=1, limit=200,
                               include_incoming=True, include_outgoing=True):
        """Build a bounded graph solely from stored Ghidra references and address facts."""
        root = self.program.getAddressFactory().getAddress(address_str)
        if root is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})
        depth, limit = max(0, min(int(depth), 3)), max(1, min(int(limit), 1000))
        nodes, edges, seen_edges = {}, [], set()
        truncated = False
        frontier, seen_addresses = [(root, 0)], set()
        while frontier and len(nodes) < limit:
            address, level = frontier.pop(0)
            address_text = str(address)
            if address_text in seen_addresses:
                continue
            seen_addresses.add(address_text)
            nodes[f"address:{address_text}"] = self._address_node(address)
            if level >= depth:
                continue
            refs = []
            if include_incoming:
                refs.extend(self._ref_manager.getReferencesTo(address))
            if include_outgoing:
                refs.extend(self._ref_manager.getReferencesFrom(address))
            for ref in refs:
                record = self._reference_record(ref)
                key = (record["from_address"], record["to_address"],
                       record["reference_type"], record["operand_index"])
                source_id = f"address:{record['from_address']}"
                target_id = f"address:{record['to_address']}"
                endpoints = ((source_id, ref.getFromAddress()), (target_id, ref.getToAddress()))
                if any(node_id not in nodes for node_id, _ in endpoints) and len(nodes) >= limit:
                    truncated = True
                    continue
                for node_id, node_address in endpoints:
                    if node_id not in nodes:
                        nodes[node_id] = self._address_node(node_address)
                if key not in seen_edges:
                    seen_edges.add(key)
                    edges.append({"from": source_id, "to": target_id,
                                  "kind": record["kind"], "evidence": record})
                other = ref.getFromAddress() if ref.getToAddress().equals(address) else ref.getToAddress()
                if str(other) not in seen_addresses and len(nodes) + len(frontier) < limit:
                    frontier.append((other, level + 1))
                elif str(other) not in seen_addresses:
                    truncated = True
        return json.dumps({"root": f"address:{root}", "depth": depth, "nodes": list(nodes.values()),
                           "edges": edges, "truncated": truncated or bool(frontier),
                           "certainty": "exact"})

    def _function_hash_record(self, fn):
        """Return a relocation-tolerant instruction-shape hash for ``fn``.

        Kept as a private primitive so a cross-program comparison can run in
        process instead of making thousands of HTTP round trips.  This is an
        *exact normalized-body* comparison, not a semantic similarity claim.
        """
        tokens, count = [], 0
        iterator = self._listing.getInstructions(fn.getBody(), True)
        while iterator.hasNext():
            instruction = iterator.next()
            parts = [instruction.getMnemonicString().upper()]
            for index in range(instruction.getNumOperands()):
                refs = instruction.getOperandReferences(index)
                if len(refs):
                    ref = refs[0]
                    target = ref.getToAddress()
                    if fn.getBody().contains(target):
                        operand = "REL"
                    elif ref.getReferenceType().isCall():
                        operand = "CALL_EXT"
                    elif ref.getReferenceType().isData():
                        operand = "DATA_EXT"
                    else:
                        operand = "EXT_REF"
                else:
                    operand = instruction.getDefaultOperandRepresentation(index)
                    for obj in instruction.getOpObjects(index):
                        if hasattr(obj, "getValue"):
                            try:
                                value = int(obj.getValue())
                                operand = f"IMM:{value}" if abs(value) < 0x10000 else "IMM_LARGE"
                            except Exception:
                                pass
                parts.append(operand)
            tokens.append(" ".join(parts))
            count += 1
        normalised = ";".join(tokens).encode("utf-8")
        return {"function": self._qname(fn), "address": str(fn.getEntryPoint()),
                "sha256": hashlib.sha256(normalised).hexdigest(),
                "instruction_count": count, "size_bytes": fn.getBody().getNumAddresses()}

    def get_function_hash(self, address_str):
        """Hash instruction shape so functions can be compared across DLLs."""
        try:
            fn = self._function_for_address(address_str)
        except ValueError as exc:
            return json.dumps({"error": str(exc)})
        return json.dumps(self._function_hash_record(fn))

    def compare_program_functions(self, source_program, target_program,
                                  min_instructions=15, limit=500):
        """Read-only exact normalized-body comparison between two project programs.

        This is deliberately a *proposal generator*.  A matching hash proves
        that the stored instruction shapes match after relocation-tolerant
        normalization; it does not prove that a C1 class, name, or datatype is
        appropriate in a kit.  The caller must inspect the returned evidence
        before applying any rename or type.  The program selected by the user
        is restored even on failure.
        """
        if not source_program or not target_program:
            return json.dumps({"error": "source_program and target_program are required"})
        if source_program == target_program:
            return json.dumps({"error": "source_program and target_program must differ"})
        min_instructions = max(1, min(int(min_instructions), 10000))
        limit = max(1, min(int(limit), 5000))
        original_program = self._current_program_path
        if original_program is None:
            return json.dumps({"error": "No active program to restore"})

        def collect(program_path):
            self.switch_program(program_path)
            by_hash, total, eligible = {}, 0, 0
            iterator = self._function_manager.getFunctions(True)
            while iterator.hasNext():
                fn = iterator.next()
                total += 1
                item = self._function_hash_record(fn)
                if item["instruction_count"] < min_instructions:
                    continue
                eligible += 1
                by_hash.setdefault(item["sha256"], []).append(item)
            return by_hash, total, eligible

        try:
            source_hashes, source_total, source_eligible = collect(source_program)
            target_hashes, target_total, target_eligible = collect(target_program)
            matches = []
            for digest in sorted(set(source_hashes) & set(target_hashes)):
                for source in source_hashes[digest]:
                    for target in target_hashes[digest]:
                        matches.append({
                            "match_kind": "exact_normalized_instruction_shape",
                            "sha256": digest,
                            "source": source,
                            "target": target,
                            "same_instruction_count": source["instruction_count"] == target["instruction_count"],
                            "same_size_bytes": source["size_bytes"] == target["size_bytes"],
                            "source_is_unnamed": source["function"].startswith("FUN_"),
                            "target_is_unnamed": target["function"].startswith("FUN_"),
                        })
            total_matches = len(matches)
            return json.dumps({
                "read_only": True,
                "source_program": source_program,
                "target_program": target_program,
                "min_instructions": min_instructions,
                "source_function_count": source_total,
                "target_function_count": target_total,
                "source_eligible": source_eligible,
                "target_eligible": target_eligible,
                "matches": matches[:limit],
                "total_matches": total_matches,
                "truncated": total_matches > limit,
                "note": "Exact normalized-body candidates only. Inspect decompilation and ABI before transferring names, namespaces, prototypes, or datatypes.",
            })
        finally:
            # Program selection is session state, not RE evidence.  Never
            # leave an exploratory comparison pointed at a kit.
            if self._current_program_path != original_program:
                self.switch_program(original_program)

    def _describe_varnode(self, varnode):
        if varnode is None:
            return "null"
        if varnode.isConstant():
            return f"const:0x{int(varnode.getOffset()):x}"
        if varnode.isRegister():
            reg = self.program.getLanguage().getRegister(varnode.getAddress(), varnode.getSize())
            if reg is not None:
                return reg.getName()
        high = varnode.getHigh()
        if high is not None:
            symbol = high.getSymbol()
            if symbol is not None and symbol.getName() not in (None, "", "UNNAMED"):
                return symbol.getName()
            if high.getName() not in (None, "", "UNNAMED"):
                return high.getName()
        if varnode.isAddress():
            return f"mem:{varnode.getAddress()}"
        if varnode.isUnique():
            return f"unique:{int(varnode.getOffset()):x}"
        return f"vn:{varnode.getAddress()}:{varnode.getSize()}"

    def analyze_dataflow(self, address_str, variable="", direction="backward", max_steps=20):
        """Trace a P-code value backward to definitions or forward to consumers."""
        if direction not in ("backward", "forward"):
            return json.dumps({"error": "direction must be backward or forward"})
        try:
            fn = self._function_for_address(address_str)
        except ValueError as exc:
            return json.dumps({"error": str(exc)})
        max_steps = max(1, min(int(max_steps), 100))
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor
        PcodeOp = jpype.JClass('ghidra.program.model.pcode.PcodeOp')
        decomp = DecompInterface()
        decomp.openProgram(self.program)
        try:
            result = decomp.decompileFunction(fn, 0, ConsoleTaskMonitor())
            high_function = result.getHighFunction() if result else None
            if high_function is None:
                return json.dumps({"error": "Decompilation failed"})
            address = self.program.getAddressFactory().getAddress(address_str)
            ops = list(self._iter_java(high_function.getPcodeOps(address)))
            if not ops:
                return json.dumps({"error": f"No P-code operation at {address_str}"})
            anchor = None
            for op in ops:
                candidates = [op.getOutput()] + [op.getInput(i) for i in range(op.getNumInputs())]
                for candidate in candidates:
                    if candidate is not None and (not variable or self._describe_varnode(candidate) == variable):
                        anchor = candidate
                        break
                if anchor is not None:
                    break
            if anchor is None:
                return json.dumps({"error": f"Variable not found at address: {variable}"})
            frontier, seen, steps = [anchor], set(), []
            call_ops = (PcodeOp.CALL, PcodeOp.CALLIND, PcodeOp.CALLOTHER)
            while frontier and len(steps) < max_steps:
                varnode = frontier.pop(0)
                operations = [varnode.getDef()] if direction == "backward" else list(self._iter_java(varnode.getDescendants()))
                for op in operations:
                    if op is None:
                        continue
                    key = str(op.getSeqnum())
                    if key in seen:
                        continue
                    seen.add(key)
                    seq = op.getSeqnum().getTarget()
                    entry = {"step": len(steps), "address": str(seq),
                             "op": op.getMnemonic() or f"OP_{op.getOpcode()}",
                             "output": self._describe_varnode(op.getOutput()),
                             "inputs": [self._describe_varnode(op.getInput(i)) for i in range(op.getNumInputs())]}
                    instruction = self._listing.getInstructionAt(seq)
                    if instruction is not None:
                        entry["asm"] = str(instruction)
                    steps.append(entry)
                    if op.getOpcode() in call_ops:
                        continue
                    if direction == "backward":
                        frontier.extend(op.getInput(i) for i in range(op.getNumInputs()))
                    elif op.getOutput() is not None:
                        frontier.append(op.getOutput())
                    if len(steps) >= max_steps:
                        break
            return json.dumps({"function": fn.getName(), "address": str(fn.getEntryPoint()),
                               "anchor": self._describe_varnode(anchor), "direction": direction,
                               "steps": steps, "truncated": bool(frontier)})
        finally:
            decomp.dispose()

    def batch_set_comments(self, comments):
        """Set several listing comments atomically after validating every input."""
        if not isinstance(comments, list) or not comments:
            return json.dumps({"error": "comments must be a non-empty JSON list"})
        if len(comments) > 100:
            return json.dumps({"error": "batch_set_comments accepts at most 100 comments"})
        kind_map = {"eol": CodeUnit.EOL_COMMENT, "pre": CodeUnit.PRE_COMMENT,
                    "post": CodeUnit.POST_COMMENT, "plate": CodeUnit.PLATE_COMMENT}
        validated = []
        try:
            for item in comments:
                if not isinstance(item, dict):
                    raise ValueError("each comment must be an object")
                address = self.program.getAddressFactory().getAddress(item.get("address", ""))
                kind = item.get("type", "eol").lower()
                text = item.get("comment")
                if address is None:
                    raise ValueError(f"Invalid address: {item.get('address', '')}")
                if kind not in kind_map:
                    raise ValueError("comment type must be eol, pre, post, or plate")
                if not isinstance(text, str):
                    raise ValueError("comment must be a string")
                validated.append((address, kind_map[kind], text))
        except ValueError as exc:
            return json.dumps({"error": str(exc)})

        def apply_comments():
            for address, kind, text in validated:
                self._listing.setComment(address, kind, text)
            return json.dumps({"status": "ok", "comments_set": len(validated)})

        return self._with_transaction("batch set comments", apply_comments)

    def get_basic_blocks(self, address_str):
        """List basic blocks for a function: address ranges plus CFG edges
        (successors/predecessors) derived from BasicBlockModel."""
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})
        fn = self._function_manager.getFunctionContaining(addr)
        if fn is None:
            return json.dumps({"error": f"No function at {address_str}"})

        try:
            from ghidra.program.model.block import BasicBlockModel
            from ghidra.util.task import TaskMonitor

            bbm = BasicBlockModel(self.program)
            monitor = TaskMonitor.DUMMY
            body = fn.getBody()

            blocks = []
            block_iter = bbm.getCodeBlocksContaining(body, monitor)
            while block_iter.hasNext():
                block = block_iter.next()
                start = block.getMinAddress()
                end = block.getMaxAddress()

                successors = []
                dest_iter = block.getDestinations(monitor)
                while dest_iter.hasNext():
                    dest = dest_iter.next()
                    dest_addr = dest.getDestinationAddress()
                    successors.append({
                        "address": str(dest_addr),
                        "flow_type": str(dest.getFlowType()),
                        "in_function": body.contains(dest_addr),
                    })

                predecessors = []
                src_iter = block.getSources(monitor)
                while src_iter.hasNext():
                    src = src_iter.next()
                    src_addr = src.getSourceAddress()
                    if src_addr is None:
                        continue
                    predecessors.append({
                        "address": str(src_addr),
                        "flow_type": str(src.getFlowType()),
                        "in_function": body.contains(src_addr),
                    })

                blocks.append({
                    "start": str(start),
                    "end": str(end),
                    "successors": successors,
                    "predecessors": predecessors,
                })

            blocks.sort(key=lambda b: b["start"])
            return json.dumps({
                "function": fn.getName(),
                "entry": str(fn.getEntryPoint()),
                "block_count": len(blocks),
                "blocks": blocks,
            })
        except Exception as e:
            return json.dumps({"error": f"Failed: {str(e)}"})

    def get_function_body_bytes(self, address_str):
        """Return raw bytes of a function body as a hex string.

        A function's body (fn.getBody(), an AddressSetView) is not always
        one contiguous range -- MSVC /GL+/LTCG code regularly produces
        functions with an internal dead-code gap (e.g. a JMP that skips
        straight over an unreachable padding/debug region), and Ghidra
        records that as two-or-more separate AddressRanges rather than one
        span with a hole in it. The previous implementation here read
        getMinAddress()..getMaxAddress() as one flat block, which silently
        INCLUDED any such gap's bytes in the result. That's a real,
        confirmed bug, not a hypothetical: on ___scrt_common_main_seh
        (0x0044af4e, body [[44af4e,44b071],[44b0a7,44b0c3]], a genuine
        54-byte dead JMP-over gap disassembly-confirmed present) the old
        code returned size=374 (the full min-to-max span, gap included)
        instead of the real 321 bytes the two declared ranges actually
        cover. Any byte-for-byte verification workflow (e.g. C1 byte_match)
        pulling "ground truth" through this endpoint for a multi-range
        function would get contaminated bytes a normal single-TU compile
        could never reproduce, and misread that as a real mismatch.

        Fixed to walk the body's real AddressRanges and concatenate only
        those; reports range_count and per-range bounds so a multi-range
        result is visible to the caller rather than silently returned as
        if it were one block, plus excluded_gap_bytes (the byte count that
        the old min/max-span approach would have wrongly included).
        """
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})
        fn = self._function_manager.getFunctionContaining(addr)
        if fn is None:
            return json.dumps({"error": f"No function at {address_str}"})

        try:
            body = fn.getBody()
            from jpype import JArray as jp_JArray
            chunks = []
            ranges = []
            total_size = 0
            for rng in body.getAddressRanges():
                r_start, r_end = rng.getMinAddress(), rng.getMaxAddress()
                r_size = int(r_end.getOffset() - r_start.getOffset()) + 1
                byte_arr = jp_JArray(jpype.JByte, 1)(r_size)
                self._program.getMemory().getBytes(r_start, byte_arr)
                chunks.append(" ".join(f"{b & 0xFF:02x}" for b in byte_arr))
                ranges.append({"start": str(r_start), "end": str(r_end), "size": r_size})
                total_size += r_size
            hex_str = " ".join(chunks)
            span_start, span_end = body.getMinAddress(), body.getMaxAddress()
            span_size = int(span_end.getOffset() - span_start.getOffset()) + 1
            result = {
                "function": fn.getName(),
                "entry": str(fn.getEntryPoint()),
                "size": total_size,
                "bytes": hex_str,
                "range_count": len(ranges),
            }
            if len(ranges) > 1:
                result["ranges"] = ranges
                result["excluded_gap_bytes"] = span_size - total_size
                result["note"] = (
                    f"Multi-range function body ({len(ranges)} ranges) -- "
                    f"{span_size - total_size} internal gap byte(s) excluded from "
                    "'bytes'/'size'. Likely LTCG-inserted dead/unreachable code; "
                    "confirm with disassemble_function before assuming otherwise."
                )
            return json.dumps(result)
        except Exception as e:
            return json.dumps({"error": f"Failed to read bytes: {str(e)}"})

    def search_bytes(self, pattern_str, limit=200):
        """Search memory for a hex byte pattern. Use ?? for wildcards.
        Example: '68 ?? 00 00 00' finds push dword with high 3 bytes zero.
        Uses Ghidra's native Memory.findBytes(Address, Address, ...) — avoids
        fragile JArray patterns entirely. Each match is annotated with its
        containing function (if any). Stops once `limit` matches are found."""
        result = []
        limit = int(limit)
        try:
            # Parse pattern
            parts = pattern_str.strip().split()
            pattern_bytes = []
            pattern_mask = []
            for p in parts:
                if p == "??":
                    pattern_bytes.append(0)
                    pattern_mask.append(0)
                else:
                    pattern_bytes.append(int(p, 16))
                    pattern_mask.append(0xFF)

            pattern_len = len(pattern_bytes)
            if pattern_len == 0:
                return json.dumps({"error": "Empty pattern"})

            # Build Java byte[] for pattern and mask (small arrays, always safe)
            # Java byte is signed [-128, 127]; Python ints > 127 must be converted.
            j_arr_cls = jpype.JArray(jpype.JByte, 1)
            java_pattern = j_arr_cls(pattern_len)
            java_mask = j_arr_cls(pattern_len)
            for i in range(pattern_len):
                pb = pattern_bytes[i]
                java_pattern[i] = pb - 256 if pb > 127 else pb
                pm = pattern_mask[i]
                java_mask[i] = pm - 256 if pm > 127 else pm

            from ghidra.util.task import ConsoleTaskMonitor
            mon = ConsoleTaskMonitor()

            # Search each executable block using Ghidra's native findBytes
            # Ghidra 12.1 signature:
            #   Memory.findBytes(Address startAddr, Address endAddr,
            #                    byte[] bytes, byte[] masks,
            #                    boolean forward, TaskMonitor monitor)
            # Returns Address on match, None when exhausted.
            memory = self._program.getMemory()
            blocks = memory.getBlocks()
            for block in blocks:
                if not block.isExecute():
                    continue
                start = block.getStart()
                end = block.getEnd()

                cur = start
                while True:
                    if len(result) >= limit:
                        break
                    found = memory.findBytes(
                        cur, end, java_pattern, java_mask, True, mon)
                    if found is None:
                        break
                    fn = self._function_manager.getFunctionContaining(found)
                    result.append({
                        "address": str(found),
                        "function": self._qname(fn) if fn else None,
                        "function_address": str(fn.getEntryPoint()) if fn else None,
                    })
                    # Advance past this match
                    cur = found.add(1)
                    if cur.getOffset() > end.getOffset():
                        break
                if len(result) >= limit:
                    break

        except Exception as e:
            return json.dumps({"error": f"Search failed: {str(e)}"})
        return json.dumps({"pattern": pattern_str, "matches": result, "count": len(result), "limit": limit})

    def get_stack_variables(self, address_str):
        """List local stack variables for a function."""
        result = []
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})
        fn = self._function_manager.getFunctionContaining(addr)
        if fn is None:
            return json.dumps({"error": f"No function at {address_str}"})

        try:
            for v in fn.getAllVariables():
                if v.isStackVariable():
                    result.append({
                        "name": v.getName(),
                        "offset": v.getStackOffset(),
                        "size": v.getLength(),
                        "type": str(v.getDataType().getName()),
                    })
        except Exception as e:
            return json.dumps({"error": f"Failed: {str(e)}"})
        return json.dumps({
            "function": fn.getName(),
            "stack_variables": result,
            "total": len(result),
        })

    # ── Memory read convenience operations ────────────────────────

    def _read_raw_bytes(self, addr, size):
        """Read `size` bytes at `addr` and return (python bytes, actual_count).
        Shared by get_bytes/read_float/read_double/read_int/read_*_array —
        the one place the JArray boilerplate for Memory.getBytes lives."""
        from jpype import JArray as jp_JArray
        byte_arr = jp_JArray(jpype.JByte, 1)(size)
        actual = self._program.getMemory().getBytes(addr, byte_arr)
        return bytes(b & 0xFF for b in byte_arr[:actual]), actual

    def get_bytes(self, address_str, size):
        """Return raw bytes at an address as a hex string."""
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})
        if size <= 0:
            return json.dumps({"error": "size must be positive"})
        try:
            raw, actual = self._read_raw_bytes(addr, size)
            hex_str = " ".join(f"{b:02x}" for b in raw)
            return json.dumps({
                "address": address_str,
                "size": actual,
                "bytes": hex_str,
            })
        except Exception as e:
            return json.dumps({"error": f"Failed to read bytes: {str(e)}"})

    def read_float(self, address_str):
        """Read a 32-bit float from memory at the given address."""
        import struct
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})
        try:
            raw, _ = self._read_raw_bytes(addr, 4)
            val = struct.unpack(('>' if self.program.getLanguage().isBigEndian() else '<') + 'f', raw)[0]
            return json.dumps({
                "address": address_str,
                "value": val,
                "type": "float",
            })
        except Exception as e:
            return json.dumps({"error": f"Failed to read float: {str(e)}"})

    def read_double(self, address_str):
        """Read a 64-bit double from memory at the given address."""
        import struct
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})
        try:
            raw, _ = self._read_raw_bytes(addr, 8)
            val = struct.unpack(('>' if self.program.getLanguage().isBigEndian() else '<') + 'd', raw)[0]
            return json.dumps({
                "address": address_str,
                "value": val,
                "type": "double",
            })
        except Exception as e:
            return json.dumps({"error": f"Failed to read double: {str(e)}"})

    def read_float_array(self, address_str, count):
        """Read `count` consecutive 32-bit floats from memory at the given address.
        Returns a list of float values."""
        import struct
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})
        if count <= 0:
            return json.dumps({"error": "count must be positive"})
        try:
            raw, actual = self._read_raw_bytes(addr, count * 4)
            values = list(struct.unpack(('>' if self.program.getLanguage().isBigEndian() else '<') + 'f' * (actual // 4), raw[:actual - actual % 4]))
            return json.dumps({
                "address": address_str,
                "count": len(values),
                "values": values,
                "type": "float[]",
            })
        except Exception as e:
            return json.dumps({"error": f"Failed to read float array: {str(e)}"})

    def read_double_array(self, address_str, count):
        """Read `count` consecutive 64-bit doubles from memory at the given address.
        Returns a list of double values."""
        import struct
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})
        if count <= 0:
            return json.dumps({"error": "count must be positive"})
        try:
            raw, actual = self._read_raw_bytes(addr, count * 8)
            values = list(struct.unpack(('>' if self.program.getLanguage().isBigEndian() else '<') + 'd' * (actual // 8), raw[:actual - actual % 8]))
            return json.dumps({
                "address": address_str,
                "count": len(values),
                "values": values,
                "type": "double[]",
            })
        except Exception as e:
            return json.dumps({"error": f"Failed to read double array: {str(e)}"})

    def read_float_matrix(self, address_str, row_stride_bytes, num_rows, row_length):
        """Read `num_rows` rows of `row_length` consecutive 32-bit floats
        each, where consecutive rows are `row_stride_bytes` apart (which
        may differ from row_length*4 -- e.g. a per-feature table padded to
        a wider struct stride). Collapses the manual "compute
        base+i*stride by hand, call read_float/read_float_array per row"
        cycle (an easy source of hex-arithmetic slips, e.g. 5*0x154 !=
        0x6a8) into one call. Returns {"rows": [[...], ...]}; a row that
        can't be fully read (past mapped memory) is truncated and its
        actual length noted in "row_lengths"."""
        import struct
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})
        if num_rows <= 0 or row_length <= 0:
            return json.dumps({"error": "num_rows and row_length must be positive"})
        if row_stride_bytes < row_length * 4:
            return json.dumps({
                "error": f"row_stride_bytes ({row_stride_bytes}) is smaller than "
                         f"row_length*4 ({row_length * 4}) -- rows would overlap"
            })
        try:
            rows = []
            row_lengths = []
            for i in range(num_rows):
                row_addr = addr.add(i * row_stride_bytes)
                raw, actual = self._read_raw_bytes(row_addr, row_length * 4)
                n = actual // 4
                values = list(struct.unpack(('>' if self.program.getLanguage().isBigEndian() else '<') + 'f' * n, raw[:n * 4]))
                rows.append(values)
                row_lengths.append(n)
            return json.dumps({
                "address": address_str,
                "row_stride_bytes": row_stride_bytes,
                "num_rows": len(rows),
                "row_length": row_length,
                "rows": rows,
                "row_lengths": row_lengths,
                "type": "float[][]",
            })
        except Exception as e:
            return json.dumps({"error": f"Failed to read float matrix: {str(e)}"})

    def read_int(self, address_str, size=4, signed=True):
        """Read an integer from memory at the given address.
        size: 1, 2, 4, or 8 bytes.  signed: bool.
        Returns both "value" (decimal) and "hex" (the zero-padded unsigned
        bit pattern, e.g. "0xffffffff" for -1 at size=4) -- decompiler
        output expresses bitmasks in hex, so this saves converting by hand
        every time you cross-check a read value against a `& 0x...` mask."""
        import struct
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})
        if size not in (1, 2, 4, 8):
            return json.dumps({"error": "size must be 1, 2, 4, or 8"})
        try:
            raw_bytes, _ = self._read_raw_bytes(addr, size)
            fmt_map = {
                (1, True): 'b', (1, False): 'B',
                (2, True): 'h', (2, False): 'H',
                (4, True): 'i', (4, False): 'I',
                (8, True): 'q', (8, False): 'Q',
            }
            fmt = ('>' if self.program.getLanguage().isBigEndian() else '<') + fmt_map[(size, signed)]
            val = struct.unpack(fmt, raw_bytes)[0]
            unsigned_val = val & ((1 << (size * 8)) - 1)
            return json.dumps({
                "address": address_str,
                "value": val,
                "hex": f"0x{unsigned_val:0{size*2}x}",
                "type": f"{'int' if signed else 'uint'}{size*8}",
            })
        except Exception as e:
            return json.dumps({"error": f"Failed to read int: {str(e)}"})

    def read_int_array(self, address_str, count, size=4, signed=False):
        """Read `count` consecutive integers of `size` bytes (1/2/4/8) from
        memory starting at address. Returns decoded "values" (decimal) and
        "hex_values" (zero-padded unsigned hex per element) -- eliminates
        the get_bytes-then-struct.unpack-in-a-subprocess round trip that
        table-geometry/bitfield-catalog work otherwise needs constantly."""
        import struct
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})
        if count <= 0:
            return json.dumps({"error": "count must be positive"})
        if size not in (1, 2, 4, 8):
            return json.dumps({"error": "size must be 1, 2, 4, or 8"})
        fmt_map = {
            (1, True): 'b', (1, False): 'B',
            (2, True): 'h', (2, False): 'H',
            (4, True): 'i', (4, False): 'I',
            (8, True): 'q', (8, False): 'Q',
        }
        fmt_char = fmt_map[(size, signed)]
        try:
            raw, actual = self._read_raw_bytes(addr, count * size)
            n = actual // size
            values = list(struct.unpack(('>' if self.program.getLanguage().isBigEndian() else '<') + fmt_char * n, raw[:n * size]))
            mask = (1 << (size * 8)) - 1
            hex_values = [f"0x{(v & mask):0{size*2}x}" for v in values]
            return json.dumps({
                "address": address_str,
                "count": len(values),
                "element_size": size,
                "values": values,
                "hex_values": hex_values,
                "type": f"{'int' if signed else 'uint'}{size*8}[]",
            })
        except Exception as e:
            return json.dumps({"error": f"Failed to read int array: {str(e)}"})

    def read_pointer_array(self, address_str, count):
        """Read `count` consecutive 32-bit pointers from memory and resolve
        each pointer value to a known symbol in the program (function name,
        data label, etc.) when one exists.  Saves the manual two-step of
        read_int_array + look-up-each-value-via-find_next_symbol that
        vtable, offset-table, and pointer-array RE otherwise needs."""
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})
        if count <= 0:
            return json.dumps({"error": "count must be positive"})
        try:
            raw_bytes, actual = self._read_raw_bytes(addr, count * 4)
            n = actual // 4
            import struct
            values = list(struct.unpack(('>' if self.program.getLanguage().isBigEndian() else '<') + 'I' * n, raw_bytes[:n * 4]))
            pointers = []
            sym_table = self._program.getSymbolTable()
            for i, val in enumerate(values):
                entry = {
                    "index": i,
                    "address": str(addr.add(i * 4)),
                    "pointer_hex": f"0x{val:08x}",
                    "is_null": val == 0,
                }
                if val != 0:
                    try:
                        target_str = f"0x{val:x}"
                        target_addr = self.program.getAddressFactory().getAddress(target_str)
                        fn = self._function_manager.getFunctionContaining(target_addr)
                        if fn is not None:
                            entry["symbol"] = fn.getName()
                            if str(fn.getEntryPoint()) == target_str[2:]:  # strip "0x"
                                entry["is_function"] = True
                        else:
                            sym = sym_table.getSymbol(target_addr)
                            if sym:
                                entry["symbol"] = sym.getName()
                        data_at = self._listing.getDefinedDataAt(target_addr)
                        if data_at:
                            entry["data_type"] = str(data_at.getDataType().getName())
                    except Exception:
                        pass
                pointers.append(entry)
            return json.dumps({
                "address": address_str,
                "count": len(pointers),
                "pointers": pointers,
            })
        except Exception as e:
            return json.dumps({"error": f"Failed to read pointer array: {str(e)}"})

    def resolve_switch_dispatch(self, byte_table_addr, entry_count, jump_table_addr,
                                 case_value_start=0):
        """Resolve a compiler-generated `switch` dispatched via a per-case
        BYTE index table feeding a pointer jump table (the common
        `MOV AL,[EDX+byte_table]; JMP [EAX*4+jump_table]` MSVC pattern for
        a dense switch with non-trivial fallthrough grouping). Reads
        `entry_count` bytes at `byte_table_addr` (one group-index byte per
        case value, case values numbered from `case_value_start`), reads
        the jump table at `jump_table_addr` (one pointer per distinct group
        index, count = max(byte_table)+1), and reports BOTH the raw
        group-index grouping AND the (more useful) grouping by actual
        resolved handler address -- two DIFFERENT group indices can point
        at the IDENTICAL handler address when the compiler deduplicated
        identical case bodies, which is exactly the situation decompiler
        output shows as one merged `case A: case B: ...` list even though
        the case values may be logically distinct groups. A case value
        with an ENTIRELY UNIQUE handler address (no other case value
        shares it) is a strong signal that case deserves independent
        verification, not an assumption that it behaves like its numeric
        neighbors.

        Saves the manual get_bytes(byte_table) + read_pointer_array(jump_table)
        + cross-reference-by-hand cycle."""
        import struct
        byte_addr = self.program.getAddressFactory().getAddress(byte_table_addr)
        if byte_addr is None:
            return json.dumps({"error": f"Invalid byte_table_addr: {byte_table_addr}"})
        if entry_count <= 0:
            return json.dumps({"error": "entry_count must be positive"})
        try:
            raw_bytes, actual = self._read_raw_bytes(byte_addr, entry_count)
            group_indices = list(struct.unpack(('>' if self.program.getLanguage().isBigEndian() else '<') + 'B' * actual, raw_bytes[:actual]))
        except Exception as e:
            return json.dumps({"error": f"Failed to read byte_table: {str(e)}"})

        jt_addr = self.program.getAddressFactory().getAddress(jump_table_addr)
        if jt_addr is None:
            return json.dumps({"error": f"Invalid jump_table_addr: {jump_table_addr}"})
        num_groups = (max(group_indices) + 1) if group_indices else 0
        try:
            jt_raw, jt_actual = self._read_raw_bytes(jt_addr, num_groups * 4)
            n = jt_actual // 4
            handler_values = list(struct.unpack(('>' if self.program.getLanguage().isBigEndian() else '<') + 'I' * n, jt_raw[:n * 4]))
        except Exception as e:
            return json.dumps({"error": f"Failed to read jump_table: {str(e)}"})

        sym_table = self._program.getSymbolTable()

        def resolve_symbol(val):
            if val == 0:
                return None
            try:
                target_str = f"0x{val:x}"
                target_addr = self.program.getAddressFactory().getAddress(target_str)
                fn = self._function_manager.getFunctionContaining(target_addr)
                if fn is not None:
                    return fn.getName()
                sym = sym_table.getSymbol(target_addr)
                if sym:
                    return sym.getName()
            except Exception:
                pass
            return None

        handler_hex = [f"0x{v:08x}" if i < len(handler_values) else None
                        for i, v in enumerate(handler_values)]
        entries = []
        by_address = {}
        for i, grp in enumerate(group_indices):
            case_value = case_value_start + i
            addr_hex = handler_hex[grp] if grp < len(handler_hex) else None
            entries.append({
                "case_value": case_value,
                "group_index": grp,
                "handler_address": addr_hex,
            })
            if addr_hex is not None:
                by_address.setdefault(addr_hex, []).append(case_value)

        # Flag case values whose handler address is not shared by any other
        # case value in this switch -- these are exactly the ones a naive
        # "looks like it belongs with its numeric neighbors" read will get
        # wrong (confirmed real bug pattern this tool was written to catch).
        unique_cases = sorted(
            cv for addr_hex, cvs in by_address.items() if len(cvs) == 1 for cv in cvs
        )

        return json.dumps({
            "byte_table_addr": byte_table_addr,
            "jump_table_addr": jump_table_addr,
            "entry_count": len(group_indices),
            "num_distinct_groups": num_groups,
            "entries": entries,
            "groups_by_handler_address": {
                addr_hex: {
                    "case_values": cvs,
                    "symbol": resolve_symbol(int(addr_hex, 16)),
                }
                for addr_hex, cvs in by_address.items()
            },
            "standalone_case_values": unique_cases,
        })

    def get_stack_depth(self, address_str):
        """Walk instructions from function entry to `address_str` and
        return the cumulative stack depth change (ESP delta from function
        entry) at that point.  This bridges the gap between Ghidra's
        frame-relative stack variable offsets (which are EBP/anchor-relative)
        and the raw [ESP+N] displacements visible in the disassembly.

        The mapping is:
            actual_ESP_at_instruction = entry_ESP + stack_delta_at_address
            frame_offset_of_slot     = stack_delta_at_address + ESP_displacement

        Returns the function's frame layout (local_size, parameter_size)
        and every stack-affecting instruction from entry to the target
        with its running delta, plus the final delta."""
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})
        fn = self._function_manager.getFunctionContaining(addr)
        if fn is None:
            return json.dumps({"error": f"No function at {address_str}"})

        # Ghidra's own stack analysis (run by analyzeAll) resolves many
        # ESP/EBP-relative operands to real StackReferences already —
        # ground truth, computed by Ghidra's CallDepthChangeInfo/stack
        # tracker, not our own ESP-walk below. When present, this is
        # authoritative; prefer it over the hand-simulated depth.
        resolved_stack_offset = None
        try:
            target_instr = self._listing.getInstructionAt(addr)
            if target_instr is not None:
                for ref in target_instr.getReferencesFrom():
                    to_addr = ref.getToAddress()
                    if to_addr.getAddressSpace().isStackSpace():
                        resolved_stack_offset = int(to_addr.getOffset())
                        break
        except Exception:
            pass

        body = fn.getBody()
        try:
            stack_depth = 0
            entries = []
            target_found = False
            instr_iter = self._listing.getInstructions(body, True)
            while instr_iter.hasNext():
                instr = instr_iter.next()
                ia = instr.getMinAddress()
                addr_str = str(ia)
                mnem = instr.getMnemonicString().upper()
                try:
                    op0 = instr.getDefaultOperandRepresentation(0)
                except Exception:
                    op0 = ""
                delta = 0

                # Track stack-affecting instructions
                if mnem == "PUSH":
                    is_fs_seg = False
                    try:
                        # PUSH FS:[0x0] is a 4-byte push for SEH
                        if "FS:" in str(op0).upper():
                            is_fs_seg = True
                    except Exception:
                        pass
                    # Size depends on operand — most PUSH are 4 bytes
                    # but we can't easily get size from operand here.
                    # x86 PUSH is always 4 bytes in 32-bit mode.
                    delta = -4
                elif mnem == "POP":
                    delta = 4
                elif mnem == "CALL":
                    # Net ESP effect of CALL + callee return, from the
                    # perspective of the *next instruction in the caller*:
                    #
                    #   __cdecl / plain RET (no imm16):
                    #     CALL pushes ret addr (-4), callee RET pops it (+4)
                    #     → net delta = 0
                    #
                    #   stdcall / thiscall / RET imm16:
                    #     CALL pushes ret addr (-4), callee RET N pops
                    #     ret addr (+4) AND N bytes of arguments (+N)
                    #     → net effect after return = +N
                    #
                    # At the CALL instruction itself, ONLY the return-address
                    # push (-4) is immediately observable — the callee hasn't
                    # returned yet.  So when the CALL *is* the target address,
                    # we report just the -4; for non-target calls we report
                    # the full post-return delta.
                    #
                    callee_cleanup = 0  # arg bytes popped by callee
                    try:
                        prim_ref = instr.getPrimaryReference(0)
                        if prim_ref is not None:
                            target_addr = prim_ref.getToAddress()
                            callee = self._function_manager.getFunctionAt(target_addr)
                            if callee is not None and callee.isThunk():
                                thunked = callee.getThunkedFunction(True)
                                if thunked is not None:
                                    callee = thunked
                            if callee is not None:
                                # Prefer Ghidra's own computed purge size — this is
                                # correct for both internal functions AND imported
                                # Win32 API calls (virtually all __stdcall), unlike
                                # scanning bytes for a RET <imm16> which only works
                                # when the callee has a disassembled body.
                                purge = callee.getStackPurgeSize()
                                if purge not in (Function.UNKNOWN_STACK_DEPTH_CHANGE,
                                                  Function.INVALID_STACK_DEPTH_CHANGE):
                                    callee_cleanup = purge
                                elif callee.isExternal():
                                    # Ghidra couldn't determine purge size for this
                                    # import (known Ghidra gap, see NSA/ghidra#6737).
                                    # Approximate stdcall cleanup from the declared
                                    # parameter count — far better than assuming
                                    # cdecl(0) for what is almost always stdcall.
                                    callee_cleanup = callee.getParameterCount() * 4
                                else:
                                    callee_body = callee.getBody()
                                    callee_instr_iter = self._listing.getInstructions(callee_body, True)
                                    while callee_instr_iter.hasNext():
                                        ci = callee_instr_iter.next()
                                        if ci.getMnemonicString() in ("RET", "RETF"):
                                            ret_op = ci.getDefaultOperandRepresentation(0)
                                            if ret_op:
                                                callee_cleanup = int(ret_op, 0)
                                            break
                    except Exception:
                        pass  # fall back to cleanup=0
                    # Is this CALL the target address?
                    if ia.equals(addr) or addr_str == address_str:
                        delta = -4  # only ret-addr push observable here
                    else:
                        delta = callee_cleanup  # 0 for __cdecl, N for stdcall
                elif mnem in ("RET", "RETF"):
                    delta = 4
                elif mnem == "SUB" and op0 and "ESP" in op0.upper():
                    try:
                        op1 = instr.getDefaultOperandRepresentation(1)
                        delta = -int(op1, 0)
                    except Exception:
                        delta = 0
                elif mnem == "ADD" and op0 and "ESP" in op0.upper():
                    try:
                        op1 = instr.getDefaultOperandRepresentation(1)
                        delta = int(op1, 0)
                    except Exception:
                        delta = 0
                elif mnem in ("ENTER",):
                    try:
                        op1 = instr.getDefaultOperandRepresentation(1)
                        delta = -int(op1, 0) - 4
                    except Exception:
                        delta = 0

                if delta != 0:
                    stack_depth += delta
                    entries.append({
                        "address": addr_str,
                        "instruction": f"{instr.getMnemonicString()} {op0}",
                        "delta": delta,
                        "running_depth": stack_depth,
                    })

                if ia.equals(addr) or addr_str == address_str:
                    target_found = True
                    break

            if not target_found:
                return json.dumps({"error": f"Address {address_str} not found in function"})

            # Compute frame layout from the function
            local_size = 0
            param_size = 0
            try:
                stack_frame = fn.getStackFrame()
                if stack_frame:
                    local_size = stack_frame.getLocalSize()
                    param_size = stack_frame.getParameterSize()
            except Exception:
                pass

            return json.dumps({
                "function": fn.getName(),
                "function_entry": str(fn.getEntryPoint()),
                "target_address": address_str,
                "stack_depth_at_target": stack_depth,
                "resolved_stack_offset": resolved_stack_offset,
                "resolved_stack_offset_note": (
                    "From Ghidra's own StackReference on this instruction's operand "
                    "(authoritative) when not null; stack_depth_at_target below is "
                    "our own ESP-walk simulation, kept as a fallback for instructions "
                    "Ghidra's stack analysis didn't resolve."
                ),
                "frame_local_size": local_size,
                "frame_parameter_size": param_size,
                "stack_affecting_ops": entries,
                "num_stack_ops": len(entries),
            })
        except Exception as e:
            return json.dumps({"error": f"get_stack_depth failed: {str(e)}"})

    def get_abi_summary(self, address_str):
        """Mechanical calling-convention summary for a function: scans every
        RET in the function body for its stack-purge immediate, and checks
        the opening instructions for ECX used as a memory base or spilled to
        a stack slot (the classic MSVC thiscall pattern). Packages up the
        single most-repeated manual task in ABI-port work (reading raw
        disassembly by hand to answer "thiscall or stdcall, how many stack
        args") into one call. Best-effort, not authoritative -- cross-check
        against disassembly per project convention before committing to a
        calling-convention comment, especially when ret_purge_bytes_seen has
        more than one distinct value or thiscall_evidence is empty."""
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})
        fn = self._function_manager.getFunctionContaining(addr)
        if fn is None:
            return json.dumps({"error": f"No function at {address_str}"})

        ghidra_convention = None
        try:
            ghidra_convention = fn.getCallingConventionName()
        except Exception:
            pass

        addr_set = fn.getBody()
        ret_purge_bytes = set()
        opening_instrs = []  # first 50 instructions for thiscall prologue analysis
        instr_iter = self._listing.getInstructions(addr_set, True)
        while instr_iter.hasNext():
            instr = instr_iter.next()
            mnem = instr.getMnemonicString().upper()
            if mnem in ("RET", "RETN"):
                purge = 0
                try:
                    if instr.getNumOperands() > 0:
                        rep = instr.getDefaultOperandRepresentation(0)
                        if rep:
                            purge = int(rep, 16) if rep.lower().startswith("0x") else int(rep)
                except Exception:
                    purge = 0
                ret_purge_bytes.add(purge)
            if len(opening_instrs) < 50:
                opening_instrs.append(instr)

        # thiscall evidence: ECX (or a direct register alias) used as a memory
        # base, or ECX spilled to a stack slot (MOV mem, ECX), in the opening
        # instructions.  Tracks ECX→register aliases (e.g. MOV EBX, ECX then
        # [EBX+offset]) that are the most common reason thiscall detection misses
        # real this-pointer functions.  Aliases are removed from the tracking set
        # when the alias register is overwritten from a non-ECX source.
        thiscall_evidence = []
        ecx_aliases = {"ECX"}
        for instr in opening_instrs:
            mnem = instr.getMnemonicString().upper()
            try:
                num_ops = instr.getNumOperands()
                ops = [instr.getDefaultOperandRepresentation(i) for i in range(num_ops)]
            except Exception:
                ops = []

            # Track alias creation and death via MOV instructions
            if mnem == "MOV" and len(ops) == 2:
                dst, src = ops[0], ops[1]
                is_dst_reg = not dst.startswith("[") and not dst.startswith("(")
                # Alias death: a non-ECX alias register being overwritten
                if dst in ecx_aliases and dst != "ECX":
                    ecx_aliases.discard(dst)
                # Alias creation: MOV <reg>, <src> where src is an alias
                if src in ecx_aliases and is_dst_reg:
                    ecx_aliases.add(dst)

            # Check for memory base dereference via any alias
            found_this = False
            for rep in ops:
                if not rep:
                    continue
                rep_nosp = rep.replace(" ", "")
                for alias in ecx_aliases:
                    if f"[{alias}" in rep_nosp:
                        reason = (f"{alias} used as memory base"
                                  f"{' (alias of ECX)' if alias != 'ECX' else ''}")
                        thiscall_evidence.append({
                            "address": str(instr.getMinAddress()),
                            "instruction": f"{mnem} {', '.join(ops)}",
                            "reason": reason,
                        })
                        found_this = True
                        break
                if found_this:
                    break
            if found_this:
                continue

            # ECX spilled to stack: MOV [mem], ECX
            if (mnem == "MOV" and len(ops) == 2
                    and ops[1] == "ECX" and "[" in (ops[0] or "")):
                thiscall_evidence.append({
                    "address": str(instr.getMinAddress()),
                    "instruction": f"{mnem} {', '.join(ops)}",
                    "reason": "ECX spilled to stack slot (this pointer save)",
                })
                continue

            # ECX restored from alias before a call: MOV ECX, <alias>
            # This is the most common signal when ECX is aliased to another
            # register in the prologue and then restored just before a call.
            if (mnem == "MOV" and len(ops) == 2
                    and ops[0] == "ECX" and ops[1] in ecx_aliases
                    and ops[1] != "ECX"):
                thiscall_evidence.append({
                    "address": str(instr.getMinAddress()),
                    "instruction": f"{mnem} {', '.join(ops)}",
                    "reason": f"ECX restored from alias {ops[1]} before call",
                })

        ghidra_says_thiscall = (ghidra_convention is not None and
                                 "thiscall" in str(ghidra_convention).lower())
        ghidra_says_not_thiscall = (ghidra_convention is not None and
                                     str(ghidra_convention).lower() not in ("unknown", "") and
                                     not ghidra_says_thiscall)

        ret_purge_bytes_list = sorted(ret_purge_bytes)
        stack_args_guess = None
        convention_guess = None
        if len(ret_purge_bytes_list) == 1:
            rb = ret_purge_bytes_list[0]
            if rb == 0:
                stack_args_guess = 0
                convention_guess = ("__cdecl (caller cleans stack) or a leaf/no-stack-arg "
                                    "callee-cleans function -- RET alone doesn't disambiguate")
            else:
                stack_args_guess = rb // 4
                if thiscall_evidence and ghidra_says_not_thiscall:
                    # ECX heuristic and Ghidra's own convention analysis disagree --
                    # surface the conflict rather than silently trusting either one.
                    # Common false-positive cause: ECX loaded from a stack arg and
                    # reused as a scratch pointer mid-function, not an incoming this.
                    convention_guess = (
                        f"DISAGREEMENT: ECX-usage heuristic suggests thiscall but Ghidra's "
                        f"own analysis says '{ghidra_convention}' -- {stack_args_guess} stack "
                        f"arg(s) (RET 0x{rb:x}) either way. Likely false positive: ECX may be "
                        f"loaded from a stack argument and reused as a scratch pointer, not an "
                        f"incoming this. Trust ghidra_calling_convention here; verify manually.")
                elif thiscall_evidence:
                    convention_guess = (f"thiscall, {stack_args_guess} stack arg(s) "
                                        f"(RET 0x{rb:x}), ECX = this")
                else:
                    convention_guess = (f"__stdcall, {stack_args_guess} stack arg(s) "
                                        f"(RET 0x{rb:x}) -- no thiscall evidence found")
        elif len(ret_purge_bytes_list) > 1:
            convention_guess = (f"AMBIGUOUS: multiple distinct RET purge values "
                                 f"{[hex(b) for b in ret_purge_bytes_list]} -- verify manually, "
                                 f"multiple exit paths may disagree or body range may be wrong")
        else:
            convention_guess = "no RET instruction found in function body"

        return json.dumps({
            "address": address_str,
            "name": fn.getName(),
            "ghidra_calling_convention": str(ghidra_convention) if ghidra_convention else None,
            "ret_purge_bytes_seen": [hex(b) for b in ret_purge_bytes_list],
            "stack_args_guess": stack_args_guess,
            "convention_guess": convention_guess,
            "thiscall_evidence": thiscall_evidence,
            "note": ("Mechanical signal from RET-scan + ECX-usage heuristic, not authoritative. "
                     "Cross-check against disassembly per project Rule 12 (count stack args "
                     "from the RET instruction, not the decompiler's inferred prototype) "
                     "before writing a confirmed calling-convention comment."),
        })

    def scan_unnamed_labels(self, name_prefix="FUN_", max_functions=500,
                             max_string_len=80, limit=200, offset=0):
        """Bulk self-labeling-string scanner. Mechanizes the single most
        repeated manual step in the naming-sweep workflow: for every
        function whose name still starts with name_prefix (default
        "FUN_", i.e. unnamed), walk every instruction in its body,
        collect all DATA-type references it makes, and for each
        referenced address read the RAW BYTES directly (not via Ghidra's
        string auto-analysis catalog -- list_strings has been observed
        to miss real embedded strings entirely, e.g. FlexTalk.dll
        0x103292d4/0x1032a2ec, both only found by this raw-byte approach)
        to check whether it decodes as a printable, NUL-terminated ASCII
        string. Each such string is tested against three self-labeling
        shapes seen repeatedly in this project's binaries:
          - "ClassName::method_name" (e.g. "CTextAnalyzer::do_escapes")
          - "module.DLL: name" / "module.DLL:  name()" (e.g.
            "FT_UTIL.DLL:  new_word():  Ran out of frend words.")
          - "sourcefile.cpp: function_name: ..." (e.g.
            "falloc.cpp: save_lookahead: could not allocate ...") -- names
            the actual vendor source function; the '@(#) $Id: FILE.CPP 4.1'
            SCCS version tags are deliberately NOT matched
          - bare "identifier()" debug-trace labels (e.g. "NXT_ccl_f()")
        Each candidate also carries "implied_symbol": the self-labeled name
        pulled straight out of the string (the Class::method, the function
        after '.cpp:', or the bare name), so a hit is directly actionable.
        Returns one candidate per (function, matched string) pair with
        the function's current name/address, the string's own address,
        the matched text, and which pattern matched -- replacing the
        previous manual cycle of "grep the string table -> find its
        address -> get_xrefs_to -> check if the caller is still
        unnamed" with a single bulk pass. Best-effort and NOT
        authoritative: a match is strong evidence the function's real
        name is embedded in the string (especially the Class::method and
        module.DLL: shapes), but confirm by reading the surrounding
        decompile before renaming, per project Rule 6."""
        import re
        # Each entry: (compiled_regex, label, symbol_extractor). The extractor
        # pulls the self-labeled SYMBOL name out of a match (or None when the
        # shape doesn't name one), surfaced as "implied_symbol" so a matched
        # string is directly actionable without re-reading it by hand.
        patterns = [
            (re.compile(r'^[A-Za-z_][A-Za-z0-9_]*::[A-Za-z_][A-Za-z0-9_]*'), "Class::method",
             lambda m: m.group(0)),
            (re.compile(r'^[A-Za-z_][A-Za-z0-9_.]{0,40}\.DLL:\s{1,2}[A-Za-z_]'), "module.DLL: name",
             lambda m: None),
            # SOURCEFILE.cpp: function_name: ...  -- these binaries' vendor debug
            # strings name the actual source function (e.g.
            # "falloc.cpp: save_lookahead: could not allocate ..."). The existing
            # module.DLL: / Class:: / name() shapes do NOT match this, so a scan
            # returning "no candidates" was previously a false negative. The '^'
            # anchor + required ':' after '.cpp' excludes the '@(#) $Id: FILE.CPP
            # 4.1 ...' SCCS version tags (they start with '@' and have no ':'
            # after the extension).
            (re.compile(r'^[A-Za-z_][A-Za-z0-9_]{0,40}\.cpp:\s+([A-Za-z_][A-Za-z0-9_]*)'), "file.cpp: name",
             lambda m: m.group(1)),
            (re.compile(r'^[A-Za-z_][A-Za-z0-9_]*\(\)'), "bare name()",
             lambda m: m.group(0)[:-2]),
        ]

        def classify(text):
            for rx, label, extractor in patterns:
                m = rx.match(text)
                if m:
                    return label, extractor(m)
            return None, None

        candidates = []
        scanned = 0
        it = self._function_manager.getFunctions(True)
        while it.hasNext():
            fn = it.next()
            if not fn.getName().startswith(name_prefix):
                continue
            if scanned >= max_functions:
                break
            scanned += 1
            seen_targets = set()
            found_for_fn = 0
            try:
                instr_iter = self._listing.getInstructions(fn.getBody(), True)
                while instr_iter.hasNext() and found_for_fn < 3:
                    instr = instr_iter.next()
                    for ref in self._ref_manager.getReferencesFrom(instr.getMinAddress()):
                        if not ref.getReferenceType().isData():
                            continue
                        target = ref.getToAddress()
                        tkey = str(target)
                        if tkey in seen_targets:
                            continue
                        seen_targets.add(tkey)
                        try:
                            raw, actual = self._read_raw_bytes(target, max_string_len + 1)
                        except Exception:
                            continue
                        if not raw:
                            continue
                        nul = raw.find(b'\x00')
                        text_bytes = raw[:nul] if nul >= 0 else None
                        if not text_bytes or not (0 < len(text_bytes) <= max_string_len):
                            continue
                        if not all(32 <= b < 127 for b in text_bytes):
                            continue
                        text = text_bytes.decode('latin1')
                        pattern_label, implied_symbol = classify(text)
                        if pattern_label is None:
                            continue
                        candidates.append({
                            "function_address": str(fn.getEntryPoint()),
                            "current_name": fn.getName(),
                            "string_address": tkey,
                            "matched_string": text,
                            "pattern": pattern_label,
                            "implied_symbol": implied_symbol,
                        })
                        found_for_fn += 1
                        if found_for_fn >= 3:
                            break
            except Exception:
                continue

        total = len(candidates)
        candidates = candidates[offset:offset + limit]
        return json.dumps({
            "candidates": candidates,
            "total": total,
            "functions_scanned": scanned,
            "note": ("Best-effort, not authoritative -- confirm each candidate by reading "
                     "the surrounding decompile before renaming, per project Rule 6. "
                     "'total' may undercount if max_functions was reached before scanning "
                     "every name_prefix-matching function; check functions_scanned."),
        })

    def find_class_ownership_strings(self, max_functions=5000, max_string_len=80, limit=200, offset=0, only_mismatches=False):
        """Whole-DLL debug/self-labeled-string class-ownership inventory.
        Generalizes scan_unnamed_labels (which only looks at already-unnamed
        FUN_* functions, to find rename candidates) to EVERY function
        regardless of current name, and adds a 4th pattern for the
        'MODULE_DLL!Class::method' shape (raw '!' separator, e.g.
        'FT_WAVE_DLL!CWave::input_synch...') that scan_unnamed_labels'
        existing 3 patterns do not match. For every hit, compares the
        STRING's own implied class name against the calling function's
        CURRENT Ghidra namespace and reports namespace_mismatch=true when
        they disagree.
        This mechanizes the single highest-leverage manual technique from
        this project's 2026-07-12 RE session: both the CWave/CVoice and
        CUtility/CTextAnalyzer identity corrections were found by
        eyeballing exactly this kind of embedded string by hand -- this
        makes that a single bulk query instead of a lucky spot.
        Pass only_mismatches=true to skip everything where the string's
        class agrees with (or doesn't distinguish from) the function's
        current namespace, surfacing just the disagreements worth
        investigating."""
        return json.dumps(self._do_find_class_ownership_strings(
            max_functions, max_string_len, limit, offset, only_mismatches))

    def _do_find_class_ownership_strings(self, max_functions, max_string_len, limit, offset, only_mismatches):
        import re
        # Each entry: (regex, label, class_extractor, symbol_extractor).
        # class_extractor -> the OWNING CLASS name when the shape names one (used
        # for namespace_mismatch); symbol_extractor -> the self-labeled symbol
        # name (surfaced as implied_symbol, always informational).
        patterns = [
            (re.compile(r'^[A-Za-z_][A-Za-z0-9_]*::[A-Za-z_][A-Za-z0-9_]*'), "Class::method",
             lambda m: m.group(0).split("::")[0], lambda m: m.group(0)),
            (re.compile(r'^[A-Za-z][A-Za-z0-9_]*!([A-Za-z_][A-Za-z0-9_]*)::'), "MODULE!Class::method",
             lambda m: m.group(1), lambda m: m.group(0).split("!", 1)[1]),
            (re.compile(r'^[A-Za-z_][A-Za-z0-9_.]{0,40}\.DLL:\s{1,2}[A-Za-z_]'), "module.DLL: name",
             lambda m: None, lambda m: None),
            # SOURCEFILE.cpp: name: ...  vendor debug strings that name the source
            # function (or, occasionally, a class, e.g. "translat.cpp:
            # CTranslator: ..."). implied_class is only set when the captured
            # token follows the C<Upper> class-naming convention -- so a real
            # class name like CTranslator can drive a namespace_mismatch, while a
            # plain free-function name (save_lookahead, ftinit, ...) stays purely
            # informational and never produces a false mismatch. Excludes the
            # '@(#) $Id: FILE.CPP 4.1' SCCS tags (leading '@', no ':' after ext).
            (re.compile(r'^[A-Za-z_][A-Za-z0-9_]{0,40}\.cpp:\s+([A-Za-z_][A-Za-z0-9_]*)'), "file.cpp: name",
             lambda m: m.group(1) if re.match(r'C[A-Z]', m.group(1)) else None,
             lambda m: m.group(1)),
            (re.compile(r'^[A-Za-z_][A-Za-z0-9_]*\(\)'), "bare name()",
             lambda m: None, lambda m: m.group(0)[:-2]),
        ]

        def classify(text):
            for rx, label, class_extractor, symbol_extractor in patterns:
                m = rx.match(text)
                if m:
                    return label, class_extractor(m), symbol_extractor(m)
            return None, None, None

        results = []
        scanned = 0
        it = self._function_manager.getFunctions(True)
        while it.hasNext():
            fn = it.next()
            if scanned >= max_functions:
                break
            scanned += 1
            ns = fn.getParentNamespace()
            current_class = None
            if ns is not None and not ns.isGlobal():
                current_class = str(ns.getName())
            seen_targets = set()
            found_for_fn = 0
            try:
                instr_iter = self._listing.getInstructions(fn.getBody(), True)
                while instr_iter.hasNext() and found_for_fn < 3:
                    instr = instr_iter.next()
                    for ref in self._ref_manager.getReferencesFrom(instr.getMinAddress()):
                        if not ref.getReferenceType().isData():
                            continue
                        target = ref.getToAddress()
                        tkey = str(target)
                        if tkey in seen_targets:
                            continue
                        seen_targets.add(tkey)
                        try:
                            raw, actual = self._read_raw_bytes(target, max_string_len + 1)
                        except Exception:
                            continue
                        if not raw:
                            continue
                        nul = raw.find(b'\x00')
                        text_bytes = raw[:nul] if nul >= 0 else None
                        if not text_bytes or not (0 < len(text_bytes) <= max_string_len):
                            continue
                        if not all(32 <= b < 127 for b in text_bytes):
                            continue
                        text = text_bytes.decode('latin1')
                        pattern_label, implied_class, implied_symbol = classify(text)
                        if pattern_label is None:
                            continue
                        mismatch = (implied_class is not None and current_class is not None
                                    and implied_class != current_class)
                        if only_mismatches and not mismatch:
                            continue
                        results.append({
                            "function_address": str(fn.getEntryPoint()),
                            "current_name": fn.getName(),
                            "current_namespace": current_class,
                            "string_address": tkey,
                            "matched_string": text,
                            "pattern": pattern_label,
                            "implied_class": implied_class,
                            "implied_symbol": implied_symbol,
                            "namespace_mismatch": mismatch,
                        })
                        found_for_fn += 1
                        if found_for_fn >= 3:
                            break
            except Exception:
                continue

        total = len(results)
        results = results[offset:offset + limit]
        return {
            "results": results,
            "total": total,
            "functions_scanned": scanned,
            "note": ("Best-effort, not authoritative -- a namespace_mismatch is strong evidence "
                     "(this session it was correct both times it was checked by hand: "
                     "CWave/CVoice, CUtility/CTextAnalyzer) but confirm via a fresh decompile "
                     "before renaming, per project Rule 6. implied_class is null for patterns "
                     "that don't name a class (module.DLL:, bare name()) -- those rows are "
                     "informational only, never flagged as mismatches."),
        }

    def classify_function_inventory(self, name_prefix="FUN_", max_functions=8000,
                                    limit=500, offset=0):
        """Triage the still-unnamed (name_prefix, default 'FUN_') function
        inventory into likely-REAL functions vs. likely COMPILER ARTIFACTS,
        so a raw 'N unnamed functions' backlog can be re-scoped before anyone
        budgets effort against the raw number.

        Motivated by a concrete finding on FlexTalk.dll (full write-up:
        voxtalk/docs/RE_FUNCTION_INVENTORY_TAXONOMY_2026-07-12.md): of 511
        'FUN_*', ~35% were not real functions but MSVC exception-handling
        cleanup funclets and orphaned function-boundary fragments. Sampling 11
        non-16-byte-aligned entries by hand, all 11 were artifacts; every
        aligned one examined was real.

        Signals used, per that evidence:
          - real MSVC function entries are 16-BYTE ALIGNED; funclets and
            orphaned fragments sit immediately after their parent's code and
            are NOT aligned;
          - EH cleanup funclets are reached ONLY by call references from
            inside a SINGLE parent function (they run in the parent's frame);
          - orphaned body fragments have ZERO references of any kind.

        Per matching function, reports: address, name, aligned16, body_size,
        num_call_refs, distinct_owner_funcs, total_refs, classification
        (likely_real | likely_funclet | likely_orphan_fragment | uncertain),
        and reason. Also a summary count per class. READ-ONLY.

        NOT authoritative: alignment is an excellent discriminator but a real
        aligned leaf can be tiny, and a non-aligned entry can occasionally be
        real. Confirm by decompiling before deleting anything. The natural
        follow-ups are get_function_callers / decompile_function_by_address on
        the flagged entries, then delete_function once confirmed."""
        counts = {"likely_real": 0, "likely_funclet": 0,
                  "likely_orphan_fragment": 0, "uncertain": 0}
        rows = []
        scanned = 0
        it = self._function_manager.getFunctions(True)
        while it.hasNext():
            fn = it.next()
            if not fn.getName().startswith(name_prefix):
                continue
            if scanned >= max_functions:
                break
            scanned += 1
            entry = fn.getEntryPoint()
            aligned = (entry.getOffset() % 16 == 0)
            body_size = int(fn.getBody().getNumAddresses())

            total_refs = 0
            num_call_refs = 0
            # Distinct owning parent functions across ALL reference types: an
            # MSVC EH funclet is reached from its parent either by a CALL or by
            # a DATA pointer in the parent's exception scope table, so counting
            # both (not just calls) keeps such funclets out of "uncertain".
            owner_entries = set()
            try:
                ref_it = self._ref_manager.getReferencesTo(entry)
                while ref_it.hasNext():
                    ref = ref_it.next()
                    total_refs += 1
                    if ref.getReferenceType().isCall():
                        num_call_refs += 1
                    parent = self._function_manager.getFunctionContaining(ref.getFromAddress())
                    if parent is not None:
                        owner_entries.add(str(parent.getEntryPoint()))
            except Exception:
                pass
            distinct_owner_funcs = len(owner_entries)

            if aligned:
                cls = "likely_real"
                reason = "16-byte-aligned entry (normal MSVC function alignment)"
            elif total_refs == 0:
                cls = "likely_orphan_fragment"
                reason = ("non-aligned + zero references -- orphaned tail of a "
                          "function Ghidra split early (real entry is the nearest "
                          "aligned function before this address)")
            elif distinct_owner_funcs == 1:
                cls = "likely_funclet"
                reason = ("non-aligned + reached only from within a single parent "
                          "function (call and/or EH-table data ref) -- MSVC "
                          "exception-handling cleanup funclet")
            else:
                cls = "uncertain"
                reason = ("non-aligned, referenced from more than one function (or "
                          "only from outside any function) -- does not fit the "
                          "single-parent funclet or zero-ref orphan shape; inspect")
            counts[cls] += 1
            rows.append({
                "address": str(entry),
                "name": fn.getName(),
                "aligned16": aligned,
                "body_size": body_size,
                "num_call_refs": num_call_refs,
                "distinct_owner_funcs": distinct_owner_funcs,
                "total_refs": total_refs,
                "classification": cls,
                "reason": reason,
            })

        total = len(rows)
        # Artifacts first (most actionable), then by address.
        order = {"likely_orphan_fragment": 0, "likely_funclet": 1,
                 "uncertain": 2, "likely_real": 3}
        rows.sort(key=lambda r: (order[r["classification"]], r["address"]))
        page = rows[offset:offset + limit]
        return json.dumps({
            "results": page,
            "total": total,
            "functions_scanned": scanned,
            "summary": counts,
            "note": ("Heuristic, NOT authoritative. 16-byte alignment is the primary "
                     "real-vs-artifact discriminator (all 11 non-aligned entries sampled "
                     "by hand on FlexTalk.dll were artifacts; every aligned one was real), "
                     "but a real aligned leaf can be tiny and a non-aligned entry can "
                     "occasionally be real. Confirm via decompile before delete_function. "
                     "See voxtalk/docs/RE_FUNCTION_INVENTORY_TAXONOMY_2026-07-12.md."),
        })

    def get_allocation_site_info(self, address_str, lookback=15, lookahead=15):
        """Given the address of a CALL instruction (typically to
        operator_new/malloc or a thunk to one), walk backward within the
        same basic block for the most recent PUSH <immediate> before the
        call (the presumed allocation SIZE argument -- __cdecl
        operator new(size_t) pushes size right before the call) and walk
        forward from the call for a use of the returned pointer (EAX)
        followed by another CALL, which is the routine
        'if (ptr) ClassName::ClassName(ptr)' idiom immediately after an
        allocation -- reporting that second call's target as the LIKELY
        CONSTRUCTOR.
        This mechanizes a walk done manually many times in this project's
        2026-07-12 RE session: CVoice/CWave/CUtility/CTextAnalyzer's real
        object sizes and constructors were all confirmed exactly this way,
        by hand, via disassemble_function + eyeballing the PUSH before the
        CALL."""
        return json.dumps(self._do_get_allocation_site_info(address_str, lookback, lookahead))

    def _do_get_allocation_site_info(self, address_str, lookback, lookahead):
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return {"error": f"Invalid address: {address_str}"}
        instr = self._listing.getInstructionAt(addr)
        if instr is None:
            return {"error": f"No instruction at {address_str}"}
        if instr.getMnemonicString().upper() != "CALL":
            return {"error": (f"Instruction at {address_str} is '{instr.getMnemonicString()}', "
                              f"not CALL -- pass the address of the allocator CALL instruction "
                              f"itself.")}

        call_target = None
        try:
            for r in instr.getReferencesFrom():
                if r.getReferenceType().isCall():
                    call_target = str(r.getToAddress())
                    break
        except Exception:
            pass

        size_arg = None
        size_arg_address = None
        cur = instr.getPrevious()
        steps = 0
        while cur is not None and steps < lookback:
            mnem = cur.getMnemonicString().upper()
            if mnem in ("CALL", "JMP", "RET", "RETN"):
                break
            if mnem == "PUSH":
                try:
                    opnd = cur.getScalar(0)
                    if opnd is not None:
                        size_arg = int(opnd.getValue())
                        size_arg_address = str(cur.getMinAddress())
                        break
                except Exception:
                    pass
            cur = cur.getPrevious()
            steps += 1

        likely_constructor = None
        likely_constructor_address = None
        cur = instr.getNext()
        steps = 0
        saw_eax_use = False
        while cur is not None and steps < lookahead:
            mnem = cur.getMnemonicString().upper()
            if "EAX" in str(cur):
                saw_eax_use = True
            if mnem == "CALL" and saw_eax_use:
                try:
                    for r in cur.getReferencesFrom():
                        if r.getReferenceType().isCall():
                            likely_constructor_address = str(cur.getMinAddress())
                            likely_constructor = str(r.getToAddress())
                            break
                except Exception:
                    pass
                break
            if mnem in ("JMP", "RET", "RETN"):
                break
            cur = cur.getNext()
            steps += 1

        ctor_fn_name = None
        if likely_constructor:
            ctor_addr = self.program.getAddressFactory().getAddress(likely_constructor)
            ctor_fn = self._function_manager.getFunctionAt(ctor_addr) if ctor_addr else None
            if ctor_fn:
                ctor_fn_name = ctor_fn.getName()

        return {
            "call_address": address_str,
            "call_target": call_target,
            "size_argument": size_arg,
            "size_argument_hex": hex(size_arg) if size_arg is not None else None,
            "size_pushed_at": size_arg_address,
            "likely_constructor_call_address": likely_constructor_address,
            "likely_constructor_target": likely_constructor,
            "likely_constructor_name": ctor_fn_name,
            "note": ("Mechanical heuristic, not authoritative -- confirm the size PUSH is "
                     "really this call's size argument (not left over from an outer "
                     "expression) and that the 'likely constructor' CALL genuinely takes the "
                     "allocated pointer as its this/ECX, by reading the actual decompile "
                     "before relying on this."),
        }

    def resolve_call_site_context(self, address_str, max_args=8, lookback=40, lookahead=15):
        """Given the address of a CALL instruction, resolve (a) each
        argument pushed for that call and (b) what happens to its return
        value (EAX) immediately afterward.

        Generalizes get_allocation_site_info's own backward-PUSH-scan /
        forward-EAX-use technique (previously hardcoded for the single-
        size-argument allocator idiom) to ANY call with any number of
        pushed arguments -- built specifically to replace the manual
        'disassemble a big function, eyeball which PUSH feeds which CALL,
        eyeball what happens to EAX afterward' cycle across many call
        sites to the SAME callee within one caller (get_xrefs_to already
        finds the call site addresses; this resolves what happens at
        each one).

        Arguments: walks backward from the CALL collecting the
        contiguous run of PUSH instructions immediately before it
        (standard __cdecl/__stdcall right-to-left push order), then
        reverses them into logical argument order (arg0 = first pushed
        after any such run, i.e. closest to the call = last argument
        pushed = LAST in this reversed list -- each entry's `push_address`
        lets you confirm the exact instruction). For each PUSH: if its
        operand is a literal scalar, reports the raw hex value AND a
        best-effort NUL-terminated ASCII string preview read directly
        from that address's raw bytes (works even when Ghidra hasn't
        auto-typed the location as a String -- confirmed useful for
        un-typed literal bar-pattern strings in this project's own RE).
        If a PUSH's operand is a register, looks one instruction further
        back for a simple 'MOV reg,imm' or 'LEA reg,[imm]' setting that
        exact register and resolves THAT scalar the same way (one level
        of backtracking only -- NOT a full dataflow trace; falls back to
        "unresolved (register, not immediately preceding constant load)"
        if the register's value doesn't originate from a simple, nearby,
        directly-preceding constant load).

        Result sink: walks forward from the CALL for up to `lookahead`
        instructions looking for the FIRST of: EAX/AL compared then
        conditionally branched (reports as compare_and_branch with the
        comparison and jump target), EAX/AL stored to a fixed memory
        address (reports as store_to_address with the target), or EAX
        pushed as an argument to another CALL (reports as
        used_as_argument_to_call with that call's target). Stops at the
        first CALL/JMP/RET/RETN boundary if none of these fire first.

        Mechanical heuristic, not authoritative -- same disclaimer as
        get_allocation_site_info: confirm against the actual decompile
        before treating a resolved argument or result sink as a fact,
        especially for calling conventions that don't fit the simple
        contiguous-PUSH-run assumption (varargs, register-passed args,
        or a caller that computes an argument through a longer
        expression than one MOV/LEA back)."""
        return json.dumps(self._do_resolve_call_site_context(
            address_str, max_args, lookback, lookahead))

    def _read_cstring_preview(self, addr, max_len=96):
        try:
            mem = self.program.getMemory()
            raw = bytearray()
            cur = addr
            for _ in range(max_len):
                b = mem.getByte(cur) & 0xff
                if b == 0:
                    break
                raw.append(b)
                cur = cur.add(1)
            if not raw:
                return None
            if all(0x20 <= b < 0x7f for b in raw):
                return raw.decode("ascii", errors="replace")
            return None
        except Exception:
            return None

    def _resolve_scalar_arg(self, scalar_value):
        entry = {"raw_value": scalar_value, "hex": hex(scalar_value if scalar_value >= 0 else scalar_value & 0xffffffff)}
        try:
            addr = self.program.getAddressFactory().getAddress(hex(scalar_value & 0xffffffff))
            if addr is not None:
                preview = self._read_cstring_preview(addr)
                if preview is not None:
                    entry["string_preview"] = preview
        except Exception:
            pass
        return entry

    def _do_resolve_call_site_context(self, address_str, max_args, lookback, lookahead):
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return {"error": f"Invalid address: {address_str}"}
        instr = self._listing.getInstructionAt(addr)
        if instr is None:
            return {"error": f"No instruction at {address_str}"}
        if instr.getMnemonicString().upper() != "CALL":
            return {"error": (f"Instruction at {address_str} is '{instr.getMnemonicString()}', "
                              f"not CALL -- pass the address of the CALL instruction itself.")}

        call_target = None
        try:
            for r in instr.getReferencesFrom():
                if r.getReferenceType().isCall():
                    call_target = str(r.getToAddress())
                    break
        except Exception:
            pass
        callee_name = None
        if call_target:
            try:
                t_addr = self.program.getAddressFactory().getAddress(call_target)
                fn = self._function_manager.getFunctionAt(t_addr)
                if fn:
                    callee_name = fn.getName()
            except Exception:
                pass

        # Backward scan: contiguous PUSH run immediately before the call.
        pushes = []  # in reverse-encounter (closest-to-call-first) order
        cur = instr.getPrevious()
        steps = 0
        while cur is not None and steps < lookback and len(pushes) < max_args:
            mnem = cur.getMnemonicString().upper()
            if mnem in ("CALL", "JMP", "RET", "RETN"):
                break
            if mnem == "PUSH":
                entry = {"push_address": str(cur.getMinAddress())}
                try:
                    scalar = cur.getScalar(0)
                except Exception:
                    scalar = None
                if scalar is not None:
                    entry["resolved"] = "immediate"
                    entry.update(self._resolve_scalar_arg(int(scalar.getValue())))
                else:
                    reg_str = None
                    try:
                        reg_str = str(cur.getOpObjects(0)[0])
                    except Exception:
                        pass
                    entry["register"] = reg_str
                    # One level of backtracking: look just behind this PUSH
                    # for a MOV reg,imm or LEA reg,[imm] setting the same reg.
                    resolved_reg = False
                    probe = cur.getPrevious()
                    probe_steps = 0
                    while probe is not None and probe_steps < 6:
                        p_mnem = probe.getMnemonicString().upper()
                        if p_mnem in ("PUSH", "CALL", "JMP", "RET", "RETN"):
                            break
                        if p_mnem in ("MOV", "LEA") and reg_str is not None:
                            try:
                                dst = str(probe.getOpObjects(0)[0])
                            except Exception:
                                dst = None
                            if dst == reg_str:
                                try:
                                    p_scalar = probe.getScalar(1)
                                except Exception:
                                    p_scalar = None
                                if p_scalar is not None:
                                    entry["resolved"] = "immediate_via_register"
                                    entry["set_at"] = str(probe.getMinAddress())
                                    entry.update(self._resolve_scalar_arg(int(p_scalar.getValue())))
                                    resolved_reg = True
                                break
                        probe = probe.getPrevious()
                        probe_steps += 1
                    if not resolved_reg:
                        entry["resolved"] = "unresolved_register"
                pushes.append(entry)
            elif mnem in ("MOV", "LEA", "ADD", "SUB", "AND", "OR", "XOR", "SHL", "SHR", "INC", "DEC", "TEST", "CMP"):
                pass  # setup instructions between/before pushes -- keep scanning
            else:
                break
            cur = cur.getPrevious()
            steps += 1

        # __cdecl/__stdcall push right-to-left: the LAST push before the call
        # (first in our closest-first list) is the FIRST logical argument.
        arguments = list(reversed(pushes))
        for i, a in enumerate(arguments):
            a["arg_index"] = i

        # Forward scan: what happens to the return value (EAX)?
        result_sink = {"kind": "unresolved_or_discarded"}
        cur = instr.getNext()
        steps = 0
        saw_eax = False
        while cur is not None and steps < lookahead:
            text = str(cur)
            mnem = cur.getMnemonicString().upper()
            if mnem in ("CMP", "TEST") and "EAX" in text or ("AL" in text and mnem in ("CMP", "TEST")):
                if "EAX" in text or ",AL" in text or "AL," in text:
                    saw_eax = True
                    nxt = cur.getNext()
                    if nxt is not None and nxt.getMnemonicString().upper().startswith("J"):
                        result_sink = {
                            "kind": "compare_and_branch",
                            "compare_address": str(cur.getMinAddress()),
                            "compare_text": text,
                            "branch_address": str(nxt.getMinAddress()),
                            "branch_mnemonic": nxt.getMnemonicString(),
                            "branch_target": str(nxt.getOpObjects(0)[0]) if nxt.getNumOperands() > 0 else None,
                        }
                        break
            if mnem == "MOV" and ("EAX" in text or "AL" in text):
                try:
                    src = str(cur.getOpObjects(1)[0]) if cur.getNumOperands() > 1 else None
                except Exception:
                    src = None
                if src in ("EAX", "AL"):
                    try:
                        dst_objs = cur.getOpObjects(0)
                        dst = str(dst_objs[0]) if dst_objs else None
                    except Exception:
                        dst = None
                    result_sink = {
                        "kind": "store_to_address_or_variable",
                        "store_address": str(cur.getMinAddress()),
                        "store_text": text,
                        "destination_operand": dst,
                    }
                    break
            if mnem == "PUSH" and "EAX" in text:
                # EAX pushed as an argument to a subsequent call.
                probe = cur.getNext()
                probe_steps = 0
                while probe is not None and probe_steps < 6:
                    if probe.getMnemonicString().upper() == "CALL":
                        tgt = None
                        try:
                            for r in probe.getReferencesFrom():
                                if r.getReferenceType().isCall():
                                    tgt = str(r.getToAddress())
                                    break
                        except Exception:
                            pass
                        result_sink = {
                            "kind": "used_as_argument_to_call",
                            "push_address": str(cur.getMinAddress()),
                            "call_address": str(probe.getMinAddress()),
                            "call_target": tgt,
                        }
                        break
                    if probe.getMnemonicString().upper() in ("JMP", "RET", "RETN"):
                        break
                    probe = probe.getNext()
                    probe_steps += 1
                if result_sink.get("kind") != "unresolved_or_discarded":
                    break
            if mnem in ("CALL", "JMP", "RET", "RETN") and mnem != "CALL":
                break
            if mnem == "CALL":
                # A later, unrelated call -- EAX likely dead by now.
                break
            cur = cur.getNext()
            steps += 1

        return {
            "call_address": address_str,
            "call_target": call_target,
            "callee_name": callee_name,
            "arguments": arguments,
            "result_sink": result_sink,
            "note": ("Mechanical heuristic (contiguous-backward-PUSH-run + one-level "
                     "register backtrack; forward EAX-use scan) -- not authoritative. "
                     "Confirm against the real decompile before relying on a resolved "
                     "argument or result sink, per this project's own RE discipline."),
        }

    def map_function_by_debug_strings(self, filter_str=None, string_addresses=None, min_hits=1):
        """Locate real vendor functions via self-labeled debug/diagnostic
        strings (e.g. the embedded '@(#) $Id: MODULE.CPP ...' SCCS tags and
        their nearby 'MODULE: some error text' runtime strings found across
        this project's DLLs), and build an address-ordered roadmap of each
        function's branches from the strings alone -- no decompile needed.
        Pass filter_str to search all defined strings for a substring (e.g.
        "QEND" or ":"), or string_addresses for an explicit list of known
        string addresses. Groups get_xrefs_to results by containing function,
        sorts each function's hits by from_address (approximate code order),
        and returns only functions with >= min_hits matching strings."""
        str_map = {}
        if string_addresses:
            for a in string_addresses:
                addr = self.program.getAddressFactory().getAddress(a)
                if addr is None:
                    continue
                dd = self._listing.getDataAt(addr)
                str_map[a] = str(dd.getValue()) if dd else None
        else:
            parsed = json.loads(self.list_strings(0, 5000, filter_str))
            for s in parsed["strings"]:
                str_map[s["address"]] = s["value"]

        functions = {}
        for str_addr, str_val in str_map.items():
            addr = self.program.getAddressFactory().getAddress(str_addr)
            if addr is None:
                continue
            for r in self._ref_manager.getReferencesTo(addr):
                from_addr = r.getFromAddress()
                fn = self._function_manager.getFunctionContaining(from_addr)
                if not fn:
                    continue
                fn_addr = str(fn.getEntryPoint())
                entry = functions.setdefault(fn_addr, {
                    "function_name": self._qname(fn),
                    "hits": [],
                })
                entry["hits"].append({
                    "from_address": str(from_addr),
                    "string_address": str_addr,
                    "string_value": str_val,
                })

        result = []
        for fn_addr, data in functions.items():
            if len(data["hits"]) < min_hits:
                continue
            hits_sorted = sorted(data["hits"], key=lambda h: int(h["from_address"], 16))
            result.append({
                "function_address": fn_addr,
                "function_name": data["function_name"],
                "hit_count": len(hits_sorted),
                "roadmap": hits_sorted,
            })
        result.sort(key=lambda r: -r["hit_count"])
        return json.dumps({
            "functions": result,
            "total_strings_scanned": len(str_map),
            "note": ("Roadmap is derived purely from string xrefs, in address order -- "
                     "a navigation aid, not a substitute for a real decompile of the "
                     "function body."),
        })

    def get_seh_frame_info(self, function_address):
        """Detect the standard MSVC _except_handler3/_except_handler4 SEH
        prologue idiom at a function's entry (the 'push -1; push <handler>;
        push fs:[0]; mov fs:[0],esp' sequence that shows up as
        unaff_FS_OFFSET/local_10/puStack_c clutter in nearly every
        decompiled function in this binary) and reports whether it's
        present plus the handler function's address/name.
        Read-only/informational -- does not modify the function or its
        stack frame layout. An earlier, riskier design that auto-typed the
        3 SEH slots as an EXCEPTION_REGISTRATION struct on every matching
        function to reduce decompile noise was dropped in favor of just
        surfacing the fact plainly -- auto-retyping compiler-inserted stack
        slots across the whole binary unsupervised is a much bigger,
        harder-to-verify change than this project's 'don't invent, verify'
        rules would want done without a human looking at each result."""
        return json.dumps(self._do_get_seh_frame_info(function_address))

    def _do_get_seh_frame_info(self, function_address):
        addr = self.program.getAddressFactory().getAddress(function_address)
        if addr is None:
            return {"error": f"Invalid address: {function_address}"}
        fn = self._function_manager.getFunctionContaining(addr)
        if fn is None:
            return {"error": f"No function at {function_address}"}

        entry = fn.getEntryPoint()
        instrs = []
        cur = self._listing.getInstructionAt(entry)
        steps = 0
        while cur is not None and steps < 12:
            instrs.append(cur)
            cur = cur.getNext()
            steps += 1

        # The handler pushed here is almost always a raw code address WITHIN
        # the same function's own trailing cleanup/unwind block, not a
        # separate registered Function entry point -- requiring
        # getFunctionAt(target) is not None (an earlier version of this
        # check) filters out exactly the real handler address, since
        # getFunctionAt only matches a function's ENTRY point, not an
        # internal label. Confirmed live: CVoice_constructor's real handler
        # push (PUSH 0x1023b8aa) was silently dropped by that check.
        # Fixed: accept any PUSH of a literal scalar that falls within the
        # program's own address range (excludes PUSH -1 / PUSH 0 / small
        # stack constants, which are not address-shaped), without requiring
        # it to resolve to a Function or symbol at all -- best-effort,
        # reported as an address whether or not a name can be attached.
        handler_addr = None
        min_addr = self.program.getMinAddress()
        max_addr = self.program.getMaxAddress()
        for ins in instrs:
            if ins.getMnemonicString().upper() != "PUSH":
                continue
            try:
                scalar = ins.getScalar(0)
            except Exception:
                scalar = None
            if scalar is None:
                continue
            val = int(scalar.getValue()) & 0xFFFFFFFF
            if val in (0, 0xFFFFFFFF):
                continue
            try:
                candidate = self.program.getAddressFactory().getAddress(hex(val))
            except Exception:
                candidate = None
            if (candidate is not None and min_addr.compareTo(candidate) <= 0
                    and candidate.compareTo(max_addr) <= 0):
                handler_addr = str(candidate)
                break

        # The real MSVC SEH-frame-install idiom is TWO MOVs referencing
        # FS:[0] -- a READ ("MOV EAX,FS:[0x0]", fetching the old exception
        # chain head, usually first) and a WRITE ("MOV dword ptr FS:[0x0],
        # ESP", installing the new frame, after the PUSHes) -- there is
        # never a literal "PUSH FS:[...]" instruction in this idiom (an
        # earlier version of this check incorrectly required one, which
        # meant seh_present was ALWAYS False; confirmed live against
        # CVoice_constructor, a genuine, textbook SEH-frame function,
        # returning a false negative before this fix). The WRITE half
        # alone ("FS:[0x0]" together with "ESP" in the same MOV's operand
        # string) is the unambiguous, sufficient signal used here.
        has_fs_write = any(
            ins.getMnemonicString().upper() == "MOV" and "FS:[0x0]" in str(ins) and "ESP" in str(ins)
            for ins in instrs)
        seh_present = bool(has_fs_write)

        handler_fn_name = None
        if handler_addr and seh_present:
            h_addr = self.program.getAddressFactory().getAddress(handler_addr)
            # getFunctionContaining, not getFunctionAt -- the handler
            # address is typically an internal label inside a trailing
            # cleanup block, not itself a function entry point (same fix
            # rationale as the detection change above).
            h_fn = self._function_manager.getFunctionContaining(h_addr) if h_addr else None
            if h_fn:
                handler_fn_name = h_fn.getName()
            else:
                try:
                    for s in self.program.getSymbolTable().getSymbols(h_addr):
                        handler_fn_name = str(s.getName())
                        break
                except Exception:
                    pass

        return {
            "function": fn.getName(),
            "address": function_address,
            "seh_frame_present": seh_present,
            "handler_address": handler_addr if seh_present else None,
            "handler_name": handler_fn_name,
            "note": ("Idiom-matched heuristic over the first 12 instructions from entry -- "
                     "seh_frame_present=true means the standard push-handler/push-fs/mov-fs,esp "
                     "prologue was found, which is why unaff_FS_OFFSET/local_10/puStack_c-style "
                     "slots appear in this function's decompile; they are compiler-inserted SEH "
                     "bookkeeping, not application data, and can generally be ignored when "
                     "reading RE'd logic out of the decompile."),
        }

    _DYNAMIC_LOAD_IMPORT_NAMES = frozenset({
        "GetProcAddress", "LoadLibraryA", "LoadLibraryW",
        "LoadLibraryExA", "LoadLibraryExW",
    })

    def classify_pointer_provenance(self, address=None, function_address=None,
                                     offset=None, max_backtrack=15):
        """Answers the FIRST question worth asking before trying to trace
        which concrete object/DLL a vtable-dispatched call reaches:
        is the pointer feeding that call a compile-time constant (further
        static tracing -- e.g. resolve_vtable -- is worthwhile), or is it
        populated at runtime via GetProcAddress/LoadLibraryA-family calls
        (further static tracing of THIS binary alone cannot resolve it --
        stop and go to the real registry/config data or an oracle capture
        instead)?

        This project lost real time to this exact ambiguity twice
        (TRUTH_LEDGER rows 533-537: `CTA+0x3b390`'s "Letter-To-Sound
        dictionary" object was guessed at twice, both wrong, before
        someone read the actual Wine registry Dictionaries key) --
        this tool mechanizes the check that would have caught it
        immediately: the value written into that field comes from
        `dict_register_provider`, itself fed by a `GetProcAddress` call
        inside `dict_load_providers_from_registry`, which is a dead
        giveaway this is registry-driven, not something worth guessing
        at via more disassembly.

        Two modes:
          - address: a plain global/absolute address (e.g. a vtable
            pointer slot in .data). Uses existing xref infrastructure to
            find every write site.
          - function_address + offset: a struct-relative field (e.g.
            "CTextAnalyzer this+0x3b390") that isn't a fixed global
            address at all -- scans the named function's own
            instructions for stores whose operand contains "+ offset"
            (any base register), since Ghidra's reference manager can't
            track "writes to object+N across all instances" the way it
            tracks writes to a real address.

        For each write site found, classifies the SOURCE of the stored
        value by walking backward up to max_backtrack instructions in
        the same function looking for either an immediate constant load
        (-> "static_constant") or the most recent CALL whose target
        matches a known dynamic-loading import
        (GetProcAddress/LoadLibraryA/W/ExA/ExW -> "runtime_dynamic").
        Anything else is "unknown" (needs a manual look; a common cause
        is a copy from another register/variable that itself needs
        tracing one level further back than max_backtrack allows).

        Returns {write_sites: [{address, instruction, classification,
        evidence}], note}. Best-effort: a heuristic string/backtrack
        scan, not a full data-flow analysis -- "unknown" means
        inconclusive, not "static", so don't read it as a green light to
        keep guessing statically either."""
        import re
        write_sites_addrs = []

        if address:
            addr = self.program.getAddressFactory().getAddress(address)
            if addr is None:
                return json.dumps({"error": f"Invalid address: {address}"})
            for r in self._ref_manager.getReferencesTo(addr):
                write_sites_addrs.append(r.getFromAddress())
        elif function_address is not None and offset is not None:
            fn_addr = self.program.getAddressFactory().getAddress(function_address)
            if fn_addr is None:
                return json.dumps({"error": f"Invalid function_address: {function_address}"})
            fn = self._function_manager.getFunctionContaining(fn_addr)
            if fn is None:
                return json.dumps({"error": f"No function at {function_address}"})
            off = int(offset, 16) if isinstance(offset, str) and offset.lower().startswith("0x") \
                else int(offset)
            needles = [f"+ 0x{off:x}", f"+0x{off:x}"]
            instr_iter = self._listing.getInstructions(fn.getBody(), True)
            while instr_iter.hasNext():
                instr = instr_iter.next()
                mnem = instr.getMnemonicString().upper()
                if mnem not in ("MOV", "LEA"):
                    continue
                try:
                    dest_rep = instr.getDefaultOperandRepresentation(0)
                except Exception:
                    dest_rep = None
                if not dest_rep:
                    continue
                norm = dest_rep.replace("  ", " ")
                matched = any(n in norm for n in needles)
                # offset 0 is rendered as a bare "[REG]" with no "+0x0" at
                # all -- match a simple one-register bracketed destination
                # with no arithmetic inside it (no "+"/"-") as the offset-0
                # case specifically, so the single most common query (an
                # object's own vtable slot at +0x0) doesn't silently miss.
                if off == 0 and not matched and "[" in norm and "]" in norm \
                        and "+" not in norm and "-" not in norm:
                    matched = True
                if matched:
                    write_sites_addrs.append(instr.getMinAddress())
        else:
            return json.dumps({"error": "Provide either 'address' or both "
                                         "'function_address' and 'offset'"})

        results = []
        for site_addr in write_sites_addrs:
            instr = self._listing.getInstructionAt(site_addr)
            if instr is None:
                continue
            try:
                mnem = instr.getMnemonicString().upper()
                src_rep = instr.getDefaultOperandRepresentation(1) \
                    if instr.getNumOperands() > 1 else None
            except Exception:
                mnem, src_rep = "?", None

            classification = "unknown"
            evidence = None

            if src_rep and re.match(r'^(0x)?[0-9a-fA-F]+$', src_rep.strip()):
                classification = "static_constant"
                evidence = f"{mnem} source is immediate constant {src_rep}"
            elif src_rep:
                src_reg = src_rep.strip().split()[0] if src_rep.strip() else None
                cur = instr
                steps = 0
                while cur is not None and steps < max_backtrack:
                    cur = self._listing.getInstructionBefore(cur.getMinAddress())
                    steps += 1
                    if cur is None:
                        break
                    cmnem = cur.getMnemonicString().upper()
                    if cmnem == "CALL":
                        target_fn = None
                        try:
                            flows = cur.getFlows()
                            if flows and len(flows) > 0:
                                target_fn = self._function_manager.getFunctionAt(flows[0])
                        except Exception:
                            pass
                        if target_fn is not None:
                            tname = target_fn.getName()
                            if tname in self._DYNAMIC_LOAD_IMPORT_NAMES:
                                classification = "runtime_dynamic"
                                evidence = (f"value traced back {steps} instr to "
                                            f"CALL {tname} at {cur.getMinAddress()}")
                                break
                            else:
                                classification = "unknown"
                                evidence = (f"value traced back {steps} instr to "
                                            f"CALL {tname} (not a known dynamic-load "
                                            f"import) at {cur.getMinAddress()}")
                                break
                        else:
                            evidence = f"CALL to unresolved target at {cur.getMinAddress()}"
                            break
                    # MOV reg, imm -- treat as static if it's the register we're tracing
                    if cmnem == "MOV":
                        try:
                            cdest = cur.getDefaultOperandRepresentation(0)
                            csrc = cur.getDefaultOperandRepresentation(1) \
                                if cur.getNumOperands() > 1 else None
                        except Exception:
                            cdest, csrc = None, None
                        if cdest and src_reg and cdest.strip() == src_reg and csrc and \
                                re.match(r'^(0x)?[0-9a-fA-F]+$', csrc.strip()):
                            classification = "static_constant"
                            evidence = (f"value traced back {steps} instr to "
                                        f"MOV {cdest}, {csrc} at {cur.getMinAddress()}")
                            break

            results.append({
                "address": str(site_addr),
                "instruction": f"{mnem} {src_rep if src_rep else ''}".strip(),
                "classification": classification,
                "evidence": evidence,
            })

        return json.dumps({
            "write_sites": results,
            "note": ("Heuristic backward-scan, not full data-flow analysis. "
                     "'static_constant' -> worth tracing further with resolve_vtable/"
                     "get_xrefs_from. 'runtime_dynamic' -> this binary's own code "
                     "cannot resolve which concrete DLL/object this is; go to the real "
                     "registry/config data or an oracle capture instead of guessing. "
                     "'unknown' -> inconclusive, not a green light either way."),
        })

    def find_thunk_candidates(self, min_gap_bytes=4, max_gap_bytes=128,
                               max_tail_bytes=6, limit=200):
        """Mechanical scan for undefined vtable-forwarding thunks --
        gaps between defined functions (in executable memory blocks)
        that `analyzeAll()` left as raw, un-disassembled bytes but which
        contain the classic COM-wrapper thunk shape: an indirect CALL
        through a register plus a fixed offset (`FF /2`, i.e. `CALL
        [reg+disp]` or `CALL [reg]`), followed shortly by a RET. This is
        the exact pattern found by hand repeatedly this project
        (ft_sdict.dll 0x1050bf0a/0x1050bf5c, ft_hgrap.dll 5 of its 6
        vtable-forwarding stubs) -- outer-wrapper interface objects whose
        methods are only reached through a vtable, never a direct CALL,
        so Ghidra's control-flow-driven auto-analysis never turns the
        bytes into a Function at all.

        Does NOT use Ghidra's own disassembler (which would commit
        Instruction definitions for every candidate, including false
        positives in what might just be unrelated data bytes) -- instead
        does a lightweight manual ModRM decode of the `FF /2` opcode
        family to find candidate indirect-CALL sites, then checks for a
        C3/C2 RET within max_tail_bytes after it. A gap qualifies only if
        it contains EXACTLY ONE such indirect call (real thunks are
        single-call forwarders; more than one is a sign of unrelated
        code/data, not a thunk).

        Returns candidates: [{address, length_bytes, preceding_function,
        following_function}] -- the neighboring function names are free
        context (a candidate sitting between two `Foo_wrapper_thunkN`
        functions is far more likely a real thunk than an isolated one).

        Best-effort, NOT authoritative: confirm each candidate with
        create_function + decompile_function_by_address before trusting
        or renaming it -- the byte-pattern match alone cannot rule out
        coincidental matches in padding/data regions."""
        candidates = []

        def find_indirect_calls(data):
            hits = []
            i = 0
            n = len(data)
            while i < n - 1:
                if data[i] == 0xFF:
                    modrm = data[i + 1]
                    mod = (modrm >> 6) & 3
                    reg = (modrm >> 3) & 7
                    rm = modrm & 7
                    if reg == 2 and mod != 3:
                        length = 2
                        if mod == 0:
                            if rm == 5:
                                length += 4
                            elif rm == 4:
                                length += 1
                        elif mod == 1:
                            length += 1
                            if rm == 4:
                                length += 1
                        elif mod == 2:
                            length += 4
                            if rm == 4:
                                length += 1
                        hits.append((i, length))
                        i += length
                        continue
                i += 1
            return hits

        try:
            memory = self._program.getMemory()
            blocks = [b for b in memory.getBlocks() if b.isExecute()]

            func_ranges = []
            it = self._function_manager.getFunctions(True)
            while it.hasNext():
                fn = it.next()
                body = fn.getBody()
                func_ranges.append((body.getMinAddress().getOffset(),
                                     body.getMaxAddress().getOffset()))
            func_ranges.sort()

            for block in blocks:
                if len(candidates) >= limit:
                    break
                b_start = block.getStart().getOffset()
                b_end = block.getEnd().getOffset()
                ranges = sorted(r for r in func_ranges if b_start <= r[0] <= b_end)

                gaps = []
                cursor = b_start
                for (fs, fe) in ranges:
                    if fs > cursor:
                        gaps.append((cursor, fs - 1))
                    cursor = max(cursor, fe + 1)
                if cursor <= b_end:
                    gaps.append((cursor, b_end))

                for (gs, ge) in gaps:
                    if len(candidates) >= limit:
                        break
                    gap_len = ge - gs + 1
                    if gap_len < min_gap_bytes or gap_len > max_gap_bytes:
                        continue
                    gs_addr = self.program.getAddressFactory().getAddress(f"0x{gs:x}")
                    try:
                        raw, actual = self._read_raw_bytes(gs_addr, gap_len)
                    except Exception:
                        continue
                    if not raw:
                        continue

                    start_i = 0
                    while start_i < len(raw) and raw[start_i] == 0xCC:
                        start_i += 1
                    end_i = len(raw) - 1
                    while end_i >= start_i and raw[end_i] == 0xCC:
                        end_i -= 1
                    if end_i - start_i + 1 < min_gap_bytes:
                        continue
                    trimmed = raw[start_i:end_i + 1]

                    calls = find_indirect_calls(trimmed)
                    if len(calls) != 1:
                        continue
                    call_off, call_len = calls[0]
                    tail_start = call_off + call_len
                    tail = trimmed[tail_start:tail_start + max_tail_bytes]
                    # Walk the tail looking for the RET, only skipping over
                    # POP r32 (0x58-0x5F) bytes on the way -- this is
                    # stricter than a bare "0xC3 anywhere in the window"
                    # check, which can coincidentally match a C3 byte
                    # embedded inside an unrelated address/data constant
                    # sitting right after the call (observed once in
                    # testing: a MOV-to-absolute-address instruction whose
                    # own operand bytes happened to contain 0xC3).
                    found_ret = False
                    for b in tail:
                        if 0x58 <= b <= 0x5F:
                            continue
                        found_ret = b in (0xC3, 0xC2)
                        break
                    if not found_ret:
                        continue

                    cand_addr = gs + start_i
                    cand_len = end_i - start_i + 1
                    prev_name = None
                    next_name = None
                    for (fs, fe) in ranges:
                        if fe < cand_addr:
                            fn_at = self._function_manager.getFunctionAt(
                                self.program.getAddressFactory().getAddress(f"0x{fs:x}"))
                            prev_name = fn_at.getName() if fn_at else None
                        if fs > cand_addr and next_name is None:
                            fn_at = self._function_manager.getFunctionAt(
                                self.program.getAddressFactory().getAddress(f"0x{fs:x}"))
                            next_name = fn_at.getName() if fn_at else None
                            break
                    candidates.append({
                        "address": f"0x{cand_addr:x}",
                        "length_bytes": cand_len,
                        "preceding_function": prev_name,
                        "following_function": next_name,
                    })
        except Exception as e:
            return json.dumps({"error": f"Scan failed: {str(e)}"})

        return json.dumps({
            "candidates": candidates,
            "total": len(candidates),
            "note": ("Mechanical byte-pattern match for the vtable-forwarding thunk shape "
                     "(indirect CALL through a register+offset, followed shortly by RET) "
                     "in address gaps analyzeAll() left undefined. Best-effort, NOT "
                     "authoritative -- verify each candidate with create_function + "
                     "decompile_function_by_address before relying on or renaming it."),
        })

    def find_hook_point(self, address_str, min_bytes=5):
        """Starting at `address_str`, walk forward through instructions
        until at least `min_bytes` have been covered.  Returns the
        instruction boundaries, total byte count, and safety flags for
        common hook sizes (5-byte jmp+offset, 6-byte jmp+offset+prefix).
        This prevents accidental mid-instruction cuts when installing
        hooks."""
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})
        fn = self._function_manager.getFunctionContaining(addr)
        if fn is None:
            return json.dumps({"error": f"No function at {address_str}"})

        body = fn.getBody()
        try:
            instructions = []
            cumulative = 0
            started = False
            instr_iter = self._listing.getInstructions(body, True)
            while instr_iter.hasNext():
                instr = instr_iter.next()
                ia = instr.getMinAddress()
                if not started:
                    if ia.equals(addr):
                        started = True
                    else:
                        continue
                length = instr.getLength()
                if length <= 0:
                    continue
                cumulative += length
                try:
                    op_count = instr.getNumOperands()
                    ops = []
                    for i in range(op_count):
                        rep = instr.getDefaultOperandRepresentation(i)
                        if rep:
                            ops.append(rep)
                    ops_str = ", ".join(ops)
                except Exception:
                    ops_str = ""
                instructions.append({
                    "address": str(ia),
                    "mnemonic": instr.getMnemonicString(),
                    "operands": ops_str,
                    "length": length,
                    "cumulative": cumulative,
                })
                if cumulative >= min_bytes:
                    break

            if not started:
                return json.dumps({"error": f"Address {address_str} not found in function"})

            return json.dumps({
                "address": address_str,
                "function": fn.getName(),
                "min_bytes": min_bytes,
                "total_bytes": cumulative,
                "safe_for_jmp5": cumulative >= 5,
                "safe_for_jmp6": cumulative >= 6,
                "instructions": instructions,
                "instruction_count": len(instructions),
            })
        except Exception as e:
            return json.dumps({"error": f"find_hook_point failed: {str(e)}"})

    def trace_fpu_stack(self, address_str, start_offset=0, count=20,
                         start_address=None, fpu_only=False):
        """Walk a straight-line sequence of x87 instructions and return the FPU
        register stack state at each step.  Tracks push/pop/modify operations
        symbolically — ST(i) values are represented as short string expressions
        rather than concrete numbers (since most operands are register- or
        memory-relative at analysis time).

        Use *either* start_offset (instruction index within the function) or
        start_address (a hex address to begin tracing from).  If both are
        given, start_address takes precedence.

        When fpu_only=True, non-FPU instructions are still processed for stack
        tracking but excluded from the returned trace, making the output much
        more readable when only stack state matters.

        Returns a list of trace entries, each with:
          - address, instruction, stack_depth
          - st0..st7 string representation (empty string for unused slots)
          - action: "push" / "pop" / "exchg" / "modify" / "noop"
        """
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})

        fn = self._function_manager.getFunctionContaining(addr)
        if fn is None:
            return json.dumps({"error": f"No function at {address_str}"})

        body = fn.getBody()
        all_instrs = []
        instr_iter = self._listing.getInstructions(body, True)
        while instr_iter.hasNext():
            instr = instr_iter.next()
            all_instrs.append(instr)

        # Resolve start_address → offset if provided
        if start_address is not None:
            start_addr_obj = self.program.getAddressFactory().getAddress(start_address)
            if start_addr_obj is None:
                return json.dumps({"error": f"Invalid start_address: {start_address}"})
            resolved_offset = None
            for i, instr in enumerate(all_instrs):
                if instr.getMinAddress().equals(start_addr_obj):
                    resolved_offset = i
                    break
            if resolved_offset is None:
                return json.dumps({
                    "error": f"start_address {start_address} not found in function {fn.getName()}",
                })
            start_offset = resolved_offset

        # Window
        window = all_instrs[start_offset:start_offset + count]
        if not window:
            return json.dumps({
                "function": fn.getName(),
                "trace": [],
                "total": 0,
                "error": "No instructions in range",
            })

        # ── FPU stack tracer ──────────────────────────────────────
        # stack[0] = ST(0), stack[1] = ST(1), …
        stack = []  # list of symbolic strings
        trace = []
        import re as _re

        def _pop():
            if stack:
                return stack.pop(0)
            return "?"

        def _push(val):
            stack.insert(0, val)

        def _peek(n=0):
            if n < len(stack):
                return stack[n]
            return "?"

        def _opnd_str(instr, idx):
            """Return operand idx's default representation, or None if the
            instruction has no such operand. Ghidra's
            getDefaultOperandRepresentation() does NOT throw for an
            out-of-range index on instructions with fewer operands than
            asked for (e.g. bare FXCH/FYL2X/FLD1, which encode 0 explicit
            operands) -- it returns the literal string "<UNSUPPORTED>",
            which must be normalized to None here or it corrupts every
            downstream string-building and _parse_st() check."""
            try:
                if idx >= instr.getNumOperands():
                    return None
                rep = instr.getDefaultOperandRepresentation(idx)
                if rep is None:
                    return None
                rep = str(rep)
                return None if rep == "<UNSUPPORTED>" else rep
            except Exception:
                return None

        def _parse_st(op_str):
            """Extract ST register index from strings like 'ST(2)', 'st(2)',
            'ST2', 'st2', 'ST[2]'.  Returns int or None."""
            if not op_str:
                return None
            m = _re.search(r'[Ss][Tt]\s*[\(\[]?\s*(\d+)\s*[\)\]]?', op_str)
            if m:
                return int(m.group(1))
            return None

        def _is_x87(mnem):
            """True if mnemonic is an x87 FPU instruction."""
            if (mnem.startswith("F") and mnem not in (
                "FWAIT", "FXSAVE", "FXRSTOR", "FXRSTOR64", "FXSAVE64",
                "FENI", "FDISI", "FCLEX", "FINIT", "FNOP",
            )):
                return True
            if mnem in ("FCMOVB", "FCMOVBE", "FCMOVE", "FCMOVNB",
                        "FCMOVNBE", "FCMOVNE", "FCMOVNU", "FCMOVU",
                        "FCOM", "FCOMP", "FCOMPP", "FUCOM", "FUCOMP",
                        "FUCOMPP", "FICOM", "FICOMP",):
                return True
            return False

        for instr in window:
            mnem = instr.getMnemonicString().upper()
            ia = str(instr.getMinAddress())
            entry = {"address": ia}
            action = "noop"

            # Capture instruction text for all instructions (x87 or not)
            try:
                op0 = _opnd_str(instr, 0)
                op1 = _opnd_str(instr, 1)
                ops = ", ".join(filter(None, [op0, op1]))
            except Exception:
                op0 = op1 = None
                ops = ""
            entry["instruction"] = f"{mnem} {ops}".strip()
            entry["stack_depth"] = len(stack)

            if _is_x87(mnem):
                # ── Classify & update ──────────────────────────

                # --- Constants (must come before the generic FLD/FILD
                #     push branch below, which would otherwise catch these
                #     same mnemonics first and push a raw/garbage operand
                #     label instead of a clean constant name) ---
                if mnem in ("FLDZ", "FLD1", "FLDPI", "FLDL2E",
                            "FLDLN2", "FLDL2T", "FLDLG2",):
                    const_map = {
                        "FLDZ": "0.0", "FLD1": "1.0", "FLDPI": "pi",
                        "FLDL2E": "log2(e)", "FLDLN2": "ln(2)",
                        "FLDL2T": "log2(10)", "FLDLG2": "log10(2)",
                    }
                    _push(const_map.get(mnem, mnem))
                    action = "push"

                # --- Integer load (must also come before the generic FLD
                #     branch, which would otherwise shadow it) ---
                elif mnem == "FILD":
                    lbl = f"i({op0})" if op0 else "i(mem)"
                    _push(lbl)
                    action = "push"

                # --- Pushes (loads) ---
                elif mnem in ("FLD", "FLD CW", "FLD ENV",):
                    # FLD st(i) pushes a copy of ST(i)
                    st_idx = _parse_st(op0)
                    if st_idx is not None:
                        val = _peek(st_idx)
                        _push(val)
                        action = "push"
                    else:
                        # FLD mem — symbolic load
                        lbl = op0 if op0 else "mem"
                        _push(lbl)
                        action = "push"

                # --- Stores (pops) ---
                elif mnem in ("FSTP", "FISTP", "FISTTP",):
                    _pop()
                    action = "pop"

                elif mnem == "FST":
                    # Store without pop — value remains in ST(0)
                    action = "noop"

                # --- Exchange ---
                elif mnem == "FXCH":
                    st_idx = _parse_st(op0)
                    if st_idx is None:
                        st_idx = 1  # default: FXCH ST(1)
                    if 0 < st_idx < len(stack):
                        stack[0], stack[st_idx] = stack[st_idx], stack[0]
                        action = "exchg"
                    elif st_idx == 0:
                        action = "noop"

                # --- FCOMP / FCOMPP / FUCOMPP (compare + pop) ---
                # Must come before the generic endswith("P") branch since
                # FCOMPP ends with "P" but is not an arithmetic pop.
                elif mnem == "FCOMPP":
                    _pop()
                    _pop()
                    action = "pop"
                elif mnem == "FCOMP":
                    _pop()
                    action = "pop"
                elif mnem in ("FCOM", "FUCOM", "FUCOMP", "FICOM", "FICOMP"):
                    if mnem in ("FUCOMP", "FICOMP"):
                        _pop()
                        action = "pop"

                # --- Arithmetic with pop (FADDP, FSUBP, FMULP, FDIVP,
                #     FSUBRP, FDIVRP) ---
                elif mnem.endswith("P"):
                    op_sym = {
                        "FADDP": " + ", "FSUBP": " - ", "FMULP": " * ",
                        "FDIVP": " / ", "FSUBRP": " <- ", "FDIVRP": " <- ",
                    }.get(mnem, " op ")
                    st_idx = _parse_st(op0)
                    if st_idx is not None and 0 < st_idx < len(stack):
                        # FADDP ST(2), ST(0): ST(2) = ST(2) + ST(0)
                        stack[st_idx] = f"({_peek(st_idx)}{op_sym}{_peek(0)})"
                    elif len(stack) >= 2:
                        # Default: ST(1) = ST(1) op ST(0)
                        stack[1] = f"({_peek(1)}{op_sym}{_peek(0)})"
                    _pop()  # always pop after arithmetic with P suffix

                    # If we wrote to stack[1] with default, after pop it becomes ST(0)
                    if st_idx is None and len(stack) >= 1:
                        pass  # result already at stack[0] after pop
                    action = "pop"

                # --- Binary ops that combine ST(1)/ST(0) and pop ---
                # (previously miscategorized as simple unary "modify ST(0)"
                # ops, which is wrong: these consume TWO stack slots and
                # leave ONE result behind, exactly like the FADDP-style
                # arithmetic-with-pop ops above.)
                elif mnem == "FYL2X":
                    if len(stack) >= 2:
                        stack[1] = f"({_peek(1)} * log2({_peek(0)}))"
                    _pop()
                    action = "pop"
                elif mnem == "FYL2XP1":
                    if len(stack) >= 2:
                        stack[1] = f"({_peek(1)} * log2({_peek(0)}+1.0))"
                    _pop()
                    action = "pop"
                elif mnem == "FPATAN":
                    if len(stack) >= 2:
                        stack[1] = f"atan2({_peek(1)}, {_peek(0)})"
                    _pop()
                    action = "pop"

                # --- Ops that modify ST(0) then push an extra result ---
                # (also previously miscategorized as simple unary: FPTAN
                # replaces ST(0) with tan(ST(0)) then pushes 1.0; FSINCOS
                # replaces ST(0) with sin(ST(0)) then pushes cos(original)
                # as the new ST(0), so the net effect is stack growth by 1.)
                elif mnem == "FPTAN":
                    if stack:
                        stack[0] = f"tan({_peek(0)})"
                        _push("1.0")
                        action = "push"
                elif mnem == "FSINCOS":
                    if stack:
                        orig = _peek(0)
                        stack[0] = f"sin({orig})"
                        _push(f"cos({orig})")
                        action = "push"

                # --- Unary ops modifying ST(0) in place, no push/pop ---
                elif mnem in ("FCHS", "FABS", "FSQRT", "FRNDINT",
                              "F2XM1", "FSIN", "FCOS",):
                    if stack:
                        stack[0] = f"{mnem}({_peek(0)})"
                        action = "modify"

                # --- Binary ops (no pop) ---
                elif mnem in ("FADD", "FSUB", "FMUL", "FDIV", "FSUBR", "FDIVR",
                              "FIADD", "FISUB", "FIMUL", "FIDIV",):
                    op_sym = {
                        "FADD": " + ", "FSUB": " - ", "FMUL": " * ",
                        "FDIV": " / ", "FSUBR": " <- ", "FDIVR": " <- ",
                        "FIADD": " + ", "FISUB": " - ",
                        "FIMUL": " * ", "FIDIV": " / ",
                    }.get(mnem, " op ")
                    dst = _parse_st(op0)
                    src = _parse_st(op1) if op1 else None

                    if dst is not None and src is not None:
                        # FSUB ST(0), ST(2): ST(0) = ST(0) - ST(2)
                        if dst < len(stack) and src < len(stack):
                            stack[dst] = f"({_peek(dst)}{op_sym}{_peek(src)})"
                            action = "modify"
                    elif dst is not None:
                        # FSUB ST(2): ST(2) = ST(2) - ST(0)
                        if dst < len(stack):
                            stack[dst] = f"({_peek(dst)}{op_sym}{_peek(0)})"
                            action = "modify"
                    elif op0 not in (None, "", "?") and _parse_st(op0) is None:
                        # Memory-form: FMUL dword ptr [mem] → ST(0) *= mem
                        if stack:
                            stack[0] = f"({_peek(0)}{op_sym}{op0})"
                            action = "modify"
                    elif len(stack) >= 2:
                        # Default FSUB (no operands): ST(1) = ST(1) - ST(0)
                        stack[1] = f"({_peek(1)}{op_sym}{_peek(0)})"
                        action = "modify"

                # --- Conditional moves (no stack change) ---
                elif mnem in ("FCMOVB", "FCMOVBE", "FCMOVE", "FCMOVNB",
                              "FCMOVNBE", "FCMOVNE", "FCMOVNU", "FCMOVU",):
                    action = "noop"

                # --- Transcendental ops ---
                elif mnem in ("FSCALE", "FXTRACT", "FPREM", "FPREM1"):
                    if stack:
                        stack[0] = f"{mnem}({_peek(0)})"
                        action = "modify"

                # --- Load CW/ENV (non-stack) ---
                elif mnem in ("FLDCW", "FLDENV", "FRSTOR", "FSAVE", "FNSAVE"):
                    action = "noop"

            # fallthrough: non-x87 instructions are already captured with "noop"

            # Emit current stack state
            for i in range(8):
                entry[f"st{i}"] = _peek(i) if i < len(stack) else ""
            entry["action"] = action
            if fpu_only and action == "noop" and entry.get("instruction", ""):
                # Only filter out non-x87 noop entries (x87 noops like FST
                # have action == "noop" but are x87 instructions — keep those).
                mnem = instr.getMnemonicString().upper()
                is_x87 = (mnem.startswith("F") and mnem not in (
                    "FWAIT", "FXSAVE", "FXRSTOR", "FXRSTOR64", "FXSAVE64",
                    "FENI", "FDISI", "FCLEX", "FINIT", "FNOP",
                )) or mnem in ("FCMOVB", "FCMOVBE", "FCMOVE", "FCMOVNB",
                               "FCMOVNBE", "FCMOVNE", "FCMOVNU", "FCMOVU",
                               "FCOM", "FCOMP", "FCOMPP", "FUCOM", "FUCOMP",
                               "FUCOMPP", "FICOM", "FICOMP",)
                if not is_x87:
                    continue
            trace.append(entry)

        result = {
            "function": fn.getName(),
            "entry": str(fn.getEntryPoint()),
            "start_offset": start_offset,
            "count": len(trace),
            "trace": trace,
        }
        if start_address is not None:
            result["start_address"] = start_address
        return json.dumps(result)

    # ── Write operations ──────────────────────────────────────────

    def _with_transaction(self, description, fn):
        """Execute fn inside a Ghidra transaction. fn() is a callable returning
        a JSON string. Auto-saves every _AUTO_SAVE_INTERVAL successful writes
        (hardcoded — see class docstring comment) so work isn't silently lost
        if the server restarts before anyone thinks to call save()."""
        tx_id = self._program.startTransaction(description)
        try:
            result = fn()
            # Most endpoint validation failures are represented as a JSON error
            # rather than a Python exception.  They must be a real rollback:
            # committing them both obscures the audit trail and used to advance
            # the auto-save counter despite no intended write taking place.
            try:
                failed = isinstance(result, str) and bool(json.loads(result).get("error"))
            except (TypeError, ValueError):
                failed = False
            if failed:
                self._program.endTransaction(tx_id, False)
                return result
            self._program.endTransaction(tx_id, True)
        except Exception:
            try:
                self._program.endTransaction(tx_id, False)
            except Exception:
                pass
            raise

        self._write_count += 1
        if self._write_count % self._AUTO_SAVE_INTERVAL == 0:
            try:
                self._do_save()
                logger.info("Auto-saved after %d write transactions", self._write_count)
            except Exception:
                logger.exception("Auto-save failed after %d writes", self._write_count)
        return result

    def _do_save(self):
        ConsoleTaskMonitor = jpype.JClass('ghidra.util.task.ConsoleTaskMonitor')
        mon = ConsoleTaskMonitor()
        df = self._program.getDomainFile()
        df.save(mon)

    def save(self):
        """Save the current program to disk."""
        self._do_save()
        return json.dumps({
            "status": "ok",
            "program": self._program.getName(),
        })

    def analyze(self):
        """Run Ghidra's full auto-analysis pipeline on the current program
        (disassembly, function ID, stack analysis, data references, calling
        conventions, etc.) via FlatProgramAPI.analyzeAll — the same call
        Ghidra's own "Analyze" button triggers."""
        return self._with_transaction("analyze", self._do_analyze)

    def _do_analyze(self):
        func_mgr = self._function_manager
        pre_count = func_mgr.getFunctionCount()
        self._flat.analyzeAll(self._program)
        cnt = func_mgr.getFunctionCount()
        return json.dumps({
            "status": "ok",
            "program": self._program.getName(),
            "functions": cnt,
            "created": cnt - pre_count,
        })

    def rename_function_by_address(self, address_str, new_name):
        """Rename a function at the given hex address. new_name with "::"
        (e.g. "CFoo::method") attaches/creates a real Ghidra namespace. A
        BARE new_name changes only the leaf symbol and preserves its current
        namespace, which is the safe and conventional operation for an
        already-classified method. Use ``GLOBAL::name`` to explicitly move a
        function back to global scope."""
        return self._with_transaction("rename_function", lambda: self._do_rename_function(address_str, new_name))

    def _do_rename_function(self, address_str, new_name):
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})
        fn = self._function_manager.getFunctionContaining(addr)
        if fn is None:
            return json.dumps({"error": f"No function at {address_str}"})
        old_name = fn.getName()

        # "ClassName::method" previously only set the raw symbol text -- the
        # colons were just characters, and fn.getParentNamespace() stayed
        # Global, so list_classes/list_namespaces (which correctly use the
        # real Symbol.getParentNamespace() hierarchy) never saw these
        # "classes" at all. Split on "::" and attach a real Ghidra namespace
        # (a GhidraClass where possible) so renames match this project's own
        # AGENTS.md Rule 9/10 ("Ghidra gets the same naming... class scope
        # provides the prefix"). See docs/GHIDRA_MCP_NAMESPACE_RENAME_GAP_2026-07-11.md.
        namespace_created = []
        if new_name.startswith("GLOBAL::"):
            method_name = new_name[len("GLOBAL::"):]
            if not method_name or "::" in method_name:
                return json.dumps({"error": f"Invalid global function name: {new_name}"})
            fn.getSymbol().setNamespace(self.program.getGlobalNamespace())
            fn.setName(method_name, SourceType.USER_DEFINED)
        elif "::" in new_name:
            parts = [p for p in new_name.split("::") if p]
            if len(parts) < 2:
                return json.dumps({"error": f"Invalid namespaced name: {new_name}"})
            method_name = parts[-1]
            sym_table = self.program.getSymbolTable()
            parent = self.program.getGlobalNamespace()
            for part in parts[:-1]:
                existing = sym_table.getNamespace(part, parent)
                if existing is not None:
                    parent = existing
                    continue
                try:
                    parent = sym_table.createClass(parent, part, SourceType.USER_DEFINED)
                except Exception:
                    # Name collides with a non-class namespace (or createClass
                    # otherwise refused it) -- fall back to a plain namespace
                    # rather than hard-failing the rename.
                    parent = sym_table.createNameSpace(parent, part, SourceType.USER_DEFINED)
                namespace_created.append(part)
            fn.getSymbol().setNamespace(parent)
            fn.setName(method_name, SourceType.USER_DEFINED)
        else:
            # Renaming a method is by far the common case during structural
            # RE.  Scope must remain intact: otherwise a harmless leaf-name
            # correction detaches it from its GhidraClass and degrades its
            # inferred ``this`` type back to void*.  Truly free functions are
            # already global; intentional demotion is spelled GLOBAL::name.
            fn.setName(new_name, SourceType.USER_DEFINED)

        return json.dumps({
            "status": "ok",
            "old_name": old_name,
            "new_name": new_name,
            "namespace_created": namespace_created,
            "address": address_str,
        })

    def rename_data(self, address_str, new_name):
        """Rename a data label at the given address."""
        return self._with_transaction("rename_data", lambda: self._do_rename_data(address_str, new_name))

    def _do_rename_data(self, address_str, new_name):
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})
        sym_table = self.program.getSymbolTable()
        symbols = list(sym_table.getSymbols(addr))
        if not symbols:
            return json.dumps({"error": f"No symbol at {address_str}"})
        old_name = symbols[0].getName()
        symbols[0].setName(new_name, SourceType.USER_DEFINED)
        return json.dumps({
            "status": "ok",
            "old_name": old_name,
            "new_name": new_name,
            "address": address_str,
        })

    def set_decompiler_comment(self, address_str, comment_text, comment_type="eol"):
        """Set a comment visible in the decompiler pseudocode at the given
        address.

        FIXED (2026-08-20): this previously had NO comment_type parameter
        at all -- it hardcoded CodeUnit.EOL_COMMENT unconditionally, no
        matter what the caller believed they were setting. REAL INCIDENT
        (this project, Creatures 1 Science Kit RE): a bridge client tool
        had ALREADY been calling this with an explicit comment_type
        argument (e.g. "plate") for an entire session, believing it was
        writing distinct plate vs eol comments -- the extra parameter was
        silently tolerated (not rejected) by the schema layer and simply
        discarded, so every one of those calls landed in EOL instead,
        while the OLD text sat untouched in the actual plate comment. Two
        real, confirmed consequences: (1) a stale historical plate
        comment describing an "unknown calling convention" ABI problem
        kept tripping the project's own text-based ABI-review-signal
        regex scanner (tools/export_c1_kits_ghidra.py's
        abi_review_reasons()) even after the underlying calling
        convention was genuinely fixed via set_full_prototype, because
        that scanner reads the PLATE comment among other text and the
        real fix never reached it; (2) a separately-narrated
        investigation writeup (COwnerSheet::ReconnectDdeConversation,
        Owners_Kit) that was believed to have both an updated plate AND
        an updated eol comment in fact only ever updated eol -- the
        project's semantic-status-v1.json record of that investigation's
        conclusion is unaffected (it's a separate durable file, not read
        from this comment), but the live Ghidra plate comment itself
        needs re-applying with comment_type='plate' now that this
        actually works.

        Args:
            address_str: hex address of (or inside) the target function
            comment_text: the comment text to set
            comment_type: "eol" (default, preserves prior behavior for
                any existing caller not passing this), "plate", "pre", or
                "post". Matches Ghidra's CodeUnit.{EOL,PLATE,PRE,POST}_COMMENT
                constants.
        """
        return self._with_transaction("set_comment",
            lambda: self._do_set_decompiler_comment(address_str, comment_text, comment_type))

    def _do_set_decompiler_comment(self, address_str, comment_text, comment_type="eol"):
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})
        type_map = {
            "eol": CodeUnit.EOL_COMMENT,
            "plate": CodeUnit.PLATE_COMMENT,
            "pre": CodeUnit.PRE_COMMENT,
            "post": CodeUnit.POST_COMMENT,
        }
        cu_type = type_map.get(str(comment_type).lower())
        if cu_type is None:
            return json.dumps({
                "error": f"Invalid comment_type {comment_type!r} -- must be one of: {', '.join(type_map.keys())}",
            })
        self._listing.setComment(addr, cu_type, comment_text)
        return json.dumps({"status": "ok", "address": address_str, "comment_type": comment_type})

    def set_disassembly_comment(self, address_str, comment_text, comment_type="pre"):
        """Set a comment in the disassembly listing at the given address."""
        return self._with_transaction("set_comment", lambda: self._do_set_disassembly_comment(address_str, comment_text, comment_type))

    def _do_set_disassembly_comment(self, address_str, comment_text, comment_type="pre"):
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})
        if comment_type == "pre":
            ct = CodeUnit.PRE_COMMENT
        elif comment_type == "post":
            ct = CodeUnit.POST_COMMENT
        elif comment_type == "plate":
            ct = CodeUnit.PLATE_COMMENT
        else:
            ct = CodeUnit.EOL_COMMENT
        self._listing.setComment(addr, ct, comment_text)
        return json.dumps({"status": "ok", "address": address_str})

    def rename_variable_by_name(self, function_name, old_name, new_name):
        """Rename a local variable within a named function. Resolves name via linear scan."""
        fn = self._find_function_by_name(function_name)
        if fn is None:
            return json.dumps({"error": f"Function '{function_name}' not found"})
        return self.rename_variable_by_address(str(fn.getEntryPoint()), old_name, new_name)

    def rename_variable_by_address(self, function_address, old_name, new_name):
        """Rename a local variable within a function identified by address."""
        return self._with_transaction("rename_variable", lambda: self._do_rename_variable_by_address(function_address, old_name, new_name))

    def _do_rename_variable_by_address(self, function_address, old_name, new_name):
        addr = self.program.getAddressFactory().getAddress(function_address)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {function_address}"})
        fn = self._function_manager.getFunctionContaining(addr)
        if fn is None:
            return json.dumps({"error": f"No function at {function_address}"})

        # FIXED (2026-08-23, Creatures 1 RE): the original implementation only
        # walked fn.getAllVariables() -- the low-level Listing API, which
        # enumerates database-backed Variable objects only (real stack
        # variables/parameters). It silently fails to find register-allocated
        # decompiler-only locals (the uVarNN/pCVarNN/CVarNN temporaries that
        # dominate any function's SSA output), because those never exist as
        # Variable objects at all -- they only appear as HighSymbol entries
        # once the function is decompiled. Confirmed live during this session:
        # every such rename attempt failed identically with "not found",
        # while _do_set_variable_type's HighFunction/HighSymbol-based approach
        # (same class of variable) works fine one call later in this same
        # file. This mirrors the exact bug class already fixed for
        # set_local_variable_type -- rename_variable just never got the same
        # fix. Ghidra's own decompiler-window GUI renames these register
        # temporaries successfully via this exact mechanism (right-click ->
        # Rename Variable creates a real, persisted dynamic-storage Symbol
        # for them on demand), so this is a real, supported capability that
        # was simply never wired up here.
        #
        # Fix: decompile to get the HighFunction, search
        # getLocalSymbolMap().getSymbols() (which enumerates EVERY
        # decompiler-tracked local, stack-backed or register-based) for the
        # name, then commit via HighFunctionDBUtil.updateDBVariable -- the
        # same real, verified-effective mechanism _do_set_variable_type and
        # set_this_type already use. Falls back to the original low-level
        # Variable rename for any old_name that still resolves there (keeps
        # this endpoint's behavior on already-working cases unchanged).
        for v in fn.getAllVariables():
            if v.getName() == old_name:
                v.setName(new_name, SourceType.USER_DEFINED)
                return json.dumps({
                    "status": "ok",
                    "function": fn.getName(),
                    "function_address": function_address,
                    "old_name": old_name,
                    "new_name": new_name,
                })

        # FIXED (2026-08-24, Creatures 1 RE, Macro::ExecuteInterpreter): this call used
        # timeoutSecs=60 until this fix, while decompile_function (the endpoint every
        # caller uses to READ a decompile and decide what to rename) uses timeoutSecs=0.
        # For an ordinary function that's harmless. For one flagged by Ghidra's own
        # "Type propagation algorithm not settling" warning -- i.e. one whose internal
        # type-inference fixed-point iteration genuinely does not converge -- the two
        # timeouts let the native decompile process run for different amounts of work
        # before finalizing, which can produce a DIFFERENT HighSymbol merge/numbering
        # for otherwise-identical decompiler-only locals (confirmed live: two
        # consecutive rename_variable_by_address calls, each preceded by a fresh
        # decompile_function_by_address confirming the target name's role moments
        # beforehand, both silently renamed the WRONG variable -- an unrelated
        # abs()-via-sign-extension idiom recurring elsewhere in the function, not the
        # intended one -- while two consecutive decompile_function_by_address calls
        # with zero changes between them were byte-for-byte identical). Root cause
        # isolated to this timeout mismatch, not general decompiler non-determinism.
        # Aligned every decompileFunction() call in this file to timeoutSecs=0 to match
        # decompile_function's already-proven-safe behavior (this project has called it
        # thousands of times across huge functions with zero hangs). Accepts the same
        # theoretical unbounded-wait risk decompile_function already carries, in
        # exchange for a real, previously-undetected wrong-variable-renamed bug across
        # every mutation tool that does its own internal decompile (rename_variable_by_
        # address, set_variable_type, retype_variable_at, propose_struct_fields, the ECX
        # thiscall-materialization helpers, batch_decompile, analyze_dataflow).
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor
        HighFunctionDBUtil = jpype.JClass('ghidra.program.model.pcode.HighFunctionDBUtil')

        decomp = DecompInterface()
        decomp.openProgram(self.program)
        try:
            res = decomp.decompileFunction(fn, 0, ConsoleTaskMonitor())
            if not res or not res.decompileCompleted():
                return json.dumps({"error": f"Variable '{old_name}' not found in function at {function_address} (and decompilation failed while checking for a register-allocated match)"})
            high_function = res.getHighFunction()
            if high_function is None:
                return json.dumps({"error": f"Variable '{old_name}' not found in function at {function_address} (and no high function was available while checking for a register-allocated match)"})

            target_symbol = None
            sym_iter = high_function.getLocalSymbolMap().getSymbols()
            while sym_iter.hasNext():
                sym = sym_iter.next()
                if sym.getName() == old_name:
                    target_symbol = sym
                    break
            if target_symbol is None:
                return json.dumps({"error": f"Variable '{old_name}' not found in function at {function_address} (checked both database-backed variables and decompiler-tracked locals, including register-allocated temporaries)"})

            HighFunctionDBUtil.updateDBVariable(
                target_symbol, new_name, target_symbol.getDataType(), SourceType.USER_DEFINED)
        finally:
            decomp.dispose()

        return json.dumps({
            "status": "ok",
            "function": fn.getName(),
            "function_address": function_address,
            "old_name": old_name,
            "new_name": new_name,
            "via": "high_symbol",
            "note": "Renamed via the decompiler's HighSymbol model (register-allocated or otherwise decompiler-only local) rather than a database-backed Variable.",
        })

    def uncommit_variable(self, function_address, variable_name):
        """Remove a database-committed local Variable, restoring it to a fully
        dynamic (decompiler-inferred) HighSymbol on the next decompile."""
        return self._with_transaction("uncommit_variable", lambda: self._do_uncommit_variable(function_address, variable_name))

    def _do_uncommit_variable(self, function_address, variable_name):
        # ROOT-CAUSE FIX (2026-08-23, Creatures 1 RE): repairs the class of
        # decompiler-fragility regression first confirmed on
        # RecomputeBodyPartLayout and CInstinct::RunDreamStep -- renaming a
        # register-allocated/decompiler-only local via
        # HighFunctionDBUtil.updateDBVariable (the mechanism
        # rename_variable_by_address's and set_local_variable_type's
        # HighSymbol fallback paths both use) does not just relabel it: it
        # PERMANENTLY COMMITS that HighSymbol as a real database-backed
        # Variable with FIXED VariableStorage. Before that commit, the
        # decompiler's SSA/Varnode-merge analysis is free to unify all uses of
        # a given storage location (register or stack slot) across the whole
        # function into one HighVariable, even when the compiler legitimately
        # reused that storage for several logically distinct purposes across
        # different loops/lifetimes -- exactly the "genuinely multi-purpose,
        # don't rename" pattern this project has been avoiding empirically all
        # session. Forcing one specific lifetime's storage to a committed
        # symbol competes with that automatic merge on every later decompile:
        # the portion of the function NOT covered by the committed variable's
        # official liveness range can get orphaned into raw, untyped pcode
        # instead of the struct-typed field access it used to show. This is
        # why simply renaming the symbol BACK to its old name does not fix it
        # (confirmed empirically on RunDreamStep) -- the damage is the
        # storage commit, not the label. The real fix is to remove the
        # committed Variable entirely via Function.removeVariable(), which
        # un-commits it and restores fully automatic/dynamic analysis for
        # that storage on the next decompile.
        addr = self.program.getAddressFactory().getAddress(function_address)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {function_address}"})
        fn = self._function_manager.getFunctionContaining(addr)
        if fn is None:
            return json.dumps({"error": f"No function at {function_address}"})

        target_var = None
        for v in fn.getAllVariables():
            if v.getName() == variable_name:
                target_var = v
                break
        if target_var is None:
            return json.dumps({"error": f"'{variable_name}' is not a committed database Variable in function at {function_address} -- either it was never committed (still a fully dynamic HighSymbol, nothing to uncommit), or the name doesn't match any current local/parameter. Check via list_committed_variables or a fresh decompile for its current name."})

        storage_desc = str(target_var.getVariableStorage())
        fn.removeVariable(target_var)

        return json.dumps({
            "status": "ok",
            "function": fn.getName(),
            "function_address": function_address,
            "removed_variable": variable_name,
            "former_storage": storage_desc,
            "note": "Committed Variable removed. Redecompile to confirm the decompiler's automatic Varnode-merge analysis recovers the original (pre-commit) type propagation for this storage.",
        })

    def list_committed_variables(self, function_address):
        """Diagnostic: list every database-committed Variable (stack- or
        register-backed) for a function -- the exact set
        rename_variable_by_address's low-level fallback and uncommit_variable
        both search. Useful for confirming whether a given decompiler-only
        local has actually been committed (and is therefore fixable via
        uncommit_variable) versus still being fully dynamic."""
        addr = self.program.getAddressFactory().getAddress(function_address)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {function_address}"})
        fn = self._function_manager.getFunctionContaining(addr)
        if fn is None:
            return json.dumps({"error": f"No function at {function_address}"})

        variables = []
        for v in fn.getAllVariables():
            variables.append({
                "name": v.getName(),
                "type": str(v.getDataType()),
                "storage": str(v.getVariableStorage()),
            })
        return json.dumps({
            "function": fn.getName(),
            "function_address": function_address,
            "committed_variables": variables,
            "total": len(variables),
        })

    def set_function_prototype(self, function_address, prototype):
        """Set a function's signature/prototype."""
        return self._with_transaction("set_prototype", lambda: self._do_set_prototype(function_address, prototype))

    def _do_set_prototype(self, function_address, prototype):
        addr = self.program.getAddressFactory().getAddress(function_address)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {function_address}"})
        fn = self._function_manager.getFunctionContaining(addr)
        if fn is None:
            return json.dumps({"error": f"No function at {function_address}"})
        # Keep a human-readable record of what was requested, same as upstream
        # GhidraMCPPlugin.java's addPrototypeComment (in addition to, not instead
        # of, actually applying the signature below).
        self._listing.setComment(addr, CodeUnit.PLATE_COMMENT, prototype)

        FunctionSignatureParser = jpype.JClass('ghidra.app.util.parser.FunctionSignatureParser')
        ApplyFunctionSignatureCmd = jpype.JClass('ghidra.app.cmd.function.ApplyFunctionSignatureCmd')
        from ghidra.util.task import ConsoleTaskMonitor

        try:
            parser = FunctionSignatureParser(self._program.getDataTypeManager(), None)
            sig = parser.parse(None, prototype)
        except Exception as e:
            return json.dumps({"error": f"Failed to parse prototype '{prototype}': {e}"})
        if sig is None:
            return json.dumps({"error": f"Failed to parse prototype: {prototype}"})

        cmd = ApplyFunctionSignatureCmd(addr, sig, SourceType.USER_DEFINED)
        applied = cmd.applyTo(self._program, ConsoleTaskMonitor())
        if not applied:
            return json.dumps({"error": f"Failed to apply signature: {cmd.getStatusMsg()}"})

        return json.dumps({
            "status": "ok",
            "function": fn.getName(),
            "prototype": prototype,
        })

    def set_full_prototype(self, function_address, calling_convention, return_type, parameters):
        """Set a function's COMPLETE prototype (calling convention, return
        type, and full parameter list) via Function.updateFunction() on the
        listing-level Function object -- the same real, verified-effective
        mechanism set_this_type/set_parameter already use -- instead of
        set_function_prototype's ApplyFunctionSignatureCmd/
        FunctionSignatureParser path.

        ADDED (2026-08-20) after that path was found to have TWO real,
        separate bugs on this project (Creatures 1 Science Kit RE):

        1. FunctionSignatureParser's grammar has no concept of a calling
           convention keyword in the prototype string at all. Any attempt
           to write one there (e.g. "int __thiscall Foo(...)") fails
           immediately with "Can't resolve return type: int __thiscall" --
           the parser tries to resolve the ENTIRE "int __thiscall" run as
           one return-type token, since it has no grammar rule to
           recognize '__thiscall' as a separate keyword and split it off.
           There is no working way to set calling convention through
           set_function_prototype's text-based path at all.

        2. FunctionSignatureParser's own type resolution is weaker than
           _resolve_type_by_name (the resolver set_this_type/set_parameter
           already use successfully): it does not reliably find a custom
           project structure/class pointer type at all (e.g.
           "CScannerPage *" failed with "Can't resolve datatype:
           CScannerPage *" even though that exact type resolves fine via
           _resolve_type_by_name for set_this_type on the same program).

        Both bugs surfaced together on a REAL case: after delete_function +
        create_function reset CScienceSheet::HandleControlCommand to a
        fresh, signature-not-yet-locked state (getParameterCount()==0,
        even though the decompiler still SHOWS inferred parameters --
        those are decompiler-only, not real Parameter objects, until
        something calls updateFunction()), there was no working tool left
        to establish its real 3-argument __thiscall signature at all:
        set_this_type/set_parameter both require existing parameters to
        retype (they modify, not create), and set_function_prototype
        failed on both bugs above. This tool exists to close that gap.

        Args:
            function_address: hex address of (or inside) the target function
            calling_convention: e.g. "__thiscall", "__cdecl", "__stdcall",
                "__fastcall", or "unknown" to leave it as Ghidra's default/
                unspecified convention (matches what getCallingConventionName()
                would report). Must be a convention name the program's
                compiler spec actually declares -- Ghidra will reject an
                unrecognized one and this reports that error rather than
                silently ignoring it.
            return_type: e.g. "BOOL", "void", "int", "MyStruct *" -- resolved
                via the SAME _resolve_type_by_name used for parameter types
                and set_this_type, so custom project types work here exactly
                as reliably as they do there (unlike set_function_prototype).
            parameters: a JSON array string of {"name": ..., "type": ...}
                objects, in order, e.g.
                '[{"name": "this", "type": "CScienceSheet *"},
                  {"name": "control_command", "type": "CScienceControlCommand *"},
                  {"name": "unused_padding", "type": "undefined4"}]'
                For a __thiscall function, list 'this' explicitly as the
                first entry (this tool does not auto-insert it) -- storage
                is recomputed from the calling convention via
                DYNAMIC_STORAGE_ALL_PARAMS, so an explicit 'this' entry
                still ends up in ECX as it should.

        Re-decompiles afterward like set_this_type and reports
        decompile_shows_field_access (checked, not assumed) for the FIRST
        parameter with a checkable struct/pointer-to-struct type, scoped to
        that parameter's own name -- read that field, don't trust a bare
        "status: ok" alone."""
        return self._with_transaction("set_full_prototype",
            lambda: self._do_set_full_prototype(function_address, calling_convention,
                                                  return_type, parameters))

    def _do_set_full_prototype(self, function_address, calling_convention, return_type, parameters):
        addr = self.program.getAddressFactory().getAddress(function_address)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {function_address}"})
        fn = self._function_manager.getFunctionContaining(addr)
        if fn is None:
            return json.dumps({"error": f"No function at {function_address}"})

        try:
            param_specs = json.loads(parameters) if isinstance(parameters, str) else parameters
            if not isinstance(param_specs, list):
                raise ValueError("parameters must be a JSON array")
        except Exception as e:
            return json.dumps({"error": f"Failed to parse parameters JSON: {e}"})

        dtm = self._program.getDataTypeManager()

        ret_dt = self._resolve_type_by_name(dtm, return_type)
        if ret_dt is None:
            return json.dumps({"error": f"Cannot resolve return type: {return_type}"})

        ParameterImpl = jpype.JClass('ghidra.program.model.listing.ParameterImpl')
        ReturnParameterImpl = jpype.JClass('ghidra.program.model.listing.ReturnParameterImpl')
        ArrayList = jpype.JClass('java.util.ArrayList')
        FunctionUpdateType = jpype.JClass('ghidra.program.model.listing.Function$FunctionUpdateType')

        new_params = ArrayList()
        resolved_param_summary = []
        for i, spec in enumerate(param_specs):
            if not isinstance(spec, dict) or "name" not in spec or "type" not in spec:
                return json.dumps({
                    "error": f"parameters[{i}] must be an object with 'name' and 'type' keys, got: {spec!r}",
                })
            p_name = str(spec["name"])
            p_type = str(spec["type"])
            p_dt = self._resolve_type_by_name(dtm, p_type)
            if p_dt is None:
                return json.dumps({"error": f"Cannot resolve type for parameter '{p_name}' (index {i}): {p_type}"})
            try:
                new_params.add(ParameterImpl(p_name, p_dt, self._program, SourceType.USER_DEFINED))
            except Exception as e:
                return json.dumps({"error": f"Failed to build parameter '{p_name}' (index {i}, type {p_type}): {e}"})
            resolved_param_summary.append({"index": i, "name": p_name, "type": p_type})

        try:
            return_var = ReturnParameterImpl(ret_dt, self._program)
        except Exception as e:
            return json.dumps({"error": f"Failed to build return type {return_type}: {e}"})

        try:
            fn.updateFunction(calling_convention, return_var, new_params,
                               FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, True,
                               SourceType.USER_DEFINED)
        except Exception as e:
            return json.dumps({"error": f"updateFunction failed: {e}"})

        # Self-verify like set_this_type does: don't trust a bare "status:
        # ok" for whether a struct/pointer-to-struct parameter's fields are
        # actually visible in the re-decompile. Check the first parameter
        # with a checkable type, scoped to its own name.
        verified, sample, checked_param = None, None, None
        for spec in resolved_param_summary:
            p_dt = self._resolve_type_by_name(dtm, spec["type"])
            if p_dt is None:
                continue
            v, s = self._verify_field_access_resolved(fn, p_dt, variable_name=spec["name"])
            if v is not None:
                verified, sample, checked_param = v, s, spec["name"]
                break

        return json.dumps({
            "status": "ok",
            "function": fn.getName(),
            "address": function_address,
            "calling_convention": calling_convention,
            "return_type": return_type,
            "parameters": resolved_param_summary,
            "decompile_shows_field_access": verified,
            "decompile_shows_field_access_checked_param": checked_param,
            "sample_line": sample,
            "note": ("decompile_shows_field_access is null if no parameter had a checkable "
                     "named-struct/pointer-to-struct type, false if the first checkable one's "
                     "own field names never appear as literal '{param}->field' access in the "
                     "re-decompile, true (with sample_line) if real field access was confirmed "
                     "for that specific parameter name."),
        })

    def set_local_variable_type(self, function_address, variable_name, new_type):
        """Set the type of a local variable within a function."""
        return self._with_transaction("set_variable_type", lambda: self._do_set_variable_type(function_address, variable_name, new_type))

    def _do_set_variable_type(self, function_address, variable_name, new_type):
        addr = self.program.getAddressFactory().getAddress(function_address)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {function_address}"})
        fn = self._function_manager.getFunctionContaining(addr)
        if fn is None:
            return json.dumps({"error": f"No function at {function_address}"})
        dtm = self._program.getDataTypeManager()

        # Resolve the type name. DataTypeParser's default search (no
        # DataTypeManagerService) does not reliably find custom structures
        # filed under a category like /Voxtalk/StructName -- try a direct
        # category-path lookup first (handling a trailing "*" as a pointer
        # request) before falling back to DataTypeParser for built-ins.
        dt = None
        try:
            base_name = new_type.strip()
            is_pointer = base_name.endswith("*")
            if is_pointer:
                base_name = base_name[:-1].strip()
            PointerDataType = jpype.JClass('ghidra.program.model.data.PointerDataType')
            found = None
            dt_iter = dtm.getAllDataTypes()
            while dt_iter.hasNext():
                candidate = dt_iter.next()
                if candidate.getName() == base_name:
                    found = candidate
                    break
            if found is not None:
                dt = PointerDataType(found) if is_pointer else found
        except Exception:
            dt = None

        if dt is None:
            # Fall back to DataTypeParser for built-in/primitive type strings.
            try:
                parser = DataTypeParser(dtm, dtm, None, DataTypeParserAllowedTypes.ALL)
                dt = parser.parse(new_type)
            except Exception as e:
                return json.dumps({"error": f"Cannot parse type '{new_type}': {str(e)}"})
        if dt is None:
            return json.dumps({"error": f"Cannot resolve type: {new_type}"})

        # Go through the decompiler's HighFunction/HighSymbol model rather than
        # setting the raw Variable's type directly — a decompiled variable can
        # be split/merged across multiple storage locations, and only
        # HighFunctionDBUtil.updateDBVariable keeps the low-level Variable and
        # the decompiler's SSA view consistent (matches upstream GhidraMCP).
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor
        HighFunctionDBUtil = jpype.JClass('ghidra.program.model.pcode.HighFunctionDBUtil')

        decomp = DecompInterface()
        decomp.openProgram(self.program)
        try:
            res = decomp.decompileFunction(fn, 0, ConsoleTaskMonitor())
            if not res or not res.decompileCompleted():
                return json.dumps({"error": "Decompilation failed while resolving variable"})
            high_function = res.getHighFunction()
            if high_function is None:
                return json.dumps({"error": "No high function available"})

            target_symbol = None
            sym_iter = high_function.getLocalSymbolMap().getSymbols()
            while sym_iter.hasNext():
                sym = sym_iter.next()
                if sym.getName() == variable_name:
                    target_symbol = sym
                    break
            if target_symbol is None:
                return json.dumps({"error": f"Variable '{variable_name}' not found in decompiled function"})

            HighFunctionDBUtil.updateDBVariable(
                target_symbol, target_symbol.getName(), dt, SourceType.USER_DEFINED)
        finally:
            decomp.dispose()

        # Self-verify like set_this_type does (2026-07-13): an API call
        # reporting success here is not proof the retype produced usable
        # field access -- this project hit a real case
        # (CTextAnalyzer::champ_amplitude_rules_loader) where the
        # decompiler's own local-symbol naming diverged from the raw
        # listing's stack-variable naming for the same conceptual slot,
        # so a plausible-looking variable_name can still be the wrong
        # one. Re-decompile and check honestly instead of trusting
        # status:ok alone.
        verified, sample = self._verify_field_access_resolved(fn, dt, variable_name=variable_name)
        return json.dumps({
            "status": "ok",
            "function": fn.getName(),
            "variable": variable_name,
            "type": new_type,
            "decompile_shows_field_access": verified,
            "sample_line": sample,
            "note": ("decompile_shows_field_access is null if new_type has no checkable named "
                     "fields (not a Structure/pointer-to-Structure), false if it is one but no "
                     "'->field' access for it was found in the re-decompile -- if false, this "
                     "may be the wrong variable_name (check nearby offsets via "
                     "get_stack_variables, or try an adjacent decompiler-visible local), true "
                     "(with sample_line) if real field access was confirmed."),
        })

    def _resolve_type_by_name(self, dtm, type_name):
        """Resolve a type name to a DataType: exact category-path lookup
        first (DataTypeParser's default search does not reliably find
        custom /Voxtalk/... structures), falling back to DataTypeParser for
        built-ins and pointer/array syntax.  Arrays are constructed here
        rather than left entirely to DataTypeParser: that parser does not
        reliably resolve a custom root-category type when it appears as an
        array element (for example ``CLobe[32]``).  Handles a trailing '*'
        as a pointer request over the base type. Shared by the newer
        this-parameter/anchor-based retyping tools below;
        set_local_variable_type keeps its own inline copy of this same
        logic untouched (a proven-correct code path all session, not worth
        the regression risk of a mechanical refactor)."""
        base_name = type_name.strip()
        # Parse arrays before looking up the base name.  DataTypeParser can
        # normally parse primitive arrays, but fails for custom structures
        # in the root category; recursively using this resolver keeps custom
        # and built-in array behaviour consistent across all callers.
        import re
        array_match = re.fullmatch(r"(.+?)\s*\[\s*(\d+)\s*\]", base_name)
        if array_match:
            element_type = self._resolve_type_by_name(dtm, array_match.group(1))
            if element_type is None:
                return None
            ArrayDataType = jpype.JClass('ghidra.program.model.data.ArrayDataType')
            return ArrayDataType(element_type, int(array_match.group(2)), element_type.getLength())

        is_pointer = base_name.endswith("*")
        if is_pointer:
            base_name = base_name[:-1].strip()
        PointerDataType = jpype.JClass('ghidra.program.model.data.PointerDataType')
        dt = None
        dt_iter = dtm.getAllDataTypes()
        while dt_iter.hasNext():
            candidate = dt_iter.next()
            if candidate.getName() == base_name:
                dt = PointerDataType(candidate) if is_pointer else candidate
                break
        if dt is None:
            try:
                parser = DataTypeParser(dtm, dtm, None, DataTypeParserAllowedTypes.ALL)
                dt = parser.parse(type_name)
            except Exception:
                dt = None
        return dt

    def _verify_field_access_resolved(self, fn, dt, variable_name=None):
        """Re-decompile fn and check whether the (possibly pointed-to)
        structure's own real field names appear as literal '->field' access
        in the output. An API call reporting success is NOT sufficient
        evidence the decompiler display actually resolved -- confirmed this
        session that set_function_prototype/ApplyFunctionSignatureCmd can
        report success while leaving the real applied signature (and thus
        the decompile) completely untouched for a function Ghidra has
        already namespaced to a class. This is the honest check that was
        missing: don't claim a retype worked without looking at the actual
        decompiled text for it.

        SCOPED (2026-07-13; corrected 2026-07-28): when variable_name is given, this REQUIRES the
        match to be literally '{variable_name}->{field}', not just any
        '->{field}' anywhere in the function. Without this, a caller
        retyping the WRONG local in a function that already has some OTHER
        correctly-typed variable of the same struct type gets a false
        'true' -- confirmed live on
        CTextAnalyzer::champ_amplitude_rules_loader: after 'local_18' was
        already correctly retyped, retyping the wrong sibling 'local_14' to
        the same type still reported decompile_shows_field_access:true,
        because the old unscoped scan matched local_18's pre-existing
        access instead of checking local_14 specifically. set_this_type
        must also pass the literal 'this' parameter name: an unrelated
        correctly-typed argument such as ``maternal->gene_scan_cursor`` is
        not evidence that the receiver retype took effect."""
        Pointer = jpype.JClass('ghidra.program.model.data.Pointer')
        Structure = jpype.JClass('ghidra.program.model.data.Structure')
        target_dt = dt.getDataType() if isinstance(dt, Pointer) else dt
        field_names = []
        if isinstance(target_dt, Structure):
            for comp in target_dt.getComponents():
                fname = str(comp.getFieldName() or "")
                if fname and not fname.startswith("field_0x") and not fname.startswith("gap_"):
                    field_names.append(fname)
        if not field_names:
            return None, None  # nothing checkable (not a named struct)

        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor
        decomp = DecompInterface()
        decomp.openProgram(self.program)
        try:
            res = decomp.decompileFunction(fn, 0, ConsoleTaskMonitor())
            if not res or not res.decompileCompleted():
                return False, None
            text = str(res.getDecompiledFunction().getC())
            for fname in field_names:
                needle = f"{variable_name}->{fname}" if variable_name else f"->{fname}"
                idx = text.find(needle)
                if idx != -1:
                    start = text.rfind("\n", 0, idx) + 1
                    end = text.find("\n", idx)
                    line = text[start:end if end != -1 else len(text)].strip()
                    return True, line
            return False, None
        finally:
            decomp.dispose()

    def _find_ecx_stored_local(self, fn):
        """Scan a function's prologue (first ~25 instructions from its
        entry point) for a raw 'MOV [EBP+/-N], ECX' instruction -- the
        disassembly-level signature of a genuine thiscall 'this' being
        spilled to a stack slot that Ghidra's signature recovery failed
        to bind as an auto-parameter (the 'broken this' pattern, usually
        caused by an SEH-wrapped prologue confusing calling-convention
        analysis -- documented repeatedly in this project, e.g.
        CDictionaryPage::WndProc_oninit, CHomoGraph::GetInfo, and
        CTextAnalyzer::champ_amplitude_rules_loader).

        Returns (variable_name_or_None, stack_offset) if such a MOV is
        found (variable_name is None if no matching symbol occupies that
        exact offset), or None if no such MOV is found in the scanned
        window. Best-effort and advisory only: any exception is
        swallowed and treated as 'not found', since this exists to
        strengthen set_this_type's guard, not to be a load-bearing fact
        on its own.

        IMPORTANT (2026-07-13, found live on
        CTextAnalyzer::champ_amplitude_rules_loader): the raw stack
        offset resolved here is looked up against the DECOMPILER's own
        HighSymbol namespace (high_function.getLocalSymbolMap()) --
        exactly what set_local_variable_type's HighFunctionDBUtil-based
        resolution matches names against -- NOT fn.getAllVariables()
        (the raw listing.Variable objects get_stack_variables returns).
        These two namespaces can disagree for the same conceptual slot:
        on that exact function, the prologue's 'MOV [EBP-0x14], ECX'
        writes to what the RAW LISTING calls 'local_14' (confirmed via
        get_stack_variables), but the DECOMPILER, after an intervening
        register copy, ends up threading that same value through a
        HighSymbol it names 'local_18' in the actual C-level output --
        and 'local_18' is what real field-access expressions use
        throughout the function body (confirmed: retyping 'local_18'
        via set_local_variable_type produced correct '->field' access
        matching known struct offsets; retyping listing-level 'local_14'
        would have named the wrong symbol for set_local_variable_type's
        purposes even though it's the literal spill target). Resolving
        against HighSymbol storage first avoids exactly this trap."""
        try:
            listing = self._program.getListing()
            instr = listing.getInstructionAt(fn.getEntryPoint())
            seen = 0
            offset = None
            while instr is not None and seen < 25:
                if str(instr.getMnemonicString()).upper() == "MOV" and instr.getNumOperands() == 2:
                    src = str(instr.getDefaultOperandRepresentation(1)).strip().upper()
                    dest = str(instr.getDefaultOperandRepresentation(0)).strip().upper()
                    if src == "ECX" and "EBP" in dest:
                        # Ghidra renders negative EBP-relative offsets with a
                        # DOUBLE sign, e.g. "[EBP + -0x14]", not "[EBP - 0x14]"
                        # -- confirmed via disassemble_function output on this
                        # exact binary. A regex expecting a single +/- silently
                        # never matches that form, which was caught live this
                        # session: it made this whole detector a no-op even
                        # though it looked correct and compiled cleanly. Split
                        # on "EBP" and count ALL sign characters (any number of
                        # them, any spacing) instead of assuming exactly one.
                        after_ebp = dest.split("EBP", 1)[1]
                        m = re.search(r'((?:[+-]\s*)+)(0X[0-9A-F]+|\d+)', after_ebp)
                        if m:
                            sign_str = m.group(1).replace(' ', '')
                            sign = -1 if sign_str.count('-') % 2 == 1 else 1
                            raw = m.group(2)
                            val = int(raw, 16) if raw.startswith('0X') else int(raw)
                            offset = sign * val
                            break
                seen += 1
                instr = instr.getNext()
            if offset is None:
                return None

            from ghidra.app.decompiler import DecompInterface
            from ghidra.util.task import ConsoleTaskMonitor
            decomp = DecompInterface()
            decomp.openProgram(self.program)
            try:
                res = decomp.decompileFunction(fn, 0, ConsoleTaskMonitor())
                if res and res.decompileCompleted():
                    high_function = res.getHighFunction()
                    if high_function is not None:
                        sym_iter = high_function.getLocalSymbolMap().getSymbols()
                        while sym_iter.hasNext():
                            sym = sym_iter.next()
                            try:
                                storage = sym.getStorage()
                                if (storage is not None and storage.isStackStorage()
                                        and storage.getStackOffset() == offset):
                                    return (str(sym.getName()), offset)
                            except Exception:
                                continue
            finally:
                decomp.dispose()

            # Fall back to the raw listing Variable if no HighSymbol
            # matched this exact offset -- still useful signal (proves
            # SOMETHING real is there) even if the name may not be what
            # set_local_variable_type expects.
            for v in fn.getAllVariables():
                if v.isStackVariable() and v.getStackOffset() == offset:
                    return (str(v.getName()), offset)
            return (None, offset)
        except Exception:
            pass
        return None

    def _find_in_ecx_register_variable(self, fn):
        """Detect the OTHER 'broken this' shape that _find_ecx_stored_local
        cannot see: ECX used directly as an unspilled register value the
        decompiler names 'in_ECX' (Ghidra's convention for "value present
        in a register here, not modeled via dataflow from any parameter"),
        rather than copied to a stack slot in the prologue.

        REAL INCIDENT (2026-08-20, this project): set_this_type was called
        on CScienceSheet::HandleControlCommand and ::HandleDdeEvent, both
        'unknown' calling convention with 2 real stack parameters plus this
        in-register value. Neither had a 'MOV [EBP+/-N], ECX' spill for
        _find_ecx_stored_local to catch -- ECX was read directly. The call
        proceeded (the old guard only ran for __cdecl/__stdcall), silently
        overwrote parameter 0 (a genuine, unrelated, already-correctly-typed
        argument -- e.g. CScienceControlCommand*) with the requested 'this'
        type, and the self-verification check (_verify_field_access_resolved)
        returned a FALSE POSITIVE: the re-decompiled body's very first
        statement was a switch/dereference on the old parameter-0 value at
        its original stack slot, which the decompiler now renders as
        'this->somefield' purely because 'this' is the new type occupying
        that slot -- syntactically real field access, semantically the
        wrong variable entirely, while the function's actual logic kept
        running unfixed through the untouched 'in_ECX' local throughout the
        rest of the body. String-matching '->field' access can never catch
        this particular failure mode by itself; the only real fix is
        detecting the 'in_ECX' local BEFORE the retype and refusing, same
        as the stack-spill case.

        Returns True if an 'in_ECX' (or 'unaff_ECX') identifier appears in
        the function's decompiled C text, else False. Best-effort/advisory:
        any exception is swallowed and treated as 'not found'.
        """
        try:
            from ghidra.app.decompiler import DecompInterface
            from ghidra.util.task import ConsoleTaskMonitor
            decomp = DecompInterface()
            decomp.openProgram(self.program)
            try:
                res = decomp.decompileFunction(fn, 0, ConsoleTaskMonitor())
                if not res or not res.decompileCompleted():
                    return False
                text = str(res.getDecompiledFunction().getC())
                return bool(re.search(r'\b(in|unaff)_ECX\b', text))
            finally:
                decomp.dispose()
        except Exception:
            return False

    def set_this_type(self, function_address, new_type, force=False, override_detected_local=False,
                       insert_as_new_parameter=False):
        """Set the REAL type of a thiscall function's 'this' parameter, via
        Function.updateFunction() on the listing-level Function object --
        NOT via set_function_prototype's ApplyFunctionSignatureCmd path,
        which was confirmed this session to be cosmetic-only (plate-comment
        only) for any function Ghidra has already namespaced to a real
        class: the class's own pre-existing 'this' type silently persisted
        in the real signature every time, regardless of what prototype
        string was 'successfully' applied. This is the root-cause fix: it
        rebuilds the function's parameter list with an explicit
        USER_DEFINED 'this' Parameter and commits it with
        DYNAMIC_STORAGE_ALL_PARAMS (recomputes storage per the existing
        calling convention -- for thiscall this keeps 'this' in ECX
        regardless of the new type, exactly as it should).
        Also re-decompiles afterward and reports whether the struct's own
        field names actually show up as real '->field' access in the
        output (decompile_shows_field_access) -- this is checked, not
        assumed, since a successful API call alone was already shown this
        session (via the other code path) to not guarantee a visible
        result.

        GUARDED (2026-07-13): this call REFUSES by default when Ghidra's
        own calling-convention analysis says the function is __cdecl or
        __stdcall AND parameter 0 isn't already an auto-parameter --
        i.e. nothing suggests parameter 0 is actually ECX-sourced. This
        closes two real incidents from one RE session (docs/
        RE_CSPEAKERPAGE_STRUCT_2026-07-13.md, CSpeakerPage::show_modal and
        SMException::raise): both returned status:ok and looked
        successful, but had silently retyped a genuine, unrelated,
        already-correct declared parameter (an HINSTANCE, an int) instead
        of the function's real object pointer, because the real 'this' in
        both cases was an orphaned decompiler local this tool cannot see
        either way -- only decompile_shows_field_access being false,
        checked separately by a human, caught it. __cdecl/__stdcall are
        unambiguously 100% stack-only calling conventions in the Win32 x86
        ABI (never ECX-based), so this is a hard fact, not a heuristic --
        was_auto_parameter=True is still honored as an override signal
        since an auto-parameter is Ghidra's own confident inference that
        this really is the implicit object pointer regardless of the
        named convention.

        WIDENED (2026-08-20): now ALSO refuses for 'unknown' calling
        convention when the function has MORE THAN ONE parameter. REAL
        INCIDENT (this project, Creatures 1 Science Kit): the previous
        version explicitly did not refuse on 'unknown' convention,
        reasoning it "isn't a confident negative signal" -- true for the
        single-parameter "mislabeled this" shape this tool was built for,
        but false for the shape that actually broke on
        CScienceSheet::HandleControlCommand and ::HandleDdeEvent, both
        'unknown' convention with TWO real stack parameters already
        modeled plus a genuinely separate ECX 'this' the decompiler named
        'in_ECX' -- never spilled to a stack slot, so the existing
        _find_ecx_stored_local scan couldn't see it either. The call
        proceeded, silently overwrote parameter 0 (an unrelated, already-
        correctly-typed argument -- e.g. CScienceControlCommand*), and the
        self-verification check came back a FALSE POSITIVE
        (decompile_shows_field_access=True): the switch/dereference that
        used to read the real parameter 0 got relabeled 'this->field'
        purely because 'this' is now the type occupying that slot, while
        the function's actual logic kept running unfixed through the
        untouched 'in_ECX' local for the rest of the body. A single
        checkable-field string match can't distinguish "the right variable
        now has real field access" from "the wrong variable happens to
        alias a same-shaped field at that offset" -- only refusing before
        the retype, on real evidence, closes this. 'unknown' with exactly
        one parameter is unaffected (still proceeds) -- that is still the
        dominant, safe "mislabeled this" shape this tool was built for; a
        second real argument is what turns 'unknown' from a non-signal
        into one worth checking.

        Pass force=True to bypass for a function you've independently
        confirmed really isn't ECX-sourced in a way this check can't see.

        STRENGTHENED (2026-07-13, extended 2026-08-20): force=True alone
        is no longer enough when evidence of a genuine separate 'this'
        exists -- now checked TWO ways, not just one:
          (1) a raw-disassembly scan of the prologue finds a genuine
              'MOV [EBP+/-N], ECX' -- i.e. direct proof that a DIFFERENT
              variable (an orphaned stack local, not parameter 0) is
              where 'this' actually lives (docs/TRUTH_LEDGER.md,
              CTextAnalyzer::champ_amplitude_rules_loader, 2026-07-13);
          (2) (added 2026-08-20) the decompiled C text uses an unspilled
              'in_ECX'/'unaff_ECX' register value directly -- the
              HandleControlCommand/HandleDdeEvent shape above, where
              there is no stack spill for (1) to find at all.
        This exact scenario -- reading the refusal, correctly concluding
        it was an orphaned-this case, then using force=True on parameter 0
        anyway because that was the only override offered -- reproduced
        the CSpeakerPage incident a THIRD time in a later session (docs/
        TRUTH_LEDGER.md, 2026-07-13). When either detection fires,
        force=True alone still refuses and reports detected_ecx_local
        (spill case) and/or detected_in_ecx_register (register case) so
        the caller can act on real evidence; pass
        override_detected_local=True in addition to force=True only if
        you've independently confirmed parameter 0 really is correct
        despite that evidence.

        FIXED (2026-08-20): pass insert_as_new_parameter=True (together
        with force=True, and override_detected_local=True if evidence was
        detected) for the actual correct fix once you've confirmed 'this'
        is a genuinely separate value from every already-modeled
        parameter: this PREPENDS a new 'this' parameter and keeps ALL
        existing parameters (index 0..N-1) exactly as they were, instead
        of overwriting parameter 0. This is the real fix for both
        HandleControlCommand/HandleDdeEvent-shaped incidents above --
        set_local_variable_type cannot reach an unspilled 'in_ECX'
        register value at all (it only retypes named stack/HighSymbol
        locals), so before this flag existed there was no safe path to
        fix this exact shape at all short of hand-editing outside this
        tool."""
        return self._with_transaction("set_this_type",
            lambda: self._do_set_this_type(function_address, new_type, _form_bool(force),
                                            _form_bool(override_detected_local),
                                            _form_bool(insert_as_new_parameter)))

    def _do_set_this_type(self, function_address, new_type, force=False, override_detected_local=False,
                           insert_as_new_parameter=False):
        addr = self.program.getAddressFactory().getAddress(function_address)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {function_address}"})
        fn = self._function_manager.getFunctionContaining(addr)
        if fn is None:
            return json.dumps({"error": f"No function at {function_address}"})
        if fn.getParameterCount() == 0:
            return json.dumps({
                "error": (f"Function {fn.getName()} has no parameters -- not a thiscall/method "
                          f"function, or Ghidra hasn't modeled a 'this' parameter for it. This is "
                          f"the common state right after delete_function+create_function resets a "
                          f"function (the decompiler can still SHOW inferred parameters, but "
                          f"nothing is committed via updateFunction() yet). Use "
                          f"set_full_prototype(function_address={function_address!r}, "
                          f"calling_convention='__thiscall', return_type=<the real return type>, "
                          f"parameters='[{{\"name\": \"this\", \"type\": {new_type!r}}}]') to "
                          f"establish it directly in one call -- do NOT use "
                          f"set_function_prototype for this, it has two confirmed bugs (no "
                          f"calling-convention support, weaker type resolution) documented in its "
                          f"own docstring."),
            })

        dtm = self._program.getDataTypeManager()
        dt = self._resolve_type_by_name(dtm, new_type)
        if dt is None:
            return json.dumps({"error": f"Cannot resolve type: {new_type}"})

        param_count = fn.getParameterCount()
        old_param0 = fn.getParameter(0)
        was_auto = bool(old_param0.isAutoParameter()) if old_param0 is not None else False
        old_type_name = str(old_param0.getDataType().getName()) if old_param0 is not None else None

        ghidra_convention = None
        try:
            ghidra_convention = fn.getCallingConventionName()
        except Exception:
            pass
        conv_lower = str(ghidra_convention).lower() if ghidra_convention else ""
        definitely_not_ecx = conv_lower in ("__cdecl", "__stdcall")
        # WIDENED 2026-08-20: 'unknown' convention is only a non-signal for
        # the single-parameter "mislabeled this" shape. With >1 parameter
        # already modeled, a genuinely separate 'this' is exactly the shape
        # that broke on HandleControlCommand/HandleDdeEvent -- see the
        # set_this_type docstring for the full incident writeup.
        ambiguous_unknown_multi_param = conv_lower in ("unknown", "") and param_count > 1
        guard_applies = (not was_auto) and (definitely_not_ecx or ambiguous_unknown_multi_param)

        detected_local_name = None
        detected_offset = None
        detected_in_ecx_register = False
        if guard_applies:
            detected = self._find_ecx_stored_local(fn)
            if detected is not None:
                detected_local_name, detected_offset = detected
            detected_in_ecx_register = self._find_in_ecx_register_variable(fn)
        has_evidence = bool(detected_local_name or detected_in_ecx_register or detected_offset is not None)

        if not force and guard_applies:
            detected_msgs = []
            if detected_local_name:
                detected_msgs.append(
                    f" A raw-disassembly scan of the prologue found 'MOV [EBP"
                    f"{'+' if detected_offset >= 0 else ''}{hex(detected_offset)}], ECX' -- i.e. "
                    f"a decompiler-visible local named '{detected_local_name}' occupying that same "
                    f"conceptual slot that ECX (the real 'this') is spilled into."
                )
            elif detected_offset is not None:
                detected_msgs.append(
                    f" A raw-disassembly scan of the prologue found 'MOV [EBP"
                    f"{'+' if detected_offset >= 0 else ''}{hex(detected_offset)}], ECX' but no "
                    f"named local variable occupies that exact stack offset -- ECX is being "
                    f"spilled somewhere Ghidra hasn't modeled as a variable at all."
                )
            if detected_in_ecx_register:
                detected_msgs.append(
                    f" The decompiled body uses an unspilled 'in_ECX'/'unaff_ECX' register value "
                    f"directly -- Ghidra's own signal that a real ECX-sourced value flows through "
                    f"this function without ever being copied to a stack slot, so the spill scan "
                    f"above cannot see it either way."
                )
            if detected_msgs:
                detected_msg = (
                    "".join(detected_msgs) +
                    f" This is a strong LEAD, not a 100%-certain guarantee of the exact right "
                    f"variable name. If parameter 0 ({old_type_name!r}) is a genuine, unrelated, "
                    f"already-correct argument (the common case when evidence like this is "
                    f"found), pass force=true together with insert_as_new_parameter=true to "
                    f"PREPEND a new 'this' parameter and keep parameter 0 and every other "
                    f"existing parameter exactly as they are -- do not use plain force=true here, "
                    f"it would overwrite parameter 0 instead of inserting, which is the exact "
                    f"failure mode this guard exists to prevent. If a detected local/offset above "
                    f"looks like a stable, nameable stack slot (not the in_ECX register case), "
                    f"set_local_variable_type is also an option, but it cannot reach an unspilled "
                    f"in_ECX register value at all -- insert_as_new_parameter is the only fix for "
                    f"that shape."
                )
            else:
                detected_msg = (
                    f" If you've independently confirmed parameter 0 really is 'this' in a way "
                    f"this check can't see, pass force=true (add insert_as_new_parameter=true "
                    f"instead if 'this' is actually a genuinely separate value from parameter 0, "
                    f"not parameter 0 itself)."
                )
            reason = (
                f"Ghidra's own calling-convention analysis says this function is "
                f"{ghidra_convention} -- a 100% stack-only convention that never uses ECX "
                f"for an implicit object pointer"
                if definitely_not_ecx else
                f"Ghidra's own calling-convention analysis says 'unknown' for this function, "
                f"which has {param_count} parameters already modeled -- for a function with more "
                f"than one parameter, 'unknown' is not a confident signal that parameter 0 is "
                f"'this' (it only is for the single-parameter case)"
            )
            return json.dumps({
                "error": (
                    f"Refusing to retype parameter 0 of {fn.getName()} to '{new_type}' as "
                    f"'this': {reason}, and parameter 0 ({old_type_name!r}) isn't an "
                    f"auto-parameter either, so nothing suggests it's actually 'this'. "
                    f"This is the exact failure mode that silently mistyped a genuine, "
                    f"already-correct parameter multiple times across this project (see "
                    f"docs/RE_CSPEAKERPAGE_STRUCT_2026-07-13.md, show_modal and "
                    f"SMException::raise; docs/TRUTH_LEDGER.md, "
                    f"champ_amplitude_rules_loader; and CScienceSheet::HandleControlCommand / "
                    f"::HandleDdeEvent, 2026-08-20, where this exact call self-reported "
                    f"decompile_shows_field_access=True as a FALSE POSITIVE) -- the real object "
                    f"pointer was either an orphaned decompiler local or an unspilled register "
                    f"value this check cannot retype directly." + detected_msg
                ),
                "ghidra_calling_convention": str(ghidra_convention) if ghidra_convention else None,
                "parameter_count": param_count,
                "was_auto_parameter": was_auto,
                "old_this_type": old_type_name,
                "detected_ecx_local": detected_local_name,
                "detected_ecx_stack_offset": detected_offset,
                "detected_in_ecx_register": detected_in_ecx_register,
            })

        if (force and not insert_as_new_parameter and not override_detected_local
                and guard_applies and has_evidence):
            return json.dumps({
                "error": (
                    f"Refusing DESPITE force=true: real evidence was found that ECX (the real "
                    f"'this') is NOT parameter 0 ({old_type_name!r}) -- "
                    + (f"a raw-disassembly scan found it spilled into a local named "
                       f"'{detected_local_name}' at [EBP{'+' if detected_offset is not None and detected_offset >= 0 else ''}"
                       f"{hex(detected_offset) if detected_offset is not None else '?'}]. "
                       if detected_local_name else "")
                    + (f"the decompiled body uses it directly as an unspilled 'in_ECX'/'unaff_ECX' "
                       f"register value. " if detected_in_ecx_register else "")
                    + f"force=true overrides the calling-convention heuristic when it's wrong, but "
                    f"not direct evidence pointing at a specific better candidate -- pass "
                    f"insert_as_new_parameter=true together with force=true to PREPEND a new "
                    f"'this' parameter and keep parameter 0 (and every other existing parameter) "
                    f"unchanged, which is correct whenever 'this' is a genuinely separate value "
                    f"from every already-modeled parameter (the common case here). If instead you "
                    f"have independently confirmed parameter 0 itself really should become 'this' "
                    f"(overwriting it) despite this evidence, pass override_detected_local=true "
                    f"together with force=true instead."
                ),
                "detected_ecx_local": detected_local_name,
                "detected_ecx_stack_offset": detected_offset,
                "detected_in_ecx_register": detected_in_ecx_register,
            })

        ParameterImpl = jpype.JClass('ghidra.program.model.listing.ParameterImpl')
        ArrayList = jpype.JClass('java.util.ArrayList')
        FunctionUpdateType = jpype.JClass('ghidra.program.model.listing.Function$FunctionUpdateType')

        new_params = ArrayList()
        new_params.add(ParameterImpl("this", dt, self._program, SourceType.USER_DEFINED))
        if insert_as_new_parameter:
            # Real fix (2026-08-20): PREPEND 'this', keep every existing
            # parameter (0..N-1) exactly as it was. This is the only path
            # that doesn't silently destroy a genuine, unrelated argument
            # when 'this' turns out to be a value separate from all
            # currently-modeled parameters (the HandleControlCommand/
            # HandleDdeEvent shape -- see docstring).
            for i in range(0, param_count):
                new_params.add(fn.getParameter(i))
        else:
            # Legacy/default behavior, preserved for the legitimate
            # single-parameter "mislabeled this" shape (and for explicit
            # override_detected_local=true callers who want it): overwrite
            # parameter 0 with 'this', keep parameters 1..N-1.
            for i in range(1, param_count):
                new_params.add(fn.getParameter(i))

        try:
            fn.updateFunction(fn.getCallingConventionName(), fn.getReturn(), new_params,
                               FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, True,
                               SourceType.USER_DEFINED)
        except Exception as e:
            return json.dumps({"error": f"updateFunction failed: {e}"})

        # Scope the postcondition to the receiver.  Otherwise an unrelated
        # CGenome* argument can make a retained void* auto-this look fixed.
        verified, sample = self._verify_field_access_resolved(fn, dt, variable_name="this")

        return json.dumps({
            "status": "ok",
            "function": fn.getName(),
            "address": function_address,
            "was_auto_parameter": was_auto,
            "old_this_type": old_type_name,
            "requested_type": new_type,
            "ghidra_calling_convention": str(ghidra_convention) if ghidra_convention else None,
            "parameter_count_before": param_count,
            "inserted_as_new_parameter": bool(insert_as_new_parameter),
            "guard_bypassed_with_force": bool(force and guard_applies),
            "decompile_shows_field_access": verified,
            "sample_line": sample,
            "note": ("decompile_shows_field_access is null if the requested type has no "
                     "checkable named fields (not a Structure/pointer-to-Structure), false if "
                     "it is one but no '->field' access for it was found in the re-decompile, "
                     "true (with sample_line) if real field access was confirmed. NOTE: even "
                     "'true' here is not airtight when inserted_as_new_parameter=False and real "
                     "evidence existed -- the field access can come from the WRONG variable "
                     "aliasing the same struct offset (see the 2026-08-20 "
                     "HandleControlCommand/HandleDdeEvent false-positive incident in this tool's "
                     "docstring). Prefer inserted_as_new_parameter=True whenever evidence of a "
                     "separate 'this' was reported."),
        })

    def materialize_ecx_thiscall_callback(self, function_address, this_type,
                                          stack_argument_type="void *",
                                          stack_argument_name="callback_argument",
                                          evidence_instruction_address="",
                                          expected_ret_purge_bytes=4,
                                          replace_existing=False):
        """Materialize a deliberately verified x86 ECX-this callback ABI.

        This is intentionally narrower than set_function_prototype: it is for
        small callback-table functions where the raw listing proves (1) an
        object access based directly on ECX and (2) ``ret 4``, hence exactly
        one explicit 32-bit stack argument.  Ghidra sometimes models that
        shape as a parameterless function; this method rebuilds its *real*
        listing signature as ``__thiscall(this, callback_argument)``.

        ``evidence_instruction_address`` is mandatory so the caller has to
        nominate the concrete ECX-based instruction being relied upon.  The
        endpoint refuses to replace an existing signature unless
        replace_existing=True, and rolls the whole transaction back if Ghidra
        does not actually allocate the receiver in ECX.
        """
        return self._with_transaction(
            "materialize_ecx_thiscall_callback",
            lambda: self._do_materialize_ecx_thiscall_callback(
                function_address, this_type, stack_argument_type,
                stack_argument_name, evidence_instruction_address,
                expected_ret_purge_bytes, _form_bool(replace_existing)))

    def _do_materialize_ecx_thiscall_callback(self, function_address, this_type,
                                               stack_argument_type,
                                               stack_argument_name,
                                               evidence_instruction_address,
                                               expected_ret_purge_bytes,
                                               replace_existing=False):
        addr = self.program.getAddressFactory().getAddress(function_address)
        if addr is None:
            return json.dumps({"error": f"Invalid function address: {function_address}"})
        fn = self._function_manager.getFunctionContaining(addr)
        if fn is None:
            return json.dumps({"error": f"No function at {function_address}"})
        if not evidence_instruction_address:
            return json.dumps({"error": "evidence_instruction_address is required; nominate the raw ECX-based access"})
        evidence_addr = self.program.getAddressFactory().getAddress(evidence_instruction_address)
        if evidence_addr is None or not fn.getBody().contains(evidence_addr):
            return json.dumps({"error": "Evidence instruction is not inside the target function"})
        evidence = self._listing.getInstructionAt(evidence_addr)
        if evidence is None:
            return json.dumps({"error": f"No instruction at evidence address {evidence_instruction_address}"})
        operands = " ".join(str(evidence.getDefaultOperandRepresentation(i))
                            for i in range(evidence.getNumOperands()))
        normalized_operands = operands.replace(" ", "").upper()
        if "[ECX" not in normalized_operands:
            return json.dumps({"error": "Evidence instruction has no direct [ECX+offset] memory operand",
                               "instruction": str(evidence), "operands": operands})

        try:
            expected_ret_purge_bytes = int(expected_ret_purge_bytes)
        except (TypeError, ValueError):
            return json.dumps({"error": "expected_ret_purge_bytes must be an integer"})
        # This endpoint's safety model is specifically the one-argument x86
        # callback ABI.  A different RET cleanup needs a separately audited
        # tool rather than a convenient but unsafe generalisation.
        if expected_ret_purge_bytes != 4:
            return json.dumps({"error": "This endpoint only accepts ret 4 (one 32-bit stack argument)"})
        ret_purges = []
        it = self._listing.getInstructions(fn.getBody(), True)
        while it.hasNext():
            inst = it.next()
            if str(inst.getMnemonicString()).upper() != "RET":
                continue
            purge = 0
            try:
                scalar = inst.getScalar(0)
                if scalar is not None:
                    purge = int(scalar.getUnsignedValue())
            except Exception:
                pass
            ret_purges.append(purge)
        if not ret_purges or any(purge != expected_ret_purge_bytes for purge in ret_purges):
            return json.dumps({"error": "Raw RET cleanup does not prove the required one-stack-argument callback ABI",
                               "observed_ret_purge_bytes": ret_purges,
                               "expected_ret_purge_bytes": expected_ret_purge_bytes})

        old_params = [{"name": str(fn.getParameter(i).getName()),
                       "type": str(fn.getParameter(i).getDataType().getName()),
                       "storage": str(fn.getParameter(i).getVariableStorage())}
                      for i in range(fn.getParameterCount())]
        if old_params and not replace_existing:
            return json.dumps({"error": "Function already has parameters; refusing to overwrite without replace_existing=true",
                               "existing_parameters": old_params})
        if len(old_params) > 2:
            return json.dumps({"error": "Refusing to replace a signature with more than two existing parameters",
                               "existing_parameters": old_params})

        dtm = self._program.getDataTypeManager()
        receiver_dt = self._resolve_type_by_name(dtm, this_type)
        argument_dt = self._resolve_type_by_name(dtm, stack_argument_type)
        if receiver_dt is None:
            return json.dumps({"error": f"Cannot resolve this_type: {this_type}"})
        if argument_dt is None:
            return json.dumps({"error": f"Cannot resolve stack_argument_type: {stack_argument_type}"})
        if not stack_argument_name or not str(stack_argument_name).replace("_", "a").isalnum():
            return json.dumps({"error": "stack_argument_name must be a non-empty identifier"})

        ParameterImpl = jpype.JClass('ghidra.program.model.listing.ParameterImpl')
        ArrayList = jpype.JClass('java.util.ArrayList')
        FunctionUpdateType = jpype.JClass('ghidra.program.model.listing.Function$FunctionUpdateType')
        params = ArrayList()
        params.add(ParameterImpl("this", receiver_dt, self._program, SourceType.USER_DEFINED))
        params.add(ParameterImpl(str(stack_argument_name), argument_dt, self._program,
                                 SourceType.USER_DEFINED))
        try:
            fn.updateFunction("__thiscall", fn.getReturn(), params,
                              FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, True,
                              SourceType.USER_DEFINED)
        except Exception as e:
            return json.dumps({"error": f"updateFunction(__thiscall) failed: {e}"})

        receiver = fn.getParameter(0)
        argument = fn.getParameter(1) if fn.getParameterCount() == 2 else None
        receiver_storage = str(receiver.getVariableStorage()) if receiver is not None else ""
        if receiver is None or argument is None or "ECX" not in receiver_storage.upper():
            return json.dumps({"error": "Ghidra did not materialize the receiver in ECX; transaction rolled back",
                               "actual_parameter_count": fn.getParameterCount(),
                               "receiver_storage": receiver_storage})
        verified, sample = self._verify_field_access_resolved(fn, receiver_dt, variable_name="this")
        return json.dumps({
            "status": "ok", "function": fn.getName(), "address": function_address,
            "calling_convention": str(fn.getCallingConventionName()),
            "this_type": str(receiver_dt.getName()), "this_storage": receiver_storage,
            "stack_argument_name": str(argument.getName()),
            "stack_argument_type": str(argument.getDataType().getName()),
            "stack_argument_storage": str(argument.getVariableStorage()),
            "evidence_instruction": str(evidence), "observed_ret_purge_bytes": ret_purges,
            "replaced_existing_signature": bool(old_params),
            "previous_parameters": old_params,
            "decompile_shows_field_access": verified, "sample_line": sample,
        })

    def materialize_ecx_thiscall_receiver(self, function_address, this_type,
                                          evidence_instruction_address=""):
        """Materialize a proven parameterless x86 ``__thiscall`` method.

        Ghidra can leave a real ECX-receiver method parameterless when it has
        no explicit stack arguments.  This deliberately narrow repair needs a
        nominated receiver-derived memory access and proves that every return
        is ``ret``/``ret 0`` before constructing exactly one ``this``
        parameter.  The nominated access may use ECX directly or a simple
        register alias made by ``mov reg, ecx`` earlier in the function.
        """
        return self._with_transaction(
            "materialize_ecx_thiscall_receiver",
            lambda: self._do_materialize_ecx_thiscall_receiver(
                function_address, this_type, evidence_instruction_address))

    def _do_materialize_ecx_thiscall_receiver(self, function_address,
                                               this_type,
                                               evidence_instruction_address):
        addr = self.program.getAddressFactory().getAddress(function_address)
        if addr is None:
            return json.dumps({"error": f"Invalid function address: {function_address}"})
        fn = self._function_manager.getFunctionContaining(addr)
        if fn is None:
            return json.dumps({"error": f"No function at {function_address}"})
        if fn.getParameterCount() != 0:
            return json.dumps({"error": "Function already has parameters; this zero-argument repair refuses to overwrite a signature",
                               "existing_parameters": [{"name": str(fn.getParameter(i).getName()),
                                                        "type": str(fn.getParameter(i).getDataType().getName())}
                                                       for i in range(fn.getParameterCount())]})
        if not evidence_instruction_address:
            return json.dumps({"error": "evidence_instruction_address is required; nominate a receiver-derived memory access"})
        evidence_addr = self.program.getAddressFactory().getAddress(evidence_instruction_address)
        if evidence_addr is None or not fn.getBody().contains(evidence_addr):
            return json.dumps({"error": "Evidence instruction is not inside the target function"})
        evidence = self._listing.getInstructionAt(evidence_addr)
        if evidence is None:
            return json.dumps({"error": f"No instruction at evidence address {evidence_instruction_address}"})

        # Track only the unambiguous compiler idiom needed here: MOV reg,ECX.
        # This is intentionally not a general data-flow engine.  If the
        # receiver is transformed, spilled, or reaches the access through a
        # branch, the caller must use a separately audited tool instead.
        #
        # A saved alias remains valid after ECX itself is reused for a local
        # or call argument (the normal MSVC ``MOV EDI,ECX`` prologue shape).
        # In that case discard only ECX's current alias; rejecting the whole
        # trace would contradict the documented simple-alias support.
        general_registers = set(["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP"])
        aliases = {"ECX": None}
        it = self._listing.getInstructions(fn.getBody(), True)
        while it.hasNext():
            inst = it.next()
            if inst.getAddress().compareTo(evidence_addr) > 0:
                break
            mnemonic = str(inst.getMnemonicString()).upper()
            op0 = (str(inst.getDefaultOperandRepresentation(0)).replace(" ", "").upper()
                   if inst.getNumOperands() > 0 else "")
            op1 = (str(inst.getDefaultOperandRepresentation(1)).replace(" ", "").upper()
                   if inst.getNumOperands() > 1 else "")
            if mnemonic == "MOV" and op0 in general_registers and op1 in aliases:
                aliases[op0] = str(inst.getAddress())
            elif mnemonic == "POP" and op0 in aliases:
                # The instruction iterator is address-linear, not CFG-aware.
                # A POP in an earlier return epilogue is therefore commonly
                # encountered before the address of a later branch target,
                # even though that epilogue cannot execute on the path to
                # the nominated evidence.  Do not let such a stack restore
                # erase a proven entry-register alias; other real writes to
                # the alias register still invalidate it below.
                pass
            elif op0 in aliases:
                aliases.pop(op0, None)
            if inst.getAddress() == evidence_addr:
                break

        operands = " ".join(str(evidence.getDefaultOperandRepresentation(i))
                            for i in range(evidence.getNumOperands()))
        normalized_operands = operands.replace(" ", "").upper()
        memory_bases = re.findall(r"\[([A-Z]{2,3})(?:[+\-][^\]]*)?\]", normalized_operands)
        receiver_register = next((base for base in memory_bases if base in aliases), None)
        if receiver_register is None:
            return json.dumps({"error": "Evidence instruction has no [ECX+offset] access or simple MOV-reg,ECX receiver alias",
                               "instruction": str(evidence), "operands": operands,
                               "known_ecx_aliases": sorted(aliases.keys())})

        ret_purges = []
        it = self._listing.getInstructions(fn.getBody(), True)
        while it.hasNext():
            inst = it.next()
            if str(inst.getMnemonicString()).upper() != "RET":
                continue
            purge = 0
            try:
                scalar = inst.getScalar(0)
                if scalar is not None:
                    purge = int(scalar.getUnsignedValue())
            except Exception:
                return json.dumps({"error": "Could not establish RET cleanup at a return instruction",
                                   "instruction": str(inst)})
            ret_purges.append(purge)
        if not ret_purges or any(purge != 0 for purge in ret_purges):
            return json.dumps({"error": "Raw RET cleanup does not prove a zero-stack-argument method ABI",
                               "observed_ret_purge_bytes": ret_purges})

        receiver_dt = self._resolve_type_by_name(self._program.getDataTypeManager(), this_type)
        if receiver_dt is None:
            return json.dumps({"error": f"Cannot resolve this_type: {this_type}"})
        ParameterImpl = jpype.JClass('ghidra.program.model.listing.ParameterImpl')
        ArrayList = jpype.JClass('java.util.ArrayList')
        FunctionUpdateType = jpype.JClass('ghidra.program.model.listing.Function$FunctionUpdateType')
        params = ArrayList()
        params.add(ParameterImpl("this", receiver_dt, self._program, SourceType.USER_DEFINED))
        try:
            fn.updateFunction("__thiscall", fn.getReturn(), params,
                              FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, True,
                              SourceType.USER_DEFINED)
        except Exception as e:
            return json.dumps({"error": f"updateFunction(__thiscall) failed: {e}"})
        receiver = fn.getParameter(0) if fn.getParameterCount() == 1 else None
        receiver_storage = str(receiver.getVariableStorage()) if receiver is not None else ""
        if receiver is None or "ECX" not in receiver_storage.upper():
            return json.dumps({"error": "Ghidra did not materialize the receiver in ECX; transaction rolled back",
                               "actual_parameter_count": fn.getParameterCount(),
                               "receiver_storage": receiver_storage})
        verified, sample = self._verify_field_access_resolved(fn, receiver_dt, variable_name="this")
        return json.dumps({
            "status": "ok", "function": fn.getName(), "address": function_address,
            "calling_convention": str(fn.getCallingConventionName()),
            "this_type": str(receiver_dt.getName()), "this_storage": receiver_storage,
            "evidence_instruction": str(evidence), "receiver_register_at_evidence": receiver_register,
            "ecx_alias_instruction": aliases.get(receiver_register),
            "observed_ret_purge_bytes": ret_purges,
            "decompile_shows_field_access": verified, "sample_line": sample,
        })

    def retype_variable_at(self, function_address, instruction_address, new_type, side="output", input_index=0):
        """Retype the HighVariable touched by the pcode op AT a specific
        instruction address, instead of by CURRENT variable NAME. This
        exists because set_local_variable_type's name-based lookup is
        fragile: confirmed repeatedly this session that ANY retype call can
        silently renumber/rename OTHER local variables in the same function
        on the next decompile (e.g. iVar4 becoming iVar5 becoming iVar6
        across successive calls, sometimes for multiple call sites in one
        function each needing their own chase) -- turning a single intended
        retype into a decompile/spot-the-new-name/retry loop. An
        instruction ADDRESS is stable across that churn in a way an
        auto-generated variable name is not.
        side: "output" (default) retypes the variable ASSIGNED at that
        instruction (e.g. "X = alloc_something(...)" -- the most common
        case this session). side="input" retypes the Nth input varnode
        instead (input_index, 0-based) -- use this to retype a variable
        being READ/PASSED at that instruction rather than assigned."""
        return self._with_transaction("retype_variable_at",
            lambda: self._do_retype_variable_at(function_address, instruction_address, new_type, side, input_index))

    def _do_retype_variable_at(self, function_address, instruction_address, new_type, side="output", input_index=0):
        faddr = self.program.getAddressFactory().getAddress(function_address)
        if faddr is None:
            return json.dumps({"error": f"Invalid function address: {function_address}"})
        fn = self._function_manager.getFunctionContaining(faddr)
        if fn is None:
            return json.dumps({"error": f"No function at {function_address}"})
        iaddr = self.program.getAddressFactory().getAddress(instruction_address)
        if iaddr is None:
            return json.dumps({"error": f"Invalid instruction address: {instruction_address}"})

        dtm = self._program.getDataTypeManager()
        dt = self._resolve_type_by_name(dtm, new_type)
        if dt is None:
            return json.dumps({"error": f"Cannot resolve type: {new_type}"})

        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor
        HighFunctionDBUtil = jpype.JClass('ghidra.program.model.pcode.HighFunctionDBUtil')

        decomp = DecompInterface()
        decomp.openProgram(self.program)
        try:
            res = decomp.decompileFunction(fn, 0, ConsoleTaskMonitor())
            if not res or not res.decompileCompleted():
                return json.dumps({"error": "Decompilation failed"})
            high_function = res.getHighFunction()
            if high_function is None:
                return json.dumps({"error": "No high function available"})

            pcode_ops_iter = high_function.getPcodeOps(iaddr)
            ops_seen = 0
            target_high = None
            while pcode_ops_iter.hasNext():
                op = pcode_ops_iter.next()
                ops_seen += 1
                vn = None
                if side == "output":
                    vn = op.getOutput()
                elif side == "input":
                    inputs = op.getInputs()
                    if input_index < len(inputs):
                        vn = inputs[input_index]
                if vn is not None:
                    high = vn.getHigh()
                    if high is not None and high.getSymbol() is not None:
                        target_high = high
                        break

            if target_high is None:
                return json.dumps({
                    "error": (f"No retypeable {side} variable found among {ops_seen} pcode op(s) "
                              f"at {instruction_address} in {fn.getName()} -- the instruction may "
                              f"not exist, may not produce/consume a variable at that side/index, "
                              f"or the touched value may be a constant/unnamed temporary."),
                })

            target_symbol = target_high.getSymbol()
            old_name = str(target_symbol.getName())
            HighFunctionDBUtil.updateDBVariable(
                target_symbol, old_name, dt, SourceType.USER_DEFINED)
            return json.dumps({
                "status": "ok",
                "function": fn.getName(),
                "instruction_address": instruction_address,
                "retyped_variable": old_name,
                "type": new_type,
            })
        finally:
            decomp.dispose()

    def propose_struct_fields(self, function_address, this_param_index=0):
        """Mechanize the single most-repeated manual task in this
        project's struct-building RE work: reading a constructor/method's
        decompile and converting every `this`-relative pointer-arithmetic
        expression into a byte offset by hand. This was done ~13 times by
        hand in one RE session (docs/RE_CSPEAKERPAGE_STRUCT_2026-07-13.md
        and the TRUTH_LEDGER.md rows around it) and produced one real,
        subtle bug: CSpeakerPageFields's tab_a_block was originally sized
        4 bytes too large because a self-pointer field living at the TAIL
        of a sub-object (not appended after it) was momentarily
        miscounted by hand -- caught on a second manual pass, not
        automatically.

        Walks the function's raw PCODE (not decompile text -- avoids
        re-deriving stride/cast arithmetic via regex, and is immune to
        the display quirks that make text-scraping `this[N]` vs
        `*(TYPE*)(this+N)` fragile). For every LOAD/STORE pcode op in the
        function, traces the address operand backward through
        COPY/CAST/INT_ADD/PTRADD/PTRSUB chains; if it resolves to
        `this_param_index`'s own HighVariable plus a constant offset,
        records that offset/size/direction. ALSO traces every CALL's
        arguments the same way (validated live against
        CSpeakerPage::construct: the direct-write signal alone found only
        7 of the ~12 real fields -- the rest, the sub-object boundaries,
        only show up as `this+N` passed into a sub-constructor call, e.g.
        `construct_field_0x30_body(this + 0xc)`, which is how most real
        fields in this project were actually found by hand). Aggregates
        by offset, flags any two DIRECT accesses at the same offset with
        a disagreeing size (probable struct-layout ambiguity -- inspect
        manually, don't just take the larger one), and returns a
        proposed, offset-sorted field list with reads/writes/
        passed_to_calls (callee name + arg index) reported separately.

        This is a STARTING POINT for create_structure/
        create_structure_from_offsets, not a finished field list: field
        NAMES and semantic roles still require reading the surrounding
        code, exactly as before -- this only mechanizes the offset
        arithmetic, which is the part that was tedious AND, once, wrong."""
        addr = self.program.getAddressFactory().getAddress(function_address)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {function_address}"})
        fn = self._function_manager.getFunctionContaining(addr)
        if fn is None:
            return json.dumps({"error": f"No function at {function_address}"})
        this_param_index = int(this_param_index)
        if this_param_index >= fn.getParameterCount():
            return json.dumps({"error": (f"{fn.getName()} has {fn.getParameterCount()} "
                               f"parameter(s), no index {this_param_index}")})

        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor
        PcodeOp = jpype.JClass('ghidra.program.model.pcode.PcodeOp')

        decomp = DecompInterface()
        decomp.openProgram(self.program)
        try:
            res = decomp.decompileFunction(fn, 0, ConsoleTaskMonitor())
            if not res or not res.decompileCompleted():
                return json.dumps({"error": "Decompilation failed"})
            high_function = res.getHighFunction()
            if high_function is None:
                return json.dumps({"error": "No high function available"})

            proto = high_function.getFunctionPrototype()
            target_param = proto.getParam(this_param_index)
            if target_param is None:
                return json.dumps({"error": f"No decompiler parameter at index {this_param_index}"})
            target_high = target_param.getHighVariable()
            if target_high is None:
                return json.dumps({"error": (f"Parameter {this_param_index} "
                                   f"({target_param.getName()}) has no HighVariable in this "
                                   f"decompile -- likely unused in the function body")})

            def trace_offset(vn, depth=0):
                """Returns an int byte offset from target_high if vn
                resolves to target_high + constant, else None."""
                if vn is None or depth > 24:
                    return None
                high = vn.getHigh()
                if high is not None and high.equals(target_high):
                    return 0
                if vn.isConstant():
                    return None
                op = vn.getDef()
                if op is None:
                    return None
                opcode = op.getOpcode()
                if opcode in (PcodeOp.COPY, PcodeOp.CAST):
                    return trace_offset(op.getInput(0), depth + 1)
                if opcode == PcodeOp.INT_ADD:
                    a, b = op.getInput(0), op.getInput(1)
                    if b.isConstant():
                        base = trace_offset(a, depth + 1)
                        if base is not None:
                            return base + int(b.getOffset())
                    if a.isConstant():
                        base = trace_offset(b, depth + 1)
                        if base is not None:
                            return base + int(a.getOffset())
                    return None
                if opcode == PcodeOp.PTRADD:
                    ptr, index, elem = op.getInput(0), op.getInput(1), op.getInput(2)
                    if index.isConstant() and elem.isConstant():
                        base = trace_offset(ptr, depth + 1)
                        if base is not None:
                            return base + int(index.getOffset()) * int(elem.getOffset())
                    return None
                if opcode == PcodeOp.PTRSUB:
                    ptr, off = op.getInput(0), op.getInput(1)
                    if off.isConstant():
                        base = trace_offset(ptr, depth + 1)
                        if base is not None:
                            return base + int(off.getOffset())
                    return None
                return None

            hits = {}
            untraced_accesses = 0
            addr_set = fn.getBody()
            instr_iter = self._listing.getInstructions(addr_set, True)
            while instr_iter.hasNext():
                instr = instr_iter.next()
                pcode_ops_iter = high_function.getPcodeOps(instr.getMinAddress())
                while pcode_ops_iter.hasNext():
                    op = pcode_ops_iter.next()
                    opcode = op.getOpcode()
                    if opcode in (PcodeOp.CALL, PcodeOp.CALLIND):
                        # A `this + N` pointer passed into a callee -- e.g.
                        # `construct_field_0x30_body(param_1 + 0xc)' -- is
                        # exactly how most of this project's real struct
                        # fields were actually found by hand (sub-object
                        # boundaries are discovered from CALL arguments far
                        # more often than from a direct LOAD/STORE at the
                        # constructing/observing function's own level).
                        # Distinct from reads/writes: no reliable size
                        # signal (the argument's own varnode is just
                        # pointer-sized), so tracked separately as
                        # passed_to_calls, not folded into sizes_seen.
                        callee_name = None
                        if opcode == PcodeOp.CALL:
                            try:
                                target_addr = op.getInput(0).getAddress()
                                callee_fn = self._function_manager.getFunctionAt(target_addr)
                                if callee_fn is not None:
                                    callee_name = str(callee_fn.getName())
                            except Exception:
                                pass
                        for arg_index in range(1, op.getNumInputs()):
                            offset = trace_offset(op.getInput(arg_index))
                            if offset is None:
                                continue
                            entry = hits.setdefault(offset, {
                                "reads": 0, "writes": 0, "sizes": set(),
                                "sample_addresses": [], "passed_to_calls": []})
                            if len(entry["passed_to_calls"]) < 5:
                                entry["passed_to_calls"].append({
                                    "callee": callee_name or "(indirect)",
                                    "arg_index": arg_index - 1,
                                    "address": str(instr.getMinAddress()),
                                })
                            if len(entry["sample_addresses"]) < 3:
                                entry["sample_addresses"].append(str(instr.getMinAddress()))
                        continue

                    direction, addr_vn, size = None, None, None
                    if opcode == PcodeOp.LOAD:
                        addr_vn = op.getInput(1)
                        out = op.getOutput()
                        size = int(out.getSize()) if out is not None else None
                        direction = "read"
                    elif opcode == PcodeOp.STORE:
                        addr_vn = op.getInput(1)
                        val = op.getInput(2)
                        size = int(val.getSize()) if val is not None else None
                        direction = "write"
                    else:
                        continue
                    offset = trace_offset(addr_vn)
                    if offset is None:
                        untraced_accesses += 1
                        continue
                    entry = hits.setdefault(offset, {"reads": 0, "writes": 0, "sizes": set(),
                                                      "sample_addresses": [], "passed_to_calls": []})
                    entry["reads" if direction == "read" else "writes"] += 1
                    if size:
                        entry["sizes"].add(size)
                    if len(entry["sample_addresses"]) < 3:
                        entry["sample_addresses"].append(str(instr.getMinAddress()))

            fields = []
            for offset in sorted(hits.keys()):
                entry = hits[offset]
                sizes = sorted(entry["sizes"])
                fields.append({
                    "offset": offset,
                    "offset_hex": hex(offset),
                    "sizes_seen": sizes,
                    "size_ambiguous": len(sizes) > 1,
                    "reads": entry["reads"],
                    "writes": entry["writes"],
                    "passed_to_calls": entry["passed_to_calls"],
                    "sample_addresses": entry["sample_addresses"],
                })

            return json.dumps({
                "function": fn.getName(),
                "address": function_address,
                "this_param_index": this_param_index,
                "this_param_name": str(target_param.getName()),
                "proposed_fields": fields,
                "untraced_this_relative_accesses": untraced_accesses,
                "note": ("Offsets are byte-exact where traced (via PCODE, not decompile-text "
                         "regex). Each field reports reads/writes (direct LOAD/STORE at that "
                         "offset within THIS function) separately from passed_to_calls (this+N "
                         "handed to a callee as an argument, with the callee's name when "
                         "resolvable) -- in real use on this project, most struct fields were "
                         "actually found from passed_to_calls (sub-object construction, e.g. "
                         "`construct_field_0x30_body(this + 0xc)`), not direct field writes at "
                         "this function's own level, so check both. size_ambiguous=true means "
                         "two direct accesses at the same offset disagreed on width -- inspect "
                         "manually, do not just take the larger one (passed_to_calls entries "
                         "carry no size signal, a callee argument's own varnode is just "
                         "pointer-sized, not the sub-object's real size). "
                         "untraced_this_relative_accesses counts LOAD/STORE ops that touch a "
                         "computed address this trace couldn't resolve to a constant offset "
                         "from this_param_index (e.g. array-indexed access with a non-constant "
                         "index, or a genuinely different pointer) -- a nonzero count does not "
                         "necessarily mean the proposal below is incomplete for confirmed "
                         "fields. This is a STARTING POINT for create_structure/"
                         "create_structure_from_offsets, not a finished field list -- field "
                         "NAMES, semantic roles, and sub-object SIZES still require reading "
                         "the surrounding code (a passed_to_calls hit tells you a sub-object "
                         "starts at that offset, not how big it is)."),
            })
        finally:
            decomp.dispose()

    # ── New write operations ──────────────────────────────────────

    def _resolve_namespace_path(self, path, create=False):
        """Resolve a '/'-separated namespace path (e.g. 'CFoo/Inner') to a
        Namespace, walking from the program's global namespace one segment
        at a time. create=True uses getOrCreateNameSpace at each step
        (building any missing intermediate segments); create=False uses a
        plain lookup and returns None on the first missing segment."""
        symtab = self._program.getSymbolTable()
        current = self._program.getGlobalNamespace()
        segments = [s for s in path.strip("/").split("/") if s]
        if not segments:
            return current
        for seg in segments:
            if create:
                current = symtab.getOrCreateNameSpace(current, seg, SourceType.USER_DEFINED)
            else:
                nxt = symtab.getNamespace(seg, current)
                if nxt is None:
                    return None
                current = nxt
        return current

    def manage_namespace(self, operation, path, new_name="", new_parent_path=""):
        """Explicit namespace create/rename/move -- P2 item 1 from
        docs/GRAPHIFY_GHIDRA_RE_INTEGRATION_PLAN.md. Until now the only way
        to create a real Ghidra namespace was as a side effect of
        rename_function_by_address('Class::method', ...) -- this exposes
        the operation directly, and adds rename/move, which nothing did
        before.
        operation='create': create (or no-op if it already exists) the
        namespace at `path`, building any missing intermediate segments
        (e.g. path='CFoo/Inner' creates both CFoo and CFoo/Inner as needed).
        operation='rename': rename the namespace at `path` to `new_name`
        (same parent, just the leaf name changes).
        operation='move': move the namespace at `path` to become a child
        of `new_parent_path` (creating the new parent path if it doesn't
        exist; same leaf name)."""
        return self._with_transaction("manage_namespace",
            lambda: self._do_manage_namespace(operation, path, new_name, new_parent_path))

    def _do_manage_namespace(self, operation, path, new_name="", new_parent_path=""):
        if operation == "create":
            ns = self._resolve_namespace_path(path, create=True)
            return json.dumps({"status": "ok", "operation": "create",
                               "path": path, "id": ns.getID(), "name": ns.getName()})

        ns = self._resolve_namespace_path(path, create=False)
        if ns is None:
            return json.dumps({"error": f"Namespace not found: {path}"})
        symbol = ns.getSymbol()
        if symbol is None:
            return json.dumps({"error": f"Namespace at {path} has no renamable Symbol "
                               f"(likely the global namespace)"})

        if operation == "rename":
            if not new_name:
                return json.dumps({"error": "new_name is required for operation='rename'"})
            old_name = ns.getName()
            symbol.setName(new_name, SourceType.USER_DEFINED)
            return json.dumps({"status": "ok", "operation": "rename", "path": path,
                               "old_name": old_name, "new_name": new_name})

        if operation == "move":
            if not new_parent_path:
                return json.dumps({"error": "new_parent_path is required for operation='move'"})
            new_parent = self._resolve_namespace_path(new_parent_path, create=True)
            old_parent = str(ns.getParentNamespace().getName(True))
            symbol.setNamespace(new_parent)
            return json.dumps({"status": "ok", "operation": "move", "path": path,
                               "old_parent": old_parent, "new_parent": new_parent_path})

        return json.dumps({"error": f"Unknown operation '{operation}' -- use create, rename, or move"})

    def set_parameter(self, function_address, index, new_name="", new_type=""):
        """Rename and/or retype a function parameter BY INDEX (0-based),
        via the same Function.updateFunction() listing-level approach as
        set_this_type -- P2 item 3 from
        docs/GRAPHIFY_GHIDRA_RE_INTEGRATION_PLAN.md ('parameter rename/type
        by index, not only local-variable operations'). Parameter 0 is
        guarded when it is Ghidra's implicit thiscall receiver: use
        set_this_type for that receiver and this tool for explicit
        parameters (usually starting at index 1 on a thiscall function),
        or for free-function parameters. This avoids duplicating the
        implicit receiver during Function.updateFunction().
        At least one of new_name/new_type must be given; the other keeps
        its current value. Re-decompiles afterward and reports
        decompile_shows_field_access the same honest way set_this_type
        does, when new_type is a Structure or pointer-to-Structure."""
        return self._with_transaction("set_parameter",
            lambda: self._do_set_parameter(function_address, index, new_name, new_type))

    def _do_set_parameter(self, function_address, index, new_name="", new_type=""):
        if not new_name and not new_type:
            return json.dumps({"error": "At least one of new_name or new_type is required"})
        addr = self.program.getAddressFactory().getAddress(function_address)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {function_address}"})
        fn = self._function_manager.getFunctionContaining(addr)
        if fn is None:
            return json.dumps({"error": f"No function at {function_address}"})
        index = int(index)
        if index < 0 or index >= fn.getParameterCount():
            return json.dumps({"error": (f"Index {index} out of range -- {fn.getName()} has "
                               f"{fn.getParameterCount()} parameter(s) (0-{fn.getParameterCount()-1})")})

        target = fn.getParameter(index)
        # Ghidra exposes an implicit thiscall receiver as parameter 0, but
        # Function.updateFunction() keeps that auto-parameter in addition to
        # any user ParameterImpl we add.  Rebuilding a method through the
        # generic index-0 path therefore duplicates the receiver (observed
        # live on CArchive::ReadBiochemArchiveString: this, archive,
        # output_string).  Force the caller onto the receiver-specific tool;
        # explicit stack parameters remain indexable and safe here.
        if index == 0 and bool(target.isAutoParameter()):
            return json.dumps({
                "error": (f"Parameter 0 of {fn.getName()} is Ghidra's implicit 'this' receiver; "
                          "use set_this_type for its type, or pass the explicit parameter index "
                          "(usually 1) to set_parameter. This guard prevents duplicate receivers."),
                "code": "implicit_this_requires_set_this_type",
                "function": fn.getName(),
                "receiver_type": str(target.getDataType().getName()),
                "explicit_parameter_count": max(0, fn.getParameterCount() - 1),
            })
        old_name, old_type_name = target.getName(), str(target.getDataType().getName())
        dt = target.getDataType()
        if new_type:
            dtm = self._program.getDataTypeManager()
            dt = self._resolve_type_by_name(dtm, new_type)
            if dt is None:
                return json.dumps({"error": f"Cannot resolve type: {new_type}"})
        name = new_name or old_name

        ParameterImpl = jpype.JClass('ghidra.program.model.listing.ParameterImpl')
        ArrayList = jpype.JClass('java.util.ArrayList')
        FunctionUpdateType = jpype.JClass('ghidra.program.model.listing.Function$FunctionUpdateType')

        new_params = ArrayList()
        for i in range(fn.getParameterCount()):
            if i == index:
                new_params.add(ParameterImpl(name, dt, self._program, SourceType.USER_DEFINED))
            else:
                new_params.add(fn.getParameter(i))

        try:
            fn.updateFunction(fn.getCallingConventionName(), fn.getReturn(), new_params,
                               FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, True,
                               SourceType.USER_DEFINED)
        except Exception as e:
            return json.dumps({"error": f"updateFunction failed: {e}"})

        verified, sample = (self._verify_field_access_resolved(fn, dt, variable_name=name)
                            if new_type else (None, None))

        return json.dumps({
            "status": "ok", "function": fn.getName(), "index": index,
            "old_name": old_name, "new_name": name,
            "old_type": old_type_name, "new_type": str(dt.getName()),
            "decompile_shows_field_access": verified, "sample_line": sample,
        })

    def repair_function_parameters(self, function_address, parameters):
        """Replace a function's complete listing-level parameter list.

        This is intentionally narrower than a general signature editor: it is
        for repairing a known ABI after a mistaken per-index edit inserted an
        extra parameter.  The caller supplies the complete ordered list,
        including an explicit ``this`` entry when the function is __thiscall.
        """
        return self._with_transaction(
            "repair_function_parameters",
            lambda: self._do_repair_function_parameters(function_address, parameters))

    def _do_repair_function_parameters(self, function_address, parameters):
        addr = self.program.getAddressFactory().getAddress(function_address)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {function_address}"})
        fn = self._function_manager.getFunctionContaining(addr)
        if fn is None:
            return json.dumps({"error": f"No function at {function_address}"})
        if not isinstance(parameters, list) or not parameters:
            return json.dumps({"error": "parameters must be a non-empty ordered list"})

        ParameterImpl = jpype.JClass('ghidra.program.model.listing.ParameterImpl')
        ArrayList = jpype.JClass('java.util.ArrayList')
        FunctionUpdateType = jpype.JClass('ghidra.program.model.listing.Function$FunctionUpdateType')
        SourceType = jpype.JClass('ghidra.program.model.symbol.SourceType')
        dtm = self._program.getDataTypeManager()
        new_params = ArrayList()
        normalized = []
        for i, spec in enumerate(parameters):
            if not isinstance(spec, dict) or not spec.get("name") or not spec.get("type"):
                return json.dumps({"error": f"parameter {i} must contain non-empty name and type"})
            dt = self._resolve_type_by_name(dtm, spec["type"])
            if dt is None:
                return json.dumps({"error": f"Cannot resolve type for parameter {i}: {spec['type']}"})
            name = str(spec["name"])
            new_params.add(ParameterImpl(name, dt, self._program, SourceType.USER_DEFINED))
            normalized.append({"name": name, "type": str(dt.getName())})

        try:
            fn.updateFunction(fn.getCallingConventionName(), fn.getReturn(), new_params,
                              FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, True,
                              SourceType.USER_DEFINED)
        except Exception as e:
            return json.dumps({"error": f"repair updateFunction failed: {e}"})
        return json.dumps({"status": "ok", "function": fn.getName(),
                           "calling_convention": str(fn.getCallingConventionName()),
                           "parameters": normalized})

    def set_return_type(self, function_address, new_type):
        """Set a concrete return datatype without parsing a C prototype."""
        return self._with_transaction(
            "set_return_type",
            lambda: self._do_set_return_type(function_address, new_type))

    def _do_set_return_type(self, function_address, new_type):
        if not new_type:
            return json.dumps({"error": "new_type is required"})
        addr = self.program.getAddressFactory().getAddress(function_address)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {function_address}"})
        fn = self._function_manager.getFunctionContaining(addr)
        if fn is None:
            return json.dumps({"error": f"No function at {function_address}"})
        dt = self._resolve_type_by_name(self._program.getDataTypeManager(), new_type)
        if dt is None:
            return json.dumps({"error": f"Cannot resolve return type: {new_type}"})
        old_type = str(fn.getReturnType().getName())
        try:
            fn.setReturnType(dt, SourceType.USER_DEFINED)
        except Exception as e:
            return json.dumps({"error": f"setReturnType failed: {e}"})
        actual_type = str(fn.getReturnType().getName())
        if actual_type != str(dt.getName()):
            return json.dumps({"error": "Return type did not persist",
                               "requested_type": str(dt.getName()),
                               "actual_type": actual_type})
        return json.dumps({"status": "ok", "function": fn.getName(),
                           "old_type": old_type, "new_type": actual_type})

    def edit_structure_field(self, struct_name, category, operation, offset,
                              field_name="", field_type="", field_size=0,
                              expected_size=0, allow_resize=False, dry_run=False):
        """Add, rename, retype, or clear ONE field of an EXISTING structure
        at a specific byte offset, without rebuilding the whole struct --
        P2 item 4 from docs/GRAPHIFY_GHIDRA_RE_INTEGRATION_PLAN.md
        ('structure ... field add-update-delete'). Complements
        create_structure/create_structure_from_offsets, which always
        replace the WHOLE field list.
        The default is deliberately fixed-size: add/retype refuse any
        operation which would change the structure length or shift a later
        component.  This protects RE layouts whose total size is confirmed.
        Set allow_resize=true only after explicitly reviewing the returned
        dry-run plan; use create_structure_from_offsets(replace=true) for a
        deliberate whole-layout rewrite.
        operation='rename': change only the field name at `offset` (must
        exactly match an existing component's start offset), keeping its
        type/size.
        operation='retype': change the field type (and optionally name) at
        `offset` -- new field_size may differ from the old one; this
        SHIFTS every later field's effective position by the same delta
        unless the new size exactly matches the old one, so prefer
        matching sizes when the intent is 'just a more precise type for
        the same bytes'.
        operation='clear': revert the field at `offset` back to opaque
        Undefined bytes (Structure.clearComponent) -- does NOT shrink the
        struct, just un-names/un-types that span, the safe default for
        'delete' in an RE context where total struct size is usually a
        hard-won confirmed fact that should never accidentally shrink as
        a side effect of removing one field's name."""
        args = (struct_name, category, operation, offset, field_name, field_type,
                field_size, expected_size, allow_resize, dry_run)
        if dry_run:
            return self._do_edit_structure_field(*args)
        return self._with_transaction("edit_structure_field",
            lambda: self._do_edit_structure_field(*args))

    def _do_edit_structure_field(self, struct_name, category, operation, offset,
                                  field_name="", field_type="", field_size=0,
                                  expected_size=0, allow_resize=False, dry_run=False):
        dtm = self._program.getDataTypeManager()
        CategoryPath = jpype.JClass('ghidra.program.model.data.CategoryPath')
        # ``get_type_exact_facts`` reports a datatype's canonical *type*
        # path (e.g. /MapData), whereas this endpoint historically expected
        # its containing *category* (/).  Accept both forms.  Try the input
        # as a category first so an actual /MapData/MapData type remains
        # unambiguous; only then interpret a final /<struct_name> component
        # as the canonical type path returned by that read-only endpoint.
        raw_category = str(category or "/").strip() or "/"
        normalized_category = (raw_category if raw_category.startswith("/")
                               else "/" + raw_category)
        normalized_category = normalized_category.rstrip("/") or "/"
        cat_path = CategoryPath(normalized_category)
        struct = dtm.getDataType(cat_path, struct_name)
        if struct is None and normalized_category.rsplit("/", 1)[-1] == struct_name:
            parent_category = normalized_category.rsplit("/", 1)[0] or "/"
            cat_path = CategoryPath(parent_category)
            struct = dtm.getDataType(cat_path, struct_name)
        if struct is None:
            return json.dumps({
                "error": f"Structure '{struct_name}' not found in category or type path '{category}'",
                "hint": ("Pass either the containing category (for example '/') or the "
                         "canonical type.path returned by get_type_exact_facts (for example '/MapData')."),
            })
        offset = int(offset)
        old_size = struct.getLength()
        if expected_size and old_size != int(expected_size):
            return json.dumps({"error": (f"Structure '{struct_name}' is {old_size} bytes, not "
                               f"the expected {int(expected_size)} bytes; re-read its layout before editing"),
                               "old_size": old_size})

        def plan(**details):
            details.update({"status": "dry_run", "struct": struct_name,
                            "old_size": old_size, "allow_resize": bool(allow_resize)})
            return json.dumps(details)

        def fixed_size_error(new_component_size, reason):
            return json.dumps({
                "error": (f"Refusing {operation} at 0x{offset:x}: {reason}. "
                          "This fixed-size edit would change component boundaries; "
                          "first call with dry_run=true, then either set allow_resize=true "
                          "or rebuild the confirmed layout with create_structure_from_offsets(replace=true)."),
                "old_size": old_size, "requested_component_size": new_component_size,
            })

        if operation == "add":
            if not field_type:
                return json.dumps({"error": "field_type is required for operation='add'"})
            dt = self._resolve_type_by_name(dtm, field_type)
            if dt is None:
                return json.dumps({"error": f"Cannot resolve type: {field_type}"})
            size = int(field_size) or dt.getLength()
            comp = struct.getComponentAt(offset)
            component_size = comp.getLength() if comp is not None and comp.getOffset() == offset else None
            if not allow_resize:
                if comp is None or comp.getOffset() != offset:
                    return fixed_size_error(size, "there is no existing component starting there")
                if not str(comp.getDataType().getName()).lower().startswith("undefined"):
                    return json.dumps({"error": (f"Refusing add at 0x{offset:x}: an existing non-gap field "
                                       f"'{comp.getFieldName() or comp.getDefaultFieldName()}' starts there; "
                                       "use rename or retype instead")})
                if size != component_size:
                    return fixed_size_error(size, f"the existing gap component is {component_size} bytes")
            if dry_run:
                return plan(operation="add", offset=offset, field_name=field_name,
                            field_type=str(dt.getName()), component_size=size,
                            predicted_new_size=(old_size if not allow_resize else "Ghidra-dependent"))
            try:
                # replaceAtOffset is size-preserving when replacing the exact
                # undefined component above.  insertAtOffset remains available
                # only behind the explicit resize escape hatch.
                if not allow_resize and component_size == size:
                    comp = struct.replaceAtOffset(offset, dt, size, field_name or None, None)
                else:
                    comp = struct.insertAtOffset(offset, dt, size, field_name or None, None)
            except Exception as e:
                return json.dumps({"error": f"insertAtOffset failed: {e}"})
            return json.dumps({"status": "ok", "operation": "add", "struct": struct_name,
                               "offset": offset, "field_name": str(comp.getFieldName() or ""),
                               "old_size": old_size, "new_size": struct.getLength(),
                               "size_delta": struct.getLength() - old_size})

        comp = struct.getComponentAt(offset)
        if comp is None or comp.getOffset() != offset:
            return json.dumps({"error": (f"No field starts exactly at offset {offset} "
                               f"(0x{offset:x}) in '{struct_name}' -- use operation='add' for a "
                               f"new field, or check get_struct_layout for existing offsets.")})

        if operation == "rename":
            if not field_name:
                return json.dumps({"error": "field_name is required for operation='rename'"})
            old_name = str(comp.getFieldName() or comp.getDefaultFieldName())
            if dry_run:
                return plan(operation="rename", offset=offset, old_name=old_name,
                            new_name=field_name, predicted_new_size=old_size)
            comp.setFieldName(field_name)
            return json.dumps({"status": "ok", "operation": "rename", "struct": struct_name,
                               "offset": offset, "old_name": old_name, "new_name": field_name})

        if operation == "retype":
            if not field_type:
                return json.dumps({"error": "field_type is required for operation='retype'"})
            dt = self._resolve_type_by_name(dtm, field_type)
            if dt is None:
                return json.dumps({"error": f"Cannot resolve type: {field_type}"})
            size = int(field_size) or dt.getLength()
            old_type = str(comp.getDataType().getName())
            name = field_name or str(comp.getFieldName() or "")
            old_component_size = comp.getLength()
            if not allow_resize and size != old_component_size:
                return fixed_size_error(size, f"the existing component is {old_component_size} bytes")
            if dry_run:
                return plan(operation="retype", offset=offset, old_type=old_type,
                            new_type=str(dt.getName()), old_component_size=old_component_size,
                            requested_component_size=size,
                            predicted_new_size=(old_size if size == old_component_size else "Ghidra-dependent"))
            try:
                new_comp = struct.replaceAtOffset(offset, dt, size, name or None, None)
            except Exception as e:
                return json.dumps({"error": f"replaceAtOffset failed: {e}"})
            return json.dumps({"status": "ok", "operation": "retype", "struct": struct_name,
                               "offset": offset, "old_type": old_type,
                               "new_type": str(new_comp.getDataType().getName()),
                               "old_size": old_size, "new_size": struct.getLength(),
                               "size_delta": struct.getLength() - old_size})

        if operation == "clear":
            ordinal = comp.getOrdinal()
            old_name = str(comp.getFieldName() or comp.getDefaultFieldName())
            if dry_run:
                return plan(operation="clear", offset=offset, cleared_field_name=old_name,
                            predicted_new_size=old_size)
            struct.clearComponent(ordinal)
            return json.dumps({"status": "ok", "operation": "clear", "struct": struct_name,
                               "offset": offset, "cleared_field_name": old_name,
                               "old_size": old_size, "new_size": struct.getLength(),
                               "size_delta": struct.getLength() - old_size})

        return json.dumps({"error": f"Unknown operation '{operation}' -- use add, rename, retype, or clear"})

    def create_enum(self, name, category, values_json, size=4, replace=False):
        """Create or explicitly replace an enum data type -- P2 item 5 from
        docs/GRAPHIFY_GHIDRA_RE_INTEGRATION_PLAN.md ('enum, typedef, and
        function-pointer type construction'), previously entirely
        unsupported -- no existing tool could build any of these 3 type
        kinds.
        values_json: JSON string or object of {"NAME": int_value, ...},
        e.g. '{"TYPE_NULL": 1, "TYPE_ANY": 2, "TYPE_OLD": 3}' -- directly
        matches the shape of many already-confirmed packed-flag/type-code
        fields found by RE this project (DyRuleElement.type_code,
        VqDescriptor.type, etc) that have so far only been documented as
        magic-number comments, never as a real queryable Ghidra type.
        size: byte width of the enum's underlying storage (1/2/4/8).
        replace: refuse to modify an existing type by default.  Set True only
        after reviewing the returned existing member list; replacement uses
        DataTypeManager.replaceDataType so uses of the old type are updated
        rather than deleted and recreated."""
        return self._with_transaction("create_enum",
            lambda: self._do_create_enum(name, category, values_json, size, replace))

    def _existing_enum_summary(self, existing):
        """Return the exact stored enum members for a guarded update error."""
        members = []
        for value in existing.getValues():
            members.append({"name": str(existing.getName(value)), "value": int(value)})
        members.sort(key=lambda item: (item["value"], item["name"]))
        return {"size": existing.getLength(), "members": members}

    def _do_create_enum(self, name, category, values_json, size=4, replace=False):
        import json as _json
        try:
            values = _json.loads(values_json) if isinstance(values_json, str) else values_json
        except (TypeError, ValueError) as exc:
            return json.dumps({"error": f"values must be a JSON object: {exc}"})
        if not isinstance(values, dict) or not values:
            return json.dumps({"error": "values must be a non-empty JSON object of enum-name to integer value"})
        if int(size) not in (1, 2, 4, 8):
            return json.dumps({"error": "size must be one of 1, 2, 4, or 8 bytes"})
        for member_name, member_value in values.items():
            if not isinstance(member_name, str) or not member_name.strip():
                return json.dumps({"error": "every enum member name must be a non-empty string"})
            # bool is an int subclass in Python but is never an intentional
            # recovered enum value; reject it rather than silently storing 0/1.
            if isinstance(member_value, bool) or not isinstance(member_value, int):
                return json.dumps({"error": f"enum member '{member_name}' must have an integer value"})
        dtm = self._program.getDataTypeManager()
        CategoryPath = jpype.JClass('ghidra.program.model.data.CategoryPath')
        Enum = jpype.JClass('ghidra.program.model.data.Enum')
        EnumDataType = jpype.JClass('ghidra.program.model.data.EnumDataType')
        DataTypeConflictHandler = jpype.JClass('ghidra.program.model.data.DataTypeConflictHandler')
        cat_path = CategoryPath(category if str(category).startswith("/") else "/" + category)

        existing = dtm.getDataType(cat_path, name)
        # Resolved program types are EnumDataTypeDB, which implements the
        # Enum interface but is not an instance of the transient
        # EnumDataType class used to construct a replacement.
        if existing is not None and not Enum.class_.isInstance(existing):
            return json.dumps({
                "error": (f"Type '{name}' already exists in category '{category}' but is not "
                          "an enum; refusing to replace it with an enum."),
            })
        if existing is not None and not replace:
            return json.dumps({
                "error": (f"Enum '{name}' already exists in category '{category}'. "
                          f"Refusing to overwrite -- review its exact members below and pass "
                          f"replace=true only if this replacement is intentional."),
                "existing": self._existing_enum_summary(existing),
            })

        enum = EnumDataType(cat_path, name, int(size))
        for k, v in values.items():
            enum.add(str(k), int(v))
        if existing is not None:
            resolved = dtm.replaceDataType(existing, enum, True)
            return json.dumps({"status": "ok", "name": name, "category": category,
                               "size": resolved.getLength(), "count": len(values),
                               "resolved_name": str(resolved.getName()),
                               "replaced_existing": True})
        resolved = dtm.addDataType(enum, DataTypeConflictHandler.DEFAULT_HANDLER)
        return json.dumps({"status": "ok", "name": name, "category": category,
                           "size": resolved.getLength(), "count": len(values),
                           "resolved_name": str(resolved.getName()),
                           "replaced_existing": False})

    def create_typedef(self, name, category, base_type):
        """Create a typedef aliasing an existing type under a new name --
        P2 item 5. base_type may itself be a pointer expression (e.g.
        'CVoiceFields *') -- resolved the same way set_this_type/
        set_local_variable_type resolve type strings."""
        return self._with_transaction("create_typedef",
            lambda: self._do_create_typedef(name, category, base_type))

    def _do_create_typedef(self, name, category, base_type):
        dtm = self._program.getDataTypeManager()
        CategoryPath = jpype.JClass('ghidra.program.model.data.CategoryPath')
        TypedefDataType = jpype.JClass('ghidra.program.model.data.TypedefDataType')
        DataTypeConflictHandler = jpype.JClass('ghidra.program.model.data.DataTypeConflictHandler')
        cat_path = CategoryPath(category if str(category).startswith("/") else "/" + category)

        existing = dtm.getDataType(cat_path, name)
        if existing is not None:
            return json.dumps({
                "error": f"Type '{name}' already exists in category '{category}' -- pick a "
                         f"different name.",
            })

        base_dt = self._resolve_type_by_name(dtm, base_type)
        if base_dt is None:
            return json.dumps({"error": f"Cannot resolve base type: {base_type}"})

        td = TypedefDataType(cat_path, name, base_dt)
        resolved = dtm.addDataType(td, DataTypeConflictHandler.DEFAULT_HANDLER)
        return json.dumps({"status": "ok", "name": name, "category": category,
                           "base_type": base_type, "size": resolved.getLength(),
                           "resolved_name": str(resolved.getName())})

    def create_function_pointer_type(self, name, category, return_type, param_types_json,
                                      calling_convention=""):
        """Create a named function-pointer typedef -- P2 item 5, the 3rd
        and last previously entirely-unsupported type-construction kind.
        Directly useful for this project's own recurring pattern of
        confirmed vtable-slot/callback signatures
        (e.g. '(**(code**)*param_1)(0x2000008,0x15b,...)'-style raw calls
        seen throughout this session's decompiles) that currently have no
        queryable type at all, only a plate comment or nothing.
        return_type: e.g. 'void', 'int', 'CVoiceFields *'.
        param_types_json: JSON list of type-name strings, e.g.
        '["int", "char *", "CUtilityFields *"]' (order = parameter order;
        names are auto-generated param1/param2/...).
        calling_convention: optional, e.g. '__thiscall'/'__stdcall' --
        left unset (Ghidra default) if omitted."""
        return self._with_transaction("create_function_pointer_type",
            lambda: self._do_create_function_pointer_type(
                name, category, return_type, param_types_json, calling_convention))

    def _do_create_function_pointer_type(self, name, category, return_type, param_types_json,
                                          calling_convention=""):
        import json as _json
        param_types = _json.loads(param_types_json) if isinstance(param_types_json, str) else param_types_json
        dtm = self._program.getDataTypeManager()
        CategoryPath = jpype.JClass('ghidra.program.model.data.CategoryPath')
        FunctionDefinitionDataType = jpype.JClass('ghidra.program.model.data.FunctionDefinitionDataType')
        ParameterDefinitionImpl = jpype.JClass('ghidra.program.model.data.ParameterDefinitionImpl')
        TypedefDataType = jpype.JClass('ghidra.program.model.data.TypedefDataType')
        PointerDataType = jpype.JClass('ghidra.program.model.data.PointerDataType')
        DataTypeConflictHandler = jpype.JClass('ghidra.program.model.data.DataTypeConflictHandler')
        cat_path = CategoryPath(category if str(category).startswith("/") else "/" + category)

        existing = dtm.getDataType(cat_path, name)
        if existing is not None:
            return json.dumps({
                "error": f"Type '{name}' already exists in category '{category}' -- pick a "
                         f"different name.",
            })

        ret_dt = self._resolve_type_by_name(dtm, return_type)
        if ret_dt is None:
            return json.dumps({"error": f"Cannot resolve return type: {return_type}"})

        arg_defs = []
        for i, pt in enumerate(param_types):
            pdt = self._resolve_type_by_name(dtm, pt)
            if pdt is None:
                return json.dumps({"error": f"Cannot resolve parameter {i} type: {pt}"})
            arg_defs.append(ParameterDefinitionImpl(f"param{i + 1}", pdt, None))

        func_def = FunctionDefinitionDataType(cat_path, name + "_sig")
        func_def.setReturnType(ret_dt)
        ArrayList = jpype.JClass('java.util.ArrayList')
        arg_array = jpype.JArray(ParameterDefinitionImpl)(len(arg_defs))
        for i, a in enumerate(arg_defs):
            arg_array[i] = a
        func_def.setArguments(arg_array)
        if calling_convention:
            try:
                GenericCallingConvention = jpype.JClass('ghidra.program.model.data.GenericCallingConvention')
                conv = GenericCallingConvention.getGenericCallingConvention(calling_convention.replace("__", ""))
                if conv is not None:
                    func_def.setGenericCallingConvention(conv)
            except Exception:
                pass

        ptr_dt = PointerDataType(func_def)
        td = TypedefDataType(cat_path, name, ptr_dt)
        resolved = dtm.addDataType(td, DataTypeConflictHandler.DEFAULT_HANDLER)
        return json.dumps({"status": "ok", "name": name, "category": category,
                           "return_type": return_type, "param_count": len(param_types),
                           "resolved_name": str(resolved.getName())})

    def create_function(self, address_str, name=""):
        """Create a function at the given address if none exists."""
        return self._with_transaction("create_function", lambda: self._do_create_function(address_str, name))

    def _do_create_function(self, address_str, name=""):
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})
        existing = self._function_manager.getFunctionContaining(addr)
        if existing and existing.getEntryPoint().equals(addr):
            return json.dumps({"status": "exists", "name": existing.getName(), "address": address_str})

        # Disassemble at this address first
        try:
            if self._listing.getInstructionAt(addr) is None:
                self._flat.disassemble(addr)
        except Exception:
            pass

        # Create function
        from ghidra.app.cmd.function import CreateFunctionCmd
        from ghidra.util.task import ConsoleTaskMonitor
        mon = ConsoleTaskMonitor()
        cmd = CreateFunctionCmd(addr)
        cmd.applyTo(self._program, mon)
        fn = self._function_manager.getFunctionAt(addr)
        if fn:
            if name:
                fn.setName(name, SourceType.USER_DEFINED)
            return json.dumps({
                "status": "ok",
                "name": fn.getName(),
                "address": address_str,
                "body": str(fn.getBody()),
            })
        return json.dumps({"error": "Failed to create function"})

    def delete_function(self, address_str):
        """Remove the Function definition whose ENTRY POINT is exactly
        address_str, leaving its instructions/bytes untouched
        (FunctionManager.removeFunction). Previously the MCP mutation surface
        had create_function but no way to delete one.

        Primary uses (both from classify_function_inventory's taxonomy):
          - retire a confirmed compiler artifact (EH cleanup funclet) from the
            inventory;
          - REPAIR a function Ghidra wrongly split into a truncated entry plus
            an orphaned fall-through tail: delete_function BOTH pieces, then
            create_function on the real (earlier, aligned) entry --
            CreateFunctionCmd recomputes the body by following flow and
            re-absorbs the tail into one function.

        Refuses to act unless a function starts EXACTLY at address_str; it will
        not delete a function that merely CONTAINS the address (it reports that
        function's real entry instead). Bytes are never modified, so a mistaken
        delete is recoverable with create_function at the same entry."""
        return self._with_transaction(
            "delete_function", lambda: self._do_delete_function(address_str))

    def _do_delete_function(self, address_str):
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})
        fn = self._function_manager.getFunctionAt(addr)
        if fn is None:
            containing = self._function_manager.getFunctionContaining(addr)
            if containing is not None:
                return json.dumps({
                    "error": (f"No function starts exactly at {address_str}; the "
                              f"address is inside '{containing.getName()}' (entry "
                              f"{containing.getEntryPoint()}). Refusing to delete a "
                              f"merely-containing function -- pass its exact entry "
                              f"point if that is what you meant."),
                    "containing_function": containing.getName(),
                    "containing_entry": str(containing.getEntryPoint()),
                })
            return json.dumps({"error": f"No function at {address_str}"})
        name = fn.getName()
        body = str(fn.getBody())
        removed = self._function_manager.removeFunction(addr)
        if removed:
            return json.dumps({
                "status": "ok",
                "deleted": name,
                "address": address_str,
                "former_body": body,
                "note": ("Only the Function definition was removed; instructions/bytes "
                         "are intact. To MERGE a split function, now call create_function "
                         "at the real (earlier, aligned) entry point to recompute its body "
                         "from flow. To undo, create_function at this same address."),
            })
        return json.dumps({
            "error": f"removeFunction returned false for '{name}' at {address_str}"})

    def resolve_vtable(self, address_str, count):
        """Resolve a C++ vtable's function pointers into real Function objects.

        analyzeAll() only creates Functions at addresses reached by a direct
        CALL instruction -- vtable-only-referenced methods (reached solely
        through a function-pointer table) never get one. This reads `count`
        consecutive target-endian, program-pointer-sized values starting at address_str and
        create_function's each one that doesn't already exist."""
        return self._with_transaction("resolve_vtable", lambda: self._do_resolve_vtable(address_str, count))

    _VTABLE_COMMENT_BEGIN = "--- MCP vtable begin ---"
    _VTABLE_COMMENT_END = "--- MCP vtable end ---"

    def _replace_vtable_comment_block(self, addr, entries):
        """Update only the managed portion of a plate comment."""
        import re
        lines = [self._VTABLE_COMMENT_BEGIN, "function pointer slots:"]
        for index, entry in enumerate(entries):
            target = entry.get("address") or "null"
            name = entry.get("name") or "<unresolved>"
            lines.append(f"[{index:02d}] {target} {name}")
        lines.append(self._VTABLE_COMMENT_END)
        managed = "\n".join(lines)
        existing = self._listing.getComment(CodeUnit.PLATE_COMMENT, addr) or ""
        pattern = (re.escape(self._VTABLE_COMMENT_BEGIN) + r".*?" +
                   re.escape(self._VTABLE_COMMENT_END))
        if re.search(pattern, existing, flags=re.DOTALL):
            updated = re.sub(pattern, managed, existing, flags=re.DOTALL)
        elif existing:
            updated = existing.rstrip() + "\n\n" + managed
        else:
            updated = managed
        self._listing.setComment(addr, CodeUnit.PLATE_COMMENT, updated)
        return updated

    def _do_resolve_vtable(self, address_str, count):
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})
        if count <= 0 or count > 4096:
            return json.dumps({"error": "count must be between 1 and 4096"})

        POINTER_SIZE = self.program.getDefaultPointerSize()
        try:
            raw, actual = self._read_raw_bytes(addr, count * POINTER_SIZE)
        except Exception as e:
            return json.dumps({"error": f"Failed to read vtable bytes: {str(e)}"})

        if actual != count * POINTER_SIZE:
            return json.dumps({"error": "Incomplete pointer table", "requested_bytes": count * POINTER_SIZE, "actual_bytes": actual})

        from ghidra.app.cmd.function import CreateFunctionCmd
        from ghidra.util.task import ConsoleTaskMonitor
        mon = ConsoleTaskMonitor()

        entries = []
        n_entries = actual // POINTER_SIZE
        for i in range(n_entries):
            chunk = raw[i * POINTER_SIZE:(i + 1) * POINTER_SIZE]
            ptr_val = int.from_bytes(chunk, 'big' if self.program.getLanguage().isBigEndian() else 'little')
            if ptr_val == 0:
                entries.append({"address": None, "name": None, "was_new": False})
                continue

            target_str = f"0x{ptr_val:x}"
            target_addr = self.program.getAddressFactory().getAddress(target_str)
            if target_addr is None:
                entries.append({"address": target_str, "name": None, "was_new": False,
                                 "error": "invalid address"})
                continue

            block = self.program.getMemory().getBlock(target_addr)
            processor = str(self.program.getLanguage().getProcessor()).lower()
            if block is None or not block.isInitialized() or not block.isExecute():
                entries.append({"address": target_str, "name": None, "was_new": False,
                                "error": "target is not initialized executable memory"})
                continue
            if processor == "68000" and ptr_val % 2:
                entries.append({"address": target_str, "name": None, "was_new": False,
                                "error": "unaligned 68k instruction address"})
                continue
            if self._function_manager.getFunctionContaining(target_addr) is not None and self._function_manager.getFunctionAt(target_addr) is None:
                entries.append({"address": target_str, "name": None, "was_new": False,
                                "error": "target lies inside an existing function"})
                continue
            fn = self._function_manager.getFunctionAt(target_addr)
            was_new = False
            if fn is None:
                try:
                    if self._listing.getInstructionAt(target_addr) is None:
                        self._flat.disassemble(target_addr)
                except Exception:
                    pass
                cmd = CreateFunctionCmd(target_addr)
                cmd.applyTo(self._program, mon)
                fn = self._function_manager.getFunctionAt(target_addr)
                was_new = fn is not None

            if fn is not None:
                entries.append({"address": target_str, "name": fn.getName(), "was_new": was_new})
            else:
                entries.append({"address": target_str, "name": None, "was_new": False,
                                 "error": "Failed to create function"})

        record = {
            "kind": "function_pointer_table",
            "address": address_str,
            "slot_count": n_entries,
            "entries": [{"index": i, **entry} for i, entry in enumerate(entries)],
        }
        self._replace_vtable_comment_block(addr, entries)
        return json.dumps({
            "status": "ok",
            "vtable_address": address_str,
            "pointer_size": POINTER_SIZE,
            "byte_order": "big" if self.program.getLanguage().isBigEndian() else "little",
            "count": n_entries,
            "entries": entries,
            "ndjson_record": json.dumps(record, separators=(",", ":")),
        })

    def find_vtable_candidates(self, start_str, end_str, min_slots=3):
        """Bounded read-only function-pointer run scan; does not infer C++ ABI."""
        factory = self.program.getAddressFactory()
        start, end = factory.getAddress(start_str), factory.getAddress(end_str)
        if start is None or end is None or start.getAddressSpace() != end.getAddressSpace():
            return json.dumps({"error": "start/end must be valid addresses in the same space"})
        length = end.subtract(start) + 1
        if length <= 0 or length > 1048576:
            return json.dumps({"error": "scan range must be between 1 and 1048576 bytes"})
        if min_slots < 2 or min_slots > 4096:
            return json.dumps({"error": "min_slots must be between 2 and 4096"})
        width = int(self.program.getDefaultPointerSize())
        order = 'big' if self.program.getLanguage().isBigEndian() else 'little'
        is_68k = str(self.program.getLanguage().getProcessor()).lower() == '68000'
        alignment = 2 if is_68k else width
        memory = self.program.getMemory()
        candidates = []
        read_errors = []
        # Scan each possible table alignment independently. Mac 68k longs can
        # start at word-aligned addresses; four-byte alignment would miss them.
        for phase in range(0, width, alignment):
            run = []
            def flush():
                if len(run) >= min_slots:
                    candidates.append({"address": run[0]["slot_address"],
                                       "slot_count": len(run), "entries": list(run),
                                       "evidence": {"exact_function_entries": len(run)},
                                       "classification": "function_pointer_run"})
                run.clear()
            first = (-start.getOffset() + phase) % width
            for delta in range(first, length - width + 1, width):
                slot = start.add(delta)
                try:
                    raw, actual = self._read_raw_bytes(slot, width)
                    if actual != width:
                        flush()
                        continue
                    value = int.from_bytes(raw, order)
                    target = factory.getAddress(f"0x{value:x}")
                    block = memory.getBlock(target)
                    fn = self._function_manager.getFunctionAt(target)
                    if value == 0 or (is_68k and value % 2) or block is None or not block.isInitialized() or not block.isExecute() or fn is None:
                        flush()
                        continue
                    run.append({"slot_address": str(slot), "raw_hex": raw.hex(),
                                "address": str(target), "name": fn.getName()})
                except Exception as exc:
                    if len(read_errors) < 8:
                        read_errors.append({"address": str(slot), "error": str(exc)})
                    flush()
            flush()
        return json.dumps({"read_errors": read_errors, "start": start_str, "end": end_str,
                           "pointer_size": width, "byte_order": order,
                           "alignment": alignment, "candidates": candidates,
                           "note": "Exact function-entry runs only; repeated targets retained. No vtable, RTTI or compiler ABI inferred. Zero slots treated as null; no pointer masking or relocation performed."})

    def trace_vtable_assignments(self, function_address):
        """Report lexical writes of static vtable addresses to this+N.

        Tracks ANY constant displacement, not just this+0: 90s MSVC's
        multiple-inheritance ABI writes one vtable pointer per base class,
        each at its own fixed non-zero offset within the object (e.g.
        `this[0]=&VtableA; this[3]=&VtableB; this[5]=&VtableC` for a
        3-interface composite object -- confirmed concretely in this project,
        see docs/RE_FLEXTALK_COM_VTABLE_SWEEP_2026-07-12.md's VoiceEnum/
        VoiceAttribEnum/VoiceEnumRoot composite object). A this+0-only match
        silently drops every secondary-interface assignment in exactly this
        shape, which is common, not an edge case, in this codebase."""
        import re
        addr = self.program.getAddressFactory().getAddress(function_address)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {function_address}"})
        fn = self._function_manager.getFunctionContaining(addr)
        if fn is None:
            return json.dumps({"error": f"No function at {function_address}"})
        aliases, register_values, assignments = {"ECX"}, {}, []
        memory = self._program.getMemory()
        iterator = self._listing.getInstructions(fn.getBody(), True)
        immediate = re.compile(r"^0x([0-9a-fA-F]+)$")
        register = re.compile(r"^(E[A-Z]{2})$")
        memory_disp = re.compile(
            r"\[\s*(E[A-Z]{2})\s*(?:([+-])\s*(0x[0-9a-fA-F]+|[0-9]+)\s*)?\]", re.I)
        while iterator.hasNext():
            instr = iterator.next()
            mnemonic = instr.getMnemonicString().upper()
            operands = [str(instr.getDefaultOperandRepresentation(i)).strip()
                        for i in range(instr.getNumOperands())]
            if len(operands) >= 2 and mnemonic in ("MOV", "LEA"):
                dest, src = operands[0], operands[1]
                dest_reg = register.match(dest.upper())
                src_reg = register.match(src.upper())
                value = immediate.match(src)
                if dest_reg and value:
                    register_values[dest_reg.group(1)] = f"0x{int(value.group(1), 16):x}"
                elif dest_reg and src_reg and src_reg.group(1) in register_values:
                    register_values[dest_reg.group(1)] = register_values[src_reg.group(1)]
                if dest_reg and src_reg and src_reg.group(1) in aliases:
                    aliases.add(dest_reg.group(1))
                elif dest_reg and mnemonic == "LEA" and any(
                        f"[{alias}" in src.upper().replace(" ", "") for alias in aliases):
                    aliases.add(dest_reg.group(1))
                match = memory_disp.search(dest)
                if mnemonic == "MOV" and match and match.group(1).upper() in aliases:
                    if match.group(3) is None:
                        this_offset = 0
                    else:
                        disp = int(match.group(3), 16) if match.group(3).lower().startswith("0x") \
                            else int(match.group(3))
                        this_offset = -disp if match.group(2) == "-" else disp
                    source = register_values.get(src.upper())
                    if value:
                        source = f"0x{int(value.group(1), 16):x}"
                    if source:
                        target = self.program.getAddressFactory().getAddress(source)
                        assignments.append({"write_index": len(assignments),
                            "address": str(instr.getAddress()), "instruction": str(instr),
                            "destination": dest, "this_offset": this_offset,
                            "vtable_address": source,
                            "source_kind": "immediate" if value else "register",
                            "is_readable_memory": target is not None and memory.contains(target)})
        # A composite (multiply-inherited) object has one independent "final"
        # write PER offset, not one for the whole function -- mark the
        # lexically-last assignment at each distinct this_offset.
        last_by_offset = {}
        for a in assignments:
            last_by_offset[a["this_offset"]] = a
        for a in last_by_offset.values():
            a["final_assignment"] = True
        return json.dumps({"function": fn.getName(), "entry": str(fn.getEntryPoint()),
                           "assignments": assignments,
                           "distinct_this_offsets": sorted(last_by_offset.keys()),
                           "note": "Instruction/listing order only; branches and runtime paths are not evaluated. "
                                   "final_assignment is per this_offset, not global -- a composite object has "
                                   "multiple independent 'final' writes, one per base-class vtable slot."})

    def create_vtable_type(self, name, vtable_address, slots_json, category="Vtables", replace=False):
        return self._with_transaction("create_vtable_type", lambda:
            self._do_create_vtable_type(name, vtable_address, slots_json, category, replace))

    def _do_create_vtable_type(self, name, vtable_address, slots_json, category="Vtables", replace=False):
        """Create typed vtable and minimal object/vptr structures, then apply the table."""
        slots = json.loads(slots_json) if isinstance(slots_json, str) else slots_json
        if not name or not isinstance(slots, list) or not slots:
            return json.dumps({"error": "name and non-empty slots are required"})
        table_addr = self.program.getAddressFactory().getAddress(vtable_address)
        if table_addr is None:
            return json.dumps({"error": f"Invalid vtable_address: {vtable_address}"})
        indexed = {}
        for slot in slots:
            try:
                index, function_address = int(slot["index"]), slot["function_address"]
            except (KeyError, TypeError, ValueError):
                return json.dumps({"error": "each slot needs integer index and function_address"})
            if index < 0 or index in indexed:
                return json.dumps({"error": "slot indexes must be unique non-negative integers"})
            fn_addr = self.program.getAddressFactory().getAddress(function_address)
            fn = self._function_manager.getFunctionAt(fn_addr) if fn_addr is not None else None
            if fn is None:
                return json.dumps({"error": f"slot {index} has no Function at {function_address}; resolve it first"})
            indexed[index] = fn
        dtm = self._program.getDataTypeManager()
        CategoryPath = jpype.JClass('ghidra.program.model.data.CategoryPath')
        StructureDataType = jpype.JClass('ghidra.program.model.data.StructureDataType')
        FunctionDefinitionDataType = jpype.JClass('ghidra.program.model.data.FunctionDefinitionDataType')
        PointerDataType = jpype.JClass('ghidra.program.model.data.PointerDataType')
        DataTypeConflictHandler = jpype.JClass('ghidra.program.model.data.DataTypeConflictHandler')
        Undefined = jpype.JClass('ghidra.program.model.data.Undefined')
        path = CategoryPath(category if str(category).startswith("/") else "/" + category)
        pointer_size = self.program.getDefaultPointerSize()
        table_name, object_name = name + "_vtable", name
        table = StructureDataType(path, table_name, 0)
        for index in range(max(indexed) + 1):
            fn = indexed.get(index)
            if fn is None:
                field_dt = PointerDataType(Undefined.getUndefinedDataType(1), pointer_size, dtm)
                field_name = f"slot_{index}_unknown"
            else:
                # Ghidra's FunctionDB is not exposed to JPype as the
                # FunctionSignature interface overload.  Build from the
                # concrete Function, then give the definition its stable
                # category/name before adding it to the manager.
                signature = FunctionDefinitionDataType(fn, False)
                signature.setCategoryPath(path)
                signature.setName(f"{name}_slot_{index}")
                signature = dtm.addDataType(signature, DataTypeConflictHandler.DEFAULT_HANDLER)
                field_dt = PointerDataType(signature, pointer_size, dtm)
                field_name = f"slot_{index}_{fn.getName()}"
            table.add(field_dt, pointer_size, field_name, None)
        def install(struct, type_name):
            existing = dtm.getDataType(path, type_name)
            if replace and existing is not None:
                return dtm.replaceDataType(existing, struct, True)
            return dtm.addDataType(struct, DataTypeConflictHandler.DEFAULT_HANDLER)
        table = install(table, table_name)
        obj = StructureDataType(path, object_name, 0)
        obj.add(PointerDataType(table, pointer_size, dtm), pointer_size, "vptr", None)
        obj = install(obj, object_name)
        end = table_addr.add(table.getLength() - 1)
        self._listing.clearCodeUnits(table_addr, end, False)
        self._listing.createData(table_addr, table)
        return json.dumps({"status": "ok", "vtable_address": vtable_address,
                           "vtable_type": table.getName(), "object_type": obj.getName(),
                           "slot_count": max(indexed) + 1,
                           "note": "Apply the returned object_type to an object pointer to propagate indirect-call types."})

    def create_label(self, address_str, name):
        """Create a label/symbol at the given address."""
        return self._with_transaction("create_label", lambda: self._do_create_label(address_str, name))

    def _do_create_label(self, address_str, name):
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})
        sym_table = self.program.getSymbolTable()
        sym_table.createLabel(addr, name, SourceType.USER_DEFINED)
        return json.dumps({"status": "ok", "label": name, "address": address_str})

    def set_data_type(self, address_str, type_name):
        """Set the data type at a given address."""
        return self._with_transaction("set_data_type", lambda: self._do_set_data_type(address_str, type_name))

    def _scalar_type_alias_map(self):
        """Single shared alias table mapping common C/C99-stdint/size-name
        spellings to Ghidra's own base DataTypes. Used by BOTH the bare
        scalar path and the array-element path in _do_set_data_type --
        previously these were two separate, inconsistent tables (the array
        path's fallback dict was missing most unsigned/stdint aliases,
        e.g. 'uint32_t[2605]' failed with "Cannot resolve type" even
        though bare 'uint32_t'... wait, even bare 'int32_t' worked but
        'uint32_t' never did, on EITHER path -- fixed here by covering the
        full signed/unsigned x 8/16/32/64-bit matrix in one place)."""
        _FDT = jpype.JClass('ghidra.program.model.data.FloatDataType')
        _DDT = jpype.JClass('ghidra.program.model.data.DoubleDataType')
        _IDT = jpype.JClass('ghidra.program.model.data.IntegerDataType')
        _SDT = jpype.JClass('ghidra.program.model.data.ShortDataType')
        _BDT = jpype.JClass('ghidra.program.model.data.ByteDataType')
        _LDT = jpype.JClass('ghidra.program.model.data.LongDataType')
        _CDT = jpype.JClass('ghidra.program.model.data.CharDataType')
        _BoDT = jpype.JClass('ghidra.program.model.data.BooleanDataType')
        _UDT = jpype.JClass('ghidra.program.model.data.Undefined')
        _VDT = jpype.JClass('ghidra.program.model.data.VoidDataType')
        _WDT = jpype.JClass('ghidra.program.model.data.WordDataType')          # unsigned 16-bit
        _DWDT = jpype.JClass('ghidra.program.model.data.DWordDataType')        # unsigned 32-bit
        _QWDT = jpype.JClass('ghidra.program.model.data.QWordDataType')        # unsigned 64-bit
        _UCDT = jpype.JClass('ghidra.program.model.data.UnsignedCharDataType') # unsigned 8-bit
        _LLDT = jpype.JClass('ghidra.program.model.data.LongLongDataType')     # signed 64-bit

        return {
            'float': _FDT, 'float32': _FDT,
            'double': _DDT, 'float64': _DDT,
            'void': _VDT,
            'bool': _BoDT, 'boolean': _BoDT,
            'undefined': _UDT, 'unknown': _UDT,
            'char': _CDT,
            # signed 8-bit
            'int8': _CDT, 'int8_t': _CDT, 'i8': _CDT, 'signed char': _CDT,
            # unsigned 8-bit
            'byte': _BDT, 'uint8': _UCDT, 'uint8_t': _UCDT, 'u8': _UCDT,
            'uchar': _UCDT, 'unsigned char': _UCDT,
            # signed 16-bit
            'short': _SDT, 'int16': _SDT, 'int16_t': _SDT, 'i16': _SDT,
            # unsigned 16-bit
            'word': _WDT, 'uint16': _WDT, 'uint16_t': _WDT, 'u16': _WDT,
            'ushort': _WDT, 'unsigned short': _WDT,
            # signed 32-bit
            'int': _IDT, 'int32': _IDT, 'int32_t': _IDT, 'i32': _IDT,
            'signed': _IDT, 'signed int': _IDT, 'long': _IDT,
            # unsigned 32-bit
            'dword': _DWDT, 'uint32': _DWDT, 'uint32_t': _DWDT, 'u32': _DWDT,
            'uint': _DWDT, 'unsigned': _DWDT, 'unsigned int': _DWDT,
            'unsigned long': _DWDT, 'ulong': _DWDT,
            # signed 64-bit
            'int64': _LLDT, 'int64_t': _LLDT, 'i64': _LLDT,
            'longlong': _LLDT, 'long long': _LLDT,
            # unsigned 64-bit
            'qword': _QWDT, 'uint64': _QWDT, 'uint64_t': _QWDT, 'u64': _QWDT,
            'ulonglong': _QWDT, 'unsigned long long': _QWDT,
        }

    def _do_set_data_type(self, address_str, type_name):
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})
        from ghidra.util.task import ConsoleTaskMonitor
        mon = ConsoleTaskMonitor()

        type_name_clean = type_name.strip()
        alias_map = self._scalar_type_alias_map()
        dt = None

        # ── Step 1: shared alias table for bare scalar names ──
        cls = alias_map.get(type_name_clean)
        if cls is not None:
            dt = cls()

        # ── Step 2: Use DataTypeParser for everything else ──
        # This handles native Ghidra type names, array syntax
        # (float[1998], byte[49]) when the base name is one DataTypeParser
        # already knows, and any custom/structure type by name.
        if dt is None:
            try:
                _dtm = self._program.getDataTypeManager()
                parser = DataTypeParser(_dtm, _dtm, None, DataTypeParserAllowedTypes.ALL)
                dt = parser.parse(type_name_clean)
            except Exception as e:
                logger.warning("DataTypeParser failed for '%s': %s", type_name_clean, e)

        # DataTypeParser does not reliably resolve a custom root-category
        # structure when it is written as a pointer expression (CImage *),
        # even though the bare type and a hand-created typedef resolve.  Use
        # the shared resolver as a fallback: it performs the exact datatype
        # lookup first, then constructs the requested pointer/array type.
        if dt is None:
            _dtm = self._program.getDataTypeManager()
            dt = self._resolve_type_by_name(_dtm, type_name_clean)

        # ── Step 3: If it _looks_ like an array, resolve the base type
        # through the SAME alias table (fixes the bug where 'dword[N]'
        # worked but 'uint32_t[N]' didn't -- the array path used to have
        # its own separate, much smaller fallback dict missing nearly
        # every unsigned/stdint alias covered in Step 1). ──
        if dt is None:
            import re
            m = re.match(r'(\w+(?:\s+\w+)?)\[(\d+)\]', type_name_clean)
            if m:
                base_type = m.group(1).strip()
                count = int(m.group(2))
                base_cls = alias_map.get(base_type)
                base_dt = base_cls() if base_cls is not None else None
                if base_dt is None:
                    try:
                        _dtm = self._program.getDataTypeManager()
                        parser = DataTypeParser(_dtm, _dtm, None, DataTypeParserAllowedTypes.ALL)
                        base_dt = parser.parse(base_type)
                    except Exception:
                        base_dt = None
                if base_dt:
                    ArrayDataType = jpype.JClass('ghidra.program.model.data.ArrayDataType')
                    dt = ArrayDataType(base_dt, count, base_dt.getLength())
        if dt is None:
            known_names = sorted(set(self._scalar_type_alias_map().keys()))
            return json.dumps({
                "error": f"Cannot resolve type: {type_name}",
                "hint": ("Not a recognized alias or Ghidra native type name. Known aliases "
                         "(bare or as ARRAYNAME[N]): " + ", ".join(known_names) +
                         ". Custom/structure type names (e.g. from create_structure) are also "
                         "accepted by name, including pointer and array forms such as 'CImage *' "
                         "and 'CLobe[32]'."),
            })
        listing = self._listing
        # Clear the full range to avoid conflicts with existing data
        end_addr = addr.add(dt.getLength() - 1)
        listing.clearCodeUnits(addr, end_addr, False)
        listing.createData(addr, dt)
        return json.dumps({"status": "ok", "address": address_str, "type": type_name})

    def get_comments(self, address_str):
        """Get all comments (pre/post/eol/plate) at a given address."""
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})
        cu = self._listing.getCodeUnitAt(addr)
        if cu is None:
            return json.dumps({"error": "No code unit at address"})
        result = {}
        for ctype, label in [(CodeUnit.PLATE_COMMENT, "plate"),
                              (CodeUnit.PRE_COMMENT, "pre"),
                              (CodeUnit.EOL_COMMENT, "eol"),
                              (CodeUnit.POST_COMMENT, "post")]:
            val = cu.getComment(ctype)
            if val:
                result[label] = val
        return json.dumps({"address": address_str, "comments": result})

    def create_structure(self, name, category, fields_json, replace=False):
        """Create a structure data type in the program's data type manager.
        fields_json: JSON string of [{"name": str, "type": str, "size": int}, ...]
        replace: if True and a structure with this name already exists,
        update it in place (REPLACE_HANDLER) instead of creating a
        ".conflict" duplicate -- use this when re-deriving a structure's
        layout from newly-confirmed RE (e.g. fields that were previously
        lumped as an opaque byte blob and have since been individually
        confirmed)."""
        return self._with_transaction("create_structure",
            lambda: self._do_create_structure(name, category, fields_json, replace))

    def _build_struct_from_fields(self, cat_path, name, fields, type_parser):
        """Shared struct-building helper: builds and returns an unresolved
        StructureDataType from a [{"name","type","size"}, ...] field list.
        Does not touch the DataTypeManager -- caller decides add/replace."""
        StructureDataType = jpype.JClass('ghidra.program.model.data.StructureDataType')
        Undefined = jpype.JClass('ghidra.program.model.data.Undefined')
        struct = StructureDataType(cat_path, name, 0)
        for f in fields:
            fname = f.get("name", "field")
            fsize = f.get("size", 1)
            ftype = f.get("type")
            dt = None
            if ftype:
                try:
                    dt = type_parser.parse(ftype)
                except Exception:
                    dt = None
            if dt is None:
                dt = Undefined.getUndefinedDataType(fsize)
            struct.add(dt, fsize, fname, None)
        return struct

    def _existing_struct_summary(self, existing):
        """Compact field list for an already-resolved Structure, used in
        the create_structure overwrite-guard error so the caller can see
        what's there without a separate get_struct_layout round trip."""
        fields = []
        for comp in existing.getComponents():
            fields.append({
                "offset": comp.getOffset(),
                "name": str(comp.getFieldName() or comp.getDefaultFieldName()),
                "type": str(comp.getDataType().getName()),
                "length": comp.getLength(),
            })
        return {"size": existing.getLength(), "fields": fields}

    def _class_structure_shadow_guard(self, dtm, cat_path, name, replace):
        """Refuse the common accidental ``/Class/Class`` shadow type.

        Ghidra stores a class-associated structure named ``Skeleton`` at
        datatype path ``/Skeleton``: its category is the root and its name
        is ``Skeleton``.  An analyst naturally supplying category
        ``/Skeleton`` and name ``Skeleton`` would otherwise create a second,
        unrelated ``/Skeleton/Skeleton`` type.  That is never a useful
        default for the MCP mutation surface and makes an existence probe
        unexpectedly create a type.

        Keep deliberately nested same-name types possible behind
        ``replace=True``; the safe, normal creation path must instead return
        the canonical root type for inspection.
        """
        if replace:
            return None
        normalized_category = str(cat_path.getPath()).rstrip("/") or "/"
        if normalized_category != "/" + str(name):
            return None
        CategoryPath = jpype.JClass('ghidra.program.model.data.CategoryPath')
        canonical = dtm.getDataType(CategoryPath("/"), name)
        if canonical is None:
            return None
        return json.dumps({
            "error": (f"Refusing to create nested shadow type '{normalized_category}/{name}': "
                      f"canonical root datatype '/{name}' already exists "
                      f"({canonical.getLength()} bytes). Use category='/' to inspect or update "
                      f"the class structure; only use this nested path with replace=true when "
                      f"you intentionally require a distinct nested type."),
            "canonical": self._existing_struct_summary(canonical),
        })

    def _do_create_structure(self, name, category, fields_json, replace=False):
        import json
        fields = json.loads(fields_json) if isinstance(fields_json, str) else fields_json
        dtm = self._program.getDataTypeManager()
        CategoryPath = jpype.JClass('ghidra.program.model.data.CategoryPath')
        DataTypeConflictHandler = jpype.JClass('ghidra.program.model.data.DataTypeConflictHandler')

        cat_path = CategoryPath(category if str(category).startswith("/") else "/" + category)
        type_parser = DataTypeParser(dtm, dtm, None, DataTypeParserAllowedTypes.ALL)

        shadow_error = self._class_structure_shadow_guard(dtm, cat_path, name, replace)
        if shadow_error is not None:
            return shadow_error

        # Explicit existence check BEFORE touching the DataTypeManager at all.
        # Ghidra's addDataType(..., DEFAULT_HANDLER) conflict-resolution
        # behavior for same-name/same-category structures is not something
        # this server should rely on implicitly -- confirmed this session
        # (2026-07-12) that repeated create_structure calls for the same
        # name silently updated the type in place even with replace left at
        # its default False, with no warning beyond an easy-to-miss
        # replaced_existing flag on the RESULT (which itself was only
        # trustworthy after the fact). Two near-miss overwrites of
        # already-confirmed structs (DotrFrame, DyRuleElement) happened this
        # way. Now: replace=False ALWAYS refuses if a type with this
        # name+category already exists, full stop, before any Java-level
        # conflict handler runs.
        existing = dtm.getDataType(cat_path, name)
        if existing is not None and not replace:
            return json.dumps({
                "error": (f"Structure '{name}' already exists in category '{category}' "
                          f"({existing.getLength()} bytes, {existing.getNumComponents()} fields). "
                          f"Refusing to overwrite -- pass replace=true if this is intentional "
                          f"(e.g. re-deriving a layout from newly-confirmed RE), or check the "
                          f"existing fields first (get_struct_layout / get_type_exact_facts) "
                          f"in case it's already the canonical struct from a prior/ported pass."),
                "existing": self._existing_struct_summary(existing),
            })

        struct = self._build_struct_from_fields(cat_path, name, fields, type_parser)

        if existing is not None and replace:
            # replaceDataType is the real in-place-update API; addDataType's
            # conflict handler only resolves conflicts between types added
            # in the SAME call, it does not update an already-resolved type.
            resolved = dtm.replaceDataType(existing, struct, True)
            return json.dumps({
                "status": "ok",
                "name": name,
                "category": category,
                "size": struct.getLength(),
                "resolved_name": str(resolved.getName()),
                "replaced_existing": True,
            })

        resolved = dtm.addDataType(struct, DataTypeConflictHandler.DEFAULT_HANDLER)
        return json.dumps({
            "status": "ok",
            "name": name,
            "category": category,
            "size": struct.getLength(),
            "resolved_name": str(resolved.getName()),
            "replaced_existing": False,
        })

    def create_structure_from_offsets(self, name, category, fields_json, total_size, replace=False):
        """Like create_structure, but fields_json is a SPARSE list of
        [{"offset": int, "name": str, "type": str}, ...] -- explicit gap
        fields to pad the byte layout are computed and inserted
        automatically, server-side, instead of requiring the caller to
        hand-compute every gap (which this project did with an external
        Python script twice this session for large structs -- CVoiceFields,
        CUtilityFields -- and is exactly the kind of arithmetic step where a
        mistake is easy and expensive to catch late). "type" may be omitted
        for a field to fall back to an appropriately-sized undefined type
        inferred from the NEXT field's offset (or total_size for the last
        field) -- but explicit sizing via a real type name is preferred
        wherever the field's size is actually known.
        Raises an error (not a silent truncation) on any field whose
        computed extent would overlap the next field, or that exceeds
        total_size -- overlap is exactly the mistake this tool exists to
        prevent."""
        return self._with_transaction("create_structure_from_offsets",
            lambda: self._do_create_structure_from_offsets(name, category, fields_json, total_size, replace))

    def _do_create_structure_from_offsets(self, name, category, fields_json, total_size, replace=False):
        import json
        sparse = json.loads(fields_json) if isinstance(fields_json, str) else fields_json
        sparse = sorted(sparse, key=lambda f: f["offset"])

        dtm = self._program.getDataTypeManager()
        CategoryPath = jpype.JClass('ghidra.program.model.data.CategoryPath')
        cat_path = CategoryPath(category if str(category).startswith("/") else "/" + category)
        type_parser = DataTypeParser(dtm, dtm, None, DataTypeParserAllowedTypes.ALL)

        shadow_error = self._class_structure_shadow_guard(dtm, cat_path, name, replace)
        if shadow_error is not None:
            return shadow_error

        # Resolve each explicit field's size up front (from its type where
        # given, else deferred to gap-fill below) so overlap can be checked
        # before any Undefined/gap type is synthesized.
        resolved_fields = []
        for i, f in enumerate(sparse):
            off = f["offset"]
            ftype = f.get("type")
            fsize = f.get("size")
            if ftype and fsize is None:
                try:
                    parsed = type_parser.parse(ftype)
                    if parsed is not None:
                        fsize = parsed.getLength()
                except Exception:
                    pass
            resolved_fields.append({"offset": off, "name": f.get("name", f"field_{off:x}"),
                                     "type": ftype, "size": fsize})

        dense = []
        cursor = 0
        for i, f in enumerate(resolved_fields):
            off = f["offset"]
            if off < cursor:
                return json.dumps({
                    "error": (f"Field '{f['name']}' at offset 0x{off:x} overlaps the previous "
                              f"field, which ends at 0x{cursor:x}. Refusing to build an "
                              f"overlapping struct -- fix the offset or the previous field's "
                              f"size and retry."),
                })
            if off > cursor:
                gap = off - cursor
                dense.append({"name": f"gap_{cursor:06x}_{off - 1:06x}", "type": "undefined1", "size": gap})
            fsize = f["size"]
            if fsize is None:
                # Size unknown: infer from the gap to the NEXT field (or
                # total_size for the last one) rather than silently
                # defaulting to 1 byte, which would be a much easier
                # mistake to miss than an explicit error.
                next_off = resolved_fields[i + 1]["offset"] if i + 1 < len(resolved_fields) else total_size
                fsize = next_off - off
                if fsize <= 0:
                    return json.dumps({
                        "error": (f"Field '{f['name']}' at offset 0x{off:x} has no explicit size "
                                  f"and no positive gap to the next field/total_size to infer one "
                                  f"from -- pass an explicit 'size' or 'type' for this field."),
                    })
            dense.append({"name": f["name"], "type": f["type"] or "undefined1", "size": fsize})
            cursor = off + fsize

        if cursor > total_size:
            return json.dumps({
                "error": (f"Fields extend to offset 0x{cursor:x}, past the declared "
                          f"total_size 0x{total_size:x}. Fix total_size or the field list."),
            })
        if cursor < total_size:
            dense.append({"name": f"gap_{cursor:06x}_{total_size - 1:06x}",
                          "type": "undefined1", "size": total_size - cursor})

        existing = dtm.getDataType(cat_path, name)
        if existing is not None and not replace:
            return json.dumps({
                "error": (f"Structure '{name}' already exists in category '{category}' "
                          f"({existing.getLength()} bytes, {existing.getNumComponents()} fields). "
                          f"Refusing to overwrite -- pass replace=true if intentional."),
                "existing": self._existing_struct_summary(existing),
            })

        struct = self._build_struct_from_fields(cat_path, name, dense, type_parser)

        if existing is not None and replace:
            resolved = dtm.replaceDataType(existing, struct, True)
            return json.dumps({
                "status": "ok", "name": name, "category": category,
                "size": struct.getLength(), "resolved_name": str(resolved.getName()),
                "replaced_existing": True, "fields_generated": len(dense),
            })

        DataTypeConflictHandler = jpype.JClass('ghidra.program.model.data.DataTypeConflictHandler')
        resolved = dtm.addDataType(struct, DataTypeConflictHandler.DEFAULT_HANDLER)
        return json.dumps({
            "status": "ok", "name": name, "category": category,
            "size": struct.getLength(), "resolved_name": str(resolved.getName()),
            "replaced_existing": False, "fields_generated": len(dense),
        })

    @staticmethod
    def _decompile_token_statement(token):
        """Return the smallest useful C fragment containing *token*."""
        node = token
        while node is not None:
            try:
                if node.getClass().getSimpleName() == "ClangStatement":
                    return " ".join(str(node).split())
                node = node.Parent()
            except Exception:
                break
        return str(token.getText())

    @staticmethod
    def _instruction_record(instruction):
        operands = []
        for index in range(instruction.getNumOperands()):
            rep = instruction.getDefaultOperandRepresentation(index)
            if rep:
                operands.append(rep)
        return {
            "address": str(instruction.getMinAddress()),
            "mnemonic": instruction.getMnemonicString(),
            "operands": ", ".join(operands),
        }

    def _instruction_encoded_values(self, instruction):
        """Collect raw scalar/address values represented by one instruction.

        These come from the listing instruction and its references, never from
        decompiler output or symbols.  Both signed and unsigned scalar forms
        are retained so negative displacements compare correctly.
        """
        values = set()
        for index in range(instruction.getNumOperands()):
            try:
                objects = instruction.getOpObjects(index)
            except Exception:
                objects = []
            for obj in objects:
                try:
                    if isinstance(obj, jpype.JClass(
                            "ghidra.program.model.scalar.Scalar")):
                        values.add(int(obj.getSignedValue()))
                        values.add(int(obj.getUnsignedValue()))
                    elif isinstance(obj, jpype.JClass(
                            "ghidra.program.model.address.Address")):
                        values.add(int(obj.getOffset()))
                except Exception:
                    continue
        try:
            for ref in self._ref_manager.getReferencesFrom(
                    instruction.getMinAddress()):
                target = ref.getToAddress()
                if target is not None and target.isMemoryAddress():
                    values.add(int(target.getOffset()))
        except Exception:
            pass
        return values

    def _symbol_for_decompile_token(self, token):
        """Resolve a named scalar token to its actual listing symbol."""
        text = str(token.getText()).strip()
        if not text:
            return None
        candidates = [text]
        if "::" in text:
            candidates.append(text.rsplit("::", 1)[-1])
        symbol_table = self.program.getSymbolTable()
        for name in candidates:
            try:
                for symbol in symbol_table.getSymbols(name):
                    address = symbol.getAddress()
                    if address is not None and address.isMemoryAddress():
                        return symbol
            except Exception:
                continue
        return None

    def _find_symbol_source_instruction(self, function, use_instruction,
                                        storage_address, max_back=16):
        """Find the nearby raw instruction that loaded a scalar symbol.

        A scalar symbol token is commonly attached to the later instruction
        that consumes or stores the loaded value.  Its varnode PC address can
        point at an INDIRECT p-code operation rather than the machine load, so
        do a small, deterministic listing-only search for the varnode's memory
        address instead.
        """
        storage_value = int(storage_address.getOffset())
        instruction = use_instruction
        for _ in range(max_back + 1):
            encoded_values = self._instruction_encoded_values(instruction)
            if storage_value in encoded_values:
                return instruction, encoded_values
            previous = self._listing.getInstructionBefore(
                instruction.getMinAddress())
            if (previous is None or
                    not function.getBody().contains(previous.getMinAddress())):
                break
            instruction = previous
        return None, None

    def _instruction_reads_address(self, instruction, address):
        """Whether raw listing references show a data read from address."""
        target_value = int(address.getOffset())
        try:
            for ref in self._ref_manager.getReferencesFrom(
                    instruction.getMinAddress()):
                target = ref.getToAddress()
                if (target is not None and target.isMemoryAddress() and
                        int(target.getOffset()) == target_value and
                        ref.getReferenceType().isRead()):
                    return True
        except Exception:
            pass
        return False

    @staticmethod
    def _has_scalar_cast_before(tokens, index):
        """Recognize the explicit scalar-cast shape from the known artifact."""
        start = max(0, index - 12)
        prefix = "".join(str(tokens[i].getText()) for i in range(start, index))
        scalar_type = (r"(?:undefined\d+|u?int(?:8|16|32|64)_t|"
                       r"u?char|u?short|u?int|u?long|byte|word|dword|qword)")
        return re.search(r"\(\s*" + scalar_type + r"\s*\)\s*$", prefix,
                         re.IGNORECASE) is not None

    def verify_decompile_constants(self, address_str):
        """Cross-check suspicious decompiler tokens against raw instructions.

        The operation is read-only and bounded by the function's decompiler
        token count.  Only large constants used in address arithmetic and
        named symbols explicitly cast to scalar integer types are checked;
        this keeps ordinary propagated constants and legitimate function
        pointers out of the result set.
        """
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor

        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})
        func = self._function_manager.getFunctionContaining(addr)
        if func is None:
            return json.dumps({"error": f"No function at {address_str}"})

        decomp = DecompInterface()
        decomp.openProgram(self.program)
        try:
            res = decomp.decompileFunction(func, 0, ConsoleTaskMonitor())
            if not res or not res.getDecompiledFunction():
                return json.dumps({"error": "Decompilation failed"})
            markup = res.getCCodeMarkup()
            if markup is None:
                return json.dumps({"error": "Decompiler returned no C markup"})

            code = res.getDecompiledFunction().getC()
            token_iter = markup.tokenIterator(True)
            tokens = []
            while token_iter.hasNext():
                tokens.append(token_iter.next())

            flagged = []
            seen = set()
            checked = 0
            checked_by_kind = {
                kind: 0 for kind in self._DECOMPILE_CONSTANT_DETECTORS
            }
            arithmetic_ops = {"INT_ADD", "INT_SUB", "PTRADD", "PTRSUB"}
            for index, token in enumerate(tokens):
                token_addr = token.getMinAddress()
                if token_addr is None or not func.getBody().contains(token_addr):
                    continue
                token_instruction = self._listing.getInstructionContaining(token_addr)
                if token_instruction is None:
                    continue

                claimed_value = None
                claimed_values = None
                kind = None
                instruction = token_instruction
                encoded_values = None
                symbol_address = None
                op = token.getPcodeOp()
                op_name = str(op.getMnemonic()) if op is not None else ""

                scalar = token.getScalar()
                if scalar is not None and op_name in arithmetic_ops:
                    unsigned = int(scalar.getUnsignedValue())
                    signed = int(scalar.getSignedValue())
                    if min(abs(unsigned), abs(signed)) > 0x10000:
                        claimed_values = {unsigned, signed}
                        claimed_value = str(token.getText())
                        kind = "large_arithmetic_constant"

                if kind is None and self._has_scalar_cast_before(tokens, index):
                    symbol = self._symbol_for_decompile_token(token)
                    if (symbol is not None and
                            symbol.getSymbolType() == SymbolType.FUNCTION and
                            op_name not in {"CALL", "CALLIND"}):
                        varnode = token.getVarnode()
                        storage = varnode.getAddress() if varnode is not None else None
                        if storage is not None and storage.isMemoryAddress():
                            symbol_address = symbol.getAddress()
                            claimed_values = {int(symbol_address.getOffset())}
                            claimed_value = str(token.getText())
                            kind = "function_symbol_used_as_scalar"
                            instruction, encoded_values = \
                                self._find_symbol_source_instruction(
                                    func, token_instruction, storage)

                if kind is None or instruction is None:
                    continue

                if encoded_values is None:
                    encoded_values = self._instruction_encoded_values(instruction)
                # A value-less instruction cannot support a meaningful direct
                # comparison.  Skipping it avoids calling ordinary register
                # arithmetic a mismatch merely because it has no immediate.
                if not encoded_values:
                    continue
                checked += 1
                checked_by_kind[kind] += 1
                kind_mismatch = (
                    kind == "function_symbol_used_as_scalar" and
                    symbol_address is not None and
                    self._instruction_reads_address(instruction,
                                                    symbol_address)
                )
                if claimed_values.intersection(encoded_values) and not kind_mismatch:
                    continue

                key = (str(instruction.getMinAddress()), kind, claimed_value)
                if key in seen:
                    continue
                seen.add(key)
                detector_status = self._DECOMPILE_CONSTANT_DETECTORS[kind]
                flagged.append({
                    "decompile_text": self._decompile_token_statement(token),
                    "claimed_value": claimed_value,
                    "candidate_kind": kind,
                    "detector_confidence": detector_status["confidence"],
                    "detector_validation_status":
                        detector_status["validation_status"],
                    "token_address": str(instruction.getMinAddress()),
                    "real_instruction": self._instruction_record(instruction),
                    "encoded_values": [
                        (f"-0x{-value:x}" if value < 0 else f"0x{value:x}")
                        for value in sorted(encoded_values)
                    ],
                    "verdict": "mismatch",
                    "mismatch_reason": (
                        "function symbol used as scalar data read"
                        if kind_mismatch else
                        "decompiler value absent from raw instruction"
                    ),
                })

            return json.dumps({
                "address": str(func.getEntryPoint()),
                "function": func.getName(),
                "has_overlap_warning": "WARNING:" in code,
                "tokens_scanned": len(tokens),
                "candidates_checked": checked,
                "candidates_checked_by_kind": checked_by_kind,
                "detector_status": self._DECOMPILE_CONSTANT_DETECTORS,
                "flagged": flagged,
                "clean": not flagged,
            })
        finally:
            decomp.dispose()

    def search_function_disassembly(self, address_str, mnemonic=None,
                                    operand_pattern=None,
                                    operand_match_mode="substring",
                                    max_results=200):
        """Search decoded instructions in one function without returning its
        complete disassembly.  Operand rendering intentionally matches
        disassemble_function so callers can promote a proven manual search
        directly into this bounded query."""
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})
        fn = self._function_manager.getFunctionContaining(addr)
        if fn is None:
            return json.dumps({"error": f"No function at {address_str}"})

        try:
            max_results = max(1, min(int(max_results), 1000))
        except (TypeError, ValueError):
            return json.dumps({"error": "max_results must be an integer"})
        mode = str(operand_match_mode or "substring").strip().lower()
        if mode not in ("substring", "regex"):
            return json.dumps({"error": "operand_match_mode must be substring or regex"})

        mnemonic_filter = str(mnemonic).strip().upper() if mnemonic else ""
        operand_filter = str(operand_pattern) if operand_pattern else ""
        operand_regex = None
        if operand_filter and mode == "regex":
            try:
                import re
                operand_regex = re.compile(operand_filter)
            except re.error as exc:
                return json.dumps({"error": f"Invalid operand regex: {exc}"})

        addr_set = fn.getBody()
        body_start = addr_set.getMinAddress()
        body_end = addr_set.getMaxAddress()
        body_size = int(body_end.getOffset() - body_start.getOffset()) + 1
        if body_size <= 0:
            return json.dumps({"error": "Empty function body"})
        from jpype import JArray as jp_JArray
        body_bytes = jp_JArray(jpype.JByte, 1)(body_size)
        self._program.getMemory().getBytes(body_start, body_bytes)

        total_scanned = total_matched = 0
        matches = []
        instr_iter = self._listing.getInstructions(addr_set, True)
        while instr_iter.hasNext():
            instr = instr_iter.next()
            total_scanned += 1
            mnemonic_text = instr.getMnemonicString()
            ops = []
            try:
                for i in range(instr.getNumOperands()):
                    rep = instr.getDefaultOperandRepresentation(i)
                    if rep:
                        ops.append(rep)
            except Exception:
                pass
            operands = ", ".join(ops)
            if mnemonic_filter and not mnemonic_text.upper().startswith(mnemonic_filter):
                continue
            if operand_filter:
                if operand_regex is not None:
                    if not operand_regex.search(operands):
                        continue
                elif operand_filter not in operands:
                    continue
            total_matched += 1
            if len(matches) >= max_results:
                continue
            ia = instr.getMinAddress()
            try:
                length = instr.getLength()
                start_off = int(ia.getOffset() - body_start.getOffset())
                instr_raw = body_bytes[start_off:start_off + length]
                bytes_str = " ".join(f"{b & 0xFF:02x}" for b in instr_raw)
            except Exception:
                bytes_str = ""
            matches.append({"address": str(ia), "bytes": bytes_str,
                            "mnemonic": mnemonic_text, "operands": operands})
        return json.dumps({
            "function": fn.getName(), "entry": str(fn.getEntryPoint()),
            "body": str(fn.getBody()), "mnemonic": mnemonic_filter or None,
            "operand_pattern": operand_filter or None,
            "operand_match_mode": mode, "max_results": max_results,
            "total_scanned": total_scanned, "total_matched": total_matched,
            "returned_count": len(matches), "truncated": total_matched > len(matches),
            "instructions": matches,
        })

    def disassemble_range(self, address_str, count=20):
        """Decode a bounded forward run of real instructions from any address.

        Unlike disassemble_function this is deliberately not function-bounded:
        it is for inspecting a local instruction run from an arbitrary code
        location, including unowned code or a function's middle/tail.
        """
        addr = self.program.getAddressFactory().getAddress(address_str)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {address_str}"})
        try:
            count = max(1, min(int(count), 1000))
        except (TypeError, ValueError):
            return json.dumps({"error": "count must be an integer"})

        instruction = self._listing.getInstructionContaining(addr)
        resolution = "containing" if instruction is not None else "next"
        if instruction is None:
            instruction = self._listing.getInstructionAfter(addr)
        if instruction is None:
            return json.dumps({"error": f"No instruction at or after {address_str}"})

        result = []
        while instruction is not None and len(result) < count:
            ia = instruction.getMinAddress()
            ops = []
            try:
                for i in range(instruction.getNumOperands()):
                    rep = instruction.getDefaultOperandRepresentation(i)
                    if rep:
                        ops.append(rep)
            except Exception:
                pass
            try:
                # Reuse the server's established Memory.getBytes wrapper;
                # it handles the Java return count and mapped-memory bounds.
                raw, actual = self._read_raw_bytes(ia, int(instruction.getLength()))
                bytes_str = " ".join(f"{b:02x}" for b in raw[:actual])
            except Exception:
                bytes_str = ""
            result.append({"address": str(ia), "bytes": bytes_str,
                           "mnemonic": instruction.getMnemonicString(),
                           "operands": ", ".join(ops)})
            instruction = self._listing.getInstructionAfter(ia)
        return json.dumps({
            "requested_address": address_str,
            "resolved_start_address": result[0]["address"],
            "resolution": resolution, "requested_count": count,
            "returned_count": len(result), "has_more": instruction is not None,
            "next_address": str(instruction.getMinAddress()) if instruction is not None else None,
            "instructions": result,
        })

    @staticmethod
    def _parse_tool_integer(value, name):
        """Parse decimal or 0x-prefixed integer arguments used by pure RE helpers."""
        if isinstance(value, bool):
            raise ValueError(f"{name} must be an integer")
        try:
            return int(value, 0) if isinstance(value, str) else int(value)
        except (TypeError, ValueError):
            raise ValueError(f"{name} must be a decimal or 0x-prefixed integer")

    def translate_subfield_mask(self, byte_offset, bit_mask, element_size=4):
        """Translate a byte-local bit mask into its containing element mask."""
        try:
            byte_offset = self._parse_tool_integer(byte_offset, "byte_offset")
            bit_mask = self._parse_tool_integer(bit_mask, "bit_mask")
            element_size = self._parse_tool_integer(element_size, "element_size")
        except ValueError as exc:
            return json.dumps({"error": str(exc)})
        if element_size <= 0:
            return json.dumps({"error": "element_size must be positive"})
        if byte_offset < 0 or byte_offset >= element_size:
            return json.dumps({"error": "byte_offset must be within the element"})
        if bit_mask < 0:
            return json.dumps({"error": "bit_mask must be non-negative"})
        shift = ((element_size - 1 - byte_offset) if self.program.getLanguage().isBigEndian() else byte_offset) * 8
        full_mask = bit_mask << shift
        width = max(1, element_size * 2)
        return json.dumps({"byte_offset": byte_offset, "bit_mask": bit_mask,
                           "element_size": element_size, "bit_shift": shift,
                           "full_mask": full_mask,
                           "full_mask_hex": f"0x{full_mask:0{width}x}"})

    def solve_struct_index(self, register_name, scale, displacement,
                           known_offsets, stride=4):
        """Solve field-base/index arithmetic; does not infer semantic identity."""
        try:
            scale = self._parse_tool_integer(scale, "scale")
            displacement = self._parse_tool_integer(displacement, "displacement")
            stride = self._parse_tool_integer(stride, "stride")
            if isinstance(known_offsets, str):
                known_offsets = json.loads(known_offsets)
            if not isinstance(known_offsets, list):
                raise ValueError("known_offsets must be a JSON array of integers")
            known_offsets = [self._parse_tool_integer(v, "known_offsets item")
                             for v in known_offsets]
        except (ValueError, json.JSONDecodeError) as exc:
            return json.dumps({"error": str(exc)})
        if not register_name or not str(register_name).strip():
            return json.dumps({"error": "register_name is required"})
        if scale < 0 or stride <= 0:
            return json.dumps({"error": "scale must be non-negative and stride must be positive"})
        if scale % stride != 0:
            return json.dumps({
                "register_name": str(register_name), "scale": scale,
                "displacement": displacement, "stride": stride,
                "matches": [], "certainty": "arithmetic_only",
                "note": "No universal integer index formula: scale is not divisible by stride.",
            })
        coefficient = scale // stride
        register = str(register_name).strip()
        matches = []
        for base_offset in known_offsets:
            delta_num = displacement - base_offset
            if delta_num % stride:
                continue
            delta = delta_num // stride
            term = register if coefficient == 1 else f"{coefficient}*{register}"
            formula = term if delta == 0 else f"{term} {'+' if delta > 0 else '-'} {abs(delta)}"
            matches.append({"known_offset": base_offset, "index_coefficient": coefficient,
                            "index_delta": delta, "pos_formula": formula})
        return json.dumps({
            "register_name": register, "scale": scale, "displacement": displacement,
            "stride": stride, "matches": matches, "match_count": len(matches),
            "certainty": "arithmetic_only",
            "note": "Matches establish arithmetic consistency only; confirm field semantics in context.",
        })

    def debug_compare_struct_lookup(self, name, category="", offset=-1):
        """DIAGNOSTIC, read-only, no mutation: compares the name-only
        getAllDataTypes() scan (what get_struct_layout/get_type_exact_facts
        use) against the category-path getDataType(cat_path, name) lookup
        (what edit_structure_field uses), for the same struct name. Added
        2026-07-23 to chase a bug where edit_structure_field reports
        status:ok for CTextAnalyzer (a root-category struct) but the
        change never shows up via get_struct_layout/get_type_exact_facts.
        If offset>=0, also reports each lookup's component type AT that
        offset directly, plus getDataTypeManager() identity/id for both
        paths and the struct's own getUniversalID(), to check whether the
        two lookups are secretly resolving to two different DataTypeManager
        instances (e.g. program DTM vs a built-in/archive DTM snapshot)."""
        dtm = self._program.getDataTypeManager()
        CategoryPath = jpype.JClass('ghidra.program.model.data.CategoryPath')
        cat_path = CategoryPath("/" + category)
        a = dtm.getDataType(cat_path, name)
        iterator = dtm.getAllDataTypes()
        b = None
        scan_matches = []
        while iterator.hasNext():
            candidate = iterator.next()
            if candidate.getName() == name:
                scan_matches.append(str(candidate.getDataTypePath()))
                if b is None:
                    b = candidate
        result = {
            "requested_category": category,
            "cat_path_str": str(cat_path),
            "cat_lookup_found": a is not None,
            "scan_lookup_found": b is not None,
            "scan_matches_all": scan_matches,
        }
        if a is not None:
            result["cat_lookup_path"] = str(a.getDataTypePath())
            result["cat_lookup_length"] = a.getLength()
            result["cat_lookup_dtm_name"] = str(a.getDataTypeManager().getName()) if a.getDataTypeManager() is not None else None
            try:
                result["cat_lookup_universal_id"] = str(a.getUniversalID())
            except Exception as e:
                result["cat_lookup_universal_id_error"] = str(e)
        if b is not None:
            result["scan_lookup_path"] = str(b.getDataTypePath())
            result["scan_lookup_length"] = b.getLength()
            result["scan_lookup_dtm_name"] = str(b.getDataTypeManager().getName()) if b.getDataTypeManager() is not None else None
            try:
                result["scan_lookup_universal_id"] = str(b.getUniversalID())
            except Exception as e:
                result["scan_lookup_universal_id_error"] = str(e)
        if a is not None and b is not None:
            result["same_object_identity"] = bool(a == b)
            result["same_python_wrapper_is"] = (a is b)
        offset = int(offset)
        if offset >= 0:
            if a is not None:
                ca = a.getComponentAt(offset)
                result["cat_component_at_offset"] = {
                    "found": ca is not None,
                    "start_offset": ca.getOffset() if ca is not None else None,
                    "type": str(ca.getDataType().getName()) if ca is not None else None,
                    "field_name": str(ca.getFieldName() or "") if ca is not None else None,
                }
            if b is not None:
                cb = b.getComponentAt(offset)
                result["scan_component_at_offset"] = {
                    "found": cb is not None,
                    "start_offset": cb.getOffset() if cb is not None else None,
                    "type": str(cb.getDataType().getName()) if cb is not None else None,
                    "field_name": str(cb.getFieldName() or "") if cb is not None else None,
                }
            result["same_datatype_path"] = str(a.getDataTypePath()) == str(b.getDataTypePath())
        return json.dumps(result)

    def list_call_fixups(self):
        """List every call-fixup name known to the program's compiler spec.

        Found 2026-08-01: a large-frame CRT stack-probe helper
        (_chkstk_probe in FlexTalk.dll) was not recognized as the standard
        MSVC __chkstk pattern, so the decompiler treated calls to it as an
        ordinary function that clobbers all volatile registers -- producing
        unaff_ESI/extraout_ECX garbage in every caller with a >4KB stack
        frame, even in code that otherwise decompiles cleanly. x86win.cspec
        ships fixups (e.g. "__chkstk") that model this correctly; this tool
        exists to discover the exact registered name before applying it via
        set_call_fixup.
        """
        return self._with_transaction("list_call_fixups", self._do_list_call_fixups)

    def _do_list_call_fixups(self):
        try:
            inject_lib = self._program.getCompilerSpec().getPcodeInjectLibrary()
            names = sorted(str(n) for n in inject_lib.getCallFixupNames())
        except Exception as e:
            return json.dumps({"error": f"Failed to list call fixups: {e}"})
        return json.dumps({"status": "ok", "call_fixups": names})

    def set_call_fixup(self, function_address, fixup_name):
        """Assign a known call-fixup (e.g. "__chkstk") to a function.

        A call fixup tells the decompiler's SSA/p-code analysis what a
        callee actually does to registers/stack instead of assuming the
        default calling-convention-worst-case (clobbers all volatile
        registers). Pass fixup_name="" to clear an existing fixup.
        """
        return self._with_transaction("set_call_fixup",
            lambda: self._do_set_call_fixup(function_address, fixup_name))

    def _do_set_call_fixup(self, function_address, fixup_name):
        addr = self.program.getAddressFactory().getAddress(function_address)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {function_address}"})
        fn = self._function_manager.getFunctionAt(addr)
        if fn is None:
            fn = self._function_manager.getFunctionContaining(addr)
        if fn is None:
            return json.dumps({"error": f"No function at {function_address}"})

        if fixup_name:
            try:
                inject_lib = self._program.getCompilerSpec().getPcodeInjectLibrary()
                valid_names = set(str(n) for n in inject_lib.getCallFixupNames())
            except Exception as e:
                return json.dumps({"error": f"Failed to query valid call fixups: {e}"})
            if fixup_name not in valid_names:
                return json.dumps({
                    "error": f"'{fixup_name}' is not a known call fixup for this program's compiler spec",
                    "valid_call_fixups": sorted(valid_names),
                })

        fn.setCallFixup(fixup_name if fixup_name else None)

        return json.dumps({
            "status": "ok",
            "function": fn.getName(),
            "address": function_address,
            "call_fixup": fixup_name if fixup_name else None,
        })

    def set_calling_convention(self, function_address, convention_name):
        """Set a function's calling convention directly (e.g. "__thiscall").

        Found 2026-08-01: after a delete_function+create_function repair
        (needed when a function's own decompile was corrupted, e.g. by an
        unmodeled call-fixup case -- see set_call_fixup), the recreated
        function's calling convention comes back "unknown" and stays stuck
        there -- set_function_prototype (ApplyFunctionSignatureCmd, a
        data-type-level signature edit) does not change it, and set_this_type
        can only ADD an implicit "this" slot when the convention already
        has one, so with an unknown convention it instead REPLACES the sole
        existing parameter. No prior tool could set this Function-level
        property directly. Apply this BEFORE set_this_type/set_parameter
        when convention_guess (from get_abi_summary) says thiscall/stdcall
        but ghidra_calling_convention says "unknown".
        """
        return self._with_transaction("set_calling_convention",
            lambda: self._do_set_calling_convention(function_address, convention_name))

    def _do_set_calling_convention(self, function_address, convention_name):
        addr = self.program.getAddressFactory().getAddress(function_address)
        if addr is None:
            return json.dumps({"error": f"Invalid address: {function_address}"})
        fn = self._function_manager.getFunctionAt(addr)
        if fn is None:
            fn = self._function_manager.getFunctionContaining(addr)
        if fn is None:
            return json.dumps({"error": f"No function at {function_address}"})

        try:
            valid_names = set(str(m.getName()) for m in
                self._program.getCompilerSpec().getCallingConventions())
        except Exception as e:
            return json.dumps({"error": f"Failed to query valid calling conventions: {e}"})
        if convention_name not in valid_names:
            return json.dumps({
                "error": f"'{convention_name}' is not a known calling convention for this program's compiler spec",
                "valid_calling_conventions": sorted(valid_names),
            })

        try:
            fn.setCallingConvention(convention_name)
        except Exception as e:
            return json.dumps({"error": f"setCallingConvention failed: {e}"})

        return json.dumps({
            "status": "ok",
            "function": fn.getName(),
            "address": function_address,
            "calling_convention": str(fn.getCallingConventionName()),
        })

    def delete_data_type(self, name, category="", force=False):
        """Permanently remove a data type (structure/typedef/enum/etc.) from
        the program's DataTypeManager. Added 2026-07-29 -- the mutation
        surface previously had create_structure/create_structure_from_offsets/
        edit_structure_field but no way to remove a struct at all, which
        this project needed to clean up confirmed-stale DUPLICATE structs
        (e.g. CWaveFields vs the live CWave -- see
        feedback_check_which_struct_is_live_before_working memory, a
        pattern that recurred three times: CVoice/CVoiceFields,
        CWave/CWaveFields, CTextAnalyzer/CTextAnalyzerFields).

        Lookup: if category is given, resolves via the exact
        CategoryPath+name lookup (same path edit_structure_field uses). If
        category is omitted, does a name-only scan across ALL categories
        (same path get_struct_layout/get_type_exact_facts use --
        debug_compare_struct_lookup exists because these two lookup paths
        can diverge) and refuses if more than one type shares that name
        anywhere in the program (pass category explicitly to disambiguate).

        Safety check (without force=True): refuses if the program has any
        DEFINED DATA instances (Listing.getDefinedData) actually typed as
        this data type -- i.e. it's applied somewhere as a concrete memory
        label, not just a candidate struct definition sitting unused in
        the DataTypeManager. This does NOT check whether any function's
        parameter/return/local-variable type or another struct's FIELD
        type still references it (that would require scanning every
        function signature and every other struct's fields, which this
        tool does not do) -- the caller is responsible for having already
        confirmed via decompile (which struct's field names actually
        surface on the real consumer functions) that the type being
        deleted is genuinely the unused duplicate, not the live one.
        Pass force=True once that's been confirmed by hand, or force=True
        immediately for a type you already know has zero typed-data
        instances.

        No undo tool exists for this -- Ghidra's own project has version
        history (checked in via save()), but back up the .rep project
        directory before any bulk struct-cleanup pass regardless."""
        return self._with_transaction("delete_data_type",
            lambda: self._do_delete_data_type(name, category, force))

    def _do_delete_data_type(self, name, category="", force=False):
        dtm = self._program.getDataTypeManager()
        CategoryPath = jpype.JClass('ghidra.program.model.data.CategoryPath')

        dt = None
        if category:
            cat_path = CategoryPath("/" + category)
            dt = dtm.getDataType(cat_path, name)
            if dt is None:
                return json.dumps({
                    "error": f"Data type '{name}' not found in category '{category}'"})
        else:
            matches = []
            iterator = dtm.getAllDataTypes()
            while iterator.hasNext():
                candidate = iterator.next()
                if str(candidate.getName()) == name:
                    matches.append(candidate)
            if len(matches) == 0:
                return json.dumps({"error": f"Data type '{name}' not found in any category"})
            if len(matches) > 1:
                return json.dumps({
                    "error": (f"Ambiguous: {len(matches)} data types named '{name}' found "
                              f"across categories -- pass category explicitly."),
                    "candidates": [str(c.getCategoryPath()) for c in matches],
                })
            dt = matches[0]

        instance_count = 0
        sample_addrs = []
        data_iter = self._listing.getDefinedData(True)
        while data_iter.hasNext():
            d = data_iter.next()
            if d.getDataType() == dt:
                instance_count += 1
                if len(sample_addrs) < 5:
                    sample_addrs.append(str(d.getAddress()))
                if instance_count > 1000:
                    break

        if instance_count > 0 and not force:
            return json.dumps({
                "error": (f"Data type '{name}' has {instance_count}{'+' if instance_count > 1000 else ''} "
                          f"defined-data instance(s) in the program (sample addresses: "
                          f"{sample_addrs}) -- refusing to delete without force=true."),
                "instance_count": instance_count,
                "sample_addresses": sample_addrs,
            })

        struct_size = dt.getLength()
        struct_category = str(dt.getCategoryPath())
        struct_path = str(dt.getDataTypePath())
        removed = dtm.remove(dt, None)
        if removed:
            return json.dumps({
                "status": "ok",
                "deleted": name,
                "category": struct_category,
                "path": struct_path,
                "former_size": struct_size,
                "had_defined_data_instances": instance_count,
            })
        return json.dumps({"error": f"DataTypeManager.remove returned false for '{name}'"})



def _form_bool(value, default=False):
    """Coerce a boolean-ish request value to a real Python bool, correctly
    handling the form-encoded-POST-body case.

    ROOT CAUSE this fixes (confirmed 2026-07-12, discovered live while
    testing new create_structure_from_offsets/set_this_type/etc tooling):
    bridge_mcp_ghidra.py's safe_post() sends dict payloads via
    requests.post(url, data=data), which is FORM-ENCODED
    (application/x-www-form-urlencoded), not JSON. A Python bool False in
    that payload becomes the literal TEXT "False" on the wire. Server-side,
    do_POST's JSON parse fails on a form-encoded body and falls back to
    parse_qs(), which returns every value as a STRING -- so
    data.get("replace", False) returns the STRING "False" when the caller
    passed replace=False, not the Python bool. The naive `bool(data.get(
    "replace", False))` then evaluates to True, because ANY non-empty
    string (including the literal text "False") is truthy in Python. This
    meant EVERY boolean POST parameter routed this way was silently
    ALWAYS True regardless of what the caller actually requested --
    root-causing this project's repeated "create_structure silently
    overwrites even without replace=True" near-misses, which had been
    mis-attributed to Ghidra's own DataTypeConflictHandler semantics until
    this was traced to the actual bug. Applies to any string value, not
    just POST's -- safe to use uniformly."""
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


class GhidraRequestHandler(BaseHTTPRequestHandler):
    """HTTP handler matching GhidraMCP's REST API signature exactly."""

    api: GhidraAPI = None

    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        if isinstance(data, str):
            self.wfile.write(data.encode("utf-8"))
        else:
            self.wfile.write(data)

    def _send_error(self, msg, status=500):
        self._send_json(json.dumps({"error": msg}), status)

    def _p(self, qs, key, default=None):
        vals = qs.get(key)
        if not vals:
            return default
        return vals[0]

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.strip("/")
        qs = parse_qs(parsed.query)
        p = lambda k, d=None: self._p(qs, k, d)

        try:
            def current_program_info():
                if self.api._program and self.api._current_program_path:
                    ep = str(self.api._program.getMinAddress())
                    cnt = self.api._function_manager.getFunctionCount()
                    return json.dumps({
                        "program": self.api._program.getName(),
                        "path": self.api._current_program_path,
                        "address": ep,
                        "function_count": cnt,
                    })
                return json.dumps({"program": None, "path": None})

            handlers = {
                'verify_decompile_constants': lambda: self.api.verify_decompile_constants(p("address")),
                'search_function_disassembly': lambda: self.api.search_function_disassembly(
                        p("address"), p("mnemonic"), p("operand_pattern"),
                        p("operand_match_mode", "substring"), p("max_results", "200")),
                'disassemble_range': lambda: self.api.disassemble_range(p("address"), p("count", "20")),
                'debug_compare_struct_lookup': lambda: self.api.debug_compare_struct_lookup(p("name", ""), p("category", ""), int(p("offset", -1))),
                'translate_subfield_mask': lambda: self.api.translate_subfield_mask(
                        p("byte_offset"), p("bit_mask"), p("element_size", "4")),
                'solve_struct_index': lambda: self.api.solve_struct_index(
                        p("register_name"), p("scale"), p("displacement"),
                        p("known_offsets"), p("stride", "4")),
                "": lambda: json.dumps({"status": "ok", "service": "ghidra-headless"}),
                "methods": lambda: json.dumps([
                    "methods", "guidance", "functions", "classes", "segments",
                    "imports", "exports", "namespaces", "data",
                    "searchFunctions", "get_function_by_address",
                    "get_current_address", "get_current_function",
                    "list_functions", "decompile_function",
                    "disassemble_function", "xrefs_to", "xrefs_from",
                    "function_xrefs", "strings", "decompile",
                    "list_programs", "switch_program",
                    "list_projects", "switch_project", "import_program",
                    "apply_map_symbols", "list_scripts", "run_script",
                    "rename_function_by_address", "renameFunction",
                    "renameData", "renameVariable",
                    "set_decompiler_comment", "set_disassembly_comment",
                    "set_function_prototype", "set_local_variable_type",
                    "analyze", "create_function", "resolve_vtable", "create_label",
                    "find_vtable_candidates", "trace_vtable_assignments",
                    "set_data_type", "get_comments", "save",
                    "create_structure", "create_vtable_type",
                    "get_bytes", "read_float", "read_double", "read_int",
                    "read_float_array", "read_double_array", "read_pointer_array", "read_int_array",
                    "read_float_matrix", "resolve_switch_dispatch",
                    "rename_variable_by_address", "get_basic_blocks",
                    "trace_fpu_stack",
                    "stack_depth", "hook_point", "find_next_symbol",
                    "function_callers", "function_call_graph", "get_struct_layout",
                    "get_function_hash", "compare_program_functions", "analyze_dataflow", "get_referenced_strings",
                    "batch_decompile", "batch_set_comments",
                    "get_instruction_facts", "get_function_exact_facts",
                    "get_address_exact_facts", "get_type_exact_facts",
                    "get_exact_neighborhood",
                    "create_structure_from_offsets", "set_this_type", "materialize_ecx_thiscall_callback", "materialize_ecx_thiscall_receiver",
                    "retype_variable_at", "find_class_ownership_strings",
                    "get_allocation_site_info", "resolve_call_site_context", "get_seh_frame_info",
                    "map_function_by_debug_strings",
                    "manage_namespace", "set_parameter", "repair_function_parameters", "edit_structure_field",
                    "create_enum", "create_typedef", "create_function_pointer_type",
                    "classify_function_inventory", "delete_function",
                    "list_class_methods", "propose_struct_fields",
                ]),
                "guidance": lambda: json.dumps({
                    "service": "ghidra-headless",
                    "version": "1.7",
                    "endpoints": [
                        {"path": "/methods", "description": "List all available endpoint names"},
                        {"path": "/guidance", "description": "This guidance document"},
                        {"path": "/functions", "params": {"offset": "int (0)", "limit": "int (100)"}, "description": "List all functions with pagination"},
                        {"path": "/list_functions", "params": {"offset": "int (0)", "limit": "int (100)"}, "description": "Alias for /functions"},
                        {"path": "/decompile_function", "params": {"address": "hex str", "offset": "int (0), line-based", "limit": "int (0 = no limit), line-based"}, "description": "Decompile function containing address. Response includes total_lines and resolved_constants (auto string/hex preview for every DAT_/PTR_DAT_ symbol in the returned text, one pointer dereference for PTR_DAT_)."},
                        {"path": "/decompile", "params": {"address": "hex str", "offset": "int (0)", "limit": "int (0)"}, "description": "Alias for /decompile_function"},
                        {"path": "/searchFunctions", "params": {"query": "str", "offset": "int (0)", "limit": "int (100)"}, "description": "Search functions by name substring"},
                        {"path": "/get_function_by_address", "params": {"address": "hex str"}, "description": "Get function metadata at address"},
                        {"path": "/get_current_address", "description": "Get current program info and min address"},
                        {"path": "/get_current_function", "description": "Alias for /get_current_address"},
                        {"path": "/strings", "params": {"offset": "int (0)", "limit": "int (2000)", "filter": "str (optional)"}, "description": "List defined strings with optional content filter"},
                        {"path": "/xrefs_to", "params": {"address": "hex str", "offset": "int (0)", "limit": "int (100)", "size": "int (1)", "grouped": "bool (false)"}, "description": "Get references TO an address, unioned across [address, address+size). Pass size=<declared width> (e.g. 4 for a dword) to also catch byte-sub-address accesses a size=1 query at the base alone would miss; each entry's to_address shows which specific byte was targeted. When grouped=true, returns groups keyed by byte_offset from base_address instead of a flat xrefs list -- makes byte-level access patterns visible at a glance."},
                        {"path": "/xrefs_from", "params": {"address": "hex str", "offset": "int (0)", "limit": "int (100)", "size": "int (1)"}, "description": "Get references FROM an address, unioned across [address, address+size). Same size param semantics as /xrefs_to."},
                        {"path": "/find_next_symbol", "params": {"address": "hex str", "direction": "'forward'|'backward' (forward)", "element_size": "int (optional)"}, "description": "Find the nearest defined symbol (function/label/data) strictly after/before an address, with distance_bytes. When element_size is given (e.g. 4 for uint32[], 12 for a struct), also computes elements_to_next and remainder_bytes for table-geometry work."},
                        {"path": "/function_xrefs", "params": {"name": "str or hex addr", "offset": "int (0)", "limit": "int (100)"}, "description": "Get xrefs to a named function or address"},
                        {"path": "/disassemble_function", "params": {"address": "hex str", "offset": "int (0)", "limit": "int (0)", "start_address": "hex str (optional)"}, "description": "Disassemble function, paginate by instruction index (offset) or hex address (start_address). start_address snaps to the nearest instruction at or before the given address (no need to hit an exact instruction boundary); the response's resolved_start_address field shows what it snapped to."},
                        {"path": "/classes", "params": {"offset": "int (0)", "limit": "int (100)"}, "description": "List class names mined from debug strings"},
                        {"path": "/list_class_methods", "params": {"class_name": "str", "offset": "int (0)", "limit": "int (500)"}, "description": "Complete method list (name + address) for ONE class/namespace, no caps -- /classes truncates every class to 10 method NAMES (no addresses) and 3 sample addresses total. Resolves the real Ghidra namespace and lists every direct-child Function symbol."},
                        {"path": "/segments", "params": {"offset": "int (0)", "limit": "int (100)"}, "description": "List memory segments"},
                        {"path": "/imports", "params": {"offset": "int (0)", "limit": "int (100)"}, "description": "List imported (external) symbols"},
                        {"path": "/exports", "params": {"offset": "int (0)", "limit": "int (100)"}, "description": "List export symbols (ordinal + named)"},
                        {"path": "/namespaces", "params": {"offset": "int (0)", "limit": "int (100)"}, "description": "List namespace/class symbols"},
                        {"path": "/data", "params": {"offset": "int (0)", "limit": "int (100)"}, "description": "List defined data items with types"},
                        {"path": "/list_callees", "params": {"address": "hex str", "offset": "int (0)", "limit": "int (100)"}, "description": "List functions called from a function"},
                        {"path": "/function_callers", "params": {"address": "hex str", "offset": "int (0)", "limit": "int (100)"}, "description": "List direct calling functions"},
                        {"path": "/function_call_graph", "params": {"address": "hex str", "depth": "int (2, maximum 5)", "direction": "callers|callees|both"}, "description": "Bounded direct call graph"},
                        {"path": "/get_struct_layout", "params": {"name": "exact structure name"}, "description": "Return structure size and field offsets"},
                        {"path": "/get_function_hash", "params": {"address": "hex str"}, "description": "SHA-256 of normalized instruction shape for cross-DLL comparison"},
                        {"path": "/compare_program_functions", "params": {"source_program": "project path", "target_program": "project path", "min_instructions": "int (15)", "limit": "int (500)"}, "description": "READ-ONLY exact normalized-instruction-shape comparison between two project programs. Restores the selected program before returning. Produces candidates only; names/types are never transferred automatically."},
                        {"path": "/analyze_dataflow", "params": {"address": "hex str", "variable": "optional variable/register", "direction": "backward|forward", "max_steps": "int (20, maximum 100)"}, "description": "Bounded P-code dataflow trace"},
                        {"path": "/get_instruction_facts", "params": {"address": "instruction-start hex str"}, "description": "Instruction beginning exactly at address, with its decoded operands and stored operand references only. No decompiler/P-code/analyzer conclusion or inferred relationship."},
                        {"path": "/get_function_exact_facts", "params": {"address": "hex str", "limit": "int (200)", "offset": "int (0)"}, "description": "Stored metadata and references for the containing function. A DIRECT_CALL requires both a stored call reference and a Function exactly at its target; other/indirect targets are never guessed. Page with offset when a *_truncated flag is set and total_* exceeds offset+limit."},
                        {"path": "/get_address_exact_facts", "params": {"address": "hex str", "limit": "int (100)", "offset": "int (0)"}, "description": "Stored code/data/symbol/comment/memory facts at this exact address plus raw inbound/outbound references there, not a range scan. No inferred relationship; page with offset when a *_truncated flag is set."},
                        {"path": "/get_type_exact_facts", "params": {"name": "exact data type name", "limit": "int (100)", "offset": "int (0)"}, "description": "Declared layout of an exactly named datatype and defined data instances whose datatype path exactly matches it. No recovered objects, pointer targets, or guessed field uses; page with offset when instances_truncated is set."},
                        {"path": "/get_exact_neighborhood", "params": {"address": "hex str", "depth": "int (1, maximum 3)", "limit": "int (200)", "include_incoming": "bool (true)", "include_outgoing": "bool (true)"}, "description": "Bounded address/reference graph: nodes are direct listing/symbol/data/memory facts, edges are stored Ghidra references with original type/operand. Not a decompiler/CFG/data-flow graph; check truncated."},
                        {"path": "/get_basic_blocks", "params": {"address": "hex str"}, "description": "List basic blocks with CFG edges"},
                        {"path": "/get_function_body_bytes", "params": {"address": "hex str"}, "description": "Raw bytes of function body as hex"},
                        {"path": "/search_bytes", "params": {"pattern": "hex bytes with ?? wildcards", "limit": "int (200)"}, "description": "Search executable memory for byte pattern"},
                        {"path": "/get_stack_variables", "params": {"address": "hex str"}, "description": "List local stack variables"},
                        {"path": "/get_bytes", "params": {"address": "hex str", "size": "int (1)"}, "description": "Read raw bytes as hex string"},
                        {"path": "/read_float", "params": {"address": "hex str"}, "description": "Read 32-bit float at address"},
                        {"path": "/read_double", "params": {"address": "hex str"}, "description": "Read 64-bit double at address"},
                        {"path": "/read_float_array", "params": {"address": "hex str", "count": "int (1)"}, "description": "Read consecutive 32-bit floats as array"},
                        {"path": "/read_double_array", "params": {"address": "hex str", "count": "int (1)"}, "description": "Read consecutive 64-bit doubles as array"},
                        {"path": "/read_int", "params": {"address": "hex str", "size": "int (4)", "signed": "bool (true)"}, "description": "Read integer (1/2/4/8 bytes, signed/unsigned). Returns both value (decimal) and hex (zero-padded unsigned bit pattern)."},
                        {"path": "/read_int_array", "params": {"address": "hex str", "count": "int", "size": "int (4)", "signed": "bool (false)"}, "description": "Read consecutive integers (1/2/4/8 bytes each) as an array. Returns both values (decimal) and hex_values -- replaces the get_bytes-then-struct.unpack-by-hand pattern for table dumps."},
                        {"path": "/read_pointer_array", "params": {"address": "hex str", "count": "int"}, "description": "Read `count` consecutive 32-bit pointers and resolve each to a program symbol name, function entry point, or data type when one exists at the target address. Returns per-pointer {index, address, pointer_hex, is_null, symbol, is_function, data_type} -- saves the manual read_int_array → lookup-by-address cycle for vtable/offset-table RE."},
                        {"path": "/read_float_matrix", "params": {"address": "hex str", "row_stride_bytes": "int", "num_rows": "int", "row_length": "int"}, "description": "Read num_rows rows of row_length consecutive 32-bit floats each, rows spaced row_stride_bytes apart (may differ from row_length*4, e.g. a per-feature table padded to a wider struct stride). Replaces the manual 'compute base+i*stride by hand, call read_float/read_float_array per row' cycle -- a real source of hex-arithmetic slips (e.g. 5*0x154 != 0x6a8). Returns {rows: [[...],...], row_lengths} -- a short row_length means that row ran past mapped memory."},
                        {"path": "/resolve_switch_dispatch", "params": {"byte_table_addr": "hex str", "entry_count": "int", "jump_table_addr": "hex str", "case_value_start": "int (0)"}, "description": "Resolve an MSVC-style switch dispatched via a per-case byte index table feeding a pointer jump table (MOV AL,[EDX+byte_table]; JMP [EAX*4+jump_table]). Reports groups_by_handler_address (case values sharing the SAME actual code, which is the grouping decompiler output shows -- two different byte-table group indices can point at an identical deduplicated handler) and standalone_case_values (cases with a handler address no other case shares -- a strong signal that case needs independent verification, not an assumption it behaves like its numeric neighbors). Replaces the manual get_bytes(byte_table) + read_pointer_array(jump_table) + cross-reference-by-hand cycle."},
                        {"path": "/trace_fpu_stack", "params": {"address": "hex str", "start_offset": "int (0)", "count": "int (20)", "start_address": "hex str (optional)", "fpu_only": "bool (false)"}, "description": "Trace x87 FPU stack through instruction sequence. Use start_address (hex) or start_offset (index). fpu_only=true suppresses non-FPU rows."},
                        {"path": "/stack_depth", "params": {"address": "hex str"}, "description": "Compute cumulative ESP delta from function entry to a specific instruction address. Bridges stack variable frame-offsets with raw [ESP+N] displacement."},
                        {"path": "/get_referenced_strings", "params": {"address": "hex str"}, "description": "Find all defined string data items referenced by instructions in the function containing `address`. Returns each string's value, address, the code address that references it, and reference type. Best-effort: only finds auto-analyzed references."},
                        {"path": "/abi_summary", "params": {"address": "hex str"}, "description": "Mechanical calling-convention summary: scans every RET in the function for its stack-purge immediate and checks opening instructions for ECX-as-this evidence, including direct register aliases (e.g. MOV EBX, ECX then [EBX+offset]). Returns ret_purge_bytes_seen, stack_args_guess, convention_guess, thiscall_evidence. Best-effort, not authoritative -- cross-check per project Rule 12."},
                        {"path": "/propose_struct_fields", "params": {"address": "hex str (function)", "this_param_index": "int (0)"}, "description": "Mechanize the offset arithmetic in struct-building RE: walks the function's PCODE, traces every LOAD/STORE's address operand AND every CALL's arguments back through COPY/CAST/INT_ADD/PTRADD/PTRSUB to the given parameter, and returns a proposed offset-sorted field list (offset, sizes_seen, size_ambiguous, reads/writes, passed_to_calls with callee name, sample_addresses). Validated live against CSpeakerPage::construct: direct writes alone found only 7 of ~12 real fields, the rest only show up via passed_to_calls (sub-object construction). A STARTING POINT for create_structure/create_structure_from_offsets, not a finished field list -- field names, semantic roles, and sub-object sizes still need a human reading the surrounding code."},
                        {"path": "/scan_unnamed_labels", "params": {"name_prefix": "str, default FUN_", "max_functions": "int, default 500", "max_string_len": "int, default 80", "limit": "int, default 200", "offset": "int, default 0"}, "description": "Bulk self-labeling-string scanner: for every still-unnamed function, walks its instructions' data references and raw-reads each target (bypassing Ghidra's string auto-analysis catalog, which can miss real strings) to find embedded self-labeling text -- 'Class::method', 'module.DLL: name', 'sourcefile.cpp: function_name:' (names the vendor source function; SCCS '@(#) $Id:' tags excluded), or bare 'name()' debug-trace labels. Replaces the manual grep-string-table -> get_xrefs_to -> check-caller-name cycle with one bulk pass. Returns candidates with function_address/current_name/matched_string/pattern/implied_symbol. Best-effort -- confirm via decompile before renaming, per Rule 6."},
                        {"path": "/find_class_ownership_strings", "params": {"max_functions": "int, default 5000", "max_string_len": "int, default 80", "limit": "int, default 200", "offset": "int, default 0", "only_mismatches": "bool, default false"}, "description": "Whole-DLL version of scan_unnamed_labels' string-classification core, but over EVERY function (not just unnamed ones). Shares its full pattern set incl. the 'MODULE_DLL!Class::method' raw-'!'-separator shape and the 'sourcefile.cpp: name:' shape. For every hit, compares the string's implied class against the function's CURRENT Ghidra namespace and flags namespace_mismatch (for 'file.cpp:' strings only when the token is a C<Upper> class name; the token is always returned as implied_symbol). Mechanizes this project's highest-leverage 2026-07-12 manual RE technique: both the CWave/CVoice and CUtility/CTextAnalyzer identity corrections were found by eyeballing exactly this kind of embedded string by hand. only_mismatches=true surfaces just the disagreements."},
                        {"path": "/get_allocation_site_info", "params": {"address": "hex str, a CALL instruction"}, "description": "Given an allocator CALL (operator_new/malloc/etc.), walks backward for the pushed size argument and forward for a 'likely constructor' CALL that uses the returned pointer -- mechanizes the manual PUSH-before-CALL-plus-following-CALL walk this project used repeatedly to confirm CVoice/CWave/CUtility/CTextAnalyzer's real object sizes and constructors."},
                        {"path": "/resolve_call_site_context", "params": {"address": "hex str, a CALL instruction", "max_args": "int (8)", "lookback": "int (40)", "lookahead": "int (15)"}, "description": "General version of get_allocation_site_info for ANY call site, any number of arguments. Walks backward for the contiguous PUSH run before the call (resolving each argument to an immediate + best-effort raw-bytes string preview, or one level through a register set by an immediately preceding MOV/LEA), and forward for what happens to the return value (compare-and-branch, store-to-address/variable, or used as an argument to another call). Built to replace the 'disassemble a big function, eyeball which PUSH feeds which of many calls to the same callee, eyeball what happens to EAX' cycle -- combine with get_xrefs_to(callee) to get all call site addresses, then call this once per site instead of re-reading surrounding disassembly by hand each time. Mechanical heuristic, not authoritative -- confirm against the real decompile."},
                        {"path": "/classify_function_inventory", "params": {"name_prefix": "str, default FUN_", "max_functions": "int, default 8000", "limit": "int, default 500", "offset": "int, default 0"}, "description": "Triage the still-unnamed (FUN_*) inventory into likely-real vs. likely compiler-artifact (MSVC EH cleanup funclet / orphaned function-boundary fragment), so a raw 'N unnamed functions' backlog can be re-scoped before budgeting effort. Signals: 16-byte alignment (real MSVC entries are aligned; funclets/fragments are not), single-parent-only call refs (funclet), and zero refs (orphan). Per function: address/name/aligned16/body_size/num_call_refs/distinct_owner_funcs/total_refs/classification/reason, plus a summary count. READ-ONLY, heuristic -- confirm via decompile before delete_function. On FlexTalk.dll ~35% of 511 FUN_* were artifacts (11/11 sampled non-aligned were artifacts). See voxtalk/docs/RE_FUNCTION_INVENTORY_TAXONOMY_2026-07-12.md."},
                        {"path": "/get_seh_frame_info", "params": {"address": "hex str, any address in the function"}, "description": "Detects the standard MSVC _except_handler3/4 SEH prologue idiom at a function's entry (push -1/push handler/push fs:[0]/mov fs:[0],esp -- the source of unaff_FS_OFFSET/local_10/puStack_c clutter seen in nearly every decompile in this binary) and reports the handler address/name. Read-only/informational; does not retype anything."},
                        {"path": "/map_function_by_debug_strings", "params": {"filter_str": "substring to search all defined strings for, e.g. 'QEND' or ':' (mutually exclusive with string_addresses)", "string_addresses": "comma-separated hex addresses, use instead of filter_str for an explicit known set", "min_hits": "int (1); only report functions with at least this many matching strings"}, "description": "Mechanizes the 'find the real vendor function behind a module's self-labeled debug/diagnostic strings' technique this project used to locate sdict_suffix_ending_analysis (the real QEND.CPP) from its 18 '\"QEND: ...\"' error strings: runs list_strings(filter_str) (or takes an explicit address list), resolves get_xrefs_to on every hit, groups by containing function, and returns each function's hits sorted by from_address -- an address-ordered roadmap of that function's branches straight from string content, with zero decompile calls. Also surfaces likely-wrong existing names when a function's hits don't match its current name's implied module. Read-only, string-xref-derived -- a navigation aid, not a substitute for a real decompile."},
                        {"path": "/manage_namespace", "params": {"operation": "'create'|'rename'|'move'", "path": "'/'-separated namespace path, e.g. 'CFoo/Inner'", "new_name": "required for rename", "new_parent_path": "required for move"}, "description": "POST: explicit namespace create/rename/move. Previously the only way to create a real Ghidra namespace was as a side effect of rename_function_by_address('Class::method', ...) -- this exposes the operation directly and adds rename/move, which nothing did before."},
                        {"path": "/set_parameter", "params": {"function_address": "hex str", "index": "int, 0-based", "new_name": "optional", "new_type": "optional, at least one of new_name/new_type required"}, "description": "POST: rename and/or retype a function parameter BY INDEX. Parameter 0 is guarded when it is Ghidra's implicit thiscall receiver; use set_this_type for that receiver and this endpoint for explicit parameters. Re-decompiles and reports decompile_shows_field_access honestly when new_type is a struct/pointer-to-struct."},
                        {"path": "/edit_structure_field", "params": {"struct_name": "str", "category": "str (category or canonical type.path)", "operation": "'add'|'rename'|'retype'|'clear'", "offset": "int, byte offset", "field_name": "for add/rename/retype", "field_type": "for add/retype", "field_size": "optional override"}, "description": "POST: add/rename/retype/clear ONE field of an EXISTING structure at a specific offset, without rebuilding the whole field list (complements create_structure/create_structure_from_offsets, which always replace everything). category accepts either the containing category (for example '/') or the canonical type.path returned by get_type_exact_facts (for example '/MapData'). 'clear' reverts a field to opaque Undefined bytes WITHOUT shrinking the struct (Structure.clearComponent) -- the safe default for 'delete' in an RE context where total struct size is usually a hard-won confirmed fact."},
                        {"path": "/create_enum", "params": {"name": "str", "category": "str (Voxtalk)", "values": "JSON object {\"NAME\": int_value, ...}", "size": "int (4), byte width", "replace": "bool (false)"}, "description": "POST: create an enum data type. replace=false (default) refuses to alter an existing enum and returns its exact stored members; pass replace=true only to intentionally update that existing enum in place, preserving its uses."},
                        {"path": "/create_typedef", "params": {"name": "str", "category": "str (Voxtalk)", "base_type": "str, e.g. 'CVoiceFields *'"}, "description": "POST: create a typedef aliasing an existing type under a new name."},
                        {"path": "/create_function_pointer_type", "params": {"name": "str", "category": "str (Voxtalk)", "return_type": "str", "param_types": "JSON list of type-name strings, e.g. [\"int\", \"char *\"]", "calling_convention": "optional, e.g. '__thiscall'"}, "description": "POST: create a named function-pointer typedef. Directly useful for this project's recurring raw vtable-slot/callback call pattern ('(**(code**)*param_1)(...)') that currently has no queryable type at all."},
                        {"path": "/find_thunk_candidates", "params": {"min_gap_bytes": "int, default 4", "max_gap_bytes": "int, default 128", "max_tail_bytes": "int, default 6", "limit": "int, default 200"}, "description": "Mechanical scan of address gaps between defined functions (in executable memory blocks) for the vtable-forwarding thunk shape: an indirect CALL through a register+offset followed shortly by RET, using a lightweight manual ModRM decode (not Ghidra's disassembler, so no side effects on false positives). Finds real thunks analyzeAll() left as undefined bytes because they're only reached via a vtable, never a direct CALL. Returns candidates with address/length_bytes/preceding_function/following_function. Best-effort -- verify with create_function + decompile before renaming."},
                        {"path": "/find_vtable_candidates", "params": {"start": "hex str", "end": "hex str", "min_slots": "int, default 3"}, "description": "Read-only scan for aligned runs of 32-bit values that exactly equal existing Function entry addresses. Also reports existing vtable/vftable symbols as RTTI seeds; no analyzer is run."},
                        {"path": "/trace_vtable_assignments", "params": {"address": "constructor/function hex str"}, "description": "Walk listing instructions in order and report detected MOV [this+0], vtable stores, including the lexical final assignment. ECX and simple register aliases are tracked; control flow is not evaluated."},
                        {"path": "/classify_pointer_provenance", "params": {"address": "hex str, OR use function_address+offset instead", "function_address": "hex str", "offset": "hex str, struct-relative field offset", "max_backtrack": "int, default 15"}, "description": "Answers 'is this vtable/interface pointer a compile-time constant (keep tracing statically) or populated at runtime via GetProcAddress/LoadLibraryA (stop -- this binary alone can't resolve which DLL, go to registry/config data or an oracle capture)?' Two modes: a plain global address (uses xrefs), or function_address+offset for a struct-relative field Ghidra can't xref directly. Returns write_sites with a static_constant/runtime_dynamic/unknown classification per site plus evidence. Built after this exact ambiguity cost real time twice on the CTA+0x3b390 'Letter-To-Sound dictionary' question (TRUTH_LEDGER rows 533-537)."},
                        {"path": "/hook_point", "params": {"address": "hex str", "min_bytes": "int (5)"}, "description": "Find smallest instruction-aligned block starting at address that meets min_bytes. Returns instruction boundaries, total size, and safety flags for common hook sizes (5/6 bytes)."},
                        {"path": "/list_programs", "description": "List available programs in project"},
                        {"path": "/switch_program", "description": "POST: switch to another program in the active project"},
                        {"path": "/list_projects", "description": "Ghidra projects this server can open (projects.json), which are open, and which is active"},
                        {"path": "/switch_project", "params": {"project": "key from list_projects", "program": "optional project path"}, "description": "POST: make another project active (opening it if needed) and open program, the last program used there, or its default_program. Saves the outgoing program first."},
                        {"path": "/import_program", "params": {"path": "file to import", "folder": "project folder (/)", "analyze": "bool (false)"}, "description": "POST: import a binary into the active project and make it the active program. Limited to the project's import_roots when it has any."},
                        {"path": "/apply_map_symbols", "params": {"map_path": "MSVC linker .map", "demangle": "bool (true)", "create_functions": "bool (true)"}, "description": "POST: name the active program from an MSVC .map: every public and static symbol at its Rva+Base address, functions where the map flags f, mangled C++ names demangled into namespaces and signatures."},
                        {"path": "/list_scripts", "description": "The active project's GhidraScript collection, one entry per script in numbered stage order"},
                        {"path": "/run_script", "params": {"script": "file name, stage folder or relative path", "args": "space-separated script args"}, "description": "POST: compile and run one GhidraScript from the active project's collection against the active program, inside one transaction; returns what it printed."},
                        {"path": "/rename_function_by_address", "description": "POST: rename function at address"},
                        {"path": "/renameFunction", "description": "POST: rename function by old name"},
                        {"path": "/renameData", "description": "POST: rename data label"},
                        {"path": "/renameVariable", "description": "POST: rename local variable"},
                        {"path": "/set_decompiler_comment", "params": {"address": "hex str", "comment": "str", "comment_type": "optional, one of 'eol' (default)/'plate'/'pre'/'post'"}, "description": "POST: set a comment visible in the decompiler pseudocode. FIXED (2026-08-20): comment_type was previously accepted by nothing -- every call silently wrote EOL regardless of caller intent, including callers that believed they were setting a distinct plate comment. If you have plate-comment calls from before this date, re-verify with get_comments and re-apply with comment_type='plate' -- the old text is still sitting in the plate slot untouched."},
                        {"path": "/set_disassembly_comment", "description": "POST: set comment in disassembly listing"},
                        {"path": "/set_function_prototype", "description": "POST: set function signature. WARNING (2026-08-20): confirmed to have two real bugs -- (1) no way to specify calling convention in the prototype string at all (FunctionSignatureParser's grammar has no keyword for it; 'int __thiscall Foo(...)' fails to parse), (2) weaker type resolution than set_this_type/set_full_prototype's _resolve_type_by_name (fails on some valid custom project struct-pointer types). Prefer /set_full_prototype for anything beyond a same-namespace return-type-only tweak."},
                        {"path": "/set_full_prototype", "params": {"function_address": "hex str", "calling_convention": "str, e.g. '__thiscall'/'__cdecl'/'__stdcall'/'__fastcall'/'unknown'", "return_type": "str, e.g. 'BOOL', 'void', 'MyStruct *'", "parameters": "JSON array string of {\"name\":str,\"type\":str} objects in order, e.g. '[{\"name\":\"this\",\"type\":\"CFoo *\"},{\"name\":\"arg1\",\"type\":\"int\"}]' -- for __thiscall, list 'this' explicitly as entry 0"}, "description": "POST (added 2026-08-20): set a function's COMPLETE prototype (calling convention + return type + full parameter list) via Function.updateFunction() -- the same real, verified-effective listing-level mechanism /set_this_type and /set_parameter use, not /set_function_prototype's broken ApplyFunctionSignatureCmd/FunctionSignatureParser path. Added to close a real gap found on this project: after delete_function+create_function resets a function to a signature-not-yet-locked state (getParameterCount()==0 even though the decompiler still shows inferred parameters), neither /set_this_type nor /set_parameter can bootstrap a fresh signature (they only modify EXISTING parameters), and /set_function_prototype fails on both bugs described in its own entry above. Re-decompiles afterward and reports decompile_shows_field_access (checked, not assumed) for the first checkable parameter, scoped to its own name -- don't trust a bare 'status: ok' alone."},
                        {"path": "/set_local_variable_type", "description": "POST: set local variable type by NAME. Fragile against renumbering (any retype call can silently rename OTHER locals in the same function on the next decompile) and cannot touch an auto-generated 'this' parameter (InvalidInputException). See /set_this_type and /retype_variable_at for the two targeted fixes."},
                        {"path": "/set_this_type", "params": {"function_address": "hex str", "new_type": "str, e.g. 'MyStructFields *'", "force": "bool (false)", "override_detected_local": "bool (false)", "insert_as_new_parameter": "bool (false) -- PREPEND 'this' and keep every existing parameter, instead of overwriting parameter 0; the real fix once evidence shows 'this' is a genuinely separate value (added 2026-08-20)"}, "description": "POST: set the REAL type of a thiscall function's 'this' parameter via Function.updateFunction() (listing-level), not the data-type-level ApplyFunctionSignatureCmd /set_function_prototype uses -- that path was confirmed cosmetic-only (plate-comment only) for any function already namespaced to a class. Re-decompiles afterward and reports decompile_shows_field_access (checked, not assumed) plus a sample_line when a real '->field' access was found. GUARDED (2026-07-13, WIDENED 2026-08-20): refuses when Ghidra's calling-convention analysis says __cdecl/__stdcall (100% stack-only, never ECX), OR 'unknown' with more than one parameter already modeled, and parameter 0 isn't an auto-parameter -- closes real incidents (including a 2026-08-20 FALSE POSITIVE on 'unknown'-convention CScienceSheet::HandleControlCommand/::HandleDdeEvent, both 2-stack-param functions with an unspilled 'this' the old guard let through) where this silently retyped a genuine unrelated parameter instead of the real object pointer, while decompile_shows_field_access still reported true because the wrong variable happened to alias a same-shaped field. STRENGTHENED (2026-07-13, extended 2026-08-20): when refusing, scans for evidence TWO ways -- raw-disassembly 'MOV [EBP+/-N],ECX' (detected_ecx_local, the spilled-to-stack case) AND an unspilled 'in_ECX'/'unaff_ECX' register value used directly in the decompiled text (detected_in_ecx_register, added 2026-08-20 -- the shape the spill scan alone cannot see). If either is found, force=true ALONE still refuses; pass force=true together with insert_as_new_parameter=true to prepend 'this' and keep parameter 0 untouched (the correct fix for both evidence shapes), or override_detected_local=true together with force=true if parameter 0 is nonetheless confirmed correct."},
                        {"path": "/materialize_ecx_thiscall_callback", "params": {"function_address": "hex str", "this_type": "pointer type", "stack_argument_type": "str (void *)", "stack_argument_name": "str (callback_argument)", "evidence_instruction_address": "required hex instruction address with [ECX+offset]", "expected_ret_purge_bytes": "must be 4", "replace_existing": "bool (false)"}, "description": "POST: safely repair Ghidra's parameterless model of a proven x86 callback ABI: requires a nominated direct [ECX+offset] instruction and every RET to be ret 4, then uses Function.updateFunction(__thiscall) to create a real ECX receiver plus one stack argument. Refuses to overwrite an existing signature unless replace_existing=true, and rolls back if Ghidra does not actually place this in ECX."},
                        {"path": "/materialize_ecx_thiscall_receiver", "params": {"function_address": "hex str", "this_type": "pointer type", "evidence_instruction_address": "required hex instruction address with [ECX+offset] or MOV-reg,ECX alias"}, "description": "POST: safely repair a proven zero-stack-argument x86 ECX-receiver method. Requires a nominated direct receiver-derived access, permits only a simple MOV reg,ECX alias, proves every RET has zero cleanup, then creates exactly __thiscall(this). Refuses any existing signature and rolls back unless Ghidra places this in ECX."},
                        {"path": "/retype_variable_at", "params": {"function_address": "hex str", "instruction_address": "hex str", "new_type": "str", "side": "'output' (default) | 'input'", "input_index": "int (0), only for side=input"}, "description": "POST: retype the HighVariable touched by the pcode op AT a specific instruction address, instead of by current (renumbering-prone) variable name. side=output retypes the variable ASSIGNED at that instruction (the common case: 'X = alloc_something(...)'); side=input+input_index retypes an argument being READ/PASSED there instead."},
                        {"path": "/create_function", "params": {"address": "hex str", "name": "str (optional)"}, "description": "Create function at address"},
                        {"path": "/delete_function", "params": {"address": "hex str, EXACT entry point"}, "description": "POST: remove the Function whose entry point is exactly `address`, leaving instructions/bytes intact (FunctionManager.removeFunction). Refuses if the address is only INSIDE a function (reports that function's real entry instead). Use to retire a confirmed compiler-artifact funclet, or to REPAIR a Ghidra function-boundary split: delete_function both the truncated entry and its orphaned tail, then create_function at the real (earlier, aligned) entry to recompute one merged body from flow. Reversible: create_function at the same address restores it."},
                        {"path": "/resolve_vtable", "params": {"address": "hex str", "count": "int"}, "description": "POST: resolve `count` consecutive vtable slots, persist a managed plate-comment block while preserving analyst text, and return an append-ready ndjson_record."},
                        {"path": "/create_label", "params": {"address": "hex str", "name": "str"}, "description": "Create label/symbol at address"},
                        {"path": "/set_data_type", "params": {"address": "hex str", "type_name": "str"}, "description": "Set data type at address"},
                        {"path": "/get_comments", "description": "POST: get all comments at address"},
                        {"path": "/save", "description": "POST: save program to disk. Note: the server also auto-saves every 10 successful write transactions, and always saves on a clean shutdown/restart or before switch_program -- you don't strictly need to call this yourself, but it's cheap insurance before something risky."},
                        {"path": "/create_structure", "params": {"name": "str", "category": "str (Voxtalk)", "fields": "JSON str", "replace": "bool (false)"}, "description": "Create struct data type. replace=false (default) now REFUSES with an error (including the existing struct's own field list) if a type with this name+category already exists -- confirmed this session that same-name creates could silently update an existing struct in place even without replace=true, causing two real near-miss overwrites of already-confirmed structs. Pass replace=true to update in place intentionally. Structs built via the manual per-field .add() calls this endpoint uses are unpacked/byte-precise (alignment 1) by construction -- no separate flag needed, this was already the effective default and is confirmed correct for RE-reconstructed raw-memory layouts."},
                        {"path": "/create_structure_from_offsets", "params": {"name": "str", "category": "str (Voxtalk)", "fields": "JSON list of {offset, name, type (optional), size (optional)}", "total_size": "int", "replace": "bool (false)"}, "description": "POST: like /create_structure but SPARSE -- give only the confirmed fields at their real offsets, gap fields between/after them are computed and inserted automatically server-side. Replaces the external-script gap-computation step this project did by hand twice for large structs (CVoiceFields, CUtilityFields). Errors (does not silently truncate) on any field overlap or on fields extending past total_size."},
                        {"path": "/create_vtable_type", "params": {"name": "str", "vtable_address": "hex str", "slots": "[{index, function_address}]", "category": "str (Vtables)", "replace": "bool (false)"}, "description": "POST: build a function-pointer vtable structure from existing Function signatures, create a companion object structure containing a typed vptr, and apply the vtable type at its data address."},
                        {"path": "/batch_decompile", "params": {"addresses": "JSON list, maximum 20"}, "description": "POST: decompile several functions in one decompiler session"},
                        {"path": "/batch_set_comments", "params": {"comments": "JSON list of {address, comment, type}"}, "description": "POST: atomically set up to 100 listing comments"},
                        {"path": "/analyze", "description": "POST: run full disassembly + function analysis"},
                    ],
                    "workflows": [
                        {
                            "name": "stack-coordinates",
                            "description": "Bridge disassembly ESP operands to named stack variables",
                            "steps": [
                                "Call get_stack_depth(address=target_instruction) first and check 'resolved_stack_offset' -- if non-null, that's Ghidra's own resolved frame offset for this operand; use it directly and skip the rest of this workflow.",
                                "If 'resolved_stack_offset' is null, fall back to 'stack_depth_at_target' (a best-effort ESP-walk simulation, not authoritative) and 'frame_local_size'.",
                                "Call get_stack_variables(address=function_entry) for the named locals and their frame offsets.",
                                "In the fallback case, a disassembly operand [ESP+0x10] at that instruction maps to frame offset: stack_depth_at_target + 0x10.",
                                "Look up the resulting offset in get_stack_variables output to find the local variable name (e.g. local_8 at offset -8).",
                                "Negative frame offsets are locals, positive offsets are parameters."
                            ]
                        },
                        {
                            "name": "navigate-large-function",
                            "description": "Jump directly to a specific disassembly address without guessing instruction indexes",
                            "steps": [
                                "Call disassemble_function(address=func_addr, start_address=target_hex_addr, limit=N).",
                                "The server resolves target_hex_addr to its instruction index automatically, snapping to the nearest instruction at or before it if the address doesn't land exactly on a boundary.",
                                "Check the response's resolved_start_address field to see exactly what it snapped to.",
                                "Alternatively use offset=N to paginate by instruction index from the start.",
                                "Do not pass both start_address and offset — if both are given, start_address wins."
                            ]
                        },
                        {
                            "name": "type-probe-variable",
                            "description": "Resolve an ambiguous pointer by forcing a type onto a local variable",
                            "steps": [
                                "Identify the ambiguous local variable from get_stack_variables or decompilation.",
                                "If you suspect it holds a struct pointer (e.g. WorkingNode88*), call set_local_variable_type(function_address=fn_addr, variable_name=local_X, new_type='WorkingNode88*').",
                                "Redecompile with decompile_function_by_address(address=fn_addr) — Ghidra will now show struct-field accesses instead of raw byte offsets.",
                                "If the type doesn't fit or field offsets look wrong, try a different type and redecompile again.",
                                "This avoids manual byte-tracing through memory reads."
                            ]
                        },
                        {
                            "name": "hook-safety",
                            "description": "Verify instruction-aligned boundaries before installing a code hook",
                            "steps": [
                                "Call find_hook_point(address=target, min_bytes=5) (or min_bytes=6 for a 6-byte jmp+offset+prefix).",
                                "Check safe_for_jmp5 / safe_for_jmp6 booleans before writing.",
                                "The instructions list shows each instruction's address, length, and cumulative bytes — you can see exactly what would be overwritten.",
                                "If not safe, try an adjacent address a few bytes forward or back and re-check."
                            ]
                        },
                        {
                            "name": "fpu-trace",
                            "description": "Trace x87 FPU register state through arithmetic sequences",
                            "steps": [
                                "Call trace_fpu_stack(address=func_addr, start_address=hex_addr, count=30, fpu_only=True).",
                                "fpu_only=True filters out non-FPU instructions for a clean view of stack pushes/pops/arithmetic.",
                                "Each trace entry shows st0..st8 symbolic expressions rather than concrete values (operands are register/memory-relative at analysis time).",
                                "Use start_address to jump past function prologue into the math section."
                            ]
                        },
                        {
                            "name": "xref-drilldown",
                            "description": "Find and inspect all callers of a function or address",
                            "steps": [
                                "Call get_xrefs_to(address=target) to list all references (calls, data accesses, etc.) to that address.",
                                "Each entry includes from_address, ref_type, and the containing function name if any.",
                                "For CALL references, follow up with decompile_function_by_address(address=from_address) to see each caller in context.",
                                "For data accesses, access_size_bytes (if present) tells you the access width — useful for identifying struct field alignment.",
                                "search_bytes with a byte pattern (use ?? for wildcards) can find references Ghidra's analysis missed."
                            ]
                        },
                    ],
                }),
                "functions":
                    lambda: self.api.get_all_functions(
                        int(p("offset", 0)), int(p("limit", 100))),
                "list_functions":
                    lambda: self.api.get_all_functions(
                        int(p("offset", 0)), int(p("limit", 100))),
                "decompile_function":
                    lambda: self.api.decompile_function(
                        p("address"), int(p("offset", 0)), int(p("limit", 0))),
                "decompile":
                    lambda: self.api.decompile_function(
                        p("address"), int(p("offset", 0)), int(p("limit", 0))),
                "strings":
                    lambda: self.api.list_strings(
                        int(p("offset", 0)), int(p("limit", 2000)),
                        p("filter")),
                "searchFunctions":
                    lambda: self.api.search_functions(
                        p("query", p("name", "")),
                        int(p("offset", 0)), int(p("limit", 100))),
                "get_function_by_address":
                    lambda: self.api.get_function_by_address(p("address")),
                "get_current_address":
                    lambda: current_program_info(),
                "get_current_function":
                    lambda: current_program_info(),
                "list_programs":
                    lambda: self.api.list_programs(),
                "list_projects":
                    lambda: self.api.list_projects(),
                "list_scripts":
                    lambda: self.api.list_scripts(),
                "switch_program":
                    lambda: self._do_switch_program(p("program", "")),
                "xrefs_to":
                    lambda: self.api.get_xrefs_to(
                        p("address"), int(p("offset", 0)),
                        int(p("limit", 100)), int(p("size", 1)),
                        # NOT p("grouped", "false") directly -- confirmed
                        # 2026-07-12 that get_xrefs_to's internal `if grouped:`
                        # check treats ANY non-empty string (including the
                        # literal text "false") as truthy, so grouped output
                        # was ALWAYS being returned regardless of the actual
                        # requested value until this explicit .lower()=="true"
                        # coercion (matching the established idiom already
                        # used correctly for signed/fpu_only/include_incoming
                        # below) was added.
                        p("grouped", "false").lower() == "true"),
                "xrefs_from":
                    lambda: self.api.get_xrefs_from(
                        p("address"), int(p("offset", 0)),
                        int(p("limit", 100)), int(p("size", 1))),
                "find_next_symbol":
                    lambda: self.api.find_next_symbol(
                        p("address"), p("direction", "forward"),
                        p("element_size")),
                "function_xrefs":
                    lambda: self._do_function_xrefs(
                        p("name", p("address", "")),
                        int(p("offset", 0)), int(p("limit", 100))),
                # Stubs
                "classes": lambda: self.api.list_classes(
                    int(p("offset", 0)), int(p("limit", 100))),
                "list_class_methods": lambda: self.api.list_class_methods(
                    p("class_name", ""), int(p("offset", 0)), int(p("limit", 500))),
                "segments": lambda: self.api.list_segments(
                    int(p("offset", 0)), int(p("limit", 100))),
                "imports": lambda: self.api.list_imports(
                    int(p("offset", 0)), int(p("limit", 100))),
                "exports": lambda: self.api.list_exports(
                    int(p("offset", 0)), int(p("limit", 100))),
                "namespaces": lambda: self.api.list_namespaces(
                    int(p("offset", 0)), int(p("limit", 100))),
                "data": lambda: self.api.list_data(
                    int(p("offset", 0)), int(p("limit", 100))),
                "disassemble_function":
                    lambda: self.api.disassemble_function(
                        p("address"), int(p("offset", 0)), int(p("limit", 0)),
                        start_address=p("start_address")),
                "list_callees":
                    lambda: self.api.list_callees(
                        p("address"), int(p("offset", 0)), int(p("limit", 100))),
                "function_callers":
                    lambda: self.api.get_function_callers(
                        p("address"), int(p("offset", 0)), int(p("limit", 100))),
                "function_call_graph":
                    lambda: self.api.get_function_call_graph(
                        p("address"), int(p("depth", 2)), p("direction", "both")),
                "get_struct_layout": lambda: self.api.get_struct_layout(p("name", "")),
                "class_structure_diagnostic": lambda: self.api.class_structure_diagnostic(p("function_address", "")),
                "get_function_hash": lambda: self.api.get_function_hash(p("address")),
                "compare_program_functions":
                    lambda: self.api.compare_program_functions(
                        p("source_program"), p("target_program"),
                        int(p("min_instructions", "15")), int(p("limit", "500"))),
                "analyze_dataflow":
                    lambda: self.api.analyze_dataflow(
                        p("address"), p("variable", ""), p("direction", "backward"),
                        int(p("max_steps", 20))),
                "get_instruction_facts": lambda: self.api.get_instruction_facts(p("address")),
                "get_function_exact_facts":
                    lambda: self.api.get_function_exact_facts(
                        p("address"), int(p("limit", 200)), int(p("offset", 0))),
                "get_address_exact_facts":
                    lambda: self.api.get_address_exact_facts(
                        p("address"), int(p("limit", 100)), int(p("offset", 0))),
                "get_type_exact_facts":
                    lambda: self.api.get_type_exact_facts(
                        p("name", ""), int(p("limit", 100)), int(p("offset", 0))),
                "get_exact_neighborhood":
                    lambda: self.api.get_exact_neighborhood(
                        p("address"), int(p("depth", 1)), int(p("limit", 200)),
                        p("include_incoming", "true").lower() == "true",
                        p("include_outgoing", "true").lower() == "true"),
                "get_basic_blocks":
                    lambda: self.api.get_basic_blocks(p("address")),
                "get_function_body_bytes":
                    lambda: self.api.get_function_body_bytes(p("address")),
                "search_bytes":
                    lambda: self.api.search_bytes(p("pattern"), int(p("limit", 200))),
                "get_stack_variables":
                    lambda: self.api.get_stack_variables(p("address")),
                "stack_depth":
                    lambda: self.api.get_stack_depth(p("address")),
                "abi_summary":
                    lambda: self.api.get_abi_summary(p("address")),
                "propose_struct_fields":
                    lambda: self.api.propose_struct_fields(
                        p("address"), int(p("this_param_index", 0))),
                "get_referenced_strings":
                    lambda: self.api.get_referenced_strings(p("address")),
                "scan_unnamed_labels":
                    lambda: self.api.scan_unnamed_labels(
                        p("name_prefix", "FUN_"),
                        int(p("max_functions", "500")),
                        int(p("max_string_len", "80")),
                        int(p("limit", "200")),
                        int(p("offset", "0"))),
                "find_class_ownership_strings":
                    lambda: self.api.find_class_ownership_strings(
                        int(p("max_functions", "5000")),
                        int(p("max_string_len", "80")),
                        int(p("limit", "200")),
                        int(p("offset", "0")),
                        p("only_mismatches", "false").lower() in ("1", "true", "yes")),
                "classify_function_inventory":
                    lambda: self.api.classify_function_inventory(
                        p("name_prefix", "FUN_"),
                        int(p("max_functions", "8000")),
                        int(p("limit", "500")),
                        int(p("offset", "0"))),
                "get_allocation_site_info":
                    lambda: self.api.get_allocation_site_info(
                        p("address"), int(p("lookback", "15")), int(p("lookahead", "15"))),
                "resolve_call_site_context":
                    lambda: self.api.resolve_call_site_context(
                        p("address"), int(p("max_args", "8")),
                        int(p("lookback", "40")), int(p("lookahead", "15"))),
                "get_seh_frame_info":
                    lambda: self.api.get_seh_frame_info(p("address")),
                "map_function_by_debug_strings":
                    lambda: self.api.map_function_by_debug_strings(
                        p("filter_str", None),
                        [a.strip() for a in p("string_addresses", "").split(",") if a.strip()] or None,
                        int(p("min_hits", "1"))),
                "find_thunk_candidates":
                    lambda: self.api.find_thunk_candidates(
                        int(p("min_gap_bytes", "4")),
                        int(p("max_gap_bytes", "128")),
                        int(p("max_tail_bytes", "6")),
                        int(p("limit", "200"))),
                "find_vtable_candidates":
                    lambda: self.api.find_vtable_candidates(
                        p("start"), p("end"), int(p("min_slots", "3"))),
                "trace_vtable_assignments":
                    lambda: self.api.trace_vtable_assignments(p("address")),
                "classify_pointer_provenance":
                    lambda: self.api.classify_pointer_provenance(
                        p("address"), p("function_address"), p("offset"),
                        int(p("max_backtrack", "15"))),
                "hook_point":
                    lambda: self.api.find_hook_point(
                        p("address"), int(p("min_bytes", "5"))),
                "get_bytes":
                    lambda: self.api.get_bytes(p("address"), int(p("size", "1"))),
                "read_float":
                    lambda: self.api.read_float(p("address")),
                "read_double":
                    lambda: self.api.read_double(p("address")),
                "read_float_array":
                    lambda: self.api.read_float_array(
                        p("address"), int(p("count", "1"))),
                "read_double_array":
                    lambda: self.api.read_double_array(
                        p("address"), int(p("count", "1"))),
                "read_pointer_array":
                    lambda: self.api.read_pointer_array(
                        p("address"), int(p("count", "1"))),
                "read_int_array":
                    lambda: self.api.read_int_array(
                        p("address"), int(p("count", "1")),
                        int(p("size", "4")),
                        p("signed", "false").lower() == "true"),
                "read_float_matrix":
                    lambda: self.api.read_float_matrix(
                        p("address"), int(p("row_stride_bytes")),
                        int(p("num_rows")), int(p("row_length"))),
                "resolve_switch_dispatch":
                    lambda: self.api.resolve_switch_dispatch(
                        p("byte_table_addr"), int(p("entry_count")),
                        p("jump_table_addr"),
                        int(p("case_value_start", "0"))),
                "read_int":
                    lambda: self.api.read_int(p("address"),
                                               int(p("size", "4")),
                                               p("signed", "true").lower() == "true"),
                "trace_fpu_stack":
                    lambda: self.api.trace_fpu_stack(
                        p("address"), int(p("start_offset", "0")),
                        int(p("count", "20")),
                        start_address=p("start_address"),
                        fpu_only=p("fpu_only", "false").lower() == "true"),
            }
            handler = handlers.get(path)
            if handler:
                return self._send_json(handler())
            self._send_error(f"Unknown endpoint: /{path}", 404)

        except Exception as e:
            logger.error("GET /%s: %s\n%s", path, e, traceback.format_exc())
            self._send_error(str(e))

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_POST(self):
        path = urlparse(self.path).path.strip("/")
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length else "{}"
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            # Fallback: parse as form-encoded (requests sends dict as form by default)
            from urllib.parse import parse_qs
            parsed = parse_qs(body)
            data = {k: v[0] if len(v) == 1 else v for k, v in parsed.items()}

        try:
            handlers = {
                "import_raw_68k": lambda: self.api.import_program(data.get("path", ""), "/", bool(data.get("analyze", False)), str(data.get("base_address", "0"))),
                'delete_data_type': lambda: self.api.delete_data_type(
                    data.get("name", ""), data.get("category", ""),
                    _form_bool(data.get("force", False))),
                'list_call_fixups': lambda: self.api.list_call_fixups(),
                'set_call_fixup': lambda: self.api.set_call_fixup(
                    data.get("function_address", ""), data.get("fixup_name", "")),
                'set_calling_convention': lambda: self.api.set_calling_convention(
                    data.get("function_address", ""), data.get("convention_name", "")),
                "decompile": lambda: self.api.decompile_function(
                    data.get("address", ""), int(data.get("offset", 0)),
                    int(data.get("limit", 0))),
                "decompile_function": lambda: self.api.decompile_function(
                    data.get("address", ""), int(data.get("offset", 0)),
                    int(data.get("limit", 0))),
                "searchFunctions": lambda: self.api.find_function(
                    data.get("name", "")),
                "switch_program": lambda: self._do_switch_program(
                    data.get("program", "")),
                "switch_project": lambda: self.api.switch_project(
                    data.get("project", ""), data.get("program", "")),
                "import_program": lambda: self.api.import_program(
                    data.get("path", ""), data.get("folder", "/") or "/",
                    str(data.get("analyze", "")).lower() in ("1", "true", "yes")),
                "apply_map_symbols": lambda: self.api.apply_map_symbols(
                    data.get("map_path", ""),
                    str(data.get("demangle", "true")).lower() in ("1", "true", "yes"),
                    str(data.get("create_functions", "true")).lower() in ("1", "true", "yes")),
                "run_script": lambda: self.api.run_script(
                    data.get("script", ""), data.get("args", "")),
                "rename_function_by_address": lambda: self.api.rename_function_by_address(
                    data.get("function_address", ""),
                    data.get("new_name", "")),
                "renameFunction": lambda: self._do_rename_function_by_name(
                    data.get("oldName", ""),
                    data.get("newName", "")),
                "renameData": lambda: self.api.rename_data(
                    data.get("address", ""),
                    data.get("newName", "")),
                "set_decompiler_comment": lambda: self.api.set_decompiler_comment(
                    data.get("address", ""),
                    data.get("comment", ""),
                    data.get("comment_type", "eol")),
                "set_disassembly_comment": lambda: self.api.set_disassembly_comment(
                    data.get("address", ""),
                    data.get("comment", "")),
                "renameVariable": lambda: self.api.rename_variable_by_name(
                    data.get("functionName", ""),
                    data.get("oldName", ""),
                    data.get("newName", "")),
                "rename_variable_by_address": lambda: self.api.rename_variable_by_address(
                    data.get("function_address", ""),
                    data.get("old_name", ""),
                    data.get("new_name", "")),
                "uncommit_variable": lambda: self.api.uncommit_variable(
                    data.get("function_address", ""),
                    data.get("variable_name", "")),
                "list_committed_variables": lambda: self.api.list_committed_variables(
                    data.get("function_address", "")),
                "set_function_prototype": lambda: self.api.set_function_prototype(
                    data.get("function_address", ""),
                    data.get("prototype", "")),
                "set_full_prototype": lambda: self.api.set_full_prototype(
                    data.get("function_address", ""),
                    data.get("calling_convention", ""),
                    data.get("return_type", ""),
                    data.get("parameters", "[]")),
                "set_local_variable_type": lambda: self.api.set_local_variable_type(
                    data.get("function_address", ""),
                    data.get("variable_name", ""),
                    data.get("new_type", "")),
                "analyze": lambda: self.api.analyze(),
                "create_function": lambda: self.api.create_function(
                    data.get("address", ""), data.get("name", "")),
                "delete_function": lambda: self.api.delete_function(
                    data.get("address", "")),
                "resolve_vtable": lambda: self.api.resolve_vtable(
                    data.get("address", ""), int(data.get("count", 0))),
                "create_vtable_type": lambda: self.api.create_vtable_type(
                    data.get("name", ""), data.get("vtable_address", ""),
                    data.get("slots", []), data.get("category", "Vtables"),
                    _form_bool(data.get("replace", False))),
                "create_label": lambda: self.api.create_label(
                    data.get("address", ""), data.get("name", "")),
                "set_data_type": lambda: self.api.set_data_type(
                    data.get("address", ""), data.get("type_name", "")),
                "get_comments": lambda: self.api.get_comments(
                    data.get("address", "")),
                "save": lambda: self.api.save(),
                "create_structure": lambda: self.api.create_structure(
                    data.get("name", ""),
                    data.get("category", DEFAULT_CATEGORY),
                    data.get("fields", []),
                    _form_bool(data.get("replace", False))),
                "batch_decompile": lambda: self.api.batch_decompile(data.get("addresses", [])),
                "batch_set_comments": lambda: self.api.batch_set_comments(data.get("comments", [])),
                "create_structure_from_offsets": lambda: self.api.create_structure_from_offsets(
                    data.get("name", ""), data.get("category", DEFAULT_CATEGORY),
                    data.get("fields", []), int(data.get("total_size", 0)),
                    _form_bool(data.get("replace", False))),
                "set_this_type": lambda: self.api.set_this_type(
                    data.get("function_address", ""), data.get("new_type", ""),
                    data.get("force", False), data.get("override_detected_local", False),
                    data.get("insert_as_new_parameter", False)),
                "materialize_ecx_thiscall_callback": lambda: self.api.materialize_ecx_thiscall_callback(
                    data.get("function_address", ""), data.get("this_type", ""),
                    data.get("stack_argument_type", "void *"), data.get("stack_argument_name", "callback_argument"),
                    data.get("evidence_instruction_address", ""), data.get("expected_ret_purge_bytes", 4),
                    data.get("replace_existing", False)),
                "materialize_ecx_thiscall_receiver": lambda: self.api.materialize_ecx_thiscall_receiver(
                    data.get("function_address", ""), data.get("this_type", ""),
                    data.get("evidence_instruction_address", "")),
                "class_structure_diagnostic": lambda: self.api.class_structure_diagnostic(
                    data.get("function_address", "")),
                "promote_class_structure_fields": lambda: self.api.promote_class_structure_fields(
                    data.get("class_name", ""), data.get("source_name", ""),
                    _form_bool(data.get("confirm", False)),
                    data.get("target_size")),
                "retype_variable_at": lambda: self.api.retype_variable_at(
                    data.get("function_address", ""), data.get("instruction_address", ""),
                    data.get("new_type", ""), data.get("side", "output"),
                    int(data.get("input_index", 0))),
                "manage_namespace": lambda: self.api.manage_namespace(
                    data.get("operation", ""), data.get("path", ""),
                    data.get("new_name", ""), data.get("new_parent_path", "")),
                "set_parameter": lambda: self.api.set_parameter(
                    data.get("function_address", ""), int(data.get("index", 0)),
                    data.get("new_name", ""), data.get("new_type", "")),
                "repair_function_parameters": lambda: self.api.repair_function_parameters(
                    data.get("function_address", ""), data.get("parameters", [])),
                "set_return_type": lambda: self.api.set_return_type(
                    data.get("function_address", ""), data.get("new_type", "")),
                "edit_structure_field": lambda: self.api.edit_structure_field(
                    data.get("struct_name", ""), data.get("category", DEFAULT_CATEGORY),
                    data.get("operation", ""), int(data.get("offset", 0)),
                    data.get("field_name", ""), data.get("field_type", ""),
                    int(data.get("field_size", 0)), int(data.get("expected_size", 0)),
                    _form_bool(data.get("allow_resize", False)),
                    _form_bool(data.get("dry_run", False))),
                "create_enum": lambda: self.api.create_enum(
                    data.get("name", ""), data.get("category", DEFAULT_CATEGORY),
                    data.get("values", {}), int(data.get("size", 4)),
                    _form_bool(data.get("replace", False))),
                "create_typedef": lambda: self.api.create_typedef(
                    data.get("name", ""), data.get("category", DEFAULT_CATEGORY),
                    data.get("base_type", "")),
                "create_function_pointer_type": lambda: self.api.create_function_pointer_type(
                    data.get("name", ""), data.get("category", DEFAULT_CATEGORY),
                    data.get("return_type", ""), data.get("param_types", []),
                    data.get("calling_convention", "")),
            }
            handler = handlers.get(path)
            if handler:
                return self._send_json(handler())
            self._send_error(f"Unknown endpoint: /{path}", 404)
        except Exception as e:
            logger.error("POST /%s: %s", path, e)
            self._send_error(str(e))

    def _do_function_xrefs(self, name_or_addr, offset, limit):
        """Resolve function name to address then get xrefs."""
        # Try as name first (linear scan avoids getFunction(str,None) overload crash)
        fn = self.api._find_function_by_name(name_or_addr)
        if fn:
            addr = str(fn.getEntryPoint())
        else:
            addr = name_or_addr  # fallback: treat as raw address
        return self.api.get_xrefs_to(addr, offset, limit)

    def _do_switch_program(self, program_path):
        if not program_path:
            return json.dumps({"error": "Missing 'program' query parameter"})
        try:
            self.api.switch_program(program_path)
            return json.dumps({
                "status": "ok",
                "program": self.api._program.getName(),
                "path": program_path,
                "functions": self.api._function_manager.getFunctionCount(),
            })
        except Exception as e:
            return json.dumps({"error": str(e)})

    def _do_rename_function_by_name(self, old_name, new_name):
        """Rename a function by its current name. Resolves name to address first."""
        fn = self.api._find_function_by_name(old_name)
        if fn is None:
            return json.dumps({"error": f"Function '{old_name}' not found"})
        return self.api.rename_function_by_address(str(fn.getEntryPoint()), new_name)

    def log_message(self, fmt, *args):
        logger.debug(fmt, *args)


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    parser = argparse.ArgumentParser(description="Ghidra headless MCP HTTP server")
    parser.add_argument("--port", type=int, default=8082, help="HTTP server port")
    parser.add_argument("--project-dir", default=PROJECT_DIR)
    parser.add_argument("--project-name", default=PROJECT_NAME)
    parser.add_argument("--program-path", default=DEFAULT_PROGRAM_PATH)
    parser.add_argument("--create-project", action=argparse.BooleanOptionalAction,
                        default=True, help="Create the configured project when it does not exist")
    args = parser.parse_args()

    if not HAS_GHIDRA:
        logger.error("pyghidra not installed. Run: pip install pyghidra")
        sys.exit(1)

    ghidra_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if not ghidra_dir:
        logger.error("GHIDRA_INSTALL_DIR not set")
        sys.exit(1)

    logger.info("Starting Ghidra JVM...")
    pyghidra.start()
    _init_java_classes()

    registry = {"projects": {}}
    if os.path.exists(PROJECTS_FILE):
        with open(PROJECTS_FILE, encoding="utf-8") as handle:
            registry = json.load(handle)
    # The command-line project is the one opened at startup; it is looked up
    # in the registry by location, and added to it if it is not there.
    start_key = next((key for key, entry in registry.get("projects", {}).items()
                      if os.path.realpath(entry["dir"]) == os.path.realpath(args.project_dir)
                      and entry["name"] == args.project_name), None)
    if start_key is None:
        start_key = args.project_name
        registry.setdefault("projects", {})[start_key] = {
            "dir": args.project_dir, "name": args.project_name,
            "create": args.create_project, "description": "from the command line"}

    api = GhidraAPI()
    api.set_registry(registry)
    api.switch_project(start_key, args.program_path)
    logger.info("Project %s active, program %s", start_key, api._current_program_path)

    GhidraRequestHandler.api = api
    server = HTTPServer(("127.0.0.1", args.port), GhidraRequestHandler)
    logger.info("Ghidra server running on http://127.0.0.1:%d", args.port)
    logger.info("Available endpoints: /methods, /list_functions, /decompile_function, /strings, /xrefs_to, ...")
    logger.info("Available programs: %s", api.list_programs())

    # Handle SIGTERM for clean shutdown (ghidrad.sh stop sends SIGTERM)
    shutdown_requested = False

    def _handle_sigterm(signum, frame):
        nonlocal shutdown_requested
        if shutdown_requested:
            return  # already shutting down
        shutdown_requested = True
        logger.info("SIGTERM received, saving and shutting down...")
        # Do NOT call server.shutdown() here: it blocks waiting for
        # serve_forever()'s own loop to notice and exit, but that loop
        # runs on this same (main) thread -- currently suspended inside
        # the very select() call this signal just interrupted. Calling
        # shutdown() from here deadlocks, the init script's do_stop times
        # out after 5s and sends SIGKILL (uncatchable), and this whole
        # handler -- including the save below -- never gets to run.
        # Save synchronously right here instead, then hard-exit.
        try:
            api.close_projects()
            logger.info("Saved on shutdown")
        except Exception:
            logger.exception("Save on shutdown failed")
        os._exit(0)

    signal.signal(signal.SIGTERM, _handle_sigterm)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        server.shutdown()
    finally:
        # Always save on the way down, regardless of the auto-save counter
        # in _with_transaction — a clean stop/restart must never lose the
        # last batch of writes just because it didn't happen to land on a
        # multiple of _AUTO_SAVE_INTERVAL.
        try:
            api.close_projects()
            logger.info("Saved on shutdown")
        except Exception:
            logger.exception("Save on shutdown failed")
        # Give JVM and decompile children time to exit cleanly
        import time
        time.sleep(0.5)


if __name__ == "__main__":
    main()
