import ast, hashlib, json, shutil
from pathlib import Path
import argparse
parser=argparse.ArgumentParser(description='Generate unadapted merge into a separate output directory; does not apply Mac fixes')
parser.add_argument('--output',type=Path,required=True)
out=parser.parse_args().output.resolve()
if out==Path(__file__).resolve().parent/'vendor': raise SystemExit('Refusing to overwrite adapted live sources')
out.mkdir(parents=True,exist_ok=True)
c=Path('/home/harri/.ghidra_mcp_venv_2'); f=Path('/home/harri/.ghidra_mcp_venv')
manifest={}
for filename in ['ghidra_headless_server.py','bridge_mcp_ghidra.py']:
    cs=(c/filename).read_text(); fs=(f/filename).read_text()
    ct=ast.parse(cs); ft=ast.parse(fs)
    edits=[]; added=[]
    if filename.startswith('ghidra_headless'):
        for fc in [n for n in ft.body if isinstance(n,ast.ClassDef)]:
            cc=next((n for n in ct.body if isinstance(n,ast.ClassDef) and n.name==fc.name),None)
            if not cc: continue
            names={n.name for n in cc.body if isinstance(n,ast.FunctionDef)}
            missing=[n for n in fc.body if isinstance(n,ast.FunctionDef) and n.name not in names]
            chunks=[]
            for n in missing:
                start=min([n.lineno]+[d.lineno for d in n.decorator_list])
                chunks.append('\n'.join(fs.splitlines()[start-1:n.end_lineno]))
                added.append(fc.name+'.'+n.name)
            if chunks: edits.append((cc.end_lineno,cc.end_lineno,'\n'+'\n\n'.join(chunks)+'\n'))
            for method in ['do_GET','do_POST']:
                fm=next((n for n in fc.body if isinstance(n,ast.FunctionDef) and n.name==method),None)
                cm=next((n for n in cc.body if isinstance(n,ast.FunctionDef) and n.name==method),None)
                if not fm or not cm: continue
                def handlers(m):
                    return next(n.value for n in ast.walk(m) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='handlers' for t in n.targets))
                fd,cd=handlers(fm),handlers(cm)
                keys={k.value for k in cd.keys}
                entries=[repr(k.value)+': '+ast.get_source_segment(fs,v)+',' for k,v in zip(fd.keys,fd.values) if k.value not in keys]
                # Insert just after opening dictionary (all lambdas reference same handler scope).
                if entries: edits.append((cd.lineno,cd.lineno,'\n'.join('                '+e for e in entries)))
        # Class-level detector metadata required by FlexTalk verifier.
        fc=next(n for n in ft.body if isinstance(n,ast.ClassDef) and n.name=='GhidraAPI')
        cc=next(n for n in ct.body if isinstance(n,ast.ClassDef) and n.name=='GhidraAPI')
        for n in fc.body:
            if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='_DECOMPILE_CONSTANT_DETECTORS' for t in n.targets):
                edits.append((cc.lineno,cc.lineno,'\n'.join(fs.splitlines()[n.lineno-1:n.end_lineno])))
    else:
        names={n.name for n in ct.body if isinstance(n,ast.FunctionDef)}
        for n in ft.body:
            if isinstance(n,ast.FunctionDef) and n.name not in names:
                start=min([n.lineno]+[d.lineno for d in n.decorator_list])
                edits.append((next(x.lineno-1 for x in ct.body if isinstance(x,ast.If) and '__name__' in ast.unparse(x.test)),)*2+('\n'.join(fs.splitlines()[start-1:n.end_lineno])+'\n',))
                added.append(n.name)
    lines=cs.splitlines()
    for start,end,replacement in sorted(edits,reverse=True): lines[start:end]=[replacement]
    result='\n'.join(lines)+'\n'
    ast.parse(result)
    (out/filename).write_text(result)
    manifest[filename]={'creatures_sha256':hashlib.sha256(cs.encode()).hexdigest(),'flextalk_sha256':hashlib.sha256(fs.encode()).hexdigest(),'added_from_flextalk':added}
for name in ['instance_config.py','capability_catalog.py']: shutil.copy2(c/name,out/name)
(out.parent/'merge-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
