from pathlib import Path
import struct
# Near-model CODE0 jump-table entry and CODE1 return 42 + typed big-endian test data.
code0=struct.pack('>IIIIHHHH',0,0,8,32,0,0x3f3c,1,0xa9f0)
code1=bytes.fromhex('00000000 702a4e75 12345678 3f800000 3ff0000000000000 00000002')
resources=[code0,code1]
data=b'';refs=b''
for i,r in enumerate(resources):
 refs+=struct.pack('>HH',i,0xffff)+len(data).to_bytes(4,'big')+b'\0'*4
 data+=struct.pack('>I',len(r))+r
map_offset=256+len(data)
header=struct.pack('>IIII',256,map_offset,len(data),28+2+8+len(refs))
resource_map=header+b'\0'*8+struct.pack('>HH',28,28+2+8+len(refs))+struct.pack('>H4sHH',0,b'CODE',1,10)+refs
out=Path('/home/harri/OldMacStuff/tools/mac-re/fixtures');out.mkdir(exist_ok=True)
(out/'return42.rsrc').write_bytes(header+b'\0'*(256-16)+data+resource_map)
