"""Strict classic resource-fork containers and inventory, no format guessing."""
import hashlib, struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]

def resource_fork(path: str, container: str='auto') -> tuple[bytes,str]:
    data=Path(path).read_bytes()
    if len(data)>128*1024*1024: raise ValueError('Resource container exceeds 128 MiB')
    if container=='auto':
        if data[:4] in (b'\0\x05\x16\x07',b'\0\x05\x16\0'): container='appledouble'
        elif len(data)>=128 and data[0]==0 and 1<=data[1]<=63 and data[74]==0 and data[82]==0: container='macbinary'
        else: container='raw'
    if container=='appledouble':
        count=struct.unpack_from('>H',data,24)[0]
        for i in range(count):
            kind,start,size=struct.unpack_from('>III',data,26+12*i)
            if kind==2:
                if start+size>len(data): raise ValueError('Truncated resource entry')
                data=data[start:start+size];break
        else: raise ValueError('No resource fork entry')
    elif container=='macbinary':
        data_len,size=struct.unpack_from('>II',data,83)
        start=128+((data_len+127)//128)*128
        if start+size>len(data): raise ValueError('Truncated MacBinary')
        data=data[start:start+size]
    elif container!='raw': raise ValueError('container must be auto, raw, appledouble or macbinary')
    inventory(data) # validate before creating any output
    return data,container

def inventory(data:bytes) -> list[dict]:
    def take(start,size):
        if start<0 or size<0 or start+size>len(data): raise ValueError('Resource fork offset outside file')
        return data[start:start+size]
    do,mo,dl,ml=struct.unpack('>IIII',take(0,16))
    take(do,dl);take(mo,ml)
    if ml<28: raise ValueError('Resource map too short')
    to,no=struct.unpack('>HH',take(mo+24,4));types=mo+to;names=mo+no
    count=struct.unpack('>H',take(types,2))[0]+1
    if count==65536: return []
    result=[]
    for i in range(count):
        entry=take(types+2+i*8,8)
        typ=entry[:4].decode('mac_roman');n,ref=struct.unpack('>HH',entry[4:])
        for j in range(n+1):
            e=take(types+ref+j*12,12);rid,name=struct.unpack('>hH',e[:4]);offset=int.from_bytes(e[5:8],'big')
            start=do+offset;size=struct.unpack('>I',take(start,4))[0];take(start+4,size)
            if offset+4+size>dl: raise ValueError('Resource data outside data section')
            title=None
            if name!=65535:
                length=take(names+name,1)[0];title=take(names+name+1,length).decode('mac_roman')
            result.append({'type':typ,'id':rid,'name':title,'size':size,'offset':start+4,'attributes':e[4]})
    return result

def prepare(path:str,container:str='auto') -> dict:
    source=Path(path).resolve()
    if not source.is_relative_to(ROOT): raise ValueError('Source must be in OldMacStuff')
    data,kind=resource_fork(str(source),container)
    digest=hashlib.sha256(data).hexdigest()
    dest=ROOT/'MacRE/imports'/digest[:16]/(source.name+'.rsrc')
    dest.parent.mkdir(parents=True,exist_ok=True)
    if dest.exists() and dest.read_bytes()!=data: raise ValueError('Output collision')
    if not dest.exists(): dest.write_bytes(data)
    return {'source':str(source),'container':kind,'resource_fork':str(dest),'sha256':digest,'resources':inventory(data)}
