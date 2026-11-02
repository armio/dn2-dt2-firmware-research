"""Exact-instruction OR-FDEP model for two byte-bound donor conversion sites.

ADI classic Programming Reference rev2.4 pp12-10/11: immediate shift opcode
uses upper6 bits of eight-bit opcode. OR-FDEP0x64 =>0x19. SHARC+ PRM table18-9
has inconsistent immediate entries (0x19 attributed to BITEXT(NU)); the frozen
runner inherits that table. We use the documented OR-FDEP operation for the
exact two compiler-runtime words, not a float/int conversion stub or global
emulator change. Existing deposited output bits and unaffected status survive.
"""
from pathlib import Path
import hashlib
ENTRY=0xb88f70
SITES={0x34:(0x023e00195f0c,0,12,31,1),0x76:(0x023e10191702,0,2,23,8)}
# tuple: exact native48-bit word, Rn, Rx, bit6, len6
class NativeConversionModel:
 def __init__(self,st,memory,entry=ENTRY):
  self.st,self.memory,self.entry=st,memory,entry;self.events=[]
  for delta,(raw,*_) in SITES.items():
   insn=st.decode_at(memory,None,entry+delta)
   if insn.raw!=raw or insn.type_name!='6b_shiftimm' or insn.length_bytes!=6:raise ValueError(('conversion instruction binding differs',hex(entry+delta),hex(insn.raw)))
 def hook(self,r):
  from sharc_core.flags import _astatx_fext
  state=r.state;pc=state.pc_sw;raw,rn,rx,pos,length=SITES[pc-self.entry]
  insn=r._decode(pc)
  if insn.raw!=raw or insn.length_bytes!=6:raise ValueError('conversion model byte mismatch')
  dest,src=state.uregs[rn],state.uregs[rx]
  if not isinstance(dest,self.st.Const) or not isinstance(src,self.st.Const):raise ValueError('conversion operands not concrete')
  value=self.st.Const((dest.value|((src.value&((1<<length)-1))<<pos))&0xffffffff)
  state.uregs[rn]=value
  code=self.st.UREG_CODES['ASTATX'];state.uregs[code]=_astatx_fext(pos+length,value)(state.uregs[code])
  self.events.append(dict(pc=hex(pc),rn=rn,rx=rx,bit=pos,length=length,previous=dest.value,source=src.value,result=value.value))
  state.pc_sw+=3
 def install(self,fixups):
  for delta in SITES:
   pc=self.entry+delta
   if pc in fixups.hooks:raise ValueError('conversion model hook collision')
   fixups.hooks[pc]=self.hook
