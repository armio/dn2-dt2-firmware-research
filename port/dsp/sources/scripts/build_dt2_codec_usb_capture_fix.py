#!/usr/bin/env python3
"""Fix T1DQ's illegal same-DAG indexed stores without changing its layout."""
from pathlib import Path
import argparse,json
import build_dt2_codec_usb_capture as P
C=P.C
BASE=C.ROOT/'output/dn2-research/dt2-dsp-codec-usb-capture-20261012/section_7.bin'
BASE_SHA='8f74f19df77e8d9cd5ab36ad186e2a492dd8ea53f91f98f238fe7c63a2b82ae3'
# Every replacement is the existing6-byte instruction with UREG I0 -> R0.
# The private USB scratch word now preservesR0 instead ofI0. The indexed
# stores then use exactly the native legal data-register encoding family.
PATCHES=((0xbf14a7,0x1110200e3928),(0xbf14aa,0x0f10200e3800),
 (0xbf14ad,0xad10ffffff80),(0xbf14b0,0xad10ffffff81),
 (0xbf14b6,0x0f103f800000),(0xbf14b9,0xad10ffffff82),
 (0xbf14bc,0xad10ffffff85),(0xbf14bf,0x1010200e3928))
INDEXED=(0xbf14ad,0xbf14b0,0xbf14b9,0xbf14bc)
REFERENCE='https://www.analog.com/media/en/dsp-documentation/processor-manuals/SC58x-2158x-prm.pdf#page=390'


def build(out):
 raw=BASE.read_bytes();assert C.SHA(raw)==BASE_SHA
 doc=json.loads((BASE.parent/'build-receipt.json').read_text())
 k=C.M.Digikit(C.SRC/'toolchains/digikit');k.ldr.L2_BYTE_LIMIT=0x20100000;m=P.B.decode_view(k,raw)
 image=bytearray(raw);patches=[]
 for pc,before in PATCHES:
  ins=k.st.decode_at(m,None,pc);assert ins.length_bytes==6 and ins.raw==before
  assert (before>>32)&0x7f==0x10
  after=before&~(0x7f<<32)
  C.B.write_span(image,C.S.code_address(pc,window='l2'),C.S.to_bytes(after))
  patches.append(dict(pc=hex(pc),before=C.S.to_bytes(before).hex(),after=C.S.to_bytes(after).hex(),raw_before=hex(before),raw_after=hex(after)))
 result=bytes(image);assert C.B.walk(result).complete
 out.mkdir(parents=True,exist_ok=False)
 doc.update(baseline_sha256=BASE_SHA,section7_sha256=C.SHA(result),flash_ready=False)
 doc['codec_usb_capture_fix']=dict(base=str(BASE.resolve()),base_sha256=BASE_SHA,patches=patches,
  fault=dict(reason='0x501 ILOPI',pc='0xbf14ad',instruction='DM(-128,I6)=I0',raw='0xad10ffffff80',evidence=str((C.ROOT/'output/dn2-research/t1dq-silent-fault-20261012/diagnostics-1.json').resolve())),
  cause='Type15a indexed data-memory stores cannot read their source UREG from the same DAG as the address index. I0 and I6 both belong toDAG1; the old interpreter accepted this forbidden combination.',
  correction='Use preservedR0 for the existing USB descriptor scratch, constants and indexed stores. Exact same instruction widths and addresses; no new hooks, buffers or execution paths.',
  unchanged=['Completed-codec snapshot conversion and guard','Physical PCM and page toggle','Other USB streams','Existing timing observations','USB MAIN previous-block diagnostic purpose'],
  reference=REFERENCE,reference_section='Type15a SISD restrictions, PRM16–7/16–8',
  remaining=['Hardware confirmation that the identified illegal instruction is eliminated and audio/USB recover.'])
 (out/'section_7.bin').write_bytes(result);(out/'build-receipt.json').write_text(json.dumps(doc,indent=2)+'\n')
 print(json.dumps(dict(section7_sha256=C.SHA(result),changed_instructions=len(patches),layout_unchanged=True),indent=2))


if __name__=='__main__':
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--out',type=Path,required=True);build(ap.parse_args().out)
