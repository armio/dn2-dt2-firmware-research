"""Scoped runner correction for SHARC+ unqualified register MODIFY.

ADI SC58x-2158x PRM, section Instruction Types / table6-2, p6-10,
and Type7a/7b pp14-46..14-50 (2023 edition): unqualified MODIFY adds the
modifier without scaling. Only explicit (sw)/(nw) forms scale in byte space.
https://www.analog.com/media/en/dsp-documentation/processor-manuals/SC58x-2158x-prm.pdf

The pinned runner instead scales Type7b and unqualified Type7a by4. Keep its
predicate, circular wrapping, compute and sequencing implementations; alter
only that form's modifier scale while it executes. No pinned files are edited.
Single-threaded offline execution only.
"""
from collections import Counter


def install():
    import sys
    import sharc_core.forms as forms
    import sharc_core.forms_dag as dag
    import sharc_core.memory as memory
    counts=Counter();sites=set()
    # PRM6-2: long-word and normal-word accesses use the same modifier
    # scaling. A long transfer moves 8 bytes, but its offset unit is 4 bytes
    # in byte-addressed space. The pinned runner incorrectly uses 8.
    original_scale=getattr(memory._access_modifier_scale,'_original_scale',memory._access_modifier_scale)
    def access_scale(width,assume):
        if width=='long-word':
            counts['long-word-offset']+=1
            return original_scale('normal-word',assume)
        return original_scale(width,assume)
    access_scale._original_scale=original_scale
    for name,module in list(sys.modules.items()):
        if name.startswith('sharc_core.') and hasattr(module,'_access_modifier_scale'):
            module._access_modifier_scale=access_scale
    # The older G3 post-fixup supplies the missing register-pair transfer for
    # Type3b/4b, but also hard-codes the wrong8-byte offset. Keep its pair
    # behavior and use the same corrected unit as the underlying core.
    fx=sys.modules.get('sharc_dn2_fixups')
    if fx is not None:
        def long_word(self,t,f,s,pc):
            if not self.is_long(t,f) or fx.F(f,'g'):return None
            if fx.cond_of(f)!=31 and fx.seq._predicate(s,fx.cond_of(f)) is not True:return None
            iv=s.uregs[16+fx.F(f,'i')]
            if not isinstance(iv,fx.Const):return None
            if t=='4b':
                offset=fx._signed((fx.F(f,'data[5:5]')<<5)|fx.F(f,'data[4:0]'),6)
                code=fx.F(f,'dreg')
            else:
                mv=s.uregs[32+fx.F(f,'m')]
                if not isinstance(mv,fx.Const):return None
                offset=fx._signed(mv.value,32);code=fx.F(f,'ureg')
            addr=iv.value if fx.F(f,'u') else (iv.value+4*offset)&0xffffffff
            if fx.F(f,'d'):
                _,values=fx.fm._lw_store_pair(dict(s.uregs),code)
                def post(r):
                    for j,v in enumerate(values):fx._dm_write(r.state,addr+4*j,4,v)
                    self.note('LW pair / normal-word offset',pc)
                return post
            codes=fx.fm._lw_load_codes(code)
            def post(r):
                for j,c in enumerate(codes):
                    value=fx._dm_read(r.state,addr+4*j,4)
                    if value is not None:r.state.uregs[c]=value
                self.note('LW pair / normal-word offset',pc)
            return post
        fx.Fixups.long_word=long_word
    for kind in ('7a','7b'):
        original=getattr(forms.FORMS[kind],'_unscaled_modify_original',forms.FORMS[kind])
        def corrected(state,insn,fields,name,original=original,kind=kind):
            unqualified=kind=='7b' or not(fields.get('w',0) or fields.get('l',0))
            if not unqualified:return original(state,insn,fields,name)
            prior=dag._access_modifier_scale
            dag._access_modifier_scale=lambda width,assume:1
            try:
                counts[kind]+=1;sites.add(state.pc_sw)
                return original(state,insn,fields,name)
            finally:dag._access_modifier_scale=prior
        corrected._unscaled_modify_original=original
        forms.FORMS[kind]=corrected
    return counts,sites
