"""Publication-boundary tests use synthetic bytes; no firmware required."""
import copy
import hashlib
import importlib.util
import struct
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location('browser_export', Path(__file__).with_name('export_browser_recipe.py'))
EXPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXPORT)


class RecipeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root/'adapter.S').write_text('rts\n')
        self.proof = dict(source='adapter.S', sha256=EXPORT.sha(b'rts\n'), reason='Original test adapter')
        for name, data in [('input', b'abcdefgh'), ('output', b'cdef\0\0\x12\x34')]:
            (self.root/name).write_bytes(data)
        self.plan = dict(release='R012', inputs={}, sources={
            'dn2.3': dict(kind='firmware', input='dn2', section=3, path=str(self.root/'input'),
                          bytes=8, sha256=EXPORT.sha(b'abcdefgh'))}, images={
            'main': dict(path=str(self.root/'output'), bytes=8,
                         sha256=EXPORT.sha(b'cdef\0\0\x12\x34'), operations=[
                dict(kind='copy', source='dn2.3', offset=2, bytes=4),
                dict(kind='fill', value=0, bytes=2),
                dict(kind='scalar', value=0x1234, bytes=2, endian='big', provenance=self.proof)])})

    def test_export_contains_no_private_paths_or_donor_bytes(self):
        recipe = EXPORT.export(self.plan, self.root)
        rendered = str(recipe)
        self.assertNotIn(str(self.root), rendered)
        self.assertNotIn('abcdefgh', rendered)
        self.assertEqual(recipe['images']['main']['bytes'], 8)

    def test_refuses_unexplained_tail(self):
        self.plan['images']['main']['operations'].pop()
        with self.assertRaisesRegex(ValueError, 'unexplained'):
            EXPORT.export(self.plan, self.root)

    def test_refuses_opaque_literal_diff(self):
        self.plan['images']['main']['operations'] = [dict(kind='literal', hex='6364656600001234')]
        with self.assertRaisesRegex(ValueError, 'Unsupported operation'):
            EXPORT.export(self.plan, self.root)

    def test_refuses_unverified_scalar_source(self):
        self.proof['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'provenance mismatch'):
            EXPORT.export(self.plan, self.root)

    def test_refuses_adapter_containing_donor_bytes(self):
        self.plan['sources']['bad'] = dict(kind='adapter', path=str(self.root/'input'),
            bytes=8, sha256=EXPORT.sha(b'abcdefgh'), provenance=[self.proof],
            toolchain_sha256='1'*64, donor_holes=[dict(offset=2, bytes=4)])
        with self.assertRaisesRegex(ValueError, 'donor hole'):
            EXPORT.export(self.plan, self.root)

    def computed_plan(self, generator, data, result):
        (self.root/'firmware').write_bytes(data)
        (self.root/'computed').write_bytes(result)
        self.plan['sources']['dn2.7'] = dict(kind='firmware', input='dn2', section=7, path=str(self.root/'firmware'),
                                             bytes=len(data), sha256=EXPORT.sha(data))
        self.plan['sources']['table'] = dict(kind='computed', generator=generator, path=str(self.root/'computed'),
                                             bytes=len(result), sha256=EXPORT.sha(result), provenance=[self.proof],
                                             input=dict(source='dn2.7', offset=0, bytes=len(data)))

    def test_computed_source_names_formula_not_values(self):
        words = [(0x9f800000 + c * 0x00810000) & 0xffffffff for c in range(19)]
        data = struct.pack('>19I', *words)
        result = EXPORT.computed_data('sem-type-planes', data)
        sem, bp = struct.unpack('>19I', result[:76]), struct.unpack('>19I', result[76:])
        icon = sum(1 << (31 - r) for r in range(4, 9))
        for c in range(19):
            if 7 <= c < 12:
                self.assertEqual(sem[c] & ~icon & 0xffffffff, words[c] & ~icon & 0xffffffff)
                self.assertEqual(bp[c], words[c] & icon)
                flipped = sum(1 << (31 - (12 - r)) for r in range(4, 9) if sem[c] & 1 << (31 - r))
                self.assertEqual(flipped, words[c] & icon)
            else:
                self.assertEqual((sem[c], bp[c]), (words[c], 0))
        self.computed_plan('sem-type-planes', data, result)
        recipe = EXPORT.export(self.plan, self.root)
        self.assertNotIn('base64', recipe['sources']['table'])
        self.assertEqual(recipe['sources']['table']['input'], dict(source='dn2.7', offset=0, bytes=76))

    def test_refuses_computed_values_that_differ(self):
        data = bytes(range(76))
        self.computed_plan('sem-type-planes', data, bytes(152))
        with self.assertRaisesRegex(ValueError, 'Computed source differs'):
            EXPORT.export(self.plan, self.root)

    def test_log_cutoff_formula_is_pinned(self):
        table = struct.pack('<1024f', *(2 ** (i / 128 - 3) for i in range(1024)))
        self.assertEqual(EXPORT.sha(EXPORT.computed_data('sem-graph-log-cutoff', table)),
                         '004870c97070d426388b184713cf6562c469e5544533898ac86d62584fde73f0')

    def test_refuses_computed_input_from_non_firmware_source(self):
        data = bytes(range(76))
        self.computed_plan('sem-type-planes', data, EXPORT.computed_data('sem-type-planes', data))
        table = self.plan['sources'].pop('table')
        self.plan['sources']['adapter'] = dict(kind='adapter', path=str(self.root/'firmware'), bytes=76,
                                               sha256=EXPORT.sha(data), provenance=[self.proof],
                                               toolchain_sha256='1' * 64, donor_holes=[])
        self.plan['sources']['table'] = table
        table['input']['source'] = 'adapter'
        with self.assertRaisesRegex(ValueError, 'official OS section'):
            EXPORT.export(self.plan, self.root)
        self.plan['sources']['table']['input']['source'] = 'missing'
        with self.assertRaisesRegex(ValueError, 'official OS section'):
            EXPORT.export(self.plan, self.root)

    def test_refuses_computed_input_outside_source(self):
        data = bytes(range(76))
        self.computed_plan('sem-type-planes', data, EXPORT.computed_data('sem-type-planes', data))
        self.plan['sources']['table']['input']['offset'] = 4
        with self.assertRaisesRegex(ValueError, 'outside source'):
            EXPORT.export(self.plan, self.root)

    def test_copy_boundary_checked(self):
        self.plan['images']['main']['operations'][0]['offset'] = 7
        with self.assertRaisesRegex(ValueError, 'outside source'):
            EXPORT.export(self.plan, self.root)


if __name__ == '__main__':
    unittest.main()
