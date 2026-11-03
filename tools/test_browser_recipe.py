"""Publication-boundary tests use synthetic bytes; no firmware required."""
import copy
import hashlib
import importlib.util
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

    def test_copy_boundary_checked(self):
        self.plan['images']['main']['operations'][0]['offset'] = 7
        with self.assertRaisesRegex(ValueError, 'outside source'):
            EXPORT.export(self.plan, self.root)


if __name__ == '__main__':
    unittest.main()
