import hashlib
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('public_bank',
    Path(__file__).resolve().parents[1]/'port/public-bank/build.py')
public_bank = importlib.util.module_from_spec(spec)
spec.loader.exec_module(public_bank)


class PublicBankBuild(unittest.TestCase):
    def test_generated_bank_has_fixed_geometry_and_no_recorded_audio(self):
        bank = public_bank.silent_bank()
        self.assertEqual(len(bank), 47104)
        self.assertEqual(struct.unpack_from('<2I', bank), (0x3142534f, 3))
        self.assertEqual(set(bank[44:]), {0})
        for pointer, frames, rate in public_bank.DIRECTORY:
            self.assertEqual(rate, 48000)
            self.assertGreaterEqual(pointer-0x310800, 44)
            self.assertLessEqual(pointer-0x310800+2*frames, len(bank))
        self.assertEqual(hashlib.sha256(bank).hexdigest(), public_bank.load_profile()['bank']['sha256'])

    def test_projection_changes_exact_pins_without_removing_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, target = root/'source', root/'target'
            source.mkdir()
            old, new = 'a'*64, 'b'*64
            (source/'build.py').write_text(f"assert sha(image) == '{old}'\n")
            (source/'private').mkdir()
            (source/'private/secret.bin').write_bytes(b'private input')
            profile = dict(replacements={old:new}, release_outputs={})
            self.assertEqual(public_bank.materialize(source, target, profile), 1)
            self.assertEqual((target/'build.py').read_text(), f"assert sha(image) == '{new}'\n")
            self.assertFalse((target/'private').exists())

    def test_unused_profile_pin_fails_instead_of_silently_skipping(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root/'source'
            source.mkdir()
            (source/'build.py').write_text('assert True\n')
            with self.assertRaisesRegex(ValueError, 'unused substitutions'):
                public_bank.materialize(source, root/'target',
                    dict(replacements={'a'*64:'b'*64}, release_outputs={}))

    def test_projection_rejects_symlink_to_private_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root/'source'
            (source/'port').mkdir(parents=True)
            (source/'build.py').write_text('pass\n')
            private = root/'private.bin'
            private.write_bytes(b'private input')
            (source/'port/leak.py').symlink_to(private)
            with self.assertRaisesRegex(ValueError, 'refuses symlinks'):
                public_bank.materialize(source, root/'target', dict(replacements={}, release_outputs={}))


if __name__ == '__main__':
    unittest.main()
