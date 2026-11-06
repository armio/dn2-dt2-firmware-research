import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('check_inputs', Path(__file__).resolve().parents[1]/'tools/check_inputs.py')
check_inputs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check_inputs)


class PrivateInputValidation(unittest.TestCase):
    def test_exact_input_and_corruption_are_distinguished(self):
        expected = {'bytes': 3, 'sha256': hashlib.sha256(b'abc').hexdigest()}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'fixture'
            path.write_bytes(b'abc')
            self.assertEqual(check_inputs.verify(path, expected, 'fixture'), path.resolve())
            path.write_bytes(b'abd')
            with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
                check_inputs.verify(path, expected, 'fixture')
            self.assertEqual(path.read_bytes(), b'abd')
            path.write_bytes(b'abcd')
            with self.assertRaisesRegex(ValueError, 'expected 3 bytes'):
                check_inputs.verify(path, expected, 'fixture')

    def test_missing_input_is_not_created(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'missing'
            with self.assertRaises(FileNotFoundError):
                check_inputs.verify(path, {'bytes': 0, 'sha256': ''}, 'fixture')
            self.assertFalse(path.exists())

    def test_public_targets_require_only_the_two_official_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'releases').mkdir()
            expected = {}
            for name, data in (('dn2', b'recipient'), ('dt2', b'donor')):
                (root/name).write_bytes(data)
                expected[name] = dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
            for target in ('R012', 'R013', 'R014', 'R020'):
                (root/'releases'/f'{target.lower()}.json').write_text(json.dumps(dict(inputs=expected)))
                with self.subTest(target=target), patch.object(check_inputs, 'ROOT', root):
                    result = check_inputs.inputs(root/'dn2', root/'dt2', target=target)
                    self.assertEqual(set(result), {'dn2', 'dt2'})
                    with self.assertRaisesRegex(ValueError, 'does not use --sample-bank'):
                        check_inputs.inputs(root/'dn2', root/'dt2', root/'missing-bank', target=target)

    def test_historical_targets_still_require_the_exact_bank(self):
        for target in ('T1E2', 'R003', 'R008', 'R011'):
            with self.subTest(target=target), self.assertRaisesRegex(ValueError, 'requires --sample-bank'):
                check_inputs.inputs('unused-dn2', 'unused-dt2', target=target)


if __name__ == '__main__':
    unittest.main()
