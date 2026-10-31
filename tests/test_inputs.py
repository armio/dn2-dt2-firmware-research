import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

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


if __name__ == '__main__':
    unittest.main()
