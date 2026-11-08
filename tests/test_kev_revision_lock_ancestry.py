"""Locked KEV acceptance must reject redirected ancestors before lock creation."""
import os
import tempfile
import unittest
from pathlib import Path
from ogde.core import SecurityError
from ogde.kev_revision_locked import accept_kev_attestation_locked


@unittest.skipUnless(os.name == 'posix' and hasattr(os, 'O_NOFOLLOW'), 'POSIX required')
class LockAncestryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'real' / 'nested').mkdir(parents=True)
        (self.root / 'alias').symlink_to(self.root / 'real', target_is_directory=True)

    def attempt(self, path):
        with self.assertRaises(SecurityError):
            accept_kev_attestation_locked(
                {}, {}, state_path=path, trusted_public_pem=b'not-a-key',
                expected_signer='test', as_of='2026-11-08')

    def test_immediate_symlink_parent_does_not_create_lock(self):
        self.attempt(self.root / 'alias' / 'state.json')
        self.assertFalse((self.root / 'real' / 'state.json.lock').exists())

    def test_nested_symlink_ancestor_does_not_create_lock(self):
        self.attempt(self.root / 'alias' / 'nested' / 'state.json')
        self.assertFalse((self.root / 'real' / 'nested' / 'state.json.lock').exists())

    def test_missing_directory_does_not_create_lock(self):
        self.attempt(self.root / 'missing' / 'state.json')
        self.assertFalse((self.root / 'missing' / 'state.json.lock').exists())

    def test_nested_symlink_does_not_modify_existing_state(self):
        state = self.root / 'real' / 'nested' / 'state.json'
        original = b'operator-owned-state-unchanged'
        state.write_bytes(original)
        self.attempt(self.root / 'alias' / 'nested' / 'state.json')
        self.assertEqual(state.read_bytes(), original)
        self.assertFalse((self.root / 'real' / 'nested' / 'state.json.lock').exists())

    def test_existing_private_lock_not_opened_through_symlink(self):
        lock = self.root / 'real' / 'nested' / 'state.json.lock'
        lock.write_bytes(b'private-lock')
        lock.chmod(0o600)
        self.attempt(self.root / 'alias' / 'nested' / 'state.json')
        self.assertEqual(lock.read_bytes(), b'private-lock')

    def test_directory_target_does_not_create_lock(self):
        target = self.root / 'real' / 'nested'
        self.attempt(target)
        self.assertFalse((self.root / 'real' / 'nested.lock').exists())

    def test_fifo_target_does_not_create_lock(self):
        target = self.root / 'real' / 'pipe'
        os.mkfifo(target)
        self.attempt(target)
        self.assertFalse((self.root / 'real' / 'pipe.lock').exists())

    def test_target_symlink_does_not_create_lock(self):
        target = self.root / 'real' / 'state.json'
        target.symlink_to(self.root / 'real' / 'elsewhere')
        self.attempt(target)
        self.assertFalse((self.root / 'real' / 'state.json.lock').exists())


if __name__ == '__main__':
    unittest.main()
