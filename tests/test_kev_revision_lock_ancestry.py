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

    def test_world_readable_state_does_not_create_lock(self):
        target = self.root / 'real' / 'state.json'
        target.write_text('{}')
        target.chmod(0o644)
        self.attempt(target)
        self.assertFalse((self.root / 'real' / 'state.json.lock').exists())
        self.assertEqual(target.read_text(), '{}')

    def test_private_regular_state_reaches_signature_validation(self):
        target = self.root / 'real' / 'state.json'
        target.write_text('{"schema_version":1,"kind":"ogde-kev-revision-state","signers":{}}')
        target.chmod(0o600)
        self.attempt(target)
        self.assertTrue((self.root / 'real' / 'state.json.lock').exists())

    def test_hardlinked_state_is_rejected_before_lock_creation(self):
        original = self.root / 'private-original-state'
        original.write_bytes(b'private-state-unchanged')
        original.chmod(0o600)
        state = self.root / 'real' / 'state.json'
        os.link(original, state)
        self.attempt(state)
        self.assertEqual(original.read_bytes(), b'private-state-unchanged')
        self.assertEqual(state.read_bytes(), b'private-state-unchanged')
        self.assertFalse((self.root / 'real' / 'state.json.lock').exists())

    def test_hardlinked_lock_is_rejected_without_mutating_other_link(self):
        state = self.root / 'real' / 'state.json'
        state.write_text('{"schema_version":1}')
        state.chmod(0o600)
        outside = self.root / 'private-other-file'
        outside.write_bytes(b'private-original')
        outside.chmod(0o600)
        lock = self.root / 'real' / 'state.json.lock'
        os.link(outside, lock)
        self.attempt(state)
        self.assertEqual(outside.read_bytes(), b'private-original')
        self.assertEqual(lock.read_bytes(), b'private-original')
        self.assertEqual(state.read_text(), '{"schema_version":1}')

    def test_world_readable_lock_rejected_without_state_mutation(self):
        state = self.root / 'real' / 'state.json'
        state.write_bytes(b'operator-state')
        state.chmod(0o600)
        lock = self.root / 'real' / 'state.json.lock'
        lock.write_bytes(b'operator-lock')
        lock.chmod(0o644)
        self.attempt(state)
        self.assertEqual(state.read_bytes(), b'operator-state')
        self.assertEqual(lock.read_bytes(), b'operator-lock')

    def test_lock_symlink_rejected_without_touching_target(self):
        state = self.root / 'real' / 'state.json'
        state.write_bytes(b'operator-state')
        state.chmod(0o600)
        outside = self.root / 'private-lock-target'
        outside.write_bytes(b'private-data')
        lock = self.root / 'real' / 'state.json.lock'
        lock.symlink_to(outside)
        self.attempt(state)
        self.assertEqual(state.read_bytes(), b'operator-state')
        self.assertEqual(outside.read_bytes(), b'private-data')

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
