import tempfile
import unittest
from pathlib import Path
from ogde.core import SecurityError
from ogde.kev_state_path_guard import validate_kev_state_path


class StatePathGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'real' / 'nested').mkdir(parents=True)

    def test_valid_missing_target(self):
        self.assertEqual(validate_kev_state_path(self.root / 'real' / 'state.json'),
                         self.root / 'real' / 'state.json')

    def test_valid_existing_regular_target(self):
        target = self.root / 'real' / 'state.json'
        target.write_text('{}')
        self.assertEqual(validate_kev_state_path(target), target)

    def test_target_symlink_rejected(self):
        (self.root / 'link.json').symlink_to(self.root / 'real' / 'state.json')
        with self.assertRaises(SecurityError):
            validate_kev_state_path(self.root / 'link.json')

    def test_immediate_parent_symlink_rejected(self):
        (self.root / 'alias').symlink_to(self.root / 'real', target_is_directory=True)
        with self.assertRaises(SecurityError):
            validate_kev_state_path(self.root / 'alias' / 'state.json')

    def test_ancestor_symlink_rejected(self):
        (self.root / 'alias').symlink_to(self.root / 'real', target_is_directory=True)
        with self.assertRaises(SecurityError):
            validate_kev_state_path(self.root / 'alias' / 'nested' / 'state.json')

    def test_dangling_parent_symlink_rejected(self):
        (self.root / 'broken').symlink_to(self.root / 'missing', target_is_directory=True)
        with self.assertRaises(SecurityError):
            validate_kev_state_path(self.root / 'broken' / 'state.json')

    def test_missing_directory_rejected(self):
        with self.assertRaises(SecurityError):
            validate_kev_state_path(self.root / 'missing' / 'state.json')


    def test_existing_fifo_target_rejected_before_read(self):
        """Never attempt to read a FIFO as revision state (which could block)."""
        import os
        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFO support required")
        target = self.root / 'real' / 'state.json'
        os.mkfifo(target, 0o600)
        from ogde.kev_revision_state import load_kev_revision_state
        with self.assertRaises(SecurityError):
            load_kev_revision_state(target)
        self.assertTrue(target.exists())

    def test_world_readable_state_rejected_without_modification(self):
        """Reject exposed revision state rather than silently repairing it."""
        import os
        target = self.root / 'real' / 'state.json'
        target.write_text('{"not":"trusted"}')
        os.chmod(target, 0o644)
        before = target.read_bytes()
        from ogde.kev_revision_state import load_kev_revision_state
        with self.assertRaises(SecurityError):
            load_kev_revision_state(target)
        self.assertEqual(target.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
