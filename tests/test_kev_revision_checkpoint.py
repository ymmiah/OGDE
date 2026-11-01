import copy
import unittest
from ogde.core import SecurityError
from ogde.kev_revision_checkpoint import create_kev_revision_checkpoint, verify_kev_revision_checkpoint


class RevisionCheckpointTests(unittest.TestCase):
    def setUp(self):
        self.state = {"kind": "ogde-kev-revision-state", "schema_version": 1,
                      "signers": {"operator-lab": {"revision": 2, "key_id": "a" * 64,
                                                  "snapshot_sha256": "b" * 64}}}

    def test_valid_checkpoint(self):
        checkpoint = create_kev_revision_checkpoint(self.state)
        self.assertTrue(verify_kev_revision_checkpoint(self.state, checkpoint))
        self.assertNotIn("operator-lab", str(checkpoint))

    def test_rollback_detected(self):
        checkpoint = create_kev_revision_checkpoint(self.state)
        rolled = copy.deepcopy(self.state)
        rolled["signers"]["operator-lab"]["revision"] = 1
        with self.assertRaises(SecurityError):
            verify_kev_revision_checkpoint(rolled, checkpoint)

    def test_rewritten_key_detected(self):
        checkpoint = create_kev_revision_checkpoint(self.state)
        altered = copy.deepcopy(self.state)
        altered["signers"]["operator-lab"]["key_id"] = "c" * 64
        with self.assertRaises(SecurityError):
            verify_kev_revision_checkpoint(altered, checkpoint)

    def test_removed_signer_detected(self):
        checkpoint = create_kev_revision_checkpoint(self.state)
        altered = copy.deepcopy(self.state)
        altered["signers"] = {}
        with self.assertRaises(SecurityError):
            verify_kev_revision_checkpoint(altered, checkpoint)

    def test_modified_checkpoint_rejected(self):
        checkpoint = create_kev_revision_checkpoint(self.state)
        checkpoint["signer_count"] = 0
        with self.assertRaises(SecurityError):
            verify_kev_revision_checkpoint(self.state, checkpoint)

    def test_bad_state_rejected(self):
        with self.assertRaises(SecurityError):
            create_kev_revision_checkpoint({"schema_version": 1})

    def test_invalid_schema_rejected(self):
        checkpoint = create_kev_revision_checkpoint(self.state)
        checkpoint["schema_version"] = True
        with self.assertRaises(SecurityError):
            verify_kev_revision_checkpoint(self.state, checkpoint)


if __name__ == "__main__":
    unittest.main()
