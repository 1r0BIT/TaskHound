import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from taskhound.utils.cache_manager import get_cache, init_cache
from taskhound.resolver import resolve_sid


class TestSidCaching(unittest.TestCase):

    def setUp(self):
        # Create temp dir for cache
        self.test_dir = tempfile.mkdtemp()
        self.cache_path = Path(self.test_dir) / "test_cache.db"

        # Initialize cache
        init_cache(ttl_hours=1, enabled=True, cache_file=self.cache_path)
        self.cache = get_cache()

    def tearDown(self):
        if self.cache:
            self.cache.close()
        shutil.rmtree(self.test_dir)

    @patch("taskhound.resolver.sid_to_name.resolve_sid_from_bloodhound")
    @patch("taskhound.resolver.sid_to_name.resolve_sid_via_bloodhound_api")
    @patch("taskhound.resolver.sid_to_name.resolve_sid_via_smb")
    @patch("taskhound.resolver.sid_to_name.resolve_sid_via_ldap")
    def test_sid_fail_count_increment(self, mock_ldap, mock_smb, mock_bh_api, mock_bh_offline):
        # Mock all resolution methods to fail (return None)
        mock_bh_offline.return_value = None
        mock_bh_api.return_value = None
        mock_smb.return_value = None
        mock_ldap.return_value = None

        sid = "S-1-5-21-1111111111-2222222222-3333333333-1001"

        # First attempt
        resolve_sid(sid, no_ldap=False, domain="test", username="user", password="pw")
        self.assertEqual(self.cache.get("sid_failures", sid), 1)

        # Second attempt
        resolve_sid(sid, no_ldap=False, domain="test", username="user", password="pw")
        self.assertEqual(self.cache.get("sid_failures", sid), 2)

        # Third attempt
        resolve_sid(sid, no_ldap=False, domain="test", username="user", password="pw")
        self.assertEqual(self.cache.get("sid_failures", sid), 3)

    @patch("taskhound.resolver.sid_to_name.resolve_sid_from_bloodhound")
    def test_sid_skip_after_failures(self, mock_bh_offline):
        sid = "S-1-5-21-1111111111-2222222222-3333333333-1002"

        # Manually set fail count to 3
        self.cache.set("sid_failures", sid, 3)

        # Attempt resolution
        result, _ = resolve_sid(sid)

        # Should return Unresolvable immediately without calling resolvers
        self.assertIn("Unresolvable", result)
        mock_bh_offline.assert_not_called()

    @patch("taskhound.resolver.sid_to_name.resolve_sid_from_bloodhound")
    def test_sid_success_clears_failures(self, mock_bh_offline):
        sid = "S-1-5-21-1111111111-2222222222-3333333333-1003"

        # Manually set fail count to 2
        self.cache.set("sid_failures", sid, 2)

        # Mock success
        mock_bh_offline.return_value = "DOMAIN\\User"

        # Attempt resolution
        resolve_sid(sid, hv_loader=MagicMock())

        # Should have cached the success
        self.assertEqual(self.cache.get("sids", sid), "DOMAIN\\User")
        # Should have cleared failures
        self.assertIsNone(self.cache.get("sid_failures", sid))

if __name__ == "__main__":
    unittest.main()
