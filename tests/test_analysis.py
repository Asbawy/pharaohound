#!/usr/bin/env python3
"""
tests/test_analysis.py — Unit tests for Pharaohound analysis and models layers.
"""

import unittest
from pharaohound.models import ObjectStore, ADObject, build_user, build_group
from pharaohound.analyzers import REGISTRY


class TestPharaohoundModels(unittest.TestCase):
    def setUp(self):
        self.store = ObjectStore()

    def test_object_registration(self):
        user = ADObject(
            sid="S-1-5-21-12345-6789",
            name="TESTUSER@CORP.LOCAL",
            object_type="user",
            properties={"domain": "CORP.LOCAL"}
        )
        self.store.register(user)
        self.assertEqual(len(self.store.users), 1)
        self.assertEqual(self.store.resolve_sid("S-1-5-21-12345-6789").name, "TESTUSER@CORP.LOCAL")
        self.assertEqual(self.store.name_of("S-1-5-21-12345-6789"), "TESTUSER@CORP.LOCAL")

    def test_transitive_memberships(self):
        # Create nested groups: User -> Group B -> Group A
        user = ADObject(
            sid="S-1-5-21-U",
            name="USER",
            object_type="user",
            raw={"PrimaryGroupSID": "S-1-5-21-GB"}
        )
        group_b = ADObject(
            sid="S-1-5-21-GB",
            name="GROUP_B",
            object_type="group",
            raw={"Members": [{"ObjectIdentifier": "S-1-5-21-U", "ObjectType": "user"}]}
        )
        group_a = ADObject(
            sid="S-1-5-21-GA",
            name="GROUP_A",
            object_type="group",
            raw={"Members": [{"ObjectIdentifier": "S-1-5-21-GB", "ObjectType": "group"}]}
        )
        self.store.register(user)
        self.store.register(group_b)
        self.store.register(group_a)

        # Transitive groups for User should contain GB and GA
        groups = self.store.transitive_groups_for("S-1-5-21-U")
        self.assertIn("S-1-5-21-GB", groups)
        self.assertIn("S-1-5-21-GA", groups)


class TestAnalyzerRegistry(unittest.TestCase):
    def test_registry_discovery(self):
        analyzers = REGISTRY.all_analyzers()
        self.assertTrue(len(analyzers) > 0)
        # Ensure at least one standard analyzer class is present
        names = [cls.__name__ for cls in analyzers]
        self.assertIn("LAPSReadersAnalyzer", names)
        self.assertIn("ADCSAnalyzer", names)


if __name__ == "__main__":
    unittest.main()
