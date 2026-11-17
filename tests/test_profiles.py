from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from core.errors import DaError, ParserError
from core.profiles import (
    AssetBundle,
    AssetDiscovery,
    Profile,
    ProfileStore,
    merge_selector,
)
from tests.test_da_loader import build_da


class ProfileTests(unittest.TestCase):
    def test_from_dict_relative_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile = Profile.from_dict(
                {
                    "name": "demo",
                    "hw_code": "0x0766",
                    "da": "MTK_AllInOne_DA.bin",
                    "exploit": "none",
                    "watchdog": "0x10007000",
                },
                source=root / "demo.json",
            )
        self.assertEqual(profile.hw_code, 0x0766)
        self.assertEqual(profile.da, root / "MTK_AllInOne_DA.bin")
        self.assertEqual(profile.watchdog, 0x10007000)
        self.assertEqual(profile.exploit, "none")

    def test_missing_hw_code(self):
        with self.assertRaises(ParserError):
            Profile.from_dict({"name": "broken"})

    def test_invalid_exploit(self):
        with self.assertRaises(ParserError):
            Profile.from_dict({"hw_code": 0x0766, "exploit": "magic"})

    def test_store_loads_and_reports_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "good.json").write_text(
                json.dumps({"hw_code": "0x0766", "name": "good"}), encoding="utf-8"
            )
            (root / "bad.json").write_text("{not json", encoding="utf-8")
            store = ProfileStore([root])
        self.assertEqual(len(store.profiles), 1)
        self.assertEqual(store.profiles[0].name, "good")
        self.assertEqual(len(store.errors), 1)

    def test_store_skips_disabled_profiles(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "template.json").write_text(
                json.dumps({"hw_code": "0x0766", "enabled": False}),
                encoding="utf-8",
            )
            store = ProfileStore([root])
        self.assertEqual(store.profiles, [])

    def test_best_match_prefers_subcode(self):
        store = ProfileStore([])
        store.add(
            Profile(name="generic", hw_code=0x0766, hw_version=1, da=Path("a.bin"))
        )
        store.add(
            Profile(
                name="specific",
                hw_code=0x0766,
                hw_version=1,
                hw_sub_code=0x8A00,
                da=Path("b.bin"),
            )
        )
        best = store.best(0x0766, hw_version=1, hw_sub_code=0x8A00)
        self.assertEqual(best.name, "specific")


class AssetSelectionTests(unittest.TestCase):
    def _discovery(self) -> AssetDiscovery:
        discovery = AssetDiscovery([])
        discovery.dirs = []
        return discovery

    def test_explicit_da_selects_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "MTK_AllInOne_DA.bin"
            path.write_bytes(build_da())
            bundle = merge_selector(
                0x0766,
                1,
                AssetBundle(da=path),
                ProfileStore([]),
                self._discovery(),
            )
        self.assertIsNotNone(bundle.da_entry)
        self.assertEqual(bundle.da_entry.hw_code, 0x0766)
        self.assertEqual(bundle.da_loader.da1_bytes(bundle.da_entry), b"B" * 0x100)
        self.assertFalse(bundle.missing())

    def test_da_without_matching_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "MTK_AllInOne_DA.bin"
            path.write_bytes(build_da())
            with self.assertRaises(DaError):
                merge_selector(
                    0x9999,
                    1,
                    AssetBundle(da=path),
                    ProfileStore([]),
                    self._discovery(),
                )

    def test_profile_supplies_da(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            da_path = root / "MTK_AllInOne_DA.bin"
            da_path.write_bytes(build_da())
            profile = Profile(name="demo", hw_code=0x0766, da=da_path)
            store = ProfileStore([])
            store.add(profile)
            bundle = merge_selector(
                0x0766,
                1,
                AssetBundle(),
                store,
                self._discovery(),
            )
        self.assertEqual(bundle.profile, profile)
        self.assertEqual(bundle.da, da_path)
        self.assertIsNotNone(bundle.da_entry)

    def test_asset_discovery_respects_depth(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "top_DA.bin").write_bytes(b"x")
            nested = root / "a" / "b" / "c" / "deep_DA.bin"
            nested.parent.mkdir(parents=True)
            nested.write_bytes(b"x")
            hidden = root / ".cache" / "hidden_DA.bin"
            hidden.parent.mkdir()
            hidden.write_bytes(b"x")
            discovery = AssetDiscovery([root])
            discovery.dirs = [root]
            shallow = discovery.files(["*_DA.bin"], max_depth=0)
            deep = discovery.files(["*_DA.bin"], max_depth=4)
        self.assertEqual([p.name for p in shallow], ["top_DA.bin"])
        self.assertIn("deep_DA.bin", [p.name for p in deep])
        self.assertNotIn("hidden_DA.bin", [p.name for p in deep])


if __name__ == "__main__":
    unittest.main()
