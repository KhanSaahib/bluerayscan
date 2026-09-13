"""JSON Schema consistency tests: keep docs/bluerayscan.schema.json and config.py in lockstep.

The schema gives editors validation and autocomplete with zero runtime dependencies.
These tests make sure the schema cannot drift from the real configuration loader:
every key, enum, pattern, and constraint in one must agree with the other.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import unittest

from bluerayscan import config
from bluerayscan.findings import Confidence, Severity

_SCHEMA_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "docs",
    "bluerayscan.schema.json",
)


def _load_schema() -> dict:
    with open(_SCHEMA_PATH, encoding="utf-8") as handle:
        return json.load(handle)


def _load_config(payload: dict) -> dict:
    with tempfile.TemporaryDirectory() as root:
        path = os.path.join(root, config.DEFAULT_PATH)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)
        return config.load(path)


class TestSchemaStructure(unittest.TestCase):
    """The schema must declare Draft 2020-12 and match config._KEYS exactly."""

    @classmethod
    def setUpClass(cls):
        cls.schema = _load_schema()

    def test_declares_draft_2020_12(self):
        self.assertEqual(
            self.schema.get("$schema"),
            "https://json-schema.org/draft/2020-12/schema",
        )
        self.assertEqual(self.schema.get("type"), "object")

    def test_properties_match_config_keys_exactly(self):
        schema_keys = set(self.schema.get("properties", {})) - {"$schema"}
        config_keys = set(config._KEYS)
        self.assertEqual(schema_keys, config_keys)
        self.assertIn("$schema", self.schema.get("properties", {}))

    def test_root_rejects_additional_properties(self):
        self.assertIs(self.schema.get("additionalProperties"), False)

    def test_paths_allows_arbitrary_globs_with_disable_only(self):
        paths_schema = self.schema["properties"]["paths"]
        self.assertEqual(paths_schema.get("type"), "object")
        per_path = paths_schema.get("additionalProperties", {})
        self.assertEqual(per_path.get("type"), "object")
        self.assertIs(per_path.get("additionalProperties"), False)
        self.assertEqual(set(per_path.get("properties", {})), {"disable"})

    def test_enums_match_supported_cli_values(self):
        props = self.schema["properties"]
        severities = [s.value for s in Severity]
        confidences = [c.value for c in Confidence]

        self.assertEqual(set(props["fail_on"]["enum"]), set(severities + ["none"]))
        self.assertEqual(set(props["min_severity"]["enum"]), set(severities))
        self.assertEqual(set(props["min_confidence"]["enum"]), set(confidences))
        self.assertEqual(set(props["sort"]["enum"]), {"severity", "path"})

    def test_max_file_size_pattern(self):
        pattern = self.schema["properties"]["max_file_size"]["pattern"]
        compiled = re.compile(pattern)

        for valid in ("2M", "500k", "8M", "1024", "1024B", "500KB", "1GB", "2m", "1g"):
            self.assertIsNotNone(compiled.match(valid), f"{valid!r} should match")

        for invalid in ("2kg", "2mk", "2bb", "0", "0M", "-5", "abc", ""):
            self.assertIsNone(compiled.match(invalid), f"{invalid!r} should not match")


class TestExamplesAndLoader(unittest.TestCase):
    """Documented examples must be accepted and typos must be rejected."""

    def test_schema_examples_are_accepted(self):
        schema = _load_schema()
        for example in schema.get("examples", []):
            self.assertIsInstance(_load_config(example), dict)

    def test_readme_examples_are_accepted(self):
        minimal = {
            "fail_on": "high",
            "min_confidence": "medium",
            "exclude": ["vendor", "testdata"],
            "disable": ["K8S004", "DC006"],
        }
        self.assertEqual(_load_config(minimal)["fail_on"], "high")

        paths_example = {
            "paths": {
                "examples/**": {"disable": ["K8S*"]},
                "charts/vendor/**": {"disable": ["*"]},
            }
        }
        self.assertIn("paths", _load_config(paths_example))

    def test_unknown_key_is_rejected(self):
        with self.assertRaises(config.ConfigError):
            _load_config({"unknown_setting": "value"})

    def test_cli_hyphenated_typo_is_rejected(self):
        with self.assertRaises(config.ConfigError):
            _load_config({"fail-on": "high"})


if __name__ == "__main__":
    unittest.main()
