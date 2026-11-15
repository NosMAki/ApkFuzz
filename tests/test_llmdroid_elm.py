#!/usr/bin/env python3
"""Verify ELM credential handling does not accept exposed or redirected keys."""

import os
import sys
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from llmdroid_elm import read_local_key, validate_base_url


class ELMConfigurationTests(unittest.TestCase):
    def test_endpoint_requires_plain_https_url(self):
        self.assertEqual(validate_base_url("https://elm.edina.ac.uk/api/v1"),
                         "https://elm.edina.ac.uk/api/v1/")
        for url in ("http://elm.edina.ac.uk/api/v1", "https://user:pass@elm.edina.ac.uk/",
                    "https://elm.edina.ac.uk/?key=secret", "https://elm.edina.ac.uk/#secret"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_base_url(url)

    def test_key_requires_owner_only_regular_file(self):
        with tempfile.TemporaryDirectory() as directory:
            key_file = Path(directory) / "elm.key"
            key_file.write_text("local-test-key\n", encoding="utf-8")
            os.chmod(key_file, 0o600)
            self.assertEqual(read_local_key(key_file), "local-test-key")
            os.chmod(key_file, 0o644)
            with self.assertRaises(ValueError):
                read_local_key(key_file)
            os.chmod(key_file, 0o600)
            link = Path(directory) / "link.key"
            link.symlink_to(key_file)
            with self.assertRaises(ValueError):
                read_local_key(link)


if __name__ == "__main__":
    unittest.main()
