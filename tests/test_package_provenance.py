"""Negative contracts for the real-graph checker, also run by flake checks."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("provenance", Path(__file__).with_name("package-provenance.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
audit_spec = importlib.util.spec_from_file_location("audit", Path(__file__).with_name("audit-command-derivations.py"))
audit_module = importlib.util.module_from_spec(audit_spec)
audit_spec.loader.exec_module(audit_module)


class ProvenanceTests(unittest.TestCase):
    def test_allowed_transitive_browser_and_core_still_refused(self):
        for name in ("google-chrome", "chromium", "darwin-is-not-a-snowflake-source.drv"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                module.verify_graph({name}, {name})

    def test_renamed_extra_dependency_or_source_refused(self):
        with self.assertRaises(ValueError):
            module.verify_graph({"runtime", "unexpected-source"}, {"runtime"})
        with self.assertRaises(ValueError):
            module.verify_graph(
                {"/nix/store/hash-allowed", "/nix/store/hash-unallowlisted-foreign-source"},
                {"/nix/store/hash-allowed"},
            )

    def test_required_runtime_absence_refused(self):
        with self.assertRaises(ValueError):
            module.verify_graph({"bash"}, {"bash", "python"}, {"python"})

    def test_declared_graph(self):
        module.verify_graph({"bash", "python"}, {"bash", "python"}, {"bash"})

    def test_build_authority_refused(self):
        for authority in (
            "/run/current-system",
            "/Users/operator/input",
            "/home/operator/input",
            "darwin-is-not-a-snowflake",
        ):
            with self.subTest(authority=authority), self.assertRaises(ValueError):
                audit_module.audit({"root": {"env": {"buildCommand": authority}}}, "root")

    def test_transitive_build_source_refused(self):
        for member in ("/nix/store/hash-darwin-is-not-a-snowflake-source",
                       "/nix/store/hash-google-chrome-1.drv",
                       "/nix/store/hash-chromium-1.drv"):
            with self.subTest(member=member), self.assertRaises(ValueError):
                audit_module.audit({"root": {}, "dependency": {"inputSrcs": [member]}}, "root")

    def test_compatibility_patch_is_not_browser(self):
        audit_module.audit({"root": {}, "/nix/store/hash-add-feature-for-chromium.patch.drv": {}}, "root")


if __name__ == "__main__":
    unittest.main()
