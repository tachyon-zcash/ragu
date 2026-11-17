#!/usr/bin/env python3
"""Offline ceremony regressions: python3 qa/ceremony/test_continue.py."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest


SCRIPT = Path(__file__).parent / "continue.sh"
MANIFEST_TOOL = Path(__file__).parent / "manifest.py"
FIXTURES = Path(__file__).parent / "fixtures"
VERIFIED = "Success! Bitcoin block 967690 attests existence as of 2026-09-20 UTC"
BEACON = "11" * 32
ARTIFACTS = ("attestation.txt", "beacon.txt", "tags.txt")
AGGREGATOR = "aggregator-optional-decompression-v1"


class ContinueTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ragu-ceremony-test-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.bin = self.directory / "bin"
        self.bin.mkdir()
        shutil.copyfile(SCRIPT, self.directory / "continue.sh")
        (self.directory / "commit.txt").write_text("24" * 20 + "\n")
        manifest_tool = self.directory / "qa/ceremony/manifest.py"
        manifest_tool.parent.mkdir(parents=True)
        shutil.copyfile(MANIFEST_TOOL, manifest_tool)
        (self.directory / "setup.manifest").write_bytes((FIXTURES / "standard.manifest").read_bytes())
        self.manifest_digest = hashlib.sha256(
            (self.directory / "setup.manifest").read_bytes(),
        ).hexdigest()
        (self.directory / "manifest_digest.txt").write_text(self.manifest_digest + "\n")
        (self.directory / "setup.manifest.ots").write_bytes(b"mock timestamp")
        self.original = {name: f"previous {name}\n" for name in ARTIFACTS}
        for name, contents in self.original.items():
            (self.directory / name).write_text(contents)

        # Exercise the real shell script without contacting a node, explorers,
        # or calendars. The OTS mock exposes an unverified earlier height via
        # `info`, independently of the result returned by `verify`.
        mock = "#!/usr/bin/env python3\n" + textwrap.dedent("""\
            import json
            import os
            from pathlib import Path
            import sys

            name = Path(sys.argv[0]).name
            with open(os.environ["RAGU_TEST_CALLS"], "a") as log:
                log.write(json.dumps([name, *sys.argv[1:]]) + "\\n")
            if name == "git":
                assert sys.argv[1:] == ["rev-parse", "--show-toplevel"]
                print(os.environ["RAGU_TEST_REPO"])
            elif name == "ots":
                if sys.argv[1] == "stamp":
                    assert sys.argv[2] == "setup.manifest"
                    Path("setup.manifest.ots").write_bytes(b"new mock timestamp")
                elif sys.argv[1] == "upgrade":
                    print("Success! Timestamp complete", file=sys.stderr)
                elif sys.argv[1] == "info":
                    print("verify BitcoinBlockHeaderAttestation(1)")
                elif sys.argv[1] == "verify":
                    print(os.environ["RAGU_TEST_VERIFY_OUTPUT"], file=sys.stderr)
                    sys.exit(int(os.environ.get("RAGU_TEST_VERIFY_STATUS", "0")))
                else:
                    raise AssertionError(sys.argv)
            elif name == "curl":
                url = sys.argv[-1]
                if url.endswith("/api/blocks/tip/height"):
                    print(os.environ.get("RAGU_TEST_TIP", "967790"))
                elif "/api/block-height/" in url:
                    if "blockstream.info" in url:
                        print(os.environ.get("RAGU_TEST_SECOND_BEACON", "11" * 32))
                    else:
                        print("11" * 32)
                else:
                    raise AssertionError(url)
            elif name == "cargo":
                assert sys.argv[1:-4] == [
                    "run", "-q", "-p", "ragu_ceremony", "--bin", "registry_tags", "--",
                ]
                assert sys.argv[-4:] == [
                    "--profile", os.environ.get("RAGU_TEST_PROFILE", "standard"),
                    "11" * 32, os.environ["RAGU_TEST_MANIFEST_DIGEST"],
                ]
                print(os.environ.get("RAGU_TEST_TAG_OUTPUT", "derived tags"))
                sys.exit(int(os.environ.get("RAGU_TEST_CARGO_STATUS", "0")))
            else:
                raise AssertionError(name)
        """)
        for name in ("git", "ots", "curl", "cargo"):
            path = self.bin / name
            path.write_text(mock)
            path.chmod(0o755)

    def run_script(self, *args, **settings):
        environment = dict(os.environ)
        environment.update({
            "PATH": f"{self.bin}{os.pathsep}{environment['PATH']}",
            "RAGU_TEST_REPO": str(self.directory),
            "RAGU_TEST_CALLS": str(self.directory / "calls.jsonl"),
            "RAGU_TEST_VERIFY_OUTPUT": VERIFIED,
            "RAGU_TEST_MANIFEST_DIGEST": self.manifest_digest,
        })
        environment.update(settings)
        return subprocess.run(
            ["bash", str(self.directory / "continue.sh"), str(self.directory), *args],
            capture_output=True, text=True, env=environment, timeout=15,
        )

    def assert_records_unchanged(self):
        for name, contents in self.original.items():
            self.assertEqual((self.directory / name).read_text(), contents)
        self.assertEqual(list(self.directory.glob(".continue.*")), [])

    def replace_manifest(self, document):
        data = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
        (self.directory / "setup.manifest").write_bytes(data)
        self.manifest_digest = hashlib.sha256(data).hexdigest()
        (self.directory / "manifest_digest.txt").write_text(self.manifest_digest + "\n")

    def test_aggregator_uses_its_recorded_profile(self):
        document = json.loads((FIXTURES / f"{AGGREGATOR}.manifest").read_text())
        self.replace_manifest(document)
        result = self.run_script(RAGU_TEST_PROFILE=AGGREGATOR)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_retired_aggregator_stops_before_external_calls(self):
        document = json.loads((FIXTURES / "aggregator.manifest").read_text())
        self.replace_manifest(document)
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsupported QA profile: aggregator", result.stderr)
        self.assert_records_unchanged()
        calls = [json.loads(line) for line in (self.directory / "calls.jsonl").read_text().splitlines()]
        self.assertFalse(any(call[0] in ("ots", "curl", "cargo") for call in calls))

    def test_legacy_standard_record_is_not_rewritten(self):
        document = json.loads((FIXTURES / "standard.manifest").read_text())
        del document["setup"]["profile"]
        del document["setup"]["verified_setups"]
        self.replace_manifest(document)
        original = (self.directory / "setup.manifest").read_bytes()
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.directory / "setup.manifest").read_bytes(), original)

    def test_profile_label_mismatch_stops_before_external_calls(self):
        document = json.loads((FIXTURES / "standard.manifest").read_text())
        document["setup"]["profile"]["name"] = AGGREGATOR
        self.replace_manifest(document)
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match profile", result.stderr)
        self.assert_records_unchanged()
        calls = [json.loads(line) for line in (self.directory / "calls.jsonl").read_text().splitlines()]
        self.assertFalse(any(call[0] in ("ots", "curl", "cargo") for call in calls))

    def test_different_beacon_policy_stops_before_external_calls(self):
        document = json.loads((FIXTURES / "standard.manifest").read_text())
        document["beacon"]["height_rule"] = "different rule"
        self.replace_manifest(document)
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("N+100", result.stderr)
        self.assert_records_unchanged()
        calls = [json.loads(line) for line in (self.directory / "calls.jsonl").read_text().splitlines()]
        self.assertFalse(any(call[0] in ("ots", "curl", "cargo") for call in calls))

    def test_noncanonical_profile_record_stops_before_external_calls(self):
        document = json.loads((FIXTURES / "standard.manifest").read_text())
        data = json.dumps(document, indent=2).encode()
        (self.directory / "setup.manifest").write_bytes(data)
        self.manifest_digest = hashlib.sha256(data).hexdigest()
        (self.directory / "manifest_digest.txt").write_text(self.manifest_digest + "\n")
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("canonical bytes", result.stderr)
        self.assert_records_unchanged()
        calls = [json.loads(line) for line in (self.directory / "calls.jsonl").read_text().splitlines()]
        self.assertFalse(any(call[0] in ("ots", "curl", "cargo") for call in calls))

    def test_changed_manifest_does_not_contact_beacon_or_publish(self):
        (self.directory / "setup.manifest").write_bytes(b"changed setup")
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match", result.stderr)
        self.assert_records_unchanged()
        calls = [json.loads(line) for line in (self.directory / "calls.jsonl").read_text().splitlines()]
        self.assertFalse(any(call[0] in ("ots", "curl", "cargo") for call in calls))

    def test_missing_timestamp_stamps_manifest(self):
        (self.directory / "setup.manifest.ots").unlink()
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = [json.loads(line) for line in (self.directory / "calls.jsonl").read_text().splitlines()]
        self.assertIn(["ots", "stamp", "setup.manifest"], calls)
        self.assertIn(["ots", "verify", "setup.manifest.ots"], calls)
        self.assertEqual((self.directory / "setup.manifest.ots").read_bytes(), b"new mock timestamp")

    def test_unverified_timestamp_does_not_publish(self):
        for output in (
            "File does not match original!",
            "Bitcoin verification failed: Digest does not match merkleroot",
            "Could not connect to local Bitcoin node",
            "Pending confirmation in Bitcoin blockchain",
            VERIFIED,
        ):
            with self.subTest(output=output):
                result = self.run_script(
                    RAGU_TEST_VERIFY_STATUS="1", RAGU_TEST_VERIFY_OUTPUT=output,
                )
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assert_records_unchanged()
        calls = [json.loads(line) for line in (self.directory / "calls.jsonl").read_text().splitlines()]
        self.assertFalse(any(call[0] in ("curl", "cargo") for call in calls))

    def test_missing_or_ambiguous_verified_height_does_not_publish(self):
        for output in (
            "Success! Timestamp complete",
            "verify BitcoinBlockHeaderAttestation(1)",
            VERIFIED + "\n" + VERIFIED.replace("967690", "967689"),
        ):
            with self.subTest(output=output):
                result = self.run_script(RAGU_TEST_VERIFY_OUTPUT=output)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assert_records_unchanged()

    def test_default_uses_verified_height(self):
        result = self.run_script(
            RAGU_TEST_VERIFY_OUTPUT="Ignoring BitcoinBlockHeaderAttestation(1)\n" + VERIFIED,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.directory / "attestation.txt").read_text(),
                         "ATTESTATION_BLOCK=967690\nBEACON_RULE=N+100\nBEACON_HEIGHT=967790\n")
        self.assertEqual((self.directory / "beacon.txt").read_text(), BEACON + "\n")
        self.assertEqual((self.directory / "tags.txt").read_text(), "derived tags\n")
        self.assertEqual(list(self.directory.glob(".continue.*")), [])

    def test_derivation_failure_preserves_records(self):
        result = self.run_script(RAGU_TEST_CARGO_STATUS="101", RAGU_TEST_TAG_OUTPUT="partial tags")
        self.assertEqual(result.returncode, 101, result.stdout + result.stderr)
        self.assert_records_unchanged()

    def test_explorer_disagreement_preserves_records(self):
        result = self.run_script(RAGU_TEST_SECOND_BEACON="22" * 32)
        self.assertNotEqual(result.returncode, 0)
        self.assert_records_unchanged()

    def test_waiting_for_beacon_preserves_records(self):
        result = self.run_script(RAGU_TEST_TIP="967789")
        self.assertNotEqual(result.returncode, 0)
        self.assert_records_unchanged()

    def test_explicit_dry_run_marks_timestamp_unverified(self):
        result = self.run_script(
            "967790", RAGU_TEST_VERIFY_STATUS="1", RAGU_TEST_VERIFY_OUTPUT="Attestation pending",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.directory / "attestation.txt").read_text(),
                         "ATTESTATION_BLOCK=unverified\nBEACON_RULE=given\nBEACON_HEIGHT=967790\n")
        self.assertIn("dry run", result.stdout)


if __name__ == "__main__":
    unittest.main()
