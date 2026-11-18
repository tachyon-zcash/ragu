"""Run the workspace suite and split the PCD unit tests across CI runners."""

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PCD = ROOT / "crates" / "ragu_pcd"
BINARY_NAME = "ragu_pcd.exe" if sys.platform == "win32" else "ragu_pcd"
PROOF_TEST_MODULES = (
    "online_batch_tests::",
    "proof::fuse_fixture_tests::",
    "proof::profile_substitution_tests::",
)


def workspace(artifact, features, suite="full"):
    artifact.mkdir(parents=True, exist_ok=True)
    runner = [sys.executable, str(Path(__file__).resolve()), "capture", str(artifact), suite]
    feature_flags = {"default": [], "all": ["--all-features"]}[features]
    profiles = ["--config", ".github/actions/rust-setup/ci-release.toml"]
    if sys.platform == "darwin":
        profiles += ["--config", ".github/actions/rust-setup/ci-release-macos.toml"]
    if suite != "full":
        if suite not in ("regular", "proofs"):
            raise SystemExit(f"Unknown PCD test suite: {suite}")
        profiles += ["--config", f".github/actions/rust-setup/ci-release-pcd-{suite}.toml"]
    if suite == "proofs":
        # Keep the PCD library's workspace feature resolution. The regular
        # build executes the workspace's other targets, including doctests.
        feature_flags += ["--lib"]
    subprocess.run(
        [
            "cargo", "test", "--release", "--workspace", "--locked", *feature_flags,
            *profiles,
            "--config", f'target."cfg(all())".runner={json.dumps(runner)}',
        ],
        cwd=ROOT,
        check=True,
    )
    if not (artifact / BINARY_NAME).is_file():
        raise SystemExit("Cargo did not produce a ragu_pcd unit-test executable")


def capture(artifact, suite, executable, *args):
    # Cargo runs this wrapper for every test target. Route the PCD unit binary
    # to the shards and keep Cargo's execution of all other targets.
    if re.fullmatch(r"ragu_pcd-[0-9a-f]{16}(?:\.exe)?", Path(executable).name):
        destination = artifact / BINARY_NAME
        if destination.exists():
            raise SystemExit("Cargo produced more than one ragu_pcd unit-test executable")
        shutil.copy2(executable, destination)
    elif suite != "proofs":
        raise SystemExit(subprocess.call([executable, *args]))


def shard(artifact, index, count, suite="full"):
    executable = artifact / BINARY_NAME
    if sys.platform != "win32":
        executable.chmod(0o755)  # Artifact download resets file permissions.

    inventory = subprocess.check_output(
        [executable, "--list", "--format", "terse"], cwd=PCD, text=True
    )
    names = sorted(
        line.rsplit(": ", 1)[0]
        for line in inventory.splitlines()
        if line.endswith((": test", ": benchmark"))
    )
    if suite != "full":
        if suite not in ("regular", "proofs"):
            raise SystemExit(f"Unknown PCD test suite: {suite}")
        names = [
            name for name in names
            if name.startswith(PROOF_TEST_MODULES) == (suite == "proofs")
        ]
    if not 0 <= index < count <= len(names) or len(set(names)) != len(names):
        raise SystemExit("Invalid shard or libtest inventory")
    selected = names[index::count]
    print(f"Shard {index + 1}/{count} selects {len(selected)} of {len(names)} entries", flush=True)
    subprocess.run(
        [executable, "--exact", *selected],
        cwd=PCD,
        env={**os.environ, "CARGO_MANIFEST_DIR": str(PCD)},
        check=True,
    )


if __name__ == "__main__":
    mode, directory, *arguments = sys.argv[1:]
    artifact = Path(directory).resolve()
    if mode == "workspace":
        workspace(artifact, *arguments)
    elif mode == "capture":
        capture(artifact, *arguments)
    elif mode == "shard":
        index, count, *suite = arguments
        shard(artifact, int(index), int(count), *suite)
    else:
        raise SystemExit(f"Unknown mode: {mode}")
