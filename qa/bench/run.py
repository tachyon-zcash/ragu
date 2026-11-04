#!/usr/bin/env python3
"""Build frozen revisions and measure the wallet/aggregator workflow.

Only the Python standard library is required. Measurements run one executable
at a time; Cargo builds finish before warmups or measured processes start.
"""

import argparse
from collections import Counter, defaultdict
from contextlib import contextmanager
import csv
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import statistics
import subprocess
import sys
import tarfile
import time
import tomllib


SCHEMA = 1
BENCH = Path("crates/ragu_pcd/benches/workflow.rs")
FEATURES = ["std", "test-utils", "baked-aggregator", "unstable-aggregator"]
TIMINGS = {
    "wallet": {"finalize": 1, "seed": 2, "verify_uncompressed": 2,
               "compress": 2, "verify_compressed": 2, "fuse": 1},
    "aggregator": {"canonical_preparation": 1, "finalize": 1, "decompress": 2,
                   "verify_uncompressed": 2, "fuse": 1, "verify_fused_uncompressed": 1,
                   "compress": 1, "verify_compressed": 1},
}
PROOFS = {"wallet_parent", "decompressed_0", "decompressed_1", "aggregator_parent"}
SHAPES = {("wallet", "leaf_0"), ("wallet", "leaf_1"), ("aggregator", "parent")}
OPERATIONS = [
    ("Finalize + bootstrap (one-time wallet startup cost)", "finalize", "wallet"),
    ("Aggregator finalize + bootstrap (once)", "finalize", "aggregator"),
    ("Seed one leaf", "seed", "wallet"),
    ("Decompress one wallet proof", "decompress", "aggregator"),
    ("Verify uncompressed", "verify_uncompressed", None),
    ("Fuse two children", "fuse", None),
    ("Compress", "compress", None),
    ("Verify compressed", "verify_compressed", None),
]


def require(condition, message):
    # Correctness checks must also run under python -O.
    if not condition:
        raise ValueError(message)


def read_json(path):
    return json.loads(path.read_text())


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def tree_digest(root):
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            content = b"L" + os.readlink(path).encode()
        elif path.is_file():
            content = b"F" + bytes.fromhex(sha256(path))
        else:
            continue
        digest.update(path.relative_to(root).as_posix().encode() + b"\0" + content)
    return digest.hexdigest()


def capture(command, **kwargs):
    return subprocess.check_output(command, text=True, stderr=subprocess.STDOUT, **kwargs).strip()


def optional_capture(command):
    try:
        return {"value": capture(command)}
    except (OSError, subprocess.CalledProcessError) as error:
        return {"unavailable": str(error)}


def build_environment():
    env = dict(os.environ)
    for name in list(env):
        if (name in {"RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER",
                     "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_TARGET", "CARGO_TARGET_DIR"}
                or name.startswith(("CARGO_PROFILE_", "CARGO_BUILD_RUSTFLAGS"))
                or (name.startswith("CARGO_TARGET_") and name.endswith("_RUSTFLAGS"))):
            del env[name]
    env.update(CARGO_INCREMENTAL="0", CARGO_TERM_COLOR="never")
    return env


def environment(toolchain):
    system = platform.system()
    require(system in {"Darwin", "Linux"}, "This runner supports macOS and Linux.")
    if system == "Darwin":
        hardware = optional_capture(["sysctl", "machdep.cpu.brand_string", "hw.model",
                                     "hw.physicalcpu", "hw.logicalcpu", "hw.memsize"])
    else:
        cpu = Path("/proc/cpuinfo").read_text()
        model = next((line for line in cpu.splitlines()
                      if line.startswith(("model name", "Hardware"))), platform.machine())
        memory = Path("/proc/meminfo").read_text().splitlines()[0]
        hardware = {"value": model + "\n" + memory}
    return {
        "system": system, "release": platform.release(), "machine": platform.machine(),
        "logical_cpus": os.cpu_count(), "hardware": hardware,
        "rustc": capture(["rustc", "+" + toolchain, "-Vv"], env=build_environment()),
        "cargo": capture(["cargo", "+" + toolchain, "-V"], env=build_environment()),
        "python": platform.python_version(),
    }


def same_host(before, after):
    keys = ["system", "release", "machine", "logical_cpus", "hardware", "rustc", "cargo"]
    return all(before[key] == after[key] for key in keys)


def sleep_marker():
    if platform.system() == "Darwin":
        return optional_capture(["sysctl", "-n", "kern.sleeptime"])
    if hasattr(time, "CLOCK_BOOTTIME"):
        return {"suspended_seconds": time.clock_gettime(time.CLOCK_BOOTTIME) - time.monotonic()}
    return {"unavailable": "No suspend clock available"}


def slept(before, after):
    if "value" in before and "value" in after:
        return before["value"] != after["value"]
    if "suspended_seconds" in before and "suspended_seconds" in after:
        return after["suspended_seconds"] - before["suspended_seconds"] > 1
    return None


def memory_status():
    if platform.system() == "Darwin":
        return {"swap": optional_capture(["sysctl", "-n", "vm.swapusage"]),
                "vm_stat": optional_capture(["vm_stat"])}
    return {name: Path("/proc", name).read_text() for name in ["meminfo", "vmstat"]}


def processes():
    rows = capture(["ps", "-ww", "-axo", "pid=,ppid=,pcpu=,comm="])
    return [{"pid": int(pid), "parent": int(parent), "cpu": float(cpu), "command": command}
            for pid, parent, cpu, command in (line.split(None, 3) for line in rows.splitlines())]


def competing(rows, root_pid=None):
    own = {root_pid}
    while True:
        descendants = {row["pid"] for row in rows if row["parent"] in own}
        if descendants <= own:
            break
        own |= descendants
    names = {"cargo", "rustc", "rustdoc", "clippy-driver", "build-script-build",
             "clang", "clang++", "gcc", "g++", "ld", "ninja"}
    return [row for row in rows
            if row["pid"] not in own and row["cpu"] > 15
            and (Path(row["command"]).name in names
                 or Path(row["command"]).name.startswith("workflow-")
                 or "/release/" in row["command"] or "/debug/" in row["command"])]


def wait_quiet():
    previous, quiet = None, 0
    while quiet < 2:
        try:
            busy = competing(processes())
        except (OSError, subprocess.CalledProcessError) as error:
            print("Process telemetry unavailable; this limitation will be recorded:", error, flush=True)
            return
        quiet = quiet + 1 if not busy else 0
        pids = tuple(row["pid"] for row in busy)
        if pids and pids != previous:
            print("Waiting for active build/test jobs:", pids, flush=True)
        previous = pids
        if quiet < 2:
            time.sleep(5)


def peak_rss(stderr, system):
    pattern = (r"(\d+)\s+maximum resident set size" if system == "Darwin"
               else r"Maximum resident set size \(kbytes\):\s*(\d+)")
    match = re.search(pattern, stderr)
    return int(match.group(1)) * (1 if system == "Darwin" else 1024) if match else None


def check_run_files(out, name, saved, case):
    require(saved["case"] == case, f"Changed case metadata: {name}")
    build = read_json(out / "bin" / (case["id"] + ".json"))
    require(saved["binary_sha256"] == build["sha256"], f"Different executable recorded: {name}")
    for suffix, key in [(".jsonl", "stdout_sha256"), (".stderr", "stderr_sha256"),
                        (".cpu.json", "cpu_sha256")]:
        require(sha256(out / "raw" / (name + suffix)) == saved[key],
                f"Changed raw artifact: {name}{suffix}")


def records(path, case=None):
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    require(rows and rows[-1] == {"kind": "complete", "accepted": True},
            f"Incomplete or rejected workload: {path}")
    require(all(isinstance(row, dict) for row in rows), f"Invalid record: {path}")
    kinds = Counter(row.get("kind") for row in rows)
    require(set(kinds) <= {"timing", "proof", "shape", "rng", "configuration", "complete"},
            f"Unknown record kind: {path}")
    require(kinds["complete"] == kinds["rng"] == 1, f"Duplicate completion or RNG record: {path}")
    actual = Counter((row["profile"], row["step"], row["iteration"])
                     for row in rows if row["kind"] == "timing")
    expected = Counter((profile, step, iteration) for profile, steps in TIMINGS.items()
                       for step, count in steps.items() for iteration in range(count))
    require(actual == expected, f"Missing, extra, or duplicate operation: {path}")
    for row in rows:
        if row["kind"] == "timing":
            seconds = row["seconds"]
            require(type(seconds) in {float, int} and math.isfinite(seconds) and seconds >= 0,
                    f"Invalid timing: {path}")
        if row["kind"] in {"proof", "shape"}:
            require(re.fullmatch(r"[0-9a-f]{128}", row["digest"]) is not None,
                    f"Invalid proof digest: {path}")
    proofs = [row for row in rows if row["kind"] == "proof"]
    shapes = [row for row in rows if row["kind"] == "shape"]
    require(Counter(row["label"] for row in proofs) == Counter(PROOFS),
            f"Missing or duplicate ordinary proof: {path}")
    require(Counter((row["profile"], row["label"]) for row in shapes) == Counter(SHAPES),
            f"Missing or duplicate compressed proof: {path}")
    for row in shapes:
        require(row["rank"] == (13 if row["profile"] == "wallet" else 15),
                f"Unexpected proof rank: {path}")
        require(row["compressed_bytes"] == 32 * (1 + row["points"] + row["scalars"])
                and row["polynomials"] > 0 and row["ordinary_bytes"] > 0,
                f"Inconsistent proof shape: {path}")
    rng = next(row["value"] for row in rows if row["kind"] == "rng")
    require(type(rng) is int and 0 <= rng < 2**64, f"Invalid RNG state: {path}")
    if case is not None:
        configs = [row for row in rows if row["kind"] == "configuration"]
        expected = {"kind": "configuration", "workers": case["workers"],
                    "asm_feature": case["asm"], "seed": 0, "header": 4,
                    "inputs": [42, 7], "backend": "AcceleratedBackend"}
        require(configs == [expected], f"Runtime configuration differs from the requested build: {path}")
    identities = {"rng": rng}
    for row in proofs + shapes:
        key = row["kind"] + ":" + row.get("profile", "") + ":" + row["label"]
        identities[key] = row
    return rows, identities


def order(cases, round_number):
    offset = round_number % len(cases)
    rotated = cases[offset:] + cases[:offset]
    # Visit every starting position before reversing the next rotation cycle.
    return list(reversed(rotated)) if (round_number // len(cases)) % 2 else rotated


def feature_flags(case):
    features = FEATURES + (["asm"] if case["asm"] else []) + (
        ["multicore"] if case["mode"] == "multi" else [])
    return ["--no-default-features", "--features", ",".join(features)]


def initialize(args):
    repo = args.repo.resolve()
    revision = capture(["git", "rev-parse", "--verify", "--end-of-options",
                        args.revision + "^{commit}"], cwd=repo)
    revisions = [("candidate", revision)]
    if args.base:
        baseline = capture(["git", "rev-parse", "--verify", "--end-of-options",
                            args.base + "^{commit}"], cwd=repo)
        revisions.insert(0, ("baseline", baseline))
    channel = args.toolchain or tomllib.loads(
        (repo / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = (args.output or repo / "target" / "workflow-bench" / (timestamp + "-" + revision[:9])).resolve()
    out.mkdir(parents=True, exist_ok=False)
    for name in ["controller", "sources", "snapshots", "bin", "build-logs", "raw", "interrupted"]:
        (out / name).mkdir()
    shutil.copy2(Path(__file__), out / "controller/run.py")
    shutil.copy2(repo / BENCH, out / "controller/workflow.rs")
    sources = {}
    for _, sha in revisions:
        if sha in sources:
            continue
        archive = out / "snapshots" / (sha + ".tar")
        with archive.open("wb") as stream:
            subprocess.run(["git", "archive", "--format=tar", sha], cwd=repo, stdout=stream, check=True)
        source = out / "sources" / sha
        source.mkdir()
        with tarfile.open(archive) as stream:
            stream.extractall(source, filter="data")
        require((source / "Cargo.lock").is_file(), "Each revision must contain a committed Cargo.lock.")
        shutil.copy2(out / "controller/workflow.rs", source / BENCH)
        manifest = source / "crates/ragu_pcd/Cargo.toml"
        content = manifest.read_text()
        existing = [item for item in tomllib.loads(content).get("bench", [])
                    if item["name"] == "workflow"]
        if existing:
            require(existing[0].get("harness") is False
                    and existing[0].get("path", "benches/workflow.rs") == "benches/workflow.rs",
                    "The revision uses the workflow target name for a different benchmark.")
        else:
            manifest.write_text(content + '\n[[bench]]\nname = "workflow"\nharness = false\n')
        sources[sha] = {"archive_sha256": sha256(archive), "source_sha256": tree_digest(source),
                        "lock_sha256": sha256(source / "Cargo.lock")}
    cases = []
    for asm in (["off", "on"] if args.asm == "both" else [args.asm]):
        for mode in args.modes:
            for role, sha in revisions:
                cases.append({"id": f"{role}-asm-{asm}-{mode}", "role": role, "revision": sha,
                              "asm": asm == "on", "mode": mode,
                              "workers": args.threads if mode == "multi" else 1})
    reference = None
    if args.reference:
        _, reference = records(args.reference)
        shutil.copy2(args.reference, out / "supplied-reference.jsonl")
    manifest = {
        "schema": SCHEMA, "created_utc": timestamp, "repository": str(repo),
        "toolchain": channel, "jobs": args.jobs, "offline": args.offline,
        "warmups": args.warmups, "repetitions": args.repetitions,
        "wait_for_quiet": not args.no_wait, "cases": cases, "sources": sources,
        "runner_sha256": sha256(out / "controller/run.py"),
        "harness_sha256": sha256(out / "controller/workflow.rs"),
        "environment": environment(channel), "supplied_reference": reference,
    }
    write_json(out / "manifest.json", manifest)
    print("Frozen campaign:", out, flush=True)
    return out, manifest


def build(out, manifest, case):
    executable = out / "bin" / ("workflow-" + case["id"])
    metadata = out / "bin" / (case["id"] + ".json")
    if metadata.exists():
        saved = read_json(metadata)
        require(saved["case"] == case and executable.is_file()
                and saved["sha256"] == sha256(executable), f"Changed build artifact: {case['id']}")
        return
    source = out / "sources" / case["revision"]
    base = ["cargo", "+" + manifest["toolchain"]]
    locked = ["--locked"] + (["--offline"] if manifest["offline"] else [])
    command = base + ["build", "--release", "-p", "ragu_pcd", "--bench", "workflow",
                      "--target-dir", str(out / "build"), "--jobs", str(manifest["jobs"]),
                      "--message-format=json-render-diagnostics"] + locked + feature_flags(case)
    attempt = len(list((out / "build-logs").glob(case["id"] + "-*.log")))
    log = out / "build-logs" / f"{case['id']}-{attempt}.log"
    print("Building", case["id"], case["revision"][:9], flush=True)
    with log.open("w") as stream:
        result = subprocess.run(command, cwd=source, env=build_environment(),
                                stdout=stream, stderr=subprocess.STDOUT)
    require(result.returncode == 0, f"Build failed; retained log: {log}")
    artifacts = []
    for line in log.read_text().splitlines():
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (message.get("reason") == "compiler-artifact"
                and message["target"]["name"] == "workflow" and message.get("executable")):
            require(Path(message["target"]["src_path"]).resolve() == source / BENCH,
                    "Cargo built a different workload source.")
            artifacts.append(Path(message["executable"]))
    require(len(artifacts) == 1, f"Expected one workflow executable in {log}")
    for package, feature, enabled in [
        ("zakura-udon", "aarch64-asm", case["asm"]),
        ("ragu_core", "multicore", case["mode"] == "multi"),
    ]:
        command_tree = base + ["tree", "-p", "ragu_pcd", "-e", "features", "-i", package]
        tree = capture(command_tree + locked + feature_flags(case), cwd=source, env=build_environment())
        require((f'{package} feature "{feature}"' in tree) == enabled,
                f"Unexpected {feature} feature selection for {case['id']}")
        (out / "bin" / f"{case['id']}-{package}-features.txt").write_text(tree + "\n")
    require(sha256(source / "Cargo.lock") == manifest["sources"][case["revision"]]["lock_sha256"],
            "The build changed the frozen dependency lockfile.")
    shutil.copy2(artifacts[0], executable)
    write_json(metadata, {"case": case, "sha256": sha256(executable), "command": command})


def run_one(out, manifest, case, phase, number):
    name = f"{phase}-{number:03d}-{case['id']}"
    paths = {suffix: out / "raw" / (name + suffix)
             for suffix in [".jsonl", ".stderr", ".cpu.json", ".meta.json"]}
    archived = out / "interrupted" / name
    if paths[".meta.json"].exists():
        saved = read_json(paths[".meta.json"])
        check_run_files(out, name, saved, case)
        if saved.get("interrupted"):
            destination = archived / str(len(list(archived.glob("*"))))
            destination.mkdir(parents=True)
            for path in paths.values():
                if path.exists():
                    path.rename(destination / path.name)
        else:
            require(saved["exit_code"] == 0 and "error" not in saved, f"Failed run retained: {name}")
            records(paths[".jsonl"], case)
            return saved
    require(not any(path.exists() for path in paths.values()),
            f"Partial output without completion metadata is retained for inspection: {name}. "
            "Start a new campaign instead of overwriting it.")
    if manifest["wait_for_quiet"]:
        wait_quiet()
    binary = out / "bin" / ("workflow-" + case["id"])
    identity = read_json(out / "bin" / (case["id"] + ".json"))
    require(sha256(binary) == identity["sha256"], f"Changed executable: {binary}")
    wrapper = (["/usr/bin/time", "-l" if platform.system() == "Darwin" else "-v"]
               if Path("/usr/bin/time").is_file() else [])
    command = wrapper + [str(binary)]
    before, memory_before = sleep_marker(), memory_status()
    started = time.monotonic()
    interrupted, telemetry = False, []
    print("Start", name, flush=True)
    with paths[".jsonl"].open("w") as stdout, paths[".stderr"].open("w") as stderr:
        child = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True,
                                 env=dict(build_environment(), RAYON_NUM_THREADS=str(case["workers"])))
        try:
            while child.poll() is None:
                try:
                    rows = processes()
                    telemetry.append({"elapsed": time.monotonic() - started,
                                      "busy": competing(rows, child.pid),
                                      "processes": [row for row in rows if row["cpu"] >= 5]})
                except (OSError, subprocess.CalledProcessError) as error:
                    telemetry.append({"elapsed": time.monotonic() - started, "unavailable": str(error)})
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
        except KeyboardInterrupt:
            interrupted = True
            os.killpg(child.pid, signal.SIGTERM)
            child.wait()
    after = sleep_marker()
    saved = {
        "case": case, "phase": phase, "round": number, "command": command,
        "binary_sha256": identity["sha256"], "exit_code": child.returncode,
        "elapsed": time.monotonic() - started, "interrupted": interrupted,
        "prior_interruption": archived.exists(), "sleep_before": before, "sleep_after": after,
        "slept": slept(before, after), "competing": any(row.get("busy") for row in telemetry),
        "process_telemetry_unavailable": any("unavailable" in row for row in telemetry),
        "memory_before": memory_before, "memory_after": memory_status(),
        "peak_rss_bytes": peak_rss(paths[".stderr"].read_text(), platform.system()),
    }
    write_json(paths[".cpu.json"], telemetry)
    saved.update(stdout_sha256=sha256(paths[".jsonl"]),
                 stderr_sha256=sha256(paths[".stderr"]), cpu_sha256=sha256(paths[".cpu.json"]))
    if not interrupted:
        try:
            require(child.returncode == 0, f"Workload failed: {name}")
            records(paths[".jsonl"], case)
        except (ValueError, KeyError) as error:
            saved["error"] = str(error)
    write_json(paths[".meta.json"], saved)
    if interrupted:
        raise KeyboardInterrupt
    require("error" not in saved, saved.get("error", ""))
    print("Done", name, f"({saved['elapsed']:.2f} s)", flush=True)
    return saved


def round_interrupted(metadata):
    return any(row["slept"] is True or row.get("prior_interruption") for row in metadata)


@contextmanager
def campaign_lock(out):
    with (out / "campaign.lock").open("w") as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError("Another runner is using this output directory.") from error
        yield


def run(out, manifest, build_only=False):
    require(manifest["schema"] == SCHEMA, "Unsupported campaign schema.")
    ids = set()
    for case in manifest["cases"]:
        require(case["role"] in {"baseline", "candidate"} and case["mode"] in {"single", "multi"}
                and type(case["asm"]) is bool and type(case["workers"]) is int and case["workers"] > 0
                and (case["mode"] != "single" or case["workers"] == 1)
                and re.fullmatch(r"[a-f0-9]{40}", case["revision"]) is not None,
                "Invalid campaign case.")
        expected_id = f"{case['role']}-asm-{'on' if case['asm'] else 'off'}-{case['mode']}"
        require(case["id"] == expected_id and case["id"] not in ids, "Invalid or duplicate case ID.")
        ids.add(case["id"])
    require(sha256(Path(__file__)) == manifest["runner_sha256"],
            "The runner changed. Resume with the saved controller/run.py in the output directory.")
    require(sha256(out / "controller/workflow.rs") == manifest["harness_sha256"],
            "The saved workload source changed.")
    require(same_host(manifest["environment"], environment(manifest["toolchain"])),
            "Host or compiler changed. Use a new campaign to avoid mixing environments.")
    with campaign_lock(out):
        for sha, saved in manifest["sources"].items():
            require(sha256(out / "snapshots" / (sha + ".tar")) == saved["archive_sha256"],
                    "The archived source changed.")
            require(tree_digest(out / "sources" / sha) == saved["source_sha256"],
                    "The frozen source tree changed.")
        for case in manifest["cases"]:
            build(out, manifest, case)
        for sha, saved in manifest["sources"].items():
            require(tree_digest(out / "sources" / sha) == saved["source_sha256"],
                    "The build modified the frozen source tree.")
        if build_only:
            print("Builds preserved. Start measurements with: resume", out, flush=True)
            return
        guard = None
        if platform.system() == "Darwin" and shutil.which("caffeinate"):
            guard = subprocess.Popen(["caffeinate", "-is", "-w", str(os.getpid())])
        try:
            reference_path = out / "reference.json"
            golden = read_json(reference_path) if reference_path.exists() else manifest["supplied_reference"]
            selected, rejected = [], {}
            phases = [("warmup", count) for count in range(manifest["warmups"])]
            number = 0
            while phases or len(selected) < manifest["repetitions"]:
                if phases:
                    phase, iteration = phases.pop(0)
                else:
                    phase, iteration = "measure", number + 1
                    number = iteration
                metadata = []
                for case in order(manifest["cases"], iteration):
                    item = run_one(out, manifest, case, phase, iteration)
                    metadata.append(item)
                    path = out / "raw" / f"{phase}-{iteration:03d}-{case['id']}.jsonl"
                    _, identities = records(path, case)
                    if golden is None:
                        golden = identities
                        write_json(reference_path, golden)
                    require(identities == golden, f"Proof, shape, or RNG mismatch: {path}")
                if phase == "measure":
                    if round_interrupted(metadata):
                        rejected[str(iteration)] = "Recorded system sleep or an interrupted attempt."
                        print("Retaining interrupted round and repeating the full comparison:", iteration, flush=True)
                    else:
                        selected.append(iteration)
            write_json(out / "quality.json", {"selected_rounds": selected,
                                              "interrupted_rounds": rejected,
                                              "retained_rounds": number})
            summarize(out)
        finally:
            if guard is not None:
                guard.terminate()
                guard.wait()


def summarize(out):
    manifest, quality = read_json(out / "manifest.json"), read_json(out / "quality.json")
    golden = manifest["supplied_reference"] or read_json(out / "reference.json")
    selected = quality["selected_rounds"]
    require(len(selected) == manifest["repetitions"], "The measured comparison is incomplete.")
    results, shapes, sample_rows, resources = {}, {}, [], []
    complete, rounds = 0, defaultdict(list)
    for case in manifest["cases"]:
        values, per_process = defaultdict(list), defaultdict(list)
        phases = ([("warmup", n) for n in range(manifest["warmups"])]
                  + [("measure", n) for n in range(1, quality["retained_rounds"] + 1)])
        for phase, number in phases:
            name = f"{phase}-{number:03d}-{case['id']}"
            meta = read_json(out / "raw" / (name + ".meta.json"))
            check_run_files(out, name, meta, case)
            require(meta["phase"] == phase and meta["round"] == number, f"Changed round metadata: {name}")
            rows, identities = records(out / "raw" / (name + ".jsonl"), case)
            require(meta["exit_code"] == 0 and identities == golden, f"Invalid retained run: {name}")
            use = phase == "measure" and number in selected
            require(not use or not round_interrupted([meta]), "An interrupted round was selected.")
            complete += 1
            if phase == "measure":
                rounds[number].append(meta)
            within = defaultdict(list)
            for row in rows:
                if row["kind"] == "timing":
                    sample_rows.append({"case": case["id"], "phase": phase, "round": number,
                                        "selected": use, **{k: row[k] for k in
                                                          ["profile", "step", "iteration", "seconds"]}})
                    if use:
                        key = row["profile"] + "/" + row["step"]
                        values[key].append(row["seconds"])
                        within[key].append(row["seconds"])
                if row["kind"] == "shape":
                    shape = {k: v for k, v in row.items() if k not in {"kind", "digest", "label"}}
                    previous = shapes.setdefault(row["profile"], shape)
                    require(previous == shape, "Proof shapes differ.")
            for key, samples in within.items():
                per_process[key].append(statistics.median(samples))
            resources.append({"run": name, "selected": use, **{k: meta[k] for k in
                              ["peak_rss_bytes", "competing", "slept", "process_telemetry_unavailable"]}})
        results[case["id"]] = {key: {"median": statistics.median(samples), "minimum": min(samples),
                                    "maximum": max(samples), "samples": samples,
                                    "process_medians": per_process[key]} for key, samples in values.items()}
    eligible = [number for number, rows in sorted(rounds.items()) if not round_interrupted(rows)]
    require(selected == eligible[:manifest["repetitions"]],
            "The selected rounds do not match the recorded interruptions.")
    write_json(out / "results.json", results)
    write_json(out / "resources.json", resources)
    with (out / "samples.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(sample_rows[0]))
        writer.writeheader()
        writer.writerows(sample_rows)
    def row(title, cells):
        return "| " + title + " | " + " | ".join(cells) + " |"
    def size(count):
        return f"{count / 1e6:.2f} MB" if count >= 1e6 else f"{count / 1e3:.2f} KB"
    modes = [mode for mode in ["single", "multi"] if any(c["mode"] == mode for c in manifest["cases"])]
    columns = [(profile, mode) for profile in ["wallet", "aggregator"] for mode in modes]
    roles = {c["role"] for c in manifest["cases"]}
    revision = next(c["revision"] for c in manifest["cases"] if c["role"] == "candidate")
    text = ["# Wallet and aggregator workflow", "", f"Candidate revision: {revision}.",
            f"Compiler: {manifest['environment']['rustc'].splitlines()[0]}.",
            f"{manifest['warmups']} warmup process(es) and {manifest['repetitions']} measured processes per configuration. "
            "Per-child rows pool two samples per process; sample ranges and process medians are retained below.", "",
            "Each aggregator verification checks one aggregated proof. ASM selects the AArch64 feature; "
            "other architectures use portable arithmetic under this feature selection.", ""]
    if "baseline" in roles:
        baseline = next(c["revision"] for c in manifest["cases"] if c["role"] == "baseline")
        text += [f"Baseline revision: {baseline}. Timing cells show before → after and the percentage "
                 "change in time. These revisions must share proof and RNG identities.", ""]
    for asm in [False, True]:
        current = [c for c in manifest["cases"] if c["asm"] == asm]
        if not current:
            continue
        text += ["## ASM feature " + ("enabled" if asm else "disabled"), ""]
        lookup = {(c["role"], c["mode"]): c["id"] for c in current}
        title = [f"{p.title()} R{13 if p == 'wallet' else 15} "
                 + ("single" if m == "single" else
                    f"{next(c['workers'] for c in current if c['mode'] == m)} workers") for p, m in columns]
        text += [row("Field / operation", title), "|---|" + "---:|" * len(columns)]
        for label, step, applies in OPERATIONS:
            cells = []
            for profile, mode in columns:
                if applies not in {None, profile}:
                    cells.append("—")
                    continue
                after = results[lookup["candidate", mode]][profile + "/" + step]["median"]
                if "baseline" in roles:
                    before = results[lookup["baseline", mode]][profile + "/" + step]["median"]
                    change = f"{100 * (after / before - 1):+.1f}%" if before else "n/a"
                    cells.append(f"{before:.3f} → {after:.3f} s ({change})")
                else:
                    cells.append(f"{after:.3f} s")
            text.append(row(label, cells))
        for label, value in [
            ("Polynomial coefficient capacity", lambda s: f"{1 << s['rank']:,}"),
            ("Dense coefficient size per polynomial", lambda s: size((1 << s["rank"]) * 32)),
            ("Polynomials per proof", lambda s: str(s["polynomials"])),
            ("IPA rounds per curve", lambda s: str(s["rank"])),
            ("Compressed points", lambda s: str(s["points"])),
            ("Compressed scalars", lambda s: str(s["scalars"])),
            ("Compressed wire size", lambda s: size(s["compressed_bytes"])),
            ("Uncompressed wire size", lambda s: size(s["ordinary_bytes"])),
        ]:
            text.append(row(label, [value(shapes[profile]) for profile, _ in columns]))
        text.append("")
    text += ["## Validation and variability", "",
             f"All {complete} completed processes verified their proofs and matched the reference proof digests, "
             "shapes, and final RNG state. Every raw run is retained. Interrupted attempts, if any, are in interrupted/.",
             f"Measured rounds selected: {selected}. Interrupted rounds retained: {quality['interrupted_rounds']}.",
             f"Selected processes with build/test contention: {sum(r['competing'] for r in resources if r['selected'])}. "
             f"Process telemetry unavailable: {sum(r['process_telemetry_unavailable'] for r in resources if r['selected'])}. "
             f"Sleep detection unavailable: {sum(r['slept'] is None for r in resources if r['selected'])}.",
             "Small differences within sample variability are uncertain. Whole-process peak RSS includes proving "
             "and startup, not just verification. CPU and system memory counters are in the raw metadata.", ""]
    for case in manifest["cases"]:
        text += ["### " + case["id"] + " (" + case["revision"][:9] + ")", "",
                 "| Operation | Median | Minimum | Maximum | Process medians |",
                 "|---|---:|---:|---:|---|"]
        for key, item in results[case["id"]].items():
            text.append(row(key, [f"{item[k]:.6f} s" for k in ["median", "minimum", "maximum"]]
                            + [", ".join(f"{v:.6f} s" for v in item["process_medians"])]))
        rss = [r["peak_rss_bytes"] for r in resources
               if r["selected"] and r["run"].endswith(case["id"]) and r["peak_rss_bytes"] is not None]
        if rss:
            text += ["", f"Whole-process peak RSS: median {size(statistics.median(rss))}; "
                     f"range {size(min(rss))}–{size(max(rss))}."]
        text.append("")
    (out / "report.md").write_text("\n".join(text) + "\n")
    print("Report:", out / "report.md", flush=True)


def positive(value):
    result = int(value)
    if result < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return result


def main():
    require(sys.version_info >= (3, 12), "Python 3.12 or newer is required.")
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    new = sub.add_parser("run", help="freeze, build, and measure committed revisions")
    new.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    new.add_argument("--revision", default="HEAD")
    new.add_argument("--base", help="optional compatible baseline revision")
    new.add_argument("--asm", choices=["on", "off", "both"], default="both")
    new.add_argument("--modes", nargs="+", choices=["single", "multi"], default=["single", "multi"])
    new.add_argument("--threads", type=positive, default=min(12, os.cpu_count() or 1))
    new.add_argument("--warmups", type=positive, default=1)
    new.add_argument("--repetitions", type=positive, default=3)
    new.add_argument("--toolchain", help="one Rust toolchain for every revision")
    new.add_argument("--jobs", type=positive, default=2)
    new.add_argument("--offline", action="store_true")
    new.add_argument("--no-wait", action="store_true", help="skip waiting for competing build/test jobs")
    new.add_argument("--reference", type=Path, help="require identities from a prior raw JSONL run")
    new.add_argument("--output", type=Path, help="new output directory; defaults under target/workflow-bench")
    new.add_argument("--build-only", action="store_true")
    resume = sub.add_parser("resume", help="resume verified artifacts without overwriting failed runs")
    resume.add_argument("output", type=Path)
    report = sub.add_parser("summarize", help="regenerate the report from completed raw samples")
    report.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.action == "run":
        require(len(args.modes) == len(set(args.modes)), "Core modes must be distinct.")
        out, manifest = initialize(args)
        run(out, manifest, args.build_only)
    elif args.action == "resume":
        out = args.output.resolve()
        run(out, read_json(out / "manifest.json"))
    else:
        summarize(args.output.resolve())


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted; completed runs and the interrupted attempt are retained.", file=sys.stderr)
        sys.exit(130)
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as error:
        print(f"Benchmark error: {error}", file=sys.stderr)
        sys.exit(1)
