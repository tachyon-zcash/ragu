#!/usr/bin/env python3
"""Canonicalize a setup description; inspect the optional Bitcoin QA record."""

import argparse
import json
from pathlib import Path
import re
import sys


FORMAT = "ragu-setup-manifest-v1"
HEIGHT_RULE = "earliest verified OpenTimestamps Bitcoin attestation height + 100"
PROFILES = ("standard", "aggregator-optional-decompression-v1")


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key: {key}")
        result[key] = value
    return result


def reject_number(value):
    raise ValueError(f"non-integer number: {value}")


def load(path):
    return json.loads(Path(path).read_text(), object_pairs_hook=unique_keys,
                      parse_float=reject_number, parse_constant=reject_number)


def required(document, path):
    value = document
    for key in path.split("."):
        if not isinstance(value, dict) or key not in value:
            raise ValueError(f"missing {path}")
        value = value[key]
    if value is None or value == "":
        raise ValueError(f"empty {path}")
    return value


def hex_digest(value, path):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError(f"{path} must be a lowercase SHA-256 digest")


def profile_name(document, allow_legacy=False):
    if required(document, "format") != FORMAT:
        raise ValueError("unsupported manifest format")
    setup = required(document, "setup")
    if not isinstance(setup, dict):
        raise ValueError("setup must be an object")
    profile = setup.get("profile")
    if profile is None and allow_legacy:
        # Pre-profile v1 records were Standard-only. They are inspected as
        # recorded, never rewritten or assigned a new digest here.
        name = "standard"
    else:
        name = required(document, "setup.profile.name")
        required(document, "setup.profile.definition")
    if not isinstance(name, str) or not name:
        raise ValueError("profile name must be a nonempty string")
    if name not in PROFILES:
        raise ValueError(f"unsupported QA profile: {name}")
    suffix = "" if name == "standard" else f" ({name})"
    for side in ("native", "nested"):
        path = f"beacon.{side}_registry_label"
        if required(document, path) != f"ragu_pcd {side} registry{suffix}":
            raise ValueError(f"{path} does not match profile {name}")
    return name


def validate_description(document):
    profile_name(document)
    for artifact in ("source", "dependencies", "public_parameters"):
        path = f"artifacts.{artifact}.sha256"
        hex_digest(required(document, path), path)
    commit = required(document, "provenance.git_commit")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("provenance.git_commit must be a full Git commit ID")
    for path in (
        "artifacts.source.encoding", "artifacts.dependencies.lockfile",
        "artifacts.dependencies.content_binding", "artifacts.public_parameters.generation",
        "build.toolchain", "build.target", "build.configuration",
        "setup.application_builder", "setup.configuration", "setup.native_registry",
        "setup.nested_registry", "setup.fields_and_domains", "setup.ranks_and_capacities",
        "setup.transcript_rules_and_dst", "beacon.source", "beacon.height_rule",
        "beacon.tag_derivation",
    ):
        required(document, path)
    for path in ("build.features", "setup.application_steps", "setup.verified_setups"):
        if not isinstance(required(document, path), list):
            raise ValueError(f"{path} must be a list")
    for setup in document["setup"]["verified_setups"]:
        required(setup, "profile")
        hex_digest(required(setup, "manifest_sha256"), "verified_setups.manifest_sha256")
        hex_digest(required(setup, "record_sha256"), "verified_setups.record_sha256")
    reject_placeholders(document)


def reject_placeholders(value):
    if isinstance(value, dict):
        for key, item in value.items():
            reject_placeholders(key)
            reject_placeholders(item)
    elif isinstance(value, list):
        for item in value:
            reject_placeholders(item)
    elif isinstance(value, str) and value.startswith("<") and value.endswith(">"):
        raise ValueError(f"replace setup placeholder: {value}")


def canonical_bytes(document):
    validate_description(document)
    return (json.dumps(document, sort_keys=True, ensure_ascii=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode("ascii")


def continuation_profile(document):
    if not isinstance(document, dict):
        raise ValueError("manifest must be an object")
    if isinstance(document.get("setup"), dict) and "profile" in document["setup"]:
        validate_description(document)
    name = profile_name(document, allow_legacy=True)
    if required(document, "beacon.source") != "bitcoin-mainnet":
        raise ValueError("continue.sh only implements the Bitcoin QA example")
    if required(document, "beacon.height_rule") != HEIGHT_RULE:
        raise ValueError("continue.sh requires the recorded N+100 beacon rule")
    return name


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("description", type=Path)
    parser.add_argument("--continue-profile", action="store_true",
                        help="inspect a frozen Bitcoin QA record, including legacy Standard v1")
    args = parser.parse_args()
    try:
        document = load(args.description)
        if args.continue_profile:
            name = continuation_profile(document)
            if "profile" in document["setup"] and args.description.read_bytes() != canonical_bytes(document):
                raise ValueError("profile-aware setup.manifest must use the v1 canonical bytes")
            print(name)
        else:
            sys.stdout.buffer.write(canonical_bytes(document))
    except (ValueError, OSError, TypeError) as error:
        parser.exit(1, f"invalid setup description: {error}\n")


if __name__ == "__main__":
    main()
