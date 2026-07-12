from __future__ import annotations

import json
from pathlib import Path

import pytest

import improvement_candidate_export as exporter
import improvement_harness_runtime_v2 as runtime


REPO = Path(__file__).resolve().parent


def test_candidate_output_bundle_round_trips_with_hashes(tmp_path):
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    (source / "experiment").mkdir(parents=True)
    destination.mkdir()
    (source / "approval.json").write_text('{"approved":true}\n', encoding="utf-8")
    (source / "experiment" / "checkpoint.npz").write_bytes(b"bounded-checkpoint")
    bundle = exporter.build_bundle(source)
    stdout = "training log\n" + exporter.PREFIX + json.dumps(bundle, sort_keys=True, separators=(",", ":")) + "\n"
    manifest = runtime.materialize_candidate_output_bundle(stdout, destination)
    assert manifest == runtime.strict_manifest(source, max_files=128, max_bytes=4_000_000)


def test_candidate_output_bundle_rejects_traversal_and_hash_drift(tmp_path):
    destination = tmp_path / "destination"
    destination.mkdir()
    bundle = {
        "schema_version": "blast-pit.candidate-output-bundle.v1",
        "file_count": 1,
        "total_bytes": 1,
        "files": [{"path": "../escape", "bytes": 1, "sha256": "0" * 64, "base64": "eA=="}],
    }
    stdout = exporter.PREFIX + json.dumps(bundle) + "\n"
    with pytest.raises(runtime.RuntimeFailure, match="path"):
        runtime.materialize_candidate_output_bundle(stdout, destination)
    assert list(destination.iterdir()) == []


def test_candidate_image_recipe_is_digest_and_wheel_hash_locked():
    dockerfile = (REPO / "Dockerfile.candidate").read_text(encoding="utf-8")
    lock = (REPO / "requirements-candidate.lock").read_text(encoding="utf-8")
    dockerignore = (REPO / "Dockerfile.candidate.dockerignore").read_text(encoding="utf-8").splitlines()
    assert "FROM python@sha256:" in dockerfile
    assert "--require-hashes" in dockerfile and "--no-deps" in dockerfile
    package_lines = [line for line in lock.splitlines() if line and not line.startswith("#")]
    assert len(package_lines) == 15
    assert all("==" in line and "--hash=sha256:" in line for line in package_lines)
    assert dockerignore == ["**", "!requirements-candidate.lock"]
