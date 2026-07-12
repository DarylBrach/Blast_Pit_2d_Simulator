import json
from argparse import Namespace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import improvement_candidate_driver_v2 as driver


def record(driver_hash: str, seed_hash: str) -> dict[str, object]:
    return {
        "schema_version": "blast-pit.codex-improvement-authorization.v2",
        "project": "Blast_Pit_2d_Simulator",
        "status": "approved",
        "authority": "human-owner",
        "automatic_release": False,
        "candidate_network_access": False,
        "candidate_driver_v2_source_sha256": driver_hash,
        "development_seed_sha256": seed_hash,
        "expires_utc": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
    }


def test_v2_parent_authorization_is_source_and_seed_bound(tmp_path):
    seed = tmp_path / "seeds.txt"
    seed.write_text("1\n2\n", encoding="utf-8")
    authorization = tmp_path / "approval.json"
    authorization.write_text(
        json.dumps(
            record(
                driver.v37.canonical_source_sha256(Path(driver.__file__)),
                driver.v37.canonical_text_evidence(seed)["sha256"],
            )
        ),
        encoding="utf-8",
    )
    args = Namespace(parent_authorization=authorization, seed_file=seed)
    loaded, digest = driver.load_parent_authorization(args)
    assert loaded["schema_version"].endswith(".v2")
    assert len(digest) == 64


def test_v1_parent_is_rejected(tmp_path):
    seed = tmp_path / "seeds.txt"
    seed.write_text("1\n", encoding="utf-8")
    authorization = tmp_path / "approval.json"
    value = record("0" * 64, "0" * 64)
    value["schema_version"] = "blast-pit.codex-improvement-authorization.v1"
    authorization.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="scope mismatch"):
        driver.load_parent_authorization(Namespace(parent_authorization=authorization, seed_file=seed))


def test_v2_delegated_approval_names_v2_controller(monkeypatch, tmp_path):
    monkeypatch.setattr(driver.v37, "experiment_fingerprint", lambda *args: "fingerprint")
    monkeypatch.setattr(driver.v37, "file_evidence", lambda path: {"sha256": "a" * 64})
    monkeypatch.setattr(driver.v37, "canonical_text_evidence", lambda path: {"sha256": "b" * 64})
    monkeypatch.setattr(driver.v37, "canonical_source_sha256", lambda path: "c" * 64)
    args = Namespace(
        generations=1,
        max_frames=64,
        rollout_frames=64,
        source_v36=tmp_path / "source.npz",
        seed_file=tmp_path / "seeds.txt",
        experiment_id="candidate",
        max_runtime_seconds=60,
        artifact_root=tmp_path,
    )
    path = driver.create_approval(args, "d" * 64)
    value = json.loads(path.read_text(encoding="utf-8"))
    assert value["delegated_by"] == "CodexImprovementController_v2.py"
    assert value["parent_authorization_sha256"] == "d" * 64
