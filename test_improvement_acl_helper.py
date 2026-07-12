from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

import improvement_harness_runtime_v2 as runtime


REPO = Path(__file__).resolve().parent
HELPER = REPO / "improvement_acl_helper.ps1"
POWERSHELL = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"


def acl_environment(temp: Path) -> dict[str, str]:
    return runtime._minimal_environment(temp)


def invoke(contract_path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [POWERSHELL, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", HELPER, "-Contract", contract_path],
        cwd=contract_path.parent,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
        env=acl_environment(contract_path.parent),
    )


@pytest.fixture
def windows_acl_capability(tmp_path: Path) -> None:
    if os.name != "nt" or not POWERSHELL.is_file():
        pytest.skip("Windows PowerShell ACL facilities are unavailable")
    probe = tmp_path / "acl-capability-probe"
    probe.mkdir()
    environment = acl_environment(tmp_path)
    environment["ACL_PROBE_PATH"] = str(probe)
    script = (
        "Import-Module Microsoft.PowerShell.Security -ErrorAction Stop; "
        "$null = Get-Command Get-Acl -ErrorAction Stop; "
        "$null = Get-Command Set-Acl -ErrorAction Stop; "
        "$null = Get-Acl -LiteralPath $env:ACL_PROBE_PATH -ErrorAction Stop; "
        "Write-Output 'PASS'"
    )
    completed = subprocess.run(
        [POWERSHELL, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
        cwd=tmp_path,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
        env=environment,
    )
    if completed.returncode != 0 or completed.stdout.strip() != "PASS":
        reason = " ".join((completed.stderr or completed.stdout or "unknown capability failure").split())[:500]
        pytest.skip(f"native Windows ACL capability unavailable: {reason}")


def test_acl_helper_environment_excludes_inherited_powershell_module_path(monkeypatch, tmp_path):
    monkeypatch.setenv("PSModulePath", "C:\\untrusted-pwsh-modules")
    environment = acl_environment(tmp_path)
    assert all(key.upper() != "PSMODULEPATH" for key in environment)


@pytest.mark.windows_acl
@pytest.mark.skipif(os.name != "nt" or not POWERSHELL.is_file(), reason="Windows PowerShell ACL helper test")
def test_acl_helper_snapshot_and_idempotent_exact_restore(tmp_path, windows_acl_capability):
    parent = tmp_path / "parent"; root = parent / "root"; control = parent / "control"
    root.mkdir(parents=True); control.mkdir()
    contract = {
        "schema_version": "blast-pit.acl-lease-contract.v1",
        "operation": "snapshot",
        "lease_id": "pytest-lease",
        "root": str(root),
        "authorized_parent": str(parent),
        "control_dir": str(control),
        "snapshot": None,
        "restricted_sid": None,
    }
    path = control / "snapshot.json"; path.write_text(json.dumps(contract), encoding="utf-8")
    result = invoke(path)
    assert result.returncode == 0, result.stderr
    snapshot = json.loads(result.stdout)
    assert set(snapshot) == {"schema_version", "operation", "lease_id", "pass", "snapshot", "restricted_sid"}
    assert snapshot["pass"] is True and snapshot["snapshot"]["root"] == str(root)

    contract.update({"operation": "restore", "snapshot": snapshot["snapshot"]})
    restore_path = control / "restore.json"; restore_path.write_text(json.dumps(contract), encoding="utf-8")
    restored = invoke(restore_path)
    assert restored.returncode == 0, restored.stderr
    assert json.loads(restored.stdout)["snapshot"]["sddl"] == snapshot["snapshot"]["sddl"]


@pytest.mark.skipif(os.name != "nt" or not POWERSHELL.is_file(), reason="Windows PowerShell ACL helper test")
def test_acl_helper_rejects_contract_outside_declared_control_directory(tmp_path):
    parent = tmp_path / "parent"; root = parent / "root"; control = parent / "control"; other = parent / "other"
    root.mkdir(parents=True); control.mkdir(); other.mkdir()
    contract = {
        "schema_version": "blast-pit.acl-lease-contract.v1",
        "operation": "snapshot",
        "lease_id": "pytest-lease",
        "root": str(root),
        "authorized_parent": str(parent),
        "control_dir": str(other),
        "snapshot": None,
        "restricted_sid": None,
    }
    path = control / "snapshot.json"; path.write_text(json.dumps(contract), encoding="utf-8")
    result = invoke(path)
    assert result.returncode != 0 and "outside the fixed control directory" in result.stderr


def test_acl_helper_source_contains_only_child_delete_upgrade_policy():
    source = HELPER.read_text(encoding="utf-8")
    assert "FileSystemRights]::Delete" in source
    assert "PropagationFlags]::InheritOnly" in source
    assert "ChangePermissions" in source and "TakeOwnership" in source
    assert "sandbox ACL delta must be exactly one added rule" in source
    assert "'snapshot', 'discover', 'upgrade', 'restore', 'verify'" in source
