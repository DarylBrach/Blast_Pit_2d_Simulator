import json
from pathlib import Path

import pytest

import improvement_sandbox_canary as canary


def roots(tmp_path):
    allowed = tmp_path / "allowed"; forbidden = tmp_path / "forbidden"
    allowed.mkdir(); forbidden.mkdir()
    return allowed, forbidden


def protected_file(forbidden):
    path = forbidden / "protected.py"
    path.write_text("protected", encoding="utf-8")
    return path


def deny_boundaries(monkeypatch):
    monkeypatch.setattr(canary, "probe_boundary_operation", lambda *args: denied(args[-1]))
    monkeypatch.setattr(canary, "probe_network", lambda host, port: {
        "host": host, "port": port, "succeeded": False, "permission_denied": True,
        "breach": False, "error": "PermissionError: denied",
    })


def denied(operation):
    return {"operation": operation, "succeeded": False, "permission_denied": True,
            "breach": False, "cleanup_ok": True, "error": "PermissionError: denied"}


def test_all_operations_pass_and_leave_no_allowed_residue(monkeypatch, tmp_path):
    allowed, forbidden = roots(tmp_path)
    protected = protected_file(forbidden); deny_boundaries(monkeypatch)
    real = canary.probe_operation
    monkeypatch.setattr(canary, "probe_operation", lambda path, token, operation: denied(operation) if path == forbidden else real(path, token, operation))
    result = canary.run_canary([str(allowed)], [str(forbidden)], str(protected), "192.0.2.10", 9, "random-token-123")
    assert result["pass"] is True
    assert [row["operation"] for row in result["allowed"][0]["operations"]] == list(canary.operation_targets(allowed, "random-token-123"))
    assert not list(allowed.iterdir()) and list(forbidden.iterdir()) == [protected]


def test_each_forbidden_operation_success_is_breach_and_exact_cleanup(monkeypatch, tmp_path):
    allowed, forbidden = roots(tmp_path)
    protected = protected_file(forbidden); deny_boundaries(monkeypatch)
    real = canary.probe_operation
    monkeypatch.setattr(canary, "probe_operation", lambda path, token, operation: denied(operation) if path == allowed else real(path, token, operation))
    result = canary.run_canary([str(allowed)], [str(forbidden)], str(protected), "192.0.2.10", 9, "breach")
    assert result["pass"] is False
    rows = result["forbidden"][0]["operations"]
    assert all(row["breach"] and row["cleanup_ok"] for row in rows)
    assert list(forbidden.iterdir()) == [protected]


def test_non_permission_failure_does_not_count_as_denial(monkeypatch, tmp_path):
    allowed, forbidden = roots(tmp_path)
    protected = protected_file(forbidden); deny_boundaries(monkeypatch)
    real = canary.probe_operation
    def fake(path, token, operation):
        if path == forbidden:
            return {**denied(operation), "permission_denied": False, "error": "FileNotFoundError"}
        return real(path, token, operation)
    monkeypatch.setattr(canary, "probe_operation", fake)
    assert canary.run_canary([str(allowed)], [str(forbidden)], str(protected), "192.0.2.10", 9, "not-denied")["pass"] is False


def test_preexisting_any_canary_target_is_validation_failure(tmp_path):
    allowed, forbidden = roots(tmp_path); token = "collision"
    protected = protected_file(forbidden)
    target = canary.operation_targets(forbidden, token)["file_create_fsync_unlink"][0]
    target.write_text("preexisting")
    with pytest.raises(canary.CanaryError, match="pre-existing"):
        canary.run_canary([str(allowed)], [str(forbidden)], str(protected), "192.0.2.10", 9, token)
    assert target.read_text() == "preexisting"


@pytest.mark.parametrize("token", ["", "../escape", "has space", "x" * 65])
def test_malformed_token_rejected(tmp_path, token):
    allowed, forbidden = roots(tmp_path)
    with pytest.raises(canary.CanaryError):
        canary.validate_inputs([str(allowed)], [str(forbidden)], token)


def test_duplicate_and_nested_roots_rejected(tmp_path):
    parent = tmp_path / "parent"; child = parent / "child"; other = tmp_path / "other"
    child.mkdir(parents=True); other.mkdir()
    with pytest.raises(canary.CanaryError, match="duplicate|nested"):
        canary.validate_inputs([str(parent)], [str(parent)], "dup")
    with pytest.raises(canary.CanaryError, match="nested"):
        canary.validate_inputs([str(parent)], [str(child)], "nested")
    with pytest.raises(canary.CanaryError, match="nested"):
        canary.validate_inputs([str(other), str(parent)], [str(child)], "nested2")


def test_missing_file_root_and_count_rejected(tmp_path):
    file_path = tmp_path / "file"; file_path.write_text("x")
    with pytest.raises(canary.CanaryError): canary.validate_directory(str(tmp_path / "missing"))
    with pytest.raises(canary.CanaryError): canary.validate_directory(str(file_path))
    paths = []
    for index in range(canary.MAX_PATHS + 1):
        path = tmp_path / f"p{index}"; path.mkdir(); paths.append(str(path))
    with pytest.raises(canary.CanaryError, match="exceeds"):
        canary.validate_inputs(paths[:-1], [paths[-1]], "bounded")


def test_symlink_leaf_and_ancestor_rejected_when_supported(tmp_path):
    target = tmp_path / "target"; target.mkdir(); child = target / "child"; child.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlinks unavailable")
    with pytest.raises(canary.CanaryError, match="symlink|reparse"):
        canary.validate_directory(str(link))
    with pytest.raises(canary.CanaryError, match="symlink|reparse"):
        canary.validate_directory(str(link / "child"))


def test_cli_emits_one_json_object(monkeypatch, capsys, tmp_path):
    allowed, forbidden = roots(tmp_path); real = canary.probe_operation
    protected = protected_file(forbidden); deny_boundaries(monkeypatch)
    monkeypatch.setattr(canary, "probe_operation", lambda path, token, operation: denied(operation) if path == forbidden else real(path, token, operation))
    assert canary.main(["--allowed", str(allowed), "--forbidden", str(forbidden), "--protected-file", str(protected), "--network-host", "192.0.2.10", "--network-port", "9", "--token", "cli-token"]) == 0
    captured = capsys.readouterr(); assert captured.err == "" and captured.out.count("\n") == 1
    assert json.loads(captured.out)["pass"] is True


def test_boundary_authority_or_non_permission_failure_blocks_pass(monkeypatch, tmp_path):
    allowed, forbidden = roots(tmp_path); protected = protected_file(forbidden)
    real = canary.probe_operation
    monkeypatch.setattr(canary, "probe_operation", lambda path, token, operation: denied(operation) if path == forbidden else real(path, token, operation))
    monkeypatch.setattr(canary, "probe_boundary_operation", lambda *args: {
        **denied(args[-1]), "succeeded": args[-1] == "root_delete_handle",
        "breach": args[-1] == "root_delete_handle", "permission_denied": args[-1] != "root_delete_handle",
    })
    monkeypatch.setattr(canary, "probe_network", lambda host, port: {
        "host": host, "port": port, "succeeded": False, "permission_denied": True, "breach": False, "error": "denied",
    })
    result = canary.run_canary([str(allowed)], [str(forbidden)], str(protected), "192.0.2.10", 9, "boundary")
    assert result["pass"] is False
    assert next(row for row in result["boundary_guards"] if row["operation"] == "root_delete_handle")["breach"] is True


def test_network_success_is_recorded_without_claiming_os_isolation(monkeypatch, tmp_path):
    allowed, forbidden = roots(tmp_path); protected = protected_file(forbidden); deny_boundaries(monkeypatch)
    real = canary.probe_operation
    monkeypatch.setattr(canary, "probe_operation", lambda path, token, operation: denied(operation) if path == forbidden else real(path, token, operation))
    monkeypatch.setattr(canary, "probe_network", lambda host, port: {
        "host": host, "port": port, "succeeded": True, "permission_denied": False, "breach": True, "error": None,
    })
    result = canary.run_canary([str(allowed)], [str(forbidden)], str(protected), "192.0.2.10", 9, "network")
    assert result["pass"] is True and result["network_observation"]["breach"] is True
