from __future__ import annotations

import base64
import json
import os
import sys
import time
from pathlib import Path

import pytest

import improvement_harness_runtime_v2 as runtime


def valid_patch(path: str = "a.py") -> str:
    return (
        f"diff --git a/{path} b/{path}\n"
        "index 1111111..2222222 100644\n"
        f"--- a/{path}\n"
        f"+++ b/{path}\n"
        "@@ -1 +1 @@\n"
        "-old\n"
        "+new\n"
    )


def test_patch_parser_accepts_exact_existing_allowlist_and_rejects_path_escape():
    patch = valid_patch()
    assert runtime.parse_patch_paths(patch, {"a.py"}, 10_000) == ["a.py"]
    with pytest.raises(runtime.RuntimeFailure):
        runtime.parse_patch_paths(patch.replace("a.py", "../escape.py"), {"a.py"}, 10_000)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda patch: patch + "--- a/forbidden.py\n+++ b/forbidden.py\n@@ -1 +1 @@\n-x\n+y\n",
        lambda patch: patch.replace("diff --git a/a.py b/a.py", 'diff --git "a/a.py" "b/a.py"'),
        lambda patch: patch.replace("\n", "\r\n"),
        lambda patch: patch + patch,
        lambda patch: patch.replace("+++ b/a.py", "+++ b/other.py"),
        lambda patch: patch.replace("index 1111111..2222222 100644\n", "new file mode 100644\n"),
        lambda patch: patch.replace("diff --git", "diff --cc"),
    ],
)
def test_patch_parser_rejects_ambiguous_or_extended_sections(mutation):
    with pytest.raises(runtime.RuntimeFailure):
        runtime.parse_patch_paths(mutation(valid_patch()), {"a.py"}, 100_000)


def test_canary_topology_requires_pairwise_sibling_roots(tmp_path):
    home = tmp_path / "home"
    workspace = home / "runner" / "worktree"
    workspace.mkdir(parents=True)
    assert not runtime.roots_are_disjoint([workspace, home])
    left = tmp_path / "left"
    right = tmp_path / "right"
    left.mkdir()
    right.mkdir()
    assert runtime.roots_are_disjoint([left, right])


def test_safe_remove_tree_preflights_entire_tree_before_deleting(tmp_path):
    root = tmp_path / "authorized"
    target = root / "run" / "role"
    target.mkdir(parents=True)
    safe_file = target / "a-safe.txt"
    safe_file.write_text("preserve on quarantine", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        (target / "z-link").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(runtime.RuntimeFailure, match="quarantined"):
        runtime.safe_remove_tree(target, root)
    assert safe_file.read_text() == "preserve on quarantine" and outside.exists()


def test_safe_remove_tree_removes_only_strict_descendant(tmp_path):
    root = tmp_path / "authorized"
    target = root / "run" / "role"
    target.mkdir(parents=True)
    (target / "evidence.txt").write_text("x", encoding="utf-8")
    runtime.safe_remove_tree(target, root)
    assert root.is_dir() and not target.exists()
    with pytest.raises(runtime.RuntimeFailure):
        runtime.safe_remove_tree(root, root)


def test_toolless_environment_disables_every_exposed_tool_and_copies_auth(tmp_path):
    real = tmp_path / "real-codex"
    (real / "plugins" / "cache" / "openai-curated").mkdir(parents=True)
    (real / "plugins" / "cache" / "openai-curated" / "marker").write_text("offline", encoding="utf-8")
    (real / "auth.json").write_text(json.dumps({"token": "top-secret-token-value"}), encoding="utf-8")
    isolation = tmp_path / "isolations" / "role"
    isolation.parent.mkdir()
    environment, secrets, digest, cwd = runtime.prepare_toolless_role_environment(isolation, real)
    config = (Path(environment["CODEX_HOME"]) / "config.toml").read_text(encoding="utf-8")
    assert "shell_tool = false" in config and "shell_snapshot = false" in config
    assert "web_search = false" in config and "enabled = false" in config
    assert "plugins = false" in config and "apps = false" in config
    assert '[permissions.reviewer.filesystem]' in config and '":minimal" = "read"' in config
    assert digest == "plugins-disabled-by-policy" and cwd.is_dir()
    assert "top-secret-token-value" in secrets
    assert base64.b64encode(b"top-secret-token-value").decode() in secrets
    runtime.safe_remove_tree(isolation, isolation.parent)


def _event_program(events: list[dict[str, object]]) -> str:
    encoded = json.dumps(events)
    return "import json,time; events=json.loads(" + repr(encoded) + "); [print(json.dumps(x),flush=True) for x in events]"


def run_events(tmp_path: Path, events: list[dict[str, object]]) -> runtime.ProcessResult:
    auth = tmp_path / "auth.json"
    auth.write_text("{}", encoding="utf-8")
    return runtime.streamed_toolless_codex(
        [sys.executable, "-c", _event_program(events)],
        "prompt",
        tmp_path,
        10,
        tmp_path / "events.jsonl",
        tmp_path / "stderr.log",
        dict(os.environ),
        [],
        auth,
        tmp_path / "lifecycle.json",
    )


def valid_events() -> list[dict[str, object]]:
    return [
        {"type": "thread.started"},
        {"type": "turn.started"},
        {"type": "item.completed", "item": {"type": "agent_message", "text": "ok"}},
        {"type": "turn.completed"},
    ]


def test_streamed_role_deletes_auth_before_turn_and_retains_lifecycle(tmp_path):
    result = run_events(tmp_path, valid_events())
    lifecycle = json.loads((tmp_path / "lifecycle.json").read_text())
    assert result.return_code == 0
    assert lifecycle["thread_event_line"] == 1 and lifecycle["turn_event_line"] == 2
    assert lifecycle["auth_deleted"] is True and lifecycle["post_run_auth_absent"] is True
    assert not (tmp_path / "auth.json").exists()


@pytest.mark.parametrize(
    "events,match",
    [
        ([{"type": "turn.started"}], "preceded"),
        (valid_events() + [{"type": "future.event"}], "unexpected Codex event"),
        (
            [
                {"type": "thread.started"},
                {"type": "turn.started"},
                {"type": "item.completed", "item": {"type": "dynamic_tool_call"}},
                {"type": "turn.completed"},
            ],
            "unexpected item type",
        ),
        (valid_events() + [{"type": "thread.started"}], "duplicate thread"),
    ],
)
def test_streamed_role_fail_closes_unknown_order_duplicate_and_tool_events(tmp_path, events, match):
    with pytest.raises(runtime.RuntimeFailure, match=match):
        run_events(tmp_path, events)


def test_streamed_role_rejects_malformed_nonempty_jsonl(tmp_path):
    auth = tmp_path / "auth.json"
    auth.write_text("{}")
    code = "print('{bad json',flush=True)"
    with pytest.raises(runtime.RuntimeFailure, match="malformed"):
        runtime.streamed_toolless_codex(
            [sys.executable, "-c", code], "", tmp_path, 10, tmp_path / "events", tmp_path / "stderr", dict(os.environ), [], auth
        )


def test_secret_variants_are_redacted_and_rejected():
    token = "sk-secret-value-123456"
    variants = runtime.secret_variants([token])
    encoded = base64.b64encode(token.encode()).decode()
    assert encoded in variants
    assert encoded not in runtime.redact(f"authorization={encoded}", variants)
    with pytest.raises(runtime.RuntimeFailure, match="authentication"):
        runtime.reject_secret_value({"nested": encoded}, variants)


def test_sandbox_config_is_unelevated_network_denied_and_exact_roots(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    text = runtime.sandbox_config_text("candidate", [first, second])
    assert 'sandbox = "unelevated"' in text and "enabled = false" in text
    assert str(first).replace("\\", "\\\\") in text
    with pytest.raises(runtime.RuntimeFailure, match="unelevated"):
        runtime.sandbox_config_text("candidate", [first], "elevated")
    with pytest.raises(runtime.RuntimeFailure, match="non-nested"):
        runtime.sandbox_config_text("candidate", [first, first / "nested"])


def test_candidate_sandbox_requires_precreated_write_roots(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    isolation = root / "isolation"
    with pytest.raises(runtime.RuntimeFailure, match="pre-created"):
        runtime.prepare_candidate_sandbox(isolation, root, [root / "missing"])


def test_canary_wrapper_rejects_forged_minimal_pass(monkeypatch, tmp_path):
    scratch = tmp_path / "scratch"
    allowed = tmp_path / "allowed"
    forbidden = tmp_path / "forbidden"
    evidence = tmp_path / "evidence"
    for path in (scratch, allowed, forbidden, evidence):
        path.mkdir()
    canary = tmp_path / "canary.py"
    canary.write_text("# trusted fixture", encoding="utf-8")

    def fake(**kwargs):
        return runtime.ProcessResult([], str(tmp_path), 0, '{"schema_version":"blast-pit.sandbox-canary.v1","pass":true}\n', "")

    monkeypatch.setattr(runtime, "run_sandboxed", fake)
    with pytest.raises(runtime.RuntimeFailure, match="did not pass"):
        runtime.qualify_candidate_sandbox(
            codex=tmp_path / "codex.cmd",
            python=Path(sys.executable),
            canary_source=canary,
            profile="candidate",
            cwd=allowed,
            allowed=[allowed, scratch],
            forbidden=[forbidden],
            timeout=10,
            environment={},
            scratch=scratch,
            evidence_dir=evidence,
            token="safe-token",
        )


def test_run_process_enforces_output_bound_and_job_kills_descendants(monkeypatch, tmp_path):
    monkeypatch.setattr(runtime, "MAX_PROCESS_STREAM_BYTES", 256)
    with pytest.raises(runtime.RuntimeFailure, match="output exceeded"):
        runtime.run_process([sys.executable, "-c", "print('x'*10000)"], tmp_path, 10)
    monkeypatch.setattr(runtime, "MAX_PROCESS_STREAM_BYTES", 8_000_000)

    marker = tmp_path / "descendant-survived.txt"
    grandchild = "import pathlib,sys,time; time.sleep(3); pathlib.Path(sys.argv[1]).write_text('bad')"
    child = "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]]); time.sleep(30)"
    with pytest.raises(runtime.RuntimeTimeout):
        runtime.run_process([sys.executable, "-c", child, grandchild, str(marker)], tmp_path, 1)
    time.sleep(3.5)
    assert not marker.exists()
