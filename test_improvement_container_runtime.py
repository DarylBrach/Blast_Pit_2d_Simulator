from __future__ import annotations

import json
import os
import hashlib
import re
import secrets
import subprocess
import time
from pathlib import Path

import pytest

import improvement_harness_runtime_v2 as runtime


REPO = Path(__file__).resolve().parent
DOCKER = Path(r"C:\Program Files\Docker\Docker\resources\bin\docker.exe")
IMAGE_ID = "sha256:ebecafb90288df12553cb8b66e0bc2a3ce325513a19f65e40e5ce9e526db0698"
POLICY = REPO / "candidate_container_policy_v1.json"


def docker_environment() -> dict[str, str]:
    allowed = {"APPDATA", "LOCALAPPDATA", "PATH", "PATHEXT", "SYSTEMROOT", "WINDIR"}
    return {key: value for key, value in os.environ.items() if key.upper() in allowed}


def unique_run_id(sequence: int) -> str:
    """Return a valid run ID that cannot collide with a concurrent test process."""
    return f"20260711T{sequence:06d}Z-{secrets.token_hex(4)}"


def governed_containers_for_run(run_id: str) -> list[str]:
    """Query only containers owned by this test run, never global daemon state."""
    result = subprocess.run(
        [
            DOCKER,
            "container",
            "ls",
            "--all",
            "--no-trunc",
            "--filter",
            f"label={runtime.CONTAINER_LABEL}=true",
            "--filter",
            f"label={runtime.CONTAINER_LABEL}.run-id={run_id}",
            "--format",
            "{{.ID}}",
        ],
        cwd=REPO,
        env=docker_environment(),
        text=True,
        encoding="utf-8",
        capture_output=True,
        timeout=60,
        check=True,
    )
    values = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    assert all(re.fullmatch(r"[a-f0-9]{64}", value) for value in values)
    return values


def assert_run_containers_absent(run_id: str, timeout: float = 5.0) -> None:
    """Allow bounded Docker metadata convergence while checking exact ownership."""
    deadline = time.monotonic() + timeout
    while True:
        remaining = governed_containers_for_run(run_id)
        if not remaining:
            return
        if time.monotonic() >= deadline:
            pytest.fail(f"governed candidate containers remain for {run_id}: {remaining}")
        time.sleep(0.1)


@pytest.fixture
def governed_docker_test_lock():
    """Serialize destructive lifecycle tests that share the host Docker daemon."""
    if not DOCKER.is_file():
        yield
        return
    if os.name != "nt":  # pragma: no cover - the governed Docker host is Windows
        pytest.fail("the governed Docker integration lock requires Windows")
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_mutex = kernel32.CreateMutexW
    create_mutex.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
    create_mutex.restype = wintypes.HANDLE
    wait_for_single_object = kernel32.WaitForSingleObject
    wait_for_single_object.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    wait_for_single_object.restype = wintypes.DWORD
    release_mutex = kernel32.ReleaseMutex
    release_mutex.argtypes = [wintypes.HANDLE]
    release_mutex.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    handle = create_mutex(None, False, "Local\\AdlerBaer.BlastPit.GovernedDockerTests.v1")
    if not handle:
        raise OSError(ctypes.get_last_error(), "CreateMutexW failed for governed Docker test lock")
    acquired = False
    try:
        result = wait_for_single_object(handle, 120_000)
        if result not in {0x00000000, 0x00000080}:  # WAIT_OBJECT_0 or WAIT_ABANDONED
            if result == 0x00000102:
                pytest.fail("timed out waiting for the governed Docker test lock")
            raise OSError(ctypes.get_last_error(), f"WaitForSingleObject failed: {result:#x}")
        acquired = True
        yield
    finally:
        if acquired and not release_mutex(handle):
            raise OSError(ctypes.get_last_error(), "ReleaseMutex failed for governed Docker test lock")
        close_handle(handle)


def test_container_policy_is_exact_and_rejects_drift(tmp_path):
    policy = runtime.load_container_policy(POLICY)
    assert policy.value["network_mode"] == "none"
    assert policy.value["read_only_rootfs"] is True
    assert policy.value["cap_drop"] == ["ALL"]
    changed = dict(policy.value)
    changed["network_mode"] = "bridge"
    path = tmp_path / "changed.json"
    path.write_text(json.dumps(changed), encoding="utf-8")
    with pytest.raises(runtime.RuntimeFailure, match="fixed runtime contract"):
        runtime.load_container_policy(path)


def test_container_path_is_fixed_to_disposable_workspace(tmp_path):
    workspace = tmp_path / "workspace"
    worktree = workspace / "worktree"
    worktree.mkdir(parents=True)
    assert runtime.container_path(workspace, worktree / "candidate.py").endswith("/worktree/candidate.py")
    with pytest.raises(runtime.RuntimeFailure, match="outside"):
        runtime.container_path(workspace, tmp_path / "protected.py")


def test_container_mount_tree_rejects_hardlinks(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    first = workspace / "first.txt"
    second = workspace / "second.txt"
    first.write_text("bounded", encoding="utf-8")
    os.link(first, second)
    with pytest.raises(runtime.RuntimeFailure, match="linked file"):
        runtime._validate_container_tree(workspace)


@pytest.mark.skipif(not DOCKER.is_file(), reason="Docker Desktop is required by the governed candidate runtime")
@pytest.mark.docker_host
def test_authorization_bound_docker_host_and_image_are_live(tmp_path, governed_docker_test_lock):
    expected = runtime.docker_host_identity(
        docker=DOCKER,
        cwd=REPO,
        environment=docker_environment(),
        timeout=60,
        image_id=IMAGE_ID,
    )
    assert expected["server_os"] == "linux"
    assert expected["server_security_options"] == ["name=seccomp,profile=builtin", "name=cgroupns"]
    evidence = tmp_path / "preflight.json"
    runtime.verify_candidate_container_host(
        docker=DOCKER,
        cwd=REPO,
        environment=docker_environment(),
        timeout=60,
        image_id=IMAGE_ID,
        expected_identity={key: value for key, value in expected.items() if key != "schema_version"},
        policy_path=POLICY,
        evidence=evidence,
    )
    assert json.loads(evidence.read_text())["pass"] is True
    attestation = json.loads((REPO / "candidate_image_attestation_v1.json").read_text(encoding="utf-8"))
    assert attestation["image_id"] == IMAGE_ID
    for name, expected_hash in attestation["build_inputs"].items():
        assert hashlib.sha256((REPO / name).read_bytes()).hexdigest() == expected_hash
    packages = subprocess.run(
        [
            DOCKER,
            "run",
            "--rm",
            "--pull",
            "never",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--user",
            "65532:65532",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=268435456,mode=1777",
            IMAGE_ID,
            "python",
            "-m",
            "pip",
            "list",
            "--format",
            "json",
        ],
        cwd=REPO,
        text=True,
        encoding="utf-8",
        capture_output=True,
        timeout=120,
        check=True,
    )
    actual_packages = {(item["name"].lower(), item["version"]) for item in json.loads(packages.stdout)}
    expected_packages = {(item["name"].lower(), item["version"]) for item in attestation["python_package_sbom"]}
    assert actual_packages == expected_packages


@pytest.mark.skipif(not DOCKER.is_file(), reason="Docker Desktop is required by the governed candidate runtime")
@pytest.mark.docker_host
def test_live_container_canary_blocks_native_extension_host_escape(tmp_path, governed_docker_test_lock):
    run_id = unique_run_id(0)
    workspace = tmp_path / "workspace"
    registry = tmp_path / "registry"
    evidence = tmp_path / "evidence"
    workspace.mkdir()
    registry.mkdir()
    evidence.mkdir()
    qualification = runtime.qualify_candidate_container(
        docker=DOCKER,
        image_id=IMAGE_ID,
        policy_path=POLICY,
        workspace_root=workspace,
        canary_source=REPO / "improvement_container_canary.py",
        run_id=run_id,
        cycle=0,
        authorization_sha256="a" * 64,
        registry_dir=registry,
        cwd=REPO,
        environment=docker_environment(),
        timeout=120,
        evidence_dir=evidence,
        token="pytest-native-boundary",
    )
    assert qualification["pass"] is True
    assert qualification["python_audit_hook_security_boundary"] is False
    canary = json.loads((evidence / "container_canary.json").read_text())
    probes = {row["label"]: row for row in canary["probes"]}
    for label in (
        "workspace_write_cycle",
        "python_socket",
        "native_socket",
        "raw_socket",
        "native_mount",
        "numpy_fromfile_host",
        "numpy_memmap_host",
        "ctypes_open_host",
    ):
        assert probes[label]["succeeded"] is False
    assert probes["native_process_contained"]["succeeded"] is True
    assert probes["output_write_cycle"]["succeeded"] is True
    assert_run_containers_absent(run_id)
    lifecycle = next(evidence.glob("*_container_lifecycle.json"))
    lifecycle_value = json.loads(lifecycle.read_text())
    assert lifecycle_value["run_id"] == run_id
    assert lifecycle_value["state"] == "REMOVED"
    assert lifecycle_value["cleanup"]["absence_verified"] is True


@pytest.mark.skipif(not DOCKER.is_file(), reason="Docker Desktop is required by the governed candidate runtime")
@pytest.mark.docker_host
def test_durable_lifecycle_recovers_a_leftover_container(monkeypatch, tmp_path, governed_docker_test_lock):
    run_id = unique_run_id(1)
    run_workspace = tmp_path / run_id
    mounted = run_workspace / "mounted"
    mounted.mkdir(parents=True)
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    original_remove = runtime._remove_container
    monkeypatch.setattr(
        runtime,
        "_remove_container",
        lambda *args, **kwargs: (_ for _ in ()).throw(runtime.RuntimeFailure("injected cleanup fault")),
    )
    with pytest.raises(runtime.RuntimeFailure, match="requires recovery"):
        runtime.run_candidate_container(
            docker=DOCKER,
            image_id=IMAGE_ID,
            policy_path=POLICY,
            workspace_root=mounted,
            workdir=".",
            command=["python", "-c", "print('contained')"],
            run_id=run_id,
            cycle=1,
            command_id="recovery-fault",
            authorization_sha256="b" * 64,
            registry_dir=run_workspace,
            cwd=REPO,
            environment=docker_environment(),
            timeout=60,
            evidence=evidence / "command.json",
        )
    assert len(governed_containers_for_run(run_id)) == 1
    monkeypatch.setattr(runtime, "_remove_container", original_remove)
    recovered = runtime.recover_governed_containers(
        docker=DOCKER,
        worktree_root=tmp_path,
        cwd=REPO,
        environment=docker_environment(),
        timeout=60,
        evidence_dir=evidence / "recovery",
        run_id=run_id,
    )
    assert len(recovered) == 1 and recovered[0]["removed"] is True
    assert_run_containers_absent(run_id)
    record = json.loads(next(run_workspace.glob("container-*.json")).read_text())
    assert record["state"] == "REMOVED_RECOVERY"
    runtime.assert_governed_containers_quiescent(
        docker=DOCKER,
        worktree_root=tmp_path,
        run_id=run_id,
        cwd=REPO,
        environment=docker_environment(),
        timeout=60,
        evidence=evidence / "quiescence.json",
    )


@pytest.mark.skipif(not DOCKER.is_file(), reason="Docker Desktop is required by the governed candidate runtime")
@pytest.mark.docker_host
def test_container_timeout_removes_the_workload_and_verifies_absence(tmp_path, governed_docker_test_lock):
    run_id = unique_run_id(4)
    run_workspace = tmp_path / run_id
    mounted = run_workspace / "mounted"
    mounted.mkdir(parents=True)
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    with pytest.raises(runtime.RuntimeTimeout):
        runtime.run_candidate_container(
            docker=DOCKER,
            image_id=IMAGE_ID,
            policy_path=POLICY,
            workspace_root=mounted,
            workdir=".",
            command=["python", "-c", "import time; time.sleep(30)"],
            run_id=run_id,
            cycle=1,
            command_id="timeout-fault",
            authorization_sha256="d" * 64,
            registry_dir=run_workspace,
            cwd=REPO,
            environment=docker_environment(),
            timeout=3,
            evidence=evidence / "timeout.json",
        )
    assert_run_containers_absent(run_id)
    lifecycle = json.loads(next(evidence.glob("*_container_lifecycle.json")).read_text())
    assert lifecycle["state"] == "REMOVED" and lifecycle["cleanup"]["absence_verified"] is True


def test_container_policy_inspection_rejects_extra_mount(monkeypatch, tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    policy = runtime.load_container_policy(POLICY)
    labels = {runtime.CONTAINER_LABEL: "true"}
    value = {
        "Id": "a" * 64,
        "Image": IMAGE_ID,
        "Name": "/fixed",
        "Config": {
            "Image": IMAGE_ID,
            "Entrypoint": None,
            "Cmd": ["python", "--version"],
            "User": "65532:65532",
            "WorkingDir": "/workspace",
            "Labels": labels,
        },
        "State": {"Running": False},
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true", "seccomp=builtin"],
            "Privileged": False,
            "PidMode": "",
            "IpcMode": "private",
            "CgroupnsMode": "private",
            "PidsLimit": 128,
            "Memory": 2147483648,
            "MemorySwap": 2147483648,
            "NanoCpus": 2000000000,
            "Tmpfs": {
                "/tmp": "rw,nosuid,nodev,size=268435456,mode=1777",
                "/output": "rw,nosuid,nodev,size=268435456,mode=1777",
            },
            "AutoRemove": False,
            "Devices": [],
            "Ulimits": [{"Name": "nofile", "Soft": 1024, "Hard": 1024}],
        },
        "Mounts": [
            {"Type": "bind", "Source": str(workspace), "Destination": "/workspace", "RW": False, "Propagation": "rprivate"},
            {"Type": "bind", "Source": str(tmp_path), "Destination": "/host", "RW": False, "Propagation": "rprivate"},
        ],
    }
    with pytest.raises(runtime.RuntimeFailure, match="exactly one"):
        runtime._assert_container_policy(
            value,
            policy=policy,
            image_id=IMAGE_ID,
            workspace_root=workspace,
            name="fixed",
            labels=labels,
            expected_workdir="/workspace",
            expected_command=["python", "--version"],
        )
    value["Mounts"] = value["Mounts"][:1]
    value["Config"]["WorkingDir"] = "/"
    with pytest.raises(runtime.RuntimeFailure, match="fixed security policy"):
        runtime._assert_container_policy(
            value,
            policy=policy,
            image_id=IMAGE_ID,
            workspace_root=workspace,
            name="fixed",
            labels=labels,
            expected_workdir="/workspace",
            expected_command=["python", "--version"],
        )
    value["Config"]["WorkingDir"] = "/workspace"
    value["Config"]["Cmd"] = ["sh"]
    with pytest.raises(runtime.RuntimeFailure, match="fixed security policy"):
        runtime._assert_container_policy(
            value,
            policy=policy,
            image_id=IMAGE_ID,
            workspace_root=workspace,
            name="fixed",
            labels=labels,
            expected_workdir="/workspace",
            expected_command=["python", "--version"],
        )
