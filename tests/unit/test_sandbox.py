"""Unit tests for the sandbox runner.

The runner's own behaviour (the argument vector, the time and output limits,
killing the container) is tested here with ordinary local processes standing
in for the container runtime. The isolation the runtime provides is tested
against real containers in tests/integration/test_sandbox_isolation.py.
"""

from __future__ import annotations

import subprocess
import sys
from typing import Any

import pytest

from guardrail_gateway.config import Settings
from guardrail_gateway.sandbox import (
    ContainerSandbox,
    SandboxLimits,
    SandboxUnavailableError,
    build_sandbox,
)

pytestmark = pytest.mark.unit

IMAGE = "python:3.13-alpine"


class LocalRuntime:
    """Runs the submitted code with the local interpreter instead of a container."""

    def __init__(self) -> None:
        self.commands: list[list[str]] = []
        self.killed: list[str] = []

    def __call__(self, command: list[str]) -> subprocess.Popen[bytes]:
        self.commands.append(command)
        if command[1] == "kill":
            self.killed.append(command[2])
            program = "pass"
        elif command[1] == "version":
            program = "print('27.0')"
        else:
            # Read the code from stdin, as `python -` does inside the container.
            program = "import sys; exec(sys.stdin.read())"
        return subprocess.Popen(
            [sys.executable, "-c", program],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )


def _sandbox(runtime: Any, **limits: Any) -> ContainerSandbox:
    return ContainerSandbox(IMAGE, SandboxLimits(**limits), spawn=runtime)


def test_the_container_has_no_network_no_host_filesystem_and_no_privileges() -> None:
    command = _sandbox(LocalRuntime()).command("run-1", network=False)

    assert command[:2] == ["docker", "run"]
    assert command[command.index("--network") + 1] == "none"
    assert "--read-only" in command
    assert "--rm" in command
    assert command[command.index("--cap-drop") + 1] == "ALL"
    assert command[command.index("--security-opt") + 1] == "no-new-privileges"
    assert command[command.index("--user") + 1] == "65534:65534"
    assert "noexec" in command[command.index("--tmpfs") + 1]
    # Nothing from the host is mounted, and nothing is privileged.
    for forbidden in ("--volume", "-v", "--mount", "--privileged", "--pid", "--cap-add"):
        assert forbidden not in command
    assert command[-4:] == [IMAGE, "python", "-I", "-"]


def test_the_limits_are_passed_to_the_runtime() -> None:
    sandbox = _sandbox(LocalRuntime(), cpus=0.25, memory_mb=64, pids=8)

    command = sandbox.command("run-1", network=False)

    assert command[command.index("--cpus") + 1] == "0.25"
    assert command[command.index("--memory") + 1] == "64m"
    # Equal to the memory limit, so there is no swap to spill into.
    assert command[command.index("--memory-swap") + 1] == "64m"
    assert command[command.index("--pids-limit") + 1] == "8"


def test_network_is_attached_only_when_asked_for() -> None:
    command = _sandbox(LocalRuntime()).command("run-1", network=True)

    assert command[command.index("--network") + 1] == "bridge"


def test_a_stronger_oci_runtime_can_be_selected() -> None:
    sandbox = ContainerSandbox(IMAGE, SandboxLimits(), "podman", "runsc", LocalRuntime())

    command = sandbox.command("run-1", network=False)

    assert command[:4] == ["podman", "run", "--runtime", "runsc"]


def test_the_code_never_appears_in_the_argument_vector() -> None:
    runtime = LocalRuntime()

    result = _sandbox(runtime).run("print('a-distinctive-marker')", network=False)

    assert result.stdout.strip() == "a-distinctive-marker"
    assert all("a-distinctive-marker" not in part for part in runtime.commands[0])


def test_output_and_exit_code_are_returned() -> None:
    code = "import sys; print('out'); print('err', file=sys.stderr); sys.exit(3)"

    result = _sandbox(LocalRuntime()).run(code, network=False)

    assert (result.exit_code, result.stdout.strip(), result.stderr.strip()) == (3, "out", "err")
    assert not result.timed_out
    assert not result.output_truncated
    assert not result.network
    assert result.duration_ms > 0


def test_each_run_gets_its_own_container_name() -> None:
    runtime = LocalRuntime()
    sandbox = _sandbox(runtime)

    sandbox.run("pass", network=False)
    sandbox.run("pass", network=False)

    names = [command[command.index("--name") + 1] for command in runtime.commands]
    assert len(set(names)) == 2
    assert all(name.startswith("guardrail-sandbox-") for name in names)


def test_a_run_past_its_time_limit_is_killed() -> None:
    runtime = LocalRuntime()

    result = _sandbox(runtime, timeout_seconds=0.5).run(
        "import time; print('started', flush=True); time.sleep(60)", network=False
    )

    assert result.timed_out
    assert result.exit_code is None
    assert result.stdout.strip() == "started"
    assert result.duration_ms < 20_000
    name = runtime.commands[0][runtime.commands[0].index("--name") + 1]
    # The container itself is killed, not only the client waiting on it.
    assert runtime.killed == [name]


def test_a_run_past_its_output_limit_is_killed_and_truncated() -> None:
    runtime = LocalRuntime()
    flood = "import sys\nwhile True:\n    sys.stdout.write('x' * 4096)\n"

    result = _sandbox(runtime, output_bytes=10_000, timeout_seconds=30).run(flood, network=False)

    assert result.output_truncated
    assert not result.timed_out
    assert result.exit_code is None
    assert len(result.stdout) == 10_000
    assert len(runtime.killed) == 1
    assert result.duration_ms < 20_000


def test_output_exactly_at_the_limit_is_not_truncated() -> None:
    result = _sandbox(LocalRuntime(), output_bytes=100).run(
        "import sys; sys.stdout.write('x' * 100)", network=False
    )

    assert not result.output_truncated
    assert (result.exit_code, len(result.stdout)) == (0, 100)


def test_output_that_is_not_text_is_still_returned() -> None:
    result = _sandbox(LocalRuntime()).run(
        "import sys; sys.stdout.buffer.write(bytes([255, 254, 65]))", network=False
    )

    assert result.stdout.endswith("A")


def test_a_runtime_that_cannot_start_is_unavailable() -> None:
    def missing(_command: list[str]) -> subprocess.Popen[bytes]:
        raise FileNotFoundError("docker")

    sandbox = _sandbox(missing)

    assert not sandbox.available()
    with pytest.raises(SandboxUnavailableError):
        sandbox.run("print(1)", network=False)


def test_a_runtime_whose_daemon_is_down_is_unavailable() -> None:
    def failing(_command: list[str]) -> subprocess.Popen[bytes]:
        return subprocess.Popen(
            [sys.executable, "-c", "import sys; sys.exit(1)"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    assert not _sandbox(failing).available()


def test_a_working_runtime_is_available() -> None:
    runtime = LocalRuntime()

    assert _sandbox(runtime).available()
    assert runtime.commands[0][:2] == ["docker", "version"]


def test_a_runtime_that_exits_before_reading_the_code_reports_its_error() -> None:
    def exits_at_once(_command: list[str]) -> subprocess.Popen[bytes]:
        return subprocess.Popen(
            [sys.executable, "-c", "import sys; sys.stderr.write('no such image'); sys.exit(125)"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    result = _sandbox(exits_at_once).run("print(1)" * 100_000, network=False)

    assert result.exit_code == 125
    assert result.stderr == "no such image"


def test_no_image_means_no_sandbox(settings: Settings) -> None:
    assert build_sandbox(settings) is None


def test_the_sandbox_is_built_from_settings(settings: Settings) -> None:
    configured = settings.model_copy(
        update={
            "sandbox_image": IMAGE,
            "sandbox_runtime": "podman",
            "sandbox_oci_runtime": "runsc",
            "sandbox_cpus": 1.0,
            "sandbox_memory_mb": 256,
            "sandbox_pids": 16,
            "sandbox_timeout_seconds": 5.0,
            "sandbox_output_bytes": 1_000,
        }
    )

    sandbox = build_sandbox(configured)

    assert isinstance(sandbox, ContainerSandbox)
    command = sandbox.command("run-1", network=False)
    assert command[:4] == ["podman", "run", "--runtime", "runsc"]
    assert command[command.index("--memory") + 1] == "256m"
    assert command[command.index("--cpus") + 1] == "1.0"
    assert command[command.index("--pids-limit") + 1] == "16"
    assert sandbox._limits == SandboxLimits(1.0, 256, 16, 5.0, 1_000)


@pytest.mark.parametrize("image", ["python; rm -rf /", "--privileged", "image name", ""])
def test_an_image_name_that_could_be_an_option_or_a_command_is_refused(image: str) -> None:
    with pytest.raises(ValueError, match="sandbox_image"):
        Settings(sandbox_image=image)
