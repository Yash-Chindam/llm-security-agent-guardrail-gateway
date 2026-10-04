"""The isolation the container runtime actually provides.

These run real containers, so they need a container runtime and run when
`GUARDRAIL_TEST_SANDBOX_IMAGE` names an image, which CI does. Each test runs
code that tries to do what the sandbox must prevent.
"""

from __future__ import annotations

import os

import pytest

from guardrail_gateway.sandbox import ContainerSandbox, SandboxLimits

IMAGE = os.environ.get("GUARDRAIL_TEST_SANDBOX_IMAGE")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(IMAGE is None, reason="GUARDRAIL_TEST_SANDBOX_IMAGE is not set"),
]


def _sandbox(**limits: object) -> ContainerSandbox:
    assert IMAGE is not None
    return ContainerSandbox(IMAGE, SandboxLimits(**{"timeout_seconds": 60.0, **limits}))  # type: ignore[arg-type]


def test_the_runtime_is_available() -> None:
    assert _sandbox().available()


def test_code_runs_and_returns_its_output() -> None:
    result = _sandbox().run("print(sum(range(10)))", network=False)

    assert (result.exit_code, result.stdout.strip()) == (0, "45")


def test_there_is_no_network() -> None:
    code = (
        "import socket\n"
        "try:\n"
        "    socket.create_connection(('1.1.1.1', 53), timeout=3)\n"
        "    print('CONNECTED')\n"
        "except OSError as error:\n"
        "    print('blocked', type(error).__name__)\n"
        "print(sorted(name for _, name in socket.if_nameindex()))\n"
    )

    result = _sandbox().run(code, network=False)

    assert "CONNECTED" not in result.stdout
    assert "blocked" in result.stdout
    # Only the loopback interface exists.
    assert "['lo']" in result.stdout


def test_an_approved_run_does_get_a_network_interface() -> None:
    code = "import socket; print(sorted(name for _, name in socket.if_nameindex()))"

    result = _sandbox().run(code, network=True)

    assert result.network
    assert "eth0" in result.stdout


def test_the_filesystem_is_read_only_and_holds_nothing_from_the_host() -> None:
    code = (
        "import os\n"
        "for path in ('/probe', '/usr/probe', '/home/probe', '/etc/probe'):\n"
        "    try:\n"
        "        open(path, 'w').close()\n"
        "        print('WROTE', path)\n"
        "    except OSError:\n"
        "        pass\n"
        "print('docker.sock', os.path.exists('/var/run/docker.sock'))\n"
        "print('mounts', sum(1 for line in open('/proc/mounts') if ' /host' in line))\n"
    )

    result = _sandbox().run(code, network=False)

    assert result.exit_code == 0, result.stderr
    assert "WROTE" not in result.stdout
    assert "docker.sock False" in result.stdout
    assert "mounts 0" in result.stdout


def test_the_scratch_directory_is_writable_but_cannot_hold_executables() -> None:
    code = (
        "import os, subprocess\n"
        "open('/tmp/tool', 'w').write('#!/bin/sh\\necho RAN\\n')\n"
        "os.chmod('/tmp/tool', 0o755)\n"
        "try:\n"
        "    print(subprocess.run(['/tmp/tool'], capture_output=True, text=True).stdout)\n"
        "except OSError as error:\n"
        "    print('refused', type(error).__name__)\n"
    )

    result = _sandbox().run(code, network=False)

    assert "RAN" not in result.stdout
    assert "refused PermissionError" in result.stdout


def test_it_runs_unprivileged_with_no_capabilities() -> None:
    code = (
        "import os\n"
        "print('uid', os.getuid(), 'gid', os.getgid())\n"
        "lines = [line for line in open('/proc/self/status') if ':\\t' in line]\n"
        "status = dict(line.split(':\\t') for line in lines)\n"
        "print('caps', status['CapEff'].strip(), status['CapPrm'].strip())\n"
        "print('nnp', status['NoNewPrivs'].strip())\n"
    )

    result = _sandbox().run(code, network=False)

    assert "uid 65534 gid 65534" in result.stdout
    assert "caps 0000000000000000 0000000000000000" in result.stdout
    assert "nnp 1" in result.stdout


def test_a_run_past_its_memory_limit_is_killed() -> None:
    code = "block = bytearray(512 * 1024 * 1024)\nprint('ALLOCATED', len(block))\n"

    result = _sandbox(memory_mb=64).run(code, network=False)

    assert "ALLOCATED" not in result.stdout
    assert result.exit_code != 0


def test_a_fork_bomb_is_contained_by_the_process_limit() -> None:
    code = (
        "import os, time\n"
        "children = 0\n"
        "try:\n"
        "    for _ in range(200):\n"
        "        if os.fork() == 0:\n"
        "            time.sleep(5)\n"
        "            os._exit(0)\n"
        "        children += 1\n"
        "except OSError:\n"
        "    pass\n"
        "print('children', children)\n"
    )

    result = _sandbox(pids=16).run(code, network=False)

    count = int(result.stdout.split("children")[1].split()[0])
    assert count < 16


def test_a_run_past_its_time_limit_is_killed_and_its_container_removed() -> None:
    import subprocess

    result = _sandbox(timeout_seconds=3.0).run(
        "import time\nprint('started', flush=True)\ntime.sleep(120)\n", network=False
    )

    assert result.timed_out
    assert result.exit_code is None
    assert "started" in result.stdout
    assert result.duration_ms < 60_000
    left = subprocess.run(
        ["docker", "ps", "--all", "--quiet", "--filter", "name=guardrail-sandbox-"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert left.stdout.strip() == ""


def test_a_run_that_floods_output_is_killed() -> None:
    flood = "import sys\nwhile True:\n    sys.stdout.write('x' * 65536)\n"

    result = _sandbox(output_bytes=100_000).run(flood, network=False)

    assert result.output_truncated
    assert len(result.stdout) == 100_000
    assert result.duration_ms < 60_000
