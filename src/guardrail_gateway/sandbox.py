"""An ephemeral sandbox for code an agent proposes to run.

Section 11 of the design specification requires that code execution happens in
an ephemeral sandbox with no host filesystem access, no network unless that
was explicitly approved, and limits on CPU, memory, processes, output, and
time. Each run is a new container that is removed when it ends:

- No volume is mounted, the root filesystem is read-only, and the only
  writable path is a small in-memory `/tmp` that cannot hold executables.
- The network is `none` unless the action was approved with network access.
- It runs as an unprivileged user with every capability dropped and no way to
  gain privileges.
- CPU, memory (with no swap), process count, and open files are capped by the
  container runtime. Wall-clock time and output size are capped here: a run
  that exceeds either has its container killed.

The code is sent on standard input, so it never appears in a process list or
on disk. The sandbox only runs what the action endpoint has already allowed;
this module makes no authorization decision.

An ordinary container shares the host kernel. A deployment that runs hostile
code should set `GUARDRAIL_SANDBOX_OCI_RUNTIME` to one with a stronger
boundary, such as gVisor's `runsc`.
"""

from __future__ import annotations

import subprocess  # nosec B404 - argv is built here, no shell
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from threading import Event, Thread
from time import perf_counter
from typing import IO, Protocol
from uuid import uuid4

from guardrail_gateway.config import Settings
from guardrail_gateway.models import SandboxResult

_CHUNK_BYTES = 4_096
_UNPRIVILEGED_USER = "65534:65534"
# How long the runtime gets to report a killed container's exit.
_REAP_SECONDS = 10.0


class SandboxUnavailableError(Exception):
    """Raised when the container runtime cannot start a sandbox."""


@dataclass(frozen=True, slots=True)
class SandboxLimits:
    cpus: float = 0.5
    memory_mb: int = 128
    pids: int = 32
    timeout_seconds: float = 10.0
    output_bytes: int = 65_536

    @classmethod
    def from_settings(cls, settings: Settings) -> SandboxLimits:
        return cls(
            cpus=settings.sandbox_cpus,
            memory_mb=settings.sandbox_memory_mb,
            pids=settings.sandbox_pids,
            timeout_seconds=settings.sandbox_timeout_seconds,
            output_bytes=settings.sandbox_output_bytes,
        )


class Sandbox(Protocol):
    """Where allowed code runs; replaceable by another isolation technology."""

    def available(self) -> bool: ...

    def run(self, code: str, network: bool) -> SandboxResult:
        """Run the code or raise SandboxUnavailableError."""


def _spawn(command: list[str]) -> subprocess.Popen[bytes]:
    return subprocess.Popen(  # noqa: S603  # nosec B603 - fixed argv, code goes to stdin
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )


class ContainerSandbox:
    """Run Python in a new, locked-down container for each request."""

    def __init__(
        self,
        image: str,
        limits: SandboxLimits,
        runtime: str = "docker",
        oci_runtime: str | None = None,
        spawn: Callable[[list[str]], subprocess.Popen[bytes]] = _spawn,
    ) -> None:
        self._image = image
        self._limits = limits
        self._runtime = runtime
        self._oci_runtime = oci_runtime
        self._spawn = spawn

    def command(self, name: str, network: bool) -> list[str]:
        """The full argument vector for one run. Nothing in it comes from the caller."""

        limits = self._limits
        isolation = ["--runtime", self._oci_runtime] if self._oci_runtime else []
        return [
            self._runtime,
            "run",
            *isolation,
            "--rm",
            "--interactive",
            "--name",
            name,
            "--network",
            "bridge" if network else "none",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=16m",  # noqa: S108  # nosec B108 - inside the sandbox
            "--workdir",
            "/tmp",  # noqa: S108  # nosec B108 - inside the sandbox
            "--user",
            _UNPRIVILEGED_USER,
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            str(limits.pids),
            "--memory",
            f"{limits.memory_mb}m",
            # Equal to the memory limit, so the run cannot spill into swap.
            "--memory-swap",
            f"{limits.memory_mb}m",
            "--cpus",
            str(limits.cpus),
            "--ulimit",
            "nofile=64:64",
            "--env",
            "PYTHONDONTWRITEBYTECODE=1",
            self._image,
            # Isolated mode: no user site directory and no environment influence.
            "python",
            "-I",
            "-",
        ]

    def available(self) -> bool:
        try:
            process = self._spawn([self._runtime, "version", "--format", "{{.Server.Version}}"])
            process.communicate(timeout=_REAP_SECONDS)
        except (OSError, subprocess.SubprocessError):
            return False
        return process.returncode == 0

    def run(self, code: str, network: bool) -> SandboxResult:
        name = f"guardrail-sandbox-{uuid4().hex}"
        started = perf_counter()
        try:
            process = self._spawn(self.command(name, network))
        except OSError as error:
            raise SandboxUnavailableError from error

        overflow = Event()
        captured: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
        readers = [
            Thread(target=self._capture, args=(stream, captured[key], overflow), daemon=True)
            for key, stream in (("stdout", process.stdout), ("stderr", process.stderr))
            if stream is not None
        ]
        for reader in readers:
            reader.start()
        self._send(process, code)

        timed_out = not self._finished(process, overflow)
        if timed_out or overflow.is_set():
            self._kill(name, process)
        for reader in readers:
            reader.join(_REAP_SECONDS)
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                stream.close()

        killed = timed_out or overflow.is_set()
        return SandboxResult(
            exit_code=None if killed else process.returncode,
            stdout=captured["stdout"].decode(errors="replace"),
            stderr=captured["stderr"].decode(errors="replace"),
            timed_out=timed_out,
            output_truncated=overflow.is_set(),
            network=network,
            duration_ms=round((perf_counter() - started) * 1_000, 3),
        )

    def _capture(self, stream: IO[bytes], into: bytearray, overflow: Event) -> None:
        """Keep output up to the limit; past it, flag the run to be stopped."""

        limit = self._limits.output_bytes
        while chunk := stream.read1(_CHUNK_BYTES):  # type: ignore[attr-defined]
            room = limit - len(into)
            into.extend(chunk[:room])
            if len(chunk) > room:
                # Reading continues so the runtime is never blocked on a
                # full pipe while it is being killed; nothing more is kept.
                overflow.set()

    @staticmethod
    def _send(process: subprocess.Popen[bytes], code: str) -> None:
        if process.stdin is None:  # pragma: no cover - always piped by _spawn
            return
        # The runtime may exit before reading the code, for example because
        # the image is missing. Its exit code and stderr say why.
        with suppress(OSError):
            process.stdin.write(code.encode())
            process.stdin.close()

    def _finished(self, process: subprocess.Popen[bytes], overflow: Event) -> bool:
        """Wait for the run to end; False when it ran out of time."""

        deadline = perf_counter() + self._limits.timeout_seconds
        while perf_counter() < deadline:
            if overflow.is_set():
                return True
            try:
                process.wait(timeout=0.05)
            except subprocess.TimeoutExpired:
                continue
            return True
        return process.poll() is not None

    def _kill(self, name: str, process: subprocess.Popen[bytes]) -> None:
        """Stop the container itself; killing only the client would leave it running."""

        with suppress(OSError, subprocess.SubprocessError):
            self._spawn([self._runtime, "kill", name]).communicate(timeout=_REAP_SECONDS)
        process.kill()
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=_REAP_SECONDS)


def build_sandbox(settings: Settings) -> Sandbox | None:
    """The configured sandbox, or None when code execution is not offered."""

    if settings.sandbox_image is None:
        return None
    return ContainerSandbox(
        settings.sandbox_image,
        SandboxLimits.from_settings(settings),
        settings.sandbox_runtime,
        settings.sandbox_oci_runtime,
    )
