"""Run the same quality gates used by CI."""

from __future__ import annotations

import subprocess
import sys

NPM = "npm.cmd" if sys.platform == "win32" else "npm"

COMMANDS = (
    (sys.executable, "-m", "ruff", "check", "."),
    (sys.executable, "-m", "ruff", "format", "--check", "."),
    (sys.executable, "-m", "mypy", "src"),
    (sys.executable, "-m", "pytest", "tests/unit", "--no-cov"),
    (sys.executable, "-m", "pytest", "tests/integration", "--no-cov"),
    (sys.executable, "-m", "pytest", "tests"),
    (NPM, "run", "test:e2e"),
)


def main() -> int:
    for command in COMMANDS:
        result = subprocess.run(command, check=False)  # noqa: S603
        if result.returncode:
            return result.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
