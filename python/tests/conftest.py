"""Starts a real daemon for the tests. Needs a built `wyatt` binary.

Set WYATT_BIN to use a specific binary; the default is the workspace's
target/debug/wyatt. Tests that need the daemon are skipped without it.
"""

import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]

POLICY = """
version: 1
name: python-tests
defaults:
  approval_timeout: 10s
agents:
  bot: {{ uid: {uid} }}
  nobody: {{ uid: {other_uid} }}
tools:
  read_file: {{ driver: fs.read, root: {root} }}
  echo: {{ driver: proc, command: [/bin/echo] }}
  send_email: {{ driver: delegate, args: {{ to: string, body: string }} }}
  deploy: {{ driver: delegate, args: {{ env: string }} }}
  search: {{ driver: delegate, args: {{ q: string }} }}
rules:
  - {{ id: read, allow: read_file }}
  - {{ id: echo, allow: echo }}
  - {{ id: search, allow: search }}
  - id: mail
    allow: send_email
    when: {{ args.to: {{ glob: "*@example.com" }} }}
  - id: no-exfil
    deny: send_email
    when: {{ session.labels: {{ contains: secret }} }}
    reason: this session has read a secret
  - {{ id: deploy, approve: deploy }}
"""


def _binary() -> Path | None:
    b = os.environ.get("WYATT_BIN")
    if b:
        return Path(b)
    p = REPO / "target" / "debug" / "wyatt"
    return p if p.exists() else shutil.which("wyatt") and Path(shutil.which("wyatt"))


@pytest.fixture(scope="session")
def daemon(tmp_path_factory):
    binary = _binary()
    if binary is None:
        pytest.skip("no wyatt binary: run `cargo build` or set WYATT_BIN")
    d = tmp_path_factory.mktemp("wyatt")
    root = d / "files"
    root.mkdir()
    (root / "notes.txt").write_text("hello from the sandbox\n")
    (root / ".env").write_text("DB_PASSWORD=correct-horse-battery-staple\n")
    (d / "outside.txt").write_text("should not be readable\n")
    policy = d / "wyatt.yaml"
    policy.write_text(POLICY.format(uid=os.getuid(), other_uid=os.getuid() + 1, root=root))
    agent, control = d / "agent.sock", d / "control.sock"
    proc = subprocess.Popen(
        [str(binary), "serve", "-p", str(policy), "--socket", str(agent), "--control", str(control), "--state", str(d / "state")],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.monotonic() + 10
    while not (agent.exists() and control.exists()):
        if proc.poll() is not None or time.monotonic() > deadline:
            proc.kill()
            pytest.fail(f"wyatt serve did not start: {proc.stderr.read()}")
        time.sleep(0.02)
    yield {"agent": agent, "control": control, "root": root, "dir": d, "binary": binary, "state": d / "state"}
    proc.terminate()
    proc.wait(timeout=5)
