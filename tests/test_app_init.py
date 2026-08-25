"""Regression test for a real bug in app/__init__.py's startup firewall
sync lock: the lock_file object was function-local, so its refcount hit
zero (closing the fd, releasing the flock) the instant _sync_firewall_once
returned — not held for "this worker's entire lifetime" as the code
claimed and the comment promised. A second, later-starting gunicorn
worker could then acquire the same now-free lock and re-run sync_all(),
re-duplicating every firewall rule in iptables.

This needs a real second OS process to prove: flock() semantics are what
was actually broken (a file descriptor getting garbage-collected releases
its lock), not any pure-Python logic a single-process/mocked test could
see. So this spawns a real child process that runs the actual
_sync_firewall_once, lets it return, and keeps the process alive
(simulating a worker that's done syncing but still serving requests) —
then checks from the test process whether the lock is still genuinely
held.
"""
import fcntl
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

CHILD_SCRIPT = '''
import sys
import time

sys.path.insert(0, {project_root!r})

import config
config.DB_PATH = sys.argv[1]

from app import _sync_firewall_once
from app import firewall as fw
fw.sync_all = lambda: None  # never touch real iptables/pivpn in this test


class _Logger:
    def warning(self, *a, **k):
        pass


class _App:
    logger = _Logger()


_sync_firewall_once(_App())
print("SYNCED", flush=True)
time.sleep(5)
'''


def test_firewall_sync_lock_held_for_whole_worker_lifetime(tmp_path):
    script = tmp_path / "child.py"
    script.write_text(CHILD_SCRIPT.format(project_root=str(PROJECT_ROOT)))
    db_path = str(tmp_path / "test.db")

    child = subprocess.Popen(
        [sys.executable, str(script), db_path],
        cwd=str(PROJECT_ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        line = child.stdout.readline()
        assert line.strip() == "SYNCED"  # _sync_firewall_once has returned
        assert child.poll() is None  # still alive — a worker still serving, not exited

        lock_path = tmp_path / ".firewall-sync.lock"
        deadline = time.time() + 3
        acquired = False
        while time.time() < deadline:
            if lock_path.exists():
                f = open(lock_path, "w")
                try:
                    fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    acquired = True
                except BlockingIOError:
                    acquired = False
                finally:
                    f.close()
                break
            time.sleep(0.05)
        assert not acquired, (
            "a second process acquired the same lock while the first was still "
            "alive — the flock was released early instead of held for the "
            "worker's whole lifetime"
        )
    finally:
        child.terminate()
        child.wait(timeout=5)
