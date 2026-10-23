#!/usr/bin/env python3
"""Tests for sampler.sh on this host's /proc.

Run: python3 loadtest/live/test_sampler.py
"""
import csv
import os
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def comm(pid):
    """The process's name, as pgrep -x matches it."""
    with open(f"/proc/{pid}/comm") as f:
        return f.read().strip()


def lines(path):
    with open(path) as f:
        return sum(1 for _ in f)


class SamplerTest(unittest.TestCase):
    def test_a_root_device_that_lsblk_cannot_resolve_still_gives_rows(self):
        # GitHub's runners mount / from /dev/root, which lsblk does not know.
        with tempfile.TemporaryDirectory() as d:
            bin_dir = os.path.join(d, "bin")
            os.mkdir(bin_dir)
            for name, body in (("findmnt", "echo /dev/root"), ("lsblk", "exit 32")):
                path = os.path.join(bin_dir, name)
                with open(path, "w") as f:
                    f.write(f"#!/bin/sh\n{body}\n")
                os.chmod(path, 0o700)
            # A process with a name that no other process has.
            name = "samplertest"
            followed = subprocess.Popen([sys.executable, "-c", (
                f"open('/proc/self/comm', 'w').write('{name}'); import time; time.sleep(30)")])
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and comm(followed.pid) != name:
                time.sleep(0.1)
            self.assertEqual(comm(followed.pid), name)
            out = os.path.join(d, "sampler.csv")
            env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}")
            sampler = subprocess.Popen(
                ["bash", os.path.join(HERE, "sampler.sh"), out, "", name], env=env)
            try:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline and sampler.poll() is None:
                    if os.path.exists(out) and lines(out) >= 2:
                        break
                    time.sleep(0.1)
                code = sampler.poll()
            finally:
                for p in (sampler, followed):
                    p.kill()
                    p.wait()
            self.assertIsNone(code, f"sampler.sh exited with {code}")
            with open(out) as f:
                rows = list(csv.DictReader(f))
            self.assertGreaterEqual(len(rows), 1)
            self.assertEqual(rows[0]["alive"], "1")
            self.assertEqual(rows[0]["pid"], str(followed.pid))
            self.assertGreater(int(rows[0]["threads"]), 0)


if __name__ == "__main__":
    unittest.main()
