"""Offline protocol and Keccak checks for any backend; no wallet or RPC required.

  .venv/bin/python test_engine.py --engine ./miner_metal
  .venv/bin/python test_engine.py --engine './miner_cpu --threads 1'
"""
import argparse
import queue
import random
import shlex
import subprocess
import threading
import time

from Crypto.Hash import keccak


class Engine:
    def __init__(self, command):
        self.proc = subprocess.Popen(shlex.split(command), stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, text=True, bufsize=1)
        self.lines = queue.Queue()
        self.jobs = {}
        self.seen = set()
        self.checked = 0
        threading.Thread(target=self.read_output, daemon=True).start()

    def read_output(self):
        for line in self.proc.stdout:
            self.lines.put(line.split())
        self.lines.put(None)

    def send(self, command):
        self.proc.stdin.write(command + "\n")
        self.proc.stdin.flush()

    def next_line(self, deadline):
        try:
            parts = self.lines.get(timeout=max(0, deadline - time.monotonic()))
        except queue.Empty:
            raise AssertionError("engine response timed out") from None
        assert parts, "engine exited unexpectedly"
        assert parts[0] != "ERR", " ".join(parts)
        if parts[0] == "HIT":
            job, nonce, top = int(parts[1]), int(parts[2], 16), int(parts[3], 16)
            message, threshold = self.jobs[job]
            digest = keccak.new(digest_bits=256, data=message + nonce.to_bytes(8, "big")).digest()
            assert top == int.from_bytes(digest[:8], "big"), "GPU/CPU digest mismatch"
            assert top < threshold, "hit above threshold"
            assert (job, nonce) not in self.seen, "duplicate nonce"
            self.seen.add((job, nonce))
            self.checked += 1
        return parts

    def wait_for(self, kind, job=None):
        deadline = time.monotonic() + 60
        while True:
            parts = self.next_line(deadline)
            if parts[0] == kind and (job is None or int(parts[1]) == job):
                return parts

    def job(self, number, message, threshold):
        self.jobs[number] = (message, threshold)
        self.send(f"JOB {number} {message.hex()} {threshold:016x}")

    def expect_quiet(self):
        # Allow an in-flight batch to finish, then observe a full reporting interval.
        self.wait_for("RATE")
        deadline = time.monotonic() + 5
        while True:
            parts = self.next_line(deadline)
            assert parts[0] != "HIT", "engine emitted a hit while stopped"
            if parts[0] == "RATE":
                return

    def close(self, graceful):
        try:
            if self.proc.poll() is None:
                self.send("QUIT")
            code = self.proc.wait(timeout=5)
            if graceful:
                assert code == 0, f"engine exit status {code}"
        finally:
            if self.proc.poll() is None:
                self.proc.kill()
                self.proc.wait()
            self.proc.stdin.close()
            self.proc.stdout.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True)
    args = parser.parse_args()
    engine = Engine(args.engine)
    passed = False
    try:
        assert engine.wait_for("SELFTEST")[1] == "OK", "backend selftest failed"
        assert int(engine.wait_for("READY")[1]) > 0, "no devices initialized"
        rng = random.Random(42)
        messages = [bytes(rng.randrange(256) for _ in range(184)) for _ in range(3)]
        threshold = 1 << 44
        engine.job(11, messages[0], threshold)
        for _ in range(3):
            engine.wait_for("HIT", 11)

        engine.send("THR 11 0")
        engine.expect_quiet()
        engine.send(f"THR 999 {threshold:016x}")  # a stale race must not change the current threshold
        engine.expect_quiet()
        engine.send(f"THR 11 {threshold:016x}")
        engine.wait_for("HIT", 11)

        engine.job(12, messages[1], threshold)
        engine.wait_for("HIT", 12)
        for _ in range(2):
            assert engine.wait_for("HIT")[1] == "12", "stale job emitted after replacement"
        engine.send("IDLE")
        engine.expect_quiet()
        engine.job(13, messages[2], threshold)
        engine.wait_for("HIT", 13)
        passed = True
    finally:
        engine.close(graceful=passed)
    print(f"PASS: {engine.checked} independent digest checks; JOB, THR, stale THR, IDLE, resume, QUIT")


if __name__ == "__main__":
    main()
