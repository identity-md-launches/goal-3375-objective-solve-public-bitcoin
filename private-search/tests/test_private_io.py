import contextlib
import copy
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.dont_write_bytecode = True
COMPONENT = Path(__file__).absolute().parents[1]
ROOT = COMPONENT.parent
sys.path.insert(0, str(COMPONENT))
from kangaroo import cli
from kangaroo.engine import Engine
from kangaroo.manifest import canonical, synthetic_manifest
from kangaroo.storage import CandidateSink, PrivateDirectory, strict_json

SCRATCH = ROOT / "test" / "scratch" / "private-search-tests"
SENTINEL = b"SECRET_SENTINEL_NO_LOG_140".ljust(32, b"!")


class ScratchCase(unittest.TestCase):
    def setUp(self):
        SCRATCH.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="synthetic-", dir=SCRATCH)
        self.base = Path(self.temp.name)
        self.state = self.base / "state"

    def tearDown(self):
        self.temp.cleanup()

    def command(self, *args, script="run.py", **kwargs):
        return subprocess.run([sys.executable, "-I", "-B", str(COMPONENT / script), *map(str, args)],
                              capture_output=True, env={}, timeout=10, **kwargs)

    def assert_no_secret(self, data):
        if isinstance(data, str):
            data = data.encode()
        for forbidden in (SENTINEL, SENTINEL.hex().encode(), str(int.from_bytes(SENTINEL, "big")).encode()):
            self.assertNotIn(forbidden, data)


class StorageTests(ScratchCase):
    def test_atomic_checkpoint_roundtrip_modes_and_private_export(self):
        manifest, _ = synthetic_manifest(1 << 139, 4096, "lower", "io-v1")
        engine = Engine(manifest, seed="io-v1")
        engine.run(50, 1)
        with PrivateDirectory(str(self.state), None) as directory:
            directory.save(engine, export=True)
            self.assertEqual(directory.load(), engine.snapshot())
            for line in directory.read("dp.jsonl").splitlines():
                self.assertEqual(strict_json(line)["schema"], "walk-dp@1")
            self.assertEqual(stat.S_IMODE(os.fstat(directory.fd).st_mode), 0o700)
            for entry in self.state.iterdir():
                self.assertEqual(stat.S_IMODE(entry.stat().st_mode), 0o600)

    def test_atomic_failure_preserves_previous_checkpoint_and_recovers(self):
        with PrivateDirectory(str(self.state), None) as directory:
            directory.atomic_write("checkpoint.json", b"previous")
            with mock.patch("kangaroo.storage.os.replace", side_effect=OSError(SENTINEL.hex())):
                with self.assertRaises(OSError):
                    directory.atomic_write("checkpoint.json", b"next")
            self.assertEqual(directory.read("checkpoint.json"), b"previous")
            directory.atomic_write("checkpoint.json", b"final")
            self.assertEqual(directory.read("checkpoint.json"), b"final")
            self.assertFalse((self.state / ".checkpoint.json.pending").exists())

    def test_hash_duplicate_json_and_nan_rejected(self):
        manifest, _ = synthetic_manifest(1000, 17, "lower", "io-v1")
        engine = Engine(manifest)
        with PrivateDirectory(str(self.state), None) as directory:
            directory.save(engine)
            checkpoint = strict_json(directory.read("checkpoint.json"))
            checkpoint["payload"]["steps"] = "17"
            directory.atomic_write("checkpoint.json", canonical(checkpoint))
            with self.assertRaises(ValueError):
                directory.load()
        for text in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}'):
            with self.assertRaises(ValueError):
                strict_json(text)

    def test_exclusive_lock(self):
        with PrivateDirectory(str(self.state), None):
            with self.assertRaises(BlockingIOError):
                PrivateDirectory(str(self.state), None)

    def test_explicit_outside_checkout_and_no_insecure_directory(self):
        with self.assertRaises(ValueError):
            PrivateDirectory(str(self.state), str(ROOT))
        self.assertFalse(self.state.exists())
        # Exercise the outside-checkout rule with an isolated simulated checkout.
        with PrivateDirectory(str(self.state), str(self.base / "isolated-checkout")):
            pass
        os.chmod(self.state, 0o755)
        with self.assertRaises(ValueError):
            PrivateDirectory(str(self.state), None)
        for path in ("relative", str(self.base) + "/../state", str(self.base) + "/state/", "/"):
            with self.assertRaises(ValueError):
                PrivateDirectory(path, None)

    def test_symlink_directory_components_are_rejected(self):
        (self.base / "actual").mkdir(mode=0o700)
        (self.base / "alias").symlink_to(self.base / "actual", target_is_directory=True)
        for path in (self.base / "alias", self.base / "alias" / "state"):
            with self.assertRaises((OSError, ValueError)):
                PrivateDirectory(str(path), None)
        self.assertFalse((self.base / "actual" / "state").exists())

    def test_symlink_hardlink_mode_and_unknown_file_rejection(self):
        target = self.base / "target"
        target.write_bytes(SENTINEL)
        os.chmod(target, 0o600)
        self.state.mkdir(mode=0o700)
        entry = self.state / "checkpoint.json"
        entry.symlink_to(target)
        with self.assertRaises(ValueError):
            PrivateDirectory(str(self.state), None)
        entry.unlink()
        os.link(target, entry)
        with self.assertRaises(ValueError):
            PrivateDirectory(str(self.state), None)
        entry.unlink()
        entry.write_bytes(b"untrusted")
        os.chmod(entry, 0o644)
        with self.assertRaises(ValueError):
            PrivateDirectory(str(self.state), None)
        entry.unlink()
        (self.state / "unexpected").write_bytes(b"untrusted")
        with self.assertRaises(ValueError):
            PrivateDirectory(str(self.state), None)
        self.assertEqual(target.read_bytes(), SENTINEL)

    def test_symlink_swap_after_directory_open_is_rejected(self):
        target = self.base / "target"
        target.write_bytes(SENTINEL)
        os.chmod(target, 0o600)
        with PrivateDirectory(str(self.state), None) as directory:
            (self.state / "checkpoint.json").symlink_to(target)
            with self.assertRaises(ValueError):
                directory.atomic_write("checkpoint.json", b"forbidden")
        self.assertEqual(target.read_bytes(), SENTINEL)


class SinkTests(ScratchCase):
    def test_regular_private_sink_exact_bytes(self):
        with PrivateDirectory(str(self.state), None) as directory:
            fd = directory.open_file("candidate.bin", os.O_WRONLY, create=True)
            try:
                sink = CandidateSink(fd, directory)
                sink.deliver(SENTINEL)
            finally:
                os.close(fd)
            self.assertEqual(directory.read("candidate.bin"), SENTINEL)
            fd = directory.open_file("candidate.bin", os.O_WRONLY)
            try:
                with self.assertRaises(ValueError):
                    CandidateSink(fd, directory)
            finally:
                os.close(fd)

    def test_inherited_pipe_exact_bytes_and_broken_pipe(self):
        read_fd, write_fd = os.pipe()
        try:
            sink = CandidateSink(write_fd, None)
            sink.deliver(SENTINEL)
            self.assertEqual(os.read(read_fd, 33), SENTINEL)
            os.close(read_fd)
            read_fd = None
            with self.assertRaises(BrokenPipeError):
                sink.deliver(SENTINEL)
        finally:
            if read_fd is not None:
                os.close(read_fd)
            os.close(write_fd)

    def test_full_pipe_is_nonblocking(self):
        read_fd, write_fd = os.pipe()
        try:
            sink = CandidateSink(write_fd, None)
            while True:
                try:
                    os.write(write_fd, b"x" * 4096)
                except BlockingIOError:
                    break
            with self.assertRaises(BlockingIOError):
                sink.deliver(SENTINEL)
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_standard_io_alias_and_external_regular_file_rejected(self):
        with self.assertRaises(ValueError):
            CandidateSink(1, None)
        alias = os.dup(1)
        try:
            with self.assertRaises(ValueError):
                CandidateSink(alias, None)
        finally:
            os.close(alias)
        with PrivateDirectory(str(self.state), None) as directory:
            other = self.base / "outside-candidate"
            fd = os.open(other, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with self.assertRaises((ValueError, FileNotFoundError)):
                    CandidateSink(fd, directory)
            finally:
                os.close(fd)

    def test_named_fifo_rejected(self):
        fifo = self.base / "named-fifo"
        os.mkfifo(fifo, 0o600)
        reader = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
        writer = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
        try:
            with self.assertRaises(ValueError):
                CandidateSink(writer, None)
        finally:
            os.close(reader)
            os.close(writer)


class LauncherTests(ScratchCase):
    def test_default_is_synthetic_and_does_not_disclose_candidate(self):
        result = self.command()
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertEqual(output["mode"], "synthetic")
        self.assertEqual(output["status"], "solved")
        self.assertFalse(output["candidateDelivered"])
        self.assertNotIn(b"point", result.stdout + result.stderr)
        self.assertNotIn(b"distance", result.stdout + result.stderr)

    def test_real_mode_fails_before_engine_without_sink_or_private_path(self):
        for args in (["--mode", "real"],
                     ["--mode", "real", "--entrant-controlled", "--max-steps", "1", "--max-seconds", "1"],
                     ["--mode", "real", "--entrant-controlled", "--max-steps", "1", "--max-seconds", "1",
                      "--private-dir", str(self.state), "--candidate-fd", "1"]):
            with mock.patch("kangaroo.cli.Engine") as engine, contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli.guarded_main(args), 2)
                engine.assert_not_called()
        self.assertFalse(self.state.exists())

    def test_private_launcher_start_resume_and_never_overwrite(self):
        arguments = ["--private-dir", self.state, "--max-seconds", "5", "--synthetic-width", "65536",
                     "--synthetic-position", "lower", "--export-dp"]
        first = self.command(*arguments, "--max-steps", "17", script="launch.py")
        self.assertEqual(first.returncode, 3)
        self.assertEqual((self.state / "candidate.bin").stat().st_size, 0)
        resumed = self.command(*arguments, "--max-steps", "10000", "--resume", script="launch.py")
        self.assertEqual(resumed.returncode, 0)
        self.assertTrue(json.loads(resumed.stdout)["candidateDelivered"])
        _, known = synthetic_manifest(1 << 139, 65536, "lower", "trial-v1")
        candidate = (self.state / "candidate.bin").read_bytes()
        self.assertEqual(candidate, known.to_bytes(32, "big"))
        again = self.command(*arguments, "--max-steps", "10000", "--resume", script="launch.py")
        self.assertEqual(again.returncode, 2)
        self.assertEqual((self.state / "candidate.bin").read_bytes(), candidate)

    def test_resume_config_mismatch_rejected(self):
        result = self.command("--private-dir", self.state, "--max-steps", "1")
        self.assertEqual(result.returncode, 3)
        before = (self.state / "checkpoint.json").read_bytes()
        result = self.command("--private-dir", self.state, "--resume", "--dp-bits", "4")
        self.assertEqual(result.returncode, 2)
        self.assertEqual((self.state / "checkpoint.json").read_bytes(), before)

    def test_secret_sentinel_normal_and_error_paths(self):
        known = int.from_bytes(SENTINEL, "big")
        manifest, _ = synthetic_manifest(known, 1, "lower", "sentinel-v1")
        for inject_error in (False, True):
            with self.subTest(error=inject_error):
                read_fd, write_fd = os.pipe()
                stdout, stderr = io.StringIO(), io.StringIO()
                try:
                    with contextlib.ExitStack() as stack:
                        stack.enter_context(mock.patch("kangaroo.cli.synthetic_manifest", return_value=(manifest, known)))
                        stack.enter_context(contextlib.redirect_stdout(stdout))
                        stack.enter_context(contextlib.redirect_stderr(stderr))
                        if inject_error:
                            stack.enter_context(mock.patch.object(Engine, "candidate_bytes", side_effect=RuntimeError(SENTINEL.hex())))
                        code = cli.guarded_main(["--candidate-fd", str(write_fd)])
                    self.assertEqual(code, 2 if inject_error else 0)
                    self.assert_no_secret(stdout.getvalue() + stderr.getvalue())
                    os.close(write_fd)
                    write_fd = None
                    recovered = os.read(read_fd, 33)
                    self.assertEqual(recovered, b"" if inject_error else SENTINEL)
                finally:
                    os.close(read_fd)
                    if write_fd is not None:
                        os.close(write_fd)

    def test_secret_sentinel_argument_and_checkpoint_errors(self):
        result = self.command("--invalid", SENTINEL.decode())
        self.assertEqual(result.returncode, 2)
        self.assert_no_secret(result.stdout + result.stderr)
        with PrivateDirectory(str(self.state), None) as directory:
            directory.atomic_write("checkpoint.json", SENTINEL)
        result = self.command("--private-dir", self.state, "--resume")
        self.assertEqual(result.returncode, 2)
        self.assert_no_secret(result.stdout + result.stderr)

    def test_diagnostic_write_failure_does_not_escape_or_chain_secret(self):
        class BrokenDiagnostic:
            def write(self, _data):
                raise OSError(SENTINEL.decode())
            def flush(self):
                raise OSError(SENTINEL.decode())
        with mock.patch("kangaroo.cli.sys.stderr", BrokenDiagnostic()):
            self.assertEqual(cli.guarded_main(["--invalid", SENTINEL.decode()]), 2)
            # No exception escapes even when both the original error and diagnostics contain a sentinel.
            with mock.patch("kangaroo.cli.execute", side_effect=RuntimeError(SENTINEL.hex())):
                self.assertEqual(cli.guarded_main([]), 2)

    def test_delivery_failure_retains_solved_checkpoint(self):
        read_fd, write_fd = os.pipe()
        os.close(read_fd)
        try:
            result = self.command("--private-dir", self.state, "--candidate-fd", write_fd,
                                  pass_fds=(write_fd,))
        finally:
            os.close(write_fd)
        self.assertEqual(result.returncode, 2)
        self.assert_no_secret(result.stdout + result.stderr)
        with PrivateDirectory(str(self.state), None) as directory:
            state = directory.load()
        self.assertEqual(state["status"], "solved")
        # A new receiving process can resume the verified collision without searching again.
        read_fd, write_fd = os.pipe()
        try:
            retry = self.command("--private-dir", self.state, "--resume", "--candidate-fd", write_fd,
                                 pass_fds=(write_fd,))
            self.assertEqual(retry.returncode, 0)
            self.assertEqual(len(os.read(read_fd, 33)), 32)
            self.assertEqual(json.loads(retry.stdout)["steps"], 0)
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_os_interrupt_resume_equivalence(self):
        args = [sys.executable, "-I", "-B", str(COMPONENT / "run.py"),
                "--private-dir", str(self.state), "--max-steps", "1000000", "--max-seconds", "5",
                "--synthetic-width", str(1 << 24), "--dp-bits", "32", "--checkpoint-steps", "1"]
        child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={})
        try:
            deadline = time.monotonic() + 3
            while not (self.state / "checkpoint.json").exists():
                if time.monotonic() >= deadline or child.poll() is not None:
                    self.fail("synthetic child did not create checkpoint")
                time.sleep(0.005)
            child.send_signal(signal.SIGTERM)
            output, errors = child.communicate(timeout=5)
            self.assertEqual(child.returncode, 3)
            self.assertEqual(json.loads(output)["status"], "interrupted")
            self.assertEqual(errors, b"")
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=5)
        with PrivateDirectory(str(self.state), None) as directory:
            interrupted = directory.load()
        baseline = Engine(interrupted["manifest"], dp_bits=32)
        baseline.run(int(interrupted["steps"]), 5)
        self.assertEqual(interrupted, baseline.snapshot())
        resumed = self.command("--private-dir", self.state, "--resume", "--max-steps", "10", "--max-seconds", "5",
                               "--synthetic-width", 1 << 24, "--dp-bits", "32", "--checkpoint-steps", "1")
        self.assertEqual(resumed.returncode, 3)
        with PrivateDirectory(str(self.state), None) as directory:
            final = directory.load()
        baseline.run(10, 5)
        self.assertEqual(final, baseline.snapshot())

    def test_nan_infinite_negative_budgets_are_rejected(self):
        for value in ("nan", "inf", "-1", "0", "86401"):
            result = self.command("--max-seconds", value)
            self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
