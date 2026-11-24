#!/usr/bin/env python3
"""Private local launcher; create a 0600 sink and inherit its FD into run.py.

No shell, no network, no environment or credential discovery. The private
candidate file is never read or printed by this launcher.
"""
import os
from pathlib import Path
import signal
import subprocess
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from kangaroo.cli import CHECKOUT, harden_process, parser, report_error, validate_args
from kangaroo.storage import PrivateDirectory


def main(argv=None):
    try:
        harden_process()
        p = parser()
        p.description = "Create a private candidate.bin sink and launch bounded run.py; synthetic by default."
        args_list = list(sys.argv[1:] if argv is None else argv)
        args = p.parse_args(args_list)
        validate_args(args, require_sink=False)
        if args.private_dir is None or args.candidate_fd is not None:
            raise ValueError("launcher needs private directory and manages the candidate FD")
        real = args.mode == "real"
        with PrivateDirectory(args.private_dir, str(CHECKOUT) if real else None,
                              create=not args.resume, lock=False) as directory:
            lock = directory.acquire_lock("launch.lock")
            fd = None
            try:
                fd = directory.open_file("candidate.bin", os.O_WRONLY, create=True)
                if os.fstat(fd).st_size != 0:
                    raise ValueError("candidate sink already occupied; never overwrite")
                os.fsync(directory.fd)
                command = [sys.executable, "-I", "-B", str(Path(__file__).resolve().with_name("run.py")),
                           *args_list, "--candidate-fd", str(fd)]
                child = None
                pending_signals = []
                previous = {}
                def forward(number, _frame):
                    if child is None:
                        pending_signals.append(number)
                    elif child.poll() is None:
                        child.send_signal(number)
                try:
                    previous = {s: signal.signal(s, forward) for s in (signal.SIGINT, signal.SIGTERM)}
                    child = subprocess.Popen(command, pass_fds=(fd,), env={})
                    for number in pending_signals:
                        if child.poll() is None:
                            child.send_signal(number)
                    status = child.wait()
                    return status if status >= 0 else 2
                finally:
                    if child is not None and child.poll() is None:
                        child.terminate()
                        try:
                            child.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            child.kill()
                            child.wait()
                    for number, handler in previous.items():
                        signal.signal(number, handler)
            finally:
                if fd is not None:
                    os.close(fd)
                os.close(lock)
    except (Exception, KeyboardInterrupt):
        report_error(launcher=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
