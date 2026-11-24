#!/usr/bin/env python3
"""Synthetic stand-in for the patched RCKangaroo binary, used by the non-CUDA
output-path tests. It speaks ONLY the candidate-fd contract: on success it
writes exactly 32 big-endian sentinel bytes to the inherited --candidate-fd and
writes nothing secret to stdout/stderr.

These are output-path / leak tests. They are NOT GPU correctness tests and make
no claim about solving any ECDLP.

--fake-mode:
  good   write 32 sentinel bytes to the fd, exit 0
  short  write only 10 bytes, exit 0           (wrapper must fail closed)
  none   write nothing, exit 0                  (wrapper must fail closed)
  crash  write 32 bytes but exit 7              (wrapper must fail closed)
  leak   write 32 bytes AND print a fake "PRIVATE KEY: <64hex>" to stdout and
         stderr (wrapper must scrub it and never surface the hex)
"""
import argparse
import os
import sys

# A fixed, obviously-synthetic sentinel (not a real key).
SENTINEL = bytes(range(1, 33))            # 01 02 ... 20  (big-endian)
SENTINEL_HEX = SENTINEL.hex()
FAKE_LEAK_HEX = "de" * 32                  # looks like a key; must be scrubbed


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--candidate-fd", type=int, default=-1)
    p.add_argument("--fake-mode", default="good")
    # accept and ignore the real solver's options so the wrapper arg list works
    for opt in ("-pubkey", "-range", "-start", "-dp", "-max", "-tames", "-gpu"):
        p.add_argument(opt, dest=opt.lstrip("-"), default=None)
    args, _unknown = p.parse_known_args()

    mode = args.fake_mode
    fd = args.candidate_fd

    if mode == "leak":
        sys.stdout.write("PRIVATE KEY: %s\n" % FAKE_LEAK_HEX)
        sys.stdout.flush()
        sys.stderr.write("fatal context dump key=%s\n" % FAKE_LEAK_HEX)
        sys.stderr.flush()

    if fd >= 0 and mode in ("good", "crash", "leak"):
        os.write(fd, SENTINEL)
        os.close(fd)
    elif fd >= 0 and mode == "short":
        os.write(fd, SENTINEL[:10])
        os.close(fd)
    elif fd >= 0 and mode == "none":
        os.close(fd)

    if mode == "crash":
        return 7
    return 0


if __name__ == "__main__":
    sys.exit(main())
