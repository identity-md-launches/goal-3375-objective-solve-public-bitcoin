#!/usr/bin/env python3
"""Synthetic-test API for candidate-check. Separate from the production command.

It runs the same evaluation and output code as candidate_check.py against a
generated, labelled synthetic challenge. Every report says mode SYNTHETIC and
production_candidate_verified false, and the production public key and address
are refused as synthetic targets, so a pass here can never be read as a
recovered Puzzle #140 key.

Command form (the challenge descriptor is public data; the candidate is not):

    python3 -I -B synthetic_api.py --challenge-file challenge.json --candidate-fd 3 3< cand.bin
"""

import json
import os
import re
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cc_core  # noqa: E402
import cc_primitives as prim  # noqa: E402

DESCRIPTOR_KEYS = ("compressed_public_key", "interval_lower_hex", "interval_upper_hex",
                   "label", "p2pkh_address")
MAX_DESCRIPTOR_BYTES = 4096

USAGE = ("usage: synthetic_api.py --challenge-file PATH --candidate-fd N\n"
         "       synthetic_api.py --help\n"
         "SYNTHETIC challenges only; the production target is refused.\n"
         "exit: 0 synthetic match, 1 no match, 2 usage/descriptor error, 3 internal error")


def make_challenge(label, scalar, lower, upper):
    """Build a public synthetic challenge descriptor from a known synthetic scalar.

    For tests and rehearsals only. The scalar is supplied by the caller and is
    not stored in the descriptor.
    """
    x, y = prim.multiply_checked(scalar)
    public_key = prim.encode_compressed(x, y)
    descriptor = {
        "compressed_public_key": public_key.hex(),
        "interval_lower_hex": "%064x" % lower,
        "interval_upper_hex": "%064x" % upper,
        "label": label,
        "p2pkh_address": prim.p2pkh_address_from_compressed(public_key),
    }
    parse_challenge(descriptor)
    return descriptor


def parse_challenge(descriptor):
    """Strictly validate a synthetic challenge descriptor and return its target.

    Raises cc_core.Refusal with a fixed code for a truncated, malformed,
    invalid-point, unlabelled or production descriptor.
    """
    if not isinstance(descriptor, dict) or sorted(descriptor) != sorted(DESCRIPTOR_KEYS):
        raise cc_core.Refusal("challenge_descriptor_malformed")
    for key in DESCRIPTOR_KEYS:
        if not isinstance(descriptor[key], str):
            raise cc_core.Refusal("challenge_descriptor_malformed")
    key_hex = descriptor["compressed_public_key"]
    if re.fullmatch(r"[0-9a-f]{66}", key_hex) is None:
        raise cc_core.Refusal("challenge_public_key_invalid")
    bounds = []
    for name in ("interval_lower_hex", "interval_upper_hex"):
        if re.fullmatch(r"[0-9a-f]{64}", descriptor[name]) is None:
            raise cc_core.Refusal("challenge_interval_invalid")
        bounds.append(int(descriptor[name], 16))
    return cc_core.synthetic_target(descriptor["label"], bytes.fromhex(key_hex),
                                    descriptor["p2pkh_address"], bounds[0], bounds[1])


def check_synthetic_candidate(candidate, descriptor):
    """Report for a 32-byte big-endian candidate against a synthetic descriptor."""
    return cc_core.check_candidate(candidate, parse_challenge(descriptor))


def check_synthetic_candidate_fd(fd, descriptor):
    """As check_synthetic_candidate, reading exactly 32 bytes then EOF from fd."""
    return cc_core.check_candidate_fd(fd, parse_challenge(descriptor))


def load_challenge_file(path):
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_DESCRIPTOR_BYTES + 1)
    except Exception:
        raise cc_core.Refusal("challenge_file_unreadable") from None
    if len(raw) > MAX_DESCRIPTOR_BYTES:
        raise cc_core.Refusal("challenge_descriptor_malformed")
    try:
        descriptor = json.loads(raw.decode("ascii"))
    except Exception:
        raise cc_core.Refusal("challenge_descriptor_malformed") from None
    return descriptor


def _body(argv):
    options = cc_core.parse_options(argv, ("--candidate-fd", "--challenge-file"), ("--help",))
    if options is None:
        raise cc_core.Refusal("usage")
    if options == {"--help": True}:
        cc_core._write_line(1, USAGE)
        return cc_core.EXIT_VERIFIED
    if sorted(options) != ["--candidate-fd", "--challenge-file"]:
        raise cc_core.Refusal("usage")
    fd = cc_core.parse_fd(options["--candidate-fd"])
    descriptor = load_challenge_file(options["--challenge-file"])
    report = check_synthetic_candidate_fd(fd, descriptor)
    cc_core.emit_json(report)
    return cc_core.exit_status_for(report)


def main(argv=None):
    """Command entry point. Never returns: the process exits with the status."""
    args = list(sys.argv[1:] if argv is None else argv)
    cc_core.guarded_exit(cc_core.MODE_SYNTHETIC, USAGE, lambda: _body(args))


if __name__ == "__main__":
    main()
