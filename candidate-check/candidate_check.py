#!/usr/bin/env python3
"""Private candidate verifier for the fixed public Bitcoin Puzzle #140 manifest.

Usage (entrant-controlled private machine only):

    python3 -I -B candidate_check.py --candidate-fd 3 3< "$CANDIDATE_FILE"

The descriptor must deliver exactly 32 raw bytes (big-endian scalar) and then
EOF. The command prints one JSON object of booleans and public hashes and exits
0 only when every check is true. It never prints the candidate, a WIF, a
derived value or exception text, and it has no option, environment variable or
file that changes the public key, address or interval.
"""

import os
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cc_core  # noqa: E402

USAGE = ("usage: candidate_check.py --candidate-fd N   (N = 0 or >= 3; exactly 32 raw "
         "big-endian bytes then EOF)\n"
         "       candidate_check.py --manifest         (print the fixed public manifest)\n"
         "       candidate_check.py --help\n"
         "exit: 0 verified, 1 not verified, 2 usage/descriptor error, 3 internal error")


def production_manifest_report():
    """Public manifest and hashes; needs no candidate."""
    target = cc_core.production_target()
    hashes = cc_core.source_hashes()
    return {
        "component": cc_core.COMPONENT,
        "schema": cc_core.SCHEMA,
        "mode": target.mode,
        "manifest": cc_core.public_manifest(target),
        "manifest_sha256": cc_core.manifest_sha256(target),
        "source_sha256": hashes,
        "source_bundle_sha256": cc_core.source_bundle_sha256(hashes),
    }


def verify_production_candidate(candidate):
    """In-process interface for the claim tool.

    candidate: bytes or bytearray, exactly 32 bytes, big-endian scalar.
    Returns the public report dict; gate on report["production_candidate_verified"] is True.
    Takes no target argument: the production manifest cannot be substituted.
    """
    return cc_core.check_candidate(candidate, cc_core.production_target())


def verify_production_candidate_fd(fd):
    """Read exactly 32 bytes then EOF from an open descriptor, close it, and report."""
    return cc_core.check_candidate_fd(fd, cc_core.production_target())


def _body(argv):
    options = cc_core.parse_options(argv, ("--candidate-fd",), ("--help", "--manifest"))
    if options is None or len(options) != 1:
        raise cc_core.Refusal("usage")
    if "--help" in options:
        cc_core._write_line(1, USAGE)
        return cc_core.EXIT_VERIFIED
    if "--manifest" in options:
        cc_core.self_test()
        cc_core.emit_json(production_manifest_report())
        return cc_core.EXIT_VERIFIED
    fd = cc_core.parse_fd(options["--candidate-fd"])
    report = verify_production_candidate_fd(fd)
    cc_core.emit_json(report)
    return cc_core.exit_status_for(report)


def main(argv=None):
    """Command entry point. Never returns: the process exits with the status."""
    args = list(sys.argv[1:] if argv is None else argv)
    cc_core.guarded_exit(cc_core.MODE_PRODUCTION, USAGE, lambda: _body(args))


if __name__ == "__main__":
    main()
