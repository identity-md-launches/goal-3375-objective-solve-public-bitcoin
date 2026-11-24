"""Shared evaluation, descriptor reading and output discipline for candidate-check.

Everything that reaches stdout or stderr is built here from fixed strings,
booleans and hashes of public data. No function in this module formats a
candidate, a scalar, a derived point of a non-matching candidate, a WIF or the
text of an exception.
"""

import hashlib
import hmac
import json
import os
import re
import sys

import cc_primitives as prim

COMPONENT = "candidate-check"
SCHEMA = "candidate-check/v1"
MODE_PRODUCTION = "PRODUCTION"
MODE_SYNTHETIC = "SYNTHETIC"
SCOPE = ("candidate verification only; no UTXO, signing, broadcast or payment "
         "check; goal status is decided elsewhere")
SYNTHETIC_NOTICE = "SYNTHETIC challenge; a pass here is not a recovered Puzzle #140 key"

# Fixed public production manifest. There is no way to override it.
PRODUCTION_PUBLIC_KEY_HEX = "031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640"
PRODUCTION_ADDRESS = "1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo"
PRODUCTION_LOWER = 2 ** 139
PRODUCTION_UPPER = 2 ** 140 - 1
PRODUCTION_LABEL = "bitcoin-puzzle-140"

EXIT_VERIFIED = 0
EXIT_NOT_VERIFIED = 1
EXIT_USAGE = 2
EXIT_INTERNAL = 3

CHECK_NAMES = ("descriptor_exact_32_bytes", "scalar_valid", "scalar_in_interval",
               "public_key_match", "p2pkh_address_match")

SOURCE_FILES = ("candidate_check.py", "cc_core.py", "cc_primitives.py", "synthetic_api.py")

ERROR_CODES = frozenset((
    "usage",
    "candidate_descriptor_invalid",
    "candidate_descriptor_unreadable",
    "candidate_descriptor_is_terminal",
    "challenge_file_unreadable",
    "challenge_descriptor_malformed",
    "challenge_label_invalid",
    "challenge_public_key_invalid",
    "challenge_address_invalid",
    "challenge_interval_invalid",
    "production_target_refused",
    "self_test_failed",
    "internal_error",
))


class Refusal(Exception):
    """A refusal identified by a fixed code from ERROR_CODES and an exit status."""

    def __init__(self, code, exit_status=EXIT_USAGE):
        Exception.__init__(self, "refused")
        self.code = code if code in ERROR_CODES else "internal_error"
        self.exit_status = exit_status


class Target(object):
    """A challenge target. Built only by the two factory functions below."""

    __slots__ = ("mode", "label", "public_key", "address", "lower", "upper")

    def __init__(self, mode, label, public_key, address, lower, upper):
        self.mode = mode
        self.label = label
        self.public_key = public_key
        self.address = address
        self.lower = lower
        self.upper = upper


def production_target():
    """The one production target; takes no arguments by design."""
    return Target(MODE_PRODUCTION, PRODUCTION_LABEL, bytes.fromhex(PRODUCTION_PUBLIC_KEY_HEX),
                  PRODUCTION_ADDRESS, PRODUCTION_LOWER, PRODUCTION_UPPER)


def synthetic_target(label, public_key, address, lower, upper):
    """A labelled synthetic target; refuses the production key and address."""
    if not isinstance(label, str) or re.fullmatch(r"SYNTHETIC-[A-Za-z0-9._-]{1,48}", label) is None:
        raise Refusal("challenge_label_invalid")
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 33:
        raise Refusal("challenge_public_key_invalid")
    public_key = bytes(public_key)
    try:
        prim.decode_compressed(public_key)
    except prim.PrimitiveError:
        raise Refusal("challenge_public_key_invalid") from None
    try:
        address_hash = prim.p2pkh_hash_from_address(address)
    except prim.PrimitiveError:
        raise Refusal("challenge_address_invalid") from None
    production = production_target()
    if (public_key[1:] == production.public_key[1:] or address == production.address
            or address_hash == prim.hash160(production.public_key)):
        raise Refusal("production_target_refused")
    if not (isinstance(lower, int) and isinstance(upper, int)) or isinstance(lower, bool) \
            or isinstance(upper, bool) or not (1 <= lower <= upper < prim.N):
        raise Refusal("challenge_interval_invalid")
    return Target(MODE_SYNTHETIC, label, public_key, address, lower, upper)


def public_manifest(target):
    """Public description of a target; contains no candidate-derived data."""
    return {
        "candidate_encoding": "32-byte big-endian scalar",
        "compressed_public_key": target.public_key.hex(),
        "curve": "secp256k1",
        "interval_lower_hex": "%064x" % target.lower,
        "interval_upper_hex": "%064x" % target.upper,
        "label": target.label,
        "mode": target.mode,
        "p2pkh_address": target.address,
    }


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def manifest_sha256(target):
    return hashlib.sha256(canonical_json(public_manifest(target)).encode("ascii")).hexdigest()


def source_hashes():
    """SHA-256 of this component's own source files (public data)."""
    here = os.path.dirname(os.path.abspath(__file__))
    result = {}
    for name in SOURCE_FILES:
        with open(os.path.join(here, name), "rb") as handle:
            result[name] = hashlib.sha256(handle.read()).hexdigest()
    return result


def source_bundle_sha256(hashes):
    text = "".join("%s  %s\n" % (hashes[name], name) for name in sorted(hashes))
    return hashlib.sha256(text.encode("ascii")).hexdigest()


# --------------------------------------------------------------------------
# Known-answer self test (published values only; runs before any candidate)
# --------------------------------------------------------------------------

_KAT_POINTS = (
    (1, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
    (2, "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
    (3, "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"),
    (prim.N - 1, "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
)
_KAT_ADDRESS_ONE = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
_KAT_RIPEMD_ABC = "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"


def self_test():
    """Raise Refusal('self_test_failed') unless the primitives reproduce published values."""
    try:
        ok = prim.ripemd160(b"abc").hex() == _KAT_RIPEMD_ABC
        for scalar, expected in _KAT_POINTS:
            x, y = prim.multiply_checked(scalar)
            encoded = prim.encode_compressed(x, y)
            ok = ok and encoded.hex() == expected
            ok = ok and prim.decode_compressed(encoded) == (x, y)
        one = prim.encode_compressed(prim.GX, prim.GY)
        ok = ok and prim.p2pkh_address_from_compressed(one) == _KAT_ADDRESS_ONE
        # Public consistency of the fixed production manifest.
        production = production_target()
        prim.decode_compressed(production.public_key)
        ok = ok and prim.p2pkh_address_from_compressed(production.public_key) == production.address
        ok = ok and 1 <= production.lower <= production.upper < prim.N
    except Exception:
        ok = False
    if not ok:
        raise Refusal("self_test_failed", EXIT_INTERNAL)


# --------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------

def evaluate(candidate, target):
    """Boolean checks of a candidate against a target. Returns a dict of bools only."""
    checks = dict((name, False) for name in CHECK_NAMES)
    if not isinstance(candidate, (bytes, bytearray)) or len(candidate) != 32:
        return checks
    checks["descriptor_exact_32_bytes"] = True
    scalar = int.from_bytes(candidate, "big")
    if not (1 <= scalar < prim.N):
        return checks
    checks["scalar_valid"] = True
    checks["scalar_in_interval"] = bool(target.lower <= scalar <= target.upper)
    failed = False
    try:
        x, y = prim.multiply_checked(scalar)
        encoded = prim.encode_compressed(x, y)
        derived_address = prim.p2pkh_address_from_compressed(encoded)
        target_hash = prim.p2pkh_hash_from_address(target.address)
        derived_hash = prim.hash160(encoded)
    except BaseException:
        failed = True
    finally:
        scalar = 0
    if failed:
        # Raised outside the handler so the original exception, whose text may be
        # scalar-derived, is not reachable through __cause__ or __context__.
        raise Refusal("internal_error", EXIT_INTERNAL)
    checks["public_key_match"] = bool(hmac.compare_digest(encoded, target.public_key))
    checks["p2pkh_address_match"] = bool(
        hmac.compare_digest(derived_address.encode("ascii"), target.address.encode("ascii"))
        and hmac.compare_digest(derived_hash, target_hash))
    return checks


def build_report(target, checks):
    """Public report: fixed strings, booleans and hashes of public data only."""
    clean = dict((name, checks.get(name) is True) for name in CHECK_NAMES)
    verified = all(clean.values())
    hashes = source_hashes()
    report = {
        "component": COMPONENT,
        "schema": SCHEMA,
        "mode": target.mode,
        "manifest_sha256": manifest_sha256(target),
        "source_sha256": hashes,
        "source_bundle_sha256": source_bundle_sha256(hashes),
        "checks": clean,
        "candidate_verified": verified,
        "production_candidate_verified": bool(verified and target.mode == MODE_PRODUCTION),
        "scope": SCOPE,
    }
    if target.mode != MODE_PRODUCTION:
        report["synthetic_notice"] = SYNTHETIC_NOTICE
    return report


def check_candidate(candidate, target):
    """Self-test, evaluate and report. In-process interface for a claim tool."""
    self_test()
    return build_report(target, evaluate(candidate, target))


def exit_status_for(report):
    return EXIT_VERIFIED if report.get("candidate_verified") is True else EXIT_NOT_VERIFIED


# --------------------------------------------------------------------------
# Descriptor handling
# --------------------------------------------------------------------------

def parse_fd(text):
    """Parse a descriptor number without ever echoing the argument."""
    if not isinstance(text, str) or re.fullmatch(r"[0-9]{1,6}", text) is None:
        raise Refusal("candidate_descriptor_invalid")
    number = int(text)
    if number in (1, 2):
        raise Refusal("candidate_descriptor_invalid")
    return number


def read_candidate_fd(fd):
    """Read at most 33 bytes from fd until EOF. Returns a bytearray (caller wipes it).

    Exactly 32 bytes followed by EOF is the only accepted input; any other
    length is returned as-is and fails the descriptor_exact_32_bytes check.
    """
    try:
        if os.isatty(fd):
            raise Refusal("candidate_descriptor_is_terminal")
        os.fstat(fd)
    except Refusal:
        raise
    except Exception:
        raise Refusal("candidate_descriptor_unreadable") from None
    buffer = bytearray()
    try:
        while len(buffer) < 33:
            chunk = os.read(fd, 33 - len(buffer))
            if not chunk:
                break
            buffer += chunk
    except Exception:
        wipe(buffer)
        raise Refusal("candidate_descriptor_unreadable") from None
    finally:
        try:
            os.close(fd)
        except Exception:
            pass
    return buffer


def wipe(buffer):
    """Best-effort overwrite of a mutable buffer (Python cannot wipe int/bytes copies)."""
    if isinstance(buffer, bytearray):
        for index in range(len(buffer)):
            buffer[index] = 0


def check_candidate_fd(fd, target):
    self_test()
    buffer = read_candidate_fd(fd)
    try:
        return build_report(target, evaluate(buffer, target))
    finally:
        wipe(buffer)


# --------------------------------------------------------------------------
# Command-line discipline
# --------------------------------------------------------------------------

def parse_options(argv, value_options, flag_options):
    """Strict option parser. Returns a dict, or None on any unsupported argument.

    Unsupported arguments are never echoed: an operator may have pasted a
    secret onto the command line by mistake.
    """
    options = {}
    index = 0
    while index < len(argv):
        arg = argv[index]
        if not isinstance(arg, str):
            return None
        name, has_value, value = arg.partition("=")
        if arg in flag_options:
            name, value = arg, True
            index += 1
        elif arg in value_options:
            if index + 1 >= len(argv):
                return None
            name, value = arg, argv[index + 1]
            index += 2
        elif has_value and name in value_options:
            index += 1
        else:
            return None
        if name in options:
            return None
        options[name] = value
    return options


def _write_line(stream_fd, text):
    data = (text + "\n").encode("ascii", "replace")
    while data:
        written = os.write(stream_fd, data)
        data = data[written:]


def emit_json(value):
    _write_line(1, canonical_json(value))


def error_report(mode, code):
    return {
        "component": COMPONENT,
        "schema": SCHEMA,
        "mode": mode,
        "error": code if code in ERROR_CODES else "internal_error",
        "candidate_verified": False,
        "production_candidate_verified": False,
    }


def _silence_interpreter():
    def _quiet_hook(*_args):
        return None
    sys.excepthook = _quiet_hook
    try:
        sys.unraisablehook = _quiet_hook
    except Exception:
        pass
    sys.tracebacklimit = 0
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception:
        pass


def guarded_exit(mode, usage, body):
    """Run body() -> exit status under a handler that never prints exception content.

    Terminates the process with os._exit so no interpreter shutdown path can
    print a traceback, flush a half-written buffer or run foreign atexit hooks.
    """
    _silence_interpreter()
    status = EXIT_INTERNAL
    try:
        try:
            status = int(body())
        except Refusal as refusal:
            code, status = refusal.code, refusal.exit_status
            refusal = None
            emit_json(error_report(mode, code))
            if status == EXIT_USAGE:
                _write_line(2, usage)
        except BaseException:
            status = EXIT_INTERNAL
            emit_json(error_report(mode, "internal_error"))
    except BaseException:
        status = EXIT_INTERNAL
    try:
        sys.stdout.flush()
        sys.stderr.flush()
    except BaseException:
        pass
    os._exit(status if status in (0, 1, 2, 3) else EXIT_INTERNAL)
