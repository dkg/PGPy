# coding=utf-8
""" test doing things with keys/signatures/etc
"""
import pytest

from pgpy import PGPKey, PGPUID
from pgpy.constants import PubKeyAlgorithm, KeyFlags, EllipticCurveOID, SecurityIssues

class TestSelfSigs:
    def test_verify_self_sigs(self) -> None:
        key = PGPKey.new(PubKeyAlgorithm.EdDSA, EllipticCurveOID.Ed25519)
        keyflags = KeyFlags.Certify|KeyFlags.Sign
        # direct key signature:
        key |= key.certify(key, usage=keyflags)
        # add userid:
        key.add_uid(PGPUID.new('Test User <test@example.org>'), usage=keyflags)
        assert key.self_verify() == SecurityIssues.OK
