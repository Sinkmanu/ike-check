"""Tests for the classifier module."""

import pytest

from ike_check.classifier import (
    IKEv1ProposalResult,
    IKEv2ProposalResult,
    ProbeStatus,
    classify_suite_level,
)
from ike_check.transforms import (
    DHGroupId,
    IKEv1AuthMethod,
    IKEv1EncrId,
    IKEv1HashId,
    IKEv2EncrId,
    IKEv2IntegId,
    IKEv2PrfId,
    SecurityLevel,
)


class TestIKEv2ProposalResult:
    def test_strong_suite(self):
        r = IKEv2ProposalResult(
            encr_id=IKEv2EncrId.ENCR_AES_CBC,
            encr_key_length=256,
            prf_id=IKEv2PrfId.PRF_HMAC_SHA2_256,
            integ_id=IKEv2IntegId.AUTH_HMAC_SHA2_256_128,
            dh_group=DHGroupId.ECP_256,
            status=ProbeStatus.ACCEPTED,
        )
        assert r.security_level == SecurityLevel.STRONG
        assert r.encr_name == "AES-CBC-256"
        assert r.integ_name == "HMAC-SHA2-256"
        assert r.prf_name == "PRF-SHA2-256"
        assert r.dh_name == "ECP-256"

    def test_weak_suite_inherits_lowest(self):
        """Suite with SHA1 should be WEAK even if everything else is STRONG."""
        r = IKEv2ProposalResult(
            encr_id=IKEv2EncrId.ENCR_AES_CBC,
            encr_key_length=256,
            prf_id=IKEv2PrfId.PRF_HMAC_SHA1,  # WEAK
            integ_id=IKEv2IntegId.AUTH_HMAC_SHA2_256_128,
            dh_group=DHGroupId.ECP_256,
            status=ProbeStatus.ACCEPTED,
        )
        assert r.security_level == SecurityLevel.WEAK

    def test_insecure_dh_makes_suite_insecure(self):
        r = IKEv2ProposalResult(
            encr_id=IKEv2EncrId.ENCR_AES_CBC,
            encr_key_length=256,
            prf_id=IKEv2PrfId.PRF_HMAC_SHA2_256,
            integ_id=IKEv2IntegId.AUTH_HMAC_SHA2_256_128,
            dh_group=DHGroupId.MODP_768,  # INSECURE
            status=ProbeStatus.ACCEPTED,
        )
        assert r.security_level == SecurityLevel.INSECURE

    def test_aead_suite(self):
        r = IKEv2ProposalResult(
            encr_id=IKEv2EncrId.ENCR_AES_GCM_16,
            encr_key_length=256,
            prf_id=IKEv2PrfId.PRF_HMAC_SHA2_512,
            integ_id=None,  # AEAD
            dh_group=DHGroupId.CURVE25519,
            status=ProbeStatus.ACCEPTED,
        )
        assert r.is_aead is True
        assert r.integ_name == "(implicit)"
        assert r.security_level == SecurityLevel.STRONG

    def test_ok_level_suite(self):
        r = IKEv2ProposalResult(
            encr_id=IKEv2EncrId.ENCR_AES_CBC,
            encr_key_length=128,  # OK
            prf_id=IKEv2PrfId.PRF_HMAC_SHA2_256,
            integ_id=IKEv2IntegId.AUTH_HMAC_SHA2_256_128,
            dh_group=DHGroupId.MODP_2048,  # OK
            status=ProbeStatus.ACCEPTED,
        )
        assert r.security_level == SecurityLevel.OK


class TestIKEv1ProposalResult:
    def test_strong_ikev1_suite(self):
        r = IKEv1ProposalResult(
            encr_id=IKEv1EncrId.AES_CBC,
            encr_key_length=256,
            hash_id=IKEv1HashId.SHA2_256,
            auth_method=IKEv1AuthMethod.RSA_SIG,
            dh_group=DHGroupId.ECP_256,
            status=ProbeStatus.ACCEPTED,
        )
        assert r.security_level == SecurityLevel.STRONG
        assert r.encr_name == "AES-CBC-256"
        assert r.hash_name == "SHA2-256"

    def test_insecure_des_suite(self):
        r = IKEv1ProposalResult(
            encr_id=IKEv1EncrId.DES_CBC,
            encr_key_length=None,
            hash_id=IKEv1HashId.MD5,
            auth_method=IKEv1AuthMethod.PSK,
            dh_group=DHGroupId.MODP_768,
            status=ProbeStatus.ACCEPTED,
        )
        assert r.security_level == SecurityLevel.INSECURE


class TestClassifySuiteLevel:
    def test_counts_accepted_only(self):
        results = [
            IKEv2ProposalResult(
                encr_id=IKEv2EncrId.ENCR_AES_GCM_16,
                encr_key_length=256,
                prf_id=IKEv2PrfId.PRF_HMAC_SHA2_256,
                integ_id=None,
                dh_group=DHGroupId.ECP_256,
                status=ProbeStatus.ACCEPTED,
            ),
            IKEv2ProposalResult(
                encr_id=IKEv2EncrId.ENCR_3DES,
                encr_key_length=None,
                prf_id=IKEv2PrfId.PRF_HMAC_SHA1,
                integ_id=IKEv2IntegId.AUTH_HMAC_SHA1_96,
                dh_group=DHGroupId.MODP_1024,
                status=ProbeStatus.ACCEPTED,
            ),
            IKEv2ProposalResult(
                encr_id=IKEv2EncrId.ENCR_AES_CBC,
                encr_key_length=256,
                prf_id=IKEv2PrfId.PRF_HMAC_SHA2_256,
                integ_id=IKEv2IntegId.AUTH_HMAC_SHA2_256_128,
                dh_group=DHGroupId.ECP_256,
                status=ProbeStatus.REJECTED,  # Not counted
            ),
        ]
        counts = classify_suite_level(results)
        assert counts[SecurityLevel.STRONG] == 1
        assert counts[SecurityLevel.INSECURE] == 1
        assert counts[SecurityLevel.WEAK] == 0
        assert counts[SecurityLevel.OK] == 0

    def test_empty_results(self):
        counts = classify_suite_level([])
        assert all(v == 0 for v in counts.values())
