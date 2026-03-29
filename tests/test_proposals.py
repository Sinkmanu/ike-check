"""Tests for IKEv2 and IKEv1 proposal builders."""

import struct

import pytest

from ike_check.ikev2.proposals import build_ike_sa_init
from ike_check.ikev1.proposals import build_ikev1_main_mode, build_ikev1_aggressive_mode
from ike_check.transforms import (
    DHGroupId,
    IKEv1AuthMethod,
    IKEv1EncrId,
    IKEv1HashId,
    IKEv2EncrId,
    IKEv2IntegId,
    IKEv2PrfId,
)


class TestIKEv2Proposals:
    def test_build_non_aead_proposal(self):
        """Build a standard AES-CBC proposal with integrity."""
        pkt_bytes, spi = build_ike_sa_init(
            "192.168.1.1",
            IKEv2EncrId.ENCR_AES_CBC, 256,
            IKEv2PrfId.PRF_HMAC_SHA2_256,
            IKEv2IntegId.AUTH_HMAC_SHA2_256_128,
            DHGroupId.MODP_2048,
        )
        assert len(pkt_bytes) > 28  # IKEv2 header is 28 bytes
        assert len(spi) == 8

        # Verify IKEv2 header fields directly
        assert pkt_bytes[:8] == spi               # initiator SPI
        assert pkt_bytes[8:16] == b"\x00" * 8     # responder SPI
        assert pkt_bytes[17] == 0x20               # version 2.0
        assert pkt_bytes[18] == 34                 # IKE_SA_INIT
        hdr_len = struct.unpack("!I", pkt_bytes[24:28])[0]
        assert hdr_len == len(pkt_bytes)           # length matches

    def test_build_aead_proposal(self):
        """Build an AES-GCM (AEAD) proposal."""
        pkt_bytes, spi = build_ike_sa_init(
            "10.0.0.1",
            IKEv2EncrId.ENCR_AES_GCM_16, 256,
            IKEv2PrfId.PRF_HMAC_SHA2_512,
            None,  # AEAD, no separate integrity
            DHGroupId.ECP_256,
        )
        assert len(pkt_bytes) > 28
        assert pkt_bytes[18] == 34  # IKE_SA_INIT

    def test_non_aead_requires_integrity(self):
        """Non-AEAD cipher must have an integrity algorithm."""
        with pytest.raises(ValueError, match="Non-AEAD encryption requires"):
            build_ike_sa_init(
                "10.0.0.1",
                IKEv2EncrId.ENCR_AES_CBC, 128,
                IKEv2PrfId.PRF_HMAC_SHA2_256,
                None,  # Missing integrity for non-AEAD
                DHGroupId.MODP_2048,
            )

    def test_unique_spis(self):
        """Each packet should have a unique initiator SPI."""
        _, spi1 = build_ike_sa_init(
            "10.0.0.1",
            IKEv2EncrId.ENCR_AES_CBC, 128,
            IKEv2PrfId.PRF_HMAC_SHA2_256,
            IKEv2IntegId.AUTH_HMAC_SHA2_256_128,
            DHGroupId.MODP_2048,
        )
        _, spi2 = build_ike_sa_init(
            "10.0.0.1",
            IKEv2EncrId.ENCR_AES_CBC, 128,
            IKEv2PrfId.PRF_HMAC_SHA2_256,
            IKEv2IntegId.AUTH_HMAC_SHA2_256_128,
            DHGroupId.MODP_2048,
        )
        assert spi1 != spi2

    def test_3des_no_key_length(self):
        """3DES doesn't use a key_length attribute."""
        pkt_bytes, spi = build_ike_sa_init(
            "10.0.0.1",
            IKEv2EncrId.ENCR_3DES, None,
            IKEv2PrfId.PRF_HMAC_SHA1,
            IKEv2IntegId.AUTH_HMAC_SHA1_96,
            DHGroupId.MODP_1024,
        )
        assert len(pkt_bytes) > 28

    def test_different_dh_groups_produce_different_ke_sizes(self):
        """KE payload size should match DH group requirements."""
        pkt1, _ = build_ike_sa_init(
            "10.0.0.1",
            IKEv2EncrId.ENCR_AES_CBC, 128,
            IKEv2PrfId.PRF_HMAC_SHA2_256,
            IKEv2IntegId.AUTH_HMAC_SHA2_256_128,
            DHGroupId.MODP_2048,  # 256 bytes KE
        )
        pkt2, _ = build_ike_sa_init(
            "10.0.0.1",
            IKEv2EncrId.ENCR_AES_CBC, 128,
            IKEv2PrfId.PRF_HMAC_SHA2_256,
            IKEv2IntegId.AUTH_HMAC_SHA2_256_128,
            DHGroupId.CURVE25519,  # 32 bytes KE
        )
        # MODP-2048 packet should be larger due to larger KE payload
        assert len(pkt1) > len(pkt2)


class TestIKEv1Proposals:
    def test_build_main_mode(self):
        """Build an IKEv1 Main Mode proposal."""
        pkt_bytes, cookie = build_ikev1_main_mode(
            "192.168.1.1",
            IKEv1EncrId.AES_CBC, 256,
            IKEv1HashId.SHA2_256,
            IKEv1AuthMethod.PSK,
            DHGroupId.MODP_2048,
        )
        assert len(pkt_bytes) > 28
        assert len(cookie) == 8

        # Verify ISAKMP header directly
        assert pkt_bytes[:8] == cookie
        exch_type = pkt_bytes[18]
        assert exch_type == 2  # Identity Protection (Main Mode)
        hdr_len = struct.unpack("!I", pkt_bytes[24:28])[0]
        assert hdr_len == len(pkt_bytes)

    def test_build_aggressive_mode(self):
        """Build an IKEv1 Aggressive Mode proposal."""
        pkt_bytes, cookie = build_ikev1_aggressive_mode(
            "192.168.1.1",
            IKEv1EncrId.AES_CBC, 128,
            IKEv1HashId.SHA1,
            IKEv1AuthMethod.PSK,
            DHGroupId.MODP_1024,
        )
        assert len(pkt_bytes) > 28

        # Verify ISAKMP header
        exch_type = pkt_bytes[18]
        assert exch_type == 4  # Aggressive

    def test_3des_main_mode(self):
        """3DES proposal in Main Mode."""
        pkt_bytes, cookie = build_ikev1_main_mode(
            "10.0.0.1",
            IKEv1EncrId.DES3_CBC, None,
            IKEv1HashId.SHA1,
            IKEv1AuthMethod.PSK,
            DHGroupId.MODP_1024,
        )
        assert len(pkt_bytes) > 28

    def test_unique_cookies(self):
        """Each packet should have a unique initiator cookie."""
        _, c1 = build_ikev1_main_mode(
            "10.0.0.1",
            IKEv1EncrId.AES_CBC, 128,
            IKEv1HashId.SHA2_256,
            IKEv1AuthMethod.PSK,
            DHGroupId.MODP_2048,
        )
        _, c2 = build_ikev1_main_mode(
            "10.0.0.1",
            IKEv1EncrId.AES_CBC, 128,
            IKEv1HashId.SHA2_256,
            IKEv1AuthMethod.PSK,
            DHGroupId.MODP_2048,
        )
        assert c1 != c2
