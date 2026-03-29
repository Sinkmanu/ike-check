"""Tests for IKEv2 and IKEv1 response parsers."""

import os
import struct

import pytest

from ike_check.ikev2.parser import IKEv2ResponseType, parse_ikev2_response
from ike_check.ikev1.parser import IKEv1ResponseType, parse_ikev1_response
from ike_check.transforms import DHGroupId


def _ikev2_header(next_payload: int, flags: int = 0x20) -> bytes:
    """Build a minimal IKEv2 header (28 bytes). Length is set to 0 (caller patches)."""
    return struct.pack(
        "!8s8s BBB B I I",
        os.urandom(8),    # init SPI
        os.urandom(8),    # resp SPI
        next_payload,     # next payload
        0x20,             # version 2.0
        34,               # IKE_SA_INIT
        flags,            # flags (0x20 = Response)
        0,                # message ID
        0,                # length (patched later)
    )


def _patch_length(pkt: bytes) -> bytes:
    """Patch the total length field in an IKEv2/ISAKMP header."""
    return pkt[:24] + struct.pack("!I", len(pkt)) + pkt[28:]


def _isakmp_header(next_payload: int, exch_type: int = 2, flags: int = 0,
                    resp_cookie: bytes | None = None) -> bytes:
    """Build a minimal ISAKMP header (28 bytes)."""
    if resp_cookie is None:
        resp_cookie = b"\x00" * 8
    return struct.pack(
        "!8s8s BBB B I I",
        os.urandom(8),    # init cookie
        resp_cookie,      # resp cookie
        next_payload,     # next payload
        0x10,             # version 1.0
        exch_type,
        flags,
        0,                # message ID
        0,                # length (patched later)
    )


class TestIKEv2Parser:
    def _build_sa_response(self) -> bytes:
        """Build a simulated IKE_SA_INIT response with SA payload (accepted)."""
        # SA payload with minimal content (just needs to exist)
        # SA: header(4) + proposal header(8) + transform(8) = 20
        transform = struct.pack("!BBH BBH", 0, 0, 8, 1, 12, 0)  # ENCR AES-CBC
        proposal = struct.pack("!BBH BBBB", 0, 0, 16, 1, 1, 0, 1) + transform
        # SA payload: header(4) + proposal
        sa = struct.pack("!BBH", 34, 0, 4 + len(proposal)) + proposal  # next=KE(34)
        # KE payload
        ke_data = os.urandom(256)
        ke = struct.pack("!BBH HH", 40, 0, 8 + len(ke_data), 14, 0) + ke_data  # next=Nonce(40)
        # Nonce
        nonce_data = os.urandom(32)
        nonce = struct.pack("!BBH", 0, 0, 4 + len(nonce_data)) + nonce_data
        # Header
        hdr = _ikev2_header(33)  # next=SA(33)
        pkt = hdr + sa + ke + nonce
        return _patch_length(pkt)

    def _build_no_proposal_chosen(self) -> bytes:
        """Build a response with NO_PROPOSAL_CHOSEN notify."""
        # Notify: header(4) + proto(1) + SPI_size(1) + type(2) = 8
        notify = struct.pack("!BBH BBH", 0, 0, 8, 0, 0, 14)  # type=14
        hdr = _ikev2_header(41)  # next=Notify(41)
        pkt = hdr + notify
        return _patch_length(pkt)

    def _build_invalid_ke(self, suggested_group: int = 14) -> bytes:
        """Build a response with INVALID_KE_PAYLOAD notify suggesting a DH group."""
        notify_data = struct.pack("!H", suggested_group)
        # Notify: header(4) + proto(1) + SPI_size(1) + type(2) + data(2) = 10
        notify = struct.pack("!BBH BBH", 0, 0, 10, 0, 0, 17) + notify_data
        hdr = _ikev2_header(41)
        pkt = hdr + notify
        return _patch_length(pkt)

    def test_sa_accepted(self):
        data = self._build_sa_response()
        result = parse_ikev2_response(data)
        assert result.response_type == IKEv2ResponseType.SA_ACCEPTED

    def test_no_proposal_chosen(self):
        data = self._build_no_proposal_chosen()
        result = parse_ikev2_response(data)
        assert result.response_type == IKEv2ResponseType.NO_PROPOSAL_CHOSEN

    def test_invalid_ke_payload(self):
        data = self._build_invalid_ke(suggested_group=14)
        result = parse_ikev2_response(data)
        assert result.response_type == IKEv2ResponseType.INVALID_KE_PAYLOAD
        assert result.suggested_dh_group == DHGroupId.MODP_2048

    def test_invalid_ke_with_ecp(self):
        data = self._build_invalid_ke(suggested_group=19)
        result = parse_ikev2_response(data)
        assert result.response_type == IKEv2ResponseType.INVALID_KE_PAYLOAD
        assert result.suggested_dh_group == DHGroupId.ECP_256

    def test_malformed_data(self):
        result = parse_ikev2_response(b"\x00\x01\x02")
        assert result.response_type == IKEv2ResponseType.MALFORMED

    def test_empty_data(self):
        result = parse_ikev2_response(b"")
        assert result.response_type == IKEv2ResponseType.MALFORMED


class TestIKEv1Parser:
    def _build_sa_response(self) -> bytes:
        """Build a simulated IKEv1 SA response (accepted)."""
        # Transform: header(8) + 4 attrs × 4 bytes = 24
        attrs = (
            struct.pack("!HH", 0x8001, 7) +   # Encryption = AES-CBC
            struct.pack("!HH", 0x8002, 2) +   # Hash = SHA1
            struct.pack("!HH", 0x8003, 1) +   # Auth = PSK
            struct.pack("!HH", 0x8004, 14)    # DH Group 14
        )
        transform = struct.pack("!BBH BBH", 0, 0, 8 + len(attrs), 1, 1, 0) + attrs
        # Proposal: header(8) + transform
        proposal = struct.pack("!BBH BBBB", 0, 0, 8 + len(transform), 1, 1, 0, 1) + transform
        # SA: header(4) + DOI(4) + situation(4) + proposal
        sa = struct.pack("!BBH II", 0, 0, 12 + len(proposal), 1, 1) + proposal
        # ISAKMP header
        hdr = _isakmp_header(1, exch_type=2, resp_cookie=os.urandom(8))  # next=SA(1)
        pkt = hdr + sa
        return _patch_length(pkt)

    def _build_no_proposal_chosen(self) -> bytes:
        """Build an IKEv1 Informational response with NO-PROPOSAL-CHOSEN."""
        # Notify: header(4) + DOI(4) + proto(1) + SPI_size(1) + type(2) = 12
        notify = struct.pack("!BBH I BBH", 0, 0, 12, 1, 1, 0, 14)
        hdr = _isakmp_header(11, exch_type=5)  # next=Notify(11)
        pkt = hdr + notify
        return _patch_length(pkt)

    def test_sa_accepted(self):
        data = self._build_sa_response()
        result = parse_ikev1_response(data)
        assert result.response_type == IKEv1ResponseType.SA_ACCEPTED

    def test_no_proposal_chosen(self):
        data = self._build_no_proposal_chosen()
        result = parse_ikev1_response(data)
        assert result.response_type == IKEv1ResponseType.NO_PROPOSAL_CHOSEN

    def test_malformed_data(self):
        result = parse_ikev1_response(b"\x00\x01\x02")
        assert result.response_type == IKEv1ResponseType.MALFORMED

    def test_response_with_nonzero_resp_cookie(self):
        """Response with non-zero resp_cookie (aggressive mode) is accepted."""
        hdr = _isakmp_header(0, exch_type=4, resp_cookie=os.urandom(8))
        pkt = _patch_length(hdr)
        result = parse_ikev1_response(pkt)
        assert result.response_type == IKEv1ResponseType.SA_ACCEPTED
