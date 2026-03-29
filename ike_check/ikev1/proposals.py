"""Build IKEv1 (ISAKMP) Phase 1 proposals for Main Mode and Aggressive Mode."""

from __future__ import annotations

import os
import struct

from ..transforms import (
    DH_KE_SIZES,
    DHGroupId,
    IKEv1AuthMethod,
    IKEv1EncrId,
    IKEv1HashId,
    ISAKMPAttr,
)

# ISAKMP next-payload type constants
_NP_SA = 1
_NP_KE = 4
_NP_ID = 5
_NP_NONCE = 10
_NP_NONE = 0


def _encode_sa_attributes(
    encr_id: IKEv1EncrId,
    encr_key_length: int | None,
    hash_id: IKEv1HashId,
    auth_method: IKEv1AuthMethod,
    dh_group: DHGroupId,
) -> bytes:
    """Encode IKEv1 SA attributes as TV-format bytes."""
    attrs = [
        (ISAKMPAttr.ENCRYPTION, encr_id.value),
        (ISAKMPAttr.HASH, hash_id.value),
        (ISAKMPAttr.AUTH_METHOD, auth_method.value),
        (ISAKMPAttr.GROUP_DESC, dh_group.value),
    ]
    if encr_key_length is not None:
        attrs.append((ISAKMPAttr.KEY_LENGTH, encr_key_length))

    result = b""
    for attr_type, attr_value in attrs:
        result += struct.pack("!HH", 0x8000 | attr_type, attr_value)
    return result


def _encode_generic_header(next_payload: int, length: int) -> bytes:
    """Encode a generic ISAKMP payload header (4 bytes)."""
    return struct.pack("!BBH", next_payload, 0, length)


def _build_sa_payload(
    next_payload: int,
    encr_id: IKEv1EncrId,
    encr_key_length: int | None,
    hash_id: IKEv1HashId,
    auth_method: IKEv1AuthMethod,
    dh_group: DHGroupId,
) -> bytes:
    """Build an ISAKMP SA payload with a single proposal and transform.

    SA payload (RFC 2408):
      generic_header(4) + DOI(4) + situation(4) + proposal(s)

    Proposal payload:
      generic_header(4) + proposal#(1) + proto(1) + SPI_size(1) +
      num_transforms(1) + transform(s)

    Transform payload:
      generic_header(4) + transform#(1) + transform_id(1) + reserved(2) +
      SA attributes
    """
    # SA attributes
    attr_bytes = _encode_sa_attributes(
        encr_id, encr_key_length, hash_id, auth_method, dh_group,
    )

    # Transform payload: header(4) + transform#(1) + id(1) + reserved(2) + attrs
    transform_len = 8 + len(attr_bytes)
    transform = struct.pack(
        "!BBH BBH",
        _NP_NONE,        # next payload (last transform)
        0,               # reserved
        transform_len,   # length
        1,               # transform number
        1,               # transform ID = KEY_IKE
        0,               # reserved
    ) + attr_bytes

    # Proposal payload: header(4) + proposal#(1) + proto(1) + SPI_size(1) +
    #                   num_transforms(1) + transforms
    proposal_len = 8 + len(transform)
    proposal = struct.pack(
        "!BBH BBBB",
        _NP_NONE,   # next payload (last proposal)
        0,          # reserved
        proposal_len,
        1,          # proposal number
        1,          # protocol ID = ISAKMP
        0,          # SPI size
        1,          # number of transforms
    ) + transform

    # SA payload: header(4) + DOI(4) + situation(4) + proposals
    sa_len = 12 + len(proposal)
    sa = struct.pack(
        "!BBH II",
        next_payload,  # next payload
        0,             # reserved
        sa_len,        # length
        1,             # DOI = IPSEC
        1,             # situation = Identity Only
    ) + proposal

    return sa


def build_ikev1_main_mode(
    target_ip: str,
    encr_id: IKEv1EncrId,
    encr_key_length: int | None,
    hash_id: IKEv1HashId,
    auth_method: IKEv1AuthMethod,
    dh_group: DHGroupId,
    source_ip: str | None = None,
) -> tuple[bytes, bytes]:
    """Build an IKEv1 Main Mode (Identity Protection) SA proposal.

    Returns (packet_bytes, initiator_cookie).
    """
    init_cookie = os.urandom(8)

    sa_payload = _build_sa_payload(
        _NP_NONE, encr_id, encr_key_length, hash_id, auth_method, dh_group,
    )

    # ISAKMP header: init_cookie(8) + resp_cookie(8) + next_payload(1) +
    #                version(1) + exch_type(1) + flags(1) + msg_id(4) + length(4)
    total_len = 28 + len(sa_payload)
    header = struct.pack(
        "!8s8s BBB B I I",
        init_cookie,
        b"\x00" * 8,
        _NP_SA,    # next payload = SA
        0x10,      # version: major=1, minor=0
        2,         # exchange type: Identity Protection (Main Mode)
        0,         # flags
        0,         # message ID
        total_len,
    )

    return header + sa_payload, init_cookie


def build_ikev1_aggressive_mode(
    target_ip: str,
    encr_id: IKEv1EncrId,
    encr_key_length: int | None,
    hash_id: IKEv1HashId,
    auth_method: IKEv1AuthMethod,
    dh_group: DHGroupId,
    source_ip: str | None = None,
) -> tuple[bytes, bytes]:
    """Build an IKEv1 Aggressive Mode proposal.

    Aggressive mode sends SA + KE + Nonce + ID in the first packet.
    Returns (packet_bytes, initiator_cookie).
    """
    init_cookie = os.urandom(8)

    # SA payload (next = KE)
    sa_payload = _build_sa_payload(
        _NP_KE, encr_id, encr_key_length, hash_id, auth_method, dh_group,
    )

    # KE payload: header(4) + KE data
    ke_size = DH_KE_SIZES.get(dh_group, 256)
    ke_data = os.urandom(ke_size)
    ke_len = 4 + len(ke_data)
    ke_payload = _encode_generic_header(_NP_NONCE, ke_len) + ke_data

    # Nonce payload: header(4) + nonce data
    nonce_data = os.urandom(20)
    nonce_len = 4 + len(nonce_data)
    nonce_payload = _encode_generic_header(_NP_ID, nonce_len) + nonce_data

    # ID payload: header(4) + id_type(1) + proto(1) + port(2) + IP(4) = 12 bytes
    id_payload = struct.pack(
        "!BBH BBHI",
        _NP_NONE,  # next payload (last)
        0,         # reserved
        12,        # length
        1,         # ID type = ID_IPV4_ADDR
        17,        # protocol = UDP
        500,       # port
        0,         # IP = 0.0.0.0
    )

    # ISAKMP header
    total_len = 28 + len(sa_payload) + len(ke_payload) + len(nonce_payload) + len(id_payload)
    header = struct.pack(
        "!8s8s BBB B I I",
        init_cookie,
        b"\x00" * 8,
        _NP_SA,    # next payload = SA
        0x10,      # version: major=1, minor=0
        4,         # exchange type: Aggressive
        0,         # flags
        0,         # message ID
        total_len,
    )

    return header + sa_payload + ke_payload + nonce_payload + id_payload, init_cookie
