"""Build IKEv2 IKE_SA_INIT packets with individual cipher suite proposals."""

from __future__ import annotations

import os
import struct

from ..transforms import (
    DH_KE_SIZES,
    IKEV2_ENCR_CATALOG,
    IKEV2_KEY_LENGTH_ATTR,
    DHGroupId,
    IKEv2EncrId,
    IKEv2IntegId,
    IKEv2PrfId,
    IKEv2TransformType,
)

# IKEv2 next-payload type constants
_NP_SA = 33
_NP_KE = 34
_NP_NONCE = 40
_NP_NONE = 0

# Transform sub-structure next-payload: 3 = more transforms, 0 = last
_T_MORE = 3
_T_LAST = 0


def _encode_transform(
    transform_type: int,
    transform_id: int,
    key_length: int | None = None,
    is_last: bool = False,
) -> bytes:
    """Encode a single IKEv2 Transform as raw bytes (RFC 7296 §3.3.2)."""
    # Transform header: next(1) + reserved(1) + length(2) +
    #                   type(1) + reserved(1) + id(2)  = 8 bytes
    has_attr = key_length is not None
    t_len = 8 + (4 if has_attr else 0)
    hdr = struct.pack(
        "!BBH BBH",
        _T_LAST if is_last else _T_MORE,  # next payload
        0,                                 # reserved
        t_len,                             # length
        transform_type,                    # type
        0,                                 # reserved
        transform_id,                      # id
    )
    if has_attr:
        # Key Length attribute: TV format (bit 15 set), type 14
        attr = struct.pack("!HH", 0x8000 | IKEV2_KEY_LENGTH_ATTR, key_length)
        return hdr + attr
    return hdr


def _generate_ke_data(dh_group: DHGroupId) -> bytes:
    """Generate key exchange data of the correct size for the DH group.

    For probing purposes we use random bytes (we don't need to complete
    the handshake, just get the peer's response to our proposal).
    """
    size = DH_KE_SIZES.get(dh_group, 256)
    return os.urandom(size)


def _encode_generic_header(next_payload: int, length: int) -> bytes:
    """Encode a generic IKEv2 payload header (4 bytes)."""
    return struct.pack("!BBH", next_payload, 0, length)


def build_ike_sa_init(
    target_ip: str,
    encr_id: IKEv2EncrId,
    encr_key_length: int | None,
    prf_id: IKEv2PrfId,
    integ_id: IKEv2IntegId | None,
    dh_group: DHGroupId,
    source_ip: str | None = None,
) -> tuple[bytes, bytes]:
    """Build a complete IKE_SA_INIT packet with a single proposal.

    Constructs the packet as raw bytes to avoid scapy payload-chaining
    issues that corrupt transform attributes.

    Returns (packet_bytes, initiator_spi) for tracking.
    """
    init_spi = os.urandom(8)

    # --- Build transforms as raw bytes ---
    transform_blobs: list[bytes] = []

    # 1) Encryption
    transform_blobs.append(_encode_transform(
        IKEv2TransformType.ENCR, encr_id.value, encr_key_length,
    ))

    # 2) PRF
    transform_blobs.append(_encode_transform(
        IKEv2TransformType.PRF, prf_id.value,
    ))

    # 3) Integrity
    encr_info = IKEV2_ENCR_CATALOG[encr_id][encr_key_length]
    if not encr_info.is_aead:
        if integ_id is None:
            raise ValueError("Non-AEAD encryption requires an integrity algorithm")
        transform_blobs.append(_encode_transform(
            IKEv2TransformType.INTEG, integ_id.value,
        ))
    else:
        # AEAD: NONE integrity
        transform_blobs.append(_encode_transform(
            IKEv2TransformType.INTEG, 0,
        ))

    # 4) DH group (last transform)
    transform_blobs.append(_encode_transform(
        IKEv2TransformType.DH, dh_group.value, is_last=True,
    ))

    # Mark last transform
    for i in range(len(transform_blobs) - 1):
        # next_payload byte is already _T_MORE (set in _encode_transform)
        pass
    # Last one already has _T_LAST

    transforms_data = b"".join(transform_blobs)
    num_transforms = len(transform_blobs)

    # --- Proposal payload (RFC 7296 §3.3.1) ---
    # Header: next(1) + reserved(1) + length(2) +
    #         proposal#(1) + proto(1) + SPI_size(1) + num_transforms(1)
    proposal_len = 8 + len(transforms_data)
    proposal = struct.pack(
        "!BBH BBBB",
        0,                  # next payload (0 = last proposal)
        0,                  # reserved
        proposal_len,       # length
        1,                  # proposal number
        1,                  # protocol ID (1 = IKE)
        0,                  # SPI size (0 for IKE SA)
        num_transforms,     # number of transforms
    ) + transforms_data

    # --- SA payload ---
    sa_len = 4 + len(proposal)  # generic header (4) + proposal(s)
    sa_payload = _encode_generic_header(_NP_KE, sa_len) + proposal

    # --- KE payload (RFC 7296 §3.4) ---
    ke_data = _generate_ke_data(dh_group)
    # Header(4) + DH group(2) + reserved(2) + KE data
    ke_len = 4 + 2 + 2 + len(ke_data)
    ke_payload = _encode_generic_header(_NP_NONCE, ke_len) + struct.pack(
        "!HH", dh_group.value, 0,
    ) + ke_data

    # --- Nonce payload (RFC 7296 §3.9) ---
    nonce_data = os.urandom(32)
    nonce_len = 4 + len(nonce_data)
    nonce_payload = _encode_generic_header(_NP_NONE, nonce_len) + nonce_data

    # --- IKEv2 header (RFC 7296 §3.1) ---
    # SPI_i(8) + SPI_r(8) + next_payload(1) + version(1) + exch_type(1) +
    # flags(1) + message_id(4) + length(4) = 28 bytes
    total_len = 28 + len(sa_payload) + len(ke_payload) + len(nonce_payload)
    ike_header = struct.pack(
        "!8s8s BBB B I I",
        init_spi,           # initiator SPI
        b"\x00" * 8,        # responder SPI
        _NP_SA,             # next payload = SA
        0x20,               # version: major=2, minor=0
        34,                 # exchange type: IKE_SA_INIT
        0x08,               # flags: Initiator
        0,                  # message ID
        total_len,          # total length
    )

    pkt = ike_header + sa_payload + ke_payload + nonce_payload
    return pkt, init_spi


def build_ike_sa_init_proposals(
    target_ip: str,
    proposals: list[tuple[IKEv2EncrId, int | None, IKEv2PrfId, IKEv2IntegId | None, DHGroupId]],
    source_ip: str | None = None,
) -> list[tuple[bytes, bytes, tuple]]:
    """Build multiple IKE_SA_INIT packets, one per proposal.

    Returns list of (packet_bytes, initiator_spi, proposal_tuple).
    """
    results = []
    for encr_id, encr_kl, prf_id, integ_id, dh_group in proposals:
        pkt_bytes, spi = build_ike_sa_init(
            target_ip, encr_id, encr_kl, prf_id, integ_id, dh_group, source_ip,
        )
        results.append((pkt_bytes, spi, (encr_id, encr_kl, prf_id, integ_id, dh_group)))
    return results
