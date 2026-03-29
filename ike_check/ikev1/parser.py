"""Parse IKEv1 (ISAKMP) responses to determine proposal acceptance/rejection."""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass
from enum import Enum, auto

logger = logging.getLogger(__name__)


class IKEv1ResponseType(Enum):
    """Classification of an IKEv1 response."""

    SA_ACCEPTED = auto()
    NO_PROPOSAL_CHOSEN = auto()
    OTHER_NOTIFY = auto()
    MALFORMED = auto()


IKEV1_NOTIFY_NO_PROPOSAL_CHOSEN = 14

# ISAKMP next-payload type constants
_NP_SA = 1
_NP_NOTIFY = 11


@dataclass(frozen=True, slots=True)
class IKEv1Response:
    """Parsed IKEv1 response."""

    response_type: IKEv1ResponseType
    raw_notify_type: int | None = None


def parse_ikev1_response(data: bytes) -> IKEv1Response:
    """Parse raw bytes as an IKEv1 (ISAKMP) response and classify it.

    ISAKMP header (RFC 2408 §3.1) is 28 bytes:
      init_cookie(8) + resp_cookie(8) + next_payload(1) + version(1) +
      exch_type(1) + flags(1) + message_id(4) + length(4)
    """
    if len(data) < 28:
        logger.debug("Packet too short for ISAKMP header")
        return IKEv1Response(IKEv1ResponseType.MALFORMED)

    try:
        resp_cookie = data[8:16]
        next_payload = data[16]
        flags = data[19]

        # If encryption flag (bit 0) is set, we can't parse the payload
        # but an encrypted response means the exchange is continuing = accepted
        if flags & 0x01:
            return IKEv1Response(IKEv1ResponseType.SA_ACCEPTED)

        # Walk payloads
        offset = 28
        current_np = next_payload

        while current_np != 0 and offset + 4 <= len(data):
            np, _, payload_len = struct.unpack_from("!BBH", data, offset)

            if payload_len < 4 or offset + payload_len > len(data):
                break

            if current_np == _NP_SA:
                return IKEv1Response(IKEv1ResponseType.SA_ACCEPTED)

            if current_np == _NP_NOTIFY:
                return _parse_notify_payload(data, offset, payload_len)

            current_np = np
            offset += payload_len

        # If resp_cookie is non-zero and we got a response, it's likely
        # accepted (Aggressive Mode returns SA+KE+Nonce+ID)
        if resp_cookie != b"\x00" * 8:
            return IKEv1Response(IKEv1ResponseType.SA_ACCEPTED)

    except Exception:
        logger.debug("Error parsing ISAKMP packet")
        return IKEv1Response(IKEv1ResponseType.MALFORMED)

    return IKEv1Response(IKEv1ResponseType.MALFORMED)


def _parse_notify_payload(data: bytes, offset: int, payload_len: int) -> IKEv1Response:
    """Parse an ISAKMP Notify payload.

    Notify format (RFC 2408 §3.14):
      generic_header(4) + DOI(4) + proto(1) + SPI_size(1) + notify_type(2) + [SPI] + [data]
    """
    if payload_len < 12:
        return IKEv1Response(IKEv1ResponseType.MALFORMED)

    notify_type = struct.unpack_from("!H", data, offset + 10)[0]

    if notify_type == IKEV1_NOTIFY_NO_PROPOSAL_CHOSEN:
        return IKEv1Response(
            IKEv1ResponseType.NO_PROPOSAL_CHOSEN,
            raw_notify_type=notify_type,
        )

    return IKEv1Response(
        IKEv1ResponseType.OTHER_NOTIFY,
        raw_notify_type=notify_type,
    )
