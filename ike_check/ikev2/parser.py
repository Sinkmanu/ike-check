"""Parse IKEv2 responses to determine proposal acceptance/rejection."""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass
from enum import Enum, auto

from ..transforms import DHGroupId

logger = logging.getLogger(__name__)


class IKEv2ResponseType(Enum):
    """Classification of an IKEv2 response."""

    SA_ACCEPTED = auto()
    NO_PROPOSAL_CHOSEN = auto()
    INVALID_KE_PAYLOAD = auto()
    OTHER_NOTIFY = auto()
    MALFORMED = auto()


# IKEv2 Notify message types we care about
NOTIFY_NO_PROPOSAL_CHOSEN = 14
NOTIFY_INVALID_KE_PAYLOAD = 17

# IKEv2 payload type constants
_NP_SA = 33
_NP_NOTIFY = 41


@dataclass(frozen=True, slots=True)
class IKEv2Response:
    """Parsed IKEv2 response."""

    response_type: IKEv2ResponseType
    suggested_dh_group: DHGroupId | None = None
    raw_notify_type: int | None = None


def parse_ikev2_response(data: bytes) -> IKEv2Response:
    """Parse raw bytes as an IKEv2 response and classify it.

    Returns an IKEv2Response indicating whether the proposal was accepted,
    rejected, or if the peer suggests a different DH group.
    """
    # IKEv2 header is 28 bytes minimum
    if len(data) < 28:
        logger.debug("Packet too short for IKEv2 header")
        return IKEv2Response(IKEv2ResponseType.MALFORMED)

    try:
        next_payload = data[16]
        # Walk payloads looking for SA or Notify
        offset = 28  # start after IKEv2 header
        current_np = next_payload

        while current_np != 0 and offset + 4 <= len(data):
            # Generic payload header: next_payload(1) + critical(1) + length(2)
            np, _, payload_len = struct.unpack_from("!BBH", data, offset)

            if payload_len < 4 or offset + payload_len > len(data):
                break

            if current_np == _NP_SA:
                return IKEv2Response(IKEv2ResponseType.SA_ACCEPTED)

            if current_np == _NP_NOTIFY:
                return _parse_notify_payload(data, offset, payload_len)

            # Move to next payload
            current_np = np
            offset += payload_len

    except Exception:
        logger.debug("Error parsing IKEv2 packet")
        return IKEv2Response(IKEv2ResponseType.MALFORMED)

    return IKEv2Response(IKEv2ResponseType.MALFORMED)


def _parse_notify_payload(data: bytes, offset: int, payload_len: int) -> IKEv2Response:
    """Parse a Notify payload at the given offset.

    Notify format (RFC 7296 §3.10):
      generic_header(4) + proto(1) + SPI_size(1) + notify_type(2) + [SPI] + [data]
    """
    if payload_len < 8:
        return IKEv2Response(IKEv2ResponseType.MALFORMED)

    spi_size = data[offset + 5]
    notify_type = struct.unpack_from("!H", data, offset + 6)[0]

    if notify_type == NOTIFY_NO_PROPOSAL_CHOSEN:
        return IKEv2Response(
            IKEv2ResponseType.NO_PROPOSAL_CHOSEN,
            raw_notify_type=notify_type,
        )

    if notify_type == NOTIFY_INVALID_KE_PAYLOAD:
        suggested_dh = None
        # Notification data starts after header (8 bytes) + SPI
        notify_data_offset = offset + 8 + spi_size
        notify_data_len = payload_len - 8 - spi_size
        if notify_data_len >= 2:
            group_id = struct.unpack_from("!H", data, notify_data_offset)[0]
            try:
                suggested_dh = DHGroupId(group_id)
            except ValueError:
                logger.debug("Unknown DH group %d suggested by peer", group_id)
        return IKEv2Response(
            IKEv2ResponseType.INVALID_KE_PAYLOAD,
            suggested_dh_group=suggested_dh,
            raw_notify_type=notify_type,
        )

    return IKEv2Response(
        IKEv2ResponseType.OTHER_NOTIFY,
        raw_notify_type=notify_type,
    )
