"""Security classification for individual transforms and complete cipher suites."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto

from .transforms import (
    DH_GROUP_CATALOG,
    IKEV1_ENCR_CATALOG,
    IKEV1_HASH_CATALOG,
    IKEV2_ENCR_CATALOG,
    IKEV2_INTEG_CATALOG,
    IKEV2_PRF_CATALOG,
    DHGroupId,
    IKEv1EncrId,
    IKEv1HashId,
    IKEv1AuthMethod,
    IKEv2EncrId,
    IKEv2IntegId,
    IKEv2PrfId,
    SecurityLevel,
    TransformInfo,
)


class ProbeStatus(Enum):
    """Result of sending a single proposal probe."""

    ACCEPTED = auto()
    REJECTED = auto()
    TIMEOUT = auto()
    INVALID_KE = auto()  # IKEv2: wrong DH group, peer suggested another


@dataclass(frozen=True, slots=True)
class IKEv2ProposalResult:
    """Result of probing a single IKEv2 cipher suite."""

    encr_id: IKEv2EncrId
    encr_key_length: int | None
    prf_id: IKEv2PrfId
    integ_id: IKEv2IntegId | None  # None for AEAD
    dh_group: DHGroupId
    status: ProbeStatus
    suggested_dh: DHGroupId | None = None  # If INVALID_KE

    @property
    def encr_info(self) -> TransformInfo:
        return IKEV2_ENCR_CATALOG[self.encr_id][self.encr_key_length]

    @property
    def prf_info(self) -> TransformInfo:
        return IKEV2_PRF_CATALOG[self.prf_id]

    @property
    def integ_info(self) -> TransformInfo | None:
        if self.integ_id is None:
            return None
        return IKEV2_INTEG_CATALOG[self.integ_id]

    @property
    def dh_info(self) -> TransformInfo:
        return DH_GROUP_CATALOG[self.dh_group]

    @property
    def is_aead(self) -> bool:
        return self.encr_info.is_aead

    @property
    def security_level(self) -> SecurityLevel:
        """Overall security = minimum of all component levels."""
        levels = [
            self.encr_info.security,
            self.prf_info.security,
            self.dh_info.security,
        ]
        if self.integ_info is not None:
            levels.append(self.integ_info.security)
        return SecurityLevel(min(levels))

    @property
    def encr_name(self) -> str:
        return self.encr_info.name

    @property
    def integ_name(self) -> str:
        if self.is_aead:
            return "(implicit)"
        assert self.integ_info is not None
        return self.integ_info.name

    @property
    def prf_name(self) -> str:
        return self.prf_info.name

    @property
    def dh_name(self) -> str:
        return self.dh_info.name


@dataclass(frozen=True, slots=True)
class IKEv1ProposalResult:
    """Result of probing a single IKEv1 cipher suite."""

    encr_id: IKEv1EncrId
    encr_key_length: int | None
    hash_id: IKEv1HashId
    auth_method: IKEv1AuthMethod
    dh_group: DHGroupId
    status: ProbeStatus
    mode: str = "main"  # "main" or "aggressive"

    @property
    def encr_info(self) -> TransformInfo:
        return IKEV1_ENCR_CATALOG[self.encr_id][self.encr_key_length]

    @property
    def hash_info(self) -> TransformInfo:
        return IKEV1_HASH_CATALOG[self.hash_id]

    @property
    def dh_info(self) -> TransformInfo:
        return DH_GROUP_CATALOG[self.dh_group]

    @property
    def security_level(self) -> SecurityLevel:
        levels = [
            self.encr_info.security,
            self.hash_info.security,
            self.dh_info.security,
        ]
        return SecurityLevel(min(levels))

    @property
    def encr_name(self) -> str:
        return self.encr_info.name

    @property
    def hash_name(self) -> str:
        return self.hash_info.name

    @property
    def dh_name(self) -> str:
        return self.dh_info.name


def classify_suite_level(results: list[IKEv2ProposalResult | IKEv1ProposalResult]) -> dict[SecurityLevel, int]:
    """Count accepted suites by security level."""
    counts: dict[SecurityLevel, int] = {level: 0 for level in SecurityLevel}
    for r in results:
        if r.status == ProbeStatus.ACCEPTED:
            counts[r.security_level] += 1
    return counts
