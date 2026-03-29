"""Main scanning orchestration for IKE cipher suite enumeration."""

from __future__ import annotations

import logging
import os
import socket
import time
from dataclasses import dataclass, field
from itertools import product

from .classifier import IKEv1ProposalResult, IKEv2ProposalResult, ProbeStatus
from .ikev1.parser import IKEv1ResponseType, parse_ikev1_response
from .ikev1.proposals import build_ikev1_aggressive_mode, build_ikev1_main_mode
from .ikev2.parser import IKEv2ResponseType, parse_ikev2_response
from .transforms import (
    FULL_AEAD_PRFS,
    FULL_DH_GROUPS,
    FULL_ENCR_IDS,
    FULL_HASH_PAIRS,
    FULL_IKEV1_AUTH,
    FULL_IKEV1_DH,
    FULL_IKEV1_ENCR,
    FULL_IKEV1_HASH,
    IKEV2_ENCR_CATALOG,
    MVP_AEAD_PRFS,
    MVP_DH_GROUPS,
    MVP_ENCR_IDS,
    MVP_HASH_PAIRS,
    MVP_IKEV1_AUTH,
    MVP_IKEV1_DH,
    MVP_IKEV1_ENCR,
    MVP_IKEV1_HASH,
    WEAK_AEAD_PRFS,
    WEAK_DH_GROUPS,
    WEAK_ENCR_IDS,
    WEAK_HASH_PAIRS,
    WEAK_IKEV1_DH,
    WEAK_IKEV1_ENCR,
    WEAK_IKEV1_HASH,
    DHGroupId,
    IKEv1AuthMethod,
    IKEv1EncrId,
    IKEv1HashId,
    IKEv2EncrId,
    IKEv2IntegId,
    IKEv2PrfId,
)

logger = logging.getLogger(__name__)


@dataclass
class ScanConfig:
    """Configuration for a scan session."""

    target_ip: str
    port: int = 500
    timeout: float = 5.0
    retries: int = 2
    delay: float = 0.5
    quick: bool = False
    source_ip: str | None = None
    ike_version: str = "both"  # "ikev1", "ikev2", "both"
    aggressive: bool = False
    nat_traversal: bool = False
    dh_sweep: bool = True
    verbose: bool = False
    weak_only: bool = False


@dataclass
class ScanResults:
    """Aggregated results of a scan session."""

    target_ip: str
    port: int
    ike_version: str
    start_time: float = 0.0
    end_time: float = 0.0
    ikev2_results: list[IKEv2ProposalResult] = field(default_factory=list)
    ikev1_results: list[IKEv1ProposalResult] = field(default_factory=list)
    total_probes: int = 0
    timeout_count: int = 0

    @property
    def duration_seconds(self) -> float:
        return self.end_time - self.start_time


def _send_receive_udp(
    data: bytes,
    target_ip: str,
    port: int,
    timeout: float,
    source_ip: str | None = None,
) -> bytes | None:
    """Send UDP packet and wait for response."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        if source_ip:
            sock.bind((source_ip, 0))
        sock.sendto(data, (target_ip, port))
        try:
            response, _ = sock.recvfrom(65535)
            return response
        except socket.timeout:
            return None
    except OSError as e:
        logger.error("Socket error: %s", e)
        return None
    finally:
        sock.close()


def _send_with_retries(
    data: bytes,
    target_ip: str,
    port: int,
    timeout: float,
    retries: int,
    source_ip: str | None = None,
) -> bytes | None:
    """Send packet with retries on timeout."""
    for attempt in range(1 + retries):
        response = _send_receive_udp(data, target_ip, port, timeout, source_ip)
        if response is not None:
            return response
        if attempt < retries:
            logger.debug("Timeout, retrying (%d/%d)", attempt + 1, retries)
    return None


class Scanner:
    """IKE cipher suite scanner."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self._consecutive_timeouts = 0
        self._adaptive_delay = config.delay

    def scan(self, progress_callback=None) -> ScanResults:
        """Run the full scan and return results."""
        results = ScanResults(
            target_ip=self.config.target_ip,
            port=self.config.port,
            ike_version=self.config.ike_version,
            start_time=time.time(),
        )

        if self.config.ike_version in ("ikev2", "both"):
            self._scan_ikev2(results, progress_callback)

        if self.config.ike_version in ("ikev1", "both"):
            self._scan_ikev1(results, progress_callback)

        if self.config.nat_traversal:
            # Re-scan on port 4500 with Non-ESP marker
            orig_port = self.config.port
            self.config.port = 4500
            if self.config.ike_version in ("ikev2", "both"):
                self._scan_ikev2(results, progress_callback)
            if self.config.ike_version in ("ikev1", "both"):
                self._scan_ikev1(results, progress_callback)
            self.config.port = orig_port

        results.end_time = time.time()
        return results

    def _scan_ikev2(self, results: ScanResults, progress_callback=None) -> None:
        """Scan IKEv2 cipher suites."""
        from .ikev2.proposals import build_ike_sa_init

        if self.config.weak_only:
            encr_list = WEAK_ENCR_IDS
            hash_pairs = WEAK_HASH_PAIRS
            aead_prfs = WEAK_AEAD_PRFS
            dh_list = WEAK_DH_GROUPS
        elif self.config.quick:
            encr_list = MVP_ENCR_IDS
            hash_pairs = MVP_HASH_PAIRS
            aead_prfs = MVP_AEAD_PRFS
            dh_list = MVP_DH_GROUPS
        else:
            encr_list = FULL_ENCR_IDS
            hash_pairs = FULL_HASH_PAIRS
            aead_prfs = FULL_AEAD_PRFS
            dh_list = FULL_DH_GROUPS

        # Phase 1 optimization: sweep DH groups first
        if self.config.dh_sweep:
            accepted_dh = self._sweep_dh_groups_ikev2(dh_list, progress_callback)
            if not accepted_dh:
                logger.warning("No DH groups accepted by peer, trying all groups anyway")
                accepted_dh = dh_list
        else:
            accepted_dh = dh_list

        # Generate all proposals
        proposals = self._generate_ikev2_proposals(encr_list, hash_pairs, aead_prfs, accepted_dh)
        total = len(proposals)

        for i, (encr_id, encr_kl, prf_id, integ_id, dh_group) in enumerate(proposals):
            if progress_callback:
                progress_callback("ikev2", i + 1, total)

            try:
                pkt_bytes, spi = build_ike_sa_init(
                    self.config.target_ip,
                    encr_id, encr_kl, prf_id, integ_id, dh_group,
                    self.config.source_ip,
                )
            except Exception as e:
                logger.debug("Failed to build proposal: %s", e)
                continue

            port = self.config.port
            if self.config.nat_traversal and port == 4500:
                # Non-ESP marker (4 bytes of zeros) prepended
                pkt_bytes = b"\x00\x00\x00\x00" + pkt_bytes

            response = _send_with_retries(
                pkt_bytes, self.config.target_ip, port,
                self.config.timeout, self.config.retries,
                self.config.source_ip,
            )

            results.total_probes += 1

            if response is None:
                self._handle_timeout()
                result = IKEv2ProposalResult(
                    encr_id=encr_id, encr_key_length=encr_kl,
                    prf_id=prf_id, integ_id=integ_id,
                    dh_group=dh_group, status=ProbeStatus.TIMEOUT,
                )
                results.timeout_count += 1
            else:
                self._consecutive_timeouts = 0
                # Strip Non-ESP marker if present
                if port == 4500 and response[:4] == b"\x00\x00\x00\x00":
                    response = response[4:]
                parsed = parse_ikev2_response(response)
                status = self._map_ikev2_response(parsed)
                suggested_dh = parsed.suggested_dh_group if parsed.response_type == IKEv2ResponseType.INVALID_KE_PAYLOAD else None
                result = IKEv2ProposalResult(
                    encr_id=encr_id, encr_key_length=encr_kl,
                    prf_id=prf_id, integ_id=integ_id,
                    dh_group=dh_group, status=status,
                    suggested_dh=suggested_dh,
                )

            results.ikev2_results.append(result)

            if self._adaptive_delay > 0:
                time.sleep(self._adaptive_delay)

    # Probe ciphers used during the DH group sweep.  We try several common
    # suites so that a DH group isn't falsely discarded just because the
    # single probe cipher wasn't accepted with it.
    _DH_SWEEP_PROBES: list[tuple[IKEv2EncrId, int, IKEv2PrfId, IKEv2IntegId]] = [
        (IKEv2EncrId.ENCR_AES_CBC, 256, IKEv2PrfId.PRF_HMAC_SHA2_256, IKEv2IntegId.AUTH_HMAC_SHA2_256_128),
        (IKEv2EncrId.ENCR_AES_CBC, 128, IKEv2PrfId.PRF_HMAC_SHA1, IKEv2IntegId.AUTH_HMAC_SHA1_96),
        (IKEv2EncrId.ENCR_AES_CBC, 128, IKEv2PrfId.PRF_HMAC_SHA2_256, IKEv2IntegId.AUTH_HMAC_SHA2_256_128),
    ]

    def _sweep_dh_groups_ikev2(self, dh_groups: list[DHGroupId], progress_callback=None) -> list[DHGroupId]:
        """Quick sweep to find which DH groups the peer accepts.

        Tries multiple common cipher suites per DH group to avoid false
        negatives when the peer only accepts specific cipher+DH combinations.
        """
        from .ikev2.proposals import build_ike_sa_init

        total = len(dh_groups)
        accepted = []
        for idx, dh in enumerate(dh_groups):
            if progress_callback:
                progress_callback("ikev2_dh_sweep", idx + 1, total)
            found = False
            for encr_id, encr_kl, prf_id, integ_id in self._DH_SWEEP_PROBES:
                try:
                    pkt_bytes, _ = build_ike_sa_init(
                        self.config.target_ip,
                        encr_id, encr_kl, prf_id, integ_id,
                        dh, self.config.source_ip,
                    )
                except Exception:
                    continue

                response = _send_with_retries(
                    pkt_bytes, self.config.target_ip, self.config.port,
                    self.config.timeout, self.config.retries,
                    self.config.source_ip,
                )

                if response is not None:
                    parsed = parse_ikev2_response(response)
                    if parsed.response_type == IKEv2ResponseType.SA_ACCEPTED:
                        accepted.append(dh)
                        logger.debug("DH group %s accepted", dh.name)
                        found = True
                        break
                    elif parsed.response_type == IKEv2ResponseType.INVALID_KE_PAYLOAD:
                        if parsed.suggested_dh_group and parsed.suggested_dh_group not in accepted:
                            accepted.append(parsed.suggested_dh_group)
                        found = True
                        break

                if self._adaptive_delay > 0:
                    time.sleep(self._adaptive_delay)

            if not found and self._adaptive_delay > 0:
                time.sleep(self._adaptive_delay)

        return accepted

    def _generate_ikev2_proposals(
        self,
        encr_list: list[tuple[IKEv2EncrId, int | None]],
        hash_pairs: list[tuple[IKEv2PrfId, IKEv2IntegId]],
        aead_prfs: list[IKEv2PrfId],
        dh_list: list[DHGroupId],
    ) -> list[tuple[IKEv2EncrId, int | None, IKEv2PrfId, IKEv2IntegId | None, DHGroupId]]:
        """Generate the list of individual proposals to test.

        For non-AEAD ciphers, uses paired PRF+INTEG from the same hash family
        (hash_pairs), matching strongSwan cipher suite conventions.
        For AEAD ciphers, uses PRF only (aead_prfs) with INTEG=None.
        """
        proposals = []
        for (encr_id, encr_kl), dh_group in product(encr_list, dh_list):
            encr_info = IKEV2_ENCR_CATALOG[encr_id][encr_kl]
            if encr_info.is_aead:
                for prf_id in aead_prfs:
                    proposals.append((encr_id, encr_kl, prf_id, None, dh_group))
            else:
                for prf_id, integ_id in hash_pairs:
                    proposals.append((encr_id, encr_kl, prf_id, integ_id, dh_group))
        return proposals

    def _scan_ikev1(self, results: ScanResults, progress_callback=None) -> None:
        """Scan IKEv1 cipher suites."""
        if self.config.weak_only:
            encr_list = WEAK_IKEV1_ENCR
            hash_list = WEAK_IKEV1_HASH
            auth_list = MVP_IKEV1_AUTH
            dh_list = WEAK_IKEV1_DH
        elif self.config.quick:
            encr_list = MVP_IKEV1_ENCR
            hash_list = MVP_IKEV1_HASH
            auth_list = MVP_IKEV1_AUTH
            dh_list = MVP_IKEV1_DH
        else:
            encr_list = FULL_IKEV1_ENCR
            hash_list = FULL_IKEV1_HASH
            auth_list = FULL_IKEV1_AUTH
            dh_list = FULL_IKEV1_DH

        proposals = list(product(encr_list, hash_list, auth_list, dh_list))
        total = len(proposals)

        for i, ((encr_id, encr_kl), hash_id, auth_method, dh_group) in enumerate(proposals):
            if progress_callback:
                progress_callback("ikev1_main", i + 1, total)

            self._probe_ikev1(
                results, encr_id, encr_kl, hash_id, auth_method, dh_group, mode="main",
            )

        if self.config.aggressive:
            for i, ((encr_id, encr_kl), hash_id, auth_method, dh_group) in enumerate(proposals):
                if progress_callback:
                    progress_callback("ikev1_aggressive", i + 1, total)

                self._probe_ikev1(
                    results, encr_id, encr_kl, hash_id, auth_method, dh_group, mode="aggressive",
                )

    def _probe_ikev1(
        self,
        results: ScanResults,
        encr_id: IKEv1EncrId,
        encr_kl: int | None,
        hash_id: IKEv1HashId,
        auth_method: IKEv1AuthMethod,
        dh_group: DHGroupId,
        mode: str = "main",
    ) -> None:
        """Send a single IKEv1 probe and record the result."""
        try:
            if mode == "aggressive":
                pkt_bytes, _ = build_ikev1_aggressive_mode(
                    self.config.target_ip,
                    encr_id, encr_kl, hash_id, auth_method, dh_group,
                    self.config.source_ip,
                )
            else:
                pkt_bytes, _ = build_ikev1_main_mode(
                    self.config.target_ip,
                    encr_id, encr_kl, hash_id, auth_method, dh_group,
                    self.config.source_ip,
                )
        except Exception as e:
            logger.debug("Failed to build IKEv1 proposal: %s", e)
            return

        response = _send_with_retries(
            pkt_bytes, self.config.target_ip, self.config.port,
            self.config.timeout, self.config.retries,
            self.config.source_ip,
        )

        results.total_probes += 1

        if response is None:
            self._handle_timeout()
            status = ProbeStatus.TIMEOUT
            results.timeout_count += 1
        else:
            self._consecutive_timeouts = 0
            parsed = parse_ikev1_response(response)
            status = self._map_ikev1_response(parsed)

        result = IKEv1ProposalResult(
            encr_id=encr_id, encr_key_length=encr_kl,
            hash_id=hash_id, auth_method=auth_method,
            dh_group=dh_group, status=status, mode=mode,
        )
        results.ikev1_results.append(result)

        if self._adaptive_delay > 0:
            time.sleep(self._adaptive_delay)

    def _map_ikev2_response(self, parsed) -> ProbeStatus:
        """Map parsed IKEv2 response to ProbeStatus."""
        return {
            IKEv2ResponseType.SA_ACCEPTED: ProbeStatus.ACCEPTED,
            IKEv2ResponseType.NO_PROPOSAL_CHOSEN: ProbeStatus.REJECTED,
            IKEv2ResponseType.INVALID_KE_PAYLOAD: ProbeStatus.INVALID_KE,
            IKEv2ResponseType.OTHER_NOTIFY: ProbeStatus.REJECTED,
            IKEv2ResponseType.MALFORMED: ProbeStatus.REJECTED,
        }.get(parsed.response_type, ProbeStatus.REJECTED)

    def _map_ikev1_response(self, parsed) -> ProbeStatus:
        """Map parsed IKEv1 response to ProbeStatus."""
        from .ikev1.parser import IKEv1ResponseType
        return {
            IKEv1ResponseType.SA_ACCEPTED: ProbeStatus.ACCEPTED,
            IKEv1ResponseType.NO_PROPOSAL_CHOSEN: ProbeStatus.REJECTED,
            IKEv1ResponseType.OTHER_NOTIFY: ProbeStatus.REJECTED,
            IKEv1ResponseType.MALFORMED: ProbeStatus.REJECTED,
        }.get(parsed.response_type, ProbeStatus.REJECTED)

    def _handle_timeout(self) -> None:
        """Adapt delay on consecutive timeouts (backoff)."""
        self._consecutive_timeouts += 1
        if self._consecutive_timeouts >= 5:
            self._adaptive_delay = min(self._adaptive_delay * 1.5, 10.0)
            logger.info(
                "Many consecutive timeouts, increasing delay to %.1fs",
                self._adaptive_delay,
            )
