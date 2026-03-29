"""Complete catalog of IPSec transforms with IKEv1/IKEv2 identifiers and security ratings.

Sources:
    - IANA IKEv2 Parameters (updated 2026-01-15)
    - RFC 8247 (Algorithm Requirements for IKEv2)
    - RFC 9395 (IKEv1 Deprecation and Obsoleted Algorithms)
    - RFC 9370 (Multiple Key Exchanges in IKEv2 -- ADDKE / PQC)
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, auto


class SecurityLevel(IntEnum):
    """Security classification for transforms and cipher suites."""

    INSECURE = 0
    WEAK = 1
    OK = 2
    STRONG = 3

    @property
    def label(self) -> str:
        return self.name

    @property
    def color(self) -> str:
        return {
            SecurityLevel.INSECURE: "red",
            SecurityLevel.WEAK: "yellow",
            SecurityLevel.OK: "blue",
            SecurityLevel.STRONG: "green",
        }[self]


# ---------------------------------------------------------------------------
# IKEv2 Transform Type IDs (RFC 7296 Section 3.3.2)
# ---------------------------------------------------------------------------
class IKEv2TransformType(IntEnum):
    ENCR = 1
    PRF = 2
    INTEG = 3
    DH = 4
    # Additional Key Exchange types (RFC 9370) for PQC hybrid
    ADDKE1 = 6
    ADDKE2 = 7
    ADDKE3 = 8
    ADDKE4 = 9


# ---------------------------------------------------------------------------
# IKEv2 Transform IDs
# ---------------------------------------------------------------------------

# Encryption Algorithm IDs (RFC 7296, IANA)
class IKEv2EncrId(IntEnum):
    ENCR_DES_IV64 = 1       # DEPRECATED RFC 9395
    ENCR_DES = 2
    ENCR_3DES = 3
    ENCR_RC5 = 4             # DEPRECATED RFC 9395
    ENCR_IDEA = 5            # DEPRECATED RFC 9395
    ENCR_CAST = 6            # DEPRECATED RFC 9395
    ENCR_BLOWFISH = 7        # DEPRECATED RFC 9395
    ENCR_3IDEA = 8           # DEPRECATED RFC 9395
    ENCR_DES_IV32 = 9        # DEPRECATED RFC 9395
    ENCR_NULL = 11
    ENCR_AES_CBC = 12
    ENCR_AES_CTR = 13
    ENCR_AES_CCM_8 = 14
    ENCR_AES_CCM_12 = 15
    ENCR_AES_CCM_16 = 16
    ENCR_AES_GCM_8 = 18
    ENCR_AES_GCM_12 = 19
    ENCR_AES_GCM_16 = 20
    ENCR_CAMELLIA_CBC = 23
    ENCR_CHACHA20_POLY1305 = 28
    ENCR_KUZNYECHIK_MGM_KTREE = 32   # RFC 9227 (GOST)
    ENCR_MAGMA_MGM_KTREE = 33        # RFC 9227 (GOST)


# Key length attribute type for IKEv2
IKEV2_KEY_LENGTH_ATTR = 14  # Type 14 = Key Length (TV format)

# PRF IDs
class IKEv2PrfId(IntEnum):
    PRF_HMAC_MD5 = 1          # DEPRECATED RFC 8247
    PRF_HMAC_SHA1 = 2
    PRF_HMAC_TIGER = 3        # DEPRECATED RFC 9395
    PRF_AES128_XCBC = 4
    PRF_HMAC_SHA2_256 = 5
    PRF_HMAC_SHA2_384 = 6
    PRF_HMAC_SHA2_512 = 7
    PRF_AES128_CMAC = 8
    PRF_HMAC_STREEBOG_512 = 9  # RFC 9385 (GOST)


# Integrity IDs
class IKEv2IntegId(IntEnum):
    AUTH_NONE = 0             # Required with AEAD; not rated independently
    AUTH_HMAC_MD5_96 = 1      # DEPRECATED RFC 8247
    AUTH_HMAC_SHA1_96 = 2
    AUTH_DES_MAC = 3          # DEPRECATED RFC 8247
    AUTH_KPDK_MD5 = 4         # DEPRECATED RFC 8247
    AUTH_AES_XCBC_96 = 5
    AUTH_HMAC_MD5_128 = 6     # DEPRECATED RFC 9395
    AUTH_HMAC_SHA1_160 = 7    # DEPRECATED RFC 9395
    AUTH_AES_CMAC_96 = 8
    AUTH_AES_128_GMAC = 9
    AUTH_AES_192_GMAC = 10
    AUTH_AES_256_GMAC = 11
    AUTH_HMAC_SHA2_256_128 = 12
    AUTH_HMAC_SHA2_384_192 = 13
    AUTH_HMAC_SHA2_512_256 = 14


# DH Group IDs (shared between IKEv1 and IKEv2)
class DHGroupId(IntEnum):
    MODP_768 = 1              # DEPRECATED RFC 8247
    MODP_1024 = 2
    MODP_1536 = 5
    MODP_2048 = 14
    MODP_3072 = 15
    MODP_4096 = 16
    MODP_6144 = 17
    MODP_8192 = 18
    ECP_256 = 19
    ECP_384 = 20
    ECP_521 = 21
    MODP_1024_160 = 22        # DEPRECATED RFC 8247; RFC 5114 suspicious constants
    MODP_2048_224 = 23
    MODP_2048_256 = 24
    ECP_192 = 25              # RFC 5114; below 112-bit security
    ECP_224 = 26              # RFC 5114
    BRAINPOOL_P224R1 = 27     # RFC 6954
    BRAINPOOL_P256R1 = 28     # RFC 6954
    BRAINPOOL_P384R1 = 29     # RFC 6954
    BRAINPOOL_P512R1 = 30     # RFC 6954
    CURVE25519 = 31
    CURVE448 = 32
    GOST3410_2012_256 = 33    # RFC 9385
    GOST3410_2012_512 = 34    # RFC 9385
    ML_KEM_512 = 35           # draft-kampanakis-ml-kem-ikev2 (PQC)
    ML_KEM_768 = 36           # draft-kampanakis-ml-kem-ikev2 (PQC)
    ML_KEM_1024 = 37          # draft-kampanakis-ml-kem-ikev2 (PQC)


# ---------------------------------------------------------------------------
# IKEv1 Transform IDs (RFC 2409 / IANA)
# ---------------------------------------------------------------------------
class IKEv1EncrId(IntEnum):
    DES_CBC = 1
    IDEA_CBC = 2              # DEPRECATED RFC 9395
    BLOWFISH_CBC = 3
    RC5_CBC = 4               # DEPRECATED RFC 9395
    DES3_CBC = 5
    CAST_CBC = 6
    AES_CBC = 7


class IKEv1HashId(IntEnum):
    MD5 = 1
    SHA1 = 2
    SHA2_256 = 4
    SHA2_384 = 5
    SHA2_512 = 6


class IKEv1AuthMethod(IntEnum):
    PSK = 1
    RSA_SIG = 3
    ECDSA_SHA256 = 9
    ECDSA_SHA384 = 10
    ECDSA_SHA512 = 11


# IKEv2 Authentication Methods (RFC 7296 Section 3.8)
class IKEv2AuthMethod(IntEnum):
    RSA_DIGITAL_SIGNATURE = 1     # Legacy method; prefer DIGITAL_SIGNATURE
    SHARED_KEY_MIC = 2            # Pre-Shared Key
    DSS_DIGITAL_SIGNATURE = 3
    ECDSA_SHA256_P256 = 9         # RFC 4754
    ECDSA_SHA384_P384 = 10        # RFC 4754
    ECDSA_SHA512_P521 = 11        # RFC 4754
    GENERIC_SECURE_PASSWORD = 12  # RFC 6467
    NULL_AUTHENTICATION = 13      # RFC 7619
    DIGITAL_SIGNATURE = 14        # RFC 7427; supports RSA-PSS, ECDSA, EdDSA


# ISAKMP attribute types (RFC 2409 Appendix A)
class ISAKMPAttr(IntEnum):
    ENCRYPTION = 1
    HASH = 2
    AUTH_METHOD = 3
    GROUP_DESC = 4
    KEY_LENGTH = 14


# ---------------------------------------------------------------------------
# Descriptors: human-readable metadata for each transform value
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class TransformInfo:
    """Metadata for a single transform value."""

    name: str
    security: SecurityLevel
    is_aead: bool = False
    key_lengths: tuple[int, ...] | None = None  # Required key lengths in bits


# --- Encryption transforms ---

IKEV2_ENCR_CATALOG: dict[IKEv2EncrId, dict[int | None, TransformInfo]] = {
    # key_length -> info; None means no key length attribute needed

    # --- Deprecated (RFC 9395) -- keep for detection ---
    IKEv2EncrId.ENCR_DES_IV64: {
        None: TransformInfo("DES-IV64", SecurityLevel.INSECURE),
    },
    IKEv2EncrId.ENCR_DES: {
        None: TransformInfo("DES-CBC", SecurityLevel.INSECURE),
    },
    IKEv2EncrId.ENCR_RC5: {
        128: TransformInfo("RC5-CBC-128", SecurityLevel.INSECURE),
    },
    IKEv2EncrId.ENCR_IDEA: {
        128: TransformInfo("IDEA-CBC", SecurityLevel.INSECURE),
    },
    IKEv2EncrId.ENCR_CAST: {
        128: TransformInfo("CAST-CBC-128", SecurityLevel.INSECURE),  # DEPRECATED RFC 9395
    },
    IKEv2EncrId.ENCR_BLOWFISH: {
        128: TransformInfo("Blowfish-CBC-128", SecurityLevel.INSECURE),  # DEPRECATED RFC 9395
        256: TransformInfo("Blowfish-CBC-256", SecurityLevel.INSECURE),  # DEPRECATED RFC 9395
    },
    IKEv2EncrId.ENCR_3IDEA: {
        None: TransformInfo("3IDEA", SecurityLevel.INSECURE),
    },
    IKEv2EncrId.ENCR_DES_IV32: {
        None: TransformInfo("DES-IV32", SecurityLevel.INSECURE),
    },

    # --- Legacy ---
    IKEv2EncrId.ENCR_3DES: {
        None: TransformInfo("3DES-CBC", SecurityLevel.WEAK),  # Sweet32; MUST NOT per RFC 8247
    },
    IKEv2EncrId.ENCR_NULL: {
        None: TransformInfo("NULL", SecurityLevel.INSECURE),  # Not allowed for IKE SA
    },

    # --- AES-CBC (non-AEAD) ---
    IKEv2EncrId.ENCR_AES_CBC: {
        128: TransformInfo("AES-CBC-128", SecurityLevel.OK),      # MUST per RFC 8247
        192: TransformInfo("AES-CBC-192", SecurityLevel.STRONG),
        256: TransformInfo("AES-CBC-256", SecurityLevel.STRONG),   # SHOULD+ per RFC 8247
    },

    # --- AES-CTR (non-AEAD, needs separate INTEG) ---
    IKEv2EncrId.ENCR_AES_CTR: {
        128: TransformInfo("AES-CTR-128", SecurityLevel.OK),
        192: TransformInfo("AES-CTR-192", SecurityLevel.STRONG),
        256: TransformInfo("AES-CTR-256", SecurityLevel.STRONG),
    },

    # --- AES-GCM (AEAD) ---
    IKEv2EncrId.ENCR_AES_GCM_8: {
        128: TransformInfo("AES-128-GCM-8", SecurityLevel.OK, is_aead=True),   # 8-byte ICV; SHOULD NOT per RFC 8247
        192: TransformInfo("AES-192-GCM-8", SecurityLevel.OK, is_aead=True),
        256: TransformInfo("AES-256-GCM-8", SecurityLevel.OK, is_aead=True),
    },
    IKEv2EncrId.ENCR_AES_GCM_12: {
        128: TransformInfo("AES-128-GCM-12", SecurityLevel.OK, is_aead=True),  # 12-byte ICV; acceptable
        192: TransformInfo("AES-192-GCM-12", SecurityLevel.OK, is_aead=True),
        256: TransformInfo("AES-256-GCM-12", SecurityLevel.OK, is_aead=True),
    },
    IKEv2EncrId.ENCR_AES_GCM_16: {
        128: TransformInfo("AES-128-GCM", SecurityLevel.STRONG, is_aead=True),  # SHOULD+ per RFC 8247
        192: TransformInfo("AES-192-GCM", SecurityLevel.STRONG, is_aead=True),
        256: TransformInfo("AES-256-GCM", SecurityLevel.STRONG, is_aead=True),
    },

    # --- AES-CCM (AEAD) ---
    IKEv2EncrId.ENCR_AES_CCM_8: {
        128: TransformInfo("AES-128-CCM-8", SecurityLevel.OK, is_aead=True),   # 8-byte ICV
        192: TransformInfo("AES-192-CCM-8", SecurityLevel.OK, is_aead=True),
        256: TransformInfo("AES-256-CCM-8", SecurityLevel.OK, is_aead=True),
    },
    IKEv2EncrId.ENCR_AES_CCM_12: {
        128: TransformInfo("AES-128-CCM-12", SecurityLevel.OK, is_aead=True),
        192: TransformInfo("AES-192-CCM-12", SecurityLevel.OK, is_aead=True),
        256: TransformInfo("AES-256-CCM-12", SecurityLevel.OK, is_aead=True),
    },
    IKEv2EncrId.ENCR_AES_CCM_16: {
        128: TransformInfo("AES-128-CCM", SecurityLevel.STRONG, is_aead=True),
        192: TransformInfo("AES-192-CCM", SecurityLevel.STRONG, is_aead=True),
        256: TransformInfo("AES-256-CCM", SecurityLevel.STRONG, is_aead=True),
    },

    # --- Camellia ---
    IKEv2EncrId.ENCR_CAMELLIA_CBC: {
        128: TransformInfo("Camellia-CBC-128", SecurityLevel.OK),
        192: TransformInfo("Camellia-CBC-192", SecurityLevel.STRONG),
        256: TransformInfo("Camellia-CBC-256", SecurityLevel.STRONG),
    },

    # --- ChaCha20-Poly1305 (AEAD) ---
    IKEv2EncrId.ENCR_CHACHA20_POLY1305: {
        256: TransformInfo("ChaCha20-Poly1305", SecurityLevel.STRONG, is_aead=True),
    },

    # --- GOST (RFC 9227) ---
    IKEv2EncrId.ENCR_KUZNYECHIK_MGM_KTREE: {
        256: TransformInfo("Kuznyechik-MGM", SecurityLevel.OK, is_aead=True),
    },
    IKEv2EncrId.ENCR_MAGMA_MGM_KTREE: {
        256: TransformInfo("Magma-MGM", SecurityLevel.WEAK, is_aead=True),  # 64-bit block
    },
}


# --- PRF transforms ---

IKEV2_PRF_CATALOG: dict[IKEv2PrfId, TransformInfo] = {
    IKEv2PrfId.PRF_HMAC_MD5: TransformInfo("PRF-MD5", SecurityLevel.INSECURE),
    IKEv2PrfId.PRF_HMAC_SHA1: TransformInfo("PRF-SHA1", SecurityLevel.WEAK),
    IKEv2PrfId.PRF_HMAC_TIGER: TransformInfo("PRF-TIGER", SecurityLevel.INSECURE),  # DEPRECATED RFC 9395
    IKEv2PrfId.PRF_AES128_XCBC: TransformInfo("PRF-AES-XCBC", SecurityLevel.OK),
    IKEv2PrfId.PRF_HMAC_SHA2_256: TransformInfo("PRF-SHA2-256", SecurityLevel.STRONG),
    IKEv2PrfId.PRF_HMAC_SHA2_384: TransformInfo("PRF-SHA2-384", SecurityLevel.STRONG),
    IKEv2PrfId.PRF_HMAC_SHA2_512: TransformInfo("PRF-SHA2-512", SecurityLevel.STRONG),
    IKEv2PrfId.PRF_AES128_CMAC: TransformInfo("PRF-AES-CMAC", SecurityLevel.OK),
    IKEv2PrfId.PRF_HMAC_STREEBOG_512: TransformInfo("PRF-STREEBOG-512", SecurityLevel.OK),
}


# --- Integrity transforms ---

IKEV2_INTEG_CATALOG: dict[IKEv2IntegId, TransformInfo] = {
    # AUTH_NONE is required with AEAD ciphers; not independently insecure.
    # The scanner should not penalize AEAD+NONE combinations.
    IKEv2IntegId.AUTH_NONE: TransformInfo("NONE", SecurityLevel.OK),
    IKEv2IntegId.AUTH_HMAC_MD5_96: TransformInfo("HMAC-MD5-96", SecurityLevel.INSECURE),
    IKEv2IntegId.AUTH_HMAC_SHA1_96: TransformInfo("HMAC-SHA1-96", SecurityLevel.WEAK),
    IKEv2IntegId.AUTH_DES_MAC: TransformInfo("DES-MAC", SecurityLevel.INSECURE),          # DEPRECATED
    IKEv2IntegId.AUTH_KPDK_MD5: TransformInfo("KPDK-MD5", SecurityLevel.INSECURE),        # DEPRECATED
    IKEv2IntegId.AUTH_AES_XCBC_96: TransformInfo("AES-XCBC-96", SecurityLevel.OK),
    IKEv2IntegId.AUTH_HMAC_MD5_128: TransformInfo("HMAC-MD5-128", SecurityLevel.INSECURE),  # DEPRECATED RFC 9395
    IKEv2IntegId.AUTH_HMAC_SHA1_160: TransformInfo("HMAC-SHA1-160", SecurityLevel.WEAK),    # DEPRECATED RFC 9395
    IKEv2IntegId.AUTH_AES_CMAC_96: TransformInfo("AES-CMAC-96", SecurityLevel.OK),
    IKEv2IntegId.AUTH_AES_128_GMAC: TransformInfo("AES-128-GMAC", SecurityLevel.OK),
    IKEv2IntegId.AUTH_AES_192_GMAC: TransformInfo("AES-192-GMAC", SecurityLevel.OK),
    IKEv2IntegId.AUTH_AES_256_GMAC: TransformInfo("AES-256-GMAC", SecurityLevel.STRONG),
    IKEv2IntegId.AUTH_HMAC_SHA2_256_128: TransformInfo("HMAC-SHA2-256", SecurityLevel.STRONG),
    IKEv2IntegId.AUTH_HMAC_SHA2_384_192: TransformInfo("HMAC-SHA2-384", SecurityLevel.STRONG),
    IKEv2IntegId.AUTH_HMAC_SHA2_512_256: TransformInfo("HMAC-SHA2-512", SecurityLevel.STRONG),
}


# --- DH Groups ---

DH_GROUP_CATALOG: dict[DHGroupId, TransformInfo] = {
    DHGroupId.MODP_768: TransformInfo("MODP-768", SecurityLevel.INSECURE),
    DHGroupId.MODP_1024: TransformInfo("MODP-1024", SecurityLevel.INSECURE),  # ~80-bit; Logjam
    DHGroupId.MODP_1536: TransformInfo("MODP-1536", SecurityLevel.WEAK),      # Below 112-bit
    DHGroupId.MODP_2048: TransformInfo("MODP-2048", SecurityLevel.OK),
    DHGroupId.MODP_3072: TransformInfo("MODP-3072", SecurityLevel.STRONG),
    DHGroupId.MODP_4096: TransformInfo("MODP-4096", SecurityLevel.STRONG),
    DHGroupId.MODP_6144: TransformInfo("MODP-6144", SecurityLevel.STRONG),
    DHGroupId.MODP_8192: TransformInfo("MODP-8192", SecurityLevel.STRONG),
    DHGroupId.ECP_256: TransformInfo("ECP-256", SecurityLevel.STRONG),
    DHGroupId.ECP_384: TransformInfo("ECP-384", SecurityLevel.STRONG),
    DHGroupId.ECP_521: TransformInfo("ECP-521", SecurityLevel.STRONG),
    DHGroupId.MODP_1024_160: TransformInfo("MODP-1024-160", SecurityLevel.INSECURE),  # DEPRECATED RFC 8247
    DHGroupId.MODP_2048_224: TransformInfo("MODP-2048-224", SecurityLevel.WEAK),  # RFC 5114 trust concerns
    DHGroupId.MODP_2048_256: TransformInfo("MODP-2048-256", SecurityLevel.WEAK),  # RFC 5114 trust concerns
    DHGroupId.ECP_192: TransformInfo("ECP-192", SecurityLevel.INSECURE),          # Below 112-bit
    DHGroupId.ECP_224: TransformInfo("ECP-224", SecurityLevel.WEAK),
    DHGroupId.BRAINPOOL_P224R1: TransformInfo("brainpoolP224r1", SecurityLevel.WEAK),
    DHGroupId.BRAINPOOL_P256R1: TransformInfo("brainpoolP256r1", SecurityLevel.OK),
    DHGroupId.BRAINPOOL_P384R1: TransformInfo("brainpoolP384r1", SecurityLevel.STRONG),
    DHGroupId.BRAINPOOL_P512R1: TransformInfo("brainpoolP512r1", SecurityLevel.STRONG),
    DHGroupId.CURVE25519: TransformInfo("Curve25519", SecurityLevel.STRONG),
    DHGroupId.CURVE448: TransformInfo("Curve448", SecurityLevel.STRONG),
    DHGroupId.GOST3410_2012_256: TransformInfo("GOST-2012-256", SecurityLevel.OK),
    DHGroupId.GOST3410_2012_512: TransformInfo("GOST-2012-512", SecurityLevel.OK),
    DHGroupId.ML_KEM_512: TransformInfo("ML-KEM-512", SecurityLevel.OK),       # PQC Level 1; use as ADDKE
    DHGroupId.ML_KEM_768: TransformInfo("ML-KEM-768", SecurityLevel.STRONG),   # PQC Level 3
    DHGroupId.ML_KEM_1024: TransformInfo("ML-KEM-1024", SecurityLevel.STRONG), # PQC Level 5
}


# --- IKEv1 catalogs ---

IKEV1_ENCR_CATALOG: dict[IKEv1EncrId, dict[int | None, TransformInfo]] = {
    IKEv1EncrId.DES_CBC: {
        None: TransformInfo("DES-CBC", SecurityLevel.INSECURE),
    },
    IKEv1EncrId.IDEA_CBC: {
        None: TransformInfo("IDEA-CBC", SecurityLevel.INSECURE),  # DEPRECATED RFC 9395
    },
    IKEv1EncrId.BLOWFISH_CBC: {
        128: TransformInfo("Blowfish-CBC-128", SecurityLevel.INSECURE),  # DEPRECATED RFC 9395
    },
    IKEv1EncrId.RC5_CBC: {
        128: TransformInfo("RC5-CBC-128", SecurityLevel.INSECURE),  # DEPRECATED RFC 9395
    },
    IKEv1EncrId.DES3_CBC: {
        None: TransformInfo("3DES-CBC", SecurityLevel.WEAK),
    },
    IKEv1EncrId.CAST_CBC: {
        128: TransformInfo("CAST-CBC-128", SecurityLevel.INSECURE),  # DEPRECATED RFC 9395
    },
    IKEv1EncrId.AES_CBC: {
        128: TransformInfo("AES-CBC-128", SecurityLevel.OK),
        192: TransformInfo("AES-CBC-192", SecurityLevel.STRONG),
        256: TransformInfo("AES-CBC-256", SecurityLevel.STRONG),
    },
}

IKEV1_HASH_CATALOG: dict[IKEv1HashId, TransformInfo] = {
    IKEv1HashId.MD5: TransformInfo("MD5", SecurityLevel.INSECURE),
    IKEv1HashId.SHA1: TransformInfo("SHA1", SecurityLevel.WEAK),
    IKEv1HashId.SHA2_256: TransformInfo("SHA2-256", SecurityLevel.STRONG),
    IKEv1HashId.SHA2_384: TransformInfo("SHA2-384", SecurityLevel.STRONG),
    IKEv1HashId.SHA2_512: TransformInfo("SHA2-512", SecurityLevel.STRONG),
}

IKEV1_AUTH_CATALOG: dict[IKEv1AuthMethod, TransformInfo] = {
    IKEv1AuthMethod.PSK: TransformInfo("PSK", SecurityLevel.OK),
    IKEv1AuthMethod.RSA_SIG: TransformInfo("RSA-Sig", SecurityLevel.STRONG),
    IKEv1AuthMethod.ECDSA_SHA256: TransformInfo("ECDSA-256", SecurityLevel.STRONG),
    IKEv1AuthMethod.ECDSA_SHA384: TransformInfo("ECDSA-384", SecurityLevel.STRONG),
    IKEv1AuthMethod.ECDSA_SHA512: TransformInfo("ECDSA-512", SecurityLevel.STRONG),
}

IKEV2_AUTH_CATALOG: dict[IKEv2AuthMethod, TransformInfo] = {
    IKEv2AuthMethod.RSA_DIGITAL_SIGNATURE: TransformInfo("RSA-Sig (legacy)", SecurityLevel.OK),
    IKEv2AuthMethod.SHARED_KEY_MIC: TransformInfo("PSK", SecurityLevel.OK),
    IKEv2AuthMethod.DSS_DIGITAL_SIGNATURE: TransformInfo("DSS-Sig", SecurityLevel.WEAK),
    IKEv2AuthMethod.ECDSA_SHA256_P256: TransformInfo("ECDSA-SHA256-P256", SecurityLevel.STRONG),
    IKEv2AuthMethod.ECDSA_SHA384_P384: TransformInfo("ECDSA-SHA384-P384", SecurityLevel.STRONG),
    IKEv2AuthMethod.ECDSA_SHA512_P521: TransformInfo("ECDSA-SHA512-P521", SecurityLevel.STRONG),
    IKEv2AuthMethod.GENERIC_SECURE_PASSWORD: TransformInfo("GSPM", SecurityLevel.OK),
    IKEv2AuthMethod.NULL_AUTHENTICATION: TransformInfo("NULL", SecurityLevel.INSECURE),
    IKEv2AuthMethod.DIGITAL_SIGNATURE: TransformInfo("Digital Signature (RFC 7427)", SecurityLevel.STRONG),
}


# ---------------------------------------------------------------------------
# DH group key exchange sizes (bytes) for generating KE payloads
# ---------------------------------------------------------------------------

DH_KE_SIZES: dict[DHGroupId, int] = {
    DHGroupId.MODP_768: 96,
    DHGroupId.MODP_1024: 128,
    DHGroupId.MODP_1536: 192,
    DHGroupId.MODP_2048: 256,
    DHGroupId.MODP_3072: 384,
    DHGroupId.MODP_4096: 512,
    DHGroupId.MODP_6144: 768,
    DHGroupId.MODP_8192: 1024,
    DHGroupId.ECP_256: 64,     # 2 * 32 bytes (x, y)
    DHGroupId.ECP_384: 96,     # 2 * 48 bytes
    DHGroupId.ECP_521: 132,    # 2 * 66 bytes
    DHGroupId.MODP_1024_160: 128,
    DHGroupId.MODP_2048_224: 256,
    DHGroupId.MODP_2048_256: 256,
    DHGroupId.ECP_192: 48,     # 2 * 24 bytes
    DHGroupId.ECP_224: 56,     # 2 * 28 bytes
    DHGroupId.BRAINPOOL_P224R1: 56,   # 2 * 28 bytes
    DHGroupId.BRAINPOOL_P256R1: 64,   # 2 * 32 bytes
    DHGroupId.BRAINPOOL_P384R1: 96,   # 2 * 48 bytes
    DHGroupId.BRAINPOOL_P512R1: 128,  # 2 * 64 bytes
    DHGroupId.CURVE25519: 32,
    DHGroupId.CURVE448: 56,
    DHGroupId.GOST3410_2012_256: 64,  # 2 * 32 bytes
    DHGroupId.GOST3410_2012_512: 128, # 2 * 64 bytes
    DHGroupId.ML_KEM_512: 800,        # ML-KEM encapsulation key size
    DHGroupId.ML_KEM_768: 1184,
    DHGroupId.ML_KEM_1024: 1568,
}


# ---------------------------------------------------------------------------
# MVP subsets: reduced catalogs for --quick / MVP mode
# ---------------------------------------------------------------------------

MVP_ENCR_IDS: list[tuple[IKEv2EncrId, int | None]] = [
    # Non-AEAD
    (IKEv2EncrId.ENCR_AES_CBC, 128),
    (IKEv2EncrId.ENCR_AES_CBC, 192),
    (IKEv2EncrId.ENCR_AES_CBC, 256),
    (IKEv2EncrId.ENCR_3DES, None),
    # AEAD
    (IKEv2EncrId.ENCR_AES_GCM_16, 128),
    (IKEv2EncrId.ENCR_AES_GCM_16, 256),
    (IKEv2EncrId.ENCR_AES_GCM_12, 128),
    (IKEv2EncrId.ENCR_AES_GCM_12, 256),
    (IKEv2EncrId.ENCR_CHACHA20_POLY1305, 256),
]

MVP_PRF_IDS: list[IKEv2PrfId] = [
    IKEv2PrfId.PRF_HMAC_SHA1,
    IKEv2PrfId.PRF_HMAC_SHA2_256,
    IKEv2PrfId.PRF_HMAC_SHA2_512,
]

MVP_INTEG_IDS: list[IKEv2IntegId] = [
    IKEv2IntegId.AUTH_HMAC_SHA1_96,
    IKEv2IntegId.AUTH_HMAC_SHA2_256_128,
    IKEv2IntegId.AUTH_HMAC_SHA2_512_256,
]

MVP_DH_GROUPS: list[DHGroupId] = [
    DHGroupId.MODP_1024,
    DHGroupId.MODP_1536,
    DHGroupId.MODP_2048,
    DHGroupId.MODP_2048_256,
    DHGroupId.ECP_256,
    DHGroupId.ECP_384,
    DHGroupId.CURVE25519,
]

# Full IKEv2 catalogs for complete scans
FULL_ENCR_IDS: list[tuple[IKEv2EncrId, int | None]] = []
for _encr_id, _kl_map in IKEV2_ENCR_CATALOG.items():
    for _kl in _kl_map:
        FULL_ENCR_IDS.append((_encr_id, _kl))

FULL_PRF_IDS: list[IKEv2PrfId] = list(IKEV2_PRF_CATALOG.keys())
FULL_INTEG_IDS: list[IKEv2IntegId] = [
    k for k in IKEV2_INTEG_CATALOG if k != IKEv2IntegId.AUTH_NONE
]
FULL_DH_GROUPS: list[DHGroupId] = list(DH_GROUP_CATALOG.keys())

# ---------------------------------------------------------------------------
# IKEv2 hash pairs: paired PRF + INTEG from the same hash family.
# In real-world IKEv2 (as strongSwan implements), PRF and INTEG are always
# derived from the same hash algorithm.  Mismatched pairs (e.g.
# PRF-SHA256 + HMAC-MD5-96) are rejected by conforming implementations.
# ---------------------------------------------------------------------------

IKEV2_HASH_PAIRS: list[tuple[IKEv2PrfId, IKEv2IntegId]] = [
    (IKEv2PrfId.PRF_HMAC_MD5, IKEv2IntegId.AUTH_HMAC_MD5_96),
    (IKEv2PrfId.PRF_HMAC_SHA1, IKEv2IntegId.AUTH_HMAC_SHA1_96),
    (IKEv2PrfId.PRF_HMAC_SHA2_256, IKEv2IntegId.AUTH_HMAC_SHA2_256_128),
    (IKEv2PrfId.PRF_HMAC_SHA2_384, IKEv2IntegId.AUTH_HMAC_SHA2_384_192),
    (IKEv2PrfId.PRF_HMAC_SHA2_512, IKEv2IntegId.AUTH_HMAC_SHA2_512_256),
    (IKEv2PrfId.PRF_AES128_XCBC, IKEv2IntegId.AUTH_AES_XCBC_96),
    (IKEv2PrfId.PRF_AES128_CMAC, IKEv2IntegId.AUTH_AES_CMAC_96),
]

MVP_HASH_PAIRS: list[tuple[IKEv2PrfId, IKEv2IntegId]] = [
    (IKEv2PrfId.PRF_HMAC_SHA1, IKEv2IntegId.AUTH_HMAC_SHA1_96),
    (IKEv2PrfId.PRF_HMAC_SHA2_256, IKEv2IntegId.AUTH_HMAC_SHA2_256_128),
    (IKEv2PrfId.PRF_HMAC_SHA2_384, IKEv2IntegId.AUTH_HMAC_SHA2_384_192),
    (IKEv2PrfId.PRF_HMAC_SHA2_512, IKEv2IntegId.AUTH_HMAC_SHA2_512_256),
]

FULL_HASH_PAIRS: list[tuple[IKEv2PrfId, IKEv2IntegId]] = IKEV2_HASH_PAIRS

# For AEAD ciphers, only PRF is needed (integrity is implicit)
MVP_AEAD_PRFS: list[IKEv2PrfId] = [
    IKEv2PrfId.PRF_HMAC_SHA1,
    IKEv2PrfId.PRF_HMAC_SHA2_256,
    IKEv2PrfId.PRF_HMAC_SHA2_384,
    IKEv2PrfId.PRF_HMAC_SHA2_512,
]

FULL_AEAD_PRFS: list[IKEv2PrfId] = list(IKEV2_PRF_CATALOG.keys())

# IKEv1 MVP subsets
MVP_IKEV1_ENCR: list[tuple[IKEv1EncrId, int | None]] = [
    (IKEv1EncrId.AES_CBC, 128),
    (IKEv1EncrId.AES_CBC, 256),
    (IKEv1EncrId.DES3_CBC, None),
]

MVP_IKEV1_HASH: list[IKEv1HashId] = [
    IKEv1HashId.SHA1,
    IKEv1HashId.SHA2_256,
]

MVP_IKEV1_AUTH: list[IKEv1AuthMethod] = [
    IKEv1AuthMethod.PSK,
    IKEv1AuthMethod.RSA_SIG,
]

MVP_IKEV1_DH: list[DHGroupId] = [
    DHGroupId.MODP_1024,
    DHGroupId.MODP_2048,
    DHGroupId.ECP_256,
]

# Full IKEv1
FULL_IKEV1_ENCR: list[tuple[IKEv1EncrId, int | None]] = []
for _eid, _klm in IKEV1_ENCR_CATALOG.items():
    for _kl in _klm:
        FULL_IKEV1_ENCR.append((_eid, _kl))

FULL_IKEV1_HASH: list[IKEv1HashId] = list(IKEV1_HASH_CATALOG.keys())
FULL_IKEV1_AUTH: list[IKEv1AuthMethod] = list(IKEV1_AUTH_CATALOG.keys())
FULL_IKEV1_DH: list[DHGroupId] = list(DH_GROUP_CATALOG.keys())


# ---------------------------------------------------------------------------
# Weak-only subsets: INSECURE + WEAK transforms for targeted security checks
# ---------------------------------------------------------------------------

WEAK_ENCR_IDS: list[tuple[IKEv2EncrId, int | None]] = [
    (encr_id, kl)
    for encr_id, kl_map in IKEV2_ENCR_CATALOG.items()
    for kl, info in kl_map.items()
    if info.security <= SecurityLevel.WEAK
]

WEAK_HASH_PAIRS: list[tuple[IKEv2PrfId, IKEv2IntegId]] = [
    (prf_id, integ_id)
    for prf_id, integ_id in IKEV2_HASH_PAIRS
    if (
        IKEV2_PRF_CATALOG[prf_id].security <= SecurityLevel.WEAK
        or IKEV2_INTEG_CATALOG[integ_id].security <= SecurityLevel.WEAK
    )
]

WEAK_AEAD_PRFS: list[IKEv2PrfId] = [
    prf_id
    for prf_id, info in IKEV2_PRF_CATALOG.items()
    if info.security <= SecurityLevel.WEAK
]

WEAK_DH_GROUPS: list[DHGroupId] = [
    dh
    for dh, info in DH_GROUP_CATALOG.items()
    if info.security <= SecurityLevel.WEAK
]

WEAK_IKEV1_ENCR: list[tuple[IKEv1EncrId, int | None]] = [
    (eid, kl)
    for eid, kl_map in IKEV1_ENCR_CATALOG.items()
    for kl, info in kl_map.items()
    if info.security <= SecurityLevel.WEAK
]

WEAK_IKEV1_HASH: list[IKEv1HashId] = [
    hid
    for hid, info in IKEV1_HASH_CATALOG.items()
    if info.security <= SecurityLevel.WEAK
]

WEAK_IKEV1_DH: list[DHGroupId] = WEAK_DH_GROUPS


def get_encr_info(encr_id: IKEv2EncrId, key_length: int | None) -> TransformInfo:
    """Look up encryption transform info."""
    return IKEV2_ENCR_CATALOG[encr_id][key_length]


def get_prf_info(prf_id: IKEv2PrfId) -> TransformInfo:
    """Look up PRF transform info."""
    return IKEV2_PRF_CATALOG[prf_id]


def get_integ_info(integ_id: IKEv2IntegId) -> TransformInfo:
    """Look up integrity transform info."""
    return IKEV2_INTEG_CATALOG[integ_id]


def get_dh_info(dh_id: DHGroupId) -> TransformInfo:
    """Look up DH group info."""
    return DH_GROUP_CATALOG[dh_id]


def get_ikev1_encr_info(encr_id: IKEv1EncrId, key_length: int | None) -> TransformInfo:
    """Look up IKEv1 encryption transform info."""
    return IKEV1_ENCR_CATALOG[encr_id][key_length]


def get_ikev1_hash_info(hash_id: IKEv1HashId) -> TransformInfo:
    """Look up IKEv1 hash info."""
    return IKEV1_HASH_CATALOG[hash_id]


def get_ikev2_auth_info(auth_id: IKEv2AuthMethod) -> TransformInfo:
    """Look up IKEv2 authentication method info."""
    return IKEV2_AUTH_CATALOG[auth_id]