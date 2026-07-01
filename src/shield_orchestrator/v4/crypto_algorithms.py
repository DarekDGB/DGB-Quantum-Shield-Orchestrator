from __future__ import annotations

from dataclasses import dataclass

POLICY_V1 = "policy.v1"
CLASSICAL_ED25519 = "classical-ed25519"
ML_DSA = "ml-dsa"
FN_DSA = "fn-dsa"

ED25519_RFC8032_PROFILE = "rfc8032-ed25519-v1"
FIPS204_ML_DSA_65_PROFILE = "fips204-ml-dsa-65-v1"
FIPS206_DRAFT_FALCON1024_PROFILE = "fips206-draft-falcon1024-v1"


@dataclass(frozen=True)
class SignaturePolicy:
    policy_version: str
    required_algorithms: tuple[str, ...]
    optional_algorithms: tuple[str, ...]

    @property
    def allowed_algorithms(self) -> tuple[str, ...]:
        return self.required_algorithms + self.optional_algorithms


SIGNATURE_POLICY_V1 = SignaturePolicy(
    policy_version=POLICY_V1,
    required_algorithms=(CLASSICAL_ED25519, ML_DSA),
    optional_algorithms=(FN_DSA,),
)

ALGORITHM_DESCRIPTIONS = {
    CLASSICAL_ED25519: "Classical signature path placeholder for production Ed25519-style verification adapters.",
    ML_DSA: "ML-DSA, formerly CRYSTALS-Dilithium.",
    FN_DSA: "FN-DSA, based on Falcon-1024; optional evidence in policy.v1.",
}

ALGORITHM_STANDARD_PROFILES = {
    CLASSICAL_ED25519: (ED25519_RFC8032_PROFILE,),
    ML_DSA: (FIPS204_ML_DSA_65_PROFILE,),
    FN_DSA: (FIPS206_DRAFT_FALCON1024_PROFILE,),
}

DEFAULT_STANDARD_PROFILE_BY_ALGORITHM = {
    algorithm: profiles[0] for algorithm, profiles in ALGORITHM_STANDARD_PROFILES.items()
}


def get_signature_policy(policy_version: str) -> SignaturePolicy:
    if policy_version != POLICY_V1:
        raise ValueError("unsupported Shield v4 signature policy")
    return SIGNATURE_POLICY_V1


def require_supported_algorithm(algorithm: str) -> str:
    if algorithm not in SIGNATURE_POLICY_V1.allowed_algorithms:
        raise ValueError("unsupported Shield v4 signature algorithm")
    return algorithm


def default_standard_profile_for_algorithm(algorithm: str) -> str:
    clean_algorithm = require_supported_algorithm(algorithm)
    return DEFAULT_STANDARD_PROFILE_BY_ALGORITHM[clean_algorithm]


def require_supported_standard_profile(*, algorithm: str, standard_profile: str) -> str:
    clean_algorithm = require_supported_algorithm(algorithm)
    if not isinstance(standard_profile, str) or not standard_profile.strip():
        raise ValueError("standard_profile must be non-empty string")
    clean_profile = standard_profile.strip()
    if clean_profile not in ALGORITHM_STANDARD_PROFILES[clean_algorithm]:
        raise ValueError("unsupported Shield v4 signature standard_profile")
    return clean_profile
