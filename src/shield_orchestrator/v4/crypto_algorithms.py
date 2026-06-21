from __future__ import annotations

from dataclasses import dataclass

POLICY_V1 = "policy.v1"
CLASSICAL_ED25519 = "classical-ed25519"
ML_DSA = "ml-dsa"
FN_DSA = "fn-dsa"


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
    FN_DSA: "FN-DSA, based on Falcon; optional evidence in policy.v1.",
}


def get_signature_policy(policy_version: str) -> SignaturePolicy:
    if policy_version != POLICY_V1:
        raise ValueError("unsupported Shield v4 signature policy")
    return SIGNATURE_POLICY_V1


def require_supported_algorithm(algorithm: str) -> str:
    if algorithm not in SIGNATURE_POLICY_V1.allowed_algorithms:
        raise ValueError("unsupported Shield v4 signature algorithm")
    return algorithm
