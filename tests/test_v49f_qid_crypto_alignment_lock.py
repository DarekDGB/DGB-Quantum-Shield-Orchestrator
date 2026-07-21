from __future__ import annotations

import ast
import tomllib
from pathlib import Path

from shield_orchestrator.v4.canonical_json import (
    COMPONENT_VERDICT_DOMAIN,
    ORCHESTRATOR_RECEIPT_DOMAIN,
)
from shield_orchestrator.v4.crypto_algorithms import (
    ALGORITHM_STANDARD_PROFILES,
    CLASSICAL_ED25519,
    FN_DSA,
    ML_DSA,
    POLICY_V1,
    SIGNATURE_POLICY_V1,
)
from shield_orchestrator.v4.key_registry import SUPPORTED_ROLES
from shield_orchestrator.v4.oqs_falcon_backend import (
    OQS_FALCON_ALGORITHM,
    OQS_FALCON_MECHANISM,
)
from shield_orchestrator.v4.oqs_mldsa_backend import (
    OQS_ML_DSA_ALGORITHM,
    OQS_ML_DSA_MECHANISM,
)

ROOT = Path(__file__).resolve().parents[1]
ALIGNMENT = ROOT / "docs" / "v4" / "SHIELD_V4_QID_CRYPTO_ALIGNMENT.md"
LEGACY_DOCS = (
    ROOT / "docs" / "legacy" / "Shield_Architecture_v2.md",
    ROOT / "docs" / "legacy" / "Shield_Testnet_Bundle_Guide_v2.md",
)
CONTROLLED_FILES = (ALIGNMENT, *LEGACY_DOCS, Path(__file__).resolve())

EXPECTED_POLICY_VERSION = "policy.v1"
EXPECTED_REQUIRED_ALGORITHMS = ("classical-ed25519", "ml-dsa")
EXPECTED_OPTIONAL_ALGORITHMS = ("fn-dsa",)
EXPECTED_PROFILE_MAP = {
    "classical-ed25519": ("rfc8032-ed25519-v1",),
    "ml-dsa": ("fips204-ml-dsa-65-v1",),
    "fn-dsa": ("fips206-draft-falcon1024-v1",),
}
EXPECTED_MECHANISM_MAP = {
    "ml-dsa": "ML-DSA-65",
    "fn-dsa": "Falcon-1024",
}
EXPECTED_ROLES = (
    "shield_component_adn",
    "shield_component_dqsn",
    "shield_component_guardian_wallet",
    "shield_component_qwg",
    "shield_component_sentinel_ai",
    "shield_orchestrator",
)
EXPECTED_DOMAINS = (
    "DGB-SHIELD-V4-COMPONENT-VERDICT:shield.verdict.v2:policy.v1",
    "DGB-SHIELD-V4-ORCH-RECEIPT:shield.receipt.v2:policy.v1",
)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _is_qid_module_name(value: str) -> bool:
    return value == "qid" or value.startswith("qid.")


def _dependency_name(value: str) -> str:
    normalized = value.strip().casefold().replace("_", "-").replace(".", "-")
    for separator in ("[", " ", "<", ">", "=", "!", "~", "@", ";"):
        normalized = normalized.split(separator, 1)[0]
    return normalized


def test_v49f_runtime_constants_match_independent_literal_locks() -> None:
    assert POLICY_V1 == EXPECTED_POLICY_VERSION
    assert (CLASSICAL_ED25519, ML_DSA, FN_DSA) == (
        "classical-ed25519",
        "ml-dsa",
        "fn-dsa",
    )
    assert SIGNATURE_POLICY_V1.required_algorithms == EXPECTED_REQUIRED_ALGORITHMS
    assert SIGNATURE_POLICY_V1.optional_algorithms == EXPECTED_OPTIONAL_ALGORITHMS
    assert ALGORITHM_STANDARD_PROFILES == EXPECTED_PROFILE_MAP
    assert SUPPORTED_ROLES == EXPECTED_ROLES
    assert (COMPONENT_VERDICT_DOMAIN, ORCHESTRATOR_RECEIPT_DOMAIN) == EXPECTED_DOMAINS
    assert (OQS_ML_DSA_ALGORITHM, OQS_ML_DSA_MECHANISM) == (
        "ml-dsa",
        "ML-DSA-65",
    )
    assert (OQS_FALCON_ALGORITHM, OQS_FALCON_MECHANISM) == (
        "fn-dsa",
        "Falcon-1024",
    )


def test_v49f_document_matches_the_literal_shield_policy_and_profiles() -> None:
    text = _read(ALIGNMENT)

    exact_rows = (
        "| `classical-ed25519` | required | `rfc8032-ed25519-v1`; `Ed25519` |",
        "| `ml-dsa` | required | `fips204-ml-dsa-65-v1`; `ML-DSA-65` |",
        "| `fn-dsa` | optional evidence | `fips206-draft-falcon1024-v1`; `Falcon-1024` |",
    )
    for row in exact_rows:
        assert row in text
    for domain in EXPECTED_DOMAINS:
        assert domain in text
    for role in EXPECTED_ROLES:
        assert f"`{role}`" in text

    assert "draft FN-DSA/Falcon-1024 evidence" in text
    assert "It must not be described as final FIPS 206 proof." in text


def test_v49f_qid_and_shield_names_parameters_and_profiles_stay_separate() -> None:
    text = _read(ALIGNMENT)

    required_qid_truth = (
        "`pqc-ml-dsa` | `ML-DSA-44`",
        "`pqc-falcon` | `Falcon-512`",
        "`pqc-hybrid-ml-dsa-falcon` | `ML-DSA-44` plus `Falcon-512`",
        "Q-ID `pqc-ml-dsa` is not Shield `ml-dsa`.",
        "Q-ID `pqc-falcon` is not Shield `fn-dsa`.",
        "Q-ID defaults to `ML-DSA-44`; Shield requires `ML-DSA-65`.",
        "Q-ID defaults to `Falcon-512`; Shield optional evidence uses `Falcon-1024`.",
        "`qid-canonical-json-v1`",
        "`adamantine-qid-canonical-json-v1`",
        "`shield-v4-canon.v1`",
    )
    for fragment in required_qid_truth:
        assert fragment in text

    assert (
        "Naming similarity does not authorize key, role, registry, canonicalization,\n"
        "profile, parameter-set, signature, or authority reuse."
    ) in text


def test_v49f_key_role_policy_authority_and_proof_boundaries_are_locked() -> None:
    text = _read(ALIGNMENT)

    required_boundaries = (
        "A Q-ID identity key must never satisfy a Shield key role.",
        "A Shield key must never satisfy Q-ID identity authority.",
        "Shield `fn-dsa` is optional evidence only.",
        "never replace, rescue, downgrade, or override",
        "does not sign transactions;",
        "does not broadcast transactions;",
        "does not change DigiByte consensus;",
        "produces cryptographically verifiable decision evidence only.",
        "AdamantineOS remains the final fail-closed policy and execution boundary.",
        "verifies against the verifier-controlled Shield registry",
        "It does not prove cross-repository runtime interoperability",
        "Standard CI does not prove live liboqs execution.",
        "`shield-v4-real-oqs.yml` workflow separately proves its guarded",
        "test nodes with zero skips, failures, and errors.",
        "This alignment step makes no Q-ID live-liboqs execution claim.",
    )
    for fragment in required_boundaries:
        assert fragment in text

    assert "pre-implementation alignment lock" not in text
    assert "ecosystem-pre-v4-audit-lock" not in text
    assert "Compatible identifier direction" not in text
    assert "Planned Shield v4 tags" not in text
    assert "## V4.2 Exit Criteria" not in text
    assert "later V4.3" not in text
    assert "No crypto implementation is added in V4.2" not in text


def test_v49f_false_positive_authority_fips_and_live_claims_cannot_coexist() -> None:
    text = _read(ALIGNMENT)
    lowered = " ".join(text.split()).casefold()

    forbidden_positive_claims = (
        "shield v4 signs transactions",
        "shield v4 can sign transactions",
        "shield v4 broadcasts transactions",
        "shield v4 can broadcast transactions",
        "shield v4 changes digibyte consensus",
        "shield v4 grants final execution authority",
        "shield signatures grant final execution authority",
        "q-id identity keys may satisfy a shield",
        "q-id identity keys can satisfy a shield",
        "shield keys may satisfy q-id identity",
        "shield keys can satisfy q-id identity",
        "q-id grants shield execution authority",
        "q-id grants final approval",
        "standard ci proves live liboqs",
        "q-id live-liboqs proof",
        "q-id live-liboqs execution is proven",
        "is final fips 206 compliant",
        "is final fips 206 conformant",
        "provides final fips 206 conformance",
        "proves final fips 206",
    )
    for claim in forbidden_positive_claims:
        assert claim not in lowered

    assert lowered.count("fips 206") == 2
    assert lowered.count("final fips 206") == 2
    assert lowered.count("live liboqs") == 1
    assert lowered.count("live-liboqs") == 1
    assert text.count("does not sign transactions;") == 1
    assert text.count("does not broadcast transactions;") == 1
    assert text.count("does not change DigiByte consensus;") == 1
    assert text.count("produces cryptographically verifiable decision evidence only.") == 1
    assert lowered.count("final execution authority") == 2


def test_v49f_controlled_document_attribution_is_darekdgb_only() -> None:
    attribution_label_words = {
        "architect",
        "architects",
        "assistant",
        "assistants",
        "attribution",
        "attributions",
        "author",
        "authors",
        "authorship",
        "contributor",
        "contributors",
        "copyright",
        "creator",
        "creators",
        "maintainer",
        "maintainers",
        "owner",
        "owners",
    }
    attribution_label_phrases = (
        "created by",
        "developed by",
        "implementation by",
        "prepared by",
        "written by",
    )
    unlabelled_prefixes = (
        "copyright",
        "created by ",
        "developed by ",
        "implementation by ",
        "prepared by ",
        "written by ",
    )
    for path in (ALIGNMENT, *LEGACY_DOCS):
        text = _read(path)
        attribution_lines = []
        for line in text.splitlines():
            normalized = line.strip().replace("**", "").lstrip("#>- ").casefold()
            label = normalized.split(":", 1)[0]
            label_words = set(label.replace("-", " ").split())
            labelled_attribution = ":" in normalized and (
                bool(label_words & attribution_label_words)
                or any(phrase in label for phrase in attribution_label_phrases)
            )
            if labelled_attribution or normalized.startswith(unlabelled_prefixes):
                attribution_lines.append(line)
        assert attribution_lines == ["Author attribution: DarekDGB"]
        assert text.count("DarekDGB") == 1


def test_v49f_production_modules_do_not_import_qid_runtime_code() -> None:
    source_root = ROOT / "src" / "shield_orchestrator"
    forbidden_imports: list[tuple[Path, str]] = []

    for path in sorted(source_root.rglob("*.py")):
        tree = ast.parse(_read(path), filename=str(path))
        importlib_aliases = {"importlib"}
        import_module_aliases: set[str] = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "importlib":
                        importlib_aliases.add(alias.asname or alias.name)
                    if _is_qid_module_name(alias.name):
                        forbidden_imports.append((path.relative_to(ROOT), alias.name))
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if module == "importlib":
                    for alias in node.names:
                        if alias.name == "import_module":
                            import_module_aliases.add(alias.asname or alias.name)
                if _is_qid_module_name(module):
                    forbidden_imports.append((path.relative_to(ROOT), module))

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            is_dynamic_import = isinstance(node.func, ast.Name) and node.func.id in {
                "__import__",
                *import_module_aliases,
            }
            if (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in importlib_aliases
                and node.func.attr in {"import_module", "__import__"}
            ):
                is_dynamic_import = True
            if not is_dynamic_import:
                continue
            if not node.args or not isinstance(node.args[0], ast.Constant):
                forbidden_imports.append((path.relative_to(ROOT), "non-literal dynamic import"))
                continue
            target = node.args[0].value
            if not isinstance(target, str):
                forbidden_imports.append((path.relative_to(ROOT), "non-string dynamic import"))
            elif _is_qid_module_name(target):
                forbidden_imports.append((path.relative_to(ROOT), target))

    assert forbidden_imports == []


def test_v49f_project_metadata_has_no_qid_dependency_and_darekdgb_only_author() -> None:
    project = tomllib.loads(_read(ROOT / "pyproject.toml"))["project"]
    assert project["authors"] == [{"name": "DarekDGB"}]

    dependencies = list(project.get("dependencies", ()))
    for group in project.get("optional-dependencies", {}).values():
        dependencies.extend(group)
    for dependency in dependencies:
        lowered = dependency.casefold().replace("_", "-")
        assert _dependency_name(dependency) not in {"qid", "digibyte-q-id"}
        assert "digibyte-q-id" not in lowered


def test_v49f_controlled_files_are_ascii_safe_strict_utf8() -> None:
    for path in CONTROLLED_FILES:
        raw = path.read_bytes()
        text = raw.decode("utf-8", errors="strict")
        assert text.isascii(), path.relative_to(ROOT)
        assert not raw.startswith(b"\xef\xbb\xbf"), path.relative_to(ROOT)
        assert b"\x00" not in raw, path.relative_to(ROOT)
        assert "\r" not in text, path.relative_to(ROOT)
        assert text.endswith("\n"), path.relative_to(ROOT)
        assert all(line == line.rstrip() for line in text.splitlines())
        headings = [line for line in text.splitlines() if line.startswith("#")]
        assert len(headings) == len(set(headings)), path.relative_to(ROOT)
