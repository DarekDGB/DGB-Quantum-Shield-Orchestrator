"""V4.10-I1 native evidence boundaries. Author attribution: DarekDGB."""
from __future__ import annotations

import ast
from pathlib import Path
import re
import textwrap

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/shield-v4-real-oqs.yml"
PINS = (
    "5a1a854b0dc9f2141bdc771c555ee60c37950183",
    "c6378cd5c8db74c0adf34ddcfbb96ee9c99f8061",
)
NODES = (
    "tests/test_v48g_real_oqs_mldsa_backend.py::test_v48g_real_oqs_mldsa65_orchestrator_backend_round_trip_and_negatives",
    "tests/test_v48h_e_real_oqs_falcon_backend.py::test_v48h_e_real_oqs_falcon1024_backend_round_trip_and_negatives",
)


def test_v410i1_workflow_pins_sources_actions_and_exact_proof_nodes() -> None:
    source = WORKFLOW.read_text(encoding="utf-8")
    pins = re.findall(r'^      LIBOQS(?:_PYTHON)?_COMMIT: "([a-f0-9]+)"$', source, re.M)
    assert tuple(pins) == PINS
    assert tuple(re.findall(r'--require-testcase "([^"]+)"', source)) == NODES
    assert "--min-tests 2" in source and "--exact-tests 2" in source
    assert "runs-on: ubuntu-24.04" in source
    assert 'python-version: "3.11.15"' in source
    assert 'SHIELD_V4_REAL_OQS: "1"' in source
    assert 'SHIELD_V4_REAL_OQS_FALCON: "1"' in source
    assert re.findall(r"uses: ([^\s]+)", source) == [
        "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
        "actions/setup-python@42375524e23c412d93fb67b49958b491fce71c38",
        "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
    ]
    for node in NODES:
        path, name = node.split("::")
        tree = ast.parse((ROOT / path).read_text())
        assert name in {n.name for n in tree.body if isinstance(n, ast.FunctionDef)}
    for pin, variable in zip(PINS, ("LIBOQS_COMMIT", "LIBOQS_PYTHON_COMMIT")):
        assert f'fetch --depth 1 origin "${variable}"' in source
        assert f'= "${variable}"' in source
        assert pin in (ROOT / "docs/v4/SHIELD_V4_REAL_CRYPTO_BACKEND.md").read_text()


def test_v410i1_proof_failures_and_artifact_identity_remain_visible() -> None:
    source = WORKFLOW.read_text(encoding="utf-8")
    assert "continue-on-error" not in source
    assert "contents: read" in source and "persist-credentials: false" in source
    assert "shell: bash" in source and "set -euo pipefail" in source
    assert "if-no-files-found: error" in source and "retention-days: 90" in source
    assert "shield-v4-real-oqs-${{ github.sha }}-${{ github.run_attempt }}" in source
    assert "oqs.native()._handle != loaded._handle" in source
    assert 'head != os.environ["GITHUB_SHA"]' in source
    for name in ("collection.txt", "guard.txt", "environment.json", "SHA256SUMS", "liboqs.so"):
        assert name in source
    assert 'p.name != "SHA256SUMS"' in source
    for title in ("Assert real liboqs proof was not skipped", "Hash retained proof files", "Retain native proof evidence"):
        assert f"- name: {title}\n        if: always()" in source
    for relative in (
        "tests/test_v48h_e_real_oqs_junit_guard.py",
        "tests/test_v410i1_native_evidence_workflow_lock.py",
    ):
        assert source.count(f'- "{relative}"') == 2


def test_v410i1_all_workflow_python_blocks_parse() -> None:
    source = WORKFLOW.read_text(encoding="utf-8")
    blocks = re.findall(r"          python - <<'PY'\n(.*?)          PY\n", source, re.S)
    assert len(blocks) == 2
    for block in blocks:
        ast.parse(textwrap.dedent(block))


def test_v410i1_transfer_payloads_are_ascii_lf_and_nonempty() -> None:
    for relative in (
        ".github/workflows/shield-v4-real-oqs.yml",
        "scripts/assert_real_oqs_junit_not_skipped.py",
        "tests/test_v48h_e_real_oqs_junit_guard.py",
        "tests/test_v410i1_native_evidence_workflow_lock.py",
        "docs/v4/SHIELD_V4_REAL_CRYPTO_BACKEND.md",
        "docs/v4/SHIELD_V4_PROOF_PACK.md",
        "docs/v4/SHIELD_V4_RELEASE_STATUS_v4.0.0.md",
    ):
        payload = (ROOT / relative).read_bytes()
        text = payload.decode("ascii", errors="strict")
        assert payload and payload.endswith(b"\n")
        assert b"\r" not in payload and b"\x00" not in payload
        assert all(line == line.rstrip() for line in text.splitlines())
