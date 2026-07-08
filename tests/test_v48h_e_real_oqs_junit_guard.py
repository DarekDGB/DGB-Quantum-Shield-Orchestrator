from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from xml.etree import ElementTree as ET


SCRIPT = "assert_real_oqs_junit_not_skipped.py"


def _repo_root() -> Path:
    current = Path(__file__).resolve()
    for candidate in current.parents:
        if (candidate / "scripts" / SCRIPT).is_file():
            return candidate
    raise AssertionError(f"could not find scripts/{SCRIPT}")


def _write_junit(path: Path, nodeids: list[str]) -> None:
    root = ET.Element(
        "testsuite",
        {
            "name": "real-oqs",
            "tests": str(len(nodeids)),
            "skipped": "0",
            "failures": "0",
            "errors": "0",
        },
    )
    for nodeid in nodeids:
        module_path, test_name = nodeid.split("::", 1)
        classname = module_path.removesuffix(".py").replace("/", ".")
        ET.SubElement(root, "testcase", {"classname": classname, "name": test_name})
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)


def _run_guard(junit: Path, *args: str) -> subprocess.CompletedProcess[str]:
    root = _repo_root()
    return subprocess.run(
        [sys.executable, str(root / "scripts" / SCRIPT), str(junit), *args],
        check=False,
        text=True,
        capture_output=True,
    )


def test_real_oqs_guard_requires_specific_mldsa_and_falcon_nodeids(tmp_path: Path) -> None:
    mldsa = "tests/test_real_oqs_mldsa.py::test_live_mldsa_proof"
    falcon = "tests/test_real_oqs_falcon.py::test_live_falcon1024_proof"
    junit = tmp_path / "real-oqs.xml"
    _write_junit(junit, [mldsa, falcon])

    result = _run_guard(
        junit,
        "--min-tests",
        "2",
        "--require-testcase",
        mldsa,
        "--require-testcase",
        falcon,
    )

    assert result.returncode == 0, result.stderr
    assert "required=2" in result.stdout


def test_real_oqs_guard_rejects_silently_uncollected_falcon_nodeid(tmp_path: Path) -> None:
    mldsa = "tests/test_real_oqs_mldsa.py::test_live_mldsa_proof"
    falcon = "tests/test_real_oqs_falcon.py::test_live_falcon1024_proof"
    junit = tmp_path / "real-oqs.xml"
    _write_junit(junit, [mldsa])

    result = _run_guard(
        junit,
        "--min-tests",
        "1",
        "--require-testcase",
        mldsa,
        "--require-testcase",
        falcon,
    )

    assert result.returncode != 0
    assert "required testcase(s) missing" in result.stderr
    assert falcon in result.stderr


def test_real_oqs_guard_rejects_too_few_testcases_even_without_skips(tmp_path: Path) -> None:
    mldsa = "tests/test_real_oqs_mldsa.py::test_live_mldsa_proof"
    junit = tmp_path / "real-oqs.xml"
    _write_junit(junit, [mldsa])

    result = _run_guard(junit, "--min-tests", "2", "--require-testcase", mldsa)

    assert result.returncode != 0
    assert "expected at least 2 testcase(s)" in result.stderr
