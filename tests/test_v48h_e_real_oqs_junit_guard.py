from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest


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


NODES = ["tests/test_live.py::test_mldsa", "tests/test_live.py::test_falcon"]


def _exact_guard(path: Path, nodes: list[str] | None = None) -> subprocess.CompletedProcess[str]:
    args = ["--min-tests", "2", "--exact-tests", "2"]
    for node in NODES if nodes is None else nodes:
        args.extend(["--require-testcase", node])
    return _run_guard(path, *args)


@pytest.mark.parametrize("wrapper", [False, True])
def test_v410i1_exact_guard_accepts_real_pytest_xml_layouts(tmp_path: Path, wrapper: bool) -> None:
    path = tmp_path / "report.xml"
    _write_junit(path, NODES)
    if wrapper:
        suite = ET.parse(path).getroot()
        root = ET.Element("testsuites")
        root.append(suite)
        ET.ElementTree(root).write(path)
    result = _exact_guard(path)
    assert result.returncode == 0, result.stderr
    assert "tests=2 skipped=0 failures=0 errors=0 required=2 exact=2" in result.stdout


@pytest.mark.parametrize("mode", [
    "hidden-failure", "hidden-error", "hidden-skip", "failure", "error", "skip",
    "inflated-tests", "missing-counter", "negative-counter", "noninteger-counter",
    "extra-case", "duplicate-case", "wrong-node", "ambiguous-identity",
    "nested-suite", "nested-case", "wrong-root", "missing-suite", "aggregate-lie",
    "malformed-xml", "missing-report", "oversize-report", "duplicate-required",
    "short-required", "bare-required", "invalid-exact-count",
    "conflicting-file", "nested-outcome", "unknown-case-child",
])
def test_v410i1_exact_guard_rejects_invalid_proof_reports(tmp_path: Path, mode: str) -> None:
    path = tmp_path / "report.xml"
    _write_junit(path, NODES)
    root = ET.parse(path).getroot()
    first, second = root.findall("testcase")
    if mode.startswith("hidden-") or mode in {"failure", "error", "skip"}:
        tag = mode.removeprefix("hidden-").replace("skip", "skipped")
        ET.SubElement(first, tag).text = "probe"
        if not mode.startswith("hidden-"):
            root.set({"failure": "failures", "error": "errors", "skipped": "skipped"}[tag], "1")
    elif mode == "inflated-tests":
        root.set("tests", "100")
    elif mode == "missing-counter":
        del root.attrib["errors"]
    elif mode == "negative-counter":
        root.set("errors", "-1")
    elif mode == "noninteger-counter":
        root.set("tests", "2.0")
    elif mode == "extra-case":
        ET.SubElement(root, "testcase", {"classname": "tests.other", "name": "test_extra"})
        root.set("tests", "3")
    elif mode == "duplicate-case":
        second.attrib.update(first.attrib)
    elif mode == "wrong-node":
        second.set("name", "test_unrelated")
    elif mode == "ambiguous-identity":
        first.set("name", "test_mldsa")
        first.set("file", "tests/other.py")
    elif mode == "conflicting-file":
        first.set("file", "tests/other.py")
    elif mode == "nested-outcome":
        ET.SubElement(ET.SubElement(first, "properties"), "failure").text = "hidden failure"
    elif mode == "unknown-case-child":
        ET.SubElement(first, "unexpected")
    elif mode == "nested-suite":
        ET.SubElement(root, "testsuite", {"tests": "0", "skipped": "0", "failures": "0", "errors": "0"})
    elif mode == "nested-case":
        ET.SubElement(first, "testcase", {"classname": "tests.extra", "name": "test_hidden"})
    elif mode == "wrong-root":
        root.tag = "report"
    elif mode == "missing-suite":
        root = ET.Element("testsuites")
    elif mode == "aggregate-lie":
        wrapper = ET.Element("testsuites", {"tests": "0"})
        wrapper.append(root)
        root = wrapper
    ET.ElementTree(root).write(path)
    if mode == "malformed-xml":
        path.write_text("<testsuite>")
    elif mode == "missing-report":
        path.unlink()
    elif mode == "oversize-report":
        path.write_bytes(b" " * (8 * 1024 * 1024 + 1))
    nodes = NODES
    if mode == "duplicate-required":
        nodes = [NODES[0], NODES[0]]
    elif mode == "short-required":
        nodes = [NODES[0]]
    elif mode == "bare-required":
        nodes = ["test_mldsa", "test_falcon"]
    elif mode == "ambiguous-identity":
        nodes = [NODES[0], "tests/other.py::test_mldsa"]
    if mode == "invalid-exact-count":
        result = _run_guard(path, "--exact-tests", "0")
    else:
        result = _exact_guard(path, nodes)
    assert result.returncode != 0, mode
    assert "guard passed" not in result.stdout


def test_v410i1_guard_checks_children_even_without_exact_mode(tmp_path: Path) -> None:
    path = tmp_path / "report.xml"
    _write_junit(path, NODES)
    root = ET.parse(path).getroot()
    ET.SubElement(root.find("testcase"), "failure").text = "hidden failure"
    ET.ElementTree(root).write(path)
    result = _run_guard(path, "--min-tests", "2")
    assert result.returncode != 0
    assert "inconsistent failures counter" in result.stderr
