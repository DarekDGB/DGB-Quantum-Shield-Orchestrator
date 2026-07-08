from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def _count(suite: ET.Element, key: str) -> int:
    raw = suite.attrib.get(key, "0")
    try:
        return int(raw)
    except ValueError as exc:
        raise SystemExit(f"invalid JUnit {key} count: {raw!r}") from exc


def _suites(root: ET.Element) -> list[ET.Element]:
    if root.tag == "testsuite":
        return [root]
    suites = list(root.findall(".//testsuite"))
    if not suites:
        raise SystemExit("real-oqs JUnit guard failed: no testsuite elements found")
    return suites


def _testcases(root: ET.Element) -> list[ET.Element]:
    return list(root.findall(".//testcase"))


def _nodeid_candidates(testcase: ET.Element) -> set[str]:
    """Return stable pytest-nodeid candidates from a JUnit testcase element."""

    name = testcase.attrib.get("name", "")
    classname = testcase.attrib.get("classname", "")
    file_name = testcase.attrib.get("file", "")
    candidates: set[str] = set()

    if name:
        candidates.add(name)
    if classname and name:
        candidates.add(f"{classname}::{name}")
        class_path = classname.replace(".", "/")
        if not class_path.endswith(".py"):
            class_path = f"{class_path}.py"
        candidates.add(f"{class_path}::{name}")
    if file_name and name:
        candidates.add(f"{file_name}::{name}")

    return candidates


def _present_nodeids(root: ET.Element) -> set[str]:
    present: set[str] = set()
    for testcase in _testcases(root):
        present.update(_nodeid_candidates(testcase))
    return present


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Fail a dedicated Shield v4 real-liboqs job if its JUnit report silently "
            "skipped, missed, or dropped required proof tests."
        ),
    )
    parser.add_argument("junit_xml", help="Path to pytest --junitxml output from the real-liboqs job")
    parser.add_argument(
        "--min-tests",
        type=int,
        default=1,
        help="Minimum testcase count expected in the real-liboqs proof job",
    )
    parser.add_argument(
        "--require-testcase",
        action="append",
        default=[],
        help=(
            "Required pytest node id that must appear in the JUnit report. "
            "May be repeated. Example: tests/test_real.py::test_live_proof"
        ),
    )
    args = parser.parse_args(argv)

    if args.min_tests < 1:
        raise SystemExit("real-oqs JUnit guard failed: --min-tests must be >= 1")

    path = Path(args.junit_xml)
    if not path.is_file():
        raise SystemExit(f"real-oqs JUnit guard failed: report not found: {path}")

    root = ET.parse(path).getroot()
    suites = _suites(root)
    tests = sum(_count(suite, "tests") for suite in suites)
    skipped = sum(_count(suite, "skipped") for suite in suites)
    failures = sum(_count(suite, "failures") for suite in suites)
    errors = sum(_count(suite, "errors") for suite in suites)

    if tests < args.min_tests:
        raise SystemExit(
            f"real-oqs JUnit guard failed: expected at least {args.min_tests} testcase(s), got {tests}",
        )
    if skipped != 0:
        raise SystemExit(f"real-oqs JUnit guard failed: skipped must be 0, got {skipped}")
    if failures != 0 or errors != 0:
        raise SystemExit(
            f"real-oqs JUnit guard failed: failures={failures} errors={errors}; both must be 0",
        )

    present = _present_nodeids(root)
    missing = [nodeid for nodeid in args.require_testcase if nodeid not in present]
    if missing:
        rendered = ", ".join(missing)
        raise SystemExit(f"real-oqs JUnit guard failed: required testcase(s) missing: {rendered}")

    required_suffix = ""
    if args.require_testcase:
        required_suffix = f" required={len(args.require_testcase)}"
    print(
        f"real-oqs JUnit guard passed: tests={tests} skipped=0 failures=0 errors=0{required_suffix}",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
