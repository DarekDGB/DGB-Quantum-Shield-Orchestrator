from __future__ import annotations

import argparse
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def _count(suite: ET.Element, key: str) -> int:
    raw = suite.attrib.get(key)
    if raw is None or re.fullmatch(r"0|[1-9][0-9]*", raw) is None:
        raise SystemExit(f"invalid JUnit {key} count: {raw!r}")
    return int(raw)


def _suites(root: ET.Element) -> list[ET.Element]:
    if root.tag == "testsuite":
        suites = [root]
    elif root.tag == "testsuites":
        suites = list(root)
        if any(suite.tag != "testsuite" for suite in suites):
            raise SystemExit("real-oqs JUnit guard failed: unexpected root child")
    else:
        raise SystemExit("real-oqs JUnit guard failed: unexpected root element")
    if not suites:
        raise SystemExit("real-oqs JUnit guard failed: no testsuite elements found")
    for suite in suites:
        if any(child.tag not in {"testcase", "properties", "system-out", "system-err"} for child in suite):
            raise SystemExit("real-oqs JUnit guard failed: unexpected or nested suite child")
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
        "--exact-tests",
        type=int,
        help="Require this exact count and one unique required node ID per testcase",
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
    if args.exact_tests is not None:
        if args.exact_tests < args.min_tests:
            raise SystemExit("real-oqs JUnit guard failed: exact count must be >= minimum")
        required = args.require_testcase
        if len(required) != args.exact_tests or len(set(required)) != len(required):
            raise SystemExit("real-oqs JUnit guard failed: exact mode requires a unique complete node list")
        pattern = r"tests/(?:[A-Za-z0-9_]+/)*[A-Za-z0-9_]+\.py::test_[A-Za-z0-9_]+"
        if any(re.fullmatch(pattern, nodeid) is None for nodeid in required):
            raise SystemExit("real-oqs JUnit guard failed: exact mode requires full pytest node IDs")

    path = Path(args.junit_xml)
    if not path.is_file():
        raise SystemExit(f"real-oqs JUnit guard failed: report not found: {path}")

    if path.stat().st_size > 8 * 1024 * 1024:
        raise SystemExit("real-oqs JUnit guard failed: report exceeds 8 MiB")
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as exc:
        raise SystemExit(f"real-oqs JUnit guard failed: malformed XML: {exc}") from exc
    suites = _suites(root)
    cases = _testcases(root)
    direct_cases = [case for suite in suites for case in suite.findall("testcase")]
    if cases != direct_cases:
        raise SystemExit("real-oqs JUnit guard failed: nested testcase elements")
    for case in cases:
        if any(child.tag not in {"properties", "system-out", "system-err", "failure", "error", "skipped"} for child in case):
            raise SystemExit("real-oqs JUnit guard failed: unexpected testcase child")
        for tag in ("failure", "error", "skipped"):
            if case.findall(f".//{tag}") != case.findall(tag):
                raise SystemExit("real-oqs JUnit guard failed: nested outcome element")
    for suite in suites:
        actual = {
            "tests": len(suite.findall("testcase")),
            **{key: sum(case.find(tag) is not None for case in suite.findall("testcase"))
               for key, tag in (("skipped", "skipped"), ("failures", "failure"), ("errors", "error"))},
        }
        for key, value in actual.items():
            if _count(suite, key) != value:
                raise SystemExit(f"real-oqs JUnit guard failed: inconsistent {key} counter")
    tests = sum(_count(suite, "tests") for suite in suites)
    skipped = sum(_count(suite, "skipped") for suite in suites)
    failures = sum(_count(suite, "failures") for suite in suites)
    errors = sum(_count(suite, "errors") for suite in suites)
    if root.tag == "testsuites":
        for key, value in (("tests", tests), ("skipped", skipped), ("failures", failures), ("errors", errors)):
            if key in root.attrib and _count(root, key) != value:
                raise SystemExit(f"real-oqs JUnit guard failed: inconsistent aggregate {key} counter")

    if tests < args.min_tests:
        raise SystemExit(
            f"real-oqs JUnit guard failed: expected at least {args.min_tests} testcase(s), got {tests}",
        )
    if args.exact_tests is not None and tests != args.exact_tests:
        raise SystemExit(f"real-oqs JUnit guard failed: expected exactly {args.exact_tests} testcase(s), got {tests}")
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
    if args.exact_tests is not None:
        seen: set[str] = set()
        required = set(args.require_testcase)
        for testcase in cases:
            file_name = testcase.attrib.get("file")
            classname = testcase.attrib.get("classname")
            if file_name and classname and file_name != classname.replace(".", "/") + ".py":
                raise SystemExit("real-oqs JUnit guard failed: conflicting testcase file identity")
            matches = _nodeid_candidates(testcase) & required
            if len(matches) != 1 or seen & matches:
                raise SystemExit("real-oqs JUnit guard failed: duplicate, ambiguous, or unexpected testcase")
            seen.update(matches)
        if seen != required:
            raise SystemExit("real-oqs JUnit guard failed: exact node set mismatch")

    required_suffix = ""
    if args.require_testcase:
        required_suffix = f" required={len(args.require_testcase)}"
    if args.exact_tests is not None:
        required_suffix += f" exact={args.exact_tests}"
    print(
        f"real-oqs JUnit guard passed: tests={tests} skipped=0 failures=0 errors=0{required_suffix}",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
