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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fail a dedicated Shield v4 real-liboqs job if its JUnit report silently skipped tests.",
    )
    parser.add_argument("junit_xml", help="Path to pytest --junitxml output from the real-liboqs job")
    args = parser.parse_args(argv)

    path = Path(args.junit_xml)
    if not path.is_file():
        raise SystemExit(f"real-oqs JUnit guard failed: report not found: {path}")

    root = ET.parse(path).getroot()
    suites = _suites(root)
    tests = sum(_count(suite, "tests") for suite in suites)
    skipped = sum(_count(suite, "skipped") for suite in suites)
    failures = sum(_count(suite, "failures") for suite in suites)
    errors = sum(_count(suite, "errors") for suite in suites)

    if tests < 1:
        raise SystemExit("real-oqs JUnit guard failed: at least one testcase must be collected")
    if skipped != 0:
        raise SystemExit(f"real-oqs JUnit guard failed: skipped must be 0, got {skipped}")
    if failures != 0 or errors != 0:
        raise SystemExit(
            f"real-oqs JUnit guard failed: failures={failures} errors={errors}; both must be 0",
        )

    print(f"real-oqs JUnit guard passed: tests={tests} skipped=0 failures=0 errors=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
