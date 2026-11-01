"""Run unittest suite with deterministic JUnit XML output for CI.

Uses Python standard library only; test failure detail stays in CI artefacts.
"""
from __future__ import annotations

import argparse
import sys
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


class ReportingResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.records = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.records.append((str(test), "pass", ""))

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.records.append((str(test), "failure", self._exc_info_to_string(err, test)))

    def addError(self, test, err):
        super().addError(test, err)
        self.records.append((str(test), "error", self._exc_info_to_string(err, test)))

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.records.append((str(test), "skipped", reason))

    def addExpectedFailure(self, test, err):
        super().addExpectedFailure(test, err)
        self.records.append((str(test), "skipped", "expected failure"))

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test)
        self.records.append((str(test), "failure", "unexpected success"))


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="test-results/unittest.xml")
    args = parser.parse_args(argv)
    suite = unittest.defaultTestLoader.discover("tests")
    runner = unittest.TextTestRunner(verbosity=2, resultclass=ReportingResult)
    result = runner.run(suite)
    root = ET.Element("testsuite", {
        "name": "OGDE unittest",
        "tests": str(result.testsRun),
        "failures": str(len(result.failures) + len(result.unexpectedSuccesses)),
        "errors": str(len(result.errors)),
        "skipped": str(len(result.skipped) + len(result.expectedFailures)),
    })
    for name, status, detail in result.records:
        case = ET.SubElement(root, "testcase", {"name": name})
        if status != "pass":
            tag = "failure" if status == "failure" else status
            ET.SubElement(case, tag, {"message": status}).text = detail
    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(root).write(destination, encoding="utf-8", xml_declaration=True)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
