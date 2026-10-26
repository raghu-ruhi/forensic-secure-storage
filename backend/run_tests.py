#!/usr/bin/env python3
"""Run the whole backend test-suite and print/write a summary.

    cd backend
    pip install -r requirements-dev.txt
    python run_tests.py            # Windows CMD / PowerShell / Linux - same command

Outputs: test-results/junit.xml and test-results/summary.md (passed / failed /
skipped, per test module, and the reason for every skip). The exit code is
pytest's, so CI can fail on any failure.
"""
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "test-results")


def main(argv):
    os.makedirs(OUT, exist_ok=True)
    junit = os.path.join(OUT, "junit.xml")
    code = subprocess.call([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                            f"--junitxml={junit}", *argv], cwd=HERE)
    if not os.path.exists(junit):
        print("pytest produced no report (collection error?)")
        return code or 1

    per_module = defaultdict(lambda: {"passed": 0, "failed": 0, "skipped": 0})
    skips, failures = [], []
    seconds = 0.0
    for case in ET.parse(junit).getroot().iter("testcase"):
        module = case.get("classname", "").split(".")[-1] or "?"
        seconds += float(case.get("time", 0))
        name = f"{module}::{case.get('name')}"
        if case.find("failure") is not None or case.find("error") is not None:
            per_module[module]["failed"] += 1
            failures.append(name)
        elif case.find("skipped") is not None:
            per_module[module]["skipped"] += 1
            skips.append(f"{name} - {case.find('skipped').get('message', '')}")
        else:
            per_module[module]["passed"] += 1

    total = {k: sum(m[k] for m in per_module.values()) for k in ("passed", "failed", "skipped")}
    lines = ["# Test summary", "", f"**{total['passed']} passed, {total['failed']} failed, "
             f"{total['skipped']} skipped** in {seconds:.1f}s (sum of test times)", "",
             "| module | passed | failed | skipped |", "|---|---:|---:|---:|"]
    for module in sorted(per_module):
        m = per_module[module]
        lines.append(f"| {module} | {m['passed']} | {m['failed']} | {m['skipped']} |")
    if failures:
        lines += ["", "## Failed", *[f"- {f}" for f in failures]]
    if skips:
        lines += ["", "## Skipped (with reason)", *[f"- {s}" for s in skips]]
    text = "\n".join(lines) + "\n"
    with open(os.path.join(OUT, "summary.md"), "w", encoding="utf-8") as fh:
        fh.write(text)
    print("\n" + text)
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
