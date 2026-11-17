#!/usr/bin/env python3
"""Compare JSON reports from two disdetta binaries over repository directories."""

import argparse
import json
import os
import subprocess
import sys


def run(binary, repository):
    command = [binary, "scan", repository, "--format", "json", "--fail-on", "none"]
    return subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          check=False)


def finding_keys(report):
    result = set()
    for finding in report.get("findings", []):
        location = finding.get("location", {})
        result.add((finding.get("ruleId", ""), location.get("path", ""),
                    location.get("line", 0), location.get("column", 0)))
    return result


def format_finding(finding):
    rule, path, line, column = finding
    return "%s %s:%s:%s" % (rule, path, line, column)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--findings", action="store_true",
                        help="list findings gained and lost in differing reports")
    parser.add_argument("old")
    parser.add_argument("new")
    parser.add_argument("repositories", nargs="+")
    args = parser.parse_args()

    differences = 0
    errors = 0
    for repository in sorted(args.repositories, key=os.fspath):
        try:
            old_run = run(args.old, repository)
            new_run = run(args.new, repository)
        except OSError as error:
            print("%s: could not run binary (%s)" % (repository, error))
            errors += 1
            continue
        # Exit codes 0 to 3 are scan results (3 is an incomplete scan); other
        # codes are a usage error or a crash and the comparison is meaningless.
        if old_run.returncode > 3 or new_run.returncode > 3 or old_run.returncode < 0 or new_run.returncode < 0:
            print("%s: binary failed (old=%s, new=%s)" %
                  (repository, old_run.returncode, new_run.returncode))
            errors += 1
            continue
        if old_run.stdout == new_run.stdout and old_run.returncode == new_run.returncode:
            continue
        differences += 1
        print(repository)
        if old_run.returncode != new_run.returncode:
            print("  exit code: old=%s new=%s" % (old_run.returncode, new_run.returncode))
        if args.findings:
            try:
                old_report = json.loads(old_run.stdout)
                new_report = json.loads(new_run.stdout)
            except json.JSONDecodeError as error:
                print("  findings unavailable: invalid JSON (%s)" % error)
            else:
                for finding in sorted(finding_keys(new_report) - finding_keys(old_report)):
                    print("  new %s" % format_finding(finding))
                for finding in sorted(finding_keys(old_report) - finding_keys(new_report)):
                    print("  lost %s" % format_finding(finding))
    print("compared %d, differences %d" % (len(args.repositories), differences))
    return 2 if errors else (1 if differences else 0)


if __name__ == "__main__":
    sys.exit(main())
