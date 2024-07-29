#!/usr/bin/env python3

import json
import os
import sys

LOG_PREFIX = "[trivy][plugins][sonarqube]"
TRIVY_SONARQUBE_SEVERITY = {
    "UNKNOWN": "LOW",
    "LOW": "LOW",
    "MEDIUM": "LOW",
    "HIGH": "MEDIUM",
    "CRITICAL": "HIGH",
}


def load_trivy_report(fname):
    with open(fname) as fobj:
        return json.loads(fobj.read())


def parse_trivy_report(report):
    for result in report.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            try:
                vuln["Target"] = result["Target"]
                for key in (
                    "VulnerabilityID",
                    "Title",
                    "Description",
                    "Severity",
                    "PrimaryURL",
                ):
                    vuln[key]
            except KeyError:
                continue

            yield vuln


def make_sonar_issues(vulnerabilities, file_path=None):
    seen_rules = set()
    res = {"rules": [], "issues": []}
    for vuln in vulnerabilities:
        if vuln["VulnerabilityID"] not in seen_rules:
            res["rules"].append(
                {
                    "id": vuln["VulnerabilityID"],
                    "name": vuln["Title"],
                    "description": vuln["Description"],
                    "engineId": "Trivy",
                    "cleanCodeAttribute": "LOGICAL",
                    "impacts": [
                        {
                            "softwareQuality": "SECURITY",
                            "severity": TRIVY_SONARQUBE_SEVERITY[vuln["Severity"]],
                        }
                    ],
                }
            )
            seen_rules.add(vuln["VulnerabilityID"])
        res["issues"].append(
            {
                "ruleId": vuln["VulnerabilityID"],
                "primaryLocation": {
                    "message": f"{vuln['Description']} Details: {vuln['PrimaryURL']}",
                    "filePath": file_path or vuln["Target"],
                },
            }
        )
    return res


def make_sonar_report(res):
    return json.dumps(res, indent=2)


def main(args):
    fname = args[1]
    if not os.path.exists(fname):
        sys.exit(f"{LOG_PREFIX} file not found: {fname}")

    arg_filePath = None
    for arg in args[2:]:
        if "filePath" in arg:
            arg_filePath = arg.split("=")[-1].strip()

    report = load_trivy_report(fname)
    vulnerabilities = parse_trivy_report(report)
    res = make_sonar_issues(vulnerabilities, file_path=arg_filePath)
    report = make_sonar_report(res)
    print(report)


if __name__ == "__main__":
    main(sys.argv)
