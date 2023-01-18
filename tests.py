import json
import tempfile
import unittest

from sonarqube import (
    load_trivy_report,
    parse_trivy_report,
    make_sonar_issues,
    make_sonar_report,
)


class TestLoadTrivyReport(unittest.TestCase):
    def test_ok(self):
        _, fname = tempfile.mkstemp()
        with open(fname, "w") as fobj:
            fobj.write('{"a":[]}')

        report = load_trivy_report(fname)
        assert report == {"a": []}


class TestParseTrivyReport(unittest.TestCase):
    def test_ok(self):
        vuln1 = {"field1": "value1"}
        vuln2 = {
            "VulnerabilityID": "vuln1",
            "Severity": "severity1",
            "Description": "desc1",
        }
        vuln3 = {
            "VulnerabilityID": "vuln2",
            "Severity": "severity2",
            "Description": "desc2",
        }
        report = {
            "Results": [
                {
                    "Target": "target1",
                    "Vulnerabilities": [
                        vuln1,
                        vuln2,
                    ],
                },
                {
                    "Target": "target2",
                    "Vulnerabilities": [
                        vuln3,
                    ],
                },
            ],
        }

        vulnerabilities = list(parse_trivy_report(report))
        assert vulnerabilities == [
            {
                "VulnerabilityID": "vuln1",
                "Severity": "severity1",
                "Description": "desc1",
                "Target": "target1",
            },
            {
                "VulnerabilityID": "vuln2",
                "Severity": "severity2",
                "Description": "desc2",
                "Target": "target2",
            },
        ]


class TestMakeSonarIssues(unittest.TestCase):
    def test_file_path_override(self):
        vuln1 = {
            "VulnerabilityID": "vuln1",
            "Severity": "LOW",
            "Description": "desc1",
            "Target": "target1",
        }
        vuln2 = {
            "VulnerabilityID": "vuln2",
            "Severity": "MEDIUM",
            "Description": "desc2",
            "Target": "target2",
        }

        issues = make_sonar_issues([vuln1, vuln2], file_path="path1")
        assert issues == [
            {
                "engineId": "Trivy",
                "ruleId": "vuln1",
                "type": "VULNERABILITY",
                "severity": "MINOR",
                "primaryLocation": {
                    "message": "desc1",
                    "filePath": "path1",
                },
            },
            {
                "engineId": "Trivy",
                "ruleId": "vuln2",
                "type": "VULNERABILITY",
                "severity": "MAJOR",
                "primaryLocation": {
                    "message": "desc2",
                    "filePath": "path1",
                },
            },
        ]

    def test_no_file_path_override(self):
        vuln1 = {
            "VulnerabilityID": "vuln1",
            "Severity": "HIGH",
            "Description": "desc1",
            "Target": "target1",
        }
        vuln2 = {
            "VulnerabilityID": "vuln2",
            "Severity": "CRITICAL",
            "Description": "desc2",
            "Target": "target2",
        }

        issues = make_sonar_issues([vuln1, vuln2])
        assert issues == [
            {
                "engineId": "Trivy",
                "ruleId": "vuln1",
                "type": "VULNERABILITY",
                "severity": "CRITICAL",
                "primaryLocation": {
                    "message": "desc1",
                    "filePath": "target1",
                },
            },
            {
                "engineId": "Trivy",
                "ruleId": "vuln2",
                "type": "VULNERABILITY",
                "severity": "BLOCKER",
                "primaryLocation": {
                    "message": "desc2",
                    "filePath": "target2",
                },
            },
        ]


class TestMakeSonarReport(unittest.TestCase):
    def test_ok(self):
        issues = [1, True, "three"]
        report = make_sonar_report(issues)
        assert json.loads(report) == {"issues": [1, True, "three"]}


if __name__ == "__main__":
    unittest.main()
