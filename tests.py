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
            "Title": "title1",
            "Description": "desc1",
            "Severity": "severity1",
            "PrimaryURL": "url1",
        }
        vuln3 = {
            "VulnerabilityID": "vuln2",
            "Title": "title2",
            "Description": "desc2",
            "Severity": "severity2",
            "PrimaryURL": "url2",
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
                'VulnerabilityID': 'vuln1',
                'Title': 'title1',
                'Description': 'desc1',
                'Severity': 'severity1',
                'PrimaryURL': 'url1',
                'Target': 'target1'
            },
            {
                'VulnerabilityID': 'vuln2',
                'Title': 'title2',
                'Description': 'desc2',
                'Severity': 'severity2',
                'PrimaryURL': 'url2',
                'Target': 'target2'
            }
        ]


class TestMakeSonarIssues(unittest.TestCase):
    def test_file_path_override(self):
        vuln1 = {
            "VulnerabilityID": "vuln1",
            "Title": "title1",
            "Description": "desc1",
            "Severity": "LOW",
            "PrimaryURL": "url1",
            "Target": "target1",
        }
        vuln2 = {
            "VulnerabilityID": "vuln2",
            "Title": "title2",
            "Description": "desc2",
            "Severity": "CRITICAL",
            "PrimaryURL": "url2",
            "Target": "target2",
        }

        res = make_sonar_issues([vuln1, vuln2], file_path="path1")
        assert res == {
            'rules': [
                {
                    'id': 'vuln1',
                    'name': 'title1',
                    'description': 'desc1',
                    'engineId': 'Trivy',
                    'cleanCodeAttribute': 'LOGICAL',
                    'impacts': [{
                        'softwareQuality': 'SECURITY',
                        'severity': 'LOW'
                    }]
                }, {
                    'id': 'vuln2',
                    'name': 'title2',
                    'description': 'desc2',
                    'engineId': 'Trivy',
                    'cleanCodeAttribute': 'LOGICAL',
                    'impacts': [{
                         'softwareQuality': 'SECURITY',
                         'severity': 'HIGH'
                    }]
                }
            ],
            'issues': [
                {
                'ruleId': 'vuln1',
                'primaryLocation': {
                    'message': 'desc1 Details: url1',
                    'filePath': 'path1'
                    }
                }, {
                'ruleId': 'vuln2',
                'primaryLocation': {
                    'message': 'desc2 Details: url2',
                    'filePath': 'path1'
                    }
                }
            ]
        }

    def test_no_file_path_override(self):
        vuln1 = {
            "VulnerabilityID": "vuln1",
            "Title": "title1",
            "Description": "desc1",
            "Severity": "LOW",
            "PrimaryURL": "url1",
            "Target": "target1",
        }
        vuln2 = {
            "VulnerabilityID": "vuln2",
            "Title": "title2",
            "Description": "desc2",
            "Severity": "CRITICAL",
            "PrimaryURL": "url2",
            "Target": "target2",
        }

        res = make_sonar_issues([vuln1, vuln2])
        assert res == {
            'rules': [
                {
                    'id': 'vuln1',
                    'name': 'title1',
                    'description': 'desc1',
                    'engineId': 'Trivy',
                    'cleanCodeAttribute': 'LOGICAL',
                    'impacts': [{
                        'softwareQuality': 'SECURITY',
                        'severity': 'LOW'
                    }]
                }, {
                    'id': 'vuln2',
                    'name': 'title2',
                    'description': 'desc2',
                    'engineId': 'Trivy',
                    'cleanCodeAttribute': 'LOGICAL',
                    'impacts': [{
                         'softwareQuality': 'SECURITY',
                         'severity': 'HIGH'
                    }]
                }
            ],
            'issues': [
                {
                'ruleId': 'vuln1',
                'primaryLocation': {
                    'message': 'desc1 Details: url1',
                    'filePath': 'target1'
                    }
                }, {
                'ruleId': 'vuln2',
                'primaryLocation': {
                    'message': 'desc2 Details: url2',
                    'filePath': 'target2'
                    }
                }
            ]
        }


class TestMakeSonarReport(unittest.TestCase):
    def test_ok(self):
        issues = [1, True, "three"]
        report = make_sonar_report(issues)
        assert json.loads(report) == [1, True, "three"]


if __name__ == "__main__":
    unittest.main()
