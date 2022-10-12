#!/usr/bin/env python3

import json
import os
import sys

TRIVY_SONARQUBE_SEVERITY = {
    'UNKNOWN': 'INFO',
    'LOW': 'MINOR',
    'MEDIUM': 'MAJOR',
    'HIGH': 'CRITICAL',
    'CRITICAL': 'BLOCKER',
}

fname = sys.argv[1]
if not os.path.exists(fname):
    sys.exit('file not found: "%s"' % fname)

issues = []
report = json.load(open(fname))
for result in report['Results']:
    for vuln in result['Vulnerabilities']:
        issues.append({
            'engineId': 'Trivy',
            'ruleId': vuln['VulnerabilityID'],
            'type': 'VULNERABILITY',
            'severity': TRIVY_SONARQUBE_SEVERITY[vuln['Severity']],
            'primaryLocation': {
                'message': vuln['Description'],
                'filePath': result['Target'],
            }
        })

print(json.dumps({'issues': issues}, indent=2))
