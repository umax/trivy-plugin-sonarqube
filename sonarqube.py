#!/usr/bin/env python3

import json
import os
import sys

LOG_PREFIX = '[trivy][plugins][sonarqube]'
TRIVY_SONARQUBE_SEVERITY = {
    'UNKNOWN': 'INFO',
    'LOW': 'MINOR',
    'MEDIUM': 'MAJOR',
    'HIGH': 'CRITICAL',
    'CRITICAL': 'BLOCKER',
}

fname = sys.argv[1]
if not os.path.exists(fname):
    sys.exit('%s file not found: %s' % (LOG_PREFIX, fname))

arg_filePath = None
for arg in sys.argv[2:]:
    if 'filePath' in arg:
        arg_filePath = arg.split('=')[-1].strip()

issues = []
report = json.load(open(fname))
for result in report.get('Results', []):
    for vuln in result.get('Vulnerabilities', []):
        try:
            issues.append({
                'engineId': 'Trivy',
                'ruleId': vuln['VulnerabilityID'],
                'type': 'VULNERABILITY',
                'severity': TRIVY_SONARQUBE_SEVERITY[vuln['Severity']],
                'primaryLocation': {
                    'message': vuln['Description'],
                    'filePath': arg_filePath or result['Target'],
                }
            })
        except KeyError:
            continue

print(json.dumps({'issues': issues}, indent=2))
