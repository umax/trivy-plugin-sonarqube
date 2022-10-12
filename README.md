# trivy-plugin-sonarqube

A [Trivy](https://github.com/aquasecurity/trivy) plugin that converts JSON report to SonarQube format


## Install

```
$ trivy plugin install github.com/umax/trivy-plugin-sonarqube
```

## Usage

```
$ trivy sonarqube trivy-report.json sonarqube-report.json
```