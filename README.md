# trivy-plugin-sonarqube

A [Trivy](https://github.com/aquasecurity/trivy) plugin that converts JSON report to SonarQube format. The idea is to scan project dependencies with Trivy and post results to SonarQube through external issues report. This way you can get code scanning and dependency scanning results in one place.


## Install

```
$ trivy plugin install github.com/umax/trivy-plugin-sonarqube
```

## Usage

```
$ trivy sonarqube trivy-report.json > sq-report.json
```