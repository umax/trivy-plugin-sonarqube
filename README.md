# trivy-plugin-sonarqube

A [Trivy](https://github.com/aquasecurity/trivy) plugin that converts JSON report to [SonarQube](https://sonarqube.org) format. The idea is to scan project dependencies with Trivy and post results to SonarQube through external issues report. This way you can get code scanning and dependency scanning results in one place.


## Installation

install plugin:
```
$ trivy plugin install github.com/umax/trivy-plugin-sonarqube
```

check the installation:
```
$ trivy plugin list
```

NOTE: you need [Python](https://www.python.org/) interpreter installed to be able to run plugin.


## Usage

run `trivy` with JSON report enabled:
```
$ trivy fs --format=json --output=trivy.json PATH
```

convert Trivy report to SonarQube compatible report:
```
$ trivy sonarqube trivy.json > sonarqube.json
```

redefine `filePath` field of SonarQube result. For example, if you scan Dockerfile with `trivy image` command, `filePath` field will contain url of docker image instead of file name. As result, SonarQube will skip this report, because docker image url is not a source file in terms of SonarQube. `--filePath` option allows you to set Dockefile name:
```
$ trivy sonarqube trivy.json -- filePath=Dockerfile > sonarqube.json
```

## GitLab CI

Here is a small example how to use this plugin in GitLab CI to post Trivy results to SonarQube.

```
scan-deps:
  stage: scan
  image:
    name: aquasec/trivy
    entrypoint: [""]
  before_script:
    - apk add --no-cache python3
    - trivy plugin install github.com/umax/trivy-plugin-sonarqube
  script:
    - trivy fs
      --security-checks=vuln
      --vuln-type=library
      --exit-code=0
      --format=json
      --output=trivy-deps-report.json
      .
    - trivy sonarqube trivy-deps-report.json > sonar-deps-report.json
  artifacts:
    paths:
      - trivy-deps-report.json
      - sonar-deps-report.json

scan-code:
  stage: scan
  image: sonarsource/sonar-scanner-cli
  needs:
    - scan-deps
  script:
    - sonar-scanner -D sonar.externalIssuesReportPaths="sonar-deps-report.json" ...
```
