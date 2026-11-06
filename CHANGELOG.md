<!--
SPDX-FileCopyrightText: 2026 THALES

SPDX-License-Identifier: MIT
-->

# Changelog

Versions of the `analyze` CI/CD component (semantic versioning; in 0.x, a
breaking change bumps the minor version).

## Unreleased


## 0.4.2

The component works on the Docker executor. No input or setting to
change: `@0.4` picks it up.

### Fixed

- The component runs on the Docker executor (gitlab.com's shared runners,
  most self-managed runners): every tool image is used with
  `entrypoint: [""]`. `osa_containers_trivy`, `osa_licenses_reuse` and
  `osa_licenses_deep` failed there ("unknown command sh": the job's shell
  was passed to the tool's ENTRYPOINT), which blocked the gate on a
  missing report; cdxgen and cyclonedx-cli were exposed the same way.

## 0.4.1

The component published on gitlab.com, and tests on GitHub pull
requests. No input or setting to change: `@0.4` picks it up.

### Added

- The `analyze` component is published on gitlab.com:
  `gitlab.com/thalesgroup/oss-analyzer/analyze`, its image on
  `registry.gitlab.com/thalesgroup/oss-analyzer` (the default of
  `OSA_IMAGE_REPOSITORY`). A self-managed instance mirrors the project
  (see `README.md`).
- `.github/workflows/tests.yml`: the unit tests and the license test on
  every pull request and on `main`.


## 0.4.0

First public release: the `analyze` GitLab CI/CD component and its GitHub
Actions counterpart, a reusable workflow. SBOM (Syft, plus cdxgen for
Maven/Gradle), dependency vulnerabilities (Grype, OSV-Scanner), SAST
(Semgrep, Trivy for IaC), secrets (Gitleaks), container images (Trivy),
licenses (a gate on versioned allow / review / deny lists, REUSE headers),
behind one blocking gate with dated exceptions, an HTML dashboard and
GitLab merge request reports.
