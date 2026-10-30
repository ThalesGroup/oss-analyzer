<!--
SPDX-FileCopyrightText: 2026 THALES

SPDX-License-Identifier: MIT
-->

# Changelog

Versions of the `analyze` CI/CD component (semantic versioning; in 0.x, a
breaking change bumps the minor version).

## Unreleased


## 0.4.0

First public release: the `analyze` GitLab CI/CD component and its GitHub
Actions counterpart, a reusable workflow. SBOM (Syft, plus cdxgen for
Maven/Gradle), dependency vulnerabilities (Grype, OSV-Scanner), SAST
(Semgrep, Trivy for IaC), secrets (Gitleaks), container images (Trivy),
licenses (a gate on versioned allow / review / deny lists, REUSE headers),
behind one blocking gate with dated exceptions, an HTML dashboard and
GitLab merge request reports.
