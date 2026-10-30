<!--
SPDX-FileCopyrightText: 2026 THALES

SPDX-License-Identifier: MIT
-->

# Security Policy

oss-analyzer runs in your CI with read access to your code, and decides
whether a pipeline passes: a flaw in it matters. This page says how to
report one and how fixes are published.

## Good practices to follow

:warning: **Never store credentials in source code or in a configuration
file of a repository**, this one included.

- oss-analyzer itself scans the whole git history for secrets ([Gitleaks](https://github.com/gitleaks/gitleaks)):
  run it on your merge requests, and on this repository's pull requests.
- Keep every token oss-analyzer uses in a masked CI/CD variable or a
  GitHub secret, never in a settings file (see
  [Security related configuration](#security-related-configuration)).

## Supported Versions

Security fixes are made on the latest minor version only.

| Version | Supported          |
| ------- | ------------------ |
| 0.4.x   | :white_check_mark: |
| < 0.4   | :x:                |

## Reporting a Vulnerability

Please **don't** report a vulnerability in a public issue or pull request.
Use GitHub's private vulnerability reporting instead: the repository's
*Security* tab, *Report a vulnerability*. If you can't, write to
oss@thalesgroup.com.

Include the affected version, how to reproduce it and its impact as you
see it. The maintainers acknowledge the report, keep you informed of its
analysis, and tell you whether it is accepted or declined, and why.

## Disclosure policy

The report stays private until a fix is published. The maintainers agree
on a disclosure date with the reporter, publish the fix and a GitHub
security advisory together, and credit the reporter unless they prefer
not to be named.

## Security Update policy

A fix ships as a patch release of the latest minor version (`@0.4`
follows its patches), described in [CHANGELOG.md](CHANGELOG.md) and in a
GitHub security advisory on this repository. Watch the repository's
releases and advisories to be notified.

## Security related configuration

- **Tokens**: none is needed by default. The merge request summary
  comment needs a project access token (scope `api`, role Reporter) in a
  masked `OSA_GITLAB_TOKEN` CI/CD variable; the [Dependency-Track](https://github.com/DependencyTrack/dependency-track) upload a
  masked `DTRACK_API_KEY`; a private copy of oss-analyzer called from
  GitHub a fine-grained token with *Contents: read* on that copy alone.
  Give each one the least access it needs.
- **What leaves your CI**: no source code. The scanners download their
  vulnerability databases and the [Semgrep](https://github.com/semgrep/semgrep) registry rule packs ([Semgrep](https://github.com/semgrep/semgrep)
  metrics are turned off); [OSV-Scanner](https://github.com/google/osv-scanner) queries the [OSV.dev](https://osv.dev/) API with the
  names and versions of your dependencies. The SBOM goes to
  [Dependency-Track](https://github.com/DependencyTrack/dependency-track) only when you enable that upload, to your own
  instance.
- **Images**: the [GitLab](https://gitlab.com/gitlab-org/gitlab) component pins every scanner image to a tested
  version. Behind a registry mirror, point the `OSA_<TOOL>_IMAGE` inputs
  at images you trust.
- **Exceptions**: an exception to the policy needs a reason, an approver
  and an expiry date; review them in merge requests like code.

## Known security gaps & future enhancements

- The GitHub reusable workflow runs the scanners from their `:latest`
  image tags, not pinned versions as the GitLab component does.

Contributions that close a gap are welcome: see
[CONTRIBUTING.md](CONTRIBUTING.md).
