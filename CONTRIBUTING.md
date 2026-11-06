<!--
SPDX-FileCopyrightText: 2026 THALES

SPDX-License-Identifier: MIT
-->

# Contributing guidelines

Thanks for your interest in oss-analyzer. Bug reports, ideas and pull
requests are welcome. Please read this first: **pull requests are not
merged on GitHub**, and here is why and what happens instead.

## Team organization

oss-analyzer is developed in its maintainers' own upstream repository.
This GitHub repository is its **public mirror**: each change of the
`main` branch is a sync from upstream, one commit per release, without
the detailed history. So that both repositories never diverge, `main`
only moves through those syncs. A pull request is never merged here,
even when it's accepted.

The [GitLab](https://gitlab.com/gitlab-org/gitlab) project
[gitlab.com/thalesgroup/oss-analyzer](https://gitlab.com/thalesgroup/oss-analyzer),
which serves the CI/CD component and its image, is a read-only copy of
this repository, updated with each sync: issues and pull requests go
here.

### Roles

- **Maintainers** review issues and pull requests, integrate accepted
  pull requests upstream, publish the releases and handle security
  reports ([SECURITY.md](SECURITY.md)).
- **Contributors** open issues and pull requests, and discuss them here.

### Communication

Everything happens on this repository: issues for bugs and ideas, pull
requests for changes, private vulnerability reporting for security
issues. Everyone follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## How to become a contributor

### Contributor License Agreements

There is no CLA to sign. By contributing, you agree that your
contribution is licensed under the [MIT License](LICENSE), like the rest
of the project, and that you have the right to submit it.

### Contributing code

1. **Open an issue first** for anything beyond a small fix, to check the
   change fits before you spend time on it.
2. **Review here.** The discussion, the review comments and the changes
   you push all happen on the pull request, as usual.
3. **Integration upstream.** Once accepted, the maintainers bring your
   commits into the upstream repository, with you as their author. They
   may adjust them there (a rebase, a conflict), and tell you on the pull
   request if they change anything significant.
4. **Publication.** The next sync to `main` carries your change. Its
   commit lists the pull requests it integrates (`Integrates #42.`) and
   credits you with a `Co-authored-by:` trailer, so the contribution shows
   on your GitHub profile.
5. **Closing.** Your pull request is then **closed, not merged**, with a
   comment linking to that commit. That's the expected outcome of an
   accepted pull request in this repository, not a rejection.

A declined pull request is closed with an explanation, as anywhere else.

Between steps 3 and 5, the change exists upstream but isn't public yet:
syncs happen with releases, so expect days or weeks rather than minutes.
Please don't rebase an accepted pull request onto a newer `main` at that
point, unless asked to.

## Pull Request Checklist

### License

Every new file carries the two [SPDX](https://spdx.dev/) tags, `SPDX-FileCopyrightText` and
`SPDX-License-Identifier` with the MIT license (or a `.license` file next
to it), as [REUSE](https://reuse.software/) checks.

### Coding style

- **Keep it focused**: one topic per pull request, small commits with a
  clear message. Each commit is integrated as is, with its message.
- **Keep the docs true**: comments, `README.md`, `security/README.md`,
  and an entry under `## Unreleased` in `CHANGELOG.md` for any visible
  change.

### Testing

Python 3.11+, with `security/scripts/requirements.txt` installed.

#### Running unit tests

```bash
python -m unittest discover -s security/tests
```

#### Running sanity check

The license gate on its deterministic fixture, in both modes (see
[data/test/README.md](data/test/README.md)):

```bash
for mode in enforce audit; do
  OSA_MODE=$mode python security/scripts/license_gate.py \
    --sbom data/test/sbom-fixture.cdx.json \
    --policy data/test/policy-fixture.yml \
    --output-dir /tmp/fixture-$mode > /dev/null
done
python data/test/check_license_fixture.py \
  /tmp/fixture-enforce/licenses.json /tmp/fixture-audit/licenses.json \
  data/test/sbom-fixture.expected.json
```

### Issues management

- Search the existing issues before opening one.
- A bug report says the oss-analyzer version, the platform (GitLab
  component, GitHub workflow or local script), what happened and what
  was expected, with the relevant job log.
- **Security issues** never go in a public issue: see
  [SECURITY.md](SECURITY.md).

## The default license lists

`security/policy-licenses.yml` is a generic baseline, classified on public
criteria. It isn't legal advice, and organizations are expected to
replace or complete it. Pull requests that fix an obvious mistake in it
are welcome; changes to a verdict that depends on a legal reading
(copyleft, source-available, field-of-use) are better proposed in an
issue first.
