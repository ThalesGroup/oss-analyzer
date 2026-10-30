<!--
SPDX-FileCopyrightText: 2026 THALES

SPDX-License-Identifier: MIT
-->

# Code analysis suite — vulnerabilities, secrets, licenses

100% Open Source chain for [GitLab](https://gitlab.com/gitlab-org/gitlab) CI or GitHub Actions, polyglot (Go,
Rust, Java/JVM, Python, JS/TS, C/C++). No paid service, no code sent
to a third party.

## The principle

A single **[CycloneDX](https://cyclonedx.org/) SBOM** is produced at the start of the pipeline by
[Syft](https://github.com/anchore/syft); the vulnerability scanners, the license control and continuous
monitoring all consume it, so they never disagree on the inventory.

```
sbom ──> scan (parallel) ──────────────> gate
Syft     Grype    (SCA, reference)        license_gate.py
         OSV      (SCA, second opinion)   aggregate_report.py  ← sole blocker
         Semgrep  (SAST)                  ↓
         Gitleaks (secrets)               security-report.md
         Trivy    (containers, IaC)
```

Scan jobs are all `allow_failure: true`: they collect, they don't judge.
The verdict is rendered once, in `osa_report_aggregate`, after applying the
policy and its exceptions.

## The tools

| Role | Tool | Why this one |
|---|---|---|
| SBOM | **[Syft](https://github.com/anchore/syft)** | Detects every ecosystem with no configuration, [CycloneDX](https://cyclonedx.org/) + [SPDX](https://spdx.dev/) output |
| SCA | **[Grype](https://github.com/anchore/grype)** | Consumes the SBOM directly, reliable `fix.state` |
| SCA (2nd opinion) | **[OSV-Scanner](https://github.com/google/osv-scanner)** | Better data for Go and Rust; overlap with [Grype](https://github.com/anchore/grype) is deduplicated in the report (one finding per component and advisory, matched by ID or alias) |
| SAST | **[Semgrep](https://github.com/semgrep/semgrep)** | Multi-language OSS engine, readable and extensible rules |
| Secrets | **[Gitleaks](https://github.com/gitleaks/gitleaks)** | Scans the git history, not just the working tree |
| Containers/IaC | **[Trivy](https://github.com/aquasecurity/trivy)** | Images, Dockerfile, [k8s](https://kubernetes.io/) manifests, [Terraform](https://github.com/hashicorp/terraform) |
| License headers | **[REUSE](https://reuse.software/)** | Checks the [SPDX](https://spdx.dev/) headers of *this repo's own* files (not third-party licenses) |
| Continuous monitoring | **[Dependency-Track](https://github.com/DependencyTrack/dependency-track)** | Re-scans the SBOM when new CVEs are published, without a rebuild |

**C/C++**: SCA works when the project uses **[Conan](https://conan.io/)** or **vcpkg**. With
vendored dependencies, only SAST ([Semgrep](https://github.com/semgrep/semgrep), `p/c` + in-house rules) covers
the code.

## Installation

### GitLab CI: the `analyze` component

A single `include`, no file to copy, scripts versioned with the component
(they ship in its image) — see
[Use it as a GitLab CI/CD component](../README.md#use-it-as-a-gitlab-cicd-component).
If your runners can't pull from the public registries, first point the
`OSA_<TOOL>_IMAGE` inputs at a mirror — see
[Container images](#container-images).
Then:

1. Create a weekly CI/CD schedule (`0 3 * * 1`): it replays the chain
   against fresh databases and runs the heavy job (`osa_licenses_deep`).
2. First run on a project with a backlog: `OSA_MODE: audit` reports
   everything and blocks nothing; then switch back to `enforce`, possibly
   one policy category at a time (`mode:` per category).
3. To customize the defaults, add settings files to `security/` — see
   [Customizing oss-analyzer](../README.md#customizing-oss-analyzer).
4. [GitLab Pages](https://docs.gitlab.com/user/project/pages/): the component's `osa_pages` job (`OSA_ENABLE_PAGES:
   true`) only produces a `public/` artifact, for the project's own
   `pages` job to publish — see that job's comment in
   [templates/analyze.yml](../templates/analyze.yml).

The include works from any project that can read `oss-analyzer`. From a
Private copy, allow the target project under **Settings > CI/CD > Token
Access** — an include failing with "reference not found" usually means
the project can't read it.

### GitHub Actions

[.github/workflows/security.yml](../.github/workflows/security.yml) is the
same chain as a reusable workflow (`on: workflow_call`).

1. Nothing to copy: the workflow's jobs check out oss-analyzer itself
   (scripts and organization defaults) next to the caller's code. The
   caller only keeps its own settings files, if any, in `security/` (the
   `settings-dir` input): as with the component, each one completes the
   defaults — see [Customizing oss-analyzer](../README.md#customizing-oss-analyzer).
2. Add a caller workflow, telling the workflow where oss-analyzer is, with
   the same ref as in `uses:` (a called workflow can't reliably know its
   own repository and ref) — see
   [security-caller.yml](../.github/workflows/security-caller.yml) for the
   same-repository case, where both inputs stay empty. oss-analyzer's
   GitHub repository is `ThalesGroup/oss-analyzer`:
   ```yaml
   on:
     pull_request:
     push:
       branches: [main]
     schedule:
       - cron: "0 3 * * 1"
   jobs:
     security:
       uses: ThalesGroup/oss-analyzer/.github/workflows/security.yml@<ref>
       with:
         oss-analyzer-repository: ThalesGroup/oss-analyzer
         oss-analyzer-ref: <ref>
       permissions:
         contents: read
         pull-requests: write
   ```
   A public oss-analyzer repository needs nothing more: the jobs check it
   out with the caller's `GITHUB_TOKEN`. That token only reads the caller's
   own repository, so a private or internal oss-analyzer needs both its
   *Settings > Actions > Access* granting the caller (for `uses:`) and a
   token able to read it — a fine-grained PAT with *Contents: read* on
   oss-analyzer alone, or a GitHub App token — stored as a caller secret
   and passed next to `with:`:
   ```yaml
       secrets:
         OSS_ANALYZER_TOKEN: ${{ secrets.OSS_ANALYZER_TOKEN }}
   ```
3. To actually block a PR, make the `gate` job a **required status
   check** in the branch protection rules.

The report is a `security-report` workflow artifact, summarized in a PR
comment. Images are still on public `:latest` tags, not the versions the
GitLab component pins, and Pages publishing isn't wired up on the GitHub
side. `licenses-deep` runs [Trivy](https://github.com/aquasecurity/trivy) offline ([Maven Central](https://central.sonatype.com/) throttles
GitHub-hosted runners), so it only reports licenses found in the files
themselves (vendored or copy-pasted code), none for dependencies:
those are checked by `licenses-gate`, from the SBOM.

### Container images

Every tool image is **pinned to a tested version**, declared in two
places to keep in sync: the `OSA_<TOOL>_IMAGE` inputs of
[templates/analyze.yml](../templates/analyze.yml) and the top of
`security/scripts/analyze-archive.sh`.

**Images are pulled from their public registries** ([Docker Hub](https://hub.docker.com/), ghcr.io).
Behind a registry mirror or a pull-through cache, override the
`OSA_<TOOL>_IMAGE` inputs. If it needs credentials, give the runner a
`DOCKER_AUTH_CONFIG` CI/CD variable (GitLab Runner's own, read to pull
each job's `image:`), with the secret in a masked variable it references.

**Locally, `analyze-archive.sh` uses the public registries** (no
`docker login` needed). Each image can be overridden
through `SYFT_IMAGE`, `GRYPE_IMAGE`, `OSV_IMAGE`, `SEMGREP_IMAGE`,
`GITLEAKS_IMAGE`, `TRIVY_IMAGE`, `REUSE_IMAGE`, `CDXGEN_IMAGE`,
`CYCLONEDX_CLI_IMAGE`.

**Upgrading a tool**: check the new tag is served
(`docker buildx imagetools inspect docker.io/<image>:<tag>`),
then update both places.

---

## Usage

### Analyzing a project archive (outside CI)

```bash
security/scripts/analyze-archive.sh [--no-dashboard] [--no-project-dashboard] [--deep-licenses] <archive.zip|archive.tar.gz|folder> [output-folder]
```

- Accepts a `.zip`, `.tar.gz`/`.tgz`, `.tar` or an extracted folder.
- Uses each tool natively if installed, otherwise its [Docker](https://www.docker.com/) image.
  Only [Syft](https://github.com/anchore/syft) is mandatory (no SBOM, no analysis).
- Writes `security-report.md/.json`, `licenses.md/.json`, `coverage.json`
  and each tool's raw output to
  `security-reports/<project>/<timestamp>/` (default root:
  `<repo-root>/security-reports`, wherever you run it from). Runs are
  never overwritten.
- Regenerates two dashboards: `<project>/dashboard-<project>.html`
  (this project only — the one to hand to a project team) and
  `dashboard.html` (all projects, with trend over runs).
  `--no-dashboard` skips both, `--no-project-dashboard` the first one.
- Exits with the gate's code: `0` pass, `1` policy violated.
- `--deep-licenses` adds a slow, file-by-file [Trivy](https://github.com/aquasecurity/trivy) license scan
  (`trivy-licenses.json`, reviewed manually — not used by the gate).


**Reduced coverage**: a skipped or failed tool doesn't stop the chain,
but it's reported — `WARNING` in the terminal, `coverage.json`, and a
**⚠️ Reduced coverage** section in the report. The verdict is unchanged:
a ✅ then means "nothing found by the tools that ran".

In CI, the other way round: the pipeline knows which scanners it enabled
and passes them to `aggregate_report.py --expect` — [Trivy](https://github.com/aquasecurity/trivy)'s IaC report too
when a Dockerfile exists ([Trivy](https://github.com/aquasecurity/trivy) only runs then). A missing, empty,
unreadable report from one of them, or one that isn't that scanner's report
(an error document or a placeholder such as `{}` left by a failed run: each
report must have its tool's structure, e.g. [Grype](https://github.com/anchore/grype)'s `matches`) is an
**⛔ Incomplete coverage** gap — a scan that didn't happen must not read as
"nothing found". It blocks the gate in `enforce` mode of the policy section
the scanner feeds (`vulnerabilities` for [Grype](https://github.com/anchore/grype)/OSV, `sast` for [Semgrep](https://github.com/semgrep/semgrep) and
[Trivy](https://github.com/aquasecurity/trivy) IaC, `secrets` for [Gitleaks](https://github.com/gitleaks/gitleaks), `licenses` for the license gate), and
only warns in `audit` mode. Jobs failing on the runner's side (runner lost,
job not picked up) are retried automatically, twice, before that.

**Windows**: run the script from Git Bash
(`security/scripts/analyze-archive.sh D:\Downloads\project.zip`) or WSL
(`wsl bash security/scripts/analyze-archive.sh /mnt/d/...`), with [Docker](https://www.docker.com/)
Desktop running for the [Docker](https://www.docker.com/) fallback.

To regenerate a dashboard by hand (plain Python, any shell):

```bash
python security/scripts/generate_dashboard.py --reports-root security-reports [--output ...] [--project <name>]
```

### In a Merge Request (CI usage)

The pipeline runs on every MR.

- **`osa_report_aggregate`** is the only job that can turn the MR red; its
  log prints `security-report.md`. Orange scan jobs are expected.
- **`osa_report_dashboard`** generates `dashboard.html` whatever the
  verdict (findings most severe first, one tab per category after ALL,
  one expandable group per component with a bar of its critical / high /
  medium / low shares, a Licenses tab listing the components the license
  gate didn't allow, a Fix availability chart), linked as **"OSS security dashboard"** in the MR pipeline
  widget. `osa_pages` (`OSA_ENABLE_PAGES: true`) hands it to the project's
  own `pages` job on the default branch only — check your Pages
  visibility, the dashboard lists findings.
- **`osa_report_gitlab_native`** fills the MR **Reports** tab from the
  same findings as the gate: Security scan (dependencies, secrets —
  Ultimate) and Code Quality (SAST, secrets, IaC — every edition). Without
  Ultimate nothing breaks, Code Quality still shows. Set
  `OSA_ENABLE_GITLAB_REPORTS: false` to skip it (e.g. GitLab's own
  analyzers already run). Vulnerabilities left in the Vulnerability Report
  by a previous scanner are never auto-resolved — resolve them by hand
  when switching.
- **`osa_report_mr_comment`** (`OSA_ENABLE_MR_COMMENT: true`, MR pipelines
  only) posts the verdict, the counts, the blocking findings and the
  dashboard link as a comment on the MR, one per MR (and per
  `OSA_JOB_SUFFIX`), updated by every pipeline. `CI_JOB_TOKEN` can't write
  comments: create a project access token (scope `api`, role Reporter) and
  store it as a masked `OSA_GITLAB_TOKEN` CI/CD variable. Without it, the
  job warns in its log and stays green.
- Everything else is in each job's artifacts, under `security-reports/`:
  each job publishes only the files it writes (the SBOMs in the SBOM
  jobs, `<scanner>.json` in each scanner, `licenses.*` in
  `osa_licenses_gate`, `security-report.*` in `osa_report_aggregate`).
  A job of yours reading one of them needs the job that writes it.

### Differences between the two usages

The engine is the same on both sides. **Anything added to CI (GitLab or
GitHub) must also run through `analyze-archive.sh`, and vice versa** —
the table lists the deliberate exceptions.

| | CI | Local |
|---|---|---|
| SBOM / SCA / SAST / secrets / [Trivy](https://github.com/aquasecurity/trivy) / [REUSE](https://reuse.software/) | ✅ | ✅ |
| C/C++ registry rules (`p/c`) | ✅ | ⚠️ in-house rules only (no registry call) |
| Deep license scan | ⏳ `osa_licenses_deep`, schedule/manual by default (GitHub: `licenses-deep`, schedule/`workflow_dispatch`) | ⏳ `--deep-licenses` only |
| Dashboard | ✅ one run per pipeline | ✅ history, trend, multi-project portfolio |
| GitLab native MR reports | ✅ GitLab only | ❌ n/a (the dashboard carries the same findings) |
| [Dependency-Track](https://github.com/DependencyTrack/dependency-track) | ⚠️ once `OSA_ENABLE_DTRACK` and `OSA_DTRACK_URL` are set | ❌ |

### Handling a gate failure

- **Vulnerability (SCA)**: bump the dependency if a fix exists; otherwise,
  if the vulnerable code isn't reachable, add an exception.
- **SAST ([Semgrep](https://github.com/semgrep/semgrep))**: fix the code, or mark a false positive with
  `// nosemgrep: <rule-id>` on the line rather than a global exception.
- **Secret ([Gitleaks](https://github.com/gitleaks/gitleaks))**: **revoke it first**, then clean up the history.
  Never whitelisted in `policy-global.yml`; `policy-gitleaks.toml`'s
  allowlist is only for structural false positives (doc examples,
  fixtures).
- **License**: see [Licenses](#licenses-the-decision-framework), then
  switch dependency or add an exception.

Exceptions live in `security/policy-global.yml`. Each needs an
`expires` date (an unquoted YAML date): without one, or once expired, it
is ignored with a warning and the finding blocks again. `reason` and
`approved_by` aren't checked by the scripts — they're for the merge
request review, which should refuse an exception without them.

```yaml
vulnerabilities:
  exceptions:
    - id: CVE-2024-12345
      reason: "Vulnerable function never reached — reachability analysis from 03/12"
      approved_by: "first.last"
      expires: 2026-12-31
licenses:
  exceptions:
    - package: "pkg:npm/some-gpl-tool@2.1.0"
      license: GPL-3.0-only
      reason: "Build tool only — never shipped in the delivered artifact"
      approved_by: "first.last"
      expires: 2027-01-01
```

### Base policy, audit mode

With the CI/CD component, this repository's settings files
(`security/policy-*`) are the **organization defaults**, embedded in the
oss-analyzer image; a project's own files complete them — see the README's
[Customizing oss-analyzer](../README.md#customizing-oss-analyzer) for every
facet. For the policy, a project's `policy-global.yml` only holds its
differences, merged on top by `security/scripts/policy.py` (through
`prepare_settings.py`): its settings win, its exceptions add up, and a
license it lists leaves the base's other lists. `meta.inherit: false` applies
the project's policy alone. The job log of `osa_prepare` prints, for each
facet, where it comes from, plus the distribution model and modes.

Each of `vulnerabilities`, `sast`, `secrets` and `licenses` accepts
`mode: enforce | audit` (default: the component's `OSA_MODE` input,
`enforce`). In audit mode, findings that would block are reported as
"would block in enforce mode" and the pipeline passes — e.g. block secrets
right away while clearing a CVE backlog.

`licenses.by_distribution_model.<model>` reclassifies licenses for one
distribution model on top of the common lists. The organization base has
none: the same lists apply whatever the model, which is only shown in
the reports. A project may add its own, for the model in use
(`meta.distribution_model` or the component's `OSA_DISTRIBUTION_MODEL`).
Precedence, most specific last: the base's common lists, then the
project's common lists (merge), then the project's **model** rules
(applied after the merge).

### New findings only (`OSA_GATE_SCOPE: new`)

Audit mode never blocks, so a project with a backlog would let new
findings in while clearing the old ones. With the component's
`OSA_GATE_SCOPE: new` input, the gate blocks only what a merge request
brings:

- **On a merge request**, `osa_report_aggregate` downloads its own
  `security-report.json` from the target branch's latest successful
  pipeline (`fetch_baseline.py`, with the job's `CI_JOB_TOKEN`). A finding
  already there is reported as **existing**, in "Already on the target
  branch", and doesn't block; a new one blocks as usual. How findings are
  matched:
  - a code finding (SAST) by rule and file, not line: a moved line isn't
    new, a second occurrence in the same file is;
  - a dependency vulnerability by its purl, version included: upgrading a
    component that keeps the same CVE counts as new;
  - a license violation by the component's purl without its version: a
    version bump doesn't change the license;
  - a secret never: [Gitleaks](https://github.com/gitleaks/gitleaks) only scans the merge request's commits, so
    what it finds there is new, and a rotated credential in the same file
    must not pass for the old one.
  On a merge request from a fork, the baseline is read from the target
  project; if the fork's job token can't read it, the full gate applies.
- **No baseline** (no successful pipeline on the target branch yet, its
  artifacts expired after 90 days, or the API refused): the full gate
  applies, every finding counts as new, and the report says so.
- **Outside a merge request** (default branch, tags, schedules), there is
  nothing to compare with: findings and license violations are reported as
  "would block" without failing the pipeline. That keeps the default branch
  green, which also keeps its report usable as the next merge requests'
  baseline. It also means **a project without merge request pipelines gets
  no blocking gate at all** with this scope: keep `all` there.
- **Coverage gaps** (an expected scanner with no report) block in every case.

The baseline is the target branch's latest report, not the merge base: a
CVE published since that pipeline shows as new on the merge request until
the target branch runs again (a schedule on the default branch keeps it
fresh). The GitHub reusable workflow doesn't offer this scope.

---

## Licenses: the decision framework

The allow / review / deny lists live in `policy-licenses.yml`, which
`policy-global.yml` pulls in (`licenses.lists_file`, relative to the
policy). oss-analyzer ships a generic baseline of common licenses,
classified on public criteria: permissive and public-domain licenses →
`allow`; weak and strong copyleft, source-available and field-of-use
licenses → `review`; non-commercial ones → `deny`. So strong copyleft
(GPL, AGPL) and SSPL are `review`, not `deny`: with
`fail_on_review: false`, only non-commercial licenses block. A license
missing from the lists gets `unknown`.

The baseline is a starting point, not legal advice: replace it with your
organization's decisions in your build of oss-analyzer, or reclassify
licenses per project in the project's own `policy-licenses.yml`. Keep the
file's group comments (`# SPDX identifiers`...): `build_license_catalog.py`
reads them back (`scripts/license_lists.py`). A decision that depends on
the context, such as a GPL component in a service that's never shipped,
goes through a license exception (`licenses.exceptions`) or a project's
own lists.

### How the script decides

- The whole label is looked up first: a listed license name holding an
  operator word ("MATPLOTLIB License 1.3.0 or Later") is a license, not
  an expression.
- Otherwise it's split on the [SPDX](https://spdx.dev/) operators, uppercase only, as [SPDX](https://spdx.dev/)
  defines them: `OR` keeps the most permissive option, `AND` the most
  restrictive. Lowercase `or` / `and` are words: an unlisted name holding
  them is reported whole in "Unclassified licenses", never split.
- Several entries in a component's `licenses` array are treated as `OR`
  (`MIT OR Apache-2.0` on most Rust crates). Check the multi-license
  components in `licenses.md` if your context requires `AND`.
- `X WITH Y` not listed as-is falls back to the base license `X` only when
  `Y` is an [SPDX](https://spdx.dev/) license exception (`Classpath-exception-2.0`,
  `LLVM-exception`...), which only adds permissions. A restricting clause
  (`Apache-2.0 WITH Commons-Clause`) or an unknown one isn't dropped: the
  label gets `unknown` and is reported.
- Non-SPDX labels (`"Apache License, Version 2.0"`) are normalized via an
  alias table (`scripts/license_ids.py`), to extend from the report's
  "Unclassified licenses" section. The policy merge uses the same
  normalization: a project listing `Apache License 2.0` reclassifies the
  base's `Apache-2.0`.

### Completing the lists: the license catalog

The lists don't cover every [SPDX](https://spdx.dev/) identifier; the rest falls to
`unknown`. `build_license_catalog.py` drafts a verdict for every [SPDX](https://spdx.dev/)
identifier, for legal review (candidates to add to the lists):

```bash
python security/scripts/build_license_catalog.py --policy security/policy-global.yml \
  --gate-report security-reports/licenses.json \
  --output-dir security-reports/license-catalog
```

- Verdict sources, by precedence: the policy's own lists, then the
  [ScanCode LicenseDB](https://scancode-licensedb.aboutcode.org/) category
  (`CATEGORY_VERDICT` in the script), then the policy's `unknown`.
- `license-catalog.md` lists what to decide: the policy's choices [ScanCode](https://github.com/aboutcode-org/scancode-licensedb)
  disagrees with (e.g. `JSON`, Permissive for [ScanCode](https://github.com/aboutcode-org/scancode-licensedb)), the policy entries
  that aren't [SPDX](https://spdx.dev/) identifiers and look like a mistake (a misspelled [SPDX](https://spdx.dev/)
  ID, a stale or unknown `LicenseRef` key), with the [ScanCode](https://github.com/aboutcode-org/scancode-licensedb) `LicenseRef`
  key to use instead, the [SPDX](https://spdx.dev/) identifiers [ScanCode](https://github.com/aboutcode-org/scancode-licensedb) doesn't classify, and the labels
  the given gate reports left unclassified (`--gate-report`, repeatable).
  The non-SPDX entries written on purpose are only counted, and listed in
  `license-catalog.json` (`not_spdx_expected`): the `LicenseRef` keys of
  live [ScanCode](https://github.com/aboutcode-org/scancode-licensedb) licenses, and the listed names of licenses with no [SPDX](https://spdx.dev/)
  identifier (the "Names of licenses..." group of `policy-licenses.yml`).
- `license-catalog.yml` is the draft `licenses:` lists, a comment on each
  line giving its source. Nothing is written into the policy.
- Sources are downloaded from the [SPDX](https://spdx.dev/) and [ScanCode](https://github.com/aboutcode-org/scancode-licensedb) GitHub repositories;
  `--spdx-licenses`, `--spdx-exceptions` and `--scancode` take local files
  instead, for offline runs.

---

## Known pitfalls

- **[cdxgen](https://github.com/CycloneDX/cdxgen) and [Maven Central](https://central.sonatype.com/)**: `osa_sbom_cdxgen` resolves [Maven](https://maven.apache.org/)/[Gradle](https://github.com/gradle/gradle)
  dependencies from the repositories the project's build uses — [Maven](https://maven.apache.org/)
  Central by default, which throttles shared runner IPs (`429 Too Many
  Requests`) and then makes the resolver wait silently. The job is
  bounded (10 minutes) and best-effort: past that, or on any failure,
  `osa_sbom_merge` goes on with [Syft](https://github.com/anchore/syft)'s SBOM alone, which misses transitive
  dependencies pulled in through a parent/BOM import; both jobs' logs say
  so.
  `OSA_MAVEN_MIRROR_URL` avoids it for [Maven](https://maven.apache.org/), by mirroring `central`
  through a remote (proxy) of [Maven Central](https://central.sonatype.com/) in your artifact repository:

  ```yaml
  include:
    - component: $CI_SERVER_FQDN/thalesgroup/oss-analyzer/analyze@0.4
      inputs:
        OSA_MAVEN_MIRROR_URL: https://repo.example.com/maven2
  variables:
    OSA_MAVEN_MIRROR_AUTH: $MAVEN_MIRROR_AUTH   # base64 of user:secret
  ```

  Use a remote that mirrors `repo.maven.apache.org` as is, not a virtual
  repository aggregating several: those may serve POMs and
  `maven-metadata.xml` files that differ from Central's.
  `OSA_MAVEN_MIRROR_AUTH` is a masked CI/CD variable, or a reference to
  one as above; an anonymous mirror needs none.
  Repositories the project declares itself are still used directly.
  [Gradle](https://github.com/gradle/gradle) builds aren't covered.
- **[Semgrep](https://github.com/semgrep/semgrep) registry packs** (`sast.registry_packs`, `p/...`) are
  downloaded from the registry: on a runner without internet, list local
  rule files instead (a path to a clone of `semgrep-rules`), or empty the
  list and rely on `policy-semgrep.yml`.
- **[Gitleaks](https://github.com/gitleaks/gitleaks) needs `GIT_DEPTH: 0`** to see secrets removed from the code
  but still in history. On MR pipelines it only scans the MR's commit
  range, elsewhere the whole history of the commit built (`HEAD`), so a
  secret on an unrelated branch never fails the pipeline.
- **GitLab Security scan and License compliance reports** need Ultimate;
  Code Quality works on every edition. The artifacts and job log carry
  the same information.
- **`ignore_unfixed: true`** lists unfixed vulnerabilities in their own
  section, but without [Dependency-Track](https://github.com/DependencyTrack/dependency-track) nobody is notified when a fix
  ships.
- **A scanner that finds nothing** is more often misconfigured than
  reassuring — check the SBOM (`syft ... -o table`) first.
