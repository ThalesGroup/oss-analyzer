#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 THALES
#
# SPDX-License-Identifier: MIT

# =============================================================================
# Analyzes a project delivered as an archive (.zip, .tar.gz/.tgz) or as an
# already-extracted folder, outside CI, with the same chain as the GitLab
# pipeline (sbom -> scan -> gate).
#
# Uses native binaries if they're installed (syft, grype, osv-scanner,
# semgrep, gitleaks); otherwise automatically falls back to the Docker
# images, same versions as the CI/CD component (templates/analyze.yml). Docker is
# only required for tools that aren't installed natively.
#
# Every run is archived in its own timestamped folder under
# [root-folder]/<project-name>/<YYYYMMDD-HHMMSS>/ — one folder per analyzed
# project, one sub-folder per run. The history accumulates from one run to
# the next instead of being overwritten. Two HTML dashboards
# (generate_dashboard.py) are regenerated at the end of every run:
#   - [root-folder]/<project-name>/dashboard-<project-name>.html, scoped to
#     this project alone — the one to hand to a project team (skip it with
#     --no-project-dashboard);
#   - [root-folder]/dashboard.html, the shared cross-project overview.
# --no-dashboard disables both.
#
# Usage:
#   security/scripts/analyze-archive.sh [--no-dashboard] [--no-project-dashboard] [--deep-licenses] <archive.zip|archive.tar.gz|folder> [reports-root-folder]
#
# Examples:
#   security/scripts/analyze-archive.sh ~/Downloads/delivered-project.zip
#   security/scripts/analyze-archive.sh ./my-extracted-project ./my-reports
#   # -> writes into ./my-reports/my-extracted-project/20260814-143000/
#   #    and regenerates ./my-reports/my-extracted-project/dashboard-my-extracted-project.html
#   #    and ./my-reports/dashboard.html
#   security/scripts/analyze-archive.sh --no-dashboard ./my-extracted-project
#   security/scripts/analyze-archive.sh --deep-licenses ./my-extracted-project
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECURITY_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# --- Fallback Docker images — same versions as the CI pipeline --------------
# Public registries, as the CI component's defaults: a local run needs no
# `docker login`. Each one can be overridden from the environment, e.g. to
# go through a registry mirror:
#   SYFT_IMAGE=registry.example.com/anchore/syft:v1.52.0 analyze-archive.sh ...
# Keep the versions in sync with the OSA_<TOOL>_IMAGE inputs of templates/analyze.yml.
SYFT_IMAGE="${SYFT_IMAGE:-anchore/syft:v1.52.0}"
# Distroless tag (not -debug like the CI): run_docker relies on the image's
# own grype entrypoint, and no shell is needed outside a GitLab job.
GRYPE_IMAGE="${GRYPE_IMAGE:-anchore/grype:v0.119.0}"
OSV_IMAGE="${OSV_IMAGE:-ghcr.io/google/osv-scanner:v2.6.0}"
SEMGREP_IMAGE="${SEMGREP_IMAGE:-semgrep/semgrep:1.177.0}"
GITLEAKS_IMAGE="${GITLEAKS_IMAGE:-zricethezav/gitleaks:v8.30.1}"
TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy:0.74.0}"
REUSE_IMAGE="${REUSE_IMAGE:-fsfe/reuse:6.2.0}"
# cdxgen: only used when a Maven/Gradle manifest is detected (see step 3
# below) — Syft's static pom.xml/build.gradle read misses every transitive
# dependency pulled in via a parent POM's BOM import. Bundles a JDK +
# Maven/Gradle so it can drive the project's own build for a resolved
# dependency graph, unlike Syft.
CDXGEN_IMAGE="${CDXGEN_IMAGE:-ghcr.io/cyclonedx/cdxgen:13.3.0}"
CYCLONEDX_CLI_IMAGE="${CYCLONEDX_CLI_IMAGE:-cyclonedx/cyclonedx-cli:0.33.1}"

# --- Arguments ---------------------------------------------------------------
GENERATE_DASHBOARD=1
GENERATE_PROJECT_DASHBOARD=1
DEEP_LICENSES=0
while true; do
  case "${1:-}" in
    --no-dashboard) GENERATE_DASHBOARD=0; shift ;;
    --no-project-dashboard) GENERATE_PROJECT_DASHBOARD=0; shift ;;
    --deep-licenses) DEEP_LICENSES=1; shift ;;
    *) break ;;
  esac
done

REPO_ROOT="$(cd "$SECURITY_DIR/.." && pwd)"

INPUT="${1:-}"
# Defaults to <repo-root>/security-reports — independent of the directory
# the script is launched from. Without this, two runs launched from
# different current folders would land in separate trees and the
# dashboard's history/trend would end up scattered with no warning.
REPORTS_ROOT="${2:-$REPO_ROOT/security-reports}"

if [ -z "$INPUT" ]; then
  echo "Usage: $0 [--no-dashboard] [--no-project-dashboard] [--deep-licenses] <archive.zip|archive.tar.gz|folder> [reports-root-folder]" >&2
  exit 2
fi
if [ ! -e "$INPUT" ]; then
  echo "Not found: $INPUT" >&2
  exit 2
fi

# On Windows, "python3"/"python" can appear on the PATH via an App
# Execution Alias stub that actually fails at runtime ("Python was not
# found... Microsoft Store"). command -v isn't enough, so we check an
# actual execution.
have() {
  command -v "$1" >/dev/null 2>&1 || return 1
  case "$1" in
    python3|python) "$1" --version >/dev/null 2>&1 ;;
    *) return 0 ;;
  esac
}

# Resolves the available Python interpreter once, reused everywhere.
PY=""
if have python3; then PY=python3; elif have python; then PY=python; fi

# --- Timestamped output folder: <root>/<project-name>/<YYYYMMDD-HHMMSS>/ --
project_name="$(basename "$INPUT")"
project_name="${project_name%.zip}"
project_name="${project_name%.tar.gz}"
project_name="${project_name%.tgz}"
project_name="${project_name%.tar}"
# Sanitizes the name: alphanumeric/-/_ only, for a path that's safe everywhere.
project_name="$(printf '%s' "$project_name" | sed 's/[^A-Za-z0-9_.-]/_/g')"
[ -n "$project_name" ] || project_name="project"

run_id="$(date +%Y%m%d-%H%M%S)"
OUTPUT_DIR="$REPORTS_ROOT/$project_name/$run_id"

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"
echo "==> Reports for this run archived in: $OUTPUT_DIR"

# --- 1. Resolve the target: extract the archive, or use the folder as-is
CLEANUP_WORKDIR=""
cleanup() {
  if [ -n "$CLEANUP_WORKDIR" ] && [ -d "$CLEANUP_WORKDIR" ]; then
    rm -rf "$CLEANUP_WORKDIR"
  fi
}
trap cleanup EXIT

if [ -d "$INPUT" ]; then
  TARGET_DIR="$(cd "$INPUT" && pwd)"
  echo "==> Analyzing folder: $TARGET_DIR"
else
  CLEANUP_WORKDIR="$(mktemp -d)"
  TARGET_DIR="$CLEANUP_WORKDIR/extracted"
  mkdir -p "$TARGET_DIR"
  echo "==> Extracting $INPUT to a temporary folder..."
  case "$INPUT" in
    *.zip)
      if command -v unzip >/dev/null 2>&1; then
        unzip -q "$INPUT" -d "$TARGET_DIR"
      elif [ -n "$PY" ]; then
        "$PY" -c "import zipfile,sys; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" "$INPUT" "$TARGET_DIR"
      else
        echo "Neither 'unzip' nor Python is available to extract a .zip." >&2
        exit 2
      fi
      ;;
    *.tar.gz|*.tgz)
      tar -xzf "$INPUT" -C "$TARGET_DIR"
      ;;
    *.tar)
      tar -xf "$INPUT" -C "$TARGET_DIR"
      ;;
    *)
      echo "Unsupported archive format: $INPUT (expected: .zip, .tar.gz, .tgz, .tar)" >&2
      exit 2
      ;;
  esac
  # If the archive contains a single root folder, descend into it —
  # avoids an SBOM that starts with "my-project-v2/my-project-v2/...".
  entries=("$TARGET_DIR"/*)
  if [ "${#entries[@]}" -eq 1 ] && [ -d "${entries[0]}" ]; then
    TARGET_DIR="${entries[0]}"
  fi
  echo "==> Extracted to: $TARGET_DIR"
fi

# --- 2. Native binary vs Docker choice ---------------------------------------
run_docker() {
  local image="$1"; shift
  if ! have docker; then
    echo "    Docker required but missing — tool skipped (install Docker or the native binary)." >&2
    return 1
  fi
  echo "    (native binary missing — falling back to Docker: $image)"
  docker run --rm -v "$TARGET_DIR:/src:ro" -v "$OUTPUT_DIR:/out" -w /src "$image" "$@"
}

# --- Coverage gaps -------------------------------------------------------------
# Every scanner below is optional and swallows its own failure (`|| true`),
# so one broken tool never stops the chain — but a step that produced
# nothing must not pass for a clean scan either. Each such degradation is
# warned about right away, then written to coverage.json, which
# aggregate_report.py turns into a "Reduced coverage" section of the report.
COVERAGE_GAPS=()
note_gap() {
  COVERAGE_GAPS+=("$1"$'\t'"$2")
  echo "    WARNING: $1 — $2" >&2
}
# Records a gap when a step's output file is missing or empty.
check_output() {
  local tool="$1" file="$2"
  [ -s "$file" ] || note_gap "$tool" "no $(basename "$file") produced (tool skipped or failed) — its findings are absent from this report."
}

echo ""
echo "==> Detected tools:"
for tool in syft grype osv-scanner semgrep gitleaks trivy cdxgen reuse docker; do
  if have "$tool"; then echo "    [native]  $tool"; else echo "    [missing] $tool"; fi
done
echo ""

# --- 3. SBOM (mandatory — everything else depends on it) ---------------------
# Syft alone only reads pom.xml/build.gradle as text: it never resolves a
# real Maven/Gradle dependency graph, so it misses every transitive
# dependency pulled in through a parent/BOM import. When such a manifest is
# found, cdxgen also runs (it drives the actual build tool for a resolved
# graph) and the two SBOMs are merged into one — everything downstream
# (Grype, license_gate.py, the dashboard) still reads a single sbom.cdx.json.
echo "==> [1/9] SBOM (Syft)"
SBOM="$OUTPUT_DIR/sbom.cdx.json"
SBOM_SYFT="$OUTPUT_DIR/sbom.syft.cdx.json"
if have syft; then
  syft scan "dir:$TARGET_DIR" \
    --exclude './node_modules/**' --exclude './target/debug/**' --exclude './.git/**' \
    -o "cyclonedx-json=$SBOM_SYFT" -o table
else
  run_docker "$SYFT_IMAGE" scan dir:/src \
    --exclude './node_modules/**' --exclude './target/debug/**' --exclude './.git/**' \
    -o cyclonedx-json=/out/sbom.syft.cdx.json -o table \
    || { echo "SBOM missing — stopping (nothing can run without it)." >&2; exit 1; }
fi
if [ ! -s "$SBOM_SYFT" ]; then
  echo "SBOM missing or empty — stopping." >&2
  exit 1
fi

echo "==> [2/9] SBOM (cdxgen — Java/Maven/Gradle real dependency resolution)"
SBOM_CDXGEN="$OUTPUT_DIR/sbom.cdxgen.cdx.json"
# Consequence shared by every way cdxgen can fail — spelled out in the report
# so a reader can't mistake the SCA count for a full scan.
JAVA_FLOOR="Java dependencies come from Syft's static pom.xml/build.gradle read only: transitive dependencies (parent POM / BOM imports) are missing, so SCA findings are a floor, not a total."
if find "$TARGET_DIR" -iname pom.xml -o -iname build.gradle -o -iname build.gradle.kts 2>/dev/null | grep -q .; then
  if have cdxgen; then
    (cd "$TARGET_DIR" && cdxgen -t java -o "$SBOM_CDXGEN" .) || true
    [ -s "$SBOM_CDXGEN" ] || note_gap "cdxgen" \
      "native cdxgen produced no SBOM (Maven/Gradle dependency resolution failed). $JAVA_FLOOR"
  elif have docker; then
    echo "    (native binary missing — falling back to Docker: $CDXGEN_IMAGE)"
    # Unlike run_docker's other callers, cdxgen needs read-write access to
    # $TARGET_DIR: it drives a real `mvn`/`gradle` build there (dependency
    # downloads, local .m2/gradle cache), not just a static file read.
    docker run --rm -v "$TARGET_DIR:/app" -w /app -v "$OUTPUT_DIR:/out" "$CDXGEN_IMAGE" \
      -t java -o /out/sbom.cdxgen.cdx.json . || true
    [ -s "$SBOM_CDXGEN" ] || note_gap "cdxgen" \
      "Docker fallback produced no SBOM — image pull refused or the Maven/Gradle build failed. $JAVA_FLOOR"
  else
    note_gap "cdxgen" "Docker required but missing — cdxgen skipped. $JAVA_FLOOR"
  fi
else
  echo "    No pom.xml/build.gradle(.kts) found — skipped."
fi

if [ -s "$SBOM_CDXGEN" ]; then
  echo "    Merging Syft + cdxgen SBOMs..."
  MERGE_FAILED="SBOM merge failed — keeping the Syft-only SBOM, cdxgen's resolved dependencies are not scanned. $JAVA_FLOOR"
  if have cyclonedx-cli; then
    cyclonedx-cli merge --input-files "$SBOM_SYFT" "$SBOM_CDXGEN" \
      --output-file "$SBOM" --output-format json \
      || { note_gap "sbom-merge" "$MERGE_FAILED"; cp "$SBOM_SYFT" "$SBOM"; }
  elif have docker; then
    docker run --rm -v "$OUTPUT_DIR:/out" "$CYCLONEDX_CLI_IMAGE" merge \
      --input-files /out/sbom.syft.cdx.json /out/sbom.cdxgen.cdx.json \
      --output-file /out/sbom.cdx.json --output-format json \
      || { note_gap "sbom-merge" "$MERGE_FAILED"; cp "$SBOM_SYFT" "$SBOM"; }
  else
    note_gap "sbom-merge" "Docker required but missing for cyclonedx-cli. $MERGE_FAILED"
    cp "$SBOM_SYFT" "$SBOM"
  fi
else
  cp "$SBOM_SYFT" "$SBOM"
fi

# --- 4. Scanners (independent, each optional) --------------------------------
echo "==> [3/9] SCA — Grype"
if have grype; then
  grype "sbom:$SBOM" -o json --file "$OUTPUT_DIR/grype.json" || true
  grype "sbom:$SBOM" -o table || true
else
  run_docker "$GRYPE_IMAGE" sbom:/out/sbom.cdx.json -o json --file /out/grype.json || true
fi
check_output "grype" "$OUTPUT_DIR/grype.json"

echo "==> [4/9] SCA — OSV-Scanner (second opinion)"
osv_rc=0
if have osv-scanner; then
  osv-scanner scan source --recursive --format json --output "$OUTPUT_DIR/osv.json" "$TARGET_DIR" || osv_rc=$?
else
  run_docker "$OSV_IMAGE" scan source --recursive --format json --output /out/osv.json /src || osv_rc=$?
fi
# Exit code 128 = "No package sources found": nothing for OSV to scan, which
# is not a coverage loss (and it writes no output file in that case).
if [ "$osv_rc" -eq 128 ]; then
  echo "    No package manifest/lockfile recognized by OSV-Scanner — nothing to scan."
else
  check_output "osv-scanner" "$OUTPUT_DIR/osv.json"
fi

echo "==> [5/9] SAST — Semgrep"
# oss-analyzer's own rules only (policy-semgrep.yml): unlike the CI/CD
# component, the registry packs (sast.registry_packs) aren't run here, so
# that the analysis of an archive needs no network access to the registry.
if have semgrep; then
  semgrep scan --config "$SECURITY_DIR/policy-semgrep.yml" --metrics off \
    --json --output "$OUTPUT_DIR/semgrep.json" "$TARGET_DIR" || true
else
  # The image has no implicit "semgrep" entrypoint: it must be invoked
  # explicitly. The in-house rules are mounted separately (they live in
  # security/, outside $TARGET_DIR which is the only folder mounted by default)
  # — the file alone, not security/, whose other YAML files aren't rules.
  if have docker; then
    echo "    (native binary missing — falling back to Docker: $SEMGREP_IMAGE)"
    docker run --rm \
      -v "$TARGET_DIR:/src:ro" \
      -v "$SECURITY_DIR/policy-semgrep.yml:/security-rules/policy-semgrep.yml:ro" \
      -v "$OUTPUT_DIR:/out" -w /src "$SEMGREP_IMAGE" \
      semgrep scan --config /security-rules/policy-semgrep.yml \
      --metrics off --json --output /out/semgrep.json /src || true
  else
    echo "    Docker required but missing — tool skipped (install Docker or the native binary)." >&2
  fi
fi
check_output "semgrep" "$OUTPUT_DIR/semgrep.json"

echo "==> [6/9] Secrets — Gitleaks"
if have gitleaks; then
  gitleaks detect --source "$TARGET_DIR" --config "$SECURITY_DIR/policy-gitleaks.toml" \
    --report-format json --report-path "$OUTPUT_DIR/gitleaks.json" --redact --exit-code 0 --no-git || true
elif have docker; then
  # Same config as the native run, mounted alone like Semgrep's rules
  # (run_docker only mounts the target and the output folder).
  echo "    (native binary missing — falling back to Docker: $GITLEAKS_IMAGE)"
  docker run --rm -v "$TARGET_DIR:/src:ro" -v "$OUTPUT_DIR:/out" \
    -v "$SECURITY_DIR/policy-gitleaks.toml:/security-rules/policy-gitleaks.toml:ro" \
    -w /src "$GITLEAKS_IMAGE" detect --source /src --no-git \
    --config /security-rules/policy-gitleaks.toml \
    --report-format json --report-path /out/gitleaks.json --redact --exit-code 0 || true
else
  echo "    Docker required but missing — tool skipped (install Docker or the native binary)." >&2
fi
check_output "gitleaks" "$OUTPUT_DIR/gitleaks.json"

# --- Infra/containers: Trivy (IaC config always; image only if $IMAGE_TAG) ---
echo "==> [7/9] Infra / IaC — Trivy"
if have trivy; then
  trivy config --format json --output "$OUTPUT_DIR/trivy-iac.json" "$TARGET_DIR" || true
  if [ -n "${IMAGE_TAG:-}" ]; then
    trivy image --scanners vuln,secret --format json --output "$OUTPUT_DIR/trivy-image.json" "$IMAGE_TAG" || true
  fi
else
  run_docker "$TRIVY_IMAGE" config --format json --output /out/trivy-iac.json /src || true
  if [ -n "${IMAGE_TAG:-}" ]; then
    # The image to scan isn't in $TARGET_DIR: the Docker registry (not
    # the mounted filesystem) resolves $IMAGE_TAG, so the /src mount isn't needed.
    docker run --rm -v "$OUTPUT_DIR:/out" "$TRIVY_IMAGE" \
      image --scanners vuln,secret --format json --output /out/trivy-image.json "$IMAGE_TAG" || true
  fi
fi
check_output "trivy-iac" "$OUTPUT_DIR/trivy-iac.json"
if [ -n "${IMAGE_TAG:-}" ]; then
  check_output "trivy-image" "$OUTPUT_DIR/trivy-image.json"
fi

if [ "$DEEP_LICENSES" -eq 1 ]; then
  echo "    (--deep-licenses) File-by-file license analysis — slower"
  if have trivy; then
    trivy fs --scanners license --license-full --format json \
      --output "$OUTPUT_DIR/trivy-licenses.json" "$TARGET_DIR" || true
  else
    run_docker "$TRIVY_IMAGE" fs --scanners license --license-full --format json \
      --output /out/trivy-licenses.json /src || true
  fi
  check_output "trivy-licenses" "$OUTPUT_DIR/trivy-licenses.json"
fi

# --- License headers: REUSE (SPDX headers/copyright per file) ---------------
# Distinct from --deep-licenses above: that one detects the license of
# *third-party* code (dependencies, vendored fragments) within
# $TARGET_DIR; this one checks that $TARGET_DIR's own files carry a
# proper SPDX-FileCopyrightText/SPDX-License-Identifier header, per the
# REUSE spec (https://reuse.software/). Same tool, same non-blocking
# status, as licenses:reuse / licenses-reuse in the CI pipelines.
echo "==> [8/9] License headers — REUSE"
if have reuse; then
  reuse --root "$TARGET_DIR" lint --json > "$OUTPUT_DIR/reuse.json" || true
else
  # reuse has no "generic Docker image + native binary" split like the
  # scanners above: it's a single Python CLI, so the fallback runs the
  # official image directly rather than through run_docker's generic
  # /src:ro, /out layout — --root has to point at the mounted source.
  if have docker; then
    echo "    (native binary missing — falling back to Docker: $REUSE_IMAGE)"
    docker run --rm -v "$TARGET_DIR:/src:ro" -v "$OUTPUT_DIR:/out" "$REUSE_IMAGE" \
      --root /src lint --json > "$OUTPUT_DIR/reuse.json" || true
  else
    echo "    Docker required but missing — tool skipped (install Docker or the native binary)." >&2
  fi
fi
check_output "reuse" "$OUTPUT_DIR/reuse.json"

# --- 5. Gate — licenses then aggregation -------------------------------------
echo "==> [9/9] Policy: licenses + aggregation"
if [ -z "$PY" ]; then
  echo "Python is required for the gate (license_gate.py / aggregate_report.py)." >&2
  exit 1
fi
"$PY" -c "import yaml" 2>/dev/null || "$PY" -m pip install --quiet pyyaml

"$PY" "$SECURITY_DIR/scripts/license_gate.py" \
  --sbom "$SBOM" --policy "$SECURITY_DIR/policy-global.yml" --output-dir "$OUTPUT_DIR" || true
check_output "license-gate" "$OUTPUT_DIR/licenses.json"

# Written on every local run, even with no gap: an empty list means every
# step ran, while an absent file (e.g. in CI) means coverage wasn't tracked.
"$PY" -c 'import json, pathlib, sys
gaps = [dict(zip(("tool", "reason"), g.split("\t", 1))) for g in sys.argv[2:]]
pathlib.Path(sys.argv[1]).write_text(json.dumps(gaps, indent=2, ensure_ascii=False), encoding="utf-8")' \
  "$OUTPUT_DIR/coverage.json" ${COVERAGE_GAPS[@]+"${COVERAGE_GAPS[@]}"}

set +e
"$PY" "$SECURITY_DIR/scripts/aggregate_report.py" \
  --input-dir "$OUTPUT_DIR" --policy "$SECURITY_DIR/policy-global.yml" --output-dir "$OUTPUT_DIR" \
  --source-dir "$TARGET_DIR"
GATE_EXIT=$?
set -e

echo ""
echo "==> Reports written to: $OUTPUT_DIR"
echo "    - security-report.md / security-report.json  (overview)"
echo "    - licenses.md / licenses.json                 (license detail)"
echo "    - grype.json, osv.json, semgrep.json, gitleaks.json  (raw, per tool)"
if [ "${#COVERAGE_GAPS[@]}" -gt 0 ]; then
  echo "" >&2
  echo "==> WARNING: reduced coverage — ${#COVERAGE_GAPS[@]} step(s) degraded, this is NOT a full scan:" >&2
  for gap in "${COVERAGE_GAPS[@]}"; do
    echo "    - ${gap%%$'\t'*}: ${gap#*$'\t'}" >&2
  done
  echo "    (also listed in security-report.md and coverage.json)" >&2
fi
# The per-project dashboard is scoped by pointing --reports-root at the
# project's own folder — NOT by --project, which only picks the initial view
# of a dashboard that still embeds every project found under the root.
PROJECT_REPORTS="$REPORTS_ROOT/$project_name"
PROJECT_DASHBOARD_CMD=(--reports-root "$PROJECT_REPORTS" --output "$PROJECT_REPORTS/dashboard-$project_name.html")
SHARED_DASHBOARD_CMD=(--reports-root "$REPORTS_ROOT" --project "$project_name")
print_dashboard_hint() {
  if [ "$GENERATE_PROJECT_DASHBOARD" -eq 1 ]; then
    echo "    python \"$SECURITY_DIR/scripts/generate_dashboard.py\" ${PROJECT_DASHBOARD_CMD[*]@Q}"
  fi
  echo "    python \"$SECURITY_DIR/scripts/generate_dashboard.py\" ${SHARED_DASHBOARD_CMD[*]@Q}"
}

if [ "$GENERATE_DASHBOARD" -eq 1 ]; then
  echo ""
  echo "==> Visual dashboards (this run + history)"
  if [ -n "$PY" ]; then
    if [ "$GENERATE_PROJECT_DASHBOARD" -eq 1 ]; then
      "$PY" "$SECURITY_DIR/scripts/generate_dashboard.py" "${PROJECT_DASHBOARD_CMD[@]}" ||         echo "    Project dashboard generation failed — the raw reports remain available." >&2
    fi
    "$PY" "$SECURITY_DIR/scripts/generate_dashboard.py" "${SHARED_DASHBOARD_CMD[@]}" ||       echo "    Shared dashboard generation failed — the raw reports remain available." >&2
  else
    echo "    Python unavailable — dashboards not generated. Run again later with:" >&2
    print_dashboard_hint >&2
  fi
else
  echo ""
  echo "==> Dashboards not generated (--no-dashboard). To generate them:"
  print_dashboard_hint
fi

exit "$GATE_EXIT"
