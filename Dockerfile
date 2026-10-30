# SPDX-FileCopyrightText: 2026 THALES
#
# SPDX-License-Identifier: MIT

# oss-analyzer image: the Python scripts of security/scripts/ and their
# dependencies, used by the CI/CD component's report jobs so that a given
# component version always runs the scripts of that same version (instead
# of each consuming project carrying its own copy of security/scripts/).
#
# Built from the repository root:
#   docker build -t oss-analyzer .
#
# The scanners themselves (Syft, Grype, Semgrep, ...) are not in here: each
# runs from its own pinned image, as in the rest of the suite.

ARG BASE_IMAGE=docker.io/python:3.12-slim
FROM ${BASE_IMAGE}

LABEL org.opencontainers.image.title="oss-analyzer" \
      org.opencontainers.image.description="Report, gate and dashboard scripts of the oss-analyzer security suite" \
      org.opencontainers.image.source="https://github.com/ThalesGroup/oss-analyzer" \
      org.opencontainers.image.licenses="MIT"

ENV OSA_HOME=/opt/oss-analyzer \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY security/scripts/requirements.txt ${OSA_HOME}/requirements.txt
RUN pip install --no-cache-dir -r ${OSA_HOME}/requirements.txt

COPY security/scripts/*.py ${OSA_HOME}/scripts/
# The organization default settings, side by side (policy-global.yml's
# lists_file is relative): prepare_settings.py completes them with the
# consuming project's own settings files, if any.
COPY security/policy-global.yml security/policy-licenses.yml security/policy-semgrep.yml security/policy-gitleaks.toml ${OSA_HOME}/defaults/

# Non-root. The component's jobs only write into the report folder, which
# osa_prepare and osa_sbom_generate make world-writable (chmod -R a+rwX) for
# the same reason: Grype's image already runs as non-root uid 65532.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin osa
USER 10001
