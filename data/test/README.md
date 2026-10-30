<!--
SPDX-FileCopyrightText: 2026 THALES

SPDX-License-Identifier: MIT
-->

# Test fixtures

This folder holds the deterministic license fixture described below.

## What each part should trigger


`sbom-fixture.cdx.json`, for the license gate (`license_gate.py`), is a
deterministic synthetic SBOM covering every verdict: `allow` (MIT), dual license `OR`, `WITH Classpath-exception`, `review` (LGPL, MPL, and GPL, AGPL, SSPL), `deny` (CC-BY-NC), missing license, old `GPL-2.0+` notation, compound `AND`/`OR` expression, a listed name holding `or` (matched whole), an unlisted name holding `and` (reported whole), `WITH Commons-Clause` (no fallback to Apache-2.0).

## Usage


### License gate alone, on a deterministic SBOM

To validate `license_gate.py` without depending on the real registries,
nor on the organization's license lists (`policy-fixture.yml` carries
the fixture's own):

```bash
python security/scripts/license_gate.py \
  --sbom data/test/sbom-fixture.cdx.json \
  --policy data/test/policy-fixture.yml \
  --output-dir data/test/reports
cat data/test/reports/licenses.md
```

Expected result, component by component in
`sbom-fixture.expected.json`: **3 allowed** (MIT, dual license `MIT OR
Apache-2.0`, the listed name `MATPLOTLIB License 1.3.0 or Later`), **11 to
review** (`GPL-2.0-only WITH Classpath-exception-2.0`, LGPL-2.1, MPL-2.0,
GPL-3.0, AGPL-3.0, SSPL-1.0, missing license, the old `GPL-2.0+` notation,
compound expression `(MIT OR GPL-3.0-only) AND MPL-2.0` — the `AND` keeps
the most restrictive one —, the unlisted name holding `and`, `Apache-2.0
WITH Commons-Clause`), **1 denied** (CC-BY-NC-4.0) → exits with failure
(code 1). The CI's `test:license-gate` job checks every one of them, in
enforce and audit modes (`check_license_fixture.py`).

### Cleanup

`data/test/reports/` is just test output, free to delete:

```bash
rm -rf data/test/reports
```
