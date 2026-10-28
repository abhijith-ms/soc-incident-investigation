#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

case_run=$(mktemp -d /mnt/Games/SOC/incident-investigation/run-XXXXXX)
GOMEMLIMIT=256MiB /mnt/Games/SOC/tools/velociraptor-v0.77.3-linux-amd64 \
  --definitions artifacts artifacts collect Custom.SOC.CaseFiles \
  --args "CaseDirectory=$PWD/fixtures/SOC-CASE-001" \
  --output "$case_run/collection.zip" --timeout 30
python3 scripts/analyze_case.py "$case_run/collection.zip" --output "$case_run/analysis"
