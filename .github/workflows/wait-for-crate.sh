#!/usr/bin/env bash
set -euo pipefail

echo "Waiting for ${CRATE_NAME} ${CRATE_VERSION} to appear in crates.io index..."
found=0
for i in $(seq 1 12); do
  sleep 10
  if python3 - <<'PY'
import json
import os
import urllib.request

crate = os.environ["CRATE_NAME"]
version = os.environ["CRATE_VERSION"]
req = urllib.request.Request(
    f"https://crates.io/api/v1/crates/{crate}/versions",
    headers={"User-Agent": "ActPlane CI publish version check"},
)
with urllib.request.urlopen(req, timeout=30) as response:
    versions = {v["num"] for v in json.load(response)["versions"]}
raise SystemExit(0 if version in versions else 1)
PY
  then
    echo "Found after $((i * 10))s"
    found=1
    break
  fi
  echo "Attempt $i/12..."
done

if [ "$found" -ne 1 ]; then
  echo "${CRATE_NAME} ${CRATE_VERSION} did not appear in crates.io index"
  exit 1
fi
