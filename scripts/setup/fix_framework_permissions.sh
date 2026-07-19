#!/usr/bin/env bash
set -euo pipefail

mkdir -p \
  data/framework-artifacts/native \
  data/framework-artifacts/garak \
  data/framework-artifacts/pyrit \
  data/framework-artifacts/promptfoo

chown root:root data/framework-artifacts
chmod 755 data/framework-artifacts

chown -R 1000:1000 \
  data/framework-artifacts/native \
  data/framework-artifacts/garak \
  data/framework-artifacts/pyrit \

chmod -R 775 \
  data/framework-artifacts/native \
  data/framework-artifacts/garak \
  data/framework-artifacts/pyrit \

chown -R 1001:1001 \
  data/framework-artifacts/promptfoo

chmod -R 775 \
  data/framework-artifacts/promptfoo

echo "Framework artifact permissions fixed."
