#!/usr/bin/env bash
# Refuse any push whose destination is the protected `main` branch.
#
# Reads the standard git pre-push payload on stdin, one line per ref:
#   <local ref> <local sha> <remote ref> <remote sha>
#
# Armed for every clone via `pre-commit install` (see .pre-commit-config.yaml).
# Emergency bypass (discouraged): git push --no-verify
set -euo pipefail

protected_ref="refs/heads/main"
status=0

while read -r _local_ref _local_sha remote_ref _remote_sha; do
  if [ "${remote_ref:-}" = "$protected_ref" ]; then
    echo "✋ Direct pushes to 'main' are blocked. Open a pull request from a feature branch." >&2
    echo "   Emergency bypass (avoid): git push --no-verify" >&2
    status=1
  fi
done

exit "$status"
