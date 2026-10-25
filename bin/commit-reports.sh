#!/usr/bin/env bash
# Commit the reports the parallel re-scan jobs rewrote, in one commit.
#
# The daily refresh (.github/workflows/refresh-vulns.yml) scans the mirror in
# parallel jobs, each a slice of one repository's SBOMs (bin/refresh-vulns.sh
# with SHARD), and each hands back only the .vuln.json files it rewrote. This
# lands them together, as the one-job refresh did. Its checkout is sparse
# (bin/ only — the reports are gigabytes), so the files go into the index as
# blobs (git hash-object + update-index), never through the work tree.
#
# On a rejected push it does not rebase: other actors push to this branch
# (both builder repos, the weekly prune, humans), so it resets to the new
# remote head and stages the same reports again; a report a builder wrote
# meanwhile is replaced by this newer scan. (The prune shares the refresh's
# concurrency group, so it never runs in between.)
#
# Usage: bin/commit-reports.sh <dir>   # <dir>/<repository>/sha256-<hex>.vuln.json
set -euo pipefail

src=${1:?usage: commit-reports.sh <dir>}
log() { echo "[refresh] $*"; }

files=()
if [[ -d "$src" ]]; then
  while IFS= read -r -d '' f; do
    files+=("${f#"$src"/}")
  done < <(find "$src" -mindepth 2 -maxdepth 2 -type f -name 'sha256-*.vuln.json' -print0 | sort -z)
fi
if [[ ${#files[@]} -eq 0 ]]; then
  log "no refreshed reports — skipping commit"
  exit 0
fi

db_date=$(for f in "${files[@]}"; do
  jq -r '(.descriptor.db.built // "")[0:10]' "$src/$f" 2>/dev/null || true
done | sort | tail -1)
today=$(date -u +%F)

git config user.name "edgestack-image-sbom CI"
git config user.email "edgestack-ci@users.noreply.github.com"
branch=$(git rev-parse --abbrev-ref HEAD)

stage() {
  local f blob
  for f in "${files[@]}"; do
    blob=$(git hash-object -w -- "$src/$f")
    git update-index --add --cacheinfo "100644,${blob},${f}"
  done
}

for attempt in 1 2 3; do
  stage
  staged=$(git diff --cached --name-only | wc -l | tr -d ' ')
  if [[ "$staged" -eq 0 ]]; then
    log "every refreshed report is already on ${branch} — nothing to commit"
    exit 0
  fi
  git commit -q -m "Refresh vulnerability reports ${today} (grype db ${db_date:-unknown})"
  if git push -q origin HEAD; then
    log "pushed ${staged} refreshed report(s)"
    exit 0
  fi
  log "push failed (attempt ${attempt}/3) — staging the reports again onto the new remote head"
  git fetch -q origin "$branch"
  git reset -q --hard "origin/${branch}"
done
log "ERROR: failed to push after 3 attempts" >&2
exit 1
