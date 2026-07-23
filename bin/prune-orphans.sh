#!/usr/bin/env bash
# Prune SBOM/vuln reports for image digests no longer referenced by a live tag.
#
# SBOMs are immutable and never overwritten, so every rebuild adds new files
# and old digests pile up (a rebuilt tag moves to a new digest; the previous
# digest's files become orphans). This bounds the working set to the digests
# still referenced by a current quay tag: for each mirror directory it lists
# the repository's active tags via the public quay API, keeps the files whose
# digest matches any live tag, and `git rm`s the rest (both .spdx.json and
# .vuln.json for an orphaned digest).
#
# Safe by construction: if the quay API call for a repository fails or yields
# no digests, that directory is skipped untouched — a transient API error can
# never delete valid files. Manifest-list tags (latest*) and cosign .sbom
# attachment tags appear in the listing too; their digests simply never match
# a file name, which is harmless. Works across branches (master + cilium):
# any digest a live tag points at is kept, whatever built it.
#
# Usage: bin/prune-orphans.sh          # prune + commit/push when RUN_COMMIT=1
#        DRY_RUN=true bin/prune-orphans.sh   # list orphans, change nothing
set -euo pipefail

DRY_RUN="${DRY_RUN:-false}"
QUAY_NS="edgestack"
API="https://quay.io/api/v1/repository"

log() { echo "[prune] $*"; }

# Echo every active tag's manifest digest (sha256:...) for a repo, across all
# pages. Buffers and only prints on FULL success; returns non-zero on any API
# failure so the caller can skip the directory instead of deleting from a
# partial listing.
live_digests_for_repo() {
  local repo=$1 page=1 buf="" tmp
  tmp=$(mktemp)
  while :; do
    if ! curl -sf --retry 3 --retry-delay 5 \
         "${API}/${QUAY_NS}/${repo}/tag/?onlyActiveTags=true&limit=100&page=${page}" -o "$tmp"; then
      rm -f "$tmp"; return 1
    fi
    buf+=$(jq -r '.tags[].manifest_digest // empty' "$tmp")$'\n'
    [[ "$(jq -r '.has_additional' "$tmp")" == "true" ]] || break
    page=$((page + 1))
    [[ $page -gt 50 ]] && { rm -f "$tmp"; return 1; }   # sanity cap
  done
  rm -f "$tmp"
  printf '%s' "$buf"
}

removed=0
kept=0
for dir in */; do
  repo="${dir%/}"
  ls "$repo"/sha256-*.spdx.json >/dev/null 2>&1 || continue

  if ! live_raw=$(live_digests_for_repo "$repo"); then
    log "WARNING: quay API failed for ${repo} — skipping (no files touched)"
    continue
  fi
  live_hex=$(printf '%s\n' "$live_raw" | sed 's/^sha256://' | grep -E '^[0-9a-f]{64}$' | sort -u)
  if [[ -z "$live_hex" ]]; then
    log "WARNING: no live digests for ${repo} — skipping to avoid deleting valid files"
    continue
  fi

  for f in "$repo"/sha256-*.json; do
    [[ -e "$f" ]] || continue
    base=$(basename "$f"); hex=${base#sha256-}; hex=${hex%%.*}
    if printf '%s\n' "$live_hex" | grep -qxF "$hex"; then
      kept=$((kept + 1))
    else
      log "orphan: $f"
      [[ "$DRY_RUN" != "true" ]] && git rm -q "$f"
      removed=$((removed + 1))
    fi
  done
done

log "kept ${kept} file(s), ${removed} orphan file(s) $([[ "$DRY_RUN" == "true" ]] && echo 'would be removed (dry-run)' || echo 'removed')"

if [[ "${RUN_COMMIT:-0}" != "1" || "$DRY_RUN" == "true" || "$removed" -eq 0 ]]; then
  exit 0
fi

git config user.name "edgestack-image-sbom CI"
git config user.email "edgestack-ci@users.noreply.github.com"
git commit -q -m "Prune ${removed} orphaned report file(s) for retired image digests"

branch=$(git rev-parse --abbrev-ref HEAD)
for attempt in 1 2 3; do
  if git push -q origin HEAD; then
    log "pushed prune of ${removed} file(s)"
    exit 0
  fi
  log "push failed (attempt ${attempt}/3) — rebasing and retrying"
  git pull -q --rebase origin "$branch"
done
log "ERROR: failed to push after 3 attempts" >&2
exit 1
