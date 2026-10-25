#!/usr/bin/env bash
# Prune SBOM/vuln reports for image digests no longer referenced by a live tag,
# keeping each live tag's previous build.
#
# SBOMs are immutable and never overwritten, so every rebuild adds new files
# and old digests pile up (a rebuilt tag moves to a new digest; the previous
# digest's files become orphans). This bounds the working set to the digests a
# current quay tag points at, plus, in the repositories KEEP_PREVIOUS_REPOS
# matches (VM images, *-container-disk, by default), the KEEP_PREVIOUS builds
# each live tag pointed at before it (default 1): a cluster keeps running the
# VM image build it imported until it deletes it, usually one back as its
# rollback, and the daily re-scan keeps that build's report current for it.
# KaaS node images (*-kube) are not re-graded in clusters and keep only their
# live tags, which holds the daily re-scan set down. For each mirror directory
# it lists the repository's tags with their history via the public quay API
# (onlyActiveTags=false), keeps the files whose digest is kept, and `git rm`s
# the rest (both .spdx.json and .vuln.json for an orphaned digest). A tag with
# no active entry is gone and keeps nothing.
#
# Safe by construction: if the quay API call for a repository fails or yields
# no digests, that directory is skipped untouched — a transient API error can
# never delete valid files. Manifest-list tags (latest*) and cosign .sbom
# attachment tags appear in the listing too; their digests simply never match
# a file name, which is harmless. Works across branches (master + cilium):
# any digest a live tag points at is kept, whatever built it.
#
# Usage: bin/prune-orphans.sh          # prune + commit/push when RUN_COMMIT=1
#        DRY_RUN=true bin/prune-orphans.sh     # list orphans, change nothing
#        KEEP_PREVIOUS=0 bin/prune-orphans.sh  # live tags' digests only
#        KEEP_PREVIOUS_REPOS='.' bin/prune-orphans.sh  # previous builds everywhere
set -euo pipefail

DRY_RUN="${DRY_RUN:-false}"
KEEP_PREVIOUS="${KEEP_PREVIOUS:-1}"
KEEP_PREVIOUS_REPOS="${KEEP_PREVIOUS_REPOS:--container-disk$}"
QUAY_NS="edgestack"
API="https://quay.io/api/v1/repository"

log() { echo "[prune] $*"; }

[[ "$KEEP_PREVIOUS" =~ ^[0-9]+$ ]] || { log "KEEP_PREVIOUS must be a whole number" >&2; exit 2; }

# The digests a repository's tag listing keeps (input: every page's .tags as
# one array): each active tag's digest, then the $keep distinct digests it
# pointed at before, newest first. An entry with an end_ts is
# history; a tag with no active entry keeps nothing.
KEEP_JQ='
  group_by(.name)[]
  | (map(select(.end_ts == null) | .manifest_digest // empty)) as $live
  | select($live | length > 0)
  | $live[], (
      [ sort_by(-(.start_ts // 0))[] | select(.end_ts != null)
        | .manifest_digest // empty | select(IN($live[]) | not) ]
      | reduce .[] as $d ([]; if any(.[]; . == $d) then . else . + [$d] end)
      | .[:$keep][] )'

# Echo every kept manifest digest (sha256:...) for a repo, across all pages.
# Buffers and only prints on FULL success; returns non-zero on any API failure
# so the caller can skip the directory instead of deleting from a partial
# listing.
kept_digests_for_repo() {
  local repo=$1 page=1 tmp pages keep=0
  [[ "$repo" =~ $KEEP_PREVIOUS_REPOS ]] && keep=$KEEP_PREVIOUS
  tmp=$(mktemp); pages=$(mktemp)
  while :; do
    if ! curl -sf --retry 3 --retry-delay 5 \
         "${API}/${QUAY_NS}/${repo}/tag/?onlyActiveTags=false&limit=100&page=${page}" -o "$tmp"; then
      rm -f "$tmp" "$pages"; return 1
    fi
    jq -c '.tags // []' "$tmp" >> "$pages"
    [[ "$(jq -r '.has_additional' "$tmp")" == "true" ]] || break
    page=$((page + 1))
    [[ $page -gt 50 ]] && { rm -f "$tmp" "$pages"; return 1; }   # sanity cap
  done
  if ! jq -rs --argjson keep "$keep" "add | ${KEEP_JQ}" "$pages"; then
    rm -f "$tmp" "$pages"; return 1
  fi
  rm -f "$tmp" "$pages"
}

removed=0
kept=0
removed_paths=()   # replayed verbatim if the push races another pusher
for dir in */; do
  repo="${dir%/}"
  ls "$repo"/sha256-*.spdx.json >/dev/null 2>&1 || continue

  if ! kept_raw=$(kept_digests_for_repo "$repo"); then
    log "WARNING: quay API failed for ${repo} — skipping (no files touched)"
    continue
  fi
  kept_hex=$(printf '%s\n' "$kept_raw" | sed 's/^sha256://' | grep -E '^[0-9a-f]{64}$' | sort -u)
  if [[ -z "$kept_hex" ]]; then
    log "WARNING: no live digests for ${repo} — skipping to avoid deleting valid files"
    continue
  fi

  for f in "$repo"/sha256-*.json; do
    [[ -e "$f" ]] || continue
    base=$(basename "$f"); hex=${base#sha256-}; hex=${hex%%.*}
    if printf '%s\n' "$kept_hex" | grep -qxF "$hex"; then
      kept=$((kept + 1))
    else
      log "orphan: $f"
      [[ "$DRY_RUN" != "true" ]] && git rm -q "$f"
      removed_paths+=("$f")
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
  log "push failed (attempt ${attempt}/3) — replaying the deletions onto the new remote head"

  # Deliberately NOT `git pull --rebase`. Four different actors push to this
  # branch (both builder repos, the daily refresh, and humans merging PRs), so a
  # rejected push is routine — and every file this job deletes is one a refresh
  # or a PR may have just rewritten. Rebasing turns each of those into a
  # modify/delete conflict, which no merge strategy resolves (-X ours/theirs
  # apply to content conflicts only), leaving the runner stuck mid-rebase and
  # the job dead. That is exactly how the 2026-08-10 run died against PR #1.
  #
  # The resolution is never in doubt: the digest is referenced by no live quay
  # tag, and a fresher body for its report does not make it less orphaned. So
  # drop the local commit and re-apply the same deletions on top of whatever
  # landed. Deletions only — anything the other pusher ADDED is a different
  # digest, hence a different file name, and survives untouched.
  git fetch -q origin "$branch"
  git reset -q --hard "origin/${branch}"
  git rm -q --ignore-unmatch -- "${removed_paths[@]}"

  # Recount rather than reusing $removed: a concurrent prune may have taken some
  # of these already, and --ignore-unmatch makes that a no-op, not an error.
  staged=$(git diff --cached --name-only | wc -l | tr -d ' ')
  if [[ "$staged" -eq 0 ]]; then
    log "another push already removed every orphan — nothing left to do"
    exit 0
  fi
  git commit -q -m "Prune ${staged} orphaned report file(s) for retired image digests"
done
log "ERROR: failed to push after 3 attempts" >&2
exit 1
