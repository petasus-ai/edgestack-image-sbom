#!/usr/bin/env bash
# Re-scan every SBOM in this mirror and refresh its vulnerability report.
#
# Golden images live for months, but a build scans for CVEs only once. This
# script (run daily by .github/workflows/refresh-vulns.yml) re-scans every
# <repo>/sha256-<hex>.spdx.json with a freshly-updated grype DB and rewrites
# the sibling <repo>/sha256-<hex>.vuln.json when the new scan used a NEWER DB
# than the published report (descriptor.db.built gate — no churn otherwise).
# VULN_FORCE=true rewrites unconditionally. All changes land in one commit.
#
# grype must be on PATH and its DB already updated (the workflow does both).
# Committing/pushing is left to the workflow when RUN_COMMIT is unset; set
# RUN_COMMIT=1 to have this script commit and push (used by the workflow).
set -euo pipefail

VULN_FORCE="${VULN_FORCE:-false}"

log() { echo "[refresh] $*"; }

db_built() { jq -r '(.descriptor.db.built // .descriptor.db.status.built // "")' "$1" 2>/dev/null || echo ""; }
to_epoch() { date -d "$1" +%s 2>/dev/null || echo 0; }

# Portal projection — MUST match image-builder scripts/vuln-pipeline.sh so
# build-time and scheduled reports stay schema-identical. Keeps exactly the
# portal-contract fields plus grype/DB versions, and normalizes the DB build
# time to descriptor.db.built (grype v6 nests it under db.status.built).
#
# Three lookups parameterize it, and all three carry the "real but not
# patchable in place" judgments the portal needs to decide what is actionable.
# A refresh that dropped any of them would silently re-grade every image the
# moment it replaced the build-time report — which is what happened while $av
# was hardcoded to {} and $isfrozen did not exist here at all.
#
# $av  (fix.availableInDistro / distroLatest) comes from distro-fix-check.sh.
#      grype matches Rocky/Alma against the RHEL feed, so it cites fixes that
#      EL clones have not rebuilt yet; without this an image that is already
#      fully upgraded is graded down for an upgrade nobody can perform.
# $vend (artifact.vendored) marks a bundled copy (setuptools/_vendor/), judged
#      from the SBOM's sourceInfo because grype reconstructs no locations from
#      SPDX — a version is vendored only when EVERY SBOM entry for it sits
#      under _vendor/, so a stale bundle next to a properly installed copy
#      keeps the real one actionable.
# $isfrozen / $frz (artifact.frozen) mark packages the image's upgrade-freeze
#      policy pins in place: the fix exists, but applying it on a running node
#      is unsupported, so the remediation is a rebuild. Per-repo policy, from
#      bin/freeze-policy.json — the builders sharing this mirror do not have
#      the same freeze list.
VULN_PROJECT='{
  descriptor: {
    name: .descriptor.name, version: .descriptor.version,
    timestamp: .descriptor.timestamp,
    db: {
      built: (.descriptor.db.built // .descriptor.db.status.built),
      schemaVersion: (.descriptor.db.schemaVersion // .descriptor.db.status.schemaVersion)
    }
  },
  matches: [.matches[] |
    ($av[.artifact.name + "|" + ((.vulnerability.fix.versions // []) | join(","))]) as $d | {
    vulnerability: {
      id: .vulnerability.id, severity: .vulnerability.severity,
      fix: {
        versions: (.vulnerability.fix.versions // []), state: .vulnerability.fix.state,
        availableInDistro: (if $d == null then null else $d.availableInDistro end),
        distroLatest: (if $d == null then null else $d.distroLatest end)
      },
      cvss: (.vulnerability.cvss // []), urls: (.vulnerability.urls // []),
      dataSource: .vulnerability.dataSource
    },
    artifact: {name: .artifact.name, version: .artifact.version, type: .artifact.type,
      vendored: ($vend[.artifact.name + "|" + .artifact.version] // false),
      frozen: (if $isfrozen then (.artifact.name | test($frz)) else false end)}
  }]
}'

BIN=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
POLICY="$BIN/freeze-policy.json"

# One index cache for the whole run: ~150 SBOMs collapse to a couple of dozen
# (family, release, arch) triples, and distro-fix-check.sh would otherwise
# re-download a distro's entire package index per SBOM. Deliberately run-scoped
# and thrown away — a persisted cache would answer "newest version the distro
# publishes" from yesterday, which is the one thing it must not do.
DFCACHE=$(mktemp -d "${TMPDIR:-/tmp}/dfcache.XXXXXX")
export DISTRO_FIX_CACHE_DIR="$DFCACHE"
trap 'rm -rf "$DFCACHE"' EXIT

# Which arch is this image? The purl qualifiers carry it; the freeze/vendored
# judgments do not care but distro-fix-check.sh does, since this job runs on an
# x86_64 runner and half the mirrored SBOMs are aarch64. Majority wins because
# noarch/all packages are excluded, not counted. Empty = let the script fall
# back to uname.
sbom_arch() {
  jq -r '[.packages[]?.externalRefs[]? | select(.referenceType == "purl")
          | .referenceLocator | select(test("[?&]arch="))
          | capture("[?&]arch=(?<a>[^&]+)").a
          | select(. == "x86_64" or . == "amd64" or . == "aarch64" or . == "arm64")]
    | if length == 0 then "" else (group_by(.) | max_by(length) | .[0]) end' "$1" 2>/dev/null || echo ""
}

changed=0
scanned=0
db_date_seen=""
policy_repo=""      # repo whose freeze policy is currently loaded
frz='^$'            # FREEZE_PKG_REGEX in force — ^$ matches no package name
marker=""           # FREEZE_MARKER_REGEX in force; empty = repo has no policy

while IFS= read -r -d '' sbom; do
  scanned=$((scanned + 1))
  vuln="${sbom%.spdx.json}.vuln.json"
  repo=$(basename "$(dirname "$sbom")")
  tmp=$(mktemp)

  # Resolve the repo's freeze policy once per directory — find|sort groups the
  # SBOMs by repo, so this runs a handful of times, not once per digest.
  if [[ "$repo" != "$policy_repo" ]]; then
    policy_repo="$repo"
    # .repoRegex is bound before the pipe: inside `$r | test(...)` the input is
    # already $r, so reading .repoRegex there would index a string.
    marker=$(jq -r --arg r "$repo" \
      'first(.policies[]? | .repoRegex as $re | select($r | test($re)) | .markerRegex) // ""' \
      "$POLICY" 2>/dev/null || echo "")
    frz=$(jq -r --arg r "$repo" \
      'first(.policies[]? | .repoRegex as $re | select($r | test($re)) | .pkgRegex) // "^$"' \
      "$POLICY" 2>/dev/null || echo '^$')
    [[ -n "$frz" ]] || frz='^$'
    log "${repo}: freeze policy $([[ -n "$marker" ]] && echo "loaded" || echo "none — frozen stays false")"
  fi

  raw=$(mktemp)
  if ! grype "sbom:${sbom}" -o json > "$raw" 2>/dev/null; then
    log "WARNING: grype failed on ${sbom} — leaving existing report untouched"
    rm -f "$tmp" "$raw"; continue
  fi
  if ! jq -e '.descriptor and (.matches | type == "array")' "$raw" >/dev/null 2>&1; then
    log "WARNING: invalid grype output for ${sbom} — skipping"
    rm -f "$tmp" "$raw"; continue
  fi
  # name|version → bundled-copy judgment for artifact.vendored (see
  # VULN_PROJECT). Fails soft to {} — every finding then stays vendored:false.
  vend=$(jq -c '[.packages[]? | select(.sourceInfo)
      | {k: (.name + "|" + (.versionInfo // "")), v: (.sourceInfo | contains("/_vendor/"))}]
    | group_by(.k) | map({key: .[0].k, value: (map(.v) | all)}) | from_entries' "$sbom" 2>/dev/null || echo '{}')
  echo "$vend" | jq -e 'type == "object"' >/dev/null 2>&1 || vend='{}'

  # Is the fix grype cites actually published by this distro yet? Fails soft to
  # {} — the fields then stay null, the contract's "not judged".
  avail=$(DISTRO_FIX_ARCH="$(sbom_arch "$sbom")" "$BIN/distro-fix-check.sh" "$repo" "$raw" || echo '{}')
  echo "$avail" | jq -e 'type == "object"' >/dev/null 2>&1 || avail='{}'

  # Is this image under its repo's upgrade-freeze policy? Judged from the SBOM,
  # since a digest carries no tag. Fails soft to false.
  isfrozen=false
  if [[ -n "$marker" ]]; then
    isfrozen=$(jq --arg re "$marker" '[.packages[]?.name // empty] | any(test($re))' "$sbom" 2>/dev/null || echo false)
    [[ "$isfrozen" == "true" ]] || isfrozen=false
  fi

  jq -c --argjson av "$avail" --argjson vend "$vend" \
    --argjson isfrozen "$isfrozen" --arg frz "$frz" "$VULN_PROJECT" "$raw" > "$tmp"
  rm -f "$raw"

  new_built=$(db_built "$tmp")
  [[ -n "$new_built" ]] && db_date_seen="${new_built%%T*}"

  if [[ -f "$vuln" && "$VULN_FORCE" != "true" ]]; then
    old_built=$(db_built "$vuln")
    if [[ -n "$old_built" && "$(to_epoch "$new_built")" -le "$(to_epoch "$old_built")" ]]; then
      rm -f "$tmp"; continue
    fi
  fi

  # Rewrite only when the payload actually differs (guards against a same-DB
  # rescan that somehow slipped the gate, avoiding a no-op diff).
  if [[ -f "$vuln" ]] && cmp -s "$tmp" "$vuln"; then
    rm -f "$tmp"; continue
  fi

  mv "$tmp" "$vuln"
  changed=$((changed + 1))
  log "updated ${vuln} ($(jq '.matches | length' "$vuln") findings, DB ${new_built}) — $(jq '
    [.matches[] | select(.artifact.frozen)] | length' "$vuln") frozen, $(jq '
    [.matches[] | select(.vulnerability.fix.availableInDistro == false)] | length' "$vuln") not yet in distro"
done < <(find . -type f -name 'sha256-*.spdx.json' -print0 | sort -z)

log "scanned ${scanned} SBOM(s), ${changed} report(s) changed"

if [[ "${RUN_COMMIT:-0}" != "1" ]]; then
  exit 0
fi

if [[ "$changed" -eq 0 ]]; then
  log "no changes — skipping commit"
  exit 0
fi

git config user.name "edgestack-image-sbom CI"
git config user.email "edgestack-ci@users.noreply.github.com"
git add -A

today=$(date -u +%F)
git commit -q -m "Refresh vulnerability reports ${today} (grype db ${db_date_seen:-unknown})"

branch=$(git rev-parse --abbrev-ref HEAD)
for attempt in 1 2 3; do
  if git push -q origin HEAD; then
    log "pushed ${changed} refreshed report(s)"
    exit 0
  fi
  log "push failed (attempt ${attempt}/3) — rebasing and retrying"
  git pull -q --rebase origin "$branch"
done
log "ERROR: failed to push after 3 attempts" >&2
exit 1
