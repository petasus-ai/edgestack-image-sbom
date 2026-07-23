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
# build-time and scheduled reports are byte-comparable. Keeps exactly the
# portal-contract fields plus grype/DB versions, and normalizes the DB build
# time to descriptor.db.built (grype v6 nests it under db.status.built).
VULN_PROJECT='{
  descriptor: {
    name: .descriptor.name, version: .descriptor.version,
    timestamp: .descriptor.timestamp,
    db: {
      built: (.descriptor.db.built // .descriptor.db.status.built),
      schemaVersion: (.descriptor.db.schemaVersion // .descriptor.db.status.schemaVersion)
    }
  },
  matches: [.matches[] | {
    vulnerability: {
      id: .vulnerability.id, severity: .vulnerability.severity,
      fix: {versions: (.vulnerability.fix.versions // []), state: .vulnerability.fix.state},
      cvss: (.vulnerability.cvss // []), urls: (.vulnerability.urls // []),
      dataSource: .vulnerability.dataSource
    },
    artifact: {name: .artifact.name, version: .artifact.version, type: .artifact.type}
  }]
}'

changed=0
scanned=0
db_date_seen=""

while IFS= read -r -d '' sbom; do
  scanned=$((scanned + 1))
  vuln="${sbom%.spdx.json}.vuln.json"
  tmp=$(mktemp)

  raw=$(mktemp)
  if ! grype "sbom:${sbom}" -o json > "$raw" 2>/dev/null; then
    log "WARNING: grype failed on ${sbom} — leaving existing report untouched"
    rm -f "$tmp" "$raw"; continue
  fi
  if ! jq -e '.descriptor and (.matches | type == "array")' "$raw" >/dev/null 2>&1; then
    log "WARNING: invalid grype output for ${sbom} — skipping"
    rm -f "$tmp" "$raw"; continue
  fi
  jq -c "$VULN_PROJECT" "$raw" > "$tmp"
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
  log "updated ${vuln} ($(jq '.matches | length' "$vuln") findings, DB ${new_built})"
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
