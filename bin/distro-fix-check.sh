#!/usr/bin/env bash
# Is the fix grype reports ACTUALLY installable on this image's distro?
#
# grype has no Rocky/Alma vulnerability feed: it matches EL clones against the
# RHEL feed. That is right about whether a CVE applies (they are RHEL rebuilds)
# but wrong about the fix being available — Rocky/Alma rebuild Red Hat's errata
# days-to-weeks later. A fully-upgraded Rocky 9.8 image therefore shows findings
# whose "fixed in 2.48-10.el9_8.1" does not exist in any Rocky repo, so the
# report demands an upgrade that cannot be performed.
#
# This resolves that: it reads each distro repo's package index, finds the
# NEWEST version the distro actually publishes for the affected package, and
# compares it against the fix version grype cites.
#
# Usage:  distro-fix-check.sh <image-repo-name> <raw-grype.json>
# Env:    DISTRO_FIX_ARCH       image arch (x86_64|amd64|aarch64|arm64), default `uname -m`
#         DISTRO_FIX_CACHE_DIR  memoize the package index across invocations
# Output (stdout): JSON keyed by "<pkg>|<comma-joined fix versions>":
#   { "libcap|0:2.48-10.el9_8.1": { "availableInDistro": false,
#                                   "distroLatest": "2.48-10.el9_7.1" }, ... }
#
# Fails soft: any network/parse problem prints "{}" and exits 0, so the vuln
# pipeline keeps publishing (the fields simply stay null = "unknown").
set -uo pipefail

REPO="${1:-}"; RAW="${2:-}"
[[ -n "$REPO" && -f "$RAW" ]] || { echo '{}'; exit 0; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/distrofix.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
log() { echo "[distro-fix] $*" >&2; }
bail() { log "$* — reporting all findings as unknown"; echo '{}'; exit 0; }

# DISTRO_FIX_ARCH overrides the host arch. The build-time caller scans on a
# runner of the image's own architecture, so uname is right there; the mirror's
# daily re-scan walks aarch64 and x86_64 SBOMs from one x86_64 runner and must
# say which one each report is for, or half the corpus gets judged against the
# wrong package index. Accepts either spelling of each arch.
case "${DISTRO_FIX_ARCH:-$(uname -m)}" in
  x86_64|amd64)   RPM_ARCH=x86_64;  DEB_ARCH=amd64 ;;
  aarch64|arm64)  RPM_ARCH=aarch64; DEB_ARCH=arm64 ;;
  *) bail "unsupported arch ${DISTRO_FIX_ARCH:-$(uname -m)}" ;;
esac

# The image repo name carries distro+version, whatever suffix the builder uses:
# rocky-9-uefi-container-disk, alma-10-container-disk, ubuntu-2404-kube, ...
FAMILY=""; MAJOR=""; CODENAME=""
case "$REPO" in
  rocky-*) FAMILY=rocky; MAJOR=$(echo "$REPO" | sed -E 's/^rocky-([0-9]+).*/\1/') ;;
  alma-*)  FAMILY=alma;  MAJOR=$(echo "$REPO" | sed -E 's/^alma-([0-9]+).*/\1/') ;;
  ubuntu-*)
    FAMILY=ubuntu
    case "$(echo "$REPO" | sed -E 's/^ubuntu-([0-9]+).*/\1/')" in
      2004) CODENAME=focal ;; 2204) CODENAME=jammy ;;
      2404) CODENAME=noble ;; 2604) CODENAME=resolute ;;
      *) bail "unknown ubuntu release in '$REPO'" ;;
    esac ;;
  *) bail "cannot derive distro from repo name '$REPO'" ;;
esac

MAP="$WORK/latest.tsv"   # name <TAB> newest-version-in-distro
: > "$WORK/all.tsv"

# DISTRO_FIX_CACHE_DIR memoizes the finished index across invocations. The
# build-time caller judges one image and leaves it unset; the mirror's daily
# re-scan judges ~150 SBOMs that collapse to a couple of dozen distinct
# (family, release, arch) triples, and re-downloading a distro's whole package
# index per SBOM would dwarf the scan itself. Fresh every run — the cache is a
# run-scoped temp dir, not a persisted one, because "newest version the distro
# publishes" is exactly the value that must not go stale.
CACHED=""
if [[ -n "${DISTRO_FIX_CACHE_DIR:-}" ]] && mkdir -p "$DISTRO_FIX_CACHE_DIR" 2>/dev/null; then
  CACHED="${DISTRO_FIX_CACHE_DIR}/latest-${FAMILY}-${MAJOR:-$CODENAME}-${RPM_ARCH}.tsv"
fi

# ---- which findings need judging at all? -------------------------------------
# Extracted BEFORE any index is fetched. Only OS-managed, already-"fixed"
# findings are meaningful here, and an image with none of them — every fully
# upgraded Ubuntu image, in practice, since grype has a native Ubuntu feed —
# needs no index, so the download is skipped entirely rather than performed and
# then found to have nothing to answer.
jq -r '
  .matches[]
  | select(.artifact.type == "rpm" or .artifact.type == "deb" or .artifact.type == "apk")
  | select(.vulnerability.fix.state == "fixed")
  | select((.vulnerability.fix.versions // []) | length > 0)
  | .artifact.name + "|" + ((.vulnerability.fix.versions // []) | join(","))
' "$RAW" 2>/dev/null | sort -u > "$WORK/pairs.txt"

if [[ ! -s "$WORK/pairs.txt" ]]; then
  log "no fixed OS findings to judge — nothing to look up"
  echo '{}'; exit 0
fi

# ---- collect every (package, version) the distro publishes -------------------
decompress() {  # stdin -> stdout, by file extension in $1
  case "$1" in
    *.gz)  gzip -dc ;;
    *.zst) command -v zstd >/dev/null && zstd -dc || cat >/dev/null ;;
    *.xz)  command -v xz   >/dev/null && xz -dc   || cat >/dev/null ;;
    *)     cat ;;
  esac
}

fetch_rpm_repo() {  # $1 = repo root URL (…/BaseOS/x86_64/os)
  local root=$1 repomd href
  repomd=$(curl -sSfL --max-time 120 "${root}/repodata/repomd.xml" 2>/dev/null) || return 1
  href=$(echo "$repomd" | grep -oE 'href="[^"]*primary\.xml[^"]*"' | head -1 | sed 's/href="//; s/"$//')
  [[ -n "$href" ]] || return 1
  # primary.xml is usually a single huge line, so grep -o (not line-based tools).
  curl -sSfL --max-time 300 "${root}/${href}" 2>/dev/null | decompress "$href" \
    | grep -oE '<name>[^<]+</name>|<version epoch="[0-9]+" ver="[^"]+" rel="[^"]+"/>' \
    | sed -E 's|^<name>(.*)</name>$|N\t\1|; s|^<version epoch="[0-9]+" ver="([^"]+)" rel="([^"]+)"/>$|V\t\1-\2|' \
    | awk -F'\t' '$1=="N"{n=$2} $1=="V" && n!=""{print n"\t"$2}' >> "$WORK/all.tsv"
}

fetch_deb_index() {  # $1 = full Packages.* URL
  local url=$1
  curl -sSfL --max-time 300 "$url" 2>/dev/null | decompress "$url" \
    | awk '/^Package: /{p=$2} /^Version: /{if(p!=""){print p"\t"$2}}' >> "$WORK/all.tsv"
}

if [[ -n "$CACHED" && -s "$CACHED" ]]; then
  cp "$CACHED" "$MAP"
  log "reusing cached ${FAMILY}${MAJOR:-$CODENAME}/${RPM_ARCH} index ($(wc -l < "$MAP") packages)"
else
  case "$FAMILY" in
    rocky|alma)
      if [[ "$FAMILY" == rocky ]]; then base="https://dl.rockylinux.org/pub/rocky/${MAJOR}"
      else                              base="https://repo.almalinux.org/almalinux/${MAJOR}"; fi
      # CRB is called PowerTools on EL8. extras/ has no arch subdir on some mirrors;
      # a repo that 404s is simply skipped.
      crb=CRB; [[ "$MAJOR" == "8" ]] && crb=PowerTools
      for r in BaseOS AppStream "$crb" extras; do
        log "reading ${FAMILY}${MAJOR} ${r}"
        fetch_rpm_repo "${base}/${r}/${RPM_ARCH}/os" || log "  (skipped ${r})"
      done ;;
    ubuntu)
      if [[ "$DEB_ARCH" == amd64 ]]; then base="http://archive.ubuntu.com/ubuntu"
      else                                base="http://ports.ubuntu.com/ubuntu-ports"; fi
      for pocket in "$CODENAME" "${CODENAME}-updates" "${CODENAME}-security"; do
        for comp in main universe restricted multiverse; do
          log "reading ${pocket}/${comp}"
          fetch_deb_index "${base}/dists/${pocket}/${comp}/binary-${DEB_ARCH}/Packages.gz" \
            || log "  (skipped ${pocket}/${comp})"
        done
      done ;;
  esac

  [[ -s "$WORK/all.tsv" ]] || bail "no distro package index could be read"

  # Keep only the newest version per package: sort by name, then version ascending,
  # and let the last line for each name win.
  sort -t"$(printf '\t')" -k1,1 -k2,2V "$WORK/all.tsv" \
    | awk -F'\t' '{m[$1]=$2} END{for (k in m) print k"\t"m[k]}' > "$MAP"
  log "distro publishes $(wc -l < "$MAP") packages"

  # Populate the cache only from a complete read; a bail above never gets here,
  # so a transient mirror failure cannot poison every later lookup in the run.
  [[ -n "$CACHED" ]] && cp "$MAP" "$CACHED"
fi

# ---- compare each cited fix against what the distro actually ships -----------

# Epochs are stripped before comparing: the RHEL feed writes "0:2.48-10.el9_8.1"
# while repo metadata carries the epoch separately, and they effectively never
# differ between a fix and the same package's newest build.
strip_epoch() { echo "${1#*:}"; }
ge() {  # $1 >= $2 ?  (version-sort: the greater one sorts last)
  [[ "$1" == "$2" ]] && return 0
  [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" == "$1" ]]
}

: > "$WORK/out.tsv"
while IFS= read -r key; do
  [[ -n "$key" ]] || continue
  name=${key%%|*}; fixvers=${key#*|}
  latest=$(awk -F'\t' -v n="$name" '$1==n{print $2; exit}' "$MAP")
  # Package not published by the distro at all (EPEL, CUDA, DOCA, vendor repos)
  # -> we cannot judge; leave it unknown rather than guess.
  [[ -n "$latest" ]] || continue
  avail=false
  IFS=',' read -ra vs <<< "$fixvers"
  for v in "${vs[@]}"; do
    ge "$(strip_epoch "$latest")" "$(strip_epoch "$v")" && { avail=true; break; }
  done
  printf '%s\t%s\t%s\n' "$key" "$avail" "$latest" >> "$WORK/out.tsv"
done < "$WORK/pairs.txt"

log "judged $(wc -l < "$WORK/out.tsv") of $(wc -l < "$WORK/pairs.txt") fixed OS findings"
log "not yet published by the distro: $(awk -F'\t' '$2=="false"' "$WORK/out.tsv" | wc -l)"

jq -R -s -c '
  split("\n") | map(select(length > 0) | split("\t"))
  | map({key: .[0], value: {availableInDistro: (.[1] == "true"), distroLatest: .[2]}})
  | from_entries
' "$WORK/out.tsv"
