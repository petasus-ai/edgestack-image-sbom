# edgestack-image-sbom

Public SBOM + vulnerability mirror for EdgeStack golden container-disk images
(`quay.io/edgestack/*-container-disk`). The registry portal reads it over
CORS-enabled raw.githubusercontent.com. Both file types are keyed by the
image's manifest digest (`manifest_digest` in the quay `/api/v1` tag listing,
without the `sha256:` prefix), so a repository holds one of each per digest:

```
<repository>/sha256-<digest-hex>.spdx.json   # SBOM — immutable
<repository>/sha256-<digest-hex>.vuln.json    # vulnerabilities — mutable
```

`<repository>` is the quay repository name, e.g. `ubuntu-2204-container-disk`.

## `.spdx.json` — SBOM (immutable)

SPDX 2.3 JSON produced by syft (package-level, UTF-8, uncompressed). The source
of truth is the SBOM attached to the image on quay.io via `cosign attach sbom`;
this file is a byte-identical copy. A digest-keyed path is **never rewritten
with different content** — the packages in an image never change.

## `.vuln.json` — vulnerability report (mutable, "last scan")

grype-native JSON. Unlike the SBOM, this file is **mutable**: the same image
accrues new CVEs over time as advisories are published, so the report is the
result of the most recent scan. It is overwritten whenever it is re-scanned
with a **newer grype DB** (`descriptor.db.built` gate). A report is published
even with zero findings (`"matches": []` = "no known vulnerabilities as of
`descriptor.db.built`"). No cosign attachment — a time-varying artifact must
not accrete on the immutable registry digest.

Reports are produced two ways, both applying the same newer-DB update gate:

- **at build time** by [edgestack-image-builder](https://github.com/petasus-ai/edgestack-image-builder)
  CI (`scripts/vuln-pipeline.sh`), right after the SBOM is published;
- **daily** by this repo's `.github/workflows/refresh-vulns.yml`, which updates
  the grype DB, re-scans every `*.spdx.json`, and batches the newly-stale
  reports into one commit. It is self-contained (no image/registry access) and
  pushes with the built-in `GITHUB_TOKEN`.

Do not edit either file type manually.

## Actionability fields

Three projected fields tell the portal that a finding is real but **not**
patchable with a plain `dnf update` / `apt upgrade`, so it must not be counted
as actionable. The daily re-scan has to reproduce all three, or it re-grades
every image the moment it overwrites the build-time report:

- **`vulnerability.fix.availableInDistro`** / **`distroLatest`** — is the fix
  grype cites actually published by this distro yet? grype has no Rocky/Alma
  feed and matches EL clones against Red Hat's, which is right about whether a
  CVE applies and wrong about the fix existing: Rocky rebuilds Red Hat's errata
  days-to-weeks later. `bin/distro-fix-check.sh` reads the distro's own package
  index and answers it. The file is a **verbatim copy** of the builder's
  `scripts/distro-fix-check.sh` so the two stay diffable; `DISTRO_FIX_ARCH`
  (derived here from the SBOM's purl qualifiers, since this job runs on x86_64
  runners and half the mirrored SBOMs are aarch64) and `DISTRO_FIX_CACHE_DIR`
  (one index read per family/release/arch instead of per SBOM) are the only
  knobs the refresh sets.
- **`artifact.vendored`** — a copy bundled inside another package (a `_vendor/`
  path). Judged from the SBOM's `sourceInfo`, and only when *every* entry for
  that version is vendored, so a stale bundle beside a real install keeps the
  real one actionable.
- **`artifact.frozen`** — a package the image's upgrade-freeze policy pins in
  place. The fix may exist, but applying it on a running node is unsupported;
  the remediation is a rebuild. Policy lives in `bin/freeze-policy.json`, keyed
  by image repository, because the builders sharing this mirror do not have the
  same freeze list — one global regex would be wrong for all of them. A
  repository with no entry gets `frozen:false` everywhere, so a builder that
  has not added itself is unaffected. Each entry is copied from that builder's
  `scripts/supply-chain.conf` and must be kept in sync with it.

## Retention

SBOMs are immutable, so a rebuilt tag moves to a new digest and the previous
digest's files become orphans that would otherwise accumulate forever.
`.github/workflows/prune-orphans.yml` (weekly + `workflow_dispatch`, with a
`dry_run` input) runs `bin/prune-orphans.sh`, which lists each repository's
active tags via the public quay API and removes the `.spdx.json`/`.vuln.json`
of any digest no longer referenced by a live tag. This bounds both the working
tree and the daily re-scan set to the digests currently on quay. It is safe by
construction: if the quay API for a repository fails or returns no digests,
that directory is skipped untouched, so a transient error can never delete
valid files. It keeps any digest a live tag points at, regardless of which
branch (master or cilium) built it.

The two maintenance workflows share a `mirror-maintenance` concurrency group so
the daily re-scan and the weekly prune never run against the tree at once.
