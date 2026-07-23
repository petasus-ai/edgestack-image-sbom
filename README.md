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
