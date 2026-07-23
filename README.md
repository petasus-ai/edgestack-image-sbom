# edgestack-image-sbom

Public SBOM mirror for EdgeStack golden container-disk images
(`quay.io/edgestack/*-container-disk`). The source of truth is the SBOM
attached to each image on quay.io via `cosign attach sbom`; this repository
holds a byte-identical copy so the registry portal can read it over
CORS-enabled raw.githubusercontent.com.

## Layout

```
<repository>/sha256-<digest-hex>.spdx.json
```

- `<repository>` — quay repository name, e.g. `ubuntu-2204-container-disk`
- `<digest-hex>` — the image's manifest digest without the `sha256:` prefix
  (identical to `manifest_digest` in the quay `/api/v1` tag listing)
- Content — SPDX 2.3 JSON produced by syft, UTF-8, uncompressed

Files are **immutable**: a digest-keyed path is never rewritten with different
content. Files are published automatically by the CI of
[edgestack-image-builder](https://github.com/petasus-ai/edgestack-image-builder)
(`scripts/sbom-pipeline.sh`); do not edit manually.
