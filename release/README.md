# Release Packaging

This folder contains the files used to export a clean public release tree.

To produce a shareable release tree, run:

```bash
bash scripts/export-release-candidate.sh
```

That export:

- copies the repository into `../xLedgRSv2Beta`
- excludes private ops files listed in `release/export-ignore.txt`
- keeps the release-safe public config templates in `cfg/`
- installs public release notes from `release/templates/`
- verifies the exported `cfg/` tree has no uncommented `validation_seed`
- verifies the exported deploy/config templates do not hardcode hosts or raw IPs

The release templates live under `release/templates/`.
