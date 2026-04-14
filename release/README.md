# Release Export

The working `xLedgRS-1.7` tree can keep private deploy hosts, validator seeds,
and machine-specific configs while we are still testing locally.

When you are ready to produce a shareable beta tree, run:

```bash
bash scripts/export-release-candidate.sh
```

That export:

- copies the current source tree into `../XLedgRS-V1Beta`
- excludes private ops files listed in `release/export-ignore.txt`
- installs sanitized replacement configs and a generic deploy script
- verifies the exported `cfg/` tree has no uncommented `validation_seed`
- verifies the exported deploy/config templates do not hardcode hosts or raw IPs

The release templates live under `release/templates/` so they can be reviewed
and edited without touching the private operational files in the active tree.
