# Operator Scripts

This folder contains small release and startup helpers for local operators.

- `export-release-candidate.sh` - Produces a sanitized release tree and verifies that private config values were not exported.
- `start-xLedgRSv2Beta.sh` - Starts a follower node using the shipped release naming.
- `start-xLedgRSv2Beta-validator.sh` - Starts a validator-mode node using the validator config template.

These scripts are convenience wrappers; the canonical binary entrypoint remains
`xledgrs`.
