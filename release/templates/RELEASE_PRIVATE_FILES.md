# Private Files Omitted From Release Export

The release export intentionally omits or replaces the following categories:

- machine-specific deploy scripts with hardcoded hosts
- configs that contain real validator seeds or bind addresses
- local checkpoint/watch helpers tied to one operator environment
- internal planning notes that reference private infrastructure

The exported tree keeps release-safe replacements for the public-facing config
files under `cfg/` and omits environment-specific deploy wrappers entirely.

If you need private operational files for your own deployment, recreate them
outside the shared release tree and inject your own hosts, paths, and seeds.
