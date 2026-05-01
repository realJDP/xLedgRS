# Configuration Templates

This folder contains release-safe example configuration files for running
xLedgRSv2Beta as a follower or validator on XRPL mainnet or testnet.

- `xLedgRSv2Beta.cfg` - Mainnet follower template.
- `testnet.cfg` - Testnet follower template.
- `validator-mainnet.cfg` - Mainnet validator template with seed/token fields left for the operator.
- `validator-testnet.cfg` - Testnet validator template with seed/token fields left for the operator.
- `xLedgRSv2Beta-example.cfg` - General example showing the supported config shape.
- `validators.txt` - Validator public-key list used by the sample configurations.

Never commit a live validator seed, validator token, private key, or production
node database path into this directory.
