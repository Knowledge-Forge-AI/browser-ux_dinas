# Destination-owned structured representation of Firefox enterprise policies.
# Semantically validated to match legacy firefox-policies.json["policies"].
# Modernized in BUX3B2B to consume semantic extension durability renderer.
# Contributed to programs.browserBaseline.firefox.policies in BUX3B2A/BUX3B2B.
# BUX5C0 adds PasswordManagerEnabled = false only while KeePassXC is the configured
# password authority, and locks full-screen toolbar autohide (macOS default is false).
# See docs/architecture/browser-operator-preferences.md.
import ./families/gecko.nix
