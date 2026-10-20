# Destination-owned structured representation of Chrome managed policy.
# Semantically validated to match legacy chrome-policy.plist via AST comparison.
# Modernized in BUX3B2B to consume semantic extension durability renderer.
# Contributed to programs.browserBaseline.chrome.managedPreferences.
# BUX5C0 adds PasswordManagerEnabled = false only while KeePassXC is the configured
# password authority (docs/architecture/browser-operator-preferences.md).
import ./families/chromium.nix
