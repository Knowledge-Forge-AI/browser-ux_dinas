# Known Policy Goals

Default security posture:

- Prevent random sites from accessing camera and microphone.
- Keep password manager and browser extension defaults usable.
- Avoid weakening hardened settings globally when an allowlist will solve the real workflow.

Known practical exceptions:

- Legitimate videoconferencing and HIPAA-compliant telehealth sites should be allowlisted for camera and microphone in Chrome when the user wants start-of-meeting reliability.
- Chrome convenience tier may support Google Wallet card autofill and address autofill when explicitly requested.
- Safari is being evaluated for Apple-site use; do not assume full Chrome-tier policy should be copied there.

Preferred implementation:

- Browser policy should live in the nix-darwin flake.
- Domain exceptions should be explicit and documented.
- Verify through browser policy/status UI where feasible.
