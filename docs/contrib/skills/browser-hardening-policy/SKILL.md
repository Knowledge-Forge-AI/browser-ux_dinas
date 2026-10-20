---
name: browser-hardening-policy
description: Manage browser hardening policy and practical exceptions for Chrome, Firefox, Brave YouTube, and Safari on the user's Mac. Use when changing browser managed preferences, extension policy, password manager/autofill policy, camera or microphone allowlists, telehealth or videoconferencing site exceptions, Safari hardening tiers, or browser policy verification.
---

# Browser Hardening Policy

## Overview

Use this skill to keep browser policy secure by default while preserving practical workflows such as telehealth, interviews, password management, and autofill.

## Workflow

1. Identify the browser and policy tier before changing anything:
   - Chrome: convenience tier with managed exceptions.
   - Firefox: privacy/security tier with fewer convenience exceptions.
   - Brave YouTube: modified browser/PWA wrapper, treat separately.
   - Safari: evaluate before applying Chrome-tier convenience hardening.
2. Locate policy sources in this Browser UX repository under `config/browser` and `modules` before editing. Core remains the selected physical writer. Use `rg` for Chrome, Firefox, Safari, Brave, KeePassXC, camera, microphone, autofill, and extension IDs.
3. Prefer allowlists over global access. Camera and microphone should remain blocked by default except for legitimate videoconferencing and HIPAA-compliant telehealth sites.
4. Do not weaken unrelated browser hardening while fixing a workflow.
5. Record exact domains, policy keys, and rationale in the relevant nix-darwin docs when adding exceptions.
6. Verify the policy in the browser UI or policy page after activation when feasible.

## Exception Rules

- Camera and microphone: allow known meeting and telehealth domains by default only when the user wants to avoid start-of-meeting friction.
- KeePassXC and password manager defaults: avoid locking settings unnecessarily; keep browser and extension policy aligned.
- Card and address autofill: Chrome convenience tier may allow Google Wallet/card/address workflows when explicitly requested.
- Safari: do not assume Chrome policies map directly. Research Safari-managed preference support and user workflow first.

## Verification

Prefer concrete checks:

- Chrome: `chrome://policy`, extension settings, site settings, and managed preference files.
- Firefox: `about:policies`, extension settings, and profile policy files.
- Safari: managed preferences, Settings UI, and actual site permission prompts.

Use browser automation or app UI only when it is safer than direct file/policy inspection.

## BUX5A authority boundary

Browser UX owns these sources; core remains the selected command owner until BUX6.
The destination command package is unregistered. Explicit BUX5A trials are limited
to help, status, and fixture-only dry runs. Starting a destination Brave session
would reuse core's launchd label and mutate CNT state; it requires separate operator
authorization and is not a qualification step. Normal activation and promotion
never authorize CNT imports/clears or Shared Images mutation/sync. Generic rclone
and storage authority remain external to Browser UX. Even rclone dry runs contact
a remote; use recording stubs for qualification.
