# Browser UX Scrollbar Visibility privacy policy

This policy applies to Browser UX Scrollbar Visibility, including its Firefox and Chromium editions. Installation and distribution may occur through Mozilla Add-ons, the Chrome Web Store, or administrator-managed policy.

## Local processing

The extension examines page DOM structure, computed styles, scroll geometry, and modal, popover and fullscreen state to draw usable vertical scroll controls. It handles pointer and wheel input on those controls, checks focus state to preserve page interaction, and checks a bounded set of keyboard activation keys (`Space`, `Enter`, `ArrowDown`, `ArrowUp`, `F4`) on native `<select>` controls to detect native picker activity. Website content and user activity are processed locally within the browser only as needed for this feature. It does not log arbitrary keystrokes, extract form values, read credentials, or maintain a browsing-history record.

## Collection, storage and sharing

The extension has no analytics, telemetry, account system, remote executable code, or external network data transmission. It does not persist page content or interactions and does not send them to the developer or any third party. The developer receives no extension-processed page data. Transient state is discarded when the page or extension context closes.

Browser installation and update checks, marketplace account details, and marketplace usage statistics are handled separately by the browser or marketplace under its own policies. The Firefox edition declares no data collection in its manifest. Marketplace signing and review are separate from the extension's local processing; this policy does not claim marketplace approval.

## Permissions and user control

The `scripting` permission inserts packaged scrollbar CSS at `USER` origin. HTTP and HTTPS host access (`http://*/*` and `https://*/*`) allows the feature to operate across supported websites and eligible frames. Browser-restricted pages and documented rendering limits remain excluded. You can disable or remove the extension through the browser; where an administrator manages installation via enterprise or declarative policy, contact that administrator.

## Limited Use

Use of locally processed website content and interaction information is limited to the extension's single purpose: making hidden scroll controls visible and usable. The extension is designed to comply with the Chrome Web Store User Data Policy, including the Limited Use requirements. It does not use or transfer user data for advertising, profiling, creditworthiness, lending, or unrelated purposes. No human receives or reads page data through this extension.

## Contact

Samuel Leighton Lair — sam.lair@knowledge-forge.ai
