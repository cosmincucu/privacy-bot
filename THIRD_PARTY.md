# Third-party components

`seccomp-browser.json` is adapted from the Playwright v1.63.0 Docker seccomp profile at
https://github.com/microsoft/playwright/blob/v1.63.0/utils/docker/seccomp_profile.json
(Microsoft Corporation, Apache-2.0; licence in `LICENSE.playwright`).
Original SHA-256: `cc3e61cabda6bbc1e53e54d27ba4d55a9d3be829b6dd1a596f4a7b31b1cc7849`.
It retains a default-deny system-call policy and permits the user namespaces
needed by Chromium's sandbox. It applies only to the new application container.
Local change: `chroot` is allowed through seccomp without the outer container's
`CAP_SYS_CHROOT` condition. Chromium needs it inside its own user namespace;
the application container still drops every capability, runs as UID 1000 and
uses no-new-privileges. Kernel privilege checks continue to apply. Without this
change, the real container acceptance failed at Chromium's sandbox chroot.

The browser workflow was adapted from Purchase Bot by the same project author.
Other research projects are references only: no broker lists, application source
or legal templates were copied. Python dependency licences remain with their packages.
