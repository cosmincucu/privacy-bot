# Contributing with an agent

Read README.md and the relevant documents under docs/ before changing the product.
Use synthetic fixtures and isolated data for tests. Preserve encrypted-state and API
compatibility, dependency pins and third-party notices.

- Product code, generic examples and tests belong here. Personal data, credentials,
  browser profiles, operational transcripts and deployment inventories do not.
- Keep sources optional. Unavailable, blocked, needs-login and unknown must never
  mean clean, absent or removed. Preserve explicit review before sending requests.
- Run pytest and exercise the actual UI for changes that affect browser behavior.
  Report failed and skipped checks accurately.
- Do not deploy, publish, send notifications, access personal accounts or delete
  runtime state without authorization for that specific action.
- Follow the contributor's configured identity, model and worker policies outside
  this repository. Keep private machine paths and account details out of source.

Write documentation for someone installing the application for the first time.
Explain current behavior, prerequisites, limitations and recovery steps.
