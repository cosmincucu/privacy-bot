# Named job-status readers

A machine reader can call only `GET /api/dashboard`. Its response contains job
status, schedule settings, recent run status, and the status fields needed to
count findings, removals and unread alerts. The server omits profile data, credit
reports, evidence, source matching configuration, URLs, free-text diagnostics,
browser sessions and all future extra fields. Browser access is unchanged.

Machine readers are disabled by default. To enable one, generate an independent
random bearer with at least 32 bytes of entropy, store it in a protected credential
store and provide it only to the named caller. Mount a mode-0600 JSON registry
readable by the application and set `PRIVACY_BOT_JOB_READERS_FILE` to its path:

```json
{
  "schema_version": 1,
  "readers": [
    {"id": "assistant", "sha256": "<64 lowercase hexadecimal SHA-256 characters>"}
  ]
}
```

Replace the placeholder with the digest of the exact UTF-8 token. The registry
contains digests, never bearer values. Identifiers and digests must be unique;
additional permissions and wildcard scopes are rejected. A configured file must
exist, be a regular file rather than a symlink, and deny group/world access.

The caller sends `Authorization: Bearer TOKEN` to the configured HTTPS
`PUBLIC_URL`, including its path prefix. The configured Host check still applies.
Every other route and every write is denied, including login and browser-session
creation. An invalid bearer cannot fall back to a broader browser or private
network session. Keep bearer values out of source, request URLs and logs.

Revoke a reader by removing its entry, or rotate it by replacing the digest and
the caller's token. Restart the application to load the new registry. An empty
list revokes all readers without affecting browser access. This capability does
not enable assistant writes or send notifications.
