# Release Notes

## Unreleased

- Normalize volatile SMTP greeting, HTTP/RTSP banner and HTTP header dates to
  a fixed marker before port and host smart hashing. Support case differences,
  variable day widths, numeric timezones and escaped banner line endings.
- Preserve meaningful certificate, build and Last-Modified dates. Keep raw
  inputs unchanged, including direct calls to `master_clean()`.
- Add regression tests and document direct library usage, source reinstalls
  and historical rehash/deduplication requirements. Existing stored hashes are
  not migrated automatically; SHA-256 and serialization remain unchanged.

- Mask `X-GitHub-Request-Id` and `X-Fastly-Request-ID` before smart hashing.
- Mask `Connection-Id` before smart hashing.
- Move the smart hash debug helper out of the package source tree.
