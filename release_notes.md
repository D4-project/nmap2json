# Release Notes

## v2610.01 - 2026-10-08

Release candidate for changes since `v2605.01`.

### Smart Hash Stability

- Normalize volatile protocol timestamps before port and host smart hashing:
  SMTP greetings, HTTP/RTSP banner `Date:` headers, HTTP `Date:` headers, and
  cookie expiry values.
- Support case variations, one- or two-digit days, numeric timezones, and
  escaped banner line endings.
- Preserve meaningful dates and identifiers in hash input, including
  certificate validity periods, `Last-Modified`, service versions, and build
  dates.
- Mask additional volatile headers before smart hashing:
  `X-GitHub-Request-Id`, `X-Fastly-Request-ID`, and `Connection-Id`.

### Documentation and Tests

- Document source reinstall requirements, smart-hash helper usage, and
  historical rehash/deduplication expectations.
- Add regression tests for volatile date normalization, header masking, raw
  input preservation, and meaningful hash differences.
- Move the smart-hash debug helper out of the package source tree into
  `tests/smarthash_debug.py`.

### Compatibility Notes

- Existing raw scan data remains unchanged.
- SHA-256 and JSON serialization remain unchanged.
- Hashes for affected reports may change after rehashing. Existing stored
  hashes are not migrated automatically.
- The package metadata still uses version `0.0.0`; record deployed Git
  revisions when installing from source.

### Commits

- `75934bb` Normalize volatile protocol dates before smart hashing
- `3c19c73` Fix issue 8
