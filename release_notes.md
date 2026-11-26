# Release Notes

## v2611.05

- Exclude nonzero response TTL values from Nmap and Masscan host and port
  smart hashes. Retain zero TTL in the hash and keep the original TTL value
  in the JSON report.

## v2611.04

- Add `"engine": "masscan"` only to Masscan host reports. Nmap JSON stays
  unchanged; unmarked reports are treated as Nmap by Plum.
- Exclude this report metadata from host content hashes. Existing host, port
  and script hashes remain unchanged; NSE data named `engine` is preserved.

## v2611.03

- Preserve the full received banner and Masscan detection outputs with consistent
  escaped bytes. Provide an optional bounded preview without splitting bytes.
- Mask observed protocol dates and FTP clocks before hashing both script types,
  including an HTTP Date header cut by the banner budget.
- Hashes for affected observations change. Stored historical reports require
  explicit reconversion and rehashing to adopt this policy.

## v2611.2 - Masscan report conversion

- Convert Masscan XML into the existing per-host and per-port JSON shape.
- Group repeated observations by IP and transport/port; preserve observed
  services and banners as `masscan-detection` script entries.
- Keep status-only ports free of inferred application protocols.
- Accept hostnames supplied by the caller for Masscan IPs with open ports,
  before calculating document hashes. This lets Plum-Agent preserve requested
  FQDNs and PTR records without looking up IPs with no open port.
- Preserve existing Nmap output and smart hashes across the regression corpus.
- Package version: `2611.2`. This version supersedes the local `2611.1` candidates.

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

### Packaging

- Existing raw scan data remains unchanged.
- SHA-256 and JSON serialization remain unchanged.
- Hashes for affected reports may change after rehashing. Existing stored
  hashes are not migrated automatically.
- PyPI package version: `2610.1` (PEP 440 form matching GitHub release
  `v2610.01`).

### Commits

- `75934bb` Normalize volatile protocol dates before smart hashing
- `3c19c73` Fix issue 8
