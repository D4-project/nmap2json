# nmap2json

Convert saved Nmap and Masscan XML reports into a common JSON format.
The command-line tool and Python library produce the same array of host
objects with a shared host and port schema and the same smart-hash rules.

For Masscan XML reports up to 1 MiB, the converter groups repeated observations
by IP address, transport protocol, and port. It stores observed services and
banners in `masscan-detection` script entries and adds `"engine": "masscan"`
to each host. An open port without service evidence remains unlabeled.

## Requirements

- Python 3.10+

## Installation

From this repository:

```bash
python -m pip install .
```

After updating this checkout, reinstall it in the environment used by your
scanner or migration tools (updating Git alone does not update that environment):

```bash
python -m pip install --force-reinstall --no-deps .
python -c "import nmap2json.smarthash as s; print(s.__file__)"
```

The package metadata uses a calendar-style release version. Record the deployed
Git revision with `git rev-parse HEAD` as well when installing from source.
Installing this checkout does not publish a release to PyPI.

## Banner storage and Plum compatibility

Version `2611.5` uses the Git tag `v2611.05`. Install the same version in each
Plum-Island, Plum-Agent, and migration environment to keep hashes consistent.

Preserve the complete banner received from either scanner, without a new
64-character storage limit. The original Nmap `banner.nse` output may already
be truncated and cannot be reconstructed. Masscan's FTP parser removes carriage
returns; normalization does not invent missing bytes. Nonprintable bytes use
consistent `\xNN` escaping. Optional display clipping does not affect stored data.

Masscan host reports include `"engine": "masscan"`, determined from the XML
scanner attribute. Nmap reports stay unchanged: no Nmap marker is added.
The engine metadata is excluded from host hashes; port and script hashes are
unchanged. Plum treats unmarked reports as Nmap without migrating historical data.

Why no Nmap marker: Nmap is Plum's historical default. Explicitly marking it
would require a bulk backfill and redundant index memberships on installations
with two million reports. Plum instead searches Nmap as the candidate UID set
minus explicitly marked Masscan UIDs. No historical reports are rewritten; an
old unmarked Masscan report is consequently treated as Nmap. This is scanner
metadata (`engine:masscan`), not an Antibodies tag.

Masscan service/output metadata remains in `masscan-detection`. Plum-Island adds
the standard `banner` script and extracts observed HTTP response headers into
`http-headers`, before hashing and tagging. The IP view shows a single full banner
block, as for Nmap. Protocol dates and FTP clocks are masked only in hash input;
original observations remain intact. Affected hashes can change; existing stored
hashes require explicit reconversion and rehashing to adopt the new policy.

## Command-line usage

Convert a saved Nmap or Masscan XML report with the same command.

```bash
python -m nmap2json -i nmap-report.xml -o output.json
python -m nmap2json -i masscan-report.xml -o output.json
```

Omit `-o` to print the JSON to stdout.

Write one JSON file per host, prefixed with the host IP:

```bash
python -m nmap2json -i myoutput.xml -o output.json --multiple
```

Filter output:

```bash
python -m nmap2json -i myoutput.xml --notopen
python -m nmap2json -i myoutput.xml --deadhost
```

## CLI help

```text
usage: python -m nmap2json [-h] -i INPUT [-o OUTPUT] [-m] [-n] [-d] [--debug]

Convert saved Nmap or Masscan XML reports to JSON

options:
  -h, --help           show this help message and exit
  -i, --input INPUT    Input XML report
  -o, --output OUTPUT  Output JSON file (prints to stdout if omitted)
  -m, --multiple       Enable multiple JSON outputs (IP prefixed)
  -n, --notopen        Remove from output closed ports
  -d, --deadhost       Remove from output dead hosts
  --debug              Export with smarthash masking
```

Note: `--debug` is currently parsed but not applied by the CLI. It does not
export masked data. Use `master_clean()` below to inspect normalization.

## Added fields

Each host object includes extra fields:

```json
{
  "host_reply": true,
  "hsh256": "446c094a24f248da6a87cc7bffaae3df9cf5b0dc5a07d1ca7fff8cdb2071b389"
}
```

- `host_reply`: `true` when at least one scanned port is open.
- `hsh256`: stable SHA-256 hash of the host object, excluding `starttime`,
  `endtime`, and existing hash fields.

Each port also gets its own `hsh256` field.

### Response TTL and hashes

Since `2611.5`, host and port hashes omit nonzero `reason_ttl` values for both
scanners. A reply's TTL can change with the network path and hop count, even
when the host and service are unchanged. An explicit zero stays in the hash
input to preserve the historical treatment of zero in existing hashes. The
exported JSON retains the original `reason_ttl` value.

Smart hashing masks volatile protocol dates with a fixed `[DATE]` marker in
the hash input: SMTP `220 ...; <date>` greetings, HTTP/RTSP `Date:` headers in
`banner`, and `Date:` headers in `http-headers` / `http-security-headers`
(plus cookie expiry). Textual weekday/month dates support case variations, one- or
two-digit days, numeric timezones, and month-first RTSP dates. Banner line
breaks may be literal or Nmap-escaped. This is deliberately not a generic
date remover: certificate validity, `Last-Modified`, and build dates remain
significant. Other date formats are not currently normalized.

Normalization leaves original reports unchanged. SHA-256 and the existing
JSON serialization remain unchanged. Previously stored hashes are not updated
automatically: rehashing old reports requires a separate migration, including
merging observation timestamps when multiple old IDs collapse to one new ID.

## Library usage

Load a Nmap or Masscan XML report from a string.

```python
import json
from nmap2json import nmap_xml_to_json

python_obj = nmap_xml_to_json(xml_str)
print(json.dumps(python_obj, indent=2))
```

Load a Nmap or Masscan XML report from a file.

```python
import json
from nmap2json import nmap_file_to_json

python_obj = nmap_file_to_json("myoutput.xml")
print(json.dumps(python_obj, indent=2))
```

Filter closed ports or dead hosts from library calls:

```python
from nmap2json import nmap_file_to_json

only_open_ports = nmap_file_to_json("myoutput.xml", wipe_notopen=True)
only_live_hosts = nmap_file_to_json("myoutput.xml", wipe_deadhost=True)
```

### Smart hashing an existing port report

```python
from copy import deepcopy
from nmap2json.smarthash import port_smart_hash

port = {
    "protocol": "tcp",
    "portid": "25",
    "scripts": [{
        "id": "banner",
        "output": "220 mail ESMTP; mon, 2 mar 2026 10:13:52 -0500",
    }],
}
later = deepcopy(port)
later["scripts"][0]["output"] = (
    "220 mail ESMTP; Tue, 12 May 2026 10:15:46 GMT"
)
assert port_smart_hash(port) == port_smart_hash(later)
assert "mon, 2 mar" in port["scripts"][0]["output"]  # Raw data unchanged.
```

`port_smart_hash()` returns a lowercase SHA-256 hexadecimal string and excludes
existing `hsh256` fields by default. For a complete host object, call
`headers_smart_hash(host, exclude_keys=["starttime", "endtime", "hsh256"])`.
Unlike the converter, a direct call does not sort input dictionaries/lists:
keep serialization order consistent when rehashing stored reports.

To inspect a normalized copy without hashing:

```python
from nmap2json.smarthash import master_clean, SMART_HASH_SCRIPTS

normalized = master_clean({"ports": [port]}, SMART_HASH_SCRIPTS)
print(normalized["ports"][0]["scripts"][0]["output"])
# 220 mail ESMTP; [DATE]
```

### Existing datasets

The improved normalization changes hashes for affected reports. Deploy the
same revision on scanners and migration tools. A plain export/import that keeps
old IDs retains separate date or TTL variants. Recalculate port hashes and derived
IDs, merge earliest/latest observation bounds, and remove superseded IDs during
replacement. Preserve original report contents; select a deterministic
representative when several reports merge. nmap2json itself does not migrate
databases or rewrite historical IDs.

## Tests

From the repository root:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

Regression tests cover the common Masscan and Nmap output format, nonzero
TTL stability, and preservation of the historical zero TTL behavior. Date tests
cover SMTP, HTTP/RTSP, escaped banner line endings,
header/cookie clocks, raw-input preservation, and meaningful differences
(service versions, certificate validity, `Last-Modified`, build dates).

## License

GNU Affero General Public License v3 or later.
