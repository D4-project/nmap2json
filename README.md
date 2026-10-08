# nmap2json

Convert Nmap XML output to JSON.

`nmap2json` can be used as a Python library or as a command-line tool. It reads
Nmap XML (`-oX`) and returns one JSON array containing one object per host.

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

## Command-line usage

Generate an Nmap XML report:

```bash
nmap -v -A -oX myoutput.xml -p 25,80,443,22 -Pn www.example.org
```

Print converted JSON to stdout:

```bash
python -m nmap2json -i myoutput.xml
```

Write JSON to a file:

```bash
python -m nmap2json -i myoutput.xml -o output.json
```

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
usage: python3 -m nmap2json [-h] -i INPUT [-o OUTPUT] [-m] [-n] [-d] [--debug]

Convert Nmap XML to JSON

options:
  -h, --help           show this help message and exit
  -i, --input INPUT    Input Nmap XML file
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

Load Nmap XML from a string:

```python
import json
from nmap2json import nmap_xml_to_json

python_obj = nmap_xml_to_json(xml_str)
print(json.dumps(python_obj, indent=2))
```

Load Nmap XML from a file:

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
same revision on scanners and migration tools. A plain export/import that
retains old IDs cannot deduplicate old date variants: recalculate port hashes
and derived IDs, merge earliest/latest observation bounds, and remove superseded
IDs during replacement. Preserve original report contents; select a deterministic
representative when several reports merge. nmap2json itself does not migrate
databases or rewrite historical IDs.

## Tests

From the repository root:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

Date regression tests cover SMTP, HTTP/RTSP, escaped banner line endings,
header/cookie clocks, raw-input preservation, and meaningful differences
(service versions, certificate validity, `Last-Modified`, build dates).

## License

GNU Affero General Public License v3 or later.
