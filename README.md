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

## License

GNU Affero General Public License v3 or later.
