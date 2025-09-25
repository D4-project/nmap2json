# nmap2json

## Description 
nmap2json is a simple python library to convert nmap xml output to python object dumpable in json.

It provides also the tool nmapconvert.py where you may save the json as array or, per ip, or send it to the direct output.

## Example

Usage is simple; after running a nmap scan using export into XML file, for example with;

>$ nmap -v -A -oX myoutput.xml -p 25,80,443,22 -Pn www.whateveryouscan.domain

you could simply output the results as a json object.

>$ python nmapconvert.py -i myoutput.xml

## Help


```bash
usage: nmapconvert.py [-h] -i INPUT [-o OUTPUT] [-m]

Convert Nmap XML to JSON

options:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Input Nmap XML file
  -o OUTPUT, --output OUTPUT
                        Output JSON file (prints to stdout if omitted)
  -m, --multiple        Enable multiple JSON outputs (IP prefixed)

```

## Requirements
 - Python >= 3.9

## Library usage 

This library allows you to load a nmap xml output either from a file or from a loaded string.

```python
import json
from nmap2json import nmap_file_to_json, nmap_xml_to_json

Convert the XML loaded in a string
python_obj = nmap_xml_to_json(xml_str)

Convert the XML directly from a file
python_obj = nmap_file_to_json(xml_file)

print(json.dumps(python_obj, indent=2))
```
