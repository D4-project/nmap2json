# nmap2json

## Description 
nmap2json is a simple python script to convert nmap xml output to json object.
You may save json, per ip, or send it to the direct output.

## Example

Usage is simple; after running a nmap scan using export into XML file, for example with;

>$ nmap -v -A -oX myoutput.xml -p 25,80,443,22 -Pn www.whateveryouscan.domain

you could simply output the results as a json object.

>$ python nmap2json.py -i myoutput.xml

## Help


```bash
usage: nmap2json.py [-h] -i INPUT [-o OUTPUT] [-m]

Convert Nmap XML to JSON

options:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Input Nmap XML file
  -o OUTPUT, --output OUTPUT
                        Output JSON file (prints to stdout if omitted)
  -m, --multiple        Enable multiple JSON outputs (IP prefixed)

```