#!/usr/bin/env python3


"""
This script will convert a XLM nmap output file to somehow a usable Json
It also calculate an unique MD5 hash based on any field except timestamps ones.

It may also be used as a library, the main function is nmap_xml_to_json(xml_file)

"""
import os
import json
import argparse
from nmap2json import nmap_file_to_json

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert Nmap XML to JSON")
    parser.add_argument("-i", "--input", required=True, help="Input Nmap XML file")
    parser.add_argument(
        "-o", "--output", help="Output JSON file (prints to stdout if omitted)"
    )
    parser.add_argument(
        "-m",
        "--multiple",
        action="store_true",
        help="Enable multiple JSON outputs (IP prefixed)",
    )
    args = parser.parse_args()

    result = nmap_file_to_json(args.input)

    if args.output:
        if args.multiple:
            i = 0
            for host in result:
                i += 1
                filename = os.path.splitext(args.output)[
                    0
                ]  # split on name to get it without ext.
                if host["addr"]:
                    OUTFILE = f"{host['addr']}_{filename}.json"
                else:
                    OUTFILE = f"NOIP_{filename}_NOIP_{i}.json"
                with open(OUTFILE, "w", encoding="utf-8") as f:
                    json.dump(host, f, indent=2)
                print(f"{i} JSON generated: {OUTFILE}")
        else:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2)
            print(f"JSON generated: {args.output}")
    else:
        print(json.dumps(result, indent=2))
