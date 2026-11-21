#!/usr/bin/env python3

"""
This script will convert a XLM nmap output file to somehow a usable Json
It also calculate an unique MD5 hash based on any field except timestamps ones.

It may also be used as a library, the main function is nmap_xml_to_json(xml_file)

"""
from ipaddress import ip_address
from pathlib import Path
import json
import argparse
from .nmap2json import nmap_file_to_json

def main(argv=None):
    parser = argparse.ArgumentParser(description="Convert saved Nmap or Masscan XML reports to JSON")
    parser.add_argument("-i", "--input", required=True, help="Input XML report")
    parser.add_argument(
        "-o", "--output", help="Output JSON file (prints to stdout if omitted)"
    )
    parser.add_argument(
        "-m",
        "--multiple",
        action="store_true",
        help="Enable multiple JSON outputs (IP prefixed)",
    )
    parser.add_argument(
        "-n",
        "--notopen",
        action="store_true",
        help="Remove from output closed ports",
    )
    parser.add_argument(
        "-d",
        "--deadhost",
        action="store_true",
        help="Remove from output dead hosts",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Export with smarthash masking",
    )

    args = parser.parse_args(argv)
    result = nmap_file_to_json(args.input, args.notopen, args.deadhost)

    if args.output:
        if args.multiple:
            destination = Path(args.output)
            for i, host in enumerate(result, start=1):
                try:
                    address = str(ip_address(host.get("addr") or ""))
                    # A zone identifier is not part of an IP file name.
                    address = address.split("%", 1)[0]
                except ValueError:
                    address = "NOIP"
                suffix = f"_NOIP_{i}" if address == "NOIP" else ""
                output_file = destination.with_name(f"{address}_{destination.stem}{suffix}.json")
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(host, f, indent=2)
                print(f"{i} JSON generated: {output_file}")
        else:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2)
            print(f"JSON generated: {args.output}")
    else:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
