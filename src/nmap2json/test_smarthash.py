#!/usr/bin/env python3

"""
This script will test the smarthash against a converted json collection

"""

import argparse
import json
import hashlib
from smarthash import master_clean, headers_smart_hash, filter_keys


def main(filename: str, debug: bool = False):
    """
    Load a file an smart hash it.
    """
    hosts = []  # Output array.
    with open(filename, "r", encoding="utf-8") as infile:
        read_data = infile.read()
    hosts_in = json.loads(read_data)

    if isinstance(hosts_in, dict):
        # Manage file exported from Plum Island DB
        if hosts_in.get("body"):
            hosts_in = [hosts_in.get("body")]
        else:
            # Manage json of "one hosts"
            hosts_in = [hosts_in]

    for data in hosts_in:
        # Sort data for concistent hashing.
        # json.dump with sorted option is not enought since
        # we had list of dict.
        # smh_data = smarthash(data, ["",""])

        to_exclude = ["starttime", "endtime", "hsh256"]
        to_process = ["http-headers", "http-security-headers"]
        if debug is True:
            # Yes we hash twice in case of debug...
            # data = smarthash(data, ["http-headers", "http-security-headers"])
            filtered = filter_keys(data, to_exclude)  # Remove some fiels from report
            filtered = master_clean(filtered, to_process)
            obj_str = json.dumps(
                filtered,
            )  # dump result before hashing.
            filtered["hsh256"] = hashlib.sha256(obj_str.encode("utf-8")).hexdigest()
            hosts.append(filtered)
        else:
            data["hsh256"] = headers_smart_hash(data, exclude_keys=to_exclude)
            hosts.append(data)
    return hosts


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Display smarthash results against a converted Nmap XML to JSON"
    )
    parser.add_argument(
        "-i", "--input", required=True, help="Input Nmap converted to Json file"
    )
    parser.add_argument(
        "-o", "--output", help="Output JSON file (prints to stdout if omitted)"
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Output the smarthash normalised report",
    )
    args = parser.parse_args()
    result = main(args.input, args.debug)

    if args.output:
        OUTFILE = f"smarthash_{args.input}.json"
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
            print(f"JSON generated: {args.output}")
    else:
        print(json.dumps(result, indent=2))
