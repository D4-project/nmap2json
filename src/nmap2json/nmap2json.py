#!/usr/bin/env python3

"""Normalize Nmap and Masscan XML reports and compute host and port SHA-256 hashes."""

import xml.etree.ElementTree as ET
import json
from io import BytesIO, StringIO
from .masscan import merged_hosts
from .banner import normalize_banner
from .report_xml import read_report
from .smarthash import headers_smart_hash, port_smart_hash


def script_order(script):
    """Sort scripts by ID and break ties between Masscan detections."""
    if script["id"] == "masscan-detection":
        return (
            script["id"],
            script.get("service", ""),
            "output" in script,
            script.get("output", ""),
        )
    return (script["id"],)


def sort_dict(data: str | dict):
    """
    Recursively sorts a nested dictionary structure by key.
    Returns a new sorted structure.
    """

    ignore_keys = set()

    # Sort the dictionary by keys and recursively sort its values
    if isinstance(data, dict):
        return {
            k: sort_dict(v) for k, v in sorted(data.items()) if k not in ignore_keys
        }

    # Recursively process each item in the list
    elif isinstance(data, list):
        normalized_items = [sort_dict(item) for item in data]

        if all(isinstance(i, dict) for i in normalized_items):
            # If id Key is present, sort using that as key (for services)
            if all("id" in d for d in normalized_items):
                return sorted(normalized_items, key=script_order)
            else:
                # Fallback : use json dump with sorting
                return sorted(
                    normalized_items, key=lambda d: json.dumps(d, sort_keys=True)
                )
        else:
            return normalized_items
    else:
        return data  # Whatever it could be.


def parse_table(table: ET.Element):
    """
    Parse a <table> recursively.
    Returns a dict if elems have keys or nested tables,
    otherwise returns a list for simple elem-only tables.
    """

    elems_with_key = {}
    elems_without_key = []

    # Parse found direct <elem>
    for elem in table.findall("elem"):
        key = elem.get("key")
        if key:
            elems_with_key[key] = elem.text
        else:
            elems_without_key.append(elem.text)

    # Parse nested tables
    sub_tables = []
    for sub_table in table.findall("table"):
        # hope recursion will stop :)
        sub_tables.append((sub_table.get("key"), parse_table(sub_table)))

    # Final rebuild
    if elems_with_key or sub_tables:
        sresult = elems_with_key.copy()
        for key, val in sub_tables:
            if key:
                sresult[key] = val
            else:
                # tables without keys.. create a keyword
                # Will be reconverted later by a last pass
                if "__list__" not in sresult:
                    sresult["__list__"] = []
                sresult["__list__"].append(val)
        # if elems_without_key is alone, push under  __list__
        if elems_without_key:
            sresult["__list__"] = elems_without_key
        return sresult
    else:
        # for simpel table
        return elems_without_key


def map_port_and_nse(current_host: ET.Element):
    """
    Parse by port output and NSE scripts results
    """

    ports_data = []
    for port in current_host.findall("ports/port"):
        port_data = port.attrib.copy()
        state = port.find("state")
        service = port.find("service")
        scripts = port.findall("script")

        if state is not None:
            port_data["state"] = state.attrib
        if service is not None:
            port_data["service"] = service.attrib
        if scripts:
            port_data["scripts"] = []
            for s in scripts:
                script_entry = s.attrib.copy()
                if "output" in script_entry:
                    script_entry["output"] = normalize_banner(
                        script_entry["output"], script_entry.get("id")
                    )

                # parse tables recursively, hopes it comes back... :)
                for table in s.findall("table"):
                    table_key = table.get("key", "unknown")
                    script_entry[table_key] = parse_table(table)

                # parse direct <elem> without key
                elems_direct = [
                    e.text for e in s.findall("elem") if e.get("key") is None
                ]
                if elems_direct:
                    script_entry["elems"] = elems_direct

                # parse direct <elem> with key (not inside <table>)
                for elem in s.findall("elem"):
                    key = elem.get("key")
                    if key:
                        script_entry[key] = elem.text

                port_data["scripts"].append(script_entry)

        ports_data.append(port_data)
    return ports_data


def convert_extensions_list(obj: str | dict | None):
    """
    This function will replace __list__ multiple list previousely created
    to named dict.
    """

    if isinstance(obj, dict):
        for key, value in list(obj.items()):
            if key == "extensions" and isinstance(value, dict) and "__list__" in value:
                # Convertir le __list__ en format dict
                new_ext = {}
                for item in value["__list__"]:
                    name = item["name"]
                    val = item.get("value", "")  # somes Items are really empty.
                    new_ext[name] = val
                    if "critical" in item:
                        new_ext[f"{name} critical"] = item["critical"]
                obj[key] = new_ext  # Remplace extensions
            else:
                convert_extensions_list(value)
    elif isinstance(obj, list):
        for item in obj:
            convert_extensions_list(item)


def any_open_port(report: dict):
    """
    Set a Flag to True if any of the scanned port is up
    """
    result = False
    for port in report.get("ports"):
        if port.get("state").get("state") == "open":
            result = True
    return result


def add_port_hashes(ports: list):
    """
    Add a smart hash for each port after the portid key.
    """
    result = []
    for port in ports:
        port_hash = port_smart_hash(port, exclude_keys=["hsh256"])
        hashed_port = {}
        hash_inserted = False
        for key, value in port.items():
            if key == "hsh256":
                continue
            hashed_port[key] = value
            if key == "portid":
                hashed_port["hsh256"] = port_hash
                hash_inserted = True
        if not hash_inserted:
            hashed_port["hsh256"] = port_hash
        result.append(hashed_port)
    return result


def nmap_file_to_json(
    xml_file: str,
    wipe_notopen: bool = False,
    wipe_deadhost: bool = False,
    *,
    hostname_resolver=None,
) -> dict:
    """Read a Nmap or Masscan XML report from a path or file-like object."""
    if hasattr(xml_file, "read"):
        tree = read_report(xml_file)
    else:
        with open(xml_file, "rb") as stream:
            tree = read_report(stream)
    return nmap_to_json(
        tree, wipe_notopen, wipe_deadhost, hostname_resolver=hostname_resolver
    )


def nmap_xml_to_json(
    xml_file: str,
    wipe_notopen: bool = False,
    wipe_deadhost: bool = False,
    *,
    hostname_resolver=None,
) -> dict:
    """Convert Nmap or Masscan XML text or bytes into a list of host reports."""
    stream = BytesIO(xml_file) if isinstance(xml_file, bytes) else StringIO(xml_file)
    tree = read_report(stream)
    return nmap_to_json(
        tree, wipe_notopen, wipe_deadhost, hostname_resolver=hostname_resolver
    )


def nmap_to_json(
    tree: ET,
    wipe_notopen: bool = False,
    wipe_deadhost: bool = False,
    *,
    hostname_resolver=None,
) -> dict:
    """Normalize a parsed report and attach host and port smart hashes."""
    root = tree.getroot() if isinstance(tree, ET.ElementTree) else tree
    masscan_report = root.get("scanner") == "masscan"
    if masscan_report:
        host_elements = merged_hosts(root)
    else:
        host_elements = root.findall("host")

    hosts = []
    for curr_host in host_elements:
        data = {
            "addr": None,  # defined to keep the uppper place in json
            "hsh256": None,
            "starttime": curr_host.get("starttime"),
            "endtime": curr_host.get("endtime"),
            "status": {},
            "hostnames": [],
            "ports": [],
        }

        if masscan_report:
            data["engine"] = "masscan"

        # Status
        status = curr_host.find("status")
        if status is not None:
            data["status"] = status.attrib

        # Address
        addr_elem = curr_host.find("address")
        if addr_elem is not None:
            data["addr"] = addr_elem.attrib.get("addr")

        # Hostnames
        for hostname in curr_host.findall("hostnames/hostname"):
            data["hostnames"].append(hostname.attrib)

        # Ports and port-level NSE scripts
        data["ports"] = map_port_and_nse(curr_host)

        # last pass to convert __list__
        convert_extensions_list(data)

        # Inject True if the host has replied on any ports.
        data["host_reply"] = any_open_port(data)

        if masscan_report and data["host_reply"] and hostname_resolver is not None:
            for hostname in hostname_resolver(data["addr"]) or ():
                if (
                    isinstance(hostname, dict)
                    and isinstance(hostname.get("name"), str)
                    and hostname.get("name")
                    and hostname.get("type") in ("PTR", "user")
                    and hostname not in data["hostnames"]
                ):
                    data["hostnames"].append(dict(hostname))
            data["hostnames"].sort(
                key=lambda item: (item.get("type", ""), item.get("name", ""))
            )

        # If required cleanup non open ports.
        if wipe_notopen:
            copy_data = data.copy()
            copy_data["ports"] = []  # Wipe out the port section.
            if data["ports"]:
                for port in data["ports"]:
                    if port.get("state").get("state") == "open":
                        copy_data["ports"].append(port)
            data = copy_data

        # Sort data for concistent hashing.
        # json.dump with sorted option is not enought since
        # we had list of dict.
        data = sort_dict(data)
        data["ports"] = add_port_hashes(data["ports"])
        data["hsh256"] = headers_smart_hash(
            data, exclude_keys=["starttime", "endtime", "hsh256"]
        )
        # If required cleanup dead host.
        if wipe_deadhost is True:
            if data["host_reply"] is True:
                hosts.append(data)
        else:
            hosts.append(data)

    return hosts
