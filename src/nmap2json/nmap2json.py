#!/usr/bin/env python3

"""
This library will convert a XLM nmap output file to somehow a usable python object.
It also calculate an unique MD5 hash based on all fields except timestamps ones.

The library provides,

    nmap_file_to_json(str)
    load a xml file and convert it into a python object.
    The input str is a string with the file path.
    nmap_xfl_to_json(str)
    load a xml from a string and convert it into a python object.

"""
import xml.etree.ElementTree as ET
import json
import hashlib


def filter_keys(obj: dict | list, exclude_keys: list):
    """
    Recursively filter out specified keys from dictionaries and lists
    Used before hashing.
    """
    if isinstance(obj, dict):
        return {
            k: filter_keys(v, exclude_keys)
            for k, v in obj.items()
            if k not in exclude_keys
        }
    elif isinstance(obj, list):
        return [filter_keys(i, exclude_keys) for i in obj]
    else:
        return obj


def hash_object(obj: dict, exclude_keys=None):
    """
    Generate sha256 of result.
    """

    exclude_keys = exclude_keys or []
    filtered = filter_keys(obj, exclude_keys)
    obj_str = json.dumps(filtered)  # , sort_keys=True) # keysorting
    return hashlib.sha256(obj_str.encode("utf-8")).hexdigest()


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
                return sorted(normalized_items, key=lambda d: d["id"])
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
        port_data = port.attrib
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
                    val = item["value"]
                    new_ext[name] = val
                    if "critical" in item:
                        new_ext[f"{name} critical"] = item["critical"]
                obj[key] = new_ext  # Remplace extensions
            else:
                convert_extensions_list(value)
    elif isinstance(obj, list):
        for item in obj:
            convert_extensions_list(item)


def nmap_file_to_json(xml_file: str):
    """
    Parse Nmap XML String report
    """
    tree = ET.parse(xml_file)
    return nmap_to_json(tree)


def nmap_xml_to_json(xml_file: str):
    """
    Parse Nmap XML File report
    """
    tree = ET.fromstring(xml_file)
    return nmap_to_json(tree)


def nmap_to_json(tree: ET):
    """
    This is the main parsing function
    """
    root = tree.getroot()

    hosts = []
    for curr_host in root.findall("host"):
        data = {
            "addr": None,  # defined to keep the uppper place in json
            "sha256": None,
            "starttime": curr_host.get("starttime"),
            "endtime": curr_host.get("endtime"),
            "status": {},
            "hostnames": [],
            "ports": [],
        }

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

        # Sort data for concistent hashing.
        data = sort_dict(data)
        data["sha256"] = hash_object(
            data, exclude_keys=["sha256", "starttime", "endtime"]
        )
        hosts.append(data)
    return hosts
