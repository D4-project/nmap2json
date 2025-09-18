#!/usr/bin/env python3

'''
This script will convert a XLM nmap output file to somehow a usable Json
It also calculate an unique MD5 hash based on any field except timestamps ones.

It may also be used as a library, the main function is nmap_xml_to_json(xml_file)

'''
import os
import xml.etree.ElementTree as ET
import json
import argparse
import hashlib

def filter_keys(obj, exclude_keys):
    ''' 
    Recursively filter out specified keys from dictionaries and lists
    Used before hashing.
    '''
    if isinstance(obj, dict):
        return {k: filter_keys(v, exclude_keys) for k, v in obj.items() if k not in exclude_keys}
    elif isinstance(obj, list):
        return [filter_keys(i, exclude_keys) for i in obj]
    else:
        return obj

def hash_object(obj, exclude_keys=None):
    ''' 
    Generate md5 of result. 
    '''
    exclude_keys = exclude_keys or []
    filtered = filter_keys(obj, exclude_keys)
    obj_str = json.dumps(filtered) # , sort_keys=True) # keysorting
    return hashlib.md5(obj_str.encode('utf-8')).hexdigest()

def sort_dict(data):
    """
    Recursively sorts a nested dictionary structure by key.
    Returns a new sorted structure.
    #TODO Still somme issues with dict in list.
    """
    if isinstance(data, dict):
        # Sort the dictionary by keys and recursively sort its values
        return {k: sort_dict(data[k]) for k, v in sorted(data.items())}
    elif isinstance(data, list):
        # Recursively process each item in the list
        return [sort_dict(item) for item in data]
    else:
        # Non-dictionary, non-list values are left as-is
        return data

def parse_table(table):
    '''
    Parse a <table> recursively.
    Returns a dict if elems have keys or nested tables,
    otherwise returns a list for simple elem-only tables.
    '''
    elems_with_key = {}
    elems_without_key = []

    # Parse found direct <elem>
    for elem in table.findall('elem'):
        key = elem.get('key')
        if key:
            elems_with_key[key] = elem.text
        else:
            elems_without_key.append(elem.text)

    # Parse nested tables
    sub_tables = []
    for sub_table in table.findall('table'):
        # hope recursion will stop :)
        sub_tables.append((sub_table.get('key'), parse_table(sub_table)))

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

def map_port_and_nse(current_host):
    """
    Parse by port output and NSE scripts results
    """
    ports_data = []
    for port in current_host.findall('ports/port'):
        port_data = port.attrib
        state = port.find('state')
        service = port.find('service')
        scripts = port.findall('script')

        if state is not None:
            port_data['state'] = state.attrib
        if service is not None:
            port_data['service'] = service.attrib
        if scripts:
            port_data['scripts'] = []
            for s in scripts:
                script_entry = s.attrib.copy()

                # parse tables recursively, hopes it comes back... :)
                for table in s.findall('table'):
                    table_key = table.get('key', 'unknown')
                    script_entry[table_key] = parse_table(table)

                # parse direct <elem> without key
                elems_direct = [e.text for e in s.findall('elem') if e.get('key') is None]
                if elems_direct:
                    script_entry['elems'] = elems_direct

                # parse direct <elem> with key (not inside <table>)
                for elem in s.findall('elem'):
                    key = elem.get('key')
                    if key:
                        script_entry[key] = elem.text

                port_data['scripts'].append(script_entry)

        ports_data.append(port_data)
    return ports_data

def convert_extensions_list(obj):
    '''
    This function will replace __list__ multiple list previousely created
    to named dict. 
    '''
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

def nmap_xml_to_json(xml_file):
    """
    Parse Nmap XML report
    """
    tree = ET.parse(xml_file)
    root = tree.getroot()

    hosts = []
    for curr_host in root.findall('host'):
        data = {
            'addr': None, # defined to keep the uppper place in json
            'sha256': None,
            'starttime': curr_host.get('starttime'),
            'endtime': curr_host.get('endtime'),
            'status': {},
            'hostnames': [],
            'ports': [],
        }

        # Status
        status = curr_host.find('status')
        if status is not None:
            data['status'] = status.attrib

        # Address
        addr_elem = curr_host.find('address')
        if addr_elem is not None:
            data['addr'] = addr_elem.attrib.get('addr')

        # Hostnames
        for hostname in curr_host.findall('hostnames/hostname'):
            data['hostnames'].append(hostname.attrib)

        # Ports and port-level NSE scripts
        data['ports'] = map_port_and_nse(curr_host)

        # last pass to convert __list__
        convert_extensions_list(data)

        # Sort data for concistent hashing.
        data = sort_dict(data)
        data['sha256'] = hash_object(data, exclude_keys=["sha256", "starttime", "endtime"])
        hosts.append(data)
    return hosts


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Convert Nmap XML to JSON")
    parser.add_argument('-i', '--input', required=True, help="Input Nmap XML file")
    parser.add_argument('-o', '--output', help="Output JSON file (prints to stdout if omitted)")
    parser.add_argument('-m', '--multiple', action='store_true',
                        help="Enable multiple JSON outputs (IP prefixed)")
    args = parser.parse_args()

    result = nmap_xml_to_json(args.input)

    if args.output:
        if args.multiple:
            i=0
            for host in result:
                i += 1
                filename = os.path.splitext(args.output)[0] # split on name to get it without ext.
                if host['addr']:
                    OUTFILE = f"{host['addr']}_{filename}.json"
                else:
                    OUTFILE = f"NOIP_{filename}_NOIP_{i}.json"
                with open(OUTFILE, 'w', encoding='utf-8') as f:
                    json.dump(host, f, indent=2)
                print(f"{i} JSON generated: {OUTFILE}")
        else:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2)
            print(f"JSON generated: {args.output}")
    else:
        print(json.dumps(result, indent=2))
