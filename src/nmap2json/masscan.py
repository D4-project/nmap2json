"""Collect Masscan host events from one saved report before Nmap normalization."""

from collections import defaultdict
from ipaddress import ip_address
from xml.etree import ElementTree as ET


def observation_time(element, field):
    """Return the timestamp attribute as an integer, or -1 if absent."""
    value = element.get(field)
    return int(value) if value is not None else -1


def merge_port(events):
    """Merge status and unique service detections for one Masscan port."""
    # A native status event carries the original state/reason. A banner event
    # repeats the open state with a generic reason. Break ties deterministically.
    def status_order(event):
        """Prefer native status events, then order by time and attributes."""
        time, port = event
        state = port.find("state")
        return (
            port.find("service") is None,
            time,
            tuple(sorted(state.attrib.items())),
            tuple(sorted(port.attrib.items())),
        )

    _, primary = max(events, key=status_order)
    port = ET.Element("port", primary.attrib.copy())
    port.append(primary.find("state"))
    detections = set()
    for _, event in events:
        for service in event.findall("service"):
            name = service.get("name")
            if name and service.get("method") != "table":
                detections.add((name, service.get("banner")))
    for name, banner in sorted(
        detections, key=lambda d: (d[0], d[1] is not None, d[1] or "")
    ):
        script = ET.SubElement(port, "script", id="masscan-detection", service=name)
        if banner is not None:
            script.set("output", banner)
    return port


def merged_hosts(root):
    """Yield one host per IP with one port per transport/number pair."""
    by_address = defaultdict(list)
    for host in root.findall("host"):
        address = host.find("address")
        if address is None or not address.get("addr"):
            raise ValueError("Masscan host is missing its IP address")
        by_address[str(ip_address(address.get("addr")))].append(host)

    for address, events in sorted(by_address.items()):
        host = ET.Element("host")
        for field, select in (("starttime", min), ("endtime", max)):
            times = [e.get(field) for e in events if e.get(field) is not None]
            if times:
                host.set(field, select(times, key=int))
        ET.SubElement(host, "address", addr=address)
        statuses = [
            (observation_time(e, "endtime"), tuple(sorted(s.attrib.items())))
            for e in events
            for s in e.findall("status")
        ]
        if statuses:
            ET.SubElement(host, "status", dict(max(statuses)[1]))
        names = {
            tuple(sorted(n.attrib.items()))
            for e in events
            for n in e.findall("hostnames/hostname")
        }
        if names:
            hostnames = ET.SubElement(host, "hostnames")
            for name in sorted(names):
                ET.SubElement(hostnames, "hostname", dict(name))
        by_port = defaultdict(list)
        for event in events:
            for port in event.findall("ports/port"):
                if (
                    not port.get("protocol")
                    or not port.get("portid")
                    or port.find("state") is None
                ):
                    raise ValueError("Masscan port lacks transport, number or state")
                by_port[port.get("protocol"), port.get("portid")].append(
                    (observation_time(event, "endtime"), port)
                )
        ports = ET.SubElement(host, "ports")
        for observations in by_port.values():
            ports.append(merge_port(observations))
        yield host
