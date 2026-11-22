"""Scanner provenance is explicit report metadata, not deduplication content."""

from copy import deepcopy
import unittest
from nmap2json import nmap_xml_to_json
from nmap2json.smarthash import headers_smart_hash


class EngineMetadataTest(unittest.TestCase):
    def test_scanner_field_and_legacy_nmap_default(self):
        for scanner, expected in (
            ("masscan", "masscan"),
            ("nmap", "nmap"),
            (None, "nmap"),
        ):
            attribute = f' scanner="{scanner}"' if scanner else ""
            xml = f'<nmaprun{attribute}><host><address addr="192.0.2.1"/><ports><port protocol="tcp" portid="22"><state state="open"/></port></ports></host></nmaprun>'
            report = nmap_xml_to_json(xml)[0]
            if expected == "masscan":
                self.assertEqual(report["engine"], "masscan")
            else:
                self.assertNotIn("engine", report)
            legacy = deepcopy(report)
            legacy.pop("engine", None)
            options = dict(exclude_keys=["starttime", "endtime", "hsh256"])
            self.assertEqual(report["hsh256"], headers_smart_hash(legacy, **options))
            report["engine"] = "masscan" if expected == "nmap" else "nmap"
            self.assertEqual(headers_smart_hash(report, **options), report["hsh256"])

    def test_nested_nse_engine_field_remains_content(self):
        report = {
            "addr": "192.0.2.1",
            "engine": "nmap",
            "ports": [{"scripts": [{"id": "example", "engine": "a"}]}],
        }
        changed = deepcopy(report)
        changed["ports"][0]["scripts"][0]["engine"] = "b"
        self.assertNotEqual(headers_smart_hash(report), headers_smart_hash(changed))
