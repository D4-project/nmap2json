"""Full banners survive parsing; optional previews respect escaped bytes."""

from copy import deepcopy
import unittest
from nmap2json import nmap_xml_to_json
from nmap2json.banner import normalize_banner
from nmap2json.smarthash import port_smart_hash, master_clean, SMART_HASH_SCRIPTS


class BannerPolicyTest(unittest.TestCase):
    def port(self, output, script):
        return {
            "portid": "80",
            "protocol": "tcp",
            "scripts": [{"id": script, "output": output}],
        }

    def test_shared_cut_and_escaped_byte_boundaries(self):
        raw = "a" * 59 + r"\x0a" + "more data"
        for script in ("banner", "masscan-detection"):
            result = normalize_banner(raw, script, limit=64)
            self.assertEqual(result, "a" * 59 + "...")
            self.assertLessEqual(len(result), 64)
        self.assertEqual(
            normalize_banner("abc" * 30, "banner"),
            normalize_banner("abc" * 30, "masscan-detection"),
        )
        self.assertEqual(
            normalize_banner(r"abc\x0d\x0a", "masscan-detection"), r"abc\x0D\x0A"
        )
        self.assertEqual(normalize_banner("a" * 64, "banner"), "a" * 64)

    def test_parser_preserves_full_output_from_both_scanners(self):
        for scanner in ("nmap", "masscan"):
            if scanner == "nmap":
                detail = '<script id="banner" output="' + "a" * 90 + '"/>'
            else:
                detail = '<service name="http" banner="' + "a" * 90 + '"/>'
            xml = f'<nmaprun scanner="{scanner}"><host><address addr="192.0.2.1"/><ports><port portid="80" protocol="tcp"><state state="open"/>{detail}</port></ports></host></nmaprun>'
            output = nmap_xml_to_json(xml)[0]["ports"][0]["scripts"][0]["output"]
            self.assertEqual(output, "a" * 90)

    def test_no_implicit_size_limit(self):
        for script in ("banner", "masscan-detection"):
            output = "a" * 100_000 + r"\x0d\x0a"
            self.assertEqual(
                normalize_banner(output, script), "a" * 100_000 + r"\x0D\x0A"
            )

    def test_protocol_dates_masked_even_when_cut(self):
        for script in ("banner", "masscan-detection"):
            for separator in ("\r\n", r"\x0d\x0a"):
                for padding in ("", "a" * 20 + separator):
                    prefix = "HTTP/1.1 200 OK" + separator + padding + "Date: "
                    a = self.port(
                        normalize_banner(
                            prefix + "Sat, 21 Nov 2026 12:22:23 GMT", script
                        ),
                        script,
                    )
                    b = self.port(
                        normalize_banner(
                            prefix + "Sun, 22 Nov 2026 13:42:45 GMT", script
                        ),
                        script,
                    )
                    before = deepcopy(a)
                    self.assertEqual(port_smart_hash(a), port_smart_hash(b))
                    self.assertEqual(a, before)
        a = self.port(
            "220-Local time is now 13:22. Server port: 21.", "masscan-detection"
        )
        b = self.port(
            "220-Local time is now 14:55. Server port: 21.", "masscan-detection"
        )
        self.assertEqual(port_smart_hash(a), port_smart_hash(b))

    def test_meaningful_dates_are_retained(self):
        for prefix in ("Last-Modified: ", "Build date: "):
            a = self.port(prefix + "Sat, 21 Nov 2026 12:22:23 GMT", "masscan-detection")
            b = self.port(prefix + "Sat, 21 Nov 2026 12:22:24 GMT", "masscan-detection")
            self.assertNotEqual(port_smart_hash(a), port_smart_hash(b))
