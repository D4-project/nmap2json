import io
import unittest
from xml.etree.ElementTree import ParseError

from nmap2json import nmap_file_to_json, nmap_xml_to_json


class MasscanReportTests(unittest.TestCase):
    def event(
        self,
        port,
        ts,
        details="",
        address="192.0.2.1",
        protocol="tcp",
        state="open",
        reason="syn-ack",
    ):
        return (
            f'<host endtime="{ts}"><address addr="{address}"/><ports>'
            f'<port portid="{port}" protocol="{protocol}"><state state="{state}" reason="{reason}"/>'
            f"{details}</port></ports></host>"
        )

    def report(self, *events, scanner="masscan"):
        return f'<nmaprun scanner="{scanner}">' + "".join(events) + "</nmaprun>"

    def test_status_only_matches_nmap_with_and_without_filters(self):
        for state in ("open", "closed"):
            event = self.event(5060, 100, state=state)
            for filtered in (True, False):
                with self.subTest(state=state, filtered=filtered):
                    self.assertEqual(
                        nmap_xml_to_json(self.report(event), filtered, filtered),
                        nmap_xml_to_json(
                            self.report(event, scanner="nmap"), filtered, filtered
                        ),
                    )
        self.assertEqual(nmap_xml_to_json(self.report(), True, True), [])

    def test_permutations_keep_one_port_and_match_equivalent_nse(self):
        opened = self.event(25, 100)
        smtp = self.event(
            25, 105, '<service name="smtp" banner="220 ESMTP"/>', reason="response"
        )
        tls = self.event(
            25, 112, '<service name="ssl" banner=" ALERT(0x0246) "/>', reason="response"
        )
        equivalent = self.event(
            25,
            112,
            '<script id="masscan-detection" service="ssl" output=" ALERT(0x0246) "/>'
            '<script id="masscan-detection" service="smtp" output="220 ESMTP"/>',
        )
        expected = nmap_xml_to_json(self.report(equivalent, scanner="nmap"))
        for events in ((opened, smtp, tls), (tls, smtp, opened, smtp)):
            self.assertEqual(nmap_xml_to_json(self.report(*events)), expected)
        self.assertEqual(expected[0]["endtime"], "112")
        self.assertEqual(
            [s["service"] for s in expected[0]["ports"][0]["scripts"]], ["smtp", "ssl"]
        )

    def test_multiple_ips_transports_and_absent_banner(self):
        document = self.report(
            self.event(53, 10),
            self.event(53, 20, protocol="udp"),
            self.event(2222, 12, '<service name="ssh"/>', address="2001:db8::1"),
            self.event(
                22, 13, '<service name="ssh" method="table"/>', address="2001:db8::1"
            ),
        )
        first, second = nmap_file_to_json(io.BytesIO(document.encode()))
        self.assertEqual(first["endtime"], "20")
        self.assertEqual({p["protocol"] for p in first["ports"]}, {"tcp", "udp"})
        ports = {p["portid"]: p for p in second["ports"]}
        self.assertNotIn("scripts", ports["22"])
        self.assertNotIn("output", ports["2222"]["scripts"][0])

    def test_invalid_inputs_do_not_become_success(self):
        for document in ("", '<nmaprun scanner="masscan">'):
            with self.assertRaises(ParseError):
                nmap_xml_to_json(document)
        with self.assertRaises(ValueError):
            nmap_xml_to_json(
                '<nmaprun scanner="masscan">' + " " * (1024 * 1024) + "</nmaprun>"
            )
        with self.assertRaises(ValueError):
            nmap_xml_to_json('<!DOCTYPE nmaprun [<!ENTITY example "value">]><nmaprun/>')
        self.assertEqual(nmap_xml_to_json("<!DOCTYPE nmaprun><nmaprun/>"), [])

    def test_same_hostname_preserved_separately_for_each_recorded_address(self):
        name = '<hostnames><hostname name="example.test" type="user"/></hostnames>'
        addresses = ["192.0.2.1", "192.0.2.2", "2001:db8::1"]
        events = [
            self.event(22, 100, address=address).replace("<ports>", name + "<ports>")
            for address in addresses
        ]
        hosts = nmap_xml_to_json(self.report(*events, events[0]))
        self.assertEqual([host["addr"] for host in hosts], addresses)
        for host in hosts:
            self.assertEqual(host["hostnames"], [{"name": "example.test", "type": "user"}])

    def test_large_historical_nmap_report_keeps_its_hash(self):
        event = self.event(22, 100)
        report = self.report(event, scanner="nmap")
        padded = report.replace("<host ", " " * (1024 * 1024) + "<host ")
        self.assertEqual(nmap_xml_to_json(report), nmap_xml_to_json(padded))
