"""Verify TTL stability for native Nmap and Masscan reports."""

import unittest

from nmap2json import nmap_xml_to_json


class ResponseTtlTest(unittest.TestCase):
    def test_nonzero_ttl_does_not_change_host_or_port_hashes(self):
        for scanner in ("nmap", "masscan"):
            with self.subTest(scanner=scanner):
                banner = (
                    '<service name="ssh" banner="SSH-2.0-OpenSSH_9.6"/>'
                    if scanner == "masscan"
                    else '<script id="banner" output="SSH-2.0-OpenSSH_9.6"/>'
                )
                xml = f'''<nmaprun scanner="{scanner}">
  <host>
    <status state="up" reason="syn-ack" reason_ttl="52"/>
    <address addr="192.0.2.1"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" reason_ttl="53"/>
        {banner}
      </port>
    </ports>
  </host>
</nmaprun>'''
                first = nmap_xml_to_json(xml)[0]
                different_ttl = xml.replace(
                    'reason_ttl="52"', 'reason_ttl="102"'
                ).replace('reason_ttl="53"', 'reason_ttl="103"')
                second = nmap_xml_to_json(different_ttl)[0]
                missing_ttl = xml.replace(' reason_ttl="52"', "").replace(
                    ' reason_ttl="53"', ""
                )
                third = nmap_xml_to_json(missing_ttl)[0]

                self.assertEqual(first["status"]["reason_ttl"], "52")
                self.assertEqual(first["ports"][0]["state"]["reason_ttl"], "53")
                self.assertEqual(second["status"]["reason_ttl"], "102")
                self.assertEqual(second["ports"][0]["state"]["reason_ttl"], "103")
                for report in (second, third):
                    self.assertEqual(first["hsh256"], report["hsh256"])
                    self.assertEqual(
                        first["ports"][0]["hsh256"], report["ports"][0]["hsh256"]
                    )

                zero_ttl = xml.replace('reason_ttl="52"', 'reason_ttl="0"').replace(
                    'reason_ttl="53"', 'reason_ttl="0"'
                )
                zero = nmap_xml_to_json(zero_ttl)[0]
                self.assertNotEqual(first["hsh256"], zero["hsh256"])
                self.assertNotEqual(
                    first["ports"][0]["hsh256"], zero["ports"][0]["hsh256"]
                )

                changed_banner = xml.replace("OpenSSH_9.6", "OpenSSH_9.7")
                changed = nmap_xml_to_json(changed_banner)[0]
                self.assertNotEqual(first["hsh256"], changed["hsh256"])
                self.assertNotEqual(
                    first["ports"][0]["hsh256"], changed["ports"][0]["hsh256"]
                )
