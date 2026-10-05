"""Protocol clocks must not prevent port/report deduplication."""

import copy
import unittest

from nmap2json.smarthash import (
    headers_smart_hash,
    master_clean,
    no_time,
    port_smart_hash,
    SMART_HASH_SCRIPTS,
)


class VolatileDateTests(unittest.TestCase):
    """Exercise both hash entry points without modifying stored reports."""

    @staticmethod
    def port(output, script="banner"):
        """Build a minimal port result."""
        return {
            "portid": "80",
            "protocol": "tcp",
            "scripts": [{"id": script, "output": output}],
        }

    def test_protocol_dates_share_hashes(self):
        """Support casing, variable day width, timezone and Nmap escaping."""
        pairs = [
            (
                "220 localhost ESMTP Sendmail 8.14.7; mon, 2 mar 2026 10:13:52 -0500",
                "220 localhost ESMTP Sendmail 8.14.7; Tue, 12 May 2026 10:15:46 GMT",
            ),
        ]
        for separator in ("\r\n", "\n", r"\0d\0a", r"\x0d\x0a", r"\r\n"):
            for protocol in ("HTTP/1.1", "RTSP/1.0"):
                prefix = protocol + " 400 Bad Request" + separator + "Date: "
                pairs.append(
                    (
                        prefix + "mon, 04 may 2026 20:40:27 gmt",
                        prefix + "mon, nov 13 2023 15:42:29 gmt",
                    )
                )
        for left, right in pairs:
            with self.subTest(left=left):
                first, second = self.port(left), self.port(right)
                self.assertEqual(port_smart_hash(first), port_smart_hash(second))
                self.assertEqual(
                    headers_smart_hash({"ports": [first]}),
                    headers_smart_hash({"ports": [second]}),
                )

    def test_headers_and_cookie_expiry(self):
        """HTTP helper scripts retain existing cookie normalization."""
        for script in SMART_HASH_SCRIPTS:
            first = self.port(
                "Date: Mon, 2 Mar 2026 10:13:52 -0500\n"
                "Set-Cookie: id=abc; expires=Mon, 2-Mar-2026 11:00:00 GMT",
                script,
            )
            second = self.port(
                "Date: Tue, 12 May 2026 10:15:46 GMT\n"
                "Set-Cookie: id=longer; expires=Tue, 12-May-2026 11:00:00 GMT",
                script,
            )
            self.assertEqual(port_smart_hash(first), port_smart_hash(second))

    def test_meaningful_changes_still_change_hash(self):
        """Do not merge distinct versions, certificates or Last-Modified."""
        for script, output in (
            ("banner", "220 server ESMTP v1; Mon, 2 Mar 2026 10:13:52 GMT"),
            ("ssl-cert", "Not valid before: Mon, 2 Mar 2026 10:13:52 GMT"),
            ("http-headers", "Last-Modified: Mon, 2 Mar 2026 10:13:52 GMT"),
            ("banner", "Build date: Mon, 2 Mar 2026 10:13:52 GMT"),
        ):
            changed = (
                output.replace("v1", "v2")
                if "v1" in output
                else output.replace("2026", "2025")
            )
            with self.subTest(script=script, output=output):
                self.assertNotEqual(
                    port_smart_hash(self.port(output, script)),
                    port_smart_hash(self.port(changed, script)),
                )

    def test_original_not_mutated(self):
        """Hashing and the public cleaner leave the source object intact."""
        port = self.port("Date: Mon, 2 Mar 2026 10:13:52 GMT", "http-headers")
        report = {"ports": [port]}
        original = copy.deepcopy(report)
        cleaned = master_clean(report, SMART_HASH_SCRIPTS)
        self.assertIn("[DATE]", cleaned["ports"][0]["scripts"][0]["output"])
        port_smart_hash(port)
        headers_smart_hash(report)
        self.assertEqual(report, original)

    def test_missing_output(self):
        """Optional NSE output must not crash hashing."""
        for output in (None, ""):
            self.assertEqual(len(port_smart_hash(self.port(output))), 64)

    def test_fixed_marker(self):
        """Marker length must not depend on original date length."""
        self.assertEqual(no_time("Mon, 2 Mar 2026 10:13:52 -0500"), "[DATE]")
        self.assertEqual(no_time("Tue, 12 May 2026 10:15:46 GMT"), "[DATE]")


if __name__ == "__main__":
    unittest.main()
