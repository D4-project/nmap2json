import unittest

from nmap2json.smarthash import (
    HEADERS_TOCLEAN,
    anonymise_cookies,
    anonymise_headers,
    no_time,
)


class SmartHashTests(unittest.TestCase):
    def test_issue_5_masks_moving_http_header_parts(self):
        output = "\n".join(
            [
                "Date: Wed, 01 Oct 2025 06:28:59 GMT",
                "CF-Ray: 9879e72e7d656f6f-CDG",
                'ETag: "e3b0b55949321bee09e380eb849f90fd"',
                "Set-Cookie: comexio_session_id=ucbloft6ln6d271udthjugg3g2; "
                "expires=Fri, 10-Oct-2025 14:29:07 GMT; path=/",
            ]
        )

        cleaned = anonymise_headers(
            anonymise_cookies(no_time(output)),
            HEADERS_TOCLEAN,
        )

        self.assertNotIn("Wed, 01 Oct 2025 06:28:59 GMT", cleaned)
        self.assertNotIn("9879e72e7d656f6f-CDG", cleaned)
        self.assertNotIn("e3b0b55949321bee09e380eb849f90fd", cleaned)
        self.assertNotIn("ucbloft6ln6d271udthjugg3g2", cleaned)
        self.assertIn("CF-Ray: XXXXXXXXXXXXXXXXXXXX", cleaned)
        self.assertIn("ETag: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", cleaned)
        self.assertIn("comexio_session_id=[REDACTED]", cleaned)

    def test_special_header_does_not_stop_later_header_cleanup(self):
        output = "\n".join(
            [
                'content-security-policy-report-only: script-src nonce-"abc123"',
                "ETag: changing-value",
            ]
        )

        cleaned = anonymise_headers(output, HEADERS_TOCLEAN)

        self.assertNotIn("abc123", cleaned)
        self.assertNotIn("changing-value", cleaned)
        self.assertIn("ETag: XXXXXXXXXXXXXX", cleaned)

    def test_issue_7_masks_github_and_fastly_request_headers(self):
        output = "\n".join(
            [
                "X-GitHub-Request-Id: C561:71A05:1027E40:10585CC:69218E59",
                "X-Fastly-Request-ID: f1271990bf630f317be33e46e46b83674e173c56",
            ]
        )

        cleaned = anonymise_headers(output, HEADERS_TOCLEAN)

        self.assertNotIn("C561:71A05:1027E40:10585CC:69218E59", cleaned)
        self.assertNotIn("f1271990bf630f317be33e46e46b83674e173c56", cleaned)
        self.assertIn(
            "X-GitHub-Request-Id: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", cleaned
        )
        self.assertIn(
            "X-Fastly-Request-ID: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", cleaned
        )


if __name__ == "__main__":
    unittest.main()
