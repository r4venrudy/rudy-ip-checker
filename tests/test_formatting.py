import unittest

from rudy_runtime.formatting import canonical_ip, clean_banner, split_message, summarize_abuseipdb, summarize_rdap, summarize_shodan, summarize_virustotal, validate_ip


class FormattingTests(unittest.TestCase):
    def test_validate_ip(self):
        self.assertTrue(validate_ip("8.8.8.8"))
        self.assertTrue(validate_ip("2001:4860:4860::8888"))
        self.assertFalse(validate_ip("999.1.1.1"))
        self.assertFalse(validate_ip("example.com"))

    def test_canonical_ip(self):
        self.assertEqual(canonical_ip(" 8.8.8.8 "), "8.8.8.8")
        self.assertEqual(canonical_ip("2001:DB8::0001"), "2001:db8::1")
        self.assertIsNone(canonical_ip("8.8.8"))
        self.assertIsNone(canonical_ip(None))

    def test_clean_banner_strips_html_and_newlines(self):
        self.assertEqual(clean_banner("SSH-2.0\r\n<b>hi</b>\tthere"), "SSH-2.0 hi there")
        self.assertTrue(clean_banner("x" * 150).endswith("..."))

    def test_split_message_respects_limit(self):
        text = "a" * 4500 + "\n" + "\n".join("line %d" % i for i in range(500))
        chunks = split_message(text)
        self.assertTrue(all(len(c) <= 2000 for c in chunks))
        self.assertEqual("".join(chunks).count("a"), 4500)

    def test_split_message_empty(self):
        self.assertEqual(split_message(""), ["No data found."])

    def test_summarize_virustotal(self):
        vt = {"data": {"attributes": {"last_analysis_stats": {"malicious": 2, "harmless": 70},
                                      "as_owner": "Example AS", "country": "TR", "whois": "x" * 9000}}}
        out = summarize_virustotal(vt)
        self.assertEqual(out[0], "VirusTotal: 2 malicious, 0 suspicious, 70 harmless")
        self.assertIn("AS owner: Example AS", out)
        self.assertFalse(any("whois" in line.lower() for line in out))
        self.assertEqual(summarize_virustotal({}), ["VirusTotal: no data"])


if __name__ == "__main__":
    unittest.main()


class ShodanSummaryTests(unittest.TestCase):
    def test_owner_cves_and_sorted_ports(self):
        host = {
            "org": "Example Org", "os": None, "hostnames": ["a.example", "b.example"],
            "vulns": ["CVE-2021-%04d" % i for i in range(7)],
            "data": [{"port": 443, "data": "HTTP/1.1 200 OK\r\n"}, {"port": 53, "transport": "udp", "data": ""}],
        }
        self.assertEqual(summarize_shodan(host), [
            "Organization: Example Org",
            "Hostnames: a.example, b.example",
            "Known CVEs: CVE-2021-0000, CVE-2021-0001, CVE-2021-0002, CVE-2021-0003, CVE-2021-0004 (+2 more)",
            "Port 53/udp - ",
            "Port 443/tcp - HTTP/1.1 200 OK",
        ])

    def test_empty_report(self):
        self.assertEqual(summarize_shodan({}), [])


RDAP_SAMPLE = {
    "handle": "NET-8-8-8-0-2", "name": "GOGL", "startAddress": "8.8.8.0", "endAddress": "8.8.8.255", "country": "US",
    "entities": [{
        "roles": ["registrant"],
        "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Google LLC"]]],
        "entities": [{
            "roles": ["abuse"],
            "vcardArray": ["vcard", [["fn", {}, "text", "Abuse"], ["email", {}, "text", "network-abuse@google.com"]]],
        }],
    }],
}


class RdapSummaryTests(unittest.TestCase):
    def test_full_network_object(self):
        self.assertEqual(summarize_rdap(RDAP_SAMPLE), [
            "Network: GOGL (NET-8-8-8-0-2)",
            "Range: 8.8.8.0 - 8.8.8.255",
            "Registered country: US",
            "Owner: Google LLC",
            "Abuse contact: network-abuse@google.com",
        ])

    def test_sparse_object(self):
        self.assertEqual(summarize_rdap({"entities": [{"roles": ["abuse"]}]}), [])


class AbuseIpdbSummaryTests(unittest.TestCase):
    def test_report(self):
        report = {"data": {"abuseConfidenceScore": 87, "totalReports": 42, "lastReportedAt": "2026-10-12T08:00:00+00:00",
                           "usageType": "Data Center/Web Hosting/Transit"}}
        self.assertEqual(summarize_abuseipdb(report), [
            "AbuseIPDB: 87% abuse confidence, 42 reports in 90 days",
            "Last reported: 2026-10-12",
            "Usage type: Data Center/Web Hosting/Transit",
        ])

    def test_empty(self):
        self.assertEqual(summarize_abuseipdb({}), ["AbuseIPDB: no data"])
