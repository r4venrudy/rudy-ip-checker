import unittest

from rudy_runtime.formatting import build_report, canonical_ip, clean_banner, split_message, summarize_abuseipdb, summarize_rdap, summarize_shodan, summarize_virustotal


class FormattingTests(unittest.TestCase):
    def test_canonical_ip(self):
        self.assertEqual(canonical_ip(" 8.8.8.8 "), "8.8.8.8")
        self.assertEqual(canonical_ip("2001:DB8::0001"), "2001:db8::1")
        self.assertEqual(canonical_ip("::ffff:8.8.8.8"),"8.8.8.8")
        self.assertIsNone(canonical_ip("8.8.8"))
        self.assertIsNone(canonical_ip("999.1.1.1"))
        self.assertIsNone(canonical_ip("example.com"))
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

    def test_virustotal_engines_and_date(self):
        vt = {"data": {"attributes": {"last_analysis_stats": {"malicious": 2},
                                      "last_analysis_results": {"Fortinet": {"category": "malicious"},
                                                                "BitDefender": {"category": "malicious"},
                                                                "Avira": {"category": "harmless"}},
                                      "last_analysis_date": 1760400000}}}
        out = summarize_virustotal(vt)
        self.assertIn("Flagged by: BitDefender, Fortinet", out)
        self.assertIn("Last analysed: 2025-10-14", out)

    def test_summarize_virustotal(self):
        vt = {"data": {"attributes": {"last_analysis_stats": {"malicious": 2, "harmless": 70},
                                      "as_owner": "Example AS", "country": "TR", "whois": "x" * 9000}}}
        out = summarize_virustotal(vt)
        self.assertEqual(out[0], "VirusTotal: 2 malicious, 0 suspicious, 70 harmless")
        self.assertIn("AS owner: Example AS", out)

    def test_virustotal_owner_and_abuse_contact_are_escaped(self):
        out=summarize_virustotal({"data":{"attributes":{"last_analysis_stats":{},"as_owner":"*Evil_Net*"}}})
        self.assertIn("AS owner: \\*Evil\\_Net\\*", out)
        abuse={"roles":["abuse"],"vcardArray":["vcard",[["email",{},"text","abuse_team@example.net"]]]}
        self.assertIn("Abuse contact: abuse\\_team@example.net", summarize_rdap({"entities":[abuse]}))
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


class BuildReportTests(unittest.TestCase):
    def test_sections_in_fixed_order_with_failures_in_place(self):
        results = {"Tor": {"1.2.3.4"}, "Shodan": None, "WHOIS": RDAP_SAMPLE}
        report = build_report("1.2.3.4", results, {"VirusTotal"})
        self.assertEqual(report.split("\n\n")[0], "**Shodan**\nNo data for this address")
        self.assertIn("**Tor**\nExit node: Yes", report)
        self.assertTrue(report.endswith("**VirusTotal**\nLookup failed"))
        self.assertNotIn("AbuseIPDB", report)
        self.assertLess(report.index("**WHOIS**"), report.index("**VirusTotal**"))

    def test_ipv6_tor_note(self):
        self.assertIn("only has IPv4", build_report("2001:db8::1", {"Tor": set()}, set()))


class MarkdownEscapeTests(unittest.TestCase):
    def test_external_text_cannot_format_the_reply(self):
        lines=summarize_shodan({"org":"**Evil** Corp","hostnames":["a_b_c.example"],"data":[{"port":80,"data":"Server: `x` ~~y~~"}]})
        self.assertEqual(lines[0],"Organization: \\*\\*Evil\\*\\* Corp")
        self.assertEqual(lines[1],"Hostnames: a\\_b\\_c.example")
        self.assertEqual(lines[2],"Port 80/tcp - Server: \\`x\\` \\~\\~y\\~\\~")
        link=summarize_shodan({"data":[{"port":80,"data":"[Login](https://example.com)"}]})
        self.assertEqual(link[0],"Port 80/tcp - \\[Login\\](https://example.com)")


class HostnameTests(unittest.TestCase):
    def test_hostnames_are_cleaned_and_validated(self):
        from rudy_runtime.formatting import hostname_from
        self.assertEqual(hostname_from(" https://Example.com:8443/path "),"example.com")
        self.assertEqual(hostname_from("mail.example.com.tr."),"mail.example.com.tr")
        for bad in ("", "localhost", "8.8.8.8", "exa mple.com", "-x.example.com"):
            self.assertIsNone(hostname_from(bad),bad)


class VirusTotalNoDataTests(unittest.TestCase):
    def test_unknown_address_says_no_data(self):
        report=build_report("203.0.113.9",{"VirusTotal":None},set())
        self.assertEqual(report,"**VirusTotal**\nNo data for this address")


class ShodanTagsTests(unittest.TestCase):
    def test_tags_and_last_scan(self):
        lines=summarize_shodan({"tags":["vpn","self-signed"],"last_update":"2026-10-01T08:15:22.123456"})
        self.assertEqual(lines,["Tags: vpn, self-signed","Last scanned by Shodan: 2026-10-01"])


class AbuseIpdbExtraTests(unittest.TestCase):
    def test_domain_and_whitelist(self):
        lines=summarize_abuseipdb({"data":{"abuseConfidenceScore":0,"totalReports":3,"domain":"google.com","isWhitelisted":True}})
        self.assertEqual(lines[-2:],["Domain: google.com","Whitelisted by AbuseIPDB"])


class RdapEventTests(unittest.TestCase):
    def test_registration_and_change_dates(self):
        lines=summarize_rdap({"events":[{"eventAction":"registration","eventDate":"2014-03-14T10:00:00-04:00"},
                                        {"eventAction":"last changed","eventDate":"2024-01-02T00:00:00Z"}]})
        self.assertEqual(lines,["Registered: 2014-03-14","Last changed: 2024-01-02"])


class Ipv6TorFromAbuseIpdbTests(unittest.TestCase):
    def test_abuseipdb_answers_for_ipv6(self):
        results={"Tor":set(),"AbuseIPDB":{"data":{"abuseConfidenceScore":100,"isTor":True}}}
        self.assertIn("**Tor**\nExit node: Yes (from AbuseIPDB)",build_report("2001:db8::1",results,set()))


class GreyNoiseTests(unittest.TestCase):
    def test_summaries(self):
        from rudy_runtime.formatting import summarize_greynoise
        self.assertEqual(summarize_greynoise({"riot":True,"name":"Google Public DNS"}),["Known benign service: Google Public DNS"])
        self.assertEqual(summarize_greynoise({"noise":True,"classification":"malicious","name":"unknown","last_seen":"2026-10-14"}),
                         ["Seen scanning the internet: malicious","Last seen: 2026-10-14"])
        self.assertEqual(summarize_greynoise({"noise":False,"riot":False}),["Not seen scanning the internet"])
        self.assertIn("**GreyNoise**",build_report("203.0.113.5",{"GreyNoise":{"noise":False,"riot":False}},set()))
