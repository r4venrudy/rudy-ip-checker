import unittest

from rudy_runtime.formatting import canonical_ip, clean_banner, split_message, summarize_virustotal, validate_ip


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
