import unittest
import os

import istio_advisory_parser
import utils


def read_test_resource(file: list) -> str:
    file_path = os.path.join('.', 'test_resources', file)
    with open(file_path, "r") as f:
        lines = f.readlines()
    lines = [x.replace('\n', '').strip() for x in lines]
    return "".join(lines)


class MyTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.istio_advisories_html = read_test_resource('istio_advisories_page.html')
        self.istio_advisory_html = read_test_resource('istio_advisory_page.html')
        self.istio_advisory2_html = read_test_resource('istio_advisory_page2.html')
        self.istio_support_html = read_test_resource('istio_support_announcements.html')

    def test_advisory_page(self):
        cves = istio_advisory_parser.retrieve_cve_from_advisory_page(None, self.istio_advisory_html)
        self.assertEqual(cves, ['CVE-2020-1764'])

    def test_advisory_page2(self):
        cves = istio_advisory_parser.retrieve_cve_from_advisory_page(None, self.istio_advisory2_html)
        self.assertEqual(cves, ['CVE-2020-8659', 'CVE-2020-8660', 'CVE-2020-8661', 'CVE-2020-8664'])

    def test_advisories_parser(self):
        advisory_links = istio_advisory_parser.retrieve_istio_sec_advisories(self.istio_advisories_html)
        self.assertEqual(17, len(advisory_links))
        applicable_adv = utils.filter_not_applicable_advisories("1.4.5", advisory_links)
        self.assertEqual(5, len(applicable_adv))
        adv1_link = applicable_adv[0]
        self.assertEqual(adv1_link, 'https://istio.io/latest/news/security/istio-security-2020-008/')
        adv2_link = applicable_adv[1]
        self.assertEqual(adv2_link, 'https://istio.io/latest/news/security/istio-security-2020-006/')
        adv3_link = applicable_adv[2]
        self.assertEqual(adv3_link, 'https://istio.io/latest/news/security/istio-security-2020-005/')
        adv4_link = applicable_adv[3]
        self.assertEqual(adv4_link, 'https://istio.io/latest/news/security/istio-security-2020-004/')
        adv5_link = applicable_adv[4]
        self.assertEqual(adv5_link, 'https://istio.io/latest/news/security/istio-security-2020-003/')

    def test_advisories_parser2(self):
        advisory_links = istio_advisory_parser.retrieve_istio_sec_advisories(self.istio_advisories_html)
        self.assertEqual(17, len(advisory_links))
        applicable_adv = utils.filter_not_applicable_advisories("1.4.7", advisory_links)
        self.assertEqual(3, len(applicable_adv))
        adv1_link = applicable_adv[0]
        self.assertEqual(adv1_link, 'https://istio.io/latest/news/security/istio-security-2020-008/')
        adv2_link = applicable_adv[1]
        self.assertEqual(adv2_link, 'https://istio.io/latest/news/security/istio-security-2020-006/')
        adv3_link = applicable_adv[2]
        self.assertEqual(adv3_link, 'https://istio.io/latest/news/security/istio-security-2020-005/')

    def test_advisories_parser_empty(self):
        advisory_links = istio_advisory_parser.retrieve_istio_sec_advisories(self.istio_advisories_html)
        self.assertEqual(17, len(advisory_links))
        applicable_adv = utils.filter_not_applicable_advisories("1.5.10", advisory_links)
        self.assertEqual(0, len(applicable_adv))

    def test_unsupported_versions(self):
        eol_versions = istio_advisory_parser.retrieve_istio_unsupported_versions(html=self.istio_support_html)
        self.assertEqual(6, len(eol_versions))
        self.assertTrue('1.0' in eol_versions)


if __name__ == '__main__':
    unittest.main()
