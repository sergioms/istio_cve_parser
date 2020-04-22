import unittest
import client


class MyTestCase(unittest.TestCase):
    def setUp(self):
        self.all_vulns = ['1.0.1 to 1.0.8', '1.5', '1.0 to 1.0.8']

    def test_version_range1(self):
        self.assertTrue(client.is_in_version_range("1.5", "1.5"))

    def test_version_range2(self):
        self.assertTrue(client.is_in_version_range("1.5", "1.5.0"))

    def test_version_range3(self):
        self.assertTrue(client.is_in_version_range("1.5.0", "1.5"))

    def test_version_range4(self):
        self.assertTrue(client.is_in_version_range("1.5.0", "1.5"))

    def test_version_range5(self):
        self.assertFalse(client.is_in_version_range("2.5", "1.5"))

    def test_version_range6(self):
        self.assertFalse(client.is_in_version_range("1.5", "2.5.0"))

    def test_version_range7(self):
        self.assertFalse(client.is_in_version_range("1.5.3", "1.5"))

    def test_version_range9(self):
        self.assertFalse(client.is_in_version_range("1.5.0", "3.5"))

    def test_version_range9(self):
        self.assertTrue(client.is_in_version_range("1.5", "1.0 to 1.5"))

    def test_version_range9(self):
        self.assertTrue(client.is_in_version_range("1.5", "1.0 to 1.5.0"))

    def test_version_range10(self):
        self.assertTrue(client.is_in_version_range("1.5.0", "1.0 to 1.5.0"))

    def test_version_range10(self):
        self.assertTrue(client.is_in_version_range("1.5.0", "1.0 to 1.5"))

    def test_version_range10(self):
        self.assertFalse(client.is_in_version_range("1.5.0", "1.0 to 1.4"))

    def test_version_range11(self):
        self.assertFalse(client.is_in_version_range("1.5.0", "1.0 to 1.4"))

    def test_version_range12(self):
        self.assertFalse(client.is_in_version_range("1.5.0", "2.0 to 2.6.0"))

    def test_version_range12(self):
        self.assertFalse(client.is_in_version_range("2.5.0", "1.0 to 1.6.0"))

    def testnorm1(self):
        major, minor, build = client.norm_version('1.0.1')
        print(f'send 1.0.1 and got {major}_{minor}_{build}')
        self.assertEqual(major, 1)
        self.assertEqual(minor, 0)
        self.assertEqual(build, 1)

    def testnorm2(self):
        major, minor, build = client.norm_version('126.0.45')
        print(f'send 126.0.45 and got {major}_{minor}_{build}')
        self.assertEqual(major, 126)
        self.assertEqual(minor, 0)
        self.assertEqual(build, 45)

    def testnorm3(self):
        major, minor, build = client.norm_version('11.33')
        print(f'send 11.33 and got {major}_{minor}_{build}')
        self.assertEqual(major, 11)
        self.assertEqual(minor, 33)
        self.assertEqual(build, 0)

    def testnorm4(self):
        major, minor, build = client.norm_version('v.1.4')
        print(f'send v.1.4 and got {major}_{minor}_{build}')
        self.assertIsNone(major)
        self.assertIsNone(minor)
        self.assertIsNone(build)

    def testnorm5(self):
        major, minor, build = client.norm_version('v.1')
        print(f'send v.1 and got {major}_{minor}_{build}')
        self.assertIsNone(major)
        self.assertIsNone(minor)
        self.assertIsNone(build)

    def test1(self):
        vulns = client.filter_not_applicable_vulns('1.0', self.all_vulns)
        self.assertEqual(1, len(vulns))

    def test2(self):
        vulns = client.filter_not_applicable_vulns('1.0.0', self.all_vulns)
        self.assertEqual(1, len(vulns))

    def test3(self):
        vulns = client.filter_not_applicable_vulns('1.0.1', self.all_vulns)
        self.assertEqual(2, len(vulns))

    def test4(self):
        vulns = client.filter_not_applicable_vulns('1.0.9', self.all_vulns)
        self.assertEqual(2, len(vulns))

    def test5(self):
        vulns = client.filter_not_applicable_vulns('1.5', self.all_vulns)
        self.assertEqual(1, len(vulns))

    def test6(self):
        vulns = client.filter_not_applicable_vulns('1.5.1', self.all_vulns)
        self.assertEqual(0, len(vulns))


if __name__ == '__main__':
    unittest.main()
