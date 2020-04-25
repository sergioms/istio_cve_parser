import client

import unittest
import utils


class MyTestCase(unittest.TestCase):
    def setUp(self):
        self.all_advisories = [
            ('https://istio.io/adv1', ['1.0.1 to 1.0.8', '2.0 to 2.1.3', '3.0']),
            ('https://istio.io/adv2', ['1.0 to 1.0.8']),
            ('https://istio.io/adv3', ['3.0.4 to 3.0.8', '4.0'])
        ]

    def test_version_range1(self):
        self.assertTrue(utils.is_in_version_range("1.5", "1.5"))

    def test_version_range2(self):
        self.assertTrue(utils.is_in_version_range("1.5", "1.5.0"))

    def test_version_range3(self):
        self.assertTrue(utils.is_in_version_range("1.5.0", "1.5"))

    def test_version_range4(self):
        self.assertTrue(utils.is_in_version_range("1.5.0", "1.5"))

    def test_version_range5(self):
        self.assertFalse(utils.is_in_version_range("2.5", "1.5"))

    def test_version_range6(self):
        self.assertFalse(utils.is_in_version_range("1.5", "2.5.0"))

    def test_version_range7(self):
        self.assertFalse(utils.is_in_version_range("1.5.3", "1.5"))

    def test_version_range8(self):
        self.assertFalse(utils.is_in_version_range("1.5.0", "3.5"))

    def test_version_range9(self):
        self.assertTrue(utils.is_in_version_range("1.5", "1.0 to 1.5"))

    def test_version_range10(self):
        self.assertTrue(utils.is_in_version_range("1.5", "1.0 to 1.5.0"))

    def test_version_range11(self):
        self.assertTrue(utils.is_in_version_range("1.5.0", "1.0 to 1.5.0"))

    def test_version_range12(self):
        self.assertTrue(utils.is_in_version_range("1.5.0", "1.0 to 1.5"))

    def test_version_range13(self):
        self.assertFalse(utils.is_in_version_range("1.5.0", "1.0 to 1.4"))

    def test_version_range14(self):
        self.assertFalse(utils.is_in_version_range("1.5.0", "1.0 to 1.4"))

    def test_version_range15(self):
        self.assertFalse(utils.is_in_version_range("1.5.0", "2.0 to 2.6.0"))

    def test_version_range16(self):
        self.assertFalse(utils.is_in_version_range("2.5.0", "1.0 to 1.6.0"))

    def test_norm1(self):
        major, minor, build = utils.norm_version('1.0.1')
        self.assertEqual(major, 1)
        self.assertEqual(minor, 0)
        self.assertEqual(build, 1)

    def test_norm2(self):
        major, minor, build = utils.norm_version('126.0.45')
        self.assertEqual(major, 126)
        self.assertEqual(minor, 0)
        self.assertEqual(build, 45)

    def test_norm3(self):
        major, minor, build = utils.norm_version('11.33')
        self.assertEqual(major, 11)
        self.assertEqual(minor, 33)
        self.assertEqual(build, 0)

    def test_norm4(self):
        self.assertRaises(ValueError, utils.norm_version,'v.1.4')

    def test_norm5(self):
        self.assertRaises(ValueError, utils.norm_version,'v.1')

    def test1(self):
        advisories = utils.filter_not_applicable_advisories('1.0', self.all_advisories)
        self.assertEqual(1, len(advisories))
        self.assertEqual('https://istio.io/adv2', advisories[0])

    def test2(self):
        advisories = utils.filter_not_applicable_advisories('1.0.0', self.all_advisories)
        self.assertEqual(1, len(advisories))
        self.assertEqual('https://istio.io/adv2', advisories[0])

    def test3(self):
        advisories = utils.filter_not_applicable_advisories('1.0.1', self.all_advisories)
        self.assertEqual(2, len(advisories))
        self.assertEqual('https://istio.io/adv1', advisories[0])
        self.assertEqual('https://istio.io/adv2', advisories[1])

    def test4(self):
        advisories = utils.filter_not_applicable_advisories('1.0.9', self.all_advisories)
        self.assertEqual(0, len(advisories))

    def test5(self):
        advisories = utils.filter_not_applicable_advisories('1.5', self.all_advisories)
        self.assertEqual(0, len(advisories))

    def test6(self):
        advisories = utils.filter_not_applicable_advisories('3.0.3', self.all_advisories)
        self.assertEqual(0, len(advisories))

    def test7(self):
        advisories = utils.filter_not_applicable_advisories('3.0.6', self.all_advisories)
        self.assertEqual(1, len(advisories))
        self.assertEqual('https://istio.io/adv3', advisories[0])


if __name__ == '__main__':
    unittest.main()
