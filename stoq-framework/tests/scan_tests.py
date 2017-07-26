#   Copyright 2014-2017 PUNCH Cyber Analytics Group
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import unittest

import stoq.scan


class StoqScanTestCase(unittest.TestCase):

    def setUp(self):
        self.payload = b"This string will be hashed for testing"
        self.magic_string = "\x4d\x5a\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        self.magic = "application/octet-stream"
        self.md5 = "5a2db68e8be7f8ef361c27eb21e2ac37"
        self.sha1 = "632fb8827e40de9ffd8f8dbafdaddf9a4db5fb2a"
        self.sha256 = "a698ce08530306b9fd281f2533207fb48bae63e27a3cfe7529aa505be7e7257b"
        self.sha512 = "e069a3adaabcbda2463152e6f30ddd837b37429faef5a056d777614a535e81b3c564c454e22d1d0becee6eaab63f03678d56ff7273a8ab5128d4e6c531220f9a"
        self.ssdeep = "3:hWKxMu3r:hZxvr"

    def test_get_hashes(self):
        hashes = stoq.scan.get_hashes(self.payload)
        self.assertEqual(hashes['md5'], self.md5)
        self.assertEqual(hashes['sha1'], self.sha1)
        self.assertEqual(hashes['sha256'], self.sha256)
        self.assertEqual(hashes['sha512'], self.sha512)

    def test_get_md5(self):
        md5 = stoq.scan.get_md5(self.payload)
        self.assertEqual(md5, self.md5)

    def test_get_sha1(self):
        sha1 = stoq.scan.get_sha1(self.payload)
        self.assertEqual(sha1, self.sha1)

    def test_get_sha256(self):
        sha256 = stoq.scan.get_sha256(self.payload)
        self.assertEqual(sha256, self.sha256)

    def test_get_sha512(self):
        sha512 = stoq.scan.get_sha512(self.payload)
        self.assertEqual(sha512, self.sha512)

    def test_get_ssdeep(self):
        ssdeep = stoq.scan.get_ssdeep(self.payload)
        self.assertEqual(ssdeep, self.ssdeep)

    def test_ssdeep_compare(self):
        compare = stoq.scan.compare_ssdeep(self.payload, self.payload)
        self.assertEqual(compare, 100)

    def test_get_magic(self):
        magic = stoq.scan.get_magic(self.magic_string)
        self.assertEqual(magic, self.magic)

    def tearDown(self):
        pass
