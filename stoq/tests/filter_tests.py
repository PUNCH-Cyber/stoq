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

import os
import unittest

try:
    import hydra
    from stoq.core import Stoq
    from stoq.filters import StoqBloomFilter
    HAS_HYDRA = True
except ImportError:
    HAS_HYDRA = False


@unittest.skipUnless(HAS_HYDRA, "Hydra not installed, skipping")
class StoqFiltersTestCase(unittest.TestCase):

    def setUp(self):
        self.stoq = Stoq()
        self.stoq.log.setLevel("CRITICAL")

        self.bloom_file = os.path.join(self.stoq.temp_dir, "stoq-test.bloom")

    def test_bloom_filter(self):
        bloomfilter = StoqBloomFilter()

        create_resp = bloomfilter.create_filter(self.bloom_file, 5000, 0.001)
        self.assertTrue(create_resp)

        query_resp = bloomfilter.query_filter("google.com")
        self.assertFalse(query_resp)

        add_resp = bloomfilter.query_filter("google.com", add_missing=True)
        self.assertFalse(add_resp)

        query_resp = bloomfilter.query_filter("google.com")
        self.assertTrue(query_resp)

        backup_resp = bloomfilter.backup_scheduler(0)
        self.assertTrue(backup_resp)

    def test_import_filter(self):
        bloomfilter = StoqBloomFilter()

        import_resp = bloomfilter.import_filter(self.bloom_file)
        self.assertTrue(import_resp)

        query_resp = bloomfilter.query_filter("google.com")
        self.assertTrue(query_resp)

        os.unlink(self.bloom_file)
        os.unlink(self.bloom_file + ".desc")

    def tearDown(self):
        pass
