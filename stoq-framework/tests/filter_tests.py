#!/usr/bin/env python3

import os
import unittest

from stoq.core import Stoq
from stoq.filters import StoqBloomFilter


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
