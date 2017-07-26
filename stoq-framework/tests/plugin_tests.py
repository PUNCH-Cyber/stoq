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

from stoq.core import Stoq


class StoqPluginTestCase(unittest.TestCase):
    def setUp(self):
        self.stoq = Stoq()

        # Use tests from installed $CWD/tests, otherwise, try to use the install stoQ tests
        test_path = os.path.join(os.getcwd(), "tests")
        if not os.path.isdir(test_path):
            try:
                import stoq
                test_path = os.path.join(os.path.dirname(stoq.__file__), "tests")
            except ImportError:
                print("Test suite not found. Is stoQ installed or are tests in {}?".format(test_path))
                exit(1)

        self.stoq.plugin_dir = os.path.join(test_path, "plugins")

        # Make sure the plugins are setup for tests
        self.stoq.default_connector = "test_connector"
        self.stoq.manager.setPluginPlaces([self.stoq.plugin_dir])
        self.stoq.collect_plugins()

        self.stoq.log.setLevel("CRITICAL")

    def test_load_carver_plugin(self):
        pass

    def test_load_connector_plugin(self):
        connector = self.stoq.load_plugin("test_connector", "connector")
        self.assertFalse(connector.incompatible_plugin)
        self.assertIsNotNone(connector)

    def test_save_with_connector(self):
        payload = "test payload"
        connector = self.stoq.load_plugin("test_connector", "connector")
        resp = connector.save(payload)
        self.assertEqual(resp, payload)

    def test_load_decoder_plugin(self):
        pass

    def test_load_extractor_plugin(self):
        pass

    def test_load_reader_plugin(self):
        pass

    def test_load_source_plugin(self):
        pass

    def test_load_worker_plugin(self):
        worker = self.stoq.load_plugin("test_worker", "worker")
        self.assertIsNotNone(worker)
        self.assertFalse(worker.incompatible_plugin)

    def test_scan_payload_return_none(self):
        worker = self.stoq.load_plugin("test_worker", "worker")
        resp = worker.start(None)
        self.assertFalse(resp)

    def test_scan_payload_return_false(self):
        worker = self.stoq.load_plugin("test_worker", "worker")
        resp = worker.start(None, return_false=True)
        self.assertFalse(resp)

    def test_scan_payload_return_true(self):
        worker = self.stoq.load_plugin("test_worker", "worker")
        resp = worker.start(None, return_true=True)
        self.assertTrue(resp)

    def test_scan_payload_return_string(self):
        worker = self.stoq.load_plugin("test_worker", "worker")
        resp = worker.start(None, return_string=True)
        self.assertTrue(resp)

    def test_scan_payload_return_bytes(self):
        worker = self.stoq.load_plugin("test_worker", "worker")
        resp = worker.start(None, return_bytes=True)
        self.assertTrue(resp)

    def test_scan_payload_return_list(self):
        worker = self.stoq.load_plugin("test_worker", "worker")
        resp = worker.start(None, return_list=True)
        self.assertTrue(resp)

    def test_scan_payload_return_dict(self):
        worker = self.stoq.load_plugin("test_worker", "worker")
        resp = worker.start(None, return_dict=True)
        self.assertTrue(resp)

    def test_scan_payload_and_save_without_template(self):
        payload = b"This is a payload to scan\x90\x90\x90\x00\x20"
        worker = self.stoq.load_plugin("test_worker", "worker")
        worker.saveresults = True
        worker.hashpayload = True
        resp = worker.start(payload, return_dict=True)
        self.assertTrue(resp)

    def test_scan_filename_and_save_without_template(self):
        worker = self.stoq.load_plugin("test_worker", "worker")
        worker.saveresults = True
        worker.hashpayload = True
        resp = worker.start(None, path="/tmp/notreallyafile", archive="test_connector", return_dict=True)
        self.assertTrue(resp)

    def test_scan_payload_and_save_with_template(self):
        payload = b"This is a payload to scan\x90\x90\x90\x00\x20"
        worker = self.stoq.load_plugin("test_worker", "worker")
        worker.template = "test.tpl"
        worker.saveresults = True
        worker.hashpayload = True
        worker.start(payload, return_dict=True)
        self.assertTrue(worker.template)

    def test_scan_payload_and_save_without_template_use_dispatching(self):
        pass

    def test_multiprocessing_worker(self):
        pass

    def test_archive_of_source_payload(self):
        pass

    def test_add_metadata_to_results(self):
        pass

    def test_min_version(self):
        worker = self.stoq.load_plugin("test_worker_min_version", "worker")
        self.assertTrue(worker.incompatible_plugin)

    def test_max_version(self):
        worker = self.stoq.load_plugin("test_worker_max_version", "worker")
        self.assertTrue(worker.incompatible_plugin)

    def test_carve_payload(self):
        pass

    def test_decoder_to_bytearray(self):
        pass

    def tearDown(self):
        pass

if __name__ == '__main__':
    unittest.main()
