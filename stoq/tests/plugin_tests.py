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
import types
import unittest
import collections

try:
    import jinja2
    HAS_JINJA2 = True
except ImportError:
    HAS_JINJA2 = False

from stoq.core import Stoq


class StoqPluginTestCase(unittest.TestCase):
    def setUp(self):
        self.stoq = Stoq()

        # Use tests from installed $CWD/tests, otherwise, try to use the install stoQ tests
        self.test_path = os.path.join(os.getcwd(), "tests")
        if not os.path.isdir(self.test_path):
            try:
                import stoq
                self.test_path = os.path.join(os.path.dirname(stoq.__file__), "tests")
            except ImportError:
                print("Test suite not found. Is stoQ installed or are tests in {}?".format(self.test_path))
                exit(1)

        self.stoq.default_connector = "test_connector"

        # Make sure the plugins are setup for tests
        self.stoq.plugin_dir = os.path.join(self.test_path, "plugins")
        self.invalid_plugins = os.path.join(self.test_path, "invalid_plugins")
        self.stoq.collect_plugins()

        self.data_prefix = os.path.join(self.test_path, "data")

        # Set stoQ variables for the test environment
        self.stoq.source_base_tuple = (os.path.join(self.data_prefix, "get"))

        # Variables used to get/read a file
        self.get_text_file = os.path.join(self.data_prefix, "get/text_file")

        # Dispatcher paths
        self.dispatch_rules = os.path.join(self.test_path, "test_dispatch.yar")
        self.get_dispatch_file = os.path.join(self.data_prefix, "get/dispatch_test")

        self.stoq.log.setLevel("CRITICAL")

    def test_load_carver_plugin(self):
        plugin = self.stoq.load_plugin("test_carver", "carver")
        self.assertFalse(plugin.incompatible_plugin)
        self.assertIsNotNone(plugin)

    def test_load_carver_from_worker(self):
        plugin = self.stoq.load_plugin("test_worker", "worker")
        resp = plugin.load_carver("test_carver")
        self.assertTrue(resp)

    def test_carver_plugin_carve(self):
        payload = "This is the return string"
        plugin = self.stoq.load_plugin("test_carver", "carver")
        resp = plugin.carve(payload)
        self.assertIsInstance(resp, list)
        self.assertEqual(resp[0][1], payload)
        self.assertEqual(resp[1][1], payload)

    def test_load_connector_plugin(self):
        plugin = self.stoq.load_plugin("test_connector", "connector")
        self.assertFalse(plugin.incompatible_plugin)
        self.assertIsNotNone(plugin)

    def test_load_connector_from_worker(self):
        plugin = self.stoq.load_plugin("test_worker", "worker")
        resp = plugin.load_connector("test_connector")
        self.assertTrue(resp)

    def test_connector_plugin_save(self):
        payload = "test payload"
        connector = self.stoq.load_plugin("test_connector", "connector")
        resp = connector.save(payload)
        self.assertEqual(resp, payload)

    def test_load_decoder(self):
        plugin = self.stoq.load_plugin("test_decoder", "decoder")
        self.assertFalse(plugin.incompatible_plugin)
        self.assertIsNotNone(plugin)

    def test_load_decoder_from_worker(self):
        plugin = self.stoq.load_plugin("test_worker", "worker")
        resp = plugin.load_decoder("test_decoder")
        self.assertTrue(resp)

    def test_decoder_plugin_decode(self):
        payload = "This is the return string"
        plugin = self.stoq.load_plugin("test_decoder", "decoder")
        resp = plugin.decode(payload)
        self.assertIsInstance(resp, list)
        self.assertEqual(resp[0][1], payload)
        self.assertEqual(resp[1][1], payload)

    def test_load_extractor(self):
        plugin = self.stoq.load_plugin("test_extractor", "extractor")
        self.assertFalse(plugin.incompatible_plugin)
        self.assertIsNotNone(plugin)

    def test_load_extractor_from_worker(self):
        plugin = self.stoq.load_plugin("test_worker", "worker")
        resp = plugin.load_extractor("test_extractor")
        self.assertTrue(resp)

    def test_extractor_plugin_extract(self):
        payload = "This is the return string"
        plugin = self.stoq.load_plugin("test_extractor", "extractor")
        resp = plugin.extract(payload)
        self.assertIsInstance(resp, list)
        self.assertEqual(resp[0][1], payload)
        self.assertEqual(resp[1][1], payload)

    def test_load_reader(self):
        plugin = self.stoq.load_plugin("test_reader", "reader")
        self.assertFalse(plugin.incompatible_plugin)
        self.assertIsNotNone(plugin)

    def test_load_reader_from_worker(self):
        plugin = self.stoq.load_plugin("test_worker", "worker")
        resp = plugin.load_reader("test_reader")
        self.assertTrue(resp)

    def test_reader_plugin_read(self):
        payload = "This is the return string"
        plugin = self.stoq.load_plugin("test_reader", "reader")
        resp = plugin.read(payload)
        self.assertIsInstance(resp, str)
        self.assertEqual(resp, payload)

    def test_load_source_plugin(self):
        plugin = self.stoq.load_plugin("test_source", "source")
        self.assertFalse(plugin.incompatible_plugin)
        self.assertIsNotNone(plugin)

    def test_load_source_from_worker(self):
        plugin = self.stoq.load_plugin("test_worker", "worker")
        resp = plugin.load_source("test_source")
        self.assertTrue(resp)

    def test_load_worker_plugin(self):
        worker = self.stoq.load_plugin("test_worker", "worker")
        self.assertFalse(worker.incompatible_plugin)
        self.assertIsNotNone(worker)

    def test_load_worker_from_worker(self):
        plugin = self.stoq.load_plugin("test_worker", "worker")
        resp = plugin.load_worker("test_worker_archive_connector")
        self.assertTrue(resp)

    def test_load_worker_plugin_archive_connector(self):
        worker = self.stoq.load_plugin("test_worker_archive_connector", "worker")
        self.assertFalse(worker.incompatible_plugin)
        self.assertIsNotNone(worker)

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

    def test_scan_payload_return_true_ratelimit(self):
        worker = self.stoq.load_plugin("test_worker", "worker")
        resp = worker.start(None, return_true=True, ratelimit="1/3")
        self.assertTrue(resp)

    def test_load_plugin_validate_config(self):
        worker = self.stoq.load_plugin("test_worker", "worker")
        self.assertFalse(worker.hashpayload)
        self.assertFalse(worker.saveresults)
        self.assertEqual(worker.description, "Test stoQ worker plugin")
        self.assertIsInstance(worker.param_list, list)
        self.assertIsInstance(worker.param_dict, dict)
        self.assertIsInstance(worker.param_tuple, tuple)

    def test_set_default_tlp(self):
        worker = self.stoq.load_plugin("test_worker", "worker")
        self.assertEqual(worker.default_tlp, self.stoq.default_tlp)

    def test_scan_payload_and_save_without_template(self):
        payload = b"This is a payload to scan\x90\x90\x90\x00\x20"
        worker = self.stoq.load_plugin("test_worker", "worker")
        worker.saveresults = True
        worker.hashpayload = True
        resp = worker.start(payload, return_dict=True)
        self.assertTrue(resp)

    def test_scan_filename_and_save_bytes_without_template(self):
        worker = self.stoq.load_plugin("test_worker", "worker")
        worker.saveresults = True
        worker.hashpayload = True
        resp = worker.start(None, path="/tmp/notreallyafile", archive="test_connector", return_bytes=True)
        self.assertTrue(resp)

    def test_scan_payload_and_save_combined_without_template(self):
        payload = b"This is a payload to scan\x90\x90\x90\x00\x20"
        worker = self.stoq.load_plugin("test_worker", "worker")
        worker.saveresults = True
        worker.hashpayload = True
        worker.combined_results = False
        resp = worker.start(payload, return_dict=True)
        self.assertTrue(resp)

    def test_scan_filename_and_save_without_template(self):
        worker = self.stoq.load_plugin("test_worker", "worker")
        worker.saveresults = True
        worker.hashpayload = True
        resp = worker.start(None, path="/tmp/notreallyafile", archive="test_connector", return_dict=True)
        self.assertTrue(resp)

    @unittest.skipUnless(HAS_JINJA2, "Jinja2 not installed")
    def test_scan_payload_and_save_with_template(self):
        payload = b"This is a payload to scan\x90\x90\x90\x00\x20"
        worker = self.stoq.load_plugin("test_worker", "worker")
        worker.template = "test.tpl"
        worker.saveresults = True
        worker.hashpayload = True
        worker.start(payload, return_dict=True)
        self.assertTrue(worker.template)

    @unittest.skipUnless(HAS_JINJA2, "Jinja2 not installed")
    def test_scan_payload_and_save_combined_with_template(self):
        payload = b"This is a payload to scan\x90\x90\x90\x00\x20"
        worker = self.stoq.load_plugin("test_worker", "worker")
        worker.template = "test.tpl"
        worker.saveresults = True
        worker.hashpayload = True
        worker.combined_results = False
        worker.start(payload, return_dict=True)
        self.assertTrue(worker.template)

    def test_scan_payload_and_save_without_template_use_dispatching(self):
        payload = self.stoq.get_file(self.get_dispatch_file)
        self.stoq.dispatch_rules = self.dispatch_rules
        worker = self.stoq.load_plugin("test_worker_dispatch", "worker")
        worker.saveresults = True
        worker.hashpayload = True
        resp = worker.start(payload, return_dict=True)
        self.assertTrue(worker.dispatch)
        self.assertIsNotNone(worker.yara_dispatcher_rules)
        self.assertTrue(resp)

    def test_scan_payload_with_source(self):
        self.stoq.default_source = "test_source"
        worker = self.stoq.load_plugin("test_worker", "worker")
        self.stoq.worker.path = self.get_text_file
        resp = worker.run()
        self.assertTrue(resp)

    def test_multiprocessing_worker(self):
        self.stoq.default_source = "test_source"
        worker = self.stoq.load_plugin("test_worker", "worker")
        self.stoq.worker.path = os.path.join(self.data_prefix, "get")
        resp = worker.run()
        self.assertTrue(resp)

    # Invalid plugin tests
    def test_collect_plugin_invalid_path(self):
        self.stoq.plugin_dir = os.path.join(self.invalid_plugins, "nonexistent")
        resp = self.stoq.collect_plugins()
        self.assertIsNone(resp)

    def test_collect_plugin_invalid_config(self):
        self.stoq.plugin_dir = os.path.join(self.invalid_plugins, "invalid_config")
        resp = self.stoq.collect_plugins()
        self.assertIsNone(resp)

    def test_collect_plugin_no_module(self):
        self.stoq.plugin_dir = os.path.join(self.invalid_plugins, "no_module")
        resp = self.stoq.collect_plugins()
        self.assertIsNone(resp)

    def test_get_plugin_invalid_category(self):
        resp = self.stoq.get_plugin("test_worker", "invalid_category")
        self.assertFalse(resp)

    def test_get_plugin_invalid_name(self):
        resp = self.stoq.get_plugin("invalid_name", "worker")
        self.assertFalse(resp)

    def test_load_plugin_name_none(self):
        resp = self.stoq.load_plugin(None, "worker")
        self.assertIsNone(resp)

    def test_load_plugin_category_none(self):
        resp = self.stoq.load_plugin("test_worker", None)
        self.assertIsNone(resp)

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

    def test_get_categories(self):
        resp = self.stoq.get_categories
        self.assertIsInstance(resp, collections.abc.KeysView)

    def test_get_all_plugin_names(self):
        resp = self.stoq.get_all_plugin_names
        self.assertIsInstance(resp, collections.abc.KeysView)

    def test_get_all_plugins(self):
        resp = self.stoq.get_all_plugins
        self.assertIsInstance(resp, dict)

    def test_get_plugins_of_category_worker(self):
        resp = self.stoq.get_plugins_of_category("worker")
        self.assertIsInstance(resp, types.GeneratorType)

    def test_get_plugins_of_category_connector(self):
        resp = self.stoq.get_plugins_of_category("connector")
        self.assertIsInstance(resp, types.GeneratorType)

    def test_get_plugins_of_category_reader(self):
        resp = self.stoq.get_plugins_of_category("reader")
        self.assertIsInstance(resp, types.GeneratorType)

    def test_get_plugins_of_category_source(self):
        resp = self.stoq.get_plugins_of_category("source")
        self.assertIsInstance(resp, types.GeneratorType)

    def test_get_plugins_of_category_extractor(self):
        resp = self.stoq.get_plugins_of_category("extractor")
        self.assertIsInstance(resp, types.GeneratorType)

    def test_get_plugins_of_category_carver(self):
        resp = self.stoq.get_plugins_of_category("carver")
        self.assertIsInstance(resp, types.GeneratorType)

    def test_get_plugins_of_category_decoder(self):
        resp = self.stoq.get_plugins_of_category("decoder")
        self.assertIsInstance(resp, types.GeneratorType)

    def test_list_plugins(self):
        pass

    def tearDown(self):
        pass

if __name__ == '__main__':
    unittest.main()
