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
import uuid
import shutil
import unittest
import datetime


from stoq.core import Stoq
from stoq.logo import print_logo

# Disable InsecureRequestWarning
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class StoqCoreTestCase(unittest.TestCase):
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

        data_prefix = os.path.join(test_path, "data")
        # Set stoQ variables for the test environment
        self.stoq.source_base_tuple = (os.path.join(data_prefix, "get"),
                                       os.path.join(data_prefix, "results"))

        self.stoq.log.setLevel("CRITICAL")

        # Variables used to get/read a file or url
        self.config_file_test = os.path.join(data_prefix, "stoq.cfg")
        self.get_text_file = os.path.join(data_prefix, "get/text_file")
        self.get_text_file_none = os.path.join(data_prefix, "get/nonexistent")
        self.get_text_file_nonauthorized = os.path.join(data_prefix, "notauthorized")
        self.get_text_url = "https://www.google.com/"
        self.get_invalid_url = "http://{}".format(str(uuid.uuid4()))

        # Variables used to write a file
        self.write_path = os.path.join(self.stoq.temp_dir, "write")
        self.write_path_nonexist = os.path.join(self.write_path, "newdir")
        self.write_text_file = "text_file"
        self.write_bin_file = "bin_file"

        # stoQ Results
        self.result_file_str = os.path.join(data_prefix, "results/smtp-session-str.stoq")
        self.result_file_bytes = os.path.join(data_prefix, "results/smtp-session-bytes.stoq")

    def test_signal_handler(self):
        from stoq import signal_handler
        from stoq.exceptions import SigtermCaught

        with self.assertRaises(SigtermCaught) as cm:
            signal_handler(1, None)

    def test_logo(self):
        self.assertIsNotNone(print_logo())

    def test_argv(self):
        argv = ['argv_test']
        temp_stoq = Stoq(argv=argv)
        self.assertEqual(temp_stoq.argv, argv)

    def test_base_dir(self):
        base_dir = os.path.realpath(os.getcwd())
        temp_stoq = Stoq(base_dir=base_dir)
        self.assertEqual(temp_stoq.base_dir, base_dir)

    def test_get_text_file(self):
        data = self.stoq.get_file(self.get_text_file)
        self.assertEqual(data, b"This is a text file\n")

    def test_get_invalid_url(self):
        data = self.stoq.get_file(self.get_invalid_url)
        self.assertIsNone(data)

    def test_get_url(self):
        data = self.stoq.get_file(self.get_text_url)
        self.assertIsNotNone(data)

    def test_get_url_without_ssl_verify(self):
        data = self.stoq.get_file(self.get_text_url, verify=False)
        self.assertIsNotNone(data)

    def test_get_text_nonexistent(self):
        data = self.stoq.get_file(self.get_text_file_none)
        self.assertIsNone(data)

    def test_get_text_notauthorized(self):
        data = self.stoq.get_file(self.get_text_file_nonauthorized)
        self.assertIsNone(data)

    def test_json_logger(self):
        s = Stoq()
        s.log_syntax = 'json'
        s.logger_init()
        self.assertEqual(s.log_syntax, 'json')

    def test_load_config(self):
        s = Stoq()
        s.config_file = self.config_file_test
        s.load_config()
        self.assertIsInstance(s.log_level, str)
        self.assertIsInstance(s.url_prefix_tuple, tuple)
        self.assertIsInstance(s.plugin_dir_list, list)
        self.assertIsInstance(s.is_dict, dict)

    def test_write_text_file(self):
        payload = "This is the content to write to disk"
        fullpath = os.path.join(self.write_path, self.write_text_file)
        result = self.stoq.write(payload, filename=self.write_text_file, path=self.write_path)
        with open(fullpath, "r") as f:
                self.assertEqual(payload, f.read())
        os.unlink(fullpath)
        self.assertEqual(result, fullpath)

    def test_write_text_file_nonexist(self):
        payload = "This is the content to write to disk"
        fullpath = os.path.join(self.write_path_nonexist, self.write_text_file)
        result = self.stoq.write(payload, filename=self.write_text_file, path=self.write_path_nonexist)
        self.assertEqual(result, fullpath)
        with open(fullpath, "r") as f:
                self.assertEqual(payload, f.read())
        shutil.rmtree(self.write_path_nonexist)

    def test_write_text_file_append(self):
        payload = "This is the content to write to disk"
        fullpath = os.path.join(self.write_path, self.write_text_file)
        result = self.stoq.write(payload, filename=self.write_text_file, path=self.write_path)

        with open(fullpath, "r") as f:
                self.assertEqual(payload, f.read())

        new_payload = "...and even more data now"
        fullpath = os.path.join(self.write_path, self.write_text_file)
        result = self.stoq.write(new_payload, filename=self.write_text_file,
                                 path=self.write_path, append=True)

        self.assertEqual(result, fullpath)
        with open(fullpath, "r") as f:
                self.assertEqual(payload + new_payload, f.read())

        os.unlink(fullpath)

    def test_write_text_file_overwrite(self):
        payload = "but now it is just this."
        fullpath = os.path.join(self.write_path, self.write_text_file)
        result = self.stoq.write(payload, filename=self.write_text_file,
                                 path=self.write_path, overwrite=True)
        self.assertEqual(result, fullpath)
        with open(fullpath, "r") as f:
                self.assertEqual(payload, f.read())
        os.unlink(fullpath)

    def test_write_bin_file(self):
        payload = b"hi\xe7\x8c\xab\x20\x62\x69\x6c\x6c\x79\x20\x74\x68\x65\x20\x74\x72\x6f\x6c\x6c"
        fullpath = os.path.join(self.write_path, self.write_text_file)
        result = self.stoq.write(payload, filename=self.write_text_file,
                                 path=self.write_path, binary=True)
        self.assertEqual(result, fullpath)
        with open(fullpath, "rb") as f:
                self.assertEqual(payload, f.read())
        os.unlink(fullpath)

    def test_force_unicode(self):
        data = b"hi\xe7\x8c\xab"
        resp = self.stoq.force_unicode(data)
        self.assertEqual(resp, "hi猫")

    def test_get_time(self):
        # Split the time since the microsecond will be different
        stoq_time = self.stoq.get_time.split(".")[0]
        curr_time = datetime.datetime.now().isoformat().split(".")[0]
        self.assertEqual(stoq_time, curr_time)

    def test_get_uuid(self):
        self.assertIsNotNone(self.stoq.get_uuid)

    def test_get_hashpath(self):
        h = "4caa16eba080d3d4937b095fb68999f3dbabd99d"
        path = os.path.join(self.stoq.archive_base, "4/c/a/a/1")
        result = self.stoq.hashpath(h)
        self.assertEqual(result, path)

    def test_loads_dumps_str(self):
        payload = self.stoq.get_file(self.result_file_str)
        json_str = self.stoq.loads(payload.decode())
        self.assertEqual(json_str['results'][0]['scan']['subject'], "Test")
        dumps = self.stoq.dumps(json_str)
        self.assertIsNotNone(dumps)

    def test_loads_dumps_str_compactly(self):
        payload = self.stoq.get_file(self.result_file_str)
        json_str = self.stoq.loads(payload.decode())
        self.assertEqual(json_str['results'][0]['scan']['subject'], "Test")
        dumps = self.stoq.dumps(json_str, compactly=True)
        self.assertIsNotNone(dumps)

    def test_loads_dumps_bytes(self):
        payload = self.stoq.get_file(self.result_file_bytes)
        json_str = self.stoq.loads(payload)
        self.assertEqual(json_str['results'][0]['scan']['subject'], "Test")
        dumps = self.stoq.dumps(json_str)
        self.assertIsNotNone(dumps)

    def test_loads_dumps_bytes_no_indent(self):
        payload = self.stoq.get_file(self.result_file_bytes)
        json_str = self.stoq.loads(payload)
        json_str['bytes'] = b"hi\xe7\x8c\xab\x20\x62\x69\x6c\x6c\x79\x20\x74\x68\x65\x20\x74\x72\x6f\x6c\x6c"
        self.assertEqual(json_str['results'][0]['scan']['subject'], "Test")
        dumps = self.stoq.dumps(json_str, indent=None)
        self.assertIsInstance(dumps, str)
        loads = self.stoq.loads(dumps)
        self.assertIsInstance(loads, dict)
        self.assertIsInstance(loads['bytes'], str)

    def test_loads_dumps_bytes_dict(self):
        payload = self.stoq.get_file(self.result_file_str)
        json_str = self.stoq.loads(payload)
        self.assertEqual(json_str['results'][0]['scan']['subject'], "Test")
        dumps = self.stoq.dumps(json_str)
        self.assertIsNotNone(dumps)

    def test_sanitize_json(self):
        payload = self.stoq.get_file(self.result_file_str)
        json_str = self.stoq.loads(payload.decode())
        sanitized_json = self.stoq.sanitize_json(json_str)
        self.assertEqual(sanitized_json['results'][0]['scan']['dot_notation'], 'Test')

    def test_normalize_json(self):
        payload = self.stoq.get_file(self.result_file_str)
        json_str = self.stoq.loads(payload.decode())
        normalized_json = self.stoq.normalize_json(json_str)
        self.assertIsInstance(normalized_json, dict)

    def tearDown(self):
        pass
