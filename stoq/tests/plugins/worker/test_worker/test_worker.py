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

"""
Overview
========

Test stoQ worker plugin

"""

import argparse

from stoq.args import StoqArgs
from stoq.plugins import StoqWorkerPlugin


class TestWorkerScan(StoqWorkerPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):

        self.stoq = stoq

        parser = argparse.ArgumentParser()
        parser = StoqArgs(parser)

        options = parser.parse_args(self.stoq.argv[2:])

        super().activate(options=options)

        return True

    def scan(self, payload, **kwargs):
        """
        Test worker plugin

        :param bytes payload: Payload to be scanned
        :param **kwargs kwargs: Additional parameters (unused)

        :returns: Results from scan
        :rtype: dict or None

        """

        super().scan()

        return_false = kwargs.get("return_false", False)
        return_true = kwargs.get("return_true", False)
        return_string = kwargs.get("return_string", False)
        return_bytes = kwargs.get("return_bytes", False)
        return_list = kwargs.get("return_list", False)
        return_dict = kwargs.get("return_dict", False)
        return_payload = kwargs.get("return_payload", False)

        if return_false:
            return False
        elif return_true:
            return True
        elif return_string:
            return "This is a string being return by test_worker"
        elif return_bytes:
            return b"\x90\x90\x90\x00\x00\x00\x90\x90"
        elif return_list:
            results = []
            results.append({'key': 'value1', 'int': 1, 'str': 'test1'})
            results.append({'key': 'value2', 'int': 2, 'str': 'test2'})
            return results
        elif return_dict:
            results = {}
            results['str'] = "This is a parameter returned"
            results['int'] = 1
            results['list'] = ['a', 'b', 'c']
            results['dict'] = {'a': 1, 'b': '2', 'c': 'abc123'}
            return results
        elif return_payload:
            return payload
        else:
            return None
