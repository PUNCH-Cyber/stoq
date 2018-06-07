#!/usr/bin/env python3

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

from datetime import datetime
import unittest

import stoq.helpers as helpers


class TestHelpers(unittest.TestCase):
    def test_dumps_types(self):
        # Verify that all of these come back with some content and don't raise
        self.assertTrue(helpers.dumps([1, 2, 3]))
        self.assertTrue(helpers.dumps({'a': 1, 'b': 2}))
        self.assertTrue(helpers.dumps({1, 2, 3}))
        self.assertTrue(helpers.dumps(datetime.now()))
        self.assertTrue(helpers.dumps(b'notunicode'))
        self.assertTrue(helpers.dumps(ClassWithAttrs()))

    def test_dumps_compactly(self):
        self.assertEqual(
            helpers.dumps({
                'a': 1,
                'b': 2
            }, compactly=True), '{"a": 1, "b": 2}')


class ClassWithAttrs():
    def __init__(self):
        self.a = 1
