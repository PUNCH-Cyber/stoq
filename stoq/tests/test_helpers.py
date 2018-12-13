#!/usr/bin/env python3

#   Copyright 2014-2018 PUNCH Cyber Analytics Group
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
from collections import defaultdict
import unittest

import stoq.helpers as helpers


class TestHelpers(unittest.TestCase):
    def setUp(self) -> None:
        self.generic_content = b'The quick brown fox'

    def test_dumps_types(self):
        # Verify that all of these come back with some content and don't raise
        self.assertTrue(helpers.dumps([1, 2, 3]))
        self.assertTrue(helpers.dumps({'a': 1, 'b': 2}))
        self.assertTrue(helpers.dumps({1, 2, 3}))
        self.assertTrue(helpers.dumps(datetime.now()))
        self.assertTrue(helpers.dumps(b'somebytes'))
        self.assertTrue(helpers.dumps(ClassWithAttrs()))

    def test_dumps_unicode(self):
        self.assertEqual(
            helpers.dumps({'key': b'value'}, compactly=True), '{"key": "value"}'
        )
        self.assertEqual(
            helpers.dumps({'key': b'hi\xe7\x8c\xab'}, compactly=True), '{"key": "hi猫"}'
        )

    def test_dumps_compactly(self):
        self.assertEqual(
            helpers.dumps({'a': 1, 'b': 2}, compactly=True), '{"a": 1, "b": 2}'
        )

    def test_dict_merge(self):
        d1 = defaultdict(list)
        d1['testkey'].append('test value')
        d1['anotherkey'].append('another value')
        d2 = defaultdict(list)
        d2['testkey'].append('merged test value')
        d2['anotherkey'].append('merged another value')
        self.assertEqual(
            helpers.merge_dicts(d1, d2),
            {
                'testkey': ['test value', 'merged test value'],
                'anotherkey': ['another value', 'merged another value'],
            },
        )

    def test_get_md5(self):
       h = helpers.get_md5(self.generic_content)
       self.assertEqual(h, 'a2004f37730b9445670a738fa0fc9ee5')

    def test_get_sha1(self):
       h = helpers.get_sha1(self.generic_content)
       self.assertEqual(h, 'c519c1a06cdbeb2bc499e22137fb48683858b345')

    def test_get_sha256(self):
       h = helpers.get_sha256(self.generic_content)
       self.assertEqual(h, '5cac4f980fedc3d3f1f99b4be3472c9b30d56523e632d151237ec9309048bda9')

    def test_get_sha512(self):
       h = helpers.get_sha512(self.generic_content)
       self.assertEqual(h, '015e6d23e760f612cca616c54f110cb12dd54213f1e046c7607081372402eff4936b379296ed549236020afb37bd3e728a044a4243754f095498c98bc24f77e0')


class ClassWithAttrs:
    def __init__(self):
        self.a = 1
