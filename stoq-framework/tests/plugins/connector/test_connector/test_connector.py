#   Copyright 2014-2015 PUNCH Cyber Analytics Group
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

Test stoQ connector plugin

"""

from stoq.plugins import StoqConnectorPlugin


class TestConnector(StoqConnectorPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq
        super().activate()

    # We are just going to be a wrapper for Stoq.get_file()
    def get_file(self, **kwargs):
        """
        Return a payload for testing

        :returns: Content of payload
        :rtype: bytes

        """

        return b"This is a payload to scanned\x90\x90\x90\x00\x20"

    def save(self, payload, **kwargs):
        """
        Test stoQ connector plugin

        :param bytes payload: Content to be "saved"
        :param **kwargs kwargs: Additional attributes (unused)

        """

        return payload
