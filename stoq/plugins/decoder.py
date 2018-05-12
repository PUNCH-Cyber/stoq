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

from stoq.plugins.base import StoqPluginBase


class StoqDecoderPlugin(StoqPluginBase):

    def decode(self):
        pass

    def to_bytearray(self, payload):
        """
        Convert payload to a bytearray

        :param bytes payload: Payload to be converted into byte array

        :returns: Payload as a bytearray
        :rtype: bytearray

        """
        self.log.debug("Converting payload ({} bytes) to a bytearray".format(len(payload)))
        if isinstance(payload, bytearray):
            pass
        elif isinstance(payload, bytes):
            payload = bytearray(payload)

        else:
            payload = bytearray(payload.encode())

        return payload
