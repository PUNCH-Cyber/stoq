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

import re

from stoq.plugins.base import StoqPluginBase


class StoqCarverPlugin(StoqPluginBase):

    def carve(self):
        pass

    def carve_payload(self, regex, payload, ignorecase=False):
        """
        Generator that returns a list of offsets for a specified value
        within a payload

        :param bytes regex: Regular expression to search for
        :param bytes payload: Payload to be searched against
        :param bool ignorecase: True or False, use re.IGNORECASE

        :returns: Offset of value(s) discovered
        :rtype: generator

        """

        self.log.debug("Carve: Attempting to carve payload")
        try:
            payload = payload.read()
        except:
            pass

        if ignorecase:
            # Ignorecase, Multiline, Dot matches all
            flags = re.I|re.M|re.S
        else:
            # Multiline, Dot matches all
            flags = re.M|re.S

        for buff in re.finditer(regex, payload, flags):
            self.log.debug("Carve: Payload carve at offset {} - {}".format(buff.start(), buff.end()))
            yield buff.start(), buff.end()