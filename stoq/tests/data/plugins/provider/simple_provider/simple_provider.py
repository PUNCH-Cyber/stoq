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

from queue import Queue

from stoq import Payload
from stoq.plugins import ProviderPlugin


class SimpleProvider(ProviderPlugin):
    RAISE_EXCEPTION = False
    RETURN_PAYLOAD = True

    def ingest(self, queue: Queue) -> None:
        if self.RAISE_EXCEPTION:
            raise RuntimeError('Test exception, please ignore')
        if self.RETURN_PAYLOAD:
            queue.put(Payload(b'Important stuff'))
        else:
            queue.put({"simple_archiver": {"task": "This is a task from provider"}})
