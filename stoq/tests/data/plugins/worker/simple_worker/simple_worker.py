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

from typing import List, Optional

from stoq.data_classes import (
    ExtractedPayload,
    Payload,
    PayloadMeta,
    RequestMeta,
    WorkerResponse,
)
from stoq.plugins import WorkerPlugin


class SimpleWorker(WorkerPlugin):
    RAISE_EXCEPTION = False
    RETURN_ERRORS = False
    DISPATCH_TO: List[str] = []

    def scan(
        self, payload: Payload, request_meta: RequestMeta
    ) -> Optional[WorkerResponse]:
        if self.RAISE_EXCEPTION:
            raise Exception('Test exception please ignore')
        if self.DISPATCH_TO:
            dispatch_meta = PayloadMeta(dispatch_to=self.DISPATCH_TO)
            p = ExtractedPayload(b'Lorem ipsum', dispatch_meta)
        else:
            p = ExtractedPayload(b'Lorem ipsum')
        wr = WorkerResponse({'valuable_insight': 'wow'}, extracted=[p])
        if self.RETURN_ERRORS:
            wr.errors += ['Test error please ignore']
        return wr
