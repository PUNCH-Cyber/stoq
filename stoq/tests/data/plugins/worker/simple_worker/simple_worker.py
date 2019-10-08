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
    Error,
    ExtractedPayload,
    Payload,
    PayloadMeta,
    Request,
    WorkerResponse,
)
from stoq.plugins import WorkerPlugin


class SimpleWorker(WorkerPlugin):
    RAISE_EXCEPTION = False
    RETURN_ERRORS = False
    DISPATCH_TO: List[str] = []
    SHOULD_SCAN = True
    EXTRACTED_PAYLOAD = None

    async def scan(
        self, payload: Payload, request: Request
    ) -> Optional[WorkerResponse]:
        if self.RAISE_EXCEPTION:
            raise Exception('Test exception please ignore')
        extracted_payload = self.EXTRACTED_PAYLOAD or b'Lorem ipsum'
        meta = PayloadMeta(should_scan=self.SHOULD_SCAN, dispatch_to=self.DISPATCH_TO)
        p = ExtractedPayload(extracted_payload, meta)
        wr = WorkerResponse({'valuable_insight': 'wow'}, extracted=[p])
        if self.RETURN_ERRORS:
            wr.errors.append(
                Error(
                    plugin_name='simple_worker',
                    error='Test error please ignore',
                    payload_id=payload.results.payload_id,
                )
            )
        return wr
