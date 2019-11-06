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

from typing import Optional

from stoq.data_classes import Payload, DispatcherResponse, Request
from stoq.plugins import DispatcherPlugin


class ConditionalDispatcher(DispatcherPlugin):
    CONDITIONAL_DISPATCH_WORKER = 'dummy_worker'
    WORKERS = ['simple_worker']

    async def get_dispatches(
        self, payload: Payload, request: Request
    ) -> Optional[DispatcherResponse]:
        dr = DispatcherResponse()
        if any(
            self.CONDITIONAL_DISPATCH_WORKER in request_payload.results.plugins_run['workers']
            for request_payload in request.payloads
        ):
            dr.plugin_names.extend(self.WORKERS)
        dr.meta['test_key'] = 'Useful metadata info'
        return dr
