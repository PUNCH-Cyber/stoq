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

from typing import Iterator
from stoq.data_classes import Payload, DispatcherResponse, RequestMeta
from stoq.plugins import DispatcherPlugin


class SimpleDispatcher(DispatcherPlugin):
    RAISE_EXCEPTION = False
    RETURN_ERRORS = False
    SHOULD_ARCHIVE = True
    WORKERS = ['dummy_worker']
    RULE_COUNT = 1

    def dispatch(self, payload: Payload, request_meta: RequestMeta
                ) -> DispatcherResponse:
        if self.RAISE_EXCEPTION:
            raise Exception('Test exception please ignore')
        dr = DispatcherResponse()
        for worker in self.WORKERS:
            for count in range(0, self.RULE_COUNT):
                dr.plugin_names.append(worker)
                dr.meta[worker] = {f'rule{count}': worker}
                payload.payload_meta.should_archive = self.SHOULD_ARCHIVE
                if self.RETURN_ERRORS:
                    dr.errors += ['Test error please ignore']
        return dr