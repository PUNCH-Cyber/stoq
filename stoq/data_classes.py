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

import uuid
from typing import Dict, List, Optional, Union

import stoq.helpers as helpers


class PayloadMeta:
    def __init__(
        self,
        should_archive: bool = True,
        extra_data: Dict = None,
        dispatch_to: List[str] = None,
    ) -> None:
        self.should_archive = should_archive
        self.extra_data = {} if extra_data is None else extra_data
        self.dispatch_to = [] if dispatch_to is None else dispatch_to

    def __str__(self) -> str:
        return helpers.dumps(self)


class Payload:
    def __init__(
        self,
        content: bytes,
        payload_meta: Optional[PayloadMeta] = None,
        extracted_by: Optional[str] = None,
        extracted_from: Optional[str] = None,
        payload_id: Optional[str] = None,
    ) -> None:
        self.content = content
        self.size: int = len(content)
        self.payload_meta = PayloadMeta() if payload_meta is None else payload_meta
        self.extracted_by = extracted_by
        self.extracted_from = extracted_from
        self.dispatch_meta: Dict[str, Dict] = {}
        self.deep_dispatch_meta: Dict[str, Dict] = {}
        self.worker_results: List[Dict[str, Dict]] = [{}]  # Empty dict for first round
        self.plugins_run: Dict[str, Union[List[List[str]], List[str]]] = {
            'workers': [[]],
            'archivers': [],
        }
        self.payload_id = str(uuid.uuid4()) if payload_id is None else payload_id


class RequestMeta:
    def __init__(
        self,
        archive_payloads: bool = True,
        source: Optional[str] = None,
        extra_data: Dict = None,
    ) -> None:
        self.archive_payloads = archive_payloads
        self.source = source
        self.extra_data = {} if extra_data is None else extra_data

    def __str__(self) -> str:
        return helpers.dumps(self)


class PayloadResults:
    def __init__(
        self,
        payload_id: str,
        size: int,
        payload_meta: PayloadMeta,
        workers: List[Dict[str, Dict]],
        plugins_run: Dict[str, Union[List[List[str]], List[str]]],
        extracted_from: Optional[str] = None,
        extracted_by: Optional[str] = None,
    ) -> None:
        self.payload_id = payload_id
        self.size = size
        self.payload_meta = payload_meta
        self.workers: List[Dict[str, Dict]] = workers
        self.archivers: Dict[str, Dict] = {}
        self.plugins_run = plugins_run
        self.extracted_from = (
            extracted_from
        )  # payload_id of parent payload, if applicable
        self.extracted_by = (
            extracted_by
        )  # plugin name that extracted this payload, if applicable

    @classmethod
    def from_payload(cls, payload: Payload) -> 'PayloadResults':
        return cls(
            payload.payload_id,
            payload.size,
            payload.payload_meta,
            payload.worker_results,
            payload.plugins_run,
            payload.extracted_from,
            payload.extracted_by,
        )

    def __str__(self) -> str:
        return helpers.dumps(self)


class StoqResponse:
    def __init__(
        self,
        time: str,
        results: List[PayloadResults],
        request_meta: RequestMeta,
        errors: List[str],
        decorators: Optional[Dict[str, Dict]] = None,
    ) -> None:
        self.time = time
        self.results = results
        self.request_meta = request_meta
        self.errors = errors
        self.decorators: Dict[str, Dict] = {} if decorators is None else decorators
        self.scan_id = str(uuid.uuid4())

    def __str__(self) -> str:
        return helpers.dumps(self)


class ExtractedPayload:
    def __init__(
        self, content: bytes, payload_meta: Optional[PayloadMeta] = None
    ) -> None:
        self.content = content
        self.payload_meta: PayloadMeta = PayloadMeta() if payload_meta is None else payload_meta


class WorkerResponse:
    def __init__(
        self,
        results: Optional[Dict] = None,
        extracted: List[ExtractedPayload] = None,
        errors: List[str] = None,
    ) -> None:
        self.results = results
        self.extracted = [] if extracted is None else extracted
        self.errors = [] if errors is None else errors

    def __str__(self) -> str:
        return helpers.dumps(self)


class ArchiverResponse:
    def __init__(
        self, results: Optional[Dict] = None, errors: List[str] = None
    ) -> None:
        self.results = results
        self.errors = [] if errors is None else errors

    def __str__(self) -> str:
        return helpers.dumps(self)


class DispatcherResponse:
    def __init__(
        self,
        plugin_names: Optional[List[str]] = None,
        meta: Optional[Dict] = None,
        errors: List[str] = None,
    ) -> None:
        self.plugin_names = [] if plugin_names is None else plugin_names
        self.meta = {} if meta is None else meta
        self.errors = [] if errors is None else errors

    def __str__(self) -> str:
        return helpers.dumps(self)


class DeepDispatcherResponse:
    def __init__(
        self,
        plugin_names: Optional[List[str]] = None,
        meta: Optional[Dict] = None,
        errors: List[str] = None,
    ) -> None:
        self.plugin_names = [] if plugin_names is None else plugin_names
        self.meta = {} if meta is None else meta
        self.errors = [] if errors is None else errors

    def __str__(self) -> str:
        return helpers.dumps(self)


class DecoratorResponse:
    def __init__(
        self, results: Optional[Dict] = None, errors: List[str] = None
    ) -> None:
        self.results = results
        self.errors = [] if errors is None else errors

    def __str__(self) -> str:
        return helpers.dumps(self)
