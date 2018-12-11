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
from copy import deepcopy
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional, Union, Tuple, DefaultDict

import stoq.helpers as helpers


class PayloadMeta:
    def __init__(
        self,
        should_archive: bool = True,
        extra_data: Optional[Dict] = None,
        dispatch_to: Optional[List[str]] = None,
    ) -> None:
        """

        Object to store metadata pertaining to a payload

        :param should_archive: Archive payload if destination archiver is defined
        :param extra_data: Additional metadata that should be added to the results
        :param dispatch_to: Force payload to be dispatched to specified plugins

        >>> extra_data = {'filename': 'bad.exe', 'source': 'suricata'}
        >>> dispatch_to = ['yara']
        >>> payload_meta = PayloadMeta( should_archive=True, extra_data=extra_data, dispatch_to=dispatch_to)

        """

        self.should_archive = should_archive
        self.extra_data = {} if extra_data is None else extra_data
        self.dispatch_to = [] if dispatch_to is None else dispatch_to

    def __str__(self) -> str:
        return helpers.dumps(self)

    def __repr__(self):
        return repr(self.__dict__)


class Payload:
    def __init__(
        self,
        content: bytes,
        payload_meta: Optional[PayloadMeta] = None,
        extracted_by: Optional[str] = None,
        extracted_from: Optional[str] = None,
        payload_id: Optional[str] = None,
    ) -> None:
        """

        Object to store payload and related information

        :param content: Raw bytes to be scanned
        :param payload_meta: Metadata pertaining to originating source
        :param extracted_by: Name of plugin that extracted the payload
        :param extracted_from: Unique payload ID the payload was extracted from
        :param payload_id: Unique ID of payload

        >>> content = b'This is a raw payload'
        >>> payload_meta = PayloadMeta(should_archive=True)
        >>> payload = Payload(content, payload_meta=payload_meta)

        """
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

    def __repr__(self):
        return repr(self.__dict__)


class RequestMeta:
    def __init__(
        self,
        archive_payloads: bool = True,
        source: Optional[str] = None,
        extra_data: Optional[Dict] = None,
    ) -> None:
        """

        Origin source request metadata

        :param archive_payload: Archive payload if destination archiver is defined
        :param source: Request source information
        :param extra_data: Additional metadata that should be added to the results

        >>> extra_data = {'source': 'Ingest from data dump directory'}
        >>> request = RequestMeta(archive_payload=True, extra_data=extra_data)

        """
        self.archive_payloads = archive_payloads
        self.source = source
        self.extra_data = {} if extra_data is None else extra_data

    def __str__(self) -> str:
        return helpers.dumps(self)

    def __repr__(self):
        return repr(self.__dict__)


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
        """

        Results from worker plugins from the scanning of a payload

        :param payload_id: Unique ID of payload
        :param size: Size of raw payload
        :param payload_meta: `PayloadMeta` object for payload
        :param workers: Results from worker plugins
        :param plugins_run: Plugins used to scan payload
        :param extracted_by: Name of plugin that extracted the payload
        :param extracted_from: Unique payload ID the payload was extracted from

        """
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
        """

        Class method to create ``PayloadResults`` from ``Payload`` object

        >>> content = b'This is a raw payload'
        >>> payload_meta = PayloadMeta(should_archive=True)
        >>> payload = Payload(content, payload_meta=payload_meta)
        >>> payload_results = PayloadResults(payload)

        """
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

    def __repr__(self):
        return repr(self.__dict__)


class StoqResponse:
    def __init__(
        self,
        results: List[PayloadResults],
        request_meta: RequestMeta,
        errors: DefaultDict[str, List[str]],
        time: Optional[str] = None,
        decorators: Optional[Dict[str, Dict]] = None,
    ) -> None:
        """

        Response object of a completed scan

        :param results: ``PayloadResults`` object of scanned payload
        :param request_meta: ``RequetMeta`` object pertaining to original scan request
        :param errors: Errors that may have occurred during lifecyle of the payload
        :param time: ISO Formatted timestamp of scan
        :param decorators: Decorator plugin results

        """
        self.results = results
        self.request_meta = request_meta
        self.errors = errors
        self.time: str = datetime.now().isoformat() if time is None else time
        self.decorators: Dict[str, Dict] = {} if decorators is None else decorators
        self.scan_id = str(uuid.uuid4())

    def split(self) -> List[Dict]:
        """
        Split worker results individually

        """
        split_results = []
        for result in self.results:
            for workers in result.workers:
                for k, v in workers.items():
                    rcopy = deepcopy(self.__dict__)
                    rcopy['results'] = [deepcopy(result.__dict__)]
                    rcopy['results'][0]['workers'] = [{k: v}]
                    split_results.append(rcopy)
        return split_results

    def __str__(self) -> str:
        return helpers.dumps(self)

    def __repr__(self):
        return repr(self.__dict__)


class ExtractedPayload:
    def __init__(
        self, content: bytes, payload_meta: Optional[PayloadMeta] = None
    ) -> None:
        """

        Object to store extracted payloads for further analysis

        :param content: Raw bytes of extracted payload
        :param payload_meta: ``PayloadMeta`` object containing metadata about extracted payload

        >>> src = '/tmp/bad.exe'
        >>> data = open(src, 'rb').read()
        >>> extra_data = {'source': src}
        >>> extracted_meta = PayloadMeta(should_archive=True, extra_data=extra_data)
        >>> extracted_payload = ExtractedPayload(content=data, payload_meta=extracted_meta)

        """

        self.content = content
        self.payload_meta: PayloadMeta = PayloadMeta() if payload_meta is None else payload_meta


class WorkerResponse:
    def __init__(
        self,
        results: Optional[Dict] = None,
        extracted: Optional[List[ExtractedPayload]] = None,
        errors: Optional[List[str]] = None,
    ) -> None:
        """

        Object containing response from worker plugins

        :param results: Results from worker scan
        :param extracted: ``ExtractedPayload`` object of extracted payloads from scan
        :param errors: Errors that occurred

        >>> results = {'is_bad': True, 'filetype': 'executable'}
        >>> extracted_payload = ExtractedPayload(content=data, payload_meta=extracted_meta)
        >>> response = WorkerResponse(results=results, extracted=[extracted_payload])

        """
        self.results = results
        self.extracted = [] if extracted is None else extracted
        self.errors = [] if errors is None else errors

    def __str__(self) -> str:
        return helpers.dumps(self)

    def __repr__(self):
        return repr(self.__dict__)


class ArchiverResponse:
    def __init__(
        self, results: Optional[Dict] = None, errors: Optional[List[str]] = None
    ) -> None:
        """

        Object containing response from archiver destination plugins

        :param results: Results from archiver plugin
        :param errors: Errors that occurred

        >>> results = {'file_id': '12345}
        >>> archiver_response = ArchiverResponse(results=results)

        """
        self.results = results
        self.errors = [] if errors is None else errors

    def __str__(self) -> str:
        return helpers.dumps(self)

    def __repr__(self):
        return repr(self.__dict__)


class DispatcherResponse:
    def __init__(
        self,
        plugin_names: Optional[List[str]] = None,
        meta: Optional[Dict] = None,
        errors: Optional[List[str]] = None,
    ) -> None:
        """

        Object containing response from dispatcher plugins

        :param plugins_names: Plugins to send payload to for scanning
        :param meta: Metadata pertaining to dispatching results
        :param errors: Errors that occurred

        >>> plugins = ['yara', 'exif']
        >>> meta = {'hit': 'exe_file'}
        >>> dispatcher = DispatcherResponse(plugin_names=plugins, meta=meta)

        """
        self.plugin_names = [] if plugin_names is None else plugin_names
        self.meta = {} if meta is None else meta
        self.errors = [] if errors is None else errors

    def __str__(self) -> str:
        return helpers.dumps(self)

    def __repr__(self):
        return repr(self.__dict__)


class DeepDispatcherResponse:
    def __init__(
        self,
        plugin_names: Optional[List[str]] = None,
        meta: Optional[Dict] = None,
        errors: Optional[List[str]] = None,
    ) -> None:
        """

        Object containing response from deep dispatcher plugins

        :param plugins_names: Plugins to send payload to for scanning
        :param meta: Metadata pertaining to deep dispatching results
        :param errors: Errors that occurred

        >>> plugins = ['yara', 'exif']
        >>> meta = {'hit': 'exe_file'}
        >>> deep_dispatcher = DeepDispatcherResponse(plugin_names=plugins, meta=meta)

        """
        self.plugin_names = [] if plugin_names is None else plugin_names
        self.meta = {} if meta is None else meta
        self.errors = [] if errors is None else errors

    def __str__(self) -> str:
        return helpers.dumps(self)

    def __repr__(self):
        return repr(self.__dict__)


class DecoratorResponse:
    def __init__(
        self, results: Optional[Dict] = None, errors: Optional[List[str]] = None
    ) -> None:
        """
         Object containing response from decorator plugins

        :param results: Results from decorator plugin
        :param errors: Errors that occurred

        >>> results = {'decorator_key': 'decorator_value'}
        >>> errors = ['This plugin failed for a reason']
        >>> response = DecoratorResponse(results=results, errors=errors)

        """
        self.results = results
        self.errors = [] if errors is None else errors

    def __str__(self) -> str:
        return helpers.dumps(self)

    def __repr__(self):
        return repr(self.__dict__)
