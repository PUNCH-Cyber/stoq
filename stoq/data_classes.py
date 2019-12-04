#!/usr/bin/env python5

#   Copyright 2014-present PUNCH Cyber Analytics Group
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
from typing import Dict, List, Optional, DefaultDict, Union

import stoq.helpers as helpers


class Error:
    def __init__(
        self,
        error: str,
        plugin_name: Optional[str] = None,
        payload_id: Optional[str] = None,
    ) -> None:
        """

        Object for errors collected from plugins

        :param error: Error message to add to results
        :param plugin_name: The name of the plugin producing the error
        :param payload_id: The ``payload_id`` of the ``Payload`` that the error occurred on

        >>> from stoq import Error, Payload
        >>> errors: List[Error] = []
        >>> payload = Payload(b'test bytes')
        >>> err = Error(
        ...     error='This is our error message',
        ...     plugin_name='test_plugin', 
        ...     payload_id=payload.results.payload_id
        ... )
        >>> errors.append(err)

        """
        self.error = error
        self.plugin_name = plugin_name
        self.payload_id = payload_id

    def __str__(self) -> str:
        return helpers.dumps(self)

    def __repr__(self):
        return repr(self.__dict__)


class PayloadMeta:
    def __init__(
        self,
        should_archive: bool = True,
        should_scan: bool = True,
        extra_data: Optional[Dict] = None,
        dispatch_to: Optional[List[str]] = None,
    ) -> None:
        """

        Object to store metadata pertaining to a payload

        :param should_archive: Archive payload if destination archiver is defined
        :param should_scan: Define whether the payload should be scanned by worker plugin
        :param extra_data: Additional metadata that should be added to the results
        :param dispatch_to: Force payload to be dispatched to specified plugins

        >>> from stoq import PayloadMeta
        >>> extra_data = {'filename': 'bad.exe', 'source': 'suricata'}
        >>> dispatch_to = ['yara']
        >>> payload_meta = PayloadMeta(
        ...     should_archive=True, extra_data=extra_data, dispatch_to=dispatch_to
        ... )

        """

        self.should_archive = should_archive
        self.should_scan = should_scan
        self.extra_data = {} if extra_data is None else extra_data
        self.dispatch_to = [] if dispatch_to is None else dispatch_to

    def __str__(self) -> str:
        return helpers.dumps(self)

    def __repr__(self):
        return repr(self.__dict__)


class Payload:
    def __init__(
        self,
        content: Union[bytes, str],
        payload_meta: Optional[PayloadMeta] = None,
        extracted_by: Optional[Union[str, List[str]]] = None,
        extracted_from: Optional[Union[str, List[str]]] = None,
        payload_id: Optional[str] = None,
    ) -> None:
        """

        Object to store payload and related information

        :param content: Raw bytes to be scanned
        :param payload_meta: Metadata pertaining to originating source
        :param extracted_by: Name of plugin that extracted the payload
        :param extracted_from: Unique payload ID the payload was extracted from
        :param payload_id: Unique ID of payload

        >>> from stoq import PayloadMeta, Payload
        >>> content = b'This is a raw payload'
        >>> payload_meta = PayloadMeta(should_archive=True)
        >>> payload = Payload(content, payload_meta=payload_meta)

        """
        self.content = content if isinstance(content, bytes) else content.encode()
        self.dispatch_meta: Dict[str, Dict] = {}
        self.results = PayloadResults(
            payload_id=payload_id,
            size=len(content),
            payload_meta=payload_meta,
            extracted_from=extracted_from,
            extracted_by=extracted_by,
        )

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

        >>> from stoq import RequestMeta
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
        size: int,
        payload_id: Optional[str] = None,
        payload_meta: Optional[PayloadMeta] = None,
        plugins_run: Optional[Dict[str, List[str]]] = None,
        extracted_from: Optional[Union[str, List[str]]] = None,
        extracted_by: Optional[Union[str, List[str]]] = None,
        workers: Optional[Dict] = None,
    ) -> None:
        """

        Results from worker plugins from the scanning of a payload

        :param payload_id: Unique ID of payload
        :param size: Size of raw payload
        :param payload_meta: `PayloadMeta` object for payload
        :param plugins_run: Plugins used to scan payload
        :param extracted_from: Unique payload ID the payload was extracted from
        :param extracted_by: Name of plugin that extracted the payload
        :param workers: Results from worker plugins

        """
        self.size = size
        self.payload_id = str(uuid.uuid4()) if payload_id is None else payload_id
        self.payload_meta = PayloadMeta() if payload_meta is None else payload_meta
        self.plugins_run = plugins_run or {'workers': [], 'archivers': []}
        if isinstance(extracted_from, str):
            extracted_from = [extracted_from]
        self.extracted_from = extracted_from or []
        if isinstance(extracted_by, str):
            extracted_by = [extracted_by]
        self.extracted_by = extracted_by or []
        self.workers = workers or {}
        self.archivers: Dict[str, Dict] = {}

    def __str__(self) -> str:
        return helpers.dumps(self)

    def __repr__(self):
        return repr(self.__dict__)


class Request:
    def __init__(
        self,
        payloads: Optional[List[Payload]] = None,
        request_meta: Optional[RequestMeta] = None,
        errors: Optional[List[Error]] = None,
    ):
        """

        Object that contains the state of a ``Stoq`` scan. This object is accessible within 
        all archiver, dispatcher, and worker plugins.

        :param payloads: All payloads that are being processed, to include extracted payloads
        :param request_meta: Original ``RequestMeta`` object
        :param errors: All errors that have been generated by plugins or ``Stoq``

        """

        self.payloads = payloads or []
        self.request_meta = request_meta or RequestMeta()
        self.errors = errors or []

    def __str__(self) -> str:
        return helpers.dumps(self)

    def __repr__(self):
        return repr(self.__dict__)


class StoqResponse:
    def __init__(
        self,
        request: Request,
        time: Optional[str] = None,
        decorators: Optional[Dict[str, Dict]] = None,
        scan_id: Optional[str] = None,
    ) -> None:
        """

        Response object of a completed scan

        :param results: ``PayloadResults`` object of scanned payload
        :param request_meta: ``RequetMeta`` object pertaining to original scan request
        :param time: ISO Formatted timestamp of scan
        :param decorators: Decorator plugin results

        """
        self.results = [p.results for p in request.payloads]
        self.request_meta = request.request_meta
        self.errors = request.errors
        self.time: str = datetime.now().isoformat() if time is None else time
        self.decorators = {} if decorators is None else decorators
        self.scan_id = str(uuid.uuid4()) if scan_id is None else scan_id

    def split(self) -> List[Dict]:
        """
        Split worker results individually

        """
        split_results = []
        for result in self.results:
            for k, v in result.workers.items():
                rcopy = deepcopy(self.__dict__)
                rcopy['results'] = [deepcopy(result.__dict__)]
                rcopy['results'][0]['workers'] = {k: v}
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

        >>> from stoq import PayloadMeta, ExtractedPayload
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
        errors: Optional[List[Error]] = None,
        dispatch_to: Optional[List[str]] = None,
    ) -> None:
        """

        Object containing response from worker plugins

        :param results: Results from worker scan
        :param extracted: ``ExtractedPayload`` objects of extracted payloads from scan
        :param errors: Errors that occurred

        >>> from stoq import WorkerResponse, ExtractedPayload
        >>> results = {'is_bad': True, 'filetype': 'executable'}
        >>> extracted_payload = [ExtractedPayload(content=data, payload_meta=extracted_meta)]
        >>> response = WorkerResponse(results=results, extracted=extracted_payload)

        """
        self.results = results
        self.extracted = extracted or []
        self.errors = errors or []
        self.dispatch_to = dispatch_to or []

    def __str__(self) -> str:
        return helpers.dumps(self)

    def __repr__(self):
        return repr(self.__dict__)


class ArchiverResponse:
    def __init__(
        self, results: Optional[Dict] = None, errors: Optional[List[Error]] = None
    ) -> None:
        """

        Object containing response from archiver destination plugins

        :param results: Results from archiver plugin
        :param errors: Errors that occurred

        >>> from stoq import ArchiverResponse
        >>> results = {'file_id': '12345'}
        >>> archiver_response = ArchiverResponse(results=results)

        """
        self.results = results
        self.errors = errors or []

    def __str__(self) -> str:
        return helpers.dumps(self)

    def __repr__(self):
        return repr(self.__dict__)


class DispatcherResponse:
    def __init__(
        self,
        plugin_names: Optional[List[str]] = None,
        meta: Optional[Dict] = None,
        errors: Optional[List[Error]] = None,
    ) -> None:
        """

        Object containing response from dispatcher plugins

        :param plugins_names: Plugins to send payload to for scanning
        :param meta: Metadata pertaining to dispatching results
        :param errors: Errors that occurred

        >>> from stoq import DispatcherResponse
        >>> plugins = ['yara', 'exif']
        >>> meta = {'hit': 'exe_file'}
        >>> dispatcher = DispatcherResponse(plugin_names=plugins, meta=meta)

        """
        self.plugin_names = [] if plugin_names is None else plugin_names
        self.meta = {} if meta is None else meta
        self.errors = errors or []

    def __str__(self) -> str:
        return helpers.dumps(self)

    def __repr__(self):
        return repr(self.__dict__)


class DecoratorResponse:
    def __init__(
        self, results: Optional[Dict] = None, errors: Optional[List[Error]] = None
    ) -> None:
        """

         Object containing response from decorator plugins

        :param results: Results from decorator plugin
        :param errors: Errors that occurred

        >>> from stoq import DecoratorResponse
        >>> results = {'decorator_key': 'decorator_value'}
        >>> errors = ['This plugin failed for a reason']
        >>> response = DecoratorResponse(results=results, errors=errors)

        """
        self.results = results
        self.errors = errors or []

    def __str__(self) -> str:
        return helpers.dumps(self)

    def __repr__(self):
        return repr(self.__dict__)
