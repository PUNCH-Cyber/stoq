#!/usr/bin/env python3

from typing import Dict, List, Optional, Union

import stoq.helpers as helpers


class PayloadMeta():
    def __init__(self,
                 should_archive: bool = True,
                 extra_data: Optional[Dict] = None) -> None:
        self.should_archive = should_archive
        self.extra_data = {} if extra_data is None else extra_data


class Payload():
    def __init__(self,
                 content: bytes,
                 payload_meta: Optional[PayloadMeta] = None,
                 extracted_by: Optional[str] = None,
                 extracted_from: Optional[int] = None) -> None:
        self.content = content
        self.payload_meta = PayloadMeta() if payload_meta is None else payload_meta
        self.extracted_by = extracted_by
        self.extracted_from = extracted_from
        self.dispatch_meta: Dict[str, Dict] = {}
        self.deep_dispatch_meta: Dict[str, Dict] = {}
        self.worker_results: List[Dict[str, Dict]] = [{}]  # Empty dict for first round
        self.plugins_run: Dict[str, Union[List[List[str]], List[str]]] = {'workers': [[]], 'archivers': []}


class RequestMeta():
    def __init__(self,
                 archive_payloads: bool = True,
                 source: Optional[str] = None,
                 extra_data: Optional[Dict] = None) -> None:
        self.archive_payloads = archive_payloads
        self.source = source
        self.extra_data = {} if extra_data is None else extra_data


class PayloadResults():
    def __init__(self,
                 payload_id: int,
                 md5: str,
                 sha1: str,
                 sha256: str,
                 sha512: str,
                 size: int,
                 payload_meta: PayloadMeta,
                 workers: List[Dict[str, Dict]],
                 plugins_run: Dict[str, Union[List[List[str]], List[str]]],
                 extracted_from: Optional[int] = None,
                 extracted_by: Optional[str] = None) -> None:
        self.payload_id = payload_id
        self.md5 = md5
        self.sha1 = sha1
        self.sha256 = sha256
        self.sha512 = sha512
        self.size = size
        self.extracted_from = extracted_from  # payload_id of parent payload, if applicable
        self.extracted_by = extracted_by  # plugin name that extracted this payload, if applicable
        self.payload_meta = payload_meta
        self.workers: List[Dict[str, Dict]] = workers
        self.archivers: Dict[str, Dict] = {}
        self.plugins_run = plugins_run


    @classmethod
    def from_payload(cls, payload: Payload,
                     payload_id: int) -> 'PayloadResults':
        md5 = helpers.get_md5(payload.content)
        sha1 = helpers.get_sha1(payload.content)
        sha256 = helpers.get_sha256(payload.content)
        sha512 = helpers.get_sha512(payload.content)
        size = len(payload.content)
        return cls(payload_id, md5, sha1, sha256, sha512, size, payload.payload_meta,
                   payload.worker_results, payload.plugins_run, payload.extracted_from,
                   payload.extracted_by)


class StoqResponse():
    def __init__(self,
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


class ExtractedPayload():
    def __init__(self,
                 content: bytes,
                 payload_meta: Optional[PayloadMeta] = None) -> None:
        self.content = content
        self.payload_meta: PayloadMeta = PayloadMeta() if payload_meta is None else payload_meta


class WorkerResponse():
    def __init__(self,
                 results: Optional[Dict] = None,
                 extracted: List[ExtractedPayload] = None,
                 errors: List[str] = None) -> None:
        self.results = results
        self.extracted = [] if extracted is None else extracted
        self.errors = [] if errors is None else errors


class ArchiverResponse():
    def __init__(self,
                 results: Optional[Dict] = None,
                 errors: List[str] = None) -> None:
        self.results = results
        self.errors = [] if errors is None else errors


class DispatcherResponse():
    def __init__(self,
                 plugin_names: Optional[List[str]] = None,
                 meta: Optional[Dict] = None,
                 errors: List[str] = None) -> None:
        self.plugin_names = [] if plugin_names is None else plugin_names
        self.meta = {} if meta is None else meta
        self.errors = [] if errors is None else errors


class DeepDispatcherResponse():
    def __init__(self,
                 plugin_names: Optional[List[str]] = None,
                 meta: Optional[Dict] = None,
                 errors: List[str] = None) -> None:
        self.plugin_names = [] if plugin_names is None else plugin_names
        self.meta = {} if meta is None else meta
        self.errors = [] if errors is None else errors


class DecoratorResponse():
    def __init__(self,
                 results: Optional[Dict] = None,
                 errors: List[str] = None) -> None:
        self.results = results
        self.errors = [] if errors is None else errors
