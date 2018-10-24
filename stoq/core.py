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

import concurrent.futures
import configparser
from datetime import datetime
import logging
from logging.handlers import RotatingFileHandler
import os
from typing import Dict, List, Optional, Set, Tuple
import queue

from pythonjsonlogger import jsonlogger  # pyre-ignore[21]

from .exceptions import StoqException
from stoq.data_classes import (
    Payload,
    PayloadMeta,
    PayloadResults,
    RequestMeta,
    StoqResponse,
)

import stoq.helpers as helpers
from stoq.plugin_manager import StoqPluginManager
from stoq.utils import ratelimited

# Created to enable `None' as a valid paramater
_UNSET = object()


class Stoq(StoqPluginManager):
    def __init__(
        self,
        base_dir: str = None,
        config_file: str = None,
        log_dir: str = _UNSET,
        log_level: str = None,
        plugin_dir_list: List[str] = None,
        plugin_opts: Dict[str, Dict] = None,
        providers: List[str] = None,
        source_archivers: List[str] = None,
        dest_archivers: List[str] = None,
        connectors: List[str] = None,
        dispatchers: List[str] = None,
        deep_dispatchers: List[str] = None,
        decorators: List[str] = None,
        always_dispatch: List[str] = None,
    ) -> None:
        if not base_dir:
            base_dir = os.getcwd()
        base_dir = os.path.realpath(base_dir)
        config_file = config_file if config_file else os.path.join(base_dir, 'stoq.cfg')

        config = configparser.ConfigParser(allow_no_value=True)
        if os.path.exists(config_file):
            config.read(config_file)

        self.max_queue = int(config.get('core', 'max_queue', fallback='100'))
        self.max_recursion = int(config.get('core', 'max_recursion', fallback='3'))
        self.max_dispatch_passes = int(
            config.get('core', 'max_dispatch_passes', fallback='1')
        )

        if log_dir is _UNSET:
            log_dir = config.get(
                'core', 'log_dir', fallback=os.path.join(base_dir, 'logs')
            )
        if not log_level:
            log_level = config.get('core', 'log_level', fallback='INFO')
        log_maxbytes = int(config.get('core', 'log_maxbytes', fallback='1500000'))
        log_backup_count = int(config.get('core', 'log_backup_count', fallback='5'))
        log_syntax = config.get('core', 'log_syntax', fallback='text')
        self._init_logger(
            log_dir, log_level, log_maxbytes, log_backup_count, log_syntax
        )

        if not plugin_dir_list:
            plugin_dir_str = config.get(
                'core', 'plugin_dir_list', fallback=os.path.join(base_dir, 'plugins')
            )
            plugin_dir_list = [d.strip() for d in plugin_dir_str.split(',')]

        super().__init__(plugin_dir_list, plugin_opts)

        if not providers:
            providers_str = config.get('core', 'providers', fallback='')
            providers = [d.strip() for d in providers_str.split(',') if d.strip()]
        self._loaded_provider_plugins = {d: self.load_plugin(d) for d in providers if d}
        if not source_archivers:
            source_arch_str = config.get('core', 'source_archivers', fallback='')
            source_archivers = [
                d.strip() for d in source_arch_str.split(',') if d.strip()
            ]
        self._loaded_source_archiver_plugins = {
            d: self.load_plugin(d) for d in source_archivers if d
        }
        if not dest_archivers:
            dest_arch_str = config.get('core', 'dest_archivers', fallback='')
            dest_archivers = [d.strip() for d in dest_arch_str.split(',') if d.strip()]
        self._loaded_dest_archiver_plugins = {
            d: self.load_plugin(d) for d in dest_archivers if d
        }
        if not connectors:
            conn_str = config.get('core', 'connectors', fallback='')
            connectors = [d.strip() for d in conn_str.split(',') if d.strip()]
        self._loaded_connector_plugins = [self.load_plugin(d) for d in connectors if d]
        if not dispatchers:
            dispatcher_str = config.get('core', 'dispatchers', fallback='')
            dispatchers = [d.strip() for d in dispatcher_str.split(',') if d.strip()]
        self._loaded_dispatcher_plugins = {
            d: self.load_plugin(d) for d in dispatchers if d
        }
        if not deep_dispatchers:
            deep_dispatcher_str = config.get('core', 'deep_dispatchers', fallback='')
            deep_dispatchers = [
                d.strip() for d in deep_dispatcher_str.split(',') if d.strip()
            ]
        self._loaded_deep_dispatcher_plugins = {
            d: self.load_plugin(d) for d in deep_dispatchers if d
        }
        if not decorators:
            decorator_str = config.get('core', 'decorators', fallback='')
            decorators = [d.strip() for d in decorator_str.split(',') if d.strip()]
        self._loaded_decorator_plugins = {
            d: self.load_plugin(d) for d in decorators if d
        }

        self.always_dispatch = always_dispatch
        if not self.always_dispatch:
            ad_str = config.get('core', 'always_dispatch', fallback='')
            self.always_dispatch = [d.strip() for d in ad_str.split(',') if d.strip()]
            for ad in self.always_dispatch:
                self.load_plugin(ad)

    @ratelimited()
    def scan(
        self,
        content: bytes,
        payload_meta: Optional[PayloadMeta] = None,
        request_meta: Optional[RequestMeta] = None,
        add_start_dispatch: Optional[List[str]] = None,
        add_start_deep_dispatch: Optional[List[str]] = None,
        ratelimit: Optional[str] = None,
    ) -> StoqResponse:
        payload_meta = PayloadMeta() if payload_meta is None else payload_meta
        payload = Payload(content, payload_meta)
        return self.scan_payload(
            payload, request_meta, add_start_dispatch, add_start_deep_dispatch
        )

    def scan_payload(
        self,
        payload: Payload,
        request_meta: Optional[RequestMeta] = None,
        add_start_dispatch: Optional[List[str]] = None,
        add_start_deep_dispatch: Optional[List[str]] = None,
    ) -> StoqResponse:
        request_meta = RequestMeta() if request_meta is None else request_meta
        add_start_dispatch = [] if add_start_dispatch is None else add_start_dispatch
        add_start_deep_dispatch = (
            [] if add_start_deep_dispatch is None else add_start_deep_dispatch
        )
        scan_results = []
        errors = []
        scan_queue = [(payload, add_start_dispatch, add_start_deep_dispatch)]
        hashes_seen: Set[str] = set(helpers.get_sha256(payload.content))

        for _recursion_level in range(self.max_recursion + 1):
            next_scan_queue: List[Tuple[Payload, List[str], List[str]]] = []
            for payload, add_dispatch, add_deep_dispatch in scan_queue:
                payload_results, extracted, p_errors = self._single_scan(
                    payload, add_dispatch, add_deep_dispatch, request_meta
                )
                scan_results.append(payload_results)
                # TODO: Add option for no-dedup
                for ex in extracted:
                    ex_hash = helpers.get_sha256(ex.content)
                    if ex_hash not in hashes_seen:
                        hashes_seen.add(ex_hash)
                        next_scan_queue.append((ex, ex.payload_meta.dispatch_to, []))
                errors.extend(p_errors)
            scan_queue = next_scan_queue

        response = StoqResponse(
            datetime.now().isoformat(), scan_results, request_meta, errors
        )

        for plugin_name, decorator in self._loaded_decorator_plugins.items():
            try:
                decorator_response = decorator.decorate(response)
            except Exception as e:
                msg = f'Exception decorating with decorator {plugin_name}: {str(e)}'
                self.log.exception(msg)
                errors.append(msg)
                continue
            if decorator_response is None:
                continue
            if decorator_response.results is not None:
                response.decorators[plugin_name] = decorator_response.results
            if decorator_response.errors is not None:
                response.errors.extend(decorator_response.errors)

        for connector in self._loaded_connector_plugins:
            connector.save(response)
        return response

    def run(self) -> None:
        # Don't initialize any (provider) plugins here! They should be
        # initialized on stoq start-up or via load_plugin()
        if not self._loaded_provider_plugins:
            raise StoqException('No activated provider plugins')
        payload_queue: queue.Queue = queue.Queue(self.max_queue)
        with concurrent.futures.ThreadPoolExecutor() as executor:
            # Start the load operations and mark each future with its URL
            future_to_name = {
                executor.submit(plugin.ingest, payload_queue): name
                for name, plugin in self._loaded_provider_plugins.items()
            }
            while len(future_to_name) > 0 or payload_queue.qsize() > 0:
                try:
                    # Using get_nowait results in high CPU churn
                    task = payload_queue.get(timeout=0.1)
                    payload = None
                    # Determine whether the provider has returned a `Payload`, or a task.
                    # If it is a task, load the defined archiver plugin to load the
                    # `Payload`, otherwise, simply continue on with the scanning.
                    if isinstance(task, Payload):
                        payload = task
                    else:
                        for (
                            source_name,
                            source_archiver,
                        ) in self._loaded_source_archiver_plugins.items():
                            try:
                                payload = source_archiver.get(task)
                                if isinstance(payload, Payload):
                                    break
                            except Exception as e:
                                self.log.warn(
                                    f'{task} not found in archive {source_name}'
                                )
                    if not payload:
                        raise StoqException('Unable to determine Payload from {task}')
                    self.scan_payload(payload)
                except queue.Empty:
                    pass
                for future in [fut for fut in future_to_name if fut.done()]:
                    try:
                        future.result()
                        self.log.info(
                            f'Provider plugin {future_to_name[future]} exited'
                        )
                        del future_to_name[future]
                    except Exception as e:
                        msg = (
                            f'Provider plugin {future_to_name[future]} '
                            'exited with an exception'
                        )
                        self.log.exception(msg)
                        raise StoqException(msg) from e

    def _single_scan(
        self,
        payload: Payload,
        add_dispatch: List[str],
        add_deep_dispatch: List[str],
        request_meta: RequestMeta,
    ) -> Tuple[PayloadResults, List[Payload], List[str]]:

        extracted = []
        errors = []
        dispatch_pass = 0

        dispatches, dispatch_errors = self._get_dispatches(
            payload, add_dispatch, request_meta
        )
        if dispatch_errors:
            errors.extend(dispatch_errors)
        for plugin_name in dispatches:
            try:
                plugin = self.load_plugin(plugin_name)
            except Exception as e:
                msg = f'Exception loading plugin {plugin_name} for dispatch'
                self.log.exception(msg)
                errors.append(msg)
                continue
            # Normal dispatches are the "1st round" of scanning
            payload.plugins_run['workers'][0].append(plugin_name)
            try:
                worker_response = plugin.scan(payload, request_meta)  # pyre-ignore[16]
            except Exception as e:
                msg = f'Exception scanning with plugin {plugin_name}: {str(e)}'
                self.log.exception(msg)
                errors.append(msg)
                continue
            if worker_response is None:
                continue
            if worker_response.results is not None:
                # Normal dispatches are the "1st round" of scanning
                payload.worker_results[0][plugin_name] = worker_response.results
            extracted.extend(
                [
                    Payload(
                        ex.content, ex.payload_meta, plugin_name, payload.payload_id
                    )
                    for ex in worker_response.extracted
                ]
            )
            if worker_response.errors:
                errors.extend(worker_response.errors)

        while dispatch_pass < self.max_dispatch_passes:
            dispatch_pass += 1
            deep_dispatches, deep_dispatch_errors = self._get_deep_dispatches(
                payload, add_deep_dispatch, request_meta
            )
            if deep_dispatch_errors:
                errors.extend(deep_dispatch_errors)
            if deep_dispatches:
                # Add another entry for this round
                payload.plugins_run['workers'].append([])
                payload.worker_results.append({})
            else:
                break
            for plugin_name in deep_dispatches:
                try:
                    plugin = self.load_plugin(plugin_name)
                except Exception as e:
                    msg = f'Exception loading plugin {plugin_name} for deep dispatch (pass {dispatch_pass}/{self.max_dispatch_passes})'
                    self.log.exception(msg)
                    errors.append(msg)
                    continue
                payload.plugins_run['workers'][dispatch_pass].append(plugin_name)
                try:
                    worker_response = plugin.scan(  # pyre-ignore[16]
                        payload, request_meta
                    )
                except Exception as e:
                    msg = f'Exception scanning with plugin {plugin_name} for deep dispatch (pass {dispatch_pass}/{self.max_dispatch_passes}): {str(e)}'
                    self.log.exception(msg)
                    errors.append(msg)
                    continue
                if worker_response is None:
                    continue
                if worker_response.results is not None:
                    payload.worker_results[dispatch_pass][
                        plugin_name
                    ] = worker_response.results
                extracted.extend(
                    [
                        Payload(
                            ex.content, ex.payload_meta, plugin_name, payload.payload_id
                        )
                        for ex in worker_response.extracted
                    ]
                )
                if worker_response.errors:
                    errors.extend(worker_response.errors)

        payload_results = PayloadResults.from_payload(payload)
        if request_meta.archive_payloads and payload.payload_meta.should_archive:
            for plugin_name, archiver in self._loaded_dest_archiver_plugins.items():
                payload.plugins_run['archivers'].append(plugin_name)
                try:
                    archiver_response = archiver.archive(payload, request_meta)
                except Exception as e:
                    msg = f'Exception archiving with archiver {plugin_name}: {str(e)}'
                    self.log.exception(msg)
                    errors.append(msg)
                    continue
                if archiver_response is None:
                    continue
                if archiver_response.results is not None:
                    payload_results.archivers[plugin_name] = archiver_response.results
                if archiver_response.errors is not None:
                    errors.extend(archiver_response.errors)
        return (payload_results, extracted, errors)

    def _init_logger(
        self,
        log_dir: Optional[str],
        log_level: str,
        log_maxbytes: int,
        log_backup_count: int,
        log_syntax: str,
    ) -> None:
        self.log = logging.getLogger('stoq')
        self.log.setLevel(log_level.upper())

        if log_syntax == 'json':
            formatter = jsonlogger.JsonFormatter
        else:
            formatter = logging.Formatter

        stderr_handler = logging.StreamHandler()
        stderr_logformat = formatter(
            '[%(asctime)s %(levelname)s] %(name)s: ' '%(message)s'
        )
        stderr_handler.setFormatter(stderr_logformat)
        self.log.addHandler(stderr_handler)

        if log_dir:
            # Let's attempt to make the log directory if it doesn't exist
            os.makedirs(log_dir, exist_ok=True)
            log_path = os.path.abspath(os.path.join(log_dir, 'stoq.log'))
            file_handler = RotatingFileHandler(
                filename=log_path,
                mode='a',
                maxBytes=log_maxbytes,
                backupCount=log_backup_count,
            )
            file_logformat = formatter(
                '%(asctime)s %(levelname)s %(name)s:'
                '%(filename)s:%(funcName)s:%(lineno)s: '
                '%(message)s',
                datefmt='%Y-%m-%d %H:%M:%S',
            )
            file_handler.setFormatter(file_logformat)
            self.log.addHandler(file_handler)
            self.log.debug(f'Writing logs to {log_path}')

    def _get_dispatches(
        self, payload: Payload, add_dispatches: List[str], request_meta: RequestMeta
    ) -> Tuple[Set[str], List[str]]:
        errors = []
        dispatches: Set[str] = set().union(add_dispatches, self.always_dispatch)

        for dispatcher_name, dispatcher in self._loaded_dispatcher_plugins.items():
            try:
                dispatcher_result = dispatcher.get_dispatches(payload, request_meta)
                dispatches.update(dispatcher_result.plugin_names)
                if dispatcher_result.meta is not None:
                    payload.dispatch_meta[dispatcher_name] = dispatcher_result.meta
            except Exception as e:
                msg = f'Exception with dispatcher {dispatcher_name}: {str(e)}'
                self.log.exception(msg)
                errors.append(msg)

        return (dispatches, errors)

    def _get_deep_dispatches(
        self,
        payload: Payload,
        add_deep_dispatches: List[str],
        request_meta: RequestMeta,
    ) -> Tuple[Set[str], List[str]]:
        errors = []
        deep_dispatches = set(add_deep_dispatches)

        for (
            deep_dispatcher_name,
            deep_dispatcher,
        ) in self._loaded_deep_dispatcher_plugins.items():
            try:
                deep_dispatcher_result = deep_dispatcher.get_deep_dispatches(
                    payload, request_meta
                )
                deep_dispatches.update(deep_dispatcher_result.plugin_names)
                if deep_dispatcher_result.meta is not None:
                    payload.deep_dispatch_meta[
                        deep_dispatcher_name
                    ] = deep_dispatcher_result.meta
            except Exception as e:
                msg = f'Exception with deep_dispatcher {deep_dispatcher_name}: {str(e)}'
                self.log.exception(msg)
                errors.append(msg)

        return (deep_dispatches, errors)

