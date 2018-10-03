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

import collections
import concurrent.futures
import configparser
from datetime import datetime
import itertools
import logging
from logging.handlers import RotatingFileHandler
import os
from typing import DefaultDict, Dict, List, Optional, Set, Tuple, Iterator
import queue

from pythonjsonlogger import jsonlogger
import yara

from .exceptions import StoqException
from stoq.data_classes import Payload, PayloadMeta, PayloadResults, RequestMeta, StoqResponse, DispatcherResponse
import stoq.helpers as helpers
from stoq.plugin_manager import StoqPluginManager
from stoq.utils import ratelimited

# Created to enable `None' as a valid paramater
_UNSET = object()


class Stoq(StoqPluginManager):
    def __init__(self,
                 base_dir: str = None,
                 config_file: str = None,
                 log_dir: str = _UNSET,
                 log_level: str = None,
                 plugin_dir_list: List[str] = None,
                 plugin_opts: Dict[str, Dict] = None,
                 providers: List[str] = None,
                 archivers: List[str] = None,
                 connectors: List[str] = None,
                 dispatchers: List[str] = None,
                 decorators: List[str] = None,
                 always_dispatch: List[str] = None) -> None:
        if not base_dir:
            base_dir = os.getcwd()
        base_dir = os.path.realpath(base_dir)
        config_file = config_file if config_file else os.path.join(
            base_dir, 'stoq.cfg')

        config = configparser.ConfigParser(allow_no_value=True)
        if os.path.exists(config_file):
            config.read(config_file)

        self.max_queue = int(config.get('core', 'max_queue', fallback='100'))
        self.max_recursion = int(
            config.get('core', 'max_recursion', fallback='3'))

        if log_dir is _UNSET:
            log_dir = config.get(
                'core', 'log_dir', fallback=os.path.join(base_dir, 'logs'))
        if not log_level:
            log_level = config.get('core', 'log_level', fallback='INFO')
        log_maxbytes = int(
            config.get('core', 'log_maxbytes', fallback='1500000'))
        log_backup_count = int(
            config.get('core', 'log_backup_count', fallback='5'))
        log_syntax = config.get('core', 'log_syntax', fallback='text')
        self._init_logger(log_dir, log_level, log_maxbytes, log_backup_count,
                          log_syntax)


        if not plugin_dir_list:
            plugin_dir_str = config.get(
                'core',
                'plugin_dir_list',
                fallback=os.path.join(base_dir, 'plugins'))
            plugin_dir_list = [d.strip() for d in plugin_dir_str.split(',')]

        super().__init__(plugin_dir_list, plugin_opts)

        if not providers:
            providers_str = config.get('core', 'providers', fallback='')
            providers = [d.strip() for d in providers_str.split(',') if d.strip()]
        self._loaded_provider_plugins = {d: self.load_plugin(d) for d in providers if d}
        if not archivers:
            arch_str = config.get('core', 'archivers', fallback='')
            archivers = [d.strip() for d in arch_str.split(',') if d.strip()]
        self._loaded_archiver_plugins = {d: self.load_plugin(d) for d in archivers if d}
        if not connectors:
            conn_str = config.get('core', 'connectors', fallback='')
            connectors = [d.strip() for d in conn_str.split(',') if d.strip()]
        self._loaded_connector_plugins = [self.load_plugin(d) for d in connectors if d]
        if not dispatchers:
            dispatcher_str = config.get('core', 'dispatchers', fallback='')
            dispatchers = [d.strip() for d in dispatcher_str.split(',') if d.strip()]
        self._loaded_dispatcher_plugins = {d: self.load_plugin(d) for d in dispatchers if d}
        if not decorators:
            decorator_str = config.get('core', 'decorators', fallback='')
            decorators = [d.strip() for d in decorator_str.split(',') if d.strip()]
        self._loaded_decorator_plugins = {d: self.load_plugin(d) for d in decorators if d}

        self.always_dispatch = always_dispatch
        if not self.always_dispatch:
            ad_str = config.get('core', 'always_dispatch', fallback='')
            self.always_dispatch = [
                d.strip() for d in ad_str.split(',') if d.strip()
            ]
            for ad in self.always_dispatch:
                self.load_plugin(ad)

    @ratelimited()
    def scan(self,
             content: bytes,
             payload_meta: Optional[PayloadMeta] = None,
             request_meta: Optional[RequestMeta] = None,
             add_start_dispatch: Optional[List[str]] = None,
             ratelimit: Optional[str] = None) -> StoqResponse:
        payload_meta = PayloadMeta() if payload_meta is None else payload_meta
        payload = Payload(content, payload_meta)
        return self.scan_payload(payload, request_meta, add_start_dispatch)

    def scan_payload(
            self,
            payload: Payload,
            request_meta: Optional[RequestMeta] = None,
            add_start_dispatch: Optional[List[str]] = None) -> StoqResponse:
        request_meta = RequestMeta() if request_meta is None else request_meta
        add_start_dispatch = [] if add_start_dispatch is None else add_start_dispatch

        scan_results = []
        errors = []
        scan_queue = [(payload, add_start_dispatch)]
        hashes_seen: Set[str] = set(helpers.get_sha256(payload.content))

        num_payloads = 0
        for _recursion_level in range(self.max_recursion + 1):
            next_scan_queue: List[Tuple[Payload, List[str]]] = []
            for payload, add_dispatch in scan_queue:
                payload_results, extracted, p_errors = self._single_scan(
                    payload, num_payloads, add_dispatch, request_meta)
                scan_results.append(payload_results)
                # TODO: Add option for no-dedup
                for ex in extracted:
                    ex_hash = helpers.get_sha256(ex.content)
                    if ex_hash not in hashes_seen:
                        hashes_seen.add(ex_hash)
                        next_scan_queue.append((ex, ex.payload_meta.dispatch_to))
                errors.extend(p_errors)
                num_payloads += 1
            scan_queue = next_scan_queue

        response = StoqResponse(datetime.now().isoformat(), scan_results, request_meta, errors)

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
                response.decorators[
                    plugin_name] = decorator_response.results
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
        self.payload_queue: queue.Queue = queue.Queue(self.max_queue)
        with concurrent.futures.ThreadPoolExecutor() as executor:
            # Start the load operations and mark each future with its URL
            future_to_name = {
                executor.submit(plugin.ingest, self.payload_queue): name
                for name, plugin in self._loaded_provider_plugins.items()
            }
            while len(future_to_name) > 0 or self.payload_queue.qsize() > 0:
                try:
                    # Using get_nowait results in high CPU churn
                    self.scan_payload(self.payload_queue.get(timeout=0.1))
                except queue.Empty:
                    pass
                for future in [fut for fut in future_to_name if fut.done()]:
                    try:
                        future.result()
                        self.log.info('Provider plugin '
                                      f'{future_to_name[future]} exited')
                        del future_to_name[future]
                    except Exception as e:
                        msg = (f'Provider plugin {future_to_name[future]} '
                               'exited with an exception')
                        self.log.exception(msg)
                        raise StoqException(msg) from e

    def _single_scan(self, payload: Payload, id: int, add_dispatch: List[str],
                     request_meta: RequestMeta,
                     ) -> Tuple[PayloadResults, List[Payload], List[str]]:
        payload_results = PayloadResults.from_payload(payload, id)
        extracted = []
        errors = []
        dispatches, dispatch_errors = self._get_dispatches(
            payload, add_dispatch, request_meta)
        if dispatch_errors:
            errors.extend(dispatch_errors)
        for plugin_name in dispatches:
            payload_results.plugins['workers'].append(plugin_name)
            try:
                plugin = self.load_plugin(plugin_name)
            except Exception as e:
                msg = f'Exception loading plugin {plugin_name} for dispatch'
                self.log.exception(msg)
                errors.append(msg)
                continue
            try:
                worker_response = plugin.scan(payload, request_meta)
            except Exception as e:
                msg = f'Exception scanning with plugin {plugin_name}: {str(e)}'
                self.log.exception(msg)
                errors.append(msg)
                continue
            if worker_response is None:
                continue
            if worker_response.results is not None:
                payload_results.workers[plugin_name] = worker_response.results
            extracted.extend([
                Payload(ex.content, ex.payload_meta, plugin_name, id)
                for ex in worker_response.extracted
            ])
            if worker_response.errors is not None:
                errors.extend(worker_response.errors)
        if request_meta.archive_payloads and payload.payload_meta.should_archive:
            for plugin_name, archiver in self._loaded_archiver_plugins.items():
                payload_results.plugins['archivers'].append(plugin_name)
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
                    payload_results.archivers[
                        plugin_name] = archiver_response.results
                if archiver_response.errors is not None:
                    errors.extend(archiver_response.errors)
        return (payload_results, extracted, errors)

    def _init_logger(self, log_dir: Optional[str], log_level: str,
                     log_maxbytes: int, log_backup_count: int,
                     log_syntax: str) -> None:
        self.log = logging.getLogger('stoq')
        self.log.setLevel(log_level.upper())

        if log_syntax == 'json':
            formatter = jsonlogger.JsonFormatter
        else:
            formatter = logging.Formatter

        stderr_handler = logging.StreamHandler()
        stderr_logformat = formatter('[%(asctime)s %(levelname)s] %(name)s: '
                                     '%(message)s')
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
                backupCount=log_backup_count)
            file_logformat = formatter(
                '%(asctime)s %(levelname)s %(name)s:'
                '%(filename)s:%(funcName)s:%(lineno)s: '
                '%(message)s',
                datefmt='%Y-%m-%d %H:%M:%S')
            file_handler.setFormatter(file_logformat)
            self.log.addHandler(file_handler)
            self.log.debug(f'Writing logs to {log_path}')

    def _get_dispatches(self, payload: Payload, add_dispatches: List[str],
                        request_meta: RequestMeta
                        ) -> Tuple[List[str], List[str]]:
        errors = []
        dispatchers = [d for d in add_dispatches] + \
                      [d for d in self.always_dispatch]

        for dispatcher_name, dispatcher in self._loaded_dispatcher_plugins.items():
            try:
                dispatcher_result = dispatcher.dispatch(payload, request_meta)
                dispatchers.extend(dispatcher_result.plugin_names)
                payload.dispatch_meta.update(
                    {dispatcher_name: dispatcher_result.meta})
            except Exception as e:
                msg = f'Exception with dispatcher {dispatcher_name}: {str(e)}'
                self.log.exception(msg)
                errors.append(msg)

        return (dispatchers, errors)

