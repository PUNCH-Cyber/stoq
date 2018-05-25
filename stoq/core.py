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
from typing import DefaultDict, Dict, List, Optional, Set, Tuple
import queue

from pythonjsonlogger import jsonlogger
import yara

from stoq.data_classes import Payload, PayloadMeta, PayloadResults, RequestMeta, StoqResponse
import stoq.helpers as helpers
from stoq.plugin_manager import StoqPluginManager
from stoq.utils import ratelimited


class Stoq(StoqPluginManager):
    def __init__(self,
                 base_dir: str = None,
                 config_file: str = None,
                 log_dir: str = None,
                 log_level: str = None,
                 dispatch_rules_path: str = None,
                 plugin_dir_list: List[str] = None,
                 plugin_opts: Dict[str, Dict] = None,
                 sources: List[str] = None,
                 archivers: List[str] = None,
                 connectors: List[str] = None,
                 always_dispatch: List[str] = None) -> None:
        if not base_dir:
            base_dir = os.getcwd()
        base_dir = os.path.realpath(base_dir)
        config_file = config_file if config_file else os.path.join(
            base_dir, 'stoq.cfg')

        config = configparser.ConfigParser()
        if os.path.exists(config_file):
            config.read(config_file)

        self.max_queue = int(config.get('core', 'max_queue', fallback='100'))
        self.max_recursion = int(
            config.get('core', 'max_recursion', fallback='3'))

        if not log_dir:
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

        if not dispatch_rules_path:
            dispatch_rules_path = config.get(
                'core',
                'dispatch_rules_path',
                fallback=os.path.join(base_dir, 'dispatcher.yar'))
        self.set_dispatch_rules(os.path.realpath(dispatch_rules_path))

        if not plugin_dir_list:
            plugin_dir_str = config.get(
                'core',
                'plugin_dir_list',
                fallback=os.path.join(base_dir, 'plugins'))
            plugin_dir_list = [d.strip() for d in plugin_dir_str.split(',')]

        super().__init__(plugin_dir_list, plugin_opts)

        if not sources:
            sources_str = config.get('core', 'sources', fallback='')
            sources = [d.strip() for d in sources_str.split(',') if d.strip()]
        if not archivers:
            arch_str = config.get('core', 'archivers', fallback='')
            archivers = [d.strip() for d in arch_str.split(',') if d.strip()]
        if not connectors:
            conn_str = config.get('core', 'connectors', fallback='')
            connectors = [d.strip() for d in conn_str.split(',') if d.strip()]
        if not always_dispatch:
            ad_str = config.get('core', 'always_dispatch', fallback='')
            self.always_dispatch = [
                d.strip() for d in ad_str.split(',') if d.strip()
            ]
        for plugin_name in itertools.chain(sources, archivers, connectors,
                                           self.always_dispatch):
            self.load_plugin(plugin_name)

    @ratelimited()
    def scan(self,
             content: bytes,
             payload_meta: Optional[PayloadMeta] = None,
             request_meta: Optional[RequestMeta] = None,
             add_start_dispatch: Optional[List[str]] = None,
             ratelimit: Optional[str] = None) -> StoqResponse:
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
        for _recursion_level in range(self.max_recursion):
            next_scan_queue: List[Tuple[Payload, List[str]]] = []
            for payload, add_dispatch in scan_queue:
                payload_results, extracted, p_errors = self._single_scan(
                    payload, num_payloads, add_dispatch, request_meta)
                scan_results.append(payload_results)
                # TODO: Add option for no-dedup
                for ex in extracted:
                    if helpers.get_sha256(ex.content) not in hashes_seen:
                        next_scan_queue.append(ex)
                errors.extend(p_errors)
                num_payloads += 1
            scan_queue = next_scan_queue
        response = StoqResponse(datetime.now(), scan_results, request_meta, errors)
        for connector in self._loaded_connector_plugins:
            connector.save(response)
        return response

    def run(self) -> None:
        # Don't initialize any (provider) plugins here!
        # Callers should use load_plugin()
        # TODO: throw if no activated source plugins
        self.payload_queue: queue.Queue = queue.Queue(self.max_queue)
        with concurrent.futures.ThreadPoolExecutor() as executor:
            # Start the load operations and mark each future with its URL
            future_to_name = {
                executor.submit(plugin.ingest, self.payload_queue): name
                for name, plugin in self._act_provider_plugins.items()
            }
            while len(future_to_name) > 0 or self.payload_queue.qsize() > 0:
                try:
                    # Using get_nowait results in high CPU churn
                    self.scan_payload(self.payload_queue.get(timeout=5))
                except queue.Empty:
                    pass
                for future in [fut for fut in future_to_name if fut.done()]:
                    try:
                        future.result()
                        self.log.info('Provider plugin '
                                      f'{future_to_name[future]} '
                                      'exited')
                    except Exception as e:
                        self.log.exception('Provider plugin '
                                           f'{future_to_name[future]} exited '
                                           'with an exception')
                        raise

    def set_dispatch_rules(self, filepath: Optional[str]) -> None:
        if filepath is None:
            self.dispatch_rules = None
        elif not os.path.isfile(filepath):
            self.log.warning(
                f'Nonexistent dispatch rules file provided, skipping: {filepath}'
            )
            self.dispatch_rules = None
        else:
            self.dispatch_rules = yara.compile(filepath=filepath)

    def _single_scan(self, payload: Payload, id: int, add_dispatch: List[str],
                     request_meta: RequestMeta,
                     ) -> Tuple[PayloadResults, List[Payload], List[str]]:
        payload_results = PayloadResults.from_payload(payload, id)
        extracted = []
        errors = []
        dispatches = self._get_dispatches(payload, add_dispatch)
        yara_dr_archive = True
        for plugin_name, dispatch_rules in dispatches:
            if dispatch_rules and any(
                    dr.get('save', '').lower().strip() == 'false'
                    for dr in dispatch_rules):
                yara_dr_archive = False
            payload_results.dispatched_to.append(plugin_name)
            try:
                plugin = self.load_plugin(plugin_name)
            except Exception as e:
                msg = f'Exception loading plugin {plugin_name} for dispatch'
                self.log.exception(msg)
                errors.append(msg)
                continue
            try:
                worker_response = plugin.scan(payload, dispatch_rules, request_meta)
            except Exception as e:
                msg = f'Exception scanning with plugin {plugin_name}'
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
        if request_meta.archive_payloads and payload.payload_meta.should_archive and yara_dr_archive:
            for name, archiver in self._loaded_archiver_plugins.items():
                payload_results.dispatched_to.append(name)
                try:
                    archiver_response = archiver.archive(payload, request_meta)
                except Exception as e:
                    msg = f'Exception archiving payload with archiver {plugin_name}'
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

    def _init_logger(self, log_dir: str, log_level: str, log_maxbytes: int,
                     log_backup_count: int, log_syntax: str) -> None:
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

    def _get_dispatches(self, payload: Payload, add_dispatches: List[str]
                        ) -> List[Tuple[str, Optional[List[Dict]]]]:
        names_to_rules: DefaultDict = collections.defaultdict(list)
        for match in self._yara_dispatch_matches(payload.content):
            if 'plugin' in match['meta']:
                plugin_names = set(match['meta']['plugin'].lower().split(','))
                for name in plugin_names:
                    names_to_rules[name.strip()].append(match['meta'])
        return ([(d, None) for d in add_dispatches] +
                [(d, None) for d in self.always_dispatch] +
                list(names_to_rules.items()))

    def _yara_dispatch_matches(self, content: bytes) -> List[Dict]:
        if self.dispatch_rules is None:
            return []
        return self.dispatch_rules.match(data=content, timeout=60)
