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

"""
    .. _stoqoverview:

    Overview
    ========

    `stoQ` is an extremely flexible framework. In this section we will go over some of
    the most advanced uses and show examples of how it can be used as a framework.

    .. _framework:

    Framework
    =========

    stoQ is much more than simply a command to be run. First and foremost, stoQ is a
    framework. The command `stoq` is simply a means of interacting with the framework.
    For more detailed and robust information on APIs available for stoQ, please check
    out the :ref:`plugin documentation <pluginoverview>`.

    ``Stoq`` is the primary class for interacting with `stoQ` and its plugins.
    All arguments, except for plugins to be used, must be defined upon instantiation.
    Plugins can be loaded at any time. However, to ensure consistent
    behavior, it is recommended that all required plugins be loaded
    upon instantiation.

    For these examples, it is assumed the below :ref:`plugins have been installed <installplugins>`:
        - dirmon
        - exif
        - filedir
        - hash
        - yara


    .. _individualscan:

    Individual Scan
    ---------------

    Individual scans are useful for scanning single payloads at a time. The user is
    responsible for ensuring a payload is passed to the ``Stoq`` class.

    .. note:: ``Provider`` plugins are ignored when conducting an individual scan.

    1. First, import the required class:

        >>> from stoq import Stoq


    2. We will now define the plugins we want to us. In this case, we will be
       loading the ``hash``, and ``exif`` plugins:

        >>> workers = ['hash', 'exif']
        >>> plugin_dirs = ['/opt/plugins']


    3. Now that we have our environment defined, lets instantiate the ``Stoq`` class:

        >>> s = Stoq(
        ...     plugin_dir_list=plugin_dirs,
        ...     always_dispatch=workers
        ... )


    4. We can now load a payload, and scan it individually with `stoQ`:

        >>> src = '/tmp/bad.exe'
        >>> with open(src, 'rb') as src_payload:
        ...     s = Stoq()
        ...     meta = {'filename': src}
        ...     results = s.scan(
        ...             content=src_payload.read(),
        ...             request_meta=meta,
        ...             add_start_dispatch=plugins)
        >>> print(results)
        ...    {
        ...        "time": "...",
        ...        "results": [
        ...            {
        ...                "payload_id": "...",
        ...                "size": 507904,
        ...                "payload_meta": {
        ...                    "should_archive": true,
        ...                    "extra_data": {
        ...                        "filename": "/tmp/bad.exe"
        ...                    },
        ...                    "dispatch_to": []
        ...                },
        ...                "workers": [
        ...                    {
        ...                        "hash": {
        ... [...]


    .. _providerscan:

    Using Providers
    ---------------

    Using stoQ with providers allows for the scanning of multiple payloads from
    multiple sources. This method will instantiate a `Queue` which payloads
    are published to for scanning by `stoQ`. Additionally, payloads may be
    retrieved from multiple disparate data sources using `Archiver` plugins.

    1. First, import the required class:

        >>> from stoq import Stoq


    2. We will now define the plugins we want to us. In this case, we will be
       loading the ``dirmon``, ``filedir``, ``hash``, and ``exif`` plugins. We
       will also set the ``base_dir`` to a specific directory. Additionally,
       we will also set some plugin options to ensure the plugins are
       operating the way we'd like them:

        >>> always_dispatch = ['hash']
        >>> providers = ['dirmon']
        >>> connectors = ['filedir']
        >>> dispatchers = ['yara']
        >>> plugin_opts = {
        ...     'dirmon': {'source_dir': '/tmp/datadump'},
        ...     'filedir': {'results_dir': '/tmp/stoq-results'}
        ... }
        >>> base_dir = '/usr/local/stoq'
        >>> plugin_dirs = ['/opt/plugins']


    .. note:: Any plugin options available in the plugin's ``.stoq`` configuration
              file can be set via the ``plugin_opts`` argument.

    3. Now that we have our environment defined, lets instantiate the ``Stoq`` class,
    and run:

        >>> s = Stoq(
        ...     base_dir=base_dir,
        ...     plugin_dir_list=plugin_dirs,
        ...     dispatchers=dispatchers,
        ...     providers=providers,
        ...     connectors=connectors,
        ...     plugins_opts=plugins_opts,
        ...     always_dispatch=always_dispatch
        ... )
        >>> s.run()


    A few things are happening here:
        #. The ``/tmp/datadump`` directory is being monitored for newly created files
        #. Each file is opened, and the payload is loaded into ``Stoq``
        #. The payload is scanned with the ``yara`` dispatcher plugin
        #. The yara dispatcher plugin returns a list of plugins that the payload should
           be scanned with
        #. The plugins identified by the ``yara`` dispatcher are loaded, and the payload is
           sent to them
        #. Each payload will always be sent to the ``hash`` plugin because it was defined
           in ``always_dispatch``
        #. The results from all plugins are collected, and sent to the ``filedir``
           connector plugin
        #. The ``filedir`` plugin saves each result to disk in ``/tmp/stoq-results``

    .. _manualscan:

    Manual Interaction
    ==================

    ``Stoq`` may also be interacted with manually, rather than relying on the normal workflow.
    In this section, we will touch on how this can be done.

    Instantiating stoQ
    ------------------

    Let's start by simply instantiating ``Stoq`` with no options. There are several arguments
    available when instantiating ``Stoq``, please refer to the :ref:`plugin documentation <pluginoverview>`
    for more information and options available.:

        >>> from stoq import Stoq
        >>> s = Stoq()


    Loading plugins
    ---------------

    `stoQ` plugins can be loaded using a simple helper function. The framework will
    automatically detect the type of plugin is it based on the ``class`` of the plugin.
    There is no need to define the plugin type, `stoQ` will handle that once it is loaded.:

        >>> plugin = s.load_plugin('yara')


    Instantiate Payload Object
    --------------------------

    In order to scan a payload, a ``Payload`` object must first be instantiated. The
    ``Payload`` object houses all information related to a payload, to include the
    content of the payload and metadata (i.e., size, originating plugin information,
    dispatch metadata, among others) pertaining to the payload. Optionally, a ``Payload``
    object can be instantiated with a ``PayloadMeta`` object to ensure the originating
    metadata (i.e., filename, source path, etc...) is also made available:

        >>> import os
        >>> from stoq.data_classes import PayloadMeta, Payload
        >>> filename = '/tmp/test_file.exe'
        >>> with open(filename, 'rb') as src:
        ...    meta = PayloadMeta(
        ...        extra_data={
        ...            'filename': os.path.basename(filename),
        ...            'source_dir': os.path.dirname(filename),
        ...        }
        ...    )
        >>> payload = Payload(src.read(), meta)


    Scan payload
    ------------
    There are two helper functions available for scanning a payload. If a dispatcher
    plugin is not being used, then a worker plugin must be defined by passing the
    ``add_start_dispatch`` argument. This tells `stoQ` to send the ``Payload`` object
    to the specified worker plugins.

    From raw bytes
    ^^^^^^^^^^^^^^

    If a `Payload` object has not been created yet, the content of the raw payload can
    simply be passed to the `Stoq.scan` function. A ``Payload`` object will automatically
    be created.:

        >>> start_dispatch = ['yara']
        >>> results = s.scan('raw bytes', add_start_dispatch=start_dispatch)


    From ``Payload`` object
    ^^^^^^^^^^^^^^^^^^^^^^^

    If a ``Payload`` object has already been instatiated, as detailed above, the
    ``scan_payload`` function may be called:

        >>> start_dispatch = ['yara']
        >>> results = s.scan_payload(payload, add_start_dispatch=start_dispatch)


    Save Results
    ------------

    Finally, results may be saved using the desired ``Connector`` plugin. `stoQ` stores
    results from the framework as a ``StoqResponse`` object. The results will be saved
    to all connector plugins that have been loaded. In this example, we will only load
    the ``filedir`` plugin which will save the results to a specified directory.:

        >>> connector = s.load_plugin('filedir')
        >>> connector.save(results)

    Split Results
    -------------

    In some cases it may be required to split results out individually. For example, when
    saving results to different indexes depending on plugin name, such as with ElasticSearch or Splunk.

        >>> results = s.scan_payload(payload)
        >>> results.split()

    .. _multiplugindir:

    Multiple Plugin directories
    ===========================

    When instantiating ``Stoq``, multiple plugins directories may be defined. For more
    information on default paths, please refer to the :ref:`getting started documentation <stoqhome>`::

        >>> from stoq import Stoq
        >>> plugins_directories = ['/usr/local/stoq/plugins', '/home/.stoq/plugins']
        >>> s = Stoq(plugin_dir_list=plugins_directories)


    API
    ===

"""

import os
import json
import queue
import logging
import configparser
import concurrent.futures
from collections import defaultdict
from pythonjsonlogger import jsonlogger  # pyre-ignore[21]
from logging.handlers import RotatingFileHandler
from typing import Dict, List, Optional, Set, Tuple, DefaultDict


from .exceptions import StoqException
from stoq.data_classes import (
    Payload,
    PayloadMeta,
    PayloadResults,
    RequestMeta,
    StoqResponse,
    ArchiverResponse,
)

import stoq.helpers as helpers
from stoq.utils import ratelimited
from stoq.plugin_manager import StoqPluginManager

# Created to enable `None' as a valid paramater
_UNSET = object()


class Stoq(StoqPluginManager):
    def __init__(
        self,
        base_dir: Optional[str] = None,
        config_file: Optional[str] = None,
        log_dir: Optional[str] = _UNSET,
        log_level: Optional[str] = None,
        plugin_dir_list: Optional[List[str]] = None,
        plugin_opts: Optional[Dict[str, Dict]] = None,
        providers: Optional[List[str]] = None,
        source_archivers: Optional[List[str]] = None,
        dest_archivers: Optional[List[str]] = None,
        connectors: Optional[List[str]] = None,
        dispatchers: Optional[List[str]] = None,
        deep_dispatchers: Optional[List[str]] = None,
        decorators: Optional[List[str]] = None,
        always_dispatch: Optional[List[str]] = None,
    ) -> None:
        """

        Core Stoq Class

        :param base_dir: Base directory for stoQ
        :param config_file: stoQ Configuration file
        :param log_dir: Path to log directory
        :param log_level: Log level for logging events
        :param plugin_dir_list: Paths to search for stoQ plugins
        :param plugin_opts: Plugin specific options that are passed once a plugin is loaded
        :param providers: Provider plugins to be loaded and run for sending payloads to scan
        :param source_archivers: Archiver plugins to be used for loading payloads for analysis
        :param dest_archiver: Archiver plugins to be used for archiving payloads and extracted payloads
        :param connectors: Connectors to be loaded and run for saving results
        :param dispatchers: Dispatcher plugins to be used
        :param deep_dispatchers: Deep Dispatcher plugins to be used
        :param decorators: Decorators to be used
        :param always_dispatch: Plugins to always send payloads to, no matter what

        """
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
        """

        Wrapper for `scan_payload` that creates a `Payload` object from bytes

        :param content: Raw bytes to be scanned
        :param payload_meta: Metadata pertaining to originating source
        :param request_meta: Metadata pertaining to the originating request
        :param add_start_dispatch: Force first round of scanning to use specified plugins
        :param add_start_deep_dispatch: Force second round of scanning to use specified plugins
        :param ratelimit: Rate limit calls to scan

        :return: Complete scan results
        :rtype: StoqResponse

        """
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
        """

        Scan an individual payload

        :param payload: ``Payload`` object of data to be scanned
        :param request_meta: Metadata pertaining to the originating request
        :param add_start_dispatch: Force first round of scanning to use specified plugins
        :param add_start_deep_dispatch: Force second round of scanning to use specified plugins

        :return: Complete scan results
        :rtype: StoqResponse

        """
        request_meta = RequestMeta() if request_meta is None else request_meta
        add_start_dispatch = [] if add_start_dispatch is None else add_start_dispatch
        add_start_deep_dispatch = (
            [] if add_start_deep_dispatch is None else add_start_deep_dispatch
        )
        scan_results: List = []
        errors: DefaultDict[str, List[str]] = defaultdict(list)
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
                errors = helpers.merge_dicts(errors, p_errors)
            scan_queue = next_scan_queue

        response = StoqResponse(
            results=scan_results, request_meta=request_meta, errors=errors
        )

        for plugin_name, decorator in self._loaded_decorator_plugins.items():
            try:
                decorator_response = decorator.decorate(response)
            except Exception as e:
                msg = 'decorator'
                self.log.exception(msg)
                response.errors[plugin_name].append(
                    helpers.format_exc(e, msg='decorator')
                )
                continue
            if decorator_response is None:
                continue
            if decorator_response.results is not None:
                response.decorators[plugin_name] = decorator_response.results
            if decorator_response.errors is not None:
                response.errors[plugin_name].extend(decorator_response.errors)

        for connector in self._loaded_connector_plugins:
            connector.save(response)
        return response

    def run(
        self,
        add_start_dispatch: Optional[List[str]] = None,
        add_start_deep_dispatch: Optional[List[str]] = None,
    ) -> None:
        """

        Run stoQ using a provider plugin to scan multiple files until exhaustion

        """
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
                    # Determine whether the provider has returned a `Payload`, or a task.
                    # If it is a task, load the defined archiver plugin to load the
                    # `Payload`, otherwise, simply continue on with the scanning.
                    if isinstance(task, Payload):
                        self.scan_payload(
                            task,
                            add_start_dispatch=add_start_dispatch,
                            add_start_deep_dispatch=add_start_deep_dispatch,
                        )
                    else:
                        for source_archiver, task_meta in task.items():
                            try:
                                ar = ArchiverResponse(task_meta)
                                payload = self._loaded_source_archiver_plugins[
                                    source_archiver
                                ].get(ar)
                                if payload:
                                    self.scan_payload(
                                        payload,
                                        add_start_dispatch=add_start_dispatch,
                                        add_start_deep_dispatch=add_start_deep_dispatch,
                                    )
                            except Exception as e:
                                self.log.warn(
                                    f'"{task_meta}" failed with archiver "{source_archiver}": {str(e)}'
                                )
                except queue.Empty:
                    pass
                for future in [fut for fut in future_to_name if fut.done()]:
                    try:
                        future.result()
                        self.log.info(
                            f'Provider plugin {future_to_name[future]} successfully completed'
                        )
                        del future_to_name[future]
                    except Exception as e:
                        msg = f'provider:{future_to_name[future]} failed'
                        self.log.exception(msg)
                        raise StoqException(msg) from e

    def _single_scan(
        self,
        payload: Payload,
        add_dispatch: List[str],
        add_deep_dispatch: List[str],
        request_meta: RequestMeta,
    ) -> Tuple[PayloadResults, List[Payload], DefaultDict[str, List[str]]]:

        extracted = []
        errors: DefaultDict[str, List[str]] = defaultdict(list)
        dispatch_pass = 0

        dispatches, dispatch_errors = self._get_dispatches(
            payload, add_dispatch, request_meta
        )
        if dispatch_errors:
            errors = helpers.merge_dicts(errors, dispatch_errors)
        for plugin_name in dispatches:
            try:
                plugin = self.load_plugin(plugin_name)
            except Exception as e:
                msg = 'worker:failed to load'
                self.log.exception(msg)
                errors[plugin_name].append(helpers.format_exc(e, msg=msg))
                continue
            # Normal dispatches are the "1st round" of scanning
            payload.plugins_run['workers'][0].append(plugin_name)
            try:
                worker_response = plugin.scan(payload, request_meta)  # pyre-ignore[16]
            except Exception as e:
                msg = 'worker:failed to scan'
                self.log.exception(msg)
                errors[plugin_name].append(helpers.format_exc(e, msg=msg))
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
                errors[plugin_name].extend(worker_response.errors)

        while dispatch_pass < self.max_dispatch_passes:
            dispatch_pass += 1
            deep_dispatches, deep_dispatch_errors = self._get_deep_dispatches(
                payload, add_deep_dispatch, request_meta
            )
            if deep_dispatch_errors:
                errors = helpers.merge_dicts(errors, deep_dispatch_errors)
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
                    msg = f'deep dispatch:failed to load (pass {dispatch_pass}/{self.max_dispatch_passes})'
                    self.log.exception(msg)
                    errors[plugin_name].append(helpers.format_exc(e, msg=msg))
                    continue
                payload.plugins_run['workers'][dispatch_pass].append(plugin_name)
                try:
                    worker_response = plugin.scan(  # pyre-ignore[16]
                        payload, request_meta
                    )
                except Exception as e:
                    msg = f'deep dispatch:failed to scan (pass {dispatch_pass}/{self.max_dispatch_passes})'
                    self.log.exception(msg)
                    errors[plugin_name].append(helpers.format_exc(e, msg=msg))
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
                    errors[plugin_name].extend(worker_response.errors)

        payload_results = PayloadResults.from_payload(payload)
        if request_meta.archive_payloads and payload.payload_meta.should_archive:
            for plugin_name, archiver in self._loaded_dest_archiver_plugins.items():
                payload.plugins_run['archivers'].append(plugin_name)
                try:
                    archiver_response = archiver.archive(payload, request_meta)
                except Exception as e:
                    msg = 'archiver:failed to archive'
                    self.log.exception(msg)
                    errors[plugin_name].append(helpers.format_exc(e, msg=msg))
                    continue
                if archiver_response is None:
                    continue
                if archiver_response.results is not None:
                    payload_results.archivers[plugin_name] = archiver_response.results
                if archiver_response.errors is not None:
                    errors[plugin_name].extend(archiver_response.errors)

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
    ) -> Tuple[Set[str], DefaultDict[str, List[str]]]:

        errors: DefaultDict[str, List[str]] = defaultdict(list)
        dispatches: Set[str] = set().union(add_dispatches, self.always_dispatch)

        for dispatcher_name, dispatcher in self._loaded_dispatcher_plugins.items():
            try:
                dispatcher_result = dispatcher.get_dispatches(payload, request_meta)
                dispatches.update(dispatcher_result.plugin_names)
                if dispatcher_result.meta is not None:
                    payload.dispatch_meta[dispatcher_name] = dispatcher_result.meta
            except Exception as e:
                msg = 'dispatcher:failed to dispatch'
                self.log.exception(msg)
                errors[dispatcher_name].append(helpers.format_exc(e, msg=msg))

        return (dispatches, errors)

    def _get_deep_dispatches(
        self,
        payload: Payload,
        add_deep_dispatches: List[str],
        request_meta: RequestMeta,
    ) -> Tuple[Set[str], DefaultDict[str, List[str]]]:

        errors: DefaultDict[str, List[str]] = defaultdict(list)
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
                msg = 'deep dispatcher:failed to deep dispatch'
                self.log.exception(msg)
                errors[deep_dispatcher_name].append(helpers.format_exc(e, msg=msg))

        return (deep_dispatches, errors)

