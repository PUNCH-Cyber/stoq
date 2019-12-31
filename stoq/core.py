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
    Plugins can be loaded at any time. However, to ensure consistent behavior, it is
    recommended that all required plugins be loaded upon instantiation.

    For these examples, it is assumed the below :ref:`plugins have been installed <installplugins>` in
    `$CWD/plugins`:
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

        >>> import asyncio
        >>> from stoq import Stoq, RequestMeta


    2. We will now define the plugins we want to use. In this case, we will be
       loading the ``hash``, and ``exif`` plugins:

        >>> workers = ['hash', 'exif']


    3. Now that we have our environment defined, lets instantiate the ``Stoq`` class:

        >>> s = Stoq(always_dispatch=workers)


    4. We can now load a payload, and scan it individually with `stoQ`:

        >>> src = '/tmp/bad.exe'
        >>> loop = asyncio.get_event_loop()
        >>> with open(src, 'rb') as src_payload:
        ...     meta = RequestMeta(extra_data={'filename': src})
        ...     results = loop.run_until_complete(s.scan(
        ...             content=src_payload.read(),
        ...             request_meta=meta))
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
        ...                "workers": {
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


    2. We will now define the plugins we want to use. In this case, we will be
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
        >>> loop = asyncio.get_event_loop()
        >>> loop.run_until_complete(s.run())


    A few things are happening here:
        #. The ``/tmp/datadump`` directory is being monitored for newly created files
        #. Each file is opened, and the payload is loaded into ``Stoq`` asynchronously
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
        >>> import asyncio
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

        >>> loop = asyncio.get_event_loop()
        >>> start_dispatch = ['yara']
        >>> results = loop.run_until_complete(
        ...     s.scan('raw bytes', add_start_dispatch=start_dispatch)
        ... )


    From ``Payload`` object
    ^^^^^^^^^^^^^^^^^^^^^^^

    If a ``Payload`` object has already been instantiated, as detailed above, the
    ``scan_request`` function may be called. First, a new `Request` object must
    be instantiated with the `Payload` object that we previously created:

        >>> import asyncio
        >>> from stoq import Payload, Request, RequestMeta
        >>> start_dispatch = ['yara']
        >>> loop = asyncio.get_event_loop()
        >>> payload = Payload(b'content to scan')
        >>> request = Request(payloads=[payload], request_meta=RequestMeta())
        >>> results = loop.run_until_complete(
        ...    s.scan_request(request, add_start_dispatch=start_dispatch)
        ... )


    Save Results
    ------------

    Finally, results may be saved using the desired ``Connector`` plugin. `stoQ` stores
    results from the framework as a ``StoqResponse`` object. The results will be saved
    to all connector plugins that have been loaded. In this example, we will only load
    the ``filedir`` plugin which will save the results to a specified directory.:

        >>> connector = s.load_plugin('filedir')
        >>> loop.run_until_complete(connector.save(results))

    Split Results
    -------------

    In some cases it may be required to split results out individually. For example, when
    saving results to different indexes depending on plugin name, such as with ElasticSearch or Splunk.

        >>> results = loop.run_until_complete(s.scan(payload))
        >>> split_results = results.split()

    Reconstructing Subresponse Results
    ----------------------------------

    stoQ can produce complex results depending on the recursion depth and extracted payload objects.
    In order to help handle complex results and limit redundant processing of payloads when using
    stoQ as a framework, a method exists that will allow for iterating over each result as if it
    were the original root object. This is especially useful when handling compressed archives, such
    as `zip` or `apk` files that may have multiple levels of archived content. Additionally, the
    defined decorators will be run against each newly constructed `StoqResponse` and added to the
    results.

        >>> await for result in s.reconstruct_all_subresponses(results):
        ...     print(result)

    Below is a simple flow diagram of the iterated results when being reconstructed.

    .. image:: /_static/reconstruct-results.png


    .. _multiplugindir:

    Multiple Plugin directories
    ===========================

    When instantiating ``Stoq``, multiple plugins directories may be defined. For more
    information on default paths, please refer to the :ref:`getting started documentation <stoqhome>`::

        >>> from stoq import Stoq
        >>> plugin_directories = ['/usr/local/stoq/plugins', '/home/.stoq/plugins']
        >>> s = Stoq(plugin_dir_list=plugin_directories)


    API
    ===

"""

import os
import asyncio
import logging
import configparser
from collections import defaultdict
from pythonjsonlogger import jsonlogger  # type: ignore
from logging.handlers import RotatingFileHandler
from typing import (
    AsyncGenerator,
    Awaitable,
    Coroutine,
    DefaultDict,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)

import stoq.helpers as helpers
from stoq.utils import ratelimited
from stoq.exceptions import StoqException
from stoq.plugin_manager import StoqPluginManager
from stoq.data_classes import (
    ArchiverResponse,
    DecoratorResponse,
    DispatcherResponse,
    Error,
    ExtractedPayload,
    Payload,
    PayloadMeta,
    PayloadResults,
    Request,
    RequestMeta,
    StoqResponse,
    WorkerResponse,
)
from stoq.plugins import (
    ArchiverPlugin,
    ConnectorPlugin,
    DecoratorPlugin,
    DispatcherPlugin,
    WorkerPlugin,
)


# Created to enable `None' as a valid paramater
_UNSET = object()


class Stoq(StoqPluginManager):
    def __init__(
        self,
        base_dir: Optional[str] = None,
        config_file: Optional[str] = None,
        log_dir: Optional[Union[str, object]] = _UNSET,
        log_level: Optional[str] = None,
        plugin_dir_list: Optional[List[str]] = None,
        plugin_opts: Optional[Dict[str, Dict]] = None,
        providers: Optional[List[str]] = None,
        provider_consumers: Optional[int] = None,
        source_archivers: Optional[List[str]] = None,
        dest_archivers: Optional[List[str]] = None,
        connectors: Optional[List[str]] = None,
        dispatchers: Optional[List[str]] = None,
        decorators: Optional[List[str]] = None,
        always_dispatch: Optional[List[str]] = None,
        max_queue: Optional[int] = None,
        max_recursion: Optional[int] = None,
        max_required_worker_depth: Optional[int] = None,
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
        :param decorators: Decorators to be used
        :param always_dispatch: Plugins to always send payloads to, no matter what
        :param provider_consumers: Number of provider consumers to instaniate
        :param max_queue: Max Queue size for Providers plugins
        :param max_recursion: Maximum level of recursion into a payload and extracted payloads
        :param max_required_worker_depth: Maximum depth for required worker plugins dependencies

        """
        if not base_dir:
            base_dir = os.getcwd()
        base_dir = os.path.realpath(base_dir)
        config_file = config_file or os.path.join(base_dir, 'stoq.cfg')
        config = helpers.StoqConfigParser(allow_no_value=True)
        if os.path.exists(config_file):
            config.read(config_file)

        self.max_queue = max_queue or config.getint('core', 'max_queue', fallback=100)
        self.provider_consumers = provider_consumers or config.getint(
            'core', 'provider_consumers', fallback=2
        )
        self.max_recursion = max_recursion or config.getint(
            'core', 'max_recursion', fallback=10
        )
        self.max_required_worker_depth = max_required_worker_depth or config.getint(
            'core', 'max_required_worker_depth', fallback=10
        )

        if log_dir is _UNSET:
            log_dir = config.get(
                'core', 'log_dir', fallback=os.path.join(base_dir, 'logs')
            )
        log_level = log_level or config.get('core', 'log_level', fallback='INFO')
        log_maxbytes = int(config.get('core', 'log_maxbytes', fallback='1500000'))
        log_backup_count = int(config.get('core', 'log_backup_count', fallback='5'))
        log_syntax = config.get('core', 'log_syntax', fallback='text')
        self._init_logger(
            log_dir,
            log_level,  # type: ignore
            log_maxbytes,
            log_backup_count,
            log_syntax,
        )

        plugin_dir_list = plugin_dir_list or config.getlist(
            'core', 'plugin_dir_list', fallback=os.path.join(base_dir, 'plugins')
        )

        super().__init__(plugin_dir_list, plugin_opts, config)

        providers = providers or config.getlist('core', 'providers', fallback=[])
        self._loaded_provider_plugins = {
            d: self.load_plugin(d) for d in providers if d  # type: ignore
        }

        source_archivers = source_archivers or config.getlist(
            'core', 'source_archivers', fallback=[]
        )
        self._loaded_source_archiver_plugins = {
            d: self.load_plugin(d) for d in source_archivers if d  # type: ignore
        }

        dest_archivers = dest_archivers or config.getlist(
            'core', 'dest_archivers', fallback=[]
        )
        self._loaded_dest_archiver_plugins = {
            d: self.load_plugin(d) for d in dest_archivers if d  # type: ignore
        }

        connectors = connectors or config.getlist('core', 'connectors', fallback=[])
        self._loaded_connector_plugins = [
            self.load_plugin(d) for d in connectors if d  # type: ignore
        ]

        dispatchers = dispatchers or config.getlist('core', 'dispatchers', fallback=[])
        self._loaded_dispatcher_plugins = {
            d: self.load_plugin(d) for d in dispatchers if d  # type: ignore
        }

        decorators = decorators or config.getlist('core', 'decorators', fallback=[])
        self._loaded_decorator_plugins = {
            d: self.load_plugin(d) for d in decorators if d  # type: ignore
        }

        self.always_dispatch = always_dispatch or config.get(
            'core', 'always_dispatch', fallback=[]
        )
        if self.always_dispatch:
            for ad in self.always_dispatch:
                self.load_plugin(ad)

    @ratelimited()
    async def scan(
        self,
        content: bytes,
        payload_meta: Optional[PayloadMeta] = None,
        request_meta: Optional[RequestMeta] = None,
        add_start_dispatch: Optional[List[str]] = None,
        ratelimit: Optional[str] = None,
    ) -> StoqResponse:
        """

        Wrapper for `scan_request` that creates a `Payload` object from bytes

        :param content: Raw bytes to be scanned
        :param payload_meta: Metadata pertaining to originating source
        :param request_meta: Metadata pertaining to the originating request
        :param add_start_dispatch: Force first round of scanning to use specified plugins
        :param ratelimit: Rate limit calls to scan

        """
        self.log.debug(
            f'Content received ({len(content)} bytes): '
            f'PayloadMeta: {helpers.dumps(payload_meta, indent=0)}, '
            f'RequestMeta: {helpers.dumps(request_meta, indent=0)}'
        )
        payload_meta = payload_meta or PayloadMeta()
        payload = Payload(content, payload_meta)
        request_meta = request_meta or RequestMeta()
        request = Request(payloads=[payload], request_meta=request_meta)
        return await self.scan_request(request, add_start_dispatch)

    async def run(
        self,
        request_meta: Optional[RequestMeta] = None,
        add_start_dispatch: Optional[List[str]] = None,
    ) -> None:
        """

        Run stoQ using a provider plugin to scan multiple files until exhaustion

        :param request_meta: Metadata pertaining to the originating request
        :param add_start_dispatch: Force first round of scanning to use specified plugins

        """
        # Don't initialize any (provider) plugins here! They should be
        # initialized on stoq start-up or via load_plugin()
        if not self._loaded_provider_plugins:
            raise StoqException('No activated provider plugins')

        self.log.debug(
            f'Starting provider queue: RequestMeta: {request_meta}, '
            f'start_dispatches: {add_start_dispatch}'
        )
        payload_queue: asyncio.Queue = asyncio.Queue(maxsize=self.max_queue)
        providers = [
            asyncio.ensure_future(plugin.ingest(payload_queue))
            for name, plugin in self._loaded_provider_plugins.items()
        ]
        workers = [
            asyncio.ensure_future(
                self._consume(payload_queue, request_meta, add_start_dispatch)
            )
            for n in range(self.provider_consumers)
        ]
        try:
            await asyncio.gather(*providers)
            await payload_queue.join()
        except KeyboardInterrupt:
            pass
        except Exception as e:
            self.log.exception(e, exc_info=True)
        finally:
            for worker in workers:
                worker.cancel()
                self.log.debug('Cancelling provider worker')

    async def scan_request(
        self, request: Request, add_start_dispatch: Optional[List[str]] = None
    ) -> StoqResponse:
        """

        Scan an individual payload

        :param request: ``Request`` object of payload(s) to be scanned
        :param add_start_dispatch: Force first round of scanning to use specified plugins

        """

        self.log.debug(
            f'Request received: RequestMeta: {helpers.dumps(request.request_meta, indent=0)}, '
            f'start_dispatches: {helpers.dumps(add_start_dispatch, indent=0)}'
        )

        add_dispatches: Set[Tuple[Payload, str]] = set()
        hashes_seen: DefaultDict[str, List] = defaultdict(list)
        for idx, payload in enumerate(request.payloads):
            if payload.results.payload_meta.should_scan and add_start_dispatch:
                for plugin_name in add_start_dispatch:
                    add_dispatches.add((payload, plugin_name))

            sha = helpers.get_sha256(payload.content)
            hashes_seen[sha].append(idx)

        for _recursion_level in range(1, self.max_recursion + 1):
            self.log.debug(f'Beginning worker round {_recursion_level}')
            scan_result = await self._execute_scan_round(request, add_dispatches)

            if scan_result is None:
                self.log.debug('No more plugins to run, completing scan')
                break

            extracted_payloads, add_dispatches = scan_result
            # TODO: Add option for no-dedup
            for extracted_payload in extracted_payloads:
                payload_hash = helpers.get_sha256(extracted_payload.content)
                if payload_hash not in hashes_seen:
                    self.log.debug(
                        f'Extracted payload {extracted_payload.results.payload_id} with '
                        f'PayloadMeta: {extracted_payload.results.payload_meta}'
                    )

                    request.payloads.append(extracted_payload)
                    hashes_seen[payload_hash].append(len(request.payloads) - 1)

                    payload_meta = extracted_payload.results.payload_meta
                    if _recursion_level >= self.max_recursion:
                        request.errors.append(
                            Error(
                                error=f'Final worker round ({_recursion_level}) reached, unable to process payload',
                                payload_id=extracted_payload.results.payload_id,
                            )
                        )
                    elif payload_meta.should_scan and payload_meta.dispatch_to:
                        add_dispatches.update(
                            (extracted_payload, add_dispatch)
                            for add_dispatch in payload_meta.dispatch_to
                        )
                else:
                    payload_idx = hashes_seen[payload_hash]
                    for idx in payload_idx:
                        request.payloads[idx].results.extracted_by.extend(
                            extracted_payload.results.extracted_by
                        )
                        request.payloads[idx].results.extracted_from.extend(
                            extracted_payload.results.extracted_from
                        )

        archive_tasks: List = []
        if request.request_meta.archive_payloads:
            for payload in request.payloads:
                if not payload.results.payload_meta.should_archive:
                    continue

                for archiver in self._loaded_dest_archiver_plugins.values():
                    archive_tasks.append(
                        self._apply_archiver(archiver, payload, request)
                    )
            await asyncio.gather(*archive_tasks)

        response = StoqResponse(request=request)

        decorator_tasks = []
        for decorator in self._loaded_decorator_plugins.values():
            decorator_tasks.append(self._apply_decorator(decorator, response))
        await asyncio.gather(*decorator_tasks)

        connector_tasks = []
        for connector in self._loaded_connector_plugins:
            connector_tasks.append(self._apply_connector(connector, response))
        await asyncio.gather(*connector_tasks)
        return response

    async def reconstruct_all_subresponses(
        self, stoq_response: StoqResponse
    ) -> AsyncGenerator[StoqResponse, None]:
        """

        Generate a new `StoqResponse` object for each `Payload` within
        the `Request`

        """

        for i, new_root_payload_result in enumerate(stoq_response.results):
            parent_payload_ids = {stoq_response.results[i].payload_id}
            # Contruct a new root Payload object since StoqResponse only has the
            # PayloadResults object
            new_root_payload = Payload(b'')
            new_root_payload.results = new_root_payload_result
            relevant_payloads: List[Payload] = [new_root_payload]

            for payload_result in stoq_response.results[i:]:
                for extracted_from in payload_result.extracted_from:
                    if extracted_from in parent_payload_ids:
                        parent_payload_ids.add(payload_result.payload_id)
                        new_payload = Payload(b'')
                        new_payload.results = payload_result
                        relevant_payloads.append(new_payload)

            new_request = Request(
                payloads=relevant_payloads, request_meta=stoq_response.request_meta
            )
            new_response = StoqResponse(
                request=new_request,
                time=stoq_response.time,
                scan_id=stoq_response.scan_id,
            )
            decorator_tasks = []
            for plugin_name, decorator in self._loaded_decorator_plugins.items():
                decorator_tasks.append(self._apply_decorator(decorator, new_response))
            await asyncio.gather(*decorator_tasks)
            yield new_response

    async def _execute_scan_round(
        self, request: Request, add_dispatches: Set[Tuple[Payload, str]]
    ) -> Optional[Tuple[List[Payload], Set[Tuple[Payload, str]]]]:
        # Form total set of dispatches to run
        total_dispatches: Set[Tuple[Payload, str]] = set(add_dispatches)
        get_dispatches: List[Awaitable] = [
            self._get_dispatches(payload, request)
            for payload in request.payloads
            if payload.results.payload_meta.should_scan
        ]
        for future in asyncio.as_completed(get_dispatches):
            payload, plugins = await future
            for plugin in plugins:
                total_dispatches.add((payload, plugin))

        # Resolve plugin dependencies
        can_run, deferred = self._resolve_dependencies(total_dispatches, request)

        if not can_run:  # Nothing left to do
            return None

        self.log.debug(
            f'Starting scan of {len(can_run)} tasks,'
            f' deferring {len(deferred)} to future rounds'
        )

        # Run plugins
        nested_worker_results: List[  # type: ignore
            Tuple[Set[Tuple[Payload, str]], List[Payload]]
        ] = await asyncio.gather(
            *[
                self._apply_worker(payload, plugin, request)
                for payload, plugin in can_run
            ]
        )

        extracted_payloads = []
        for additional_dispatches, extracted in nested_worker_results:
            deferred.update(additional_dispatches)
            extracted_payloads.extend(extracted)
        return extracted_payloads, deferred

    async def _get_dispatches(
        self, payload: Payload, request: Request
    ) -> Tuple[Payload, Set[str]]:
        # Run all dispatchers to form our initial set of worker plugins to run
        worker_plugins: Set[str] = set(
            self.always_dispatch
        ) if self.always_dispatch else set()
        dispatch_results: List[Set[str]] = await asyncio.gather(  # type: ignore
            *[
                self._apply_dispatcher(dispatcher, payload, request)
                for dispatcher in self._loaded_dispatcher_plugins.values()
            ]
        )
        for dispatch_result in dispatch_results:
            worker_plugins.update(dispatch_result)
        return payload, worker_plugins

    def _resolve_dependencies(
        self, total_dispatches: Set[Tuple[Payload, str]], request: Request
    ) -> Tuple[Set[Tuple[Payload, WorkerPlugin]], Set[Tuple[Payload, str]]]:
        # Resolve dependencies for each worker plugin that we want to run
        total_can_run: Set[Tuple[Payload, WorkerPlugin]] = set()
        total_deferred: Set[Tuple[Payload, str]] = set()
        for payload, plugin in total_dispatches:
            try:
                can_run, deferred = self._resolve_plugin_dependencies(
                    payload, plugin, request, set()
                )
            except RuntimeError as e:
                self.log.exception(e)
                request.errors.append(
                    Error(
                        payload_id=payload.results.payload_id,
                        plugin_name=plugin,
                        error=helpers.format_exc(e),
                    )
                )
                continue

            total_can_run.update(can_run)
            total_deferred.update(deferred)
        return total_can_run, total_deferred

    def _resolve_plugin_dependencies(
        self,
        payload: Payload,
        plugin_name: str,
        request: Request,
        init_plugin_dependency_chain: Set[str],
        depth: int = 0,
    ) -> Tuple[Set[Tuple[Payload, WorkerPlugin]], Set[Tuple[Payload, str]]]:
        if plugin_name in init_plugin_dependency_chain:
            raise RecursionError(
                'Circular required plugin dependency found, '
                f'unable to process plugin {plugin_name}'
            )

        if depth > self.max_required_worker_depth:
            raise RecursionError(
                f'Max required plugin depth {self.max_required_worker_depth} reached, '
                'unable to generate additional tasks'
            )

        try:
            plugin: WorkerPlugin = self.load_plugin(plugin_name)  # type: ignore
        except Exception as e:
            msg = f'Worker plugin {plugin_name} failed to load'
            self.log.exception(msg)
            request.errors.append(
                Error(
                    payload_id=payload.results.payload_id,
                    plugin_name=plugin_name,
                    error=helpers.format_exc(e, msg=msg),
                )
            )
            return set(), set()

        if plugin_name in payload.results.plugins_run['workers']:
            return set(), set()

        can_run: Set[Tuple[Payload, WorkerPlugin]] = set()
        deferred: Set[Tuple[Payload, str]] = set()
        if self._plugin_can_run(payload, plugin):
            can_run.add((payload, plugin))
        else:
            deferred.add((payload, plugin_name))

        if len(plugin.required_workers) != 0:
            self.log.debug(
                f'{plugin_name} has dependencies of {", ".join(plugin.required_workers)}'
            )

            plugin_dependency_chain = init_plugin_dependency_chain.copy()
            plugin_dependency_chain.add(plugin_name)
            for required_plugin in plugin.required_workers:
                (
                    required_plugin_can_run,
                    required_plugin_deferred,
                ) = self._resolve_plugin_dependencies(
                    payload,
                    required_plugin,
                    request,
                    plugin_dependency_chain,
                    depth + 1,
                )
                can_run.update(required_plugin_can_run)
                deferred.update(required_plugin_deferred)
        return can_run, deferred

    async def _consume(
        self,
        payload_queue: asyncio.Queue,
        request_meta: Optional[RequestMeta] = None,
        add_start_dispatch: Optional[List[str]] = None,
    ) -> None:
        while True:
            try:
                task = await payload_queue.get()
                # Determine whether the provider has returned a `Payload`, or a task.
                # If it is a task, load the defined archiver plugin to load the
                # `Payload`, otherwise, simply continue on with the scanning.
                if isinstance(task, Payload):
                    request = Request([task], request_meta)
                    await self.scan_request(request, add_start_dispatch)
                else:
                    for source_archiver, task_meta in task.items():
                        self.log.debug(
                            f'Provider task received: source_archiver: {source_archiver}, '
                            f'task_meta: {task_meta}'
                        )
                        try:
                            ar = ArchiverResponse(task_meta)
                            payload = await self._loaded_source_archiver_plugins[
                                source_archiver
                            ].get(ar)
                            if payload:
                                request = Request([payload], request_meta)
                                await self.scan_request(request, add_start_dispatch)
                        except Exception as e:
                            self.log.warn(
                                f'"{task_meta}" failed with archiver "{source_archiver}": {str(e)}'
                            )
                payload_queue.task_done()
            except asyncio.QueueEmpty:
                pass

    def _plugin_can_run(self, payload: Payload, worker_plugin: WorkerPlugin) -> bool:
        for required_plugin_name in worker_plugin.required_workers:
            if required_plugin_name not in payload.results.plugins_run['workers']:
                return False
        return True

    async def _apply_worker(
        self, payload: Payload, plugin: WorkerPlugin, request: Request
    ) -> Tuple[Set[Tuple[Payload, str]], List[Payload]]:
        self.log.debug(
            f'Scanning Payload {payload.results.payload_id} with WorkerPlugin {plugin.plugin_name}'
        )
        try:
            worker_response: Optional[WorkerResponse] = await plugin.scan(
                payload, request
            )
        except Exception as e:
            worker_response = None
            msg = 'worker:failed to scan'
            self.log.exception(msg)
            request.errors.append(
                Error(
                    payload_id=payload.results.payload_id,
                    plugin_name=plugin.plugin_name,
                    error=helpers.format_exc(e, msg=msg),
                )
            )
        payload.results.plugins_run['workers'].append(plugin.plugin_name)

        if not worker_response:
            return set(), []

        if worker_response.results is not None:
            payload.results.workers[plugin.plugin_name] = worker_response.results
        request.errors.extend(worker_response.errors)

        additional_dispatches: Set[Tuple[Payload, str]] = {
            (payload, plugin_name) for plugin_name in worker_response.dispatch_to
        }

        extracted_payloads: List[Payload] = [
            Payload(
                content=extracted_payload.content,
                payload_meta=extracted_payload.payload_meta,
                extracted_by=plugin.plugin_name,
                extracted_from=payload.results.payload_id,
            )
            for extracted_payload in worker_response.extracted
        ]

        self.log.debug(
            f'Completed scan of {payload.results.payload_id} with '
            f'{len(worker_response.results) if worker_response.results else 0} result keys, '  # type: ignore
            f'{len(additional_dispatches)} additional dispatches, and '
            f'{len(extracted_payloads)} extracted payloads'
        )
        return additional_dispatches, extracted_payloads

    async def _apply_dispatcher(
        self, dispatcher: DispatcherPlugin, payload: Payload, request: Request
    ) -> Set[str]:
        self.log.debug(
            f'Sending {payload.results.payload_id} to dispatcher ({dispatcher.plugin_name})'
        )
        plugin_names: Set[str] = set()
        try:
            dispatcher_result = await dispatcher.get_dispatches(payload, request)
        except Exception as e:
            msg = 'dispatcher:failed to dispatch'
            self.log.exception(msg)
            request.errors.append(
                Error(
                    plugin_name=dispatcher.plugin_name,
                    error=helpers.format_exc(e, msg=msg),
                    payload_id=payload.results.payload_id,
                )
            )
            return plugin_names

        if dispatcher_result:
            if dispatcher_result.plugin_names is not None:
                plugin_names.update(dispatcher_result.plugin_names)
                self.log.debug(
                    f'Dispatching {payload.results.payload_id} to {plugin_names}'
                )

            if dispatcher_result.meta is not None:
                payload.dispatch_meta[dispatcher.plugin_name] = dispatcher_result.meta

        return plugin_names

    async def _apply_archiver(
        self, archiver: ArchiverPlugin, payload: Payload, request: Request
    ) -> None:
        archiver_response: Optional[ArchiverResponse] = None
        self.log.debug(
            f'Archiving {payload.results.payload_id} with {archiver.plugin_name}'
        )
        try:
            archiver_response = await archiver.archive(payload, request)
        except Exception as e:
            msg = 'archiver:failed to archive'
            self.log.exception(msg)
            request.errors.append(
                Error(
                    payload_id=payload.results.payload_id,
                    plugin_name=archiver.plugin_name,
                    error=helpers.format_exc(e, msg=msg),
                )
            )

        payload.results.plugins_run['archivers'].append(archiver.plugin_name)
        if archiver_response:
            if archiver_response.errors is not None:
                request.errors.extend(archiver_response.errors)

            if archiver_response.results is not None:
                payload.results.archivers[
                    archiver.plugin_name
                ] = archiver_response.results

    async def _apply_decorator(
        self, decorator: DecoratorPlugin, response: StoqResponse
    ) -> StoqResponse:
        """Mutates the given StoqResponse object to include decorator information"""
        self.log.debug(f'Applying decorator {decorator.plugin_name}')
        try:
            decorator_response = await decorator.decorate(response)
        except Exception as e:
            msg = 'decorator'
            self.log.exception(msg)
            error = Error(
                plugin_name=decorator.plugin_name, error=helpers.format_exc(e, msg=msg)
            )
            response.errors.append(error)
            return response
        if decorator_response is None:
            return response
        if decorator_response.results is not None:
            response.decorators[decorator.plugin_name] = decorator_response.results
        if decorator_response.errors:
            response.errors.extend(decorator_response.errors)
        return response

    async def _apply_connector(
        self, connector: ConnectorPlugin, response: StoqResponse
    ) -> None:
        self.log.debug(f'Saving results to connector {connector.plugin_name}')
        try:
            await connector.save(response)
        except Exception as e:
            msg = f'Failed to save results using {connector.__module__}'
            self.log.exception(msg)
            error = Error(
                plugin_name=connector.plugin_name, error=helpers.format_exc(e, msg=msg)
            )

    def _init_logger(
        self,
        log_dir: Union[object, str],
        log_level: str,
        log_maxbytes: int,
        log_backup_count: int,
        log_syntax: str,
    ) -> None:
        self.log = logging.getLogger('stoq')
        self.log.setLevel(log_level.upper())

        if log_syntax == 'json':
            formatter = jsonlogger.JsonFormatter  # type: ignore
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
            os.makedirs(log_dir, exist_ok=True)  # type: ignore
            log_path = os.path.abspath(
                os.path.join(log_dir, 'stoq.log')  # type: ignore
            )
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
