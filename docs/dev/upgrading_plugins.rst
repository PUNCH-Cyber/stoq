.. _upgradingplugins:

Upgrading Plugins
=================

v2 to v3
********

With the release of stoQ v3, a few enhancements were introduced that requires v2 plugins
be slightly modified for use with v3. Some key changes include:

    - Full asyncio support with all plugins
    - The entire request state is passed to dispatchers, workers, and archivers. This 
      includes making all payloads, and their respective results, available to them.
    - A `Logger` object is now available to all plugins upono instantiation
    - Errors from plugins are no longer simply a list of strings, they are now a list
      of `Error` objects
    - Configuration parameters are passed to each plugin as a `StoqConfigParser` object
      rather than a `ConfigParser` object
    - DeepDispatcher plugins have been deprecated


__init__
--------

All plugin classes are instantiated exactly the same way. If the plugin requires additional
configuration options, the `__init__` function may be added to your plugin class.

v2
^^

::

    from typing import Dict, Optional
    from configparser import ConfigParser

    class MyPlugin(ConnectorPlugin):
        def __init__(self, config: ConfigParser, plugin_opts: Optional[Dict]) -> None:
            super().__init__(config, plugin_opts)

            if plugin_opts and 'my_setting' in plugin_opts:
                self.my_setting = plugin_opts['my_setting']
            elif config.has_option('options', 'my_setting'):
                self.my_setting = config.get('options', 'my_setting')
            else:
                self.my_setting = None

v3
^^

::

    from stoq.helpers import StoqConfigParser


    class MyPlugin(ConnectorPlugin):
        def __init__(self, config: StoqConfigParser) -> None:
            super().__init__(config)

            self.my_setting = config.get('options', 'my_setting', fallback=None)


ArchiverPlugin
--------------

v2
^^

::

    from stoq import Payload, RequestMeta, ArchiverPlugin, ArchiverResponse


    class MyArchiver(ArchiverPlugin):
        def archive(
            self, payload: Payload, request_meta: RequestMeta
        ) -> ArchiverResponse
            return ArchiverResponse

        def get(self, task: ArchiverResponse) -> Payload:
            return Payload()


v3
^^

::

    from stoq import Payload, RequestMeta, ArchiverPlugin, ArchiverResponse


    class MyArchiver(ArchiverPlugin):
        async def archive(
            self, payload: Payload, request: Request
        ) -> ArchiverResponse
            return ArchiverResponse

        async def get(self, task: ArchiverResponse) -> Payload:
            return Payload()


ConnectorPlugin
---------------

v2
^^

::

    from stoq import StoqResponse, ConnectorPlugin


    class MyConnector(ConnectorPlugin):
        def save(self, response: StoqResponse) -> None:
            print(f'saving: {response}')


v3
^^

::

    from stoq import StoqResponse, ConnectorPlugin


    class MyConnector(ConnectorPlugin):
        async def save(self, response: StoqResponse) -> None:
            print(f'saving: {response}')


DecoratorPlugin
---------------

v2
^^

::

    from stoq import StoqResponse, DecoratorPlugin, DecoratorResponse


    class MyDecorator(DecoratorPlugin):
        def decorate(self, response: StoqResponse) -> DecoratorResponse:
            return DecoratorResponse


v3
^^

::

    from stoq import StoqResponse, DecoratorPlugin, DecoratorResponse


    class MyDecorator(DecoratorPlugin):
        async def decorate(self, response: StoqResponse) -> DecoratorResponse:
            return DecoratorResponse


DispatcherPlugin
----------------

v2
^^

::

    from stoq import Payload, RequestMeta, DispatcherPlugin, DispatcherResponse


    class MyDispatcher(DispatcherPlugin):
        def get_dispatches(
            self, payload: Payload, request_meta: RequestMeta
        ) -> DispatcherResponse:
            return DispatcherResponse()


v3
^^

::

    from stoq import Payload, Request, DispatcherPlugin, DispatcherResponse


    class MyDispatcher(DispatcherPlugin):
        async def get_dispatches(
            self, payload: Payload, request: Request
        ) -> DispatcherResponse:
            return DispatcherResponse()



ProviderPlugin
--------------

v2
^^

::

    from queue import Queue
    from stoq import Payload, RequestMeta, ProviderPlugin


    class MyProvider(ProviderPlugin):
        def ingest(self, queue: Queue) -> None:
            queue.put(Payload(b'This is my payload'))


v3
^^

::

    from asyncio import Queue
    from stoq import Payload, Request, ProviderPlugin


    class MyProvider(ProviderPlugin):
        async def ingest(self, queue: Queue) -> None:
            await queue.put(Payload(b'This is my payload'))


WorkerPlugin
------------

v2
^^

::

    from stoq import Payload, RequestMeta, WorkerPlugin, WorkerResponse


    class MyWorker(WorkerPlugin):
        def scan(self, payload: Payload, request_meta: RequestMeta) -> WorkerResponse:
            return WorkerResponse()


v3
^^

::

    from stoq import Payload, Request, WorkerPlugin, WorkerResponse


    class MyWorker(WorkerPlugin):
        async def scan(self, payload: Payload, request: Request) -> WorkerResponse:
            return WorkerResponse()



