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
    .. _provider:

    Overview
    ========

    Provider plugins are designed for passing multiple payloads, or locations of payloads,
    to `stoQ`. They allow for multiple payloads to be run against `stoQ` until the source
    is exhausted. As such, they are useful for monitoring directories for new files,
    subscribing to a queue (i.e., RabbitMQ, Google PubSub, ZeroMQ), or scanning entire
    directories recursively. Multiple provider plugins can be provided allowing for even more
    flexibility. Provider plugins may either send a payload to `stoQ` for scanning, or send a
    message that an :ref:`Archiver plugin <archiver>` is able to handle for loading of a
    payload.

    .. note:: Provider plugins are not available when using `scan mode`. This is due to
              `scan mode` being designed for individual scans, not multiple payloads.

    Provider plugins can be defined multiple ways. In these examples, we will use the
    ``dirmon`` provider plugin.

    From ``stoq.cfg``::

        [core]
        providers = dirmon


    .. note:: Multiple plugins can be defined separated by a comma

    From the command line::

        $ stoq run -P dirmon [...]

    .. note:: Multiple plugins can be defined by simply adding the plugin name

    Or, when instantiating the ``Stoq()`` class::

        >>> import stoq
        >>> providers = ['dirmon']
        >>> s = Stoq(providers=providers, [...])


    Writing a plugin
    ================

    `Provider plugins` add either ``Payload`` objects to the `stoQ` queue, or a ``str``.
    If a ``Payload`` object is added, `stoQ` will begin processing the payload. However,
    if a ``str`` is added, `stoQ` will pass it to ``Archiver`` plugins that were
    loaded when ``Stoq`` was instantiated with the ``source_archivers`` argument.

    A `provider` plugin must be a subclass of the ``ProviderPlugin`` class.

    As with any plugin, a :ref:`configuration file <pluginconfig>` must also exist
    and be properly configured.

    Example
    -------

    ::

        from queue import Queue

        from stoq import Payload
        from stoq.plugins import ProviderPlugin


        class ExampleProvider(ProviderPlugin):
            def ingest(self, queue: Queue) -> None:
                queue.put(Payload(b'This is a payload'))

    API
    ===

"""

from abc import abstractmethod
from queue import Queue

from stoq.plugins import BasePlugin


class ProviderPlugin(BasePlugin):
    @abstractmethod
    def ingest(self, queue: Queue) -> None:
        pass
