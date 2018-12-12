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
    .. _archiver:

    Overview
    ========

    Archiver plugins are used for retrieving or saving scanned payloads. A payload
    can be anything from the initial payload scanned, or extracted payloads from
    previous scans. There are two types of archivers, :ref:`source <archiversource>`
    and :ref:`destination <archiverdest>`.

    .. _archiverdest:

    destination
    ^^^^^^^^^^^

    Archiver plugins used as a destination useful for saving payloads, be it the original
    scanned payload or any extracted payloads. Multiple destination archivers can be
    defined, allowing for a payload to be saved in either a single or multiple locations.
    The results from this plugin method may be used to subsequently load the payload again.

    Destination archiver plugins can be defined multiple ways. In these examples, we will
    use the ``filedir`` archiver plugin.

    From ``stoq.cfg``::

        [core]
        dest_archivers = filedir


    .. note:: Multiple plugins can be defined separated by a comma

    From the command line::

        $ stoq run -A filedir [...]


    .. note:: Multiple plugins can be defined by simply adding the plugin name

    Or, when instantiating the ``Stoq()`` class::

        >>> import stoq
        >>> dest_archivers = ['filedir']
        >>> s = Stoq(dest_archivers=dest_archivers, [...])


    .. _archiversource:

    source
    ^^^^^^

    Archiver plugins used as a source retrieve payloads for scanning. This is useful
    in several use cases, such as when using a provider plugin that isn't able to pass
    a payload to `stoQ`. For example, if the provider plugin being used leverages a
    queueing system, such as RabbitMQ, there may be problems placing multiple payloads
    onto a queue as it is inefficient, prone to failure, and does not scale well. With
    archiver plugins as a source, the queuing system can be leveraged by sending a
    message with a payload location, and the archiver plugin can then retrieve the
    payload for scanning. The `ArchiverResponse` results returned from
    `ArchiverPlugin.archive()` is used to load the payload.


    Source archiver plugins can be defined multiple ways. In these examples, we will
    use the ``filedir`` archiver plugin.

    From ``stoq.cfg``::

        [core]
        source_archivers = filedir


    .. note:: Multiple plugins can be defined separated by a comma

    From the command line::

        $ stoq run -S filedir [...]


    .. note:: Multiple plugins can be defined by simply adding the plugin name

    Or, when instantiating the ``Stoq()`` class::

        >>> import stoq
        >>> source_archivers = ['filedir']
        >>> s = Stoq(source_archivers=source_archivers, [...])


    .. _writingplugin:

    Writing a plugin
    ================


    Unlike most other `stoQ` plugins, `archiver` plugins have two core methods, of which at
    least one of the below is required.

        - archive
        - get


    The ``archive`` method is used to archive payloads that are passed to `stoQ` or extracted
    from other plugins. In order for a payload to be archived, that attribute ``should_archive``
    must be set to ``True`` in the payloads ``PayloadMeta`` object. If set to ``False``, the
    payload will not be archived.

    An `archiver` plugin must be a subclass of the ``ArchiverPlugin`` class.

    As with any plugin, a :ref:`configuration file <pluginconfig>` must also exist
    and be properly configured.


    Example
    ^^^^^^^
    ::

        from typing import Optional

        from stoq.plugins import ArchiverPlugin
        from stoq.data_classes import ArchiverResponse, Payload, RequestMeta, PayloadMeta


        class ExampleArchiver(ArchiverPlugin):
            def archive(
                self, payload: Payload, request_meta: RequestMeta
            ) -> Optional[ArchiverResponse]:
                with open('/tmp/archived_payload', 'wb) as out:
                    out.write(payload.content)
                ar = ArchiverResponse({'path': '/tmp/archive_payload'})
                return ar

            def get(self, task: ArchiverResponse) -> Optional[Payload]:
                with open(task.results['path'], 'rb') as infile:
                    return Payload(
                        infile.read(),
                        PayloadMeta(
                            extra_data={'path': task.results['path']}))


    .. note:: `ArchiverPlugin.archive()` returns an `ArchiverResponse` object, which contains metadata that is
              later used by `ArchiverPlugin.get()` to load the payload.

    API
    ===

"""

from abc import abstractmethod
from typing import Optional

from stoq.data_classes import ArchiverResponse, Payload, RequestMeta
from stoq.plugins import BasePlugin


class ArchiverPlugin(BasePlugin):
    def archive(
        self, payload: Payload, request_meta: RequestMeta
    ) -> Optional[ArchiverResponse]:
        """
        Archive payload

        :param payload: Payload object to archive
        :param request_meta: Originating request metadata

        :return: ArchiverResponse object. Results are used to retrieve payload.

        >>> from stoq import Stoq, Payload
        >>> payload = Payload(b'this is going to be saved')
        >>> s = Stoq()
        >>> archiver = s.load_plugin('filedir')
        >>> archiver.archive(payload)
        ... {'path': '/tmp/bad.exe'}

        """
        pass

    def get(self, task: ArchiverResponse) -> Optional[Payload]:
        """
        Retrieve payload for processing

        :param task: Task to be processed to load payload. Must contain `ArchiverResponse`
        results from `ArchiverPlugin.archive()`

        :return: Payload object for scanning

        >>> from stoq import Stoq
        >>> s = Stoq()
        >>> archiver = s.load_plugin('filedir')
        >>> task = ArchiverResponse(results={'path': '/tmp/bad.exe'})
        >>> payload = archiver.get(task)

        """
        pass
