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
    .. _connector:

    Overview
    ========

    The last plugin class is the Connector plugin. This plugin class allows for the
    saving or passing off of the final result. Once all other plugins have completed
    their tasks, the final result is sent to the loaded connector plugins for handling.
    For example, a connector plugin may save results to disk, ElasticSearch, or even
    pass them off to a queueing system such as RabbitMQ.

    Connector plugins can be defined multiple ways. In these examples, we will use the
    ``filedir`` connector plugin, allowing results to be saved to disk.

    From ``stoq.cfg``::

        [core]
        connectors = filedir

    .. note:: Multiple plugins can be defined separated by a comma.

    From the command line::

        $ stoq run -C filedir [...]

    .. note:: Multiple plugins can be defined by simply adding the plugin name

    Or, when instantiating the ``Stoq()`` class::

        >>> import stoq
        >>> connectors = ['filedir']
        >>> s = Stoq(connectors=connectors, [...])


    Writing a plugin
    ================

    A `connector` plugin must be a subclass of the ``ConnectorPlugin`` class.

    As with any plugin, a :ref:`configuration file <pluginconfig>` must also exist
    and be properly configured.

    Example
    -------

    ::

        from stoq.data_classes import StoqResponse
        from stoq.plugins import ConnectorPlugin

        class ExampleConnector(ConnectorPlugin):
            def save(self, response: StoqResponse) -> None:
                with open('/tmp/stoqresult.txt', 'w') as result:
                    result.write(response)

    API
    ===

"""

from abc import abstractmethod

from stoq.data_classes import StoqResponse
from stoq.plugins import BasePlugin


class ConnectorPlugin(BasePlugin):
    @abstractmethod
    def save(self, response: StoqResponse) -> None:
        pass
