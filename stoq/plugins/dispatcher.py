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
    .. _dispatcher:

    Overview
    ========

    Dispatcher plugins allow for dynamic routing and loading of worker plugins. These
    plugins are extremely powerful in that they allow for an extremely flexible scanning
    flow based on characteristics of the payload itself. For instance, routing a payload
    to a worker plugin for scanning can be done by yara signatures, TRiD results, simple
    regex matching, or just about anything else. Each loaded dispatcher plugin is run
    once per payload.

    Dispatcher plugins can be defined multiple ways. In these examples, we will use the
    ``yara`` dispatcher plugin.

    From ``stoq.cfg``::

        [core]
        dispatchers = yara

    .. note:: Multiple plugins can be defined separated by a comma

    From the command line::

        $ stoq run -R yara [...]

    .. note:: Multiple plugins can be defined by simply adding the plugin name

    Or, when instantiating the ``Stoq()`` class:

        >>> import stoq
        >>> dispatchers = ['yara']
        >>> s = Stoq(dispatchers=dispatchers, [...])

    Now, let's write a simple yara rule to pass a payload to the ``pecarve`` plugin if a
    DOS stub is found::

        rule exe_file
        {
            meta:
                plugin = "pecarve"
                save = "True"
            strings:
                $MZ = "MZ"
                $ZM = "ZM"
                $dos_stub = "This program cannot be run in DOS mode"
                $win32_stub = "This program must be run under Win32"
            condition:
                ($MZ or $ZM) and ($dos_stub or $win32_stub)
        }


    In this case, if this yara signature hits on a payload, the payload will be passed to
    the ``pecarve`` plugin, which will then extract the PE file as a payload, and send it
    to `stoQ` for continued scanning. Additionally, because ``save = "True"``, the extracted
    payload will also be saved if a :ref:`Destination Archiver <archiverdest>` plugin is
    defined.


    Writing a plugin
    ================

    A `dispatcher` plugin must be a subclass of the ``DispatcherPlugin`` class.

    As with any plugin, a :ref:`configuration file <pluginconfig>` must also exist
    and be properly configured.

    Example
    -------
    ::

        from typing import Optional
        from stoq.data_classes import Payload, DispatcherResponse, RequestMeta
        from stoq.plugins import DispatcherPlugin


        class ExampleDispatcher(DispatcherPlugin):
            def get_dispatches(
                self, payload: Payload, request_meta: RequestMeta
            ) -> Optional[DispatcherResponse]:
                dr = DispatcherResponse()
                dr.errors.append('This is an example error and is completely optional')
                dr.meta['example_key'] = 'Useful metadata info'
                return dr


    API
    ===

"""

from abc import abstractmethod
from typing import Optional

from stoq.data_classes import Payload, DispatcherResponse, RequestMeta
from stoq.plugins import BasePlugin


class DispatcherPlugin(BasePlugin):
    @abstractmethod
    def get_dispatches(
        self, payload: Payload, request_meta: RequestMeta
    ) -> Optional[DispatcherResponse]:
        pass
