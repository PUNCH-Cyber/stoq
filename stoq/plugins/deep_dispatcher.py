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
    .. _deepdispatcher:

    Overview
    ========

    Deep Dispatcher plugins are similar to :ref:`dispatcher plugins <dispatcher>`, but there
    are some significant differences in their utility. One of the primary differences between
    them is deep dispatchers can be run 0 to N times per payload, where dispatcher plugins
    are only run once per payload. Additionally, deep dispatchers are run after dispatcher
    plugins and after the worker plugins has scanned the payload, but before continuing on
    to any additional payloads. Because deep dispatchers are handled after the worker plugins
    scan the payload, deep dispatchers are passed the original payload in addition to the
    scan results from the workers. This allows for additional and deeper dispatching based
    on not only the payload, but also any results from the workers. This concept can become
    somewhat complex, so it is recommended the reader review the
    :ref:`workflow section <workflow>` to better understand the full workflow.

    Deep Dispatcher plugins can be defined multiple ways. In these examples, we will use
    the ``test_deep_dispatcher`` deep dispatcher plugin.

    From ``stoq.cfg``::

        [core]
        deep_dispatchers = test_deep_dispatcher
        max_dispatch_passes = 3


    .. note:: Multiple plugins can be defined separated by a comma. Additionally, ``max_dispatch_passes``
              can be defined in ``stoq.cfg`` to ensure Deep Dispatchers do not end up in an endless loop.


    From the command line::

        $ stoq run -E test_deep_dispatcher [...]

    .. note:: Multiple plugins can be defined by simply adding the plugin name

    Or, when instantiating the ``Stoq()`` class:

        >>> import stoq
        >>> deep_dispatchers = ['test_deep_dispatcher']
        >>> s = Stoq(deep_dispatchers=deep_dispatchers, [...])


    Writing a plugin
    ================

    A `deep dispatcher` plugin must be a subclass of the ``DeepDispatcherPlugin`` class.

    As with any plugin, a :ref:`configuration file <pluginconfig>` must also exist
    and be properly configured.

    Example
    -------

    ::

        from typing import Optional

        from stoq.data_classes import Payload, DeepDispatcherResponse, RequestMeta
        from stoq.plugins import DeepDispatcherPlugin


        class ExampleDeepDispatcher(DeepDispatcherPlugin):
            def get_deep_dispatches(
                self, payload: Payload, request_meta: RequestMeta
            ) -> Optional[DeepDispatcherResponse]:
                dr = DeepDispatcherResponse()
                dr.errors.append('This is an example error and is completely optional')
                dr.meta['deep_key'] = 'Useful deep metadata info'
                return dr

    API
    ===

"""

from abc import abstractmethod
from typing import Optional

from stoq.data_classes import Payload, DeepDispatcherResponse, RequestMeta
from stoq.plugins import BasePlugin


class DeepDispatcherPlugin(BasePlugin):
    @abstractmethod
    def get_deep_dispatches(
        self, payload: Payload, request_meta: RequestMeta
    ) -> Optional[DeepDispatcherResponse]:
        pass
