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
    .. _decorator:

    Overview
    ========

    Decorator plugins are the last plugins run just before saving results. This
    plugin class allows for the analysis of all results from each plugin, the
    original payload, and any extracted payloads. Multiple decorator plugins can
    be loaded, but each plugin is only passed the results once. Decorator plugins
    are extremely useful when post-processing is required of the collective
    results from the entire stoQ workflow.

    Decorator plugins can be defined multiple ways. In these examples, we will use
    the ``test_decorator`` decorator plugin.

    From ``stoq.cfg``::

        [core]
        decorators = test_decorator

    .. note:: Multiple plugins can be defined separated by a comma.

    From the command line::

        $ stoq run -D yara [...]

    .. note:: Multiple plugins can be defined by simply adding the plugin name

    Or, when instantiating the ``Stoq()`` class::

        >>> import stoq
        >>> decorators = ['test_decorator']
        >>> s = Stoq(decorators=decorators, [...])


    Writing a plugin
    ================

    A `decorator` plugin must be a subclass of the ``DecoratorPlugin`` class. Results
    from a decorator are appended to the final ``StoqResponse`` object.

    As with any plugin, a :ref:`configuration file <pluginconfig>` must also exist
    and be properly configured.

    Example
    -------

    ::

        from typing import Optional

        from stoq.data_classes import StoqResponse, DecoratorResponse
        from stoq.plugins import DecoratorPlugin


        class ExampleDecorator(DecoratorPlugin):

            def decorate(self, response: StoqResponse) -> Optional[DecoratorResponse]:
                do_more = False
                if 'yara' in response.results[0].plugins_run:
                    do_more = True
                dr = DecoratorResponse({'do_more': do_more})
                return dr

    API
    ===

"""

from abc import abstractmethod
from typing import Optional

from stoq.data_classes import StoqResponse, DecoratorResponse
from stoq.plugins import BasePlugin


class DecoratorPlugin(BasePlugin):
    @abstractmethod
    def decorate(self, response: StoqResponse) -> Optional[DecoratorResponse]:
        pass
