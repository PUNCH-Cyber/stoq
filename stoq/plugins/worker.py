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
    .. _worker:

    Overview
    ========

    Worker plugins are the primary data producers within `stoQ`. These plugins
    allow for tasks such as scanning payloads with yara, hashing payloads, and
    even extracting indicators of compromise (IOC) from documents. Worker plugins
    can be defined in all scanning modes. Additionally worker plugins can be
    dynamically loaded using dispatching plugins. More information on dispatcher
    plugins can be found in the :ref:`dispatcher plugin section <dispatcher>`.

    Worker plugins can be defined multiple ways. In these examples, we will use
    the ``hash`` worker plugin.

    From the command line, worker plugins can be defined two different ways,
    depending on the use.

    If *only* the original payload must be scanned, then ``--start-dispatch``
    or ``-s`` command line argument may be used.::

        $ stoq scan -s hash [...]

    However, if the original payload and all subsequent payloads must be scanned,
    the ``--always-dispatch`` or ``-a`` command line argument may be used::

        $ stoq scan -a hash [...]

    .. note:: The difference between ``--start-dispatch`` and ``--always-dispatch``
              can be somewhat confusing. The primary difference between the two is
              that if a worker plugin extracts any payloads for further scanning,
              any extracted payloads will only be scanned by workers defined by
              ``--always-dispatch``. If ``--start-dispatch`` was used, the plugin
              defined will not be used to scan any extracted payloads.

    Or, when instantiating the ``Stoq()`` class::

        >>> import stoq
        >>> workers = ['yara']
        >>> s = Stoq(always_dispatch=workers, [...])

    Lastly, worker plugins can be defined by dispatcher plugins. As mentioned previously,
    more information on them can be found in the :ref:`dispatcher plugin section <dispatcher>`

    Writing a plugin
    ================

    A `worker` plugin must be a subclass of the ``WorkerPlugin`` class.

    As with any plugin, a :ref:`configuration file <pluginconfig>` must also exist
    and be properly configured.

    Example
    -------

    ::

        from typing import Dict, List, Optional

        from stoq.plugins import WorkerPlugin
        from stoq.helpers import StoqConfigParser
        from stoq.data_classes import (
            Payload,
            Request,
            WorkerResponse,
        )


        class ExampleWorker(WorkerPlugin):
            def __init__(self, config: StoqConfigParser) -> None:
                super().__init__(config)
                self.useful = config.getboolean('options', 'useful', fallback=False)

            async def scan(
                self, payload: Payload, request: Request
            ) -> Optional[WorkerResponse]:
                response = {'worker_results': f'useful: {self.useful}'}
                return WorkerResponse(response)

    Required Workers
    ----------------

    `required_workers` is a configuration option specific to `WorkerPlugin` class.
    The purpose of this option is to allow a user to define worker dependencies. For
    example, WorkerA must be run after WorkerB because WorkerA requires the results
    from WorkerB to run successfully. This configuration option may be set in the
    `.stoq` configuration file for the `WorkerPlugin`, or within the `__init__` 
    function.

    ::

        from typing import List, Optional

        from stoq.plugins import WorkerPlugin
        from stoq.helpers import StoqConfigParser
        from stoq.data_classes import (
            Payload,
            Request,
            WorkerResponse,
        )
        class WorkerA(WorkerPlugin):
            def __init__(self, config: StoqConfigParser) -> None:
                super().__init__(config)
                self.required_workers = config.getset(
                    'options', 'required_workers', fallback=set('WorkerB')
                )

            async def scan(
                self, payload: Payload, request: Request
            ) -> Optional[WorkerResponse]:
                is_bad: bool = payload.results.workers['WorkerB']['is_bad']
                response = {'worker_results': f'is_bad: {is_bad}'}
                return WorkerResponse(response)


    Extracted Payloads
    ------------------

    Worker plugins may also extract payloads, and return them to ``Stoq`` for
    further analysis. Each extracted payload that is returned will be inserted
    into the same workflow as the original payload.

    ::

        from typing import Dict, List, Optional

        from stoq.plugins import WorkerPlugin
        from stoq.helpers import StoqConfigParser
        from stoq.data_classes import (
            ExtractedPayload,
            Payload,
            PayloadMeta,
            RequestMeta,
            WorkerResponse,
        )


        class ExampleWorker(WorkerPlugin):
            def __init__(self, config: StoqConfigParser) -> None:
                super().__init__(config)
                self.useful = config.getboolean('options', 'useful', fallback=False)

            async def scan(
                self, payload: Payload, request: Request
            ) -> Optional[WorkerResponse]:
                extracted_payloads: List = []
                extracted_payloads.append(ExtractedPayload(b'Lorem ipsum'))
                response = {'worker_results': f'useful: {self.useful}'}
                return WorkerResponse(response, extracted=extracted_payloads)


    Dispatch To
    -----------

    In some cases it may be useful for a worker plugin to dicate which plugins an extracted
    payload is scanned with.

    ::

        >>> meta = PayloadMeta(dispatch_to='yara')
        >>> extracted_payload = ExtractedPayload(b'this is a payload with bad stuff', meta)


    Should Scan
    -----------

    Likewise, there may be cases where an extracted payload should not be scanned by workers,
    but should be added to the results or archived. Simply set `PayloadMeta.should_scan` to
    `False`.

    ::

        >>> meta = PayloadMeta(should_scan=False)
        >>> extracted_payload = ExtractedPayload(b'this is a payload', meta)


    API
    ===

"""
from typing import Dict, Optional
from abc import abstractmethod, ABC
from configparser import ConfigParser

from stoq.plugins import BasePlugin
from stoq.helpers import StoqConfigParser
from stoq.data_classes import Payload, Request, WorkerResponse


class WorkerPlugin(BasePlugin, ABC):
    def __init__(self, config: StoqConfigParser) -> None:
        super().__init__(config)
        self.required_workers = config.getset(
            'options', 'required_workers', fallback=set()
        )

    @abstractmethod
    async def scan(
        self, payload: Payload, request: Request
    ) -> Optional[WorkerResponse]:
        pass
