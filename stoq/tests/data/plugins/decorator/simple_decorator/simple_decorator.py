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

from typing import Optional

from stoq.data_classes import StoqResponse, DecoratorResponse
from stoq.plugins import DecoratorPlugin


class SimpleDecorator(DecoratorPlugin):
    RAISE_EXCEPTION = False
    RETURN_ERRORS = False

    async def decorate(self, response: StoqResponse) -> Optional[DecoratorResponse]:
        if self.RAISE_EXCEPTION:
            raise Exception('Test exception please ignore')
        dr = DecoratorResponse({'simple_decoration': 123})
        if self.RETURN_ERRORS:
            dr.errors += ['Test error please ignore']
        return dr
