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

import logging
from abc import ABC
from configparser import ConfigParser
from typing import Dict, Optional, Set


class BasePlugin(ABC):
    plugin_name: str
    __version__: str
    __website__: str = ''
    __description__: str = ''
    __author__: str = ''

    def __init__(self, config: ConfigParser, plugin_opts: Optional[Dict]) -> None:
        self.config = config
        self.plugin_opts = plugin_opts
        self.log = logging.getLogger(f'stoq.{self.plugin_name}')  # type: ignore
