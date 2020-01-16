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
from typing import Dict, Optional

from stoq.helpers import StoqConfigParser


class BasePlugin(ABC):
    def __init__(self, config: StoqConfigParser) -> None:
        self.config = config
        self.plugin_name = config.get('Core', 'Name', fallback=self.__class__.__name__)
        self.__author__ = config.get('Documentation', 'Author', fallback='')
        self.__version__ = config.get('Documentation', 'Version', fallback='')
        self.__website__ = config.get('Documentation', 'Website', fallback='')
        self.__description__ = config.get('Documentation', 'Description', fallback='')
        self.log = logging.getLogger(f'stoq.{self.plugin_name}')
