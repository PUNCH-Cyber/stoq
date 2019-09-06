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

from abc import ABC
from configparser import ConfigParser
from typing import Dict, Optional


class BasePlugin(ABC):
    def __init__(self, config: ConfigParser, plugin_opts: Optional[Dict]) -> None:
        self.config = config
        self.plugin_opts = plugin_opts
        self._version_info = {}
        if config.has_option("Documentation", "Version"):
            self._version_info.update({"PluginVersion": config.get("Documentation", "Version")})

    def version_info(self):
        """
        version_info() method

        All plugins will inherit this method which will return the version information
        of the plugin.  Each plugin may overload this method to provide more information.
        A decorator plugin could be used to gather all version_info for all plugins that
        were run.

        For example:

        Adding the following code to the exif plugin would enhance the exif version information:

        def version_info(self):
            try:
                cmd = [self.bin_path, '-ver']
                output = run(cmd, stdout=PIPE)
                version = output.stdout.rstrip()
                self._version_info.update({'ExifToolVersion': version})
            except Exception as err:
                raise StoqPluginException(f'Failed gathering exiftool version: {err}')
            return self._version_info
        """
        return self._version_info