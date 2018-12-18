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

import os
import sys
import requests
import subprocess
from tempfile import NamedTemporaryFile

from .exceptions import StoqException


class StoqPluginInstaller:

    DEFAULT_REPO = 'git+https://github.com/PUNCH-Cyber/stoq-plugins-public.git'

    @staticmethod
    def install(
        plugin_path: str, install_dir: str, upgrade: bool, github: bool
    ) -> None:
        if github:
            if plugin_path.startswith('git+http'):
                pass
            elif plugin_path.startswith('stoq:'):
                plugin_name = plugin_path.split(':')[1]
                plugin_path = f'{StoqPluginInstaller.DEFAULT_REPO}#egg={plugin_name}&subdirectory={plugin_name}'
            else:
                raise StoqException('Invalid Github repository specified.')
        else:
            plugin_path = os.path.abspath(plugin_path)
            if not os.path.isdir(plugin_path):
                raise StoqException(
                    f'Given plugin directory does not exist: {plugin_path}'
                )
        install_dir = os.path.abspath(install_dir)
        if not os.path.isdir(install_dir):
            raise StoqException(
                f'Given install directory does not exist: {install_dir}'
            )
        StoqPluginInstaller.setup_package(plugin_path, install_dir, upgrade, github)

    @staticmethod
    def setup_package(
        plugin_path: str, install_dir: str, upgrade: bool, github: bool
    ) -> None:
        if github:
            url = (
                plugin_path.split('+')[1]
                .split('#')[0]
                .replace('.git', '')
                .replace('github.com', 'raw.githubusercontent.com')
                .replace('@', '/')
            )
            path = plugin_path.split('subdirectory=')[1]
            requirements = f'{url}/{path}/requirements.txt'
            with NamedTemporaryFile() as temp_file:
                response = requests.get(requirements)
                if response.status_code == 200:
                    temp_file.write(response.content)
                    temp_file.flush()
                    subprocess.check_call(
                        [
                            sys.executable,
                            '-m',
                            'pip',
                            'install',
                            '--quiet',
                            '-r',
                            temp_file.name,
                        ]
                    )
        else:
            requirements = f'{plugin_path}/requirements.txt'
            if os.path.isfile(requirements):
                subprocess.check_call(
                    [
                        sys.executable,
                        '-m',
                        'pip',
                        'install',
                        '--quiet',
                        '-r',
                        requirements,
                    ]
                )

        cmd = [sys.executable, '-m', 'pip', 'install', plugin_path, '-t', install_dir]
        if upgrade:
            cmd.append('--upgrade')
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as err:
            raise StoqException(err.output)
