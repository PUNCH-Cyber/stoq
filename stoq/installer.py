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
import pip
import sys
import subprocess

from .exceptions import StoqException

PIP_VER = float(sys.modules[pip.__package__].__version__)


class StoqPluginInstaller:

    DEFAULT_REPO = 'git+https://github.com/PUNCH-Cyber/stoq-plugins-public.git@v2'

    @staticmethod
    def install(plugin_path: str, install_dir: str, upgrade: bool, git: bool) -> None:
        if git:
            if plugin_path.startswith('git+http'):
                pass
            elif plugin_path.startswith('stoq:'):
                plugin_name = plugin_path.split(':')[1]
                plugin_path = f'{StoqPluginInstaller.DEFAULT_REPO}#egg={plugin_name}&subdirectory=v2/{plugin_name}'
            else:
                raise StoqException('Invalid git repository specified.')
            if PIP_VER <= 18.1:
                print(
                    'Warning: dependencies in requirements.txt will not be installed. Please upgraded pip to >= 18.2'
                )
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
        StoqPluginInstaller.setup_package(plugin_path, install_dir, upgrade, git)

    @staticmethod
    def setup_package(
        plugin_path: str, install_dir: str, upgrade: bool, git: bool
    ) -> None:
        if not git and PIP_VER <= 18.1:
            requirements = '{}/requirements.txt'.format(plugin_path)
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
        if PIP_VER >= 18.2:
            # Check to ensure pip isn't a broken version, if not, add the `-e` arg
            # https://github.com/pypa/pip/issues/4390
            cmd.insert(4, '-e')
        if upgrade:
            cmd.append('--upgrade')

        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as err:
            raise StoqException(err.output)
