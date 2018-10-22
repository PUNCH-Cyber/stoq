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

import configparser
import glob
import os
import subprocess
import sys
from typing import Any, Dict

from .exceptions import StoqException


class StoqPluginInstaller:

    PIP_EXISTS_STR = "already exists. Specify --upgrade to force replacement."

    @staticmethod
    def install(plugin_dir: str, install_dir: str, upgrade: bool) -> None:
        plugin_dir = os.path.abspath(plugin_dir)
        install_dir = os.path.abspath(install_dir)
        if not os.path.isdir(plugin_dir):
            raise StoqException(f'Given plugin directory does not exist: {plugin_dir}')
        if not os.path.isdir(install_dir):
            raise StoqException(
                f'Given install directory does not exist: {install_dir}'
            )
        # Find the stoQ configuration file
        config_path_glob = '{}/*/*.stoq'.format(plugin_dir)
        config_path = glob.glob(config_path_glob)
        if len(config_path) == 0:
            raise StoqException(
                f'No config file found matching glob {config_path_glob}'
            )
        elif len(config_path) > 1:
            raise StoqException(
                'More than one config file found matching ' f'glob {config_path_glob}'
            )
        plugin_info = StoqPluginInstaller.parse_config(config_path[0])
        StoqPluginInstaller.save_plugin_info(plugin_info, plugin_dir)
        StoqPluginInstaller.setup_package(plugin_dir, install_dir, upgrade)

    @staticmethod
    def setup_package(plugin_dir: str, install_dir: str, upgrade: bool) -> None:
        cmd = [sys.executable, '-m', 'pip', 'install', plugin_dir, '-t', install_dir]
        if upgrade:
            cmd.append('--upgrade')

        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        if StoqPluginInstaller.PIP_EXISTS_STR.encode() in output:
            raise StoqException(
                'There is an existing version of this plugin '
                'already installed. You must specify "upgrade" '
                'to force replacement'
            )

        # TODO: Is it correct to do this install after the setup.py one?
        # requirements.txt contains specific library versions (or githubs),
        # whereas setup.py doesn't
        requirements = '{}/requirements.txt'.format(plugin_dir)
        if os.path.isfile(requirements):
            subprocess.check_call(
                [sys.executable, '-m', 'pip', 'install', '--quiet', '-r', requirements]
            )

    @staticmethod
    def parse_config(config_path: str) -> Dict[str, Any]:
        config = configparser.ConfigParser()
        config.read(config_path)
        plugin_name = config.get('Core', 'Name', fallback='')
        if not plugin_name:
            raise StoqException('Config file must contain a Name in the Core section')
        # We are going to use this to dynamically define data points in
        # setup.py
        plugin_info = {}
        plugin_info['NAME'] = plugin_name
        if config.get('Documentation', 'Author', fallback=''):
            plugin_info['AUTHOR'] = config['Documentation']['Author']
        if config.get('Documentation', 'Version', fallback=''):
            plugin_info['VERSION'] = config['Documentation']['Version']
        if config.get('Documentation', 'Website', fallback=''):
            plugin_info['WEBSITE'] = config['Documentation']['Website']
        if config.get('Documentation', 'Description', fallback=''):
            plugin_info['DESCRIPTION'] = config['Documentation']['Description']
        return plugin_info

    @staticmethod
    def save_plugin_info(plugin_info: Dict[str, Any], plugin_dir: str) -> None:
        # Let's create text files with the appropriate attributes so setup.py
        # can be more dynamic
        for option, value in plugin_info.items():
            with open(os.path.join(plugin_dir, option), 'w') as f:
                f.write(value)
