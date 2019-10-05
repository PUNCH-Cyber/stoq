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
import abc
import sys
import inspect
import logging
import pkgutil
import configparser
import importlib.util
from pkg_resources import parse_version, working_set
from typing import Dict, List, Optional, Tuple, Any, Union, Set

import stoq.helpers as helpers
from stoq.data_classes import Error
from .exceptions import StoqException, StoqPluginNotFound
from stoq.plugins import (
    ArchiverPlugin,
    BasePlugin,
    ProviderPlugin,
    WorkerPlugin,
    ConnectorPlugin,
    DispatcherPlugin,
    DecoratorPlugin,
)


class StoqPluginManager:
    def __init__(
        self,
        plugin_dir_list: List[str],
        plugin_opts: Optional[Dict[str, Dict]] = None,
        stoq_config: Optional[configparser.ConfigParser] = None,
    ) -> None:
        self._stoq_config = stoq_config
        self._plugin_opts = {} if plugin_opts is None else plugin_opts
        self._available_plugins: Dict[str, str] = {}
        self._loaded_plugins: Dict[str, BasePlugin] = {}
        self._loaded_provider_plugins: Dict[str, ProviderPlugin] = {}
        self._loaded_worker_plugins: Dict[str, WorkerPlugin] = {}
        self._loaded_source_archiver_plugins: Dict[str, ArchiverPlugin] = {}
        self._loaded_dest_archiver_plugins: Dict[str, ArchiverPlugin] = {}
        self._loaded_dispatcher_plugins: Dict[str, DispatcherPlugin] = {}
        self._loaded_connector_plugins: List[ConnectorPlugin] = []
        self._loaded_decorator_plugins: Dict[str, DecoratorPlugin] = {}

        self.valid_plugin_classes = [
            ArchiverPlugin,
            ProviderPlugin,
            WorkerPlugin,
            ConnectorPlugin,
            DispatcherPlugin,
            DecoratorPlugin,
        ]

        if not hasattr(self, 'log') or self.log is None:
            self.log: logging.Logger = logging.getLogger('stoq')

        for plugin_path in plugin_dir_list:
            plugin_path = os.path.abspath(plugin_path)
            if os.path.isdir(plugin_path):
                if plugin_path not in sys.path:
                    self.log.debug(f'Adding {plugin_path} to sys.path')
                    sys.path.insert(0, plugin_path)
            else:
                self.log.warning(
                    f'{plugin_path} is an invalid directory, not adding it to path'
                )
        self._collect_plugins()

    def load_plugin(self, plugin_name: str) -> BasePlugin:
        plugin_name = plugin_name.strip()
        if plugin_name in self._loaded_plugins:
            return self._loaded_plugins[plugin_name]
        if plugin_name not in self._available_plugins:
            raise StoqPluginNotFound(
                f'The plugin "{plugin_name}" is invalid or does not exist'
            )

        plugin_class = self._import_plugin(plugin_name)

        # Plugin configuration order of precendence:
        # 1) plugin options provided at instantiation of `Stoq()`
        # 2) plugin configuration in `stoq.cfg`
        if isinstance(
            self._stoq_config, configparser.ConfigParser
        ) and self._stoq_config.has_section(plugin_name):
            plugin_opts = dict(self._stoq_config.items(plugin_name))
        else:
            plugin_opts = {}
        plugin_opts.update(self._plugin_opts.get(plugin_name, {}))
        plugin_config = configparser.ConfigParser()
        plugin_config.read_dict({'options': plugin_opts})
        plugin = plugin_class(plugin_config, self._plugin_opts.get(plugin_name))
        if hasattr(plugin, '__min_stoq_version__'):
            # Placing this import at the top of this file causes a circular
            # import chain that causes stoq to crash on initialization
            from stoq import __version__

            if parse_version(__version__) < parse_version(
                str(plugin.__min_stoq_version__)
            ):
                self.log.warning(
                    f'Plugin {plugin_name} not compatible with this version of '
                    'stoQ. Unpredictable results may occur!'
                )
        self._loaded_plugins[plugin_name] = plugin
        return plugin

    def list_plugins(self) -> Dict[str, Dict[str, Union[str, Set[str]]]]:
        installed_plugins: Dict[str, Dict[str, Union[str, Set[str]]]] = {}
        for plugin_name in self._available_plugins.keys():
            plugin_classes: Set[str] = set()
            plugin = self._import_plugin(plugin_name)
            plugin_classes = set(
                [
                    p.__module__.split('.')[-1]
                    for p in self.valid_plugin_classes
                    if issubclass(plugin, p)
                ]
            )
            installed_plugins[plugin_name] = {
                'classes': plugin_classes,
                'version': plugin.__version__,  # type: ignore
                'description': plugin.__description__,  # type: ignore
            }
        return installed_plugins

    def _import_plugin(self, plugin_name: str) -> abc.ABCMeta:
        module = importlib.import_module(self._available_plugins[plugin_name])
        plugin_classes = inspect.getmembers(
            module,
            predicate=lambda mem: inspect.isclass(mem)
            and issubclass(mem, BasePlugin)
            and mem not in self.valid_plugin_classes
            and not inspect.isabstract(mem),
        )
        if len(plugin_classes) == 0:
            raise StoqException(
                f'No valid plugin classes found in the module for {plugin_name}'
            )
        if len(plugin_classes) > 1:
            raise StoqException(
                f'Multiple possible plugin classes found in the module for {plugin_name},'
                ' unable to distinguish which to use.'
            )
        return plugin_classes[0][1]

    def onerror(self, name):
        if name.startswith('stoq_plugins.'):
            self.log.warning(f'Error importing {name}:', exc_info=True)

    def _collect_plugins(self) -> None:
        self._available_plugins = {
            p.name.split('.')[-1]: p.name
            for p in pkgutil.walk_packages(onerror=self.onerror)
            if p.name.startswith('stoq_plugins') and not p.ispkg
        }
