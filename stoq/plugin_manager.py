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
import inspect
import logging
import configparser
import importlib.util
from pkg_resources import parse_version, working_set
from typing import Dict, List, Optional, Tuple, Any, Union

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
        self._plugin_name_to_info: Dict[str, Tuple[str, configparser.ConfigParser]] = {}
        self._loaded_plugins: Dict[str, BasePlugin] = {}
        self._loaded_provider_plugins: Dict[str, ProviderPlugin] = {}
        self._loaded_worker_plugins: Dict[str, WorkerPlugin] = {}
        self._loaded_source_archiver_plugins: Dict[str, ArchiverPlugin] = {}
        self._loaded_dest_archiver_plugins: Dict[str, ArchiverPlugin] = {}
        self._loaded_dispatcher_plugins: Dict[str, DispatcherPlugin] = {}
        self._loaded_connector_plugins: List[ConnectorPlugin] = []
        self._loaded_decorator_plugins: Dict[str, DecoratorPlugin] = {}

        if not hasattr(self, 'log') or self.log is None:
            self.log: logging.Logger = logging.getLogger('stoq')

    @property
    def _collect_plugins(self) -> Dict[str, str]:
        return {
            p.project_name: p.version
            for p in working_set
            if p.project_name.startswith('stoq-plugin')
        }

    def load_plugin(self, plugin_name: str) -> BasePlugin:
        plugin_name = plugin_name.strip()
        if plugin_name in self._loaded_plugins:
            return self._loaded_plugins[plugin_name]
        if f'stoq-plugin-{plugin_name}' not in self._collect_plugins:
            raise StoqPluginNotFound(
                f'The plugin "{plugin_name}" is invalid or does not exist'
            )

        module = importlib.import_module(f'stoq_plugins.{plugin_name}.{plugin_name}')
        plugin_classes = inspect.getmembers(
            module,
            predicate=lambda mem: inspect.isclass(mem)
            and issubclass(mem, BasePlugin)
            and mem
            not in [
                ArchiverPlugin,
                BasePlugin,
                ProviderPlugin,
                WorkerPlugin,
                ConnectorPlugin,
                DispatcherPlugin,
                DecoratorPlugin,
            ]
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
        _, plugin_class = plugin_classes[0]
        # Plugin configuration order of precendence:
        # 1) plugin options provided at instantiation of `Stoq()`
        # 2) plugin configuration in `stoq.cfg`
        if isinstance(
            self._stoq_config, configparser.ConfigParser
        ) and self._stoq_config.has_section(plugin_name):
            plugin_config = dict(self._stoq_config.items(plugin_name))
        else:
            plugin_config = {}
        plugin_config.update(self._plugin_opts.get(plugin_name, {}))
        plugin = plugin_class(plugin_config, self._plugin_opts.get(plugin_name))
        if hasattr(plugin, '__min_stoq_version__'):
            # Placing this import at the top of this file causes a circular
            # import chain that causes stoq to crash on initialization
            from stoq import __version__

            if parse_version(__version__) < parse_version(plugin.__min_stoq_version__):
                self.log.warning(
                    f'Plugin {plugin_name} not compatible with this version of '
                    'stoQ. Unpredictable results may occur!'
                )
        self._loaded_plugins[plugin_name] = plugin
        return plugin

    def list_plugins(self) -> Dict[str, Dict[str, Any]]:
        import ast

        valid_classes = [
            'ArchiverPlugin',
            'BasePlugin',
            'ProviderPlugin',
            'WorkerPlugin',
            'ConnectorPlugin',
            'DispatcherPlugin',
            'DecoratorPlugin',
        ]
        plugins = {}
        for plugin in self._plugin_name_to_info.keys():
            plugin_classes = []
            try:
                with open(self._plugin_name_to_info[plugin][0]) as f:
                    parsed_plugin = ast.parse(f.read())
                classes = [
                    n
                    for n in parsed_plugin.body  # type: ignore
                    if isinstance(n, ast.ClassDef)
                ]
                for c in classes:
                    for base in c.bases:
                        if base.id in valid_classes:  # type: ignore
                            plugin_classes.append(
                                base.id.replace('Plugin', '')  # type: ignore
                            )
            except (UnicodeDecodeError, ValueError):
                plugin_classes = ['UNKNOWN']
            plugins[plugin] = {
                'classes': plugin_classes,
                'version': self._plugin_name_to_info[plugin][1].get(
                    'Documentation', 'version', fallback=''
                ),
                'description': self._plugin_name_to_info[plugin][1].get(
                    'Documentation', 'description', fallback=''
                ),
            }
        return plugins
