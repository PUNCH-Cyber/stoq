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
from pkg_resources import parse_version
from typing import Dict, List, Optional, Tuple, Any

from .exceptions import StoqException, StoqPluginNotFound
from stoq.plugins import (
    ArchiverPlugin,
    BasePlugin,
    ProviderPlugin,
    WorkerPlugin,
    ConnectorPlugin,
    DispatcherPlugin,
    DeepDispatcherPlugin,
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
        self._loaded_deep_dispatcher_plugins: Dict[str, DeepDispatcherPlugin] = {}
        self._loaded_connector_plugins: List[ConnectorPlugin] = []
        self._loaded_decorator_plugins: Dict[str, DecoratorPlugin] = {}

        if not hasattr(self, 'log') or self.log is None:
            self.log: logging.Logger = logging.getLogger('stoq')
        self._collect_plugins(plugin_dir_list)

    def _collect_plugins(self, plugin_dir_list: List[str]) -> None:
        for plugin_dir in plugin_dir_list:
            abs_plugin_dir = os.path.abspath(plugin_dir.strip())
            if not os.path.isdir(abs_plugin_dir):
                self.log.warning(
                    f'Invalid plugin directory specified, skipping: {abs_plugin_dir}'
                )
                continue
            for root_path, _, files in os.walk(abs_plugin_dir):
                for file in files:
                    if not file.endswith('.stoq'):
                        continue
                    plugin_conf_path = os.path.join(root_path, file)
                    plugin_config = configparser.ConfigParser()
                    try:
                        plugin_config.read(plugin_conf_path)
                        plugin_name = plugin_config.get('Core', 'Name')
                        module_name = plugin_config.get('Core', 'Module')
                    except Exception:
                        self.log.warning(
                            f'Error parsing config file: {plugin_conf_path}',
                            exc_info=True,
                        )
                        continue
                    module_path_pyc = os.path.join(root_path, module_name) + '.pyc'
                    module_path_py = os.path.join(root_path, module_name) + '.py'
                    if os.path.isfile(module_path_pyc):
                        self._plugin_name_to_info[plugin_name] = (
                            module_path_pyc,
                            plugin_config,
                        )
                    elif os.path.isfile(module_path_py):
                        self._plugin_name_to_info[plugin_name] = (
                            module_path_py,
                            plugin_config,
                        )
                    else:
                        self.log.warning(
                            f'Unable to find module at: {module_path_pyc} or {module_path_py}',
                            exc_info=True,
                        )
                        continue

    def load_plugin(self, plugin_name: str) -> BasePlugin:
        plugin_name = plugin_name.strip()
        if plugin_name in self._loaded_plugins:
            return self._loaded_plugins[plugin_name]
        if plugin_name not in self._plugin_name_to_info:
            raise StoqPluginNotFound(
                f'The plugin "{plugin_name}" is invalid or does not exist in your plugin path'
            )
        module_path, plugin_config = self._plugin_name_to_info[plugin_name]
        if plugin_config.has_option('options', 'min_stoq_version'):
            min_stoq_version = plugin_config.get('options', 'min_stoq_version')
            # Placing this import at the top of this file causes a circular
            # import chain that causes stoq to crash on initialization
            from stoq import __version__

            if parse_version(__version__) < parse_version(min_stoq_version):
                self.log.warning(
                    f'Plugin {plugin_name} not compatible with this version of '
                    'stoQ. Unpredictable results may occur!'
                )
        spec = importlib.util.spec_from_file_location(
            plugin_config.get('Core', 'Module'), module_path
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # pyre-ignore
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
                DeepDispatcherPlugin,
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
        # 3) `plugin_name.stoq`
        if isinstance(
            self._stoq_config, configparser.ConfigParser
        ) and self._stoq_config.has_section(plugin_name):
            if not plugin_config.has_section('options'):
                plugin_config.add_section('options')
            for opt in self._stoq_config.options(plugin_name):
                plugin_config['options'][opt] = self._stoq_config.get(plugin_name, opt)
        if self._plugin_opts.get(plugin_name):
            plugin_config.read_dict({'options': self._plugin_opts.get(plugin_name)})
        plugin = plugin_class(plugin_config, self._plugin_opts.get(plugin_name))
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
            'DeepDispatcherPlugin',
            'DecoratorPlugin',
        ]
        plugins = {}
        for plugin in self._plugin_name_to_info.keys():
            plugin_classes = []
            try:
                with open(self._plugin_name_to_info[plugin][0]) as f:
                    parsed_plugin = ast.parse(f.read())
                classes = [n for n in parsed_plugin.body if isinstance(n, ast.ClassDef)]
                for c in classes:
                    for base in c.bases:
                        if base.id in valid_classes:  # pyre-ignore[16]
                            plugin_classes.append(
                                base.id.replace('Plugin', '')  # pyre-ignore[16]
                            )
            except (UnicodeDecodeError, ValueError):
                plugin_classes = ['UNKNOWN']
            plugins[plugin] = {
                'classes': plugin_classes,
                'version': self._plugin_name_to_info[plugin][1].get(
                    'Documentation', 'version'
                ),
                'description': self._plugin_name_to_info[plugin][1].get(
                    'Documentation', 'description'
                ),
            }
        return plugins
