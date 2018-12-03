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
import importlib.util
import inspect
import logging
import os
from pkg_resources import parse_version
from typing import Dict, List, Optional, Set, Tuple, Sequence, Any

from .exceptions import StoqException
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
        self, plugin_dir_list: List[str], plugin_opts: Optional[Dict[str, Dict]] = None
    ) -> None:
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
                    config = configparser.ConfigParser()
                    try:
                        config.read(plugin_conf_path)
                        name = config.get('Core', 'Name')
                        module_name = config.get('Core', 'Module')
                    except Exception:
                        self.log.warning(
                            f'Error parsing config file: {plugin_conf_path}',
                            exc_info=True,
                        )
                        continue
                    module_path_pyc = os.path.join(root_path, module_name) + '.pyc'
                    module_path_py = os.path.join(root_path, module_name) + '.py'
                    if os.path.isfile(module_path_pyc):
                        self._plugin_name_to_info[name] = (module_path_pyc, config)
                    elif os.path.isfile(module_path_py):
                        self._plugin_name_to_info[name] = (module_path_py, config)
                    else:
                        self.log.warning(
                            f'Unable to find module at: {module_path_pyc} or {module_path_py}',
                            exc_info=True,
                        )
                        continue

    def load_plugin(self, name: str) -> BasePlugin:
        name = name.strip()
        if name in self._loaded_plugins:
            return self._loaded_plugins[name]
        module_path, config = self._plugin_name_to_info[name]
        if config.has_option('options', 'min_stoq_version'):
            min_stoq_version = config.get('options', 'min_stoq_version')
            # Placing this import at the top of this file causes a circular
            # import chain that causes stoq to crash on initialization
            from stoq import __version__

            if parse_version(__version__) < parse_version(min_stoq_version):
                self.log.warning(
                    f'Plugin {name} not compatible with this version of '
                    'stoQ. Unpredictable results may occur!'
                )
        spec = importlib.util.spec_from_file_location(
            config.get('Core', 'Module'), module_path
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
                f'No valid plugin classes found in the module for {name}'
            )
        if len(plugin_classes) > 1:
            raise StoqException(
                f'Multiple possible plugin classes found in the module for {name},'
                ' unable to distinguish which to use.'
            )
        _, plugin_class = plugin_classes[0]
        plugin = plugin_class(config, self._plugin_opts.get(name))
        self._loaded_plugins[name] = plugin
        return plugin

    def list_plugins(self) -> Dict[str, Dict[str, Sequence[Any]]]:
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
            with open(self._plugin_name_to_info[plugin][0]) as f:
                parsed_plugin = ast.parse(f.read())
            classes = [n for n in parsed_plugin.body if isinstance(n, ast.ClassDef)]
            plugin_classes = []
            for c in classes:
                for base in c.bases:
                    if base.id in valid_classes:  # pyre-ignore[16]
                        plugin_classes.append(
                            base.id.replace('Plugin', '')  # pyre-ignore[16]
                        )
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
