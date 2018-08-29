#!/usr/bin/env python3

import configparser
import importlib.util
import inspect
import logging
import os
from typing import Dict, List, Optional, Set, Tuple

from .exceptions import StoqException
from stoq.plugins import (ArchiverPlugin, BasePlugin, ProviderPlugin,
                          WorkerPlugin, ConnectorPlugin, DispatcherPlugin,
                          DecoratorPlugin)


class StoqPluginManager():
    def __init__(self,
                 plugin_dir_list: List[str],
                 plugin_opts: Optional[Dict[str, Dict]] = None) -> None:
        self._plugin_opts = {} if plugin_opts is None else plugin_opts
        self._plugin_name_to_info: Dict[str, Tuple[
            str, configparser.ConfigParser]] = {}
        self._loaded_plugins: Dict[str, BasePlugin] = {}
        self._loaded_provider_plugins: Dict[str, ProviderPlugin] = {}
        self._loaded_worker_plugins: Dict[str, WorkerPlugin] = {}
        self._loaded_archiver_plugins: Dict[str, ArchiverPlugin] = {}
        self._loaded_dispatcher_plugins: Dict[str, DispatcherPlugin] = {}
        self._loaded_connector_plugins: List[ConnectorPlugin] = []
        self._loaded_decorator_plugins: List[DecoratorPlugin] = {}

        if not hasattr(self, 'log') or self.log is None:
            self.log = logging.getLogger('stoq')
        self._collect_plugins(plugin_dir_list)

    def _collect_plugins(self, plugin_dir_list: List[str]) -> None:
        for plugin_dir in plugin_dir_list:
            abs_plugin_dir = os.path.abspath(plugin_dir.strip())
            if not os.path.isdir(abs_plugin_dir):
                self.log.warning('Invalid plugin directory specified, '
                                 f'skipping: {abs_plugin_dir}')
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
                            exc_info=True)
                        continue
                    module_path = os.path.join(root_path, module_name) + '.py'
                    if not os.path.isfile(module_path):
                        self.log.warning(
                            f'Unable to find module at: {module_path}',
                            exc_info=True)
                        continue
                    self._plugin_name_to_info[name] = (module_path, config)

    def add_plugin(self, name: str, plugin: BasePlugin) -> None:
        name = name.strip()
        self._loaded_plugins[name] = plugin
        if isinstance(plugin, ProviderPlugin):
            self._loaded_provider_plugins[name] = plugin
        elif isinstance(plugin, WorkerPlugin):
            self._loaded_worker_plugins[name] = plugin
        elif isinstance(plugin, ArchiverPlugin):
            self._loaded_archiver_plugins[name] = plugin
        elif isinstance(plugin, DispatcherPlugin):
            self._loaded_dispatcher_plugins[name] = plugin
        elif isinstance(plugin, ConnectorPlugin):
            self._loaded_connector_plugins.append(plugin)
        elif isinstance(plugin, DecoratorPlugin):
            self._loaded_decorator_plugins[name] = plugin
        else:
            raise StoqException(f'The provided plugin {name} is not a child '
                                'of any of the supported plugin classes')

    def load_plugin(self, name: str) -> BasePlugin:
        name = name.strip()
        if name in self._loaded_plugins:
            return self._loaded_plugins[name]
        module_path, config = self._plugin_name_to_info[name]
        spec = importlib.util.spec_from_file_location(
            config.get('Core', 'Module'), module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        plugin_classes = inspect.getmembers(
            module,
            predicate=
            lambda mem: inspect.isclass(mem) and issubclass(mem, BasePlugin) and not inspect.isabstract(mem)
        )
        if len(plugin_classes) == 0:
            raise StoqException('No valid plugin classes found in the module '
                                f'for {name}')
        _, plugin_class = plugin_classes[0]
        plugin = plugin_class(config, self._plugin_opts.get(name))
        self.add_plugin(name, plugin)
        return plugin

    def list_plugins(self) -> Set[str]:
        return set().union(self._plugin_name_to_info.keys(),
                           self._loaded_plugins.keys())
