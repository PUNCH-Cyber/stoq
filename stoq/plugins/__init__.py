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

"""

Overview
========

*StoqPluginManager()* is the primary class that controls all aspects of
plugin management to include initialization, loading, listing, and unloading.
This class is instantiated within the *Stoq()* class. This should not be
instantiated outside of |stoQ| as it relies on objects within *Stoq()* to
function properly.

.. note:: Full plugin development documentation can be found at
          :doc:`PluginDevelopment`.

Examples
========

Instantiate Stoq::

    from stoq.core import Stoq
    stoq = Stoq()

Listing all available plugins::

    stoq.list_plugins()

Once Stoq() is initialized, we can load a worker. The worker should always be
instantiated first, then any additional plugins may be loaded through the
worker plugin itself. The plugins will be instantiated within a dict in the
worker plugin class. For example, a |stoQ| connector plugin may be accessed
from it's plural name (connectors) within the worker object by calling
``worker.connectors`` or a reader plugin may be called with
``worker.readers``::

    worker = stoq.load_plugin("yara", "worker")
    worker.load_connector("file")
    payload = worker.connectors['file'].get_file(path="/tmp/bad.exe")
    results = worker.scan(payload)

We may also retrieve a payload from a connector, such as MongoDB::

    worker.load_connector("mongodb")
    file_hash = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    payload = worker.connectors['mongodb'].get_file(sha1=file_hash)
    results = worker.scan(payload)

.. note:: Only certain connector plugins support ``.get_file(**kwargs)``. Refer
          to the plugin to determine if it is supported or not.

Now that we have results, we can load our connector to save the results::

   worker.connectors['mongodb'].save(results)

We may also save a file via the connector. In this example, we will save a
payload to with some additional attributes to GridFS::

    payload_attributes = {}
    payload_attributes['md5'] = "d41d8cd98f00b204e9800998ecf8427e"
    payload_attributes['sha1'] = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    payload_attributes['sha256'] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    worker.connectors['mongodb'].save(payload, archive=True, payload_attributes)

.. note:: ``save()`` accepts ``**kwargs``, so one may pass any attribute that
          is needed to it. GridFS will automatically calculate the payload size
          and datetime uploaded.

API
===
"""

import os
import re
import sys
import configparser
import importlib.util
import multiprocessing

from stoq.plugins.worker import StoqWorkerPlugin
from stoq.plugins.connector import StoqConnectorPlugin
from stoq.plugins.reader import StoqReaderPlugin
from stoq.plugins.source import StoqSourcePlugin
from stoq.plugins.extractor import StoqExtractorPlugin
from stoq.plugins.carver import StoqCarverPlugin
from stoq.plugins.decoder import StoqDecoderPlugin
from stoq.plugins.decorator import StoqDecoratorPlugin


class StoqPluginManager:
    """

    stoQ Plugin Manager Class

    """

    # Define the plugin categories and the associated class.
    # If we need to add a new plugin category, it must be done here.
    plugin_categories = {
        "worker": StoqWorkerPlugin,
        "connector": StoqConnectorPlugin,
        "reader": StoqReaderPlugin,
        "source": StoqSourcePlugin,
        "extractor": StoqExtractorPlugin,
        "carver": StoqCarverPlugin,
        "decoder": StoqDecoderPlugin,
        "decorator": StoqDecoratorPlugin
        }

    def __init__(self):
        self.plugin_extension = ".stoq"
        self.collect_plugins()

    @property
    def __plugindict__(self):
        """

        Create a dict of plugin class name and the plugin category

        """
        plugins = {}
        for category, category_class in self.plugin_categories.items():
            plugins[category_class.__name__] = category

        return plugins

    def collect_plugins(self):
        """
        Find all stoQ plugins and their configuration file

        """

        self.__collected_plugins__ = {}

        for plugin_dir_candidate in self.plugin_dir_list:
            abs_plugin_path = os.path.abspath(plugin_dir_candidate.strip())
            if not os.path.isdir(abs_plugin_path):
                self.log.info(
                    "Invalid plugin directory specified, skipping: {}".format(
                        abs_plugin_path))
                return

            for root_path, _, files in os.walk(abs_plugin_path):
                for plg in files:
                    if plg.endswith(self.plugin_extension):
                        try:
                            plugin_path = "{}/{}".format(root_path, plg)
                            config = configparser.ConfigParser()
                            config.read(plugin_path)
                            name = config.get("Core", "Name")
                            module = config.get("Core", "Module")
                            module_path = "{}/{}.py".format(root_path, module)
                            if os.path.isfile(module_path):
                                # open each module file and detect the category of plugin
                                with open(module_path, "r", encoding="utf-8") as src:
                                    cat = re.search(r'(?<=from stoq\.plugins import )(.+)',
                                                    src.read()).group()
                                    category = self.__plugindict__.get(cat, False)

                                config["Core"]["Category"] = category
                                config["Core"]["Module"] = module_path
                                config["Core"]["Root"] = plugin_dir_candidate
                                config["Core"]["Config"] = plugin_path
                                self.__collected_plugins__[name] = config
                            else:
                                self.log.warning("Found {} but no module {}, skipping".format(plugin_path, module_path))
                        except:
                            self.log.error("Error parsing config file: {}".format(plugin_path))

    @property
    def get_categories(self):
        """
        Create list of plugin categories available

        """

        return self.plugin_categories.keys()

    def get_plugins_of_category(self, category):
        """
        Lists plugin name of a specific category

        :param str category: Category to discover plugins in

        :returns: A tuple of discovered plugins
        :rtype: tuple

        """

        for _, config in self.__collected_plugins__.items():
            if config.get("Core", "Category") == category:
                yield (config.get("Core", "Name"),
                       config.get("Documentation", "Version"),
                       config.get("Documentation", "Description")
                       )

    def get_plugin(self, name, category):
        """
        Initializes a plugin within a specific category

        :param str name: Name of plugin to get
        :param str category: Category of the named plugin

        :returns: plugin object
        :rtype: object

        """

        # Make sure we clean up argv so argument parsing of plugins
        # doesn't cause issues when loading multiple worker plugins
        if self.worker and self.argv:
            self.argv = []

        if category not in self.plugin_categories:
            self.log.error("Invalid plugin category {}".format(category))
            return False

        info = self.__collected_plugins__.get(name)

        if not info:
            self.log.warning("No plugin available with the name {}".format(name))
            return False

        path = info.get("Core", "Module")
        if not path:
            self.log.error("No module found for {}".format(name))
            return False

        module_name = os.path.splitext(path)[0]

        try:
            spec = importlib.util.spec_from_file_location(module_name, path)
            # Because module_from_spec wasn't introduced until python 3.5, we
            # are going to check for it first. Let's hope this method doesn't
            # get deprecated also...
            if hasattr(importlib.util, 'module_from_spec'):
                plugin = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(plugin)
            else:
                # Looks like we are at python 3.4, let's do it that way instead
                plugin = spec.loader.load_module()

            # Since the class we want to load for the plugin is a subclass
            # of a plugin category, we are going to iterate over all classes
            # in the module, and find the first one that is a subclass of
            # plugin type we are looking for.
            for plugin_object in dir(plugin):
                try:
                    if issubclass(getattr(plugin, plugin_object), self.plugin_categories[category]):
                        if self.plugin_categories[category].__name__ is not plugin_object:
                            loaded_plugin = getattr(plugin, plugin_object)
                            loaded_plugin.details = info
                            return loaded_plugin()
                except TypeError:
                    pass
        except Exception:
            self.log.error("Unable to load plugin", exc_info=True)
            return False

        return False

    def load_plugin(self, name, category):
        """
        Load the desired plugin

        :param str name: Plugin name to be loaded
        :param str category: The category of plugin to be loaded

        :returns: The loaded plugin object
        :rtype: object

        """

        if not name or not category:
            self.log.error("Attempted to load a plugin, but a name or category was not provided")
            return None

        # Initialize our plugin
        self.log.debug("Attempting to load plugin {}:{}".format(category, name))
        plugin = self.get_plugin(name, category)

        if not plugin:
            self.log.warning("Plugin {}:{} failed to load".format(category, name))
            return False

        for sect in plugin.details.sections():
            for opt in plugin.details.options(sect):
                # define each configuration option as an object within
                # plugin class.
                # Note: In order to reduce logic, we attempt to load
                # the option as a boolean. By default, this will raise
                # an error which in turn will cause us to load it as
                # a string.
                try:
                    setattr(plugin, opt,
                            plugin.details.getboolean(sect, opt))
                except ValueError:
                    value = plugin.details.get(sect, opt)
                    if opt.endswith("_list"):
                        # If our option ends with a list, let's turn it
                        # into one
                        # Example:
                        # worker_list = this, is, a, list
                        # Becomes:
                        # worker.worker_list = ['this', 'is', 'a', 'list']
                        value = [i.strip() for i in value.split(",")]
                    elif opt.endswith("_dict"):
                        value = self.loads(value)
                    elif opt.endswith("_tuple"):
                        value = tuple(i.strip() for i in value.split(","))
                    elif opt.endswith("_int"):
                        value = int(value.strip())

                    setattr(plugin, opt, value)

        setattr(plugin, 'category', category)
        plugin_path = "{}/{}/{}".format(plugin.root, category, name)
        plugin_path = os.path.abspath(plugin_path)
        self.log.debug("{}:{} plugin path set to {}".format(category, name, plugin_path))
        setattr(plugin, 'plugin_path', plugin_path)

        # Make sure we attempt to activate the plugin after we setattr
        # from the plugin config file
        plugin.activate(self)
        return plugin

    @property
    def get_all_plugin_names(self):
        """
        List all plugin names

        :returns: All plugin names
        :rtype: list

        """

        return self.__collected_plugins__.keys()

    @property
    def get_all_plugins(self):
        """
        List all valid plugins and configurations

        :returns: All valid plugins
        :rtype: dict

        """

        return self.__collected_plugins__

    def list_plugins(self):
        """
        List all available plugins and their category

        """

        print("Available Plugins:")
        for category in self.get_categories:
            print(" {}s".format(category))
            for plugin, ver, desc in self.get_plugins_of_category(category):
                print("   - {}v{}{}".format(plugin.ljust(20),
                                            str(ver).ljust(7),
                                            desc))

        return True
