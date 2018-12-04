.. _pluginoverview:

Plugins
=======

Overview
********

`stoQ` is a highly flexible framework because of its ability to leverage plugins for each
layer of operations. One of the biggest benefits to this approach is that it ensures the
user is able to quickly and easily pivot to and from different technologies in their stack,
without having to drastically alter workflow. To better understand the `stoQ` workflow and
how each of the below plugins are used, check out the :ref:`stoQ workflow section <workflow>`.

For a full listing of all publicly available plugins, check out the `stoQ public plugins <https://github.com/PUNCH-Cyber/stoq-plugins-public>`_ repository.

.. _pluginconfig:

Configuration
*************

Each plugin must have an ``.stoq`` configuration file. The configuration file resides in
the same directory as the plugin module. The plugin's configuration file allows for
configuring a plugin with default or static settings. The configuration file is a standard
YAML file and is parsed using the ``configparser`` module. The following is an example
plugin configuration file with all *required* fields::

    [Core]
    Name = example_plugin
    Module = example_plugin

    [Documentation]
    Author = PUNCH Cyber
    Version = 0.1
    Website = https://github.com/PUNCH-Cyber/stoq-plugins-public
    Description = Example stoQ Plugin

.. note: If any of the above settings are missing, the plugin will fail to load or may not
         run properly.

* **Core**
    - **Name**: The plugin name that stoQ will use when calling the plugin. This must be unique.
    - **Module**: The python module that contains the plugin (without the `.py` extension).
* **Documentation**
    - **Author**: Author of the plugin
    - **Version**: Plugin version
    - **Website**: Website where the plugin can be found
    - **Description**: Description of the plugins utility

Additionally, some optional settings may be defined::

    [options]
    min_stoq_version = 2.0.0

* **options**
    - **min_stoq_version**: Minimum version of stoQ required to work properly. If the version of `stoQ` is less than the version defined, a warning will be raised.

Custom settings may be added as required for plugins, but the plugins must be configured to
load and set them. For example, our configuration file may be::

    [Core]
    Name = example_plugin
    Module = example_plugin

    [Documentation]
    Author = PUNCH Cyber
    Version = 0.1
    Website = https://github.com/PUNCH-Cyber/stoq-plugins-public
    Description = Example stoQ Plugin

    [worker]
    source = /tmp


Now, in the ``__init__`` method of our plugin class, we can ensure we define the ``source``
setting under the ``worker`` section of the configuration file::


        if plugin_opts and 'source' in plugin_opts:
            self.source = plugin_opts['source']
        elif config.has_option('worker', 'source'):
            self.source = config.get('worker', 'source')


First, we are checking for any plugin options were provided to ``Stoq`` at instantiation or at the
:ref:`command line <pluginoptions>`. If not, it will check the plugin's configuration file for
the ``source`` setting under the ``worker`` section. If ``source`` is defined in either, the
setting will be made available to the plugin by defining ``self.source``.


.. _multiclass:

Multiclass Plugins
******************

Plugins that are of more than one plugin class are called `Multiclass Plugins`.
`Multiclass plugins` help to simplify and centralize plugin code. Development
is nearly identical to creating a regular plugin.In order to create a
`Multiclass plugin`, the plugin must be a subclass of one or more plugin class.

In this example, we will create a `Multiclass plugin` that is a worker as well
as a dispatcher plugin. We simply need to subclass our plugin class with
``WorkerPlugin`` and ``DispatcherPlugin`` and ensure the ``scan`` (required
for worker plugins) and ``get_dispatches`` (required for dispatcher plugins)
methods exist.::

    from typing import Optional
    from stoq.plugins import DispatcherPlugin, WorkerPlugin

    class MultiClassPlugin(WorkerPlugin, DispatcherPlugin):
        def scan(
            self, payload: Payload, request_meta: RequestMeta
        ) -> Optional[WorkerResponse]:
            # do worker plugin stuff here
            return

        def get_dispatches(
            self, payload: Payload, request_meta: RequestMeta
        ) -> Optional[DispatcherResponse]:
            # do dispatcher plugin stuff here
            return


.. _pluginclasses:

Classes
*******

.. toctree::
   :maxdepth: 3

   archivers
   connectors
   decorators
   deepdispatchers
   dispatchers
   providers
   workers