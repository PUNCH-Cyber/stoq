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

Plugins may be provided configuration options in one of four ways. In order of precendece:

    - From the command line
    - Upon instantiation of `Stoq()`
    - Defined in `stoq.cfg`
    - Defined in the plugin's `.stoq` configuration file

.. _pluginconfigcmdline:

Command Line
------------

When running ``stoq`` from the command line, simply add ``--plugin-opts`` to your arguments
followed by the desired plugin options. The syntax for plugin options is::

    plugin_name:option=value

For example, if we want to tell the plugin ``dirmon`` to monitor the directory ``/tmp/monitor``
for new files by setting the option ``source_dir``, the syntax would be::

    dirmon:source_dir=/tmp/monitor


.. _pluginconfiginstantiation:

Instantiation
-------------

When using stoQ as a framework, plugin options may be defined when instantiating ``Stoq`` using the ``plugin_opts``
argument::

    >>> from stoq import Stoq
    >>> plugin_options = {'dirmon': {'source_dir': '/tmp/monitor'}}
    >>> s = Stoq(plugin_opts=plugin_options)


.. _pluginconfigstoqcfg:

stoq.cfg
--------

The recommended location for storing static plugin configuration options is in `stoq.cfg`.  The reason for this
if all plugin options defined in the plugin's `.stoq` file will be overwritten when the plugin is upgraded.

To define plugin options in `stoq.cfg` simply add a section header of the plugin name, then define the plugin options.
For example, to define the plugin option `source_dir` for the `dirmon` plugin, the below can be added to `stoq.cfg`::

    [dirmon]
    source_dir = /tmp/monitor


.. _pluginconfigpluginstoq:

Plugin .stoq configuration file
--------------------------------

Each plugin must have a ``.stoq`` configuration file. The configuration file resides in
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
    min_stoq_version = 3.0.0

* **options**
    - **min_stoq_version**: Minimum version of stoQ required to work properly. If the version of `stoQ` is less than the version defined, a warning will be raised.

.. note::
    Plugin options *must* be under the `[options]` section header to be accessible via the other plugin configuration options.

.. warning::
    Plugin configuration options may be overwritten when a plugin is upgraded. Upgrading plugins is a destructive
    operation. This will overwrite/remove all data within the plugins directory, to include the plugin configuration
    file. It is highly recommended that the plugin directory be backed up regularly to ensure important information
    is not lost, or plugin configuration options be defined in `stoq.cfg`.


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
    from stoq import Payload, Request, WorkerResponse
    from stoq.plugins import DispatcherPlugin, WorkerPlugin

    class MultiClassPlugin(WorkerPlugin, DispatcherPlugin):
        async def scan(
            self, payload: Payload, request: Request
        ) -> Optional[WorkerResponse]:
            # do worker plugin stuff here
            return

        async def get_dispatches(
            self, payload: Payload, request: Request
        ) -> Optional[DispatcherResponse]:
            # do dispatcher plugin stuff here
            return


.. _pluginlogging:

Plugin Logging
**************

Upon instantiation, plugins are provided a `Logger` object within the plugin class
named `self.log`. This is just a standard Python logging object that supports the
log levels `debug`, `info`, `warning`, `error`, and `critical`.::

    from typing import Optional
    from stoq.plugins import WorkerPlugin
    from stoq import Payload, Request, WorkerResponse

    class LoggingPlugin(WorkerPlugin):
        async def scan(
            self, payload: Payload, request: Request
        ) -> Optional[WorkerResponse]:
            self.log.info('Scanning payload now')


.. _pluginclasses:

Classes
*******

.. toctree::
   :maxdepth: 3

   archivers
   connectors
   decorators
   dispatchers
   providers
   workers
