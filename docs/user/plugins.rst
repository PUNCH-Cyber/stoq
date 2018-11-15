.. _pluginoverview:

Plugin Overview
===============

`stoQ` is a highly flexible framework because of its ability to leverage plugins for each layer of operations. One of the biggest benefits to this approach is that it ensures the user is able to quickly and easily pivot to and from different technologies in their stack, without having to drastically alter workflow. To better understand the `stoQ` workflow and how each of the below plugins are used, check out the :ref:`stoQ workflow section <workflow>`.

For a full listing of all publicly available plugins, check out the `stoQ public plugins <https://github.com/PUNCH-Cyber/stoq-plugins-public>`_ repository.

.. _provider:

Providers
---------

Provider plugins are designed for passing multiple payloads, or locations of payloads, to `stoQ`. They allow for multiple payloads to be run against `stoQ` until the source is exhausted. As such, they are useful for monitoring directories for new files, subscribing to a queue (i.e., RabbitMQ, Google PubSub, ZeroMQ), or scanning entire directories recursively. Multiple provider plugins can be provided allowing for even more flexibility. Provider plugins may either send a payload to `stoQ` for scanning, or send a message that an :ref:`Archiver plugin <archiver>` is able to handle for loading of a payload.

.. note:: Provider plugins are not available when using `scan mode`. This is due to `scan mode` being designed for individual scans, not multiple payloads.

Provider plugins can be defined multiple ways. In these examples, we will use the ``dirmon`` provider plugin.

From ``stoq.cfg``::

    [core]
    providers = dirmon


.. note:: Multiple plugins can be defined separated by a comma

From the command line::

    $ stoq run -P dirmon [...]

.. note:: Multiple plugins can be defined by simply adding the plugin name

Or, when instantiating the ``Stoq()`` class::

    import stoq
    providers = ['dirmon']
    s = Stoq(providers=providers, [...])


.. _worker:

Workers
-------

Worker plugins are the primary data producers within `stoQ`. These plugins allow for tasks such as scanning payloads with yara, hashing payloads, and even extracting indicators of compromise (IOC) from documents. Worker plugins can be defined in all scanning modes. Additionally worker plugins can be dynamically loaded using dispatching plugins. More information on dispatcher plugins can be found in the :ref:`dispatcher plugin section <dispatcher>`.

Worker plugins can be defined multiple ways. In these examples, we will use the ``hash`` worker plugin.

From the command line, worker plugins can be defined two different ways, depending on the use.

If *only* the original payload must be scanned, then ``--start-dispatch`` or ``-s`` command line argument may be used.::

    $ stoq scan -s hash [...]

However, if the original payload and all subsequent payloads must be scanned, the ``--always-dispatch`` or ``-a`` command line argument may be used::

    $ stoq scan -a hash [...]

.. note:: The difference between ``--start-dispatch`` and ``--always-dispatch`` can be somewhat confusing. The primary difference between the two is that if a worker plugin extracts any payloads for further scanning, any extracted payloads will only be scanned by workers defined by ``--always-dispatch``. If ``--start-dispatch`` was used, the plugin defined will not be used to scan any extracted payloads.

Or, when instantiating the ``Stoq()`` class::

    import stoq
    workers= ['yara']
    s = Stoq(always_dispatch=workers, [...])

Lastly, worker plugins can be defined by dispatcher plugins. As mentioned previously, more information on them can be found in the :ref:`dispatcher plugin section <dispatcher>`


.. _archiver:

Archivers
---------

Archiver plugins are used for retrieving or saving scanned payloads. A payload can be anything from the initial payload scanned, or extracted payloads from previous scans. There are two types of archivers, :ref:`source <archiversource>` and :ref:`destination <archiverdest>`.

.. _archiversource:

source archivers
^^^^^^^^^^^^^^^^

Archiver plugins used as a source retrieve payloads for scanning. This is useful in several use cases, such as when using a provider plugin that isn't able to pass a payload to `stoQ`. For example, if the provider plugin being used leverages a queueing system, such as RabbitMQ, there may be problems placing multiple payloads onto a queue as it is inefficient, prone to failure, and does not scale well. With archiver plugins as a source, the queuing system can be leveraged by sending a message with a payload location, and the archiver plugin can then retrieve the payload for scanning.

Source archiver plugins can be defined multiple ways. In these examples, we will use the ``filedir`` archiver plugin.

From ``stoq.cfg``::

    [core]
    source_archivers = filedir


.. note:: Multiple plugins can be defined separated by a comma

From the command line::

    $ stoq run -S filedir [...]

.. note:: Multiple plugins can be defined by simply adding the plugin name

Or, when instantiating the ``Stoq()`` class::

    import stoq
    source_archivers = ['filedir']
    s = Stoq(source_archivers=source_archivers, [...])

.. _archiverdest:

destination archivers
^^^^^^^^^^^^^^^^^^^^^

Archiver plugins used as a destination useful for saving payloads, be it the original scanned payload or any extracted payloads. Multiple destination archivers can be defined, allowing for a payload to be saved in a single or multiple locations.

Destination archiver plugins can be defined multiple ways. In these examples, we will use the ``filedir`` archiver plugin.

From ``stoq.cfg``::

    [core]
    dest_archivers = filedir

.. note:: Multiple plugins can be defined separated by a comma

From the command line::

    $ stoq run -A filedir [...]

.. note:: Multiple plugins can be defined by simply adding the plugin name

Or, when instantiating the ``Stoq()`` class::

    import stoq
    dest_archivers = ['filedir']
    s = Stoq(dest_archivers=dest_archivers, [...])


.. _dispatcher:

Dispatchers
-----------

Dispatcher plugins allow for dynamic routing and loading of worker plugins. These plugins are extremly powerful in that they allow for an extremely flexible scanning flow based on characteristics of the payload itself. For instance, routing a payload to a worker plugin for scanning can be done by yara signatures, TRiD results, simple regex matching, or just about anything else. Each loaded dispatcher plugin is run once per payload.

Dispatcher plugins can be defined multiple ways. In these examples, we will use the ``yara`` dispatcher plugin.

From ``stoq.cfg``::

    [core]
    dispatchers = yara

.. note:: Multiple plugins can be defined separated by a comma

From the command line::

    $ stoq run -R yara [...]

.. note:: Multiple plugins can be defined by simply adding the plugin name

Or, when instantiating the ``Stoq()`` class::

    import stoq
    dispatchers = ['yara']
    s = Stoq(dispatchers=dispatchers, [...])

Now, let's write a simple yara rule to pass a payload to the ``pecarve`` plugin if a DOS stub is found::

    rule exe_file
    {
        meta:
            plugin = "pecarve"
            save = "True"
        strings:
            $MZ = "MZ"
            $ZM = "ZM"
            $dos_stub = "This program cannot be run in DOS mode"
            $win32_stub = "This program must be run under Win32"
        condition:
            ($MZ or $ZM) and ($dos_stub or $win32_stub)
    }

In this case, if this yara signature hits on a payload, the payload will be passed to the ``pecarve`` plugin, which will then extract the PE file as a payload, and send it to `stoQ` for continued scanning. Additionally, because ``save = "True"``, the extracted payload will also be saved if a :ref:`Destination Archiver <archiverdest>` plugin is defined.

.. _deepdispatcher:

Deep Dispatchers
----------------

Deep Dispatcher plugins are similar to :ref:`dispatcher plugins <dispatcher>`, but there are some significant differences in their utility. One of the primary differences between them is deep dispatchers can be run 0 to N times per payload, where dispatcher plugins are only run once per payload. Additionally, deep dispatchers are run after dispatcher plugins and after the worker plugins has scanned the payload, but before continuing on to any additional payloads. Because deep dispatchers are handled after the worker plugins scan the payload, deep dispatchers are passed the original payload in addition to the scan results from the workers. This allows for additional and deeper dispatching based on not only the payload, but also any results from the workers. This concept can become somewhat complex, so it is recommended the reader review the :ref:`workflow section <workflow>` to better understand the full workflow.

Deep Dispatcher plugins can be defined multiple ways. In these examples, we will use the ``test_deep_dispatcher`` deep dispatcher plugin.

From ``stoq.cfg``::

    [core]
    deep_dispatchers = test_deep_dispatcher
    max_dispatch_passes = 3

.. note:: Multiple plugins can be defined separated by a comma. Additionally, ``max_dispatch_passes`` can be defined in ``stoq.cfg`` to ensure Deep Dispatchers do not end up in an endless loop.

From the command line::

    $ stoq run -E test_deep_dispatcher [...]

.. note:: Multiple plugins can be defined by simply adding the plugin name

Or, when instantiating the ``Stoq()`` class::

    import stoq
    deep_dispatchers = ['test_deep_dispatcher']
    s = Stoq(deep_dispatchers=deep_dispatchers, [...])

.. _decorator:

Decorators
----------

Decorator plugins are the last plugins run just before saving results. This plugin class allows for the analysis of all results from each plugin, the original payload, and any extracted payloads. Multiple decorator plugins can be loaded, but each plugin is only passed the results once. Decorator plugins are extremely useful when post-processing is required of the collective results from the entire stoQ workflow.

Decorator plugins can be defined multiple ways. In these examples, we will use the ``test_decorator`` decorator plugin.

From ``stoq.cfg``::

    [core]
    decorators = test_decorator

.. note:: Multiple plugins can be defined separated by a comma.

From the command line::

    $ stoq run -D yara [...]

.. note:: Multiple plugins can be defined by simply adding the plugin name

Or, when instantiating the ``Stoq()`` class::

    import stoq
    decorators = ['test_decorator']
    s = Stoq(decorators=decorators, [...])

.. _connector:

Connectors
----------

The last plugin class is the Connector plugin. This plugin class allows for the saving or passing off of the final result. Once all other plugins have completed their tasks, the final result is sent to the loaded connector plugins for handling. For example, a connector plugin may save results to disk, ElasticSearch, or even pass them off to a queueing system such as RabbitMQ.

Connector plugins can be defined multiple ways. In these examples, we will use the ``filedir`` connector plugin, allowing results to be saved to disk.

From ``stoq.cfg``::

    [core]
    connectors = filedir

.. note:: Multiple plugins can be defined separated by a comma.

From the command line::

    $ stoq run -C filedir [...]

.. note:: Multiple plugins can be defined by simply adding the plugin name

Or, when instantiating the ``Stoq()`` class::

    import stoq
    connectors = ['filedir']
    s = Stoq(connectors=connectors, [...])
