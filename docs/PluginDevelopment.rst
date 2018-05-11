==================
Plugin Development
==================

.. |stoQ| replace:: **stoQ**

Overview
========

There are several plugin categories that are available currently:

    - worker
    - connector
    - reader
    - source
    - extractor
    - carver
    - decoder
    - decorator

The **worker** plugin category is for the plugins that will produce data from
payloads and provide the results back to the framework for output. Once the
**worker** plugin is complete, the framework will want to handle the results in
some fashion. This is where the **connector** plugins come into play. Once the
results have been provided back to the framework, the connector is then called.
The **connector** plugins may also be used for file archiving if supported
within the plugin. One may save a file using a connector by simply calling
``save()`` with the ``archive=True`` option. Conversely, in order to retrieve a
file from MongoDB's GridFS, one simply would call ``get_file()``.  **Reader**
plugins are used to enrich data for worker plugins such as indicator
extraction, STIX support, or a multitude of other enhancements. **Source**
plugins handle the messaging and queueing of objects that the worker should
handle. For instance, monitoring a directory for new files or AMQP.
**Extractor** plugins handle various tasks such as decompressing zip files and
deflating pdf streams. **Carver** plugins are used to carve content out of
payloads (e.g., SWF streams out of DOC files, PE out of RTF, etc...).
**Decoder** plugins provide the capability to automatically decode a payload,
such as XOR, ROR, and base64. **Decorator** plugins allow for post processing
of results from |stoQ| before being saved or returned.


Configuration
=============

Each plugin has it's own configuration file ending in *.stoq*. Upon
initialization of the plugin, the configuration options within the file will be
loaded and made available to the worker object.

At a minimum, the below configuration options are required for all plugins.

.. code:: yaml

    [Core]
    # Name of plugin. stoQ will use this when calling the plugin.
    Name = basicplugin
    # Name of the .py file for this plugin
    Module = basicplugin

    [Documentation]
    Author = Joe Stoq
    Version = 0.1
    Website = https://github.com/PUNCH-Cyber/stoq
    Description = Basic Plugin Example


If a plugin requires additional configuration parameters, they can be added to
the ``[options]`` section and will be made available via the plugin object. For
example, if we have defined our plugin object as ``plugin``, we can access the
``hashpayload`` attribute by calling ``self.hashpayload``.

.. code:: yaml

    [options]
    hashpayload = True
    saveresults = True
    max_tlp = red
    max_stoq_version = 0.10.3
    min_stoq_version = 0.9
    ratelimit = 1/5

.. note:: As of |stoQ| version 0.10.3, plugin version checking is supported.
          If the min/max version of |stoQ| is not met, processing of the
          payload will proceed, but the user will be warned unpredictable
          results may be encountered.

.. note:: *Worker* plugins require the ``hashpayload`` and ``saveresults``
          configuration options. No other plugins have additional requirements.

.. note:: *Worker* plugin supports a ``max_tlp`` option, which will limit
          it's ability to scan a payload based on the TLP level of the
          payload itself. Valid options are red, amber, green, and white. More
          information on TLP levels can be found at https://www.us-cert.gov/tlp

.. note:: *Worker* plugins support rate limiting. The value for ``ratelimit``
          should be in the form of "count/per seconds". For example, the value
          ``1/10`` would mean |stoQ| will processes ``1`` sample every
          ``10 seconds``.

Plugin Development
==================

A *Worker* plugin extends the ``StoqWorkerPlugin`` class. As such, it must
inherit the ``StoqWorkerPlugin`` class when initialized. In order to function
properly, there must be several methods defined within the worker plugin.

    - __init__
    - activate

The ``__init__`` method is called upon initialization of the plugin. This
occurs when the ``Stoq.load_plugin`` method is called with the plugin name or
when ``Stoq.collect_plugins`` plugins is called.

The ``activate`` method is automatically called after the plugin has been
initialized. When it is called, it must have ``stoq`` as an attribute.  This
allows the plugin to have full access to the |stoQ| framework and configuration
options. The ``activate`` method should only be called once by the framework
upon initialization. Any initial configuration and command line options should
be placed here. This method must also return ``True`` in order for the
framework to continue, otherwise |stoQ| will assume that the plugin activation
has failed.

Additionally, the ``deactivate`` method is called when/if the plugin is ever
deactivated, including when |stoQ| shuts down. This method is not required,
though it is recommended should the plugin have any actions that need to
cleaning up or if |stoQ| needs to deactivate the plugin for any reason.

For each of the above core methods, they should minimally call
``super().METHOD_NAME()`` right before they return. METHOD_NAME should be
changed to the respective method. This will allow the respective parent class
execute any required code.

For time-based events (periodic flushes of buffers, etc), every plugin can
define a ``wants_heartbeat`` property of the plugin. If that property is True,
then a separate thread will be launched by stoQ to call the plugin's ``heartbeat``
method. The ``heartbeat`` method will be called with the plugin object as its
only argument (so ``heartbeat`` can be treated as a class method of the plugin).
The ``heartbeat`` method will only be called once, and it is expected to loop
to call whatever periodic actions the plugin wishes to take. For example

.. code:: python

    def heartbeat(self):
        while True:
            time.sleep(1)
            self._checkCommit()

.. note:: Actions performed in the heartbeat must be multithread/multiprocess
          safe. If the actions in the heartbeat may change the values of properties
          that other plugin methods (like ``save``) may also change, it is the responsibility
          of the plugin to properly handle locking access to those objects, or find other
          methods of thread safety.

.. note:: Also, at present only Worker and Connector plugins are checked to see
          if they need heartbeats. Others may be added in the future if the need arises.


Workers
-------

In addition to the above requirements, the below method is required for
*Worker* plugins:

    - scan

The ``scan`` method is called when command ``stoq`` command has a payload available for
processing. ``scan`` requires two attributes, ``payload`` and ``**kwargs``.
``payload`` is the payload that the plugin should process. If the plugin does
not require a payload, ``payload`` will be ``None``. ``**kwargs`` is a
``dict`` that contains the message provide by RabbitMQ, or some basic
metadata if RabbitMQ is not utilized. Once the ``scan`` method has completed
processing the payload, it should return it's results as a ``dict`` or ``list``.
If results are returned as a ``list``, each item in the ``list`` will be processed
separately by the ``StoqConnectorPlugin``. This will result in multiple results
being saved separately for each payload. This allows for worker plugins to save
results without making multiple calls, such as when interacting with an API that
returns multiple results or parsing an SMTP session that contains a stream of
e-mails. Optionally, if the results do not need to be process, it can return
``None``.

Below is an example of a basic worker plugin.

.. code:: python

    # Required imports
    import argparse
    from stoq.args import StoqArgs
    from stoq.plugins import StoqWorkerPlugin


    # The worker plugin class must be unique. It will be inheriting
    # the StoqWorkerPlugin class.
    class BasicWorker(StoqWorkerPlugin):

        def __init__(self):
            # In nearly all cases, we do not want to handle anything here
            super().__init__()

        # This function is required in order to initialize the worker.
        # The framework will call the activate() function upon initialization
        # and must return True in order for the framework to continue
        def activate(self, stoq):

            # Ensure the stoQ class is available throughout the
            # plugin
            self.stoq = stoq

            # Instantiate our workers command line argument parser
            parser = argparse.ArgumentParser()

            # Initialize the default requirements for a worker, if needed.
            parser = StoqArgs(parser)

            # Define the argparse group for this plugin
            worker_opts = parser.add_argument_group("Plugin Options")

            # Define the command line arguments for the worker
            worker_opts.add_argument("-r", "--rules",
                                     dest='rulepath',
                                     help="Path to rules file.")

            # The first command line argument is reserved for the framework.
            # The work should only parse everything after the first command
            # line argument. We must always use stoQ's argv object to ensure
            # the plugin is properly instantied whether it is imported or
            # used via a command line script
            options = parser.parse_args(self.stoq.argv[2:])

            # If we need to handle command line argument, let's pass them
            # to super().activate so they can be instantied within the worker
            super().activate(options=options)

            # Must return true, otherwise the framework believes something
            # went wrong
            return True

        # The framework will call the scan() function when it is ready to
        # scan. All of the initial functionality should reside here
        def scan(self, payload, **kwargs):

            # Must return a dict
            kwargs['err'] = "Need more to do!"
            return kwargs

.. note:: ``super().activate(options=options)`` must be called for the plugin
          to be fully initialized.

Connectors
----------

In addition to the above requirements, the below methods are required for
*Connector* plugins

    - save

The ``save`` method is called to save a payload to the specified connector. It
must have the ``payload`` and ``**kwargs`` attributes. The ``payload``
attribute should be the data that will be saved via the connector. ``**kwargs``
are any additional attributes that the method may require.

Optionally, the below methods can be provided.

    - connect
    - disconnect
    - get_file

``connect`` should be called when a connection, or reconnection, to the
connector database is required. Ideally, logic should be placed in ``save``
that will call ``connect`` to verify a live connection still exists.

``disconnect`` is called when the connector should cleanly disconnect from the
database.

``get_file`` is used if the database supports the saving of files. ``get_file``
may be used to retrieve any files that are saved to the connector. The
``**kwargs`` attribute should contain whatever datapoints are need to retrieve
the file.

.. code:: python

    from stoq.plugins import StoqConnectorPlugin


    class BasicConnector(StoqConnectorPlugin):

        def __init__(self):
            super().__init__()

        def activate(self, stoq):
            self.stoq = stoq

            # Any additonal requirements once the connector is activated
            # should be placed here

            super().activate()

        def get_file(self, **kwargs):

            # Code to retrieve file from this connector should be placed here

            # No results, carry on.
            return None

        def save(self, payload, **kwargs):
            """
            Save results to mongodb

            :param str payload: Content to be inserted into database
            :param dict **kwargs: Any additional attributes that should
                                    be added to the GridFS object on insert
            """

            # Make sure we have a valid connection
            self.connect()

            # Code to handle saving of the results should be placed here

            super().save()

        def connect(self, force_connect=False):
            # Logic should reside here that determines if we have an
            # active/valid connection, and if not, make one. Otherwise
            # continue on so the framework can save it's results.
            super().connect()

        def disconnect(self):
            super().disconnect()


Readers
-------

In addition to the above requirements, the below method is required for
*Reader* plugins:

    - read

The ``read`` method requires the ``payload`` attribute, and optionally
``**kwargs``. The ``payload`` should be the content that the *Reader* plugin
should process. Any additional attributes should be defined in ``**kwargs``.
Once the *Reader* plugin is done processing the ``payload``, it should return
its results.

.. code:: python

    from stoq.plugins import StoqReaderPlugin


    class BasicReader(StoqReaderPlugin):

        def __init__(self):
            super().__init__()

        def activate(self, stoq):
            self.stoq = stoq
            super().activate()

        def read(self, payload, **kwargs):
            """
            Basic Reader

            :param bytes payload: Payload to be processed
            :returns: Content of payload

            """
            return payload


Sources
-------

In addition to the above requirements, the below methods are required for
*Source* plugins:

    - ingest

The ``ingest`` method does not require any arrtributes when called. *Source*
plugins should push data back to the worker by calling the
``worker.multiprocess_put`` method. This is will pull data back to the
main method for processing data in and our of the framework to include
retrieving payloads, hashing, metadata generation, result handling, and saving
of results.

.. code:: python

    from stoq.plugins import StoqSourcePlugin


    class FileSource(StoqSourcePlugin):

        def __init__(self):
            super().__init__()

        def activate(self, stoq):
            self.stoq = stoq
            super().activate()

        def ingest(self):

            path = "/tmp/bad.exe"
            self.stoq.worker.multiprocess_put(path=path, archive='file')

            return True

A source plugin also requires the ``multiprocess`` boolean configuration
option in it's ``.stoq`` file under the [options] header. For example::

    [options]
    multiprocess = True

If set to ``True``, the source plugin will be capable of being run with
multiple instances simultaneously. Note: if ``multiprocess`` option is
set to ``False`` the source will still be run in a Python process, but
stoq will only run one instance of that process.

Extractors
----------

In addition to the above requirements, the below methods are required for
*Extractor* plugins:

    - extract

``extract()`` must be called with the ``payload`` parameter. Optionally,
``**kwargs`` may be provided. The plugin may return None or a list of tuples.
Index 0 of the tuple must be a dict() containing metadata associated with
the decoded content, and Index 1 must be the decoded content itself as bytes.

.. code:: python

    from stoq.plugins import StoqExtractorPlugin


    class ExampleExtractor(StoqExtractorPlugin):

        def __init__(self):
            super().__init__()

        def activate(self, stoq):
            self.stoq = stoq
            super().activate()

        def extract(self, payload, **kwargs):

            # handle any extraction requirements here
            meta = {"size": len(payload), "type": "test"}
            return [(meta, payload)]

Carvers
-------

In addition to the above requirements, the below methods are required for
*Carver* plugins:

    - carve

``carve()`` must be called with the ``payload`` parameter. Optionally,
``**kwargs`` may be provided. The plugin may return None or a list of tuples.
Index 0 of the tuple must be a dict() containing metadata associated with
the decoded content, and Index 1 must be the decoded content itself as bytes.

.. code:: python

    from stoq.plugins import StoqCarverPlugin


    class ExampleCarver(StoqExtractorPlugin):

        def __init__(self):
            super().__init__()

        def activate(self, stoq):
            self.stoq = stoq
            super().activate()

        def carve(self, payload, **kwargs):

            # handle any carving requirements here
            meta = {"size": len(payload), "type": "test"}
            return [(meta, payload)]

Decoders
--------

In addition to the above requirements, the below methods are required for
*Decoder* plugins:

    - decode

``decode()`` must be called with the ``payload`` parameter. Optionally,
``**kwargs`` may be provided. The plugin may return None or a list of tuples.
Index 0 of the tuple must be a dict() containing metadata associated with
the decoded content, and Index 1 must be the decoded content itself as bytes.

.. code:: python

    from stoq.plugins import StoqDecoderPlugin


    class ExampleDecoder(StoqDecoderPlugin):

        def __init__(self):
            super().__init__()

        def activate(self, stoq):
            self.stoq = stoq
            super().activate()

        def decode(self, payload, **kwargs):

            # handle any decoding requirements here
            meta = {"size": len(payload), "type": "test"}
            return [(meta, payload)]

Decorators
----------

In addition to the above requirements, the below methods are required for
*Decorator* plugins:

    - decorate

``decorate()`` must be called with the ``results`` parameter. The plugin *must*
return a ``dict`` of the original results provided to it, or modified ``results``.

.. note:: The ``dict`` returned from ``decorate()`` *WILL* be what is saved/returned
          from |stoQ|, so be extremely careful with how `results` is modified.

.. code:: python

    from stoq.plugins import StoqDecoratorPlugin


    class ExampleDecorator(StoqDecoratorPlugin):

        def __init__(self):
            super().__init__()

        def activate(self, stoq):
            self.stoq = stoq
            super().activate()

        def decorate(self, results):
            # handle any logic to determine what is added to results here
            if 'APT' in results['scan']:
                results = {'apt_malware': True}
            return results

Packaging Plugins
=================

|stoQ| provides a method to install plugins and their dependencies utilzing
setuptool and pip. In order to leverage the plugin installation feature, some
requirements must be met for the plugin package.

    - The plugin package must be a directory

    - The plugin directory must have a subdirectory by the same name as defined
      in the plugins ``.stoq`` configuration file

    - The plugin directory must contain a valid |stoQ| configuration file

    - The plugin directory must contain a valid |Stoq| plugin

    - The plugin directory must contain a file named ``__init__.py``

    - Optionally, the archive/directory may contain a valid pip *requirements.txt* file.
      The pip packages within this file will automatically be installed with
      the |stoQ| plugin.

    - Optionally, a MANIFEST.in file can be included to define which files within the package
      should be copied to the installation path.

.. note:: The plugin's configuration file will not be copied by default, this
          file should either be defined here or within ``package_data`` in
          ``setup.py``.

As an example, a |stoQ| plugin archive should have the following structure::

    basicworker-plugin/
        setup.py
        MANIFEST.in (optional)
        requirements.txt (optional)
        basicworker/
            __init__.py
            basicworker.stoq
            basicworker.py

The |stoQ| installation process will extract plugin options from it's ``.stoq``
configuration file. As such, the plugin's ``setup.py`` file should be fairly
simple. The below ``setup.py`` should suffice for most plugins.::

    from setuptools import setup, find_packages

    setup(
        name=open("NAME").read(),
        version=open("VERSION").read(),
        author=open("AUTHOR").read(),
        url=open("WEBSITE").read(),
        license="Apache License 2.0",
        description=open("DESCRIPTION").read(),
        packages=find_packages(),
        include_package_data=True,
        classifiers=[
            "Development Status :: 3 - Alpha",
            "Topic :: Utilities",
        ],
    )


Templates
---------

|stoQ| allows for two types of outputs. First, a JSON blob that can be easily
parsed in an automated fashion. In addition, |stoQ| can handle output using
Jinja2 templating. This allows for highly customizable and human readable
output that may be neccessary in many circumstances. As an example, when using
the slack worker plugin, it is not ideal to have hundreds, maybe even
thousands, of lines sent to a channel as a result of scanning a payload. With
|stoQ|'s templating engine, one can easily send human readable and easily
digested results to the Slack channel, while at the same time providing the
JSON results to a connector for saving into a database for later use.

Using |stoQ|'s templates is a simple process. Simply create a ``templates``
directory in the plugin's directory and then create a new ``template`` file
in Jinja2 format. For example, let's say we have a worker plugin by the
name *peinfo*. We want to create a Slack template for this plugin.
All that is needed now is for a ``slack.tpl`` template to be placed in this
directory. Now, we just need to run the slack worker with the ``-T slack.tpl``
argument. The slack worker plugin will then load the template and render the
results.

Additionally, content that is passed to the connector plugin may also be parsed
using the templating engine. In order to use this functionality, the worker
plugin that is producing the data must have a template named after the connector
plugin that is being utilized. For instance, if one would like to ensure the
stdout connector output is human readable and not the JSON results, simply
create a new template with the name ``stdout.tpl`` and call the worker with
``-T stdout.tpl``.


Installing a Plugin
-------------------

Installation of a |stoQ| plugin is very simple. Let's assume that we want to
install the basicworker plugin that comes prepackaged with |stoQ|. We must
first package the plugin as detailed above, and then run the command from
within the |stoQ| directory::

    stoq install basicworker-plugin


        .d8888b.  888             .d88888b.
       d88P  Y88b 888            d88P" "Y88b
       Y88b.      888            888     888
        "Y888b.   888888 .d88b.  888     888
           "Y88b. 888   d88""88b 888     888
             "888 888   888  888 888 Y8b 888
       Y88b  d88P Y88b. Y88..88P Y88b.Y8b88P
        "Y8888P"   "Y888 "Y88P"   "Y888888"
                                        Y8b

    [+] Looking for plugin in /vagrant/stoq/plugin-packages/worker/yara...
    [+] Installing yara plugin into /vagrant/stoq/stoq/plugins/worker...
    [+] Install complete.

Let's examine what |stoQ| just did. First, we opened the *basicworker-plugin*
plugin package and began searching for a |stoQ| plugin configuration file. Once
it was found, we loaded it and searched for the Name and Module configuration
options within the file. That allowed us to discover the plugin name along with
the plugins .py filename. |stoQ| then discovered the plugin class to determine
the full path where the plugin should be installed to. It then called pip to
complete the installation.

If a file or directory exists, it will not be overwritten. Instead, a warning
message will be displayed letting the user know that the plugin will not be
installed.  In order to successfully install the plugin, the file or directory
must be removed, renamed, or --upgrade be called at the command line.
