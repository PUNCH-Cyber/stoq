#   Copyright 2014-2016 PUNCH Cyber Analytics Group
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
import time
import signal
import logging
import threading
import multiprocessing

try:
    import yara
    yara_imported = True
except ImportError:
    yara = None
    yara_imported = False

from pkg_resources import parse_version as version

from yapsy.PluginManager import PluginManager
from yapsy.FilteredPluginManager import FilteredPluginManager

from jinja2 import Environment, FileSystemLoader
from jinja2.exceptions import TemplateNotFound

from stoq import signal_handler
from stoq.helpers import ratelimited
from stoq.exceptions import SigtermCaught
from stoq.scan import get_hashes, get_ssdeep, get_magic, get_sha1


class StoqPluginManager:
    """

    stoQ Plugin Manager Class

    """

    def __init__(self):

        # Define the plugin categories and the associated class.
        # If we need to add a new plugin category, it must be done here.
        self.plugin_categories = {"worker": StoqWorkerPlugin,
                                  "connector": StoqConnectorPlugin,
                                  "reader": StoqReaderPlugin,
                                  "source": StoqSourcePlugin,
                                  "extractor": StoqExtractorPlugin,
                                  "carver": StoqCarverPlugin,
                                  "decoder": StoqDecoderPlugin
                                  }

        self.manager = PluginManager()
        self.manager.setPluginInfoExtension("stoq")
        self.manager.setPluginPlaces([self.plugin_dir])
        self.manager.setCategoriesFilter(self.plugin_categories)

        # Setup our plugin filter
        self.manager = FilteredPluginManager(self.manager)

    @property
    def __plugindict__(self):
        """

        Create a dict() of plugin class name and the plugin category

        """
        plugins = {}
        for category, category_class in self.plugin_categories.items():
            class_str = re.search(r'(?<=<class \'stoq\.plugins\.)(.+)(?=.*\'>)',
                                  str(category_class)).group(0)
            plugins[class_str] = category

        return plugins

    def collect_plugins(self):
        """
        Wrapper for yapsy.PluginManager.collectPlugins()

        """

        self.manager.collectPlugins()

    def get_categories(self):
        """
        Wrapper for yapsy.PluginManager.getCategories()

        """

        return self.manager.getCategories()

    def get_plugins_of_category(self, category):
        """
        Wrapper for yapsy.PluginManager.getPluginsOfCategory()

        """

        return self.manager.getPluginsOfCategory(category)

    def get_plugin_names_of_category(self, category):
        """
        Lists plugin name of a specific category

        :param str category: Category to discover plugins in

        :returns: A list of discovered plugins
        :rtype: list

        """

        return [p.name for p in self.get_plugins_of_category(category)]

    def get_plugin(self, name, category):
        """
        Initializes a plugin within a specific category

        :param str name: Name of plugin to get
        :param str category: Category of the named plugin

        :returns: plugin object
        :rtype: object

        """

        return self.manager.getPluginByName(name, category)

    def deactivate_plugin(self, name, category):
        """
        Deactivate a plugin within a specific category

        :param str name: Name of plugin to deactivate
        :param str category: Category of the named plugin

        """

        return self.manager.deactivatePluginByName(name, category=category)

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

        # We are going to dynamically reimplement the isPluginOk method
        # so only the needed plugins are loaded into memory. Much faster
        # and efficient
        self.manager.isPluginOk = lambda x: x.name == name

        # Gather, filter, and load plugin
        self.manager.locatePlugins()
        self.manager.filterPlugins()
        self.manager.loadPlugins()

        # Initialize our plugin
        self.log.debug("Attempting to load plugin {}:{}".format(category, name))
        plugin = self.get_plugin(name, category)

        if not plugin:
            self.log.warn("Plugin {}:{} failed to load".format(category, name))
            return False

        for sect in plugin.details.sections():
            # Let's skip over the sections that are required by our
            # plugin manager. No sense in trying to overwrite.
            if any([s in sect for s in ['Core', 'Documentation']]):
                next

            for opt in plugin.details.options(sect):
                # define each configuration option as an object within
                # plugin class.
                # Note: In order to reduce logic, we attempt to load
                # the option as a boolean. By default, this will raise
                # an error which in turn will cause us to load it as
                # a string.
                try:
                    setattr(plugin.plugin_object, opt,
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

                    setattr(plugin.plugin_object, opt, value)

        setattr(plugin.plugin_object, 'category', category)
        plugin_path = "{}/{}/{}".format(self.plugin_dir, category, name)
        plugin_path = os.path.abspath(plugin_path)
        self.log.debug("{}:{} plugin path set to {}".format(category, name, plugin_path))
        setattr(plugin.plugin_object, 'plugin_path', plugin_path)

        # Make sure we attempt to activate the plugin after we setattr
        # from the plugin config file
        plugin.plugin_object.activate(self)
        return plugin.plugin_object

    def get_all_plugin_names(self):
        """
        List all plugin names

        :returns: All plugin names
        :rtype: list

        """

        return [p.name for p in self.get_all_plugins()]

    def get_all_plugins(self):
        """
        Wrapper for yapsy.PluginManager.getAllPlugins()

        """

        return self.manager.getAllPlugins()

    def list_plugins(self):
        """
        List all available plugins and their category

        """

        # Make sure we update the filter, otherwise all plugins won't be
        # visible.
        self.manager.isPluginOk = lambda x: x.name != ""
        self.collect_plugins()
        print("Available Plugins:")
        for category in self.get_categories():
            print(" {0}s".format(category))
            for plugin in self.get_plugins_of_category(category):
                print("   - {0}v{1}{2}".format(plugin.name.ljust(20),
                                               str(plugin.version).ljust(7),
                                               plugin.description))


class StoqPluginBase:

    def __init__(self):
        self.is_activated = False
        self.min_stoq_version = None
        self.max_stoq_version = None
        super().__init__()

    @property
    def min_version(self):
        if self.min_stoq_version:
            return version(self.stoq.version) >= version(self.min_stoq_version)
        else:
            return True

    @property
    def max_version(self):
        if self.max_stoq_version:
            return version(self.stoq.version) < version(self.max_stoq_version)
        else:
            return True

    def activate(self):

        # Instantiate the logging handler for this plugin
        logname = "stoq.{}.{}".format(self.category, self.name)
        self.log = logging.getLogger(logname)

        if not self.min_version or not self.max_version:
            self.log.critical("Plugin not compatible with this version of stoQ. "
                              "Unpredictable results may occur!")

        if hasattr(self, 'max_tlp'):
            self.max_tlp = self.max_tlp.lower()

        self.is_activated = True
        self.log.debug("{} plugin activated".format(self.name))

    def deactivate(self):
        self.is_activated = False
        self.log.debug("{} plugin deactivated".format(self.name))

    def heartbeat(self, force=False):
        pass


class StoqWorkerPlugin(StoqPluginBase):
    """
    stoQ Worker Plugin Class

    """

    def __init__(self):
        super().__init__()

        self.max_processes = 0
        self.dispatch = None
        self.output_connector = None
        self.source_plugin = None
        self.source_queue = None
        self.yara_dispatcher_rules = None
        self.yara_dispatcher_hits = None
        self.mp_queues = None
        self.connector_queue = None
        self.connector_feeder = None
        self.ratelimit = None
        self.cron = None
        self.default_tlp = None
        self.outfile = None
        self.use_output_date = False

        self.workers = {}
        self.connectors = {}
        self.sources = {}
        self.readers = {}
        self.extractors = {}
        self.carvers = {}
        self.decoders = {}

    def activate(self, options=None):
        """
        Activate the plugin within the framework

        :param dict options: argparse options

        :returns: The worker plugin object
        :rtype: object

        """

        super().activate()

        if options:
            # Make sure each command line argument is exposed
            # to the framework as an attribute of the worker
            for k in options.__dict__:
                if options.__dict__[k] is not None:
                    setattr(self, k, options.__dict__[k])

        # Ensure the log level is set appropriately
        if self.log_level:
            self.stoq.log_level = self.log_level.upper()
            self.stoq.log.setLevel(self.stoq.log_level)

        # Set the default TLP for each sample
        if self.default_tlp:
            self.stoq.default_tlp = self.default_tlp

        # Set the maximum recursion level when dispatching
        if self.max_recursion:
            self.stoq.max_recursion = self.max_recursion

        if not self.max_processes:
            # Let's set the max_processes to 50% of total CPUs
            self.max_processes = int(multiprocessing.cpu_count() / 2)
            if self.max_processes < 1:
                self.max_processes = 1
        else:
            self.max_processes = int(self.max_processes)

        # yara-python is not installed, dispatching is not supported
        if not yara_imported and self.dispatch:
            self.log.error("Failed to load yara-python, dispatching will not work. "
                           "Try reinstalling yara-python.")
            self.dispatch = False

        # This is the first worker be initialized, so it will be the primary
        # one. Additional worker plugins can be loaded, but they will not be
        # accessible globally.
        if not self.stoq.worker:
            # Make sure we are accessible to the framework
            self.stoq.worker = self

        # If no connector was defined by the worker, let's use the
        # framework's default one. Even if we don't want to save results,
        # this should be defined just in case a plugin  wants to interact
        # with a connector.
        if not self.output_connector:
            self.output_connector = self.stoq.default_connector

        # If our worker saves it's results let's initialize and load the
        # connector plugin
        if self.saveresults:
            self.load_connector(self.output_connector)
            self.log.debug("Using {} as default connector for results".format(self.output_connector))

        # If the worker wants to archive files, let's load that connector
        # now
        if self.archive_connector:
            self.load_connector(self.archive_connector)
            self.log.debug("Using {} as default archive connector".format(self.archive_connector))

        # Check to see if a source plugin requirement was defined at the
        # command line. This is useful for plugins that don't need any
        # input and simply produce data.
        if options.source_plugin or options.path or options.error_queue:
            # Check to see if a ingest source plugin was defined at the
            # command line, otherwise use the default one defined in
            # stoq.cfg
            if not self.source_plugin:
                self.source_plugin = self.stoq.default_source
            self.load_source(self.source_plugin)
            self.log.debug("Using {} as default source".format(self.source_plugin))

        if self.dispatch:
            self.log.debug("Loading yara rules for dispatching")
            with open(self.stoq.dispatch_rules) as rules:
                self.yara_dispatcher_rules = yara.compile(file=rules)

        if self.ingest_metadata:
            try:
                ingest_metadata = {}
                for md in self.ingest_metadata:
                    k, v = md.split(":")
                    if k in ingest_metadata:
                        self.log.debug("Duplicate metadata key found {}, skipping".format(k))
                        continue
                    ingest_metadata[k] = v
                self.ingest_metadata = ingest_metadata
                self.log.debug("Ingest time metadata: {}".format(self.ingest_metadata))
            except Exception as err:
                self.log.warn("Unable to parse ingest metadata, skipping: {}".format(err))

        return self

    def _start_heartbeats(self):
        # check each plugin to see if they have asked for a heartbeat
        # helper function. If the wants_heartbeat class variable exists
        # and is true, start a thread that calls the class' "heartbeat"
        # method.
        for category in self.stoq.plugin_categories:
            full_category_name = category + "s"
            plugin_category = getattr(self, full_category_name, None)
            if plugin_category is not None:
                for plugin in plugin_category:
                    pluginObj = plugin_category[plugin]
                    if hasattr(pluginObj, "wants_heartbeat") and pluginObj.wants_heartbeat:
                        thread = threading.Thread(target=pluginObj.heartbeat,
                                                  args=(),
                                                  daemon=True)
                        pluginObj.heartbeat_thread = thread
                        thread.start()

    def run(self):
        """
        Run the plugin with a source plugin, or standalone

        """

        procs = []

        try:
            # Catch a SIGTERM to ensure graceful shutdown
            signal.signal(signal.SIGTERM, signal_handler)

            # There are some conditions where a source plugin may not be loaded
            # yet. Verify we have one loaded, if needed.
            if self.source_plugin:
                self.load_source(self.source_plugin)

            # See if we have loaded any source plugins.
            if self.sources:
                self.mp_queues = multiprocessing.JoinableQueue()
                if self.sources[self.source_plugin].multiprocess:
                    self.log.debug("Plugin supports multiprocessing, instantiating processes")
                    procs = [multiprocessing.Process(target=self._multiprocess,
                                                     args=(self.mp_queues,))
                             for _ in range(self.max_processes)]

                    self.log.debug("{} processes instantiated".format(len(procs)))
                    # Start our processes before we populate them
                    for proc in procs:
                        proc.start()
                else:
                    proc = multiprocessing.Process(target=self._multiprocess,
                                                   args=(self.mp_queues,))
                    proc.start()
                    procs = [proc]

                # Start processing the source plugin
                self.sources[self.source_plugin].ingest()

                # Make sure we exit out when we are all done
                for _ in procs:
                    self.multiprocess_put(_stoq_multiprocess_eoq=True)
            else:
                # Looks like we don't have any. Let's just call the worker
                # directly. Useful when we have a work plugin that requires no
                # input.
                self.start(ratelimit=self.ratelimit)

            done = False
            while not done:
                alive = [p.is_alive() for p in procs]
                if not any(alive):
                    done = True

        except KeyboardInterrupt:
            self.log.warn("Keyboard interrupt received..attempting graceful shutdown")
        except SigtermCaught:
            self.log.warn("SIGTERM Caught..attempting graceful shutdown")
        except Exception as err:
            self.log.critical(err, exc_info=True)
        finally:
            self.log.debug("Cleaning up multiprocess queue")
            if procs:
                for proc in procs:
                    proc.terminate()
                    proc.join()
            return None

    def _deactivate_everything(self):
        # call all plugin deactivate methods, so that they can
        # finish their work before we terminate.
        for category in self.stoq.plugin_categories:
            full_category_name = category + "s"
            plugin_category = getattr(self, full_category_name, None)
            if plugin_category is not None:
                for plugin in plugin_category:
                    if plugin:
                        plugin_category[plugin].deactivate()

    def _multiprocess(self, queue):
        self._start_heartbeats()
        while True:
            msg = queue.get()
            self.log.debug("Received message from source: {}".format(msg))
            should_stop = msg.get("_stoq_multiprocess_eoq", False)
            if should_stop:
                self.log.debug("Shutdown command received. Stopping.")
                self._deactivate_everything()
                return
            try:
                self.start(**msg)
            except Exception as e:
                # Something went wrong. If the source plugin supports
                # publishing, let's go ahead and push the error to it.
                # Otherwise, let's just log to the stoQ log
                msg['err'] = str(e)
                self.log.error(msg, exc_info=True)

                if hasattr(self.sources[self.source_plugin], 'publish'):
                    self.sources[self.source_plugin].publish_connect()
                    self.sources[self.source_plugin].publish(msg, self.stoq.worker.name, err=True)
                    self.sources[self.source_plugin].publish_release()

    def multiprocess_put(self, **kwargs):
        # Ensure that the max_queue size is not reached. If so, let's wait 1
        # second. The reasoning for this is when using a queueing system, such
        # as RabbitMQ or Kafka, they will keep adding to the multiprocessing
        # queue until the queue has emptied, or, until the system resources
        # have been exhausted. If the latter, stoQ will silently die.
        while self.mp_queues.qsize() >= self.stoq.max_queue:
            self.log.debug("Queue maximum size ({}) reached. Sleeping...".format(self.stoq.max_queue))
            time.sleep(1)

        # Ensure ratelimit is defined
        kwargs['ratelimit'] = self.ratelimit

        self.mp_queues.put(kwargs)

    def scan(self):
        pass

    def load_worker(self, worker):
        """
        Load a worker plugin from another worker plugin

        :param str worker: The name of worker plugin to be loaded

        :returns: True

        """

        if worker not in self.workers:
            self.workers[worker] = self.stoq.load_plugin(worker, 'worker')
            # Define the parent plugin within the plugin so we can use it
            # should multiple worker plugins be loaded
            self.workers[worker].parentname = self.name

        return True

    def load_connector(self, connector):
        """
        Load a connector plugin

        :param str connector: The name of connector plugin to be loaded

        :returns: True

        """

        if connector not in self.connectors:
            self.connectors[connector] = self.stoq.load_plugin(connector,
                                                               'connector')
            # Define the parent plugin within the plugin so we can use it
            # should multiple worker plugins be loaded
            self.connectors[connector].parentname = self.name

        return True

    def load_source(self, source):
        """
        Load a source plugin

        :param str source: The name of source plugin to be loaded

        :returns: True

        """
        if source not in self.sources:
            self.sources[source] = self.stoq.load_plugin(source, 'source')
            # Define the parent plugin within the plugin so we can use it
            # should multiple worker plugins be loaded
            self.sources[source].parentname = self.name

        return True

    def load_reader(self, reader):
        """
        Load a reader plugin

        :param str reader: The name of reader plugin to be loaded

        :returns: True

        """

        if reader not in self.readers:
            self.readers[reader] = self.stoq.load_plugin(reader, 'reader')
            # Define the parent plugin within the plugin so we can use it
            # should multiple worker plugins be loaded
            self.readers[reader].parentname = self.name

        return True

    def load_extractor(self, extractor):
        """
        Load an extractor plugin

        :param str extractor: The name of extractor plugin to be loaded

        :returns: True

        """

        if extractor not in self.extractors:
            self.extractors[extractor] = self.stoq.load_plugin(extractor,
                                                               'extractor')
            # Define the parent plugin within the plugin so we can use it
            # should multiple worker plugins be loaded
            self.extractors[extractor].parentname = self.name

        return True

    def load_carver(self, carver):
        """
        Load an carver plugin

        :param str carver: The name of carver plugin to be loaded

        :returns: True

        """

        if carver not in self.carvers:
            self.carvers[carver] = self.stoq.load_plugin(carver, 'carver')
            # Define the parent plugin within the plugin so we can use it
            # should multiple worker plugins be loaded
            self.carvers[carver].parentname = self.name

        return True

    def load_decoder(self, decoder):
        """
        Load an decoder plugin

        :param str decoder: The name of decoder plugin to be loaded

        :returns: True

        """

        if decoder not in self.decoders:
            self.decoders[decoder] = self.stoq.load_plugin(decoder, 'decoder')
            # Define the parent plugin within the plugin so we can use it
            # should multiple worker plugins be loaded
            self.decoders[decoder].parentname = self.name

        return True

    def save_payload(self, payload, connector):
        """
        Save a payload using the designated connector

        :param bytes payload: Payload to pass to the connector for saving
        :param str connector: Connector plugin to save the payload with

        """

        if self.log_level == 'DEBUG':
            time.process_time()

        arc = get_hashes(payload)

        # Let's make sure we add some additional metadata so we don't need
        # to create this later.
        arc['ssdeep'] = get_ssdeep(payload)
        arc['content-type'] = get_magic(payload)

        # Make sure our connector is loaded
        self.load_connector(connector)

        self.log.debug("Saving content ({} bytes) with {} plugin".format(len(payload), connector))

        # Save our payload to the appropriate plugin
        res = self.connectors[connector].save(payload, archive=True, **arc)

        arc['conn_id'] = res

        if self.log_level == 'DEBUG':
            etime = time.process_time()
            self.log.debug("Content saved in {:.2f}s".format(etime))

        return arc

    # Handle our worker and process the results
    @ratelimited()
    def start(self, payload=None, **kwargs):
        """
        Process the payload with the worker plugin

        :param bytes payload: (optional) Payload to be processed
        :param str ratelimit: Rate limit processing (count/per seconds)
        :param str archive: Connector plugin to use as a source for the payload
        :param str/list uuid: UUID for this result, and any parent results
        :param str filename: File name, if available, for the payload
        :param str path: Path the file is being ingested from

        :returns: Tuple of JSON results and template rendered results
        :rtype: dict and str or lists

        """

        tlp = kwargs.get('tlp', self.stoq.default_tlp).lower()
        # Default to TLP:WHITE
        payload_tlp = self.stoq.tlps.get(tlp, 3)
        self.log.debug("Payload is TLP:{}".format(tlp))

        if hasattr(self, 'max_tlp'):
            # Default to TLP:RED
            max_tlp = self.stoq.tlps.get(self.max_tlp, 0)
            self.log.debug("Maximum for plugin is TLP:{}".format(self.max_tlp))

            # If the payload's TLP is less than the maximum allowed TLP for
            # this plugin we will skip it.
            if payload_tlp < max_tlp:
                self.log.info("Payload (TLP:{}) not approved for this plugin (TLP:{})".format(tlp, self.max_tlp))
                return None

        if self.log_level == 'DEBUG':
            time.process_time()

        archive_type = False
        payload_hashes = None
        template_results = None
        results = {}
        results['results'] = []
        results['plugins'] = {}
        worker_result = {}

        results['date'] = self.stoq.get_time

        # If we don't have a uuid, let's generate one
        uid = kwargs.get('uuid', None)
        if type(uid) == str:
            self.log.debug("Adding UUID {}".format(uid))
            kwargs['uuid'] = [uid]
        elif not uid:
            kwargs['uuid'] = [self.stoq.get_uuid]

        # If we have no payload, let's try to find one to process
        if not payload and 'archive' in kwargs:
            # We are going to use the 'archive' field in kwargs to define where
            # we are going to get the file from. Once we know that, we will
            # load the appropriate plugin if required. Then, we will call
            # get_file() to grab the payload.
            archive_type = kwargs['archive']
            worker_result['archive'] = kwargs['archive']

            self.load_connector(archive_type)
            if hasattr(self.connectors[archive_type], 'get_file'):
                self.log.debug("Attempting to retrieve payload using {}".format(archive_type))
                payload = self.connectors[archive_type].get_file(**kwargs)
            else:
                self.log.warn("Connector unable to get file..skipping")
                return False

        if payload:
            # Make sure we define this before possibly modifying the full file
            # path when/if we archive.
            if 'filename' not in kwargs:
                if 'path' in kwargs:
                    kwargs['filename'] = os.path.basename(kwargs['path'])
                    worker_result['path'] = kwargs['path']
                else:
                    kwargs['filename'] = "Unknown"

                # Make sure we save the filename in the worker results as well
                worker_result['filename'] = kwargs['filename']

            # If this worker wants us to save this payload to the archive,
            # let's handle that now before anything else. Otherwise any
            # subsequent plugins may not be able to retrieve the files. We are
            # however going to skip saving the payload if our source is the
            # same as the connector.
            if self.archive_connector and self.archive_connector != archive_type:
                payload_hashes = self.save_payload(payload, self.archive_connector)

            # Some workers don't need a hash to be generated, so let's only
            # generate hashes if needed. This is defined in the .stoq
            # configuration file for the worker plugin. We are also only going
            # to generate a hash if our save_payload function hasn't been
            # called. Otherwise, we will just use those results.
            if self.hashpayload:
                if payload_hashes:
                    worker_result.update(payload_hashes)
                else:
                    worker_result.update(get_hashes(payload))

        self.log.debug("Scan: Scanning payload")
        # Send our payload to the worker, and store the results
        worker_result['scan'] = self.scan(payload, **kwargs)

        worker_result['plugin'] = self.name

        worker_result['uuid'] = kwargs['uuid'].copy()

        if payload:
            worker_result['size'] = len(payload)

        # Preserve the original metadata that was submitted with this payload
        worker_result['source_meta'] = kwargs.copy()

        if self.ingest_metadata:
            for k, v in self.ingest_metadata.items():
                if k not in worker_result['source_meta']:
                    worker_result['source_meta'].update({k: v})
                else:
                    self.log.debug("Duplicate metadata key found {}, skipping".format(k))

        # Check to see if the keys are in the primary result dict, if so,
        # we will remove them from the source_meta key, otherwise, we will
        # leave it be. Meant to reduce duplication of data when chaining
        # plugins.
        for k, v in kwargs.items():
            if k in worker_result:
                if v == worker_result[k]:
                    worker_result['source_meta'].pop(k, None)

            # Sometimes when chaining plugins source_meta will be appended
            # but the keys should be at the root of the results. Let's make
            # sure we move them to the root rather than storing them in the
            # source_meta
            elif k in ('filename', 'magic', 'ssdeep', 'path', 'size'):
                worker_result[k] = v
                worker_result['source_meta'].pop(k, None)

        worker_result['payload_id'] = 0

        results['tlp'] = tlp
        results['plugins'].update({"0": self.name})

        # Keep track of our total count of payloads, in case yara dispatch
        # finds something
        payload_id = 1

        results['results'].append(worker_result)

        # If we want to use the dispatcher, let's do that now
        if self.dispatch:
            self.log.debug("Dispatch: Beginning dispatching of payload...")
            # Our carver, extractor, and decoder plugins will return a list of
            # set()s. Let's make sure we handle the initial payload the same
            # way, so we can simplify the below routine.
            dispatch_payloads = [({}, payload)]

            # Track hashes of payloads so we don't handle duplicates.
            processed_hashes = {}

            while dispatch_payloads:
                self.log.debug("Dispatch: Count of payloads to dispatch: {}".format(len(dispatch_payloads)))
                for index, dispatch_payload in enumerate(dispatch_payloads):

                    dispatch_payloads.pop(index)

                    current_hash = dispatch_payload[0].get('sha1', get_sha1(dispatch_payload[1]))
                    # get the current parent uuid, so we can ensure any dispatched children are
                    # appended to the approriate list
                    dispatch_kwargs = kwargs.copy()
                    dispatch_kwargs['uuid'] = dispatch_payload[0].get('uuid', worker_result['uuid'])

                    if len(dispatch_kwargs['uuid']) > int(self.stoq.max_recursion):
                        self.log.debug("Dispatch: Maximum recursion depth of {} reached".format(self.stoq.max_recursion))
                        continue

                    self.log.debug("Dispatch: Current dispatch hash {}".format(current_hash))

                    # Skip over this payload if we've already processed it
                    if current_hash in processed_hashes:
                        self.log.info("Dispatch: Skipping duplicate hash {}".format(current_hash))
                        continue

                    processed_hashes.setdefault(current_hash, True)
                    # We are copy()ing processed hashes so we don't dispatch
                    # payloads twice, but we still want to be able to send
                    # dispatched payloads for additional processing
                    temp_processed_hashes = processed_hashes.copy()

                    # Send the payload to the yara dispatcher
                    for yara_result in self.yara_dispatcher(dispatch_payload[1]):
                        dispatch_result = self._parse_dispatch_results(yara_result, **dispatch_kwargs)

                        if dispatch_result['sha1'] in temp_processed_hashes:
                            self.log.info("Dispatch: Skipping duplicate hash: {}".format(dispatch_result['sha1']))
                            continue

                        temp_processed_hashes.setdefault(dispatch_result['sha1'], True)

                        dispatch_payloads.append(yara_result)

                        dispatch_result['payload_id'] = payload_id

                        if dispatch_result.get('save').lower() == 'true' and self.archive_connector:
                            self.save_payload(yara_result[1], self.archive_connector)

                        results['results'].append(dispatch_result)
                        results['plugins'].update({str(payload_id): dispatch_result['dispatcher']})

                        payload_id += 1

        results['payloads'] = payload_id

        # If we want the results for all plugins to be returned in one
        # big json blob, combined_results must be true.
        if self.combined_results:
            results, template_results = self._save_results(results)
        else:
            # Looks like we want to save each result individually, this
            # gets complex.
            split_results = []
            split_template_results = []

            # Make sure we save the top level key/values so we can append
            # them to the new individual result dict
            result_date = results['date']
            result_payloads = results['payloads']
            result_plugins = results['plugins']

            for result in results['results']:
                # Create the new individual results dict
                plugin_result = {}
                plugin_result['date'] = result_date
                plugin_result['payloads'] = result_payloads
                plugin_result['plugins'] = result_plugins
                plugin_result['results'] = [result]

                # Because this function returns the results, we are going
                # to save the individual results as it is returned from
                # the _save_results function
                r, t = self._save_results(plugin_result)

                # Append the results to the main results list. In many cases
                # templates won't be utilized, so no sense in saving them if
                # nothing is there.
                split_results.append(r)
                if t:
                    split_template_results.append(t)

            # Replace the original results with our newly created list of
            # results.
            results = split_results
            if split_template_results:
                template_results = split_template_results

        if self.log_level == 'DEBUG':
            etime = time.process_time()
            self.log.debug("Processed payload in {:.2f}s".format(etime))

        return results, template_results

    def _save_results(self, results, **kwargs):
        self.log.debug("Save: Attempting to save results")

        template_results = None

        plugin = results['results'][0].get('plugin', self.name)

        # Make sure we pass whether to append the date to the output connector
        kwargs.update({'use_date': self.use_output_date})

        # Some plugins will only be the plugin name itself. If it is a
        # dispatched result, it will contain the plugin category as well as the
        # plugin name.
        if plugin.count(':') == 1:
            plugin_cat, plugin_name = plugin.split(':')
            index = self.name
        else:
            plugin_name = plugin
            index = plugin_name

        # Parse output with a template
        if self.template:
            self.log.debug("Template: Attempting to templatize results")
            try:
                # Figure out the plugin path from the results plugin object
                if plugin in self.workers:
                    plugin_path = self.workers[plugin_name].plugin_path
                else:
                    plugin_path = self.plugin_path

                template_path = "{}/templates".format(plugin_path)

                tpl_env = Environment(loader=FileSystemLoader(template_path),
                                      trim_blocks=True, lstrip_blocks=True)
                template_results = tpl_env.get_template(self.template).render(results=results)
            except TemplateNotFound:
                self.log.error("Unable to load template. Does {}/{} exist?".format(template_path, self.template))
            except Exception as err:
                self.log.error(str(err))

        # If we are saving the results from the worker, let's take care of
        # it. This is defined in the .stoq configuration file for the
        # worker plugin. An output_connector must also be defined.
        if self.saveresults and self.output_connector:
            # Just to ensure we have loaded a connector for output
            self.load_connector(self.output_connector)

            if self.outfile:
                path = os.path.dirname(os.path.abspath(self.outfile))
                fn = os.path.basename(self.outfile)
                kwargs.update({'path': path, 'filename': fn, 'append': True})

            if template_results:
                self.connectors[self.output_connector].save(template_results,
                                                            index=index,
                                                            **kwargs)
            else:
                sha1 = results['results'][0].get('sha1', None)
                self.connectors[self.output_connector].save(results,
                                                            sha1=sha1,
                                                            index=index,
                                                            **kwargs)

        self.log.debug("Save: Results saved")
        return results, template_results

    def yara_dispatcher(self, payload, **kwargs):
        """
        Determine if a payload needs additional processing to extract
        or carve content from a payload

        :param bytes payload: Payload to be processed

        :returns: Set of metadata and content from plugin
        :rtype: Generator

        """

        self.yara_dispatcher_hits = []

        self.log.debug("Dispatch: Scanning payload with yara")
        self.yara_dispatcher_rules.match(data=payload, timeout=60,
                                         callback=self._dispatcher_callback)
        self.log.debug("Dispatch: Yara hits = {}".format(len(self.yara_dispatcher_hits)))

        for hit in self.yara_dispatcher_hits:
            if 'meta' in hit:
                plugin_kwargs = hit['meta']
                if 'plugin' in hit['meta']:
                    plugin_type, plugin_name = hit['meta']['plugin'].lower().split(":")
                else:
                    continue

            # Make sure this is a valid plugin category
            if plugin_type not in self.stoq.plugin_categories:
                self.log.error("{} is not a valid plugin type".format(plugin_type))
                continue

            self.log.debug("Dispatch: Sending payload to {}:{}".format(plugin_type, plugin_name))

            try:
                if plugin_type == 'carver':
                    self.load_carver(plugin_name)
                    content = self.carvers[plugin_name].carve(payload, **plugin_kwargs)
                elif plugin_type == 'extractor':
                    self.load_extractor(plugin_name)
                    content = self.extractors[plugin_name].extract(payload, **plugin_kwargs)
                elif plugin_type == 'decoder':
                    self.load_decoder(plugin_name)
                    content = self.decoders[plugin_name].decode(payload, **plugin_kwargs)
                else:
                    content = None
            except Exception:
                self.log.error("Unable to handle dispatched payload with "
                               "{}:{}".format(plugin_type, plugin_name), exc_info=True)
                content = None

            if content:
                self.log.debug("Dispatch: {} extracted items".format(len(content)))
                # Iterate over the results from the plugin and append the
                # yara rule metadata to it
                for meta in content:
                    dispatch_result = hit['meta'].copy()
                    # Make sure we hash the extracted content
                    dispatch_result.update(get_hashes(meta[1]))

                    dispatch_result['source_meta'] = {}

                    # Keep any metadata returned by the plugin as source_meta,
                    # but move some keys to the top lvel of the result.
                    for k, v in meta[0].items():
                        if k in ('filename', 'magic', 'ssdeep', 'path', 'size'):
                            dispatch_result[k] = v
                        else:
                            dispatch_result['source_meta'][k] = v

                    yield (dispatch_result, meta[1])

        # Cleanup
        self.yara_dispatcher_hits = None

    def _dispatcher_callback(self, data):
        if data['matches']:
            self.yara_dispatcher_hits.append(data)
        yara.CALLBACK_CONTINUE

    def _parse_dispatch_results(self, content, **kwargs):
        meta = content[0]
        meta['dispatcher'] = meta['plugin']
        meta['plugin'] = self.name
        # Make sure we append our new uuid to the uuid list, so we can track
        # parents and children
        meta['uuid'] = kwargs['uuid'].copy()
        meta['uuid'].append(self.stoq.get_uuid)
        meta['scan'] = self.scan(content[1])

        return meta


class StoqConnectorPlugin(StoqPluginBase):

    def connect(self):
        pass

    def disconnect(self):
        pass

    def save(self):
        pass


class StoqReaderPlugin(StoqPluginBase):

    def read(self):
        pass


class StoqSourcePlugin(StoqPluginBase, multiprocessing.Process):

    def ingest(self):
        pass


class StoqExtractorPlugin(StoqPluginBase):

    def extract(self):
        pass


class StoqCarverPlugin(StoqPluginBase):

    def carve(self):
        pass

    def carve_payload(self, regex, payload, ignorecase=False):
        """
        Generator that returns a list of offsets for a specified value
        within a payload

        :param bytes regex: Regular expression to search for
        :param bytes payload: Payload to be searched against
        :param bool ignorecase: True or False, use re.IGNORECASE

        :returns: Offset of value(s) discovered
        :rtype: generator

        """

        self.log.debug("Carve: Attempting to carve payload")
        try:
            payload = payload.read()
        except:
            pass

        if ignorecase:
            # Ignorecase, Multiline, Dot matches all
            flags = re.I|re.M|re.S
        else:
            # Multiline, Dot matches all
            flags = re.M|re.S

        for buff in re.finditer(regex, payload, flags):
            self.log.debug("Carve: Payload carve at offset {} - {}".format(buff.start(), buff.end()))
            yield buff.start(), buff.end()


class StoqDecoderPlugin(StoqPluginBase):

    def decode(self):
        pass

    def to_bytearray(self, payload):
        """
        Convert payload to a bytearray

        :param bytes payload: Payload to be converted into byte array

        :returns: Payload as a bytearray
        :rtype: bytearray

        """
        self.log.debug("Converting payload ({} bytes) to a bytearray".format(len(payload)))
        if isinstance(payload, bytearray):
            pass
        elif isinstance(payload, bytes):
            payload = bytearray(payload)

        else:
            payload = bytearray(payload.encode())

        return payload


class StoqPluginInstaller:

    import pip
    import glob
    import argparse
    import configparser

    def __init__(self, stoq):

        self.stoq = stoq
        self.plugin_info = {}

        parser = self.argparse.ArgumentParser()
        installer_opts = parser.add_argument_group("Plugin Installer Options")
        installer_opts.add_argument("plugin", help="stoQ Plugin Archive")
        installer_opts.add_argument("--upgrade",
                                    action="store_true",
                                    help="Upgrade the stoQ Plugin")

        options = parser.parse_args(self.stoq.argv[2:])

        if not options.plugin:
            parser.print_help()
            exit(-1)

        # Set the source path of the plugin archive/directory
        self.plugin = os.path.abspath(options.plugin)

        self.upgrade_plugin = options.upgrade

    def install(self):
        self.stoq.log.info("Looking for plugin in {}...".format(self.plugin))
        try:
            if os.path.isdir(self.plugin):
                self.setup_from_dir()
            else:
                self.stoq.log.critical("Unable to install plugin. Is this a valid plugin?")
                exit(-1)

            try:
                cmd = ['install', self.plugin, '-t', self.plugin_root,
                       '--quiet', '--allow-all-external']
                # Use pip to install/upgrade the plugin in the appropriate
                # directory for this plugin category
                if self.upgrade_plugin:
                    cmd.append('--upgrade')

                self.pip.main(cmd)

                # Time to install the requirements, if they exist.
                requirements = "{}/requirements.txt".format(self.plugin)
                if os.path.isfile(requirements):
                    self.pip.main(['install', '--quiet', '-r', requirements])

            except Exception as err:
                self.stoq.log.critical("Error installing requirements: {}".format(str(err)))
                exit(-1)

        except FileNotFoundError as err:
            self.stoq.log.critical(err)
            exit(-1)

        self.stoq.log.info("Install complete.")

    def setup_from_dir(self):
        # Find the stoQ configuration file
        config_file = self.glob.glob("{}/*/*.stoq".format(self.plugin))

        if len(config_file) > 1:
            self.stoq.log.critical("More than one stoQ configuration file found. Exiting.")
            exit(-1)

        if os.path.isfile(config_file[0]):
            # Open the stoQ configuration files and parse it
            with open(config_file[0], "rb") as config_content:
                self.parse_config(config_content.read())
        else:
            self.stoq.log.critical("Is this a valid configuration file? Exiting.")
            exit(-1)

        # Find the module name and set the plugin options
        module_root = os.path.join(self.plugin, self.plugin_name)
        module_path = os.path.join(module_root, self.plugin_module)
        with open(module_path, "rb") as module_content:
            self.set_plugin_category(module_content.read())

        self.set_plugin_path()

        self.save_plugin_info()

        return True

    def parse_config(self, stream):
        config = self.configparser.ConfigParser()
        config.read_string(stream.decode('utf-8'))
        try:
            self.plugin_name = config['Core']['Name']
            self.plugin_module = "{}.py".format(config['Core']['Module'])

            # We are going to use this to dynamically define data points in
            # setup.py
            self.plugin_info['NAME'] = self.plugin_name
            self.plugin_info['AUTHOR'] = config['Documentation']['Author']
            self.plugin_info['VERSION'] = config['Documentation']['Version']
            self.plugin_info['WEBSITE'] = config['Documentation']['Website']
            self.plugin_info['DESCRIPTION'] = config['Documentation']['Description']

        except Exception as err:
            self.stoq.log.critical("Is this a valid stoQ configuration file? {}".format(err))
            exit(-1)

    def save_plugin_info(self):
        # Let's create text files with the appropriate attributes so setup.py
        # can be more dynamic
        for option, value in self.plugin_info.items():
            with open(os.path.join(self.plugin, option), "w") as f:
                f.write(value)

    def set_plugin_category(self, plugin_stream):
        # We've extract the StoqPlugin class that is specific to our plugin
        # category, so now we can identity where the plugin will be
        # installed into
        try:
            plugin_type = re.search('(?<=from stoq\.plugins import )(.+)',
                                    plugin_stream.decode('utf-8')).group()
            self.plugin_category = self.stoq.__plugindict__[plugin_type]
        except Exception as err:
            self.stoq.log.critical("Unable to determine the category. Is this a valid plugin? {}".format(err))
            exit(-1)

    def set_plugin_path(self):
        self.plugin_root = os.path.join(self.stoq.plugin_dir,
                                        self.plugin_category)

        self.stoq.log.info("Installing {} plugin into {}...".format(self.plugin_name, self.plugin_root))
