#   Copyright 2014-2015 PUNCH Cyber Analytics Group
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
instatiated outside of |stoQ| as it relies on objects within *Stoq()* to
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
    payload = worker.connectors['mongodb'].get_file(sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709")
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
import multiprocessing

try:
    import yara
    yara_imported = True
except ImportError:
    yara = None
    yara_imported = False

from yapsy.PluginManager import PluginManager
from yapsy.FilteredPluginManager import FilteredPluginManager

from jinja2 import Environment, FileSystemLoader
from jinja2.exceptions import TemplateNotFound

# noinspection PyUnresolvedReferences
from stoq.scan import get_hashes, get_ssdeep, get_magic, get_sha1


# noinspection PyUnresolvedReferences
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

        self.manager.deactivatePluginByName(name, category)

    def load_plugin(self, name, category):
        """
        Load the desired plugin

        :param str name: Plugin name to be loaded
        :param str category: The category of plugin to be loaded

        :returns: The loaded plugin object
        :rtype: object

        """

        # We are going to dynamically reimplement the isPluginOk method
        # so only the needed plugins are loaded into memory. Much faster
        # and efficient
        self.manager.isPluginOk = lambda x: x.name == name

        # Gather, filter, and load plugin
        self.manager.locatePlugins()
        self.manager.filterPlugins()
        self.manager.loadPlugins()

        # Initialize our plugin
        plugin = self.get_plugin(name, category)

        if not plugin:
            self.log.warn("Plugin {}:{} failed to load".format(category, name))
            return False

        for sect in plugin.details.sections():
            # Let's skip over the sections that are required by our
            # plugin manager. No sense in trying to overwrite.
            if any([s in sect for s in ['Core', 'Documentation']]):
                continue

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
        super().__init__()

    def activate(self):
        self.is_activated = True
        self.stoq.log.debug("Plugin Activated: {0},{1}".format(self.name,
                                                               self.is_activated))

    def deactivate(self):
        self.is_activated = False
        self.stoq.log.debug("Plugin Deactivated: {0},{1}".format(self.name,
                                                                 self.is_activated))

    def heartbeat(self, force=False):
        pass


# noinspection PyUnresolvedReferences,PyUnresolvedReferences
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

        self.yara_dispatcher_rules = None

        self.yara_dispatcher_hits = None

        self.mp_queues = None

        self.connector_queue = None

        self.connector_feeder = None

        self.workers = {}
        self.connectors = {}
        self.sources = {}
        self.readers = {}
        self.extractors = {}
        self.carvers = {}
        self.decoders = {}

    @property
    def min_version(self):
        return None

    @property
    def max_version(self):
        return None

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

        if not self.max_processes:
            # Let's set the max_processes to 50% of total CPUs
            self.max_processes = int(multiprocessing.cpu_count() / 2)
            if self.max_processes < 1:
                self.max_processes = 1
        else:
            self.max_processes = int(self.max_processes)

        # yara-python is not installed, dispatching is not supported
        if not yara_imported:
            self.dispatch = False

        # This is the first worker be initialized, so it will be the primary
        # one. Additional worker plugins can be loaded, but they will not be
        # accessible globally.
        if not self.stoq.worker:
            # Make sure we are accessible to the framework
            self.stoq.worker = self

        # If our worker saves it's results let's initialize and load the
        # connector plugin
        if self.saveresults:
            # If no connector was defined by the worker, let's use the
            # framework's default one.
            if not self.output_connector:
                self.output_connector = self.stoq.default_connector
            self.load_connector(self.output_connector)

        # If the worker wants to archive files, let's load that connector
        # now
        if self.archive_connector:
            self.load_connector(self.archive_connector)

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

        if self.dispatch:
            with open(self.stoq.dispatch_rules) as rules:
                self.yara_dispatcher_rules = yara.compile(file=rules)

        for connector in self.connectors:
            connObj = self.connectors[connector]
            if hasattr(connObj, "wants_heartbeat") and connObj.wants_heartbeat:
                connObj = self.connectors[connector]
                thread = threading.Thread(target=connObj.heartbeat,
                                          args=(connObj),
                                          daemon=True)
                connObj.heartbeat_thread = thread
                thread.start()

        for worker in self.workers:
            workerObj = self.workers[worker]
            if hasattr(workerObj, "wants_heartbeat") and workerObj.wants_heartbeat:
                thread = threading.Thread(target=workerObj.heartbeat,
                                          args=(workerObj),
                                          daemon=True)
                workerObj.heartbeat_thread = thread
                thread.start()

        return self

    def deactivate(self):
        """
        Deactivate the plugin within the framework

        """
        super().deactivate()

    @property
    def run(self):
        """
        Run the plugin with a source plugin, or standalone

        """

        procs = None

        try:
            # There are some conditions where a source plugin may not be loaded
            # yet. Verify we have one loaded, if needed.
            if self.source_plugin:
                self.load_source(self.source_plugin)

            # See if we have loaded any source plugins.
            if self.sources:
                self.mp_queues = multiprocessing.JoinableQueue()
                if self.sources[self.source_plugin].multiprocess:
                    procs = [multiprocessing.Process(target=self._multiprocess,
                                                     args=(self.mp_queues,))
                             for _ in range(self.max_processes)]

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
                self.start()

        except KeyboardInterrupt:
            self.stoq.log.info("Keyboard interrupt received..terminating processes")
            # call all connector/decoder/etc deactivate methods, so that they can
            # finish their work before we terminate.
            for source in self.sources:
                self.sources[source].deactivate()
            for reader in self.readers:
                self.readers[reader].deactivate()
            for decoder in self.decoders:
                self.decoders[decoder].deactivate()
            for extractor in self.extractors:
                self.extractors[extractor].deactivate()
            for carver in self.carvers:
                self.carvers[carver].deactivate()
            for connector in self.connectors:
                self.connectors[connector].deactivate()
            for worker in self.workers:
                self.workers[worker].deactivate()
        finally:
            if procs:
                for proc in procs:
                    proc.terminate()
                    proc.join()
            return None

    def _multiprocess(self, queue):
        while True:
            msg = queue.get()
            should_stop = msg.get("_stoq_multiprocess_eoq", False)
            if should_stop:
                return
            self.start(**msg)

    def multiprocess_put(self, **kwargs):
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

        arc = get_hashes(payload)

        # Let's make sure we add some additional metadata so we don't need
        # to create this later.
        arc['ssdeep'] = get_ssdeep(payload)
        arc['content-type'] = get_magic(payload)

        # Make sure our connector is loaded
        self.load_connector(connector)

        # Save our payload to the appropriate plugin
        res = self.connectors[connector].save(payload, archive=True, **arc)

        arc['conn_id'] = res

        return arc

    # Handle our worker and process the results
    def start(self, payload=None, **kwargs):
        """
        Process the payload with the worker plugin

        :param bytes payload: (optional) Payload to be processed
        :param \*\*kwargs: addtional arguments that may be needed by the
                           worker plugin (i.e., username and password via HTTP)
        :type kwargs: dict or None

        :returns: Tuple of JSON results and template rendered results
        :rtype: dict and str

        """

        archive_type = False
        template_results = None
        payload_hashes = None
        results = {"results": []}
        worker_result = {}

        results['date'] = self.stoq.get_time

        # If we don't have a uuid, let's generate one
        if 'uuid' not in kwargs:
            kwargs['uuid'] = self.stoq.get_uuid

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
                payload = self.connectors[archive_type].get_file(**kwargs)
            else:
                self.stoq.log.warn("Connector unable to get file..skipping")
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

        # Send our payload to the worker, and store the results
        worker_result['scan'] = self.scan(payload, **kwargs)

        worker_result['plugin'] = self.name
        worker_result['uuid'] = kwargs['uuid']

        if payload:
            worker_result['size'] = len(payload)

        # Preserve the original metadata that was submitted with this payload
        worker_result['source_meta'] = kwargs.copy()

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
            elif k in ('filename', 'puuid', 'magic', 'ssdeep', 'path'):
                worker_result[k] = v
                worker_result['source_meta'].pop(k, None)

        worker_result['payload_id'] = 0

        # Keep track of our total count of payloads, in case yara dispatch
        # finds something
        payload_id = 1

        results['results'].append(worker_result)

        # If we want to use the dispatcher, let's do that now
        if self.dispatch:
            # Our carver, extractor, and decoder plugins will return a list of
            # set()s. Let's make sure we handle the initial payload the same
            # way, so we can simplify the below routine.
            dispatch_payloads = [({}, payload)]
            dispatch_queue = []

            current_depth = 0

            # Track hashes of payloads so we don't handle duplicates.
            processed_hashes = {}

            while dispatch_payloads and int(self.stoq.max_recursion) >= current_depth:
                for index, dispatch_payload in enumerate(dispatch_payloads):

                    dispatch_payloads.pop(index)

                    current_hash = dispatch_payload[0].get('sha1', get_sha1(dispatch_payload[1]))

                    # Skip over this payload if we've already processed it
                    if current_hash in processed_hashes:
                        self.stoq.log.info("Skipping duplicate hash: {}".format(current_hash))
                        continue

                    processed_hashes.setdefault(current_hash, True)
                    # We are copy()ing processed hashes so we don't dispatch
                    # payloads twice, but we still want to be able to send
                    # dispatched payloads for additional processing
                    temp_processed_hashes = processed_hashes.copy()

                    # Send the payload to the yara dispatcher
                    for yara_result in self.yara_dispatcher(dispatch_payload[1]):
                        dispatch_result = self._parse_dispatch_results(yara_result, **kwargs)

                        if dispatch_result['sha1'] in temp_processed_hashes:
                            self.stoq.log.info("Skipping duplicate hash: {}".format(dispatch_result['sha1']))
                            continue

                        temp_processed_hashes.setdefault(dispatch_result['sha1'], True)

                        dispatch_queue.append(yara_result)

                        dispatch_result['payload_id'] = payload_id
                        payload_id += 1

                        if dispatch_result.get('save').lower() == 'true' and self.archive_connector:
                            self.save_payload(yara_result[1], self.archive_connector)

                        results['results'].append(dispatch_result)

                dispatch_payloads = dispatch_queue.copy()
                dispatch_queue = []

                current_depth += 1

        results['payloads'] = payload_id

        # Parse output with a template
        if self.template:
            template_path = "{}/templates".format(self.plugin_path)
            try:
                tpl_env = Environment(loader=FileSystemLoader(template_path),
                                      trim_blocks=True, lstrip_blocks=True)
                template_results = tpl_env.get_template(self.template).render(results=results)
            except TemplateNotFound:
                self.stoq.log.error("Unable to load template. Does {}/{} "
                                    "exist?".format(template_path, self.template))
            except Exception as err:
                self.stoq.log.error(str(err))

        # If we are saving the results from the worker, let's take care of
        # it. This is defined in the .stoq configuration file for the
        # worker plugin. An output_connector must also be defined.
        if self.saveresults and self.output_connector:
            # Just to ensure we have loaded a connector for output
            self.load_connector(self.output_connector)

            if template_results:
                self.connectors[self.output_connector].save(template_results)
            else:
                # Attempt to save the results, and pass along the primary
                # results as **kwargs, otherwise just pass along the results.
                try:
                    kwargs = {'sha1': results['results'][0]['sha1']}
                    self.connectors[self.output_connector].save(results,
                                                                **kwargs)
                except (KeyError, IndexError):
                    self.connectors[self.output_connector].save(results)

        return results, template_results

    def yara_dispatcher(self, payload, **kwargs):
        """
        Determine if a payload needs additional processing to extract
        or carve content from a payload

        :param bytes payload: Payload to be processed
        :param \*\*kwargs: addtional arguments that may be needed
        :type kwargs: dict or None

        :returns: Set of metadata and content from plugin
        :rtype: Generator

        """

        self.yara_dispatcher_hits = []

        self.yara_dispatcher_rules.match(data=payload, timeout=60,
                                         callback=self._dispatcher_callback)

        for hit in self.yara_dispatcher_hits:
            if 'meta' in hit:
                plugin_kwargs = hit['meta']
                if 'plugin' in hit['meta']:
                    plugin_type, plugin_name = hit['meta']['plugin'].lower().split(":")
                else:
                    continue

            # Make sure this is a valid plugin category
            if plugin_type not in self.stoq.plugin_categories:
                self.stoq.log.error("{} is not a valid plugin type".format(plugin_type))
                continue

            if plugin_type == 'carver':
                self.load_carver(plugin_name)
                try:
                    content = self.carvers[plugin_name].carve(payload, **plugin_kwargs)
                except:
                    content = None
            elif plugin_type == 'extractor':
                self.load_extractor(plugin_name)
                try:
                    content = self.extractors[plugin_name].extract(payload, **plugin_kwargs)
                except:
                    content = None
            elif plugin_type == 'decoder':
                self.load_decoder(plugin_name)
                try:
                    content = self.decoders[plugin_name].decode(payload, **plugin_kwargs)
                except:
                    content = None
            else:
                content = None

            if content:
                # Iterate over the results from the plugin and append the
                # yara rule metadata to it
                for meta in content:
                    dispatch_result = hit['meta'].copy()
                    # Make sure we hash the extracted content
                    dispatch_result.update(get_hashes(meta[1]))
                    # Keep any metadata returned by the plugin as source_meta
                    dispatch_result['source_meta'] = meta[0]
                    yield (dispatch_result, meta[1])

        # Cleanup
        self.yara_dispatcher_hits = None

    def _dispatcher_callback(self, data):
        if data['matches']:
            self.yara_dispatcher_hits.append(data)
        yara.CALLBACK_CONTINUE

    def _parse_dispatch_results(self, content, **kwargs):
        meta = content[0]
        meta['puuid'] = kwargs['uuid']
        meta['uuid'] = self.stoq.get_uuid
        meta['scan'] = self.scan(content[1])

        return meta


class StoqConnectorPlugin(StoqPluginBase):
    @property
    def min_version(self):
        return None

    @property
    def max_version(self):
        return None

    def activate(self):
        super().activate()

    def deactivate(self):
        super().deactivate()

    def connect(self):
        pass

    def disconnect(self):
        pass

    def save(self):
        pass


class StoqReaderPlugin(StoqPluginBase):
    @property
    def min_version(self):
        return None

    @property
    def max_version(self):
        return None

    def activate(self):
        super().activate()

    def deactivate(self):
        super().deactivate()

    def read(self):
        pass


class StoqSourcePlugin(StoqPluginBase, multiprocessing.Process):
    @property
    def min_version(self):
        return None

    @property
    def max_version(self):
        return None

    def activate(self):
        super().activate()

    def deactivate(self):
        super().deactivate()

    def ingest(self):
        pass


class StoqExtractorPlugin(StoqPluginBase):
    @property
    def min_version(self):
        return None

    @property
    def max_version(self):
        return None

    def activate(self):
        super().activate()

    def deactivate(self):
        super().deactivate()

    def extract(self):
        pass


class StoqCarverPlugin(StoqPluginBase):
    @property
    def min_version(self):
        return None

    @property
    def max_version(self):
        return None

    def activate(self):
        super().activate()

    def deactivate(self):
        super().deactivate()

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
            yield buff.start(), buff.end()


class StoqDecoderPlugin(StoqPluginBase):
    @property
    def min_version(self):
        return None

    @property
    def max_version(self):
        return None

    def activate(self):
        super().activate()

    def deactivate(self):
        super().deactivate()

    def decode(self):
        pass

    def to_bytearray(self, payload):
        """
        Convert payload to a bytearray

        :param bytes payload: Payload to be converted into byte array

        :returns: Payload as a bytearray
        :rtype: bytearray

        """
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
    from zipfile import ZipFile

    def __init__(self, stoq):

        self.stoq = stoq
        self.plugin_info = {}

        self.plugin_module = None
        self.plugin_name = None
        self.plugin_category = None
        self.plugin_root = None

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
        print("[+] Looking for plugin in {}...".format(self.plugin))
        try:
            if os.path.isdir(self.plugin):
                self.setup_from_dir()
            else:
                print("[!] Unable to install plugin. Is this a valid plugin?")
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
                print("[!] Error installing requirements: {}".format(str(err)))
                exit(-1)

        except FileNotFoundError as err:
            print(str(err))
            exit(-1)

        print("[+] Install complete.")

    def setup_from_dir(self):
        # Find the stoQ configuration file
        config_file = self.glob.glob("{}/*/*.stoq".format(self.plugin))

        if len(config_file) > 1:
            print("[!] More than one stoQ configuration file found. Exiting.")
            exit(-1)

        if os.path.isfile(config_file[0]):
            # Open the stoQ configuration files and parse it
            with open(config_file[0], "rb") as config_content:
                self.parse_config(config_content.read())
        else:
            print("[!] Is this a valid configuration file? Exiting.")
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
            print(str(err))
            print("[!] Is this a valid stoQ configuration file? Exiting...")
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
            print(str(err))
            print("Unable to determine the category. Is this a valid plugin?")
            exit(-1)

    def set_plugin_path(self):
        self.plugin_root = os.path.join(self.stoq.plugin_dir,
                                        self.plugin_category)

        print("[+] Installing {} plugin into {}...".format(self.plugin_name,
                                                           self.plugin_root))
