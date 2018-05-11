import os
import time
import signal
import itertools
import threading
import multiprocessing

from stoq.exceptions import SigtermCaught
from stoq import signal_handler, __version__
from stoq.plugins.base import StoqPluginBase
from stoq.helpers import ratelimited, flatten
from stoq.scan import get_hashes, get_ssdeep, get_magic, get_sha1

try:
    import yara
    yara_imported = True
except ImportError:
    yara = None
    yara_imported = False

try:
    from jinja2 import Environment, FileSystemLoader
    from jinja2.exceptions import TemplateNotFound
    jinja_imported = True
except ImportError:
    jinja_imported = False


class StoqWorkerPlugin(StoqPluginBase):
    """
    stoQ Worker Plugin Class

    """

    def __init__(self):
        super().__init__()

        self.max_processes = 0
        self.dispatch = None
        self.output_connector = None
        self.decorator_plugin = None
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
        self.results_file = None
        self.use_output_date = False
        self.flatten_results = False
        self.flatten_delimiter = False
        self.ingest_metadata = None

        self.workers = {}
        self.connectors = {}
        self.sources = {}
        self.readers = {}
        self.extractors = {}
        self.carvers = {}
        self.decoders = {}
        self.decorators = {}

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
            self.log.warning("Failed to load yara-python, dispatching will not work. "
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

        if self.decorator_plugin:
            self.load_decorator(self.decorator_plugin)

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

        # If an outfile is defined on the command line, let's make sure we update
        # where stoQ places results
        if self.outfile:
            abspath = os.path.abspath(self.outfile)
            self.stoq.results_dir = abspath

            # Looks like the user wants results to be appended to a file. Ensure
            # we update the results_dir and results_file to ensure they get saved
            # there if the output connector supports it
            if os.path.isfile(abspath):
                self.results_file = os.path.basename(abspath)
                self.stoq.results_dir = os.path.dirname(abspath)

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
                self.log.warning("Unable to parse ingest metadata, skipping: {}".format(err))

        if self.template and not jinja_imported:
            self.log.warning("Templates will not work. jinja2 must be installed first.")
            self.template = False

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
            self.log.warning("Keyboard interrupt received..attempting graceful shutdown")
        except SigtermCaught:
            self.log.warning("SIGTERM Caught..attempting graceful shutdown")
        except Exception as err:
            self.log.critical(err, exc_info=True)
        finally:
            self.log.debug("Cleaning up multiprocess queue")
            if procs:
                for proc in procs:
                    proc.terminate()
                    proc.join()
            return True

    def _deactivate_everything(self):
        # call all plugin deactivate methods, so that they can
        # finish their work before we terminate.
        for category in self.stoq.plugin_categories:
            full_category_name = category + "s"
            plugin_category = getattr(self, full_category_name, None)
            if plugin_category:
                for plugin in plugin_category:
                    if plugin_category[plugin]:
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
        while self.mp_queues.qsize() >= int(self.stoq.max_queue):
            self.log.debug("Queue maximum size ({}) reached. Sleeping...".format(self.stoq.max_queue))
            time.sleep(1)

        # Ensure ratelimit is defined
        kwargs['ratelimit'] = self.ratelimit

        self.mp_queues.put(kwargs)

    def scan(self, *args, **kwargs):
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

    def load_decorator(self, decorator):
        """
        Load a decorator plugin

        :param str decorator: The name of decorator plugin to be loaded

        :returns: True

        """

        if decorator not in self.decorators:
            self.decorators[decorator] = self.stoq.load_plugin(decorator, 'decorator')
            # Define the parent plugin within the plugin so we can use it
            # should multiple worker plugins be loaded
            self.decorators[decorator].parentname = self.name

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
        :param str tlp: TLP Level of results
        :param str ratelimit: Rate limit processing (count/per seconds)
        :param str archive: Connector plugin to use as a source for the payload
        :param str filename: File name, if available, for the payload
        :param str path: Path the file is being ingested from
        :param str/list uuid: UUID for this result, and any parent results

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
        results = {}
        worker_result = {}

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
                self.log.warning("Connector unable to get file..skipping")
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
        # Send our payload to the worker. This should return a generator or list
        # if the results are to be processed.
        scan_results = self.scan(payload, **kwargs)

        # Make sure the scan_result is a list so we can iterate over them
        # in case a plugin produces more than one result
        if type(scan_results) in (dict, str):
            scan_results = [scan_results]
        elif not scan_results:
            # If a worker plugin returns None or False, move on, but let the user
            # know as something could be wrong.
            self.log.debug("No results returned, moving on...")
            return False
        elif scan_results is True:
            # Some plugins don't save results or require additional processing.
            # These plugins should return True so we can silently go on about our day.
            return True

        for scan_result in scan_results:
            results['results'] = []
            results['plugins'] = {}

            # If we don't have a uuid, let's generate one
            uid = kwargs.get('uuid', self.stoq.get_uuid)
            if isinstance(uid, str):
                self.log.debug("Adding UUID {}".format(uid))
                kwargs['uuid'] = [uid]

            worker_result['scan'] = scan_result

            results['date'] = self.stoq.get_time

            worker_result['uuid'] = kwargs['uuid'].copy()
            worker_result['plugin'] = self.name

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
                recursion_level = 0

                while dispatch_payloads:
                    self.log.debug("Dispatch: Count of payloads to dispatch: {}".format(len(dispatch_payloads)))
                    for index, dispatch_payload in enumerate(dispatch_payloads):

                        dispatch_payloads.pop(index)

                        current_hash = dispatch_payload[0].get('sha1', get_sha1(dispatch_payload[1]))
                        # get the current parent uuid, so we can ensure any dispatched children are
                        # appended to the approriate list
                        dispatch_kwargs = kwargs.copy()
                        dispatch_kwargs['uuid'] = dispatch_payload[0].get('uuid', worker_result['uuid'])
                        # The dispatch args are empty for the initial payload,
                        # so only overwrite if we have a value
                        if 'filename' in dispatch_payload[0]:
                            dispatch_kwargs['filename'] = dispatch_payload[0].get('filename')

                        if recursion_level > int(self.stoq.max_recursion):
                            self.log.debug(
                                "Dispatch: Maximum recursion depth of {} reached".format(self.stoq.max_recursion))
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
                        for dispatch_result, dispatch_content in self.yara_dispatcher(dispatch_payload[1], **dispatch_kwargs):

                            # Create a key based on the sha1 hash of the payload, and
                            # the dispatched plugin.
                            hash_key = "{}-{}".format(
                                dispatch_result['sha1'], dispatch_result['dispatcher'])

                            # Make sure a previously handled payload or dispatched payload has
                            # not already been handled. If so, let's skip the results.
                            if dispatch_result['sha1'] in temp_processed_hashes or hash_key in temp_processed_hashes:
                                 self.log.info(
                                     "Dispatch: Skipping duplicate hash: {}".format(dispatch_result['sha1']))
                                 continue

                            # Ensure we add this hash key to our processed results
                            temp_processed_hashes.setdefault(hash_key, True)

                            dispatch_payloads.append((dispatch_result, dispatch_content))

                            dispatch_result['payload_id'] = payload_id

                            if dispatch_result.get('save', '').lower() == 'true' and self.archive_connector:
                                self.save_payload(dispatch_content, self.archive_connector)

                            results['results'].append(dispatch_result)
                            results['plugins'].update({str(payload_id): dispatch_result['dispatcher']})

                            payload_id += 1

                    # Increment the recursion level to make sure we don't go too deep
                    recursion_level += 1

            results['payloads'] = payload_id

            if self.decorator_plugin in self.decorators:
                results = self.decorators[self.decorator_plugin].decorate(results)

            # If we want the results for all plugins to be returned in one
            # big json blob, combined_results must be true.
            if self.combined_results:
                # We will overwrite results with what is returned in order to
                # support post processing results, such as with flattening
                # and templates.
                results = self._save_results(results)
            else:
                results_list = []
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

                    results_list.append(self._save_results(plugin_result))

                results = results_list

            if self.log_level == 'DEBUG':
                etime = time.process_time()
                self.log.debug("Processed payload in {:.2f}s".format(etime))

        return results

    def _save_results(self, results, **kwargs):
        self.log.debug("Save: Attempting to save results")

        plugin = results['results'][0].get('plugin', self.name)
        sha1 = results['results'][0].get('sha1', None)

        # Make sure we pass whether to append the date to the output connector
        kwargs.update({'use_date': self.use_output_date})

        # Some plugins will only be the plugin name itself. If it is a
        # dispatched result, it will contain the plugin category as well as the
        # plugin name.
        if plugin.count(':') == 1:
            _, plugin_name = plugin.split(':')
            index = self.name
        else:
            plugin_name = plugin
            index = plugin_name

        if self.flatten_results:
            self.log.debug("Save: flattening results")
            results = flatten(results, delim=self.flatten_delimiter)

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

                tpl = Environment(
                    loader=FileSystemLoader(template_path), trim_blocks=True, lstrip_blocks=True)

                results = tpl.get_template(self.template).render(results=results)

            except TemplateNotFound:
                # Set to False so we don't repeatedly try to render the template
                self.template = False
                self.log.error("Unable to load template. Does {}/{} exist?".format(
                    template_path, self.template))
            except Exception as err:
                # Set to False so we don't repeatedly try to render the template
                self.template = False
                self.log.error(str(err))
                results = None

        # If we are saving the results from the worker, let's take care of
        # it. This is defined in the .stoq configuration file for the
        # worker plugin. An output_connector must also be defined.
        if self.saveresults and self.output_connector:
            # Just to ensure we have loaded a connector for output
            self.load_connector(self.output_connector)

            if self.results_file:
                kwargs.update({'filename': self.results_file, 'append': True})

            self.connectors[self.output_connector].save(
                results, sha1=sha1, index=index, **kwargs)

        self.log.debug("Save: Results saved")

        return results

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
            dispatch_plugins = []
            plugin_list = []

            if 'meta' in hit:
                plugin_kwargs = hit['meta']
                plugin_kwargs.update(kwargs)
                if 'plugin' in hit['meta']:
                    # In some instances multiple plugins may be loaded from a single
                    # yara dispatcher hit. Let's split the `plugin` attribute to ensure
                    # we load all of the appropriate plugins for dispatching. This will
                    # result in a list similar to:
                    # `["decoder:b64", "carver:pe"]`
                    dispatch_plugins = hit['meta']['plugin'].lower().split(",")

                    # Now that we have a list of plugins for dispatching, let's split
                    # again, this time by `:` so we have another list of plugin types
                    # and plugin names. This will result in a list similar to:
                    # `[("decoder", "b64"), ("carver", "pe")]`
                    for meta in dispatch_plugins:
                        try:
                            meta_plg = meta.split(":")
                            plugin_list.append((meta_plg[0].strip(), meta_plg[1].strip()))
                        except:
                            self.log.debug("Invalid dispatch plugin syntax, skipping: {}".format(meta))

                    # Ensure we have no duplicate plugins
                    plugin_list.sort()
                    plugin_list = list(plugin_list for plugin_list,_ in itertools.groupby(plugin_list))
                else:
                    continue

            for plugin_type, plugin_name in plugin_list:
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
                        dispatch_result['dispatcher'] = "{}:{}".format(plugin_type, plugin_name)
                        dispatch_result['plugin'] =  self.name
                        dispatch_result['uuid'] = kwargs['uuid'].copy()
                        dispatch_result['uuid'].append(self.stoq.get_uuid)
                        dispatch_result['scan'] = self.scan(meta[1])

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

                        yield dispatch_result, meta[1]

        # Cleanup
        self.yara_dispatcher_hits = None

    def _dispatcher_callback(self, data):
        if data['matches']:
            self.yara_dispatcher_hits.append(data)
        yara.CALLBACK_CONTINUE
