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

A stoQ Interactive Shell

Examples
========

Instantiate a stoQ Interactive Shell session::

    $ ./stoq-cli.py shell

     .d8888b.  888             .d88888b.
    d88P  Y88b 888            d88P" "Y88b
    Y88b.      888            888     888
     "Y888b.   888888 .d88b.  888     888
        "Y88b. 888   d88""88b 888     888
          "888 888   888  888 888 Y8b 888
    Y88b  d88P Y88b. Y88..88P Y88b.Y8b88P
     "Y8888P"   "Y888 "Y88P"   "Y888888"
                                     Y8b
            Analysis. Simplified.


    [stoQ] >

List all available plugins::

    [stoQ] > list
    Available Plugins:
    connectors
    - stdout              v0.9    Sends content to STDOUT
    - file                v0.9    Retrieves and saves content to local disk
    extractors
    - decompress          v0.9    Extract content from a multitude of archive formats
    - gpg                 v0.1    Handle GnuPG encrypted content
    carvers
    - pe                  v0.9    Carve portable executable files from a data stream
    - swf                 v0.9    Carve and decompress SWF payloads
    - ole                 v0.9    Carve OLE streams within Microsoft Office Documents
    - xdp                 v0.9    Carve and decode streams from XDP documents
    - rtf                 v0.9    Carve hex/binary streams from RTF payloads
    readers
    - pdftext             v0.9    Extract text from a PDF document
    - tika                v0.1    Upload content to a Tika server for automated text extraction
    - iocregex            v0.9    Regex routines to extract and normalize IOC's from a payload
    sources
    - rabbitmq            v0.9    Publish and Consume messages from a RabbitMQ Server
    - dirmon              v0.9    Monitor a directory for newly created files for processing
    - filedir             v0.9    Ingest a file or directory for processing
    workers
    - peinfo              v0.9    Gather relevant information about an executable using pefile
    - exif                v0.9    Processes a payload using ExifTool
    - publisher           v0.9    Publish messages to single or multiple RabbitMQ queues for processing
    - trid                v0.4    Identify file types from their TrID signature
    - xorsearch           v0.9    Search a payload for XOR'd strings
    - yara                v0.9    Process a payload using yara
    - iocextract          v0.9    Utilizes reader/iocregex plugin to extract indicators of compromise from documents
    decoders
    - rot47               v0.1    Decode ROT47 encoded content
    - bitwise_rotate      v0.1    Rotate bits left or right. Defaults to 4 bits right for nibble swapping.
    - b64                 v0.1    Decode base64 encoded content
    - b85                 v0.1    Decode base85 encoded content
    - xor                 v0.1    Decode XOR encoded content


Load the yara plugin::

    [stoQ] > load worker yara


Conduct a simple scan of a payload using only the yara plugin::

    [stoQ] > read /tmp/bad.exe
    [*] Read /tmp/bad.exe(510968 bytes)
    [*] sha1: 074c5b3707ebcda408a186082e529cf8ae5859ed
    [*] sha256: 3cb2eb909ea3cfac42621ed4d024ed9d15a2005cc91a54050ef75fc9bee695b7
    [*] sha512: 53fcb7f9087b5f356067f6f2cd288575e97876fdad9e1376231923e414b541b0fdba7f17095daba0899155f2cde11efb5d4fcad1bfd3390e59c5a894d8bc1c1d
    [*] md5: 0b40e4e5987e7fb14b7a9b9b9218c703
    [*] magic: application/x-dosexec
    [stoQ] > run worker yara
    [stoQ] > results
    { "hits" : [ {
            "matches" : true,
            "meta" : {
                    "author" : "PUNCH Cyber Analytics Group",
                    "cve" : "N/A",
                    "description" : "Badness",
                    "type" : "Suspicious String",
                    "version" : "1.0",
                    "weight" : 100
                    },
            "namespace" : "default",
            "rule" : "win_api_LoadLibrary",
            "strings" : [
                    [
                        "23967",
                        "$LoadLibrary",
                        "b'LoadLibrary'"
                    ],
                ],
            "tags" : [  ]
            } ],
        }


Display all available settings::

    [stoQ] > set
    worker.yara.saveresults = True
    worker.yara.max_processes = 1
    worker.yara.website = https://github.com/PUNCH-Cyber/stoq-plugins-public
    worker.yara.templates = plugins/worker/yara/templates/
    worker.yara.carvers = {}
    worker.yara.template = False
    worker.yara.readers = {}
    worker.yara.plugin_path = /usr/local/stoq/plugins/worker/yara
    worker.yara.dispatch = False
    worker.yara.version = 0.9
    worker.yara.description = Process a payload using yara
    worker.yara.yararules = plugins/worker/yara/rules/stoq.yar
    worker.yara.name = yara
    worker.yara.path = False
    worker.yara.module = /usr/local/stoq/plugins/worker/yara/yarascan
    worker.yara.extractors = {}
    worker.yara.archive_connector = False
    worker.yara.source_plugin = False
    worker.yara.workers = {}
    worker.yara.decoders = {}
    worker.yara.category = worker
    worker.yara.log_level = False
    worker.yara.hashpayload = True
    worker.yara.is_activated = True
    worker.yara.output_connector = stdout
    worker.yara.author = Marcus LaFerrera
    worker.yara.error_queue = False
    worker.yara.sources = {}
    stoq.config_file = /usr/local/stoq/stoq.cfg
    stoq.default_connector = stdout
    stoq.log_dir = /usr/local/stoq/logs
    stoq.log_maxbytes = 1500000
    stoq.log_path = /usr/local/stoq/logs/stoq.log
    stoq.base_dir = /usr/local/stoq
    stoq.useragent = Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.1)
    stoq.url_prefix_tuple = http://, https://
    stoq.results_dir = /usr/local/stoq/results
    stoq.temp_dir = /usr/local/stoq/temp
    stoq.dispatch_rules = /usr/local/stoq/dispatcher.yar
    stoq.default_source = filedir
    stoq.log_level = INFO
    stoq.log_backup_count = 5
    stoq.source_base_tuple = /usr/local/stoq
    stoq.max_recursion = 3
    stoq.plugin_dir = /usr/local/stoq/plugins
    stoq.archive_base = /usr/local/stoq/archive


Update a configuration setting::

    [stoQ] > set stoq.log_level DEBUG
    stoq.log_level -> DEBUG


Save results, to include any payloads that may have been
carved/extracted/decoded. If mutiple results have been processed, the integer
will be incremented and correspond to the payload id viewable in the
``results`` command::

    [stoQ] > save
    [*] Saving content to /usr/local/stoq/results/results-0-bad.exe


Now's let pass arguments to a plugin. In this instance we want to XOR a
payload using a specific XOR key::

    [stoQ] > run decoder xor key=2
    [*] Run using xor complete. View results with 'results'


List contents of a directory::

    [stoQ] > ls /tmp
    bad.exe

"""

import os
import cmd
import time

from stoq.scan import get_hashes, get_magic


class StoqShell(cmd.Cmd):

    def __init__(self, stoq):
        super().__init__()
        self.stoq = stoq
        self.default_prompt = "[stoQ] > "
        self.prompt = self.default_prompt
        self.plugins = {}
        self.payload = ""

    def set_prompt(self, msg=""):
        self.prompt = "{}{} > ".format(self.default_prompt, msg)

    def do_usage(self, input):
        """
        usage <category> <plugin>
            Display any documentation available for the specified plugin
        """
        try:
            args = input.split(" ")
            category = args[0]
            plugin = args[1]

            if category == 'worker':
                usage = self.plugins[category][plugin].scan.__doc__
            elif category == 'carver':
                usage = self.plugins[category][plugin].carve.__doc__
            elif category == 'extractor':
                usage = self.plugins[category][plugin].extract.__doc__
            elif category == 'decoder':
                usage = self.plugins[category][plugin].decode.__doc__
            elif category == 'reader':
                usage = self.plugins[category][plugin].read.__doc__
            else:
                print("[!] Please provide a valid plugin category")

            if usage:
                print(usage)
            else:
                print("[!] No documentation is available for {}:{}".format(category, plugin))
        except IndexError:
            print("[!] Category and plugin are required. Try: 'load <category> <plugin>'")
        except Exception as err:
            print("[!] Error: {}".format(str(err)))

    def do_list(self, input):
        """
        list
            List available plugins
        """

        self.stoq.list_plugins()

    def do_load(self, input):
        """
        load <category> <plugin>
            Load plugin of category
        """
        try:
            args = input.split(" ")
            category = args[0]
            plugin = args[1]

            if category not in self.plugins:
                self.plugins[category] = {}

            self.plugins[category][plugin] = self.stoq.load_plugin(plugin, category)

            if self.plugins[category][plugin]:
                print("[*] {}:{} loaded".format(category, plugin))

        except IndexError:
            print("[!] Category and plugin are required. Try: 'load <category> <plugin>'")
        except Exception as err:
            print("[!] Error: {}".format(str(err)))

    def do_run(self, input):
        """
        run <category> <plugin> [key=value]
            Run an individual plugin against the loaded payload
        """

        try:
            kwargs = {}
            self.results = None

            args = input.split(" ")
            category = args[0]
            plugin = args[1]

            # If there are additional arguments, they must be parameters for
            # the plugin. Split them as key=value so we can pass them to the
            # plugin as **kwargs
            if len(args) > 2:
                params = args[2:]
                for param in params:
                    key, value = param.split("=")
                    kwargs[key] = value

            if category == 'worker':
                self.results = self.plugins[category][plugin].scan(self.payload, **kwargs)
            elif category == 'carver':
                self.results = self.plugins[category][plugin].carve(self.payload, **kwargs)
            elif category == 'extractor':
                self.results = self.plugins[category][plugin].extract(self.payload, **kwargs)
            elif category == 'decoder':
                self.results = self.plugins[category][plugin].decode(self.payload, **kwargs)
            elif category == 'reader':
                self.results = self.plugins[category][plugin].read(self.payload, **kwargs)
            else:
                print("[!] Please provide a valid plugin category")

            if self.results:
                print("[*] Run using {} complete. View results with 'results'".format(plugin))
            else:
                print("[!] {} did not return any results".format(plugin))

        except KeyError:
            print("[!] The plugin '{1}' has not been loaded. Try: 'load {0} {1}'".format(category, plugin))
        except IndexError:
            print("[!] Category and plugin are required. Try: 'run <category> <plugin> [key=value]'")
        except Exception as err:
            print("[!] Error: {}".format(str(err)))

    def do_results(self, input):
        """
        results
            Display results of previous plugin run
        """

        try:
            # This is a mess. Plugins can produce either str(), bytes(),
            # or a list(). If it is a list(), there may be a tuple() in it.
            # Let's go over them and make sure we produce that right content
            # to display
            if self.results:
                if type(self.results) is dict:
                    print(self.stoq.dumps(self.results, compactly=False))
                elif type(self.results) is list:
                    for idx, r in enumerate(self.results):
                        if type(r) is dict:
                            print(self.stoq.dumps(r, compactly=False))
                        if type(r) is tuple:
                            if type(r[0]) is dict:
                                print("[*] Extracted content: id {}".format(idx))
                                for sub_key, sub_value in r[0].items():
                                    print("    - {}: {}".format(sub_key, sub_value))
                                hashes = get_hashes(r[1])
                                mime = get_magic(r[1])
                                for key, value in hashes.items():
                                    print("    - {}: {}".format(key, value))
                                print("    - magic: {}".format(mime))

                            else:
                                print(r)
                        else:
                            print(r)
                else:
                    print(self.results)
            else:
                print("[!] No results. Did you run a plugin? Try 'run <category> <plugin>'")
        except Exception as err:
            print("[!] Error: {}".format(str(err)))

    def do_save(self, input):
        """
        save [payload | id]
            Save all results, the current payload, or only a specific results ID to disk
        """

        try:
            # This is a mess. Plugins can produce either str(), bytes(),
            # or a list(). If it is a list(), there may be a tuple() in it.
            # Let's go over them and make sure we produce that right content
            # to save.
            if self.results:
                epoch = int(time.time())
                results = []
                if len(input) == 0:
                    if type(self.results) in (str, bytes, dict):
                        results.append(self.results)
                    elif type(self.results) is list:
                        for idx, r in enumerate(self.results):
                            if type(r) in (str, bytes):
                                results.append(r)
                            if type(r) is tuple:
                                if type(r[0]) is dict:
                                    results.append(r[1])
                elif input == "payload":
                    results.append(self.payload)
                else:
                    payload_id = int(input)
                    results.append(self.results[payload_id][1])

                for idx, content in enumerate(results):
                    filename = "results-{}-{}.{}".format(idx, self.filename, epoch)
                    path = self.stoq.write(content, binary=True,
                                           path=self.stoq.results_dir,
                                           filename=filename)
                    if not path:
                        print("[!] {}/{} already exists.".format(self.stoq.results_dir, filename))
            else:
                print("[!] No results. Did you run a plugin? Try 'run <category> <plugin>'")
        except Exception as err:
            print("[!] Error: {}".format(str(err)))

    def do_payload(self, input):
        """
        payload <id>
            Switch object to scan to an extracted stream
        """
        try:
            payload_id = int(input)
            self.payload = self.results[payload_id][1]
            print("[*] Payload switched to {}".format(input))
        except IndexError:
            print("[!] Invalid ID. Try 'results' for a complete list")
        except Exception as err:
            print("[!] Error: {}".format(str(err)))

    def do_read(self, input):
        """
        read <path to file>
            Open a file at specified path
        """

        try:
            self.filename = os.path.basename(input)
            self.payload = self.stoq.get_file(input)
            if not self.payload:
                print("[!] No payload found.")
            else:
                hashes = get_hashes(self.payload)
                mime = get_magic(self.payload)
                print("[*] Filename: {}".format(input))
                print("[*] Size: {}".format(len(self.payload)))

                # Iterate over all of the hashes that were generated
                for key, value in hashes.items():
                    print("[*] {}: {}".format(key, value))
                print("[*] magic: {}".format(mime))
        except Exception as err:
            print("[!] Error: {}".format(str(err)))

    def do_set(self, input):
        """
        set <global setting> <new value>
            Set global setting to value
        """

        try:
            if len(input) == 0:
                options = {}
                options['stoq'] = self.stoq.__dict__

                # Gather all of the __dict__()'s for each loaded plugin
                for category_key, category_value in self.plugins.items():
                    for plugin_key, plugin_value in category_value.items():
                        if plugin_value:
                            options['{}.{}'.format(category_key, plugin_key)] = plugin_value.__dict__

                # Only list the type()'s we want the user to interact with
                valid_types = (str, dict, tuple, int, bool)

                # Gather all of the settings and display them to the user
                for key, value in options.items():
                    for sub_key, sub_value in value.items():
                        if type(sub_value) in valid_types:
                            # Pretty up the output so the user doesn't get confused
                            if type(sub_value) in (list, tuple):
                                sub_value = ", ".join(sub_value)
                            print("{}.{} = {}".format(key, sub_key, str(sub_value)))
            else:
                args = input.split(" ")
                setting = args[0].split(".")
                value = " ".join(args[1:])

                # Determine the type() for the setting so we can be sure we store it
                # correctly
                if args[0].endswith("_list"):
                    value = [i.strip() for i in value.split(",")]
                elif args[0].endswith("_dict"):
                    value = self.loads(value)
                elif args[0].endswith("_tuple"):
                    value = tuple(i.strip() for i in value.split(","))
                elif value in ('True', 'False'):
                    value = bool(value)

                if setting[0] == "stoq":
                    if hasattr(self.stoq, setting[1]):
                        setattr(self.stoq, setting[1], value)
                    else:
                        print("[!] Attribute '{}' does not exist. Run 'set' to view global settings".format(args[0]))
                        return
                else:
                    if hasattr(self.plugins[setting[0]][setting[1]], setting[2]):
                        setattr(self.plugins[setting[0]][setting[1]], setting[2], value)
                    else:
                        print("[!] Attribute '{}' does not exist. Run 'set' to view global settings".format(args[0]))
                        return

                print("{} -> {}".format(args[0], value))
        except KeyError:
            print("[!] Attribute '{}' does not exist. Try 'settings'".format(args[0]))
        except Exception as err:
            print("[!] Error: {}".format(str(err)))

    def do_ls(self, input):
        """
        ls <path>
            List contents in the specified directory
        """
        # TODO:Clean this up and make the output prettier.
        try:
            path = os.path.abspath(input)
            for f in os.listdir(path):
                print(f)
        except FileNotFoundError:
            print("[!] File/Directory does not exist.")
        except Exception as err:
            print("[!] Error: {}".format(str(err)))

    def do_exit(self, input):
        self.do_EOF(True)

    def do_EOF(self, input):
        print("\nExiting...")
        exit(0)
