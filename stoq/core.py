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

The *Stoq* class is the core of the framework. It must be
instantiated in order for all other modules to function properly.
This class is meant to be called from stoq.py.

Upon instantiation, default configuration options are defined
within *__init__*. These are overridden if there is identical
configuration option in *stoq.cfg*.

The *StoqPluginManager* will also be instantiated as a child
class automatically. This allows for the ability to globally
access the API for plugins and easily grant the ability for
plugins to load other plugins.

Examples
========

Instantiate the *Stoq* class::

    from stoq.core import Stoq
    stoq = Stoq()

Retrieve a file from a url::

    content = stoq.get_file("http://google.com")

Write content to disk::

    stoq.write("example content", path="/tmp", filename="example.txt")

.. note:: If no filename is given, ``Stoq.get_uuid`` will be called and a
          random filename will be defined automatically. Additionally, if
          the filename already exists, the file will not be overwritten.
          However, if ``Stoq.write()`` is called with ``overwrite=True``,
          the file will be overwritten. If the content to be written is
          binary, one may add ``binary=True`` when calling ``Stoq.write()``.

In many cases, you may wish to define plugin options. This is especially so
if you are not using *stoQ* from the command line. You may provide the
parameter `plugin_options` when instantiating the *Stoq()* class.

Instantiate *Stoq* class, and set attributes for plugins::

    from stoq.core import Stoq

    plugin_options = {
        'worker': {
            'yara': {
                'yararules': '/data/yara/rules.yar'
                }
            }
        }
    stoq = Stoq(plugin_options=plugin_options)

The plugin options will be available within the plugin object itself.
For instance, in the above example the yara worker plugin will now have
the attribute `yararules` defined as `/data/yara/rules.yar`.

API
===
"""


import os
import json
import uuid
import fcntl
import logging
import requests
import datetime
import configparser

from bs4 import UnicodeDammit
from pythonjsonlogger import jsonlogger
from requests.exceptions import HTTPError
from logging.handlers import RotatingFileHandler
from argparse import RawDescriptionHelpFormatter, ArgumentParser

from stoq.plugins import StoqPluginManager
from stoq.helpers import JsonComplexDecoder, JsonComplexEncoder

try:
    from raven.handlers.logging import SentryHandler
    raven_imported = True
except ImportError:
    raven_imported = False


class Stoq(StoqPluginManager):
    """

    Core stoQ Framework Class

    """

    def __init__(
        self, argv=None, base_dir=None, log_dir=None, results_dir=None,
        temp_dir=None, plugin_dir_list=None, archive_base=None,
        config_file=None, dispatch_rules=None, useragent=None, plugin_options=None,
        log_level=None, log_maxbytes=None, log_backup_count=None, default_connector=None,
        default_source=None, filename_suffix=None, max_recursion=None, max_queue=None,
        source_base_tuple=None, url_prefix_tuple=None, log_syntax=None,
        sentry_url=None, sentry_ignore_list=None, default_tlp=None):
        """
        Initialize a stoQ class

        :param list argv: sys.argv or list of command line arguments
        :param str base_dir: Base directory that is the root for all paths
        :param str log_dir: Directory to save log to
        :param str results_dir: Directory to save results to
        :param str temp_dir: Default temporary working directory
        :param list plugin_dir_list: Directories to search for plugins in
        :param str archive_base: Directory to save archived files to
        :param str config_file: stoQ configuration file to use for settings
        :param str dispatch_rules: Path to rules used for dispatching
        :param str useragent: Useragent to use when making HTTP queries
        :param dict plugin_options: Options to be passed to the plugins in lieu of command line arguments
        :param str log_level: Log level for stoQ and all loaded plugins
        :param int log_maxbytes: Maximum log file size in bytes
        :param int log_backup_count: Maximum amount of log files to retain
        :param str default_connector: Default connector plugin to use for output
        :param str default_source: Default source plugin to use for ingesting
        :param str filename_suffix: The filename suffix to use when saving files without a filename
        :param int max_recursion: Maximum recursion level when dispatching payloads
        :param int max_queue: When using multiprocessing, maximum amount of messages permitted in queue
        :param tuple source_base_tuple: Base directories permitted to read from when ingesting
        :param tuple url_prefix_tuple: Permitted URL prefixes
        :param str log_syntax: Defines the format for log files
        :param list sentry_ignore_list: Exceptions to ignore when sending to sentry
        :param str default_tlp: Default TLP level set for all results

        """

        # If Stoq is instantiated from a command line script, such as
        # `stoq`, we will parse the command line parameters. If not,
        # we will set the command line parameters to an empty list so we
        # can still have our required variables set without making spaghetti
        # code
        self.argv = argv if argv else ['']

        # Default to the base directory as the working directory, otherwise
        # it will be set to the value passed at instantiation. This value
        # will determine the default values for all paths required by stoQ,
        # unless they are overridden within the configuration file.
        if not base_dir:
            self.base_dir = os.path.realpath(os.path.dirname(self.argv[0]))
        else:
            self.base_dir = os.path.realpath(base_dir)

        self.config_file = config_file if config_file else os.path.join(self.base_dir, "stoq.cfg")
        if os.path.exists(self.config_file):
            self.load_config()

        # Make sure the stoQ objects we require exist.
        # Setup our basic directory structure. This is overwritten
        # if we have anything set in our configuration file, unless
        self.worker = None
        self.log_dir = self._set_opt('log_dir', log_dir, os.path.join(self.base_dir, "logs"))
        self.results_dir = self._set_opt('results_dir', results_dir,  os.path.join(self.base_dir, "results"))
        self.temp_dir = self._set_opt('temp_dir', temp_dir, os.path.join(self.base_dir, "temp"))
        self.plugin_dir_list = self._set_opt('plugin_dir_list', plugin_dir_list, [os.path.join(self.base_dir, "plugins")])
        self.archive_base = self._set_opt('archive_base', archive_base, os.path.join(self.base_dir, "archive"))
        self.dispatch_rules = self._set_opt('dispatch_rules', dispatch_rules, os.path.join(self.base_dir, 'dispatcher.yar'))
        self.useragent = self._set_opt('useragent', useragent, 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.1)')
        self.plugin_options = self._set_opt('plugin_options', plugin_options, {})
        self.log_level = self._set_opt('log_level', log_level, 'info')
        self.log_maxbytes = self._set_opt('log_maxbytes', log_maxbytes, 1500000)
        self.log_backup_count = self._set_opt('log_backup_count', log_backup_count, 5)
        self.default_connector = self._set_opt('default_connector', default_connector, 'stdout')
        self.default_source = self._set_opt('default_source', default_source, 'filedir')
        self.filename_suffix = self._set_opt('filename_suffix', filename_suffix, 'stoq')
        self.max_recursion = self._set_opt('max_recursion', max_recursion, 3)
        self.max_queue = self._set_opt('max_queue', max_queue, 100)
        self.source_base_tuple = self._set_opt('source_base_tuple', source_base_tuple, (self.base_dir,))
        self.url_prefix_tuple = self._set_opt('url_prefix_tuple', url_prefix_tuple, ('http://', 'https://'))
        self.log_syntax = self._set_opt('log_syntax', log_syntax, 'text')
        self.sentry_url = self._set_opt('sentry_url', sentry_url)
        self.sentry_ignore_list = self._set_opt('sentry_ignore_list', sentry_ignore_list,  [])
        self.default_tlp = self._set_opt('default_tlp', default_tlp, 'white')
        self.tlps = {
            'red': 0,
            'amber': 1,
            'green': 2,
            'white': 3
            }

        self.logger_init()

        # Ensure our plugin manager is initiated
        StoqPluginManager.__init__(self)



    def load_config(self):
        """
        Load configuration file. Defaults to stoq.cfg.

        """

        config = configparser.ConfigParser()
        config.read(self.config_file)
        for sect in config.sections():
            for opt in config.options(sect):

                # Skip if this has already been set
                if hasattr(self, opt):
                    if not getattr(self, opt):
                        continue

                # define each configuration option as an object within
                # self class
                value = config.get(sect, opt)

                # Support loading of dict(), list(), and tuple()
                if opt.endswith("_list"):
                    value = [i.strip() for i in value.split(",")]
                elif opt.endswith("_dict"):
                    value = self.loads(value)
                elif opt.endswith("_tuple"):
                    value = tuple(i.strip() for i in value.split(","))
                elif opt.endswith("_int"):
                    value = int(value.strip())

                if opt == "plugin_dir":
                    print("plugin_dir has been deprecated, please rename it to "
                          "plugin_dir_list in stoq.cfg. This will be removed "
                          "in a future version.")
                    self.plugin_dir_list = [value]
                setattr(self, opt, value)

    def logger_init(self):
        """
        Initialize the logger globally.

        :returns: True

        """

        # Let's attempt to make the log directory if it doesn't exist
        os.makedirs(self.log_dir, exist_ok=True)

        # Instantiate a logger
        self.log = logging.getLogger("stoq")

        # Set the default logging level
        self.log.setLevel(self.log_level.upper())

        # Define the log filename and path
        log_file = "stoq.log"
        self.log_path = os.path.abspath(os.path.join(self.log_dir, log_file))

        # Setup our logfile
        file_handler = RotatingFileHandler(
            filename=self.log_path, mode='a', maxBytes=int(self.log_maxbytes),
            backupCount=int(self.log_backup_count))

        # Setup our STDERR output
        stderr_handler = logging.StreamHandler()

        if self.log_syntax == "json":
            formatter = jsonlogger.JsonFormatter
        else:
            formatter = logging.Formatter

        # Define the format of the log file
        log_format = formatter("%(asctime)s %(levelname)s %(name)s:%(filename)s:%(funcName)s:%(lineno)s: "
                               "%(message)s", datefmt='%Y-%m-%d %H:%M:%S')

        stderr_logformat = formatter("[%(asctime)s %(levelname)s] %(name)s: %(message)s")

        file_handler.setFormatter(log_format)
        stderr_handler.setFormatter(stderr_logformat)

        # Attach the handler to the logger
        self.log.addHandler(file_handler)
        self.log.addHandler(stderr_handler)

        # If logging to sentry.io, setup the logger
        if raven_imported and self.sentry_url:
            try:
                sentry_handler = SentryHandler(self.sentry_url,
                                               ignore_exceptions=self.sentry_ignore_list)
                sentry_handler.setFormatter("[%(asctime)s][%(levelname)s] %(name)s "
                                            "%(filename)s:%(funcName)s:%(lineno)d | %(message)s")
                sentry_handler.setLevel(logging.WARN)
                self.log.addHandler(sentry_handler)
            except:
                self.log.error("Unable to initiate logging to Sentry")

    def get_file(self, source, params=None, verify=True,
                 auth=None, timeout=30, **kwargs):
        """
        Obtain contents of file from disk or URL.

        .. note:: A file will only be opened from disk if the
                  path of the file matches the regex defined by
                  source_base_tuple in stoq.cfg.

        :param bytes source: Path or URL of file to read.
        :param bytes params: Additional parameters to pass if requesting a URL
        :param bool verify: Ensure SSL Certification Verification
        :param auth: Authentication methods supported by python-requests
        :param int timeout: Time to wait for a server response
        :param \*\*kwargs: Additional HTTP headers

        :returns: Content of file retrieved
        :rtype: bytes or None

        """

        self.log.debug("Retrieving file from {}".format(source))

        if source.startswith(self.url_prefix_tuple):
            # Set our default headers
            headers = self.__set_requests_headers(**kwargs)
            try:
                response = requests.get(
                    source, params=params, auth=auth, verify=verify,
                    timeout=timeout, headers=headers)
            except:
                self.log.warning("Unable to retrieve content from {}".format(source), exc_info=True)
                return

            # Raise an exception if it was not successful
            try:
                response.raise_for_status()
            except HTTPError as err:
                self.log.warning(err)
                return

            content = response.content
            self.log.debug("{} ({} bytes) retrieved".format(source, len(content)))
            return content

        else:
            # Ensure we have an absolute path for security reasons
            abspath = os.path.abspath(source)
            # use our ingest_base regex to validate the base path
            # in order to ensure we are ingesting from a safe path
            if abspath.startswith(self.source_base_tuple):
                if os.path.isfile(abspath):
                    # Looking good, read file
                    try:
                        with open(abspath, "rb") as f:
                            content = f.read()
                            self.log.debug("{} ({} bytes) retrieved".format(abspath, len(content)))
                            return content
                    except PermissionError as err:
                        self.log.warning("{}".format(err))
                else:
                    self.log.warning("attempted to open {}, but file does not exist".format(abspath))
            else:
                self.log.error("Unauthorized source path. Update "
                               "source_base_tuple path in stoq.cfg.")

        return

    def put_file(self, url, params=None, data=None, auth=None, verify=True, timeout=30, **kwargs):
        """
        Handles PUT request to specified URL

        :param bytes url: URL to for PUT request
        :param bytes params: Additional parameters to pass if requesting a URL
        :param bytes data: Content to PUT
        :param auth: Authentication methods supported by python-requests
        :param bool verify: Ensure SSL Certification Verification
        :param int timeout: Time to wait for a server response
        :param \*\*kwargs: Additional HTTP headers

        :returns: Content returned from PUT request
        :rtype: bytes or None

        """

        self.log.debug("PUT payload ({} bytes) to {}. params={}".format(len(data), url, params))

        # Set our default headers
        headers = self.__set_requests_headers(**kwargs)
        try:
            response = requests.put(url, data, params=params, timeout=timeout,
                                    auth=auth, headers=headers, verify=verify)
        except:
            self.log.warning("Unable to PUT content to {}".format(url), exc_info=True)
            return

        try:
            response.raise_for_status()
        except HTTPError as err:
            self.log.warning(err)
            return

        content = response.content

        self.log.debug("{} ({} bytes) received".format(url, len(content)))

        return content

    def post_file(self, url, params=None, files=None, data=None, auth=None, verify=True, timeout=30,
                  **kwargs):
        """
        Handles POST request to specified URL

        :param bytes url: URL to for POST request
        :param bytes params: Additional parameters to pass if requesting a URL
        :param tuple files: Tuple of file data to POST
        :param bytes data: Content to POST
        :param auth: Authentication methods supported by python-requests
        :param bool verify: Ensure SSL Certification Verification
        :param int timeout: Time to wait for a server response
        :param \*\*kwargs: Additional HTTP headers

        :returns: Content returned from POST request
        :rtype: bytes or None

        """

        if data:
            data_len = len(data)
        else:
            data_len = 0

        self.log.debug("POST payload ({} bytes) to {}. params={}".format(data_len, url, params))

        # Set our default headers
        headers = self.__set_requests_headers(**kwargs)
        try:
            response = requests.post(
                url, data, params=params, files=files, timeout=timeout,
                auth=auth, headers=headers, verify=verify)
        except:
            self.log.warning("Unable to POST to {}".format(url), exc_info=True)
            return

        try:
            response.raise_for_status()
        except HTTPError as err:
            self.log.warning(err)
            return

        content = response.content

        self.log.debug("{} ({} bytes) received".format(url, len(content)))

        return content

    def write(self, payload, filename=None, path=None,
              binary=False, overwrite=False, append=False):
        """
        Write content to disk

        :param str payload: Data to be written to disk
        :param str filename: Filename, if none is provided, a random filename
                             will be used
        :param str path: Path for output file
        :param bool binary: Define whether content is binary or not
        :param bool overwrite: Define whether output file should be
                          overwritten
        :param bool append: Define whether output file should be appended to

        :returns: Full path of file that was written
        :rtype: str or False

        """

        if not filename:
            filename = "{}.{}".format(self.get_uuid, self.filename_suffix)

        if not path:
            path = self.base_dir

        # Create our full path to file and make sure it's safe
        # This method is x4 faster than os.path.join
        fullpath = "{}/{}".format(path, filename)
        fullpath = os.path.abspath(fullpath)

        if not payload:
            self.log.warning("Unable to save file {}, no content was provided".format(fullpath))
            return False

        self.log.debug("Attempting to save file to {} ({} bytes)".format(fullpath, len(payload)))

        # Default write mode, do not overwrite
        write_mode = "x"

        if overwrite:
            write_mode = "w"
        elif append:
            write_mode = "a"

        if binary:
            write_mode += "b"

        # Check to see if the directory exists, if not, create it
        if not os.path.exists(path):
            self.log.debug("Creating directory {}".format(path))
            try:
                os.makedirs(path)
            except FileExistsError:
                self.log.debug("Potential race condition, not creating directory {}".format(path))

        # Finally ready to write
        try:
            self.log.info("Saving file to {}".format(fullpath))
            with open(fullpath, write_mode) as outfile:
                fcntl.flock(outfile, fcntl.LOCK_EX)
                outfile.write(payload)
                fcntl.flock(outfile, fcntl.LOCK_UN)

        except FileExistsError:
            self.log.debug("File already exists: {}".format(fullpath))

        return fullpath

    def force_unicode(self, payload):
        """
        Force a string to be properly encoded in unicode using BeautifulSoup4

        :param bytes payload: String to be forced into unicode

        :returns: Unicode bytes
        :rtype: bytes

        """

        return UnicodeDammit(payload).unicode_markup

    @property
    def get_time(self):
        """
        Get the current time, in ISO format

        :returns: Current time in ISO Format
        :rtype: str

        """

        return datetime.datetime.now().isoformat()

    @property
    def get_uuid(self):
        """
        Generate a random uuid

        :returns: Random uuid
        :rtype: str

        """

        return str(uuid.uuid4())

    def hashpath(self, sha1):
        """
        Generate a path based on the first five chars of a SHA1 hash

        example:
        The SHA1 4caa16eba080d3d4937b095fb68999f3dbabd99d
        would return a path similar to:
        /opt/malware/4/c/a/a/1

        :param str sha1: SHA1 hash of a payload

        :returns: Path
        :rtype: str

        """

        return os.path.join(self.archive_base, '/'.join(list(sha1[:5])))

    def dumps(self, data, indent=4, compactly=False):
        """
        Wrapper for json library. Dump dict to a json string

        :param dict data: Python dict to convert to json
        :param int indent: Indent level for return value
        :param compactly: set to True to return unindented JSON (no newlines
                          between key/values),

        :returns: Converted json string
        :rtype: str

        """

        if compactly is True or not indent:
            indent = None

        return json.dumps(data, indent=indent, cls=JsonComplexDecoder)

    def loads(self, data):
        """
        Wrapper for json library. Load json string as a python dict

        :param str data: json string to load into dict

        :returns: Converted dict
        :rtype: dict

        """

        # Using try/except because it is faster than checking the type() of data,
        # be it str() or bytes()
        try:
            return json.loads(data, object_hook=JsonComplexEncoder)
        except:
            return json.loads(data.decode(), object_hook=JsonComplexEncoder)

    def __set_requests_headers(self, headers=None):
        """
        Set default requests headers.

        :param dict headers: Dictionary containing any headers defined by
                             the plugin

        :returns: The same dictionary, plus any default headers that were not
                  defined.
        :rtype: dict

        """

        if not headers:
            headers = {}

        # Define a set of default headers, in case none are provided
        default_headers = [('User-Agent', self.useragent)]

        # Iterate over our default headers and assign them
        # if they are not defined in **kwargs
        for header, value in default_headers:
            if header not in headers:
                headers[header] = value

        self.log.debug("HTTP Headers: {}".format(headers))
        return headers

    def sanitize_json(self, obj):
        """
        Sanitize json so keys do not contain '.' or ' '. Required for
        compaitibility with databases such as mongodb and elasticsearch

        :param dict obj: dict object

        :returns: Sanitized dict object
        :rtype: dict

        """
        self.log.debug("Sanitizing JSON")
        new_obj = {}
        for key in obj.keys():
            new_key = key.replace(".", "_").replace(" ", "_")
            if isinstance(obj[key], dict):
                new_obj[new_key] = self.sanitize_json(obj[key])
            elif isinstance(obj[key], list):
                new_obj[new_key] = []
                for iter_obj in obj[key]:
                    if isinstance(iter_obj, dict):
                        new_obj[new_key].append(self.sanitize_json(iter_obj))
                    if isinstance(iter_obj, bytes):
                        new_obj[new_key].append(str(iter_obj))
                    else:
                        new_obj[new_key].append(iter_obj)
            else:
                new_obj[new_key] = obj[key]
        return new_obj

    def normalize_json(self, obj):
        """
        Normalize json blobs:
            - If a key's value is a dict:
                - Make the value a list
                - Iterate over sub keys and do the same
            - If a key's value is a list:
                - Iterate over the values to ensure they are a string
            - If the key's value is anything else:
                - Force the value to be a string

        :param dict obj: dict object to normalize

        :returns: Normalized dict object
        :rtype: dict

        """
        # Original code open sourced by NIH
        # Modified for use with stoQ

#######################
#
# Copyright (c) 2015 United States Government/National Institutes of Health
# Author: Aaron Gee-Clough
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
#
#####################

        self.log.debug("Normalizing JSON")

        conversion_types = (bytes, int, float, bool)

        if isinstance(obj, list):
            response = []
            for entry in obj:
                response.append(self.normalize_json(entry))
        elif isinstance(obj, dict):
            response = {}
            for key in obj:
                if isinstance(obj[key], conversion_types):
                    response[key] = str(obj[key])
                elif isinstance(obj[key], list):
                    response[key] = []
                    for entry in obj[key]:
                        response[key].append(self.normalize_json(entry))
                elif isinstance(obj[key], dict):
                    response[key] = []
                    response[key].append(self.normalize_json(obj[key]))
                elif obj[key] is None:
                    response[key] = ""
                else:
                    response[key] = str(obj[key])
        elif isinstance(obj, conversion_types):
            response = str(obj)
        elif obj is None:
            response = ""
        else:
            response = str(obj)
        return response

    def _set_opt(self, obj, value, default=None):
        """
        Determine value of object based on precedence

        - If parameter defined at instantiation, return value
        - Else, if the object exists and is None, return default
        - Else, if the object is defined, return object value
        - Else, return default

        """
        # If a value was provided, return the value
        if value:
            return value
        elif hasattr(self, obj):
            # Otherwise, the object already exists...

            # But, the object is set to None
            if getattr(self, obj) is None:
                return default
            else:
                # Return the value the object is already set to
                return getattr(self, obj)
        else:
            # No value was provided, and the object does not exist
            return default
