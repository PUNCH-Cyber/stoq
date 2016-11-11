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
import demjson

from bs4 import UnicodeDammit

from stoq.plugins import StoqPluginManager


__version__ = "0.10.7"


class Stoq(StoqPluginManager):
    """

    Core stoQ Framework Class

    """

    def __init__(self, argv=None, base_dir=None):
        """
        Initialize a stoQ class

        :param list argv: sys.argv or list of command line arguments
        :param str base_dir: Base directory that is the root for all paths

        """

        # If Stoq is instantiated from a command line script, such as
        # stoq-cli.py, we will parse the command line parameters. If not,
        # we will set the command line parameters to an empty list so we
        # can still have our required variables set without making spaghetti
        # code.
        if argv:
            self.argv = argv
        else:
            self.argv = ['']

        # Default to the base directory as the working directory, otherwise
        # it will be set to the value passed at instantiation. This value
        # will determine the default values for all paths required by stoQ,
        # unless they are overridden within the configuration file.
        if not base_dir:
            self.base_dir = os.path.realpath(os.path.dirname(self.argv[0]))
        else:
            self.base_dir = os.path.realpath(base_dir)

        self.version = __version__

        # Make sure the stoQ objects we require exist.
        # Setup our basic directory structure. This is overwritten
        # if we have anything set in our configuration file.
        self.log_dir = os.path.join(self.base_dir, "logs")
        self.results_dir = os.path.join(self.base_dir, "results")
        self.temp_dir = os.path.join(self.base_dir, "temp")
        self.plugin_dir = os.path.join(self.base_dir, "plugins")
        self.archive_base = os.path.join(self.base_dir, "archive")
        self.config_file = os.path.join(self.base_dir, "stoq.cfg")
        self.dispatch_rules = os.path.join(self.base_dir, 'dispatcher.yar')

        # What should be our default user agent when retrieving urls?
        self.useragent = "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.1)"

        self.worker = None

        # Default logging options
        # Valid options: DEBUG, INFO, WARN, ERROR, CRITICAL
        self.log_level = "INFO"
        self.log_maxbytes = 1500000
        self.log_backup_count = 5

        # Default connector plugin to be used for output
        self.default_connector = "stdout"

        # Default source plugin to be used for input
        self.default_source = "filedir"

        # The default suffix to append to a filename if
        # a filename is not provided.
        self.filename_suffix = "stoq"

        # Define the default maximum recursion depth for the dispatcher
        self.max_recursion = 3

        # Maximum queue size for multiprocessing support
        self.max_queue = 100

        # tuple() to match the root directory of where files can be ingested
        # from. Need for get_file().
        self.source_base_tuple = (self.base_dir)

        # Define what URL prefixes we accept
        self.url_prefix_tuple = ('http://', 'https://')

        # Load the configuration file, if it exists
        if os.path.exists(self.config_file):
            self.load_config()

        # Initialize the logger
        self.logger_init()

        # Default TLP for each payload processed
        self.default_tlp = "white"
        self.tlps = {'red': 0,
                     'amber': 1,
                     'green': 2,
                     'white': 3
                     }

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
        file_handler = logging.handlers.RotatingFileHandler(filename=self.log_path,
                                                            mode='a',
                                                            maxBytes=int(self.log_maxbytes),
                                                            backupCount=int(self.log_backup_count))

        # Setup our STDERR output
        stderr_handler = logging.StreamHandler()

        # Define the format of the log file
        log_format = logging.Formatter("%(asctime)s %(levelname)s %(name)s:%(filename)s:%(funcName)s:%(lineno)s: "
                                       "%(message)s",
                                       datefmt='%Y-%m-%d %H:%M:%S')

        stderr_log_format = logging.Formatter("[%(levelname)s] %(name)s: %(message)s")

        file_handler.setFormatter(log_format)
        stderr_handler.setFormatter(stderr_log_format)

        # Attach the handler to the logger
        self.log.addHandler(file_handler)
        self.log.addHandler(stderr_handler)

    def get_file(self, source, params=None, verify=True,
                 auth=None, **kwargs):
        """
        Obtain contents of file from disk or URL.

        .. note:: A file will only be opened from disk if the
                  path of the file matches the regex defined by
                  source_base_tuple in stoq.cfg.

        :param bytes source: Path or URL of file to read.
        :param bytes params: Additional parameters to pass if requesting a URL
        :param bool verify: Ensure SSL Certification Verification
        :param auth: Authentication methods supported by python-requests
        :param \*\*kwargs: Additional HTTP headers

        :returns: Content of file retrieved
        :rtype: bytes or None

        """

        self.log.debug("Retrieving file from {}".format(source))

        if source.startswith(self.url_prefix_tuple):
            # Set our default headers
            headers = self.__set_requests_headers(**kwargs)
            response = requests.get(source, params=params, auth=auth,
                                    verify=verify, headers=headers)

            # Raise an exception if it was not successful
            try:
                response.raise_for_status()
            except Exception as err:
                self.log.warn(err)

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
                        self.log.warn("{}".format(err))
            else:
                self.log.error("Unauthorized source path. Update "
                               "source_base_tuple path in stoq.cfg.")

        return None

    def put_file(self, url, params=None, data=None, auth=None, **kwargs):
        """
        Handles PUT request to specified URL

        :param bytes url: URL to for PUT request
        :param bytes params: Additional parameters to pass if requesting a URL
        :param bytes data: Content to PUT
        :param auth: Authentication methods supported by python-requests
        :param \*\*kwargs: Additional HTTP headers

        :returns: Content returned from PUT request
        :rtype: bytes or None

        """

        self.log.debug("PUT payload ({} bytes) to {}. params={}".format(len(data), url, params))

        # Set our default headers
        headers = self.__set_requests_headers(**kwargs)
        response = requests.put(url, data, params=params,
                                auth=auth, headers=headers)

        try:
            response.raise_for_status()
        except Exception as err:
            self.log.warn(err)

        content = response.content

        self.log.debug("{} ({} bytes) received".format(url, len(content)))

        return content

    def post_file(self, url, params=None, files=None, data=None, auth=None, **kwargs):
        """
        Handles POST request to specified URL

        :param bytes url: URL to for POST request
        :param bytes params: Additional parameters to pass if requesting a URL
        :param tuple files: Tuple of file data to POST
        :param bytes data: Content to POST
        :param auth: Authentication methods supported by python-requests
        :param \*\*kwargs: Additional HTTP headers

        :returns: Content returned from POST request
        :rtype: bytes or None

        """

        self.log.debug("POST payload ({} bytes) to {}. params={}".format(len(data), url, params))

        # Set our default headers
        headers = self.__set_requests_headers(**kwargs)
        response = requests.post(url, data, params=params, files=files,
                                 auth=auth, headers=headers)

        try:
            response.raise_for_status()
        except Exception as err:
            self.log.warn(err)

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
            self.log.warn("Unable to save file {}, no content was provided".format(fullpath))
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
            os.makedirs(path)

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

    def dumps(self, data, compactly=False):
        """
        Wrapper for json library. Dump dict to a json string

        :param dict data: Python dict to convert to json
        :param compactly: set to True to return unindented JSON (no newlines
                          between key/values),

        :returns: Converted json string
        :rtype: str

        """

        # We start with the default python json library to encode as
        # it is *MUCH* faster than demjson. However, if we run into issues
        # with being unable to serialize, we are going to use demjson
        # since it handles such data much better.

        try:
            if compactly is True:
                indent = None
            else:
                indent = 4
            return json.dumps(data, indent=indent)
        except TypeError:
            return demjson.encode(data, encode_bytes=str, compactly=compactly)

    def loads(self, data):
        """
        Wrapper for json library. Load json string as a python dict

        :param str data: json string to load into dict

        :returns: Converted dict
        :rtype: dict

        """

        try:
            return json.loads(data, object_hook=self.__sanitize_json)
        except:
            return json.loads(data.decode('utf-8'),
                              object_hook=self.__sanitize_json)

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

    def __sanitize_json(self, obj):
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
            new_key = key.replace(".", "_")
            new_key = new_key.replace(" ", "_")
            if isinstance(obj[key], dict):
                new_obj[key] = self.__sanitize_json(obj[key])
            else:
                new_obj[new_key] = obj[key]
        return new_obj

    def __normalize_json(self, obj):
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
                response.append(self.__normalize_json(entry))
        elif isinstance(obj, dict):
            response = {}
            for key in obj:
                if isinstance(obj[key], conversion_types):
                    response[key] = str(obj[key])
                elif isinstance(obj[key], list):
                    response[key] = []
                    for entry in obj[key]:
                        response[key].append(self.__normalize_json(entry))
                elif isinstance(obj[key], dict):
                    response[key] = []
                    response[key].append(self.__normalize_json(obj[key]))
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
