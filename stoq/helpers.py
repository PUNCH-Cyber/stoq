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

import os
import time
import json
import threading
import datetime
import collections
import unittest

from functools import wraps

import stoq

class JsonComplexDecoder(json.JSONEncoder):
    """
    Extends json.dumps() to convert bytes to string

    """
    def default(self, obj):
        if isinstance(obj, (bytes, datetime.datetime)):
            return str(obj)
        else:
            return obj


def JsonComplexEncoder(obj):
    """
    Extends json.loads() to convert bytes to string

    """
    if isinstance(obj, bytes):
        return str(obj)
    else:
        return obj


# Based on code from https://gist.github.com/gregburek/1441055
def ratelimited():
    """
    Thread safe decorator to rate limit a function

    """

    lock = threading.Lock()

    def decorator(func):
        last_call = time.perf_counter()

        @wraps(func)
        def ratelimit(*args, **kwargs):
            limit = kwargs.get("ratelimit", None)
            if limit:
                count, seconds = limit.split("/")
                interval = int(seconds) / int(count)
                lock.acquire()
                nonlocal last_call
                elapsed = time.perf_counter() - last_call
                left_to_wait = interval - elapsed

                if left_to_wait > 0:
                    time.sleep(left_to_wait)

                last_call = time.perf_counter()

                lock.release()

            try:
                kwargs.pop("ratelimit")
            except KeyError:
                pass

            return func(*args, **kwargs)

        return ratelimit

    return decorator


def flatten(data, delim='_'):
    """
    Flatten a nested `dict`

    """
    result = {}

    def flatten_dict(keys, name=''):
        if isinstance(keys, collections.MutableMapping):
            for value in keys:
                flatten_dict(keys[value], "{}{}{}".format(name, value, delim))
        elif isinstance(keys, list):
            count = 0
            for value in keys:
                if isinstance(value, collections.MutableMapping):
                    flatten_dict(value, "{}{}{}".format(name, count, delim))
                else:
                    result[name[:-1]] = keys
                count += 1
        else:
            result[name[:-1]] = keys

    flatten_dict(data)
    return result


def runtests(s, plugin=None, everything=False):
    """
    Run stoQ tests

    :param object s: Stoq() object
    :param str plugin: stoQ plugin name
    :param bool everything: Test all plugin

    """

    tests = []
    if plugin:
        for plg in plugin:
            try:
                test_path = os.path.join(
                    os.path.abspath(
                        os.path.dirname(
                            s.__collected_plugins__.get(plg).get(
                                "Core", "Config"))), "tests")
            except AttributeError:
                s.log.error("Plugin does not exist: {}".format(plg))
            else:
                tests.append(test_path)
    elif everything:
        for _, config in s.__collected_plugins__.items():
            test_path = os.path.join(
                os.path.abspath(
                    os.path.join(
                        os.path.dirname(
                            config.get("Core", "Config")), "tests")))
            tests.append(test_path)
    else:
        try:
            test_path = os.path.join(
                os.path.dirname(stoq.__file__), "tests")
        except ImportError:
            s.log.error(
                "Test suite not found. Is stoQ installed or are tests in {}?".format(
                    test_path))
        else:
            tests.append(test_path)

    for test_path in tests:
        if not os.path.isdir(test_path):
            s.log.error("Invalid test suite {} ..skipping".format(test_path))
            continue

        test_suite = unittest.TestLoader().discover(test_path, pattern='*_tests.py')
        unittest.TextTestRunner(verbosity=1).run(test_suite)
