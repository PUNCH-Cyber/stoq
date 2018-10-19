#!/usr/bin/env python3

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

from functools import wraps
import threading
import time


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
