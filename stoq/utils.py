#!/usr/bin/env python3

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
