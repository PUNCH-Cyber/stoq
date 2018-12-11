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

import json
import hashlib
import datetime
import traceback
import collections

from bs4 import UnicodeDammit  # pyre-ignore
from typing import Optional, Dict, DefaultDict, Union, List


class JsonComplexEncoder(json.JSONEncoder):
    """
    Extends the default JSON encoder to handle bytes and sets
    """

    def default(self, obj):
        if isinstance(obj, bytes):
            return UnicodeDammit(obj).unicode_markup
        elif isinstance(obj, datetime.datetime):
            return str(obj)
        elif isinstance(obj, set):
            return list(obj)
        try:
            return vars(obj)
        except Exception:
            pass
        return json.JSONEncoder.default(self, obj)


def dumps(data, indent=4, compactly=False):
    if compactly is True or not indent:
        indent = None
    return json.dumps(data, indent=indent, cls=JsonComplexEncoder, ensure_ascii=False)


def get_md5(content: bytes) -> str:
    return hashlib.md5(content).hexdigest()


def get_sha1(content: bytes) -> str:
    return hashlib.sha1(content).hexdigest()


def get_sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def get_sha512(content: bytes) -> str:
    return hashlib.sha512(content).hexdigest()


def format_exc(exc: Exception, limit: int = -1, msg: Optional[str] = None):
    tb = traceback.format_tb(exc.__traceback__, limit=limit)[0].split('\n')[0].strip()
    e = f'{tb} ; {repr(exc)}'
    if msg:
        e = f'Exception: {msg}: {e}'
    return e


def merge_dicts(
    d1: DefaultDict[str, List[str]],
    d2: Union[DefaultDict[str, List[str]], Dict[str, List[str]]],
) -> DefaultDict[str, List[str]]:
    for k, v in d2.items():
        d1[k].extend(v)
    return d1
