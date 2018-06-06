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

import datetime
import hashlib
# import magic
# import ssdeep
import json


class JsonComplexEncoder(json.JSONEncoder):
    """
    Extends the default JSON encoder to handle bytes and sets
    """
    def default(self, obj):
        if isinstance(obj, (bytes, datetime.datetime)):
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
    return json.dumps(data, indent=indent, cls=JsonComplexEncoder)

# This is silly. python-magic is the preferred library as it is maintained.
# But, sometimes filemagic is used by other libraries. Let's determine which
# one is installed so we can call it properly.
# if hasattr(magic.Magic, 'from_buffer'):
#     USE_PYTHON_MAGIC = True
# else:
#     USE_PYTHON_MAGIC = False


def get_md5(content: bytes) -> str:
    return hashlib.md5(content).hexdigest()


def get_sha1(content: bytes) -> str:
    return hashlib.sha1(content).hexdigest()


def get_sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def get_sha512(content: bytes) -> str:
    return hashlib.sha512(content).hexdigest()


# def get_ssdeep(content: bytes) -> Optional[str]:
#     try:
#         fuzzy = ssdeep.hash(content)
#     except Exception:
#         fuzzy = None
#     return fuzzy
#
#
# def get_magic(content: bytes, mime=True) -> Optional[str]:
#     try:
#         if USE_PYTHON_MAGIC:
#             magic_scan = magic.Magic(mime=mime)
#             # Limit the buffer for 1000 bytes, otheriwse magic will fail
#             magic_result = magic_scan.from_buffer(content[0:1000])
#         else:
#             if mime:
#                 flags = magic.MAGIC_MIME_TYPE
#             else:
#                 flags = None
#
#             with magic.Magic(flags=flags) as m:
#                 magic_result = m.id_buffer(content[0:1000])
#
#         # In some cases there may be encoded content within the results. If so,
#         # let's make sure we decode it so it is handled properly.
#         if hasattr(magic_result, 'decode'):
#             magic_result = magic_result.decode('utf-8')
#     except Exception:
#         magic_result = None
#
#     return magic_result
