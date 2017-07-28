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

Basic scanning functions such as hash calculation and file type detection.

Examples
========

Calculate the md5 hash of a payload::

    import stoq.scan
    stoq.scan.get_md5("this is a payload")

Calculate the md5, sha1, sha256, and sha512 of a payload::

    stoq.scan.get_hashes("this is a payload")

API
===
"""

import magic
import hashlib
import ssdeep

# This is silly. python-magic is the preferred library as it is maintained.
# But, sometimes filemagic is used by other libraries. Let's determine which
# one is installed so we can call it properly.
if hasattr(magic.Magic, "from_buffer"):
    USE_PYTHON_MAGIC = True
else:
    USE_PYTHON_MAGIC = False


def get_hashes(payload):
    """
    Calculate the md5, sha1, sha256, and sha512 of a payload

    :param payload: The payload to be hashed.

    :returns: All of the above hashes
    :rtype: dict

    """

    r = {}
    r['md5'] = get_md5(payload)
    r['sha1'] = get_sha1(payload)
    r['sha256'] = get_sha256(payload)
    r['sha512'] = get_sha512(payload)
    return r


def get_md5(payload):
    """
    Generate md5 hash of a payload

    :param payload: The payload to be hashed.

    :returns: md5 hash
    :rtype: str

    """
    return hashlib.md5(payload).hexdigest()


def get_sha1(payload):
    """
    Generate sha1 hash of a payload

    :param payload: The payload to be hashed.

    :returns: sha1 hash
    :rtype: str

    """
    return hashlib.sha1(payload).hexdigest()


def get_sha256(payload):
    """
    Generate sha256 hash of a payload

    :param payload: The payload to be hashed.

    :returns: sha256 hash
    :rtype: str

    """
    return hashlib.sha256(payload).hexdigest()


def get_sha512(payload):
    """
    Generate sha512 hash of a payload

    :param payload: The payload to be hashed.

    :returns: sha512 hash
    :rtype: str

    """
    return hashlib.sha512(payload).hexdigest()


def get_ssdeep(payload):
    """
    Generate ssdeep hash of a payload

    :param payload: The payload to be hashed.

    :returns: ssdeep hash
    :rtype: str or None

    """
    try:
        fuzzy = ssdeep.hash(payload)
    except:
        fuzzy = None

    return fuzzy


def compare_ssdeep(payload1, payload2):
    """
    Compare binary payloads with ssdeep to determine

    :param bytes payload1: Binary content to compare
    :param bytes payload2: Binary content to compare

    :returns: Match score from 0 (no match) to 100
    :type: int or None

    """

    payload1_hash = get_ssdeep(payload1)
    payload2_hash = get_ssdeep(payload2)

    try:
        match = ssdeep.compare(payload1_hash, payload2_hash)
    except:
        match = None

    return match


def get_magic(payload, mime=True):
    """
    Attempt to identify the magic of a payload

    :param bytes payload: Payload to be analyzed
    :param bool mime: Define whether the payload is of mime magic_type

    :returns: Identified magic type, otherwise None
    :rtype: bytes

    """
    try:
        if USE_PYTHON_MAGIC:
            magic_scan = magic.Magic(mime=mime)

            # Limit the buffer for 1000 bytes, otheriwse magic will fail
            magic_result = magic_scan.from_buffer(payload[0:1000])
        else:
            if mime:
                flags = magic.MAGIC_MIME_TYPE
            else:
                flags = None

            with magic.Magic(flags=flags) as m:
                magic_result = m.id_buffer(payload[0:1000])

        # In some cases there may be encoded content within the results. If so,
        # let's make sure we decode it so it is handled properly.
        if hasattr(magic_result, 'decode'):
            magic_result = magic_result.decode("utf-8")

    except:
        magic_result = None

    return magic_result


def bytes_frequency(payload, min_length=1, max_length=3, min_count=10):
    """
    Determine the frequency of bytes or series of bytes in a payload

    :param bytes payload: Payload to be analyzed
    :param int min_length: Minimum length of continuous bytes
    :param int max_length: Maximum length of continuous bytes
    :param int min_count: Minimum count of instances of a specific byte or
                          series of bytes

    :returns: Bytes, count, percentage of frequency
    :rtype: tuple

    """
    possible_keys = {}
    start_index = 0

    payload_size = len(payload)

    for keylength in range(min_length, max_length):
        possible_keys[keylength] = {}

    while start_index < payload_size:

        for slice_length in range(min_length, max_length):
            end_index = start_index + slice_length

            key_value = payload[start_index:end_index]
            key_length = len(key_value)

            if key_value == key_length * chr(key_value[0]).encode():
                pass
            elif key_value in possible_keys[key_length]:
                possible_keys[key_length][key_value] += 1
            else:
                possible_keys[key_length][key_value] = 1

        start_index += 1

    for keylength in range(min_length, max_length):
        for byte_value, count in possible_keys[keylength].items():
            if count >= min_count:
                yield (byte_value, count,
                       float("{:.2f}".format(100 * float(count) / float(payload_size))))
