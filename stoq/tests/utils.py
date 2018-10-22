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


def current_dir():
    return os.path.dirname(os.path.realpath(__file__))


def get_data_dir():
    return os.path.join(current_dir(), 'data')


def get_plugins_dir():
    return os.path.join(get_data_dir(), 'plugins')


def get_plugins2_dir():
    return os.path.join(get_data_dir(), 'plugins2')


def get_invalid_plugins_dir():
    return os.path.join(get_data_dir(), 'invalid_plugins')


def get_complex_dispatcher():
    return os.path.join(get_data_dir(), 'complex_dispatcher.yar')


def get_always_dispatcher():
    return os.path.join(get_data_dir(), 'always_dispatcher.yar')
