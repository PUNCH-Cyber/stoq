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


import logging
from typing import Optional
import unittest


from stoq import StoqException
from stoq.data_classes import Payload, WorkerResponse, RequestMeta
from stoq.plugin_manager import StoqPluginManager
from stoq.plugins import WorkerPlugin
import stoq.tests.utils as utils


class TestPluginManager(unittest.TestCase):
    DUMMY_PLUGINS = [
        'dummy_archiver',
        'dummy_connector',
        'dummy_provider',
        'dummy_worker',
        'dummy_decorator',
    ]

    def setUp(self) -> None:
        logging.disable(logging.CRITICAL)

    def tearDown(self) -> None:
        logging.disable(logging.NOTSET)

    def test_no_plugins(self):
        pm = StoqPluginManager([])
        self.assertEqual(len(pm.list_plugins()), 0)

    def test_collect_plugins(self):
        pm = StoqPluginManager([utils.get_plugins_dir()])
        collected_plugins = pm.list_plugins()
        for name in self.DUMMY_PLUGINS:
            self.assertIn(name, collected_plugins)

    def test_multiple_dirs(self):
        pm = StoqPluginManager([utils.get_plugins_dir(), utils.get_plugins2_dir()])
        collected_plugins = pm.list_plugins()
        for name in self.DUMMY_PLUGINS + ['dummy_worker2']:
            self.assertIn(name, collected_plugins)

    def test_collect_one_invalid_dir(self):
        # Verify that the invalid directory doesn't cause an exception
        pm = StoqPluginManager([utils.get_plugins_dir(), '/no/way/this/exists'])
        self.assertGreater(len(pm.list_plugins()), 0)

    def test_collect_invalid_config(self):
        pm = StoqPluginManager([utils.get_invalid_plugins_dir()])
        collected_plugins = pm.list_plugins()
        self.assertNotIn('missing_module', collected_plugins)
        self.assertNotIn('invalid_config', collected_plugins)

    def test_load_plugin(self):
        pm = StoqPluginManager([utils.get_plugins_dir()])
        for name in self.DUMMY_PLUGINS:
            pm.load_plugin(name)

    def test_load_non_plugin(self):
        pm = StoqPluginManager([utils.get_invalid_plugins_dir()])
        collected_plugins = pm.list_plugins()
        # The plugin should be collected even though it is invalid at load time
        self.assertIn('missing_plugin', collected_plugins)
        with self.assertRaises(StoqException):
            pm.load_plugin('missing_plugin')

    def test_load_multiple_plugins_in_module(self):
        pm = StoqPluginManager([utils.get_invalid_plugins_dir()])
        collected_plugins = pm.list_plugins()
        # The plugin should be collected even though it is invalid at load time
        self.assertIn('multiple_plugins_in_module', collected_plugins)
        with self.assertRaises(StoqException):
            pm.load_plugin('multiple_plugins_in_module')

    def test_no_reload(self):
        pm = StoqPluginManager([utils.get_plugins_dir()])
        worker = pm.load_plugin('dummy_worker')
        self.assertIsNotNone(worker)
        worker2 = pm.load_plugin('dummy_worker')
        self.assertIs(worker, worker2)  # Same object

    def test_plugin_config(self):
        pm = StoqPluginManager([utils.get_plugins_dir()])
        plugin = pm.load_plugin('configurable_worker')
        self.assertEqual(plugin.get_important_option(), 'cybercybercyber')

    def test_plugin_opts(self):
        pm = StoqPluginManager(
            [utils.get_plugins_dir()],
            {'configurable_worker': {'crazy_runtime_option': 16}},
        )
        plugin = pm.load_plugin('configurable_worker')
        self.assertEqual(plugin.get_crazy_runtime_option(), 16)

    def test_min_stoq_version(self):
        pm = StoqPluginManager([utils.get_invalid_plugins_dir()])
        # We have to override the fact that all log calls are disabled in setUp()
        # for the calls here to actually go through
        logging.disable(logging.NOTSET)
        with self.assertLogs(level='WARNING'):
            plugin = pm.load_plugin('incompatible_min_stoq_version')
        self.assertIsNotNone(plugin)

    def test_plugin_override(self):
        """Verify that if plugin directories have plugins with duplicate names,
        the one in the last specified directory will be used"""
        pm = StoqPluginManager([utils.get_plugins_dir(), utils.get_plugins2_dir()])
        collected_plugins = pm.list_plugins()
        self.assertIn('dummy_worker', collected_plugins)
        worker = pm.load_plugin('dummy_worker')
        self.assertTrue(worker.PLUGINS2_DUP_MARKER)

        pm = StoqPluginManager([utils.get_plugins2_dir(), utils.get_plugins_dir()])
        self.assertIn('dummy_worker', collected_plugins)
        worker = pm.load_plugin('dummy_worker')
        with self.assertRaises(Exception):
            worker.PLUGINS2_DUP_MARKER



class ExampleExternalPlugin(WorkerPlugin):
    # Intentionally override this method to not require the config argument
    def __init__(self):
        pass

    def scan(
        self, payload: Payload, request_meta: RequestMeta, *args
    ) -> Optional[WorkerResponse]:
        pass


class NoParentClassPlugin:
    def scan(
        self, payload: Payload, request_meta: RequestMeta, *args
    ) -> Optional[WorkerResponse]:
        pass
