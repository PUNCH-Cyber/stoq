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

import sys
import asyncio
import json
import logging
import tempfile

import asynctest  # type: ignore
import stoq.tests.utils as utils
from stoq import Stoq, StoqException
from stoq.data_classes import (
    ArchiverResponse,
    DecoratorResponse,
    DispatcherResponse,
    Payload,
    PayloadMeta,
    PayloadResults,
    Request,
    RequestMeta,
    StoqResponse,
    WorkerResponse,
)


# type: ignore
class TestCore(asynctest.TestCase):
    def setUp(self) -> None:
        logging.disable(logging.CRITICAL)
        self.generic_content = b'The quick brown fox'  # type: ignore

    def tearDown(self) -> None:
        logging.disable(logging.NOTSET)

    def test_no_base_dir(self):
        # Verify that this doesn't throw an exception. Explicitly set log_dir
        # to none since we don't want to create logs in a random location and
        # shouldn't use a config file in this test.
        s = Stoq(log_dir=None)
        self.assertEqual(len(s.list_plugins()), 0)

    def test_config_from_base_dir(self):
        s = Stoq(base_dir=utils.get_data_dir())
        self.assertEqual(s.max_queue, 919)

    def test_file_log(self):
        with tempfile.TemporaryDirectory() as log_dir:
            # This verifies that the file handler logging doesn't throw an
            # exception, but we can't assert anything about contents because
            # we explcitly don't want to log things (to stdout) during tests
            Stoq(log_dir=log_dir)

    def test_initial_plugins(self):
        s = Stoq(
            base_dir=utils.get_data_dir(),
            providers=['dummy_provider'],
            source_archivers=['dummy_archiver'],
            dest_archivers=['dummy_archiver'],
            connectors=['dummy_connector'],
            decorators=['dummy_decorator'],
            dispatchers=['dummy_dispatcher'],
        )
        self.assertEqual(len(s._loaded_provider_plugins), 1)
        self.assertEqual(len(s._loaded_source_archiver_plugins), 1)
        self.assertEqual(len(s._loaded_dest_archiver_plugins), 1)
        self.assertEqual(len(s._loaded_connector_plugins), 1)
        self.assertEqual(len(s._loaded_decorator_plugins), 1)
        self.assertEqual(len(s._loaded_dispatcher_plugins), 1)

    ############ 'SCAN' TESTS ############

    async def test_scan(self):
        s = Stoq(base_dir=utils.get_data_dir())
        response = await s.scan(self.generic_content)
        self.assertEqual(len(response.results), 1)
        self.assertEqual(response.results[0].size, len(self.generic_content))

    async def test_split_results(self):
        s = Stoq(base_dir=utils.get_data_dir())
        response = await s.scan(
            self.generic_content,
            add_start_dispatch=['multiclass_plugin', 'simple_worker'],
        )
        split_response = response.split()
        self.assertEqual(len(split_response), 2)
        for r in split_response:
            if 'simple_worker' in r['results'][0]['workers']:
                self.assertNotIn('multiclass_plugin', r['results'][0]['workers'])
            elif 'multiclass_plugin' in r['results'][0]['workers']:
                self.assertNotIn('simple_worker', r['results'][0]['workers'])
            else:
                raise Exception('required plugin not found in results')

    async def test_worker_should_scan(self):
        s = Stoq(base_dir=utils.get_data_dir())
        simple_worker = s.load_plugin('simple_worker')
        simple_worker.SHOULD_SCAN = False
        simple_worker.EXTRACTED_DISPATCH_TO = ['dummy_worker']
        response = await s.scan(
            self.generic_content, add_start_dispatch=['simple_worker']
        )
        # TODO: Extracted payloads are not being dispatched
        self.assertIn('simple_worker', response.results[0].plugins_run['workers'][0])
        self.assertEqual(2, len(response.results))
        self.assertNotIn('dummy_worker', response.results[1].plugins_run['workers'])

    async def test_always_dispatch(self):
        s = Stoq(base_dir=utils.get_data_dir(), always_dispatch=['simple_worker'])
        response = await s.scan(self.generic_content)
        self.assertIn('simple_worker', s._loaded_plugins)
        self.assertIn('simple_worker', response.results[0].plugins_run['workers'])
        self.assertIn('simple_worker', response.results[1].plugins_run['workers'])

    async def test_start_dispatch(self):
        s = Stoq(base_dir=utils.get_data_dir())
        response = await s.scan(
            self.generic_content, add_start_dispatch=['extract_payload']
        )
        self.assertIn('extract_payload', response.results[0].plugins_run['workers'])
        self.assertNotIn('extract_payload', response.results[1].plugins_run['workers'])

    async def test_dispatch(self):
        s = Stoq(base_dir=utils.get_data_dir(), dispatchers=['simple_dispatcher'])
        dummy_worker = s.load_plugin('dummy_worker')
        dummy_worker.scan = asynctest.create_autospec(
            dummy_worker.scan, return_value=None
        )
        response = await s.scan(self.generic_content)
        self.assertEqual(len(dummy_worker.scan.await_args[0]), 2)
        self.assertEqual(
            dummy_worker.scan.await_args[0][0].dispatch_meta['simple_dispatcher'],
            {'test_key': 'Useful metadata info'},
        )
        self.assertIn('dummy_worker', response.results[0].plugins_run['workers'])

    async def test_dispatcher_exception(self):
        s = Stoq(base_dir=utils.get_data_dir(), dispatchers=['simple_dispatcher'])
        simple_dispatcher = s.load_plugin('simple_dispatcher')
        simple_dispatcher.RAISE_EXCEPTION = True
        with self.assertRaises(Exception) as context:
            await simple_dispatcher.get_dispatches(task)
        self.assertTrue('Test exception', context.exception)

    async def test_conditional_dispatch(self):
        s = Stoq(base_dir=utils.get_data_dir(), dispatchers=['conditional_dispatcher'])
        simple_worker = s.load_plugin('simple_worker')
        simple_worker.scan = asynctest.create_autospec(
            simple_worker.scan, return_value=None
        )
        response = await s.scan(self.generic_content)
        self.assertNotIn('simple_worker', response.results[0].plugins_run['workers'])

        response = await s.scan(
            self.generic_content, add_start_dispatch=['dummy_worker']
        )
        self.assertIn('simple_worker', response.results[0].plugins_run['workers'])

    @asynctest.skipIf(
        sys.version_info >= (3, 8), 'skipping because python >= 3.8 breaks test'
    )
    async def test_dispatch_duplicate(self):
        s = Stoq(base_dir=utils.get_data_dir(), dispatchers=['simple_dispatcher'])
        s.load_plugin('simple_dispatcher').WORKERS = ['simple_worker', 'simple_worker']
        simple_worker = s.load_plugin('simple_worker')
        simple_worker.scan = asynctest.create_autospec(
            simple_worker.scan, return_value=None
        )
        await s.scan(self.generic_content)
        self.assertEqual(simple_worker.scan.await_count, 1)
        self.assertEqual(len(simple_worker.scan.await_args[0]), 2)

    async def test_dispatch_from_worker(self):
        s = Stoq(base_dir=utils.get_data_dir())
        simple_worker = s.load_plugin('simple_worker')
        simple_worker.EXTRACTED_DISPATCH_TO = ['extract_payload']
        response = await s.scan(
            self.generic_content, add_start_dispatch=['simple_worker']
        )
        self.assertEqual(len(response.results), 3)
        self.assertIn('simple_worker', response.results[0].plugins_run['workers'][0])
        self.assertIn('extract_payload', response.results[1].plugins_run['workers'][0])
        self.assertIn('extract_payload', response.results[2].extracted_by)

    async def test_additional_dispatch_from_worker(self):
        s = Stoq(base_dir=utils.get_data_dir())
        simple_worker = s.load_plugin('simple_worker')
        simple_worker.ADDITIONAL_DISPATCH_TO = ['dummy_worker']
        response = await s.scan(
            self.generic_content, add_start_dispatch=['simple_worker']
        )

        self.assertEqual(len(response.results), 2)
        self.assertCountEqual(
            response.results[0].plugins_run['workers'],
            ['simple_worker', 'dummy_worker'],
        )
        self.assertEqual(len(response.results[1].plugins_run['workers']), 0)

    @asynctest.skipIf(
        sys.version_info >= (3, 8), 'skipping because python >= 3.8 breaks test'
    )
    async def test_dispatch_multiple_plugins(self):
        multi_plugin_content = b'multi-plugin-content'
        s = Stoq(base_dir=utils.get_data_dir(), dispatchers=['simple_dispatcher'])
        s.load_plugin('simple_dispatcher').WORKERS = ['simple_worker', 'dummy_worker']
        simple_worker = s.load_plugin('simple_worker')
        simple_worker.scan = asynctest.create_autospec(
            simple_worker.scan, return_value=None
        )
        dummy_worker = s.load_plugin('dummy_worker')
        dummy_worker.scan = asynctest.create_autospec(
            dummy_worker.scan, return_value=None
        )
        await s.scan(multi_plugin_content)
        simple_worker.scan.assert_awaited_once()
        self.assertEqual(len(simple_worker.scan.await_args[0]), 2)
        dummy_worker.scan.assert_awaited_once()
        self.assertEqual(len(dummy_worker.scan.await_args[0]), 2)

    @asynctest.skipIf(
        sys.version_info >= (3, 8), 'skipping because python >= 3.8 breaks test'
    )
    async def test_dispatch_multiple_plugins2(self):
        again_multi_plugin_content = b'again-multi-plugin-space-content'
        s = Stoq(base_dir=utils.get_data_dir(), dispatchers=['simple_dispatcher'])
        s.load_plugin('simple_dispatcher').WORKERS = ['simple_worker', 'dummy_worker']
        simple_worker = s.load_plugin('simple_worker')
        simple_worker.scan = asynctest.create_autospec(
            simple_worker.scan, return_value=None
        )
        dummy_worker = s.load_plugin('dummy_worker')
        dummy_worker.scan = asynctest.create_autospec(
            dummy_worker.scan, return_value=None
        )
        await s.scan(again_multi_plugin_content)
        simple_worker.scan.assert_awaited_once()
        self.assertEqual(len(simple_worker.scan.await_args[0]), 2)
        dummy_worker.scan.assert_awaited_once()
        self.assertEqual(len(dummy_worker.scan.await_args[0]), 2)

    async def test_dispatch_nonexistent_plugin(self):
        s = Stoq(base_dir=utils.get_data_dir())
        response = await s.scan(
            self.generic_content, add_start_dispatch=['this_plugin_doesnt_exist']
        )
        self.assertNotIn(
            'this_plugin_doesnt_exist', response.results[0].plugins_run['workers']
        )
        self.assertEqual(len(response.errors), 1)

    async def test_scan_with_required_plugin(self):
        s = Stoq(base_dir=utils.get_data_dir())
        simple_worker = s.load_plugin('simple_worker')
        simple_worker.EXTRACTED_DISPATCH_TO = ['simple_worker']
        simple_worker.required_workers.add('dummy_worker')
        response = await s.scan(
            self.generic_content, add_start_dispatch=['simple_worker']
        )
        self.assertEqual(2, len(response.results))
        self.assertCountEqual(
            ['dummy_worker', 'simple_worker'],
            response.results[0].plugins_run['workers'],
        )
        self.assertCountEqual(
            ['dummy_worker', 'simple_worker'],
            response.results[1].plugins_run['workers'],
        )

    async def test_scan_with_duplicate_extracted_payloads(self):
        s = Stoq(base_dir=utils.get_data_dir())
        simple_worker = s.load_plugin('simple_worker')
        simple_worker.EXTRACTED_DISPATCH_TO = ['extract_payload']
        simple_worker.EXTRACTED_PAYLOAD = self.generic_content + b'more data'
        extract_worker = s.load_plugin('extract_payload')
        extract_worker.EXTRACTED_PAYLOAD = self.generic_content + b'more data'
        response = await s.scan(
            self.generic_content, add_start_dispatch=['simple_worker']
        )
        self.assertEqual(2, len(response.results))
        self.assertEqual('simple_worker', response.results[0].plugins_run['workers'][0])
        self.assertNotIn('extract_payload', response.results[0].plugins_run['workers'])
        self.assertNotIn('simple_worker', response.results[1].plugins_run['workers'])
        self.assertEqual(
            'extract_payload', response.results[1].plugins_run['workers'][0]
        )
        self.assertEqual('simple_worker', response.results[1].extracted_by[0])
        self.assertEqual('extract_payload', response.results[1].extracted_by[1])

    async def test_scan_with_nested_required_plugin(self):
        s = Stoq(base_dir=utils.get_data_dir())
        simple_worker = s.load_plugin('simple_worker')
        simple_worker.EXTRACTED_DISPATCH_TO = ['simple_worker']
        simple_worker.required_workers.add('dummy_worker')
        dummy_worker = s.load_plugin('dummy_worker')
        dummy_worker.required_workers.add('extract_payload')
        response = await s.scan(
            self.generic_content, add_start_dispatch=['simple_worker']
        )
        self.assertEqual(4, len(response.results))
        self.assertCountEqual(
            ['dummy_worker', 'extract_payload', 'simple_worker'],
            response.results[0].plugins_run['workers'],
        )
        self.assertIn('extract_payload', response.results[1].extracted_by)
        self.assertCountEqual(
            ['dummy_worker', 'extract_payload', 'simple_worker'],
            response.results[2].plugins_run['workers'],
        )
        self.assertIn('extract_payload', response.results[3].extracted_by)

    async def test_scan_with_required_plugin_max_depth(self):
        s = Stoq(base_dir=utils.get_data_dir(), max_required_worker_depth=1)
        simple_worker = s.load_plugin('simple_worker')
        simple_worker.EXTRACTED_DISPATCH_TO = ['simple_worker']
        simple_worker.required_workers.add('dummy_worker')
        dummy_worker = s.load_plugin('dummy_worker')
        dummy_worker.required_workers.add('extract_payload')
        response = await s.scan(
            self.generic_content, add_start_dispatch=['simple_worker']
        )
        self.assertEqual(1, len(response.results))
        self.assertIn('Max required plugin depth', response.errors[0].error)

    async def test_scan_with_required_plugin_circular_reference(self):
        s = Stoq(base_dir=utils.get_data_dir(), max_required_worker_depth=2000)
        simple_worker = s.load_plugin('simple_worker')
        simple_worker.EXTRACTED_DISPATCH_TO = ['simple_worker']
        simple_worker.required_workers.add('dummy_worker')
        dummy_worker = s.load_plugin('dummy_worker')
        dummy_worker.required_workers.add('simple_worker')
        response = await s.scan(
            self.generic_content, add_start_dispatch=['simple_worker']
        )
        self.assertEqual(1, len(response.results))
        self.assertIn('Circular', response.errors[0].error)

    async def test_source_archive(self):
        s = Stoq(base_dir=utils.get_data_dir(), source_archivers=['simple_archiver'])
        simple_archiver = s.load_plugin('simple_archiver')
        simple_archiver.PAYLOAD = b'This is a payload'
        task = ArchiverResponse(results={'path': '/tmp/123'})
        payload = await simple_archiver.get(task)
        self.assertEqual('/tmp/123', payload.results.payload_meta.extra_data['path'])
        self.assertEqual(payload.content, simple_archiver.PAYLOAD)

    @asynctest.skipIf(
        sys.version_info >= (3, 8), 'skipping because python >= 3.8 breaks test'
    )
    async def test_dest_archive(self):
        s = Stoq(base_dir=utils.get_data_dir(), dest_archivers=['dummy_archiver'])
        dummy_archiver = s.load_plugin('dummy_archiver')
        dummy_archiver.archive = asynctest.create_autospec(
            dummy_archiver.archive, return_value=None
        )
        response = await s.scan(
            self.generic_content, request_meta=RequestMeta(archive_payloads=True)
        )
        dummy_archiver.archive.assert_awaited_once()
        self.assertIn('dummy_archiver', response.results[0].plugins_run['archivers'])

    async def test_dont_dest_archive_request(self):
        s = Stoq(base_dir=utils.get_data_dir(), dest_archivers=['dummy_archiver'])
        dummy_archiver = s.load_plugin('dummy_archiver')
        dummy_archiver.archive = asynctest.CoroutineMock(return_value=None)
        response = await s.scan(
            self.generic_content,
            add_start_dispatch=['extract_payload'],
            request_meta=RequestMeta(archive_payloads=False),
        )
        dummy_archiver.archive.assert_not_awaited()
        self.assertNotIn('dummy_archiver', response.results[0].plugins_run['archivers'])
        self.assertNotIn('dummy_archiver', response.results[1].plugins_run['archivers'])

    @asynctest.skipIf(
        sys.version_info >= (3, 8), 'skipping because python >= 3.8 breaks test'
    )
    async def test_dont_dest_archive_payload(self):
        s = Stoq(base_dir=utils.get_data_dir(), dest_archivers=['dummy_archiver'])
        dummy_archiver = s.load_plugin('dummy_archiver')
        dummy_archiver.archive = asynctest.create_autospec(
            dummy_archiver.archive, return_value=None
        )
        response = await s.scan(
            self.generic_content,
            payload_meta=PayloadMeta(should_archive=False),
            add_start_dispatch=['extract_payload'],
            request_meta=RequestMeta(archive_payloads=True),
        )
        dummy_archiver.archive.assert_awaited_once()
        self.assertNotIn('dummy_archiver', response.results[0].plugins_run['archivers'])
        self.assertIn('dummy_archiver', response.results[1].plugins_run['archivers'])

    async def test_dont_dest_archive_yara(self):
        s = Stoq(base_dir=utils.get_data_dir(), dest_archivers=['dummy_archiver'])
        response = await s.scan(
            self.generic_content, request_meta=RequestMeta(archive_payloads=True)
        )
        # The yara rule 'similar_simple_rule' should set save = False
        self.assertNotIn('dummy_archiver', response.results[0].archivers)

    async def test_worker_in_results(self):
        s = Stoq(base_dir=utils.get_data_dir())
        response = await s.scan(
            self.generic_content, add_start_dispatch=['simple_worker']
        )
        self.assertIn('simple_worker', response.results[0].workers)
        self.assertIn('valuable_insight', response.results[0].workers['simple_worker'])
        self.assertEqual(len(response.errors), 0)

    async def test_worker_not_in_results(self):
        s = Stoq(base_dir=utils.get_data_dir())
        response = await s.scan(
            self.generic_content, add_start_dispatch=['dummy_worker']
        )
        self.assertNotIn('dummy_worker', response.results[0].workers)

    async def test_archiver_in_results(self):
        s = Stoq(base_dir=utils.get_data_dir(), dest_archivers=['simple_archiver'])
        response = await s.scan(
            self.generic_content, request_meta=RequestMeta(archive_payloads=True)
        )
        self.assertIn('simple_archiver', response.results[0].archivers)
        self.assertIn('file_save_id', response.results[0].archivers['simple_archiver'])
        self.assertEqual(len(response.errors), 0)

    async def test_archiver_not_in_results(self):
        s = Stoq(base_dir=utils.get_data_dir(), dest_archivers=['dummy_archiver'])
        response = await s.scan(
            self.generic_content, request_meta=RequestMeta(archive_payloads=True)
        )
        self.assertNotIn('dummy_archiver', response.results[0].archivers)

    async def test_worker_exception(self):
        s = Stoq(base_dir=utils.get_data_dir())
        simple_worker = s.load_plugin('simple_worker')
        simple_worker.RAISE_EXCEPTION = True
        response = await s.scan(
            self.generic_content, add_start_dispatch=['simple_worker']
        )
        self.assertIn('simple_worker', response.results[0].plugins_run['workers'])
        self.assertEqual(len(response.errors), 1)
        self.assertIn('Test exception', response.errors[0].error)

    async def test_worker_errors(self):
        s = Stoq(base_dir=utils.get_data_dir())
        simple_worker = s.load_plugin('simple_worker')
        simple_worker.RETURN_ERRORS = True
        response = await s.scan(
            self.generic_content, add_start_dispatch=['simple_worker']
        )
        self.assertIn('simple_worker', response.results[0].plugins_run['workers'][0])
        self.assertIn('simple_worker', response.results[0].workers)
        self.assertEqual(len(response.errors), 1)
        self.assertIn('Test error', response.errors[0].error)

    async def test_source_archiver_exception(self):
        s = Stoq(base_dir=utils.get_data_dir(), source_archivers=['simple_archiver'])
        simple_archiver = s.load_plugin('simple_archiver')
        simple_archiver.RAISE_EXCEPTION = True
        task = 'This will fail'
        with self.assertRaises(Exception) as context:
            await simple_archiver.get(task)
        self.assertTrue('Test exception', context.exception)

    async def test_dest_archiver_exception(self):
        s = Stoq(base_dir=utils.get_data_dir(), dest_archivers=['simple_archiver'])
        simple_archiver = s.load_plugin('simple_archiver')
        simple_archiver.RAISE_EXCEPTION = True
        response = await s.scan(self.generic_content)
        self.assertIn('simple_archiver', response.results[0].plugins_run['archivers'])
        self.assertEqual(len(response.errors), 1)
        self.assertIn('Test exception', response.errors[0].error)

    async def test_dest_archiver_errors(self):
        s = Stoq(base_dir=utils.get_data_dir(), dest_archivers=['simple_archiver'])
        simple_archiver = s.load_plugin('simple_archiver')
        simple_archiver.RETURN_ERRORS = True
        response = await s.scan(self.generic_content)
        self.assertIn('simple_archiver', response.results[0].plugins_run['archivers'])
        self.assertIn('simple_archiver', response.results[0].archivers)
        self.assertEqual(len(response.errors), 1)
        self.assertIn('Test error', response.errors[0].error)

    async def test_max_recursion(self):
        s = Stoq(base_dir=utils.get_data_dir(), always_dispatch=['extract_payload'])
        response = await s.scan(self.generic_content)
        self.assertEqual(len(response.results), s.max_recursion + 1)
        self.assertIn('Final worker round', response.errors[0].error)

    async def test_dedup(self):
        # The simple_worker plugin always extracts the same payload
        s = Stoq(base_dir=utils.get_data_dir(), always_dispatch=['simple_worker'])
        response = await s.scan(self.generic_content)
        self.assertEqual(len(response.results), 2)

    @asynctest.skipIf(
        sys.version_info >= (3, 8), 'skipping because python >= 3.8 breaks test'
    )
    async def test_connector(self):
        s = Stoq(base_dir=utils.get_data_dir(), connectors=['dummy_connector'])
        dummy_connector = s.load_plugin('dummy_connector')
        dummy_connector.save = asynctest.create_autospec(dummy_connector.save)
        await s.scan(self.generic_content)
        dummy_connector.save.assert_awaited_once()

    async def test_connector_exception(self):
        s = Stoq(base_dir=utils.get_data_dir(), connectors=['dummy_connector'])
        dummy_connector = s.load_plugin('dummy_connector')
        dummy_connector.save = asynctest.create_autospec(
            dummy_connector.save, side_effect=RuntimeError('Unexpected exception')
        )
        logging.disable(logging.NOTSET)
        with self.assertLogs(level='ERROR') as cm:
            await s.scan(self.generic_content)
        self.assertTrue(
            cm.output[0].startswith(
                'ERROR:stoq:Failed to save results using dummy_connector'
            )
        )
        logging.disable(logging.CRITICAL)

    async def test_decorator(self):
        s = Stoq(base_dir=utils.get_data_dir(), decorators=['simple_decorator'])
        _ = s.load_plugin('simple_decorator')
        response = await s.scan(self.generic_content)
        self.assertIn('simple_decorator', response.decorators)
        self.assertIn('simple_decoration', response.decorators['simple_decorator'])
        self.assertEqual(len(response.errors), 0)

    async def test_decorator_errors(self):
        s = Stoq(base_dir=utils.get_data_dir(), decorators=['simple_decorator'])
        simple_decorator = s.load_plugin('simple_decorator')
        simple_decorator.RETURN_ERRORS = True
        response = await s.scan(self.generic_content)
        self.assertIn('simple_decorator', response.decorators)
        self.assertIn('simple_decoration', response.decorators['simple_decorator'])
        self.assertEqual(len(response.errors), 1)
        self.assertIn('Test error', response.errors[0].error)

    async def test_decorator_exception(self):
        s = Stoq(base_dir=utils.get_data_dir(), decorators=['simple_decorator'])
        simple_decorator = s.load_plugin('simple_decorator')
        simple_decorator.RAISE_EXCEPTION = True
        response = await s.scan(self.generic_content)
        self.assertEqual(len(response.errors), 1)
        self.assertIn('Test exception', response.errors[0].error)

    async def test_multiclass_plugin(self):
        s = Stoq(base_dir=utils.get_data_dir(), dispatchers=['multiclass_plugin'])
        multiclass_worker = s.load_plugin('multiclass_plugin')
        multiclass_worker.scan = asynctest.create_autospec(
            multiclass_worker.scan, return_value=None
        )
        response = await s.scan(self.generic_content)
        self.assertEqual(len(multiclass_worker.scan.await_args[0]), 2)
        self.assertEqual(
            multiclass_worker.scan.await_args[0][0].dispatch_meta['multiclass_plugin'][
                'multiclass_plugin'
            ]['rule0'],
            'multiclass_plugin',
        )
        self.assertIn(
            'multiclass_plugin', response.results[0].plugins_run['workers'][0]
        )
        self.assertIn('multiclass_plugin', s._loaded_dispatcher_plugins)
        self.assertIn('multiclass_plugin', s._loaded_plugins)

        ############ 'RUN' TESTS ############

    @asynctest.skipIf(
        sys.version_info >= (3, 8), 'skipping because python >= 3.8 breaks test'
    )
    async def test_provider(self):
        s = Stoq(
            base_dir=utils.get_data_dir(),
            providers=['simple_provider'],
            connectors=['dummy_connector'],
        )
        dummy_connector = s.load_plugin('dummy_connector')
        dummy_connector.save = asynctest.create_autospec(dummy_connector.save)
        await s.run()
        dummy_connector.save.assert_awaited_once()

    async def test_no_providers(self):
        s = Stoq(base_dir=utils.get_data_dir())
        with self.assertRaises(StoqException):
            await s.run()

    @asynctest.skipIf(
        sys.version_info >= (3, 8), 'skipping because python >= 3.8 breaks test'
    )
    async def test_multi_providers(self):
        s = Stoq(
            base_dir=utils.get_data_dir(),
            providers=['simple_provider', 'simple_provider2'],
            connectors=['dummy_connector'],
        )
        dummy_connector = s.load_plugin('dummy_connector')
        dummy_connector.save = asynctest.create_autospec(dummy_connector.save)
        await s.run()
        self.assertEqual(dummy_connector.save.await_count, 2)

    async def test_provider_exception(self):
        s = Stoq(base_dir=utils.get_data_dir(), providers=['simple_provider'])
        simple_provider = s.load_plugin('simple_provider')
        simple_provider.RAISE_EXCEPTION = True
        logging.disable(logging.NOTSET)
        with self.assertLogs(level='ERROR') as cm:
            await s.run()
        self.assertTrue(
            cm.output[0].startswith('ERROR:stoq:Test exception, please ignore')
        )
        logging.disable(logging.CRITICAL)

    @asynctest.skipIf(
        sys.version_info >= (3, 8), 'skipping because python >= 3.8 breaks test'
    )
    async def test_provider_with_task(self):
        s = Stoq(
            base_dir=utils.get_data_dir(),
            source_archivers=['simple_archiver'],
            providers=['simple_provider'],
            connectors=['dummy_connector'],
        )
        dummy_connector = s.load_plugin('dummy_connector')
        dummy_connector.save = asynctest.create_autospec(dummy_connector.save)
        simple_provider = s.load_plugin('simple_provider')
        simple_provider.RETURN_PAYLOAD = False
        simple_archiver = s.load_plugin('simple_archiver')
        simple_archiver.PAYLOAD = b'This is a payload'
        await s.run()
        dummy_connector.save.assert_awaited_once()

    @asynctest.skipIf(
        sys.version_info >= (3, 8), 'skipping because python >= 3.8 breaks test'
    )
    async def test_provider_with_start_dispatch(self):
        s = Stoq(
            base_dir=utils.get_data_dir(),
            source_archivers=['simple_archiver'],
            providers=['simple_provider'],
            connectors=['dummy_connector'],
        )
        dummy_connector = s.load_plugin('dummy_connector')
        dummy_connector.save = asynctest.create_autospec(dummy_connector.save)
        simple_provider = s.load_plugin('simple_provider')
        simple_provider.RETURN_PAYLOAD = True
        simple_archiver = s.load_plugin('simple_archiver')
        simple_archiver.PAYLOAD = b'This is a payload'
        dummy_worker = s.load_plugin('dummy_worker')
        dummy_worker.scan = asynctest.create_autospec(dummy_worker.scan)
        await s.run(add_start_dispatch=['dummy_worker'])
        dummy_worker.scan.assert_awaited_once()
        dummy_connector.save.assert_awaited_once()

    def test_stoqresponse_to_str(self):
        response = StoqResponse(Request(), [])
        response_str = str(response)
        response_dict = json.loads(response_str)
        self.assertIsInstance(response_str, str)
        self.assertIsInstance(response_dict, dict)

    def test_payloadmeta_to_str(self):
        response = PayloadMeta()
        response_str = str(response)
        response_dict = json.loads(response_str)
        self.assertIsInstance(response_str, str)
        self.assertIsInstance(response_dict, dict)

    def test_requestmeta_to_str(self):
        response = RequestMeta()
        response_str = str(response)
        response_dict = json.loads(response_str)
        self.assertIsInstance(response_str, str)
        self.assertIsInstance(response_dict, dict)

    def test_payloadresults_to_str(self):
        payload = Payload(self.generic_content)
        response_str = str(payload.results)
        response_dict = json.loads(response_str)
        self.assertIsInstance(response_str, str)
        self.assertIsInstance(response_dict, dict)

    def test_workerresponse_to_str(self):
        response = WorkerResponse()
        response_str = str(response)
        response_dict = json.loads(response_str)
        self.assertIsInstance(response_str, str)
        self.assertIsInstance(response_dict, dict)

    def test_archiverresponse_to_str(self):
        response = ArchiverResponse()
        response_str = str(response)
        response_dict = json.loads(response_str)
        self.assertIsInstance(response_str, str)
        self.assertIsInstance(response_dict, dict)

    def test_dispatcherresponse_to_str(self):
        response = DispatcherResponse()
        response_str = str(response)
        response_dict = json.loads(response_str)
        self.assertIsInstance(response_str, str)
        self.assertIsInstance(response_dict, dict)

    def test_decoratorresponse_to_str(self):
        response = DecoratorResponse()
        response_str = str(response)
        response_dict = json.loads(response_str)
        self.assertIsInstance(response_str, str)
        self.assertIsInstance(response_dict, dict)

    async def test_reconstruct_all_subresponses(self):
        # Construct a fake stoq_response as if it were generated from a file
        # A.zip that contains two files, B.txt and C.zip, where C.zip contains D.txt
        results = [
            Payload(content=b'', payload_id='A.zip', payload_meta=PayloadMeta()),
            Payload(
                content=b'',
                payload_id='B.txt',
                payload_meta=PayloadMeta(),
                extracted_from='A.zip',
                extracted_by='fake',
            ),
            Payload(
                content=b'',
                payload_id='C.zip',
                payload_meta=PayloadMeta(),
                extracted_from='A.zip',
                extracted_by='fake',
            ),
            Payload(
                content=b'',
                payload_id='D.txt',
                payload_meta=PayloadMeta(),
                extracted_from='C.zip',
                extracted_by='fake',
            ),
        ]
        request = Request(request_meta=RequestMeta(extra_data={'check': 'me'}))
        payload_count = 1
        for result in results:
            result.results.workers['fake'] = f'result-{payload_count}'
            result.results.plugins_run['workers'].append('fake')
            request.payloads.append(result)
            payload_count += 1

        initial_response = StoqResponse(request)
        s = Stoq(base_dir=utils.get_data_dir(), decorators=['simple_decorator'])
        all_subresponses = [
            r async for r in s.reconstruct_all_subresponses(initial_response)
        ]
        # We expect there to be four "artificial" responses generated, one for
        # each payload as the root.
        self.assertEqual(len(all_subresponses), 4)
        # We expect the first response to have all 4 payloads, the second response
        # to have just the second payload, the third response to have the third
        # and fourth payload, and the fourth response to have just the fourth payload
        self.assertEqual(
            [len(stoq_response.results) for stoq_response in all_subresponses],
            [4, 1, 2, 1],
        )
        self.assertEqual(
            [
                stoq_response.results[0].workers['fake']
                for stoq_response in all_subresponses
            ],
            ['result-1', 'result-2', 'result-3', 'result-4'],
        )
        self.assertTrue(
            all(
                'simple_decorator' in stoq_response.decorators
                for stoq_response in all_subresponses
            )
        )
        # Assert that they all have the same scan ID
        self.assertEqual(
            len({stoq_response.scan_id for stoq_response in all_subresponses}), 1
        )
