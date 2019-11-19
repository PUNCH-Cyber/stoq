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

import os
import sys
import select
import asyncio
import argparse
import unittest
from pathlib import Path
from typing import Dict, Union

import stoq.tests as tests
from stoq.installer import StoqPluginInstaller
from stoq import Stoq, PayloadMeta, RequestMeta, __version__


def main() -> None:
    about = f'stoQ :: v{__version__} :: an automated analysis framework'
    # If $STOQ_HOME exists, set our base directory to that, otherwise
    # use $HOME/.stoq
    try:
        stoq_home = str(
            Path(os.getenv('STOQ_HOME', f'{str(Path.home())}/.stoq')).resolve(
                strict=True
            )
        )
    except FileNotFoundError as err:
        print(f"$STOQ_HOME is invalid, exiting: {err}", file=sys.stderr)
        sys.exit(1)

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=about,
        epilog='''
Examples:

    - Scan a file with installed plugins and dispatch rules:

    $ %(prog)s scan mybadfile.exe

    - Scan a file and force it to go through the yara plugin:

    $ %(prog)s scan mybadfile.exe -s yara

    - Ingest from PubSub, force all payloads through yara, trid, and exif,
      then save results to file:

    $ %(prog)s run -a yara trid exif -P pubsub -C file

    - Monitor a directory (specified in dirmon.stoq) for newly created files
      send them to workers, and archive all payloads into MongoDB:

    $ %(prog)s run -P dirmon -A mongodb

    - Install a plugin from a directory

    $ %(prog)s install path/to/plugin_directory

    ''',
    )
    subparsers = parser.add_subparsers(title='commands', dest='command')
    subparsers.required = True

    scan = subparsers.add_parser('scan', help='Scan a given payload')
    scan.add_argument(
        'file',
        nargs='?',
        type=argparse.FileType('rb'),
        default=sys.stdin.buffer,
        help='File to scan, can also be provided from stdin',
    )

    run = subparsers.add_parser(
        'run', help='Continually ingest and scan payloads from Provider plugins'
    )
    run.add_argument(
        '-P', '--providers', nargs='+', help='Provider plugins to ingest payloads from'
    )

    # Add shared arguments so they still show up in the help dialog
    for subparser in [scan, run]:
        subparser.add_argument(
            '-A',
            '--dest-archivers',
            nargs='+',
            help='Archiver plugins to send payloads to',
        )
        subparser.add_argument(
            '-S',
            '--source-archivers',
            nargs='+',
            help='Archiver plugins to read payload from',
        )
        subparser.add_argument(
            '-D',
            '--decorators',
            nargs='+',
            help='Decorator plugins to send results to before saving',
        )
        subparser.add_argument(
            '-C', '--connectors', nargs='+', help='Connector plugins to send results to'
        )
        subparser.add_argument(
            '-R',
            '--dispatchers',
            nargs='+',
            help='Dispatcher plugins to use send payloads to',
        )
        subparser.add_argument(
            '-a',
            '--always-dispatch',
            nargs='+',
            help='Worker plugins to always dispatch plugins to',
        )
        subparser.add_argument(
            '-s',
            '--start-dispatch',
            nargs='+',
            help='Worker plugins to add to the original payload dispatch',
        )
        subparser.add_argument(
            '--max-recursion',
            type=int,
            default=None,
            help='Maximum level of recursion into a payload and extracted payloads',
        )
        subparser.add_argument('--plugin-opts', nargs='+', help='Plugin options')
        subparser.add_argument(
            '--request-source',
            default=None,
            help='Source name to add to initial scan request',
        )
        subparser.add_argument(
            '--request-extra',
            nargs='+',
            help='Key/value pair to add to initial scan request metadata',
        )
        subparser.add_argument(
            '--plugin-dir', nargs='+', help='Directory(ies) containing stoQ plugins'
        )
        subparser.add_argument(
            '--config-file',
            default=f'{stoq_home}/stoq.cfg',
            help='Path to stoQ configuration file',
        )
        subparser.add_argument(
            '--log-level',
            default=None,
            choices=['debug', 'info', 'warning', 'error' 'crtical'],
            help='Log level for stoQ events',
        )

    plugin_list = subparsers.add_parser('list', help='List available plugins')
    plugin_list.add_argument(
        '--plugin-dir', nargs='+', help='Directory(ies) containing stoQ plugins'
    )

    install = subparsers.add_parser('install', help='Install a given plugin')
    install.add_argument(
        'plugin_path', help='Directory or Github repo of the plugin to install'
    )
    install.add_argument(
        '--install_dir',
        default=os.path.join(stoq_home, 'plugins'),
        help='Override the default plugin installation directory',
    )
    install.add_argument(
        '--upgrade',
        action='store_true',
        help='Force the plugin to be upgraded if it already exists',
    )
    install.add_argument(
        '--github', action='store_true', help='Install plugin from Github repository'
    )

    subparsers.add_parser('test', help='Run stoQ tests')
    args = parser.parse_args()

    plugin_opts: Union[Dict, None] = None
    try:
        if args.plugin_opts:
            plugin_opts = {}
            for arg in args.plugin_opts:
                plugin_name, plugin_option = arg.split(':')
                opt, value = plugin_option.split('=')
                if value.lower() == 'true':
                    value = True
                elif value.lower() == 'false':
                    value = False
                if plugin_name in plugin_opts:
                    plugin_opts[plugin_name].update({opt: value})
                else:
                    plugin_opts[plugin_name] = {opt: value}
    except AttributeError:
        pass
    except ValueError as err:
        print(f'Failed parsing plugin option: {err}')

    request_meta = RequestMeta()
    try:
        if args.request_source:
            request_meta.source = args.request_source
        if args.request_extra:
            for arg in args.request_extra:
                extra_key, extra_value = arg.split('=')
                if extra_value.lower() == 'true':
                    extra_value = True
                elif extra_value.lower() == 'false':
                    extra_value = False
                request_meta.extra_data[extra_key] = extra_value
    except AttributeError:
        pass
    except ValueError as err:
        print(f'Failed parsing request metadata option: {err}')

    try:
        if not os.path.isfile(args.config_file):
            print(f'Warning: {args.config_file} does not exist, using stoQ defaults!')
    except AttributeError:
        pass

    if args.command == 'scan':
        with args.file as f:
            # Verify that the file or stdin has some sort of data
            if not select.select([f], [], [], 0.0)[0]:
                print('Error: No content to scan was provided')
                sys.exit(2)
            content = f.read()
        if not content:
            print('Error: The provided content to scan was empty')
            sys.exit(2)

        if args.file.name == '<stdin>':
            filename = None
        else:
            path = args.file.name
            try:
                filename = os.path.basename(path.encode('utf-8'))
            except AttributeError:
                filename = os.path.basename(path)

        stoq = Stoq(
            base_dir=stoq_home,
            config_file=args.config_file,
            log_level=args.log_level,
            plugin_opts=plugin_opts,
            source_archivers=args.source_archivers,
            dest_archivers=args.dest_archivers,
            connectors=args.connectors,
            dispatchers=args.dispatchers,
            decorators=args.decorators,
            always_dispatch=args.always_dispatch,
            max_recursion=args.max_recursion,
            plugin_dir_list=args.plugin_dir,
        )
        response = asyncio.get_event_loop().run_until_complete(
            stoq.scan(
                content,
                PayloadMeta(extra_data={'filename': filename}),
                request_meta=request_meta,
                add_start_dispatch=args.start_dispatch,
            )
        )
        if not args.connectors:
            print(response)
    elif args.command == 'run':
        stoq = Stoq(
            base_dir=stoq_home,
            config_file=args.config_file,
            log_level=args.log_level,
            plugin_opts=plugin_opts,
            providers=args.providers,
            source_archivers=args.source_archivers,
            dest_archivers=args.dest_archivers,
            connectors=args.connectors,
            dispatchers=args.dispatchers,
            decorators=args.decorators,
            always_dispatch=args.always_dispatch,
            max_recursion=args.max_recursion,
            plugin_dir_list=args.plugin_dir,
        )
        asyncio.get_event_loop().run_until_complete(
            stoq.run(request_meta=request_meta, add_start_dispatch=args.start_dispatch)
        )
    elif args.command == 'list':
        stoq = Stoq(base_dir=stoq_home, plugin_dir_list=args.plugin_dir)
        print(about)
        print('-' * len(about))
        for name, info in stoq.list_plugins().items():
            print(f'{name:<20s} v{info["version"]:<10s}{info["description"]}')
            print(f'\t\t\t\t- {", ".join(info["classes"]):<20s}')

    elif args.command == 'install':
        StoqPluginInstaller.install(
            args.plugin_path, args.install_dir, args.upgrade, args.github
        )
        print(f'Successfully installed {args.plugin_path} into {args.install_dir}')
    elif args.command == 'test':
        test_path = os.path.dirname(tests.__file__)
        test_suite = unittest.TestLoader().discover(test_path)
        unittest.TextTestRunner(verbosity=1).run(test_suite)


if __name__ == '__main__':
    main()
