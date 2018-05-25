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

import argparse
import os
from pathlib import Path
import select
import sys

from stoq import Stoq, PayloadMeta
import stoq.helpers as helpers
from stoq.logo import get_logo


def main() -> None:
    # If $STOQ_HOME exists, set our base directory to that, otherwise
    # use ~/.stoq
    homedir = os.getenv('STOQ_HOME', '{}/.stoq'.format(str(Path.home())))

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='''
    stoQ - an automated analysis framework

            {}
            '''.format(get_logo()),
        epilog='''
Examples:

    - Scan a file with installed plugins and dispatch rules:

    $ %(prog)s scan mybadfile.exe

    - Scan a file and force it to go through the yara plugin:

    $ %(prog)s scan mybadfile.exe -s yara

    - Ingest from RabbitMQ, force all payloads through yara, trid, and exif,
      then save results to file:

    $ %(prog)s run -a yara trid exif -P rabbitmq -C file

    - Monitor a directory (specified in dirmon.stoq) for newly created files
      send them to workers, and archive all payloads into MongoDB:

    $ %(prog)s run -P dirmon -A mongodb

    - Install a plugin from a directory

    $ %(prog)s install path/to/plugin_directory

    ''')
    subparsers = parser.add_subparsers(title='commands', dest='command')
    subparsers.required = True

    scan = subparsers.add_parser('scan', help='Scan a given payload')
    scan.add_argument(
        'file',
        nargs='?',
        type=argparse.FileType('rb'),
        default=sys.stdin.buffer,
        help='File to scan, can also be provided from stdin')
    scan.add_argument(
        '-s',
        '--start-dispatch',
        nargs='+',
        help='Worker plugins to add to the original payload dispatch')

    run = subparsers.add_parser(
        'run',
        help='Continually ingest and scan payloads from Provider plugins')
    run.add_argument(
        '-P',
        '--providers',
        nargs='+',
        help='Provider plugins to ingest payloads from')

    # Add shared arguments so they still show up in the help dialog
    for subparser in [scan, run]:
        subparser.add_argument(
            '-A',
            '--archivers',
            nargs='+',
            help='Archiver plugins to send payloads to')
        subparser.add_argument(
            '-C',
            '--connectors',
            nargs='+',
            help='Connector plugins to send results to')
        subparser.add_argument(
            '-a',
            '--always-dispatch',
            nargs='+',
            help='Worker plugins to always dispatch plugins to')

    subparsers.add_parser('list', help='List available plugins')
    subparsers.add_parser('install', help='Install a given plugin')
    subparsers.add_parser('shell', help='Launch an interactive shell')
    subparsers.add_parser('test', help='Run stoQ tests')

    args = parser.parse_args()

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
            base_dir=homedir,
            archivers=args.archivers,
            connectors=args.connectors,
            always_dispatch=args.always_dispatch)
        response = stoq.scan(
            content,
            PayloadMeta(filename=filename),
            add_start_dispatch=args.start_dispatch)
        print(helpers.dumps(response))
    elif args.command == 'run':
        stoq = Stoq(
            base_dir=homedir,
            providers=args.providers,
            archivers=args.archivers,
            connectors=args.connectors,
            always_dispatch=args.always_dispatch)
        stoq.run()
    elif args.command == 'list':
        stoq = Stoq(base_dir=homedir)
        print(stoq.list_plugins())
    elif args.command == 'install':
        # TODO
        pass
    elif args.command == 'shell':
        # TODO
        pass
    elif args.command == 'test':
        # TODO
        pass


if __name__ == '__main__':
    main()
