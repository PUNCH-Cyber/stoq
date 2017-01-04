#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
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

import sys

from time import sleep

from argparse import RawDescriptionHelpFormatter, ArgumentParser

from stoq.core import Stoq
from stoq.shell import StoqShell
from stoq.logo import print_logo


if __name__ == '__main__':

    stoq = Stoq(argv=sys.argv)

    parser = ArgumentParser(formatter_class=RawDescriptionHelpFormatter,
                            description=print_logo(),
                            usage='''
    %(prog)s [command] [<args>]

    Available Commands:
        help    Display help message
        shell   Launch an interactive shell
        list    List available plugins
        worker  Load specified worker plugin
        install Install a stoQ plugin
    ''',
                            epilog='''
    Examples:

        - Scan a file with yara:

        $ %(prog)s yara -F mybadfile.exe

        - Monitor a directory for newly created files in the new_files
          directory, send them to workers, and archive the file into MongoDB:

        $ %(prog)s publisher -I dirmon -F new_files/ -w yara -w trid -w exif -A mongodb

        - Start workers, ingest from RabbitMQ, and save results to file:

        $ %(prog)s yara -C file -I rabbitmq &
        $ %(prog)s trid -C file -I rabbitmq &
        $ %(prog)s exif -C file -I rabbitmq &

        - Install a plugin from a directory

        $ %(prog)s install path/to/plugin_directory

        - Display worker specific command line arguments

        $ %(prog)s yara -h

    ''')

    parser.add_argument("command", help="Subcommand to be run")
    options = parser.parse_args(stoq.argv[1:2])

    if not options.command or options.command == 'help':
        parser.print_help()

    # Display a listing of valid plugins and their category
    elif options.command == "list":
        stoq.list_plugins()

    elif options.command == "install":
        from stoq.plugins import StoqPluginInstaller
        installer = StoqPluginInstaller(stoq)
        installer.install()

    elif options.command == "shell":
        StoqShell(stoq).cmdloop()

    else:
        # Initialize and load the worker plugin and make it an object of our
        # stoq class
        worker = stoq.load_plugin(options.command, 'worker')
        if not worker:
            exit(-1)

        if worker.cron:
            # Look liks a cron interval was provided, let's loop per the value provided
            while True:
                worker.run()
                sleep(worker.cron)
        else:
            # No cron value was provided, let's run once and exit.
            worker.run()

# Done!
exit(0)
