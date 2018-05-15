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

from time import sleep
from pathlib import Path

from argparse import RawDescriptionHelpFormatter, ArgumentParser

import stoq
from stoq import __version__
from stoq.core import Stoq
from stoq.shell import StoqShell
from stoq.logo import print_logo
from stoq.helpers import run_stoq_tests, run_plugin_tests
from stoq.plugins.installer import StoqPluginInstaller


def main():

    # If $STOQ_HOME exists, set our base directory to that, otherwise
    # use ~/.stoq
    homedir = os.getenv("STOQ_HOME", "{}/.stoq".format(str(Path.home())))

    s = Stoq(argv=sys.argv, base_dir=homedir)

    logo = print_logo()

    parser = ArgumentParser(
        formatter_class=RawDescriptionHelpFormatter,
        description='''
    stoQ - an automated analysis framework

            {}
    Available Commands:
        help     Display help message
        shell    Launch an interactive shell
        list     List available plugins
        worker   Load specified worker plugin
        install  Install a stoQ plugin
        test     Run stoQ tests

            '''.format(logo),
        usage='%(prog)s [command] [<args>]',
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

    parser.add_argument(dest="command", help="Commands")
    options = parser.parse_args(s.argv[1:2])

    if not options.command or options.command == 'help':
        parser.print_help()

    # Display a listing of valid plugins and their category
    elif options.command == "list":
        s.list_plugins()

    elif options.command == "install":
        installer = StoqPluginInstaller(s)
        installer.install()

    elif options.command == "shell":
        StoqShell(s).cmdloop()

    elif options.command == "test":
        # We are going to manually parse the command line options here instead
        # of using argparse.
        try:
            if s.argv[2] == "stoq":
                run_stoq_tests(s)
            elif s.argv[2] == "all":
                run_plugin_tests(s)
            else:
                run_plugin_tests(s, plugin=s.argv[2:])
        except IndexError:
            parser.print_usage()
            print("No test type provided. Valid options are: {stoq|all|plugin name ...}")
    else:
        # Initialize and load the worker plugin and make it an object of our
        # stoq class
        s.log.info("Starting stoQ v{}".format(__version__))

        worker = s.load_plugin(options.command, 'worker')
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
