import argparse
import os
import sys
import subprocess
import glob
import configparser
import re


class StoqPluginInstaller:

    pip_exists_str = "already exists. Specify --upgrade to force replacement."

    def __init__(self, stoq):

        self.stoq = stoq
        self.plugin_info = {}

        parser = argparse.ArgumentParser()
        installer_opts = parser.add_argument_group("Plugin Installer Options")
        installer_opts.add_argument("plugin", help="stoQ Plugin Archive")
        installer_opts.add_argument("--upgrade",
                                    action="store_true",
                                    help="Upgrade the stoQ Plugin")
        installer_opts.add_argument("-P", "--plugin-dir",
                                    dest='plugin_dir',
                                    default=False,
                                    help="Root directory to install plugin to")

        options = parser.parse_args(self.stoq.argv[2:])

        if not options.plugin:
            parser.print_help()
            exit(-1)

        # Set the source path of the plugin archive/directory
        self.plugin = os.path.abspath(options.plugin)

        # Define a directory to install a plugin to, if so desired
        self.plugin_dir = options.plugin_dir

        self.upgrade_plugin = options.upgrade

    def install(self):
        self.stoq.log.info("Looking for plugin in {}...".format(self.plugin))
        try:
            if os.path.isdir(self.plugin):
                self.setup_from_dir()
            else:
                self.stoq.log.critical("Unable to install plugin. Is this a valid plugin?")
                exit(-1)

            try:
                cmd = [
                    sys.executable,
                    '-m',
                    'pip',
                    'install',
                    self.plugin,
                    '-t',
                    self.plugin_root,
                ]
                # Use pip to install/upgrade the plugin in the appropriate
                # directory for this plugin category
                if self.upgrade_plugin:
                    cmd.append('--upgrade')

                output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
                if self.pip_exists_str.encode() in output:
                    self.stoq.log.critical("Plugin {}".format(self.pip_exists_str))
                    exit(-1)

                # Time to install the requirements, if they exist.
                requirements = "{}/requirements.txt".format(self.plugin)
                if os.path.isfile(requirements):
                    subprocess.check_call([
                        sys.executable,
                        '-m',
                        'pip',
                        'install',
                        '--quiet',
                        '-r',
                        requirements,
                    ])

            except Exception as err:
                self.stoq.log.critical("Error installing requirements: {}".format(str(err)))
                exit(-1)

        except FileNotFoundError as err:
            self.stoq.log.critical(err)
            exit(-1)

        self.stoq.log.info("Install complete.")

    def setup_from_dir(self):
        # Find the stoQ configuration file
        config_file = glob.glob("{}/*/*.stoq".format(self.plugin))

        if len(config_file) > 1:
            self.stoq.log.critical("More than one stoQ configuration file found. Exiting.")
            exit(-1)

        if os.path.isfile(config_file[0]):
            # Open the stoQ configuration files and parse it
            with open(config_file[0], "rb") as config_content:
                self.parse_config(config_content.read())
        else:
            self.stoq.log.critical("Is this a valid configuration file? Exiting.")
            exit(-1)

        # Find the module name and set the plugin options
        module_root = os.path.join(self.plugin, self.plugin_name)
        module_path = os.path.join(module_root, self.plugin_module)
        with open(module_path, "rb") as module_content:
            self.set_plugin_category(module_content.read())

        self.set_plugin_path()

        self.save_plugin_info()

        return True

    def parse_config(self, stream):
        config = configparser.ConfigParser()
        config.read_string(stream.decode('utf-8'))
        try:
            self.plugin_name = config['Core']['Name']
            self.plugin_module = "{}.py".format(config['Core']['Module'])

            # We are going to use this to dynamically define data points in
            # setup.py
            self.plugin_info['NAME'] = self.plugin_name
            self.plugin_info['AUTHOR'] = config['Documentation']['Author']
            self.plugin_info['VERSION'] = config['Documentation']['Version']
            self.plugin_info['WEBSITE'] = config['Documentation']['Website']
            self.plugin_info['DESCRIPTION'] = config['Documentation']['Description']

        except Exception as err:
            self.stoq.log.critical("Is this a valid stoQ configuration file? {}".format(err))
            exit(-1)

    def save_plugin_info(self):
        # Let's create text files with the appropriate attributes so setup.py
        # can be more dynamic
        for option, value in self.plugin_info.items():
            with open(os.path.join(self.plugin, option), "w") as f:
                f.write(value)

    def set_plugin_category(self, plugin_stream):
        # We've extract the StoqPlugin class that is specific to our plugin
        # category, so now we can identity where the plugin will be
        # installed into
        try:
            plugin_type = re.search(r'(?<=from stoq\.plugins import )(.+)',
                                    plugin_stream.decode('utf-8')).group()
            self.plugin_category = self.stoq.__plugindict__[plugin_type]
        except Exception as err:
            self.stoq.log.critical("Unable to determine the category. Is this a valid plugin? {}".format(err))
            exit(-1)

    def set_plugin_path(self):
        if self.plugin_dir:
            install_path  = self.plugin_dir
        else:
            if len(self.stoq.plugin_dir_list) > 1:
                self.stoq.log.critical("Multiple plugin directories defined in stoq.cfg."
                                       "Unable to determine plugin installation directory."
                                       "Please explicitly define one using --plugin-dir")
                exit(-1)
            install_path = self.stoq.plugin_dir_list[0]

        self.plugin_root = os.path.join(install_path, self.plugin_category)

        self.stoq.log.info("Installing {} plugin into {}...".format(self.plugin_name, self.plugin_root))