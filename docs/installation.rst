.. _install:

Installation
============

stoQ is extremely lightweight and strives for minimal dependencies. It can be
installed either via `pip` or directly from source. Once you have stoQ installed,
it's just a matter of installing the required plugins for your use case. stoQ has
over 40 publicly available plugins that can be found in their own repository
`here <https://github.com/PUNCH-Cyber/stoq-plugins-public>`_.


.. _minreq:

Minimum requirements
********************
stoQ requires a minimum of python 3.6 and is recommended to be run in a `python venv <https://docs.python.org/3/library/venv.html>`_.

.. _installsetup:

Initial Setup
-------------
Setup a \$STOQ_HOME (defaults to ~/.stoq) folder, the necessary plugin folder and a virtual environment::

    $ mkdir -p ~/.stoq/plugins
    $ python3 -m venv ~/.stoq/.venv
    $ source ~/.stoq/.venv/bin/activate


.. _installlateststable:

Stable
******

The simplest way to get started is to install stoQ from pip::

    $ pip3 install stoq-framework


.. _installlatestdev:

Development
***********

If you would rather use the latest development version, you can simply clone
the repository and install from there::

    $ git clone https://github.com/PUNCH-Cyber/stoq


Then, simply open the `stoq` directory and install::

    $ cd stoq
    $ python3 setup.py install


.. _installplugins:

Installing Plugins
******************

There are two ways of installing `stoQ` plugins. All core public plugins can be installed
via the command line directly from GitHub. Additionally, plugins can be installed from a
local directory.

.. _installplugingithub:

From GitHub
-----------

Once you have stoQ installed, you can start installing the `publicly available plugins <https://github.com/PUNCH-Cyber/stoq-plugins-public>`_.
For a full listing of plugins and a description of their functionality, you can
visit the stoQ public plugins repository `here <https://github.com/PUNCH-Cyber/stoq-plugins-public>`_.

In order to install plugins from the stoQ plugin repository, you can use the ``stoq`` command::

    $ stoq install --github stoq:PLUGIN_NAME


For this example, let's just install the `yara` and `stdout` plugins. First, let's
install the yara plugin::

    $ stoq install --github stoq:yara
    Successfully installed to ~/.stoq/plugins/yara


Now, let's install the stdout plugin::

    $ stoq install --github stoq:stdout
    Successfully installed to ~/.stoq/plugins/stdout


.. _installplugingitdir:

From directory
--------------

Plugins can also be installed from a local directory. This is useful if you have custom
or third party plugins. Additionally, plugins can be installed from a cloned version of
`stoQ's` public plugin repository::


    $ stoq install path/to/plugin


.. _upgradeplugins:

Upgrading plugins
-----------------

Plugins may be upgraded (or downgraded) by adding the `--upgrade` command line option to the install command::

    $ stoq install --upgrade --github stoq:stdout

.. warning::
    Upgrading plugins is a destructive operation. This will overwrite/remove all data within the plugins directory,
    to include the plugin configuration file. It is highly recommended that the plugin directory be backed up
    regularly to ensure important information is not lost, or plugin configuration options be defined in `stoq.cfg`.

.. _devenv:

Dev Environment
***************

Want to try stoQ out or setup a development environment? It's simple. Just clone the stoQ
repository then startup a virtual machine using `Vagrant`.

First, clone the repository::

    $ git clone https://github.com/PUNCH-Cyber/stoq

Then, simply go into the ``stoq`` directory and startup `Vagrant`::

    $ cd stoq
    $ vagrant up

.. note:: You'll need to ensure you have `Vagrant <https://www.vagrantup.com>`_ installed
          and setup.
