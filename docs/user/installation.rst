Installation
============

stoQ is extremly lightweight and strives for minimal dependecies. It can be installed either via `pip` or directly from source. Once you have stoQ installed, it's just a matter of installing the required plugins for your use case. stoQ has over 40 publicly available plugins that can be found in their own repository `here <https://github.com/PUNCH-Cyber/stoq-plugins-public>`_.


Minimum requirements
********************
stoQ requires at a minimum Python v3.6.


Latest stable release
*********************

The simplest way to get started is to install stoQ from pip::

    $ pip install stoq-framework


Latest development release
**************************

If you would rather use the latest development version, you can simply clone the repository and install from there::

    $ git clone https://github.com/PUNCH-Cyber/stoq


Then, simply open the `stoq` directory and install::

    $ cd stoq
    $ python3 setup.py install


Installing core plugins from GitHub
***********************************

Once you have stoQ installed, you can start installing the `publicly available plugins <https://github.com/PUNCH-Cyber/stoq-plugins-public>`_. For a full listing of plugins and a description of their functionality, you can visit the stoQ public plugins repository `here <https://github.com/PUNCH-Cyber/stoq-plugins-public>`_.

In order to install plugins from the stoQ plugin repository, you can use the ``stoq`` command::

    $ stoq install --github stoq:PLUGIN_NAME


For this example, let's just install the `yara` and `stdout` plugins. First, let's install the yara plugin::

    $ stoq install --github stoq:yara
    Successfully installed to ~/.stoq/plugins/yara


Now, let's install the stdout plugin::

    $ stoq install --github stoq:stdout
    Successfully installed to ~/.stoq/plugins/stdout


Installing plugins from directory
*********************************

Plugins can also be installed from a local directory. This is useful if you have custom or third party plugins. Additionally, plugins can be install from a cloned version of stoQ's public plugin repository::


    $ stoq install path/to/plugin


Development Environment
***********************

Want to try stoQ out or setup a development environment? It's simple. Just clone the stoQ repository then startup a virtual machine using `Vagrant`.

First, clone the repository::

    $ git clone https://github.com/PUNCH-Cyber/stoq

Then, simply go into the ``stoq`` directory and startup `Vagrant`::

    $ cd stoq
    $ vagrant up

.. note:: You'll need to ensure you have `Vagrant <https://www.vagrantup.com>`_ installed and setup.