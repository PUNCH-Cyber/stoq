.. _packaging:

Packaging Plugins
=================

`stoQ` has a built-in plugin installation and upgrade capability. `stoQ` plugins may
be packaged to allow for a simple and consistent installation process. Though packaging
plugins isn't a necessity, it is highly recommended to do so for simplicity and reproducibility.

Let's take a look at a basic directory structure for a `stoQ` plugin::

    |-- example_plugin/
    |   `-- setup.py
    |   `-- MANIFEST.in
    |   `-- requirements.txt
    |   `-- example_plugin/
    |       `-- __init__.py
    |       `-- example_plugin.py
    |       `-- example_plugin.stoq


`stoQ` plugin packages leverage python's packaging library, setuptools. When a plugin is installed,
``pip`` is used for package management and installation. As such, all rules for both apply for `stoQ`
plugins.

.. _packagesetup:

setup.py
^^^^^^^^

The setup.py file is a standard ``setuptools`` script. ``include_package_data`` should always be set to
``True`` to ensure the plugin configuration file and any additional files are properly installed.

::

    from setuptools import setup, find_packages
    setup(
        name="example_plugin",
        version="3.0.0",
        author="Marcus LaFerrera (@mlaferrera)",
        url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
        license="Apache License 2.0",
        description="Example stoQ plugin",
        packages=find_packages(),
        include_package_data=True,
    )


.. _packagemanifest:

MANIFEST.in
^^^^^^^^^^^

The manifest file ensure that the plugins ``.stoq`` configuration file, and any other required
files, are installed alongside the plugin. More information on the ``.stoq`` configuration file
:ref:`can be found here <pluginconfig>`.

::

    include example_plugin/*.stoq


.. _packagerequirements:

requirements.txt
^^^^^^^^^^^^^^^^

If a requirements file exists, `stoQ` will install dependencies appropriately. They will not be installed
along side the plugin, but rather in python's system path. This file is not required if no additional
dependencies need to be installed.


.. _packageplugindir:

plugin subdirectory
^^^^^^^^^^^^^^^^^^^

The subdirectory above, ``example_plugin``, is the primary plugin directory. This is the core location
for the `stoQ` plugin that will be installed into the `stoQ` plugin directory. The plugin module, along with
files identified in :ref:`MANIFEST.in <packagemanifest>` will be copied.

More information on writing a plugin :ref:`can be found here <pluginoverview>`.

Examples
^^^^^^^^

There are plenty of examples for packaging plugin in `stoQ's` `public plugin repository <https://github.com/PUNCH-Cyber/stoq-plugins-public>`_.
