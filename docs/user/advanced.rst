.. _advanceduse:

Advanced Usage
==============

`stoQ` is an extremely flexible framework. In this section we will go over some of the most advanced uses and show examples of how it can be used as a framework.

.. _framework:

Framework
---------

stoQ is much more than simply a command to be run. First and foremost, stoQ is a framework. The command `stoq` is simply a means of interacting with the framework. For more detailed and robust information on APIs available for stoQ, please check out the :ref:`API documentation <api>`.

For these examples, it is assumed the below :ref:`plugins have been installed <installplugins>`:
    - filedir
    - yara


Instantiating stoQ
^^^^^^^^^^^^^^^^^^

Let's start by simply instantiating ``Stoq`` with no options. There are several arguments available when instantiating ``Stoq``, please refer to the :ref:`API documentation <api>` for more information and options available.

::

    from stoq import Stoq
    s = Stoq()


Loading plugins
^^^^^^^^^^^^^^^

`stoQ` plugins can be loaded using a simple helper function. The framework will automatically detect the type of plugin is it based on the ``class`` of the plugin. There is no need to define the plugin type, `stoQ` will handle that once it is loaded.

::

    s.load_plugin('yara')


Instantiate Payload Object
^^^^^^^^^^^^^^^^^^^^^^^^^^

In order to scan a payload, a ``Payload`` object must first be instantiated. The ``Payload`` object houses all information related to a payload, to include the content of the payload and metadata (i.e., size, originating plugin information, dispatch metadata, among others) pertaining to the payload. Optionally, a ``Payload`` object can be instantiated with a ``PayloadMeta`` object to ensure the originating metadata (i.e., filename, source path, etc...) is also made available::

    import os
    from stoq.data_classes import PayloadMeta, Payload
    filename = '/tmp/test_file.exe'
    with open(filename, 'rb') as src:
        meta = PayloadMeta(
            extra_data={
                'filename': os.path.basename(filename),
                'source_dir': os.path.dirname(filename),
            }
        )
        payload = Payload(src.read(), meta)


Scan payload
^^^^^^^^^^^^
There are two helper functions available for scanning a payload. If a dispatcher plugin is not being used, then a worker plugin must be defined by passing the ``add_start_dispatch`` argument. This tells `stoQ` to send the ``Payload`` object to the specified worker plugins.


From raw bytes
""""""""""""""

If a `Payload` object has not been created yet, the content of the raw payload can simply be passed to the `Stoq.scan` function. A ``Payload`` object will automatically be created.::

    start_dispatch = ['yara']
    results = s.scan('raw bytes', add_start_dispatch=start_dispatch)


From ``Payload`` object
"""""""""""""""""""""""

If a ``Payload`` object has already been instatiated, as detailed above, the ``scan_payload`` function may be called::

    start_dispatch = ['yara']
    results = s.scan_payload(payload, add_start_dispatch=start_dispatch)


Save Results
^^^^^^^^^^^^

Finally, results may be saved using the desired ``Connector`` plugin. `stoQ` stores results from the framework as a ``StoqResponse`` object. The results will be saved to all connector plugins that have been loaded. In this example, we will only load the ``filedir`` plugin which will save the results to a specified directory.::

    s.load_plugin('filedir')
    s.save(results)


.. _multiplugindir:

Multiple Plugin directories
---------------------------

When instantiating ``Stoq``, multiple plugins directories may be defined. For more information on default paths, please refer to the :ref:`getting started documentation <stoqhome>`::

    from stoq import Stoq
    plugins_directories = ['/usr/local/stoq/plugins', '/home/.stoq/plugins']
    s = Stoq(plugin_dir_list=plugins_directories)