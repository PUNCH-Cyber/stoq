==========
Dispatcher
==========

.. |stoQ| replace:: **stoQ**


Overview
========

|stoQ| provides for the ability to dispatch, or route, payloads to other 
plugins. This is done by leveraging *yara* to identify payloads that have
certain characteristics and then automatically routing to specific plugins
based on the results. Currently two plugin categories are supported for
use with dispatching, *extractor* and *carver*. 

Usage
=====

If dispatching is desired, simply start the worker with the ``-D`` command
line argument. Ensure that your *dispatcher.yar* file contains the appropriate
rules to properly route the payloads.

Writing a Dispatcher Rule
-------------------------

Dispatching relies on *yara* and a set of rules to appropriately route
payloads to their intended plugin. As with any yara rules, the ``strings``
and ``condition`` parameters are required, but dispatching also requires
the ``meta`` attribute. Two keys, ``plugin`` and ``save`` are required
within the ``meta`` attribute. The ``plugin`` key identifies the |stoQ| 
plugin category and plugin namei (e.g., ``plugin = "carver:rtf"``) that should
be loaded if the *yara* rule hits. The ``save`` key identifies whether
content that is extracted or carved from the payload should be saved. 
Additionally, all of the meta values are passed to the specified plugin
as **kwargs.

As an example, a |stoQ| dispatcher plugin that would identify RTF documents
and then send the document to the RTF carver plugin would be written as::

    rule rtf_file
    {
        meta:
            plugin = "carver:rtf"
            save = "True"
        strings:
            $rtf = "{\\rt" nocase
        condition:
            $rtf at 0
    }


Results from the specified plugin are returned as a ``list()`` of ``sets()``.
Each unique object, or ``payload``, that is extracted from the primary payload
is assigned an incremental ``payload`` and a unique ``uuid``. In addition, the
``puuid`` is added to the results to identify the parent uuid the stream was
extracted from. The results from the dispatcher are then appended to the
primary results ``dict()`` and the key ``payloads`` is added with the total
count of streams processed, to include the original payload.


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

