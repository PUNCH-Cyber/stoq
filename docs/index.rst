.. stoQ documentation master file, created by
   sphinx-quickstart on Wed Dec 31 15:15:53 2014.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

===========================
stoQ: Analysis. Simplified.
===========================

.. |stoQ| replace:: **stoQ**


Quick Links

.. toctree::
   :maxdepth: 1

   Installation
   PluginDevelopment
   Dispatcher
   Stoq
   Args
   Plugins
   Scan
   Filters
   Shell


Overview
========

|stoQ| is a automation framework that helps to simplify the more mundane and
repetitive tasks an analyst is required to do. It allows analysts and DevSecOps
teams the ability to quickly transition from different data sources, databases,
decoders/encoders, and numerous other tasks. stoQ was designed to be enterprise
ready and scalable, while also being lean enough for individual security researchers.


Usage
=====

|stoQ| can be run in several modes to include interactive shell, single file,
entire directories, monitoring directories for new files, and queue mode.
Let's go over some of the simplest ways of using |stoQ|.

Basic Usage via Interactive Shell
---------------------------------

|stoQ| provides a simply interactive shell interface. This interface is
designed to allow a user to interact with |stoQ| and |stoQ| plugins on
a much more granular level than via the command line.

To enter the interactive shell, simply run |stoQ| with the ``shell``
argument.::

    bash$ ./stoq-cli.py shell

        _______ _________ _______  _______
        (  ____ \__   __/(  ___  )(  ___  )
        | (    \/   ) (   | (   ) || (   ) |
        | (_____    | |   | |   | || |   | |
        (_____  )   | |   | |   | || |   | |
              ) |   | |   | |   | || | /\| |
        /\____) |   | |   | (___) || (_\ \ |
        \_______)   )_(   (_______)(____\/_)

                Analysis. Simplified.
                      v0.9.7

    [stoQ] >

Once in the interactive shell, you can run the ``help`` command for a
complete listing of available commands. Please view the :doc:`Shell` documentation
for a more exhaustive list of directions.

Basic Usage via Command Line
----------------------------

In order to use |stoQ| via the command line, at least two options must be
defined. The worker plugin that should be loaded, and the source of input.
In order to see a basic usage help, simply execute ``stoq-cli.py``::

    bash$ stoq-cli.py

        .------..------..------..------.
        |S.--. ||T.--. ||O.--. ||Q.--. |
        | :/\: || :/\: || :/\: || (\/) |
        | :\/: || (__) || :\/: || :\/: |
        | '--'S|| '--'T|| '--'O|| '--'Q|
        `------'`------'`------'`------'
              Analysis. Simplified.
                    v0.9.7

    usage:
        stoq-cli.py [command] [<args>]

        Available Commands:
            help    Display help message
            shell   Launch an interactive shell
            list    List plugins available
            worker  Load specified worker plugin
            install Install a stoQ plugin



To view a complete listing of available plugins simply call ``stoq-cli.py`` with the
``list`` command line argument::


    bash$ stoq-cli.py list

        _______ _______  _____   _____
        |______    |    |     | |   __|
        ______|    |    |_____| |____\|

             Analysis. Simplified.
                   v0.9.7

    Available Plugins:
     connectors
        - s3                  v0.1    Sends and retrieves content from Amazon S3 buckets
        - queue               v0.1    Send results to a queuing system, such as RabbitMQ
        - mongodb             v0.9    Sends and retrieves content from MongoDB
        - emailer             v0.1    Send results to recipients via e-mail
        - elasticsearch       v0.2    Saves content to an ElasticSearch index
        - stdout              v0.9    Sends content to STDOUT
        - file                v0.9    Retrieves and saves content to local disk
        - fluentd             v0.1    Sends content to a fluentd server
     sources
        - rabbitmq            v0.9    Publish and Consume messages from a RabbitMQ Server
        - dirmon              v0.9    Monitor a directory for newly created files for processing
        - filedir             v0.9    Ingest a file or directory for processing
     carvers
        - pe                  v0.9    Carve portable executable files from a data stream
        - swf                 v0.9    Carve and decompress SWF payloads
        - ole                 v0.9    Carve OLE streams within Microsoft Office Documents
        - xdp                 v0.9    Carve and decode streams from XDP documents
        - rtf                 v0.9    Carve hex/binary streams from RTF payloads
     workers
        - basicworker         v0.1    StoQ framework example of a basic worker plugin
        - peinfo              v0.9    Gather relevant information about an executable using pefile
        - passivetotal        v0.5    Query PassiveTotal API for a domain or IP address
        - threatcrowd         v0.1    Interact with ThreatCrowd API
        - opswat              v0.9    Submit content to an OPSWAT Metascan server for scanning and retrieve the results
        - exif                v0.9    Processes a payload using ExifTool
        - publisher           v0.9    Publish messages to single or multiple RabbitMQ queues for processing
        - trid                v0.4    Identify file types from their TrID signature
        - totalhash           v0.7    Query TotalHash API for analysis results
        - xorsearch           v0.9    Search a payload for XOR'd strings
        - clamav              v0.1    Scan content with ClamAV
        - yara                v0.9    Process a payload using yara
        - censys              v0.2    Interact with Censys.io API
        - iocextract          v0.9    Utilizes reader/iocregex plugin to extract indicators of compromise from documents
        - vtmis               v0.9    Interact with VTMIS public and private API
        - slack               v0.9    Interact with StoQ Plugins using Slack as an interface
        - fireeye             v0.1    Saves a file into a directory fireeye monitors via CIFS for analysis
     readers
        - pdftext             v0.9    Extract text from a PDF document
        - tika                v0.1    Upload content to a Tika server for automated text extraction
        - iocregex            v0.9    Regex routines to extract and normalize IOC's from a payload
     extractors
        - decompress          v0.9    Extract content from a multitude of archive formats
        - gpg                 v0.1    Handle GnuPG encrypted content
     decoders
        - rot47               v0.1    Decode ROT47 encoded content
        - bitrot              v0.1    Rotate bits left or right. Defaults to 4 bits right for nibble swapping.
        - b64                 v0.1    Decode base64 encoded content
        - b85                 v0.1    Decode base85 encoded content
        - xor                 v0.1    Decode XOR encoded content


Now that we have a complete listing of available worker and connector plugins,
we can begin processing data. Let's say that we have a file named *bad.exe* that we want to
process with the *yara* worker plugin. We also want the results to be displayed to our console.
We can simply run |stoQ| with the following command line arguments::


    bash$ stoq-cli.py yara -F bad.exe
    {
    "date" : "2015-10-29T15:22:55.824563",
    "payloads" : 1,
    "results" : [ {
            "md5" : "0ace1c67d408986ca60cd52272dc8d35",
            "payload_id" : 0,
            "plugin" : "yara",
            "scan" : [ { "matches" : true,
                         "meta" : {
                                 "author" : "PUNCH Cyber Analytics Group",
                                 "cve" : "N/A",
                                 "description" : "Badness",
                                 "type" : "Suspicious String",
                                 "version" : "1.0",
                                 "weight" : 100
                                 },
                         "namespace" : "default",
                         "rule" : "win_api_LoadLibrary",
                         "strings" : [
                                 [
                                     "23967",
                                     "$LoadLibrary",
                                     "b'LoadLibrary'"
                                 ],
                             ],
                         "tags" : [  ]
                       }
                    ],
            "sha1" : "5a04547c1c56064855c3c6426448d67ccc1e0829",
            "sha256" : "458f1bb61b7ef167467228141ad44295f3425fbeb6303e9d31607097d6869932",
            "sha512" : "c5dbd244d186546846c25a393edeafdd6604e2a2e04e021a21d0524f7b02d3ecb85c12dba252a11a3bb01c20fb736ca6153e055eef2cf1bc2f15fea667f2fce4",
            "size" : 55208,
            "uuid" : ["da8215ed-89ca-43db-8c96-a8b8231f6a5e"]
        } ]
    }


We can easily change the method the results are handled by modifying the ``-C``
flag. Simply replace ``stdout`` with another plugin name, such as ``file`` or
``mongodb``. The default *connector* plugin may also be changed by changing
the ``output_connector`` option in *stoq.cfg*.

Additionally, output can be customized using |stoQ|'s templating engine.


Using the queues
----------------

Queues enable |stoQ| to process payloads in a ditributed and scalable manner.
In this use case, we will utilize the *publisher* worker plugin with RabbitMQ.
The *publisher* worker plugin's primary purpose is to handle files to be ingested,
and then notify the other worker plugins that there is a file that is ready to
be processed. By default, the *publisher* worker plugin will notify each of the
worker plugins that are defined in *publisher.stoq*. This can be easily
modified at run time by defining one or many ``-w`` command line arguments for
the *publisher*. For now, we will assume that the default worker queues
(*yara, exif, peinfo, trid*) are sufficient.

Let's assume that we have a directory in our current working directory named
*malicious*. We want to monitor this directory, using the dirmon source plugin,
for any new files that are created, archive them to MongoDB, and then process
them with our default workers listed above::

    bash$ stoq-cli.py publisher -I dirmon -F malicious -A mongodb

Once a file is placed into this directory, the newly created file will be
ingested, saved into our MongoDB instance, and a message will be sent to the
appropriate queues for processing.

Now, we need to make sure our worker plugins are running so they can processes
their newly identified file. In this scenario, since we are saving the file
itself into MongoDB, we will also save our worker plugin results into MongoDB::

    bash$ stoq-cli.py yara -I rabbitmq -C mongodb &
    bash$ stoq-cli.py exif -I rabbitmq -C mongodb &
    bash$ stoq-cli.py peinfo -I rabbitmq -C mongodb &
    bash$ stoq-cli.py trid -I rabbitmq -C mongodb &


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
