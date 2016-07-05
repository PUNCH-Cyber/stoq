##########
Installing
##########

.. |stoQ| replace:: **stoQ**


Installation Script
*******************

If using Ubuntu, Redhat 7, or CentOS, installation of the core framework and
plugins can be installed utilizing the installation script provided with the
framework.::

    git clone https://github.com/PUNCH-Cyber/stoq.git
    cd stoq/
    ./install.sh

.. note:: |stoQ| has not been tested on other operating systems, however,
          if the required packages are available it should work without issue.


Detailed Ubuntu Installation
****************************

Core Requirements
-----------------

Install the core requirements via apt-get and pip::

    apt-add-repository -y multiverse
    sudo apt-get install automake build-essential cython autoconf  \
                         python3 python3-dev python3-setuptools \
                         libyaml-dev libffi-dev libfuzzy-dev \
                         libxml2-dev libxslt1-dev libz-dev p7zip-full \
                         p7zip-rar unace-nonfree libssl-dev libmagic-dev
    sudo easy_install3 pip


It is recommended to install |stoQ| within a virtualenv. This is however
completely optional.  In order to setup the virtualenv, the following should be
completed::

    sudo pip3 install virtualenv
    virtualenv /usr/local/stoq/.stoq-pyenv
    source /usr/local/stoq/.stoq-pyenv/bin/activate

Install the latest version of yara from https://plusvic.github.io/yara/

Once the virtualenv has been activated and yara is installed, we can install
the core |stoQ| requirements::

    pip install yara-python
    python setup.py install
    pip install hydra

.. note:: Sometimes yara-python will fail to install on certain versions of Ubuntu
          when being install from the setup.py script. Because of this, we will
          install yara-python manually first.

.. note:: hydra requires Cython to be installed, so we will install it separately.
          Thanks to the way setuptools handles ordering of packages, this is
          required.

Make a directory to store all of |stoQ| and then copy the required files::

    mkdir /usr/local/stoq
    cp -R stoq/* /usr/local/stoq/
    chmod +x /usr/local/stoq/stoq-cli.py

|stoQ| does not require any special permissions to run. For security reasons,
it is recommended that |stoQ| is run as a non-privileged user. To create a
|stoQ| user, run::

     sudo groupadd -r stoq
     sudo useradd -r -c stoQ -g stoq -d /usr/local/stoq stoq
     chown -R stoq:stoq /usr/local/stoq

The core framework for |stoQ| should now be installed. We can use |stoQ|'s plugin
installation feature to handle this. First, we will need to clone |stoQ|'s public
plugin repository::

    git clone https://github.com/PUNCH-Cyber/stoq-plugins-public.git /tmp/stoq-plugins-public

Now, we can install the basic plugins that are commonly used within |stoQ|::

    cd /usr/local/stoq
    stoq-cli.py install /tmp/stoq-plugins-public/connector/file
    stoq-cli.py install /tmp/stoq-plugins-public/connector/stdout
    stoq-cli.py install /tmp/stoq-plugins-public/connector/mongodb
    stoq-cli.py install /tmp/stoq-plugins-public/connector/elasticsearch
    stoq-cli.py install /tmp/stoq-plugins-public/connector/emailer
    stoq-cli.py install /tmp/stoq-plugins-public/connector/queue
    stoq-cli.py install /tmp/stoq-plugins-public/decoder/b64
    stoq-cli.py install /tmp/stoq-plugins-public/decoder/b85
    stoq-cli.py install /tmp/stoq-plugins-public/decoder/bitrot
    stoq-cli.py install /tmp/stoq-plugins-public/decoder/rot47
    stoq-cli.py install /tmp/stoq-plugins-public/decoder/xor
    stoq-cli.py install /tmp/stoq-plugins-public/extractor/gpg
    stoq-cli.py install /tmp/stoq-plugins-public/extractor/decompress
    stoq-cli.py install /tmp/stoq-plugins-public/carver/ole
    stoq-cli.py install /tmp/stoq-plugins-public/carver/rtf
    stoq-cli.py install /tmp/stoq-plugins-public/carver/pe
    stoq-cli.py install /tmp/stoq-plugins-public/carver/swf
    stoq-cli.py install /tmp/stoq-plugins-public/carver/xdp
    stoq-cli.py install /tmp/stoq-plugins-public/source/dirmon
    stoq-cli.py install /tmp/stoq-plugins-public/source/filedir
    stoq-cli.py install /tmp/stoq-plugins-public/reader/iocregex
    stoq-cli.py install /tmp/stoq-plugins-public/reader/pdftext
    stoq-cli.py install /tmp/stoq-plugins-public/reader/tika
    stoq-cli.py install /tmp/stoq-plugins-public/worker/publisher
    stoq-cli.py install /tmp/stoq-plugins-public/worker/yara
    stoq-cli.py install /tmp/stoq-plugins-public/worker/iocextract
    stoq-cli.py install /tmp/stoq-plugins-public/worker/peinfo
    stoq-cli.py install /tmp/stoq-plugins-public/worker/xorsearch
    stoq-cli.py install /tmp/stoq-plugins-public/worker/exif
    stoq-cli.py install /tmp/stoq-plugins-public/worker/clamav
    stoq-cli.py install /tmp/stoq-plugins-public/worker/vtmis
    stoq-cli.py install /tmp/stoq-plugins-public/worker/censys
    stoq-cli.py install /tmp/stoq-plugins-public/worker/threatcrowd
    stoq-cli.py install /tmp/stoq-plugins-public/worker/passivetotal
    stoq-cli.py install /tmp/stoq-plugins-public/worker/totalhash


.. note:: - *xorsearch* requires XORsearch to be installed
                        http://blog.didierstevens.com/programs/xorsearch/

          - *exif* requires ExifTool to be installed
                   http://www.sno.phy.queensu.ca/~phil/exiftool/

          - *tika* requires that Apache Tika be installed
                   https://tika.apache.org/download.html

          - *clamav* requires that a ClamAV daemon be installed
                     http://www.clamav.net/


Additional Plugins
------------------

There are several other plugins that are available in the *stoQ* public
plugin repository at https://github.com/PUNCH-Cyber/stoq-plugins-public


Supervisord
***********

|stoQ| can easily be added to supervisord for running as a system service in
daemon mode. In our example, let's say that we want to use the yara and exif
plugins to monitor RabbitMQ and save any results into MongoDB. We've installed
|stoQ| into /usr/local/stoq and our python virtual environment is in
```/usr/local/stoq/env```. First, let's install the supervisor Ubuntu package::

    sudo apt-get install supervisor

Now, let's create a new file in ```/etc/supervisor/conf.d``` named ```stoq.conf```


Additional Plugins
------------------

There are several other plugins that are available in the *stoQ* public
plugin repository at https://github.com/PUNCH-Cyber/stoq-plugins-public


Supervisord
***********

|stoQ| can easily be added to supervisord for running as a system service in
daemon mode. In our example, let's say that we want to use the yara and exif
plugins to monitor RabbitMQ and save any results into MongoDB. We've installed
|stoQ| into /usr/local/stoq and our python virtual environment is in
```/usr/local/stoq/env```. First, let's install the supervisor Ubuntu package::

    sudo apt-get install supervisor

Now, let's create a new file in ```/etc/supervisor/conf.d``` named ```stoq.conf```
with the below content::

    [program:exif]
    command=/usr/local/stoq/.stoq-pyenv/bin/python stoq-cli.py %(program_name)s -I rabbitmq -C mongodb
    process_name=%(program_name)s_%(process_num)02d
    directory=/usr/local/stoq
    autostart=true
    autorestart=true
    startretries=3
    numprocs=1
    user=stoq

    [program:yara]
    command=/usr/local/stoq/.stoq-pyenv/bin/python stoq-cli.py %(program_name)s -I rabbitmq -C mongodb
    process_name=%(program_name)s_%(process_num)02d
    directory=/usr/local/stoq
    autostart=true
    autorestart=true
    startretries=3
    numprocs=1
    user=stoq

Then, simply restart supervisord::

    supervisorctl reload

You should now have two |stoQ| workers running, monitoring their RabbitMQ queue,
and saving their results into your MongoDB instance.

Vagrant
*******

If testing |stoQ| is something you are interested in doing, you can use Vagrant
to setup a simple instance.

First, install Vagrant from https://www.vagrantup.com/downloads, then, install
VirtualBox from https://www.virtualbox.org/wiki/Downloads.

Once the prerequisits are installed, download the Ubuntu box::

    vagrant box add ubuntu/trusty64

Next, create a new directory named ```stoq``` and save the Vagrantfile in it::

    wget -O Vagrantfile https://raw.githubusercontent.com/PUNCH-Cyber/stoq/master/Vagrantfile

Now, let's bring up the Vagrant box::

    vagrant up

Log into the new box::

    vagrant ssh

Switch to the ``stoq`` user::

    sudo su - stoq

Your newly installed |stoQ| instance is now available in ``/usr/local/stoq``.

All done!
