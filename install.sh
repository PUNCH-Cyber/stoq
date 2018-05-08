#!/usr/bin/env bash
#   Copyright 2014-2017 PUNCH Cyber Analytics Group
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
###
#
# stoQ installation script.
# Supports: Ubuntu, Redhat 7, and CentOS
#
###

# Die if anything in this script fails to execute
set -e

PREFIX=/usr/local
BIN_DIR=$PREFIX/bin
STAGE_DIR=$PWD
TMP_DIR=$STAGE_DIR/tmp
PLUGIN_DIR=$STAGE_DIR/stoq-plugins-public
STOQ_HOME=$PREFIX/stoq
PYENV_DIR=$STOQ_HOME/.stoq-pyenv
STOQ_USER=stoq
STOQ_GROUP=stoq

# Dependency versions
YARA_VERSION=3.7.1
XORSEARCH_VERSION=1_11_1
EXIF_VERSION=10.94
FLOSS_VERSION=1.5.0

# Make sure all output, to include STDERR is logged appropriately
exec > >(tee -a $STAGE_DIR/stoq-install.log)
exec 2> >(tee -a $STAGE_DIR/stoq-install-errors.log)

# debian and red hat based operating systems supported
if [ -f /etc/debian_version ]; then
    OS=Debian
elif [ -f /etc/redhat-release ]; then
    VERSION=$(rpm -q --qf "%{VERSION}" $(rpm -q --whatprovides redhat-release))
    if [[ ! $VERSION =~ ^7 ]]; then
        echo "ERROR: This installation only supports Red Hat 7 based operating systems." 1>&2
        exit 1
    fi
    OS=RedHat
else
    echo "ERROR: This installation should only be used on debian or red hat based operating systems. Exiting!" 1>&2
    exit 1
fi

# pre-reqs
install_prereqs() {
    echo "[stoQ] Installing prerequisites..."

    if [ "$OS" == "Debian" ]; then
        set +e
        apt-add-repository -y multiverse
        set -e
        # Some older versions of ubuntu do not have this installed. Catch the
        # error and install it.
        if [ $? -ne 0 ]; then
            apt-get -yq install software-properties-common
            apt-add-repository -y multiverse
        fi

        apt-get -yq update
        apt-get -yq install git-core curl wget unzip p7zip-full unace-nonfree p7zip-rar automake \
                            build-essential cython autoconf python3 python3-dev python3-setuptools \
                            libyaml-dev libffi-dev libfuzzy-dev libxml2-dev libxslt1-dev libz-dev \
                            libssl-dev libmagic-dev

        easy_install3 pip

    elif [ "$OS" == "RedHat" ]; then
        rpm -q epel-release
        if [ $? -ne 0 ]; then
            # In CentOS, EPEL is included in the extras repository.
            # Extras should be enabled my default.
            yum install --enablerepo=Extras epel-release
            if [ $? -ne 0 ]; then
                # If epel-release cannot be installed via yum
                # install it manually via rpm
                # XXX: Does this work on CentOS and RH both?
                yum -y -q install wget
                wget https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
                rpm -ivh epel-release-latest-7.noarch.rpm
            fi
        fi

        # XXX: p7zip-rar unace-nonfree does not appear available via RPM
        yum -y -q group install 'Development Tools'
        yum -y -q --enablerepo=*optional install file-devel
        yum -y -q install git wget unzip p7zip Cython python34 python34-devel python34-setuptools \
                          libyaml-devel libffi-devel libxml2-devel libxslt-devel openssl-devel file-devel \
                          ssdeep-devel zlib-devel

        easy_install-3.4 pip

    fi

    pip3 install virtualenv --quiet
    echo "[stoQ] Done installing prerequisites."
}

build_dirs() {
    if [ ! -d $TMP_DIR ]; then
        echo "[stoQ] Creating installer temporary directory ($TMP_DIR)"
        mkdir -p $TMP_DIR
    fi

    if [ ! -d $STOQ_HOME ]; then
        echo "[stoQ] Creating stoQ directory ($STOQ_HOME)"
        mkdir -p $STOQ_HOME
    fi

    if [ ! -d $STOQ_HOME/temp ]; then
        echo "[stoQ] Creating stoQ tmp directory ($STOQ_HOME/temp)"
        mkdir -p $STOQ_HOME
    fi
}

# Core build
install_core() {
    echo "[stoQ] Installing core components..."

    # Make sure directories are built
    build_dirs

    echo "[stoQ] Setting up virtualenv..."
    virtualenv $PYENV_DIR
    source $PYENV_DIR/bin/activate
    echo "[stoQ] virtualenv activated..."

    set +e
    groupadd -r $STOQ_GROUP
    useradd -r -c stoQ -g $STOQ_GROUP -d $STOQ_HOME -s /bin/bash $STOQ_USER
    set -e

    # Sometimes yara-python fails to install on Ubuntu 16.04 LTS boxes. Why?
    # Because setuptools is the worst thing about python.
    set +e
    python3 -c "import yara"
    set -e
    if [ $? -ne 0 ]; then
        # Make sure we run ldconfig, otherwise libyara.so.3 won't be found on new installs
        ldconfig
        pip3 install --global-option="build" --global-option="--dynamic-linking" yara-python
    fi

    cd $STAGE_DIR

    python3 setup.py install

    if [ ! -d $PLUGIN_DIR ]; then
        git clone https://github.com/PUNCH-Cyber/stoq-plugins-public.git
    fi

    # Make sure we setup stoQ in the proper directory
    for f in `ls extras`; do
        cp extras/$f $STOQ_HOME/
    done

    cd $STOQ_HOME

    # Install all of the plugins
    for category in connector decoder extractor carver source reader worker;
    do
        for plugin in `ls $PLUGIN_DIR/$category`;
        do
            stoq install $PLUGIN_DIR/$category/$plugin
        done
    done

    echo "[stoQ] Done installing core components."
}

# Tika
install_tika() {
    # Make sure directories are built
    build_dirs

    echo "[stoQ] Installing tika..."

    TIKA_URL=$(curl https://tika.apache.org/download.html | sed -n 's/.*href="\(.*server.*\.jar\)">.*/\1/ip;T;q')
    TIKA_DOWNLOAD=$(curl -s $TIKA_URL | sed -n 's/.*<strong>\(.*\)<\/strong>.*/\1/ip;T;q')
    TIKA_VERSION=$(echo $TIKA_URL | awk 'BEGIN{FS="server-|.jar"} {print $2}')
    TIKA_INSTALL_DIR=$PREFIX/tika

    if [ "$OS" == "Debian" ]; then
        apt-get -yq install default-jdk
    elif [ "$OS" == "RedHat" ]; then
        yum -y -q install java-1.7.0-openjdk
    fi

    cd $TMP_DIR

    wget $TIKA_DOWNLOAD
    wget https://people.apache.org/keys/group/tika.asc
    wget http://www.apache.org/dist/tika/tika-server-$TIKA_VERSION.jar.asc

    gpg --import tika.asc
    gpg --verify tika-server-$TIKA_VERSION.jar.asc
    if [ ! -d $TIKA_INSTALL_DIR ]; then
        mkdir -p $TIKA_INSTALL_DIR
    fi
    mv tika-server-$TIKA_VERSION.jar $TIKA_INSTALL_DIR/
    java -jar $TIKA_INSTALL_DIR/tika-server-$TIKA_VERSION.jar --host=localhost --port=9998 &
    echo "[stoQ] Done installing tika."
}

# Yara worker
install_yara() {
    # Make sure directories are built
    build_dirs

    echo "[stoQ] Installing yara..."

    if [ -f "`which yara`" ]; then
        echo "[stoQ] yara v`yara -v` already installed..skipping"
        return
    fi

    if [ "$OS" == "Debian" ]; then
        apt-get -yq install bison flex libtool libjansson-dev
        WITH_CUCKOO="--enable-cuckoo"
    elif [ "$OS" == "RedHat" ]; then
        yum -y -q install bison flex libtool
        WITH_CUCKOO=""
    fi

    cd $TMP_DIR
    if [ -d $TMP_DIR/yara ]; then
        rm -rf $TMP_DIR/yara
    fi

    wget https://github.com/VirusTotal/yara/archive/v$YARA_VERSION.tar.gz
    tar zxvf v$YARA_VERSION.tar.gz
    cd yara-$YARA_VERSION

    set +e
    ./bootstrap.sh
    # Sometimes bootstrap will fail the first time, but work the 2nd time.
    # Temp fix until the yara repo fixes the issue
    if [ $? -ne 0 ]; then
        set -e
        ./bootstrap.sh
    fi
    set -e

    ./configure --with-crypto --enable-magic $WITH_CUCKOO
    make
    make install

    echo "[stoQ] Done installing yara."
}

# XOR worker
install_xor() {
    # Make sure directories are built
    build_dirs

    echo "[stoQ] Installing xorsearch..."
    cd $TMP_DIR
    wget -O XORSearch.zip "https://didierstevens.com/files/software/XORSearch_V$XORSEARCH_VERSION.zip"
    unzip -qq XORSearch -d XORSearch
    gcc -o $BIN_DIR/xorsearch XORSearch/XORSearch.c
    rm -r XORSearch.zip
    echo "[stoQ] Done installing xorsearch."
}

# TrID worker
install_trid() {
    # Make sure directories are built
    build_dirs

    echo "[stoQ] Installing trid"
    cd $TMP_DIR
    # Download and install TRiD
    wget -O trid_linux_64.zip "http://mark0.net/download/trid_linux_64.zip"
    unzip -qq trid_linux_64 -d $BIN_DIR
    chmod +x $BIN_DIR/trid
    rm -r trid_linux_64.zip
    # Download and install the definitions
    cd $TMP_DIR
    wget -O triddefs.zip "http://mark0.net/download/triddefs.zip"
    unzip -qq triddefs -d $STOQ_HOME/plugins/worker/trid
    rm -r triddefs.zip
    echo "[stoQ] Done installing trid"
}

# exif worker
install_exif() {
    # Make sure directories are built
    build_dirs

    echo "[stoQ] Installing exiftool..."
    # The default debian exiftool does not work properly. Let's just
    # directly from the source.
    # apt-get install -yq libimage-exiftool-perl
    # XXX: Do we need to make sure this is installed on ubuntu?
    if [ "$OS" == "RedHat" ]; then
        yum -y -q install perl-ExtUtils-MakeMaker
    fi
    cd $TMP_DIR
    wget -O exif.tgz "http://www.sno.phy.queensu.ca/~phil/exiftool/Image-ExifTool-$EXIF_VERSION.tar.gz"
    tar -xvf exif.tgz
    rm exif.tgz
    cd Image-ExifTool-$EXIF_VERSION
    perl Makefile.PL
    make
    make test
    make install
    echo "[stoQ] Done installing exiftool."
}

# clamav worker
install_clamav() {
    echo "[stoQ] Installing clamav"
    # XXX: Should check to see if clam is already installed
    if [ "$OS" == "Debian" ]; then
        apt-get install -yq clamav clamav-daemon
        echo "[!] This takes really long, running in the background..."
        freshclam && service clamav-daemon start &
    elif [ "$OS" == "RedHat" ]; then
        yum -y -q install clamav clamav-scanner clamav-scanner-systemd clamav-update
        sed -i -r -e 's/^Example$/#Example/' -e 's/^#(LocalSocket .*)$/\1/' /etc/clamd.d/scan.conf
        sed -i -r -e 's/^Example$/#Example/' /etc/freshclam.conf
        # XXX: Do we enable it? Is it done automatically on ubuntu?
        systemctl enable clamd@scan
        echo "[!] This takes really long, running in the background..."
        freshclam && systemctl start clamd@scan &
    fi

    echo "[stoQ] Done installing clamav."
}

# floss worker
install_floss() {
    # Make sure directories are built
    build_dirs

    echo "[stoQ] Installing floss..."
    cd $TMP_DIR
    wget -O floss.zip https://github.com/fireeye/flare-floss/releases/download/v$FLOSS_VERSION/floss-$FLOSS_VERSION-GNU.Linux.zip
    unzip floss.zip
    mv floss $STOQ_HOME/plugins/worker/floss/
    chmod +x $STOQ_HOME/plugins/worker/floss/floss
    echo "[stoQ] Done installing floss."
}

# RabbitMQ worker
install_rabbitmq() {
    echo "[stoQ] Installing RabbitMQ..."

    if [ "$OS" == "Debian" ]; then
        apt-get -yq install rabbitmq-server
    elif [ "$OS" == "RedHat" ]; then
        yum -y -q install rabbitmq-server
        chkconfig rabbitmq-server on
        service rabbitmq-server start
    fi

    rabbitmq-plugins enable rabbitmq_management
    set +e
    rabbitmqctl add_user stoq stoq-password
    rabbitmqctl add_vhost stoq
    rabbitmqctl set_permissions -p stoq stoq ".*" ".*" ".*"
    set -e
    echo "[stoQ] Done installing RabbitMQ."
    echo "[stoQ] Note RabbitMQ u: stoq p: stoq-password - consider changing."
}

# Cleanup
cleanup() {
    echo source $PYENV_DIR/bin/activate >> $STOQ_HOME/.profile
    echo export STOQ_HOME=$STOQ_HOME >> $STOQ_HOME/.profile
    chown -R $STOQ_USER:$STOQ_GROUP $STOQ_HOME
    echo ""
    echo "*********************************"
    echo "stoQ Home is set to $STOQ_HOME"
    echo "Run 'sudo su - stoq' to use stoQ"
    echo "*********************************"
    echo ""
    cd $STOQ_HOME
}

####
#
# MAIN
#
###
do_install() {
    #Note: never uncomment - this sets up the virtualenv
    install_prereqs

    install_yara
    install_core
    install_tika
    install_xor
    install_exif
    install_trid
    install_clamav
    install_floss
    install_rabbitmq
    cleanup
}

# Make sure command executed is the same as the script name to
# allow for sourcing of this script
if [ "`basename -- $0`" == "`basename -- $BASH_SOURCE`" ]; then
    do_install
fi
