#!/usr/bin/env bash
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
###
#
# stoQ installation script.
# Supports: Ubuntu, Redhat 7, and CentOS
#
###

# Die if anything in this script fails to execute
set -e

PREFIX=$HOME
export STOQ_HOME=$PREFIX/.stoq
STAGE_DIR=$PREFIX/stage

install_core() {
    apt-get update -y && apt-get install -yq python3-setuptools python3-pip

    build_dirs

    if [ ! -d ${STAGE_DIR}/stoq ]; then
        git clone https://github.com/PUNCH-Cyber/stoq ${STAGE_DIR}/stoq
    fi
    cd ${STAGE_DIR}/stoq
    git checkout v2
    python3 setup.py install

    if [ ! -d ${STAGE_DIR}/stoq-plugins-public ]; then
        git clone https://github.com/PUNCH-Cyber/stoq-plugins-public ${STAGE_DIR}/stoq-plugins-public
    fi
    cd ${STAGE_DIR}/stoq-plugins-public
    git checkout v2
    for plugin in `ls v2/`
    do
        stoq install v2/$plugin
    done
}

build_dirs() {
    if [ ! -d $STOQ_HOME/plugins ]; then
        echo "[stoQ] Creating stoQ directory ($STOQ_HOME)"
        mkdir -p $STOQ_HOME/plugins
    fi

    if [ ! -d $STAGE_DIR ]; then
        echo "[stoQ] Creating stoQ tmp directory ($STAGE_DIR)"
        mkdir -p $STAGE_DIR
    fi
}

install_core
