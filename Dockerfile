FROM ubuntu:16.04
MAINTAINER Adam Trask ”adam@punchcyber.com”

ENV LANG='C.UTF-8' LC_ALL='C.UTF-8' LANGUAGE='C.UTF-8' STOQ_TMP='/usr/local/tmp' STOQ_DIR='/usr/local/stoq'
ENV STOQ_ENV $STOQ_DIR/.stoq-pyenv

ADD . ${STOQ_TMP}/stoq
ADD ./stoq ${STOQ_DIR}

RUN apt-get update \ 
  && apt-get -y install software-properties-common \
  && apt-add-repository -y multiverse

#############################
### Install Prerequisites ###
#############################
RUN apt-get update \
  && echo "[stoQ] Installing prerequisites..." \
  && apt-get -y install \
    autoconf \
    automake \
    build-essential \
    curl \
    cython \
    git-core \
    libffi-dev \
    libfuzzy-dev \
    libmagic-dev \
    libssl-dev \
    libxml2-dev \
    libxslt1-dev \
    libyaml-dev \
    libz-dev \
    p7zip-full \
    p7zip-rar \
    python3 \
    python3-dev \
    python3-setuptools \
    unace-nonfree \
    unzip \
    wget \
  && echo "[stoQ] Setting up virtualenv..." \
  && easy_install3 pip \
  && pip3 install virtualenv --quiet \
  && virtualenv ${STOQ_ENV}

####################
### Install Yara ###
####################
WORKDIR ${STOQ_TMP}
RUN echo "[stoQ] Installing yara..." \
  && apt-get -yq install \
    bison \
    flex \
    libjansson-dev \ 
    libtool \
  && git clone https://github.com/plusvic/yara.git yara \
  && git clone --recursive https://github.com/VirusTotal/yara-python

WORKDIR ${STOQ_TMP}/yara
RUN bash bootstrap.sh \
  && ./configure --with-crypto --enable-magic --enable-cuckoo \
  && make \
  && make install

WORKDIR ${STOQ_TMP}/yara-python
RUN echo "[stoQ] Installing yara-python..." \
  && . ${STOQ_ENV}/bin/activate \
  && python setup.py build --dynamic-linking \
  && python setup.py install

####################
### Install Core ###
####################
WORKDIR ${STOQ_TMP}/stoq
RUN echo "[stoQ] Installing core stoQ components..." \
  && . ${STOQ_ENV}/bin/activate \
  && python setup.py install \
  && pip install hydra

WORKDIR ${STOQ_DIR}
RUN . ${STOQ_ENV}/bin/activate \
  && chmod +x ${STOQ_DIR}/stoq-cli.py \
  && git clone https://github.com/PUNCH-Cyber/stoq-plugins-public.git \
  && for category in connector decoder extractor carver source reader worker; \
    do for plugin in `ls ${STOQ_DIR}/stoq-plugins-public/$category`; \
      do ${STOQ_DIR}/stoq-cli.py install ${STOQ_DIR}/stoq-plugins-public/$category/$plugin; done \
    done

###################
### Install Xor ###
###################
WORKDIR ${STOQ_TMP}
RUN echo "[stoQ] Installing xorsearch..." \
  && wget -O XORSearch.zip "https://didierstevens.com/files/software/XORSearch_V1_11_1.zip" \
  && unzip -qq XORSearch -d XORSearch \
  && gcc -o /usr/local/bin/xorsearch XORSearch/XORSearch.c

####################
### Install Exif ###
####################
WORKDIR ${STOQ_TMP}
RUN echo "[stoQ] Installing exiftool..." \
  && wget -O exif.tgz "http://www.sno.phy.queensu.ca/~phil/exiftool/Image-ExifTool-10.02.tar.gz" \
  && tar -xvf exif.tgz

WORKDIR Image-ExifTool-10.02
RUN perl Makefile.PL \
  && make \
  && make test \
  && make install

####################
### Install Trid ###
####################
WORKDIR ${STOQ_TMP}
RUN echo "[stoQ] Installing trid" \
  && apt-get -yq install libc6-i386 lib32ncurses5 \
  && wget -O trid_linux_64.zip "http://mark0.net/download/trid_linux_64.zip" \
  && unzip -qq trid_linux_64 -d /usr/local/bin \
  && chmod +x /usr/local/bin/trid \
  && wget -O triddefs.zip "http://mark0.net/download/triddefs.zip" \
  && unzip -qq triddefs -d ${STOQ_DIR}/plugins/worker/trid

###########################
### Cleanup and Staging ###
###########################
WORKDIR ${STOQ_DIR}
RUN rm -r ${STOQ_TMP}

