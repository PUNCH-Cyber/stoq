FROM ubuntu:16.04
MAINTAINER Adam Trask ”adam@punchcyber.com”

ENV LANG='C.UTF-8' LC_ALL='C.UTF-8' LANGUAGE='C.UTF-8' STOQ_TMP='/tmp' STOQ_DIR='/usr/local/stoq'

ADD . ${STOQ_TMP}/stoq
ADD ./cmd ${STOQ_DIR}

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
    python3-pip \
    python3-setuptools \
    unace-nonfree \
    unzip \
    wget

############################
### Install Requirements ###
############################
RUN echo "[stoQ] Installing python requirements..." \
 && pip3 install requests[security] \
 && pip3 install -r ${STOQ_TMP}/stoq/requirements.txt \
 && pip3 install hydra jinja2

####################
### Install Core ###
####################
WORKDIR ${STOQ_TMP}/stoq
RUN echo "[stoQ] Installing core stoQ components..." \
  && python3 setup.py install

#######################
### Install Plugins ###
#######################
WORKDIR ${STOQ_DIR}
RUN echo "[stoQ] Installing plugins" \
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
  && wget -O exif.tgz "http://www.sno.phy.queensu.ca/~phil/exiftool/Image-ExifTool-10.59.tar.gz" \
  && tar -xvf exif.tgz

WORKDIR ${STOQ_TMP}/Image-ExifTool-10.59
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
RUN apt-get clean
RUN rm -rf \
	/tmp/* \
	/var/lib/apt/lists/* \
	/var/tmp/*
