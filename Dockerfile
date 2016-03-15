FROM ubuntu:14.04
MAINTAINER Adam Trask ”adam@punchcyber.com”

RUN apt-get -y install software-properties-common \
  && apt-add-repository -y multiverse

ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8
ENV LANGUAGE C.UTF-8  

ENV STOQ_TMP /usr/local/tmp
ENV STOQ_DIR /usr/local/stoq
ENV STOQ_ENV $STOQ_DIR/.stoq-pyenv

ENV STOQ_UID 1005
ENV STOQ_USER stoq

ENV STOQ_GID 1005
ENV STOQ_GROUP stoq

ADD . ${STOQ_TMP}/stoq
ADD ./stoq ${STOQ_DIR}

#############################
### Install Prerequisites ###
#############################
RUN echo "[stoQ] Installing prerequisites..."

RUN apt-get -yq update && apt-get -yq install \
  git-core \
  wget \
  unzip \
  p7zip-full \
  unace-nonfree \
  p7zip-rar \
  automake \
  build-essential \
  cython \
  autoconf \
  python3 \
  python3-dev \
  python3-setuptools \
  libyaml-dev \
  libffi-dev \
  libfuzzy-dev \
  libxml2-dev \
  libxslt1-dev \
  libz-dev \
  libssl-dev \
  libmagic-dev
  
RUN easy_install3 pip 
RUN pip3 install virtualenv --quiet

RUN echo "[stoQ] Done installing prerequisites."

##################################
### Create Virtual Environment ###
##################################
RUN echo "[stoQ] Setting up virtualenv..."
RUN virtualenv ${STOQ_ENV}

####################
### Install Yara ###
####################
RUN echo "[stoQ] Installing yara..."
RUN apt-get -yq install \
  bison \
  flex \
  libtool

WORKDIR ${STOQ_TMP}
RUN git clone https://github.com/plusvic/yara.git yara

WORKDIR yara
RUN bash bootstrap.sh \
  && ./configure --with-crypto --enable-magic \
  && make \
  && make install

RUN echo "[stoQ] Done installing yara."

####################
### Install Core ###
####################
RUN echo "[stoQ] Installing core components..."

WORKDIR ${STOQ_TMP}/stoq
RUN . ${STOQ_ENV}/bin/activate \
  && python setup.py install \
  && pip install hydra

WORKDIR ${STOQ_DIR}
RUN . ${STOQ_ENV}/bin/activate \
  && chmod +x ${STOQ_DIR}/stoq-cli.py \
  && git clone https://github.com/PUNCH-Cyber/stoq-plugins-public.git \
  && for category in connector decoder extractor carver source reader worker; \
    do for plugin in `ls ${STOQ_DIR}/stoq-plugins-public/$category`; \
      do ./stoq-cli.py install ${STOQ_DIR}/stoq-plugins-public/$category/$plugin; done \
    done

RUN echo "[stoQ] Done installing core components."

####################
### Install Tika ###
####################
RUN echo "[stoQ] Installing tika..."

ENV TIKA_URL curl https://tika.apache.org/download.html | sed -n 's/.*href="\(.*server.*\.jar\)">.*/\1/ip;T;q'
ENV TIKA_DOWNLOAD curl -s ${TIKA_URL} | sed -n 's/.*<strong>\(.*\)<\/strong>.*/\1/ip;T;q'
ENV TIKA_VERSION echo ${TIKA_URL} | awk 'BEGIN{FS="server-|.jar"} {print $2}'
ENV TIKA_DIR /usr/local/tika

WORKDIR ${STOQ_TMP}
RUN apt-get -yq install default-jdk \
  && wget ${TIKA_DOWNLOAD} \
  && wget https://people.apache.org/keys/group/tika.asc \
  && wget http://www.apache.org/dist/tika/tika-server-${TIKA_VERSION}.jar.asc \
  && gpg --import tika.asc \
  && gpg --verify tika-server-${TIKA_VERSION}.jar.asc \
  && mv tika-server-${TIKA_VERSION}.jar ${TIKA_DIR}/ \
  && java -jar ${TIKA_DIR}/tika-server-${TIKA_VERSION}.jar --host=localhost --port=9998 &

RUN echo "[stoQ] Done installing tika."

###################
### Install Xor ###
###################
RUN echo "[stoQ] Installing xorsearch..."

WORKDIR ${STOQ_TMP}
RUN wget -O XORSearch.zip "https://didierstevens.com/files/software/XORSearch_V1_11_1.zip" \
  && unzip -qq XORSearch -d XORSearch \
  && gcc -o /usr/local/bin/xorsearch XORSearch/XORSearch.c \
  && rm -r XORSearch.zip

RUN echo "[stoQ] Done installing xorsearch."

####################
### Install Exif ###
####################
RUN echo "[stoQ] Installing exiftool..."

WORKDIR ${STOQ_TMP}
RUN wget -O exif.tgz "http://www.sno.phy.queensu.ca/~phil/exiftool/Image-ExifTool-10.02.tar.gz" \
  && tar -xvf exif.tgz \
  && rm exif.tgz

WORKDIR Image-ExifTool-10.02
RUN perl Makefile.PL \
  && make \
  && make test \
  && make install

RUN echo "[stoQ] Done installing exiftool."

####################
### Install Trid ###
####################
RUN echo "[stoQ] Installing trid"
RUN apt-get -yq install libc6-i386 lib32ncurses5

WORKDIR ${STOQ_TMP}
RUN wget -O trid_linux_64.zip "http://mark0.net/download/trid_linux_64.zip" \
  && unzip -qq trid_linux_64 -d /usr/local/bin \
  && chmod +x /usr/local/bin/trid \
  && rm -r trid_linux_64.zip \
  && wget -O triddefs.zip "http://mark0.net/download/triddefs.zip" \
  && unzip -qq triddefs -d ${STOQ_DIR}/plugins/worker/trid \
  && rm -r triddefs.zip

RUN echo "[stoQ] Done installing trid"

###########################
### Cleanup and Staging ###
###########################
RUN groupadd --gid ${STOQ_GID} --system ${STOQ_GROUP} \
  && useradd --uid ${STOQ_UID} --gid ${STOQ_GID} --home-dir ${STOQ_DIR} ${STOQ_USER} \
  && chown --recursive ${STOQ_USER}:${STOQ_GROUP} ${STOQ_DIR}

WORKDIR ${STOQ_DIR}
USER ${STOQ_USER}
