FROM python:3.7
LABEL maintainer="marcus@punchcyber.com"

ENV USER stoq
ENV GROUP stoq
ENV STOQ_HOME /home/$USER/.stoq
ENV STOQ_TMP /tmp/stoq
ENV XORSEARCH_VER 1_11_2
ENV EXIFTOOL_VER 11.91

RUN groupadd -r $GROUP && \
    useradd -r -g $GROUP $USER && \
    install -d $STOQ_HOME -o $USER -g $GROUP && \
    mkdir -p /home/$USER/.stoq/plugins

RUN apt-get update && \
    apt-get install -y software-properties-common && \
    apt-add-repository -y non-free && \
    apt-get update && \
    apt-get -y install \
    automake \
    build-essential \
    libyaml-dev \
    git-core \
    p7zip-full \
    unace-nonfree \
    unzip \
    wget \
    curl \
    libfuzzy-dev \
    libc6-i386 \
    libssl-dev \
    swig \
    lib32ncurses6 && \
    apt-get clean -y && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN pip install stoq-framework\>=3.0.0 six && \
    git clone https://github.com/PUNCH-Cyber/stoq-plugins-public ${STOQ_TMP}/stoq-plugins-public && \
    cd ${STOQ_TMP}/stoq-plugins-public && \
    git checkout v3 && \
    for plugin in `ls -d */`; do stoq install $plugin; done

WORKDIR ${STOQ_TMP}
# Install xorsearch
RUN wget -O XORSearch.zip "https://didierstevens.com/files/software/XORSearch_V${XORSEARCH_VER}.zip" && \
    unzip -qq XORSearch -d XORSearch && \
    gcc -o /usr/local/bin/xorsearch XORSearch/XORSearch.c

# Install exiftool
RUN wget -O exif.tgz "https://www.sno.phy.queensu.ca/~phil/exiftool/Image-ExifTool-${EXIFTOOL_VER}.tar.gz" && \
    tar -xvf exif.tgz && \
    cd Image-ExifTool-${EXIFTOOL_VER} && \
    perl Makefile.PL && \
    make && \
    make test && \
    make install

# Install TRiD
RUN wget -O trid_linux_64.zip "http://mark0.net/download/trid_linux_64.zip" && \
    unzip -qq trid_linux_64 -d /usr/local/bin && \
    chmod +x /usr/local/bin/trid && \
    wget -O triddefs.zip "http://mark0.net/download/triddefs.zip" && \
    unzip -qq triddefs -d $STOQ_HOME/plugins/trid

RUN rm -rf $STOQ_TMP

# Ensure the latest version of the IANA TLDs are in the appropriate place for the iocextract plugin
ADD https://data.iana.org/TLD/tlds-alpha-by-domain.txt $STOQ_HOME/plugins/iocextract/

RUN chmod 644 $STOQ_HOME/plugins/iocextract/tlds-alpha-by-domain.txt

USER $USER
ENTRYPOINT ["stoq"]
