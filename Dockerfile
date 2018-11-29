FROM python:3.7
LABEL maintainer="marcus@punchcyber.com"

ENV USER stoq
ENV GROUP stoq
ENV STOQ_HOME /home/$USER/.stoq
ENV STOQ_TMP /tmp

RUN groupadd -r $USER && useradd -r -g $GROUP $USER && \
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
    curl && \
    apt-get clean -y && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN pip install stoq-framework && \
    git clone --single-branch --branch v2 https://github.com/PUNCH-Cyber/stoq-plugins-public ${STOQ_TMP}/stoq-plugins-public && \
    cd ${STOQ_TMP}/stoq-plugins-public && \
    for plugin in `ls -d */`; do stoq install $plugin; done

ENTRYPOINT ["stoq"]