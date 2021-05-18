FROM ubuntu:18.04

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends\
    apache2 \
    ca-certificates \
    git \
    gnupg \
    libgconf-2-4 \
    libnss3-tools \
    ntp \
    wget \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
RUN wget -q https://deb.nodesource.com/setup_12.x -O - | bash -
RUN wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add -
RUN echo 'deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main' | tee /etc/apt/sources.list.d/google-chrome.list
RUN apt-get update && apt-get install -y --no-install-recommends \
    google-chrome-stable \
    libxss1 \
    libxtst6 \
    nodejs \
    libgtk2.0-0 libgtk-3-0 libnotify-dev \
    libgconf-2-4 libnss3 libxss1 \
    libasound2 libxtst6 xauth xvfb \
    libgbm-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /root
RUN git clone https://github.com/openid-certification/oidc-provider-conformance-tests.git --depth 1
WORKDIR /root/oidc-provider-conformance-tests
RUN npm install --production
WORKDIR /root
RUN git clone https://github.com/openid-certification/openid-client-conformance-tests.git --depth 1
WORKDIR /root/openid-client-conformance-tests
RUN npm install --production
RUN npm install -g concurrently@5

COPY run.sh /root/run.sh
RUN chmod 755 /root/run.sh

ENTRYPOINT /root/run.sh
