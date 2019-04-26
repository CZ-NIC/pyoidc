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
    wget
RUN wget -q https://deb.nodesource.com/setup_8.x -O - | bash -
RUN wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add -
RUN echo 'deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main' | tee /etc/apt/sources.list.d/google-chrome.list
RUN apt-get update && apt-get install -y --no-install-recommends \
    google-chrome-stable \
    nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /root
RUN git clone https://github.com/openid-certification/oidc-provider-conformance-tests.git
WORKDIR /root/oidc-provider-conformance-tests
# We have to use older version
RUN git checkout 91f6bec60e4d33644b39bc686a2217600cfdb65c
# And add some commits we need
RUN git config user.email "root@docker.local" && git config user.name "Root"
RUN git cherry-pick 65235ae4b8e3931985342d02dc0321c6f97eda9a..385e0c88d410ff1cbb0a7b3e8a0cbe122d8a9c7e
RUN npm install --production
WORKDIR /root
RUN git clone https://github.com/openid-certification/openid-client-conformance-tests.git --depth 1
WORKDIR /root/openid-client-conformance-tests
RUN npm install --production

COPY run.sh /root/run.sh
RUN chmod 755 /root/run.sh

ENTRYPOINT /root/run.sh
