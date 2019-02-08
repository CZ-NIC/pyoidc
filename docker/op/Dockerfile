FROM ubuntu:18.04

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends git ntp curl gnupg ca-certificates
RUN curl -sL https://deb.nodesource.com/setup_8.x | bash -
RUN apt-get update && apt-get install -y --no-install-recommends nodejs apache2 && apt-get clean && rm -rf /var/lib/apt/lists/*

ENV SRCDIR /usr/local/src
ENV INSTDIR node-oidc-provider
ENV SUBDIR ${SRCDIR}/${INSTDIR}


ENV VERSION_NODE_OP   tags/v4.0.3

WORKDIR ${SRCDIR}
RUN git clone https://github.com/panva/node-oidc-provider.git
WORKDIR ${SRCDIR}/node-oidc-provider
RUN git checkout ${VERSION_NODE_OP}
RUN pwd
WORKDIR ${INSTDIR}
RUN pwd
RUN npm install

COPY docker/op/apache-ssl.conf /etc/apache2/sites-available/ssl.conf
COPY docker/op/cert.pem /etc/apache2/
COPY docker/op/key.pem /etc/apache2/

RUN a2enmod headers && a2enmod ssl && a2enmod proxy && a2enmod proxy_http && a2ensite ssl

COPY docker/op/run.sh ${SUBDIR}/

WORKDIR ${SUBDIR}
ENTRYPOINT ["./run.sh"]
