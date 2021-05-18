FROM ubuntu:18.04

ENV DEBIAN_FRONTEND noninteractive
ENV SRCDIR /usr/local/src
ENV INSTDIR oidf
ENV SUBDIR ${SRCDIR}/${INSTDIR}/oidc_cp_rplib

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    libffi-dev \
    libssl-dev \
    python3-dev \
    python3-pip \
    python3-setuptools && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN python3 -mpip install -U pip setuptools
RUN git clone --depth=1 https://github.com/openid-certification/otest.git ${SRCDIR}/otest
WORKDIR ${SRCDIR}/otest
RUN python3 setup.py install

RUN git clone --depth=1 https://github.com/openid-certification/oidctest.git ${SRCDIR}/oidctest
WORKDIR ${SRCDIR}/oidctest
RUN python3 setup.py install

WORKDIR ${SRCDIR}
RUN oidc_setup.py ${SRCDIR}/oidctest ${INSTDIR}
COPY docker/rp_test/cert.pem ${SUBDIR}/certs/
COPY docker/rp_test/key.pem ${SUBDIR}/certs/
COPY docker/rp_test/conf.py ${SUBDIR}/
COPY docker/rp_test/run.sh ${SUBDIR}/

RUN mkdir pyoidc
COPY . ${SRCDIR}/pyoidc/
WORKDIR ${SRCDIR}/pyoidc
RUN python3 setup.py install

WORKDIR ${SUBDIR}
ENTRYPOINT ["./run.sh"]
