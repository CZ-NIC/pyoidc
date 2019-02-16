FROM jfloff/alpine-python:3.6

RUN apk add openssl-dev libffi-dev git

ENV SRCDIR /usr/local/src
ENV INSTDIR oidf
ENV SUBDIR ${SRCDIR}/${INSTDIR}/oidc_cp_rplib


RUN git clone https://github.com/openid-certification/otest.git ${SRCDIR}/otest
WORKDIR ${SRCDIR}/otest
RUN python3 setup.py install

RUN git clone https://github.com/openid-certification/oidctest.git ${SRCDIR}/oidctest
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
