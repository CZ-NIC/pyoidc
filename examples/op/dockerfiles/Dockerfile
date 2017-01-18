FROM itsdirg/dirg_base

MAINTAINER DIRG <dirg@its.umu.se>

VOLUME ["/opt/dirg/settings"]

ADD start.sh /start.sh
ADD https://github.com/rohe/pyoidc/releases/latest /opt/dirg/src/code.tar.gz

RUN cd /opt/dirg/src && \
    mkdir pyoidc-master && \
    cd pyoidc-master && \
    tar xf  ../code.tar.gz --strip-components=1 && \
    pip install -r examples/op/example_op/requirements.txt

EXPOSE 8092
CMD ["/start.sh"]
