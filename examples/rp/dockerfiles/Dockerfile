FROM itsdirg/dirg_base

MAINTAINER DIRG <dirg@its.umu.se>

VOLUME ["/opt/dirg/settings"]

ADD start.sh /start.sh
ADD https://github.com/rohe/pyoidc/releases/latest /opt/dirg/src/code.tar.gz

RUN cd /opt/dirg/src && \
    mkdir pyoidc-master && \
    cd pyoidc-master && \
    tar xf  ../code.tar.gz --strip-components=1 && \
    pip install -r examples/rp/example_rp/requirements.txt

EXPOSE 8666
CMD ["/start.sh"]
