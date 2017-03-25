#!/bin/bash

apt-get update
apt-get install -y \
	wget \
	unzip \
	libffi-dev \
	libxmlsec1 \
	xmlsec1 \
	libxmlsec1-openssl \
	libxmlsec1-dev \

# Create a folder for the pyoidc src
mkdir /opt/dirg/src
cd /opt/dirg/src

# Download and unzip pyoidc
wget "https://github.com/rohe/pyoidc/archive/master.zip"
zip_name=$(ls)
unzip "${zip_name}"
rm "${zip_name}"
src_name=$(ls)
mv "${src_name}" pyoidc-master

# install op dependencies
pip install cherrypy pysaml2
pip install -e /opt/dirg/src/pyoidc-master/
