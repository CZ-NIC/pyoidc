#!/bin/bash

# Check if running on mac
if [ "$(uname)" = "Darwin" ]; then
    # Check so the boot2docker vm is running
    if [ "$(boot2docker status)" != "running" ]; then
        boot2docker start
    fi
    boot2docker shellinit
    HOST_IP=$(boot2docker ip)
else
    # if running on linux
    if [ "$(id -u)" -ne 0 ]; then
        sudo="sudo"
    fi
    HOST_IP=$(ifconfig | grep 'inet addr:'| grep -v '127.0.0.1' | grep -v '172.17' | cut -d: -f2 | awk '{ print $1}' | head -1)
fi

echo "HOST IP: " "${HOST_IP}"

${sudo} docker run -d \
    --name op \
    -p 8092:8092 \
    -e HOST_IP="${HOST_IP}" \
    -i -t \
    itsdirg/pyoidc_example_op

${sudo} docker run -d \
    --name rp \
    -p 8666:8666 \
    -e HOST_IP="${HOST_IP}" \
    -i -t \
    itsdirg/pyoidc_example_rp
