FROM node:0.10.36

MAINTAINER Luke Meyer <lmeyer@redhat.com>

ENTRYPOINT ["openshift-auth-proxy"]

COPY . /opt/openshift-auth-proxy

RUN cd /opt/openshift-auth-proxy \
    && npm install -g .
