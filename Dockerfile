FROM node:0.12.7

MAINTAINER Jimmi Dyson <jimmidyson@gmail.com>

ENTRYPOINT [ \
  "openshift-auth-proxy", \
  "--listen-port=3000" \
]

COPY . /opt/openshift-auth-proxy

RUN cd /opt/openshift-auth-proxy \
    && npm install -g .
