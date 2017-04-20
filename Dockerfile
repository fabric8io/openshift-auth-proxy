FROM node:0.10.36

MAINTAINER OpenShift Development <dev@lists.openshift.redhat.com>

ENV APP_DIR=/opt/openshift-auth-proxy

COPY . ${APP_DIR}

RUN cd ${APP_DIR} && \
    npm install

WORKDIR ${APP_DIR}

ENTRYPOINT ["/opt/openshift-auth-proxy/run.sh"]
