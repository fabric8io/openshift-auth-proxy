FROM node:8

MAINTAINER OpenShift Development <dev@lists.openshift.redhat.com>

ENV APP_DIR=/opt/openshift-auth-proxy

COPY . ${APP_DIR}

RUN cd ${APP_DIR} && \
    npm install

WORKDIR ${APP_DIR}

ENTRYPOINT ["./run.sh"]
