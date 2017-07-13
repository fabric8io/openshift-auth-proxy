FROM rhel7.3:7.3-released

MAINTAINER OpenShift Development <dev@lists.openshift.redhat.com>

ENV APP_DIR=/usr/lib/node_modules/openshift-auth-proxy

USER 0

LABEL io.k8s.description="Logging auth proxy" \
  io.k8s.display-name="Logging auth proxy" \
  io.openshift.expose-services="443:https" \
  com.redhat.component=logging-auth-proxy-docker \
  name="openshift3/logging-auth-proxy" \
  version="v3.6.134" \
  release="1" \
  architecture=x86_64

# Note: NODE_VERSION differs from upstream because proxy
# seg faults on node 4.2.1
ENV APP_DIR=/usr/lib/node_modules/openshift-auth-proxy \
    NODE_VERSION=0.10.47 \
    OCP_PROXY_VERSION=0.1.1

RUN yum-config-manager --enable rhel-7-server-ose-3.6-rpms && \
    INSTALL_PKGS="nodejs-${NODE_VERSION} \
                  nodejs-openshift-auth-proxy-${OCP_PROXY_VERSION}" && \
    yum install -y $INSTALL_PKGS && \
    rpm -V $INSTALL_PKGS && \
    yum clean all

WORKDIR ${APP_DIR}

ENTRYPOINT ["./run.sh"]

