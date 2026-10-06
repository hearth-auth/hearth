# syntax=docker/dockerfile:1.6
#
# The Jepsen control node (design decision 2): JDK 21 and Leiningen. It runs
# the Jepsen project mounted at /jepsen and drives n1–n5 over SSH as root.
# Jepsen and its libraries come from Clojars at run time (Open Question 1);
# this image holds none of them.
FROM eclipse-temurin:21-jdk-noble@sha256:b468c3fc688b14450571494f588bd939378e7fd542ed5a73f8efc13f17872a87

# openssh-client: the link to the nodes. gnuplot-nox: Jepsen's latency and
# rate graphs. openssl: the per-run CA and leaves (gen-material.sh). git:
# Jepsen records the test code's commit in store/. curl: fetches lein below.
# The mounted /jepsen belongs to the host user, not root, so git must trust it.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openssh-client gnuplot-nox openssl git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && git config --system --add safe.directory '*'

# The base image sets en_US.UTF-8, and ssh forwards LANG and LC_* to the
# nodes, which lack that locale. C.UTF-8 is built into every glibc.
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8 LANGUAGE=

# Pinned by hash. The script checks the sha256 of the jar it downloads.
ARG LEIN_VERSION=2.11.2
ARG LEIN_SHA256=f83e3de252cb09d301f18f1912acffa807b54c1c9a96772ae63847a946032bd4
ENV LEIN_ROOT=1
RUN curl -fsSL -o /usr/local/bin/lein \
        "https://codeberg.org/leiningen/leiningen/raw/tag/${LEIN_VERSION}/bin/lein" \
    && echo "${LEIN_SHA256}  /usr/local/bin/lein" | sha256sum -c - \
    && chmod 0755 /usr/local/bin/lein \
    && lein version

COPY ssh_config /root/.ssh/config
COPY entrypoint.sh /usr/local/bin/control-entrypoint
COPY ssh-check.sh /usr/local/bin/jepsen-ssh-check
RUN chmod 0700 /root/.ssh \
    && chmod 0600 /root/.ssh/config \
    && chmod 0755 /usr/local/bin/control-entrypoint /usr/local/bin/jepsen-ssh-check

WORKDIR /jepsen
ENTRYPOINT ["/usr/local/bin/control-entrypoint"]
