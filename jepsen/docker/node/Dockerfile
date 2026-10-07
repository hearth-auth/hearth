# syntax=docker/dockerfile:1.6
#
# A Jepsen DB node (design decision 2). The control container drives it over
# SSH as root. The partition and delay nemeses change `iptables` and `tc`, so
# the Compose file runs it `privileged`. The node runs the hearth binary that
# the Jepsen `db` setup uploads; this image holds no hearth build.
#
# Same base image and digest as the root Dockerfile's runtime stage, so the
# binary meets the glibc it is built against (decision 3).
FROM debian:bookworm-slim@sha256:67b30a61dc87758f0caf819646104f29ecbda97d920aaf5edc834128ac8493d3

# openssh-server: the control link. iptables, iproute2 (tc): the nemeses.
# procps, psmisc: pgrep / pkill / killall for `kill -9` and process checks.
# curl, ca-certificates: health checks against the node's HTTPS port.
# sudo: Jepsen's control helpers may wrap commands in it.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openssh-server iptables iproute2 procps psmisc curl ca-certificates sudo \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /etc/ssh/ssh_host_* \
    && mkdir -p /run/sshd /root/.ssh \
    && chmod 700 /root/.ssh

COPY sshd.conf /etc/ssh/sshd_config.d/jepsen.conf
COPY entrypoint.sh /usr/local/bin/node-entrypoint
RUN chmod 0755 /usr/local/bin/node-entrypoint

ENTRYPOINT ["/usr/local/bin/node-entrypoint"]
