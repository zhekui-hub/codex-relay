# Author: zhekui
# Purpose: Provide an isolated Linux systemd environment for the relay integration test.
# No functions; the container runs systemd and the test harness is invoked separately.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive container=docker
RUN apt-get update && apt-get install -y --no-install-recommends \
    systemd systemd-sysv dbus dbus-user-session nginx curl ca-certificates \
    python3 iproute2 util-linux openssl && apt-get clean
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
