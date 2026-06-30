FROM ubuntu:24.04
ENV container=docker DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
  && apt-get install -y --no-install-recommends systemd systemd-sysv dbus curl python3 openssh-server iptables procps ca-certificates \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/* /lib/systemd/system/multi-user.target.wants/* /etc/systemd/system/*.wants/* /lib/systemd/system/local-fs.target.wants/* /lib/systemd/system/sockets.target.wants/*udev* /lib/systemd/system/sockets.target.wants/*initctl* /lib/systemd/system/sysinit.target.wants/systemd-tmpfiles-setup* /lib/systemd/system/systemd-update-utmp*
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
