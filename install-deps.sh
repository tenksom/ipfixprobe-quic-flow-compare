#!/bin/bash
# Installs everything the QUIC flow compare test needs on Oracle Linux 10
# (the CI container): runtime tools plus build dependencies of build-tools.sh.
set -euo pipefail

dnf install -y dnf-plugins-core
dnf config-manager --set-enabled ol10_codeready_builder
# Fedora EPEL, the Arrow repo package requires "epel-release" (oracle-epel-release-el10 does not provide it).
dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-10.noarch.rpm
# Apache Arrow/Parquet GLib for tshark's parquet-helper.
dnf install -y https://packages.apache.org/artifactory/arrow/almalinux/10/apache-arrow-release-latest.rpm

dnf install -y \
  tcpdump python3 python3-pip curl wget findutils procps-ng tar gzip zstd \
  git make gcc gcc-c++ cmake flex bison perl golang \
  glib2-devel libpcap-devel zlib-devel c-ares-devel speexdsp-devel \
  libgcrypt-devel pcre2-devel \
  arrow-glib-devel parquet-glib-devel

pip3 install -r "$(dirname "$0")/requirements.txt"
