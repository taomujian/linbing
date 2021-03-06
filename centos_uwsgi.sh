#!/bin/bash

UWSGI_VERSION="$( rpm -q uwsgi --queryformat '%{VERSION}' )"
UWSGI_PLUGINS_DIR="$( dirname "$( rpm -q uwsgi-plugin-common -l | grep '_plugin\.so' | tail -1 )" )"

if [[ $X_SCLS == *rh-python38* ]]; then
    UWSGI_PLUGINS_DIR="/opt/rh/rh-python38/root${UWSGI_PLUGINS_DIR:?}"
fi

if [[ ! -f "${UWSGI_PLUGINS_DIR:?}/python38_plugin.so" ]]; then
    yum -y install gcc libcap-devel libuuid-devel make openssl-devel rh-python38-python-devel
    mkdir -pv /opt/rh/rh-python38/root/src
    cd /opt/rh/rh-python38/root/src
    curl -LO "https://projects.unbit.it/downloads/uwsgi-${UWSGI_VERSION:?}.tar.gz"
    tar zxvf "uwsgi-${UWSGI_VERSION:?}.tar.gz"
    cd "uwsgi-${UWSGI_VERSION:?}/"
    make PROFILE=nolang
    PYTHON=python3 /usr/sbin/uwsgi --build-plugin "plugins/python python38"
    [[ ! -d "${UWSGI_PLUGINS_DIR:?}/" ]] && mkdir -pv "${UWSGI_PLUGINS_DIR:?}/"
    mkdir /usr/lib/uwsgi
    mkdir /usr/lib/uwsgi/plugins
    mv -v python38_plugin.so /usr/lib/uwsgi/plugins/
fi