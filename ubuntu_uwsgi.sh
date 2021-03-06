#!/bin/bash

cd ~ 
export PYTHON=python3.8 
uwsgi --build-plugin "/usr/src/uwsgi/plugins/python python38"
mv python38_plugin.so /usr/lib/uwsgi/plugins/python38_plugin.so
chmod 644 /usr/lib/uwsgi/plugins/python38_plugin.so