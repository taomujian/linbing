#!/bin/bash

# chkconfig: 2345 10 90 
# description: myservice ....

PIDS=`ps -ef |grep mysql |grep -v grep | awk '{print $2}'`
if [ "$PIDS" = "" ]; then
    nginx
    service mysql start
    service redis-server start
    redis-server /etc/redis/redis.conf
    cd /root/flask
    uwsgi --ini /root/flask/uwsgi.ini
    tail -f /dev/null
fi
