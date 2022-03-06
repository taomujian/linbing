#!/bin/bash

PIDS=`ps -ef |grep mysql |grep -v grep | awk '{print $2}'`
if [ "$PIDS" = "" ]; then
    # 启动
    mysql_install_db --user=mysql
    sleep 3
    mysqld_safe &
    sleep 3
    mysqladmin -u "$MARIADB_USER" password "$MARIADB_PASS"

    # 授权
    mysql -u "$MARIADB_USER" -p"$MARIADB_PASS" -e "use mysql; grant all privileges on *.* to '$MARIADB_USER'@'%' identified by 
    '$MARIADB_PASS' with grant option;"

    h=$(hostname)

    # 设置用户密码
    mysql -u "$MARIADB_USER" -p"$MARIADB_PASS" -e "use mysql; update user set password=password('$MARIADB_PASS') where user='$M
    ARIADB_USER' and host='$h';"

    # 刷新权限
    mysql -u "$MARIADB_USER" -p"$MARIADB_PASS" -e "flush privileges;"

    systemctl start redis
    redis-server /etc/redis.conf
    
    nginx
    setsid mysqld_safe &
    cd /root/python
    nohup gunicorn -c gunicorn.conf main:app -k uvicorn.workers.UvicornWorker > gunicorn.log 2>&1 &
    tail -f /dev/null
fi
