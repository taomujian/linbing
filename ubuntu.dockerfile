# 底层为ubuntu
FROM ubuntu:18.04

# 设置相关环境变量,数据库账号密码
ENV DEBIAN_FRONTEND noninteractive
ENV MARIADB_USER root
ENV MARIADB_PASS 123456
ENV REDIS_PASS 123456
ENV TZ=Asia/Shanghai
ENV LANG C.UTF-8

# 暴露端口
EXPOSE 8800
EXPOSE 1100

# 更新apt源及安装依赖
RUN sed -i s@/archive.ubuntu.com/@/mirrors.aliyun.com/@g /etc/apt/sources.list && apt-get clean && apt update \
&& apt install -y mariadb-server wget nmap masscan nginx libxml2-dev build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev \
libxslt1-dev zlib1g-dev libffi-dev libsqlite3-dev libpq-dev uuid-dev libcap-dev redis-server libpcre3-dev python3-dev inetutils-ping --fix-missing \
&& mkdir /root/python && useradd -s /sbin/nologin -M nginx && sed -i "s|bind 127.0.0.1 ::1|bind 127.0.0.1|" /etc/redis/redis.conf \
&& sed -i "s|# requirepass foobared|requirepass '${REDIS_PASS}'|" /etc/redis/redis.conf

RUN wget https://www.python.org/ftp/python/3.10.4/Python-3.10.4.tgz && tar -zxvf Python-3.10.4.tgz && cd Python-3.10.4 && ./configure \
&& make && make install && rm -rf /usr/bin/python3 && rm -rf /usr/bin/pip3 && ln -s /usr/local/bin/python3.10 /usr/bin/python3 && ln -s /usr/local/bin/pip3.10 /usr/bin/pip3

# 复制本地文件到docker 中
ADD nginx/vue.conf /etc/nginx/conf.d/vue.conf
ADD nginx/nginx.conf /etc/nginx/nginx.conf
ADD vue /usr/share/nginx/html/vue
ADD python /root/python
ADD python/gunicorn.conf /root/python/gunicorn.conf
ADD ubuntu_docker_run.sh /ubuntu_docker_run.sh

RUN ln -sf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone && apt install -y tzdata && service mysql start \
&& mysql -e "SET PASSWORD FOR ${MARIADB_USER}@localhost = PASSWORD('${MARIADB_PASS}');FLUSH PRIVILEGES;" \
&& mysql -e "update mysql.user set plugin='mysql_native_password' where User='${MARIADB_USER}';FLUSH PRIVILEGES;" \
&& pip3 install -r /root/python/requirements.txt && chmod +x /ubuntu_docker_run.sh 

CMD ["/ubuntu_docker_run.sh"]