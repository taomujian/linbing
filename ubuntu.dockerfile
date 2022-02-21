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
&& apt install -y mariadb-server python3.8 python3.8-dev python3-pip nmap masscan nginx libxml2-dev \
libxslt1-dev zlib1g-dev libffi-dev libpq-dev uuid-dev libcap-dev redis-server libpcre3-dev python3-dev inetutils-ping --fix-missing \
&& mkdir /root/python && useradd -s /sbin/nologin -M nginx && sed -i "s|bind 127.0.0.1 ::1|bind 127.0.0.1|" /etc/redis/redis.conf \
&& sed -i "s|# requirepass foobared|requirepass '${REDIS_PASS}'|" /etc/redis/redis.conf

# 复制本地文件到docker 中
ADD nginx/vue.conf /etc/nginx/conf.d/vue.conf
ADD nginx/nginx.conf /etc/nginx/nginx.conf
ADD vue /usr/share/nginx/html/vue
ADD python /root/python
ADD python/gunicorn.conf /root/python/gunicorn.conf
ADD ubuntu_run.sh /ubuntu_run.sh

RUN ln -sf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone && apt install -y tzdata && service mysql start \
&& mysql -e "SET PASSWORD FOR ${MARIADB_USER}@localhost = PASSWORD('${MARIADB_PASS}');FLUSH PRIVILEGES;" \
&& mysql -e "update mysql.user set plugin='mysql_native_password' where User='${MARIADB_USER}';FLUSH PRIVILEGES;" \
&& update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.8 1 && update-alternatives --config python3 \
&& pip3 install --upgrade pip && pip3 install -r /root/python/requirements.txt && chmod +x /ubuntu_run.sh 

CMD ["/ubuntu_run.sh"]