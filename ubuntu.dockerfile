# 底层为ubuntu
FROM ubuntu:18.04
MAINTAINER taomujian

# 设置相关环境变量,数据库账号密码
ENV DEBIAN_FRONTEND noninteractive
ENV MARIADB_USER root
ENV MARIADB_PASS 1234567
ENV TZ=Asia/Shanghai
ENV LANG C.UTF-8

# 更新apt源及安装依赖
RUN sed -i s@/archive.ubuntu.com/@/mirrors.aliyun.com/@g /etc/apt/sources.list && apt-get clean && apt update \
&& apt install -y mariadb-server python3.8 python3.8-dev python3-pip uwsgi uwsgi-src nmap masscan nginx libpq-dev uuid-dev libcap-dev \
libpcre3-dev postfix python3-dev inetutils-ping && mkdir /root/flask && useradd -s /sbin/nologin -M nginx

RUN cd ~ && export PYTHON=python3.8 && uwsgi --build-plugin "/usr/src/uwsgi/plugins/python python38" && mv python38_plugin.so /usr/lib/uwsgi/plugins/python38_plugin.so \
&& chmod 644 /usr/lib/uwsgi/plugins/python38_plugin.so

# 暴露端口
EXPOSE 3306 11000

# 复制本地文件到docker 中
ADD nginx/flask.conf /etc/nginx/conf.d/flask.conf
ADD nginx/vue.conf /etc/nginx/conf.d/vue.conf
ADD nginx/nginx.conf /etc/nginx/nginx.conf
ADD vue /usr/share/nginx/html/vue
ADD flask /root/flask
ADD flask/uwsgi.ini /root/flask/uwsgi.ini
ADD ubuntu_run.sh /ubuntu_run.sh

RUN ln -sf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone && apt install -y tzdata && service mysql start \
&& mysql -e "SET PASSWORD FOR ${MARIADB_USER}@localhost = PASSWORD('${MARIADB_PASS}');FLUSH PRIVILEGES;" \
&& mysql -e "update mysql.user set plugin='mysql_native_password' where User='${MARIADB_USER}';FLUSH PRIVILEGES;" \
&& update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.8 1 && update-alternatives --config python3 \
&& pip3 install -r /root/flask/requirements.txt && chmod +x /ubuntu_run.sh 

CMD ["/ubuntu_run.sh"]