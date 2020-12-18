# 底层为centos
FROM centos:7
MAINTAINER taomujian

# 更新yum源及安装依赖
RUN mv /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.backup \
&& curl -o /etc/yum.repos.d/epel.repo http://mirrors.aliyun.com/repo/epel-7.repo \
&& curl -o /etc/yum.repos.d/CentOS-Base.repo https://mirrors.aliyun.com/repo/Centos-7.repo \
&& sed -i -e '/mirrors.cloud.aliyuncs.com/d' -e '/mirrors.aliyuncs.com/d' /etc/yum.repos.d/CentOS-Base.repo \
&& yum clean all && yum makecache && yum update -y && yum install -y epel-release mariadb-server gcc gcc-c++ wget bzip2 \
&& wget https://ftp.gnu.org/gnu/gcc/gcc-9.2.0/gcc-9.2.0.tar.xz && tar xvf gcc-9.2.0.tar.xz \
&& yum install -y -q zlib-devel bzip2-devel openssl-devel ncurses-devel sqlite-devel readline-devel tk-devel make libffi-devel postfix nmap masscan nginx -y initscripts postgresql-devel python3-devel uwsgi uwsgi-plugin-common \
&& mkdir /root/flask && mkdir /var/log/uwsgi && cd gcc-9.2.0 && ./contrib/download_prerequisites && mkdir build && cd build && ../configure --prefix=/usr/local --disable-multilib --enable-languages=c,c++ && make && make install \
&& ln -sf /usr/local/bin/gcc cc && yum remove -y gcc

RUN wget https://www.python.org/ftp/python/3.8.1/Python-3.8.1.tgz && tar -zxvf Python-3.8.1.tgz && cd Python-3.8.1 && ./configure prefix=/usr/local/python3.8 --enable-shared --enable-optimizations LDFLAGS="-Wl,--rpath=/usr/local/python3.8/lib" \
&& make && make install && rm -rf /usr/bin/python3 && rm -rf /usr/bin/pip3 && ln -s /usr/local/python3.8/bin/python3.8 /usr/bin/python3 && ln -s /usr/local/python3.8/bin/pip3.8 /usr/bin/pip3

# 设置相关环境变量,数据库账号密码
ENV MARIADB_USER root
ENV MARIADB_PASS 1234567
ENV TZ=Asia/Shanghai
ENV LANG C.UTF-8

# 暴露端口
EXPOSE 3306 11000

# 复制本地文件到docker 中
ADD nginx/flask.conf /etc/nginx/conf.d/flask.conf
ADD nginx/vue.conf /etc/nginx/conf.d/vue.conf
ADD nginx/nginx.conf /etc/nginx/nginx.conf
ADD vue /usr/share/nginx/html/vue
ADD flask /root/flask
ADD flask/uwsgi.ini /root/flask/uwsgi.ini
ADD centos_run.sh /centos_run.sh
ADD centos_uwsgi.sh /centos_uwsgi.sh

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone && pip3 install -r /root/flask/requirements.txt && chmod 775 /centos_uwsgi.sh && ./centos_uwsgi.sh && chmod 775 /centos_run.sh

CMD ["/centos_run.sh"]